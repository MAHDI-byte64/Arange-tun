package pool

import (
	"testing"
	"time"
)

// TestShouldCloseDraining locks the drain-close policy: a live transfer is never cut
// before the hard ceiling; empty or idle-past-grace pipes close.
func TestShouldCloseDraining(t *testing.T) {
	cases := []struct {
		name       string
		streams    int
		drainedFor time.Duration
		idle       bool
		want       bool
	}{
		{"empty closes immediately", 0, time.Second, false, true},
		{"active within grace stays", 1, 10 * time.Second, false, false},
		{"idle within grace stays", 1, 10 * time.Second, true, false},
		{"idle past grace closes", 1, 2 * time.Minute, true, true},
		{"active past grace but not ceiling stays", 1, 2 * time.Minute, false, false},
		{"active past hard ceiling closes", 1, 31 * time.Minute, false, true},
	}
	for _, c := range cases {
		if got := shouldCloseDraining(c.streams, c.drainedFor, c.idle); got != c.want {
			t.Errorf("%s: shouldCloseDraining(%d,%v,%v)=%v, want %v", c.name, c.streams, c.drainedFor, c.idle, got, c.want)
		}
	}
}

// TestSetDrainingTracksTime: SetDraining timestamps the transition; Revive clears it.
func TestSetDrainingTracksTime(t *testing.T) {
	s := &YamuxSession{}
	if s.DrainingFor() != 0 {
		t.Fatal("a fresh session should report DrainingFor()==0")
	}
	s.SetDraining()
	time.Sleep(3 * time.Millisecond)
	if s.DrainingFor() <= 0 {
		t.Fatal("after SetDraining, DrainingFor() should be > 0")
	}
	s.Revive()
	if s.DrainingFor() != 0 {
		t.Fatal("after Revive, DrainingFor() should reset to 0")
	}
}

// TestActiveCountLocked counts only Active sessions (draining excluded).
func TestActiveCountLocked(t *testing.T) {
	np := &NodePool{sessions: []*YamuxSession{
		{state: StateActive}, {state: StateDraining}, {state: StateActive}, {state: StateDraining},
	}}
	if got := np.activeCountLocked(); got != 2 {
		t.Fatalf("activeCountLocked = %d, want 2", got)
	}
}

// TestReplenishNotBlockedByDrainers is the regression test for issue #23: even when
// every slot is occupied by a stuck (still-streaming) draining pipe, the pool must
// still dial fresh ACTIVE pipes to meet the minimum — it must never starve.
func TestReplenishNotBlockedByDrainers(t *testing.T) {
	np := &NodePool{
		Alias:          "n1",
		label:          "tcp",
		minConnections: 2,
		maxConnections: 3,
		dialer:         fakeDialer, // returns live "ssh" sessions
		lifecycle:      NewLifecyclePolicy("drain-test"),
		shutdown:       make(chan struct{}),
	}

	// Fill all 3 slots with draining pipes that each hold an OPEN stream (so they are
	// NOT closed by the drain policy this pass) — the pre-fix pool would refuse to
	// dial because len(sessions) == max.
	for i := 0; i < 3; i++ {
		sess, _, err := fakeDialer()
		if err != nil {
			t.Fatalf("fakeDialer: %v", err)
		}
		ys := NewYamuxSession(sess, 10, 2, "tls", np.lifecycle)
		if _, err := ys.OpenStream(); err != nil { // keep a stream open (never closed)
			t.Fatalf("open stream: %v", err)
		}
		ys.SetDraining()
		np.sessions = append(np.sessions, ys)
	}

	np.evaluateHealthAndScale() // should replenish active pipes despite the 3 drainers

	active := 0
	for _, s := range np.sessions {
		if s.IsActive() {
			active++
		}
	}
	if active < np.minConnections {
		t.Fatalf("pool starved: only %d active pipes after replenish (want >= %d); draining pipes blocked scale-up", active, np.minConnections)
	}
}

// TestReplenishEvictsDrainersAtCap: when every slot is a stuck draining pipe AT the
// total cap, replenishment must evict the oldest drainer to admit fresh active pipes
// — reaching the minimum without ever exceeding maxTotalFactor * maxConnections.
func TestReplenishEvictsDrainersAtCap(t *testing.T) {
	np := &NodePool{
		Alias:          "n1",
		label:          "tcp",
		minConnections: 2,
		maxConnections: 2, // total cap = maxTotalFactor(2) * 2 = 4
		dialer:         fakeDialer,
		lifecycle:      NewLifecyclePolicy("evict-test"),
		shutdown:       make(chan struct{}),
	}
	cap := maxTotalFactor * np.maxConnections

	// Fill to the total cap with stuck (still-streaming, recent, idle) drainers.
	for i := 0; i < cap; i++ {
		sess, _, err := fakeDialer()
		if err != nil {
			t.Fatalf("fakeDialer: %v", err)
		}
		ys := NewYamuxSession(sess, 10, 2, "tls", np.lifecycle)
		if _, err := ys.OpenStream(); err != nil {
			t.Fatalf("open stream: %v", err)
		}
		ys.SetDraining()
		np.sessions = append(np.sessions, ys)
	}

	np.evaluateHealthAndScale()

	active, total := 0, len(np.sessions)
	for _, s := range np.sessions {
		if s.IsActive() {
			active++
		}
	}
	if active < np.minConnections {
		t.Fatalf("eviction failed: only %d active pipes (want >= %d)", active, np.minConnections)
	}
	if total > cap {
		t.Fatalf("total sessions %d exceeded the cap %d", total, cap)
	}
}
