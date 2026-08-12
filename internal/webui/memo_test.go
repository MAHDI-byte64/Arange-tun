package webui

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The memo is what stops the panel re-running a ping subprocess per tunnel on
// every six-second refresh. It has to actually collapse the repeats, actually
// expire, and never serialise the parallel refresh it was added to speed up.

func TestMemoComputesOnceWithinTheTTL(t *testing.T) {
	m := newMemo[int](time.Minute)
	var calls int32

	for i := 0; i < 5; i++ {
		got := m.get("k", func() int {
			atomic.AddInt32(&calls, 1)
			return 42
		})
		if got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	}
	if calls != 1 {
		t.Errorf("computed %d times, want 1 — the repeats were not collapsed", calls)
	}
}

func TestMemoRecomputesAfterExpiry(t *testing.T) {
	m := newMemo[int](5 * time.Millisecond)
	var calls int32
	compute := func() int { return int(atomic.AddInt32(&calls, 1)) }

	if got := m.get("k", compute); got != 1 {
		t.Fatalf("first call got %d, want 1", got)
	}
	time.Sleep(20 * time.Millisecond)
	if got := m.get("k", compute); got != 2 {
		t.Errorf("after expiry got %d, want a fresh 2 — a stale value was served forever", got)
	}
}

func TestMemoKeepsKeysApart(t *testing.T) {
	m := newMemo[string](time.Minute)
	if got := m.get("a", func() string { return "A" }); got != "A" {
		t.Fatalf("got %q", got)
	}
	if got := m.get("b", func() string { return "B" }); got != "B" {
		t.Errorf("key b returned %q — one key's value was served for another", got)
	}
}

// A failed probe is the reading that turns a card red and the one most likely
// to change next, so it must expire sooner than a successful one — otherwise a
// recovered tunnel keeps showing red.
func TestFailedPingIsRecheckedSoonerThanASuccessfulOne(t *testing.T) {
	m := newPingMemo()

	m.get("fail", func() int { return -1 })
	m.get("ok", func() int { return 12 })

	m.mu.Lock()
	failExp := m.entries["fail"].exp
	okExp := m.entries["ok"].exp
	m.mu.Unlock()

	if !failExp.Before(okExp) {
		t.Error("a failed probe is cached as long as a successful one — a recovered tunnel would stay red")
	}
	if d := time.Until(failExp); d > pingFailedTTL+time.Second {
		t.Errorf("failed probe cached for %v, want about %v", d, pingFailedTTL)
	}
}

// The refresh runs one goroutine per tunnel; compute must not hold the lock, or
// the probes serialise and the page gets slower rather than faster.
func TestMemoDoesNotSerialiseConcurrentComputes(t *testing.T) {
	m := newMemo[int](time.Minute)
	const n = 8

	var wg sync.WaitGroup
	started := make(chan struct{}, n)
	release := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.get(string(rune('a'+i)), func() int {
				started <- struct{}{}
				<-release // hold inside compute until every other one is in too
				return i
			})
		}(i)
	}

	// Every compute must be able to be in flight at once. If get held the lock
	// across compute, only one would ever start and this would time out.
	for i := 0; i < n; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("only %d of %d computes ran concurrently — the lock is held across compute", i, n)
		}
	}
	close(release)
	wg.Wait()
}
