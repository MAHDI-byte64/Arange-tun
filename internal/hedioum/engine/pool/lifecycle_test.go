package pool

import (
	"testing"
	"time"
)

// TestPolicyRollBounds verifies the rolled lifetimes/budgets always land inside the
// documented global bounds, across many draws, for both SSH and non-SSH mimics.
func TestPolicyRollBounds(t *testing.T) {
	p := NewLifecyclePolicy("some-node-auth-token")

	for i := 0; i < 5000; i++ {
		// Non-SSH: bounded lifetime AND a real transfer budget.
		life, budget := p.roll("tls")
		if life < auxMinLifetime || life > auxMaxLifetime {
			t.Fatalf("aux lifetime %v out of [%v,%v]", life, auxMinLifetime, auxMaxLifetime)
		}
		if budget < auxMinBudget || budget > auxMaxBudget {
			t.Fatalf("aux budget %d out of [%d,%d]", budget, uint64(auxMinBudget), uint64(auxMaxBudget))
		}

		// SSH: long lifetime, and NO byte budget (backbone tolerates volume).
		sshLife, sshBudget := p.roll("ssh")
		if sshLife < sshMinLifetime || sshLife > sshMaxLifetime {
			t.Fatalf("ssh lifetime %v out of [%v,%v]", sshLife, sshMinLifetime, sshMaxLifetime)
		}
		if sshBudget != 0 {
			t.Fatalf("ssh must have no byte budget, got %d", sshBudget)
		}
	}
}

// TestPolicyPerServerPersonality verifies two servers (different auth tokens) land
// on different baselines — distinct aggregate "handwriting" — while one token is
// deterministic (stable personality for that server).
func TestPolicyPerServerPersonality(t *testing.T) {
	a := NewLifecyclePolicy("token-server-A")
	b := NewLifecyclePolicy("token-server-B")

	if a.auxLifetimeBase == b.auxLifetimeBase &&
		a.auxBudgetBase == b.auxBudgetBase &&
		a.sshLifetimeBase == b.sshLifetimeBase {
		t.Fatal("two different tokens produced identical personalities")
	}

	// Same token -> same personality (stable per server).
	a2 := NewLifecyclePolicy("token-server-A")
	if a != a2 {
		t.Fatalf("same token produced different personalities: %+v vs %+v", a, a2)
	}
}

// TestPolicyPerConnectionJitter verifies that, within one server, repeated rolls do
// NOT collapse to a single value — every connection differs (no fixed per-pipe
// signature).
func TestPolicyPerConnectionJitter(t *testing.T) {
	p := NewLifecyclePolicy("jitter-token")
	seen := map[time.Duration]int{}
	for i := 0; i < 200; i++ {
		life, _ := p.roll("tls")
		seen[life]++
	}
	if len(seen) < 50 {
		t.Fatalf("aux lifetimes not varied enough: only %d distinct values", len(seen))
	}
}

// TestShouldRetireByAge: a non-SSH pipe past its lifetime retires; a fresh one does not.
func TestShouldRetireByAge(t *testing.T) {
	fresh := &YamuxSession{mimicType: "tls", bornAt: time.Now(), retireAfter: time.Hour, byteBudget: 5 * gib}
	if fresh.ShouldRetire() {
		t.Fatal("a fresh pipe within budget must not retire")
	}
	old := &YamuxSession{mimicType: "tls", bornAt: time.Now().Add(-2 * time.Hour), retireAfter: time.Hour, byteBudget: 5 * gib}
	if !old.ShouldRetire() {
		t.Fatal("a pipe past its lifetime must retire")
	}
}

// TestShouldRetireByBytes: a non-SSH pipe over its transfer budget retires even if young.
func TestShouldRetireByBytes(t *testing.T) {
	s := &YamuxSession{mimicType: "tls", bornAt: time.Now(), retireAfter: time.Hour, byteBudget: 1 * gib}
	s.cumulativeBytes = 2 * gib
	if !s.ShouldRetire() {
		t.Fatal("a pipe over its byte budget must retire")
	}
}

// TestShouldRetireSSHNoByteBudget: SSH (byteBudget 0) never retires on volume, only
// on its long lifetime.
func TestShouldRetireSSHNoByteBudget(t *testing.T) {
	s := &YamuxSession{mimicType: "ssh", bornAt: time.Now(), retireAfter: 12 * time.Hour, byteBudget: 0}
	s.cumulativeBytes = 500 * gib // huge volume
	if s.ShouldRetire() {
		t.Fatal("SSH must not retire on volume (no byte budget)")
	}

	oldSSH := &YamuxSession{mimicType: "ssh", bornAt: time.Now().Add(-13 * time.Hour), retireAfter: 12 * time.Hour}
	if !oldSSH.ShouldRetire() {
		t.Fatal("SSH must still retire once past its long lifetime")
	}
}

// TestEvaluateHealthRetiresExpiredPipe drives the real watchdog once over a live
// yamux session forced past its lifetime and asserts it is shifted to Draining
// (the pool then closes it and churns to a fresh pipe on later passes).
func TestEvaluateHealthRetiresExpiredPipe(t *testing.T) {
	sess, _, err := fakeDialer()
	if err != nil {
		t.Fatalf("fakeDialer: %v", err)
	}
	ys := NewYamuxSession(sess, 10, 2, "tls", NewLifecyclePolicy("tok"))
	ys.bornAt = time.Now().Add(-2 * time.Hour) // force past a 1h lifetime
	ys.retireAfter = time.Hour

	np := &NodePool{
		Alias:          "n",
		label:          "tcp",
		minConnections: 0, // no replenish -> the nil dialer is never called
		maxConnections: 5,
		sessions:       []*YamuxSession{ys},
		shutdown:       make(chan struct{}),
	}
	np.evaluateHealthAndScale()

	if !ys.IsDraining() {
		t.Fatal("an expired pipe must be shifted to Draining by the watchdog")
	}
}

// TestNewYamuxSessionRollsBudget checks the constructor wires the policy through:
// a non-SSH session gets a bounded lifetime + budget; an SSH one gets no budget.
func TestNewYamuxSessionRollsBudget(t *testing.T) {
	p := NewLifecyclePolicy("ctor-token")

	tls := NewYamuxSession(nil, 10, 2, "tls", p)
	if tls.retireAfter < auxMinLifetime || tls.retireAfter > auxMaxLifetime {
		t.Fatalf("tls retireAfter %v out of aux bounds", tls.retireAfter)
	}
	if tls.byteBudget == 0 {
		t.Fatal("tls session must have a transfer budget")
	}
	if tls.bornAt.IsZero() {
		t.Fatal("bornAt must be set")
	}

	ssh := NewYamuxSession(nil, 10, 2, "ssh", p)
	if ssh.byteBudget != 0 {
		t.Fatal("ssh session must have no transfer budget")
	}
	if ssh.retireAfter < sshMinLifetime || ssh.retireAfter > sshMaxLifetime {
		t.Fatalf("ssh retireAfter %v out of ssh bounds", ssh.retireAfter)
	}
}
