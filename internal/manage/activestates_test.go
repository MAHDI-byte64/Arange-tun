package manage

import "testing"

// The batched unit query pairs verdicts with units by position, so a reply that
// does not line up must be rejected rather than trusted: mislabelling which
// tunnel is running is a far worse outcome than the process the batch saves.

func TestActiveStatesPairsEachUnitWithItsVerdict(t *testing.T) {
	services := []string{"a.service", "b.service", "c.service"}
	states, ok := matchActiveStates(services, "active\ninactive\nactive")
	if !ok {
		t.Fatal("a well-formed reply was rejected")
	}
	for svc, want := range map[string]bool{"a.service": true, "b.service": false, "c.service": true} {
		if states[svc] != want {
			t.Errorf("%s: got %v, want %v", svc, states[svc], want)
		}
	}
}

// systemd reports several flavours of "not running"; only "active" is running.
func TestActiveStatesTreatsEveryOtherStateAsNotRunning(t *testing.T) {
	services := []string{"a.service", "b.service", "c.service", "d.service"}
	states, ok := matchActiveStates(services, "failed\nactivating\nunknown\ninactive")
	if !ok {
		t.Fatal("a well-formed reply was rejected")
	}
	for _, svc := range services {
		if states[svc] {
			t.Errorf("%s was reported as running", svc)
		}
	}
}

// A stray line — a warning that reached stdout, or a systemd that answered
// differently — shifts every verdict after it. Rejecting the whole reply sends
// the caller to the one-at-a-time path instead of confidently lying.
func TestActiveStatesRejectsAMisalignedReply(t *testing.T) {
	services := []string{"a.service", "b.service"}

	if _, ok := matchActiveStates(services, "warning: something\nactive\ninactive"); ok {
		t.Error("a reply with an extra line was accepted — verdicts would name the wrong unit")
	}
	if _, ok := matchActiveStates(services, "active"); ok {
		t.Error("a short reply was accepted")
	}
	// The empty reply of a machine with no working systemd must not be read as
	// one verdict for a single unit either.
	if _, ok := matchActiveStates(services, ""); ok {
		t.Error("an empty reply was accepted")
	}
}

// Asking about nothing must not run systemd at all, nor return a nil map the
// caller would have to guard.
func TestActiveStatesOfNothingIsEmptyNotNil(t *testing.T) {
	states := ActiveStates(nil)
	if states == nil {
		t.Fatal("got a nil map")
	}
	if len(states) != 0 {
		t.Errorf("got %v, want empty", states)
	}
}
