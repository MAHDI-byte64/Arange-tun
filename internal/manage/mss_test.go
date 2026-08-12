package manage

import (
	"strings"
	"testing"
)

// The MSS clamp only means something on the transports that carry TCP segments.
// The datagram transports size their packets with the KCP MTU, so offering — or
// worse, applying — a clamp there is a setting that silently does nothing.
func TestSupportsMSS(t *testing.T) {
	for _, tr := range []string{"tcp", "tcpmux", "stealth", "ws", "wss", "wsmux", "wssmux"} {
		if !supportsMSS(tr) {
			t.Errorf("%s carries TCP segments but supportsMSS says no", tr)
		}
	}
	for _, tr := range []string{"udp", "kcp", "xdi", "quic"} {
		if supportsMSS(tr) {
			t.Errorf("%s is a datagram transport but supportsMSS says yes", tr)
		}
	}
}

// buildSpec must apply the clamp to a websocket tunnel — the regression this
// whole change fixes was that WS carried the value but never put it on a socket.
func TestBuildSpecAppliesMSSOnWebSocket(t *testing.T) {
	s, err := buildSpec(TunnelRequest{
		Name: "wsm", Role: "server", Transport: "wss",
		Port: "443", Ports: []string{"443"},
		Advanced: &AdvancedTuning{MSS: 1208},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.MSS != 1208 {
		t.Errorf("MSS = %d, want 1208 applied to the wss tunnel", s.MSS)
	}
}

// A clamp on a datagram transport must be dropped, not carried into a config
// where it would read as set but do nothing.
func TestBuildSpecDropsMSSOnDatagram(t *testing.T) {
	s, err := buildSpec(TunnelRequest{
		Name: "kcpx", Role: "server", Transport: "kcp",
		Port: "8443", Ports: []string{"8443"},
		Advanced: &AdvancedTuning{MSS: 1208},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.MSS != 0 {
		t.Errorf("MSS = %d, want 0 — a datagram transport cannot clamp segments", s.MSS)
	}
}

// SetMSS validates before it writes: a value below the floor every IPv4 path
// must carry is a typo the kernel would reject, so it is refused here with an
// explanation rather than saved and failed silently on the socket.
func TestSetMSSRejectsAValueBelowTheFloor(t *testing.T) {
	// Uses an in-memory spec check via the same validation SetMSS performs; the
	// disk/systemd path is exercised by the integration tests. Here we only need
	// the guard, which trips before any I/O.
	err := setMSSFloorCheck(400)
	if err == nil || !strings.Contains(err.Error(), "536") {
		t.Errorf("a 400-byte clamp was accepted, want a floor error: %v", err)
	}
	if err := setMSSFloorCheck(0); err != nil {
		t.Errorf("0 (off) was rejected: %v", err)
	}
	if err := setMSSFloorCheck(1208); err != nil {
		t.Errorf("a normal clamp was rejected: %v", err)
	}
}
