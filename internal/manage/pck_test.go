package manage

import (
	"fmt"
	"strings"
	"testing"
)

// Adding a transport means touching a dozen places that each fail quietly when
// missed: a predicate that leaves it out of the KCP family gives it a zero-sized
// window, one that leaves it out of the datagram family has the health check
// probe a TCP socket that does not exist, and a menu that does not list it makes
// the whole thing unreachable. None of those is a compile error and none is
// visible until somebody builds a tunnel and it does not work.
//
// pck is BackPack's custom-TCP carrier (KCP inside hand-built TCP through a
// packet socket), ported with attribution. These pin the wiring in this fork.

// pck is a KCP transport underneath, so the presets must fill its window and
// tick interval. Without this it would run with a zero window and carry nothing.
func TestPckIsTunedByThePresets(t *testing.T) {
	for _, p := range []string{PresetBalance, PresetTurbo, PresetAggressive, PresetThroughput} {
		s := TunnelSpec{Role: "server", Transport: "pck"}
		ApplyPreset(&s, p)
		if s.KCPSndWnd <= 0 || s.KCPRcvWnd <= 0 || s.KCPInterval <= 0 || s.KCPMTU <= 0 {
			t.Fatalf("%s left pck untuned: mtu %d interval %d wnd %d/%d",
				p, s.KCPMTU, s.KCPInterval, s.KCPSndWnd, s.KCPRcvWnd)
		}
	}
}

// The predicates decide what the rest of the program believes about it. Each of
// these has a consequence spelled out in the message, because "the predicate is
// wrong" is not something anyone would chase from the symptom.
func TestPckPredicates(t *testing.T) {
	if !isKCP("pck") {
		t.Fatal("pck is not in the KCP family — its kcp_* settings would never be written to the config")
	}
	if !isMux("pck") {
		t.Fatal("pck is not in the mux family — its smux settings would be left at zero")
	}
	if !isDatagram("pck") {
		t.Fatal("pck is not in the datagram family — the health check would probe a TCP socket that does not exist")
	}
	if !supportsProxyProtocol("pck") {
		t.Fatal("pck cannot carry the real client IP, but it multiplexes and has somewhere to put the header")
	}
	if !validTransport("pck") {
		t.Fatal("pck is not a valid transport — every edit and creation path would refuse it")
	}
	// It rides on crafted TCP, but its data is not a kernel TCP stream this
	// process can clamp, so it is sized by the KCP MTU like the other carriers.
	if supportsMSS("pck") {
		t.Fatal("pck was offered an MSS clamp, but it has no kernel TCP segments to clamp")
	}
}

// It has to be reachable from the menu, in the family the operator would look
// in for it. This fork groups the raw-packet carriers under Experimental.
func TestPckIsOfferedInAMenuGroup(t *testing.T) {
	found := false
	for _, g := range transportGroups {
		for _, e := range g.entries {
			if e.value == "pck" {
				if e.label == "" || e.desc == "" {
					t.Fatal("the pck entry has no label or description")
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("pck is not offered anywhere in the transport menu, so it is unreachable from setup")
	}
}

// The pck knobs must survive a write→read round trip, or an edit would silently
// drop the operator's egress overrides.
func TestPckConfigRoundTrips(t *testing.T) {
	s := TunnelSpec{
		Name: "pck1", Role: "server", Transport: "pck",
		BindAddr: "0.0.0.0:8443", Token: "secret", Ports: []string{"443"},
		PckInterface: "eth0", PckGatewayMAC: "aa:bb:cc:dd:ee:ff",
		PckFlags: []string{"PA", "A"},
	}
	var b strings.Builder
	p := func(format string, args ...any) { b.WriteString(fmt.Sprintf(format, args...)) }
	s.writePck(p)
	out := b.String()
	for _, want := range []string{
		`pck_interface = "eth0"`,
		`pck_gateway_mac = "aa:bb:cc:dd:ee:ff"`,
		`pck_flags = ["PA", "A"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("writePck did not emit %q\n--- got ---\n%s", want, out)
		}
	}

	// A non-pck tunnel must never carry pck keys.
	s.Transport = "tcp"
	b.Reset()
	s.writePck(p)
	if b.Len() != 0 {
		t.Errorf("writePck emitted keys for a non-pck transport: %q", b.String())
	}
}
