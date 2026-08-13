package ingress

import (
	"net"
	"testing"

	"github.com/hashicorp/yamux"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/config"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/mimic"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/securestream"
)

// TestClientMimicForTypes locks the endpoint-type → client-mimic mapping, including
// the implicit-TLS aliases (smtps/imaps reuse the plain TLS client) and the
// STARTTLS mail mimics.
func TestClientMimicForTypes(t *testing.T) {
	cases := map[string]string{
		"ssh":   "ssh",
		"tls":   "tls",
		"smtps": "tls",  // implicit TLS
		"imaps": "tls",  // implicit TLS
		"smtp":  "smtp", // STARTTLS
		"imap":  "imap", // STARTTLS
		"":      "ssh",  // default
	}
	for mimicType, wantName := range cases {
		m := clientMimicFor(config.Endpoint{Mimic: mimicType}, "tok")
		if m.Name() != wantName {
			t.Errorf("clientMimicFor(%q).Name() = %q, want %q", mimicType, m.Name(), wantName)
		}
	}
}

// TestProbeEndpoint drives ProbeEndpoint against an in-process SSH-mimic egress and
// verifies it reports a positive round-trip latency (proves the full path:
// TCP + mimic handshake + yamux ping).
func TestProbeEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const token = "probe-secret-token"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sm := &mimic.SSHMimic{Token: token, Filter: securestream.NewReplayFilter(0)}
		authed, _, err := sm.Accept(conn)
		if err != nil {
			return
		}
		sess, err := yamux.Server(authed, hubYamuxConfig())
		if err != nil {
			return
		}
		_, _ = sess.AcceptStream() // block to keep the session alive for the ping
	}()

	ep := config.Endpoint{Target: ln.Addr().String(), Mimic: "ssh"}
	rtt, err := ProbeEndpoint(ep, token)
	if err != nil {
		t.Fatalf("ProbeEndpoint: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt = %v, want > 0", rtt)
	}
}

// TestProbeEndpointWrongTokenFails: a bad token must not report a healthy pipe.
func TestProbeEndpointWrongToken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sm := &mimic.SSHMimic{Token: "server-token", Filter: securestream.NewReplayFilter(0)}
		if _, replay, err := sm.Accept(conn); err != nil && replay != nil {
			replay.Close() // no decoy configured; just drop
		}
	}()

	ep := config.Endpoint{Target: ln.Addr().String(), Mimic: "ssh"}
	if _, err := ProbeEndpoint(ep, "client-wrong-token"); err == nil {
		t.Fatal("ProbeEndpoint should fail with a wrong token")
	}
}

// TestEndpointPickerAlwaysValid checks the Chaos-Mesh weighted picker: a single
// endpoint is returned as-is, and with several endpoints every pick is a real
// configured endpoint (weights are sane, no out-of-range index).
func TestEndpointPickerAlwaysValid(t *testing.T) {
	single := config.ForeignNode{Endpoints: []config.Endpoint{{Target: "1.2.3.4:22", Mimic: "ssh"}}}
	d := newEndpointDialer(single)
	if got := d.pick(); got.Mimic != "ssh" {
		t.Fatalf("single-endpoint pick = %+v", got)
	}

	multi := config.ForeignNode{Endpoints: []config.Endpoint{
		{Target: "1.2.3.4:22", Mimic: "ssh"},
		{Target: "1.2.3.4:443", Mimic: "tls"},
		{Target: "1.2.3.4:993", Mimic: "imaps"},
	}}
	d = newEndpointDialer(multi)
	if len(d.weights) != 3 {
		t.Fatalf("weights len = %d, want 3", len(d.weights))
	}
	valid := map[string]bool{"ssh": true, "tls": true, "imaps": true}
	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		ep := d.pick()
		if !valid[ep.Mimic] {
			t.Fatalf("pick returned an unknown endpoint: %+v", ep)
		}
		seen[ep.Mimic]++
	}
	// Over 300 weighted draws all three should appear at least once (weights are
	// 0.3+rand, so none is ever zero).
	if len(seen) != 3 {
		t.Fatalf("expected all 3 endpoints to be picked, saw %v", seen)
	}
}
