package e2e

import (
	"testing"
)

// The QUIC transport, end to end.
//
// QUIC carries the tunnel in reliable streams over a single UDP flow, so it
// never appears in the TCP listen table and cannot be probed with a TCP
// connect — the readiness check has to be real data through the relay, which
// is exactly what startTunnel + roundTrip do. This proves the ported transport
// actually establishes and carries a payload both ways, not merely that it
// compiles.
func TestQuicCarriesTrafficEndToEnd(t *testing.T) {
	backend := startEchoBackend(t)
	tun := startTunnel(t, "quic", backend, tunnelOptions{})

	// A payload large enough to span more than one QUIC packet, so the test
	// exercises the stream framing rather than a single-datagram happy path.
	payload := randomPayload(t, 64<<10)
	if err := tun.roundTrip(payload); err != nil {
		t.Fatalf("quic round trip failed: %v", err)
	}
}
