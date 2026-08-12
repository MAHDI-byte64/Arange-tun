package e2e

import (
	"fmt"
	"testing"
	"time"
)

// Setting the MSS clamp changed how the websocket transports build their
// listener — from ListenAndServe to a socket with the tunnel's options on it.
// A mistake there breaks the whole transport, not just the clamp, so this puts
// a clamped ws and wss tunnel up and pushes real bytes through both ways to
// prove the listener still accepts and carries traffic.
func TestWebSocketCarriesTrafficWithMSSClamp(t *testing.T) {
	certPath, keyPath := testCert(t)
	for _, transport := range []string{"ws", "wss", "wsmux", "wssmux"} {
		t.Run(transport, func(t *testing.T) {
			backend := startEchoBackend(t)
			tunnelPort := freePort(t)
			entryPort := freePort(t)
			const token = "mss-clamp-e2e-token-0123456789abc"

			srvCfg := baseServerConfig(transport, tunnelPort, entryPort, backend.addr, token)
			cliCfg := baseClientConfig(transport, fmt.Sprintf("127.0.0.1:%d", tunnelPort), token, nil)
			// The TLS transports need a certificate; the plain ones ignore it.
			srvCfg.TLSCertFile = certPath
			srvCfg.TLSKeyFile = keyPath
			// A real, sub-default clamp on both ends — the shape an operator applies
			// after Health Check reports a small path MTU.
			srvCfg.MSS = 1300
			cliCfg.MSS = 1300

			tun := runPair(t, srvCfg, cliCfg, entryPort, tunnelPort)
			if err := tun.waitReady(45 * time.Second); err != nil {
				t.Fatalf("%s tunnel with an MSS clamp never carried traffic: %v", transport, err)
			}
			if err := tun.roundTrip(randomPayload(t, 32<<10)); err != nil {
				t.Errorf("%s round trip failed under an MSS clamp: %v", transport, err)
			}
		})
	}
}
