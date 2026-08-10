package spoof

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// The spoof tester answers the one question that decides whether this tunnel can
// work at all on a given network: will packets with a forged source IP actually
// leave this host and arrive at a peer? Most datacenters drop them (egress
// filtering / BCP38). Two coordinated servers run it — a receiver and a sender —
// and it reports the delivery rate per candidate spoof IP.

// TestProbe is one candidate to test.
type TestProbe struct {
	SpoofIP string // the source IP to forge
	Count   int    // packets to send
}

// TestResult is the outcome for one spoof IP.
type TestResult struct {
	SpoofIP  string  `json:"spoofIP"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"lossPct"`
	OK       bool    `json:"ok"` // delivery above the threshold
}

const testMagic uint32 = 0x5350_4631 // "SPF1"

// RunReceiver captures probe packets on the given port for the duration and
// counts, per forged source IP, how many arrived. It is the peer side of a test:
// run it on server B, then send from server A.
func RunReceiver(ctx context.Context, iface string, port int, transport string) (map[string]int, error) {
	iface, err := resolveIface(iface)
	if err != nil {
		return nil, err
	}
	rcv, err := newReceiver(iface, carrierOr(transport), uint16(port), nil)
	if err != nil {
		return nil, err
	}
	defer rcv.close()

	rules := recvRules(carrierOr(transport), port)
	applyFirewall(rules, nil)
	defer removeFirewall(rules)

	counts := map[string]int{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			frame, err := rcv.recv()
			if err != nil {
				return
			}
			ip := parseProbe(frame)
			if ip != "" {
				counts[ip]++
			}
		}
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
	return counts, nil
}

// SendProbes forges `count` packets from each candidate source IP toward the
// peer's real IP:port. Pair it with RunReceiver on the peer.
func SendProbes(iface string, peerRealIP string, port int, transport string, probes []TestProbe) error {
	dst := net.ParseIP(peerRealIP)
	if dst == nil {
		return fmt.Errorf("invalid peer IP %q", peerRealIP)
	}
	for _, p := range probes {
		src := net.ParseIP(p.SpoofIP)
		if src == nil {
			continue
		}
		snd, err := newSender(carrierOr(transport), src, dst, uint16(port), uint16(port))
		if err != nil {
			return err
		}
		n := p.Count
		if n <= 0 {
			n = 20
		}
		for i := 0; i < n; i++ {
			_ = snd.send(buildProbe(src))
			time.Sleep(5 * time.Millisecond)
		}
		snd.close()
	}
	return nil
}

// buildProbe is the probe payload: a magic number and the forged source IP, so
// the receiver can attribute each packet to the IP it was sent from.
func buildProbe(src net.IP) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], testMagic)
	copy(b[4:8], src.To4())
	return b
}

func parseProbe(frame []byte) string {
	if len(frame) < 8 || binary.BigEndian.Uint32(frame[0:4]) != testMagic {
		return ""
	}
	return net.IP(frame[4:8]).String()
}
