// Package spoof is the Spoof tunnel: a UDP pipe whose packets carry a forged
// source IP (mutual bidirectional IP spoofing), so a Layer-3 firewall that
// filters on source/destination IP sees a whitelisted-looking flow. Each end
// stamps its own forged source IP; the payload is a single UDP flow (meant to
// carry WireGuard or any UDP service), sealed with ChaCha20-Poly1305.
//
// It is a pure-Go take on ParsaKSH/spoof-tunnel's technique — not wire-compatible
// with it (two Arange-tun ends talk to each other). It only works where the
// network permits forged source IPs; the built-in spoof tester checks that.
//
// Both roles need root: raw packet injection and pcap capture.
package spoof

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/mahdi-byte64/arange-tun/config"
)

// RunClient runs the local side: an app sends UDP to cfg.Listen, and each
// datagram is spoofed to the server; the server's spoofed replies are written
// back to the app.
func RunClient(ctx context.Context, sc *config.SpoofConfig, logger *logrus.Logger) {
	requireRoot(logger)
	transport := carrierOr(sc.Transport)

	iface, err := resolveIface(sc.Interface)
	if err != nil {
		logger.Fatalf("spoof client: %v", err)
	}
	serverIP := net.ParseIP(sc.ServerIP)
	spoofIP := net.ParseIP(sc.SpoofIP)
	peerSpoofIP := net.ParseIP(sc.PeerSpoofIP)
	if serverIP == nil || spoofIP == nil {
		logger.Fatalf("spoof client: server_ip and spoof_ip are required")
	}
	if sc.ServerPort <= 0 || sc.RecvPort <= 0 || sc.Listen == "" {
		logger.Fatalf("spoof client: listen, server_port and recv_port are required")
	}

	aead, err := newAEAD(sc.Key)
	if err != nil {
		logger.Fatalf("spoof client: %v", err)
	}

	// The app's UDP socket.
	laddr, err := net.ResolveUDPAddr("udp4", sc.Listen)
	if err != nil {
		logger.Fatalf("spoof client: bad listen %q: %v", sc.Listen, err)
	}
	app, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		logger.Fatalf("spoof client: cannot listen on %s: %v", sc.Listen, err)
	}
	defer app.Close()

	snd, err := newSender(transport, spoofIP, serverIP, uint16(sc.ServerPort), uint16(sc.ServerPort))
	if err != nil {
		logger.Fatalf("spoof client: %v", err)
	}
	defer snd.close()
	rcv, err := newReceiver(iface, transport, uint16(sc.RecvPort), peerSpoofIP)
	if err != nil {
		logger.Fatalf("spoof client: %v", err)
	}
	defer rcv.close()

	rules := recvRules(transport, sc.RecvPort)
	applyFirewall(rules, logger)
	defer removeFirewall(rules)
	if transport == carrierICMP {
		restore := suppressICMPReplies()
		defer restore()
	}

	logger.Infof("spoof client: %s pipe up — app %s ⇄ server %s:%d (spoof src %s, peer %s, iface %s)",
		transport, sc.Listen, sc.ServerIP, sc.ServerPort, sc.SpoofIP, sc.PeerSpoofIP, iface)
	pump(ctx, app, snd, rcv, aead, logger, "spoof client")
}

// RunServer runs the remote side: it receives spoofed packets, relays the inner
// UDP flow to Forward, and spoofs the replies back to the client.
func RunServer(ctx context.Context, sc *config.SpoofConfig, logger *logrus.Logger) {
	requireRoot(logger)
	transport := carrierOr(sc.Transport)

	iface, err := resolveIface(sc.Interface)
	if err != nil {
		logger.Fatalf("spoof server: %v", err)
	}
	clientIP := net.ParseIP(sc.ClientIP)
	spoofIP := net.ParseIP(sc.SpoofIP)
	peerSpoofIP := net.ParseIP(sc.PeerSpoofIP)
	if clientIP == nil || spoofIP == nil {
		logger.Fatalf("spoof server: client_ip and spoof_ip are required")
	}
	if sc.ListenPort <= 0 || sc.ClientPort <= 0 || sc.Forward == "" {
		logger.Fatalf("spoof server: listen_port, client_port and forward are required")
	}

	aead, err := newAEAD(sc.Key)
	if err != nil {
		logger.Fatalf("spoof server: %v", err)
	}

	// The connection to the real service (e.g. local WireGuard).
	fwd, err := net.Dial("udp4", sc.Forward)
	if err != nil {
		logger.Fatalf("spoof server: cannot reach forward target %s: %v", sc.Forward, err)
	}
	defer fwd.Close()

	snd, err := newSender(transport, spoofIP, clientIP, uint16(sc.ClientPort), uint16(sc.ClientPort))
	if err != nil {
		logger.Fatalf("spoof server: %v", err)
	}
	defer snd.close()
	rcv, err := newReceiver(iface, transport, uint16(sc.ListenPort), peerSpoofIP)
	if err != nil {
		logger.Fatalf("spoof server: %v", err)
	}
	defer rcv.close()

	rules := recvRules(transport, sc.ListenPort)
	applyFirewall(rules, logger)
	defer removeFirewall(rules)
	if transport == carrierICMP {
		restore := suppressICMPReplies()
		defer restore()
	}

	logger.Infof("spoof server: %s pipe up — listen :%d → forward %s (spoof src %s, client %s:%d, iface %s)",
		transport, sc.ListenPort, sc.Forward, sc.SpoofIP, sc.ClientIP, sc.ClientPort, iface)
	pumpConn(ctx, fwd, snd, rcv, aead, logger, "spoof server")
}

// pump moves a UDP listener's app traffic across the spoof link and back. The
// app's address is learned from its first datagram so replies can find it.
func pump(ctx context.Context, app *net.UDPConn, snd *sender, rcv *receiver, a *aead, logger *logrus.Logger, tag string) {
	var appAddr atomic.Pointer[net.UDPAddr]

	// app → link
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := app.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			appAddr.Store(addr)
			frame, err := a.seal(buf[:n])
			if err != nil {
				continue
			}
			if err := snd.send(frame); err != nil {
				logger.Debugf("%s: send failed: %v", tag, err)
			}
		}
	}()
	// link → app
	go func() {
		for {
			frame, err := rcv.recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			payload, err := a.open(frame)
			if err != nil {
				continue // not ours
			}
			if to := appAddr.Load(); to != nil {
				_, _ = app.WriteToUDP(payload, to)
			}
		}
	}()
	<-ctx.Done()
	logger.Printf("shutting down %s...", tag)
}

// pumpConn is pump for the server side, where the near end is a connected UDP
// socket to the forward target rather than a listener.
func pumpConn(ctx context.Context, fwd net.Conn, snd *sender, rcv *receiver, a *aead, logger *logrus.Logger, tag string) {
	// link → forward
	go func() {
		for {
			frame, err := rcv.recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			payload, err := a.open(frame)
			if err != nil {
				continue
			}
			_, _ = fwd.Write(payload)
		}
	}()
	// forward → link
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := fwd.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			frame, err := a.seal(buf[:n])
			if err != nil {
				continue
			}
			if err := snd.send(frame); err != nil {
				logger.Debugf("%s: send failed: %v", tag, err)
			}
		}
	}()
	<-ctx.Done()
	logger.Printf("shutting down %s...", tag)
}

func carrierOr(t string) string {
	switch t {
	case carrierTCP, carrierICMP, carrierUDP:
		return t
	default:
		return carrierUDP
	}
}
