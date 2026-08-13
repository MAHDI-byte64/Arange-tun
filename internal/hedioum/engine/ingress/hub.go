package ingress

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/config"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/pool"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/tunproto"
)

// StartIranHub initializes the SOCKS5 listeners and dynamically scaling connection
// pools for all configured foreign egress nodes.
//
// It runs until ctx is cancelled. onLive, when non-nil, is called periodically
// with the total number of live pool connections across all nodes, so the
// Arange-tun adapter can publish a truthful "connected" signal to the panel (the
// pool keeps MinConnections warm, so a positive count means the foreign node is
// reachable and the tunnel is up).
func StartIranHub(ctx context.Context, cfg *config.AppConfig, onLive func(total int)) {
	hubManager := pool.NewHubManager()

	for _, node := range cfg.ForeignNodes {
		nodeCopy := node // local copy for the closure

		// The dialer spreads new physical pipes across this node's endpoints with a
		// fluctuating per-server mimic distribution (see dial.go).
		dialer := newEndpointDialer(nodeCopy)
		hubManager.RegisterNode(nodeCopy, dialer.dial)

		// Local SOCKS5 listener, strictly bound to localhost, for X-UI/Xray.
		go startLocalSocksListener(nodeCopy, hubManager)
	}

	if len(cfg.ForeignNodes) == 0 {
		slog.Warn("iran hub started with no foreign nodes; add a node and restart")
	}

	if onLive != nil {
		go reportLiveLoop(ctx, cfg, hubManager, onLive)
	}

	// Block until terminated (the adapter cancels ctx on SIGTERM). Not a bare
	// select{}: with zero nodes there are no other goroutines, and select{} would
	// trip the runtime's deadlock detector and crash-loop the service.
	<-ctx.Done()
}

// reportLiveLoop periodically sums the live pool connections across every node
// and hands the total to onLive, until ctx ends.
func reportLiveLoop(ctx context.Context, cfg *config.AppConfig, hm *pool.HubManager, onLive func(total int)) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	report := func() {
		total := 0
		for _, node := range cfg.ForeignNodes {
			total += hm.GetStats(node.Alias).ActiveConns
		}
		onLive(total)
	}
	report() // publish an initial reading rather than waiting a full interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			report()
		}
	}
}

// startLocalSocksListener boots up a TCP server listening exclusively on 127.0.0.1.
// It acts as the local bridge for X-UI's outbound routing.
func startLocalSocksListener(node config.ForeignNode, hubManager *pool.HubManager) {
	listenAddr := fmt.Sprintf("127.0.0.1:%d", node.LocalSocksPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("failed to bind SOCKS5 listener", "node", node.Alias, "addr", listenAddr, "err", err)
		return
	}

	slog.Info("SOCKS5 ingress active", "node", node.Alias, "addr", listenAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue // Silently ignore transient socket accept errors
		}

		go handleClientTraffic(clientConn, node.Alias, hubManager)
	}
}

// handleClientTraffic processes the local SOCKS5 handshake, extracts the target metadata,
// and multiplexes the payload over a Yamux stream.
func handleClientTraffic(localConn net.Conn, nodeAlias string, hubManager *pool.HubManager) {
	defer localConn.Close()

	// 1. Negotiate SOCKS5 and read the request (command + destination).
	cmd, dst, err := readSocksRequest(localConn)
	if err != nil {
		// Drop bad requests/scanners to conserve CPU and RAM.
		slog.Debug("socks handshake failed", "node", nodeAlias, "err", err)
		return
	}

	switch cmd {
	case cmdConnect:
		// Reply success (BND 0.0.0.0:0) and pipe the TCP stream.
		if err := sendSocksReply(localConn, repSuccess, net.IPv4zero, 0); err != nil {
			return
		}
		_ = localConn.SetDeadline(time.Time{}) // drop the handshake deadline for the tunnel
		handleTCPConnect(localConn, dst, nodeAlias, hubManager)
	case cmdUDPAssociate:
		handleUDPAssociate(localConn, nodeAlias, hubManager)
	default:
		slog.Debug("unsupported SOCKS command", "node", nodeAlias, "cmd", cmd)
		_ = sendSocksReply(localConn, repCmdNotSupported, net.IPv4zero, 0)
	}
}

// handleTCPConnect multiplexes a SOCKS5 CONNECT over a Yamux stream to the egress.
func handleTCPConnect(localConn net.Conn, targetDest, nodeAlias string, hubManager *pool.HubManager) {
	// Request a multiplexed logical stream from the TCP sub-pool.
	stream, err := hubManager.GetStreamTCP(nodeAlias)
	if err != nil {
		// Pool temporarily exhausted or dead: drop; X-UI/Xray core retries.
		slog.Debug("tcp pool unavailable, dropping connection", "node", nodeAlias, "err", err)
		return
	}
	defer stream.Close()

	// Announce the stream as a TCP CONNECT and inject the target address:
	// [StreamTCP][u16 len][target]
	if err := tunproto.WriteTCPHeader(stream, targetDest); err != nil {
		return
	}

	// Full-duplex pipe between the local X-UI connection and the Yamux stream.
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, localConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(localConn, stream)
		errChan <- err
	}()
	<-errChan
}
