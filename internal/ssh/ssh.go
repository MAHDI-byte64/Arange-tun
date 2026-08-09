// Package ssh is a client-only VPN-egress tunnel over SSH. It dials an SSH
// server abroad with a username and password and exposes a local SOCKS5 proxy
// whose connections are dialed from the server side (SSH dynamic forwarding), so
// a panel outbound pointed at the SOCKS5 leaves by the server's IP. It keeps the
// SSH connection up, reconnecting with backoff if it drops.
//
// Security here is deliberately light (password auth, host key not pinned): this
// is a convenience egress, not a hardened channel — the SSH session is still
// encrypted, but the server is trusted on first use.
package ssh

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"
	"github.com/mahdi-byte64/arange-tun/internal/socksproxy"
)

// RunClient keeps an SSH connection up and serves a SOCKS5 proxy through it
// until ctx ends.
func RunClient(ctx context.Context, sc *config.SSHConfig, logger *logrus.Logger) {
	host := sc.Host
	if host == "" {
		logger.Fatalf("ssh: the server host is required")
		return
	}
	port := sc.Port
	if port <= 0 {
		port = 22
	}
	if sc.User == "" {
		logger.Fatalf("ssh: the username is required")
		return
	}
	bind := sc.SocksBind
	if bind == "" {
		bind = "127.0.0.1"
	}
	if sc.SocksPort <= 0 {
		logger.Fatalf("ssh: a SOCKS5 port is required")
		return
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(sc.SocksPort)))
	if err != nil {
		logger.Fatalf("ssh: cannot open the SOCKS5 port %d: %v", sc.SocksPort, err)
		return
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
		metrics.ClearPeer()
	}()

	server := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            sc.User,
		Auth:            []ssh.AuthMethod{ssh.Password(sc.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // trust-on-first-use; see package doc
		Timeout:         15 * time.Second,
	}

	logger.Infof("ssh client: connecting to %s@%s, SOCKS5 on %s", sc.User, server, ln.Addr())
	runWithReconnect(ctx, server, cfg, ln, logger)
}

// runWithReconnect (re)establishes the SSH connection and serves SOCKS5 over it,
// backing off between attempts. Each successful connection serves until it drops
// or ctx ends.
func runWithReconnect(ctx context.Context, server string, cfg *ssh.ClientConfig, ln net.Listener, logger *logrus.Logger) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		client, err := dial(ctx, server, cfg)
		if err != nil {
			metrics.ClearPeer()
			logger.Warnf("ssh client: connect failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		metrics.ReportPeer(server)
		logger.Infof("ssh client: connected to %s", server)

		// A SOCKS dial opens a direct-tcpip channel from the SSH server to the
		// target, so the traffic egresses at the server.
		dialThrough := func(dctx context.Context, network, address string) (net.Conn, error) {
			return client.Dial(network, address)
		}

		serveCtx, cancel := context.WithCancel(ctx)
		go socksproxy.Serve(serveCtx, ln, dialThrough, logger)

		// Block until the connection drops or ctx ends.
		waitClosed(ctx, client)
		cancel()
		client.Close()
		metrics.ClearPeer()
		if ctx.Err() != nil {
			return
		}
		logger.Warnf("ssh client: connection lost, reconnecting...")
	}
}

func dial(ctx context.Context, server string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, server, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// waitClosed returns when the SSH connection closes or ctx ends. A keepalive
// request doubles as the liveness probe.
func waitClosed(ctx context.Context, client *ssh.Client) {
	closed := make(chan struct{})
	go func() {
		client.Wait() // returns when the underlying connection is gone
		close(closed)
	}()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if _, _, err := client.SendRequest("keepalive@arange-tun", true, nil); err != nil {
				return
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
