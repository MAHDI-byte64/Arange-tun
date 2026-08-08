// Package frp is Arange-tun's own reverse-proxy tunnel — a small, self-contained
// protocol written from scratch, with no external binary and nothing borrowed
// from any other frp project but the three letters.
//
// It is a reverse tunnel in the same shape as the built-in Amin engine: the
// abroad/kharej side always dials out, the Iran side accepts that one control
// connection and then drives every forwarded stream over it. Because it is just
// another transport value ("frp"), it reuses the whole Amin lifecycle — the same
// config file, systemd unit, status, logs and details — so from the panel it is
// managed exactly like an Amin tunnel and lives in the same list.
//
// The wire protocol, end to end:
//
//	handshake  client → server:  MAGIC ‖ token          (one length-framed blob)
//	           server → client:  0x01 accept / 0x00 deny (one byte)
//	transport  a smux session over the same TCP connection. The Iran side opens
//	           streams (smux client); the kharej side accepts them (smux server).
//	per stream server → client:  target address          (one length-framed blob)
//	           then the stream carries the forwarded connection, byte for byte.
//
// One kharej client is served at a time: a fresh successful handshake replaces
// the previous session (most-recent-wins), which is what lets a restarted client
// take over cleanly without the server needing to notice the old one has gone.
package frp

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

// magic prefixes the handshake so a stray connection — a health probe, a port
// scanner, the wrong protocol — is rejected immediately instead of being read as
// a token. It is not a secret; the token is.
var magic = []byte("ARANGE-FRP/1")

// maxFrame caps a length-framed control blob (handshake token, target address).
// These are tiny by nature; the cap is only there so a malformed length can
// never ask for an unbounded allocation.
const maxFrame = 4096

// handshakeTimeout bounds how long a half-open connection may sit mid-handshake
// before it is dropped, so a peer that connects and then says nothing cannot tie
// up the accept path.
const handshakeTimeout = 10 * time.Second

// smuxConfig is the multiplexer tuning both ends must agree on. The keepalive is
// what lets each side notice a silently dead peer and tear the session down.
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 40 * time.Second
	return c
}

// writeFrame writes a 2-byte big-endian length followed by the payload.
func writeFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return fmt.Errorf("frame too large: %d", len(b))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// readFrame reads a frame written by writeFrame, refusing an oversized length.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxFrame {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---------------------------------------------------------------------------
// Server (Iran side): accepts the kharej control connection, then drives every
// forwarded stream out over it.
// ---------------------------------------------------------------------------

type server struct {
	cfg    *config.ServerConfig
	logger *logrus.Logger
	token  []byte

	mu      sync.Mutex
	session *smux.Session // the current kharej client, or nil when none is up
}

// RunServer runs the Iran side until ctx ends. It listens on the tunnel bind
// address for the kharej client, and on every exposed port for user traffic.
func RunServer(ctx context.Context, cfg *config.ServerConfig, logger *logrus.Logger) {
	s := &server{cfg: cfg, logger: logger, token: []byte(cfg.Token)}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.BindAddr)
	if err != nil {
		logger.Fatalf("frp: cannot listen on %s: %v", cfg.BindAddr, err)
		return
	}
	defer ln.Close()
	logger.Infof("frp server: waiting for a client on %s", cfg.BindAddr)

	// Every exposed port gets its own listener up front; each blocks until a
	// client session exists, so users get a clean refusal rather than a hang
	// while the kharej side is still connecting.
	for _, mapping := range s.mappings() {
		go s.serveExposed(ctx, mapping)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warnf("frp server: accept error: %v", err)
				continue
			}
		}
		go s.handleControl(ctx, conn)
	}
}

// handleControl runs the handshake on an incoming connection and, if it checks
// out, installs it as the live session — displacing any previous one.
func (s *server) handleControl(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	blob, err := readFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	if len(blob) < len(magic) || subtle.ConstantTimeCompare(blob[:len(magic)], magic) != 1 {
		conn.Close()
		return
	}
	got := blob[len(magic):]
	if subtle.ConstantTimeCompare(got, s.token) != 1 {
		s.logger.Warnf("frp server: rejected client %s — bad token", conn.RemoteAddr())
		_, _ = conn.Write([]byte{0x00})
		conn.Close()
		return
	}
	if _, err := conn.Write([]byte{0x01}); err != nil {
		conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{}) // the session manages its own liveness now

	// Iran opens streams, so it is the smux client.
	sess, err := smux.Client(conn, smuxConfig())
	if err != nil {
		conn.Close()
		return
	}

	s.mu.Lock()
	if old := s.session; old != nil {
		old.Close()
	}
	s.session = sess
	s.mu.Unlock()

	peer := conn.RemoteAddr().String()
	metrics.ReportPeer(peer)
	s.logger.Infof("frp server: client %s connected", peer)

	// Hold here until the session dies, then retire it if it is still the live
	// one (a newer client may already have replaced it).
	<-sessionClosed(sess)
	s.mu.Lock()
	if s.session == sess {
		s.session = nil
		metrics.ClearPeer()
	}
	s.mu.Unlock()
	sess.Close()
	s.logger.Infof("frp server: client %s disconnected", peer)
}

// current returns the live client session, or nil when no client is connected.
func (s *server) current() *smux.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

// serveExposed listens on one exposed port and, for each user connection, opens
// a stream to the client that carries it to the real service.
func (s *server) serveExposed(ctx context.Context, m mapping) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", m.listen)
	if err != nil {
		s.logger.Errorf("frp server: cannot listen on %s: %v", m.listen, err)
		return
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s.logger.Infof("frp server: exposing %s → %s", m.listen, m.target)

	for {
		user, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.forward(user, m.target)
	}
}

// forward carries one user connection to the client over a fresh stream. The
// target address is sent first, then the two are spliced together.
func (s *server) forward(user net.Conn, target string) {
	defer user.Close()

	sess := s.current()
	if sess == nil {
		return // no client connected yet — drop it, the user can retry
	}
	stream, err := sess.OpenStream()
	if err != nil {
		s.logger.Debugf("frp server: cannot open stream: %v", err)
		return
	}
	defer stream.Close()

	if err := writeFrame(stream, []byte(target)); err != nil {
		return
	}
	pipe(user, stream)
}

// mapping is one exposed-port rule: a local listen address on the Iran side and
// the address the kharej client dials for it.
type mapping struct {
	listen string // e.g. ":443"
	target string // e.g. "127.0.0.1:2096"
}

// mappings expands the configured Ports into concrete listen/target pairs,
// accepting the same forms the rest of the tool uses: "443", "443=2096",
// "443=127.0.0.1:2096" and "8000-8010".
func (s *server) mappings() []mapping {
	var out []mapping
	for _, raw := range s.cfg.Ports {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		left, right, hasRight := strings.Cut(raw, "=")
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)

		lo, hi, isRange := portRange(left)
		if isRange {
			for port := lo; port <= hi; port++ {
				out = append(out, mapping{
					listen: fmt.Sprintf(":%d", port),
					target: normalizeTarget(strconv.Itoa(port)),
				})
			}
			continue
		}

		// A single "port" or "ip:port" on the left is the listen side.
		listen := left
		if _, err := strconv.Atoi(left); err == nil {
			listen = ":" + left
		}
		target := left
		if hasRight && right != "" {
			target = right
		}
		out = append(out, mapping{listen: listen, target: normalizeTarget(target)})
	}
	return out
}

// portRange parses "8000-8010" into its bounds. It reports isRange=false for
// anything that is not a valid ascending numeric range.
func portRange(s string) (lo, hi int, isRange bool) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// normalizeTarget turns a target spec into a host:port the client can dial. A
// bare port means the loopback service on the kharej box, which is the usual
// case: the service runs on the same machine the client does.
func normalizeTarget(spec string) string {
	spec = strings.TrimSpace(spec)
	if _, err := strconv.Atoi(spec); err == nil {
		return "127.0.0.1:" + spec
	}
	return spec
}

// ---------------------------------------------------------------------------
// Client (abroad / kharej side): dials the Iran server, then forwards each
// stream it is handed to the real local service.
// ---------------------------------------------------------------------------

// RunClient runs the kharej side until ctx ends, redialing with backoff whenever
// the session drops.
func RunClient(ctx context.Context, cfg *config.ClientConfig, logger *logrus.Logger) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := dialAndServe(ctx, cfg, logger); err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warnf("frp client: %v — retrying in %s", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second // a clean run resets the retry delay
	}
}

// dialAndServe brings up one session and serves streams until it ends.
func dialAndServe(ctx context.Context, cfg *config.ClientConfig, logger *logrus.Logger) error {
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := d.DialContext(dialCtx, "tcp", cfg.RemoteAddr)
	cancel()
	if err != nil {
		return fmt.Errorf("cannot reach server %s: %w", cfg.RemoteAddr, err)
	}

	// Handshake: announce ourselves, then wait for the one-byte verdict.
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := writeFrame(conn, append(append([]byte{}, magic...), []byte(cfg.Token)...)); err != nil {
		conn.Close()
		return fmt.Errorf("handshake write failed: %w", err)
	}
	var verdict [1]byte
	if _, err := io.ReadFull(conn, verdict[:]); err != nil {
		conn.Close()
		return fmt.Errorf("handshake read failed: %w", err)
	}
	if verdict[0] != 0x01 {
		conn.Close()
		return fmt.Errorf("server rejected the token")
	}
	_ = conn.SetDeadline(time.Time{})

	// Iran opens streams, so the kharej side accepts them: smux server.
	sess, err := smux.Server(conn, smuxConfig())
	if err != nil {
		conn.Close()
		return fmt.Errorf("mux setup failed: %w", err)
	}
	defer sess.Close()

	metrics.ReportPeer(cfg.RemoteAddr)
	defer metrics.ClearPeer()
	logger.Infof("frp client: connected to %s", cfg.RemoteAddr)

	go func() {
		<-ctx.Done()
		sess.Close()
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("session closed: %w", err)
		}
		go serveStream(stream, logger)
	}
}

// serveStream reads the target from a stream and pipes it to the local service.
func serveStream(stream *smux.Stream, logger *logrus.Logger) {
	defer stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
	tgt, err := readFrame(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	target := string(tgt)
	local, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Debugf("frp client: cannot reach %s: %v", target, err)
		return
	}
	defer local.Close()
	pipe(local, stream)
}

// ---------------------------------------------------------------------------
// Shared plumbing.
// ---------------------------------------------------------------------------

// pipe splices a local connection and a tunnel stream together, counting the
// traffic that crosses the tunnel so the panel shows it. Reads from the stream
// are traffic in; writes to it are traffic out — the same convention the other
// transports report. It returns once either side closes.
func pipe(local net.Conn, stream *smux.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Tunnel → local: bytes arriving from the peer.
	go func() {
		defer wg.Done()
		copyCounted(local, stream, true)
		if c, ok := local.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			local.Close()
		}
		stream.Close()
	}()

	// Local → tunnel: bytes leaving toward the peer.
	go func() {
		defer wg.Done()
		copyCounted(stream, local, false)
		stream.Close()
		local.Close()
	}()

	wg.Wait()
}

// copyCounted copies src→dst in chunks, reporting each chunk as tunnel traffic.
// inbound picks which direction of the meter it lands on.
func copyCounted(dst io.Writer, src io.Reader, inbound bool) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if inbound {
				metrics.AddBytes(uint64(n), 0)
			} else {
				metrics.AddBytes(0, uint64(n))
			}
		}
		if rerr != nil {
			return
		}
	}
}

// sessionClosed returns a channel that is closed once the smux session ends, so
// a goroutine can wait on it with a plain receive.
func sessionClosed(sess *smux.Session) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		<-sess.CloseChan()
		close(ch)
	}()
	return ch
}
