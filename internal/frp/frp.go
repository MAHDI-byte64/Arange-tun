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
//
// The opening handshake carries no constant bytes, so deep packet inspection has
// no fixed signature to match: the client sends a random 16-byte salt followed
// by HMAC-SHA256(token, salt), and the server recomputes it. A connection that
// fails the check is not answered with a distinctive rejection — it is drained
// quietly and dropped, so an active probe cannot tell the port apart from a dead
// one.
package frp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"
	"github.com/mahdi-byte64/arange-tun/internal/utils/network"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

const (
	saltLen  = 16
	proofLen = 32 // sha256 output
)

// authProof is HMAC-SHA256(token, salt): the value a client proves it knows the
// token by. It looks random on the wire and differs every connection.
func authProof(token, salt []byte) []byte {
	h := hmac.New(sha256.New, token)
	h.Write(salt)
	return h.Sum(nil)
}

// sinkAndClose swallows whatever a rejected connection sends for a moment, then
// closes it — so a bad handshake produces no distinctive response for a probe to
// fingerprint, just a socket that accepted data and went quiet.
func sinkAndClose(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<16))
	conn.Close()
}

// maxFrame caps a length-framed blob. Control blobs (handshake token, target
// address) are tiny; a UDP datagram frame can be as large as a UDP payload
// gets, so the cap is the datagram ceiling. It exists so a malformed length can
// never ask for an unbounded allocation.
const maxFrame = 65535

// handshakeTimeout bounds how long a half-open connection may sit mid-handshake
// before it is dropped, so a peer that connects and then says nothing cannot tie
// up the accept path.
const handshakeTimeout = 10 * time.Second

// A stream opens with a one-byte mode telling the kharej side how to carry it:
// as a raw TCP connection, or as a run of framed UDP datagrams.
const (
	modeTCP byte = 0
	modeUDP byte = 1
)

// udpIdleTimeout retires a UDP flow that has gone quiet. UDP has no close, so a
// flow is only ever known to be over by its silence; without this a busy server
// would accumulate a stream per source address forever.
const udpIdleTimeout = 60 * time.Second

// udpBufSize is the read buffer for one datagram — large enough for any single
// UDP payload.
const udpBufSize = 65535

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
	udp    bool // expose the ports as UDP instead of TCP

	mu      sync.Mutex
	session *smux.Session // the current kharej client, or nil when none is up
}

// RunServer runs the Iran side until ctx ends. It listens on the tunnel bind
// address for the kharej client, and on every exposed port for user traffic.
// When udp is set the exposed ports carry UDP; otherwise they carry TCP.
func RunServer(ctx context.Context, cfg *config.ServerConfig, logger *logrus.Logger, udp bool) {
	s := &server{cfg: cfg, logger: logger, token: []byte(cfg.Token), udp: udp}

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
		if s.udp {
			go s.serveExposedUDP(ctx, mapping)
		} else {
			go s.serveExposed(ctx, mapping)
		}
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
	// Obfuscation: wrap the whole connection first — the Noise record layer
	// (random-looking) or a uTLS session (looks like HTTPS) — so everything after
	// the TCP connect is hidden. A peer that cannot complete the wrap is dropped.
	switch s.cfg.ObfsMode() {
	case "noise":
		wrapped, err := network.NoiseServerConn(conn, string(s.token), handshakeTimeout)
		if err != nil {
			conn.Close()
			return
		}
		conn = wrapped
	case "tls":
		wrapped, err := network.TLSServerConn(conn, handshakeTimeout)
		if err != nil {
			conn.Close()
			return
		}
		conn = wrapped
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	var hs [saltLen + proofLen]byte
	if _, err := io.ReadFull(conn, hs[:]); err != nil {
		conn.Close()
		return
	}
	salt, proof := hs[:saltLen], hs[saltLen:]
	if !hmac.Equal(proof, authProof(s.token, salt)) {
		// No distinctive rejection — drain quietly so a probe learns nothing.
		sinkAndClose(conn)
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
// mode and target are sent first, then the two are spliced together.
func (s *server) forward(user net.Conn, target string) {
	defer user.Close()

	stream := s.openTargetStream(modeTCP, target)
	if stream == nil {
		return
	}
	defer stream.Close()
	pipe(user, stream)
}

// openTargetStream opens a stream to the current client and writes the opening
// preamble — one mode byte then the target address. It returns nil when no
// client is connected or the stream could not be set up.
func (s *server) openTargetStream(mode byte, target string) *smux.Stream {
	sess := s.current()
	if sess == nil {
		return nil // no client connected yet — drop it, the user can retry
	}
	stream, err := sess.OpenStream()
	if err != nil {
		s.logger.Debugf("frp server: cannot open stream: %v", err)
		return nil
	}
	if _, err := stream.Write([]byte{mode}); err != nil {
		stream.Close()
		return nil
	}
	if err := writeFrame(stream, []byte(target)); err != nil {
		stream.Close()
		return nil
	}
	return stream
}

// serveExposedUDP listens on one exposed port as UDP and relays each source's
// datagrams over its own stream. UDP is connectionless, so a "flow" is invented
// per source address: the first datagram from an address opens a stream, and
// datagrams keep flowing over it until the flow falls idle.
func (s *server) serveExposedUDP(ctx context.Context, m mapping) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", m.listen)
	if err != nil {
		s.logger.Errorf("frp server: cannot listen (udp) on %s: %v", m.listen, err)
		return
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	s.logger.Infof("frp server: exposing %s → %s (udp)", m.listen, m.target)

	flows := newUDPFlows()
	defer flows.closeAll()
	go flows.reap(ctx)

	buf := make([]byte, udpBufSize)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		flow := flows.get(src.String())
		if flow == nil {
			stream := s.openTargetStream(modeUDP, m.target)
			if stream == nil {
				continue
			}
			flow = flows.add(src, stream)
			// Datagrams coming back from the service are written to the same
			// source address the flow was opened for.
			go func(f *udpFlow) {
				streamToPacket(f, pc)
				flows.remove(f.key)
			}(flow)
		}
		flow.touch()
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if err := writeFrame(flow.stream, payload); err != nil {
			flows.remove(flow.key)
			continue
		}
		metrics.AddBytes(0, uint64(n))
	}
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

	// Obfuscation: upgrade the connection before anything else, matching the
	// server's mode.
	switch cfg.ObfsMode() {
	case "noise":
		wrapped, werr := network.NoiseClientConn(conn, cfg.Token, handshakeTimeout)
		if werr != nil {
			conn.Close()
			return fmt.Errorf("obfuscation handshake failed: %w", werr)
		}
		conn = wrapped
	case "tls":
		sni := cfg.TLSSni
		if sni == "" {
			sni = network.SNIFromAddr(cfg.RemoteAddr)
		}
		wrapped, werr := network.TLSClientConn(conn, sni, handshakeTimeout)
		if werr != nil {
			conn.Close()
			return fmt.Errorf("obfuscation handshake failed: %w", werr)
		}
		conn = wrapped
	}

	// Handshake: a random salt and the token proof, no constant bytes, then wait
	// for the one-byte verdict.
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	hs := make([]byte, 0, saltLen+proofLen)
	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		conn.Close()
		return fmt.Errorf("handshake salt failed: %w", err)
	}
	hs = append(hs, salt[:]...)
	hs = append(hs, authProof([]byte(cfg.Token), salt[:])...)
	if _, err := conn.Write(hs); err != nil {
		conn.Close()
		return fmt.Errorf("handshake write failed: %w", err)
	}
	var verdict [1]byte
	if _, err := io.ReadFull(conn, verdict[:]); err != nil {
		conn.Close()
		return fmt.Errorf("handshake read failed (rejected?): %w", err)
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

// serveStream reads the opening preamble — a mode byte then the target — and
// forwards the stream to the local service as TCP or UDP accordingly.
func serveStream(stream *smux.Stream, logger *logrus.Logger) {
	defer stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
	var mode [1]byte
	if _, err := io.ReadFull(stream, mode[:]); err != nil {
		return
	}
	tgt, err := readFrame(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	target := string(tgt)

	if mode[0] == modeUDP {
		serveStreamUDP(stream, target, logger)
		return
	}

	local, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Debugf("frp client: cannot reach %s: %v", target, err)
		return
	}
	defer local.Close()
	pipe(local, stream)
}

// serveStreamUDP dials the local service over UDP and shuttles datagrams both
// ways: framed datagrams arriving on the stream are written to the socket, and
// replies are framed back onto the stream. The flow ends when the stream closes
// or the socket falls idle.
func serveStreamUDP(stream *smux.Stream, target string, logger *logrus.Logger) {
	uconn, err := net.DialTimeout("udp", target, 10*time.Second)
	if err != nil {
		logger.Debugf("frp client: cannot reach %s (udp): %v", target, err)
		return
	}
	defer uconn.Close()

	done := make(chan struct{})

	// Socket → stream: replies from the service, until the socket falls idle.
	go func() {
		defer close(done)
		buf := make([]byte, udpBufSize)
		for {
			_ = uconn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := uconn.Read(buf)
			if n > 0 {
				if werr := writeFrame(stream, buf[:n]); werr != nil {
					return
				}
				metrics.AddBytes(uint64(n), 0)
			}
			if err != nil {
				return
			}
		}
	}()

	// Stream → socket: datagrams from the user side.
	for {
		payload, err := readFrame(stream)
		if err != nil {
			break
		}
		if _, err := uconn.Write(payload); err != nil {
			break
		}
		metrics.AddBytes(0, uint64(len(payload)))
	}
	uconn.Close()
	<-done
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

// udpFlow is one source address's run of datagrams, carried on its own stream.
type udpFlow struct {
	key    string
	src    net.Addr
	stream *smux.Stream
	last   atomic.Int64 // unix-nano of the most recent datagram either way
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

// udpFlows tracks the live flows for one exposed UDP port, keyed by source
// address, and reaps the ones that fall idle.
type udpFlows struct {
	mu sync.Mutex
	m  map[string]*udpFlow
}

func newUDPFlows() *udpFlows { return &udpFlows{m: make(map[string]*udpFlow)} }

func (u *udpFlows) get(key string) *udpFlow {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.m[key]
}

func (u *udpFlows) add(src net.Addr, stream *smux.Stream) *udpFlow {
	f := &udpFlow{key: src.String(), src: src, stream: stream}
	f.touch()
	u.mu.Lock()
	u.m[f.key] = f
	u.mu.Unlock()
	return f
}

func (u *udpFlows) remove(key string) {
	u.mu.Lock()
	f := u.m[key]
	delete(u.m, key)
	u.mu.Unlock()
	if f != nil {
		f.stream.Close()
	}
}

func (u *udpFlows) closeAll() {
	u.mu.Lock()
	for _, f := range u.m {
		f.stream.Close()
	}
	u.m = make(map[string]*udpFlow)
	u.mu.Unlock()
}

// reap closes flows that have gone quiet for longer than udpIdleTimeout, so a
// server that has served many short UDP exchanges does not keep a stream open
// for every source address it has ever seen.
func (u *udpFlows) reap(ctx context.Context) {
	t := time.NewTicker(udpIdleTimeout / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
			u.mu.Lock()
			for key, f := range u.m {
				if f.last.Load() < cutoff {
					f.stream.Close()
					delete(u.m, key)
				}
			}
			u.mu.Unlock()
		}
	}
}

// streamToPacket reads framed datagrams from a flow's stream and writes each
// back to its source address over the shared packet socket, until the stream
// ends. Each datagram refreshes the flow's idle timer, so a long download with
// no upstream traffic is not reaped mid-transfer.
func streamToPacket(f *udpFlow, pc net.PacketConn) {
	for {
		payload, err := readFrame(f.stream)
		if err != nil {
			return
		}
		if _, err := pc.WriteTo(payload, f.src); err != nil {
			return
		}
		f.touch()
		metrics.AddBytes(uint64(len(payload)), 0)
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
