// Package rathole is a Go port of the rathole reverse-proxy protocol
// (github.com/rapiz1/rathole, Apache-2.0), reimplemented from its source rather
// than shelling out to any binary. It shares no code with the built-in frp
// tunnel: where frp multiplexes every forwarded connection as smux streams over
// one TCP connection, rathole is built the way the original is — a single
// control channel that only carries commands, and a pool of separate TCP
// connections ("data channels"), one per forwarded connection.
//
// The protocol, faithful to rathole:
//
//	control  client → server:  Hello::ControlChannelHello(v1, sha256(service))
//	         server → client:  Hello::ControlChannelHello(v1, nonce)
//	         client → server:  Auth(sha256(token ‖ nonce))
//	         server → client:  Ack::Ok            (or AuthFailed / ServiceNotExist)
//	         server → client:  ControlChannelCmd::CreateDataChannel  (per visitor)
//	         server → client:  ControlChannelCmd::HeartBeat          (periodic)
//	data     client → server:  Hello::DataChannelHello(v1, session_key)
//	         server → client:  DataChannelCmd::StartForwardTcp / …Udp
//	         then the connection carries the forwarded traffic.
//
// The control messages use rathole's fixed-size bincode layout: an enum
// discriminant is a little-endian u32, a version is one byte, a digest is 32
// raw bytes. Two things are adapted to Arange-tun's single-tunnel config, in
// which the Iran server holds the whole port map rather than the kharej client:
// the server sends the forward target after the StartForward command (the
// original client already knows its own local_addr), and UDP's per-source
// framing carries the source address as a length-prefixed string rather than a
// serialized SocketAddr. Both ends here are this code, so this stays internally
// consistent while keeping rathole's architecture intact.
package rathole

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/mahdi-byte64/arange-tun/internal/utils/network"

	"github.com/sirupsen/logrus"
)

const (
	protoVersion byte = 1 // rathole PROTO_V1
	hashWidth         = 32

	handshakeTimeout  = 10 * time.Second
	heartbeatInterval = 30 * time.Second
	dataChannelWait   = 15 * time.Second
	udpIdleTimeout    = 60 * time.Second
	udpBufSize        = 65535
	tcpPoolWarm       = 2 // data channels pre-requested for latency, like rathole's pool
)

// Hello enum discriminants (bincode u32).
const (
	helloControl uint32 = 0
	helloData    uint32 = 1
)

// Ack enum discriminants.
const (
	ackOk              uint32 = 0
	ackServiceNotExist uint32 = 1
	ackAuthFailed      uint32 = 2
)

// ControlChannelCmd discriminants.
const (
	cmdCreateDataChannel uint32 = 0
	cmdHeartBeat         uint32 = 1
)

// DataChannelCmd discriminants.
const (
	cmdStartForwardTCP uint32 = 0
	cmdStartForwardUDP uint32 = 1
)

// sinkAndClose swallows whatever a rejected connection sends for a moment, then
// closes it — so a failed handshake produces no distinctive response for an
// active probe to fingerprint.
func sinkAndClose(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<16))
	conn.Close()
}

// sessionKey is sha256(token ‖ nonce) — the value that both authenticates the
// control channel and, echoed back in a DataChannelHello, routes a data channel
// to it.
func sessionKey(token string, nonce []byte) [32]byte {
	concat := make([]byte, 0, len(token)+len(nonce))
	concat = append(concat, []byte(token)...)
	concat = append(concat, nonce...)
	return sha256.Sum256(concat)
}

// ---------------------------------------------------------------------------
// Wire encoding (rathole's fixed-size bincode messages).
// ---------------------------------------------------------------------------

// writeHello writes a 37-byte Hello: [u32 variant][u8 version][32 digest].
func writeHello(w io.Writer, variant uint32, d [32]byte) error {
	var buf [37]byte
	binary.LittleEndian.PutUint32(buf[0:4], variant)
	buf[4] = protoVersion
	copy(buf[5:37], d[:])
	_, err := w.Write(buf[:])
	return err
}

// readHello reads a 37-byte Hello, returning its variant and digest.
func readHello(r io.Reader) (variant uint32, d [32]byte, err error) {
	var buf [37]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return
	}
	variant = binary.LittleEndian.Uint32(buf[0:4])
	copy(d[:], buf[5:37])
	return
}

// writeU32 / readU32 carry an Auth digest-less discriminant message (Ack, cmds).
func writeU32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func readU32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// writeAuth / readAuth carry the 32-byte session key.
func writeAuth(w io.Writer, d [32]byte) error { _, err := w.Write(d[:]); return err }
func readAuth(r io.Reader) ([32]byte, error) {
	var d [32]byte
	_, err := io.ReadFull(r, d[:])
	return d, err
}

// writeFrame / readFrame carry a short length-prefixed blob — the forward target
// the server appends after StartForward. 2-byte big-endian length.
func writeFrame(w io.Writer, b []byte) error {
	if len(b) > 65535 {
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

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---------------------------------------------------------------------------
// Server (Iran side).
// ---------------------------------------------------------------------------

// controlChannel is one connected kharej client: the control connection itself,
// its session key, and the pool of data channels it has opened.
type controlChannel struct {
	conn    net.Conn
	key     [32]byte
	dataCh  chan net.Conn // data channels this client has opened, awaiting a visitor
	reqCh   chan struct{} // requests for the client to open another data channel
	closed  chan struct{}
	closeMu sync.Once
}

func (c *controlChannel) close() {
	c.closeMu.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

type server struct {
	cfg    *config.ServerConfig
	logger *logrus.Logger
	token  string
	udp    bool

	mu      sync.Mutex
	current *controlChannel
}

// RunServer runs the Iran side until ctx ends. When udp is set the exposed ports
// carry UDP; otherwise TCP.
func RunServer(ctx context.Context, cfg *config.ServerConfig, logger *logrus.Logger, udp bool) {
	s := &server{cfg: cfg, logger: logger, token: cfg.Token, udp: udp}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.BindAddr)
	if err != nil {
		logger.Fatalf("rathole: cannot listen on %s: %v", cfg.BindAddr, err)
		return
	}
	defer ln.Close()
	logger.Infof("rathole server: waiting for a client on %s", cfg.BindAddr)

	// Exposed-port listeners persist across client reconnects; each blocks until
	// a control channel exists.
	for _, m := range s.mappings() {
		if s.udp {
			go s.serveExposedUDP(ctx, m)
		} else {
			go s.serveExposedTCP(ctx, m)
		}
	}

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warnf("rathole server: accept error: %v", err)
				continue
			}
		}
		go s.handleIncoming(ctx, conn)
	}
}

// handleIncoming reads the opening Hello and routes the connection: a control
// hello starts an authentication, a data hello joins an existing control
// channel's pool.
func (s *server) handleIncoming(ctx context.Context, conn net.Conn) {
	// Stealth: wrap every connection — control and data channels alike — in the
	// Noise record layer first, so nothing after the TCP connect has a
	// fingerprint and a peer without the token is dropped without a reply.
	if s.cfg.Stealth {
		wrapped, err := network.NoiseServerConn(conn, s.token, handshakeTimeout)
		if err != nil {
			conn.Close()
			return
		}
		conn = wrapped
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	variant, d, err := readHello(conn)
	if err != nil {
		conn.Close()
		return
	}
	switch variant {
	case helloControl:
		s.controlHandshake(ctx, conn)
	case helloData:
		s.routeDataChannel(conn, d)
	default:
		conn.Close()
	}
}

// controlHandshake runs rathole's control-channel handshake, then installs the
// connection as the live client (displacing any previous one) and drives its
// command loop.
func (s *server) controlHandshake(ctx context.Context, conn net.Conn) {
	// Send our nonce.
	var nonce [hashWidth]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return
	}
	if err := writeHello(conn, helloControl, nonce); err != nil {
		conn.Close()
		return
	}

	// Read the client's Auth and validate it against sha256(token ‖ nonce).
	got, err := readAuth(conn)
	if err != nil {
		conn.Close()
		return
	}
	key := sessionKey(s.token, nonce[:])
	if subtle.ConstantTimeCompare(got[:], key[:]) != 1 {
		// No distinctive rejection (the AuthFailed ack is a fingerprint an active
		// probe could match); drain quietly and drop instead.
		sinkAndClose(conn)
		return
	}
	if err := writeU32(conn, ackOk); err != nil {
		conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	cc := &controlChannel{
		conn:   conn,
		key:    key,
		dataCh: make(chan net.Conn, 16),
		reqCh:  make(chan struct{}, 64),
		closed: make(chan struct{}),
	}

	s.mu.Lock()
	if old := s.current; old != nil {
		old.close()
	}
	s.current = cc
	s.mu.Unlock()

	peer := conn.RemoteAddr().String()
	metrics.ReportPeer(peer)
	s.logger.Infof("rathole server: client %s connected", peer)

	// Pre-warm a few data channels so the first visitors do not wait a round trip.
	for i := 0; i < tcpPoolWarm; i++ {
		cc.reqCh <- struct{}{}
	}

	s.runControl(ctx, cc)

	s.mu.Lock()
	if s.current == cc {
		s.current = nil
		metrics.ClearPeer()
	}
	s.mu.Unlock()
	cc.close()
	s.logger.Infof("rathole server: client %s disconnected", peer)
}

// runControl writes CreateDataChannel on request and HeartBeat on a timer, until
// the connection breaks or ctx ends. rathole's control channel is server→client
// only after the handshake.
func (s *server) runControl(ctx context.Context, cc *controlChannel) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cc.closed:
			return
		case <-cc.reqCh:
			if err := writeU32(cc.conn, cmdCreateDataChannel); err != nil {
				return
			}
		case <-ticker.C:
			if err := writeU32(cc.conn, cmdHeartBeat); err != nil {
				return
			}
		}
	}
}

// routeDataChannel hands a freshly opened data channel to the control channel
// whose session key it presented.
func (s *server) routeDataChannel(conn net.Conn, key [32]byte) {
	_ = conn.SetDeadline(time.Time{})
	s.mu.Lock()
	cc := s.current
	s.mu.Unlock()
	if cc == nil || subtle.ConstantTimeCompare(cc.key[:], key[:]) != 1 {
		conn.Close()
		return
	}
	select {
	case cc.dataCh <- conn:
	case <-cc.closed:
		conn.Close()
	case <-time.After(dataChannelWait):
		conn.Close() // nobody claimed it
	}
}

// acquireDataChannel asks the current client for a data channel and waits for
// one to arrive. It returns nil when no client is connected or none arrives.
func (s *server) acquireDataChannel() net.Conn {
	s.mu.Lock()
	cc := s.current
	s.mu.Unlock()
	if cc == nil {
		return nil
	}
	select {
	case cc.reqCh <- struct{}{}:
	default: // request queue full — a data channel is likely already coming
	}
	select {
	case dc := <-cc.dataCh:
		return dc
	case <-cc.closed:
		return nil
	case <-time.After(dataChannelWait):
		return nil
	}
}

// serveExposedTCP listens on one exposed TCP port; each visitor takes a data
// channel, is told the forward target, and is spliced to it.
func (s *server) serveExposedTCP(ctx context.Context, m mapping) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", m.listen)
	if err != nil {
		s.logger.Errorf("rathole server: cannot listen on %s: %v", m.listen, err)
		return
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	s.logger.Infof("rathole server: exposing %s → %s", m.listen, m.target)

	for {
		visitor, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.forwardTCP(visitor, m.target)
	}
}

func (s *server) forwardTCP(visitor net.Conn, target string) {
	defer visitor.Close()
	dc := s.acquireDataChannel()
	if dc == nil {
		return
	}
	defer dc.Close()
	if err := writeU32(dc, cmdStartForwardTCP); err != nil {
		return
	}
	if err := writeFrame(dc, []byte(target)); err != nil {
		return
	}
	pipe(dc, visitor)
}

// serveExposedUDP listens on one exposed UDP port and multiplexes every source's
// datagrams over a single data channel, rathole-style. The data channel is
// re-acquired if it drops.
func (s *server) serveExposedUDP(ctx context.Context, m mapping) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", m.listen)
	if err != nil {
		s.logger.Errorf("rathole server: cannot listen (udp) on %s: %v", m.listen, err)
		return
	}
	defer pc.Close()
	go func() { <-ctx.Done(); pc.Close() }()
	s.logger.Infof("rathole server: exposing %s → %s (udp)", m.listen, m.target)

	for ctx.Err() == nil {
		dc := s.acquireDataChannel()
		if dc == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		if err := writeU32(dc, cmdStartForwardUDP); err != nil {
			dc.Close()
			continue
		}
		if err := writeFrame(dc, []byte(m.target)); err != nil {
			dc.Close()
			continue
		}
		s.runUDPServer(ctx, pc, dc)
		dc.Close()
	}
}

// runUDPServer shuttles datagrams between the public UDP socket and one data
// channel until the data channel breaks. A datagram to the client is framed with
// its source; a datagram back names the source to send it to.
func (s *server) runUDPServer(ctx context.Context, pc net.PacketConn, dc net.Conn) {
	var seenMu sync.Mutex
	seen := make(map[string]net.Addr)

	done := make(chan struct{})
	// Data channel → public socket.
	go func() {
		defer close(done)
		for {
			from, data, err := readUDP(dc)
			if err != nil {
				return
			}
			seenMu.Lock()
			addr := seen[from]
			seenMu.Unlock()
			if addr != nil {
				if _, err := pc.WriteTo(data, addr); err != nil {
					return
				}
				metrics.AddBytes(uint64(len(data)), 0)
			}
		}
	}()

	// Public socket → data channel.
	buf := make([]byte, udpBufSize)
	var writeMu sync.Mutex
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			return
		}
		seenMu.Lock()
		seen[addr.String()] = addr
		seenMu.Unlock()
		writeMu.Lock()
		err = writeUDP(dc, addr.String(), buf[:n])
		writeMu.Unlock()
		if err != nil {
			return
		}
		metrics.AddBytes(0, uint64(n))
	}
}

// mapping is one exposed-port rule.
type mapping struct {
	listen string
	target string
}

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

		if lo, hi, ok := portRange(left); ok {
			for port := lo; port <= hi; port++ {
				out = append(out, mapping{listen: fmt.Sprintf(":%d", port), target: normalizeTarget(strconv.Itoa(port))})
			}
			continue
		}

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

func portRange(s string) (lo, hi int, ok bool) {
	a, b, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	lo, e1 := strconv.Atoi(strings.TrimSpace(a))
	hi, e2 := strconv.Atoi(strings.TrimSpace(b))
	if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func normalizeTarget(spec string) string {
	spec = strings.TrimSpace(spec)
	if _, err := strconv.Atoi(spec); err == nil {
		return "127.0.0.1:" + spec
	}
	return spec
}

// ---------------------------------------------------------------------------
// Client (abroad / kharej side).
// ---------------------------------------------------------------------------

// RunClient runs the kharej side until ctx ends, redialing with backoff whenever
// the control channel drops.
func RunClient(ctx context.Context, cfg *config.ClientConfig, logger *logrus.Logger) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := runControlClient(ctx, cfg, logger); err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warnf("rathole client: %v — retrying in %s", err, backoff)
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
		backoff = time.Second
	}
}

// runControlClient brings up one control channel and reacts to its commands
// until it ends.
func runControlClient(ctx context.Context, cfg *config.ClientConfig, logger *logrus.Logger) error {
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := d.DialContext(dctx, "tcp", cfg.RemoteAddr)
	cancel()
	if err != nil {
		return fmt.Errorf("cannot reach server %s: %w", cfg.RemoteAddr, err)
	}

	if cfg.Stealth {
		wrapped, werr := network.NoiseClientConn(conn, cfg.Token, handshakeTimeout)
		if werr != nil {
			conn.Close()
			return fmt.Errorf("stealth handshake failed: %w", werr)
		}
		conn = wrapped
	}

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	// The Hello's digest field would normally be sha256(service name) — a
	// constant, and therefore a DPI signature. With a single logical service the
	// server does not look it up, so a random value goes here instead and nothing
	// fixed travels the wire.
	var svc [32]byte
	if _, err := rand.Read(svc[:]); err != nil {
		conn.Close()
		return fmt.Errorf("hello salt failed: %w", err)
	}
	if err := writeHello(conn, helloControl, svc); err != nil {
		conn.Close()
		return fmt.Errorf("hello write failed: %w", err)
	}
	// Read the server's nonce, derive the session key, send Auth.
	variant, nonce, err := readHello(conn)
	if err != nil || variant != helloControl {
		conn.Close()
		return fmt.Errorf("bad server hello: %w", err)
	}
	key := sessionKey(cfg.Token, nonce[:])
	if err := writeAuth(conn, key); err != nil {
		conn.Close()
		return fmt.Errorf("auth write failed: %w", err)
	}
	ack, err := readU32(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ack read failed: %w", err)
	}
	if ack != ackOk {
		conn.Close()
		switch ack {
		case ackAuthFailed:
			return fmt.Errorf("server rejected the token")
		case ackServiceNotExist:
			return fmt.Errorf("server has no matching service")
		default:
			return fmt.Errorf("server refused the control channel (ack %d)", ack)
		}
	}
	_ = conn.SetDeadline(time.Time{})

	metrics.ReportPeer(cfg.RemoteAddr)
	defer metrics.ClearPeer()
	logger.Infof("rathole client: connected to %s", cfg.RemoteAddr)

	go func() { <-ctx.Done(); conn.Close() }()

	// Command loop: open a data channel on request, ignore heartbeats.
	for {
		cmd, err := readU32(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control channel closed: %w", err)
		}
		switch cmd {
		case cmdCreateDataChannel:
			go openDataChannel(ctx, cfg, key, logger)
		case cmdHeartBeat:
			// keep-alive only
		}
	}
}

// openDataChannel opens one data channel, presents the session key, and forwards
// whatever the server asks it to.
func openDataChannel(ctx context.Context, cfg *config.ClientConfig, key [32]byte, logger *logrus.Logger) {
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := d.DialContext(dctx, "tcp", cfg.RemoteAddr)
	cancel()
	if err != nil {
		logger.Debugf("rathole client: data channel dial failed: %v", err)
		return
	}
	if cfg.Stealth {
		wrapped, werr := network.NoiseClientConn(conn, cfg.Token, handshakeTimeout)
		if werr != nil {
			conn.Close()
			return
		}
		conn = wrapped
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := writeHello(conn, helloData, key); err != nil {
		return
	}
	cmd, err := readU32(conn)
	if err != nil {
		return
	}
	target, err := readFrame(conn)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case cmdStartForwardTCP:
		local, err := net.DialTimeout("tcp", string(target), 10*time.Second)
		if err != nil {
			logger.Debugf("rathole client: cannot reach %s: %v", target, err)
			return
		}
		defer local.Close()
		pipe(conn, local)
	case cmdStartForwardUDP:
		runUDPClient(conn, string(target), logger)
	}
}

// runUDPClient services the UDP multiplex on one data channel: it keeps a local
// UDP socket per visitor source, forwarding datagrams both ways.
func runUDPClient(dc net.Conn, target string, logger *logrus.Logger) {
	type flow struct {
		conn net.Conn
	}
	var mu sync.Mutex
	flows := make(map[string]*flow)
	var writeMu sync.Mutex

	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.conn.Close()
		}
		mu.Unlock()
	}()

	for {
		from, data, err := readUDP(dc)
		if err != nil {
			return
		}
		mu.Lock()
		f := flows[from]
		if f == nil {
			local, derr := net.DialTimeout("udp", target, 10*time.Second)
			if derr != nil {
				mu.Unlock()
				logger.Debugf("rathole client: cannot reach %s (udp): %v", target, derr)
				continue
			}
			f = &flow{conn: local}
			flows[from] = f
			// Replies from the service go back framed with this source.
			go func(fromKey string, local net.Conn) {
				buf := make([]byte, udpBufSize)
				for {
					_ = local.SetReadDeadline(time.Now().Add(udpIdleTimeout))
					n, rerr := local.Read(buf)
					if n > 0 {
						writeMu.Lock()
						werr := writeUDP(dc, fromKey, buf[:n])
						writeMu.Unlock()
						if werr != nil {
							break
						}
						metrics.AddBytes(uint64(n), 0)
					}
					if rerr != nil {
						break
					}
				}
				local.Close()
				mu.Lock()
				delete(flows, fromKey)
				mu.Unlock()
			}(from, local)
		}
		conn := f.conn
		mu.Unlock()

		if _, err := conn.Write(data); err != nil {
			continue
		}
		metrics.AddBytes(0, uint64(len(data)))
	}
}

// ---------------------------------------------------------------------------
// UDP framing and plumbing.
// ---------------------------------------------------------------------------

// writeUDP frames one datagram for a data channel: [u16 addrLen][addr][u16
// dataLen][data]. The address is the visitor's source, echoed so the far end
// can route the datagram — rathole's UdpTraffic, with the source as a string.
func writeUDP(w io.Writer, from string, data []byte) error {
	if len(from) > 65535 || len(data) > 65535 {
		return fmt.Errorf("udp frame too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(from)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, from); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readUDP(r io.Reader) (from string, data []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	fb := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err = io.ReadFull(r, fb); err != nil {
		return
	}
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	data = make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	return string(fb), data, nil
}

// pipe splices a tunnel connection and a local connection, counting the traffic
// that crosses the tunnel. Reads from the tunnel are traffic in; writes to it
// are traffic out. It returns once either side closes.
func pipe(tunnel, local net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyCounted(local, tunnel, true) // tunnel → local
		if c, ok := local.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			local.Close()
		}
		tunnel.Close()
	}()
	go func() {
		defer wg.Done()
		copyCounted(tunnel, local, false) // local → tunnel
		tunnel.Close()
		local.Close()
	}()
	wg.Wait()
}

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
