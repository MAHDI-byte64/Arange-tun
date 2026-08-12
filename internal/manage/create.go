package manage

import (
	"fmt"
	"net"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/optimize"
	"github.com/mahdi-byte64/arange-tun/internal/utils/network"
)

// TunnelRequest is a non-interactive description of a tunnel to create. It is
// the data the web panel collects from its form; every field mirrors something
// the interactive Setup flows in setup.go ask for. Turning it into a validated
// TunnelSpec and persisting it lives in CreateTunnel, so the CLI and the panel
// build tunnels through exactly the same building blocks (validation, presets,
// certificate generation, systemd unit, service start).
type TunnelRequest struct {
	Name      string `json:"name"`
	Role      string `json:"role"`      // "server" (Iran/edge) or "client" (kharej/origin)
	Transport string `json:"transport"` // tcp, tcpmux, udp, kcp, ws, wss, wsmux, wssmux, stealth, xdi
	Preset    string `json:"preset"`    // balance|turbo|aggressive — empty defaults to turbo

	// Shared secret. Empty is allowed for a server (a 64-char token is
	// generated); a client must supply the same token its server was given.
	Token string `json:"token"`

	// Server side (role == "server").
	Port          string   `json:"port"`          // tunnel control port
	IPv6          bool     `json:"ipv6"`          // bind :: as well as IPv4
	Ports         []string `json:"ports"`         // forwarded/exposed port specs
	ProxyProtocol bool     `json:"proxyProtocol"` // prepend PROXY protocol v2 header

	// Client side (role == "client").
	ServerHost    string   `json:"serverHost"`    // IP or domain of the server
	ServerPort    string   `json:"serverPort"`    // server's tunnel control port
	EdgeIP        string   `json:"edgeIP"`        // websocket transports: CDN edge to dial
	Proxy         string   `json:"proxy"`         // socks5:// or http:// URL to reach the server through
	Interface     string   `json:"iface"`         // pin the tunnel to a network interface
	LocalAddr     string   `json:"localAddr"`     // pin the tunnel to a source address
	FallbackAddrs []string `json:"fallbackAddrs"` // backup server addresses
	LoadBalance   bool     `json:"loadBalance"`   // spread connections over all addresses at once
	Obfs          string   `json:"obfs"`          // frp/rathole DPI obfuscation: "" / "noise" / "tls"
	TLSSni        string   `json:"tlsSni"`        // frp/rathole tls obfs: SNI / (for acme) the domain
	TLSCertMode   string   `json:"tlsCertMode"`   // frp/rathole tls obfs: "self" or "acme" (Let's Encrypt)

	// TLS, for a wss/wssmux server. Ignored for other transports and for a
	// client (which never verifies the certificate).
	TLSMode    string `json:"tlsMode"`    // self|acme|existing — empty defaults to self
	TLSHost    string `json:"tlsHost"`    // optional SAN embedded in a self-signed cert
	ACMEDomain string `json:"acmeDomain"` // domain for a Let's Encrypt certificate
	ACMEEmail  string `json:"acmeEmail"`  // optional expiry-warning address
	TLSCert    string `json:"tlsCert"`    // path to an existing certificate
	TLSKey     string `json:"tlsKey"`     // path to an existing key

	// SimpleAuth authorises a wss tunnel by the raw token, for a server behind
	// a TLS-terminating proxy. Set the same value on both ends.
	SimpleAuth bool `json:"simpleAuth"`

	// Advanced, when present, overrides the preset's tuning the same way the
	// CLI's "fine-tune the advanced settings by hand" step does. Nil means use
	// the preset unchanged, which is the recommended path.
	Advanced *AdvancedTuning `json:"advanced,omitempty"`
}

// AdvancedTuning carries optional overrides applied on top of the chosen
// preset. It mirrors applyManualTuning in setup.go. Numeric fields override
// only when greater than zero (a preset already fills a sensible value); the
// tri-state *bool fields override only when non-nil, so the form can leave a
// toggle at its preset default or force it on or off.
type AdvancedTuning struct {
	Nodelay   *bool  `json:"nodelay"`
	KeepAlive int    `json:"keepAlive"`
	Heartbeat int    `json:"heartbeat"`
	LogLevel  string `json:"logLevel"`
	LogFormat string `json:"logFormat"` // "json" for machine parsing, "text" for human-readable

	// Server-only.
	ChannelSize int   `json:"channelSize"`
	AcceptUDP   *bool `json:"acceptUDP"`

	// Client-only.
	ConnectionPool int   `json:"connectionPool"`
	AggressivePool *bool `json:"aggressivePool"`

	// Multiplexed transports (tcpmux, wsmux, wssmux, kcp, xdi).
	MuxCon          int `json:"muxCon"`
	MuxVersion      int `json:"muxVersion"`
	MuxFrameSize    int `json:"muxFrameSize"`
	MuxRecvBuffer   int `json:"muxRecvBuffer"`
	MuxStreamBuffer int `json:"muxStreamBuffer"`

	// KCP transports (kcp, xdi).
	KCPMTU          int `json:"kcpMTU"`
	KCPInterval     int `json:"kcpInterval"`
	KCPSndWnd       int `json:"kcpSndWnd"`
	KCPRcvWnd       int `json:"kcpRcvWnd"`
	KCPDataShards   int `json:"kcpDataShards"`
	KCPParityShards int `json:"kcpParityShards"`

	// MSS clamps the largest TCP segment the tunnel sends (0 = off). Only the
	// transports that carry TCP segments honour it; see supportsMSS.
	MSS int `json:"mss"`

	// Limits.
	MaxConnections int `json:"maxConnections"`
	BandwidthMbps  int `json:"bandwidthMbps"`

	// ZeroCopy is only honoured on the plain tcp transport.
	ZeroCopy *bool `json:"zeroCopy"`
}

// CreateResult reports what CreateTunnel did, for a caller that wants to tell
// the user whether the service actually came up.
type CreateResult struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Active  bool   `json:"active"`
	Token   string `json:"token"` // the token in effect, so a generated one can be shown once
}

// CreateTunnel validates a request, builds the tunnel config, generates any
// certificate it needs, writes the systemd unit and starts the service — the
// non-interactive equivalent of SetupServer/SetupClient followed by
// finishSetup. It returns an error describing the first problem rather than
// leaving a half-built tunnel behind, so the caller can surface it as-is.
func CreateTunnel(req TunnelRequest) (CreateResult, error) {
	if name := strings.TrimSpace(req.Name); name != "" && fileExists(app.ConfigPath(name)) {
		return CreateResult{}, fmt.Errorf("a tunnel named %q already exists", name)
	}
	spec, err := buildSpec(req)
	if err != nil {
		return CreateResult{}, err
	}

	// Match the CLI: apply the system-wide network tuning before the tunnel
	// starts. It is best-effort — a machine without the privileges to change
	// sysctls (or one where they are already set) is no reason to refuse the
	// tunnel — so its result is deliberately ignored.
	optimize.ApplyQuiet()

	service, err := spec.Save()
	if err != nil {
		return CreateResult{}, err
	}
	return CreateResult{
		Name:    spec.Name,
		Service: service,
		Active:  IsActive(service),
		Token:   spec.Token,
	}, nil
}

// buildSpec turns a validated request into a TunnelSpec. It performs the same
// checks the interactive flows do, in the same order, so a tunnel built from
// the panel is indistinguishable from one built at the CLI.
func buildSpec(req TunnelRequest) (TunnelSpec, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return TunnelSpec{}, fmt.Errorf("invalid tunnel name %q — use letters, digits, dots, dashes (max 40)", name)
	}

	transport := strings.TrimSpace(req.Transport)
	if !validTransport(transport) {
		return TunnelSpec{}, fmt.Errorf("unknown transport %q", transport)
	}

	s := TunnelSpec{Name: name, Role: req.Role, Transport: transport}

	// Obfuscation is frp/rathole-only; ignore it elsewhere.
	if isReverseProxy(transport) {
		switch strings.TrimSpace(req.Obfs) {
		case "noise", "tls":
			s.Obfs = strings.TrimSpace(req.Obfs)
		}
		s.TLSSni = strings.TrimSpace(req.TLSSni)
		// A real Let's Encrypt certificate is a server-side choice for the tls
		// mode; the domain doubles as the SNI the client presents.
		if s.Obfs == "tls" && req.Role == "server" && strings.EqualFold(strings.TrimSpace(req.TLSCertMode), "acme") {
			domain := strings.TrimSpace(req.TLSSni)
			if domain == "" {
				return TunnelSpec{}, fmt.Errorf("a domain is required for a real Let's Encrypt certificate")
			}
			s.ACMEDomain = domain
			s.ACMEEmail = strings.TrimSpace(req.ACMEEmail)
		}
	}

	switch req.Role {
	case "server":
		if err := buildServer(&s, req); err != nil {
			return TunnelSpec{}, err
		}
	case "client":
		if err := buildClient(&s, req); err != nil {
			return TunnelSpec{}, err
		}
	default:
		return TunnelSpec{}, fmt.Errorf("role must be \"server\" or \"client\", got %q", req.Role)
	}

	preset := strings.TrimSpace(req.Preset)
	if preset == "" {
		preset = PresetTurbo
	}
	if !validPreset(preset) {
		return TunnelSpec{}, fmt.Errorf("unknown preset %q — use balance, turbo or aggressive", preset)
	}
	ApplyPreset(&s, preset)

	if req.Advanced != nil {
		applyAdvanced(&s, req.Advanced)
	}
	return s, nil
}

// buildServer fills the server-specific fields: bind address, forwarded ports,
// token, PROXY protocol and, for wss transports, the certificate and simple
// auth.
func buildServer(s *TunnelSpec, req TunnelRequest) error {
	if !validPort(req.Port) {
		return fmt.Errorf("invalid tunnel port %q", req.Port)
	}
	// Binding the IPv6 wildcard accepts IPv4 too on a dual-stack host, so this
	// is "IPv6 as well" rather than "IPv6 instead".
	bind := "0.0.0.0"
	if req.IPv6 {
		bind = "::"
	}
	s.BindAddr = net.JoinHostPort(bind, req.Port)

	s.Ports = normalizePorts(req.Ports)
	if len(s.Ports) == 0 {
		return fmt.Errorf("at least one exposed port is required")
	}
	if err := validatePortSpecs(s.Ports); err != nil {
		return err
	}

	if token := strings.TrimSpace(req.Token); token != "" {
		s.Token = token
	} else {
		s.Token = randomToken(64)
	}

	if supportsProxyProtocol(s.Transport) {
		s.ProxyProtocol = req.ProxyProtocol
	}

	if needsTLS(s.Transport) {
		if err := configureServerTLS(s, req); err != nil {
			return err
		}
		s.SimpleAuth = req.SimpleAuth
	}
	return nil
}

// buildClient fills the client-specific fields: remote address, token, edge IP,
// upstream proxy, interface/source pinning and fallback addresses.
func buildClient(s *TunnelSpec, req TunnelRequest) error {
	host := strings.Trim(strings.TrimSpace(req.ServerHost), "[]")
	if host == "" {
		return fmt.Errorf("server address is required")
	}
	if !validPort(req.ServerPort) {
		return fmt.Errorf("invalid server port %q", req.ServerPort)
	}
	// JoinHostPort adds the brackets an IPv6 literal needs and leaves a
	// hostname or IPv4 address alone.
	s.RemoteAddr = net.JoinHostPort(host, req.ServerPort)

	token := strings.TrimSpace(req.Token)
	if token == "" {
		return fmt.Errorf("the security token is required and must match the server's")
	}
	s.Token = token

	if isWS(s.Transport) {
		s.EdgeIP = strings.TrimSpace(req.EdgeIP)
	}
	if needsTLS(s.Transport) {
		s.SimpleAuth = req.SimpleAuth
	}

	// A proxy and interface/source pinning are meaningless for the datagram
	// transports, which a TCP proxy cannot relay — mirror the CLI and ignore
	// them there rather than writing a config the engine would reject.
	if !isDatagram(s.Transport) {
		if raw := strings.TrimSpace(req.Proxy); raw != "" {
			if _, err := network.ParseProxy(raw); err != nil {
				return fmt.Errorf("invalid proxy URL: %v", err)
			}
			s.Proxy = raw
		}
		if iface := strings.TrimSpace(req.Interface); iface != "" {
			if _, err := net.InterfaceByName(iface); err != nil {
				return fmt.Errorf("no such interface %q", iface)
			}
			s.Interface = iface
		}
		s.LocalAddr = strings.TrimSpace(req.LocalAddr)
	}

	// Backup addresses let the tunnel survive a filtered server IP. A bare IP
	// reuses the main port, matching what the CLI does.
	for _, part := range req.FallbackAddrs {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(part); err != nil {
			part = net.JoinHostPort(strings.Trim(part, "[]"), req.ServerPort)
		}
		s.FallbackAddrs = append(s.FallbackAddrs, part)
	}
	if len(s.FallbackAddrs) > 0 {
		s.LoadBalance = req.LoadBalance
	}
	return nil
}

// configureServerTLS resolves the certificate for a wss/wssmux server. It is
// the non-interactive form of setupServerTLS: self-signed (the default), a
// Let's Encrypt domain, or an existing pair on disk.
func configureServerTLS(s *TunnelSpec, req TunnelRequest) error {
	mode := strings.TrimSpace(req.TLSMode)
	if mode == "" {
		mode = "self"
	}
	switch mode {
	case "self":
		cert, key, err := EnsureSelfSignedCert(s.Name, strings.TrimSpace(req.TLSHost))
		if err != nil {
			return fmt.Errorf("certificate generation failed: %v", err)
		}
		s.TLSCert, s.TLSKey = cert, key
		return nil

	case "acme":
		domain := strings.TrimSpace(req.ACMEDomain)
		if domain == "" {
			return fmt.Errorf("a domain is required for a Let's Encrypt certificate")
		}
		if net.ParseIP(domain) != nil {
			return fmt.Errorf("%q is an IP address; Let's Encrypt only issues for domain names", domain)
		}
		s.ACMEDomain = domain
		s.ACMEEmail = strings.TrimSpace(req.ACMEEmail)
		// The self-signed pair is generated anyway: it is what the config points
		// at until issuance succeeds, and the fallback if issuance fails.
		cert, key, err := EnsureSelfSignedCert(s.Name, domain)
		if err != nil {
			return fmt.Errorf("certificate generation failed: %v", err)
		}
		s.TLSCert, s.TLSKey = cert, key
		return nil

	case "existing":
		s.TLSCert = strings.TrimSpace(req.TLSCert)
		s.TLSKey = strings.TrimSpace(req.TLSKey)
		if err := validCertPair(s.TLSCert, s.TLSKey); err != nil {
			return fmt.Errorf("invalid certificate: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("tls mode must be self, acme or existing, got %q", mode)
	}
}

// applyAdvanced overlays the manual tuning overrides on top of the preset
// values, exactly as applyManualTuning does after ApplyPreset. Because these
// are deliberate overrides, the spec is marked custom so a later preset change
// will not silently discard them.
func applyAdvanced(s *TunnelSpec, a *AdvancedTuning) {
	if a.Nodelay != nil {
		s.Nodelay = *a.Nodelay
	}
	if a.KeepAlive > 0 {
		s.KeepAlive = a.KeepAlive
	}
	if a.Heartbeat > 0 {
		s.Heartbeat = a.Heartbeat
	}
	if lvl := strings.TrimSpace(a.LogLevel); lvl != "" {
		s.LogLevel = lvl
	}
	switch strings.TrimSpace(a.LogFormat) {
	case "json":
		s.LogFormat = "json"
	case "text":
		s.LogFormat = ""
	}

	if s.Role == "server" {
		if a.ChannelSize > 0 {
			s.ChannelSize = a.ChannelSize
		}
		if a.AcceptUDP != nil && s.Transport == "tcp" {
			s.AcceptUDP = *a.AcceptUDP
		}
	} else {
		if a.ConnectionPool > 0 {
			s.ConnectionPool = a.ConnectionPool
		}
		if a.AggressivePool != nil {
			s.AggressivePool = *a.AggressivePool
		}
	}

	if isMux(s.Transport) {
		if a.MuxCon > 0 {
			s.MuxCon = a.MuxCon
		}
		if a.MuxVersion > 0 {
			s.MuxVersion = a.MuxVersion
		}
		if a.MuxFrameSize > 0 {
			s.MuxFrameSize = a.MuxFrameSize
		}
		if a.MuxRecvBuffer > 0 {
			s.MuxRecvBuffer = a.MuxRecvBuffer
		}
		if a.MuxStreamBuffer > 0 {
			s.MuxStreamBuffer = a.MuxStreamBuffer
		}
	}
	if isKCP(s.Transport) {
		if a.KCPMTU > 0 {
			s.KCPMTU = a.KCPMTU
		}
		if a.KCPInterval > 0 {
			s.KCPInterval = a.KCPInterval
		}
		if a.KCPSndWnd > 0 {
			s.KCPSndWnd = a.KCPSndWnd
		}
		if a.KCPRcvWnd > 0 {
			s.KCPRcvWnd = a.KCPRcvWnd
		}
		// Shards are meaningful at zero (it disables FEC), but zero is also the
		// "leave the preset alone" signal here; a caller that wants FEC off can
		// pick the balance preset, which sets no shards.
		if a.KCPDataShards > 0 {
			s.KCPDataShards = a.KCPDataShards
		}
		if a.KCPParityShards > 0 {
			s.KCPParityShards = a.KCPParityShards
		}
	}

	if a.MSS > 0 && supportsMSS(s.Transport) {
		s.MSS = a.MSS
	}
	if a.MaxConnections > 0 {
		s.MaxConnections = a.MaxConnections
	}
	if a.BandwidthMbps > 0 {
		s.BandwidthMbps = a.BandwidthMbps
	}
	if a.ZeroCopy != nil && s.Transport == "tcp" {
		s.ZeroCopy = *a.ZeroCopy
	}

	// Hand-set values no longer match any preset, so mark the tunnel custom and
	// keep a later preset change from overwriting them.
	s.Preset = ""
}

// normalizePorts trims each forwarded-port entry and drops the empties, the
// same shape parsePorts produces from a comma-separated string. The web form
// sends the entries as a list, so this is where they are tidied.
func normalizePorts(ports []string) []string {
	var out []string
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
