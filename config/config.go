package config

// TransportType defines the type of transport.
type TransportType string

const (
	TCP    TransportType = "tcp"
	TCPMUX TransportType = "tcpmux"
	WS     TransportType = "ws"
	WSS    TransportType = "wss"
	WSMUX  TransportType = "wsmux"
	WSSMUX TransportType = "wssmux"
	UDP    TransportType = "udp"
	KCP    TransportType = "kcp"
	// QUIC carries the tunnel inside QUIC streams over UDP. Like KCP it survives
	// packet loss and reordering well, but with a modern, TLS-1.3-based handshake
	// and built-in stream multiplexing. Ported from the upstream Backhaul engine.
	QUIC TransportType = "quic"
	// STEALTH is a TCP tunnel wrapped in a Noise (NNpsk0) record layer. It has
	// no TLS fingerprint and no recognisable handshake — on the wire it is
	// indistinguishable from random — so deep packet inspection has nothing to
	// match. The pre-shared key is derived from the tunnel token.
	STEALTH TransportType = "stealth"
	// XDI carries the KCP transport inside ICMP echo instead of UDP —
	// experimental. It is for the network that filters UDP and TCP but not
	// ICMP, where the tunnel rides in ping packets. Linux only, and needs a raw
	// socket. Everything above the packet layer is identical to KCP.
	XDI TransportType = "xdi"
)

// KCPConfig holds the tuning of the KCP transport: a reliable, retransmitting
// protocol carried inside UDP datagrams. Every field is filled from the chosen
// performance preset, so a config never has to be edited by hand.
type KCPConfig struct {
	MTU          int  `toml:"kcp_mtu"`
	Interval     int  `toml:"kcp_interval"`
	Resend       int  `toml:"kcp_resend"`
	NoDelay      int  `toml:"kcp_nodelay"`
	NoCongestion int  `toml:"kcp_nocongestion"`
	SndWnd       int  `toml:"kcp_sndwnd"`
	RcvWnd       int  `toml:"kcp_rcvwnd"`
	AckNoDelay   bool `toml:"kcp_acknodelay"`
	// DataShards/ParityShards enable forward error correction: for every
	// DataShards packets, ParityShards extra packets are sent so that many
	// losses are repaired instantly instead of waiting for a retransmit.
	DataShards   int `toml:"kcp_datashards"`
	ParityShards int `toml:"kcp_parityshards"`
}

// WithDefaults returns a copy with any unset field filled in, so a config
// written by an older version — or by hand — can never produce a KCP session
// with a zero window or a zero tick interval.
func (k KCPConfig) WithDefaults() KCPConfig {
	if k.MTU <= 0 {
		k.MTU = 1350
	}
	if k.Interval <= 0 {
		k.Interval = 20
	}
	if k.Resend < 0 {
		k.Resend = 2
	}
	if k.SndWnd <= 0 {
		k.SndWnd = 1024
	}
	if k.RcvWnd <= 0 {
		k.RcvWnd = 1024
	}
	// Parity without data shards is meaningless to the encoder, so treat a
	// half-configured pair as FEC disabled rather than failing to start.
	if k.DataShards <= 0 || k.ParityShards <= 0 {
		k.DataShards, k.ParityShards = 0, 0
	}
	return k
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	BindAddr         string        `toml:"bind_addr"`
	Transport        TransportType `toml:"transport"`
	Token            string        `toml:"token"`
	Nodelay          bool          `toml:"nodelay"`
	Keepalive        int           `toml:"keepalive_period"`
	ChannelSize      int           `toml:"channel_size"`
	LogLevel         string        `toml:"log_level"`
	LogFormat        string        `toml:"log_format"` // "" (text) or "json"
	Ports            []string      `toml:"ports"`
	PPROF            bool          `toml:"pprof"`
	MuxSession       int           `toml:"mux_session"`
	MuxVersion       int           `toml:"mux_version"`
	MaxFrameSize     int           `toml:"mux_framesize"`
	MaxReceiveBuffer int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer  int           `toml:"mux_streambuffer"`
	Sniffer          bool          `toml:"sniffer"`
	WebPort          int           `toml:"web_port"`
	SnifferLog       string        `toml:"sniffer_log"`
	TLSCertFile      string        `toml:"tls_cert"`
	TLSKeyFile       string        `toml:"tls_key"`
	// ACMEDomain switches wss/wssmux to a Let's Encrypt certificate for this
	// domain instead of the generated self-signed one. The domain must resolve
	// to this server. Empty keeps the self-signed certificate.
	ACMEDomain string `toml:"acme_domain"`
	ACMEEmail  string `toml:"acme_email"`
	// SimpleAuth authorises a wss tunnel by the raw token instead of a proof
	// bound to the TLS session. It exists for one deployment the binding
	// otherwise makes impossible: a TLS-terminating reverse proxy — typically
	// NGINX — in front of the tunnel, which holds a different TLS session from
	// the client so a bound proof can never match. It is off by default because
	// it hands the token to whoever terminates the TLS; turn it on only when a
	// trusted proxy is doing so, and set it on both ends.
	SimpleAuth bool `toml:"simple_auth"`
	Heartbeat  int  `toml:"heartbeat"`
	MuxCon     int  `toml:"mux_con"`
	AcceptUDP  bool `toml:"accept_udp"`
	SkipOptz   bool `toml:"skip_optz"`
	MSS        int  `toml:"mss"`
	SO_RCVBUF  int  `toml:"so_rcvbuf"`
	SO_SNDBUF  int  `toml:"so_sndbuf"`
	// SOPinTCP restores the old behaviour of pinning SO_RCVBUF/SO_SNDBUF on
	// TCP sockets. Off by default: pinning them stops the kernel auto-tuning
	// the window, which costs a large multiple of the throughput on a fast
	// uplink. The datagram transports set their own buffers regardless.
	SOPinTCP bool `toml:"so_pin_tcp"`
	// ZeroCopy lets the kernel move the bytes of forwarded connections
	// directly between the two sockets, without them passing through this
	// process. It is faster and it is the least proven path here, so it is off
	// by default and turned on per tunnel.
	//
	// Purely local: nothing about it reaches the wire, so the two ends need not
	// agree and it is safe to enable on one side first. It applies only to the
	// plain `tcp` transport on Linux, and only when the tunnel has no bandwidth
	// limit — anything else quietly keeps the buffered path.
	ZeroCopy bool `toml:"zero_copy"`

	ProxyProtocol bool `toml:"proxy_protocol"`
	// Stealth is the legacy on/off form of Obfs ("noise"), kept so configs
	// written before Obfs existed still work. New configs set Obfs.
	Stealth bool `toml:"stealth"`
	// Obfs is the DPI-obfuscation mode for an frp/rathole tunnel: "" / "none",
	// "noise" (the Noise record layer), or "tls" (a uTLS session that looks like
	// HTTPS). Both ends must match.
	Obfs string `toml:"obfs"`
	// TLSSni is the SNI the tls obfs presents; empty derives it from the address.
	TLSSni string `toml:"tls_sni"`
	// MaxConnections caps simultaneous forwarded connections (0 = unlimited).
	MaxConnections int `toml:"max_connections"`
	// BandwidthMbps caps total tunnel throughput in Mbit/s (0 = unlimited).
	BandwidthMbps int    `toml:"bandwidth_mbps"`
	Preset        string `toml:"preset"`
	// Embedded so the kcp_* keys sit at the top level of the [server] table
	// alongside every other tuning key.
	KCPConfig
}

// ClientConfig represents the configuration for the client.
type ClientConfig struct {
	RemoteAddr string `toml:"remote_addr"`
	// FallbackAddrs are additional server addresses tried in order whenever the
	// primary cannot be reached (a filtered IP, a blocked port, a CDN edge).
	FallbackAddrs    []string      `toml:"fallback_addrs"`
	Transport        TransportType `toml:"transport"`
	Token            string        `toml:"token"`
	ConnectionPool   int           `toml:"connection_pool"`
	RetryInterval    int           `toml:"retry_interval"`
	Nodelay          bool          `toml:"nodelay"`
	Keepalive        int           `toml:"keepalive_period"`
	LogLevel         string        `toml:"log_level"`
	LogFormat        string        `toml:"log_format"` // "" (text) or "json"
	PPROF            bool          `toml:"pprof"`
	MuxSession       int           `toml:"mux_session"`
	MuxVersion       int           `toml:"mux_version"`
	MaxFrameSize     int           `toml:"mux_framesize"`
	MaxReceiveBuffer int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer  int           `toml:"mux_streambuffer"`
	Sniffer          bool          `toml:"sniffer"`
	WebPort          int           `toml:"web_port"`
	SnifferLog       string        `toml:"sniffer_log"`
	DialTimeout      int           `toml:"dial_timeout"`
	AggressivePool   bool          `toml:"aggressive_pool"`
	EdgeIP           string        `toml:"edge_ip"`
	// SimpleAuth authorises a wss tunnel by the raw token instead of a proof
	// bound to the TLS session. It exists for one deployment the binding
	// otherwise makes impossible: a TLS-terminating reverse proxy — typically
	// NGINX — in front of the tunnel, which holds a different TLS session from
	// the client so a bound proof can never match. It is off by default because
	// it hands the token to whoever terminates the TLS; turn it on only when a
	// trusted proxy is doing so, and set it on both ends.
	SimpleAuth bool `toml:"simple_auth"`
	SkipOptz   bool `toml:"skip_optz"`
	MSS        int  `toml:"mss"`
	SO_RCVBUF  int  `toml:"so_rcvbuf"`
	SO_SNDBUF  int  `toml:"so_sndbuf"`
	// Proxy routes the connection to the tunnel server through a local or
	// nearby proxy, for a client that cannot open an arbitrary outbound
	// connection itself. One URL: "socks5://127.0.0.1:1080" or
	// "http://user:pass@10.0.0.1:8080". Empty means dial the server directly.
	//
	// It applies only to the connections that reach the server. The dial to the
	// local backend never goes through it — that traffic does not leave the
	// machine, so sending it out and back would be both slower and wrong.
	Proxy string `toml:"proxy"`
	// LocalAddr binds the connections that reach the server to a chosen source
	// address, which on a machine with more than one uplink is what decides
	// which of them the tunnel leaves by. An address on its own is enough; the
	// port is the kernel's to pick. Needs no privilege.
	LocalAddr string `toml:"local_addr"`
	// Interface pins those connections to a named device, for when the source
	// address alone does not settle the route. Linux, and needs CAP_NET_RAW.
	Interface string `toml:"interface"`
	// SOMark stamps an fwmark on their packets, which is what `ip rule` matches
	// on — the way to put the tunnel on a routing table of its own without
	// changing routing for the rest of the machine. Linux, and needs
	// CAP_NET_ADMIN. Zero means none.
	SOMark int `toml:"so_mark"`
	// SOPinTCP restores the old behaviour of pinning SO_RCVBUF/SO_SNDBUF on
	// TCP sockets. Off by default: pinning them stops the kernel auto-tuning
	// the window, which costs a large multiple of the throughput on a fast
	// uplink. The datagram transports set their own buffers regardless.
	SOPinTCP bool `toml:"so_pin_tcp"`
	// ZeroCopy lets the kernel move the bytes of forwarded connections
	// directly between the two sockets, without them passing through this
	// process. It is faster and it is the least proven path here, so it is off
	// by default and turned on per tunnel.
	//
	// Purely local: nothing about it reaches the wire, so the two ends need not
	// agree and it is safe to enable on one side first. It applies only to the
	// plain `tcp` transport on Linux, and only when the tunnel has no bandwidth
	// limit — anything else quietly keeps the buffered path.
	ZeroCopy bool `toml:"zero_copy"`

	Preset string `toml:"preset"`
	// LoadBalance spreads the pool's data connections over every configured
	// address instead of putting them all on the live one. All the addresses
	// must reach the SAME server, since the control channel — and therefore
	// the tunnel's identity — lives on one of them.
	LoadBalance bool `toml:"load_balance"`
	// Stealth / Obfs / TLSSni configure DPI obfuscation for an frp/rathole
	// tunnel; they must match the server. See ServerConfig.
	Stealth bool   `toml:"stealth"`
	Obfs    string `toml:"obfs"`
	TLSSni  string `toml:"tls_sni"`
	// Embedded so the kcp_* keys sit at the top level of the [client] table
	// alongside every other tuning key.
	KCPConfig
}

// ObfsMode resolves the effective obfuscation mode of a server config,
// mapping the legacy stealth flag onto "noise".
func (c *ServerConfig) ObfsMode() string { return resolveObfs(c.Obfs, c.Stealth) }

// ObfsMode resolves the effective obfuscation mode of a client config.
func (c *ClientConfig) ObfsMode() string { return resolveObfs(c.Obfs, c.Stealth) }

// resolveObfs normalizes the obfuscation mode: an explicit Obfs wins, otherwise
// the legacy Stealth bool means "noise", otherwise none.
func resolveObfs(obfs string, stealth bool) string {
	switch obfs {
	case "noise", "tls":
		return obfs
	case "none":
		return ""
	}
	if stealth {
		return "noise"
	}
	return ""
}

// WGPeer is one allowed client on a WireGuard exit server: its public key and
// the address it is given inside the tunnel.
type WGPeer struct {
	PublicKey  string `toml:"public_key"`
	AllowedIPs string `toml:"allowed_ips"` // e.g. "10.66.66.2/32"
}

// WireGuardConfig configures a WireGuard tunnel. It is not a reverse tunnel like
// the others: a "server" is a real kernel WireGuard exit node that NATs its
// peers out to the internet, and a "client" brings WireGuard up in userspace and
// exposes a SOCKS5 proxy whose traffic egresses through the tunnel — the proxy a
// panel like x-ui points an outbound at.
type WireGuardConfig struct {
	Role string `toml:"role"` // "server" or "client"

	// Server (exit node) fields.
	PrivateKey string   `toml:"private_key"` // interface private key (base64)
	ListenPort int      `toml:"listen_port"` // UDP port the server listens on
	Address    string   `toml:"address"`     // interface address, e.g. "10.66.66.1/24"
	Egress     string   `toml:"egress"`      // outbound interface to NAT through; empty = auto-detect
	Peers      []WGPeer `toml:"peers"`

	// Client fields, parsed from a pasted wg-quick config.
	ClientPrivateKey string `toml:"client_private_key"`
	ClientAddress    string `toml:"client_address"` // interface address(es), comma-separated
	DNS              string `toml:"dns"`            // resolver reached through the tunnel; empty = 1.1.1.1
	MTU              int    `toml:"mtu"`
	PeerPublicKey    string `toml:"peer_public_key"`
	PresharedKey     string `toml:"preshared_key"`
	Endpoint         string `toml:"endpoint"` // server host:port
	AllowedIPs       string `toml:"allowed_ips"`
	Keepalive        int    `toml:"keepalive"`
	SocksBind        string `toml:"socks_bind"` // e.g. "127.0.0.1"
	SocksPort        int    `toml:"socks_port"`

	// AmneziaWG obfuscation parameters, taken from a pasted AmneziaWG config.
	// All zero means plain WireGuard (wire-compatible); set together they add the
	// junk packets and header randomization that hide the WireGuard fingerprint.
	Jc   int    `toml:"jc"`   // junk packet count
	Jmin int    `toml:"jmin"` // junk packet min size
	Jmax int    `toml:"jmax"` // junk packet max size
	S1   int    `toml:"s1"`   // init packet junk size
	S2   int    `toml:"s2"`   // response packet junk size
	H1   uint32 `toml:"h1"`   // magic header — init
	H2   uint32 `toml:"h2"`   // magic header — response
	H3   uint32 `toml:"h3"`   // magic header — underload
	H4   uint32 `toml:"h4"`   // magic header — transport
}

// PacketForward is one explicit port mapping for a packet client: a local
// listener relayed, over the raw-packet tunnel, to a target reached from the
// server (abroad) side.
type PacketForward struct {
	Listen   string `toml:"listen"`   // local listen address, e.g. "0.0.0.0:8080"
	Target   string `toml:"target"`   // target as seen by the server, e.g. "127.0.0.1:80"
	Protocol string `toml:"protocol"` // "tcp" or "udp"
}

// PacketConfig is the Packet tunnel: a raw-packet (pcap) transport that carries
// KCP over crafted TCP packets injected below the kernel stack, so DPI and
// stateful firewalls that track the kernel's connections never see it. Its
// topology is inverted from the reverse-proxy tunnels: the SERVER is the abroad
// exit node and the CLIENT is the Iran entry that exposes the forwarded ports
// and dials out to the server. It has its own section and engine, like
// WireGuard, and ignores the [server]/[client] sections.
type PacketConfig struct {
	Role string `toml:"role"` // "server" (abroad exit) or "client" (Iran entry)

	Key   string `toml:"key"`   // shared secret; must be identical on both ends
	Block string `toml:"block"` // KCP encryption: aes (default), aes-128-gcm, …, none, null

	// Server (abroad exit) fields.
	ListenPort int `toml:"listen_port"` // TCP port to listen on (non-standard — avoid 80/443)

	// Client (Iran entry) fields.
	ServerAddr string          `toml:"server_addr"` // abroad public host:port
	Ports      []string        `toml:"ports"`       // exposed TCP ports, forwarded 1:1 to 127.0.0.1:<port> on the server
	Forward    []PacketForward `toml:"forward"`     // explicit forward mappings (advanced)
	Socks      string          `toml:"socks"`       // optional SOCKS5 listen address, e.g. "127.0.0.1:1080"
	Conn       int             `toml:"conn"`        // parallel tunnel connections (default 1)

	// KCP tuning (optional; sensible defaults applied by the engine).
	Mode string `toml:"mode"` // normal/fast/fast2/fast3 (default fast)
	MTU  int    `toml:"mtu"`  // KCP MTU (default 1350; lower for restrictive networks)

	// TCP flag cycling for traffic-shape obfuscation. Comma-separated flag
	// combinations like "PA" or "PA,A". Empty means the engine default ("PA").
	LocalFlags  string `toml:"local_flags"`
	RemoteFlags string `toml:"remote_flags"`

	// Network parameters. All optional — empty triggers auto-detection of the
	// default-route interface, this host's IPv4 on it, and the gateway MAC.
	Interface string `toml:"interface"`
	LocalIP   string `toml:"local_ip"`
	RouterMAC string `toml:"router_mac"`
	Sockbuf   int    `toml:"sockbuf"` // pcap capture buffer bytes

	LogLevel string `toml:"log_level"` // none/debug/info/warn/error/fatal (default none)
}

// SSHConfig is the SSH tunnel: a client-only VPN egress. It opens an SSH
// connection to a server abroad and exposes a local SOCKS5 proxy whose traffic
// leaves through that server (SSH dynamic forwarding). Point a panel outbound at
// the SOCKS5. Like WireGuard and Packet it has its own section and engine.
type SSHConfig struct {
	Role string `toml:"role"` // only "client"

	Host     string `toml:"host"`     // server IP or domain
	Port     int    `toml:"port"`     // SSH port (default 22)
	User     string `toml:"user"`     // SSH username
	Password string `toml:"password"` // SSH password

	SocksBind string `toml:"socks_bind"` // e.g. "127.0.0.1"
	SocksPort int    `toml:"socks_port"` // local SOCKS5 port

	LogLevel string `toml:"log_level"`
}

// SpoofConfig is the Spoof tunnel: a UDP pipe that carries traffic inside
// packets whose SOURCE IP is forged, so a Layer-3 firewall that filters on
// source/destination IP sees a whitelisted-looking flow. Both ends forge their
// source IP (mutual bidirectional spoofing). It only works where the network
// permits forged source IPs (most datacenters block it — the spoof tester
// checks). The pipe is a single UDP flow, meant to carry WireGuard or any UDP
// service. Like WireGuard/Packet it has its own section and engine.
type SpoofConfig struct {
	Role string `toml:"role"` // "client" (local) or "server" (remote)

	Key       string `toml:"key"`       // shared secret; ChaCha20-Poly1305 key is derived from it
	Transport string `toml:"transport"` // carrier: "udp" (default), "tcp", "icmp"

	// The forged source addresses. SpoofIP is what THIS end stamps as its source;
	// PeerSpoofIP is what the peer stamps (so we can filter its packets).
	SpoofIP     string `toml:"spoof_ip"`      // our forged source IP
	PeerSpoofIP string `toml:"peer_spoof_ip"` // the peer's forged source IP

	// Client (local) fields.
	Listen     string `toml:"listen"`      // local UDP listen for the app, e.g. "127.0.0.1:1080"
	ServerIP   string `toml:"server_ip"`   // the server's REAL IP
	ServerPort int    `toml:"server_port"` // the port the server listens on (our send dst)
	RecvPort   int    `toml:"recv_port"`   // port we receive the server's spoofed replies on

	// Server (remote) fields.
	ListenPort int    `toml:"listen_port"` // port we receive spoofed packets on
	Forward    string `toml:"forward"`     // where to relay the inner UDP flow, e.g. "127.0.0.1:51820"
	ClientIP   string `toml:"client_ip"`   // the client's REAL IP (our reply dst)
	ClientPort int    `toml:"client_port"` // the client's recv port

	// Network parameters (optional; empty auto-detects the default-route interface
	// and this host's IPv4).
	Interface string `toml:"interface"`
	LocalIP   string `toml:"local_ip"`

	LogLevel string `toml:"log_level"`
}

// Config represents the complete configuration, including both server and client settings.
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Client    ClientConfig    `toml:"client"`
	WireGuard WireGuardConfig `toml:"wireguard"`
	Packet    PacketConfig    `toml:"packet"`
	SSH       SSHConfig       `toml:"ssh"`
	Spoof     SpoofConfig     `toml:"spoof"`
}
