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
	// SPOOF carries the KCP transport inside raw IPv4 packets whose source
	// address is forged — experimental "IP Spoofing". It is for a path that
	// treats the source IP as identity: the packets leave with a forged source,
	// but on the wire they appear to come from spoof_src_ip. Like xdi it is KCP
	// over a different packet layer; everything above is identical. Linux only,
	// needs a raw socket (root), and the spoof_* keys configure it. Ported from
	// the upstream BackPack engine (AGPL-3.0).
	SPOOF TransportType = "spoof"
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

// SpoofConfig holds the IP-spoofing carrier's settings, embedded in both the
// server and client config so the spoof_* keys sit at the top level of the
// table. It only takes effect when transport = "spoof"; every field is ignored
// otherwise. Ported from the upstream BackPack engine (AGPL-3.0).
//
// The carrier forges the source address of the raw packets it sends. Routing
// still uses the real peer — the server's bind address, the client's remote
// address — so the packet actually arrives; only the source in the on-wire
// header is replaced with SpoofSrcIP. The two ends must agree on the profile
// and, where it matters, on the spoofed addresses.
type SpoofConfig struct {
	// SpoofProfile is the L4 shim wrapped around each datagram, which decides
	// what the packet looks like to inspection: "udp" (default), "icmp" (looks
	// like ping) or "tcp" (looks like a TCP flow; the receiving side auto-manages
	// an iptables rule to drop the kernel's RSTs). It sets BOTH directions unless
	// SpoofUplink/SpoofDownlink override them.
	SpoofProfile string `toml:"spoof_profile"`
	// SpoofUplink and SpoofDownlink set the profile per direction, for a path
	// whose filtering is not symmetric — e.g. ICMP survives client→server while
	// UDP survives server→client. Uplink is client→server, downlink is
	// server→client; both ends must set the same pair. Empty falls back to
	// SpoofProfile, which is the symmetric case.
	SpoofUplink   string `toml:"spoof_uplink"`
	SpoofDownlink string `toml:"spoof_downlink"`
	// SpoofSrcIP is the forged source address stamped on every outgoing packet.
	// Empty leaves the host's real source in place, which spoofs nothing.
	SpoofSrcIP string `toml:"spoof_src_ip"`
	// SpoofSrcPool is an optional list of forged sources to rotate through: each
	// time the carrier (re)connects it picks one, so the tunnel is not pinned to
	// a single address a firewall might rate-limit or block. SpoofSrcIP, if set,
	// is always a member. Empty means use SpoofSrcIP alone.
	SpoofSrcPool []string `toml:"spoof_src_pool"`
	// SpoofPeerIP is the peer's REAL IPv4 address — where the forged packets are
	// actually routed. On the server it is REQUIRED: because the client forges
	// its source, the server cannot learn where to send replies from the packets
	// themselves and must be told the client's real address. On the client it is
	// optional and defaults to the host of RemoteAddr.
	SpoofPeerIP string `toml:"spoof_peer_ip"`
	// SpoofDstIP is a forged destination written only into the cosmetic L4 shim
	// of the profiles that carry one; the packet is still routed to the real
	// peer. Empty mirrors SpoofSrcIP. Ignored by the udp profile.
	SpoofDstIP string `toml:"spoof_dst_ip"`
	// SpoofInterface pins the raw socket to a named egress device (e.g. "eth0"),
	// for a multi-homed host where the forged source would otherwise pick the
	// wrong link. Empty lets the kernel route by the real destination.
	SpoofInterface string `toml:"spoof_interface"`
	// SpoofPipe switches the spoof transport from a KCP tunnel to a raw UDP pipe
	// for WireGuard: instead of forwarding ports, it relays datagrams between a
	// local WireGuard socket and the forged-source channel, so a whole-device VPN
	// rides over it. WireGuard supplies its own encryption and loss handling, so
	// no KCP sits underneath. Ports/mux settings are ignored in this mode.
	SpoofPipe bool `toml:"spoof_pipe"`
	// SpoofPipeAddr is this host's WireGuard UDP endpoint. On the client it is
	// where the tunnel listens and where WireGuard's `endpoint` points; on the
	// server it is where the real WireGuard listens and datagrams are forwarded.
	// Defaults to 127.0.0.1:51820.
	SpoofPipeAddr string `toml:"spoof_pipe_addr"`
	// SpoofSockBuf sizes the send and receive socket buffers (SO_SNDBUF /
	// SO_RCVBUF) of the raw and UDP sockets the carrier owns, in bytes. A large
	// buffer is what lets the forged-source flow reach real bandwidth: under a
	// burst the kernel parks packets here instead of dropping them before the
	// read loop drains them. 0 uses the carrier default (4 MiB).
	SpoofSockBuf int `toml:"spoof_sockbuf"`
	// SpoofPeerSrcIP pins the forged source the peer stamps on its packets, so
	// anything arriving with a different source is dropped before the encryption
	// ever looks at it. Empty accepts any source. Set it to the peer's
	// spoof_src_ip for a tighter, cheaper receive path.
	SpoofPeerSrcIP string `toml:"spoof_peer_src_ip"`
	// SpoofICMPReply makes an icmp/icmpv6 tunnel look like a real ping exchange:
	// the client sends Echo Requests and the server answers with Echo Replies,
	// instead of both ends sending Requests. Cosmetic; both ends must set it the
	// same. Ignored by the udp/tcp profiles.
	SpoofICMPReply bool `toml:"spoof_icmp_reply"`
	// SpoofMTU is the largest IP packet the carrier emits before it fragments in
	// userspace. 0 uses 1500. Lower it on a path with a smaller MTU.
	SpoofMTU int `toml:"spoof_mtu"`

	// The DPI-evasion knobs below are optional obfuscation ported from the
	// reference spooftunnel. The header cosmetics (ttl/dscp/source-port) need no
	// agreement between the two ends; the wire-changing ones (padding, fake TLS)
	// must be set the same on both.

	// SpoofTTLJitter varies the IP TTL per packet across realistic OS defaults
	// {64,128,255} instead of a fixed 64, to blur TTL-based fingerprints.
	SpoofTTLJitter bool `toml:"spoof_ttl_jitter"`
	// SpoofRandomDSCP varies the IP DSCP/ToS byte per packet across plausible
	// values instead of leaving it 0.
	SpoofRandomDSCP bool `toml:"spoof_random_dscp"`
	// SpoofShufflePort randomises the L4 SOURCE port per packet (udp/tcp) within
	// [SpoofPortMin,SpoofPortMax], so the flow does not sit on one source port.
	SpoofShufflePort bool `toml:"spoof_shuffle_port"`
	SpoofPortMin     int  `toml:"spoof_port_min"`
	SpoofPortMax     int  `toml:"spoof_port_max"`
	// SpoofPadding appends 1..SpoofPaddingMax random bytes to every payload
	// (self-describing, so the receiver strips them). Both ends must set it same.
	SpoofPadding    bool `toml:"spoof_padding"`
	SpoofPaddingMax int  `toml:"spoof_padding_max"`
	// SpoofFakeTLS prepends a fake TLS 1.2 record header to each TCP segment. TCP
	// profile only; both ends must agree.
	SpoofFakeTLS bool `toml:"spoof_fake_tls"`
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
	// Embedded so the spoof_* keys sit at the top level too. Only used when
	// transport = "spoof".
	SpoofConfig
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
	// HealthFailover scores every configured address on a timer and keeps the
	// tunnel on the healthiest exit, re-measuring so it follows the best route as
	// conditions change. It is mutually exclusive with load_balance: steering to
	// one best exit is the opposite of spreading across all of them.
	HealthFailover bool `toml:"health_failover"`
	// Stealth / Obfs / TLSSni configure DPI obfuscation for an frp/rathole
	// tunnel; they must match the server. See ServerConfig.
	Stealth bool   `toml:"stealth"`
	Obfs    string `toml:"obfs"`
	TLSSni  string `toml:"tls_sni"`
	// Embedded so the kcp_* keys sit at the top level of the [client] table
	// alongside every other tuning key.
	KCPConfig
	// Embedded so the spoof_* keys sit at the top level too. Only used when
	// transport = "spoof".
	SpoofConfig
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

// HedioumConfig is the Hedioum tunnel: a two-node connection-pool proxy that
// carries SOCKS5 traffic over many multiplexed, camouflaged pipes. Its engine is
// vendored (with the author's permission — see internal/hedioum/engine/NOTICE.md)
// from Hedioum Pool Tunnel by hedioum: https://github.com/hedioum/Hedioum-Pool-Tunnel
//
// Its topology is the same inverted shape as Packet: the "foreign" role is the
// abroad exit node (it dials the open internet) and the "iran" role is the entry
// that exposes a local SOCKS5 which X-UI/Xray point their outbound at. The two
// ends authenticate with a shared token. It has its own section and engine, like
// WireGuard and Packet, and ignores the [server]/[client] sections.
type HedioumConfig struct {
	Role string `toml:"role"` // "foreign" (abroad exit) or "iran" (entry hub)

	// AuthToken is the shared secret; it must be identical on both ends.
	AuthToken string `toml:"auth_token"`

	// Mimic is the camouflage protocol the pipes impersonate: "ssh" (default),
	// "tls", "smtp" or "imap". Both ends must agree.
	Mimic string `toml:"mimic"`

	// ---- Foreign (abroad exit) fields ----

	// ListenPort is the public port the camouflage listener binds on the foreign
	// node (the port the iran hub dials).
	ListenPort int `toml:"listen_port"`
	// EgressIPMode controls how the foreign node dials the open internet: "ipv4"
	// (default, no IPv6 identity leak), "ipv6" or "dual". EgressBindIP optionally
	// pins the source IP on multi-IP servers.
	EgressIPMode string `toml:"egress_ip_mode"`
	EgressBindIP string `toml:"egress_bind_ip"`
	// DecoyPort is the local port the real sshd was relocated to; unauthorized
	// probes on the public listen port are proxied here (default 2022).
	DecoyPort int `toml:"decoy_port"`
	// HTTPDecoyPort serves a plaintext decoy web page so the box looks like an
	// ordinary web host to reputation scanners (default 80; negative disables it).
	HTTPDecoyPort int `toml:"http_decoy_port"`
	// DecoyStyle selects the camouflage persona: "apache" (default) or
	// "directadmin".
	DecoyStyle string `toml:"decoy_style"`
	// Domain, when set, makes the TLS mimic present a real Let's Encrypt cert (via
	// ACME) for this domain instead of self-signed. Requires the domain's A/AAAA
	// records to point at this server. ACMEEmail is the optional account email.
	Domain    string `toml:"domain"`
	ACMEEmail string `toml:"acme_email"`

	// ---- Iran (entry hub) fields ----

	// ServerAddr is the foreign node's public host or IP, ServerPort its listen
	// port (the ListenPort configured on the foreign side).
	ServerAddr string `toml:"server_addr"`
	ServerPort int    `toml:"server_port"`
	// SocksPort is the localhost SOCKS5 port the hub exposes for X-UI/Xray.
	SocksPort int `toml:"socks_port"`
	// ServerName is the TLS SNI/CN the pipes present (mimic "tls" only; optional).
	ServerName string `toml:"server_name"`
	// Pool sizing and per-pipe bandwidth targets (Chaos Mesh dynamic scaling). All
	// optional — the engine applies sensible defaults when zero.
	MinConnections      int `toml:"min_connections"`
	MaxConnections      int `toml:"max_connections"`
	BandwidthLimitMbps  int `toml:"bandwidth_limit_mbps"`
	BandwidthJitterMbps int `toml:"bandwidth_jitter_mbps"`

	LogLevel string `toml:"log_level"` // none/debug/info/warn/error (default info)
}

// Config represents the complete configuration, including both server and client settings.
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Client    ClientConfig    `toml:"client"`
	WireGuard WireGuardConfig `toml:"wireguard"`
	Packet    PacketConfig    `toml:"packet"`
	SSH       SSHConfig       `toml:"ssh"`
	Hedioum   HedioumConfig   `toml:"hedioum"`
}
