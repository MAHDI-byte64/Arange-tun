// Package packet is the Arange-tun adapter around the vendored paqet engine (in
// ./engine, MIT-licensed — see engine/LICENSE). paqet is a raw-packet proxy: it
// captures and injects crafted TCP packets with libpcap, carrying KCP+smux
// below the kernel's TCP/IP stack, so DPI and stateful firewalls that track the
// kernel's own connections never see the tunnel.
//
// The topology is inverted from the reverse-proxy tunnels: the SERVER is the
// abroad exit node and the CLIENT is the Iran entry that exposes the forwarded
// ports and dials out. This adapter builds the engine's config from our TOML
// [packet] section, auto-detects the network parameters the engine needs, and
// installs the firewall rules that keep the raw session alive.
package packet

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/client"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/conf"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/forward"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/pkg/buffer"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/server"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/socks"
)

// RunServer runs the abroad exit node until ctx ends.
func RunServer(ctx context.Context, pc *config.PacketConfig, logger *logrus.Logger) {
	requireRoot(logger)
	cfg, port, err := buildServerConf(pc)
	if err != nil {
		logger.Fatalf("packet server: %v", err)
	}
	initEngine(cfg)

	rules := serverRules(port)
	if haveIptables() {
		applyFirewall(rules, logger)
		defer removeFirewall(rules, logger)
	} else {
		logger.Warnf("packet server: iptables not found — the kernel's RST packets may disrupt the tunnel; install iptables")
	}

	srv, err := server.New(cfg)
	if err != nil {
		logger.Fatalf("packet server: failed to initialize: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		logger.Fatalf("packet server: %v", err)
	}
	logger.Infof("packet server started — exit node listening on :%d (iface %s)", port, cfg.Network.Interface_)

	<-ctx.Done()
	logger.Println("shutting down packet server...")
}

// RunClient runs the Iran entry node until ctx ends.
func RunClient(ctx context.Context, pc *config.PacketConfig, logger *logrus.Logger) {
	requireRoot(logger)
	cfg, serverIP, port, err := buildClientConf(pc)
	if err != nil {
		logger.Fatalf("packet client: %v", err)
	}
	initEngine(cfg)

	rules := clientRules(serverIP, port)
	if haveIptables() {
		applyFirewall(rules, logger)
		defer removeFirewall(rules, logger)
	} else {
		logger.Warnf("packet client: iptables not found — the kernel's RST packets may disrupt the tunnel; install iptables")
	}

	clnt, err := client.New(cfg)
	if err != nil {
		logger.Fatalf("packet client: failed to initialize: %v", err)
	}
	if err := clnt.Start(ctx); err != nil {
		logger.Fatalf("packet client: %v", err)
	}

	for _, ss := range cfg.SOCKS5 {
		s, err := socks.New(clnt)
		if err != nil {
			logger.Fatalf("packet client: failed to initialize SOCKS5: %v", err)
		}
		if err := s.Start(ctx, ss); err != nil {
			logger.Fatalf("packet client: SOCKS5 error: %v", err)
		}
	}
	for _, ff := range cfg.Forward {
		f, err := forward.New(clnt, ff.Listen.String(), ff.Target)
		if err != nil {
			logger.Fatalf("packet client: failed to initialize forward: %v", err)
		}
		if err := f.Start(ctx, ff.Protocol); err != nil {
			logger.Fatalf("packet client: forward error: %v", err)
		}
	}
	logger.Infof("packet client started — entry node -> %s:%d (iface %s)", serverIP, port, cfg.Network.Interface_)

	<-ctx.Done()
	logger.Println("shutting down packet client...")
}

// initEngine applies the log level and buffer sizes the engine reads globally,
// mirroring the upstream run command's setup.
func initEngine(cfg *conf.Conf) {
	flog.SetLevel(cfg.Log.Level)
	buffer.Initialize(cfg.Transport.TCPBuf, cfg.Transport.UDPBuf)
}

func buildServerConf(pc *config.PacketConfig) (*conf.Conf, int, error) {
	if pc.ListenPort <= 0 {
		return nil, 0, fmt.Errorf("listen_port is required")
	}
	iface, localIP, mac, err := resolveNetwork(pc.Interface, pc.LocalIP, pc.RouterMAC)
	if err != nil {
		return nil, 0, err
	}
	port := pc.ListenPort
	cfg := &conf.Conf{
		Role:   "server",
		Log:    conf.Log{Level_: logLevel(pc.LogLevel)},
		Listen: conf.Server{Addr_: fmt.Sprintf(":%d", port)},
		Network: conf.Network{
			Interface_: iface,
			IPv4:       conf.Addr{Addr_: net.JoinHostPort(localIP, strconv.Itoa(port)), RouterMac_: mac},
			PCAP:       conf.PCAP{Sockbuf: pc.Sockbuf},
			TCP:        conf.TCP{LF_: parseFlags(pc.LocalFlags), RF_: parseFlags(pc.RemoteFlags)},
		},
		Transport: kcpTransport(pc, 1, packetMTU(iface, pc.MTU)),
	}
	if err := conf.Prepare(cfg); err != nil {
		return nil, 0, err
	}
	return cfg, port, nil
}

func buildClientConf(pc *config.PacketConfig) (*conf.Conf, string, int, error) {
	if strings.TrimSpace(pc.ServerAddr) == "" {
		return nil, "", 0, fmt.Errorf("server_addr is required")
	}
	serverIP, port, err := resolveServerAddr(pc.ServerAddr)
	if err != nil {
		return nil, "", 0, err
	}
	iface, localIP, mac, err := resolveNetwork(pc.Interface, pc.LocalIP, pc.RouterMAC)
	if err != nil {
		return nil, "", 0, err
	}

	forwards := forwardsFor(pc)
	var socksList []conf.SOCKS5
	if s := strings.TrimSpace(pc.Socks); s != "" {
		socksList = append(socksList, conf.SOCKS5{Listen_: s})
	}
	if len(forwards) == 0 && len(socksList) == 0 {
		return nil, "", 0, fmt.Errorf("a packet client needs at least one exposed port or a socks listener")
	}

	conn := pc.Conn
	if conn <= 0 {
		conn = 1
	}
	cfg := &conf.Conf{
		Role:    "client",
		Log:     conf.Log{Level_: logLevel(pc.LogLevel)},
		SOCKS5:  socksList,
		Forward: forwards,
		Network: conf.Network{
			Interface_: iface,
			// Port 0 lets the engine pick a random source port for the raw socket.
			IPv4: conf.Addr{Addr_: net.JoinHostPort(localIP, "0"), RouterMac_: mac},
			PCAP: conf.PCAP{Sockbuf: pc.Sockbuf},
			TCP:  conf.TCP{LF_: parseFlags(pc.LocalFlags), RF_: parseFlags(pc.RemoteFlags)},
		},
		Server:    conf.Server{Addr_: net.JoinHostPort(serverIP, strconv.Itoa(port))},
		Transport: kcpTransport(pc, conn, packetMTU(iface, pc.MTU)),
	}
	if err := conf.Prepare(cfg); err != nil {
		return nil, "", 0, err
	}
	return cfg, serverIP, port, nil
}

// forwardsFor builds the engine forward mappings: each exposed port is relayed
// 1:1 to 127.0.0.1:<port> on the server side, plus any explicit mappings.
func forwardsFor(pc *config.PacketConfig) []conf.Forward {
	var out []conf.Forward
	for _, p := range pc.Ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, conf.Forward{
			Listen_:  net.JoinHostPort("0.0.0.0", p),
			Target:   net.JoinHostPort("127.0.0.1", p),
			Protocol: "tcp",
		})
	}
	for _, f := range pc.Forward {
		proto := strings.TrimSpace(f.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		out = append(out, conf.Forward{Listen_: f.Listen, Target: f.Target, Protocol: proto})
	}
	return out
}

func kcpTransport(pc *config.PacketConfig, conn, mtu int) conf.Transport {
	return conf.Transport{
		Protocol: "kcp",
		Conn:     conn,
		KCP: &conf.KCP{
			Block_: strings.TrimSpace(pc.Block),
			Key:    pc.Key,
			Mode:   strings.TrimSpace(pc.Mode),
			MTU:    mtu,
		},
	}
}

// packetFrameOverhead is the worst-case link+IP+TCP header size the raw engine
// prepends to a KCP segment: Ethernet(14) + IPv4(20) + TCP with options(<=40),
// plus a little margin.
const packetFrameOverhead = 80

// packetMTU chooses the KCP MTU. The raw engine turns each KCP segment into one
// crafted Ethernet frame and injects it with the DF bit set, so the frame must
// fit the interface MTU or the driver rejects it with EMSGSIZE ("message too
// long"), and it must also survive the path to the peer. The default (1280, the
// IPv6 minimum MTU) is deliverable across virtually any Iran<->abroad path; a
// user-set value is honoured but still capped to what the local link can carry.
func packetMTU(iface string, requested int) int {
	m := requested
	if m <= 0 {
		m = 1280
	}
	if ifi, err := net.InterfaceByName(iface); err == nil && ifi.MTU > 0 {
		if limit := ifi.MTU - packetFrameOverhead; limit > 0 && m > limit {
			m = limit
		}
	}
	// The KCP engine accepts 50..1500; keep well inside that.
	if m > 1500 {
		m = 1500
	}
	if m < 576 {
		m = 576
	}
	return m
}

// resolveServerAddr splits and resolves the abroad host:port to an IPv4 and
// port. The firewall rules match the numeric server IP, so a hostname is
// resolved here.
func resolveServerAddr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, fmt.Errorf("invalid server_addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid server port in %q", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), port, nil
		}
		return host, port, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", 0, fmt.Errorf("could not resolve server_addr host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), port, nil
		}
	}
	return "", 0, fmt.Errorf("no IPv4 address for server_addr host %q", host)
}

// parseFlags turns "PA,A" into ["PA","A"]; empty yields nil so the engine
// applies its default ("PA").
func parseFlags(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func logLevel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "none"
	}
	return s
}

func haveIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}
