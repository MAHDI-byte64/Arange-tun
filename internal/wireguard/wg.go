// Package wireguard adds a WireGuard tunnel to Arange-tun. Unlike the reverse
// tunnels (Amin, frp, rathole) it does not forward ports back to Iran; it is a
// VPN egress with two roles:
//
//   - a "server" is a real kernel WireGuard exit node that NATs its peers out to
//     the internet (see server.go), handing out a ready client config;
//   - a "client" brings WireGuard up in userspace — no kernel interface, no
//     change to the host's routing — and exposes a SOCKS5 proxy whose traffic
//     egresses through the tunnel. That proxy is what a panel like x-ui points an
//     outbound at, so its users leave by the WireGuard endpoint's IP.
//
// The userspace side is built on wireguard-go's netstack TUN: the SOCKS5 server
// dials each target through the in-process network stack, so nothing touches the
// machine's real interfaces or route table.
package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ParsedClient holds the fields pulled out of a pasted wg-quick config, ready to
// store in a WireGuardConfig.
type ParsedClient struct {
	PrivateKey    string
	Address       string
	DNS           string
	MTU           int
	PeerPublicKey string
	PresharedKey  string
	Endpoint      string
	AllowedIPs    string
	Keepalive     int
}

// ParseClientConfig reads a standard wg-quick config ([Interface] / [Peer]) and
// returns its fields. It is lenient about spacing and case in the keys, which is
// how these configs vary in the wild.
func ParseClientConfig(text string) (*ParsedClient, error) {
	pc := &ParsedClient{}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				pc.PrivateKey = val
			case "address":
				pc.Address = val
			case "dns":
				pc.DNS = val
			case "mtu":
				pc.MTU, _ = strconv.Atoi(val)
			}
		case "peer":
			switch key {
			case "publickey":
				pc.PeerPublicKey = val
			case "presharedkey":
				pc.PresharedKey = val
			case "endpoint":
				pc.Endpoint = val
			case "allowedips":
				pc.AllowedIPs = val
			case "persistentkeepalive":
				pc.Keepalive, _ = strconv.Atoi(val)
			}
		}
	}
	if pc.PrivateKey == "" {
		return nil, fmt.Errorf("no PrivateKey in the [Interface] section")
	}
	if pc.Address == "" {
		return nil, fmt.Errorf("no Address in the [Interface] section")
	}
	if pc.PeerPublicKey == "" {
		return nil, fmt.Errorf("no PublicKey in the [Peer] section")
	}
	if pc.Endpoint == "" {
		return nil, fmt.Errorf("no Endpoint in the [Peer] section")
	}
	if _, err := wgtypes.ParseKey(pc.PrivateKey); err != nil {
		return nil, fmt.Errorf("the Interface PrivateKey is not a valid WireGuard key")
	}
	if _, err := wgtypes.ParseKey(pc.PeerPublicKey); err != nil {
		return nil, fmt.Errorf("the Peer PublicKey is not a valid WireGuard key")
	}
	return pc, nil
}

// GenerateKeypair returns a fresh WireGuard private/public key pair, base64
// encoded the way every WireGuard config writes them.
func GenerateKeypair() (priv, pub string, err error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return k.String(), k.PublicKey().String(), nil
}

// keyHex converts a base64 WireGuard key to the hex the wireguard-go uapi wants.
func keyHex(b64 string) (string, error) {
	k, err := wgtypes.ParseKey(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

// RunClient brings up a userspace WireGuard tunnel from wc and serves a SOCKS5
// proxy through it until ctx ends.
func RunClient(ctx context.Context, wc *config.WireGuardConfig, logger *logrus.Logger) {
	// Interface addresses (the tunnel's own IPs), stripped of any /prefix.
	var addrs []netip.Addr
	for _, a := range strings.Split(wc.ClientAddress, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if i := strings.IndexByte(a, '/'); i >= 0 {
			a = a[:i]
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			logger.Fatalf("wireguard: bad interface address %q: %v", a, err)
			return
		}
		addrs = append(addrs, ip)
	}
	if len(addrs) == 0 {
		logger.Fatalf("wireguard: the client has no interface address")
		return
	}

	// DNS resolvers, reached through the tunnel. Cloudflare's is the default
	// because it is what most generated configs use and it answers over WG.
	dnsStr := strings.TrimSpace(wc.DNS)
	if dnsStr == "" {
		dnsStr = "1.1.1.1"
	}
	var dns []netip.Addr
	for _, d := range strings.Split(dnsStr, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if ip, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, ip)
		}
	}

	mtu := wc.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	tun, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		logger.Fatalf("wireguard: cannot create tunnel device: %v", err)
		return
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard "))
	uapi, err := clientUAPI(wc)
	if err != nil {
		logger.Fatalf("wireguard: %v", err)
		dev.Close()
		return
	}
	if err := dev.IpcSet(uapi); err != nil {
		logger.Fatalf("wireguard: cannot configure the tunnel: %v", err)
		dev.Close()
		return
	}
	if err := dev.Up(); err != nil {
		logger.Fatalf("wireguard: cannot bring the tunnel up: %v", err)
		dev.Close()
		return
	}
	logger.Infof("wireguard client: tunnel up (endpoint %s)", wc.Endpoint)

	bind := strings.TrimSpace(wc.SocksBind)
	if bind == "" {
		bind = "127.0.0.1"
	}
	socksAddr := net.JoinHostPort(bind, strconv.Itoa(wc.SocksPort))
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", socksAddr)
	if err != nil {
		logger.Fatalf("wireguard: cannot bind SOCKS5 on %s: %v", socksAddr, err)
		dev.Close()
		return
	}
	logger.Infof("wireguard client: SOCKS5 proxy on %s — traffic egresses through the tunnel", socksAddr)

	if host := endpointHost(wc.Endpoint); host != "" {
		metrics.ReportPeer(host)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
		dev.Close()
		metrics.ClearPeer()
	}()

	// The SOCKS5 server dials every target through the WireGuard netstack.
	serveSOCKS5(ctx, ln, tnet.DialContext, logger)
}

// clientUAPI renders wireguard-go's configuration string for the client device.
func clientUAPI(wc *config.WireGuardConfig) (string, error) {
	priv, err := keyHex(wc.ClientPrivateKey)
	if err != nil {
		return "", fmt.Errorf("bad client private key: %w", err)
	}
	pub, err := keyHex(wc.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("bad peer public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if strings.TrimSpace(wc.PresharedKey) != "" {
		psk, err := keyHex(wc.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("bad preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}

	// The endpoint is reached over the real internet; resolve a hostname to an
	// ip:port here so the tunnel does not depend on wireguard-go's resolver.
	ep := strings.TrimSpace(wc.Endpoint)
	if ep != "" {
		if ipport, err := resolveEndpoint(ep); err == nil {
			ep = ipport
		}
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
	}

	ka := wc.Keepalive
	if ka <= 0 {
		ka = 25 // keep the NAT mapping open, as most configs do
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", ka)

	allowed := strings.TrimSpace(wc.AllowedIPs)
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0" // full tunnel: everything egresses through WG
	}
	for _, a := range strings.Split(allowed, ",") {
		if a = strings.TrimSpace(a); a != "" {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), nil
}

// resolveEndpoint turns "host:port" into "ip:port", leaving an address that is
// already numeric untouched.
func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return ep, err
	}
	if net.ParseIP(host) != nil {
		return ep, nil // already numeric
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ep, fmt.Errorf("cannot resolve %q", host)
	}
	return net.JoinHostPort(ips[0], port), nil
}

// endpointHost returns just the host part of an endpoint, for the status peer.
func endpointHost(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ep); err == nil {
		return host
	}
	return ep
}
