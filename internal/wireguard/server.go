package wireguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ifaceName is the kernel interface a WireGuard exit server brings up. It is
// derived from the listen port so two servers on one host do not collide, and
// kept within Linux's 15-character interface-name limit.
func ifaceName(port int) string { return fmt.Sprintf("arwg%d", port) }

// RunServer brings up a kernel WireGuard exit node from wc — an interface with
// the configured peers, IP forwarding, and a NAT masquerade so the peers reach
// the internet through this machine — and tears it all down when ctx ends.
//
// It needs a Linux host with kernel WireGuard support and the `ip`/`iptables`
// tools, run as root. Each step that cannot be done is reported plainly rather
// than left as a half-configured interface.
func RunServer(ctx context.Context, wc *config.WireGuardConfig, logger *logrus.Logger) {
	if _, err := exec.LookPath("ip"); err != nil {
		logger.Fatalf("wireguard server: the `ip` tool (iproute2) is required but not found")
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		logger.Fatalf("wireguard server: the `iptables` tool is required but not found")
		return
	}

	ifname := ifaceName(wc.ListenPort)
	subnet, err := subnetOf(wc.Address)
	if err != nil {
		logger.Fatalf("wireguard server: bad interface address %q: %v", wc.Address, err)
		return
	}
	egress := strings.TrimSpace(wc.Egress)
	if egress == "" {
		if e := defaultRouteInterface(); e != "" {
			egress = e
		} else {
			logger.Fatalf("wireguard server: could not detect the outbound interface — set it explicitly")
			return
		}
	}

	// A stale interface from a previous crash would make `ip link add` fail;
	// remove it first, ignoring the error when there is nothing to remove.
	_ = run("ip", "link", "del", ifname)

	if err := run("ip", "link", "add", "dev", ifname, "type", "wireguard"); err != nil {
		logger.Fatalf("wireguard server: cannot create interface %s (kernel WireGuard support?): %v", ifname, err)
		return
	}
	// From here on, tear the interface down on any early return.
	teardown := func() {
		_ = run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE")
		_ = run("iptables", "-D", "FORWARD", "-i", ifname, "-j", "ACCEPT")
		_ = run("iptables", "-D", "FORWARD", "-o", ifname, "-j", "ACCEPT")
		_ = run("ip", "link", "del", ifname)
	}

	if err := configureDevice(ifname, wc); err != nil {
		logger.Fatalf("wireguard server: cannot configure %s: %v", ifname, err)
		teardown()
		return
	}
	if err := run("ip", "address", "add", wc.Address, "dev", ifname); err != nil {
		logger.Fatalf("wireguard server: cannot set address on %s: %v", ifname, err)
		teardown()
		return
	}
	if err := run("ip", "link", "set", "up", "dev", ifname); err != nil {
		logger.Fatalf("wireguard server: cannot bring %s up: %v", ifname, err)
		teardown()
		return
	}

	// Route the peers out to the internet: forwarding on, then a masquerade so
	// their tunnel-internal source addresses become this host's public IP.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		logger.Warnf("wireguard server: could not enable IP forwarding: %v", err)
	}
	if err := run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE"); err != nil {
		logger.Fatalf("wireguard server: cannot add NAT rule: %v", err)
		teardown()
		return
	}
	_ = run("iptables", "-A", "FORWARD", "-i", ifname, "-j", "ACCEPT")
	_ = run("iptables", "-A", "FORWARD", "-o", ifname, "-j", "ACCEPT")

	logger.Infof("wireguard server: exit node up on %s (udp/%d), NAT via %s, %d peer(s)",
		ifname, wc.ListenPort, egress, len(wc.Peers))

	// The server's data plane is in the kernel, so this process never sees the
	// bytes. Read the interface's counters and report the deltas, so the panel
	// shows the exit node's traffic like every other tunnel.
	go pollTraffic(ctx, ifname)

	<-ctx.Done()
	logger.Println("wireguard server: shutting down, removing interface and NAT rules")
	teardown()
}

// pollTraffic reads the WireGuard interface's byte counters every few seconds
// and reports the change since the last read to the metrics collector. The
// counters are cumulative across all peers; "in" is what peers sent, "out" is
// what was sent to them.
func pollTraffic(ctx context.Context, ifname string) {
	cl, err := wgctrl.New()
	if err != nil {
		return
	}
	defer cl.Close()

	var lastRx, lastTx int64
	first := true
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			dev, err := cl.Device(ifname)
			if err != nil {
				continue
			}
			var rx, tx int64
			for _, p := range dev.Peers {
				rx += p.ReceiveBytes
				tx += p.TransmitBytes
			}
			if !first {
				// A counter only ever grows; a negative delta means the interface
				// was recreated, so treat it as no traffic this interval.
				din, dout := rx-lastRx, tx-lastTx
				if din < 0 {
					din = 0
				}
				if dout < 0 {
					dout = 0
				}
				if din > 0 || dout > 0 {
					metrics.AddBytes(uint64(din), uint64(dout))
				}
			}
			lastRx, lastTx, first = rx, tx, false
		}
	}
}

// configureDevice sets the private key, listen port and peers on the interface
// over netlink, so the `wg` userspace tool is not required.
func configureDevice(ifname string, wc *config.WireGuardConfig) error {
	cl, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()

	priv, err := wgtypes.ParseKey(strings.TrimSpace(wc.PrivateKey))
	if err != nil {
		return fmt.Errorf("bad private key: %w", err)
	}
	port := wc.ListenPort

	var peers []wgtypes.PeerConfig
	for _, p := range wc.Peers {
		pub, err := wgtypes.ParseKey(strings.TrimSpace(p.PublicKey))
		if err != nil {
			return fmt.Errorf("bad peer public key: %w", err)
		}
		var allowed []net.IPNet
		for _, a := range strings.Split(p.AllowedIPs, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return fmt.Errorf("bad peer allowed IP %q: %w", a, err)
			}
			allowed = append(allowed, *ipnet)
		}
		peers = append(peers, wgtypes.PeerConfig{PublicKey: pub, AllowedIPs: allowed})
	}

	replace := true
	return cl.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: replace,
		Peers:        peers,
	})
}

// subnetOf turns an interface address like "10.66.66.1/24" into its network,
// "10.66.66.0/24", which is what the NAT rule matches as its source.
func subnetOf(addr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(addr))
	if err != nil {
		return "", err
	}
	return ipnet.String(), nil
}

// defaultRouteInterface returns the interface the default route leaves by, so
// NAT masquerades out of the right link without the operator naming it.
func defaultRouteInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// run executes a short-lived system command, returning its combined output as
// part of the error so a failure explains itself.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GeneratedExitServer is the result of generating an exit-node setup: what the
// server stores, and the ready-to-paste client config it hands out.
type GeneratedExitServer struct {
	ServerPrivateKey string
	ServerPublicKey  string
	Address          string          // server interface address, e.g. "10.66.66.1/24"
	Peers            []config.WGPeer // the generated client as an allowed peer
	ClientConfigText string          // a wg-quick .conf for the kharej/user side
}

// GenerateExitServer builds a fresh exit-node keypair and one client, and
// renders the client's wg-quick config pointing at endpointHost:listenPort.
func GenerateExitServer(listenPort int, endpointHost, dns string) (*GeneratedExitServer, error) {
	srvPriv, srvPub, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	cliPriv, cliPub, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dns) == "" {
		dns = "1.1.1.1"
	}
	serverAddr := "10.66.66.1/24"
	clientAddr := "10.66.66.2/32"

	var conf strings.Builder
	fmt.Fprintf(&conf, "[Interface]\n")
	fmt.Fprintf(&conf, "PrivateKey = %s\n", cliPriv)
	fmt.Fprintf(&conf, "Address = %s\n", clientAddr)
	fmt.Fprintf(&conf, "DNS = %s\n\n", dns)
	fmt.Fprintf(&conf, "[Peer]\n")
	fmt.Fprintf(&conf, "PublicKey = %s\n", srvPub)
	fmt.Fprintf(&conf, "Endpoint = %s:%d\n", endpointHost, listenPort)
	fmt.Fprintf(&conf, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&conf, "PersistentKeepalive = 25\n")

	return &GeneratedExitServer{
		ServerPrivateKey: srvPriv,
		ServerPublicKey:  srvPub,
		Address:          serverAddr,
		Peers:            []config.WGPeer{{PublicKey: cliPub, AllowedIPs: clientAddr}},
		ClientConfigText: conf.String(),
	}, nil
}
