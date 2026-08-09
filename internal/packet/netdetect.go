package packet

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The Packet engine crafts link-layer frames itself, so it must know the
// outbound interface, this host's IPv4 on it, and the gateway (router) MAC to
// address those frames to. The upstream tool asks the operator for all three;
// we detect them from the default route instead, so a Packet tunnel needs no
// manual network wiring. Any field the user did set in the config wins.

// resolveNetwork fills interface, local IPv4 and gateway MAC from the config,
// falling back to auto-detection for whichever are empty.
func resolveNetwork(iface, localIP, routerMAC string) (string, string, string, error) {
	gwIP, gwIface := defaultRoute()
	if iface == "" {
		iface = gwIface
	}
	if iface == "" {
		return "", "", "", fmt.Errorf("could not determine the network interface; set [packet].interface")
	}
	if localIP == "" {
		ip, err := interfaceIPv4(iface)
		if err != nil {
			return "", "", "", fmt.Errorf("could not determine this host's IPv4 on %s; set [packet].local_ip: %w", iface, err)
		}
		localIP = ip
	}
	if routerMAC == "" {
		if gwIP == "" {
			return "", "", "", fmt.Errorf("could not determine the gateway IP; set [packet].router_mac")
		}
		mac, err := gatewayMAC(gwIP)
		if err != nil {
			return "", "", "", fmt.Errorf("could not determine the gateway MAC for %s; set [packet].router_mac: %w", gwIP, err)
		}
		routerMAC = mac
	}
	return iface, localIP, routerMAC, nil
}

// defaultRoute returns the gateway IP and interface of the IPv4 default route,
// parsed from `ip route show default` (e.g. "default via 192.168.1.1 dev eth0").
func defaultRoute() (gwIP, iface string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		switch f {
		case "via":
			if i+1 < len(fields) {
				gwIP = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				iface = fields[i+1]
			}
		}
	}
	return gwIP, iface
}

// interfaceIPv4 returns the first non-loopback IPv4 address on the interface.
func interfaceIPv4(name string) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address on %s", name)
}

// gatewayMAC resolves the gateway's MAC. It reads the kernel ARP/neighbour
// table; if the entry is missing it primes resolution by sending a datagram at
// the gateway (which forces an ARP request) and then polls briefly.
func gatewayMAC(gwIP string) (string, error) {
	if mac := lookupMAC(gwIP); mac != "" {
		return mac, nil
	}
	// Prime the neighbour table: a UDP send to the gateway makes the kernel ARP
	// for it. The datagram itself is discarded; only the ARP entry matters.
	if c, err := net.DialTimeout("udp", net.JoinHostPort(gwIP, "9"), time.Second); err == nil {
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}
	for i := 0; i < 15; i++ {
		if mac := lookupMAC(gwIP); mac != "" {
			return mac, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", fmt.Errorf("gateway %s not found in the neighbour table", gwIP)
}

// lookupMAC returns the MAC for an IP from /proc/net/arp, falling back to
// `ip neigh`. It ignores incomplete (all-zero) entries.
func lookupMAC(ip string) string {
	if mac := arpTableMAC(ip); mac != "" {
		return mac
	}
	return ipNeighMAC(ip)
}

func arpTableMAC(ip string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// IPaddress HWtype Flags HWaddress Mask Device
		if len(fields) >= 4 && fields[0] == ip && validMAC(fields[3]) {
			return fields[3]
		}
	}
	return ""
}

func ipNeighMAC(ip string) string {
	out, err := exec.Command("ip", "neigh", "show", ip).Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) && validMAC(fields[i+1]) {
			return fields[i+1]
		}
	}
	return ""
}

func validMAC(s string) bool {
	if _, err := net.ParseMAC(s); err != nil {
		return false
	}
	return s != "00:00:00:00:00:00"
}

// portOnly formats a bare port for iptables --dport/--sport arguments.
func portOnly(p int) string { return strconv.Itoa(p) }
