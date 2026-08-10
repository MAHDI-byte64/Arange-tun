package spoof

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// The spoof engine sends through a raw IP socket (the kernel picks the outgoing
// interface by the destination route), but the pcap receiver needs a named
// interface to capture on. Detect the default-route interface unless the config
// names one.

func resolveIface(iface string) (string, error) {
	if iface != "" {
		return iface, nil
	}
	if dev := defaultRouteIface(); dev != "" {
		return dev, nil
	}
	return "", fmt.Errorf("could not determine the network interface; set [spoof].interface")
}

func defaultRouteIface() string {
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

// localIPv4 returns this host's first non-loopback IPv4 on the interface, used
// as a fallback when the config does not set local_ip (the real receive IP).
func localIPv4(iface string) (string, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 on %s", iface)
}
