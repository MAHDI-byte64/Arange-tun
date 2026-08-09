package manage

// Packet tunnels are created like WireGuard ones: a separate engine with its
// own [packet] section rather than the reverse-proxy TunnelSpec path. The
// topology is inverted — the SERVER is the abroad exit node and the CLIENT is
// the Iran entry that exposes the forwarded ports and dials out — so the server
// is created first (it hands back a shared key) and the client is pointed at it.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// CreatePacketServer starts an abroad exit node listening on listenPort and
// returns the shared key the client must use (generated when key is empty).
func CreatePacketServer(name string, listenPort int, key, block string) (string, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return "", fmt.Errorf("invalid tunnel name %q — use letters, digits, dots, dashes (max 40)", name)
	}
	if _, ok := Find(name); ok {
		return "", fmt.Errorf("a tunnel named %q already exists", name)
	}
	if listenPort < 1 || listenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", listenPort)
	}
	if listenPort == 80 || listenPort == 443 {
		return "", fmt.Errorf("port %d is a standard port; the RST-drop firewall rules would disrupt normal traffic on it — pick a high, non-standard port", listenPort)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		k, err := randomKey()
		if err != nil {
			return "", err
		}
		key = k
	}
	toml := packetRenderServer(name, listenPort, key, strings.TrimSpace(block))
	if _, err := saveGeneratedTunnel(name, toml); err != nil {
		return "", err
	}
	return key, nil
}

// CreatePacketClient starts an Iran entry node that exposes ports (each relayed
// to 127.0.0.1:<port> on the server) and dials serverAddr with the shared key.
func CreatePacketClient(name, serverAddr, key, block string, ports []string, socks string) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return fmt.Errorf("invalid tunnel name %q — use letters, digits, dots, dashes (max 40)", name)
	}
	if _, ok := Find(name); ok {
		return fmt.Errorf("a tunnel named %q already exists", name)
	}
	serverAddr = strings.TrimSpace(serverAddr)
	if serverAddr == "" {
		return fmt.Errorf("the server address (abroad host:port) is required")
	}
	if _, _, err := splitHostPortStrict(serverAddr); err != nil {
		return fmt.Errorf("invalid server address %q: %w", serverAddr, err)
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("the shared key is required — copy it from the server")
	}
	ports = cleanPorts(ports)
	socks = strings.TrimSpace(socks)
	if len(ports) == 0 && socks == "" {
		return fmt.Errorf("give at least one port to expose, or a SOCKS5 listen address")
	}
	toml := packetRenderClient(name, serverAddr, strings.TrimSpace(key), strings.TrimSpace(block), ports, socks)
	_, err := saveGeneratedTunnel(name, toml)
	return err
}

// PacketEdit is a packet tunnel's config in the shape the create/edit form uses.
type PacketEdit struct {
	Role       string   `json:"role"`
	ListenPort int      `json:"listenPort"`
	ServerAddr string   `json:"serverAddr"`
	Key        string   `json:"key"`
	Block      string   `json:"block"`
	Ports      []string `json:"ports"`
	Socks      string   `json:"socks"`
}

// PacketForEdit loads a packet tunnel's config so the panel can prefill its form.
func PacketForEdit(name string) (PacketEdit, error) {
	cfg, err := LoadTunnelConfig(name)
	if err != nil {
		return PacketEdit{}, err
	}
	p := cfg.Packet
	if p.Role == "" {
		return PacketEdit{}, fmt.Errorf("%q is not a packet tunnel", name)
	}
	return PacketEdit{
		Role:       p.Role,
		ListenPort: p.ListenPort,
		ServerAddr: p.ServerAddr,
		Key:        p.Key,
		Block:      p.Block,
		Ports:      p.Ports,
		Socks:      p.Socks,
	}, nil
}

// UpdatePacketServer overwrites an existing packet server and restarts it. An
// empty key keeps the current one, so an edit that does not touch the key does
// not silently rotate it.
func UpdatePacketServer(name string, listenPort int, key, block string) (string, error) {
	name = strings.TrimSpace(name)
	if !fileExists(app.ConfigPath(name)) {
		return "", fmt.Errorf("no tunnel named %q to edit", name)
	}
	if listenPort < 1 || listenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", listenPort)
	}
	if listenPort == 80 || listenPort == 443 {
		return "", fmt.Errorf("port %d is a standard port; pick a high, non-standard port", listenPort)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		if cfg, err := LoadTunnelConfig(name); err == nil {
			key = cfg.Packet.Key
		}
		if key == "" {
			return "", fmt.Errorf("the shared key is required")
		}
	}
	toml := packetRenderServer(name, listenPort, key, strings.TrimSpace(block))
	if _, err := saveGeneratedTunnel(name, toml); err != nil {
		return "", err
	}
	return key, nil
}

// UpdatePacketClient overwrites an existing packet client and restarts it.
func UpdatePacketClient(name, serverAddr, key, block string, ports []string, socks string) error {
	name = strings.TrimSpace(name)
	if !fileExists(app.ConfigPath(name)) {
		return fmt.Errorf("no tunnel named %q to edit", name)
	}
	serverAddr = strings.TrimSpace(serverAddr)
	if serverAddr == "" {
		return fmt.Errorf("the server address (abroad host:port) is required")
	}
	if _, _, err := splitHostPortStrict(serverAddr); err != nil {
		return fmt.Errorf("invalid server address %q: %w", serverAddr, err)
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("the shared key is required")
	}
	ports = cleanPorts(ports)
	socks = strings.TrimSpace(socks)
	if len(ports) == 0 && socks == "" {
		return fmt.Errorf("give at least one port to expose, or a SOCKS5 listen address")
	}
	toml := packetRenderClient(name, serverAddr, strings.TrimSpace(key), strings.TrimSpace(block), ports, socks)
	_, err := saveGeneratedTunnel(name, toml)
	return err
}

func packetRenderServer(name string, listenPort int, key, block string) string {
	var b strings.Builder
	b.WriteString("# Generated by arange-tun — do not edit while the service is running.\n")
	fmt.Fprintf(&b, "# name = %q\n\n", name)
	b.WriteString("[packet]\n")
	b.WriteString("role = \"server\"\n")
	fmt.Fprintf(&b, "listen_port = %d\n", listenPort)
	fmt.Fprintf(&b, "key = %q\n", key)
	if block != "" {
		fmt.Fprintf(&b, "block = %q\n", block)
	}
	return b.String()
}

func packetRenderClient(name, serverAddr, key, block string, ports []string, socks string) string {
	var b strings.Builder
	b.WriteString("# Generated by arange-tun — do not edit while the service is running.\n")
	fmt.Fprintf(&b, "# name = %q\n\n", name)
	b.WriteString("[packet]\n")
	b.WriteString("role = \"client\"\n")
	fmt.Fprintf(&b, "server_addr = %q\n", serverAddr)
	fmt.Fprintf(&b, "key = %q\n", key)
	if block != "" {
		fmt.Fprintf(&b, "block = %q\n", block)
	}
	if len(ports) > 0 {
		b.WriteString("ports = [")
		for i, p := range ports {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", p)
		}
		b.WriteString("]\n")
	}
	if socks != "" {
		fmt.Fprintf(&b, "socks = %q\n", socks)
	}
	return b.String()
}

// randomKey returns 32 random bytes as hex, a strong default shared secret.
func randomKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// cleanPorts trims, drops blanks, and validates each port is 1–65535.
func cleanPorts(ports []string) []string {
	var out []string
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			out = append(out, p)
		}
	}
	return out
}

func splitHostPortStrict(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("host is required")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port must be 1-65535")
	}
	return host, port, nil
}
