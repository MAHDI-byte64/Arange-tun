package manage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// Tunnel is a discovered tunnel derived from a config file on disk.
type Tunnel struct {
	Name      string
	Role      string // "server" or "client"
	Transport string
	Addr      string   // bind_addr (server) or remote_addr (client)
	Ports     []string // server only
	Service   string
}

// List scans the config directory and returns all tunnels, sorted by name.
func List() []Tunnel {
	var tunnels []Tunnel
	matches, _ := filepath.Glob(app.ConfigDir + "/*.toml")
	for _, path := range matches {
		var cfg config.Config
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t := Tunnel{Name: name, Service: app.ServiceName(name)}
		switch {
		case cfg.WireGuard.Role != "":
			// WireGuard is a VPN egress, not a reverse tunnel. For a client the
			// address is the WG endpoint it dials; for a server it is the UDP
			// port it listens on.
			t.Role = cfg.WireGuard.Role
			t.Transport = "wireguard"
			if cfg.WireGuard.Role == "client" {
				t.Addr = cfg.WireGuard.Endpoint
			} else {
				t.Addr = fmt.Sprintf(":%d", cfg.WireGuard.ListenPort)
			}
		case cfg.Packet.Role != "":
			// Packet is a raw-packet tunnel with an inverted topology: the client
			// (Iran) exposes the forwarded ports and dials the server (abroad).
			t.Role = cfg.Packet.Role
			t.Transport = "packet"
			if cfg.Packet.Role == "client" {
				t.Addr = cfg.Packet.ServerAddr
				t.Ports = cfg.Packet.Ports
			} else {
				t.Addr = fmt.Sprintf(":%d", cfg.Packet.ListenPort)
			}
		case cfg.SSH.Role != "":
			// SSH is a client-only VPN egress: it dials an SSH server and exposes
			// a local SOCKS5. Its address is the server it dials.
			t.Role = "client"
			t.Transport = "ssh"
			t.Addr = fmt.Sprintf("%s:%d", cfg.SSH.Host, cfg.SSH.Port)
		case cfg.Server.BindAddr != "":
			t.Role = "server"
			t.Transport = string(cfg.Server.Transport)
			t.Addr = cfg.Server.BindAddr
			t.Ports = cfg.Server.Ports
		case cfg.Client.RemoteAddr != "":
			t.Role = "client"
			t.Transport = string(cfg.Client.Transport)
			t.Addr = cfg.Client.RemoteAddr
		default:
			continue
		}
		tunnels = append(tunnels, t)
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Name < tunnels[j].Name })
	return tunnels
}

// LoadTunnelConfig reads a tunnel's full config file. Callers that need more
// than the summary List gives — preset, limits, certificate, fallbacks — read
// it through this rather than parsing the TOML themselves.
func LoadTunnelConfig(name string) (config.Config, error) {
	var cfg config.Config
	_, err := toml.DecodeFile(app.ConfigPath(name), &cfg)
	return cfg, err
}

// Delete removes a tunnel: stops/disables the service, deletes the unit,
// config, any per-tunnel refresh script, and reloads systemd.
func Delete(name string) error {
	service := app.ServiceName(name)
	if IsActive(service) || IsEnabled(service) {
		_ = DisableService(service)
	}
	removeUnit(name)
	os.Remove(app.ConfigPath(name))
	deleteTunnelMeta(name)
	return DaemonReload()
}

// RestartAll restarts every discovered tunnel service and returns how many
// were restarted and how many failed.
func RestartAll() (ok, failed int) {
	for _, t := range List() {
		if err := RestartService(t.Service); err != nil {
			failed++
		} else {
			ok++
		}
	}
	return ok, failed
}

// Find returns one tunnel by name.
func Find(name string) (Tunnel, bool) {
	for _, t := range List() {
		if t.Name == name {
			return t, true
		}
	}
	return Tunnel{}, false
}
