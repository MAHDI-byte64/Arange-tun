package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// AppConfig represents the root structure of the application configuration
type AppConfig struct {
	Role string `json:"role"` // "iran" or "foreign"

	// Foreign Node specific properties
	ForeignListenPort int    `json:"foreign_listen_port,omitempty"`
	AuthToken         string `json:"auth_token,omitempty"`
	// EgressIPMode controls how the foreign node dials the open internet:
	// "ipv4" (default, no v6 identity leak), "ipv6", or "dual". EgressBindIP
	// optionally pins the source IP on multi-IP servers.
	EgressIPMode string `json:"egress_ip_mode,omitempty"`
	EgressBindIP string `json:"egress_bind_ip,omitempty"`
	// DecoyPort is the local port the real sshd was relocated to; unauthorized
	// probes on the public listen port are proxied here. Default 2022.
	DecoyPort int `json:"decoy_port,omitempty"`
	// HTTPDecoyPort serves a plaintext Apache "It works" page so the server looks
	// like an ordinary web host to IP-reputation scanners. Default 80; a negative
	// value disables it.
	HTTPDecoyPort int `json:"http_decoy_port,omitempty"`
	// Domain, when set, makes the TLS mimic present a real Let's Encrypt certificate
	// for this domain (via ACME) instead of the self-signed cert — the strongest
	// defence against passive cert fingerprinting. Requires the domain's A/AAAA
	// records to point at this server. Empty = self-signed (still works, less safe).
	Domain string `json:"domain,omitempty"`
	// ACMEEmail is the optional Let's Encrypt account email (expiry notices).
	ACMEEmail string `json:"acme_email,omitempty"`
	// DecoyStyle selects the camouflage persona served to unauthorized probes:
	// "apache" (default, the Apache2 Ubuntu default page) or "directadmin" (a
	// DirectAdmin hosting box — "webserver is functioning normally" on the web ports
	// and the DirectAdmin panel on :2222).
	DecoyStyle string `json:"decoy_style,omitempty"`
	// Mimics lists the camouflage listeners the foreign runs (SSH, TLS, ...). If
	// empty, a single SSH listener is synthesized from ForeignListenPort/DecoyPort.
	Mimics []MimicListener `json:"mimics,omitempty"`

	// Iran Node specific properties
	ForeignNodes []ForeignNode `json:"foreign_nodes,omitempty"`
}

// MimicListener is one camouflage listener on the foreign node.
type MimicListener struct {
	Type       string `json:"type"`                  // "ssh" | "tls" | "smtp" | "imap"
	Port       int    `json:"port"`                  // public listen port
	Decoy      string `json:"decoy,omitempty"`       // decoy backend; "" = protocol default
	ServerName string `json:"server_name,omitempty"` // TLS SNI/CN (optional)
}

// Endpoint is one way the hub reaches a foreign node (a target port + mimic). A
// node's endpoints share one SOCKS port and one pool; the dialer spreads pipes
// across them with a fluctuating mimic distribution.
type Endpoint struct {
	Target     string `json:"target"`                // "host:port"
	Mimic      string `json:"mimic"`                 // "ssh" | "tls" | "smtp" | "imap"
	ServerName string `json:"server_name,omitempty"` // TLS SNI
}

// ForeignNode defines the connection parameters for upstream egress servers
type ForeignNode struct {
	Alias          string `json:"alias"`
	TargetIP       string `json:"target_ip"`
	TargetPort     int    `json:"target_port"`
	LocalSocksPort int    `json:"local_socks_port"`
	// Endpoints are the (target, mimic) pairs this one SOCKS port is served by. If
	// empty, a single SSH endpoint is synthesized from TargetIP/TargetPort.
	Endpoints           []Endpoint `json:"endpoints,omitempty"`
	MinConnections      int        `json:"min_connections"`       // Establishes the baseline warm-up pool size
	MaxConnections      int        `json:"max_connections"`       // Dynamically customizes pool sizing per server
	BandwidthLimitMbps  int        `json:"bandwidth_limit_mbps"`  // Target speed (Mbps) per physical connection before scale-up
	BandwidthJitterMbps int        `json:"bandwidth_jitter_mbps"` // Variance to evade DPI patterns (Chaos Mesh)
	AuthToken           string     `json:"auth_token"`
}

// getConfigPath determines the storage destination for the configuration.
// Production uses /etc/hedioum; when running as root we always use it (SaveConfig
// creates it) so a fresh install does not accidentally write the config to the
// current working directory. Non-root dev falls back to the local directory.
func getConfigPath() string {
	const prodDir = "/etc/hedioum"
	const fileName = "hedioum.json"

	if stat, err := os.Stat(prodDir); err == nil && stat.IsDir() {
		return filepath.Join(prodDir, fileName)
	}
	if os.Geteuid() == 0 {
		return filepath.Join(prodDir, fileName)
	}
	return fileName
}

// LoadConfig reads the configuration state from the persistent storage layer
func LoadConfig() (*AppConfig, error) {
	configPath := getConfigPath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, errors.New("configuration file does not exist")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

// parseConfig unmarshals config JSON and applies backward-compatible defaults.
// Separated from disk I/O so it is unit-testable.
func parseConfig(data []byte) (*AppConfig, error) {
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// --- Backward Compatibility & Fallback Logic ---
	// Ensures existing deployments won't crash due to missing fields in old JSON configs.
	if cfg.Role == "foreign" && cfg.EgressIPMode == "" {
		cfg.EgressIPMode = "ipv4" // default: no IPv6 identity leak
	}
	if cfg.Role == "foreign" && cfg.DecoyPort == 0 {
		cfg.DecoyPort = 2022 // default decoy sshd port
	}
	if cfg.Role == "foreign" && cfg.HTTPDecoyPort == 0 {
		cfg.HTTPDecoyPort = 80 // default: serve an Apache decoy on :80 (negative = off)
	}
	if cfg.Role == "foreign" && cfg.DecoyStyle == "" {
		cfg.DecoyStyle = "apache" // default persona (backward compatible)
	}
	// Synthesize a single SSH listener from the legacy fields if none configured,
	// so v0.6 foreign configs keep working unchanged.
	if cfg.Role == "foreign" && len(cfg.Mimics) == 0 {
		port := cfg.ForeignListenPort
		if port == 0 {
			port = 22
		}
		cfg.Mimics = []MimicListener{{
			Type:  "ssh",
			Port:  port,
			Decoy: fmt.Sprintf("127.0.0.1:%d", cfg.DecoyPort),
		}}
	}

	for i := range cfg.ForeignNodes {
		if cfg.ForeignNodes[i].TargetPort == 0 {
			cfg.ForeignNodes[i].TargetPort = 22 // Default fallback for old configs
		}
		// Synthesize a single SSH endpoint from the legacy target if none set.
		if len(cfg.ForeignNodes[i].Endpoints) == 0 {
			cfg.ForeignNodes[i].Endpoints = []Endpoint{{
				Target: net.JoinHostPort(cfg.ForeignNodes[i].TargetIP, strconv.Itoa(cfg.ForeignNodes[i].TargetPort)),
				Mimic:  "ssh",
			}}
		}
		if cfg.ForeignNodes[i].MinConnections == 0 {
			cfg.ForeignNodes[i].MinConnections = 10 // Default baseline: 10 connections
		}
		if cfg.ForeignNodes[i].MaxConnections == 0 {
			cfg.ForeignNodes[i].MaxConnections = 20 // Default max limit
		}
		if cfg.ForeignNodes[i].BandwidthLimitMbps == 0 {
			cfg.ForeignNodes[i].BandwidthLimitMbps = 8 // Default target: 8 Mbps per connection
		}
		if cfg.ForeignNodes[i].BandwidthJitterMbps == 0 {
			cfg.ForeignNodes[i].BandwidthJitterMbps = 2 // Default jitter: +/- 2 Mbps (Chaos variance)
		}
	}

	return &cfg, nil
}

// SaveConfig persists the current application configuration state atomically to disk
func SaveConfig(cfg *AppConfig) error {
	configPath := getConfigPath()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Ensure the parent directory exists if using localized paths
	dir := filepath.Dir(configPath)
	if dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(configPath, data, 0600)
}

// UpdateForeignNode rewrites an existing node configuration or appends it if missing
func (cfg *AppConfig) UpdateForeignNode(updatedNode ForeignNode) {
	for i, node := range cfg.ForeignNodes {
		if node.Alias == updatedNode.Alias {
			cfg.ForeignNodes[i] = updatedNode
			return
		}
	}
	cfg.ForeignNodes = append(cfg.ForeignNodes, updatedNode)
}

// RemoveForeignNode purges a registered egress target from the slice by its unique alias
func (cfg *AppConfig) RemoveForeignNode(alias string) bool {
	for i, node := range cfg.ForeignNodes {
		if node.Alias == alias {
			cfg.ForeignNodes = append(cfg.ForeignNodes[:i], cfg.ForeignNodes[i+1:]...)
			return true
		}
	}
	return false
}
