package hedioum

import (
	"testing"

	appconfig "github.com/mahdi-byte64/arange-tun/config"
)

// The foreign adapter must translate our section into the engine's foreign
// AppConfig and fill in the same defaults the engine's own loader would, so a
// minimal panel form still yields a working exit node.
func TestBuildForeignConfigDefaults(t *testing.T) {
	hc := &appconfig.HedioumConfig{
		Role:       "foreign",
		AuthToken:  "tok",
		ListenPort: 8443,
		// Mimic, EgressIPMode, DecoyPort, HTTPDecoyPort, DecoyStyle all left empty.
	}
	cfg := buildForeignConfig(hc)

	if cfg.Role != "foreign" {
		t.Fatalf("role = %q, want foreign", cfg.Role)
	}
	if cfg.EgressIPMode != "ipv4" {
		t.Errorf("egress mode = %q, want ipv4 default (no v6 identity leak)", cfg.EgressIPMode)
	}
	if cfg.DecoyPort != 2022 {
		t.Errorf("decoy port = %d, want 2022 default", cfg.DecoyPort)
	}
	if cfg.HTTPDecoyPort != 80 {
		t.Errorf("http decoy port = %d, want 80 default", cfg.HTTPDecoyPort)
	}
	if cfg.DecoyStyle != "apache" {
		t.Errorf("decoy style = %q, want apache default", cfg.DecoyStyle)
	}
	if len(cfg.Mimics) != 1 || cfg.Mimics[0].Type != "ssh" || cfg.Mimics[0].Port != 8443 {
		t.Errorf("mimic = %+v, want one ssh listener on 8443", cfg.Mimics)
	}
}

// A negative HTTPDecoyPort disables the plaintext :80 decoy and must be carried
// through verbatim rather than being replaced by the default.
func TestBuildForeignConfigDisablesHTTPDecoy(t *testing.T) {
	cfg := buildForeignConfig(&appconfig.HedioumConfig{Role: "foreign", ListenPort: 22, HTTPDecoyPort: -1})
	if cfg.HTTPDecoyPort != -1 {
		t.Errorf("http decoy port = %d, want -1 preserved (disabled)", cfg.HTTPDecoyPort)
	}
}

// The iran adapter must build a single foreign node with one endpoint, applying
// the pool-sizing defaults so a bare form still gets a warm, self-scaling pool.
func TestBuildIranConfigDefaults(t *testing.T) {
	hc := &appconfig.HedioumConfig{
		Role:       "iran",
		AuthToken:  "tok",
		Mimic:      "tls",
		ServerAddr: "203.0.113.5",
		ServerPort: 8443,
		SocksPort:  1080,
	}
	cfg := buildIranConfig(hc)

	if cfg.Role != "iran" {
		t.Fatalf("role = %q, want iran", cfg.Role)
	}
	if len(cfg.ForeignNodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(cfg.ForeignNodes))
	}
	n := cfg.ForeignNodes[0]
	if n.TargetIP != "203.0.113.5" || n.TargetPort != 8443 || n.LocalSocksPort != 1080 || n.AuthToken != "tok" {
		t.Errorf("node fields not mapped: %+v", n)
	}
	if n.MinConnections != 10 || n.MaxConnections != 20 || n.BandwidthLimitMbps != 8 || n.BandwidthJitterMbps != 2 {
		t.Errorf("pool defaults not applied: %+v", n)
	}
	if len(n.Endpoints) != 1 || n.Endpoints[0].Mimic != "tls" || n.Endpoints[0].Target != "203.0.113.5:8443" {
		t.Errorf("endpoint = %+v, want one tls endpoint to 203.0.113.5:8443", n.Endpoints)
	}
}

// An empty mimic must default to ssh on both sides so the two ends agree without
// the operator having to pick anything.
func TestMimicDefaultsToSSH(t *testing.T) {
	if got := mimicOrDefault(""); got != "ssh" {
		t.Errorf("empty mimic = %q, want ssh", got)
	}
	if got := mimicOrDefault(" TLS "); got != "tls" {
		t.Errorf("mimic normalisation = %q, want tls", got)
	}
}
