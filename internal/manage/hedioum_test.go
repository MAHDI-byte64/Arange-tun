package manage

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/mahdi-byte64/arange-tun/config"
)

// The rendered [hedioum] TOML must parse back into the config the engine reads,
// with the role and the side-specific fields intact — otherwise a tunnel the
// panel "created" would fail to start.
func TestHedioumForeignRenderRoundTrips(t *testing.T) {
	out := hedioumRenderForeign("h1", 8443, "secret-token", "tls", "dual", "example.com", "me@example.com", "directadmin")

	var cfg config.Config
	if _, err := toml.Decode(out, &cfg); err != nil {
		t.Fatalf("rendered foreign TOML does not parse: %v\n%s", err, out)
	}
	h := cfg.Hedioum
	if h.Role != "foreign" {
		t.Errorf("role = %q, want foreign", h.Role)
	}
	if h.ListenPort != 8443 || h.AuthToken != "secret-token" || h.Mimic != "tls" {
		t.Errorf("core fields not rendered: %+v", h)
	}
	if h.EgressIPMode != "dual" || h.Domain != "example.com" || h.ACMEEmail != "me@example.com" || h.DecoyStyle != "directadmin" {
		t.Errorf("foreign fields not rendered: %+v", h)
	}
}

func TestHedioumIranRenderRoundTrips(t *testing.T) {
	out := hedioumRenderIran("h2", "203.0.113.9", 8443, "secret-token", "ssh", 1081)

	var cfg config.Config
	if _, err := toml.Decode(out, &cfg); err != nil {
		t.Fatalf("rendered iran TOML does not parse: %v\n%s", err, out)
	}
	h := cfg.Hedioum
	if h.Role != "iran" {
		t.Errorf("role = %q, want iran", h.Role)
	}
	if h.ServerAddr != "203.0.113.9" || h.ServerPort != 8443 || h.AuthToken != "secret-token" || h.Mimic != "ssh" || h.SocksPort != 1081 {
		t.Errorf("iran fields not rendered: %+v", h)
	}
}

// validMimic gates the create/edit calls, so an unknown camouflage must be
// rejected while the four supported ones (and the empty default) pass.
func TestValidMimic(t *testing.T) {
	for _, ok := range []string{"", "ssh", "tls", "smtp", "imap", "TLS"} {
		if !validMimic(ok) {
			t.Errorf("mimic %q should be accepted", ok)
		}
	}
	for _, bad := range []string{"http", "wireguard", "nonsense"} {
		if validMimic(bad) {
			t.Errorf("mimic %q should be rejected", bad)
		}
	}
}

// The iran validator is the one gate before a config is written; it must reject
// each missing/out-of-range field with a message, not silently accept it.
func TestValidateHedioumIran(t *testing.T) {
	if err := validateHedioumIran("1.2.3.4", 8443, "tok", "ssh", 1080); err != nil {
		t.Fatalf("a complete iran config should validate: %v", err)
	}
	cases := []struct {
		name         string
		addr         string
		port         int
		token, mimic string
		socks        int
		wantContains string
	}{
		{"no addr", "", 8443, "tok", "ssh", 1080, "address"},
		{"bad port", "1.2.3.4", 0, "tok", "ssh", 1080, "port"},
		{"no token", "1.2.3.4", 8443, "", "ssh", 1080, "token"},
		{"bad mimic", "1.2.3.4", 8443, "tok", "http", 1080, "mimic"},
		{"bad socks", "1.2.3.4", 8443, "tok", "ssh", 0, "SOCKS5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateHedioumIran(c.addr, c.port, c.token, c.mimic, c.socks)
			if err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantContains) {
				t.Errorf("error %q does not mention %q", err, c.wantContains)
			}
		})
	}
}
