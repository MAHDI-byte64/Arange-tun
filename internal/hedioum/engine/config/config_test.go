package config

import "testing"

func TestLegacyIranConfigSynthesizesEndpoint(t *testing.T) {
	const j = `{"role":"iran","foreign_nodes":[{"alias":"a","target_ip":"1.2.3.4","target_port":22,"local_socks_port":40001,"auth_token":"x"}]}`
	cfg, err := parseConfig([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	eps := cfg.ForeignNodes[0].Endpoints
	if len(eps) != 1 || eps[0].Mimic != "ssh" || eps[0].Target != "1.2.3.4:22" {
		t.Fatalf("synthesized endpoints = %+v", eps)
	}
}

func TestLegacyForeignConfigSynthesizesMimic(t *testing.T) {
	const j = `{"role":"foreign","foreign_listen_port":8443,"decoy_port":2022,"auth_token":"x"}`
	cfg, err := parseConfig([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mimics) != 1 {
		t.Fatalf("mimics = %+v", cfg.Mimics)
	}
	m := cfg.Mimics[0]
	if m.Type != "ssh" || m.Port != 8443 || m.Decoy != "127.0.0.1:2022" {
		t.Fatalf("synthesized mimic = %+v", m)
	}
}

func TestExplicitEndpointsPreserved(t *testing.T) {
	const j = `{"role":"iran","foreign_nodes":[{"alias":"a","local_socks_port":40001,"auth_token":"x",
	  "endpoints":[{"target":"1.2.3.4:22","mimic":"ssh"},{"target":"1.2.3.4:443","mimic":"tls"}]}]}`
	cfg, err := parseConfig([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	eps := cfg.ForeignNodes[0].Endpoints
	if len(eps) != 2 || eps[1].Mimic != "tls" || eps[1].Target != "1.2.3.4:443" {
		t.Fatalf("endpoints = %+v", eps)
	}
}

func TestForeignDefaults(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"role":"foreign","auth_token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EgressIPMode != "ipv4" || cfg.DecoyPort != 2022 {
		t.Fatalf("defaults: mode=%q decoy=%d", cfg.EgressIPMode, cfg.DecoyPort)
	}
	if cfg.DecoyStyle != "apache" {
		t.Fatalf("decoy_style default = %q, want apache", cfg.DecoyStyle)
	}
	if cfg.Domain != "" {
		t.Fatalf("domain should default empty, got %q", cfg.Domain)
	}
}

// TestForeignDomainConfig: an explicit domain/style/email round-trips through parse.
func TestForeignDomainConfig(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"role":"foreign","auth_token":"x","domain":"vpn.example.com","acme_email":"a@b.c","decoy_style":"directadmin"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "vpn.example.com" || cfg.ACMEEmail != "a@b.c" || cfg.DecoyStyle != "directadmin" {
		t.Fatalf("domain config not parsed: %+v", cfg)
	}
}

func TestUpdateForeignNode(t *testing.T) {
	cfg := &AppConfig{Role: "iran"}
	// Append when absent.
	cfg.UpdateForeignNode(ForeignNode{Alias: "a", LocalSocksPort: 40001})
	cfg.UpdateForeignNode(ForeignNode{Alias: "b", LocalSocksPort: 40002})
	if len(cfg.ForeignNodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(cfg.ForeignNodes))
	}
	// Update in place (same alias) must not append.
	cfg.UpdateForeignNode(ForeignNode{Alias: "a", LocalSocksPort: 49999})
	if len(cfg.ForeignNodes) != 2 {
		t.Fatalf("update should not append; got %d nodes", len(cfg.ForeignNodes))
	}
	for _, n := range cfg.ForeignNodes {
		if n.Alias == "a" && n.LocalSocksPort != 49999 {
			t.Fatalf("node a not updated: port=%d", n.LocalSocksPort)
		}
	}
}

func TestRemoveForeignNode(t *testing.T) {
	cfg := &AppConfig{ForeignNodes: []ForeignNode{{Alias: "a"}, {Alias: "b"}, {Alias: "c"}}}
	if !cfg.RemoveForeignNode("b") || len(cfg.ForeignNodes) != 2 {
		t.Fatalf("remove b failed: %+v", cfg.ForeignNodes)
	}
	if cfg.ForeignNodes[0].Alias != "a" || cfg.ForeignNodes[1].Alias != "c" {
		t.Fatalf("wrong remaining order: %+v", cfg.ForeignNodes)
	}
	if cfg.RemoveForeignNode("missing") {
		t.Fatal("removing a missing alias should return false")
	}
}

func TestHTTPDecoyDefaults(t *testing.T) {
	// Foreign with no field -> defaulted to 80.
	cfg, _ := parseConfig([]byte(`{"role":"foreign","auth_token":"x"}`))
	if cfg.HTTPDecoyPort != 80 {
		t.Fatalf("default http_decoy_port = %d, want 80", cfg.HTTPDecoyPort)
	}
	// A negative sentinel (disabled) must be preserved, not re-defaulted.
	cfg, _ = parseConfig([]byte(`{"role":"foreign","auth_token":"x","http_decoy_port":-1}`))
	if cfg.HTTPDecoyPort != -1 {
		t.Fatalf("disabled http_decoy_port = %d, want -1", cfg.HTTPDecoyPort)
	}
}
