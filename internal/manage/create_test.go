package manage

import "testing"

// buildSpec is the validation-and-mapping core of CreateTunnel; these tests
// exercise it directly so they never touch systemd or the disk (Save does
// that, and it needs root). They assert the request maps to the same spec the
// interactive flows would build.

func TestBuildSpecServerTCP(t *testing.T) {
	s, err := buildSpec(TunnelRequest{
		Name:      "srv1",
		Role:      "server",
		Transport: "tcp",
		Port:      "443",
		Ports:     []string{"443", "8080=127.0.0.1:2096"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.BindAddr != "0.0.0.0:443" {
		t.Errorf("BindAddr = %q, want 0.0.0.0:443", s.BindAddr)
	}
	if len(s.Ports) != 2 {
		t.Errorf("Ports = %v, want 2 entries", s.Ports)
	}
	if len(s.Token) != 64 {
		t.Errorf("expected a 64-char generated token, got %d chars", len(s.Token))
	}
	if s.Preset != PresetTurbo {
		t.Errorf("Preset = %q, want turbo (the default)", s.Preset)
	}
}

func TestBuildSpecServerIPv6BindAndPreset(t *testing.T) {
	s, err := buildSpec(TunnelRequest{
		Name: "srv6", Role: "server", Transport: "tcp",
		Port: "9000", IPv6: true, Ports: []string{"9000"},
		Preset: "balance", Token: "keepthis",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.BindAddr != "[::]:9000" {
		t.Errorf("BindAddr = %q, want [::]:9000", s.BindAddr)
	}
	if s.Token != "keepthis" {
		t.Errorf("Token = %q, want the supplied token", s.Token)
	}
	if s.Preset != PresetBalance {
		t.Errorf("Preset = %q, want balance", s.Preset)
	}
}

func TestBuildSpecClientFallbackAndRemote(t *testing.T) {
	s, err := buildSpec(TunnelRequest{
		Name: "cli1", Role: "client", Transport: "tcp",
		ServerHost: "203.0.113.5", ServerPort: "443", Token: "shared",
		FallbackAddrs: []string{"203.0.113.6", "203.0.113.7:8443"},
		LoadBalance:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.RemoteAddr != "203.0.113.5:443" {
		t.Errorf("RemoteAddr = %q", s.RemoteAddr)
	}
	// A bare fallback IP reuses the main port; one with a port keeps it.
	want := []string{"203.0.113.6:443", "203.0.113.7:8443"}
	for i, w := range want {
		if i >= len(s.FallbackAddrs) || s.FallbackAddrs[i] != w {
			t.Errorf("FallbackAddrs = %v, want %v", s.FallbackAddrs, want)
			break
		}
	}
	if !s.LoadBalance {
		t.Error("LoadBalance should be enabled when fallbacks are present")
	}
}

func TestBuildSpecProxyProtocolOnlyWhereSupported(t *testing.T) {
	// ws does not support the PROXY protocol header; the flag must be dropped.
	s, err := buildSpec(TunnelRequest{
		Name: "wsx", Role: "server", Transport: "ws",
		Port: "80", Ports: []string{"80"}, ProxyProtocol: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.ProxyProtocol {
		t.Error("ProxyProtocol must be false for a transport that cannot carry it")
	}
}

func TestBuildSpecAdvancedOverridesPreset(t *testing.T) {
	yes := true
	s, err := buildSpec(TunnelRequest{
		Name: "adv", Role: "server", Transport: "tcp",
		Port: "443", Ports: []string{"443"}, Preset: "turbo",
		Advanced: &AdvancedTuning{
			MaxConnections: 500,
			BandwidthMbps:  200,
			Nodelay:        &yes,
			ZeroCopy:       &yes,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.MaxConnections != 500 || s.BandwidthMbps != 200 {
		t.Errorf("limits not applied: max=%d bw=%d", s.MaxConnections, s.BandwidthMbps)
	}
	if !s.ZeroCopy {
		t.Error("ZeroCopy override not applied on the tcp transport")
	}
	// Any manual tuning marks the tunnel custom so a later preset change cannot
	// silently overwrite it.
	if s.Preset != "" {
		t.Errorf("Preset = %q, want empty (custom) after advanced overrides", s.Preset)
	}
}

func TestBuildSpecValidationErrors(t *testing.T) {
	cases := map[string]TunnelRequest{
		"bad name":          {Name: "bad name", Role: "server", Transport: "tcp", Port: "1", Ports: []string{"1"}},
		"unknown role":      {Name: "x", Role: "middle", Transport: "tcp"},
		"unknown transport": {Name: "x", Role: "server", Transport: "carrierpigeon", Port: "1", Ports: []string{"1"}},
		"server no ports":   {Name: "x", Role: "server", Transport: "tcp", Port: "443"},
		"server bad port":   {Name: "x", Role: "server", Transport: "tcp", Port: "0", Ports: []string{"443"}},
		"client no token":   {Name: "x", Role: "client", Transport: "tcp", ServerHost: "1.2.3.4", ServerPort: "443"},
		"client no host":    {Name: "x", Role: "client", Transport: "tcp", ServerPort: "443", Token: "t"},
		"bad port spec":     {Name: "x", Role: "server", Transport: "tcp", Port: "443", Ports: []string{"nope"}},
	}
	for name, req := range cases {
		if _, err := buildSpec(req); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
