package packet

import (
	"testing"

	"github.com/mahdi-byte64/arange-tun/config"
)

// explicit network params so the tests never touch auto-detection (no default
// route or gateway ARP in CI). "lo" always exists; the MAC only needs to parse.
func baseNet(pc *config.PacketConfig) {
	pc.Interface = "lo"
	pc.LocalIP = "127.0.0.1"
	pc.RouterMAC = "aa:bb:cc:dd:ee:ff"
}

func TestBuildServerConf(t *testing.T) {
	pc := &config.PacketConfig{Role: "server", ListenPort: 8888, Key: "secret"}
	baseNet(pc)
	cfg, port, err := buildServerConf(pc)
	if err != nil {
		t.Fatalf("buildServerConf: %v", err)
	}
	if port != 8888 {
		t.Fatalf("port = %d, want 8888", port)
	}
	if cfg.Role != "server" {
		t.Fatalf("role = %q, want server", cfg.Role)
	}
	// conf.Prepare must have built the KCP block cipher from the key.
	if cfg.Transport.KCP == nil || cfg.Transport.KCP.Block == nil {
		t.Fatalf("KCP block cipher was not built")
	}
	if cfg.Network.IPv4.Router == nil {
		t.Fatalf("router MAC was not parsed")
	}
}

func TestBuildServerConfRequiresPort(t *testing.T) {
	pc := &config.PacketConfig{Role: "server", Key: "secret"}
	baseNet(pc)
	if _, _, err := buildServerConf(pc); err == nil {
		t.Fatalf("expected an error when listen_port is missing")
	}
}

func TestBuildClientConfForwards(t *testing.T) {
	pc := &config.PacketConfig{
		Role:       "client",
		ServerAddr: "1.2.3.4:8888",
		Key:        "secret",
		Ports:      []string{"8080", "2053"},
	}
	baseNet(pc)
	cfg, serverIP, port, err := buildClientConf(pc)
	if err != nil {
		t.Fatalf("buildClientConf: %v", err)
	}
	if serverIP != "1.2.3.4" || port != 8888 {
		t.Fatalf("server = %s:%d, want 1.2.3.4:8888", serverIP, port)
	}
	if len(cfg.Forward) != 2 {
		t.Fatalf("forwards = %d, want 2", len(cfg.Forward))
	}
	// Each exposed port is relayed 1:1 to 127.0.0.1:<port> on the server side.
	if cfg.Forward[0].Listen.String() != "0.0.0.0:8080" || cfg.Forward[0].Target != "127.0.0.1:8080" {
		t.Fatalf("forward[0] = %s -> %s, want 0.0.0.0:8080 -> 127.0.0.1:8080",
			cfg.Forward[0].Listen, cfg.Forward[0].Target)
	}
}

func TestBuildClientConfNeedsPortsOrSocks(t *testing.T) {
	pc := &config.PacketConfig{Role: "client", ServerAddr: "1.2.3.4:8888", Key: "secret"}
	baseNet(pc)
	if _, _, _, err := buildClientConf(pc); err == nil {
		t.Fatalf("expected an error with no ports and no socks")
	}
}

func TestBuildClientConfSocksOnly(t *testing.T) {
	pc := &config.PacketConfig{Role: "client", ServerAddr: "1.2.3.4:8888", Key: "secret", Socks: "127.0.0.1:1080"}
	baseNet(pc)
	cfg, _, _, err := buildClientConf(pc)
	if err != nil {
		t.Fatalf("buildClientConf: %v", err)
	}
	if len(cfg.SOCKS5) != 1 {
		t.Fatalf("socks5 = %d, want 1", len(cfg.SOCKS5))
	}
}

func TestParseFlags(t *testing.T) {
	if got := parseFlags(""); got != nil {
		t.Fatalf("empty = %v, want nil", got)
	}
	got := parseFlags("PA, A ,")
	if len(got) != 2 || got[0] != "PA" || got[1] != "A" {
		t.Fatalf("parseFlags = %v, want [PA A]", got)
	}
}

func TestResolveServerAddr(t *testing.T) {
	ip, port, err := resolveServerAddr("1.2.3.4:9999")
	if err != nil || ip != "1.2.3.4" || port != 9999 {
		t.Fatalf("resolveServerAddr = %s:%d err=%v", ip, port, err)
	}
	if _, _, err := resolveServerAddr("nohost"); err == nil {
		t.Fatalf("expected an error for a missing port")
	}
}

func TestFirewallRuleShape(t *testing.T) {
	// A server rule must NOTRACK the listen port and drop kernel RSTs on it.
	rules := serverRules(8888)
	if len(rules) == 0 {
		t.Fatalf("no server rules")
	}
	add := rules[0].verb("-A")
	if add[0] != "-t" || add[2] != "-A" {
		t.Fatalf("verb shape wrong: %v", add)
	}
	// Client rules are keyed on the server IP; an empty IP yields none.
	if got := clientRules("", 8888); got != nil {
		t.Fatalf("clientRules with empty IP = %v, want nil", got)
	}
	if got := clientRules("1.2.3.4", 8888); len(got) == 0 {
		t.Fatalf("clientRules should produce rules for a real IP")
	}
}
