package manage

// Hedioum tunnels are created like Packet ones: a separate (vendored) engine
// with its own [hedioum] section rather than the reverse-proxy TunnelSpec path.
// The topology is inverted — the FOREIGN role is the abroad exit node and the
// IRAN role is the entry hub that exposes a local SOCKS5 and dials out — so the
// foreign is created first (it hands back a shared token) and the iran hub is
// pointed at it.

import (
	"fmt"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// hedioumMimics is the set of camouflage protocols both ends may agree on.
var hedioumMimics = map[string]bool{
	"ssh": true, "tls": true, "smtp": true, "imap": true,
}

// validMimic reports whether m is a supported mimic (empty means the "ssh"
// default and is allowed).
func validMimic(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	return m == "" || hedioumMimics[m]
}

// CreateHedioumForeign starts an abroad exit node with a camouflage listener on
// listenPort and returns the shared token the iran hub must use (generated when
// token is empty).
func CreateHedioumForeign(name string, listenPort int, token, mimic, egressIPMode, domain, acmeEmail, decoyStyle string) (string, error) {
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
	if !validMimic(mimic) {
		return "", fmt.Errorf("unknown mimic %q — use ssh, tls, smtp or imap", mimic)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		t, err := randomKey()
		if err != nil {
			return "", err
		}
		token = t
	}
	toml := hedioumRenderForeign(name, listenPort, token, mimic, egressIPMode, domain, acmeEmail, decoyStyle)
	if _, err := saveGeneratedTunnel(name, toml); err != nil {
		return "", err
	}
	return token, nil
}

// CreateHedioumIran starts an Iran-side entry hub that exposes a local SOCKS5 on
// socksPort and dials the abroad foreign node with the shared token.
func CreateHedioumIran(name, serverAddr string, serverPort int, token, mimic string, socksPort int) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return fmt.Errorf("invalid tunnel name %q — use letters, digits, dots, dashes (max 40)", name)
	}
	if _, ok := Find(name); ok {
		return fmt.Errorf("a tunnel named %q already exists", name)
	}
	if err := validateHedioumIran(serverAddr, serverPort, token, mimic, socksPort); err != nil {
		return err
	}
	toml := hedioumRenderIran(name, serverAddr, serverPort, strings.TrimSpace(token), mimic, socksPort)
	_, err := saveGeneratedTunnel(name, toml)
	return err
}

func validateHedioumIran(serverAddr string, serverPort int, token, mimic string, socksPort int) error {
	if strings.TrimSpace(serverAddr) == "" {
		return fmt.Errorf("the foreign server address (abroad host) is required")
	}
	if serverPort < 1 || serverPort > 65535 {
		return fmt.Errorf("invalid foreign server port %d", serverPort)
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("the shared token is required — copy it from the foreign node")
	}
	if !validMimic(mimic) {
		return fmt.Errorf("unknown mimic %q — use ssh, tls, smtp or imap", mimic)
	}
	if socksPort < 1 || socksPort > 65535 {
		return fmt.Errorf("invalid SOCKS5 port %d", socksPort)
	}
	return nil
}

// HedioumEdit is a hedioum tunnel's config in the shape the create/edit form uses.
type HedioumEdit struct {
	Role         string `json:"role"`
	Mimic        string `json:"mimic"`
	AuthToken    string `json:"authToken"`
	ListenPort   int    `json:"listenPort"`
	EgressIPMode string `json:"egressIPMode"`
	Domain       string `json:"domain"`
	ACMEEmail    string `json:"acmeEmail"`
	DecoyStyle   string `json:"decoyStyle"`
	ServerAddr   string `json:"serverAddr"`
	ServerPort   int    `json:"serverPort"`
	SocksPort    int    `json:"socksPort"`
}

// HedioumForEdit loads a hedioum tunnel's config so the panel can prefill its form.
func HedioumForEdit(name string) (HedioumEdit, error) {
	cfg, err := LoadTunnelConfig(name)
	if err != nil {
		return HedioumEdit{}, err
	}
	h := cfg.Hedioum
	if h.Role == "" {
		return HedioumEdit{}, fmt.Errorf("%q is not a hedioum tunnel", name)
	}
	return HedioumEdit{
		Role:         h.Role,
		Mimic:        h.Mimic,
		AuthToken:    h.AuthToken,
		ListenPort:   h.ListenPort,
		EgressIPMode: h.EgressIPMode,
		Domain:       h.Domain,
		ACMEEmail:    h.ACMEEmail,
		DecoyStyle:   h.DecoyStyle,
		ServerAddr:   h.ServerAddr,
		ServerPort:   h.ServerPort,
		SocksPort:    h.SocksPort,
	}, nil
}

// UpdateHedioumForeign overwrites an existing foreign node and restarts it. An
// empty token keeps the current one, so an edit that does not touch the token
// does not silently rotate it.
func UpdateHedioumForeign(name string, listenPort int, token, mimic, egressIPMode, domain, acmeEmail, decoyStyle string) (string, error) {
	name = strings.TrimSpace(name)
	if !fileExists(app.ConfigPath(name)) {
		return "", fmt.Errorf("no tunnel named %q to edit", name)
	}
	if listenPort < 1 || listenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", listenPort)
	}
	if !validMimic(mimic) {
		return "", fmt.Errorf("unknown mimic %q — use ssh, tls, smtp or imap", mimic)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if cfg, err := LoadTunnelConfig(name); err == nil {
			token = cfg.Hedioum.AuthToken
		}
		if token == "" {
			return "", fmt.Errorf("the shared token is required")
		}
	}
	toml := hedioumRenderForeign(name, listenPort, token, mimic, egressIPMode, domain, acmeEmail, decoyStyle)
	if _, err := saveGeneratedTunnel(name, toml); err != nil {
		return "", err
	}
	return token, nil
}

// UpdateHedioumIran overwrites an existing iran hub and restarts it.
func UpdateHedioumIran(name, serverAddr string, serverPort int, token, mimic string, socksPort int) error {
	name = strings.TrimSpace(name)
	if !fileExists(app.ConfigPath(name)) {
		return fmt.Errorf("no tunnel named %q to edit", name)
	}
	if err := validateHedioumIran(serverAddr, serverPort, token, mimic, socksPort); err != nil {
		return err
	}
	toml := hedioumRenderIran(name, serverAddr, serverPort, strings.TrimSpace(token), mimic, socksPort)
	_, err := saveGeneratedTunnel(name, toml)
	return err
}

func hedioumRenderForeign(name string, listenPort int, token, mimic, egressIPMode, domain, acmeEmail, decoyStyle string) string {
	var b strings.Builder
	b.WriteString("# Generated by arange-tun — do not edit while the service is running.\n")
	fmt.Fprintf(&b, "# name = %q\n\n", name)
	b.WriteString("[hedioum]\n")
	b.WriteString("role = \"foreign\"\n")
	fmt.Fprintf(&b, "listen_port = %d\n", listenPort)
	fmt.Fprintf(&b, "auth_token = %q\n", token)
	if m := strings.TrimSpace(mimic); m != "" {
		fmt.Fprintf(&b, "mimic = %q\n", strings.ToLower(m))
	}
	if v := strings.TrimSpace(egressIPMode); v != "" {
		fmt.Fprintf(&b, "egress_ip_mode = %q\n", strings.ToLower(v))
	}
	if v := strings.TrimSpace(domain); v != "" {
		fmt.Fprintf(&b, "domain = %q\n", v)
	}
	if v := strings.TrimSpace(acmeEmail); v != "" {
		fmt.Fprintf(&b, "acme_email = %q\n", v)
	}
	if v := strings.TrimSpace(decoyStyle); v != "" {
		fmt.Fprintf(&b, "decoy_style = %q\n", strings.ToLower(v))
	}
	return b.String()
}

func hedioumRenderIran(name, serverAddr string, serverPort int, token, mimic string, socksPort int) string {
	var b strings.Builder
	b.WriteString("# Generated by arange-tun — do not edit while the service is running.\n")
	fmt.Fprintf(&b, "# name = %q\n\n", name)
	b.WriteString("[hedioum]\n")
	b.WriteString("role = \"iran\"\n")
	fmt.Fprintf(&b, "server_addr = %q\n", strings.TrimSpace(serverAddr))
	fmt.Fprintf(&b, "server_port = %d\n", serverPort)
	fmt.Fprintf(&b, "auth_token = %q\n", token)
	if m := strings.TrimSpace(mimic); m != "" {
		fmt.Fprintf(&b, "mimic = %q\n", strings.ToLower(m))
	}
	fmt.Fprintf(&b, "socks_port = %d\n", socksPort)
	return b.String()
}
