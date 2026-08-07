package manage

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// External tunnels: frp (fatedier/frp) and backhaul (Musixal/Backhaul). Unlike
// the built-in engine ("Amin Tunnel"), these are third-party binaries the panel
// installs from their GitHub releases and drives through generated config files
// and systemd units. Everything for one external tunnel lives under
// /etc/arange-tun/ext; the shared binaries live under /root/Arange-tun/bin.

var (
	extDir    = app.ConfigDir + "/ext"
	extBinDir = app.InstallDir + "/bin"
)

func extServiceName(name string) string { return app.ServicePrefix + "ext-" + name + ".service" }
func extMetaPath(name string) string    { return extDir + "/" + name + ".json" }
func extConfPath(name string) string    { return extDir + "/" + name + ".toml" }
func extUnitPath(name string) string    { return app.ServiceDir + "/" + extServiceName(name) }

// FRPProxy is one port mapping on an frp client: a local service exposed on a
// remote port of the frp server.
type FRPProxy struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // tcp | udp
	LocalIP    string `json:"localIP"`
	LocalPort  string `json:"localPort"`
	RemotePort string `json:"remotePort"`
}

// ExtTunnel describes an frp or backhaul tunnel. The fields used depend on the
// kind and role; the JSON is stored verbatim so the panel can edit it later.
type ExtTunnel struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`      // "frp" | "backhaul"
	Role      string `json:"role"`      // "server" (Iran) | "client" (kharej)
	Transport string `json:"transport"` // frp: tcp/kcp/quic — backhaul: tcp/tcpmux/ws/wss/wsmux/wssmux/udp
	Token     string `json:"token"`

	// Server (Iran).
	BindPort  string   `json:"bindPort,omitempty"`
	IPv6      bool     `json:"ipv6,omitempty"`
	Ports     []string `json:"ports,omitempty"` // backhaul server: forwarded ports
	AcceptUDP bool     `json:"acceptUDP,omitempty"`

	// Client (kharej).
	ServerHost string     `json:"serverHost,omitempty"`
	ServerPort string     `json:"serverPort,omitempty"`
	EdgeIP     string     `json:"edgeIP,omitempty"`  // backhaul websocket transports
	Proxies    []FRPProxy `json:"proxies,omitempty"` // frp client mappings

	// Filled in for a wss/wssmux backhaul server (a self-signed pair is
	// generated automatically). Not sent by the form.
	TLSCert string `json:"tlsCert,omitempty"`
	TLSKey  string `json:"tlsKey,omitempty"`

	// Runtime status, filled by ListExtTunnels (not persisted meaningfully).
	Service string `json:"service,omitempty"`
	State   string `json:"state,omitempty"`
}

// CreateExtTunnel validates the request, installs the binary if it is not
// already present, writes the native config and a systemd unit, and starts it.
func CreateExtTunnel(t ExtTunnel) error {
	name := strings.TrimSpace(t.Name)
	if fileExists(extMetaPath(name)) || fileExists(app.ConfigPath(name)) {
		return fmt.Errorf("a tunnel named %q already exists", name)
	}
	return writeAndStartExt(t)
}

// UpdateExtTunnel rewrites an existing external tunnel and restarts it.
func UpdateExtTunnel(t ExtTunnel) error {
	name := strings.TrimSpace(t.Name)
	if !fileExists(extMetaPath(name)) {
		return fmt.Errorf("no external tunnel named %q to edit", name)
	}
	return writeAndStartExt(t)
}

// writeAndStartExt is the shared body of create and update: validate, generate
// the config, ensure the binary, write everything, and (re)start the service.
func writeAndStartExt(t ExtTunnel) error {
	if err := validateExt(&t); err != nil {
		return err
	}
	conf, binName, err := extConfig(t)
	if err != nil {
		return err
	}
	binPath, err := ensureExtBinary(t.Kind, binName)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(extDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(extConfPath(t.Name), []byte(conf), 0644); err != nil {
		return err
	}
	if err := saveExtMeta(t); err != nil {
		return err
	}
	if err := writeExtUnit(t.Name, binPath); err != nil {
		return err
	}
	if err := DaemonReload(); err != nil {
		return err
	}
	service := extServiceName(t.Name)
	if err := RestartService(service); err != nil {
		// A fresh unit is enabled+started by StartService; fall back to that when
		// restart fails because the unit was not running yet.
		return StartService(service)
	}
	return StartService(service)
}

// saveExtMeta persists the tunnel description as JSON, dropping the transient
// status fields.
func saveExtMeta(t ExtTunnel) error {
	t.Service, t.State = "", ""
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(extMetaPath(t.Name), b, 0644)
}

// GetExtTunnel reads one external tunnel's stored description.
func GetExtTunnel(name string) (ExtTunnel, error) {
	var t ExtTunnel
	b, err := os.ReadFile(extMetaPath(name))
	if err != nil {
		return t, err
	}
	err = json.Unmarshal(b, &t)
	return t, err
}

// ListExtTunnels returns every external tunnel with its live service state.
func ListExtTunnels() []ExtTunnel {
	var out []ExtTunnel
	matches, _ := filepath.Glob(extDir + "/*.json")
	for _, path := range matches {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var t ExtTunnel
		if json.Unmarshal(b, &t) != nil || t.Name == "" {
			continue
		}
		t.Token = "" // never hand the token back to the browser in a list
		t.Service = extServiceName(t.Name)
		t.State = "stopped"
		if IsActive(t.Service) {
			t.State = "running"
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DeleteExtTunnel stops and removes an external tunnel entirely.
func DeleteExtTunnel(name string) error {
	service := extServiceName(name)
	if IsActive(service) || IsEnabled(service) {
		_ = DisableService(service)
	}
	os.Remove(extUnitPath(name))
	os.Remove(extConfPath(name))
	os.Remove(extMetaPath(name))
	return DaemonReload()
}

// RestartExtTunnel restarts an external tunnel's service.
func RestartExtTunnel(name string) error {
	return RestartService(extServiceName(name))
}

// ExtExists reports whether an external tunnel with this name is configured.
func ExtExists(name string) bool { return fileExists(extMetaPath(name)) }

// writeExtUnit writes the systemd unit that runs the external binary against
// its generated config. frp and backhaul both take "-c <config>".
func writeExtUnit(name, binPath string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Arange-tun external tunnel (%s)
After=network.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, name, binPath, extConfPath(name))
	return os.WriteFile(extUnitPath(name), []byte(unit), 0644)
}

// ---- binary install ----------------------------------------------------------

// ensureExtBinary returns the path to an external binary, downloading and
// extracting the release if it is not already present.
func ensureExtBinary(kind, binName string) (string, error) {
	dst := filepath.Join(extBinDir, binName)
	if fileExists(dst) {
		return dst, nil
	}
	if err := installExtBinaries(kind); err != nil {
		return "", err
	}
	if !fileExists(dst) {
		return "", fmt.Errorf("%s was not found in the downloaded release", binName)
	}
	return dst, nil
}

// installExtBinaries downloads a kind's release tarball and extracts the
// binaries it ships into the shared bin directory. Trust rests on TLS to
// github.com, the same as the source-build installer.
func installExtBinaries(kind string) error {
	if err := os.MkdirAll(extBinDir, 0755); err != nil {
		return err
	}
	arch := runtime.GOARCH
	var url string
	var wanted map[string]bool
	switch kind {
	case "frp":
		tag, err := latestReleaseTag("fatedier", "frp")
		if err != nil {
			return fmt.Errorf("could not find the latest frp release: %w", err)
		}
		ver := strings.TrimPrefix(tag, "v")
		url = fmt.Sprintf("https://github.com/fatedier/frp/releases/download/%s/frp_%s_linux_%s.tar.gz", tag, ver, arch)
		wanted = map[string]bool{"frps": true, "frpc": true}
	case "backhaul":
		// latest/download resolves to the newest release's asset, and backhaul's
		// asset name carries no version, so no tag lookup is needed.
		url = fmt.Sprintf("https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_%s.tar.gz", arch)
		wanted = map[string]bool{"backhaul": true}
	default:
		return fmt.Errorf("unknown tunnel kind %q", kind)
	}

	tmp := filepath.Join(extBinDir, kind+"-download.tar.gz")
	defer os.Remove(tmp)
	if err := downloadExt(url, tmp); err != nil {
		return fmt.Errorf("could not download %s: %w", kind, err)
	}
	return extractBinaries(tmp, wanted, extBinDir)
}

// downloadExt fetches url to dest, trying the direct path and then the tunnel
// relay so it works from Iran.
func downloadExt(url, dest string) error {
	var lastErr error = fmt.Errorf("no source reachable")
	for _, s := range sources(3 * time.Minute) {
		resp, err := s.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s returned status %d", s.name, resp.StatusCode)
			continue
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		f.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// extractBinaries pulls the wanted executables out of a .tar.gz by basename,
// ignoring whatever directory the archive wraps them in, and writes them
// executable into destDir.
func extractBinaries(archive string, wanted map[string]bool, destDir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	found := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if !wanted[base] {
			continue
		}
		out, err := os.OpenFile(filepath.Join(destDir, base), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // release asset over TLS, names checked
			out.Close()
			return err
		}
		out.Close()
		found++
	}
	if found == 0 {
		return fmt.Errorf("none of the expected binaries were in the archive")
	}
	return nil
}

// ---- validation & config -----------------------------------------------------

// validExtTransport reports whether a transport is valid for the given kind.
func validExtTransport(kind, tr string) bool {
	switch kind {
	case "frp":
		switch tr {
		case "", "tcp", "kcp", "quic":
			return true
		}
	case "backhaul":
		switch tr {
		case "tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp":
			return true
		}
	}
	return false
}

// validateExt checks a request and fills in derived fields (a self-signed
// certificate for a wss backhaul server).
func validateExt(t *ExtTunnel) error {
	t.Name = strings.TrimSpace(t.Name)
	if !validName(t.Name) {
		return fmt.Errorf("invalid tunnel name %q — use letters, digits, dots, dashes (max 40)", t.Name)
	}
	if t.Kind != "frp" && t.Kind != "backhaul" {
		return fmt.Errorf("unknown tunnel kind %q", t.Kind)
	}
	if t.Role != "server" && t.Role != "client" {
		return fmt.Errorf("role must be \"server\" or \"client\", got %q", t.Role)
	}
	if strings.TrimSpace(t.Token) == "" {
		return fmt.Errorf("a token is required (and must match on both ends)")
	}
	if t.Kind == "backhaul" && !validExtTransport("backhaul", t.Transport) {
		return fmt.Errorf("unknown backhaul transport %q", t.Transport)
	}
	if t.Kind == "frp" && !validExtTransport("frp", t.Transport) {
		return fmt.Errorf("unknown frp transport %q — use tcp, kcp or quic", t.Transport)
	}

	switch t.Role {
	case "server":
		if !validPort(t.BindPort) {
			return fmt.Errorf("invalid tunnel port %q", t.BindPort)
		}
		if t.Kind == "backhaul" {
			t.Ports = normalizePorts(t.Ports)
			if len(t.Ports) == 0 {
				return fmt.Errorf("at least one forwarded port is required")
			}
			if err := validatePortSpecs(t.Ports); err != nil {
				return err
			}
			if needsTLS(t.Transport) {
				cert, key, err := EnsureSelfSignedCert(t.Name, "")
				if err != nil {
					return fmt.Errorf("certificate generation failed: %v", err)
				}
				t.TLSCert, t.TLSKey = cert, key
			}
		}
	case "client":
		host := strings.Trim(strings.TrimSpace(t.ServerHost), "[]")
		if host == "" {
			return fmt.Errorf("server address is required")
		}
		t.ServerHost = host
		if !validPort(t.ServerPort) {
			return fmt.Errorf("invalid server port %q", t.ServerPort)
		}
		if t.Kind == "frp" {
			if len(t.Proxies) == 0 {
				return fmt.Errorf("add at least one port mapping")
			}
			for i := range t.Proxies {
				p := &t.Proxies[i]
				p.Name = strings.TrimSpace(p.Name)
				if p.Name == "" {
					p.Name = fmt.Sprintf("%s-%d", t.Name, i+1)
				}
				if p.Type != "tcp" && p.Type != "udp" {
					p.Type = "tcp"
				}
				if p.LocalIP == "" {
					p.LocalIP = "127.0.0.1"
				}
				if !validPort(p.LocalPort) || !validPort(p.RemotePort) {
					return fmt.Errorf("mapping %q has an invalid port", p.Name)
				}
			}
		}
	}
	return nil
}

// extConfig generates the native config text and the binary name to run.
func extConfig(t ExtTunnel) (conf, binName string, err error) {
	switch t.Kind {
	case "frp":
		return frpConfig(t)
	case "backhaul":
		return backhaulConfig(t)
	}
	return "", "", fmt.Errorf("unknown tunnel kind %q", t.Kind)
}

// frpConfig renders an frps.toml (server) or frpc.toml (client).
func frpConfig(t ExtTunnel) (string, string, error) {
	var b strings.Builder
	if t.Role == "server" {
		fmt.Fprintf(&b, "bindPort = %s\n", t.BindPort)
		b.WriteString("auth.method = \"token\"\n")
		fmt.Fprintf(&b, "auth.token = %q\n", t.Token)
		switch t.Transport {
		case "kcp":
			fmt.Fprintf(&b, "kcpBindPort = %s\n", t.BindPort)
		case "quic":
			fmt.Fprintf(&b, "quicBindPort = %s\n", t.BindPort)
		}
		return b.String(), "frps", nil
	}
	fmt.Fprintf(&b, "serverAddr = %q\n", t.ServerHost)
	fmt.Fprintf(&b, "serverPort = %s\n", t.ServerPort)
	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %q\n", t.Token)
	if t.Transport != "" && t.Transport != "tcp" {
		fmt.Fprintf(&b, "transport.protocol = %q\n", t.Transport)
	}
	for _, p := range t.Proxies {
		b.WriteString("\n[[proxies]]\n")
		fmt.Fprintf(&b, "name = %q\n", p.Name)
		fmt.Fprintf(&b, "type = %q\n", p.Type)
		fmt.Fprintf(&b, "localIP = %q\n", p.LocalIP)
		fmt.Fprintf(&b, "localPort = %s\n", p.LocalPort)
		fmt.Fprintf(&b, "remotePort = %s\n", p.RemotePort)
	}
	return b.String(), "frpc", nil
}

// backhaulConfig renders a [server] or [client] backhaul config.
func backhaulConfig(t ExtTunnel) (string, string, error) {
	var b strings.Builder
	if t.Role == "server" {
		host := "0.0.0.0"
		if t.IPv6 {
			host = "::"
		}
		b.WriteString("[server]\n")
		fmt.Fprintf(&b, "bind_addr = %q\n", net.JoinHostPort(host, t.BindPort))
		fmt.Fprintf(&b, "transport = %q\n", t.Transport)
		fmt.Fprintf(&b, "token = %q\n", t.Token)
		if t.AcceptUDP && t.Transport == "tcp" {
			b.WriteString("accept_udp = true\n")
		}
		if needsTLS(t.Transport) {
			fmt.Fprintf(&b, "tls_cert = %q\n", t.TLSCert)
			fmt.Fprintf(&b, "tls_key = %q\n", t.TLSKey)
		}
		b.WriteString("ports = [\n")
		for _, p := range t.Ports {
			fmt.Fprintf(&b, "  %q,\n", p)
		}
		b.WriteString("]\n")
		return b.String(), "backhaul", nil
	}
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "remote_addr = %q\n", net.JoinHostPort(t.ServerHost, t.ServerPort))
	fmt.Fprintf(&b, "transport = %q\n", t.Transport)
	fmt.Fprintf(&b, "token = %q\n", t.Token)
	if t.EdgeIP != "" && isWS(t.Transport) {
		fmt.Fprintf(&b, "edge_ip = %q\n", t.EdgeIP)
	}
	return b.String(), "backhaul", nil
}

// latestReleaseTag returns the newest release tag of any GitHub repo, used to
// build the frp asset URL (its filename carries the version).
func latestReleaseTag(owner, repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	var lastErr error = fmt.Errorf("no source reachable")
	for _, s := range sources(20 * time.Second) {
		resp, err := s.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("%s returned status %d", s.name, resp.StatusCode)
			continue
		}
		if m := tagNameRe.FindStringSubmatch(string(body)); m != nil {
			return strings.TrimSpace(m[1]), nil
		}
		lastErr = fmt.Errorf("no tag in the response from %s", s.name)
	}
	return "", lastErr
}
