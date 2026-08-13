package menu

import (
	"fmt"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/manage"
	"github.com/mahdi-byte64/arange-tun/internal/tui"
)

// directTunnelMenu creates the "direct" tunnels — the ones where the Iran side
// dials OUT rather than exposing ports the way a reverse tunnel does. WireGuard,
// Packet and SSH each have their own engine and config section, so they are
// built here instead of through the reverse Setup Server / Setup Client flow.
func directTunnelMenu() {
	for {
		tui.Clear()
		tui.Title("Direct Tunnel")
		tui.Warn("These dial OUT from the Iran side (VPN-style egress), unlike the reverse")
		tui.Warn("tunnels under Setup Server / Setup Client. Each has its own engine.")
		fmt.Println()
		idx := tui.ChooseOpt("Which tunnel do you want to create?", []tui.Option{
			{Title: "WireGuard", Desc: "VPN egress + local SOCKS5 — server (exit) or client (Iran)"},
			{Title: "Packet", Desc: "raw-packet (pcap) tunnel below the kernel stack — needs root + libpcap"},
			{Title: "SSH", Desc: "SOCKS5 over an SSH login abroad — client only"},
			{Title: "Hedioum", Desc: "pooled SOCKS5 over camouflaged pipes — foreign (exit) or iran (hub)"},
		})
		switch idx {
		case 0:
			wireGuardCreateMenu()
		case 1:
			packetCreateMenu()
		case 2:
			sshCreateMenu()
		case 3:
			hedioumCreateMenu()
		default:
			return
		}
	}
}

// askName reads a tunnel name and reports whether it is non-empty. The engines
// validate the exact character set; this only catches the empty case early so a
// blank prompt does not fall through into the create call.
func askName() (string, bool) {
	name := tui.Prompt("Tunnel name: ")
	if strings.TrimSpace(name) == "" {
		tui.Error("A tunnel name is required.")
		tui.PressEnter()
		return "", false
	}
	return name, true
}

// splitCSV turns a comma-separated line into a trimmed slice, dropping blanks.
// The engines clean and validate each entry; this just breaks the line up.
func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// WireGuard
// ---------------------------------------------------------------------------

func wireGuardCreateMenu() {
	tui.Clear()
	tui.Title("WireGuard tunnel")
	fmt.Println()
	switch tui.ChooseOpt("Which side is this?", []tui.Option{
		{Title: "Server (exit node, abroad)", Desc: "generates the keys and prints a ready client config"},
		{Title: "Client (Iran — dials a WireGuard server)", Desc: "paste a wg-quick config; opens a local SOCKS5"},
	}) {
	case 0:
		wireGuardServerCreate()
	case 1:
		wireGuardClientCreate()
	}
}

func wireGuardServerCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	port := tui.PromptInt("Listen port (UDP)", 51820)
	endpoint := tui.PromptDefault("This server's public IP or domain (the client's endpoint)", resolveServerIP())
	dns := tui.PromptDefault("DNS handed to clients", "1.1.1.1")
	egress := tui.Prompt("Egress interface to NAT out of (optional, e.g. eth0): ")

	clientConf, err := manage.CreateWireGuardServer(name, port, endpoint, dns, egress)
	if err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success("WireGuard exit node created and started.")
	fmt.Println()
	tui.Info("Give the config below to the client — paste it on the other side:")
	fmt.Println()
	fmt.Println(clientConf)
	tui.PressEnter()
}

func wireGuardClientCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	fmt.Println()
	tui.Info("Paste the WireGuard (wg-quick) config for the server you are dialing.")
	tui.Warn("When you are finished, type END on a line of its own and press Enter.")
	fmt.Println()
	conf := tui.PromptMultiline("END")
	if strings.TrimSpace(conf) == "" {
		tui.Error("No config was pasted.")
		tui.PressEnter()
		return
	}
	fmt.Println()
	bind := tui.PromptDefault("SOCKS5 bind address", "127.0.0.1")
	port := tui.PromptInt("SOCKS5 port (apps connect here)", 1080)

	if err := manage.CreateWireGuardClient(name, conf, bind, port); err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success(fmt.Sprintf("WireGuard client created — SOCKS5 proxy on %s:%d.", bind, port))
	tui.PressEnter()
}

// ---------------------------------------------------------------------------
// Packet
// ---------------------------------------------------------------------------

func packetCreateMenu() {
	tui.Clear()
	tui.Title("Packet tunnel")
	tui.Warn("Needs root and libpcap. The SERVER is the abroad exit; the CLIENT is the")
	tui.Warn("Iran entry that exposes ports. Create the server first — it prints a key.")
	fmt.Println()
	switch tui.ChooseOpt("Which side is this?", []tui.Option{
		{Title: "Server (abroad exit node)", Desc: "listens for the client and prints the shared key"},
		{Title: "Client (Iran entry — exposes ports)", Desc: "dials the server using the shared key"},
	}) {
	case 0:
		packetServerCreate()
	case 1:
		packetClientCreate()
	}
}

func packetServerCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	port := tui.PromptInt("Listen port (high, non-standard — not 80/443)", 8090)
	key := tui.Prompt("Shared key (leave empty to generate a strong one): ")

	genKey, err := manage.CreatePacketServer(name, port, key, "")
	if err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success("Packet exit node created and started.")
	fmt.Println()
	tui.Info("Shared key — copy it to the client:")
	tui.Success("  " + genKey)
	tui.PressEnter()
}

func packetClientCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	server := tui.Prompt("Server address (abroad host:port): ")
	key := tui.Prompt("Shared key (from the server): ")
	fmt.Println()
	tui.Info("Ports to expose on THIS machine, comma separated.")
	tui.Warn("e.g. 443,8080  or  443=1.1.1.1:443 to forward elsewhere.")
	ports := splitCSV(tui.Prompt("Ports: "))
	socks := tui.Prompt("Or a SOCKS5 listen address instead (optional, e.g. 127.0.0.1:1080): ")

	if err := manage.CreatePacketClient(name, server, key, "", ports, socks); err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success("Packet entry node created and started.")
	tui.PressEnter()
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

func sshCreateMenu() {
	tui.Clear()
	tui.Title("SSH tunnel")
	tui.Warn("Client only: it dials an SSH server abroad and opens a local SOCKS5")
	tui.Warn("proxy that carries traffic out through that SSH login.")
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	host := tui.Prompt("SSH server IP or domain: ")
	port := tui.PromptInt("SSH port", 22)
	user := tui.PromptDefault("SSH username", "root")
	password := tui.Prompt("SSH password: ")
	fmt.Println()
	bind := tui.PromptDefault("SOCKS5 bind address", "127.0.0.1")
	socksPort := tui.PromptInt("SOCKS5 port (apps connect here)", 1080)

	if err := manage.CreateSSHClient(name, host, port, user, password, bind, socksPort); err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success(fmt.Sprintf("SSH client created — SOCKS5 proxy on %s:%d.", bind, socksPort))
	tui.PressEnter()
}

// ---------------------------------------------------------------------------
// Hedioum
// ---------------------------------------------------------------------------

func hedioumCreateMenu() {
	tui.Clear()
	tui.Title("Hedioum tunnel")
	tui.Warn("Two nodes: the FOREIGN side is the abroad exit; the IRAN side exposes a")
	tui.Warn("local SOCKS5 and dials out. Create the foreign first — it prints a token.")
	fmt.Println()
	switch tui.ChooseOpt("Which side is this?", []tui.Option{
		{Title: "Foreign (abroad exit node)", Desc: "listens for the hub and prints the shared token"},
		{Title: "Iran (entry hub — exposes SOCKS5)", Desc: "dials the foreign node using the shared token"},
	}) {
	case 0:
		hedioumForeignCreate()
	case 1:
		hedioumIranCreate()
	}
}

// askHedioumMimic reads the camouflage protocol, defaulting to ssh.
func askHedioumMimic() string {
	switch tui.ChooseOpt("Camouflage (must match both ends)", []tui.Option{
		{Title: "SSH", Desc: "looks like an SSH server (recommended)"},
		{Title: "TLS", Desc: "looks like HTTPS"},
		{Title: "SMTP", Desc: "looks like a mail server (STARTTLS)"},
		{Title: "IMAP", Desc: "looks like a mail server (STARTTLS)"},
	}) {
	case 1:
		return "tls"
	case 2:
		return "smtp"
	case 3:
		return "imap"
	default:
		return "ssh"
	}
}

func hedioumForeignCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	port := tui.PromptInt("Listen port", 8443)
	mimic := askHedioumMimic()
	token := tui.Prompt("Shared token (leave empty to generate a strong one): ")
	domain := tui.Prompt("Domain for a real Let's Encrypt cert (optional): ")
	acme := ""
	if strings.TrimSpace(domain) != "" {
		acme = tui.Prompt("ACME account email (optional): ")
	}

	genToken, err := manage.CreateHedioumForeign(name, port, token, mimic, "ipv4", domain, acme, "apache")
	if err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success("Hedioum foreign node created and started.")
	fmt.Println()
	tui.Info("Shared token — copy it to the Iran hub:")
	tui.Success("  " + genToken)
	tui.PressEnter()
}

func hedioumIranCreate() {
	fmt.Println()
	name, ok := askName()
	if !ok {
		return
	}
	server := tui.Prompt("Foreign server IP or domain: ")
	serverPort := tui.PromptInt("Foreign listen port", 8443)
	mimic := askHedioumMimic()
	token := tui.Prompt("Shared token (from the foreign node): ")
	socksPort := tui.PromptInt("Local SOCKS5 port (apps connect here)", 1080)

	if err := manage.CreateHedioumIran(name, server, serverPort, token, mimic, socksPort); err != nil {
		tui.Error("Failed: " + err.Error())
		tui.PressEnter()
		return
	}
	tui.Success(fmt.Sprintf("Hedioum iran hub created — SOCKS5 proxy on 127.0.0.1:%d.", socksPort))
	tui.PressEnter()
}
