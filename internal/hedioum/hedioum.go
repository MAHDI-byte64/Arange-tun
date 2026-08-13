// Package hedioum is the Arange-tun adapter around the vendored Hedioum Pool
// Tunnel engine (in ./engine — vendored with the author's permission, see
// engine/NOTICE.md). Hedioum is a two-node, connection-pool proxy: it carries
// SOCKS5 traffic over many multiplexed, camouflaged pipes (SSH/TLS/SMTP/IMAP
// mimicry, ChaCha20-Poly1305 AEAD, dynamic pool scaling) between an abroad exit
// node and an Iran-side entry hub.
//
// The topology is the same inverted shape as Packet: the "foreign" role is the
// abroad exit node (it dials the open internet) and the "iran" role is the entry
// that exposes a local SOCKS5 which X-UI/Xray point their outbound at. This
// adapter builds the engine's config from our TOML [hedioum] section, wires the
// engine's logging into ours, and — for the iran hub — publishes a truthful
// "connected" signal into the tunnel's metrics snapshot so the panel does not
// show a dead pool as green.
package hedioum

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	appconfig "github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/config"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/egress"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/ingress"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"
)

// RunForeign runs the abroad exit node until ctx ends.
func RunForeign(ctx context.Context, hc *appconfig.HedioumConfig, logger *logrus.Logger) {
	configureSlog(hc.LogLevel)
	cfg := buildForeignConfig(hc)
	logger.Infof("hedioum foreign (abroad exit) starting — mimic %q on :%d", mimicOrDefault(hc.Mimic), hc.ListenPort)
	egress.StartForeignDaemon(ctx, cfg)
	logger.Println("shutting down hedioum foreign...")
}

// RunIran runs the Iran-side entry hub until ctx ends.
func RunIran(ctx context.Context, hc *appconfig.HedioumConfig, logger *logrus.Logger) {
	configureSlog(hc.LogLevel)
	cfg := buildIranConfig(hc)
	logger.Infof("hedioum iran (entry hub) starting — SOCKS5 on 127.0.0.1:%d → %s:%d (mimic %q)",
		hc.SocksPort, hc.ServerAddr, hc.ServerPort, mimicOrDefault(hc.Mimic))

	// The pool keeps MinConnections warm, so a positive live count means the
	// foreign node is reachable and the tunnel is up. Publish that into the
	// metrics snapshot the panel reads, and clear it when the pool empties, so a
	// hub whose foreign has gone away is shown offline instead of green forever.
	peer := net.JoinHostPort(hc.ServerAddr, strconv.Itoa(hc.ServerPort))
	onLive := func(total int) {
		if total > 0 {
			metrics.ReportPeer(peer)
		} else {
			metrics.ClearPeer()
		}
	}

	ingress.StartIranHub(ctx, cfg, onLive)
	metrics.ClearPeer()
	logger.Println("shutting down hedioum iran...")
}

// buildForeignConfig translates our [hedioum] section into the engine's foreign
// AppConfig, applying the same defaults the engine's own config loader would.
func buildForeignConfig(hc *appconfig.HedioumConfig) *config.AppConfig {
	cfg := &config.AppConfig{
		Role:              "foreign",
		AuthToken:         hc.AuthToken,
		ForeignListenPort: hc.ListenPort,
		EgressIPMode:      firstNonEmpty(hc.EgressIPMode, "ipv4"),
		EgressBindIP:      hc.EgressBindIP,
		DecoyPort:         firstPositive(hc.DecoyPort, 2022),
		DecoyStyle:        firstNonEmpty(hc.DecoyStyle, "apache"),
		Domain:            hc.Domain,
		ACMEEmail:         hc.ACMEEmail,
	}

	// HTTPDecoyPort: 0 means "use the default 80"; a negative value disables it.
	if hc.HTTPDecoyPort == 0 {
		cfg.HTTPDecoyPort = 80
	} else {
		cfg.HTTPDecoyPort = hc.HTTPDecoyPort
	}

	// One camouflage listener on the public port. The engine synthesizes an SSH
	// listener from the legacy fields when Mimics is empty, but we set it
	// explicitly so a non-SSH mimic is honoured.
	cfg.Mimics = []config.MimicListener{{
		Type:       mimicOrDefault(hc.Mimic),
		Port:       hc.ListenPort,
		ServerName: hc.ServerName,
	}}
	return cfg
}

// buildIranConfig translates our [hedioum] section into the engine's iran
// AppConfig: a single foreign node reached over one endpoint.
func buildIranConfig(hc *appconfig.HedioumConfig) *config.AppConfig {
	target := net.JoinHostPort(hc.ServerAddr, strconv.Itoa(hc.ServerPort))
	node := config.ForeignNode{
		Alias:               "primary",
		TargetIP:            hc.ServerAddr,
		TargetPort:          hc.ServerPort,
		LocalSocksPort:      hc.SocksPort,
		AuthToken:           hc.AuthToken,
		MinConnections:      firstPositive(hc.MinConnections, 10),
		MaxConnections:      firstPositive(hc.MaxConnections, 20),
		BandwidthLimitMbps:  firstPositive(hc.BandwidthLimitMbps, 8),
		BandwidthJitterMbps: firstPositive(hc.BandwidthJitterMbps, 2),
		Endpoints: []config.Endpoint{{
			Target:     target,
			Mimic:      mimicOrDefault(hc.Mimic),
			ServerName: hc.ServerName,
		}},
	}
	return &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{node}}
}

// mimicOrDefault returns the configured mimic, defaulting to "ssh".
func mimicOrDefault(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if m == "" {
		return "ssh"
	}
	return m
}

// configureSlog points the engine's structured logger at stderr (which systemd
// captures for the per-tunnel unit) at the level our config asks for.
func configureSlog(level string) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "none", "off", "silent":
		lvl = slog.LevelError + 8 // above every emitted level: effectively silent
	default: // "", "info"
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func firstNonEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func firstPositive(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
