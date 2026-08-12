package manage

// Update discovery. What is newer, and how to find out from a machine that may
// not be able to reach GitHub directly. The update itself downloads no binary:
// it rebuilds from source, which lives in updatesource.go.
//
// Every network step here is tried in order:
//
//  1. direct GitHub
//  2. the tunnel SOCKS relay (the peer/kharej side can reach GitHub)
//
// Both terminate TLS at GitHub, which is the whole of the trust model.
// Third-party GitHub proxies used to sit behind those two and were removed: on
// a blocked network — the only time a proxy is reached for — everything the
// update needed travelled the same proxy, so a hostile one could serve modified
// content and whatever was needed to make it look right. A server with neither
// direct access nor a live tunnel installs offline instead; see the README.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/socks"
)

func repoURL() string {
	return fmt.Sprintf("https://github.com/%s/%s", app.RepoOwner, app.RepoName)
}

// InstallPath returns the install directory recorded at install time (used by
// the uninstaller), falling back to the standard location.
func InstallPath() string {
	b, err := os.ReadFile(app.InstallPathFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// relayHTTPClient returns an HTTP client routed through the tunnel SOCKS relay
// when one is configured (the port a server tunnel maps to the peer's built-in
// SOCKS5 proxy), or nil when none exists.
func relayHTTPClient(timeout time.Duration) *http.Client {
	matches, _ := filepath.Glob(app.ConfigDir + "/*.toml")
	for _, path := range matches {
		var cfg config.Config
		if _, err := toml.DecodeFile(path, &cfg); err != nil || cfg.Server.BindAddr == "" {
			continue
		}
		if port := relayExposedPort(cfg.Server.Ports, cfg.Server.Token); port != "" {
			return socks.HTTPClient("127.0.0.1:"+port, "arange-tun", cfg.Server.Token, timeout)
		}
	}
	return nil
}

// relayExposedPort finds the local port that a tunnel maps to the peer's SOCKS
// proxy, or "" when the tunnel carries no such mapping.
//
// Two forms exist: the legacy fixed 1080, and the port derived from the tunnel
// token. Matching only the legacy one — which is what this used to do — meant
// no relay was found for anything written since the port became token-derived,
// leaving the updater with nothing but a direct connection to GitHub. That is
// exactly what a server in Iran does not have.
func relayExposedPort(ports []string, token string) string {
	for _, suffix := range []string{
		fmt.Sprintf("=127.0.0.1:%d", app.SocksInternalPort),
		fmt.Sprintf("=127.0.0.1:%d", app.SocksPortForToken(token)),
	} {
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if !strings.HasSuffix(p, suffix) {
				continue
			}
			port := strings.TrimSuffix(p, suffix)
			// The mapping may carry a bind address ("127.0.0.1:41234=...").
			if i := strings.LastIndex(port, ":"); i >= 0 {
				port = port[i+1:]
			}
			return port
		}
	}
	return ""
}

// source is one way to reach GitHub: a name to log and the client to use.
type source struct {
	name   string
	client *http.Client
}

// sources returns the ordered download paths: direct, then the tunnel relay.
func sources(timeout time.Duration) []source {
	out := []source{{name: "direct", client: &http.Client{Timeout: timeout}}}
	if relay := relayHTTPClient(timeout); relay != nil {
		out = append(out, source{name: "tunnel relay", client: relay})
	}
	return out
}

// tagNameRe pulls "tag_name":"v1.3.0" out of the GitHub API JSON.
var tagNameRe = regexp.MustCompile(`"tag_name"\s*:\s*"([^"]+)"`)

// versionValidRe sanity-checks a version string read from the raw VERSION file.
var versionValidRe = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}$`)

// latestTag discovers the newest published version. It tries two methods across
// both sources (direct, then the tunnel relay) so it works from Iran too:
//
//  1. the GitHub API releases/latest endpoint (JSON tag_name) — the accurate
//     "latest release", used when the server or its tunnel peer can reach
//     api.github.com directly (own IP, not rate limited).
//  2. the raw VERSION file on main, which is bumped with each release. This is
//     the fallback for a peer whose IP is rate limited by the API, where the
//     JSON request comes back 403 but raw.githubusercontent.com still answers.
func latestTag() (string, error) {
	var lastErr error = fmt.Errorf("no source reachable")
	beta := Channel() == ChannelBeta

	// On the beta channel the full release list is needed: /releases/latest
	// deliberately skips pre-releases, which are the whole point of the channel.
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", app.RepoOwner, app.RepoName)
	if beta {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=20", app.RepoOwner, app.RepoName)
	}
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/main/VERSION", app.RepoOwner, app.RepoName)

	// 1) GitHub API JSON — accurate, works direct and via the tunnel relay.
	for _, s := range sources(20 * time.Second) {
		resp, err := s.client.Get(apiURL)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if tag := pickTag(string(body), beta); tag != "" {
				return tag, nil
			}
		}
		lastErr = fmt.Errorf("api via %s: status %d", s.name, resp.StatusCode)
	}

	// 2) raw VERSION file — works when the API rate-limits the source's IP.
	for _, s := range sources(20 * time.Second) {
		resp, err := s.client.Get(rawURL)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			// The VERSION file tracks the stable line, so it is only a valid
			// answer on the stable channel.
			if v := strings.TrimSpace(string(body)); versionValidRe.MatchString(v) && !beta {
				return v, nil
			}
		}
		lastErr = fmt.Errorf("VERSION via %s: status %d", s.name, resp.StatusCode)
	}
	return "", fmt.Errorf("could not reach GitHub (direct or through the tunnel relay): %v", lastErr)
}

// normVersion strips a leading "v" so v1.3.0 and 1.3.0 compare equal.
func normVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// parseVer turns "v1.3.0" into [1 3 0]; missing or non-numeric parts become 0.
func parseVer(v string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(normVersion(v), ".", 3) {
		j := 0
		for j < len(part) && part[j] >= '0' && part[j] <= '9' {
			j++
		}
		out[i], _ = strconv.Atoi(part[:j])
	}
	return out
}

// newerVersion reports whether remote is a strictly newer semantic version
// than local — so a dev build ahead of the latest release never "updates"
// backwards, and any published newer release is detected automatically.
func newerVersion(remote, local string) bool {
	r, l := parseVer(remote), parseVer(local)
	for i := 0; i < 3; i++ {
		if r[i] != l[i] {
			return r[i] > l[i]
		}
	}
	return false
}

// CheckUpdate reports whether there is anything newer to build. Because there
// are no releases, "newer" means new commits on main rather than a higher
// version tag: the VERSION string rarely changes, but every push does, so a
// version-only check kept saying "up to date" while the source moved on. The
// installed commit is compared to the newest on main; if the commit API cannot
// be reached, it falls back to the VERSION comparison so the check still works.
func CheckUpdate() (bool, string, error) {
	remote, err := latestCommitSHA()
	if err != nil {
		tag, terr := latestTag()
		if terr != nil {
			return false, "", err
		}
		if newerVersion(tag, app.Version) {
			return true, fmt.Sprintf("Version %s is available (current %s).", tag, app.Version), nil
		}
		return false, fmt.Sprintf("Already up to date (%s).", app.Version), nil
	}
	local := installedCommitSHA()
	if local == "" {
		return true, "A source update is available — rebuild to get the latest code on main.", nil
	}
	if !strings.EqualFold(local, remote) {
		return true, fmt.Sprintf("New commits are available on main (installed %s).", shortSHA(local)), nil
	}
	return false, "Already up to date (latest source on main).", nil
}

// pickTag chooses a version from a GitHub releases response.
//
// On stable it takes the first tag and rejects it if it is a pre-release. On
// beta it walks every tag in the list — GitHub returns them newest first — and
// takes the highest version, so a pre-release newer than the last stable one
// wins while an older one does not.
func pickTag(body string, beta bool) string {
	matches := tagNameRe.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}
	if !beta {
		tag := strings.TrimSpace(matches[0][1])
		if isPrerelease(tag) {
			return "" // /releases/latest should never return one, but do not install it if it does
		}
		return tag
	}

	best := ""
	for _, m := range matches {
		tag := strings.TrimSpace(m[1])
		if tag == "" {
			continue
		}
		if best == "" || newerVersion(tag, best) {
			best = tag
		}
	}
	return best
}

// ApplyUpdate rebuilds arange-tun from the current source on main and installs
// it safely: a full snapshot is taken first, the freshly built binary is put in
// place, every service is restarted and health-checked, and if anything fails
// to come back up the snapshot is rolled back automatically — so a broken build
// can never leave the server without working tunnels. There are no release
// binaries; the update always compiles from source (see buildFromSource).
func ApplyUpdate(logf func(string)) error {
	if logf == nil {
		logf = func(string) {}
	}
	// There are no release binaries to download — the update rebuilds from the
	// current source on the repo's main branch. Naming the target version is
	// best-effort, for the log only, so a failure to read it is not fatal.
	target := "the latest source"
	if tag, err := latestTag(); err == nil {
		target = tag
	}

	// Snapshot BEFORE touching anything, so we can always get back.
	logf("Taking a safety snapshot...")
	snap, err := TakeSnapshot("pre-update")
	if err != nil {
		// A snapshot we cannot take is a good reason not to proceed blindly.
		return fmt.Errorf("could not take a safety snapshot: %w", err)
	}
	logf("Snapshot saved: " + filepath.Base(snap.Dir))

	logf("Building " + target + " from source...")
	if err := buildFromSource(logf); err != nil {
		return err
	}

	// Keep the standard layout recorded for the uninstaller.
	_ = os.MkdirAll(app.BackupDir, 0755)
	if InstallPath() == "" {
		_ = os.MkdirAll(app.ConfigDir, 0755)
		_ = os.WriteFile(app.InstallPathFile, []byte(app.InstallDir+"\n"), 0644)
	}

	logf("Restarting services...")
	RestartService(app.WebUIService)
	// Installs from before the monitor service acquire it here, so upgrading
	// does not leave a machine with no watchdog and no alerts. This restarts
	// unconditionally: the unit text is identical across versions, so an
	// install-if-missing check would decide there was nothing to do and leave
	// the old binary running.
	if err := RestartMonitorService(); err != nil {
		logf("Warning: monitor service could not start: " + err.Error())
	}
	ok, failed := RestartAll()
	logf(fmt.Sprintf("Restarted %d tunnels (%d failed).", ok, failed))

	// Health check: every tunnel that has a unit must come back active.
	logf("Checking health...")
	if bad := unhealthyAfterUpdate(); len(bad) > 0 {
		logf("Health check FAILED for: " + strings.Join(bad, ", "))
		logf("Rolling back to the previous version...")
		if rerr := RestoreSnapshot(snap, logf); rerr != nil {
			return fmt.Errorf("update failed AND rollback failed: %v (rollback: %v) — "+
				"restore manually from %s", strings.Join(bad, ", "), rerr, snap.Dir)
		}
		return fmt.Errorf("update to %s failed health check (%s) — rolled back to %s",
			target, strings.Join(bad, ", "), snap.Meta.Version)
	}

	logf("Health check passed.")
	logf("Update complete — now running " + target + ".")
	return nil
}

// unhealthyAfterUpdate returns the names of services that did not come back up
// after an update. It waits briefly, since systemd restarts are not instant.
func unhealthyAfterUpdate() []string {
	var bad []string
	if fileExists(app.ServiceDir+"/"+app.WebUIService) &&
		!WaitServiceActive(app.WebUIService, 20*time.Second) {
		bad = append(bad, "web panel")
	}
	// The monitor counts: if the new version cannot run the watchdog and the
	// alerts, the update has broken something even though every tunnel is still
	// carrying traffic — and without this it would be judged healthy and kept.
	if fileExists(app.ServiceDir+"/"+app.MonitorService) &&
		!WaitServiceActive(app.MonitorService, 20*time.Second) {
		bad = append(bad, "monitor")
	}
	for _, t := range List() {
		// Only judge tunnels that are supposed to be running.
		if !fileExists(app.ServiceDir + "/" + t.Service) {
			continue
		}
		if !WaitServiceActive(t.Service, 20*time.Second) {
			bad = append(bad, t.Name)
		}
	}
	return bad
}

// RollbackUpdate restores a snapshot on demand (menu: Update → Rollback).
func RollbackUpdate(s Snapshot, logf func(string)) error {
	return RestoreSnapshot(s, logf)
}
