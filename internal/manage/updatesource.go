package manage

// Source-based self-update. Arange-tun publishes no release binaries, so an
// update rebuilds the binary from the current source on the repo's main branch:
// the source tarball is downloaded (direct, or through the tunnel SOCKS relay so
// it works from Iran too), compiled with the local Go toolchain, and swapped in
// atomically. Trust rests on TLS to github.com — the same model the installer
// uses when it builds from source.

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// installedCommitFile records the git commit the running binary was built from,
// so an update can tell "there are new commits on main" apart from "nothing
// changed" — the version string in VERSION rarely moves, but every push does.
var installedCommitFile = app.ConfigDir + "/installed_commit"

// commitSHARe pulls the first 40-hex "sha" out of the GitHub commits API JSON —
// which is the commit's own SHA, since it is the first field of the object.
var commitSHARe = regexp.MustCompile(`"sha"\s*:\s*"([0-9a-f]{7,40})"`)

// latestCommitSHA returns the SHA of the newest commit on the default branch,
// trying the direct path and then the tunnel relay so it works from Iran.
func latestCommitSHA() (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/main", app.RepoOwner, app.RepoName)
	var lastErr error = fmt.Errorf("no source reachable")
	for _, s := range sources(20 * time.Second) {
		resp, err := s.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("%s returned status %d", s.name, resp.StatusCode)
			continue
		}
		if m := commitSHARe.FindStringSubmatch(string(body)); m != nil {
			return m[1], nil
		}
		lastErr = fmt.Errorf("no commit sha in the response from %s", s.name)
	}
	return "", lastErr
}

// installedCommitSHA reads the recorded build commit, or "" when none is stored
// (an install from before this was tracked).
func installedCommitSHA() string {
	b, err := os.ReadFile(installedCommitFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeInstalledCommit records the commit a fresh build came from.
func writeInstalledCommit(sha string) {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return
	}
	_ = os.MkdirAll(app.ConfigDir, 0755)
	_ = os.WriteFile(installedCommitFile, []byte(sha+"\n"), 0644)
}

// shortSHA trims a commit to its first 7 characters for display.
func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// buildFromSource downloads main's source, compiles it, and atomically replaces
// the installed binary. It restarts nothing — ApplyUpdate owns the snapshot,
// restart and health-check around this.
func buildFromSource(logf func(string)) error {
	if logf == nil {
		logf = func(string) {}
	}
	gobin, err := goBinary()
	if err != nil {
		return err
	}

	srcDir := filepath.Join(app.InstallDir, "src")
	if err := os.RemoveAll(srcDir); err != nil {
		return err
	}
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return err
	}

	tgz := filepath.Join(app.InstallDir, "source-update.tar.gz")
	defer os.Remove(tgz)
	logf("Downloading source from GitHub...")
	if err := downloadSource(tgz, logf); err != nil {
		return fmt.Errorf("could not download the source: %w", err)
	}
	logf("Extracting source...")
	if err := extractTarGz(tgz, srcDir); err != nil {
		return fmt.Errorf("could not unpack the source: %w", err)
	}

	// The Packet tunnel's pcap engine is built with cgo, so the machine needs a C
	// compiler and the libpcap headers. Install them if they are missing, the same
	// way the installer does, so a panel update is self-sufficient.
	ensurePcapBuildDeps(logf)

	tmpBin := app.BinPath + ".new"
	_ = os.Remove(tmpBin)
	logf("Compiling (go build) — this can take a minute...")
	cmd := exec.Command(gobin, "build", "-trimpath", "-ldflags", "-s -w", "-o", tmpBin, ".")
	cmd.Dir = srcDir
	// Direct module fetching first, Iran-friendly mirrors as a fallback — the
	// same order the installer uses.
	//
	// The panel runs the build from the systemd service, whose environment has
	// no HOME. Without it Go cannot derive GOPATH ($HOME/go) or its module and
	// build caches and fails before it compiles a line — "module cache not
	// found: neither GOMODCACHE nor GOPATH is set". So the caches are pinned to
	// explicit writable paths under the install dir, which makes the build work
	// the same whether it is launched from a login shell or a bare service.
	goCache := filepath.Join(app.InstallDir, "go")
	gopath := filepath.Join(goCache, "path")
	_ = os.MkdirAll(gopath, 0755)
	_ = os.MkdirAll(filepath.Join(goCache, "mod"), 0755)
	_ = os.MkdirAll(filepath.Join(goCache, "build"), 0755)
	cmd.Env = append(os.Environ(),
		// cgo is on: the Packet tunnel's pcap engine links against libpcap, which
		// the installer put on the machine. The rest of the tree is pure Go.
		"CGO_ENABLED=1",
		// Iran-reachable mirrors first, and pipe-separated ("|") on purpose: with
		// commas Go only advances to the next proxy on a 404/410, so a 403 — which
		// is exactly what proxy.golang.org returns from a sanctioned region — is a
		// hard stop that never reaches the mirrors. "|" makes it fall through on
		// ANY error, so a blocked proxy is skipped instead of failing the build.
		"GOPROXY=https://goproxy.cn|https://mirror-go.runflare.com|https://proxy.golang.org|direct",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"HOME="+app.InstallDir,
		"GOPATH="+gopath,
		"GOMODCACHE="+filepath.Join(goCache, "mod"),
		"GOCACHE="+filepath.Join(goCache, "build"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpBin)
		return fmt.Errorf("build failed: %w\n%s", err, tailBytes(out, 1500))
	}
	if err := os.Chmod(tmpBin, 0755); err != nil {
		os.Remove(tmpBin)
		return err
	}
	if err := os.Rename(tmpBin, app.BinPath); err != nil {
		os.Remove(tmpBin)
		return fmt.Errorf("could not replace the binary: %w", err)
	}
	logf("New binary installed.")
	// Record the commit just built, so the next check can tell it apart from a
	// later push. Best-effort: a missing record only means the next check offers
	// a rebuild it did not strictly need.
	if sha, err := latestCommitSHA(); err == nil {
		writeInstalledCommit(sha)
	}
	return nil
}

// ensurePcapBuildDeps installs a C compiler and the libpcap development headers
// when they are missing, so the cgo build of the Packet engine succeeds. It is
// best-effort: the panel runs as root, but on an unknown distro or with no
// network it just logs and lets the build surface the real error.
func ensurePcapBuildDeps(logf func(string)) {
	haveCC := false
	for _, cc := range []string{"cc", "gcc", "clang"} {
		if _, err := exec.LookPath(cc); err == nil {
			haveCC = true
			break
		}
	}
	if haveCC && pcapHeaderPresent() {
		return
	}
	logf("Installing build prerequisites (gcc, libpcap headers)...")
	type pm struct {
		bin  string
		args [][]string
	}
	candidates := []pm{
		{"apt-get", [][]string{{"update", "-y"}, {"install", "-y", "gcc", "libpcap-dev"}}},
		{"dnf", [][]string{{"install", "-y", "gcc", "libpcap-devel"}}},
		{"yum", [][]string{{"install", "-y", "gcc", "libpcap-devel"}}},
		{"apk", [][]string{{"add", "--no-cache", "gcc", "musl-dev", "libpcap-dev"}}},
		{"pacman", [][]string{{"-Sy", "--noconfirm", "gcc", "libpcap"}}},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err != nil {
			continue
		}
		for _, a := range c.args {
			cmd := exec.Command(c.bin, a...)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			_ = cmd.Run()
		}
		break
	}
	if !pcapHeaderPresent() {
		logf("Warning: libpcap headers still missing — the Packet engine may fail to build. Install libpcap-dev/libpcap-devel manually.")
	}
}

// pcapHeaderPresent reports whether the libpcap development header is installed.
func pcapHeaderPresent() bool {
	return fileExists("/usr/include/pcap/pcap.h") || fileExists("/usr/include/pcap.h")
}

// goBinary finds a usable Go toolchain: one on PATH, or the standard
// /usr/local/go install the installer drops in.
func goBinary() (string, error) {
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	if p := "/usr/local/go/bin/go"; fileExists(p) {
		return p, nil
	}
	return "", fmt.Errorf("Go toolchain not found — cannot rebuild from source; re-run the installer, which installs Go")
}

// downloadSource fetches the main-branch source tarball into dest, trying the
// direct path and then the tunnel relay.
func downloadSource(dest string, logf func(string)) error {
	url := fmt.Sprintf("%s/archive/refs/heads/main.tar.gz", repoURL())
	var lastErr error = fmt.Errorf("no source reachable")
	for _, s := range sources(3 * time.Minute) {
		logf("Trying " + s.name + "...")
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

// extractTarGz unpacks a .tar.gz into destDir, stripping the single leading
// directory a GitHub archive wraps everything in (REPO-main/...). It writes only
// regular files and directories and refuses any entry whose path would escape
// destDir.
func extractTarGz(archive, destDir string) error {
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

	root := filepath.Clean(destDir) + string(os.PathSeparator)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Strip the leading "REPO-main/" component the archive adds.
		rel := hdr.Name
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			rel = rel[i+1:]
		} else {
			continue // the top-level directory entry itself
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(destDir, rel)
		if !strings.HasPrefix(target, root) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // our own source, path checked above
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

// tailBytes returns the last n bytes of b as a string, for surfacing the end of
// a long build log — where the actual compiler error is.
func tailBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
