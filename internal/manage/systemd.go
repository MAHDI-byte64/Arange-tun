package manage

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

// systemctl runs a systemctl subcommand and returns combined output.
func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// systemctlOut runs a systemctl subcommand and returns its standard output
// only. It exists for the calls whose output is read positionally: a warning on
// stderr would be interleaved by CombinedOutput and shift every line after it,
// which for a batched query means answering about the wrong unit.
func systemctlOut(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).Output()
	return strings.TrimSpace(string(out)), err
}

// DaemonReload reloads the systemd manager configuration.
func DaemonReload() error {
	_, err := systemctl("daemon-reload")
	return err
}

// IsActive reports whether a unit is currently running.
func IsActive(service string) bool {
	out, _ := systemctl("is-active", service)
	return out == "active"
}

// ActiveStates answers IsActive for many units at once, keyed by unit name.
//
// systemd takes a list and prints one verdict per unit in order, so asking
// about every tunnel costs the same single process as asking about one. Asking
// separately did not: the panel refreshes its stats every four seconds and its
// tunnel list every six, each walking every tunnel, so a machine with a handful
// of them was spawning a systemctl several times a second forever just to keep
// a light green.
//
// The verdicts are matched to units by position, so this only trusts the reply
// when it has exactly one line per unit. Anything else — an unexpected warning,
// a systemd that answered differently — falls back to asking one at a time,
// because a misaligned batch would confidently report the wrong unit's state,
// which is far worse than the process it saves.
func ActiveStates(services []string) map[string]bool {
	if len(services) == 0 {
		return map[string]bool{}
	}
	// is-active exits non-zero unless every unit is active, so the error is
	// expected here and carries no information — the verdicts are on stdout.
	out, _ := systemctlOut(append([]string{"is-active"}, services...)...)
	if states, ok := matchActiveStates(services, out); ok {
		return states
	}
	states := make(map[string]bool, len(services))
	for _, s := range services {
		states[s] = IsActive(s)
	}
	return states
}

// matchActiveStates pairs each unit with its verdict by position, reporting
// whether the reply lined up at all. Split out from ActiveStates so the pairing
// — the part that would silently mislabel units if it were wrong — can be
// tested without a running systemd.
func matchActiveStates(services []string, out string) (map[string]bool, bool) {
	lines := strings.Split(out, "\n")
	if len(lines) != len(services) {
		return nil, false
	}
	states := make(map[string]bool, len(services))
	for i, s := range services {
		states[s] = strings.TrimSpace(lines[i]) == "active"
	}
	return states, true
}

// IsEnabled reports whether a unit is enabled at boot.
func IsEnabled(service string) bool {
	out, _ := systemctl("is-enabled", service)
	return out == "enabled"
}

// StartService starts and enables a unit.
func StartService(service string) error {
	_, err := systemctl("enable", "--now", service)
	return err
}

// StopService stops a unit (leaves it enabled).
func StopService(service string) error {
	_, err := systemctl("stop", service)
	return err
}

// RestartService restarts a unit.
func RestartService(service string) error {
	_, err := systemctl("restart", service)
	return err
}

// DisableService stops and disables a unit.
func DisableService(service string) error {
	_, err := systemctl("disable", "--now", service)
	return err
}

// writeUnit writes a systemd unit file for a tunnel that runs the arange-tun
// binary in engine mode against its config.
func writeUnit(name string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Arange-tun Tunnel (%s)
After=network.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, name, app.BinPath, app.ConfigPath(name))

	path := app.ServiceDir + "/" + app.ServiceName(name)
	return os.WriteFile(path, []byte(unit), 0644)
}

// removeUnit deletes a tunnel unit file if present.
func removeUnit(name string) {
	os.Remove(app.ServiceDir + "/" + app.ServiceName(name))
}

// FollowLog streams live journal logs for a service until the user presses
// Ctrl+C. The child runs in its own process group so the interrupt only
// stops the log viewer, not the arange-tun menu.
func FollowLog(service string) error {
	cmd := exec.Command("journalctl", "-u", service, "-n", "200", "-f", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			_ = cmd.Process.Kill()
		case <-done:
		}
	}()

	err := cmd.Wait()
	close(done)
	signal.Stop(sig)
	return err
}
