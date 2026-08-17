// Package optimize applies kernel/network tuning for high-throughput,
// low-latency tunnels. It is used by the "Optimize" menu item and applied
// automatically behind the Best Performance preset.
package optimize

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// sysctls is the tuning table applied to /etc/sysctl.d and the live kernel.
// Values favour many concurrent connections and high throughput.
var sysctls = [][2]string{
	// Buffer sizes (256MB ceilings, kernel auto-tunes within).
	{"net.core.rmem_max", "268435456"},
	{"net.core.wmem_max", "268435456"},
	{"net.core.rmem_default", "16777216"},
	{"net.core.wmem_default", "16777216"},
	{"net.core.optmem_max", "65536"},
	{"net.ipv4.tcp_rmem", "4096 87380 268435456"},
	{"net.ipv4.tcp_wmem", "4096 65536 268435456"},
	// Connection handling.
	{"net.core.somaxconn", "65536"},
	{"net.core.netdev_max_backlog", "250000"},
	{"net.ipv4.tcp_max_syn_backlog", "20480"},
	{"net.ipv4.ip_local_port_range", "1024 65535"},
	{"net.ipv4.tcp_tw_reuse", "1"},
	{"net.ipv4.tcp_fin_timeout", "15"},
	{"net.ipv4.tcp_max_tw_buckets", "1440000"},
	// Latency / throughput features.
	{"net.ipv4.tcp_window_scaling", "1"},
	{"net.ipv4.tcp_fastopen", "3"},
	{"net.ipv4.tcp_mtu_probing", "1"},
	{"net.ipv4.tcp_slow_start_after_idle", "0"},
	{"net.ipv4.tcp_notsent_lowat", "131072"},
	// Congestion control — BBR + fq for best tunnel performance.
	{"net.core.default_qdisc", "fq"},
	{"net.ipv4.tcp_congestion_control", "bbr"},
	// Forwarding (reverse tunnels frequently forward traffic).
	{"net.ipv4.ip_forward", "1"},
}

// conntrackSysctls tune the kernel connection-tracking table, the usual reason a
// busy tunnel server is fast for hours and then slowly grinds to a crawl until
// the tunnels are restarted.
//
// Every forwarded connection consumes a conntrack slot. The table is small by
// default and — worse — an ESTABLISHED entry is kept for FIVE DAYS
// (nf_conntrack_tcp_timeout_established = 432000), so on a server that churns
// connections the table fills, the kernel starts logging "nf_conntrack: table
// full, dropping packet", and new connections stall. Restarting the tunnels
// closes their connections and frees the slots, which is why a restart "fixes"
// it — for a while.
//
// These settings raise the ceiling and, more importantly, expire dead states
// quickly, so slots are returned to the pool instead of piling up. They live in
// their own file and are applied best-effort because the keys only exist once
// the nf_conntrack module is loaded.
var conntrackSysctls = [][2]string{
	// A large ceiling so a burst of connections cannot fill the table.
	{"net.netfilter.nf_conntrack_max", "1048576"},
	// Established connections expire in a day, not five. The tunnel's own
	// keepalives keep the control channel's entry fresh, so nothing long-lived
	// is cut; what this frees is the mass of finished connections the default
	// would hold for days.
	{"net.netfilter.nf_conntrack_tcp_timeout_established", "86400"},
	// The short-lived teardown/handshake states are what actually pile up under
	// churn — expire them fast.
	{"net.netfilter.nf_conntrack_tcp_timeout_time_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_close_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_fin_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_syn_sent", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_syn_recv", "20"},
	{"net.netfilter.nf_conntrack_generic_timeout", "120"},
	{"net.netfilter.nf_conntrack_udp_timeout", "30"},
	{"net.netfilter.nf_conntrack_udp_timeout_stream", "120"},
	// Do not track connections we never saw open (half-open pickups), so a scan
	// or a flood cannot burn slots on flows that were never ours.
	{"net.netfilter.nf_conntrack_tcp_loose", "0"},
}

const sysctlFile = "/etc/sysctl.d/99-arange-tun.conf"

const conntrackFile = "/etc/sysctl.d/99-arange-tun-conntrack.conf"

const modulesFile = "/etc/modules-load.d/arange-tun.conf"

const limitsFile = "/etc/security/limits.d/99-arange-tun.conf"

const limitsContent = `# Raised by arange-tun for high connection counts
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
* soft nproc  1048576
* hard nproc  1048576
`

// Apply performs the full optimization with progress output. printf is used so
// the caller can pass a logging function (e.g. tui printer).
func Apply(logf func(string)) {
	if runtime.GOOS != "linux" {
		logf("Optimizations are only supported on Linux — skipping.")
		return
	}

	loadBBRModule(logf)

	// Persist sysctl settings.
	var b strings.Builder
	b.WriteString("# Managed by arange-tun — network optimizations\n")
	for _, kv := range sysctls {
		fmt.Fprintf(&b, "%s = %s\n", kv[0], kv[1])
	}
	if err := os.WriteFile(sysctlFile, []byte(b.String()), 0644); err != nil {
		logf("Could not write " + sysctlFile + ": " + err.Error())
	} else {
		logf("Wrote persistent settings to " + sysctlFile)
	}

	// Apply live (best effort per key so one failure doesn't abort the rest).
	applied := 0
	for _, kv := range sysctls {
		if err := exec.Command("sysctl", "-w", kv[0]+"="+kv[1]).Run(); err == nil {
			applied++
		}
	}
	logf(fmt.Sprintf("Applied %d/%d kernel parameters live.", applied, len(sysctls)))

	// Connection-tracking table tuning — the fix for the "fast for hours, then
	// slow until a restart" symptom. Needs the nf_conntrack module loaded, so
	// ensure it (now and at boot) before writing its keys.
	applyConntrack(logf)

	// Persist file limits.
	if err := os.WriteFile(limitsFile, []byte(limitsContent), 0644); err != nil {
		logf("Could not write " + limitsFile + ": " + err.Error())
	} else {
		logf("Raised open-file / process limits in " + limitsFile)
	}

	verifyBBR(logf)
	logf("Optimization complete.")
}

// ApplyQuiet runs Apply discarding output — used by the Best Performance flow.
func ApplyQuiet() {
	Apply(func(string) {})
}

// applyConntrack loads the nf_conntrack module (now and at boot) and applies the
// connection-tracking timeouts and ceiling. Best-effort throughout: a server
// whose kernel has conntrack built without a module, or built out entirely, is
// left as-is rather than failing the whole optimize run.
func applyConntrack(logf func(string)) {
	// Load now, and persist the module so the keys still exist after a reboot
	// (otherwise sysctl -p would warn on the conntrack file at boot).
	moduleOK := exec.Command("modprobe", "nf_conntrack").Run() == nil
	if err := os.WriteFile(modulesFile, []byte("nf_conntrack\n"), 0644); err != nil {
		logf("Note: could not persist the nf_conntrack module load: " + err.Error())
	}

	// The table hash size is a module parameter, not a sysctl; widen it too so a
	// larger table is not bottlenecked by a tiny hash. Best-effort.
	_ = os.WriteFile("/sys/module/nf_conntrack/parameters/hashsize", []byte("262144"), 0644)

	// Persist the conntrack keys in their own file so the core file still applies
	// cleanly on a kernel without conntrack.
	var b strings.Builder
	b.WriteString("# Managed by arange-tun — connection-tracking table tuning\n")
	for _, kv := range conntrackSysctls {
		fmt.Fprintf(&b, "%s = %s\n", kv[0], kv[1])
	}
	if err := os.WriteFile(conntrackFile, []byte(b.String()), 0644); err != nil {
		logf("Could not write " + conntrackFile + ": " + err.Error())
	}

	applied := 0
	for _, kv := range conntrackSysctls {
		if err := exec.Command("sysctl", "-w", kv[0]+"="+kv[1]).Run(); err == nil {
			applied++
		}
	}
	switch {
	case applied > 0:
		logf(fmt.Sprintf("Tuned connection tracking: %d/%d parameters (raises the table ceiling and expires dead entries fast — the usual fix for slowdown after a few hours).", applied, len(conntrackSysctls)))
	case !moduleOK:
		logf("Connection tracking not tuned: the nf_conntrack module is unavailable on this kernel (harmless if this server does not use a stateful firewall).")
	default:
		logf("Connection tracking parameters were not applied (keys absent on this kernel).")
	}
}

// loadBBRModule attempts to load the tcp_bbr kernel module.
func loadBBRModule(logf func(string)) {
	if err := exec.Command("modprobe", "tcp_bbr").Run(); err != nil {
		logf("Note: could not load tcp_bbr module (may be built-in).")
	}
}

// verifyBBR checks whether BBR is the active congestion control algorithm.
func verifyBBR(logf func(string)) {
	out, err := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output()
	if err != nil {
		return
	}
	if strings.TrimSpace(string(out)) == "bbr" {
		logf("BBR congestion control is active.")
	} else {
		logf("BBR not active — kernel may not support it (needs Linux 4.9+).")
	}
}
