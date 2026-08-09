package packet

import (
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// requireRoot stops early with a clear message when the engine cannot possibly
// work: raw-packet capture and injection need root (CAP_NET_RAW/CAP_NET_ADMIN).
func requireRoot(logger *logrus.Logger) {
	if os.Geteuid() != 0 {
		logger.Fatalf("packet: raw-packet capture requires root privileges")
	}
}

// The kernel has no socket for the crafted TCP packets the Packet engine
// exchanges, so it would answer them with RST and confuse conntrack/NAT. These
// iptables rules bypass connection tracking (NOTRACK) for the tunnel port and
// drop the kernel's stray RSTs (in both directions), which is what keeps the
// raw-packet session alive. They mirror the rules the upstream project
// documents. We add them on start and remove them on a clean shutdown.

type fwRule struct {
	table string
	chain string
	args  []string
}

func (r fwRule) verb(v string) []string {
	return append([]string{"-t", r.table, v, r.chain}, r.args...)
}

// serverRules protect the server's listen port.
func serverRules(port int) []fwRule {
	p := portOnly(port)
	return []fwRule{
		{"raw", "PREROUTING", []string{"-p", "tcp", "--dport", p, "-j", "NOTRACK"}},
		{"raw", "OUTPUT", []string{"-p", "tcp", "--sport", p, "-j", "NOTRACK"}},
		{"mangle", "OUTPUT", []string{"-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
		{"mangle", "PREROUTING", []string{"-p", "tcp", "--dport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
	}
}

// clientRules protect the client's traffic to a specific server ip:port. The
// client uses ephemeral source ports, so the rules match the fixed server side.
func clientRules(serverIP string, port int) []fwRule {
	p := portOnly(port)
	if serverIP == "" {
		return nil
	}
	return []fwRule{
		{"raw", "PREROUTING", []string{"-p", "tcp", "-s", serverIP, "--sport", p, "-j", "NOTRACK"}},
		{"raw", "OUTPUT", []string{"-p", "tcp", "-d", serverIP, "--dport", p, "-j", "NOTRACK"}},
		{"mangle", "OUTPUT", []string{"-p", "tcp", "-d", serverIP, "--dport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
		{"mangle", "PREROUTING", []string{"-p", "tcp", "-s", serverIP, "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
	}
}

// applyFirewall installs the rules, first clearing any identical leftovers from
// a previous run so restarts don't stack duplicates.
func applyFirewall(rules []fwRule, logger *logrus.Logger) {
	for _, r := range rules {
		deleteRuleRepeatedly(r)
		if err := iptables(r.verb("-A")...); err != nil {
			logger.Warnf("packet: could not add firewall rule (%s %s): %v", r.table, r.chain, err)
		}
	}
}

// removeFirewall deletes the rules on shutdown.
func removeFirewall(rules []fwRule, logger *logrus.Logger) {
	for _, r := range rules {
		deleteRuleRepeatedly(r)
	}
}

func deleteRuleRepeatedly(r fwRule) {
	// Delete up to a few times in case duplicates accumulated.
	for i := 0; i < 4; i++ {
		if err := iptables(r.verb("-D")...); err != nil {
			return
		}
	}
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		// A -D on a rule that isn't present is expected during cleanup/dedup.
		return &iptablesError{args: args, out: msg, err: err}
	}
	return nil
}

type iptablesError struct {
	args []string
	out  string
	err  error
}

func (e *iptablesError) Error() string {
	return "iptables " + strings.Join(e.args, " ") + ": " + e.err.Error() + " (" + e.out + ")"
}
