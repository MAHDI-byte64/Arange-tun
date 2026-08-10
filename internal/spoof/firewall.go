package spoof

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// The kernel has no socket for the spoofed packets we receive, so it would answer
// them — an ICMP port-unreachable for UDP, an RST for TCP, an echo reply for
// ICMP — which leaks the real IP and can confuse stateful middleboxes. These
// rules silence the kernel for our receive port / carrier. They are best-effort
// and removed on a clean shutdown.

type fwRule struct {
	table string
	chain string
	args  []string
}

func (r fwRule) verb(v string) []string {
	return append([]string{"-t", r.table, v, r.chain}, r.args...)
}

// recvRules silence the kernel for inbound spoofed packets on our receive port.
func recvRules(transport string, recvPort int) []fwRule {
	p := strconv.Itoa(recvPort)
	rules := []fwRule{
		// Don't let conntrack track the spoofed flow.
		{"raw", "PREROUTING", []string{"-p", carrierProto(transport), "--dport", p, "-j", "NOTRACK"}},
	}
	switch transport {
	case carrierTCP:
		// Drop the RST the kernel would send back to the forged source.
		rules = append(rules, fwRule{"filter", "OUTPUT", []string{"-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", p, "-j", "DROP"}})
	case carrierICMP:
		// Handled by icmp_echo_ignore_all (see suppressICMPReplies); nothing here.
	default: // udp
		// Drop the ICMP port-unreachable the kernel emits for the closed UDP port.
		rules = append(rules, fwRule{"filter", "OUTPUT", []string{"-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"}})
	}
	return rules
}

func carrierProto(transport string) string {
	switch transport {
	case carrierTCP:
		return "tcp"
	case carrierICMP:
		return "icmp"
	default:
		return "udp"
	}
}

func applyFirewall(rules []fwRule, logger *logrus.Logger) {
	warn := func(format string, args ...any) {
		if logger != nil {
			logger.Warnf(format, args...)
		}
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		warn("spoof: iptables not found — the kernel may answer spoofed packets and leak the real IP")
		return
	}
	for _, r := range rules {
		deleteRuleRepeatedly(r)
		if err := iptables(r.verb("-A")...); err != nil {
			warn("spoof: could not add firewall rule (%s %s): %v", r.table, r.chain, err)
		}
	}
}

func removeFirewall(rules []fwRule) {
	for _, r := range rules {
		deleteRuleRepeatedly(r)
	}
}

func deleteRuleRepeatedly(r fwRule) {
	for i := 0; i < 4; i++ {
		if err := iptables(r.verb("-D")...); err != nil {
			return
		}
	}
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return &ipterr{args, strings.TrimSpace(string(out)), err}
	}
	return nil
}

type ipterr struct {
	args []string
	out  string
	err  error
}

func (e *ipterr) Error() string {
	return "iptables " + strings.Join(e.args, " ") + ": " + e.err.Error() + " (" + e.out + ")"
}

// suppressICMPReplies stops the kernel from auto-answering echo requests, which
// is needed only for the ICMP carrier. It returns a restore func.
func suppressICMPReplies() func() {
	const path = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
	prev, err := os.ReadFile(path)
	if err != nil {
		return func() {}
	}
	if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
		return func() {}
	}
	return func() { _ = os.WriteFile(path, prev, 0644) }
}

func requireRoot(logger *logrus.Logger) {
	if os.Geteuid() != 0 {
		logger.Fatalf("spoof: raw packet spoofing requires root privileges")
	}
}
