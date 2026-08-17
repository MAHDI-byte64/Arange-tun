package optimize

import "testing"

// The connection-tracking tuning is the fix for a tunnel server that runs fast
// for hours and then crawls until a restart: the table fills with finished
// connections the default keeps for days. These assertions lock in the two
// settings that actually matter — a raised ceiling and a much shorter
// established timeout — so a later edit cannot quietly drop them.
func TestConntrackTuningPresent(t *testing.T) {
	get := func(key string) (string, bool) {
		for _, kv := range conntrackSysctls {
			if kv[0] == key {
				return kv[1], true
			}
		}
		return "", false
	}

	if v, ok := get("net.netfilter.nf_conntrack_max"); !ok || v == "" {
		t.Errorf("nf_conntrack_max must be raised, got %q (present=%v)", v, ok)
	}

	// The whole point: the default established timeout is 432000s (5 days). If it
	// is not brought well below that, finished connections still pile up.
	v, ok := get("net.netfilter.nf_conntrack_tcp_timeout_established")
	if !ok {
		t.Fatal("the established-connection timeout is not tuned")
	}
	if v != "86400" && v >= "432000" {
		t.Errorf("established timeout %q is not lower than the 5-day default", v)
	}

	// The short teardown states are what actually churn — they must be short.
	for _, key := range []string{
		"net.netfilter.nf_conntrack_tcp_timeout_time_wait",
		"net.netfilter.nf_conntrack_tcp_timeout_close_wait",
		"net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
	} {
		if _, ok := get(key); !ok {
			t.Errorf("%s is not tuned", key)
		}
	}
}
