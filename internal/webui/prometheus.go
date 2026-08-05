package webui

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/manage"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"
	"github.com/mahdi-byte64/arange-tun/internal/sysstat"
)

// handlePrometheus serves the numbers in Prometheus text exposition format,
// for anyone running Grafana over several servers. It is raw values only —
// no strings, no formatting — because that is what a scraper wants.
//
// Reached with the remote access token (Settings → Remote access); a panel
// session works too, so it can be inspected from a browser.
func (s *server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder

	m := sysstat.Get()
	gauge(&b, "arange-tun_cpu_percent", "CPU usage percent", m.CPUPercent)
	gauge(&b, "arange-tun_mem_percent", "Memory usage percent", m.MemPercent)
	gauge(&b, "arange-tun_swap_percent", "Swap usage percent", m.SwapPercent)
	gauge(&b, "arange-tun_disk_percent", "Disk usage percent", m.DiskPercent)
	gauge(&b, "arange-tun_uptime_seconds", "System uptime in seconds", m.Uptime.Seconds())
	gauge(&b, "arange-tun_monitor_running", "1 when the arange-tun-monitor service is active",
		boolVal(manage.MonitorRunning()))

	tunnels := manage.List()
	health := manage.AllHealth()

	b.WriteString("# HELP arange-tun_tunnel_up 1 when the tunnel's peer is connected\n# TYPE arange-tun_tunnel_up gauge\n")
	for _, t := range tunnels {
		up := health[t.Name].State == "online"
		fmt.Fprintf(&b, "arange-tun_tunnel_up{name=%q,transport=%q,role=%q} %d\n",
			t.Name, t.Transport, t.Role, int(boolVal(up)))
	}

	counterHead(&b, "arange-tun_tunnel_bytes_in_total", "Bytes received over the tunnel")
	counterHead(&b, "arange-tun_tunnel_bytes_out_total", "Bytes sent over the tunnel")
	var kcpSnaps []metrics.Snapshot
	for _, t := range tunnels {
		snap, err := metrics.Read(app.ConfigDir, t.Name)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "arange-tun_tunnel_bytes_in_total{name=%q} %d\n", t.Name, snap.BytesIn)
		fmt.Fprintf(&b, "arange-tun_tunnel_bytes_out_total{name=%q} %d\n", t.Name, snap.BytesOut)
		if snap.KCP != nil {
			snap.Name = t.Name
			kcpSnaps = append(kcpSnaps, snap)
		}
	}

	if len(kcpSnaps) > 0 {
		for _, c := range []struct {
			metric, help string
			val          func(*metrics.KCPStats) uint64
		}{
			{"arange-tun_kcp_retransmitted_total", "KCP segments sent again", func(k *metrics.KCPStats) uint64 { return k.Retransmitted }},
			{"arange-tun_kcp_lost_total", "KCP segments that never arrived", func(k *metrics.KCPStats) uint64 { return k.Lost }},
			{"arange-tun_kcp_fec_recovered_total", "Packets rebuilt by forward error correction", func(k *metrics.KCPStats) uint64 { return k.FECRecovered }},
		} {
			counterHead(&b, c.metric, c.help)
			for _, snap := range kcpSnaps {
				fmt.Fprintf(&b, "%s{name=%q} %d\n", c.metric, snap.Name, c.val(snap.KCP))
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}

func gauge(b *strings.Builder, name, help string, v float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n",
		name, help, name, name, strconv.FormatFloat(v, 'f', -1, 64))
}

func counterHead(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
}

func boolVal(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
