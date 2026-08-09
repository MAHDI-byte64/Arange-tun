# Arange-tun

**Reverse tunneling engine** · Go · AGPL-3.0 · Linux amd64/arm64 · single binary

Arange-tun is a high-performance **reverse tunnel** engine written entirely in
**Go**, purpose-built for **Iran ⇄ abroad (kharej)** server setups. It ships as a
single self-contained binary with an interactive **CLI** and a secured **web
dashboard**, so you can run and manage everything with or without a terminal.

> 📖 راهنمای فارسی: **[README_FA.md](README_FA.md)** · Telegram: **[@devmahdi_com](https://t.me/devmahdi_com)**
نکته:این پروژه یک فورک از بک پک می‌باشد (صرفا ظاهر پنل و cli)
---

## How it works

A reverse tunnel turns the usual direction around: the **client always dials
out**, so the machine behind it needs no open inbound port.

```
end user ──▶ forwarded port (Iran server) ──[ one transport ]──▶ kharej client ──▶ real service
                       ▲                                                │
                       └─────────────── tunnel dialed by the client ────┘
```

- The **Iran server** (role: *server*) is the entry point. It exposes the
  forwarded ports; local users connect to the **Iran IP**, which is fast and
  reachable for them.
- The **abroad / kharej server** (role: *client*) dials the Iran server and
  forwards the traffic to the **real service** (a VPN panel, a web app, …).
- Traffic entering a forwarded port on the Iran side is carried through **one
  transport** to the kharej side and handed to the service there.

Always set up the **Iran server first**, then the kharej client — the client
needs the Iran address and the token the server generates.

---

## Install

One command as root on the VPS. There are no prebuilt releases — the installer
**builds Arange-tun from source**: it downloads the current source from this
repo into `/root/Arange-tun`, installs Go automatically if the machine has no
new-enough toolchain, compiles the binary, and opens the menu:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahdi-byte64/Arange-tun/main/install.sh)
```

Reopen the menu any time with:

```bash
sudo arange-tun
```

Everything lives in a tidy layout: the source and build in `/root/Arange-tun`,
backups in `/root/Arange-tun/backups`, and tunnel configs in `/etc/arange-tun`.

The server needs to reach **github.com** (for the source) and the Go module
proxies (direct first, Iran-friendly mirrors as a fallback). If you already have
a clone of the repo, running `sudo bash install.sh` inside it builds that local
source instead of downloading anything.

**Updating** — re-run the one-liner. It fetches the latest source and rebuilds
the binary in place; your tunnels in `/etc/arange-tun` are untouched, so restart
them afterwards with `sudo arange-tun` → *Restart ALL*.

---

## Quick start

Get the roles right first — this is the one thing people trip on:

| Role | Where it runs | How to create it | What it does |
|------|---------------|------------------|--------------|
| **Server** | Iran server (entry point) | *Setup Server* | Exposes the ports; users connect to the Iran IP. |
| **Client** | Abroad / kharej (origin) | *Setup Client* | Dials the Iran server and forwards to the real service. |

### From the CLI

**1) On the Iran server — create the Server tunnel**

```bash
sudo arange-tun   →  1. Setup Server
```

Pick the transport family (TCP / UDP / WebSocket) and variant, the tunnel port
and the exposed ports, accept the suggested **64-character token** (press Enter),
and choose a performance preset — **Turbo** is the recommended default. Copy the
token; you need it on the client.

**2) On the abroad (kharej) server — create the Client tunnel**

```bash
sudo arange-tun   →  2. Setup Client
```

Enter the **Iran server IP**, the tunnel port and the **same token**. Done.

### From the web dashboard

Open the panel (port 7777, see below), click **New tunnel**, choose the side
(server or client), fill the same fields, and submit — the tunnel is written,
enabled and started immediately, exactly as the CLI would. On a server tunnel
with the token left blank, a 64-character token is generated and shown once so
you can copy it to the client.

---

## Web dashboard

A secured dashboard on **port 7777** that matches the CLI's look. The login link
and code are shown in the CLI under **Web Panel** (which also holds the panel
port, certificate and password). Open the port on your firewall first, e.g.
`sudo ufw allow 7777`.

The dashboard can:

- **Create tunnels** — server or client, every transport and preset, TLS options
  (self-signed / Let's Encrypt / existing files), and an optional advanced-tuning
  section with the same manual knobs the CLI offers.
- **Restart or delete** a tunnel from its Details dialog.
- **Monitor** live CPU / RAM / disk / traffic, each tunnel's state, real ping and
  logs — with per-tunnel and long-term metrics.
- Manage **backup**, **Telegram setup** and the **panel password** in Settings.

Every create / restart / delete action runs exactly what the CLI runs (config
file, systemd unit, service start/stop), so a tunnel built or removed from the
panel is identical to one built or removed from a terminal.

---

## Transports

Nine transports across TCP, UDP and WebSocket, plus an experimental ICMP option,
all with connection pooling:

| Family | Variants | Notes |
|--------|----------|-------|
| **TCP** | TCP, TCP Mux, TCP + Stealth | *Stealth* wraps TCP in a Noise layer with **no fingerprint** — random-looking bytes with nothing for DPI to match. Best under heavy filtering. |
| **UDP** | UDP, UDP + KCP | *KCP* adds reliable delivery with **forward error correction**, repairing loss without waiting for a retransmit. |
| **WebSocket** | WS, WS Mux, WSS, WSS Mux | *WSS* uses TLS with a real Chrome fingerprint and a Let's Encrypt (or self-signed) certificate; a **decoy site** answers non-tunnel probes so the server looks like a normal HTTPS website. |
| **Experimental** | xDi (ICMP) | Tunnels inside ping packets, for networks that filter TCP/UDP but not ICMP. |

Every transport is explained in **[docs/transports.md](docs/transports.md)**. If a
kharej server is DPI-filtered, **TCP + Stealth** or **WSS** usually get the
tunnel through; a network-layer IP block or a "dirty" exit is a clean-IP / CDN
matter — see **[docs/filtered-or-dirty-ip.md](docs/filtered-or-dirty-ip.md)**.

---

## Features

**Performance**

- Three presets — **Balance**, **Turbo** (recommended) and **Aggressive** —
  tuning pools, socket buffers, receive windows and kernel settings (BBR + fq).
- **Link Test** measures the route (latency, jitter, loss) and recommends the
  transport that suits it, deriving liveness timers from your real round trip.
- **Optimize** applies kernel/network tuning on its own (BBR + fq, socket-buffer
  ceilings, file-descriptor limits).

**Reliability**

- **Automatic failover** to backup server addresses when the main one is
  filtered, or **load balancing** across all of them at once.
- **Self-healing watchdog** restarts a dropped tunnel within ~1 minute, from its
  own service — monitoring keeps running even with the web panel stopped.
- **Automatic rollback** — updates and edits revert themselves if the tunnel does
  not come back up.
- **systemd-managed** services that survive reboots and closed terminals.

**Security**

- **The token never travels in the clear on an encrypted transport.** Stealth and
  KCP derive their keys from it without sending it; WSS / WSS Mux bind the
  credential to the TLS session. (Plain TCP / TCP Mux / WS send it as-is — use an
  encrypted transport on an untrusted path.)
- **PROXY Protocol v2** forwards each user's real IP, so per-user device limits in
  the panel behind the tunnel keep working.
- **Per-tunnel limits** on simultaneous connections and on throughput.
- Login-protected dashboard. Downloads are SHA-256 verified; anything that cannot
  be verified is refused rather than installed.

**Management**

- **Interactive CLI** for setup, editing ports / transport / preset, per-tunnel
  control, live logs and status — every option explains itself.
- **Setup checks the address you give it**, warning about a CDN in front of the
  server or an AAAA record that would send the tunnel over IPv6.
- **CDN edge** — a client can reach the server through a CDN edge (e.g.
  Cloudflare) instead of the origin, so the server's own IP is not exposed.
- **JSON logging** (`log_format = "json"`) for log collectors; human-readable logs
  stay the default.
- **Auto-refresh** — restart all tunnels every N hours.

**Monitoring**

- **Web dashboard (port 7777)** — create, restart, delete and watch tunnels, with
  live system and per-tunnel metrics (see above).
- **Metrics** — traffic and connections on every transport and, on KCP,
  retransmits, loss and packets repaired by FEC. Totals persist across restarts.
- **Health Check** — tests the server, the panel and every tunnel, printing a fix
  under each problem.

**Updates & backup**

- **Updates** — re-run the install one-liner to fetch the latest source and
  rebuild the binary in place. Your tunnels and settings in `/etc/arange-tun`
  are left untouched.
- **Backup** — every tunnel, the panel password, Telegram settings, TLS
  certificates and the schedule in one portable `.tar.gz`, from the CLI, the web
  panel or the bot.

**Telegram**

- **Alerts** when CPU / memory / disk crosses a threshold, or a tunnel goes down
  or comes back — each with a recovery message.
- Status, system and backup on demand, as buttons or commands.
- It reaches Telegram **through a tunnel peer**, so it works from Iran where
  Telegram is blocked, choosing the tunnel itself and moving to another when one
  goes down.

---

## File layout

| Path | What |
|------|------|
| `/usr/local/bin/arange-tun` | the binary |
| `/etc/arange-tun/` | per-tunnel TOML configs and runtime state |
| `/root/Arange-tun/` | the installed release bundle |
| `/root/Arange-tun/backups/` | configuration backups |
| `arange-tun-<name>.service` | one systemd unit per tunnel |

Run modes: `arange-tun` (no args) opens the interactive menu;
`arange-tun -c /etc/arange-tun/<name>.toml` runs a single tunnel (what the
systemd units execute); `arange-tun --webui` runs the web panel;
`arange-tun -v` prints the version.

---

## Build from source

Requires **Go 1.24+**, a **C compiler**, and the **libpcap development headers**
(`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora). The binary is
built with cgo because the **Packet** tunnel embeds a raw-packet (libpcap)
engine; the rest of the tree is pure Go. The installer sets these up
automatically. From a clone of the repo:

```bash
CGO_ENABLED=1 go build -o arange-tun .   # build the binary
make release                             # cross-build linux amd64 + arm64 into ./release
go test ./...                            # run the test suite (the e2e tests move real traffic)
```

**Requirements to run:** Linux (amd64 or arm64), root, and systemd. The Packet
tunnel additionally needs libpcap present at runtime (installed automatically).

---

## Documentation

Each topic has its own page under [`docs/`](docs/):

**Setup & management** —
[CLI menu](docs/cli-menu.md) ·
[Failover & load balancing](docs/failover-load-balancing.md) ·
[Per-tunnel limits](docs/limits.md) ·
[Server layout](docs/server-layout.md)

**Transports & performance** —
[Transports](docs/transports.md) ·
[Decoy site (WSS camouflage)](docs/camouflage.md) ·
[Filtered or dirty IP](docs/filtered-or-dirty-ip.md) ·
[Choosing a transport](docs/choosing-a-transport.md) ·
[Performance presets](docs/performance-presets.md) ·
[Real client IP](docs/real-client-ip.md)

**Monitoring** —
[Web panel](docs/web-panel.md) ·
[Telegram bot](docs/telegram-bot.md) ·
[Alerts](docs/alerts.md) ·
[Tunnel metrics](docs/tunnel-metrics.md) ·
[Health Check](docs/health-check.md) ·
[Monitor service](docs/monitor-service.md)

**Maintenance** —
[Backup & restore](docs/backup-restore.md) ·
[Updates & rollback](docs/updates.md)

---

## License

Released under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contact

Telegram: **[@devmahdi_com](https://t.me/devmahdi_com)**
