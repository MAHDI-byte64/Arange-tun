<div align="center">

# 🌿 Arange-tun

**A high-performance reverse-tunnel & VPN-egress engine for Iran ⇄ abroad servers**

Go · AGPL-3.0 · Linux amd64/arm64 · one self-contained binary · CLI **and** web dashboard

📖 راهنمای فارسی: **[README_FA.md](README_FA.md)**

<sub>This project is a fork of BackPack (panel & CLI look and feel).</sub>

</div>

---

## 📑 Contents

- [Why Arange-tun](#-why-arange-tun)
- [Install](#-install)
- [How reverse tunneling works](#-how-reverse-tunneling-works)
- [Tunnel types — pick the right one](#-tunnel-types--pick-the-right-one)
  - [Backhaul](#backhaul--the-built-in-engine) · [frp](#frp--built-in-reverse-proxy) · [Rathole v2](#rathole-v2--pooled-reverse-proxy) · [Packet](#packet--raw-packets-below-the-kernel) · [WireGuard](#wireguard--vpn-egress) · [SSH](#ssh--socks5-over-ssh) · [Hedioum](#hedioum--pooled-socks5-over-camouflaged-pipes)
- [Transports (Backhaul engine)](#-transports-backhaul-engine)
- [The web dashboard](#-the-web-dashboard)
- [Using the CLI](#-using-the-cli)
- [Features](#-features)
- [File layout & run modes](#-file-layout--run-modes)
- [Build from source](#-build-from-source)
- [Documentation](#-documentation)
- [License & contact](#-license--contact)

---

## ✨ Why Arange-tun

- **One binary, two front-ends.** An interactive **CLI** and a login-protected **web dashboard** that do exactly the same things — create, edit, monitor, back up.
- **Eight tunnel types under one roof.** From a simple reverse proxy to raw-packet DPI evasion, one-command SSH egress and pooled camouflaged SOCKS5 — all managed the same way.
- **Built for filtered networks.** Fingerprint-free Stealth, TLS mimicry, AmneziaWG, and raw-packet injection that hides *below* the kernel stack.
- **Runs itself.** systemd services, a self-healing watchdog, automatic rollback, Telegram alerts that reach you *through* a tunnel even from Iran.
- **No mystery binaries.** Every engine is compiled from the source in this repo — nothing is downloaded and run blind.

---

## 🚀 Install

One command as root on the VPS. There are **no prebuilt releases** — the installer
**builds from source**: it fetches the current source into `/root/Arange-tun`,
installs Go and the build prerequisites automatically, compiles the binary, and
opens the menu.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahdi-byte64/Arange-tun/main/install.sh)
```

Reopen the menu any time with:

```bash
sudo arange-tun
```

**Updating** — re-run the one-liner (or use *Update* in the panel/CLI). It rebuilds
the binary in place; your tunnels in `/etc/arange-tun` are untouched, so restart
them afterwards with *Restart ALL*.

> The server needs to reach **github.com** and the Go module proxies (direct first,
> Iran-friendly mirrors as fallback). Already have a clone? `sudo bash install.sh`
> inside it builds that local source instead of downloading.

---

## 🧭 How reverse tunneling works

A reverse tunnel turns the usual direction around: the **client always dials out**,
so the machine behind it needs no open inbound port.

```
end user ──▶ forwarded port (Iran server) ──[ one transport ]──▶ kharej client ──▶ real service
                     ▲                                                  │
                     └──────────────── tunnel dialed by the client ─────┘
```

- The **Iran server** is the entry point — it **exposes the ports**; local users
  connect to the fast, reachable **Iran IP**.
- The **abroad / kharej client** dials the Iran server and forwards traffic to the
  **real service** (a VPN panel, a web app, …).

👉 **Always set up the Iran server first**, then the kharej client — the client needs
the Iran address and the token the server shows.

> Two of the tunnel types (**Packet** and the VPN-egress ones) flip this around — the
> table below tells you which side is which for each.

---

## 🧩 Tunnel types — pick the right one

Arange-tun manages eight tunnel types. They all share the same lifecycle (create →
start → monitor → edit → delete), from the CLI or the panel's **New tunnel** chooser,
which groups them into **Reverse** (port forwarding) and **Direct** (VPN outbound).

| Tunnel | Family | Where each side runs | Reach for it when… |
|--------|--------|----------------------|--------------------|
| **Backhaul** | Reverse | 🇮🇷 Iran = server · 🌍 abroad = client | You want the flexible default — many transports and DPI options. |
| **frp** | Reverse | 🇮🇷 Iran = server · 🌍 abroad = client | You want a simple, fast reverse proxy with obfuscation. |
| **Rathole v2** | Reverse | 🇮🇷 Iran = server · 🌍 abroad = client | You want pooled data channels for low, steady latency. |
| **Packet** | Reverse *(inverted)* | 🌍 abroad = server · 🇮🇷 Iran = client | DPI/firewalls are aggressive — this hides *below* the kernel stack. |
| **WireGuard** | Direct (VPN egress) | 🌍 abroad = server · 🇮🇷 Iran = client (SOCKS5) | You want a full VPN exit, optionally AmneziaWG-obfuscated. |
| **SSH** | Direct (VPN egress) | 🇮🇷 Iran = client only | You just need a quick egress and can SSH into a box abroad. |
| **Hedioum** | Direct (VPN egress) | 🌍 abroad = foreign · 🇮🇷 Iran = hub (SOCKS5) | You want a pooled SOCKS5 exit that mimics SSH/TLS/mail and self-scales. |

Each type opens with a **built-in setup guide** in the panel before its form. Here's
the short version of each.

### Backhaul — the built-in engine

The default reverse tunnel and the most flexible one: ten [transports](#-transports-backhaul-engine)
across TCP/UDP/WebSocket, connection pooling, presets, and DPI options.

- **🇮🇷 Iran (server):** *Setup Server* → pick a transport + preset, set the tunnel
  port and the exposed ports, copy the generated **64-char token**.
- **🌍 abroad (client):** *Setup Client* → enter the Iran IP, the tunnel port and the
  **same token**. Both sides must use the same transport and token.

### frp — built-in reverse proxy

frp's own protocol (a token handshake with multiplexed streams), compiled in — no
external binary. It works and is managed exactly like a Backhaul tunnel, in **TCP** or
**UDP** variants, with a **DPI obfuscation** choice: *Stealth (Noise)* — random-looking
with no fingerprint — or *TLS (uTLS)* — looks like ordinary HTTPS, with a self-signed
or a real **Let's Encrypt** certificate.

- 🇮🇷 Iran = server (exposes the ports) · 🌍 abroad = client (dials out, same token &
  obfuscation on both sides).

### Rathole v2 — pooled reverse proxy

A faithful Go port of Rathole: a control channel plus a **pool of separate data
channels**, which keeps latency low and steady under many connections. Same TCP/UDP
variants and the same Stealth / TLS obfuscation choice as frp.

- 🇮🇷 Iran = server · 🌍 abroad = client.

### Packet — raw packets below the kernel

The strongest DPI evasion. Packet captures and injects **crafted raw TCP packets**
with libpcap, carrying an encrypted KCP transport **beneath the OS TCP/IP stack** — so
DPI and stateful firewalls that track the kernel's own connections never see the
tunnel (even a `ufw deny` on the port has no effect on it).

- **Inverted topology:** 🌍 **abroad = server** (the exit node — listens, generates a
  shared key; run your real service here) · 🇮🇷 **Iran = client** (exposes the ports and
  dials out). Each exposed port is relayed 1:1 to `127.0.0.1:<port>` on the server.
- **Requirements:** **root** and **libpcap** on both ends (installed automatically),
  **Linux only**, and a **high, non-standard port** (never 80/443). The interface, local
  IP, gateway MAC and firewall rules are all detected/applied automatically.

### WireGuard — VPN egress

A full VPN exit, not a reverse tunnel. The abroad side is a real kernel WireGuard exit
node; the Iran side brings WireGuard up **in userspace** and opens a local **SOCKS5
proxy** whose traffic leaves through the tunnel.

- **🌍 abroad (server):** generates a WireGuard config — copy it to the client.
- **🇮🇷 Iran (client):** paste **any** WireGuard config (from the server side, WARP, a
  provider, or your own), pick a SOCKS5 port, and point your panel's outbound at
  `127.0.0.1:<port>`. **AmneziaWG** configs work too — their obfuscation defeats the
  WireGuard-fingerprint blocks used in some regions.

### SSH — SOCKS5 over SSH

The simplest egress, **client only** — there's nothing to install on the server beyond
an SSH login. Arange-tun logs in to a server abroad and opens a local **SOCKS5 proxy**
whose traffic leaves through it, reconnecting automatically if the link drops.

- **🇮🇷 Iran (client):** enter the server's **IP/domain, port, username and password**
  and a local SOCKS5 port; add a SOCKS outbound in your panel at `127.0.0.1:<port>`.
- Security is intentionally light (password login, host key trusted on first use) —
  use it for convenience, not as a hardened channel.

### Hedioum — pooled SOCKS5 over camouflaged pipes

A two-node egress that carries **SOCKS5 over a self-scaling pool of camouflaged pipes**.
Each pipe impersonates a real protocol — **SSH, TLS, SMTP or IMAP** — is encrypted with
ChaCha20-Poly1305, and jitters its bandwidth to blur DPI patterns. The abroad node also
serves a **decoy** (an Apache or DirectAdmin page) to anyone who probes it without the
token, so it looks like an ordinary server.

- **🌍 abroad (foreign):** pick a **camouflage** and a listen port, optionally a domain
  for a real **Let's Encrypt** certificate (ACME); it generates a shared **token**.
- **🇮🇷 Iran (hub):** point it at the foreign IP/port with the **same camouflage** and
  the **token**, and choose a local SOCKS5 port; add a SOCKS outbound in your panel at
  `127.0.0.1:<port>`. The pool grows and shrinks with load on its own.

> The Hedioum engine is vendored **with the author's permission** from
> [Hedioum Pool Tunnel](https://github.com/hedioum/Hedioum-Pool-Tunnel) by **hedioum**;
> all credit for its design belongs to them. See
> [`internal/hedioum/engine/NOTICE.md`](internal/hedioum/engine/NOTICE.md).

---

## 🔌 Transports (Backhaul engine)

The Backhaul tunnel offers ten transports across TCP, UDP and WebSocket, plus an
experimental ICMP option, all with connection pooling:

| Family | Variants | Notes |
|--------|----------|-------|
| **TCP** | TCP · TCP Mux · TCP + Stealth | *Stealth* wraps TCP in a Noise layer with **no fingerprint** — random-looking bytes with nothing for DPI to match. Best under heavy filtering. |
| **UDP** | UDP · UDP + KCP · QUIC | *KCP* adds reliable delivery with **forward error correction**, repairing loss without waiting for a retransmit. *QUIC* multiplexes many reliable streams over one UDP flow, with its own loss recovery and a TLS 1.3 handshake underneath. |
| **WebSocket** | WS · WS Mux · WSS · WSS Mux | *WSS* uses TLS with a real Chrome fingerprint and a Let's Encrypt (or self-signed) certificate; a **decoy site** answers non-tunnel probes so the server looks like a normal HTTPS website. |
| **Experimental** | xDi (ICMP) · IP Spoofing | *xDi* tunnels inside ping packets, for networks that filter TCP/UDP but not ICMP. *IP Spoofing* carries KCP inside raw IPv4 packets with a **forged source address** (udp/icmp/tcp profiles, a rotating source pool, DPI-evasion obfuscation and a WireGuard pipe mode) — for a path that filters on the real flow. Both are Linux-only and need root. |

If a kharej server is DPI-filtered, **TCP + Stealth** or **WSS** usually get the tunnel
through; a network-layer IP block or a "dirty" exit is a clean-IP / CDN matter. Full
detail in **[docs/transports.md](docs/transports.md)** and
**[docs/choosing-a-transport.md](docs/choosing-a-transport.md)**.

---

## 🖥️ The web dashboard

A secured dashboard on **port 7777** that mirrors the CLI. The login link and code are
shown in the CLI under **Web Panel** (which also holds the panel port, certificate and
password). Open the port on your firewall first, e.g. `sudo ufw allow 7777`.

From the dashboard you can:

- **➕ Create any tunnel type** — the **New tunnel** chooser groups Reverse and Direct
  tunnels, each with its own setup guide and form (transports, presets, TLS options,
  obfuscation, and an optional advanced-tuning section with the same manual knobs the
  CLI offers).
- **✏️ Edit, ⏸️ stop/▶️ start, 🔁 restart or 🗑️ delete** a tunnel from its Details dialog —
  including WireGuard, Packet, SSH and Hedioum tunnels.
- **📊 Monitor** live CPU / RAM / disk / traffic, each tunnel's state, real ping and
  logs — with per-tunnel and long-term metrics.
- **⚙️ Manage** backup, Telegram setup and the panel password in Settings, and **update**
  the binary from source.

Every create / edit / restart / delete runs exactly what the CLI runs (config file,
systemd unit, service start/stop), so a tunnel built or removed from the panel is
identical to one from a terminal.

---

## 🧰 Using the CLI

Get the roles right first — this is the one thing people trip on for the reverse
tunnels:

| Role | Where it runs | How to create it | What it does |
|------|---------------|------------------|--------------|
| **Server** | 🇮🇷 Iran (entry point) | *Setup Server* | Exposes the ports; users connect to the Iran IP. |
| **Client** | 🌍 abroad / kharej (origin) | *Setup Client* | Dials the Iran server and forwards to the real service. |

```bash
sudo arange-tun        # opens the interactive menu
```

**1) On the Iran server →** *Setup Server*: pick the transport and preset, set the
tunnel port and exposed ports, accept the suggested **64-character token**, copy it.

**2) On the abroad server →** *Setup Client*: enter the **Iran IP**, the tunnel port and
the **same token**. Done.

The menu also edits ports / transport / preset, controls each tunnel, and shows live
logs and status — every option explains itself. See **[docs/cli-menu.md](docs/cli-menu.md)**.

---

## 🛡️ Features

<details open>
<summary><b>Performance</b></summary>

- Three presets — **Balance**, **Turbo** (recommended), **Aggressive** — tuning pools,
  socket buffers, receive windows and kernel settings (BBR + fq).
- **Link Test** measures the route (latency, jitter, loss) and recommends a transport,
  deriving liveness timers from your real round trip.
- **Optimize** applies kernel/network tuning on its own.
</details>

<details>
<summary><b>Reliability</b></summary>

- **Automatic failover** to backup server addresses, or **load balancing** across all
  of them at once.
- **Self-healing watchdog** restarts a dropped tunnel within ~1 minute, from its own
  service — monitoring keeps running even with the web panel stopped.
- **Automatic rollback** — updates and edits revert themselves if the tunnel does not
  come back up.
- **systemd-managed** services that survive reboots and closed terminals.
</details>

<details>
<summary><b>Security</b></summary>

- **The token never travels in the clear on an encrypted transport.** Stealth and KCP
  derive their keys from it without sending it; WSS binds the credential to the TLS
  session. (Plain TCP / WS send it as-is — use an encrypted transport on an untrusted
  path.)
- **PROXY Protocol v2** forwards each user's real IP, so per-user device limits in the
  panel behind the tunnel keep working.
- **Per-tunnel limits** on simultaneous connections and on throughput.
- Login-protected dashboard. Downloads are SHA-256 verified; anything that cannot be
  verified is refused rather than installed.
</details>

<details>
<summary><b>Management & monitoring</b></summary>

- **Interactive CLI** and **web dashboard (port 7777)** for everything.
- **Setup checks the address you give it**, warning about a CDN in front of the server
  or an AAAA record that would send the tunnel over IPv6.
- **CDN edge** — reach the server through a CDN edge (e.g. Cloudflare) so its own IP is
  not exposed.
- **Metrics** — traffic and connections on every transport and, on KCP, retransmits,
  loss and FEC repairs; totals persist across restarts.
- **Health Check** — tests the server, the panel and every tunnel, printing a fix under
  each problem.
- **JSON logging** (`log_format = "json"`) for log collectors.
</details>

<details>
<summary><b>Updates, backup & Telegram</b></summary>

- **Updates** — rebuild from source in place; tunnels and settings in `/etc/arange-tun`
  are left untouched.
- **Backup** — every tunnel, the panel password, Telegram settings, TLS certificates
  and the schedule in one portable `.tar.gz`, from the CLI, the panel or the bot.
- **Telegram** — alerts when CPU / memory / disk crosses a threshold or a tunnel
  goes down/comes back; status, system and backup on demand. It reaches Telegram
  **through a tunnel peer**, so it works from Iran, moving to another tunnel if one
  drops.
</details>

---

## 🗂️ File layout & run modes

| Path | What |
|------|------|
| `/usr/local/bin/arange-tun` | the binary |
| `/etc/arange-tun/` | per-tunnel TOML configs and runtime state |
| `/root/Arange-tun/` | the source & build bundle |
| `/root/Arange-tun/backups/` | configuration backups |
| `arange-tun-<name>.service` | one systemd unit per tunnel |

**Run modes:** `arange-tun` (no args) opens the menu · `arange-tun -c
/etc/arange-tun/<name>.toml` runs a single tunnel (what the systemd units execute) ·
`arange-tun --webui` runs the web panel · `arange-tun -v` prints the version.

---

## 🔧 Build from source

Requires **Go 1.24+**, a **C compiler**, and the **libpcap development headers**
(`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora). The binary is built
with cgo because the **Packet** tunnel embeds a raw-packet (libpcap) engine; the rest of
the tree is pure Go. The installer sets these up automatically. From a clone:

```bash
CGO_ENABLED=1 go build -o arange-tun .   # build the binary
make release                             # cross-build linux amd64 + arm64 into ./release
go test ./...                            # run the test suite (the e2e tests move real traffic)
```

**Requirements to run:** Linux (amd64 or arm64), root, and systemd. Packet tunnels
additionally need libpcap at runtime and root.

---

## 📚 Documentation

Each topic has its own page under [`docs/`](docs/):

**Setup & management** — [CLI menu](docs/cli-menu.md) · [Failover & load balancing](docs/failover-load-balancing.md) · [Per-tunnel limits](docs/limits.md) · [Server layout](docs/server-layout.md)

**Transports & performance** — [Transports](docs/transports.md) · [Decoy site (WSS camouflage)](docs/camouflage.md) · [Filtered or dirty IP](docs/filtered-or-dirty-ip.md) · [Choosing a transport](docs/choosing-a-transport.md) · [Performance presets](docs/performance-presets.md) · [Real client IP](docs/real-client-ip.md)

**Monitoring** — [Web panel](docs/web-panel.md) · [Telegram bot](docs/telegram-bot.md) · [Alerts](docs/alerts.md) · [Tunnel metrics](docs/tunnel-metrics.md) · [Health Check](docs/health-check.md) · [Monitor service](docs/monitor-service.md)

**Maintenance** — [Backup & restore](docs/backup-restore.md) · [Updates & rollback](docs/updates.md)

---

## 📄 License & contact

Released under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE).

**Credits:** the **Hedioum** tunnel embeds the engine of
[Hedioum Pool Tunnel](https://github.com/hedioum/Hedioum-Pool-Tunnel) by **hedioum**,
vendored **with the author's permission** and with attribution — see
[`internal/hedioum/engine/NOTICE.md`](internal/hedioum/engine/NOTICE.md).

**GitHub:** [mahdi-byte64](https://github.com/mahdi-byte64) — open an issue on the repository.
