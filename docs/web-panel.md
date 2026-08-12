# Web panel

A dashboard on **port 7777**, matching the CLI's look. It shows live
CPU / RAM / disk / traffic, each tunnel's state, real ping, and logs. Backup,
Telegram setup and the panel password live in **Settings**.

Run it on the **Iran** server, where you watch things from.

## Managing tunnels

The **New tunnel** button (top of the Tunnels section) opens a form that mirrors
the CLI's *Setup Server* / *Setup Client* flows: pick the side, transport and
preset, fill the ports, address and token, and — for a `wss`/`wssmux` server —
the certificate (self-signed, Let's Encrypt, or existing files). An optional
**advanced** section exposes the same manual tuning knobs the CLI offers, on top
of the chosen preset. On a server tunnel with the token left blank, a 64-char
token is generated and shown once so you can copy it to the client.

A tunnel's **Details** dialog has **Restart** and **Delete** buttons. Every one
of these actions runs exactly what the CLI runs (config file, systemd unit,
service start/stop), so a tunnel built or removed here is identical to one built
or removed from a terminal.

## Getting in

The link and login code are shown in the CLI under **Web Panel** (whose settings
also cover update, panel port and password). Open the port first:

```bash
sudo ufw allow 7777
```

A password set by hand must be at least **8 characters** — the same length as
the one generated on first run.

## Where it listens

By default the panel answers on every interface (`0.0.0.0`), which is what you
want when you open it from a laptop. If you only ever reach it through an SSH
tunnel, it does not need to answer the internet at all. Set `bind` in
`/etc/arange-tun/webui.json` and restart the panel:

```json
{ "bind": "127.0.0.1" }
```

```bash
sudo systemctl restart arange-tun-webui
```

Then reach it over a forwarded port from your own machine:

```bash
ssh -L 7777:127.0.0.1:7777 root@your-server
```

The login page is then not on a public port at all, which is worth more than any
password. Leave `bind` unset to keep the current behaviour.

## HTTPS

`https: true` in the same file serves the panel over TLS — self-signed against
the server's IP, or a real Let's Encrypt certificate when `tls_domain` is set.
Worth doing if you reach the panel over the open internet: without it the
password and the session cookie cross the network in the clear. The session
cookie is marked `Secure` as soon as HTTPS is on, so it is never sent back
over a plain connection.

---
[← Back to the main README](../README.md)
