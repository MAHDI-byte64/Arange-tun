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

---
[← Back to the main README](../README.md)
