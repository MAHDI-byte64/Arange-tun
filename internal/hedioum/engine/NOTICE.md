# Hedioum Pool Tunnel — vendored engine

The Go packages under this directory (`internal/hedioum/engine/`) are the engine
of **Hedioum Pool Tunnel** by **hedioum**:

- Upstream: https://github.com/hedioum/Hedioum-Pool-Tunnel

They are vendored into Arange-tun **with the author's permission**, with
attribution, to provide the Hedioum tunnel type. Only the engine packages needed
to run the two daemons are included (the upstream CLI, TUI dashboard, installer
and self-updater are not).

Changes made while vendoring:
- The Go module path was rewritten from
  `github.com/hedioum/Hedioum-Pool-Tunnel/...` to
  `github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/...`, flattening the
  upstream `internal/` packages directly under `engine/`.
- The engine is driven by Arange-tun's own config and run under its per-tunnel
  systemd service, through the adapter in `internal/hedioum/` — rather than the
  upstream standalone binary.

All credit for the tunnel design and implementation belongs to hedioum.
