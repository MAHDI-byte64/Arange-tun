# Server layout (file locations)

Everything lives in a tidy, predictable layout. You can also see this any time
from **Manage → File Locations** in the CLI.

| Path | What |
|------|------|
| `/root/Arange-tun` | The release bundle and downloaded archives. |
| `/root/Arange-tun/backups` | [Backup](backup-restore.md) `.tar.gz` files. |
| `/etc/arange-tun` | Tunnel configs (one `.toml` per tunnel) and runtime state. |
| `/usr/local/bin/arange-tun` | The binary itself. |
| `arange-tun-<name>.service` | A systemd unit per tunnel. |
| `arange-tun-monitor.service` | The [monitor service](monitor-service.md). |

The install directory is recorded in `/etc/arange-tun/install_path`, which is what
the uninstaller reads to know what to remove.

---
[← Back to the main README](../README.md)
