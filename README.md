# monux

```
\\ //
 \V/
  U
  |
  | monux
```

TLS-encrypted server-client KVM software for sharing input devices and clipboards across Linux machines.

Monux relies on the Linux uinput API, and supports keyboards, mice, and touchpads across Wayland, X11, and even bare Linux consoles. Clipboards can be seamlessly copied between machines. OSX and Windows are not currently supported.

This fork adds low-latency tuning for local networks and a `--www` mode for use over the public internet.

## Installation

```bash
git clone https://github.com/mntzrr/monux.git
cd monux
./install.sh
```

For prerequisites, autostart on login, portable builds, updating, and uninstalling, see [docs/installation.md](docs/installation.md).

## Usage

Run the server on the machine with the physical input devices:

```bash
monux server
```

Run the client on each machine you want to control:

```bash
monux client <server-ip-or-hostname>
```

On a local network you can omit the host and let the client discover the server via mDNS. For switch shortcuts, screen-edge switching, the control socket, the tray indicator, and tuning options, see [docs/usage.md](docs/usage.md).

## Documentation

- [Installation & Updating](docs/installation.md) — prerequisites, building and installing, autostart on login, portable binaries, updating and automatic updates.
- [Usage](docs/usage.md) — running the server and client, switch shortcuts, screen-edge switching (Hyprland), the liveness check, tuning, the control socket, daemon management, and the tray indicator.
- [Configuration](docs/configuration.md) — the `~/.config/monux/config.toml` file, the `monux config` command, and value history/revert.
- [Troubleshooting](docs/troubleshooting.md) — filing bug reports, recording live reproductions, input freezes, RTT spikes and degraded WiFi links, and adaptive fidelity.

## License

This project is licensed under the AGPLv3 (or later versions) and is copyright Nicholas Parker.
