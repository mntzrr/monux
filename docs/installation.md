# Installation

## Prerequisites

- Linux with `uinput` and `evdev` kernel modules enabled (`/dev/uinput` and `/dev/input/` should exist).
- A Rust toolchain (`rustup` recommended).
- Access to input devices: your user in the `input` group with `/dev/uinput` group-writable. `monux setup` persists both for you (it re-executes with sudo and prompts for your password; log out and back in after the group change). Running the server as root with `sudo -E monux server` also works as a fallback, `-E` preserving your session so clipboard sharing works.

## From this repository

```bash
git clone https://github.com/mntzrr/monux.git
cd monux
./install.sh
```

Or install directly with cargo:

```bash
cargo install --path . --root ~/.local
```

The repository includes `.cargo/config.toml` with `target-cpu=native`, so the binary is automatically optimized for the machine you build it on.

To uninstall later: `monux system uninstall` asks for confirmation (skip with `--yes` for scripts; without a terminal it aborts instead), stops any running server/client, removes the binary (and stale copies), the `/usr/local/bin` link, and the system settings persisted by `monux setup` (udev rules, uinput module load, WiFi powersave and UDP buffer configs). It asks before removing `~/.config/monux` (identity keypair and peer approvals) — non-interactively the config is kept — and prints a hint for undoing the `input` group membership (`sudo gpasswd -d $USER input`), which is deliberately left alone since it may predate monux. If the binary is already gone, `./uninstall.sh` from the repo is a fallback wrapper that prints the remaining manual steps.

After installation, the binary is available as `monux` in `~/.local/bin`, which is in `PATH` by default on systemd-based distros and in most shell profiles (unlike `~/.cargo/bin`). If your shell doesn't find it, add `export PATH="$HOME/.local/bin:$PATH"` to your shell's rc file. A shorthand alias `mx` (a relative symlink next to the binary, refreshed by every update) is installed alongside it — every command in this document works as `mx <cmd>` too; an `mx` you created yourself for another purpose is never overwritten (and never removed by the uninstaller either).

## Autostart on login (optional)

`monux setup` can also install a per-user systemd service that starts monux with your graphical session:

```bash
monux setup --autostart server   # or: --autostart client
```

This writes `~/.config/systemd/user/monux-<role>.service` and enables+starts it via `systemctl --user` (`Restart=on-failure`, 3s delay). The client service runs plain `monux client` with no address argument, so it finds the server via mDNS auto-discovery — nothing machine-specific is baked into the unit. `--autostart off` disables both services and removes the unit files. Setup is flag-scoped: any flag (like `--autostart` here) runs only that flag's actions — and `--autostart` alone doesn't even elevate, being per-user — while a bare `monux setup` applies the full machine-tuning set (and elevates via sudo). The tray indicator comes for free: the daemon auto-spawns it (see [the tray-indicator section](usage.md#tray-indicator-monux-gui-indicator)), subject to the same `DBUS_SESSION_BUS_ADDRESS` caveat as clipboard sharing.

`monux setup --autostart status` changes nothing and prints a read-only report: for each role, whether the unit file is installed, whether it is enabled and active (with the main pid and start timestamp from `systemctl --user show`), and — cross-referenced with monux's single-instance lock — whether a live daemon was autostarted or started manually, plus the unit path:

```text
server: installed, enabled, active (pid 417077 since 2026-07-25T15:28:34) — running (autostarted)
client: not installed
unit: ~/.config/systemd/user/monux-server.service
```

No sudo is involved — it only queries your own systemd user manager and the filesystem, and it degrades to the file/lock state (with a note) when systemctl can't answer.

Check status and logs with:

```bash
systemctl --user status monux-server
journalctl --user -u monux-server
```

**Clipboard sharing under autostart:** the service inherits the systemd user manager's environment, not your compositor's session, so an autostarted daemon typically starts at login *before* the compositor exists and never sees `WAYLAND_DISPLAY` (a later `import-environment` only updates the manager itself, not services already running). monux handles this itself: when `WAYLAND_DISPLAY` is missing or stale it finds the session's wayland socket in `XDG_RUNTIME_DIR`, and an unreachable compositor is retried in the background rather than disabling sharing for the session — clipboard sharing switches on as soon as the compositor is up, and survives a compositor restart. `XDG_RUNTIME_DIR` (which systemd always sets) is therefore all that's needed. Screen-edge switching resolves the same way — no `HYPRLAND_INSTANCE_SIGNATURE` needed, and it waits for Hyprland rather than switching itself off (see [Screen-edge switching](usage.md#screen-edge-switching-hyprland)). The tray indicator still needs `DBUS_SESSION_BUS_ADDRESS` in the user manager's environment; Hyprland handles that when launched via UWSM, or with its systemd integration (`exec-once = dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP`).

## If you want a portable binary

Remove or edit `.cargo/config.toml` and change `target-cpu=native` to `target-cpu=x86-64`, then rebuild. This produces a binary that runs on any x86-64 CPU.

## Updating

```bash
monux update
```

This pulls the latest source from GitHub into `~/.cache/monux/src`, rebuilds it on this machine (with `target-cpu=native`), and installs over the existing binary. Run it on each machine (server and clients), then restart any running `monux server` / `monux client` to pick up the new version. `monux --version` prints the commit the binary was built from, so you can check that all machines match.

Updating never disrupts a running session: the processes keep their in-memory binary while the file on disk is replaced, so you can update mid-session.

To pick up the new version, restart the processes — the session then heals itself:

- **Server:** start `monux server` again however you normally run it (the new instance asks the old one to shut down and takes over). Clients reconnect within a few seconds, and the machine that was active is re-activated automatically — no client-side steps needed.
- **Client:** run `monux update` on the client machine and restart the client there (e.g. over SSH). It reconnects and resumes by itself. With auto-update (below, on by default) it does both by itself — no remote access needed.

Active-session resumption survives server restarts for up to an hour (see `active_client` in `~/.config/monux`).

**Protocol-compatibility gate:** a client never installs a build whose protocol version its server couldn't talk to. The client records the server's protocol version at every connection, including handshakes the server refused, and `monux update` (manual or automatic) checks the new source against it before building. Servers also advertise their protocol version via mDNS, so a manual `monux update` first refreshes the record from the LAN (gating on the lowest version when several servers answer) and only falls back to the last recorded version when no server answers. If the pair couldn't talk, the update is skipped with a log message telling you to update the server first; once the server is updated, the client learns the new version via mDNS or on its next connection attempt and the gate opens by itself. `monux update --force` bypasses the gate.

**Protocol negotiation:** from protocol v16 on, mixed-version pairs no longer refuse each other at the handshake: they connect at the lower of the two protocol versions, each side using only the features that version supports, and log the degraded set (e.g. `running at v16 (disabled: …)`). Peers older than v16 predate negotiation and still need an exact version match. One bridge crosses the era boundary: a v16+ client connecting to a v15 server — the oldest version it fully speaks — retries the handshake once speaking v15 ("clamping"), so a newer client keeps working against a not-yet-updated server. Updating the server first remains the safe order; the gate above still refuses pre-negotiation mismatches, and accepts any pair where both sides are v16+. Touchpad multitouch (gestures) requires protocol v9 or newer on both ends — earlier versions only forward single-touch pointer and button events. From v17 the server tags each forwarded input frame with the class of the device it came from (keyboard, mouse, touchpad), so the client routes it to the matching virtual device rather than inferring the destination from event codes that a mouse and a touchpad necessarily share; a pair that negotiates below v17 keeps the untagged frame and that inference. From v18 the server can ask its clients for their own diagnostics bundles (`monux diagnostics --peer`), so one bug report covers both machines; a pair that negotiates below v18 keeps working exactly as before and the client is listed in the report as too old to poll.

**Downgrading:** `monux update --to <version|commit>` installs a specific build instead of the latest (e.g. `--to 8.3.0` or `--to 5b4c00e`; a version resolves to the newest commit whose Cargo.toml declares it, anything else is treated as a commit prefix). The protocol-compatibility gate applies in reverse too: the target build's protocol must be able to pair with your server, so **downgrade the server first** and let clients follow — their gate opens once they reconnect, mirroring the upgrade order (`--force` overrides). A successful downgrade writes a pin (`~/.config/monux/update-pin`): the background auto-updater then logs that it is pinned and skips every check — it never undoes a manual downgrade and never removes the pin. A plain `monux update` lifts the pin ("unpinned; updating to latest") and returns to the latest. `monux update --rollback` is shorthand for `--to <the previously installed build>` — every install records the build it replaced (`~/.config/monux/previous-version`). After a downgrade, restart the daemons to apply it: `mx daemon restart`.

## Automatic updates

`monux server` and `monux client` automatically check the GitHub repo once shortly after startup and then daily (opt out with `--no-auto-update`). **The check reports; it does not install.** When a newer commit appears you get a desktop notification, the tray shows *Update available*, and `monux status` reports it — installing is your call: the tray's update action, `mx daemon update`, or `monux update`. Installing means compiling and running whatever the repo currently holds (including every build script and proc macro in the dependency tree), on a machine where monux may be running as root for uinput access, so it is not something that happens unattended by default. Once you trigger it, the rebuild runs in the background at low CPU priority and the process restarts itself into the new binary a few seconds later; the restart drops the session briefly and it heals itself — clients reconnect and whichever machine was active is re-activated (see above). Clients are additionally protected by the protocol-compatibility gate above: a client only installs builds its server can talk to, so a version split can't happen. And if a client connects to a server running a newer protocol version (the server upgraded ahead of it), spotting that in the handshake wakes the check immediately instead of waiting for the daily tick.

**Unattended installing (`--auto-install`).** If you want the old behaviour — the daemon installing and restarting on its own, useful for machines you can't easily reach — pass `--auto-install` (or set `server.auto-install` / `client.auto-install` in the config file). It then **requires a verified release signature**: the target commit must carry a git tag signed by the monux release key, checked against a public key compiled into the binary. A commit that carries no tag, or a tag whose signature doesn't verify, is refused and logged — unattended installing of code that cannot be attributed is exactly what the signature check exists to prevent. If the build has no release key compiled in, `--auto-install` refuses everything and says so; `monux update` typed by hand still works (it warns that nothing can be verified, and proceeds, because you are the review gate).

---

← Back to [wiki index](README.md) · [project README](../README.md)
