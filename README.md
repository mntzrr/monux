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

### Prerequisites

- Linux with `uinput` and `evdev` kernel modules enabled (`/dev/uinput` and `/dev/input/` should exist).
- A Rust toolchain (`rustup` recommended).
- Access to input devices: your user in the `input` group with `/dev/uinput` group-writable. `monux setup` persists both for you (it re-executes with sudo and prompts for your password; log out and back in after the group change). Running the server as root with `sudo -E monux server` also works as a fallback, `-E` preserving your session so clipboard sharing works.

### From this repository

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

### Autostart on login (optional)

`monux setup` can also install a per-user systemd service that starts monux with your graphical session:

```bash
monux setup --autostart server   # or: --autostart client
```

This writes `~/.config/systemd/user/monux-<role>.service` and enables+starts it via `systemctl --user` (`Restart=on-failure`, 3s delay). The client service runs plain `monux client` with no address argument, so it finds the server via mDNS auto-discovery — nothing machine-specific is baked into the unit. `--autostart off` disables both services and removes the unit files. Setup is flag-scoped: any flag (like `--autostart` here) runs only that flag's actions — and `--autostart` alone doesn't even elevate, being per-user — while a bare `monux setup` applies the full machine-tuning set (and elevates via sudo). The tray indicator comes for free: the daemon auto-spawns it (see the tray-indicator section below), subject to the same `DBUS_SESSION_BUS_ADDRESS` caveat as clipboard sharing.

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

**Clipboard sharing caveat:** the service inherits the systemd user manager's environment, not your compositor's session. Clipboard sharing needs `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, and `DBUS_SESSION_BUS_ADDRESS` imported into the user manager. Hyprland handles this when launched via UWSM, or with its systemd integration (`exec-once = dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP`). Without it the service still works for input, but clipboard sharing stays disabled — exactly like running monux with `WAYLAND_DISPLAY` unset.

### If you want a portable binary

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

**Protocol negotiation:** from protocol v16 on, mixed-version pairs no longer refuse each other at the handshake: they connect at the lower of the two protocol versions, each side using only the features that version supports, and log the degraded set (e.g. `running at v16 (disabled: …)`). Peers older than v16 predate negotiation and still need an exact version match. One bridge crosses the era boundary: a v16+ client connecting to a v15 server — the oldest version it fully speaks — retries the handshake once speaking v15 ("clamping"), so a newer client keeps working against a not-yet-updated server. Updating the server first remains the safe order; the gate above still refuses pre-negotiation mismatches, and accepts any pair where both sides are v16+. Touchpad multitouch (gestures) requires protocol v9 or newer on both ends — earlier versions only forward single-touch pointer and button events.

**Downgrading:** `monux update --to <version|commit>` installs a specific build instead of the latest (e.g. `--to 8.3.0` or `--to 5b4c00e`; a version resolves to the newest commit whose Cargo.toml declares it, anything else is treated as a commit prefix). The protocol-compatibility gate applies in reverse too: the target build's protocol must be able to pair with your server, so **downgrade the server first** and let clients follow — their gate opens once they reconnect, mirroring the upgrade order (`--force` overrides). A successful downgrade writes a pin (`~/.config/monux/update-pin`): the background auto-updater then logs that it is pinned and skips every check — it never undoes a manual downgrade and never removes the pin. A plain `monux update` lifts the pin ("unpinned; updating to latest") and returns to the latest. `monux update --rollback` is shorthand for `--to <the previously installed build>` — every install records the build it replaced (`~/.config/monux/previous-version`). After a downgrade, restart the daemons to apply it: `mx daemon restart`.

### Automatic updates

`monux server` and `monux client` automatically check the GitHub repo once shortly after startup and then daily (opt out with `--no-auto-update`). When a newer commit appears, it is rebuilt and installed in the background at low CPU priority; a few seconds later (after a desktop notification) the process restarts itself into the new binary. The restart drops the session for a few seconds, which then heals itself: clients reconnect automatically and whichever machine was active is re-activated (see above). This is handy for machines you can't easily reach — e.g. keeping a client up to date without SSH access. Clients are additionally protected by the protocol-compatibility gate above: a client only auto-updates to builds its server can talk to, so a version split can't happen. And if the client ever connects to a server running a newer protocol version (the server upgraded ahead of it), spotting it in the handshake immediately wakes the client's auto-updater instead of waiting for the daily tick — the pair converges on its own. Auto-update trusts the configured GitHub repo and this machine's git setup implicitly; pass `--no-auto-update` if you prefer to review changes first.

## Usage

Run the server on the machine with the physical input devices:

```bash
monux server
```

Run the client on each machine you want to control:

```bash
monux client <server-ip-or-hostname>
```

On a local network you can omit the host and let the client discover the server via mDNS:

```bash
monux client
```

The server advertises its hostname, protocol version, and certificate fingerprint in its mDNS TXT record; `monux servers` lists everything answering on the LAN plus the servers this client remembers — without connecting to anything. mDNS is link-local multicast and cannot cross routers, so when the machines sit on different subnets (same modem, different router) discovery never sees the server, while a direct connection works fine: connect once with `monux client <ip>` and the address is remembered (`~/.config/monux/known_servers`, the 5 most recent) and tried before mDNS from then on. The remembered store also widens the host argument: `monux client` takes an IP, a remembered server name, or a fingerprint prefix — every field printed by `monux servers` is a valid connect target.

The first time a client connects, verify the fingerprint shown on both sides matches, then approve it. Approved certificates are stored in `~/.config/monux/known_certs/`.

### Server: sudo vs non-sudo

The server runs as your normal user (in the `input` group, with `/dev/uinput` accessible — see `monux setup`). This is the recommended setup.

`sudo -E monux server` remains available as a fallback (e.g. if device permissions aren't set up); `-E` preserves your session environment so clipboard sharing keeps working. Note that running as root did **not** prove to prevent intermittent input freezes: with aggressive clipboard managers (`wl-clip-persist`, `wl-paste --watch`) a stall is still possible on some compositors. If you hit freezes, see *Troubleshooting* — `WAYLAND_DISPLAY= monux server` (clipboard sharing disabled) is the isolation test.

Switch between the server and connected clients using `LeftShift+LeftAlt+R` (next) and `LeftAlt+P` (previous), or send `SIGUSR1` / `SIGUSR2` to the server process. Shortcuts are configurable via `--shortcut` / `--shortcut-prev`. The switch fires the moment the full combo is pressed; keep holding the modifier keys and tap the last key again to cycle through further clients.

Pause input handling entirely with a pause chord (opt-in via `--pause-shortcut <keys>`, e.g. `leftshift,leftalt,p`; disabled by default). While paused, monux ungrabs **all** input devices — keyboards included — so the local machine gets raw evdev input with monux's re-emit completely out of the way (useful for games and raw-input apps). monux keeps listening ungrabbed, so the pause chord still works: press it again to resume, which re-grabs per the current rotation state (keyboards always, mice only while a client is active). While paused nothing is forwarded to clients and switch chords are not acted on — since devices are ungrabbed, those keystrokes also pass through to the local system. Clipboard sharing continues untouched while paused.

Every switch also shows a desktop notification (via `notify-send`), so an unexpected switch is visible immediately. The same goes for connection lifecycle events: the server notifies when a client joins or is dropped, the client notifies when the connection is lost and when it (re)connects, and a client on a degraded link (RTT over 50ms or packet loss over 2% — a WiFi/link problem, not monux) warns at most once per 5 minutes, plus once when the link recovers.

> **Pick a shortcut that doesn't collide with your compositor/WM/application binds.** monux consumes only the *last* key of the combo, so if the same combo is bound elsewhere (e.g. `Alt+Shift+R` toggling your clipboard manager), pressing it fires *both* actions — and a switch you didn't mean to make looks exactly like dead keys: your input silently goes to the other machine. The notification exists to make such accidents obvious.

### Screen-edge switching (Hyprland)

As an alternative to shortcuts, the server can switch input when you push the cursor against a screen edge and hold it there briefly — the classic "screen-edge KVM" behavior. It's opt-in: map an edge to a client with `--edge-map` (repeatable, and values may be comma-separated):

```bash
monux server --edge-map right=auto
monux server --edge-map right=aa11bb --edge-map left=laptop
monux server '--edge-map right=auto,left=laptop'
```

The target is a client fingerprint prefix (see the `Added client ...` log line), a hostname (resolved via the system resolver, including `<name>.local` mDNS records, and matched to a connected client by IP), or `auto` for "exactly one connected client" (an error while zero or several clients are connected). Targets are re-resolved against the live client list on every connect and at switch time, so reconnects and IP changes are tolerated; the server logs the resolution at startup and on every client (dis)connect. Switching fires through the same path as the goto shortcuts, so pause mode and no-op handling behave identically.

Detection polls the cursor position from Hyprland's IPC every 40 ms and checks it against the mapped edges (Hyprland delivers no usable pointer enter/leave at screen edges, so an event-driven design is not viable there). With multiple monitors, only the *exposed* parts of an edge count: where two outputs abut, the cursor crosses over instead of switching (two side-by-side monitors expose the right edge only on the rightmost one; differing heights and vertical offsets produce the expected step segments). Each end of an exposed segment has a corner dead zone (~8%), so flinging the cursor into a screen corner never triggers a switch. The switch fires after the cursor dwells on the edge for 250 ms (tune with `--edge-dwell-ms`), and a short re-arm cooldown prevents accidental repeat switches while parked on the edge.

A direction can be pinned to one monitor with `<direction>@<monitor>=<target>`. The qualifier is the output name (the default — see `hyprctl monitors`, e.g. `eDP-1`, `DP-3`, `HDMI-A-1`), or one of the persistent identifiers the compositor reports: the monitor's serial, model, or description (Hyprland exposes them in `hyprctl monitors -j`; the startup layout log line prints them per output, e.g. `eDP-1 [Dell Inc. DELL U2720Q 83JLZ23] 1920x1080@(0,0)`). Output names can change across compositor restarts or GPU changes, so prefer the serial or model — `--edge-map bottom@83JLZ23=auto` keeps working when `eDP-1` becomes `eDP-2`. Descriptions contain spaces (quote them in your shell), and a literal `,` `=` or `@` can't appear in a qualifier — another reason the serial or model is the recommended form. A compositor reporting no identifiers degrades silently to name-only matching. An unqualified entry (`bottom=auto`) covers every output's exposed segments in that direction — with two side-by-side monitors that's the bottom edge of *both*; a qualified entry applies only to the matching output(s). When both exist for one direction, the qualified entry wins on its output and the unqualified one covers the rest; a qualified entry *alone* for a direction leaves the other monitors' edges in that direction inert. For example, on a side-by-side two-monitor server (eDP-1 left, HDMI-A-1 right) this maps only the right monitor's bottom edge, so the laptop's edge stays passive:

```bash
monux server --edge-map bottom@HDMI-A-1=auto
monux server --edge-map bottom@83JLZ23=auto                               # same, by serial (survives renames)
monux server --edge-map bottom@HDMI-A-1=aa11bb --edge-map bottom=laptop   # qualified wins on HDMI-A-1, laptop elsewhere
```

Two diagnostics cover qualifier problems, each logged only when the situation changes (not on every layout poll). A qualifier matching nothing (a typo, or a monitor currently unplugged) produces no trigger zone and logs `edge-map: no output matching '<qualifier>' in the current layout (outputs: eDP-1 [Dell Inc. DELL U2720Q 83JLZ23], DP-3 […])`. A qualifier matching *several* outputs — two identical monitor models — zones all of them and logs `edge-map: '<qualifier>' matches 2 outputs (eDP-1, DP-3); use the serial to pick one`.

Caveats: this requires a Hyprland session on the server (the layout comes from Hyprland's IPC, re-queried when it changes) — on other compositors the feature disables itself with a warning. Fullscreen games (and anything else that pins or rapidly slams the pointer into an edge) can trigger a switch mid-game; pause monux with the `--pause-shortcut` chord before gaming, or raise `--edge-dwell-ms`.

**Switching back by edge:** the client can run the same detection on its own machine, so pushing the cursor against the opposite edge returns input to the server. Usually there is nothing to configure on the client: the server tells each mapped client which server edge it sits beyond (a `Telling client <fp> it is our <dir>-hand neighbor` log line), and the client infers the return trip from that — sitting beyond the server's right edge means watching its own *left* edge (`Server says we're its right-hand client: watching the left edge (inferred)`). The inference is re-applied on every (re)connect. An explicit `--edge-map` on the client always wins over the inference — configure it only to override what the server advertises (the client's only valid target is `auto`, meaning "the server" — a client has exactly one peer):

```bash
monux server --edge-map right=auto    # push right: input goes to the client
                                      # (the client infers: push left to come back)
monux client --edge-map left=auto     # explicit override of the inferred edge
```

While the client has input, dwelling on a mapped edge of the client machine sends a switch request to the server, which honors it only from the client that currently owns input (stale or foreign requests are ignored). The request carries the fraction along the edge where the cursor crossed (0.0–1.0); the server ignores it for now — it's reserved for future cursor warping — and the server's cursor is already parked at the edge the switch-out left from, so the pointer doesn't jump on the round trip. Detection on the client is quiet while disconnected and, like on the server, needs a Hyprland session (otherwise it disables itself with a warning); `--edge-dwell-ms` applies there too.

### Client silence: the liveness check

While a client owns the input, the server pings it every 2 seconds and the client answers immediately (any data received from the client counts, not just pongs). If nothing arrives for ~6 seconds (~12 with `--www`, matching its relaxed QUIC timers) — the classic symptom of a WiFi link that black-holed — the server switches back to the local machine and ungrabs, so keystrokes stop flowing into the void: `No sign of life from current client <addr> ... switching to the local machine and ungrabbing`. The client is **not** disconnected or removed from the rotation; the 25s QUIC idle timeout still owns that, and pinging continues meanwhile. When the client answers again, the server requires 3 consecutive heard-events (each received chunk counts once, so pongs buffered during a freeze can complete this in a single burst on thaw) **and** at least 5 seconds spent in the silenced state — whichever finishes later (hysteresis against a flapping link) — then re-activates it automatically: `Client <addr> is answering again ... re-activating it`. Switching by hand in the meantime — to another client, or deliberately to the local machine — always wins: the client is then just marked healthy again, without yanking input. Manually switching to a silenced client is allowed; the same silence check applies and ungrabs again if the silence continues.

### Local network vs. internet

By default Monux is tuned for low-latency local networks (LAN, wired links, direct WiFi). Use `--www` on both server and client when connecting over the public internet:

```bash
monux server --www
monux client --www <server-host-or-ip>
```

`--www` uses conservative QUIC settings (default congestion control and RTT estimation) and skips socket QoS flags.

### Pointer motion rate (office vs gaming)

By default the server coalesces pointer motion **adaptively**: **250 updates per second** normally, raised to **500** automatically while the link is measured close and clean (see "Adaptive fidelity" below). High-polling-rate mice (1000-8000 Hz) otherwise produce thousands of tiny packets per second for no visible benefit at a desk. Motion deltas are summed losslessly — the cursor ends up in exactly the same place, just updated less often, with far less network traffic and CPU use on both machines. All motion travels as unreliable QUIC datagrams: they are never retransmitted, so a WiFi blip can't stall later input or replay a stale backlog (the "cursor crawls for a second" effect); each coalesced datagram repeats the last few deltas so the client heals lost frames and the cursor position stays exact. At full rate (`--motion-hz 0`, gaming) no history is repeated — skipping a superseded frame beats healing it. Pin a rate with `--motion-hz`, e.g. `--motion-hz 60` for maximum savings, `--motion-hz 500` for extra smoothness.

### Pointer and scroll sensitivity (client)

When the server's mouse and the client's machine disagree on DPI/sensitivity, scale the deltas on the client: `--mouse-scale 0.5` halves pointer motion, `--scroll-scale 2` doubles scroll steps (including hi-res wheels). Both default to `1.0` and accept values from 0.05 to 20. Fractional remainders are carried between events per axis, so small scales lose no motion over time — 0.5x emits exactly one tick per two input ticks. The scaling applies only where the client injects into its own virtual devices; the server machine's local input always stays 1:1.

### Control socket and `monux status`

Both daemons publish their live state and accept a small command set over a per-user unix socket: `$XDG_RUNTIME_DIR/monux/server.sock` and `$XDG_RUNTIME_DIR/monux/client.sock` (under `/tmp/monux-<uid>/` when XDG_RUNTIME_DIR is unset). The socket is same-user only — the directory is 0700, there is no further authentication — and the file is removed again on shutdown.

The quickest way to use it is the built-in CLI, which pretty-prints the daemon's state (rotation target, connected clients with fingerprint prefixes, RTT and resolved edge directions, clipboard owner, update availability) or the raw JSON with `--json`:

```bash
monux status            # server socket first, then the client's
monux status --client   # restrict to one role
monux status --json     # machine-readable response
```

The wire protocol is newline-delimited JSON, one request and one response per line, so any language can drive it (this is the backend of the tray indicator below). Requests: `{"cmd":"status"}`, `{"cmd":"diagnostics"}` (a troubleshooting bundle: state dump plus the daemon's recent log lines), `{"cmd":"switch","target":"next"|"prev"|"local"|<fingerprint-prefix>}`, `{"cmd":"pause"}` / `{"cmd":"resume"}` (idempotent: pausing a paused server is a no-op), `{"cmd":"update_now"}` (wakes the background update check), `{"cmd":"indicator","action":"hide"|"show"}` (hides the auto-spawned tray indicator without stopping the daemon, or restores it), `{"cmd":"restart"}` (graceful shutdown + re-exec, like after an update), `{"cmd":"exit"}`. Responses: `{"ok":true,"state":{...}}` for status, `{"ok":true,"diagnostics":{...}}` for diagnostics, `{"ok":true}` for accepted commands, `{"ok":false,"error":"..."}` on failure. The server socket serves the full set; the client socket only status/diagnostics/update_now/indicator/restart/exit — rotation and pause are server concepts. Example with socat:

```bash
echo '{"cmd":"pause"}' | socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/monux/server.sock
```

### Managing the daemon (`monux daemon`)

The same socket backs the `monux daemon` management verbs — drive the running daemon without touching its terminal or signals:

```bash
monux daemon switch next         # or prev / local / a client fingerprint prefix
monux daemon pause               # ungrab everything (raw local input)
monux daemon resume
monux daemon restart             # graceful restart into the installed binary
monux daemon exit                # graceful stop
monux daemon update              # wake the background update check now
```

Commands try the server socket first, then the client's (`--socket <path>` overrides where offered); server-only actions (switch/pause/resume) return the daemon's error when pointed at a client. Acknowledgement is immediate — `switch` is queued to the rotation, `exit`/`restart` ack before the daemon begins shutting down.

### Tray indicator (`monux gui indicator`)

`monux gui indicator` puts a StatusNotifierItem (SNI) tray icon in your panel — any SNI host works: waybar (with a `tray` module), KDE Plasma, xfce4-panel, and so on. It is a thin client of the control socket: it polls `{"cmd":"status"}` every 2 seconds (server socket first, then the client's) and never talks to the daemon's event loops, so it can neither stall nor be stalled by monux.

The icon is a colored dot whose tooltip carries the details ("monux: input on 192.168.1.102", per-client RTT and uptime, clipboard owner):

- **green** — input is local (client role: connected, not owning input)
- **blue** — input is on a client (client role: this machine owns the input)
- **grey** — the server is paused
- **red** — the link is degraded: any client with RTT over 50 ms (server role), or not connected to the server (client role)
- hollow grey **?** — no monux daemon is running

The menu follows the current state: switch to local / to a specific client and pause/resume (server only), per-client connection facts and clipboard owner, "Check for update now" (or "Update available: `<sha>` — update now" when the auto-updater has seen a newer commit), "Copy diagnostics" (puts a bug-report bundle — version, state dump, recent logs — on the clipboard via `wl-copy`/`xclip`/`xsel`), and "Restart monux" / "Exit monux".

The indicator starts automatically with the daemon: whenever `monux server` or `monux client` runs with a desktop session bus available, it spawns `monux gui indicator` as a child process and stops it again on shutdown (opt out with `--no-indicator` or `MONUX_NO_INDICATOR=1`). If the indicator dies on its own (e.g. its tray host restarted), the daemon respawns it — a bounded few times, after which it logs how to start it manually. Only one indicator runs at a time: a manually started `monux gui indicator` takes over from the auto-spawned one (and vice versa), never a duplicate icon.

You can hide the icon without stopping the daemon — the menu's **Hide tray icon**, or `monux gui tray hide` — and bring it back with `monux gui tray show` (or a manually started `monux gui indicator`); the daemon suppresses (re)spawns only until then, and a daemon restart always starts the indicator fresh. `show` refuses to override a daemon started with `--no-indicator`.

`monux gui tray show` with no monux daemon running doesn't error either: it starts a *standalone* tray indicator. In that state (hollow grey `?`) the menu doubles as a launcher — **Start server** / **Start client** (via the autostart systemd unit when installed, otherwise a detached `monux <role>` spawn) and **Hide tray** (exits the standalone indicator; with a daemon, hiding goes through the control socket as before). A started daemon appears in the tray within seconds, and its own auto-spawned indicator then takes over from the standalone one.

For launching the tray from your desktop's app menu there is a **monux tray** shortcut (runs `monux gui tray show`): install.sh writes it to `$XDG_DATA_HOME/applications/monux-tray.desktop` (default `~/.local/share/applications/`), `monux setup --desktop-shortcut` (re)creates it, and `monux system uninstall` removes it again.

Headless sessions are detected and skipped silently by the daemon; a manually started indicator there exits with a "no D-Bus session / no tray host" error. The systemd units installed by `monux setup --autostart` get the indicator for free, since the daemon spawns it — with the same caveat as clipboard sharing: the service needs `DBUS_SESSION_BUS_ADDRESS` in the systemd user manager's environment (see the autostart caveat above), otherwise the auto-spawn is skipped.

## Configuration

Every `monux server` / `monux client` flag (except the client's positional host) can be persisted in `~/.config/monux/config.toml`, sectioned `[server]` / `[client]` with the flag long-names as keys; repeatable flags are TOML arrays:

```toml
[server]
port = 1213
edge-map = ["right=auto", "left=aa11bb"]
motion-hz = 250

[client]
mouse-scale = 0.5
```

Precedence: an explicit CLI flag always beats the config file, which beats the built-in default. Daemons read the file once at startup — restart to apply changes (`mx daemon restart`).

Manage the file with `monux config` (or by hand):

```bash
monux config                                   # effective values and their source
monux config keys edge                         # the key reference, optionally filtered
monux config set server.edge-map right=auto left=aa11bb
monux config edit                              # $EDITOR, validated on save
```

`set` validates values with the same parsers as the flags before writing (atomic, 0600). A daemon never refuses to start over the config file: a malformed file is logged and ignored, and unknown keys (e.g. written by a newer version, or left behind by a rename) are warned about and skipped — `monux config validate` reports them with did-you-mean suggestions, line numbers, and the exact `mx config unset` lines that clean them up. When an update introduces new config keys, the first daemon start of the new version logs them once (`mx config keys` has the reference).

### History

Every mutation through `mx config` — `set`, `unset`, `edit`, and `revert` itself — preserves the replaced value as a `# was:` comment directly above the key (or in the was-block an `unset` leaves in its place), newest first, at most 5 per key:

```bash
monux config set server.shortcut leftshift,leftalt,r
# server.shortcut = "leftshift,leftalt,r" (was: leftshift,leftalt,r (default))
monux config set server.shortcut leftshift,leftalt,q
# server.shortcut = "leftshift,leftalt,q" (was: "leftshift,leftalt,r")

monux config history server.shortcut
# server.shortcut = "leftshift,leftalt,q" (current)
#  1. "leftshift,leftalt,r" @ 2026-07-25T01:12:03Z (restored by plain revert)

monux config revert server.shortcut
# server.shortcut = "leftshift,leftalt,r" (was: "leftshift,leftalt,q")
```

The file itself stays hand-editable — the history is plain comments:

```toml
[server]
# was: "leftshift,leftalt,q" @ 2026-07-25T01:12:11Z
shortcut = "leftshift,leftalt,r"
```

`monux config history` without a key lists every key that has history, sectioned; `monux config revert <key> --to <timestamp>` restores a specific entry instead of the newest. A revert re-validates the recorded value with the key's own validator before setting it, banks the current value (so it is itself undoable), and recreates the key line when the key was unset. Setting the value a key already has is a complete no-op (no entry, no file write), as is unsetting a key that isn't set. A comment only counts as history when it matches the full strict shape `# was: <TOML value> @ <timestamp>` in a managed position — your own comments, even ones starting with `# was:`, are never listed, moved, or pruned.

## Troubleshooting

If input (e.g. the Enter key) stops registering on the server machine while `monux server` runs, the server log tells you what monux sees. The first log line records the exact build (`monux v1.0.0+<sha> starting`) — always include it when reporting.

**While the freeze is happening** (switch to a TTY or SSH in):

1. `pgrep -f 'monux server' | xargs -r sudo kill -HUP` — dumps the server's full internal state (switch state, grab state, clients, clipboard owner, counters) to its log. SIGHUP is safe; it only logs.
2. Check the 10-second heartbeat lines in the log: `Input status: local (Ungrab): N events in, M emitted locally`. They show whether monux sees your keystrokes at all, and where they went.
3. `hyprctl devices | grep -i 'monux virtual'` — are the virtual keyboard/mouse still there? (The startup log lists their `/dev/input/eventN` nodes.)
4. `sudo libinput debug-events` — does the kernel see the physical key presses?
5. For a recurring dead key, restart the server with tracing: `MONUX_TRACE_KEYS=28 monux server` (28 = Enter; comma-separate more codes). Every pipeline stage then logs `KEYTRACE` lines: `capture` (the physical device delivered it, and whether a combo consumed it), `route` (forward to client / emit local / passthrough drop), `uinput` (emitted to the virtual device, or a repeat dropped). Where the trail stops is where the bug lives.

**Reading the evidence:**

- `INPUT SWALLOWED: ...` — monux sees your keys but they have nowhere to go (grab state vs switch state mismatch). Report the log.
- `KEYTRACE capture` appears but no `KEYTRACE route`/`uinput` follows → the rotation loop stalled before routing (pair with the SIGHUP dump). `route: emit local` + `uinput: emit` appear but apps see nothing → the virtual device/compositor side (`hyprctl` checks above). `capture: consumed=true` for a key that isn't in your shortcut → report your `--shortcut`/`--shortcut-goto` config.
- `Synthetic (resync-injected) key event: ...` — the evdev buffer overflowed (SYN_DROPPED, typically an 8K device during a busy startup) and the crate injected a state-diff event. A synthetic key press whose release never arrives is a stuck/phantom key — if phantom input correlates with these lines, report it.
- Phantom keypresses (e.g. a flood of newlines) right after starting the server, stopping at your next real keypress, are the compositor's key-repeat: monux grabbed the keyboard between a press and its release, so the compositor kept repeating the key it never saw released. Since v1.0.5 monux waits for all keys to be released before grabbing, so this can't happen; a `Grabbing ... with keys still held` warning means the 3s fallback fired (a key stuck held in the kernel — press and release it once).
- **Repeated characters on the client** — the client log distinguishes the mechanisms: `Duplicate press for key N` means the same press was delivered twice (event duplication), `Input burst: N key events delivered after a gap` means what you typed during a stall arrived at once when it cleared, and `Key N was held Ns before its release arrived` (debug level) marks delayed releases. Since v2.0.5, auto-repeats arriving faster than the physical repeat rate (the stall-backlog signature) are coalesced before injection, so a WiFi blip no longer flushes as a burst of repeats; real-time key holds repeat normally. Repeats that coincide with freeze warnings share the same root cause.
- Keys visible in `libinput debug-events` and the heartbeat's *emitted* counter rises, but apps see nothing, and `hyprctl devices` lacks the virtual keyboard → the compositor dropped the virtual device. `hyprctl reload` recovers it; report it.
- `Clipboard paste storm` or `Serving paste request ... took Ns` warnings coinciding with freezes → a clipboard manager (`wl-clip-persist`, `wl-paste --watch`) is hammering monux's clipboard serving. Tame or remove it.
- `Our own virtual device node ... vanished` → the virtual devices were destroyed mid-session; restart monux.
- Freeze windows that self-heal after seconds-to-a-minute point at a blocking wait that timed out — check whether they line up with clipboard warnings above.
- On connection loss, both sides log `Connection stats on drop: rtt=... lost_packets=N/M congestion_events=... black_holes=...`. High loss/congestion/black-holes means a lossy link (WiFi interference, weak signal); near-zero loss with a normal RTT means the *peer* went silent (CPU stall on that machine, or WiFi buffering/power saving there despite setup — recheck `iw dev` on the client).

### RTT spikes and degraded links (WiFi)

Latency-sensitive input shares the link with bulk clipboard traffic, and QUIC's stream priorities only order data *inside* the connection — the kernel/WiFi driver queue below is FIFO, so an unthrottled multi-MB clipboard transfer fills it and input packets behind it wait for the whole backlog to drain (bufferbloat, seen as RTT spikes for the duration of the transfer). monux therefore paces bulk transfers — adaptively by default: **40 Mbps**, raised to **160 Mbps** while the link is measured close and clean (see below), on both server and client. Pin a rate with `--bulk-throttle-mbps` (0 disables); large clipboard transfers take slightly longer at low rates (5 MB ≈ 1 s at 40 Mbps).

### Adaptive fidelity (proximity)

When the machines sit next to each other, the link should feel like it. Both endpoints sample their connection's RTT and loss (server: every 5s per client; client: every 15s): a link that stays at or under 15ms RTT and 1% loss for three consecutive samples is promoted to the **proximity tier** — pointer motion rises 250→500 Hz, bulk pacing rises 40→160 Mbps — and one bad sample (over 50ms or 2% loss) snaps straight back. Explicit `--motion-hz` / `--bulk-throttle-mbps` flags pin the rate and opt out of adaptation.

The other half of proximity is the *path*: everything normally goes via the router even when the machines are arm's-length apart. monux can steer the connection onto a **direct, routerless link** instead with a plain Ethernet cable: plug it between the machines (both ends auto-assign link-local addresses, no DHCP or config needed) and mDNS discovery steers the connection over it automatically. Connecting by hand with `monux client <ip>` always overrides the preference.

When the link is degraded, monux says so in several places: a desktop notification (at most once per 5 minutes, plus once on recovery), the client's `Link stats:` / `Link degraded:` log lines (every 15s sample), and the server's 10-second input-status heartbeat (`Link to <client> is degraded: rtt=...`, only while above the threshold). If you see sporadic RTT spikes on WiFi, the checklist:

1. **Power saving off on BOTH machines** — check with `iw dev <iface> get power_save` (`monux setup` disables it, but only on the machine where you ran it).
2. **2.4 GHz congestion** — wireless peripherals, Bluetooth, USB3 ports, and the neighbors' networks all share the band; sporadic spikes that correlate with nothing on either machine are usually this.
3. **Move the AP and clients to 5 GHz** — the single biggest fix when the hardware allows it.
4. Read the trend around a spike in the client's debug-level `Link stats:` lines (rtt and window loss every 15s).

What monux already marks for you: in local mode both endpoints run with `SO_PRIORITY=6` on the QUIC socket, which the WiFi driver maps to 802.11 UP 6 — the voice access category (AC_VO) — so monux packets cut ahead of best-effort traffic in each machine's own wireless uplink queue, no router cooperation needed. A DSCP mark on the wire is not possible from inside the process (quinn-udp overwrites the TOS byte per packet with its ECN codepoint), so the AP/router hop (which picks its downlink queue from each packet's DSCP) is covered by netfilter rules instead: `monux setup` installs them automatically on both server and client machines (a dedicated `inet monux-qos` nftables table, or two iptables mangle OUTPUT rules as fallback), and `monux system uninstall` removes them again. The rules don't persist across reboots — re-run `monux setup` after a reboot (or wrap the manual equivalent below in a systemd unit):

```bash
# nftables
sudo nft 'add table inet monux-qos'
sudo nft 'add chain inet monux-qos output { type filter hook output priority mangle; policy accept; }'
sudo nft 'add rule inet monux-qos output udp sport 1213 ip dscp set cs6'
sudo nft 'add rule inet monux-qos output udp dport 1213 ip dscp set cs6'
# undo: sudo nft delete table inet monux-qos

# or iptables
sudo iptables -t mangle -A OUTPUT -p udp --sport 1213 -j DSCP --set-dscp-class CS6
sudo iptables -t mangle -A OUTPUT -p udp --dport 1213 -j DSCP --set-dscp-class CS6
```

## License

This project is licensed under the AGPLv3 (or later versions) and is copyright Nicholas Parker.
