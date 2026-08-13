# Usage

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

## Server: sudo vs non-sudo

The server runs as your normal user (in the `input` group, with `/dev/uinput` accessible — see `monux setup`). This is the recommended setup.

`sudo -E monux server` remains available as a fallback (e.g. if device permissions aren't set up); `-E` preserves your session environment so clipboard sharing keeps working. Note that running as root did **not** prove to prevent intermittent input freezes: with aggressive clipboard managers (`wl-clip-persist`, `wl-paste --watch`) a stall is still possible on some compositors. If you hit freezes, see [Troubleshooting](troubleshooting.md) — `WAYLAND_DISPLAY= monux server` (clipboard sharing disabled) is the isolation test. An *empty* `WAYLAND_DISPLAY` is the opt-out; merely *unsetting* it no longer disables sharing, since monux then finds the session socket in `XDG_RUNTIME_DIR` (see [the autostart section](installation.md#autostart-on-login-optional)).

Switch between the server and connected clients using `LeftShift+LeftAlt+R` (next) and `LeftAlt+P` (previous), or send `SIGUSR1` / `SIGUSR2` to the server process. Shortcuts are configurable via `--shortcut` / `--shortcut-prev`. The switch fires the moment the full combo is pressed; keep holding the modifier keys and tap the last key again to cycle through further clients.

Pause input handling entirely with a pause chord (opt-in via `--pause-shortcut <keys>`, e.g. `leftshift,leftalt,p`; disabled by default). While paused, monux ungrabs **all** input devices — keyboards included — so the local machine gets raw evdev input with monux's re-emit completely out of the way (useful for games and raw-input apps). monux keeps listening ungrabbed, so the pause chord still works: press it again to resume, which re-grabs per the current rotation state (keyboards always, mice only while a client is active). While paused nothing is forwarded to clients and switch chords are not acted on — since devices are ungrabbed, those keystrokes also pass through to the local system. Clipboard sharing continues untouched while paused.

Every switch also shows a desktop notification (via `notify-send`), so an unexpected switch is visible immediately. The same goes for connection lifecycle events: the server notifies when a client joins or is dropped, the client notifies when the connection is lost and when it (re)connects, and a client on a degraded link (RTT over 50ms or packet loss over 2% — a WiFi/link problem, not monux) warns at most once per 5 minutes, plus once when the link recovers.

> **Pick a shortcut that doesn't collide with your compositor/WM/application binds.** monux consumes only the *last* key of the combo, so if the same combo is bound elsewhere (e.g. `Alt+Shift+R` toggling your clipboard manager), pressing it fires *both* actions — and a switch you didn't mean to make looks exactly like dead keys: your input silently goes to the other machine. The notification exists to make such accidents obvious.

## Screen-edge switching (Hyprland)

As an alternative to shortcuts, the server can switch input when you push the cursor against a screen edge and hold it there briefly — the classic "screen-edge KVM" behavior. It's opt-in: map an edge to a client with `--edge-map` (repeatable, and values may be comma-separated):

```bash
monux server --edge-map right=auto
monux server --edge-map right=aa11bb --edge-map left=laptop
monux server '--edge-map right=auto,left=laptop'
```

The target is a client fingerprint prefix (see the `Added client ...` log line), a hostname (resolved via the system resolver, including `<name>.local` mDNS records, and matched to a connected client by IP), or `auto` for "exactly one connected client" (an error while zero or several clients are connected). Targets are re-resolved against the live client list on every connect and at switch time, so reconnects and IP changes are tolerated; the server logs the resolution at startup and on every client (dis)connect. Switching fires through the same path as the goto shortcuts, so pause mode and no-op handling behave identically.

Detection polls the cursor position from Hyprland's IPC every 40 ms and checks it against the mapped edges (Hyprland delivers no usable pointer enter/leave at screen edges, so an event-driven design is not viable there). With multiple monitors, only the *exposed* parts of an edge count: where two outputs abut, the cursor crosses over instead of switching (two side-by-side monitors expose the right edge only on the rightmost one; differing heights and vertical offsets produce the expected step segments). Each end of an exposed segment has a corner dead zone (~8%), so flinging the cursor into a screen corner never triggers a switch. The switch fires after the cursor dwells on the edge for 250 ms (tune with `--edge-dwell-ms`), and a short re-arm cooldown prevents accidental repeat switches while parked on the edge.

The IPC socket is found via `HYPRLAND_INSTANCE_SIGNATURE`, or — when that isn't in the environment, as for an autostarted daemon — by picking the newest instance under `$XDG_RUNTIME_DIR/hypr`. A daemon that starts before Hyprland does (the autostart case) waits for the compositor and enables edge switching once it answers, rather than disabling it for the session.

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

## Client silence: the liveness check

While a client owns the input, the server pings it every 2 seconds and the client answers immediately (any data received from the client counts, not just pongs). If nothing arrives for ~6 seconds (~12 with `--www`, matching its relaxed QUIC timers) — the classic symptom of a WiFi link that black-holed — the server switches back to the local machine and ungrabs, so keystrokes stop flowing into the void: `No sign of life from current client <addr> ... switching to the local machine and ungrabbing`. The client is **not** disconnected or removed from the rotation; the 25s QUIC idle timeout still owns that, and pinging continues meanwhile. When the client answers again, the server requires 3 consecutive heard-events (each received chunk counts once, so pongs buffered during a freeze can complete this in a single burst on thaw) **and** at least 5 seconds spent in the silenced state — whichever finishes later (hysteresis against a flapping link) — then re-activates it automatically: `Client <addr> is answering again ... re-activating it`. Switching by hand in the meantime — to another client, or deliberately to the local machine — always wins: the client is then just marked healthy again, without yanking input. Manually switching to a silenced client is allowed; the same silence check applies and ungrabs again if the silence continues.

## Local network vs. internet

By default Monux is tuned for low-latency local networks (LAN, wired links, direct WiFi). Use `--www` on both server and client when connecting over the public internet:

```bash
monux server --www
monux client --www <server-host-or-ip>
```

`--www` uses conservative QUIC settings (default congestion control and RTT estimation) and skips socket QoS flags.

## Pointer motion rate (office vs gaming)

By default the server coalesces pointer motion **adaptively**: **250 updates per second** normally, raised to **500** automatically while the link is measured close and clean (see ["Adaptive fidelity"](troubleshooting.md#adaptive-fidelity-proximity)). High-polling-rate mice (1000-8000 Hz) otherwise produce thousands of tiny packets per second for no visible benefit at a desk. Motion deltas are summed losslessly — the cursor ends up in exactly the same place, just updated less often, with far less network traffic and CPU use on both machines. All motion travels as unreliable QUIC datagrams: they are never retransmitted, so a WiFi blip can't stall later input or replay a stale backlog (the "cursor crawls for a second" effect); each coalesced datagram repeats the last few deltas so the client heals lost frames and the cursor position stays exact. At full rate (`--motion-hz 0`, gaming) no history is repeated — skipping a superseded frame beats healing it. Pin a rate with `--motion-hz`, e.g. `--motion-hz 60` for maximum savings, `--motion-hz 500` for extra smoothness.

## Pointer and scroll sensitivity (client)

When the server's mouse and the client's machine disagree on DPI/sensitivity, scale the deltas on the client: `--mouse-scale 0.5` halves pointer motion, `--scroll-scale 2` doubles scroll steps (including hi-res wheels). Both default to `1.0` and accept values from 0.05 to 20. Fractional remainders are carried between events per axis, so small scales lose no motion over time — 0.5x emits exactly one tick per two input ticks. The scaling applies only where the client injects into its own virtual devices; the server machine's local input always stays 1:1.

## Control socket and `monux status`

Both daemons publish their live state and accept a small command set over a per-user unix socket: `$XDG_RUNTIME_DIR/monux/server.sock` and `$XDG_RUNTIME_DIR/monux/client.sock` (under `/tmp/monux-<uid>/` when XDG_RUNTIME_DIR is unset). The socket is same-user only — the directory is 0700, there is no further authentication — and the file is removed again on shutdown.

The quickest way to use it is the built-in CLI, which pretty-prints the daemon's state (rotation target, connected clients with fingerprint prefixes, RTT and resolved edge directions, clipboard owner, update availability) or the raw JSON with `--json`:

```bash
monux status            # server socket first, then the client's
monux status --client   # restrict to one role
monux status --json     # machine-readable response
```

The wire protocol is newline-delimited JSON, one request and one response per line, so any language can drive it (this is the backend of the tray indicator below). Requests: `{"cmd":"status"}`, `{"cmd":"diagnostics"}` (a troubleshooting bundle: state dump, environment and the daemon's recent log lines; optional `"lines":<n>` asks for a longer log tail, and `"peer":true` makes a server also poll its connected clients), `{"cmd":"switch","target":"next"|"prev"|"local"|<fingerprint-prefix>}`, `{"cmd":"pause"}` / `{"cmd":"resume"}` (idempotent: pausing a paused server is a no-op), `{"cmd":"update_now"}` (wakes the background update check), `{"cmd":"indicator","action":"hide"|"show"}` (hides the auto-spawned tray indicator without stopping the daemon, or restores it), `{"cmd":"restart"}` (graceful shutdown + re-exec, like after an update), `{"cmd":"exit"}`. Responses: `{"ok":true,"state":{...}}` for status, `{"ok":true,"diagnostics":{...}}` for diagnostics (plus `"peers":[...]` when peers were polled and any were found), `{"ok":true}` for accepted commands, `{"ok":false,"error":"..."}` on failure. The server socket serves the full set; the client socket only status/diagnostics/update_now/indicator/restart/exit — rotation and pause are server concepts. Example with socat:

```bash
echo '{"cmd":"pause"}' | socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/monux/server.sock
```

## Managing the daemon (`monux daemon`)

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

## Tray indicator (`monux gui indicator`)

`monux gui indicator` puts a StatusNotifierItem (SNI) tray icon in your panel — any SNI host works: waybar (with a `tray` module), KDE Plasma, xfce4-panel, and so on. It is a thin client of the control socket: it polls `{"cmd":"status"}` every 2 seconds (server socket first, then the client's) and never talks to the daemon's event loops, so it can neither stall nor be stalled by monux.

The icon is a colored dot whose tooltip carries the details ("monux: input on 192.168.1.102", per-client RTT and uptime, clipboard owner):

- **green** — input is local (client role: connected, not owning input)
- **blue** — input is on a client (client role: this machine owns the input)
- **grey** — the server is paused
- **red** — the link is degraded: any client with RTT over 50 ms (server role), or not connected to the server (client role)
- hollow grey **?** — no monux daemon is running

The menu follows the current state: switch to local / to a specific client and pause/resume (server only), per-client connection facts and clipboard owner, "Check for update now" (or "Update available: `<sha>` — update now" when the auto-updater has seen a newer commit), "Copy diagnostics" (puts an issue-ready bug-report bundle — version, environment, state dump, recent logs and journal — on the clipboard via `wl-copy`/`xclip`/`xsel`; the same bundle `monux diagnostics --copy` produces, see [Filing a bug report](troubleshooting.md#filing-a-bug-report-monux-diagnostics)), and "Restart monux" / "Exit monux".

The indicator starts automatically with the daemon: whenever `monux server` or `monux client` runs with a desktop session bus available, it spawns `monux gui indicator` as a child process (opt out with `--no-indicator` or `MONUX_NO_INDICATOR=1`). When the daemon shuts down, the indicator is deliberately left running: it notices the daemon is gone and falls back to the standalone launcher state below — so the tray survives daemon exits and restarts, and only disappears when you hide it (the menu's **Hide tray icon** or `monux gui tray hide`). If the indicator dies on its own (e.g. its tray host restarted), the daemon respawns it — a bounded few times, after which it logs how to start it manually. Only one indicator runs at a time: a manually started `monux gui indicator` takes over from the auto-spawned one (and vice versa), never a duplicate icon.

You can hide the icon without stopping the daemon — the menu's **Hide tray icon**, or `monux gui tray hide` — and bring it back with `monux gui tray show` (or a manually started `monux gui indicator`); the daemon suppresses (re)spawns only until then, and a daemon restart always starts the indicator fresh. `show` refuses to override a daemon started with `--no-indicator`.

`monux gui tray show` with no monux daemon running doesn't error either: it starts a *standalone* tray indicator. In that state (hollow grey `?`) the menu doubles as a launcher — **Start server** / **Start client** (via the autostart systemd unit when installed, otherwise a detached `monux <role>` spawn) and **Hide tray** (exits the standalone indicator; with a daemon, hiding goes through the control socket as before). A started daemon appears in the tray within seconds, and its own auto-spawned indicator then takes over from the standalone one.

For launching the tray from your desktop's app menu there is a **monux tray** shortcut (runs `monux gui tray show`): install.sh writes it to `$XDG_DATA_HOME/applications/monux-tray.desktop` (default `~/.local/share/applications/`), `monux setup --desktop-shortcut` (re)creates it, and `monux system uninstall` removes it again.

Headless sessions are detected and skipped silently by the daemon; a manually started indicator there exits with a "no D-Bus session / no tray host" error. The systemd units installed by `monux setup --autostart` get the indicator for free, since the daemon spawns it — with the same caveat as clipboard sharing: the service needs `DBUS_SESSION_BUS_ADDRESS` in the systemd user manager's environment (see [the autostart caveat](installation.md#autostart-on-login-optional)), otherwise the auto-spawn is skipped.

---

← Back to [wiki index](README.md) · [project README](../README.md)
