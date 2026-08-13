# Troubleshooting

## Filing a bug report (`monux diagnostics`)

`monux diagnostics` collects everything a report needs in one paste, so you don't have to assemble it by hand:

```bash
monux diagnostics                  # read it here
monux diagnostics --copy           # issue-ready markdown, on the clipboard
monux diagnostics --redact --copy  # ...with IPs, hostnames and home paths stripped
monux diagnostics --peer           # include the connected clients' side too
monux diagnostics --privacy        # exactly what a bundle contains, before you paste it
```

A bundle carries four things: the daemon's **state dump** and **recent log lines** (from the control socket), the **journal** for its systemd unit (`--since` defaults to the last 30 minutes), and the **environment** the daemon runs in — kernel, OS, session type, desktop, `/dev/uinput` permissions, `input`-group membership and autostart state. That last part is collected *inside the daemon*, not by the CLI: an autostarted daemon's environment differs from your shell's in exactly the ways that cause bugs, so asking the shell would describe the wrong process.

**With no daemon running it still works** — it reports the environment and the journal, which is where the answer lives for "monux won't start" and "monux crashed" (the in-memory log ring dies with the daemon; the journal doesn't).

**Both machines in one paste:** `--peer` asks each connected client for its own bundle over the existing connection, so a report about a freeze or a clipboard that won't cross carries both sides with UTC timestamps that line up. Server-side only (a client has no peers), and it needs protocol v18+ on both ends — an older client is *reported as skipped* rather than silently omitted. Peers that don't answer within 5s are recorded as unanswered, since a silent client is usually what the report is about.

**Privacy:** the bundle never contains clipboard *contents* (only the owner and MIME types) or keystrokes — unless you deliberately turn on `MONUX_TRACE_KEYS`, which logs key *codes*. It does contain your hostname, LAN IPs and certificate fingerprints; `--redact` replaces them with placeholders. Loopback addresses and fingerprints are deliberately kept (they identify nobody and the report is much harder to read without them), and a hostname too generic to substitute safely — three characters or fewer, or a word the report is made of like `monux` or `server` — is left in place and called out on stderr.

## Recording a live reproduction

For failures a snapshot can't explain — an input freeze, a dead key, a stall under load — record one instead:

```bash
systemctl --user stop monux-server   # the capture has to BE the daemon
monux diagnostics record             # reproduce the problem, then Ctrl-C
monux diagnostics record --keys 28   # ...also tracing a key (28 = Enter)
```

It runs the daemon with debug logging (`--trace` for everything, including QUIC internals), tees to a capture file while still printing to your terminal, and prints the path when you stop it. The file opens with the environment header, so it's self-describing when it arrives without the command that produced it. It refuses to start beside a daemon that is already running — two daemons fight over the input devices, and the resulting misbehaviour has nothing to do with the bug you're chasing.

## Input freezes

If input (e.g. the Enter key) stops registering on the server machine while `monux server` runs, the server log tells you what monux sees. The first log line records the exact build (`monux v1.0.0+<sha> starting`) — always include it when reporting, or just attach `monux diagnostics`, which records it for you.

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

## RTT spikes and degraded links (WiFi)

Latency-sensitive input shares the link with bulk clipboard traffic, and QUIC's stream priorities only order data *inside* the connection — the kernel/WiFi driver queue below is FIFO, so an unthrottled multi-MB clipboard transfer fills it and input packets behind it wait for the whole backlog to drain (bufferbloat, seen as RTT spikes for the duration of the transfer). monux therefore paces bulk transfers — adaptively by default: **40 Mbps**, raised to **160 Mbps** while the link is measured close and clean (see below), on both server and client. Pin a rate with `--bulk-throttle-mbps` (0 disables); large clipboard transfers take slightly longer at low rates (5 MB ≈ 1 s at 40 Mbps).

## Adaptive fidelity (proximity)

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

---

← Back to [wiki index](README.md) · [project README](../README.md)
