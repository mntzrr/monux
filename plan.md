# monux v8.0.0 batch plan

Agreed 2026-07-24. Ships as **v8.0.0** (MAJOR: item 5 below bumps PROTOCOL_VERSION 14 → 15).
Execution order: Phase A (CLI, no behavior risk) → Phase D (config; rewrites the same
clap structs while fresh) → Phase B (interlocked: remembered servers + handshake
hostname + servers listing) → Phase C (mx alias, any point).
Rules: zero-warning `cargo build --release` + green `cargo test --release` before every
commit; commit style = multiple `-m` flags, no line wrap; user pushes and runs
`monux update` themselves.

## Phase A — CLI restructure + help rewrite (items 3, 4)

Target shape:

```
server · client · setup · update · status · gui {indicator,tray} · daemon {…} · system {uninstall}
```

- [x] Flatten `SystemCommands`: `setup`, `update`, `status` become first-level;
      `gui` group takes `indicator` + `tray`; `uninstall` stays as the sole member
      of `system` (deliberate friction against typos).
- [x] Merge `clients` into `status`: server-socket client table gains
      fingerprint-prefix + resolved-edge-direction columns; delete the `clients`
      command and `control::clients_cli`.
- [x] Drop `daemon status` (exact duplicate of first-level `status`).
- [x] Flag-scoped setup: no flags → everything (today's default); any flag →
      only that flag's actions. Elevation only when the requested steps need root
      (`--autostart` alone must not sudo re-exec). Move the ip-forward step from
      the base set into the `--hotspot` group (NAT dependency; useless otherwise).
- [x] `uninstall`: add a pre-flight confirmation prompt before touching anything
      (`--yes` for scripts); keep the existing config-purge prompt.
- [x] Update every `monux system …` string: printed instructions in setup.rs,
      update.rs, autoupdate.rs, uninstall.rs, doc comments, indicator_spawn.rs
      (spawns `gui indicator` now), README, install.sh.
- [x] Help rewrite: one-line `about` per subcommand; details in long help;
      man-page-style EXAMPLES section after the flags (`after_long_help`) with
      realistic commands on the new CLI; top-level getting-started block; trim
      wall-of-text doc comments (Indicator, hotspot) keeping real caveats.
- [x] Tests: fix parse tests (main.rs ~1499+); add `Cli::command().debug_assert()`.

## Phase B — discovery & connection identity (items 1, 6, 5-handshake)

### B1. Remembered servers (fixes mDNS across routers/subnets)

Root cause: mDNS (224.0.0.251:5353) is link-local multicast; routers don't forward
it. Same modem + different routers = different subnets → discovery fails; direct IP
works because the modem routes.

- [x] New `src/known_servers.rs`: `~/.config/monux/known_servers`, one record per
      line: `addr  fingerprint  hostname?  last-connected-unix`. Most-recent-first,
      dedup on addr, cap 5, atomic write (tmp+rename). Pure load/save/record fns
      + unit tests (roundtrip, dedup/move-to-front, cap).
- [x] Record on every successful connect in `client::run` after `set_connected`
      (client.rs ~141): addr + server fingerprint (from verifier) + hostname when
      known (mDNS name, or handshake name from B3) + now.
- [x] Startup when no `--host` (main.rs ~831): try remembered addresses first
      (most recent first), then mDNS. `--host` stays authoritative.
- [x] Reconnect loop (main.rs ~1426): replace "3 failures → re-run mDNS" with
      candidate cycling: remembered list → one mDNS attempt → start over; existing
      backoff and HEALTHY_SESSION reset unchanged.
- [x] Bound the QUIC handshake with ~3s timeout in client.rs `Connection::new` so
      cycling past stale addresses is quick.
- [x] Extend DISCOVERY_TIMEOUT_HINT: mDNS can't cross routers/subnets; a one-time
      `monux client <ip>` is remembered thereafter.
- [x] Connect-by-name / by-fingerprint: host arg resolution order: IP literal →
      remembered-store instance-name match (case-insensitive) → system resolution
      (today) → remembered-store fingerprint-prefix match. Every field printed by
      `monux servers` is then a valid connect target.
- [x] Auto-connect with multiple mDNS servers: prefer the remembered match if one
      appears; log the others + hint to `monux servers`.

### B2. Server hostname in handshake (protocol v15)

- [x] PROTOCOL_VERSION 14 → 15 (msgs/shared.rs).
- [x] After the version exchange on the events stream, a v15+ server sends its
      hostname (length-prefixed string); client reads it iff server ≥ v15, server
      sends iff client ≥ v15 (both sides know peer version already).
- [x] Client: feeds B1 records; approval prompt uses it on direct-IP connects
      (not just mDNS ones).

### B3. `monux servers` — display-only listing

- [x] Server advertises `fp` (full cert fingerprint) in mDNS TXT next to `pv`.
      Informational; old clients ignore unknown TXT props; no wire change.
- [x] discovery.rs: `discover_servers(timeout) -> Vec<DiscoveredServer>` collects
      ALL instances (name, addrs, port, pv, fp); singular `discover_server`
      reimplemented on top, behavior unchanged.
- [x] New first-level `monux servers`: union of mDNS instances + remembered file
      (marked "remembered, last connected X ago"). NEVER connects — no probes, no
      `--probe`. One clean line per server address: name, bare `ip:port`,
      fingerprint prefix, protocol, source. Footer: connect with
      `monux client <ip|name|fp-prefix>`, pre-approve with `--fingerprints`.

## Phase D — config file + `mx config` (item 7) — execute right after Phase A

The config file is persistent flag storage; `mx config` is its CLI.

- [x] `~/.config/monux/config.toml`, sections `[server]` / `[client]`, keys = flag
      long-names. Add toml/serde deps only if not already present (check Cargo.toml).
- [x] Config-capable flags (all server/client runtime args) become `Option<T>`
      without clap defaults; resolution in one place:
      explicit flag > config file > built-in default.
- [x] First-level `config` subcommand:
      `show` (effective values + source annotation (default|config file) + file path),
      `keys` (reference: each key with one-line help, expected-value syntax, default;
      `set <key>` with no value prints the same per-key card),
      `set <role.key> <value>` (validates with the flag's own parser before writing;
      atomic tmp+rename write), `unset <role.key>`,
      `edit` (opens config.toml in $EDITOR, fallback vi; validates on save,
      crontab-style re-edit offer on parse errors; atomic replace),
      `validate` (parse + value-check the file, report errors with line numbers,
      change nothing — guards files edited outside `mx config` and scripts);
      unknown key errors list valid keys.
- [x] Single key registry {key, section, expects, default, help, parser} drives
      show/keys/set/unset; a test maps every registry entry to a real clap flag
      so the registry can't drift from the CLI.
- [x] Staleness policy: daemon startup warns-and-ignores unknown keys (never
      fails to start); `validate` lists stale keys with did-you-mean + the exact
      `unset` cleanup lines; renames get an alias map honored for a deprecation
      window (startup warning names the replacement, next edit/set rewrites it).
- [x] New-key visibility: registry entries carry a `since` version; the daemon
      keeps ~/.config/monux/last-version and, on the first start of a new
      version, logs one line per key introduced since (then updates the file);
      `mx config keys` annotates entries with (new in vX.Y).
- [x] Daemons read their section at startup only; `set` prints
      "restart to apply: mx daemon restart" when a daemon is running. No live-reload.
- [x] `setup`-persisted system settings are NOT config — they stay machine state.
- [x] Tests: parse/serialize roundtrip, set/unset validation, precedence,
      unknown-key errors, show output.

## Phase C — `mx` alias (item 2)

- [x] `mx -> monux` symlink in `~/.local/bin`: created by install.sh and by the
      atomic-install staging in update.rs; removed by uninstall.rs ONLY if it's a
      symlink pointing at monux. Collision guard: existing non-monux `mx` → skip
      with warning.

## Phase G — review remediation (v9.1.1)

From the 2026-07-24 codebase review (8 scopes, ~50 findings). Fix tier 1 (HIGH+MEDIUM):

- [x] G1 approval.rs: move the 60s cert prompt OFF quinn's single endpoint driver
      (reject + dedicated prompt thread + retry-succeeds); fixes the flush().expect
      panic, the dead poisoned-lock reset, prompt_active wedging
- [x] G2 device/util.rs: log_event masks only half the key event (real code leaks
      to trace logs)
- [x] G3 single_instance.rs: O_NOFOLLOW on the /tmp lock open; bail on symlink
- [x] G4 control.rs: control-socket /tmp fallback dir: verify uid ownership,
      hard-fail chmod
- [x] G5 setup.rs: write_unit_file root write follows symlinks (O_NOFOLLOW/tmp+rename)
- [x] G6 setup.rs: run_cmd error includes full argv — redact after wifi-sec.psk
- [x] G7 discovery.rs: deadline expiry bails even with found servers — break instead
- [x] G8 rotation/edge: blocking getaddrinfo on the input loop (edge hostname
      resolution on add/remove/log paths) — off-loop + cache
- [x] G9 update.rs: no cross-process update lock — flock around run()
- [x] G10 clipboard: reader never recreated after compositor restart
- [x] G11 convert.rs: zip send-side uncompressed-size budget (timeout detaches, zip
      keeps running)
- [x] G12 uninstall.rs: autostart units never disabled/removed
- [x] G13 uninstall.rs: removable_usr_local removes ANY symlink — resolve+compare
- [x] G14 setup.rs: hotspot_live_subnet matches first 10.42.* on any iface; aborts
      retry on cmd error
- [x] G15 setup.rs: stale hotspot join profile accepted as success — update+reconnect

## Phase H — review remediation, LOW tier — SHIPPED in v9.1.2

All 24 items landed: recv_version size cap; dedicated bulk-handshake buffers;
pin cleared only after Installed; is_newer_remote ancestry check; known_servers
hostname sanitization; v_clipboard_kb ceiling; graceful-close RemoveClient;
fingerprint-slot race eliminated (peer_identity); stale edge_info_sent; clipboard
temp-dir sweep cross-process; hostapd.conf 0600 from first open; uninstall root
HOME guard; pause vs silence/recovery switches; dead clipboard channel degrades;
indicator_spawn races; wedged-compositor gate; serve.rs Arc<[u8]> cache;
IGNORED_MIME_TYPE early return; uri-list parsing; event Display allocs;
motion-history scratch; degraded-link transitions only; no .local.local lookup;
neutral accept() warn labels.

## Phase I — per-monitor edge-map — SHIPPED in v9.2.0

`<direction>[@<monitor>]=<target>`: a monitor qualifier pins the zone to the
matching output(s), overriding the unqualified entry there; unqualified keeps
the all-exposed-segments behavior. The qualifier matches the output name
(default) or, when the compositor reports them (Hyprland), the serial, model,
or description; name-only compositors degrade silently. Unknown qualifiers and
multi-output matches warn (on change only); the layout log prints identifiers.

## Phase J — config history (inline `# was:` comments) — v9.3.0

- [x] Switch config.rs raw-doc writer to toml_edit (comments/formatting survive
      set/unset/edit)
- [x] History entries `# was: <TOML> @ <timestamp>` above keys, newest first,
      cap 5/key; strict-format parsing (human comments never touched)
- [x] set: push current onto stack (same-value = no-op, no write); unset: bank
      value as was-comment + remove key; edit: diff-inject was for changed/removed
- [x] `mx config history [key]`: stack per key / full timeline (revert preview)
- [x] `mx config revert <key> [--to <timestamp>]`: pop previous value, bank
      current (undoable undo); revalidates; recreates unset keys
- [x] Docs: README config section, subcommand help/examples, module docs

## Phase K — scrap the hotspot feature — v10.0.0

The feature is structurally flaky (single-radio client+AP at the mercy of
NM/driver/VPN/channel matrix). Remove it entirely:

- [x] msgs: keep the HotspotInfo variant (same index/payload), mark deprecated —
      never send, ignore on receipt. Wire stays v16, no protocol bump.
- [x] setup.rs: remove all hotspot code (host/join/remove, hostapd/dnsmasq/unit
      writers, NAT, ip-forward, Mullvad workaround, vif mgmt, psk, flags +
      elevation/scoping branches)
- [x] server.rs: remove HotspotInfo advertisement, credential probe, lifecycle
      start/stop hooks
- [x] client.rs: remove HotspotInfo handler, provision_hotspot (NM auto-join),
      --no-auto-hotspot
- [x] config.rs: drop client.no-auto-hotspot registry key (staleness policy
      covers existing configs)
- [x] uninstall.rs: KEEPS the teardown (unit, /etc/monux, NAT, vif, NM profile);
      needed constants move in from setup.rs
- [x] Docs: README hotspot sections, help text, config keys/help
- [x] Validation: zero-warning build, green tests, `grep -ri hotspot` returns
      only uninstall teardown + deprecated variant + history files
- [x] Report includes the manual teardown commands for live installs
      (disable monux-hotspot unit, delete monux-direct profile)

## Future / on hold

- **Protocol feature-negotiation** — SHIPPED in v9.0.0 (protocol v16): v16+ peers
  connect at min(their, our); pre-negotiation pairs keep exact-match refusal; a
  newer client clamps once to a >= v15 server; the feature map + degraded-set
  logging live in msgs/shared.rs; the update gate keys off pair_works().
- **Item 5 (downgrade)** — SHIPPED in v9.1.0: `monux update --to <version|commit>`
  (Cargo.toml-history scan, commit-prefix fallback), `--rollback` (records the
  replaced build per install), the update-pin (auto-update skips, plain update
  unpins), detached-HEAD reattach, direction-aware pair_works gate.
- **Hotspot leftovers**: fix hostapd presence check (`hostapd -v` exits 1 → always
  "installs"; check /usr/bin/hostapd instead); `ensure_ap_interface` must verify
  the existing vif's type (a stale `managed` vif breaks hostapd beaconing) and
  delete+recreate on mismatch; optional ieee80211n/ac in hostapd.conf. User then
  re-runs `monux setup --hotspot` and tests client internet via NAT.
- **Awaiting user data**: phantom pause (watch for 'Control socket: pause
  requested'), clipboard wedge (capture `monux status` from both machines on
  recurrence), drag-lag (Link stats on repro).
