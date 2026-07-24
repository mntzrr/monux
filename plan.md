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

## Future / on hold

- **Protocol feature-negotiation** (prerequisite for downgrade): handshake connects
  at min(their, our) protocol instead of exact-match refusal; feature→version map
  in msgs/ gates each message on the negotiated version; degraded set is logged
  ("peer speaks v14: hostname, hotspot auto-join disabled"). Bootstrap: pairs with
  a pre-v15 peer keep exact-match refusal; negotiation starts at v15.
- **Item 5 (downgrade)** — blocked on the above. Then: `monux update --to
  <version|commit>` (scan Cargo.toml history / commit prefix; read target protocol
  from checked-out source; gate = target ≥ supported floor, server leads; `--force`),
  `--rollback` sugar via recorded previous version, update-pin file so daily
  auto-update never undoes a manual downgrade (plain `monux update` unpins), plain
  update resets detached HEAD to origin/master. Auto-update never downgrades.
- **Hotspot leftovers**: fix hostapd presence check (`hostapd -v` exits 1 → always
  "installs"; check /usr/bin/hostapd instead); `ensure_ap_interface` must verify
  the existing vif's type (a stale `managed` vif breaks hostapd beaconing) and
  delete+recreate on mismatch; optional ieee80211n/ac in hostapd.conf. User then
  re-runs `monux setup --hotspot` and tests client internet via NAT.
- **Awaiting user data**: phantom pause (watch for 'Control socket: pause
  requested'), clipboard wedge (capture `monux status` from both machines on
  recurrence), drag-lag (Link stats on repro).
