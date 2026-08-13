# Configuration

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

## History

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

---

← Back to [wiki index](README.md) · [project README](../README.md)
