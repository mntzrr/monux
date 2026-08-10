//! Persistent flag storage: `~/.config/monux/config.toml` and the
//! `mx config` subcommand that manages it.
//!
//! The file stores values for the `server` and `client` daemons' flags,
//! keyed by the flag long-names under `[server]` / `[client]` sections
//! (repeatable flags are TOML arrays). Precedence, resolved once at daemon
//! startup in main.rs (`ServerArgs::resolve` / `ClientArgs::resolve`):
//! explicit CLI flag > config file > built-in default.
//!
//! The file is advisory: daemons warn-and-continue on a malformed file,
//! invalid values, and unknown keys (a newer/older version may have written
//! them) — a config problem must never prevent a daemon from starting.
//! `mx config validate` is the strict checker for hand-edited files.
//!
//! A single static registry (REGISTRY) describes every config-capable key
//! and drives `show`/`keys`/`set`/`unset`/`validate`; a test in main.rs maps
//! every registry entry to a real clap flag so the two can't drift apart.
//! Renamed keys are honored through ALIASES for a deprecation window.
//!
//! ## History
//!
//! Every mutation through `mx config` (set/unset/edit — and revert itself)
//! preserves the replaced value as a comment directly above the key (or in
//! the was-block an `unset` leaves in its place), newest first, at most
//! HISTORY_CAP entries per key:
//!
//! ```toml
//! [server]
//! # was: "leftshift,leftalt,r" @ 2026-07-25T01:12:03Z
//! shortcut = "leftshift,leftalt,q"
//! ```
//!
//! Values are rendered as TOML so they re-validate on revert; timestamps
//! are UTC, RFC3339 seconds. A comment is treated as history ONLY when it
//! matches the full strict shape `# was: <valid-TOML-value> @ <timestamp>`
//! AND sits in a managed position (directly above a managed key, or in a
//! was-block left by `unset`): human comments — even ones starting with
//! `# was:` — that don't fully parse are never listed, moved, or pruned.
//! The mutation path edits through toml_edit so all of this (and any other
//! comment or formatting) survives; the daemon LOAD path above stays on
//! plain toml, which simply ignores comments. `mx config history` shows the
//! stacks; `mx config revert` restores an entry and banks the current
//! value, so a revert is itself undoable. A was-block left by `unset`
//! carries no key name, so it is attributed to an absent key by validator
//! fit (first match in file order) — exact for a single unset key; revert
//! one key at a time to keep it exact.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, ErrorKind, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use tracing::{error, info, warn};

use crate::single_instance;

/// The config file's name inside the monux config dir (~/.config/monux).
const CONFIG_FILE_NAME: &str = "config.toml";

/// The version every key of the first config-capable release carries;
/// `keys` annotates entries whose `since` differs with "(new in vX.Y)".
const BASELINE_SINCE: &str = "7.4.0";

/// Records the last monux version that ran a daemon, so the first start of a
/// newer version can announce the config keys it introduced.
const LAST_VERSION_FILE: &str = "last-version";

// Built-in defaults, shared by the registry's default_display and the
// resolution at the flag use sites in main.rs.
pub const DEFAULT_SHORTCUT: &str = "leftshift,leftalt,r";
pub const DEFAULT_SHORTCUT_PREV: &str = "leftalt,p";
pub const DEFAULT_PAUSE_SHORTCUT: &str = "";
pub const DEFAULT_LISTEN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
pub const DEFAULT_PORT: u16 = 1213;
pub const DEFAULT_MAX_CLIPBOARD_SIZE_KB: u64 = 5120;
/// Largest accepted max-clipboard-size-kb value: the daemons convert KB to
/// bytes with a checked *1024 (see main.rs), so the validator caps KB at the
/// value whose conversion can never overflow — a config problem must never
/// prevent daemon startup.
pub const MAX_CLIPBOARD_SIZE_KB: u64 = u64::MAX / 1024;
pub const DEFAULT_EDGE_DWELL_MS: u64 = 250;
pub const DEFAULT_INPUT_SCALE: f64 = 1.0;

/// Which daemon section of the file a key belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Server,
    Client,
}

impl Section {
    pub fn as_str(&self) -> &'static str {
        match self {
            Section::Server => "server",
            Section::Client => "client",
        }
    }
}

/// A key's value shape: TOML scalar types, or an array of strings for
/// repeatable flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Bool,
    Int,
    Float,
    Str,
    StrArray,
}

/// One config-capable flag.
#[derive(Debug)]
pub struct KeySpec {
    /// Full key name: "server.motion-hz".
    pub key: &'static str,
    pub section: Section,
    /// The flag long-name (the TOML key inside the section).
    pub flag: &'static str,
    /// Value-syntax hint shown by `keys`/`set` and validation errors.
    pub expects: &'static str,
    /// How the built-in default renders in `show`/`keys`; for keys with a
    /// semantic "unset" (adaptive modes, opt-ins) this is a description.
    pub default_display: &'static str,
    /// One-line description (also used in the new-keys daemon announcement).
    pub help: &'static str,
    pub kind: Kind,
    /// Validates the flag-syntax string form of a value (one string for
    /// scalars, the whole array for repeatable keys).
    pub validate: fn(&[&str]) -> Result<(), String>,
    /// First version carrying the key; drives the new-keys announcement.
    pub since: &'static str,
}

/// Every config-capable flag of `monux server` / `monux client` (everything
/// except the client's positional host and clap's --help/--version).
pub static REGISTRY: &[KeySpec] = &[
    // [server]
    KeySpec {
        key: "server.shortcut",
        section: Section::Server,
        flag: "shortcut",
        expects: "key1,key2,key3",
        default_display: DEFAULT_SHORTCUT,
        help: "keyboard chord switching input to the next client in the rotation",
        kind: Kind::Str,
        validate: v_chord,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.shortcut-prev",
        section: Section::Server,
        flag: "shortcut-prev",
        expects: "key1,key2,key3",
        default_display: DEFAULT_SHORTCUT_PREV,
        help: "keyboard chord switching input to the previous client in the rotation",
        kind: Kind::Str,
        validate: v_chord,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.shortcut-goto",
        section: Section::Server,
        flag: "shortcut-goto",
        expects: "key1,key2,key3=[fingerprint-prefix]",
        default_display: "none",
        help: "chord switching directly to a client by fingerprint prefix ('' = the server)",
        kind: Kind::StrArray,
        validate: v_goto,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.pause-shortcut",
        section: Section::Server,
        flag: "pause-shortcut",
        expects: "key1,key2,key3 (empty disables)",
        default_display: "\"\" (disabled)",
        help: "chord pausing/resuming input handling: ungrabs ALL devices while paused",
        kind: Kind::Str,
        validate: v_chord_or_empty,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.device",
        section: Section::Server,
        flag: "device",
        expects: "device-name-pattern (regex)",
        default_display: "all devices",
        help: "substring/regex selecting which input devices to monitor",
        kind: Kind::StrArray,
        validate: v_regex,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.listen",
        section: Section::Server,
        flag: "listen",
        expects: "ip",
        default_display: "0.0.0.0",
        help: "server listen IP",
        kind: Kind::Str,
        validate: v_ip,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.port",
        section: Section::Server,
        flag: "port",
        expects: "integer 1-65535",
        default_display: "1213",
        help: "server port (the mDNS advertisement must match it)",
        kind: Kind::Int,
        validate: v_port,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.fingerprint",
        section: Section::Server,
        flag: "fingerprint",
        expects: "certificate fingerprint (hex, ':' allowed)",
        default_display: "none",
        help: "client certificate fingerprint pre-approved without prompting",
        kind: Kind::StrArray,
        validate: v_fingerprints,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.exit-secs",
        section: Section::Server,
        flag: "exit-secs",
        expects: "integer (seconds)",
        default_display: "none (run until stopped)",
        help: "exit the server automatically after this many seconds (config testing)",
        kind: Kind::Int,
        validate: v_exit_secs,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.max-clipboard-size-kb",
        section: Section::Server,
        flag: "max-clipboard-size-kb",
        expects: "integer 0-18014398509481983 (KB)",
        default_display: "5120",
        help: "maximum clipboard transfer size in KB",
        kind: Kind::Int,
        validate: v_clipboard_kb,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.www",
        section: Section::Server,
        flag: "www",
        expects: "true|false",
        default_display: "false",
        help: "conservative tuning for the public internet (default: low-latency LAN tuning)",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.motion-hz",
        section: Section::Server,
        flag: "motion-hz",
        expects: "integer updates/s (0 = forward every event)",
        default_display: "adaptive (250, raised to 500 on a close clean link)",
        help: "rate for forwarding pointer motion; deltas coalesce losslessly between updates",
        kind: Kind::Int,
        validate: v_motion_hz,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.bulk-throttle-mbps",
        section: Section::Server,
        flag: "bulk-throttle-mbps",
        expects: "number (Mbps; 0 = no pacing)",
        default_display: "adaptive (40, raised to 160 on a close clean link)",
        help: "pacing for clipboard/bulk transfers, keeping input latency off the WiFi queue",
        kind: Kind::Float,
        validate: v_bulk_throttle,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.edge-map",
        section: Section::Server,
        flag: "edge-map",
        expects: "direction[@monitor]=target (target: fingerprint-prefix|hostname|auto; monitor: output name, serial, model, or description)",
        default_display: "none (edge switching disabled)",
        help: "switch input when the cursor dwells on a mapped screen edge (Hyprland)",
        kind: Kind::StrArray,
        validate: v_edge_map_server,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.edge-dwell-ms",
        section: Section::Server,
        flag: "edge-dwell-ms",
        expects: "integer (ms)",
        default_display: "250",
        help: "how long the cursor must dwell on a mapped edge before the switch fires",
        kind: Kind::Int,
        validate: v_edge_dwell,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.no-auto-update",
        section: Section::Server,
        flag: "no-auto-update",
        expects: "true|false",
        default_display: "false",
        help: "disable the daily background auto-update",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "server.auto-install",
        section: Section::Server,
        flag: "auto-install",
        expects: "true|false",
        default_display: "false (report updates, install on request)",
        help: "install background updates automatically instead of only reporting them",
        kind: Kind::Bool,
        validate: v_bool,
        since: "13.0.0",
    },
    KeySpec {
        key: "server.no-indicator",
        section: Section::Server,
        flag: "no-indicator",
        expects: "true|false",
        default_display: "false",
        help: "do not auto-spawn the tray indicator with the daemon",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    // [client]
    KeySpec {
        key: "client.port",
        section: Section::Client,
        flag: "port",
        expects: "integer 1-65535",
        default_display: "1213",
        help: "server port (ignored when the server is auto-discovered via mDNS)",
        kind: Kind::Int,
        validate: v_port,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.fingerprint",
        section: Section::Client,
        flag: "fingerprint",
        expects: "certificate fingerprint (hex, ':' allowed)",
        default_display: "none",
        help: "server certificate fingerprint pre-approved without prompting",
        kind: Kind::StrArray,
        validate: v_fingerprints,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.max-clipboard-size-kb",
        section: Section::Client,
        flag: "max-clipboard-size-kb",
        expects: "integer 0-18014398509481983 (KB)",
        default_display: "5120",
        help: "maximum clipboard transfer size in KB",
        kind: Kind::Int,
        validate: v_clipboard_kb,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.www",
        section: Section::Client,
        flag: "www",
        expects: "true|false",
        default_display: "false",
        help: "conservative tuning for the public internet (default: low-latency LAN tuning)",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.mouse-scale",
        section: Section::Client,
        flag: "mouse-scale",
        expects: "number 0.05-20",
        default_display: "1.0",
        help: "multiplier on pointer motion deltas (DPI/sensitivity compensation)",
        kind: Kind::Float,
        validate: v_scale,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.scroll-scale",
        section: Section::Client,
        flag: "scroll-scale",
        expects: "number 0.05-20",
        default_display: "1.0",
        help: "multiplier on scroll wheel deltas (including hi-res wheel axes)",
        kind: Kind::Float,
        validate: v_scale,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.bulk-throttle-mbps",
        section: Section::Client,
        flag: "bulk-throttle-mbps",
        expects: "number (Mbps; 0 = no pacing)",
        default_display: "adaptive (40, raised to 160 on a close clean link)",
        help: "pacing for clipboard/bulk transfers, keeping input latency off the WiFi queue",
        kind: Kind::Float,
        validate: v_bulk_throttle,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.edge-map",
        section: Section::Client,
        flag: "edge-map",
        expects: "direction[@monitor]=auto (monitor: output name, serial, model, or description)",
        default_display: "none (inferred from the server's map)",
        help: "edge-dwell switch BACK to the server while this client has input (Hyprland)",
        kind: Kind::StrArray,
        validate: v_edge_map_client,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.edge-dwell-ms",
        section: Section::Client,
        flag: "edge-dwell-ms",
        expects: "integer (ms)",
        default_display: "250",
        help: "how long the cursor must dwell on a mapped edge before the return fires",
        kind: Kind::Int,
        validate: v_edge_dwell,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.no-auto-update",
        section: Section::Client,
        flag: "no-auto-update",
        expects: "true|false",
        default_display: "false",
        help: "disable the daily background auto-update",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.auto-install",
        section: Section::Client,
        flag: "auto-install",
        expects: "true|false",
        default_display: "false (report updates, install on request)",
        help: "install background updates automatically instead of only reporting them",
        kind: Kind::Bool,
        validate: v_bool,
        since: "13.0.0",
    },
    KeySpec {
        key: "client.no-indicator",
        section: Section::Client,
        flag: "no-indicator",
        expects: "true|false",
        default_display: "false",
        help: "do not auto-spawn the tray indicator with the daemon",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
];

/// Renamed keys honored for a deprecation window: (old name, new name).
/// The old name reads as the new one with a deprecation warning.
static ALIASES: &[(&str, &str)] = &[];

/// Looks up a full key ("server.port") in the registry.
pub fn find(key: &str) -> Option<&'static KeySpec> {
    REGISTRY.iter().find(|s| s.key == key)
}

/// The canonical name for a renamed key, when `key` is an old alias.
fn alias_target(key: &str) -> Option<&'static str> {
    ALIASES
        .iter()
        .find(|(old, _)| *old == key)
        .map(|(_, new)| *new)
}

/// The config file's path inside the monux config dir.
pub fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(CONFIG_FILE_NAME)
}

/// A parsed config file: the validated known values plus an itemized account
/// of everything that was wrong with it, so daemons can warn-and-continue
/// and `mx config validate` can report. Never fails on unknown keys.
#[derive(Default, Debug)]
pub struct File {
    /// Validated values keyed by full registry key ("server.port").
    values: BTreeMap<&'static str, toml::Value>,
    /// Keys present in the file but not in the registry.
    pub unknown: Vec<String>,
    /// Renamed keys honored via ALIASES: (old name, canonical name).
    pub aliased: Vec<(String, &'static str)>,
    /// Known keys whose values failed type/validator checks: (key, reason).
    pub invalid: Vec<(String, String)>,
}

impl File {
    /// Parses config file contents. Malformed TOML is the only hard error.
    pub fn parse(text: &str) -> Result<File> {
        let doc: toml::Table =
            toml::from_str(text).map_err(|e| anyhow!("{}", e))?;
        let mut file = File::default();
        for (section_name, section_value) in &doc {
            let Some(table) = section_value.as_table() else {
                file.unknown.push(section_name.clone());
                continue;
            };
            for (flag, value) in table {
                let raw_key = format!("{}.{}", section_name, flag);
                // Honor rename aliases: the old name reads as the new one.
                let canonical = alias_target(&raw_key).unwrap_or(raw_key.as_str());
                let Some(spec) = find(canonical) else {
                    file.unknown.push(raw_key);
                    continue;
                };
                if canonical != raw_key {
                    file.aliased.push((raw_key, spec.key));
                }
                match check_value(spec, value) {
                    Ok(value) => {
                        file.values.insert(spec.key, value);
                    }
                    Err(reason) => file.invalid.push((spec.key.to_string(), reason)),
                }
            }
        }
        Ok(file)
    }

    /// The stored value for a full registry key, if present and valid.
    pub fn get(&self, key: &str) -> Option<&toml::Value> {
        self.values.get(key)
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.values.get(key)?.as_bool()
    }

    /// An Int-kind value as u16/u32/u64/...; None on overflow (the loader's
    /// validation already bounded it, so this can't fail in practice).
    pub fn get_int<T: TryFrom<i64>>(&self, key: &str) -> Option<T> {
        T::try_from(self.values.get(key)?.as_integer()?).ok()
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.values.get(key)?.as_float()
    }

    pub fn get_str(&self, key: &str) -> Option<String> {
        self.values.get(key)?.as_str().map(str::to_string)
    }

    pub fn get_str_vec(&self, key: &str) -> Option<Vec<String>> {
        Some(
            self.values
                .get(key)?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        )
    }

    pub fn get_ip(&self, key: &str) -> Option<IpAddr> {
        self.get_str(key)?.parse().ok()
    }

    /// A StrArray of device-name patterns as compiled regexes. The loader
    /// validated every pattern, so a non-compiling one is just dropped.
    pub fn get_regex_vec(&self, key: &str) -> Option<Vec<Regex>> {
        Some(
            self.get_str_vec(key)?
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
        )
    }
}

/// Loads and parses the config file; a missing file is an empty config.
pub fn load(path: &Path) -> Result<File> {
    match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(File::default()),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
        Ok(text) => File::parse(&text).with_context(|| format!("Failed to parse {}", path.display())),
    }
}

/// Loads the config for a starting daemon. The file is advisory: a malformed
/// file, bad values, and unknown keys degrade to log warnings and built-in
/// defaults — they must never prevent a daemon from starting. Also announces
/// the config keys introduced since the last recorded version.
pub fn load_for_daemon(config_dir: &Path) -> File {
    let path = path(config_dir);
    let file = match load(&path) {
        Ok(file) => file,
        Err(e) => {
            error!(
                "Ignoring config file {}: {:#} — continuing with defaults and flags (see 'mx config validate')",
                path.display(),
                e
            );
            File::default()
        }
    };
    for key in &file.unknown {
        warn!(
            "ignoring unknown config key '{}' (removed or renamed?); run 'mx config validate'",
            key
        );
    }
    for (old, new) in &file.aliased {
        warn!(
            "config key '{}' was renamed to '{}'; the old name still works for now, please update {}",
            old,
            new,
            path.display()
        );
    }
    for (key, reason) in &file.invalid {
        warn!(
            "ignoring invalid value for config key '{}': {} (in {})",
            key,
            reason,
            path.display()
        );
    }
    announce_new_keys(config_dir, env!("CARGO_PKG_VERSION"));
    file
}

/// Type-checks a TOML value against the key's kind and runs the key's
/// validator, normalizing integers given for float keys (TOML `40` for a
/// Mbps value is the integer 40, not a type error).
fn check_value(spec: &KeySpec, value: &toml::Value) -> std::result::Result<toml::Value, String> {
    let normalized = match spec.kind {
        Kind::Bool => value.as_bool().map(toml::Value::from),
        Kind::Int => value.as_integer().map(toml::Value::from),
        Kind::Float => value
            .as_float()
            .or_else(|| value.as_integer().map(|i| i as f64))
            .map(toml::Value::from),
        Kind::Str => value.as_str().map(|s| toml::Value::from(s.to_string())),
        Kind::StrArray => value.as_array().and_then(|items| {
            items
                .iter()
                .map(|i| i.as_str().map(|s| toml::Value::from(s.to_string())))
                .collect::<Option<Vec<_>>>()
                .map(toml::Value::Array)
        }),
    };
    let Some(normalized) = normalized else {
        return Err(format!("expected {}", spec.expects));
    };
    let strings = value_strings(&normalized).unwrap_or_default();
    let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
    (spec.validate)(&refs)?;
    Ok(normalized)
}

/// Renders a (normalized) TOML value as the flag-syntax strings the
/// validators expect.
fn value_strings(value: &toml::Value) -> Option<Vec<String>> {
    Some(match value {
        toml::Value::Boolean(b) => vec![b.to_string()],
        toml::Value::Integer(i) => vec![i.to_string()],
        toml::Value::Float(f) => vec![f.to_string()],
        toml::Value::String(s) => vec![s.clone()],
        toml::Value::Array(items) => items
            .iter()
            .map(|i| i.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    })
}

/// Reads the file as an editable TOML document, preserving comments,
/// formatting, and the unknown keys/sections `set`/`unset` don't manage.
/// A missing file is an empty document.
fn read_doc(path: &Path) -> Result<toml_edit::DocumentMut> {
    match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(toml_edit::DocumentMut::new()),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
        Ok(text) => text.parse::<toml_edit::DocumentMut>().with_context(|| {
            format!(
                "{} is not valid TOML; fix it with 'mx config edit' or check it with 'mx config validate'",
                path.display()
            )
        }),
    }
}

// --- History (# was: comments) ----------------------------------------------

/// Maximum history entries kept per key; the oldest falls off.
const HISTORY_CAP: usize = 5;

/// Every history entry is a comment of exactly this shape, directly above
/// the key it belongs to (or in the was-block an `unset` left behind):
/// `# was: <TOML value> @ <RFC3339-seconds UTC timestamp>`.
const WAS_PREFIX: &str = "# was: ";

/// One parsed `# was:` history line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WasEntry {
    /// The previous value, rendered as TOML (so it re-validates on revert).
    value: String,
    /// RFC3339-seconds UTC timestamp (YYYY-MM-DDTHH:MM:SSZ).
    timestamp: String,
}

impl WasEntry {
    fn render(&self) -> String {
        format!("{}{} @ {}\n", WAS_PREFIX, self.value, self.timestamp)
    }
}

/// Parses a comment line as a history entry. The shape is strict: exactly
/// `# was: <value> @ <timestamp>` at column 0, a plausible timestamp, and a
/// value that parses as TOML. Anything less is a human comment and is never
/// treated as history.
fn parse_was_line(line: &str) -> Option<WasEntry> {
    let rest = line.strip_prefix(WAS_PREFIX)?;
    let (value, timestamp) = rest.rsplit_once(" @ ")?;
    if !valid_timestamp(timestamp) {
        return None;
    }
    value.parse::<toml_edit::Value>().ok()?;
    Some(WasEntry {
        value: value.to_string(),
        timestamp: timestamp.to_string(),
    })
}

/// Exactly YYYY-MM-DDTHH:MM:SSZ with plausible field ranges.
fn valid_timestamp(ts: &str) -> bool {
    let b = ts.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }
    let field = |from: usize, to: usize| -> Option<u32> {
        let s = &ts[from..to];
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (Some(_year), Some(month), Some(day), Some(hour), Some(min), Some(sec)) = (
        field(0, 4),
        field(5, 7),
        field(8, 10),
        field(11, 13),
        field(14, 16),
        field(17, 19),
    ) else {
        return false;
    };
    (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && min <= 59 && sec <= 59
}

/// The current UTC time as an RFC3339-seconds timestamp. No clock crate in
/// the dependency tree: days→civil date via Howard Hinnant's algorithm.
fn now_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_timestamp(secs)
}

fn format_timestamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since the Unix epoch → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The contiguous run of strict was-lines directly at the bottom of `prefix`
/// — i.e. directly above the key the prefix belongs to — is that key's
/// was-stack, newest first. Returns (head, stack, indent): the head is user
/// content above the stack and is never touched, and the indent is the key's
/// own leading whitespace. The indent sits *below* the stack in the prefix,
/// so it is neither head nor stack: it is held out here and re-appended by
/// `render_stack_block`, which is what keeps an indented key indented.
fn split_bottom_stack(prefix: &str) -> (&str, Vec<WasEntry>, &str) {
    let mut segs: Vec<&str> = prefix.split_inclusive('\n').collect();
    // split_inclusive only ever leaves the last segment without a newline, so
    // there is at most one such segment to take.
    let indent = match segs.last() {
        Some(s) if !s.contains('\n') && s.trim().is_empty() => segs.pop().expect("just matched"),
        _ => "",
    };
    let mut head_end = prefix.len() - indent.len();
    let mut stack = vec![];
    while let Some(seg) = segs.last() {
        let line = seg.strip_suffix('\n').unwrap_or(seg);
        match parse_was_line(line) {
            Some(entry) => {
                stack.push(entry);
                head_end -= seg.len();
                segs.pop();
            }
            None => break,
        }
    }
    stack.reverse(); // file order is newest first
    (&prefix[..head_end], stack, indent)
}

/// Every maximal run of strict was-lines in `text`, as (start, end, entries)
/// byte ranges in file order.
fn scan_runs(text: &str) -> Vec<(usize, usize, Vec<WasEntry>)> {
    let mut runs = vec![];
    let mut current: Option<(usize, usize, Vec<WasEntry>)> = None;
    let mut offset = 0;
    for seg in text.split_inclusive('\n') {
        let line = seg.strip_suffix('\n').unwrap_or(seg);
        match parse_was_line(line) {
            Some(entry) => match &mut current {
                Some((_, end, entries)) => {
                    *end = offset + seg.len();
                    entries.push(entry);
                }
                None => current = Some((offset, offset + seg.len(), vec![entry])),
            },
            None => {
                if let Some(run) = current.take() {
                    runs.push(run);
                }
            }
        }
        offset += seg.len();
    }
    if let Some(run) = current.take() {
        runs.push(run);
    }
    runs
}

/// The strict was-runs in a key's prefix that are NOT the key's own stack
/// (not directly above the key line): orphan blocks left by `unset`. For
/// unmanaged keys even the bottom run counts — "directly above a managed
/// key" is the managed position.
fn orphan_runs_in(prefix: &str, managed: bool) -> Vec<(usize, usize, Vec<WasEntry>)> {
    let mut runs = scan_runs(prefix);
    if !managed {
        return runs;
    }
    if let Some(last) = runs.last() {
        // The bottom run is the key's stack only when nothing (not even a
        // blank line) sits between it and the key line.
        let after = &prefix[last.1..];
        if !after.contains('\n') && after.trim().is_empty() {
            runs.pop();
        }
    }
    runs
}

/// Pushes `entry` onto the was-stack at the bottom of `prefix` (newest
/// first, capped at HISTORY_CAP — the oldest falls off) and returns the new
/// prefix. The user content above the stack is preserved verbatim.
fn push_stack(prefix: &str, entry: WasEntry) -> String {
    let (head, mut stack, indent) = split_bottom_stack(prefix);
    stack.insert(0, entry);
    stack.truncate(HISTORY_CAP);
    render_stack_block(head, &stack, indent)
}

/// Rebuilds a prefix from user content + a was-stack + the key's own indent.
/// A was-line is history only at column 0 (see `parse_was_line`), so the
/// stack is never indented; the indent goes back on the last line, where the
/// key follows it.
fn render_stack_block(head: &str, stack: &[WasEntry], indent: &str) -> String {
    let mut out = String::from(head);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for entry in stack {
        out.push_str(&entry.render());
    }
    out.push_str(indent);
    out
}

/// Where an orphan was-block (left by `unset`) is stored.
#[derive(Debug)]
enum OrphanHolder {
    /// In the prefix of the key `flag` of the section (not directly above
    /// it).
    KeyPrefix(&'static str, String),
    /// In the header decor of the following section.
    NextHeader(String),
    /// In the document trailing (the section is the last one).
    DocTrailing,
}

/// An orphan was-block and where to find it.
#[derive(Debug)]
struct Orphan {
    entries: Vec<WasEntry>,
    holder: OrphanHolder,
    /// Index among the strict runs in the holder's text.
    run_index: usize,
}

/// The comment prefix of a table key.
fn key_prefix<'a>(table: &'a toml_edit::Table, flag: &str) -> &'a str {
    table
        .get_key_value(flag)
        .and_then(|(key, _)| key.leaf_decor().prefix())
        .and_then(|p| p.as_str())
        .unwrap_or("")
}

/// All orphan was-blocks of a section, in file order: strict was-runs in a
/// managed position that don't sit directly above a managed key — above a
/// following key's own comments/stack, in the next section's header decor,
/// or in the document trailing for the last section.
fn gather_orphans(doc: &toml_edit::DocumentMut, section: &'static str) -> Vec<Orphan> {
    let mut out = vec![];
    if let Some(table) = doc.get(section).and_then(|i| i.as_table()) {
        for (flag, _) in table.iter() {
            let prefix = key_prefix(table, flag);
            let managed = find(&format!("{}.{}", section, flag)).is_some();
            for (run_index, (_, _, entries)) in orphan_runs_in(prefix, managed).into_iter().enumerate() {
                out.push(Orphan {
                    entries,
                    holder: OrphanHolder::KeyPrefix(section, flag.to_string()),
                    run_index,
                });
            }
        }
    }
    // The section tail: the following section's header decor, or the
    // document trailing when this is the last section.
    let sections: Vec<&str> = doc.iter().map(|(name, _)| name).collect();
    match sections.iter().position(|name| *name == section) {
        Some(i) if i + 1 < sections.len() => {
            let next = sections[i + 1];
            if let Some(table) = doc.get(next).and_then(|i| i.as_table()) {
                let prefix = table
                    .decor()
                    .prefix()
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                for (run_index, (_, _, entries)) in scan_runs(prefix).into_iter().enumerate() {
                    out.push(Orphan {
                        entries,
                        holder: OrphanHolder::NextHeader(next.to_string()),
                        run_index,
                    });
                }
            }
        }
        Some(_) => {
            let trailing = doc.trailing().as_str().unwrap_or("");
            for (run_index, (_, _, entries)) in scan_runs(trailing).into_iter().enumerate() {
                out.push(Orphan {
                    entries,
                    holder: OrphanHolder::DocTrailing,
                    run_index,
                });
            }
        }
        None => {}
    }
    out
}

/// Whether every entry of an orphan block passes the key's validator.
fn orphan_fits(orphan: &Orphan, spec: &KeySpec) -> bool {
    orphan.entries.iter().all(|e| {
        e.value
            .parse::<toml_edit::Value>()
            .ok()
            .and_then(|v| te_to_model(&v))
            .and_then(|m| check_value(spec, &m).ok())
            .is_some()
    })
}

/// The orphan block attributed to an absent managed key: orphan blocks
/// whose entries all pass the key's validator, the first in file order —
/// exact for a single unset key. With several unset keys of compatible
/// value shapes the match is best-effort (the file order usually keeps the
/// original key order); unset/revert one key at a time to keep it exact.
fn find_orphan(doc: &toml_edit::DocumentMut, spec: &KeySpec) -> Option<Orphan> {
    gather_orphans(doc, spec.section.as_str())
        .into_iter()
        .find(|o| orphan_fits(o, spec))
}

/// The byte range of the run `run_index` together with the comment lines
/// directly above it (the block an `unset` left) and one blank separator
/// line after it.
fn run_block_range(text: &str, run_index: usize) -> Option<(usize, usize)> {
    let (mut start, mut end, _) = *scan_runs(text).get(run_index)?;
    while start > 0 {
        let prev_end = start - 1; // the '\n' ending the previous line
        let prev_start = text[..prev_end].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let prev = &text[prev_start..prev_end];
        // The unset key's own comments travel with the block; another
        // was-run's line or a non-comment does not.
        if prev.starts_with('#') && parse_was_line(prev).is_none() {
            start = prev_start;
        } else {
            break;
        }
    }
    if text[end..].starts_with('\n') {
        end += 1;
    }
    Some((start, end))
}

/// Removes the block `run_index` from `text`, returning (text-without,
/// block). The block is normalized to end with a single newline.
fn excise_run(text: &str, run_index: usize) -> (String, String) {
    let Some((start, end)) = run_block_range(text, run_index) else {
        return (text.to_string(), String::new());
    };
    let mut block = text[start..end].trim_end_matches('\n').to_string();
    block.push('\n');
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    out.push_str(&text[end..]);
    // Tidy any blank-line buildup the removal left behind.
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    (out, block)
}

/// Rewrites the text an orphan holder holds. `f` maps the old text to the
/// new one.
fn rewrite_holder(doc: &mut toml_edit::DocumentMut, holder: &OrphanHolder, f: impl FnOnce(&str) -> String) {
    match holder {
        OrphanHolder::KeyPrefix(section, flag) => {
            if let Some(table) = doc.get_mut(section).and_then(|i| i.as_table_mut()) {
                if let Some((mut key, _)) = table.get_key_value_mut(flag) {
                    let old = key
                        .leaf_decor_mut()
                        .prefix()
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();
                    key.leaf_decor_mut().set_prefix(f(&old));
                }
            }
        }
        OrphanHolder::NextHeader(name) => {
            if let Some(table) = doc.get_mut(name).and_then(|i| i.as_table_mut()) {
                let old = table
                    .decor()
                    .prefix()
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                table.decor_mut().set_prefix(f(&old));
            }
        }
        OrphanHolder::DocTrailing => {
            let old = doc.trailing().as_str().unwrap_or("").to_string();
            doc.set_trailing(f(&old));
        }
    }
}

/// Removes an absent key's orphan block from wherever it lives and returns
/// its text (comments + was-lines), for re-attaching above a recreated key.
fn adopt_orphan(doc: &mut toml_edit::DocumentMut, spec: &KeySpec) -> Option<String> {
    let orphan = find_orphan(doc, spec)?;
    let mut block = String::new();
    rewrite_holder(doc, &orphan.holder, |old| {
        let (without, taken) = excise_run(old, orphan.run_index);
        block = taken;
        without
    });
    if block.is_empty() { None } else { Some(block) }
}

/// Converts an editable TOML value into the plain `toml` model the load
/// path and the validators use. Only the scalar/array shapes config keys
/// take; datetimes and tables are out of scope (None).
fn te_to_model(value: &toml_edit::Value) -> Option<toml::Value> {
    Some(match value {
        toml_edit::Value::Boolean(b) => toml::Value::from(*b.value()),
        toml_edit::Value::Integer(i) => toml::Value::from(*i.value()),
        toml_edit::Value::Float(f) => toml::Value::from(*f.value()),
        toml_edit::Value::String(s) => toml::Value::from(s.value().clone()),
        toml_edit::Value::Array(items) => toml::Value::Array(
            items
                .iter()
                .map(te_to_model)
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    })
}

/// A stored value rendered as canonical single-line TOML (decor and
/// comments stripped) for display and history entries.
fn render_value(value: &toml_edit::Value) -> String {
    match te_to_model(value) {
        Some(model) => model.to_string(),
        None => value.to_string().trim().to_string(),
    }
}

fn render_item(item: &toml_edit::Item) -> String {
    match item.as_value() {
        Some(value) => render_value(value),
        None => item.to_string().trim().to_string(),
    }
}

/// The value as it will appear in a `# was:` entry: single-line TOML, or
/// None when it can't be represented on one line (then no entry is banked).
fn render_entry_value(value: &toml_edit::Value) -> Option<String> {
    let rendered = render_value(value);
    if rendered.contains('\n') {
        None
    } else {
        Some(rendered)
    }
}

/// Semantic equality of two stored values, normalized via the key's kind
/// (float keys match `40` with `40.0`); invalid stored values fall back to
/// comparing their literal rendering.
fn values_equal(spec: &KeySpec, a: &toml_edit::Value, b: &toml_edit::Value) -> bool {
    let normalized = |v: &toml_edit::Value| te_to_model(v).and_then(|m| check_value(spec, &m).ok());
    match (normalized(a), normalized(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a.to_string().trim() == b.to_string().trim(),
    }
}

/// The section's table, creating an explicit empty one at the end of the
/// document when missing. Bails when the name is taken by a non-table.
fn section_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    section: &str,
    path: &Path,
) -> Result<&'a mut toml_edit::Table> {
    match doc.get(section) {
        None => {
            doc.as_table_mut()
                .insert(section, toml_edit::Item::Table(toml_edit::Table::new()));
        }
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "'{}' in {} is a value, not a [section] table",
            section,
            path.display()
        ),
    }
    Ok(doc
        .get_mut(section)
        .and_then(|i| i.as_table_mut())
        .expect("section table just ensured"))
}

/// Appends a comment block at the end of a section: into the following
/// section's header decor, or the document trailing for the last section.
fn attach_tail(doc: &mut toml_edit::DocumentMut, section: &str, block: &str) {
    let sections: Vec<String> = doc.iter().map(|(name, _)| name.to_string()).collect();
    let next = sections
        .iter()
        .position(|name| name == section)
        .and_then(|i| sections.get(i + 1));
    match next {
        Some(name) if doc.get(name).is_some_and(|i| i.is_table()) => {
            let table = doc
                .get_mut(name)
                .and_then(|i| i.as_table_mut())
                .expect("checked above");
            let mut prefix = table
                .decor()
                .prefix()
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            append_block(&mut prefix, block);
            if !prefix.ends_with("\n\n") {
                prefix.push('\n');
            }
            table.decor_mut().set_prefix(prefix);
        }
        _ => {
            let mut trailing = doc.trailing().as_str().unwrap_or("").to_string();
            append_block(&mut trailing, block);
            doc.set_trailing(trailing);
        }
    }
}

/// Attaches a comment block where a removed key was: above the next key of
/// the section, or at the section's end when the key was the last one.
fn attach_block(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    next_flag: Option<&str>,
    block: &str,
) {
    if block.is_empty() {
        return;
    }
    if let Some(flag) = next_flag {
        if let Some(table) = doc.get_mut(section).and_then(|i| i.as_table_mut()) {
            if let Some((mut key, _)) = table.get_key_value_mut(flag) {
                let old = key
                    .leaf_decor_mut()
                    .prefix()
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                key.leaf_decor_mut().set_prefix(format!(
                    "{}\n\n{}",
                    block.trim_end_matches('\n'),
                    old.trim_start_matches('\n')
                ));
                return;
            }
        }
    }
    attach_tail(doc, section, block);
}

/// Appends a block to comment text, separated from previous content by a
/// blank line; the result ends with a single newline.
fn append_block(text: &mut String, block: &str) {
    let trimmed = text.trim_end_matches('\n');
    if !trimmed.is_empty() {
        text.truncate(trimmed.len());
        text.push_str("\n\n");
    }
    text.push_str(block.trim_end_matches('\n'));
    text.push('\n');
}

/// Writes a file atomically (same-dir tmp + rename) with owner-only
/// permissions: the config holds pre-approved fingerprints, so it is 0600
/// like the rest of the monux state.
fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let write = || -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        // A leftover tmp from a crashed run may carry wider perms.
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    };
    write().with_context(|| format!("Failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("Failed to install {}", path.display()))
}

/// Outcome of a successful `set`: what was stored and what it replaced.
#[derive(Debug)]
pub struct SetOutcome {
    pub key: &'static str,
    /// The stored value, rendered as TOML.
    pub new_value: String,
    /// The previous override, rendered as TOML; None when the key was at
    /// its default.
    pub old_value: Option<String>,
    /// True when the stored value already was the current one: a complete
    /// no-op — no was-entry, no file write.
    pub unchanged: bool,
}

/// Validates and stores a config value, banking the replaced one as a
/// `# was:` history entry. Scalars take exactly one value, repeatable
/// (array) keys one or more. Setting the value the key already has is a
/// complete no-op.
pub fn set_value(path: &Path, key: &str, values: &[String]) -> Result<SetOutcome> {
    let spec = find(key).ok_or_else(|| unknown_key_error(key))?;
    if spec.kind == Kind::StrArray {
        if values.is_empty() {
            bail!("'{}' expects at least one value ({})", key, spec.expects);
        }
    } else if values.len() != 1 {
        bail!("'{}' expects exactly one value ({})", key, spec.expects);
    }
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    (spec.validate)(&refs).map_err(|e| anyhow!("invalid value for '{}': {}", key, e))?;
    let stored = match spec.kind {
        Kind::Bool => toml_edit::Value::from(refs[0].parse::<bool>().expect("validated above")),
        Kind::Int => toml_edit::Value::from(refs[0].parse::<i64>().expect("validated above")),
        Kind::Float => toml_edit::Value::from(refs[0].parse::<f64>().expect("validated above")),
        Kind::Str => toml_edit::Value::from(refs[0]),
        Kind::StrArray => {
            let mut array = toml_edit::Array::new();
            for s in &refs {
                array.push(*s);
            }
            toml_edit::Value::Array(array)
        }
    };
    let new_render = render_value(&stored);
    let mut doc = read_doc(path)?;
    let section = spec.section.as_str();
    let table = section_table(&mut doc, section, path)?;
    if let Some(old_item) = table.get(spec.flag) {
        let old_render = render_item(old_item);
        let old_value = old_item.as_value();
        if let Some(old_value) = old_value {
            if values_equal(spec, old_value, &stored) {
                return Ok(SetOutcome {
                    key: spec.key,
                    new_value: new_render,
                    old_value: Some(old_render),
                    unchanged: true,
                });
            }
        }
        let entry_value = old_value.and_then(render_entry_value);
        let decor = old_value.map(|v| v.decor().clone());
        // A real transition: bank the current value on the key's was-stack
        // (even when the new value equals an entry already in the stack),
        // then replace the value, keeping its decor (spacing, trailing
        // comment).
        if let Some(entry_value) = entry_value {
            let (mut key_mut, _) = table.get_key_value_mut(spec.flag).expect("present");
            let prefix = key_mut
                .leaf_decor_mut()
                .prefix()
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            key_mut.leaf_decor_mut().set_prefix(push_stack(
                &prefix,
                WasEntry {
                    value: entry_value,
                    timestamp: now_timestamp(),
                },
            ));
        }
        let mut new_value = stored;
        if let Some(decor) = decor {
            *new_value.decor_mut() = decor;
        }
        *table.get_mut(spec.flag).expect("present") = toml_edit::Item::Value(new_value);
        atomic_write(path, &doc.to_string())?;
        return Ok(SetOutcome {
            key: spec.key,
            new_value: new_render,
            old_value: Some(old_render),
            unchanged: false,
        });
    }
    // A new key: nothing to bank, but adopt the was-block an earlier unset
    // left behind so the key keeps its history.
    let adopted = adopt_orphan(&mut doc, spec);
    let table = section_table(&mut doc, section, path)?;
    table.insert(spec.flag, toml_edit::Item::Value(stored));
    if let Some(block) = adopted {
        let (mut key_mut, _) = table.get_key_value_mut(spec.flag).expect("just inserted");
        key_mut.leaf_decor_mut().set_prefix(block);
    }
    atomic_write(path, &doc.to_string())?;
    Ok(SetOutcome {
        key: spec.key,
        new_value: new_render,
        old_value: None,
        unchanged: false,
    })
}

/// Outcome of an `unset`.
#[derive(Debug)]
pub enum UnsetOutcome {
    /// A registry key's override was removed; it reverts to the default.
    Removed(&'static KeySpec, String),
    /// The key is known but had no override; nothing changed.
    AlreadyDefault(&'static KeySpec),
    /// An unknown (stale/renamed) key was removed from the file — the
    /// cleanup path `validate` prints.
    RemovedUnknown(String, String),
}

/// Removes a config value, banking it as a `# was:` history entry: the
/// was-block stays where the key was. Unknown keys error out — unless they
/// are actually present in the file, which is exactly the stale-key cleanup
/// case (no history: unknown keys are not managed).
pub fn unset_value(path: &Path, key: &str) -> Result<UnsetOutcome> {
    let mut doc = read_doc(path)?;
    let spec = find(key);
    // Capture the key's prefix (comments + was-stack) and the following
    // key before removing it.
    let removed = match key.split_once('.') {
        Some((section, flag)) => {
            // An inline-table section (`server = { port = 4321 }`) is a real
            // override: the load path takes it and the daemon runs on it. It
            // is not editable here though — an inline table has nowhere to put
            // the `# was:` line, so this bails exactly like `set` does rather
            // than reporting "already at default", which would contradict both
            // `mx config show` and the running daemon.
            if doc
                .get(section)
                .and_then(|i| i.as_inline_table())
                .is_some_and(|t| t.contains_key(flag))
            {
                bail!(
                    "'{}' in {} is a value, not a [section] table",
                    section,
                    path.display()
                );
            }
            doc.get_mut(section)
                .and_then(|i| i.as_table_mut())
                .map(|table| {
                    // The key line is about to go, and its own indent goes
                    // with it: what stays behind is the comment block that
                    // sat above it, which starts at column 0.
                    let prefix = key_prefix(table, flag)
                        .trim_end_matches(|c: char| c != '\n' && c.is_whitespace())
                        .to_string();
                    let next_flag = table
                        .iter()
                        .skip_while(|(name, _)| *name != flag)
                        .nth(1)
                        .map(|(name, _)| name.to_string());
                    (section.to_string(), table.remove(flag), prefix, next_flag)
                })
        }
        None => None,
    };
    let Some((section, removed, prefix, next_flag)) = removed else {
        return match spec {
            Some(spec) => Ok(UnsetOutcome::AlreadyDefault(spec)),
            None => Err(unknown_key_error(key)),
        };
    };
    match (spec, removed) {
        (Some(spec), Some(old)) => {
            // Bank the removed value at the bottom of the key's own
            // was-stack; the block stays in place in the section.
            let block = match old.as_value().and_then(render_entry_value) {
                Some(value) => push_stack(
                    &prefix,
                    WasEntry {
                        value,
                        timestamp: now_timestamp(),
                    },
                ),
                None => prefix,
            };
            attach_block(&mut doc, &section, next_flag.as_deref(), &block);
            atomic_write(path, &doc.to_string())?;
            Ok(UnsetOutcome::Removed(spec, render_item(&old)))
        }
        (Some(spec), None) => Ok(UnsetOutcome::AlreadyDefault(spec)),
        (None, Some(old)) => {
            // Unknown (stale) key: no history, but its comments survive.
            attach_block(&mut doc, &section, next_flag.as_deref(), &prefix);
            atomic_write(path, &doc.to_string())?;
            Ok(UnsetOutcome::RemovedUnknown(
                key.to_string(),
                render_item(&old),
            ))
        }
        (None, None) => Err(unknown_key_error(key)),
    }
}

/// Outcome of a `revert`.
#[derive(Debug)]
pub struct RevertOutcome {
    pub key: &'static str,
    /// The restored value, rendered as TOML.
    pub restored: String,
    /// The value it replaced (banked onto the stack, so the revert is
    /// itself undoable); None when the key was unset.
    pub replaced: Option<String>,
}

/// Restores a previous value from a key's was-stack: the newest entry, or
/// the one matching `to` exactly. The entry is re-validated with the key's
/// registry validator, the current value (if any) is banked as usual, and
/// the key line is recreated when it was unset.
pub fn revert_value(path: &Path, key: &str, to: Option<&str>) -> Result<RevertOutcome> {
    let spec = find(key).ok_or_else(|| unknown_key_error(key))?;
    let mut doc = read_doc(path)?;
    let section = spec.section.as_str();
    let present = doc
        .get(section)
        .and_then(|i| i.as_table())
        .is_some_and(|t| t.contains_value(spec.flag));
    let stack = key_stack(&doc, spec);
    if stack.is_empty() {
        bail!("no history for '{}' — nothing to revert to", key);
    }
    let idx = match to {
        None => 0,
        Some(timestamp) => match stack.iter().position(|e| e.timestamp == timestamp) {
            Some(i) => i,
            None => bail!(
                "no history entry for '{}' at {}\navailable:\n{}",
                key,
                timestamp,
                stack
                    .iter()
                    .map(|e| format!("  {} @ {}", e.value, e.timestamp))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        },
    };
    let entry = stack[idx].clone();
    // The recorded value must still pass the key's validator.
    let parsed: toml_edit::Value = entry
        .value
        .parse()
        .map_err(|_| anyhow!("history entry for '{}' is not a TOML value: {}", key, entry.value))?;
    let model = te_to_model(&parsed)
        .with_context(|| format!("history entry for '{}' is not a config value: {}", key, entry.value))?;
    check_value(spec, &model).map_err(|e| {
        anyhow!(
            "the recorded value {} for '{}' no longer validates: {} — fix or remove the entry by hand",
            entry.value,
            key,
            e
        )
    })?;
    let restored = render_value(&parsed);
    // Pop the entry; bank the current value on top as usual.
    let mut remaining = stack.clone();
    remaining.remove(idx);
    let mut replaced = None;
    if present {
        let table = doc
            .get(section)
            .and_then(|i| i.as_table())
            .expect("checked present");
        let old_item = table.get(spec.flag).expect("checked present");
        replaced = Some(render_item(old_item));
        if let Some(value) = old_item.as_value().and_then(render_entry_value) {
            remaining.insert(
                0,
                WasEntry {
                    value,
                    timestamp: now_timestamp(),
                },
            );
            remaining.truncate(HISTORY_CAP);
        }
    }
    if present {
        let table = doc
            .get_mut(section)
            .and_then(|i| i.as_table_mut())
            .expect("checked present");
        let (mut key_mut, _) = table.get_key_value_mut(spec.flag).expect("checked present");
        let prefix = key_mut
            .leaf_decor_mut()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let (head, _, indent) = split_bottom_stack(&prefix);
        key_mut
            .leaf_decor_mut()
            .set_prefix(render_stack_block(head, &remaining, indent));
        let decor = table
            .get(spec.flag)
            .and_then(|i| i.as_value())
            .map(|v| v.decor().clone());
        let mut new_value = parsed;
        if let Some(decor) = decor {
            *new_value.decor_mut() = decor;
        }
        *table.get_mut(spec.flag).expect("checked present") = toml_edit::Item::Value(new_value);
    } else {
        // Recreate the key line below its (remaining) was-block.
        let adopted = adopt_orphan(&mut doc, spec).unwrap_or_default();
        let (head, _, indent) = split_bottom_stack(&adopted);
        let (head, indent) = (head.to_string(), indent.to_string());
        let table = section_table(&mut doc, section, path)?;
        table.insert(spec.flag, toml_edit::Item::Value(parsed));
        let (mut key_mut, _) = table.get_key_value_mut(spec.flag).expect("just inserted");
        key_mut
            .leaf_decor_mut()
            .set_prefix(render_stack_block(&head, &remaining, &indent));
    }
    atomic_write(path, &doc.to_string())?;
    Ok(RevertOutcome {
        key: spec.key,
        restored,
        replaced,
    })
}

/// The was-stack of a managed key: the run directly above its line, or the
/// orphan block it left behind when unset. A key set in an inline-table
/// section has neither — the section has no comment lines to hold a stack,
/// and an orphan block belongs to a key that is *absent* from the file, which
/// this one is not.
fn key_stack(doc: &toml_edit::DocumentMut, spec: &KeySpec) -> Vec<WasEntry> {
    let section = spec.section.as_str();
    if let Some(table) = doc.get(section).and_then(|i| i.as_table()) {
        if table.contains_value(spec.flag) {
            return split_bottom_stack(key_prefix(table, spec.flag)).1;
        }
    } else if key_is_set(doc, spec) {
        return vec![];
    }
    match find_orphan(doc, spec) {
        Some(orphan) => orphan.entries,
        None => vec![],
    }
}

/// Whether the file carries a value for the key, in a `[section]` table or an
/// inline-table section — the same reach the load path (`File::parse`, which
/// takes any table) has, so `history` and `show` cannot disagree about
/// whether a key is set.
fn key_is_set(doc: &toml_edit::DocumentMut, spec: &KeySpec) -> bool {
    doc.get(spec.section.as_str())
        .and_then(|i| i.as_table_like())
        .and_then(|t| t.get(spec.flag))
        .is_some_and(|i| i.is_value())
}

/// One key's history, for `config history`.
#[derive(Debug)]
struct KeyHistory {
    spec: &'static KeySpec,
    /// The current value rendered as TOML; None when unset.
    current: Option<String>,
    /// The was-stack, newest first.
    entries: Vec<WasEntry>,
}

/// Every registry key's current value and was-stack. Orphan blocks are
/// attributed greedily in registry order — each block is listed under at
/// most one absent key.
fn read_history(path: &Path) -> Result<Vec<KeyHistory>> {
    let text = match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(REGISTRY
                .iter()
                .map(|spec| KeyHistory {
                    spec,
                    current: None,
                    entries: vec![],
                })
                .collect())
        }
        Err(e) => return Err(e).with_context(|| format!("Failed to read {}", path.display())),
        Ok(text) => text,
    };
    let doc = text.parse::<toml_edit::DocumentMut>().with_context(|| {
        format!(
            "{} is not valid TOML; fix it with 'mx config edit' or check it with 'mx config validate'",
            path.display()
        )
    })?;
    let mut orphan_pools: std::collections::HashMap<&'static str, Vec<Orphan>> = [
        (
            Section::Server.as_str(),
            gather_orphans(&doc, Section::Server.as_str()),
        ),
        (
            Section::Client.as_str(),
            gather_orphans(&doc, Section::Client.as_str()),
        ),
    ]
    .into_iter()
    .collect();
    Ok(REGISTRY
        .iter()
        .map(|spec| {
            let current = doc
                .get(spec.section.as_str())
                .and_then(|i| i.as_table_like())
                .and_then(|t| t.get(spec.flag))
                .filter(|i| i.is_value())
                .map(render_item);
            let entries = if current.is_some() {
                key_stack(&doc, spec)
            } else {
                let pool = orphan_pools
                    .get_mut(spec.section.as_str())
                    .expect("both sections pooled");
                pool.iter()
                    .position(|o| orphan_fits(o, spec))
                    .map(|i| pool.remove(i).entries)
                    .unwrap_or_default()
            };
            KeyHistory {
                spec,
                current,
                entries,
            }
        })
        .collect())
}

/// The error for a `set`/`unset` on a key that is neither in the registry
/// nor in the file: a did-you-mean suggestion when close, the valid keys of
/// a recognizable section prefix, and the full-reference hint.
fn unknown_key_error(key: &str) -> anyhow::Error {
    let mut msg = format!("unknown config key '{}'", key);
    if let Some(suggestion) = did_you_mean(key) {
        msg.push_str(&format!(" — did you mean '{}'?", suggestion));
    }
    if let Some((section, _)) = key.split_once('.') {
        let valid: Vec<&str> = REGISTRY
            .iter()
            .filter(|s| s.section.as_str() == section)
            .map(|s| s.key)
            .collect();
        if !valid.is_empty() {
            msg.push_str(&format!("\nvalid {} keys: {}", section, valid.join(", ")));
        }
    }
    anyhow!("{}\n(full reference: 'mx config keys')", msg)
}

/// The best-matching registry key within a small edit distance, if any.
pub fn did_you_mean(key: &str) -> Option<&'static str> {
    let mut best: Option<(&str, usize)> = None;
    for spec in REGISTRY {
        let d = levenshtein(key, spec.key);
        if d <= 3 && best.is_none_or(|(_, bd)| d < bd) {
            best = Some((spec.key, d));
        }
    }
    best.map(|(k, _)| k)
}

/// Classic Levenshtein edit distance (keys are short, O(n*m) is fine).
fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Whether a `validate` finding blocks an `edit` install.
#[derive(Debug, PartialEq, Eq)]
pub enum Severity {
    /// Malformed TOML or an invalid value for a known key.
    Error,
    /// Unknown or renamed key: the daemons ignore it, but it is stale.
    Warning,
}

/// One `validate` finding.
#[derive(Debug)]
pub struct Issue {
    /// 1-based line number, when it could be determined.
    pub line: Option<usize>,
    pub severity: Severity,
    pub message: String,
    /// The exact `mx config unset` line removing the entry, when there is one.
    pub cleanup: Option<String>,
}

/// Parses and registry-validates the config file without changing it,
/// reporting every problem with a line number where one can be determined.
/// A missing file is clean.
pub fn validate_file(path: &Path) -> Result<Vec<Issue>> {
    let text = match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).with_context(|| format!("Failed to read {}", path.display())),
        Ok(text) => text,
    };
    // Malformed TOML is the one case where per-key checks can't run.
    if let Err(e) = toml::from_str::<toml::Table>(&text) {
        let message = e.to_string();
        return Ok(vec![Issue {
            // toml 0.8 exposes the position only in the Display text
            // ("TOML parse error at line N, column C").
            line: message
                .split("at line ")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .and_then(|n| n.trim().parse().ok()),
            severity: Severity::Error,
            message: format!("TOML syntax error: {}", message),
            cleanup: None,
        }]);
    }
    // Reuse the loader's classification so validate and the daemons agree.
    let file = File::parse(&text).expect("the TOML parsed successfully above");
    let mut issues = vec![];
    for key in &file.unknown {
        // A dotless entry is a top-level item outside every section (the
        // "not a table" branch of File::parse). `mx config unset` addresses
        // keys as <section>.<flag> only, so there is no cleanup line to print
        // for one — offering it would just hand the user a command that exits
        // with "unknown config key".
        if !key.contains('.') {
            issues.push(Issue {
                line: key_line(&text, key),
                severity: Severity::Warning,
                message: format!(
                    "'{}' sits outside any section — every key lives under [server] or [client]; move or delete it by hand",
                    key
                ),
                cleanup: None,
            });
            continue;
        }
        issues.push(Issue {
            line: key_line(&text, key),
            severity: Severity::Warning,
            message: match did_you_mean(key) {
                Some(suggestion) => format!(
                    "unknown key '{}' (did you mean '{}'?) — removed or renamed?",
                    key, suggestion
                ),
                None => format!("unknown key '{}' — removed or renamed?", key),
            },
            cleanup: Some(format!("mx config unset {}", key)),
        });
    }
    for (old, new) in &file.aliased {
        issues.push(Issue {
            line: key_line(&text, old),
            severity: Severity::Warning,
            message: format!("key '{}' was renamed to '{}' — please update the file", old, new),
            cleanup: Some(format!("mx config unset {}", old)),
        });
    }
    for (key, reason) in &file.invalid {
        issues.push(Issue {
            line: key_line(&text, key),
            severity: Severity::Error,
            message: format!("invalid value for '{}': {}", key, reason),
            cleanup: Some(format!("mx config unset {}", key)),
        });
    }
    issues.sort_by_key(|i| i.line);
    Ok(issues)
}

/// The 1-based line of `flag =` inside `[section]`, if found.
fn key_line(text: &str, key: &str) -> Option<usize> {
    let (section, flag) = key.split_once('.')?;
    let mut in_section = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == format!("[{}]", section);
            continue;
        }
        if in_section && !t.starts_with('#') {
            if let Some((k, _)) = t.split_once('=') {
                if k.trim().trim_matches('"') == flag {
                    return Some(i + 1);
                }
            }
        }
    }
    None
}

/// One line of `config show`: a key, its effective value, and its source.
#[derive(Debug)]
pub struct Effective {
    pub spec: &'static KeySpec,
    pub rendered: String,
    pub from_file: bool,
}

/// Every registry key with its effective value: the config file's override
/// rendered as TOML, or the built-in default's display string.
pub fn effective(file: &File) -> Vec<Effective> {
    REGISTRY
        .iter()
        .map(|spec| match file.values.get(spec.key) {
            Some(v) => Effective {
                spec,
                rendered: v.to_string(),
                from_file: true,
            },
            None => Effective {
                spec,
                rendered: spec.default_display.to_string(),
                from_file: false,
            },
        })
        .collect()
}

/// Registry keys introduced after version `prev` (semver-ish compare).
pub fn keys_since(prev: &str) -> Vec<&'static KeySpec> {
    let prev = parse_version(prev).unwrap_or((0, 0, 0));
    REGISTRY
        .iter()
        .filter(|s| parse_version(s.since).unwrap_or((0, 0, 0)) > prev)
        .collect()
}

/// Parses "7.4.0" (also "7.4", ignoring any -pre/+build suffix) into a
/// comparable tuple; None when the major.minor don't parse. Shared with the
/// updater, which orders release tags by it.
pub(crate) fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.split(['-', '+']).next()?.trim();
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// New-key visibility: on the first daemon start of a version newer than the
/// recorded one, logs one line per config key introduced since, then updates
/// the record. A fresh install records the version and announces nothing.
pub fn announce_new_keys(config_dir: &Path, current: &str) {
    let path = config_dir.join(LAST_VERSION_FILE);
    let Some(current_v) = parse_version(current) else {
        return;
    };
    match fs::read_to_string(&path) {
        Ok(stored) => {
            let Some(stored_v) = parse_version(stored.trim()) else {
                // Unparseable content: start the record over, announce nothing.
                write_last_version(&path, current);
                return;
            };
            if stored_v >= current_v {
                return;
            }
            for spec in keys_since(stored.trim()) {
                info!(
                    "new in v{}: {} — {}; see 'mx config keys'",
                    spec.since, spec.key, spec.help
                );
            }
            write_last_version(&path, current);
        }
        Err(_) => write_last_version(&path, current),
    }
}

fn write_last_version(path: &Path, current: &str) {
    if let Err(e) = fs::write(path, format!("{}\n", current)) {
        warn!("Failed to record the version in {}: {}", path.display(), e);
    }
}

// --- Value validators (the flag parsers' config-file counterparts) --------

/// Accepted range for --mouse-scale/--scroll-scale: wide enough for genuine
/// DPI/sensitivity mismatches, narrow enough to catch typos.
pub const MIN_INPUT_SCALE: f64 = 0.05;
pub const MAX_INPUT_SCALE: f64 = 20.0;

/// Value parser for the client's --mouse-scale/--scroll-scale flags and the
/// matching config keys.
pub fn parse_input_scale(s: &str) -> std::result::Result<f64, String> {
    match s.parse::<f64>() {
        Ok(v) if v.is_finite() && (MIN_INPUT_SCALE..=MAX_INPUT_SCALE).contains(&v) => Ok(v),
        _ => Err(format!(
            "scale must be a number between {} and {}",
            MIN_INPUT_SCALE, MAX_INPUT_SCALE
        )),
    }
}

/// Accepted range for --bulk-throttle-mbps when enabled (0 disables): wide
/// enough for any WiFi/LAN link, narrow enough to catch typos.
pub const MIN_BULK_THROTTLE_MBPS: f64 = 0.1;
pub const MAX_BULK_THROTTLE_MBPS: f64 = 10_000.0;

/// Value parser for --bulk-throttle-mbps on server and client and the
/// matching config keys.
pub fn parse_bulk_throttle(s: &str) -> std::result::Result<f64, String> {
    match s.parse::<f64>() {
        Ok(v) if v == 0.0 => Ok(v),
        Ok(v)
            if v.is_finite() && (MIN_BULK_THROTTLE_MBPS..=MAX_BULK_THROTTLE_MBPS).contains(&v) =>
        {
            Ok(v)
        }
        _ => Err(format!(
            "throttle must be 0 (disabled) or a number between {} and {}",
            MIN_BULK_THROTTLE_MBPS, MAX_BULK_THROTTLE_MBPS
        )),
    }
}

/// The single value of a scalar key.
fn expect_one<'a>(values: &'a [&'a str]) -> std::result::Result<&'a str, String> {
    match values {
        [v] => Ok(v),
        _ => Err("expects exactly one value".to_string()),
    }
}

fn check_int_range(v: &str, min: i64, max: i64) -> std::result::Result<(), String> {
    match v.parse::<i64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(()),
        _ => Err(format!("'{}' is not an integer in {}..={}", v, min, max)),
    }
}

fn v_bool(values: &[&str]) -> std::result::Result<(), String> {
    let v = expect_one(values)?;
    v.parse::<bool>()
        .map(|_| ())
        .map_err(|_| format!("'{}' is not a boolean (true/false)", v))
}

fn v_chord(values: &[&str]) -> std::result::Result<(), String> {
    crate::device::shortcut::validate_chord(expect_one(values)?).map_err(|e| e.to_string())
}

fn v_chord_or_empty(values: &[&str]) -> std::result::Result<(), String> {
    let v = expect_one(values)?;
    if v.trim().is_empty() {
        Ok(())
    } else {
        v_chord(values)
    }
}

fn v_goto(values: &[&str]) -> std::result::Result<(), String> {
    for v in values {
        crate::device::shortcut::validate_goto(v).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn v_regex(values: &[&str]) -> std::result::Result<(), String> {
    for v in values {
        Regex::new(v).map_err(|e| format!("invalid regex '{}': {}", v, e))?;
    }
    Ok(())
}

fn v_ip(values: &[&str]) -> std::result::Result<(), String> {
    let v = expect_one(values)?;
    v.parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("'{}' is not an IP address", v))
}

fn v_port(values: &[&str]) -> std::result::Result<(), String> {
    check_int_range(expect_one(values)?, 1, 65535)
}

fn v_exit_secs(values: &[&str]) -> std::result::Result<(), String> {
    check_int_range(expect_one(values)?, 0, u32::MAX as i64)
}

fn v_clipboard_kb(values: &[&str]) -> std::result::Result<(), String> {
    check_int_range(expect_one(values)?, 0, MAX_CLIPBOARD_SIZE_KB as i64)
}

fn v_motion_hz(values: &[&str]) -> std::result::Result<(), String> {
    check_int_range(expect_one(values)?, 0, u32::MAX as i64)
}

fn v_edge_dwell(values: &[&str]) -> std::result::Result<(), String> {
    check_int_range(expect_one(values)?, 0, i64::MAX)
}

fn v_scale(values: &[&str]) -> std::result::Result<(), String> {
    parse_input_scale(expect_one(values)?).map(|_| ())
}

fn v_bulk_throttle(values: &[&str]) -> std::result::Result<(), String> {
    parse_bulk_throttle(expect_one(values)?).map(|_| ())
}

fn v_fingerprints(values: &[&str]) -> std::result::Result<(), String> {
    for v in values {
        let hex: String = v.chars().filter(|c| *c != ':').collect();
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "'{}' is not a certificate fingerprint (hex digits, ':' allowed)",
                v
            ));
        }
    }
    Ok(())
}

fn v_edge_map_server(values: &[&str]) -> std::result::Result<(), String> {
    let owned: Vec<String> = values.iter().map(|s| s.to_string()).collect();
    crate::edge::parse_edge_map(&owned)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn v_edge_map_client(values: &[&str]) -> std::result::Result<(), String> {
    let owned: Vec<String> = values.iter().map(|s| s.to_string()).collect();
    crate::edge::parse_client_edge_map(&owned)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// --- The `mx config` subcommand ---------------------------------------------

/// Actions of the `config` subcommand (parsed in main.rs); bare
/// `monux config` maps to Show.
pub enum Action {
    Show,
    Keys(Option<String>),
    Set { key: String, values: Vec<String> },
    Unset { key: String },
    Edit,
    Validate,
    History { key: Option<String> },
    Revert { key: String, to: Option<String> },
}

/// Runs a `config` subcommand action. The bool is the "clean" verdict used
/// for the exit code: false only for a failed `validate` or an `edit` whose
/// result the user chose not to install.
pub fn cli(config_dir: &Path, action: &Action) -> Result<bool> {
    let path = path(config_dir);
    match action {
        Action::Show => {
            cli_show(&path)?;
            Ok(true)
        }
        Action::Keys(filter) => {
            cli_keys(filter.as_deref());
            Ok(true)
        }
        Action::Set { key, values } => {
            cli_set(&path, key, values)?;
            Ok(true)
        }
        Action::Unset { key } => {
            cli_unset(&path, key)?;
            Ok(true)
        }
        Action::Edit => cli_edit(&path),
        Action::Validate => cli_validate(&path),
        Action::History { key } => {
            cli_history(&path, key.as_deref())?;
            Ok(true)
        }
        Action::Revert { key, to } => {
            cli_revert(&path, key, to.as_deref())?;
            Ok(true)
        }
    }
}

fn cli_show(path: &Path) -> Result<()> {
    let file = load(path)
        .with_context(|| "cannot show values from a malformed config file; run 'mx config validate'")?;
    println!("Config file: {}", path.display());
    for section in [Section::Server, Section::Client] {
        println!("\n[{}]", section.as_str());
        for e in effective(&file)
            .into_iter()
            .filter(|e| e.spec.section == section)
        {
            let source = if e.from_file { "config file" } else { "default" };
            println!("{} = {} ({})", e.spec.flag, e.rendered, source);
        }
    }
    if !file.unknown.is_empty() || !file.invalid.is_empty() || !file.aliased.is_empty() {
        println!(
            "\nnote: {} unknown/invalid entr{} ignored — see 'mx config validate'",
            file.unknown.len() + file.invalid.len() + file.aliased.len(),
            if file.unknown.len() + file.invalid.len() + file.aliased.len() == 1 { "y" } else { "ies" },
        );
    }
    Ok(())
}

fn cli_keys(filter: Option<&str>) {
    let filter = filter.map(|f| f.to_lowercase());
    for spec in REGISTRY {
        if let Some(f) = &filter {
            if !spec.key.to_lowercase().contains(f) && !spec.help.to_lowercase().contains(f) {
                continue;
            }
        }
        let new = if spec.since != BASELINE_SINCE {
            format!(" (new in v{})", spec.since)
        } else {
            String::new()
        };
        println!(
            "{}{} — {} — expects: {}; default: {}",
            spec.key, new, spec.help, spec.expects, spec.default_display
        );
    }
}

fn cli_set(path: &Path, key: &str, values: &[String]) -> Result<()> {
    let spec = find(key).ok_or_else(|| unknown_key_error(key))?;
    if values.is_empty() {
        return print_key_card(path, spec);
    }
    let outcome = set_value(path, key, values)?;
    if outcome.unchanged {
        println!("{} = {} (unchanged)", outcome.key, outcome.new_value);
        return Ok(());
    }
    let was = outcome
        .old_value
        .unwrap_or_else(|| format!("{} (default)", spec.default_display));
    println!("{} = {} (was: {})", outcome.key, outcome.new_value, was);
    // Daemons read the file once at startup; a live one needs a restart.
    if single_instance::live_holder(spec.section.as_str()).is_some() {
        println!(
            "note: a {} daemon is running — restart to apply: mx daemon restart",
            spec.section.as_str()
        );
    }
    Ok(())
}

/// `set <key>` with no value: the key's reference card. Changes nothing.
fn print_key_card(path: &Path, spec: &KeySpec) -> Result<()> {
    let file = match load(path) {
        Ok(file) => file,
        Err(e) => {
            println!("note: ignoring malformed config file ({:#}); showing the default", e);
            File::default()
        }
    };
    let (current, source) = match file.get(spec.key) {
        Some(v) => (v.to_string(), "config file"),
        None => (spec.default_display.to_string(), "default"),
    };
    println!("{} — {}", spec.key, spec.help);
    println!("    expects: {}", spec.expects);
    println!("    default: {}", spec.default_display);
    println!("    current: {} ({})", current, source);
    Ok(())
}

fn cli_unset(path: &Path, key: &str) -> Result<()> {
    match unset_value(path, key)? {
        UnsetOutcome::Removed(spec, old) => println!(
            "removed {} = {}; reverts to {} (default)",
            spec.key, old, spec.default_display
        ),
        UnsetOutcome::AlreadyDefault(spec) => println!(
            "{} is not set in the config file; already at default: {}",
            spec.key, spec.default_display
        ),
        UnsetOutcome::RemovedUnknown(key, old) => {
            println!("removed unknown key {} = {}", key, old)
        }
    }
    Ok(())
}

/// `config history [key]`: the current value plus the was-stack, numbered
/// newest-first — the revert preview.
fn cli_history(path: &Path, key: Option<&str>) -> Result<()> {
    let all = read_history(path)?;
    match key {
        Some(key) => {
            let spec = find(key).ok_or_else(|| unknown_key_error(key))?;
            let h = all
                .iter()
                .find(|h| h.spec.key == spec.key)
                .expect("every registry key is listed");
            print_history(h);
        }
        None => {
            if all.iter().all(|h| h.entries.is_empty()) {
                println!("no history");
                return Ok(());
            }
            for section in [Section::Server, Section::Client] {
                let in_section: Vec<&KeyHistory> = all
                    .iter()
                    .filter(|h| h.spec.section == section && !h.entries.is_empty())
                    .collect();
                if in_section.is_empty() {
                    continue;
                }
                println!("[{}]", section.as_str());
                for h in in_section {
                    print_history(h);
                }
            }
        }
    }
    Ok(())
}

/// One key's history block: the current value, then the stack.
fn print_history(h: &KeyHistory) {
    match &h.current {
        Some(v) => println!("{} = {} (current)", h.spec.key, v),
        None => println!("{} (unset)", h.spec.key),
    }
    if h.entries.is_empty() {
        println!("  no history");
        return;
    }
    for (i, e) in h.entries.iter().enumerate() {
        let note = if i == 0 { " (restored by plain revert)" } else { "" };
        println!(" {}. {} @ {}{}", i + 1, e.value, e.timestamp, note);
    }
}

fn cli_revert(path: &Path, key: &str, to: Option<&str>) -> Result<()> {
    let outcome = revert_value(path, key, to)?;
    let was = outcome.replaced.unwrap_or_else(|| "unset".to_string());
    println!("{} = {} (was: {})", outcome.key, outcome.restored, was);
    // Daemons read the file once at startup; a live one needs a restart.
    let spec = find(key).expect("revert_value validated the key");
    if single_instance::live_holder(spec.section.as_str()).is_some() {
        println!(
            "note: a {} daemon is running — restart to apply: mx daemon restart",
            spec.section.as_str()
        );
    }
    Ok(())
}

fn cli_validate(path: &Path) -> Result<bool> {
    let issues = validate_file(path)?;
    if issues.is_empty() {
        println!("{}: OK (no issues)", path.display());
        return Ok(true);
    }
    for issue in &issues {
        let at = issue
            .line
            .map(|l| format!("{}:{}", path.display(), l))
            .unwrap_or_else(|| path.display().to_string());
        println!("{}: {}", at, issue.message);
        if let Some(cleanup) = &issue.cleanup {
            println!("    remove with: {}", cleanup);
        }
    }
    println!("{} issue(s) in {}", issues.len(), path.display());
    Ok(false)
}

/// Header written when `config edit` creates the file.
const EDIT_HEADER: &str = "\
# monux configuration — persistent flag storage for the 'server' and 'client' daemons.
# Keys are the flag long-names under [server] / [client]; repeatable flags are
# TOML arrays. An explicit CLI flag always wins over this file, which wins
# over the built-in defaults.
# Reference: 'mx config keys' · effective values: 'mx config show' · check: 'mx config validate'

";

/// `config edit`: edits a scratch copy in $EDITOR (fallback vi) and installs
/// only a valid result, crontab-style — a file with parse errors or invalid
/// values is never installed; unknown keys are noted but never block.
fn cli_edit(path: &Path) -> Result<bool> {
    let scratch = PathBuf::from(format!("{}.edit-{}", path.display(), std::process::id()));
    if path.exists() {
        if let Err(e) = fs::copy(path, &scratch) {
            // A half-written copy is worthless — nobody has edited it yet —
            // and would otherwise sit in the config dir forever.
            let _ = fs::remove_file(&scratch);
            return Err(e)
                .with_context(|| format!("Failed to copy {} for editing", path.display()));
        }
    } else {
        atomic_write(&scratch, EDIT_HEADER)?;
    }
    match edit_loop(path, &scratch) {
        Ok(installed) => {
            let _ = fs::remove_file(&scratch);
            Ok(installed)
        }
        // Everything after the editor exits — reading the scratch back, the
        // history diff, the atomic install — can still fail, and by then the
        // scratch holds the only copy of what the user typed. Keep it and name
        // it, the way crontab does. The name carries the pid, so the next
        // `mx config edit` starts from a scratch of its own and cannot clobber
        // it.
        Err(e) => Err(e.context(format!("your edits are kept in {}", scratch.display()))),
    }
}

fn edit_loop(path: &Path, scratch: &Path) -> Result<bool> {
    loop {
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
        let mut parts = editor.split_whitespace();
        let program = parts.next().context("$EDITOR is empty")?;
        let status = std::process::Command::new(program)
            .args(parts)
            .arg(scratch)
            .status()
            .with_context(|| format!("Failed to run editor '{}'", editor))?;
        if !status.success() {
            bail!("editor '{}' exited with {}", editor, status);
        }
        let issues = validate_file(scratch)?;
        // Unknown/renamed keys never block an install; say so and proceed.
        for issue in issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Warning))
        {
            println!("note: {}", issue.message);
        }
        let blocking: Vec<&Issue> = issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error))
            .collect();
        if blocking.is_empty() {
            atomic_write(path, &inject_edit_history(path, scratch)?)?;
            println!("installed {}", path.display());
            return Ok(true);
        }
        println!("The edited config has problems:");
        for issue in &blocking {
            match issue.line {
                Some(line) => println!("  line {}: {}", line, issue.message),
                None => println!("  {}", issue.message),
            }
        }
        if !prompt_reedit()? {
            println!("{} left unchanged", path.display());
            return Ok(false);
        }
    }
}

/// `config edit` installs a hand-edited file: diff it against the current
/// one per managed key and bank a was-entry for every changed or removed
/// key (added keys get none), so hand edits are revertable like `set`s.
/// Returns the text to install.
fn inject_edit_history(path: &Path, scratch: &Path) -> Result<String> {
    let new_text = fs::read_to_string(scratch)?;
    // The scratch validated already; an unparseable old file means no diff
    // is possible and the new text installs as-is.
    let (Ok(mut new_doc), Ok(old_doc)) = (
        new_text.parse::<toml_edit::DocumentMut>(),
        fs::read_to_string(path)
            .unwrap_or_default()
            .parse::<toml_edit::DocumentMut>(),
    ) else {
        return Ok(new_text);
    };
    let timestamp = now_timestamp();
    for spec in REGISTRY {
        let section = spec.section.as_str();
        let old_value = old_doc
            .get(section)
            .and_then(|i| i.as_table())
            .and_then(|t| t.get(spec.flag))
            .and_then(|i| i.as_value());
        let Some(old_value) = old_value else {
            continue; // added keys get no history
        };
        let Some(entry_value) = render_entry_value(old_value) else {
            continue;
        };
        let new_item = new_doc
            .get(section)
            .and_then(|i| i.as_table())
            .and_then(|t| t.get(spec.flag));
        match new_item.and_then(|i| i.as_value()) {
            Some(new_value) => {
                if values_equal(spec, old_value, new_value) {
                    continue;
                }
                let table = new_doc
                    .get_mut(section)
                    .and_then(|i| i.as_table_mut())
                    .expect("the key exists in a section table");
                let (mut key_mut, _) = table.get_key_value_mut(spec.flag).expect("the key exists");
                let prefix = key_mut
                    .leaf_decor_mut()
                    .prefix()
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                key_mut.leaf_decor_mut().set_prefix(push_stack(
                    &prefix,
                    WasEntry {
                        value: entry_value,
                        timestamp: timestamp.clone(),
                    },
                ));
            }
            None => {
                // Removed key: leave the was-block at the end of the section.
                section_table(&mut new_doc, section, scratch)?;
                attach_tail(
                    &mut new_doc,
                    section,
                    &WasEntry {
                        value: entry_value,
                        timestamp: timestamp.clone(),
                    }
                    .render(),
                );
            }
        }
    }
    Ok(new_doc.to_string())
}

/// Asks "re-edit?" on /dev/tty (never stdin, which scripts may redirect).
/// Defaults to yes in a terminal; without a terminal there is no one to
/// ask, so it defaults to no.
fn prompt_reedit() -> Result<bool> {
    let Ok(mut tty) = fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return Ok(false);
    };
    write!(tty, "re-edit? [Y/n] ")
        .and_then(|_| tty.flush())
        .context("Failed to prompt on /dev/tty")?;
    let mut answer = String::new();
    std::io::BufReader::new(tty.try_clone()?)
        .read_line(&mut answer)
        .context("Failed to read /dev/tty")?;
    let answer = answer.trim().to_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = path(dir.path());
        (dir, path)
    }

    #[test]
    fn set_and_load_roundtrip() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        set_value(&path, "server.www", &["true".to_string()]).unwrap();
        set_value(
            &path,
            "client.edge-map",
            &["left=auto".to_string(), "top=auto".to_string()],
        )
        .unwrap();
        set_value(&path, "client.bulk-throttle-mbps", &["40".to_string()]).unwrap();
        let file = load(&path).unwrap();
        assert_eq!(file.get_int::<u16>("server.port"), Some(4321));
        assert_eq!(file.get_bool("server.www"), Some(true));
        assert_eq!(
            file.get_str_vec("client.edge-map").unwrap(),
            vec!["left=auto".to_string(), "top=auto".to_string()]
        );
        assert_eq!(file.get_f64("client.bulk-throttle-mbps"), Some(40.0));
        assert!(file.unknown.is_empty() && file.invalid.is_empty() && file.aliased.is_empty());
    }

    #[test]
    fn config_file_is_owner_only_and_atomic() {
        let (dir, path) = tmp_config();
        set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "config.toml must be 0600");
        // The atomic tmp+rename must not leave scratch files behind.
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != CONFIG_FILE_NAME)
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {:?}", leftovers);
    }

    #[test]
    fn set_validates_each_kind() {
        let (_dir, path) = tmp_config();
        // bool
        assert!(set_value(&path, "server.www", &["yes".to_string()]).is_err());
        assert!(set_value(&path, "server.www", &["true".to_string()]).is_ok());
        // int: junk, 0, and out of range
        assert!(set_value(&path, "server.port", &["abc".to_string()]).is_err());
        assert!(set_value(&path, "server.port", &["0".to_string()]).is_err());
        assert!(set_value(&path, "server.port", &["70000".to_string()]).is_err());
        // float: junk and out of the scale range
        assert!(set_value(&path, "client.mouse-scale", &["fast".to_string()]).is_err());
        assert!(set_value(&path, "client.mouse-scale", &["100".to_string()]).is_err());
        // string: per-key validation (listen is an IP)
        assert!(set_value(&path, "server.listen", &["999.1.1.1".to_string()]).is_err());
        assert!(set_value(&path, "server.shortcut", &["notakey,nope".to_string()]).is_err());
        // array: per-item and whole-array validation
        assert!(set_value(&path, "server.edge-map", &["sideways=auto".to_string()]).is_err());
        assert!(set_value(&path, "server.fingerprint", &["not-hex!".to_string()]).is_err());
        assert!(set_value(&path, "client.edge-map", &["left=aa11bb".to_string()]).is_err());
        // scalars reject multiple values
        assert!(set_value(&path, "server.port", &["1".to_string(), "2".to_string()]).is_err());
        // ...and the failures wrote nothing.
        let file = load(&path).unwrap();
        assert_eq!(file.get_bool("server.www"), Some(true));
        assert!(file.get_int::<u16>("server.port").is_none());
        assert!(file.get_str_vec("server.edge-map").is_none());
    }

    #[test]
    fn clipboard_kb_validation_caps_at_the_overflow_boundary() {
        // The ceiling is exactly the value whose KB→bytes conversion (a
        // checked *1024 in main.rs) cannot overflow: the daemon must never
        // refuse to start over a config value the validator accepted.
        let cap = MAX_CLIPBOARD_SIZE_KB;
        assert!(cap.checked_mul(1024).is_some());
        assert!(v_clipboard_kb(&[&cap.to_string()]).is_ok());
        assert!(v_clipboard_kb(&[&(cap + 1).to_string()]).is_err());
        assert!(v_clipboard_kb(&[&u64::MAX.to_string()]).is_err());
        assert!(v_clipboard_kb(&["5120"]).is_ok());
        assert!(v_clipboard_kb(&["0"]).is_ok());
        assert!(v_clipboard_kb(&["-1"]).is_err());
    }

    #[test]
    fn unknown_keys_load_but_are_reported() {
        let file = File::parse("[server]\nport = 4321\nfrobnicate = 1\n\n[bogus]\nx = 2\n").unwrap();
        // Known values still load; unknown keys land in the warn-list.
        assert_eq!(file.get_int::<u16>("server.port"), Some(4321));
        let mut unknown = file.unknown.clone();
        unknown.sort();
        assert_eq!(unknown, vec!["bogus.x".to_string(), "server.frobnicate".to_string()]);
    }

    #[test]
    fn removed_no_auto_hotspot_key_warns_and_is_ignored() {
        // 'client.no-auto-hotspot' went away with the hotspot feature in
        // v10.0.0: an existing config carrying it must hit the staleness
        // policy — warned about (unknown list) and ignored, never an error.
        let file = File::parse("[client]\nmouse-scale = 0.5\nno-auto-hotspot = true\n").unwrap();
        assert_eq!(file.unknown, vec!["client.no-auto-hotspot".to_string()]);
        assert!(file.invalid.is_empty());
        // The rest of the file still loads.
        assert_eq!(file.get_f64("client.mouse-scale"), Some(0.5));
        assert!(file.get_bool("client.no-auto-hotspot").is_none());
    }

    #[test]
    fn invalid_values_are_reported_and_skipped() {
        let file = File::parse("[server]\nport = \"not-a-port\"\nwww = true\n").unwrap();
        assert_eq!(file.get_bool("server.www"), Some(true));
        assert!(file.get_int::<u16>("server.port").is_none());
        assert_eq!(file.invalid.len(), 1);
        assert_eq!(file.invalid[0].0, "server.port");
    }

    #[test]
    fn malformed_toml_is_a_load_error() {
        assert!(File::parse("[server\nport = 1").is_err());
        let (dir, path) = tmp_config();
        fs::write(&path, "[server\nport = 1").unwrap();
        assert!(load(&path).is_err());
        // ...but the daemon loader degrades to an empty config, never fails.
        let file = load_for_daemon(dir.path());
        assert!(file.get_int::<u16>("server.port").is_none());
    }

    #[test]
    fn did_you_mean_suggests_close_keys() {
        assert_eq!(did_you_mean("servre.shortcut"), Some("server.shortcut"));
        assert_eq!(did_you_mean("client.mouse-sacle"), Some("client.mouse-scale"));
        assert_eq!(did_you_mean("zzz"), None);
    }

    #[test]
    fn keys_since_reports_only_newer_entries() {
        // Everything predating the baseline, and everything at it, is old
        // news; keys added later are what the daemon announces.
        assert_eq!(keys_since("7.3.0").len(), REGISTRY.len());
        assert_eq!(keys_since("7.3").len(), REGISTRY.len());
        assert_eq!(keys_since("99.0.0").len(), 0);

        // The post-baseline keys are exactly the ones whose `since` says so —
        // asserted against the registry rather than a hard-coded count, so
        // adding a key doesn't mean editing this test.
        let announced = keys_since(BASELINE_SINCE);
        let expected: Vec<&str> = REGISTRY
            .iter()
            .filter(|s| s.since != BASELINE_SINCE)
            .map(|s| s.key)
            .collect();
        assert_eq!(
            announced.iter().map(|s| s.key).collect::<Vec<_>>(),
            expected
        );
        // A user upgrading FROM a version that already had them hears nothing.
        for spec in &announced {
            assert!(keys_since(spec.since).iter().all(|s| s.key != spec.key));
        }
    }

    #[test]
    fn validate_reports_unknown_and_invalid_with_lines_and_cleanup() {
        let (_dir, path) = tmp_config();
        fs::write(
            &path,
            "[server]\nport = 4321\nfrobnicate = 1\n\n[client]\nmouse-scale = 999\n",
        )
        .unwrap();
        let issues = validate_file(&path).unwrap();
        assert_eq!(issues.len(), 2);
        let unknown = issues
            .iter()
            .find(|i| i.message.contains("frobnicate"))
            .unwrap();
        assert_eq!(unknown.line, Some(3));
        assert!(matches!(unknown.severity, Severity::Warning));
        assert!(unknown.message.contains("server.frobnicate"));
        assert_eq!(
            unknown.cleanup.as_deref(),
            Some("mx config unset server.frobnicate")
        );
        let invalid = issues
            .iter()
            .find(|i| i.message.contains("mouse-scale"))
            .unwrap();
        assert_eq!(invalid.line, Some(6));
        assert!(matches!(invalid.severity, Severity::Error));
        // A key above the first section header has no <section>.<flag> name,
        // so no cleanup command is printed for it — the one we used to print
        // could never have worked.
        fs::write(&path, "port = 1213\n[server]\nwww = true\n").unwrap();
        let issues = validate_file(&path).unwrap();
        assert_eq!(issues.len(), 1);
        assert!(matches!(issues[0].severity, Severity::Warning));
        assert!(
            issues[0].message.contains("'port' sits outside any section"),
            "{}",
            issues[0].message
        );
        assert_eq!(issues[0].cleanup, None);
        let err = unset_value(&path, "port").unwrap_err();
        assert!(err.to_string().contains("unknown config key"), "{}", err);
    }

    #[test]
    fn inline_table_section_is_refused_instead_of_reported_as_default() {
        let (_dir, path) = tmp_config();
        // A hand-written inline-table section is a real override: the load
        // path takes it and the daemon runs on it.
        fs::write(&path, "server = { port = 4321 }\n").unwrap();
        assert_eq!(load(&path).unwrap().get_int::<u16>("server.port"), Some(4321));
        assert!(validate_file(&path).unwrap().is_empty());
        // So `unset` must refuse it out loud, the way `set` already does,
        // rather than claim the key is at its default and change nothing.
        for err in [
            unset_value(&path, "server.port").unwrap_err(),
            set_value(&path, "server.port", &["5555".to_string()]).unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("is a value, not a [section] table"),
                "{}",
                err
            );
        }
        assert_eq!(read_text(&path), "server = { port = 4321 }\n");
        // `history` agrees with `show`: the key is set, it just has no stack
        // (an inline table has nowhere to keep one).
        let all = read_history(&path).unwrap();
        let port = all.iter().find(|h| h.spec.key == "server.port").unwrap();
        assert_eq!(port.current.as_deref(), Some("4321"));
        assert!(port.entries.is_empty());
        // A key the inline section does not carry is genuinely at its default.
        assert!(matches!(
            unset_value(&path, "server.www").unwrap(),
            UnsetOutcome::AlreadyDefault(_)
        ));
    }

    #[test]
    fn validate_clean_or_missing_file_has_no_issues() {
        let (_dir, path) = tmp_config();
        fs::write(&path, "[server]\nport = 4321\nwww = true\n").unwrap();
        assert!(validate_file(&path).unwrap().is_empty());
        // A missing file is clean.
        let (_dir2, missing) = tmp_config();
        assert!(validate_file(&missing).unwrap().is_empty());
    }

    #[test]
    fn validate_malformed_toml_reports_a_syntax_error() {
        let (_dir, path) = tmp_config();
        fs::write(&path, "[server\nport = 1").unwrap();
        let issues = validate_file(&path).unwrap();
        assert_eq!(issues.len(), 1);
        assert!(matches!(issues[0].severity, Severity::Error));
        assert!(issues[0].message.contains("TOML syntax error"));
    }

    #[test]
    fn unset_removes_overrides_and_stale_keys() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        match unset_value(&path, "server.port").unwrap() {
            UnsetOutcome::Removed(spec, old) => {
                assert_eq!(spec.key, "server.port");
                assert_eq!(old, "4321");
            }
            other => panic!("expected Removed, got {:?}", other),
        }
        assert!(matches!(
            unset_value(&path, "server.port").unwrap(),
            UnsetOutcome::AlreadyDefault(_)
        ));
        // Unknown (stale) keys present in the file can be removed — that is
        // exactly the cleanup path 'validate' prints.
        fs::write(&path, "[server]\nfrobnicate = 1\n").unwrap();
        assert!(matches!(
            unset_value(&path, "server.frobnicate").unwrap(),
            UnsetOutcome::RemovedUnknown(..)
        ));
        // ...but a key that is neither known nor in the file is an error.
        let err = unset_value(&path, "server.frobnicate").unwrap_err();
        assert!(err.to_string().contains("unknown config key"));
        assert!(err.to_string().contains("valid server keys"));
    }

    #[test]
    fn float_keys_accept_integer_toml_values() {
        // `bulk-throttle-mbps = 40` (integer) is a valid spelling of 40 Mbps.
        let file = File::parse("[server]\nbulk-throttle-mbps = 40\n").unwrap();
        assert_eq!(file.get_f64("server.bulk-throttle-mbps"), Some(40.0));
    }

    #[test]
    fn effective_marks_value_sources() {
        let file = File::parse("[server]\nport = 4321\n").unwrap();
        let all = effective(&file);
        let port = all.iter().find(|e| e.spec.key == "server.port").unwrap();
        assert!(port.from_file);
        assert_eq!(port.rendered, "4321");
        let www = all.iter().find(|e| e.spec.key == "server.www").unwrap();
        assert!(!www.from_file);
        assert_eq!(www.rendered, "false");
    }

    #[test]
    fn announce_new_keys_records_last_version() {
        let dir = tempfile::tempdir().unwrap();
        // Fresh install: the version is recorded, nothing announced.
        announce_new_keys(dir.path(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            fs::read_to_string(dir.path().join(LAST_VERSION_FILE))
                .unwrap()
                .trim(),
            env!("CARGO_PKG_VERSION")
        );
        // Same version again: the file is left alone.
        announce_new_keys(dir.path(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            fs::read_to_string(dir.path().join(LAST_VERSION_FILE))
                .unwrap()
                .trim(),
            env!("CARGO_PKG_VERSION")
        );
        // An upgrade rewrites the record.
        announce_new_keys(dir.path(), "99.0.0");
        assert_eq!(
            fs::read_to_string(dir.path().join(LAST_VERSION_FILE))
                .unwrap()
                .trim(),
            "99.0.0"
        );
    }

    // --- History (# was: comments) ----------------------------------------

    fn read_text(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    /// The was-stack of one key as (value, timestamp) pairs, newest first.
    fn stack_of(path: &Path, key: &str) -> Vec<(String, String)> {
        read_history(path)
            .unwrap()
            .into_iter()
            .find(|h| h.spec.key == key)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| (e.value, e.timestamp))
            .collect()
    }

    #[test]
    fn comments_and_formatting_survive_set_and_unset() {
        let (_dir, path) = tmp_config();
        fs::write(
            &path,
            "# monux config — hand-maintained\n\n[server] # server side\n# keep this note\nport = 4321 # inline note\n\n[client]\nwww = true\n",
        )
        .unwrap();
        set_value(&path, "server.port", &["5555".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(text.contains("# monux config — hand-maintained"));
        assert!(text.contains("[server] # server side"));
        assert!(text.contains("# keep this note"));
        assert!(text.contains("port = 5555 # inline note"));
        assert!(text.contains("[client]\nwww = true\n"));
        unset_value(&path, "server.port").unwrap();
        let text = read_text(&path);
        assert!(text.contains("# keep this note"));
        assert!(text.contains("[client]\nwww = true\n"));
        assert!(!text.contains("port = "));
        // The daemon load path is unaffected by any of this.
        assert_eq!(load(&path).unwrap().get_bool("client.www"), Some(true));
    }

    #[test]
    fn indented_keys_keep_their_indent_across_mutations() {
        let (_dir, path) = tmp_config();
        // The key's own indent sits BELOW the was-stack in the key's prefix.
        // It is neither head nor stack: counting it into the head sliced the
        // head out of the middle of the newest was-line.
        fs::write(
            &path,
            "[server]\n# was: 1000 @ 2026-07-25T01:12:03Z\n  port = 4321\n",
        )
        .unwrap();
        set_value(&path, "server.port", &["5555".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(text.contains("\n  port = 5555\n"), "indent kept:\n{}", text);
        assert!(!text.contains("\n# \n"), "no sliced was-line:\n{}", text);
        let values: Vec<String> = stack_of(&path, "server.port")
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(values, vec!["4321", "1000"]);
        // Revert rebuilds the same block, indent included.
        revert_value(&path, "server.port", None).unwrap();
        let text = read_text(&path);
        assert!(text.contains("\n  port = 4321\n"), "indent kept:\n{}", text);

        // An indented key with no history yet keeps its indent too.
        fs::write(&path, "[server]\n  www = true\n").unwrap();
        set_value(&path, "server.www", &["false".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(text.contains("\n  www = false\n"), "indent kept:\n{}", text);
        assert_eq!(stack_of(&path, "server.www").len(), 1);
        // Unsetting takes the indent with the key line: the was-block that
        // stays behind is left at column 0, with no blank-but-spaced line.
        unset_value(&path, "server.www").unwrap();
        let text = read_text(&path);
        assert!(
            text.lines().all(|l| l.trim().is_empty() == l.is_empty()),
            "no whitespace-only line:\n{:?}",
            text
        );
        assert_eq!(stack_of(&path, "server.www").len(), 2);

        // An indent longer than "# was: " used to cut the banked value at a
        // byte that is not a char boundary — a panic mid-command, reachable
        // from `mx config set server.device` with a non-ASCII device name.
        fs::write(
            &path,
            "[server]\n# was: [\"Clavier Français\"] @ 2026-07-25T01:12:03Z\n          device = [\"kbd\"]\n",
        )
        .unwrap();
        set_value(&path, "server.device", &["mouse".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(
            text.contains("\n          device = [\"mouse\"]\n"),
            "indent kept:\n{}",
            text
        );
        let values: Vec<String> = stack_of(&path, "server.device")
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(values, vec!["[\"kbd\"]", "[\"Clavier Français\"]"]);
    }

    #[test]
    fn set_banks_was_entries_newest_first() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.shortcut", &["leftshift,leftalt,r".to_string()]).unwrap();
        set_value(&path, "server.shortcut", &["leftshift,leftalt,q".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(
            text.contains("# was: \"leftshift,leftalt,r\" @ "),
            "was-entry in:\n{}",
            text
        );
        // The comment sits directly above the key.
        let pos_was = text.find("# was: ").unwrap();
        let pos_key = text.find("shortcut = ").unwrap();
        assert!(pos_was < pos_key);
        assert_eq!(stack_of(&path, "server.shortcut").len(), 1);
        // Arrays render inline.
        set_value(&path, "server.edge-map", &["right=auto".to_string()]).unwrap();
        set_value(
            &path,
            "server.edge-map",
            &["right=auto".to_string(), "left=aa11bb".to_string()],
        )
        .unwrap();
        let stack = stack_of(&path, "server.edge-map");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].0, "[\"right=auto\"]");
    }

    #[test]
    fn same_value_set_is_a_complete_noop() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        let before = read_text(&path);
        let outcome = set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        assert!(outcome.unchanged);
        assert_eq!(read_text(&path), before, "no file write on a no-op set");
        assert!(stack_of(&path, "server.port").is_empty());
        // Float keys normalize: 40 stored, set "40" again — still a no-op.
        set_value(&path, "client.bulk-throttle-mbps", &["40".to_string()]).unwrap();
        let before = read_text(&path);
        assert!(set_value(&path, "client.bulk-throttle-mbps", &["40".to_string()])
            .unwrap()
            .unchanged);
        assert_eq!(read_text(&path), before);
    }

    #[test]
    fn sixth_set_drops_the_oldest_entry() {
        let (_dir, path) = tmp_config();
        for port in [1000, 1001, 1002, 1003, 1004, 1005, 1006] {
            set_value(&path, "server.port", &[port.to_string()]).unwrap();
        }
        let stack = stack_of(&path, "server.port");
        assert_eq!(stack.len(), HISTORY_CAP);
        let values: Vec<&str> = stack.iter().map(|(v, _)| v.as_str()).collect();
        assert_eq!(values, vec!["1005", "1004", "1003", "1002", "1001"]);
    }

    #[test]
    fn setting_a_value_equal_to_a_stack_entry_still_pushes() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["1000".to_string()]).unwrap();
        set_value(&path, "server.port", &["2000".to_string()]).unwrap();
        set_value(&path, "server.port", &["1000".to_string()]).unwrap();
        let stack = stack_of(&path, "server.port");
        // A real transition: 1000 was already in the stack, 2000 is banked.
        let values: Vec<&str> = stack.iter().map(|(v, _)| v.as_str()).collect();
        assert_eq!(values, vec!["2000", "1000"]);
    }

    #[test]
    fn unset_banks_the_value_and_leaves_the_block() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["4321".to_string()]).unwrap();
        set_value(&path, "server.www", &["true".to_string()]).unwrap();
        unset_value(&path, "server.port").unwrap();
        let text = read_text(&path);
        assert!(!text.contains("port ="), "key line removed:\n{}", text);
        assert!(text.contains("# was: 4321 @ "), "was-block in:\n{}", text);
        assert!(load(&path).unwrap().get_int::<u16>("server.port").is_none());
        assert_eq!(stack_of(&path, "server.port").len(), 1);
        // Unset-when-unset is a no-op: same bytes, AlreadyDefault.
        let before = read_text(&path);
        assert!(matches!(
            unset_value(&path, "server.port").unwrap(),
            UnsetOutcome::AlreadyDefault(_)
        ));
        assert_eq!(read_text(&path), before);
        // ...also when nothing was ever set.
        assert!(matches!(
            unset_value(&path, "server.listen").unwrap(),
            UnsetOutcome::AlreadyDefault(_)
        ));
    }

    #[test]
    fn revert_pops_newest_and_banks_current() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["1000".to_string()]).unwrap();
        set_value(&path, "server.port", &["2000".to_string()]).unwrap();
        let outcome = revert_value(&path, "server.port", None).unwrap();
        assert_eq!(outcome.restored, "1000");
        assert_eq!(outcome.replaced.as_deref(), Some("2000"));
        assert_eq!(load(&path).unwrap().get_int::<u16>("server.port"), Some(1000));
        // The revert is itself undoable.
        let stack = stack_of(&path, "server.port");
        let values: Vec<&str> = stack.iter().map(|(v, _)| v.as_str()).collect();
        assert_eq!(values, vec!["2000"]);
        let outcome = revert_value(&path, "server.port", None).unwrap();
        assert_eq!(outcome.restored, "2000");
        assert_eq!(load(&path).unwrap().get_int::<u16>("server.port"), Some(2000));
        let stack = stack_of(&path, "server.port");
        let values: Vec<&str> = stack.iter().map(|(v, _)| v.as_str()).collect();
        assert_eq!(values, vec!["1000"]);
    }

    #[test]
    fn revert_recreates_an_unset_key() {
        let (_dir, path) = tmp_config();
        set_value(&path, "server.shortcut", &["leftshift,leftalt,q".to_string()]).unwrap();
        unset_value(&path, "server.shortcut").unwrap();
        let outcome = revert_value(&path, "server.shortcut", None).unwrap();
        assert_eq!(outcome.restored, "\"leftshift,leftalt,q\"");
        assert_eq!(outcome.replaced, None);
        assert_eq!(
            load(&path).unwrap().get_str("server.shortcut").as_deref(),
            Some("leftshift,leftalt,q")
        );
        assert!(stack_of(&path, "server.shortcut").is_empty());
    }

    #[test]
    fn revert_to_an_older_timestamp() {
        let (_dir, path) = tmp_config();
        fs::write(
            &path,
            "[server]\n# was: 2000 @ 2026-07-25T01:12:04Z\n# was: 1000 @ 2026-07-25T01:12:03Z\nport = 3000\n",
        )
        .unwrap();
        let outcome = revert_value(&path, "server.port", Some("2026-07-25T01:12:03Z")).unwrap();
        assert_eq!(outcome.restored, "1000");
        // The current value was banked, the matching entry popped.
        let stack = stack_of(&path, "server.port");
        let values: Vec<&str> = stack.iter().map(|(v, _)| v.as_str()).collect();
        assert_eq!(values, vec!["3000", "2000"]);
    }

    #[test]
    fn revert_errors_on_missing_history_and_unknown_timestamp() {
        let (_dir, path) = tmp_config();
        let err = revert_value(&path, "server.port", None).unwrap_err();
        assert!(err.to_string().contains("no history"), "{}", err);
        set_value(&path, "server.port", &["1000".to_string()]).unwrap();
        set_value(&path, "server.port", &["2000".to_string()]).unwrap();
        let err = revert_value(&path, "server.port", Some("1999-12-31T23:59:59Z")).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("no history entry"), "{}", msg);
        assert!(msg.contains("available:"), "{}", msg);
        // The available timestamps are listed.
        let ts = stack_of(&path, "server.port")[0].1.clone();
        assert!(msg.contains(&ts), "{}", msg);
        // Unknown keys get the usual error.
        assert!(revert_value(&path, "server.bogus", None).is_err());
    }

    #[test]
    fn revert_revalidates_the_recorded_value() {
        let (_dir, path) = tmp_config();
        fs::write(
            &path,
            "[server]\n# was: 99999 @ 2026-07-25T01:12:03Z\nport = 4321\n",
        )
        .unwrap();
        let err = revert_value(&path, "server.port", None).unwrap_err();
        assert!(err.to_string().contains("no longer validates"), "{}", err);
        // Nothing changed.
        assert_eq!(load(&path).unwrap().get_int::<u16>("server.port"), Some(4321));
    }

    #[test]
    fn malformed_was_lines_are_neither_listed_nor_pruned() {
        let (_dir, path) = tmp_config();
        let original = "[server]\n# was: hello\n# was: 1 @ not-a-timestamp\n# was: 1 @ 2026-13-99T99:99:99Z\n# a human note\nport = 4321\n";
        fs::write(&path, original).unwrap();
        // None of these parse as history — the key has no stack.
        assert!(stack_of(&path, "server.port").is_empty());
        // A mutation leaves every one of them untouched.
        set_value(&path, "server.port", &["5555".to_string()]).unwrap();
        let text = read_text(&path);
        assert!(text.contains("# was: hello\n"));
        assert!(text.contains("# was: 1 @ not-a-timestamp\n"));
        assert!(text.contains("# was: 1 @ 2026-13-99T99:99:99Z\n"));
        assert!(text.contains("# a human note\n"));
        // Only the one strict entry we just wrote is listed.
        assert_eq!(stack_of(&path, "server.port").len(), 1);
        // A valid was-line above a malformed one is not "directly above the
        // key" either — the malformed line shields it.
        fs::write(
            &path,
            "[server]\n# was: 1000 @ 2026-07-25T01:12:03Z\n# was: oops\nport = 4321\n",
        )
        .unwrap();
        assert!(stack_of(&path, "server.port").is_empty());
    }

    #[test]
    fn edit_diff_injects_was_for_changed_and_removed_keys_only() {
        let (_dir, path) = tmp_config();
        fs::write(
            &path,
            "[server]\nport = 4321\nshortcut = \"leftshift,leftalt,r\"\nwww = true\n",
        )
        .unwrap();
        let scratch = path.with_extension("edit-test");
        // port unchanged, shortcut changed, www removed, motion-hz added.
        fs::write(
            &scratch,
            "[server]\nport = 4321\nshortcut = \"leftshift,leftalt,q\"\nmotion-hz = 250\n",
        )
        .unwrap();
        let installed = inject_edit_history(&path, &scratch).unwrap();
        // Changed key: the old value is banked directly above it.
        let shortcut_pos = installed.find("shortcut = ").unwrap();
        let was_pos = installed
            .find("# was: \"leftshift,leftalt,r\" @ ")
            .unwrap();
        assert!(was_pos < shortcut_pos, "{}", installed);
        // Removed key: a was-block exists for it (at the section end).
        assert!(installed.contains("# was: true @ "), "{}", installed);
        // Unchanged and added keys get nothing.
        assert!(!installed.contains("# was: 4321"), "{}", installed);
        let motion_pos = installed.find("motion-hz = ").unwrap();
        assert!(!installed[..motion_pos].contains("# was: 250"), "{}", installed);
        // The result parses and holds the new values.
        let file = File::parse(&installed).unwrap();
        assert_eq!(
            file.get_str("server.shortcut").as_deref(),
            Some("leftshift,leftalt,q")
        );
        assert!(file.get_bool("server.www").is_none());
        // And the injected history is revertable.
        fs::write(&path, &installed).unwrap();
        assert_eq!(stack_of(&path, "server.shortcut").len(), 1);
        assert_eq!(stack_of(&path, "server.www").len(), 1);
        let outcome = revert_value(&path, "server.www", None).unwrap();
        assert_eq!(outcome.restored, "true");
        assert_eq!(load(&path).unwrap().get_bool("server.www"), Some(true));
    }

    /// An executable stub $EDITOR that overwrites the file it is handed with
    /// `content`, standing in for the user's editing session.
    fn stub_editor(dir: &Path, name: &str, content: &str) -> PathBuf {
        let script = dir.join(name);
        fs::write(
            &script,
            format!("#!/bin/sh\ncat > \"$1\" <<'MONUX_EOF'\n{}MONUX_EOF\n", content),
        )
        .unwrap();
        fs::set_permissions(&script, PermissionsExt::from_mode(0o755)).unwrap();
        script
    }

    #[test]
    fn edit_keeps_the_scratch_when_the_install_fails() {
        let (dir, path) = tmp_config();
        fs::write(&path, "[server]\nport = 4321\n").unwrap();
        let scratch = PathBuf::from(format!("{}.edit-{}", path.display(), std::process::id()));
        // $EDITOR is process-global; no other test reads it.
        let editor = stub_editor(dir.path(), "rewrite.sh", "server = { www = true }\n");
        std::env::set_var("EDITOR", &editor);
        // This edit is valid TOML with valid values, so it clears the editor
        // loop's checks and only the history injection fails — i.e. a failure
        // strictly after the user has done the work, when the scratch holds
        // the only copy of it.
        let err = cli_edit(&path).unwrap_err();
        assert!(
            format!("{:#}", err).contains("your edits are kept in"),
            "{:#}",
            err
        );
        assert_eq!(read_text(&scratch), "server = { www = true }\n");
        assert_eq!(
            read_text(&path),
            "[server]\nport = 4321\n",
            "a failed install leaves the config alone"
        );
        // A clean run installs and takes the scratch with it.
        let editor = stub_editor(dir.path(), "ok.sh", "[server]\nport = 5555\n");
        std::env::set_var("EDITOR", &editor);
        assert!(cli_edit(&path).unwrap());
        assert_eq!(load(&path).unwrap().get_int::<u16>("server.port"), Some(5555));
        assert!(!scratch.exists(), "no scratch left behind on success");
        std::env::remove_var("EDITOR");
    }

    #[test]
    fn timestamps_are_rfc3339_seconds_utc() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(86400), "1970-01-02T00:00:00Z");
        assert_eq!(format_timestamp(1735689600), "2025-01-01T00:00:00Z");
        assert_eq!(format_timestamp(1767225600), "2026-01-01T00:00:00Z");
        // The strict parser accepts what we write and rejects lookalikes.
        assert!(valid_timestamp("2026-07-25T01:12:03Z"));
        assert!(!valid_timestamp("2026-13-25T01:12:03Z"));
        assert!(!valid_timestamp("2026-07-25T25:12:03Z"));
        assert!(!valid_timestamp("2026-07-25 01:12:03Z"));
        assert!(!valid_timestamp("2026-07-25T01:12:03+00:00"));
        assert!(!valid_timestamp("not-a-timestamp"));
        // Written entries always carry a valid timestamp.
        let (_dir, path) = tmp_config();
        set_value(&path, "server.port", &["1000".to_string()]).unwrap();
        set_value(&path, "server.port", &["2000".to_string()]).unwrap();
        let ts = &stack_of(&path, "server.port")[0].1;
        assert!(valid_timestamp(ts));
    }
}
