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
        expects: "direction=target (fingerprint-prefix|hostname|auto)",
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
        key: "client.no-auto-hotspot",
        section: Section::Client,
        flag: "no-auto-hotspot",
        expects: "true|false",
        default_display: "false",
        help: "do not join the server's advertised 'monux-direct' hotspot automatically",
        kind: Kind::Bool,
        validate: v_bool,
        since: BASELINE_SINCE,
    },
    KeySpec {
        key: "client.edge-map",
        section: Section::Client,
        flag: "edge-map",
        expects: "direction=auto",
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

/// Reads the file as a raw TOML document, preserving unknown keys and
/// sections `set`/`unset` don't manage. A missing file is an empty document.
fn read_doc(path: &Path) -> Result<toml::Table> {
    match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
        Ok(text) => toml::from_str(&text).with_context(|| {
            format!(
                "{} is not valid TOML; fix it with 'mx config edit' or check it with 'mx config validate'",
                path.display()
            )
        }),
    }
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
}

/// Validates and stores a config value. Scalars take exactly one value,
/// repeatable (array) keys one or more.
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
        Kind::Bool => toml::Value::from(refs[0].parse::<bool>().expect("validated above")),
        Kind::Int => toml::Value::from(refs[0].parse::<i64>().expect("validated above")),
        Kind::Float => toml::Value::from(refs[0].parse::<f64>().expect("validated above")),
        Kind::Str => toml::Value::from(refs[0]),
        Kind::StrArray => {
            toml::Value::Array(refs.iter().map(|s| toml::Value::from(*s)).collect())
        }
    };
    let mut doc = read_doc(path)?;
    match doc.get(spec.section.as_str()) {
        None => {
            doc.insert(
                spec.section.as_str().to_string(),
                toml::Value::Table(toml::Table::new()),
            );
        }
        Some(toml::Value::Table(_)) => {}
        Some(_) => bail!(
            "'{}' in {} is a value, not a [section] table",
            spec.section.as_str(),
            path.display()
        ),
    }
    let table = doc
        .get_mut(spec.section.as_str())
        .and_then(|v| v.as_table_mut())
        .expect("section table just ensured");
    let old = table.insert(spec.flag.to_string(), stored.clone());
    atomic_write(path, &toml::to_string(&doc).context("Failed to serialize config")?)?;
    Ok(SetOutcome {
        key: spec.key,
        new_value: stored.to_string(),
        old_value: old.map(|v| v.to_string()),
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

/// Removes a config value. Unknown keys error out — unless they are actually
/// present in the file, which is exactly the stale-key cleanup case.
pub fn unset_value(path: &Path, key: &str) -> Result<UnsetOutcome> {
    let mut doc = read_doc(path)?;
    let spec = find(key);
    let removed = match key.split_once('.') {
        Some((section, flag)) => doc
            .get_mut(section)
            .and_then(|v| v.as_table_mut())
            .and_then(|table| table.remove(flag)),
        None => None,
    };
    match (spec, removed) {
        (Some(spec), Some(old)) => {
            atomic_write(path, &toml::to_string(&doc).context("Failed to serialize config")?)?;
            Ok(UnsetOutcome::Removed(spec, old.to_string()))
        }
        (Some(spec), None) => Ok(UnsetOutcome::AlreadyDefault(spec)),
        (None, Some(old)) => {
            atomic_write(path, &toml::to_string(&doc).context("Failed to serialize config")?)?;
            Ok(UnsetOutcome::RemovedUnknown(key.to_string(), old.to_string()))
        }
        (None, None) => Err(unknown_key_error(key)),
    }
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
        if d <= 3 && best.map_or(true, |(_, bd)| d < bd) {
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
/// comparable tuple; None when the major.minor don't parse.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
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
        fs::copy(path, &scratch)
            .with_context(|| format!("Failed to copy {} for editing", path.display()))?;
    } else {
        atomic_write(&scratch, EDIT_HEADER)?;
    }
    let result = edit_loop(path, &scratch);
    let _ = fs::remove_file(&scratch);
    result
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
            atomic_write(path, &fs::read_to_string(scratch)?)?;
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
        assert_eq!(keys_since(BASELINE_SINCE).len(), 0);
        assert_eq!(keys_since("7.3.0").len(), REGISTRY.len());
        assert_eq!(keys_since("7.3").len(), REGISTRY.len());
        assert_eq!(keys_since("99.0.0").len(), 0);
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
}
