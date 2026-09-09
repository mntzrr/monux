pub mod alias;
pub mod autoupdate;
pub mod client;
pub mod clipboard;
pub mod config;
pub mod control;
pub mod device;
pub mod diagnostics;
pub mod discovery;
pub mod edge;
// Tray indicator: the model layer (poll, view, menu rows, action requests)
// is platform-agnostic; the ksni/D-Bus rendering inside is Linux-only and
// macOS gets an NSStatusItem renderer in indicator_macos.
#[cfg(target_os = "linux")]
pub mod indicator_spawn;
#[cfg(target_os = "macos")]
pub mod indicator_macos;
pub mod indicator;
pub mod known_servers;
pub mod logging;
pub mod msgs;
pub mod network;
pub mod notify;
pub mod rotation;
pub mod server;
pub mod servers;
// System integration: the optimization base set (udev rules, kernel modules,
// systemd units, sysctl) is Linux-only; `setup` also carries the shared
// autostart helpers, and macOS gets the login service via LaunchAgents in
// setup_macos. Uninstall (the `system` command) remains Linux-only.
pub mod setup;
#[cfg(target_os = "macos")]
pub mod setup_macos;
#[cfg(target_os = "linux")]
pub mod uninstall;
#[cfg(target_os = "macos")]
pub mod uninstall_macos;
pub mod single_instance;
pub mod update;

/// Set when the process begins a graceful shutdown (SIGINT/SIGTERM, control
/// socket exit, update restart). Long-running tasks use it to tell a channel
/// that closed because the process is tearing down (quiet, expected) from
/// one that closed unexpectedly (worth a warning).
pub static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Convenience for tasks: whether a graceful shutdown has begun.
pub fn shutting_down() -> bool {
    SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Marks the beginning of a graceful shutdown (see SHUTTING_DOWN).
pub fn mark_shutting_down() {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Locks a std Mutex, tolerating a poisoned one.
///
/// monux's mutexes guard plain bookkeeping — a supervisor's child handle, a
/// clipboard payload cache, certificate approval state — never an invariant
/// that a panic mid-update could leave half-applied. So poisoning carries no
/// information here, while `.unwrap()` on it converts one panic in one thread
/// into a permanently wedged subsystem for the lifetime of the process: a tray
/// that never comes back, a clipboard that never serves again, on a daemon
/// that is otherwise healthy.
///
/// The certificate verifier reasoned its way to this individually ("a
/// panicking prompt thread must not wedge certificate verification for the
/// lifetime of the process"); this is that decision, made once.
pub fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
