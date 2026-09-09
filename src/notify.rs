//! Best-effort desktop notifications via notify-send (libnotify), shared by
//! the switch, update, connection-lifecycle, and link-quality call sites.
//!
//! Every notification KIND carries a distinct
//! `x-canonical-private-synchronous` id, so repeats of the same kind replace
//! the previous one instead of stacking, while different kinds never replace
//! each other. Current ids: `monux-switch`, `monux-update`, `monux-client`
//! (server-side roster changes), `monux-connection` (client-side
//! connect/lost), `monux-link` (degradation/recovery), `monux-indicator`
//! (tray indicator action feedback).
//!
//! Under `cargo test` (the lib's cfg(test) build) notifications are
//! suppressed: unit tests exercise call sites that notify for real (the
//! rotation pause/switch tests among them), and the popups must not spam the
//! developer's desktop — they previously looked exactly like a phantom
//! daemon pausing itself.

#[cfg(not(test))]
use std::process::{Command, Stdio};

/// notify-send urgency (-u).
#[derive(Clone, Copy)]
pub enum Urgency {
    Low,
    Normal,
}

impl Urgency {
    #[cfg(not(test))]
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn as_str(self) -> &'static str {
        match self {
            Urgency::Low => "low",
            Urgency::Normal => "normal",
        }
    }
}

/// Shows a desktop notification, fire-and-forget: spawning notify-send never
/// blocks the caller, and any failure (missing binary, no session bus, root
/// without -E) is silently ignored — notifications are strictly best-effort.
/// `id` is the x-canonical-private-synchronous hint (see module docs).
/// Safe to call from any thread: std::process needs no tokio runtime, unlike
/// tokio::process, whose spawn panics ("there is no reactor running") on
/// plain threads such as the tray indicator's menu-action callbacks.
#[cfg(not(test))]
pub fn notify(id: &str, urgency: Urgency, timeout_ms: u32, summary: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = (id, urgency, timeout_ms);
        notify_macos(summary, body);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let timeout = timeout_ms.to_string();
        let hint = format!("string:x-canonical-private-synchronous:{}", id);
        if let Ok(mut child) = Command::new("notify-send")
            .args([
                "-a",
                "monux",
                "-u",
                urgency.as_str(),
                "-t",
                &timeout,
                "-h",
                &hint,
                summary,
                body,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            // Reap the child so notify-send doesn't linger as a zombie for the
            // lifetime of long-lived daemons (tokio::process used to reap for us).
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

/// macOS delivery: osascript Notification Center, fire-and-forget like
/// notify-send. The script text is escaped, not quoted raw — a body with a
/// quote or backslash would otherwise break out of the AppleScript string.
#[cfg(all(not(test), target_os = "macos"))]
fn notify_macos(summary: &str, body: &str) {
    let escape = |s: &str| {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    };
    let script = format!(
        "display notification {} with title {}",
        escape(body),
        escape(summary)
    );
    if let Ok(mut child) = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        // Reap, as with notify-send.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

/// Test builds notify nothing: unit tests drive call sites that fire real
/// notifications (pause/switch, connection lifecycle), and 'cargo test' must
/// not popup-spam the developer's desktop (see the module docs).
#[cfg(test)]
pub fn notify(_id: &str, _urgency: Urgency, _timeout_ms: u32, _summary: &str, _body: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the tray-indicator panic: notify() must not need a
    /// tokio runtime (the indicator calls it from ksni's plain service
    /// thread, where tokio::process spawning panicked with "there is no
    /// reactor running"). Also passes without notify-send installed — a
    /// failed spawn is best-effort and swallowed, not a panic.
    #[test]
    fn notify_without_a_tokio_runtime_does_not_panic() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        notify("monux-test", Urgency::Low, 1, "monux", "test notification");
    }
}
