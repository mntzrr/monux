//! Watches the D-Bus session bus for desktop notifications and forwards them
//! to the server (client-side notification forwarding, protocol v19; see
//! shared::supports_notification_forwarding). Spawned per connection by the
//! client when `client.forward-notifications` is on, feeding an unbounded
//! channel the step loop drains into ClientEvent::Notification frames.
//!
//! Desktop notifications on Linux are method calls on
//! org.freedesktop.Notifications, so watching means asking the bus to turn
//! this connection into a MONITOR for the Notify match rule and reading the
//! matched calls off a MessageStream
//! (zbus::fdo::MonitoringProxy::become_monitor). The bus may refuse
//! monitoring (dbus-daemon policy); the watcher then logs once and exits, and
//! the step loop, seeing the channel close, drops its receiver — the feature
//! turns off without the connection noticing.
//!
//! The watcher is best-effort end to end: a session-bus restart ends the
//! monitor connection, a malformed Notify call is skipped, and a closed
//! channel is teardown. None of these are worth failing the connection over.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zbus::zvariant;

use crate::client::ForwardedNotification;

/// Cap on the bytes forwarded for each Notify field, cut on a char boundary
/// (the shared::encode_hostname pattern). The events stream is where input
/// frames live; a notification body is a chat message, not an attachment.
const MAX_APP_NAME_BYTES: usize = 64;
const MAX_SUMMARY_BYTES: usize = 256;
const MAX_BODY_BYTES: usize = 1024;

/// Identical (app, summary, body) triples re-seen within this window are
/// dropped: progress-reporting apps re-notify constantly, and forwarding
/// every copy would spam the other machine.
const DEDUP_WINDOW: Duration = Duration::from_secs(10);

/// Rolling cap on forwarded notifications per minute across all apps: far
/// above anything a human generates, far below what a runaway app could.
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_PER_MINUTE: usize = 20;

/// The freedesktop Notify signature, reduced to what the call carries:
/// (app_name, replaces_id, app_icon, summary, body, actions, hints,
/// expire_timeout). Only app_name/summary/body/hints.urgency survive
/// sanitization; the rest is consumed to keep the signature honest.
type NotifyArgs<'a> = (
    String,
    u32,
    String,
    String,
    String,
    Vec<String>,
    HashMap<String, zvariant::Value<'a>>,
    i32,
);

/// Runs until the bus connection ends, the channel closes (connection
/// teardown), or shutdown begins. See the module docs.
pub async fn watch(tx: mpsc::UnboundedSender<ForwardedNotification>) {
    let conn = match zbus::Connection::session().await {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Notification forwarding unavailable: no D-Bus session bus: {}", e);
            return;
        }
    };
    let rule = match zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::MethodCall)
        .interface("org.freedesktop.Notifications")
        .and_then(|b| b.member("Notify"))
        .map(|b| b.build())
    {
        Ok(rule) => rule,
        Err(e) => {
            warn!("Notification forwarding unavailable: bad match rule: {}", e);
            return;
        }
    };
    let proxy = match zbus::fdo::MonitoringProxy::new(&conn).await {
        Ok(proxy) => proxy,
        Err(e) => {
            warn!("Notification forwarding unavailable: no monitoring proxy: {}", e);
            return;
        }
    };
    if let Err(e) = proxy.become_monitor(&[rule], 0).await {
        warn!(
            "Notification forwarding unavailable: the session bus refused monitor mode: {}",
            e
        );
        return;
    }
    info!("Watching the session bus for desktop notifications to forward");
    let mut stream = zbus::MessageStream::from(conn);
    let mut gate = RateLimiter::new();
    while let Some(msg) = stream.next().await {
        if tx.is_closed() {
            break;
        }
        let Ok(msg) = msg else {
            // A malformed monitored message: skip, don't die.
            continue;
        };
        let body = msg.body();
        let Ok((app_name, _, _, summary, body, _, hints, _)) =
            body.deserialize::<NotifyArgs>()
        else {
            continue;
        };
        let urgency = hints
            .get("urgency")
            .and_then(|v| v.downcast_ref::<u8>().ok())
            .unwrap_or(1);
        let Some(n) = sanitize(app_name, &summary, &body, urgency) else {
            continue;
        };
        let key = (n.app_name.clone(), n.summary.clone(), n.body.clone());
        if !gate.allow(&key, Instant::now()) {
            debug!(
                "Duplicate or over the rate cap, not forwarding [{}] {}",
                n.app_name, n.summary
            );
            continue;
        }
        debug!("Forwarding notification [{}] {}", n.app_name, n.summary);
        if tx.send(n).is_err() {
            break;
        }
    }
    debug!("Notification watcher stopped");
}

/// Cuts `s` to at most `max` bytes on a char boundary (see
/// shared::encode_hostname for the same pattern).
fn truncate_to(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The app names monux itself shows notifications under (notify.rs passes
/// "-a monux", and server::notify_forwarded re-displays forwarded ones under
/// the same app). Forwarding them would at best duplicate and at worst loop
/// between mutual-KVM machines, so the watcher drops them at the source.
fn excluded_app(app_name: &str) -> bool {
    matches!(app_name, "monux" | "monux-remote")
}

/// Turns a Notify call into the forwardable form, or None when it must not
/// be forwarded at all. Static filtering happens here; rate limiting happens
/// in RateLimiter.
fn sanitize(
    app_name: String,
    summary: &str,
    body: &str,
    urgency: u8,
) -> Option<ForwardedNotification> {
    if excluded_app(&app_name) {
        return None;
    }
    let app_name = truncate_to(&app_name, MAX_APP_NAME_BYTES).to_string();
    let summary = truncate_to(summary, MAX_SUMMARY_BYTES).to_string();
    if summary.is_empty() {
        return None;
    }
    let body = truncate_to(body, MAX_BODY_BYTES).to_string();
    Some(ForwardedNotification {
        app_name,
        summary,
        body,
        urgency,
    })
}

/// Dedup + rate limit for forwarded notifications. Time is injected so the
/// unit tests don't sleep.
struct RateLimiter {
    /// Last forward time per (app, summary, body) triple (DEDUP_WINDOW).
    recent: HashMap<(String, String, String), Instant>,
    /// Forward timestamps within the current RATE_WINDOW, oldest first.
    window: VecDeque<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            recent: HashMap::new(),
            window: VecDeque::new(),
        }
    }

    /// Whether the notification may be forwarded right now; true records it.
    fn allow(&mut self, key: &(String, String, String), now: Instant) -> bool {
        // Prune stale state first so neither structure grows without bound.
        self.recent.retain(|_, at| now.duration_since(*at) < DEDUP_WINDOW);
        while self
            .window
            .front()
            .is_some_and(|at| now.duration_since(*at) >= RATE_WINDOW)
        {
            self.window.pop_front();
        }
        if self.window.len() >= MAX_PER_MINUTE {
            return false;
        }
        if self.recent.contains_key(key) {
            return false;
        }
        self.recent.insert(key.clone(), now);
        self.window.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(app: &str, summary: &str) -> (String, String, String) {
        (app.to_string(), summary.to_string(), String::new())
    }

    #[test]
    fn truncate_cuts_on_char_boundaries() {
        assert_eq!(truncate_to("hello", 5), "hello");
        assert_eq!(truncate_to("hello", 10), "hello");
        // 21 '€' = 63 bytes; the 22nd would straddle a 64-byte cut.
        let euro = "\u{20ac}".repeat(30);
        assert_eq!(truncate_to(&euro, 64), "\u{20ac}".repeat(21));
        // A cut that lands between a multi-byte char's bytes backs up to the
        // last boundary, never producing invalid UTF-8.
        let cut = truncate_to(&euro, 65);
        assert_eq!(cut, "\u{20ac}".repeat(21));
        assert!(str::from_utf8(cut.as_bytes()).is_ok());
    }

    #[test]
    fn monux_app_names_are_excluded() {
        assert!(excluded_app("monux"));
        assert!(excluded_app("monux-remote"));
        assert!(!excluded_app("Signal"));
        assert!(!excluded_app("Monux")); // a real app, not us
    }

    #[test]
    fn sanitize_drops_excluded_and_empty_summary() {
        assert!(sanitize("monux".to_string(), "hi", "there", 1).is_none());
        assert!(sanitize("Signal".to_string(), "", "body", 1).is_none());
        let n = sanitize("Signal".to_string(), "hi", "hello", 2).unwrap();
        assert_eq!(n.app_name, "Signal");
        assert_eq!(n.summary, "hi");
        assert_eq!(n.body, "hello");
        assert_eq!(n.urgency, 2);
    }

    #[test]
    fn sanitize_caps_field_lengths() {
        let n = sanitize(
            "a".repeat(100),
            &"s".repeat(300),
            &"b".repeat(2000),
            1,
        )
        .unwrap();
        assert_eq!(n.app_name.len(), 64);
        assert_eq!(n.summary.len(), 256);
        assert_eq!(n.body.len(), 1024);
    }

    #[test]
    fn rate_limiter_allows_then_dedups() {
        let mut gate = RateLimiter::new();
        let t0 = Instant::now();
        let k = key("Signal", "hi");
        assert!(gate.allow(&k, t0));
        // The identical triple inside the dedup window is dropped...
        assert!(!gate.allow(&k, t0 + Duration::from_secs(5)));
        // ...a different one passes...
        assert!(gate.allow(&key("Signal", "bye"), t0 + Duration::from_secs(5)));
        // ...and the original passes again once the window has passed.
        assert!(gate.allow(&k, t0 + DEDUP_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn rate_limiter_caps_the_minute() {
        let mut gate = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..MAX_PER_MINUTE {
            assert!(
                gate.allow(&key("app", &i.to_string()), t0),
                "notification {} should pass",
                i
            );
        }
        assert!(!gate.allow(&key("app", "over"), t0));
        // One second later the cap still holds (window is a minute)...
        assert!(!gate.allow(&key("app", "still over"), t0 + Duration::from_secs(1)));
        // ...and after the window rolls, capacity frees up.
        let t1 = t0 + RATE_WINDOW + Duration::from_secs(1);
        assert!(gate.allow(&key("app", "fresh"), t1));
    }
}
