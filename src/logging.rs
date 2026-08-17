use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use tracing;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::EnvFilter;

/// Total log lines kept in the in-memory ring buffer (see RingBufferLayer).
/// Bounded: older lines are dropped as new ones arrive. Sized so a bug report
/// covers minutes of a busy daemon rather than seconds — at ~150 bytes a line
/// the whole ring costs well under 100 KB, and a report that starts after the
/// interesting lines were evicted is worth far more than that.
const LOG_RING_CAPACITY: usize = 500;

/// Default number of ring-buffer lines served by the control socket's
/// diagnostics command.
pub const RECENT_LOGS_DEFAULT: usize = 50;

/// Most lines a diagnostics request may ask for: the whole ring.
pub const RECENT_LOGS_MAX: usize = LOG_RING_CAPACITY;

static LOG_RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn log_ring() -> &'static Mutex<VecDeque<String>> {
    LOG_RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_RING_CAPACITY)))
}

/// The last `n` log lines captured by the ring layer, oldest first. Empty
/// when the layer isn't installed (unit tests) or nothing was logged yet.
pub fn recent_logs(n: usize) -> Vec<String> {
    match log_ring().lock() {
        Ok(lines) => {
            let skip = lines.len().saturating_sub(n.min(LOG_RING_CAPACITY));
            lines.iter().skip(skip).cloned().collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Appends one formatted line, evicting the oldest line at capacity.
fn push_line(lines: &mut VecDeque<String>, line: String) {
    if lines.len() >= LOG_RING_CAPACITY {
        lines.pop_front();
    }
    lines.push_back(line);
}

/// Extracts the message plus any extra fields from a tracing event.
#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: String,
}

impl tracing::field::Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields
                .push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

/// Wall-clock stamp for one ring-buffer line, in the same RFC3339 UTC format
/// the stderr layer prints. Bug reports are read against a wall clock ("it
/// froze around 14:32") and — for a server/client pair — against the OTHER
/// machine's log, so an unstamped line is nearly unusable in a report.
/// Formatting goes through the same tracing-subscriber timer as stderr, so
/// the two renderings can't drift apart.
fn timestamp() -> String {
    use tracing_subscriber::fmt::format::Writer;
    use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
    let mut buf = String::new();
    match SystemTime.format_time(&mut Writer::new(&mut buf)) {
        Ok(()) => buf,
        // The timer is infallible in practice; a report with unstamped lines
        // still beats losing the line.
        Err(_) => "<no timestamp>".to_string(),
    }
}

/// A tracing layer keeping the daemon's last LOG_RING_CAPACITY log lines in a
/// global ring buffer, served by the control socket's diagnostics command
/// (control.rs). The global EnvFilter short-circuits filtered-out events
/// before they reach this layer, so the hot path (QUIC/input debugging
/// volume) never pays for it; per kept event it's one string format and one
/// short-held mutex push.
pub(crate) struct RingBufferLayer;

/// The ring layer, for tests that need to assert on what a bug report would
/// carry (see device::input's keystroke-masking guard). Test-only: the daemon
/// installs the layer through init_logging.
#[cfg(test)]
pub(crate) fn ring_layer_for_tests() -> RingBufferLayer {
    RingBufferLayer
}

impl<S: tracing::Subscriber> Layer<S> for RingBufferLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let line = if visitor.fields.is_empty() {
            format!(
                "{} {} {}: {}",
                timestamp(),
                metadata.level(),
                metadata.target(),
                visitor.message
            )
        } else {
            format!(
                "{} {} {}: {} {}",
                timestamp(),
                metadata.level(),
                metadata.target(),
                visitor.message,
                visitor.fields
            )
        };
        if let Ok(mut lines) = log_ring().lock() {
            push_line(&mut lines, line);
        }
    }
}

pub fn init_logging() {
    // An empty (or whitespace-only) LOG_LEVEL — e.g. an exported-but-unset
    // variable in a shell profile or systemd unit — reads as unset, not as an
    // invalid filter.
    let level = std::env::var("LOG_LEVEL").unwrap_or_default();
    let level = if level.trim().is_empty() {
        "info"
    } else {
        level.as_str()
    };
    let filter_layer = EnvFilter::try_new(level)
        .unwrap_or_else(|_| {
            eprintln!(
                "Ignoring invalid LOG_LEVEL value {:?}; falling back to 'info'",
                level
            );
            EnvFilter::try_new("info").expect("Failed to initialize filter layer")
        })
        // quinn_proto: Gets very noisy when LOG_LEVEL=trace
        .add_directive(
            "quinn_proto=info"
                .parse()
                .expect("Failed to parse quinn_proto directive"),
        );

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        // The filter applies globally, so the ring buffer sees exactly what
        // the stderr log shows.
        .with(filter_layer)
        .with(
            tracing_subscriber::fmt::layer().with_writer(std::io::stderr),
        )
        .with(RingBufferLayer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_is_bounded_and_drops_oldest() {
        let mut lines = VecDeque::new();
        for i in 0..(LOG_RING_CAPACITY + 50) {
            push_line(&mut lines, format!("line {}", i));
        }
        assert_eq!(lines.len(), LOG_RING_CAPACITY);
        assert_eq!(lines.front().unwrap(), "line 50");
        assert_eq!(lines.back().unwrap(), &format!("line {}", LOG_RING_CAPACITY + 49));
    }

    #[test]
    fn recent_logs_returns_the_tail() {
        use tracing_subscriber::layer::SubscriberExt;
        // The ring is global; a scoped subscriber with the layer installed
        // lets us verify capture without disturbing other tests' output.
        let marker = format!("ring-layer-test-{}", std::process::id());
        let subscriber = tracing_subscriber::registry().with(RingBufferLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("{}", marker);
        });
        let logs = recent_logs(RECENT_LOGS_DEFAULT);
        assert!(
            logs.iter().any(|l| l.contains(&marker)),
            "the marker line must be captured: {:?}",
            logs
        );
        // Captured lines carry level and target like the stderr log.
        let line = logs.iter().find(|l| l.contains(&marker)).unwrap();
        assert!(line.contains("INFO"), "{}", line);
        // recent_logs honors the requested tail length.
        assert!(recent_logs(0).is_empty());
        assert!(recent_logs(1).len() <= 1);
    }

    #[test]
    fn captured_lines_are_timestamped() {
        use tracing_subscriber::layer::SubscriberExt;
        let marker = format!("ring-stamp-test-{}", std::process::id());
        let subscriber = tracing_subscriber::registry().with(RingBufferLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("{}", marker);
        });
        let logs = recent_logs(RECENT_LOGS_MAX);
        let line = logs
            .iter()
            .find(|l| l.contains(&marker))
            .expect("the marker line must be captured");
        // The stamp leads the line, before the level — an RFC3339 UTC
        // instant, so a reader can align it with the peer machine's log.
        let stamp = line.split(' ').next().expect("a leading field");
        assert!(stamp.ends_with('Z'), "{}", line);
        assert!(stamp.starts_with("20"), "{}", line);
        assert!(stamp.contains('T'), "{}", line);
        assert!(line.contains("INFO"), "{}", line);
    }

    #[test]
    fn the_timestamp_renders_an_rfc3339_instant() {
        let stamp = timestamp();
        assert!(stamp.contains('T') && stamp.ends_with('Z'), "{}", stamp);
        // YYYY-MM-DDTHH:MM:SS at minimum.
        assert!(stamp.len() >= 20, "{}", stamp);
    }
}
