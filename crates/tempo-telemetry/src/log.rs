use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Environment variable controlling the global logger's minimum level.
pub const LOG_LEVEL_ENV: &str = "TEMPO_LOG";

const RING_CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Option<Level> {
        match value.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }

    fn from_u8(value: u8) -> Level {
        match value {
            0 => Level::Trace,
            1 => Level::Debug,
            2 => Level::Info,
            3 => Level::Warn,
            _ => Level::Error,
        }
    }
}

/// One structured log record: a JSON line on stderr and an entry in the ring.
#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    pub ts_ms: u64,
    pub level: Level,
    pub target: String,
    pub message: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
}

/// Structured JSON-lines logger with a bounded in-memory ring buffer.
///
/// The ring keeps the most recent events (default 512) so a control-plane
/// endpoint or a post-mortem can retrieve recent history without scraping
/// stderr. Emission never blocks on a poisoned lock and never panics.
#[derive(Debug)]
pub struct Logger {
    min_level: AtomicU8,
    local_output_enabled: AtomicBool,
    ring: Mutex<VecDeque<LogEvent>>,
    ring_capacity: usize,
    write_stderr: bool,
}

impl Logger {
    pub fn new(ring_capacity: usize, write_stderr: bool) -> Self {
        Self {
            min_level: AtomicU8::new(Level::Info as u8),
            local_output_enabled: AtomicBool::new(true),
            // Pre-allocation is bounded independently of the logical capacity
            // so a huge capacity doesn't reserve memory up front; the ring
            // still grows to (and is evicted at) `ring_capacity`.
            ring: Mutex::new(VecDeque::with_capacity(ring_capacity.clamp(1, 1024))),
            ring_capacity: ring_capacity.max(1),
            write_stderr,
        }
    }

    pub fn set_min_level(&self, level: Level) {
        self.min_level.store(level as u8, Ordering::Relaxed);
    }

    pub fn min_level(&self) -> Level {
        Level::from_u8(self.min_level.load(Ordering::Relaxed))
    }

    pub fn enabled(&self, level: Level) -> bool {
        level >= self.min_level()
    }

    /// Enable or disable all local log artifacts: stderr JSONL and the
    /// in-memory recent-event ring. Disabling clears already-retained events.
    pub fn set_local_output_enabled(&self, enabled: bool) {
        self.local_output_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.ring
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
        }
    }

    pub fn local_output_enabled(&self) -> bool {
        self.local_output_enabled.load(Ordering::Relaxed)
    }

    /// Starts a structured event; finish it with [`EventBuilder::emit`].
    pub fn event<'a>(&'a self, level: Level, target: &str, message: &str) -> EventBuilder<'a> {
        EventBuilder {
            logger: self,
            event: LogEvent {
                ts_ms: now_ms(),
                level,
                target: target.to_string(),
                message: message.to_string(),
                fields: BTreeMap::new(),
            },
        }
    }

    /// The most recent events, oldest first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<LogEvent> {
        if !self.local_output_enabled() {
            return Vec::new();
        }
        let ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        ring.iter()
            .skip(ring.len().saturating_sub(limit))
            .cloned()
            .collect()
    }

    fn emit_event(&self, event: LogEvent) {
        if !self.enabled(event.level) {
            return;
        }
        if !self.local_output_enabled() {
            return;
        }
        if self.write_stderr
            && let Ok(line) = serde_json::to_string(&event)
        {
            // Best-effort by design: telemetry must never take the daemon down.
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        while ring.len() >= self.ring_capacity {
            ring.pop_front();
        }
        ring.push_back(event);
    }
}

/// Builder returned by [`Logger::event`]; add fields, then [`emit`](Self::emit).
#[derive(Debug)]
pub struct EventBuilder<'a> {
    logger: &'a Logger,
    event: LogEvent,
}

impl EventBuilder<'_> {
    pub fn field(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.event.fields.insert(key.into(), value.into());
        self
    }

    pub fn emit(self) {
        self.logger.emit_event(self.event);
    }
}

static GLOBAL_LOGGER: OnceLock<Logger> = OnceLock::new();

/// The process-wide logger. First use initializes the minimum level from
/// `TEMPO_LOG` (`trace|debug|info|warn|error`, default `info`).
pub fn logger() -> &'static Logger {
    GLOBAL_LOGGER.get_or_init(|| {
        let logger = Logger::new(RING_CAPACITY, true);
        if let Ok(value) = std::env::var(LOG_LEVEL_ENV)
            && let Some(level) = Level::parse(&value)
        {
            logger.set_min_level(level);
        }
        logger
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet_logger(capacity: usize) -> Logger {
        Logger::new(capacity, false)
    }

    #[test]
    fn level_ordering_and_parsing() {
        assert!(Level::Error > Level::Warn);
        assert!(Level::Warn > Level::Info);
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse(" info "), Some(Level::Info));
        assert_eq!(Level::parse("nope"), None);
    }

    #[test]
    fn events_below_min_level_are_dropped() {
        let logger = quiet_logger(16);
        logger.set_min_level(Level::Warn);
        logger.event(Level::Info, "test", "dropped").emit();
        logger.event(Level::Error, "test", "kept").emit();
        let recent = logger.recent(16);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "kept");
    }

    #[test]
    fn ring_evicts_oldest_first() {
        let logger = quiet_logger(3);
        for i in 0..5 {
            logger
                .event(Level::Info, "test", &format!("event-{i}"))
                .emit();
        }
        let recent = logger.recent(10);
        let messages: Vec<&str> = recent.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["event-2", "event-3", "event-4"]);
        assert_eq!(logger.recent(1).len(), 1);
        assert_eq!(logger.recent(1)[0].message, "event-4");
    }

    #[test]
    fn local_output_disable_clears_and_suppresses_recent_events() {
        let logger = quiet_logger(4);
        logger.event(Level::Info, "test", "before").emit();
        assert_eq!(logger.recent(10).len(), 1);

        logger.set_local_output_enabled(false);
        assert!(!logger.local_output_enabled());
        assert!(logger.recent(10).is_empty());

        logger.event(Level::Error, "test", "suppressed").emit();
        assert!(logger.recent(10).is_empty());

        logger.set_local_output_enabled(true);
        logger.event(Level::Info, "test", "after").emit();
        let recent = logger.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "after");
    }

    #[test]
    fn fields_serialize_as_json_object() {
        let logger = quiet_logger(4);
        logger
            .event(Level::Info, "tempod", "engine restarted")
            .field("attempt", 3)
            .field("engine", "cdp")
            .emit();
        let recent = logger.recent(1);
        let Some(event) = recent.first() else {
            panic!("expected one event");
        };
        let line = serde_json::to_string(event).unwrap_or_default();
        let parsed: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        assert_eq!(parsed["level"], "info");
        assert_eq!(parsed["target"], "tempod");
        assert_eq!(parsed["message"], "engine restarted");
        assert_eq!(parsed["fields"]["attempt"], 3);
        assert_eq!(parsed["fields"]["engine"], "cdp");
        assert!(parsed["ts_ms"].as_u64().is_some());
    }

    #[test]
    fn fields_key_omitted_when_empty() {
        let logger = quiet_logger(4);
        logger.event(Level::Info, "tempod", "bare").emit();
        let recent = logger.recent(1);
        let Some(event) = recent.first() else {
            panic!("expected one event");
        };
        let line = serde_json::to_string(event).unwrap_or_default();
        assert!(!line.contains("\"fields\""));
    }

    #[test]
    fn enabled_reflects_min_level() {
        let logger = quiet_logger(4);
        logger.set_min_level(Level::Debug);
        assert!(logger.enabled(Level::Debug));
        assert!(!logger.enabled(Level::Trace));
        assert_eq!(logger.min_level(), Level::Debug);
    }
}
