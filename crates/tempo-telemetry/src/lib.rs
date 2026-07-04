//! tempo-telemetry — the observability backbone for the tempo workspace.
//!
//! Two planes, zero external dependencies beyond serde:
//!
//! - **Metrics** ([`Registry`], [`Counter`], [`Gauge`], [`Histogram`]): a
//!   process-wide registry rendering Prometheus text exposition (0.0.4) and a
//!   JSON snapshot. Histograms default to bucket boundaries aligned with the
//!   CI latency budgets in `final.md` §10 (150ms, 500ms, 1.2s), so budget
//!   verification can read the exposition directly instead of re-deriving
//!   percentiles.
//! - **Structured logs** ([`Logger`], [`LogEvent`]): JSON-lines events on
//!   stderr plus a bounded in-memory ring for post-mortem retrieval, replacing
//!   bare `eprintln!` call sites across the daemon.
//!
//! Both planes are lock-light (atomics on the hot path, a registry mutex only
//! on first registration and render) and poison-tolerant: a panicked holder
//! never wedges telemetry, because telemetry must outlive the failure it is
//! reporting.
//!
//! ```
//! use tempo_telemetry::{global, Level, logger};
//!
//! let requests = global().counter("tempod_http_requests_total", "HTTP requests", &[("route", "health")]);
//! requests.inc();
//! let latency = global().histogram("tempod_act_batch_seconds", "act_batch latency", &[], None);
//! let timer = latency.start_timer();
//! drop(timer); // observes on drop
//! assert!(global().render_prometheus().contains("tempod_http_requests_total"));
//! logger().event(Level::Info, "docs", "hello").field("answer", 42).emit();
//! ```

mod log;
mod metrics;

pub use log::{logger, EventBuilder, Level, LogEvent, Logger};
pub use metrics::{
    Counter, Gauge, Histogram, MetricKind, Registry, Timer, DEFAULT_LATENCY_BOUNDS_SECS,
    PROMETHEUS_CONTENT_TYPE,
};

use std::sync::OnceLock;

static GLOBAL: OnceLock<Registry> = OnceLock::new();

/// The process-wide metrics registry. Instrumentation call sites use this so
/// the exposition endpoint sees every metric without plumbing a handle
/// through each crate boundary.
pub fn global() -> &'static Registry {
    GLOBAL.get_or_init(Registry::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_registry_is_shared_and_renders() {
        let counter = global().counter("tempo_telemetry_selftest_total", "self test", &[]);
        counter.inc();
        let text = global().render_prometheus();
        assert!(text.contains("tempo_telemetry_selftest_total"));
    }
}
