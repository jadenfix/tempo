use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use serde_json::{json, Map, Value};

/// Prometheus text exposition format 0.0.4.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Default latency buckets (seconds). The 0.15 / 0.5 / 1.2 boundaries mirror
/// the CI budget bars in `final.md` §10 (observe p50 ≤ 150ms / p95 ≤ 500ms,
/// action→quiescent p50 ≤ 1.2s) so budget checks can read cumulative bucket
/// counts straight off the exposition without percentile estimation error at
/// exactly the bar.
pub const DEFAULT_LATENCY_BOUNDS_SECS: [f64; 15] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1.0, 1.2, 2.5, 5.0, 10.0,
];

/// Which exposition family a metric belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl MetricKind {
    fn as_str(self) -> &'static str {
        match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        }
    }
}

/// Monotonically increasing counter. Cheap to clone; clones share the cell.
#[derive(Debug, Clone)]
pub struct Counter {
    cell: Arc<AtomicU64>,
}

impl Counter {
    fn new() -> Self {
        Self {
            cell: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.cell.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.cell.load(Ordering::Relaxed)
    }
}

/// An `f64` cell updated through bit-cast CAS, so gauges never need a lock.
#[derive(Debug)]
struct AtomicF64 {
    bits: AtomicU64,
}

impl AtomicF64 {
    fn new(value: f64) -> Self {
        Self {
            bits: AtomicU64::new(value.to_bits()),
        }
    }

    fn load(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }

    fn store(&self, value: f64) {
        self.bits.store(value.to_bits(), Ordering::Relaxed);
    }

    fn add(&self, delta: f64) {
        let mut current = self.bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(current) + delta).to_bits();
            match self.bits.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Instantaneous value (queue depth, active sessions, uptime).
#[derive(Debug, Clone)]
pub struct Gauge {
    cell: Arc<AtomicF64>,
}

impl Gauge {
    fn new() -> Self {
        Self {
            cell: Arc::new(AtomicF64::new(0.0)),
        }
    }

    pub fn set(&self, value: f64) {
        self.cell.store(value);
    }

    pub fn add(&self, delta: f64) {
        self.cell.add(delta);
    }

    pub fn sub(&self, delta: f64) {
        self.cell.add(-delta);
    }

    pub fn get(&self) -> f64 {
        self.cell.load()
    }
}

#[derive(Debug)]
struct HistogramCore {
    /// Upper bounds of the finite buckets, strictly increasing.
    bounds: Vec<f64>,
    /// One cell per finite bound plus the trailing +Inf overflow bucket.
    buckets: Vec<AtomicU64>,
    sum: AtomicF64,
    count: AtomicU64,
}

/// Fixed-boundary histogram; `observe` is one atomic add per call.
#[derive(Debug, Clone)]
pub struct Histogram {
    core: Arc<HistogramCore>,
}

impl Histogram {
    fn new(bounds: &[f64]) -> Self {
        let mut cleaned: Vec<f64> = bounds.iter().copied().filter(|b| b.is_finite()).collect();
        cleaned.sort_by(f64::total_cmp);
        cleaned.dedup();
        let mut buckets = Vec::with_capacity(cleaned.len() + 1);
        for _ in 0..=cleaned.len() {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            core: Arc::new(HistogramCore {
                bounds: cleaned,
                buckets,
                sum: AtomicF64::new(0.0),
                count: AtomicU64::new(0),
            }),
        }
    }

    pub fn observe(&self, value: f64) {
        if !value.is_finite() {
            return;
        }
        let idx = self
            .core
            .bounds
            .iter()
            .position(|bound| value <= *bound)
            .unwrap_or(self.core.bounds.len());
        if let Some(bucket) = self.core.buckets.get(idx) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        self.core.sum.add(value);
        self.core.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Starts a timer that observes elapsed seconds when dropped (or when
    /// [`Timer::stop`] is called, whichever comes first).
    pub fn start_timer(&self) -> Timer {
        Timer {
            histogram: self.clone(),
            start: Instant::now(),
            recorded: false,
        }
    }

    pub fn count(&self) -> u64 {
        self.core.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> f64 {
        self.core.sum.load()
    }

    /// Estimated quantile (`0.0..=1.0`) by linear interpolation inside the
    /// covering bucket; values landing in the +Inf overflow bucket report the
    /// largest finite bound. `None` until at least one observation exists.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        let rank = (q * total as f64).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for (idx, bucket) in self.core.buckets.iter().enumerate() {
            let in_bucket = bucket.load(Ordering::Relaxed);
            if in_bucket == 0 {
                cumulative += in_bucket;
                continue;
            }
            if cumulative + in_bucket >= rank {
                let upper = match self.core.bounds.get(idx) {
                    Some(bound) => *bound,
                    // Overflow bucket: no finite upper edge to interpolate to.
                    None => return self.core.bounds.last().copied().or(Some(f64::INFINITY)),
                };
                let lower = if idx == 0 {
                    0.0_f64.min(upper)
                } else {
                    self.core.bounds.get(idx - 1).copied().unwrap_or(0.0)
                };
                let into_bucket = (rank - cumulative) as f64 / in_bucket as f64;
                return Some(lower + (upper - lower) * into_bucket);
            }
            cumulative += in_bucket;
        }
        self.core.bounds.last().copied().or(Some(f64::INFINITY))
    }

    fn bucket_counts(&self) -> Vec<u64> {
        self.core
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }
}

/// Observes elapsed wall-clock seconds into its histogram exactly once.
#[derive(Debug)]
pub struct Timer {
    histogram: Histogram,
    start: Instant,
    recorded: bool,
}

impl Timer {
    /// Records now and returns the elapsed seconds.
    pub fn stop(mut self) -> f64 {
        self.record()
    }

    fn record(&mut self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if !self.recorded {
            self.recorded = true;
            self.histogram.observe(elapsed);
        }
        elapsed
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.record();
    }
}

#[derive(Debug, Clone)]
enum Series {
    Counter(Counter),
    Gauge(Gauge),
    Histogram(Histogram),
}

#[derive(Debug)]
struct Family {
    help: String,
    kind: MetricKind,
    series: BTreeMap<Vec<(String, String)>, Series>,
}

/// Metric registry: name → family → labeled series. Registration takes the
/// mutex once per (name, labels) pair; the returned handles are lock-free.
#[derive(Debug, Default)]
pub struct Registry {
    families: Mutex<BTreeMap<String, Family>>,
    /// Bumped when a name is re-registered under a different kind; the
    /// mismatched caller gets a detached (unexported) handle instead of a
    /// panic, and the conflict is visible in the exposition.
    type_conflicts: AtomicU64,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counter(&self, name: &str, help: &str, labels: &[(&str, &str)]) -> Counter {
        match self.series(name, help, MetricKind::Counter, labels, || {
            Series::Counter(Counter::new())
        }) {
            Some(Series::Counter(counter)) => counter,
            _ => {
                self.type_conflicts.fetch_add(1, Ordering::Relaxed);
                Counter::new()
            }
        }
    }

    pub fn gauge(&self, name: &str, help: &str, labels: &[(&str, &str)]) -> Gauge {
        match self.series(name, help, MetricKind::Gauge, labels, || {
            Series::Gauge(Gauge::new())
        }) {
            Some(Series::Gauge(gauge)) => gauge,
            _ => {
                self.type_conflicts.fetch_add(1, Ordering::Relaxed);
                Gauge::new()
            }
        }
    }

    /// `bounds: None` uses [`DEFAULT_LATENCY_BOUNDS_SECS`].
    pub fn histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        bounds: Option<&[f64]>,
    ) -> Histogram {
        let bounds: Vec<f64> = bounds.unwrap_or(&DEFAULT_LATENCY_BOUNDS_SECS).to_vec();
        let registered_bounds = bounds.clone();
        match self.series(name, help, MetricKind::Histogram, labels, move || {
            Series::Histogram(Histogram::new(&registered_bounds))
        }) {
            Some(Series::Histogram(histogram)) => histogram,
            _ => {
                self.type_conflicts.fetch_add(1, Ordering::Relaxed);
                Histogram::new(&bounds)
            }
        }
    }

    fn series(
        &self,
        name: &str,
        help: &str,
        kind: MetricKind,
        labels: &[(&str, &str)],
        make: impl FnOnce() -> Series,
    ) -> Option<Series> {
        let name = sanitize_metric_name(name);
        let key = normalize_labels(labels);
        let mut families = self.families.lock().unwrap_or_else(PoisonError::into_inner);
        let family = families.entry(name).or_insert_with(|| Family {
            help: help.to_string(),
            kind,
            series: BTreeMap::new(),
        });
        if family.kind != kind {
            return None;
        }
        let series = family.series.entry(key).or_insert_with(make);
        Some(series.clone())
    }

    /// Prometheus text exposition (format 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let families = self.families.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = String::new();
        for (name, family) in families.iter() {
            out.push_str(&format!(
                "# HELP {name} {}\n# TYPE {name} {}\n",
                escape_help(&family.help),
                family.kind.as_str()
            ));
            for (labels, series) in family.series.iter() {
                match series {
                    Series::Counter(counter) => {
                        out.push_str(&format!(
                            "{name}{} {}\n",
                            render_labels(labels, None),
                            counter.get()
                        ));
                    }
                    Series::Gauge(gauge) => {
                        out.push_str(&format!(
                            "{name}{} {}\n",
                            render_labels(labels, None),
                            format_f64(gauge.get())
                        ));
                    }
                    Series::Histogram(histogram) => {
                        let counts = histogram.bucket_counts();
                        let mut cumulative = 0u64;
                        for (idx, in_bucket) in counts.iter().enumerate() {
                            cumulative += in_bucket;
                            let le = match histogram.core.bounds.get(idx) {
                                Some(bound) => format_f64(*bound),
                                None => "+Inf".to_string(),
                            };
                            out.push_str(&format!(
                                "{name}_bucket{} {cumulative}\n",
                                render_labels(labels, Some(&le))
                            ));
                        }
                        out.push_str(&format!(
                            "{name}_sum{} {}\n",
                            render_labels(labels, None),
                            format_f64(histogram.sum())
                        ));
                        out.push_str(&format!(
                            "{name}_count{} {}\n",
                            render_labels(labels, None),
                            histogram.count()
                        ));
                    }
                }
            }
        }
        let conflicts = self.type_conflicts.load(Ordering::Relaxed);
        if conflicts > 0 {
            out.push_str(&format!(
                "# HELP tempo_telemetry_type_conflicts_total metric registered under conflicting kinds\n# TYPE tempo_telemetry_type_conflicts_total counter\ntempo_telemetry_type_conflicts_total {conflicts}\n"
            ));
        }
        out
    }

    /// JSON snapshot of every family, including estimated p50/p95 for
    /// histograms — the machine-readable twin of the Prometheus text.
    pub fn snapshot_json(&self) -> Value {
        let families = self.families.lock().unwrap_or_else(PoisonError::into_inner);
        let mut root = Map::new();
        for (name, family) in families.iter() {
            let mut series_out = Vec::new();
            for (labels, series) in family.series.iter() {
                let labels_json: Map<String, Value> = labels
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                let value = match series {
                    Series::Counter(counter) => json!(counter.get()),
                    Series::Gauge(gauge) => json!(gauge.get()),
                    Series::Histogram(histogram) => json!({
                        "count": histogram.count(),
                        "sum": histogram.sum(),
                        "p50": histogram.quantile(0.50),
                        "p95": histogram.quantile(0.95),
                        "p99": histogram.quantile(0.99),
                    }),
                };
                series_out.push(json!({ "labels": labels_json, "value": value }));
            }
            root.insert(
                name.clone(),
                json!({
                    "kind": family.kind.as_str(),
                    "help": family.help,
                    "series": series_out,
                }),
            );
        }
        Value::Object(root)
    }
}

fn normalize_labels(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut normalized: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (sanitize_label_name(k), (*v).to_string()))
        .collect();
    normalized.sort();
    normalized.dedup_by(|a, b| a.0 == b.0);
    normalized
}

fn render_labels(labels: &[(String, String)], le: Option<&str>) -> String {
    if labels.is_empty() && le.is_none() {
        return String::new();
    }
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
        .collect();
    if let Some(le) = le {
        parts.push(format!("le=\"{le}\""));
    }
    format!("{{{}}}", parts.join(","))
}

fn sanitize_metric_name(name: &str) -> String {
    sanitize(name, true)
}

fn sanitize_label_name(name: &str) -> String {
    sanitize(name, false)
}

fn sanitize(name: &str, allow_colon: bool) -> String {
    let mut out = String::with_capacity(name.len());
    for (idx, ch) in name.chars().enumerate() {
        let valid = ch.is_ascii_alphabetic()
            || ch == '_'
            || (allow_colon && ch == ':')
            || (idx > 0 && ch.is_ascii_digit());
        out.push(if valid { ch } else { '_' });
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

fn format_f64(value: f64) -> String {
    if value == f64::INFINITY {
        "+Inf".to_string()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn counter_shares_state_across_clones_and_lookups() {
        let registry = Registry::new();
        let a = registry.counter("requests_total", "requests", &[("route", "health")]);
        let b = registry.counter("requests_total", "requests", &[("route", "health")]);
        a.inc();
        b.add(2);
        assert_eq!(a.get(), 3);
        assert_eq!(b.get(), 3);
        let other = registry.counter("requests_total", "requests", &[("route", "mcp")]);
        assert_eq!(other.get(), 0);
    }

    #[test]
    fn concurrent_counter_increments_are_lossless() {
        let registry = Registry::new();
        let counter = registry.counter("concurrent_total", "c", &[]);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let counter = counter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    counter.inc();
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        assert_eq!(counter.get(), 8000);
    }

    #[test]
    fn gauge_set_add_sub() {
        let registry = Registry::new();
        let gauge = registry.gauge("active_sessions", "sessions", &[]);
        gauge.set(5.0);
        gauge.add(2.5);
        gauge.sub(1.5);
        assert!((gauge.get() - 6.0).abs() < 1e-9);
    }

    #[test]
    fn histogram_buckets_sum_count_and_quantiles() {
        let registry = Registry::new();
        let histogram =
            registry.histogram("latency_seconds", "latency", &[], Some(&[0.1, 0.5, 1.0]));
        for value in [0.05, 0.05, 0.2, 0.4, 0.9, 3.0] {
            histogram.observe(value);
        }
        assert_eq!(histogram.count(), 6);
        assert!((histogram.sum() - 4.6).abs() < 1e-9);
        let p50 = histogram.quantile(0.5).unwrap_or(f64::NAN);
        assert!(p50 > 0.1 && p50 <= 0.5, "p50 was {p50}");
        // Highest observation lands in +Inf: quantile reports last finite bound.
        let p100 = histogram.quantile(1.0).unwrap_or(f64::NAN);
        assert!((p100 - 1.0).abs() < 1e-9, "p100 was {p100}");
        assert_eq!(
            registry
                .histogram("latency_seconds", "latency", &[], None)
                .count(),
            6
        );
    }

    #[test]
    fn histogram_ignores_non_finite_and_empty_quantile_is_none() {
        let registry = Registry::new();
        let histogram = registry.histogram("empty_seconds", "empty", &[], Some(&[1.0]));
        assert_eq!(histogram.quantile(0.5), None);
        histogram.observe(f64::NAN);
        histogram.observe(f64::INFINITY);
        assert_eq!(histogram.count(), 0);
    }

    #[test]
    fn timer_observes_once_on_drop_or_stop() {
        let registry = Registry::new();
        let histogram = registry.histogram("timer_seconds", "timer", &[], Some(&[10.0]));
        {
            let _timer = histogram.start_timer();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(histogram.count(), 1);
        let timer = histogram.start_timer();
        let elapsed = timer.stop();
        assert!(elapsed >= 0.0);
        assert_eq!(histogram.count(), 2);
    }

    #[test]
    fn prometheus_render_shape() {
        let registry = Registry::new();
        registry
            .counter(
                "requests_total",
                "total requests",
                &[("route", "he\"al\\th")],
            )
            .inc();
        registry.gauge("uptime_seconds", "uptime", &[]).set(3.0);
        let histogram = registry.histogram("obs_seconds", "observe", &[], Some(&[0.15, 0.5]));
        histogram.observe(0.1);
        histogram.observe(0.3);
        let text = registry.render_prometheus();
        assert!(text.contains("# TYPE requests_total counter"));
        assert!(text.contains("requests_total{route=\"he\\\"al\\\\th\"} 1"));
        assert!(text.contains("# TYPE uptime_seconds gauge"));
        assert!(text.contains("uptime_seconds 3"));
        assert!(text.contains("obs_seconds_bucket{le=\"0.15\"} 1"));
        assert!(text.contains("obs_seconds_bucket{le=\"0.5\"} 2"));
        assert!(text.contains("obs_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(text.contains("obs_seconds_sum 0.4"));
        assert!(text.contains("obs_seconds_count 2"));
    }

    #[test]
    fn type_conflict_returns_detached_handle_and_is_reported() {
        let registry = Registry::new();
        let counter = registry.counter("mixed_metric", "first", &[]);
        counter.inc();
        let gauge = registry.gauge("mixed_metric", "second", &[]);
        gauge.set(42.0); // must not corrupt the counter
        assert_eq!(counter.get(), 1);
        let text = registry.render_prometheus();
        assert!(text.contains("mixed_metric 1"));
        assert!(text.contains("tempo_telemetry_type_conflicts_total 1"));
        assert!(!text.contains("42"));
    }

    #[test]
    fn sanitizes_invalid_names_and_labels() {
        let registry = Registry::new();
        registry
            .counter("1bad-name.total", "sanitize", &[("bad-label!", "v")])
            .inc();
        let text = registry.render_prometheus();
        assert!(text.contains("_bad_name_total{bad_label_=\"v\"} 1"));
    }

    #[test]
    fn snapshot_json_includes_percentiles() {
        let registry = Registry::new();
        let histogram = registry.histogram("snap_seconds", "snap", &[], Some(&[0.1, 1.0]));
        for _ in 0..100 {
            histogram.observe(0.05);
        }
        let snapshot = registry.snapshot_json();
        let p50 = snapshot["snap_seconds"]["series"][0]["value"]["p50"]
            .as_f64()
            .unwrap_or(f64::NAN);
        assert!(p50 <= 0.1, "p50 was {p50}");
        assert_eq!(snapshot["snap_seconds"]["kind"], "histogram");
    }

    #[test]
    fn registry_survives_poisoned_lock() {
        let registry = Arc::new(Registry::new());
        registry.counter("poison_total", "p", &[]).inc();
        let clone = Arc::clone(&registry);
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _guard = clone
                .families
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let _ = tx.send(());
            panic!("poison the registry mutex");
        });
        let _ = rx.recv();
        let _ = handle.join();
        // Both render and registration still work after the poisoning panic.
        assert!(registry.render_prometheus().contains("poison_total 1"));
        registry.counter("after_poison_total", "p", &[]).inc();
    }
}
