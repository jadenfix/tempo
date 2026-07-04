//! Benchmarks for the page-settled state machine. `observe` runs once per
//! settle-poll sample on every action batch, so its cost bounds how tightly
//! the runtime can poll without burning CPU.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempo_act::{PageSignals, QuiescenceConfig, QuiescenceTracker};

/// A realistic settle trace: network + JS busy, then layout churn, then quiet.
fn sample_trace() -> Vec<PageSignals> {
    (0..200_u64)
        .map(|tick| PageSignals {
            now_ms: tick * 25,
            inflight_requests: if tick < 40 { (40 - tick) as u32 / 8 } else { 0 },
            layout_generation: tick.min(60) / 3,
            frame_generation: tick.min(80) / 2,
            pending_js_tasks: if tick < 30 { 2 } else { 0 },
        })
        .collect()
}

fn bench_observe_trace(c: &mut Criterion) {
    let trace = sample_trace();
    let config = QuiescenceConfig::default();
    c.bench_function("act/quiescence-trace-200", |b| {
        b.iter(|| {
            let mut tracker = QuiescenceTracker::new();
            let mut settled = 0_u32;
            for signals in &trace {
                if tracker.observe(black_box(*signals), config)
                    == tempo_act::QuiescenceDecision::Settled
                {
                    settled += 1;
                }
            }
            black_box(settled)
        });
    });
}

fn bench_observe_single(c: &mut Criterion) {
    let config = QuiescenceConfig::default();
    c.bench_function("act/quiescence-single-sample", |b| {
        let mut tracker = QuiescenceTracker::new();
        let signals = PageSignals::quiet(1_000);
        b.iter(|| black_box(tracker.observe(black_box(signals), config)));
    });
}

criterion_group!(benches, bench_observe_trace, bench_observe_single);
criterion_main!(benches);
