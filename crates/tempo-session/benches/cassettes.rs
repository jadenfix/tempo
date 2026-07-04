//! Benchmarks for the cassette store used by replay-fork and deterministic
//! re-execution. Speculative branches replay many cassettes per branch, so
//! record/replay cost multiplies across every fork.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempo_session::{CassetteKey, CassetteStore, ResponseCassette};

fn cassette(index: usize) -> ResponseCassette {
    ResponseCassette::new(
        "GET",
        format!("https://api.example.com/v1/items/{index}"),
        200,
        vec![("content-type".into(), "application/json".into())],
        format!("{{\"id\":{index},\"payload\":\"{}\"}}", "x".repeat(256)).into_bytes(),
    )
}

/// Record N cassettes into a fresh store: measures append cost including any
/// duplicate-key scanning over the already-written prefix.
fn bench_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/cassette-record");
    group.sample_size(10);
    for &count in &[50_usize, 200] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = CassetteStore::open(dir.path().join("cassettes.jsonl")).unwrap();
                    (dir, store)
                },
                |(dir, store)| {
                    for index in 0..count {
                        store.record(&cassette(index)).unwrap();
                    }
                    black_box(dir)
                },
                criterion::BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Replay lookups against a store holding 500 cassettes: a hit near the end of
/// the file and a guaranteed miss.
fn bench_replay(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let store = CassetteStore::open(dir.path().join("cassettes.jsonl")).unwrap();
    for index in 0..500 {
        store.record(&cassette(index)).unwrap();
    }
    let hit_key = cassette(499).key;
    let miss_key = CassetteKey::from_request("GET", "https://api.example.com/none", b"");

    c.bench_function("session/cassette-replay-hit-500", |b| {
        b.iter(|| black_box(store.replay(black_box(&hit_key)).unwrap()));
    });
    c.bench_function("session/cassette-replay-miss-500", |b| {
        b.iter(|| black_box(store.replay(black_box(&miss_key)).unwrap()));
    });
}

criterion_group!(benches, bench_record, bench_replay);
criterion_main!(benches);
