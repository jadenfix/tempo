//! Latency benchmarks for the engine-host wire protocol: frame encode/decode
//! in memory, and full request/response round-trips over a real Unix socket
//! pair. This is the per-RPC floor every driver call pays.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::io::Cursor;
use std::os::unix::net::UnixStream;
use tempo_engine_host::{read_frame, write_frame, WireFrame};

fn frame_with_payload_bytes(bytes: usize) -> WireFrame {
    let payload = serde_json::json!({
        "kind": "observe_result",
        "data": "x".repeat(bytes),
    });
    WireFrame::new(7, "driver.response", payload)
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/encode-frame");
    for &bytes in &[256_usize, 4 * 1024, 64 * 1024] {
        let frame = frame_with_payload_bytes(bytes);
        group.bench_with_input(BenchmarkId::from_parameter(bytes), &frame, |b, frame| {
            let mut sink = Vec::with_capacity(bytes + 1024);
            b.iter(|| {
                sink.clear();
                write_frame(&mut sink, black_box(frame)).unwrap();
                black_box(sink.len())
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/decode-frame");
    for &bytes in &[256_usize, 4 * 1024, 64 * 1024] {
        let frame = frame_with_payload_bytes(bytes);
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(bytes),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    let mut cursor = Cursor::new(encoded.as_slice());
                    black_box(read_frame(&mut cursor).unwrap())
                });
            },
        );
    }
    group.finish();
}

/// One synchronous request/response round-trip over a real UDS pair with an
/// echo peer thread: framing + serialization + scheduler + socket syscalls.
fn bench_uds_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/uds-roundtrip");
    for &bytes in &[256_usize, 4 * 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(bytes), &bytes, |b, &bytes| {
            let (mut ours, mut theirs) = UnixStream::pair().unwrap();
            let echo = std::thread::spawn(move || {
                while let Ok(frame) = read_frame(&mut theirs) {
                    if frame.method == "bench.stop" {
                        break;
                    }
                    if write_frame(&mut theirs, &frame).is_err() {
                        break;
                    }
                }
            });

            let frame = frame_with_payload_bytes(bytes);
            b.iter(|| {
                write_frame(&mut ours, black_box(&frame)).unwrap();
                black_box(read_frame(&mut ours).unwrap())
            });

            write_frame(
                &mut ours,
                &WireFrame::new(0, "bench.stop", serde_json::Value::Null),
            )
            .unwrap();
            echo.join().unwrap();
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_uds_roundtrip);
criterion_main!(benches);
