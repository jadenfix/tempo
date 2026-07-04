//! Latency benchmarks for the observation compiler hot path: snapshot
//! compilation, stable-ID remapping, diffing, budget truncation, and the
//! set-of-marks compositor. Run with `scripts/bench.sh` or
//! `cargo bench -p tempo-observe`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempo_observe::{
    composite_set_of_marks_rgba, diff_observations, observation_corpus_report, serialized_len,
    CompileOptions, ObservationCompiler, RawElement,
};

/// Synthetic page with a realistic role mix. Deterministic so criterion
/// baselines are comparable across runs and machines.
fn synthetic_page(url: &str, elements: usize, generation: u64) -> tempo_observe::ObservationInput {
    let roles = [
        "button", "link", "textbox", "checkbox", "combobox", "menuitem", "tab", "generic",
    ];
    let raw = (0..elements)
        .map(|index| {
            let role = roles[index % roles.len()];
            RawElement::new(role, format!("Element {index} label text"))
                .source_id(format!("ax:{generation}:{index}"))
                .stable_hint(format!("{role}#stable-{index}"))
                .bounds([
                    (index % 40) as f32 * 32.0,
                    (index / 40) as f32 * 28.0,
                    120.0,
                    24.0,
                ])
        })
        .collect();
    tempo_observe::ObservationInput::new(url, raw)
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("observe/compile");
    for &elements in &[50_usize, 200, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(elements),
            &elements,
            |b, &elements| {
                b.iter(|| {
                    let mut compiler = ObservationCompiler::new();
                    black_box(compiler.compile(synthetic_page(
                        "https://bench.example",
                        elements,
                        0,
                    )))
                });
            },
        );
    }
    group.finish();
}

/// Second-snapshot compile against a warm stable-ID mapper: the steady-state
/// per-observation cost of a live session (relayout, new engine source IDs).
fn bench_recompile_warm(c: &mut Criterion) {
    let mut group = c.benchmark_group("observe/recompile-warm");
    for &elements in &[200_usize, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(elements),
            &elements,
            |b, &elements| {
                b.iter_batched(
                    || {
                        let mut compiler = ObservationCompiler::new();
                        compiler.compile(synthetic_page("https://bench.example", elements, 0));
                        compiler
                    },
                    |mut compiler| {
                        black_box(compiler.compile(synthetic_page(
                            "https://bench.example",
                            elements,
                            1,
                        )))
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_diff(c: &mut Criterion) {
    let mut group = c.benchmark_group("observe/diff");
    for &elements in &[200_usize, 1000] {
        // Unbudgeted compiles so the diff sees the full element lists.
        let options = CompileOptions {
            max_bytes: 0,
            max_tokens: 0,
            max_marks: 16,
        };
        let mut compiler = ObservationCompiler::with_options(options);
        let previous = compiler.compile(synthetic_page("https://bench.example", elements, 0));
        let mut mutated = synthetic_page("https://bench.example", elements, 1);
        // Mutate ~5% of labels so the diff has real added/changed work.
        for raw in mutated.elements.iter_mut().step_by(20) {
            *raw = raw.clone().value("changed");
        }
        let current = compiler.compile(mutated);
        group.bench_with_input(
            BenchmarkId::from_parameter(elements),
            &(previous, current),
            |b, (previous, current)| {
                b.iter(|| black_box(diff_observations(previous, current)));
            },
        );
    }
    group.finish();
}

/// Budget truncation is the worst-case compile path: the binary search
/// re-serializes O(log n) candidate prefixes.
fn bench_budget_truncation(c: &mut Criterion) {
    c.bench_function("observe/budget-truncate-1000", |b| {
        b.iter(|| {
            let mut compiler = ObservationCompiler::new();
            black_box(compiler.compile(synthetic_page("https://bench.example", 1000, 0)))
        });
    });
}

fn bench_corpus_report(c: &mut Criterion) {
    let corpus: Vec<_> = (0..8)
        .map(|generation| synthetic_page("https://bench.example", 200, generation))
        .collect();
    c.bench_function("observe/corpus-report-8x200", |b| {
        b.iter(|| {
            black_box(observation_corpus_report(
                &corpus,
                CompileOptions::default(),
            ))
        });
    });
}

fn bench_serialized_len(c: &mut Criterion) {
    let mut compiler = ObservationCompiler::new();
    let observation = compiler.compile(synthetic_page("https://bench.example", 200, 0));
    c.bench_function("observe/serialized-len-200", |b| {
        b.iter(|| black_box(serialized_len(&observation)));
    });
}

fn bench_set_of_marks(c: &mut Criterion) {
    let mut compiler = ObservationCompiler::new();
    let observation = compiler.compile(synthetic_page("https://bench.example", 200, 0));
    let width = 1280_u32;
    let height = 800_u32;
    let screenshot = vec![0xEE_u8; (width * height * 4) as usize];
    c.bench_function("observe/set-of-marks-1280x800", |b| {
        b.iter(|| {
            black_box(
                composite_set_of_marks_rgba(&screenshot, width, height, &observation).unwrap(),
            )
        });
    });
}

criterion_group!(
    benches,
    bench_compile,
    bench_recompile_warm,
    bench_diff,
    bench_budget_truncation,
    bench_corpus_report,
    bench_serialized_len,
    bench_set_of_marks
);
criterion_main!(benches);
