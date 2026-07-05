//! SessionJournal append throughput under WAL + synchronous=NORMAL (#304).
//!
//! Satisfies the #232 / #314 acceptance bar: measure the post-WAL hot path that
//! replay-fork and decided-run journaling depend on. Before/after numbers for the
//! old DELETE+FULL config were captured in #304's test suite; this bench tracks
//! regression on the current configuration only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempo_schema::Action;
use tempo_session::{JournalEvent, RunId, SessionId, SessionJournal};

fn append_event(seq: u64) -> JournalEvent {
    JournalEvent::ActionPlanned {
        action: Action::Wait { millis: seq },
    }
}

fn bench_journal_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/journal-append");
    group.sample_size(10);
    for &count in &[50_usize, 200] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("journal.sqlite");
                    let journal = SessionJournal::open(
                        &path,
                        RunId("bench-run".into()),
                        SessionId("bench-session".into()),
                    )
                    .unwrap();
                    (dir, journal)
                },
                |(_dir, mut journal)| {
                    for seq in 0..count {
                        journal.append(append_event(seq as u64)).unwrap();
                    }
                    black_box(journal.next_seq())
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_journal_append);
criterion_main!(benches);
