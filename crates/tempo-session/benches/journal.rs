//! SessionJournal append throughput under WAL + synchronous=NORMAL (#304).
//!
//! Satisfies the #232 / #314 acceptance bar: measure the post-WAL hot path that
//! replay-fork and decided-run journaling depend on, alongside an in-tree
//! DELETE+FULL comparison path matching the pre-#304 durability posture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rusqlite::{params, Connection};
use std::path::Path;
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
        group.bench_with_input(
            BenchmarkId::new("wal-normal", count),
            &count,
            |b, &count| {
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
                    |(dir, mut journal)| {
                        for seq in 0..count {
                            journal.append(append_event(seq as u64)).unwrap();
                        }
                        black_box(journal.next_seq());
                        (dir, journal)
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("legacy-delete-full", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let path = dir.path().join("journal.sqlite");
                        let journal = LegacyDeleteFullJournal::open(&path).unwrap();
                        (dir, journal)
                    },
                    |(dir, mut journal)| {
                        for seq in 0..count {
                            journal
                                .append(seq as u64, append_event(seq as u64))
                                .unwrap();
                        }
                        black_box(journal.next_seq());
                        (dir, journal)
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

struct LegacyDeleteFullJournal {
    conn: Connection,
    next_seq: u64,
}

impl LegacyDeleteFullJournal {
    fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS journal_entries(
                 run_id TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 schema_version TEXT NOT NULL,
                 timestamp_ms TEXT NOT NULL,
                 event_json TEXT NOT NULL,
                 PRIMARY KEY(run_id, session_id, seq)
             );
             CREATE INDEX IF NOT EXISTS journal_entries_seq_idx
                 ON journal_entries(seq);",
        )?;
        Ok(Self { conn, next_seq: 0 })
    }

    fn append(&mut self, timestamp_ms: u64, event: JournalEvent) -> rusqlite::Result<()> {
        let seq = self.next_seq;
        let event_json = serde_json::to_string(&event)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO journal_entries(
                 run_id, session_id, seq, schema_version, timestamp_ms, event_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "bench-run",
                "bench-session",
                i64::try_from(seq).unwrap(),
                tempo_schema::SCHEMA_VERSION,
                timestamp_ms.to_string(),
                event_json,
            ],
        )?;
        tx.commit()?;
        self.next_seq += 1;
        Ok(())
    }

    fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

criterion_group!(benches, bench_journal_append);
criterion_main!(benches);
