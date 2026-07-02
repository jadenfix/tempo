//! tempo-session — durable session journal and cassette replay primitives.
//!
//! The engine/runtime layers decide what to do. This crate makes those decisions
//! durable: every step is appended as a synced JSONL record, and every replayable
//! response is stored in a deterministic cassette format that can move between hosts.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_driver::{StepOutcome, TransportError};
use tempo_schema::{Action, CompiledObservation, ObservationDiff};
use thiserror::Error;

/// Stable session identifier recorded in every journal entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// Stable run identifier recorded in every journal entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunId(pub String);

/// One durable session event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEvent {
    SessionStarted {
        url: String,
    },
    Observation {
        observation: CompiledObservation,
    },
    ActionPlanned {
        action: Action,
    },
    StepApplied {
        action: Action,
        diff: ObservationDiff,
    },
    StepError {
        action: Action,
        reason: String,
    },
    TransportError {
        context: String,
        reason: String,
    },
    CassetteRecorded {
        key: CassetteKey,
    },
    SessionClosed,
}

impl JournalEvent {
    /// Convert a driver step result into the journal shape that survives process restarts.
    pub fn from_step_outcome(action: Action, outcome: StepOutcome) -> Self {
        match outcome {
            StepOutcome::Applied { diff } => Self::StepApplied { action, diff },
            StepOutcome::StepError { reason } => Self::StepError { action, reason },
        }
    }

    /// Convert a transport failure into a journalable event without coupling the journal
    /// format to engine-specific error enums.
    pub fn from_transport_error(context: impl Into<String>, error: &TransportError) -> Self {
        Self::TransportError {
            context: context.into(),
            reason: error.to_string(),
        }
    }
}

/// One append-only JSONL journal entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub schema_version: String,
    pub run_id: RunId,
    pub session_id: SessionId,
    pub seq: u64,
    pub timestamp_ms: u128,
    pub event: JournalEvent,
}

/// State recovered when a journal is reopened after a crash.
#[derive(Clone, Debug, PartialEq)]
pub struct ResumeState {
    pub path: PathBuf,
    pub run_id: RunId,
    pub session_id: SessionId,
    pub next_seq: u64,
    pub entries: Vec<JournalEntry>,
}

/// Append-only session journal. Each append is flushed and synced before returning.
pub struct SessionJournal {
    path: PathBuf,
    run_id: RunId,
    session_id: SessionId,
    next_seq: u64,
}

impl SessionJournal {
    /// Open or create a journal and recover the next sequence number from existing entries.
    pub fn open(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(&path)?;

        let entries = read_journal_entries(&path)?;
        let next_seq = entries
            .iter()
            .map(|entry| entry.seq)
            .max()
            .map(|seq| seq + 1)
            .unwrap_or(0);

        Ok(Self {
            path,
            run_id,
            session_id,
            next_seq,
        })
    }

    /// Reopen a journal and return all recovered entries.
    pub fn resume(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<ResumeState, JournalError> {
        let journal = Self::open(path, run_id, session_id)?;
        let entries = read_journal_entries(&journal.path)?;
        Ok(ResumeState {
            path: journal.path,
            run_id: journal.run_id,
            session_id: journal.session_id,
            next_seq: journal.next_seq,
            entries,
        })
    }

    /// Append one event, flush it, and sync it before returning.
    pub fn append(&mut self, event: JournalEvent) -> Result<JournalEntry, JournalError> {
        let entry = JournalEntry {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            run_id: self.run_id.clone(),
            session_id: self.session_id.clone(),
            seq: self.next_seq,
            timestamp_ms: current_timestamp_ms()?,
            event,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &entry)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;

        self.next_seq += 1;
        Ok(entry)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Deterministic key for replayable request/response cassettes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CassetteKey(pub String);

impl CassetteKey {
    pub fn from_request(method: &str, url: &str, body: &[u8]) -> Self {
        let mut hash = Fnv1a64::new();
        hash.update(method.as_bytes());
        hash.update(&[0]);
        hash.update(url.as_bytes());
        hash.update(&[0]);
        hash.update(body);
        Self(format!("{:016x}", hash.finish()))
    }
}

/// Byte-stable replay record. No host-local paths or timestamps are stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseCassette {
    pub key: CassetteKey,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ResponseCassette {
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self::for_request(method, url, [], status, headers, body)
    }

    pub fn for_request(
        method: impl Into<String>,
        url: impl Into<String>,
        request_body: impl AsRef<[u8]>,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        let method = method.into();
        let url = url.into();
        let key = CassetteKey::from_request(&method, &url, request_body.as_ref());
        Self {
            key,
            method,
            url,
            status,
            headers,
            body,
        }
    }
}

/// Append-only cassette store used by replay-fork and deterministic re-execution.
pub struct CassetteStore {
    path: PathBuf,
}

impl CassetteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path })
    }

    pub fn record(&self, cassette: &ResponseCassette) -> Result<(), JournalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, cassette)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    pub fn replay(&self, key: &CassetteKey) -> Result<Option<ResponseCassette>, JournalError> {
        for cassette in read_cassettes(&self.path)? {
            if &cassette.key == key {
                return Ok(Some(cassette));
            }
        }
        Ok(None)
    }

    pub fn all(&self) -> Result<Vec<ResponseCassette>, JournalError> {
        read_cassettes(&self.path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("journal line {line} is corrupt: {source}")]
    Corrupt {
        line: usize,
        source: serde_json::Error,
    },
    #[error("system clock is before unix epoch")]
    ClockBeforeEpoch,
}

/// Human-readable crate summary retained for callers that expose crate capabilities.
pub fn describe() -> &'static str {
    "session lifecycle, synced JSONL journal, portable cassettes, and deterministic replay primitives"
}

pub fn read_journal_entries(path: impl AsRef<Path>) -> Result<Vec<JournalEntry>, JournalError> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str(&line).map_err(|source| JournalError::Corrupt {
            line: index + 1,
            source,
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

pub fn read_cassettes(path: impl AsRef<Path>) -> Result<Vec<ResponseCassette>, JournalError> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut cassettes = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let cassette = serde_json::from_str(&line).map_err(|source| JournalError::Corrupt {
            line: index + 1,
            source,
        })?;
        cassettes.push(cassette);
    }

    Ok(cassettes)
}

fn current_timestamp_ms() -> Result<u128, JournalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::ClockBeforeEpoch)?;
    Ok(duration.as_millis())
}

struct Fnv1a64(u64);

impl Fnv1a64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use tempo_schema::{NodeId, QuiescencePolicy};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn journal_reopens_after_each_synced_step_without_losing_entries() -> TestResult {
        let path = unique_path("journal-reopen")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-a".into());
        let session_id = SessionId("session-a".into());

        let events = vec![
            JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            },
            JournalEvent::ActionPlanned {
                action: Action::Goto {
                    url: "https://example.com".into(),
                },
            },
            JournalEvent::StepApplied {
                action: Action::Scroll { x: 0.0, y: 25.0 },
                diff: ObservationDiff {
                    since_seq: 0,
                    seq: 1,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
            JournalEvent::SessionClosed,
        ];

        for (expected_len, event) in events.into_iter().enumerate() {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            journal.append(event)?;
            let resumed = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
            assert_eq!(resumed.entries.len(), expected_len + 1);
            assert_eq!(resumed.next_seq, (expected_len + 1) as u64);
            assert_eq!(resumed.entries[expected_len].seq, expected_len as u64);
        }

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn step_outcome_conversion_preserves_grounding_failures() {
        let action = Action::Click {
            node: NodeId("missing".into()),
        };
        let event = JournalEvent::from_step_outcome(
            action.clone(),
            StepOutcome::StepError {
                reason: "node not found".into(),
            },
        );

        assert_eq!(
            event,
            JournalEvent::StepError {
                action,
                reason: "node not found".into(),
            }
        );
    }

    #[test]
    fn cassette_replay_is_byte_stable() -> TestResult {
        let path_a = unique_path("cassette-a")?;
        let path_b = unique_path("cassette-b")?;
        remove_if_exists(&path_a)?;
        remove_if_exists(&path_b)?;

        let first = ResponseCassette::new(
            "GET",
            "https://example.com/api",
            200,
            vec![("content-type".into(), "application/json".into())],
            br#"{"ok":true}"#.to_vec(),
        );
        let second = ResponseCassette::new(
            "POST",
            "https://example.com/form",
            201,
            vec![("x-tempo".into(), "recorded".into())],
            b"created".to_vec(),
        );

        let store_a = CassetteStore::open(&path_a)?;
        store_a.record(&first)?;
        store_a.record(&second)?;
        let bytes_a = fs::read_to_string(&path_a)?;

        let store_b = CassetteStore::open(&path_b)?;
        for cassette in store_a.all()? {
            store_b.record(&cassette)?;
        }
        let bytes_b = fs::read_to_string(&path_b)?;

        assert_eq!(bytes_a, bytes_b);
        assert_eq!(store_a.replay(&first.key)?, Some(first));
        assert_eq!(store_a.replay(&CassetteKey("missing".into()))?, None);

        remove_if_exists(&path_a)?;
        remove_if_exists(&path_b)?;
        Ok(())
    }

    #[test]
    fn journal_records_are_host_portable() -> TestResult {
        let path = unique_path("portable")?;
        remove_if_exists(&path)?;
        let mut journal = SessionJournal::open(
            &path,
            RunId("portable-run".into()),
            SessionId("portable-session".into()),
        )?;

        journal.append(JournalEvent::ActionPlanned {
            action: Action::Skill {
                name: "extract-price".into(),
                input: serde_json::json!({
                    "quiescence": format!("{:?}", QuiescencePolicy::Composite),
                }),
            },
        })?;

        let serialized = fs::read_to_string(&path)?;
        let path_text = path.to_string_lossy();
        assert!(!serialized.contains(path_text.as_ref()));
        assert!(!serialized.contains("target/debug"));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn corrupt_journal_lines_are_reported_with_line_numbers() -> TestResult {
        let path = unique_path("corrupt")?;
        remove_if_exists(&path)?;
        let mut journal = SessionJournal::open(
            &path,
            RunId("corrupt-run".into()),
            SessionId("corrupt-session".into()),
        )?;
        journal.append(JournalEvent::SessionClosed)?;
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(b"not-json\n")?;

        let err = read_journal_entries(&path).err();
        assert!(matches!(err, Some(JournalError::Corrupt { line: 2, .. })));

        remove_if_exists(&path)?;
        Ok(())
    }

    fn unique_path(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-session-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}
