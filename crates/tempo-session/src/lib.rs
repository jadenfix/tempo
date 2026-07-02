//! tempo-session — durable session journal and cassette replay primitives.
//!
//! The engine/runtime layers decide what to do. This crate makes those decisions
//! durable: every step is appended as a synced JSONL record, and every replayable
//! response is stored in a deterministic cassette format that can move between hosts.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
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
///
/// The journal holds a single file handle for its whole lifetime and takes an
/// advisory exclusive lock on it at [`open`](SessionJournal::open). This prevents
/// two writers from concurrently allocating the same sequence number (which would
/// permanently brick future opens with a [`JournalError::SequenceGap`]) and avoids
/// the reopen-per-append TOCTOU where a rotated/deleted file was silently recreated.
pub struct SessionJournal {
    path: PathBuf,
    /// Held for the journal's lifetime. Dropping the handle releases the advisory
    /// lock, so `file` must outlive every append.
    file: File,
    run_id: RunId,
    session_id: SessionId,
    next_seq: u64,
}

impl SessionJournal {
    /// Open or create a journal and recover the next sequence number from existing entries.
    ///
    /// Takes an advisory exclusive lock on the journal file; if another live
    /// [`SessionJournal`] already holds it, this fails with [`JournalError::Locked`]
    /// rather than racing to allocate duplicate sequence numbers.
    pub fn open(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(JournalError::Locked { path }),
            Err(TryLockError::Error(source)) => return Err(JournalError::Io(source)),
        }

        // Physically drop any torn final record left by a crash so that the next
        // append does not concatenate onto it and create genuine mid-file corruption.
        truncate_torn_tail(&path, &file)?;

        let entries = read_journal_entries(&path)?;
        validate_journal_entries(&entries, &run_id, &session_id)?;
        let next_seq = entries
            .iter()
            .map(|entry| entry.seq)
            .max()
            .map(|seq| seq + 1)
            .unwrap_or(0);

        Ok(Self {
            path,
            file,
            run_id,
            session_id,
            next_seq,
        })
    }

    /// Read a journal's recovered state without holding it open.
    ///
    /// Unlike [`open`](SessionJournal::open), this takes no lock: it is a read-only
    /// recovery snapshot and can be called while a writer holds the journal.
    pub fn resume(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<ResumeState, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(&path)?;

        let entries = read_journal_entries(&path)?;
        validate_journal_entries(&entries, &run_id, &session_id)?;
        let next_seq = entries
            .iter()
            .map(|entry| entry.seq)
            .max()
            .map(|seq| seq + 1)
            .unwrap_or(0);

        Ok(ResumeState {
            path,
            run_id,
            session_id,
            next_seq,
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

        serde_json::to_writer(&mut self.file, &entry)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;

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
    /// Derive the cassette key from request identity using SHA-256.
    ///
    /// URLs and bodies are page-controlled, so a non-collision-resistant hash (the
    /// former FNV-1a-64) let an attacker craft two distinct requests sharing one key
    /// and thereby substitute a chosen recorded response during replay. SHA-256 is
    /// collision-resistant and its 256-bit output removes birthday collisions on
    /// large corpora. Fields are length-unambiguously separated by NUL bytes.
    pub fn from_request(method: &str, url: &str, body: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update([0]);
        hasher.update(url.as_bytes());
        hasher.update([0]);
        hasher.update(body);
        let digest = hasher.finalize();

        let mut key = String::with_capacity(digest.len() * 2);
        for byte in digest {
            // Writing formatted hex into a String is infallible.
            let _ = write!(key, "{byte:02x}");
        }
        Self(key)
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
    #[error("journal is already locked by another session: {path:?}")]
    Locked { path: PathBuf },
    #[error("journal serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("journal line {line} is corrupt: {source}")]
    Corrupt {
        line: usize,
        source: serde_json::Error,
    },
    #[error(
        "journal identity mismatch at seq {seq}: expected run={expected_run:?} session={expected_session:?}, got run={actual_run:?} session={actual_session:?}"
    )]
    IdentityMismatch {
        seq: u64,
        expected_run: RunId,
        expected_session: SessionId,
        actual_run: RunId,
        actual_session: SessionId,
    },
    #[error("journal sequence gap at entry {index}: expected seq {expected}, got {actual}")]
    SequenceGap {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("system clock is before unix epoch")]
    ClockBeforeEpoch,
}

/// Human-readable crate summary retained for callers that expose crate capabilities.
pub fn describe() -> &'static str {
    "session lifecycle, synced JSONL journal, portable cassettes, and deterministic replay primitives"
}

pub fn read_journal_entries(path: impl AsRef<Path>) -> Result<Vec<JournalEntry>, JournalError> {
    read_jsonl(path)
}

pub fn read_cassettes(path: impl AsRef<Path>) -> Result<Vec<ResponseCassette>, JournalError> {
    read_jsonl(path)
}

/// Parse an append-only JSONL file into records.
///
/// A crash between the JSON write and the trailing newline+sync leaves a torn final
/// line. To keep such a session resumable, a single unparsable trailing record is
/// tolerated (dropped) **only** when the file does not end in a newline — i.e. it was
/// never fully committed. A completed line (one followed by `\n`) that fails to parse
/// is treated as genuine mid-file corruption and reported with its line number.
fn read_jsonl<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Vec<T>, JournalError> {
    let bytes = std::fs::read(path.as_ref())?;
    // A fully-committed record always ends in a newline. If the file does not, its
    // last segment is a partially-written (torn) record that may be dropped.
    let torn_tail_possible = bytes.last() != Some(&b'\n');
    let lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    let last_index = lines.len().saturating_sub(1);

    let mut records = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        // Parse from bytes so an invalid-UTF-8 torn tail is tolerated rather than
        // surfacing as a hard IO error.
        match serde_json::from_slice::<T>(raw) {
            Ok(record) => records.push(record),
            Err(source) => {
                if torn_tail_possible && index == last_index {
                    break;
                }
                return Err(JournalError::Corrupt {
                    line: index + 1,
                    source,
                });
            }
        }
    }

    Ok(records)
}

/// Truncate a torn trailing record (bytes after the last committed newline) so the
/// journal file contains only fully-synced records before the next append.
///
/// Every committed append ends in `\n`, so any bytes past the final newline are an
/// incomplete write from a crash and are safe to discard. A file that already ends in
/// a newline (or is empty) is left untouched.
fn truncate_torn_tail(path: &Path, file: &File) -> Result<(), JournalError> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|idx| idx as u64 + 1)
        .unwrap_or(0);
    file.set_len(keep)?;
    file.sync_all()?;
    Ok(())
}

fn validate_journal_entries(
    entries: &[JournalEntry],
    run_id: &RunId,
    session_id: &SessionId,
) -> Result<(), JournalError> {
    for (index, entry) in entries.iter().enumerate() {
        if &entry.run_id != run_id || &entry.session_id != session_id {
            return Err(JournalError::IdentityMismatch {
                seq: entry.seq,
                expected_run: run_id.clone(),
                expected_session: session_id.clone(),
                actual_run: entry.run_id.clone(),
                actual_session: entry.session_id.clone(),
            });
        }
        let expected = index as u64;
        if entry.seq != expected {
            return Err(JournalError::SequenceGap {
                index,
                expected,
                actual: entry.seq,
            });
        }
    }
    Ok(())
}

fn current_timestamp_ms() -> Result<u128, JournalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::ClockBeforeEpoch)?;
    Ok(duration.as_millis())
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
    fn journal_resume_matrix_survives_crash_after_each_event() -> TestResult {
        let path = unique_path("crash-matrix")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-crash".into());
        let session_id = SessionId("session-crash".into());
        let events = crash_matrix_events();

        for crash_after in 0..=events.len() {
            remove_if_exists(&path)?;
            {
                let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
                for event in events.iter().take(crash_after).cloned() {
                    journal.append(event)?;
                }
            }

            let resumed = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
            assert_eq!(
                resumed.entries.len(),
                crash_after,
                "crash_after={crash_after}"
            );
            assert_eq!(resumed.next_seq, crash_after as u64);
            for (index, entry) in resumed.entries.iter().enumerate() {
                assert_eq!(entry.seq, index as u64);
                assert_eq!(entry.run_id, run_id);
                assert_eq!(entry.session_id, session_id);
            }

            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            for event in events.iter().skip(crash_after).cloned() {
                journal.append(event)?;
            }
            let complete = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
            assert_eq!(complete.entries.len(), events.len());
            assert_eq!(complete.next_seq, events.len() as u64);
        }

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn journal_rejects_resume_with_wrong_identity() -> TestResult {
        let path = unique_path("identity-mismatch")?;
        remove_if_exists(&path)?;
        let mut journal = SessionJournal::open(
            &path,
            RunId("original-run".into()),
            SessionId("original-session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;

        let result = SessionJournal::resume(
            &path,
            RunId("different-run".into()),
            SessionId("original-session".into()),
        );
        assert!(matches!(result, Err(JournalError::IdentityMismatch { .. })));

        // Reopening requires the advisory lock, so release the live journal first.
        drop(journal);

        let result = SessionJournal::open(
            &path,
            RunId("original-run".into()),
            SessionId("different-session".into()),
        );
        assert!(matches!(result, Err(JournalError::IdentityMismatch { .. })));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn journal_rejects_sequence_gaps_on_resume() -> TestResult {
        let path = unique_path("sequence-gap")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-gap".into());
        let session_id = SessionId("session-gap".into());

        write_entry(
            &path,
            JournalEntry {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                run_id: run_id.clone(),
                session_id: session_id.clone(),
                seq: 0,
                timestamp_ms: 1,
                event: JournalEvent::SessionStarted {
                    url: "https://example.com".into(),
                },
            },
        )?;
        write_entry(
            &path,
            JournalEntry {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                run_id: run_id.clone(),
                session_id: session_id.clone(),
                seq: 2,
                timestamp_ms: 2,
                event: JournalEvent::SessionClosed,
            },
        )?;

        assert!(matches!(
            SessionJournal::resume(&path, run_id, session_id),
            Err(JournalError::SequenceGap {
                index: 1,
                expected: 1,
                actual: 2,
            })
        ));

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

    #[test]
    fn torn_final_line_still_loads_earlier_entries_and_resumes() -> TestResult {
        let path = unique_path("torn-tail")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-torn".into());
        let session_id = SessionId("session-torn".into());

        // Two fully-synced entries.
        {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
            journal.append(JournalEvent::ActionPlanned {
                action: Action::Goto {
                    url: "https://example.com".into(),
                },
            })?;
        }

        // Simulate a crash mid-write of a third record: a partial JSON fragment with
        // no trailing newline is left after the last committed entry.
        {
            let mut file = OpenOptions::new().append(true).open(&path)?;
            file.write_all(br#"{"schema_version":"0.1","seq":2,"even"#)?;
            file.flush()?;
        }

        // A read still recovers the earlier valid entries (the torn tail is dropped).
        let entries = read_journal_entries(&path)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 1);

        // Resume reports a consistent recovery snapshot.
        let resumed = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
        assert_eq!(resumed.entries.len(), 2);
        assert_eq!(resumed.next_seq, 2);

        // Reopening repairs the file so appends continue from the right sequence and
        // the journal stays parseable afterwards.
        let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        let appended = journal.append(JournalEvent::SessionClosed)?;
        assert_eq!(appended.seq, 2);
        drop(journal);

        let final_state = SessionJournal::resume(&path, run_id, session_id)?;
        assert_eq!(final_state.entries.len(), 3);
        assert_eq!(final_state.next_seq, 3);
        assert_eq!(final_state.entries[2].seq, 2);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn concurrent_open_is_rejected_so_seq_numbers_cannot_collide() -> TestResult {
        let path = unique_path("lock-contended")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-lock".into());
        let session_id = SessionId("session-lock".into());

        let mut first = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        first.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;

        // A second concurrent open of the same journal must fail rather than allocate
        // a duplicate seq that would brick every future open with a SequenceGap.
        let contended = SessionJournal::open(&path, run_id.clone(), session_id.clone());
        assert!(matches!(contended, Err(JournalError::Locked { .. })));

        // Once the first writer is dropped, the lock is released and reopening works.
        drop(first);
        let mut second = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        let entry = second.append(JournalEvent::SessionClosed)?;
        assert_eq!(entry.seq, 1);
        drop(second);

        let resumed = SessionJournal::resume(&path, run_id, session_id)?;
        assert_eq!(resumed.entries.len(), 2);
        assert_eq!(resumed.next_seq, 2);
        assert_eq!(resumed.entries[0].seq, 0);
        assert_eq!(resumed.entries[1].seq, 1);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_key_is_sha256_based_and_stable() {
        let a = CassetteKey::from_request("GET", "https://example.com/api", b"payload");
        let b = CassetteKey::from_request("GET", "https://example.com/api", b"payload");
        // Deterministic: identical input yields an identical key.
        assert_eq!(a, b);

        // SHA-256 hex digest is 64 lowercase hex characters.
        assert_eq!(a.0.len(), 64);
        assert!(a
            .0
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Known SHA-256 of "GET\0https://example.com/api\0payload".
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(b"GET\0https://example.com/api\0payload");
            let digest = hasher.finalize();
            let mut key = String::with_capacity(digest.len() * 2);
            for byte in digest {
                let _ = write!(key, "{byte:02x}");
            }
            key
        };
        assert_eq!(a.0, expected);

        // Distinct request components produce distinct keys (field separation is
        // unambiguous: "GET" + "x" must not collide with "GETx" + "").
        let split = CassetteKey::from_request("GET", "x", b"");
        let joined = CassetteKey::from_request("GETx", "", b"");
        assert_ne!(split, joined);

        let other_method = CassetteKey::from_request("POST", "https://example.com/api", b"payload");
        assert_ne!(a, other_method);
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

    fn crash_matrix_events() -> Vec<JournalEvent> {
        vec![
            JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            },
            JournalEvent::Observation {
                observation: CompiledObservation {
                    schema_version: tempo_schema::SCHEMA_VERSION.into(),
                    url: "https://example.com".into(),
                    seq: 0,
                    elements: vec![],
                    marks: vec![],
                },
            },
            JournalEvent::ActionPlanned {
                action: Action::Click {
                    node: NodeId("button.checkout".into()),
                },
            },
            JournalEvent::StepApplied {
                action: Action::Click {
                    node: NodeId("button.checkout".into()),
                },
                diff: ObservationDiff {
                    since_seq: 0,
                    seq: 1,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
            JournalEvent::CassetteRecorded {
                key: CassetteKey("checkout-response".into()),
            },
            JournalEvent::SessionClosed,
        ]
    }

    fn write_entry(path: &Path, entry: JournalEntry) -> Result<(), JournalError> {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        serde_json::to_writer(&mut file, &entry)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }
}
