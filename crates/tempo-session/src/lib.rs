//! tempo-session — durable session journal and cassette replay primitives.
//!
//! The engine/runtime layers decide what to do. This crate makes those decisions
//! durable: every step is committed to a SQLite journal, and every replayable
//! response is stored in a deterministic cassette format that can move between hosts.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempo_driver::{StepOutcome, TransportError};
use tempo_schema::{Action, CompiledObservation, HumanTakeover, ObservationDiff};
use thiserror::Error;

pub const TEMPO_STEALTH_MODE_ENV: &str = "TEMPO_STEALTH_MODE";
pub const TEMPO_DURABLE_RETENTION_ENV: &str = "TEMPO_DURABLE_RETENTION";
pub const TEMPO_DURABLE_ENCRYPTION_KEY_HEX_ENV: &str = "TEMPO_DURABLE_ENCRYPTION_KEY_HEX";
pub const DURABLE_ENCRYPTION_KEY_BYTES: usize = 32;
const ENCRYPTED_RECORD_VERSION: u8 = 1;
const ENCRYPTED_RECORD_ALGORITHM: &str = "XChaCha20-Poly1305";

/// Explicit durable-state retention policy for journals and replay cassettes.
///
/// `PlaintextUnsafe` is retained for compatibility and local audit fixtures, but it
/// writes URLs, actions, headers, and bodies as readable local artifacts. Production
/// audit/replay paths should use `Encrypted` with a key owned by the caller's OS
/// keychain, fleet KMS, or an ephemeral per-session secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableRetentionPolicy {
    PlaintextUnsafe,
    Encrypted { key: DurableEncryptionKey },
}

impl DurableRetentionPolicy {
    pub fn encrypted(key: DurableEncryptionKey) -> Self {
        Self::Encrypted { key }
    }

    pub fn from_env() -> Result<Self, JournalError> {
        durable_retention_policy_from_env()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DurableEncryptionKey([u8; DURABLE_ENCRYPTION_KEY_BYTES]);

impl DurableEncryptionKey {
    pub fn from_bytes(bytes: [u8; DURABLE_ENCRYPTION_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, JournalError> {
        let key = <[u8; DURABLE_ENCRYPTION_KEY_BYTES]>::try_from(bytes).map_err(|_| {
            JournalError::InvalidEncryptionKeyLength {
                expected: DURABLE_ENCRYPTION_KEY_BYTES,
                actual: bytes.len(),
            }
        })?;
        Ok(Self(key))
    }

    pub fn from_hex(hex: &str) -> Result<Self, JournalError> {
        Self::from_slice(&hex_decode(hex)?)
    }

    fn as_bytes(&self) -> &[u8; DURABLE_ENCRYPTION_KEY_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for DurableEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DurableEncryptionKey(<redacted>)")
    }
}

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
    StructuredFastPathSelected {
        origin: String,
        lane: String,
        signal: String,
        source: String,
    },
    Observation {
        observation: CompiledObservation,
    },
    /// One model-decided action batch, journaled before any of its actions run
    /// (journal-before-effect, #248). Provider token usage is recorded per
    /// decision so cache-hit rate stays observable (`cache_read_input_tokens`,
    /// #218).
    ModelDecision {
        actions: Vec<Action>,
        rationale: Option<String>,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_input_tokens: u64,
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
    /// A CAPTCHA / auth-wall / login state was detected on the post-action page
    /// and the run hard-paused for a human to take over (#244). This is NOT a
    /// step error and NOT retryable: a resumed run replays this event and stops
    /// again rather than auto-continuing. tempo never solves the challenge.
    HumanTakeoverRequired {
        takeover: HumanTakeover,
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

/// Append-only session journal. Each append is committed before returning.
///
/// The journal holds a sidecar lock file for its whole lifetime. This prevents
/// two live writers from concurrently allocating sequence numbers while keeping
/// every event durable as its own SQLite transaction.
///
/// # Dedicated writer
///
/// `conn` is the journal's dedicated writer: the only read-write SQLite connection
/// this crate ever opens for a journal. The sidecar lock makes it unique across
/// processes and `append(&mut self)` serializes writes within one, so all writes flow
/// through this single connection without any cross-connection write contention.
/// Every other connection ([`resume`](SessionJournal::resume),
/// [`read_journal_entries`]) is read-only, and in WAL mode reads never block on this
/// writer (and vice versa).
///
/// # WAL sidecar files and cross-host portability
///
/// While a journal is open it runs in `journal_mode=WAL`, so recent commits live in
/// `<journal>-wal` (with a `<journal>-shm` index). Dropping the journal converts it
/// back to rollback mode, which checkpoints the WAL into the main file and removes
/// both sidecars: a cleanly closed journal is a single self-contained file that any
/// host can open — including read-only, which not every SQLite build supports for a
/// WAL-stamped file missing its sidecars. If a process died mid-session, copy the
/// `-wal` and `-shm` files along with the journal — or open and cleanly close it
/// locally first — otherwise the most recent commits are left behind.
pub struct SessionJournal {
    path: PathBuf,
    /// Held for the journal's lifetime. Dropping the handle releases the advisory lock.
    _lock: File,
    /// Dedicated writer connection; see the struct-level docs.
    conn: Connection,
    retention_policy: DurableRetentionPolicy,
    run_id: RunId,
    session_id: SessionId,
    next_seq: u64,
}

impl SessionJournal {
    /// Open or create a journal and recover the next sequence number from existing entries.
    ///
    /// Takes an advisory exclusive lock on a sidecar file; if another live
    /// [`SessionJournal`] already holds it, this fails with [`JournalError::Locked`]
    /// rather than racing to allocate duplicate sequence numbers.
    pub fn open(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<Self, JournalError> {
        Self::open_with_retention_policy(
            path,
            run_id,
            session_id,
            DurableRetentionPolicy::PlaintextUnsafe,
        )
    }

    pub fn open_with_retention_policy(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<Self, JournalError> {
        Self::open_with_stealth_value(
            path,
            run_id,
            session_id,
            std::env::var_os(TEMPO_STEALTH_MODE_ENV),
            retention_policy,
        )
    }

    fn open_with_stealth_value(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        stealth_value: Option<OsString>,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<Self, JournalError> {
        reject_durable_state_in_stealth_mode_value(stealth_value)?;
        let path = path.as_ref().to_path_buf();
        let lock = lock_journal_writer(&path)?;
        let conn = open_journal_connection(&path, JournalOpenMode::ReadWriteCreate)?;

        let entries = read_journal_entries_from_connection(&conn, &retention_policy)?;
        validate_journal_entries(&entries, &run_id, &session_id)?;
        let next_seq = entries
            .iter()
            .map(|entry| entry.seq)
            .max()
            .map(|seq| seq + 1)
            .unwrap_or(0);

        Ok(Self {
            path,
            _lock: lock,
            conn,
            retention_policy,
            run_id,
            session_id,
            next_seq,
        })
    }

    /// Read a journal's recovered state without holding it open.
    ///
    /// Unlike [`open`](SessionJournal::open), this takes no writer lock: it is a
    /// read-only recovery snapshot and can be called while a writer holds the journal.
    pub fn resume(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<ResumeState, JournalError> {
        Self::resume_with_retention_policy(
            path,
            run_id,
            session_id,
            DurableRetentionPolicy::PlaintextUnsafe,
        )
    }

    pub fn resume_with_retention_policy(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<ResumeState, JournalError> {
        Self::resume_with_stealth_value(
            path,
            run_id,
            session_id,
            std::env::var_os(TEMPO_STEALTH_MODE_ENV),
            retention_policy,
        )
    }

    fn resume_with_stealth_value(
        path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        stealth_value: Option<OsString>,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<ResumeState, JournalError> {
        reject_durable_state_in_stealth_mode_value(stealth_value)?;
        let path = path.as_ref().to_path_buf();
        // Read-only snapshot: no writer lock, no schema init, no pragma writes, and it
        // never creates the database. A journal that does not exist yet resumes as an
        // empty session rather than being materialized on disk.
        let entries = match open_readonly_connection(&path)? {
            Some(conn) => read_journal_entries_from_connection(&conn, &retention_policy)?,
            None => Vec::new(),
        };
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

    /// Append one event in a committed SQLite transaction before returning.
    pub fn append(&mut self, event: JournalEvent) -> Result<JournalEntry, JournalError> {
        reject_durable_state_in_stealth_mode()?;
        let entry = JournalEntry {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            run_id: self.run_id.clone(),
            session_id: self.session_id.clone(),
            seq: self.next_seq,
            timestamp_ms: current_timestamp_ms()?,
            event,
        };

        insert_journal_entry(&mut self.conn, &entry, &self.retention_policy)?;

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

impl Drop for SessionJournal {
    fn drop(&mut self) {
        // Checkpoint on clean close: converting out of WAL checkpoints the log,
        // deletes the -wal/-shm sidecars, and stamps the header back to rollback
        // mode, leaving one self-contained file for cross-host copies. This matters
        // because a sidecar-less WAL-stamped database cannot be opened by read-only
        // connections on every SQLite build (macOS system SQLite returns
        // SQLITE_CANTOPEN), which would break the lock-free read/resume paths.
        // Best-effort by design — Drop cannot fail; if a concurrent read snapshot
        // holds the database past the busy timeout, the file simply stays in WAL
        // mode (with its sidecars) until the next clean close.
        let _ = self
            .conn
            .query_row("PRAGMA journal_mode=DELETE", [], |_| Ok(()));
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
    /// large corpora. Fields are versioned and length-prefixed so page-controlled
    /// NUL bytes cannot move data across component boundaries.
    pub fn from_request(method: &str, url: &str, body: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"tempo-session:cassette-key:v2\0");
        update_length_prefixed(&mut hasher, method.as_bytes());
        update_length_prefixed(&mut hasher, url.as_bytes());
        update_length_prefixed(&mut hasher, body);
        Self::from_hasher(hasher)
    }

    fn legacy_v1_from_request(method: &str, url: &str, body: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update([0]);
        hasher.update(url.as_bytes());
        hasher.update([0]);
        hasher.update(body);
        Self::from_hasher(hasher)
    }

    fn from_hasher(hasher: Sha256) -> Self {
        let digest = hasher.finalize();
        let mut key = String::with_capacity(digest.len() * 2);
        for byte in digest {
            // Writing formatted hex into a String is infallible.
            let _ = write!(key, "{byte:02x}");
        }
        Self(key)
    }
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
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
///
/// Lookups are served by an incremental in-memory index of `key -> byte span`
/// built lazily over the JSONL file, so `record`/`replay` decode only new tail
/// bytes plus the single record they touch instead of re-reading and
/// re-decoding the whole file per call. The index stores offsets, not
/// payloads, so resident memory stays flat regardless of cassette sizes.
pub struct CassetteStore {
    path: PathBuf,
    retention_policy: DurableRetentionPolicy,
    index: Mutex<CassetteIndex>,
}

/// Byte span of one encoded cassette record line in the backing file.
#[derive(Clone, Copy, Debug)]
struct CassetteSpan {
    offset: u64,
    len: usize,
}

#[derive(Debug, Default)]
struct CassetteIndex {
    by_key: HashMap<CassetteKey, CassetteSpan>,
    /// File length covered by the index, always ending on a newline boundary
    /// (or 0). A shorter file than this means truncation: rebuild from scratch.
    indexed_bytes: u64,
    /// Newline-terminated lines covered, for parity with whole-file scan
    /// error line numbers.
    indexed_lines: usize,
}

impl CassetteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        Self::open_with_retention_policy(path, DurableRetentionPolicy::PlaintextUnsafe)
    }

    pub fn open_with_retention_policy(
        path: impl AsRef<Path>,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<Self, JournalError> {
        Self::open_with_stealth_value(
            path,
            std::env::var_os(TEMPO_STEALTH_MODE_ENV),
            retention_policy,
        )
    }

    fn open_with_stealth_value(
        path: impl AsRef<Path>,
        stealth_value: Option<OsString>,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<Self, JournalError> {
        reject_durable_state_in_stealth_mode_value(stealth_value)?;
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        apply_private_file_mode(&mut options);
        let file = options.open(&path)?;
        ensure_private_file_permissions(&file)?;
        Ok(Self {
            path,
            retention_policy,
            index: Mutex::new(CassetteIndex::default()),
        })
    }

    pub fn record(&self, cassette: &ResponseCassette) -> Result<(), JournalError> {
        reject_durable_state_in_stealth_mode()?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        apply_private_file_mode(&mut options);
        let mut file = options.open(&self.path)?;
        ensure_private_file_permissions(&file)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(JournalError::Locked {
                    path: self.path.clone(),
                });
            }
            Err(TryLockError::Error(source)) => return Err(JournalError::Io(source)),
        }

        let append_boundary = repair_cassette_tail_before_append(&file)?;

        let mut index = self.lock_index();
        self.catch_up_index(&mut index)?;
        if index.by_key.contains_key(&cassette.key) {
            let existing = self.read_indexed_cassette(&index, &cassette.key)?;
            if existing.as_ref() == Some(cassette) {
                return Ok(());
            }
            return Err(JournalError::CassetteConflict {
                key: cassette.key.clone(),
            });
        }

        let cassette_json = serde_json::to_vec(cassette)?;
        let mut frame =
            encode_durable_record_bytes(&cassette_json, &self.retention_policy, cassette_aad())?;
        let record_len = frame.len();
        frame.push(b'\n');
        let mut offset = file.metadata()?.len();
        if let CassetteAppendBoundary::NeedsNewline = append_boundary {
            frame.insert(0, b'\n');
            offset += 1;
        }
        // One write_all per record, no per-record fsync: durability is the OS
        // page cache, the same posture as the journal's WAL
        // `synchronous=NORMAL` (fsync deferred to checkpoints). A torn append
        // after a crash is repaired by `repair_cassette_tail_before_append`.
        file.write_all(&frame)?;

        // The append is visible to every subsequent read on this store: extend
        // the index in place instead of paying a tail re-scan on the next call.
        index.by_key.insert(
            cassette.key.clone(),
            CassetteSpan {
                offset,
                len: record_len,
            },
        );
        if index.indexed_bytes == offset {
            index.indexed_bytes = offset + record_len as u64 + 1;
            index.indexed_lines += 1;
        }
        Ok(())
    }

    pub fn replay(&self, key: &CassetteKey) -> Result<Option<ResponseCassette>, JournalError> {
        reject_durable_state_in_stealth_mode()?;
        let mut index = self.lock_index();
        self.catch_up_index(&mut index)?;
        self.read_indexed_cassette(&index, key)
    }

    fn lock_index(&self) -> std::sync::MutexGuard<'_, CassetteIndex> {
        // A poisoned mutex only means another thread panicked mid-update; the
        // index is rebuilt defensively, so recover the guard.
        match self.index.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = CassetteIndex::default();
                guard
            }
        }
    }

    /// Bring the index up to date with bytes appended since the last call.
    /// Truncation (tail repair, external rewrite) is detected by a shrinking
    /// file and triggers a full rebuild.
    fn catch_up_index(&self, index: &mut CassetteIndex) -> Result<(), JournalError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                *index = CassetteIndex::default();
                return Ok(());
            }
            Err(source) => return Err(JournalError::Io(source)),
        };
        let file_len = file.metadata()?.len();
        if file_len < index.indexed_bytes {
            *index = CassetteIndex::default();
        }
        if file_len == index.indexed_bytes {
            return Ok(());
        }

        let base = index.indexed_bytes;
        file.seek(SeekFrom::Start(base))?;
        let mut tail = Vec::with_capacity((file_len - base) as usize);
        file.read_to_end(&mut tail)?;

        let mut cursor = 0usize;
        while cursor < tail.len() {
            let newline = tail[cursor..].iter().position(|byte| *byte == b'\n');
            let (line_end, terminated) = match newline {
                Some(relative) => (cursor + relative, true),
                None => (tail.len(), false),
            };
            let raw = &tail[cursor..line_end];
            let line_number = index.indexed_lines + 1;

            if raw.iter().all(u8::is_ascii_whitespace) {
                if !terminated {
                    break;
                }
                cursor = line_end + 1;
                index.indexed_bytes = base + cursor as u64;
                index.indexed_lines = line_number;
                continue;
            }

            let decoded =
                match decode_durable_record_bytes(raw, &self.retention_policy, cassette_aad()) {
                    Ok(decoded) => decoded,
                    Err(source) => {
                        if !terminated && is_incomplete_json_record(raw) {
                            // Torn tail from an interrupted append: readable
                            // records before it stay served; the tail is
                            // re-examined on the next call.
                            break;
                        }
                        return Err(source);
                    }
                };
            let record = match serde_json::from_slice::<ResponseCassette>(&decoded) {
                Ok(record) => record,
                Err(source) => {
                    if !terminated && is_incomplete_json_record(raw) {
                        break;
                    }
                    return Err(JournalError::Corrupt {
                        line: line_number,
                        source,
                    });
                }
            };
            let span = CassetteSpan {
                offset: base + cursor as u64,
                len: raw.len(),
            };
            // First writer wins, matching the whole-file scan which returned
            // the earliest record for a key.
            index.by_key.entry(record.key).or_insert(span);
            if terminated {
                cursor = line_end + 1;
                index.indexed_bytes = base + cursor as u64;
                index.indexed_lines = line_number;
            } else {
                // Complete record without a trailing newline (crash between
                // record and separator writes): serve it, but leave the
                // watermark before it so the next catch-up re-anchors on a
                // newline boundary.
                break;
            }
        }
        Ok(())
    }

    /// Read and decode exactly one indexed record.
    fn read_indexed_cassette(
        &self,
        index: &CassetteIndex,
        key: &CassetteKey,
    ) -> Result<Option<ResponseCassette>, JournalError> {
        let Some(span) = index.by_key.get(key) else {
            return Ok(None);
        };
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(span.offset))?;
        let mut raw = vec![0_u8; span.len];
        file.read_exact(&mut raw)?;
        let decoded = decode_durable_record_bytes(&raw, &self.retention_policy, cassette_aad())?;
        let record: ResponseCassette = serde_json::from_slice(&decoded)
            .map_err(|source| JournalError::Corrupt { line: 0, source })?;
        if &record.key != key {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Replay a request using the current key format, migrating pre-v2 cassette
    /// records when a legacy key is the only match.
    pub fn replay_request(
        &self,
        method: &str,
        url: &str,
        request_body: impl AsRef<[u8]>,
    ) -> Result<Option<ResponseCassette>, JournalError> {
        let request_body = request_body.as_ref();
        let key = CassetteKey::from_request(method, url, request_body);
        if let Some(cassette) = self.replay(&key)? {
            return Ok(Some(cassette));
        }

        let legacy_key = CassetteKey::legacy_v1_from_request(method, url, request_body);
        if legacy_key == key {
            return Ok(None);
        }

        let Some(legacy_cassette) = self.replay(&legacy_key)? else {
            return Ok(None);
        };

        let migrated_cassette = ResponseCassette {
            key,
            ..legacy_cassette
        };
        self.record(&migrated_cassette)?;
        Ok(Some(migrated_cassette))
    }

    pub fn all(&self) -> Result<Vec<ResponseCassette>, JournalError> {
        read_cassettes_with_retention_policy(&self.path, &self.retention_policy)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "TEMPO_STEALTH_MODE is enabled; durable journals and cassettes are disabled to avoid plaintext local artifacts"
    )]
    StealthModeUnsupported,
    #[error("journal is already locked by another session: {path:?}")]
    Locked { path: PathBuf },
    #[error("journal sqlite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
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
    #[error("journal field {field} is out of range or malformed: {value}")]
    InvalidField { field: &'static str, value: String },
    #[error("durable encryption key must be {expected} bytes, got {actual}")]
    InvalidEncryptionKeyLength { expected: usize, actual: usize },
    #[error(
        "durable retention requires TEMPO_DURABLE_ENCRYPTION_KEY_HEX unless TEMPO_DURABLE_RETENTION=plaintext-unsafe is explicitly set"
    )]
    SecureRetentionPolicyRequired,
    #[error(
        "invalid TEMPO_DURABLE_RETENTION value {value:?}; expected encrypted or plaintext-unsafe"
    )]
    InvalidDurableRetentionPolicy { value: String },
    #[error("secure randomness failed while preparing encrypted durable state: {reason}")]
    Random { reason: String },
    #[error("encrypted durable record is malformed: {reason}")]
    EncryptedRecordMalformed { reason: String },
    #[error(
        "encrypted durable record version {found} is newer than supported version {supported}"
    )]
    EncryptedRecordVersion { found: u8, supported: u8 },
    #[error("encrypted durable record requires an encrypted retention policy")]
    EncryptedRecordRequiresKey,
    #[error("plaintext durable record rejected because encrypted retention policy was requested")]
    PlaintextRecordRejected,
    #[error("durable record encryption failed")]
    EncryptionFailed,
    #[error("durable record decryption failed")]
    DecryptionFailed,
    #[error("cassette key conflict for {key:?}")]
    CassetteConflict { key: CassetteKey },
    #[error("system clock is before unix epoch")]
    ClockBeforeEpoch,
    #[error(
        "journal schema version {found} is newer than supported version {supported}; upgrade tempo to open this journal"
    )]
    IncompatibleVersion { found: i64, supported: i64 },
    #[error(
        "journal file {path:?} is not a tempo SQLite journal (legacy JSONL or foreign format); it cannot be opened by this version"
    )]
    LegacyFormat { path: PathBuf },
    #[error("journal could not enter WAL mode; sqlite reported journal_mode={mode}")]
    WalModeUnavailable { mode: String },
}

/// Human-readable crate summary retained for callers that expose crate capabilities.
pub fn describe() -> &'static str {
    "session lifecycle, SQLite journal, portable cassettes, and deterministic replay primitives"
}

fn reject_durable_state_in_stealth_mode() -> Result<(), JournalError> {
    reject_durable_state_in_stealth_mode_value(std::env::var_os(TEMPO_STEALTH_MODE_ENV))
}

fn reject_durable_state_in_stealth_mode_value(value: Option<OsString>) -> Result<(), JournalError> {
    if stealth_mode_enabled_from_env_value(value) {
        return Err(JournalError::StealthModeUnsupported);
    }
    Ok(())
}

fn stealth_mode_enabled_from_env_value(value: Option<OsString>) -> bool {
    let Some(value) = value else {
        return false;
    };
    matches!(
        value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "stealth"
    )
}

/// Resolve the production durable retention policy from environment.
///
/// By default production callers fail closed unless `TEMPO_DURABLE_ENCRYPTION_KEY_HEX`
/// contains a 32-byte hex key. Plaintext durable artifacts remain available only via
/// `TEMPO_DURABLE_RETENTION=plaintext-unsafe` or explicit low-level compatibility APIs.
pub fn durable_retention_policy_from_env() -> Result<DurableRetentionPolicy, JournalError> {
    durable_retention_policy_from_env_values(
        std::env::var_os(TEMPO_DURABLE_RETENTION_ENV),
        std::env::var_os(TEMPO_DURABLE_ENCRYPTION_KEY_HEX_ENV),
    )
}

fn durable_retention_policy_from_env_values(
    retention_value: Option<OsString>,
    key_hex_value: Option<OsString>,
) -> Result<DurableRetentionPolicy, JournalError> {
    let retention = retention_value
        .as_ref()
        .map(|value| value.to_string_lossy().trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    match retention.as_deref() {
        Some("plaintext-unsafe") => Ok(DurableRetentionPolicy::PlaintextUnsafe),
        Some("encrypted" | "encrypt") | None => {
            let Some(key_hex) = key_hex_value
                .as_ref()
                .map(|value| value.to_string_lossy().trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                return Err(JournalError::SecureRetentionPolicyRequired);
            };
            Ok(DurableRetentionPolicy::encrypted(
                DurableEncryptionKey::from_hex(&key_hex)?,
            ))
        }
        Some(value) => Err(JournalError::InvalidDurableRetentionPolicy {
            value: value.to_string(),
        }),
    }
}

pub fn read_journal_entries(path: impl AsRef<Path>) -> Result<Vec<JournalEntry>, JournalError> {
    read_journal_entries_with_retention_policy(path, &DurableRetentionPolicy::PlaintextUnsafe)
}

pub fn read_journal_entries_with_retention_policy(
    path: impl AsRef<Path>,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<JournalEntry>, JournalError> {
    reject_durable_state_in_stealth_mode()?;
    let path = path.as_ref();
    // Preserve the "missing journal is not silently created" contract: surface a
    // NotFound IO error rather than fabricating an empty database.
    std::fs::metadata(path)?;
    // Read-only: never runs schema init or pragma writes, so a concurrent writer's
    // commit window cannot make this fail with SQLITE_BUSY.
    match open_readonly_connection(path)? {
        Some(conn) => read_journal_entries_from_connection(&conn, retention_policy),
        None => Ok(Vec::new()),
    }
}

pub fn read_cassettes(path: impl AsRef<Path>) -> Result<Vec<ResponseCassette>, JournalError> {
    read_cassettes_with_retention_policy(path, &DurableRetentionPolicy::PlaintextUnsafe)
}

pub fn read_cassettes_with_retention_policy(
    path: impl AsRef<Path>,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<ResponseCassette>, JournalError> {
    reject_durable_state_in_stealth_mode()?;
    read_cassette_jsonl(path, retention_policy)
}

/// Current on-disk journal schema version. Stamped into `PRAGMA user_version` on the
/// write path and checked on every open so a newer, unknown layout is rejected instead
/// of being silently read (and re-stamped) with the wrong assumptions.
const SUPPORTED_JOURNAL_VERSION: i64 = 1;

/// The 16-byte magic every SQLite database file begins with. Used to distinguish a
/// legacy/foreign journal (e.g. a pre-#193 JSONL file) from a real SQLite database
/// before handing the path to SQLite, so callers get an actionable error rather than a
/// raw `SQLITE_NOTADB`.
const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// How long a connection waits for a competing lock before returning `SQLITE_BUSY`.
///
/// In WAL mode readers never wait on the writer, so this no longer couples reader
/// latency to the writer's commit window. It still bounds the waits that remain: the
/// `journal_mode` conversions on writer open and clean close, which need a moment of
/// exclusive access and may have to wait out a long-lived read snapshot.
const JOURNAL_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

enum JournalOpenMode {
    ReadWriteCreate,
    ReadOnly,
}

fn open_journal_connection(path: &Path, mode: JournalOpenMode) -> Result<Connection, JournalError> {
    if let JournalOpenMode::ReadWriteCreate = mode {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        create_private_file_if_missing(path)?;
    }

    // Reject a legacy/foreign file (e.g. a pre-#193 JSONL journal) up front so the
    // caller gets `LegacyFormat` instead of an opaque `SQLITE_NOTADB` deep inside a
    // pragma or query.
    ensure_not_legacy_format(path)?;

    let flags = match mode {
        JournalOpenMode::ReadWriteCreate => {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        }
        JournalOpenMode::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
    };
    let conn = Connection::open_with_flags(path, flags).map_err(|err| map_db_error(err, path))?;
    if let JournalOpenMode::ReadWriteCreate = &mode {
        ensure_private_path_permissions(path)?;
    }
    conn.busy_timeout(JOURNAL_BUSY_TIMEOUT)?;
    // The version gate must run before `configure_journal_connection`: the WAL
    // conversion there is a persistent, file-mutating pragma, and a journal rejected
    // as incompatible must be left byte-identical on disk (no mode flip, no orphaned
    // -wal/-shm sidecars) for the newer tempo that owns it.
    check_journal_version(&conn, path)?;
    configure_journal_connection(&conn, &mode)?;
    if let JournalOpenMode::ReadWriteCreate = mode {
        initialize_journal_schema(&conn)?;
        stamp_journal_version(&conn)?;
    }
    Ok(conn)
}

/// Open an existing journal read-only, without taking a writer lock, running schema
/// init, or writing any pragma. Returns `Ok(None)` when the journal does not exist yet
/// (or is a zero-byte placeholder), so a read/resume never creates the database.
fn open_readonly_connection(path: &Path) -> Result<Option<Connection>, JournalError> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() == 0 => return Ok(None),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    Ok(Some(open_journal_connection(
        path,
        JournalOpenMode::ReadOnly,
    )?))
}

fn create_private_file_if_missing(path: &Path) -> Result<(), JournalError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    apply_private_file_mode(&mut options);
    match options.open(path) {
        Ok(file) => ensure_private_file_permissions(&file),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Map a raw SQLite failure to an actionable [`JournalError::LegacyFormat`] when it
/// signals the file is not a database, otherwise pass it through.
fn map_db_error(err: rusqlite::Error, path: &Path) -> JournalError {
    if let rusqlite::Error::SqliteFailure(inner, _) = &err
        && inner.code == rusqlite::ErrorCode::NotADatabase
    {
        return JournalError::LegacyFormat {
            path: path.to_path_buf(),
        };
    }
    JournalError::Sqlite(err)
}

/// Return [`JournalError::LegacyFormat`] if an existing, non-empty file does not begin
/// with the SQLite header magic. A missing or zero-byte file is fine: the write path
/// will create a fresh database and the read path treats it as empty.
fn ensure_not_legacy_format(path: &Path) -> Result<(), JournalError> {
    use std::io::Read as _;

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let mut header = [0u8; SQLITE_HEADER_MAGIC.len()];
    let mut read = 0usize;
    while read < header.len() {
        match file.read(&mut header[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    if read == 0 {
        // Empty file: a valid target for a fresh database.
        return Ok(());
    }
    if read < header.len() || &header != SQLITE_HEADER_MAGIC {
        return Err(JournalError::LegacyFormat {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Read `PRAGMA user_version` and reject a journal written by a newer, unknown schema
/// rather than silently reading (and re-stamping) it with stale assumptions.
fn check_journal_version(conn: &Connection, path: &Path) -> Result<(), JournalError> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| map_db_error(err, path))?;
    if version > SUPPORTED_JOURNAL_VERSION {
        return Err(JournalError::IncompatibleVersion {
            found: version,
            supported: SUPPORTED_JOURNAL_VERSION,
        });
    }
    Ok(())
}

/// Stamp the current schema version. Only called on the write path, after the version
/// has been checked, so an incompatible database is never overwritten.
fn stamp_journal_version(conn: &Connection) -> Result<(), JournalError> {
    // `PRAGMA` does not accept bound parameters; the value is a compile-time constant.
    conn.execute_batch(&format!("PRAGMA user_version={SUPPORTED_JOURNAL_VERSION};"))?;
    Ok(())
}

/// Apply the write-path pragmas. Only called after [`check_journal_version`] has
/// accepted the file, because `journal_mode=WAL` is a persistent mutation and a
/// rejected journal must be left untouched.
fn configure_journal_connection(
    conn: &Connection,
    mode: &JournalOpenMode,
) -> Result<(), JournalError> {
    // A read-only connection cannot (and must not) write these pragmas; doing so would
    // require a write lock and defeat the lock-free read/resume contract. WAL is a
    // persistent database property, so read-only connections inherit it from the file.
    if let JournalOpenMode::ReadWriteCreate = mode {
        // WAL + synchronous=NORMAL (#232): one WAL append per commit, no fsync on the
        // step critical path, and readers that never block on the writer. Every
        // committed append survives a process crash. On power loss SQLite may drop a
        // suffix of the most recent commits, but it never corrupts the database and
        // never keeps a later commit while losing an earlier one, so the
        // contiguous-seq invariant that resume validates is preserved.
        //
        // `PRAGMA journal_mode=WAL` reports the resulting mode instead of erroring
        // when it cannot switch, so the returned row is verified. This same pragma
        // migrates a pre-#232 `DELETE`-mode journal in place on first writer open.
        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(JournalError::WalModeUnavailable { mode: journal_mode });
        }
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;",
        )?;
    }
    Ok(())
}

fn initialize_journal_schema(conn: &Connection) -> Result<(), JournalError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS journal_entries(
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
    Ok(())
}

fn lock_journal_writer(path: &Path) -> Result<File, JournalError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock_path = journal_lock_path(path);
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(false);
    apply_private_file_mode(&mut options);
    let file = options.open(&lock_path)?;
    ensure_private_file_permissions(&file)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(JournalError::Locked {
            path: path.to_path_buf(),
        }),
        Err(TryLockError::Error(source)) => Err(JournalError::Io(source)),
    }
}

fn journal_lock_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(".lock");
    PathBuf::from(raw)
}

#[cfg(unix)]
fn apply_private_file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn apply_private_file_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn ensure_private_file_permissions(file: &File) -> Result<(), JournalError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_file_permissions(_file: &File) -> Result<(), JournalError> {
    Ok(())
}

#[cfg(unix)]
fn ensure_private_path_permissions(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_path_permissions(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

fn insert_journal_entry(
    conn: &mut Connection,
    entry: &JournalEntry,
    retention_policy: &DurableRetentionPolicy,
) -> Result<(), JournalError> {
    let seq = i64::try_from(entry.seq).map_err(|_| JournalError::InvalidField {
        field: "seq",
        value: entry.seq.to_string(),
    })?;
    let event_json = serde_json::to_string(&entry.event)?;
    let timestamp_ms = entry.timestamp_ms.to_string();
    let aad = journal_event_aad(
        entry.schema_version.as_str(),
        entry.run_id.0.as_str(),
        entry.session_id.0.as_str(),
        seq.to_string().as_str(),
        timestamp_ms.as_str(),
    );
    let event_record = encode_durable_record_string(event_json.as_bytes(), retention_policy, &aad)?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO journal_entries(
             run_id, session_id, seq, schema_version, timestamp_ms, event_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            entry.run_id.0.as_str(),
            entry.session_id.0.as_str(),
            seq,
            entry.schema_version.as_str(),
            timestamp_ms,
            event_record,
        ],
    )?;
    tx.commit()?;
    Ok(())
}

fn read_journal_entries_from_connection(
    conn: &Connection,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<JournalEntry>, JournalError> {
    let mut stmt = conn.prepare(
        "SELECT schema_version, run_id, session_id, seq, timestamp_ms, event_json
         FROM journal_entries
         ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        entries.push(journal_entry_from_row(row, retention_policy)?);
    }
    Ok(entries)
}

fn journal_entry_from_row(
    row: &rusqlite::Row<'_>,
    retention_policy: &DurableRetentionPolicy,
) -> Result<JournalEntry, JournalError> {
    let schema_version: String = row.get(0)?;
    let run_id: String = row.get(1)?;
    let session_id: String = row.get(2)?;
    let seq: i64 = row.get(3)?;
    let timestamp_ms: String = row.get(4)?;
    let event_json: String = row.get(5)?;

    let seq = u64::try_from(seq).map_err(|_| JournalError::InvalidField {
        field: "seq",
        value: seq.to_string(),
    })?;
    let timestamp_ms = timestamp_ms
        .parse::<u128>()
        .map_err(|_| JournalError::InvalidField {
            field: "timestamp_ms",
            value: timestamp_ms.clone(),
        })?;
    let aad = journal_event_aad(
        schema_version.as_str(),
        run_id.as_str(),
        session_id.as_str(),
        seq.to_string().as_str(),
        timestamp_ms.to_string().as_str(),
    );
    let event_json = decode_durable_record_string(event_json.as_bytes(), retention_policy, &aad)?;
    let event = serde_json::from_str::<JournalEvent>(&event_json)?;

    Ok(JournalEntry {
        schema_version,
        run_id: RunId(run_id),
        session_id: SessionId(session_id),
        seq,
        timestamp_ms,
        event,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRecordDocument {
    tempo_session_envelope: EncryptedRecordEnvelope,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRecordEnvelope {
    version: u8,
    algorithm: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

fn encode_durable_record_string(
    plaintext: &[u8],
    retention_policy: &DurableRetentionPolicy,
    aad: &[u8],
) -> Result<String, JournalError> {
    match retention_policy {
        DurableRetentionPolicy::PlaintextUnsafe => {
            String::from_utf8(plaintext.to_vec()).map_err(|err| JournalError::InvalidField {
                field: "durable_record",
                value: err.to_string(),
            })
        }
        DurableRetentionPolicy::Encrypted { key } => {
            let mut nonce = [0_u8; 24];
            getrandom::fill(&mut nonce).map_err(|error| JournalError::Random {
                reason: error.to_string(),
            })?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| JournalError::EncryptionFailed)?;
            let ciphertext = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| JournalError::EncryptionFailed)?;
            serde_json::to_string(&EncryptedRecordDocument {
                tempo_session_envelope: EncryptedRecordEnvelope {
                    version: ENCRYPTED_RECORD_VERSION,
                    algorithm: ENCRYPTED_RECORD_ALGORITHM.into(),
                    nonce_hex: hex_encode(&nonce),
                    ciphertext_hex: hex_encode(&ciphertext),
                },
            })
            .map_err(JournalError::Serde)
        }
    }
}

fn encode_durable_record_bytes(
    plaintext: &[u8],
    retention_policy: &DurableRetentionPolicy,
    aad: &[u8],
) -> Result<Vec<u8>, JournalError> {
    Ok(encode_durable_record_string(plaintext, retention_policy, aad)?.into_bytes())
}

fn decode_durable_record_string(
    record: &[u8],
    retention_policy: &DurableRetentionPolicy,
    aad: &[u8],
) -> Result<String, JournalError> {
    let bytes = decode_durable_record_bytes(record, retention_policy, aad)?;
    String::from_utf8(bytes).map_err(|err| JournalError::InvalidField {
        field: "durable_record",
        value: err.to_string(),
    })
}

fn decode_durable_record_bytes(
    record: &[u8],
    retention_policy: &DurableRetentionPolicy,
    aad: &[u8],
) -> Result<Vec<u8>, JournalError> {
    let record_text = std::str::from_utf8(record).ok();
    let encrypted = match record_text {
        Some(text) => parse_encrypted_record_document(text)?,
        None => None,
    };

    match (retention_policy, encrypted) {
        (DurableRetentionPolicy::PlaintextUnsafe, Some(_)) => {
            Err(JournalError::EncryptedRecordRequiresKey)
        }
        (DurableRetentionPolicy::PlaintextUnsafe, None) => Ok(record.to_vec()),
        (DurableRetentionPolicy::Encrypted { key: _ }, None) => {
            Err(JournalError::PlaintextRecordRejected)
        }
        (DurableRetentionPolicy::Encrypted { key }, Some(document)) => {
            let envelope = document.tempo_session_envelope;
            if envelope.version > ENCRYPTED_RECORD_VERSION {
                return Err(JournalError::EncryptedRecordVersion {
                    found: envelope.version,
                    supported: ENCRYPTED_RECORD_VERSION,
                });
            }
            if envelope.version != ENCRYPTED_RECORD_VERSION {
                return Err(JournalError::EncryptedRecordMalformed {
                    reason: format!("unsupported envelope version {}", envelope.version),
                });
            }
            if envelope.algorithm != ENCRYPTED_RECORD_ALGORITHM {
                return Err(JournalError::EncryptedRecordMalformed {
                    reason: format!("unsupported algorithm {}", envelope.algorithm),
                });
            }
            let nonce = hex_decode_exact::<24>(&envelope.nonce_hex)?;
            let ciphertext = hex_decode(&envelope.ciphertext_hex)?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| JournalError::DecryptionFailed)?;
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext.as_slice(),
                        aad,
                    },
                )
                .map_err(|_| JournalError::DecryptionFailed)
        }
    }
}

fn parse_encrypted_record_document(
    record_text: &str,
) -> Result<Option<EncryptedRecordDocument>, JournalError> {
    // Plaintext records (the default policy) never contain the envelope key, so
    // skip the full `Value` parse on the common path. A substring hit still
    // falls through to the authoritative top-level `get` check below, so a page
    // value that merely embeds the literal is not misclassified.
    //
    // Envelope detection is canonical-encoding based: Tempo's own writer emits
    // the field name literally, and only that spelling is recognized. A
    // JSON-equivalent record that escapes characters inside the top-level key
    // is treated as plaintext; external durable-record producers, if ever
    // supported, must emit the canonical field name.
    if !record_text.contains("tempo_session_envelope") {
        return Ok(None);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(record_text) else {
        return Ok(None);
    };
    if value.get("tempo_session_envelope").is_none() {
        return Ok(None);
    }
    serde_json::from_value(value).map(Some).map_err(|source| {
        JournalError::EncryptedRecordMalformed {
            reason: source.to_string(),
        }
    })
}

fn journal_event_aad(
    schema_version: &str,
    run_id: &str,
    session_id: &str,
    seq: &str,
    timestamp_ms: &str,
) -> Vec<u8> {
    aad_fields(&[
        "tempo-session",
        "journal-event",
        "v1",
        schema_version,
        run_id,
        session_id,
        seq,
        timestamp_ms,
    ])
}

fn cassette_aad() -> &'static [u8] {
    b"tempo-session\0cassette\0v1"
}

fn aad_fields(fields: &[&str]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        let bytes = field.as_bytes();
        aad.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        aad.extend_from_slice(bytes);
    }
    aad
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn hex_decode_exact<const N: usize>(hex: &str) -> Result<[u8; N], JournalError> {
    let bytes = hex_decode(hex)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| JournalError::EncryptedRecordMalformed {
        reason: format!("expected {N} decoded bytes, got {}", bytes.len()),
    })
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, JournalError> {
    let raw = hex.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(JournalError::EncryptedRecordMalformed {
            reason: "hex string has odd length".into(),
        });
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, JournalError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(JournalError::EncryptedRecordMalformed {
            reason: format!("invalid hex byte 0x{byte:02x}"),
        }),
    }
}

fn read_cassette_jsonl(
    path: impl AsRef<Path>,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<ResponseCassette>, JournalError> {
    let bytes = std::fs::read(path.as_ref())?;
    let torn_tail_possible = bytes.last() != Some(&b'\n');
    let lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    let last_index = lines.len().saturating_sub(1);

    let mut records = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let decoded = match decode_durable_record_bytes(raw, retention_policy, cassette_aad()) {
            Ok(decoded) => decoded,
            Err(source) => {
                if torn_tail_possible && index == last_index && is_incomplete_json_record(raw) {
                    break;
                }
                return Err(source);
            }
        };
        match serde_json::from_slice::<ResponseCassette>(&decoded) {
            Ok(record) => records.push(record),
            Err(source) => {
                if torn_tail_possible && index == last_index && is_incomplete_json_record(raw) {
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

fn is_incomplete_json_record(raw: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(raw).is_err()
}

enum CassetteAppendBoundary {
    Ready,
    NeedsNewline,
}

/// Chunk size for the backwards scan that locates the last newline of a file
/// whose tail is unterminated. Bounds each read; the scan touches only the
/// unterminated segment, never the whole file.
const CASSETTE_TAIL_SCAN_CHUNK: u64 = 64 * 1024;

/// Repair a trailing incomplete JSON record before append without deleting a complete
/// record that still needs authentication/decode by the caller.
///
/// The healthy path (file empty or newline-terminated) costs one metadata call
/// plus a single-byte read. Only a torn tail — rare, post-crash — walks
/// backwards to the previous newline, and reads just that segment.
fn repair_cassette_tail_before_append(file: &File) -> Result<CassetteAppendBoundary, JournalError> {
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok(CassetteAppendBoundary::Ready);
    }
    // `&File` implements Read + Seek; reads leave the append-mode writes
    // unaffected (O_APPEND writes always go to EOF).
    let mut reader = file;
    let mut last = [0u8; 1];
    reader.seek(SeekFrom::End(-1))?;
    reader.read_exact(&mut last)?;
    if last == [b'\n'] {
        return Ok(CassetteAppendBoundary::Ready);
    }

    // Unterminated tail: scan backwards in bounded chunks for the last newline,
    // accumulating only the trailing segment.
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk_end = file_len;
    let keep = loop {
        let chunk_start = chunk_end.saturating_sub(CASSETTE_TAIL_SCAN_CHUNK);
        let mut chunk = vec![0u8; (chunk_end - chunk_start) as usize];
        reader.seek(SeekFrom::Start(chunk_start))?;
        reader.read_exact(&mut chunk)?;
        if let Some(idx) = chunk.iter().rposition(|byte| *byte == b'\n') {
            chunk.drain(..=idx);
            chunk.extend_from_slice(&tail);
            tail = chunk;
            break chunk_start + idx as u64 + 1;
        }
        chunk.extend_from_slice(&tail);
        tail = chunk;
        if chunk_start == 0 {
            break 0;
        }
        chunk_end = chunk_start;
    };
    if is_incomplete_json_record(&tail) {
        file.set_len(keep)?;
        file.sync_all()?;
        return Ok(CassetteAppendBoundary::Ready);
    }
    Ok(CassetteAppendBoundary::NeedsNewline)
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
                    omitted: 0,
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
    fn direct_read_of_missing_journal_is_not_silently_created() -> TestResult {
        let path = unique_path("missing-read")?;
        remove_if_exists(&path)?;

        let err = read_journal_entries(&path).err();

        assert!(
            matches!(err, Some(JournalError::Io(source)) if source.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!path.exists());
        assert!(!journal_lock_path(&path).exists());
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
    fn cassette_record_is_idempotent_for_identical_key_and_payload() -> TestResult {
        let path = unique_path("cassette-idempotent")?;
        remove_if_exists(&path)?;
        let cassette = ResponseCassette::new(
            "GET",
            "https://example.com/api",
            200,
            vec![("content-type".into(), "application/json".into())],
            br#"{"ok":true}"#.to_vec(),
        );

        let store = CassetteStore::open(&path)?;
        store.record(&cassette)?;
        store.record(&cassette)?;

        let cassettes = store.all()?;
        assert_eq!(cassettes, vec![cassette]);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_record_rejects_conflicting_duplicate_keys() -> TestResult {
        let path = unique_path("cassette-conflict")?;
        remove_if_exists(&path)?;
        let first = ResponseCassette::new(
            "GET",
            "https://example.com/api",
            200,
            vec![("content-type".into(), "application/json".into())],
            br#"{"ok":true}"#.to_vec(),
        );
        let mut conflicting = first.clone();
        conflicting.status = 500;
        conflicting.body = br#"{"ok":false}"#.to_vec();

        let store = CassetteStore::open(&path)?;
        store.record(&first)?;
        let result = store.record(&conflicting);

        assert!(matches!(
            result,
            Err(JournalError::CassetteConflict { key }) if key == first.key
        ));
        assert_eq!(store.all()?, vec![first]);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_replay_request_migrates_legacy_key() -> TestResult {
        let path = unique_path("cassette-legacy-key")?;
        remove_if_exists(&path)?;
        let method = "POST";
        let url = "https://example.com/api";
        let request_body = b"left\0right";
        let current_key = CassetteKey::from_request(method, url, request_body);
        let legacy_key = CassetteKey::legacy_v1_from_request(method, url, request_body);
        assert_ne!(current_key, legacy_key);

        let legacy = ResponseCassette {
            key: legacy_key,
            method: method.into(),
            url: url.into(),
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok":true}"#.to_vec(),
        };
        let expected = ResponseCassette {
            key: current_key.clone(),
            ..legacy.clone()
        };

        let store = CassetteStore::open(&path)?;
        store.record(&legacy)?;
        assert_eq!(store.replay(&current_key)?, None);

        assert_eq!(
            store.replay_request(method, url, request_body)?,
            Some(expected.clone())
        );
        assert_eq!(store.replay(&current_key)?, Some(expected.clone()));
        assert_eq!(store.all()?, vec![legacy, expected.clone()]);

        assert_eq!(
            store.replay_request(method, url, request_body)?,
            Some(expected)
        );
        assert_eq!(store.all()?.len(), 2);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_replay_request_prefers_current_key() -> TestResult {
        let path = unique_path("cassette-current-key")?;
        remove_if_exists(&path)?;
        let method = "GET";
        let url = "https://example.com/api";
        let request_body = b"";
        let current_key = CassetteKey::from_request(method, url, request_body);
        let legacy_key = CassetteKey::legacy_v1_from_request(method, url, request_body);

        let legacy = ResponseCassette {
            key: legacy_key,
            method: method.into(),
            url: url.into(),
            status: 200,
            headers: Vec::new(),
            body: b"legacy".to_vec(),
        };
        let current = ResponseCassette {
            key: current_key,
            method: method.into(),
            url: url.into(),
            status: 202,
            headers: Vec::new(),
            body: b"current".to_vec(),
        };

        let store = CassetteStore::open(&path)?;
        store.record(&legacy)?;
        store.record(&current)?;

        assert_eq!(
            store.replay_request(method, url, request_body)?,
            Some(current.clone())
        );
        assert_eq!(store.all()?, vec![legacy, current]);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_record_repairs_torn_tail_before_append() -> TestResult {
        let path = unique_path("cassette-torn-tail")?;
        remove_if_exists(&path)?;
        let first = ResponseCassette::new(
            "GET",
            "https://example.com/api",
            200,
            Vec::new(),
            b"ok".to_vec(),
        );
        let second = ResponseCassette::new(
            "POST",
            "https://example.com/form",
            201,
            Vec::new(),
            b"created".to_vec(),
        );

        let store = CassetteStore::open(&path)?;
        store.record(&first)?;
        {
            let mut file = OpenOptions::new().append(true).open(&path)?;
            file.write_all(br#"{"key":{"#)?;
            file.flush()?;
        }

        assert_eq!(store.all()?, vec![first.clone()]);
        store.record(&second)?;
        assert_eq!(store.all()?, vec![first, second]);

        let bytes = fs::read(&path)?;
        assert_eq!(bytes.last(), Some(&b'\n'));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_index_replay_matches_all_across_tail_repair() -> TestResult {
        let path = unique_path("cassette-index-tail-repair")?;
        remove_if_exists(&path)?;
        let store = CassetteStore::open(&path)?;
        let first = test_cassette(1);
        let second = test_cassette(2);
        let complete_unterminated = test_cassette(3);
        let after_boundary_repair = test_cassette(4);
        let after_torn_tail = test_cassette(5);

        store.record(&first)?;
        assert_cassette_store_contents(&store, std::slice::from_ref(&first))?;

        store.record(&second)?;
        assert_cassette_store_contents(&store, &[first.clone(), second.clone()])?;

        append_cassette_without_newline(&path, &complete_unterminated)?;
        assert_cassette_store_contents(
            &store,
            &[first.clone(), second.clone(), complete_unterminated.clone()],
        )?;

        store.record(&after_boundary_repair)?;
        assert_cassette_store_contents(
            &store,
            &[
                first.clone(),
                second.clone(),
                complete_unterminated.clone(),
                after_boundary_repair.clone(),
            ],
        )?;

        append_raw_cassette_tail(&path, br#"{"key":{"#)?;
        assert_cassette_store_contents(
            &store,
            &[
                first.clone(),
                second.clone(),
                complete_unterminated.clone(),
                after_boundary_repair.clone(),
            ],
        )?;

        store.record(&after_torn_tail)?;
        assert_cassette_store_contents(
            &store,
            &[
                first,
                second,
                complete_unterminated,
                after_boundary_repair,
                after_torn_tail,
            ],
        )?;

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_index_catches_up_across_instances_and_rebuilds_after_shrink() -> TestResult {
        let path = unique_path("cassette-index-multi-instance")?;
        remove_if_exists(&path)?;
        let writer = CassetteStore::open(&path)?;
        let reader = CassetteStore::open(&path)?;
        let first = test_cassette(10);
        let second = test_cassette(11);
        let third = test_cassette(12);

        writer.record(&first)?;
        let first_len = fs::metadata(&path)?.len();
        assert_eq!(reader.replay(&first.key)?, Some(first.clone()));

        writer.record(&second)?;
        assert_eq!(reader.replay(&second.key)?, Some(second.clone()));
        assert_cassette_store_contents(&reader, &[first.clone(), second.clone()])?;

        {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(first_len)?;
            file.sync_all()?;
        }
        assert_eq!(reader.replay(&second.key)?, None);
        assert_cassette_store_contents(&reader, std::slice::from_ref(&first))?;

        writer.record(&third)?;
        assert_cassette_store_contents(&reader, &[first, third])?;

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn cassette_index_poison_resets_before_replay() -> TestResult {
        let path = unique_path("cassette-index-poison")?;
        remove_if_exists(&path)?;
        let store = CassetteStore::open(&path)?;
        let cassette = test_cassette(20);
        store.record(&cassette)?;

        let poison_result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut guard = match store.index.lock() {
                        Ok(guard) => guard,
                        Err(_) => panic!("index should not be poisoned before this test"),
                    };
                    guard.by_key.clear();
                    if let Ok(metadata) = fs::metadata(&path) {
                        guard.indexed_bytes = metadata.len();
                    }
                    panic!("poison cassette index with an inconsistent watermark");
                })
                .join()
        });
        assert!(poison_result.is_err());

        assert_eq!(store.replay(&cassette.key)?, Some(cassette.clone()));
        assert_cassette_store_contents(&store, std::slice::from_ref(&cassette))?;

        remove_if_exists(&path)?;
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

        let serialized = fs::read(&path)?;
        let path_text = path.to_string_lossy();
        assert!(!contains_bytes(&serialized, path_text.as_ref().as_bytes()));
        assert!(!contains_bytes(&serialized, b"target/debug"));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn journal_file_is_real_sqlite_database_with_committed_rows() -> TestResult {
        let path = unique_path("sqlite")?;
        remove_if_exists(&path)?;
        let mut journal = SessionJournal::open(
            &path,
            RunId("sqlite-run".into()),
            SessionId("sqlite-session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://sqlite.test".into(),
        })?;
        journal.append(JournalEvent::SessionClosed)?;
        drop(journal);

        let conn = Connection::open(&path)?;
        let row_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM journal_entries", [], |row| row.get(0))?;
        let closed: String = conn.query_row(
            "SELECT event_json FROM journal_entries WHERE seq = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(row_count, 2);
        assert_eq!(closed, r#"{"kind":"session_closed"}"#);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn corrupt_sqlite_event_payload_is_reported_on_read() -> TestResult {
        let path = unique_path("corrupt-sqlite")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-corrupt".into());
        let session_id = SessionId("session-corrupt".into());

        {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
        }

        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE journal_entries SET event_json = '{' WHERE seq = 0",
            [],
        )?;
        let err = read_journal_entries(&path).err();
        assert!(matches!(err, Some(JournalError::Serde(_))));

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
    fn journal_writer_uses_wal_mode_with_normal_synchronous() -> TestResult {
        // #232: the dedicated writer connection must run WAL + synchronous=NORMAL
        // instead of the previous DELETE + FULL configuration.
        let path = unique_path("wal-pragmas")?;
        remove_if_exists(&path)?;
        let journal = SessionJournal::open(
            &path,
            RunId("run-wal".into()),
            SessionId("session-wal".into()),
        )?;

        let journal_mode: String = journal
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let synchronous: i64 = journal
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        // 1 == NORMAL in SQLite's synchronous pragma encoding.
        assert_eq!(synchronous, 1);

        drop(journal);
        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn readers_are_not_blocked_by_an_open_writer_transaction() -> TestResult {
        // #232: WAL removes reader/writer contention. Under the previous
        // rollback-journal DELETE mode, an open EXCLUSIVE write transaction makes
        // readers wait out the 5s busy timeout and then fail with SQLITE_BUSY; in WAL
        // the read-only resume/read paths must return the committed snapshot at once.
        let path = unique_path("wal-concurrent")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-wal-concurrent".into());
        let session_id = SessionId("session-wal-concurrent".into());

        let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;

        // Hold the write lock with an uncommitted row, as an in-flight append would.
        journal.conn.execute_batch("BEGIN EXCLUSIVE")?;
        journal.conn.execute(
            "INSERT INTO journal_entries(
                 run_id, session_id, seq, schema_version, timestamp_ms, event_json
             ) VALUES (?1, ?2, 1, ?3, '1', '{\"kind\":\"session_closed\"}')",
            params![
                run_id.0.as_str(),
                session_id.0.as_str(),
                tempo_schema::SCHEMA_VERSION,
            ],
        )?;

        let started = std::time::Instant::now();
        let resumed = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
        let entries = read_journal_entries(&path)?;
        let elapsed = started.elapsed();

        // Snapshot isolation: readers see only the committed entry.
        assert_eq!(resumed.entries.len(), 1);
        assert_eq!(resumed.next_seq, 1);
        assert_eq!(entries.len(), 1);
        // And they must not have waited out the writer via the busy timeout.
        assert!(
            elapsed < JOURNAL_BUSY_TIMEOUT,
            "read-only snapshot stalled behind the writer for {elapsed:?}"
        );

        journal.conn.execute_batch("ROLLBACK")?;
        drop(journal);
        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn legacy_delete_mode_journal_migrates_to_wal_on_open() -> TestResult {
        // Journals created before #232 are rollback-journal DELETE-mode databases.
        // The first read-write open must migrate them to WAL in place and keep every
        // existing entry readable.
        let path = unique_path("legacy-delete-mode")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-delete-mode".into());
        let session_id = SessionId("session-delete-mode".into());

        {
            // Build the journal exactly as the pre-#232 writer did.
            let mut conn = Connection::open(&path)?;
            conn.execute_batch(
                "PRAGMA journal_mode=DELETE;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;",
            )?;
            initialize_journal_schema(&conn)?;
            stamp_journal_version(&conn)?;
            insert_journal_entry(
                &mut conn,
                &JournalEntry {
                    schema_version: tempo_schema::SCHEMA_VERSION.into(),
                    run_id: run_id.clone(),
                    session_id: session_id.clone(),
                    seq: 0,
                    timestamp_ms: 1,
                    event: JournalEvent::SessionStarted {
                        url: "https://example.com".into(),
                    },
                },
                &DurableRetentionPolicy::PlaintextUnsafe,
            )?;
        }
        // SQLite stamps header bytes 18/19 (write/read format version) with 1 for
        // rollback-journal databases and 2 for WAL databases.
        let header = fs::read(&path)?;
        assert_eq!(&header[18..20], &[1, 1]);

        let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        let journal_mode: String = journal
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(journal.next_seq(), 1);
        journal.append(JournalEvent::SessionClosed)?;
        drop(journal);

        // Clean close converts back to rollback mode, so the at-rest file stays
        // openable everywhere; the next writer open migrates to WAL again.
        let header = fs::read(&path)?;
        assert_eq!(&header[18..20], &[1, 1]);
        let resumed = SessionJournal::resume(&path, run_id, session_id)?;
        assert_eq!(resumed.entries.len(), 2);
        assert_eq!(resumed.next_seq, 2);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn clean_close_checkpoints_wal_so_journal_file_is_self_contained() -> TestResult {
        // #232 portability contract: journals move between hosts, so a cleanly closed
        // journal must be complete without its -wal/-shm sidecars.
        let path = unique_path("wal-checkpoint")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-checkpoint".into());
        let session_id = SessionId("session-checkpoint".into());
        let wal_path = sqlite_sidecar_path(&path, "-wal");
        let events = crash_matrix_events();

        {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            for event in events.iter().cloned() {
                journal.append(event)?;
            }
            // While the writer is live, recent commits reside in the WAL sidecar.
            assert!(fs::metadata(&wal_path)?.len() > 0);
        }

        // After a clean close the WAL has been checkpointed into the main file, the
        // -wal sidecar is gone (even on builds like macOS system SQLite that
        // otherwise persist it), and the header is stamped back to rollback mode.
        assert!(!wal_path.exists());
        let header = fs::read(&path)?;
        assert_eq!(&header[18..20], &[1, 1]);
        // Simulate copying only the journal file to another host: without any
        // sidecar (a stale -shm is ignored for a rollback-mode database), every
        // committed entry must be readable through the read-only path.
        remove_one_if_exists(&sqlite_sidecar_path(&path, "-shm"))?;
        let entries = read_journal_entries(&path)?;
        assert_eq!(entries.len(), events.len());

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

        // Known SHA-256 of the v2 versioned, length-prefixed request tuple.
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(b"tempo-session:cassette-key:v2\0");
            update_length_prefixed(&mut hasher, b"GET");
            update_length_prefixed(&mut hasher, b"https://example.com/api");
            update_length_prefixed(&mut hasher, b"payload");
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

        let nul_in_url = CassetteKey::from_request("GET", "x\0", b"y");
        let nul_in_body = CassetteKey::from_request("GET", "x", b"\0y");
        assert_ne!(nul_in_url, nul_in_body);

        let other_method = CassetteKey::from_request("POST", "https://example.com/api", b"payload");
        assert_ne!(a, other_method);
    }

    #[test]
    fn resume_reads_committed_snapshot_while_writer_holds_journal() -> TestResult {
        // #202: resume is a lock-free read-only snapshot. It must succeed while a
        // SessionJournal is open for writing, returning the committed entries without a
        // SQLITE_BUSY error.
        let path = unique_path("resume-concurrent")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-live".into());
        let session_id = SessionId("session-live".into());

        let mut writer = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
        writer.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        writer.append(JournalEvent::SessionClosed)?;

        // Writer is still alive and holding the journal; the read must not fail.
        let resumed = SessionJournal::resume(&path, run_id.clone(), session_id.clone())?;
        assert_eq!(resumed.entries.len(), 2);
        assert_eq!(resumed.next_seq, 2);

        let entries = read_journal_entries(&path)?;
        assert_eq!(entries.len(), 2);

        drop(writer);
        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn resume_of_missing_journal_is_empty_and_does_not_create_db() -> TestResult {
        // #202: a read/resume of a journal that does not exist yet returns an empty
        // snapshot and must not materialize a database on disk.
        let path = unique_path("resume-missing")?;
        remove_if_exists(&path)?;

        let resumed = SessionJournal::resume(
            &path,
            RunId("run-absent".into()),
            SessionId("session-absent".into()),
        )?;
        assert!(resumed.entries.is_empty());
        assert_eq!(resumed.next_seq, 0);
        assert!(!path.exists());
        assert!(!journal_lock_path(&path).exists());

        Ok(())
    }

    #[test]
    fn durable_session_state_fails_closed_when_stealth_mode_is_requested() -> TestResult {
        for value in ["1", "true", "yes", "on", "stealth", " TRUE "] {
            assert!(matches!(
                reject_durable_state_in_stealth_mode_value(Some(OsString::from(value))),
                Err(JournalError::StealthModeUnsupported)
            ));
        }

        for value in [
            None,
            Some(OsString::from("")),
            Some(OsString::from("0")),
            Some(OsString::from("false")),
        ] {
            assert!(reject_durable_state_in_stealth_mode_value(value).is_ok());
        }

        let journal_path = unique_path("stealth-journal-blocked")?;
        let cassette_path = unique_path("stealth-cassette-blocked")?;
        remove_if_exists(&journal_path)?;
        remove_if_exists(&cassette_path)?;
        assert!(matches!(
            SessionJournal::open_with_stealth_value(
                &journal_path,
                RunId("run-stealth".into()),
                SessionId("session-stealth".into()),
                Some(OsString::from("true")),
                DurableRetentionPolicy::PlaintextUnsafe,
            ),
            Err(JournalError::StealthModeUnsupported)
        ));
        assert!(!journal_path.exists());
        assert!(!journal_lock_path(&journal_path).exists());
        assert!(matches!(
            SessionJournal::resume_with_stealth_value(
                &journal_path,
                RunId("run-stealth".into()),
                SessionId("session-stealth".into()),
                Some(OsString::from("true")),
                DurableRetentionPolicy::PlaintextUnsafe,
            ),
            Err(JournalError::StealthModeUnsupported)
        ));
        assert!(!journal_path.exists());
        assert!(!journal_lock_path(&journal_path).exists());
        assert!(matches!(
            CassetteStore::open_with_stealth_value(
                &cassette_path,
                Some(OsString::from("stealth")),
                DurableRetentionPolicy::PlaintextUnsafe,
            ),
            Err(JournalError::StealthModeUnsupported)
        ));
        assert!(!cassette_path.exists());
        Ok(())
    }

    #[test]
    fn durable_retention_policy_env_requires_key_or_plaintext_opt_in() -> TestResult {
        assert!(matches!(
            durable_retention_policy_from_env_values(None, None),
            Err(JournalError::SecureRetentionPolicyRequired)
        ));
        assert!(matches!(
            durable_retention_policy_from_env_values(Some(OsString::from("encrypted")), None),
            Err(JournalError::SecureRetentionPolicyRequired)
        ));
        assert_eq!(
            durable_retention_policy_from_env_values(
                Some(OsString::from("plaintext-unsafe")),
                None,
            )?,
            DurableRetentionPolicy::PlaintextUnsafe
        );

        let key_hex = "2a".repeat(DURABLE_ENCRYPTION_KEY_BYTES);
        assert!(matches!(
            durable_retention_policy_from_env_values(None, Some(OsString::from(key_hex))),
            Ok(DurableRetentionPolicy::Encrypted { key })
                if key == DurableEncryptionKey::from_bytes([0x2a; DURABLE_ENCRYPTION_KEY_BYTES])
        ));
        assert!(matches!(
            durable_retention_policy_from_env_values(Some(OsString::from("forever")), None),
            Err(JournalError::InvalidDurableRetentionPolicy { value }) if value == "forever"
        ));
        for alias in ["plaintext", "plain"] {
            assert!(matches!(
                durable_retention_policy_from_env_values(Some(OsString::from(alias)), None),
                Err(JournalError::InvalidDurableRetentionPolicy { value }) if value == alias
            ));
        }
        Ok(())
    }

    #[test]
    fn encrypted_journal_hides_event_bytes_and_requires_key() -> TestResult {
        let path = unique_path("encrypted-journal")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-encrypted".into());
        let session_id = SessionId("session-encrypted".into());
        let policy = encrypted_test_policy(7);
        let wrong_policy = encrypted_test_policy(8);

        let mut journal = SessionJournal::open_with_retention_policy(
            &path,
            run_id.clone(),
            session_id.clone(),
            policy.clone(),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com/search?q=journal-secret".into(),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: Action::Type {
                node: NodeId("login-field".into()),
                text: "typed-secret".into(),
            },
        })?;
        drop(journal);

        let bytes = fs::read(&path)?;
        assert!(contains_bytes(&bytes, b"tempo_session_envelope"));
        assert!(!contains_bytes(&bytes, b"journal-secret"));
        assert!(!contains_bytes(&bytes, b"typed-secret"));

        let resumed = SessionJournal::resume_with_retention_policy(
            &path,
            run_id.clone(),
            session_id.clone(),
            policy,
        )?;
        assert_eq!(resumed.entries.len(), 2);
        assert!(matches!(
            read_journal_entries(&path),
            Err(JournalError::EncryptedRecordRequiresKey)
        ));
        assert!(matches!(
            SessionJournal::resume_with_retention_policy(&path, run_id, session_id, wrong_policy),
            Err(JournalError::DecryptionFailed)
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn encrypted_cassettes_hide_payload_bytes_and_require_key() -> TestResult {
        let path = unique_path("encrypted-cassette")?;
        remove_if_exists(&path)?;
        let policy = encrypted_test_policy(9);
        let wrong_policy = encrypted_test_policy(10);
        let cassette = ResponseCassette::for_request(
            "POST",
            "https://example.com/api?token=cassette-url-secret",
            b"request-body-secret",
            200,
            vec![("x-secret".into(), "header-secret".into())],
            b"response-body-secret".to_vec(),
        );

        let store = CassetteStore::open_with_retention_policy(&path, policy.clone())?;
        store.record(&cassette)?;

        let bytes = fs::read(&path)?;
        assert!(contains_bytes(&bytes, b"tempo_session_envelope"));
        assert!(!contains_bytes(&bytes, b"cassette-url-secret"));
        assert!(!contains_bytes(&bytes, b"request-body-secret"));
        assert!(!contains_bytes(&bytes, b"header-secret"));
        assert!(!contains_bytes(&bytes, b"response-body-secret"));
        assert_eq!(store.replay(&cassette.key)?, Some(cassette.clone()));
        assert!(matches!(
            read_cassettes(&path),
            Err(JournalError::EncryptedRecordRequiresKey)
        ));

        let wrong_store = CassetteStore::open_with_retention_policy(&path, wrong_policy)?;
        assert!(matches!(
            wrong_store.all(),
            Err(JournalError::DecryptionFailed)
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn encrypted_record_future_version_is_forward_detectable() -> TestResult {
        let future = serde_json::to_vec(&EncryptedRecordDocument {
            tempo_session_envelope: EncryptedRecordEnvelope {
                version: ENCRYPTED_RECORD_VERSION + 1,
                algorithm: ENCRYPTED_RECORD_ALGORITHM.into(),
                nonce_hex: hex_encode(&[0_u8; 24]),
                ciphertext_hex: hex_encode(b"not-a-real-ciphertext"),
            },
        })?;

        assert!(matches!(
            decode_durable_record_bytes(&future, &encrypted_test_policy(11), b"test-aad"),
            Err(JournalError::EncryptedRecordVersion {
                found,
                supported
            }) if found == ENCRYPTED_RECORD_VERSION + 1 && supported == ENCRYPTED_RECORD_VERSION
        ));
        Ok(())
    }

    #[test]
    fn malformed_non_ascii_hex_is_rejected_without_panicking() -> TestResult {
        assert!(matches!(
            DurableEncryptionKey::from_hex("éé"),
            Err(JournalError::EncryptedRecordMalformed { .. })
        ));

        let malformed = serde_json::to_vec(&EncryptedRecordDocument {
            tempo_session_envelope: EncryptedRecordEnvelope {
                version: ENCRYPTED_RECORD_VERSION,
                algorithm: ENCRYPTED_RECORD_ALGORITHM.into(),
                nonce_hex: "éé".into(),
                ciphertext_hex: hex_encode(b"not-a-real-ciphertext"),
            },
        })?;
        assert!(matches!(
            decode_durable_record_bytes(&malformed, &encrypted_test_policy(12), b"test-aad"),
            Err(JournalError::EncryptedRecordMalformed { .. })
        ));
        Ok(())
    }

    #[test]
    fn encrypted_retention_rejects_existing_plaintext_records() -> TestResult {
        let journal_path = unique_path("encrypted-rejects-plaintext-journal")?;
        let cassette_path = unique_path("encrypted-rejects-plaintext-cassette")?;
        remove_if_exists(&journal_path)?;
        remove_if_exists(&cassette_path)?;
        let run_id = RunId("run-plaintext".into());
        let session_id = SessionId("session-plaintext".into());

        {
            let mut journal =
                SessionJournal::open(&journal_path, run_id.clone(), session_id.clone())?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://plaintext.example".into(),
            })?;
        }
        assert!(matches!(
            SessionJournal::resume_with_retention_policy(
                &journal_path,
                run_id,
                session_id,
                encrypted_test_policy(13),
            ),
            Err(JournalError::PlaintextRecordRejected)
        ));

        let cassette = ResponseCassette::new(
            "GET",
            "https://plaintext.example/api",
            200,
            vec![("x-mode".into(), "plaintext".into())],
            b"plaintext-body".to_vec(),
        );
        let store = CassetteStore::open(&cassette_path)?;
        store.record(&cassette)?;
        let encrypted_store =
            CassetteStore::open_with_retention_policy(&cassette_path, encrypted_test_policy(14))?;
        assert!(matches!(
            encrypted_store.all(),
            Err(JournalError::PlaintextRecordRejected)
        ));

        remove_if_exists(&journal_path)?;
        remove_if_exists(&cassette_path)?;
        Ok(())
    }

    #[test]
    fn encrypted_journal_aad_separates_nul_containing_identities() -> TestResult {
        let path = unique_path("encrypted-aad-collision")?;
        remove_if_exists(&path)?;
        let policy = encrypted_test_policy(15);
        let source_run = RunId("a".into());
        let source_session = SessionId("b\0c".into());
        let target_run = RunId("a\0b".into());
        let target_session = SessionId("c".into());

        {
            let mut journal = SessionJournal::open_with_retention_policy(
                &path,
                source_run,
                source_session,
                policy.clone(),
            )?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://aad.example".into(),
            })?;
        }
        {
            let conn = Connection::open(&path)?;
            conn.execute(
                "UPDATE journal_entries SET run_id = ?1, session_id = ?2 WHERE seq = 0",
                rusqlite::params![target_run.0.as_str(), target_session.0.as_str()],
            )?;
        }

        assert!(matches!(
            SessionJournal::resume_with_retention_policy(&path, target_run, target_session, policy,),
            Err(JournalError::DecryptionFailed)
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn encrypted_cassette_complete_tampered_tail_fails_closed() -> TestResult {
        let path = unique_path("encrypted-complete-tail-tamper")?;
        remove_if_exists(&path)?;
        let policy = encrypted_test_policy(16);
        let store = CassetteStore::open_with_retention_policy(&path, policy.clone())?;
        store.record(&ResponseCassette::new(
            "GET",
            "https://tail.example/api",
            200,
            Vec::new(),
            b"tail-body".to_vec(),
        ))?;

        let mut bytes = fs::read(&path)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        let mut document: EncryptedRecordDocument = serde_json::from_slice(&bytes)?;
        let replacement = if document
            .tempo_session_envelope
            .ciphertext_hex
            .starts_with("00")
        {
            "ff"
        } else {
            "00"
        };
        document
            .tempo_session_envelope
            .ciphertext_hex
            .replace_range(0..2, replacement);
        std::fs::write(&path, serde_json::to_vec(&document)?)?;

        let store = CassetteStore::open_with_retention_policy(&path, policy)?;
        assert!(matches!(store.all(), Err(JournalError::DecryptionFailed)));
        let before_record = fs::read(&path)?;
        assert!(matches!(
            store.record(&ResponseCassette::new(
                "GET",
                "https://tail.example/next",
                200,
                Vec::new(),
                b"next-body".to_vec(),
            )),
            Err(JournalError::DecryptionFailed)
        ));
        assert_eq!(fs::read(&path)?, before_record);

        remove_if_exists(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn durable_session_files_are_owner_only_on_unix() -> TestResult {
        let journal_path = unique_path("private-journal")?;
        let cassette_path = unique_path("private-cassette")?;
        remove_if_exists(&journal_path)?;
        remove_if_exists(&cassette_path)?;

        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run-private".into()),
            SessionId("session-private".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        drop(journal);

        assert_eq!(file_mode(&journal_path)?, 0o600);
        assert_eq!(file_mode(&journal_lock_path(&journal_path))?, 0o600);

        let cassette = ResponseCassette::new(
            "GET",
            "https://example.com/api",
            200,
            Vec::new(),
            b"ok".to_vec(),
        );
        let store = CassetteStore::open(&cassette_path)?;
        store.record(&cassette)?;
        assert_eq!(file_mode(&cassette_path)?, 0o600);

        remove_if_exists(&journal_path)?;
        remove_if_exists(&cassette_path)?;
        Ok(())
    }

    #[test]
    fn encrypted_journal_hides_plaintext_and_requires_key() -> TestResult {
        let path = unique_path("encrypted-journal")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-encrypted".into());
        let session_id = SessionId("session-encrypted".into());
        let policy = DurableRetentionPolicy::encrypted(test_key(7));
        let secret_url = "https://secret.example/path?token=top-secret";

        {
            let mut journal = SessionJournal::open_with_retention_policy(
                &path,
                run_id.clone(),
                session_id.clone(),
                policy.clone(),
            )?;
            journal.append(JournalEvent::SessionStarted {
                url: secret_url.into(),
            })?;
        }

        let bytes = fs::read(&path)?;
        assert!(!contains_bytes(&bytes, b"top-secret"));
        assert!(!contains_bytes(&bytes, secret_url.as_bytes()));

        let resumed = SessionJournal::resume_with_retention_policy(
            &path,
            run_id.clone(),
            session_id.clone(),
            policy,
        )?;
        assert_eq!(resumed.entries.len(), 1);
        assert_eq!(
            resumed.entries[0].event,
            JournalEvent::SessionStarted {
                url: secret_url.into()
            }
        );
        assert!(matches!(
            SessionJournal::resume(&path, run_id.clone(), session_id.clone()),
            Err(JournalError::EncryptedRecordRequiresKey)
        ));
        assert!(matches!(
            SessionJournal::resume_with_retention_policy(
                &path,
                run_id,
                session_id,
                DurableRetentionPolicy::encrypted(test_key(8)),
            ),
            Err(JournalError::DecryptionFailed)
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn encrypted_cassettes_hide_plaintext_and_require_key() -> TestResult {
        let path = unique_path("encrypted-cassette")?;
        remove_if_exists(&path)?;
        let policy = DurableRetentionPolicy::encrypted(test_key(9));
        let cassette = ResponseCassette::new(
            "GET",
            "https://api.example/private?token=top-secret",
            200,
            vec![("set-cookie".into(), "session=top-secret".into())],
            b"top-secret body".to_vec(),
        );

        let store = CassetteStore::open_with_retention_policy(&path, policy.clone())?;
        store.record(&cassette)?;

        let bytes = fs::read(&path)?;
        assert!(!contains_bytes(&bytes, b"top-secret"));
        assert!(!contains_bytes(&bytes, b"set-cookie"));
        assert_eq!(store.replay(&cassette.key)?, Some(cassette));
        assert!(matches!(
            read_cassettes(&path),
            Err(JournalError::EncryptedRecordRequiresKey)
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn opening_newer_schema_version_is_rejected() -> TestResult {
        // #203: a journal stamped with a higher user_version must be rejected with a
        // distinct error instead of being silently downgraded/re-stamped.
        let path = unique_path("newer-version")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-ver".into());
        let session_id = SessionId("session-ver".into());

        {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
        }

        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(&format!(
                "PRAGMA user_version={};",
                SUPPORTED_JOURNAL_VERSION + 1
            ))?;
        }

        assert!(matches!(
            SessionJournal::resume(&path, run_id.clone(), session_id.clone()),
            Err(JournalError::IncompatibleVersion {
                found,
                supported,
            }) if found == SUPPORTED_JOURNAL_VERSION + 1 && supported == SUPPORTED_JOURNAL_VERSION
        ));
        assert!(matches!(
            read_journal_entries(&path),
            Err(JournalError::IncompatibleVersion { .. })
        ));
        assert!(matches!(
            SessionJournal::open(&path, run_id, session_id),
            Err(JournalError::IncompatibleVersion { .. })
        ));

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn rejected_incompatible_version_open_leaves_file_byte_identical() -> TestResult {
        // The IncompatibleVersion gate must run before the persistent WAL pragma:
        // a journal owned by a newer tempo is rejected, so this version must not
        // flip its journal mode, restamp its header, or leave -wal/-shm sidecars.
        let path = unique_path("newer-version-untouched")?;
        remove_if_exists(&path)?;
        let run_id = RunId("run-ver-untouched".into());
        let session_id = SessionId("session-ver-untouched".into());

        {
            let mut journal = SessionJournal::open(&path, run_id.clone(), session_id.clone())?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
        }
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(&format!(
                "PRAGMA user_version={};",
                SUPPORTED_JOURNAL_VERSION + 1
            ))?;
        }
        // Clear any stale sidecars left by builds that persist them past close, so
        // the assertions below observe only what the rejected open itself creates.
        remove_one_if_exists(&sqlite_sidecar_path(&path, "-wal"))?;
        remove_one_if_exists(&sqlite_sidecar_path(&path, "-shm"))?;
        let before = fs::read(&path)?;

        assert!(matches!(
            SessionJournal::open(&path, run_id, session_id),
            Err(JournalError::IncompatibleVersion { .. })
        ));

        assert!(
            fs::read(&path)? == before,
            "rejected incompatible-version open mutated the journal file"
        );
        assert!(!sqlite_sidecar_path(&path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&path, "-shm").exists());

        remove_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn opening_legacy_non_sqlite_file_reports_distinct_error() -> TestResult {
        // #203: a pre-#193 JSONL (or any non-SQLite) file must produce an actionable
        // LegacyFormat error rather than a raw opaque SQLITE_NOTADB.
        let path = unique_path("legacy-jsonl")?;
        remove_if_exists(&path)?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)?;
            file.write_all(
                b"{\"schema_version\":\"1\",\"run_id\":\"r\",\"session_id\":\"s\",\"seq\":0}\n",
            )?;
            file.flush()?;
        }

        let run_id = RunId("run-legacy".into());
        let session_id = SessionId("session-legacy".into());

        assert!(matches!(
            SessionJournal::resume(&path, run_id.clone(), session_id.clone()),
            Err(JournalError::LegacyFormat { path: p }) if p == path
        ));
        assert!(matches!(
            read_journal_entries(&path),
            Err(JournalError::LegacyFormat { .. })
        ));
        assert!(matches!(
            SessionJournal::open(&path, run_id, session_id),
            Err(JournalError::LegacyFormat { .. })
        ));

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
        remove_one_if_exists(path)?;
        remove_one_if_exists(&journal_lock_path(path))?;
        remove_one_if_exists(&sqlite_sidecar_path(path, "-wal"))?;
        remove_one_if_exists(&sqlite_sidecar_path(path, "-shm"))
    }

    fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
        let mut raw = path.as_os_str().to_os_string();
        raw.push(suffix);
        PathBuf::from(raw)
    }

    fn remove_one_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn encrypted_test_policy(seed: u8) -> DurableRetentionPolicy {
        DurableRetentionPolicy::encrypted(DurableEncryptionKey::from_bytes([seed; 32]))
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> Result<u32, std::io::Error> {
        use std::os::unix::fs::PermissionsExt;

        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn test_key(seed: u8) -> DurableEncryptionKey {
        DurableEncryptionKey::from_bytes([seed; DURABLE_ENCRYPTION_KEY_BYTES])
    }

    fn test_cassette(index: usize) -> ResponseCassette {
        ResponseCassette::new(
            if index.is_multiple_of(2) {
                "POST"
            } else {
                "GET"
            },
            format!("https://example.com/cassette/{index}"),
            200 + (index % 10) as u16,
            vec![("x-tempo-index".into(), index.to_string())],
            format!("body-{index}").into_bytes(),
        )
    }

    fn assert_cassette_store_contents(
        store: &CassetteStore,
        expected: &[ResponseCassette],
    ) -> TestResult {
        assert_eq!(store.all()?, expected);
        for cassette in expected {
            assert_eq!(store.replay(&cassette.key)?, Some(cassette.clone()));
        }
        assert_eq!(store.replay(&CassetteKey("missing".into()))?, None);
        Ok(())
    }

    fn append_cassette_without_newline(path: &Path, cassette: &ResponseCassette) -> TestResult {
        let cassette_json = serde_json::to_vec(cassette)?;
        let record = encode_durable_record_bytes(
            &cassette_json,
            &DurableRetentionPolicy::PlaintextUnsafe,
            cassette_aad(),
        )?;
        append_raw_cassette_tail(path, &record)
    }

    fn append_raw_cassette_tail(path: &Path, bytes: &[u8]) -> TestResult {
        let mut file = OpenOptions::new().append(true).open(path)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(())
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
                    omitted: 0,
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
                    omitted: 0,
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
        let mut conn = open_journal_connection(path, JournalOpenMode::ReadWriteCreate)?;
        insert_journal_entry(&mut conn, &entry, &DurableRetentionPolicy::PlaintextUnsafe)
    }
}
