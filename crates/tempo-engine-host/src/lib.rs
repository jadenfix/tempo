//! tempo-engine-host — out-of-process engine supervision and wire frames.
//!
//! `tempod` keeps browser engines out of its address space. This crate provides
//! the process supervisor, length-prefixed JSON frame codec, and session journal
//! recovery hook used when an engine child exits mid-task.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use tempo_session::{JournalError, ResumeState, RunId, SessionId, SessionJournal};
use thiserror::Error;

pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Restart behavior for an engine child.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RestartPolicy {
    Never,
    Always { max_restarts: u32 },
}

/// Command line and recovery paths for one hosted engine child.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHostConfig {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    pub restart: RestartPolicy,
    #[serde(default)]
    pub session_journal: Option<PathBuf>,
}

impl EngineHostConfig {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            restart: RestartPolicy::Never,
            session_journal: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    pub fn session_journal(mut self, path: impl Into<PathBuf>) -> Self {
        self.session_journal = Some(path.into());
        self
    }
}

/// Live supervised engine process.
pub struct EngineHost {
    config: EngineHostConfig,
    child: Child,
    restarts: u32,
}

impl EngineHost {
    pub fn spawn(config: EngineHostConfig) -> Result<Self, EngineHostError> {
        let child = spawn_child(&config)?;
        Ok(Self {
            config,
            child,
            restarts: 0,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn restart_count(&self) -> u32 {
        self.restarts
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, EngineHostError> {
        Ok(self.child.try_wait()?)
    }

    pub fn kill(&mut self) -> Result<(), EngineHostError> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _status = self.child.wait()?;
        Ok(())
    }

    pub fn restart_if_exited(&mut self) -> Result<bool, EngineHostError> {
        let Some(status) = self.child.try_wait()? else {
            return Ok(false);
        };

        match self.config.restart {
            RestartPolicy::Never => Err(EngineHostError::ProcessExited { status }),
            RestartPolicy::Always { max_restarts } => {
                if self.restarts >= max_restarts {
                    return Err(EngineHostError::RestartLimit {
                        max_restarts,
                        last_status: status,
                    });
                }
                self.child = spawn_child(&self.config)?;
                self.restarts = self.restarts.saturating_add(1);
                Ok(true)
            }
        }
    }

    pub fn resume_session(
        &self,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<ResumeState, EngineHostError> {
        let path = self
            .config
            .session_journal
            .as_ref()
            .ok_or(EngineHostError::MissingJournalPath)?;
        Ok(SessionJournal::resume(path, run_id, session_id)?)
    }
}

impl Drop for EngineHost {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// One length-prefixed JSON frame crossing the engine-host boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireFrame {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub payload: Value,
}

impl WireFrame {
    pub fn new(id: u64, method: impl Into<String>, payload: Value) -> Self {
        Self {
            id,
            method: method.into(),
            payload,
        }
    }
}

/// Serialize a frame as `[u32 big-endian byte length][JSON bytes]`.
pub fn write_frame(writer: &mut impl Write, frame: &WireFrame) -> Result<(), EngineHostError> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(EngineHostError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_FRAME_BYTES as usize,
        });
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON frame.
pub fn read_frame(reader: &mut impl Read) -> Result<WireFrame, EngineHostError> {
    let mut len = [0_u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES as usize {
        return Err(EngineHostError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES as usize,
        });
    }
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Recover a session directly from a journal path after an engine process exits.
pub fn resume_session_from_journal(
    journal_path: impl AsRef<Path>,
    run_id: RunId,
    session_id: SessionId,
) -> Result<ResumeState, EngineHostError> {
    Ok(SessionJournal::resume(journal_path, run_id, session_id)?)
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "out-of-process engine child supervision, wire frames, and session journal recovery"
}

fn spawn_child(config: &EngineHostConfig) -> Result<Child, EngineHostError> {
    Ok(Command::new(&config.program)
        .args(&config.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

#[derive(Debug, Error)]
pub enum EngineHostError {
    #[error("engine child I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("engine frame JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engine frame too large: {len} bytes > {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error("engine child exited: {status}")]
    ProcessExited { status: ExitStatus },
    #[error("engine child restart limit reached after {max_restarts} restarts: {last_status}")]
    RestartLimit {
        max_restarts: u32,
        last_status: ExitStatus,
    },
    #[error("engine host config has no session journal path")]
    MissingJournalPath,
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error;
    use std::fs;
    use std::io::Cursor;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempo_session::JournalEvent;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn frame_codec_round_trips_json_payload() -> TestResult {
        let frame = WireFrame::new(
            7,
            "driver.observe",
            json!({
                "context": "ctx-1",
                "sinceSeq": 4,
            }),
        );
        let mut bytes = Vec::new();

        write_frame(&mut bytes, &frame)?;
        let decoded = read_frame(&mut Cursor::new(bytes))?;

        assert_eq!(decoded, frame);
        Ok(())
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());

        assert!(matches!(
            read_frame(&mut Cursor::new(bytes)),
            Err(EngineHostError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn invalid_frame_json_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8_u32.to_be_bytes());
        bytes.extend_from_slice(b"not-json");

        assert!(matches!(
            read_frame(&mut Cursor::new(bytes)),
            Err(EngineHostError::Json(_))
        ));
    }

    #[test]
    fn child_process_starts_and_reports_pid() -> TestResult {
        let mut host = EngineHost::spawn(shell_config("sleep 2"))?;
        let pid = host.pid();

        assert!(pid > 0);
        assert!(host.try_wait()?.is_none());

        host.kill()?;
        Ok(())
    }

    #[test]
    fn child_process_restarts_after_forced_exit() -> TestResult {
        let mut host = EngineHost::spawn(
            shell_config("sleep 20").restart(RestartPolicy::Always { max_restarts: 1 }),
        )?;
        let first_pid = host.pid();

        host.kill()?;
        let restarted = host.restart_if_exited()?;
        let second_pid = host.pid();

        assert!(restarted);
        assert_ne!(first_pid, second_pid);
        assert_eq!(host.restart_count(), 1);

        host.kill()?;
        Ok(())
    }

    #[test]
    fn exited_child_without_restart_policy_returns_status() -> TestResult {
        let mut host = EngineHost::spawn(shell_config("exit 7"))?;
        wait_for_exit(&mut host)?;

        assert!(matches!(
            host.restart_if_exited(),
            Err(EngineHostError::ProcessExited { .. })
        ));
        Ok(())
    }

    #[test]
    fn session_resume_reads_real_journal_after_child_exit() -> TestResult {
        let root = unique_dir("journal")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let run_id = RunId("run".into());
        let session_id = SessionId("session".into());
        let mut journal = SessionJournal::open(&journal_path, run_id.clone(), session_id.clone())?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://host.test".into(),
        })?;
        journal.append(JournalEvent::SessionClosed)?;

        let host = EngineHost::spawn(shell_config("exit 0").session_journal(journal_path.clone()))?;
        let resumed = host.resume_session(run_id, session_id)?;

        assert_eq!(resumed.path, journal_path);
        assert_eq!(resumed.entries.len(), 2);
        assert_eq!(resumed.next_seq, 2);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    fn shell_config(script: &str) -> EngineHostConfig {
        EngineHostConfig::new("sh").arg("-c").arg(script)
    }

    fn wait_for_exit(host: &mut EngineHost) -> Result<(), EngineHostError> {
        for _ in 0..50 {
            if host.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        host.kill()
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-engine-host-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}
