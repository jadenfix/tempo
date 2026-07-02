//! tempo-engine-host — out-of-process engine supervision and UDS wire frames.
//!
//! `tempod` keeps browser engines out of its address space. This crate provides
//! the process supervisor, Unix-domain-socket request/response transport,
//! length-prefixed JSON frame codec, and session journal recovery hook used when
//! an engine child exits mid-task.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use tempo_driver::{DriverTrait, StepOutcome, TransportError, Unsupported};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use tempo_session::{JournalError, ResumeState, RunId, SessionId, SessionJournal};
use thiserror::Error;

pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;
pub const ENGINE_HOST_SOCKET_ENV: &str = "TEMPO_ENGINE_HOST_SOCKET";
pub const DRIVER_REQUEST_METHOD: &str = "driver.request";
pub const DRIVER_RESPONSE_METHOD: &str = "driver.response";

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
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
}

impl EngineHostConfig {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            restart: RestartPolicy::Never,
            session_journal: None,
            control_socket: None,
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

    pub fn control_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.control_socket = Some(path.into());
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

    /// Bind the configured UDS control socket before launching the child.
    ///
    /// The child receives `TEMPO_ENGINE_HOST_SOCKET=<path>`, then connects back to
    /// tempod using the `EngineIpcClient` / `EngineIpcConnection` frame protocol.
    pub fn spawn_with_ipc(
        config: EngineHostConfig,
    ) -> Result<(Self, EngineIpcServer), EngineHostError> {
        let socket_path = config
            .control_socket
            .clone()
            .ok_or(EngineHostError::MissingControlSocketPath)?;
        let server = EngineIpcServer::bind(socket_path)?;
        let host = Self::spawn(config)?;
        Ok((host, server))
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

/// Driver command payload carried inside a `driver.request` frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DriverCommand {
    Goto {
        url: String,
    },
    Observe,
    ObserveDiff {
        since_seq: u64,
    },
    Act {
        action: Action,
    },
    ActBatch {
        batch: ActionBatch,
    },
    Fork,
    Extract {
        node: NodeId,
    },
    EvaluateScript {
        expression: String,
        await_promise: bool,
    },
    Screenshot,
    Close,
}

/// Server-side request with the frame id needed for the matching response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DriverRequest {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_id: Option<String>,
    pub command: DriverCommand,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DriverRequestPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    driver_id: Option<String>,
    #[serde(flatten)]
    command: DriverCommand,
}

/// Serializable step outcome mirroring `tempo_driver::StepOutcome`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireStepOutcome {
    Applied { diff: ObservationDiff },
    StepError { reason: String },
}

impl From<StepOutcome> for WireStepOutcome {
    fn from(outcome: StepOutcome) -> Self {
        match outcome {
            StepOutcome::Applied { diff } => Self::Applied { diff },
            StepOutcome::StepError { reason } => Self::StepError { reason },
        }
    }
}

impl From<WireStepOutcome> for StepOutcome {
    fn from(outcome: WireStepOutcome) -> Self {
        match outcome {
            WireStepOutcome::Applied { diff } => Self::Applied { diff },
            WireStepOutcome::StepError { reason } => Self::StepError { reason },
        }
    }
}

/// Wire-safe error returned by an engine process for driver-level failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DriverWireError {
    Transport { message: String },
    Unsupported { capability: String },
    Protocol { message: String },
}

impl DriverWireError {
    pub fn transport(error: &TransportError) -> Self {
        Self::Transport {
            message: error.to_string(),
        }
    }

    pub fn unsupported(error: &Unsupported) -> Self {
        Self::Unsupported {
            capability: error.to_string(),
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }
}

/// Driver response payload carried inside a `driver.response` frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DriverResponse {
    Observation { observation: CompiledObservation },
    Diff { diff: ObservationDiff },
    Step { outcome: WireStepOutcome },
    Forked { driver_id: String },
    Extracted { value: Value },
    Evaluated { value: Value },
    Screenshot { bytes: Vec<u8> },
    Closed,
    Error { error: DriverWireError },
}

/// Bound Unix-domain-socket listener for engine child connections.
pub struct EngineIpcServer {
    listener: UnixListener,
    path: PathBuf,
}

impl EngineIpcServer {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, EngineHostError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    pub fn accept(&self) -> Result<EngineIpcConnection, EngineHostError> {
        let (stream, _) = self.listener.accept()?;
        Ok(EngineIpcConnection { stream })
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EngineIpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Client used by an engine process to send driver requests over the host UDS.
pub struct EngineIpcClient {
    stream: UnixStream,
    next_id: u64,
}

impl EngineIpcClient {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, EngineHostError> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
            next_id: 1,
        })
    }

    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream, next_id: 1 }
    }

    pub fn request(&mut self, command: DriverCommand) -> Result<DriverResponse, EngineHostError> {
        self.request_for(None, command)
    }

    pub fn request_for(
        &mut self,
        driver_id: Option<&str>,
        command: DriverCommand,
    ) -> Result<DriverResponse, EngineHostError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(EngineHostError::RequestIdExhausted)?;
        let payload = serde_json::to_value(DriverRequestPayload {
            driver_id: driver_id.map(str::to_string),
            command,
        })?;
        write_frame(
            &mut self.stream,
            &WireFrame::new(id, DRIVER_REQUEST_METHOD, payload),
        )?;

        let response = read_expected_frame(&mut self.stream, DRIVER_RESPONSE_METHOD)?;
        if response.id != id {
            return Err(EngineHostError::ResponseIdMismatch {
                expected: id,
                actual: response.id,
            });
        }
        Ok(serde_json::from_value(response.payload)?)
    }

    pub fn into_inner(self) -> UnixStream {
        self.stream
    }
}

/// Accepted server-side engine connection.
pub struct EngineIpcConnection {
    stream: UnixStream,
}

impl EngineIpcConnection {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, EngineHostError> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
        })
    }

    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream }
    }

    pub fn read_driver_request(&mut self) -> Result<DriverRequest, EngineHostError> {
        let request = read_expected_frame(&mut self.stream, DRIVER_REQUEST_METHOD)?;
        let payload: DriverRequestPayload = serde_json::from_value(request.payload)?;
        Ok(DriverRequest {
            id: request.id,
            driver_id: payload.driver_id,
            command: payload.command,
        })
    }

    pub fn write_driver_response(
        &mut self,
        request_id: u64,
        response: DriverResponse,
    ) -> Result<(), EngineHostError> {
        let payload = serde_json::to_value(response)?;
        write_frame(
            &mut self.stream,
            &WireFrame::new(request_id, DRIVER_RESPONSE_METHOD, payload),
        )
    }

    pub fn into_inner(self) -> UnixStream {
        self.stream
    }
}

/// Execute driver requests from a connected UDS stream until the peer disconnects
/// or a `Close` command is handled.
pub async fn serve_driver_connection<D>(
    connection: &mut EngineIpcConnection,
    driver: &mut D,
) -> Result<(), EngineHostError>
where
    D: DriverTrait + ?Sized,
{
    let mut forks = BTreeMap::new();
    let mut next_fork_id = 1_u64;

    loop {
        let request = match connection.read_driver_request() {
            Ok(request) => request,
            Err(EngineHostError::Io(err)) if is_disconnect(&err) => return Ok(()),
            Err(err) => return Err(err),
        };
        let should_close_root =
            request.driver_id.is_none() && matches!(request.command, DriverCommand::Close);
        let response = execute_routed_driver_command(
            driver,
            &mut forks,
            &mut next_fork_id,
            request.driver_id.as_deref(),
            request.command,
        )
        .await;
        connection.write_driver_response(request.id, response)?;
        if should_close_root {
            return Ok(());
        }
    }
}

async fn execute_routed_driver_command<D>(
    root_driver: &mut D,
    forks: &mut BTreeMap<String, Box<dyn DriverTrait>>,
    next_fork_id: &mut u64,
    driver_id: Option<&str>,
    command: DriverCommand,
) -> DriverResponse
where
    D: DriverTrait + ?Sized,
{
    let Some(driver_id) = driver_id else {
        return execute_driver_command_with_forks(root_driver, forks, next_fork_id, command).await;
    };

    let Some(mut forked_driver) = forks.remove(driver_id) else {
        return DriverResponse::Error {
            error: DriverWireError::protocol(format!("unknown forked driver: {driver_id}")),
        };
    };
    let should_remove = matches!(command, DriverCommand::Close);
    let response =
        execute_driver_command_with_forks(forked_driver.as_mut(), forks, next_fork_id, command)
            .await;
    if !(should_remove && matches!(response, DriverResponse::Closed)) {
        forks.insert(driver_id.to_string(), forked_driver);
    }
    response
}

async fn execute_driver_command_with_forks<D>(
    driver: &mut D,
    forks: &mut BTreeMap<String, Box<dyn DriverTrait>>,
    next_fork_id: &mut u64,
    command: DriverCommand,
) -> DriverResponse
where
    D: DriverTrait + ?Sized,
{
    match command {
        DriverCommand::Fork => match driver.fork().await {
            Ok(forked_driver) => register_fork_driver(forks, next_fork_id, forked_driver),
            Err(error) => DriverResponse::Error {
                error: DriverWireError::unsupported(&error),
            },
        },
        command => execute_driver_command(driver, command).await,
    }
}

fn register_fork_driver(
    forks: &mut BTreeMap<String, Box<dyn DriverTrait>>,
    next_fork_id: &mut u64,
    forked_driver: Box<dyn DriverTrait>,
) -> DriverResponse {
    let fork_id = *next_fork_id;
    let Some(next_id) = next_fork_id.checked_add(1) else {
        return DriverResponse::Error {
            error: DriverWireError::protocol("fork driver id counter exhausted"),
        };
    };
    *next_fork_id = next_id;
    let driver_id = format!("fork-{fork_id}");
    forks.insert(driver_id.clone(), forked_driver);
    DriverResponse::Forked { driver_id }
}

/// Execute one typed driver command and convert driver failures into wire-safe responses.
pub async fn execute_driver_command<D>(driver: &mut D, command: DriverCommand) -> DriverResponse
where
    D: DriverTrait + ?Sized,
{
    match command {
        DriverCommand::Goto { url } => match driver.goto(&url).await {
            Ok(observation) => DriverResponse::Observation { observation },
            Err(error) => driver_error(error),
        },
        DriverCommand::Observe => match driver.observe().await {
            Ok(observation) => DriverResponse::Observation { observation },
            Err(error) => driver_error(error),
        },
        DriverCommand::ObserveDiff { since_seq } => match driver.observe_diff(since_seq).await {
            Ok(diff) => DriverResponse::Diff { diff },
            Err(error) => driver_error(error),
        },
        DriverCommand::Act { action } => match driver.act(&action).await {
            Ok(outcome) => DriverResponse::Step {
                outcome: outcome.into(),
            },
            Err(error) => driver_error(error),
        },
        DriverCommand::ActBatch { batch } => match driver.act_batch(&batch).await {
            Ok(outcome) => DriverResponse::Step {
                outcome: outcome.into(),
            },
            Err(error) => driver_error(error),
        },
        DriverCommand::Fork => DriverResponse::Error {
            error: DriverWireError::protocol("fork requires a persistent driver connection"),
        },
        DriverCommand::Extract { node } => match driver.extract(&node).await {
            Ok(value) => DriverResponse::Extracted { value },
            Err(error) => driver_error(error),
        },
        DriverCommand::EvaluateScript {
            expression,
            await_promise,
        } => match driver.evaluate_script(&expression, await_promise).await {
            Ok(value) => DriverResponse::Evaluated { value },
            Err(error) => driver_error(error),
        },
        DriverCommand::Screenshot => match driver.screenshot().await {
            Ok(bytes) => DriverResponse::Screenshot { bytes },
            Err(error) => driver_error(error),
        },
        DriverCommand::Close => match driver.close().await {
            Ok(()) => DriverResponse::Closed,
            Err(error) => driver_error(error),
        },
    }
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
    "out-of-process engine child supervision, UDS driver transport, wire frames, and session journal recovery"
}

fn spawn_child(config: &EngineHostConfig) -> Result<Child, EngineHostError> {
    let mut command = Command::new(&config.program);
    command
        .args(&config.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(socket_path) = &config.control_socket {
        command.env(ENGINE_HOST_SOCKET_ENV, socket_path);
    }
    Ok(command.spawn()?)
}

fn read_expected_frame(
    reader: &mut impl Read,
    expected_method: &'static str,
) -> Result<WireFrame, EngineHostError> {
    let frame = read_frame(reader)?;
    if frame.method != expected_method {
        return Err(EngineHostError::UnexpectedFrameMethod {
            expected: expected_method,
            actual: frame.method,
        });
    }
    Ok(frame)
}

fn driver_error(error: TransportError) -> DriverResponse {
    DriverResponse::Error {
        error: DriverWireError::transport(&error),
    }
}

fn is_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
    )
}

fn remove_stale_socket(path: &Path) -> Result<(), EngineHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => Err(EngineHostError::SocketPathOccupied {
                path: path.to_path_buf(),
            }),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                Ok(fs::remove_file(path)?)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(EngineHostError::Io(err)),
        },
        Ok(_) => Err(EngineHostError::SocketPathOccupied {
            path: path.to_path_buf(),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(EngineHostError::Io(err)),
    }
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
    #[error("engine host config has no UDS control socket path")]
    MissingControlSocketPath,
    #[error("engine host socket path is occupied by a non-socket file: {path:?}")]
    SocketPathOccupied { path: PathBuf },
    #[error("unexpected engine frame method: expected {expected}, got {actual}")]
    UnexpectedFrameMethod {
        expected: &'static str,
        actual: String,
    },
    #[error("engine response id mismatch: expected {expected}, got {actual}")]
    ResponseIdMismatch { expected: u64, actual: u64 },
    #[error("engine request id counter exhausted")]
    RequestIdExhausted,
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error;
    use std::fs;
    use std::io::{self, Cursor};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempo_driver::TestDriver;
    use tempo_session::JournalEvent;

    type TestResult = Result<(), Box<dyn Error>>;
    type ForkClientResponses = (
        String,
        DriverResponse,
        DriverResponse,
        DriverResponse,
        DriverResponse,
        DriverResponse,
        DriverResponse,
    );

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
    fn malformed_frame_corpus_is_rejected() {
        enum ExpectedFailure {
            Io,
            Json,
            TooLarge,
        }

        let cases = [
            ("empty stream", Vec::new(), ExpectedFailure::Io),
            ("short length prefix", vec![0, 0], ExpectedFailure::Io),
            (
                "declared body is truncated",
                framed_bytes(16, b"{\"id\":1"),
                ExpectedFailure::Io,
            ),
            (
                "non-object json body",
                framed_bytes(4, b"null"),
                ExpectedFailure::Json,
            ),
            (
                "object missing required frame fields",
                framed_bytes(2, b"{}"),
                ExpectedFailure::Json,
            ),
            (
                "invalid json body",
                framed_bytes(5, b"abcde"),
                ExpectedFailure::Json,
            ),
            (
                "length prefix exceeds cap",
                (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec(),
                ExpectedFailure::TooLarge,
            ),
        ];

        for (name, bytes, expected) in cases {
            let result = read_frame(&mut Cursor::new(bytes));
            match expected {
                ExpectedFailure::Io => assert!(
                    matches!(result, Err(EngineHostError::Io(_))),
                    "{name}: {result:?}"
                ),
                ExpectedFailure::Json => assert!(
                    matches!(result, Err(EngineHostError::Json(_))),
                    "{name}: {result:?}"
                ),
                ExpectedFailure::TooLarge => assert!(
                    matches!(result, Err(EngineHostError::FrameTooLarge { .. })),
                    "{name}: {result:?}"
                ),
            }
        }
    }

    #[test]
    fn unexpected_frame_method_is_rejected_before_payload_decode() -> TestResult {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &WireFrame::new(1, DRIVER_RESPONSE_METHOD, json!({})),
        )?;

        assert!(matches!(
            read_expected_frame(&mut Cursor::new(bytes), DRIVER_REQUEST_METHOD),
            Err(EngineHostError::UnexpectedFrameMethod { .. })
        ));
        Ok(())
    }

    #[test]
    fn driver_request_rejects_invalid_command_payload_over_uds() -> TestResult {
        let (mut client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        write_frame(
            &mut client_stream,
            &WireFrame::new(
                1,
                DRIVER_REQUEST_METHOD,
                json!({"kind": "definitely_not_a_driver_command"}),
            ),
        )?;

        assert!(matches!(
            connection.read_driver_request(),
            Err(EngineHostError::Json(_))
        ));
        Ok(())
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

    #[test]
    fn ipc_client_and_server_round_trip_driver_command_over_uds() -> TestResult {
        let root = unique_dir("uds")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let client_path = socket_path.clone();

        let handle = thread::spawn(move || -> Result<DriverResponse, EngineHostError> {
            let mut client = EngineIpcClient::connect(client_path)?;
            client.request(DriverCommand::ObserveDiff { since_seq: 41 })
        });

        let mut connection = server.accept()?;
        let request = connection.read_driver_request()?;
        assert_eq!(request.id, 1);
        assert_eq!(request.driver_id, None);
        assert_eq!(
            request.command,
            DriverCommand::ObserveDiff { since_seq: 41 }
        );

        let diff = ObservationDiff {
            since_seq: 41,
            seq: 42,
            added: vec![],
            removed: vec![],
            changed: vec![],
        };
        connection
            .write_driver_response(request.id, DriverResponse::Diff { diff: diff.clone() })?;

        let response = join_client(handle)?;
        assert_eq!(response, DriverResponse::Diff { diff });

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn serve_driver_connection_executes_driver_commands_over_socket_pair() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        let handle = thread::spawn(
            move || -> Result<(DriverResponse, DriverResponse, DriverResponse), EngineHostError> {
                let mut client = EngineIpcClient::from_stream(client_stream);
                let observed = client.request(DriverCommand::Goto {
                    url: "https://example.com".into(),
                })?;
                let evaluated = client.request(DriverCommand::EvaluateScript {
                    expression: "document.title".into(),
                    await_promise: true,
                })?;
                let closed = client.request(DriverCommand::Close)?;
                Ok((observed, evaluated, closed))
            },
        );
        let mut driver = TestDriver::new();

        futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))?;
        let (observed, evaluated, closed) = join_client_triple(handle)?;

        match observed {
            DriverResponse::Observation { observation } => {
                assert_eq!(observation.url, "https://example.com");
                assert_eq!(observation.seq, 1);
            }
            other => return Err(format!("unexpected driver response: {other:?}").into()),
        }
        assert_eq!(
            evaluated,
            DriverResponse::Evaluated {
                value: serde_json::json!({
                    "expression": "document.title",
                    "awaitPromise": true,
                }),
            }
        );
        assert_eq!(closed, DriverResponse::Closed);
        Ok(())
    }

    #[test]
    fn serve_driver_connection_routes_forked_driver_handles() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        let handle = thread::spawn(move || -> Result<ForkClientResponses, EngineHostError> {
            let mut client = EngineIpcClient::from_stream(client_stream);
            let root_goto = client.request(DriverCommand::Goto {
                url: "https://root.test".into(),
            })?;
            let forked = client.request(DriverCommand::Fork)?;
            let DriverResponse::Forked { driver_id } = forked else {
                return Err(EngineHostError::Io(io::Error::other(format!(
                    "unexpected fork response: {forked:?}"
                ))));
            };
            let fork_goto = client.request_for(
                Some(&driver_id),
                DriverCommand::Goto {
                    url: "https://fork.test".into(),
                },
            )?;
            let root_observe = client.request(DriverCommand::Observe)?;
            let fork_observe = client.request_for(Some(&driver_id), DriverCommand::Observe)?;
            let fork_close = client.request_for(Some(&driver_id), DriverCommand::Close)?;
            let root_close = client.request(DriverCommand::Close)?;
            Ok((
                driver_id,
                root_goto,
                fork_goto,
                root_observe,
                fork_observe,
                fork_close,
                root_close,
            ))
        });
        let mut driver = TestDriver::new();

        futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))?;
        let (driver_id, root_goto, fork_goto, root_observe, fork_observe, fork_close, root_close) =
            join_fork_client(handle)?;

        assert_eq!(driver_id, "fork-1");
        assert_observation_response(root_goto, "https://root.test", 1)?;
        assert_observation_response(fork_goto, "https://fork.test", 2)?;
        assert_observation_response(root_observe, "https://root.test", 1)?;
        assert_observation_response(fork_observe, "https://fork.test", 2)?;
        assert_eq!(fork_close, DriverResponse::Closed);
        assert_eq!(root_close, DriverResponse::Closed);
        Ok(())
    }

    #[test]
    fn spawn_with_ipc_binds_socket_and_passes_path_to_child() -> TestResult {
        let root = unique_dir("spawn-ipc")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let socket_path = root.join("engine.sock");
        let marker_path = root.join("socket-env.txt");
        let config = EngineHostConfig::new("sh")
            .arg("-c")
            .arg(format!(
                "printf '%s' \"${ENGINE_HOST_SOCKET_ENV}\" > \"$1\""
            ))
            .arg("tempo-engine-host-test")
            .arg(marker_path.to_string_lossy().to_string())
            .control_socket(socket_path.clone());

        let (mut host, server) = EngineHost::spawn_with_ipc(config)?;
        wait_for_exit(&mut host)?;

        assert_eq!(server.local_path(), socket_path.as_path());
        assert!(fs::symlink_metadata(&socket_path)?.file_type().is_socket());
        assert_eq!(
            fs::read_to_string(&marker_path)?,
            socket_path.display().to_string()
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn ipc_bind_rejects_non_socket_path() -> TestResult {
        let root = unique_dir("occupied")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let path = root.join("engine.sock");
        fs::write(&path, b"not a socket")?;

        let result = EngineIpcServer::bind(&path);
        assert!(matches!(
            result,
            Err(EngineHostError::SocketPathOccupied { .. })
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    fn join_client(
        handle: thread::JoinHandle<Result<DriverResponse, EngineHostError>>,
    ) -> Result<DriverResponse, Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("client thread panicked".into()),
        }
    }

    fn join_client_triple(
        handle: thread::JoinHandle<
            Result<(DriverResponse, DriverResponse, DriverResponse), EngineHostError>,
        >,
    ) -> Result<(DriverResponse, DriverResponse, DriverResponse), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("client thread panicked".into()),
        }
    }

    fn join_fork_client(
        handle: thread::JoinHandle<Result<ForkClientResponses, EngineHostError>>,
    ) -> Result<ForkClientResponses, Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("client thread panicked".into()),
        }
    }

    fn assert_observation_response(
        response: DriverResponse,
        expected_url: &str,
        expected_seq: u64,
    ) -> TestResult {
        match response {
            DriverResponse::Observation { observation } => {
                assert_eq!(observation.url, expected_url);
                assert_eq!(observation.seq, expected_seq);
                Ok(())
            }
            other => Err(format!("unexpected driver response: {other:?}").into()),
        }
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
        let mut path = PathBuf::from("/tmp");
        path.push(format!("teh-{label}-{}-{nanos:x}", std::process::id()));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn framed_bytes(len: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + body.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }
}
