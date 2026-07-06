//! tempo-engine-host — out-of-process engine supervision and UDS wire frames.
//!
//! `tempod` keeps browser engines out of its address space. This crate provides
//! the process supervisor, Unix-domain-socket request/response transport,
//! length-prefixed JSON frame codec, and session journal recovery hook used when
//! an engine child exits mid-task.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tempo_driver::{
    BrowsingContextCreateOptions, DriverTrait, StepOutcome, TaintedValue, TransportError,
    Unsupported,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff, Provenance};
use tempo_session::{
    durable_retention_policy_from_env, DurableRetentionPolicy, JournalError, ResumeState, RunId,
    SessionId, SessionJournal,
};
use thiserror::Error;

pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;
/// Aggregate cap on the raw byte length of a reassembled screenshot.
///
/// Every individual chunk frame is already bounded by [`MAX_FRAME_BYTES`] (1 MiB),
/// but the reassembled total is otherwise unbounded: a compromised or malicious
/// engine child (the untrusted component this crate isolates) could stream endless
/// `final_chunk: false` chunks to exhaust tempod's memory. 64 MiB is a small
/// multiple of [`MAX_FRAME_BYTES`] that comfortably fits any real full-page PNG
/// screenshot (which are typically well under a few MiB) while bounding abuse.
pub const MAX_SCREENSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Aggregate cap on the number of chunk frames in a single screenshot stream.
///
/// [`MAX_SCREENSHOT_BYTES`] already bounds the memory an attacker can force us to
/// accumulate; this secondary cap bounds the number of frames we will read for one
/// response so a child sending endless tiny `final_chunk: false` chunks cannot spin
/// us indefinitely. A legitimate [`MAX_SCREENSHOT_BYTES`]-sized screenshot needs at
/// most ~86 chunks at the effective per-chunk payload of ~765 KiB (see
/// [`max_screenshot_chunk_bytes`]); 512 leaves generous headroom.
pub const MAX_SCREENSHOT_CHUNKS: u64 = 512;
pub const ENGINE_HOST_SOCKET_ENV: &str = "TEMPO_ENGINE_HOST_SOCKET";
pub const ENGINE_HOST_TOKEN_ENV: &str = "TEMPO_ENGINE_HOST_TOKEN";
pub const DRIVER_AUTH_METHOD: &str = "driver.auth";
pub const DRIVER_REQUEST_METHOD: &str = "driver.request";
pub const DRIVER_RESPONSE_METHOD: &str = "driver.response";
const SCREENSHOT_FRAME_OVERHEAD_RESERVE: usize = 4096;

mod base64_bytes {
    use super::{Deserialize, Deserializer, Serializer, BASE64};
    use base64::Engine as _;
    use serde::de::Error as _;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        BASE64.decode(encoded).map_err(D::Error::custom)
    }
}

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
    control_token: Option<String>,
}

impl EngineHost {
    pub fn spawn(config: EngineHostConfig) -> Result<Self, EngineHostError> {
        let child = spawn_child(&config, None)?;
        Ok(Self {
            config,
            child,
            restarts: 0,
            control_token: None,
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
                self.child = spawn_child(&self.config, self.control_token.as_deref())?;
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
        let retention_policy = durable_retention_policy_from_env()?;
        self.resume_session_with_retention_policy(run_id, session_id, retention_policy)
    }

    pub fn resume_session_plaintext_unsafe(
        &self,
        run_id: RunId,
        session_id: SessionId,
    ) -> Result<ResumeState, EngineHostError> {
        self.resume_session_with_retention_policy(
            run_id,
            session_id,
            DurableRetentionPolicy::PlaintextUnsafe,
        )
    }

    pub fn resume_session_with_retention_policy(
        &self,
        run_id: RunId,
        session_id: SessionId,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<ResumeState, EngineHostError> {
        let path = self
            .config
            .session_journal
            .as_ref()
            .ok_or(EngineHostError::MissingJournalPath)?;
        Ok(SessionJournal::resume_with_retention_policy(
            path,
            run_id,
            session_id,
            retention_policy,
        )?)
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
        let token = server.auth_token().to_string();
        let child = spawn_child(&config, Some(&token))?;
        let host = Self {
            config,
            child,
            restarts: 0,
            control_token: Some(token),
        };
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
    write_frame_serializable(writer, frame, &mut Vec::with_capacity(256))
}

/// [`write_frame`] with a caller-owned scratch buffer: long-lived connections
/// reuse one allocation across frames instead of allocating per message.
pub fn write_frame_with(
    writer: &mut impl Write,
    frame: &WireFrame,
    scratch: &mut Vec<u8>,
) -> Result<(), EngineHostError> {
    write_frame_serializable(writer, frame, scratch)
}

/// Core frame writer: serialize after a 4-byte length placeholder and emit the
/// whole frame in a single `write_all`. One syscall per frame instead of two —
/// on a Unix socket the length prefix and payload land in one `write(2)`.
fn write_frame_serializable<T: Serialize>(
    writer: &mut impl Write,
    frame: &T,
    scratch: &mut Vec<u8>,
) -> Result<(), EngineHostError> {
    encode_frame_serializable(frame, scratch)?;
    write_encoded_frame(writer, scratch)
}

fn encode_frame_serializable<T: Serialize>(
    frame: &T,
    scratch: &mut Vec<u8>,
) -> Result<(), EngineHostError> {
    scratch.clear();
    scratch.extend_from_slice(&[0_u8; 4]);
    serde_json::to_writer(&mut *scratch, frame)?;
    let len = scratch.len() - 4;
    if len > MAX_FRAME_BYTES as usize {
        return Err(EngineHostError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES as usize,
        });
    }
    let prefix = (len as u32).to_be_bytes();
    scratch[..4].copy_from_slice(&prefix);
    Ok(())
}

fn write_encoded_frame(writer: &mut impl Write, frame: &[u8]) -> Result<(), EngineHostError> {
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

/// Borrowed frame used by request paths to serialize typed payloads directly,
/// skipping the intermediate `serde_json::Value` tree the owned [`WireFrame`]
/// forces. Field names and order match [`WireFrame`] exactly.
#[derive(Serialize)]
struct WireFrameRef<'a, T: Serialize> {
    id: u64,
    method: &'a str,
    payload: &'a T,
}

#[derive(Deserialize)]
struct WireFramePayload<T> {
    id: u64,
    payload: T,
}

#[derive(Deserialize)]
struct WireFrameEnvelope<'a> {
    id: u64,
    method: String,
    #[serde(borrow)]
    payload: &'a RawValue,
}

/// Read one length-prefixed JSON frame.
pub fn read_frame(reader: &mut impl Read) -> Result<WireFrame, EngineHostError> {
    read_frame_with(reader, &mut Vec::new())
}

/// [`read_frame`] with a caller-owned scratch buffer. The buffer's capacity is
/// bounded by [`MAX_FRAME_BYTES`], so a long-lived connection holds at most one
/// frame-sized allocation instead of allocating per message.
pub fn read_frame_with(
    reader: &mut impl Read,
    scratch: &mut Vec<u8>,
) -> Result<WireFrame, EngineHostError> {
    read_frame_payload_with(reader, scratch)
}

fn read_frame_payload_with<T: DeserializeOwned>(
    reader: &mut impl Read,
    scratch: &mut Vec<u8>,
) -> Result<T, EngineHostError> {
    read_frame_bytes_with(reader, scratch)?;
    Ok(serde_json::from_slice(scratch)?)
}

fn read_frame_bytes_with(
    reader: &mut impl Read,
    scratch: &mut Vec<u8>,
) -> Result<(), EngineHostError> {
    let mut len = [0_u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES as usize {
        return Err(EngineHostError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES as usize,
        });
    }
    scratch.clear();
    scratch.resize(len, 0);
    reader.read_exact(scratch)?;
    Ok(())
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
    CachedObservation {
        seq: u64,
    },
    Act {
        action: Action,
    },
    ActBatch {
        batch: ActionBatch,
    },
    Fork,
    CreateBrowsingContext {
        options: BrowsingContextCreateOptions,
    },
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
    Observation {
        observation: CompiledObservation,
    },
    Diff {
        diff: ObservationDiff,
    },
    CachedObservation {
        observation: Option<CompiledObservation>,
    },
    Step {
        outcome: WireStepOutcome,
    },
    Forked {
        driver_id: String,
    },
    BrowsingContextCreated {
        driver_id: String,
    },
    Extracted {
        value: Value,
        provenance: Provenance,
    },
    Evaluated {
        value: Value,
        provenance: Provenance,
    },
    Screenshot {
        #[serde(with = "base64_bytes")]
        bytes: Vec<u8>,
    },
    Closed,
    Error {
        error: DriverWireError,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScreenshotChunkPayload {
    ScreenshotChunk {
        chunk_index: u64,
        final_chunk: bool,
        #[serde(with = "base64_bytes")]
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AuthPayload {
    token: String,
}

/// Bound Unix-domain-socket listener for engine child connections.
pub struct EngineIpcServer {
    listener: UnixListener,
    path: PathBuf,
    auth_token: String,
}

impl EngineIpcServer {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, EngineHostError> {
        let path = path.as_ref().to_path_buf();
        ensure_private_socket_parent(&path)?;
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path)?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&path);
            return Err(EngineHostError::Io(error));
        }
        Ok(Self {
            listener,
            path,
            auth_token: generate_control_token()?,
        })
    }

    pub fn accept(&self) -> Result<EngineIpcConnection, EngineHostError> {
        let (mut stream, _) = self.listener.accept()?;
        authorize_peer(&stream)?;
        verify_control_token(&mut stream, &self.auth_token)?;
        Ok(EngineIpcConnection { stream })
    }

    /// Accept a peer that is authorized by uid alone, skipping the control-token
    /// handshake.
    ///
    /// The shipped `tempod` engine-attach client (`connect_engine_ipc` ->
    /// [`EngineIpcClient::from_stream`]) speaks the driver protocol without an
    /// auth frame, so an engine host that serves it (the `tempo-engined-cdp`
    /// binary) must not demand the token. Security rests on the same footing as
    /// [`accept`](Self::accept) minus the token: [`bind`](Self::bind) creates the
    /// socket `0600` inside a private-parent directory, and every peer's uid must
    /// match the owner's. Callers that do authenticate keep using `accept`.
    pub fn accept_unauthenticated(&self) -> Result<EngineIpcConnection, EngineHostError> {
        let (stream, _) = self.listener.accept()?;
        authorize_peer(&stream)?;
        Ok(EngineIpcConnection { stream })
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }
}

impl Drop for EngineIpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Client used by an engine process to send driver requests over the host UDS.
///
/// Owns reusable read/write scratch buffers (bounded by [`MAX_FRAME_BYTES`]),
/// so steady-state requests allocate nothing for framing.
pub struct EngineIpcClient {
    stream: UnixStream,
    next_id: u64,
    write_scratch: Vec<u8>,
    read_scratch: Vec<u8>,
}

impl EngineIpcClient {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, EngineHostError> {
        let token = std::env::var(ENGINE_HOST_TOKEN_ENV)
            .map_err(|_| EngineHostError::MissingControlToken)?;
        Self::connect_with_token(path, &token)
    }

    pub fn connect_with_token(
        path: impl AsRef<Path>,
        token: &str,
    ) -> Result<Self, EngineHostError> {
        let mut client = Self::from_stream(UnixStream::connect(path)?);
        client.authenticate(token)?;
        Ok(client)
    }

    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream,
            next_id: 1,
            write_scratch: Vec::new(),
            read_scratch: Vec::new(),
        }
    }

    pub fn authenticate(&mut self, token: &str) -> Result<(), EngineHostError> {
        write_frame_serializable(
            &mut self.stream,
            &WireFrameRef {
                id: 0,
                method: DRIVER_AUTH_METHOD,
                payload: &AuthPayload {
                    token: token.to_string(),
                },
            },
            &mut self.write_scratch,
        )
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
        // Serialize the typed payload straight into the frame buffer: the old
        // path built a serde_json::Value tree of the whole command first.
        let payload = DriverRequestPayload {
            driver_id: driver_id.map(str::to_string),
            command,
        };
        write_frame_serializable(
            &mut self.stream,
            &WireFrameRef {
                id,
                method: DRIVER_REQUEST_METHOD,
                payload: &payload,
            },
            &mut self.write_scratch,
        )?;

        let response = read_expected_frame_with(
            &mut self.stream,
            DRIVER_RESPONSE_METHOD,
            &mut self.read_scratch,
        )?;
        if response.id != id {
            return Err(EngineHostError::ResponseIdMismatch {
                expected: id,
                actual: response.id,
            });
        }
        read_driver_response_payload(&mut self.stream, id, response.payload)
    }

    pub fn into_inner(self) -> UnixStream {
        self.stream
    }
}

/// Thread-safe, multiplexing wrapper over one engine-host UDS connection.
///
/// [`EngineIpcClient`] serializes callers for a full round-trip: the request
/// frame is written and the response frame is read while the caller exclusively
/// owns the stream, so a slow response for one command blocks every other
/// command on the connection (issue #230). This client instead:
///
/// * writes request frames under a short-held writer lock (bounded by the
///   socket write timeout, never held across a response wait),
/// * parks each caller on its own channel keyed by the request's frame id, and
/// * runs one detached reader thread that matches response frames to waiting
///   callers by id, so responses may return out of order and many requests can
///   be in flight concurrently.
///
/// Every wait is bounded: callers pass an explicit `timeout` to
/// [`SharedEngineIpcClient::request_for`] and a request that outlives it fails
/// with [`EngineHostError::IpcTimeout`] while its late response, if any, is
/// discarded by the reader. A read failure (or peer disconnect) fails all
/// in-flight requests and marks the client dead so later requests fail fast
/// instead of queueing behind a wedged connection.
///
/// The engine host currently answers requests in order; this client does not
/// depend on that, so the host loop can start pipelining (responding by frame
/// id, out of order) without further daemon changes.
#[derive(Clone)]
pub struct SharedEngineIpcClient {
    inner: Arc<SharedIpcInner>,
}

#[derive(Debug, Error)]
pub enum EngineIpcRequestError {
    #[error("engine request failed before dispatch: {0}")]
    NotDispatched(#[source] EngineHostError),
    #[error("engine request failed after dispatch status became uncertain: {0}")]
    DispatchUncertain(#[source] EngineHostError),
}

impl EngineIpcRequestError {
    pub fn into_inner(self) -> EngineHostError {
        match self {
            Self::NotDispatched(error) | Self::DispatchUncertain(error) => error,
        }
    }
}

struct SharedIpcInner {
    writer: Mutex<SharedIpcWriter>,
    pending: Mutex<SharedIpcPending>,
}

impl Drop for SharedIpcInner {
    fn drop(&mut self) {
        // The detached reader thread holds its own clone of this socket and can
        // block in `read` indefinitely. Without an explicit shutdown the
        // underlying socket would stay open after the last client handle is
        // dropped, so the engine peer would never observe EOF and its serve
        // loop would never exit (and the reader thread would leak). Shutdown
        // wakes the reader (its read returns EOF) and closes the connection
        // for the peer; this runs only once no clones remain (the reader holds
        // a `Weak`).
        if let Ok(writer) = self.writer.get_mut() {
            let _ = writer.stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

struct SharedIpcWriter {
    stream: UnixStream,
    next_id: u64,
}

#[derive(Default)]
struct SharedIpcPending {
    waiters: BTreeMap<u64, mpsc::Sender<Result<DriverResponse, String>>>,
    /// Once set, the connection is unusable and every request fails fast with
    /// this reason instead of waiting on a dead stream.
    dead: Option<String>,
}

impl SharedEngineIpcClient {
    /// Wrap an authenticated [`EngineIpcClient`], preserving its frame-id
    /// counter. Convert before issuing concurrent requests; the wrapped client
    /// must have no response outstanding.
    pub fn from_client(client: EngineIpcClient) -> Result<Self, EngineHostError> {
        Self::new(client.stream, client.next_id)
    }

    /// Wrap a raw connected stream (no auth exchange is performed here).
    pub fn from_stream(stream: UnixStream) -> Result<Self, EngineHostError> {
        Self::new(stream, 1)
    }

    fn new(stream: UnixStream, next_id: u64) -> Result<Self, EngineHostError> {
        let reader = stream.try_clone()?;
        // Responses are awaited via per-request `recv_timeout` bounds, not a
        // socket read timeout: the dedicated reader must be able to sit idle
        // indefinitely without surfacing spurious timeouts (and without ever
        // desynchronizing mid-frame).
        reader.set_read_timeout(None)?;
        let inner = Arc::new(SharedIpcInner {
            writer: Mutex::new(SharedIpcWriter { stream, next_id }),
            pending: Mutex::new(SharedIpcPending::default()),
        });
        let weak = Arc::downgrade(&inner);
        std::thread::spawn(move || shared_ipc_reader_loop(reader, &weak));
        Ok(Self { inner })
    }

    /// Send one driver command and wait up to `timeout` for its response.
    /// Safe to call from many threads concurrently; responses are matched to
    /// callers by frame id, so a slow command does not delay an unrelated one.
    pub fn request_for(
        &self,
        driver_id: Option<&str>,
        command: DriverCommand,
        timeout: Duration,
    ) -> Result<DriverResponse, EngineHostError> {
        self.request_for_with_dispatch_status(driver_id, command, timeout)
            .map_err(EngineIpcRequestError::into_inner)
    }

    /// Send one driver command and preserve whether an error happened before
    /// the frame was fully dispatched to the engine. Callers with idempotency
    /// semantics can retry or clear provisional leases only for
    /// [`EngineIpcRequestError::NotDispatched`].
    pub fn request_for_with_dispatch_status(
        &self,
        driver_id: Option<&str>,
        command: DriverCommand,
        timeout: Duration,
    ) -> Result<DriverResponse, EngineIpcRequestError> {
        let id = {
            let mut writer = self.inner.writer.lock().map_err(|_| {
                EngineIpcRequestError::NotDispatched(EngineHostError::IpcClosed {
                    reason: "engine IPC writer lock poisoned".into(),
                })
            })?;
            let id = writer.next_id;
            writer.next_id = writer
                .next_id
                .checked_add(1)
                .ok_or(EngineHostError::RequestIdExhausted)
                .map_err(EngineIpcRequestError::NotDispatched)?;
            id
        };
        let payload = DriverRequestPayload {
            driver_id: driver_id.map(str::to_string),
            command,
        };
        let mut encoded = Vec::with_capacity(256);
        encode_frame_serializable(
            &WireFrameRef {
                id,
                method: DRIVER_REQUEST_METHOD,
                payload: &payload,
            },
            &mut encoded,
        )
        .map_err(EngineIpcRequestError::NotDispatched)?;
        let (tx, rx) = mpsc::channel();

        // Registration happens before the frame is written so the reader can
        // never see a response for an id that is not yet registered. No nested
        // writer/pending locks are held here, so the reader cannot deadlock
        // behind a sender while JSON encoding happens outside the writer lock.
        {
            {
                let mut pending = self.inner.pending.lock().map_err(|_| {
                    EngineIpcRequestError::NotDispatched(EngineHostError::IpcClosed {
                        reason: "engine IPC pending lock poisoned".into(),
                    })
                })?;
                if let Some(reason) = &pending.dead {
                    return Err(EngineIpcRequestError::NotDispatched(
                        EngineHostError::IpcClosed {
                            reason: reason.clone(),
                        },
                    ));
                }
                pending.waiters.insert(id, tx);
            }
            let mut writer = match self.inner.writer.lock() {
                Ok(writer) => writer,
                Err(_) => {
                    self.forget_waiter(id);
                    return Err(EngineIpcRequestError::NotDispatched(
                        EngineHostError::IpcClosed {
                            reason: "engine IPC writer lock poisoned".into(),
                        },
                    ));
                }
            };
            // The write is bounded by the stream's write timeout and never
            // overlaps a response wait. Serialization happened before taking
            // this lock, so concurrent callers do not queue behind JSON work.
            if let Err(error) = write_encoded_frame(&mut writer.stream, &encoded) {
                self.forget_waiter(id);
                return Err(EngineIpcRequestError::NotDispatched(error));
            }
        }

        match rx.recv_timeout(timeout) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(reason)) => Err(EngineIpcRequestError::DispatchUncertain(
                EngineHostError::IpcClosed { reason },
            )),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Deregister so the reader discards the late response instead
                // of delivering it to a caller that has already given up.
                self.forget_waiter(id);
                Err(EngineIpcRequestError::DispatchUncertain(
                    EngineHostError::IpcTimeout { timeout },
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(
                EngineIpcRequestError::DispatchUncertain(EngineHostError::IpcClosed {
                    reason: "engine IPC reader exited without a response".into(),
                }),
            ),
        }
    }

    fn forget_waiter(&self, id: u64) {
        if let Ok(mut pending) = self.inner.pending.lock() {
            pending.waiters.remove(&id);
        }
    }

    /// Whether the reader thread has observed a fatal disconnect and marked the
    /// connection dead. Once dead, every [`Self::request_for`] fails fast with
    /// [`EngineHostError::IpcClosed`] rather than blocking on a stream that will
    /// never answer, so a liveness monitor can use this to trigger reconnect +
    /// re-attach instead of leaving the engine terminally wedged (#398). A
    /// poisoned lock is reported as dead: the connection is unusable either way.
    pub fn is_dead(&self) -> bool {
        self.inner
            .pending
            .lock()
            .map(|pending| pending.dead.is_some())
            .unwrap_or(true)
    }
}

impl std::fmt::Debug for SharedEngineIpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SharedEngineIpcClient").finish()
    }
}

/// Reader half of [`SharedEngineIpcClient`]: matches response frames to waiting
/// requests by frame id. Holds only a `Weak` handle so a fully-dropped client
/// does not keep the connection state alive; the thread exits on read failure,
/// peer disconnect, or once every client handle is gone.
fn shared_ipc_reader_loop(mut stream: UnixStream, inner: &Weak<SharedIpcInner>) {
    let reason = loop {
        let frame = match read_expected_frame(&mut stream, DRIVER_RESPONSE_METHOD) {
            Ok(frame) => frame,
            Err(error) => break error.to_string(),
        };
        // Chunked screenshot continuations are written contiguously by the
        // host, so reassembling inline (blocking this reader until the final
        // chunk) mirrors the wire contract; a framing violation kills the
        // connection below, exactly as it did for the exclusive client.
        let response = if payload_kind(&frame.payload) == Some("screenshot_chunk") {
            match read_chunked_screenshot_response(&mut stream, frame.id, frame.payload) {
                Ok(response) => Ok(response),
                Err(error) => break error.to_string(),
            }
        } else {
            // A malformed payload only fails the one request it answers; the
            // frame boundary itself was still consistent.
            serde_json::from_value::<DriverResponse>(frame.payload)
                .map_err(|error| format!("engine frame JSON failed: {error}"))
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let Ok(mut pending) = inner.pending.lock() else {
            break "engine IPC pending lock poisoned".to_string();
        };
        // An unknown id is a response whose requester already timed out and
        // deregistered; discard it so the slot cannot be delivered stale.
        if let Some(waiter) = pending.waiters.remove(&frame.id) {
            let _ = waiter.send(response);
        }
    };

    let Some(inner) = inner.upgrade() else {
        return;
    };
    let Ok(mut pending) = inner.pending.lock() else {
        return;
    };
    pending.dead = Some(reason.clone());
    for (_, waiter) in std::mem::take(&mut pending.waiters) {
        let _ = waiter.send(Err(reason.clone()));
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
        let request = read_expected_frame_payload::<DriverRequestPayload>(
            &mut self.stream,
            DRIVER_REQUEST_METHOD,
        )?;
        Ok(DriverRequest {
            id: request.id,
            driver_id: request.payload.driver_id,
            command: request.payload.command,
        })
    }

    pub async fn read_driver_request_async(&mut self) -> Result<DriverRequest, EngineHostError> {
        let mut stream = self.stream.try_clone()?;
        run_blocking_ipc(move || {
            let request = read_expected_frame_payload::<DriverRequestPayload>(
                &mut stream,
                DRIVER_REQUEST_METHOD,
            )?;
            Ok(DriverRequest {
                id: request.id,
                driver_id: request.payload.driver_id,
                command: request.payload.command,
            })
        })
        .await
    }

    pub fn write_driver_response(
        &mut self,
        request_id: u64,
        response: DriverResponse,
    ) -> Result<(), EngineHostError> {
        if let DriverResponse::Screenshot { bytes } = response {
            return write_screenshot_response(&mut self.stream, request_id, bytes);
        }
        write_frame_serializable(
            &mut self.stream,
            &WireFrameRef {
                id: request_id,
                method: DRIVER_RESPONSE_METHOD,
                payload: &response,
            },
            &mut Vec::with_capacity(256),
        )
    }

    pub async fn write_driver_response_async(
        &mut self,
        request_id: u64,
        response: DriverResponse,
    ) -> Result<(), EngineHostError> {
        let mut stream = self.stream.try_clone()?;
        run_blocking_ipc(move || {
            if let DriverResponse::Screenshot { bytes } = response {
                return write_screenshot_response(&mut stream, request_id, bytes);
            }
            write_frame_serializable(
                &mut stream,
                &WireFrameRef {
                    id: request_id,
                    method: DRIVER_RESPONSE_METHOD,
                    payload: &response,
                },
                &mut Vec::with_capacity(256),
            )
        })
        .await
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
        let request = match connection.read_driver_request_async().await {
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
        connection
            .write_driver_response_async(request.id, response)
            .await?;
        if should_close_root {
            return Ok(());
        }
    }
}

async fn run_blocking_ipc<T, F>(call: F) -> Result<T, EngineHostError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, EngineHostError> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle
            .spawn_blocking(call)
            .await
            .map_err(|error| EngineHostError::BlockingTask(error.to_string()))?,
        Err(_) => call(),
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
        DriverCommand::CreateBrowsingContext { options } => {
            match driver.create_browsing_context(options).await {
                Ok(created_driver) => {
                    register_browsing_context_driver(forks, next_fork_id, created_driver)
                }
                Err(error) => DriverResponse::Error {
                    error: DriverWireError::unsupported(&error),
                },
            }
        }
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

fn register_browsing_context_driver(
    forks: &mut BTreeMap<String, Box<dyn DriverTrait>>,
    next_fork_id: &mut u64,
    created_driver: Box<dyn DriverTrait>,
) -> DriverResponse {
    let context_id = *next_fork_id;
    let Some(next_id) = next_fork_id.checked_add(1) else {
        return DriverResponse::Error {
            error: DriverWireError::protocol("context driver id counter exhausted"),
        };
    };
    *next_fork_id = next_id;
    let driver_id = format!("context-{context_id}");
    forks.insert(driver_id.clone(), created_driver);
    DriverResponse::BrowsingContextCreated { driver_id }
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
        DriverCommand::CachedObservation { seq } => DriverResponse::CachedObservation {
            observation: driver.cached_observation(seq),
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
        DriverCommand::CreateBrowsingContext { .. } => DriverResponse::Error {
            error: DriverWireError::protocol(
                "browsing context creation requires a persistent driver connection",
            ),
        },
        DriverCommand::Extract { node } => match driver.extract(&node).await {
            Ok(TaintedValue { value, provenance }) => {
                DriverResponse::Extracted { value, provenance }
            }
            Err(error) => driver_error(error),
        },
        DriverCommand::EvaluateScript {
            expression,
            await_promise,
        } => match driver.evaluate_script(&expression, await_promise).await {
            Ok(TaintedValue { value, provenance }) => {
                DriverResponse::Evaluated { value, provenance }
            }
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
    let retention_policy = durable_retention_policy_from_env()?;
    resume_session_from_journal_with_retention_policy(
        journal_path,
        run_id,
        session_id,
        retention_policy,
    )
}

pub fn resume_session_from_journal_plaintext_unsafe(
    journal_path: impl AsRef<Path>,
    run_id: RunId,
    session_id: SessionId,
) -> Result<ResumeState, EngineHostError> {
    resume_session_from_journal_with_retention_policy(
        journal_path,
        run_id,
        session_id,
        DurableRetentionPolicy::PlaintextUnsafe,
    )
}

pub fn resume_session_from_journal_with_retention_policy(
    journal_path: impl AsRef<Path>,
    run_id: RunId,
    session_id: SessionId,
    retention_policy: DurableRetentionPolicy,
) -> Result<ResumeState, EngineHostError> {
    Ok(SessionJournal::resume_with_retention_policy(
        journal_path,
        run_id,
        session_id,
        retention_policy,
    )?)
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "out-of-process engine child supervision, UDS driver transport, wire frames, and session journal recovery"
}

fn read_driver_response_payload(
    reader: &mut impl Read,
    request_id: u64,
    payload: Value,
) -> Result<DriverResponse, EngineHostError> {
    if payload_kind(&payload) == Some("screenshot_chunk") {
        return read_chunked_screenshot_response(reader, request_id, payload);
    }
    Ok(serde_json::from_value(payload)?)
}

fn read_chunked_screenshot_response(
    reader: &mut impl Read,
    request_id: u64,
    first_payload: Value,
) -> Result<DriverResponse, EngineHostError> {
    let mut expected_index = 0_u64;
    let mut payload = first_payload;
    let mut bytes = Vec::new();

    loop {
        if payload_kind(&payload) != Some("screenshot_chunk") {
            return Err(EngineHostError::InvalidScreenshotChunk {
                reason: "expected screenshot_chunk continuation".into(),
            });
        }
        let ScreenshotChunkPayload::ScreenshotChunk {
            chunk_index,
            final_chunk,
            bytes: chunk_bytes,
        } = serde_json::from_value(payload)?;
        if chunk_index != expected_index {
            return Err(EngineHostError::InvalidScreenshotChunk {
                reason: format!("expected chunk {expected_index}, got {chunk_index}"),
            });
        }
        if bytes.len().saturating_add(chunk_bytes.len()) > MAX_SCREENSHOT_BYTES {
            return Err(EngineHostError::InvalidScreenshotChunk {
                reason: format!(
                    "reassembled screenshot would exceed {MAX_SCREENSHOT_BYTES} byte cap"
                ),
            });
        }
        bytes.extend_from_slice(&chunk_bytes);
        if final_chunk {
            return Ok(DriverResponse::Screenshot { bytes });
        }

        expected_index = expected_index
            .checked_add(1)
            .ok_or(EngineHostError::ScreenshotChunkIndexExhausted)?;
        if expected_index >= MAX_SCREENSHOT_CHUNKS {
            return Err(EngineHostError::InvalidScreenshotChunk {
                reason: format!(
                    "screenshot chunk stream exceeds {MAX_SCREENSHOT_CHUNKS} chunk cap"
                ),
            });
        }
        let frame = read_expected_frame(reader, DRIVER_RESPONSE_METHOD)?;
        if frame.id != request_id {
            return Err(EngineHostError::ResponseIdMismatch {
                expected: request_id,
                actual: frame.id,
            });
        }
        payload = frame.payload;
    }
}

fn write_screenshot_response(
    writer: &mut impl Write,
    request_id: u64,
    bytes: Vec<u8>,
) -> Result<(), EngineHostError> {
    if bytes.len() <= max_screenshot_chunk_bytes() {
        let payload = screenshot_payload_value(&bytes);
        let frame = WireFrame::new(request_id, DRIVER_RESPONSE_METHOD, payload);
        match write_frame(writer, &frame) {
            Err(EngineHostError::FrameTooLarge { .. }) => {}
            result => return result,
        }
    }
    write_screenshot_chunks(writer, request_id, &bytes)
}

/// Borrowed twin of [`ScreenshotChunkPayload`]: identical JSON output without
/// copying each chunk out of the screenshot buffer first (the old `to_vec()`
/// doubled memory traffic for multi-megabyte screenshots).
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScreenshotChunkRef<'a> {
    ScreenshotChunk {
        chunk_index: u64,
        final_chunk: bool,
        #[serde(with = "base64_bytes")]
        bytes: &'a [u8],
    },
}

fn write_screenshot_chunks(
    writer: &mut impl Write,
    request_id: u64,
    bytes: &[u8],
) -> Result<(), EngineHostError> {
    let chunk_size = max_screenshot_chunk_bytes();
    let mut scratch = Vec::new();
    for (chunk_index, chunk) in bytes.chunks(chunk_size).enumerate() {
        let chunk_index = u64::try_from(chunk_index)
            .map_err(|_| EngineHostError::ScreenshotChunkIndexExhausted)?;
        let final_chunk = (chunk_index as usize + 1) * chunk_size >= bytes.len();
        write_frame_serializable(
            writer,
            &WireFrameRef {
                id: request_id,
                method: DRIVER_RESPONSE_METHOD,
                payload: &ScreenshotChunkRef::ScreenshotChunk {
                    chunk_index,
                    final_chunk,
                    bytes: chunk,
                },
            },
            &mut scratch,
        )?;
    }
    Ok(())
}

fn screenshot_payload_value(bytes: &[u8]) -> Value {
    serde_json::json!({
        "kind": "screenshot",
        "bytes": BASE64.encode(bytes),
    })
}

fn payload_kind(payload: &Value) -> Option<&str> {
    payload.get("kind").and_then(Value::as_str)
}

fn max_screenshot_chunk_bytes() -> usize {
    let base64_budget =
        (MAX_FRAME_BYTES as usize).saturating_sub(SCREENSHOT_FRAME_OVERHEAD_RESERVE);
    let chunk_bytes = (base64_budget / 4).saturating_mul(3);
    chunk_bytes.max(1)
}

fn spawn_child(
    config: &EngineHostConfig,
    control_token: Option<&str>,
) -> Result<Child, EngineHostError> {
    let mut command = Command::new(&config.program);
    command
        .args(&config.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(socket_path) = &config.control_socket {
        command.env(ENGINE_HOST_SOCKET_ENV, socket_path);
    }
    if let Some(control_token) = control_token {
        command.env(ENGINE_HOST_TOKEN_ENV, control_token);
    }
    Ok(command.spawn()?)
}

fn read_expected_frame(
    reader: &mut impl Read,
    expected_method: &'static str,
) -> Result<WireFrame, EngineHostError> {
    read_expected_frame_with(reader, expected_method, &mut Vec::new())
}

fn read_expected_frame_with(
    reader: &mut impl Read,
    expected_method: &'static str,
    scratch: &mut Vec<u8>,
) -> Result<WireFrame, EngineHostError> {
    let frame = read_frame_with(reader, scratch)?;
    if frame.method != expected_method {
        return Err(EngineHostError::UnexpectedFrameMethod {
            expected: expected_method,
            actual: frame.method,
        });
    }
    Ok(frame)
}

fn read_expected_frame_payload<T: DeserializeOwned>(
    reader: &mut impl Read,
    expected_method: &'static str,
) -> Result<WireFramePayload<T>, EngineHostError> {
    read_expected_frame_payload_with(reader, expected_method, &mut Vec::new())
}

fn read_expected_frame_payload_with<T: DeserializeOwned>(
    reader: &mut impl Read,
    expected_method: &'static str,
    scratch: &mut Vec<u8>,
) -> Result<WireFramePayload<T>, EngineHostError> {
    read_frame_bytes_with(reader, scratch)?;
    let frame: WireFrameEnvelope<'_> = serde_json::from_slice(scratch)?;
    if frame.method != expected_method {
        return Err(EngineHostError::UnexpectedFrameMethod {
            expected: expected_method,
            actual: frame.method,
        });
    }
    Ok(WireFramePayload {
        id: frame.id,
        payload: serde_json::from_str(frame.payload.get())?,
    })
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

fn ensure_private_socket_parent(path: &Path) -> Result<(), EngineHostError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };

    match fs::metadata(parent) {
        Ok(metadata) => validate_private_socket_directory(parent, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            let metadata = fs::metadata(parent)?;
            validate_private_socket_directory(parent, &metadata)
        }
        Err(err) => Err(EngineHostError::Io(err)),
    }
}

fn validate_private_socket_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), EngineHostError> {
    if !metadata.is_dir() {
        return Err(EngineHostError::SocketPathOccupied {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(EngineHostError::InsecureSocketDirectory {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

fn verify_control_token(
    reader: &mut impl Read,
    expected_token: &str,
) -> Result<(), EngineHostError> {
    let frame = read_expected_frame_payload::<AuthPayload>(reader, DRIVER_AUTH_METHOD)?;
    if !constant_time_eq(frame.payload.token.as_bytes(), expected_token.as_bytes()) {
        return Err(EngineHostError::ControlAuthFailed);
    }
    Ok(())
}

fn generate_control_token() -> Result<String, EngineHostError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| EngineHostError::ControlTokenGeneration(error.to_string()))?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

/// Verify the connecting peer's uid matches the server's own uid before serving
/// it. Linux uses `SO_PEERCRED`; macOS and BSD use `getpeereid`.
#[cfg(target_os = "linux")]
fn authorize_peer(stream: &UnixStream) -> Result<(), EngineHostError> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|errno| EngineHostError::PeerCredentials(errno.to_string()))?;
    authorize_peer_uid(creds.uid(), nix::unistd::geteuid().as_raw())
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn authorize_peer(stream: &UnixStream) -> Result<(), EngineHostError> {
    let (peer_uid, _peer_gid) = nix::unistd::getpeereid(stream)
        .map_err(|errno| EngineHostError::PeerCredentials(errno.to_string()))?;
    authorize_peer_uid(peer_uid.as_raw(), nix::unistd::geteuid().as_raw())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn authorize_peer(_stream: &UnixStream) -> Result<(), EngineHostError> {
    Err(EngineHostError::PeerCredentials(format!(
        "peer credential checks are unsupported on {}",
        std::env::consts::OS
    )))
}

/// Pure uid comparison extracted for testing: the peer is authorized only when
/// its uid matches the server's uid.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    test
))]
fn authorize_peer_uid(peer_uid: u32, server_uid: u32) -> Result<(), EngineHostError> {
    if peer_uid == server_uid {
        Ok(())
    } else {
        Err(EngineHostError::UnauthorizedPeer {
            peer_uid,
            server_uid,
        })
    }
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
    #[error("engine host socket directory is not private: {path:?} mode {mode:o}")]
    InsecureSocketDirectory { path: PathBuf, mode: u32 },
    #[error("engine host control token is missing")]
    MissingControlToken,
    #[error("engine host control token generation failed: {0}")]
    ControlTokenGeneration(String),
    #[error("engine host control authentication failed")]
    ControlAuthFailed,
    #[error("engine control socket peer uid {peer_uid} does not match owner uid {server_uid}")]
    UnauthorizedPeer { peer_uid: u32, server_uid: u32 },
    #[error("engine control socket peer credential check failed: {0}")]
    PeerCredentials(String),
    #[error("unexpected engine frame method: expected {expected}, got {actual}")]
    UnexpectedFrameMethod {
        expected: &'static str,
        actual: String,
    },
    #[error("engine response id mismatch: expected {expected}, got {actual}")]
    ResponseIdMismatch { expected: u64, actual: u64 },
    #[error("engine request id counter exhausted")]
    RequestIdExhausted,
    #[error("engine IPC request timed out after {timeout:?}")]
    IpcTimeout { timeout: Duration },
    #[error("engine IPC connection closed: {reason}")]
    IpcClosed { reason: String },
    #[error("engine screenshot chunk stream is invalid: {reason}")]
    InvalidScreenshotChunk { reason: String },
    #[error("engine screenshot chunk index counter exhausted")]
    ScreenshotChunkIndexExhausted,
    #[error("engine host blocking IPC task failed: {0}")]
    BlockingTask(String),
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
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tempo_driver::{BrowsingContextCreateOptions, BrowsingContextKind, TestDriver};
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
    type ContextClientResponses = (
        String,
        DriverResponse,
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
    fn driver_response_screenshot_uses_base64_payload() -> TestResult {
        let payload = serde_json::to_value(DriverResponse::Screenshot {
            bytes: vec![0, 1, 2, 255],
        })?;

        assert_eq!(
            payload,
            json!({
                "kind": "screenshot",
                "bytes": "AAEC/w==",
            })
        );
        let decoded: DriverResponse = serde_json::from_value(payload)?;
        assert_eq!(
            decoded,
            DriverResponse::Screenshot {
                bytes: vec![0, 1, 2, 255]
            }
        );
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

        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &WireFrame::new(1, DRIVER_RESPONSE_METHOD, json!({})),
        )?;
        assert!(matches!(
            read_expected_frame_payload::<DriverRequestPayload>(
                &mut Cursor::new(bytes),
                DRIVER_REQUEST_METHOD
            ),
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
    fn driver_request_wrong_method_is_rejected_before_payload_decode() -> TestResult {
        let (mut client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        write_frame(
            &mut client_stream,
            &WireFrame::new(1, DRIVER_RESPONSE_METHOD, json!({})),
        )?;

        assert!(matches!(
            connection.read_driver_request(),
            Err(EngineHostError::UnexpectedFrameMethod { .. })
        ));
        Ok(())
    }

    #[test]
    fn auth_wrong_method_is_rejected_before_payload_decode() -> TestResult {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &WireFrame::new(0, DRIVER_REQUEST_METHOD, json!({})),
        )?;

        assert!(matches!(
            verify_control_token(&mut Cursor::new(bytes), "server-token"),
            Err(EngineHostError::UnexpectedFrameMethod { .. })
        ));
        Ok(())
    }

    #[test]
    fn shared_client_matches_out_of_order_responses_by_frame_id() -> TestResult {
        // Two requests go out concurrently; the fake engine answers them in
        // REVERSE order. Each caller must receive its own response — proof the
        // shared client multiplexes by frame id instead of assuming in-order
        // replies (issue #230).
        let (client_stream, server_stream) = UnixStream::pair()?;
        let shared = SharedEngineIpcClient::from_stream(client_stream)?;

        let first_client = shared.clone();
        let first = thread::spawn(move || {
            first_client.request_for(
                Some("driver-a"),
                DriverCommand::Extract {
                    node: tempo_schema::NodeId("node-a".into()),
                },
                Duration::from_secs(5),
            )
        });
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        let request_a = connection.read_driver_request()?;
        assert_eq!(request_a.driver_id.as_deref(), Some("driver-a"));

        let second_client = shared.clone();
        let second = thread::spawn(move || {
            second_client.request_for(
                Some("driver-b"),
                DriverCommand::Extract {
                    node: tempo_schema::NodeId("node-b".into()),
                },
                Duration::from_secs(5),
            )
        });
        let request_b = connection.read_driver_request()?;
        assert_eq!(request_b.driver_id.as_deref(), Some("driver-b"));

        // Answer B first, then A.
        connection.write_driver_response(
            request_b.id,
            DriverResponse::Extracted {
                value: json!("value-b"),
                provenance: Provenance::Page,
            },
        )?;
        connection.write_driver_response(
            request_a.id,
            DriverResponse::Extracted {
                value: json!("value-a"),
                provenance: Provenance::Page,
            },
        )?;

        let response_a = first.join().map_err(|_| "first requester panicked")??;
        let response_b = second.join().map_err(|_| "second requester panicked")??;
        assert_eq!(
            response_a,
            DriverResponse::Extracted {
                value: json!("value-a"),
                provenance: Provenance::Page,
            }
        );
        assert_eq!(
            response_b,
            DriverResponse::Extracted {
                value: json!("value-b"),
                provenance: Provenance::Page,
            }
        );
        Ok(())
    }

    #[test]
    fn shared_client_bounds_a_wedged_request_and_discards_its_late_response() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let shared = SharedEngineIpcClient::from_stream(client_stream)?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);

        // The engine reads the request but never answers within the bound.
        let started = Instant::now();
        let timed_out = shared.request_for(
            None,
            DriverCommand::Extract {
                node: tempo_schema::NodeId("wedged".into()),
            },
            Duration::from_millis(100),
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(timed_out, Err(EngineHostError::IpcTimeout { .. })));
        let wedged_request = connection.read_driver_request()?;

        // The late response for the abandoned request must be discarded, NOT
        // delivered to the next caller, and the connection must stay usable.
        connection.write_driver_response(
            wedged_request.id,
            DriverResponse::Extracted {
                value: json!("late"),
                provenance: Provenance::Page,
            },
        )?;
        let follow_up_client = shared.clone();
        let follow_up = thread::spawn(move || {
            follow_up_client.request_for(
                None,
                DriverCommand::Extract {
                    node: tempo_schema::NodeId("fresh".into()),
                },
                Duration::from_secs(5),
            )
        });
        let fresh_request = connection.read_driver_request()?;
        connection.write_driver_response(
            fresh_request.id,
            DriverResponse::Extracted {
                value: json!("fresh"),
                provenance: Provenance::Page,
            },
        )?;
        let response = follow_up
            .join()
            .map_err(|_| "follow-up requester panicked")??;
        assert_eq!(
            response,
            DriverResponse::Extracted {
                value: json!("fresh"),
                provenance: Provenance::Page,
            }
        );
        Ok(())
    }

    #[test]
    fn shared_client_disconnect_fails_pending_and_later_requests_fast() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let shared = SharedEngineIpcClient::from_stream(client_stream)?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);

        let pending_client = shared.clone();
        let pending = thread::spawn(move || {
            pending_client.request_for(
                None,
                DriverCommand::Extract {
                    node: tempo_schema::NodeId("pending".into()),
                },
                Duration::from_secs(30),
            )
        });
        let _ = connection.read_driver_request()?;
        drop(connection); // Engine dies mid-request.

        let pending_result = pending.join().map_err(|_| "pending requester panicked")?;
        assert!(matches!(
            pending_result,
            Err(EngineHostError::IpcClosed { .. })
        ));

        // Later requests fail fast instead of waiting out their timeout.
        let started = Instant::now();
        let later = shared.request_for(
            None,
            DriverCommand::Extract {
                node: tempo_schema::NodeId("later".into()),
            },
            Duration::from_secs(30),
        );
        assert!(later.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn shared_client_classifies_dead_connection_as_not_dispatched() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let shared = SharedEngineIpcClient::from_stream(client_stream)?;
        drop(server_stream);

        let result = shared.request_for_with_dispatch_status(
            None,
            DriverCommand::Observe,
            Duration::from_secs(1),
        );
        match result {
            Err(EngineIpcRequestError::NotDispatched(_)) => Ok(()),
            Err(EngineIpcRequestError::DispatchUncertain(error)) => Err(format!(
                "dead connection before write must not be classified as uncertain dispatch: {error}"
            )
            .into()),
            Ok(response) => Err(format!(
                "dead connection before write unexpectedly returned response: {response:?}"
            )
            .into()),
        }
    }

    #[test]
    fn shared_client_reassembles_chunked_screenshot_responses() -> TestResult {
        let screenshot = patterned_bytes(MAX_FRAME_BYTES as usize + 128 * 1024);
        let expected = screenshot.clone();
        let (client_stream, server_stream) = UnixStream::pair()?;
        let shared = SharedEngineIpcClient::from_stream(client_stream)?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);

        let requester = thread::spawn(move || {
            shared.request_for(None, DriverCommand::Screenshot, Duration::from_secs(10))
        });
        let request = connection.read_driver_request()?;
        assert_eq!(request.command, DriverCommand::Screenshot);
        connection
            .write_driver_response(request.id, DriverResponse::Screenshot { bytes: screenshot })?;

        let response = requester.join().map_err(|_| "requester panicked")??;
        assert_eq!(response, DriverResponse::Screenshot { bytes: expected });
        Ok(())
    }

    #[test]
    fn large_screenshot_response_chunks_and_keeps_connection_open() -> TestResult {
        let screenshot = patterned_bytes(MAX_FRAME_BYTES as usize + 256 * 1024);
        let expected = screenshot.clone();
        let full_payload = screenshot_payload_value(&screenshot);
        let full_frame = WireFrame::new(1, DRIVER_RESPONSE_METHOD, full_payload);
        assert!(serde_json::to_vec(&full_frame)?.len() > MAX_FRAME_BYTES as usize);

        let (client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        let handle = thread::spawn(
            move || -> Result<(DriverResponse, DriverResponse), EngineHostError> {
                let mut client = EngineIpcClient::from_stream(client_stream);
                let screenshot = client.request(DriverCommand::Screenshot)?;
                let closed = client.request(DriverCommand::Close)?;
                Ok((screenshot, closed))
            },
        );

        let screenshot_request = connection.read_driver_request()?;
        assert_eq!(screenshot_request.command, DriverCommand::Screenshot);
        connection.write_driver_response(
            screenshot_request.id,
            DriverResponse::Screenshot { bytes: screenshot },
        )?;

        let close_request = connection.read_driver_request()?;
        assert_eq!(close_request.command, DriverCommand::Close);
        connection.write_driver_response(close_request.id, DriverResponse::Closed)?;

        let (response, closed) = join_client_pair(handle)?;
        assert_eq!(response, DriverResponse::Screenshot { bytes: expected });
        assert_eq!(closed, DriverResponse::Closed);
        Ok(())
    }

    #[test]
    fn screenshot_chunk_reassembly_accepts_normal_multi_chunk_under_cap() -> TestResult {
        let request_id = 3;
        let expected = patterned_bytes(20);
        let first_payload = screenshot_chunk_payload(0, false, expected[0..8].to_vec())?;

        let mut stream = Vec::new();
        write_frame(
            &mut stream,
            &WireFrame::new(
                request_id,
                DRIVER_RESPONSE_METHOD,
                screenshot_chunk_payload(1, false, expected[8..16].to_vec())?,
            ),
        )?;
        write_frame(
            &mut stream,
            &WireFrame::new(
                request_id,
                DRIVER_RESPONSE_METHOD,
                screenshot_chunk_payload(2, true, expected[16..].to_vec())?,
            ),
        )?;

        let response =
            read_chunked_screenshot_response(&mut Cursor::new(stream), request_id, first_payload)?;

        assert_eq!(response, DriverResponse::Screenshot { bytes: expected });
        Ok(())
    }

    #[test]
    fn screenshot_chunk_reassembly_rejects_excessive_chunk_count() -> TestResult {
        // A compromised child streams endless tiny `final_chunk: false` chunks. The
        // first chunk (index 0) arrives as the initial payload; the reader supplies the
        // continuation frames. Without a cap this would accumulate frames forever; the
        // chunk cap must reject it while the accumulator is still tiny (bounded memory).
        let request_id = 7;
        let first_payload = screenshot_chunk_payload(0, false, vec![0_u8; 8])?;

        let mut stream = Vec::new();
        for chunk_index in 1..=MAX_SCREENSHOT_CHUNKS {
            write_frame(
                &mut stream,
                &WireFrame::new(
                    request_id,
                    DRIVER_RESPONSE_METHOD,
                    screenshot_chunk_payload(chunk_index, false, vec![0_u8; 8])?,
                ),
            )?;
        }

        let result =
            read_chunked_screenshot_response(&mut Cursor::new(stream), request_id, first_payload);

        assert!(
            matches!(result, Err(EngineHostError::InvalidScreenshotChunk { .. })),
            "expected InvalidScreenshotChunk, got {result:?}"
        );
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
        let resumed = host.resume_session_plaintext_unsafe(run_id, session_id)?;

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
        create_private_dir(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let client_path = socket_path.clone();
        let auth_token = server.auth_token().to_string();

        let handle = thread::spawn(move || -> Result<DriverResponse, EngineHostError> {
            let mut client = EngineIpcClient::connect_with_token(client_path, &auth_token)?;
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
            url: None,
            omitted: 0,
            marks: Vec::new(),
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
    fn ipc_client_round_trips_cached_observation_command_over_uds() -> TestResult {
        let root = unique_dir("uds-cached-observation")?;
        remove_dir_if_exists(&root)?;
        create_private_dir(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let client_path = socket_path.clone();
        let auth_token = server.auth_token().to_string();

        let handle = thread::spawn(move || -> Result<DriverResponse, EngineHostError> {
            let mut client = EngineIpcClient::connect_with_token(client_path, &auth_token)?;
            client.request(DriverCommand::CachedObservation { seq: 42 })
        });

        let mut connection = server.accept()?;
        let request = connection.read_driver_request()?;
        assert_eq!(request.id, 1);
        assert_eq!(request.driver_id, None);
        assert_eq!(
            request.command,
            DriverCommand::CachedObservation { seq: 42 }
        );

        let observation = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.test/".into(),
            seq: 42,
            elements: Vec::new(),
            omitted: 0,
            marks: Vec::new(),
        };
        connection.write_driver_response(
            request.id,
            DriverResponse::CachedObservation {
                observation: Some(observation.clone()),
            },
        )?;

        let response = join_client(handle)?;
        assert_eq!(
            response,
            DriverResponse::CachedObservation {
                observation: Some(observation)
            }
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn accept_unauthenticated_serves_tokenless_from_stream_client() -> TestResult {
        // Mirrors the shipped daemon attach path: `connect_engine_ipc` connects a
        // tokenless `EngineIpcClient::from_stream`, and the `tempo-engined-cdp`
        // host accepts it via `accept_unauthenticated` (uid-checked, no token).
        let root = unique_dir("uds-tokenless")?;
        remove_dir_if_exists(&root)?;
        create_private_dir(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let client_path = socket_path.clone();

        let handle = thread::spawn(move || -> Result<DriverResponse, EngineHostError> {
            let mut client = EngineIpcClient::from_stream(UnixStream::connect(client_path)?);
            client.request(DriverCommand::ObserveDiff { since_seq: 7 })
        });

        let mut connection = server.accept_unauthenticated()?;
        let request = connection.read_driver_request()?;
        assert_eq!(request.command, DriverCommand::ObserveDiff { since_seq: 7 });
        let diff = ObservationDiff {
            since_seq: 7,
            seq: 8,
            url: None,
            omitted: 0,
            marks: Vec::new(),
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
    fn ipc_accept_rejects_wrong_control_token() -> TestResult {
        let root = unique_dir("uds-auth")?;
        remove_dir_if_exists(&root)?;
        create_private_dir(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let mut stream = UnixStream::connect(&socket_path)?;
        let payload = serde_json::to_value(AuthPayload {
            token: "not-the-server-token".into(),
        })?;
        write_frame(&mut stream, &WireFrame::new(0, DRIVER_AUTH_METHOD, payload))?;

        assert!(matches!(
            server.accept(),
            Err(EngineHostError::ControlAuthFailed)
        ));

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
                provenance: Provenance::Page,
            }
        );
        assert_eq!(closed, DriverResponse::Closed);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn serve_driver_connection_offloads_uds_read_on_tokio_runtime() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = tokio::spawn(async move {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            serve_driver_connection(&mut connection, &mut driver).await
        });
        let client = thread::spawn(move || -> Result<DriverResponse, EngineHostError> {
            thread::sleep(Duration::from_millis(100));
            let mut client = EngineIpcClient::from_stream(client_stream);
            client.request(DriverCommand::Close)
        });

        let started = Instant::now();
        let yielded = tokio::time::timeout(Duration::from_millis(50), tokio::task::yield_now())
            .await
            .is_ok();
        assert!(
            yielded,
            "blocking UDS read held the current-thread runtime for {:?}",
            started.elapsed()
        );

        let client_response = tokio::task::spawn_blocking(move || match client.join() {
            Ok(result) => result,
            Err(_) => Err(EngineHostError::Io(io::Error::other(
                "client thread panicked",
            ))),
        })
        .await
        .map_err(|error| EngineHostError::BlockingTask(error.to_string()))??;
        assert_eq!(client_response, DriverResponse::Closed);
        server.await??;
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
    fn serve_driver_connection_routes_created_browsing_context_handles() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let mut connection = EngineIpcConnection::from_stream(server_stream);
        let handle = thread::spawn(move || -> Result<ContextClientResponses, EngineHostError> {
            let mut client = EngineIpcClient::from_stream(client_stream);
            let root_goto = client.request(DriverCommand::Goto {
                url: "https://root.test".into(),
            })?;
            let created = client.request(DriverCommand::CreateBrowsingContext {
                options: BrowsingContextCreateOptions {
                    kind: BrowsingContextKind::Tab,
                    background: false,
                },
            })?;
            let DriverResponse::BrowsingContextCreated { driver_id } = created else {
                return Err(EngineHostError::Io(io::Error::other(format!(
                    "unexpected context response: {created:?}"
                ))));
            };
            let context_initial = client.request_for(Some(&driver_id), DriverCommand::Observe)?;
            let context_goto = client.request_for(
                Some(&driver_id),
                DriverCommand::Goto {
                    url: "https://context.test".into(),
                },
            )?;
            let root_observe = client.request(DriverCommand::Observe)?;
            let context_observe = client.request_for(Some(&driver_id), DriverCommand::Observe)?;
            let context_close = client.request_for(Some(&driver_id), DriverCommand::Close)?;
            let root_close = client.request(DriverCommand::Close)?;
            Ok((
                driver_id,
                root_goto,
                context_initial,
                context_goto,
                root_observe,
                context_observe,
                context_close,
                root_close,
            ))
        });
        let mut driver = TestDriver::new();

        futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))?;
        let (
            driver_id,
            root_goto,
            context_initial,
            context_goto,
            root_observe,
            context_observe,
            context_close,
            root_close,
        ) = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("client thread panicked".into()),
        };

        assert_eq!(driver_id, "context-1");
        assert_observation_response(root_goto, "https://root.test", 1)?;
        assert_observation_response(context_initial, "about:blank", 0)?;
        assert_observation_response(context_goto, "https://context.test", 1)?;
        assert_observation_response(root_observe, "https://root.test", 1)?;
        assert_observation_response(context_observe, "https://context.test", 1)?;
        assert_eq!(context_close, DriverResponse::Closed);
        assert_eq!(root_close, DriverResponse::Closed);
        Ok(())
    }

    #[test]
    fn spawn_with_ipc_binds_socket_and_passes_path_to_child() -> TestResult {
        let root = unique_dir("spawn-ipc")?;
        remove_dir_if_exists(&root)?;
        create_private_dir(&root)?;
        let socket_path = root.join("engine.sock");
        let marker_path = root.join("socket-env.txt");
        let config = EngineHostConfig::new("sh")
            .arg("-c")
            .arg(format!(
                "printf '%s\\n%s' \"${ENGINE_HOST_SOCKET_ENV}\" \"${ENGINE_HOST_TOKEN_ENV}\" > \"$1\""
            ))
            .arg("tempo-engine-host-test")
            .arg(marker_path.to_string_lossy().to_string())
            .control_socket(socket_path.clone());

        let (mut host, server) = EngineHost::spawn_with_ipc(config)?;
        wait_for_exit(&mut host)?;

        assert_eq!(server.local_path(), socket_path.as_path());
        assert!(fs::symlink_metadata(&socket_path)?.file_type().is_socket());
        let marker = fs::read_to_string(&marker_path)?;
        let mut marker_lines = marker.lines();
        let expected_socket = socket_path.display().to_string();
        assert_eq!(marker_lines.next(), Some(expected_socket.as_str()));
        assert_eq!(marker_lines.next(), Some(server.auth_token()));
        assert_eq!(server.auth_token().len(), 64);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn authorize_peer_uid_accepts_owner_and_rejects_other_users() {
        assert!(authorize_peer_uid(1000, 1000).is_ok());
        assert!(matches!(
            authorize_peer_uid(1001, 1000),
            Err(EngineHostError::UnauthorizedPeer {
                peer_uid: 1001,
                server_uid: 1000,
            })
        ));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn accept_authorizes_same_uid_peer_and_restricts_socket_permissions() -> TestResult {
        let root = unique_dir("peercred")?;
        remove_dir_if_exists(&root)?;
        let socket_path = root.join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;

        // The socket must be owner-only (0600) and its directory owner-only (0700).
        let socket_mode = fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777;
        let dir_mode = fs::symlink_metadata(&root)?.permissions().mode() & 0o777;
        assert_eq!(socket_mode, 0o600, "socket mode was {socket_mode:o}");
        assert_eq!(dir_mode, 0o700, "dir mode was {dir_mode:o}");

        // A same-uid connection (this test process) must be authorized.
        let client_path = socket_path.clone();
        let auth_token = server.auth_token().to_string();
        let handle =
            thread::spawn(move || EngineIpcClient::connect_with_token(client_path, &auth_token));
        let accepted = server.accept();
        let _client = join_connect(handle)?;
        if let Err(error) = accepted {
            return Err(format!("same-uid peer was rejected: {error}").into());
        }

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn ipc_bind_rejects_non_socket_path() -> TestResult {
        let root = unique_dir("occupied")?;
        remove_dir_if_exists(&root)?;
        create_private_dir(&root)?;
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

    #[test]
    fn ipc_bind_creates_private_parent_and_owner_only_socket() -> TestResult {
        let root = unique_dir("private-socket")?;
        remove_dir_if_exists(&root)?;
        let socket_path = root.join("nested").join("engine.sock");
        let server = EngineIpcServer::bind(&socket_path)?;
        let parent = socket_path
            .parent()
            .ok_or("socket path unexpectedly has no parent")?;

        assert_eq!(fs::metadata(parent)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777,
            0o600
        );

        drop(server);
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn ipc_bind_rejects_insecure_existing_parent() -> TestResult {
        let root = unique_dir("insecure-socket")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        let result = EngineIpcServer::bind(root.join("engine.sock"));

        assert!(matches!(
            result,
            Err(EngineHostError::InsecureSocketDirectory { mode: 0o755, .. })
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

    fn join_client_pair(
        handle: thread::JoinHandle<Result<(DriverResponse, DriverResponse), EngineHostError>>,
    ) -> Result<(DriverResponse, DriverResponse), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("client thread panicked".into()),
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    fn join_connect(
        handle: thread::JoinHandle<Result<EngineIpcClient, EngineHostError>>,
    ) -> Result<EngineIpcClient, Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("connect thread panicked".into()),
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

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn screenshot_chunk_payload(
        chunk_index: u64,
        final_chunk: bool,
        bytes: Vec<u8>,
    ) -> Result<Value, serde_json::Error> {
        serde_json::to_value(ScreenshotChunkPayload::ScreenshotChunk {
            chunk_index,
            final_chunk,
            bytes,
        })
    }

    fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
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
