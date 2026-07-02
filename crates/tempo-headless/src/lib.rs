//! tempo-headless — headless `tempod` control plane.
//!
//! The daemon owns session lifecycle, engine-host supervision, graceful drain,
//! and JSONL export for StepTriples. The HTTP layer here is intentionally small:
//! it uses the standard library so the control surface works before a larger web
//! framework is selected for production packaging.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempo_agent::StepTriple;
use tempo_bidi::{
    browsing_context_load, BidiErrorCode, BidiEventMethod, BidiMessage, BidiRouter,
    BrowsingContextId, BrowsingContextInfo, CaptureScreenshotResult, CreateContextResult,
    DriverCommand as BidiDriverCommand, GetTreeResult, NavigateResult, RoutedCommand,
    ScriptEvaluateResult,
};
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError, Unsupported};
use tempo_engine_host::{
    DriverCommand as HostDriverCommand, DriverResponse, DriverWireError, EngineHost,
    EngineHostConfig, EngineHostError, EngineIpcClient,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use thiserror::Error;

const MAX_HTTP_BYTES: usize = 64 * 1024;
const MAX_WS_PAYLOAD_BYTES: u64 = MAX_HTTP_BYTES as u64;
/// Maximum number of live BiDi browsing contexts (forked drivers) held at once.
const MAX_BIDI_CONTEXTS: usize = 64;
/// Per-connection socket read/write timeout, bounding slowloris-style stalls.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout applied to engine-host IPC round-trips so a stalled engine cannot
/// wedge the daemon indefinitely.
const ENGINE_IPC_TIMEOUT: Duration = Duration::from_secs(30);
const WS_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_OPCODE_TEXT: u8 = 0x1;
const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;

/// Stable tempod session id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TempodSessionId(pub String);

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TempodSessionState {
    Running,
    Adopted,
    Killed,
}

/// Session record returned by the control API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempodSession {
    pub id: TempodSessionId,
    pub url: String,
    pub state: TempodSessionState,
    pub created_ms: u128,
}

/// One event in tempod's per-session control-plane log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TempodSessionEvent {
    pub session_id: TempodSessionId,
    pub seq: u64,
    pub timestamp_ms: u128,
    pub event: TempodSessionEventKind,
}

/// Typed events clients can attach to for session logs and StepTriple telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TempodSessionEventKind {
    SessionCreated { url: String },
    SessionAdopted,
    SessionKilled,
    SessionDrained,
    StepTriple { triple: StepTriple },
}

/// Driver handle attached to tempod through the engine-host UDS protocol.
#[derive(Clone)]
pub struct AttachedEngineDriver {
    engine: Engine,
    client: Arc<Mutex<EngineIpcClient>>,
    driver_id: Option<String>,
}

impl AttachedEngineDriver {
    pub fn new(engine: Engine, client: EngineIpcClient) -> Self {
        Self {
            engine,
            client: Arc::new(Mutex::new(client)),
            driver_id: None,
        }
    }

    fn request(&self, command: HostDriverCommand) -> Result<DriverResponse, DriverClientError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| DriverClientError::LockFailed)?;
        Ok(client.request_for(self.driver_id.as_deref(), command)?)
    }

    fn request_observation(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<CompiledObservation, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Observation { observation } => Ok(observation),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    fn request_diff(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<ObservationDiff, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Diff { diff } => Ok(diff),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    fn request_step(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<StepOutcome, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Step { outcome } => Ok(outcome.into()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    fn request_value(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<serde_json::Value, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Extracted { value } => Ok(value),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    fn request_evaluation(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<serde_json::Value, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Evaluated { value } => Ok(value),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    fn request_bytes(
        &self,
        command: HostDriverCommand,
        expected: &'static str,
    ) -> Result<Vec<u8>, TransportError> {
        match self
            .request(command)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Screenshot { bytes } => Ok(bytes),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, expected)),
        }
    }

    async fn fork_attached(&mut self) -> Result<Self, Unsupported> {
        match self.request(HostDriverCommand::Fork) {
            Ok(DriverResponse::Forked { driver_id }) => Ok(Self {
                engine: self.engine,
                client: Arc::clone(&self.client),
                driver_id: Some(driver_id),
            }),
            Ok(DriverResponse::Error { error }) => Err(driver_wire_unsupported(error)),
            Ok(_) => Err(Unsupported("unexpected engine IPC fork response")),
            Err(_) => Err(Unsupported("engine IPC fork failed")),
        }
    }
}

impl fmt::Debug for AttachedEngineDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachedEngineDriver")
            .field("engine", &self.engine)
            .field("driver_id", &self.driver_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DriverTrait for AttachedEngineDriver {
    fn engine(&self) -> Engine {
        self.engine
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        self.request_observation(HostDriverCommand::Goto { url: url.into() }, "goto")
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        self.request_observation(HostDriverCommand::Observe, "observe")
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        self.request_diff(HostDriverCommand::ObserveDiff { since_seq }, "observe_diff")
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        self.request_step(
            HostDriverCommand::Act {
                action: action.clone(),
            },
            "act",
        )
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        self.request_step(
            HostDriverCommand::ActBatch {
                batch: batch.clone(),
            },
            "act_batch",
        )
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        Ok(Box::new(self.fork_attached().await?))
    }

    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
        self.request_value(HostDriverCommand::Extract { node: node.clone() }, "extract")
    }

    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<serde_json::Value, TransportError> {
        self.request_evaluation(
            HostDriverCommand::EvaluateScript {
                expression: expression.into(),
                await_promise,
            },
            "evaluate_script",
        )
    }

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
        self.request_bytes(HostDriverCommand::Screenshot, "screenshot")
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        match self
            .request(HostDriverCommand::Close)
            .map_err(driver_client_transport_error)?
        {
            DriverResponse::Closed => Ok(()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "close")),
        }
    }
}

#[derive(Debug, Error)]
enum DriverClientError {
    #[error("attached engine driver lock failed")]
    LockFailed,
    #[error("engine host failed: {0}")]
    Host(#[from] EngineHostError),
}

/// In-memory session pool for a tempod process.
#[derive(Clone, Default)]
pub struct SessionPool {
    sessions: BTreeMap<TempodSessionId, TempodSession>,
    events: BTreeMap<TempodSessionId, Vec<TempodSessionEvent>>,
    bidi: BidiRouter,
    driver: Option<AttachedEngineDriver>,
    mcp: Option<Arc<Mutex<tempo_mcp::TempoMcpServer<AttachedEngineDriver>>>>,
    bidi_contexts: BTreeMap<BrowsingContextId, AttachedEngineDriver>,
    next_bidi_context_id: u64,
    next_id: u64,
    draining: bool,
}

impl fmt::Debug for SessionPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionPool")
            .field("sessions", &self.sessions)
            .field("event_sessions", &self.events.len())
            .field("bidi", &self.bidi)
            .field("driver", &self.driver)
            .field("mcp_attached", &self.mcp.is_some())
            .field("next_id", &self.next_id)
            .field("draining", &self.draining)
            .finish()
    }
}

impl SessionPool {
    pub fn create(&mut self, url: impl Into<String>) -> TempodSession {
        let id = TempodSessionId(format!("session-{}", self.next_id));
        self.next_id = self.next_id.saturating_add(1);
        let session = TempodSession {
            id: id.clone(),
            url: url.into(),
            state: TempodSessionState::Running,
            created_ms: current_time_ms(),
        };
        self.sessions.insert(id, session.clone());
        self.record_event(
            &session.id,
            TempodSessionEventKind::SessionCreated {
                url: session.url.clone(),
            },
        );
        session
    }

    pub fn list(&self) -> Vec<TempodSession> {
        self.sessions.values().cloned().collect()
    }

    pub fn adopt(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        let session = {
            let session = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
            session.state = TempodSessionState::Adopted;
            session.clone()
        };
        self.record_event(id, TempodSessionEventKind::SessionAdopted);
        Ok(session.clone())
    }

    pub fn kill(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        let session = {
            let session = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
            session.state = TempodSessionState::Killed;
            session.clone()
        };
        self.record_event(id, TempodSessionEventKind::SessionKilled);
        Ok(session.clone())
    }

    pub fn drain(&mut self) {
        self.draining = true;
        let mut drained = Vec::new();
        for session in self.sessions.values_mut() {
            if session.state == TempodSessionState::Running {
                session.state = TempodSessionState::Killed;
                drained.push(session.id.clone());
            }
        }
        for id in drained {
            self.record_event(&id, TempodSessionEventKind::SessionDrained);
        }
    }

    pub fn draining(&self) -> bool {
        self.draining
    }

    pub fn attach_engine_driver(&mut self, engine: Engine, client: EngineIpcClient) {
        self.close_forked_contexts();
        self.close_mcp_forks();
        let driver = AttachedEngineDriver::new(engine, client);
        self.mcp = Some(Arc::new(Mutex::new(tempo_mcp::TempoMcpServer::new(
            driver.clone(),
        ))));
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
        self.bidi_contexts
            .insert(default_context_id(), driver.clone());
        self.driver = Some(driver);
    }

    pub fn detach_engine_driver(&mut self) {
        self.close_forked_contexts();
        self.driver = None;
        self.close_mcp_forks();
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
    }

    /// Best-effort close of every forked BiDi context driver so engine-side
    /// resources are released instead of leaking when contexts/sessions end.
    fn close_forked_contexts(&mut self) {
        for driver in self.bidi_contexts.values_mut() {
            if driver.driver_id.is_some() {
                let _ = futures::executor::block_on(driver.close());
            }
        }
    }

    /// Best-effort close of every live forked driver held by the current MCP
    /// server before it is dropped at session teardown, so remote engine
    /// contexts (up to `MAX_LIVE_FORKS`) do not leak for the process lifetime.
    ///
    /// `close_all_forks` is async and talks to the engine over IPC, so a `Drop`
    /// impl cannot do this. The whole MCP stack is driven synchronously via
    /// `futures::executor::block_on` (mirroring `route_mcp`), so we do the same
    /// here. Teardown must not fail on cleanup, so lock and close errors are
    /// logged and swallowed. Leaves `self.mcp` as `None`.
    fn close_mcp_forks(&mut self) {
        let Some(server) = self.mcp.take() else {
            return;
        };
        let Ok(mut server) = server.lock() else {
            eprintln!("tempod: MCP server lock poisoned during fork teardown; skipping fork close");
            return;
        };
        for error in futures::executor::block_on(server.close_all_forks()) {
            eprintln!("tempod: error closing MCP fork at teardown: {error}");
        }
    }

    fn bidi_driver_for(&self, context: &BrowsingContextId) -> Option<AttachedEngineDriver> {
        self.bidi_contexts
            .get(context)
            .cloned()
            .or_else(|| self.bidi_contexts.get(&default_context_id()).cloned())
    }

    fn register_bidi_context(&mut self, driver: AttachedEngineDriver) -> BrowsingContextId {
        let context = BrowsingContextId(format!("tempo-bidi-{}", self.next_bidi_context_id));
        self.next_bidi_context_id = self.next_bidi_context_id.saturating_add(1);
        self.bidi_contexts.insert(context.clone(), driver);
        context
    }

    pub fn record_step(
        &mut self,
        id: &TempodSessionId,
        triple: StepTriple,
    ) -> Result<TempodSessionEvent, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        Ok(self.record_event(id, TempodSessionEventKind::StepTriple { triple }))
    }

    pub fn events(
        &self,
        id: &TempodSessionId,
        after_seq: Option<u64>,
    ) -> Result<Vec<TempodSessionEvent>, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        let events = self.events.get(id).map(Vec::as_slice).unwrap_or_default();
        Ok(events
            .iter()
            .filter(|event| after_seq.is_none_or(|after| event.seq > after))
            .cloned()
            .collect())
    }

    fn record_event(
        &mut self,
        id: &TempodSessionId,
        event: TempodSessionEventKind,
    ) -> TempodSessionEvent {
        let events = self.events.entry(id.clone()).or_default();
        let record = TempodSessionEvent {
            session_id: id.clone(),
            seq: events.len() as u64,
            timestamp_ms: current_time_ms(),
            event,
        };
        events.push(record.clone());
        record
    }
}

fn driver_client_transport_error(error: DriverClientError) -> TransportError {
    TransportError::Other(error.to_string())
}

fn driver_wire_transport_error(error: DriverWireError) -> TransportError {
    match error {
        DriverWireError::Transport { message } | DriverWireError::Protocol { message } => {
            TransportError::Other(message)
        }
        DriverWireError::Unsupported { capability } => TransportError::Other(capability),
    }
}

fn driver_wire_unsupported(error: DriverWireError) -> Unsupported {
    match error {
        DriverWireError::Unsupported { .. } => Unsupported("engine IPC capability unsupported"),
        DriverWireError::Transport { .. } | DriverWireError::Protocol { .. } => {
            Unsupported("engine IPC fork failed")
        }
    }
}

fn unexpected_driver_response(response: DriverResponse, expected: &'static str) -> TransportError {
    TransportError::Other(format!(
        "engine returned unexpected response for {expected}: {response:?}"
    ))
}

/// Supervised engine host registry used by tempod.
pub struct EngineSupervisor {
    hosts: BTreeMap<String, EngineHost>,
}

impl EngineSupervisor {
    pub fn new() -> Self {
        Self {
            hosts: BTreeMap::new(),
        }
    }

    pub fn start(
        &mut self,
        id: impl Into<String>,
        config: EngineHostConfig,
    ) -> Result<u32, TempodError> {
        let id = id.into();
        let host = EngineHost::spawn(config)?;
        let pid = host.pid();
        self.hosts.insert(id, host);
        Ok(pid)
    }

    pub fn kill(&mut self, id: &str) -> Result<(), TempodError> {
        let host = self
            .hosts
            .get_mut(id)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))?;
        host.kill()?;
        Ok(())
    }

    pub fn restart_if_exited(&mut self, id: &str) -> Result<bool, TempodError> {
        let host = self
            .hosts
            .get_mut(id)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))?;
        Ok(host.restart_if_exited()?)
    }

    pub fn pid(&self, id: &str) -> Result<u32, TempodError> {
        self.hosts
            .get(id)
            .map(EngineHost::pid)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))
    }
}

impl Default for EngineSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// JSONL exporter for StepTriple telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtlpJsonExporter {
    path: PathBuf,
}

impl OtlpJsonExporter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn export_step(&self, triple: &StepTriple) -> Result<(), TempodError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(
            &mut file,
            &json!({
                "resource": {
                    "service.name": "tempod",
                },
                "name": "tempo.step",
                "body": triple,
            }),
        )?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Run tempod forever on an address such as `127.0.0.1:8787`.
pub fn run_tempod(addr: &str) -> Result<(), TempodError> {
    let listener = TcpListener::bind(addr)?;
    let pool = Arc::new(Mutex::new(SessionPool::default()));
    serve_forever(listener, pool)
}

/// Run tempod with an already-running engine reachable through the UDS driver protocol.
pub fn run_tempod_with_attached_driver(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
) -> Result<(), TempodError> {
    let listener = TcpListener::bind(addr)?;
    let mut pool = SessionPool::default();
    pool.attach_engine_driver(engine, connect_engine_ipc(socket_path)?);
    serve_forever(listener, Arc::new(Mutex::new(pool)))
}

/// Connect to the engine host UDS and apply an IPC read/write timeout so a
/// stalled engine cannot wedge the daemon indefinitely.
fn connect_engine_ipc(socket_path: impl AsRef<Path>) -> Result<EngineIpcClient, TempodError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(ENGINE_IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(ENGINE_IPC_TIMEOUT))?;
    Ok(EngineIpcClient::from_stream(stream))
}

/// Serve requests until the listener fails or the process is stopped.
///
/// Each connection is handled on its own thread so that a slow, stalled, or
/// failing client is isolated to that connection: per-connection I/O errors and
/// transient `accept` errors are logged and the accept loop keeps running.
pub fn serve_forever(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let pool = Arc::clone(&pool);
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, &pool) {
                        log_connection_error(&err);
                    }
                });
            }
            Err(err) => {
                // A transient accept error (e.g. EMFILE) must not kill the daemon.
                log_connection_error(&TempodError::Io(err));
            }
        }
    }
    Ok(())
}

/// Serve exactly one HTTP request. Tests use this against a real TCP listener.
pub fn serve_one(listener: TcpListener, pool: Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let (stream, _addr) = listener.accept()?;
    handle_connection(stream, &pool)
}

/// Apply per-connection socket timeouts, then handle the connection. Timeouts
/// bound how long a stalled client can occupy a handler thread (slowloris).
fn handle_connection(stream: TcpStream, pool: &Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    apply_socket_timeouts(&stream)?;
    handle_stream(stream, pool)
}

/// Apply read and write timeouts to an accepted connection. A stalled client
/// (slowloris) is aborted after `SOCKET_TIMEOUT` instead of occupying a handler
/// thread forever.
fn apply_socket_timeouts(stream: &TcpStream) -> Result<(), TempodError> {
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    Ok(())
}

fn log_connection_error(err: &TempodError) {
    eprintln!("tempod connection error: {err}");
}

fn handle_stream(mut stream: TcpStream, pool: &Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            // Reject a malformed/oversized request with an error response rather
            // than dropping the connection (issue #84); the connection error, if
            // any, stays isolated to this handler (issue #85).
            let response = HttpResponse::json(
                err.status(),
                json!({
                    "error": err.to_string(),
                }),
            );
            stream.write_all(response.to_bytes().as_slice())?;
            stream.flush()?;
            return Ok(());
        }
    };
    match websocket_upgrade_key(&request) {
        Ok(Some(key)) => {
            stream.write_all(websocket_upgrade_response(&key).as_slice())?;
            stream.flush()?;
            return serve_bidi_websocket(stream, pool);
        }
        Ok(None) => {}
        Err(err) => {
            let response = HttpResponse::json(
                err.status(),
                json!({
                    "error": err.to_string(),
                }),
            );
            stream.write_all(response.to_bytes().as_slice())?;
            stream.flush()?;
            return Ok(());
        }
    }
    let response = {
        let mut pool = pool.lock().map_err(|_| TempodError::PoolLock)?;
        handle_http_request(&mut pool, request)
    };
    stream.write_all(response.to_bytes().as_slice())?;
    stream.flush()?;
    Ok(())
}

fn handle_http_request(pool: &mut SessionPool, request: HttpRequest) -> HttpResponse {
    match route_http_request(pool, request) {
        Ok(response) => response,
        Err(err) => HttpResponse::json(
            err.status(),
            json!({
                "error": err.to_string(),
            }),
        ),
    }
}

fn route_http_request(
    pool: &mut SessionPool,
    request: HttpRequest,
) -> Result<HttpResponse, TempodError> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/health") => Ok(HttpResponse::json(200, json!({"ok": true}))),
        ("GET", tempo_mcp::A2A_AGENT_CARD_PATH) | ("GET", tempo_mcp::A2A_AGENT_JSON_PATH) => Ok(
            HttpResponse::from_mcp(tempo_mcp::agent_card_response(&request.base_url())),
        ),
        ("GET", "/mcp") => Ok(HttpResponse::from_mcp(tempo_mcp::handle_get())),
        ("POST", "/mcp") => Ok(route_mcp(pool, &request)),
        ("POST", "/bidi") => {
            if !bidi_origin_allowed(&request) {
                return Err(TempodError::Forbidden("origin not allowed".into()));
            }
            Ok(route_bidi(pool, request.body))
        }
        ("GET", "/sessions") => Ok(HttpResponse::json(200, pool.list())),
        ("POST", "/sessions") => {
            let body: CreateSessionRequest = serde_json::from_slice(&request.body)?;
            if body.url.trim().is_empty() {
                return Err(TempodError::BadRequest("session url is required".into()));
            }
            Ok(HttpResponse::json(201, pool.create(body.url)))
        }
        ("POST", "/drain") => {
            pool.drain();
            Ok(HttpResponse::json(
                200,
                json!({
                    "draining": pool.draining(),
                    "sessions": pool.list(),
                }),
            ))
        }
        _ => {
            if request.method == "GET" {
                if let Some((id, after_seq)) = session_events_from_path(&request.path)? {
                    return Ok(HttpResponse::json(200, pool.events(&id, after_seq)?));
                }
            }
            if request.method == "POST" && request.path.ends_with("/adopt") {
                let id = session_id_from_action_path(&request.path, "adopt")?;
                return Ok(HttpResponse::json(200, pool.adopt(&id)?));
            }
            if request.method == "DELETE" {
                let id = session_id_from_path(&request.path)?;
                return Ok(HttpResponse::json(200, pool.kill(&id)?));
            }
            Err(TempodError::BadRequest(format!(
                "unsupported route: {} {}",
                request.method, request.path
            )))
        }
    }
}

fn session_events_from_path(
    path: &str,
) -> Result<Option<(TempodSessionId, Option<u64>)>, TempodError> {
    let (path, query) = split_path_query(path);
    let Some(session_path) = path.strip_suffix("/events") else {
        return Ok(None);
    };
    if !session_path.starts_with("/sessions/") {
        return Ok(None);
    }
    Ok(Some((
        session_id_from_path(session_path)?,
        after_seq(query)?,
    )))
}

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

fn after_seq(query: Option<&str>) -> Result<Option<u64>, TempodError> {
    let Some(query) = query else {
        return Ok(None);
    };
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name == "after_seq" {
            let parsed = value.parse::<u64>().map_err(|error| {
                TempodError::BadRequest(format!("invalid after_seq cursor: {error}"))
            })?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn websocket_upgrade_key(request: &HttpRequest) -> Result<Option<String>, TempodError> {
    if request.method != "GET" || request.path != "/bidi" {
        return Ok(None);
    }
    let upgrade = request
        .header("upgrade")
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection_upgrade = request
        .header("connection")
        .map(|value| header_has_token(value, "upgrade"))
        .unwrap_or(false);
    if !upgrade && !connection_upgrade && request.header("sec-websocket-key").is_none() {
        return Ok(None);
    }
    if !upgrade || !connection_upgrade {
        return Err(TempodError::BadRequest(
            "WebSocket upgrade requires Upgrade: websocket and Connection: Upgrade".into(),
        ));
    }
    if request.header("sec-websocket-version") != Some("13") {
        return Err(TempodError::BadRequest(
            "WebSocket upgrade requires Sec-WebSocket-Version: 13".into(),
        ));
    }
    // Reject cross-origin WebSocket handshakes (DNS-rebinding defence). Browsers
    // always send Origin on WS upgrades, so this blocks a malicious page from
    // driving the automated browser; non-browser clients omit Origin and pass.
    if !bidi_origin_allowed(request) {
        return Err(TempodError::Forbidden(
            "WebSocket origin not allowed".into(),
        ));
    }
    let key = request
        .header("sec-websocket-key")
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| {
            TempodError::BadRequest("WebSocket upgrade requires Sec-WebSocket-Key".into())
        })?;
    Ok(Some(key.to_string()))
}

/// Origin policy for the BiDi control endpoint. Mirrors the MCP route: Origin is
/// optional for non-browser clients, but when present only loopback origins are
/// accepted, blocking DNS-rebinding driven WebSocket/POST access.
fn bidi_origin_allowed(request: &HttpRequest) -> bool {
    tempo_mcp::origin_allowed(request.origin.as_deref())
}

fn header_has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|entry| entry.trim().eq_ignore_ascii_case(token))
}

fn websocket_upgrade_response(key: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_ACCEPT_GUID.as_bytes());
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
    )
    .into_bytes()
}

fn serve_bidi_websocket(
    mut stream: TcpStream,
    pool: &Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
    loop {
        let Some(frame) = read_websocket_frame(&mut stream)? else {
            return Ok(());
        };
        match frame.opcode {
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                let messages = {
                    let mut pool = pool.lock().map_err(|_| TempodError::PoolLock)?;
                    route_bidi_websocket(&mut pool, frame.payload)
                };
                for message in messages {
                    let payload = serde_json::to_vec(&message)?;
                    write_websocket_frame(&mut stream, WS_OPCODE_TEXT, &payload)?;
                }
            }
            WS_OPCODE_PING => {
                write_websocket_frame(&mut stream, WS_OPCODE_PONG, &frame.payload)?;
            }
            WS_OPCODE_CLOSE => {
                write_websocket_frame(&mut stream, WS_OPCODE_CLOSE, &[])?;
                return Ok(());
            }
            _ => {
                write_websocket_frame(&mut stream, WS_OPCODE_CLOSE, &[])?;
                return Ok(());
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

fn read_websocket_frame(stream: &mut TcpStream) -> Result<Option<WebSocketFrame>, TempodError> {
    let mut header = [0_u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(TempodError::Io(err)),
    }
    let fin = header[0] & 0x80 != 0;
    if !fin {
        return Err(TempodError::BadRequest(
            "fragmented websocket frames are not supported".into(),
        ));
    }
    if header[1] & 0x80 == 0 {
        return Err(TempodError::BadRequest(
            "client websocket frames must be masked".into(),
        ));
    }
    let opcode = header[0] & 0x0f;
    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut ext = [0_u8; 2];
        stream.read_exact(&mut ext)?;
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0_u8; 8];
        stream.read_exact(&mut ext)?;
        len = u64::from_be_bytes(ext);
    }
    if len > MAX_WS_PAYLOAD_BYTES {
        return Err(TempodError::BadRequest(
            "websocket payload is too large".into(),
        ));
    }
    let payload_len = usize::try_from(len)
        .map_err(|err| TempodError::BadRequest(format!("invalid websocket length: {err}")))?;
    let mut mask = [0_u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    Ok(Some(WebSocketFrame { opcode, payload }))
}

fn write_websocket_frame(
    stream: &mut TcpStream,
    opcode: u8,
    payload: &[u8],
) -> Result<(), TempodError> {
    let mut header = vec![0x80 | (opcode & 0x0f)];
    if payload.len() < 126 {
        let len = u8::try_from(payload.len())
            .map_err(|err| TempodError::BadRequest(format!("invalid websocket length: {err}")))?;
        header.push(len);
    } else if u16::try_from(payload.len()).is_ok() {
        let len = u16::try_from(payload.len())
            .map_err(|err| TempodError::BadRequest(format!("invalid websocket length: {err}")))?;
        header.push(126);
        header.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u64::try_from(payload.len())
            .map_err(|err| TempodError::BadRequest(format!("invalid websocket length: {err}")))?;
        header.push(127);
        header.extend_from_slice(&len.to_be_bytes());
    }
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn route_bidi(pool: &mut SessionPool, body: Vec<u8>) -> HttpResponse {
    route_bidi_dispatch(pool, body).response
}

fn route_bidi_websocket(pool: &mut SessionPool, body: Vec<u8>) -> Vec<BidiMessage> {
    let dispatch = route_bidi_dispatch(pool, body);
    let mut messages = Vec::with_capacity(1 + dispatch.events.len());
    messages.push(dispatch.message);
    messages.extend(dispatch.events);
    messages
}

fn route_bidi_dispatch(pool: &mut SessionPool, body: Vec<u8>) -> BidiDispatchResult {
    match pool.bidi.route_json(&body) {
        Ok(RoutedCommand::Immediate(message)) => BidiDispatchResult::new(200, message),
        Ok(RoutedCommand::Driver { id, command }) => {
            if pool.driver.is_none() {
                return BidiDispatchResult::new(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            }
            route_bidi_driver(pool, id, command)
        }
        Err(error) => BidiDispatchResult::new(
            400,
            BidiMessage::error(None, BidiErrorCode::InvalidArgument, error.to_string()),
        ),
    }
}

fn route_bidi_driver(
    pool: &mut SessionPool,
    id: tempo_bidi::CommandId,
    command: BidiDriverCommand,
) -> BidiDispatchResult {
    match command {
        BidiDriverCommand::Navigate(command) => {
            let context = command.context.clone();
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return driver_required_result(id);
            };
            let url = command.url.clone();
            match futures::executor::block_on(driver.goto(&url)) {
                Ok(_) => {
                    pool.bidi_contexts.insert(context.clone(), driver);
                    BidiDispatchResult::with_events(
                        200,
                        bidi_success_or_error(
                            id,
                            NavigateResult {
                                navigation: Some(format!("tempo-navigation-{id}")),
                                url: url.clone(),
                            },
                        ),
                        browsing_context_load_events(pool, &context, &url),
                    )
                }
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
        BidiDriverCommand::GetTree(command) => {
            let root = command.root.unwrap_or_else(default_context_id);
            let Some(mut driver) = pool.bidi_driver_for(&root) else {
                return driver_required_result(id);
            };
            match futures::executor::block_on(driver.observe()) {
                Ok(observation) => {
                    pool.bidi_contexts.insert(root.clone(), driver);
                    BidiDispatchResult::new(
                        200,
                        bidi_success_or_error(
                            id,
                            GetTreeResult {
                                contexts: vec![BrowsingContextInfo {
                                    context: root,
                                    url: observation.url,
                                    children: Vec::new(),
                                }],
                            },
                        ),
                    )
                }
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
        BidiDriverCommand::CaptureScreenshot(_) => {
            let context = screenshot_context(&command);
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return driver_required_result(id);
            };
            match futures::executor::block_on(driver.screenshot()) {
                Ok(bytes) => {
                    pool.bidi_contexts.insert(context, driver);
                    BidiDispatchResult::new(
                        200,
                        bidi_success_or_error(
                            id,
                            CaptureScreenshotResult {
                                data: base64::engine::general_purpose::STANDARD.encode(bytes),
                            },
                        ),
                    )
                }
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
        BidiDriverCommand::CreateContext(command) => {
            if pool.bidi_contexts.len() >= MAX_BIDI_CONTEXTS {
                return BidiDispatchResult::new(
                    200,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "browsing context limit reached",
                    ),
                );
            }
            let reference = command.reference_context.unwrap_or_else(default_context_id);
            let Some(mut driver) = pool.bidi_driver_for(&reference) else {
                return driver_required_result(id);
            };
            match futures::executor::block_on(driver.fork_attached()) {
                Ok(forked) => {
                    pool.bidi_contexts.insert(reference, driver);
                    let context = pool.register_bidi_context(forked);
                    BidiDispatchResult::new(
                        200,
                        bidi_success_or_error(id, CreateContextResult { context }),
                    )
                }
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
        BidiDriverCommand::Close(command) => {
            let context = command.context.clone();
            if context == default_context_id() {
                return BidiDispatchResult::new(
                    200,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::InvalidArgument,
                        "the root browsing context cannot be closed",
                    ),
                );
            }
            match pool.bidi_contexts.remove(&context) {
                Some(mut driver) => {
                    // Release the forked engine-side driver so it is not leaked.
                    if driver.driver_id.is_some() {
                        let _ = futures::executor::block_on(driver.close());
                    }
                    BidiDispatchResult::new(200, bidi_success_or_error(id, json!({})))
                }
                None => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::InvalidArgument,
                        "unknown browsing context",
                    ),
                ),
            }
        }
        BidiDriverCommand::EvaluateScript(command) => {
            let context = command.target.context.clone();
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return driver_required_result(id);
            };
            let expression = command.expression.clone();
            match futures::executor::block_on(
                driver.evaluate_script(&expression, command.await_promise),
            ) {
                Ok(value) => {
                    pool.bidi_contexts.insert(context.clone(), driver);
                    BidiDispatchResult::new(
                        200,
                        bidi_success_or_error(
                            id,
                            ScriptEvaluateResult {
                                result: value,
                                realm: Some(context.0),
                            },
                        ),
                    )
                }
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
    }
}

fn driver_required_result(id: tempo_bidi::CommandId) -> BidiDispatchResult {
    BidiDispatchResult::new(
        503,
        BidiMessage::error(
            Some(id),
            BidiErrorCode::UnknownError,
            "driver command requires an attached engine driver",
        ),
    )
}

fn bidi_success_or_error(id: tempo_bidi::CommandId, result: impl Serialize) -> BidiMessage {
    match BidiRouter::driver_success(id, result) {
        Ok(message) => message,
        Err(error) => BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
    }
}

fn browsing_context_load_events(
    pool: &SessionPool,
    context: &BrowsingContextId,
    url: &str,
) -> Vec<BidiMessage> {
    if !pool
        .bidi
        .event_subscribed(BidiEventMethod::BrowsingContextLoad, Some(context))
    {
        return Vec::new();
    }
    browsing_context_load(context.clone(), url)
        .map(|event| vec![event])
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct BidiDispatchResult {
    response: HttpResponse,
    message: BidiMessage,
    events: Vec<BidiMessage>,
}

impl BidiDispatchResult {
    fn new(status: u16, message: BidiMessage) -> Self {
        Self::with_events(status, message, Vec::new())
    }

    fn with_events(status: u16, message: BidiMessage, events: Vec<BidiMessage>) -> Self {
        Self {
            response: bidi_response(status, message.clone()),
            message,
            events,
        }
    }
}

fn default_context_id() -> BrowsingContextId {
    BrowsingContextId("tempo-root".into())
}

fn screenshot_context(command: &BidiDriverCommand) -> BrowsingContextId {
    match command {
        BidiDriverCommand::CaptureScreenshot(params) => params.context.clone(),
        _ => default_context_id(),
    }
}

fn bidi_response(status: u16, message: BidiMessage) -> HttpResponse {
    match serde_json::to_vec(&message) {
        Ok(body) => HttpResponse::new(status, "application/json", body),
        Err(error) => HttpResponse::json(
            500,
            json!({
                "error": error.to_string(),
            }),
        ),
    }
}

fn route_mcp(pool: &mut SessionPool, request: &HttpRequest) -> HttpResponse {
    if let Some(server) = &pool.mcp {
        let Ok(mut server) = server.lock() else {
            return HttpResponse::json(
                500,
                json!({
                    "error": "MCP server lock failed",
                }),
            );
        };
        return HttpResponse::from_mcp(futures::executor::block_on(
            server.handle_post(request.origin.as_deref(), &request.body),
        ));
    };
    HttpResponse::from_mcp(tempo_mcp::handle_post_driverless(
        request.origin.as_deref(),
        &request.body,
    ))
}

fn session_id_from_action_path(path: &str, action: &str) -> Result<TempodSessionId, TempodError> {
    let suffix = format!("/{action}");
    let path = path
        .strip_suffix(&suffix)
        .ok_or_else(|| TempodError::BadRequest(format!("invalid session action path: {path}")))?;
    session_id_from_path(path)
}

fn session_id_from_path(path: &str) -> Result<TempodSessionId, TempodError> {
    let id = path
        .strip_prefix("/sessions/")
        .ok_or_else(|| TempodError::BadRequest(format!("invalid session path: {path}")))?;
    if id.is_empty() {
        return Err(TempodError::BadRequest("session id is required".into()));
    }
    Ok(TempodSessionId(id.into()))
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    host: Option<String>,
    origin: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn base_url(&self) -> String {
        let host = self
            .host
            .as_deref()
            .filter(|host| valid_host_header(host))
            .unwrap_or("localhost");
        format!("http://{host}")
    }
}

fn valid_host_header(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, TempodError> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err(TempodError::BadRequest("HTTP request is too large".into()));
        }
        if header_end(&bytes).is_some() {
            break;
        }
    }

    let header_end =
        header_end(&bytes).ok_or_else(|| TempodError::BadRequest("missing HTTP headers".into()))?;
    let headers = String::from_utf8(bytes[..header_end].to_vec())
        .map_err(|err| TempodError::BadRequest(err.to_string()))?;
    let header_map = header_map(headers.lines());
    let origin = header_map.get("origin").cloned();
    let host = header_map.get("host").cloned();
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing method".into()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing path".into()))?
        .to_string();
    let content_len = content_length(&header_map)?;
    let body_start = header_end + 4;
    // `content_len` is already bounded by MAX_HTTP_BYTES, but compute the end
    // offset with a checked add so a malicious Content-Length can never overflow
    // and panic (issue #84).
    let body_end = body_start
        .checked_add(content_len)
        .ok_or_else(|| TempodError::BadRequest("HTTP body length overflow".into()))?;
    if body_end > MAX_HTTP_BYTES {
        return Err(TempodError::BadRequest("HTTP request is too large".into()));
    }
    while bytes.len() < body_end {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err(TempodError::BadRequest("HTTP request is too large".into()));
        }
    }
    if bytes.len() < body_end {
        return Err(TempodError::BadRequest("incomplete HTTP body".into()));
    }

    Ok(HttpRequest {
        method,
        path,
        headers: header_map,
        host,
        origin,
        body: bytes[body_start..body_end].to_vec(),
    })
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn header_map<'a>(lines: impl Iterator<Item = &'a str>) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    headers
}

fn content_length(headers: &BTreeMap<String, String>) -> Result<usize, TempodError> {
    match headers.get("content-length") {
        Some(value) => {
            let length: usize = value
                .trim()
                .parse()
                .map_err(|err: std::num::ParseIntError| TempodError::BadRequest(err.to_string()))?;
            if length > MAX_HTTP_BYTES {
                return Err(TempodError::BadRequest(
                    "Content-Length exceeds maximum allowed size".into(),
                ));
            }
            Ok(length)
        }
        None => Ok(0),
    }
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    fn json(status: u16, body: impl Serialize) -> Self {
        let body = match serde_json::to_vec(&body) {
            Ok(body) => body,
            Err(err) => format!("{{\"error\":\"{err}\"}}").into_bytes(),
        };
        Self::new(status, "application/json", body)
    }

    fn from_mcp(response: tempo_mcp::McpHttpResponse) -> Self {
        Self::new(response.status, response.content_type, response.body)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "OK",
        };
        let mut bytes = format!(
            "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

#[derive(Debug, Error)]
pub enum TempodError {
    #[error("tempod I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("tempod JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("session not found: {0:?}")]
    SessionNotFound(TempodSessionId),
    #[error("engine not found: {0}")]
    EngineNotFound(String),
    #[error("session pool lock failed")]
    PoolLock,
    #[error("engine host failed: {0}")]
    Engine(#[from] EngineHostError),
}

impl TempodError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Forbidden(_) => 403,
            Self::SessionNotFound(_) | Self::EngineNotFound(_) => 404,
            Self::Io(_) | Self::Json(_) | Self::PoolLock | Self::Engine(_) => 500,
        }
    }
}

fn current_time_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempo_agent::{IdempotencyKey, StepTripleOutcome};
    use tempo_driver::TestDriver;
    use tempo_engine_host::{
        serve_driver_connection, DriverRequest, EngineIpcConnection, RestartPolicy,
    };
    use tempo_schema::{Action, ObservationDiff, QuiescencePolicy};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn session_pool_create_list_adopt_kill_and_drain() -> TestResult {
        let mut pool = SessionPool::default();

        let session = pool.create("https://pool.test");
        let adopted = pool.adopt(&session.id)?;
        let killed = pool.kill(&session.id)?;
        pool.drain();

        assert_eq!(pool.list().len(), 1);
        assert_eq!(adopted.state, TempodSessionState::Adopted);
        assert_eq!(killed.state, TempodSessionState::Killed);
        assert!(pool.draining());
        Ok(())
    }

    #[test]
    fn session_pool_records_lifecycle_and_step_events() -> TestResult {
        let mut pool = SessionPool::default();
        let session = pool.create("https://events.test");
        pool.adopt(&session.id)?;
        let step = sample_step_triple(7);
        let step_event = pool.record_step(&session.id, step.clone())?;
        pool.kill(&session.id)?;

        assert_eq!(step_event.seq, 2);
        assert_eq!(
            step_event.event,
            TempodSessionEventKind::StepTriple { triple: step }
        );

        let events = pool.events(&session.id, None)?;
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events[0].event,
            TempodSessionEventKind::SessionCreated { .. }
        ));
        assert_eq!(events[1].event, TempodSessionEventKind::SessionAdopted);
        assert!(matches!(
            events[2].event,
            TempodSessionEventKind::StepTriple { .. }
        ));
        assert_eq!(events[3].event, TempodSessionEventKind::SessionKilled);

        let after_adopt = pool.events(&session.id, Some(1))?;
        assert_eq!(after_adopt.len(), 2);
        assert_eq!(after_adopt[0].seq, 2);
        Ok(())
    }

    #[test]
    fn session_pool_records_drain_events_for_running_sessions() -> TestResult {
        let mut pool = SessionPool::default();
        let running = pool.create("https://running.test");
        let adopted = pool.create("https://adopted.test");
        pool.adopt(&adopted.id)?;

        pool.drain();

        let running_events = pool.events(&running.id, None)?;
        let adopted_events = pool.events(&adopted.id, None)?;
        assert_eq!(
            running_events.last().map(|event| event.event.clone()),
            Some(TempodSessionEventKind::SessionDrained)
        );
        assert_eq!(
            adopted_events.last().map(|event| event.event.clone()),
            Some(TempodSessionEventKind::SessionAdopted)
        );
        Ok(())
    }

    #[test]
    fn http_create_and_list_sessions_over_tcp() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one(listener, server_pool));

        let response = send_http(
            addr,
            "POST /sessions HTTP/1.1\r\ncontent-length: 26\r\n\r\n{\"url\":\"https://one.test\"}",
        )?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 201 Created"));
        assert!(response.contains("\"id\":\"session-0\""));

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one(listener, server_pool));

        let response = send_http(addr, "GET /sessions HTTP/1.1\r\n\r\n")?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https://one.test"));
        Ok(())
    }

    #[test]
    fn http_session_events_endpoint_returns_logs_and_cursor_window() -> TestResult {
        let mut pool = SessionPool::default();
        let session = pool.create("https://events.test");
        pool.record_step(&session.id, sample_step_triple(1))?;
        pool.kill(&session.id)?;

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/sessions/session-0/events".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        assert_eq!(response.status, 200);
        let events: Vec<TempodSessionEvent> = serde_json::from_slice(&response.body)?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[2].event, TempodSessionEventKind::SessionKilled);

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/sessions/session-0/events?after_seq=0".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        let events: Vec<TempodSessionEvent> = serde_json::from_slice(&response.body)?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert!(matches!(
            events[0].event,
            TempodSessionEventKind::StepTriple { .. }
        ));
        Ok(())
    }

    #[test]
    fn http_session_events_endpoint_rejects_bad_cursor_and_missing_session() -> TestResult {
        let mut pool = SessionPool::default();
        let bad_cursor = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/sessions/session-0/events?after_seq=bad".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );
        let missing_session = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/sessions/session-0/events".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );

        assert_eq!(bad_cursor.status, 400);
        assert_eq!(missing_session.status, 404);
        Ok(())
    }

    #[test]
    fn tempod_serves_agent_card_over_well_known_http() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one(listener, pool));

        let response = send_http(
            addr,
            "GET /.well-known/agent-card.json HTTP/1.1\r\nhost: tempod.test:7777\r\n\r\n",
        )?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("content-type: application/a2a+json"));
        let body = response
            .split("\r\n\r\n")
            .nth(1)
            .ok_or("missing HTTP response body")?;
        let card: Value = serde_json::from_str(body)?;
        assert_eq!(card["name"], "tempo");
        assert_eq!(card["url"], "http://tempod.test:7777/mcp");
        assert_eq!(card["preferredTransport"], "MCP");
        assert!(card["skills"]
            .as_array()
            .ok_or("agent-card skills must be an array")?
            .iter()
            .any(|skill| skill["id"] == "handshake"));
        Ok(())
    }

    #[test]
    fn tempod_serves_a2a_agent_json_alias() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: tempo_mcp::A2A_AGENT_JSON_PATH.into(),
                headers: BTreeMap::new(),
                host: Some("localhost:8787".into()),
                origin: None,
                body: Vec::new(),
            },
        )?;

        assert_eq!(response.status, 200);
        assert_eq!(
            response.content_type,
            tempo_mcp::A2A_AGENT_CARD_CONTENT_TYPE
        );
        let card: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(card["url"], "http://localhost:8787/mcp");
        Ok(())
    }

    #[test]
    fn agent_card_falls_back_when_host_header_is_not_authority() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: tempo_mcp::A2A_AGENT_CARD_PATH.into(),
                headers: BTreeMap::new(),
                host: Some("localhost/path".into()),
                origin: None,
                body: Vec::new(),
            },
        )?;

        assert_eq!(response.status, 200);
        let card: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(card["url"], "http://localhost/mcp");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_routes_immediate_protocol_commands() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"session.status","params":{}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ready"], true);
        Ok(())
    }

    #[test]
    fn bidi_websocket_upgrade_routes_immediate_protocol_command() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one(listener, pool));
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        stream.write_all(
            b"GET /bidi HTTP/1.1\r\n\
              host: 127.0.0.1\r\n\
              upgrade: websocket\r\n\
              connection: Upgrade\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              sec-websocket-version: 13\r\n\r\n",
        )?;
        let response = read_http_head(&mut stream)?;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));
        assert!(response.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

        stream.write_all(&masked_client_frame(
            WS_OPCODE_TEXT,
            br#"{"id":1,"method":"session.status","params":{}}"#,
        )?)?;
        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_TEXT);
        let value: Value = serde_json::from_slice(&payload)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ready"], true);

        stream.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        assert!(payload.is_empty());
        join_server(handle)?;
        Ok(())
    }

    #[test]
    fn bidi_websocket_subscription_emits_browsing_context_load_event() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let pool = Arc::new(Mutex::new(pool));
        let handle = thread::spawn({
            let pool = Arc::clone(&pool);
            move || serve_one(listener, pool)
        });
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        stream.write_all(
            b"GET /bidi HTTP/1.1\r\n\
              host: 127.0.0.1\r\n\
              upgrade: websocket\r\n\
              connection: Upgrade\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              sec-websocket-version: 13\r\n\r\n",
        )?;
        let response = read_http_head(&mut stream)?;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        stream.write_all(&masked_client_frame(
            WS_OPCODE_TEXT,
            br#"{"id":1,"method":"session.subscribe","params":{"events":["browsingContext.load"],"contexts":["tempo-root"]}}"#,
        )?)?;
        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_TEXT);
        let value: Value = serde_json::from_slice(&payload)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 1);

        stream.write_all(&masked_client_frame(
            WS_OPCODE_TEXT,
            br#"{"id":2,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://event.test"}}"#,
        )?)?;
        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_TEXT);
        let value: Value = serde_json::from_slice(&payload)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 2);
        assert_eq!(value["result"]["url"], "https://event.test");

        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_TEXT);
        let value: Value = serde_json::from_slice(&payload)?;
        assert_eq!(value["type"], "event");
        assert_eq!(value["method"], "browsingContext.load");
        assert_eq!(value["params"]["context"], "tempo-root");
        assert_eq!(value["params"]["url"], "https://event.test");

        stream.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        assert!(payload.is_empty());

        drop(pool);
        join_server(handle)?;
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn bidi_endpoint_requires_driver_for_engine_commands() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"ctx","url":"https://example.test"}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 7);
        Ok(())
    }

    #[test]
    fn bidi_endpoint_routes_navigation_to_attached_engine_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(
                request.command,
                HostDriverCommand::Goto {
                    url: "https://example.test".into(),
                }
            );
            DriverResponse::Observation {
                observation: observation("https://example.test", 1),
            }
        })?;

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"ctx","url":"https://example.test"}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["url"], "https://example.test");
        assert_eq!(value["result"]["navigation"], "tempo-navigation-7");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_routes_script_evaluate_to_attached_engine_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(
                request.command,
                HostDriverCommand::EvaluateScript {
                    expression: "document.title".into(),
                    await_promise: true,
                }
            );
            DriverResponse::Evaluated {
                value: json!("Tempo"),
            }
        })?;

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":8,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"ctx"},"awaitPromise":true}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 8);
        assert_eq!(value["result"]["result"], "Tempo");
        assert_eq!(value["result"]["realm"], "ctx");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_routes_create_context_and_preserves_independent_context_state() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let created = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"browsingContext.create","params":{"type":"tab"}}"#
                    .to_vec(),
            },
        )?;
        let created: Value = serde_json::from_slice(&created.body)?;
        let created_context = created["result"]["context"]
            .as_str()
            .ok_or("create result must include context")?
            .to_string();

        let root_nav = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://root.test"}}"#.to_vec(),
            },
        )?;
        let fork_nav = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":3,"method":"browsingContext.navigate","params":{{"context":"{created_context}","url":"https://fork.test"}}}}"#
                )
                .into_bytes(),
            },
        )?;
        let root_tree = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body:
                    br#"{"id":4,"method":"browsingContext.getTree","params":{"root":"tempo-root"}}"#
                        .to_vec(),
            },
        )?;
        let fork_tree = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":5,"method":"browsingContext.getTree","params":{{"root":"{created_context}"}}}}"#
                )
                .into_bytes(),
            },
        )?;
        drop(pool);
        join_driver_handler(server)?;

        let root_nav: Value = serde_json::from_slice(&root_nav.body)?;
        let fork_nav: Value = serde_json::from_slice(&fork_nav.body)?;
        let root_tree: Value = serde_json::from_slice(&root_tree.body)?;
        let fork_tree: Value = serde_json::from_slice(&fork_tree.body)?;

        assert_eq!(created["type"], "success");
        assert_eq!(created["result"]["context"], created_context);
        assert_eq!(root_nav["type"], "success");
        assert_eq!(fork_nav["type"], "success");
        assert_eq!(
            root_tree["result"]["contexts"][0]["url"],
            "https://root.test"
        );
        assert_eq!(
            fork_tree["result"]["contexts"][0]["url"],
            "https://fork.test"
        );
        Ok(())
    }

    #[test]
    fn mcp_endpoint_routes_driverless_tools_without_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let get_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/mcp".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        let post_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/mcp".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#.to_vec(),
            },
        )?;
        let handshake_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/mcp".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"handshake","arguments":{"origin":"https://mcp.test","responses":[{"path":"/mcp/catalog.json","status":200,"content_type":"application/json","body":"{\"tools\":[]}"}]}}}"#.to_vec(),
            },
        )?;
        let observe_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/mcp".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#.to_vec(),
            },
        )?;

        assert_eq!(get_response.status, 405);
        assert_eq!(get_response.content_type, "text/plain; charset=utf-8");
        assert_eq!(post_response.status, 200);
        let tools: Value = serde_json::from_slice(&post_response.body)?;
        assert_eq!(tools["jsonrpc"], "2.0");
        assert_eq!(tools["id"], 9);
        assert_eq!(tools["result"]["tools"][0]["name"], "observe");

        assert_eq!(handshake_response.status, 200);
        let handshake: Value = serde_json::from_slice(&handshake_response.body)?;
        assert_eq!(handshake["id"], 10);
        assert_eq!(handshake["result"]["structuredContent"]["lane"], "mcp");
        assert_eq!(
            handshake["result"]["structuredContent"]["skips_render"],
            true
        );

        assert_eq!(observe_response.status, 200);
        let observe: Value = serde_json::from_slice(&observe_response.body)?;
        assert_eq!(observe["id"], 11);
        assert_eq!(observe["error"]["code"], -32002);
        Ok(())
    }

    #[test]
    fn mcp_endpoint_routes_tools_call_to_attached_engine_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.command, HostDriverCommand::Observe);
            DriverResponse::Observation {
                observation: observation("https://mcp.test", 4),
            }
        })?;

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/mcp".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: Some("http://127.0.0.1".into()),
                body: br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["id"], 3);
        assert_eq!(
            value["result"]["structuredContent"]["url"],
            "https://mcp.test"
        );
        assert_eq!(value["result"]["structuredContent"]["seq"], 4);
        Ok(())
    }

    #[test]
    fn mcp_endpoint_routes_act_batch_to_attached_engine_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(
                request.command,
                HostDriverCommand::ActBatch {
                    batch: ActionBatch {
                        actions: vec![Action::Scroll { x: 0.0, y: 12.0 }],
                        quiescence: QuiescencePolicy::Composite,
                    },
                }
            );
            DriverResponse::Step {
                outcome: StepOutcome::Applied {
                    diff: ObservationDiff {
                        since_seq: 1,
                        seq: 2,
                        added: Vec::new(),
                        removed: Vec::new(),
                        changed: Vec::new(),
                    },
                }
                .into(),
            }
        })?;

        let response = route_http_request(
            &mut pool,
            mcp_tool_request(
                12,
                "act_batch",
                json!({
                    "batch": {
                        "actions": [{"kind": "scroll", "x": 0.0, "y": 12.0}],
                        "quiescence": "composite",
                    }
                }),
            )?,
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["id"], 12);
        assert_eq!(value["result"]["structuredContent"]["status"], "applied");
        assert_eq!(value["result"]["structuredContent"]["diff"]["seq"], 2);
        Ok(())
    }

    #[test]
    fn mcp_endpoint_persists_fork_driver_ids_across_posts() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let fork_response = route_http_request(&mut pool, mcp_tool_request(1, "fork", json!({}))?)?;
        let fork: Value = serde_json::from_slice(&fork_response.body)?;
        let driver_id = fork["result"]["structuredContent"]["driver_id"]
            .as_str()
            .ok_or("fork response must include a driver_id")?
            .to_string();

        let act_response = route_http_request(
            &mut pool,
            mcp_tool_request(
                2,
                "act",
                json!({
                    "driver_id": driver_id.clone(),
                    "action": {"kind": "scroll", "x": 0.0, "y": 8.0},
                }),
            )?,
        )?;
        let root_response =
            route_http_request(&mut pool, mcp_tool_request(3, "observe", json!({}))?)?;
        let fork_response = route_http_request(
            &mut pool,
            mcp_tool_request(4, "observe", json!({"driver_id": driver_id}))?,
        )?;

        drop(pool);
        join_driver_handler(server)?;

        assert_eq!(act_response.status, 200);
        let act: Value = serde_json::from_slice(&act_response.body)?;
        assert_eq!(act["result"]["structuredContent"]["status"], "applied");

        let root: Value = serde_json::from_slice(&root_response.body)?;
        let fork: Value = serde_json::from_slice(&fork_response.body)?;
        assert_eq!(root["result"]["structuredContent"]["seq"], 0);
        assert_eq!(fork["result"]["structuredContent"]["seq"], 1);
        Ok(())
    }

    /// Engine-host-side driver that counts how many times `close()` is invoked
    /// across the root driver and every fork it spawns (forks share the counter).
    /// Lets a test assert that fork closes actually reach the engine over IPC.
    struct CloseCountingDriver {
        inner: Box<dyn DriverTrait>,
        closes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CloseCountingDriver {
        fn new(closes: Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self {
                inner: Box::new(TestDriver::new()),
                closes,
            }
        }
    }

    #[async_trait]
    impl DriverTrait for CloseCountingDriver {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.inner.observe_diff(since_seq).await
        }

        async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            let forked_inner = self.inner.fork().await?;
            Ok(Box::new(CloseCountingDriver {
                inner: forked_inner,
                closes: Arc::clone(&self.closes),
            }))
        }

        async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
            self.inner.extract(node).await
        }

        async fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<serde_json::Value, TransportError> {
            self.inner.evaluate_script(expression, await_promise).await
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            self.inner.screenshot().await
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.closes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.close().await
        }
    }

    #[test]
    fn detach_engine_driver_closes_live_forks() -> TestResult {
        // Regression guard for the #93 leak (#121 follow-up): tearing down a
        // session must close every live fork so remote engine contexts do not
        // leak. Against the pre-fix `detach_engine_driver` (which just dropped
        // the MCP server) the fork closes never reach the engine and `closes`
        // stays at 0, failing this test.
        let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine_closes = Arc::clone(&closes);
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = CloseCountingDriver::new(engine_closes);
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        // Open three live forks through the MCP endpoint.
        for id in 0..3 {
            let response = route_http_request(&mut pool, mcp_tool_request(id, "fork", json!({}))?)?;
            let fork: Value = serde_json::from_slice(&response.body)?;
            assert!(
                fork["result"]["structuredContent"]["driver_id"].is_string(),
                "fork {id} did not return a driver_id: {fork}"
            );
        }

        // Session teardown must close the forks before dropping the server.
        pool.detach_engine_driver();
        assert!(pool.mcp.is_none(), "detach must drop the MCP server");

        // Drop the pool so the root IPC connection closes and the engine host
        // thread finishes, then confirm all three fork closes were observed.
        drop(pool);
        join_driver_handler(server)?;
        assert_eq!(
            closes.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "every live fork must be closed at session teardown"
        );
        Ok(())
    }

    #[test]
    fn attached_engine_driver_fork_routes_to_forked_handle() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });
        let mut root_driver =
            AttachedEngineDriver::new(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let (root_observation, fork_observation) = futures::executor::block_on(async {
            root_driver.goto("https://root.test").await?;
            let mut forked_driver = root_driver
                .fork()
                .await
                .map_err(|error| Box::new(error) as Box<dyn Error>)?;
            forked_driver.goto("https://fork.test").await?;
            let root_observation = root_driver.observe().await?;
            let fork_observation = forked_driver.observe().await?;
            forked_driver.close().await?;
            root_driver.close().await?;
            Ok::<_, Box<dyn Error>>((root_observation, fork_observation))
        })?;
        join_driver_handler(server)?;

        assert_eq!(root_observation.url, "https://root.test");
        assert_eq!(root_observation.seq, 1);
        assert_eq!(fork_observation.url, "https://fork.test");
        assert_eq!(fork_observation.seq, 2);
        Ok(())
    }

    #[test]
    fn otlp_export_writes_step_triple_jsonl() -> TestResult {
        let root = unique_dir("otlp")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("steps.jsonl");
        let exporter = OtlpJsonExporter::new(&path);
        let triple = StepTriple {
            key: IdempotencyKey("step-1".into()),
            seq: 1,
            action: Action::Scroll { x: 0.0, y: 1.0 },
            outcome: StepTripleOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: 0,
                    seq: 1,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
        };

        exporter.export_step(&triple)?;
        let bytes = std::fs::read(&path)?;
        let value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap_or(&bytes))?;

        assert_eq!(value["resource"]["service.name"], "tempod");
        assert_eq!(value["name"], "tempo.step");
        assert_eq!(value["body"]["seq"], 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn engine_supervisor_starts_and_restarts_child() -> TestResult {
        let mut supervisor = EngineSupervisor::new();
        let config = EngineHostConfig::new("sh")
            .arg("-c")
            .arg("sleep 20")
            .restart(RestartPolicy::Always { max_restarts: 1 });
        let first_pid = supervisor.start("engine-a", config)?;

        supervisor.kill("engine-a")?;
        let restarted = supervisor.restart_if_exited("engine-a")?;
        let second_pid = supervisor.pid("engine-a")?;

        assert!(restarted);
        assert_ne!(first_pid, second_pid);
        supervisor.kill("engine-a")?;
        Ok(())
    }

    // ---- Issue #83: BiDi Origin / DNS-rebinding defence ----

    #[test]
    fn bidi_post_rejects_cross_origin_requests() -> TestResult {
        let mut pool = SessionPool::default();
        let response = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: Some("http://evil.example".into()),
                body: br#"{"id":1,"method":"session.status","params":{}}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 403);

        // Loopback origin is accepted.
        let allowed = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: Some("http://127.0.0.1:8787".into()),
                body: br#"{"id":1,"method":"session.status","params":{}}"#.to_vec(),
            },
        );
        assert_eq!(allowed.status, 200);
        Ok(())
    }

    #[test]
    fn bidi_websocket_upgrade_rejects_cross_origin() -> TestResult {
        let request = HttpRequest {
            method: "GET".into(),
            path: "/bidi".into(),
            headers: BTreeMap::from([
                ("upgrade".into(), "websocket".into()),
                ("connection".into(), "Upgrade".into()),
                ("sec-websocket-version".into(), "13".into()),
                (
                    "sec-websocket-key".into(),
                    "dGhlIHNhbXBsZSBub25jZQ==".into(),
                ),
                ("origin".into(), "http://evil.example".into()),
            ]),
            host: None,
            origin: Some("http://evil.example".into()),
            body: Vec::new(),
        };
        match websocket_upgrade_key(&request) {
            Err(TempodError::Forbidden(_)) => Ok(()),
            other => Err(format!("expected Forbidden, got {other:?}").into()),
        }
    }

    // ---- Issue #84: Content-Length overflow must not panic ----

    #[test]
    fn overflowing_content_length_is_rejected_without_panic() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one(listener, pool));

        let response = send_http(
            addr,
            "POST /sessions HTTP/1.1\r\ncontent-length: 18446744073709551615\r\n\r\n",
        )?;
        // The daemon thread must return cleanly (no panic / process death).
        join_server(handle)?;
        assert!(response.starts_with("HTTP/1.1 400"));
        Ok(())
    }

    #[test]
    fn content_length_helper_rejects_oversized_and_overflow_values() {
        let mut over = BTreeMap::new();
        over.insert(
            "content-length".to_string(),
            "18446744073709551615".to_string(),
        );
        assert!(content_length(&over).is_err());

        let mut big = BTreeMap::new();
        big.insert(
            "content-length".to_string(),
            (MAX_HTTP_BYTES + 1).to_string(),
        );
        assert!(content_length(&big).is_err());

        let mut ok = BTreeMap::new();
        ok.insert("content-length".to_string(), "12".to_string());
        assert_eq!(content_length(&ok).ok(), Some(12));
    }

    // ---- Issue #85: per-connection errors do not kill the listener ----

    #[test]
    fn connection_error_does_not_terminate_accept_loop() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        // serve_forever must keep accepting after a faulty connection.
        let handle = thread::spawn(move || serve_forever(listener, server_pool));

        // First client connects and disconnects immediately without sending a
        // request (client-side reset), which previously bubbled an Io error out
        // of the accept loop.
        {
            let stream = TcpStream::connect(addr)?;
            drop(stream);
        }

        // A subsequent well-formed request must still be served, proving the
        // listener survived the faulty connection.
        let response = send_http(
            addr,
            "POST /sessions HTTP/1.1\r\ncontent-length: 26\r\n\r\n{\"url\":\"https://two.test\"}",
        )?;
        assert!(response.starts_with("HTTP/1.1 201 Created"));

        // The accept loop is still running; shut it down by dropping the listener
        // via process teardown (thread is detached-like). We just confirm it has
        // not returned an error yet.
        assert!(!handle.is_finished());
        Ok(())
    }

    // ---- Issue #86: read timeout is applied per connection ----

    #[test]
    fn apply_socket_timeouts_sets_read_and_write_deadlines() -> TestResult {
        // Real 30s slowloris timeouts are impractical to exercise in a unit test,
        // so verify deterministically that the helper installs both deadlines on
        // the accepted socket; serve_forever/serve_one call it per connection.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _addr) = listener.accept()?;

        apply_socket_timeouts(&server)?;
        assert_eq!(server.read_timeout()?, Some(SOCKET_TIMEOUT));
        assert_eq!(server.write_timeout()?, Some(SOCKET_TIMEOUT));
        drop(client);
        Ok(())
    }

    // ---- Issue #87: bidi context cap + close cleanup ----

    #[test]
    fn bidi_create_context_is_capped() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        // Repeatedly create contexts; once the cap is reached, further creates
        // must be rejected instead of growing the map without bound.
        let mut saw_error = false;
        for _ in 0..(MAX_BIDI_CONTEXTS + 2) {
            let response = route_bidi_driver(
                &mut pool,
                999,
                BidiDriverCommand::CreateContext(tempo_bidi::CreateContextParameters {
                    context_type: tempo_bidi::ContextType::Tab,
                    reference_context: None,
                    background: false,
                }),
            );
            let value: Value = serde_json::from_slice(&response.response.body)?;
            if value["type"] == "error" {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "create must be rejected once the cap is reached");
        assert!(pool.bidi_contexts.len() <= MAX_BIDI_CONTEXTS);
        drop(pool);
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn bidi_close_removes_context_and_releases_driver() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || {
            let connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let created = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"browsingContext.create","params":{"type":"tab"}}"#
                    .to_vec(),
            },
        )?;
        let created: Value = serde_json::from_slice(&created.body)?;
        let created_context = created["result"]["context"]
            .as_str()
            .ok_or("create result must include context")?
            .to_string();
        assert_eq!(pool.bidi_contexts.len(), 2);

        let closed = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":2,"method":"browsingContext.close","params":{{"context":"{created_context}"}}}}"#
                )
                .into_bytes(),
            },
        )?;
        let closed: Value = serde_json::from_slice(&closed.body)?;
        assert_eq!(closed["type"], "success");
        // The forked context is removed, so the map is back to just the root.
        assert_eq!(pool.bidi_contexts.len(), 1);
        assert!(!pool
            .bidi_contexts
            .contains_key(&BrowsingContextId(created_context)));

        drop(pool);
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn bidi_close_rejects_root_context() -> TestResult {
        let mut pool = SessionPool::default();
        let result = route_bidi_driver(
            &mut pool,
            5,
            BidiDriverCommand::Close(tempo_bidi::CloseParameters {
                context: default_context_id(),
                prompt_unload: false,
            }),
        );
        let value: Value = serde_json::from_slice(&result.response.body)?;
        assert_eq!(value["type"], "error");
        Ok(())
    }

    fn send_http(addr: std::net::SocketAddr, request: &str) -> Result<String, std::io::Error> {
        let mut stream = TcpStream::connect(addr)?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn read_http_head(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 128];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                return Err("connection closed before HTTP headers".into());
            }
            bytes.extend_from_slice(&buffer[..read]);
            if header_end(&bytes).is_some() {
                return Ok(String::from_utf8(bytes)?);
            }
        }
    }

    fn masked_client_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = vec![0x80 | (opcode & 0x0f)];
        if payload.len() < 126 {
            frame.push(0x80 | u8::try_from(payload.len())?);
        } else if u16::try_from(payload.len()).is_ok() {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&u64::try_from(payload.len())?.to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        Ok(frame)
    }

    fn read_server_frame(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header)?;
        let opcode = header[0] & 0x0f;
        if header[1] & 0x80 != 0 {
            return Err("server frame must not be masked".into());
        }
        let mut length = u64::from(header[1] & 0x7f);
        if length == 126 {
            let mut extended = [0_u8; 2];
            stream.read_exact(&mut extended)?;
            length = u64::from(u16::from_be_bytes(extended));
        } else if length == 127 {
            let mut extended = [0_u8; 8];
            stream.read_exact(&mut extended)?;
            length = u64::from_be_bytes(extended);
        }
        let payload_len = usize::try_from(length)?;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload)?;
        Ok((opcode, payload))
    }

    fn join_server(
        handle: thread::JoinHandle<Result<(), TempodError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("server thread failed".into()),
        }
    }

    fn attach_driver_handler<F>(
        pool: &mut SessionPool,
        handler: F,
    ) -> Result<thread::JoinHandle<Result<(), EngineHostError>>, std::io::Error>
    where
        F: FnOnce(DriverRequest) -> DriverResponse + Send + 'static,
    {
        let (client_stream, server_stream) = UnixStream::pair()?;
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        Ok(thread::spawn(move || {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let request = connection.read_driver_request()?;
            let request_id = request.id;
            let response = handler(request);
            connection.write_driver_response(request_id, response)
        }))
    }

    fn join_driver_handler(
        handle: thread::JoinHandle<Result<(), EngineHostError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("driver handler thread failed".into()),
        }
    }

    fn mcp_tool_request(
        id: u64,
        name: &str,
        arguments: Value,
    ) -> Result<HttpRequest, serde_json::Error> {
        Ok(HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            headers: BTreeMap::new(),
            host: None,
            origin: Some("http://127.0.0.1".into()),
            body: serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            }))?,
        })
    }

    fn observation(url: &str, seq: u64) -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: url.into(),
            seq,
            elements: Vec::new(),
            marks: Vec::new(),
        }
    }

    fn sample_step_triple(seq: u64) -> StepTriple {
        StepTriple {
            key: IdempotencyKey(format!("step-{seq}")),
            seq,
            action: Action::Scroll { x: 0.0, y: 1.0 },
            outcome: StepTripleOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: seq.saturating_sub(1),
                    seq,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-headless-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}
