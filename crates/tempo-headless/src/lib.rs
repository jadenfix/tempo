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
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempo_agent::StepTriple;
use tempo_bidi::{
    BidiErrorCode, BidiMessage, BidiRouter, BrowsingContextId, BrowsingContextInfo,
    CaptureScreenshotResult, CreateContextResult, DriverCommand as BidiDriverCommand,
    GetTreeResult, NavigateResult, RoutedCommand, ScriptEvaluateResult,
};
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError, Unsupported};
use tempo_engine_host::{
    DriverCommand as HostDriverCommand, DriverResponse, DriverWireError, EngineHost,
    EngineHostConfig, EngineHostError, EngineIpcClient,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use thiserror::Error;

const MAX_HTTP_BYTES: usize = 64 * 1024;

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
        self.driver = None;
        self.mcp = None;
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
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
    pool.attach_engine_driver(engine, EngineIpcClient::connect(socket_path)?);
    serve_forever(listener, Arc::new(Mutex::new(pool)))
}

/// Serve requests until the listener fails or the process is stopped.
pub fn serve_forever(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
    for stream in listener.incoming() {
        handle_stream(stream?, &pool)?;
    }
    Ok(())
}

/// Serve exactly one HTTP request. Tests use this against a real TCP listener.
pub fn serve_one(listener: TcpListener, pool: Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let (stream, _addr) = listener.accept()?;
    handle_stream(stream, &pool)
}

fn handle_stream(mut stream: TcpStream, pool: &Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let request = read_http_request(&mut stream)?;
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
        ("POST", "/bidi") => Ok(route_bidi(pool, request.body)),
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

fn route_bidi(pool: &mut SessionPool, body: Vec<u8>) -> HttpResponse {
    match pool.bidi.route_json(&body) {
        Ok(RoutedCommand::Immediate(message)) => bidi_response(200, message),
        Ok(RoutedCommand::Driver { id, command }) => {
            if pool.driver.is_none() {
                return bidi_response(
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
        Err(error) => bidi_response(
            400,
            BidiMessage::error(None, BidiErrorCode::InvalidArgument, error.to_string()),
        ),
    }
}

fn route_bidi_driver(
    pool: &mut SessionPool,
    id: tempo_bidi::CommandId,
    command: BidiDriverCommand,
) -> HttpResponse {
    let message = match command {
        BidiDriverCommand::Navigate(command) => {
            let Some(mut driver) = pool.bidi_driver_for(&command.context) else {
                return bidi_response(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            };
            let url = command.url.clone();
            match futures::executor::block_on(driver.goto(&url)) {
                Ok(_) => {
                    pool.bidi_contexts.insert(command.context.clone(), driver);
                    BidiRouter::driver_success(
                        id,
                        NavigateResult {
                            navigation: Some(format!("tempo-navigation-{id}")),
                            url: command.url,
                        },
                    )
                }
                Err(error) => Ok(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    error.to_string(),
                )),
            }
        }
        BidiDriverCommand::GetTree(command) => {
            let root = command.root.unwrap_or_else(default_context_id);
            let Some(mut driver) = pool.bidi_driver_for(&root) else {
                return bidi_response(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            };
            match futures::executor::block_on(driver.observe()) {
                Ok(observation) => {
                    pool.bidi_contexts.insert(root.clone(), driver);
                    BidiRouter::driver_success(
                        id,
                        GetTreeResult {
                            contexts: vec![BrowsingContextInfo {
                                context: root,
                                url: observation.url,
                                children: Vec::new(),
                            }],
                        },
                    )
                }
                Err(error) => Ok(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    error.to_string(),
                )),
            }
        }
        BidiDriverCommand::CaptureScreenshot(_) => {
            let context = screenshot_context(&command);
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return bidi_response(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            };
            match futures::executor::block_on(driver.screenshot()) {
                Ok(bytes) => {
                    pool.bidi_contexts.insert(context.clone(), driver);
                    BidiRouter::driver_success(
                        id,
                        CaptureScreenshotResult {
                            data: base64::engine::general_purpose::STANDARD.encode(bytes),
                        },
                    )
                }
                Err(error) => Ok(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    error.to_string(),
                )),
            }
        }
        BidiDriverCommand::CreateContext(command) => {
            let reference = command.reference_context.unwrap_or_else(default_context_id);
            let Some(mut driver) = pool.bidi_driver_for(&reference) else {
                return bidi_response(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            };
            let created = futures::executor::block_on(driver.fork_attached());
            match created {
                Ok(forked) => {
                    pool.bidi_contexts.insert(reference.clone(), driver);
                    let context = pool.register_bidi_context(forked);
                    BidiRouter::driver_success(id, CreateContextResult { context })
                }
                Err(error) => Ok(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    error.to_string(),
                )),
            }
        }
        BidiDriverCommand::EvaluateScript(command) => {
            let Some(mut driver) = pool.bidi_driver_for(&command.target.context) else {
                return bidi_response(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "driver command requires an attached engine driver",
                    ),
                );
            };
            let expression = command.expression.clone();
            match futures::executor::block_on(
                driver.evaluate_script(&expression, command.await_promise),
            ) {
                Ok(value) => {
                    pool.bidi_contexts
                        .insert(command.target.context.clone(), driver);
                    BidiRouter::driver_success(
                        id,
                        ScriptEvaluateResult {
                            result: value,
                            realm: Some(command.target.context.0),
                        },
                    )
                }
                Err(error) => Ok(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    error.to_string(),
                )),
            }
        }
    };

    match message {
        Ok(message) => bidi_response(200, message),
        Err(error) => bidi_response(
            500,
            BidiMessage::error(None, BidiErrorCode::UnknownError, error.to_string()),
        ),
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
    host: Option<String>,
    origin: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
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
    let origin = header_value(headers.lines(), "origin");
    let host = header_value(headers.lines(), "host");
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
    let content_len = content_length(headers.lines())?;
    let body_start = header_end + 4;
    while bytes.len() < body_start + content_len {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err(TempodError::BadRequest("HTTP request is too large".into()));
        }
    }
    if bytes.len() < body_start + content_len {
        return Err(TempodError::BadRequest("incomplete HTTP body".into()));
    }

    Ok(HttpRequest {
        method,
        path,
        host,
        origin,
        body: bytes[body_start..body_start + content_len].to_vec(),
    })
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length<'a>(lines: impl Iterator<Item = &'a str>) -> Result<usize, TempodError> {
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse()
                    .map_err(|err: std::num::ParseIntError| {
                        TempodError::BadRequest(err.to_string())
                    });
            }
        }
    }
    Ok(0)
}

fn header_value<'a>(lines: impl Iterator<Item = &'a str>, target: &str) -> Option<String> {
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(target) {
            return Some(value.trim().to_string());
        }
    }
    None
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
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_agent::{IdempotencyKey, StepTripleOutcome};
    use tempo_driver::TestDriver;
    use tempo_engine_host::{
        serve_driver_connection, DriverRequest, EngineIpcConnection, RestartPolicy,
    };
    use tempo_schema::{Action, ObservationDiff};

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
    fn bidi_endpoint_requires_driver_for_engine_commands() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
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
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let created = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
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
    fn mcp_endpoint_persists_fork_driver_ids_across_posts() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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

    #[test]
    fn attached_engine_driver_fork_routes_to_forked_handle() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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

    fn send_http(addr: std::net::SocketAddr, request: &str) -> Result<String, std::io::Error> {
        let mut stream = TcpStream::connect(addr)?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
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
