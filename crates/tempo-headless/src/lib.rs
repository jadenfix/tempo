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
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempo_agent::{StepTriple, StepTripleOutcome};
use tempo_bidi::{
    browsing_context_load, network_before_request_sent, network_response_completed, BidiErrorCode,
    BidiEventMethod, BidiMessage, BidiRouter, BrowsingContextId, BrowsingContextInfo,
    CaptureScreenshotResult, CreateContextResult, DriverCommand as BidiDriverCommand,
    GetTreeResult, NavigateResult, NetworkRequest as BidiNetworkRequest,
    NetworkResponse as BidiNetworkResponse, RoutedCommand, ScriptEvaluateResult,
};
use tempo_driver::{
    BrowsingContextCreateOptions, BrowsingContextKind, DriverTrait, Engine, StepOutcome,
    TransportError, Unsupported,
};
use tempo_engine_host::{
    DriverCommand as HostDriverCommand, DriverResponse, DriverWireError, EngineHost,
    EngineHostConfig, EngineHostError, EngineIpcClient,
};
use tempo_policy::{decide_action, decide_effect, InputTaint, PolicyDecision};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff, SideEffect};
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
/// Upper bound on how long the whole engine-resource teardown (`drain` /
/// `detach_engine_driver` / `Drop`) waits for blocking engine-IPC closes:
/// forked BiDi contexts, MCP forks, session-owned contexts, and the root-driver
/// `Close`. Teardown runs while the caller holds the global pool `Mutex`, so a
/// wedged engine child that never answers any of those closes would otherwise
/// hold that lock for the full `ENGINE_IPC_TIMEOUT` (or forever, if the
/// connection carries no read timeout), hanging every request, including
/// `GET /health`, and turning a graceful `POST /drain` into a full-daemon hang
/// (#200). All closes run in order on one detached worker thread; on timeout the
/// worker owns the resources and finishes/drops them later, so the lock is
/// released promptly regardless of how many handles are wedged.
#[cfg(not(test))]
const ENGINE_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const ENGINE_TEARDOWN_TIMEOUT: Duration = Duration::from_millis(200);
const WS_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_OPCODE_TEXT: u8 = 0x1;
const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;
pub const TEMPO_OTLP_JSONL_ENV: &str = "TEMPO_OTLP_JSONL";

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

    async fn create_browsing_context_attached(
        &mut self,
        options: BrowsingContextCreateOptions,
    ) -> Result<Self, Unsupported> {
        match self.request(HostDriverCommand::CreateBrowsingContext { options }) {
            Ok(DriverResponse::BrowsingContextCreated { driver_id }) => Ok(Self {
                engine: self.engine,
                client: Arc::clone(&self.client),
                driver_id: Some(driver_id),
            }),
            Ok(DriverResponse::Error { error }) => Err(driver_wire_unsupported(error)),
            Ok(_) => Err(Unsupported("unexpected engine IPC create context response")),
            Err(_) => Err(Unsupported("engine IPC create context failed")),
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
    session_drivers: BTreeMap<TempodSessionId, AttachedEngineDriver>,
    events: BTreeMap<TempodSessionId, Vec<TempodSessionEvent>>,
    otlp_exporter: Option<OtlpJsonExporter>,
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
            .field("session_drivers", &self.session_drivers.keys())
            .field("event_sessions", &self.events.len())
            .field("otlp_exporter", &self.otlp_exporter)
            .field("bidi", &self.bidi)
            .field("driver", &self.driver)
            .field("mcp_attached", &self.mcp.is_some())
            .field("next_id", &self.next_id)
            .field("draining", &self.draining)
            .finish()
    }
}

impl SessionPool {
    pub fn from_env() -> Self {
        Self::from_otlp_env_value(std::env::var_os(TEMPO_OTLP_JSONL_ENV))
    }

    fn from_otlp_env_value(value: Option<std::ffi::OsString>) -> Self {
        match value {
            Some(path) if !path.is_empty() => {
                Self::default().with_otlp_exporter(OtlpJsonExporter::new(path))
            }
            _ => Self::default(),
        }
    }

    pub fn with_otlp_exporter(mut self, exporter: OtlpJsonExporter) -> Self {
        self.otlp_exporter = Some(exporter);
        self
    }

    pub fn set_otlp_exporter(&mut self, exporter: Option<OtlpJsonExporter>) {
        self.otlp_exporter = exporter;
    }

    pub fn otlp_exporter(&self) -> Option<&OtlpJsonExporter> {
        self.otlp_exporter.as_ref()
    }

    pub fn create(&mut self, url: impl Into<String>) -> Result<TempodSession, TempodError> {
        if self.draining {
            return Err(TempodError::Draining);
        }
        let url = url.into();
        let session_driver = self.create_session_engine_context(&url)?;
        let id = TempodSessionId(format!("session-{}", self.next_id));
        self.next_id = self.next_id.saturating_add(1);
        let session = TempodSession {
            id: id.clone(),
            url,
            state: TempodSessionState::Running,
            created_ms: current_time_ms(),
        };
        self.sessions.insert(id, session.clone());
        if let Some(driver) = session_driver {
            self.session_drivers.insert(session.id.clone(), driver);
        }
        self.record_event(
            &session.id,
            TempodSessionEventKind::SessionCreated {
                url: session.url.clone(),
            },
        );
        Ok(session)
    }

    pub fn list(&self) -> Vec<TempodSession> {
        self.sessions.values().cloned().collect()
    }

    pub fn adopt(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        if self.draining {
            return Err(TempodError::Draining);
        }
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
        self.close_session_driver(id);
        self.record_event(id, TempodSessionEventKind::SessionKilled);
        Ok(session.clone())
    }

    pub fn drain(&mut self) {
        self.draining = true;
        self.bidi.begin_drain();
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
        self.close_engine_resources(true);
    }

    pub fn draining(&self) -> bool {
        self.draining
    }

    pub fn attach_engine_driver(&mut self, engine: Engine, client: EngineIpcClient) {
        self.close_engine_resources(true);
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
        self.close_engine_resources(true);
    }

    /// Best-effort close of every live engine-backed resource: forked BiDi
    /// contexts, MCP forks, and optionally the attached root driver. Explicit
    /// drain/detach closes the root driver once; `Drop` skips root close because
    /// it cannot safely block forever if a test or crashed engine never responds.
    /// Idempotent and double-close-safe: it takes/clears the collections it
    /// closes, so a later call finds them empty.
    fn close_engine_resources(&mut self, close_root: bool) {
        self.bounded_engine_teardown(close_root, ENGINE_TEARDOWN_TIMEOUT);
    }

    /// Bound the ENTIRE engine-resource teardown so no wedged engine can hang
    /// drain / detach / `Drop` while the global pool `Mutex` is held (#200).
    ///
    /// Forked BiDi contexts, MCP forks, session-owned contexts, and (when
    /// `close_root`) the root driver each close over blocking engine IPC. A
    /// single wedged handle whose `close()` never returns would otherwise hold
    /// the pool lock indefinitely. So we detach all of them onto one worker
    /// thread that runs the closes in order -- forked contexts, MCP forks,
    /// session contexts, root -- and await its completion with one
    /// `recv_timeout`. Total public teardown is therefore bounded by one
    /// `timeout` regardless of how many handles are wedged.
    ///
    /// Ordering is preserved because forked handles must be closed before the root
    /// `Close` (the engine-host connection exits after the root `Close`). In the
    /// normal case (responsive engine) every close completes and the worker
    /// signals before `timeout`, so teardown stays synchronous/prompt. On timeout
    /// we log and proceed: the detached worker still owns the resources and drops
    /// them (and their connections) once its closes eventually return or the
    /// engine child dies, so the caller regains the lock promptly.
    ///
    /// `self` is cleaned up immediately (collections drained/cleared, `driver`
    /// and `mcp` nulled) before the worker is spawned, so this is idempotent and
    /// double-close-safe: a later call finds nothing to close.
    ///
    /// For `Drop` (`close_root == false`) the root driver is dropped WITHOUT a
    /// `Close` IPC (as before, so `Drop` never blocks on a root round-trip), but
    /// its fork / MCP closes are still bounded through the same worker.
    ///
    /// `AttachedEngineDriver` and `TempoMcpServer<AttachedEngineDriver>` are
    /// `Send + 'static` (`Arc<Mutex<..>>` + `Copy` `Engine`; forks are
    /// `Box<dyn DriverTrait>`, which is `Send`), so they move to the worker thread.
    fn bounded_engine_teardown(&mut self, close_root: bool, timeout: Duration) {
        // Collect everything to close and clean up `self` up front.
        let forks: Vec<AttachedEngineDriver> = std::mem::take(&mut self.bidi_contexts)
            .into_values()
            .filter(|driver| driver.driver_id.is_some())
            .collect();
        self.next_bidi_context_id = 1;
        let session_drivers = std::mem::take(&mut self.session_drivers)
            .into_iter()
            .map(|(id, driver)| (id.0, driver))
            .collect::<Vec<_>>();
        let mcp = self.mcp.take();
        // On `Drop` the root driver is dropped here without a Close IPC.
        let root = if close_root { self.driver.take() } else { None };
        self.driver = None;

        if forks.is_empty() && session_drivers.is_empty() && mcp.is_none() && root.is_none() {
            return;
        }

        let (tx, rx) = std::sync::mpsc::channel();
        // Detached on purpose: on timeout we must NOT join (that would reintroduce
        // the unbounded block); the worker finishes on its own and drops the
        // resources it owns.
        thread::spawn(move || {
            // Forked BiDi contexts first: engine-side resources released before the
            // engine-host connection exits on the root Close.
            for mut driver in forks {
                if let Err(error) = futures::executor::block_on(driver.close()) {
                    eprintln!("tempod: error closing forked BiDi context at teardown: {error}");
                }
            }
            // Then MCP forks.
            if let Some(server) = mcp {
                match server.lock() {
                    Ok(mut server) => {
                        for error in futures::executor::block_on(server.close_all_forks()) {
                            eprintln!("tempod: error closing MCP fork at teardown: {error}");
                        }
                    }
                    Err(_) => eprintln!(
                        "tempod: MCP server lock poisoned during fork teardown; skipping fork close"
                    ),
                }
            }
            // Then session-owned engine contexts.
            for (id, mut driver) in session_drivers {
                if let Err(error) = futures::executor::block_on(driver.close()) {
                    eprintln!("tempod: error closing session engine context {id}: {error}");
                }
            }
            // Finally the root driver's Close (only when close_root).
            if let Some(mut driver) = root
                && let Err(error) = futures::executor::block_on(driver.close())
            {
                eprintln!("tempod: error closing root engine driver at teardown: {error}");
            }
            let _ = tx.send(());
        });
        match rx.recv_timeout(timeout) {
            Ok(()) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!(
                    "tempod: engine-resource teardown did not complete within {timeout:?}; \
                     abandoning it so the pool lock is released (#200)"
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("tempod: engine-resource teardown thread ended without a result");
            }
        }
    }

    /// Allocate a fresh engine context for a newly-created tempod session and
    /// navigate it to the session URL. Without an attached engine, tempod still
    /// supports metadata-only session records for driverless control-plane tests.
    fn create_session_engine_context(
        &mut self,
        url: &str,
    ) -> Result<Option<AttachedEngineDriver>, TempodError> {
        let Some(root_driver) = self.driver.as_mut() else {
            return Ok(None);
        };
        let options = BrowsingContextCreateOptions {
            kind: BrowsingContextKind::Tab,
            background: true,
        };
        let mut session_driver =
            futures::executor::block_on(root_driver.create_browsing_context_attached(options))
                .map_err(|error| {
                    TempodError::Driver(format!(
                        "attached engine failed to create session context: {error}"
                    ))
                })?;
        if let Err(error) = futures::executor::block_on(session_driver.goto(url)) {
            let _ = futures::executor::block_on(session_driver.close());
            return Err(TempodError::Driver(format!(
                "attached engine failed to navigate session context: {error}"
            )));
        }
        Ok(Some(session_driver))
    }

    /// Best-effort close of one session-owned engine context. Session lifecycle
    /// state changes must still be recorded even if engine teardown races a
    /// crashed child, so close errors are logged and swallowed.
    fn close_session_driver(&mut self, id: &TempodSessionId) {
        let Some(mut driver) = self.session_drivers.remove(id) else {
            return;
        };

        let id = id.0.clone();
        match run_teardown_bounded(
            "session engine context Close",
            ENGINE_TEARDOWN_TIMEOUT,
            move || futures::executor::block_on(driver.close()),
        ) {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                eprintln!("tempod: error closing engine driver for session {id}: {error}");
            }
            None => {
                self.abandon_attached_engine_after_teardown_timeout("session engine context Close");
            }
        }
    }

    /// Best-effort close of every forked BiDi context driver so engine-side
    /// resources are released instead of leaking when contexts/sessions end.
    fn close_forked_contexts(&mut self) {
        let forked_contexts = self
            .bidi_contexts
            .values()
            .filter_map(|driver| {
                driver
                    .driver_id
                    .as_ref()
                    .map(|driver_id| (driver_id.clone(), driver.clone()))
            })
            .collect::<Vec<_>>();
        if forked_contexts.is_empty() {
            return;
        }

        let Some(errors) = run_teardown_bounded(
            "forked BiDi context Close commands",
            ENGINE_TEARDOWN_TIMEOUT,
            move || {
                let mut errors = Vec::new();
                for (driver_id, mut driver) in forked_contexts {
                    if let Err(error) = futures::executor::block_on(driver.close()) {
                        errors.push(format!("{driver_id}: {error}"));
                    }
                }
                errors
            },
        ) else {
            self.abandon_attached_engine_after_teardown_timeout(
                "forked BiDi context Close commands",
            );
            return;
        };

        for error in errors {
            eprintln!("tempod: error closing forked BiDi context at teardown: {error}");
        }
    }

    fn close_removed_bidi_context(&mut self, mut driver: AttachedEngineDriver) {
        if driver.driver_id.is_none() {
            return;
        }
        match run_teardown_bounded(
            "removed BiDi context Close",
            ENGINE_TEARDOWN_TIMEOUT,
            move || futures::executor::block_on(driver.close()),
        ) {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                eprintln!("tempod: error closing removed BiDi context at teardown: {error}");
            }
            None => {
                self.abandon_attached_engine_after_teardown_timeout("removed BiDi context Close");
            }
        }
    }

    fn abandon_attached_engine_after_teardown_timeout(&mut self, label: &'static str) {
        eprintln!(
            "tempod: {label} was abandoned while sharing the attached engine IPC; \
             detaching engine state to avoid future pool-lock stalls (#200)"
        );
        self.driver = None;
        self.mcp = None;
        self.session_drivers.clear();
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
    }

    fn bidi_driver_for(&self, context: &BrowsingContextId) -> Option<AttachedEngineDriver> {
        self.bidi_contexts.get(context).cloned()
    }

    fn register_bidi_context(&mut self, driver: AttachedEngineDriver) -> BrowsingContextId {
        let context = BrowsingContextId(format!("tempo-bidi-{}", self.next_bidi_context_id));
        self.next_bidi_context_id = self.next_bidi_context_id.saturating_add(1);
        self.bidi_contexts.insert(context.clone(), driver);
        context
    }

    fn start_bidi_session(&mut self) {
        self.close_forked_contexts();
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
        if let Some(driver) = &self.driver {
            self.bidi_contexts
                .insert(default_context_id(), driver.clone());
        }
    }

    fn end_bidi_session(&mut self) {
        self.close_forked_contexts();
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
    }

    pub fn record_step(
        &mut self,
        id: &TempodSessionId,
        triple: StepTriple,
    ) -> Result<TempodSessionEvent, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        if let Some(exporter) = &self.otlp_exporter {
            // Telemetry export is best-effort: a failing export (issue #214) must
            // never break the core step-recording path. Log and continue rather
            // than propagating the IO error out of `record_step`.
            if let Err(error) = exporter.export_step(&triple) {
                eprintln!("tempod: OTLP step export failed (telemetry only): {error}");
            }
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

impl Drop for SessionPool {
    /// Best-effort graceful close of any still-live engine forks / BiDi contexts
    /// when the pool is dropped (e.g. on normal daemon shutdown), so remote
    /// engine contexts are reclaimed promptly instead of only when the engine
    /// child process exits.
    ///
    /// CAVEAT: `Drop` runs only on a normal unwind/return — NOT on
    /// `SIGKILL`, nor a `SIGTERM` that terminates the process without unwinding.
    /// A full graceful-shutdown signal handler is a larger follow-up (out of
    /// scope here). Retention is already bounded by `MAX_LIVE_FORKS` /
    /// `MAX_BIDI_CONTEXTS`, and engine child processes are killed via
    /// `EngineHost::drop` at process exit, so this Drop mainly reclaims contexts
    /// promptly on graceful drop.
    ///
    /// `close_engine_resources` takes/clears the collections, so this cannot
    /// double-close a driver already closed by an explicit
    /// `detach_engine_driver`. Cleanup is best-effort: the close helpers already
    /// swallow and log their own errors, and we catch any panic so `Drop` never
    /// unwinds.
    fn drop(&mut self) {
        // Nothing engine-backed to close (never attached, or already detached).
        if self.mcp.is_none() && self.bidi_contexts.is_empty() && self.session_drivers.is_empty() {
            return;
        }
        let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.close_engine_resources(false);
        }));
        if closed.is_err() {
            eprintln!(
                "tempod: panic while closing engine resources during SessionPool drop; ignoring"
            );
        }
    }
}

fn run_teardown_bounded<T, F>(label: &'static str, timeout: Duration, cleanup: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached on purpose: on timeout we must not join (that would reintroduce
    // the unbounded block); the thread finishes on its own and drops owned
    // cleanup resources once the engine responds or disconnects.
    thread::spawn(move || {
        let _ = tx.send(cleanup());
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => Some(result),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "tempod: {label} did not complete within {timeout:?} at teardown; \
                 abandoning it so the pool lock is released (#200)"
            );
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("tempod: {label} thread ended without a result at teardown");
            None
        }
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
///
/// Hardened per issue #214:
/// * The append file handle is opened once (lazily) and reused for every step,
///   so we no longer `create_dir_all` + open + close per step while the caller
///   holds the pool lock — only the minimal write + flush stays on the hot path.
/// * On unix the file is created with `0600` permissions so telemetry captured
///   from a browsing session is not world-readable.
/// * Sensitive fields (typed action text, select values, skill inputs, and URL
///   query strings) are redacted/hashed before serialization instead of being
///   written verbatim. See [`redact_action`] / [`redact_step_outcome`].
#[derive(Clone)]
pub struct OtlpJsonExporter {
    path: PathBuf,
    /// Lazily-opened, reused append handle (issue #214, weakness 2). Shared so
    /// clones of the owning `SessionPool` write to the same open file.
    handle: Arc<Mutex<Option<File>>>,
}

impl fmt::Debug for OtlpJsonExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not expose the raw OS file handle in Debug output.
        formatter
            .debug_struct("OtlpJsonExporter")
            .field("path", &self.path)
            .field(
                "open",
                &self.handle.lock().map(|guard| guard.is_some()).ok(),
            )
            .finish()
    }
}

impl OtlpJsonExporter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Open (creating parents as needed) the append target with restrictive
    /// permissions. Called at most once per exporter; the handle is then reused.
    fn open_append_file(&self) -> Result<File, TempodError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 0600: owner read/write only (issue #214, weakness 3).
            options.mode(0o600);
        }
        let file = options.open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Enforce 0600 even if the file pre-existed with looser permissions;
            // `mode()` above only applies to files this call actually creates.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }

    pub fn export_step(&self, triple: &StepTriple) -> Result<(), TempodError> {
        // Serialize (including redaction) before touching the handle lock so the
        // lock-held region is just the write + flush.
        let mut bytes = serde_json::to_vec(&redacted_export_record(triple))?;
        bytes.push(b'\n');

        let mut guard = self.handle.lock().map_err(|_| TempodError::PoolLock)?;
        if guard.is_none() {
            *guard = Some(self.open_append_file()?);
        }
        match guard.as_mut() {
            Some(file) => {
                file.write_all(&bytes)?;
                file.flush()?;
                Ok(())
            }
            // Unreachable: the handle was just populated above.
            None => Ok(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Build the redacted OTLP record written for a step (issue #214, weakness 3).
///
/// We keep telemetry-useful, non-sensitive fields (idempotency key, seq, action
/// kind, node ids, coordinates, observation-diff counts) and redact anything
/// that can carry raw secrets: typed text, select values, skill inputs, and URL
/// query strings.
fn redacted_export_record(triple: &StepTriple) -> serde_json::Value {
    json!({
        "resource": {
            "service.name": "tempod",
        },
        "name": "tempo.step",
        "body": {
            "key": triple.key,
            "seq": triple.seq,
            "action": redact_action(&triple.action),
            "outcome": redact_step_outcome(&triple.outcome),
        },
    })
}

/// Redact an [`Action`] for telemetry: preserve structural fields, hash or strip
/// anything that can embed user/page secrets.
fn redact_action(action: &Action) -> serde_json::Value {
    match action {
        Action::Goto { url } => json!({ "kind": "goto", "url": strip_url_secrets(url) }),
        Action::Click { node } => json!({ "kind": "click", "node": node }),
        // Typed text frequently carries credentials — hash instead of logging.
        Action::Type { node, text } => {
            json!({ "kind": "type", "node": node, "text": hash_secret(text) })
        }
        // Select values can be sensitive (e.g. account numbers) — hash them.
        Action::Select { node, value } => {
            json!({ "kind": "select", "node": node, "value": hash_secret(value) })
        }
        Action::Scroll { x, y } => json!({ "kind": "scroll", "x": x, "y": y }),
        Action::Wait { millis } => json!({ "kind": "wait", "millis": millis }),
        Action::Extract { node } => json!({ "kind": "extract", "node": node }),
        // Skill input is arbitrary JSON that may contain secrets — keep the name,
        // hash the serialized input.
        Action::Skill { name, input } => json!({
            "kind": "skill",
            "name": name,
            "input": hash_secret(&input.to_string()),
        }),
    }
}

/// Summarize a step outcome without emitting raw page content. The observation
/// diff (which contains taint-labeled page text) is reduced to element counts.
fn redact_step_outcome(outcome: &StepTripleOutcome) -> serde_json::Value {
    match outcome {
        StepTripleOutcome::Applied { diff } => json!({
            "kind": "applied",
            "since_seq": diff.since_seq,
            "seq": diff.seq,
            "added": diff.added.len(),
            "removed": diff.removed.len(),
            "changed": diff.changed.len(),
        }),
        // `reason` is free-form and can embed arbitrary remote/secret content
        // (e.g. a failed navigation echoing a URL with `?token=...`, or a remote
        // error body), so hash it rather than logging it verbatim — consistent
        // with how `Type.text`/`Select.value`/`Skill.input` are redacted.
        StepTripleOutcome::StepError { reason } => json!({
            "kind": "step_error",
            "reason": hash_secret(reason),
        }),
    }
}

/// Strip the query string and fragment from a URL so secrets carried in query
/// parameters are not written verbatim, while keeping the scheme/host/path for
/// telemetry.
fn strip_url_secrets(url: &str) -> &str {
    match url.find(['?', '#']) {
        Some(index) => &url[..index],
        None => url,
    }
}

/// Hash a sensitive value to `sha256:<hex>` so raw secrets are never persisted
/// while still allowing equality/correlation across steps.
fn hash_secret(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2 + 7);
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Run tempod forever on an address such as `127.0.0.1:8787`.
pub fn run_tempod(addr: &str) -> Result<(), TempodError> {
    let listener = TcpListener::bind(addr)?;
    let pool = Arc::new(Mutex::new(SessionPool::from_env()));
    serve_forever(listener, pool)
}

/// Run tempod with an already-running engine reachable through the UDS driver protocol.
pub fn run_tempod_with_attached_driver(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
) -> Result<(), TempodError> {
    let listener = TcpListener::bind(addr)?;
    let mut pool = SessionPool::from_env();
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
    // DNS-rebinding defence (issue #83 follow-up): the session/control-plane
    // routes mutate or expose browser state, so they get the same loopback-Origin
    // guard already applied to /mcp and /bidi. Without this a malicious page could
    // DNS-rebind to the loopback listener and drive/observe the browser via
    // /sessions, /drain, /adopt, DELETE, or the session-events routes.
    if control_route_requires_origin_check(&request.method, &request.path)
        && !bidi_origin_allowed(&request)
    {
        return Err(TempodError::Forbidden("origin not allowed".into()));
    }
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
            Ok(HttpResponse::json(201, pool.create(body.url)?))
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
            if request.method == "GET"
                && let Some((id, after_seq)) = session_events_from_path(&request.path)?
            {
                return Ok(HttpResponse::json(200, pool.events(&id, after_seq)?));
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

/// Whether a route served by `route_http_request` must pass the loopback-Origin
/// guard. Session/control-plane routes (create, drain, adopt, delete, list,
/// session events, and any unrecognised — hence potentially state-changing —
/// route) are guarded. Exempt are the public idempotent metadata routes
/// (`/health`, the A2A agent card, `GET /mcp`) and the routes that already run
/// their own Origin check (`POST /mcp` via `route_mcp`, `POST /bidi`, and the
/// `GET /bidi` WebSocket upgrade handled before this function). The guard relies
/// on `origin_allowed` returning `true` when no Origin header is present, so
/// non-browser/CLI clients keep working.
fn control_route_requires_origin_check(method: &str, path: &str) -> bool {
    !matches!(
        (method, path),
        ("GET", "/health")
            | ("GET", tempo_mcp::A2A_AGENT_CARD_PATH)
            | ("GET", tempo_mcp::A2A_AGENT_JSON_PATH)
            | ("GET", "/mcp")
            | ("POST", "/mcp")
            | ("GET", "/bidi")
            | ("POST", "/bidi")
    )
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
        Ok(RoutedCommand::SessionStarted(message)) => {
            pool.start_bidi_session();
            BidiDispatchResult::new(200, message)
        }
        Ok(RoutedCommand::SessionEnded(message)) => {
            pool.end_bidi_session();
            BidiDispatchResult::new(200, message)
        }
        Ok(RoutedCommand::Driver { id, command }) => {
            if pool.draining {
                return BidiDispatchResult::new(
                    503,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        "tempod is draining; BiDi driver commands are not accepted",
                    ),
                );
            }
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
            if let Some(denied) = enforce_bidi_action_policy(
                id,
                &command.action,
                command.input_tainted,
                command.confirmed,
            ) {
                return denied;
            }
            let context = command.context.clone();
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return unknown_browsing_context_result(id);
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
                        browsing_context_navigation_events(pool, id, &context, &url),
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
                return unknown_browsing_context_result(id);
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
                return unknown_browsing_context_result(id);
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
                return unknown_browsing_context_result(id);
            };
            let options = BrowsingContextCreateOptions {
                kind: match command.context_type {
                    tempo_bidi::ContextType::Tab => BrowsingContextKind::Tab,
                    tempo_bidi::ContextType::Window => BrowsingContextKind::Window,
                },
                background: command.background,
            };
            match futures::executor::block_on(driver.create_browsing_context_attached(options)) {
                Ok(created_driver) => {
                    pool.bidi_contexts.insert(reference, driver);
                    let context = pool.register_bidi_context(created_driver);
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
                Some(driver) => {
                    // Release the forked engine-side driver so it is not leaked.
                    pool.close_removed_bidi_context(driver);
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
            if let Some(denied) = enforce_bidi_effect_policy(
                id,
                SideEffect::Write,
                command.input_tainted,
                command.confirmed,
            ) {
                return denied;
            }
            let context = command.target.context.clone();
            let Some(mut driver) = pool.bidi_driver_for(&context) else {
                return unknown_browsing_context_result(id);
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

fn enforce_bidi_action_policy(
    id: tempo_bidi::CommandId,
    action: &Action,
    input_tainted: Option<bool>,
    confirmed: bool,
) -> Option<BidiDispatchResult> {
    let Some(input_tainted) = input_tainted else {
        return Some(missing_bidi_input_taint_result(id));
    };
    let decision = decide_action(action, InputTaint::new(input_tainted));
    bidi_policy_denial(id, decision, confirmed)
}

fn enforce_bidi_effect_policy(
    id: tempo_bidi::CommandId,
    effect: SideEffect,
    input_tainted: Option<bool>,
    confirmed: bool,
) -> Option<BidiDispatchResult> {
    let Some(input_tainted) = input_tainted else {
        return Some(missing_bidi_input_taint_result(id));
    };
    let decision = decide_effect(effect, InputTaint::new(input_tainted));
    bidi_policy_denial(id, decision, confirmed)
}

fn missing_bidi_input_taint_result(id: tempo_bidi::CommandId) -> BidiDispatchResult {
    BidiDispatchResult::new(
        200,
        BidiMessage::error(
            Some(id),
            BidiErrorCode::InvalidArgument,
            "inputTainted/input_tainted is required for policy-gated BiDi commands",
        ),
    )
}

fn bidi_policy_denial(
    id: tempo_bidi::CommandId,
    decision: PolicyDecision,
    confirmed: bool,
) -> Option<BidiDispatchResult> {
    if decision.requires_confirmation() && !confirmed {
        Some(BidiDispatchResult::new(
            200,
            BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                format!(
                    "policy denied: {:?} BiDi command with input_tainted={} requires {:?}; retry with confirmed=true after human confirmation",
                    decision.side_effect,
                    decision.input_taint.is_tainted(),
                    decision.gate
                ),
            ),
        ))
    } else {
        None
    }
}

fn unknown_browsing_context_result(id: tempo_bidi::CommandId) -> BidiDispatchResult {
    BidiDispatchResult::new(
        200,
        BidiMessage::error(
            Some(id),
            BidiErrorCode::InvalidArgument,
            "unknown browsing context",
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

fn browsing_context_navigation_events(
    pool: &SessionPool,
    id: tempo_bidi::CommandId,
    context: &BrowsingContextId,
    url: &str,
) -> Vec<BidiMessage> {
    let mut events = network_navigation_events(pool, id, context, url);
    events.extend(browsing_context_load_events(pool, context, url));
    events
}

fn network_navigation_events(
    pool: &SessionPool,
    id: tempo_bidi::CommandId,
    context: &BrowsingContextId,
    url: &str,
) -> Vec<BidiMessage> {
    let request_id = format!("tempo-request-{id}");
    let mut events = Vec::new();
    if pool
        .bidi
        .event_subscribed(BidiEventMethod::NetworkBeforeRequestSent, Some(context))
    {
        let request = tempo_net::NetworkRequest::new(
            request_id.clone(),
            "GET",
            url,
            format!("tempo-bidi-profile-{}", context.0),
            tempo_net::IdentityMode::AgentDeclared,
        );
        if let Ok(event) =
            network_before_request_sent(BidiNetworkRequest::from_tempo_request(&request))
        {
            events.push(event);
        }
    }
    if pool
        .bidi
        .event_subscribed(BidiEventMethod::NetworkResponseCompleted, Some(context))
    {
        // DriverTrait exposes navigation completion but not the underlying HTTP
        // response status yet, so this is the top-level successful navigation.
        let response = tempo_net::NetworkResponseRecord::new(request_id, url, 200);
        if let Ok(event) =
            network_response_completed(BidiNetworkResponse::from_tempo_response(&response))
        {
            events.push(event);
        }
    }
    events
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
    if pool.draining {
        return HttpResponse::json(
            503,
            json!({
                "error": "tempod is draining; MCP tool calls are not accepted",
            }),
        );
    }
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
    #[error("tempod is draining; new sessions are not accepted")]
    Draining,
    #[error("session pool lock failed")]
    PoolLock,
    #[error("driver failed: {0}")]
    Driver(String),
    #[error("engine host failed: {0}")]
    Engine(#[from] EngineHostError),
}

impl TempodError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Forbidden(_) => 403,
            Self::SessionNotFound(_) | Self::EngineNotFound(_) => 404,
            Self::Draining => 503,
            Self::Io(_) | Self::Json(_) | Self::PoolLock | Self::Driver(_) | Self::Engine(_) => 500,
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
    use tempo_agent::IdempotencyKey;
    use tempo_driver::TestDriver;
    use tempo_engine_host::{
        serve_driver_connection, DriverRequest, DriverWireError, EngineIpcConnection, RestartPolicy,
    };
    use tempo_schema::{Action, ObservationDiff, QuiescencePolicy};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn session_pool_create_list_adopt_kill_and_drain() -> TestResult {
        let mut pool = SessionPool::default();

        let session = pool.create("https://pool.test")?;
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
    fn http_create_session_allocates_attached_driver_context_and_kill_closes_it() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert_eq!(create.driver_id, None);
            assert_eq!(
                create.command,
                HostDriverCommand::CreateBrowsingContext {
                    options: BrowsingContextCreateOptions {
                        kind: BrowsingContextKind::Tab,
                        background: true,
                    },
                }
            );
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-1".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-1"));
            assert_eq!(
                goto.command,
                HostDriverCommand::Goto {
                    url: "https://session.test".into(),
                }
            );
            connection.write_driver_response(
                goto.id,
                DriverResponse::Observation {
                    observation: observation("https://session.test", 1),
                },
            )?;

            let close = connection.read_driver_request()?;
            assert_eq!(close.driver_id.as_deref(), Some("session-context-1"));
            assert_eq!(close.command, HostDriverCommand::Close);
            connection.write_driver_response(close.id, DriverResponse::Closed)
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let create = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://session.test"}"#.to_vec(),
            },
        )?;

        assert_eq!(create.status, 201);
        let session: TempodSession = serde_json::from_slice(&create.body)?;
        assert_eq!(session.id.0, "session-0");
        assert_eq!(session.url, "https://session.test");
        assert_eq!(session.state, TempodSessionState::Running);
        assert!(pool.session_drivers.contains_key(&session.id));

        let kill = route_http_request(
            &mut pool,
            HttpRequest {
                method: "DELETE".into(),
                path: "/sessions/session-0".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;

        assert_eq!(kill.status, 200);
        let killed: TempodSession = serde_json::from_slice(&kill.body)?;
        assert_eq!(killed.state, TempodSessionState::Killed);
        assert!(!pool.session_drivers.contains_key(&session.id));

        drop(pool);
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn http_kill_does_not_hang_on_wedged_session_context() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(create.driver_id.is_none());
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-1".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-1"));
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            connection.write_driver_response(
                goto.id,
                DriverResponse::Observation {
                    observation: observation("https://session.test", 1),
                },
            )?;

            let close = connection.read_driver_request()?;
            assert_eq!(close.driver_id.as_deref(), Some("session-context-1"));
            assert_eq!(close.command, HostDriverCommand::Close);
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let create = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://session.test"}"#.to_vec(),
            },
        )?;
        assert_eq!(create.status, 201);
        assert_eq!(pool.session_drivers.len(), 1);

        let started = std::time::Instant::now();
        let kill = route_http_request(
            &mut pool,
            HttpRequest {
                method: "DELETE".into(),
                path: "/sessions/session-0".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        let elapsed = started.elapsed();

        assert_eq!(kill.status, 200);
        assert!(
            elapsed < Duration::from_secs(5),
            "session kill hung on a wedged session context close: took {elapsed:?}"
        );
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());
        assert!(pool.session_drivers.is_empty());
        assert!(pool.bidi_contexts.is_empty());

        let started = std::time::Instant::now();
        let rejected = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://after-kill-timeout.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        let elapsed = started.elapsed();
        let rejected: Value = serde_json::from_slice(&rejected.body)?;
        assert_eq!(rejected["type"], "error");
        assert!(
            elapsed < Duration::from_secs(5),
            "post-kill driver command re-blocked on abandoned engine client: took {elapsed:?}"
        );

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn http_create_session_cleans_context_when_initial_navigation_fails() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-failed".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-failed"));
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            connection.write_driver_response(
                goto.id,
                DriverResponse::Error {
                    error: DriverWireError::transport(&TransportError::NavTimeout),
                },
            )?;

            let close = connection.read_driver_request()?;
            assert_eq!(close.driver_id.as_deref(), Some("session-context-failed"));
            assert_eq!(close.command, HostDriverCommand::Close);
            connection.write_driver_response(close.id, DriverResponse::Closed)
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let create = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://fail.test"}"#.to_vec(),
            },
        );

        assert_eq!(create.status, 500);
        assert!(pool.list().is_empty());
        assert!(pool.session_drivers.is_empty());

        drop(pool);
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn session_pool_records_lifecycle_and_step_events() -> TestResult {
        let mut pool = SessionPool::default();
        let session = pool.create("https://events.test")?;
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
    fn session_pool_exports_recorded_steps_to_otlp_jsonl() -> TestResult {
        let root = unique_dir("pool-otlp")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("steps.jsonl");
        let mut pool = SessionPool::default().with_otlp_exporter(OtlpJsonExporter::new(&path));
        let session = pool.create("https://events.test")?;
        let step = sample_step_triple(11);

        let step_event = pool.record_step(&session.id, step.clone())?;

        let bytes = std::fs::read(&path)?;
        let value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap_or(&bytes))?;
        assert_eq!(value["resource"]["service.name"], "tempod");
        assert_eq!(value["name"], "tempo.step");
        assert_eq!(value["body"]["seq"], 11);
        assert_eq!(
            step_event.event,
            TempodSessionEventKind::StepTriple { triple: step }
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn session_pool_from_env_value_configures_otlp_jsonl_exporter() -> TestResult {
        let path = unique_dir("env-otlp")?.join("steps.jsonl");

        let mut pool = SessionPool::from_otlp_env_value(Some(path.as_os_str().to_os_string()));
        assert_eq!(
            pool.otlp_exporter()
                .ok_or("expected env path to configure exporter")?
                .path(),
            path.as_path()
        );

        pool.set_otlp_exporter(None);
        assert!(pool.otlp_exporter().is_none());
        assert!(SessionPool::from_otlp_env_value(None)
            .otlp_exporter()
            .is_none());
        assert!(
            SessionPool::from_otlp_env_value(Some(std::ffi::OsString::new()))
                .otlp_exporter()
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn otlp_json_exporter_writes_bare_file_path() -> TestResult {
        let unique = unique_dir("bare-otlp")?;
        let bare_path = PathBuf::from(
            unique
                .file_name()
                .ok_or("unique test path must have a file name")?,
        )
        .with_extension("jsonl");
        let _ = std::fs::remove_file(&bare_path);

        OtlpJsonExporter::new(&bare_path).export_step(&sample_step_triple(12))?;

        let bytes = std::fs::read(&bare_path)?;
        let value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap_or(&bytes))?;
        assert_eq!(value["body"]["seq"], 12);
        std::fs::remove_file(&bare_path)?;
        Ok(())
    }

    #[test]
    fn session_pool_records_drain_events_for_running_sessions() -> TestResult {
        let mut pool = SessionPool::default();
        let running = pool.create("https://running.test")?;
        let adopted = pool.create("https://adopted.test")?;
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
    fn session_pool_drain_rejects_new_sessions_and_bidi_sessions() -> TestResult {
        let mut pool = SessionPool::default();
        let running = pool.create("https://running.test")?;

        pool.drain();

        assert!(pool.draining());
        assert!(matches!(
            pool.create("https://late.test"),
            Err(TempodError::Draining)
        ));
        assert!(matches!(
            pool.adopt(&running.id),
            Err(TempodError::Draining)
        ));
        assert_eq!(pool.list()[0].id, running.id);
        assert_eq!(pool.list()[0].state, TempodSessionState::Killed);

        let status = route_http_request(
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
        let status: Value = serde_json::from_slice(&status.body)?;
        assert_eq!(status["result"]["ready"], false);

        let new_session = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"session.new","params":{}}"#.to_vec(),
            },
        )?;
        let new_session: Value = serde_json::from_slice(&new_session.body)?;
        assert_eq!(new_session["type"], "error");
        assert_eq!(new_session["error"], "session not created");
        Ok(())
    }

    #[test]
    fn http_adopt_session_returns_503_while_draining() -> TestResult {
        let mut pool = SessionPool::default();
        let session = pool.create("https://before-drain.test")?;
        pool.drain();

        let response = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: format!("/sessions/{}/adopt", session.id.0),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );

        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            value["error"],
            "tempod is draining; new sessions are not accepted"
        );
        assert_eq!(pool.list()[0].state, TempodSessionState::Killed);
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
        let session = pool.create("https://events.test")?;
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
    fn http_create_session_returns_503_while_draining_but_reads_still_work() -> TestResult {
        let mut pool = SessionPool::default();
        pool.create("https://before-drain.test")?;
        pool.drain();

        let health = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/health".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        assert_eq!(health.status, 200);

        let list = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        assert_eq!(list.status, 200);
        let sessions: Vec<TempodSession> = serde_json::from_slice(&list.body)?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].state, TempodSessionState::Killed);

        let create = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://after-drain.test"}"#.to_vec(),
            },
        );
        assert_eq!(create.status, 503);
        let value: Value = serde_json::from_slice(&create.body)?;
        assert_eq!(
            value["error"],
            "tempod is draining; new sessions are not accepted"
        );
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
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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
            br#"{"id":2,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://event.test","inputTainted":false}}"#,
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
    fn bidi_network_subscription_emits_navigation_network_events() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        });
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let subscribed = route_bidi_dispatch(
            &mut pool,
            br#"{"id":1,"method":"session.subscribe","params":{"events":["network"],"contexts":["tempo-root"]}}"#.to_vec(),
        );
        let subscribed_value: Value = serde_json::from_slice(&subscribed.response.body)?;
        assert_eq!(subscribed_value["type"], "success");
        assert!(subscribed.events.is_empty());

        let navigated = route_bidi_dispatch(
            &mut pool,
            br#"{"id":2,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://network-event.test","inputTainted":false}}"#.to_vec(),
        );
        let navigated_value: Value = serde_json::from_slice(&navigated.response.body)?;
        assert_eq!(navigated_value["type"], "success");
        assert_eq!(
            navigated_value["result"]["url"],
            "https://network-event.test"
        );

        assert_eq!(navigated.events.len(), 2);
        let before_request: Value = serde_json::to_value(&navigated.events[0])?;
        assert_eq!(before_request["type"], "event");
        assert_eq!(before_request["method"], "network.beforeRequestSent");
        assert_eq!(before_request["params"]["request"], "tempo-request-2");
        assert_eq!(
            before_request["params"]["url"],
            "https://network-event.test"
        );
        assert_eq!(before_request["params"]["method"], "GET");
        assert_eq!(before_request["params"]["bodySize"], 0);

        let response_completed: Value = serde_json::to_value(&navigated.events[1])?;
        assert_eq!(response_completed["type"], "event");
        assert_eq!(response_completed["method"], "network.responseCompleted");
        assert_eq!(response_completed["params"]["request"], "tempo-request-2");
        assert_eq!(
            response_completed["params"]["url"],
            "https://network-event.test"
        );
        assert_eq!(response_completed["params"]["status"], 200);
        assert_eq!(response_completed["params"]["bodySize"], 0);

        drop(pool);
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
                body: br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://example.test","inputTainted":false}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 7);
        Ok(())
    }

    #[test]
    fn bidi_endpoint_rejects_unknown_context_before_driver_execution() -> TestResult {
        let cases: &[(u64, &[u8])] = &[
            (
                21,
                br#"{"id":21,"method":"browsingContext.navigate","params":{"context":"missing","url":"https://example.test","inputTainted":false}}"#,
            ),
            (
                22,
                br#"{"id":22,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"missing"},"inputTainted":false}}"#,
            ),
            (
                23,
                br#"{"id":23,"method":"browsingContext.captureScreenshot","params":{"context":"missing"}}"#,
            ),
            (
                24,
                br#"{"id":24,"method":"browsingContext.getTree","params":{"root":"missing"}}"#,
            ),
            (
                25,
                br#"{"id":25,"method":"browsingContext.create","params":{"type":"tab","referenceContext":"missing"}}"#,
            ),
        ];

        for (id, body) in cases {
            assert_bidi_unknown_context_rejected(*id, body)?;
        }
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
                body: br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://example.test","inputTainted":false}}"#.to_vec(),
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
    fn bidi_endpoint_rejects_navigation_without_input_taint_evidence() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":21,"method":"browsingContext.navigate","params":{"context":"ctx","url":"https://example.test"}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 21);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("inputTainted/input_tainted is required"));
        assert_no_driver_ipc(&mut server_stream)?;
        Ok(())
    }

    #[test]
    fn bidi_endpoint_allows_confirmed_tainted_navigation_to_attached_engine_driver() -> TestResult {
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
                body: br#"{"id":17,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://example.test","inputTainted":true,"confirmed":true}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 17);
        assert_eq!(value["result"]["url"], "https://example.test");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_denies_unconfirmed_tainted_navigation_before_driver_execution() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":18,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://example.test","inputTainted":true}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 18);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("policy denied"));
        assert!(message.contains("input_tainted=true"));
        assert_no_driver_ipc(&mut server_stream)?;
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
                body: br#"{"id":8,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"tempo-root"},"awaitPromise":true,"inputTainted":false}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 8);
        assert_eq!(value["result"]["result"], "Tempo");
        assert_eq!(value["result"]["realm"], "tempo-root");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_rejects_script_without_input_taint_evidence() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":22,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"ctx"},"awaitPromise":true}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 22);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("inputTainted/input_tainted is required"));
        assert_no_driver_ipc(&mut server_stream)?;
        Ok(())
    }

    #[test]
    fn bidi_endpoint_allows_confirmed_tainted_script_to_attached_engine_driver() -> TestResult {
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
                body: br#"{"id":20,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"tempo-root"},"awaitPromise":true,"inputTainted":true,"confirmed":true}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 20);
        assert_eq!(value["result"]["result"], "Tempo");
        Ok(())
    }

    #[test]
    fn bidi_endpoint_denies_unconfirmed_tainted_script_before_driver_execution() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":19,"method":"script.evaluate","params":{"expression":"document.body.textContent='owned'","target":{"context":"tempo-root"},"input_tainted":true}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 19);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("policy denied"));
        assert!(message.contains("input_tainted=true"));
        assert_no_driver_ipc(&mut server_stream)?;
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

        let root_nav = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://root.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        let created = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"browsingContext.create","params":{"type":"tab"}}"#
                    .to_vec(),
            },
        )?;
        let created: Value = serde_json::from_slice(&created.body)?;
        let created_context = created["result"]["context"]
            .as_str()
            .ok_or("create result must include context")?
            .to_string();

        let initial_created_tree = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":3,"method":"browsingContext.getTree","params":{{"root":"{created_context}"}}}}"#
                )
                .into_bytes(),
            },
        )?;
        let context_nav = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":4,"method":"browsingContext.navigate","params":{{"context":"{created_context}","url":"https://context.test","inputTainted":false}}}}"#
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
                    br#"{"id":5,"method":"browsingContext.getTree","params":{"root":"tempo-root"}}"#
                        .to_vec(),
            },
        )?;
        let context_tree = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":6,"method":"browsingContext.getTree","params":{{"root":"{created_context}"}}}}"#
                )
                .into_bytes(),
            },
        )?;
        drop(pool);
        join_driver_handler(server)?;

        let root_nav: Value = serde_json::from_slice(&root_nav.body)?;
        let initial_created_tree: Value = serde_json::from_slice(&initial_created_tree.body)?;
        let context_nav: Value = serde_json::from_slice(&context_nav.body)?;
        let root_tree: Value = serde_json::from_slice(&root_tree.body)?;
        let context_tree: Value = serde_json::from_slice(&context_tree.body)?;

        assert_eq!(root_nav["type"], "success");
        assert_eq!(created["type"], "success");
        assert_eq!(created["result"]["context"], created_context);
        assert_eq!(
            initial_created_tree["result"]["contexts"][0]["url"],
            "about:blank"
        );
        assert_eq!(context_nav["type"], "success");
        assert_eq!(
            root_tree["result"]["contexts"][0]["url"],
            "https://root.test"
        );
        assert_eq!(
            context_tree["result"]["contexts"][0]["url"],
            "https://context.test"
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
    fn mcp_endpoint_routes_observe_diff_to_attached_engine_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.driver_id, None);
            assert_eq!(
                request.command,
                HostDriverCommand::ObserveDiff { since_seq: 7 }
            );
            DriverResponse::Diff {
                diff: ObservationDiff {
                    since_seq: 7,
                    seq: 9,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                },
            }
        })?;

        let response = route_http_request(
            &mut pool,
            mcp_tool_request(14, "observe_diff", json!({"since_seq": 7}))?,
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["id"], 14);
        assert_eq!(value["result"]["structuredContent"]["since_seq"], 7);
        assert_eq!(value["result"]["structuredContent"]["seq"], 9);
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
                    },
                    "input_tainted": false
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
    fn mcp_endpoint_rejects_act_without_input_taint_evidence() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            mcp_tool_request(
                13,
                "act",
                json!({"action": {"kind": "scroll", "x": 0.0, "y": 8.0}}),
            )?,
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["id"], 13);
        assert_eq!(value["error"]["code"], -32602);
        let message = value["error"]["message"]
            .as_str()
            .ok_or("error response should include a message")?;
        assert!(message.contains("input_tainted is required"));

        let mut byte = [0_u8; 1];
        match server_stream.read(&mut byte) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(bytes) => return Err(format!("invalid act dispatched {bytes} IPC bytes").into()),
            Err(error) => return Err(error.into()),
        }
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
                    "input_tainted": false
                }),
            )?,
        )?;
        let root_response =
            route_http_request(&mut pool, mcp_tool_request(3, "observe", json!({}))?)?;
        let fork_response = route_http_request(
            &mut pool,
            mcp_tool_request(4, "observe", json!({"driver_id": driver_id.clone()}))?,
        )?;
        let fork_diff_response = route_http_request(
            &mut pool,
            mcp_tool_request(
                5,
                "observe_diff",
                json!({"driver_id": driver_id, "since_seq": 0}),
            )?,
        )?;

        drop(pool);
        join_driver_handler(server)?;

        assert_eq!(act_response.status, 200);
        let act: Value = serde_json::from_slice(&act_response.body)?;
        assert_eq!(act["result"]["structuredContent"]["status"], "applied");

        let root: Value = serde_json::from_slice(&root_response.body)?;
        let fork: Value = serde_json::from_slice(&fork_response.body)?;
        let fork_diff: Value = serde_json::from_slice(&fork_diff_response.body)?;
        assert_eq!(root["result"]["structuredContent"]["seq"], 0);
        assert_eq!(fork["result"]["structuredContent"]["seq"], 1);
        assert_eq!(fork_diff["result"]["structuredContent"]["since_seq"], 0);
        assert_eq!(fork_diff["result"]["structuredContent"]["seq"], 1);
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

        async fn create_browsing_context(
            &mut self,
            options: BrowsingContextCreateOptions,
        ) -> Result<Box<dyn DriverTrait>, Unsupported> {
            let created_inner = self.inner.create_browsing_context(options).await?;
            Ok(Box::new(CloseCountingDriver {
                inner: created_inner,
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
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = CloseCountingDriver::new(engine_closes);
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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
            4,
            "every live fork and the root driver must be closed at explicit detach"
        );
        Ok(())
    }

    #[test]
    fn dropping_pool_closes_live_forks() -> TestResult {
        // Drop must run the same teardown as `detach_engine_driver`, so a pool
        // that is simply dropped (normal daemon shutdown, no explicit detach)
        // still closes its live engine forks instead of leaking them.
        let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine_closes = Arc::clone(&closes);
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = CloseCountingDriver::new(engine_closes);
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        for id in 0..3 {
            let response = route_http_request(&mut pool, mcp_tool_request(id, "fork", json!({}))?)?;
            let fork: Value = serde_json::from_slice(&response.body)?;
            assert!(
                fork["result"]["structuredContent"]["driver_id"].is_string(),
                "fork {id} did not return a driver_id: {fork}"
            );
        }

        // No explicit detach: rely solely on `Drop` to close the forks.
        drop(pool);
        join_driver_handler(server)?;
        assert_eq!(
            closes.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "dropping the pool must close every live fork"
        );
        Ok(())
    }

    #[test]
    fn drain_closes_engine_resources_and_blocks_driver_work() -> TestResult {
        let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine_closes = Arc::clone(&closes);
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = CloseCountingDriver::new(engine_closes);
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let mcp_fork = route_http_request(&mut pool, mcp_tool_request(1, "fork", json!({}))?)?;
        let mcp_fork: Value = serde_json::from_slice(&mcp_fork.body)?;
        assert!(mcp_fork["result"]["structuredContent"]["driver_id"].is_string());

        let bidi_create = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"browsingContext.create","params":{"type":"tab"}}"#
                    .to_vec(),
            },
        )?;
        let bidi_create: Value = serde_json::from_slice(&bidi_create.body)?;
        assert_eq!(bidi_create["type"], "success");
        assert_eq!(pool.bidi_contexts.len(), 2);

        pool.drain();

        assert!(pool.draining());
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());
        assert!(pool.bidi_contexts.is_empty());
        join_driver_handler(server)?;
        assert_eq!(
            closes.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "drain must close MCP forks, BiDi forks, and the root driver"
        );

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":3,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://after-drain.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            value["message"],
            "tempod is draining; BiDi driver commands are not accepted"
        );

        let mcp_response = route_http_request(
            &mut pool,
            mcp_tool_request(4, "observe", json!({"driver_id": "late"}))?,
        )?;
        assert_eq!(mcp_response.status, 503);
        let value: Value = serde_json::from_slice(&mcp_response.body)?;
        assert_eq!(
            value["error"],
            "tempod is draining; MCP tool calls are not accepted"
        );
        Ok(())
    }

    #[test]
    fn close_root_driver_does_not_hang_on_wedged_engine() -> TestResult {
        // #200 regression guard. Teardown closes the root driver via a blocking
        // engine-IPC `Close` round-trip while the caller holds the global pool
        // `Mutex`. A wedged engine child that never answers `Close` must NOT hang
        // the daemon (which would block every request, including `GET /health`).
        //
        // The server end of the IPC connection here is held open but never
        // replies, and the test-side client stream carries no read timeout, so
        // the `Close` read blocks indefinitely. Against the pre-fix
        // `close_root_driver` (a bare `block_on(driver.close())`) this call would
        // block forever and the test itself would hang. The bounded close must
        // return within its timeout and leave the root driver detached.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || {
            // Keep the server end open (so the client read blocks rather than
            // seeing EOF) but never respond, then wait to be released.
            let _held = server_stream;
            thread::park_timeout(Duration::from_secs(60));
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        assert!(pool.driver.is_some());

        let started = std::time::Instant::now();
        pool.bounded_engine_teardown(true, Duration::from_millis(200));
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(10),
            "bounded root-driver close hung on a wedged engine: took {elapsed:?}"
        );
        assert!(
            pool.driver.is_none(),
            "root driver must be detached even when its Close is abandoned"
        );

        // Release the wedged server end so its (and the abandoned close) thread
        // observe EOF and exit instead of parking for the full timeout.
        wedged_engine.thread().unpark();
        Ok(())
    }

    #[test]
    fn drain_does_not_hang_on_wedged_bidi_fork() -> TestResult {
        // Public #200 regression guard: `drain()` must not hang when a forked
        // BiDi context wedges on `Close`.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || {
            let _held = server_stream;
            thread::park_timeout(Duration::from_secs(60));
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let driver = pool.driver.as_ref().ok_or("attached root driver missing")?;
        pool.bidi_contexts.insert(
            BrowsingContextId("wedged-bidi-fork".into()),
            AttachedEngineDriver {
                engine: Engine::Cdp,
                client: Arc::clone(&driver.client),
                driver_id: Some("fork-1".into()),
            },
        );

        let started = std::time::Instant::now();
        pool.drain();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "drain hung on a wedged BiDi fork before bounded teardown returned: took {elapsed:?}"
        );
        assert!(pool.draining());
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());
        assert!(pool.bidi_contexts.is_empty());

        wedged_engine.thread().unpark();
        wedged_engine
            .join()
            .map_err(|_| "wedged engine thread failed")?;
        Ok(())
    }

    #[test]
    fn drain_does_not_hang_on_wedged_mcp_fork() -> TestResult {
        // Public #200 regression guard: `drain()` must bound MCP fork cleanup,
        // not only the root-driver close.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let fork_request = connection.read_driver_request()?;
            assert!(fork_request.driver_id.is_none());
            assert!(matches!(fork_request.command, HostDriverCommand::Fork));
            connection.write_driver_response(
                fork_request.id,
                DriverResponse::Forked {
                    driver_id: "fork-1".into(),
                },
            )?;

            let close_request = connection.read_driver_request()?;
            assert_eq!(close_request.driver_id.as_deref(), Some("fork-1"));
            assert!(matches!(close_request.command, HostDriverCommand::Close));
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let fork_response = route_http_request(&mut pool, mcp_tool_request(1, "fork", json!({}))?)?;
        let fork: Value = serde_json::from_slice(&fork_response.body)?;
        assert!(
            fork["result"]["structuredContent"]["driver_id"].is_string(),
            "fork did not return a driver_id: {fork}"
        );

        let started = std::time::Instant::now();
        pool.drain();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "drain hung on a wedged MCP fork before bounded teardown returned: took {elapsed:?}"
        );
        assert!(pool.draining());
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());
        assert!(pool.bidi_contexts.is_empty());

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn drain_does_not_hang_on_wedged_session_context() -> TestResult {
        // Public #200 regression guard for session-owned engine contexts added
        // to tempod session creation. `drain()` must bound these closes too.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(create.driver_id.is_none());
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-1".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-1"));
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            connection.write_driver_response(
                goto.id,
                DriverResponse::Observation {
                    observation: observation("https://session.test", 1),
                },
            )?;

            let close = connection.read_driver_request()?;
            assert_eq!(close.driver_id.as_deref(), Some("session-context-1"));
            assert_eq!(close.command, HostDriverCommand::Close);
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let create = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://session.test"}"#.to_vec(),
            },
        )?;

        assert_eq!(create.status, 201);
        assert_eq!(pool.session_drivers.len(), 1);

        let started = std::time::Instant::now();
        pool.drain();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "drain hung on a wedged session context before bounded teardown returned: took {elapsed:?}"
        );
        assert!(pool.draining());
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());
        assert!(pool.bidi_contexts.is_empty());
        assert!(pool.session_drivers.is_empty());

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn teardown_does_not_hang_on_wedged_forked_context() -> TestResult {
        // Detach path coverage for the same #200 forked-context hang.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || {
            let _held = server_stream;
            thread::park_timeout(Duration::from_secs(60));
        });

        let mut pool = SessionPool::default();
        pool.bidi_contexts.insert(
            BrowsingContextId("tempo-bidi-wedged".to_string()),
            AttachedEngineDriver {
                engine: Engine::Cdp,
                client: Arc::new(Mutex::new(EngineIpcClient::from_stream(client_stream))),
                driver_id: Some("context-wedged".to_string()),
            },
        );
        pool.next_bidi_context_id = 2;

        let started = std::time::Instant::now();
        pool.detach_engine_driver();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "teardown hung on a wedged forked context: took {elapsed:?}"
        );
        assert!(pool.bidi_contexts.is_empty());
        assert!(pool.mcp.is_none());
        assert!(pool.driver.is_none());

        wedged_engine.thread().unpark();
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
    fn otlp_export_failure_does_not_break_record_step() -> TestResult {
        // Issue #214 (weakness 1): point the exporter at an existing directory so
        // the append-open fails; record_step must still succeed (best-effort).
        let dir = unique_dir("otlp-export-fail")?;
        remove_dir_if_exists(&dir)?;
        std::fs::create_dir_all(&dir)?;
        let mut pool = SessionPool::default().with_otlp_exporter(OtlpJsonExporter::new(&dir));
        let session = pool.create("https://fail.test")?;

        let result = pool.record_step(&session.id, sample_step_triple(1));
        assert!(
            result.is_ok(),
            "record_step must survive a telemetry export error"
        );

        // The step event is still recorded despite the export failure.
        let events = pool.events(&session.id, None)?;
        assert!(events
            .iter()
            .any(|event| matches!(event.event, TempodSessionEventKind::StepTriple { .. })));

        remove_dir_if_exists(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn otlp_export_file_has_owner_only_permissions() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        // Issue #214 (weakness 3): the telemetry file must not be world-readable.
        let root = unique_dir("otlp-perms")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("steps.jsonl");
        OtlpJsonExporter::new(&path).export_step(&sample_step_triple(3))?;

        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export file must be created with 0600 perms");

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn otlp_export_redacts_secrets_from_action() -> TestResult {
        // Issue #214 (weakness 3): typed text and URL query strings must never be
        // written verbatim, while non-sensitive fields remain for telemetry.
        let root = unique_dir("otlp-redact")?;
        remove_dir_if_exists(&root)?;

        let typed_path = root.join("typed.jsonl");
        let secret = "hunter2-super-secret-password";
        let typed = StepTriple {
            key: IdempotencyKey("step-type".into()),
            seq: 5,
            action: Action::Type {
                node: NodeId("login-password".into()),
                text: secret.into(),
            },
            outcome: StepTripleOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: 4,
                    seq: 5,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
        };
        OtlpJsonExporter::new(&typed_path).export_step(&typed)?;
        let typed_text = String::from_utf8(std::fs::read(&typed_path)?)?;
        assert!(
            !typed_text.contains(secret),
            "raw typed secret must not be written verbatim"
        );
        assert!(typed_text.contains("sha256:"), "typed text must be hashed");
        let typed_value: Value = serde_json::from_str(typed_text.trim_end())?;
        assert_eq!(typed_value["body"]["action"]["kind"], "type");
        assert_eq!(typed_value["body"]["action"]["node"], "login-password");
        assert_eq!(typed_value["body"]["seq"], 5);

        let goto_path = root.join("goto.jsonl");
        let goto = StepTriple {
            key: IdempotencyKey("step-goto".into()),
            seq: 6,
            action: Action::Goto {
                url: "https://ex.test/login?token=SECRETQUERY123".into(),
            },
            outcome: StepTripleOutcome::StepError {
                reason: "boom".into(),
            },
        };
        OtlpJsonExporter::new(&goto_path).export_step(&goto)?;
        let goto_text = String::from_utf8(std::fs::read(&goto_path)?)?;
        assert!(
            !goto_text.contains("SECRETQUERY123"),
            "URL query secret must be stripped"
        );
        let goto_value: Value = serde_json::from_str(goto_text.trim_end())?;
        assert_eq!(goto_value["body"]["action"]["url"], "https://ex.test/login");
        assert_eq!(goto_value["body"]["action"]["kind"], "goto");

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn otlp_export_redacts_secrets_from_step_error_reason() -> TestResult {
        // Issue #214 (review follow-up): a StepError reason is free-form and can
        // echo remote/secret content (e.g. a failed navigation URL carrying a
        // token). It must be hashed, not written verbatim.
        let root = unique_dir("otlp-redact-reason")?;
        remove_dir_if_exists(&root)?;

        let path = root.join("step-error.jsonl");
        let reason = "navigation failed: https://ex.test/login?token=SECRET123 refused";
        let triple = StepTriple {
            key: IdempotencyKey("step-error".into()),
            seq: 7,
            action: Action::Click {
                node: NodeId("submit".into()),
            },
            outcome: StepTripleOutcome::StepError {
                reason: reason.into(),
            },
        };
        OtlpJsonExporter::new(&path).export_step(&triple)?;
        let text = String::from_utf8(std::fs::read(&path)?)?;
        assert!(
            !text.contains("SECRET123"),
            "raw token in StepError reason must not be written verbatim"
        );
        assert!(
            !text.contains("token=SECRET123"),
            "URL query secret in StepError reason must not leak"
        );
        assert!(text.contains("sha256:"), "StepError reason must be hashed");
        let value: Value = serde_json::from_str(text.trim_end())?;
        assert_eq!(value["body"]["outcome"]["kind"], "step_error");
        assert_eq!(
            value["body"]["outcome"]["reason"],
            Value::String(hash_secret(reason))
        );

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

    fn control_request(method: &str, path: &str, origin: Option<&str>, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: BTreeMap::new(),
            host: None,
            origin: origin.map(str::to_string),
            body: body.to_vec(),
        }
    }

    #[test]
    fn control_routes_reject_cross_origin_requests() -> TestResult {
        // #83 follow-up: session/control-plane routes must share the loopback
        // Origin guard so a DNS-rebinding page cannot create/drive sessions.
        let create_body = br#"{"url":"https://example.test"}"#;

        // Cross-origin POST /sessions is blocked before the handler runs (no
        // session is created).
        let mut pool = SessionPool::default();
        let blocked = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                "/sessions",
                Some("http://evil.example"),
                create_body,
            ),
        );
        assert_eq!(blocked.status, 403);
        assert!(
            pool.list().is_empty(),
            "cross-origin request must not create a session"
        );

        // A second, non-idempotent route is likewise blocked.
        let blocked_drain = handle_http_request(
            &mut pool,
            control_request("POST", "/drain", Some("http://evil.example"), b""),
        );
        assert_eq!(blocked_drain.status, 403);
        assert!(
            !pool.draining(),
            "cross-origin /drain must not drain the pool"
        );

        // GET /sessions (observes state) is also guarded.
        let blocked_list = handle_http_request(
            &mut pool,
            control_request("GET", "/sessions", Some("http://evil.example"), b""),
        );
        assert_eq!(blocked_list.status, 403);

        // No Origin header (non-browser/CLI client) still reaches the handler.
        let no_origin = handle_http_request(
            &mut pool,
            control_request("POST", "/sessions", None, create_body),
        );
        assert_eq!(no_origin.status, 201);

        // A loopback Origin is accepted.
        let loopback = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                "/sessions",
                Some("http://127.0.0.1:8787"),
                create_body,
            ),
        );
        assert_eq!(loopback.status, 201);
        Ok(())
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
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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
    fn bidi_close_does_not_hang_on_wedged_forked_context() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || {
            let _held = server_stream;
            thread::park_timeout(Duration::from_secs(60));
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let started = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"session.new","params":{}}"#.to_vec(),
            },
        )?;
        let started: Value = serde_json::from_slice(&started.body)?;
        assert_eq!(started["type"], "success");

        let driver = pool.driver.as_ref().ok_or("attached root driver missing")?;
        let context = BrowsingContextId("wedged-bidi-close-fork".into());
        pool.bidi_contexts.insert(
            context.clone(),
            AttachedEngineDriver {
                engine: Engine::Cdp,
                client: Arc::clone(&driver.client),
                driver_id: Some("fork-1".into()),
            },
        );

        let started = std::time::Instant::now();
        let closed = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: format!(
                    r#"{{"id":2,"method":"browsingContext.close","params":{{"context":"{}"}}}}"#,
                    context.0
                )
                .into_bytes(),
            },
        )?;
        let elapsed = started.elapsed();

        let closed: Value = serde_json::from_slice(&closed.body)?;
        assert_eq!(closed["type"], "success");
        assert!(
            elapsed < Duration::from_secs(5),
            "browsingContext.close hung on a wedged forked context: took {elapsed:?}"
        );
        assert!(pool.bidi_contexts.is_empty());
        assert!(pool.driver.is_none());
        assert!(pool.mcp.is_none());

        let started = std::time::Instant::now();
        let rejected = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":3,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://after-close-timeout.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        let elapsed = started.elapsed();
        let rejected: Value = serde_json::from_slice(&rejected.body)?;
        assert_eq!(rejected["type"], "error");
        assert!(
            elapsed < Duration::from_secs(5),
            "post-close driver command re-blocked on abandoned engine client: took {elapsed:?}"
        );

        wedged_engine.thread().unpark();
        wedged_engine
            .join()
            .map_err(|_| "wedged engine thread failed")?;
        Ok(())
    }

    #[test]
    fn bidi_session_end_closes_forked_contexts_and_rejects_driver_work() -> TestResult {
        let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine_closes = Arc::clone(&closes);
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = CloseCountingDriver::new(engine_closes);
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
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
        assert_eq!(created["type"], "success");
        assert_eq!(pool.bidi_contexts.len(), 2);

        let ended = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"session.end","params":{}}"#.to_vec(),
            },
        )?;
        let ended: Value = serde_json::from_slice(&ended.body)?;
        assert_eq!(ended["type"], "success");
        assert!(pool.bidi_contexts.is_empty());
        assert_eq!(
            closes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "session.end must close the forked engine context"
        );

        let rejected = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":3,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://after-end.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        let rejected: Value = serde_json::from_slice(&rejected.body)?;
        assert_eq!(rejected["type"], "error");
        assert_eq!(rejected["id"], 3);
        assert_eq!(rejected["message"], "BiDi session has ended");
        assert_eq!(
            closes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "rejected post-end command must not reach engine IPC"
        );

        let restarted = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":4,"method":"session.new","params":{}}"#.to_vec(),
            },
        )?;
        let restarted: Value = serde_json::from_slice(&restarted.body)?;
        assert_eq!(restarted["type"], "success");
        assert_eq!(pool.bidi_contexts.len(), 1);
        assert!(pool.bidi_contexts.contains_key(&default_context_id()));

        drop(pool);
        join_driver_handler(server)?;
        Ok(())
    }

    #[test]
    fn bidi_session_end_does_not_hang_on_wedged_forked_context() -> TestResult {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || {
            let _held = server_stream;
            thread::park_timeout(Duration::from_secs(60));
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        let started = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":1,"method":"session.new","params":{}}"#.to_vec(),
            },
        )?;
        let started: Value = serde_json::from_slice(&started.body)?;
        assert_eq!(started["type"], "success");

        let driver = pool.driver.as_ref().ok_or("attached root driver missing")?;
        pool.bidi_contexts.insert(
            BrowsingContextId("wedged-bidi-session-fork".into()),
            AttachedEngineDriver {
                engine: Engine::Cdp,
                client: Arc::clone(&driver.client),
                driver_id: Some("fork-1".into()),
            },
        );

        let started = std::time::Instant::now();
        let ended = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":2,"method":"session.end","params":{}}"#.to_vec(),
            },
        )?;
        let elapsed = started.elapsed();

        let ended: Value = serde_json::from_slice(&ended.body)?;
        assert_eq!(ended["type"], "success");
        assert!(
            elapsed < Duration::from_secs(5),
            "session.end hung on a wedged forked context before bounded teardown returned: took {elapsed:?}"
        );
        assert!(pool.bidi_contexts.is_empty());
        assert!(
            pool.driver.is_none(),
            "timed-out fork close must detach the shared engine client"
        );
        assert!(pool.mcp.is_none());
        assert!(pool.session_drivers.is_empty());

        let restarted = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":3,"method":"session.new","params":{}}"#.to_vec(),
            },
        )?;
        let restarted: Value = serde_json::from_slice(&restarted.body)?;
        assert_eq!(restarted["type"], "success");

        let started = std::time::Instant::now();
        let rejected = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"id":4,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://after-timeout.test","inputTainted":false}}"#.to_vec(),
            },
        )?;
        let elapsed = started.elapsed();
        let rejected: Value = serde_json::from_slice(&rejected.body)?;
        assert_eq!(rejected["type"], "error");
        assert!(
            elapsed < Duration::from_secs(5),
            "post-timeout driver command re-blocked on abandoned engine client: took {elapsed:?}"
        );

        wedged_engine.thread().unpark();
        wedged_engine
            .join()
            .map_err(|_| "wedged engine thread failed")?;
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

    fn assert_no_driver_ipc(stream: &mut UnixStream) -> Result<(), Box<dyn Error>> {
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Ok(bytes) => Err(format!("invalid BiDi command dispatched {bytes} IPC bytes").into()),
            Err(error) => Err(error.into()),
        }
    }

    fn assert_bidi_unknown_context_rejected(id: u64, body: &[u8]) -> Result<(), Box<dyn Error>> {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: body.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], id);
        assert_eq!(value["error"], "invalid argument");
        assert_eq!(value["message"], "unknown browsing context");
        assert_no_driver_ipc(&mut server_stream)?;
        Ok(())
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
