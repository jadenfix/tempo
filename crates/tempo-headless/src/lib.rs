//! tempo-headless — headless `tempod` control plane.
//!
//! The daemon owns session lifecycle, engine-host supervision, graceful drain,
//! and JSONL export for StepTriples. The HTTP layer here is intentionally small:
//! it uses the standard library so the control surface works before a larger web
//! framework is selected for production packaging.

#![recursion_limit = "256"]

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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
    output_cap_message, BrowsingContextCreateOptions, BrowsingContextKind, DriverTrait, Engine,
    StepOutcome, TransportError, Unsupported, MAX_PROTOCOL_RESPONSE_BYTES, MAX_SCREENSHOT_BYTES,
};
use tempo_engine_host::{
    DriverCommand as HostDriverCommand, DriverResponse, DriverWireError, EngineHost,
    EngineHostConfig, EngineHostError, EngineIpcClient, SharedEngineIpcClient,
};
use tempo_net::UrlPolicy;
use tempo_policy::{decide_action, decide_effect, ConfirmationGate, InputTaint, PolicyDecision};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff, SideEffect};
use thiserror::Error;
use url::Url;

const MAX_HTTP_BYTES: usize = 64 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_SESSION_IDEMPOTENCY_RECORDS: usize = 1024;
const MAX_WS_PAYLOAD_BYTES: u64 = MAX_HTTP_BYTES as u64;
/// Maximum accepted TCP control-plane connections handled concurrently.
const MAX_HTTP_CONNECTIONS: usize = 128;
/// Maximum upgraded BiDi WebSocket sessions held concurrently.
const MAX_WEBSOCKET_CONNECTIONS: usize = 32;
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
/// Upper bound on how long a session create waits for the attached engine to
/// create a session browsing context AND navigate it to the session URL before
/// giving up. The create+goto (and the failure-path `Close`) run on a detached
/// worker thread awaited with one `recv_timeout`; on timeout the worker owns
/// and abandons the wedged work while create returns a `TempodError`, so the
/// daemon stays available (#213/#217). The bound is 2x `ENGINE_IPC_TIMEOUT`
/// plus a small margin so a genuinely slow-but-valid navigation the engine
/// still answers within its own per-round-trip IPC budget is never cut off;
/// only the pathological never-answers case is capped.
///
/// Since issue #230 the HTTP create path (`create_session_shared`) runs this
/// whole window with the pool lock RELEASED — the #213 residual (lock held for
/// up to the bound) is gone — and only re-locks briefly to publish the session.
/// The bound still matters: it is what caps a single create attempt end to end.
#[cfg(not(test))]
const SESSION_CREATE_TIMEOUT: Duration = Duration::from_secs(65);
#[cfg(test)]
const SESSION_CREATE_TIMEOUT: Duration = Duration::from_millis(200);
const WS_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_OPCODE_TEXT: u8 = 0x1;
const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;
const HTTP_CONNECTION_LIMIT_MESSAGE: &str = "too many active tempod HTTP connections";
const WEBSOCKET_CONNECTION_LIMIT_MESSAGE: &str = "too many active tempod WebSocket connections";
pub const TEMPO_OTLP_JSONL_ENV: &str = "TEMPO_OTLP_JSONL";
pub const TEMPO_TEMPOD_AUTH_TOKEN_ENV: &str = "TEMPO_TEMPOD_AUTH_TOKEN";
pub const TEMPO_STEALTH_MODE_ENV: &str = "TEMPO_STEALTH_MODE";
/// Machine-readable REST contract used as the source of truth for generated SDKs.
pub const TEMPOD_OPENAPI_PATH: &str = "/openapi.json";
const TEMPOD_OPENAPI_CONTENT_TYPE: &str = "application/vnd.oai.openapi+json;version=3.1";
/// Constant marker written in place of any secret-bearing field in OTLP
/// telemetry (issue #214 review). A constant — never a hash, length, or prefix
/// of the secret — so low-entropy secrets (PINs, OTPs, common passwords/tokens)
/// cannot be recovered by an offline dictionary search of the exported value.
const REDACTED_MARKER: &str = "[redacted]";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempodAuth {
    bearer_token: Option<String>,
}

impl TempodAuth {
    pub fn disabled() -> Self {
        Self { bearer_token: None }
    }

    pub fn bearer(token: impl Into<String>) -> Result<Self, TempodError> {
        let token = token.into();
        validate_bearer_token(&token)?;
        Ok(Self {
            bearer_token: Some(token),
        })
    }

    pub fn is_required(&self) -> bool {
        self.bearer_token.is_some()
    }

    fn authorize(&self, request: &HttpRequest) -> Result<(), TempodError> {
        let Some(expected) = &self.bearer_token else {
            return Ok(());
        };
        let Some(header) = request.header("authorization") else {
            return Err(TempodError::Unauthorized("missing bearer token".into()));
        };
        let Some(actual) = authorization_bearer_token(header) else {
            return Err(TempodError::Unauthorized("invalid bearer token".into()));
        };
        if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(TempodError::Unauthorized("invalid bearer token".into()))
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempodServerConfig {
    allow_remote_binds: bool,
    auth: TempodAuth,
}

impl TempodServerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_remote_binds(mut self) -> Self {
        self.allow_remote_binds = true;
        self
    }

    pub fn with_auth(mut self, auth: TempodAuth) -> Self {
        self.auth = auth;
        self
    }

    fn validate_bind_addr(&self, addr: &str) -> Result<(), TempodError> {
        if bind_addr_is_loopback(addr)? {
            return Ok(());
        }
        if self.allow_remote_binds && self.auth.is_required() {
            return Ok(());
        }
        Err(TempodError::BadRequest(format!(
            "non-loopback tempod bind {addr:?} requires --allow-remote and {TEMPO_TEMPOD_AUTH_TOKEN_ENV} or --auth-token"
        )))
    }

    fn validate_listener(&self, listener: &TcpListener) -> Result<(), TempodError> {
        let addr = listener.local_addr()?;
        if addr.ip().is_loopback() {
            return Ok(());
        }
        if self.allow_remote_binds && self.auth.is_required() {
            return Ok(());
        }
        Err(TempodError::BadRequest(format!(
            "non-loopback tempod listener {addr:?} requires allow_remote_binds() and TempodAuth::bearer(...)"
        )))
    }
}

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

/// Controls intentional local history retention for the headless control plane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrivacyMode {
    /// Keep in-memory per-session events and allow opt-in OTLP export.
    #[default]
    Audit,
    /// Do not retain per-session events, ignore OTLP export, and purge terminal
    /// sessions from the in-memory pool.
    Stealth,
}

impl PrivacyMode {
    fn from_env_value(value: Option<std::ffi::OsString>) -> Self {
        let Some(value) = value else {
            return Self::Audit;
        };
        let value = value.to_string_lossy();
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "stealth"
        ) {
            Self::Stealth
        } else {
            Self::Audit
        }
    }

    const fn retains_history(self) -> bool {
        matches!(self, Self::Audit)
    }

    const fn retains_idempotency_cache(self) -> bool {
        matches!(self, Self::Audit)
    }
}

/// Per-driver (per browsing context / fork / root) operation gate.
///
/// Serializes engine round-trips issued through clones of the SAME driver
/// handle so per-session ordering is preserved, while distinct drivers —
/// distinct sessions/contexts — proceed fully in parallel over the shared,
/// multiplexed engine connection (issue #230). Acquisition is bounded: a
/// waiter gives up after the timeout instead of queueing indefinitely, and
/// every hold is itself bounded by the engine IPC timeout, so waits always
/// terminate.
#[derive(Default)]
struct OpGate {
    busy: Mutex<bool>,
    released: Condvar,
}

impl OpGate {
    fn acquire(self: &Arc<Self>, timeout: Duration) -> Option<OpGateGuard> {
        let deadline = std::time::Instant::now().checked_add(timeout);
        // Poisoning is recovered (`into_inner`): the guarded state is one bool
        // whose invariant cannot be broken mid-panic, and treating poison as
        // fatal would wedge every later operation on this driver behind a
        // one-off panic (#305 review nit).
        let mut busy = self
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if !*busy {
                *busy = true;
                return Some(OpGateGuard {
                    gate: Arc::clone(self),
                });
            }
            let remaining = deadline
                .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()))?;
            busy = match self.released.wait_timeout(busy, remaining) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }
}

struct OpGateGuard {
    gate: Arc<OpGate>,
}

impl Drop for OpGateGuard {
    fn drop(&mut self) {
        *self
            .gate
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        self.gate.released.notify_one();
    }
}

/// Driver handle attached to tempod through the engine-host UDS protocol.
///
/// Clones share the multiplexed engine connection AND the per-driver [`OpGate`]:
/// round-trips through clones of one handle stay ordered, while handles for
/// different engine-side drivers (`driver_id`s) run concurrently (issue #230).
#[derive(Clone)]
pub struct AttachedEngineDriver {
    engine: Engine,
    client: SharedEngineIpcClient,
    driver_id: Option<String>,
    url_policy: UrlPolicy,
    gate: Arc<OpGate>,
}

impl AttachedEngineDriver {
    pub fn new(engine: Engine, client: EngineIpcClient) -> Result<Self, TempodError> {
        let client = SharedEngineIpcClient::from_client(client)
            .map_err(|error| TempodError::Driver(format!("engine IPC setup failed: {error}")))?;
        Ok(Self {
            engine,
            client,
            driver_id: None,
            #[cfg(not(test))]
            url_policy: UrlPolicy::block_private(),
            #[cfg(test)]
            url_policy: UrlPolicy::allow_all(),
            gate: Arc::new(OpGate::default()),
        })
    }

    pub fn with_navigation_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    fn request(&self, command: HostDriverCommand) -> Result<DriverResponse, DriverClientError> {
        // Same-driver ordering: hold this driver's gate for the round-trip.
        // The gate wait and the round-trip itself are both bounded, and no
        // other lock (pool, MCP, or another session's gate) is held here.
        let _gate = self
            .gate
            .acquire(ENGINE_IPC_TIMEOUT)
            .ok_or(DriverClientError::Busy)?;
        Ok(self
            .client
            .request_for(self.driver_id.as_deref(), command, ENGINE_IPC_TIMEOUT)?)
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

    /// New handle for a newly-created engine-side driver: shares the
    /// connection, but gets its OWN operation gate so it never serializes
    /// against its parent or siblings.
    fn derived(&self, driver_id: String) -> Self {
        Self {
            engine: self.engine,
            client: self.client.clone(),
            driver_id: Some(driver_id),
            url_policy: self.url_policy.clone(),
            gate: Arc::new(OpGate::default()),
        }
    }

    async fn fork_attached(&mut self) -> Result<Self, Unsupported> {
        match self.request(HostDriverCommand::Fork) {
            Ok(DriverResponse::Forked { driver_id }) => Ok(self.derived(driver_id)),
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
            Ok(DriverResponse::BrowsingContextCreated { driver_id }) => Ok(self.derived(driver_id)),
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
            .field("url_policy", &self.url_policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DriverTrait for AttachedEngineDriver {
    fn engine(&self) -> Engine {
        self.engine
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        enforce_tempod_navigation_url_transport(&self.url_policy, url)?;
        self.request_observation(HostDriverCommand::Goto { url: url.into() }, "goto")
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        self.request_observation(HostDriverCommand::Observe, "observe")
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        self.request_diff(HostDriverCommand::ObserveDiff { since_seq }, "observe_diff")
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        enforce_action_navigation_url_policy(&self.url_policy, action)?;
        self.request_step(
            HostDriverCommand::Act {
                action: action.clone(),
            },
            "act",
        )
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        enforce_batch_navigation_url_policy_transport(&self.url_policy, batch)?;
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
    #[error(
        "engine driver is busy: another operation on this session/context did not finish in time"
    )]
    Busy,
    #[error("engine host failed: {0}")]
    Host(#[from] EngineHostError),
}

/// In-memory session pool for a tempod process.
#[derive(Clone)]
pub struct SessionPool {
    sessions: BTreeMap<TempodSessionId, TempodSession>,
    session_drivers: BTreeMap<TempodSessionId, AttachedEngineDriver>,
    session_act_batch_idempotency:
        BTreeMap<(TempodSessionId, String), SessionActBatchIdempotencyEntry>,
    events: BTreeMap<TempodSessionId, Vec<TempodSessionEvent>>,
    otlp_exporter: Option<OtlpJsonExporter>,
    privacy_mode: PrivacyMode,
    bidi: BidiRouter,
    driver: Option<AttachedEngineDriver>,
    /// One MCP server for the attached engine. No outer `Mutex`: the server
    /// itself runs concurrent tool calls on distinct drivers and serializes
    /// same-driver calls internally (issue #230), so tool calls on different
    /// sessions no longer queue behind a process-wide MCP lock.
    mcp: Option<Arc<tempo_mcp::TempoMcpServer<AttachedEngineDriver>>>,
    bidi_contexts: BTreeMap<BrowsingContextId, AttachedEngineDriver>,
    url_policy: UrlPolicy,
    next_bidi_context_id: u64,
    next_id: u64,
    draining: bool,
}

impl Default for SessionPool {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            session_drivers: BTreeMap::new(),
            session_act_batch_idempotency: BTreeMap::new(),
            events: BTreeMap::new(),
            otlp_exporter: None,
            privacy_mode: PrivacyMode::default(),
            bidi: BidiRouter::default(),
            driver: None,
            mcp: None,
            bidi_contexts: BTreeMap::new(),
            #[cfg(not(test))]
            url_policy: UrlPolicy::block_private(),
            #[cfg(test)]
            url_policy: UrlPolicy::allow_all(),
            next_bidi_context_id: 0,
            next_id: 0,
            draining: false,
        }
    }
}

impl fmt::Debug for SessionPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionPool")
            .field("sessions", &self.sessions)
            .field("session_drivers", &self.session_drivers.keys())
            .field(
                "session_act_batch_idempotency",
                &self.session_act_batch_idempotency.len(),
            )
            .field("event_sessions", &self.events.len())
            .field("otlp_exporter", &self.otlp_exporter)
            .field("privacy_mode", &self.privacy_mode)
            .field("bidi", &self.bidi)
            .field("driver", &self.driver)
            .field("mcp_attached", &self.mcp.is_some())
            .field("url_policy", &self.url_policy)
            .field("next_id", &self.next_id)
            .field("draining", &self.draining)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SessionActBatchIdempotencyEntry {
    request_fingerprint: JsonValue,
    response: CachedSessionActBatchResponse,
}

#[derive(Clone, Debug, PartialEq)]
struct CachedSessionActBatchResponse {
    status: u16,
    body: JsonValue,
}

impl SessionPool {
    pub fn from_env() -> Self {
        Self::from_env_values(
            std::env::var_os(TEMPO_OTLP_JSONL_ENV),
            std::env::var_os(TEMPO_STEALTH_MODE_ENV),
        )
    }

    #[cfg(test)]
    fn from_otlp_env_value(value: Option<std::ffi::OsString>) -> Self {
        Self::from_env_values(value, None)
    }

    fn from_env_values(
        otlp_value: Option<std::ffi::OsString>,
        stealth_value: Option<std::ffi::OsString>,
    ) -> Self {
        let privacy_mode = PrivacyMode::from_env_value(stealth_value);
        let mut pool = Self::default().with_privacy_mode(privacy_mode);
        if privacy_mode.retains_history()
            && let Some(path) = otlp_value
            && !path.is_empty()
        {
            pool = pool.with_otlp_exporter(OtlpJsonExporter::new(path));
        }
        pool
    }

    pub fn with_privacy_mode(mut self, privacy_mode: PrivacyMode) -> Self {
        self.privacy_mode = privacy_mode;
        if !privacy_mode.retains_history() {
            self.otlp_exporter = None;
            self.events.clear();
            self.session_act_batch_idempotency.clear();
        }
        self
    }

    pub fn with_navigation_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    pub fn privacy_mode(&self) -> PrivacyMode {
        self.privacy_mode
    }

    pub fn with_otlp_exporter(mut self, exporter: OtlpJsonExporter) -> Self {
        if self.privacy_mode.retains_history() {
            self.otlp_exporter = Some(exporter);
        }
        self
    }

    pub fn set_otlp_exporter(&mut self, exporter: Option<OtlpJsonExporter>) {
        self.otlp_exporter = if self.privacy_mode.retains_history() {
            exporter
        } else {
            None
        };
    }

    pub fn otlp_exporter(&self) -> Option<&OtlpJsonExporter> {
        self.otlp_exporter.as_ref()
    }

    /// Create a session while exclusively holding the pool. The HTTP path uses
    /// [`create_session_shared`] instead, which runs the engine round-trips
    /// WITHOUT the pool lock so other sessions and metadata routes stay live
    /// (issue #230); this method serves already-locked callers (tests, and
    /// driverless metadata-only pools).
    pub fn create(&mut self, url: impl Into<String>) -> Result<TempodSession, TempodError> {
        if self.draining {
            return Err(TempodError::Draining);
        }
        let url = url.into();
        enforce_tempod_navigation_url(&self.url_policy, &url)?;
        let session_driver = self.create_session_engine_context(&url)?;
        Ok(self.finish_create(url, session_driver))
    }

    /// Insert the session record (and its engine context driver, when present)
    /// and emit the created event. Callers have already checked `draining`.
    fn finish_create(
        &mut self,
        url: String,
        session_driver: Option<AttachedEngineDriver>,
    ) -> TempodSession {
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
        session
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
        self.clear_session_idempotency(id);
        self.record_event(id, TempodSessionEventKind::SessionKilled);
        self.purge_terminal_session_if_stealth(id);
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
        self.session_act_batch_idempotency.clear();
        self.close_engine_resources(true);
        self.purge_terminal_sessions_if_stealth();
    }

    pub fn draining(&self) -> bool {
        self.draining
    }

    pub fn attach_engine_driver(
        &mut self,
        engine: Engine,
        client: EngineIpcClient,
    ) -> Result<(), TempodError> {
        self.close_engine_resources(true);
        let driver = AttachedEngineDriver::new(engine, client)?
            .with_navigation_url_policy(self.url_policy.clone());
        self.mcp = Some(Arc::new(tempo_mcp::TempoMcpServer::new(driver.clone())));
        self.bidi_contexts.clear();
        self.next_bidi_context_id = 1;
        self.bidi_contexts
            .insert(default_context_id(), driver.clone());
        self.driver = Some(driver);
        Ok(())
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
    /// `Send + 'static` (shared multiplexed IPC client + `Copy` `Engine`; forks
    /// are `Box<dyn DriverTrait>`, which is `Send`), so they move to the worker
    /// thread.
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
                for error in futures::executor::block_on(server.close_all_forks()) {
                    eprintln!("tempod: error closing MCP fork at teardown: {error}");
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
        let Some(root_driver) = self.driver.as_ref() else {
            return Ok(None);
        };
        if let Some(message) =
            tempod_resolved_navigation_url_policy_denial(&root_driver.url_policy, url)
        {
            return Err(TempodError::Forbidden(message));
        }
        match run_session_context_create(root_driver.clone(), url) {
            Some(result) => result.map(Some),
            None => {
                // The engine failed to answer the bounded create+goto window at
                // all — treat it as unresponsive and detach the shared engine
                // state so later engine-backed requests fail fast instead of
                // each waiting out its own IPC timeout against a wedged child
                // (#213). The abandoned worker still owns the in-flight work
                // and releases it once the engine answers or disconnects.
                self.abandon_attached_engine_after_teardown_timeout(
                    "session-create engine navigation",
                );
                Err(TempodError::Driver(
                    "attached engine timed out creating/navigating session context".into(),
                ))
            }
        }
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
        // Detach the engine, but do NOT merely drop the remaining pre-existing
        // session/BiDi contexts: dropping an `AttachedEngineDriver` sends no
        // `Close`, so any context that was already live would leak engine-side
        // (the maps are cleared, so no later `kill`/BiDi-close can reclaim it)
        // (#213 review). Delegate to the same bounded, detached best-effort
        // teardown used elsewhere: it `mem::take`s the forked BiDi contexts, MCP
        // forks, session-owned contexts, and root driver, runs their `Close`es in
        // order on one detached worker, and awaits with a single `recv_timeout`
        // -- so the engine still ends up invalidated (`driver`/`mcp` nulled, maps
        // cleared, so later engine requests fast-fail) while the pre-existing
        // contexts get a best-effort `Close` instead of a silent drop. The shared
        // IPC handle is wedged, so these closes cannot complete synchronously; the
        // bound (200ms in tests) caps the extra lock-hold and the detached worker
        // owns/finishes the closes once the engine answers or disconnects.
        //
        // Not re-entrant: `bounded_engine_teardown` never calls back into
        // `abandon_*`. Not a double-close of a caller-owned driver either --
        // `close_session_driver` `remove`s its single driver before its own
        // bounded attempt, and the create `on_orphan` path owns the freshly
        // created context, so the map contents drained here are disjoint from
        // those already-owned drivers.
        self.bounded_engine_teardown(true, ENGINE_TEARDOWN_TIMEOUT);
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

    fn cached_session_act_batch_response(
        &self,
        id: &TempodSessionId,
        key: &str,
        request_fingerprint: &JsonValue,
    ) -> Result<Option<CachedSessionActBatchResponse>, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        if !self.privacy_mode.retains_idempotency_cache() {
            return Ok(None);
        }
        let Some(entry) = self
            .session_act_batch_idempotency
            .get(&(id.clone(), key.to_owned()))
        else {
            return Ok(None);
        };
        if &entry.request_fingerprint != request_fingerprint {
            return Err(TempodError::Conflict(
                "idempotency_key was already used for a different act_batch request".into(),
            ));
        }
        Ok(Some(entry.response.clone()))
    }

    fn ensure_session_idempotency_capacity(
        &self,
        id: &TempodSessionId,
        key: &str,
    ) -> Result<(), TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        if !self.privacy_mode.retains_idempotency_cache() {
            return Ok(());
        }
        if self
            .session_act_batch_idempotency
            .contains_key(&(id.clone(), key.to_owned()))
            || self.session_idempotency_record_count(id) < MAX_SESSION_IDEMPOTENCY_RECORDS
        {
            return Ok(());
        }
        Err(TempodError::Conflict(format!(
            "session idempotency cache is full; max {MAX_SESSION_IDEMPOTENCY_RECORDS} records"
        )))
    }

    fn remember_session_act_batch_response(
        &mut self,
        id: &TempodSessionId,
        key: &str,
        request_fingerprint: JsonValue,
        status: u16,
        body: JsonValue,
    ) -> Result<(), TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        if !self.privacy_mode.retains_idempotency_cache() {
            return Ok(());
        }
        self.ensure_session_idempotency_capacity(id, key)?;
        self.session_act_batch_idempotency.insert(
            (id.clone(), key.to_owned()),
            SessionActBatchIdempotencyEntry {
                request_fingerprint,
                response: CachedSessionActBatchResponse { status, body },
            },
        );
        Ok(())
    }

    fn session_idempotency_record_count(&self, id: &TempodSessionId) -> usize {
        self.session_act_batch_idempotency
            .keys()
            .filter(|(session_id, _)| session_id == id)
            .count()
    }

    fn clear_session_idempotency(&mut self, id: &TempodSessionId) {
        self.session_act_batch_idempotency
            .retain(|(session_id, _), _| session_id != id);
    }

    fn session_driver(&self, id: &TempodSessionId) -> Result<AttachedEngineDriver, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        self.session_drivers.get(id).cloned().ok_or_else(|| {
            TempodError::DriverUnavailable(format!(
                "session {} has no attached engine driver",
                id.0
            ))
        })
    }

    fn purge_terminal_session_if_stealth(&mut self, id: &TempodSessionId) {
        if self.privacy_mode.retains_history() {
            return;
        }
        self.events.remove(id);
        self.clear_session_idempotency(id);
        self.sessions.remove(id);
    }

    fn purge_terminal_sessions_if_stealth(&mut self) {
        if self.privacy_mode.retains_history() {
            return;
        }
        self.events.clear();
        self.session_act_batch_idempotency.clear();
        self.sessions
            .retain(|_, session| session.state == TempodSessionState::Running);
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

/// Run the blocking session create+goto engine IPC on a detached worker thread,
/// bounded by `timeout`, so a slow/unresponsive navigation target cannot stall
/// the daemon (and the pool lock it holds) indefinitely (#213). Returns `None` on
/// timeout; the detached worker then owns and abandons/finishes the wedged work
/// once the engine answers or disconnects, so the caller is released promptly.
/// Mirrors `run_teardown_bounded` (#200) but for the create path.
///
/// If the caller has already timed out (`recv_timeout` returned `None`) but the
/// worker's `op()` LATER produces a value, `tx.send` fails and that value would
/// otherwise be dropped on the floor. For the create path that value can be a
/// freshly-created, engine-owned session context; silently dropping it leaks the
/// browsing context on the engine side (the shared engine has already been
/// invalidated, so no later pool code owns/closes it). `on_orphan` is invoked ON
/// THE WORKER THREAD with exactly that un-sent value so the caller can release it
/// (e.g. close the orphaned session context) instead of leaking it (#213 review).
fn run_create_bounded<T, F, C>(timeout: Duration, op: F, on_orphan: C) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    C: FnOnce(T) + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached on purpose: on timeout we must not join (that would reintroduce
    // the unbounded block); the worker finishes on its own and drops the owned
    // session driver / engine handle once the engine responds or disconnects.
    thread::spawn(move || {
        // If the receiver already timed out, `send` hands the value back inside
        // the `SendError`; run the orphan cleanup on this worker thread so the
        // late success is torn down (bounded by the same engine window) rather
        // than abandoned.
        if let Err(std::sync::mpsc::SendError(orphaned)) = tx.send(op()) {
            on_orphan(orphaned);
        }
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => Some(result),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "tempod: session-create engine navigation did not complete within {timeout:?}; \
                 abandoning it so the pool lock is released (#213)"
            );
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("tempod: session-create engine worker ended without a result");
            None
        }
    }
}

/// Run the session create-context + goto engine round-trips on a detached
/// worker bounded by [`SESSION_CREATE_TIMEOUT`] (#213/#217). Returns `None` on
/// timeout — the worker then owns the wedged work and closes any late-created
/// context via the orphan hook instead of leaking it. The failure-path `Close`
/// runs on the same worker so it is bounded by the same window.
fn run_session_context_create(
    mut worker_driver: AttachedEngineDriver,
    url: &str,
) -> Option<Result<AttachedEngineDriver, TempodError>> {
    let url = url.to_string();
    run_create_bounded(
        SESSION_CREATE_TIMEOUT,
        move || -> Result<AttachedEngineDriver, TempodError> {
            let options = BrowsingContextCreateOptions {
                kind: BrowsingContextKind::Tab,
                background: true,
            };
            let mut session_driver = futures::executor::block_on(
                worker_driver.create_browsing_context_attached(options),
            )
            .map_err(|error| {
                TempodError::Driver(format!(
                    "attached engine failed to create session context: {error}"
                ))
            })?;
            if let Err(error) = futures::executor::block_on(session_driver.goto(&url)) {
                let _ = futures::executor::block_on(session_driver.close());
                return Err(TempodError::Driver(format!(
                    "attached engine failed to navigate session context: {error}"
                )));
            }
            Ok(session_driver)
        },
        // If the create+goto succeeds AFTER the caller has already timed out
        // (receiver gone), close the freshly-created session context here on
        // the worker thread instead of dropping it. Nothing else owns this
        // context, so dropping it silently would leak the browsing context
        // engine-side (#213 review). `Err(_)` values carry no engine resource.
        |orphaned: Result<AttachedEngineDriver, TempodError>| {
            if let Ok(mut orphaned_driver) = orphaned {
                let _ = futures::executor::block_on(orphaned_driver.close());
            }
        },
    )
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
/// * Sensitive fields (typed action text, select values, skill inputs, node
///   ids, and step-error reasons) are replaced with a constant redaction marker
///   before serialization instead of being written verbatim or hashed, and URL
///   secrets (userinfo, query, fragment) are stripped. See [`redact_action`] /
///   [`redact_step_outcome`].
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
/// We keep telemetry-useful, non-sensitive fields (seq, action kind,
/// coordinates, millis, skill name, observation-diff counts) and replace
/// anything that can carry raw secrets with a constant marker: the idempotency
/// key, typed text, select values, skill inputs, node ids, and step-error
/// reasons. `Goto` URLs are reduced to origin + shape metadata (see
/// [`redact_goto_url`]).
fn redacted_export_record(triple: &StepTriple) -> serde_json::Value {
    json!({
        "resource": {
            "service.name": "tempod",
        },
        "name": "tempo.step",
        "body": {
            // `IdempotencyKey` is public and deserializable, so callers can
            // construct arbitrary keys; it must not be assumed generated/secret-free.
            // Emit the constant marker instead of the raw key — `seq` already
            // provides step ordering (issue #214 review, medium finding).
            "key": REDACTED_MARKER,
            "seq": triple.seq,
            "action": redact_action(&triple.action),
            "outcome": redact_step_outcome(&triple.outcome),
        },
    })
}

/// Redact an [`Action`] for telemetry: preserve non-sensitive structural fields,
/// replace anything that can embed user/page secrets with the constant marker,
/// and strip URL secrets.
///
/// Node ids are redacted with the marker too: a [`NodeId`] can be selector-backed
/// (e.g. `a[href="/reset?token=SECRET"]`) and thereby embed arbitrary page
/// secrets in an attribute value, so neither the id nor a hash of it is exported.
fn redact_action(action: &Action) -> serde_json::Value {
    match action {
        Action::Goto { url } => json!({ "kind": "goto", "url": redact_goto_url(url) }),
        Action::Click { node: _ } => json!({ "kind": "click", "node": REDACTED_MARKER }),
        // Typed text frequently carries credentials; the node id can be a
        // secret-bearing selector — mark both.
        Action::Type { node: _, text: _ } => {
            json!({ "kind": "type", "node": REDACTED_MARKER, "text": REDACTED_MARKER })
        }
        // Select values can be sensitive (e.g. account numbers) — mark them.
        Action::Select { node: _, value: _ } => {
            json!({ "kind": "select", "node": REDACTED_MARKER, "value": REDACTED_MARKER })
        }
        Action::Scroll { x, y } => json!({ "kind": "scroll", "x": x, "y": y }),
        Action::Wait { millis } => json!({ "kind": "wait", "millis": millis }),
        Action::Extract { node: _ } => json!({ "kind": "extract", "node": REDACTED_MARKER }),
        // Skill input is arbitrary JSON that may contain secrets — keep the name
        // (a skill identifier, not page-derived), mark the input.
        Action::Skill { name, input: _ } => json!({
            "kind": "skill",
            "name": name,
            "input": REDACTED_MARKER,
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
        // error body), so replace it with the constant marker — consistent with
        // how `Type.text`/`Select.value`/`Skill.input` are redacted.
        StepTripleOutcome::StepError { reason: _ } => json!({
            "kind": "step_error",
            "reason": REDACTED_MARKER,
        }),
    }
}

/// Redact a `Goto` URL for telemetry: emit only the origin plus non-sensitive
/// shape metadata, never the path (issue #214 review, high finding).
///
/// The path can itself carry secrets (`/reset/SECRET`, signed object keys,
/// account ids), so — unlike userinfo/query/fragment which were merely stripped
/// — we drop the path entirely and export only:
///
/// * `origin`: `<scheme>://<host[:port]>` with userinfo removed and the port
///   included only when it is non-default for the scheme,
/// * `path_segments`: count of non-empty `/`-separated path segments,
/// * `has_query` / `has_fragment`: booleans, so telemetry keeps shape without
///   the secret-bearing contents.
///
/// If the URL fails to parse (or has no host to form an origin), fall back to
/// the constant [`REDACTED_MARKER`] rather than emitting anything raw. Panic-free:
/// no `unwrap`/`expect`.
fn redact_goto_url(url: &str) -> serde_json::Value {
    let Ok(parsed) = Url::parse(url) else {
        return json!(REDACTED_MARKER);
    };
    // Without a host we cannot form a safe origin; redact wholesale.
    let Some(host) = parsed.host_str() else {
        return json!(REDACTED_MARKER);
    };
    // `Url::port` returns `None` for the scheme's default port, giving us the
    // "optional port" behaviour for free; userinfo is never part of this.
    let origin = match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), host, port),
        None => format!("{}://{}", parsed.scheme(), host),
    };
    let path_segments = parsed
        .path()
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count();
    json!({
        "origin": origin,
        "path_segments": path_segments,
        "has_query": parsed.query().is_some(),
        "has_fragment": parsed.fragment().is_some(),
    })
}

/// Run tempod forever on an address such as `127.0.0.1:8787`.
pub fn run_tempod(addr: &str) -> Result<(), TempodError> {
    run_tempod_with_config(addr, TempodServerConfig::default())
}

pub fn run_tempod_with_config(addr: &str, config: TempodServerConfig) -> Result<(), TempodError> {
    run_tempod_with_config_and_navigation_url_policy(addr, config, UrlPolicy::block_private())
}

/// Run tempod with an explicit navigation URL policy.
pub fn run_tempod_with_navigation_url_policy(
    addr: &str,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    run_tempod_with_config_and_navigation_url_policy(
        addr,
        TempodServerConfig::default(),
        url_policy,
    )
}

pub fn run_tempod_with_config_and_navigation_url_policy(
    addr: &str,
    config: TempodServerConfig,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    config.validate_bind_addr(addr)?;
    let listener = TcpListener::bind(addr)?;
    let pool = Arc::new(Mutex::new(
        SessionPool::from_env().with_navigation_url_policy(url_policy),
    ));
    serve_forever_with_config(listener, pool, config)
}

/// Run tempod with an already-running engine reachable through the UDS driver protocol.
pub fn run_tempod_with_attached_driver(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config(addr, TempodServerConfig::default(), engine, socket_path)
}

pub fn run_tempod_with_attached_driver_config(
    addr: &str,
    config: TempodServerConfig,
    engine: Engine,
    socket_path: impl AsRef<Path>,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config_and_navigation_url_policy(
        addr,
        config,
        engine,
        socket_path,
        UrlPolicy::block_private(),
    )
}

/// Run tempod with an attached engine and explicit navigation URL policy.
pub fn run_tempod_with_attached_driver_and_navigation_url_policy(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config_and_navigation_url_policy(
        addr,
        TempodServerConfig::default(),
        engine,
        socket_path,
        url_policy,
    )
}

pub fn run_tempod_with_attached_driver_config_and_navigation_url_policy(
    addr: &str,
    config: TempodServerConfig,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    config.validate_bind_addr(addr)?;
    let listener = TcpListener::bind(addr)?;
    let mut pool = SessionPool::from_env().with_navigation_url_policy(url_policy);
    pool.attach_engine_driver(engine, connect_engine_ipc(socket_path)?)?;
    serve_forever_with_config(listener, Arc::new(Mutex::new(pool)), config)
}

/// Connect to the engine host UDS with a bounded write timeout. Read bounding
/// is per-request: the multiplexed client (`SharedEngineIpcClient`) awaits each
/// response with its own `ENGINE_IPC_TIMEOUT` and clears the socket read
/// timeout so its idle reader thread never mis-times a frame (issue #230).
fn connect_engine_ipc(socket_path: impl AsRef<Path>) -> Result<EngineIpcClient, TempodError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    stream.set_write_timeout(Some(ENGINE_IPC_TIMEOUT))?;
    Ok(EngineIpcClient::from_stream(stream))
}

#[derive(Clone)]
struct ConnectionLimiter {
    state: Arc<Mutex<ConnectionLimiterState>>,
    max_http: usize,
    max_websocket: usize,
}

#[derive(Debug, Default)]
struct ConnectionLimiterState {
    active_http: usize,
    active_websocket: usize,
}

#[derive(Clone, Copy, Debug)]
enum ConnectionPermitKind {
    Http,
    WebSocket,
}

struct ConnectionPermit {
    limiter: ConnectionLimiter,
    kind: ConnectionPermitKind,
}

impl Default for ConnectionLimiter {
    fn default() -> Self {
        Self::new(MAX_HTTP_CONNECTIONS, MAX_WEBSOCKET_CONNECTIONS)
    }
}

impl ConnectionLimiter {
    fn new(max_http: usize, max_websocket: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionLimiterState::default())),
            max_http,
            max_websocket,
        }
    }

    fn try_acquire_http(&self) -> Option<ConnectionPermit> {
        let mut state = self.state();
        if state.active_http >= self.max_http {
            return None;
        }
        state.active_http += 1;
        Some(ConnectionPermit {
            limiter: self.clone(),
            kind: ConnectionPermitKind::Http,
        })
    }

    fn try_acquire_websocket(&self) -> Option<ConnectionPermit> {
        let mut state = self.state();
        if state.active_websocket >= self.max_websocket {
            return None;
        }
        state.active_websocket += 1;
        Some(ConnectionPermit {
            limiter: self.clone(),
            kind: ConnectionPermitKind::WebSocket,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ConnectionLimiterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn active_counts(&self) -> (usize, usize) {
        let state = self.state();
        (state.active_http, state.active_websocket)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state();
        match self.kind {
            ConnectionPermitKind::Http => {
                state.active_http = state.active_http.saturating_sub(1);
            }
            ConnectionPermitKind::WebSocket => {
                state.active_websocket = state.active_websocket.saturating_sub(1);
            }
        }
    }
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
    serve_forever_with_config(listener, pool, TempodServerConfig::default())
}

pub fn serve_forever_with_auth(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
) -> Result<(), TempodError> {
    serve_forever_with_config(listener, pool, TempodServerConfig::new().with_auth(auth))
}

pub fn serve_forever_with_config(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    config: TempodServerConfig,
) -> Result<(), TempodError> {
    config.validate_listener(&listener)?;
    serve_forever_trusted(listener, pool, config.auth, ConnectionLimiter::default())
}

#[cfg(test)]
fn serve_forever_with_limits(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    limiter: ConnectionLimiter,
) -> Result<(), TempodError> {
    serve_forever_trusted(listener, pool, TempodAuth::disabled(), limiter)
}

fn serve_forever_trusted(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
    limiter: ConnectionLimiter,
) -> Result<(), TempodError> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let Some(http_permit) = limiter.try_acquire_http() else {
                    drop(stream);
                    continue;
                };
                let pool = Arc::clone(&pool);
                let limiter = limiter.clone();
                let auth = auth.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, &pool, &auth, &limiter, http_permit)
                    {
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
    serve_one_with_config(listener, pool, TempodServerConfig::default())
}

pub fn serve_one_with_auth(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
) -> Result<(), TempodError> {
    serve_one_with_config(listener, pool, TempodServerConfig::new().with_auth(auth))
}

pub fn serve_one_with_config(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    config: TempodServerConfig,
) -> Result<(), TempodError> {
    config.validate_listener(&listener)?;
    serve_one_trusted(listener, pool, config.auth, ConnectionLimiter::default())
}

fn serve_one_trusted(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
    limiter: ConnectionLimiter,
) -> Result<(), TempodError> {
    let (stream, _addr) = listener.accept()?;
    let Some(http_permit) = limiter.try_acquire_http() else {
        drop(stream);
        return Err(TempodError::ConnectionLimit(
            HTTP_CONNECTION_LIMIT_MESSAGE.into(),
        ));
    };
    handle_connection(stream, &pool, &auth, &limiter, http_permit)
}

/// Apply per-connection socket options, then handle the connection. Timeouts
/// bound how long a stalled client can occupy a handler thread (slowloris).
fn handle_connection(
    stream: TcpStream,
    pool: &Arc<Mutex<SessionPool>>,
    auth: &TempodAuth,
    limiter: &ConnectionLimiter,
    http_permit: ConnectionPermit,
) -> Result<(), TempodError> {
    apply_socket_options(&stream)?;
    handle_stream(stream, pool, auth, limiter, http_permit)
}

/// Apply read/write timeouts and disable Nagle on an accepted connection. A
/// stalled client (slowloris) is aborted after `SOCKET_TIMEOUT` instead of
/// occupying a handler thread forever. TCP_NODELAY matters because this is a
/// request/response control plane: with Nagle on, a small response or BiDi
/// event written after another small write can sit in the kernel until the
/// peer's delayed ACK (tens of milliseconds) instead of going out immediately.
fn apply_socket_options(stream: &TcpStream) -> Result<(), TempodError> {
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_nodelay(true)?;
    Ok(())
}

fn log_connection_error(err: &TempodError) {
    eprintln!("tempod connection error: {err}");
}

fn handle_stream(
    mut stream: TcpStream,
    pool: &Arc<Mutex<SessionPool>>,
    auth: &TempodAuth,
    limiter: &ConnectionLimiter,
    http_permit: ConnectionPermit,
) -> Result<(), TempodError> {
    let mut http_permit = Some(http_permit);
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
    match websocket_upgrade_key_with_auth(&request, auth) {
        Ok(Some(key)) => {
            let Some(websocket_permit) = limiter.try_acquire_websocket() else {
                let response = tempod_error_response(&TempodError::ConnectionLimit(
                    WEBSOCKET_CONNECTION_LIMIT_MESSAGE.into(),
                ));
                stream.write_all(response.to_bytes().as_slice())?;
                stream.flush()?;
                return Ok(());
            };
            drop(http_permit.take());
            stream.write_all(websocket_upgrade_response(&key).as_slice())?;
            stream.flush()?;
            return serve_bidi_websocket(stream, pool, websocket_permit);
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
    let response = handle_http_request_with_auth(pool, request, auth);
    stream.write_all(response.to_bytes().as_slice())?;
    stream.flush()?;
    Ok(())
}

fn tempod_error_response(err: &TempodError) -> HttpResponse {
    HttpResponse::json(err.status(), err.body())
}

/// Lock the pool for a SHORT, engine-IPC-free critical section. Routes must
/// never hold this guard across an engine round-trip (issue #230): engine work
/// happens on cloned per-session driver handles after the guard is dropped.
fn lock_pool(pool: &Arc<Mutex<SessionPool>>) -> Result<MutexGuard<'_, SessionPool>, TempodError> {
    pool.lock().map_err(|_| TempodError::PoolLock)
}

#[cfg(test)]
fn handle_http_request(pool: &Arc<Mutex<SessionPool>>, request: HttpRequest) -> HttpResponse {
    handle_http_request_with_auth(pool, request, &TempodAuth::disabled())
}

fn handle_http_request_with_auth(
    pool: &Arc<Mutex<SessionPool>>,
    request: HttpRequest,
    auth: &TempodAuth,
) -> HttpResponse {
    match route_http_request_with_auth(pool, request, auth) {
        Ok(response) => response,
        Err(err) => tempod_error_response(&err),
    }
}

/// Route one HTTP request. Locking discipline (issue #230): metadata routes
/// (`/health`, list/adopt/kill/drain/events) take the pool lock only for their
/// in-memory work (kill/drain additionally run the pre-existing BOUNDED
/// engine-context closes from #200/#205 under it), while the engine-op routes
/// (`POST /sessions`, `POST /mcp`, `POST /bidi`) split into lock -> clone the
/// needed per-session handle -> unlock -> engine round-trip -> re-lock to
/// publish results. No engine round-trip ever runs while the pool lock is
/// held, so operations on different sessions execute concurrently and
/// `/health`/`/drain` never queue behind an in-flight browser operation.
#[cfg(test)]
fn route_http_request(
    pool: &Arc<Mutex<SessionPool>>,
    request: HttpRequest,
) -> Result<HttpResponse, TempodError> {
    route_http_request_with_auth(pool, request, &TempodAuth::disabled())
}

fn route_http_request_with_auth(
    pool: &Arc<Mutex<SessionPool>>,
    request: HttpRequest,
    auth: &TempodAuth,
) -> Result<HttpResponse, TempodError> {
    if route_requires_auth(&request.method, &request.path) {
        auth.authorize(&request)?;
    }
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
        // Health never touches the pool at all: it must answer even while
        // metadata routes are briefly holding the lock.
        ("GET", "/health") => Ok(HttpResponse::json(200, json!({"ok": true}))),
        ("GET", TEMPOD_OPENAPI_PATH) => Ok(HttpResponse::new(
            200,
            TEMPOD_OPENAPI_CONTENT_TYPE,
            tempod_openapi(&request.base_url()).to_string().into_bytes(),
        )),
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
        ("GET", "/sessions") => Ok(HttpResponse::json(200, lock_pool(pool)?.list())),
        ("POST", "/sessions") => {
            let body: CreateSessionRequest = serde_json::from_slice(&request.body)?;
            if body.url.trim().is_empty() {
                return Err(TempodError::BadRequest("session url is required".into()));
            }
            Ok(HttpResponse::json(
                201,
                create_session_shared(pool, body.url)?,
            ))
        }
        ("POST", "/drain") => {
            let mut pool = lock_pool(pool)?;
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
                return Ok(HttpResponse::json(
                    200,
                    lock_pool(pool)?.events(&id, after_seq)?,
                ));
            }
            if request.method == "POST" && request.path.ends_with("/adopt") {
                let id = session_id_from_action_path(&request.path, "adopt")?;
                return Ok(HttpResponse::json(200, lock_pool(pool)?.adopt(&id)?));
            }
            if request.method == "GET" && request.path.ends_with("/observe") {
                let id = session_id_from_action_path(&request.path, "observe")?;
                return Ok(HttpResponse::json(200, route_session_observe(pool, &id)?));
            }
            if request.method == "POST" && request.path.ends_with("/act_batch") {
                let id = session_id_from_action_path(&request.path, "act_batch")?;
                let body = parse_session_act_batch_request(&request.body)?;
                return route_session_act_batch(pool, id, body);
            }
            if request.method == "DELETE" {
                let id = session_id_from_path(&request.path)?;
                return Ok(HttpResponse::json(200, lock_pool(pool)?.kill(&id)?));
            }
            Err(TempodError::BadRequest(format!(
                "unsupported route: {} {}",
                request.method, request.path
            )))
        }
    }
}

/// `POST /sessions` with the engine round-trips OFF the pool lock (issue #230;
/// completes the follow-up documented on [`SESSION_CREATE_TIMEOUT`]):
///
/// 1. lock — admission (drain check) and root-driver handle clone;
/// 2. unlock — bounded create-context + goto on a detached worker
///    (`SESSION_CREATE_TIMEOUT`, unchanged from #217), so concurrent creates
///    and every other route proceed meanwhile;
/// 3. lock — re-check drain (closing the fresh context if drain won the race)
///    and publish the session record + driver.
fn create_session_shared(
    pool: &Arc<Mutex<SessionPool>>,
    url: String,
) -> Result<TempodSession, TempodError> {
    let root_driver = {
        let pool = lock_pool(pool)?;
        if pool.draining {
            return Err(TempodError::Draining);
        }
        enforce_tempod_navigation_url(&pool.url_policy, &url)?;
        pool.driver.clone()
    };

    let session_driver = match root_driver {
        None => None,
        Some(root_driver) => match run_session_context_create(root_driver, &url) {
            Some(result) => Some(result?),
            None => {
                // Same circuit breaker as the locked path: an engine that
                // cannot answer within the whole create window is treated as
                // unresponsive and detached so later requests fail fast (#213).
                lock_pool(pool)?.abandon_attached_engine_after_teardown_timeout(
                    "session-create engine navigation",
                );
                return Err(TempodError::Driver(
                    "attached engine timed out creating/navigating session context".into(),
                ));
            }
        },
    };

    let mut pool = lock_pool(pool)?;
    if pool.draining {
        // Drain raced the off-lock engine work: the pool must stay empty, so
        // release the freshly-created context (bounded) instead of leaking it.
        if let Some(mut driver) = session_driver
            && run_teardown_bounded(
                "session context Close after drain race",
                ENGINE_TEARDOWN_TIMEOUT,
                move || futures::executor::block_on(driver.close()),
            )
            .is_none()
        {
            eprintln!(
                "tempod: session context created during drain was abandoned to a detached worker"
            );
        }
        return Err(TempodError::Draining);
    }
    Ok(pool.finish_create(url, session_driver))
}

fn route_session_observe(
    pool: &Arc<Mutex<SessionPool>>,
    id: &TempodSessionId,
) -> Result<CompiledObservation, TempodError> {
    let mut driver = lock_pool(pool)?.session_driver(id)?;
    futures::executor::block_on(driver.observe())
        .map_err(|error| TempodError::Driver(error.to_string()))
}

fn route_session_act_batch(
    pool: &Arc<Mutex<SessionPool>>,
    id: TempodSessionId,
    body: SessionActBatchRequest,
) -> Result<HttpResponse, TempodError> {
    let (mut driver, request_fingerprint, idempotency_key, policy) = {
        let mut pool = lock_pool(pool)?;
        let policy = enforce_session_batch_policy(&pool.url_policy, &body)?;
        let request_fingerprint = session_act_batch_idempotency_fingerprint(&body);
        if let Some(key) = body.idempotency_key.as_deref()
            && let Some(response) =
                pool.cached_session_act_batch_response(&id, key, &request_fingerprint)?
        {
            return Ok(HttpResponse::json(response.status, response.body));
        }
        let driver = pool.session_driver(&id)?;
        let idempotency_key = body.idempotency_key.clone();
        if let Some(key) = idempotency_key.as_deref() {
            pool.remember_session_act_batch_response(
                &id,
                key,
                request_fingerprint.clone(),
                409,
                session_act_batch_unknown_outcome_response(&policy),
            )?;
        }
        (driver, request_fingerprint, idempotency_key, policy)
    };

    let response = match futures::executor::block_on(driver.act_batch(&body.batch)) {
        Ok(outcome) => CachedSessionActBatchResponse {
            status: 200,
            body: step_outcome_response(outcome, policy),
        },
        Err(error) => CachedSessionActBatchResponse {
            status: 500,
            body: json!({ "error": error.to_string() }),
        },
    };

    if let Some(key) = idempotency_key {
        let mut pool = lock_pool(pool)?;
        pool.remember_session_act_batch_response(
            &id,
            &key,
            request_fingerprint,
            response.status,
            response.body.clone(),
        )?;
    }
    Ok(HttpResponse::json(response.status, response.body))
}

fn parse_session_act_batch_request(body: &[u8]) -> Result<SessionActBatchRequest, TempodError> {
    let value: JsonValue = serde_json::from_slice(body).map_err(|error| {
        TempodError::BadRequest(format!("invalid act_batch request JSON: {error}"))
    })?;
    reject_explicit_null_field(&value, "input_tainted")?;
    reject_explicit_null_field(&value, "idempotency_key")?;
    serde_json::from_value(value).map_err(|error| {
        TempodError::BadRequest(format!("invalid act_batch request JSON: {error}"))
    })
}

fn reject_explicit_null_field(value: &JsonValue, field: &'static str) -> Result<(), TempodError> {
    if value.get(field).is_some_and(JsonValue::is_null) {
        return Err(TempodError::BadRequest(format!(
            "{field} must not be null; omit the field to use its default"
        )));
    }
    Ok(())
}

fn enforce_session_batch_policy(
    policy: &UrlPolicy,
    body: &SessionActBatchRequest,
) -> Result<SessionBatchPolicyReport, TempodError> {
    if let Some(key) = body.idempotency_key.as_deref() {
        if key.is_empty() {
            return Err(TempodError::BadRequest(
                "idempotency_key must not be empty".into(),
            ));
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(TempodError::BadRequest(format!(
                "idempotency_key exceeds {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            )));
        }
    }
    enforce_batch_navigation_url_policy(policy, &body.batch)?;
    let forced_tainted_actions = body
        .batch
        .actions
        .iter()
        .filter(|action| action_requires_external_taint_floor(action))
        .count();
    let input_tainted_effective = body.input_tainted.unwrap_or(true) || forced_tainted_actions > 0;
    let declared_input_tainted = body.input_tainted.unwrap_or(true);
    let mut report = SessionBatchPolicyReport {
        input_tainted_declared: body.input_tainted,
        input_tainted_effective,
        forced_tainted_actions,
        max_side_effect: SideEffect::Read,
        strongest_gate: ConfirmationGate::None,
        confirmation_required: false,
        confirmed: body.confirmed,
        idempotency_required: false,
        idempotency_key_provided: body.idempotency_key.is_some(),
    };
    let mut first_confirmation_index = None;
    let mut first_idempotency_index = None;
    for (index, action) in body.batch.actions.iter().enumerate() {
        let input_taint =
            InputTaint::new(declared_input_tainted || action_requires_external_taint_floor(action));
        let decision = decide_action(action, input_taint);
        report.max_side_effect = report.max_side_effect.max(decision.side_effect);
        report.strongest_gate = report.strongest_gate.max(decision.gate);
        if decision.requires_confirmation() {
            report.confirmation_required = true;
            first_confirmation_index.get_or_insert(index);
        }
        if decision.idempotency_required {
            report.idempotency_required = true;
            first_idempotency_index.get_or_insert(index);
        }
    }
    let missing_confirmation = report.confirmation_required && !body.confirmed;
    let missing_idempotency = report.idempotency_required && body.idempotency_key.is_none();
    if missing_confirmation || missing_idempotency {
        let denied_action_index = match (missing_confirmation, missing_idempotency) {
            (true, true) => match (first_confirmation_index, first_idempotency_index) {
                (Some(confirmation_index), Some(idempotency_index)) => {
                    confirmation_index.min(idempotency_index)
                }
                (Some(confirmation_index), None) => confirmation_index,
                (None, Some(idempotency_index)) => idempotency_index,
                (None, None) => 0,
            },
            (true, false) => first_confirmation_index.unwrap_or_default(),
            (false, true) => first_idempotency_index.unwrap_or_default(),
            (false, false) => unreachable!("policy denial requires at least one reason"),
        };
        let denied_action_kind = body
            .batch
            .actions
            .get(denied_action_index)
            .map(action_kind)
            .unwrap_or("batch");
        let reason = match (missing_confirmation, missing_idempotency) {
            (true, true) => {
                "requires human confirmation and idempotency_key before execution".to_string()
            }
            (true, false) => "requires human confirmation before execution".to_string(),
            (false, true) => "requires idempotency_key before execution".to_string(),
            (false, false) => unreachable!("policy denial requires at least one reason"),
        };
        return Err(TempodError::PolicyDenied(Box::new(PolicyDeniedError {
            reason,
            denied_action_index,
            denied_action_kind,
            policy: report,
        })));
    }
    Ok(report)
}

fn action_requires_external_taint_floor(action: &Action) -> bool {
    match action {
        Action::Goto { .. }
        | Action::Scroll { .. }
        | Action::Wait { .. }
        | Action::Extract { .. } => false,
        Action::Click { .. }
        | Action::Type { .. }
        | Action::Select { .. }
        | Action::Skill { .. } => true,
    }
}

fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::Goto { .. } => "goto",
        Action::Click { .. } => "click",
        Action::Type { .. } => "type",
        Action::Select { .. } => "select",
        Action::Scroll { .. } => "scroll",
        Action::Wait { .. } => "wait",
        Action::Extract { .. } => "extract",
        Action::Skill { .. } => "skill",
    }
}

fn tempod_navigation_url_policy_denial(policy: &UrlPolicy, url: &str) -> Option<String> {
    policy
        .enforce(url)
        .err()
        .map(|error| format!("navigation URL denied by tempod URL policy: {error}"))
}

fn tempod_resolved_navigation_url_policy_denial(policy: &UrlPolicy, url: &str) -> Option<String> {
    if let Some(message) = tempod_navigation_url_policy_denial(policy, url) {
        return Some(message);
    }
    if policy == &UrlPolicy::allow_all() {
        return None;
    }
    let sockets = match resolve_navigation_url_sockets(url) {
        Ok(sockets) => sockets,
        Err(reason) => {
            return Some(format!(
                "navigation URL denied by tempod URL policy: {reason}"
            ));
        }
    };
    for socket in sockets {
        if let Err(error) = policy.enforce_resolved_socket(url, socket) {
            return Some(format!(
                "navigation URL denied by tempod URL policy: {error}"
            ));
        }
    }
    None
}

fn resolve_navigation_url_sockets(url: &str) -> Result<Vec<SocketAddr>, String> {
    let parsed = url::Url::parse(url).map_err(|error| format!("invalid URL: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "URL has no port for its scheme".to_string())?;
    let sockets = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve {host}:{port}: {error}"))?
        .collect::<Vec<_>>();
    if sockets.is_empty() {
        return Err(format!("failed to resolve {host}:{port}: no addresses"));
    }
    Ok(sockets)
}

fn enforce_tempod_navigation_url(policy: &UrlPolicy, url: &str) -> Result<(), TempodError> {
    if let Some(message) = tempod_navigation_url_policy_denial(policy, url) {
        return Err(TempodError::Forbidden(message));
    }
    Ok(())
}

fn enforce_batch_navigation_url_policy(
    policy: &UrlPolicy,
    batch: &ActionBatch,
) -> Result<(), TempodError> {
    for (index, action) in batch.actions.iter().enumerate() {
        if let Action::Goto { url } = action
            && let Some(message) = tempod_navigation_url_policy_denial(policy, url)
        {
            return Err(TempodError::Forbidden(format!(
                "action {index} goto {message}"
            )));
        }
    }
    Ok(())
}

fn enforce_tempod_navigation_url_transport(
    policy: &UrlPolicy,
    url: &str,
) -> Result<(), TransportError> {
    if tempod_resolved_navigation_url_policy_denial(policy, url).is_some() {
        return Err(TransportError::UrlBlocked);
    }
    Ok(())
}

fn enforce_action_navigation_url_policy(
    policy: &UrlPolicy,
    action: &Action,
) -> Result<(), TransportError> {
    if let Action::Goto { url } = action {
        enforce_tempod_navigation_url_transport(policy, url)?;
    }
    Ok(())
}

fn enforce_batch_navigation_url_policy_transport(
    policy: &UrlPolicy,
    batch: &ActionBatch,
) -> Result<(), TransportError> {
    for action in &batch.actions {
        enforce_action_navigation_url_policy(policy, action)?;
    }
    Ok(())
}

fn session_act_batch_idempotency_fingerprint(body: &SessionActBatchRequest) -> JsonValue {
    json!({
        "batch": &body.batch,
        "input_tainted": body.input_tainted,
        "confirmed": body.confirmed,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionBatchPolicyReport {
    input_tainted_declared: Option<bool>,
    input_tainted_effective: bool,
    forced_tainted_actions: usize,
    max_side_effect: SideEffect,
    strongest_gate: ConfirmationGate,
    confirmation_required: bool,
    confirmed: bool,
    idempotency_required: bool,
    idempotency_key_provided: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDeniedError {
    reason: String,
    denied_action_index: usize,
    denied_action_kind: &'static str,
    policy: SessionBatchPolicyReport,
}

impl fmt::Display for PolicyDeniedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "policy denied: {} at action {} ({}); input_tainted={}",
            self.reason,
            self.denied_action_index,
            self.denied_action_kind,
            self.policy.input_tainted_effective
        )
    }
}

impl std::error::Error for PolicyDeniedError {}

fn step_outcome_response(outcome: StepOutcome, policy: SessionBatchPolicyReport) -> JsonValue {
    let policy = session_batch_policy_json(&policy);
    match outcome {
        StepOutcome::Applied { diff } => json!({
            "status": "applied",
            "diff": diff,
            "policy": policy,
        }),
        StepOutcome::StepError { reason } => json!({
            "status": "step_error",
            "reason": reason,
            "policy": policy,
        }),
    }
}

fn session_act_batch_unknown_outcome_response(policy: &SessionBatchPolicyReport) -> JsonValue {
    json!({
        "status": "unknown_outcome",
        "reason": "act_batch execution is already in progress for this idempotency_key; retry with the same request to replay the terminal result",
        "policy": session_batch_policy_json(policy),
    })
}

fn policy_denied_error_json(error: &PolicyDeniedError) -> JsonValue {
    json!({
        "error": error.to_string(),
        "reason": &error.reason,
        "denied_action_index": error.denied_action_index,
        "denied_action_kind": error.denied_action_kind,
        "policy": session_batch_policy_json(&error.policy),
    })
}

fn session_batch_policy_json(policy: &SessionBatchPolicyReport) -> JsonValue {
    json!({
        "input_tainted_declared": policy.input_tainted_declared,
        "input_tainted_effective": policy.input_tainted_effective,
        "forced_tainted_actions": policy.forced_tainted_actions,
        "max_side_effect": policy.max_side_effect,
        "strongest_gate": confirmation_gate_name(policy.strongest_gate),
        "confirmation_required": policy.confirmation_required,
        "confirmed": policy.confirmed,
        "idempotency_required": policy.idempotency_required,
        "idempotency_key_provided": policy.idempotency_key_provided,
    })
}

fn confirmation_gate_name(gate: ConfirmationGate) -> &'static str {
    match gate {
        ConfirmationGate::None => "none",
        ConfirmationGate::Confirm => "confirm",
        ConfirmationGate::ConfirmWithTaintReview => "confirm_with_taint_review",
    }
}

pub fn tempod_openapi(base_url: &str) -> JsonValue {
    let base_url = base_url.trim_end_matches('/');
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "tempo tempod control plane",
            "version": env!("CARGO_PKG_VERSION")
        },
        "servers": [{"url": base_url}],
        "paths": {
            "/health": {
                "get": {
                    "operationId": "health",
                    "responses": {"200": {"description": "tempod is reachable"}}
                }
            },
            TEMPOD_OPENAPI_PATH: {
                "get": {
                    "operationId": "openapi",
                    "responses": {"200": {"description": "OpenAPI 3.1 document"}}
                }
            },
            "/sessions": {
                "get": {
                    "operationId": "listSessions",
                    "responses": {"200": {"description": "List sessions"}}
                },
                "post": {
                    "operationId": "createSession",
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateSessionRequest"}}}
                    },
                    "responses": {"201": {"description": "Created session"}}
                }
            },
            "/sessions/{session_id}/observe": {
                "get": {
                    "operationId": "observeSession",
                    "parameters": [{"$ref": "#/components/parameters/SessionId"}],
                    "responses": {"200": {"description": "Compiled observation"}}
                }
            },
            "/sessions/{session_id}/act_batch": {
                "post": {
                    "operationId": "actBatchSession",
                    "parameters": [{"$ref": "#/components/parameters/SessionId"}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SessionActBatchRequest"}}}
                    },
                    "responses": {
                        "200": {"description": "Action batch outcome"},
                        "403": {"description": "Policy denied"},
                        "409": {"description": "Idempotency conflict"}
                    }
                }
            },
            "/mcp": {
                "get": {"operationId": "mcpGet", "responses": {"200": {"description": "MCP metadata"}}},
                "post": {"operationId": "mcpPost", "responses": {"200": {"description": "MCP JSON-RPC response"}}}
            }
        },
        "components": {
            "parameters": {
                "SessionId": {
                    "name": "session_id",
                    "in": "path",
                    "required": true,
                    "schema": {"type": "string"}
                }
            },
            "schemas": {
                "CreateSessionRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["url"],
                    "properties": {"url": {"type": "string", "format": "uri"}}
                },
                "SessionActBatchRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["batch"],
                    "properties": {
                        "batch": {"type": "object"},
                        "input_tainted": {"type": "boolean"},
                        "confirmed": {"type": "boolean", "default": false},
                        "idempotency_key": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_IDEMPOTENCY_KEY_BYTES
                        }
                    }
                }
            }
        }
    })
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

#[cfg(test)]
fn websocket_upgrade_key(request: &HttpRequest) -> Result<Option<String>, TempodError> {
    websocket_upgrade_key_with_auth(request, &TempodAuth::disabled())
}

fn websocket_upgrade_key_with_auth(
    request: &HttpRequest,
    auth: &TempodAuth,
) -> Result<Option<String>, TempodError> {
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
    auth.authorize(request)?;
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
            | ("GET", TEMPOD_OPENAPI_PATH)
            | ("GET", "/mcp")
            | ("POST", "/mcp")
            | ("GET", "/bidi")
            | ("POST", "/bidi")
    )
}

fn route_requires_auth(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "/mcp") | ("POST", "/mcp") | ("GET", "/bidi") | ("POST", "/bidi")
    ) || control_route_requires_origin_check(method, path)
}

fn bind_addr_is_loopback(addr: &str) -> Result<bool, TempodError> {
    let addrs = addr.to_socket_addrs()?;
    let mut saw_addr = false;
    for addr in addrs {
        saw_addr = true;
        if !addr.ip().is_loopback() {
            return Ok(false);
        }
    }
    if saw_addr {
        Ok(true)
    } else {
        Err(TempodError::BadRequest(
            "bind address did not resolve".into(),
        ))
    }
}

fn validate_bearer_token(token: &str) -> Result<(), TempodError> {
    if token.is_empty() {
        return Err(TempodError::BadRequest("auth token is required".into()));
    }
    if token.trim() != token
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(TempodError::BadRequest(
            "auth token must not contain whitespace or control characters".into(),
        ));
    }
    Ok(())
}

fn authorization_bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim() != token {
        return None;
    }
    validate_bearer_token(token).ok()?;
    Some(token)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
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
    _websocket_permit: ConnectionPermit,
) -> Result<(), TempodError> {
    loop {
        let Some(frame) = read_websocket_frame(&mut stream)? else {
            return Ok(());
        };
        match frame.opcode {
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                // Commands are dispatched without holding the pool lock across
                // engine round-trips (issue #230); this connection still
                // processes its own frames strictly in order.
                let messages = route_bidi_websocket(pool, frame.payload);
                for message in messages {
                    let payload = bidi_message_payload(&message)?;
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
    // Server-to-client frame header is at most 10 bytes (no mask): build it on
    // the stack instead of allocating a Vec per frame.
    let mut header = [0_u8; 10];
    header[0] = 0x80 | (opcode & 0x0f);
    let header_len = if payload.len() < 126 {
        header[1] = payload.len() as u8;
        2
    } else if let Ok(len) = u16::try_from(payload.len()) {
        header[1] = 126;
        header[2..4].copy_from_slice(&len.to_be_bytes());
        4
    } else {
        let len = u64::try_from(payload.len())
            .map_err(|err| TempodError::BadRequest(format!("invalid websocket length: {err}")))?;
        header[1] = 127;
        header[2..10].copy_from_slice(&len.to_be_bytes());
        10
    };

    // Small frames (the common case: BiDi responses/events, pings) go out in
    // one write syscall and one TCP segment. Large payloads keep two writes
    // rather than paying a multi-hundred-KB copy to save one syscall.
    const INLINE_COPY_LIMIT: usize = 8 * 1024;
    if payload.len() <= INLINE_COPY_LIMIT {
        let mut frame = Vec::with_capacity(header_len + payload.len());
        frame.extend_from_slice(&header[..header_len]);
        frame.extend_from_slice(payload);
        stream.write_all(&frame)?;
    } else {
        stream.write_all(&header[..header_len])?;
        stream.write_all(payload)?;
    }
    stream.flush()?;
    Ok(())
}

fn route_bidi(pool: &Arc<Mutex<SessionPool>>, body: Vec<u8>) -> HttpResponse {
    route_bidi_dispatch(pool, body).response
}

fn route_bidi_websocket(pool: &Arc<Mutex<SessionPool>>, body: Vec<u8>) -> Vec<BidiMessage> {
    let dispatch = route_bidi_dispatch(pool, body);
    let mut messages = Vec::with_capacity(1 + dispatch.events.len());
    messages.push(dispatch.message);
    messages.extend(dispatch.events);
    messages
}

fn pool_lock_bidi_error(id: Option<tempo_bidi::CommandId>) -> BidiDispatchResult {
    BidiDispatchResult::new(
        500,
        BidiMessage::error(id, BidiErrorCode::UnknownError, "session pool lock failed"),
    )
}

/// Route one BiDi command. Router bookkeeping and drain/driver admission run
/// under a brief pool lock; driver commands then execute on a cloned
/// per-context handle with the lock released (issue #230), so commands on
/// different browsing contexts run concurrently while the per-context
/// [`OpGate`] keeps same-context commands ordered.
fn route_bidi_dispatch(pool: &Arc<Mutex<SessionPool>>, body: Vec<u8>) -> BidiDispatchResult {
    let (id, command) = {
        let Ok(mut pool) = pool.lock() else {
            return pool_lock_bidi_error(None);
        };
        match pool.bidi.route_json(&body) {
            Ok(RoutedCommand::Immediate(message)) => return BidiDispatchResult::new(200, message),
            Ok(RoutedCommand::SessionStarted(message)) => {
                pool.start_bidi_session();
                return BidiDispatchResult::new(200, message);
            }
            Ok(RoutedCommand::SessionEnded(message)) => {
                pool.end_bidi_session();
                return BidiDispatchResult::new(200, message);
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
                (id, command)
            }
            Err(error) => {
                return BidiDispatchResult::new(
                    400,
                    BidiMessage::error(None, BidiErrorCode::InvalidArgument, error.to_string()),
                )
            }
        }
    };
    route_bidi_driver(pool, id, command)
}

/// Clone the driver handle for a BiDi context under a brief pool lock.
fn bidi_driver_handle(
    pool: &Arc<Mutex<SessionPool>>,
    context: &BrowsingContextId,
) -> Result<Option<AttachedEngineDriver>, TempodError> {
    Ok(lock_pool(pool)?.bidi_driver_for(context))
}

fn route_bidi_driver(
    pool: &Arc<Mutex<SessionPool>>,
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
            let Ok(handle) = bidi_driver_handle(pool, &context) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            let url = command.url.clone();
            // Engine round-trip runs with NO pool lock held (issue #230);
            // `driver` is a clone sharing the context's connection + op gate.
            match futures::executor::block_on(driver.goto(&url)) {
                Ok(_) => {
                    let events = match lock_pool(pool) {
                        Ok(pool) => browsing_context_navigation_events(&pool, id, &context, &url),
                        Err(_) => Vec::new(),
                    };
                    BidiDispatchResult::with_events(
                        200,
                        bidi_success_or_error(
                            id,
                            NavigateResult {
                                navigation: Some(format!("tempo-navigation-{id}")),
                                url: url.clone(),
                            },
                        ),
                        events,
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
            let Ok(handle) = bidi_driver_handle(pool, &root) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            match futures::executor::block_on(driver.observe()) {
                Ok(observation) => BidiDispatchResult::new(
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
                ),
                Err(error) => BidiDispatchResult::new(
                    200,
                    BidiMessage::error(Some(id), BidiErrorCode::UnknownError, error.to_string()),
                ),
            }
        }
        BidiDriverCommand::CaptureScreenshot(_) => {
            let context = screenshot_context(&command);
            let Ok(handle) = bidi_driver_handle(pool, &context) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            match futures::executor::block_on(driver.screenshot()) {
                Ok(bytes) => {
                    if bytes.len() > MAX_SCREENSHOT_BYTES {
                        return BidiDispatchResult::new(
                            200,
                            BidiMessage::error(
                                Some(id),
                                BidiErrorCode::UnknownError,
                                output_cap_message("screenshot", bytes.len(), MAX_SCREENSHOT_BYTES),
                            ),
                        );
                    }
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
            let reference = command.reference_context.unwrap_or_else(default_context_id);
            // Phase 1: cap check + reference handle under a brief lock.
            let driver = {
                let Ok(pool) = pool.lock() else {
                    return pool_lock_bidi_error(Some(id));
                };
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
                match pool.bidi_driver_for(&reference) {
                    Some(driver) => driver,
                    None => return unknown_browsing_context_result(id),
                }
            };
            let options = BrowsingContextCreateOptions {
                kind: match command.context_type {
                    tempo_bidi::ContextType::Tab => BrowsingContextKind::Tab,
                    tempo_bidi::ContextType::Window => BrowsingContextKind::Window,
                },
                background: command.background,
            };
            let mut driver = driver;
            match futures::executor::block_on(driver.create_browsing_context_attached(options)) {
                Ok(created_driver) => {
                    // Phase 3: register under the lock, re-checking the state
                    // that may have changed during the off-lock round-trip.
                    let Ok(mut pool) = pool.lock() else {
                        return pool_lock_bidi_error(Some(id));
                    };
                    if pool.draining
                        || pool.driver.is_none()
                        || pool.bidi_contexts.len() >= MAX_BIDI_CONTEXTS
                    {
                        // Release the fresh context (bounded) instead of
                        // registering into a pool that can no longer track it.
                        pool.close_removed_bidi_context(created_driver);
                        return BidiDispatchResult::new(
                            200,
                            BidiMessage::error(
                                Some(id),
                                BidiErrorCode::UnknownError,
                                "browsing context could not be registered (limit reached or tempod is draining)",
                            ),
                        );
                    }
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
            let Ok(mut pool) = pool.lock() else {
                return pool_lock_bidi_error(Some(id));
            };
            match pool.bidi_contexts.remove(&context) {
                Some(driver) => {
                    // Release the forked engine-side driver so it is not
                    // leaked; this close is BOUNDED (#200/#205), so holding the
                    // lock across it keeps the established teardown pattern.
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
            let Ok(handle) = bidi_driver_handle(pool, &context) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            let expression = command.expression.clone();
            match futures::executor::block_on(
                driver.evaluate_script(&expression, command.await_promise),
            ) {
                Ok(value) => BidiDispatchResult::new(
                    200,
                    bidi_success_or_error(
                        id,
                        ScriptEvaluateResult {
                            result: value,
                            realm: Some(context.0),
                        },
                    ),
                ),
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
        let (message, response) = capped_bidi_response(status, message);
        Self {
            response,
            message,
            events: events.into_iter().map(capped_bidi_message).collect(),
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

fn capped_bidi_response(status: u16, message: BidiMessage) -> (BidiMessage, HttpResponse) {
    match capped_bidi_payload(message) {
        Ok((message, body)) => (message, HttpResponse::new(status, "application/json", body)),
        Err(error) => (error.clone(), bidi_response_unchecked(status, error)),
    }
}

fn capped_bidi_message(message: BidiMessage) -> BidiMessage {
    match capped_bidi_payload(message) {
        Ok((message, _body)) => message,
        Err(error) => error,
    }
}

fn bidi_message_payload(message: &BidiMessage) -> Result<Vec<u8>, TempodError> {
    let capped = capped_bidi_message(message.clone());
    serde_json::to_vec(&capped).map_err(Into::into)
}

fn capped_bidi_payload(message: BidiMessage) -> Result<(BidiMessage, Vec<u8>), BidiMessage> {
    match serde_json::to_vec(&message) {
        Ok(body) if body.len() <= MAX_PROTOCOL_RESPONSE_BYTES => Ok((message, body)),
        Ok(body) => Err(BidiMessage::error(
            bidi_message_id(&message),
            BidiErrorCode::UnknownError,
            output_cap_message("bidi_response", body.len(), MAX_PROTOCOL_RESPONSE_BYTES),
        )),
        Err(error) => Err(BidiMessage::error(
            bidi_message_id(&message),
            BidiErrorCode::UnknownError,
            error.to_string(),
        )),
    }
}

fn bidi_message_id(message: &BidiMessage) -> Option<tempo_bidi::CommandId> {
    match message {
        BidiMessage::Success { id, .. } => Some(*id),
        BidiMessage::Error { id, .. } => *id,
        BidiMessage::Event { .. } => None,
    }
}

fn bidi_response_unchecked(status: u16, message: BidiMessage) -> HttpResponse {
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

fn route_mcp(pool: &Arc<Mutex<SessionPool>>, request: &HttpRequest) -> HttpResponse {
    // Phase 1 (pool lock, brief): drain admission + MCP server handle clone.
    let server = {
        let Ok(pool) = pool.lock() else {
            return HttpResponse::json(
                500,
                json!({
                    "error": "session pool lock failed",
                }),
            );
        };
        if pool.draining {
            return HttpResponse::json(
                503,
                json!({
                    "error": "tempod is draining; MCP tool calls are not accepted",
                }),
            );
        }
        pool.mcp.clone()
    };
    // Phase 2 (NO pool lock): the tool call. The server itself runs calls on
    // distinct drivers concurrently and serializes same-driver calls, so no
    // process-wide lock stands between two sessions' tool calls (issue #230).
    if let Some(server) = server {
        return HttpResponse::from_mcp(futures::executor::block_on(
            server.handle_post(request.origin.as_deref(), &request.body),
        ));
    }
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
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionActBatchRequest {
    batch: ActionBatch,
    input_tainted: Option<bool>,
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    idempotency_key: Option<String>,
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
            401 => "Unauthorized",
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
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("{0}")]
    PolicyDenied(Box<PolicyDeniedError>),
    #[error("connection limit reached: {0}")]
    ConnectionLimit(String),
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
    #[error("driver unavailable: {0}")]
    DriverUnavailable(String),
    #[error("engine host failed: {0}")]
    Engine(#[from] EngineHostError),
}

impl TempodError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Conflict(_) => 409,
            Self::Forbidden(_) => 403,
            Self::PolicyDenied(_) => 403,
            Self::SessionNotFound(_) | Self::EngineNotFound(_) => 404,
            Self::Draining | Self::ConnectionLimit(_) | Self::DriverUnavailable(_) => 503,
            Self::Io(_) | Self::Json(_) | Self::PoolLock | Self::Driver(_) | Self::Engine(_) => 500,
        }
    }

    fn body(&self) -> JsonValue {
        match self {
            Self::PolicyDenied(error) => policy_denied_error_json(error),
            _ => json!({
                "error": self.to_string(),
            }),
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
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tempo_agent::IdempotencyKey;
    use tempo_driver::TestDriver;
    use tempo_engine_host::{
        serve_driver_connection, DriverRequest, DriverWireError, EngineIpcConnection, RestartPolicy,
    };
    use tempo_schema::{Action, ObservationDiff, QuiescencePolicy};

    type TestResult = Result<(), Box<dyn Error>>;

    /// Test shims (issue #230): production routing takes
    /// `&Arc<Mutex<SessionPool>>` so engine round-trips can run off-lock. These
    /// wrappers keep the many tests written against a bare `&mut SessionPool`
    /// exercising the real routing code: the pool is temporarily moved into a
    /// shared handle for the call and moved back afterwards. (Local fns shadow
    /// the glob-imported production versions.)
    fn with_shared_pool<T>(
        pool: &mut SessionPool,
        run: impl FnOnce(&Arc<Mutex<SessionPool>>) -> T,
    ) -> T {
        let shared = Arc::new(Mutex::new(std::mem::take(pool)));
        let result = run(&shared);
        if let Ok(mutex) = Arc::try_unwrap(shared) {
            match mutex.into_inner() {
                Ok(inner) => *pool = inner,
                Err(poisoned) => *pool = poisoned.into_inner(),
            }
        }
        result
    }

    fn route_http_request(
        pool: &mut SessionPool,
        request: HttpRequest,
    ) -> Result<HttpResponse, TempodError> {
        with_shared_pool(pool, |shared| super::route_http_request(shared, request))
    }

    fn handle_http_request(pool: &mut SessionPool, request: HttpRequest) -> HttpResponse {
        with_shared_pool(pool, |shared| super::handle_http_request(shared, request))
    }

    fn handle_http_request_with_auth(
        pool: &mut SessionPool,
        request: HttpRequest,
        auth: &TempodAuth,
    ) -> HttpResponse {
        with_shared_pool(pool, |shared| {
            super::handle_http_request_with_auth(shared, request, auth)
        })
    }

    fn route_bidi_dispatch(pool: &mut SessionPool, body: Vec<u8>) -> BidiDispatchResult {
        with_shared_pool(pool, |shared| super::route_bidi_dispatch(shared, body))
    }

    fn route_bidi_driver(
        pool: &mut SessionPool,
        id: tempo_bidi::CommandId,
        command: BidiDriverCommand,
    ) -> BidiDispatchResult {
        with_shared_pool(pool, |shared| super::route_bidi_driver(shared, id, command))
    }

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
    fn http_create_session_bounds_wedged_navigation() -> TestResult {
        // Fake engine that creates the session context but NEVER answers the
        // goto, on a raw pair with no read timeout -- a slow/unresponsive
        // navigation target that would otherwise hang create+goto forever while
        // the caller holds the global pool lock (#213).
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-wedged".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-wedged"));
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            // Never respond to the goto: hold the connection open so the create
            // path blocks on the engine round-trip.
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

        let started = std::time::Instant::now();
        let response = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://wedged-nav.test"}"#.to_vec(),
            },
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "session create hung on a wedged navigation target: took {elapsed:?}"
        );
        assert_eq!(
            response.status, 500,
            "wedged navigation should fail session creation, not hang"
        );
        // A timed-out create must not leave a half-created session or a leaked
        // driver behind.
        assert!(pool.list().is_empty());
        assert!(pool.session_drivers.is_empty());

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn wedged_create_does_not_block_concurrent_health_beyond_bound() -> TestResult {
        // Same wedged navigation target as above, but here we prove that while a
        // create is stuck on it a concurrent `GET /health` is delayed only by the
        // bounded create window (approach-A residual) and never indefinitely.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-wedged".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        let pool = Arc::new(Mutex::new(pool));

        // Thread A holds the pool lock across the wedged create. It signals once it
        // owns the lock so the health probe below is guaranteed to contend for it.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let create_pool = Arc::clone(&pool);
        let create = thread::spawn(move || -> Result<u16, String> {
            let mut guard = create_pool
                .lock()
                .map_err(|_| "pool lock poisoned".to_string())?;
            locked_tx
                .send(())
                .map_err(|_| "lock signal failed".to_string())?;
            let response = handle_http_request(
                &mut guard,
                HttpRequest {
                    method: "POST".into(),
                    path: "/sessions".into(),
                    headers: BTreeMap::new(),
                    host: None,
                    origin: None,
                    body: br#"{"url":"https://wedged-nav.test"}"#.to_vec(),
                },
            );
            Ok(response.status)
        });

        locked_rx
            .recv()
            .map_err(|_| "create thread never acquired the pool lock")?;
        let started = std::time::Instant::now();
        let health = {
            let mut guard = pool.lock().map_err(|_| "pool lock poisoned")?;
            route_http_request(
                &mut guard,
                HttpRequest {
                    method: "GET".into(),
                    path: "/health".into(),
                    headers: BTreeMap::new(),
                    host: None,
                    origin: None,
                    body: Vec::new(),
                },
            )?
        };
        let waited = started.elapsed();

        assert_eq!(health.status, 200);
        assert!(
            waited < Duration::from_secs(5),
            "GET /health blocked on the pool lock beyond the create bound: waited {waited:?}"
        );

        let create_status = match create.join() {
            Ok(result) => result.map_err(|error| -> Box<dyn Error> { error.into() })?,
            Err(_) => return Err("create thread panicked".into()),
        };
        assert_eq!(create_status, 500);

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn wedged_create_invalidates_engine_so_followup_request_does_not_deadlock() -> TestResult {
        // A create that times out on a wedged navigation target leaves the
        // detached create worker blocked in `AttachedEngineDriver::request` while
        // holding the shared `Arc<Mutex<EngineIpcClient>>`. If the pool kept the
        // engine attached, a FOLLOW-UP engine-backed request would clone that same
        // wedged client and block FOREVER on the mutex -- reintroducing the exact
        // `/health` / `/drain` stall #213 prevents. The fix detaches the engine on
        // create timeout, so the follow-up returns promptly instead of deadlocking.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let wedged_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-wedged".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            // Never answer the goto: the create worker stays blocked holding the
            // shared engine mutex.
            thread::park_timeout(Duration::from_secs(60));
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

        // First create times out; it must invalidate the shared engine.
        let first = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://wedged-nav.test"}"#.to_vec(),
            },
        );
        assert_eq!(first.status, 500);

        // A follow-up engine-backed request must NOT block on the wedged mutex. We
        // use a `POST /mcp` `observe` -- an UNBOUNDED engine round-trip made under
        // the pool lock via the shared `pool.mcp` driver (unlike create, it is NOT
        // wrapped in `run_create_bounded`). The create worker from the timed-out
        // request is still parked in `AttachedEngineDriver::request` holding the
        // shared engine mutex, so if the engine were still attached this observe
        // would lock the same client and deadlock forever, stalling the pool lock --
        // the exact hazard #213 addresses. Run it on a worker and bound the wait so
        // the regression surfaces here as a timeout failure instead of hanging the
        // whole suite. Against the pre-fix code this `recv_timeout` expires; with the
        // fix the engine (and its MCP fork) is detached, so the request falls through
        // to the driverless MCP path and returns promptly.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let followup = thread::spawn(move || -> (u16, Vec<u8>, SessionPool) {
            let response = route_http_request(
                &mut pool,
                HttpRequest {
                    method: "POST".into(),
                    path: "/mcp".into(),
                    headers: BTreeMap::new(),
                    host: None,
                    origin: Some("http://127.0.0.1".into()),
                    body: br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#.to_vec(),
                },
            );
            let (status, body) = match response {
                Ok(response) => (response.status, response.body),
                Err(error) => (0, error.to_string().into_bytes()),
            };
            let _ = done_tx.send(status);
            (status, body, pool)
        });

        let status = done_rx.recv_timeout(Duration::from_secs(5)).map_err(|_| {
            "follow-up engine-backed request blocked on the wedged engine mutex after \
             a create timeout: the shared engine was not invalidated"
        })?;
        // Engine detached on timeout, so the observe is served by the driverless MCP
        // path (HTTP 200 with a JSON-RPC \"no driver\" error) instead of deadlocking.
        assert_eq!(status, 200);

        let (joined_status, body, pool) = match followup.join() {
            Ok(joined) => joined,
            Err(_) => return Err("follow-up thread panicked".into()),
        };
        assert_eq!(joined_status, 200);
        // Confirm we truly went driverless (engine invalidated), not to the engine.
        let value: Value = serde_json::from_slice(&body)?;
        assert_eq!(value["id"], 42);
        assert_eq!(value["error"]["code"], -32002);
        // The attached engine was invalidated, not merely bypassed: no root driver,
        // no MCP fork, and no leaked session drivers remain to wait on the wedged
        // IPC handle.
        assert!(
            pool.driver.is_none(),
            "attached engine was not invalidated after a create timeout"
        );
        assert!(pool.mcp.is_none());
        assert!(pool.session_drivers.is_empty());
        drop(pool);

        wedged_engine.thread().unpark();
        join_driver_handler(wedged_engine)?;
        Ok(())
    }

    #[test]
    fn create_closes_session_context_that_succeeds_after_timeout() -> TestResult {
        // The detached create worker's `op()` can finish JUST AFTER the caller's
        // `recv_timeout` has already expired (create timed out). In that window the
        // engine DID create+navigate a real browsing context, so `op()` returns
        // `Ok(session_driver)`, but the receiver is gone and `tx.send` fails. If that
        // `Ok(driver)` is dropped on the floor, the freshly-created context is leaked
        // engine-side -- and because the timeout path already invalidated the shared
        // engine, no later pool code owns/closes it. The fix closes the orphaned
        // context on the worker thread; this test asserts the engine receives that
        // `Close`. Against the pre-fix branch no `Close` is ever sent (driver dropped),
        // so the engine blocks awaiting it and the `close_seen` signal never fires.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let late_engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            let create = connection.read_driver_request()?;
            assert!(matches!(
                create.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-late".into(),
                },
            )?;

            let goto = connection.read_driver_request()?;
            assert_eq!(goto.driver_id.as_deref(), Some("session-context-late"));
            assert!(matches!(goto.command, HostDriverCommand::Goto { .. }));
            // Answer the goto only AFTER the create bound (200ms in cfg(test)) has
            // elapsed, so the caller's `recv_timeout` has already returned `None`
            // and the worker's late `Ok(session_driver)` fails to send.
            thread::sleep(Duration::from_millis(400));
            connection.write_driver_response(
                goto.id,
                DriverResponse::Observation {
                    observation: observation("https://late-success.test", 1),
                },
            )?;

            // The orphaned late-success context must be closed, not leaked.
            // Since #230 the abandon path's root `Close` is written on the
            // multiplexed connection as soon as the create times out (it no
            // longer queues behind the in-flight goto), so the engine may see
            // it interleaved before/after the context close. Answer everything
            // and require only that the orphaned CONTEXT receives its Close.
            loop {
                let close = connection.read_driver_request()?;
                assert_eq!(close.command, HostDriverCommand::Close);
                let context_close = close.driver_id.as_deref() == Some("session-context-late");
                connection.write_driver_response(close.id, DriverResponse::Closed)?;
                if context_close {
                    let _ = close_tx.send(());
                    return Ok(());
                }
            }
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

        let started = std::time::Instant::now();
        let response = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://late-success.test"}"#.to_vec(),
            },
        );
        let elapsed = started.elapsed();

        // The caller is released at the bound even though the engine answers later.
        assert!(
            elapsed < Duration::from_secs(5),
            "session create hung past the create bound: took {elapsed:?}"
        );
        assert_eq!(response.status, 500);
        assert!(pool.list().is_empty());
        assert!(pool.session_drivers.is_empty());

        // The worker's late `Ok(session_driver)` must be torn down via `close()`,
        // not dropped. Bound the wait so the pre-fix leak surfaces as a failure
        // here (no `Close` ever arrives) rather than hanging the suite.
        close_rx.recv_timeout(Duration::from_secs(5)).map_err(|_| {
            "create worker that succeeded after the timeout leaked the session \
             context: engine never received a Close for it"
        })?;

        join_driver_handler(late_engine)?;
        Ok(())
    }

    #[test]
    fn wedged_create_closes_pre_existing_session_context_on_invalidation() -> TestResult {
        // Regression for the #213 review leak: when a session context is ALREADY
        // live and a LATER create times out on a wedged navigation, the engine is
        // invalidated. The pre-existing context must receive a best-effort `Close`
        // -- not be dropped silently. The pre-fix `abandon_*` merely `.clear()`ed
        // `session_drivers`/`bidi_contexts`; dropping an `AttachedEngineDriver`
        // sends no `Close`, so the live browsing context leaked engine-side (the
        // maps were cleared, so no later `kill`/BiDi-close could reclaim it).
        // Against the pre-fix branch no `Close` is ever sent for the pre-existing
        // context, so `pre_close_rx` never fires and this test fails. With the fix
        // `abandon_*` delegates to the bounded detached teardown, which `Close`s the
        // pre-existing context once the wedged `goto` frees the shared engine mutex.
        let (client_stream, server_stream) = UnixStream::pair()?;
        let (pre_close_tx, pre_close_rx) = std::sync::mpsc::channel();
        let engine = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);

            // (1) Pre-existing session context: create + goto, both answered, so it
            // is live in `pool.session_drivers` before the wedged create runs.
            let create_pre = connection.read_driver_request()?;
            assert!(create_pre.driver_id.is_none());
            assert!(matches!(
                create_pre.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create_pre.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-pre".into(),
                },
            )?;
            let goto_pre = connection.read_driver_request()?;
            assert_eq!(goto_pre.driver_id.as_deref(), Some("session-context-pre"));
            assert!(matches!(goto_pre.command, HostDriverCommand::Goto { .. }));
            connection.write_driver_response(
                goto_pre.id,
                DriverResponse::Observation {
                    observation: observation("https://pre-existing.test", 1),
                },
            )?;

            // (2) The create that times out: create answered, `goto` answered only
            // AFTER the create bound (200ms in cfg(test)) so the caller's
            // `recv_timeout` expires and invalidates the engine. Answering it late
            // then releases the shared engine mutex so the detached teardown worker
            // can send its best-effort `Close`es for the pre-existing context.
            let create_wedged = connection.read_driver_request()?;
            assert!(matches!(
                create_wedged.command,
                HostDriverCommand::CreateBrowsingContext { .. }
            ));
            connection.write_driver_response(
                create_wedged.id,
                DriverResponse::BrowsingContextCreated {
                    driver_id: "session-context-wedged".into(),
                },
            )?;
            let goto_wedged = connection.read_driver_request()?;
            assert_eq!(
                goto_wedged.driver_id.as_deref(),
                Some("session-context-wedged")
            );
            assert!(matches!(
                goto_wedged.command,
                HostDriverCommand::Goto { .. }
            ));
            thread::sleep(Duration::from_millis(400));
            connection.write_driver_response(
                goto_wedged.id,
                DriverResponse::Observation {
                    observation: observation("https://wedged-nav.test", 2),
                },
            )?;

            // (3) After invalidation, the pre-existing context must be closed. The
            // orphaned wedged context and the root are also closed here; their order
            // is not deterministic, so respond `Closed` to every `Close` and signal
            // when the PRE-EXISTING context's `Close` is observed. Read until the
            // client ends (all engine handles dropped once the closes complete).
            loop {
                let request = match connection.read_driver_request() {
                    Ok(request) => request,
                    Err(_) => break,
                };
                if request.command == HostDriverCommand::Close {
                    if request.driver_id.as_deref() == Some("session-context-pre") {
                        let _ = pre_close_tx.send(());
                    }
                    connection.write_driver_response(request.id, DriverResponse::Closed)?;
                }
            }
            Ok(())
        });

        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

        // Create the pre-existing, live session context.
        let pre = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://pre-existing.test"}"#.to_vec(),
            },
        );
        assert_eq!(pre.status, 201);
        assert_eq!(pool.session_drivers.len(), 1);

        // A second create times out on the wedged navigation and invalidates the
        // shared engine.
        let wedged = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://wedged-nav.test"}"#.to_vec(),
            },
        );
        assert_eq!(wedged.status, 500);
        // Engine invalidated: no root driver / MCP fork / leaked session drivers.
        assert!(
            pool.driver.is_none(),
            "attached engine was not invalidated after a create timeout"
        );
        assert!(pool.mcp.is_none());
        assert!(pool.session_drivers.is_empty());
        assert!(pool.bidi_contexts.is_empty());

        // The KEY assertion: the pre-existing session context must get a best-effort
        // `Close`, not be dropped silently. Bound the wait so the pre-fix leak
        // surfaces as a failure here (no `Close` ever arrives) rather than hanging
        // the suite.
        pre_close_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| {
                "engine invalidation dropped the pre-existing session context without a \
             Close: the live browsing context was leaked engine-side"
            })?;

        drop(pool);
        join_driver_handler(engine)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Issue #230: end-to-end concurrency tests. All of them drive the daemon
    // over real TCP against a fake engine that answers each driver request on
    // its own worker thread (delayed, wedged, or out of order), because the
    // whole point is that the DAEMON must no longer serialize independent
    // browser operations.
    // ------------------------------------------------------------------

    enum FakeEngineReply {
        Respond(DriverResponse),
        RespondAfter(Duration, DriverResponse),
        /// Never answer this request (the wedged-engine case).
        Wedge,
    }

    /// Serve driver requests concurrently: one reader thread, one detached
    /// worker per request, writes serialized by a mutex. Returns after wiring
    /// the threads; they exit when the daemon side closes the connection.
    fn spawn_concurrent_fake_engine<H>(server_stream: UnixStream, handler: H) -> TestResult
    where
        H: Fn(&DriverRequest) -> FakeEngineReply + Send + Sync + 'static,
    {
        let writer = Arc::new(Mutex::new(EngineIpcConnection::from_stream(
            server_stream.try_clone()?,
        )));
        let mut reader = EngineIpcConnection::from_stream(server_stream);
        let handler = Arc::new(handler);
        thread::spawn(move || loop {
            let request = match reader.read_driver_request() {
                Ok(request) => request,
                Err(_) => return,
            };
            let writer = Arc::clone(&writer);
            let handler = Arc::clone(&handler);
            thread::spawn(move || {
                let (delay, response) = match handler(&request) {
                    FakeEngineReply::Respond(response) => (Duration::ZERO, response),
                    FakeEngineReply::RespondAfter(delay, response) => (delay, response),
                    FakeEngineReply::Wedge => return,
                };
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                if let Ok(mut writer) = writer.lock() {
                    let _ = writer.write_driver_response(request.id, response);
                }
            });
        });
        Ok(())
    }

    /// Pool with an attached concurrent fake engine, shared for TCP serving.
    fn shared_pool_with_fake_engine<H>(
        handler: H,
    ) -> Result<Arc<Mutex<SessionPool>>, Box<dyn Error>>
    where
        H: Fn(&DriverRequest) -> FakeEngineReply + Send + Sync + 'static,
    {
        let (client_stream, server_stream) = UnixStream::pair()?;
        spawn_concurrent_fake_engine(server_stream, handler)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        Ok(Arc::new(Mutex::new(pool)))
    }

    type ServerHandles = Vec<thread::JoinHandle<Result<(), TempodError>>>;

    /// Spawn `count` single-request server threads accepting on one listener.
    fn spawn_servers(
        listener: &TcpListener,
        pool: &Arc<Mutex<SessionPool>>,
        count: usize,
    ) -> Result<ServerHandles, Box<dyn Error>> {
        let mut handles = Vec::with_capacity(count);
        for _ in 0..count {
            let listener = listener.try_clone()?;
            let pool = Arc::clone(pool);
            handles.push(thread::spawn(move || serve_one(listener, pool)));
        }
        Ok(handles)
    }

    fn http_post(
        addr: std::net::SocketAddr,
        path: &str,
        body: &str,
    ) -> Result<String, std::io::Error> {
        send_http(
            addr,
            &format!(
                "POST {path} HTTP/1.1\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    }

    fn bidi_navigate_body(id: u64, context: &str, url: &str) -> String {
        format!(
            r#"{{"id":{id},"method":"browsingContext.navigate","params":{{"context":"{context}","url":"{url}","inputTainted":false}}}}"#
        )
    }

    /// (a-1) Two POST /sessions whose navigations each take ~120ms (inside the
    /// 200ms cfg(test) create bound) must overlap. Overlap is proven by the
    /// engine-side arrival times: the second create's goto reaches the engine
    /// while the first goto is still pending. Reverted to pre-#230 locking
    /// (pool lock held across the create round-trips), the second create's
    /// frames cannot arrive until the first create finished (>=120ms gap) and
    /// this fails.
    #[test]
    fn concurrent_session_creates_overlap_across_sessions() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let context_ids = AtomicUsize::new(1);
        let goto_arrivals: Arc<Mutex<Vec<std::time::Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let arrivals = Arc::clone(&goto_arrivals);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::CreateBrowsingContext { .. } => {
                let n = context_ids.fetch_add(1, Ordering::SeqCst);
                FakeEngineReply::Respond(DriverResponse::BrowsingContextCreated {
                    driver_id: format!("session-context-{n}"),
                })
            }
            HostDriverCommand::Goto { url } => {
                if let Ok(mut arrivals) = arrivals.lock() {
                    arrivals.push(std::time::Instant::now());
                }
                FakeEngineReply::RespondAfter(
                    Duration::from_millis(120),
                    DriverResponse::Observation {
                        observation: observation(url, 1),
                    },
                )
            }
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 2)?;

        let started = std::time::Instant::now();
        let first =
            thread::spawn(move || http_post(addr, "/sessions", r#"{"url":"https://one.test"}"#));
        let second =
            thread::spawn(move || http_post(addr, "/sessions", r#"{"url":"https://two.test"}"#));
        let first = first.join().map_err(|_| "first create panicked")??;
        let second = second.join().map_err(|_| "second create panicked")??;
        let elapsed = started.elapsed();

        assert!(first.starts_with("HTTP/1.1 201"), "{first}");
        assert!(second.starts_with("HTTP/1.1 201"), "{second}");
        // Loose wall-clock sanity (serial would be >=240ms plus overhead).
        assert!(
            elapsed < Duration::from_millis(2000),
            "session creates took unexpectedly long: {elapsed:?}"
        );
        let arrivals = goto_arrivals
            .lock()
            .map_err(|_| "arrival log poisoned")?
            .clone();
        assert_eq!(arrivals.len(), 2);
        let gap = arrivals[1].duration_since(arrivals[0]);
        assert!(
            gap < Duration::from_millis(60),
            "second session's navigation reached the engine {gap:?} after the first: \
             creates were serialized (>=120ms gap) instead of overlapping"
        );
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (a-2) The literal #230 acceptance shape: two ~300ms browser operations
    /// on two different browsing contexts complete in <500ms total. Reverted
    /// to one-op-at-a-time dispatch they serialize to >=600ms and this fails.
    #[test]
    fn two_slow_ops_on_different_contexts_complete_in_parallel() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let context_ids = AtomicUsize::new(1);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::CreateBrowsingContext { .. } => {
                let n = context_ids.fetch_add(1, Ordering::SeqCst);
                FakeEngineReply::Respond(DriverResponse::BrowsingContextCreated {
                    driver_id: format!("context-{n}"),
                })
            }
            HostDriverCommand::Goto { url } => FakeEngineReply::RespondAfter(
                Duration::from_millis(300),
                DriverResponse::Observation {
                    observation: observation(url, 1),
                },
            ),
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 3)?;

        let created = http_post(
            addr,
            "/bidi",
            r#"{"id":1,"method":"browsingContext.create","params":{"type":"tab"}}"#,
        )?;
        assert!(created.contains(r#""type":"success""#), "{created}");

        let started = std::time::Instant::now();
        let first = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(2, "tempo-root", "https://one.test"),
            )
        });
        let second = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(3, "tempo-bidi-1", "https://two.test"),
            )
        });
        let first = first.join().map_err(|_| "first navigate panicked")??;
        let second = second.join().map_err(|_| "second navigate panicked")??;
        let elapsed = started.elapsed();

        assert!(first.contains(r#""type":"success""#), "{first}");
        assert!(second.contains(r#""type":"success""#), "{second}");
        assert!(
            elapsed < Duration::from_millis(500),
            "two ~300ms ops on different contexts did not run concurrently: {elapsed:?} \
             (serial would be >=600ms)"
        );
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (b) Two navigations on the SAME context must stay ordered: the second
    /// must not reach the engine until the first one's response returned.
    /// Reverted to a daemon without the per-context gate, both gotos arrive
    /// within milliseconds of each other and this fails.
    #[test]
    fn same_context_navigations_stay_serialized() -> TestResult {
        let goto_arrivals: Arc<Mutex<Vec<std::time::Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let arrivals = Arc::clone(&goto_arrivals);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::Goto { url } => {
                if let Ok(mut arrivals) = arrivals.lock() {
                    arrivals.push(std::time::Instant::now());
                }
                FakeEngineReply::RespondAfter(
                    Duration::from_millis(250),
                    DriverResponse::Observation {
                        observation: observation(url, 1),
                    },
                )
            }
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 2)?;

        let first = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(1, "tempo-root", "https://first.test"),
            )
        });
        thread::sleep(Duration::from_millis(60));
        let second = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(2, "tempo-root", "https://second.test"),
            )
        });
        let first = first.join().map_err(|_| "first navigate panicked")??;
        let second = second.join().map_err(|_| "second navigate panicked")??;
        assert!(first.contains(r#""type":"success""#), "{first}");
        assert!(second.contains(r#""type":"success""#), "{second}");

        let arrivals = goto_arrivals
            .lock()
            .map_err(|_| "arrival log poisoned")?
            .clone();
        assert_eq!(arrivals.len(), 2);
        let gap = arrivals[1].duration_since(arrivals[0]);
        assert!(
            gap >= Duration::from_millis(150),
            "second same-context goto reached the engine {gap:?} after the first; \
             it must wait for the first response (~250ms): per-session ordering was lost"
        );
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (c) /health and /drain must answer while an engine operation is in
    /// flight (the #200/#213 availability family, now for the op hot path).
    /// Reverted to pool-lock-across-round-trip routing, the health probe waits
    /// out the 800ms navigation and this fails.
    #[test]
    fn health_and_drain_respond_while_engine_op_is_in_flight() -> TestResult {
        let pool = shared_pool_with_fake_engine(|request| match &request.command {
            HostDriverCommand::Goto { url } => FakeEngineReply::RespondAfter(
                Duration::from_millis(800),
                DriverResponse::Observation {
                    observation: observation(url, 1),
                },
            ),
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 3)?;

        let navigate = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(1, "tempo-root", "https://slow.test"),
            )
        });
        thread::sleep(Duration::from_millis(150));

        let started = std::time::Instant::now();
        let health = send_http(addr, "GET /health HTTP/1.1\r\n\r\n")?;
        let health_latency = started.elapsed();
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
        assert!(
            health_latency < Duration::from_millis(300),
            "GET /health queued behind an in-flight engine op: {health_latency:?}"
        );

        let started = std::time::Instant::now();
        let drain = http_post(addr, "/drain", "")?;
        let drain_latency = started.elapsed();
        assert!(drain.starts_with("HTTP/1.1 200"), "{drain}");
        assert!(drain.contains(r#""draining":true"#), "{drain}");
        assert!(
            drain_latency < Duration::from_secs(3),
            "POST /drain queued behind an in-flight engine op: {drain_latency:?}"
        );

        let _ = navigate.join().map_err(|_| "navigate thread panicked")?;
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (d) Drain while two operations are mid-flight on different contexts:
    /// drain must complete promptly and the daemon must stay consistent.
    #[test]
    fn drain_completes_cleanly_during_concurrent_ops() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let context_ids = AtomicUsize::new(1);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::CreateBrowsingContext { .. } => {
                let n = context_ids.fetch_add(1, Ordering::SeqCst);
                FakeEngineReply::Respond(DriverResponse::BrowsingContextCreated {
                    driver_id: format!("context-{n}"),
                })
            }
            HostDriverCommand::Goto { url } => FakeEngineReply::RespondAfter(
                Duration::from_millis(300),
                DriverResponse::Observation {
                    observation: observation(url, 1),
                },
            ),
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        // Exactly four requests: create-context, two navigations, drain.
        let servers = spawn_servers(&listener, &pool, 4)?;

        // A second context so the two in-flight ops target different sessions.
        let created = http_post(
            addr,
            "/bidi",
            r#"{"id":1,"method":"browsingContext.create","params":{"type":"tab"}}"#,
        )?;
        assert!(created.contains(r#""type":"success""#), "{created}");

        let nav_root = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(2, "tempo-root", "https://root.test"),
            )
        });
        let nav_fork = thread::spawn(move || {
            http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(3, "tempo-bidi-1", "https://fork.test"),
            )
        });
        thread::sleep(Duration::from_millis(100));

        let started = std::time::Instant::now();
        let drain = http_post(addr, "/drain", "")?;
        assert!(drain.starts_with("HTTP/1.1 200"), "{drain}");
        assert!(drain.contains(r#""draining":true"#), "{drain}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "drain stalled behind concurrent in-flight ops"
        );

        // The in-flight ops must resolve (success or error, but never hang).
        let _ = nav_root.join().map_err(|_| "root navigate panicked")?;
        let _ = nav_fork.join().map_err(|_| "fork navigate panicked")?;
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (#305 review blocker) An MCP `fork` in flight when `/drain` fires must
    /// not leak the forked browsing context: the fork's engine round-trip can
    /// complete AFTER drain's `close_all_forks` snapshot, so the retired MCP
    /// fork registry refuses the late registration and the tool call closes
    /// its own fork. Reverted, the engine never receives a Close for the late
    /// fork and the recv below times out.
    #[test]
    fn mcp_fork_in_flight_across_drain_is_closed_not_leaked() -> TestResult {
        let (fork_closed_tx, fork_closed_rx) = std::sync::mpsc::channel();
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::Fork => FakeEngineReply::RespondAfter(
                Duration::from_millis(300),
                DriverResponse::Forked {
                    driver_id: "fork-1".into(),
                },
            ),
            HostDriverCommand::Close if request.driver_id.as_deref() == Some("fork-1") => {
                let _ = fork_closed_tx.send(());
                FakeEngineReply::Respond(DriverResponse::Closed)
            }
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 2)?;

        let fork_call = thread::spawn(move || {
            http_post(
                addr,
                "/mcp",
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fork","arguments":{}}}"#,
            )
        });
        // Drain while the fork's engine round-trip is still in flight.
        thread::sleep(Duration::from_millis(100));
        let drain = http_post(addr, "/drain", "")?;
        assert!(drain.starts_with("HTTP/1.1 200"), "{drain}");

        // The late fork must be closed engine-side, not leaked.
        fork_closed_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| {
                "fork completing after the drain snapshot was never closed: \
             the forked browsing context leaked engine-side"
            })?;
        let fork_response = fork_call.join().map_err(|_| "fork call panicked")??;
        assert!(
            fork_response.contains("shut down"),
            "late fork must be refused after drain: {fork_response}"
        );
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
        Ok(())
    }

    /// (e) A wedged operation on context A (engine never answers) must not
    /// block operations on context B. Reverted to shared-client/pool-lock
    /// serialization, B queues behind A's 30s IPC timeout and this fails.
    #[test]
    fn wedged_op_on_one_context_does_not_block_another() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let context_ids = AtomicUsize::new(1);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::CreateBrowsingContext { .. } => {
                let n = context_ids.fetch_add(1, Ordering::SeqCst);
                FakeEngineReply::Respond(DriverResponse::BrowsingContextCreated {
                    driver_id: format!("context-{n}"),
                })
            }
            HostDriverCommand::Goto { url } if url.contains("wedged") => FakeEngineReply::Wedge,
            HostDriverCommand::Goto { url } => FakeEngineReply::RespondAfter(
                Duration::from_millis(50),
                DriverResponse::Observation {
                    observation: observation(url, 1),
                },
            ),
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 2)?;

        let created = http_post(
            addr,
            "/bidi",
            r#"{"id":1,"method":"browsingContext.create","params":{"type":"tab"}}"#,
        )?;
        assert!(created.contains(r#""type":"success""#), "{created}");

        // Context A wedges forever (its request thread stays parked on the
        // bounded IPC wait; never joined).
        let wedged_listener = listener.try_clone()?;
        let wedged_pool = Arc::clone(&pool);
        thread::spawn(move || serve_one(wedged_listener, wedged_pool));
        thread::spawn(move || {
            let _ = http_post(
                addr,
                "/bidi",
                &bidi_navigate_body(2, "tempo-root", "https://wedged.test"),
            );
        });
        thread::sleep(Duration::from_millis(150));

        // Context B must complete promptly regardless.
        let started = std::time::Instant::now();
        let fast = http_post(
            addr,
            "/bidi",
            &bidi_navigate_body(3, "tempo-bidi-1", "https://fast.test"),
        )?;
        let latency = started.elapsed();
        assert!(fast.contains(r#""type":"success""#), "{fast}");
        assert!(
            latency < Duration::from_secs(2),
            "op on context B queued behind wedged context A: {latency:?}"
        );
        for server in servers {
            server.join().map_err(|_| "server thread panicked")??;
        }
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
    fn bidi_response_serialization_is_capped() -> TestResult {
        let result = BidiDispatchResult::new(
            200,
            BidiMessage::Success {
                id: 77,
                result: json!({"blob": "x".repeat(MAX_PROTOCOL_RESPONSE_BYTES)}),
            },
        );
        let value: Value = serde_json::from_slice(&result.response.body)?;

        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 77);
        assert_eq!(value["error"], "unknown error");
        assert!(value["message"]
            .as_str()
            .ok_or("BiDi cap error should include a message")?
            .contains("bidi_response exceeded output cap"));
        Ok(())
    }

    #[test]
    fn bidi_endpoint_rejects_oversized_screenshot_bytes_before_base64() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.command, HostDriverCommand::Screenshot);
            DriverResponse::Screenshot {
                bytes: vec![0_u8; MAX_SCREENSHOT_BYTES + 1],
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
                body: br#"{"id":31,"method":"browsingContext.captureScreenshot","params":{"context":"tempo-root"}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 31);
        assert_eq!(value["error"], "unknown error");
        assert!(value["message"]
            .as_str()
            .ok_or("BiDi screenshot cap error should include a message")?
            .contains("screenshot exceeded output cap"));
        Ok(())
    }

    #[test]
    fn bidi_endpoint_rejects_script_without_input_taint_evidence() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        let driver = pool.driver.as_ref().ok_or("attached root driver missing")?;
        pool.bidi_contexts.insert(
            BrowsingContextId("wedged-bidi-fork".into()),
            driver.derived("fork-1".into()),
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
            AttachedEngineDriver::new(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?
                .derived("context-wedged".to_string()),
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
            AttachedEngineDriver::new(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        // Issue #214 review: secret-bearing fields (typed text, node ids) are
        // replaced with a constant marker (never a hash), and URL secrets are
        // stripped, while non-sensitive fields remain for telemetry.
        let root = unique_dir("otlp-redact")?;
        remove_dir_if_exists(&root)?;

        let typed_path = root.join("typed.jsonl");
        let secret = "hunter2-super-secret-password";
        // A selector-backed node id that itself embeds a page secret (High
        // finding): it must be redacted, not exported verbatim or hashed.
        let node_selector = "a[href=\"/reset?token=SECRET123\"]";
        let typed = StepTriple {
            key: IdempotencyKey("step-type".into()),
            seq: 5,
            action: Action::Type {
                node: NodeId(node_selector.into()),
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
        assert!(
            !typed_text.contains("SECRET123"),
            "secret embedded in a selector-backed node id must not leak"
        );
        assert!(
            !typed_text.contains("sha256:"),
            "no dictionary-searchable hash may be emitted"
        );
        let typed_value: Value = serde_json::from_str(typed_text.trim_end())?;
        assert_eq!(typed_value["body"]["action"]["kind"], "type");
        assert_eq!(typed_value["body"]["action"]["text"], REDACTED_MARKER);
        assert_eq!(typed_value["body"]["action"]["node"], REDACTED_MARKER);
        assert_eq!(typed_value["body"]["seq"], 5);

        let goto_path = root.join("goto.jsonl");
        let goto = StepTriple {
            // Arbitrary caller-supplied key (public/deserializable type): it must
            // be redacted, never exported verbatim (issue #214 review, medium).
            key: IdempotencyKey("secret-key-SECRET123".into()),
            seq: 6,
            action: Action::Goto {
                // Secret in the PATH plus userinfo/query/fragment: none may leak.
                url: "https://user:pass@example.test/reset/SECRET123?token=T#frag".into(),
            },
            outcome: StepTripleOutcome::StepError {
                reason: "boom".into(),
            },
        };
        OtlpJsonExporter::new(&goto_path).export_step(&goto)?;
        let goto_text = String::from_utf8(std::fs::read(&goto_path)?)?;
        assert!(
            !goto_text.contains("SECRET123"),
            "URL path secret (and userinfo) must not leak"
        );
        assert!(
            !goto_text.contains("user:"),
            "URL userinfo must be stripped entirely"
        );
        assert!(
            !goto_text.contains("token=T"),
            "URL query secret must be stripped"
        );
        assert!(
            !goto_text.contains("/reset"),
            "URL path must not be exported"
        );
        assert!(
            !goto_text.contains("sha256:"),
            "no dictionary-searchable hash may be emitted"
        );
        let goto_value: Value = serde_json::from_str(goto_text.trim_end())?;
        // The idempotency key is redacted, not written verbatim.
        assert_eq!(goto_value["body"]["key"], REDACTED_MARKER);
        assert_eq!(goto_value["body"]["action"]["kind"], "goto");
        // Only the origin plus non-sensitive shape metadata is exported.
        assert_eq!(
            goto_value["body"]["action"]["url"]["origin"],
            "https://example.test"
        );
        assert_eq!(goto_value["body"]["action"]["url"]["path_segments"], 2);
        assert_eq!(goto_value["body"]["action"]["url"]["has_query"], true);
        assert_eq!(goto_value["body"]["action"]["url"]["has_fragment"], true);

        // A URL with an explicit non-default port keeps `host:port` in the
        // origin, and userinfo is dropped.
        let port_path = root.join("goto-port.jsonl");
        let port_goto = StepTriple {
            key: IdempotencyKey("step-goto-port".into()),
            seq: 7,
            action: Action::Goto {
                url: "https://user:pass@example.test:8443/a/b".into(),
            },
            outcome: StepTripleOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: 6,
                    seq: 7,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
        };
        OtlpJsonExporter::new(&port_path).export_step(&port_goto)?;
        let port_text = String::from_utf8(std::fs::read(&port_path)?)?;
        assert!(
            !port_text.contains("user:"),
            "URL userinfo must be stripped from a port-bearing URL"
        );
        let port_value: Value = serde_json::from_str(port_text.trim_end())?;
        assert_eq!(
            port_value["body"]["action"]["url"]["origin"],
            "https://example.test:8443"
        );
        assert_eq!(port_value["body"]["action"]["url"]["path_segments"], 2);
        assert_eq!(port_value["body"]["action"]["url"]["has_query"], false);
        assert_eq!(port_value["body"]["action"]["url"]["has_fragment"], false);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn otlp_export_redacts_secrets_from_step_error_reason() -> TestResult {
        // Issue #214 review: a StepError reason is free-form and can echo
        // remote/secret content (e.g. a failed navigation URL carrying a token).
        // It must be replaced with the constant marker — never hashed (a hash of
        // a low-entropy secret is dictionary-searchable) or written verbatim.
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
        assert!(
            !text.contains("sha256:"),
            "no dictionary-searchable hash may be emitted"
        );
        let value: Value = serde_json::from_str(text.trim_end())?;
        assert_eq!(value["body"]["outcome"]["kind"], "step_error");
        assert_eq!(value["body"]["outcome"]["reason"], REDACTED_MARKER);

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

    fn with_bearer(mut request: HttpRequest, token: &str) -> HttpRequest {
        request
            .headers
            .insert("authorization".into(), format!("Bearer {token}"));
        request
    }

    fn bidi_websocket_request(token: Option<&str>) -> HttpRequest {
        let mut request = HttpRequest {
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
            ]),
            host: None,
            origin: None,
            body: Vec::new(),
        };
        if let Some(token) = token {
            request = with_bearer(request, token);
        }
        request
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

    // ---- Issue #256: capability auth for non-loopback tempod binds ----

    #[test]
    fn non_loopback_bind_requires_remote_flag_and_auth_token() -> TestResult {
        assert!(TempodServerConfig::new()
            .validate_bind_addr("127.0.0.1:8787")
            .is_ok());

        assert!(matches!(
            TempodServerConfig::new().validate_bind_addr("0.0.0.0:8787"),
            Err(TempodError::BadRequest(_))
        ));
        assert!(matches!(
            TempodServerConfig::new()
                .allow_remote_binds()
                .validate_bind_addr("0.0.0.0:8787"),
            Err(TempodError::BadRequest(_))
        ));
        assert!(matches!(
            TempodServerConfig::new()
                .with_auth(TempodAuth::bearer("secret-token")?)
                .validate_bind_addr("0.0.0.0:8787"),
            Err(TempodError::BadRequest(_))
        ));
        assert!(TempodServerConfig::new()
            .allow_remote_binds()
            .with_auth(TempodAuth::bearer("secret-token")?)
            .validate_bind_addr("0.0.0.0:8787")
            .is_ok());
        Ok(())
    }

    #[test]
    fn listener_apis_reject_non_loopback_without_remote_policy() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));

        let listener = TcpListener::bind("0.0.0.0:0")?;
        assert!(matches!(
            serve_forever(listener, Arc::clone(&pool)),
            Err(TempodError::BadRequest(_))
        ));

        let listener = TcpListener::bind("0.0.0.0:0")?;
        assert!(matches!(
            serve_forever_with_auth(
                listener,
                Arc::clone(&pool),
                TempodAuth::bearer("secret-token")?
            ),
            Err(TempodError::BadRequest(_))
        ));

        let listener = TcpListener::bind("0.0.0.0:0")?;
        assert!(matches!(
            serve_one(listener, Arc::clone(&pool)),
            Err(TempodError::BadRequest(_))
        ));

        let listener = TcpListener::bind("0.0.0.0:0")?;
        assert!(matches!(
            serve_one_with_config(
                listener,
                pool,
                TempodServerConfig::new().allow_remote_binds()
            ),
            Err(TempodError::BadRequest(_))
        ));
        Ok(())
    }

    #[test]
    fn listener_config_allows_non_loopback_with_remote_flag_and_auth() -> TestResult {
        let listener = TcpListener::bind("0.0.0.0:0")?;
        let connect_addr =
            std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr()?.port()));
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let config = TempodServerConfig::new()
            .allow_remote_binds()
            .with_auth(TempodAuth::bearer("secret-token")?);
        let handle = thread::spawn(move || serve_one_with_config(listener, pool, config));
        let body = r#"{"url":"https://one.test"}"#;

        let response = send_http(
            connect_addr,
            &format!(
                "POST /sessions HTTP/1.1\r\nauthorization: Bearer secret-token\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ),
        )?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 201 Created"));
        assert!(response.contains("\"id\":\"session-0\""));
        Ok(())
    }

    #[test]
    fn auth_config_requires_bearer_for_rest_control_and_allows_missing_origin_with_token(
    ) -> TestResult {
        let auth = TempodAuth::bearer("secret-token")?;
        let create_body = br#"{"url":"https://example.test"}"#;
        let mut pool = SessionPool::default();

        let missing = handle_http_request_with_auth(
            &mut pool,
            control_request("POST", "/sessions", None, create_body),
            &auth,
        );
        assert_eq!(missing.status, 401);
        assert!(pool.list().is_empty());

        let wrong = handle_http_request_with_auth(
            &mut pool,
            with_bearer(
                control_request("POST", "/sessions", None, create_body),
                "wrong-token",
            ),
            &auth,
        );
        assert_eq!(wrong.status, 401);
        assert!(pool.list().is_empty());

        let allowed = handle_http_request_with_auth(
            &mut pool,
            with_bearer(
                control_request("POST", "/sessions", None, create_body),
                "secret-token",
            ),
            &auth,
        );
        assert_eq!(allowed.status, 201);
        assert_eq!(pool.list().len(), 1);
        Ok(())
    }

    #[test]
    fn auth_config_requires_bearer_for_mcp_post() -> TestResult {
        let auth = TempodAuth::bearer("secret-token")?;
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let mut pool = SessionPool::default();

        let get_missing = handle_http_request_with_auth(
            &mut pool,
            control_request("GET", "/mcp", None, b""),
            &auth,
        );
        assert_eq!(get_missing.status, 401);

        let missing = handle_http_request_with_auth(
            &mut pool,
            control_request("POST", "/mcp", None, body),
            &auth,
        );
        assert_eq!(missing.status, 401);

        let wrong = handle_http_request_with_auth(
            &mut pool,
            with_bearer(control_request("POST", "/mcp", None, body), "wrong-token"),
            &auth,
        );
        assert_eq!(wrong.status, 401);

        let allowed = handle_http_request_with_auth(
            &mut pool,
            with_bearer(control_request("POST", "/mcp", None, body), "secret-token"),
            &auth,
        );
        assert_eq!(allowed.status, 200);
        let value: Value = serde_json::from_slice(&allowed.body)?;
        assert!(value["result"]["tools"].is_array());
        Ok(())
    }

    #[test]
    fn auth_config_requires_bearer_for_bidi_websocket_upgrade() -> TestResult {
        let auth = TempodAuth::bearer("secret-token")?;

        match websocket_upgrade_key_with_auth(&bidi_websocket_request(None), &auth) {
            Err(TempodError::Unauthorized(_)) => {}
            other => return Err(format!("expected Unauthorized, got {other:?}").into()),
        }
        match websocket_upgrade_key_with_auth(&bidi_websocket_request(Some("wrong-token")), &auth) {
            Err(TempodError::Unauthorized(_)) => {}
            other => return Err(format!("expected Unauthorized, got {other:?}").into()),
        }
        assert_eq!(
            websocket_upgrade_key_with_auth(&bidi_websocket_request(Some("secret-token")), &auth)?,
            Some("dGhlIHNhbXBsZSBub25jZQ==".into())
        );
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

    #[test]
    fn serve_forever_rejects_excess_http_connections() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let limiter = ConnectionLimiter::new(1, 1);
        let server_limiter = limiter.clone();
        let handle =
            thread::spawn(move || serve_forever_with_limits(listener, pool, server_limiter));

        let held = TcpStream::connect(addr)?;
        wait_for_connection_counts(&limiter, (1, 0))?;

        let mut rejected = TcpStream::connect(addr)?;
        rejected.set_read_timeout(Some(Duration::from_secs(5)))?;
        assert_connection_closed_without_response(&mut rejected)?;
        assert_eq!(limiter.active_counts(), (1, 0));

        drop(held);
        assert!(!handle.is_finished());
        Ok(())
    }

    #[test]
    fn bidi_websocket_upgrade_rejects_when_websocket_limit_reached() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let limiter = ConnectionLimiter::new(1, 1);
        let server_limiter = limiter.clone();
        let handle =
            thread::spawn(move || serve_forever_with_limits(listener, pool, server_limiter));

        let mut held = open_bidi_websocket(addr)?;
        wait_for_connection_counts(&limiter, (0, 1))?;

        let response = send_http(addr, BIDI_WEBSOCKET_UPGRADE_REQUEST)?;
        assert!(
            response.starts_with("HTTP/1.1 503"),
            "expected 503 when WebSocket connection limit is reached, got: {response}"
        );
        assert!(response.contains(WEBSOCKET_CONNECTION_LIMIT_MESSAGE));
        assert!(!response.starts_with("HTTP/1.1 101"));

        held.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, payload) = read_server_frame(&mut held)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        assert!(payload.is_empty());
        wait_for_connection_counts(&limiter, (0, 0))?;
        assert!(!handle.is_finished());
        Ok(())
    }

    #[test]
    fn websocket_permit_is_released_on_close() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let limiter = ConnectionLimiter::new(1, 1);
        let server_limiter = limiter.clone();
        let handle =
            thread::spawn(move || serve_forever_with_limits(listener, pool, server_limiter));

        let mut first = open_bidi_websocket(addr)?;
        wait_for_connection_counts(&limiter, (0, 1))?;
        first.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, payload) = read_server_frame(&mut first)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        assert!(payload.is_empty());
        wait_for_connection_counts(&limiter, (0, 0))?;

        let mut second = open_bidi_websocket(addr)?;
        wait_for_connection_counts(&limiter, (0, 1))?;
        second.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, payload) = read_server_frame(&mut second)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        assert!(payload.is_empty());
        wait_for_connection_counts(&limiter, (0, 0))?;

        assert!(!handle.is_finished());
        Ok(())
    }

    // ---- Issue #86: read timeout is applied per connection ----

    #[test]
    fn apply_socket_options_sets_deadlines_and_nodelay() -> TestResult {
        // Real 30s slowloris timeouts are impractical to exercise in a unit test,
        // so verify deterministically that the helper installs both deadlines and
        // TCP_NODELAY on the accepted socket; serve_forever/serve_one call it per
        // connection.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _addr) = listener.accept()?;

        apply_socket_options(&server)?;
        assert_eq!(server.read_timeout()?, Some(SOCKET_TIMEOUT));
        assert_eq!(server.write_timeout()?, Some(SOCKET_TIMEOUT));
        assert!(server.nodelay()?);
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.bidi_contexts
            .insert(context.clone(), driver.derived("fork-1".into()));

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
            driver.derived("fork-1".into()),
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

    const BIDI_WEBSOCKET_UPGRADE_REQUEST: &str = "GET /bidi HTTP/1.1\r\n\
        host: 127.0.0.1\r\n\
        upgrade: websocket\r\n\
        connection: Upgrade\r\n\
        sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        sec-websocket-version: 13\r\n\r\n";

    fn send_http(addr: std::net::SocketAddr, request: &str) -> Result<String, std::io::Error> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        read_http_response(&mut stream)
    }

    fn read_http_response(stream: &mut TcpStream) -> Result<String, std::io::Error> {
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn assert_connection_closed_without_response(stream: &mut TcpStream) -> TestResult {
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
            Ok(read) => Err(format!(
                "expected over-limit HTTP connection to close without a response, read {read} byte(s)"
            )
            .into()),
            Err(error) => Err(error.into()),
        }
    }

    fn open_bidi_websocket(addr: std::net::SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(BIDI_WEBSOCKET_UPGRADE_REQUEST.as_bytes())?;
        let response = read_http_head(&mut stream)?;
        assert!(
            response.starts_with("HTTP/1.1 101 Switching Protocols"),
            "expected WebSocket upgrade, got: {response}"
        );
        Ok(stream)
    }

    fn wait_for_connection_counts(
        limiter: &ConnectionLimiter,
        expected: (usize, usize),
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let actual = limiter.active_counts();
            if actual == expected {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(format!(
            "connection counts did not settle to {expected:?}; last observed {:?}",
            limiter.active_counts()
        )
        .into())
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
    ) -> Result<thread::JoinHandle<Result<(), EngineHostError>>, Box<dyn Error>>
    where
        F: FnOnce(DriverRequest) -> DriverResponse + Send + 'static,
    {
        let (client_stream, server_stream) = UnixStream::pair()?;
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;

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
