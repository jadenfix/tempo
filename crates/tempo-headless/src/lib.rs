//! tempo-headless — headless `tempod` control plane.
//!
//! The daemon owns session lifecycle, engine-host supervision, graceful drain,
//! and StepTriple telemetry export (OTLP/HTTP to a collector, JSONL as the
//! local fallback lane). The transport is axum/hyper on tokio (final.md §3.1,
//! issue #249): the session REST surface, MCP, and the BiDi WebSocket are all
//! served from one router, while session/engine work stays synchronous below
//! the transport and runs on blocking worker threads.

#![recursion_limit = "256"]

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as UrlPath, RawQuery, Request as AxumRequest, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tempo_agent::{StepTriple, StepTripleOutcome};
// Re-exported so consumers of `TempodSessionEventKind::StepTriple` (e.g. the
// shell agent panel) can name the event payload without a direct tempo-agent dep.
use tempo_act::detect_human_takeover;
pub use tempo_agent::{
    IdempotencyKey as SessionStepKey, StepTriple as SessionStepTriple,
    StepTripleOutcome as SessionStepOutcome,
};
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
    EngineHostConfig, EngineHostError, EngineIpcClient, RestartPolicy, SharedEngineIpcClient,
};
use tempo_net::{
    web_bot_auth_key_directory_json, BlockCode, BrowserHardeningBlockCode, BrowserHardeningBlocked,
    BrowserHardeningPolicy, IdentityStrategyTable, StaticThreatDomainProvider,
    ThreatDomainProviderAudit, UrlPolicy, WebBotAuthVerifier, WEB_BOT_AUTH_KEY_DIRECTORY_PATH,
};
use tempo_policy::trust::{
    action_caller_texts, gate_boundary_action, gate_boundary_effect, requires_observation_evidence,
    CallerPolicyClaims,
};
use tempo_policy::ConfirmationGate;
use tempo_schema::{
    Action, ActionBatch, CompiledObservation, HumanTakeover, NodeId, ObservationDiff, SideEffect,
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

/// Maximum accepted HTTP body size; hyper's per-connection read buffer is
/// capped to the same bound so oversized headers are rejected as well.
const MAX_HTTP_BYTES: usize = 64 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_SESSION_IDEMPOTENCY_RECORDS: usize = 1024;
const MAX_WS_PAYLOAD_BYTES: usize = MAX_HTTP_BYTES;
/// Maximum accepted TCP control-plane connections handled concurrently.
const MAX_HTTP_CONNECTIONS: usize = 128;
/// Maximum retained tempod sessions. Killed sessions stay in the in-memory
/// session map until the reaper lands (#412), so cap the retained map, not just
/// currently-running sessions.
const MAX_TEMPOD_SESSIONS: usize = 1024;
/// Maximum upgraded BiDi WebSocket sessions held concurrently.
const MAX_WEBSOCKET_CONNECTIONS: usize = 32;
/// Best-effort post-action observations must not create unbounded OS threads.
const MAX_POST_ACTION_IDENTITY_OBSERVERS: usize = 32;
/// Maximum number of live BiDi browsing contexts (forked drivers) held at once.
const MAX_BIDI_CONTEXTS: usize = 64;
/// Bound on how long a client may take to send its request head, so a
/// slowloris client cannot hold one of the capped connection permits forever
/// (hyper `header_read_timeout`).
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
const HTTP_CONNECTION_LIMIT_MESSAGE: &str = "too many active tempod HTTP connections";
const WEBSOCKET_CONNECTION_LIMIT_MESSAGE: &str = "too many active tempod WebSocket connections";
pub const TEMPO_OTLP_JSONL_ENV: &str = "TEMPO_OTLP_JSONL";
/// Collector endpoint for real OTLP/HTTP export of StepTriples (issue #249),
/// e.g. `http://collector.internal:4318`; `/v1/traces` is appended when absent.
pub const TEMPO_OTLP_ENDPOINT_ENV: &str = "TEMPO_OTLP_ENDPOINT";
pub const TEMPO_TEMPOD_AUTH_TOKEN_ENV: &str = "TEMPO_TEMPOD_AUTH_TOKEN";
pub const TEMPO_TEMPOD_AUTH_TOKEN_FILE_ENV: &str = "TEMPO_TEMPOD_AUTH_TOKEN_FILE";
pub const TEMPO_THREAT_DOMAIN_FILE_ENV: &str = "TEMPO_THREAT_DOMAIN_FILE";
pub const TEMPO_THREAT_DOMAIN_URL_ENV: &str = "TEMPO_THREAT_DOMAIN_URL";
pub const TEMPO_THREAT_DOMAIN_METADATA_URL_ENV: &str = "TEMPO_THREAT_DOMAIN_METADATA_URL";
pub const TEMPO_THREAT_DOMAIN_CACHE_FILE_ENV: &str = "TEMPO_THREAT_DOMAIN_CACHE_FILE";
pub const TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE_ENV: &str =
    "TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE";
pub const TEMPO_THREAT_DOMAIN_PUBLIC_KEYS_ENV: &str = "TEMPO_THREAT_DOMAIN_PUBLIC_KEYS";
pub const TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS_ENV: &str =
    "TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS";
pub const TEMPO_THREAT_DOMAIN_SHA256_ENV: &str = "TEMPO_THREAT_DOMAIN_SHA256";
pub const TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS_ENV: &str = "TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS";
pub const TEMPO_THREAT_DOMAIN_FAILURE_MODE_ENV: &str = "TEMPO_THREAT_DOMAIN_FAILURE_MODE";
pub const TEMPO_THREAT_DOMAIN_AUDIT_JSONL_ENV: &str = "TEMPO_THREAT_DOMAIN_AUDIT_JSONL";
/// Prometheus text exposition endpoint (`GET /metrics`).
pub const TEMPOD_METRICS_PATH: &str = "/metrics";
pub const TEMPO_STEALTH_MODE_ENV: &str = "TEMPO_STEALTH_MODE";
/// Machine-readable REST contract used as the source of truth for generated SDKs.
pub const TEMPOD_OPENAPI_PATH: &str = "/openapi.json";
const TEMPOD_OPENAPI_CONTENT_TYPE: &str = "application/vnd.oai.openapi+json;version=3.1";
const WEB_BOT_AUTH_KEY_DIRECTORY_CONTENT_TYPE: &str = "application/jwk-set+json";
const TEMPOD_AUTH_TOKEN_BYTES: usize = 32;
const TEMPOD_RUNTIME_DIR_NAME: &str = "tempo";
const TEMPOD_AUTH_TOKEN_FILE_NAME: &str = "tempod.token";
const TEMPO_THREAT_DOMAIN_REMOTE_TIMEOUT: Duration = Duration::from_secs(10);
const TEMPO_THREAT_DOMAIN_REMOTE_MAX_BYTES: u64 = 2 * 1024 * 1024;
const TEMPO_THREAT_DOMAIN_DEFAULT_MAX_STALE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Constant marker written in place of any secret-bearing field in OTLP
/// telemetry (issue #214 review). A constant — never a hash, length, or prefix
/// of the secret — so low-entropy secrets (PINs, OTPs, common passwords/tokens)
/// cannot be recovered by an offline dictionary search of the exported value.
const REDACTED_MARKER: &str = "[redacted]";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempodRuntimeAuthToken {
    pub token: String,
    pub path: PathBuf,
}

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

    /// Authorize a request from its raw `Authorization` header value.
    fn authorize(&self, authorization: Option<&str>) -> Result<(), TempodError> {
        let Some(expected) = &self.bearer_token else {
            return Ok(());
        };
        let Some(header) = authorization else {
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

pub fn tempod_runtime_auth_token_path() -> PathBuf {
    if let Some(path) =
        std::env::var_os(TEMPO_TEMPOD_AUTH_TOKEN_FILE_ENV).filter(|path| !path.is_empty())
    {
        return PathBuf::from(path);
    }
    tempod_runtime_dir().join(TEMPOD_AUTH_TOKEN_FILE_NAME)
}

pub fn load_tempod_runtime_auth_token() -> Result<Option<TempodRuntimeAuthToken>, TempodError> {
    load_tempod_runtime_auth_token_at(tempod_runtime_auth_token_path())
}

pub fn load_tempod_runtime_auth_token_at(
    path: impl Into<PathBuf>,
) -> Result<Option<TempodRuntimeAuthToken>, TempodError> {
    let path = path.into();
    match read_runtime_auth_token_file(&path) {
        Ok(token) => Ok(Some(TempodRuntimeAuthToken { token, path })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn load_or_create_tempod_runtime_auth_token() -> Result<TempodRuntimeAuthToken, TempodError> {
    load_or_create_tempod_runtime_auth_token_at(tempod_runtime_auth_token_path())
}

pub fn load_or_create_tempod_runtime_auth_token_at(
    path: impl Into<PathBuf>,
) -> Result<TempodRuntimeAuthToken, TempodError> {
    let path = path.into();
    if let Some(existing) = load_tempod_runtime_auth_token_at(&path)? {
        return Ok(existing);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_owner_only_dir(parent)?;
    }
    let token = generate_runtime_auth_token()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(TempodRuntimeAuthToken { token, path })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            load_tempod_runtime_auth_token_at(path)?.ok_or_else(|| {
                TempodError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "runtime auth token appeared and disappeared",
                ))
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn runtime_auth_server_config() -> Result<TempodServerConfig, TempodError> {
    let token = load_or_create_tempod_runtime_auth_token()?;
    Ok(TempodServerConfig::new().with_auth(TempodAuth::bearer(token.token)?))
}

fn tempod_runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|path| !path.is_empty()) {
        return PathBuf::from(dir).join(TEMPOD_RUNTIME_DIR_NAME);
    }
    std::env::temp_dir().join(runtime_dir_leaf())
}

fn runtime_dir_leaf() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into());
    let safe_user = user
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{TEMPOD_RUNTIME_DIR_NAME}-{safe_user}")
}

fn create_owner_only_dir(path: &Path) -> Result<(), TempodError> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_runtime_auth_token_file(path: &Path) -> Result<String, std::io::Error> {
    validate_runtime_auth_token_metadata(path)?;
    let mut token = String::new();
    File::open(path)?.read_to_string(&mut token)?;
    let token = token.trim_end_matches(['\r', '\n']).to_string();
    validate_bearer_token(&token)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(token)
}

fn validate_runtime_auth_token_metadata(path: &Path) -> Result<(), std::io::Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "runtime auth token path must not be a symlink",
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "runtime auth token path must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "runtime auth token file must be owner-only",
            ));
        }
    }
    Ok(())
}

fn generate_runtime_auth_token() -> Result<String, TempodError> {
    let mut bytes = [0_u8; TEMPOD_AUTH_TOKEN_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|error| TempodError::Io(std::io::Error::other(error.to_string())))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Clone, Debug, Default)]
pub struct TempodServerConfig {
    allow_remote_binds: bool,
    auth: TempodAuth,
    allowed_hosts: BTreeSet<String>,
    web_bot_auth_verifiers: Vec<WebBotAuthVerifier>,
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

    pub fn with_web_bot_auth_verifiers(mut self, verifiers: Vec<WebBotAuthVerifier>) -> Self {
        self.web_bot_auth_verifiers = verifiers;
        self
    }

    pub fn auth_is_required(&self) -> bool {
        self.auth.is_required()
    }

    pub fn web_bot_auth_verifier_count(&self) -> usize {
        self.web_bot_auth_verifiers.len()
    }

    fn with_bind_addr_host(mut self, addr: &str) -> Self {
        if let Some(host) = normalized_host_header_name(addr) {
            self.allowed_hosts.insert(host);
        }
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

/// Sanitized browser-hardening block record for API errors and session events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempodBrowserHardeningBlock {
    pub url: String,
    pub code: String,
    pub url_policy_code: Option<String>,
    pub origin: Option<String>,
    pub reason: String,
    pub action: Option<String>,
    pub action_index: Option<usize>,
}

impl fmt::Display for TempodBrowserHardeningBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.reason)
    }
}

/// Typed events clients can attach to for session logs and StepTriple telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TempodSessionEventKind {
    SessionCreated {
        url: String,
    },
    SessionAdopted,
    SessionResumed,
    SessionKilled,
    SessionDrained,
    StepTriple {
        triple: StepTriple,
    },
    /// A hard pause: the agent loop detected a CAPTCHA / auth-wall / login state
    /// ([`tempo_schema::HumanTakeover`], #244/#343) and stopped so a human can
    /// take over. Carried on the typed session-event stream so a windowed client
    /// ([`tempo-shell`], #354) can raise a blocking takeover banner from the same
    /// `/sessions/{id}/events` poll it already runs. Detection is pure over the
    /// observation and never auto-solves the challenge.
    HumanTakeoverRequired {
        takeover: HumanTakeover,
    },
    /// A navigation or action was blocked before dispatch by Tempo's browser
    /// hardening policy: SSRF/private-network, strict HTTPS, threat-domain, or
    /// risky download protection. This is reporting, not bypass.
    BrowserHardeningBlocked {
        block: TempodBrowserHardeningBlock,
    },
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

/// Current process privacy mode from `TEMPO_STEALTH_MODE`.
pub fn privacy_mode_from_env() -> PrivacyMode {
    PrivacyMode::from_env_value(std::env::var_os(TEMPO_STEALTH_MODE_ENV))
}

/// Apply privacy-mode retention rules to process-level telemetry.
///
/// Stealth mode disables local log output/ring retention and the `/metrics`
/// exposition endpoint even when telemetry was otherwise enabled by config.
pub fn configure_process_telemetry_for_privacy(
    privacy_mode: PrivacyMode,
    configured_metrics_enabled: bool,
) -> bool {
    let retain_local_telemetry = privacy_mode.retains_history();
    tempo_telemetry::logger().set_local_output_enabled(retain_local_telemetry);
    let effective_metrics_enabled =
        metrics_enabled_for_privacy(privacy_mode, configured_metrics_enabled);
    set_metrics_enabled(effective_metrics_enabled);
    effective_metrics_enabled
}

const fn metrics_enabled_for_privacy(
    privacy_mode: PrivacyMode,
    configured_metrics_enabled: bool,
) -> bool {
    configured_metrics_enabled && privacy_mode.retains_history()
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
    browser_hardening_policy: BrowserHardeningPolicy,
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
            #[cfg(not(test))]
            browser_hardening_policy: BrowserHardeningPolicy::standard(),
            #[cfg(test)]
            browser_hardening_policy: BrowserHardeningPolicy::standard()
                .with_url_policy(UrlPolicy::allow_all()),
            gate: Arc::new(OpGate::default()),
        })
    }

    pub fn with_navigation_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.browser_hardening_policy = self
            .browser_hardening_policy
            .clone()
            .with_url_policy(url_policy.clone());
        self.url_policy = url_policy;
        self
    }

    pub fn with_browser_hardening_policy(
        mut self,
        browser_hardening_policy: BrowserHardeningPolicy,
    ) -> Self {
        self.url_policy = browser_hardening_policy.url_policy().clone();
        self.browser_hardening_policy = browser_hardening_policy;
        self
    }

    /// Whether the underlying multiplexed IPC connection has been marked dead by
    /// its reader thread (engine child exited or socket disconnected). A dead
    /// driver returns [`EngineHostError::IpcClosed`] promptly for every request
    /// rather than timing out, so it never trips the teardown circuit breaker
    /// (which fires only on `None`/timeout); the liveness monitor watches this
    /// flag to reconnect + re-attach instead (#398).
    fn is_dead(&self) -> bool {
        self.client.is_dead()
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

    /// Bounded liveness probe on the shared engine (#440): one root-context
    /// `Observe` round-trip, capped at `timeout`. Returns `true` when the engine
    /// answers within the bound (even with an engine-level error response —
    /// that still proves the IPC connection is live and the child is serving),
    /// and `false` when the shared IPC connection is already dead
    /// (`SharedEngineIpcClient` fails fast via `pending.dead`) or the round-trip
    /// times out (a genuinely wedged child). Used to decide whether a session
    /// `Close` timeout should abandon the shared engine: a lone slow `Close`
    /// must not, but an unreachable engine must. Bypasses the per-driver
    /// [`OpGate`] on purpose — a read-only probe must not queue behind this
    /// driver's own in-flight command, only reflect engine reachability.
    fn probe_responsive(&self, timeout: Duration) -> bool {
        self.client
            .request_for(
                self.driver_id.as_deref(),
                HostDriverCommand::Observe,
                timeout,
            )
            .is_ok()
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
            browser_hardening_policy: self.browser_hardening_policy.clone(),
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
            .field("browser_hardening_policy", &self.browser_hardening_policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DriverTrait for AttachedEngineDriver {
    fn engine(&self) -> Engine {
        self.engine
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        enforce_tempod_navigation_url_transport(&self.browser_hardening_policy, url)?;
        self.request_observation(HostDriverCommand::Goto { url: url.into() }, "goto")
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        self.request_observation(HostDriverCommand::Observe, "observe")
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        self.request_diff(HostDriverCommand::ObserveDiff { since_seq }, "observe_diff")
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        enforce_action_navigation_url_policy(&self.browser_hardening_policy, action)?;
        self.request_step(
            HostDriverCommand::Act {
                action: action.clone(),
            },
            "act",
        )
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        enforce_batch_navigation_url_policy_transport(&self.browser_hardening_policy, batch)?;
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
    threat_domain_audit_exporter: Option<ThreatDomainAuditJsonExporter>,
    privacy_mode: PrivacyMode,
    otlp_http_exporter: Option<OtlpHttpExporter>,
    bidi: BidiRouter,
    driver: Option<AttachedEngineDriver>,
    /// One MCP server for the attached engine. No outer `Mutex`: the server
    /// itself runs concurrent tool calls on distinct drivers and serializes
    /// same-driver calls internally (issue #230), so tool calls on different
    /// sessions no longer queue behind a process-wide MCP lock.
    mcp: Option<Arc<tempo_mcp::TempoMcpServer<AttachedEngineDriver>>>,
    bidi_contexts: BTreeMap<BrowsingContextId, AttachedEngineDriver>,
    url_policy: UrlPolicy,
    browser_hardening_policy: BrowserHardeningPolicy,
    next_bidi_context_id: u64,
    next_id: u64,
    max_sessions: usize,
    draining: bool,
    identity_strategy_table: IdentityStrategyTable,
}

impl Default for SessionPool {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            session_drivers: BTreeMap::new(),
            session_act_batch_idempotency: BTreeMap::new(),
            events: BTreeMap::new(),
            otlp_exporter: None,
            threat_domain_audit_exporter: None,
            privacy_mode: PrivacyMode::default(),
            otlp_http_exporter: None,
            bidi: BidiRouter::default(),
            driver: None,
            mcp: None,
            bidi_contexts: BTreeMap::new(),
            #[cfg(not(test))]
            url_policy: UrlPolicy::block_private(),
            #[cfg(test)]
            url_policy: UrlPolicy::allow_all(),
            #[cfg(not(test))]
            browser_hardening_policy: BrowserHardeningPolicy::standard(),
            #[cfg(test)]
            browser_hardening_policy: BrowserHardeningPolicy::standard()
                .with_url_policy(UrlPolicy::allow_all()),
            next_bidi_context_id: 0,
            next_id: 0,
            max_sessions: MAX_TEMPOD_SESSIONS,
            identity_strategy_table: IdentityStrategyTable::default(),
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
            .field(
                "identity_strategy_config",
                &self.identity_strategy_table.config(),
            )
            .field(
                "identity_strategy_tracked_origins",
                &self.identity_strategy_table.tracked_origins(),
            )
            .field("otlp_http_exporter", &self.otlp_http_exporter)
            .field(
                "threat_domain_audit_exporter",
                &self.threat_domain_audit_exporter,
            )
            .field("bidi", &self.bidi)
            .field("driver", &self.driver)
            .field("mcp_attached", &self.mcp.is_some())
            .field("url_policy", &self.url_policy)
            .field("browser_hardening_policy", &self.browser_hardening_policy)
            .field("next_id", &self.next_id)
            .field("max_sessions", &self.max_sessions)
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
            std::env::var_os(TEMPO_OTLP_ENDPOINT_ENV),
            std::env::var_os(TEMPO_STEALTH_MODE_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_FILE_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_URL_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_CACHE_FILE_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_SHA256_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_FAILURE_MODE_ENV),
            std::env::var_os(TEMPO_THREAT_DOMAIN_AUDIT_JSONL_ENV),
        )
    }

    #[cfg(test)]
    fn from_otlp_env_values(
        jsonl: Option<std::ffi::OsString>,
        endpoint: Option<std::ffi::OsString>,
    ) -> Self {
        Self::from_env_values(
            jsonl, endpoint, None, None, None, None, None, None, None, None,
        )
    }

    /// Wire the telemetry lanes from environment values: `TEMPO_OTLP_JSONL`
    /// keeps the local JSONL fallback lane, `TEMPO_OTLP_ENDPOINT` enables real
    /// OTLP/HTTP export to a collector (issue #249), `TEMPO_STEALTH_MODE`
    /// disables local history and all opt-in telemetry export, and
    /// `TEMPO_THREAT_DOMAIN_FILE` loads an offline threat-domain feed into
    /// the browser hardening policy, `TEMPO_THREAT_DOMAIN_URL` fetches an
    /// HTTPS-only production threat-domain snapshot with SSRF and size guards,
    /// `TEMPO_THREAT_DOMAIN_CACHE_FILE` provides an owner-only stale-cache
    /// fallback, `TEMPO_THREAT_DOMAIN_SHA256` pins the expected snapshot digest,
    /// `TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS` bounds cache age, and
    /// `TEMPO_THREAT_DOMAIN_FAILURE_MODE` selects fail-closed or fail-open
    /// behavior when configured protection cannot load, and
    /// `TEMPO_THREAT_DOMAIN_AUDIT_JSONL` persists count-only feed-load audit
    /// records.
    #[allow(clippy::too_many_arguments)]
    fn from_env_values(
        jsonl: Option<std::ffi::OsString>,
        endpoint: Option<std::ffi::OsString>,
        stealth_value: Option<std::ffi::OsString>,
        threat_domain_file: Option<std::ffi::OsString>,
        threat_domain_url: Option<std::ffi::OsString>,
        threat_domain_cache_file: Option<std::ffi::OsString>,
        threat_domain_sha256: Option<std::ffi::OsString>,
        threat_domain_max_stale_seconds: Option<std::ffi::OsString>,
        threat_domain_failure_mode: Option<std::ffi::OsString>,
        threat_domain_audit_jsonl: Option<std::ffi::OsString>,
    ) -> Self {
        let privacy_mode = PrivacyMode::from_env_value(stealth_value);
        let mut pool = Self::default().with_privacy_mode(privacy_mode);
        if let Some(path) = threat_domain_audit_jsonl.filter(|path| !path.is_empty()) {
            pool.threat_domain_audit_exporter = Some(ThreatDomainAuditJsonExporter::new(path));
        }
        pool.apply_threat_domain_file_env(threat_domain_file);
        pool.apply_threat_domain_url_env(
            threat_domain_url,
            threat_domain_cache_file,
            threat_domain_sha256,
            threat_domain_max_stale_seconds,
            threat_domain_failure_mode,
        );
        if privacy_mode.retains_history()
            && let Some(path) = jsonl
            && !path.is_empty()
        {
            pool = pool.with_otlp_exporter(OtlpJsonExporter::new(path));
        }
        if privacy_mode.retains_history() {
            match endpoint {
                Some(endpoint) if !endpoint.is_empty() => match endpoint.into_string() {
                    Ok(endpoint) => match OtlpHttpExporter::new(endpoint) {
                        Ok(exporter) => pool.otlp_http_exporter = Some(exporter),
                        Err(error) => {
                            log_tempod_error("ignoring invalid OTLP endpoint", error);
                        }
                    },
                    Err(_) => {
                        log_tempod_warn("ignoring non-UTF-8 OTLP endpoint")
                            .field("env", TEMPO_OTLP_ENDPOINT_ENV)
                            .emit();
                    }
                },
                _ => {}
            }
        }
        pool
    }

    fn apply_threat_domain_file_env(&mut self, threat_domain_file: Option<std::ffi::OsString>) {
        let Some(path) = threat_domain_file.filter(|path| !path.is_empty()) else {
            return;
        };
        let path = PathBuf::from(path);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => {
                log_tempod_warn("ignoring unreadable threat-domain feed")
                    .field("env", TEMPO_THREAT_DOMAIN_FILE_ENV)
                    .field("error", error.to_string())
                    .emit();
                return;
            }
        };
        let provider = match StaticThreatDomainProvider::from_feed_lines(
            "tempo-threat-domain-file",
            &contents,
        ) {
            Ok(provider) => provider,
            Err(error) => {
                log_tempod_warn("ignoring invalid threat-domain feed")
                    .field("env", TEMPO_THREAT_DOMAIN_FILE_ENV)
                    .field("error", error.to_string())
                    .emit();
                return;
            }
        };
        let mut policy = self.browser_hardening_policy.clone();
        let audit = policy.apply_threat_domain_provider(&provider);
        self.browser_hardening_policy = policy;
        if let Some(exporter) = &self.threat_domain_audit_exporter
            && let Err(error) = exporter.export_audit(&audit)
        {
            log_tempod_error("threat-domain audit export failed", error);
        }
        tempo_telemetry::logger()
            .event(
                tempo_telemetry::Level::Info,
                "tempod",
                "loaded threat-domain feed",
            )
            .field("provider_id", audit.provider_id.clone())
            .field("rule_count", audit.rule_count.to_string())
            .field("exact_rules", audit.exact_rules.to_string())
            .field("suffix_rules", audit.suffix_rules.to_string())
            .emit();
    }

    fn apply_threat_domain_url_env(
        &mut self,
        threat_domain_url: Option<std::ffi::OsString>,
        threat_domain_cache_file: Option<std::ffi::OsString>,
        threat_domain_sha256: Option<std::ffi::OsString>,
        threat_domain_max_stale_seconds: Option<std::ffi::OsString>,
        threat_domain_failure_mode: Option<std::ffi::OsString>,
    ) {
        let Some(url) = threat_domain_url.filter(|url| !url.is_empty()) else {
            return;
        };
        let url = match url.into_string() {
            Ok(url) => url,
            Err(_) => {
                log_tempod_warn("ignoring non-UTF-8 threat-domain feed URL")
                    .field("env", TEMPO_THREAT_DOMAIN_URL_ENV)
                    .emit();
                return;
            }
        };
        let cache_file = threat_domain_cache_file
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let failure_mode = parse_threat_domain_failure_mode_env(threat_domain_failure_mode);
        let expected_sha256 = match parse_optional_sha256_env(threat_domain_sha256) {
            Ok(expected) => expected,
            Err(error) => {
                log_tempod_warn("ignoring invalid threat-domain feed digest pin")
                    .field("env", TEMPO_THREAT_DOMAIN_SHA256_ENV)
                    .field("error", error)
                    .emit();
                if failure_mode.fail_closed() {
                    self.browser_hardening_policy = self
                        .browser_hardening_policy
                        .clone()
                        .with_url_policy(UrlPolicy::block_all());
                }
                return;
            }
        };
        let max_stale = parse_threat_domain_max_stale_env(threat_domain_max_stale_seconds);
        let snapshot = match fetch_threat_domain_feed_url_or_cache(
            &url,
            cache_file.as_deref(),
            expected_sha256.as_deref(),
            max_stale,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                log_tempod_warn("ignoring unreachable threat-domain feed URL")
                    .field("env", TEMPO_THREAT_DOMAIN_URL_ENV)
                    .field("error", error)
                    .field("failure_mode", failure_mode.as_str())
                    .emit();
                if failure_mode.fail_closed() {
                    self.browser_hardening_policy = self
                        .browser_hardening_policy
                        .clone()
                        .with_url_policy(UrlPolicy::block_all());
                }
                return;
            }
        };
        let provider = match StaticThreatDomainProvider::from_feed_lines(
            "tempo-threat-domain-url",
            &snapshot.contents,
        ) {
            Ok(provider) => provider,
            Err(error) => {
                log_tempod_warn("ignoring invalid threat-domain feed URL")
                    .field("env", TEMPO_THREAT_DOMAIN_URL_ENV)
                    .field("error", error.to_string())
                    .emit();
                return;
            }
        };
        let mut policy = self.browser_hardening_policy.clone();
        let audit = policy.apply_threat_domain_provider(&provider);
        self.browser_hardening_policy = policy;
        if let Some(exporter) = &self.threat_domain_audit_exporter
            && let Err(error) = exporter.export_audit_from(
                &audit,
                snapshot.source,
                snapshot.env,
                snapshot.cache_write_failed(),
            )
        {
            log_tempod_error("threat-domain audit export failed", error);
        }
        if let Some(error) = &snapshot.cache_write_error {
            log_tempod_warn("threat-domain cache write failed")
                .field("env", TEMPO_THREAT_DOMAIN_CACHE_FILE_ENV)
                .field("error", error.as_str())
                .emit();
        }
        tempo_telemetry::logger()
            .event(
                tempo_telemetry::Level::Info,
                "tempod",
                "loaded threat-domain feed URL",
            )
            .field("provider_id", audit.provider_id.clone())
            .field("rule_count", audit.rule_count.to_string())
            .field("exact_rules", audit.exact_rules.to_string())
            .field("suffix_rules", audit.suffix_rules.to_string())
            .emit();
    }

    fn apply_verified_signed_threat_domain_policy_snapshot(
        &mut self,
        trusted_public_keys: &mut BTreeMap<String, String>,
        metadata_json: &str,
        feed_contents: &str,
        now_ms: u64,
    ) -> Result<ThreatDomainProviderAudit, String> {
        let snapshot = build_verified_signed_threat_domain_policy_snapshot(
            &self.browser_hardening_policy,
            trusted_public_keys,
            metadata_json,
            feed_contents,
            now_ms,
        )?;
        self.browser_hardening_policy = snapshot.policy;
        *trusted_public_keys = snapshot.trusted_public_keys;
        Ok(snapshot.audit)
    }

    #[cfg(test)]
    fn refresh_signed_threat_domain_policy_once(
        &mut self,
        trusted_public_keys: &mut BTreeMap<String, String>,
        metadata_url: &str,
        feed_url: &str,
        metadata_cache_path: Option<&Path>,
        feed_cache_path: Option<&Path>,
        now_ms: u64,
    ) -> Result<SignedThreatDomainRefreshResult, String> {
        let metadata_json = fetch_threat_domain_feed_url(metadata_url)
            .map_err(|error| format!("failed to fetch signed threat metadata: {error}"))?;
        let feed_contents = fetch_threat_domain_feed_url(feed_url)
            .map_err(|error| format!("failed to fetch signed threat feed: {error}"))?;
        let snapshot = build_verified_signed_threat_domain_policy_snapshot(
            &self.browser_hardening_policy,
            trusted_public_keys,
            &metadata_json,
            &feed_contents,
            now_ms,
        )?;
        let cache_write_error = match (metadata_cache_path, feed_cache_path) {
            (Some(metadata_cache_path), Some(feed_cache_path)) => write_signed_threat_domain_cache(
                metadata_cache_path,
                feed_cache_path,
                &metadata_json,
                &feed_contents,
            )
            .err(),
            (None, None) => None,
            _ => Some(
                "signed threat metadata and feed cache paths must be configured together".into(),
            ),
        };
        self.browser_hardening_policy = snapshot.policy;
        *trusted_public_keys = snapshot.trusted_public_keys;
        Ok(SignedThreatDomainRefreshResult {
            audit: snapshot.audit,
            metadata: snapshot.metadata,
            cache_write_error,
        })
    }

    pub fn with_privacy_mode(mut self, privacy_mode: PrivacyMode) -> Self {
        self.privacy_mode = privacy_mode;
        if !privacy_mode.retains_history() {
            self.otlp_exporter = None;
            self.otlp_http_exporter = None;
            self.events.clear();
            self.session_act_batch_idempotency.clear();
        }
        self
    }

    pub fn with_navigation_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.browser_hardening_policy = self
            .browser_hardening_policy
            .clone()
            .with_url_policy(url_policy.clone());
        self.url_policy = url_policy;
        if let Some(driver) = self.driver.take() {
            self.driver = Some(driver.with_navigation_url_policy(self.url_policy.clone()));
        }
        self
    }

    pub fn with_browser_hardening_policy(
        mut self,
        browser_hardening_policy: BrowserHardeningPolicy,
    ) -> Self {
        self.url_policy = browser_hardening_policy.url_policy().clone();
        self.browser_hardening_policy = browser_hardening_policy.clone();
        if let Some(driver) = self.driver.take() {
            self.driver = Some(driver.with_browser_hardening_policy(browser_hardening_policy));
        }
        self
    }

    pub fn with_identity_strategy_table(
        mut self,
        identity_strategy_table: IdentityStrategyTable,
    ) -> Self {
        self.identity_strategy_table = identity_strategy_table;
        self
    }

    pub fn identity_strategy_table(&self) -> &IdentityStrategyTable {
        &self.identity_strategy_table
    }

    fn record_identity_strategy_outcome(
        &mut self,
        id: &TempodSessionId,
        observation: &CompiledObservation,
        human_takeover: Option<HumanTakeover>,
    ) {
        let human_driven = human_takeover.is_some();
        if let Some(takeover) = human_takeover
            && let Err(error) = self.record_human_takeover(id, takeover)
        {
            log_tempod_warn("failed to record human takeover")
                .field("session_id", id.0.clone())
                .field("url", observation.url.clone())
                .field("error", error.to_string())
                .emit();
        }
        if let Err(error) = self
            .identity_strategy_table
            .record_request(&observation.url, human_driven)
        {
            log_tempod_warn("failed to update identity strategy")
                .field("session_id", id.0.clone())
                .field("url", observation.url.clone())
                .field("error", error.to_string())
                .emit();
        }
    }

    #[cfg(test)]
    fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
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

    pub fn with_otlp_http_exporter(mut self, exporter: OtlpHttpExporter) -> Self {
        if self.privacy_mode.retains_history() {
            self.otlp_http_exporter = Some(exporter);
        }
        self
    }

    pub fn otlp_http_exporter(&self) -> Option<&OtlpHttpExporter> {
        self.otlp_http_exporter.as_ref()
    }

    /// Create a session while exclusively holding the pool. The HTTP path uses
    /// [`create_session_shared`] instead, which runs the engine round-trips
    /// WITHOUT the pool lock so other sessions and metadata routes stay live
    /// (issue #230); this method serves already-locked callers (tests, and
    /// driverless metadata-only pools).
    pub fn create(&mut self, url: impl Into<String>) -> Result<TempodSession, TempodError> {
        self.ensure_accepting_session()?;
        let url = url.into();
        enforce_tempod_navigation_url(&self.browser_hardening_policy, &url)?;
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

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    fn session_limit_reached(&self) -> bool {
        self.sessions.len() >= self.max_sessions
    }

    fn ensure_accepting_session(&self) -> Result<(), TempodError> {
        if self.draining {
            return Err(TempodError::Draining);
        }
        if self.session_limit_reached() {
            return Err(TempodError::SessionLimit {
                max: self.max_sessions,
            });
        }
        Ok(())
    }

    fn engine_attached(&self) -> bool {
        self.driver.is_some()
    }

    /// A root engine driver is attached but its IPC connection has been marked
    /// dead (engine child exited / socket disconnected). This is the terminal
    /// state #398 fixes: the dead driver fast-fails every request with
    /// `IpcClosed` yet is never swapped out, so the node zombifies. The liveness
    /// monitor polls this to trigger reconnect + re-attach; readiness reports it.
    fn engine_driver_dead(&self) -> bool {
        self.driver
            .as_ref()
            .is_some_and(AttachedEngineDriver::is_dead)
    }

    /// An engine driver is attached AND its IPC connection is still live. This is
    /// the condition readiness cares about: a dead-but-attached driver is not a
    /// serviceable engine.
    fn engine_live(&self) -> bool {
        self.driver.as_ref().is_some_and(|driver| !driver.is_dead())
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
            if session.state == TempodSessionState::Killed {
                return Err(TempodError::Conflict(format!(
                    "session {} is killed and cannot be adopted",
                    id.0
                )));
            }
            session.state = TempodSessionState::Adopted;
            session.clone()
        };
        self.record_event(id, TempodSessionEventKind::SessionAdopted);
        Ok(session.clone())
    }

    /// Mark that a human has handed control back to the agent after an adopted
    /// takeover window. This records an auditable control-plane event; it does
    /// not bypass browser hardening or auto-clear a page challenge.
    pub fn resume(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        if self.draining {
            return Err(TempodError::Draining);
        }
        let session = {
            let session = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
            if session.state != TempodSessionState::Adopted {
                return Err(TempodError::Conflict(format!(
                    "session {} must be adopted before it can be resumed",
                    id.0
                )));
            }
            session.state = TempodSessionState::Running;
            session.clone()
        };
        self.record_event(id, TempodSessionEventKind::SessionResumed);
        Ok(session)
    }

    /// Kill a session, closing its engine context. Retained for direct
    /// (non-HTTP) callers; the HTTP `DELETE /sessions/{id}` path uses
    /// [`route_session_kill`], which runs the `Close` OFF the pool lock (#440).
    /// Both share [`close_detached_session_driver`], so neither abandons the
    /// shared engine merely because one session's `Close` was slow.
    pub fn kill(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        let (session, detached, root) = self.begin_kill(id)?;
        if let Some(driver) = detached
            && close_detached_session_driver(id.0.clone(), driver, root)
        {
            self.abandon_attached_engine_after_teardown_timeout("session engine context Close");
        }
        Ok(session)
    }

    /// Locked phase of a session kill: flip the session to `Killed`, DETACH its
    /// engine context from the map (so the session is immediately unreachable —
    /// `session_driver` fails fast for it), and record the lifecycle change.
    /// The detached driver's bounded `Close` and the abandon decision happen
    /// afterwards on the returned handles, off the pool lock for the HTTP path
    /// (#440, mirroring `create_session_shared` #230). Also returns a root
    /// driver clone for the off-lock liveness probe.
    fn begin_kill(
        &mut self,
        id: &TempodSessionId,
    ) -> Result<
        (
            TempodSession,
            Option<AttachedEngineDriver>,
            Option<AttachedEngineDriver>,
        ),
        TempodError,
    > {
        let session = {
            let session = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
            session.state = TempodSessionState::Killed;
            session.clone()
        };
        let detached = self.session_drivers.remove(id);
        let root = self.driver.clone();
        self.clear_session_idempotency(id);
        self.record_event(id, TempodSessionEventKind::SessionKilled);
        self.purge_terminal_session_if_stealth(id);
        Ok((session, detached, root))
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
            .with_browser_hardening_policy(self.browser_hardening_policy.clone());
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
                    log_tempod_error("error closing forked BiDi context at teardown", error);
                }
            }
            // Then MCP forks.
            if let Some(server) = mcp {
                for error in futures::executor::block_on(server.close_all_forks()) {
                    log_tempod_error("error closing MCP fork at teardown", error);
                }
            }
            // Then session-owned engine contexts.
            for (id, mut driver) in session_drivers {
                if let Err(error) = futures::executor::block_on(driver.close()) {
                    tempo_telemetry::logger()
                        .event(
                            tempo_telemetry::Level::Error,
                            "tempod",
                            "error closing session engine context at teardown",
                        )
                        .field("session_id", id)
                        .field("error", error.to_string())
                        .emit();
                }
            }
            // Finally the root driver's Close (only when close_root).
            if let Some(mut driver) = root
                && let Err(error) = futures::executor::block_on(driver.close())
            {
                log_tempod_error("error closing root engine driver at teardown", error);
            }
            let _ = tx.send(());
        });
        match rx.recv_timeout(timeout) {
            Ok(()) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                log_tempod_warn("engine-resource teardown timed out")
                    .field("timeout", format!("{timeout:?}"))
                    .field("issue", "#200")
                    .emit();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                log_tempod_warn("engine-resource teardown thread ended without a result").emit();
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
            tempod_resolved_navigation_url_policy_denial(&root_driver.browser_hardening_policy, url)
        {
            return Err(TempodError::BrowserHardeningBlocked(Box::new(message)));
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
            log_tempod_error("error closing forked BiDi context at teardown", error);
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
                log_tempod_error("error closing removed BiDi context at teardown", error);
            }
            None => {
                self.abandon_attached_engine_after_teardown_timeout("removed BiDi context Close");
            }
        }
    }

    fn abandon_attached_engine_after_teardown_timeout(&mut self, label: &'static str) {
        log_tempod_warn("attached engine IPC was abandoned")
            .field("label", label)
            .field("issue", "#200")
            .emit();
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
        // `begin_kill` `remove`s the killed session's single driver (closed
        // off-lock by `close_detached_session_driver`) before this can run, and
        // the create `on_orphan` path owns the freshly created context, so the
        // map contents drained here are disjoint from those already-owned
        // drivers.
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
                log_tempod_error("OTLP step export failed", error);
            }
        }
        if let Some(exporter) = &self.otlp_http_exporter {
            // Same best-effort contract for the collector lane (issue #249):
            // the span is redacted, then handed to the export worker without
            // blocking; a full queue or dead worker only logs.
            if let Err(error) = exporter.export_step(&triple) {
                log_tempod_error("OTLP/HTTP step export failed", error);
            }
        }
        Ok(self.record_event(id, TempodSessionEventKind::StepTriple { triple }))
    }

    /// Record a human-takeover pause onto the session's event stream (#244/#343):
    /// the typed signal a windowed client turns into a blocking takeover banner.
    ///
    /// This is the recording API for the takeover event; the producer wire that
    /// calls it — the agent loop reporting a detected takeover to tempod — is the
    /// same deferred agent↔tempod bridge that already gates [`Self::record_step`]
    /// (both have no HTTP route today; #247 shared-session wiring). tempod never
    /// solves the challenge: this only journals that a human is needed.
    pub fn record_human_takeover(
        &mut self,
        id: &TempodSessionId,
        takeover: HumanTakeover,
    ) -> Result<TempodSessionEvent, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        Ok(self.record_event(
            id,
            TempodSessionEventKind::HumanTakeoverRequired { takeover },
        ))
    }

    pub fn record_browser_hardening_block(
        &mut self,
        id: &TempodSessionId,
        block: TempodBrowserHardeningBlock,
    ) -> Result<TempodSessionEvent, TempodError> {
        if !self.sessions.contains_key(id) {
            return Err(TempodError::SessionNotFound(id.clone()));
        }
        Ok(self.record_event(
            id,
            TempodSessionEventKind::BrowserHardeningBlocked { block },
        ))
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
        if !self.privacy_mode.retains_history() {
            return TempodSessionEvent {
                session_id: id.clone(),
                seq: 0,
                timestamp_ms: current_time_ms(),
                event,
            };
        }
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
            log_tempod_error(
                "panic while closing engine resources during SessionPool drop",
                "panic",
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
            log_tempod_warn("teardown worker timed out")
                .field("label", label)
                .field("timeout", format!("{timeout:?}"))
                .field("issue", "#200")
                .emit();
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            log_tempod_warn("teardown worker ended without a result")
                .field("label", label)
                .emit();
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
            log_tempod_warn("session-create engine navigation timed out")
                .field("timeout", format!("{timeout:?}"))
                .field("issue", "#213")
                .emit();
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            log_tempod_warn("session-create engine worker ended without a result").emit();
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

struct ThreatDomainFeedSnapshot {
    contents: String,
    source: &'static str,
    env: &'static str,
    cache_write_error: Option<String>,
}

impl ThreatDomainFeedSnapshot {
    const fn cache_write_failed(&self) -> bool {
        self.cache_write_error.is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ThreatDomainSignedMetadata {
    version: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    feed_sha256: String,
    key_id: String,
    signature: String,
    #[serde(default)]
    next_key_id: Option<String>,
    #[serde(default)]
    next_public_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedThreatDomainMetadata {
    version: String,
    key_id: String,
    feed_sha256: String,
    next_key_id: Option<String>,
    next_public_key: Option<String>,
}

fn verify_signed_threat_domain_metadata(
    metadata_json: &str,
    feed_contents: &str,
    trusted_public_keys: &BTreeMap<String, String>,
    now_ms: u64,
) -> Result<VerifiedThreatDomainMetadata, String> {
    let metadata: ThreatDomainSignedMetadata = serde_json::from_str(metadata_json)
        .map_err(|error| format!("invalid threat-feed metadata JSON: {error}"))?;
    if metadata.expires_at_ms <= now_ms {
        return Err("threat-feed metadata is expired".into());
    }
    if metadata.issued_at_ms > metadata.expires_at_ms {
        return Err("threat-feed metadata issued_at is after expires_at".into());
    }
    let normalized_feed_sha256 = normalize_sha256_hex(&metadata.feed_sha256)?;
    let actual_feed_sha256 = sha256_hex(feed_contents.as_bytes());
    if !constant_time_eq(
        actual_feed_sha256.as_bytes(),
        normalized_feed_sha256.as_bytes(),
    ) {
        return Err("threat-feed metadata digest does not match feed bytes".into());
    }
    let public_key = trusted_public_keys
        .get(&metadata.key_id)
        .ok_or_else(|| "threat-feed metadata key_id is not trusted".to_string())?;
    let public_key_bytes = BASE64_STANDARD
        .decode(public_key)
        .map_err(|error| format!("invalid trusted threat-feed public key: {error}"))?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "trusted threat-feed public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| format!("invalid trusted threat-feed public key: {error}"))?;
    let signature_bytes = BASE64_STANDARD
        .decode(metadata.signature.as_bytes())
        .map_err(|error| format!("invalid threat-feed metadata signature: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| format!("invalid threat-feed metadata signature: {error}"))?;
    let payload = threat_domain_metadata_signing_payload(&metadata)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|error| format!("threat-feed metadata signature verification failed: {error}"))?;
    if metadata.next_key_id.is_some() != metadata.next_public_key.is_some() {
        return Err("threat-feed key rotation must include next_key_id and next_public_key".into());
    }
    if let Some(next_public_key) = &metadata.next_public_key {
        let next_public_key_bytes = BASE64_STANDARD
            .decode(next_public_key)
            .map_err(|error| format!("invalid next threat-feed public key: {error}"))?;
        let next_public_key_bytes: [u8; 32] = next_public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "next threat-feed public key must be 32 bytes".to_string())?;
        VerifyingKey::from_bytes(&next_public_key_bytes)
            .map_err(|error| format!("invalid next threat-feed public key: {error}"))?;
    }
    Ok(VerifiedThreatDomainMetadata {
        version: metadata.version,
        key_id: metadata.key_id,
        feed_sha256: normalized_feed_sha256,
        next_key_id: metadata.next_key_id,
        next_public_key: metadata.next_public_key,
    })
}

fn threat_domain_metadata_signing_payload(
    metadata: &ThreatDomainSignedMetadata,
) -> Result<Vec<u8>, String> {
    let mut payload = BTreeMap::new();
    payload.insert("expires_at_ms", json!(metadata.expires_at_ms));
    payload.insert(
        "feed_sha256",
        json!(normalize_sha256_hex(&metadata.feed_sha256)?),
    );
    payload.insert("issued_at_ms", json!(metadata.issued_at_ms));
    payload.insert("key_id", json!(metadata.key_id));
    if let Some(next_key_id) = &metadata.next_key_id {
        payload.insert("next_key_id", json!(next_key_id));
    }
    if let Some(next_public_key) = &metadata.next_public_key {
        payload.insert("next_public_key", json!(next_public_key));
    }
    payload.insert("version", json!(metadata.version));
    serde_json::to_vec(&payload)
        .map_err(|error| format!("failed to encode threat-feed metadata payload: {error}"))
}

fn write_signed_threat_domain_cache(
    metadata_path: &Path,
    feed_path: &Path,
    metadata_json: &str,
    feed_contents: &str,
) -> Result<(), String> {
    write_threat_domain_cache(metadata_path, metadata_json)?;
    write_threat_domain_cache(feed_path, feed_contents)
}

#[cfg(test)]
fn read_signed_threat_domain_cache(
    metadata_path: &Path,
    feed_path: &Path,
    trusted_public_keys: &BTreeMap<String, String>,
    now_ms: u64,
) -> Result<(String, VerifiedThreatDomainMetadata), String> {
    let metadata_json = read_owner_only_text_file(metadata_path)
        .map_err(|error| format!("failed to read signed metadata cache: {error}"))?;
    let feed_contents = read_owner_only_text_file(feed_path)
        .map_err(|error| format!("failed to read signed feed cache: {error}"))?;
    let verified = verify_signed_threat_domain_metadata(
        &metadata_json,
        &feed_contents,
        trusted_public_keys,
        now_ms,
    )?;
    Ok((feed_contents, verified))
}

fn apply_verified_threat_domain_key_rotation(
    trusted_public_keys: &BTreeMap<String, String>,
    verified: &VerifiedThreatDomainMetadata,
) -> Result<BTreeMap<String, String>, String> {
    let mut next_trusted = trusted_public_keys.clone();
    let (Some(next_key_id), Some(next_public_key)) =
        (&verified.next_key_id, &verified.next_public_key)
    else {
        return Ok(next_trusted);
    };
    if next_key_id.trim().is_empty() {
        return Err("threat-feed next key id must not be empty".into());
    }
    if next_trusted.contains_key(next_key_id) {
        return Err("threat-feed next key id already exists".into());
    }
    let next_public_key_bytes = BASE64_STANDARD
        .decode(next_public_key)
        .map_err(|error| format!("invalid next threat-feed public key: {error}"))?;
    let next_public_key_bytes: [u8; 32] = next_public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "next threat-feed public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&next_public_key_bytes)
        .map_err(|error| format!("invalid next threat-feed public key: {error}"))?;
    next_trusted.insert(next_key_id.clone(), next_public_key.clone());
    Ok(next_trusted)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedThreatDomainPolicySnapshot {
    policy: BrowserHardeningPolicy,
    trusted_public_keys: BTreeMap<String, String>,
    audit: ThreatDomainProviderAudit,
    metadata: VerifiedThreatDomainMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
struct SignedThreatDomainRefreshResult {
    audit: ThreatDomainProviderAudit,
    metadata: VerifiedThreatDomainMetadata,
    cache_write_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedThreatDomainRefreshConfig {
    metadata_url: String,
    feed_url: String,
    metadata_cache_path: Option<PathBuf>,
    feed_cache_path: Option<PathBuf>,
    trusted_public_keys: BTreeMap<String, String>,
    interval: Duration,
}

fn signed_threat_domain_refresh_config_from_env() -> Option<SignedThreatDomainRefreshConfig> {
    let metadata_url = std::env::var(TEMPO_THREAT_DOMAIN_METADATA_URL_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let feed_url = std::env::var(TEMPO_THREAT_DOMAIN_URL_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let trusted_public_keys = match parse_signed_threat_domain_public_keys_env(std::env::var_os(
        TEMPO_THREAT_DOMAIN_PUBLIC_KEYS_ENV,
    )) {
        Ok(keys) if !keys.is_empty() => keys,
        Ok(_) => {
            log_tempod_warn("signed threat-feed refresh disabled without public keys")
                .field("env", TEMPO_THREAT_DOMAIN_PUBLIC_KEYS_ENV)
                .emit();
            return None;
        }
        Err(error) => {
            log_tempod_warn("signed threat-feed refresh disabled by invalid public keys")
                .field("env", TEMPO_THREAT_DOMAIN_PUBLIC_KEYS_ENV)
                .field("error", error)
                .emit();
            return None;
        }
    };
    let interval = parse_signed_threat_domain_refresh_interval_env(std::env::var_os(
        TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS_ENV,
    ));
    Some(SignedThreatDomainRefreshConfig {
        metadata_url,
        feed_url,
        metadata_cache_path: std::env::var_os(TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE_ENV)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from),
        feed_cache_path: std::env::var_os(TEMPO_THREAT_DOMAIN_CACHE_FILE_ENV)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from),
        trusted_public_keys,
        interval,
    })
}

fn spawn_signed_threat_domain_refresh_supervisor_from_env(pool: Arc<Mutex<SessionPool>>) {
    let Some(config) = signed_threat_domain_refresh_config_from_env() else {
        return;
    };
    spawn_signed_threat_domain_refresh_supervisor(pool, config);
}

fn spawn_signed_threat_domain_refresh_supervisor(
    pool: Arc<Mutex<SessionPool>>,
    config: SignedThreatDomainRefreshConfig,
) {
    let _ = thread::Builder::new()
        .name("tempod-threat-feed-refresh".into())
        .spawn(move || signed_threat_domain_refresh_worker(pool, config))
        .map_err(|error| {
            log_tempod_error("signed threat-feed refresh worker failed to start", error)
        });
}

fn signed_threat_domain_refresh_worker(
    pool: Arc<Mutex<SessionPool>>,
    config: SignedThreatDomainRefreshConfig,
) {
    let mut trusted_public_keys = config.trusted_public_keys.clone();
    loop {
        run_signed_threat_domain_refresh_pass(&pool, &config, &mut trusted_public_keys);
        thread::sleep(config.interval);
    }
}

fn run_signed_threat_domain_refresh_pass(
    pool: &Arc<Mutex<SessionPool>>,
    config: &SignedThreatDomainRefreshConfig,
    trusted_public_keys: &mut BTreeMap<String, String>,
) {
    let metadata_json = match fetch_threat_domain_feed_url(&config.metadata_url) {
        Ok(metadata_json) => metadata_json,
        Err(error) => {
            log_tempod_warn("signed threat-feed metadata refresh failed")
                .field("env", TEMPO_THREAT_DOMAIN_METADATA_URL_ENV)
                .field("error", error)
                .emit();
            return;
        }
    };
    let feed_contents = match fetch_threat_domain_feed_url(&config.feed_url) {
        Ok(feed_contents) => feed_contents,
        Err(error) => {
            log_tempod_warn("signed threat-feed refresh failed")
                .field("env", TEMPO_THREAT_DOMAIN_URL_ENV)
                .field("error", error)
                .emit();
            return;
        }
    };
    let now_ms = current_time_ms() as u64;
    let refresh = {
        let mut pool = match pool.lock() {
            Ok(pool) => pool,
            Err(_) => {
                log_tempod_warn("signed threat-feed refresh skipped because pool lock is poisoned")
                    .emit();
                return;
            }
        };
        pool.apply_verified_signed_threat_domain_policy_snapshot(
            trusted_public_keys,
            &metadata_json,
            &feed_contents,
            now_ms,
        )
    };
    match refresh {
        Ok(audit) => {
            let cache_write_error = match (
                config.metadata_cache_path.as_deref(),
                config.feed_cache_path.as_deref(),
            ) {
                (Some(metadata_cache_path), Some(feed_cache_path)) => {
                    write_signed_threat_domain_cache(
                        metadata_cache_path,
                        feed_cache_path,
                        &metadata_json,
                        &feed_contents,
                    )
                    .err()
                }
                (None, None) => None,
                _ => Some(
                    "signed threat metadata and feed cache paths must be configured together"
                        .into(),
                ),
            };
            if let Some(error) = cache_write_error {
                log_tempod_warn("signed threat-feed cache write failed")
                    .field("error", error)
                    .emit();
            }
            tempo_telemetry::logger()
                .event(
                    tempo_telemetry::Level::Info,
                    "tempod",
                    "signed threat-feed refresh applied",
                )
                .field("provider_id", audit.provider_id)
                .field("rule_count", audit.rule_count.to_string())
                .field("exact_rules", audit.exact_rules.to_string())
                .field("suffix_rules", audit.suffix_rules.to_string())
                .emit();
        }
        Err(error) => {
            log_tempod_warn("signed threat-feed refresh verification failed")
                .field("error", error)
                .emit();
        }
    }
}

fn build_verified_signed_threat_domain_policy_snapshot(
    current_policy: &BrowserHardeningPolicy,
    trusted_public_keys: &BTreeMap<String, String>,
    metadata_json: &str,
    feed_contents: &str,
    now_ms: u64,
) -> Result<VerifiedThreatDomainPolicySnapshot, String> {
    let metadata = verify_signed_threat_domain_metadata(
        metadata_json,
        feed_contents,
        trusted_public_keys,
        now_ms,
    )?;
    let provider = StaticThreatDomainProvider::from_feed_lines(
        "tempo-signed-threat-domain-feed",
        feed_contents,
    )
    .map_err(|error| error.to_string())?;
    let trusted_public_keys =
        apply_verified_threat_domain_key_rotation(trusted_public_keys, &metadata)?;
    let mut policy = current_policy.clone();
    let audit = policy.apply_threat_domain_provider(&provider);
    Ok(VerifiedThreatDomainPolicySnapshot {
        policy,
        trusted_public_keys,
        audit,
        metadata,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreatDomainFeedFailureMode {
    FailClosed,
    FailOpen,
}

impl ThreatDomainFeedFailureMode {
    const fn fail_closed(self) -> bool {
        matches!(self, Self::FailClosed)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
        }
    }
}

fn parse_threat_domain_failure_mode_env(
    value: Option<std::ffi::OsString>,
) -> ThreatDomainFeedFailureMode {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return ThreatDomainFeedFailureMode::FailClosed;
    };
    let Ok(value) = value.into_string() else {
        log_tempod_warn("using fail-closed for non-UTF-8 threat-domain failure mode")
            .field("env", TEMPO_THREAT_DOMAIN_FAILURE_MODE_ENV)
            .emit();
        return ThreatDomainFeedFailureMode::FailClosed;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "fail_open" | "fail-open" | "open" => ThreatDomainFeedFailureMode::FailOpen,
        "fail_closed" | "fail-closed" | "closed" => ThreatDomainFeedFailureMode::FailClosed,
        other => {
            log_tempod_warn("using fail-closed for invalid threat-domain failure mode")
                .field("env", TEMPO_THREAT_DOMAIN_FAILURE_MODE_ENV)
                .field("value", other)
                .emit();
            ThreatDomainFeedFailureMode::FailClosed
        }
    }
}

fn fetch_threat_domain_feed_url_or_cache(
    url: &str,
    cache_path: Option<&Path>,
    expected_sha256: Option<&str>,
    max_stale: Duration,
) -> Result<ThreatDomainFeedSnapshot, String> {
    match fetch_threat_domain_feed_url(url)
        .and_then(|contents| verify_threat_domain_feed_sha256(contents, expected_sha256))
    {
        Ok(contents) => {
            let cache_write_error = if let Some(cache_path) = cache_path {
                write_threat_domain_cache(cache_path, &contents).err()
            } else {
                None
            };
            Ok(ThreatDomainFeedSnapshot {
                contents,
                source: "env_https_url",
                env: TEMPO_THREAT_DOMAIN_URL_ENV,
                cache_write_error,
            })
        }
        Err(remote_error) => {
            let Some(cache_path) = cache_path else {
                return Err(remote_error);
            };
            let contents = read_threat_domain_cache(cache_path, expected_sha256, max_stale)
                .map_err(|cache_error| {
                    format!("{remote_error}; cache unavailable: {cache_error}")
                })?;
            Ok(ThreatDomainFeedSnapshot {
                contents,
                source: "env_cache_file",
                env: TEMPO_THREAT_DOMAIN_CACHE_FILE_ENV,
                cache_write_error: None,
            })
        }
    }
}

fn fetch_threat_domain_feed_url(url: &str) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|error| format!("invalid URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("threat-domain feed URL must use https".into());
    }
    UrlPolicy::block_private()
        .enforce(parsed.as_str())
        .map_err(|error| error.to_string())?;
    let client = reqwest::blocking::Client::builder()
        .timeout(TEMPO_THREAT_DOMAIN_REMOTE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    let response = client
        .get(parsed.as_str())
        .send()
        .map_err(|error| format!("failed to fetch threat-domain feed: {error}"))?;
    if response.status().is_redirection() {
        return Err("threat-domain feed redirects are not followed".into());
    }
    if !response.status().is_success() {
        return Err(format!(
            "threat-domain feed returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > TEMPO_THREAT_DOMAIN_REMOTE_MAX_BYTES)
    {
        return Err(format!(
            "threat-domain feed exceeds {} bytes",
            TEMPO_THREAT_DOMAIN_REMOTE_MAX_BYTES
        ));
    }
    let bytes = response
        .bytes()
        .map_err(|error| format!("failed to read threat-domain feed: {error}"))?;
    if bytes.len() > TEMPO_THREAT_DOMAIN_REMOTE_MAX_BYTES as usize {
        return Err(format!(
            "threat-domain feed exceeds {} bytes",
            TEMPO_THREAT_DOMAIN_REMOTE_MAX_BYTES
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("threat-domain feed is not UTF-8: {error}"))
}

fn verify_threat_domain_feed_sha256(
    contents: String,
    expected_sha256: Option<&str>,
) -> Result<String, String> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(contents);
    };
    let actual = sha256_hex(contents.as_bytes());
    if constant_time_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
        Ok(contents)
    } else {
        Err("threat-domain feed SHA-256 digest mismatch".into())
    }
}

fn parse_optional_sha256_env(value: Option<std::ffi::OsString>) -> Result<Option<String>, String> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| "digest pin must be UTF-8".to_string())?;
    normalize_sha256_hex(&value).map(Some)
}

fn normalize_sha256_hex(value: &str) -> Result<String, String> {
    let value = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_ascii_lowercase();
    let valid = value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if valid {
        Ok(value)
    } else {
        Err("digest pin must be a 64-character hexadecimal SHA-256 value".into())
    }
}

fn parse_threat_domain_max_stale_env(value: Option<std::ffi::OsString>) -> Duration {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return TEMPO_THREAT_DOMAIN_DEFAULT_MAX_STALE;
    };
    let Ok(value) = value.into_string() else {
        log_tempod_warn("ignoring non-UTF-8 threat-domain stale-cache limit")
            .field("env", TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS_ENV)
            .emit();
        return TEMPO_THREAT_DOMAIN_DEFAULT_MAX_STALE;
    };
    match value.trim().parse::<u64>() {
        Ok(seconds) => Duration::from_secs(seconds),
        Err(error) => {
            log_tempod_warn("ignoring invalid threat-domain stale-cache limit")
                .field("env", TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS_ENV)
                .field("error", error.to_string())
                .emit();
            TEMPO_THREAT_DOMAIN_DEFAULT_MAX_STALE
        }
    }
}

fn parse_signed_threat_domain_refresh_interval_env(value: Option<std::ffi::OsString>) -> Duration {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL;
    };
    let Ok(value) = value.into_string() else {
        log_tempod_warn("using default signed threat-feed refresh interval for non-UTF-8 value")
            .field("env", TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS_ENV)
            .emit();
        return TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL;
    };
    match value.trim().parse::<u64>() {
        Ok(seconds) if seconds >= 60 => Duration::from_secs(seconds),
        Ok(_) => {
            log_tempod_warn("using default signed threat-feed refresh interval below minimum")
                .field("env", TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS_ENV)
                .emit();
            TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL
        }
        Err(error) => {
            log_tempod_warn("using default signed threat-feed refresh interval for invalid value")
                .field("env", TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS_ENV)
                .field("error", error.to_string())
                .emit();
            TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL
        }
    }
}

fn parse_signed_threat_domain_public_keys_env(
    value: Option<std::ffi::OsString>,
) -> Result<BTreeMap<String, String>, String> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(BTreeMap::new());
    };
    let value = value
        .into_string()
        .map_err(|_| "signed threat-feed public keys must be UTF-8".to_string())?;
    let mut keys = BTreeMap::new();
    for raw_entry in value.split(',') {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key_id, public_key) = entry
            .split_once('=')
            .ok_or_else(|| "public key entries must be key_id=base64".to_string())?;
        let key_id = key_id.trim();
        let public_key = public_key.trim();
        if key_id.is_empty() {
            return Err("public key id must not be empty".into());
        }
        if keys.contains_key(key_id) {
            return Err("duplicate public key id".into());
        }
        let public_key_bytes = BASE64_STANDARD
            .decode(public_key)
            .map_err(|error| format!("invalid signed threat-feed public key: {error}"))?;
        let public_key_bytes: [u8; 32] = public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signed threat-feed public key must be 32 bytes".to_string())?;
        VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|error| format!("invalid signed threat-feed public key: {error}"))?;
        keys.insert(key_id.to_string(), public_key.to_string());
    }
    Ok(keys)
}

fn read_threat_domain_cache(
    path: &Path,
    expected_sha256: Option<&str>,
    max_stale: Duration,
) -> Result<String, String> {
    let metadata = validate_owner_only_cache_file(path)?;
    let age = metadata
        .modified()
        .map_err(|error| format!("failed to read cache mtime: {error}"))?
        .elapsed()
        .map_err(|error| format!("failed to compute cache age: {error}"))?;
    if age > max_stale {
        return Err("cache is older than the configured stale limit".into());
    }
    let contents =
        std::fs::read_to_string(path).map_err(|error| format!("failed to read cache: {error}"))?;
    verify_threat_domain_feed_sha256(contents, expected_sha256)
}

#[cfg(test)]
fn read_owner_only_text_file(path: &Path) -> Result<String, String> {
    validate_owner_only_cache_file(path)?;
    std::fs::read_to_string(path).map_err(|error| format!("failed to read cache: {error}"))
}

fn validate_owner_only_cache_file(path: &Path) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to stat cache: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("cache path must not be a symlink".into());
    }
    if !metadata.file_type().is_file() {
        return Err("cache path is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("cache file must be owner-only".into());
        }
    }
    Ok(metadata)
}

fn write_threat_domain_cache(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create cache directory: {error}"))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("cache path must not be a symlink".into());
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err("cache path is not a regular file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to stat cache: {error}")),
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to open cache: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("failed to secure cache permissions: {error}"))?;
    }
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("failed to write cache: {error}"))?;
    file.flush()
        .map_err(|error| format!("failed to flush cache: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// JSONL exporter for count-only threat-domain feed audit records.
#[derive(Clone)]
pub struct ThreatDomainAuditJsonExporter {
    path: PathBuf,
    handle: Arc<Mutex<Option<File>>>,
}

impl fmt::Debug for ThreatDomainAuditJsonExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreatDomainAuditJsonExporter")
            .field("path", &self.path)
            .field(
                "open",
                &self.handle.lock().map(|guard| guard.is_some()).ok(),
            )
            .finish()
    }
}

impl ThreatDomainAuditJsonExporter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            handle: Arc::new(Mutex::new(None)),
        }
    }

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
            options.mode(0o600);
        }
        let file = options.open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }

    pub fn export_audit(&self, audit: &ThreatDomainProviderAudit) -> Result<(), TempodError> {
        self.export_audit_from(audit, "env_file", TEMPO_THREAT_DOMAIN_FILE_ENV, false)
    }

    pub fn export_audit_from(
        &self,
        audit: &ThreatDomainProviderAudit,
        source: &'static str,
        env: &'static str,
        cache_write_failed: bool,
    ) -> Result<(), TempodError> {
        let mut bytes = serde_json::to_vec(&json!({
            "timestamp_ms": current_time_ms(),
            "source": source,
            "env": env,
            "provider_id": audit.provider_id.as_str(),
            "rule_count": audit.rule_count,
            "exact_rules": audit.exact_rules,
            "suffix_rules": audit.suffix_rules,
            "cache_write_failed": cache_write_failed,
        }))?;
        bytes.push(b'\n');

        let mut guard = self.handle.lock().map_err(|_| TempodError::PoolLock)?;
        if guard.is_none() {
            *guard = Some(self.open_append_file()?);
        }
        if let Some(file) = guard.as_mut() {
            file.write_all(&bytes)?;
            file.flush()?;
        }
        Ok(())
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

/// Path suffix mandated by the OTLP/HTTP spec for the traces signal.
const OTLP_TRACES_PATH: &str = "/v1/traces";
/// Bounded handoff between `record_step` and the export worker: when the
/// collector cannot keep up the queue fills and spans are dropped (logged),
/// never queued unboundedly and never blocking the step path.
const OTLP_EXPORT_QUEUE_CAPACITY: usize = 256;
/// Opportunistic batching bound: one HTTP request carries at most this many
/// spans.
const OTLP_EXPORT_BATCH_LIMIT: usize = 64;
/// Bound on one export POST so a stalled collector cannot wedge the worker
/// (and thereby turn the bounded queue into a permanent span sink).
const OTLP_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Real OTLP/HTTP exporter for StepTriple telemetry (issue #249, final.md §7):
/// posts spans to `{endpoint}/v1/traces` using the OTLP JSON encoding
/// (`application/json`), one span per recorded step.
///
/// The encoding is the OTLP `ExportTraceServiceRequest` JSON mapping built
/// with `serde_json`; the transport is a `reqwest` blocking client on one
/// dedicated worker thread. That keeps the dependency set to crates already
/// in the workspace instead of pulling the full `opentelemetry` SDK for a
/// single-signal, single-attribute-set exporter.
///
/// The issue #216 hardening carries over from the JSONL lane:
/// * Redaction happens in [`OtlpHttpExporter::export_step`], BEFORE the span
///   crosses the channel — raw secrets never reach the worker or the wire.
/// * Best-effort: `export_step` only does an in-memory `try_send`; a full
///   queue or dead worker returns an error the caller logs, and the step path
///   never blocks on collector I/O.
#[derive(Clone)]
pub struct OtlpHttpExporter {
    endpoint: String,
    sender: std::sync::mpsc::SyncSender<serde_json::Value>,
}

impl fmt::Debug for OtlpHttpExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OtlpHttpExporter")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl OtlpHttpExporter {
    /// Create an exporter posting to `endpoint` (a collector base URL such as
    /// `http://collector.internal:4318`; `/v1/traces` is appended when the
    /// endpoint does not already end with it) and spawn its worker thread.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, TempodError> {
        let endpoint = normalize_otlp_endpoint(&endpoint.into())?;
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<serde_json::Value>(OTLP_EXPORT_QUEUE_CAPACITY);
        let worker_endpoint = endpoint.clone();
        thread::Builder::new()
            .name("tempod-otlp-export".into())
            .spawn(move || otlp_export_worker(&worker_endpoint, &receiver))?;
        Ok(Self { endpoint, sender })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Redact and enqueue one step span. Never blocks: a full queue or a dead
    /// worker drops the span and reports why, so the caller can log it.
    pub fn export_step(&self, triple: &StepTriple) -> Result<(), TempodError> {
        let span = otlp_span_record(triple);
        self.sender.try_send(span).map_err(|error| match error {
            TrySendError::Full(_) => {
                TempodError::Driver("OTLP export queue is full; span dropped".into())
            }
            TrySendError::Disconnected(_) => {
                TempodError::Driver("OTLP export worker exited; span dropped".into())
            }
        })
    }
}

/// Validate and complete an OTLP/HTTP collector endpoint.
fn normalize_otlp_endpoint(endpoint: &str) -> Result<String, TempodError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let full = if trimmed.ends_with(OTLP_TRACES_PATH) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{OTLP_TRACES_PATH}")
    };
    let parsed = Url::parse(&full).map_err(|error| {
        TempodError::BadRequest(format!("invalid OTLP endpoint {endpoint:?}: {error}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(TempodError::BadRequest(format!(
            "OTLP endpoint {endpoint:?} must use http or https"
        )));
    }
    Ok(full)
}

/// Export worker: drains the bounded queue, batches opportunistically, and
/// POSTs OTLP JSON to the collector. Failures are logged and dropped —
/// telemetry only, by contract.
fn otlp_export_worker(endpoint: &str, receiver: &std::sync::mpsc::Receiver<serde_json::Value>) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(OTLP_HTTP_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            // Without a client every span would silently vanish; exit so
            // `export_step` reports a dead worker instead.
            log_tempod_error("OTLP export worker failed to start", error);
            return;
        }
    };
    while let Ok(first) = receiver.recv() {
        let mut spans = vec![first];
        while spans.len() < OTLP_EXPORT_BATCH_LIMIT {
            match receiver.try_recv() {
                Ok(span) => spans.push(span),
                Err(_) => break,
            }
        }
        let request = json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "tempod"}},
                    ],
                },
                "scopeSpans": [{
                    "scope": {"name": "tempo-headless"},
                    "spans": spans,
                }],
            }],
        });
        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(error) => {
                log_tempod_error("OTLP export encoding failed", error);
                continue;
            }
        };
        match client
            .post(endpoint)
            .header("content-type", "application/json")
            .body(body)
            .send()
        {
            Ok(response) if !response.status().is_success() => {
                log_tempod_warn("OTLP collector rejected export")
                    .field("status", response.status().as_u16())
                    .emit();
            }
            Ok(_) => {}
            Err(error) => {
                log_tempod_error("OTLP export failed", error);
            }
        }
    }
}

/// Build one OTLP JSON span for a step. Sensitive fields go through the same
/// redaction as the JSONL lane ([`redact_action`] / [`redact_step_outcome`]),
/// so both telemetry lanes have a single redaction source of truth.
fn otlp_span_record(triple: &StepTriple) -> serde_json::Value {
    let (trace_id, span_id) = otlp_ids();
    let now_ns = current_time_ns().to_string();
    let status_code = match &triple.outcome {
        StepTripleOutcome::Applied { .. } => 1,
        StepTripleOutcome::StepError { .. } => 2,
    };
    json!({
        "traceId": trace_id,
        "spanId": span_id,
        "name": "tempo.step",
        // SPAN_KIND_INTERNAL
        "kind": 1,
        "startTimeUnixNano": now_ns,
        "endTimeUnixNano": now_ns,
        "attributes": [
            {"key": "tempo.step.seq", "value": {"intValue": triple.seq.to_string()}},
            {"key": "tempo.step.action", "value": {"stringValue": redact_action(&triple.action).to_string()}},
            {"key": "tempo.step.outcome", "value": {"stringValue": redact_step_outcome(&triple.outcome).to_string()}},
        ],
        "status": {"code": status_code},
    })
}

/// Unique-enough trace/span ids without a dedicated RNG dependency: a
/// per-process urandom seed mixed with the wall clock and a monotone counter.
/// Telemetry-lane quality — not cryptographic, but distinct per step and (via
/// the seed) across hosts, which is what fleet observability needs.
fn otlp_ids() -> (String, String) {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        if let Ok(mut file) = File::open("/dev/urandom") {
            use std::io::Read as _;
            let _ = file.read_exact(&mut bytes);
        }
        u64::from_le_bytes(bytes) ^ u64::from(std::process::id()).rotate_left(32)
    });
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = current_time_ns();
    let time_lo = nanos as u64;
    let time_hi = (nanos >> 64) as u64;
    let trace_hi = seed ^ time_hi.rotate_left(17) ^ count.rotate_left(41);
    // The low word is forced non-zero so an all-zero (invalid) id is impossible.
    let trace_lo = (time_lo ^ count) | 1;
    let span = (seed.rotate_left(23) ^ time_lo ^ count.rotate_left(7)) | 1;
    (
        format!("{trace_hi:016x}{trace_lo:016x}"),
        format!("{span:016x}"),
    )
}

fn current_time_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

/// Run tempod forever on an address such as `127.0.0.1:8787`.
pub fn run_tempod(addr: &str) -> Result<(), TempodError> {
    run_tempod_with_config(addr, runtime_auth_server_config()?)
}

/// Run a tempod daemon without authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn run_tempod_unsafe(addr: &str) -> Result<(), TempodError> {
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
        runtime_auth_server_config()?,
        url_policy,
    )
}

/// Run tempod on an address without authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn run_tempod_with_navigation_url_policy_unsafe(
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
    run_tempod_with_config_and_navigation_url_policy_and_identity_strategy(
        addr,
        config,
        url_policy,
        IdentityStrategyTable::default(),
    )
}

pub fn run_tempod_with_config_and_navigation_url_policy_and_identity_strategy(
    addr: &str,
    config: TempodServerConfig,
    url_policy: UrlPolicy,
    identity_strategy_table: IdentityStrategyTable,
) -> Result<(), TempodError> {
    let config = config.with_bind_addr_host(addr);
    config.validate_bind_addr(addr)?;
    let listener = TcpListener::bind(addr)?;
    let pool = Arc::new(Mutex::new(
        SessionPool::from_env()
            .with_navigation_url_policy(url_policy)
            .with_identity_strategy_table(identity_strategy_table),
    ));
    spawn_signed_threat_domain_refresh_supervisor_from_env(Arc::clone(&pool));
    serve_forever_with_config(listener, pool, config)
}

/// Run tempod with an already-running engine reachable through the UDS driver protocol.
pub fn run_tempod_with_attached_driver(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config(addr, runtime_auth_server_config()?, engine, socket_path)
}

/// Run a tempod daemon with a pre-attached driver and no authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn run_tempod_with_attached_driver_unsafe(
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
    run_tempod_with_attached_driver_config_and_navigation_url_policy_and_identity_strategy(
        addr,
        config,
        engine,
        socket_path,
        UrlPolicy::block_private(),
        IdentityStrategyTable::default(),
    )
}

/// Run tempod with an attached engine and explicit navigation URL policy.
pub fn run_tempod_with_attached_driver_and_navigation_url_policy(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config_and_navigation_url_policy_and_identity_strategy(
        addr,
        runtime_auth_server_config()?,
        engine,
        socket_path,
        url_policy,
        IdentityStrategyTable::default(),
    )
}

/// Run a tempod daemon with a pre-attached engine and explicit URL policy,
/// without authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn run_tempod_with_attached_driver_and_navigation_url_policy_unsafe(
    addr: &str,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config_and_navigation_url_policy_and_identity_strategy(
        addr,
        TempodServerConfig::default(),
        engine,
        socket_path,
        url_policy,
        IdentityStrategyTable::default(),
    )
}

pub fn run_tempod_with_attached_driver_config_and_navigation_url_policy(
    addr: &str,
    config: TempodServerConfig,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    run_tempod_with_attached_driver_config_and_navigation_url_policy_and_identity_strategy(
        addr,
        config,
        engine,
        socket_path,
        url_policy,
        IdentityStrategyTable::default(),
    )
}

pub fn run_tempod_with_attached_driver_config_and_navigation_url_policy_and_identity_strategy(
    addr: &str,
    config: TempodServerConfig,
    engine: Engine,
    socket_path: impl AsRef<Path>,
    url_policy: UrlPolicy,
    identity_strategy_table: IdentityStrategyTable,
) -> Result<(), TempodError> {
    let config = config.with_bind_addr_host(addr);
    config.validate_bind_addr(addr)?;
    let listener = TcpListener::bind(addr)?;
    let socket_path = socket_path.as_ref().to_path_buf();
    let mut pool = SessionPool::from_env()
        .with_navigation_url_policy(url_policy)
        .with_identity_strategy_table(identity_strategy_table);
    pool.attach_engine_driver(engine, connect_engine_ipc(&socket_path)?)?;
    let pool = Arc::new(Mutex::new(pool));
    spawn_signed_threat_domain_refresh_supervisor_from_env(Arc::clone(&pool));
    spawn_engine_liveness_monitor(
        Arc::clone(&pool),
        engine,
        socket_path,
        EngineReconnectPolicy::default(),
    );
    serve_forever_with_config(listener, pool, config)
}

pub fn run_tempod_with_spawned_engine_config_and_navigation_url_policy(
    addr: &str,
    config: TempodServerConfig,
    engine: Engine,
    engine_program: impl Into<PathBuf>,
    engine_args: impl IntoIterator<Item = String>,
    socket_path: Option<PathBuf>,
    url_policy: UrlPolicy,
) -> Result<(), TempodError> {
    let config = config.with_bind_addr_host(addr);
    config.validate_bind_addr(addr)?;
    let listener = TcpListener::bind(addr)?;
    let socket_path = match socket_path {
        Some(socket_path) => socket_path,
        None => create_private_engine_control_socket_path()?,
    };
    let mut host_config = EngineHostConfig::new(engine_program)
        .restart(RestartPolicy::Always {
            max_restarts: u32::MAX,
        })
        .control_socket(socket_path.clone());
    for arg in engine_args {
        host_config = host_config.arg(arg);
    }
    let (engine_host, engine_server) = EngineHost::spawn_with_ipc(host_config)?;
    let engine_connection = engine_server.accept_timeout(Duration::from_secs(30))?;
    let mut pool = SessionPool::from_env().with_navigation_url_policy(url_policy);
    pool.attach_engine_driver(
        engine,
        attach_engine_client_from_stream(engine_connection.into_inner())?,
    )?;
    let pool = Arc::new(Mutex::new(pool));
    spawn_signed_threat_domain_refresh_supervisor_from_env(Arc::clone(&pool));
    spawn_spawned_engine_liveness_monitor(
        Arc::clone(&pool),
        engine,
        engine_host,
        engine_server,
        EngineReconnectPolicy::default(),
    );
    serve_forever_with_config(listener, pool, config)
}

fn attach_engine_client_from_stream(
    stream: std::os::unix::net::UnixStream,
) -> Result<EngineIpcClient, TempodError> {
    stream.set_write_timeout(Some(ENGINE_IPC_TIMEOUT))?;
    Ok(EngineIpcClient::from_stream(stream))
}

fn spawn_spawned_engine_liveness_monitor(
    pool: Arc<Mutex<SessionPool>>,
    engine: Engine,
    engine_host: EngineHost,
    engine_server: tempo_engine_host::EngineIpcServer,
    policy: EngineReconnectPolicy,
) {
    thread::spawn(move || {
        run_spawned_engine_liveness_monitor(&pool, engine, engine_host, engine_server, policy)
    });
}

fn run_spawned_engine_liveness_monitor(
    pool: &Arc<Mutex<SessionPool>>,
    engine: Engine,
    mut engine_host: EngineHost,
    engine_server: tempo_engine_host::EngineIpcServer,
    policy: EngineReconnectPolicy,
) {
    let mut controller = ReconnectController::new(policy.clone(), Instant::now());
    loop {
        thread::sleep(policy.poll_interval);
        if Arc::strong_count(pool) <= 1 {
            return;
        }
        let dead = match pool.lock() {
            Ok(guard) => guard.engine_driver_dead(),
            Err(_) => return,
        };
        match controller.on_sample(dead, Instant::now()) {
            ReconnectAction::Idle => {}
            ReconnectAction::GiveUp => {
                log_tempod_warn(
                    "spawned engine reconnect budget exhausted; leaving engine detached",
                )
                .field("issue", "#398")
                .field("attempts", controller.attempts.to_string())
                .emit();
                if let Ok(mut guard) = pool.lock() {
                    guard.detach_engine_driver();
                }
                if let Err(error) = engine_host.kill() {
                    log_tempod_error(
                        "failed to kill spawned engine after reconnect give-up",
                        error,
                    );
                }
                return;
            }
            ReconnectAction::Reconnect { backoff } => {
                let delay = jittered_backoff(backoff, policy.max_backoff, current_time_ns());
                thread::sleep(delay);
                match reconnect_spawned_engine(pool, engine, &mut engine_host, &engine_server) {
                    Ok(()) => {
                        controller.record_reconnect(Instant::now());
                        tempo_telemetry::logger()
                            .event(
                                tempo_telemetry::Level::Info,
                                "tempod",
                                "restarted spawned engine after disconnect",
                            )
                            .field("issue", "#398")
                            .field("attempts", controller.attempts.to_string())
                            .field("pid", engine_host.pid().to_string())
                            .emit();
                    }
                    Err(error) => {
                        controller.record_failure();
                        log_tempod_error("spawned engine reconnect attempt failed", error);
                    }
                }
            }
        }
    }
}

fn reconnect_spawned_engine(
    pool: &Arc<Mutex<SessionPool>>,
    engine: Engine,
    engine_host: &mut EngineHost,
    engine_server: &tempo_engine_host::EngineIpcServer,
) -> Result<(), TempodError> {
    if engine_host.try_wait()?.is_none() {
        engine_host.kill()?;
    }
    engine_host.restart_if_exited()?;
    let connection = engine_server.accept_timeout(Duration::from_secs(30))?;
    lock_pool(pool)?.attach_engine_driver(
        engine,
        attach_engine_client_from_stream(connection.into_inner())?,
    )
}

fn create_private_engine_control_socket_path() -> Result<PathBuf, TempodError> {
    let root = std::env::temp_dir().join(format!(
        "tempo-engine-{}-{}",
        std::process::id(),
        current_time_ms()
    ));
    fs::create_dir(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    Ok(root.join("engine.sock"))
}

/// Connect to the engine host UDS with a bounded write timeout. Read bounding
/// is per-request: the multiplexed client (`SharedEngineIpcClient`) awaits each
/// response with its own `ENGINE_IPC_TIMEOUT` and clears the socket read
/// timeout so its idle reader thread never mis-times a frame (issue #230).
fn connect_engine_ipc(socket_path: impl AsRef<Path>) -> Result<EngineIpcClient, TempodError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    attach_engine_client_from_stream(stream)
}

/// Reconnect behaviour for the engine-liveness monitor (#398).
///
/// tempod attaches to an engine over a UDS socket and, before this fix, never
/// re-attached: when the engine child died the multiplexed IPC client marked
/// itself dead and every request failed fast with `IpcClosed` forever, while the
/// dead driver stayed in `pool.driver` (the teardown circuit breaker only fires
/// on `None`/timeout, never on a prompt `Err`). The node zombified.
///
/// The monitor polls driver liveness and, on death, reconnects to the same
/// socket and re-attaches with exponential backoff + jitter. `max_attempts`
/// bounds churn so an engine that crashes on startup cannot hot-spin; a
/// reconnected engine that stays live for `stable_window` resets the counter so
/// a long-running node is never permanently capped by old, forgiven flaps.
#[derive(Clone, Debug)]
pub struct EngineReconnectPolicy {
    /// How often the monitor samples driver liveness.
    pub poll_interval: Duration,
    /// Backoff before the first reconnect attempt of an episode.
    pub base_backoff: Duration,
    /// Upper bound on any single backoff (before jitter).
    pub max_backoff: Duration,
    /// Maximum reconnect attempts (failed reconnects + unstable restarts) before
    /// giving up and leaving the engine detached (readiness then reports
    /// `engine_detached` so an orchestrator sheds the node). `None` retries
    /// forever with capped backoff.
    pub max_attempts: Option<u32>,
    /// Continuous liveness after a reconnect that resets the attempt counter.
    pub stable_window: Duration,
}

impl Default for EngineReconnectPolicy {
    fn default() -> Self {
        // Bounded-restart is the production default (not "never re-attach").
        Self {
            poll_interval: Duration::from_millis(500),
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(30),
            max_attempts: Some(10),
            stable_window: Duration::from_secs(60),
        }
    }
}

/// Deterministic exponential backoff for the `attempts`-th reconnect: `base <<
/// attempts`, saturated and capped at `max_backoff`. The shift is clamped so a
/// large attempt count cannot overflow the multiply.
fn engine_reconnect_backoff(policy: &EngineReconnectPolicy, attempts: u32) -> Duration {
    let shift = attempts.min(16);
    policy
        .base_backoff
        .saturating_mul(1_u32 << shift)
        .min(policy.max_backoff)
}

/// Add up to (but not including) half the backoff as jitter, capped at
/// `max_backoff`, so many nodes reconnecting to the same restarted engine do not
/// thunder in lockstep. Seeded from wall-clock nanos — the crate carries no RNG
/// dependency and reconnect timing has no determinism contract, so this reuses
/// the existing `current_time_ns` source rather than adding one (#398).
fn jittered_backoff(backoff: Duration, max_backoff: Duration, seed: u128) -> Duration {
    let span = backoff.as_nanos() / 2;
    if span == 0 {
        return backoff;
    }
    let extra = (seed % span) as u64;
    backoff
        .saturating_add(Duration::from_nanos(extra))
        .min(max_backoff)
}

/// What the liveness monitor should do on one sample of driver state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconnectAction {
    /// Driver is live; nothing to do.
    Idle,
    /// Driver is dead; attempt a reconnect after `backoff` (jitter applied by
    /// the caller so this stays a pure, testable decision).
    Reconnect { backoff: Duration },
    /// The attempt budget is exhausted; detach and stop reconnecting.
    GiveUp,
}

/// Pure decision core of the liveness monitor, split out so backoff growth,
/// the give-up bound, and the stable-uptime reset are unit-testable without
/// sockets or sleeps.
struct ReconnectController {
    policy: EngineReconnectPolicy,
    /// Reconnect attempts since the last stable window: failed reconnects and
    /// successful-but-unstable restarts both count, so a crash loop is bounded.
    attempts: u32,
    /// When the currently-attached driver was last (re)attached, used to detect
    /// a stable window has elapsed.
    stable_since: Instant,
}

impl ReconnectController {
    fn new(policy: EngineReconnectPolicy, now: Instant) -> Self {
        Self {
            policy,
            attempts: 0,
            stable_since: now,
        }
    }

    /// Decide the action for one liveness sample.
    fn on_sample(&mut self, driver_dead: bool, now: Instant) -> ReconnectAction {
        if !driver_dead {
            if self.attempts > 0
                && now.saturating_duration_since(self.stable_since) >= self.policy.stable_window
            {
                // The engine has been live for a full stable window: forgive
                // prior churn so old flaps never permanently cap a healthy node.
                self.attempts = 0;
                self.stable_since = now;
            }
            return ReconnectAction::Idle;
        }
        if self
            .policy
            .max_attempts
            .is_some_and(|max| self.attempts >= max)
        {
            return ReconnectAction::GiveUp;
        }
        ReconnectAction::Reconnect {
            backoff: engine_reconnect_backoff(&self.policy, self.attempts),
        }
    }

    /// Record a successful reconnect: count it toward the churn budget (so a
    /// hot crash loop is bounded) and restart the stable-uptime clock.
    fn record_reconnect(&mut self, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        self.stable_since = now;
    }

    /// Record a failed reconnect attempt; the next sample backs off further.
    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
}

/// Spawn the background engine-liveness monitor for the socket-attached serve
/// path (#398). It runs for the life of the daemon on its own thread; the serve
/// loop owns the main thread, so this is a detached daemon that dies with the
/// process.
fn spawn_engine_liveness_monitor(
    pool: Arc<Mutex<SessionPool>>,
    engine: Engine,
    socket_path: PathBuf,
    policy: EngineReconnectPolicy,
) {
    thread::spawn(move || run_engine_liveness_monitor(&pool, engine, &socket_path, policy));
}

/// The monitor loop: sample liveness every `poll_interval`, and on a dead driver
/// reconnect + re-attach with backoff. Returns when the attempt budget is
/// exhausted (driver left detached, readiness reports it) or the pool `Arc` is
/// the last reference (daemon shutting down).
fn run_engine_liveness_monitor(
    pool: &Arc<Mutex<SessionPool>>,
    engine: Engine,
    socket_path: &Path,
    policy: EngineReconnectPolicy,
) {
    let mut controller = ReconnectController::new(policy.clone(), Instant::now());
    loop {
        thread::sleep(policy.poll_interval);
        // If the daemon has dropped its pool handle, only ours remains: stop.
        if Arc::strong_count(pool) <= 1 {
            return;
        }
        let dead = match pool.lock() {
            Ok(guard) => guard.engine_driver_dead(),
            Err(_) => return,
        };
        match controller.on_sample(dead, Instant::now()) {
            ReconnectAction::Idle => {}
            ReconnectAction::GiveUp => {
                log_tempod_warn("engine reconnect budget exhausted; leaving engine detached")
                    .field("issue", "#398")
                    .field("attempts", controller.attempts.to_string())
                    .emit();
                if let Ok(mut guard) = pool.lock() {
                    guard.detach_engine_driver();
                }
                return;
            }
            ReconnectAction::Reconnect { backoff } => {
                let delay = jittered_backoff(backoff, policy.max_backoff, current_time_ns());
                thread::sleep(delay);
                match reconnect_engine(pool, engine, socket_path) {
                    Ok(()) => {
                        controller.record_reconnect(Instant::now());
                        tempo_telemetry::logger()
                            .event(
                                tempo_telemetry::Level::Info,
                                "tempod",
                                "reconnected to engine after disconnect",
                            )
                            .field("issue", "#398")
                            .field("attempts", controller.attempts.to_string())
                            .emit();
                    }
                    Err(error) => {
                        controller.record_failure();
                        log_tempod_error("engine reconnect attempt failed", error);
                    }
                }
            }
        }
    }
}

/// Connect a fresh IPC client and re-attach it as the pool's root driver. The
/// re-attach swaps in a live driver: `attach_engine_driver` first tears down the
/// stale (dead) driver and its forks, then installs the new client, so in-flight
/// sessions holding a clone of the old dead driver still fast-fail while new
/// operations resolve `pool.driver` to the live client.
fn reconnect_engine(
    pool: &Arc<Mutex<SessionPool>>,
    engine: Engine,
    socket_path: &Path,
) -> Result<(), TempodError> {
    let client = connect_engine_ipc(socket_path)?;
    lock_pool(pool)?.attach_engine_driver(engine, client)
}

/// Connection caps from issue #295, mapped onto tokio semaphores: `try_acquire`
/// (never `acquire`) keeps the observable behavior — an over-cap connection is
/// rejected immediately, never queued. tower's `ConcurrencyLimit` is
/// deliberately not used here because it queues callers instead of shedding
/// them.
#[derive(Clone)]
struct ConnectionLimiter {
    http: Arc<Semaphore>,
    websocket: Arc<Semaphore>,
    #[cfg(test)]
    max_http: usize,
    max_websocket: usize,
}

type ConnectionPermit = OwnedSemaphorePermit;

/// Per-connection slot holding the HTTP connection permit. A successful BiDi
/// WebSocket upgrade takes the HTTP permit out and holds a WebSocket permit
/// instead (issue #295's permit swap), so upgraded sockets count only against
/// the WebSocket cap.
type HttpPermitSlot = Arc<Mutex<Option<ConnectionPermit>>>;

impl Default for ConnectionLimiter {
    fn default() -> Self {
        Self::new(MAX_HTTP_CONNECTIONS, MAX_WEBSOCKET_CONNECTIONS)
    }
}

impl ConnectionLimiter {
    fn new(max_http: usize, max_websocket: usize) -> Self {
        Self {
            http: Arc::new(Semaphore::new(max_http)),
            websocket: Arc::new(Semaphore::new(max_websocket)),
            #[cfg(test)]
            max_http,
            max_websocket,
        }
    }

    fn try_acquire_http(&self) -> Option<ConnectionPermit> {
        Arc::clone(&self.http).try_acquire_owned().ok()
    }

    fn try_acquire_websocket(&self) -> Option<ConnectionPermit> {
        Arc::clone(&self.websocket).try_acquire_owned().ok()
    }

    fn active_websockets(&self) -> usize {
        self.max_websocket
            .saturating_sub(self.websocket.available_permits())
    }

    #[cfg(test)]
    fn active_counts(&self) -> (usize, usize) {
        (
            self.max_http.saturating_sub(self.http.available_permits()),
            self.active_websockets(),
        )
    }
}

/// Serve requests until the listener fails or the process is stopped.
///
/// The accept loop enforces the issue #295 HTTP connection cap at accept time
/// (an over-cap connection is dropped immediately, never queued) and hands each
/// accepted connection to hyper on its own tokio task, so a slow, stalled, or
/// failing client stays isolated to that connection and transient `accept`
/// errors are logged without killing the daemon.
pub fn serve_forever(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
    serve_forever_with_config(listener, pool, runtime_auth_server_config()?)
}

/// Serve requests without authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn serve_forever_unsafe(
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
    let host_guard = TempodHostGuard::from_listener(&listener, &config.allowed_hosts)?;
    let web_bot_auth_verifiers = config.web_bot_auth_verifiers.clone();
    serve_forever_trusted(
        listener,
        pool,
        config.auth,
        host_guard,
        ConnectionLimiter::default(),
        web_bot_auth_verifiers,
    )
}

#[cfg(test)]
fn serve_forever_with_limits(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    limiter: ConnectionLimiter,
) -> Result<(), TempodError> {
    let host_guard = TempodHostGuard::from_listener(&listener, &BTreeSet::new())?;
    serve_forever_trusted(
        listener,
        pool,
        TempodAuth::disabled(),
        host_guard,
        limiter,
        Vec::new(),
    )
}

fn serve_forever_trusted(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
    host_guard: TempodHostGuard,
    limiter: ConnectionLimiter,
    web_bot_auth_verifiers: Vec<WebBotAuthVerifier>,
) -> Result<(), TempodError> {
    let _ = process_start();
    let runtime = transport_runtime()?;
    runtime.block_on(async move {
        let listener = tokio_listener(listener)?;
        let router = tempod_router(TempodAppState {
            pool,
            auth,
            host_guard,
            limiter: limiter.clone(),
            web_bot_auth_verifiers,
        });
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    // Over-cap connections are shed at accept time (issue
                    // #295): dropped immediately instead of queueing.
                    let Some(permit) = limiter.try_acquire_http() else {
                        drop(stream);
                        continue;
                    };
                    tokio::spawn(serve_tcp_connection(stream, router.clone(), permit));
                }
                Err(err) => {
                    // A transient accept error (e.g. EMFILE) must not kill the daemon.
                    log_connection_error(&TempodError::Io(err));
                }
            }
        }
    })
}

/// Serve exactly one connection. Tests use this against a real TCP listener;
/// every non-upgrade response carries `connection: close`, so this serves one
/// HTTP exchange (or one whole BiDi WebSocket session).
pub fn serve_one(listener: TcpListener, pool: Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    serve_one_with_config(listener, pool, runtime_auth_server_config()?)
}

/// Serve exactly one request without authentication checks.
///
/// This is intentionally unsafe and for test/fixture-only use.
pub fn serve_one_unsafe(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
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
    let host_guard = TempodHostGuard::from_listener(&listener, &config.allowed_hosts)?;
    let web_bot_auth_verifiers = config.web_bot_auth_verifiers.clone();
    serve_one_trusted(
        listener,
        pool,
        config.auth,
        host_guard,
        ConnectionLimiter::default(),
        web_bot_auth_verifiers,
    )
}

fn serve_one_trusted(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
    host_guard: TempodHostGuard,
    limiter: ConnectionLimiter,
    web_bot_auth_verifiers: Vec<WebBotAuthVerifier>,
) -> Result<(), TempodError> {
    let _ = process_start();
    let runtime = transport_runtime()?;
    runtime.block_on(async move {
        let listener = tokio_listener(listener)?;
        let (stream, _addr) = listener.accept().await?;
        let Some(permit) = limiter.try_acquire_http() else {
            drop(stream);
            return Err(TempodError::ConnectionLimit(
                HTTP_CONNECTION_LIMIT_MESSAGE.into(),
            ));
        };
        let router = tempod_router(TempodAppState {
            pool,
            auth,
            host_guard,
            limiter: limiter.clone(),
            web_bot_auth_verifiers,
        });
        serve_tcp_connection(stream, router, permit).await;
        // A BiDi upgrade hands the socket to a spawned WebSocket task and the
        // HTTP connection future completes at the 101; wait for the session
        // (visible as a held WebSocket permit on this call's limiter) so the
        // runtime is not torn down underneath it.
        while limiter.active_websockets() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    })
}

/// Single-threaded tokio runtime for the transport. Handlers never block this
/// thread: all pool/engine work runs via `spawn_blocking`, which is what keeps
/// `/health` responsive while engine operations are in flight (issues
/// #200/#213/#230).
fn transport_runtime() -> Result<tokio::runtime::Runtime, TempodError> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn tokio_listener(listener: TcpListener) -> Result<tokio::net::TcpListener, TempodError> {
    listener.set_nonblocking(true)?;
    Ok(tokio::net::TcpListener::from_std(listener)?)
}

/// Serve one accepted TCP connection with hyper/axum.
///
/// * `TCP_NODELAY`, because this is a request/response control plane.
/// * `header_read_timeout` bounds slowloris-style stalls (`SOCKET_TIMEOUT`).
/// * `half_close(true)` keeps clients working that shut down their write side
///   after sending the request.
/// * `max_buf_size` caps hyper's read buffering at the pre-existing
///   `MAX_HTTP_BYTES` transport bound.
/// * The connection's HTTP permit rides in an [`HttpPermitSlot`] request
///   extension so a BiDi WebSocket upgrade can swap it for a WebSocket permit
///   (issue #295).
async fn serve_tcp_connection(
    stream: tokio::net::TcpStream,
    router: Router,
    permit: ConnectionPermit,
) {
    if let Err(err) = stream.set_nodelay(true) {
        log_connection_error(&TempodError::Io(err));
        return;
    }
    let slot: HttpPermitSlot = Arc::new(Mutex::new(Some(permit)));
    let service = TowerToHyperService::new(router.layer(Extension(Arc::clone(&slot))));
    let connection = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(SOCKET_TIMEOUT)
        .half_close(true)
        .max_buf_size(MAX_HTTP_BYTES)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    if let Err(err) = connection.await {
        // Per-connection protocol/I-O errors stay isolated to this connection.
        tempo_telemetry::logger()
            .event(tempo_telemetry::Level::Error, "tempod", "connection error")
            .field("error", err.to_string())
            .emit();
    }
}

fn log_connection_error(err: &TempodError) {
    log_tempod_error("connection error", err);
}

fn log_tempod_error(message: &'static str, error: impl fmt::Display) {
    tempo_telemetry::logger()
        .event(tempo_telemetry::Level::Error, "tempod", message)
        .field("error", error.to_string())
        .emit();
}

fn log_tempod_warn(message: &'static str) -> tempo_telemetry::EventBuilder<'static> {
    tempo_telemetry::logger().event(tempo_telemetry::Level::Warn, "tempod", message)
}

/// Shared state behind every route.
#[derive(Clone)]
struct TempodAppState {
    pool: Arc<Mutex<SessionPool>>,
    auth: TempodAuth,
    host_guard: TempodHostGuard,
    limiter: ConnectionLimiter,
    web_bot_auth_verifiers: Vec<WebBotAuthVerifier>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TempodHostGuard {
    allowed_hosts: BTreeSet<String>,
    allow_any_valid_host: bool,
    is_loopback_listener: bool,
}

impl TempodHostGuard {
    fn from_listener(
        listener: &TcpListener,
        configured_hosts: &BTreeSet<String>,
    ) -> Result<Self, TempodError> {
        let mut allowed_hosts = configured_hosts.clone();
        let addr = listener.local_addr()?;
        allowed_hosts.insert(canonical_ip_host(addr.ip()));
        let is_loopback_listener = addr.ip().is_loopback();
        if is_loopback_listener {
            allowed_hosts.insert("localhost".to_string());
            allowed_hosts.insert("127.0.0.1".to_string());
            allowed_hosts.insert("[::1]".to_string());
        }
        Ok(Self {
            allowed_hosts,
            allow_any_valid_host: addr.ip().is_unspecified(),
            is_loopback_listener,
        })
    }

    #[cfg(test)]
    fn loopback() -> Self {
        Self {
            allowed_hosts: BTreeSet::from([
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "[::1]".to_string(),
            ]),
            allow_any_valid_host: false,
            is_loopback_listener: true,
        }
    }

    fn is_loopback_listener(&self) -> bool {
        self.is_loopback_listener
    }

    fn allows(&self, host: Option<&str>) -> bool {
        let Some(host) = host.and_then(normalized_host_header_name) else {
            return false;
        };
        self.allow_any_valid_host || self.allowed_hosts.contains(&host)
    }
}

/// The tempod control-plane router (final.md §3.1): session lifecycle REST,
/// MCP, and the BiDi WebSocket on one axum HTTP server.
///
/// Locking discipline (issue #230) is unchanged below the transport: metadata
/// routes take the pool lock only for in-memory work, engine-op routes clone a
/// per-session handle and run engine round-trips OFF the lock, and `/health`
/// touches no state at all. Every pool-touching handler runs on
/// `spawn_blocking`, so the transport thread (and `/health`) never queues
/// behind an in-flight browser operation.
fn tempod_router(state: TempodAppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route(TEMPOD_OPENAPI_PATH, get(openapi))
        .route(
            WEB_BOT_AUTH_KEY_DIRECTORY_PATH,
            get(web_bot_auth_key_directory),
        )
        .route(tempo_mcp::A2A_AGENT_CARD_PATH, get(agent_card))
        .route(tempo_mcp::A2A_AGENT_JSON_PATH, get(agent_card))
        .route("/mcp", get(mcp_get).post(mcp_post))
        .route("/bidi", get(bidi_websocket_upgrade).post(bidi_post))
        .route("/sessions", get(sessions_list).post(sessions_create))
        .route("/sessions/{id}", delete(session_kill))
        .route("/sessions/{id}/adopt", post(session_adopt))
        .route("/sessions/{id}/resume", post(session_resume))
        .route("/sessions/{id}/observe", get(session_observe))
        .route("/sessions/{id}/act_batch", post(session_act_batch))
        .route("/sessions/{id}/events", get(session_events))
        .route("/drain", post(drain))
        .route(TEMPOD_METRICS_PATH, get(metrics))
        .fallback(unsupported_route)
        .layer(DefaultBodyLimit::max(MAX_HTTP_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard_control_plane,
        ))
        .layer(middleware::from_fn(instrument_requests))
        .layer(middleware::from_fn(close_connections))
        .with_state(state)
}

/// Per-route bearer-auth + loopback Host/Origin guard, evaluated before any
/// handler or body read. Route classification is unchanged from the
/// socket-level server: [`route_requires_auth`] /
/// [`control_route_requires_origin_check`].
///
/// DNS-rebinding defence (issue #83 follow-up): the session/control-plane
/// routes mutate or expose browser state, so they require both an expected
/// Host and the same loopback-Origin guard already applied to /mcp and /bidi.
/// The Origin side still accepts missing Origin for non-browser/CLI clients,
/// but those requests must now carry an expected Host.
async fn guard_control_plane(
    State(state): State<TempodAppState>,
    request: AxumRequest,
    next: Next,
) -> Response {
    let method = request.method().as_str();
    let path = request.uri().path();
    let is_loopback_listener = state.host_guard.is_loopback_listener();
    let auth_protected_metadata =
        state.auth.is_required() && is_protected_metadata_route(method, path);
    if (route_requires_host_check(method, path, is_loopback_listener) || auth_protected_metadata)
        && !state
            .host_guard
            .allows(header_str(request.headers(), header::HOST))
    {
        return tempod_error_response(&TempodError::Forbidden("host not allowed".into()))
            .into_response();
    }
    if route_requires_auth(method, path, is_loopback_listener)
        && let Err(err) = state
            .auth
            .authorize(header_str(request.headers(), header::AUTHORIZATION))
    {
        return tempod_error_response(&err).into_response();
    }
    if method == "GET"
        && path == TEMPOD_METRICS_PATH
        && !loopback_host_header_allowed(request.headers())
    {
        return tempod_error_response(&TempodError::Forbidden("host not allowed".into()))
            .into_response();
    }
    if control_route_requires_origin_check(method, path)
        && !tempo_mcp::origin_allowed(header_str(request.headers(), header::ORIGIN))
    {
        return tempod_error_response(&TempodError::Forbidden("origin not allowed".into()))
            .into_response();
    }
    next.run(request).await
}

fn tempod_error_response(err: &TempodError) -> HttpResponse {
    HttpResponse::json(err.status(), err.body())
}

/// Close every non-upgrade connection after one exchange. This preserves the
/// previous server's wire behavior (every response carried
/// `connection: close`), so existing clients that read to EOF keep working.
async fn close_connections(request: AxumRequest, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Request counter + latency histogram at the HTTP funnel (from #324), with
/// bounded route-class labels. Auth/origin rejections are counted with their
/// route class, matching the previous funnel placement; BiDi WebSocket
/// upgrade attempts are excluded, as before, because an upgraded connection
/// is not a request/response exchange.
async fn instrument_requests(request: AxumRequest, next: Next) -> Response {
    let method = request.method().as_str();
    let path = request.uri().path();
    if method == "GET"
        && path == "/bidi"
        && (request.headers().contains_key(header::UPGRADE)
            || request.headers().contains_key(header::SEC_WEBSOCKET_KEY))
    {
        return next.run(request).await;
    }
    let route = metrics_route_class(method, path);
    let timer = tempo_telemetry::global()
        .histogram(
            "tempod_http_request_seconds",
            "Latency of HTTP requests that reached the route handler",
            &[("route", route)],
            None,
        )
        .start_timer();
    let response = next.run(request).await;
    drop(timer);
    tempo_telemetry::global()
        .counter(
            "tempod_http_requests_total",
            "HTTP requests that reached the route handler, by route and status class \
             (connection-limit rejections and WebSocket upgrades are not counted)",
            &[
                ("route", route),
                ("status", status_class(response.status().as_u16())),
            ],
        )
        .inc();
    response
}

/// Route label with bounded cardinality: per-session paths collapse into one
/// `session` class so session ids can never grow the metric space.
fn metrics_route_class(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("GET", "/health") => "health",
        ("GET", "/ready") => "ready",
        ("GET", TEMPOD_METRICS_PATH) => "metrics",
        (_, "/mcp") => "mcp",
        (_, "/bidi") => "bidi",
        (_, "/sessions") => "sessions",
        (_, "/drain") => "drain",
        _ if path.starts_with("/sessions/") => "session",
        ("GET", path)
            if path == tempo_mcp::A2A_AGENT_CARD_PATH || path == tempo_mcp::A2A_AGENT_JSON_PATH =>
        {
            "agent_card"
        }
        _ => "other",
    }
}

fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

static METRICS_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Enable/disable `GET /metrics` (wired from `tempo-config`'s
/// `telemetry.metrics_enabled`). Disabled means 404, not an absent route, so
/// operators can tell "off by config" from "wrong tempod version".
pub fn set_metrics_enabled(enabled: bool) {
    METRICS_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

fn metrics_enabled() -> bool {
    METRICS_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

static PROCESS_START: OnceLock<std::time::Instant> = OnceLock::new();

/// Anchor for the uptime gauge. The serve entry points call this at startup;
/// if only a scrape ever calls it, uptime under-reports rather than lying.
fn process_start() -> std::time::Instant {
    *PROCESS_START.get_or_init(std::time::Instant::now)
}

/// GET /metrics — Prometheus text exposition (from #324). Deliberately behind
/// the loopback-Origin guard and a loopback Host guard (plus bearer auth on
/// remote binds): exposition is control-plane data. Scrapers send no Origin
/// header, so they pass the Origin guard, but browser DNS-rebinding requests
/// still carry an attacker Host and are denied before the scrape.
async fn metrics(State(state): State<TempodAppState>) -> Response {
    if !metrics_enabled() {
        return HttpResponse::json(
            404,
            json!({"error": "metrics exposition disabled by configuration"}),
        )
        .into_response();
    }
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        let pool = lock_pool(&state.pool)?;
        Ok(metrics_response(&pool))
    })
    .await
}

/// Prometheus text exposition. Point-in-time gauges (uptime, build info,
/// active sessions, draining) are refreshed at scrape time; counters and
/// histograms accumulate at their call sites.
fn metrics_response(pool: &SessionPool) -> HttpResponse {
    let registry = tempo_telemetry::global();
    registry
        .gauge("tempod_uptime_seconds", "Seconds since daemon start", &[])
        .set(process_start().elapsed().as_secs_f64());
    registry
        .gauge(
            "tempod_build_info",
            "Constant 1, labeled with the tempod version",
            &[("version", env!("CARGO_PKG_VERSION"))],
        )
        .set(1.0);
    registry
        .gauge(
            "tempod_sessions_active",
            "Sessions currently attached to the pool",
            &[],
        )
        .set(pool.active_session_count() as f64);
    registry
        .gauge(
            "tempod_draining",
            "1 while the daemon is draining, else 0",
            &[],
        )
        .set(if pool.draining() { 1.0 } else { 0.0 });
    HttpResponse::new(
        200,
        tempo_telemetry::PROMETHEUS_CONTENT_TYPE,
        registry.render_prometheus().into_bytes(),
    )
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn loopback_host_header_allowed(headers: &HeaderMap) -> bool {
    match header_str(headers, header::HOST) {
        Some(host) => loopback_host_allowed(Some(host)),
        None => true,
    }
}

fn base_url_from_headers(headers: &HeaderMap) -> String {
    let host = header_str(headers, header::HOST)
        .filter(|host| loopback_host_allowed(Some(host)))
        .unwrap_or("localhost");
    format!("http://{host}")
}

/// Run a blocking route body on the tokio blocking pool so no handler ever
/// blocks the transport thread.
async fn run_blocking<T, F>(work: F) -> Response
where
    T: IntoResponse + Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(response) => response.into_response(),
        Err(_) => {
            HttpResponse::json(500, json!({"error": "tempod worker task failed"})).into_response()
        }
    }
}

/// GET /health never touches the pool or the blocking pool: it must answer
/// even while every route worker is busy with engine or lock work.
async fn health() -> HttpResponse {
    HttpResponse::json(200, json!({"ok": true}))
}

async fn ready(State(state): State<TempodAppState>) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        let pool = lock_pool(&state.pool)?;
        Ok(readiness_response(&pool))
    })
    .await
}

fn readiness_response(pool: &SessionPool) -> HttpResponse {
    let mut reasons = Vec::new();
    if pool.draining() {
        reasons.push("draining");
    }
    if !pool.engine_attached() {
        reasons.push("engine_detached");
    } else if !pool.engine_live() {
        // Attached but the IPC connection is dead (engine child exited): the node
        // cannot service engine-backed work until the liveness monitor reconnects
        // (#398). Surface it so an orchestrator's readiness probe sheds this node.
        reasons.push("engine_dead");
    }
    if pool.session_limit_reached() {
        reasons.push("session_limit_reached");
    }
    let ready = reasons.is_empty();
    HttpResponse::json(
        if ready { 200 } else { 503 },
        json!({
            "ok": ready,
            "ready": ready,
            "draining": pool.draining(),
            "engine_attached": pool.engine_attached(),
            "engine_live": pool.engine_live(),
            "sessions": pool.active_session_count(),
            "max_sessions": pool.max_sessions,
            "reasons": reasons,
        }),
    )
}

async fn openapi(headers: HeaderMap) -> HttpResponse {
    HttpResponse::new(
        200,
        TEMPOD_OPENAPI_CONTENT_TYPE,
        tempod_openapi(&base_url_from_headers(&headers))
            .to_string()
            .into_bytes(),
    )
}

async fn agent_card(headers: HeaderMap) -> HttpResponse {
    HttpResponse::from_mcp(tempo_mcp::agent_card_response(&base_url_from_headers(
        &headers,
    )))
}

async fn web_bot_auth_key_directory(State(state): State<TempodAppState>) -> HttpResponse {
    HttpResponse::new(
        200,
        WEB_BOT_AUTH_KEY_DIRECTORY_CONTENT_TYPE,
        web_bot_auth_key_directory_json(&state.web_bot_auth_verifiers).into_bytes(),
    )
}

async fn mcp_get() -> HttpResponse {
    HttpResponse::from_mcp(tempo_mcp::handle_get())
}

async fn mcp_post(
    State(state): State<TempodAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let origin = header_str(&headers, header::ORIGIN).map(str::to_owned);
    run_blocking(move || route_mcp(&state.pool, origin.as_deref(), &body)).await
}

async fn bidi_post(
    State(state): State<TempodAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !tempo_mcp::origin_allowed(header_str(&headers, header::ORIGIN)) {
        return tempod_error_response(&TempodError::Forbidden("origin not allowed".into()))
            .into_response();
    }
    run_blocking(move || route_bidi(&state.pool, body.to_vec())).await
}

async fn sessions_list(State(state): State<TempodAppState>) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        Ok(HttpResponse::json(200, lock_pool(&state.pool)?.list()))
    })
    .await
}

async fn sessions_create(State(state): State<TempodAppState>, body: Bytes) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        // Malformed JSON is a client error (400) on this transport; the
        // hand-rolled parser surfaced it as a 500.
        let request: CreateSessionRequest = serde_json::from_slice(&body)
            .map_err(|err| TempodError::BadRequest(format!("invalid session request: {err}")))?;
        if request.url.trim().is_empty() {
            return Err(TempodError::BadRequest("session url is required".into()));
        }
        let created = create_session_shared(&state.pool, request.url)?;
        tempo_telemetry::global()
            .counter(
                "tempod_sessions_created_total",
                "Sessions created over the HTTP control plane",
                &[],
            )
            .inc();
        Ok(HttpResponse::json(201, created))
    })
    .await
}

async fn session_kill(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        Ok(HttpResponse::json(
            200,
            route_session_kill(&state.pool, &TempodSessionId(id))?,
        ))
    })
    .await
}

async fn session_adopt(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        Ok(HttpResponse::json(
            200,
            lock_pool(&state.pool)?.adopt(&TempodSessionId(id))?,
        ))
    })
    .await
}

async fn session_resume(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        Ok(HttpResponse::json(
            200,
            lock_pool(&state.pool)?.resume(&TempodSessionId(id))?,
        ))
    })
    .await
}

async fn session_events(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
    RawQuery(query): RawQuery,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        let after_seq = after_seq(query.as_deref())?;
        Ok(HttpResponse::json(
            200,
            lock_pool(&state.pool)?.events(&TempodSessionId(id), after_seq)?,
        ))
    })
    .await
}

async fn session_observe(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        Ok(HttpResponse::json(
            200,
            route_session_observe(&state.pool, &TempodSessionId(id))?,
        ))
    })
    .await
}

async fn session_act_batch(
    State(state): State<TempodAppState>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        let body = parse_session_act_batch_request(&body)?;
        route_session_act_batch(&state.pool, TempodSessionId(id), body)
    })
    .await
}

async fn drain(State(state): State<TempodAppState>) -> Response {
    run_blocking(move || -> Result<HttpResponse, TempodError> {
        let mut pool = lock_pool(&state.pool)?;
        pool.drain();
        Ok(HttpResponse::json(
            200,
            json!({
                "draining": pool.draining(),
                "sessions": pool.list(),
            }),
        ))
    })
    .await
}

/// Unmatched routes answer 404 (standard HTTP; the hand-rolled parser answered
/// 400 for them).
async fn unsupported_route(request: AxumRequest) -> HttpResponse {
    HttpResponse::json(
        404,
        json!({
            "error": format!(
                "unsupported route: {} {}",
                request.method(),
                request.uri().path()
            ),
        }),
    )
}

/// GET /bidi — BiDi WebSocket upgrade.
///
/// Guard order matches the previous server: bearer auth (middleware, 401) ->
/// upgrade-header validation (`WebSocketUpgrade` extractor, 400) ->
/// loopback-Origin guard (403, DNS-rebinding defence; browsers always send
/// Origin on WS upgrades, non-browser clients omit it and pass) -> WebSocket
/// connection cap (503). No subprotocol is negotiated, as before.
async fn bidi_websocket_upgrade(
    State(state): State<TempodAppState>,
    headers: HeaderMap,
    permit_slot: Option<Extension<HttpPermitSlot>>,
    ws: WebSocketUpgrade,
) -> Response {
    if !tempo_mcp::origin_allowed(header_str(&headers, header::ORIGIN)) {
        return tempod_error_response(&TempodError::Forbidden(
            "WebSocket origin not allowed".into(),
        ))
        .into_response();
    }
    let Some(websocket_permit) = state.limiter.try_acquire_websocket() else {
        return tempod_error_response(&TempodError::ConnectionLimit(
            WEBSOCKET_CONNECTION_LIMIT_MESSAGE.into(),
        ))
        .into_response();
    };
    let pool = Arc::clone(&state.pool);
    ws.max_message_size(MAX_WS_PAYLOAD_BYTES)
        .on_upgrade(move |socket| async move {
            // Permit swap (issue #295): the socket stops being an HTTP request
            // and becomes a WebSocket, releasing its HTTP connection permit.
            if let Some(Extension(slot)) = permit_slot
                && let Ok(mut slot) = slot.lock()
            {
                slot.take();
            }
            let _websocket_permit = websocket_permit;
            serve_bidi_websocket(socket, pool).await;
        })
}

/// Serve BiDi messages on an upgraded WebSocket. Commands are dispatched
/// without holding the pool lock across engine round-trips (issue #230); this
/// connection still processes its own messages strictly in order.
async fn serve_bidi_websocket(mut socket: WebSocket, pool: Arc<Mutex<SessionPool>>) {
    while let Some(Ok(message)) = socket.recv().await {
        let payload = match message {
            WsMessage::Text(text) => text.as_bytes().to_vec(),
            WsMessage::Binary(bytes) => bytes.to_vec(),
            // The websocket protocol layer answers pings and echoes the
            // close handshake itself while the stream keeps being polled;
            // after a close completes, `recv` returns `None` and the loop
            // ends.
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Close(_) => continue,
        };
        let dispatch_pool = Arc::clone(&pool);
        let Ok(messages) =
            tokio::task::spawn_blocking(move || route_bidi_websocket(&dispatch_pool, payload))
                .await
        else {
            return;
        };
        for message in messages {
            let Ok(payload) = bidi_message_payload(&message) else {
                return;
            };
            let Ok(text) = String::from_utf8(payload) else {
                return;
            };
            if socket.send(WsMessage::Text(text.into())).await.is_err() {
                return;
            }
        }
    }
}

/// Lock the pool for a SHORT, engine-IPC-free critical section. Routes must
/// never hold this guard across an engine round-trip (issue #230): engine work
/// happens on cloned per-session driver handles after the guard is dropped.
fn lock_pool(pool: &Arc<Mutex<SessionPool>>) -> Result<MutexGuard<'_, SessionPool>, TempodError> {
    // Poisoning is recovered (`into_inner`) for the same reason the driver
    // `OpGate` recovers it (see [`OpGate::acquire`], #305): treating a one-off
    // panic as fatal would permanently wedge every later pool-touching route
    // behind `PoolLock` with no recovery (#413).
    Ok(pool
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
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
        pool.ensure_accepting_session()?;
        enforce_tempod_navigation_url(&pool.browser_hardening_policy, &url)?;
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
        abandon_created_session_driver(session_driver, "session context Close after drain race");
        return Err(TempodError::Draining);
    }
    if pool.session_limit_reached() {
        let max = pool.max_sessions;
        abandon_created_session_driver(
            session_driver,
            "session context Close after session-limit race",
        );
        return Err(TempodError::SessionLimit { max });
    }
    Ok(pool.finish_create(url, session_driver))
}

/// `DELETE /sessions/{id}` with the session's engine-context `Close` run OFF the
/// pool lock (#440, mirroring `create_session_shared` #230):
///
/// 1. lock — [`SessionPool::begin_kill`] flips the session to `Killed`, removes
///    its driver from the map (the session is instantly unreachable), records
///    the lifecycle event, and hands back the detached driver plus a root-driver
///    handle;
/// 2. unlock — bounded `Close` of the detached driver and, only if that times
///    out, a bounded liveness probe of the shared engine
///    ([`close_detached_session_driver`]). Every other session and route
///    proceeds meanwhile — a slow `Close` can no longer stall the pool mutex;
/// 3. lock (rare) — abandon the shared engine ONLY when the probe found it
///    genuinely unreachable (dead IPC or wedged child), never for a lone slow
///    `Close`, so racing a `DELETE` against another session's in-flight
///    navigation can no longer strand every surviving session.
fn route_session_kill(
    pool: &Arc<Mutex<SessionPool>>,
    id: &TempodSessionId,
) -> Result<TempodSession, TempodError> {
    let (session, detached, root) = lock_pool(pool)?.begin_kill(id)?;
    if let Some(driver) = detached
        && close_detached_session_driver(id.0.clone(), driver, root)
    {
        lock_pool(pool)?
            .abandon_attached_engine_after_teardown_timeout("session engine context Close");
    }
    Ok(session)
}

/// Bounded, off-lock `Close` of a killed session's detached engine context.
/// Returns `true` when the caller should abandon the shared engine — i.e. the
/// `Close` timed out AND a bounded liveness probe of the root driver found the
/// engine unreachable (dead IPC or wedged child). Returns `false` otherwise,
/// crucially including the case where the `Close` merely timed out but the
/// engine is still responsive (busy serving another session): a lone slow
/// `Close` must never abandon the shared engine and strand survivors (#440).
/// Close errors are logged and swallowed; session lifecycle state was already
/// recorded under the lock in [`SessionPool::begin_kill`].
fn close_detached_session_driver(
    session_id: String,
    mut driver: AttachedEngineDriver,
    root: Option<AttachedEngineDriver>,
) -> bool {
    match run_teardown_bounded(
        "session engine context Close",
        ENGINE_TEARDOWN_TIMEOUT,
        move || futures::executor::block_on(driver.close()),
    ) {
        Some(Ok(())) => false,
        Some(Err(error)) => {
            tempo_telemetry::logger()
                .event(
                    tempo_telemetry::Level::Error,
                    "tempod",
                    "error closing engine driver for session",
                )
                .field("session_id", session_id)
                .field("error", error.to_string())
                .emit();
            false
        }
        None => match root {
            // Distinguish "this driver is slow" from "the engine is wedged"
            // (#440): only abandon when the shared engine cannot answer a
            // lightweight probe. The detached worker still owns and finishes
            // the wedged `Close` once the engine responds or disconnects.
            Some(root) => !root.probe_responsive(ENGINE_TEARDOWN_TIMEOUT),
            None => false,
        },
    }
}

fn abandon_created_session_driver(
    session_driver: Option<AttachedEngineDriver>,
    operation: &'static str,
) {
    if let Some(mut driver) = session_driver
        && run_teardown_bounded(operation, ENGINE_TEARDOWN_TIMEOUT, move || {
            futures::executor::block_on(driver.close())
        })
        .is_none()
    {
        log_tempod_warn("session context created during rejected create was abandoned").emit();
    }
}

fn route_session_observe(
    pool: &Arc<Mutex<SessionPool>>,
    id: &TempodSessionId,
) -> Result<CompiledObservation, TempodError> {
    let mut driver = lock_pool(pool)?.session_driver(id)?;
    futures::executor::block_on(driver.observe())
        .map_err(|error| TempodError::Driver(error.to_string()))
}

/// Caller-supplied policy claims for a REST `act_batch`. Advisory only: the
/// trust seam merges them escalate-only against server evidence (#254/#342).
fn session_batch_caller_claims(body: &SessionActBatchRequest) -> CallerPolicyClaims {
    CallerPolicyClaims::new(body.input_tainted, body.confirmed)
}

/// Fetch the session's live observation when server-side taint recomputation
/// could change a gate outcome for any action in the batch (mirrors
/// [`gate_bidi_command`], #342). Returns `None` when no action needs page
/// evidence, so evidence-free denials never trigger an engine round-trip or
/// reserve the idempotency lease. Fails closed (no dispatch) if observe fails.
fn session_batch_policy_observation(
    pool: &Arc<Mutex<SessionPool>>,
    id: &TempodSessionId,
    body: &SessionActBatchRequest,
) -> Result<Option<CompiledObservation>, TempodError> {
    let claims = session_batch_caller_claims(body);
    let needs_evidence = body.batch.actions.iter().any(|action| {
        requires_observation_evidence(action.side_effect(), &action_caller_texts(action), claims)
    });
    if !needs_evidence {
        return Ok(None);
    }
    // Clone the driver handle under a brief lock, then observe with NO pool lock
    // held (engine round-trip, #230). observe carries the existing IPC timeout.
    let mut driver = lock_pool(pool)?.session_driver(id)?;
    let observation = futures::executor::block_on(driver.observe()).map_err(|error| {
        TempodError::Driver(format!(
            "policy taint recomputation requires an observation, but observe failed: {error}"
        ))
    })?;
    Ok(Some(observation))
}

fn route_session_act_batch(
    pool: &Arc<Mutex<SessionPool>>,
    id: TempodSessionId,
    body: SessionActBatchRequest,
) -> Result<HttpResponse, TempodError> {
    // Recompute taint from the session's live observation the same bounded way
    // the BiDi seam does (#342): fetch one observation only when page evidence
    // could change a gate outcome, and do it with NO pool lock held (engine
    // round-trip, #230). Evidence-free denials never observe or reserve the
    // idempotency lease.
    let observation = session_batch_policy_observation(pool, &id, &body)?;

    let (mut driver, request_fingerprint, idempotency_key, policy) = {
        let mut pool = lock_pool(pool)?;
        let policy = match enforce_session_batch_policy(
            &pool.browser_hardening_policy,
            pool.privacy_mode,
            &body,
            observation.as_ref(),
        ) {
            Ok(policy) => policy,
            Err(TempodError::BrowserHardeningBlocked(block)) => {
                let _ = pool.record_browser_hardening_block(&id, (*block).clone());
                return Err(TempodError::BrowserHardeningBlocked(block));
            }
            Err(error) => return Err(error),
        };
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
    spawn_post_action_identity_observation(pool.clone(), id.clone(), driver);
    Ok(HttpResponse::json(response.status, response.body))
}

fn spawn_post_action_identity_observation(
    pool: Arc<Mutex<SessionPool>>,
    id: TempodSessionId,
    mut driver: AttachedEngineDriver,
) {
    let Some(_slot) = try_acquire_post_action_identity_slot() else {
        log_tempod_warn("post-action identity observation skipped: worker limit reached")
            .field("session_id", id.0)
            .field("limit", MAX_POST_ACTION_IDENTITY_OBSERVERS)
            .emit();
        return;
    };
    thread::spawn(move || {
        let _slot = _slot;
        let post_action_observation = futures::executor::block_on(driver.observe())
            .map_err(|error| {
                log_tempod_warn(
                    "policy taint requires post-action observation, but observe failed",
                )
                .field("session_id", id.0.clone())
                .field("error", error.to_string())
                .emit();
            })
            .ok();
        if let Some(observation) = post_action_observation {
            let takeover = detect_human_takeover(&observation);
            match lock_pool(&pool) {
                Ok(mut pool) => pool.record_identity_strategy_outcome(&id, &observation, takeover),
                Err(error) => {
                    log_tempod_warn("failed to record post-action identity strategy")
                        .field("session_id", id.0.clone())
                        .field("error", error.to_string())
                        .emit();
                }
            }
        }
    });
}

struct PostActionIdentitySlot;

impl Drop for PostActionIdentitySlot {
    fn drop(&mut self) {
        POST_ACTION_IDENTITY_OBSERVERS.fetch_sub(1, Ordering::Relaxed);
    }
}

static POST_ACTION_IDENTITY_OBSERVERS: AtomicUsize = AtomicUsize::new(0);

fn try_acquire_post_action_identity_slot() -> Option<PostActionIdentitySlot> {
    let mut current = POST_ACTION_IDENTITY_OBSERVERS.load(Ordering::Relaxed);
    loop {
        if current >= MAX_POST_ACTION_IDENTITY_OBSERVERS {
            return None;
        }
        match POST_ACTION_IDENTITY_OBSERVERS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(PostActionIdentitySlot),
            Err(observed) => current = observed,
        }
    }
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
    policy: &BrowserHardeningPolicy,
    privacy_mode: PrivacyMode,
    body: &SessionActBatchRequest,
    observation: Option<&CompiledObservation>,
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
    // Route every action through the shared trust seam (#254/#342): taint is
    // recomputed from `observation` (page-provenance spans vs the action's
    // caller-controlled free text) and merged escalate-only with the caller's
    // advisory `input_tainted`/`confirmed`. The caller can only ADD taint,
    // never clear server-derived taint, and `confirmed:true` never satisfies a
    // gate at this boundary (no server-attributable confirmation channel).
    let claims = session_batch_caller_claims(body);
    let mut report = SessionBatchPolicyReport {
        input_tainted_declared: body.input_tainted,
        input_tainted_effective: false,
        forced_tainted_actions: 0,
        max_side_effect: SideEffect::Read,
        strongest_gate: ConfirmationGate::None,
        confirmation_required: false,
        confirmed: body.confirmed,
        confirmed_effective: body.confirmed,
        confirmed_claim_ignored: false,
        idempotency_required: false,
        idempotency_key_provided: body.idempotency_key.is_some(),
        idempotency_cache_retained: privacy_mode.retains_idempotency_cache(),
    };
    let mut first_confirmation_index = None;
    let mut first_idempotency_index = None;
    for (index, action) in body.batch.actions.iter().enumerate() {
        let (decision, requires_confirmation) =
            match gate_boundary_action(action, observation, claims) {
                Ok(decision) => (decision, false),
                Err(required) => (required.decision, true),
            };
        report.max_side_effect = report.max_side_effect.max(decision.side_effect);
        report.strongest_gate = report.strongest_gate.max(decision.gate);
        if decision.input_taint.is_tainted() {
            report.input_tainted_effective = true;
            // Server evidence or the boundary write-floor tainted this action
            // beyond the caller's own declared claim.
            if !claims.claims_tainted() {
                report.forced_tainted_actions += 1;
            }
        }
        if requires_confirmation {
            report.confirmation_required = true;
            first_confirmation_index.get_or_insert(index);
        }
        if decision.idempotency_required {
            report.idempotency_required = true;
            first_idempotency_index.get_or_insert(index);
        }
    }
    report.confirmed_claim_ignored = report.confirmation_required && body.confirmed;
    report.confirmed_effective = body.confirmed && !report.confirmed_claim_ignored;
    let missing_confirmation = report.confirmation_required && !report.confirmed_effective;
    let missing_idempotency_key = report.idempotency_required && body.idempotency_key.is_none();
    let idempotency_unavailable = report.idempotency_required && !report.idempotency_cache_retained;
    let ineffective_idempotency = missing_idempotency_key || idempotency_unavailable;
    if missing_confirmation || ineffective_idempotency {
        return Err(deny_session_batch_policy(
            missing_confirmation,
            ineffective_idempotency,
            idempotency_unavailable,
            first_confirmation_index,
            first_idempotency_index,
            body,
            report,
        ));
    }
    Ok(report)
}

/// Build the `PolicyDenied` error for a batch the boundary refuses to execute.
///
/// The `(false, false)` arms below were previously `unreachable!`. This runs
/// while the caller holds the pool guard, so a panic here would poison the pool
/// mutex and permanently wedge the daemon (#413). A logic bug that reached the
/// denial path with no active reason now yields a plain denial instead of
/// panicking; the normal single-/dual-reason paths are unchanged.
fn deny_session_batch_policy(
    missing_confirmation: bool,
    ineffective_idempotency: bool,
    idempotency_unavailable: bool,
    first_confirmation_index: Option<usize>,
    first_idempotency_index: Option<usize>,
    body: &SessionActBatchRequest,
    report: SessionBatchPolicyReport,
) -> TempodError {
    let denied_action_index = match (missing_confirmation, ineffective_idempotency) {
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
        (false, false) => 0,
    };
    let denied_action_kind = body
        .batch
        .actions
        .get(denied_action_index)
        .map(action_kind)
        .unwrap_or("batch");
    let confirmation_reason = if report.confirmed_claim_ignored {
        "requires server-attributable confirmation before execution; confirmed=true was ignored"
    } else {
        "requires human confirmation before execution"
    };
    let idempotency_reason = if idempotency_unavailable {
        "requires retained idempotency replay state before execution; stealth mode disables the idempotency cache"
    } else {
        "requires idempotency_key before execution"
    };
    let reason = match (missing_confirmation, ineffective_idempotency) {
        (true, true) => format!("{confirmation_reason}; also {idempotency_reason}"),
        (true, false) => confirmation_reason.to_string(),
        (false, true) => idempotency_reason.to_string(),
        (false, false) => "policy denied".to_string(),
    };
    TempodError::PolicyDenied(Box::new(PolicyDeniedError {
        reason,
        denied_action_index,
        denied_action_kind,
        policy: report,
    }))
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

fn tempod_navigation_url_policy_denial(
    policy: &BrowserHardeningPolicy,
    url: &str,
) -> Option<TempodBrowserHardeningBlock> {
    policy
        .check_url(url)
        .err()
        .map(|blocked| tempod_browser_hardening_block(url, blocked, None, None))
}

fn tempod_resolved_navigation_url_policy_denial(
    policy: &BrowserHardeningPolicy,
    url: &str,
) -> Option<TempodBrowserHardeningBlock> {
    if let Some(block) = tempod_navigation_url_policy_denial(policy, url) {
        return Some(block);
    }
    let url_policy = policy.url_policy();
    if url_policy == &UrlPolicy::allow_all() {
        return None;
    }
    let sockets = match resolve_navigation_url_sockets(url) {
        Ok(sockets) => sockets,
        Err(reason) => {
            return Some(tempod_url_policy_hardening_block(
                url,
                "url_policy_resolution_failed",
                None,
                reason,
                None,
                None,
            ));
        }
    };
    for socket in sockets {
        if let Err(error) = url_policy.enforce_resolved_socket(url, socket) {
            return Some(tempod_url_policy_hardening_block(
                url,
                &format!(
                    "url_policy_{}",
                    block_code_label(error.reason.code).replace('-', "_")
                ),
                Some(error.reason.code),
                error.reason.detail,
                None,
                None,
            ));
        }
    }
    None
}

fn tempod_browser_hardening_block(
    url: &str,
    blocked: BrowserHardeningBlocked,
    action: Option<&str>,
    action_index: Option<usize>,
) -> TempodBrowserHardeningBlock {
    let (code, url_policy_code) = browser_hardening_code_labels(blocked.code);
    TempodBrowserHardeningBlock {
        url: url.into(),
        code,
        url_policy_code,
        origin: blocked.origin,
        reason: blocked.reason,
        action: action.map(str::to_string),
        action_index,
    }
}

fn tempod_url_policy_hardening_block(
    url: &str,
    code: &str,
    url_policy_code: Option<BlockCode>,
    reason: impl Into<String>,
    action: Option<&str>,
    action_index: Option<usize>,
) -> TempodBrowserHardeningBlock {
    TempodBrowserHardeningBlock {
        url: url.into(),
        code: code.into(),
        url_policy_code: url_policy_code.map(block_code_label).map(str::to_string),
        origin: None,
        reason: reason.into(),
        action: action.map(str::to_string),
        action_index,
    }
}

fn browser_hardening_code_labels(code: BrowserHardeningBlockCode) -> (String, Option<String>) {
    match code {
        BrowserHardeningBlockCode::UrlPolicy(block_code) => (
            format!(
                "url_policy_{}",
                block_code_label(block_code).replace('-', "_")
            ),
            Some(block_code_label(block_code).into()),
        ),
        BrowserHardeningBlockCode::InsecureTopLevelNavigation => {
            ("insecure_top_level_navigation".into(), None)
        }
        BrowserHardeningBlockCode::ThreatListedDomain => ("threat_listed_domain".into(), None),
        BrowserHardeningBlockCode::RiskyDownload => ("risky_download".into(), None),
    }
}

fn block_code_label(code: BlockCode) -> &'static str {
    match code {
        BlockCode::InvalidUrl => "invalid-url",
        BlockCode::UnsupportedScheme => "unsupported-scheme",
        BlockCode::EmptyHost => "empty-host",
        BlockCode::MalformedIpv6 => "malformed-ipv6",
        BlockCode::Localhost => "localhost",
        BlockCode::BlockedIp => "blocked-ip",
        BlockCode::PolicyDenied => "policy-denied",
        BlockCode::CrawlLimit => "crawl-limit",
    }
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

fn enforce_tempod_navigation_url(
    policy: &BrowserHardeningPolicy,
    url: &str,
) -> Result<(), TempodError> {
    if let Some(block) = tempod_navigation_url_policy_denial(policy, url) {
        return Err(TempodError::BrowserHardeningBlocked(Box::new(block)));
    }
    Ok(())
}

fn enforce_batch_navigation_url_policy(
    policy: &BrowserHardeningPolicy,
    batch: &ActionBatch,
) -> Result<(), TempodError> {
    for (index, action) in batch.actions.iter().enumerate() {
        if let Action::Goto { url } = action
            && let Some(mut block) = tempod_navigation_url_policy_denial(policy, url)
        {
            block.action = Some("goto".into());
            block.action_index = Some(index);
            return Err(TempodError::BrowserHardeningBlocked(Box::new(block)));
        }
    }
    Ok(())
}

fn enforce_tempod_navigation_url_transport(
    policy: &BrowserHardeningPolicy,
    url: &str,
) -> Result<(), TransportError> {
    if tempod_resolved_navigation_url_policy_denial(policy, url).is_some() {
        return Err(TransportError::UrlBlocked);
    }
    Ok(())
}

fn enforce_action_navigation_url_policy(
    policy: &BrowserHardeningPolicy,
    action: &Action,
) -> Result<(), TransportError> {
    if let Action::Goto { url } = action {
        enforce_tempod_navigation_url_transport(policy, url)?;
    }
    Ok(())
}

fn enforce_batch_navigation_url_policy_transport(
    policy: &BrowserHardeningPolicy,
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
    confirmed_effective: bool,
    confirmed_claim_ignored: bool,
    idempotency_required: bool,
    idempotency_key_provided: bool,
    idempotency_cache_retained: bool,
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
        "confirmed_effective": policy.confirmed_effective,
        "confirmed_claim_ignored": policy.confirmed_claim_ignored,
        "idempotency_required": policy.idempotency_required,
        "idempotency_key_provided": policy.idempotency_key_provided,
        "idempotency_cache_retained": policy.idempotency_cache_retained,
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
            "/ready": {
                "get": {
                    "operationId": "ready",
                    "security": [{"TempodBearer": []}],
                    "responses": {
                        "200": {
                            "description": "tempod is ready for new sessions",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReadinessResponse"}}}
                        },
                        "503": {
                            "description": "tempod is reachable but not ready for new sessions",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReadinessResponse"}}}
                        }
                    }
                }
            },
            TEMPOD_OPENAPI_PATH: {
                "get": {
                    "operationId": "openapi",
                    "responses": {"200": {"description": "OpenAPI 3.1 document"}}
                }
            },
            WEB_BOT_AUTH_KEY_DIRECTORY_PATH: {
                "get": {
                    "operationId": "webBotAuthKeyDirectory",
                    "responses": {"200": {"description": "Web Bot Auth HTTP message signatures JWK directory"}}
                }
            },
            "/sessions": {
                "get": {
                    "operationId": "listSessions",
                    "security": [{"TempodBearer": []}],
                    "responses": {"200": {"description": "List sessions"}}
                },
                "post": {
                    "operationId": "createSession",
                    "security": [{"TempodBearer": []}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateSessionRequest"}}}
                    },
                    "responses": {
                        "201": {"description": "Created session"},
                        "403": {
                            "description": "Browser hardening blocked navigation",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BrowserHardeningError"}}}
                        },
                        "429": {"description": "Session admission limit reached"}
                    }
                }
            },
            "/sessions/{session_id}/observe": {
                "get": {
                    "operationId": "observeSession",
                    "security": [{"TempodBearer": []}],
                    "parameters": [{"$ref": "#/components/parameters/SessionId"}],
                    "responses": {"200": {"description": "Compiled observation"}}
                }
            },
            "/sessions/{session_id}/resume": {
                "post": {
                    "operationId": "resumeSession",
                    "security": [{"TempodBearer": []}],
                    "parameters": [{"$ref": "#/components/parameters/SessionId"}],
                    "responses": {
                        "200": {"description": "Session resumed and resume event recorded"},
                        "409": {"description": "Session is terminal and cannot be resumed"}
                    }
                }
            },
            "/sessions/{session_id}/act_batch": {
                "post": {
                    "operationId": "actBatchSession",
                    "security": [{"TempodBearer": []}],
                    "parameters": [{"$ref": "#/components/parameters/SessionId"}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SessionActBatchRequest"}}}
                    },
                    "responses": {
                        "200": {"description": "Action batch outcome"},
                        "403": {
                            "description": "Policy denied or browser hardening blocked navigation",
                            "content": {"application/json": {"schema": {"oneOf": [
                                {"$ref": "#/components/schemas/PolicyDeniedError"},
                                {"$ref": "#/components/schemas/BrowserHardeningError"}
                            ]}}}
                        },
                        "409": {"description": "Idempotency conflict"}
                    }
                }
            },
            "/mcp": {
                "get": {
                    "operationId": "mcpGet",
                    "security": [{"TempodBearer": []}],
                    "responses": {"200": {"description": "MCP metadata"}}
                },
                "post": {
                    "operationId": "mcpPost",
                    "security": [{"TempodBearer": []}],
                    "responses": {"200": {"description": "MCP JSON-RPC response"}}
                }
            }
        },
        "components": {
            "securitySchemes": {
                "TempodBearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Bearer token from TEMPO_TEMPOD_AUTH_TOKEN, --auth-token, or the owner-only tempod runtime token file."
                }
            },
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
                "ReadinessResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "ok",
                        "ready",
                        "draining",
                        "engine_attached",
                        "sessions",
                        "max_sessions",
                        "reasons"
                    ],
                    "properties": {
                        "ok": {"type": "boolean"},
                        "ready": {"type": "boolean"},
                        "draining": {"type": "boolean"},
                        "engine_attached": {"type": "boolean"},
                        "sessions": {"type": "integer", "minimum": 0},
                        "max_sessions": {"type": "integer", "minimum": 0},
                        "reasons": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["draining", "engine_detached", "session_limit_reached"]
                            }
                        }
                    }
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
                },
                "PolicyDeniedError": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": ["error"],
                    "properties": {
                        "error": {"type": "string"}
                    }
                },
                "BrowserHardeningError": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["error", "browser_hardening"],
                    "properties": {
                        "error": {"type": "string"},
                        "browser_hardening": {"$ref": "#/components/schemas/TempodBrowserHardeningBlock"}
                    }
                },
                "TempodBrowserHardeningBlock": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["url", "code", "origin", "reason", "action", "action_index"],
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "code": {
                            "type": "string",
                            "enum": [
                                "url_policy_invalid_url",
                                "url_policy_unsupported_scheme",
                                "url_policy_empty_host",
                                "url_policy_malformed_ipv6",
                                "url_policy_localhost",
                                "url_policy_blocked_ip",
                                "url_policy_crawl_limit",
                                "url_policy_resolution_failed",
                                "insecure_top_level_navigation",
                                "threat_listed_domain",
                                "risky_download"
                            ]
                        },
                        "url_policy_code": {
                            "type": ["string", "null"],
                            "enum": [
                                "invalid-url",
                                "unsupported-scheme",
                                "empty-host",
                                "malformed-ipv6",
                                "localhost",
                                "blocked-ip",
                                "crawl-limit",
                                null
                            ]
                        },
                        "origin": {"type": ["string", "null"]},
                        "reason": {"type": "string"},
                        "action": {"type": ["string", "null"]},
                        "action_index": {"type": ["integer", "null"], "minimum": 0}
                    }
                }
            }
        }
    })
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

/// Whether a route must pass the loopback-Origin guard. Session/control-plane routes (create, drain, adopt, resume, delete, list,
/// session events, and any unrecognised — hence potentially state-changing —
/// route) are guarded. Exempt are the public idempotent metadata routes
/// (`/health`, the A2A agent card, `GET /mcp`) and the routes that already run
/// their own Origin check (`POST /mcp` via `route_mcp`, `POST /bidi`, and the
/// `GET /bidi` WebSocket upgrade handler). The guard relies
/// on `origin_allowed` returning `true` when no Origin header is present, so
/// non-browser/CLI clients keep working.
fn control_route_requires_origin_check(method: &str, path: &str) -> bool {
    !matches!(
        (method, path),
        ("GET", "/health")
            | ("GET", tempo_mcp::A2A_AGENT_CARD_PATH)
            | ("GET", tempo_mcp::A2A_AGENT_JSON_PATH)
            | ("GET", WEB_BOT_AUTH_KEY_DIRECTORY_PATH)
            | ("GET", TEMPOD_OPENAPI_PATH)
            | ("GET", "/mcp")
            | ("POST", "/mcp")
            | ("GET", "/bidi")
            | ("POST", "/bidi")
    )
}

fn is_metadata_route(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "/health")
            | ("GET", tempo_mcp::A2A_AGENT_CARD_PATH)
            | ("GET", tempo_mcp::A2A_AGENT_JSON_PATH)
            | ("GET", WEB_BOT_AUTH_KEY_DIRECTORY_PATH)
            | ("GET", TEMPOD_OPENAPI_PATH)
    )
}

fn is_protected_metadata_route(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", tempo_mcp::A2A_AGENT_CARD_PATH)
            | ("GET", tempo_mcp::A2A_AGENT_JSON_PATH)
            | ("GET", TEMPOD_OPENAPI_PATH)
    )
}

fn is_public_key_directory_route(method: &str, path: &str) -> bool {
    matches!((method, path), ("GET", WEB_BOT_AUTH_KEY_DIRECTORY_PATH))
}

fn route_requires_auth(method: &str, path: &str, is_loopback_listener: bool) -> bool {
    matches!(
        (method, path),
        ("GET", "/mcp") | ("POST", "/mcp") | ("GET", "/bidi") | ("POST", "/bidi")
    ) || control_route_requires_origin_check(method, path)
        || is_protected_metadata_route(method, path)
        || (!is_loopback_listener
            && is_metadata_route(method, path)
            && !is_public_key_directory_route(method, path))
}

fn route_requires_host_check(method: &str, path: &str, is_loopback_listener: bool) -> bool {
    route_requires_auth(method, path, is_loopback_listener)
        && !(is_loopback_listener && is_protected_metadata_route(method, path))
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
            let Some(input_tainted) = command.input_tainted else {
                return missing_bidi_input_taint_result(id);
            };
            let claims = CallerPolicyClaims::new(Some(input_tainted), command.confirmed);
            let context = command.context.clone();
            let Ok(handle) = bidi_driver_handle(pool, &context) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            if let Some(denied) = gate_bidi_command(
                &mut driver,
                id,
                command.action.side_effect(),
                &action_caller_texts(&command.action),
                claims,
            ) {
                return denied;
            }
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
            let Some(input_tainted) = command.input_tainted else {
                return missing_bidi_input_taint_result(id);
            };
            let claims = CallerPolicyClaims::new(Some(input_tainted), command.confirmed);
            let context = command.target.context.clone();
            let Ok(handle) = bidi_driver_handle(pool, &context) else {
                return pool_lock_bidi_error(Some(id));
            };
            let Some(mut driver) = handle else {
                return unknown_browsing_context_result(id);
            };
            if let Some(denied) = gate_bidi_command(
                &mut driver,
                id,
                SideEffect::Write,
                &[command.expression.as_str()],
                claims,
            ) {
                return denied;
            }
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

/// Trust boundary for policy-gated BiDi commands (#254): caller-supplied
/// `inputTainted`/`confirmed` are advisory. Taint is recomputed against the
/// target context's live observation when that evidence could change the
/// outcome (see `tempo_policy::trust`), the caller claim only ever escalates,
/// and a bare `confirmed=true` never satisfies a human gate because no
/// server-attributable confirmation channel exists at this boundary.
fn gate_bidi_command(
    driver: &mut AttachedEngineDriver,
    id: tempo_bidi::CommandId,
    effect: SideEffect,
    texts: &[&str],
    claims: CallerPolicyClaims,
) -> Option<BidiDispatchResult> {
    let observation = if requires_observation_evidence(effect, texts, claims) {
        match futures::executor::block_on(driver.observe()) {
            Ok(observation) => Some(observation),
            Err(error) => {
                return Some(BidiDispatchResult::new(
                    200,
                    BidiMessage::error(
                        Some(id),
                        BidiErrorCode::UnknownError,
                        format!(
                            "policy taint recomputation requires an observation, but observe failed: {error}"
                        ),
                    ),
                ));
            }
        }
    } else {
        None
    };
    match gate_boundary_effect(effect, texts, observation.as_ref(), claims) {
        Ok(_) => None,
        Err(required) => Some(BidiDispatchResult::new(
            200,
            BidiMessage::error(Some(id), BidiErrorCode::InvalidArgument, required.message()),
        )),
    }
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
    let identity_mode = network_navigation_identity_mode(pool, url);
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
            identity_mode,
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

fn network_navigation_identity_mode(pool: &SessionPool, url: &str) -> tempo_net::IdentityMode {
    pool.identity_strategy_table()
        .mode_for_url(url)
        .unwrap_or(tempo_net::IdentityMode::AgentDeclared)
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

fn route_mcp(pool: &Arc<Mutex<SessionPool>>, origin: Option<&str>, body: &[u8]) -> HttpResponse {
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
            server.handle_post(origin, body),
        ));
    }
    HttpResponse::from_mcp(tempo_mcp::handle_post_driverless(origin, body))
}

fn valid_host_header(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

fn loopback_host_allowed(host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim).filter(|host| valid_host_header(host)) else {
        return false;
    };
    let Ok(url) = Url::parse(&format!("http://{host}/")) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn normalized_host_header_name(host: &str) -> Option<String> {
    if !valid_host_header(host) {
        return None;
    }
    if host.starts_with('[') {
        let end = host.find(']')?;
        let literal = &host[..=end];
        let suffix = &host[end + 1..];
        if !suffix.is_empty() && !valid_port_suffix(suffix) {
            return None;
        }
        return Some(literal.to_ascii_lowercase());
    }
    if host.contains(['[', ']']) {
        return None;
    }
    let host = match host.rsplit_once(':') {
        Some((name, port)) if valid_port(port) => name,
        Some(_) => return None,
        None => host,
    }
    .trim_end_matches('.');
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn canonical_ip_host(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
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
}

impl IntoResponse for HttpResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            [(header::CONTENT_TYPE, self.content_type)],
            self.body,
        )
            .into_response()
    }
}

impl IntoResponse for TempodError {
    fn into_response(self) -> Response {
        tempod_error_response(&self).into_response()
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
    #[error("browser hardening blocked navigation: {0}")]
    BrowserHardeningBlocked(Box<TempodBrowserHardeningBlock>),
    #[error("{0}")]
    PolicyDenied(Box<PolicyDeniedError>),
    #[error("connection limit reached: {0}")]
    ConnectionLimit(String),
    #[error("session limit reached: max {max} retained sessions")]
    SessionLimit { max: usize },
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
            Self::BrowserHardeningBlocked(_) => 403,
            Self::PolicyDenied(_) => 403,
            Self::SessionLimit { .. } => 429,
            Self::SessionNotFound(_) | Self::EngineNotFound(_) => 404,
            Self::Draining | Self::ConnectionLimit(_) | Self::DriverUnavailable(_) => 503,
            Self::Io(_) | Self::Json(_) | Self::PoolLock | Self::Driver(_) | Self::Engine(_) => 500,
        }
    }

    fn body(&self) -> JsonValue {
        match self {
            Self::BrowserHardeningBlocked(block) => json!({
                "error": self.to_string(),
                "browser_hardening": block,
            }),
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

    fn expect_test_err<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    // RFC 6455 opcodes used by the raw-socket WebSocket test client.
    const WS_OPCODE_TEXT: u8 = 0x1;
    const WS_OPCODE_CLOSE: u8 = 0x8;

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

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

    /// Request description used by the in-process tests. The shims below feed
    /// it through the production axum router (`tempod_router`) via
    /// `tower::ServiceExt::oneshot`, so every in-process test exercises the
    /// same routing, guards, and handlers as a real socket connection.
    #[derive(Debug)]
    struct HttpRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        host: Option<String>,
        origin: Option<String>,
        body: Vec<u8>,
    }

    /// Simplified response captured from the router for assertions.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestResponse {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    }

    fn oneshot_response(
        shared: &Arc<Mutex<SessionPool>>,
        auth: &TempodAuth,
        request: HttpRequest,
    ) -> Result<TestResponse, TempodError> {
        use tower::ServiceExt as _;
        let router = tempod_router(TempodAppState {
            pool: Arc::clone(shared),
            auth: auth.clone(),
            host_guard: TempodHostGuard::loopback(),
            limiter: ConnectionLimiter::default(),
            web_bot_auth_verifiers: Vec::new(),
        });
        let mut builder = axum::http::Request::builder()
            .method(request.method.as_str())
            .uri(&request.path);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        builder = builder.header("host", request.host.as_deref().unwrap_or("127.0.0.1:8787"));
        if let Some(origin) = &request.origin {
            builder = builder.header("origin", origin);
        }
        let http_request = builder
            .body(axum::body::Body::from(request.body))
            .map_err(|error| TempodError::BadRequest(error.to_string()))?;
        let runtime = transport_runtime()?;
        runtime.block_on(async move {
            let response = match router.oneshot(http_request).await {
                Ok(response) => response,
                Err(infallible) => match infallible {},
            };
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = axum::body::to_bytes(response.into_body(), MAX_HTTP_BYTES * 16)
                .await
                .map_err(|error| TempodError::Driver(error.to_string()))?
                .to_vec();
            Ok(TestResponse {
                status,
                content_type,
                body,
            })
        })
    }

    fn route_http_request(
        pool: &mut SessionPool,
        request: HttpRequest,
    ) -> Result<TestResponse, TempodError> {
        with_shared_pool(pool, |shared| {
            oneshot_response(shared, &TempodAuth::disabled(), request)
        })
    }

    fn handle_http_request(pool: &mut SessionPool, request: HttpRequest) -> TestResponse {
        handle_http_request_with_auth(pool, request, &TempodAuth::disabled())
    }

    fn handle_http_request_with_auth(
        pool: &mut SessionPool,
        request: HttpRequest,
        auth: &TempodAuth,
    ) -> TestResponse {
        match with_shared_pool(pool, |shared| oneshot_response(shared, auth, request)) {
            Ok(response) => response,
            Err(error) => {
                let response = tempod_error_response(&error);
                TestResponse {
                    status: response.status,
                    content_type: response.content_type.to_string(),
                    body: response.body,
                }
            }
        }
    }

    fn json_array_contains(value: &Value, expected: &str) -> bool {
        value
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == expected))
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

    fn discard_unserved_attached_engine(pool: &mut SessionPool) {
        pool.session_drivers.clear();
        pool.bidi_contexts.clear();
        pool.mcp = None;
        pool.driver = None;
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
    fn session_act_batch_ignores_caller_confirmed_for_external_writes() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session = pool.finish_create("https://rest-policy.test".into(), Some(session_driver));
        let body = br#"{
            "batch": {
                "actions": [{"kind": "click", "node": "button-primary"}],
                "quiescence": "composite"
            },
            "input_tainted": false,
            "confirmed": true,
            "idempotency_key": "click-once"
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );

        assert_eq!(response.status, 403);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["denied_action_kind"], "click");
        assert_eq!(value["policy"]["confirmed"], true);
        assert_eq!(value["policy"]["confirmed_effective"], false);
        assert_eq!(value["policy"]["confirmed_claim_ignored"], true);
        assert!(value["reason"]
            .as_str()
            .ok_or("policy denial should include a reason")?
            .contains("confirmed=true was ignored"));
        assert_no_driver_ipc(&mut server_stream)?;
        discard_unserved_attached_engine(&mut pool);
        Ok(())
    }

    #[test]
    fn stealth_session_act_batch_rejects_uncacheable_idempotency_required_actions() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default().with_privacy_mode(PrivacyMode::Stealth);
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session =
            pool.finish_create("https://stealth-policy.test".into(), Some(session_driver));
        let body = br#"{
            "batch": {
                "actions": [{"kind": "click", "node": "stealth-button"}],
                "quiescence": "composite"
            },
            "input_tainted": false,
            "confirmed": true,
            "idempotency_key": "stealth-click-once"
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );

        assert_eq!(response.status, 403);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["denied_action_kind"], "click");
        assert_eq!(value["policy"]["idempotency_required"], true);
        assert_eq!(value["policy"]["idempotency_key_provided"], true);
        assert_eq!(value["policy"]["idempotency_cache_retained"], false);
        assert!(value["reason"]
            .as_str()
            .ok_or("policy denial should include a reason")?
            .contains("stealth mode disables the idempotency cache"));
        assert_no_driver_ipc(&mut server_stream)?;
        discard_unserved_attached_engine(&mut pool);
        Ok(())
    }

    /// The exact #342 repro: a REST `act_batch` Goto whose URL embeds a
    /// page-provenance span with different casing must be DENIED even when the
    /// caller claims `input_tainted:false`. The engine serves exactly ONE
    /// request (the policy-evidence Observe) and NO ActBatch. This test FAILS
    /// (the Goto is dispatched, 200) if the server-side taint recomputation is
    /// removed or case-sensitive — mirrors
    /// `bidi_navigate_recomputes_taint_from_observation_and_blocks_clean_claim`.
    #[test]
    fn session_act_batch_goto_recomputes_taint_from_observation_and_blocks_clean_claim(
    ) -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.command, HostDriverCommand::Observe);
            DriverResponse::Observation {
                observation: tainted_observation("https://current.test", 1, "Evil.Example/Exfil"),
            }
        })?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session = pool.finish_create("https://current.test".into(), Some(session_driver));

        let body = br#"{
            "batch": {
                "actions": [{"kind": "goto", "url": "https://evil.example/exfil?otp=123456"}],
                "quiescence": "composite"
            },
            "input_tainted": false
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );
        join_driver_handler(handle)?;

        assert_eq!(response.status, 403);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["denied_action_kind"], "goto");
        assert_eq!(value["policy"]["input_tainted_effective"], true);
        assert_eq!(value["policy"]["confirmation_required"], true);
        assert!(value["reason"]
            .as_str()
            .ok_or("policy denial should include a reason")?
            .contains("requires human confirmation"));
        Ok(())
    }

    /// A genuinely-clean Goto (URL text overlaps no page-provenance span) still
    /// executes: recomputation fetches the Observe, finds the claim honest, and
    /// dispatches the ActBatch (#342).
    #[test]
    fn session_act_batch_goto_with_clean_claim_and_no_page_overlap_executes() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler_seq(&mut pool, 2, |request| match request.command {
            HostDriverCommand::Observe => DriverResponse::Observation {
                observation: tainted_observation(
                    "https://current.test",
                    1,
                    "unrelated banner text",
                ),
            },
            HostDriverCommand::ActBatch { .. } => DriverResponse::Step {
                outcome: StepOutcome::Applied {
                    diff: ObservationDiff {
                        since_seq: 1,
                        seq: 2,
                        omitted: 0,
                        added: Vec::new(),
                        removed: Vec::new(),
                        changed: Vec::new(),
                    },
                }
                .into(),
            },
            _ => DriverResponse::Closed,
        })?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session = pool.finish_create("https://current.test".into(), Some(session_driver));

        let body = br#"{
            "batch": {
                "actions": [{"kind": "goto", "url": "https://clean.example/dashboard"}],
                "quiescence": "composite"
            },
            "input_tainted": false
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["status"], "applied");
        assert_eq!(value["policy"]["input_tainted_effective"], false);
        Ok(())
    }

    /// Escalate-only merge: a caller that marks its own Goto `input_tainted:true`
    /// is honored (taint can only be ADDED), and recomputation is skipped
    /// because the claim already sits at maximum taint — no Observe IPC, the
    /// tainted Read escalates to a confirmation gate and is denied (#342).
    #[test]
    fn session_act_batch_goto_honors_caller_escalated_taint_without_observation() -> TestResult {
        let (client_stream, mut server_stream) = UnixStream::pair()?;
        server_stream.set_nonblocking(true)?;
        let mut pool = SessionPool::default();
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session = pool.finish_create("https://current.test".into(), Some(session_driver));

        let body = br#"{
            "batch": {
                "actions": [{"kind": "goto", "url": "https://fresh.example/page"}],
                "quiescence": "composite"
            },
            "input_tainted": true
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );

        assert_eq!(response.status, 403);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["denied_action_kind"], "goto");
        assert_eq!(value["policy"]["input_tainted_effective"], true);
        assert_eq!(value["policy"]["confirmation_required"], true);
        assert_no_driver_ipc(&mut server_stream)?;
        discard_unserved_attached_engine(&mut pool);
        Ok(())
    }

    /// `confirmed:true` cannot bypass the recomputed gate: a page-tainted Goto
    /// claimed clean-and-confirmed is still denied, and the caller confirmation
    /// is reported ignored (no server-attributable channel) (#342/#334).
    #[test]
    fn session_act_batch_goto_confirmed_claim_cannot_bypass_recomputed_taint() -> TestResult {
        let mut pool = SessionPool::default();
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.command, HostDriverCommand::Observe);
            DriverResponse::Observation {
                observation: tainted_observation("https://current.test", 1, "evil.example/exfil"),
            }
        })?;
        let session_driver = pool
            .driver
            .clone()
            .ok_or("attached engine driver should be present")?;
        let session = pool.finish_create("https://current.test".into(), Some(session_driver));

        let body = br#"{
            "batch": {
                "actions": [{"kind": "goto", "url": "https://evil.example/exfil?otp=123456"}],
                "quiescence": "composite"
            },
            "input_tainted": false,
            "confirmed": true
        }"#;

        let response = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                &format!("/sessions/{}/act_batch", session.id.0),
                None,
                body,
            ),
        );
        join_driver_handler(handle)?;

        assert_eq!(response.status, 403);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["denied_action_kind"], "goto");
        assert_eq!(value["policy"]["confirmed"], true);
        assert_eq!(value["policy"]["confirmed_effective"], false);
        assert_eq!(value["policy"]["confirmed_claim_ignored"], true);
        assert!(value["reason"]
            .as_str()
            .ok_or("policy denial should include a reason")?
            .contains("confirmed=true was ignored"));
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
            handles.push(thread::spawn(move || serve_one_unsafe(listener, pool)));
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
            HostDriverCommand::Observe => FakeEngineReply::Respond(DriverResponse::Observation {
                observation: observation("about:blank", 0),
            }),
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

    /// (#440) A `DELETE /sessions/{id}` whose engine-context `Close` wedges,
    /// racing a long in-flight command on ANOTHER session, must NOT: (a) detach
    /// the shared engine, (b) make surviving sessions `DriverUnavailable`, or
    /// (c) hold the pool lock across the teardown. Before the fix, the killed
    /// session's `Close` timeout alone tripped `abandon_*`, which `mem::take`s
    /// every session driver and the root driver under the lock — stranding all
    /// survivors and holding the mutex for the whole bound.
    #[test]
    fn delete_with_wedged_close_does_not_strand_or_lock_out_survivors() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        let context_ids = AtomicUsize::new(1);
        let pool = shared_pool_with_fake_engine(move |request| match &request.command {
            HostDriverCommand::CreateBrowsingContext { .. } => {
                let n = context_ids.fetch_add(1, Ordering::SeqCst);
                FakeEngineReply::Respond(DriverResponse::BrowsingContextCreated {
                    driver_id: format!("session-context-{n}"),
                })
            }
            HostDriverCommand::Goto { url } => {
                FakeEngineReply::Respond(DriverResponse::Observation {
                    observation: observation(url, 1),
                })
            }
            // The survivor's own observe (its first session context is
            // `session-context-1`) models a long in-flight command on another
            // session. The daemon's liveness probe runs on the ROOT context
            // (`driver_id: None`) and is answered promptly, so the engine reads
            // as responsive-but-busy, not wedged.
            HostDriverCommand::Observe => {
                if request.driver_id.as_deref() == Some("session-context-1") {
                    FakeEngineReply::RespondAfter(
                        Duration::from_millis(400),
                        DriverResponse::Observation {
                            observation: observation("about:blank", 2),
                        },
                    )
                } else {
                    FakeEngineReply::Respond(DriverResponse::Observation {
                        observation: observation("about:blank", 2),
                    })
                }
            }
            // The killed session's context Close never answers (in production it
            // is stuck behind the other session's in-flight navigation).
            HostDriverCommand::Close => FakeEngineReply::Wedge,
            _ => FakeEngineReply::Respond(DriverResponse::Closed),
        })?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let servers = spawn_servers(&listener, &pool, 5)?;

        // Two live sessions: session-0 (survivor) and session-1 (to be killed).
        let survivor = http_post(addr, "/sessions", r#"{"url":"https://survivor.test"}"#)?;
        assert!(survivor.starts_with("HTTP/1.1 201"), "{survivor}");
        let victim = http_post(addr, "/sessions", r#"{"url":"https://victim.test"}"#)?;
        assert!(victim.starts_with("HTTP/1.1 201"), "{victim}");

        // Kick off the survivor's long in-flight observe (~400ms).
        let observe_survivor = thread::spawn(move || {
            send_http(addr, "GET /sessions/session-0/observe HTTP/1.1\r\n\r\n")
        });
        // Ensure that observe has reached the engine before the DELETE races it.
        thread::sleep(Duration::from_millis(40));

        // DELETE the victim: its Close wedges, so the bounded Close times out.
        let delete_victim =
            thread::spawn(move || send_http(addr, "DELETE /sessions/session-1 HTTP/1.1\r\n\r\n"));

        // (c) While the DELETE is inside its wedged-Close teardown window, a
        // request that needs the pool lock must NOT block on it. Create a third
        // session and time it: if the lock were held across teardown, this
        // would stall for the whole ENGINE_TEARDOWN_TIMEOUT.
        thread::sleep(Duration::from_millis(40));
        let create_started = Instant::now();
        let third = http_post(addr, "/sessions", r#"{"url":"https://third.test"}"#)?;
        let create_elapsed = create_started.elapsed();
        assert!(third.starts_with("HTTP/1.1 201"), "{third}");
        assert!(
            create_elapsed < Duration::from_millis(100),
            "creating a session while a DELETE was tearing down a wedged Close took {create_elapsed:?}: \
             the pool lock was held across the teardown"
        );

        let observe_survivor = observe_survivor
            .join()
            .map_err(|_| "survivor observe panicked")??;
        let delete_victim = delete_victim
            .join()
            .map_err(|_| "delete victim panicked")??;

        // (b) The survivor's request completed against the still-attached engine
        // instead of failing DriverUnavailable.
        assert!(
            observe_survivor.starts_with("HTTP/1.1 200"),
            "survivor was stranded by the racing DELETE: {observe_survivor}"
        );
        assert!(delete_victim.starts_with("HTTP/1.1 200"), "{delete_victim}");

        // (a) The shared engine is still attached and every non-victim session
        // still has its driver; only the killed session was detached.
        {
            let pool = pool.lock().map_err(|_| "pool poisoned")?;
            assert!(
                pool.driver.is_some(),
                "a single wedged session Close abandoned the shared engine"
            );
            assert!(
                pool.session_drivers
                    .contains_key(&TempodSessionId("session-0".into())),
                "survivor session lost its engine driver"
            );
            assert!(
                pool.session_drivers
                    .contains_key(&TempodSessionId("session-2".into())),
                "session created during the teardown lost its engine driver"
            );
            assert!(
                !pool
                    .session_drivers
                    .contains_key(&TempodSessionId("session-1".into())),
                "killed session's driver should have been detached"
            );
        }

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
            HostDriverCommand::Observe => FakeEngineReply::Respond(DriverResponse::Observation {
                observation: observation("about:blank", 0),
            }),
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
            HostDriverCommand::Observe => FakeEngineReply::Respond(DriverResponse::Observation {
                observation: observation("about:blank", 0),
            }),
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
            HostDriverCommand::Observe => FakeEngineReply::Respond(DriverResponse::Observation {
                observation: observation("about:blank", 0),
            }),
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
            HostDriverCommand::Observe => FakeEngineReply::Respond(DriverResponse::Observation {
                observation: observation("about:blank", 0),
            }),
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
        thread::spawn(move || serve_one_unsafe(wedged_listener, wedged_pool));
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
        let resumed = pool.resume(&session.id)?;
        assert_eq!(resumed.state, TempodSessionState::Running);
        let step = sample_step_triple(7);
        let step_event = pool.record_step(&session.id, step.clone())?;
        pool.kill(&session.id)?;

        assert_eq!(step_event.seq, 3);
        assert_eq!(
            step_event.event,
            TempodSessionEventKind::StepTriple { triple: step }
        );

        let events = pool.events(&session.id, None)?;
        assert_eq!(events.len(), 5);
        assert!(matches!(
            events[0].event,
            TempodSessionEventKind::SessionCreated { .. }
        ));
        assert_eq!(events[1].event, TempodSessionEventKind::SessionAdopted);
        assert_eq!(events[2].event, TempodSessionEventKind::SessionResumed);
        assert!(matches!(
            events[3].event,
            TempodSessionEventKind::StepTriple { .. }
        ));
        assert_eq!(events[4].event, TempodSessionEventKind::SessionKilled);

        let after_adopt = pool.events(&session.id, Some(1))?;
        assert_eq!(after_adopt.len(), 3);
        assert_eq!(after_adopt[0].seq, 2);
        assert_eq!(after_adopt[0].event, TempodSessionEventKind::SessionResumed);
        Ok(())
    }

    #[test]
    fn session_pool_records_human_takeover_on_the_event_stream() -> TestResult {
        use tempo_schema::TakeoverKind;

        let mut pool = SessionPool::default();
        let session = pool.create("https://captcha.test")?;
        let takeover = HumanTakeover {
            kind: TakeoverKind::Captcha,
            reason: "cloudflare turnstile detected".into(),
            url: "https://captcha.test/challenge".into(),
        };
        let event = pool.record_human_takeover(&session.id, takeover.clone())?;

        // It lands on the same /events stream the shell already polls.
        assert_eq!(
            event.event,
            TempodSessionEventKind::HumanTakeoverRequired {
                takeover: takeover.clone()
            }
        );
        let events = pool.events(&session.id, None)?;
        assert!(events.iter().any(|event| matches!(
            &event.event,
            TempodSessionEventKind::HumanTakeoverRequired { takeover: seen } if *seen == takeover
        )));

        // Serde tag is the snake_case variant the wire/client agree on.
        let json = serde_json::to_value(&event.event)?;
        assert_eq!(json["kind"], "human_takeover_required");
        assert_eq!(json["takeover"]["kind"], "captcha");

        // Unknown session id is rejected, like record_step.
        assert!(matches!(
            pool.record_human_takeover(&TempodSessionId("missing".into()), takeover),
            Err(TempodError::SessionNotFound(_))
        ));
        Ok(())
    }

    #[test]
    fn browser_hardening_blocks_are_structured_errors() -> TestResult {
        let mut pool = SessionPool::default().with_browser_hardening_policy(
            BrowserHardeningPolicy::strict().with_url_policy(UrlPolicy::allow_all()),
        );
        let error = expect_test_err(
            pool.create("http://example.com/login"),
            "strict hardening should block cleartext navigation",
        );
        assert_eq!(error.status(), 403);

        let response = tempod_error_response(&error);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            value["browser_hardening"]["code"],
            "insecure_top_level_navigation"
        );
        assert_eq!(
            value["browser_hardening"]["url"],
            "http://example.com/login"
        );
        assert_eq!(value["browser_hardening"]["origin"], "http://example.com");
        assert_eq!(value["browser_hardening"]["action"], Value::Null);
        Ok(())
    }

    #[test]
    fn session_pool_records_browser_hardening_blocks_on_the_event_stream() -> TestResult {
        let mut pool = SessionPool::default();
        let session = pool.create("https://hardening.test")?;
        let block = TempodBrowserHardeningBlock {
            url: "https://hardening.test/installer.dmg".into(),
            code: "risky_download".into(),
            url_policy_code: None,
            origin: Some("https://hardening.test".into()),
            reason: "browser hardening blocked an executable-like download path".into(),
            action: Some("goto".into()),
            action_index: Some(0),
        };
        let event = pool.record_browser_hardening_block(&session.id, block.clone())?;

        assert_eq!(
            event.event,
            TempodSessionEventKind::BrowserHardeningBlocked {
                block: block.clone()
            }
        );
        let json = serde_json::to_value(&event.event)?;
        assert_eq!(json["kind"], "browser_hardening_blocked");
        assert_eq!(json["block"]["code"], "risky_download");
        assert_eq!(json["block"]["action"], "goto");

        assert!(matches!(
            pool.record_browser_hardening_block(&TempodSessionId("missing".into()), block),
            Err(TempodError::SessionNotFound(_))
        ));
        Ok(())
    }

    #[test]
    fn session_batch_policy_tags_browser_hardening_blocked_goto_action() -> TestResult {
        let body = SessionActBatchRequest {
            batch: ActionBatch {
                actions: vec![Action::Goto {
                    url: "https://example.com/download/installer.dmg".into(),
                }],
                quiescence: tempo_schema::QuiescencePolicy::Composite,
            },
            input_tainted: None,
            confirmed: false,
            idempotency_key: None,
        };
        let error = expect_test_err(
            enforce_session_batch_policy(
                &BrowserHardeningPolicy::standard().with_url_policy(UrlPolicy::allow_all()),
                PrivacyMode::Audit,
                &body,
                None,
            ),
            "risky downloads should be blocked before dispatch",
        );

        match error {
            TempodError::BrowserHardeningBlocked(block) => {
                assert_eq!(block.code, "risky_download");
                assert_eq!(block.action.as_deref(), Some("goto"));
                assert_eq!(block.action_index, Some(0));
            }
            other => return Err(format!("unexpected error: {other}").into()),
        }
        Ok(())
    }

    #[test]
    fn stealth_mode_does_not_retain_lifecycle_or_step_events() -> TestResult {
        let mut pool = SessionPool::default().with_privacy_mode(PrivacyMode::Stealth);
        let session = pool.create("https://stealth.test")?;
        pool.adopt(&session.id)?;
        let step_event = pool.record_step(&session.id, sample_step_triple(13))?;

        assert!(matches!(
            step_event.event,
            TempodSessionEventKind::StepTriple { .. }
        ));
        assert_eq!(pool.events(&session.id, None)?, Vec::new());

        pool.kill(&session.id)?;
        assert!(matches!(
            pool.events(&session.id, None),
            Err(TempodError::SessionNotFound(_))
        ));
        Ok(())
    }

    #[test]
    fn stealth_mode_disables_metrics_exposition_even_when_config_enabled() {
        assert!(metrics_enabled_for_privacy(PrivacyMode::Audit, true));
        assert!(!metrics_enabled_for_privacy(PrivacyMode::Audit, false));
        assert!(!metrics_enabled_for_privacy(PrivacyMode::Stealth, true));
        assert!(!metrics_enabled_for_privacy(PrivacyMode::Stealth, false));
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

        let mut pool =
            SessionPool::from_otlp_env_values(Some(path.as_os_str().to_os_string()), None);
        assert_eq!(
            pool.otlp_exporter()
                .ok_or("expected env path to configure exporter")?
                .path(),
            path.as_path()
        );

        pool.set_otlp_exporter(None);
        assert!(pool.otlp_exporter().is_none());
        assert!(SessionPool::from_otlp_env_values(None, None)
            .otlp_exporter()
            .is_none());
        assert!(
            SessionPool::from_otlp_env_values(Some(std::ffi::OsString::new()), None)
                .otlp_exporter()
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn session_pool_from_env_loads_threat_domain_feed() -> TestResult {
        let root = unique_dir("env-threat-feed")?;
        std::fs::create_dir_all(&root)?;
        let path = root.join("threat-domains.txt");
        std::fs::write(
            &path,
            "# local fixture feed\nmalware.test\n*.phishing.test\n",
        )?;

        let pool = SessionPool::from_env_values(
            None,
            None,
            None,
            Some(path.as_os_str().to_os_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(pool.browser_hardening_policy.threat_domain_count(), 2);
        assert!(matches!(
            pool.browser_hardening_policy
                .check_url("https://login.phishing.test/"),
            Err(BrowserHardeningBlocked {
                code: BrowserHardeningBlockCode::ThreatListedDomain,
                ..
            })
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn session_pool_from_env_persists_threat_domain_feed_audit() -> TestResult {
        let root = unique_dir("env-threat-audit")?;
        std::fs::create_dir_all(&root)?;
        let feed_path = root.join("threat-domains.txt");
        let audit_path = root.join("threat-audit.jsonl");
        std::fs::write(
            &feed_path,
            "# local fixture feed\nmalware.test\n*.phishing.test\n",
        )?;

        let pool = SessionPool::from_env_values(
            None,
            None,
            None,
            Some(feed_path.as_os_str().to_os_string()),
            None,
            None,
            None,
            None,
            None,
            Some(audit_path.as_os_str().to_os_string()),
        );

        assert_eq!(pool.browser_hardening_policy.threat_domain_count(), 2);
        let bytes = std::fs::read(&audit_path)?;
        let value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap_or(&bytes))?;
        assert_eq!(value["source"], "env_file");
        assert_eq!(value["env"], TEMPO_THREAT_DOMAIN_FILE_ENV);
        assert_eq!(value["provider_id"], "tempo-threat-domain-file");
        assert_eq!(value["rule_count"], 2);
        assert_eq!(value["exact_rules"], 1);
        assert_eq!(value["suffix_rules"], 1);
        let serialized = String::from_utf8(bytes)?;
        assert!(!serialized.contains("malware.test"));
        assert!(!serialized.contains("phishing.test"));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn threat_domain_feed_url_rejects_cleartext() {
        let error = expect_test_err(
            fetch_threat_domain_feed_url("http://example.test/threats.txt"),
            "cleartext feed URLs must be rejected before network",
        );

        assert!(error.contains("must use https"));
    }

    #[test]
    fn threat_domain_feed_url_rejects_private_targets() {
        let error = expect_test_err(
            fetch_threat_domain_feed_url("https://127.0.0.1/threats.txt"),
            "private feed URLs must be rejected before network",
        );

        assert!(error.contains("URL blocked"));
    }

    #[test]
    fn threat_domain_feed_invalid_digest_pin_fails_closed_by_default() {
        let pool = SessionPool::from_env_values(
            None,
            None,
            None,
            None,
            Some(std::ffi::OsString::from("https://example.test/feed.txt")),
            None,
            Some(std::ffi::OsString::from("not-a-sha256")),
            None,
            None,
            None,
        );

        assert!(matches!(
            pool.browser_hardening_policy
                .check_url("https://example.com/"),
            Err(BrowserHardeningBlocked {
                code: BrowserHardeningBlockCode::UrlPolicy(BlockCode::PolicyDenied),
                ..
            })
        ));
    }

    #[test]
    fn threat_domain_feed_invalid_digest_pin_can_fail_open_explicitly() {
        let pool = SessionPool::from_env_values(
            None,
            None,
            None,
            None,
            Some(std::ffi::OsString::from("https://example.test/feed.txt")),
            None,
            Some(std::ffi::OsString::from("not-a-sha256")),
            None,
            Some(std::ffi::OsString::from("fail-open")),
            None,
        );

        assert!(pool
            .browser_hardening_policy
            .check_url("https://example.com/")
            .is_ok());
    }

    #[test]
    fn threat_domain_feed_sha256_accepts_matching_digest() -> TestResult {
        let contents = "malware.test\n".to_string();
        let digest = sha256_hex(contents.as_bytes());

        let verified = verify_threat_domain_feed_sha256(contents.clone(), Some(&digest))
            .map_err(std::io::Error::other)?;

        assert_eq!(verified, contents);
        Ok(())
    }

    #[test]
    fn threat_domain_feed_sha256_rejects_mismatch() {
        let error = expect_test_err(
            verify_threat_domain_feed_sha256(
                "malware.test\n".to_string(),
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
            "mismatched feed digest must be rejected",
        );

        assert!(error.contains("digest mismatch"));
    }

    #[test]
    fn signed_threat_domain_metadata_accepts_trusted_signature() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id.clone(),
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );

        let verified =
            verify_signed_threat_domain_metadata(&metadata_json, feed, &trusted, 1_788_480_001_000)
                .map_err(std::io::Error::other)?;

        assert_eq!(verified.key_id, key_id);
        assert_eq!(verified.feed_sha256, sha256_hex(feed.as_bytes()));
        Ok(())
    }

    #[test]
    fn signed_threat_domain_metadata_rejects_expired_envelope() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_788_480_001_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );

        let error = expect_test_err(
            verify_signed_threat_domain_metadata(&metadata_json, feed, &trusted, 1_788_480_002_000),
            "expired signed metadata must be rejected",
        );

        assert!(error.contains("expired"));
        Ok(())
    }

    #[test]
    fn signed_threat_domain_key_rotation_adds_current_key_signed_next_key() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[10_u8; 32]);
        let next_signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let key_id = "root-2026".to_string();
        let next_key_id = "root-2027".to_string();
        let next_public_key = BASE64_STANDARD.encode(next_signing_key.verifying_key().to_bytes());
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: Some(next_key_id.clone()),
            next_public_key: Some(next_public_key.clone()),
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );
        let verified =
            verify_signed_threat_domain_metadata(&metadata_json, feed, &trusted, 1_788_480_001_000)
                .map_err(std::io::Error::other)?;

        let rotated = apply_verified_threat_domain_key_rotation(&trusted, &verified)
            .map_err(std::io::Error::other)?;

        assert_eq!(rotated.get(&next_key_id), Some(&next_public_key));
        Ok(())
    }

    #[test]
    fn signed_threat_domain_key_rotation_rejects_duplicate_key_id() {
        let key_id = "root-2026".to_string();
        let verified = VerifiedThreatDomainMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            key_id: key_id.clone(),
            feed_sha256: "0".repeat(64),
            next_key_id: Some(key_id.clone()),
            next_public_key: Some(BASE64_STANDARD.encode([1_u8; 32])),
        };
        let mut trusted = BTreeMap::new();
        trusted.insert(key_id, BASE64_STANDARD.encode([2_u8; 32]));

        let error = expect_test_err(
            apply_verified_threat_domain_key_rotation(&trusted, &verified),
            "duplicate rotation key ids must be rejected",
        );

        assert!(error.contains("already exists"));
    }

    #[test]
    fn signed_threat_domain_policy_snapshot_applies_after_full_verification() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );
        let mut pool = SessionPool::default().with_browser_hardening_policy(
            BrowserHardeningPolicy::standard().with_url_policy(UrlPolicy::allow_all()),
        );

        let audit = pool
            .apply_verified_signed_threat_domain_policy_snapshot(
                &mut trusted,
                &metadata_json,
                feed,
                1_788_480_001_000,
            )
            .map_err(std::io::Error::other)?;

        assert_eq!(audit.rule_count, 1);
        assert!(matches!(
            pool.browser_hardening_policy
                .check_url("https://malware.test/payload"),
            Err(BrowserHardeningBlocked {
                code: BrowserHardeningBlockCode::ThreatListedDomain,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn signed_threat_domain_production_fixture_applies_exact_and_suffix_rules() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n*.phishing.test\n";
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );
        let mut pool = SessionPool::default().with_browser_hardening_policy(
            BrowserHardeningPolicy::standard().with_url_policy(UrlPolicy::allow_all()),
        );

        let audit = pool
            .apply_verified_signed_threat_domain_policy_snapshot(
                &mut trusted,
                &metadata_json,
                feed,
                1_788_480_001_000,
            )
            .map_err(std::io::Error::other)?;

        assert_eq!(audit.rule_count, 2);
        assert_eq!(audit.exact_rules, 1);
        assert_eq!(audit.suffix_rules, 1);
        assert!(matches!(
            pool.browser_hardening_policy
                .check_url("https://malware.test/payload"),
            Err(BrowserHardeningBlocked {
                code: BrowserHardeningBlockCode::ThreatListedDomain,
                ..
            })
        ));
        assert!(matches!(
            pool.browser_hardening_policy
                .check_url("https://login.phishing.test/"),
            Err(BrowserHardeningBlocked {
                code: BrowserHardeningBlockCode::ThreatListedDomain,
                ..
            })
        ));
        assert!(pool
            .browser_hardening_policy
            .check_url("https://example.com/")
            .is_ok());
        Ok(())
    }

    #[test]
    fn signed_threat_domain_policy_snapshot_failure_preserves_existing_policy() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[15_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );
        let mut pool = SessionPool::default().with_browser_hardening_policy(
            BrowserHardeningPolicy::standard().with_url_policy(UrlPolicy::allow_all()),
        );

        let error = expect_test_err(
            pool.apply_verified_signed_threat_domain_policy_snapshot(
                &mut trusted,
                &metadata_json,
                "different.test\n",
                1_788_480_001_000,
            ),
            "tampered feed must not swap policy",
        );

        assert!(error.contains("digest"));
        assert!(pool
            .browser_hardening_policy
            .check_url("https://malware.test/payload")
            .is_ok());
        Ok(())
    }

    #[test]
    fn signed_threat_domain_refresh_rejects_cleartext_metadata_without_policy_swap() {
        let mut pool = SessionPool::default().with_browser_hardening_policy(
            BrowserHardeningPolicy::standard().with_url_policy(UrlPolicy::allow_all()),
        );
        let mut trusted = BTreeMap::new();

        let error = expect_test_err(
            pool.refresh_signed_threat_domain_policy_once(
                &mut trusted,
                "http://example.test/metadata.json",
                "https://example.test/feed.txt",
                None,
                None,
                1_788_480_001_000,
            ),
            "cleartext signed metadata URL must be rejected before network",
        );

        assert!(error.contains("must use https"));
        assert!(pool
            .browser_hardening_policy
            .check_url("https://example.com/")
            .is_ok());
    }

    #[test]
    fn signed_threat_domain_public_key_env_parses_trust_roots() -> TestResult {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[16_u8; 32]);
        let encoded = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
        let keys = parse_signed_threat_domain_public_keys_env(Some(std::ffi::OsString::from(
            format!("root-2026={encoded}"),
        )))
        .map_err(std::io::Error::other)?;

        assert_eq!(keys.get("root-2026"), Some(&encoded));
        Ok(())
    }

    #[test]
    fn signed_threat_domain_refresh_interval_enforces_minimum() {
        assert_eq!(
            parse_signed_threat_domain_refresh_interval_env(Some(std::ffi::OsString::from("59"))),
            TEMPO_THREAT_DOMAIN_DEFAULT_REFRESH_INTERVAL
        );
        assert_eq!(
            parse_signed_threat_domain_refresh_interval_env(Some(std::ffi::OsString::from("60"))),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn signed_threat_domain_cache_round_trips_verified_snapshot() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let root = unique_dir("signed-threat-cache")?;
        std::fs::create_dir_all(&root)?;
        let metadata_path = root.join("feed.metadata.json");
        let feed_path = root.join("feed.txt");
        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        write_signed_threat_domain_cache(&metadata_path, &feed_path, &metadata_json, feed)
            .map_err(std::io::Error::other)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id.clone(),
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );

        let (cached_feed, verified) = read_signed_threat_domain_cache(
            &metadata_path,
            &feed_path,
            &trusted,
            1_788_480_001_000,
        )
        .map_err(std::io::Error::other)?;

        assert_eq!(cached_feed, feed);
        assert_eq!(verified.key_id, key_id);
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn signed_threat_domain_cache_rejects_tampered_feed() -> TestResult {
        use ed25519_dalek::{Signer, SigningKey};

        let root = unique_dir("signed-threat-cache-tamper")?;
        std::fs::create_dir_all(&root)?;
        let metadata_path = root.join("feed.metadata.json");
        let feed_path = root.join("feed.txt");
        let feed = "malware.test\n";
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let key_id = "root-2026".to_string();
        let mut metadata = ThreatDomainSignedMetadata {
            version: "2026-07-05T00:00:00Z".into(),
            issued_at_ms: 1_788_480_000_000,
            expires_at_ms: 1_791_072_000_000,
            feed_sha256: sha256_hex(feed.as_bytes()),
            key_id: key_id.clone(),
            signature: String::new(),
            next_key_id: None,
            next_public_key: None,
        };
        let payload =
            threat_domain_metadata_signing_payload(&metadata).map_err(std::io::Error::other)?;
        metadata.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let metadata_json = serde_json::to_string(&metadata)?;
        write_signed_threat_domain_cache(
            &metadata_path,
            &feed_path,
            &metadata_json,
            "different.test\n",
        )
        .map_err(std::io::Error::other)?;
        let mut trusted = BTreeMap::new();
        trusted.insert(
            key_id,
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        );

        let error = expect_test_err(
            read_signed_threat_domain_cache(
                &metadata_path,
                &feed_path,
                &trusted,
                1_788_480_001_000,
            ),
            "tampered cached feed must be rejected",
        );

        assert!(error.contains("digest"));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn threat_domain_cache_round_trips_owner_only_snapshot() -> TestResult {
        let root = unique_dir("threat-cache")?;
        std::fs::create_dir_all(&root)?;
        let path = root.join("feed.cache");
        let contents = "malware.test\n";
        let digest = sha256_hex(contents.as_bytes());

        write_threat_domain_cache(&path, contents).map_err(std::io::Error::other)?;
        let cached =
            read_threat_domain_cache(&path, Some(&digest), std::time::Duration::from_secs(60))
                .map_err(std::io::Error::other)?;

        assert_eq!(cached, contents);
        remove_dir_if_exists(&root)?;
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
        assert!(matches!(
            pool.resume(&running.id),
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
    fn http_resume_session_records_event_and_rejects_terminal_sessions() -> TestResult {
        let mut pool = SessionPool::default();
        let created = pool.create("https://resume.test")?;
        pool.adopt(&created.id)?;

        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions/session-0/resume".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        )?;
        assert_eq!(response.status, 200);
        let resumed: TempodSession = serde_json::from_slice(&response.body)?;
        assert_eq!(resumed.state, TempodSessionState::Running);

        let events = pool.events(&created.id, None)?;
        assert_eq!(
            events.last().map(|event| event.event.clone()),
            Some(TempodSessionEventKind::SessionResumed)
        );

        pool.kill(&created.id)?;
        let adopt_terminal = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions/session-0/adopt".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );
        assert_eq!(adopt_terminal.status, 409);
        let terminal = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions/session-0/resume".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );
        assert_eq!(terminal.status, 409);
        Ok(())
    }

    #[test]
    fn http_resume_session_requires_adopted_state() -> TestResult {
        let mut pool = SessionPool::default();
        let created = pool.create("https://resume-state.test")?;

        let running = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions/session-0/resume".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );
        assert_eq!(running.status, 409);
        assert_eq!(pool.events(&created.id, None)?.len(), 1);

        pool.adopt(&created.id)?;
        pool.resume(&created.id)?;
        let repeated = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions/session-0/resume".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: Vec::new(),
            },
        );
        assert_eq!(repeated.status, 409);
        let events = pool.events(&created.id, None)?;
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event == TempodSessionEventKind::SessionResumed)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn http_create_and_list_sessions_over_tcp() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one_unsafe(listener, server_pool));

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
        let handle = thread::spawn(move || serve_one_unsafe(listener, server_pool));

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
    fn health_stays_live_while_ready_reports_detached_and_draining() -> TestResult {
        let mut pool = SessionPool::default();

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

        let ready = handle_http_request(&mut pool, control_request("GET", "/ready", None, b""));
        assert_eq!(ready.status, 503);
        let value: Value = serde_json::from_slice(&ready.body)?;
        assert_eq!(value["ready"], false);
        assert_eq!(value["engine_attached"], false);
        assert!(json_array_contains(&value["reasons"], "engine_detached"));

        pool.drain();
        let draining_ready =
            handle_http_request(&mut pool, control_request("GET", "/ready", None, b""));
        assert_eq!(draining_ready.status, 503);
        let value: Value = serde_json::from_slice(&draining_ready.body)?;
        assert_eq!(value["draining"], true);
        assert!(json_array_contains(&value["reasons"], "draining"));
        Ok(())
    }

    #[test]
    fn http_create_session_returns_429_at_session_cap() -> TestResult {
        let mut pool = SessionPool::default().with_max_sessions(1);

        let created = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://first.test"}"#.to_vec(),
            },
        );
        assert_eq!(created.status, 201);

        let rejected = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: br#"{"url":"https://second.test"}"#.to_vec(),
            },
        );
        assert_eq!(rejected.status, 429);
        let value: Value = serde_json::from_slice(&rejected.body)?;
        assert_eq!(
            value["error"],
            "session limit reached: max 1 retained sessions"
        );

        let ready = handle_http_request(&mut pool, control_request("GET", "/ready", None, b""));
        assert_eq!(ready.status, 503);
        let value: Value = serde_json::from_slice(&ready.body)?;
        assert_eq!(value["sessions"], 1);
        assert_eq!(value["max_sessions"], 1);
        assert!(json_array_contains(
            &value["reasons"],
            "session_limit_reached"
        ));
        Ok(())
    }

    #[test]
    fn ready_endpoint_is_origin_and_host_guarded() -> TestResult {
        let mut pool = SessionPool::default();
        let blocked_origin = handle_http_request(
            &mut pool,
            control_request("GET", "/ready", Some("http://evil.example"), b""),
        );
        assert_eq!(blocked_origin.status, 403);

        let blocked_host = handle_http_request(
            &mut pool,
            with_host(
                control_request("GET", "/ready", None, b""),
                "attacker.example:8787",
            ),
        );
        assert_eq!(blocked_host.status, 403);
        Ok(())
    }

    #[test]
    fn tempod_serves_agent_card_over_well_known_http() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one_unsafe(listener, pool));

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
        assert_eq!(card["url"], "http://localhost/mcp");
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
    fn tempod_serves_web_bot_auth_key_directory() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: WEB_BOT_AUTH_KEY_DIRECTORY_PATH.into(),
                headers: BTreeMap::new(),
                host: Some("localhost:8787".into()),
                origin: None,
                body: Vec::new(),
            },
        )?;

        assert_eq!(response.status, 200);
        assert_eq!(
            response.content_type,
            WEB_BOT_AUTH_KEY_DIRECTORY_CONTENT_TYPE
        );
        let directory: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            directory["keys"]
                .as_array()
                .ok_or("key directory must expose keys array")?
                .len(),
            0
        );
        Ok(())
    }

    #[test]
    fn tempod_key_directory_serves_configured_web_bot_auth_verifier() -> TestResult {
        use tempo_net::WebBotAuthSigningKey;
        use tower::ServiceExt as _;

        let runtime = transport_runtime()?;
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7_u8; 32])?;
        let router = tempod_router(TempodAppState {
            pool: Arc::new(Mutex::new(SessionPool::default())),
            auth: TempodAuth::disabled(),
            host_guard: TempodHostGuard::loopback(),
            limiter: ConnectionLimiter::default(),
            web_bot_auth_verifiers: vec![key.verifier()],
        });
        let response = runtime.block_on(async move {
            router
                .oneshot(
                    axum::http::Request::builder()
                        .method("GET")
                        .uri(WEB_BOT_AUTH_KEY_DIRECTORY_PATH)
                        .header("host", "127.0.0.1:8787")
                        .body(axum::body::Body::empty())
                        .map_err(|error| TempodError::Driver(error.to_string()))?,
                )
                .await
                .map_err(|error| TempodError::Driver(error.to_string()))
        })?;

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .ok_or("missing content-type")?;
        assert_eq!(content_type, WEB_BOT_AUTH_KEY_DIRECTORY_CONTENT_TYPE);
        let body = runtime
            .block_on(
                async move { axum::body::to_bytes(response.into_body(), MAX_HTTP_BYTES).await },
            )
            .map_err(|error| TempodError::Driver(error.to_string()))?;
        let directory: Value = serde_json::from_slice(&body)?;
        let keys = directory["keys"]
            .as_array()
            .ok_or("key directory must expose keys array")?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "tempo-agent");
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
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
    fn openapi_falls_back_when_host_header_is_not_loopback() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: TEMPOD_OPENAPI_PATH.into(),
                headers: BTreeMap::new(),
                host: Some("attacker.example:8787".into()),
                origin: None,
                body: Vec::new(),
            },
        )?;

        assert_eq!(response.status, 200);
        let openapi: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(openapi["servers"][0]["url"], "http://localhost");
        assert_eq!(openapi["paths"]["/ready"]["get"]["operationId"], "ready");
        Ok(())
    }

    #[test]
    fn openapi_advertises_readiness_and_session_admission_limit() {
        let openapi = tempod_openapi("http://localhost");

        assert_eq!(openapi["paths"]["/ready"]["get"]["operationId"], "ready");
        assert_eq!(
            openapi["components"]["securitySchemes"]["TempodBearer"]["scheme"],
            "bearer"
        );
        assert_eq!(
            openapi["paths"]["/ready"]["get"]["security"],
            json!([{"TempodBearer": []}])
        );
        assert_eq!(
            openapi["paths"]["/sessions"]["post"]["security"],
            json!([{"TempodBearer": []}])
        );
        assert_eq!(
            openapi["paths"]["/sessions/{session_id}/resume"]["post"]["operationId"],
            "resumeSession"
        );
        assert_eq!(
            openapi["paths"]["/mcp"]["post"]["security"],
            json!([{"TempodBearer": []}])
        );
        assert_eq!(
            openapi["paths"]["/ready"]["get"]["responses"]["503"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ReadinessResponse"
        );
        assert_eq!(
            openapi["paths"]["/sessions"]["post"]["responses"]["429"]["description"],
            "Session admission limit reached"
        );
        assert_eq!(
            openapi["paths"]["/sessions"]["post"]["responses"]["403"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/BrowserHardeningError"
        );
        assert_eq!(
            openapi["components"]["schemas"]["BrowserHardeningError"]["required"],
            json!(["error", "browser_hardening"])
        );
        assert_eq!(
            openapi["components"]["schemas"]["TempodBrowserHardeningBlock"]["properties"]["code"]
                ["enum"][8],
            "insecure_top_level_navigation"
        );
        assert_eq!(
            openapi["components"]["schemas"]["ReadinessResponse"]["properties"]["reasons"]["items"]
                ["enum"],
            json!(["draining", "engine_detached", "session_limit_reached"])
        );
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
        let handle = thread::spawn(move || serve_one_unsafe(listener, pool));
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
            move || serve_one_unsafe(listener, pool)
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
    fn bidi_navigation_identity_follows_recorded_strategy() -> TestResult {
        let mut pool = SessionPool::default();
        let url = "https://challenged.example/path";

        assert_eq!(
            network_navigation_identity_mode(&pool, url),
            tempo_net::IdentityMode::AgentDeclared
        );
        pool.identity_strategy_table
            .record_request(url, true)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            network_navigation_identity_mode(&pool, url),
            tempo_net::IdentityMode::UserDriven
        );
        assert_eq!(
            network_navigation_identity_mode(&pool, "not a url"),
            tempo_net::IdentityMode::AgentDeclared
        );
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
        // A clean-claimed navigate first fetches policy taint evidence
        // (Observe), then executes the Goto (#254).
        let handle = attach_driver_handler_seq(&mut pool, 2, |request| match request.command {
            HostDriverCommand::Observe => DriverResponse::Observation {
                observation: observation("about:blank", 0),
            },
            HostDriverCommand::Goto { url } => {
                assert_eq!(url, "https://example.test");
                DriverResponse::Observation {
                    observation: observation("https://example.test", 1),
                }
            }
            _ => DriverResponse::Closed,
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
    fn bidi_endpoint_denies_confirmed_tainted_navigation_without_confirmation_channel() -> TestResult
    {
        // Pre-#254 a bare confirmed=true from the same caller bypassed the
        // gate. It is now advisory: with no server-attributable confirmation
        // channel the tainted navigation stays blocked, without engine IPC.
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
                body: br#"{"id":17,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://example.test","inputTainted":true,"confirmed":true}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 17);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("policy denied"));
        assert!(message.contains("confirmed=true was ignored"));
        assert_no_driver_ipc(&mut server_stream)?;
        Ok(())
    }

    #[test]
    fn bidi_navigate_recomputes_taint_from_observation_and_blocks_clean_claim() -> TestResult {
        let mut pool = SessionPool::default();
        // The engine serves exactly ONE request: the policy-evidence Observe.
        // Its observation carries a page-provenance span embedded in the
        // navigation URL with different casing, so recomputation blocks the
        // Goto even though the caller claimed inputTainted=false and
        // confirmed=true. This fails if server-side recomputation is removed
        // or case-sensitive.
        let handle = attach_driver_handler(&mut pool, |request| {
            assert_eq!(request.command, HostDriverCommand::Observe);
            DriverResponse::Observation {
                observation: tainted_observation("https://current.test", 1, "Evil.Example/Exfil"),
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
                body: br#"{"id":26,"method":"browsingContext.navigate","params":{"context":"tempo-root","url":"https://evil.example/exfil?otp=123456","inputTainted":false,"confirmed":true}}"#.to_vec(),
            },
        )?;
        join_driver_handler(handle)?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 26);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("policy denied"));
        assert!(message.contains("input_tainted=true"));
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
    fn bidi_endpoint_denies_client_claimed_clean_script_without_confirmation_channel() -> TestResult
    {
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
                body: br#"{"id":8,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"tempo-root"},"awaitPromise":true,"inputTainted":false}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 8);
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
    fn bidi_endpoint_denies_confirmed_tainted_script_without_confirmation_channel() -> TestResult {
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
                body: br#"{"id":20,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"tempo-root"},"awaitPromise":true,"inputTainted":true,"confirmed":true}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 20);
        assert_eq!(value["error"], "invalid argument");
        let message = value["message"]
            .as_str()
            .ok_or("BiDi error response should include a message")?;
        assert!(message.contains("policy denied"));
        assert!(message.contains("confirmed=true was ignored"));
        assert_no_driver_ipc(&mut server_stream)?;
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
                    omitted: 0,
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
                        omitted: 0,
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
                    omitted: 0,
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
                    omitted: 0,
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
                    omitted: 0,
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

    // ---- Issue #249: real OTLP/HTTP export to a collector ----

    /// Minimal OTLP collector fixture: accepts one connection, captures the
    /// HTTP request (head + body), answers 200 `{}`.
    #[allow(clippy::type_complexity)]
    fn spawn_otlp_collector_fixture() -> Result<
        (
            std::net::SocketAddr,
            thread::JoinHandle<Result<(String, Vec<u8>), String>>,
        ),
        Box<dyn Error>,
    > {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(String, Vec<u8>), String> {
            let (mut stream, _addr) = listener.accept().map_err(|error| error.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|error| error.to_string())?;
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            let (body_start, content_length) = loop {
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Err("collector connection closed before headers".into());
                }
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(end) = header_end(&bytes) {
                    let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.trim().eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .ok_or("collector request missing content-length")?;
                    break (end + 4, content_length);
                }
            };
            while bytes.len() < body_start + content_length {
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Err("collector connection closed mid-body".into());
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                .map_err(|error| error.to_string())?;
            let head = String::from_utf8_lossy(&bytes[..body_start]).to_string();
            let body = bytes[body_start..body_start + content_length].to_vec();
            Ok((head, body))
        });
        Ok((addr, handle))
    }

    #[test]
    fn otlp_http_export_posts_redacted_spans_to_collector() -> TestResult {
        let (addr, collector) = spawn_otlp_collector_fixture()?;
        let exporter = OtlpHttpExporter::new(format!("http://{addr}"))?;
        assert!(exporter.endpoint().ends_with("/v1/traces"));

        let mut pool = SessionPool::default().with_otlp_http_exporter(exporter);
        let session = pool.create("https://otlp.test")?;
        let secret = "hunter2-super-secret-password";
        let triple = StepTriple {
            key: IdempotencyKey("step-otlp".into()),
            seq: 9,
            action: Action::Type {
                node: NodeId("a[href=\"/reset?token=SECRET123\"]".into()),
                text: secret.into(),
            },
            outcome: StepTripleOutcome::StepError {
                reason: "failed with token SECRET123".into(),
            },
        };
        pool.record_step(&session.id, triple)?;

        let (head, body) = collector
            .join()
            .map_err(|_| "collector fixture panicked")??;
        let request_line = head.lines().next().unwrap_or_default();
        assert!(
            request_line.starts_with("POST /v1/traces HTTP/1.1"),
            "collector saw: {request_line}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "collector head: {head}"
        );

        // #216 guarantee: redaction happened BEFORE export — no secret crosses
        // the wire in any encoding position.
        let text = String::from_utf8(body.clone())?;
        assert!(
            !text.contains(secret),
            "typed secret must be redacted before export"
        );
        assert!(
            !text.contains("SECRET123"),
            "node-id/step-error secrets must be redacted before export"
        );

        let value: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            value["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "tempod"
        );
        let span = &value["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "tempo.step");
        assert_eq!(span["status"]["code"], 2);
        let trace_id = span["traceId"].as_str().ok_or("missing traceId")?;
        let span_id = span["spanId"].as_str().ok_or("missing spanId")?;
        assert_eq!(trace_id.len(), 32);
        assert_eq!(span_id.len(), 16);
        assert_ne!(trace_id, "00000000000000000000000000000000");
        assert_ne!(span_id, "0000000000000000");
        let attributes = span["attributes"].as_array().ok_or("missing attributes")?;
        let seq = attributes
            .iter()
            .find(|attribute| attribute["key"] == "tempo.step.seq")
            .ok_or("missing tempo.step.seq attribute")?;
        assert_eq!(seq["value"]["intValue"], "9");
        Ok(())
    }

    #[test]
    fn otlp_http_export_never_blocks_step_recording_when_collector_is_down() -> TestResult {
        // Reserve a port with no listener behind it.
        let dead = TcpListener::bind("127.0.0.1:0")?;
        let addr = dead.local_addr()?;
        drop(dead);

        let exporter = OtlpHttpExporter::new(format!("http://{addr}"))?;
        let mut pool = SessionPool::default().with_otlp_http_exporter(exporter);
        let session = pool.create("https://otlp-down.test")?;

        let started = Instant::now();
        for seq in 0..(OTLP_EXPORT_QUEUE_CAPACITY as u64 + 64) {
            // Best-effort (#216): recording steps must keep succeeding, fast,
            // even when every span is dropped because the collector is gone —
            // more steps than the queue holds, so the full-queue path runs too.
            pool.record_step(&session.id, sample_step_triple(seq))?;
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "record_step must not block on collector I/O: {elapsed:?}"
        );
        Ok(())
    }

    #[test]
    fn otlp_endpoint_normalization_and_env_wiring() -> TestResult {
        assert_eq!(
            normalize_otlp_endpoint("http://collector.internal:4318")?,
            "http://collector.internal:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector.internal:4318/")?,
            "http://collector.internal:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("https://collector.internal:4318/v1/traces")?,
            "https://collector.internal:4318/v1/traces"
        );
        assert!(normalize_otlp_endpoint("ftp://collector.internal").is_err());
        assert!(normalize_otlp_endpoint("not a url").is_err());

        let pool = SessionPool::from_otlp_env_values(
            None,
            Some(std::ffi::OsString::from("http://127.0.0.1:4318")),
        );
        assert_eq!(
            pool.otlp_http_exporter()
                .ok_or("expected endpoint env to configure the exporter")?
                .endpoint(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert!(pool.otlp_exporter().is_none());

        // Telemetry is best-effort: a bad endpoint is ignored, not fatal.
        let ignored =
            SessionPool::from_otlp_env_values(None, Some(std::ffi::OsString::from("not a url")));
        assert!(ignored.otlp_http_exporter().is_none());
        Ok(())
    }

    // ---- Issue #249: axum transport regressions ----

    #[test]
    fn chunked_transfer_encoding_create_session_is_decoded() -> TestResult {
        // The hand-rolled parser only understood Content-Length and silently
        // treated a chunked body as empty, so a standard HTTP/1.1 client using
        // Transfer-Encoding: chunked got a bogus error. hyper decodes it.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one_unsafe(listener, server_pool));

        let body = r#"{"url":"https://chunked.test"}"#;
        let request = format!(
            "POST /sessions HTTP/1.1\r\nhost: 127.0.0.1\r\ntransfer-encoding: chunked\r\n\r\n{len:x}\r\n{body}\r\n0\r\n\r\n",
            len = body.len(),
        );
        let response = send_http(addr, &request)?;
        join_server(handle)?;
        assert!(response.starts_with("HTTP/1.1 201"), "{response}");
        let sessions = pool.lock().map_err(|_| "pool poisoned")?.list();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].url, "https://chunked.test");
        Ok(())
    }

    #[test]
    fn oversized_body_is_rejected_with_413() -> TestResult {
        // Replaces the old content_length() parser unit test: the transport
        // still refuses bodies beyond MAX_HTTP_BYTES, now with the standard
        // 413 (the hand-rolled parser answered 400).
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one_unsafe(listener, pool));

        let oversized = "x".repeat(MAX_HTTP_BYTES + 1);
        let response = send_http(
            addr,
            &format!(
                "POST /sessions HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n\r\n{oversized}",
                oversized.len(),
            ),
        )?;
        join_server(handle)?;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        Ok(())
    }

    #[test]
    fn malformed_json_create_session_is_rejected_as_bad_request() -> TestResult {
        let mut pool = SessionPool::default();
        let response = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/sessions".into(),
                headers: BTreeMap::new(),
                host: None,
                origin: None,
                body: b"{not json".to_vec(),
            },
        );
        // Standard client error; the hand-rolled parser surfaced this as 500.
        assert_eq!(response.status, 400, "{response:?}");
        assert!(pool.list().is_empty());
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

    // ---- Issue #398: engine restart + re-attach with backoff ----

    #[test]
    fn engine_reconnect_backoff_grows_and_caps() {
        let policy = EngineReconnectPolicy {
            poll_interval: Duration::from_millis(1),
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(800),
            max_attempts: Some(5),
            stable_window: Duration::from_secs(10),
        };
        assert_eq!(
            engine_reconnect_backoff(&policy, 0),
            Duration::from_millis(100)
        );
        assert_eq!(
            engine_reconnect_backoff(&policy, 1),
            Duration::from_millis(200)
        );
        assert_eq!(
            engine_reconnect_backoff(&policy, 2),
            Duration::from_millis(400)
        );
        assert_eq!(
            engine_reconnect_backoff(&policy, 3),
            Duration::from_millis(800)
        );
        // Capped at max_backoff, and a large attempt count cannot overflow.
        assert_eq!(
            engine_reconnect_backoff(&policy, 4),
            Duration::from_millis(800)
        );
        assert_eq!(
            engine_reconnect_backoff(&policy, 100),
            Duration::from_millis(800)
        );
    }

    #[test]
    fn jittered_backoff_stays_within_half_and_caps_at_max() {
        let base = Duration::from_millis(200);
        let max = Duration::from_secs(30);
        for seed in [0_u128, 1, 99, 12_345, u128::MAX / 3] {
            let jittered = jittered_backoff(base, max, seed);
            assert!(jittered >= base, "jitter dipped below base: {jittered:?}");
            assert!(
                jittered < base + base / 2,
                "jitter exceeded half the backoff: {jittered:?}"
            );
        }
        // A backoff already above max is clamped regardless of jitter.
        assert_eq!(
            jittered_backoff(Duration::from_secs(40), Duration::from_secs(30), 7),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn reconnect_controller_backs_off_then_gives_up_at_budget() {
        let policy = EngineReconnectPolicy {
            poll_interval: Duration::from_millis(1),
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            max_attempts: Some(3),
            stable_window: Duration::from_secs(60),
        };
        let now = Instant::now();
        let mut controller = ReconnectController::new(policy, now);

        // Live driver: no action.
        assert_eq!(controller.on_sample(false, now), ReconnectAction::Idle);

        // Each failed reconnect grows the backoff.
        assert_eq!(
            controller.on_sample(true, now),
            ReconnectAction::Reconnect {
                backoff: Duration::from_millis(100)
            }
        );
        controller.record_failure();
        assert_eq!(
            controller.on_sample(true, now),
            ReconnectAction::Reconnect {
                backoff: Duration::from_millis(200)
            }
        );
        controller.record_failure();
        assert_eq!(
            controller.on_sample(true, now),
            ReconnectAction::Reconnect {
                backoff: Duration::from_millis(400)
            }
        );
        controller.record_failure();
        // Budget (3) exhausted: give up rather than hot-spin forever.
        assert_eq!(controller.on_sample(true, now), ReconnectAction::GiveUp);
    }

    #[test]
    fn reconnect_controller_resets_after_stable_window() {
        let policy = EngineReconnectPolicy {
            poll_interval: Duration::from_millis(1),
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            max_attempts: Some(3),
            stable_window: Duration::from_secs(60),
        };
        let start = Instant::now();
        let mut controller = ReconnectController::new(policy, start);

        // Two restarts accrue churn.
        controller.record_reconnect(start);
        controller.record_reconnect(start);
        assert_eq!(controller.attempts, 2);

        // Brief liveness (< stable_window) does not forgive the churn.
        let soon = start + Duration::from_secs(1);
        assert_eq!(controller.on_sample(false, soon), ReconnectAction::Idle);
        assert_eq!(controller.attempts, 2);

        // A full stable window of continuous liveness resets the counter.
        let stable = start + Duration::from_secs(61);
        assert_eq!(controller.on_sample(false, stable), ReconnectAction::Idle);
        assert_eq!(controller.attempts, 0);

        // A later death backs off from base again, not from the forgiven count.
        assert_eq!(
            controller.on_sample(true, stable),
            ReconnectAction::Reconnect {
                backoff: Duration::from_millis(100)
            }
        );
    }

    /// End-to-end recovery: a simulated engine-child death marks the driver dead
    /// (so readiness reports it), and a reconnect + re-attach swaps in a live
    /// driver so operations succeed again instead of returning `IpcClosed`
    /// forever (#398).
    #[test]
    fn engine_liveness_reconnect_recovers_after_engine_death() -> TestResult {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("tempo-398-{}", current_time_ns()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("engine.sock");

        let server_path = path.clone();
        let engine = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let listener = UnixListener::bind(&server_path)?;
            // Connection 1: answer exactly one Observe, then drop the socket
            // (the engine child "dies").
            let (stream, _) = listener.accept()?;
            {
                let mut conn = EngineIpcConnection::from_stream(stream);
                let request = conn.read_driver_request()?;
                conn.write_driver_response(
                    request.id,
                    DriverResponse::Observation {
                        observation: observation("https://before.test", 1),
                    },
                )?;
            }
            // Connection 2 (the reconnect): answer one Observe and stay up.
            let (stream, _) = listener.accept()?;
            let mut conn = EngineIpcConnection::from_stream(stream);
            let request = conn.read_driver_request()?;
            conn.write_driver_response(
                request.id,
                DriverResponse::Observation {
                    observation: observation("https://after.test", 2),
                },
            )?;
            Ok(())
        });

        // Wait for the listener to bind, then attach.
        let mut client = None;
        for _ in 0..500 {
            match connect_engine_ipc(&path) {
                Ok(connected) => {
                    client = Some(connected);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let client = client.ok_or("engine socket never became connectable")?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        lock_pool(&pool)?.attach_engine_driver(Engine::Cdp, client)?;

        // Pre-death op succeeds on connection 1.
        let driver = lock_pool(&pool)?
            .driver
            .clone()
            .ok_or("driver missing after attach")?;
        assert!(matches!(
            driver.request(HostDriverCommand::Observe)?,
            DriverResponse::Observation { .. }
        ));

        // The engine dropped connection 1: the driver's reader marks it dead.
        let mut dead = false;
        for _ in 0..500 {
            if lock_pool(&pool)?.engine_driver_dead() {
                dead = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(dead, "driver never observed the engine death");
        assert!(!lock_pool(&pool)?.engine_live());
        // The stale driver clone fast-fails (in-flight sessions see IpcClosed
        // until the pool re-attaches a fresh driver).
        assert!(driver.request(HostDriverCommand::Observe).is_err());

        // Reconnect + re-attach installs a live driver.
        reconnect_engine(&pool, Engine::Cdp, &path)?;
        assert!(lock_pool(&pool)?.engine_live());
        assert!(!lock_pool(&pool)?.engine_driver_dead());

        // A fresh op resolves the live driver and succeeds on connection 2 —
        // recovered, not IpcClosed forever.
        let driver = lock_pool(&pool)?
            .driver
            .clone()
            .ok_or("driver missing after reconnect")?;
        assert!(matches!(
            driver.request(HostDriverCommand::Observe)?,
            DriverResponse::Observation { .. }
        ));

        engine
            .join()
            .map_err(|_| "engine thread panicked")?
            .map_err(|error| error.to_string())?;
        let _ = std::fs::remove_dir_all(&dir);
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
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one_unsafe(listener, pool));

        let response = send_http(
            addr,
            "GET /bidi HTTP/1.1\r\n\
             host: 127.0.0.1\r\n\
             origin: http://evil.example\r\n\
             upgrade: websocket\r\n\
             connection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             sec-websocket-version: 13\r\n\r\n",
        )?;
        join_server(handle)?;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "cross-origin WebSocket upgrade must be rejected: {response}"
        );
        Ok(())
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

    fn with_host(mut request: HttpRequest, host: &str) -> HttpRequest {
        request.host = Some(host.to_string());
        request
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
    fn metrics_endpoint_exposes_prometheus_counters() -> TestResult {
        let mut pool = SessionPool::default();
        // Drive requests through the funnel so counters and histograms move.
        let health = handle_http_request(&mut pool, control_request("GET", "/health", None, b""));
        assert_eq!(health.status, 200);
        let created = handle_http_request(
            &mut pool,
            control_request(
                "POST",
                "/sessions",
                None,
                br#"{"url":"https://example.test"}"#,
            ),
        );
        assert_eq!(created.status, 201);

        let metrics = handle_http_request(
            &mut pool,
            control_request("GET", TEMPOD_METRICS_PATH, None, b""),
        );
        assert_eq!(metrics.status, 200);
        assert_eq!(
            metrics.content_type,
            tempo_telemetry::PROMETHEUS_CONTENT_TYPE
        );
        let text = String::from_utf8(metrics.body.clone())?;
        assert!(text.contains("tempod_http_requests_total{route=\"health\",status=\"2xx\"}"));
        assert!(text.contains("tempod_sessions_created_total"));
        // Presence only: the registry is process-global, so exact gauge
        // values would race any concurrently-running test that scrapes.
        assert!(text.contains("tempod_sessions_active"));
        assert!(text.contains("tempod_build_info{version="));
        assert!(text.contains("tempod_uptime_seconds"));
        assert!(text.contains("tempod_http_request_seconds_bucket"));
        assert!(text.contains("tempod_draining"));

        // Config toggle: disabled means 404 (route present, exposition off).
        // Same test so the global flag never races the scrape above.
        set_metrics_enabled(false);
        let disabled = handle_http_request(
            &mut pool,
            control_request("GET", TEMPOD_METRICS_PATH, None, b""),
        );
        set_metrics_enabled(true);
        assert_eq!(disabled.status, 404);
        Ok(())
    }

    #[test]
    fn metrics_endpoint_is_origin_guarded() -> TestResult {
        // The exposition is control-plane data: a DNS-rebinding page must not
        // be able to read operational state cross-origin. Scrapers and CLI
        // clients send no Origin header, so they pass the guard.
        let mut pool = SessionPool::default();
        let blocked = handle_http_request(
            &mut pool,
            control_request("GET", TEMPOD_METRICS_PATH, Some("http://evil.example"), b""),
        );
        assert_eq!(blocked.status, 403);
        Ok(())
    }

    #[test]
    fn metrics_endpoint_rejects_non_loopback_host_without_origin() -> TestResult {
        let mut pool = SessionPool::default();
        let blocked = handle_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: TEMPOD_METRICS_PATH.into(),
                headers: BTreeMap::new(),
                host: Some("attacker.example:8787".into()),
                origin: None,
                body: Vec::new(),
            },
        );

        assert_eq!(blocked.status, 403);
        let body: Value = serde_json::from_slice(&blocked.body)?;
        assert_eq!(body["error"], "forbidden: host not allowed");
        Ok(())
    }

    #[test]
    fn metrics_route_class_bounds_label_cardinality() {
        assert_eq!(metrics_route_class("GET", "/health"), "health");
        assert_eq!(metrics_route_class("GET", "/ready"), "ready");
        assert_eq!(metrics_route_class("GET", "/metrics"), "metrics");
        assert_eq!(metrics_route_class("POST", "/sessions"), "sessions");
        assert_eq!(
            metrics_route_class("POST", "/sessions/abc123/act_batch"),
            "session"
        );
        assert_eq!(
            metrics_route_class("POST", "/sessions/abc123/resume"),
            "session"
        );
        assert_eq!(metrics_route_class("DELETE", "/sessions/abc123"), "session");
        assert_eq!(metrics_route_class("POST", "/mcp"), "mcp");
        assert_eq!(metrics_route_class("GET", "/favicon.ico"), "other");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_auth_token_file_is_owner_only_and_reused() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("runtime-auth")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("tempod.token");

        let created = load_or_create_tempod_runtime_auth_token_at(&path)?;
        let loaded = load_or_create_tempod_runtime_auth_token_at(&path)?;

        assert_eq!(created, loaded);
        assert!(created.token.len() >= 40);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&root)?.permissions().mode() & 0o777,
            0o700
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn runtime_auth_token_rejects_world_readable_file() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("runtime-auth-loose")?;
        remove_dir_if_exists(&root)?;
        std::fs::create_dir_all(&root)?;
        let path = root.join("tempod.token");
        std::fs::write(&path, "loose-token\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

        assert!(matches!(
            load_tempod_runtime_auth_token_at(&path),
            Err(TempodError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
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

    #[test]
    fn control_routes_reject_untrusted_host_without_origin() -> TestResult {
        // #375: after DNS rebinding, browser fetches can be same-origin and
        // omit Origin, but the Host header remains attacker-controlled.
        let create_body = br#"{"url":"https://example.test"}"#;
        let mut pool = SessionPool::default();
        let blocked = handle_http_request(
            &mut pool,
            with_host(
                control_request("POST", "/sessions", None, create_body),
                "evil.example",
            ),
        );
        assert_eq!(blocked.status, 403);
        assert!(
            pool.list().is_empty(),
            "untrusted Host request must not create a session"
        );

        let blocked_metrics = handle_http_request(
            &mut pool,
            with_host(
                control_request("GET", TEMPOD_METRICS_PATH, None, b""),
                "evil.example",
            ),
        );
        assert_eq!(blocked_metrics.status, 403);

        let allowed_localhost = handle_http_request(
            &mut pool,
            with_host(
                control_request("POST", "/sessions", None, create_body),
                "localhost:8787",
            ),
        );
        assert_eq!(allowed_localhost.status, 201);

        let allowed_ipv6_loopback = handle_http_request(
            &mut pool,
            with_host(
                control_request("POST", "/sessions", None, create_body),
                "[::1]:8787",
            ),
        );
        assert_eq!(allowed_ipv6_loopback.status, 201);
        Ok(())
    }

    #[test]
    fn host_header_normalization_rejects_rebinding_authorities() {
        assert_eq!(
            normalized_host_header_name("LOCALHOST:8787").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            normalized_host_header_name("127.0.0.1:8787").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            normalized_host_header_name("[::1]:8787").as_deref(),
            Some("[::1]")
        );
        assert_eq!(
            normalized_host_header_name("localhost.").as_deref(),
            Some("localhost")
        );
        assert!(normalized_host_header_name("evil.example").is_some());
        assert!(normalized_host_header_name("localhost/path").is_none());
        assert!(normalized_host_header_name("localhost:bad").is_none());
        assert!(normalized_host_header_name("[::1").is_none());
    }

    // ---- Issue #256: capability auth for non-loopback tempod binds ----

    #[test]
    fn loopback_control_routes_require_runtime_capability_when_auth_is_enabled() -> TestResult {
        let auth = TempodAuth::bearer("runtime-token")?;
        let create_body = br#"{"url":"https://loopback.test"}"#;
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
                "runtime-token",
            ),
            &auth,
        );
        assert_eq!(allowed.status, 201);
        assert_eq!(pool.list().len(), 1);
        Ok(())
    }

    #[test]
    fn non_loopback_metadata_routes_require_auth_when_auth_is_enabled() -> TestResult {
        let auth = TempodAuth::bearer("runtime-token")?;
        let metadata_endpoints = [
            "/health",
            tempo_mcp::A2A_AGENT_CARD_PATH,
            TEMPOD_OPENAPI_PATH,
        ];

        let run_once =
            |path: &str, token: Option<&str>| -> Result<String, Box<dyn std::error::Error>> {
                let listener = TcpListener::bind("0.0.0.0:0")?;
                let connect_addr =
                    std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr()?.port()));
                let pool = Arc::new(Mutex::new(SessionPool::default()));
                let config = TempodServerConfig::new()
                    .allow_remote_binds()
                    .with_auth(auth.clone());
                let handle = thread::spawn(move || serve_one_with_config(listener, pool, config));

                let request = if let Some(token) = token {
                    format!(
                        "GET {path} HTTP/1.1\r\n\
                     host: 127.0.0.1\r\n\
                     authorization: Bearer {token}\r\n\r\n"
                    )
                } else {
                    format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
                };
                let response = send_http(connect_addr, &request)?;
                join_server(handle).map_err(|error| error as Box<dyn std::error::Error>)?;
                Ok(response)
            };

        for path in metadata_endpoints {
            let missing = run_once(path, None)?;
            assert!(
                missing.starts_with("HTTP/1.1 401"),
                "missing token for {path}: {missing}"
            );

            let ok = run_once(path, Some("runtime-token"))?;
            assert!(
                ok.starts_with("HTTP/1.1 200"),
                "authorized request for {path}: {ok}"
            );
        }

        Ok(())
    }

    #[test]
    fn non_loopback_web_bot_auth_key_directory_is_public_when_auth_is_enabled() -> TestResult {
        let auth = TempodAuth::bearer("runtime-token")?;
        let listener = TcpListener::bind("0.0.0.0:0")?;
        let connect_addr =
            std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr()?.port()));
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let config = TempodServerConfig::new()
            .allow_remote_binds()
            .with_auth(auth);
        let handle = thread::spawn(move || serve_one_with_config(listener, pool, config));

        let request =
            format!("GET {WEB_BOT_AUTH_KEY_DIRECTORY_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        let response = send_http(connect_addr, &request)?;
        join_server(handle)?;

        assert!(
            response.starts_with("HTTP/1.1 200"),
            "key directory should be public: {response}"
        );
        assert!(response.contains("content-type: application/jwk-set+json"));
        assert!(response.ends_with("{\"keys\":[]}"));
        Ok(())
    }

    #[test]
    fn loopback_operational_metadata_routes_require_auth_when_auth_is_enabled() -> TestResult {
        let auth = TempodAuth::bearer("runtime-token")?;
        let metadata_endpoints = [
            tempo_mcp::A2A_AGENT_CARD_PATH,
            tempo_mcp::A2A_AGENT_JSON_PATH,
            TEMPOD_OPENAPI_PATH,
        ];

        for path in metadata_endpoints {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let connect_addr = listener.local_addr()?;
            let pool = Arc::new(Mutex::new(SessionPool::default()));
            let config = TempodServerConfig::new().with_auth(auth.clone());
            let handle = thread::spawn(move || serve_one_with_config(listener, pool, config));

            let response = send_http(
                connect_addr,
                &format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"),
            )?;
            join_server(handle)?;
            assert!(
                response.starts_with("HTTP/1.1 401"),
                "missing token for {path}: {response}"
            );
        }

        let mut pool = SessionPool::default();
        let health = handle_http_request_with_auth(
            &mut pool,
            control_request("GET", "/health", None, b""),
            &auth,
        );
        assert_eq!(health.status, 200);
        Ok(())
    }

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
            serve_one_unsafe(listener, Arc::clone(&pool)),
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

        let mut pool = SessionPool::default();
        let missing = handle_http_request_with_auth(&mut pool, bidi_websocket_request(None), &auth);
        assert_eq!(missing.status, 401, "upgrade without token: {missing:?}");

        let wrong = handle_http_request_with_auth(
            &mut pool,
            bidi_websocket_request(Some("wrong-token")),
            &auth,
        );
        assert_eq!(wrong.status, 401, "upgrade with wrong token: {wrong:?}");

        // With the right token the request clears auth and reaches the
        // WebSocket upgrade (101 Switching Protocols) on a real socket.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_auth = auth.clone();
        let handle = thread::spawn(move || serve_one_with_auth(listener, server_pool, server_auth));

        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(
            b"GET /bidi HTTP/1.1\r\n\
              host: 127.0.0.1\r\n\
              authorization: Bearer secret-token\r\n\
              upgrade: websocket\r\n\
              connection: Upgrade\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              sec-websocket-version: 13\r\n\r\n",
        )?;
        let response = read_http_head(&mut stream)?;
        assert!(
            response.starts_with("HTTP/1.1 101 Switching Protocols"),
            "authorized upgrade: {response}"
        );
        stream.write_all(&masked_client_frame(WS_OPCODE_CLOSE, &[])?)?;
        let (opcode, _payload) = read_server_frame(&mut stream)?;
        assert_eq!(opcode, WS_OPCODE_CLOSE);
        drop(stream);
        join_server(handle)?;
        Ok(())
    }

    // ---- Issue #84: Content-Length overflow must not panic ----

    #[test]
    fn overflowing_content_length_is_rejected_without_panic() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let handle = thread::spawn(move || serve_one_unsafe(listener, pool));

        let response = send_http(
            addr,
            "POST /sessions HTTP/1.1\r\ncontent-length: 18446744073709551615\r\n\r\n",
        )?;
        // The daemon thread must return cleanly (no panic / process death),
        // and the absurd Content-Length is refused as a client error (hyper
        // answers 431 for an unsatisfiable message head; the hand-rolled
        // parser answered 400).
        join_server(handle)?;
        assert!(response.starts_with("HTTP/1.1 4"), "{response}");
        Ok(())
    }

    // ---- Issue #85: per-connection errors do not kill the listener ----

    #[test]
    fn connection_error_does_not_terminate_accept_loop() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        // serve_forever must keep accepting after a faulty connection.
        let handle = thread::spawn(move || serve_forever_unsafe(listener, server_pool));

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
        let request = request_with_default_host(addr, request);
        stream.write_all(request.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        read_http_response(&mut stream)
    }

    fn request_with_default_host(addr: std::net::SocketAddr, request: &str) -> String {
        if request.to_ascii_lowercase().contains("\r\nhost:") {
            return request.to_string();
        }
        let Some(head_end) = request.find("\r\n") else {
            return request.to_string();
        };
        let mut with_host =
            String::with_capacity(request.len() + "host: 127.0.0.1:65535\r\n".len());
        with_host.push_str(&request[..head_end + 2]);
        with_host.push_str(&format!("host: 127.0.0.1:{}\r\n", addr.port()));
        with_host.push_str(&request[head_end + 2..]);
        with_host
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

    /// Like [`attach_driver_handler`], but serves a fixed number of engine
    /// round-trips (policy taint recomputation adds an Observe before gated
    /// commands, #254).
    fn attach_driver_handler_seq<F>(
        pool: &mut SessionPool,
        requests: usize,
        mut handler: F,
    ) -> Result<thread::JoinHandle<Result<(), EngineHostError>>, Box<dyn Error>>
    where
        F: FnMut(DriverRequest) -> DriverResponse + Send + 'static,
    {
        let (client_stream, server_stream) = UnixStream::pair()?;
        pool.attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        Ok(thread::spawn(move || {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            for _ in 0..requests {
                let request = connection.read_driver_request()?;
                let request_id = request.id;
                let response = handler(request);
                connection.write_driver_response(request_id, response)?;
            }
            Ok(())
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
            omitted: 0,
            marks: Vec::new(),
        }
    }

    /// An observation carrying one page-provenance span, for #254 taint
    /// recomputation tests.
    fn tainted_observation(url: &str, seq: u64, page_text: &str) -> CompiledObservation {
        let mut observation = observation(url, seq);
        observation.elements = vec![tempo_schema::InteractiveElement {
            node_id: NodeId("page.content".into()),
            role: "link".into(),
            name: vec![tempo_schema::TaintSpan {
                provenance: tempo_schema::Provenance::Page,
                text: page_text.into(),
            }],
            value: Vec::new(),
            bounds: None,
            rank: 1.0,
        }];
        observation
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
                    omitted: 0,
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

    /// #413: a one-off panic under the pool guard poisons the mutex. `lock_pool`
    /// must recover the guard (like the driver `OpGate`) instead of returning
    /// `PoolLock` forever, so the pool stays usable and routes keep working.
    #[test]
    fn lock_pool_recovers_poisoned_pool_and_pool_stays_usable() -> TestResult {
        let shared = Arc::new(Mutex::new(SessionPool::default()));

        let poison_target = Arc::clone(&shared);
        let outcome = thread::spawn(move || {
            let _guard = match poison_target.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            panic!("poison the pool mutex while the guard is held");
        })
        .join();
        assert!(
            outcome.is_err(),
            "helper thread must panic to poison the mutex"
        );
        assert!(shared.is_poisoned(), "pool mutex should now be poisoned");

        // Recovery path: this used to return `TempodError::PoolLock` forever.
        let mut guard = lock_pool(&shared)?;
        // The recovered pool is fully functional (a real route surface).
        let _session = guard.create("https://poison-recovery.test")?;
        assert_eq!(guard.list().len(), 1);
        Ok(())
    }

    /// #413: the denial builder used to `unreachable!` on `(false, false)`.
    /// Because it runs under the pool guard, a panic there would poison the
    /// pool and wedge the daemon. A logic bug reaching it must return a denial
    /// error, not panic.
    #[test]
    fn deny_session_batch_policy_returns_error_instead_of_panicking_with_no_reason() -> TestResult {
        let body: SessionActBatchRequest = serde_json::from_str(
            r#"{"batch":{"actions":[],"quiescence":"composite"},"input_tainted":false}"#,
        )?;
        let report = SessionBatchPolicyReport {
            input_tainted_declared: None,
            input_tainted_effective: false,
            forced_tainted_actions: 0,
            max_side_effect: SideEffect::Read,
            strongest_gate: ConfirmationGate::None,
            confirmation_required: false,
            confirmed: false,
            confirmed_effective: false,
            confirmed_claim_ignored: false,
            idempotency_required: false,
            idempotency_key_provided: false,
            idempotency_cache_retained: true,
        };

        let error = deny_session_batch_policy(false, false, false, None, None, &body, report);
        assert!(
            matches!(error, TempodError::PolicyDenied(_)),
            "no-reason denial must be a PolicyDenied error, not a panic"
        );
        assert_eq!(error.status(), 403);
        Ok(())
    }
}
