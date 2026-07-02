//! tempo-engine-servo — typed boundary for the Servo-backed engine lane.
//!
//! This crate keeps embedding details private to the engine lane. Public APIs use
//! tempo contracts only: semantic actions, stable node ids, network interception
//! records, screenshot requests, and capability flags.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError, Unsupported};
use tempo_engine_host::{
    DriverCommand, DriverResponse, DriverWireError, EngineHostError, EngineIpcClient,
};
use tempo_net::{
    AuditRecord, EgressDecision, EgressDenied, EgressPolicy, EgressRecord, IdentityMode,
    NetworkRequest, ProfileId, SignatureError, UrlBlocked, UrlPolicy, WebBotAuthSigningKey,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use thiserror::Error;

/// Default cap for a Servo-intercepted network response body reissued through tempo-net.
pub const DEFAULT_MAX_SERVO_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Which Servo build is backing this engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServoBuildFlavor {
    Vanilla,
    TempoFork,
}

/// Engine-side viewport in CSS pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
        }
    }
}

/// Configuration required before spawning a Servo-backed page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoEngineConfig {
    pub build_flavor: ServoBuildFlavor,
    pub viewport: Viewport,
    pub user_agent: String,
    pub access_tree: bool,
    pub intercept_network: bool,
}

impl ServoEngineConfig {
    pub fn vanilla() -> Self {
        Self {
            build_flavor: ServoBuildFlavor::Vanilla,
            viewport: Viewport::default(),
            user_agent: "tempo-servo/0.1".into(),
            access_tree: true,
            intercept_network: true,
        }
    }

    pub fn tempo_fork() -> Self {
        Self {
            build_flavor: ServoBuildFlavor::TempoFork,
            ..Self::vanilla()
        }
    }

    pub fn native_fork(&self) -> Result<(), Unsupported> {
        match self.build_flavor {
            ServoBuildFlavor::TempoFork => Ok(()),
            ServoBuildFlavor::Vanilla => Err(Unsupported("native servo fork requires tempo fork")),
        }
    }
}

/// Servo-backed driver handle connected to an out-of-process Servo engine.
///
/// The libservo embedder stays in the engine process. This client speaks the
/// same DriverTrait wire protocol used by tempod and other engines.
#[derive(Clone)]
pub struct ServoIpcDriver {
    config: ServoEngineConfig,
    client: Arc<Mutex<EngineIpcClient>>,
    driver_id: Option<String>,
}

impl ServoIpcDriver {
    pub fn connect(
        config: ServoEngineConfig,
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, ServoEngineError> {
        Ok(Self::from_client(
            config,
            EngineIpcClient::connect(socket_path)?,
        ))
    }

    pub fn from_client(config: ServoEngineConfig, client: EngineIpcClient) -> Self {
        Self {
            config,
            client: Arc::new(Mutex::new(client)),
            driver_id: None,
        }
    }

    pub fn config(&self) -> &ServoEngineConfig {
        &self.config
    }

    fn request(&self, command: DriverCommand) -> Result<DriverResponse, ServoEngineError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| ServoEngineError::DriverLockFailed)?;
        Ok(client.request_for(self.driver_id.as_deref(), command)?)
    }
}

#[async_trait]
impl DriverTrait for ServoIpcDriver {
    fn engine(&self) -> Engine {
        Engine::Servo
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        match self
            .request(DriverCommand::Goto { url: url.into() })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Observation { observation } => Ok(observation),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "goto")),
        }
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        match self
            .request(DriverCommand::Observe)
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Observation { observation } => Ok(observation),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "observe")),
        }
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        match self
            .request(DriverCommand::ObserveDiff { since_seq })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Diff { diff } => Ok(diff),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "observe_diff")),
        }
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        match self
            .request(DriverCommand::Act {
                action: action.clone(),
            })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Step { outcome } => Ok(outcome.into()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "act")),
        }
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        match self
            .request(DriverCommand::ActBatch {
                batch: batch.clone(),
            })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Step { outcome } => Ok(outcome.into()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "act_batch")),
        }
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        self.config.native_fork()?;
        match self.request(DriverCommand::Fork) {
            Ok(DriverResponse::Forked { driver_id }) => Ok(Box::new(Self {
                config: self.config.clone(),
                client: Arc::clone(&self.client),
                driver_id: Some(driver_id),
            })),
            Ok(DriverResponse::Error { error }) => Err(driver_wire_unsupported(error)),
            Ok(_) => Err(Unsupported("unexpected engine IPC fork response")),
            Err(_) => Err(Unsupported("engine IPC fork failed")),
        }
    }

    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
        match self
            .request(DriverCommand::Extract { node: node.clone() })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Extracted { value } => Ok(value),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "extract")),
        }
    }

    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<serde_json::Value, TransportError> {
        match self
            .request(DriverCommand::EvaluateScript {
                expression: expression.into(),
                await_promise,
            })
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Evaluated { value } => Ok(value),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "evaluate_script")),
        }
    }

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
        match self
            .request(DriverCommand::Screenshot)
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Screenshot { bytes } => Ok(bytes),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "screenshot")),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        match self
            .request(DriverCommand::Close)
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Closed => Ok(()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "close")),
        }
    }
}

/// Engine command sent to the private Servo embedder.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServoEmbedderCommand {
    LoadUrl {
        url: String,
    },
    ActivateNode {
        node: NodeId,
    },
    TypeText {
        node: NodeId,
        text: String,
    },
    SelectValue {
        node: NodeId,
        value: String,
    },
    Scroll {
        x: f32,
        y: f32,
    },
    ExtractNode {
        node: NodeId,
    },
    InvokeSkill {
        name: String,
        input: serde_json::Value,
    },
    CaptureScreenshot {
        format: ScreenshotFormat,
    },
    Close,
}

impl ServoEmbedderCommand {
    pub fn from_action(action: Action) -> Self {
        match action {
            Action::Goto { url } => Self::LoadUrl { url },
            Action::Click { node } => Self::ActivateNode { node },
            Action::Type { node, text } => Self::TypeText { node, text },
            Action::Select { node, value } => Self::SelectValue { node, value },
            Action::Scroll { x, y } => Self::Scroll { x, y },
            Action::Extract { node } => Self::ExtractNode { node },
            Action::Skill { name, input } => Self::InvokeSkill { name, input },
        }
    }
}

/// Screenshot format requested from the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotFormat {
    Png,
}

/// Request intercepted at the engine boundary before it reaches the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoNetworkRequest {
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl ServoNetworkRequest {
    pub fn new(
        request_id: impl Into<String>,
        method: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body_len: 0,
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self.body_len = self.body.len() as u64;
        self
    }

    fn effective_body_len(&self) -> Result<u64, ServoNetworkError> {
        let actual = self.body.len() as u64;
        if actual == 0 {
            if self.body_len > 0 {
                return Err(ServoNetworkError::MissingBodyBytes {
                    declared: self.body_len,
                });
            }
            return Ok(0);
        }
        if self.body_len != 0 && self.body_len != actual {
            return Err(ServoNetworkError::BodyLengthMismatch {
                declared: self.body_len,
                actual,
            });
        }
        Ok(actual)
    }

    fn to_network_request(
        &self,
        profile_id: &ProfileId,
        identity_mode: IdentityMode,
    ) -> Result<NetworkRequest, ServoNetworkError> {
        let mut request = NetworkRequest::new(
            self.request_id.clone(),
            self.method.clone(),
            self.url.clone(),
            profile_id.clone(),
            identity_mode,
        )
        .with_body_size(self.effective_body_len()?);
        for (name, value) in &self.headers {
            request = request.with_header(name.clone(), value.clone());
        }
        Ok(request)
    }
}

/// Response returned to the engine after tempo-net policy/signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoNetworkResponse {
    pub request_id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Result of reissuing one Servo-intercepted request through tempo-net.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServoNetworkFetch {
    pub response: ServoNetworkResponse,
    pub audit: AuditRecord,
    pub egress_decision: EgressDecision,
    pub egress_record: EgressRecord,
    pub signed_headers: Vec<(String, String)>,
}

/// Reissues Servo `load_web_resource` requests through tempo-net policies.
pub struct ServoNetworkAdapter {
    profile_id: ProfileId,
    identity_mode: IdentityMode,
    url_policy: UrlPolicy,
    egress_policy: EgressPolicy,
    signing: Option<ServoSigningConfig>,
    timeout: Duration,
    max_response_body_bytes: usize,
}

impl ServoNetworkAdapter {
    pub fn new(profile_id: impl Into<ProfileId>, identity_mode: IdentityMode) -> Self {
        Self {
            profile_id: profile_id.into(),
            identity_mode,
            url_policy: UrlPolicy::block_private(),
            egress_policy: EgressPolicy::allow_all(),
            signing: None,
            timeout: Duration::from_secs(30),
            max_response_body_bytes: DEFAULT_MAX_SERVO_RESPONSE_BODY_BYTES,
        }
    }

    pub fn with_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    pub fn with_egress_policy(mut self, egress_policy: EgressPolicy) -> Self {
        self.egress_policy = egress_policy;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = max_response_body_bytes;
        self
    }

    pub fn with_web_bot_auth_key(mut self, key: WebBotAuthSigningKey, created: u64) -> Self {
        self.signing = Some(ServoSigningConfig { key, created });
        self
    }

    pub fn fetch(
        &self,
        request: &ServoNetworkRequest,
    ) -> Result<ServoNetworkFetch, ServoNetworkError> {
        let network_request = request.to_network_request(&self.profile_id, self.identity_mode)?;
        let audit = AuditRecord::from_request(&network_request, &self.url_policy)?;
        let egress_decision = self
            .egress_policy
            .decide(&network_request)
            .map_err(ServoNetworkError::from)?;
        let signed_headers = self.signed_headers(&network_request)?;
        let client = self.client_for(&egress_decision)?;
        let response = self.send_request(&client, request, &egress_decision, &signed_headers)?;
        let egress_record = EgressRecord::from_decision(
            request.request_id.clone(),
            &egress_decision,
            network_request.body_size(),
            response.body.len() as u64,
        );
        Ok(ServoNetworkFetch {
            response,
            audit,
            egress_decision,
            egress_record,
            signed_headers,
        })
    }

    fn signed_headers(
        &self,
        request: &NetworkRequest,
    ) -> Result<Vec<(String, String)>, ServoNetworkError> {
        let Some(signing) = &self.signing else {
            return Ok(Vec::new());
        };
        let headers = request.sign_web_bot_auth(&signing.key, signing.created)?;
        Ok(headers
            .as_header_pairs()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect())
    }

    fn client_for(
        &self,
        decision: &EgressDecision,
    ) -> Result<reqwest::blocking::Client, ServoNetworkError> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(url_policy_redirect(self.url_policy.clone()));
        if let EgressDecision::Proxied { proxy, .. } = decision {
            let proxy = reqwest::Proxy::all(&proxy.endpoint)
                .map_err(|error| ServoNetworkError::Proxy(error.to_string()))?;
            builder = builder.proxy(proxy);
        }
        builder
            .build()
            .map_err(|error| ServoNetworkError::ClientBuild(error.to_string()))
    }

    fn send_request(
        &self,
        client: &reqwest::blocking::Client,
        request: &ServoNetworkRequest,
        _decision: &EgressDecision,
        signed_headers: &[(String, String)],
    ) -> Result<ServoNetworkResponse, ServoNetworkError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| ServoNetworkError::InvalidMethod(error.to_string()))?;
        let mut builder = client.request(method, &request.url);
        for (name, value) in request.headers.iter().chain(signed_headers.iter()) {
            builder = builder.header(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    ServoNetworkError::InvalidHeader {
                        name: name.clone(),
                        reason: error.to_string(),
                    }
                })?,
                reqwest::header::HeaderValue::from_str(value).map_err(|error| {
                    ServoNetworkError::InvalidHeader {
                        name: name.clone(),
                        reason: error.to_string(),
                    }
                })?,
            );
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }

        let response = builder
            .send()
            .map_err(|error| ServoNetworkError::Fetch(error.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        let mut body = Vec::new();
        response
            .take(self.max_response_body_bytes as u64)
            .read_to_end(&mut body)
            .map_err(|error| ServoNetworkError::ResponseRead(error.to_string()))?;
        Ok(ServoNetworkResponse {
            request_id: request.request_id.clone(),
            status,
            headers,
            body,
        })
    }
}

struct ServoSigningConfig {
    key: WebBotAuthSigningKey,
    created: u64,
}

/// Engine readiness gates that must be satisfied before a page is agent-drivable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoReadiness {
    pub loaded: bool,
    pub access_tree_ready: bool,
    pub network_idle: bool,
}

impl ServoReadiness {
    pub fn agent_drivable(&self) -> bool {
        self.loaded && self.access_tree_ready && self.network_idle
    }
}

/// Guard used by CI to prove public signatures stay free of private embedder type names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicApiGuard {
    denied_fragments: Vec<&'static str>,
}

impl PublicApiGuard {
    pub fn servo_private_type_guard() -> Self {
        Self {
            denied_fragments: vec![
                "WebView",
                "WebViewDelegate",
                "RenderingContext",
                "Constellation",
            ],
        }
    }

    pub fn check_symbols<'a>(
        &self,
        symbols: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ServoEngineError> {
        for symbol in symbols {
            if symbol.starts_with("servo::") || symbol.contains("::servo::") {
                return Err(ServoEngineError::PrivateTypeLeaked {
                    symbol: symbol.into(),
                    fragment: "servo::",
                });
            }
            if let Some(fragment) = self
                .denied_fragments
                .iter()
                .find(|fragment| symbol.contains(**fragment))
            {
                return Err(ServoEngineError::PrivateTypeLeaked {
                    symbol: symbol.into(),
                    fragment,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ServoEngineError {
    #[error("private Servo type leaked through public API: {symbol} contains {fragment}")]
    PrivateTypeLeaked {
        symbol: String,
        fragment: &'static str,
    },
    #[error("servo engine host failed: {0}")]
    Host(#[from] EngineHostError),
    #[error("servo IPC driver lock failed")]
    DriverLockFailed,
}

#[derive(Debug, Error)]
pub enum ServoNetworkError {
    #[error(transparent)]
    Url(#[from] UrlBlocked),
    #[error("egress denied for {domain}:{port}: {reason}")]
    EgressDenied {
        domain: String,
        port: u16,
        reason: String,
    },
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(String),
    #[error("failed to configure proxy: {0}")]
    Proxy(String),
    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),
    #[error("invalid HTTP header {name}: {reason}")]
    InvalidHeader { name: String, reason: String },
    #[error("request body declares {declared} bytes but no body bytes were provided")]
    MissingBodyBytes { declared: u64 },
    #[error("request body length mismatch: declared {declared} bytes, got {actual}")]
    BodyLengthMismatch { declared: u64, actual: u64 },
    #[error("HTTP fetch failed: {0}")]
    Fetch(String),
    #[error("failed to read HTTP response: {0}")]
    ResponseRead(String),
}

impl From<EgressDenied> for ServoNetworkError {
    fn from(value: EgressDenied) -> Self {
        Self::EgressDenied {
            domain: value.domain,
            port: value.port,
            reason: value.reason,
        }
    }
}

fn servo_host_transport_error(error: ServoEngineError) -> TransportError {
    TransportError::Other(error.to_string())
}

/// Redirect policy that re-validates every hop against the URL policy so a
/// remote origin cannot redirect the fetch into an internal/loopback target
/// (issue #80). Blocks any hop the policy would block and caps the hop count.
fn url_policy_redirect(url_policy: UrlPolicy) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error(ServoRedirectBlocked("too many redirects".to_string()));
        }
        match url_policy.enforce(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(error) => attempt.error(ServoRedirectBlocked(error.to_string())),
        }
    })
}

#[derive(Debug)]
struct ServoRedirectBlocked(String);

impl std::fmt::Display for ServoRedirectBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "redirect blocked by URL policy: {}", self.0)
    }
}

impl std::error::Error for ServoRedirectBlocked {}

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
        DriverWireError::Unsupported { .. } => Unsupported("servo IPC capability unsupported"),
        DriverWireError::Transport { .. } | DriverWireError::Protocol { .. } => {
            Unsupported("servo IPC fork failed")
        }
    }
}

fn unexpected_driver_response(response: DriverResponse, expected: &'static str) -> TransportError {
    TransportError::Other(format!(
        "servo engine returned unexpected response for {expected}: {response:?}"
    ))
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "Servo engine boundary types, UDS DriverTrait client, action translation, network interception records, and capability gates"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration as StdDuration;
    use tempo_driver::{DriverTrait, Engine, TestDriver};
    use tempo_engine_host::{serve_driver_connection, EngineIpcConnection};
    use tempo_schema::{InteractiveElement, Provenance, TaintSpan};

    type TestResult = Result<(), Box<dyn Error>>;
    type HttpFixture = (
        String,
        mpsc::Receiver<String>,
        thread::JoinHandle<Result<(), io::Error>>,
    );

    #[test]
    fn vanilla_config_enables_access_tree_and_network_interception() {
        let config = ServoEngineConfig::vanilla();

        assert_eq!(config.build_flavor, ServoBuildFlavor::Vanilla);
        assert_eq!(config.viewport, Viewport::default());
        assert!(config.access_tree);
        assert!(config.intercept_network);
    }

    #[test]
    fn native_fork_requires_tempo_fork_build() {
        let vanilla = ServoEngineConfig::vanilla();
        let fork = ServoEngineConfig::tempo_fork();

        assert!(vanilla.native_fork().is_err());
        assert!(fork.native_fork().is_ok());
    }

    #[test]
    fn semantic_actions_translate_to_embedder_commands() {
        let commands = vec![
            ServoEmbedderCommand::from_action(Action::Goto {
                url: "https://example.test".into(),
            }),
            ServoEmbedderCommand::from_action(Action::Click {
                node: NodeId("button".into()),
            }),
            ServoEmbedderCommand::from_action(Action::Type {
                node: NodeId("input".into()),
                text: "hello".into(),
            }),
            ServoEmbedderCommand::from_action(Action::Scroll { x: 0.0, y: 12.0 }),
        ];

        assert_eq!(
            commands,
            vec![
                ServoEmbedderCommand::LoadUrl {
                    url: "https://example.test".into(),
                },
                ServoEmbedderCommand::ActivateNode {
                    node: NodeId("button".into()),
                },
                ServoEmbedderCommand::TypeText {
                    node: NodeId("input".into()),
                    text: "hello".into(),
                },
                ServoEmbedderCommand::Scroll { x: 0.0, y: 12.0 },
            ]
        );
    }

    #[test]
    fn readiness_requires_load_access_tree_and_network_idle() {
        assert!(ServoReadiness {
            loaded: true,
            access_tree_ready: true,
            network_idle: true,
        }
        .agent_drivable());

        assert!(!ServoReadiness {
            loaded: true,
            access_tree_ready: false,
            network_idle: true,
        }
        .agent_drivable());
    }

    #[test]
    fn public_api_guard_rejects_private_embedder_types() {
        let guard = PublicApiGuard::servo_private_type_guard();

        assert!(guard
            .check_symbols([
                "tempo_engine_servo::ServoEngineConfig",
                "tempo_engine_servo::ServoEmbedderCommand",
            ])
            .is_ok());
        assert!(matches!(
            guard.check_symbols(["tempo_engine_servo::WebViewDelegateHandle"]),
            Err(ServoEngineError::PrivateTypeLeaked { .. })
        ));
    }

    #[test]
    fn network_interception_records_request_and_response_bytes() {
        let request = ServoNetworkRequest::new("req-1", "GET", "https://example.test/data")
            .with_header("accept", "application/json");
        let response = ServoNetworkResponse {
            request_id: request.request_id.clone(),
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok":true}"#.to_vec(),
        };

        assert_eq!(request.request_id, response.request_id);
        assert_eq!(response.body, br#"{"ok":true}"#.to_vec());
    }

    #[test]
    fn servo_network_adapter_reissues_request_through_tempo_net() -> TestResult {
        let (origin, captured_request, server) = serve_http_once(br#"{"ok":true}"#.to_vec())?;
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared)
            .with_url_policy(UrlPolicy::allow_all())
            .with_timeout(StdDuration::from_secs(5));
        let request = ServoNetworkRequest::new("req-1", "GET", format!("{origin}/data"))
            .with_header("accept", "application/json");

        let fetch = adapter.fetch(&request)?;
        join_server(server)?;
        let captured = captured_request.recv_timeout(StdDuration::from_secs(1))?;

        assert!(captured.starts_with("GET /data HTTP/1.1"));
        assert_eq!(fetch.response.status, 200);
        assert_eq!(fetch.response.body, br#"{"ok":true}"#.to_vec());
        assert_eq!(fetch.audit.origin, origin);
        assert_eq!(fetch.egress_record.request_id.0, "req-1");
        assert_eq!(fetch.egress_record.bytes_sent, 0);
        assert_eq!(
            fetch.egress_record.bytes_received,
            fetch.response.body.len() as u64
        );
        assert!(fetch.signed_headers.is_empty());
        Ok(())
    }

    #[test]
    fn servo_network_adapter_blocks_private_urls_before_network() -> TestResult {
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared);
        let request = ServoNetworkRequest::new("req-1", "GET", "http://127.0.0.1:9/data");

        let error = adapter
            .fetch(&request)
            .err()
            .ok_or_else(|| io::Error::other("expected URL policy failure"))?;

        assert!(matches!(error, ServoNetworkError::Url(_)));
        Ok(())
    }

    #[test]
    fn servo_network_adapter_blocks_egress_before_network() -> TestResult {
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared)
            .with_url_policy(UrlPolicy::allow_all())
            .with_egress_policy(EgressPolicy::block_by_default());
        let request = ServoNetworkRequest::new("req-1", "GET", "http://127.0.0.1:9/data");

        let error = adapter
            .fetch(&request)
            .err()
            .ok_or_else(|| io::Error::other("expected egress policy failure"))?;

        assert!(matches!(error, ServoNetworkError::EgressDenied { .. }));
        Ok(())
    }

    #[test]
    fn servo_network_adapter_adds_web_bot_auth_headers() -> TestResult {
        let (origin, captured_request, server) = serve_http_once(b"ok".to_vec())?;
        let signing_key = WebBotAuthSigningKey::from_seed("tempo-key", &[7_u8; 32])?;
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared)
            .with_url_policy(UrlPolicy::allow_all())
            .with_web_bot_auth_key(signing_key, 123);
        let request = ServoNetworkRequest::new("req-1", "GET", format!("{origin}/signed"));

        let fetch = adapter.fetch(&request)?;
        join_server(server)?;
        let captured = captured_request
            .recv_timeout(StdDuration::from_secs(1))?
            .to_ascii_lowercase();

        assert_eq!(fetch.signed_headers.len(), 2);
        assert!(captured.contains("\r\nsignature-input:"));
        assert!(captured.contains("\r\nsignature:"));
        Ok(())
    }

    #[test]
    fn servo_network_adapter_caps_response_body_bytes() -> TestResult {
        let (origin, _captured_request, server) = serve_http_once(b"0123456789abcdef".to_vec())?;
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared)
            .with_url_policy(UrlPolicy::allow_all())
            .with_max_response_body_bytes(8);
        let request = ServoNetworkRequest::new("req-1", "GET", format!("{origin}/large"));

        let fetch = adapter.fetch(&request)?;
        join_server(server)?;

        assert_eq!(fetch.response.body, b"01234567".to_vec());
        assert_eq!(fetch.egress_record.bytes_received, 8);
        Ok(())
    }

    fn serve_http_once(body: Vec<u8>) -> Result<HttpFixture, io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel();
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            let (stream, _addr) = listener.accept()?;
            handle_http_stream(stream, body, request_tx)
        });
        Ok((format!("http://{addr}"), request_rx, handle))
    }

    fn handle_http_stream(
        mut stream: TcpStream,
        body: Vec<u8>,
        request_tx: mpsc::Sender<String>,
    ) -> Result<(), io::Error> {
        stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
        let request = read_http_request(&mut stream)?;
        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        stream.write_all(&response)?;
        stream.flush()
    }

    fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, io::Error> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = header_end(&request) {
                let body_len = content_length(&request[..header_end])?;
                if request.len() >= header_end + 4 + body_len {
                    break;
                }
            }
            if request.len() > 64 * 1024 {
                return Err(io::Error::other("request exceeded fixture cap"));
            }
        }
        Ok(request)
    }

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &[u8]) -> Result<usize, io::Error> {
        let headers = String::from_utf8_lossy(headers);
        for line in headers.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse()
                    .map_err(|error: std::num::ParseIntError| io::Error::other(error.to_string()));
            }
        }
        Ok(0)
    }

    fn join_server(handle: thread::JoinHandle<Result<(), io::Error>>) -> TestResult {
        match handle.join() {
            Ok(result) => result.map_err(|error| Box::new(error) as Box<dyn Error>),
            Err(_) => Err(Box::new(io::Error::other("fixture server panicked"))),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn servo_ipc_driver_round_trips_driver_trait_over_uds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = tokio::spawn(async move {
            let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            serve_driver_connection(&mut connection, &mut driver).await
        });
        let mut driver = ServoIpcDriver::from_client(
            ServoEngineConfig::vanilla(),
            tempo_engine_host::EngineIpcClient::from_stream(client_stream),
        );

        let observation = driver.goto("https://servo.test").await?;
        let outcome = driver
            .act(&Action::Click {
                node: NodeId("submit".into()),
            })
            .await?;
        let extracted = driver.extract(&NodeId("submit".into())).await?;
        let evaluated = driver.evaluate_script("document.title", true).await?;
        driver.close().await?;
        server.await??;

        assert_eq!(driver.engine(), Engine::Servo);
        assert_eq!(observation.url, "https://servo.test");
        assert!(matches!(outcome, StepOutcome::Applied { .. }));
        assert_eq!(extracted["node"], "submit");
        assert_eq!(evaluated["expression"], "document.title");
        assert_eq!(evaluated["awaitPromise"], true);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tempo_fork_servo_ipc_driver_routes_fork_handles(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (client_stream, server_stream) = UnixStream::pair()?;
        let server = tokio::spawn(async move {
            let mut driver = TestDriver::new();
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            serve_driver_connection(&mut connection, &mut driver).await
        });
        let mut root_driver = ServoIpcDriver::from_client(
            ServoEngineConfig::tempo_fork(),
            tempo_engine_host::EngineIpcClient::from_stream(client_stream),
        );

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
        server.await??;

        assert_eq!(root_observation.url, "https://root.test");
        assert_eq!(root_observation.seq, 1);
        assert_eq!(fork_observation.url, "https://fork.test");
        assert_eq!(fork_observation.seq, 2);
        Ok(())
    }

    fn button(id: &str) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(id.into()),
            role: "button".into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: "Submit".into(),
            }],
            value: vec![],
            bounds: Some([0.0, 0.0, 100.0, 30.0]),
            rank: 1.0,
        }
    }
}
