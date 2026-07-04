//! tempo-engine-servo — typed boundary for the Servo-backed engine lane.
//!
//! This crate keeps embedding details private to the engine lane. Public APIs use
//! tempo contracts only: semantic actions, stable node ids, network interception
//! records, screenshot requests, and capability flags.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
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

#[cfg(feature = "servo-vanilla")]
mod servo_embedder;

/// Default cap for a Servo-intercepted network response body reissued through tempo-net.
pub const DEFAULT_MAX_SERVO_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_SERVO_REDIRECTS: usize = 10;
pub const PINNED_VANILLA_SERVO_VERSION: &str = "0.3.0";

/// Which Servo build is backing this engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServoBuildFlavor {
    Vanilla,
    TempoFork,
}

/// Runtime platforms tracked by upstream Servo and exposed to Tempo SDKs.
///
/// Servo currently develops on desktop, mobile, and OpenHarmony targets. Tempo
/// keeps the control-plane transport explicit so SDKs can distinguish "Servo is
/// available here" from "this Tempo IPC transport still needs a platform-native
/// adapter".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServoRuntimePlatform {
    Macos,
    Linux,
    Windows,
    Android,
    #[serde(rename = "openharmony")]
    OpenHarmony,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServoControlPlaneTransport {
    UnixDomainSocket,
    WindowsNativePlanned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoPlatformSupport {
    pub platform: ServoRuntimePlatform,
    pub rust_targets: Vec<String>,
    pub servo_available: bool,
    pub control_transport: ServoControlPlaneTransport,
    pub note: String,
}

pub fn servo_platform_support_matrix() -> Vec<ServoPlatformSupport> {
    vec![
        ServoPlatformSupport {
            platform: ServoRuntimePlatform::Macos,
            rust_targets: vec!["aarch64-apple-darwin".into(), "x86_64-apple-darwin".into()],
            servo_available: true,
            control_transport: ServoControlPlaneTransport::UnixDomainSocket,
            note: "desktop Servo target with Unix-domain-socket tempod IPC".into(),
        },
        ServoPlatformSupport {
            platform: ServoRuntimePlatform::Linux,
            rust_targets: vec!["x86_64-unknown-linux-gnu".into(), "aarch64-unknown-linux-gnu".into()],
            servo_available: true,
            control_transport: ServoControlPlaneTransport::UnixDomainSocket,
            note: "desktop/server Servo target with Unix-domain-socket tempod IPC".into(),
        },
        ServoPlatformSupport {
            platform: ServoRuntimePlatform::Windows,
            rust_targets: vec!["x86_64-pc-windows-msvc".into(), "aarch64-pc-windows-msvc".into()],
            servo_available: true,
            control_transport: ServoControlPlaneTransport::WindowsNativePlanned,
            note: "Servo target; Tempo engine-host IPC needs a Windows-native transport adapter before tempod can run locally".into(),
        },
        ServoPlatformSupport {
            platform: ServoRuntimePlatform::Android,
            rust_targets: vec![
                "aarch64-linux-android".into(),
                "armv7-linux-androideabi".into(),
                "x86_64-linux-android".into(),
            ],
            servo_available: true,
            control_transport: ServoControlPlaneTransport::UnixDomainSocket,
            note: "Android Servo target; Tempo should package the engine host as a local app-private service".into(),
        },
        ServoPlatformSupport {
            platform: ServoRuntimePlatform::OpenHarmony,
            rust_targets: vec![
                "aarch64-unknown-linux-ohos".into(),
                "armv7-unknown-linux-ohos".into(),
                "x86_64-unknown-linux-ohos".into(),
            ],
            servo_available: true,
            control_transport: ServoControlPlaneTransport::UnixDomainSocket,
            note: "OpenHarmony Servo target; Rust reports target_os=linux and target_env=ohos".into(),
        },
    ]
}

pub fn current_servo_platform() -> Option<ServoRuntimePlatform> {
    if cfg!(target_os = "macos") {
        Some(ServoRuntimePlatform::Macos)
    } else if cfg!(all(target_os = "linux", target_env = "ohos")) {
        Some(ServoRuntimePlatform::OpenHarmony)
    } else if cfg!(target_os = "linux") {
        Some(ServoRuntimePlatform::Linux)
    } else if cfg!(target_os = "windows") {
        Some(ServoRuntimePlatform::Windows)
    } else if cfg!(target_os = "android") {
        Some(ServoRuntimePlatform::Android)
    } else {
        None
    }
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

/// Tempo-visible evidence that the vanilla Servo embedder feature is wired.
///
/// This deliberately exposes only tempo-owned types and scalar metadata. The
/// private `servo-vanilla` module imports the real Servo embedding types and
/// maps this config into that private surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoVanillaBuildPlan {
    pub servo_crate_version: String,
    pub build_flavor: ServoBuildFlavor,
    pub current_platform: Option<ServoRuntimePlatform>,
    pub supported_platforms: Vec<ServoPlatformSupport>,
    pub viewport: Viewport,
    pub user_agent: String,
    pub access_tree: bool,
    pub intercept_network: bool,
}

#[cfg(feature = "servo-vanilla")]
pub fn vanilla_servo_build_plan(
    config: &ServoEngineConfig,
) -> Result<ServoVanillaBuildPlan, Unsupported> {
    servo_embedder::VanillaServoEmbedderPlan::from_config(config).map(Into::into)
}

#[cfg(not(feature = "servo-vanilla"))]
pub fn vanilla_servo_build_plan(
    _config: &ServoEngineConfig,
) -> Result<ServoVanillaBuildPlan, Unsupported> {
    Err(Unsupported(
        "vanilla Servo embedder requires the servo-vanilla feature",
    ))
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

    /// Perform one blocking UDS request/response round-trip without stalling the
    /// async runtime (issue #101).
    ///
    /// `EngineIpcClient` speaks a synchronous, blocking frame protocol over a
    /// `std::os::unix::net::UnixStream`. Calling it directly inside an async
    /// method would block a tokio worker for the whole round-trip (which
    /// includes real navigation). When a tokio runtime is present (tempod) we
    /// offload the blocking work to the dedicated blocking pool. On the
    /// `futures::executor::block_on` paths (tempo-headless / tempo-shell) there
    /// is no tokio runtime, so `spawn_blocking` would panic — there we run the
    /// blocking call inline, which is correct because that executor is already a
    /// plain blocking thread.
    async fn request(&self, command: DriverCommand) -> Result<DriverResponse, ServoEngineError> {
        let client = Arc::clone(&self.client);
        let driver_id = self.driver_id.clone();
        let call = move || -> Result<DriverResponse, ServoEngineError> {
            let mut client = client
                .lock()
                .map_err(|_| ServoEngineError::DriverLockFailed)?;
            Ok(client.request_for(driver_id.as_deref(), command)?)
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(call)
                .await
                .map_err(|error| ServoEngineError::DriverTask(error.to_string()))?,
            Err(_) => call(),
        }
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
            .await
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
            .await
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
            .await
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
            .await
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
            .await
            .map_err(servo_host_transport_error)?
        {
            DriverResponse::Step { outcome } => Ok(outcome.into()),
            DriverResponse::Error { error } => Err(driver_wire_transport_error(error)),
            other => Err(unexpected_driver_response(other, "act_batch")),
        }
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        self.config.native_fork()?;
        match self.request(DriverCommand::Fork).await {
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
            .await
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
            .await
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
            .await
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
            .await
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
    Wait {
        millis: u64,
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
            Action::Wait { millis } => Self::Wait { millis },
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
        self.signing = Some(ServoSigningConfig {
            key,
            created,
            expires: None,
            nonce: None,
            signature_agent: None,
        });
        self
    }

    pub fn with_web_bot_auth_signature_agent(
        mut self,
        key: WebBotAuthSigningKey,
        created: u64,
        expires: u64,
        nonce: impl Into<String>,
        signature_agent: impl Into<String>,
    ) -> Self {
        self.signing = Some(ServoSigningConfig {
            key,
            created,
            expires: Some(expires),
            nonce: Some(nonce.into()),
            signature_agent: Some(signature_agent.into()),
        });
        self
    }

    pub fn fetch(
        &self,
        request: &ServoNetworkRequest,
    ) -> Result<ServoNetworkFetch, ServoNetworkError> {
        let network_request = request.to_network_request(&self.profile_id, self.identity_mode)?;
        self.url_policy.enforce(&network_request.url)?;
        let resolved_target = ResolvedTarget::from_url(&network_request.url)?;
        self.fetch_with_resolved_target(request, network_request, resolved_target)
    }

    fn fetch_with_resolved_target(
        &self,
        request: &ServoNetworkRequest,
        network_request: NetworkRequest,
        mut resolved_target: ResolvedTarget,
    ) -> Result<ServoNetworkFetch, ServoNetworkError> {
        let mut request = request.clone();
        let mut network_request = network_request;
        let mut redirects = 0_usize;

        loop {
            let audit = self.audit_checked_target(&network_request, &resolved_target)?;
            let egress_decision = self
                .egress_policy
                .decide(&network_request)
                .map_err(ServoNetworkError::from)?;
            let signed_headers = self.signed_headers(&network_request)?;
            let client = self.client_for(&egress_decision, &resolved_target)?;
            let response =
                self.send_request(&client, &request, &egress_decision, &signed_headers)?;

            if let Some(next_request) = redirect_request(&request, &response)? {
                if redirects >= MAX_SERVO_REDIRECTS {
                    return Err(ServoNetworkError::TooManyRedirects {
                        max: MAX_SERVO_REDIRECTS,
                    });
                }
                redirects = redirects.saturating_add(1);
                request = next_request;
                network_request =
                    request.to_network_request(&self.profile_id, self.identity_mode)?;
                self.url_policy.enforce(&network_request.url)?;
                resolved_target = ResolvedTarget::from_url(&network_request.url)?;
                continue;
            }

            let egress_record = EgressRecord::from_decision(
                request.request_id.clone(),
                &egress_decision,
                network_request.body_size(),
                response.body.len() as u64,
            );
            return Ok(ServoNetworkFetch {
                response,
                audit,
                egress_decision,
                egress_record,
                signed_headers,
            });
        }
    }

    fn audit_checked_target(
        &self,
        network_request: &NetworkRequest,
        resolved_target: &ResolvedTarget,
    ) -> Result<AuditRecord, ServoNetworkError> {
        Ok(AuditRecord::from_request_with_resolved_socket(
            network_request,
            &self.url_policy,
            resolved_target.socket,
        )?)
    }

    fn signed_headers(
        &self,
        request: &NetworkRequest,
    ) -> Result<Vec<(String, String)>, ServoNetworkError> {
        let Some(signing) = &self.signing else {
            return Ok(Vec::new());
        };
        let headers = if let (Some(expires), Some(nonce), Some(signature_agent)) = (
            signing.expires,
            signing.nonce.as_deref(),
            signing.signature_agent.as_deref(),
        ) {
            request.sign_web_bot_auth_with_agent(
                &signing.key,
                signing.created,
                expires,
                nonce,
                signature_agent,
            )?
        } else {
            request.sign_web_bot_auth(&signing.key, signing.created)?
        };
        Ok(headers
            .header_pairs()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect())
    }

    fn client_for(
        &self,
        decision: &EgressDecision,
        resolved_target: &ResolvedTarget,
    ) -> Result<reqwest::blocking::Client, ServoNetworkError> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&resolved_target.host, &[resolved_target.socket]);
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

fn redirect_request(
    request: &ServoNetworkRequest,
    response: &ServoNetworkResponse,
) -> Result<Option<ServoNetworkRequest>, ServoNetworkError> {
    if !is_redirect_status(response.status) {
        return Ok(None);
    }
    let Some(location) = response_header(&response.headers, "location") else {
        return Ok(None);
    };

    let base = reqwest::Url::parse(&request.url).map_err(|error| ServoNetworkError::Redirect {
        url: request.url.clone(),
        reason: error.to_string(),
    })?;
    let next_url = base
        .join(location)
        .map_err(|error| ServoNetworkError::Redirect {
            url: request.url.clone(),
            reason: error.to_string(),
        })?
        .to_string();

    let mut next = request.clone();
    next.url = next_url;
    if !same_origin(&request.url, &next.url)? {
        next.headers
            .retain(|(name, _)| !is_cross_origin_redirect_sensitive_header(name));
    }
    if redirects_to_get(response.status, &request.method) {
        next.method = "GET".into();
        next.body.clear();
        next.body_len = 0;
        next.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("content-type")
        });
    }
    Ok(Some(next))
}

fn same_origin(left: &str, right: &str) -> Result<bool, ServoNetworkError> {
    let left = reqwest::Url::parse(left).map_err(|error| ServoNetworkError::Redirect {
        url: left.into(),
        reason: error.to_string(),
    })?;
    let right = reqwest::Url::parse(right).map_err(|error| ServoNetworkError::Redirect {
        url: right.into(),
        reason: error.to_string(),
    })?;

    Ok(left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default())
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn redirects_to_get(status: u16, method: &str) -> bool {
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    if status == 303 {
        return true;
    }
    matches!(status, 301 | 302) && method.eq_ignore_ascii_case("POST")
}

fn response_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_cross_origin_redirect_sensitive_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("signature")
        || name.eq_ignore_ascii_case("signature-input")
        || name.eq_ignore_ascii_case("signature-agent")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedTarget {
    host: String,
    socket: SocketAddr,
}

impl ResolvedTarget {
    fn from_url(url: &str) -> Result<Self, ServoNetworkError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|error| ServoNetworkError::ResolveTarget {
                url: url.into(),
                reason: error.to_string(),
            })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| ServoNetworkError::ResolveTarget {
                url: url.into(),
                reason: "URL has no host".into(),
            })?
            .to_string();
        let port =
            parsed
                .port_or_known_default()
                .ok_or_else(|| ServoNetworkError::ResolveTarget {
                    url: url.into(),
                    reason: "URL has no known default port".into(),
                })?;
        let socket = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| ServoNetworkError::ResolveTarget {
                url: url.into(),
                reason: error.to_string(),
            })?
            .next()
            .ok_or_else(|| ServoNetworkError::ResolveTarget {
                url: url.into(),
                reason: "host resolved to no socket addresses".into(),
            })?;
        Ok(Self { host, socket })
    }
}

struct ServoSigningConfig {
    key: WebBotAuthSigningKey,
    created: u64,
    expires: Option<u64>,
    nonce: Option<String>,
    signature_agent: Option<String>,
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
    #[error("servo IPC driver blocking task failed: {0}")]
    DriverTask(String),
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
    #[error("failed to resolve request target {url}: {reason}")]
    ResolveTarget { url: String, reason: String },
    #[error("invalid redirect from {url}: {reason}")]
    Redirect { url: String, reason: String },
    #[error("too many redirects while reissuing Servo request: max {max}")]
    TooManyRedirects { max: usize },
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
    use std::net::{SocketAddr, TcpListener, TcpStream};
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
    fn servo_platform_matrix_tracks_android_and_openharmony() -> TestResult {
        let platforms = servo_platform_support_matrix();
        let names: Vec<_> = platforms.iter().map(|support| support.platform).collect();

        assert_eq!(
            names,
            vec![
                ServoRuntimePlatform::Macos,
                ServoRuntimePlatform::Linux,
                ServoRuntimePlatform::Windows,
                ServoRuntimePlatform::Android,
                ServoRuntimePlatform::OpenHarmony,
            ]
        );

        let android = platforms
            .iter()
            .find(|support| support.platform == ServoRuntimePlatform::Android)
            .ok_or("missing android support entry")?;
        assert!(android.servo_available);
        assert_eq!(
            android.control_transport,
            ServoControlPlaneTransport::UnixDomainSocket
        );
        assert!(android
            .rust_targets
            .contains(&"aarch64-linux-android".to_string()));

        let openharmony = platforms
            .iter()
            .find(|support| support.platform == ServoRuntimePlatform::OpenHarmony)
            .ok_or("missing openharmony support entry")?;
        assert!(openharmony.servo_available);
        assert_eq!(
            openharmony.control_transport,
            ServoControlPlaneTransport::UnixDomainSocket
        );
        assert!(openharmony
            .rust_targets
            .contains(&"aarch64-unknown-linux-ohos".to_string()));

        let windows = platforms
            .iter()
            .find(|support| support.platform == ServoRuntimePlatform::Windows)
            .ok_or("missing windows support entry")?;
        assert!(windows.servo_available);
        assert_eq!(
            windows.control_transport,
            ServoControlPlaneTransport::WindowsNativePlanned
        );
        Ok(())
    }

    #[test]
    fn vanilla_servo_build_plan_requires_feature_or_returns_private_mapping() -> TestResult {
        let config = ServoEngineConfig::vanilla();

        let result = vanilla_servo_build_plan(&config);

        #[cfg(feature = "servo-vanilla")]
        {
            let plan = result?;
            assert_eq!(plan.servo_crate_version, PINNED_VANILLA_SERVO_VERSION);
            assert_eq!(plan.build_flavor, ServoBuildFlavor::Vanilla);
            assert!(plan
                .supported_platforms
                .iter()
                .any(|support| support.platform == ServoRuntimePlatform::Android));
            assert_eq!(plan.viewport, config.viewport);
            assert_eq!(plan.user_agent, config.user_agent);
            assert!(plan.access_tree);
            assert!(plan.intercept_network);
        }

        #[cfg(not(feature = "servo-vanilla"))]
        {
            assert!(matches!(result, Err(Unsupported(_))));
        }
        Ok(())
    }

    #[cfg(feature = "servo-vanilla")]
    #[test]
    fn vanilla_servo_build_plan_rejects_tempo_fork_config() {
        let result = vanilla_servo_build_plan(&ServoEngineConfig::tempo_fork());

        assert!(matches!(result, Err(Unsupported(_))));
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
            ServoEmbedderCommand::from_action(Action::Wait { millis: 250 }),
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
                ServoEmbedderCommand::Wait { millis: 250 },
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
    fn servo_network_adapter_blocks_private_resolved_socket_before_network() -> TestResult {
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared);
        let request = ServoNetworkRequest::new("req-1", "GET", "https://public.example/data");
        let network_request =
            request.to_network_request(&adapter.profile_id, adapter.identity_mode)?;

        let error = adapter
            .fetch_with_resolved_target(
                &request,
                network_request,
                ResolvedTarget {
                    host: "public.example".into(),
                    socket: SocketAddr::from(([169, 254, 169, 254], 443)),
                },
            )
            .err()
            .ok_or_else(|| io::Error::other("expected resolved socket policy failure"))?;

        assert!(matches!(error, ServoNetworkError::Url(_)));
        Ok(())
    }

    #[test]
    fn servo_network_adapter_blocks_private_redirect_resolved_socket_before_network() -> TestResult
    {
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared);
        let original = ServoNetworkRequest::new("req-1", "GET", "https://public.example/start");
        let redirect_response = ServoNetworkResponse {
            request_id: "req-1".into(),
            status: 302,
            headers: vec![("location".into(), "https://redirect.example/latest".into())],
            body: Vec::new(),
        };
        let redirected = redirect_request(&original, &redirect_response)?
            .ok_or_else(|| io::Error::other("expected redirect request"))?;
        let network_request =
            redirected.to_network_request(&adapter.profile_id, adapter.identity_mode)?;

        let error = adapter
            .audit_checked_target(
                &network_request,
                &ResolvedTarget {
                    host: "redirect.example".into(),
                    socket: SocketAddr::from(([169, 254, 169, 254], 443)),
                },
            )
            .err()
            .ok_or_else(|| io::Error::other("expected resolved socket policy failure"))?;

        assert!(matches!(error, ServoNetworkError::Url(_)));
        Ok(())
    }

    #[test]
    fn servo_network_redirect_request_rebases_relative_location_and_switches_post_to_get(
    ) -> TestResult {
        let request = ServoNetworkRequest::new("req-1", "POST", "https://public.example/a/form")
            .with_header("content-type", "application/json")
            .with_header("x-keep", "yes")
            .with_body(br#"{"ok":true}"#.to_vec());
        let response = ServoNetworkResponse {
            request_id: "req-1".into(),
            status: 303,
            headers: vec![("Location".into(), "../done?ok=1".into())],
            body: Vec::new(),
        };

        let redirected = redirect_request(&request, &response)?
            .ok_or_else(|| io::Error::other("expected redirect request"))?;

        assert_eq!(redirected.url, "https://public.example/done?ok=1");
        assert_eq!(redirected.method, "GET");
        assert_eq!(redirected.body_len, 0);
        assert!(redirected.body.is_empty());
        assert!(redirected
            .headers
            .iter()
            .any(|(name, value)| name == "x-keep" && value == "yes"));
        assert!(!redirected
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type")));
        Ok(())
    }

    #[test]
    fn servo_network_redirect_request_preserves_non_post_302_method_and_body() -> TestResult {
        let request = ServoNetworkRequest::new("req-1", "PUT", "https://public.example/a/item")
            .with_header("content-type", "application/json")
            .with_body(br#"{"ok":true}"#.to_vec());
        let response = ServoNetworkResponse {
            request_id: "req-1".into(),
            status: 302,
            headers: vec![("location".into(), "/moved".into())],
            body: Vec::new(),
        };

        let redirected = redirect_request(&request, &response)?
            .ok_or_else(|| io::Error::other("expected redirect request"))?;

        assert_eq!(redirected.url, "https://public.example/moved");
        assert_eq!(redirected.method, "PUT");
        assert_eq!(redirected.body_len, request.body_len);
        assert_eq!(redirected.body, request.body);
        assert!(redirected
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type")));
        Ok(())
    }

    #[test]
    fn servo_network_redirect_request_strips_sensitive_headers_cross_origin() -> TestResult {
        let request = ServoNetworkRequest::new("req-1", "GET", "https://trusted.example/start")
            .with_header("authorization", "Bearer secret")
            .with_header("cookie", "session=secret")
            .with_header("proxy-authorization", "Basic secret")
            .with_header("signature", "sig1=:abc:")
            .with_header("signature-input", "sig1=(\"@method\")")
            .with_header("signature-agent", "agent")
            .with_header("accept", "text/html");
        let response = ServoNetworkResponse {
            request_id: "req-1".into(),
            status: 302,
            headers: vec![("location".into(), "https://other.example/next".into())],
            body: Vec::new(),
        };

        let redirected = redirect_request(&request, &response)?
            .ok_or_else(|| io::Error::other("expected redirect request"))?;

        assert_eq!(redirected.url, "https://other.example/next");
        assert!(redirected
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value == "text/html"));
        for sensitive in [
            "authorization",
            "cookie",
            "proxy-authorization",
            "signature",
            "signature-input",
            "signature-agent",
        ] {
            assert!(
                !redirected
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(sensitive)),
                "{sensitive} should be stripped on cross-origin redirect"
            );
        }
        Ok(())
    }

    #[test]
    fn servo_network_redirect_request_preserves_sensitive_headers_same_origin() -> TestResult {
        let request = ServoNetworkRequest::new("req-1", "GET", "https://trusted.example/start")
            .with_header("authorization", "Bearer secret")
            .with_header("cookie", "session=secret");
        let response = ServoNetworkResponse {
            request_id: "req-1".into(),
            status: 307,
            headers: vec![("location".into(), "/next".into())],
            body: Vec::new(),
        };

        let redirected = redirect_request(&request, &response)?
            .ok_or_else(|| io::Error::other("expected redirect request"))?;

        assert_eq!(redirected.url, "https://trusted.example/next");
        assert!(redirected
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization")));
        assert!(redirected
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("cookie")));
        Ok(())
    }

    #[test]
    fn servo_network_adapter_blocks_percent_encoded_metadata_before_network() -> TestResult {
        // Issue #79 follow-up: the fetch path passes request.url verbatim to
        // both the URL policy and reqwest. A percent-encoded metadata host must
        // be rejected by the guard (which now shares the WHATWG host parser),
        // never reaching the network.
        let adapter = ServoNetworkAdapter::new("profile-a", IdentityMode::AgentDeclared);
        let request =
            ServoNetworkRequest::new("req-1", "GET", "https://169%2e254%2e169%2e254/latest");

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
            .with_web_bot_auth_signature_agent(
                signing_key,
                123,
                423,
                "test-nonce",
                "https://signature-agent.test",
            );
        let request = ServoNetworkRequest::new("req-1", "GET", format!("{origin}/signed"));

        let fetch = adapter.fetch(&request)?;
        join_server(server)?;
        let captured = captured_request
            .recv_timeout(StdDuration::from_secs(1))?
            .to_ascii_lowercase();

        assert_eq!(fetch.signed_headers.len(), 3);
        assert!(captured.contains("\r\nsignature-agent: \"https://signature-agent.test\""));
        assert!(captured.contains("\r\nsignature-input:"));
        assert!(captured.contains("expires=423"));
        assert!(captured.contains("tag=\"web-bot-auth\""));
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

    #[tokio::test(flavor = "current_thread")]
    async fn request_is_offloaded_from_the_current_thread_runtime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (client_stream, server_stream) = UnixStream::pair()?;
        let (release_tx, release_rx) = mpsc::channel::<()>();

        // The server runs on its own OS thread. It reads the request, then waits
        // for a release signal that is only produced by a *second* task on the
        // same single-threaded tokio runtime. If `request` blocked the runtime's
        // only worker inline, that second task could never run and this would
        // deadlock; offloading via spawn_blocking lets both make progress.
        let server = thread::spawn(move || -> Result<(), EngineHostError> {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let request = connection.read_driver_request()?;
            release_rx
                .recv()
                .map_err(|error| EngineHostError::Io(io::Error::other(error.to_string())))?;
            let observation = CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: "https://servo.test".into(),
                seq: 1,
                elements: Vec::new(),
                marks: Vec::new(),
            };
            connection
                .write_driver_response(request.id, DriverResponse::Observation { observation })?;
            Ok(())
        });

        let mut driver = ServoIpcDriver::from_client(
            ServoEngineConfig::vanilla(),
            EngineIpcClient::from_stream(client_stream),
        );

        let ran_concurrently = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran_concurrently);
        let releaser = async move {
            flag.store(true, Ordering::SeqCst);
            // Release the (otherwise blocked) server now that concurrency is proven.
            let _ = release_tx.send(());
        };

        let (observation, ()) = tokio::join!(driver.goto("https://servo.test"), releaser);
        let observation = observation?;
        server
            .join()
            .map_err(|_| Box::<dyn std::error::Error>::from("server thread panicked"))??;

        assert!(ran_concurrently.load(Ordering::SeqCst));
        assert_eq!(observation.url, "https://servo.test");
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
