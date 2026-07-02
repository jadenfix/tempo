//! tempo-net - network policy, profile isolation, audit records, and quiescence.
//!
//! This crate is the standalone WS6 foundation from `final.md`: the browser
//! network layer must reject SSRF targets before engine navigation, keep each
//! session in an isolated profile, emit audit records that do not carry page
//! payloads, and expose network-idle counters for the action quiescence gate.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Stable request identifier used by audit and quiescence records.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub String);

impl From<&str> for RequestId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for RequestId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Session identifier supplied by `tempo-session`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub String);

impl From<&str> for SessionId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Profile identifier used to partition cookies and storage.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId(pub String);

impl From<&str> for ProfileId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for ProfileId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// URL guard mode. Live tempo traffic defaults to `BlockPrivate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlPolicyMode {
    /// Permit every URL. Intended for trusted tests and explicit local override.
    AllowAll,
    /// Block non-http(s), loopback, private, link-local, multicast, and metadata targets.
    BlockPrivate,
}

/// Pure URL policy used before network traffic is issued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlPolicy {
    mode: UrlPolicyMode,
}

impl UrlPolicy {
    /// Permit every URL without parsing.
    pub const fn allow_all() -> Self {
        Self {
            mode: UrlPolicyMode::AllowAll,
        }
    }

    /// Block private/loopback/link-local/metadata targets. This is the secure default.
    pub const fn block_private() -> Self {
        Self {
            mode: UrlPolicyMode::BlockPrivate,
        }
    }

    /// Evaluate a target URL without issuing network traffic.
    pub fn check(&self, url: &str) -> UrlPolicyVerdict {
        if self.mode == UrlPolicyMode::AllowAll {
            return UrlPolicyVerdict::Allow;
        }

        let Some((scheme, _)) = url.split_once("://") else {
            return UrlPolicyVerdict::Block(BlockReason::new(
                BlockCode::InvalidUrl,
                "URL has no scheme separator",
            ));
        };
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return UrlPolicyVerdict::Block(BlockReason::new(
                BlockCode::UnsupportedScheme,
                format!("scheme '{scheme}' is not http or https"),
            ));
        }

        let parts = match UrlParts::parse(url) {
            Ok(parts) => parts,
            Err(reason) => return UrlPolicyVerdict::Block(reason),
        };

        let host_for_name_checks = parts.host.trim_end_matches('.');
        if host_for_name_checks == "localhost" || host_for_name_checks.ends_with(".localhost") {
            return UrlPolicyVerdict::Block(BlockReason::new(
                BlockCode::Localhost,
                "localhost names resolve to loopback",
            ));
        }

        let ip = parts
            .host
            .parse::<IpAddr>()
            .ok()
            .or_else(|| parse_relaxed_ipv4(&parts.host).map(IpAddr::V4));
        if let Some(ip) = ip {
            if let Some(detail) = blocked_ip_reason(&ip) {
                return UrlPolicyVerdict::Block(BlockReason::new(BlockCode::BlockedIp, detail));
            }
        }

        UrlPolicyVerdict::Allow
    }

    /// Return `Err` when `check` would block the URL.
    pub fn enforce(&self, url: &str) -> Result<(), UrlBlocked> {
        match self.check(url) {
            UrlPolicyVerdict::Allow => Ok(()),
            UrlPolicyVerdict::Block(reason) => Err(UrlBlocked { reason }),
        }
    }
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self::block_private()
    }
}

/// Result of a URL policy check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlPolicyVerdict {
    Allow,
    Block(BlockReason),
}

impl UrlPolicyVerdict {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Stable machine-readable reason for a blocked URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCode {
    InvalidUrl,
    UnsupportedScheme,
    EmptyHost,
    MalformedIpv6,
    Localhost,
    BlockedIp,
}

/// Human-readable block reason paired with a stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReason {
    pub code: BlockCode,
    pub detail: String,
}

impl BlockReason {
    fn new(code: BlockCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// URL policy enforcement failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBlocked {
    pub reason: BlockReason,
}

impl fmt::Display for UrlBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "URL blocked: {}", self.reason.detail)
    }
}

impl Error for UrlBlocked {}

/// A component covered by an RFC 9421 HTTP Message Signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoveredComponent {
    Method,
    Authority,
    Scheme,
    Path,
    Query,
    TargetUri,
    Header(String),
}

impl CoveredComponent {
    pub fn method() -> Self {
        Self::Method
    }

    pub fn authority() -> Self {
        Self::Authority
    }

    pub fn scheme() -> Self {
        Self::Scheme
    }

    pub fn path() -> Self {
        Self::Path
    }

    pub fn query() -> Self {
        Self::Query
    }

    pub fn target_uri() -> Self {
        Self::TargetUri
    }

    pub fn header(name: impl Into<String>) -> Self {
        Self::Header(name.into().to_ascii_lowercase())
    }

    fn identifier(&self) -> String {
        match self {
            Self::Method => "@method".into(),
            Self::Authority => "@authority".into(),
            Self::Scheme => "@scheme".into(),
            Self::Path => "@path".into(),
            Self::Query => "@query".into(),
            Self::TargetUri => "@target-uri".into(),
            Self::Header(name) => name.clone(),
        }
    }

    fn from_identifier(identifier: &str) -> Self {
        match identifier {
            "@method" => Self::Method,
            "@authority" => Self::Authority,
            "@scheme" => Self::Scheme,
            "@path" => Self::Path,
            "@query" => Self::Query,
            "@target-uri" => Self::TargetUri,
            name => Self::Header(name.to_ascii_lowercase()),
        }
    }
}

/// Ed25519 signing key for Web Bot Auth / RFC 9421 message signatures.
#[derive(Clone)]
pub struct WebBotAuthSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl WebBotAuthSigningKey {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self, SignatureError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| SignatureError::InvalidKey("ed25519 seed must be 32 bytes".into()))?;
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifier(&self) -> WebBotAuthVerifier {
        WebBotAuthVerifier {
            key_id: self.key_id.clone(),
            verifying_key: self.signing_key.verifying_key(),
        }
    }
}

/// Ed25519 verification key for incoming or replayed Web Bot Auth signatures.
#[derive(Clone, Debug)]
pub struct WebBotAuthVerifier {
    key_id: String,
    verifying_key: VerifyingKey,
}

impl WebBotAuthVerifier {
    pub fn from_public_key(
        key_id: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Self, SignatureError> {
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
            SignatureError::InvalidKey("ed25519 public key must be 32 bytes".into())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|err| SignatureError::InvalidKey(err.to_string()))?;
        Ok(Self {
            key_id: key_id.into(),
            verifying_key,
        })
    }
}

/// RFC 9421 signature parameters for one signature label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureParameters {
    pub label: String,
    pub key_id: String,
    pub created: u64,
    pub components: Vec<CoveredComponent>,
}

impl SignatureParameters {
    /// Default Web Bot Auth coverage: method, authority, scheme, and path.
    pub fn web_bot_auth(key_id: impl Into<String>, created: u64) -> Self {
        Self {
            label: "sig1".into(),
            key_id: key_id.into(),
            created,
            components: vec![
                CoveredComponent::Method,
                CoveredComponent::Authority,
                CoveredComponent::Scheme,
                CoveredComponent::Path,
            ],
        }
    }

    fn signature_input_value(&self) -> String {
        let covered = self
            .components
            .iter()
            .map(|component| format!("\"{}\"", component.identifier()))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{}=({covered});created={};keyid=\"{}\";alg=\"ed25519\"",
            self.label,
            self.created,
            escape_sf_string(&self.key_id)
        )
    }

    fn signature_params_value(&self) -> String {
        let input = self.signature_input_value();
        let prefix = format!("{}=", self.label);
        input
            .strip_prefix(&prefix)
            .unwrap_or(input.as_str())
            .to_string()
    }
}

/// Headers produced by signing an HTTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureHeaders {
    pub signature_input: String,
    pub signature: String,
}

impl SignatureHeaders {
    pub fn as_header_pairs(&self) -> [(&'static str, &str); 2] {
        [
            ("Signature-Input", self.signature_input.as_str()),
            ("Signature", self.signature.as_str()),
        ]
    }
}

/// Errors returned while building or checking HTTP message signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    InvalidKey(String),
    InvalidSignatureInput(String),
    MissingComponent(String),
    UnsupportedAlgorithm(String),
    KeyIdMismatch { expected: String, actual: String },
    InvalidSignature(String),
    VerificationFailed,
    Url(BlockReason),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(reason) => write!(f, "invalid key: {reason}"),
            Self::InvalidSignatureInput(reason) => write!(f, "invalid signature input: {reason}"),
            Self::MissingComponent(name) => write!(f, "missing signed component: {name}"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported signature algorithm: {alg}"),
            Self::KeyIdMismatch { expected, actual } => {
                write!(
                    f,
                    "signature key id mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignature(reason) => write!(f, "invalid signature: {reason}"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::Url(reason) => write!(f, "invalid signed URL: {}", reason.detail),
        }
    }
}

impl Error for SignatureError {}

/// Per-session browser profile kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileKind {
    /// Fresh cookie jar and storage partition for one session.
    Ephemeral,
    /// Named profile for an explicitly durable login surface.
    Durable,
}

/// Isolated browser profile metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkProfile {
    pub id: ProfileId,
    pub session_id: SessionId,
    pub kind: ProfileKind,
    pub cookie_partition: String,
    pub storage_partition: String,
}

impl NetworkProfile {
    /// Deterministic ephemeral profile for one session.
    pub fn ephemeral(session_id: impl Into<SessionId>) -> Self {
        let session_id = session_id.into();
        let suffix = stable_partition_suffix(&session_id.0);
        Self {
            id: ProfileId(format!("ephemeral-{suffix}")),
            session_id,
            kind: ProfileKind::Ephemeral,
            cookie_partition: format!("cookies-{suffix}"),
            storage_partition: format!("storage-{suffix}"),
        }
    }

    /// Durable profile tied to a caller-supplied name.
    pub fn durable(session_id: impl Into<SessionId>, name: impl Into<String>) -> Self {
        let session_id = session_id.into();
        let name = name.into();
        let suffix = stable_partition_suffix(&format!("{}:{name}", session_id.0));
        Self {
            id: ProfileId(format!("durable-{suffix}")),
            session_id,
            kind: ProfileKind::Durable,
            cookie_partition: format!("cookies-{suffix}"),
            storage_partition: format!("storage-{suffix}"),
        }
    }
}

/// Minimal cookie representation for profile-isolation tests and driver adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    pub origin: String,
    pub name: String,
    pub value: String,
}

/// Deterministic profile manager with isolated cookie partitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileStore {
    profiles: BTreeMap<ProfileId, NetworkProfile>,
    cookies: BTreeMap<ProfileId, BTreeMap<String, BTreeMap<String, String>>>,
}

impl ProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_ephemeral(&mut self, session_id: impl Into<SessionId>) -> NetworkProfile {
        let profile = NetworkProfile::ephemeral(session_id);
        self.profiles.insert(profile.id.clone(), profile.clone());
        self.cookies.entry(profile.id.clone()).or_default();
        profile
    }

    pub fn create_durable(
        &mut self,
        session_id: impl Into<SessionId>,
        name: impl Into<String>,
    ) -> NetworkProfile {
        let profile = NetworkProfile::durable(session_id, name);
        self.profiles.insert(profile.id.clone(), profile.clone());
        self.cookies.entry(profile.id.clone()).or_default();
        profile
    }

    pub fn profile(&self, id: &ProfileId) -> Option<&NetworkProfile> {
        self.profiles.get(id)
    }

    pub fn set_cookie(
        &mut self,
        profile_id: &ProfileId,
        origin: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), ProfileError> {
        if !self.profiles.contains_key(profile_id) {
            return Err(ProfileError::UnknownProfile(profile_id.clone()));
        }
        self.cookies
            .entry(profile_id.clone())
            .or_default()
            .entry(origin.into())
            .or_default()
            .insert(name.into(), value.into());
        Ok(())
    }

    pub fn cookies_for(&self, profile_id: &ProfileId, origin: &str) -> Vec<Cookie> {
        self.cookies
            .get(profile_id)
            .and_then(|by_origin| by_origin.get(origin))
            .map(|cookies| {
                cookies
                    .iter()
                    .map(|(name, value)| Cookie {
                        origin: origin.to_string(),
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Profile-store operation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    UnknownProfile(ProfileId),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile(id) => write!(f, "unknown profile '{}'", id.0),
        }
    }
}

impl Error for ProfileError {}

/// How tempo declares itself on the wire for this origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityMode {
    /// Human-driven browsing surface.
    UserDriven,
    /// Explicit agent traffic; callers can attach Web Bot Auth signatures.
    AgentDeclared,
}

/// Request metadata accepted by tempo-net before engine/network dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRequest {
    pub id: RequestId,
    pub method: String,
    pub url: String,
    pub profile_id: ProfileId,
    pub identity_mode: IdentityMode,
    headers: BTreeMap<String, Vec<String>>,
}

impl NetworkRequest {
    pub fn new(
        id: impl Into<RequestId>,
        method: impl Into<String>,
        url: impl Into<String>,
        profile_id: impl Into<ProfileId>,
        identity_mode: IdentityMode,
    ) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            url: url.into(),
            profile_id: profile_id.into(),
            identity_mode,
            headers: BTreeMap::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .entry(name.into().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }

    pub fn header_values(&self, name: &str) -> Option<&[String]> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
    }

    pub fn sign_web_bot_auth(
        &self,
        key: &WebBotAuthSigningKey,
        created: u64,
    ) -> Result<SignatureHeaders, SignatureError> {
        let params = SignatureParameters::web_bot_auth(key.key_id(), created);
        sign_request(self, &params, key)
    }
}

/// Sign a request with Ed25519 and return RFC 9421 `Signature-Input` and `Signature` headers.
pub fn sign_request(
    request: &NetworkRequest,
    params: &SignatureParameters,
    key: &WebBotAuthSigningKey,
) -> Result<SignatureHeaders, SignatureError> {
    if params.key_id != key.key_id() {
        return Err(SignatureError::KeyIdMismatch {
            expected: key.key_id().to_string(),
            actual: params.key_id.clone(),
        });
    }
    let base = signature_base(request, params)?;
    let signature = key.signing_key.sign(base.as_bytes());
    Ok(SignatureHeaders {
        signature_input: params.signature_input_value(),
        signature: format!("{}=:{}:", params.label, BASE64.encode(signature.to_bytes())),
    })
}

/// Verify RFC 9421 `Signature-Input` and `Signature` headers against a request.
pub fn verify_request_signature(
    request: &NetworkRequest,
    signature_input: &str,
    signature: &str,
    verifier: &WebBotAuthVerifier,
) -> Result<(), SignatureError> {
    let params = parse_signature_input(signature_input)?;
    if params.key_id != verifier.key_id {
        return Err(SignatureError::KeyIdMismatch {
            expected: verifier.key_id.clone(),
            actual: params.key_id.clone(),
        });
    }
    let signature_bytes = parse_signature_header(signature, &params.label)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| SignatureError::InvalidSignature(err.to_string()))?;
    let base = signature_base(request, &params)?;
    verifier
        .verifying_key
        .verify(base.as_bytes(), &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Construct the canonical signature base string for tests and reference verification.
pub fn signature_base(
    request: &NetworkRequest,
    params: &SignatureParameters,
) -> Result<String, SignatureError> {
    let parts = UrlParts::parse(&request.url).map_err(SignatureError::Url)?;
    let mut lines = Vec::with_capacity(params.components.len() + 1);
    for component in &params.components {
        let identifier = component.identifier();
        let value = component_value(request, &parts, component)?;
        lines.push(format!("\"{identifier}\": {value}"));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        params.signature_params_value()
    ));
    Ok(lines.join("\n"))
}

/// Audit record safe to persist in the session journal. It intentionally omits
/// request body, response body, headers, path, query, and fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub request_id: RequestId,
    pub method: String,
    pub origin: String,
    pub profile_id: ProfileId,
    pub identity_mode: IdentityMode,
    pub taint_free: bool,
}

impl AuditRecord {
    /// Enforce URL policy and emit a sanitized, taint-free audit record.
    pub fn from_request(request: &NetworkRequest, policy: &UrlPolicy) -> Result<Self, UrlBlocked> {
        policy.enforce(&request.url)?;
        let parts = UrlParts::parse(&request.url).map_err(|reason| UrlBlocked { reason })?;
        Ok(Self {
            request_id: request.id.clone(),
            method: request.method.to_ascii_uppercase(),
            origin: parts.origin(),
            profile_id: request.profile_id.clone(),
            identity_mode: request.identity_mode,
            taint_free: true,
        })
    }
}

/// Outcome used by network quiescence accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    Completed,
    Failed,
}

/// Pure network-idle counter. Ticks are supplied by the caller, so tests and
/// replay are deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuiescenceCounters {
    inflight: BTreeSet<RequestId>,
    started: u64,
    completed: u64,
    failed: u64,
    last_activity_tick: u64,
}

impl QuiescenceCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin(&mut self, request_id: impl Into<RequestId>, tick: u64) {
        let inserted = self.inflight.insert(request_id.into());
        if inserted {
            self.started += 1;
        }
        self.last_activity_tick = tick;
    }

    pub fn finish(&mut self, request_id: &RequestId, outcome: RequestOutcome, tick: u64) -> bool {
        let removed = self.inflight.remove(request_id);
        if removed {
            match outcome {
                RequestOutcome::Completed => self.completed += 1,
                RequestOutcome::Failed => self.failed += 1,
            }
            self.last_activity_tick = tick;
        }
        removed
    }

    pub fn inflight(&self) -> usize {
        self.inflight.len()
    }

    pub fn totals(&self) -> QuiescenceTotals {
        QuiescenceTotals {
            started: self.started,
            completed: self.completed,
            failed: self.failed,
        }
    }

    pub fn last_activity_tick(&self) -> u64 {
        self.last_activity_tick
    }

    pub fn network_idle_at(&self, tick: u64, quiet_ticks: u64) -> bool {
        self.inflight.is_empty() && tick.saturating_sub(self.last_activity_tick) >= quiet_ticks
    }
}

/// Snapshot of quiescence accounting totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuiescenceTotals {
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
}

fn component_value(
    request: &NetworkRequest,
    parts: &UrlParts,
    component: &CoveredComponent,
) -> Result<String, SignatureError> {
    match component {
        CoveredComponent::Method => Ok(request.method.clone()),
        CoveredComponent::Authority => Ok(parts.authority_component()),
        CoveredComponent::Scheme => Ok(parts.scheme.clone()),
        CoveredComponent::Path => Ok(parts.path.clone()),
        CoveredComponent::Query => Ok(parts.query.clone().unwrap_or_else(|| "?".into())),
        CoveredComponent::TargetUri => Ok(parts.target_uri()),
        CoveredComponent::Header(name) => request
            .header_values(name)
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.trim())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .ok_or_else(|| SignatureError::MissingComponent(name.clone())),
    }
}

fn parse_signature_input(input: &str) -> Result<SignatureParameters, SignatureError> {
    let (label, rest) = input
        .split_once('=')
        .ok_or_else(|| SignatureError::InvalidSignatureInput("missing label".into()))?;
    let rest = rest.trim();
    let component_start = rest
        .find('(')
        .ok_or_else(|| SignatureError::InvalidSignatureInput("missing component list".into()))?;
    let component_end = rest.find(')').ok_or_else(|| {
        SignatureError::InvalidSignatureInput("missing component list end".into())
    })?;
    if component_end < component_start {
        return Err(SignatureError::InvalidSignatureInput(
            "component list is malformed".into(),
        ));
    }

    let components_raw = &rest[component_start + 1..component_end];
    let mut components = Vec::new();
    for token in components_raw.split_whitespace() {
        let identifier = token.trim_matches('"');
        if identifier.is_empty() {
            return Err(SignatureError::InvalidSignatureInput(
                "empty covered component".into(),
            ));
        }
        components.push(CoveredComponent::from_identifier(identifier));
    }
    if components.is_empty() {
        return Err(SignatureError::InvalidSignatureInput(
            "no covered components".into(),
        ));
    }

    let mut created = None;
    let mut key_id = None;
    let mut alg = None;
    for param in rest[component_end + 1..]
        .split(';')
        .filter(|part| !part.is_empty())
    {
        let (name, value) = param
            .split_once('=')
            .ok_or_else(|| SignatureError::InvalidSignatureInput("bad parameter".into()))?;
        match name {
            "created" => {
                created = Some(value.parse::<u64>().map_err(|_| {
                    SignatureError::InvalidSignatureInput("bad created parameter".into())
                })?);
            }
            "keyid" => key_id = Some(unquote_sf_string(value)?),
            "alg" => alg = Some(unquote_sf_string(value)?),
            _ => {}
        }
    }

    let alg = alg.ok_or_else(|| SignatureError::InvalidSignatureInput("missing alg".into()))?;
    if alg != "ed25519" {
        return Err(SignatureError::UnsupportedAlgorithm(alg));
    }

    Ok(SignatureParameters {
        label: label.to_string(),
        key_id: key_id
            .ok_or_else(|| SignatureError::InvalidSignatureInput("missing keyid".into()))?,
        created: created
            .ok_or_else(|| SignatureError::InvalidSignatureInput("missing created".into()))?,
        components,
    })
}

fn parse_signature_header(signature: &str, label: &str) -> Result<Vec<u8>, SignatureError> {
    let prefix = format!("{label}=:");
    let encoded = signature
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(':'))
        .ok_or_else(|| SignatureError::InvalidSignature("bad signature header".into()))?;
    BASE64
        .decode(encoded)
        .map_err(|err| SignatureError::InvalidSignature(err.to_string()))
}

fn escape_sf_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unquote_sf_string(value: &str) -> Result<String, SignatureError> {
    let quoted = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| SignatureError::InvalidSignatureInput("expected quoted string".into()))?;
    let mut output = String::new();
    let mut chars = quoted.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next().ok_or_else(|| {
                SignatureError::InvalidSignatureInput("bad quoted string escape".into())
            })?;
            output.push(escaped);
        } else {
            output.push(ch);
        }
    }
    Ok(output)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UrlParts {
    scheme: String,
    host: String,
    audit_host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

impl UrlParts {
    fn parse(url: &str) -> Result<Self, BlockReason> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            BlockReason::new(BlockCode::InvalidUrl, "URL has no scheme separator")
        })?;
        let scheme = scheme.to_ascii_lowercase();
        let authority = authority(rest);
        let authority = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        if authority.is_empty() {
            return Err(BlockReason::new(BlockCode::EmptyHost, "URL host is empty"));
        }

        let (host, audit_host, port) = parse_authority(authority)?;
        if host.is_empty() {
            return Err(BlockReason::new(BlockCode::EmptyHost, "URL host is empty"));
        }

        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            audit_host: audit_host.to_ascii_lowercase(),
            port,
            path: path_component(rest),
            query: query_component(rest),
        })
    }

    fn origin(&self) -> String {
        match self.non_default_port() {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.audit_host),
            None => format!("{}://{}", self.scheme, self.audit_host),
        }
    }

    fn authority_component(&self) -> String {
        match self.non_default_port() {
            Some(port) => format!("{}:{port}", self.audit_host),
            None => self.audit_host.clone(),
        }
    }

    fn target_uri(&self) -> String {
        let mut value = format!(
            "{}://{}{}",
            self.scheme,
            self.authority_component(),
            self.path
        );
        if let Some(query) = &self.query {
            value.push_str(query);
        }
        value
    }

    fn non_default_port(&self) -> Option<u16> {
        match (self.scheme.as_str(), self.port) {
            ("http", Some(80)) | ("https", Some(443)) => None,
            (_, port) => port,
        }
    }
}

fn authority(rest: &str) -> &str {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

fn path_component(rest: &str) -> String {
    let after_authority = &rest[authority(rest).len()..];
    if !after_authority.starts_with('/') {
        return "/".into();
    }
    let end = after_authority
        .find(['?', '#'])
        .unwrap_or(after_authority.len());
    after_authority[..end].to_string()
}

fn query_component(rest: &str) -> Option<String> {
    let after_authority = &rest[authority(rest).len()..];
    let query_start = after_authority.find('?')?;
    let after_query = &after_authority[query_start..];
    let query_end = after_query.find('#').unwrap_or(after_query.len());
    Some(after_query[..query_end].to_string())
}

fn parse_authority(authority: &str) -> Result<(String, String, Option<u16>), BlockReason> {
    if authority.starts_with('[') {
        let (bracketed, after) = authority.split_once(']').ok_or_else(|| {
            BlockReason::new(BlockCode::MalformedIpv6, "malformed bracketed IPv6 host")
        })?;
        let inner = &bracketed[1..];
        let host = strip_ipv6_zone(inner).to_string();
        let port = after
            .strip_prefix(':')
            .and_then(|digits| digits.parse::<u16>().ok());
        return Ok((host.clone(), format!("[{host}]"), port));
    }

    if authority.contains(':') {
        let (host, port_raw) = authority
            .rsplit_once(':')
            .ok_or_else(|| BlockReason::new(BlockCode::InvalidUrl, "malformed authority"))?;
        if port_raw.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok((
                host.to_string(),
                host.to_string(),
                port_raw.parse::<u16>().ok(),
            ));
        }
    }

    Ok((authority.to_string(), authority.to_string(), None))
}

fn strip_ipv6_zone(host: &str) -> &str {
    host.split_once("%25")
        .map(|(addr, _)| addr)
        .or_else(|| host.split_once('%').map(|(addr, _)| addr))
        .unwrap_or(host)
}

fn parse_relaxed_ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }

    let nums: Option<Vec<u64>> = parts.iter().map(|part| parse_ipv4_part(part)).collect();
    let nums = nums?;
    let n = nums.len();
    if nums[..n - 1].iter().any(|&value| value > 0xff) {
        return None;
    }

    let remaining_bytes = (4 - (n - 1)) as u32;
    let max_last = (1u64 << (8 * remaining_bytes)) - 1;
    let last = nums[n - 1];
    if last > max_last {
        return None;
    }

    let mut addr = 0u32;
    for (i, &value) in nums[..n - 1].iter().enumerate() {
        addr |= (value as u32) << (8 * (3 - i as u32));
    }
    addr |= last as u32;
    Some(Ipv4Addr::from(addr))
}

fn parse_ipv4_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (radix, digits) =
        if let Some(rest) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (16, rest)
        } else if part.len() > 1 && part.starts_with('0') {
            (8, &part[1..])
        } else {
            (10, part)
        };
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, radix).ok()
}

fn blocked_ip_reason(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => blocked_ipv4_reason(v4),
        IpAddr::V6(v6) => blocked_ipv6_reason(v6),
    }
}

fn blocked_ipv4_reason(ip: &Ipv4Addr) -> Option<String> {
    let octets = ip.octets();
    if octets[0] == 127 {
        return Some(format!("{ip} is loopback"));
    }
    if octets[0] == 10 {
        return Some(format!("{ip} is RFC 1918 private"));
    }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return Some(format!("{ip} is RFC 1918 private"));
    }
    if octets[0] == 192 && octets[1] == 168 {
        return Some(format!("{ip} is RFC 1918 private"));
    }
    if octets[0] == 169 && octets[1] == 254 {
        return Some(format!("{ip} is link-local/cloud metadata"));
    }
    if octets[0] == 0 {
        return Some(format!("{ip} is unspecified"));
    }
    if (224..=239).contains(&octets[0]) {
        return Some(format!("{ip} is multicast"));
    }
    if octets[0] == 255 {
        return Some(format!("{ip} is broadcast/reserved"));
    }
    None
}

fn blocked_ipv6_reason(ip: &Ipv6Addr) -> Option<String> {
    if *ip == Ipv6Addr::LOCALHOST {
        return Some(format!("{ip} is loopback"));
    }
    if *ip == Ipv6Addr::UNSPECIFIED {
        return Some(format!("{ip} is unspecified"));
    }
    let segments = ip.segments();
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some(format!("{ip} is link-local"));
    }
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Some(format!("{ip} is unique-local"));
    }
    if (segments[0] & 0xff00) == 0xff00 {
        return Some(format!("{ip} is multicast"));
    }
    if let Some(mapped) = ip.to_ipv4_mapped() {
        if let Some(reason) = blocked_ipv4_reason(&mapped) {
            return Some(format!("{ip} maps to blocked IPv4: {reason}"));
        }
    }
    None
}

fn stable_partition_suffix(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_allowed(policy: &UrlPolicy, url: &str) {
        assert_eq!(policy.check(url), UrlPolicyVerdict::Allow, "{url}");
    }

    fn assert_blocked(policy: &UrlPolicy, url: &str, code: BlockCode) {
        match policy.check(url) {
            UrlPolicyVerdict::Allow => panic!("{url} unexpectedly allowed"),
            UrlPolicyVerdict::Block(reason) => assert_eq!(reason.code, code, "{url}"),
        }
    }

    #[test]
    fn url_policy_blocks_private_metadata_and_local_targets() {
        let policy = UrlPolicy::block_private();
        for url in [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.2/",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0/",
            "http://224.0.0.1/",
            "http://[::1]/",
            "http://[fe80::1%25en0]/",
            "http://[fc00::1]/",
            "http://[ff02::1]/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
        assert_blocked(&policy, "http://localhost/", BlockCode::Localhost);
        assert_blocked(&policy, "https://app.localhost/path", BlockCode::Localhost);
    }

    #[test]
    fn url_policy_blocks_browser_style_ipv4_bypasses() {
        let policy = UrlPolicy::block_private();
        for url in [
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://0x0a.0.0.1/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
    }

    #[test]
    fn url_policy_allows_public_http_targets() {
        let policy = UrlPolicy::block_private();
        assert_allowed(&policy, "https://example.com/search?q=tempo#frag");
        assert_allowed(&policy, "http://93.184.216.34/");
        assert_allowed(&policy, "https://user:pass@example.com:8443/path");
    }

    #[test]
    fn url_policy_blocks_bad_schemes_and_malformed_urls() {
        let policy = UrlPolicy::block_private();
        assert_blocked(&policy, "file:///etc/passwd", BlockCode::UnsupportedScheme);
        assert_blocked(&policy, "not-a-url", BlockCode::InvalidUrl);
        assert_blocked(&policy, "http:///missing-host", BlockCode::EmptyHost);
        assert_blocked(&policy, "http://[::1", BlockCode::MalformedIpv6);
        assert_allowed(&UrlPolicy::allow_all(), "file:///etc/passwd");
    }

    #[test]
    fn profiles_isolate_cookie_jars_per_session() {
        let mut store = ProfileStore::new();
        let first = store.create_ephemeral("session-a");
        let second = store.create_ephemeral("session-b");

        assert_ne!(first.id, second.id);
        assert_ne!(first.cookie_partition, second.cookie_partition);
        assert_ne!(first.storage_partition, second.storage_partition);

        let set_first = store.set_cookie(&first.id, "https://example.com", "sid", "a");
        assert!(set_first.is_ok(), "{set_first:?}");
        let set_second = store.set_cookie(&second.id, "https://example.com", "sid", "b");
        assert!(set_second.is_ok(), "{set_second:?}");

        assert_eq!(
            store.cookies_for(&first.id, "https://example.com"),
            vec![Cookie {
                origin: "https://example.com".into(),
                name: "sid".into(),
                value: "a".into(),
            }]
        );
        assert_eq!(
            store.cookies_for(&second.id, "https://example.com"),
            vec![Cookie {
                origin: "https://example.com".into(),
                name: "sid".into(),
                value: "b".into(),
            }]
        );
    }

    #[test]
    fn profile_store_rejects_unknown_profile_writes() {
        let mut store = ProfileStore::new();
        let err = store.set_cookie(
            &ProfileId("missing".into()),
            "https://example.com",
            "sid",
            "value",
        );
        assert!(matches!(err, Err(ProfileError::UnknownProfile(_))));
    }

    #[test]
    fn audit_record_is_taint_free_and_origin_only() {
        let profile = NetworkProfile::ephemeral("session-a");
        let request = NetworkRequest::new(
            "r1",
            "get",
            "https://user:secret@example.com:8443/path?q=page-derived#frag",
            profile.id.clone(),
            IdentityMode::AgentDeclared,
        );

        let audit = AuditRecord::from_request(&request, &UrlPolicy::block_private());
        let audit = match audit {
            Ok(audit) => audit,
            Err(err) => panic!("{err}"),
        };

        assert_eq!(audit.request_id, RequestId("r1".into()));
        assert_eq!(audit.method, "GET");
        assert_eq!(audit.origin, "https://example.com:8443");
        assert_eq!(audit.profile_id, profile.id);
        assert_eq!(audit.identity_mode, IdentityMode::AgentDeclared);
        assert!(audit.taint_free);
        assert!(!audit.origin.contains("secret"));
        assert!(!audit.origin.contains("page-derived"));
    }

    #[test]
    fn audit_record_enforces_url_policy_before_emitting() {
        let profile = NetworkProfile::ephemeral("session-a");
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "http://169.254.169.254/latest/meta-data",
            profile.id,
            IdentityMode::AgentDeclared,
        );

        let audit = AuditRecord::from_request(&request, &UrlPolicy::block_private());
        assert!(audit.is_err(), "{audit:?}");
    }

    #[test]
    fn web_bot_auth_signs_and_verifies_rfc_9421_headers() {
        let key = match WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32]) {
            Ok(key) => key,
            Err(err) => panic!("{err}"),
        };
        let verifier = key.verifier();
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com:443/agent/path?tainted=not-signed",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("accept", "application/json");

        let headers = match request.sign_web_bot_auth(&key, 1_800_000_000) {
            Ok(headers) => headers,
            Err(err) => panic!("{err}"),
        };

        assert_eq!(
            headers.signature_input,
            "sig1=(\"@method\" \"@authority\" \"@scheme\" \"@path\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.signature.ends_with(':'));

        let base = match signature_base(
            &request,
            &SignatureParameters::web_bot_auth("tempo-agent", 1_800_000_000),
        ) {
            Ok(base) => base,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(
            base,
            "\"@method\": GET\n\"@authority\": example.com\n\"@scheme\": https\n\"@path\": /agent/path\n\"@signature-params\": (\"@method\" \"@authority\" \"@scheme\" \"@path\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );

        let verified = verify_request_signature(
            &request,
            &headers.signature_input,
            &headers.signature,
            &verifier,
        );
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn web_bot_auth_rejects_tampered_requests_and_wrong_keys() {
        let key = match WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32]) {
            Ok(key) => key,
            Err(err) => panic!("{err}"),
        };
        let wrong = match WebBotAuthSigningKey::from_seed("other-agent", &[9u8; 32]) {
            Ok(key) => key.verifier(),
            Err(err) => panic!("{err}"),
        };
        let request = NetworkRequest::new(
            "r1",
            "POST",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let headers = match request.sign_web_bot_auth(&key, 1_800_000_000) {
            Ok(headers) => headers,
            Err(err) => panic!("{err}"),
        };
        let tampered = NetworkRequest::new(
            "r1",
            "POST",
            "https://example.com/other/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let tampered_result = verify_request_signature(
            &tampered,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
        );
        assert!(matches!(
            tampered_result,
            Err(SignatureError::VerificationFailed)
        ));

        let wrong_key_result = verify_request_signature(
            &request,
            &headers.signature_input,
            &headers.signature,
            &wrong,
        );
        assert!(matches!(
            wrong_key_result,
            Err(SignatureError::KeyIdMismatch { .. })
        ));
    }

    #[test]
    fn signature_base_can_cover_request_headers() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("accept", "application/json")
        .with_header("accept", "text/plain");
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: "tempo-agent".into(),
            created: 1_800_000_000,
            components: vec![CoveredComponent::Header("accept".into())],
        };

        let base = match signature_base(&request, &params) {
            Ok(base) => base,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(
            base,
            "\"accept\": application/json, text/plain\n\"@signature-params\": (\"accept\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );
    }

    #[test]
    fn quiescence_counters_track_inflight_and_idle_window() {
        let mut counters = QuiescenceCounters::new();
        assert!(counters.network_idle_at(10, 0));

        counters.begin("r1", 10);
        counters.begin("r2", 11);
        assert_eq!(counters.inflight(), 2);
        assert!(!counters.network_idle_at(20, 5));

        let finished = counters.finish(&RequestId("r1".into()), RequestOutcome::Completed, 12);
        assert!(finished);
        assert_eq!(counters.inflight(), 1);
        assert!(!counters.network_idle_at(20, 5));

        let finished = counters.finish(&RequestId("r2".into()), RequestOutcome::Failed, 14);
        assert!(finished);
        assert_eq!(counters.inflight(), 0);
        assert!(!counters.network_idle_at(18, 5));
        assert!(counters.network_idle_at(19, 5));
        assert_eq!(
            counters.totals(),
            QuiescenceTotals {
                started: 2,
                completed: 1,
                failed: 1,
            }
        );
    }

    #[test]
    fn duplicate_begin_is_idempotent_for_counts() {
        let mut counters = QuiescenceCounters::new();
        counters.begin("r1", 1);
        counters.begin("r1", 2);
        assert_eq!(counters.inflight(), 1);
        assert_eq!(
            counters.totals(),
            QuiescenceTotals {
                started: 1,
                completed: 0,
                failed: 0,
            }
        );
    }
}
