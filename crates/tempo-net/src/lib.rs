//! tempo-net - network policy, profile isolation, audit records, and quiescence.
//!
//! This crate is the standalone WS6 foundation from `final.md`: the browser
//! network layer must reject SSRF targets before engine navigation, keep each
//! session in an isolated profile, emit audit records that do not carry page
//! payloads, and expose network-idle counters for the action quiescence gate.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Default maximum age for Web Bot Auth signatures.
///
/// The `created` signature parameter is part of the signed base string. Tempo
/// rejects older signatures so a captured request cannot be replayed forever.
pub const DEFAULT_WEB_BOT_AUTH_MAX_SIGNATURE_AGE: Duration = Duration::from_secs(300);

/// Default allowance for small verifier/signer clock skew.
pub const DEFAULT_WEB_BOT_AUTH_CLOCK_SKEW: Duration = Duration::from_secs(60);

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
        if let Some(ip) = ip
            && let Some(detail) = blocked_ip_reason(&ip)
        {
            return UrlPolicyVerdict::Block(BlockReason::new(BlockCode::BlockedIp, detail));
        }

        UrlPolicyVerdict::Allow
    }

    /// Evaluate both the URL and the socket address selected by DNS/connect.
    ///
    /// This is the socket-level SSRF guard used by dispatchers after name
    /// resolution but before opening a connection. It catches public hostnames
    /// that resolve to loopback, RFC 1918, link-local metadata, unique-local, or
    /// multicast targets.
    pub fn check_resolved_ip(&self, url: &str, resolved_ip: IpAddr) -> UrlPolicyVerdict {
        if self.mode == UrlPolicyMode::AllowAll {
            return UrlPolicyVerdict::Allow;
        }
        if let UrlPolicyVerdict::Block(reason) = self.check(url) {
            return UrlPolicyVerdict::Block(reason);
        }
        if let Some(detail) = blocked_ip_reason(&resolved_ip) {
            return UrlPolicyVerdict::Block(BlockReason::new(
                BlockCode::BlockedIp,
                format!("resolved IP {detail}"),
            ));
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

    /// Return `Err` when either the URL or its resolved socket IP is blocked.
    pub fn enforce_resolved_ip(&self, url: &str, resolved_ip: IpAddr) -> Result<(), UrlBlocked> {
        match self.check_resolved_ip(url, resolved_ip) {
            UrlPolicyVerdict::Allow => Ok(()),
            UrlPolicyVerdict::Block(reason) => Err(UrlBlocked { reason }),
        }
    }

    /// Return `Err` when either the URL or resolved socket address is blocked.
    pub fn enforce_resolved_socket(
        &self,
        url: &str,
        resolved_socket: SocketAddr,
    ) -> Result<(), UrlBlocked> {
        if self.mode == UrlPolicyMode::AllowAll {
            return Ok(());
        }

        let parts = UrlParts::parse(url).map_err(|reason| UrlBlocked { reason })?;
        let expected_port = egress_port(&parts);
        if expected_port != resolved_socket.port() {
            return Err(UrlBlocked {
                reason: BlockReason::new(
                    BlockCode::InvalidUrl,
                    format!(
                        "resolved socket port {} does not match URL port {expected_port}",
                        resolved_socket.port()
                    ),
                ),
            });
        }
        self.enforce_resolved_ip(url, resolved_socket.ip())
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
    CrawlLimit,
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

/// DNS result that has passed Tempo's URL and resolved-socket policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedUrlTarget {
    host: String,
    sockets: Vec<SocketAddr>,
}

impl ResolvedUrlTarget {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn sockets(&self) -> &[SocketAddr] {
        &self.sockets
    }
}

/// Failure while resolving a URL into policy-checked sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveUrlTargetError {
    MissingHost,
    MissingPort {
        host: String,
    },
    ResolveFailed {
        host: String,
        port: u16,
        reason: String,
    },
    EmptyResolution {
        host: String,
        port: u16,
    },
    UrlBlocked(UrlBlocked),
}

impl fmt::Display for ResolveUrlTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHost => write!(f, "URL has no host to resolve"),
            Self::MissingPort { host } => write!(f, "URL host {host} has no known port"),
            Self::ResolveFailed { host, port, reason } => {
                write!(f, "failed to resolve {host}:{port}: {reason}")
            }
            Self::EmptyResolution { host, port } => {
                write!(f, "host {host}:{port} resolved to no socket addresses")
            }
            Self::UrlBlocked(error) => write!(f, "{error}"),
        }
    }
}

impl Error for ResolveUrlTargetError {}

/// Resolve a URL and reject the result unless every selected socket is allowed.
///
/// Callers pass the returned sockets to their HTTP client with `resolve_to_addrs`.
/// That pins the request to the same DNS answers that were checked here, closing
/// the gap where a public hostname can resolve to loopback, RFC 1918, or metadata
/// infrastructure after a hostname-only policy check has passed.
pub fn resolve_url_target(
    url: &url::Url,
    policy: &UrlPolicy,
) -> Result<ResolvedUrlTarget, ResolveUrlTargetError> {
    policy
        .enforce(url.as_str())
        .map_err(ResolveUrlTargetError::UrlBlocked)?;
    let host = url
        .host_str()
        .ok_or(ResolveUrlTargetError::MissingHost)?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ResolveUrlTargetError::MissingPort { host: host.clone() })?;
    let sockets = (host.as_str(), port).to_socket_addrs().map_err(|error| {
        ResolveUrlTargetError::ResolveFailed {
            host: host.clone(),
            port,
            reason: error.to_string(),
        }
    })?;
    checked_url_target_from_sockets(url, host, port, sockets, policy)
}

/// Build a policy-checked target from a caller-supplied DNS result.
pub fn checked_url_target_from_sockets(
    url: &url::Url,
    host: impl Into<String>,
    port: u16,
    sockets: impl IntoIterator<Item = SocketAddr>,
    policy: &UrlPolicy,
) -> Result<ResolvedUrlTarget, ResolveUrlTargetError> {
    policy
        .enforce(url.as_str())
        .map_err(ResolveUrlTargetError::UrlBlocked)?;
    let host = host.into();
    let sockets: Vec<_> = sockets.into_iter().collect();
    if sockets.is_empty() {
        return Err(ResolveUrlTargetError::EmptyResolution { host, port });
    }
    for socket in &sockets {
        policy
            .enforce_resolved_socket(url.as_str(), *socket)
            .map_err(ResolveUrlTargetError::UrlBlocked)?;
    }
    Ok(ResolvedUrlTarget { host, sockets })
}

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
            max_signature_age: DEFAULT_WEB_BOT_AUTH_MAX_SIGNATURE_AGE,
            allowed_clock_skew: DEFAULT_WEB_BOT_AUTH_CLOCK_SKEW,
        }
    }
}

/// Ed25519 verification key for incoming or replayed Web Bot Auth signatures.
#[derive(Clone)]
pub struct WebBotAuthVerifier {
    key_id: String,
    verifying_key: VerifyingKey,
    max_signature_age: Duration,
    allowed_clock_skew: Duration,
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
            max_signature_age: DEFAULT_WEB_BOT_AUTH_MAX_SIGNATURE_AGE,
            allowed_clock_skew: DEFAULT_WEB_BOT_AUTH_CLOCK_SKEW,
        })
    }

    pub fn with_max_signature_age(mut self, max_signature_age: Duration) -> Self {
        self.max_signature_age = max_signature_age;
        self
    }

    pub fn with_allowed_clock_skew(mut self, allowed_clock_skew: Duration) -> Self {
        self.allowed_clock_skew = allowed_clock_skew;
        self
    }

    pub fn max_signature_age(&self) -> Duration {
        self.max_signature_age
    }

    pub fn allowed_clock_skew(&self) -> Duration {
        self.allowed_clock_skew
    }
}

impl fmt::Debug for WebBotAuthVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebBotAuthVerifier")
            .field("key_id", &"[redacted]")
            .field("verifying_key", &"[redacted]")
            .field("max_signature_age", &self.max_signature_age)
            .field("allowed_clock_skew", &self.allowed_clock_skew)
            .finish()
    }
}

/// RFC 9421 signature parameters for one signature label.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureParameters {
    pub label: String,
    pub key_id: String,
    pub created: u64,
    pub expires: Option<u64>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
    pub components: Vec<CoveredComponent>,
}

impl SignatureParameters {
    /// Default Web Bot Auth coverage: method, authority, scheme, path, and query.
    pub fn web_bot_auth(key_id: impl Into<String>, created: u64) -> Self {
        Self {
            label: "sig1".into(),
            key_id: key_id.into(),
            created,
            expires: Some(created.saturating_add(DEFAULT_WEB_BOT_AUTH_MAX_SIGNATURE_AGE.as_secs())),
            nonce: None,
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Method,
                CoveredComponent::Authority,
                CoveredComponent::Scheme,
                CoveredComponent::Path,
                CoveredComponent::Query,
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
        let mut input = format!(
            "{}=({covered});created={};keyid=\"{}\";alg=\"ed25519\"",
            self.label,
            self.created,
            escape_sf_string(&self.key_id)
        );
        if let Some(expires) = self.expires {
            input.push_str(&format!(";expires={expires}"));
        }
        if let Some(nonce) = &self.nonce {
            input.push_str(&format!(";nonce=\"{}\"", escape_sf_string(nonce)));
        }
        if let Some(tag) = &self.tag {
            input.push_str(&format!(";tag=\"{}\"", escape_sf_string(tag)));
        }
        input
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

impl fmt::Debug for SignatureParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureParameters")
            .field("label", &self.label)
            .field("key_id", &"[redacted]")
            .field("created", &self.created)
            .field("expires", &self.expires)
            .field("nonce_present", &self.nonce.is_some())
            .field("tag", &self.tag)
            .field("components", &self.components)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSignatureInput {
    params: SignatureParameters,
    signature_params_value: String,
}

/// Headers produced by signing an HTTP request.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureHeaders {
    pub signature_agent: Option<String>,
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

    pub fn header_pairs(&self) -> Vec<(&'static str, &str)> {
        let mut headers = Vec::with_capacity(if self.signature_agent.is_some() { 3 } else { 2 });
        if let Some(signature_agent) = &self.signature_agent {
            headers.push(("Signature-Agent", signature_agent.as_str()));
        }
        headers.extend(self.as_header_pairs());
        headers
    }
}

impl fmt::Debug for SignatureHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureHeaders")
            .field("signature_agent_present", &self.signature_agent.is_some())
            .field("signature_input", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Errors returned while building or checking HTTP message signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    InvalidKey(String),
    InvalidSignatureInput(String),
    MissingComponent(String),
    UnsupportedAlgorithm(String),
    KeyIdMismatch {
        expected: String,
        actual: String,
    },
    InvalidSignature(String),
    MissingRequiredComponent(String),
    SignatureExpired {
        created: u64,
        now: u64,
        max_age_secs: u64,
    },
    SignatureCreatedInFuture {
        created: u64,
        now: u64,
        allowed_skew_secs: u64,
    },
    VerificationClockBeforeUnixEpoch,
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
            Self::MissingRequiredComponent(name) => {
                write!(f, "signature is missing required component: {name}")
            }
            Self::SignatureExpired {
                created,
                now,
                max_age_secs,
            } => write!(
                f,
                "signature expired: created={created}, now={now}, max_age={max_age_secs}s"
            ),
            Self::SignatureCreatedInFuture {
                created,
                now,
                allowed_skew_secs,
            } => write!(
                f,
                "signature created time is too far in the future: created={created}, now={now}, allowed_skew={allowed_skew_secs}s"
            ),
            Self::VerificationClockBeforeUnixEpoch => {
                write!(f, "verification clock is before the Unix epoch")
            }
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
#[derive(Clone, PartialEq, Eq)]
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
        let suffix = stable_partition_suffix(&[&session_id.0]);
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
        let suffix = stable_partition_suffix(&[&session_id.0, &name]);
        Self {
            id: ProfileId(format!("durable-{suffix}")),
            session_id,
            kind: ProfileKind::Durable,
            cookie_partition: format!("cookies-{suffix}"),
            storage_partition: format!("storage-{suffix}"),
        }
    }
}

impl fmt::Debug for NetworkProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkProfile")
            .field("id", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("cookie_partition", &"[redacted]")
            .field("storage_partition", &"[redacted]")
            .finish()
    }
}

/// Minimal cookie representation for profile-isolation tests and driver adapters.
#[derive(Clone, PartialEq, Eq)]
pub struct Cookie {
    pub origin: String,
    pub name: String,
    pub value: String,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookie")
            .field("origin", &self.origin)
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Deterministic profile manager with isolated cookie partitions.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProfileStore {
    profiles: BTreeMap<ProfileId, NetworkProfile>,
    cookies: BTreeMap<ProfileId, BTreeMap<String, BTreeMap<String, String>>>,
}

impl fmt::Debug for ProfileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cookie_origin_count = self.cookies.values().map(BTreeMap::len).sum::<usize>();
        let cookie_count = self
            .cookies
            .values()
            .flat_map(BTreeMap::values)
            .map(BTreeMap::len)
            .sum::<usize>();
        f.debug_struct("ProfileStore")
            .field("profiles", &self.profiles.len())
            .field("cookie_profiles", &self.cookies.len())
            .field("cookie_origins", &cookie_origin_count)
            .field("cookie_count", &cookie_count)
            .finish()
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityMode {
    /// Human-driven browsing surface.
    UserDriven,
    /// Explicit agent traffic; callers can attach Web Bot Auth signatures.
    AgentDeclared,
}

/// Default maximum challenge rate before an origin falls back to user-driven identity.
pub const DEFAULT_AGENT_CHALLENGE_RATE_LIMIT: f32 = 0.10;

/// Per-origin identity strategy thresholds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IdentityStrategyConfig {
    pub max_agent_challenge_rate: f32,
}

impl Default for IdentityStrategyConfig {
    fn default() -> Self {
        Self {
            max_agent_challenge_rate: DEFAULT_AGENT_CHALLENGE_RATE_LIMIT,
        }
    }
}

/// Public snapshot of one origin's identity/challenge history.
#[derive(Clone, Debug, PartialEq)]
pub struct OriginIdentityStats {
    pub origin: String,
    pub total_requests: u64,
    pub challenged_requests: u64,
    pub challenge_rate: f32,
    pub selected_mode: IdentityMode,
}

/// Default upper bound on the number of distinct origins tracked at once.
///
/// A single session can touch many distinct origins (wildcard subdomains,
/// third-party subrequests); the counter table is bounded so it cannot grow
/// without limit for the session lifetime. When full, the least-recently-used
/// origin is evicted.
pub const DEFAULT_IDENTITY_STRATEGY_CAPACITY: usize = 1024;

/// Per-origin identity strategy driven by observed challenge rate.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityStrategyTable {
    config: IdentityStrategyConfig,
    counters: BTreeMap<String, IdentityOriginCounters>,
    capacity: usize,
    /// Monotonic tick used to order origins by recency of last record.
    clock: u64,
}

impl Default for IdentityStrategyTable {
    fn default() -> Self {
        Self::new(IdentityStrategyConfig::default())
    }
}

impl IdentityStrategyTable {
    pub fn new(config: IdentityStrategyConfig) -> Self {
        Self::with_capacity(config, DEFAULT_IDENTITY_STRATEGY_CAPACITY)
    }

    /// Construct a table that tracks at most `capacity` distinct origins,
    /// evicting the least-recently-recorded origin once full.
    pub fn with_capacity(config: IdentityStrategyConfig, capacity: usize) -> Self {
        Self {
            config,
            counters: BTreeMap::new(),
            capacity: capacity.max(1),
            clock: 0,
        }
    }

    /// Number of origins currently tracked.
    pub fn tracked_origins(&self) -> usize {
        self.counters.len()
    }

    /// Maximum number of origins tracked before least-recently-used eviction.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn config(&self) -> IdentityStrategyConfig {
        self.config
    }

    /// Record the outcome of one request and return the updated origin snapshot.
    pub fn record_request(
        &mut self,
        url: &str,
        challenged: bool,
    ) -> Result<OriginIdentityStats, IdentityStrategyError> {
        let origin = identity_origin(url)?;
        self.clock = self.clock.saturating_add(1);
        let tick = self.clock;
        // Evict the least-recently-recorded origin before inserting a new one so
        // the table stays bounded even under many distinct origins.
        if !self.counters.contains_key(&origin) && self.counters.len() >= self.capacity {
            self.evict_lru();
        }
        let counters = self.counters.entry(origin.clone()).or_default();
        counters.total_requests = counters.total_requests.saturating_add(1);
        if challenged {
            counters.challenged_requests = counters.challenged_requests.saturating_add(1);
        }
        counters.last_seen = tick;
        Ok(counters.stats(origin, self.config))
    }

    /// Remove the origin with the oldest `last_seen` tick (least recently recorded).
    fn evict_lru(&mut self) {
        if let Some(oldest) = self
            .counters
            .iter()
            .min_by_key(|(_, counters)| counters.last_seen)
            .map(|(origin, _)| origin.clone())
        {
            self.counters.remove(&oldest);
        }
    }

    /// Return the currently selected mode for a URL's origin.
    pub fn mode_for_url(&self, url: &str) -> Result<IdentityMode, IdentityStrategyError> {
        let origin = identity_origin(url)?;
        Ok(self.mode_for_origin(&origin))
    }

    /// Return the currently selected mode for a canonical origin string.
    pub fn mode_for_origin(&self, origin: &str) -> IdentityMode {
        self.counters
            .get(origin)
            .map(|counters| counters.selected_mode(self.config))
            .unwrap_or(IdentityMode::AgentDeclared)
    }

    /// Return a snapshot for a URL's origin, if that origin has history.
    pub fn stats_for_url(
        &self,
        url: &str,
    ) -> Result<Option<OriginIdentityStats>, IdentityStrategyError> {
        let origin = identity_origin(url)?;
        Ok(self
            .counters
            .get(&origin)
            .map(|counters| counters.stats(origin, self.config)))
    }

    pub fn all_stats(&self) -> Vec<OriginIdentityStats> {
        self.counters
            .iter()
            .map(|(origin, counters)| counters.stats(origin.clone(), self.config))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IdentityOriginCounters {
    total_requests: u64,
    challenged_requests: u64,
    /// Recency tick of the most recent `record_request` for this origin.
    last_seen: u64,
}

impl IdentityOriginCounters {
    fn challenge_rate(self) -> f32 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.challenged_requests as f32 / self.total_requests as f32
        }
    }

    fn selected_mode(self, config: IdentityStrategyConfig) -> IdentityMode {
        if self.challenge_rate() > config.max_agent_challenge_rate {
            IdentityMode::UserDriven
        } else {
            IdentityMode::AgentDeclared
        }
    }

    fn stats(self, origin: String, config: IdentityStrategyConfig) -> OriginIdentityStats {
        OriginIdentityStats {
            origin,
            total_requests: self.total_requests,
            challenged_requests: self.challenged_requests,
            challenge_rate: self.challenge_rate(),
            selected_mode: self.selected_mode(config),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStrategyError {
    pub reason: BlockReason,
}

impl fmt::Display for IdentityStrategyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid identity strategy URL: {}", self.reason.detail)
    }
}

impl Error for IdentityStrategyError {}

fn identity_origin(url: &str) -> Result<String, IdentityStrategyError> {
    let Some((scheme, _)) = url.split_once("://") else {
        return Err(IdentityStrategyError {
            reason: BlockReason::new(BlockCode::InvalidUrl, "URL has no scheme separator"),
        });
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(IdentityStrategyError {
            reason: BlockReason::new(
                BlockCode::UnsupportedScheme,
                format!("scheme '{scheme}' is not http or https"),
            ),
        });
    }
    let parts = UrlParts::parse(url).map_err(|reason| IdentityStrategyError { reason })?;
    Ok(parts.origin())
}

/// Request metadata accepted by tempo-net before engine/network dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkRequest {
    pub id: RequestId,
    pub method: String,
    pub url: String,
    pub profile_id: ProfileId,
    pub identity_mode: IdentityMode,
    headers: BTreeMap<String, Vec<String>>,
    body_size: u64,
    body_sha256: Option<[u8; 32]>,
}

impl fmt::Debug for NetworkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = redacted_url_for_debug(&self.url);
        f.debug_struct("NetworkRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("url", &url)
            .field("profile_id", &self.profile_id)
            .field("identity_mode", &self.identity_mode)
            .field("header_count", &header_value_count(&self.headers))
            .field("body_size", &self.body_size)
            .field("body_sha256_present", &self.body_sha256.is_some())
            .finish()
    }
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
            body_size: 0,
            body_sha256: None,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .entry(name.into().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }

    pub fn with_body_size(mut self, body_size: u64) -> Self {
        self.body_size = body_size;
        self.body_sha256 = None;
        self
    }

    pub fn with_body_sha256(mut self, body_size: u64, body_sha256: [u8; 32]) -> Self {
        self.body_size = body_size;
        self.body_sha256 = Some(body_sha256);
        self
    }

    pub fn with_body_bytes(mut self, body: impl AsRef<[u8]>) -> Self {
        let body = body.as_ref();
        self.body_size = body.len() as u64;
        self.body_sha256 = Some(Sha256::digest(body).into());
        self
    }

    pub fn body_size(&self) -> u64 {
        self.body_size
    }

    pub fn body_sha256(&self) -> Option<[u8; 32]> {
        self.body_sha256
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.as_str(), value.as_str()))
        })
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

    pub fn sign_web_bot_auth_with_agent(
        &self,
        key: &WebBotAuthSigningKey,
        created: u64,
        expires: u64,
        nonce: impl Into<String>,
        signature_agent: impl AsRef<str>,
    ) -> Result<SignatureHeaders, SignatureError> {
        let signature_agent = signature_agent.as_ref();
        if !signature_agent.starts_with("https://") {
            return Err(SignatureError::InvalidSignatureInput(
                "Signature-Agent must be an https URI".into(),
            ));
        }
        let signature_agent_header = format!("\"{}\"", escape_sf_string(signature_agent));
        let signed_request = self
            .clone()
            .with_header("Signature-Agent", signature_agent_header.clone());
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: key.key_id().to_string(),
            created,
            expires: Some(expires),
            nonce: Some(nonce.into()),
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Authority,
                CoveredComponent::Header("signature-agent".into()),
            ],
        };
        let mut headers = sign_request(&signed_request, &params, key)?;
        headers.signature_agent = Some(signature_agent_header);
        Ok(headers)
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
    // Build the `Signature-Input` value once and derive the `@signature-params`
    // value from it (identical to `signature_params_value()`), mirroring the
    // verify path's reuse via `signature_base_with_params_value`. This avoids
    // building the same input string twice per signed request.
    let signature_input = params.signature_input_value();
    let params_prefix = format!("{}=", params.label);
    let signature_params_value = signature_input
        .strip_prefix(&params_prefix)
        .unwrap_or(signature_input.as_str());
    let base = signature_base_with_params_value(request, params, signature_params_value)?;
    let signature = key.signing_key.sign(base.as_bytes());
    let signature = format!("{}=:{}:", params.label, BASE64.encode(signature.to_bytes()));
    Ok(SignatureHeaders {
        signature_agent: None,
        signature_input,
        signature,
    })
}

/// Verify RFC 9421 `Signature-Input` and `Signature` headers against a request.
pub fn verify_request_signature(
    request: &NetworkRequest,
    signature_input: &str,
    signature: &str,
    verifier: &WebBotAuthVerifier,
) -> Result<(), SignatureError> {
    let now = unix_timestamp(SystemTime::now())?;
    verify_request_signature_at(request, signature_input, signature, verifier, now)
}

/// Verify Web Bot Auth headers and require Tempo's default signed components.
pub fn verify_web_bot_auth_signature(
    request: &NetworkRequest,
    signature_input: &str,
    signature: &str,
    verifier: &WebBotAuthVerifier,
) -> Result<(), SignatureError> {
    let now = unix_timestamp(SystemTime::now())?;
    verify_web_bot_auth_signature_at(request, signature_input, signature, verifier, now)
}

/// Verify Web Bot Auth headers at a caller-supplied Unix timestamp.
pub fn verify_web_bot_auth_signature_at(
    request: &NetworkRequest,
    signature_input: &str,
    signature: &str,
    verifier: &WebBotAuthVerifier,
    now: u64,
) -> Result<(), SignatureError> {
    let parsed = parse_signature_input(signature_input)?;
    validate_web_bot_auth_components(request, &parsed.params)?;
    verify_parsed_request_signature_at(request, signature, verifier, now, parsed)
}

/// Verify RFC 9421 headers against a request at a caller-supplied Unix timestamp.
///
/// This is useful for replay/audit verification and deterministic tests. The
/// verifier's freshness policy is still applied to the supplied timestamp.
pub fn verify_request_signature_at(
    request: &NetworkRequest,
    signature_input: &str,
    signature: &str,
    verifier: &WebBotAuthVerifier,
    now: u64,
) -> Result<(), SignatureError> {
    let parsed = parse_signature_input(signature_input)?;
    verify_parsed_request_signature_at(request, signature, verifier, now, parsed)
}

fn verify_parsed_request_signature_at(
    request: &NetworkRequest,
    signature: &str,
    verifier: &WebBotAuthVerifier,
    now: u64,
    parsed: ParsedSignatureInput,
) -> Result<(), SignatureError> {
    validate_signature_freshness(&parsed.params, verifier, now)?;
    if parsed.params.key_id != verifier.key_id {
        return Err(SignatureError::KeyIdMismatch {
            expected: verifier.key_id.clone(),
            actual: parsed.params.key_id.clone(),
        });
    }
    let signature_bytes = parse_signature_header(signature, &parsed.params.label)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| SignatureError::InvalidSignature(err.to_string()))?;
    let base =
        signature_base_with_params_value(request, &parsed.params, &parsed.signature_params_value)?;
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
    let signature_params_value = params.signature_params_value();
    signature_base_with_params_value(request, params, &signature_params_value)
}

fn signature_base_with_params_value(
    request: &NetworkRequest,
    params: &SignatureParameters,
    signature_params_value: &str,
) -> Result<String, SignatureError> {
    let parts = UrlParts::parse(&request.url).map_err(SignatureError::Url)?;
    let mut lines = Vec::with_capacity(params.components.len() + 1);
    for component in &params.components {
        let identifier = component.identifier();
        let value = component_value(request, &parts, component)?;
        lines.push(format!("\"{identifier}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params_value}"));
    Ok(lines.join("\n"))
}

/// Response metadata accepted back from the network layer for protocol events.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkResponseRecord {
    pub request_id: RequestId,
    pub url: String,
    pub status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body_size: u64,
}

impl fmt::Debug for NetworkResponseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = redacted_url_for_debug(&self.url);
        f.debug_struct("NetworkResponseRecord")
            .field("request_id", &self.request_id)
            .field("url", &url)
            .field("status", &self.status)
            .field("header_count", &header_value_count(&self.headers))
            .field("body_size", &self.body_size)
            .finish()
    }
}

impl NetworkResponseRecord {
    pub fn new(request_id: impl Into<RequestId>, url: impl Into<String>, status: u16) -> Self {
        Self {
            request_id: request_id.into(),
            url: url.into(),
            status,
            headers: BTreeMap::new(),
            body_size: 0,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .entry(name.into().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }

    pub fn with_body_size(mut self, body_size: u64) -> Self {
        self.body_size = body_size;
        self
    }

    pub fn body_size(&self) -> u64 {
        self.body_size
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.as_str(), value.as_str()))
        })
    }

    pub fn header_values(&self, name: &str) -> Option<&[String]> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
    }
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
        Self::from_policy_checked_request(request)
    }

    /// Enforce URL policy plus socket-level SSRF policy, then emit a sanitized audit record.
    pub fn from_request_with_resolved_ip(
        request: &NetworkRequest,
        policy: &UrlPolicy,
        resolved_ip: IpAddr,
    ) -> Result<Self, UrlBlocked> {
        policy.enforce_resolved_ip(&request.url, resolved_ip)?;
        Self::from_policy_checked_request(request)
    }

    /// Enforce URL policy plus socket-level SSRF policy, then emit a sanitized audit record.
    pub fn from_request_with_resolved_socket(
        request: &NetworkRequest,
        policy: &UrlPolicy,
        resolved_socket: SocketAddr,
    ) -> Result<Self, UrlBlocked> {
        policy.enforce_resolved_socket(&request.url, resolved_socket)?;
        Self::from_policy_checked_request(request)
    }

    fn from_policy_checked_request(request: &NetworkRequest) -> Result<Self, UrlBlocked> {
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

/// Match rule for egress domain controls.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainRule {
    Exact(String),
    Suffix(String),
}

impl DomainRule {
    pub fn exact(domain: impl Into<String>) -> Self {
        Self::Exact(canonical_domain(domain))
    }

    pub fn suffix(domain: impl Into<String>) -> Self {
        Self::Suffix(canonical_domain(domain))
    }

    pub fn matches(&self, domain: &str) -> bool {
        // Canonicalize the input the same way the rule side is canonicalized
        // (lowercase + trailing-dot stripped) so a fully-qualified
        // `blocked.example.com.` cannot evade a `blocked.example.com` rule.
        let domain = canonical_domain(domain);
        match self {
            Self::Exact(expected) => &domain == expected,
            Self::Suffix(suffix) => {
                let suffix_with_boundary = format!(".{suffix}");
                domain == *suffix || domain.ends_with(&suffix_with_boundary)
            }
        }
    }

    fn specificity(&self) -> usize {
        match self {
            Self::Exact(domain) => domain.len() + 1_000,
            Self::Suffix(domain) => domain.len(),
        }
    }
}

/// Proxy route selected by egress policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    pub id: String,
    pub endpoint: String,
}

impl fmt::Debug for ProxyRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRoute")
            .field("id", &self.id)
            .field("endpoint", &"[redacted]")
            .finish()
    }
}

impl ProxyRoute {
    pub fn new(id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            endpoint: endpoint.into(),
        }
    }
}

/// Host/port that must be resolved and pinned before using a proxy endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEndpointTarget {
    pub host: String,
    pub port: u16,
}

/// Default egress behavior when no domain rule matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDefault {
    AllowDirect,
    Block,
}

/// Pure egress/proxy policy evaluated before dispatching a network request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressPolicy {
    default: EgressDefault,
    allowed: BTreeSet<DomainRule>,
    blocked: BTreeSet<DomainRule>,
    proxies: BTreeMap<DomainRule, ProxyRoute>,
    allow_insecure_local_proxy_endpoints: bool,
}

impl EgressPolicy {
    pub fn allow_all() -> Self {
        Self {
            default: EgressDefault::AllowDirect,
            allowed: BTreeSet::new(),
            blocked: BTreeSet::new(),
            proxies: BTreeMap::new(),
            allow_insecure_local_proxy_endpoints: false,
        }
    }

    pub fn block_by_default() -> Self {
        Self {
            default: EgressDefault::Block,
            allowed: BTreeSet::new(),
            blocked: BTreeSet::new(),
            proxies: BTreeMap::new(),
            allow_insecure_local_proxy_endpoints: false,
        }
    }

    pub fn allow_domain(mut self, rule: DomainRule) -> Self {
        self.allowed.insert(rule);
        self
    }

    pub fn block_domain(mut self, rule: DomainRule) -> Self {
        self.blocked.insert(rule);
        self
    }

    pub fn proxy_domain(mut self, rule: DomainRule, route: ProxyRoute) -> Self {
        self.proxies.insert(rule, route);
        self
    }

    /// Permit cleartext proxy endpoints only when they target loopback.
    ///
    /// This is intended for local development and tests. Public proxy routes
    /// must use secure proxy transport by default.
    pub fn allow_insecure_local_proxy_endpoints(mut self) -> Self {
        self.allow_insecure_local_proxy_endpoints = true;
        self
    }

    /// Return the proxy host/port a transport adapter must resolve and pin.
    pub fn proxy_endpoint_target(
        &self,
        proxy: &ProxyRoute,
    ) -> Result<ProxyEndpointTarget, UrlBlocked> {
        proxy_endpoint_target(&proxy.endpoint, self.allow_insecure_local_proxy_endpoints)
    }

    /// Validate a proxy endpoint socket after adapter-side DNS resolution.
    pub fn enforce_proxy_endpoint_resolved_socket(
        &self,
        proxy: &ProxyRoute,
        resolved_socket: SocketAddr,
    ) -> Result<(), UrlBlocked> {
        enforce_proxy_endpoint_resolved_socket(
            &proxy.endpoint,
            resolved_socket,
            self.allow_insecure_local_proxy_endpoints,
        )
    }

    pub fn decide(&self, request: &NetworkRequest) -> Result<EgressDecision, EgressDenied> {
        let parts =
            UrlParts::parse(&request.url).map_err(|reason| EgressDenied::from_block(reason, ""))?;
        let domain = canonical_domain(parts.host.clone());
        let port = egress_port(&parts);

        if self.rule_matches(&self.blocked, &domain) {
            return Err(EgressDenied {
                domain,
                port,
                reason: "domain is blocked by egress policy".into(),
            });
        }

        if let Some(proxy) = self.proxy_for(&domain) {
            enforce_proxy_endpoint_preflight(
                &proxy.endpoint,
                self.allow_insecure_local_proxy_endpoints,
            )
            .map_err(|blocked| EgressDenied {
                domain: domain.clone(),
                port,
                reason: format!("proxy endpoint rejected: {}", blocked.reason.detail),
            })?;
            return Ok(EgressDecision::Proxied {
                domain,
                port,
                proxy: proxy.clone(),
            });
        }

        if self.default == EgressDefault::AllowDirect || self.rule_matches(&self.allowed, &domain) {
            return Ok(EgressDecision::Direct { domain, port });
        }

        Err(EgressDenied {
            domain,
            port,
            reason: "domain is not allowed by egress policy".into(),
        })
    }

    fn rule_matches(&self, rules: &BTreeSet<DomainRule>, domain: &str) -> bool {
        rules.iter().any(|rule| rule.matches(domain))
    }

    fn proxy_for(&self, domain: &str) -> Option<&ProxyRoute> {
        let mut best: Option<(&DomainRule, &ProxyRoute)> = None;
        for (rule, route) in &self.proxies {
            if !rule.matches(domain) {
                continue;
            }
            let replace = best
                .as_ref()
                .map(|(best_rule, _)| rule.specificity() > best_rule.specificity())
                .unwrap_or(true);
            if replace {
                best = Some((rule, route));
            }
        }
        best.map(|(_, route)| route)
    }
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// Egress routing decision for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    Direct {
        domain: String,
        port: u16,
    },
    Proxied {
        domain: String,
        port: u16,
        proxy: ProxyRoute,
    },
}

impl EgressDecision {
    pub fn domain(&self) -> &str {
        match self {
            Self::Direct { domain, .. } | Self::Proxied { domain, .. } => domain,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Direct { port, .. } | Self::Proxied { port, .. } => *port,
        }
    }

    pub fn proxy_id(&self) -> Option<&str> {
        match self {
            Self::Direct { .. } => None,
            Self::Proxied { proxy, .. } => Some(proxy.id.as_str()),
        }
    }
}

/// Egress policy rejection for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressDenied {
    pub domain: String,
    pub port: u16,
    pub reason: String,
}

impl EgressDenied {
    fn from_block(reason: BlockReason, domain: &str) -> Self {
        Self {
            domain: domain.into(),
            port: 0,
            reason: reason.detail,
        }
    }
}

/// Sanitized egress record suitable for session audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRecord {
    pub request_id: RequestId,
    pub domain: String,
    pub port: u16,
    pub proxy_id: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl EgressRecord {
    pub fn from_decision(
        request_id: impl Into<RequestId>,
        decision: &EgressDecision,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            domain: decision.domain().into(),
            port: decision.port(),
            proxy_id: decision.proxy_id().map(str::to_string),
            bytes_sent,
            bytes_received,
        }
    }
}

/// Default per-origin request concurrency for crawler/scraper workloads.
///
/// Tempo is meant to be highly parallel across origins, while each individual
/// origin remains bounded and auditable.
pub const DEFAULT_CRAWL_MAX_CONCURRENT_PER_ORIGIN: usize = 4;

/// Default global request concurrency for one crawler frontier.
pub const DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT: usize = 128;

/// Default global pending queue cap for one crawler frontier.
pub const DEFAULT_CRAWL_MAX_GLOBAL_PENDING: usize = 4096;

/// Default pending queue cap for one origin within a crawler frontier.
pub const DEFAULT_CRAWL_MAX_PENDING_PER_ORIGIN: usize = 256;

/// Default global pending request metadata cap for one crawler frontier.
pub const DEFAULT_CRAWL_MAX_GLOBAL_PENDING_BYTES: usize = 4 * 1024 * 1024;

/// Default pending request metadata cap for one origin within a crawler frontier.
pub const DEFAULT_CRAWL_MAX_PENDING_BYTES_PER_ORIGIN: usize = 512 * 1024;

/// Default minimum spacing between starts for one origin, expressed in caller
/// supplied deterministic ticks.
pub const DEFAULT_CRAWL_MIN_DELAY_TICKS: u64 = 1;

/// Origin-scoped crawl policy evaluated before dispatching a request.
#[derive(Clone, PartialEq, Eq)]
pub struct CrawlPolicy {
    pub max_global_inflight: usize,
    pub max_concurrent_per_origin: usize,
    pub min_delay_ticks_per_origin: u64,
    pub respect_robots_txt: bool,
    pub user_agent: String,
}

impl CrawlPolicy {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
            ..Self::default()
        }
    }

    pub fn with_max_concurrent_per_origin(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent_per_origin = max_concurrent.max(1);
        self
    }

    pub fn with_max_global_inflight(mut self, max_inflight: usize) -> Self {
        self.max_global_inflight = max_inflight.max(1);
        self
    }

    pub fn with_min_delay_ticks_per_origin(mut self, min_delay_ticks: u64) -> Self {
        self.min_delay_ticks_per_origin = min_delay_ticks;
        self
    }

    pub fn without_robots_txt(mut self) -> Self {
        self.respect_robots_txt = false;
        self
    }
}

impl fmt::Debug for CrawlPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrawlPolicy")
            .field("max_global_inflight", &self.max_global_inflight)
            .field("max_concurrent_per_origin", &self.max_concurrent_per_origin)
            .field(
                "min_delay_ticks_per_origin",
                &self.min_delay_ticks_per_origin,
            )
            .field("respect_robots_txt", &self.respect_robots_txt)
            .field("user_agent", &"[redacted]")
            .finish()
    }
}

impl Default for CrawlPolicy {
    fn default() -> Self {
        Self {
            max_global_inflight: DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT,
            max_concurrent_per_origin: DEFAULT_CRAWL_MAX_CONCURRENT_PER_ORIGIN,
            min_delay_ticks_per_origin: DEFAULT_CRAWL_MIN_DELAY_TICKS,
            respect_robots_txt: true,
            user_agent: "tempo-agent".into(),
        }
    }
}

/// Minimal robots.txt directives used by the crawl scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RobotsRules {
    directives: Vec<RobotsDirective>,
    crawl_delay_ticks: Option<u64>,
}

impl RobotsRules {
    pub fn allow_all() -> Self {
        Self::default()
    }

    pub fn disallow_all() -> Self {
        Self {
            directives: vec![RobotsDirective {
                kind: RobotsDirectiveKind::Disallow,
                path: "/".into(),
            }],
            crawl_delay_ticks: None,
        }
    }

    /// Parse the directives that apply to `user_agent`.
    ///
    /// This deliberately implements the scheduler-critical subset: `User-agent`,
    /// `Allow`, `Disallow`, and integer `Crawl-delay`. Unknown fields are ignored.
    pub fn parse_for_agent(user_agent: &str, body: &str) -> Self {
        let target = user_agent.to_ascii_lowercase();
        let mut groups = Vec::new();
        let mut current_group = RobotsGroup::default();
        let mut current_group_has_rules = false;

        for raw_line in body.lines() {
            let line = raw_line
                .split_once('#')
                .map(|(before, _)| before)
                .unwrap_or(raw_line)
                .trim();
            if line.is_empty() {
                current_group.finish_into(&mut groups);
                current_group_has_rules = false;
                continue;
            }

            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let field = field.trim().to_ascii_lowercase();
            let value = value.trim();

            if field == "user-agent" {
                if current_group_has_rules {
                    current_group.finish_into(&mut groups);
                    current_group_has_rules = false;
                }
                if !value.is_empty() {
                    current_group.agents.push(value.to_ascii_lowercase());
                }
                continue;
            }

            if current_group.agents.is_empty() {
                continue;
            }

            match field.as_str() {
                "allow" => {
                    if !value.is_empty() {
                        current_group.directives.push(RobotsDirective {
                            kind: RobotsDirectiveKind::Allow,
                            path: normalize_robots_pattern(value),
                        });
                    }
                    current_group_has_rules = true;
                }
                "disallow" => {
                    if !value.is_empty() {
                        current_group.directives.push(RobotsDirective {
                            kind: RobotsDirectiveKind::Disallow,
                            path: normalize_robots_pattern(value),
                        });
                    }
                    current_group_has_rules = true;
                }
                "crawl-delay" => {
                    if let Some(delay) = parse_crawl_delay_ticks(value) {
                        current_group.crawl_delay_ticks = Some(
                            current_group
                                .crawl_delay_ticks
                                .map(|current| current.max(delay))
                                .unwrap_or(delay),
                        );
                    }
                    current_group_has_rules = true;
                }
                _ => {}
            }
        }

        current_group.finish_into(&mut groups);
        select_robots_rules(&target, groups)
    }

    pub fn allows_path(&self, path: &str) -> bool {
        let mut best: Option<(usize, RobotsDirectiveKind)> = None;
        for directive in &self.directives {
            if !robots_path_matches(&directive.path, path) {
                continue;
            }
            let specificity = robots_specificity(&directive.path);
            let replace = best
                .map(|(best_specificity, best_kind)| {
                    specificity > best_specificity
                        || (specificity == best_specificity
                            && best_kind == RobotsDirectiveKind::Disallow
                            && directive.kind == RobotsDirectiveKind::Allow)
                })
                .unwrap_or(true);
            if replace {
                best = Some((specificity, directive.kind));
            }
        }

        !matches!(best, Some((_, RobotsDirectiveKind::Disallow)))
    }

    pub fn crawl_delay_ticks(&self) -> Option<u64> {
        self.crawl_delay_ticks
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RobotsDirective {
    kind: RobotsDirectiveKind,
    path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RobotsDirectiveKind {
    Allow,
    Disallow,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RobotsGroup {
    agents: Vec<String>,
    directives: Vec<RobotsDirective>,
    crawl_delay_ticks: Option<u64>,
}

impl RobotsGroup {
    fn finish_into(&mut self, groups: &mut Vec<Self>) {
        if self.agents.is_empty() {
            self.directives.clear();
            self.crawl_delay_ticks = None;
            return;
        }
        groups.push(std::mem::take(self));
    }
}

fn select_robots_rules(target: &str, groups: Vec<RobotsGroup>) -> RobotsRules {
    let mut rules = RobotsRules::default();
    let mut best_agent_specificity = None;
    for group in groups {
        let Some(agent_specificity) = group
            .agents
            .iter()
            .filter_map(|agent| robots_agent_specificity(target, agent))
            .max()
        else {
            continue;
        };
        match best_agent_specificity {
            Some(best) if agent_specificity < best => continue,
            Some(best) if agent_specificity > best => {
                rules = RobotsRules::default();
                best_agent_specificity = Some(agent_specificity);
            }
            None => best_agent_specificity = Some(agent_specificity),
            Some(_) => {}
        }
        rules.directives.extend(group.directives);
        if let Some(delay) = group.crawl_delay_ticks {
            rules.crawl_delay_ticks = Some(
                rules
                    .crawl_delay_ticks
                    .map(|current| current.max(delay))
                    .unwrap_or(delay),
            );
        }
    }
    rules
}

/// Deterministic crawl decision for a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlDecision {
    Allow {
        origin: String,
    },
    Wait {
        origin: String,
        until_tick: u64,
        reason: String,
    },
    Block {
        origin: String,
        reason: String,
    },
}

impl CrawlDecision {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn origin(&self) -> &str {
        match self {
            Self::Allow { origin } | Self::Wait { origin, .. } | Self::Block { origin, .. } => {
                origin
            }
        }
    }
}

/// Public per-origin scheduler snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginCrawlSnapshot {
    pub origin: String,
    pub inflight: usize,
    pub last_started_tick: Option<u64>,
    pub backoff_until_tick: Option<u64>,
    pub robots_known: bool,
}

/// Pure crawl scheduler for high-throughput, policy-respecting scraping.
#[derive(Clone, PartialEq, Eq)]
pub struct CrawlScheduler {
    policy: CrawlPolicy,
    origins: BTreeMap<String, OriginCrawlState>,
    active_requests: BTreeMap<RequestId, ActiveCrawlRequest>,
    active_request_keys: BTreeSet<CrawlRequestKey>,
}

impl fmt::Debug for CrawlScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrawlScheduler")
            .field("policy", &self.policy)
            .field("origins", &self.origins.len())
            .field("active_requests", &self.active_requests.len())
            .field("active_request_keys", &self.active_request_keys.len())
            .finish()
    }
}

impl CrawlScheduler {
    pub fn new(policy: CrawlPolicy) -> Self {
        Self {
            policy,
            origins: BTreeMap::new(),
            active_requests: BTreeMap::new(),
            active_request_keys: BTreeSet::new(),
        }
    }

    pub fn policy(&self) -> &CrawlPolicy {
        &self.policy
    }

    pub fn set_robots_for_origin(
        &mut self,
        origin_or_url: &str,
        rules: RobotsRules,
    ) -> Result<(), CrawlError> {
        let origin = crawl_origin(origin_or_url)?;
        self.origins.entry(origin).or_default().robots = Some(rules);
        Ok(())
    }

    pub fn decide(&self, request: &NetworkRequest, tick: u64) -> Result<CrawlDecision, CrawlError> {
        let target = CrawlTarget::parse_request(request)?;
        let origin = target.origin;
        let state = self.origins.get(&origin);

        if self.policy.respect_robots_txt && !is_robots_txt_path(&target.path) {
            match state.and_then(|state| state.robots.as_ref()) {
                Some(robots)
                    if target
                        .robots_paths
                        .iter()
                        .any(|path| !robots.allows_path(path)) =>
                {
                    return Ok(CrawlDecision::Block {
                        origin,
                        reason: "blocked by robots.txt".into(),
                    });
                }
                Some(_) => {}
                None => {
                    return Ok(CrawlDecision::Wait {
                        origin,
                        until_tick: tick.saturating_add(1),
                        reason: "robots.txt rules are unknown".into(),
                    });
                }
            }
        }

        if self.active_request_keys.contains(&target.request_key) {
            return Ok(CrawlDecision::Wait {
                origin,
                until_tick: tick.saturating_add(1),
                reason: "canonical crawl request is already active".into(),
            });
        }

        if let Some(until_tick) = state.and_then(|state| state.backoff_until_tick)
            && tick < until_tick
        {
            return Ok(CrawlDecision::Wait {
                origin,
                until_tick,
                reason: "origin is in Retry-After backoff".into(),
            });
        }

        if self.active_requests.len() >= self.policy.max_global_inflight {
            return Ok(CrawlDecision::Wait {
                origin,
                until_tick: tick.saturating_add(1),
                reason: "global crawl concurrency cap reached".into(),
            });
        }

        let inflight = state.map(|state| state.inflight).unwrap_or_default();
        if inflight >= self.policy.max_concurrent_per_origin {
            return Ok(CrawlDecision::Wait {
                origin,
                until_tick: tick.saturating_add(1),
                reason: "per-origin concurrency cap reached".into(),
            });
        }

        let min_delay = self.effective_delay_ticks(state);
        if min_delay > 0
            && let Some(last_started_tick) = state.and_then(|state| state.last_started_tick)
        {
            let next_allowed_tick = last_started_tick.saturating_add(min_delay);
            if tick < next_allowed_tick {
                return Ok(CrawlDecision::Wait {
                    origin,
                    until_tick: next_allowed_tick,
                    reason: "per-origin crawl delay has not elapsed".into(),
                });
            }
        }

        Ok(CrawlDecision::Allow { origin })
    }

    pub fn begin(
        &mut self,
        request: &NetworkRequest,
        tick: u64,
    ) -> Result<CrawlDecision, CrawlError> {
        let target = CrawlTarget::parse_request(request)?;
        if self.active_requests.contains_key(&request.id) {
            return Ok(CrawlDecision::Block {
                origin: target.origin,
                reason: "request id is already active".into(),
            });
        }
        let decision = self.decide(request, tick)?;
        if let CrawlDecision::Allow { origin } = &decision {
            let state = self.origins.entry(origin.clone()).or_default();
            state.inflight = state.inflight.saturating_add(1);
            state.last_started_tick = Some(tick);
            self.active_request_keys.insert(target.request_key.clone());
            self.active_requests.insert(
                request.id.clone(),
                ActiveCrawlRequest {
                    origin: origin.clone(),
                    url_key: target.url_key,
                    request_key: target.request_key,
                },
            );
        }
        Ok(decision)
    }

    pub fn finish(&mut self, response: &NetworkResponseRecord, tick: u64) -> bool {
        let Some(active) = self.active_requests.remove(&response.request_id) else {
            return false;
        };
        self.active_request_keys.remove(&active.request_key);
        let state = self.origins.entry(active.origin).or_default();
        state.inflight = state.inflight.saturating_sub(1);
        if let Some(until_tick) = retry_after_until_tick(response, tick) {
            state.backoff_until_tick = Some(
                state
                    .backoff_until_tick
                    .map(|current| current.max(until_tick))
                    .unwrap_or(until_tick),
            );
        }
        true
    }

    pub fn snapshot_for_origin(
        &self,
        origin_or_url: &str,
    ) -> Result<Option<OriginCrawlSnapshot>, CrawlError> {
        let origin = crawl_origin(origin_or_url)?;
        Ok(self.snapshot_for_canonical_origin(&origin))
    }

    pub fn snapshots(&self) -> Vec<OriginCrawlSnapshot> {
        self.origins
            .iter()
            .map(|(origin, state)| state.snapshot(origin.clone()))
            .collect()
    }

    pub fn global_inflight(&self) -> usize {
        self.active_requests.len()
    }

    pub fn is_url_active(&self, url: &str) -> Result<bool, CrawlError> {
        let key = crawl_url_key(url)?;
        Ok(self
            .active_requests
            .values()
            .any(|active| active.url_key == key))
    }

    pub fn is_request_active(&self, request: &NetworkRequest) -> Result<bool, CrawlError> {
        let key = crawl_request_key(request)?;
        Ok(self.active_request_keys.contains(&key))
    }

    fn snapshot_for_canonical_origin(&self, origin: &str) -> Option<OriginCrawlSnapshot> {
        self.origins
            .get(origin)
            .map(|state| state.snapshot(origin.into()))
    }

    fn effective_delay_ticks(&self, state: Option<&OriginCrawlState>) -> u64 {
        let robots_delay = state
            .and_then(|state| state.robots.as_ref())
            .and_then(RobotsRules::crawl_delay_ticks)
            .unwrap_or(0);
        self.policy.min_delay_ticks_per_origin.max(robots_delay)
    }
}

impl Default for CrawlScheduler {
    fn default() -> Self {
        Self::new(CrawlPolicy::default())
    }
}

/// A scheduled crawl request ready for scheduler-owned dispatch.
///
/// This raw value has not by itself pinned a connection or proven that the
/// eventual network client will use the same socket that policy checked. SDK and
/// network-execution paths should use [`CheckedCrawlDispatch`] values produced by
/// [`CrawlFrontier::dispatch_checked_ready`]. Raw dispatch remains available for
/// scheduler internals and compatibility while #255's connection-pinned
/// execution capability is still open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlDispatch {
    pub request: NetworkRequest,
    pub origin: String,
}

impl CrawlDispatch {
    /// Validate this raw scheduler dispatch against socket SSRF, egress, and audit policy.
    ///
    /// This helper proves the caller-supplied socket is policy-allowed, but it
    /// does not force an HTTP client to connect to that socket. Prefer
    /// [`CrawlFrontier::dispatch_checked_ready`] for SDK-facing crawl dispatch,
    /// and treat the returned [`CheckedCrawlDispatch::resolved_socket`] as the
    /// only socket the network execution path may use.
    #[deprecated(
        note = "scheduler-only raw dispatch check; use CrawlFrontier::dispatch_checked_ready and execute only against CheckedCrawlDispatch::resolved_socket"
    )]
    pub fn check(
        &self,
        url_policy: &UrlPolicy,
        egress_policy: &EgressPolicy,
        resolved_socket: SocketAddr,
    ) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
        checked_crawl_dispatch(self, url_policy, egress_policy, resolved_socket, None)
    }

    /// Validate this raw scheduler dispatch and attach Tempo's default Web Bot Auth signature.
    ///
    /// This has the same socket-pinning caveat as [`CrawlDispatch::check`].
    /// It is compatibility glue for scheduler internals, not the final
    /// SDK-facing network execution capability.
    #[deprecated(
        note = "scheduler-only raw dispatch check; use CrawlFrontier::dispatch_checked_ready and execute only against CheckedCrawlDispatch::resolved_socket"
    )]
    pub fn check_signed(
        &self,
        url_policy: &UrlPolicy,
        egress_policy: &EgressPolicy,
        resolved_socket: SocketAddr,
        key: &WebBotAuthSigningKey,
        created: u64,
    ) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
        checked_crawl_dispatch(
            self,
            url_policy,
            egress_policy,
            resolved_socket,
            Some((key, created)),
        )
    }
}

/// Crawl dispatch after mandatory network policy checks have passed.
///
/// This is the only crawl dispatch type SDK-facing network execution should
/// accept. The request must be executed against [`Self::resolved_socket`];
/// re-resolving [`Self::dispatch`]'s URL reopens the DNS rebinding/TOCTOU gap
/// tracked in #255.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedCrawlDispatch {
    pub dispatch: CrawlDispatch,
    pub resolved_socket: SocketAddr,
    pub audit: AuditRecord,
    pub egress: EgressRecord,
    pub web_bot_auth_headers: Option<SignatureHeaders>,
}

impl CheckedCrawlDispatch {
    /// Consume this checked dispatch into a capability that carries the checked
    /// socket and HTTP request parts without exposing the raw URL for
    /// re-resolution.
    pub fn into_connection_pinned(
        self,
    ) -> Result<ConnectionPinnedCrawlDispatch, CrawlDispatchError> {
        ConnectionPinnedCrawlDispatch::from_checked(self)
    }
}

/// Checked crawl request metadata prepared for connection-pinned execution.
///
/// The original URL is intentionally not exposed. Transport adapters can build
/// HTTP/TLS request state from the scheme, authority, host, path/query, headers,
/// and already-approved socket without giving an HTTP client a hostname to
/// resolve again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPinnedCrawlDispatch {
    request_id: RequestId,
    method: String,
    profile_id: ProfileId,
    identity_mode: IdentityMode,
    headers: BTreeMap<String, Vec<String>>,
    body_size: u64,
    body_sha256: Option<[u8; 32]>,
    scheme: String,
    authority: String,
    host: String,
    path_and_query: String,
    origin: String,
    resolved_socket: SocketAddr,
    audit: AuditRecord,
    egress: EgressRecord,
    web_bot_auth_headers: Option<SignatureHeaders>,
}

impl ConnectionPinnedCrawlDispatch {
    fn from_checked(checked: CheckedCrawlDispatch) -> Result<Self, CrawlDispatchError> {
        let parts = UrlParts::parse(&checked.dispatch.request.url)
            .map_err(|reason| CrawlDispatchError::Url(UrlBlocked { reason }))?;
        let mut path_and_query = parts.path.clone();
        if let Some(query) = &parts.query {
            path_and_query.push_str(query);
        }
        let authority = parts.authority_component();
        Ok(Self {
            request_id: checked.dispatch.request.id,
            method: checked.dispatch.request.method,
            profile_id: checked.dispatch.request.profile_id,
            identity_mode: checked.dispatch.request.identity_mode,
            headers: checked.dispatch.request.headers,
            body_size: checked.dispatch.request.body_size,
            body_sha256: checked.dispatch.request.body_sha256,
            scheme: parts.scheme,
            authority,
            host: parts.host,
            path_and_query,
            origin: checked.dispatch.origin,
            resolved_socket: checked.resolved_socket,
            audit: checked.audit,
            egress: checked.egress,
            web_bot_auth_headers: checked.web_bot_auth_headers,
        })
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    pub fn identity_mode(&self) -> IdentityMode {
        self.identity_mode
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.as_str(), value.as_str()))
        })
    }

    pub fn header_values(&self, name: &str) -> Option<&[String]> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
    }

    pub fn body_size(&self) -> u64 {
        self.body_size
    }

    pub fn body_sha256(&self) -> Option<[u8; 32]> {
        self.body_sha256
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn resolved_socket(&self) -> SocketAddr {
        self.resolved_socket
    }

    pub fn audit(&self) -> &AuditRecord {
        &self.audit
    }

    pub fn egress(&self) -> &EgressRecord {
        &self.egress
    }

    pub fn web_bot_auth_headers(&self) -> Option<&SignatureHeaders> {
        self.web_bot_auth_headers.as_ref()
    }

    pub fn connect_tcp(&self, connect_timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&self.resolved_socket, connect_timeout)
    }

    #[cfg(test)]
    fn connect_with<T>(&self, connect: impl FnOnce(SocketAddr) -> io::Result<T>) -> io::Result<T> {
        connect(self.resolved_socket)
    }
}

/// Policy bundle used by checked frontier dispatch.
#[derive(Clone, Copy)]
pub struct CrawlDispatchGuard<'a> {
    pub url_policy: &'a UrlPolicy,
    pub egress_policy: &'a EgressPolicy,
    pub signer: Option<CrawlDispatchSigner<'a>>,
}

impl<'a> CrawlDispatchGuard<'a> {
    pub fn new(url_policy: &'a UrlPolicy, egress_policy: &'a EgressPolicy) -> Self {
        Self {
            url_policy,
            egress_policy,
            signer: None,
        }
    }

    pub fn with_signer(
        mut self,
        key: &'a WebBotAuthSigningKey,
        created: u64,
    ) -> CrawlDispatchGuard<'a> {
        self.signer = Some(CrawlDispatchSigner { key, created });
        self
    }

    pub fn check(
        &self,
        dispatch: &CrawlDispatch,
        resolved_socket: SocketAddr,
    ) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
        checked_crawl_dispatch(
            dispatch,
            self.url_policy,
            self.egress_policy,
            resolved_socket,
            self.signer.map(|signer| (signer.key, signer.created)),
        )
    }

    fn check_with_egress_decision(
        &self,
        dispatch: &CrawlDispatch,
        resolved_socket: SocketAddr,
        egress_decision: EgressDecision,
    ) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
        checked_crawl_dispatch_with_decision(
            dispatch,
            self.url_policy,
            resolved_socket,
            self.signer.map(|signer| (signer.key, signer.created)),
            egress_decision,
            self.egress_policy.allow_insecure_local_proxy_endpoints,
        )
    }

    fn precheck(&self, dispatch: &CrawlDispatch) -> Result<EgressDecision, CrawlDispatchError> {
        self.url_policy.enforce(&dispatch.request.url)?;
        Ok(self.egress_policy.decide(&dispatch.request)?)
    }
}

/// Web Bot Auth signing material for checked frontier dispatch.
#[derive(Clone, Copy)]
pub struct CrawlDispatchSigner<'a> {
    pub key: &'a WebBotAuthSigningKey,
    pub created: u64,
}

/// Failure while turning a raw crawl dispatch into a checked dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlDispatchError {
    Url(UrlBlocked),
    Egress(EgressDenied),
    Signature(SignatureError),
}

impl fmt::Display for CrawlDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(error) => write!(f, "{error}"),
            Self::Egress(error) => write!(
                f,
                "egress denied for {}:{}: {}",
                error.domain, error.port, error.reason
            ),
            Self::Signature(error) => write!(f, "{error}"),
        }
    }
}

impl Error for CrawlDispatchError {}

impl From<UrlBlocked> for CrawlDispatchError {
    fn from(value: UrlBlocked) -> Self {
        Self::Url(value)
    }
}

impl From<EgressDenied> for CrawlDispatchError {
    fn from(value: EgressDenied) -> Self {
        Self::Egress(value)
    }
}

impl From<SignatureError> for CrawlDispatchError {
    fn from(value: SignatureError) -> Self {
        Self::Signature(value)
    }
}

/// Failure while creating a connection-pinned checked crawl dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlConnectError {
    Dispatch(CrawlDispatchError),
    Resolve(ResolveUrlTargetError),
    Connect {
        resolved_socket: SocketAddr,
        reason: String,
    },
}

impl fmt::Display for CrawlConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatch(error) => write!(f, "{error}"),
            Self::Resolve(error) => write!(f, "{error}"),
            Self::Connect {
                resolved_socket,
                reason,
            } => write!(
                f,
                "failed to connect to checked socket {resolved_socket}: {reason}"
            ),
        }
    }
}

impl Error for CrawlConnectError {}

impl From<CrawlDispatchError> for CrawlConnectError {
    fn from(value: CrawlDispatchError) -> Self {
        Self::Dispatch(value)
    }
}

impl From<ResolveUrlTargetError> for CrawlConnectError {
    fn from(value: ResolveUrlTargetError) -> Self {
        Self::Resolve(value)
    }
}

impl From<UrlBlocked> for CrawlConnectError {
    fn from(value: UrlBlocked) -> Self {
        Self::Dispatch(CrawlDispatchError::Url(value))
    }
}

/// Result of one deterministic frontier scheduling pass.
///
/// This raw batch is scheduler-only. Its [`CrawlDispatch`] values have not
/// passed connect-time URL/socket/egress checks and must not be used as an
/// SDK-facing network execution surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrawlBatch {
    pub dispatches: Vec<CrawlDispatch>,
    pub waiting: Vec<CrawlDecision>,
    pub blocked: Vec<CrawlDecision>,
}

impl CrawlBatch {
    pub fn is_empty(&self) -> bool {
        self.dispatches.is_empty() && self.waiting.is_empty() && self.blocked.is_empty()
    }
}

/// Result of a checked frontier scheduling pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrawlCheckedBatch {
    pub dispatches: Vec<CheckedCrawlDispatch>,
    pub waiting: Vec<CrawlDecision>,
    pub blocked: Vec<CrawlDecision>,
    pub rejected: Vec<RejectedCrawlDispatch>,
}

impl CrawlCheckedBatch {
    pub fn is_empty(&self) -> bool {
        self.dispatches.is_empty()
            && self.waiting.is_empty()
            && self.blocked.is_empty()
            && self.rejected.is_empty()
    }
}

/// A ready crawl request rejected by connect-time policy before activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedCrawlDispatch {
    pub dispatch: CrawlDispatch,
    pub error: CrawlDispatchError,
}

/// A checked crawl dispatch paired with the TCP connection tempo-net opened to
/// the same socket that URL/socket policy approved.
#[derive(Debug)]
pub struct PinnedCrawlConnection {
    pinned: ConnectionPinnedCrawlDispatch,
    stream: TcpStream,
}

impl PinnedCrawlConnection {
    pub fn pinned(&self) -> &ConnectionPinnedCrawlDispatch {
        &self.pinned
    }

    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn into_parts(self) -> (ConnectionPinnedCrawlDispatch, TcpStream) {
        (self.pinned, self.stream)
    }
}

/// Result of a connection-pinned frontier scheduling pass.
#[derive(Debug, Default)]
pub struct CrawlPinnedBatch {
    pub connections: Vec<PinnedCrawlConnection>,
    pub waiting: Vec<CrawlDecision>,
    pub blocked: Vec<CrawlDecision>,
    pub rejected: Vec<RejectedPinnedCrawlDispatch>,
}

impl CrawlPinnedBatch {
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
            && self.waiting.is_empty()
            && self.blocked.is_empty()
            && self.rejected.is_empty()
    }
}

/// A ready crawl request rejected before a pinned connection became active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedPinnedCrawlDispatch {
    pub dispatch: CrawlDispatch,
    pub error: CrawlConnectError,
}

/// Public frontier snapshot for SDKs and fleet schedulers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlFrontierSnapshot {
    pub pending: usize,
    pub inflight: usize,
    pub origins: Vec<OriginCrawlSnapshot>,
}

/// Deterministic crawl frontier backed by [`CrawlScheduler`].
///
/// The raw and checked dispatch paths only schedule requests. The pinned TCP
/// path additionally performs DNS resolution and opens the socket inside
/// tempo-net so network execution cannot re-resolve a checked URL. All paths
/// canonicalize URL targets and deduplicate by crawl request identity: method,
/// canonical target URI, profile, declared identity mode, caller-supplied
/// headers, and body identity. Empty GET/HEAD bodies dedupe by target;
/// digest-bearing bodies dedupe by size+SHA-256; opaque bodies without a digest
/// stay request-id scoped regardless of declared size so distinct POST/form
/// submissions are not collapsed accidentally.
#[derive(Clone, PartialEq, Eq)]
pub struct CrawlFrontier {
    scheduler: CrawlScheduler,
    pending: BTreeMap<CrawlRequestKey, NetworkRequest>,
    pending_origins: BTreeMap<String, usize>,
    pending_bytes: usize,
    pending_origin_bytes: BTreeMap<String, usize>,
    max_global_pending: usize,
    max_pending_per_origin: usize,
    max_global_pending_bytes: usize,
    max_pending_bytes_per_origin: usize,
}

impl fmt::Debug for CrawlFrontier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrawlFrontier")
            .field("scheduler", &self.scheduler)
            .field("pending", &self.pending.len())
            .field("pending_origins", &self.pending_origins.len())
            .field("pending_bytes", &self.pending_bytes)
            .field("pending_origin_bytes", &self.pending_origin_bytes.len())
            .field("max_global_pending", &self.max_global_pending)
            .field("max_pending_per_origin", &self.max_pending_per_origin)
            .field("max_global_pending_bytes", &self.max_global_pending_bytes)
            .field(
                "max_pending_bytes_per_origin",
                &self.max_pending_bytes_per_origin,
            )
            .finish()
    }
}

impl CrawlFrontier {
    pub fn new(policy: CrawlPolicy) -> Self {
        Self {
            scheduler: CrawlScheduler::new(policy),
            pending: BTreeMap::new(),
            pending_origins: BTreeMap::new(),
            pending_bytes: 0,
            pending_origin_bytes: BTreeMap::new(),
            max_global_pending: DEFAULT_CRAWL_MAX_GLOBAL_PENDING,
            max_pending_per_origin: DEFAULT_CRAWL_MAX_PENDING_PER_ORIGIN,
            max_global_pending_bytes: DEFAULT_CRAWL_MAX_GLOBAL_PENDING_BYTES,
            max_pending_bytes_per_origin: DEFAULT_CRAWL_MAX_PENDING_BYTES_PER_ORIGIN,
        }
    }

    /// Bound the total pending queue for this frontier before dispatch.
    pub fn with_max_global_pending(mut self, max_pending: usize) -> Self {
        self.max_global_pending = max_pending.max(1);
        self
    }

    /// Bound pending queue entries for any one origin before dispatch.
    pub fn with_max_pending_per_origin(mut self, max_pending: usize) -> Self {
        self.max_pending_per_origin = max_pending.max(1);
        self
    }

    /// Bound retained pending request metadata bytes for this frontier before dispatch.
    pub fn with_max_global_pending_bytes(mut self, max_bytes: usize) -> Self {
        self.max_global_pending_bytes = max_bytes.max(1);
        self
    }

    /// Bound retained pending request metadata bytes for any one origin before dispatch.
    pub fn with_max_pending_bytes_per_origin(mut self, max_bytes: usize) -> Self {
        self.max_pending_bytes_per_origin = max_bytes.max(1);
        self
    }

    pub fn scheduler(&self) -> &CrawlScheduler {
        &self.scheduler
    }

    pub fn scheduler_mut(&mut self) -> &mut CrawlScheduler {
        &mut self.scheduler
    }

    /// Add a request by canonical crawl request identity. Returns `false` when
    /// the same identity is already pending or active.
    pub fn enqueue(&mut self, request: NetworkRequest) -> Result<bool, CrawlError> {
        let target = CrawlTarget::parse_request(&request)?;
        let key = target.request_key.clone();
        if self.pending.contains_key(&key) || self.scheduler.active_request_keys.contains(&key) {
            return Ok(false);
        }
        if self.pending.len() >= self.max_global_pending {
            return Err(crawl_limit_error(format!(
                "global pending crawl cap reached: {} >= {}",
                self.pending.len(),
                self.max_global_pending
            )));
        }
        let origin_pending = self
            .pending_origins
            .get(&target.origin)
            .copied()
            .unwrap_or_default();
        if origin_pending >= self.max_pending_per_origin {
            return Err(crawl_limit_error(format!(
                "per-origin pending crawl cap reached for {}: {} >= {}",
                target.origin, origin_pending, self.max_pending_per_origin
            )));
        }
        let estimated_bytes = estimated_pending_request_bytes(&request);
        if self.pending_bytes.saturating_add(estimated_bytes) > self.max_global_pending_bytes {
            return Err(crawl_limit_error(format!(
                "global pending crawl byte cap reached: {} + {} > {}",
                self.pending_bytes, estimated_bytes, self.max_global_pending_bytes
            )));
        }
        let origin_bytes = self
            .pending_origin_bytes
            .get(&target.origin)
            .copied()
            .unwrap_or_default();
        if origin_bytes.saturating_add(estimated_bytes) > self.max_pending_bytes_per_origin {
            return Err(crawl_limit_error(format!(
                "per-origin pending crawl byte cap reached for {}: {} + {} > {}",
                target.origin, origin_bytes, estimated_bytes, self.max_pending_bytes_per_origin
            )));
        }
        let origin = target.origin;
        self.pending.insert(key, request);
        *self.pending_origins.entry(origin.clone()).or_default() += 1;
        self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
        *self.pending_origin_bytes.entry(origin).or_default() += estimated_bytes;
        Ok(true)
    }

    /// Dispatch at most `max_requests` pending requests in deterministic request
    /// identity order, subject to global, per-origin, delay, robots, and backoff
    /// gates.
    ///
    /// Scheduler-only raw dispatch. The returned [`CrawlBatch`] has not passed
    /// connect-time URL/socket/egress checks, and callers must not hand its URLs
    /// to an HTTP client that can re-resolve them. SDK-facing network execution
    /// should use [`Self::dispatch_checked_ready`] and execute only against each
    /// [`CheckedCrawlDispatch::resolved_socket`].
    #[deprecated(
        note = "scheduler-only raw dispatch; use dispatch_checked_ready before network execution"
    )]
    pub fn dispatch_ready(
        &mut self,
        tick: u64,
        max_requests: usize,
    ) -> Result<CrawlBatch, CrawlError> {
        let mut batch = CrawlBatch::default();
        if max_requests == 0 {
            return Ok(batch);
        }

        let keys = self.pending.keys().cloned().collect::<Vec<_>>();
        let mut dispatched = 0usize;
        for key in keys {
            if dispatched >= max_requests {
                break;
            }
            let Some(request) = self.pending.get(&key).cloned() else {
                continue;
            };
            match self.scheduler.begin(&request, tick)? {
                CrawlDecision::Allow { origin } => {
                    self.remove_pending(&key);
                    batch.dispatches.push(CrawlDispatch { request, origin });
                    dispatched += 1;
                }
                decision @ CrawlDecision::Wait { .. } => batch.waiting.push(decision),
                decision @ CrawlDecision::Block { .. } => {
                    self.remove_pending(&key);
                    batch.blocked.push(decision);
                }
            }
        }
        Ok(batch)
    }

    /// Dispatch at most `max_requests` requests after connect-time policy checks.
    ///
    /// Unlike [`dispatch_ready`](Self::dispatch_ready), this method does not mark a
    /// request active until the caller-provided socket and the shared Tempo URL,
    /// egress, audit, and optional Web Bot Auth checks have passed. For direct
    /// egress, `resolve_socket` must return the target URL socket. For proxied
    /// egress, it must return the selected proxy endpoint socket; Tempo validates
    /// that socket against the proxy endpoint without resolving the target host.
    ///
    /// Callers that perform their own network I/O are responsible for pinning
    /// their HTTP client to each returned [`CheckedCrawlDispatch::resolved_socket`].
    /// Re-resolving the URL after this method returns invalidates the
    /// checked-dispatch guarantee. Prefer [`Self::dispatch_pinned_tcp_ready`]
    /// when the SDK can layer HTTP/TLS over a tempo-net-owned TCP stream.
    pub fn dispatch_checked_ready<F>(
        &mut self,
        tick: u64,
        max_requests: usize,
        guard: CrawlDispatchGuard<'_>,
        mut resolve_socket: F,
    ) -> Result<CrawlCheckedBatch, CrawlError>
    where
        F: FnMut(&CrawlDispatch) -> Result<SocketAddr, CrawlDispatchError>,
    {
        let mut batch = CrawlCheckedBatch::default();
        if max_requests == 0 {
            return Ok(batch);
        }

        let keys = self.pending.keys().cloned().collect::<Vec<_>>();
        let mut attempted = 0usize;
        for key in keys {
            if attempted >= max_requests {
                break;
            }
            let Some(request) = self.pending.get(&key).cloned() else {
                continue;
            };
            if self.scheduler.active_requests.contains_key(&request.id) {
                let target = CrawlTarget::parse_request(&request)?;
                self.remove_pending(&key);
                batch.blocked.push(CrawlDecision::Block {
                    origin: target.origin,
                    reason: "request id is already active".into(),
                });
                continue;
            }
            match self.scheduler.decide(&request, tick)? {
                CrawlDecision::Allow { origin } => {
                    let dispatch = CrawlDispatch { request, origin };
                    attempted += 1;
                    let egress_decision = match guard.precheck(&dispatch) {
                        Ok(egress_decision) => egress_decision,
                        Err(error) => {
                            self.remove_pending(&key);
                            batch
                                .rejected
                                .push(RejectedCrawlDispatch { dispatch, error });
                            continue;
                        }
                    };
                    let checked = match resolve_socket(&dispatch) {
                        Ok(resolved_socket) => guard.check_with_egress_decision(
                            &dispatch,
                            resolved_socket,
                            egress_decision,
                        ),
                        Err(error) => Err(error),
                    };
                    match checked {
                        Ok(checked) => match self
                            .scheduler
                            .begin(&checked.dispatch.request, tick)?
                        {
                            CrawlDecision::Allow { .. } => {
                                self.remove_pending(&key);
                                batch.dispatches.push(checked);
                            }
                            decision @ CrawlDecision::Wait { .. } => batch.waiting.push(decision),
                            decision @ CrawlDecision::Block { .. } => {
                                self.remove_pending(&key);
                                batch.blocked.push(decision);
                            }
                        },
                        Err(error) => {
                            self.remove_pending(&key);
                            batch
                                .rejected
                                .push(RejectedCrawlDispatch { dispatch, error });
                        }
                    }
                }
                decision @ CrawlDecision::Wait { .. } => batch.waiting.push(decision),
                decision @ CrawlDecision::Block { .. } => {
                    self.remove_pending(&key);
                    batch.blocked.push(decision);
                }
            }
        }
        Ok(batch)
    }

    /// Dispatch at most `max_requests` requests as already-open TCP streams.
    ///
    /// This is the SDK-facing network execution path for crawlers. tempo-net
    /// resolves the direct target or selected proxy endpoint, rejects the whole
    /// candidate set unless every socket passes the same URL/socket policy, and
    /// opens the TCP stream itself. Callers can layer HTTP/TLS over the returned
    /// stream without re-resolving the URL.
    pub fn dispatch_pinned_tcp_ready(
        &mut self,
        tick: u64,
        max_requests: usize,
        guard: CrawlDispatchGuard<'_>,
        connect_timeout: Duration,
    ) -> Result<CrawlPinnedBatch, CrawlError> {
        let mut batch = CrawlPinnedBatch::default();
        if max_requests == 0 {
            return Ok(batch);
        }

        let keys = self.pending.keys().cloned().collect::<Vec<_>>();
        let mut attempted = 0usize;
        for key in keys {
            if attempted >= max_requests {
                break;
            }
            let Some(request) = self.pending.get(&key).cloned() else {
                continue;
            };
            if self.scheduler.active_requests.contains_key(&request.id) {
                let target = CrawlTarget::parse_request(&request)?;
                self.remove_pending(&key);
                batch.blocked.push(CrawlDecision::Block {
                    origin: target.origin,
                    reason: "request id is already active".into(),
                });
                continue;
            }

            match self.scheduler.decide(&request, tick)? {
                CrawlDecision::Allow { origin } => {
                    let dispatch = CrawlDispatch { request, origin };
                    attempted += 1;
                    let egress_decision = match guard.precheck(&dispatch) {
                        Ok(egress_decision) => egress_decision,
                        Err(error) => {
                            self.remove_pending(&key);
                            batch.rejected.push(RejectedPinnedCrawlDispatch {
                                dispatch,
                                error: error.into(),
                            });
                            continue;
                        }
                    };
                    let pinned = match connect_checked_crawl_dispatch(
                        &dispatch,
                        guard,
                        egress_decision,
                        connect_timeout,
                    ) {
                        Ok(pinned) => pinned,
                        Err(error) => {
                            self.remove_pending(&key);
                            batch
                                .rejected
                                .push(RejectedPinnedCrawlDispatch { dispatch, error });
                            continue;
                        }
                    };

                    match self.scheduler.begin(&dispatch.request, tick)? {
                        CrawlDecision::Allow { .. } => {
                            self.remove_pending(&key);
                            batch.connections.push(pinned);
                        }
                        decision @ CrawlDecision::Wait { .. } => batch.waiting.push(decision),
                        decision @ CrawlDecision::Block { .. } => {
                            self.remove_pending(&key);
                            batch.blocked.push(decision);
                        }
                    }
                }
                decision @ CrawlDecision::Wait { .. } => batch.waiting.push(decision),
                decision @ CrawlDecision::Block { .. } => {
                    self.remove_pending(&key);
                    batch.blocked.push(decision);
                }
            }
        }
        Ok(batch)
    }

    pub fn finish(&mut self, response: &NetworkResponseRecord, tick: u64) -> bool {
        self.scheduler.finish(response, tick)
    }

    pub fn snapshot(&self) -> CrawlFrontierSnapshot {
        CrawlFrontierSnapshot {
            pending: self.pending.len(),
            inflight: self.scheduler.global_inflight(),
            origins: self.scheduler.snapshots(),
        }
    }

    fn remove_pending(&mut self, key: &CrawlRequestKey) -> Option<NetworkRequest> {
        let request = self.pending.remove(key)?;
        let estimated_bytes = estimated_pending_request_bytes(&request);
        self.pending_bytes = self.pending_bytes.saturating_sub(estimated_bytes);
        if let Ok(target) = CrawlTarget::parse_request(&request) {
            match self.pending_origins.get_mut(&target.origin) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    self.pending_origins.remove(&target.origin);
                }
                None => {}
            }
            match self.pending_origin_bytes.get_mut(&target.origin) {
                Some(bytes) if *bytes > estimated_bytes => *bytes -= estimated_bytes,
                Some(_) => {
                    self.pending_origin_bytes.remove(&target.origin);
                }
                None => {}
            }
        }
        Some(request)
    }
}

impl Default for CrawlFrontier {
    fn default() -> Self {
        Self::new(CrawlPolicy::default())
    }
}

fn crawl_limit_error(detail: impl Into<String>) -> CrawlError {
    CrawlError {
        reason: BlockReason::new(BlockCode::CrawlLimit, detail),
    }
}

fn estimated_pending_request_bytes(request: &NetworkRequest) -> usize {
    let headers = request
        .headers
        .iter()
        .map(|(name, values)| {
            name.len()
                + values
                    .iter()
                    .map(|value| value.len())
                    .fold(0usize, usize::saturating_add)
        })
        .fold(0usize, usize::saturating_add);
    std::mem::size_of::<NetworkRequest>()
        .saturating_add(request.id.0.len())
        .saturating_add(request.method.len())
        .saturating_add(request.url.len())
        .saturating_add(request.profile_id.0.len())
        .saturating_add(headers)
}

fn checked_crawl_dispatch(
    dispatch: &CrawlDispatch,
    url_policy: &UrlPolicy,
    egress_policy: &EgressPolicy,
    resolved_socket: SocketAddr,
    signer: Option<(&WebBotAuthSigningKey, u64)>,
) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
    let egress_decision = egress_policy.decide(&dispatch.request)?;
    checked_crawl_dispatch_with_decision(
        dispatch,
        url_policy,
        resolved_socket,
        signer,
        egress_decision,
        egress_policy.allow_insecure_local_proxy_endpoints,
    )
}

fn checked_crawl_dispatch_with_decision(
    dispatch: &CrawlDispatch,
    url_policy: &UrlPolicy,
    resolved_socket: SocketAddr,
    signer: Option<(&WebBotAuthSigningKey, u64)>,
    egress_decision: EgressDecision,
    allow_insecure_local_proxy_endpoints: bool,
) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
    let audit = match &egress_decision {
        EgressDecision::Direct { .. } => AuditRecord::from_request_with_resolved_socket(
            &dispatch.request,
            url_policy,
            resolved_socket,
        )?,
        EgressDecision::Proxied { proxy, .. } => {
            enforce_proxy_endpoint_resolved_socket(
                &proxy.endpoint,
                resolved_socket,
                allow_insecure_local_proxy_endpoints,
            )?;
            AuditRecord::from_request(&dispatch.request, url_policy)?
        }
    };
    checked_crawl_dispatch_from_records(dispatch, resolved_socket, signer, audit, egress_decision)
}

fn enforce_proxy_endpoint_resolved_socket(
    endpoint: &str,
    resolved_socket: SocketAddr,
    allow_insecure_local_proxy_endpoints: bool,
) -> Result<(), UrlBlocked> {
    let parts = UrlParts::parse(endpoint).map_err(|reason| UrlBlocked { reason })?;
    enforce_proxy_endpoint_parts_policy(&parts, allow_insecure_local_proxy_endpoints)?;
    let expected_port = proxy_endpoint_port(&parts)?;
    if expected_port != resolved_socket.port() {
        return Err(UrlBlocked {
            reason: BlockReason::new(
                BlockCode::InvalidUrl,
                format!(
                    "resolved proxy socket port {} does not match proxy endpoint port {expected_port}",
                    resolved_socket.port()
                ),
            ),
        });
    }

    if proxy_endpoint_uses_insecure_local_override(
        &parts,
        resolved_socket,
        allow_insecure_local_proxy_endpoints,
    ) {
        return Ok(());
    }

    if proxy_endpoint_host_is_localhost_name(&parts) {
        return Err(UrlBlocked {
            reason: BlockReason::new(BlockCode::Localhost, "proxy endpoint is localhost"),
        });
    }
    if let Some(ip) = proxy_endpoint_ip(&parts)
        && let Some(detail) = blocked_ip_reason(&ip)
    {
        return Err(UrlBlocked {
            reason: BlockReason::new(BlockCode::BlockedIp, format!("proxy endpoint IP {detail}")),
        });
    }
    if let Some(detail) = blocked_ip_reason(&resolved_socket.ip()) {
        return Err(UrlBlocked {
            reason: BlockReason::new(BlockCode::BlockedIp, format!("resolved proxy IP {detail}")),
        });
    }
    Ok(())
}

fn enforce_proxy_endpoint_preflight(
    endpoint: &str,
    allow_insecure_local_proxy_endpoints: bool,
) -> Result<(), UrlBlocked> {
    let _ = proxy_endpoint_target(endpoint, allow_insecure_local_proxy_endpoints)?;
    Ok(())
}

fn proxy_endpoint_target(
    endpoint: &str,
    allow_insecure_local_proxy_endpoints: bool,
) -> Result<ProxyEndpointTarget, UrlBlocked> {
    let parts = UrlParts::parse(endpoint).map_err(|reason| UrlBlocked { reason })?;
    enforce_proxy_endpoint_parts_policy(&parts, allow_insecure_local_proxy_endpoints)?;
    let port = proxy_endpoint_port(&parts)?;
    Ok(ProxyEndpointTarget {
        host: parts.host,
        port,
    })
}

fn enforce_proxy_endpoint_parts_policy(
    parts: &UrlParts,
    allow_insecure_local_proxy_endpoints: bool,
) -> Result<(), UrlBlocked> {
    let scheme = parts.scheme.as_str();
    if scheme.trim().is_empty() {
        return Err(UrlBlocked {
            reason: BlockReason::new(
                BlockCode::UnsupportedScheme,
                "proxy endpoint scheme is empty",
            ),
        });
    }
    if scheme == "https" {
        return Ok(());
    }
    if proxy_endpoint_scheme_is_cleartext(scheme) {
        if allow_insecure_local_proxy_endpoints && proxy_endpoint_host_is_loopback(parts) {
            return Ok(());
        }
        let detail = if allow_insecure_local_proxy_endpoints {
            format!("cleartext proxy endpoint scheme '{scheme}' is allowed only for loopback")
        } else {
            format!(
                "cleartext proxy endpoint scheme '{scheme}' is not allowed by default; use https:// or explicit local/test opt-in"
            )
        };
        return Err(UrlBlocked {
            reason: BlockReason::new(BlockCode::UnsupportedScheme, detail),
        });
    }
    Err(UrlBlocked {
        reason: BlockReason::new(
            BlockCode::UnsupportedScheme,
            format!("proxy endpoint scheme '{scheme}' is unsupported; use https://"),
        ),
    })
}

fn proxy_endpoint_scheme_is_cleartext(scheme: &str) -> bool {
    matches!(scheme, "http" | "socks4" | "socks4a" | "socks5" | "socks5h")
}

fn proxy_endpoint_uses_insecure_local_override(
    parts: &UrlParts,
    resolved_socket: SocketAddr,
    allow_insecure_local_proxy_endpoints: bool,
) -> bool {
    allow_insecure_local_proxy_endpoints
        && proxy_endpoint_scheme_is_cleartext(parts.scheme.as_str())
        && proxy_endpoint_host_is_loopback(parts)
        && resolved_socket.ip().is_loopback()
}

fn proxy_endpoint_host_is_loopback(parts: &UrlParts) -> bool {
    proxy_endpoint_host_is_localhost_name(parts)
        || proxy_endpoint_ip(parts).is_some_and(|ip| ip.is_loopback())
}

fn proxy_endpoint_host_is_localhost_name(parts: &UrlParts) -> bool {
    let host_for_name_checks = parts.host.trim_end_matches('.');
    host_for_name_checks == "localhost" || host_for_name_checks.ends_with(".localhost")
}

fn proxy_endpoint_ip(parts: &UrlParts) -> Option<IpAddr> {
    parts
        .host
        .parse::<IpAddr>()
        .ok()
        .or_else(|| parse_relaxed_ipv4(&parts.host).map(IpAddr::V4))
}

fn proxy_endpoint_port(parts: &UrlParts) -> Result<u16, UrlBlocked> {
    let port = match (parts.scheme.as_str(), parts.port) {
        (_, Some(port)) => port,
        ("http", None) => 80,
        ("https", None) => 443,
        ("socks4" | "socks4a" | "socks5" | "socks5h", None) => 1080,
        (scheme, None) => {
            return Err(UrlBlocked {
                reason: BlockReason::new(
                    BlockCode::InvalidUrl,
                    format!("proxy endpoint port is required for scheme '{scheme}'"),
                ),
            });
        }
    };
    if port == 0 {
        return Err(UrlBlocked {
            reason: BlockReason::new(
                BlockCode::InvalidUrl,
                "proxy endpoint port must be non-zero",
            ),
        });
    }
    Ok(port)
}

fn checked_crawl_dispatch_from_records(
    dispatch: &CrawlDispatch,
    resolved_socket: SocketAddr,
    signer: Option<(&WebBotAuthSigningKey, u64)>,
    audit: AuditRecord,
    egress_decision: EgressDecision,
) -> Result<CheckedCrawlDispatch, CrawlDispatchError> {
    let egress = EgressRecord::from_decision(
        dispatch.request.id.clone(),
        &egress_decision,
        dispatch.request.body_size(),
        0,
    );
    let signer = signer.filter(|_| dispatch.request.identity_mode == IdentityMode::AgentDeclared);
    let web_bot_auth_headers = signer
        .map(|(key, created)| dispatch.request.sign_web_bot_auth(key, created))
        .transpose()?;

    Ok(CheckedCrawlDispatch {
        dispatch: dispatch.clone(),
        resolved_socket,
        audit,
        egress,
        web_bot_auth_headers,
    })
}

fn connect_checked_crawl_dispatch(
    dispatch: &CrawlDispatch,
    guard: CrawlDispatchGuard<'_>,
    egress_decision: EgressDecision,
    connect_timeout: Duration,
) -> Result<PinnedCrawlConnection, CrawlConnectError> {
    let sockets = resolve_crawl_dispatch_sockets(dispatch, guard, &egress_decision)?;
    let mut last_connect_error = None;
    for resolved_socket in sockets {
        let checked =
            guard.check_with_egress_decision(dispatch, resolved_socket, egress_decision.clone())?;
        let pinned = checked.into_connection_pinned()?;
        match pinned.connect_tcp(connect_timeout) {
            Ok(stream) => return Ok(PinnedCrawlConnection { pinned, stream }),
            Err(error) => {
                last_connect_error = Some(CrawlConnectError::Connect {
                    resolved_socket,
                    reason: error.to_string(),
                });
            }
        }
    }
    Err(last_connect_error.unwrap_or_else(|| {
        CrawlConnectError::Resolve(ResolveUrlTargetError::EmptyResolution {
            host: dispatch.request.url.clone(),
            port: 0,
        })
    }))
}

fn resolve_crawl_dispatch_sockets(
    dispatch: &CrawlDispatch,
    guard: CrawlDispatchGuard<'_>,
    egress_decision: &EgressDecision,
) -> Result<Vec<SocketAddr>, CrawlConnectError> {
    match egress_decision {
        EgressDecision::Direct { .. } => {
            let url = url::Url::parse(&dispatch.request.url).map_err(|error| {
                CrawlDispatchError::Url(UrlBlocked {
                    reason: BlockReason::new(BlockCode::InvalidUrl, error.to_string()),
                })
            })?;
            Ok(resolve_url_target(&url, guard.url_policy)?
                .sockets()
                .to_vec())
        }
        EgressDecision::Proxied { proxy, .. } => {
            let target = guard.egress_policy.proxy_endpoint_target(proxy)?;
            let sockets = (target.host.as_str(), target.port)
                .to_socket_addrs()
                .map_err(|error| ResolveUrlTargetError::ResolveFailed {
                    host: target.host.clone(),
                    port: target.port,
                    reason: error.to_string(),
                })?
                .collect::<Vec<_>>();
            if sockets.is_empty() {
                return Err(ResolveUrlTargetError::EmptyResolution {
                    host: target.host,
                    port: target.port,
                }
                .into());
            }
            for socket in &sockets {
                guard
                    .egress_policy
                    .enforce_proxy_endpoint_resolved_socket(proxy, *socket)?;
            }
            Ok(sockets)
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OriginCrawlState {
    inflight: usize,
    last_started_tick: Option<u64>,
    backoff_until_tick: Option<u64>,
    robots: Option<RobotsRules>,
}

impl OriginCrawlState {
    fn snapshot(&self, origin: String) -> OriginCrawlSnapshot {
        OriginCrawlSnapshot {
            origin,
            inflight: self.inflight,
            last_started_tick: self.last_started_tick,
            backoff_until_tick: self.backoff_until_tick,
            robots_known: self.robots.is_some(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveCrawlRequest {
    origin: String,
    url_key: String,
    request_key: CrawlRequestKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlError {
    pub reason: BlockReason,
}

impl fmt::Display for CrawlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid crawl target: {}", self.reason.detail)
    }
}

impl Error for CrawlError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CrawlTarget {
    origin: String,
    path: String,
    robots_paths: Vec<String>,
    url_key: String,
    request_key: CrawlRequestKey,
}

impl CrawlTarget {
    fn parse_request(request: &NetworkRequest) -> Result<Self, CrawlError> {
        let parts = UrlParts::parse(&request.url).map_err(|reason| CrawlError { reason })?;
        let url_key = parts.target_uri();
        let robots_paths = crawl_robots_paths(&parts);
        let request_key = CrawlRequestKey::from_parts(request, url_key.clone());
        Ok(Self {
            origin: parts.origin(),
            path: parts.path,
            robots_paths,
            url_key,
            request_key,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CrawlRequestKey {
    target_uri: String,
    method: String,
    profile_id: ProfileId,
    identity_mode: IdentityMode,
    headers: BTreeMap<String, Vec<String>>,
    body: CrawlBodyKey,
}

impl CrawlRequestKey {
    fn from_parts(request: &NetworkRequest, target_uri: String) -> Self {
        let method = request.method.trim().to_ascii_uppercase();
        Self {
            target_uri,
            method: method.clone(),
            profile_id: request.profile_id.clone(),
            identity_mode: request.identity_mode,
            headers: request.headers.clone(),
            body: CrawlBodyKey::from_request(request, &method),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CrawlBodyKey {
    Empty,
    Digest { size: u64, sha256: [u8; 32] },
    Opaque { request_id: RequestId },
}

impl CrawlBodyKey {
    fn from_request(request: &NetworkRequest, method: &str) -> Self {
        if request.body_size == 0 && matches!(method, "GET" | "HEAD") {
            return Self::Empty;
        }
        match request.body_sha256 {
            Some(sha256) => Self::Digest {
                size: request.body_size,
                sha256,
            },
            None => Self::Opaque {
                request_id: request.id.clone(),
            },
        }
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

fn parse_signature_input(input: &str) -> Result<ParsedSignatureInput, SignatureError> {
    let (label, rest) = input
        .split_once('=')
        .ok_or_else(|| SignatureError::InvalidSignatureInput("missing label".into()))?;
    let label = label.trim();
    if label.is_empty() {
        return Err(SignatureError::InvalidSignatureInput(
            "missing label".into(),
        ));
    }
    let signature_params_value = rest.trim().to_string();
    let rest = signature_params_value.as_str();
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
    let mut expires = None;
    let mut nonce = None;
    let mut tag = None;
    for param in rest[component_end + 1..]
        .split(';')
        .filter(|part| !part.is_empty())
    {
        let (name, value) = param
            .trim()
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
            "expires" => {
                expires = Some(value.parse::<u64>().map_err(|_| {
                    SignatureError::InvalidSignatureInput("bad expires parameter".into())
                })?);
            }
            "nonce" => nonce = Some(unquote_sf_string(value)?),
            "tag" => tag = Some(unquote_sf_string(value)?),
            _ => {}
        }
    }

    if let Some(alg) = alg
        && alg != "ed25519"
    {
        return Err(SignatureError::UnsupportedAlgorithm(alg));
    }

    Ok(ParsedSignatureInput {
        params: SignatureParameters {
            label: label.to_string(),
            key_id: key_id
                .ok_or_else(|| SignatureError::InvalidSignatureInput("missing keyid".into()))?,
            created: created
                .ok_or_else(|| SignatureError::InvalidSignatureInput("missing created".into()))?,
            expires,
            nonce,
            tag,
            components,
        },
        signature_params_value,
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

fn validate_web_bot_auth_components(
    request: &NetworkRequest,
    params: &SignatureParameters,
) -> Result<(), SignatureError> {
    if params.tag.as_deref() != Some("web-bot-auth") {
        return Err(SignatureError::InvalidSignatureInput(
            "missing web-bot-auth tag".into(),
        ));
    }
    if params.expires.is_none() {
        return Err(SignatureError::InvalidSignatureInput(
            "missing expires parameter".into(),
        ));
    }

    let signature_agent = request.header_values("signature-agent");
    let has_signature_agent = params
        .components
        .iter()
        .any(|component| component == &CoveredComponent::Header("signature-agent".into()));
    let required = if let Some(values) = signature_agent {
        if values.len() != 1 {
            return Err(SignatureError::InvalidSignatureInput(
                "expected one Signature-Agent header".into(),
            ));
        }
        let signature_agent_uri = unquote_sf_string(values[0].trim())?;
        if !signature_agent_uri.starts_with("https://") {
            return Err(SignatureError::InvalidSignatureInput(
                "Signature-Agent must be an https URI".into(),
            ));
        }
        if !has_signature_agent {
            return Err(SignatureError::MissingRequiredComponent(
                "signature-agent".into(),
            ));
        }
        if params.nonce.as_deref().is_none_or(str::is_empty) {
            return Err(SignatureError::InvalidSignatureInput(
                "missing nonce parameter".into(),
            ));
        }
        vec![
            CoveredComponent::Authority,
            CoveredComponent::Header("signature-agent".into()),
        ]
    } else {
        vec![
            CoveredComponent::Method,
            CoveredComponent::Authority,
            CoveredComponent::Scheme,
            CoveredComponent::Path,
            CoveredComponent::Query,
        ]
    };

    for required in required {
        if !params
            .components
            .iter()
            .any(|component| component == &required)
        {
            return Err(SignatureError::MissingRequiredComponent(
                required.identifier(),
            ));
        }
    }
    Ok(())
}

fn validate_signature_freshness(
    params: &SignatureParameters,
    verifier: &WebBotAuthVerifier,
    now: u64,
) -> Result<(), SignatureError> {
    let max_age_secs = verifier.max_signature_age.as_secs();
    let allowed_skew_secs = verifier.allowed_clock_skew.as_secs();

    if let Some(expires) = params.expires
        && now > expires
    {
        return Err(SignatureError::SignatureExpired {
            created: params.created,
            now,
            max_age_secs: expires.saturating_sub(params.created),
        });
    }

    if params.created > now {
        let skew = params.created - now;
        if skew > allowed_skew_secs {
            return Err(SignatureError::SignatureCreatedInFuture {
                created: params.created,
                now,
                allowed_skew_secs,
            });
        }
        return Ok(());
    }

    let age = now - params.created;
    if age > max_age_secs {
        return Err(SignatureError::SignatureExpired {
            created: params.created,
            now,
            max_age_secs,
        });
    }

    Ok(())
}

fn unix_timestamp(time: SystemTime) -> Result<u64, SignatureError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignatureError::VerificationClockBeforeUnixEpoch)?
        .as_secs())
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
        // Normalize the authority/path the way the WHATWG parser (used by the
        // real fetch path via the `url` crate / reqwest / Servo) would, so this
        // guard cannot diverge from the host that is actually connected to
        // (issue #79). Without this, `https://169.254.169.254\@allowed.example/`
        // parses here as host `allowed.example` (allowed) while the fetch path
        // normalizes `\` to `/` and connects to the metadata IP.
        let normalized_rest = normalize_special_rest(&scheme, rest);
        let rest = normalized_rest.as_str();
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

/// Apply the WHATWG normalizations that matter for authority extraction so the
/// SSRF guard agrees with the real fetch path:
///   * ASCII tab (`\t`), newline (`\n`), and carriage return (`\r`) are removed
///     from the URL before parsing.
///   * For the special `http(s)` schemes a backslash is equivalent to a forward
///     slash, so it terminates the authority exactly like `/`.
///
/// Only the authority/path segment is rewritten; the query and fragment bytes
/// are preserved verbatim so signature bases stay byte-stable.
fn normalize_special_rest(scheme: &str, rest: &str) -> String {
    let mut cleaned: String = rest
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\n' | '\r'))
        .collect();
    if scheme == "http" || scheme == "https" {
        let split = cleaned.find(['?', '#']).unwrap_or(cleaned.len());
        let tail = cleaned.split_off(split);
        cleaned = cleaned.replace('\\', "/");
        cleaned.push_str(&tail);
    }
    cleaned
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
    normalize_path_dot_segments(&after_authority[..end])
}

fn query_component(rest: &str) -> Option<String> {
    let after_authority = &rest[authority(rest).len()..];
    let query_start = after_authority.find('?')?;
    let after_query = &after_authority[query_start..];
    let query_end = after_query.find('#').unwrap_or(after_query.len());
    Some(after_query[..query_end].to_string())
}

fn normalize_path_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/').skip(1) {
        if is_dot_path_segment(segment) {
            continue;
        }
        if is_dot_dot_path_segment(segment) {
            segments.pop();
            continue;
        }
        segments.push(segment);
    }

    let mut normalized = String::from("/");
    normalized.push_str(&segments.join("/"));
    if normalized.len() > 1
        && (path.ends_with('/')
            || path.rsplit('/').next().is_some_and(|segment| {
                is_dot_path_segment(segment) || is_dot_dot_path_segment(segment)
            }))
        && !normalized.ends_with('/')
    {
        normalized.push('/');
    }
    normalized
}

fn is_dot_path_segment(segment: &str) -> bool {
    matches!(segment.to_ascii_lowercase().as_str(), "." | "%2e")
}

fn is_dot_dot_path_segment(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        ".." | ".%2e" | "%2e." | "%2e%2e"
    )
}

fn parse_authority(authority: &str) -> Result<(String, String, Option<u16>), BlockReason> {
    if authority.starts_with('[') {
        let (bracketed, after) = authority.split_once(']').ok_or_else(|| {
            BlockReason::new(BlockCode::MalformedIpv6, "malformed bracketed IPv6 host")
        })?;
        let inner = &bracketed[1..];
        let host = strip_ipv6_zone(inner).parse::<Ipv6Addr>().map_err(|_| {
            BlockReason::new(BlockCode::MalformedIpv6, "malformed bracketed IPv6 host")
        })?;
        let host = host.to_string();
        let port = if after.is_empty() {
            None
        } else {
            let digits = after.strip_prefix(':').ok_or_else(|| {
                BlockReason::new(
                    BlockCode::InvalidUrl,
                    "IPv6 authority has invalid port separator",
                )
            })?;
            if digits.is_empty() {
                return Err(BlockReason::new(
                    BlockCode::InvalidUrl,
                    "URL port is not numeric",
                ));
            }
            Some(digits.parse::<u16>().map_err(|_| {
                BlockReason::new(BlockCode::InvalidUrl, "URL port is outside the u16 range")
            })?)
        };
        return Ok((host.clone(), format!("[{host}]"), port));
    }

    let (host_part, port) = match authority.rsplit_once(':') {
        Some((host, port_raw)) if port_raw.chars().all(|ch| ch.is_ascii_digit()) => (
            host,
            Some(port_raw.parse::<u16>().map_err(|_| {
                BlockReason::new(BlockCode::InvalidUrl, "URL port is outside the u16 range")
            })?),
        ),
        _ => (authority, None),
    };

    let (host, audit_host) = classify_host(host_part)?;
    Ok((host, audit_host, port))
}

/// Classify a non-bracketed authority host with the WHATWG host parser used by
/// the real fetch path (`url` crate → reqwest / Servo). This collapses
/// percent-decoding and IDNA normalization into the same parser rust-url uses,
/// so the guard's host provably matches the host reqwest will connect to
/// (issue #79). Without it, `169%2e254%2e169%2e254` and `169。254。169。254`
/// are seen here as opaque domains (allowed) while reqwest decodes/normalizes
/// them to the metadata IP `169.254.169.254`. A host the WHATWG parser rejects
/// is denied conservatively rather than allowed.
fn classify_host(host: &str) -> Result<(String, String), BlockReason> {
    match url::Host::parse(host) {
        Ok(url::Host::Domain(domain)) => Ok((domain.clone(), domain)),
        Ok(url::Host::Ipv4(ip)) => {
            let rendered = ip.to_string();
            Ok((rendered.clone(), rendered))
        }
        Ok(url::Host::Ipv6(ip)) => {
            let rendered = ip.to_string();
            Ok((rendered.clone(), format!("[{rendered}]")))
        }
        Err(error) => Err(BlockReason::new(
            BlockCode::InvalidUrl,
            format!("WHATWG host parse rejected authority: {error}"),
        )),
    }
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
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some(format!("{ip} is carrier-grade NAT (100.64.0.0/10)"));
    }
    if octets[0] == 0 {
        return Some(format!("{ip} is unspecified"));
    }
    if (224..=239).contains(&octets[0]) {
        return Some(format!("{ip} is multicast"));
    }
    if octets[0] >= 240 {
        return Some(format!("{ip} is reserved (240.0.0.0/4)"));
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
    if let Some(mapped) = ip.to_ipv4_mapped()
        && let Some(reason) = blocked_ipv4_reason(&mapped)
    {
        return Some(format!("{ip} maps to blocked IPv4: {reason}"));
    }
    None
}

/// Derive a stable, collision-resistant hex suffix used to name a session's
/// isolated cookie/storage partitions.
///
/// Profile names may be caller-supplied (and thus agent/attacker-influenced),
/// so a non-collision-resistant hash (the former FNV-1a-64) could be forced to
/// map two distinct profiles onto the same partition, breaking cross-profile
/// cookie/storage isolation. SHA-256 is collision-resistant; each part is
/// length-prefixed before hashing so component boundaries are unambiguous. The digest is
/// truncated to 32 lowercase-hex chars (128 bits) — a stable, filesystem-safe
/// identifier with ample margin against accidental collisions.
fn stable_partition_suffix(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        let bytes = part.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let digest = hasher.finalize();

    let mut suffix = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        // Writing formatted hex into a String is infallible.
        let _ = write!(suffix, "{byte:02x}");
    }
    suffix
}

fn canonical_domain(domain: impl Into<String>) -> String {
    domain.into().trim_end_matches('.').to_ascii_lowercase()
}

fn egress_port(parts: &UrlParts) -> u16 {
    parts.port.unwrap_or(match parts.scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => 0,
    })
}

fn redacted_url_for_debug(url: &str) -> String {
    UrlParts::parse(url)
        .map(|parts| parts.origin())
        .unwrap_or_else(|_| "[invalid-url]".into())
}

fn header_value_count(headers: &BTreeMap<String, Vec<String>>) -> usize {
    headers.values().map(Vec::len).sum()
}

fn crawl_origin(origin_or_url: &str) -> Result<String, CrawlError> {
    let parts = UrlParts::parse(origin_or_url).map_err(|reason| CrawlError { reason })?;
    Ok(parts.origin())
}

fn crawl_url_key(url: &str) -> Result<String, CrawlError> {
    let parts = UrlParts::parse(url).map_err(|reason| CrawlError { reason })?;
    Ok(parts.target_uri())
}

fn crawl_request_key(request: &NetworkRequest) -> Result<CrawlRequestKey, CrawlError> {
    let parts = UrlParts::parse(&request.url).map_err(|reason| CrawlError { reason })?;
    Ok(CrawlRequestKey::from_parts(request, parts.target_uri()))
}

fn crawl_robots_paths(parts: &UrlParts) -> Vec<String> {
    let mut primary = parts.path.clone();
    if let Some(query) = &parts.query {
        primary.push_str(query);
    }
    let mut paths = vec![primary.clone()];
    if let Some(decoded) = percent_decode_utf8(&primary)
        && decoded != primary
    {
        paths.push(decoded);
    }
    paths
}

fn robots_agent_specificity(target_lowercase: &str, rule_lowercase: &str) -> Option<usize> {
    let rule = rule_lowercase.trim();
    if rule.is_empty() {
        return None;
    }
    if rule == "*" {
        return Some(0);
    }
    target_lowercase.contains(rule).then_some(rule.len())
}

fn percent_decode_utf8(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            changed = true;
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    changed.then(|| String::from_utf8(decoded).ok()).flatten()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_robots_txt_path(path: &str) -> bool {
    path == "/robots.txt"
}

fn parse_crawl_delay_ticks(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    if let Some((whole, fraction)) = value.split_once('.') {
        let whole = whole.parse::<u64>().ok()?;
        let has_fraction = fraction.chars().any(|ch| ch != '0');
        return Some(if has_fraction {
            whole.saturating_add(1)
        } else {
            whole
        });
    }
    value.parse::<u64>().ok()
}

fn normalize_robots_pattern(pattern: &str) -> String {
    let anchored = pattern.ends_with('$');
    let pattern = pattern.strip_suffix('$').unwrap_or(pattern);
    let decoded = percent_decode_utf8(pattern).unwrap_or_else(|| pattern.to_string());
    let mut normalized = if decoded.starts_with('/') && !decoded.contains(['*', '?']) {
        normalize_path_dot_segments(&decoded)
    } else {
        decoded
    };
    if anchored {
        normalized.push('$');
    }
    normalized
}

fn robots_path_matches(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let anchored = pattern.ends_with('$');
    let pattern = pattern.strip_suffix('$').unwrap_or(pattern);
    if !pattern.contains('*') {
        return if anchored {
            path == pattern
        } else {
            path.starts_with(pattern)
        };
    }

    let parts = pattern.split('*').collect::<Vec<_>>();
    let Some(prefix) = parts.first().copied() else {
        return true;
    };
    if !path.starts_with(prefix) {
        return false;
    }
    let mut rest = &path[prefix.len()..];
    let Some((last, middle)) = parts[1..].split_last() else {
        return true;
    };
    for part in middle {
        if part.is_empty() {
            continue;
        }
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    if last.is_empty() {
        return true;
    }
    if anchored {
        rest.ends_with(last)
    } else {
        rest.contains(last)
    }
}

fn robots_specificity(pattern: &str) -> usize {
    pattern
        .chars()
        .filter(|ch| !matches!(ch, '*' | '$'))
        .count()
}

fn retry_after_until_tick(response: &NetworkResponseRecord, tick: u64) -> Option<u64> {
    if response.status != 429 && response.status != 503 {
        return None;
    }
    let retry_after = response
        .header_values("retry-after")
        .and_then(|values| values.first())
        .map(|value| value.trim())?;

    parse_retry_after_delta_ticks(retry_after, response)
        .map(|delay| tick.saturating_add(delay.max(1)))
}

fn parse_retry_after_delta_ticks(value: &str, response: &NetworkResponseRecord) -> Option<u64> {
    if let Ok(delay) = value.parse::<u64>() {
        return Some(delay);
    }

    let retry_after = httpdate::parse_http_date(value).ok()?;
    let Some(date) = response
        .header_values("date")
        .and_then(|values| values.first())
        .and_then(|value| httpdate::parse_http_date(value.trim()).ok())
    else {
        return Some(1);
    };
    let delta = retry_after.duration_since(date).unwrap_or_default();
    Some(
        delta
            .as_secs()
            .saturating_add(u64::from(delta.subsec_nanos() > 0)),
    )
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    const RFC9421_B26_PUBLIC_JWK_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
    const RFC9421_B26_SIGNATURE_INPUT: &str = "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
    const RFC9421_B26_SIGNATURE: &str = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:";

    fn assert_allowed(policy: &UrlPolicy, url: &str) {
        assert_eq!(policy.check(url), UrlPolicyVerdict::Allow, "{url}");
    }

    fn assert_blocked(policy: &UrlPolicy, url: &str, code: BlockCode) {
        let verdict = policy.check(url);
        assert!(
            matches!(verdict, UrlPolicyVerdict::Block(_)),
            "{url} unexpectedly allowed"
        );
        if let UrlPolicyVerdict::Block(reason) = verdict {
            assert_eq!(reason.code, code, "{url}");
        }
    }

    fn assert_close_f32(actual: f32, expected: f32) -> Result<(), String> {
        if (actual - expected).abs() <= 0.0001 {
            Ok(())
        } else {
            Err(format!("expected {expected}, got {actual}"))
        }
    }

    fn proxy_endpoint_with_credentials(
        scheme: &str,
        username: &str,
        password: &str,
        host: &str,
        port: u16,
    ) -> String {
        let mut endpoint = String::new();
        endpoint.push_str(scheme);
        endpoint.push_str("://");
        endpoint.push_str(username);
        endpoint.push(':');
        endpoint.push_str(password);
        endpoint.push('@');
        endpoint.push_str(host);
        endpoint.push(':');
        endpoint.push_str(&port.to_string());
        endpoint
    }

    fn rfc9421_b26_request() -> NetworkRequest {
        NetworkRequest::new(
            "rfc9421-b26",
            "POST",
            "https://example.com/foo?param=Value&Pet=dog",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .with_header("Content-Type", "application/json")
        .with_header("Content-Length", "18")
        .with_body_size(18)
    }

    fn rfc9421_b26_verifier() -> Result<WebBotAuthVerifier, SignatureError> {
        let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(RFC9421_B26_PUBLIC_JWK_X)
            .map_err(|err| SignatureError::InvalidKey(err.to_string()))?;
        WebBotAuthVerifier::from_public_key("test-key-ed25519", &public_key)
    }

    fn web_bot_auth_signature_agent_params(
        key_id: &str,
        created: u64,
        expires: u64,
    ) -> SignatureParameters {
        SignatureParameters {
            label: "sig1".into(),
            key_id: key_id.into(),
            created,
            expires: Some(expires),
            nonce: Some("test-nonce".into()),
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Authority,
                CoveredComponent::Header("signature-agent".into()),
            ],
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
    fn url_policy_blocks_whatwg_backslash_and_userinfo_bypasses() {
        // Issue #79: a backslash is a `/` for special schemes, so the metadata
        // IP is the real host even though a naive parser sees `allowed.example`.
        let policy = UrlPolicy::block_private();
        for url in [
            "https://169.254.169.254\\@allowed.example/",
            "https://169.254.169.254\\.allowed.example/",
            // Embedded tab/newline must be stripped before parsing.
            "https://169.254.169.254\t\\@allowed.example/",
            "https://169.254.169.254\n\\@allowed.example/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
        // Userinfo pointing at a public host is still stripped and allowed; the
        // backslash form above only differs because `\` terminates the authority.
        assert_allowed(&policy, "https://user:pass@example.com/path");
        assert_allowed(&policy, "https://allowed.example\\@example.com/");
    }

    #[test]
    fn url_policy_blocks_percent_encoded_and_idna_host_bypasses() {
        // Issue #79 follow-up: the guard must classify the host with the same
        // WHATWG parser reqwest uses, so percent-encoded / IDNA-normalized hosts
        // that decode to the metadata IP cannot slip through as opaque domains.
        let policy = UrlPolicy::block_private();
        for url in [
            // Percent-encoded dots -> 169.254.169.254 after decoding.
            "https://169%2e254%2e169%2e254/",
            "https://169%2E254%2E169%2E254/latest/meta-data",
            // Percent-encoded loopback.
            "https://127%2e0%2e0%2e1/",
            // IDNA: U+3002 ideographic full stops map to '.'.
            "https://169。254。169。254/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
        // enforce() (the production entry point) must also reject it.
        assert!(policy.enforce("https://169%2e254%2e169%2e254/").is_err());
        // A genuine public host is still allowed after WHATWG normalization.
        assert_allowed(&policy, "https://ex%61mple.com/");
    }

    #[test]
    fn url_policy_blocks_cgnat_and_reserved_ipv4() {
        // Issue #82: CGNAT 100.64.0.0/10 and reserved 240.0.0.0/4.
        let policy = UrlPolicy::block_private();
        for url in [
            "http://100.64.0.1/",
            "http://100.127.255.255/",
            "http://240.0.0.1/",
            "http://254.254.254.254/",
            "http://255.255.255.255/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
        // Neighbouring public ranges stay allowed.
        assert_allowed(&policy, "http://100.63.255.255/");
        assert_allowed(&policy, "http://100.128.0.1/");
    }

    #[test]
    fn url_policy_blocks_private_resolved_socket_targets() {
        let policy = UrlPolicy::block_private();
        let public_url = "https://public.example/agent";

        for ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let result = policy.enforce_resolved_ip(public_url, ip);
            assert!(
                matches!(&result, Err(error) if error.reason.code == BlockCode::BlockedIp),
                "{public_url} resolved to {ip} should have been blocked: {result:?}"
            );
            if let Err(error) = result {
                assert!(error.reason.detail.contains("resolved IP"));
            }
        }

        let socket = SocketAddr::from(([192, 168, 1, 10], 443));
        let result = policy.enforce_resolved_socket(public_url, socket);
        assert!(
            matches!(&result, Err(error) if error.reason.code == BlockCode::BlockedIp),
            "{public_url} resolved to {socket} should have been blocked: {result:?}"
        );
    }

    #[test]
    fn url_policy_allows_public_resolved_socket_targets() -> Result<(), UrlBlocked> {
        let policy = UrlPolicy::block_private();
        policy.enforce_resolved_ip(
            "https://public.example/agent",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        )?;
        policy.enforce_resolved_socket(
            "https://public.example/agent",
            SocketAddr::from(([93, 184, 216, 34], 443)),
        )?;
        Ok(())
    }

    #[test]
    fn checked_url_target_rejects_private_dns_answers_before_client_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = UrlPolicy::block_private();
        let url = url::Url::parse("https://public.example/agent")?;
        let result = checked_url_target_from_sockets(
            &url,
            "public.example",
            443,
            [SocketAddr::from(([169, 254, 169, 254], 443))],
            &policy,
        );

        assert!(
            matches!(
                &result,
                Err(ResolveUrlTargetError::UrlBlocked(error))
                    if error.reason.code == BlockCode::BlockedIp
                        && error.reason.detail.contains("resolved IP")
            ),
            "private DNS answer should be blocked: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn checked_url_target_returns_public_sockets_for_pinned_client(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = UrlPolicy::block_private();
        let url = url::Url::parse("https://public.example/agent")?;
        let socket = SocketAddr::from(([93, 184, 216, 34], 443));
        let target =
            checked_url_target_from_sockets(&url, "public.example", 443, [socket], &policy)?;

        assert_eq!(target.host(), "public.example");
        assert_eq!(target.sockets(), &[socket]);
        Ok(())
    }

    #[test]
    fn url_policy_rejects_resolved_socket_port_mismatch() {
        let result = UrlPolicy::block_private().enforce_resolved_socket(
            "https://public.example/agent",
            SocketAddr::from(([93, 184, 216, 34], 22)),
        );

        assert!(matches!(
            result,
            Err(UrlBlocked { reason })
                if reason.code == BlockCode::InvalidUrl
                    && reason.detail.contains("does not match URL port 443")
        ));
    }

    #[test]
    fn url_policy_allow_all_skips_resolved_socket_guard() -> Result<(), UrlBlocked> {
        UrlPolicy::allow_all().enforce_resolved_ip(
            "file:///etc/passwd",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        )?;
        UrlPolicy::allow_all().enforce_resolved_socket(
            "file:///etc/passwd",
            SocketAddr::from(([127, 0, 0, 1], 22)),
        )?;
        Ok(())
    }

    #[test]
    fn url_policy_rejects_non_bracketed_ports_outside_u16() {
        assert_blocked(
            &UrlPolicy::block_private(),
            "https://example.com:99999/a",
            BlockCode::InvalidUrl,
        );
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
        assert_blocked(&policy, "http://[not-ip]/", BlockCode::MalformedIpv6);
        assert_blocked(
            &policy,
            "http://[2001:db8::1]:not-a-port/",
            BlockCode::InvalidUrl,
        );
        assert_blocked(
            &policy,
            "http://[2001:db8::1]:999999/",
            BlockCode::InvalidUrl,
        );
        assert_blocked(&policy, "http://[2001:db8::1]extra/", BlockCode::InvalidUrl);
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
    fn partition_suffix_is_deterministic() {
        let a = stable_partition_suffix(&["session-a", "work"]);
        let b = stable_partition_suffix(&["session-a", "work"]);
        assert_eq!(a, b);

        // Same inputs must flow deterministically through the public constructor.
        let first = NetworkProfile::durable("session-a", "work");
        let second = NetworkProfile::durable("session-a", "work");
        assert_eq!(first.id, second.id);
        assert_eq!(first.cookie_partition, second.cookie_partition);
        assert_eq!(first.storage_partition, second.storage_partition);
    }

    #[test]
    fn partition_suffix_is_fixed_length_lowercase_hex() {
        let suffix = stable_partition_suffix(&["session-a", "work"]);
        assert_eq!(suffix.len(), 32);
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "unexpected charset: {suffix}"
        );
    }

    #[test]
    fn partition_suffix_differs_by_profile_name() {
        let a = stable_partition_suffix(&["session-a", "work"]);
        let b = stable_partition_suffix(&["session-a", "play"]);
        assert_ne!(a, b);

        let first = NetworkProfile::durable("session-a", "work");
        let second = NetworkProfile::durable("session-a", "play");
        assert_ne!(first.cookie_partition, second.cookie_partition);
        assert_ne!(first.storage_partition, second.storage_partition);
    }

    #[test]
    fn partition_suffix_differs_by_session_id() {
        let a = stable_partition_suffix(&["session-a", "work"]);
        let b = stable_partition_suffix(&["session-b", "work"]);
        assert_ne!(a, b);
    }

    #[test]
    fn partition_suffix_component_boundaries_are_unambiguous() {
        // Length prefixes must prevent boundary-shifting collisions: two profiles
        // whose concatenated inputs match but whose component splits differ must
        // still land on distinct partitions, even when inputs contain NUL bytes.
        let a = stable_partition_suffix(&["session-a", "work"]);
        let b = stable_partition_suffix(&["session", "a-work"]);
        let embedded_nul = stable_partition_suffix(&["session\0work"]);
        let split_at_nul = stable_partition_suffix(&["session", "work"]);
        assert_ne!(a, b);
        assert_ne!(embedded_nul, split_at_nul);
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
    fn identity_strategy_defaults_to_agent_declared_without_history() -> Result<(), String> {
        let table = IdentityStrategyTable::default();

        assert_eq!(
            table
                .mode_for_url("https://example.com/path?query=ignored")
                .map_err(|error| error.to_string())?,
            IdentityMode::AgentDeclared
        );
        assert_eq!(table.all_stats(), Vec::new());
        Ok(())
    }

    #[test]
    fn identity_strategy_tracks_challenge_rate_by_canonical_origin() -> Result<(), String> {
        let mut table = IdentityStrategyTable::new(IdentityStrategyConfig {
            max_agent_challenge_rate: 0.25,
        });

        let clean = table
            .record_request("https://Shop.Example:443/path?token=secret", false)
            .map_err(|error| error.to_string())?;
        let challenged = table
            .record_request("https://shop.example/checkout", true)
            .map_err(|error| error.to_string())?;
        let other = table
            .record_request("https://docs.example/path", false)
            .map_err(|error| error.to_string())?;

        assert_eq!(clean.origin, "https://shop.example");
        assert_eq!(challenged.origin, "https://shop.example");
        assert_eq!(challenged.total_requests, 2);
        assert_eq!(challenged.challenged_requests, 1);
        assert_close_f32(challenged.challenge_rate, 0.5)?;
        assert_eq!(challenged.selected_mode, IdentityMode::UserDriven);
        assert_eq!(other.selected_mode, IdentityMode::AgentDeclared);
        assert_eq!(
            table
                .mode_for_url("https://shop.example/account")
                .map_err(|error| error.to_string())?,
            IdentityMode::UserDriven
        );
        assert_eq!(
            table
                .mode_for_url("https://docs.example/")
                .map_err(|error| error.to_string())?,
            IdentityMode::AgentDeclared
        );
        Ok(())
    }

    #[test]
    fn identity_strategy_keeps_agent_mode_at_or_below_threshold() -> Result<(), String> {
        let mut table = IdentityStrategyTable::new(IdentityStrategyConfig {
            max_agent_challenge_rate: 0.50,
        });

        table
            .record_request("https://example.com/a", false)
            .map_err(|error| error.to_string())?;
        let stats = table
            .record_request("https://example.com/b", true)
            .map_err(|error| error.to_string())?;

        assert_close_f32(stats.challenge_rate, 0.5)?;
        assert_eq!(stats.selected_mode, IdentityMode::AgentDeclared);
        Ok(())
    }

    #[test]
    fn identity_strategy_rejects_non_http_targets() {
        let mut table = IdentityStrategyTable::default();

        let result = table.record_request("file:///tmp/page.html", true);
        assert!(matches!(
            result,
            Err(IdentityStrategyError {
                reason: BlockReason {
                    code: BlockCode::UnsupportedScheme,
                    ..
                },
            })
        ));
    }

    #[test]
    fn identity_strategy_table_stays_bounded_under_many_origins() -> Result<(), String> {
        let capacity = 8;
        let mut table =
            IdentityStrategyTable::with_capacity(IdentityStrategyConfig::default(), capacity);

        // Touch far more distinct origins than the capacity.
        for i in 0..1_000 {
            table
                .record_request(&format!("https://origin-{i}.example/path"), false)
                .map_err(|error| error.to_string())?;
        }

        assert_eq!(table.tracked_origins(), capacity);
        assert!(table.tracked_origins() <= table.capacity());
        Ok(())
    }

    #[test]
    fn identity_strategy_table_preserves_recently_used_origins() -> Result<(), String> {
        let capacity = 4;
        let mut table =
            IdentityStrategyTable::with_capacity(IdentityStrategyConfig::default(), capacity);

        // Seed an origin whose counters we want to keep alive.
        table
            .record_request("https://keep.example/a", true)
            .map_err(|error| error.to_string())?;

        // Interleave: keep touching `keep.example` while flooding new origins so
        // that `keep.example` is never the least-recently-used entry.
        for i in 0..100 {
            table
                .record_request(&format!("https://flood-{i}.example/p"), false)
                .map_err(|error| error.to_string())?;
            table
                .record_request("https://keep.example/b", false)
                .map_err(|error| error.to_string())?;
        }

        // Bounded overall...
        assert_eq!(table.tracked_origins(), capacity);
        // ...but the actively-used origin retains its accumulated counters.
        let stats = table
            .stats_for_url("https://keep.example/x")
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "recently-used origin was evicted".to_string())?;
        assert_eq!(stats.total_requests, 101);
        assert_eq!(stats.challenged_requests, 1);

        // A stale flooded origin was evicted along the way.
        assert_eq!(
            table
                .stats_for_url("https://flood-0.example/x")
                .map_err(|error| error.to_string())?,
            None
        );
        Ok(())
    }

    #[test]
    fn audit_record_is_taint_free_and_origin_only() -> Result<(), UrlBlocked> {
        let profile = NetworkProfile::ephemeral("session-a");
        let request = NetworkRequest::new(
            "r1",
            "get",
            "https://user:secret@example.com:8443/path?q=page-derived#frag",
            profile.id.clone(),
            IdentityMode::AgentDeclared,
        );

        let audit = AuditRecord::from_request(&request, &UrlPolicy::block_private())?;

        assert_eq!(audit.request_id, RequestId("r1".into()));
        assert_eq!(audit.method, "GET");
        assert_eq!(audit.origin, "https://example.com:8443");
        assert_eq!(audit.profile_id, profile.id);
        assert_eq!(audit.identity_mode, IdentityMode::AgentDeclared);
        assert!(audit.taint_free);
        assert!(!audit.origin.contains("secret"));
        assert!(!audit.origin.contains("page-derived"));
        Ok(())
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
    fn audit_record_enforces_resolved_socket_policy_before_emitting() -> Result<(), UrlBlocked> {
        let profile = NetworkProfile::ephemeral("session-a");
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://public.example/agent?payload=page-derived",
            profile.id,
            IdentityMode::AgentDeclared,
        );

        let audit = AuditRecord::from_request_with_resolved_ip(
            &request,
            &UrlPolicy::block_private(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        )?;
        assert_eq!(audit.origin, "https://public.example");
        assert!(audit.taint_free);

        let blocked = AuditRecord::from_request_with_resolved_socket(
            &request,
            &UrlPolicy::block_private(),
            SocketAddr::from(([169, 254, 169, 254], 443)),
        );
        assert!(
            matches!(&blocked, Err(error) if error.reason.code == BlockCode::BlockedIp),
            "blocked resolved socket emitted audit record: {blocked:?}"
        );
        Ok(())
    }

    #[test]
    fn network_request_exposes_dispatch_metadata_for_protocol_events() {
        let request = NetworkRequest::new(
            "r1",
            "post",
            "https://example.com/upload",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Content-Type", "application/json")
        .with_header("Accept", "application/json")
        .with_body_size(512);

        let headers = request.headers().collect::<Vec<_>>();

        assert_eq!(request.body_size(), 512);
        assert_eq!(
            request
                .header_values("content-type")
                .map(<[String]>::to_vec),
            Some(vec!["application/json".to_string()])
        );
        assert_eq!(
            headers,
            vec![
                ("accept", "application/json"),
                ("content-type", "application/json")
            ]
        );
    }

    #[test]
    fn network_response_record_exposes_response_metadata_for_protocol_events() {
        let response = NetworkResponseRecord::new("r1", "https://example.com/data", 200)
            .with_header("Content-Type", "application/json")
            .with_body_size(17);

        assert_eq!(response.request_id, RequestId("r1".into()));
        assert_eq!(response.url, "https://example.com/data");
        assert_eq!(response.status, 200);
        assert_eq!(response.body_size(), 17);
        assert_eq!(
            response.headers().collect::<Vec<_>>(),
            vec![("content-type", "application/json")]
        );
    }

    #[test]
    fn debug_output_redacts_private_network_material() -> Result<(), Box<dyn Error>> {
        let mut store = ProfileStore::new();
        let profile = store.create_ephemeral("session-secret");
        store.set_cookie(
            &profile.id,
            "https://example.com",
            "sid",
            "session-cookie-value",
        )?;
        let cookie = store
            .cookies_for(&profile.id, "https://example.com")
            .into_iter()
            .next()
            .ok_or("expected cookie")?;
        let request = NetworkRequest::new(
            "r1",
            "POST",
            "https://user:secret@example.com/path?token=secret#fragment",
            profile.id.clone(),
            IdentityMode::AgentDeclared,
        )
        .with_header("Authorization", "Bearer top-secret-token")
        .with_header("Cookie", "sid=session-cookie-value")
        .with_body_bytes(b"secret request body");
        let response =
            NetworkResponseRecord::new("r1", "https://example.com/redirect?token=secret", 302)
                .with_header("Set-Cookie", "sid=session-cookie-value")
                .with_header("Location", "https://example.com/path?token=secret")
                .with_body_size(27);
        let proxy = ProxyRoute::new(
            "primary",
            "https://proxy-user:proxy-secret@proxy.example:8443",
        );
        let key = WebBotAuthSigningKey::from_seed("tempo-agent-secret", &[7u8; 32])?;
        let headers = request.sign_web_bot_auth(&key, 1_800_000_000)?;
        let profile_debug = format!("{profile:?}");
        let verifier_debug = format!("{:?}", key.verifier());

        let debug = format!(
            "{request:?}\n{response:?}\n{cookie:?}\n{store:?}\n{profile_debug}\n{proxy:?}\n{headers:?}\n{verifier_debug}"
        );

        for secret in [
            "user:secret",
            "token=secret",
            "Bearer",
            "top-secret-token",
            "session-secret",
            "session-cookie-value",
            "secret request body",
            &profile.session_id.0,
            &profile.cookie_partition,
            &profile.storage_partition,
            "proxy-secret",
            "tempo-agent-secret",
            &headers.signature,
        ] {
            assert!(!debug.contains(secret), "leaked {secret}: {debug}");
        }
        assert!(debug.contains("https://example.com"));
        assert!(debug.contains("header_count"));
        Ok(())
    }

    #[test]
    fn egress_policy_allows_direct_public_request_by_default() -> Result<(), EgressDenied> {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/path?q=secret",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let decision = EgressPolicy::allow_all().decide(&request)?;

        assert_eq!(
            decision,
            EgressDecision::Direct {
                domain: "example.com".into(),
                port: 443,
            }
        );
        Ok(())
    }

    #[test]
    fn egress_policy_blocks_default_except_allowed_domains() -> Result<(), EgressDenied> {
        let allowed = NetworkRequest::new(
            "r1",
            "GET",
            "https://api.example/data",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let blocked = NetworkRequest::new(
            "r2",
            "GET",
            "https://other.example/data",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy =
            EgressPolicy::block_by_default().allow_domain(DomainRule::exact("api.example"));

        let allowed_decision = policy.decide(&allowed)?;
        let blocked_decision = policy.decide(&blocked);

        assert_eq!(allowed_decision.domain(), "api.example");
        assert!(matches!(blocked_decision, Err(EgressDenied { .. })));
        Ok(())
    }

    #[test]
    fn egress_policy_selects_most_specific_proxy_route() -> Result<(), EgressDenied> {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://payments.example.com/charge",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy = EgressPolicy::block_by_default()
            .proxy_domain(
                DomainRule::suffix("example.com"),
                ProxyRoute::new("general", "https://proxy.example:8443"),
            )
            .proxy_domain(
                DomainRule::exact("payments.example.com"),
                ProxyRoute::new("payments", "https://payments-proxy.example:9443"),
            );

        let decision = policy.decide(&request)?;

        assert_eq!(decision.proxy_id(), Some("payments"));
        assert_eq!(decision.port(), 443);
        Ok(())
    }

    #[test]
    fn egress_policy_rejects_cleartext_proxy_credentials_by_default() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://proxied.example/page",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let proxy_user = "proxy-user";
        let proxy_pass = "proxy-pass";
        let endpoint =
            proxy_endpoint_with_credentials("http", proxy_user, proxy_pass, "proxy.example", 8080);
        let route = ProxyRoute::new("proxy-a", endpoint);
        let policy = EgressPolicy::block_by_default()
            .proxy_domain(DomainRule::exact("proxied.example"), route.clone());

        let denied = match policy.decide(&request) {
            Ok(decision) => panic!("expected rejection, got {decision:?}"),
            Err(denied) => denied,
        };
        let debug = format!("{route:?}\n{denied:?}");

        assert_eq!(denied.domain, "proxied.example");
        assert_eq!(denied.port, 443);
        assert!(denied
            .reason
            .contains("cleartext proxy endpoint scheme 'http'"));
        assert!(denied.reason.contains("not allowed by default"));
        for secret in [
            proxy_user,
            proxy_pass,
            "proxy.example:8080",
            &format!("{proxy_user}:{proxy_pass}"),
        ] {
            assert!(!debug.contains(secret), "leaked {secret}: {debug}");
        }
    }

    #[test]
    fn egress_policy_insecure_proxy_opt_in_is_loopback_only() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://proxied.example/page",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy = EgressPolicy::block_by_default()
            .allow_insecure_local_proxy_endpoints()
            .proxy_domain(
                DomainRule::exact("proxied.example"),
                ProxyRoute::new("proxy-a", "http://proxy.example:8080"),
            );

        let denied = match policy.decide(&request) {
            Ok(decision) => panic!("expected rejection, got {decision:?}"),
            Err(denied) => denied,
        };

        assert_eq!(denied.domain, "proxied.example");
        assert!(denied
            .reason
            .contains("cleartext proxy endpoint scheme 'http'"));
        assert!(denied.reason.contains("allowed only for loopback"));
    }

    #[test]
    fn egress_policy_explicit_block_precedes_proxy_route() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://blocked.example.com/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy = EgressPolicy::allow_all()
            .proxy_domain(
                DomainRule::suffix("example.com"),
                ProxyRoute::new("general", "https://proxy.example:8443"),
            )
            .block_domain(DomainRule::exact("blocked.example.com"));

        let decision = policy.decide(&request);

        assert!(matches!(decision, Err(EgressDenied { .. })));
    }

    #[test]
    fn domain_rule_matches_ignore_trailing_dot_fqdn() {
        // Exact rule form.
        assert!(DomainRule::exact("blocked.example.com").matches("blocked.example.com."));
        assert!(DomainRule::exact("blocked.example.com").matches("Blocked.Example.Com."));
        // Suffix rule form.
        assert!(DomainRule::suffix("example.com").matches("blocked.example.com."));
        assert!(DomainRule::suffix("example.com").matches("example.com."));
        // Non-matching FQDN still does not match.
        assert!(!DomainRule::exact("blocked.example.com").matches("safe.example.com."));
    }

    #[test]
    fn egress_policy_blocks_trailing_dot_fqdn_exact_rule() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://blocked.example.com./path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy =
            EgressPolicy::allow_all().block_domain(DomainRule::exact("blocked.example.com"));

        let decision = policy.decide(&request);

        assert!(matches!(decision, Err(EgressDenied { .. })));
    }

    #[test]
    fn egress_policy_blocks_trailing_dot_fqdn_suffix_rule() {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://blocked.example.com./path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy = EgressPolicy::allow_all().block_domain(DomainRule::suffix("example.com"));

        let decision = policy.decide(&request);

        assert!(matches!(decision, Err(EgressDenied { .. })));
    }

    #[test]
    fn egress_policy_allowlist_treats_trailing_dot_fqdn_as_allowed() -> Result<(), EgressDenied> {
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://api.example./data",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let policy =
            EgressPolicy::block_by_default().allow_domain(DomainRule::exact("api.example"));

        let decision = policy.decide(&request)?;

        // The FQDN passes the allowlist and the reported domain is canonicalized.
        assert_eq!(decision.domain(), "api.example");
        Ok(())
    }

    #[test]
    fn egress_record_is_joinable_and_sanitized() -> Result<(), EgressDenied> {
        let request = NetworkRequest::new(
            "r1",
            "POST",
            "https://api.example/upload?token=page-derived",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let decision = EgressPolicy::allow_all().decide(&request)?;

        let record = EgressRecord::from_decision(request.id.clone(), &decision, 123, 456);

        assert_eq!(record.request_id, request.id);
        assert_eq!(record.domain, "api.example");
        assert_eq!(record.port, 443);
        assert_eq!(record.proxy_id, None);
        assert_eq!(record.bytes_sent, 123);
        assert_eq!(record.bytes_received, 456);
        assert!(!record.domain.contains("token"));
        Ok(())
    }

    #[test]
    fn rfc9421_ed25519_reference_vector_verifies() -> Result<(), SignatureError> {
        verify_request_signature_at(
            &rfc9421_b26_request(),
            RFC9421_B26_SIGNATURE_INPUT,
            RFC9421_B26_SIGNATURE,
            &rfc9421_b26_verifier()?,
            1_618_884_473,
        )
    }

    #[test]
    fn rfc9421_verifier_preserves_serialized_signature_params() -> Result<(), SignatureError> {
        let signature_input = format!("{RFC9421_B26_SIGNATURE_INPUT};expires=1618884773");

        let result = verify_request_signature_at(
            &rfc9421_b26_request(),
            &signature_input,
            RFC9421_B26_SIGNATURE,
            &rfc9421_b26_verifier()?,
            1_618_884_473,
        );

        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
        Ok(())
    }

    #[test]
    fn web_bot_auth_signs_and_verifies_strict_headers() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let verifier = key.verifier();
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com:443/agent/path?tainted=not-signed",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("accept", "application/json");

        let headers = request.sign_web_bot_auth(&key, 1_800_000_000)?;

        assert_eq!(
            headers.signature_input,
            "sig1=(\"@method\" \"@authority\" \"@scheme\" \"@path\" \"@query\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\";expires=1800000300;tag=\"web-bot-auth\""
        );
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.signature.ends_with(':'));

        let base = signature_base(
            &request,
            &SignatureParameters::web_bot_auth("tempo-agent", 1_800_000_000),
        )?;
        assert_eq!(
            base,
            "\"@method\": GET\n\"@authority\": example.com\n\"@scheme\": https\n\"@path\": /agent/path\n\"@query\": ?tainted=not-signed\n\"@signature-params\": (\"@method\" \"@authority\" \"@scheme\" \"@path\" \"@query\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\";expires=1800000300;tag=\"web-bot-auth\""
        );

        verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &verifier,
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_signs_signature_agent_expires_nonce_and_tag() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let headers = request.sign_web_bot_auth_with_agent(
            &key,
            1_800_000_000,
            1_800_000_300,
            "test-nonce",
            "https://signature-agent.test",
        )?;

        assert_eq!(
            headers.signature_agent.as_deref(),
            Some("\"https://signature-agent.test\"")
        );
        assert_eq!(
            headers.signature_input,
            "sig1=(\"@authority\" \"signature-agent\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\";expires=1800000300;nonce=\"test-nonce\";tag=\"web-bot-auth\""
        );
        assert_eq!(headers.header_pairs().len(), 3);

        let signed_request = request.with_header(
            "Signature-Agent",
            headers.signature_agent.clone().unwrap_or_default(),
        );
        verify_web_bot_auth_signature_at(
            &signed_request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_query_not_covered() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path?token=must-be-signed",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: "tempo-agent".into(),
            created: 1_800_000_000,
            expires: Some(1_800_000_300),
            nonce: None,
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Method,
                CoveredComponent::Authority,
                CoveredComponent::Scheme,
                CoveredComponent::Path,
            ],
        };
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );

        assert!(matches!(
            result,
            Err(SignatureError::MissingRequiredComponent(component)) if component == "@query"
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_signature_agent_without_nonce() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Signature-Agent", "\"https://signature-agent.test\"");
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: "tempo-agent".into(),
            created: 1_800_000_000,
            expires: Some(1_800_000_300),
            nonce: None,
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Authority,
                CoveredComponent::Header("signature-agent".into()),
            ],
        };
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );

        assert!(matches!(
            result,
            Err(SignatureError::InvalidSignatureInput(reason))
                if reason == "missing nonce parameter"
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_signature_agent_header_not_covered() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Signature-Agent", "\"https://signature-agent.test\"");
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: "tempo-agent".into(),
            created: 1_800_000_000,
            expires: Some(1_800_000_300),
            nonce: None,
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Method,
                CoveredComponent::Authority,
                CoveredComponent::Scheme,
                CoveredComponent::Path,
            ],
        };
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );

        assert!(matches!(
            result,
            Err(SignatureError::MissingRequiredComponent(component))
                if component == "signature-agent"
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_unquoted_signature_agent_header() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Signature-Agent", "https://signature-agent.test");
        let params =
            web_bot_auth_signature_agent_params("tempo-agent", 1_800_000_000, 1_800_000_300);
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );

        assert!(matches!(
            result,
            Err(SignatureError::InvalidSignatureInput(reason)) if reason == "expected quoted string"
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_non_https_signature_agent_header() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        )
        .with_header("Signature-Agent", "\"http://signature-agent.test\"");
        let params =
            web_bot_auth_signature_agent_params("tempo-agent", 1_800_000_000, 1_800_000_300);
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );

        assert!(matches!(
            result,
            Err(SignatureError::InvalidSignatureInput(reason))
                if reason == "Signature-Agent must be an https URI"
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_verifies_fresh_headers_with_system_clock() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let created = unix_timestamp(SystemTime::now())?;
        let headers = request.sign_web_bot_auth(&key, created)?;

        verify_web_bot_auth_signature(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_tampered_requests_and_wrong_keys() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let wrong = WebBotAuthSigningKey::from_seed("other-agent", &[9u8; 32])?.verifier();
        let request = NetworkRequest::new(
            "r1",
            "POST",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let headers = request.sign_web_bot_auth(&key, 1_800_000_000)?;
        let tampered = NetworkRequest::new(
            "r1",
            "POST",
            "https://example.com/agent/path?tampered=true",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let tampered_result = verify_web_bot_auth_signature_at(
            &tampered,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );
        assert!(matches!(
            tampered_result,
            Err(SignatureError::VerificationFailed)
        ));

        let wrong_key_result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &wrong,
            1_800_000_000,
        );
        assert!(matches!(
            wrong_key_result,
            Err(SignatureError::KeyIdMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn web_bot_auth_rejects_stale_and_future_created_times() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let verifier = key.verifier();
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let stale_headers = request.sign_web_bot_auth(&key, 1_800_000_000)?;
        let stale_result = verify_web_bot_auth_signature_at(
            &request,
            &stale_headers.signature_input,
            &stale_headers.signature,
            &verifier,
            1_800_000_301,
        );
        assert!(matches!(
            stale_result,
            Err(SignatureError::SignatureExpired {
                created: 1_800_000_000,
                now: 1_800_000_301,
                max_age_secs: 300
            })
        ));

        let future_headers = request.sign_web_bot_auth(&key, 1_800_001_000)?;
        let future_result = verify_web_bot_auth_signature_at(
            &request,
            &future_headers.signature_input,
            &future_headers.signature,
            &verifier,
            1_800_000_000,
        );
        assert!(matches!(
            future_result,
            Err(SignatureError::SignatureCreatedInFuture {
                created: 1_800_001_000,
                now: 1_800_000_000,
                allowed_skew_secs: 60
            })
        ));

        let skewed_headers = request.sign_web_bot_auth(&key, 1_800_000_060)?;
        verify_web_bot_auth_signature_at(
            &request,
            &skewed_headers.signature_input,
            &skewed_headers.signature,
            &verifier,
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_honors_custom_clock_skew_but_not_explicit_expiry() -> Result<(), SignatureError>
    {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let verifier = key
            .verifier()
            .with_max_signature_age(Duration::from_secs(600))
            .with_allowed_clock_skew(Duration::from_secs(120));
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let old_headers = request.sign_web_bot_auth(&key, 1_800_000_000)?;
        let old_result = verify_web_bot_auth_signature_at(
            &request,
            &old_headers.signature_input,
            &old_headers.signature,
            &verifier,
            1_800_000_600,
        );
        assert!(matches!(
            old_result,
            Err(SignatureError::SignatureExpired {
                created: 1_800_000_000,
                now: 1_800_000_600,
                max_age_secs: 300
            })
        ));

        let future_headers = request.sign_web_bot_auth(&key, 1_800_000_120)?;
        verify_web_bot_auth_signature_at(
            &request,
            &future_headers.signature_input,
            &future_headers.signature,
            &verifier,
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_requires_method_authority_scheme_and_path() -> Result<(), SignatureError> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let request = NetworkRequest::new(
            "r1",
            "GET",
            "https://example.com/agent/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );
        let params = SignatureParameters {
            label: "sig1".into(),
            key_id: "tempo-agent".into(),
            created: 1_800_000_000,
            expires: Some(1_800_000_300),
            nonce: None,
            tag: Some("web-bot-auth".into()),
            components: vec![
                CoveredComponent::Method,
                CoveredComponent::Authority,
                CoveredComponent::Scheme,
            ],
        };
        let headers = sign_request(&request, &params, &key)?;

        let result = verify_web_bot_auth_signature_at(
            &request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        );
        assert!(matches!(
            result,
            Err(SignatureError::MissingRequiredComponent(component)) if component == "@path"
        ));
        Ok(())
    }

    #[test]
    fn signature_base_can_cover_request_headers() -> Result<(), SignatureError> {
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
            expires: None,
            nonce: None,
            tag: None,
            components: vec![CoveredComponent::Header("accept".into())],
        };

        let base = signature_base(&request, &params)?;
        assert_eq!(
            base,
            "\"accept\": application/json, text/plain\n\"@signature-params\": (\"accept\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );
        Ok(())
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

    #[test]
    fn robots_rules_select_matching_group_and_prefer_specific_allow() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: otherbot
Disallow: /

User-agent: *
Disallow: /private
Allow: /private/public
Crawl-delay: 3
"#,
        );

        assert!(!robots.allows_path("/private"));
        assert!(!robots.allows_path("/private/deep"));
        assert!(robots.allows_path("/private/public"));
        assert!(robots.allows_path("/public"));
        assert_eq!(robots.crawl_delay_ticks(), Some(3));
    }

    #[test]
    fn robots_rules_prefer_specific_agent_group_without_blank_line() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: *
Allow: /private
User-agent: tempo-agent
Disallow: /private
"#,
        );

        assert!(!robots.allows_path("/private"));
    }

    #[test]
    fn robots_rules_choose_allow_on_equal_specificity() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: tempo-agent
Allow: /same
Disallow: /same
"#,
        );

        assert!(robots.allows_path("/same"));
    }

    #[test]
    fn robots_rules_decode_directive_patterns() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: tempo-agent
Disallow: /%70rivate
"#,
        );

        assert!(!robots.allows_path("/private"));
    }

    #[test]
    fn robots_rules_match_repeated_wildcards_in_order() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: tempo-agent
Disallow: /a/*/c/*/e
"#,
        );

        assert!(!robots.allows_path("/a/b/c/d/e"));
        assert!(robots.allows_path("/a/b/x/d/e"));
    }

    #[test]
    fn robots_rules_select_most_specific_agent_group_without_blank_separator() {
        let robots = RobotsRules::parse_for_agent(
            "tempo-agent",
            r#"
User-agent: *
Allow: /
User-agent: tempo-agent
Disallow: /
"#,
        );

        assert!(!robots.allows_path("/"));
    }

    #[test]
    fn crawl_scheduler_caps_one_origin_without_blocking_parallel_origins() -> Result<(), CrawlError>
    {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_concurrent_per_origin(1)
                .with_min_delay_ticks_per_origin(0),
        );
        scheduler.set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;
        scheduler.set_robots_for_origin("https://other.example", RobotsRules::allow_all())?;
        let first = crawl_request("r1", "https://example.com/a");
        let same_origin = crawl_request("r2", "https://example.com/b");
        let other_origin = crawl_request("r3", "https://other.example/a");

        assert_eq!(
            scheduler.begin(&first, 10)?,
            CrawlDecision::Allow {
                origin: "https://example.com".into()
            }
        );
        assert_eq!(
            scheduler.begin(&same_origin, 10)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 11,
                reason: "per-origin concurrency cap reached".into(),
            }
        );
        assert_eq!(
            scheduler.begin(&other_origin, 10)?,
            CrawlDecision::Allow {
                origin: "https://other.example".into()
            }
        );

        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/a", 200),
            11,
        ));
        assert_eq!(
            scheduler.begin(&same_origin, 11)?,
            CrawlDecision::Allow {
                origin: "https://example.com".into()
            }
        );
        Ok(())
    }

    #[test]
    fn crawl_scheduler_applies_policy_and_robots_delays() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .with_max_concurrent_per_origin(2)
                .with_min_delay_ticks_per_origin(2),
        );
        scheduler.set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;
        let first = crawl_request("r1", "https://example.com/a");
        let second = crawl_request("r2", "https://example.com/b");

        assert!(scheduler.begin(&first, 10)?.is_allowed());
        assert_eq!(
            scheduler.decide(&second, 11)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 12,
                reason: "per-origin crawl delay has not elapsed".into(),
            }
        );
        assert!(scheduler.begin(&second, 12)?.is_allowed());
        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/a", 200),
            13,
        ));
        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r2", "https://example.com/b", 200),
            13,
        ));

        scheduler.set_robots_for_origin(
            "https://example.com",
            RobotsRules::parse_for_agent(
                "tempo-agent",
                r#"
User-agent: tempo-agent
Crawl-delay: 5
"#,
            ),
        )?;
        let third = crawl_request("r3", "https://example.com/c");
        assert_eq!(
            scheduler.decide(&third, 13)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 17,
                reason: "per-origin crawl delay has not elapsed".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn crawl_scheduler_blocks_robots_disallow_paths() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::default();
        scheduler.set_robots_for_origin("https://example.com/app", RobotsRules::disallow_all())?;
        let blocked = crawl_request("r1", "https://example.com/admin");

        assert_eq!(
            scheduler.begin(&blocked, 1)?,
            CrawlDecision::Block {
                origin: "https://example.com".into(),
                reason: "blocked by robots.txt".into(),
            }
        );
        assert_eq!(scheduler.snapshots().len(), 1);
        assert_eq!(scheduler.snapshots()[0].inflight, 0);
        Ok(())
    }

    #[test]
    fn crawl_scheduler_waits_for_unknown_robots_but_allows_robots_txt() -> Result<(), CrawlError> {
        let scheduler = CrawlScheduler::default();
        let page = crawl_request("r1", "https://example.com/page");
        let robots = crawl_request("robots", "https://example.com/robots.txt");

        assert_eq!(
            scheduler.decide(&page, 1)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 2,
                reason: "robots.txt rules are unknown".into(),
            }
        );
        assert_eq!(
            scheduler.decide(&robots, 1)?,
            CrawlDecision::Allow {
                origin: "https://example.com".into()
            }
        );
        Ok(())
    }

    #[test]
    fn crawl_scheduler_applies_robots_to_query_and_percent_decoded_paths() -> Result<(), CrawlError>
    {
        let mut scheduler = CrawlScheduler::default();
        scheduler.set_robots_for_origin(
            "https://example.com",
            RobotsRules::parse_for_agent(
                "tempo-agent",
                r#"
User-agent: tempo-agent
Disallow: /search?
Disallow: /private
"#,
            ),
        )?;

        assert_eq!(
            scheduler.decide(&crawl_request("query", "https://example.com/search?q=x"), 1)?,
            CrawlDecision::Block {
                origin: "https://example.com".into(),
                reason: "blocked by robots.txt".into(),
            }
        );
        assert_eq!(
            scheduler.decide(
                &crawl_request("encoded", "https://example.com/%70rivate"),
                1
            )?,
            CrawlDecision::Block {
                origin: "https://example.com".into(),
                reason: "blocked by robots.txt".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn crawl_scheduler_applies_robots_to_normalized_dot_segments() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::default();
        scheduler.set_robots_for_origin(
            "https://example.com",
            RobotsRules::parse_for_agent(
                "tempo-agent",
                r#"
User-agent: tempo-agent
Disallow: /private
"#,
            ),
        )?;

        assert_eq!(
            scheduler.decide(
                &crawl_request("dot", "https://example.com/public/../private"),
                1,
            )?,
            CrawlDecision::Block {
                origin: "https://example.com".into(),
                reason: "blocked by robots.txt".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn crawl_frontier_dedupes_dot_segment_url_equivalents() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );

        assert!(frontier.enqueue(crawl_request("a", "https://example.com/a/../page"))?);
        assert!(!frontier.enqueue(crawl_request("b", "https://example.com/page"))?);
        assert_eq!(frontier.snapshot().pending, 1);
        Ok(())
    }

    #[test]
    fn crawl_frontier_caps_global_pending_without_counting_duplicates() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(CrawlPolicy::default().without_robots_txt())
            .with_max_global_pending(2)
            .with_max_pending_per_origin(8);

        assert!(frontier.enqueue(crawl_request("a", "https://a.example/one"))?);
        assert!(frontier.enqueue(crawl_request("b", "https://b.example/one"))?);
        assert!(!frontier.enqueue(crawl_request("a-dup", "https://a.example/one"))?);

        let Err(error) = frontier.enqueue(crawl_request("c", "https://c.example/one")) else {
            panic!("global pending cap should reject new identities");
        };
        assert_eq!(error.reason.code, BlockCode::CrawlLimit);
        assert!(error.reason.detail.contains("global pending crawl cap"));
        assert_eq!(frontier.snapshot().pending, 2);
        Ok(())
    }

    #[test]
    fn crawl_frontier_caps_pending_per_origin() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(CrawlPolicy::default().without_robots_txt())
            .with_max_global_pending(8)
            .with_max_pending_per_origin(2);

        assert!(frontier.enqueue(crawl_request("a1", "https://a.example/one"))?);
        assert!(frontier.enqueue(crawl_request("a2", "https://a.example/two"))?);
        let Err(error) = frontier.enqueue(crawl_request("a3", "https://a.example/three")) else {
            panic!("per-origin pending cap should reject new identities");
        };
        assert_eq!(error.reason.code, BlockCode::CrawlLimit);
        assert!(error.reason.detail.contains("per-origin pending crawl cap"));

        assert!(frontier.enqueue(crawl_request("b1", "https://b.example/one"))?);
        assert_eq!(frontier.snapshot().pending, 3);
        Ok(())
    }

    #[test]
    fn crawl_frontier_caps_global_pending_bytes_without_counting_duplicates(
    ) -> Result<(), CrawlError> {
        let request = crawl_request("a", "https://a.example/one")
            .with_header("x-large-frontier-header", "x".repeat(512));
        let duplicate = crawl_request("a-dup", "https://a.example/one")
            .with_header("x-large-frontier-header", "x".repeat(512));
        let second = crawl_request("b", "https://b.example/one")
            .with_header("x-large-frontier-header", "y".repeat(512));
        let first_bytes = estimated_pending_request_bytes(&request);

        let mut frontier = CrawlFrontier::new(CrawlPolicy::default().without_robots_txt())
            .with_max_global_pending(8)
            .with_max_pending_per_origin(8)
            .with_max_global_pending_bytes(first_bytes)
            .with_max_pending_bytes_per_origin(first_bytes.saturating_mul(2));

        assert!(frontier.enqueue(request)?);
        assert!(!frontier.enqueue(duplicate)?);
        let Err(error) = frontier.enqueue(second) else {
            panic!("global pending byte cap should reject new identities");
        };
        assert_eq!(error.reason.code, BlockCode::CrawlLimit);
        assert!(error
            .reason
            .detail
            .contains("global pending crawl byte cap"));
        assert_eq!(frontier.snapshot().pending, 1);
        Ok(())
    }

    #[test]
    fn crawl_frontier_caps_pending_bytes_per_origin() -> Result<(), CrawlError> {
        let first = crawl_request("a1", "https://a.example/one")
            .with_header("x-large-frontier-header", "x".repeat(512));
        let second = crawl_request("a2", "https://a.example/two")
            .with_header("x-large-frontier-header", "y".repeat(512));
        let other_origin = crawl_request("b1", "https://b.example/one")
            .with_header("x-large-frontier-header", "z".repeat(512));
        let first_bytes = estimated_pending_request_bytes(&first);

        let mut frontier = CrawlFrontier::new(CrawlPolicy::default().without_robots_txt())
            .with_max_global_pending(8)
            .with_max_pending_per_origin(8)
            .with_max_global_pending_bytes(first_bytes.saturating_mul(3))
            .with_max_pending_bytes_per_origin(first_bytes);

        assert!(frontier.enqueue(first)?);
        let Err(error) = frontier.enqueue(second) else {
            panic!("per-origin pending byte cap should reject new identities");
        };
        assert_eq!(error.reason.code, BlockCode::CrawlLimit);
        assert!(error
            .reason
            .detail
            .contains("per-origin pending crawl byte cap"));
        assert!(frontier.enqueue(other_origin)?);
        assert_eq!(frontier.snapshot().pending, 2);
        Ok(())
    }

    #[test]
    fn crawl_scheduler_honors_retry_after_backoff() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        scheduler.set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;
        let first = crawl_request("r1", "https://example.com/a");
        let second = crawl_request("r2", "https://example.com/b");

        assert!(scheduler.begin(&first, 1)?.is_allowed());
        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/a", 429)
                .with_header("Retry-After", "5"),
            2,
        ));
        assert_eq!(
            scheduler.decide(&second, 6)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 7,
                reason: "origin is in Retry-After backoff".into(),
            }
        );
        assert!(scheduler.begin(&second, 7)?.is_allowed());

        let snapshot = scheduler
            .snapshot_for_origin("https://example.com/path")?
            .ok_or_else(|| CrawlError {
                reason: BlockReason::new(BlockCode::EmptyHost, "missing crawl snapshot"),
            })?;
        assert_eq!(snapshot.backoff_until_tick, Some(7));
        assert_eq!(snapshot.inflight, 1);
        Ok(())
    }

    #[test]
    fn crawl_scheduler_honors_retry_after_http_date_against_response_date() -> Result<(), CrawlError>
    {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        scheduler.set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;
        let first = crawl_request("r1", "https://example.com/a");
        let second = crawl_request("r2", "https://example.com/b");

        assert!(scheduler.begin(&first, 10)?.is_allowed());
        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/a", 503)
                .with_header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
                .with_header("Retry-After", "Tue, 20 Apr 2021 02:08:05 GMT"),
            11,
        ));
        assert_eq!(
            scheduler.decide(&second, 20)?,
            CrawlDecision::Wait {
                origin: "https://example.com".into(),
                until_tick: 21,
                reason: "origin is in Retry-After backoff".into(),
            }
        );
        assert!(scheduler.begin(&second, 21)?.is_allowed());
        Ok(())
    }

    #[test]
    fn retry_after_http_date_requires_response_date_and_clamps_past_dates() {
        let no_date = NetworkResponseRecord::new("r1", "https://example.com/a", 429)
            .with_header("Retry-After", "Tue, 20 Apr 2021 02:08:05 GMT");
        assert_eq!(retry_after_until_tick(&no_date, 10), Some(11));

        let past = NetworkResponseRecord::new("r1", "https://example.com/a", 429)
            .with_header("Date", "Tue, 20 Apr 2021 02:08:05 GMT")
            .with_header("Retry-After", "Tue, 20 Apr 2021 02:07:55 GMT");
        assert_eq!(retry_after_until_tick(&past, 10), Some(11));
    }

    #[test]
    fn crawl_scheduler_caps_global_inflight_across_origins() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_global_inflight(1)
                .with_max_concurrent_per_origin(8)
                .with_min_delay_ticks_per_origin(0),
        );
        scheduler.set_robots_for_origin("https://a.example", RobotsRules::allow_all())?;
        scheduler.set_robots_for_origin("https://b.example", RobotsRules::allow_all())?;
        let first = crawl_request("r1", "https://a.example/one");
        let second = crawl_request("r2", "https://b.example/two");

        assert!(scheduler.begin(&first, 1)?.is_allowed());
        assert_eq!(scheduler.global_inflight(), 1);
        assert_eq!(
            scheduler.decide(&second, 1)?,
            CrawlDecision::Wait {
                origin: "https://b.example".into(),
                until_tick: 2,
                reason: "global crawl concurrency cap reached".into(),
            }
        );

        assert!(scheduler.finish(
            &NetworkResponseRecord::new("r1", "https://a.example/one", 200),
            2,
        ));
        assert!(scheduler.begin(&second, 2)?.is_allowed());
        Ok(())
    }

    #[test]
    fn crawl_frontier_dedupes_and_dispatches_deterministic_batches() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .with_max_global_inflight(2)
                .with_max_concurrent_per_origin(1)
                .with_min_delay_ticks_per_origin(0),
        );
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://blocked.example", RobotsRules::disallow_all())?;
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://a.example", RobotsRules::allow_all())?;
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://b.example", RobotsRules::allow_all())?;

        assert!(frontier.enqueue(crawl_request("b", "https://b.example/b"))?);
        assert!(frontier.enqueue(crawl_request("a1", "https://a.example/a#ignored"))?);
        assert!(!frontier.enqueue(crawl_request("a1-dup", "https://a.example/a"))?);
        assert!(frontier.enqueue(crawl_request("a2", "https://a.example/c"))?);
        assert!(frontier.enqueue(crawl_request("blocked", "https://blocked.example/private",))?);

        let batch = frontier.dispatch_ready(1, 8)?;
        assert_eq!(
            batch
                .dispatches
                .iter()
                .map(|dispatch| dispatch.request.id.0.as_str())
                .collect::<Vec<_>>(),
            vec!["a1", "b"]
        );
        assert_eq!(
            batch.waiting,
            vec![CrawlDecision::Wait {
                origin: "https://a.example".into(),
                until_tick: 2,
                reason: "per-origin concurrency cap reached".into(),
            }]
        );
        assert_eq!(
            batch.blocked,
            vec![CrawlDecision::Block {
                origin: "https://blocked.example".into(),
                reason: "blocked by robots.txt".into(),
            }]
        );
        assert_eq!(frontier.snapshot().pending, 1);
        assert_eq!(frontier.snapshot().inflight, 2);

        assert!(frontier.finish(
            &NetworkResponseRecord::new("a1", "https://a.example/a", 200),
            2,
        ));
        let second = frontier.dispatch_ready(2, 8)?;
        assert_eq!(second.dispatches.len(), 1);
        assert_eq!(second.dispatches[0].request.id.0, "a2");
        assert_eq!(frontier.snapshot().pending, 0);
        Ok(())
    }

    #[test]
    fn crawl_frontier_dedupes_urls_that_are_already_active() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );

        assert!(frontier.enqueue(crawl_request("r1", "https://example.com/page#one"))?);
        let batch = frontier.dispatch_ready(1, 1)?;
        assert_eq!(batch.dispatches.len(), 1);
        assert!(frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);
        assert!(!frontier.enqueue(crawl_request("r2", "https://example.com/page#two"))?);

        assert!(frontier.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/page", 200),
            2,
        ));
        assert!(frontier.enqueue(crawl_request("r3", "https://example.com/page"))?);
        Ok(())
    }

    #[test]
    fn crawl_frontier_dedupes_by_request_identity_not_url_only() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_concurrent_per_origin(16)
                .with_min_delay_ticks_per_origin(0),
        );
        let url = "https://example.com/page#fragment";

        assert!(frontier.enqueue(crawl_request("get-a", url))?);
        assert!(!frontier.enqueue(crawl_request(
            "get-a-dup",
            "HTTPS://EXAMPLE.COM:443/page#other",
        ))?);
        assert!(!frontier.enqueue(
            crawl_request("get-empty-bytes", "https://example.com/page").with_body_bytes([])
        )?);
        assert!(frontier
            .enqueue(crawl_request("get-json", url).with_header("Accept", "application/json"))?);
        assert!(!frontier.enqueue(
            crawl_request("get-json-dup", "https://example.com/page")
                .with_header("accept", "application/json")
        )?);
        assert!(
            frontier.enqueue(crawl_request("get-html", url).with_header("Accept", "text/html"))?
        );
        assert!(frontier.enqueue(NetworkRequest::new(
            "head-a",
            "HEAD",
            url,
            "profile-a",
            IdentityMode::AgentDeclared,
        ))?);
        assert!(!frontier.enqueue(
            NetworkRequest::new(
                "head-empty-bytes",
                "HEAD",
                "https://example.com:443/page",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_bytes([])
        )?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "get-b-profile",
            "GET",
            url,
            "profile-b",
            IdentityMode::AgentDeclared,
        ))?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "get-user-driven",
            "GET",
            url,
            "profile-a",
            IdentityMode::UserDriven,
        ))?);
        // No digest means the body is opaque to the frontier. Even a zero-size
        // POST is request-id scoped so two distinct submissions are not collapsed.
        assert!(frontier.enqueue(NetworkRequest::new(
            "post-opaque-a",
            "POST",
            url,
            "profile-a",
            IdentityMode::AgentDeclared,
        ))?);
        assert!(!frontier.enqueue(
            NetworkRequest::new(
                "post-opaque-a",
                "POST",
                "https://example.com:443/page",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_size(64)
        )?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "post-opaque-b",
            "POST",
            "https://example.com/page",
            "profile-a",
            IdentityMode::AgentDeclared,
        ))?);

        let digest_a = Sha256::digest(b"alpha").into();
        let digest_b = Sha256::digest(b"beta").into();
        assert!(frontier.enqueue(
            NetworkRequest::new(
                "post-digest-a",
                "POST",
                url,
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_sha256(5, digest_a),
        )?);
        assert!(!frontier.enqueue(
            NetworkRequest::new(
                "post-digest-a-dup",
                "POST",
                "https://example.com/page",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_sha256(5, digest_a),
        )?);
        assert!(frontier.enqueue(
            NetworkRequest::new(
                "post-digest-a-different-size",
                "POST",
                "https://example.com/page",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_sha256(6, digest_a),
        )?);
        assert!(frontier.enqueue(
            NetworkRequest::new(
                "post-digest-b",
                "POST",
                "https://example.com/page",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_body_sha256(4, digest_b),
        )?);

        assert_eq!(frontier.snapshot().pending, 11);
        let batch = frontier.dispatch_ready(1, 16)?;
        assert_eq!(batch.dispatches.len(), 11);
        assert!(frontier
            .scheduler()
            .is_request_active(&crawl_request("get-a-check", "https://example.com/page"))?);
        assert!(frontier.scheduler().is_request_active(
            &crawl_request("get-json-check", "https://example.com/page")
                .with_header("accept", "application/json")
        )?);
        assert!(frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);
        assert_eq!(frontier.snapshot().inflight, 11);
        Ok(())
    }

    #[test]
    fn crawl_frontier_url_active_tracks_until_last_identity_finishes() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_concurrent_per_origin(8)
                .with_min_delay_ticks_per_origin(0),
        );
        let profile_a = crawl_request("profile-a", "https://example.com/page");
        let profile_b = NetworkRequest::new(
            "profile-b",
            "GET",
            "https://example.com/page#fragment",
            "profile-b",
            IdentityMode::AgentDeclared,
        );
        assert!(frontier.enqueue(profile_a.clone())?);
        assert!(frontier.enqueue(profile_b.clone())?);
        let batch = frontier.dispatch_ready(1, 8)?;
        assert_eq!(batch.dispatches.len(), 2);
        assert!(frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);
        assert!(frontier.scheduler().is_request_active(&profile_a)?);
        assert!(frontier.scheduler().is_request_active(&profile_b)?);

        assert!(frontier.finish(
            &NetworkResponseRecord::new("profile-a", "https://example.com/page", 200),
            2,
        ));
        assert!(!frontier.scheduler().is_request_active(&profile_a)?);
        assert!(frontier.scheduler().is_request_active(&profile_b)?);
        assert!(frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);

        assert!(frontier.finish(
            &NetworkResponseRecord::new("profile-b", "https://example.com/page", 200),
            3,
        ));
        assert!(!frontier.scheduler().is_request_active(&profile_b)?);
        assert!(!frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_crawl_dispatch_blocks_private_resolved_socket() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://public.example", RobotsRules::allow_all())?;
        frontier.enqueue(crawl_request("r1", "https://public.example/page"))?;
        let mut batch = frontier.dispatch_ready(1, 1)?;
        let Some(dispatch) = batch.dispatches.pop() else {
            return Err(CrawlError {
                reason: BlockReason::new(BlockCode::InvalidUrl, "expected crawl dispatch"),
            });
        };

        let result = dispatch.check(
            &UrlPolicy::block_private(),
            &EgressPolicy::allow_all(),
            SocketAddr::from(([10, 0, 0, 5], 443)),
        );

        assert!(matches!(
            result,
            Err(CrawlDispatchError::Url(UrlBlocked { reason }))
                if reason.code == BlockCode::BlockedIp
                    && reason.detail.contains("resolved IP")
        ));
        Ok(())
    }

    #[test]
    fn checked_crawl_dispatch_emits_audit_egress_and_signature() -> Result<(), Box<dyn Error>> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;
        frontier.enqueue(
            crawl_request("r1", "https://example.com/page?query=signed").with_body_size(42),
        )?;
        let mut batch = frontier.dispatch_ready(1, 1)?;
        let dispatch = batch.dispatches.pop().ok_or("expected crawl dispatch")?;

        let checked = dispatch.check_signed(
            &UrlPolicy::block_private(),
            &EgressPolicy::block_by_default().allow_domain(DomainRule::exact("example.com")),
            SocketAddr::from(([93, 184, 216, 34], 443)),
            &key,
            1_800_000_000,
        )?;

        assert_eq!(checked.audit.origin, "https://example.com");
        assert!(checked.audit.taint_free);
        assert_eq!(checked.egress.domain, "example.com");
        assert_eq!(checked.egress.port, 443);
        assert_eq!(checked.egress.bytes_sent, 42);

        let headers = checked
            .web_bot_auth_headers
            .as_ref()
            .ok_or("expected Web Bot Auth headers")?;
        verify_web_bot_auth_signature_at(
            &checked.dispatch.request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn checked_crawl_dispatch_does_not_sign_user_driven_requests() -> Result<(), Box<dyn Error>> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[7u8; 32])?;
        let dispatch = CrawlDispatch {
            request: NetworkRequest::new(
                "r1",
                "GET",
                "https://example.com/page?private=1",
                "profile-a",
                IdentityMode::UserDriven,
            ),
            origin: "https://example.com".into(),
        };

        let checked = dispatch.check_signed(
            &UrlPolicy::block_private(),
            &EgressPolicy::block_by_default().allow_domain(DomainRule::exact("example.com")),
            SocketAddr::from(([93, 184, 216, 34], 443)),
            &key,
            1_800_000_000,
        )?;

        assert_eq!(checked.audit.identity_mode, IdentityMode::UserDriven);
        assert_eq!(checked.web_bot_auth_headers, None);
        Ok(())
    }

    #[test]
    fn connection_pinned_dispatch_exposes_only_socket_safe_request_parts(
    ) -> Result<(), Box<dyn Error>> {
        let dispatch = CrawlDispatch {
            request: NetworkRequest::new(
                "r1",
                "POST",
                "https://example.com:8443/a/../page?query=1#fragment",
                "profile-a",
                IdentityMode::AgentDeclared,
            )
            .with_header("x-tempo", "yes")
            .with_body_bytes(b"body"),
            origin: "https://example.com:8443".into(),
        };
        let checked = dispatch.check(
            &UrlPolicy::block_private(),
            &EgressPolicy::allow_all(),
            SocketAddr::from(([93, 184, 216, 34], 8443)),
        )?;
        let pinned = checked.into_connection_pinned()?;
        let connected = pinned.connect_with(|socket| Ok(format!("connected to {socket}")))?;

        assert_eq!(connected, "connected to 93.184.216.34:8443");
        assert_eq!(pinned.request_id().0.as_str(), "r1");
        assert_eq!(pinned.method(), "POST");
        assert_eq!(pinned.scheme(), "https");
        assert_eq!(pinned.authority(), "example.com:8443");
        assert_eq!(pinned.host(), "example.com");
        assert_eq!(pinned.path_and_query(), "/page?query=1");
        assert_eq!(pinned.origin(), "https://example.com:8443");
        assert_eq!(
            pinned.resolved_socket(),
            SocketAddr::from(([93, 184, 216, 34], 8443))
        );
        assert_eq!(
            pinned
                .header_values("x-tempo")
                .map(|values| values[0].as_str()),
            Some("yes")
        );
        assert_eq!(pinned.body_size(), 4);
        assert!(pinned.body_sha256().is_some());
        assert_eq!(pinned.audit().origin, "https://example.com:8443");
        assert_eq!(pinned.egress().domain, "example.com");
        Ok(())
    }

    #[test]
    fn checked_frontier_rejection_does_not_activate_request() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://public.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier
            .dispatch_checked_ready(1, 1, guard, |_| Ok(SocketAddr::from(([10, 0, 0, 5], 443))))?;

        assert!(batch.dispatches.is_empty());
        assert!(batch.waiting.is_empty());
        assert!(batch.blocked.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Url(UrlBlocked { reason })
                if reason.code == BlockCode::BlockedIp
                    && reason.detail.contains("resolved IP")
        ));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        assert!(!frontier
            .scheduler()
            .is_url_active("https://public.example/page")?);
        assert!(frontier.enqueue(crawl_request("r2", "https://public.example/page"))?);
        Ok(())
    }

    #[test]
    fn pinned_frontier_activates_only_after_connecting_checked_socket() -> Result<(), Box<dyn Error>>
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let accepted = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));

        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request(
            "r1",
            &format!("http://127.0.0.1:{}/page", addr.port()),
        ))?;

        let url_policy = UrlPolicy::allow_all();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier.dispatch_pinned_tcp_ready(1, 1, guard, Duration::from_secs(1))?;

        assert!(batch.rejected.is_empty());
        assert_eq!(batch.connections.len(), 1);
        assert_eq!(batch.connections[0].pinned().resolved_socket(), addr);
        assert_eq!(batch.connections[0].pinned().scheme(), "http");
        assert_eq!(batch.connections[0].pinned().authority(), &addr.to_string());
        assert_eq!(batch.connections[0].pinned().path_and_query(), "/page");
        assert_eq!(batch.connections[0].stream().peer_addr()?, addr);
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 1);

        drop(batch);
        let accepted_stream = accepted.join().map_err(|_| "accept thread panicked")??;
        assert_eq!(
            accepted_stream.peer_addr()?.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        Ok(())
    }

    #[test]
    fn pinned_frontier_rejects_private_url_before_connection_or_activation(
    ) -> Result<(), Box<dyn Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;

        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request(
            "r1",
            &format!("http://127.0.0.1:{}/private", addr.port()),
        ))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier.dispatch_pinned_tcp_ready(1, 1, guard, Duration::from_millis(50))?;

        assert!(batch.connections.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlConnectError::Dispatch(CrawlDispatchError::Url(UrlBlocked { reason }))
                if reason.code == BlockCode::BlockedIp
        ));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        Ok(())
    }

    #[test]
    fn pinned_frontier_proxied_dispatch_connects_proxy_socket() -> Result<(), Box<dyn Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let proxy_addr = listener.local_addr()?;
        let accepted = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));

        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::block_by_default()
            .allow_insecure_local_proxy_endpoints()
            .proxy_domain(
                DomainRule::exact("proxied.example"),
                ProxyRoute::new("local-proxy", format!("http://{proxy_addr}")),
            );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier.dispatch_pinned_tcp_ready(1, 1, guard, Duration::from_secs(1))?;

        assert!(batch.rejected.is_empty());
        assert_eq!(batch.connections.len(), 1);
        let pinned = batch.connections[0].pinned();
        assert_eq!(pinned.resolved_socket(), proxy_addr);
        assert_eq!(pinned.host(), "proxied.example");
        assert_eq!(pinned.path_and_query(), "/page");
        assert_eq!(pinned.egress().proxy_id.as_deref(), Some("local-proxy"));
        assert_eq!(batch.connections[0].stream().peer_addr()?, proxy_addr);
        assert_eq!(frontier.snapshot().inflight, 1);

        drop(batch);
        let _accepted_stream = accepted.join().map_err(|_| "accept thread panicked")??;
        Ok(())
    }

    #[test]
    fn checked_frontier_max_requests_bounds_rejected_attempts() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("a", "https://a.example/page"))?;
        frontier.enqueue(crawl_request("b", "https://b.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([10, 0, 0, 5], 443)))
        })?;

        assert_eq!(resolve_calls, 1);
        assert_eq!(batch.rejected.len(), 1);
        assert_eq!(frontier.snapshot().pending, 1);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_url_policy_denial_does_not_resolve() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "http://127.0.0.1/private"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([127, 0, 0, 1], 80)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert!(batch.dispatches.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Url(UrlBlocked { reason })
                if reason.code == BlockCode::BlockedIp
        ));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_proxied_dispatch_validates_proxy_socket() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::block_by_default().proxy_domain(
            DomainRule::exact("proxied.example"),
            ProxyRoute::new("proxy-a", "https://proxy.example:8443"),
        );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |dispatch| {
            resolve_calls += 1;
            assert_eq!(dispatch.request.url, "https://proxied.example/page");
            Ok(SocketAddr::from(([93, 184, 216, 34], 8443)))
        })?;

        assert_eq!(resolve_calls, 1);
        assert!(batch.rejected.is_empty());
        assert_eq!(batch.dispatches.len(), 1);
        let checked = &batch.dispatches[0];
        assert_eq!(checked.resolved_socket.port(), 8443);
        assert_eq!(checked.egress.domain, "proxied.example");
        assert_eq!(checked.egress.port, 443);
        assert_eq!(checked.egress.proxy_id.as_deref(), Some("proxy-a"));
        assert_eq!(checked.audit.origin, "https://proxied.example");
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 1);
        Ok(())
    }

    #[test]
    fn checked_frontier_proxied_dispatch_rejects_private_proxy_socket() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::block_by_default().proxy_domain(
            DomainRule::exact("proxied.example"),
            ProxyRoute::new("proxy-a", "https://proxy.example:8443"),
        );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier
            .dispatch_checked_ready(1, 1, guard, |_| Ok(SocketAddr::from(([10, 0, 0, 5], 8443))))?;

        assert!(batch.dispatches.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Url(UrlBlocked { reason })
                if reason.code == BlockCode::BlockedIp
                    && reason.detail.contains("resolved proxy IP")
        ));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_rejects_cleartext_proxy_before_resolve() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let proxy_user = "proxy-user";
        let proxy_pass = "proxy-pass";
        let endpoint =
            proxy_endpoint_with_credentials("http", proxy_user, proxy_pass, "proxy.example", 8080);
        let egress_policy = EgressPolicy::block_by_default().proxy_domain(
            DomainRule::exact("proxied.example"),
            ProxyRoute::new("proxy-a", endpoint),
        );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([93, 184, 216, 34], 8080)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert!(batch.dispatches.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Egress(EgressDenied { reason, .. })
                if reason.contains("cleartext proxy endpoint scheme 'http'")
                    && !reason.contains(proxy_user)
                    && !reason.contains(proxy_pass)
        ));
        let display = batch.rejected[0].error.to_string();
        assert!(!display.contains(proxy_user), "{display}");
        assert!(!display.contains(proxy_pass), "{display}");
        assert!(!display.contains("proxy.example:8080"), "{display}");
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_allows_explicit_insecure_loopback_proxy() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let proxy_user = "proxy-user";
        let proxy_pass = "proxy-pass";
        let endpoint =
            proxy_endpoint_with_credentials("http", proxy_user, proxy_pass, "localhost", 8080);
        let egress_policy = EgressPolicy::block_by_default()
            .allow_insecure_local_proxy_endpoints()
            .proxy_domain(
                DomainRule::exact("proxied.example"),
                ProxyRoute::new("local-proxy", endpoint),
            );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            Ok(SocketAddr::from(([127, 0, 0, 1], 8080)))
        })?;

        assert!(batch.rejected.is_empty());
        assert_eq!(batch.dispatches.len(), 1);
        let checked = &batch.dispatches[0];
        assert_eq!(
            checked.resolved_socket,
            SocketAddr::from(([127, 0, 0, 1], 8080))
        );
        assert_eq!(checked.egress.proxy_id.as_deref(), Some("local-proxy"));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 1);
        Ok(())
    }

    #[test]
    fn checked_frontier_allows_explicit_insecure_ipv6_loopback_proxy() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://proxied.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::block_by_default()
            .allow_insecure_local_proxy_endpoints()
            .proxy_domain(
                DomainRule::exact("proxied.example"),
                ProxyRoute::new("local-proxy", "http://[::1]:8080"),
            );
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            Ok(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080)))
        })?;

        assert!(batch.rejected.is_empty());
        assert_eq!(batch.dispatches.len(), 1);
        assert_eq!(
            batch.dispatches[0].egress.proxy_id.as_deref(),
            Some("local-proxy")
        );
        Ok(())
    }

    #[test]
    fn checked_frontier_max_requests_bounds_url_policy_rejections() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("a", "http://127.0.0.1/a"))?;
        frontier.enqueue(crawl_request("b", "http://127.0.0.2/b"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([127, 0, 0, 1], 80)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert_eq!(batch.rejected.len(), 1);
        assert_eq!(frontier.snapshot().pending, 1);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_duplicate_active_request_id_does_not_resolve() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://example.com/first"))?;
        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let first = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            Ok(SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;
        assert_eq!(first.dispatches.len(), 1);
        assert_eq!(frontier.snapshot().inflight, 1);

        assert!(frontier.enqueue(crawl_request("r1", "https://example.com/second"))?);
        let mut resolve_calls = 0usize;
        let second = frontier.dispatch_checked_ready(2, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert!(second.dispatches.is_empty());
        assert_eq!(
            second.blocked,
            vec![CrawlDecision::Block {
                origin: "https://example.com".into(),
                reason: "request id is already active".into(),
            }]
        );
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 1);
        assert!(frontier.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/first", 200),
            3,
        ));
        Ok(())
    }

    #[test]
    fn checked_frontier_egress_denial_does_not_resolve() -> Result<(), CrawlError> {
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://blocked.example/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::block_by_default();
        let guard = CrawlDispatchGuard::new(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert!(batch.dispatches.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Egress(EgressDenied { domain, .. })
                if domain == "blocked.example"
        ));
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    #[test]
    fn checked_frontier_activates_only_after_signed_policy_passes() -> Result<(), Box<dyn Error>> {
        let key = WebBotAuthSigningKey::from_seed("tempo-agent", &[9u8; 32])?;
        let mut frontier = CrawlFrontier::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(
            crawl_request("r1", "https://example.com/page?query=signed").with_body_size(7),
        )?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy =
            EgressPolicy::block_by_default().allow_domain(DomainRule::exact("example.com"));
        let guard =
            CrawlDispatchGuard::new(&url_policy, &egress_policy).with_signer(&key, 1_800_000_000);
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            Ok(SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;

        assert_eq!(batch.dispatches.len(), 1);
        assert!(batch.rejected.is_empty());
        assert_eq!(frontier.snapshot().pending, 0);
        assert_eq!(frontier.snapshot().inflight, 1);
        let checked = &batch.dispatches[0];
        assert_eq!(checked.audit.origin, "https://example.com");
        assert_eq!(checked.egress.bytes_sent, 7);
        let headers = checked
            .web_bot_auth_headers
            .as_ref()
            .ok_or("expected Web Bot Auth headers")?;
        verify_web_bot_auth_signature_at(
            &checked.dispatch.request,
            &headers.signature_input,
            &headers.signature,
            &key.verifier(),
            1_800_000_000,
        )?;

        assert!(frontier.finish(
            &NetworkResponseRecord::new("r1", "https://example.com/page?query=signed", 200),
            2,
        ));
        assert_eq!(frontier.snapshot().inflight, 0);
        Ok(())
    }

    fn crawl_request(id: &str, url: &str) -> NetworkRequest {
        NetworkRequest::new(id, "GET", url, "profile-a", IdentityMode::AgentDeclared)
    }
}
