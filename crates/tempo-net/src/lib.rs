//! tempo-net - network policy, profile isolation, audit records, and quiescence.
//!
//! This crate is the standalone WS6 foundation from `final.md`: the browser
//! network layer must reject SSRF targets before engine navigation, keep each
//! session in an isolated profile, emit audit records that do not carry page
//! payloads, and expose network-idle counters for the action quiescence gate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
            max_signature_age: DEFAULT_WEB_BOT_AUTH_MAX_SIGNATURE_AGE,
            allowed_clock_skew: DEFAULT_WEB_BOT_AUTH_CLOCK_SKEW,
        }
    }
}

/// Ed25519 verification key for incoming or replayed Web Bot Auth signatures.
#[derive(Clone, Debug)]
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

/// RFC 9421 signature parameters for one signature label.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Default Web Bot Auth coverage: method, authority, scheme, and path.
    pub fn web_bot_auth(key_id: impl Into<String>, created: u64) -> Self {
        Self {
            label: "sig1".into(),
            key_id: key_id.into(),
            created,
            expires: None,
            nonce: None,
            tag: None,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSignatureInput {
    params: SignatureParameters,
    signature_params_value: String,
}

/// Headers produced by signing an HTTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRequest {
    pub id: RequestId,
    pub method: String,
    pub url: String,
    pub profile_id: ProfileId,
    pub identity_mode: IdentityMode,
    headers: BTreeMap<String, Vec<String>>,
    body_size: u64,
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
    let base = signature_base(request, params)?;
    let signature = key.signing_key.sign(base.as_bytes());
    Ok(SignatureHeaders {
        signature_agent: None,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkResponseRecord {
    pub request_id: RequestId,
    pub url: String,
    pub status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body_size: u64,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRoute {
    pub id: String,
    pub endpoint: String,
}

impl ProxyRoute {
    pub fn new(id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            endpoint: endpoint.into(),
        }
    }
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
}

impl EgressPolicy {
    pub fn allow_all() -> Self {
        Self {
            default: EgressDefault::AllowDirect,
            allowed: BTreeSet::new(),
            blocked: BTreeSet::new(),
            proxies: BTreeMap::new(),
        }
    }

    pub fn block_by_default() -> Self {
        Self {
            default: EgressDefault::Block,
            allowed: BTreeSet::new(),
            blocked: BTreeSet::new(),
            proxies: BTreeMap::new(),
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

/// Default maximum number of crawl requests admitted across the whole process.
pub const DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT: usize = 256;
/// Default maximum number of crawl requests admitted for one origin at a time.
pub const DEFAULT_CRAWL_MAX_PER_ORIGIN_INFLIGHT: usize = 8;
/// Default post-request per-origin quiet period. `0` means no extra delay.
pub const DEFAULT_CRAWL_DELAY_TICKS: u64 = 0;
/// Default retained canonical URL dedupe window.
pub const DEFAULT_CRAWL_MAX_SEEN_URLS: usize = 65_536;
/// Default retained request-id dedupe window.
pub const DEFAULT_CRAWL_MAX_SEEN_REQUEST_IDS: usize = 65_536;
/// Default retained origin state window for idle politeness metadata.
pub const DEFAULT_CRAWL_MAX_TRACKED_ORIGINS: usize = 4_096;

/// Pure admission policy for fast, bounded, polite crawler scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrawlAdmissionConfig {
    pub max_global_inflight: usize,
    pub max_per_origin_inflight: usize,
    pub max_seen_urls: usize,
    pub max_seen_request_ids: usize,
    pub max_tracked_origins: usize,
    /// Caller-supplied logical ticks to wait after an origin completes a request.
    ///
    /// The unit is intentionally abstract: production can use milliseconds, while
    /// replay/tests can use deterministic ticks.
    pub crawl_delay_ticks: u64,
}

impl CrawlAdmissionConfig {
    fn normalized(self) -> Self {
        let max_global_inflight = self.max_global_inflight.max(1);
        Self {
            max_global_inflight,
            max_per_origin_inflight: self.max_per_origin_inflight.max(1),
            max_seen_urls: self.max_seen_urls.max(max_global_inflight),
            max_seen_request_ids: self.max_seen_request_ids.max(max_global_inflight),
            max_tracked_origins: self.max_tracked_origins.max(max_global_inflight),
            crawl_delay_ticks: self.crawl_delay_ticks,
        }
    }
}

impl Default for CrawlAdmissionConfig {
    fn default() -> Self {
        Self {
            max_global_inflight: DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT,
            max_per_origin_inflight: DEFAULT_CRAWL_MAX_PER_ORIGIN_INFLIGHT,
            max_seen_urls: DEFAULT_CRAWL_MAX_SEEN_URLS,
            max_seen_request_ids: DEFAULT_CRAWL_MAX_SEEN_REQUEST_IDS,
            max_tracked_origins: DEFAULT_CRAWL_MAX_TRACKED_ORIGINS,
            crawl_delay_ticks: DEFAULT_CRAWL_DELAY_TICKS,
        }
    }
}

/// One URL the crawler wants to schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlCandidate {
    pub request_id: RequestId,
    pub url: String,
    pub depth: u32,
}

impl CrawlCandidate {
    pub fn new(id: impl Into<RequestId>, url: impl Into<String>, depth: u32) -> Self {
        Self {
            request_id: id.into(),
            url: url.into(),
            depth,
        }
    }
}

/// Lease returned for an admitted crawl request.
///
/// The caller must pass the lease back to [`CrawlAdmission::finish`] when the
/// request completes so per-origin and global capacity are released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlLease {
    pub request_id: RequestId,
    pub url: String,
    pub origin: String,
    pub admitted_at_tick: u64,
}

/// Why a crawl candidate cannot run yet but may be retried later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlDelayReason {
    GlobalConcurrencyLimit { max: usize },
    PerOriginConcurrencyLimit { origin: String, max: usize },
    PolitenessWindow { origin: String },
}

/// Why a crawl candidate was rejected and should not be retried as-is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlRejectReason {
    UrlPolicy(BlockReason),
    DuplicateUrl { origin: String },
    DuplicateRequestId { request_id: RequestId },
}

/// Why a resolved crawl target is not allowed to connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlResolvedTargetError {
    StaleLease { request_id: RequestId },
    UrlPolicy(BlockReason),
}

/// Scheduling decision for one crawl candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlAdmissionDecision {
    Admit(CrawlLease),
    Delay {
        retry_after_tick: u64,
        reason: CrawlDelayReason,
    },
    Drop {
        reason: CrawlRejectReason,
    },
}

impl CrawlAdmissionDecision {
    pub fn admitted(&self) -> bool {
        matches!(self, Self::Admit(_))
    }
}

/// Bounded crawler admission table.
///
/// This is intentionally an admission primitive, not a downloader. It enforces
/// the security and systems invariants tempo needs before a crawler worker ever
/// receives work: URL policy, canonical dedupe, global parallelism, per-origin
/// parallelism, and per-origin quiet windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlAdmission {
    config: CrawlAdmissionConfig,
    url_policy: UrlPolicy,
    global_inflight: BTreeSet<RequestId>,
    live_leases: BTreeMap<RequestId, CrawlLease>,
    live_urls: BTreeSet<String>,
    origins: BTreeMap<String, OriginCrawlState>,
    seen_request_ids: BTreeSet<RequestId>,
    seen_request_id_order: VecDeque<RequestId>,
    seen_urls: BTreeSet<String>,
    seen_url_order: VecDeque<String>,
    origin_order: VecDeque<String>,
}

impl CrawlAdmission {
    pub fn new(config: CrawlAdmissionConfig, url_policy: UrlPolicy) -> Self {
        Self {
            config: config.normalized(),
            url_policy,
            global_inflight: BTreeSet::new(),
            live_leases: BTreeMap::new(),
            live_urls: BTreeSet::new(),
            origins: BTreeMap::new(),
            seen_request_ids: BTreeSet::new(),
            seen_request_id_order: VecDeque::new(),
            seen_urls: BTreeSet::new(),
            seen_url_order: VecDeque::new(),
            origin_order: VecDeque::new(),
        }
    }

    /// Secure default: block private/local targets while permitting high
    /// parallelism on public origins.
    pub fn secure_default() -> Self {
        Self::new(CrawlAdmissionConfig::default(), UrlPolicy::block_private())
    }

    pub fn config(&self) -> CrawlAdmissionConfig {
        self.config
    }

    pub fn inflight(&self) -> usize {
        self.global_inflight.len()
    }

    pub fn inflight_for_origin(&self, origin: &str) -> usize {
        self.origins
            .get(origin)
            .map(|state| state.inflight.len())
            .unwrap_or(0)
    }

    pub fn seen_count(&self) -> usize {
        self.seen_urls.len()
    }

    pub fn seen_request_id_count(&self) -> usize {
        self.seen_request_ids.len()
    }

    pub fn tracked_origin_count(&self) -> usize {
        self.origins.len()
    }

    /// Enforce the socket-level SSRF guard after DNS resolution and before connect.
    pub fn enforce_resolved_ip(
        &self,
        lease: &CrawlLease,
        resolved_ip: IpAddr,
    ) -> Result<(), CrawlResolvedTargetError> {
        if self.live_leases.get(&lease.request_id) != Some(lease) {
            return Err(CrawlResolvedTargetError::StaleLease {
                request_id: lease.request_id.clone(),
            });
        }
        self.url_policy
            .enforce_resolved_ip(&lease.url, resolved_ip)
            .map_err(|error| CrawlResolvedTargetError::UrlPolicy(error.reason))
    }

    /// Enforce the socket-level SSRF guard after DNS resolution and before connect.
    pub fn enforce_resolved_socket(
        &self,
        lease: &CrawlLease,
        resolved_socket: SocketAddr,
    ) -> Result<(), CrawlResolvedTargetError> {
        self.enforce_resolved_ip(lease, resolved_socket.ip())
    }

    /// Decide whether a crawl candidate may start at `tick`.
    pub fn admit(&mut self, candidate: CrawlCandidate, tick: u64) -> CrawlAdmissionDecision {
        if self.seen_request_ids.contains(&candidate.request_id) {
            return CrawlAdmissionDecision::Drop {
                reason: CrawlRejectReason::DuplicateRequestId {
                    request_id: candidate.request_id,
                },
            };
        }

        let canonical = match canonical_crawl_url(&candidate.url, &self.url_policy) {
            Ok(canonical) => canonical,
            Err(reason) => {
                return CrawlAdmissionDecision::Drop {
                    reason: CrawlRejectReason::UrlPolicy(reason),
                };
            }
        };
        if self.seen_urls.contains(&canonical.url) {
            return CrawlAdmissionDecision::Drop {
                reason: CrawlRejectReason::DuplicateUrl {
                    origin: canonical.origin,
                },
            };
        }

        if self.global_inflight.len() >= self.config.max_global_inflight {
            return CrawlAdmissionDecision::Delay {
                retry_after_tick: tick.saturating_add(1),
                reason: CrawlDelayReason::GlobalConcurrencyLimit {
                    max: self.config.max_global_inflight,
                },
            };
        }

        if let Some(state) = self.origins.get(&canonical.origin) {
            if state.inflight.len() >= self.config.max_per_origin_inflight {
                return CrawlAdmissionDecision::Delay {
                    retry_after_tick: state.next_allowed_tick.max(tick.saturating_add(1)),
                    reason: CrawlDelayReason::PerOriginConcurrencyLimit {
                        origin: canonical.origin,
                        max: self.config.max_per_origin_inflight,
                    },
                };
            }
            if tick < state.next_allowed_tick {
                return CrawlAdmissionDecision::Delay {
                    retry_after_tick: state.next_allowed_tick,
                    reason: CrawlDelayReason::PolitenessWindow {
                        origin: canonical.origin,
                    },
                };
            }
        }

        let is_new_origin = !self.origins.contains_key(&canonical.origin);
        if is_new_origin {
            self.origin_order.push_back(canonical.origin.clone());
        }
        let state = self.origins.entry(canonical.origin.clone()).or_default();
        self.seen_urls.insert(canonical.url.clone());
        self.seen_url_order.push_back(canonical.url.clone());
        self.seen_request_ids.insert(candidate.request_id.clone());
        self.seen_request_id_order
            .push_back(candidate.request_id.clone());
        self.global_inflight.insert(candidate.request_id.clone());
        state.inflight.insert(candidate.request_id.clone());
        let lease = CrawlLease {
            request_id: candidate.request_id,
            url: canonical.url,
            origin: canonical.origin,
            admitted_at_tick: tick,
        };
        self.live_urls.insert(lease.url.clone());
        self.live_leases
            .insert(lease.request_id.clone(), lease.clone());
        self.prune_retained_history();
        CrawlAdmissionDecision::Admit(lease)
    }

    fn prune_retained_history(&mut self) {
        self.prune_seen_request_ids();
        self.prune_seen_urls();
        self.prune_tracked_origins();
    }

    fn prune_seen_request_ids(&mut self) {
        let queue_len = self.seen_request_id_order.len();
        for _ in 0..queue_len {
            if self.seen_request_ids.len() <= self.config.max_seen_request_ids {
                break;
            }
            let Some(request_id) = self.seen_request_id_order.pop_front() else {
                break;
            };
            if self.global_inflight.contains(&request_id) {
                self.seen_request_id_order.push_back(request_id);
            } else {
                self.seen_request_ids.remove(&request_id);
            }
        }
    }

    fn prune_seen_urls(&mut self) {
        let queue_len = self.seen_url_order.len();
        for _ in 0..queue_len {
            if self.seen_urls.len() <= self.config.max_seen_urls {
                break;
            }
            let Some(url) = self.seen_url_order.pop_front() else {
                break;
            };
            if self.live_urls.contains(&url) {
                self.seen_url_order.push_back(url);
            } else {
                self.seen_urls.remove(&url);
            }
        }
    }

    fn prune_tracked_origins(&mut self) {
        let queue_len = self.origin_order.len();
        for _ in 0..queue_len {
            if self.origins.len() <= self.config.max_tracked_origins {
                break;
            }
            let Some(origin) = self.origin_order.pop_front() else {
                break;
            };
            match self.origins.get(&origin) {
                Some(state) if state.inflight.is_empty() => {
                    self.origins.remove(&origin);
                }
                Some(_) => self.origin_order.push_back(origin),
                None => {}
            }
        }
    }

    /// Release a previously admitted request. Returns `true` when the lease was live.
    pub fn finish(&mut self, lease: &CrawlLease, tick: u64) -> bool {
        if self.live_leases.get(&lease.request_id) != Some(lease) {
            return false;
        }
        let Some(state) = self.origins.get_mut(&lease.origin) else {
            return false;
        };
        if !self.global_inflight.contains(&lease.request_id)
            || !state.inflight.contains(&lease.request_id)
        {
            false
        } else {
            self.global_inflight.remove(&lease.request_id);
            self.live_urls.remove(&lease.url);
            state.inflight.remove(&lease.request_id);
            self.live_leases.remove(&lease.request_id);
            state.next_allowed_tick = state
                .next_allowed_tick
                .max(tick.saturating_add(self.config.crawl_delay_ticks));
            self.prune_retained_history();
            true
        }
    }
}

impl Default for CrawlAdmission {
    fn default() -> Self {
        Self::secure_default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OriginCrawlState {
    inflight: BTreeSet<RequestId>,
    next_allowed_tick: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalCrawlUrl {
    url: String,
    origin: String,
}

fn canonical_crawl_url(
    url: &str,
    url_policy: &UrlPolicy,
) -> Result<CanonicalCrawlUrl, BlockReason> {
    match url_policy.check(url) {
        UrlPolicyVerdict::Allow => {}
        UrlPolicyVerdict::Block(reason) => return Err(reason),
    }
    let parts = UrlParts::parse(url)?;
    Ok(CanonicalCrawlUrl {
        url: parts.target_uri(),
        origin: parts.origin(),
    })
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

    let (host_part, port) = match authority.rsplit_once(':') {
        Some((host, port_raw)) if port_raw.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, port_raw.parse::<u16>().ok())
        }
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

#[cfg(test)]
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
            nonce: None,
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
    fn url_policy_allow_all_skips_resolved_socket_guard() -> Result<(), UrlBlocked> {
        UrlPolicy::allow_all().enforce_resolved_ip(
            "file:///etc/passwd",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        )?;
        Ok(())
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
                ProxyRoute::new("general", "socks5://proxy.example:1080"),
            )
            .proxy_domain(
                DomainRule::exact("payments.example.com"),
                ProxyRoute::new("payments", "socks5://payments-proxy.example:1080"),
            );

        let decision = policy.decide(&request)?;

        assert_eq!(decision.proxy_id(), Some("payments"));
        assert_eq!(decision.port(), 443);
        Ok(())
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
                ProxyRoute::new("general", "socks5://proxy.example:1080"),
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
    fn crawl_admission_blocks_private_targets_and_dedupes_canonical_urls() -> Result<(), String> {
        let mut admission = CrawlAdmission::secure_default();

        let blocked = admission.admit(
            CrawlCandidate::new("private", "http://169.254.169.254/latest/meta-data", 0),
            0,
        );
        assert!(
            matches!(
                blocked,
                CrawlAdmissionDecision::Drop {
                    reason: CrawlRejectReason::UrlPolicy(BlockReason {
                        code: BlockCode::BlockedIp,
                        ..
                    }),
                }
            ),
            "private target should be rejected: {blocked:?}"
        );

        let first = admission.admit(
            CrawlCandidate::new(
                "r1",
                "https://Example.COM:443/path/reset-token?q=secret#fragment",
                0,
            ),
            1,
        );
        let CrawlAdmissionDecision::Admit(lease) = first else {
            return Err(format!("public URL should be admitted: {first:?}"));
        };
        assert_eq!(lease.url, "https://example.com/path/reset-token?q=secret");
        assert_eq!(lease.origin, "https://example.com");

        let duplicate = admission.admit(
            CrawlCandidate::new(
                "r2",
                "https://example.com/path/reset-token?q=secret#other",
                0,
            ),
            2,
        );
        assert_eq!(
            duplicate,
            CrawlAdmissionDecision::Drop {
                reason: CrawlRejectReason::DuplicateUrl {
                    origin: "https://example.com".into(),
                },
            }
        );
        let duplicate_debug = format!("{duplicate:?}");
        assert!(!duplicate_debug.contains("reset-token"));
        assert!(!duplicate_debug.contains("q=secret"));
        assert_eq!(admission.seen_count(), 1);
        Ok(())
    }

    #[test]
    fn crawl_admission_requires_resolved_socket_check_before_connect() -> Result<(), String> {
        let mut admission = CrawlAdmission::secure_default();
        let decision = admission.admit(
            CrawlCandidate::new("public-host", "https://public.example/agent", 0),
            0,
        );
        let CrawlAdmissionDecision::Admit(lease) = decision else {
            return Err(format!("public hostname should be admitted: {decision:?}"));
        };

        let metadata_socket = SocketAddr::from(([169, 254, 169, 254], 443));
        let blocked = admission.enforce_resolved_socket(&lease, metadata_socket);
        assert!(
            matches!(
                &blocked,
                Err(CrawlResolvedTargetError::UrlPolicy(BlockReason {
                    code: BlockCode::BlockedIp,
                    ..
                }))
            ),
            "resolved metadata target should be blocked: {blocked:?}"
        );

        let public_socket = SocketAddr::from(([93, 184, 216, 34], 443));
        admission
            .enforce_resolved_socket(&lease, public_socket)
            .map_err(|error| format!("public resolved target should be allowed: {error:?}"))?;
        assert!(admission.finish(&lease, 1));

        let stale = admission.enforce_resolved_socket(&lease, public_socket);
        assert_eq!(
            stale,
            Err(CrawlResolvedTargetError::StaleLease {
                request_id: "public-host".into(),
            })
        );
        Ok(())
    }

    #[test]
    fn crawl_admission_enforces_global_and_per_origin_limits() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 2,
                max_per_origin_inflight: 1,
                crawl_delay_ticks: 0,
                ..CrawlAdmissionConfig::default()
            },
            UrlPolicy::block_private(),
        );

        let first = admission.admit(CrawlCandidate::new("a1", "https://a.example/1", 0), 10);
        let CrawlAdmissionDecision::Admit(first_lease) = first else {
            return Err(format!("first request should be admitted: {first:?}"));
        };

        let same_origin = admission.admit(CrawlCandidate::new("a2", "https://a.example/2", 0), 11);
        assert_eq!(
            same_origin,
            CrawlAdmissionDecision::Delay {
                retry_after_tick: 12,
                reason: CrawlDelayReason::PerOriginConcurrencyLimit {
                    origin: "https://a.example".into(),
                    max: 1,
                },
            }
        );

        let second = admission.admit(CrawlCandidate::new("b1", "https://b.example/1", 0), 12);
        assert!(
            second.admitted(),
            "different origin should use remaining global capacity: {second:?}"
        );

        let global_limited =
            admission.admit(CrawlCandidate::new("c1", "https://c.example/1", 0), 13);
        assert_eq!(
            global_limited,
            CrawlAdmissionDecision::Delay {
                retry_after_tick: 14,
                reason: CrawlDelayReason::GlobalConcurrencyLimit { max: 2 },
            }
        );

        assert!(admission.finish(&first_lease, 20));
        let after_finish = admission.admit(CrawlCandidate::new("a3", "https://a.example/3", 0), 21);
        assert!(
            after_finish.admitted(),
            "finishing a lease should free per-origin and global capacity: {after_finish:?}"
        );
        Ok(())
    }

    #[test]
    fn crawl_admission_rejects_live_duplicate_request_ids() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 4,
                max_per_origin_inflight: 4,
                crawl_delay_ticks: 0,
                ..CrawlAdmissionConfig::default()
            },
            UrlPolicy::block_private(),
        );

        let first = admission.admit(CrawlCandidate::new("dup", "https://a.example/1", 0), 0);
        let CrawlAdmissionDecision::Admit(_lease) = first else {
            return Err(format!("first request should be admitted: {first:?}"));
        };

        let duplicate =
            admission.admit(CrawlCandidate::new("dup", "https://b.example/other", 0), 1);
        assert_eq!(
            duplicate,
            CrawlAdmissionDecision::Drop {
                reason: CrawlRejectReason::DuplicateRequestId {
                    request_id: "dup".into(),
                },
            }
        );
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.inflight_for_origin("https://a.example"), 1);
        assert_eq!(admission.inflight_for_origin("https://b.example"), 0);
        assert_eq!(admission.seen_count(), 1);
        Ok(())
    }

    #[test]
    fn crawl_admission_rejects_reused_request_ids_after_finish() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 4,
                max_per_origin_inflight: 4,
                crawl_delay_ticks: 0,
                ..CrawlAdmissionConfig::default()
            },
            UrlPolicy::block_private(),
        );

        let first = admission.admit(
            CrawlCandidate::new("stable-id", "https://a.example/1", 0),
            0,
        );
        let CrawlAdmissionDecision::Admit(lease) = first else {
            return Err(format!("first request should be admitted: {first:?}"));
        };
        assert!(admission.finish(&lease, 1));

        let reused = admission.admit(
            CrawlCandidate::new("stable-id", "https://b.example/other", 0),
            2,
        );
        assert_eq!(
            reused,
            CrawlAdmissionDecision::Drop {
                reason: CrawlRejectReason::DuplicateRequestId {
                    request_id: "stable-id".into(),
                },
            }
        );
        assert_eq!(admission.inflight(), 0);
        assert_eq!(admission.inflight_for_origin("https://b.example"), 0);
        Ok(())
    }

    #[test]
    fn crawl_admission_finish_ignores_forged_or_wrong_origin_leases() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 1,
                max_per_origin_inflight: 1,
                crawl_delay_ticks: 10,
                ..CrawlAdmissionConfig::default()
            },
            UrlPolicy::block_private(),
        );

        let first = admission.admit(CrawlCandidate::new("r1", "https://a.example/1", 0), 0);
        let CrawlAdmissionDecision::Admit(lease) = first else {
            return Err(format!("first request should be admitted: {first:?}"));
        };

        let wrong_origin = CrawlLease {
            origin: "https://b.example".into(),
            ..lease.clone()
        };
        assert!(!admission.finish(&wrong_origin, 5));
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.inflight_for_origin("https://a.example"), 1);

        let unknown_request = CrawlLease {
            request_id: "missing".into(),
            ..lease.clone()
        };
        assert!(!admission.finish(&unknown_request, 6));
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.inflight_for_origin("https://a.example"), 1);

        let wrong_url = CrawlLease {
            url: "https://a.example/forged".into(),
            ..lease.clone()
        };
        assert!(!admission.finish(&wrong_url, 7));
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.inflight_for_origin("https://a.example"), 1);

        assert!(admission.finish(&lease, 8));
        assert_eq!(admission.inflight(), 0);
        assert_eq!(admission.inflight_for_origin("https://a.example"), 0);
        Ok(())
    }

    #[test]
    fn crawl_admission_respects_per_origin_politeness_window() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 4,
                max_per_origin_inflight: 2,
                crawl_delay_ticks: 10,
                ..CrawlAdmissionConfig::default()
            },
            UrlPolicy::block_private(),
        );

        let first = admission.admit(
            CrawlCandidate::new("r1", "https://polite.example/first", 0),
            0,
        );
        let CrawlAdmissionDecision::Admit(lease) = first else {
            return Err(format!("first request should be admitted: {first:?}"));
        };
        assert!(admission.finish(&lease, 5));

        let delayed = admission.admit(
            CrawlCandidate::new("r2", "https://polite.example/second", 0),
            14,
        );
        assert_eq!(
            delayed,
            CrawlAdmissionDecision::Delay {
                retry_after_tick: 15,
                reason: CrawlDelayReason::PolitenessWindow {
                    origin: "https://polite.example".into(),
                },
            }
        );

        let admitted = admission.admit(
            CrawlCandidate::new("r3", "https://polite.example/third", 0),
            15,
        );
        assert!(
            admitted.admitted(),
            "candidate should run once the quiet window expires: {admitted:?}"
        );
        Ok(())
    }

    #[test]
    fn crawl_admission_retention_tables_stay_bounded_after_finish() -> Result<(), String> {
        let mut admission = CrawlAdmission::new(
            CrawlAdmissionConfig {
                max_global_inflight: 1,
                max_per_origin_inflight: 1,
                max_seen_urls: 2,
                max_seen_request_ids: 2,
                max_tracked_origins: 2,
                crawl_delay_ticks: 0,
            },
            UrlPolicy::block_private(),
        );

        for index in 0..5 {
            let decision = admission.admit(
                CrawlCandidate::new(
                    format!("r{index}"),
                    format!("https://site{index}.example/path"),
                    0,
                ),
                index,
            );
            let CrawlAdmissionDecision::Admit(lease) = decision else {
                return Err(format!("request {index} should be admitted: {decision:?}"));
            };
            assert!(admission.finish(&lease, index.saturating_add(1)));
        }

        assert!(
            admission.seen_count() <= 2,
            "seen URL table should be capped: {:?}",
            admission.seen_urls
        );
        assert!(
            admission.seen_request_id_count() <= 2,
            "seen request id table should be capped: {:?}",
            admission.seen_request_ids
        );
        assert!(
            admission.tracked_origin_count() <= 2,
            "origin table should be capped: {:?}",
            admission.origins.keys().collect::<Vec<_>>()
        );
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
    fn web_bot_auth_signs_and_verifies_rfc_9421_headers() -> Result<(), SignatureError> {
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
            "sig1=(\"@method\" \"@authority\" \"@scheme\" \"@path\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.signature.ends_with(':'));

        let base = signature_base(
            &request,
            &SignatureParameters::web_bot_auth("tempo-agent", 1_800_000_000),
        )?;
        assert_eq!(
            base,
            "\"@method\": GET\n\"@authority\": example.com\n\"@scheme\": https\n\"@path\": /agent/path\n\"@signature-params\": (\"@method\" \"@authority\" \"@scheme\" \"@path\");created=1800000000;keyid=\"tempo-agent\";alg=\"ed25519\""
        );

        verify_request_signature_at(
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

        verify_request_signature(
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
            "https://example.com/other/path",
            "profile-a",
            IdentityMode::AgentDeclared,
        );

        let tampered_result = verify_request_signature_at(
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

        let wrong_key_result = verify_request_signature_at(
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
        let stale_result = verify_request_signature_at(
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
        let future_result = verify_request_signature_at(
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
        verify_request_signature_at(
            &request,
            &skewed_headers.signature_input,
            &skewed_headers.signature,
            &verifier,
            1_800_000_000,
        )?;
        Ok(())
    }

    #[test]
    fn web_bot_auth_honors_custom_freshness_policy() -> Result<(), SignatureError> {
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
        verify_request_signature_at(
            &request,
            &old_headers.signature_input,
            &old_headers.signature,
            &verifier,
            1_800_000_600,
        )?;

        let future_headers = request.sign_web_bot_auth(&key, 1_800_000_120)?;
        verify_request_signature_at(
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
}
