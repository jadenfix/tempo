//! Leaf URL policy crate for SSRF checks that must be shared below network code.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

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
    pub fn new(code: BlockCode, detail: impl Into<String>) -> Self {
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

/// URL components parsed with the same authority normalization used by the URL policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub host: String,
    pub audit_host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
}

impl UrlParts {
    pub fn parse(url: &str) -> Result<Self, BlockReason> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            BlockReason::new(BlockCode::InvalidUrl, "URL has no scheme separator")
        })?;
        let scheme = scheme.to_ascii_lowercase();
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

    pub fn origin(&self) -> String {
        match self.non_default_port() {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.audit_host),
            None => format!("{}://{}", self.scheme, self.audit_host),
        }
    }

    pub fn authority_component(&self) -> String {
        match self.non_default_port() {
            Some(port) => format!("{}:{port}", self.audit_host),
            None => self.audit_host.clone(),
        }
    }

    pub fn target_uri(&self) -> String {
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

    pub fn non_default_port(&self) -> Option<u16> {
        match (self.scheme.as_str(), self.port) {
            ("http", Some(80)) | ("https", Some(443)) => None,
            (_, port) => port,
        }
    }
}

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

pub fn normalize_path_dot_segments(path: &str) -> String {
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
        let host = host.to_string();
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

pub fn parse_relaxed_ipv4(host: &str) -> Option<Ipv4Addr> {
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

pub fn blocked_ip_reason(ip: &IpAddr) -> Option<String> {
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

pub fn egress_port(parts: &UrlParts) -> u16 {
    parts.port.unwrap_or(match parts.scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn blocks_private_metadata_and_local_targets() {
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
    fn blocks_browser_style_ipv4_bypasses() {
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
    fn blocks_whatwg_backslash_percent_encoded_and_idna_bypasses() {
        let policy = UrlPolicy::block_private();
        for url in [
            "https://169.254.169.254\\@allowed.example/",
            "https://169.254.169.254\\.allowed.example/",
            "https://169.254.169.254\t\\@allowed.example/",
            "https://169.254.169.254\n\\@allowed.example/",
            "https://169%2e254%2e169%2e254/",
            "https://169%2E254%2E169%2E254/latest/meta-data",
            "https://127%2e0%2e0%2e1/",
            "https://169。254。169。254/",
        ] {
            assert_blocked(&policy, url, BlockCode::BlockedIp);
        }
        assert_allowed(&policy, "https://user:pass@example.com/path");
        assert_allowed(&policy, "https://allowed.example\\@example.com/");
        assert!(policy.enforce("https://169%2e254%2e169%2e254/").is_err());
    }

    #[test]
    fn blocks_cgnat_reserved_and_private_resolved_targets() {
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
        assert_allowed(&policy, "http://100.63.255.255/");
        assert_allowed(&policy, "http://100.128.0.1/");

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
    }

    #[test]
    fn validates_resolved_socket_ports_and_allow_all_override() -> Result<(), UrlBlocked> {
        let policy = UrlPolicy::block_private();
        policy.enforce_resolved_socket(
            "https://public.example/agent",
            SocketAddr::from(([93, 184, 216, 34], 443)),
        )?;

        let result = policy.enforce_resolved_socket(
            "https://public.example/agent",
            SocketAddr::from(([93, 184, 216, 34], 22)),
        );
        assert!(matches!(
            result,
            Err(UrlBlocked { reason })
                if reason.code == BlockCode::InvalidUrl
                    && reason.detail.contains("does not match URL port 443")
        ));

        UrlPolicy::allow_all().enforce_resolved_socket(
            "file:///etc/passwd",
            SocketAddr::from(([127, 0, 0, 1], 22)),
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
    fn blocks_bad_schemes_and_malformed_urls() {
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
}
