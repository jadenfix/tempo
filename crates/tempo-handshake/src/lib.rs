//! tempo-handshake — structured-web probe and lane selection.
//!
//! This crate owns the pre-render handshake contract from `final.md`: discover structured
//! web surfaces before spending engine time, then choose the API/MCP lane when a usable
//! machine-readable surface is present and the render lane otherwise.

use std::io::Read;
use std::time::Duration;

use tempo_net::UrlPolicy;
use thiserror::Error;

/// Default response body cap for each pre-render HTTP probe.
pub const DEFAULT_MAX_PROBE_BODY_BYTES: usize = 64 * 1024;

/// HTTP endpoints tempo probes before rendering a page.
pub const DEFAULT_HTTP_PROBES: &[HttpProbe] = &[
    HttpProbe {
        signal: StructuredSignal::BeaterJson,
        path: "/.well-known/beater.json",
    },
    HttpProbe {
        signal: StructuredSignal::AgentCard,
        path: "/agent-card.json",
    },
    HttpProbe {
        signal: StructuredSignal::LlmsTxt,
        path: "/llms.txt",
    },
    HttpProbe {
        signal: StructuredSignal::OpenApi,
        path: "/openapi.json",
    },
    HttpProbe {
        signal: StructuredSignal::McpCatalog,
        path: "/mcp/catalog.json",
    },
];

/// A structured-web surface that can let tempo skip pixel rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredSignal {
    /// `.well-known/beater.json`, the beater-connect descriptor.
    BeaterJson,
    /// `agent-card.json`, the agent identity and tool descriptor.
    AgentCard,
    /// `llms.txt`, a text entrypoint for agent-readable site context.
    LlmsTxt,
    /// `openapi.json`, a direct API surface.
    OpenApi,
    /// `/mcp/catalog.json`, a server-side MCP catalog.
    McpCatalog,
    /// Browser-side WebMCP, exposed as `navigator.modelContext`.
    WebMcp,
}

impl StructuredSignal {
    /// The preferred lane when this signal is the strongest available evidence.
    pub fn lane(self) -> Lane {
        match self {
            StructuredSignal::McpCatalog | StructuredSignal::WebMcp => Lane::Mcp,
            StructuredSignal::BeaterJson
            | StructuredSignal::AgentCard
            | StructuredSignal::LlmsTxt
            | StructuredSignal::OpenApi => Lane::Api,
        }
    }

    fn priority(self) -> u8 {
        match self {
            StructuredSignal::WebMcp => 6,
            StructuredSignal::McpCatalog => 5,
            StructuredSignal::BeaterJson => 4,
            StructuredSignal::OpenApi => 3,
            StructuredSignal::AgentCard => 2,
            StructuredSignal::LlmsTxt => 1,
        }
    }
}

/// A relative HTTP probe path and the signal it can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpProbe {
    pub signal: StructuredSignal,
    pub path: &'static str,
}

/// Minimal response shape needed by the handshake detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResponse {
    pub path: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

impl ProbeResponse {
    pub fn new(path: impl Into<String>, status: u16, body: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            status,
            content_type: None,
            body: body.into(),
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Runtime configuration for live HTTP structured-web probes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProbeConfig {
    pub timeout: Duration,
    pub max_body_bytes: usize,
    pub url_policy: UrlPolicy,
}

impl HttpProbeConfig {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }
}

impl Default for HttpProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            max_body_bytes: DEFAULT_MAX_PROBE_BODY_BYTES,
            url_policy: UrlPolicy::block_private(),
        }
    }
}

/// One failed live HTTP probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProbeFailure {
    pub path: String,
    pub url: String,
    pub reason: String,
}

/// Complete result from a live structured-web probe run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProbeRun {
    pub origin: String,
    pub responses: Vec<ProbeResponse>,
    pub failures: Vec<HttpProbeFailure>,
    pub report: ProbeReport,
}

impl HttpProbeRun {
    pub fn lane_decision(&self) -> LaneDecision {
        decide_lane(&self.report)
    }
}

/// Transport-level failure before individual probe responses can be collected.
#[derive(Debug, Error)]
pub enum HttpProbeError {
    #[error("failed to build HTTP probe client: {0}")]
    ClientBuild(String),
    #[error("invalid HTTP probe target: {0}")]
    InvalidTarget(String),
    #[error("HTTP probe worker panicked")]
    WorkerPanicked,
}

/// Probe the default structured-web URLs for a target URL's origin with real HTTP requests.
pub fn probe_http_origin(
    target: &str,
    config: HttpProbeConfig,
) -> Result<HttpProbeRun, HttpProbeError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .redirect(url_policy_redirect(config.url_policy.clone()))
        .build()
        .map_err(|error| HttpProbeError::ClientBuild(error.to_string()))?;
    let origin = canonical_probe_origin(target)?;

    let mut handles = Vec::with_capacity(DEFAULT_HTTP_PROBES.len());
    for (index, probe) in DEFAULT_HTTP_PROBES.iter().copied().enumerate() {
        let client = client.clone();
        let url_policy = config.url_policy.clone();
        let url = format!("{origin}{}", probe.path);
        let max_body_bytes = config.max_body_bytes;
        handles.push(std::thread::spawn(move || {
            fetch_probe(index, probe, url, max_body_bytes, url_policy, client)
        }));
    }

    let mut fetched = Vec::with_capacity(DEFAULT_HTTP_PROBES.len());
    for handle in handles {
        fetched.push(handle.join().map_err(|_| HttpProbeError::WorkerPanicked)?);
    }
    fetched.sort_by_key(|result| result.index);

    let mut responses = Vec::new();
    let mut failures = Vec::new();
    for result in fetched {
        if let Some(response) = result.response {
            responses.push(response);
        }
        if let Some(failure) = result.failure {
            failures.push(failure);
        }
    }

    let report = ProbeReport::from_responses(responses.clone());
    Ok(HttpProbeRun {
        origin,
        responses,
        failures,
        report,
    })
}

/// Evidence that a site exposes a structured surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeHit {
    pub signal: StructuredSignal,
    pub source: String,
}

impl ProbeHit {
    pub fn new(signal: StructuredSignal, source: impl Into<String>) -> Self {
        Self {
            signal,
            source: source.into(),
        }
    }
}

/// Complete handshake input gathered by the transport/browser layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeReport {
    hits: Vec<ProbeHit>,
}

impl ProbeReport {
    pub fn new() -> Self {
        Self { hits: Vec::new() }
    }

    pub fn from_hits(hits: Vec<ProbeHit>) -> Self {
        let mut report = Self::new();
        for hit in hits {
            report.add_hit(hit);
        }
        report
    }

    pub fn from_responses(responses: impl IntoIterator<Item = ProbeResponse>) -> Self {
        let mut report = Self::new();
        for response in responses {
            if let Some(hit) = detect_http_signal(&response) {
                report.add_hit(hit);
            }
        }
        report
    }

    pub fn add_hit(&mut self, hit: ProbeHit) {
        if !self
            .hits
            .iter()
            .any(|existing| existing.signal == hit.signal)
        {
            self.hits.push(hit);
        }
    }

    pub fn record_web_mcp(&mut self, available: bool) {
        if available {
            self.add_hit(ProbeHit::new(
                StructuredSignal::WebMcp,
                "navigator.modelContext",
            ));
        }
    }

    pub fn hits(&self) -> &[ProbeHit] {
        &self.hits
    }
}

/// The execution lane tempo should use for the target origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// No structured surface was found; use the browser engine.
    Render,
    /// Use an API/agent-card/llms/beater-connect surface and skip rendering.
    Api,
    /// Use an MCP surface and skip rendering.
    Mcp,
}

impl Lane {
    pub fn skips_render(self) -> bool {
        matches!(self, Lane::Api | Lane::Mcp)
    }
}

/// Deterministic lane decision with the strongest evidence that drove it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneDecision {
    pub lane: Lane,
    pub selected: Option<ProbeHit>,
}

impl LaneDecision {
    pub fn skips_render(&self) -> bool {
        self.lane.skips_render()
    }
}

/// Build absolute probe URLs for an origin while keeping the probe order stable.
pub fn probe_urls(origin: &str) -> Vec<String> {
    let origin = origin.trim_end_matches('/');
    DEFAULT_HTTP_PROBES
        .iter()
        .map(|probe| format!("{origin}{}", probe.path))
        .collect()
}

/// Build absolute probe URLs for the origin of a navigation target.
pub fn probe_urls_for_target(target: &str) -> Result<Vec<String>, HttpProbeError> {
    Ok(probe_urls(&canonical_probe_origin(target)?))
}

/// Canonicalize an arbitrary navigation target to the HTTP(S) origin tempo should probe.
pub fn canonical_probe_origin(target: &str) -> Result<String, HttpProbeError> {
    let parsed = url::Url::parse(target)
        .map_err(|error| HttpProbeError::InvalidTarget(error.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed.origin().ascii_serialization()),
        scheme => Err(HttpProbeError::InvalidTarget(format!(
            "scheme '{scheme}' is not http or https"
        ))),
    }
}

/// Select the structured lane when any supported signal is present, otherwise render.
pub fn decide_lane(report: &ProbeReport) -> LaneDecision {
    let selected = report
        .hits()
        .iter()
        .max_by_key(|hit| hit.signal.priority())
        .cloned();
    let lane = selected
        .as_ref()
        .map(|hit| hit.signal.lane())
        .unwrap_or(Lane::Render);
    LaneDecision { lane, selected }
}

/// Detect one structured signal from a fetched probe response.
pub fn detect_http_signal(response: &ProbeResponse) -> Option<ProbeHit> {
    if !response.is_success() {
        return None;
    }

    let path = response.path.trim_end_matches('/');
    let body = response.body.trim();
    if body.is_empty() {
        return None;
    }

    let signal = if path.ends_with("/.well-known/beater.json") && looks_like_json(body) {
        StructuredSignal::BeaterJson
    } else if path.ends_with("/agent-card.json") && looks_like_json(body) {
        StructuredSignal::AgentCard
    } else if path.ends_with("/llms.txt") && looks_like_text(response, body) {
        StructuredSignal::LlmsTxt
    } else if path.ends_with("/openapi.json")
        && looks_like_json(body)
        && body.contains("\"openapi\"")
    {
        StructuredSignal::OpenApi
    } else if path.ends_with("/mcp/catalog.json")
        && looks_like_json(body)
        && body.contains("\"tools\"")
    {
        StructuredSignal::McpCatalog
    } else {
        return None;
    };

    Some(ProbeHit::new(signal, path.to_string()))
}

struct IndexedProbeFetch {
    index: usize,
    response: Option<ProbeResponse>,
    failure: Option<HttpProbeFailure>,
}

/// Redirect policy that re-validates every hop against the URL policy.
///
/// The reqwest default follows up to 10 redirects with no per-hop check, so a
/// probed origin could `302 Location: http://169.254.169.254/...` and the
/// client would follow it into an internal/loopback target, capturing the
/// internal response body (issue #80). This stops any redirect whose target the
/// URL policy would block, and caps the hop count.
fn url_policy_redirect(url_policy: UrlPolicy) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error(HttpRedirectBlocked("too many redirects".to_string()));
        }
        match url_policy.enforce(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(error) => attempt.error(HttpRedirectBlocked(error.to_string())),
        }
    })
}

#[derive(Debug)]
struct HttpRedirectBlocked(String);

impl std::fmt::Display for HttpRedirectBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "redirect blocked by URL policy: {}", self.0)
    }
}

impl std::error::Error for HttpRedirectBlocked {}

fn fetch_probe(
    index: usize,
    probe: HttpProbe,
    url: String,
    max_body_bytes: usize,
    url_policy: UrlPolicy,
    client: reqwest::blocking::Client,
) -> IndexedProbeFetch {
    if let Err(error) = url_policy.enforce(&url) {
        return IndexedProbeFetch {
            index,
            response: None,
            failure: Some(HttpProbeFailure {
                path: probe.path.to_string(),
                url,
                reason: error.to_string(),
            }),
        };
    }

    match fetch_probe_response(&client, probe.path, &url, max_body_bytes) {
        Ok(response) => IndexedProbeFetch {
            index,
            response: Some(response),
            failure: None,
        },
        Err(reason) => IndexedProbeFetch {
            index,
            response: None,
            failure: Some(HttpProbeFailure {
                path: probe.path.to_string(),
                url,
                reason,
            }),
        },
    }
}

fn fetch_probe_response(
    client: &reqwest::blocking::Client,
    path: &str,
    url: &str,
    max_body_bytes: usize,
) -> Result<ProbeResponse, String> {
    let response = client.get(url).send().map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let mut body = Vec::new();
    response
        .take(max_body_bytes as u64)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    let body = String::from_utf8_lossy(&body).into_owned();

    let mut probe_response = ProbeResponse::new(path, status, body);
    if let Some(content_type) = content_type {
        probe_response = probe_response.with_content_type(content_type);
    }
    Ok(probe_response)
}

/// Human-readable crate summary for probes and diagnostics.
pub fn describe() -> &'static str {
    "structured-web probe: beater.json/agent-card/llms.txt/openapi/WebMCP; API/MCP-lane vs render decision"
}

fn looks_like_json(body: &str) -> bool {
    body.starts_with('{') || body.starts_with('[')
}

fn looks_like_text(response: &ProbeResponse, body: &str) -> bool {
    let content_type_allows_text = response
        .content_type
        .as_deref()
        .map(|content_type| {
            content_type.starts_with("text/")
                || content_type.starts_with("application/markdown")
                || content_type.starts_with("application/octet-stream")
        })
        .unwrap_or(true);
    content_type_allows_text && body.is_char_boundary(body.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration as StdDuration;

    use tempo_net::UrlPolicy;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn probe_plan_covers_required_http_surfaces() {
        let signals: Vec<_> = DEFAULT_HTTP_PROBES
            .iter()
            .map(|probe| probe.signal)
            .collect();
        assert_eq!(
            signals,
            vec![
                StructuredSignal::BeaterJson,
                StructuredSignal::AgentCard,
                StructuredSignal::LlmsTxt,
                StructuredSignal::OpenApi,
                StructuredSignal::McpCatalog,
            ]
        );
        assert_eq!(
            probe_urls("https://example.com/"),
            vec![
                "https://example.com/.well-known/beater.json",
                "https://example.com/agent-card.json",
                "https://example.com/llms.txt",
                "https://example.com/openapi.json",
                "https://example.com/mcp/catalog.json",
            ]
        );
    }

    #[test]
    fn target_probe_plan_uses_origin_not_path_query_or_fragment() -> TestResult {
        let urls =
            probe_urls_for_target("https://Example.COM:443/app/page?token=page-derived#frag")?;
        assert_eq!(
            urls,
            vec![
                "https://example.com/.well-known/beater.json",
                "https://example.com/agent-card.json",
                "https://example.com/llms.txt",
                "https://example.com/openapi.json",
                "https://example.com/mcp/catalog.json",
            ]
        );

        let custom_port = probe_urls_for_target("http://example.com:8080/deep/path")?;
        assert_eq!(
            custom_port[0],
            "http://example.com:8080/.well-known/beater.json"
        );
        Ok(())
    }

    #[test]
    fn target_probe_plan_rejects_non_http_targets() {
        let result = canonical_probe_origin("file:///tmp/page.html");
        assert!(
            matches!(result, Err(HttpProbeError::InvalidTarget(_))),
            "file target should not be probed: {result:?}"
        );
    }

    #[test]
    fn detects_each_fixture_signal() {
        let responses = vec![
            ProbeResponse::new(
                "/.well-known/beater.json",
                200,
                r#"{"version":"1","tools":[]}"#,
            ),
            ProbeResponse::new("/agent-card.json", 200, r#"{"name":"fixture"}"#),
            ProbeResponse::new("/llms.txt", 200, "# Fixture").with_content_type("text/plain"),
            ProbeResponse::new("/openapi.json", 200, r#"{"openapi":"3.1.0"}"#),
            ProbeResponse::new("/mcp/catalog.json", 200, r#"{"tools":[]}"#),
        ];

        let mut report = ProbeReport::from_responses(responses);
        report.record_web_mcp(true);

        let signals: Vec<_> = report.hits().iter().map(|hit| hit.signal).collect();
        assert_eq!(
            signals,
            vec![
                StructuredSignal::BeaterJson,
                StructuredSignal::AgentCard,
                StructuredSignal::LlmsTxt,
                StructuredSignal::OpenApi,
                StructuredSignal::McpCatalog,
                StructuredSignal::WebMcp,
            ]
        );
    }

    #[test]
    fn ignores_failed_empty_or_unstructured_fixtures() {
        let report = ProbeReport::from_responses(vec![
            ProbeResponse::new("/openapi.json", 404, r#"{"openapi":"3.1.0"}"#),
            ProbeResponse::new("/mcp/catalog.json", 200, ""),
            ProbeResponse::new("/openapi.json", 200, r#"{"swagger":"2.0"}"#),
            ProbeResponse::new("/mcp/catalog.json", 200, r#"{"resources":[]}"#),
        ]);

        assert!(report.hits().is_empty());
        assert_eq!(decide_lane(&report).lane, Lane::Render);
    }

    #[test]
    fn decision_table_skips_render_for_every_structured_signal() {
        let cases = [
            (StructuredSignal::BeaterJson, Lane::Api),
            (StructuredSignal::AgentCard, Lane::Api),
            (StructuredSignal::LlmsTxt, Lane::Api),
            (StructuredSignal::OpenApi, Lane::Api),
            (StructuredSignal::McpCatalog, Lane::Mcp),
            (StructuredSignal::WebMcp, Lane::Mcp),
        ];

        for (signal, lane) in cases {
            let report = ProbeReport::from_hits(vec![ProbeHit::new(signal, "fixture")]);
            let decision = decide_lane(&report);
            assert_eq!(decision.lane, lane, "wrong lane for {signal:?}");
            assert!(
                decision.skips_render(),
                "structured signal should skip render"
            );
        }
    }

    #[test]
    fn decision_table_renders_when_no_structured_signal_exists() {
        let decision = decide_lane(&ProbeReport::new());
        assert_eq!(decision.lane, Lane::Render);
        assert!(!decision.skips_render());
        assert_eq!(decision.selected, None);
    }

    #[test]
    fn mcp_signal_wins_over_api_signal() {
        let report = ProbeReport::from_hits(vec![
            ProbeHit::new(StructuredSignal::OpenApi, "/openapi.json"),
            ProbeHit::new(StructuredSignal::McpCatalog, "/mcp/catalog.json"),
        ]);

        let decision = decide_lane(&report);
        assert_eq!(decision.lane, Lane::Mcp);
        assert_eq!(
            decision.selected,
            Some(ProbeHit::new(
                StructuredSignal::McpCatalog,
                "/mcp/catalog.json"
            ))
        );
    }

    #[test]
    fn live_http_probe_fetches_structured_surfaces() -> TestResult {
        let (origin, server) = serve_probe_fixture("# Fixture")?;
        let target = format!("{origin}/app/page?query=ignored#fragment");

        let run = probe_http_origin(
            &target,
            HttpProbeConfig::default().with_url_policy(UrlPolicy::allow_all()),
        )?;
        join_server(server)?;

        assert_eq!(run.origin, origin);
        assert!(run.failures.is_empty(), "{:?}", run.failures);
        assert_eq!(run.responses.len(), DEFAULT_HTTP_PROBES.len());
        let paths: Vec<_> = run
            .responses
            .iter()
            .map(|response| response.path.as_str())
            .collect();
        let expected_paths: Vec<_> = DEFAULT_HTTP_PROBES.iter().map(|probe| probe.path).collect();
        assert_eq!(paths, expected_paths);

        let signals: Vec<_> = run.report.hits().iter().map(|hit| hit.signal).collect();
        assert!(signals.contains(&StructuredSignal::BeaterJson));
        assert!(signals.contains(&StructuredSignal::LlmsTxt));
        assert!(signals.contains(&StructuredSignal::McpCatalog));
        let decision = run.lane_decision();
        assert_eq!(decision.lane, Lane::Mcp);
        assert!(decision.skips_render());
        Ok(())
    }

    #[test]
    fn live_http_probe_enforces_default_url_policy_before_network() -> TestResult {
        let run = probe_http_origin("http://127.0.0.1:9", HttpProbeConfig::default())?;

        assert!(run.responses.is_empty());
        assert_eq!(run.failures.len(), DEFAULT_HTTP_PROBES.len());
        assert!(run
            .failures
            .iter()
            .all(|failure| failure.reason.contains("URL blocked")));
        assert_eq!(run.lane_decision().lane, Lane::Render);
        Ok(())
    }

    #[test]
    fn live_http_probe_caps_response_bodies() -> TestResult {
        let (origin, server) = serve_probe_fixture("0123456789abcdef")?;

        let run = probe_http_origin(
            &origin,
            HttpProbeConfig::default()
                .with_url_policy(UrlPolicy::allow_all())
                .with_max_body_bytes(8),
        )?;
        join_server(server)?;

        let llms_response = run
            .responses
            .iter()
            .find(|response| response.path == "/llms.txt")
            .ok_or_else(|| io::Error::other("missing llms.txt response"))?;
        assert_eq!(llms_response.body, "01234567");
        Ok(())
    }

    #[test]
    fn redirect_policy_blocks_hop_to_private_target() -> TestResult {
        // Issue #80: a probed origin that 302s to a private/metadata target must
        // not be followed by the client.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            if let Some(stream) = listener.incoming().next() {
                let mut stream = stream?;
                stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
                let mut buffer = [0_u8; 512];
                let _ = stream.read(&mut buffer)?;
                let body = "internal-secret";
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            }
            Ok(())
        });

        let client = reqwest::blocking::Client::builder()
            .redirect(url_policy_redirect(UrlPolicy::block_private()))
            .build()?;
        let result = client.get(format!("http://{addr}/start")).send();
        let _ = handle.join();

        match result {
            Ok(_) => Err(Box::new(io::Error::other(
                "redirect to metadata host was followed",
            ))),
            Err(error) => {
                assert!(error.is_redirect(), "expected redirect error, got {error}");
                Ok(())
            }
        }
    }

    #[test]
    fn redirect_policy_follows_allowed_hop() -> TestResult {
        // A redirect to an allowed target is still followed.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            let mut incoming = listener.incoming();
            if let Some(stream) = incoming.next() {
                let mut stream = stream?;
                stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
                let mut buffer = [0_u8; 512];
                let _ = stream.read(&mut buffer)?;
                let location = format!("http://{addr}/final");
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            }
            if let Some(stream) = incoming.next() {
                let mut stream = stream?;
                stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
                let mut buffer = [0_u8; 512];
                let _ = stream.read(&mut buffer)?;
                let body = "final-ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            }
            Ok(())
        });

        let client = reqwest::blocking::Client::builder()
            .redirect(url_policy_redirect(UrlPolicy::allow_all()))
            .build()?;
        let text = client.get(format!("http://{addr}/start")).send()?.text()?;
        let _ = handle.join();
        assert_eq!(text, "final-ok");
        Ok(())
    }

    fn serve_probe_fixture(
        llms_body: impl Into<String>,
    ) -> Result<(String, thread::JoinHandle<Result<(), io::Error>>), io::Error> {
        let llms_body = llms_body.into();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            for stream in listener.incoming().take(DEFAULT_HTTP_PROBES.len()) {
                handle_probe_stream(stream?, &llms_body)?;
            }
            Ok(())
        });
        Ok((format!("http://{addr}"), handle))
    }

    fn handle_probe_stream(mut stream: TcpStream, llms_body: &str) -> Result<(), io::Error> {
        stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(io::Error::other("request headers exceeded fixture cap"));
            }
        }

        let request = String::from_utf8_lossy(&request);
        let first_line = request
            .lines()
            .next()
            .ok_or_else(|| io::Error::other("missing request line"))?;
        let path = first_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| io::Error::other("missing request path"))?;

        let (status, content_type, body) = match path {
            "/.well-known/beater.json" => (
                "200 OK",
                "application/json",
                r#"{"version":"1","tools":[]}"#,
            ),
            "/agent-card.json" => ("404 Not Found", "text/plain", ""),
            "/llms.txt" => ("200 OK", "text/plain", llms_body),
            "/openapi.json" => ("404 Not Found", "text/plain", ""),
            "/mcp/catalog.json" => ("200 OK", "application/json", r#"{"tools":[]}"#),
            _ => ("404 Not Found", "text/plain", ""),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()
    }

    fn join_server(handle: thread::JoinHandle<Result<(), io::Error>>) -> TestResult {
        match handle.join() {
            Ok(result) => result.map_err(|error| Box::new(error) as Box<dyn Error>),
            Err(_) => Err(Box::new(io::Error::other("fixture server panicked"))),
        }
    }
}
