//! tempo-handshake — structured-web probe and lane selection.
//!
//! This crate owns the pre-render handshake contract from `final.md`: discover structured
//! web surfaces before spending engine time, then choose the API/MCP lane when a usable
//! machine-readable surface is present and the render lane otherwise.

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

/// Human-readable crate summary retained for scaffold callers.
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
}
