//! tempo-mcp - MCP protocol core for driving a tempo session.
//!
//! This crate is transport-neutral: `tempod` owns HTTP sockets, while this
//! module owns Streamable HTTP JSON-RPC semantics, Origin validation, tool
//! descriptors, and calls into the real `DriverTrait` and handshake contracts.

use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use tempo_driver::{DriverTrait, Engine, StepOutcome};
use tempo_handshake::{
    decide_lane, probe_http_origin, probe_urls, HttpProbeConfig, HttpProbeFailure,
    Lane as HandshakeLane, ProbeHit, ProbeReport, ProbeResponse, StructuredSignal,
};
use tempo_observe::composite_set_of_marks_png;
use tempo_schema::{Action, NodeId};
use thiserror::Error;
use url::{Host, Url};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub const A2A_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
pub const A2A_AGENT_JSON_PATH: &str = "/.well-known/agent.json";
pub const A2A_AGENT_CARD_CONTENT_TYPE: &str = "application/a2a+json";
const DRIVER_REQUIRED_ERROR_CODE: i64 = -32002;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpHttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl McpHttpResponse {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: value.to_string().into_bytes(),
        }
    }

    pub fn text(status: u16, value: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: value.into().into_bytes(),
        }
    }

    pub fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: Vec::new(),
        }
    }

    pub fn json_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

/// tempo's MCP session router over one driver instance.
pub struct TempoMcpServer<D> {
    driver: D,
    handshake_report: ProbeReport,
    handshake_probe_config: HttpProbeConfig,
}

impl<D> TempoMcpServer<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            handshake_report: ProbeReport::new(),
            handshake_probe_config: HttpProbeConfig::default(),
        }
    }

    pub fn with_handshake_report(mut self, report: ProbeReport) -> Self {
        self.handshake_report = report;
        self
    }

    pub fn with_handshake_probe_config(mut self, config: HttpProbeConfig) -> Self {
        self.handshake_probe_config = config;
        self
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn handshake_report_mut(&mut self) -> &mut ProbeReport {
        &mut self.handshake_report
    }
}

impl<D> TempoMcpServer<D>
where
    D: DriverTrait,
{
    /// Handle one MCP POST body. `origin` is the HTTP Origin header when present.
    pub async fn handle_post(&mut self, origin: Option<&str>, body: &[u8]) -> McpHttpResponse {
        if !origin_allowed(origin) {
            return McpHttpResponse::json(
                403,
                json_rpc_error(Value::Null, -32600, "origin not allowed"),
            );
        }

        let message: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(error) => {
                return McpHttpResponse::json(
                    400,
                    json_rpc_error(Value::Null, -32700, format!("parse error: {error}")),
                );
            }
        };

        let Some(id) = message.get("id").filter(|id| !id.is_null()).cloned() else {
            return McpHttpResponse::empty(202);
        };

        let reply = self.handle_message(&message).await;
        match reply {
            Ok(result) => McpHttpResponse::json(200, json_rpc_result(id, result)),
            Err(error) => McpHttpResponse::json(200, json_rpc_error(id, error.code, error.message)),
        }
    }

    async fn handle_message(&mut self, message: &Value) -> Result<Value, JsonRpcError> {
        if !message.is_object() {
            return Err(JsonRpcError::invalid_request(
                "JSON-RPC message must be an object",
            ));
        }

        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_request("JSON-RPC method is required"))?;
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => Ok(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tempo", "version": env!("CARGO_PKG_VERSION")},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tool_descriptor_json()})),
            "tools/call" => self.tools_call(&params).await,
            other => Err(JsonRpcError::method_not_found(format!(
                "method not found: {other}"
            ))),
        }
    }

    async fn tools_call(&mut self, params: &Value) -> Result<Value, JsonRpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("tools/call requires params.name"))?;
        if !tools().iter().any(|tool| tool.name == name) {
            return Err(JsonRpcError::invalid_params(format!(
                "unknown tool: {name}"
            )));
        }

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let call = self.call_tool(name, arguments).await?;
        Ok(tool_call_json(call))
    }

    async fn call_tool(&mut self, name: &str, arguments: Value) -> Result<ToolCall, JsonRpcError> {
        match name {
            "observe" => match self.driver.observe().await {
                Ok(observation) => Ok(ToolCall::success(json!(observation))),
                Err(error) => Ok(ToolCall::error(error.to_string())),
            },
            "act" => {
                let args: ActArgs = parse_args(arguments)?;
                match self.driver.act(&args.action).await {
                    Ok(outcome) => Ok(ToolCall::success(step_outcome_json(outcome))),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "fork" => match self.driver.fork().await {
                Ok(forked) => Ok(ToolCall::success(json!({
                    "supported": true,
                    "engine": engine_name(forked.engine()),
                }))),
                Err(error) => Ok(ToolCall::success(json!({
                    "supported": false,
                    "reason": error.to_string(),
                }))),
            },
            "extract" => {
                let args: NodeArgs = parse_args(arguments)?;
                match self.driver.extract(&args.node_id()?).await {
                    Ok(value) => Ok(ToolCall::success(value)),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "screenshot" => {
                let args: ScreenshotArgs = parse_args(arguments)?;
                let observation = if args.set_of_marks {
                    match self.driver.observe().await {
                        Ok(observation) => Some(observation),
                        Err(error) => return Ok(ToolCall::error(error.to_string())),
                    }
                } else {
                    None
                };
                match self.driver.screenshot().await {
                    Ok(bytes) => {
                        let bytes = match observation {
                            Some(observation) => {
                                match composite_set_of_marks_png(&bytes, &observation) {
                                    Ok(bytes) => bytes,
                                    Err(error) => return Ok(ToolCall::error(error.to_string())),
                                }
                            }
                            None => bytes,
                        };
                        Ok(ToolCall::success(json!({
                            "mime_type": "image/png",
                            "encoding": "base64",
                            "set_of_marks": args.set_of_marks,
                            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                        })))
                    }
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "handshake" => {
                let args: HandshakeArgs = parse_args(arguments)?;
                Ok(ToolCall::success(handshake_result_json(
                    &self.handshake_report,
                    &self.handshake_probe_config,
                    args,
                )))
            }
            _ => Err(JsonRpcError::invalid_params("unknown tool")),
        }
    }
}

pub fn handle_get() -> McpHttpResponse {
    McpHttpResponse::text(
        405,
        "this MCP endpoint does not offer a server-initiated stream",
    )
}

/// Publish tempo as an addressable agent resource.
///
/// The card is intentionally honest about the transport tempo serves today:
/// clients should connect through the MCP endpoint rather than unsupported A2A
/// task methods.
pub fn agent_card(base_url: &str) -> Value {
    let base_url = base_url.trim_end_matches('/');
    let mcp_url = format!("{base_url}/mcp");
    json!({
        "protocolVersion": "0.3.0",
        "name": "tempo",
        "description": "AI-agent-native browser control plane for live web sessions.",
        "url": mcp_url,
        "provider": {
            "organization": "tempo",
            "url": "https://github.com/jadenfix/tempo",
        },
        "version": env!("CARGO_PKG_VERSION"),
        "preferredTransport": "MCP",
        "additionalInterfaces": [{
            "transport": "MCP",
            "url": mcp_url,
        }],
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "stateTransitionHistory": false,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json", "image/png"],
        "skills": tools().into_iter().map(agent_card_skill_json).collect::<Vec<_>>(),
    })
}

pub fn agent_card_response(base_url: &str) -> McpHttpResponse {
    McpHttpResponse {
        status: 200,
        content_type: A2A_AGENT_CARD_CONTENT_TYPE,
        body: agent_card(base_url).to_string().into_bytes(),
    }
}

/// Handle MCP POST messages that do not require a page driver.
///
/// This keeps pre-render discovery available before an engine is attached:
/// initialize, ping, tools/list, and the handshake tool work; page-driving tools
/// return a JSON-RPC error instead of silently creating a browser stand-in.
pub fn handle_post_driverless(origin: Option<&str>, body: &[u8]) -> McpHttpResponse {
    handle_post_driverless_with_config(origin, body, HttpProbeConfig::default())
}

pub fn handle_post_driverless_with_config(
    origin: Option<&str>,
    body: &[u8],
    handshake_probe_config: HttpProbeConfig,
) -> McpHttpResponse {
    if !origin_allowed(origin) {
        return McpHttpResponse::json(
            403,
            json_rpc_error(Value::Null, -32600, "origin not allowed"),
        );
    }

    let message: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return McpHttpResponse::json(
                400,
                json_rpc_error(Value::Null, -32700, format!("parse error: {error}")),
            );
        }
    };

    let Some(id) = message.get("id").filter(|id| !id.is_null()).cloned() else {
        return McpHttpResponse::empty(202);
    };

    let reply = handle_driverless_message(&message, handshake_probe_config);
    match reply {
        Ok(result) => McpHttpResponse::json(200, json_rpc_result(id, result)),
        Err(error) => McpHttpResponse::json(200, json_rpc_error(id, error.code, error.message)),
    }
}

/// Origin is optional for non-browser clients; when present, only loopback
/// origins are accepted to block DNS-rebinding attacks.
pub fn origin_allowed(origin: Option<&str>) -> bool {
    origin.map(loopback_origin_allowed).unwrap_or(true)
}

pub fn tools() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            name: "observe",
            description: "Return the current compiled observation.",
            input_schema: object_schema(vec![], &[]),
        },
        ToolDescriptor {
            name: "act",
            description: "Execute one tempo semantic action.",
            input_schema: object_schema(vec![("action", json!({"type": "object"}))], &["action"]),
        },
        ToolDescriptor {
            name: "fork",
            description: "Fork the current page state when the active driver supports it.",
            input_schema: object_schema(vec![], &[]),
        },
        ToolDescriptor {
            name: "extract",
            description: "Extract structured data rooted at a stable node id.",
            input_schema: object_schema(
                vec![
                    ("node_id", json!({"type": "string"})),
                    ("node", json!({"type": "string"})),
                ],
                &[],
            ),
        },
        ToolDescriptor {
            name: "screenshot",
            description: "Capture a PNG screenshot as base64.",
            input_schema: object_schema(vec![("set_of_marks", json!({"type": "boolean"}))], &[]),
        },
        ToolDescriptor {
            name: "handshake",
            description: "Evaluate structured-web probe evidence and lane decision.",
            input_schema: object_schema(
                vec![
                    ("origin", json!({"type": "string"})),
                    ("web_mcp", json!({"type": "boolean"})),
                    ("live_http", json!({"type": "boolean"})),
                    ("responses", json!({"type": "array"})),
                ],
                &[],
            ),
        },
    ]
}

pub fn describe() -> &'static str {
    "tempo MCP server core: initialize/ping/tools/list/tools/call for observe, act, fork, extract, screenshot, and handshake"
}

#[derive(Debug, Error)]
#[error("JSON-RPC {code}: {message}")]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn driver_required(message: impl Into<String>) -> Self {
        Self {
            code: DRIVER_REQUIRED_ERROR_CODE,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ToolCall {
    is_error: bool,
    structured_content: Value,
}

impl ToolCall {
    fn success(value: Value) -> Self {
        Self {
            is_error: false,
            structured_content: value,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            is_error: true,
            structured_content: json!({"error": message.into()}),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ActArgs {
    action: Action,
}

#[derive(Debug, Deserialize)]
struct NodeArgs {
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    node: Option<NodeId>,
}

impl NodeArgs {
    fn node_id(self) -> Result<NodeId, JsonRpcError> {
        self.node
            .or_else(|| self.node_id.map(NodeId))
            .ok_or_else(|| JsonRpcError::invalid_params("extract requires node_id"))
    }
}

#[derive(Debug, Default, Deserialize)]
struct ScreenshotArgs {
    #[serde(default)]
    set_of_marks: bool,
}

#[derive(Debug, Default, Deserialize)]
struct HandshakeArgs {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    web_mcp: Option<bool>,
    #[serde(default)]
    live_http: Option<bool>,
    #[serde(default)]
    responses: Vec<ProbeResponseInput>,
}

#[derive(Debug, Deserialize)]
struct ProbeResponseInput {
    path: String,
    status: u16,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    body: String,
}

impl From<ProbeResponseInput> for ProbeResponse {
    fn from(value: ProbeResponseInput) -> Self {
        let response = ProbeResponse::new(value.path, value.status, value.body);
        match value.content_type {
            Some(content_type) => response.with_content_type(content_type),
            None => response,
        }
    }
}

fn parse_args<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, JsonRpcError> {
    serde_json::from_value(value).map_err(|error| JsonRpcError::invalid_params(error.to_string()))
}

fn probe_http_origin_off_runtime(
    origin: &str,
    config: HttpProbeConfig,
) -> Result<tempo_handshake::HttpProbeRun, String> {
    let origin = origin.to_string();
    match std::thread::spawn(move || probe_http_origin(&origin, config)).join() {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => Err("HTTP probe worker panicked".into()),
    }
}

fn handle_driverless_message(
    message: &Value,
    handshake_probe_config: HttpProbeConfig,
) -> Result<Value, JsonRpcError> {
    if !message.is_object() {
        return Err(JsonRpcError::invalid_request(
            "JSON-RPC message must be an object",
        ));
    }

    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_request("JSON-RPC method is required"))?;
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => Ok(json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tempo", "version": env!("CARGO_PKG_VERSION")},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_descriptor_json()})),
        "tools/call" => driverless_tools_call(&params, handshake_probe_config),
        other => Err(JsonRpcError::method_not_found(format!(
            "method not found: {other}"
        ))),
    }
}

fn driverless_tools_call(
    params: &Value,
    handshake_probe_config: HttpProbeConfig,
) -> Result<Value, JsonRpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_params("tools/call requires params.name"))?;
    if !tools().iter().any(|tool| tool.name == name) {
        return Err(JsonRpcError::invalid_params(format!(
            "unknown tool: {name}"
        )));
    }

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if name != "handshake" {
        return Err(JsonRpcError::driver_required(format!(
            "MCP tool call requires an attached engine driver: {name}"
        )));
    }

    let args: HandshakeArgs = parse_args(arguments)?;
    Ok(tool_call_json(ToolCall::success(handshake_result_json(
        &ProbeReport::new(),
        &handshake_probe_config,
        args,
    ))))
}

fn handshake_result_json(
    handshake_report: &ProbeReport,
    handshake_probe_config: &HttpProbeConfig,
    args: HandshakeArgs,
) -> Value {
    let mut report = ProbeReport::from_hits(handshake_report.hits().to_vec());
    let live_http_requested = args
        .live_http
        .unwrap_or_else(|| args.origin.is_some() && args.responses.is_empty());
    let response_report = ProbeReport::from_responses(args.responses.into_iter().map(Into::into));
    for hit in response_report.hits() {
        report.add_hit(hit.clone());
    }
    report.record_web_mcp(args.web_mcp.unwrap_or(false));

    let mut live_http = false;
    let mut probe_responses = Vec::new();
    let mut probe_failures = Vec::new();
    let mut probe_error = None;
    if live_http_requested {
        if let Some(origin) = args.origin.as_deref() {
            live_http = true;
            match probe_http_origin_off_runtime(origin, handshake_probe_config.clone()) {
                Ok(run) => {
                    for hit in run.report.hits() {
                        report.add_hit(hit.clone());
                    }
                    probe_responses = run
                        .responses
                        .iter()
                        .map(probe_response_json)
                        .collect::<Vec<_>>();
                    probe_failures = run
                        .failures
                        .iter()
                        .map(probe_failure_json)
                        .collect::<Vec<_>>();
                }
                Err(error) => {
                    probe_error = Some(error.to_string());
                }
            }
        }
    }

    let decision = decide_lane(&report);
    json!({
        "lane": handshake_lane_name(decision.lane),
        "skips_render": decision.skips_render(),
        "selected": decision.selected.as_ref().map(probe_hit_json),
        "hits": report.hits().iter().map(probe_hit_json).collect::<Vec<_>>(),
        "probe_urls": args.origin.as_deref().map(probe_urls).unwrap_or_default(),
        "live_http": live_http,
        "probe_responses": probe_responses,
        "probe_failures": probe_failures,
        "probe_error": probe_error,
    })
}

fn json_rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn tool_call_json(call: ToolCall) -> Value {
    let text = call.structured_content.to_string();
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": call.structured_content,
        "isError": call.is_error,
    })
}

fn tool_descriptor_json() -> Vec<Value> {
    tools()
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            })
        })
        .collect()
}

fn agent_card_skill_json(tool: ToolDescriptor) -> Value {
    json!({
        "id": tool.name,
        "name": tool.name,
        "description": tool.description,
        "tags": ["browser", "mcp", "tempo"],
        "inputModes": ["application/json"],
        "outputModes": if tool.name == "screenshot" {
            vec!["application/json", "image/png"]
        } else {
            vec!["application/json"]
        },
    })
}

fn object_schema(properties: Vec<(&'static str, Value)>, required: &[&'static str]) -> Value {
    let required = required
        .iter()
        .map(|name| Value::String((*name).to_string()))
        .collect::<Vec<_>>();
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_string(), schema))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn step_outcome_json(outcome: StepOutcome) -> Value {
    match outcome {
        StepOutcome::Applied { diff } => {
            json!({"status": "applied", "diff": diff})
        }
        StepOutcome::StepError { reason } => {
            json!({"status": "step_error", "reason": reason})
        }
    }
}

fn probe_hit_json(hit: &ProbeHit) -> Value {
    json!({
        "signal": signal_name(hit.signal),
        "source": hit.source,
        "lane": handshake_lane_name(hit.signal.lane()),
    })
}

fn probe_response_json(response: &ProbeResponse) -> Value {
    json!({
        "path": &response.path,
        "status": response.status,
        "content_type": &response.content_type,
        "body_bytes": response.body.len(),
    })
}

fn probe_failure_json(failure: &HttpProbeFailure) -> Value {
    json!({
        "path": &failure.path,
        "url": &failure.url,
        "reason": &failure.reason,
    })
}

fn signal_name(signal: StructuredSignal) -> &'static str {
    match signal {
        StructuredSignal::BeaterJson => "beater_json",
        StructuredSignal::AgentCard => "agent_card",
        StructuredSignal::LlmsTxt => "llms_txt",
        StructuredSignal::OpenApi => "openapi",
        StructuredSignal::McpCatalog => "mcp_catalog",
        StructuredSignal::WebMcp => "web_mcp",
    }
}

fn handshake_lane_name(lane: HandshakeLane) -> &'static str {
    match lane {
        HandshakeLane::Render => "render",
        HandshakeLane::Api => "api",
        HandshakeLane::Mcp => "mcp",
    }
}

fn engine_name(engine: Engine) -> &'static str {
    if engine == Engine::Servo {
        "servo"
    } else if engine == Engine::Cdp {
        "cdp"
    } else {
        "test"
    }
}

fn loopback_origin_allowed(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(addr)) => addr == Ipv6Addr::LOCALHOST,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use base64::Engine as _;
    use serde_json::json;
    use tempo_driver::{TransportError, Unsupported};
    use tempo_net::UrlPolicy;
    use tempo_schema::{
        CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
    };

    use super::*;

    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    const TEST_SCREENSHOT_PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D',
        b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', 0x78, 0x9c, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, b'I',
        b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
    ];

    #[tokio::test]
    async fn initialize_and_tool_list_follow_mcp_shape() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let initialize = server
            .handle_post(None, br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            .await
            .json_value()
            .map_err(|error| error.to_string())?;
        assert_eq!(
            initialize["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );

        let tools = server
            .handle_post(None, br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .await
            .json_value()
            .map_err(|error| error.to_string())?;
        let names = tools["result"]["tools"]
            .as_array()
            .ok_or("tools/list result must be an array")?
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "observe",
                "act",
                "fork",
                "extract",
                "screenshot",
                "handshake"
            ]
        );
        Ok(())
    }

    #[test]
    fn agent_card_advertises_real_mcp_interface_and_tools() -> Result<(), String> {
        let response = agent_card_response("http://127.0.0.1:8787/");
        let card = response.json_value().map_err(|error| error.to_string())?;
        let skills = card["skills"]
            .as_array()
            .ok_or("agent-card skills must be an array")?;

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, A2A_AGENT_CARD_CONTENT_TYPE);
        assert_eq!(card["name"], "tempo");
        assert_eq!(card["url"], "http://127.0.0.1:8787/mcp");
        assert_eq!(card["preferredTransport"], "MCP");
        assert_eq!(
            card["additionalInterfaces"][0]["url"],
            "http://127.0.0.1:8787/mcp"
        );
        assert!(skills.iter().any(|skill| skill["id"] == "observe"));
        assert!(skills.iter().any(|skill| skill["id"] == "handshake"));
        Ok(())
    }

    #[tokio::test]
    async fn observe_act_extract_and_screenshot_call_real_driver_trait() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let observe = call_tool(&mut server, "observe", json!({})).await?;
        assert_eq!(observe["url"], "https://example.test/");

        let act = call_tool(
            &mut server,
            "act",
            json!({"action": {"kind": "click", "node": "button.primary"}}),
        )
        .await?;
        assert_eq!(act["status"], "applied");
        assert_eq!(act["diff"]["seq"], 2);

        let extract =
            call_tool(&mut server, "extract", json!({"node_id": "button.primary"})).await?;
        assert_eq!(extract["node"], "button.primary");

        let screenshot = call_tool(&mut server, "screenshot", json!({})).await?;
        assert_eq!(screenshot["encoding"], "base64");
        assert_eq!(screenshot["set_of_marks"], false);
        let bytes = decode_base64_field(&screenshot, "data")?;
        assert_eq!(bytes, TEST_SCREENSHOT_PNG);
        Ok(())
    }

    #[tokio::test]
    async fn screenshot_tool_can_overlay_set_of_marks() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let raw = call_tool(&mut server, "screenshot", json!({})).await?;
        let marked = call_tool(&mut server, "screenshot", json!({"set_of_marks": true})).await?;

        assert_eq!(marked["mime_type"], "image/png");
        assert_eq!(marked["encoding"], "base64");
        assert_eq!(marked["set_of_marks"], true);
        let raw_bytes = decode_base64_field(&raw, "data")?;
        let marked_bytes = decode_base64_field(&marked, "data")?;
        assert!(marked_bytes.starts_with(PNG_SIGNATURE));
        assert_ne!(marked_bytes, raw_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn fork_reports_driver_support_without_session_side_channel() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let fork = call_tool(&mut server, "fork", json!({})).await?;
        assert_eq!(fork["supported"], true);
        assert_eq!(fork["engine"], "cdp");
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_uses_probe_report_and_lane_decision() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let result = call_tool(
            &mut server,
            "handshake",
            json!({
                "origin": "https://example.test",
                "responses": [{
                    "path": "/mcp/catalog.json",
                    "status": 200,
                    "content_type": "application/json",
                    "body": "{\"tools\":[]}"
                }]
            }),
        )
        .await?;

        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        assert_eq!(
            result["probe_urls"][0],
            "https://example.test/.well-known/beater.json"
        );
        assert_eq!(result["live_http"], false);
        assert!(result["probe_responses"]
            .as_array()
            .ok_or("probe_responses must be an array")?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_runs_live_http_probe_for_origin() -> Result<(), String> {
        let (origin, server) = serve_handshake_fixture().map_err(|error| error.to_string())?;
        let mut server_under_test = TempoMcpServer::new(MemoryDriver::new())
            .with_handshake_probe_config(
                HttpProbeConfig::default().with_url_policy(UrlPolicy::allow_all()),
            );

        let result = call_tool(
            &mut server_under_test,
            "handshake",
            json!({"origin": origin}),
        )
        .await?;
        join_server(server)?;

        assert_eq!(result["live_http"], true);
        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        assert_eq!(
            result["probe_responses"]
                .as_array()
                .ok_or("probe_responses must be an array")?
                .len(),
            tempo_handshake::DEFAULT_HTTP_PROBES.len()
        );
        assert!(result["probe_failures"]
            .as_array()
            .ok_or("probe_failures must be an array")?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_reports_url_policy_failures() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let result = call_tool(
            &mut server,
            "handshake",
            json!({"origin": "http://127.0.0.1:9"}),
        )
        .await?;

        assert_eq!(result["live_http"], true);
        assert_eq!(result["lane"], "render");
        assert!(result["probe_responses"]
            .as_array()
            .ok_or("probe_responses must be an array")?
            .is_empty());
        let failures = result["probe_failures"]
            .as_array()
            .ok_or("probe_failures must be an array")?;
        assert_eq!(failures.len(), tempo_handshake::DEFAULT_HTTP_PROBES.len());
        assert!(failures.iter().all(|failure| failure["reason"]
            .as_str()
            .map(|reason| reason.contains("URL blocked"))
            .unwrap_or(false)));
        Ok(())
    }

    #[test]
    fn driverless_mcp_serves_metadata_and_handshake_without_engine() -> Result<(), String> {
        let tools =
            handle_post_driverless(None, br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
                .json_value()
                .map_err(|error| error.to_string())?;
        assert_eq!(tools["result"]["tools"][0]["name"], "observe");

        let handshake = handle_post_driverless(
            None,
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"handshake","arguments":{"origin":"https://example.test","responses":[{"path":"/openapi.json","status":200,"content_type":"application/json","body":"{\"openapi\":\"3.1.0\"}"}]}}}"#,
        )
        .json_value()
        .map_err(|error| error.to_string())?;
        let result = &handshake["result"]["structuredContent"];
        assert_eq!(result["lane"], "api");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "openapi");

        let observe = handle_post_driverless(
            None,
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#,
        )
        .json_value()
        .map_err(|error| error.to_string())?;
        assert_eq!(observe["error"]["code"], DRIVER_REQUIRED_ERROR_CODE);
        assert!(observe["error"]["message"]
            .as_str()
            .ok_or("missing driver-required message")?
            .contains("attached engine driver"));
        Ok(())
    }

    #[tokio::test]
    async fn protocol_errors_and_notifications_have_http_semantics() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let malformed = server.handle_post(None, b"{not-json").await;
        assert_eq!(malformed.status, 400);
        assert_eq!(
            malformed.json_value().map_err(|error| error.to_string())?["error"]["code"],
            -32700
        );

        let notification = server
            .handle_post(None, br#"{"jsonrpc":"2.0","method":"ping"}"#)
            .await;
        assert_eq!(notification.status, 202);
        assert!(notification.body.is_empty());

        let get = handle_get();
        assert_eq!(get.status, 405);
        assert_eq!(get.content_type, "text/plain; charset=utf-8");
        Ok(())
    }

    #[test]
    fn origin_validation_accepts_only_loopback_origins() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://localhost")));
        assert!(origin_allowed(Some("https://localhost:3000")));
        assert!(origin_allowed(Some("http://127.0.0.1:5173")));
        assert!(origin_allowed(Some("http://[::1]:3000")));

        for origin in [
            "http://localhost.evil.test",
            "http://127.0.0.1.evil.test",
            "https://example.test",
            "file:///tmp/page.html",
            "http://user@localhost",
            "http://localhost/path",
            "null",
        ] {
            assert!(!origin_allowed(Some(origin)), "{origin}");
        }
    }

    async fn call_tool(
        server: &mut TempoMcpServer<MemoryDriver>,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        });
        let response = server.handle_post(None, body.to_string().as_bytes()).await;
        let value = response.json_value().map_err(|error| error.to_string())?;
        if value.get("error").is_some() {
            return Err(value.to_string());
        }
        Ok(value["result"]["structuredContent"].clone())
    }

    fn decode_base64_field(value: &Value, field: &str) -> Result<Vec<u8>, String> {
        let encoded = value[field]
            .as_str()
            .ok_or_else(|| format!("{field} must be a string"))?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| error.to_string())
    }

    fn serve_handshake_fixture(
    ) -> Result<(String, thread::JoinHandle<Result<(), io::Error>>), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut handled = 0;
            while handled < tempo_handshake::DEFAULT_HTTP_PROBES.len() {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        handle_probe_stream(stream)?;
                        handled += 1;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "timed out waiting for live handshake probes",
                            ));
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok((format!("http://{addr}"), handle))
    }

    fn handle_probe_stream(mut stream: TcpStream) -> Result<(), io::Error> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
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
            "/llms.txt" => ("200 OK", "text/plain", "# Fixture"),
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

    fn join_server(handle: thread::JoinHandle<Result<(), io::Error>>) -> Result<(), String> {
        match handle.join() {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("fixture server panicked".into()),
        }
    }

    #[derive(Clone)]
    struct MemoryDriver {
        observation: CompiledObservation,
    }

    impl MemoryDriver {
        fn new() -> Self {
            Self {
                observation: CompiledObservation {
                    schema_version: tempo_schema::SCHEMA_VERSION.into(),
                    url: "https://example.test/".into(),
                    seq: 1,
                    elements: vec![InteractiveElement {
                        node_id: NodeId("button.primary".into()),
                        role: "button".into(),
                        name: vec![TaintSpan {
                            provenance: Provenance::Page,
                            text: "Continue".into(),
                        }],
                        value: Vec::new(),
                        bounds: Some([0.0, 0.0, 120.0, 32.0]),
                        rank: 1.0,
                    }],
                    marks: vec![(NodeId("button.primary".into()), 1)],
                },
            }
        }
    }

    #[async_trait]
    impl DriverTrait for MemoryDriver {
        fn engine(&self) -> Engine {
            Engine::Cdp
        }

        async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
            self.observation.url = url.to_string();
            self.observation.seq += 1;
            Ok(self.observation.clone())
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            Ok(self.observation.clone())
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            Ok(ObservationDiff {
                since_seq,
                seq: self.observation.seq,
                added: Vec::new(),
                removed: Vec::new(),
                changed: self.observation.elements.clone(),
            })
        }

        async fn act(&mut self, _action: &Action) -> Result<StepOutcome, TransportError> {
            self.observation.seq += 1;
            Ok(StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.observation.seq - 1,
                    seq: self.observation.seq,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: self.observation.elements.clone(),
                },
            })
        }

        async fn act_batch(
            &mut self,
            _batch: &tempo_schema::ActionBatch,
        ) -> Result<StepOutcome, TransportError> {
            self.act(&Action::Scroll { x: 0.0, y: 0.0 }).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Ok(Box::new(self.clone()))
        }

        async fn extract(&mut self, node: &NodeId) -> Result<Value, TransportError> {
            Ok(json!({"node": node.0, "text": "Continue"}))
        }

        async fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<Value, TransportError> {
            Ok(json!({
                "expression": expression,
                "awaitPromise": await_promise,
            }))
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(TEST_SCREENSHOT_PNG.to_vec())
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }
}
