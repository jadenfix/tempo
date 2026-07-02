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
    decide_lane, probe_urls, Lane as HandshakeLane, ProbeHit, ProbeReport, ProbeResponse,
    StructuredSignal,
};
use tempo_schema::{Action, NodeId};
use thiserror::Error;
use url::{Host, Url};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

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
}

impl<D> TempoMcpServer<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            handshake_report: ProbeReport::new(),
        }
    }

    pub fn with_handshake_report(mut self, report: ProbeReport) -> Self {
        self.handshake_report = report;
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
            "screenshot" => match self.driver.screenshot().await {
                Ok(bytes) => Ok(ToolCall::success(json!({
                    "mime_type": "image/png",
                    "encoding": "base64",
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                }))),
                Err(error) => Ok(ToolCall::error(error.to_string())),
            },
            "handshake" => {
                let args: HandshakeArgs = parse_args(arguments)?;
                Ok(ToolCall::success(self.handshake_json(args)))
            }
            _ => Err(JsonRpcError::invalid_params("unknown tool")),
        }
    }

    fn handshake_json(&self, args: HandshakeArgs) -> Value {
        let mut report = ProbeReport::from_hits(self.handshake_report.hits().to_vec());
        let response_report =
            ProbeReport::from_responses(args.responses.into_iter().map(Into::into));
        for hit in response_report.hits() {
            report.add_hit(hit.clone());
        }
        report.record_web_mcp(args.web_mcp.unwrap_or(false));

        let decision = decide_lane(&report);
        json!({
            "lane": handshake_lane_name(decision.lane),
            "skips_render": decision.skips_render(),
            "selected": decision.selected.as_ref().map(probe_hit_json),
            "hits": report.hits().iter().map(probe_hit_json).collect::<Vec<_>>(),
            "probe_urls": args.origin.as_deref().map(probe_urls).unwrap_or_default(),
        })
    }
}

pub fn handle_get() -> McpHttpResponse {
    McpHttpResponse::text(
        405,
        "this MCP endpoint does not offer a server-initiated stream",
    )
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
            input_schema: object_schema(vec![], &[]),
        },
        ToolDescriptor {
            name: "handshake",
            description: "Evaluate structured-web probe evidence and lane decision.",
            input_schema: object_schema(
                vec![
                    ("origin", json!({"type": "string"})),
                    ("web_mcp", json!({"type": "boolean"})),
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
struct HandshakeArgs {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    web_mcp: Option<bool>,
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
    use async_trait::async_trait;
    use serde_json::json;
    use tempo_driver::{TransportError, Unsupported};
    use tempo_schema::{
        CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
    };

    use super::*;

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
        assert_eq!(screenshot["data"], "iVBORw==");
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
            Ok(vec![137, 80, 78, 71])
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }
}
