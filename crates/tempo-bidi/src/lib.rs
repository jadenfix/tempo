//! tempo-bidi — WebDriver BiDi subset mapped onto tempo driver operations.
//!
//! The transport layer can be WebSocket, UDS, or HTTP upgrade. This crate owns
//! the protocol contract: parse BiDi commands, route engine-backed operations,
//! and emit standard success, error, and event envelopes.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempo_schema::Action;
use thiserror::Error;

/// A WebDriver BiDi command id.
pub type CommandId = u64;

/// Browser context identifier used by the BiDi browsingContext domain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BrowsingContextId(pub String);

/// Network request identifier used by BiDi network events.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequestId(pub String);

/// Parsed client command envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BidiCommand {
    pub id: CommandId,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Server-to-client WebDriver BiDi message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BidiMessage {
    Success {
        id: CommandId,
        result: Value,
    },
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<CommandId>,
        error: String,
        message: String,
    },
    Event {
        method: String,
        params: Value,
    },
}

impl BidiMessage {
    pub fn success(id: CommandId, result: impl Serialize) -> Result<Self, BidiProtocolError> {
        Ok(Self::Success {
            id,
            result: serde_json::to_value(result)?,
        })
    }

    pub fn error(id: Option<CommandId>, error: BidiErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            id,
            error: error.as_str().into(),
            message: message.into(),
        }
    }

    pub fn event(
        method: BidiEventMethod,
        params: impl Serialize,
    ) -> Result<Self, BidiProtocolError> {
        Ok(Self::Event {
            method: method.as_str().into(),
            params: serde_json::to_value(params)?,
        })
    }

    pub fn to_json_string(&self) -> Result<String, BidiProtocolError> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Result of routing a command.
#[derive(Clone, Debug, PartialEq)]
pub enum RoutedCommand {
    Immediate(BidiMessage),
    Driver {
        id: CommandId,
        command: DriverCommand,
    },
}

/// Engine-backed work produced by BiDi routing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DriverCommand {
    CreateContext(CreateContextParameters),
    GetTree(GetTreeParameters),
    Navigate(NavigateCommand),
    CaptureScreenshot(CaptureScreenshotParameters),
    EvaluateScript(ScriptEvaluateParameters),
}

/// Navigation request mapped to tempo's semantic action space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NavigateCommand {
    pub context: BrowsingContextId,
    pub url: String,
    pub wait: ReadinessState,
    pub action: Action,
}

/// Minimal endpoint state for the session domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BidiRouter {
    ready: bool,
    next_session: u64,
}

impl BidiRouter {
    pub fn new() -> Self {
        Self {
            ready: true,
            next_session: 1,
        }
    }

    pub fn route_json(
        &mut self,
        raw: impl AsRef<[u8]>,
    ) -> Result<RoutedCommand, BidiProtocolError> {
        let command: BidiCommand = serde_json::from_slice(raw.as_ref())?;
        self.route(command)
    }

    pub fn route(&mut self, command: BidiCommand) -> Result<RoutedCommand, BidiProtocolError> {
        match command.method.as_str() {
            "session.status" => self.session_status(command.id),
            "session.new" => self.session_new(command.id, command.params),
            "session.end" => self.session_end(command.id),
            "browsingContext.create" => {
                let params = parse_params(command.params)?;
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::CreateContext(params),
                })
            }
            "browsingContext.getTree" => {
                let params = parse_params(command.params)?;
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::GetTree(params),
                })
            }
            "browsingContext.navigate" => {
                let params: NavigateParameters = parse_params(command.params)?;
                if params.url.trim().is_empty() {
                    return Ok(RoutedCommand::Immediate(BidiMessage::error(
                        Some(command.id),
                        BidiErrorCode::InvalidArgument,
                        "browsingContext.navigate requires a non-empty url",
                    )));
                }
                let action = Action::Goto {
                    url: params.url.clone(),
                };
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::Navigate(NavigateCommand {
                        context: params.context,
                        url: params.url,
                        wait: params.wait,
                        action,
                    }),
                })
            }
            "browsingContext.captureScreenshot" => {
                let params = parse_params(command.params)?;
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::CaptureScreenshot(params),
                })
            }
            "script.evaluate" => {
                let params = parse_params(command.params)?;
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::EvaluateScript(params),
                })
            }
            _ => Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(command.id),
                BidiErrorCode::UnknownCommand,
                format!("unsupported BiDi method: {}", command.method),
            ))),
        }
    }

    pub fn driver_success(
        id: CommandId,
        result: impl Serialize,
    ) -> Result<BidiMessage, BidiProtocolError> {
        BidiMessage::success(id, result)
    }

    fn session_status(&self, id: CommandId) -> Result<RoutedCommand, BidiProtocolError> {
        Ok(RoutedCommand::Immediate(BidiMessage::success(
            id,
            SessionStatusResult {
                ready: self.ready,
                message: if self.ready {
                    "tempo BiDi endpoint is ready".into()
                } else {
                    "tempo BiDi endpoint is draining".into()
                },
            },
        )?))
    }

    fn session_new(
        &mut self,
        id: CommandId,
        params: Value,
    ) -> Result<RoutedCommand, BidiProtocolError> {
        let params: SessionNewParameters = parse_params(params)?;
        let session_id = format!("tempo-bidi-{}", self.next_session);
        self.next_session = self.next_session.saturating_add(1);
        Ok(RoutedCommand::Immediate(BidiMessage::success(
            id,
            SessionNewResult {
                session_id,
                capabilities: params.capabilities.unwrap_or_else(|| json!({})),
            },
        )?))
    }

    fn session_end(&mut self, id: CommandId) -> Result<RoutedCommand, BidiProtocolError> {
        self.ready = false;
        Ok(RoutedCommand::Immediate(BidiMessage::success(
            id,
            json!({}),
        )?))
    }
}

impl Default for BidiRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// session.status result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatusResult {
    pub ready: bool,
    pub message: String,
}

/// session.new parameters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionNewParameters {
    #[serde(default)]
    pub capabilities: Option<Value>,
}

/// session.new result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionNewResult {
    pub session_id: String,
    pub capabilities: Value,
}

/// browsingContext.create context type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextType {
    Tab,
    Window,
}

/// browsingContext.create parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateContextParameters {
    #[serde(rename = "type")]
    pub context_type: ContextType,
    #[serde(default)]
    pub reference_context: Option<BrowsingContextId>,
    #[serde(default)]
    pub background: bool,
}

/// browsingContext.create result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateContextResult {
    pub context: BrowsingContextId,
}

/// browsingContext.getTree parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTreeParameters {
    #[serde(default)]
    pub root: Option<BrowsingContextId>,
    #[serde(default)]
    pub max_depth: Option<u32>,
}

/// browsingContext.getTree result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTreeResult {
    pub contexts: Vec<BrowsingContextInfo>,
}

/// One browsing context tree node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowsingContextInfo {
    pub context: BrowsingContextId,
    pub url: String,
    pub children: Vec<BrowsingContextInfo>,
}

/// Readiness target for navigation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessState {
    None,
    Interactive,
    #[default]
    Complete,
}

/// browsingContext.navigate parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigateParameters {
    pub context: BrowsingContextId,
    pub url: String,
    #[serde(default)]
    pub wait: ReadinessState,
}

/// browsingContext.navigate result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigateResult {
    pub navigation: Option<String>,
    pub url: String,
}

/// browsingContext.captureScreenshot parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureScreenshotParameters {
    pub context: BrowsingContextId,
    #[serde(default)]
    pub origin: ScreenshotOrigin,
}

/// Screenshot coordinate origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenshotOrigin {
    #[default]
    Viewport,
    Document,
}

/// browsingContext.captureScreenshot result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureScreenshotResult {
    pub data: String,
}

/// script.evaluate target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptTarget {
    pub context: BrowsingContextId,
}

/// script.evaluate parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptEvaluateParameters {
    pub expression: String,
    pub target: ScriptTarget,
    #[serde(default)]
    pub await_promise: bool,
    #[serde(default)]
    pub result_ownership: ResultOwnership,
}

/// Script result ownership.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultOwnership {
    #[default]
    None,
    Root,
}

/// script.evaluate result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptEvaluateResult {
    pub result: Value,
    #[serde(default)]
    pub realm: Option<String>,
}

/// HTTP header representation used by network events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// BiDi network request payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {
    pub request: RequestId,
    pub url: String,
    pub method: String,
    pub headers: Vec<Header>,
    pub body_size: u64,
}

/// BiDi network response payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    pub request: RequestId,
    pub url: String,
    pub status: u16,
    pub headers: Vec<Header>,
    pub body_size: u64,
}

/// Supported event methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BidiEventMethod {
    BrowsingContextLoad,
    NetworkBeforeRequestSent,
    NetworkResponseCompleted,
}

impl BidiEventMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BrowsingContextLoad => "browsingContext.load",
            Self::NetworkBeforeRequestSent => "network.beforeRequestSent",
            Self::NetworkResponseCompleted => "network.responseCompleted",
        }
    }
}

/// Emit a browsingContext.load event.
pub fn browsing_context_load(
    context: BrowsingContextId,
    url: impl Into<String>,
) -> Result<BidiMessage, BidiProtocolError> {
    BidiMessage::event(
        BidiEventMethod::BrowsingContextLoad,
        json!({
            "context": context,
            "url": url.into(),
        }),
    )
}

/// Emit a network.beforeRequestSent event.
pub fn network_before_request_sent(
    request: NetworkRequest,
) -> Result<BidiMessage, BidiProtocolError> {
    BidiMessage::event(BidiEventMethod::NetworkBeforeRequestSent, request)
}

/// Emit a network.responseCompleted event.
pub fn network_response_completed(
    response: NetworkResponse,
) -> Result<BidiMessage, BidiProtocolError> {
    BidiMessage::event(BidiEventMethod::NetworkResponseCompleted, response)
}

/// Standard BiDi error code subset used by this endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BidiErrorCode {
    InvalidArgument,
    UnknownCommand,
    UnknownError,
}

impl BidiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::UnknownCommand => "unknown command",
            Self::UnknownError => "unknown error",
        }
    }
}

#[derive(Debug, Error)]
pub enum BidiProtocolError {
    #[error("BiDi JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "WebDriver BiDi command routing and event envelopes for tempo driver operations"
}

fn parse_params<T>(params: Value) -> Result<T, BidiProtocolError>
where
    T: for<'de> Deserialize<'de>,
{
    let params = if params.is_null() { json!({}) } else { params };
    Ok(serde_json::from_value(params)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn session_status_returns_standard_success_message() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(br#"{"id":1,"method":"session.status","params":{}}"#)?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Success {
                id: 1,
                result: json!({
                    "ready": true,
                    "message": "tempo BiDi endpoint is ready",
                }),
            })
        );
        Ok(())
    }

    #[test]
    fn session_new_preserves_requested_capabilities() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":2,"method":"session.new","params":{"capabilities":{"acceptInsecureCerts":false}}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Success {
                id: 2,
                result: json!({
                    "sessionId": "tempo-bidi-1",
                    "capabilities": {
                        "acceptInsecureCerts": false,
                    },
                }),
            })
        );
        Ok(())
    }

    #[test]
    fn navigate_maps_to_goto_driver_action() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"ctx-1","url":"https://example.test","wait":"interactive"}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Driver {
                id: 7,
                command: DriverCommand::Navigate(NavigateCommand {
                    context: BrowsingContextId("ctx-1".into()),
                    url: "https://example.test".into(),
                    wait: ReadinessState::Interactive,
                    action: Action::Goto {
                        url: "https://example.test".into(),
                    },
                }),
            }
        );
        Ok(())
    }

    #[test]
    fn script_evaluate_routes_to_engine_command() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":8,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"ctx-1"},"awaitPromise":true,"resultOwnership":"root"}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Driver {
                id: 8,
                command: DriverCommand::EvaluateScript(ScriptEvaluateParameters {
                    expression: "document.title".into(),
                    target: ScriptTarget {
                        context: BrowsingContextId("ctx-1".into()),
                    },
                    await_promise: true,
                    result_ownership: ResultOwnership::Root,
                }),
            }
        );
        Ok(())
    }

    #[test]
    fn invalid_navigation_returns_bidi_error_envelope() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":9,"method":"browsingContext.navigate","params":{"context":"ctx-1","url":" "}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Error {
                id: Some(9),
                error: "invalid argument".into(),
                message: "browsingContext.navigate requires a non-empty url".into(),
            })
        );
        Ok(())
    }

    #[test]
    fn unknown_method_returns_bidi_error_envelope() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(br#"{"id":10,"method":"tempo.private","params":{}}"#)?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Error {
                id: Some(10),
                error: "unknown command".into(),
                message: "unsupported BiDi method: tempo.private".into(),
            })
        );
        Ok(())
    }

    #[test]
    fn network_response_completed_serializes_as_standard_event() -> TestResult {
        let event = network_response_completed(NetworkResponse {
            request: RequestId("request-1".into()),
            url: "https://example.test/data".into(),
            status: 200,
            headers: vec![Header {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body_size: 17,
        })?;

        assert_eq!(
            serde_json::to_value(event)?,
            json!({
                "type": "event",
                "method": "network.responseCompleted",
                "params": {
                    "request": "request-1",
                    "url": "https://example.test/data",
                    "status": 200,
                    "headers": [
                        {"name": "content-type", "value": "application/json"}
                    ],
                    "bodySize": 17,
                }
            })
        );
        Ok(())
    }

    #[test]
    fn driver_success_encodes_result_envelope() -> TestResult {
        let message = BidiRouter::driver_success(
            11,
            NavigateResult {
                navigation: Some("nav-1".into()),
                url: "https://example.test".into(),
            },
        )?;

        assert_eq!(
            message.to_json_string()?,
            r#"{"type":"success","id":11,"result":{"navigation":"nav-1","url":"https://example.test"}}"#
        );
        Ok(())
    }
}
