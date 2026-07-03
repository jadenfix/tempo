//! tempo-bidi — WebDriver BiDi subset mapped onto tempo driver operations.
//!
//! The transport layer can be WebSocket, UDS, or HTTP upgrade. This crate owns
//! the protocol contract: parse BiDi commands, route engine-backed operations,
//! and emit standard success, error, and event envelopes.

use std::collections::{BTreeMap, BTreeSet};

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

/// WebDriver BiDi session subscription identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionSubscription(pub String);

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
    Close(CloseParameters),
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
    pub input_tainted: Option<bool>,
    pub confirmed: bool,
}

/// Minimal endpoint state for the session domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BidiRouter {
    ready: bool,
    next_session: u64,
    next_subscription: u64,
    subscriptions: BTreeMap<SessionSubscription, BidiSubscription>,
}

impl BidiRouter {
    pub fn new() -> Self {
        Self {
            ready: true,
            next_session: 1,
            next_subscription: 1,
            subscriptions: BTreeMap::new(),
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
            "session.subscribe" => self.session_subscribe(command.id, command.params),
            "session.unsubscribe" => self.session_unsubscribe(command.id, command.params),
            "browsingContext.create" => {
                let params = match parse_command_params(command.id, command.params) {
                    Ok(params) => params,
                    Err(routed) => return Ok(routed),
                };
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::CreateContext(params),
                })
            }
            "browsingContext.close" => {
                let params = match parse_command_params(command.id, command.params) {
                    Ok(params) => params,
                    Err(routed) => return Ok(routed),
                };
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::Close(params),
                })
            }
            "browsingContext.getTree" => {
                let params = match parse_command_params(command.id, command.params) {
                    Ok(params) => params,
                    Err(routed) => return Ok(routed),
                };
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::GetTree(params),
                })
            }
            "browsingContext.navigate" => {
                let params: NavigateParameters =
                    match parse_command_params(command.id, command.params) {
                        Ok(params) => params,
                        Err(routed) => return Ok(routed),
                    };
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
                        input_tainted: params.input_tainted,
                        confirmed: params.confirmed,
                    }),
                })
            }
            "browsingContext.captureScreenshot" => {
                let params = match parse_command_params(command.id, command.params) {
                    Ok(params) => params,
                    Err(routed) => return Ok(routed),
                };
                Ok(RoutedCommand::Driver {
                    id: command.id,
                    command: DriverCommand::CaptureScreenshot(params),
                })
            }
            "script.evaluate" => {
                let params = match parse_command_params(command.id, command.params) {
                    Ok(params) => params,
                    Err(routed) => return Ok(routed),
                };
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

    pub fn event_subscribed(
        &self,
        event: BidiEventMethod,
        context: Option<&BrowsingContextId>,
    ) -> bool {
        self.subscriptions
            .values()
            .any(|subscription| subscription.matches(event.as_str(), context))
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
        let params: SessionNewParameters = match parse_command_params(id, params) {
            Ok(params) => params,
            Err(routed) => return Ok(routed),
        };
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

    fn session_subscribe(
        &mut self,
        id: CommandId,
        params: Value,
    ) -> Result<RoutedCommand, BidiProtocolError> {
        let params: SessionSubscribeParameters = match parse_command_params(id, params) {
            Ok(params) => params,
            Err(routed) => return Ok(routed),
        };
        let event_names = match expand_event_names(&params.events, "session.subscribe") {
            Ok(event_names) => event_names,
            Err(message) => {
                return Ok(RoutedCommand::Immediate(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::InvalidArgument,
                    message,
                )));
            }
        };
        if !params.contexts.is_empty() && !params.user_contexts.is_empty() {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "session.subscribe accepts either contexts or userContexts, not both",
            )));
        }
        if !params.user_contexts.is_empty() {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "tempo BiDi endpoint has no browser user contexts",
            )));
        }

        let subscription =
            SessionSubscription(format!("tempo-subscription-{}", self.next_subscription));
        let Some(next_subscription) = self.next_subscription.checked_add(1) else {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "BiDi subscription id counter exhausted",
            )));
        };
        self.next_subscription = next_subscription;
        self.subscriptions.insert(
            subscription.clone(),
            BidiSubscription {
                event_names,
                contexts: params.contexts,
            },
        );

        Ok(RoutedCommand::Immediate(BidiMessage::success(
            id,
            SessionSubscribeResult { subscription },
        )?))
    }

    fn session_unsubscribe(
        &mut self,
        id: CommandId,
        params: Value,
    ) -> Result<RoutedCommand, BidiProtocolError> {
        let params: SessionUnsubscribeParameters = match parse_command_params(id, params) {
            Ok(params) => params,
            Err(routed) => return Ok(routed),
        };
        if params.subscriptions.is_some() && params.events.is_some() {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "session.unsubscribe accepts either subscriptions or events, not both",
            )));
        }

        if let Some(subscriptions) = params.subscriptions {
            if subscriptions.is_empty() {
                return Ok(RoutedCommand::Immediate(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::InvalidArgument,
                    "session.unsubscribe requires at least one subscription id",
                )));
            }
            let unknown = subscriptions
                .iter()
                .filter(|subscription| !self.subscriptions.contains_key(*subscription))
                .map(|subscription| subscription.0.as_str())
                .collect::<Vec<_>>();
            if !unknown.is_empty() {
                return Ok(RoutedCommand::Immediate(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::InvalidArgument,
                    format!("unknown BiDi subscription id: {}", unknown.join(", ")),
                )));
            }
            for subscription in subscriptions {
                self.subscriptions.remove(&subscription);
            }
            return Ok(RoutedCommand::Immediate(BidiMessage::success(
                id,
                json!({}),
            )?));
        }

        let Some(events) = params.events else {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "session.unsubscribe requires subscriptions or events",
            )));
        };
        let event_names = match expand_event_names(&events, "session.unsubscribe") {
            Ok(event_names) => event_names,
            Err(message) => {
                return Ok(RoutedCommand::Immediate(BidiMessage::error(
                    Some(id),
                    BidiErrorCode::InvalidArgument,
                    message,
                )));
            }
        };

        let mut updated = self.subscriptions.clone();
        let mut matched = BTreeSet::new();
        let mut empty_subscriptions = Vec::new();
        for (subscription_id, subscription) in &mut updated {
            if !subscription.is_global() {
                continue;
            }
            for event_name in &event_names {
                if subscription.event_names.remove(event_name) {
                    matched.insert(event_name.clone());
                }
            }
            if subscription.event_names.is_empty() {
                empty_subscriptions.push(subscription_id.clone());
            }
        }
        if matched != event_names {
            return Ok(RoutedCommand::Immediate(BidiMessage::error(
                Some(id),
                BidiErrorCode::InvalidArgument,
                "session.unsubscribe events do not match an active global subscription",
            )));
        }
        for subscription_id in empty_subscriptions {
            updated.remove(&subscription_id);
        }
        self.subscriptions = updated;

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

/// session.subscribe parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSubscribeParameters {
    pub events: Vec<String>,
    #[serde(default)]
    pub contexts: Vec<BrowsingContextId>,
    #[serde(default)]
    pub user_contexts: Vec<String>,
}

/// session.subscribe result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSubscribeResult {
    pub subscription: SessionSubscription,
}

/// session.unsubscribe parameters. The spec accepts either subscription ids or
/// global event attributes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUnsubscribeParameters {
    #[serde(default)]
    pub subscriptions: Option<Vec<SessionSubscription>>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
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

/// browsingContext.close parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseParameters {
    pub context: BrowsingContextId,
    #[serde(default)]
    pub prompt_unload: bool,
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
    #[serde(default, rename = "inputTainted", alias = "input_tainted")]
    pub input_tainted: Option<bool>,
    #[serde(default)]
    pub confirmed: bool,
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
    #[serde(default, alias = "input_tainted")]
    pub input_tainted: Option<bool>,
    #[serde(default)]
    pub confirmed: bool,
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

impl NetworkRequest {
    pub fn from_tempo_request(request: &tempo_net::NetworkRequest) -> Self {
        Self {
            request: RequestId(request.id.0.clone()),
            url: request.url.clone(),
            method: request.method.to_ascii_uppercase(),
            headers: headers_from_iter(request.headers()),
            body_size: request.body_size(),
        }
    }
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

impl NetworkResponse {
    pub fn from_tempo_response(response: &tempo_net::NetworkResponseRecord) -> Self {
        Self {
            request: RequestId(response.request_id.0.clone()),
            url: response.url.clone(),
            status: response.status,
            headers: headers_from_iter(response.headers()),
            body_size: response.body_size(),
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct BidiSubscription {
    event_names: BTreeSet<String>,
    contexts: Vec<BrowsingContextId>,
}

impl BidiSubscription {
    fn is_global(&self) -> bool {
        self.contexts.is_empty()
    }

    fn matches(&self, event_name: &str, context: Option<&BrowsingContextId>) -> bool {
        if !self.event_names.contains(event_name) {
            return false;
        }
        if self.contexts.is_empty() {
            return true;
        }
        context
            .map(|context| self.contexts.iter().any(|entry| entry == context))
            .unwrap_or(false)
    }
}

fn headers_from_iter<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<Header> {
    headers
        .map(|(name, value)| Header {
            name: name.into(),
            value: value.into(),
        })
        .collect()
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

/// Build an `invalid argument` error envelope that preserves the command id, so
/// a structurally invalid `params` never bubbles a transport-level Rust error
/// and loses id correlation (issue #102).
fn invalid_params_error(id: CommandId, error: impl std::fmt::Display) -> RoutedCommand {
    RoutedCommand::Immediate(BidiMessage::error(
        Some(id),
        BidiErrorCode::InvalidArgument,
        format!("invalid parameters: {error}"),
    ))
}

/// Parse command params, converting a parse failure into an `invalid argument`
/// BiDi error response (correlated to `id`) rather than a `BidiProtocolError`.
fn parse_command_params<T>(id: CommandId, params: Value) -> Result<T, RoutedCommand>
where
    T: for<'de> Deserialize<'de>,
{
    parse_params(params).map_err(|error| invalid_params_error(id, error))
}

fn expand_event_names(events: &[String], command: &str) -> Result<BTreeSet<String>, String> {
    if events.is_empty() {
        return Err(format!("{command} requires at least one event"));
    }

    let mut expanded = BTreeSet::new();
    for event in events {
        match event.as_str() {
            "browsingContext" => {
                expanded.insert(BidiEventMethod::BrowsingContextLoad.as_str().to_string());
            }
            "network" => {
                expanded.insert(
                    BidiEventMethod::NetworkBeforeRequestSent
                        .as_str()
                        .to_string(),
                );
                expanded.insert(
                    BidiEventMethod::NetworkResponseCompleted
                        .as_str()
                        .to_string(),
                );
            }
            "browsingContext.load" | "network.beforeRequestSent" | "network.responseCompleted" => {
                expanded.insert(event.clone());
            }
            _ => return Err(format!("unsupported BiDi event: {event}")),
        }
    }
    Ok(expanded)
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
    fn session_subscribe_tracks_supported_event_modules() -> TestResult {
        let mut router = BidiRouter::new();
        let context = BrowsingContextId("ctx-1".into());

        let routed = router.route_json(
            br#"{"id":3,"method":"session.subscribe","params":{"events":["network","browsingContext.load"],"contexts":["ctx-1"]}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Success {
                id: 3,
                result: json!({"subscription": "tempo-subscription-1"}),
            })
        );
        assert!(router.event_subscribed(BidiEventMethod::NetworkBeforeRequestSent, Some(&context)));
        assert!(router.event_subscribed(BidiEventMethod::NetworkResponseCompleted, Some(&context)));
        assert!(router.event_subscribed(BidiEventMethod::BrowsingContextLoad, Some(&context)));
        assert!(!router.event_subscribed(
            BidiEventMethod::NetworkBeforeRequestSent,
            Some(&BrowsingContextId("ctx-2".into()))
        ));
        Ok(())
    }

    #[test]
    fn session_unsubscribe_by_subscription_id_removes_events() -> TestResult {
        let mut router = BidiRouter::new();
        let context = BrowsingContextId("ctx-1".into());

        router.route_json(
            br#"{"id":3,"method":"session.subscribe","params":{"events":["network.beforeRequestSent"],"contexts":["ctx-1"]}}"#,
        )?;
        let routed = router.route_json(
            br#"{"id":4,"method":"session.unsubscribe","params":{"subscriptions":["tempo-subscription-1"]}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Success {
                id: 4,
                result: json!({}),
            })
        );
        assert!(!router.event_subscribed(BidiEventMethod::NetworkBeforeRequestSent, Some(&context)));
        Ok(())
    }

    #[test]
    fn session_unsubscribe_by_event_removes_global_subscription() -> TestResult {
        let mut router = BidiRouter::new();

        router.route_json(
            br#"{"id":3,"method":"session.subscribe","params":{"events":["network"]}}"#,
        )?;
        let routed = router.route_json(
            br#"{"id":4,"method":"session.unsubscribe","params":{"events":["network.beforeRequestSent"]}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Success {
                id: 4,
                result: json!({}),
            })
        );
        assert!(!router.event_subscribed(BidiEventMethod::NetworkBeforeRequestSent, None));
        assert!(router.event_subscribed(BidiEventMethod::NetworkResponseCompleted, None));
        Ok(())
    }

    #[test]
    fn session_subscribe_rejects_unknown_events() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":5,"method":"session.subscribe","params":{"events":["script.message"]}}"#,
        )?;

        assert_eq!(
            routed,
            RoutedCommand::Immediate(BidiMessage::Error {
                id: Some(5),
                error: "invalid argument".into(),
                message: "unsupported BiDi event: script.message".into(),
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
                    input_tainted: None,
                    confirmed: false,
                }),
            }
        );
        Ok(())
    }

    #[test]
    fn navigate_routes_policy_metadata() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":9,"method":"browsingContext.navigate","params":{"context":"ctx-1","url":"https://example.test","inputTainted":true,"confirmed":true}}"#,
        )?;

        match routed {
            RoutedCommand::Driver {
                command: DriverCommand::Navigate(command),
                ..
            } => {
                assert_eq!(command.input_tainted, Some(true));
                assert!(command.confirmed);
            }
            other => return Err(format!("expected navigate driver command, got {other:?}").into()),
        }
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
                    input_tainted: None,
                    confirmed: false,
                }),
            }
        );
        Ok(())
    }

    #[test]
    fn script_evaluate_routes_policy_metadata_alias() -> TestResult {
        let mut router = BidiRouter::new();

        let routed = router.route_json(
            br#"{"id":10,"method":"script.evaluate","params":{"expression":"document.title","target":{"context":"ctx-1"},"input_tainted":true,"confirmed":true}}"#,
        )?;

        match routed {
            RoutedCommand::Driver {
                command: DriverCommand::EvaluateScript(command),
                ..
            } => {
                assert_eq!(command.input_tainted, Some(true));
                assert!(command.confirmed);
            }
            other => {
                return Err(
                    format!("expected script.evaluate driver command, got {other:?}").into(),
                )
            }
        }
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
    fn driver_command_param_parse_failure_returns_invalid_argument_with_id() -> TestResult {
        let mut router = BidiRouter::new();

        // browsingContext.create requires a `type` field; omitting it is a
        // structural param failure that must still correlate to the command id.
        let routed =
            router.route_json(br#"{"id":21,"method":"browsingContext.create","params":{}}"#)?;

        match routed {
            RoutedCommand::Immediate(BidiMessage::Error { id, error, .. }) => {
                assert_eq!(id, Some(21));
                assert_eq!(error, "invalid argument");
            }
            other => return Err(format!("expected invalid-argument error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn session_command_param_parse_failure_returns_invalid_argument_with_id() -> TestResult {
        let mut router = BidiRouter::new();

        // session.subscribe expects `events` to be an array of strings.
        let routed = router
            .route_json(br#"{"id":22,"method":"session.subscribe","params":{"events":5}}"#)?;

        match routed {
            RoutedCommand::Immediate(BidiMessage::Error { id, error, .. }) => {
                assert_eq!(id, Some(22));
                assert_eq!(error, "invalid argument");
            }
            other => return Err(format!("expected invalid-argument error, got {other:?}").into()),
        }
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
    fn network_before_request_sent_uses_tempo_net_request_metadata() -> TestResult {
        let tempo_request = tempo_net::NetworkRequest::new(
            "request-1",
            "post",
            "https://example.test/upload",
            "profile-a",
            tempo_net::IdentityMode::AgentDeclared,
        )
        .with_header("Content-Type", "application/json")
        .with_body_size(128);

        let event =
            network_before_request_sent(NetworkRequest::from_tempo_request(&tempo_request))?;

        assert_eq!(
            serde_json::to_value(event)?,
            json!({
                "type": "event",
                "method": "network.beforeRequestSent",
                "params": {
                    "request": "request-1",
                    "url": "https://example.test/upload",
                    "method": "POST",
                    "headers": [
                        {"name": "content-type", "value": "application/json"}
                    ],
                    "bodySize": 128,
                }
            })
        );
        Ok(())
    }

    #[test]
    fn network_response_completed_uses_tempo_net_response_metadata() -> TestResult {
        let tempo_response =
            tempo_net::NetworkResponseRecord::new("request-1", "https://example.test/data", 200)
                .with_header("Content-Type", "application/json")
                .with_body_size(17);
        let event =
            network_response_completed(NetworkResponse::from_tempo_response(&tempo_response))?;

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
