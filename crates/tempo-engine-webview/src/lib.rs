//! T2 system-webview engine adapter.
//!
//! The host platform owns the real WebView: WKWebView on iOS, WebView2 on
//! Windows, and Android WebView on Android. This crate owns the Tempo contract
//! layer around that host surface: stable observation compilation, NodeId to
//! host-locator mapping, DriverTrait semantics, URL pre-checks, and typed page
//! data provenance.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempo_driver::{
    DriverTrait, Engine, StepOutcome, TaintedValue, TransportError, Unsupported,
    MAX_EXTRACT_JSON_BYTES, MAX_SCREENSHOT_BYTES,
};
use tempo_net::UrlPolicy;
use tempo_observe::{
    diff_observations, CompileOptions, ObservationCompiler, ObservationInput, RawElement,
};
use tempo_schema::{
    Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff, Provenance,
    QuiescencePolicy, TaintSpan,
};

const HISTORY_RETENTION_SNAPSHOTS: usize = 16;

/// JavaScript injected into a host-owned system WebView to collect raw
/// observation candidates.
pub const WEBVIEW_OBSERVATION_SCRIPT: &str = include_str!("../runtime/tempo-webview-observe.js");

/// Host-local element handle. It is intentionally opaque to agents.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WebViewLocator(pub String);

impl From<&str> for WebViewLocator {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for WebViewLocator {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// One candidate emitted by the injected runtime or native accessibility bridge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebViewElement {
    pub locator: WebViewLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_hint: Option<String>,
    pub role: String,
    #[serde(default)]
    pub name: Vec<TaintSpan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<TaintSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds: Option<[f32; 4]>,
    #[serde(default = "default_true")]
    pub visible: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub interactive: bool,
}

impl WebViewElement {
    pub fn new(
        locator: impl Into<WebViewLocator>,
        role: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            locator: locator.into(),
            source_id: None,
            stable_hint: None,
            role: role.into(),
            name: page_spans(name.into()),
            value: Vec::new(),
            bounds: None,
            visible: true,
            enabled: true,
            interactive: true,
        }
    }

    pub fn source_id(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into());
        self
    }

    pub fn stable_hint(mut self, stable_hint: impl Into<String>) -> Self {
        self.stable_hint = Some(stable_hint.into());
        self
    }

    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = page_spans(value.into());
        self
    }

    pub fn bounds(mut self, bounds: [f32; 4]) -> Self {
        self.bounds = Some(bounds);
        self
    }

    pub fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    fn raw_element(&self) -> RawElement {
        RawElement {
            source_id: self.source_id.clone(),
            stable_hint: self.stable_hint.clone(),
            role: self.role.clone(),
            name: self.name.clone(),
            value: self.value.clone(),
            bounds: self.bounds,
            visible: self.visible,
            enabled: self.enabled,
            interactive: self.interactive,
        }
    }
}

fn default_true() -> bool {
    true
}

fn page_spans(text: String) -> Vec<TaintSpan> {
    vec![TaintSpan {
        provenance: Provenance::Page,
        text,
    }]
}

/// Full raw snapshot from a host-owned WebView.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebViewSnapshot {
    pub url: String,
    pub elements: Vec<WebViewElement>,
}

impl WebViewSnapshot {
    pub fn new(url: impl Into<String>, elements: Vec<WebViewElement>) -> Self {
        Self {
            url: url.into(),
            elements,
        }
    }
}

/// Failure returned by the native WebView host before it is mapped into
/// Tempo's DriverTrait contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebViewHostError {
    Disconnected,
    NavigationTimeout,
    UrlBlocked,
    NodeNotFound(String),
    OutputTooLarge {
        artifact: &'static str,
        bytes: usize,
        max_bytes: usize,
    },
    Other(String),
}

impl WebViewHostError {
    pub fn node_not_found(node: impl Into<String>) -> Self {
        Self::NodeNotFound(node.into())
    }

    fn into_transport_error(self) -> TransportError {
        match self {
            Self::Disconnected => TransportError::EngineGone,
            Self::NavigationTimeout => TransportError::NavTimeout,
            Self::UrlBlocked => TransportError::UrlBlocked,
            Self::NodeNotFound(node) => {
                TransportError::Other(format!("node not found below webview host: {node}"))
            }
            Self::OutputTooLarge {
                artifact,
                bytes,
                max_bytes,
            } => TransportError::OutputTooLarge {
                artifact,
                bytes,
                max_bytes,
            },
            Self::Other(message) => TransportError::Other(message),
        }
    }
}

impl fmt::Display for WebViewHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(formatter, "webview disconnected"),
            Self::NavigationTimeout => write!(formatter, "webview navigation timed out"),
            Self::UrlBlocked => write!(formatter, "webview URL blocked"),
            Self::NodeNotFound(node) => write!(formatter, "webview node not found: {node}"),
            Self::OutputTooLarge {
                artifact,
                bytes,
                max_bytes,
            } => {
                write!(
                    formatter,
                    "{artifact} exceeded output cap: {bytes} bytes > {max_bytes} bytes"
                )
            }
            Self::Other(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for WebViewHostError {}

/// Native shell callbacks used by [`WebViewDriver`].
///
/// Implementations must run on the platform's correct UI executor. On iOS this
/// means Swift owns WKWebView on MainActor and calls into Rust only at the
/// contract boundary.
pub trait WebViewHost: Send + Sync {
    fn goto(&mut self, url: &str) -> Result<WebViewSnapshot, WebViewHostError>;
    fn observe(&mut self) -> Result<WebViewSnapshot, WebViewHostError>;
    fn click(&mut self, locator: &WebViewLocator) -> Result<WebViewSnapshot, WebViewHostError>;
    fn type_text(
        &mut self,
        locator: &WebViewLocator,
        text: &str,
    ) -> Result<WebViewSnapshot, WebViewHostError>;
    fn select(
        &mut self,
        locator: &WebViewLocator,
        value: &str,
    ) -> Result<WebViewSnapshot, WebViewHostError>;
    fn scroll(&mut self, x: f32, y: f32) -> Result<WebViewSnapshot, WebViewHostError>;
    fn wait(&mut self, millis: u64) -> Result<WebViewSnapshot, WebViewHostError>;
    fn settle(&mut self, policy: QuiescencePolicy) -> Result<WebViewSnapshot, WebViewHostError>;
    fn extract(&mut self, locator: &WebViewLocator) -> Result<Value, WebViewHostError>;
    fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<Value, WebViewHostError>;
    fn screenshot(&mut self) -> Result<Vec<u8>, WebViewHostError>;
    fn close(&mut self) -> Result<(), WebViewHostError>;

    fn create_browsing_context(&mut self) -> Result<Box<dyn WebViewHost>, Unsupported> {
        Err(Unsupported("fresh WebView browsing context"))
    }
}

/// DriverTrait adapter for a host-owned system WebView.
pub struct WebViewDriver {
    host: Box<dyn WebViewHost>,
    url_policy: UrlPolicy,
    compiler: ObservationCompiler,
    history: BTreeMap<u64, Arc<CompiledObservation>>,
    locators_by_node: BTreeMap<NodeId, WebViewLocator>,
}

impl WebViewDriver {
    pub fn new(host: Box<dyn WebViewHost>) -> Self {
        Self::with_options(host, CompileOptions::default())
    }

    pub fn with_options(host: Box<dyn WebViewHost>, options: CompileOptions) -> Self {
        Self {
            host,
            url_policy: UrlPolicy::block_private(),
            compiler: ObservationCompiler::with_options(options),
            history: BTreeMap::new(),
            locators_by_node: BTreeMap::new(),
        }
    }

    pub fn allow_private_network_access(mut self) -> Self {
        self.url_policy = UrlPolicy::allow_all();
        self
    }

    pub fn injected_observation_script(&self) -> &'static str {
        WEBVIEW_OBSERVATION_SCRIPT
    }

    pub fn locator_for_observed_node(&self, node: &NodeId) -> Option<&WebViewLocator> {
        self.locators_by_node.get(node)
    }

    fn latest_seq(&self) -> u64 {
        self.history.keys().next_back().copied().unwrap_or_default()
    }

    fn record_snapshot(
        &mut self,
        snapshot: WebViewSnapshot,
    ) -> Result<Arc<CompiledObservation>, TransportError> {
        enforce_snapshot_url(&self.url_policy, &snapshot.url)?;
        let raw_elements: Vec<RawElement> = snapshot
            .elements
            .iter()
            .map(WebViewElement::raw_element)
            .collect();
        let compiled = self
            .compiler
            .compile_with_node_ids(ObservationInput::new(snapshot.url, raw_elements));

        let emitted_ids: HashSet<&str> = compiled
            .observation
            .elements
            .iter()
            .map(|element| element.node_id.0.as_str())
            .collect();
        let mut locators = BTreeMap::new();
        for raw_node in compiled.node_ids {
            if emitted_ids.contains(raw_node.node_id.0.as_str())
                && let Some(element) = snapshot.elements.get(raw_node.raw_index)
            {
                locators.insert(raw_node.node_id, element.locator.clone());
            }
        }
        self.locators_by_node = locators;

        let retained = Arc::new(compiled.observation);
        self.history.insert(retained.seq, Arc::clone(&retained));
        prune_observation_history(&mut self.history, retained.seq);
        Ok(retained)
    }

    fn observe_from_host(&mut self) -> Result<Arc<CompiledObservation>, TransportError> {
        let snapshot = self.host.observe().map_err(map_host_error)?;
        self.record_snapshot(snapshot)
    }

    fn diff_from_base(&self, since_seq: u64, current: &CompiledObservation) -> ObservationDiff {
        let Some(base) = self.history.get(&since_seq).map(Arc::as_ref) else {
            return full_snapshot_diff(since_seq, current);
        };
        diff_from_base(Some(base), current, since_seq)
    }

    fn locator_for_node(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<WebViewLocator>, TransportError> {
        if let Some(locator) = self.locators_by_node.get(node) {
            return Ok(Some(locator.clone()));
        }
        self.observe_from_host()?;
        Ok(self.locators_by_node.get(node).cloned())
    }

    fn run_node_action(
        &mut self,
        node: &NodeId,
        action: impl FnOnce(
            &mut dyn WebViewHost,
            &WebViewLocator,
        ) -> Result<WebViewSnapshot, WebViewHostError>,
    ) -> Result<StepOutcome, TransportError> {
        let previous_seq = self.latest_seq();
        let Some(locator) = self.locator_for_node(node)? else {
            return Ok(StepOutcome::StepError {
                reason: format!("node not found: {}", node.0),
            });
        };

        let snapshot = match action(&mut *self.host, &locator) {
            Ok(snapshot) => snapshot,
            Err(WebViewHostError::NodeNotFound(_)) => {
                self.observe_from_host()?;
                return Ok(StepOutcome::StepError {
                    reason: format!("node not found: {}", node.0),
                });
            }
            Err(error) => return Err(error.into_transport_error()),
        };
        let current = self.record_snapshot(snapshot)?;
        Ok(StepOutcome::applied(
            self.diff_from_base(previous_seq, current.as_ref()),
        ))
    }

    fn capped_page_value(
        &self,
        artifact: &'static str,
        value: Value,
    ) -> Result<TaintedValue, TransportError> {
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| TransportError::Other(error.to_string()))?
            .len();
        if bytes > MAX_EXTRACT_JSON_BYTES {
            return Err(TransportError::OutputTooLarge {
                artifact,
                bytes,
                max_bytes: MAX_EXTRACT_JSON_BYTES,
            });
        }
        Ok(TaintedValue::page(value))
    }
}

#[async_trait]
impl DriverTrait for WebViewDriver {
    fn engine(&self) -> Engine {
        Engine::WebView
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        self.url_policy
            .enforce(url)
            .map_err(|_error| TransportError::UrlBlocked)?;
        let snapshot = self.host.goto(url).map_err(map_host_error)?;
        Ok(self.record_snapshot(snapshot)?.as_ref().clone())
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        Ok(self.observe_from_host()?.as_ref().clone())
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        let current = self.observe_from_host()?;
        Ok(self.diff_from_base(since_seq, current.as_ref()))
    }

    fn cached_observation(&self, seq: u64) -> Option<CompiledObservation> {
        self.history
            .get(&seq)
            .map(|observation| observation.as_ref().clone())
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        let previous_seq = self.latest_seq();
        match action {
            Action::Goto { url } => {
                let observation = self.goto(url).await?;
                Ok(StepOutcome::applied(
                    self.diff_from_base(previous_seq, &observation),
                ))
            }
            Action::Click { node } => {
                self.run_node_action(node, |host, locator| host.click(locator))
            }
            Action::Type { node, text } => {
                self.run_node_action(node, |host, locator| host.type_text(locator, text))
            }
            Action::Select { node, value } => {
                self.run_node_action(node, |host, locator| host.select(locator, value))
            }
            Action::Scroll { x, y } => {
                let snapshot = self.host.scroll(*x, *y).map_err(map_host_error)?;
                let current = self.record_snapshot(snapshot)?;
                Ok(StepOutcome::applied(
                    self.diff_from_base(previous_seq, current.as_ref()),
                ))
            }
            Action::Wait { millis } => {
                let snapshot = self.host.wait(*millis).map_err(map_host_error)?;
                let current = self.record_snapshot(snapshot)?;
                Ok(StepOutcome::applied(
                    self.diff_from_base(previous_seq, current.as_ref()),
                ))
            }
            Action::Extract { node } => self.run_node_action(node, |host, locator| {
                host.extract(locator)?;
                host.observe()
            }),
            Action::FindText { .. }
            | Action::ElementPresent { .. }
            | Action::QuerySelector { .. } => Ok(StepOutcome::StepError {
                reason: "read helper actions are not implemented by WebView yet".into(),
            }),
            Action::Skill { name, .. } => Ok(StepOutcome::StepError {
                reason: format!("skill action {name:?} is handled by tempo-skills, not WebView"),
            }),
        }
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        let batch_base_seq = self.latest_seq();
        for action in &batch.actions {
            let outcome = self.act(action).await?;
            if matches!(outcome, StepOutcome::StepError { .. }) {
                return Ok(outcome);
            }
        }
        let snapshot = self.host.settle(batch.quiescence).map_err(map_host_error)?;
        let current = self.record_snapshot(snapshot)?;
        Ok(StepOutcome::applied(
            self.diff_from_base(batch_base_seq, current.as_ref()),
        ))
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        Err(Unsupported("native WebView fork"))
    }

    async fn create_browsing_context(
        &mut self,
        _options: tempo_driver::BrowsingContextCreateOptions,
    ) -> Result<Box<dyn DriverTrait>, Unsupported> {
        let host = self.host.create_browsing_context()?;
        Ok(Box::new(Self {
            host,
            url_policy: self.url_policy.clone(),
            compiler: ObservationCompiler::new(),
            history: BTreeMap::new(),
            locators_by_node: BTreeMap::new(),
        }))
    }

    async fn extract(&mut self, node: &NodeId) -> Result<TaintedValue, TransportError> {
        let Some(locator) = self.locator_for_node(node)? else {
            return self.capped_page_value("extract", missing_node_value(node));
        };
        match self.host.extract(&locator) {
            Ok(value) => self.capped_page_value("extract", value),
            Err(WebViewHostError::NodeNotFound(_)) => {
                self.observe_from_host()?;
                self.capped_page_value("extract", missing_node_value(node))
            }
            Err(error) => Err(error.into_transport_error()),
        }
    }

    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<TaintedValue, TransportError> {
        let value = self
            .host
            .evaluate_script(expression, await_promise)
            .map_err(map_host_error)?;
        self.capped_page_value("script evaluation", value)
    }

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
        let bytes = self.host.screenshot().map_err(map_host_error)?;
        if bytes.len() > MAX_SCREENSHOT_BYTES {
            return Err(TransportError::OutputTooLarge {
                artifact: "screenshot",
                bytes: bytes.len(),
                max_bytes: MAX_SCREENSHOT_BYTES,
            });
        }
        Ok(bytes)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.host.close().map_err(map_host_error)
    }
}

fn missing_node_value(node: &NodeId) -> Value {
    json!({
        "found": false,
        "error": "node id not found",
        "node": node.0,
    })
}

fn map_host_error(error: WebViewHostError) -> TransportError {
    error.into_transport_error()
}

fn enforce_snapshot_url(policy: &UrlPolicy, url: &str) -> Result<(), TransportError> {
    if url == "about:blank" {
        return Ok(());
    }
    policy
        .enforce(url)
        .map_err(|_error| TransportError::UrlBlocked)
}

fn full_snapshot_diff(since_seq: u64, current: &CompiledObservation) -> ObservationDiff {
    ObservationDiff {
        since_seq,
        seq: current.seq,
        url: Some(current.url.clone()),
        omitted: current.omitted,
        marks: current.marks.clone(),
        added: current.elements.clone(),
        removed: Vec::new(),
        changed: Vec::new(),
    }
}

fn diff_from_base(
    base: Option<&CompiledObservation>,
    current: &CompiledObservation,
    since_seq: u64,
) -> ObservationDiff {
    let Some(base) = base else {
        return full_snapshot_diff(since_seq, current);
    };
    let mut diff = diff_observations(base, current);
    diff.since_seq = since_seq;
    diff
}

fn prune_observation_history(
    history: &mut BTreeMap<u64, Arc<CompiledObservation>>,
    newest_seq: u64,
) {
    if history.len() <= HISTORY_RETENTION_SNAPSHOTS {
        return;
    }
    let keep_from = newest_seq.saturating_sub(HISTORY_RETENTION_SNAPSHOTS as u64 - 1);
    history.retain(|seq, _| *seq >= keep_from);
}

/// Static crate summary used by smoke tests and platform build scripts.
pub fn describe() -> &'static str {
    "system WebView DriverTrait adapter with host callbacks, injected observation runtime, stable NodeId grounding, and T2 fork semantics"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_driver::conformance::{ConformanceConfig, ForkExpectation};

    const TEST_SCREENSHOT_PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D',
        b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', 0x78, 0x9c, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, b'I',
        b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
    ];

    #[test]
    fn webview_driver_passes_conformance_without_native_fork() {
        let mut driver = fixture_driver(vec![button("submit", "source-submit", "submit")]);
        let config = ConformanceConfig::default().with_fork(ForkExpectation::Unsupported);

        let result = futures::executor::block_on(
            tempo_driver::conformance::assert_driver_conformance_with(&mut driver, config),
        );

        assert!(result.is_ok(), "conformance failed: {result:?}");
    }

    #[test]
    fn compiles_candidates_with_page_taint_marks_and_private_locators() -> Result<(), String> {
        let mut driver = fixture_driver(vec![
            WebViewElement::new("native-email", "textbox", "Email")
                .source_id("source-email")
                .stable_hint("email")
                .bounds([0.0, 0.0, 100.0, 24.0]),
            button("native-submit", "source-submit", "submit"),
        ]);

        let observation = futures::executor::block_on(driver.goto("https://example.com/login"))
            .map_err(|error| error.to_string())?;

        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        assert_eq!(observation.seq, 1);
        assert!(!observation.marks.is_empty());
        assert!(observation
            .elements
            .iter()
            .flat_map(|element| element.name.iter())
            .all(|span| span.provenance == Provenance::Page));
        assert!(observation
            .elements
            .iter()
            .all(|element| !element.node_id.0.starts_with("native-")));
        assert!(observation
            .elements
            .iter()
            .any(|element| driver.locator_for_observed_node(&element.node_id).is_some()));
        Ok(())
    }

    #[test]
    fn stable_ids_survive_reorder_and_native_source_changes() -> Result<(), String> {
        let first = WebViewSnapshot::new(
            "https://example.com",
            vec![button("native-old", "source-old", "submit")],
        );
        let second = WebViewSnapshot::new(
            "https://example.com",
            vec![
                WebViewElement::new("native-search", "textbox", "Search")
                    .source_id("source-search")
                    .stable_hint("search"),
                button("native-new", "source-new", "submit"),
            ],
        );
        let mut driver = scripted_driver(vec![first, second.clone()]);

        let first = futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;
        let submit_id = first
            .elements
            .iter()
            .find(|element| element.role == "button")
            .map(|element| element.node_id.clone())
            .ok_or_else(|| "missing submit button".to_string())?;
        let second_obs =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;

        assert!(second_obs
            .elements
            .iter()
            .any(|element| element.node_id == submit_id && element.role == "button"));
        assert_eq!(
            driver.locator_for_observed_node(&submit_id),
            Some(&WebViewLocator("native-new".into()))
        );
        Ok(())
    }

    #[test]
    fn duplicate_candidates_get_distinct_node_ids() -> Result<(), String> {
        let mut driver = fixture_driver(vec![
            WebViewElement::new("native-a", "button", "Save"),
            WebViewElement::new("native-b", "button", "Save"),
        ]);

        let observation =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;
        let unique: HashSet<&str> = observation
            .elements
            .iter()
            .map(|element| element.node_id.0.as_str())
            .collect();

        assert_eq!(observation.elements.len(), 2);
        assert_eq!(unique.len(), 2);
        Ok(())
    }

    #[test]
    fn missing_node_actions_are_step_errors() -> Result<(), String> {
        let mut driver = fixture_driver(vec![button("native-submit", "source-submit", "submit")]);

        let outcome = futures::executor::block_on(driver.act(&Action::Click {
            node: NodeId("missing".into()),
        }))
        .map_err(|e| e.to_string())?;

        assert!(matches!(outcome, StepOutcome::StepError { .. }));
        Ok(())
    }

    #[test]
    fn batch_stops_on_first_step_error() -> Result<(), String> {
        let mut driver = fixture_driver(vec![button("native-submit", "source-submit", "submit")]);
        let batch = ActionBatch {
            actions: vec![
                Action::Click {
                    node: NodeId("missing".into()),
                },
                Action::Scroll { x: 0.0, y: 10.0 },
            ],
            quiescence: QuiescencePolicy::FixedMillis(0),
        };

        let outcome =
            futures::executor::block_on(driver.act_batch(&batch)).map_err(|e| e.to_string())?;

        assert!(matches!(outcome, StepOutcome::StepError { .. }));
        Ok(())
    }

    #[test]
    fn extract_missing_node_is_page_derived_found_false() -> Result<(), String> {
        let mut driver = fixture_driver(vec![button("native-submit", "source-submit", "submit")]);

        let extracted = futures::executor::block_on(driver.extract(&NodeId("missing".into())))
            .map_err(|e| e.to_string())?;

        assert!(extracted.is_page_derived());
        assert_eq!(extracted.get("found"), Some(&Value::Bool(false)));
        Ok(())
    }

    #[test]
    fn observe_diff_missing_base_returns_full_snapshot_diff() -> Result<(), String> {
        let mut driver = fixture_driver(vec![button("native-submit", "source-submit", "submit")]);

        let diff =
            futures::executor::block_on(driver.observe_diff(42)).map_err(|e| e.to_string())?;

        assert_eq!(diff.since_seq, 42);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        Ok(())
    }

    #[test]
    fn screenshot_output_is_capped() {
        let mut driver = WebViewDriver::new(Box::new(MemoryWebViewHost::with_screenshot(vec![
            0_u8;
            MAX_SCREENSHOT_BYTES + 1
        ])));

        let result = futures::executor::block_on(driver.screenshot());

        assert!(matches!(
            result,
            Err(TransportError::OutputTooLarge {
                artifact: "screenshot",
                ..
            })
        ));
    }

    #[test]
    fn private_navigation_is_blocked_without_mutating_observation() -> Result<(), String> {
        let mut driver = fixture_driver(vec![button("native-submit", "source-submit", "submit")]);

        let result = futures::executor::block_on(driver.goto("http://127.0.0.1/admin"));
        assert!(matches!(result, Err(TransportError::UrlBlocked)));
        let observation =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;

        assert_eq!(observation.url, "about:blank");
        assert_eq!(observation.seq, 1);
        Ok(())
    }

    #[test]
    fn host_returned_private_snapshot_is_blocked_without_mutating_observation() -> Result<(), String>
    {
        let first = WebViewSnapshot::new(
            "https://example.com",
            vec![button("native-submit", "source-submit", "submit")],
        );
        let private = WebViewSnapshot::new(
            "http://127.0.0.1/admin",
            vec![button("native-submit", "source-submit", "submit")],
        );
        let mut driver = scripted_driver(vec![first, private]);

        let observation =
            futures::executor::block_on(driver.observe()).map_err(|error| error.to_string())?;
        let result = futures::executor::block_on(driver.observe());

        assert!(matches!(result, Err(TransportError::UrlBlocked)));
        assert_eq!(driver.latest_seq(), observation.seq);
        assert_eq!(driver.history.len(), 1);
        assert_eq!(observation.url, "https://example.com");
        Ok(())
    }

    #[test]
    fn webview_snapshot_deserializes_injected_runtime_taint_span_payload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot: WebViewSnapshot = serde_json::from_value(json!({
            "url": "https://example.com/form",
            "elements": [{
                "locator": "#email",
                "source_id": "email-source",
                "stable_hint": "email|textbox|Email",
                "role": "textbox",
                "name": [{ "provenance": "page", "text": "Email" }],
                "value": [{ "provenance": "page", "text": "person@example.com" }],
                "bounds": [0.0, 0.0, 120.0, 24.0],
                "visible": true,
                "enabled": true,
                "interactive": true
            }]
        }))?;

        assert_eq!(snapshot.elements[0].name[0].provenance, Provenance::Page);
        assert_eq!(snapshot.elements[0].value[0].text, "person@example.com");
        Ok(())
    }

    fn fixture_driver(elements: Vec<WebViewElement>) -> WebViewDriver {
        scripted_driver(vec![WebViewSnapshot::new("about:blank", elements)])
    }

    fn scripted_driver(snapshots: Vec<WebViewSnapshot>) -> WebViewDriver {
        WebViewDriver::new(Box::new(MemoryWebViewHost::new(snapshots)))
    }

    fn button(
        locator: impl Into<WebViewLocator>,
        source_id: impl Into<String>,
        stable_hint: impl Into<String>,
    ) -> WebViewElement {
        WebViewElement::new(locator, "button", "Submit")
            .source_id(source_id)
            .stable_hint(stable_hint)
            .bounds([0.0, 0.0, 100.0, 30.0])
    }

    #[derive(Clone)]
    struct MemoryWebViewHost {
        snapshots: Vec<WebViewSnapshot>,
        cursor: usize,
        screenshot: Vec<u8>,
        actions: Vec<String>,
        closed: bool,
    }

    impl MemoryWebViewHost {
        fn new(snapshots: Vec<WebViewSnapshot>) -> Self {
            Self {
                snapshots,
                cursor: 0,
                screenshot: TEST_SCREENSHOT_PNG.to_vec(),
                actions: Vec::new(),
                closed: false,
            }
        }

        fn with_screenshot(screenshot: Vec<u8>) -> Self {
            Self {
                snapshots: vec![WebViewSnapshot::new("about:blank", Vec::new())],
                cursor: 0,
                screenshot,
                actions: Vec::new(),
                closed: false,
            }
        }

        fn current_snapshot(&self) -> Result<WebViewSnapshot, WebViewHostError> {
            self.snapshots
                .get(self.cursor.min(self.snapshots.len().saturating_sub(1)))
                .cloned()
                .ok_or_else(|| WebViewHostError::Other("missing test snapshot".into()))
        }

        fn advance_snapshot(&mut self) -> Result<WebViewSnapshot, WebViewHostError> {
            let snapshot = self.current_snapshot()?;
            if self.cursor + 1 < self.snapshots.len() {
                self.cursor += 1;
            }
            Ok(snapshot)
        }

        fn contains_locator(&self, locator: &WebViewLocator) -> Result<bool, WebViewHostError> {
            Ok(self
                .current_snapshot()?
                .elements
                .iter()
                .any(|element| &element.locator == locator))
        }

        fn act_on_locator(
            &mut self,
            action: &str,
            locator: &WebViewLocator,
        ) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push(action.to_string());
            if !self.contains_locator(locator)? {
                return Err(WebViewHostError::node_not_found(locator.0.clone()));
            }
            self.current_snapshot()
        }
    }

    impl WebViewHost for MemoryWebViewHost {
        fn goto(&mut self, url: &str) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push(format!("goto:{url}"));
            let mut snapshot = self.current_snapshot()?;
            snapshot.url = url.to_string();
            if self.snapshots.is_empty() {
                self.snapshots.push(snapshot.clone());
            } else {
                let index = self.cursor.min(self.snapshots.len() - 1);
                self.snapshots[index] = snapshot.clone();
            }
            Ok(snapshot)
        }

        fn observe(&mut self) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push("observe".into());
            self.advance_snapshot()
        }

        fn click(&mut self, locator: &WebViewLocator) -> Result<WebViewSnapshot, WebViewHostError> {
            self.act_on_locator("click", locator)
        }

        fn type_text(
            &mut self,
            locator: &WebViewLocator,
            _text: &str,
        ) -> Result<WebViewSnapshot, WebViewHostError> {
            self.act_on_locator("type", locator)
        }

        fn select(
            &mut self,
            locator: &WebViewLocator,
            _value: &str,
        ) -> Result<WebViewSnapshot, WebViewHostError> {
            self.act_on_locator("select", locator)
        }

        fn scroll(&mut self, _x: f32, _y: f32) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push("scroll".into());
            self.current_snapshot()
        }

        fn wait(&mut self, _millis: u64) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push("wait".into());
            self.current_snapshot()
        }

        fn settle(
            &mut self,
            _policy: QuiescencePolicy,
        ) -> Result<WebViewSnapshot, WebViewHostError> {
            self.actions.push("settle".into());
            self.current_snapshot()
        }

        fn extract(&mut self, locator: &WebViewLocator) -> Result<Value, WebViewHostError> {
            self.actions.push("extract".into());
            if !self.contains_locator(locator)? {
                return Err(WebViewHostError::node_not_found(locator.0.clone()));
            }
            Ok(json!({ "found": true, "locator": locator.0 }))
        }

        fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<Value, WebViewHostError> {
            self.actions.push("evaluate".into());
            Ok(json!({
                "expression": expression,
                "awaitPromise": await_promise,
            }))
        }

        fn screenshot(&mut self) -> Result<Vec<u8>, WebViewHostError> {
            self.actions.push("screenshot".into());
            Ok(self.screenshot.clone())
        }

        fn close(&mut self) -> Result<(), WebViewHostError> {
            self.closed = true;
            self.actions.push("close".into());
            Ok(())
        }
    }
}
