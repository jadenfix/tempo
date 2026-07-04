//! tempo-driver — Contract **C3**: the engine-agnostic `DriverTrait` v2 and the
//! conformance suite. This is the substrate every non-engine team develops against
//! (final.md §5): freezing it unblocks WS4–WS10 while Servo and CDP progress.
//!
//! `DriverTrait` v2 is a superset of `beater_browser::BrowserDriver`, adding diff-based
//! re-observation, batched actions, page-state forking, and typed extraction. It is
//! implemented by `tempo-engine-servo` (primary), `tempo-engine-cdp` (fallback), and
//! the optional `TestDriver` for conformance tests. The grounding contract is
//! preserved: a NodeId miss is a `StepError`, never a `TransportError`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-driver"))]
use tempo_net::UrlPolicy;
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use thiserror::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
/// Maximum screenshot capture width in device independent pixels.
pub const MAX_SCREENSHOT_WIDTH: u32 = 4096;
/// Maximum screenshot capture height in device independent pixels.
pub const MAX_SCREENSHOT_HEIGHT: u32 = 4096;
/// Maximum raw screenshot bytes returned by a driver.
pub const MAX_SCREENSHOT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum serialized JSON bytes returned by a typed extract operation.
pub const MAX_EXTRACT_JSON_BYTES: usize = 1024 * 1024;
/// Maximum serialized protocol response bytes for MCP/BiDi envelopes.
pub const MAX_PROTOCOL_RESPONSE_BYTES: usize = 6 * 1024 * 1024;

pub fn output_cap_message(artifact: &str, bytes: usize, max_bytes: usize) -> String {
    format!("{artifact} exceeded output cap: {bytes} bytes > {max_bytes} bytes")
}

/// Transport / backend failures: crashed engine, navigation timeout, SSRF block.
/// Distinct from a step error, which is a *grounding* failure the agent can react to.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("engine crashed or disconnected")]
    EngineGone,
    #[error("navigation timed out")]
    NavTimeout,
    #[error("blocked by URL policy (SSRF guard)")]
    UrlBlocked,
    #[error("engine error: {0}")]
    Other(String),
    #[error("{artifact} exceeded output cap: {bytes} bytes > {max_bytes} bytes")]
    OutputTooLarge {
        artifact: &'static str,
        bytes: usize,
        max_bytes: usize,
    },
}

/// Outcome of an action: either it grounded and produced a diff, or it was a step error
/// (e.g. NodeId not present) — which is a normal, recoverable signal, not a transport fault.
#[derive(Debug)]
pub enum StepOutcome {
    Applied { diff: ObservationDiff },
    StepError { reason: String },
}

/// Capability a driver may not support (e.g. CDP lane cannot natively `fork`).
#[derive(Debug, Error)]
#[error("capability unsupported by this engine: {0}")]
pub struct Unsupported(pub &'static str);

/// Which engine backs a driver instance — recorded on every StepTriple for the
/// cross-engine differential harness (final.md §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Servo,
    Cdp,
    #[cfg(any(test, feature = "test-driver"))]
    Test,
}

/// Browser-level context kind requested by WebDriver BiDi `browsingContext.create`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowsingContextKind {
    Tab,
    Window,
}

/// Engine-agnostic request for a fresh browser browsing context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowsingContextCreateOptions {
    pub kind: BrowsingContextKind,
    pub background: bool,
}

/// C3: the engine-agnostic driver interface. Object-safe so it can cross the UDS wire
/// protocol and be swapped per-origin by the auto-fallback table.
#[async_trait]
pub trait DriverTrait: Send + Sync {
    fn engine(&self) -> Engine;

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError>;

    /// Full current observation.
    async fn observe(&mut self) -> Result<CompiledObservation, TransportError>;

    /// Diff-based re-observation: only what changed since `since_seq` (final.md §2.3).
    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError>;

    /// Execute a single semantic action.
    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError>;

    /// Execute a batch and wait for the page to settle per the batch's quiescence policy.
    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError>;

    /// Fork page state for speculative k-branch exploration (final.md §2.5). Engines that
    /// cannot fork natively return `Unsupported`; `tempo-speculate` falls back to replay-fork.
    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported>;

    /// Create a fresh browser browsing context (tab/window) for WebDriver BiDi.
    ///
    /// This is deliberately separate from [`DriverTrait::fork`]: forks clone
    /// page state for speculation, while browsing-context creation must start
    /// with a clean browser context such as `about:blank`.
    async fn create_browsing_context(
        &mut self,
        _options: BrowsingContextCreateOptions,
    ) -> Result<Box<dyn DriverTrait>, Unsupported> {
        Err(Unsupported("fresh browsing context"))
    }

    /// Typed extraction of a subtree rooted at `node`.
    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError>;

    /// Evaluate a JavaScript expression in the active browsing context.
    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<serde_json::Value, TransportError>;

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError>;

    async fn close(&mut self) -> Result<(), TransportError>;
}

/// In-memory `DriverTrait` used only by conformance tests.
#[cfg(any(test, feature = "test-driver"))]
pub struct TestDriver {
    seq: u64,
    url: String,
    url_policy: UrlPolicy,
    elements: Vec<tempo_schema::InteractiveElement>,
}

#[cfg(any(test, feature = "test-driver"))]
const TEST_SCREENSHOT_PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R',
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae,
    0x42, 0x60, 0x82,
];

#[cfg(any(test, feature = "test-driver"))]
impl TestDriver {
    pub fn new() -> Self {
        Self {
            seq: 0,
            url: "about:blank".into(),
            url_policy: UrlPolicy::block_private(),
            elements: Vec::new(),
        }
    }

    pub fn with_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    pub fn allow_private_network_access(mut self) -> Self {
        self.url_policy = UrlPolicy::allow_all();
        self
    }

    /// Seed the page with elements so tests can plan actions against known NodeIds.
    pub fn with_elements(mut self, elements: Vec<tempo_schema::InteractiveElement>) -> Self {
        self.elements = elements;
        self
    }

    fn snapshot(&self) -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: self.url.clone(),
            seq: self.seq,
            elements: self.elements.clone(),
            omitted: 0,
            marks: vec![],
        }
    }

    fn has_node(&self, node: &NodeId) -> bool {
        self.elements.iter().any(|e| &e.node_id == node)
    }
}

#[cfg(any(test, feature = "test-driver"))]
impl Default for TestDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-driver"))]
#[async_trait]
impl DriverTrait for TestDriver {
    fn engine(&self) -> Engine {
        Engine::Test
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        self.url_policy
            .enforce(url)
            .map_err(|_error| TransportError::UrlBlocked)?;
        self.url = url.to_string();
        self.seq += 1;
        Ok(self.snapshot())
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        Ok(self.snapshot())
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        Ok(ObservationDiff {
            since_seq,
            seq: self.seq,
            added: vec![],
            removed: vec![],
            changed: vec![],
        })
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        if let Action::Goto { url } = action {
            let since_seq = self.seq;
            let observation = self.goto(url).await?;
            return Ok(StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq,
                    seq: observation.seq,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            });
        }

        // Grounding contract: an action against a missing node is a StepError, not a fault.
        let missing = match action {
            Action::Click { node }
            | Action::Type { node, .. }
            | Action::Select { node, .. }
            | Action::Extract { node } => !self.has_node(node),
            _ => false,
        };
        if missing {
            return Ok(StepOutcome::StepError {
                reason: "node not found".into(),
            });
        }
        self.seq += 1;
        Ok(StepOutcome::Applied {
            diff: ObservationDiff {
                since_seq: self.seq - 1,
                seq: self.seq,
                added: vec![],
                removed: vec![],
                changed: vec![],
            },
        })
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        let mut last = StepOutcome::Applied {
            diff: ObservationDiff {
                since_seq: self.seq,
                seq: self.seq,
                added: vec![],
                removed: vec![],
                changed: vec![],
            },
        };
        for a in &batch.actions {
            last = self.act(a).await?;
            if matches!(last, StepOutcome::StepError { .. }) {
                break;
            }
        }
        Ok(last)
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        let forked = TestDriver {
            seq: self.seq,
            url: self.url.clone(),
            url_policy: self.url_policy.clone(),
            elements: self.elements.clone(),
        };
        Ok(Box::new(forked))
    }

    async fn create_browsing_context(
        &mut self,
        _options: BrowsingContextCreateOptions,
    ) -> Result<Box<dyn DriverTrait>, Unsupported> {
        Ok(Box::new(TestDriver {
            seq: 0,
            url: "about:blank".into(),
            url_policy: self.url_policy.clone(),
            elements: Vec::new(),
        }))
    }

    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
        if !self.has_node(node) {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::json!({ "node": node.0 }))
    }

    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<serde_json::Value, TransportError> {
        Ok(serde_json::json!({
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

/// Conformance suite v2 (final.md §8.1). Every engine must pass this; it is the gate for
/// M0 (TestDriver), M1 (CDP), and part of M2 (Servo slice). Extend, never weaken.
pub mod conformance {
    use super::*;

    /// Expected native page-state fork behavior for a driver under conformance.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ForkExpectation {
        /// Accept either a native fork or an explicit unsupported capability.
        Optional,
        /// `fork()` must return an independent driver handle.
        Supported,
        /// `fork()` must report `Unsupported` rather than a transport failure.
        Unsupported,
    }

    /// Portable conformance inputs for engines that need a fixture URL or have
    /// engine-specific optional capabilities.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ConformanceConfig {
        pub navigation_url: String,
        pub fork: ForkExpectation,
        pub extract_node: Option<NodeId>,
    }

    impl ConformanceConfig {
        pub fn new(navigation_url: impl Into<String>) -> Self {
            Self {
                navigation_url: navigation_url.into(),
                ..Self::default()
            }
        }

        pub fn with_fork(mut self, fork: ForkExpectation) -> Self {
            self.fork = fork;
            self
        }

        pub fn with_extract_node(mut self, node: impl Into<NodeId>) -> Self {
            self.extract_node = Some(node.into());
            self
        }
    }

    impl Default for ConformanceConfig {
        fn default() -> Self {
            Self {
                navigation_url: "https://example.com".into(),
                fork: ForkExpectation::Optional,
                extract_node: None,
            }
        }
    }

    /// Runs the portable conformance checks against any driver. Returns `Ok(())` on pass.
    pub async fn assert_driver_conformance<D: DriverTrait>(driver: &mut D) -> Result<(), String> {
        assert_driver_conformance_with(driver, ConformanceConfig::default()).await
    }

    /// Runs conformance checks with explicit capability expectations.
    pub async fn assert_driver_conformance_with<D: DriverTrait>(
        driver: &mut D,
        config: ConformanceConfig,
    ) -> Result<(), String> {
        // 1. goto returns an observation carrying the frozen schema version.
        let obs = driver
            .goto(&config.navigation_url)
            .await
            .map_err(|e| e.to_string())?;
        if obs.schema_version != tempo_schema::SCHEMA_VERSION {
            return Err("schema version mismatch".into());
        }

        // 2. Grounding contract: acting on an unknown node is a StepError, NOT a transport error.
        let out = driver
            .act(&Action::Click {
                node: NodeId("does-not-exist".into()),
            })
            .await
            .map_err(|_| {
                "grounding miss surfaced as TransportError (contract violation)".to_string()
            })?;
        if !matches!(out, StepOutcome::StepError { .. }) {
            return Err("missing node did not yield StepError".into());
        }

        // 3. observe_diff is expressed relative to the requested seq.
        let diff = driver
            .observe_diff(obs.seq)
            .await
            .map_err(|e| e.to_string())?;
        if diff.since_seq != obs.seq {
            return Err("observe_diff ignored since_seq".into());
        }

        // 4. Script evaluation is part of C3 and is required by BiDi, Servo M-vanilla,
        // and extraction helpers. Conformance only requires a transport-successful
        // value here because each engine returns its native JSON shape.
        let evaluated = driver
            .evaluate_script("document.readyState", false)
            .await
            .map_err(|e| format!("evaluate_script failed: {e}"))?;
        if evaluated.is_null() {
            return Err("evaluate_script returned null".into());
        }

        // 5. Typed extraction must work for at least one grounded node on the
        // fixture page. Engines should pass an explicit node when their fixture
        // uses a known selector/NodeId; otherwise the first observed element is used.
        let extract_node = config
            .extract_node
            .clone()
            .or_else(|| obs.elements.first().map(|element| element.node_id.clone()))
            .ok_or_else(|| "conformance fixture did not expose an extractable node".to_string())?;
        let extracted = driver
            .extract(&extract_node)
            .await
            .map_err(|e| format!("extract failed: {e}"))?;
        if extracted.is_null() || extracted.get("found") == Some(&serde_json::Value::Bool(false)) {
            return Err("extract did not return a grounded value".into());
        }

        // 6. Successful batched actions must apply as a unit and return a normal
        // step outcome.
        let ok_batch = ActionBatch {
            actions: vec![
                Action::Scroll { x: 0.0, y: 0.0 },
                Action::Extract {
                    node: extract_node.clone(),
                },
            ],
            quiescence: tempo_schema::QuiescencePolicy::FixedMillis(0),
        };
        let out = driver
            .act_batch(&ok_batch)
            .await
            .map_err(|e| format!("successful batch failed with transport error: {e}"))?;
        if !matches!(out, StepOutcome::Applied { .. }) {
            return Err("successful batch did not yield Applied".into());
        }

        // 7. Batched actions preserve the grounding contract too: a NodeId miss
        // is a StepError, not a transport error or partial success.
        let batch = ActionBatch {
            actions: vec![Action::Click {
                node: NodeId("tempo-conformance-missing-node".into()),
            }],
            quiescence: tempo_schema::QuiescencePolicy::FixedMillis(0),
        };
        let out = driver.act_batch(&batch).await.map_err(|_| {
            "batched grounding miss surfaced as TransportError (contract violation)".to_string()
        })?;
        if !matches!(out, StepOutcome::StepError { .. }) {
            return Err("batched missing node did not yield StepError".into());
        }

        // 8. Native fork capability must be explicit. Engines that do not support
        // it return Unsupported so tempo-speculate can fall back to replay-fork.
        match config.fork {
            ForkExpectation::Optional => match driver.fork().await {
                Ok(mut forked) => assert_fork_observes(&mut *forked).await?,
                Err(_unsupported) => {}
            },
            ForkExpectation::Supported => match driver.fork().await {
                Ok(mut forked) => assert_fork_observes(&mut *forked).await?,
                Err(error) => return Err(error.to_string()),
            },
            ForkExpectation::Unsupported => {
                if driver.fork().await.is_ok() {
                    return Err("driver unexpectedly supported native fork".into());
                }
            }
        }

        // 9. screenshot returns PNG bytes, matching the protocol surfaces that expose
        // `image/png` screenshots over MCP and BiDi.
        let screenshot = driver.screenshot().await.map_err(|e| e.to_string())?;
        if !screenshot.starts_with(PNG_SIGNATURE) || screenshot.len() <= PNG_SIGNATURE.len() {
            return Err("screenshot did not return PNG bytes".into());
        }

        driver.close().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn assert_fork_observes(driver: &mut dyn DriverTrait) -> Result<(), String> {
        let fork_obs = driver.observe().await.map_err(|e| e.to_string())?;
        if fork_obs.schema_version != tempo_schema::SCHEMA_VERSION {
            return Err("fork observation schema version mismatch".into());
        }
        driver.close().await.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[test]
    fn test_driver_passes_conformance() {
        let mut d = TestDriver::new().with_elements(vec![button("submit")]);
        let config = conformance::ConformanceConfig::default()
            .with_fork(conformance::ForkExpectation::Supported);
        let res = futures::executor::block_on(conformance::assert_driver_conformance_with(
            &mut d, config,
        ));
        assert!(res.is_ok(), "conformance failed: {res:?}");
    }

    #[test]
    fn test_driver_screenshot_returns_real_png_bytes() -> Result<(), String> {
        let mut driver = TestDriver::new();
        let bytes = futures::executor::block_on(driver.screenshot()).map_err(|e| e.to_string())?;

        assert!(bytes.starts_with(PNG_SIGNATURE));
        assert!(bytes.len() > PNG_SIGNATURE.len());
        Ok(())
    }

    #[test]
    fn test_driver_blocks_private_navigation_by_default() -> Result<(), String> {
        for url in [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/internal",
        ] {
            let mut driver = TestDriver::new();
            let result = futures::executor::block_on(driver.goto(url));

            assert!(
                matches!(result, Err(TransportError::UrlBlocked)),
                "{url} was not blocked: {result:?}"
            );
            let observation =
                futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;
            assert_eq!(observation.url, "about:blank", "{url} mutated url");
            assert_eq!(observation.seq, 0, "{url} mutated sequence");
        }
        Ok(())
    }

    #[test]
    fn test_driver_blocks_private_goto_action_by_default() -> Result<(), String> {
        let mut driver = TestDriver::new();
        let action = Action::Goto {
            url: "http://169.254.169.254/latest/meta-data".into(),
        };

        let result = futures::executor::block_on(driver.act(&action));

        assert!(
            matches!(result, Err(TransportError::UrlBlocked)),
            "private goto action was not blocked: {result:?}"
        );
        let observation =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;
        assert_eq!(observation.url, "about:blank");
        assert_eq!(observation.seq, 0);
        Ok(())
    }

    #[test]
    fn test_driver_blocks_private_goto_action_in_batch_by_default() -> Result<(), String> {
        let mut driver = TestDriver::new();
        let batch = ActionBatch {
            actions: vec![Action::Goto {
                url: "http://169.254.169.254/latest/meta-data".into(),
            }],
            quiescence: tempo_schema::QuiescencePolicy::FixedMillis(0),
        };

        let result = futures::executor::block_on(driver.act_batch(&batch));

        assert!(
            matches!(result, Err(TransportError::UrlBlocked)),
            "private batched goto action was not blocked: {result:?}"
        );
        let observation =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;
        assert_eq!(observation.url, "about:blank");
        assert_eq!(observation.seq, 0);
        Ok(())
    }

    #[test]
    fn test_driver_can_explicitly_allow_private_navigation() -> Result<(), String> {
        let mut driver = TestDriver::new().allow_private_network_access();

        let observation = futures::executor::block_on(driver.goto("http://127.0.0.1/fixture"))
            .map_err(|e| e.to_string())?;

        assert_eq!(observation.url, "http://127.0.0.1/fixture");
        assert_eq!(observation.seq, 1);
        Ok(())
    }

    #[test]
    fn test_driver_create_browsing_context_starts_fresh() -> Result<(), String> {
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        futures::executor::block_on(driver.goto("https://root.test")).map_err(|e| e.to_string())?;

        let mut created = futures::executor::block_on(driver.create_browsing_context(
            BrowsingContextCreateOptions {
                kind: BrowsingContextKind::Tab,
                background: false,
            },
        ))
        .map_err(|e| e.to_string())?;
        let created_observation =
            futures::executor::block_on(created.observe()).map_err(|e| e.to_string())?;
        let root_observation =
            futures::executor::block_on(driver.observe()).map_err(|e| e.to_string())?;

        assert_eq!(created_observation.url, "about:blank");
        assert_eq!(created_observation.seq, 0);
        assert!(created_observation.elements.is_empty());
        assert_eq!(root_observation.url, "https://root.test");
        assert_eq!(root_observation.seq, 1);
        assert_eq!(root_observation.elements.len(), 1);
        futures::executor::block_on(created.close()).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn conformance_accepts_drivers_that_explicitly_do_not_fork() {
        let mut driver = NoForkDriver(TestDriver::new().with_elements(vec![button("submit")]));
        let config = conformance::ConformanceConfig::default()
            .with_fork(conformance::ForkExpectation::Unsupported);

        let res = futures::executor::block_on(conformance::assert_driver_conformance_with(
            &mut driver,
            config,
        ));

        assert!(res.is_ok(), "conformance failed: {res:?}");
    }

    struct NoForkDriver(TestDriver);

    #[async_trait]
    impl DriverTrait for NoForkDriver {
        fn engine(&self) -> Engine {
            self.0.engine()
        }

        async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
            self.0.goto(url).await
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            self.0.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.0.observe_diff(since_seq).await
        }

        async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
            self.0.act(action).await
        }

        async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            self.0.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("native fork intentionally unsupported"))
        }

        async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
            self.0.extract(node).await
        }

        async fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<serde_json::Value, TransportError> {
            self.0.evaluate_script(expression, await_promise).await
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            self.0.screenshot().await
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.0.close().await
        }
    }

    fn button(id: &str) -> tempo_schema::InteractiveElement {
        tempo_schema::InteractiveElement {
            node_id: NodeId(id.into()),
            role: "button".into(),
            name: vec![tempo_schema::TaintSpan {
                provenance: tempo_schema::Provenance::Page,
                text: "Submit".into(),
            }],
            value: Vec::new(),
            bounds: Some([0.0, 0.0, 100.0, 30.0]),
            rank: 1.0,
        }
    }
}
