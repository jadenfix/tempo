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
use tempo_schema::{Action, ActionBatch, CompiledObservation, NodeId, ObservationDiff};
use thiserror::Error;

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
    elements: Vec<tempo_schema::InteractiveElement>,
}

#[cfg(any(test, feature = "test-driver"))]
impl TestDriver {
    pub fn new() -> Self {
        Self {
            seq: 0,
            url: "about:blank".into(),
            elements: Vec::new(),
        }
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
            elements: self.elements.clone(),
        };
        Ok(Box::new(forked))
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
        Ok(Vec::new())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Conformance suite v2 (final.md §8.1). Every engine must pass this; it is the gate for
/// M0 (TestDriver), M1 (CDP), and part of M2 (Servo slice). Extend, never weaken.
pub mod conformance {
    use super::*;

    /// Runs the portable conformance checks against any driver. Returns `Ok(())` on pass.
    pub async fn assert_driver_conformance<D: DriverTrait>(driver: &mut D) -> Result<(), String> {
        // 1. goto returns an observation carrying the frozen schema version.
        let obs = driver
            .goto("https://example.com")
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

        driver.close().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_passes_conformance() {
        let mut d = TestDriver::new();
        let res = futures::executor::block_on(conformance::assert_driver_conformance(&mut d));
        assert!(res.is_ok(), "conformance failed: {res:?}");
    }
}
