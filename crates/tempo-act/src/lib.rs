//! tempo-act - action execution and quiescence.
//!
//! The engine adapters own the physical injection details. This crate owns the
//! WS5 action spine from `final.md`: run semantic actions through `DriverTrait`,
//! force a post-action diff for grounding verification, and provide the composed
//! quiescence state machine used by real engines.

use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError};
use tempo_schema::{Action, ActionBatch, ObservationDiff, SideEffect};

/// Result category for one executed action or batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The driver grounded and applied the requested operation.
    Applied,
    /// The operation did not ground, but the driver stayed healthy.
    StepError { reason: String },
}

/// Journal-ready result for one semantic action or batch.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionExecution {
    pub engine: Engine,
    pub status: ExecutionStatus,
    pub action_count: usize,
    pub max_side_effect: SideEffect,
    pub since_seq: u64,
    pub seq: u64,
    pub diff: ObservationDiff,
}

impl ActionExecution {
    pub fn applied(&self) -> bool {
        matches!(self.status, ExecutionStatus::Applied)
    }

    pub fn step_error(&self) -> bool {
        matches!(self.status, ExecutionStatus::StepError { .. })
    }
}

/// Execute a single action and always verify the resulting page state by asking
/// the driver for a post-action diff from the pre-action observation sequence.
pub async fn execute_action<D>(
    driver: &mut D,
    action: &Action,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    let before = driver.observe().await?;
    let outcome = driver.act(action).await?;
    finish_execution(
        driver,
        outcome,
        before.seq,
        1,
        action.side_effect(),
        driver.engine(),
    )
    .await
}

/// Execute a batch through the driver and verify one post-batch diff.
pub async fn execute_batch<D>(
    driver: &mut D,
    batch: &ActionBatch,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    let before = driver.observe().await?;
    let outcome = driver.act_batch(batch).await?;
    finish_execution(
        driver,
        outcome,
        before.seq,
        batch.actions.len(),
        max_side_effect(&batch.actions),
        driver.engine(),
    )
    .await
}

/// Conservative maximum side-effect level for a batch.
pub fn max_side_effect(actions: &[Action]) -> SideEffect {
    actions
        .iter()
        .map(Action::side_effect)
        .max()
        .unwrap_or(SideEffect::Read)
}

async fn finish_execution<D>(
    driver: &mut D,
    outcome: StepOutcome,
    since_seq: u64,
    action_count: usize,
    max_side_effect: SideEffect,
    engine: Engine,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    let status = match outcome {
        StepOutcome::Applied { .. } => ExecutionStatus::Applied,
        StepOutcome::StepError { reason } => ExecutionStatus::StepError { reason },
    };
    let diff = driver.observe_diff(since_seq).await?;
    Ok(ActionExecution {
        engine,
        status,
        action_count,
        max_side_effect,
        since_seq,
        seq: diff.seq,
        diff,
    })
}

/// Tunables for the composed quiescence detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuiescenceConfig {
    pub idle_window_ms: u64,
    pub timeout_ms: u64,
}

impl Default for QuiescenceConfig {
    fn default() -> Self {
        Self {
            idle_window_ms: 250,
            timeout_ms: 5_000,
        }
    }
}

/// One sampled set of page-settled signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSignals {
    pub now_ms: u64,
    pub inflight_requests: u32,
    pub layout_generation: u64,
    pub frame_generation: u64,
    pub pending_js_tasks: u32,
}

impl PageSignals {
    pub fn quiet(now_ms: u64) -> Self {
        Self {
            now_ms,
            inflight_requests: 0,
            layout_generation: 0,
            frame_generation: 0,
            pending_js_tasks: 0,
        }
    }
}

/// Quiescence decision after one signal sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuiescenceDecision {
    Waiting,
    Settled,
    TimedOut,
}

/// Composite detector: network idle AND layout/frame stable AND no pending JS
/// for a configured quiet window, with a hard timeout.
#[derive(Clone, Debug, Default)]
pub struct QuiescenceTracker {
    started_at_ms: Option<u64>,
    idle_since_ms: Option<u64>,
    last_layout_generation: Option<u64>,
    last_frame_generation: Option<u64>,
}

impl QuiescenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn observe(
        &mut self,
        signals: PageSignals,
        config: QuiescenceConfig,
    ) -> QuiescenceDecision {
        let started_at = *self.started_at_ms.get_or_insert(signals.now_ms);
        let timed_out = signals.now_ms.saturating_sub(started_at) >= config.timeout_ms;

        let layout_changed = self
            .last_layout_generation
            .replace(signals.layout_generation)
            .is_some_and(|last| last != signals.layout_generation);
        let frame_changed = self
            .last_frame_generation
            .replace(signals.frame_generation)
            .is_some_and(|last| last != signals.frame_generation);
        let busy = signals.inflight_requests > 0
            || signals.pending_js_tasks > 0
            || layout_changed
            || frame_changed;

        if busy {
            self.idle_since_ms = None;
            return if timed_out {
                QuiescenceDecision::TimedOut
            } else {
                QuiescenceDecision::Waiting
            };
        }

        let idle_since = *self.idle_since_ms.get_or_insert(signals.now_ms);
        if signals.now_ms.saturating_sub(idle_since) >= config.idle_window_ms {
            QuiescenceDecision::Settled
        } else if timed_out {
            QuiescenceDecision::TimedOut
        } else {
            QuiescenceDecision::Waiting
        }
    }
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "action executor: NodeId->injection, batching, quiescence detector, grounding-verify via post-action diff"
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures::executor::block_on;
    use tempo_driver::{TransportError, Unsupported};
    use tempo_schema::{
        CompiledObservation, InteractiveElement, NodeId, Provenance, QuiescencePolicy, TaintSpan,
    };

    #[test]
    fn quiescence_requires_full_idle_window() {
        let config = QuiescenceConfig {
            idle_window_ms: 100,
            timeout_ms: 1_000,
        };
        let mut tracker = QuiescenceTracker::new();

        assert_eq!(
            tracker.observe(PageSignals::quiet(0), config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(PageSignals::quiet(99), config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(PageSignals::quiet(100), config),
            QuiescenceDecision::Settled
        );
    }

    #[test]
    fn quiescence_resets_on_network_and_layout_activity() {
        let config = QuiescenceConfig {
            idle_window_ms: 100,
            timeout_ms: 1_000,
        };
        let mut tracker = QuiescenceTracker::new();

        assert_eq!(
            tracker.observe(PageSignals::quiet(0), config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 90,
                    inflight_requests: 1,
                    layout_generation: 0,
                    frame_generation: 0,
                    pending_js_tasks: 0,
                },
                config,
            ),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 120,
                    inflight_requests: 0,
                    layout_generation: 1,
                    frame_generation: 0,
                    pending_js_tasks: 0,
                },
                config,
            ),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 220,
                    inflight_requests: 0,
                    layout_generation: 1,
                    frame_generation: 0,
                    pending_js_tasks: 0,
                },
                config,
            ),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 320,
                    inflight_requests: 0,
                    layout_generation: 1,
                    frame_generation: 0,
                    pending_js_tasks: 0,
                },
                config,
            ),
            QuiescenceDecision::Settled
        );
    }

    #[test]
    fn quiescence_times_out_when_js_never_drains() {
        let config = QuiescenceConfig {
            idle_window_ms: 100,
            timeout_ms: 250,
        };
        let mut tracker = QuiescenceTracker::new();
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 0,
                    inflight_requests: 0,
                    layout_generation: 0,
                    frame_generation: 0,
                    pending_js_tasks: 1,
                },
                config,
            ),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe(
                PageSignals {
                    now_ms: 250,
                    inflight_requests: 0,
                    layout_generation: 0,
                    frame_generation: 0,
                    pending_js_tasks: 1,
                },
                config,
            ),
            QuiescenceDecision::TimedOut
        );
    }

    #[test]
    fn executor_records_applied_action_with_post_action_diff() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("button".into()),
        };
        let execution =
            block_on(execute_action(&mut driver, &action)).map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.engine, Engine::Cdp);
        assert_eq!(execution.action_count, 1);
        assert_eq!(execution.max_side_effect, SideEffect::Write);
        assert_eq!(execution.since_seq, 10);
        assert_eq!(execution.seq, 11);
        assert_eq!(execution.diff.changed.len(), 1);
        assert_eq!(driver.observe_diff_calls, vec![10]);
        Ok(())
    }

    #[test]
    fn executor_records_step_error_without_transport_failure() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("missing".into()),
        };
        let execution =
            block_on(execute_action(&mut driver, &action)).map_err(|error| error.to_string())?;
        assert!(execution.step_error());
        assert_eq!(
            execution.status,
            ExecutionStatus::StepError {
                reason: "node not found".into()
            }
        );
        assert_eq!(execution.diff.added.len(), 0);
        assert_eq!(execution.diff.changed.len(), 0);
        assert_eq!(execution.diff.removed.len(), 0);
        Ok(())
    }

    #[test]
    fn batch_records_max_side_effect_and_action_count() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let batch = ActionBatch {
            actions: vec![
                Action::Goto {
                    url: "https://example.com".into(),
                },
                Action::Type {
                    node: NodeId("button".into()),
                    text: "hello".into(),
                },
            ],
            quiescence: QuiescencePolicy::Composite,
        };
        let execution =
            block_on(execute_batch(&mut driver, &batch)).map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.action_count, 2);
        assert_eq!(execution.max_side_effect, SideEffect::Write);
        Ok(())
    }

    #[derive(Debug)]
    struct ContractDriver {
        seq: u64,
        observe_diff_calls: Vec<u64>,
    }

    impl ContractDriver {
        fn new() -> Self {
            Self {
                seq: 10,
                observe_diff_calls: Vec::new(),
            }
        }

        fn observation(&self) -> CompiledObservation {
            CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: "https://example.test".into(),
                seq: self.seq,
                elements: vec![button_element(self.seq)],
                marks: vec![],
            }
        }
    }

    #[async_trait]
    impl DriverTrait for ContractDriver {
        fn engine(&self) -> Engine {
            Engine::Cdp
        }

        async fn goto(&mut self, _url: &str) -> Result<CompiledObservation, TransportError> {
            self.seq += 1;
            Ok(self.observation())
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            Ok(self.observation())
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.observe_diff_calls.push(since_seq);
            if since_seq == self.seq {
                return Ok(ObservationDiff {
                    since_seq,
                    seq: self.seq,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                });
            }
            Ok(ObservationDiff {
                since_seq,
                seq: self.seq,
                added: Vec::new(),
                removed: Vec::new(),
                changed: vec![button_element(self.seq)],
            })
        }

        async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
            if matches!(action, Action::Click { node } if node.0 == "missing") {
                return Ok(StepOutcome::StepError {
                    reason: "node not found".into(),
                });
            }
            self.seq += 1;
            Ok(StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.seq - 1,
                    seq: self.seq,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: vec![button_element(self.seq)],
                },
            })
        }

        async fn act_batch(&mut self, _batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            self.seq += 1;
            Ok(StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.seq - 1,
                    seq: self.seq,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: vec![button_element(self.seq)],
                },
            })
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("contract driver does not fork"))
        }

        async fn extract(&mut self, _node: &NodeId) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(Vec::new())
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn button_element(seq: u64) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId("button".into()),
            role: "button".into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: format!("Save {seq}"),
            }],
            value: Vec::new(),
            bounds: Some([0.0, 0.0, 100.0, 24.0]),
            rank: 1.0,
        }
    }
}
