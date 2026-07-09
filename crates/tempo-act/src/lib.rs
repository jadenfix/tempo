//! tempo-act - action execution and quiescence.
//!
//! The engine adapters own the physical injection details. This crate owns the
//! WS5 action spine from `final.md`: run semantic actions through `DriverTrait`,
//! force a post-action diff for grounding verification, and provide the composed
//! quiescence state machine used by real engines.

pub mod detect;

pub use detect::detect_human_takeover;

use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError};
use tempo_schema::{Action, ActionBatch, ObservationDiff, SideEffect};

/// Result category for one executed action or batch.
///
/// Note the two distinct error shapes: a batch driver applies each action in
/// order and breaks on the first step error, so a `StepError` can coexist with
/// side effects that already grounded. `PartiallyApplied` names that case
/// explicitly so a consumer never mistakes a partially-applied batch for a
/// clean no-op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The driver grounded and applied the requested operation.
    Applied,
    /// A batch step-errored *after* one or more earlier actions had already been
    /// applied and grounded (the post-batch diff is non-empty). Real side effects
    /// have occurred — this MUST NOT be treated as a replayable no-op.
    PartiallyApplied { reason: String },
    /// The operation did not ground and produced no observable change, so no side
    /// effects occurred; the driver stayed healthy.
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
    /// True only when the whole operation grounded cleanly (`Applied`). A batch
    /// that step-errored partway is deliberately NOT `applied()`, but it may
    /// still have produced side effects — see [`applied_side_effects`].
    ///
    /// [`applied_side_effects`]: ActionExecution::applied_side_effects
    pub fn applied(&self) -> bool {
        matches!(self.status, ExecutionStatus::Applied)
    }

    /// True when the driver reported a step error, whether or not earlier actions
    /// in the batch already grounded (covers both `StepError` and
    /// `PartiallyApplied`).
    pub fn step_error(&self) -> bool {
        matches!(
            self.status,
            ExecutionStatus::StepError { .. } | ExecutionStatus::PartiallyApplied { .. }
        )
    }

    /// True when the batch step-errored *after* applying and grounding at least
    /// one earlier action (`PartiallyApplied`). Distinguishes a partial-apply
    /// step error from a clean no-op step error.
    pub fn partially_applied(&self) -> bool {
        matches!(self.status, ExecutionStatus::PartiallyApplied { .. })
    }

    /// True when side effects may have occurred and the execution therefore must
    /// NOT be treated as a replayable no-op. This is the honest replay-safety
    /// signal: it holds for a clean `Applied`, and also for a `PartiallyApplied`
    /// batch StepError whose post-batch diff proved earlier actions grounded.
    /// Only a plain `StepError` (empty post-batch diff) is safe to replay.
    pub fn applied_side_effects(&self) -> bool {
        matches!(
            self.status,
            ExecutionStatus::Applied | ExecutionStatus::PartiallyApplied { .. }
        )
    }
}

/// How `finish_execution` obtains the post-action grounding diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Grounding {
    /// Trust an Applied outcome's embedded diff when it was computed against
    /// exactly the pre-action base; re-ground with a forced `observe_diff`
    /// otherwise. The live engines produce that diff from a genuine
    /// post-settle observe, so re-reading the same settled page would only
    /// duplicate work on the latency-critical path.
    TrustMatchingDiff,
    /// Always re-ground with an independent `observe_diff`, even when the
    /// embedded diff matches the base. For paths where the diff is a
    /// verification witness — replay divergence detection — the read-back
    /// must be independent of the act path it is checking.
    IndependentRediff,
}

/// Execute a single action and verify the resulting page state with a
/// post-action diff from the pre-action observation sequence (the engine's
/// own post-settle diff when it matches that base).
pub async fn execute_action<D>(
    driver: &mut D,
    action: &Action,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    execute_action_grounded(driver, action, Grounding::TrustMatchingDiff).await
}

/// Execute a single action using a caller-supplied current observation sequence
/// as the grounding base. This preserves [`execute_action`]'s post-action
/// grounding semantics while avoiding a redundant pre-action full observation
/// for callers that already hold a valid current observation `seq`.
pub async fn execute_action_since<D>(
    driver: &mut D,
    action: &Action,
    base_seq: u64,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    let outcome = driver.act(action).await?;
    finish_execution(
        driver,
        outcome,
        base_seq,
        1,
        action.side_effect(),
        driver.engine(),
        Grounding::TrustMatchingDiff,
    )
    .await
}

/// [`execute_action`], but the grounding diff always comes from an independent
/// post-action `observe_diff`. Use where the diff is a verification witness
/// (e.g. replay divergence detection) rather than a latency-sensitive product.
pub async fn execute_action_verified<D>(
    driver: &mut D,
    action: &Action,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    execute_action_grounded(driver, action, Grounding::IndependentRediff).await
}

async fn execute_action_grounded<D>(
    driver: &mut D,
    action: &Action,
    grounding: Grounding,
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
        grounding,
    )
    .await
}

/// Execute a batch through the driver and verify one post-batch diff (the
/// engine's own post-settle diff when it matches the pre-batch base).
pub async fn execute_batch<D>(
    driver: &mut D,
    batch: &ActionBatch,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    execute_batch_grounded(driver, batch, Grounding::TrustMatchingDiff).await
}

/// [`execute_batch`], but the grounding diff always comes from an independent
/// post-batch `observe_diff`. Use where the diff is a verification witness
/// (e.g. replay divergence detection) rather than a latency-sensitive product.
pub async fn execute_batch_verified<D>(
    driver: &mut D,
    batch: &ActionBatch,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    execute_batch_grounded(driver, batch, Grounding::IndependentRediff).await
}

async fn execute_batch_grounded<D>(
    driver: &mut D,
    batch: &ActionBatch,
    grounding: Grounding,
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
        grounding,
    )
    .await
}

/// Whether a post-batch diff proves at least one action grounded (any added,
/// removed, or changed element).
fn diff_grounded(diff: &ObservationDiff) -> bool {
    !diff.added.is_empty() || !diff.removed.is_empty() || !diff.changed.is_empty()
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
    grounding: Grounding,
) -> Result<ActionExecution, TransportError>
where
    D: DriverTrait + ?Sized,
{
    // An Applied outcome whose embedded diff was computed against exactly our
    // pre-action base already IS the post-action grounding diff: the live
    // engines produce it from a genuine post-settle observe, so re-issuing
    // observe_diff would pull the same settled page a second time (on CDP: a
    // full DOM fetch plus the AX-enrichment round-trips plus the observe-side
    // policy grace). Trust it only on an exact base match; any other base —
    // e.g. a per-action default batch impl whose last diff is relative to the
    // previous action, not the batch base — re-grounds below. Verification
    // callers (Grounding::IndependentRediff) always re-ground.
    let outcome = match outcome {
        StepOutcome::Applied { diff }
            if grounding == Grounding::TrustMatchingDiff && diff.since_seq == since_seq =>
        {
            return Ok(ActionExecution {
                engine,
                status: ExecutionStatus::Applied,
                action_count,
                max_side_effect,
                since_seq,
                seq: diff.seq,
                diff,
            });
        }
        other => other,
    };

    // Ground the outcome against a forced post-batch diff. The batch driver
    // applies actions in order and breaks on the first step error, so a
    // StepError with a non-empty diff means earlier actions already grounded:
    // that is a partial apply, not a no-op.
    let diff = driver.observe_diff(since_seq).await?;
    let status = match outcome {
        StepOutcome::Applied { .. } => ExecutionStatus::Applied,
        StepOutcome::StepError { reason } if diff_grounded(&diff) => {
            ExecutionStatus::PartiallyApplied { reason }
        }
        StepOutcome::StepError { reason } => ExecutionStatus::StepError { reason },
    };
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

    /// Build page signals from the real network-idle counters owned by
    /// `tempo-net`, plus the engine-local layout/frame/JS signals.
    pub fn from_network_counters(
        now_ms: u64,
        network: &tempo_net::QuiescenceCounters,
        layout_generation: u64,
        frame_generation: u64,
        pending_js_tasks: u32,
    ) -> Self {
        Self {
            now_ms,
            inflight_requests: network.inflight().min(u32::MAX as usize) as u32,
            layout_generation,
            frame_generation,
            pending_js_tasks,
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
        self.observe_inner(signals, None, config)
    }

    /// Observe engine-local signals plus real `tempo-net` network counters.
    ///
    /// Unlike sampling only `inflight_requests`, this preserves the network
    /// layer's last activity tick, so a request that starts and finishes between
    /// two action-layer samples still restarts the composed quiet window.
    pub fn observe_with_network_counters(
        &mut self,
        now_ms: u64,
        network: &tempo_net::QuiescenceCounters,
        layout_generation: u64,
        frame_generation: u64,
        pending_js_tasks: u32,
        config: QuiescenceConfig,
    ) -> QuiescenceDecision {
        self.observe_inner(
            PageSignals::from_network_counters(
                now_ms,
                network,
                layout_generation,
                frame_generation,
                pending_js_tasks,
            ),
            Some(network.last_activity_tick()),
            config,
        )
    }

    fn observe_inner(
        &mut self,
        signals: PageSignals,
        network_last_activity_ms: Option<u64>,
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

        let idle_since = self.idle_since_ms.get_or_insert(signals.now_ms);
        if let Some(network_last_activity_ms) = network_last_activity_ms {
            *idle_since = (*idle_since).max(network_last_activity_ms);
        }
        if signals.now_ms.saturating_sub(*idle_since) >= config.idle_window_ms {
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
    fn page_signals_reflect_real_network_counters() {
        let mut network = tempo_net::QuiescenceCounters::new();
        network.begin("request-1", 10);
        network.begin("request-2", 11);

        let signals = PageSignals::from_network_counters(20, &network, 3, 5, 7);

        assert_eq!(
            signals,
            PageSignals {
                now_ms: 20,
                inflight_requests: 2,
                layout_generation: 3,
                frame_generation: 5,
                pending_js_tasks: 7,
            }
        );
    }

    #[test]
    fn quiescence_network_counter_activity_resets_idle_window_between_samples() {
        let config = QuiescenceConfig {
            idle_window_ms: 100,
            timeout_ms: 1_000,
        };
        let mut tracker = QuiescenceTracker::new();
        let mut network = tempo_net::QuiescenceCounters::new();

        assert_eq!(
            tracker.observe_with_network_counters(0, &network, 0, 0, 0, config),
            QuiescenceDecision::Waiting
        );

        network.begin("request-1", 25);
        assert!(network.finish(
            &tempo_net::RequestId("request-1".into()),
            tempo_net::RequestOutcome::Completed,
            60
        ));

        assert_eq!(
            tracker.observe_with_network_counters(120, &network, 0, 0, 0, config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe_with_network_counters(159, &network, 0, 0, 0, config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe_with_network_counters(160, &network, 0, 0, 0, config),
            QuiescenceDecision::Settled
        );
    }

    #[test]
    fn quiescence_network_counter_inflight_requests_are_busy() {
        let config = QuiescenceConfig {
            idle_window_ms: 100,
            timeout_ms: 1_000,
        };
        let mut tracker = QuiescenceTracker::new();
        let mut network = tempo_net::QuiescenceCounters::new();
        network.begin("request-1", 25);

        assert_eq!(
            tracker.observe_with_network_counters(125, &network, 0, 0, 0, config),
            QuiescenceDecision::Waiting
        );
        assert_eq!(
            tracker.observe_with_network_counters(225, &network, 0, 0, 0, config),
            QuiescenceDecision::Waiting
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
        // The action's embedded diff was computed against exactly the
        // pre-action base (since_seq 10), so no forced re-diff is issued.
        assert!(driver.observe_diff_calls.is_empty());
        Ok(())
    }

    #[test]
    fn execute_action_since_applied_with_matching_base_skips_observe_and_rediff(
    ) -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("button".into()),
        };
        let execution = block_on(execute_action_since(&mut driver, &action, 10))
            .map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.since_seq, 10);
        assert_eq!(execution.seq, 11);
        assert_eq!(driver.observe_calls, 0);
        assert!(driver.observe_diff_calls.is_empty());
        Ok(())
    }

    #[test]
    fn execute_action_since_step_error_uses_supplied_base_for_rediff() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("missing".into()),
        };
        let execution = block_on(execute_action_since(&mut driver, &action, 10))
            .map_err(|error| error.to_string())?;
        assert_eq!(
            execution.status,
            ExecutionStatus::StepError {
                reason: "node not found".into()
            }
        );
        assert_eq!(execution.since_seq, 10);
        assert_eq!(execution.seq, 10);
        assert_eq!(driver.observe_calls, 0);
        assert_eq!(driver.observe_diff_calls, vec![10]);
        Ok(())
    }

    #[test]
    fn execute_action_since_applied_with_mismatched_base_regrounds() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("button".into()),
        };
        let execution = block_on(execute_action_since(&mut driver, &action, 9))
            .map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.since_seq, 9);
        assert_eq!(execution.seq, 11);
        assert_eq!(driver.observe_calls, 0);
        assert_eq!(driver.observe_diff_calls, vec![9]);
        Ok(())
    }

    #[test]
    fn applied_batch_with_matching_base_skips_forced_rediff() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let batch = ActionBatch {
            actions: vec![Action::Click {
                node: NodeId("button".into()),
            }],
            quiescence: QuiescencePolicy::Composite,
        };
        let execution =
            block_on(execute_batch(&mut driver, &batch)).map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.since_seq, 10);
        assert_eq!(execution.seq, 11);
        assert_eq!(execution.diff.changed.len(), 1);
        assert!(driver.observe_diff_calls.is_empty());
        Ok(())
    }

    #[test]
    fn verified_execution_regrounds_even_on_matching_base() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        let action = Action::Click {
            node: NodeId("button".into()),
        };
        let execution = block_on(execute_action_verified(&mut driver, &action))
            .map_err(|error| error.to_string())?;
        assert!(execution.applied());
        // The embedded diff matches the base, but verification callers must
        // still get an independent read-back.
        assert_eq!(driver.observe_diff_calls, vec![10]);
        Ok(())
    }

    #[test]
    fn applied_batch_with_mismatched_base_regrounds_with_forced_rediff() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        // Two actions through the per-action mock batch: the last embedded
        // diff is relative to the previous action (since_seq 11), not the
        // batch base (10), so the executor must re-ground from the base.
        let batch = ActionBatch {
            actions: vec![
                Action::Click {
                    node: NodeId("button".into()),
                },
                Action::Click {
                    node: NodeId("button".into()),
                },
            ],
            quiescence: QuiescencePolicy::Composite,
        };
        let execution =
            block_on(execute_batch(&mut driver, &batch)).map_err(|error| error.to_string())?;
        assert!(execution.applied());
        assert_eq!(execution.since_seq, 10);
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
        assert!(execution.applied_side_effects());
        assert!(!execution.partially_applied());
        assert_eq!(execution.action_count, 2);
        assert_eq!(execution.max_side_effect, SideEffect::Write);
        Ok(())
    }

    #[test]
    fn batch_step_error_after_grounding_reports_partially_applied() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        // First action grounds (advances seq), second step-errors — the batch
        // driver breaks after applying the first, so real side effects precede
        // the error.
        let batch = ActionBatch {
            actions: vec![
                Action::Goto {
                    url: "https://example.com".into(),
                },
                Action::Click {
                    node: NodeId("missing".into()),
                },
            ],
            quiescence: QuiescencePolicy::Composite,
        };
        let execution =
            block_on(execute_batch(&mut driver, &batch)).map_err(|error| error.to_string())?;

        assert!(!execution.applied());
        assert!(execution.step_error());
        assert!(execution.partially_applied());
        assert!(execution.applied_side_effects());
        assert_eq!(
            execution.status,
            ExecutionStatus::PartiallyApplied {
                reason: "node not found".into()
            }
        );
        // The forced post-batch diff proves the earlier action grounded.
        assert!(!execution.diff.changed.is_empty());
        Ok(())
    }

    #[test]
    fn batch_step_error_on_first_action_reports_plain_step_error() -> Result<(), String> {
        let mut driver = ContractDriver::new();
        // The very first action step-errors, so nothing grounds: a clean no-op
        // that is safe to replay.
        let batch = ActionBatch {
            actions: vec![
                Action::Click {
                    node: NodeId("missing".into()),
                },
                Action::Goto {
                    url: "https://example.com".into(),
                },
            ],
            quiescence: QuiescencePolicy::Composite,
        };
        let execution =
            block_on(execute_batch(&mut driver, &batch)).map_err(|error| error.to_string())?;

        assert!(!execution.applied());
        assert!(execution.step_error());
        assert!(!execution.partially_applied());
        assert!(!execution.applied_side_effects());
        assert_eq!(
            execution.status,
            ExecutionStatus::StepError {
                reason: "node not found".into()
            }
        );
        assert!(execution.diff.added.is_empty());
        assert!(execution.diff.changed.is_empty());
        assert!(execution.diff.removed.is_empty());
        Ok(())
    }

    #[derive(Debug)]
    struct ContractDriver {
        seq: u64,
        observe_calls: usize,
        observe_diff_calls: Vec<u64>,
    }

    impl ContractDriver {
        fn new() -> Self {
            Self {
                seq: 10,
                observe_calls: 0,
                observe_diff_calls: Vec::new(),
            }
        }

        fn observation(&self) -> CompiledObservation {
            CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: "https://example.test".into(),
                seq: self.seq,
                elements: vec![button_element(self.seq)],
                omitted: 0,
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
            self.observe_calls += 1;
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
                    omitted: 0,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                });
            }
            Ok(ObservationDiff {
                since_seq,
                seq: self.seq,
                omitted: 0,
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
                    omitted: 0,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: vec![button_element(self.seq)],
                },
            })
        }

        async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            // Mirror the real batch contract: apply each action in order, then
            // break on the first StepError. `act` advances `seq` for grounded
            // actions and leaves it untouched for a StepError, so an earlier
            // grounded action stays observable in the forced post-batch diff.
            let mut last = StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.seq,
                    seq: self.seq,
                    omitted: 0,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                },
            };
            for action in &batch.actions {
                last = self.act(action).await?;
                if matches!(last, StepOutcome::StepError { .. }) {
                    break;
                }
            }
            Ok(last)
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("contract driver does not fork"))
        }

        async fn extract(&mut self, _node: &NodeId) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
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
