//! tempo-agent — durable task loop primitives.
//!
//! The model client and engine executor sit above this crate. This layer owns the
//! crash-safe runtime contract: token budgeting, stable idempotency keys, journal
//! resume, and StepTriple extraction from durable session records.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tempo_act::{execute_action, execute_batch, ExecutionStatus};
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError};
use tempo_handshake::{probe_http_origin, LaneDecision, ProbeHit};
pub use tempo_handshake::{HttpProbeConfig, Lane as StructuredLane, StructuredSignal};
use tempo_policy::{
    ConfirmationGate, InputTaint, Origin, OriginError, OriginPolicy, OriginRuleMode,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, ObservationDiff, SideEffect};
use tempo_session::{
    read_journal_entries, JournalEntry, JournalError, JournalEvent, RunId, SessionId,
    SessionJournal,
};
use tempo_skills::{SkillError, SkillStore};
use thiserror::Error;

/// Default p95 observation budget from `final.md` §10.
pub const DEFAULT_MAX_OBSERVATION_BYTES: usize = 8 * 1024;

/// Default p50 token budget from `final.md` §10.
pub const DEFAULT_MAX_OBSERVATION_TOKENS: usize = 1_500;

/// Maximum nesting depth allowed while expanding a skill into concrete actions.
/// Bounds unbounded recursion independently of the total-action cap.
pub const MAX_SKILL_EXPANSION_DEPTH: usize = 8;

/// Maximum number of concrete (non-skill) actions a single top-level skill may
/// expand into. Caps billion-laughs–style width×depth amplification before the
/// flattened action vector can exhaust memory.
pub const MAX_SKILL_EXPANSION_ACTIONS: usize = 1_024;

/// Reason recorded when resume refuses to re-run a step that was planned but not
/// completed in a prior run, whose side effect may already have happened (#99).
pub const RESUME_INTERRUPTED_REASON: &str = "resume: step was planned but its outcome was not journaled; not re-executed to avoid duplicating a side effect";

pub type StructuredFastPathProbe = fn(&str, HttpProbeConfig) -> Option<StructuredFastPathDecision>;

/// Structured surface selected before browser navigation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredFastPathDecision {
    pub origin: String,
    pub lane: StructuredLane,
    pub signal: StructuredSignal,
    pub source: String,
}

impl StructuredFastPathDecision {
    pub fn new(
        origin: impl Into<String>,
        lane: StructuredLane,
        signal: StructuredSignal,
        source: impl Into<String>,
    ) -> Self {
        Self {
            origin: origin.into(),
            lane,
            signal,
            source: source.into(),
        }
    }

    pub fn from_lane_decision(origin: impl Into<String>, decision: LaneDecision) -> Option<Self> {
        let ProbeHit { signal, source } = decision.selected?;
        Some(Self::new(origin, decision.lane, signal, source))
    }

    pub fn skips_render(&self) -> bool {
        self.lane.skips_render()
    }

    pub fn lane_name(&self) -> &'static str {
        match self.lane {
            StructuredLane::Render => "render",
            StructuredLane::Api => "api",
            StructuredLane::Mcp => "mcp",
        }
    }

    pub fn signal_name(&self) -> &'static str {
        match self.signal {
            StructuredSignal::BeaterJson => "beater_json",
            StructuredSignal::AgentCard => "agent_card",
            StructuredSignal::LlmsTxt => "llms_txt",
            StructuredSignal::OpenApi => "openapi",
            StructuredSignal::McpCatalog => "mcp_catalog",
            StructuredSignal::WebMcp => "web_mcp",
        }
    }
}

/// Pre-render structured-web probe used to avoid pixel rendering when an origin
/// exposes an API or MCP surface.
#[derive(Clone)]
pub struct StructuredFastPath {
    enabled: bool,
    config: HttpProbeConfig,
    probe: StructuredFastPathProbe,
}

impl StructuredFastPath {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            config: HttpProbeConfig::default(),
            probe: live_structured_fast_path_probe,
        }
    }

    pub fn live() -> Self {
        Self {
            enabled: true,
            config: HttpProbeConfig::default(),
            probe: live_structured_fast_path_probe,
        }
    }

    pub fn with_probe(probe: StructuredFastPathProbe) -> Self {
        Self {
            enabled: true,
            config: HttpProbeConfig::default(),
            probe,
        }
    }

    pub fn with_config(mut self, config: HttpProbeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn allow_private_network_access(mut self) -> Self {
        self.config = self.config.allow_private_network_access();
        self
    }

    pub fn probe_target(&self, target: &str) -> Option<StructuredFastPathDecision> {
        if !self.enabled {
            return None;
        }
        (self.probe)(target, self.config.clone())
    }
}

fn live_structured_fast_path_probe(
    target: &str,
    config: HttpProbeConfig,
) -> Option<StructuredFastPathDecision> {
    let run = probe_http_origin(target, config).ok()?;
    let decision = run.lane_decision();
    StructuredFastPathDecision::from_lane_decision(run.origin, decision)
}

/// Stable key for retrying a planned step without duplicating side effects.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn for_action(index: usize, action: &Action) -> Result<Self, AgentError> {
        let action = serde_json::to_vec(action)?;
        let mut hash = Sha256::new();
        hash.update(b"tempo-agent:idempotency-key:v1\0");
        hash.update(index.to_string().as_bytes());
        hash.update(b"\0");
        hash.update(action);
        Ok(Self(lower_hex(&hash.finalize())))
    }
}

/// One planned semantic action with its retry key and token cost.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedStep {
    pub key: IdempotencyKey,
    pub action: Action,
    pub estimated_tokens: u64,
}

/// Ordered task plan consumed by the durable loop.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskPlan {
    pub steps: Vec<PlannedStep>,
}

impl TaskPlan {
    pub fn from_actions(actions: Vec<Action>, estimated_tokens: u64) -> Result<Self, AgentError> {
        let mut steps = Vec::with_capacity(actions.len());
        for (index, action) in actions.into_iter().enumerate() {
            steps.push(PlannedStep {
                key: IdempotencyKey::for_action(index, &action)?,
                action,
                estimated_tokens,
            });
        }
        Ok(Self { steps })
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Token budget state for one agent run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBudget {
    pub max_tokens: u64,
    pub used_tokens: u64,
}

impl TokenBudget {
    pub fn new(max_tokens: u64) -> Self {
        Self {
            max_tokens,
            used_tokens: 0,
        }
    }

    pub fn charge(&mut self, tokens: u64) -> Result<(), AgentError> {
        let next = self.used_tokens.saturating_add(tokens);
        if next > self.max_tokens {
            return Err(AgentError::TokenBudgetExceeded {
                attempted: next,
                max: self.max_tokens,
            });
        }
        self.used_tokens = next;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.max_tokens.saturating_sub(self.used_tokens)
    }
}

/// Resume cursor derived from existing journal entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursor {
    pub completed_steps: usize,
    pub next_step: usize,
    pub pending_planned: Option<IdempotencyKey>,
    pub closed: bool,
    pub last_step_error: Option<(usize, String)>,
}

impl ResumeCursor {
    pub fn from_entries(plan: &TaskPlan, entries: &[JournalEntry]) -> Result<Self, AgentError> {
        let mut completed_steps = 0_usize;
        let mut pending_plan_index = None;
        let mut closed = false;
        let mut last_step_error = None;

        for entry in entries {
            match &entry.event {
                JournalEvent::ActionPlanned { action } => {
                    let index = completed_steps;
                    let planned = plan
                        .steps
                        .get(index)
                        .ok_or(AgentError::JournalHasExtraStep { index })?;
                    if &planned.action != action {
                        return Err(AgentError::JournalDiverged { index });
                    }
                    pending_plan_index = Some(index);
                }
                JournalEvent::StepApplied { action, .. } => {
                    let index = completed_steps;
                    let planned = plan
                        .steps
                        .get(index)
                        .ok_or(AgentError::JournalHasExtraStep { index })?;
                    if &planned.action != action {
                        return Err(AgentError::JournalDiverged { index });
                    }
                    completed_steps += 1;
                    pending_plan_index = None;
                }
                JournalEvent::StepError { action, reason } => {
                    let index = completed_steps;
                    let planned = plan
                        .steps
                        .get(index)
                        .ok_or(AgentError::JournalHasExtraStep { index })?;
                    if &planned.action != action {
                        return Err(AgentError::JournalDiverged { index });
                    }
                    last_step_error = Some((index, reason.clone()));
                    completed_steps += 1;
                    pending_plan_index = None;
                }
                JournalEvent::SessionClosed => closed = true,
                JournalEvent::SessionStarted { .. }
                | JournalEvent::Observation { .. }
                | JournalEvent::TransportError { .. }
                | JournalEvent::CassetteRecorded { .. } => {}
            }
        }

        let next_step = completed_steps;
        let pending_planned = pending_plan_index
            .and_then(|index| plan.steps.get(index))
            .map(|step| step.key.clone());

        Ok(Self {
            completed_steps,
            next_step,
            pending_planned,
            closed,
            last_step_error,
        })
    }
}

/// Durable agent loop state for one journaled task.
pub struct AgentLoop {
    journal: SessionJournal,
    plan: TaskPlan,
    budget: TokenBudget,
    cursor: ResumeCursor,
}

impl AgentLoop {
    pub fn open(
        journal_path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        plan: TaskPlan,
        budget: TokenBudget,
    ) -> Result<Self, AgentError> {
        let journal_path = journal_path.as_ref().to_path_buf();
        let journal = SessionJournal::open(&journal_path, run_id, session_id)?;
        let entries = read_journal_entries(&journal_path)?;
        let cursor = ResumeCursor::from_entries(&plan, &entries)?;
        let mut budget = TokenBudget::new(budget.max_tokens);
        restore_completed_token_budget(&plan, cursor.completed_steps, &mut budget)?;
        Ok(Self {
            journal,
            plan,
            budget,
            cursor,
        })
    }

    pub fn cursor(&self) -> &ResumeCursor {
        &self.cursor
    }

    pub fn budget(&self) -> &TokenBudget {
        &self.budget
    }

    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    pub fn next_step(&self) -> Option<&PlannedStep> {
        self.plan.steps.get(self.cursor.next_step)
    }

    pub fn is_complete(&self) -> bool {
        self.cursor.next_step >= self.plan.len() && self.cursor.pending_planned.is_none()
    }

    /// Journal the intent to execute the next step *before* the side effect runs.
    ///
    /// Writing `ActionPlanned` up front means a crash between the driver call and
    /// the outcome record leaves a durable marker (`pending_planned`) that resume
    /// detects, so the step is not blindly re-executed and its side effect is not
    /// duplicated. Idempotent: re-planning an already-pending step is a no-op.
    pub fn plan_next_step(&mut self) -> Result<(), AgentError> {
        let step = self.next_step().ok_or(AgentError::PlanComplete)?.clone();
        if self.cursor.pending_planned.as_ref() != Some(&step.key) {
            self.journal.append(JournalEvent::ActionPlanned {
                action: step.action.clone(),
            })?;
            self.cursor.pending_planned = Some(step.key);
        }
        Ok(())
    }

    /// Whether the next step was already planned (intent journaled) in a prior run
    /// but never completed — meaning its side effect may already have happened.
    pub fn next_step_already_attempted(&self) -> bool {
        match self.next_step() {
            Some(step) => self.cursor.pending_planned.as_ref() == Some(&step.key),
            None => false,
        }
    }

    pub fn record_next_outcome(&mut self, outcome: StepOutcome) -> Result<StepTriple, AgentError> {
        let step = self.next_step().ok_or(AgentError::PlanComplete)?.clone();
        self.budget.charge(step.estimated_tokens)?;

        if self.cursor.pending_planned.as_ref() != Some(&step.key) {
            self.journal.append(JournalEvent::ActionPlanned {
                action: step.action.clone(),
            })?;
        }

        let event = JournalEvent::from_step_outcome(step.action.clone(), outcome);
        let entry = self.journal.append(event.clone())?;
        if let JournalEvent::StepError { reason, .. } = &event {
            self.cursor
                .last_step_error
                .replace((self.cursor.completed_steps, reason.clone()));
        }
        self.cursor.completed_steps += 1;
        self.cursor.next_step += 1;
        self.cursor.pending_planned = None;

        StepTriple::from_event(step.key, entry.seq, step.action, event)
    }

    pub fn record_pending_interruption(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<StepTriple, AgentError> {
        let step = self.next_step().ok_or(AgentError::PlanComplete)?.clone();
        if self.cursor.pending_planned.as_ref() != Some(&step.key) {
            return Err(AgentError::PlanComplete);
        }

        let reason = reason.into();
        let event = JournalEvent::from_step_outcome(
            step.action.clone(),
            StepOutcome::StepError {
                reason: reason.clone(),
            },
        );
        let entry = self.journal.append(event.clone())?;
        self.cursor
            .last_step_error
            .replace((self.cursor.completed_steps, reason));
        self.cursor.completed_steps += 1;
        self.cursor.next_step += 1;
        self.cursor.pending_planned = None;

        StepTriple::from_event(step.key, entry.seq, step.action, event)
    }

    pub fn record_session_started(&mut self, url: impl Into<String>) -> Result<(), AgentError> {
        self.journal
            .append(JournalEvent::SessionStarted { url: url.into() })?;
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        observation: CompiledObservation,
    ) -> Result<(), AgentError> {
        self.journal
            .append(JournalEvent::Observation { observation })?;
        Ok(())
    }

    /// Journal a driver transport failure before returning it to the caller.
    pub fn record_transport_error(
        &mut self,
        context: impl Into<String>,
        error: &TransportError,
    ) -> Result<(), AgentError> {
        self.journal
            .append(JournalEvent::from_transport_error(context, error))?;
        Ok(())
    }

    pub fn close_session(&mut self) -> Result<(), AgentError> {
        self.journal.append(JournalEvent::SessionClosed)?;
        self.cursor.closed = true;
        Ok(())
    }

    pub fn completed_keys(&self) -> BTreeSet<IdempotencyKey> {
        self.plan
            .steps
            .iter()
            .take(self.cursor.completed_steps)
            .map(|step| step.key.clone())
            .collect()
    }
}

fn restore_completed_token_budget(
    plan: &TaskPlan,
    completed_steps: usize,
    budget: &mut TokenBudget,
) -> Result<(), AgentError> {
    for step in plan.steps.iter().take(completed_steps) {
        budget.charge(step.estimated_tokens)?;
    }
    Ok(())
}

/// A live driver task: navigate to `start_url`, then execute each semantic
/// action through `DriverTrait`.
#[derive(Clone, Debug, PartialEq)]
pub struct DriverTask {
    pub start_url: String,
    pub steps: Vec<DriverStep>,
}

impl DriverTask {
    pub fn new(start_url: impl Into<String>, actions: Vec<Action>) -> Self {
        Self {
            start_url: start_url.into(),
            steps: actions.into_iter().map(DriverStep::clean).collect(),
        }
    }

    pub fn with_steps(start_url: impl Into<String>, steps: Vec<DriverStep>) -> Self {
        Self {
            start_url: start_url.into(),
            steps,
        }
    }

    pub fn task_plan(&self) -> Result<TaskPlan, AgentError> {
        let mut planned = Vec::with_capacity(self.steps.len());
        for (index, step) in self.steps.iter().enumerate() {
            planned.push(PlannedStep {
                key: IdempotencyKey::for_action(index, &step.action)?,
                action: step.action.clone(),
                estimated_tokens: step.estimated_tokens,
            });
        }
        Ok(TaskPlan { steps: planned })
    }
}

/// One live-driver action plus policy/budget metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct DriverStep {
    pub action: Action,
    pub input_taint: InputTaint,
    pub estimated_tokens: u64,
}

impl DriverStep {
    pub fn clean(action: Action) -> Self {
        Self {
            action,
            input_taint: InputTaint::CLEAN,
            estimated_tokens: 1,
        }
    }

    pub fn tainted(action: Action) -> Self {
        Self {
            action,
            input_taint: InputTaint::TAINTED,
            estimated_tokens: 1,
        }
    }

    pub fn with_estimated_tokens(mut self, estimated_tokens: u64) -> Self {
        self.estimated_tokens = estimated_tokens;
        self
    }
}

/// Observation budget enforced before observations are journaled or supplied to
/// an agent/planner context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationBudgetLimit {
    pub max_observation_bytes: usize,
    pub max_observation_tokens: usize,
}

impl Default for ObservationBudgetLimit {
    fn default() -> Self {
        Self {
            max_observation_bytes: DEFAULT_MAX_OBSERVATION_BYTES,
            max_observation_tokens: DEFAULT_MAX_OBSERVATION_TOKENS,
        }
    }
}

impl ObservationBudgetLimit {
    pub fn validate(
        self,
        observation: &CompiledObservation,
    ) -> Result<ObservationBudget, AgentError> {
        let bytes = serde_json::to_vec(observation)?.len();
        let estimated_tokens = estimate_tokens(bytes);
        if bytes > self.max_observation_bytes || estimated_tokens > self.max_observation_tokens {
            return Err(AgentError::ObservationBudgetExceeded {
                bytes,
                max_bytes: self.max_observation_bytes,
                estimated_tokens,
                max_tokens: self.max_observation_tokens,
            });
        }
        Ok(ObservationBudget {
            bytes,
            estimated_tokens,
        })
    }
}

/// Measured observation size for evals and budget reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBudget {
    pub bytes: usize,
    pub estimated_tokens: usize,
}

/// How a non-interactive runner treats policy confirmation gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfirmationMode {
    /// Execute only actions that require no human confirmation.
    #[default]
    DenyHumanRequired,
    /// Auto-confirm normal gates, but still stop for taint-review gates.
    AutoConfirmClean,
    /// Auto-confirm every policy gate. Intended for trusted CI fixtures only.
    AutoConfirmAll,
}

impl ConfirmationMode {
    fn permits(self, gate: ConfirmationGate) -> bool {
        match self {
            Self::DenyHumanRequired => !gate.requires_human(),
            Self::AutoConfirmClean => !matches!(gate, ConfirmationGate::ConfirmWithTaintReview),
            Self::AutoConfirmAll => true,
        }
    }
}

/// Stable identifiers for one durable run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRunIds {
    pub run_id: RunId,
    pub session_id: SessionId,
}

impl AgentRunIds {
    pub fn new(run_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            run_id: RunId(run_id.into()),
            session_id: SessionId(session_id.into()),
        }
    }
}

/// End-to-end runner that binds the durable `AgentLoop` to a live driver.
pub struct AgentRunner {
    journal_path: PathBuf,
    ids: AgentRunIds,
    token_budget: TokenBudget,
    observation_budget: ObservationBudgetLimit,
    confirmation_mode: ConfirmationMode,
    skill_store_root: Option<PathBuf>,
    origin_policy: OriginPolicy,
    structured_fast_path: StructuredFastPath,
}

impl AgentRunner {
    pub fn new(journal_path: impl AsRef<Path>, ids: AgentRunIds) -> Self {
        Self {
            journal_path: journal_path.as_ref().to_path_buf(),
            ids,
            token_budget: TokenBudget::new(DEFAULT_MAX_OBSERVATION_TOKENS as u64),
            observation_budget: ObservationBudgetLimit::default(),
            confirmation_mode: ConfirmationMode::default(),
            skill_store_root: None,
            origin_policy: OriginPolicy::default(),
            structured_fast_path: StructuredFastPath::disabled(),
        }
    }

    pub fn with_token_budget(mut self, token_budget: TokenBudget) -> Self {
        self.token_budget = token_budget;
        self
    }

    pub fn with_observation_budget(mut self, observation_budget: ObservationBudgetLimit) -> Self {
        self.observation_budget = observation_budget;
        self
    }

    pub fn with_confirmation_mode(mut self, confirmation_mode: ConfirmationMode) -> Self {
        self.confirmation_mode = confirmation_mode;
        self
    }

    pub fn with_skill_store(mut self, root: impl AsRef<Path>) -> Self {
        self.skill_store_root = Some(root.as_ref().to_path_buf());
        self
    }

    pub fn with_origin_policy(mut self, origin_policy: OriginPolicy) -> Self {
        self.origin_policy = origin_policy;
        self
    }

    pub fn with_structured_fast_path(mut self, structured_fast_path: StructuredFastPath) -> Self {
        self.structured_fast_path = structured_fast_path;
        self
    }

    pub async fn run_driver_task<D>(
        &self,
        driver: &mut D,
        task: &DriverTask,
    ) -> Result<AgentRunReport, AgentError>
    where
        D: DriverTrait + ?Sized,
    {
        let plan = task.task_plan()?;
        let mut agent = AgentLoop::open(
            &self.journal_path,
            self.ids.run_id.clone(),
            self.ids.session_id.clone(),
            plan,
            self.token_budget.clone(),
        )?;
        let initial_entries = read_journal_entries(agent.journal_path())?;
        let mut report = AgentRunReport::new(
            driver.engine(),
            agent.journal_path().to_path_buf(),
            initial_entries.len(),
            agent.cursor().completed_steps,
        );

        if agent.cursor().closed && agent.is_complete() {
            report.status = AgentRunStatus::AlreadyComplete;
            return Ok(report);
        }

        if let Some((action_index, reason)) = &agent.cursor().last_step_error {
            report.status = if is_policy_denial_reason(reason) {
                AgentRunStatus::PolicyDenied {
                    action_index: *action_index,
                    reason: reason.clone(),
                }
            } else {
                AgentRunStatus::StepError {
                    action_index: *action_index,
                    reason: reason.clone(),
                }
            };
            return Ok(report);
        }

        let mut current_origin;
        if !has_session_started(&initial_entries) {
            if let Some(decision) = self.structured_fast_path.probe_target(&task.start_url)
                && decision.skips_render()
            {
                report.status = AgentRunStatus::StructuredFastPath(decision);
                return Ok(report);
            }

            let observation = driver
                .goto(&task.start_url)
                .await
                .map_err(|source| journal_transport_error(&mut agent, "initial goto", source))?;
            current_origin = self.origin_for_url("initial observation", &observation.url)?;
            agent.record_session_started(task.start_url.clone())?;
            self.record_observation(&mut agent, &mut report, observation)?;
        } else {
            let observation = driver
                .observe()
                .await
                .map_err(|source| journal_transport_error(&mut agent, "resume observe", source))?;
            current_origin = self.origin_for_url("resume observation", &observation.url)?;
            self.record_observation(&mut agent, &mut report, observation)?;
        }

        while let Some(planned) = agent.next_step().cloned() {
            let index = agent.cursor().next_step;
            let driver_step = task
                .steps
                .get(index)
                .ok_or(AgentError::JournalHasExtraStep { index })?;

            // Resume safety (#99): a step whose intent was journaled in a prior run
            // but never completed may already have run its side effect. Do not
            // re-execute it, and do not let skill-store or policy recomputation
            // failures mask the durable interruption marker.
            if agent.next_step_already_attempted() {
                let policy = self.step_policy(
                    driver_step,
                    &planned.key,
                    current_origin.as_ref(),
                    driver_step.action.side_effect(),
                )?;
                let reason = RESUME_INTERRUPTED_REASON.to_string();
                let triple = agent.record_pending_interruption(reason.clone())?;
                report.actions_completed += 1;
                report.steps.push(AgentStepReport {
                    index,
                    policy,
                    triple,
                    observation_budget: None,
                });
                report.status = AgentRunStatus::Interrupted {
                    action_index: index,
                    reason,
                };
                return Ok(report);
            }

            // Read the skill store once and derive both the policy side-effect and
            // the compiled batch from that single snapshot (#98): the gate and the
            // executed actions can no longer disagree due to a between-reads mutation.
            let policy_origin = self.origin_for_step(driver_step, current_origin.as_ref())?;
            let compiled_skill = match &planned.action {
                Action::Skill { name, input } => Some(self.compile_skill_snapshot(name, input)?),
                _ => None,
            };
            let side_effect = match &compiled_skill {
                Some(skill) => skill.side_effect,
                None => driver_step.action.side_effect(),
            };
            let policy = self.step_policy(
                driver_step,
                &planned.key,
                policy_origin.as_ref(),
                side_effect,
            )?;

            if !policy.confirmed {
                let reason = policy_denied_reason(&policy);
                let triple = agent.record_next_outcome(StepOutcome::StepError {
                    reason: reason.clone(),
                })?;
                report.actions_completed += 1;
                report.steps.push(AgentStepReport {
                    index,
                    policy,
                    triple,
                    observation_budget: None,
                });
                report.status = AgentRunStatus::PolicyDenied {
                    action_index: index,
                    reason,
                };
                return Ok(report);
            }

            // Journal intent before the side effect runs (#99) so an interrupted
            // execution is detected — rather than silently repeated — on resume.
            agent.plan_next_step()?;

            let execution = match &compiled_skill {
                Some(skill) => execute_batch(driver, &skill.batch)
                    .await
                    .map_err(|source| {
                        journal_transport_error(&mut agent, "execute skill", source)
                    })?,
                None => execute_action(driver, &planned.action)
                    .await
                    .map_err(|source| {
                        journal_transport_error(&mut agent, "execute action", source)
                    })?,
            };
            // A batch StepError still fails the step. `PartiallyApplied` is a
            // StepError whose earlier actions already grounded — it must fail
            // the step exactly like a plain StepError (never a replayable no-op),
            // but the side effects are already captured by the forced post-batch
            // diff and the post-action observation below.
            let outcome = match execution.status {
                ExecutionStatus::Applied => StepOutcome::Applied {
                    diff: execution.diff,
                },
                ExecutionStatus::PartiallyApplied { reason }
                | ExecutionStatus::StepError { reason } => StepOutcome::StepError { reason },
            };
            let triple = agent.record_next_outcome(outcome)?;
            report.actions_completed += 1;

            let observation = driver.observe().await.map_err(|source| {
                journal_transport_error(&mut agent, "post-action observe", source)
            })?;
            current_origin = self.origin_for_url("post-action observation", &observation.url)?;
            let observation_budget =
                self.record_observation(&mut agent, &mut report, observation)?;
            let step_error = match &triple.outcome {
                StepTripleOutcome::StepError { reason } => Some(reason.clone()),
                StepTripleOutcome::Applied { .. } => None,
            };
            report.steps.push(AgentStepReport {
                index,
                policy,
                triple,
                observation_budget: Some(observation_budget),
            });

            if let Some(reason) = step_error {
                report.status = AgentRunStatus::StepError {
                    action_index: index,
                    reason,
                };
                return Ok(report);
            }
        }

        agent.close_session()?;
        report.status = AgentRunStatus::Completed;
        Ok(report)
    }

    /// Read a skill from the store exactly once and return both its declared
    /// side-effect (for the policy gate) and its fully expanded action batch (for
    /// execution). Single snapshot closes the TOCTOU gap between gate and compile
    /// (#98) and enforces the expansion bounds (#97).
    fn compile_skill_snapshot(
        &self,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<CompiledSkill, AgentError> {
        let root = self
            .skill_store_root
            .as_ref()
            .ok_or_else(|| AgentError::SkillStoreNotConfigured(name.to_string()))?;
        let store = SkillStore::open(root)?;
        let key = store.resolve(name)?;
        let definition = store.get(&key)?;
        let side_effect = definition.side_effect;
        let mut stack = vec![name.to_string()];
        let mut total_actions = 0_usize;
        let batch = expand_skill_batch(
            &store,
            definition.compile(input)?,
            &mut stack,
            &mut total_actions,
        )?;
        Ok(CompiledSkill { side_effect, batch })
    }

    fn record_observation(
        &self,
        agent: &mut AgentLoop,
        report: &mut AgentRunReport,
        observation: CompiledObservation,
    ) -> Result<ObservationBudget, AgentError> {
        let budget = self.observation_budget.validate(&observation)?;
        report.observations += 1;
        report.max_observation_bytes = report.max_observation_bytes.max(budget.bytes);
        report.max_observation_tokens = report.max_observation_tokens.max(budget.estimated_tokens);
        agent.record_observation(observation)?;
        Ok(budget)
    }

    fn origin_for_step(
        &self,
        step: &DriverStep,
        current_origin: Option<&Origin>,
    ) -> Result<Option<Origin>, AgentError> {
        match &step.action {
            Action::Goto { url } => self
                .origin_for_url("planned goto", url)
                .map(|origin| origin.or_else(|| current_origin.cloned())),
            _ => Ok(current_origin.cloned()),
        }
    }

    fn origin_for_url(
        &self,
        context: &'static str,
        url: &str,
    ) -> Result<Option<Origin>, AgentError> {
        match Origin::parse(url) {
            Ok(origin) => Ok(Some(origin)),
            Err(_reason) if self.origin_policy.rules().is_empty() => Ok(None),
            Err(reason) => Err(AgentError::InvalidOrigin {
                context,
                url: url.to_string(),
                reason,
            }),
        }
    }

    fn step_policy(
        &self,
        step: &DriverStep,
        key: &IdempotencyKey,
        origin: Option<&Origin>,
        side_effect: SideEffect,
    ) -> Result<StepPolicyReport, AgentError> {
        let scoped = self
            .origin_policy
            .decide_effect(origin, side_effect, step.input_taint);
        let decision = scoped.decision;
        let denied = scoped.blocked();
        Ok(StepPolicyReport {
            origin: scoped.origin.as_ref().map(origin_label),
            side_effect: decision.side_effect,
            input_tainted: decision.input_taint.is_tainted(),
            confirmation_gate: decision.gate,
            confirmed: !denied && self.confirmation_mode.permits(decision.gate),
            denied,
            denial_reason: if denied {
                Some(format!(
                    "origin policy {:?} matched {} rule(s)",
                    scoped.rule_mode, scoped.matched_rules
                ))
            } else {
                None
            },
            origin_rules_matched: scoped.matched_rules,
            origin_rule_mode: scoped.rule_mode,
            idempotency_key: key.clone(),
        })
    }
}

/// One skill read as a single snapshot: its declared side-effect and its fully
/// expanded, bounded action batch. Both are derived from one store read so the
/// policy gate and the executed actions cannot diverge (#98).
struct CompiledSkill {
    side_effect: SideEffect,
    batch: ActionBatch,
}

/// Recursively expand nested `Action::Skill` entries in `batch` into concrete
/// actions, enforcing both bounds from #97:
///
/// * `stack` (the active expansion path) caps recursion depth and still detects
///   cycles, and
/// * `total_actions` caps the number of concrete actions produced across the
///   whole expansion, aborting billion-laughs–style width×depth amplification
///   before the flattened vector can exhaust memory.
fn expand_skill_batch(
    store: &SkillStore,
    batch: ActionBatch,
    stack: &mut Vec<String>,
    total_actions: &mut usize,
) -> Result<ActionBatch, AgentError> {
    if stack.len() > MAX_SKILL_EXPANSION_DEPTH {
        return Err(AgentError::SkillExpansionTooDeep {
            depth: stack.len(),
            max: MAX_SKILL_EXPANSION_DEPTH,
        });
    }

    let mut actions = Vec::new();
    for action in batch.actions {
        match action {
            Action::Skill { name, input } => {
                if stack.iter().any(|active| active == &name) {
                    return Err(AgentError::SkillCycle(name));
                }
                let key = store.resolve(&name)?;
                let nested_batch = store.compile(&key, &input)?;
                stack.push(name);
                let nested = expand_skill_batch(store, nested_batch, stack, total_actions)?;
                stack.pop();
                actions.extend(nested.actions);
            }
            other => {
                *total_actions += 1;
                if *total_actions > MAX_SKILL_EXPANSION_ACTIONS {
                    return Err(AgentError::SkillExpansionTooLarge {
                        max: MAX_SKILL_EXPANSION_ACTIONS,
                    });
                }
                actions.push(other);
            }
        }
    }

    Ok(ActionBatch {
        actions,
        quiescence: batch.quiescence,
    })
}

/// Durable report for one live-driver run attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRunReport {
    pub engine: Engine,
    pub journal_path: PathBuf,
    pub status: AgentRunStatus,
    pub initial_journal_entries: usize,
    pub actions_completed: usize,
    pub observations: usize,
    pub max_observation_bytes: usize,
    pub max_observation_tokens: usize,
    pub steps: Vec<AgentStepReport>,
}

impl AgentRunReport {
    fn new(
        engine: Engine,
        journal_path: PathBuf,
        initial_journal_entries: usize,
        actions_completed: usize,
    ) -> Self {
        Self {
            engine,
            journal_path,
            status: AgentRunStatus::Running,
            initial_journal_entries,
            actions_completed,
            observations: 0,
            max_observation_bytes: 0,
            max_observation_tokens: 0,
            steps: Vec::new(),
        }
    }

    pub fn succeeded(&self) -> bool {
        matches!(
            self.status,
            AgentRunStatus::Completed | AgentRunStatus::AlreadyComplete
        )
    }
}

/// Terminal state for a live-driver run attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentRunStatus {
    Running,
    Completed,
    AlreadyComplete,
    StructuredFastPath(StructuredFastPathDecision),
    StepError {
        action_index: usize,
        reason: String,
    },
    PolicyDenied {
        action_index: usize,
        reason: String,
    },
    /// A prior run planned this step but never journaled its outcome; resume
    /// declined to re-execute it to avoid duplicating a side effect (#99).
    Interrupted {
        action_index: usize,
        reason: String,
    },
}

/// One live action's policy and durable outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentStepReport {
    pub index: usize,
    pub policy: StepPolicyReport,
    pub triple: StepTriple,
    pub observation_budget: Option<ObservationBudget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepPolicyReport {
    pub origin: Option<String>,
    pub side_effect: SideEffect,
    pub input_tainted: bool,
    pub confirmation_gate: ConfirmationGate,
    pub confirmed: bool,
    pub denied: bool,
    pub denial_reason: Option<String>,
    pub origin_rules_matched: usize,
    pub origin_rule_mode: OriginRuleMode,
    pub idempotency_key: IdempotencyKey,
}

/// Durable StepTriple emitted from the journal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StepTriple {
    pub key: IdempotencyKey,
    pub seq: u64,
    pub action: Action,
    pub outcome: StepTripleOutcome,
}

impl StepTriple {
    fn from_event(
        key: IdempotencyKey,
        seq: u64,
        action: Action,
        event: JournalEvent,
    ) -> Result<Self, AgentError> {
        let outcome = match event {
            JournalEvent::StepApplied { diff, .. } => StepTripleOutcome::Applied { diff },
            JournalEvent::StepError { reason, .. } => StepTripleOutcome::StepError { reason },
            _ => return Err(AgentError::JournalEventIsNotStep { seq }),
        };
        Ok(Self {
            key,
            seq,
            action,
            outcome,
        })
    }
}

/// StepTriple outcome persisted for observability and replay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StepTripleOutcome {
    Applied { diff: ObservationDiff },
    StepError { reason: String },
}

/// Rebuild StepTriples from a real session journal and the original plan.
pub fn step_triples_from_journal(
    journal_path: impl AsRef<Path>,
    plan: &TaskPlan,
) -> Result<Vec<StepTriple>, AgentError> {
    let entries = read_journal_entries(journal_path)?;
    let mut triples = Vec::new();
    let mut step_index = 0_usize;

    for entry in entries {
        match entry.event {
            JournalEvent::StepApplied { ref action, .. }
            | JournalEvent::StepError { ref action, .. } => {
                let planned = plan
                    .steps
                    .get(step_index)
                    .ok_or(AgentError::JournalHasExtraStep { index: step_index })?;
                if &planned.action != action {
                    return Err(AgentError::JournalDiverged { index: step_index });
                }
                triples.push(StepTriple::from_event(
                    planned.key.clone(),
                    entry.seq,
                    planned.action.clone(),
                    entry.event,
                )?);
                step_index += 1;
            }
            JournalEvent::SessionStarted { .. }
            | JournalEvent::Observation { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::TransportError { .. }
            | JournalEvent::CassetteRecorded { .. }
            | JournalEvent::SessionClosed => {}
        }
    }

    Ok(triples)
}

/// Rebuild StepTriples from journaled step outcomes without requiring the
/// original task plan artifact.
pub fn step_triples_from_journal_entries(
    entries: &[JournalEntry],
) -> Result<Vec<StepTriple>, AgentError> {
    let mut triples = Vec::new();

    for entry in entries {
        match &entry.event {
            JournalEvent::StepApplied { action, .. } | JournalEvent::StepError { action, .. } => {
                let index = triples.len();
                let key = IdempotencyKey::for_action(index, action)?;
                triples.push(StepTriple::from_event(
                    key,
                    entry.seq,
                    action.clone(),
                    entry.event.clone(),
                )?);
            }
            JournalEvent::SessionStarted { .. }
            | JournalEvent::Observation { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::TransportError { .. }
            | JournalEvent::CassetteRecorded { .. }
            | JournalEvent::SessionClosed => {}
        }
    }

    Ok(triples)
}

/// Rebuild StepTriples from a journal path without requiring the original task
/// plan artifact.
pub fn step_triples_from_journal_without_plan(
    journal_path: impl AsRef<Path>,
) -> Result<Vec<StepTriple>, AgentError> {
    let entries = read_journal_entries(journal_path)?;
    step_triples_from_journal_entries(&entries)
}

fn journal_transport_error(
    agent: &mut AgentLoop,
    context: &'static str,
    source: TransportError,
) -> AgentError {
    match agent.record_transport_error(context, &source) {
        Ok(()) => AgentError::transport(context, source),
        Err(error) => error,
    }
}

fn has_session_started(entries: &[JournalEntry]) -> bool {
    entries
        .iter()
        .any(|entry| matches!(entry.event, JournalEvent::SessionStarted { .. }))
}

fn is_policy_denial_reason(reason: &str) -> bool {
    reason.starts_with("policy requires") || reason.starts_with("policy denied")
}

fn policy_denied_reason(policy: &StepPolicyReport) -> String {
    if policy.denied {
        let origin = policy.origin.as_deref().unwrap_or("unknown origin");
        let reason = policy
            .denial_reason
            .as_deref()
            .unwrap_or("origin policy denied this action");
        return format!(
            "policy denied {:?} at {origin}: {reason}",
            policy.side_effect
        );
    }

    format!(
        "policy requires {:?} for {:?}",
        policy.confirmation_gate, policy.side_effect
    )
}

fn origin_label(origin: &Origin) -> String {
    match origin.port {
        Some(port) => format!("{}://{}:{port}", origin.scheme, origin.host),
        None => format!("{}://{}", origin.scheme, origin.host),
    }
}

/// Conservative token estimate used only for local observation budget checks.
pub fn estimate_tokens(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "durable agent loop core with live driver execution, token budgets, idempotent resume, and StepTriple extraction"
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("agent JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("skill store failed: {0}")]
    Skill(#[from] SkillError),
    #[error("skill store is not configured for skill action: {0}")]
    SkillStoreNotConfigured(String),
    #[error("skill expansion cycle detected at: {0}")]
    SkillCycle(String),
    #[error("skill expansion exceeded max depth {max} (reached {depth})")]
    SkillExpansionTooDeep { depth: usize, max: usize },
    #[error("skill expansion exceeded max of {max} total actions")]
    SkillExpansionTooLarge { max: usize },
    #[error("transport error during {context}: {source}")]
    Transport {
        context: String,
        source: TransportError,
    },
    #[error("invalid origin during {context}: {url}: {reason}")]
    InvalidOrigin {
        context: &'static str,
        url: String,
        reason: OriginError,
    },
    #[error("token budget exceeded: attempted {attempted}, max {max}")]
    TokenBudgetExceeded { attempted: u64, max: u64 },
    #[error(
        "observation budget exceeded: {bytes} bytes/{estimated_tokens} tokens, max {max_bytes} bytes/{max_tokens} tokens"
    )]
    ObservationBudgetExceeded {
        bytes: usize,
        max_bytes: usize,
        estimated_tokens: usize,
        max_tokens: usize,
    },
    #[error("task plan is already complete")]
    PlanComplete,
    #[error("journal action diverged from plan at step {index}")]
    JournalDiverged { index: usize },
    #[error("journal contains extra step at index {index}")]
    JournalHasExtraStep { index: usize },
    #[error("journal event at seq {seq} is not a step outcome")]
    JournalEventIsNotStep { seq: u64 },
}

impl AgentError {
    fn transport(context: impl Into<String>, source: TransportError) -> Self {
        Self::Transport {
            context: context.into(),
            source,
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_driver::TestDriver;
    use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
    use tempo_policy::{OriginPolicy, OriginRule, OriginRuleMode};
    use tempo_schema::{
        InteractiveElement, NodeId, ObservationDiff, Provenance, QuiescencePolicy, TaintSpan,
    };
    use tempo_skills::{ActionTemplate, SkillDefinition, SkillInput, SkillStore, TemplateString};

    type TestResult = Result<(), Box<dyn Error>>;

    fn is_lower_hex(value: &str) -> bool {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    #[test]
    fn token_budget_rejects_overrun() {
        let mut budget = TokenBudget::new(10);

        assert!(budget.charge(7).is_ok());
        assert_eq!(budget.remaining(), 3);
        assert!(matches!(
            budget.charge(4),
            Err(AgentError::TokenBudgetExceeded {
                attempted: 11,
                max: 10
            })
        ));
    }

    #[test]
    fn idempotency_key_is_deterministic_sha256_hex() -> TestResult {
        let action = Action::Click {
            node: NodeId("submit".into()),
        };

        let key = IdempotencyKey::for_action(0, &action)?;
        let repeated = IdempotencyKey::for_action(0, &action)?;

        assert_eq!(key, repeated);
        assert_eq!(key.0.len(), 64);
        assert!(is_lower_hex(&key.0));
        Ok(())
    }

    #[test]
    fn idempotency_key_separates_action_index_and_payload() -> TestResult {
        let click = Action::Click {
            node: NodeId("submit".into()),
        };
        let other_click = Action::Click {
            node: NodeId("cancel".into()),
        };

        assert_ne!(
            IdempotencyKey::for_action(0, &click)?,
            IdempotencyKey::for_action(1, &click)?
        );
        assert_ne!(
            IdempotencyKey::for_action(0, &click)?,
            IdempotencyKey::for_action(0, &other_click)?
        );
        Ok(())
    }

    #[test]
    fn agent_loop_records_real_journal_entries() -> TestResult {
        let root = unique_dir("record")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let plan = TaskPlan::from_actions(vec![Action::Scroll { x: 0.0, y: 32.0 }], 12)?;
        let mut agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan.clone(),
            TokenBudget::new(20),
        )?;

        let triple = agent.record_next_outcome(StepOutcome::Applied { diff: diff(0, 1) })?;
        let entries = read_journal_entries(&journal_path)?;
        let triples = step_triples_from_journal(&journal_path, &plan)?;

        assert_eq!(entries.len(), 2);
        assert!(matches!(
            entries[0].event,
            JournalEvent::ActionPlanned { .. }
        ));
        assert!(matches!(entries[1].event, JournalEvent::StepApplied { .. }));
        assert_eq!(triple.seq, 1);
        assert_eq!(triples, vec![triple]);
        assert_eq!(agent.budget().used_tokens, 12);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn journal_entries_rebuild_step_triples_without_plan() -> TestResult {
        let root = unique_dir("journal-step-triples")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let first = Action::Scroll { x: 0.0, y: 1.0 };
        let second = Action::Scroll { x: 0.0, y: 2.0 };
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://session.test".into(),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: first.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action: first.clone(),
            diff: diff(0, 1),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: second.clone(),
        })?;
        journal.append(JournalEvent::StepError {
            action: second.clone(),
            reason: "not present".into(),
        })?;
        journal.append(JournalEvent::SessionClosed)?;
        drop(journal);

        let entries = read_journal_entries(&journal_path)?;
        let triples = step_triples_from_journal_entries(&entries)?;
        let path_triples = step_triples_from_journal_without_plan(&journal_path)?;

        assert_eq!(triples, path_triples);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0].seq, 2);
        assert_eq!(triples[0].key, IdempotencyKey::for_action(0, &first)?);
        assert_eq!(triples[0].action, first);
        assert!(matches!(
            triples[0].outcome,
            StepTripleOutcome::Applied { .. }
        ));
        assert_eq!(triples[1].seq, 4);
        assert_eq!(triples[1].key, IdempotencyKey::for_action(1, &second)?);
        assert_eq!(triples[1].action, second);
        assert!(matches!(
            triples[1].outcome,
            StepTripleOutcome::StepError { .. }
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn journal_entries_ignore_pending_planned_action() -> TestResult {
        let root = unique_dir("journal-pending-plan")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let completed = Action::Scroll { x: 0.0, y: 1.0 };
        let pending = Action::Scroll { x: 0.0, y: 2.0 };
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: completed.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action: completed.clone(),
            diff: diff(0, 1),
        })?;
        journal.append(JournalEvent::ActionPlanned { action: pending })?;
        drop(journal);

        let triples = step_triples_from_journal_without_plan(&journal_path)?;

        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].key, IdempotencyKey::for_action(0, &completed)?);
        assert_eq!(triples[0].action, completed);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_skips_completed_steps_and_reuses_pending_plan() -> TestResult {
        let root = unique_dir("resume")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let first = Action::Scroll { x: 0.0, y: 1.0 };
        let second = Action::Scroll { x: 0.0, y: 2.0 };
        let plan = TaskPlan::from_actions(vec![first.clone(), second.clone()], 5)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: first.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action: first,
            diff: diff(0, 1),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: second.clone(),
        })?;
        drop(journal);

        let mut agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan,
            TokenBudget::new(20),
        )?;

        assert_eq!(agent.cursor().completed_steps, 1);
        assert_eq!(agent.next_step().map(|step| &step.action), Some(&second));
        assert!(agent.cursor().pending_planned.is_some());
        assert_eq!(agent.budget().used_tokens, 5);

        agent.record_next_outcome(StepOutcome::StepError {
            reason: "not present".into(),
        })?;
        let entries = read_journal_entries(&journal_path)?;

        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[3].event, JournalEvent::StepError { .. }));
        assert_eq!(agent.budget().used_tokens, 10);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_restores_completed_token_budget_and_rejects_overrun() -> TestResult {
        let root = unique_dir("resume-budget-overrun")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let first = Action::Scroll { x: 0.0, y: 1.0 };
        let second = Action::Scroll { x: 0.0, y: 2.0 };
        let plan = TaskPlan::from_actions(vec![first.clone(), second], 7)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: first.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action: first,
            diff: diff(0, 1),
        })?;
        drop(journal);

        assert!(matches!(
            AgentLoop::open(
                &journal_path,
                RunId("run".into()),
                SessionId("session".into()),
                plan,
                TokenBudget::new(6),
            ),
            Err(AgentError::TokenBudgetExceeded {
                attempted: 7,
                max: 6,
            })
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_restores_step_error_token_budget() -> TestResult {
        let root = unique_dir("resume-budget-step-error")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Scroll { x: 0.0, y: 1.0 };
        let plan = TaskPlan::from_actions(vec![action.clone()], 6)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        journal.append(JournalEvent::StepError {
            action,
            reason: "not present".into(),
        })?;
        drop(journal);

        let agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan,
            TokenBudget::new(10),
        )?;

        assert_eq!(agent.cursor().completed_steps, 1);
        assert_eq!(agent.budget().used_tokens, 6);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_derives_budget_from_journal_not_incoming_used_tokens() -> TestResult {
        let root = unique_dir("resume-budget-nonzero-input")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Scroll { x: 0.0, y: 1.0 };
        let plan = TaskPlan::from_actions(vec![action.clone()], 3)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action,
            diff: diff(0, 1),
        })?;
        drop(journal);

        let agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan,
            TokenBudget {
                max_tokens: 10,
                used_tokens: 5,
            },
        )?;

        assert_eq!(agent.budget().used_tokens, 3);
        assert_eq!(agent.budget().remaining(), 7);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_interruption_does_not_charge_dangling_planned_step() -> TestResult {
        let root = unique_dir("resume-budget-pending")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let first = Action::Scroll { x: 0.0, y: 1.0 };
        let second = Action::Scroll { x: 0.0, y: 2.0 };
        let plan = TaskPlan::from_actions(vec![first.clone(), second.clone()], 4)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::ActionPlanned {
            action: first.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action: first,
            diff: diff(0, 1),
        })?;
        journal.append(JournalEvent::ActionPlanned { action: second })?;
        drop(journal);

        let mut agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan,
            TokenBudget::new(8),
        )?;

        assert_eq!(agent.budget().used_tokens, 4);
        assert!(agent.next_step_already_attempted());

        agent.record_pending_interruption(RESUME_INTERRUPTED_REASON)?;

        assert_eq!(agent.budget().used_tokens, 4);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resume_rejects_divergent_journal() -> TestResult {
        let root = unique_dir("diverge")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let plan = TaskPlan::from_actions(vec![Action::Scroll { x: 0.0, y: 1.0 }], 5)?;
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::StepApplied {
            action: Action::Scroll { x: 0.0, y: 99.0 },
            diff: diff(0, 1),
        })?;
        drop(journal);

        assert!(matches!(
            AgentLoop::open(
                &journal_path,
                RunId("run".into()),
                SessionId("session".into()),
                plan,
                TokenBudget::new(20),
            ),
            Err(AgentError::JournalDiverged { index: 0 })
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn completed_keys_returns_durable_prefix_keys() -> TestResult {
        let root = unique_dir("keys")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Scroll { x: 0.0, y: 4.0 };
        let plan = TaskPlan::from_actions(vec![action], 1)?;
        let expected = plan.steps[0].key.clone();
        let mut agent = AgentLoop::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan,
            TokenBudget::new(10),
        )?;

        agent.record_next_outcome(StepOutcome::Applied { diff: diff(0, 1) })?;

        assert_eq!(agent.completed_keys(), BTreeSet::from([expected]));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_executes_test_driver_and_journals_live_outcomes() -> TestResult {
        let root = unique_dir("runner-test-driver")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-test-driver", "session-test-driver"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.engine, Engine::Test);
        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert!(report.max_observation_bytes > 0);
        assert_eq!(report.steps[0].policy.idempotency_key.0.len(), 64);
        assert!(is_lower_hex(&report.steps[0].policy.idempotency_key.0));

        let entries = read_journal_entries(&journal_path)?;
        assert!(matches!(
            entries.first().map(|entry| &entry.event),
            Some(JournalEvent::SessionStarted { .. })
        ));
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));
        assert!(matches!(
            entries.last().map(|entry| &entry.event),
            Some(JournalEvent::SessionClosed)
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_structured_fast_path_skips_initial_driver_navigation() -> TestResult {
        let root = unique_dir("runner-structured-fast-path")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://structured.example/app",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-structured", "session-structured"),
        )
        .with_structured_fast_path(StructuredFastPath::with_probe(fake_mcp_fast_path_probe));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(
            report.status,
            AgentRunStatus::StructuredFastPath(StructuredFastPathDecision::new(
                "https://structured.example",
                StructuredLane::Mcp,
                StructuredSignal::McpCatalog,
                "/mcp/catalog.json"
            ))
        );
        assert_eq!(driver.goto_calls, 0);
        assert_eq!(report.actions_completed, 0);
        assert_eq!(report.observations, 0);
        assert!(read_journal_entries(&journal_path)?.is_empty());

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_render_fast_path_decision_falls_through_to_driver() -> TestResult {
        let root = unique_dir("runner-render-fast-path")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new("https://render.example/app", vec![]);
        let mut driver = FailingDriver::new(TransportFailurePoint::PostActionObserve);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-render", "session-render"),
        )
        .with_structured_fast_path(StructuredFastPath::with_probe(fake_render_probe));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(driver.goto_calls, 1);
        assert_eq!(report.observations, 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_journals_initial_goto_transport_error() -> TestResult {
        let root = unique_dir("runner-transport-goto")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new("https://example.com", vec![]);
        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-transport-goto", "session-transport-goto"),
        );

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert!(matches!(
            error,
            Some(AgentError::Transport {
                context,
                source: TransportError::NavTimeout,
            }) if context == "initial goto"
        ));
        let entries = read_journal_entries(&journal_path)?;
        assert_eq!(entries.len(), 1);
        assert!(has_transport_error(
            &entries,
            "initial goto",
            "navigation timed out"
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_journals_execute_action_transport_error() -> TestResult {
        let root = unique_dir("runner-transport-action")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver =
            FailingDriver::new(TransportFailurePoint::Act).with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-transport-action", "session-transport-action"),
        );

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert!(matches!(
            error,
            Some(AgentError::Transport { context, .. }) if context == "execute action"
        ));
        let entries = read_journal_entries(&journal_path)?;
        let planned_pos = entries
            .iter()
            .position(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. }));
        let transport_pos = entries.iter().position(|entry| {
            matches!(
                &entry.event,
                JournalEvent::TransportError { context, reason }
                    if context == "execute action" && reason.contains("act failed")
            )
        });
        assert!(matches!(
            (planned_pos, transport_pos),
            (Some(planned), Some(transport)) if planned < transport
        ));
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_journals_post_action_observe_transport_error() -> TestResult {
        let root = unique_dir("runner-transport-post-observe")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = FailingDriver::new(TransportFailurePoint::PostActionObserve)
            .with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new(
                "run-transport-post-observe",
                "session-transport-post-observe",
            ),
        );

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert!(matches!(
            error,
            Some(AgentError::Transport { context, .. }) if context == "post-action observe"
        ));
        let entries = read_journal_entries(&journal_path)?;
        let applied_pos = entries
            .iter()
            .position(|entry| matches!(entry.event, JournalEvent::StepApplied { .. }));
        let transport_pos = entries.iter().position(|entry| {
            matches!(
                &entry.event,
                JournalEvent::TransportError { context, reason }
                    if context == "post-action observe" && reason.contains("engine crashed")
            )
        });
        assert!(matches!(
            (applied_pos, transport_pos),
            (Some(applied), Some(transport)) if applied < transport
        ));
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::SessionClosed)));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_expands_persisted_skill_and_journals_original_action() -> TestResult {
        let root = unique_dir("runner-skill")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let skills_root = root.join("skills");
        let store = SkillStore::open(&skills_root)?;
        store.put(&click_skill("click_saved_target", "1"))?;
        store.put(&nested_click_skill("2"))?;
        store.put(&click_skill("click_inner", "1"))?;
        let journal_path = root.join("session.jsonl");
        let skill_action = Action::Skill {
            name: "click_saved_target".into(),
            input: serde_json::json!({"target": "submit"}),
        };
        let task = DriverTask::new("https://example.com", vec![skill_action.clone()]);
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-skill", "session-skill"),
        )
        .with_skill_store(&skills_root);

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert!(matches!(
            report.steps[0].triple.outcome,
            StepTripleOutcome::Applied { .. }
        ));

        let entries = read_journal_entries(&journal_path)?;
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::ActionPlanned { action } if action == &skill_action
        )));
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::StepApplied { action, .. } if action == &skill_action
        )));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_denies_purchase_skill_before_driver_execution() -> TestResult {
        let root = unique_dir("runner-purchase-skill-policy")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let skills_root = root.join("skills");
        let store = SkillStore::open(&skills_root)?;
        let mut skill = click_skill("buy_saved_target", "1");
        skill.side_effect = SideEffect::Purchase;
        store.put(&skill)?;
        let journal_path = root.join("session.jsonl");
        let skill_action = Action::Skill {
            name: "buy_saved_target".into(),
            input: serde_json::json!({"target": "submit"}),
        };
        let task = DriverTask::new("https://example.com", vec![skill_action]);
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-purchase-skill-policy", "session-purchase-skill-policy"),
        )
        .with_skill_store(&skills_root);

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::PolicyDenied { .. }));
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.steps[0].policy.side_effect, SideEffect::Purchase);
        assert_eq!(
            report.steps[0].policy.confirmation_gate,
            ConfirmationGate::Confirm
        );
        assert!(!report.steps[0].policy.confirmed);
        assert!(matches!(
            report.steps[0].triple.outcome,
            StepTripleOutcome::StepError { .. }
        ));
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_reports_missing_skill_store_configuration() -> TestResult {
        let root = unique_dir("runner-skill-missing-store")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Skill {
                name: "click_saved_target".into(),
                input: serde_json::json!({"target": "submit"}),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-missing-skill-store", "session-missing-skill-store"),
        );

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert!(matches!(
            error,
            Some(AgentError::SkillStoreNotConfigured(name)) if name == "click_saved_target"
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_resume_does_not_duplicate_completed_live_steps() -> TestResult {
        let root = unique_dir("runner-resume")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let ids = AgentRunIds::new("run-resume", "session-resume");

        let mut first_driver = TestDriver::new().with_elements(vec![button("submit")]);
        let first_runner = AgentRunner::new(&journal_path, ids.clone());
        let first = first_runner
            .run_driver_task(&mut first_driver, &task)
            .await?;
        assert_eq!(first.status, AgentRunStatus::Completed);
        let entry_count = read_journal_entries(&journal_path)?.len();

        let mut second_driver = TestDriver::new().with_elements(vec![button("submit")]);
        let second_runner = AgentRunner::new(&journal_path, ids);
        let second = second_runner
            .run_driver_task(&mut second_driver, &task)
            .await?;

        assert_eq!(second.status, AgentRunStatus::AlreadyComplete);
        assert_eq!(read_journal_entries(&journal_path)?.len(), entry_count);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_denies_tainted_action_before_driver_execution() -> TestResult {
        let root = unique_dir("runner-policy")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::with_steps(
            "https://example.com",
            vec![DriverStep::tainted(Action::Click {
                node: NodeId("submit".into()),
            })],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-policy", "session-policy"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::PolicyDenied { .. }));
        assert_eq!(report.actions_completed, 1);
        assert!(matches!(
            report.steps[0].triple.outcome,
            StepTripleOutcome::StepError { .. }
        ));
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::SessionClosed)));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_denies_origin_block_before_driver_execution() -> TestResult {
        let root = unique_dir("runner-origin-deny")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let origin = Origin::parse("https://example.com")?;
        let task = DriverTask::new(
            "https://example.com/path",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-origin-deny", "session-origin-deny"),
        )
        .with_origin_policy(OriginPolicy::new(vec![OriginRule::new(
            origin,
            SideEffect::Read,
            OriginRuleMode::Block,
        )]));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(
            report.status,
            AgentRunStatus::PolicyDenied { ref reason, .. }
                if reason.contains("origin policy Block")
        ));
        assert_eq!(report.actions_completed, 1);
        assert_eq!(
            report.steps[0].policy.origin.as_deref(),
            Some("https://example.com:443")
        );
        assert!(report.steps[0].policy.denied);
        assert_eq!(report.steps[0].policy.origin_rules_matched, 1);
        assert_eq!(
            report.steps[0].policy.origin_rule_mode,
            OriginRuleMode::Block
        );
        assert!(matches!(
            report.steps[0].triple.outcome,
            StepTripleOutcome::StepError { .. }
        ));
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_applies_origin_confirmation_gate() -> TestResult {
        let root = unique_dir("runner-origin-gate")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let origin = Origin::parse("https://example.com")?;
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-origin-gate", "session-origin-gate"),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_origin_policy(OriginPolicy::new(vec![OriginRule::new(
            origin,
            SideEffect::Write,
            OriginRuleMode::RequireConfirmation,
        )]));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(
            report.steps[0].policy.origin.as_deref(),
            Some("https://example.com:443")
        );
        assert_eq!(
            report.steps[0].policy.confirmation_gate,
            ConfirmationGate::Confirm
        );
        assert!(report.steps[0].policy.confirmed);
        assert!(!report.steps[0].policy.denied);
        assert_eq!(
            report.steps[0].policy.origin_rule_mode,
            OriginRuleMode::RequireConfirmation
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_enforces_observation_budget_before_agent_context() -> TestResult {
        let root = unique_dir("runner-budget")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new("https://example.com", vec![]);
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-budget", "session-budget"),
        )
        .with_observation_budget(ObservationBudgetLimit {
            max_observation_bytes: 8,
            max_observation_tokens: 2,
        });

        let error = runner.run_driver_task(&mut driver, &task).await.err();
        assert!(matches!(
            error,
            Some(AgentError::ObservationBudgetExceeded { .. })
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cdp_runner_completes_scripted_task_and_journals_it() -> TestResult {
        let Some(chrome) = std::env::var("TEMPO_CDP_CHROME").ok() else {
            eprintln!("skipping live CDP agent smoke; TEMPO_CDP_CHROME is not set");
            return Ok(());
        };

        let url = serve_once(
            r#"<!doctype html>
            <html>
              <body>
                <button id="submit" onclick="document.body.setAttribute('data-clicked','yes'); this.textContent='Done';">Submit</button>
              </body>
            </html>"#,
        )?;
        let root = unique_dir("runner-live-cdp")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            url,
            vec![Action::Click {
                node: NodeId(r#"[id="submit"]"#.into()),
            }],
        );
        let mut driver = CdpTempoDriver::launch_with(CdpConfig::default().with_executable(chrome))
            .await?
            .allow_private_network_access();
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-live-cdp", "session-live-cdp"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;
        driver.close().await?;

        assert_eq!(report.engine, Engine::Cdp);
        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert!(read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_bounds_billion_laughs_skill_expansion() -> TestResult {
        let root = unique_dir("runner-billion-laughs")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let skills_root = root.join("skills");
        let store = SkillStore::open(&skills_root)?;

        // Each level fans out `fanout` times into the next skill; concrete actions
        // grow as fanout^depth (6^5 = 7776), far above MAX_SKILL_EXPANSION_ACTIONS
        // while the nesting depth (5) stays under MAX_SKILL_EXPANSION_DEPTH.
        let fanout = 6;
        let depth = 5;
        for level in 0..depth {
            let steps = if level + 1 == depth {
                (0..fanout)
                    .map(|_| ActionTemplate::Click {
                        node: TemplateString::literal("submit"),
                    })
                    .collect()
            } else {
                let child = format!("laugh_{}", level + 1);
                (0..fanout)
                    .map(|_| ActionTemplate::Skill {
                        name: TemplateString::literal(child.clone()),
                        input: serde_json::json!({}),
                    })
                    .collect()
            };
            store.put(&SkillDefinition {
                name: format!("laugh_{level}"),
                version: "1".into(),
                description: "billion laughs".into(),
                side_effect: SideEffect::Write,
                inputs: Vec::new(),
                quiescence: QuiescencePolicy::Composite,
                steps,
            })?;
        }

        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "https://example.com",
            vec![Action::Skill {
                name: "laugh_0".into(),
                input: serde_json::json!({}),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-billion-laughs", "session-billion-laughs"),
        )
        .with_skill_store(&skills_root);

        let error = runner.run_driver_task(&mut driver, &task).await.err();
        assert!(matches!(
            error,
            Some(AgentError::SkillExpansionTooLarge {
                max: MAX_SKILL_EXPANSION_ACTIONS
            })
        ));

        // The run aborted before any driver call: no live step was applied.
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn skill_gate_and_compile_use_one_consistent_snapshot() -> TestResult {
        let root = unique_dir("snapshot")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let skills_root = root.join("skills");
        let store = SkillStore::open(&skills_root)?;
        store.put(&click_skill("gated", "1"))?;
        let journal_path = root.join("session.jsonl");
        let runner = AgentRunner::new(&journal_path, AgentRunIds::new("run-snap", "session-snap"))
            .with_skill_store(&skills_root);
        let input = serde_json::json!({"target": "submit"});

        // A single read yields both the gate side-effect and the compiled batch.
        let snapshot = runner.compile_skill_snapshot("gated", &input)?;
        assert_eq!(snapshot.side_effect, SideEffect::Write);
        assert_eq!(snapshot.batch.actions.len(), 1);

        // Mutate the on-disk skill AFTER the snapshot: raise its side-effect and add
        // a second concrete step. A TOCTOU gate/compile split would let the gate
        // decide on the old low side-effect while a larger batch executes.
        let mut mutated = click_skill("gated", "1");
        mutated.side_effect = SideEffect::Purchase;
        mutated.steps = vec![
            ActionTemplate::Click {
                node: TemplateString::param("target"),
            },
            ActionTemplate::Click {
                node: TemplateString::param("target"),
            },
        ];
        store.put(&mutated)?;

        // The already-taken snapshot's gate side-effect and batch stay mutually
        // consistent, because both were derived from the same read.
        assert_eq!(snapshot.side_effect, SideEffect::Write);
        assert_eq!(snapshot.batch.actions.len(), 1);

        // A fresh snapshot observes the mutation atomically: gate and batch move
        // together (Purchase side-effect alongside the two-action batch).
        let after = runner.compile_skill_snapshot("gated", &input)?;
        assert_eq!(after.side_effect, SideEffect::Purchase);
        assert_eq!(after.batch.actions.len(), 2);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_resume_does_not_reexecute_planned_but_unjournaled_step() -> TestResult {
        let root = unique_dir("runner-resume-interrupted")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Click {
            node: NodeId("submit".into()),
        };
        let task = DriverTask::new("https://example.com", vec![action.clone()]);

        // Simulate a crash after intent was journaled (and the side effect may have
        // already fired) but before the outcome was recorded: SessionStarted plus a
        // dangling ActionPlanned, with no StepApplied.
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run-resume-interrupted".into()),
            SessionId("session-resume-interrupted".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        drop(journal);

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-resume-interrupted", "session-resume-interrupted"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        // Resume declines to re-run the step; had it re-executed, TestDriver would
        // have produced a StepApplied and completed the run.
        assert!(matches!(
            report.status,
            AgentRunStatus::Interrupted {
                action_index: 0,
                ..
            }
        ));
        let entries = read_journal_entries(&journal_path)?;
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::StepError { reason, .. } if reason == RESUME_INTERRUPTED_REASON
        )));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_resume_journals_interruption_when_budget_is_exhausted() -> TestResult {
        let root = unique_dir("runner-resume-interrupted-budget")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Click {
            node: NodeId("submit".into()),
        };
        let task = DriverTask::new("https://example.com", vec![action.clone()]);
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run-resume-interrupted-budget".into()),
            SessionId("session-resume-interrupted-budget".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        journal.append(JournalEvent::ActionPlanned { action })?;
        drop(journal);

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new(
                "run-resume-interrupted-budget",
                "session-resume-interrupted-budget",
            ),
        )
        .with_token_budget(TokenBudget::new(0));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::Interrupted { .. }));
        let entries = read_journal_entries(&journal_path)?;
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::StepError { reason, .. } if reason == RESUME_INTERRUPTED_REASON
        )));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_resume_interruption_preempts_missing_skill_store() -> TestResult {
        let root = unique_dir("runner-resume-interrupted-skill")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let action = Action::Skill {
            name: "missing".into(),
            input: serde_json::json!({}),
        };
        let task = DriverTask::new("https://example.com", vec![action.clone()]);
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run-resume-interrupted-skill".into()),
            SessionId("session-resume-interrupted-skill".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        journal.append(JournalEvent::ActionPlanned { action })?;
        drop(journal);

        let mut driver = TestDriver::new();
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new(
                "run-resume-interrupted-skill",
                "session-resume-interrupted-skill",
            ),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::Interrupted { .. }));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TransportFailurePoint {
        Goto,
        Act,
        PostActionObserve,
    }

    fn fake_mcp_fast_path_probe(
        _target: &str,
        _config: HttpProbeConfig,
    ) -> Option<StructuredFastPathDecision> {
        Some(StructuredFastPathDecision::new(
            "https://structured.example",
            StructuredLane::Mcp,
            StructuredSignal::McpCatalog,
            "/mcp/catalog.json",
        ))
    }

    fn fake_render_probe(
        target: &str,
        _config: HttpProbeConfig,
    ) -> Option<StructuredFastPathDecision> {
        if target.starts_with("structured://") {
            Some(StructuredFastPathDecision::new(
                "structured://fixture",
                StructuredLane::Api,
                StructuredSignal::OpenApi,
                "/openapi.json",
            ))
        } else {
            None
        }
    }

    struct FailingDriver {
        inner: TestDriver,
        failure: TransportFailurePoint,
        goto_calls: usize,
        observe_calls: usize,
    }

    impl FailingDriver {
        fn new(failure: TransportFailurePoint) -> Self {
            Self {
                inner: TestDriver::new(),
                failure,
                goto_calls: 0,
                observe_calls: 0,
            }
        }

        fn with_elements(mut self, elements: Vec<InteractiveElement>) -> Self {
            self.inner = self.inner.with_elements(elements);
            self
        }
    }

    #[async_trait::async_trait]
    impl DriverTrait for FailingDriver {
        fn engine(&self) -> Engine {
            Engine::Test
        }

        async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
            self.goto_calls += 1;
            if self.failure == TransportFailurePoint::Goto {
                return Err(TransportError::NavTimeout);
            }
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            self.observe_calls += 1;
            if self.failure == TransportFailurePoint::PostActionObserve && self.observe_calls == 2 {
                return Err(TransportError::EngineGone);
            }
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.inner.observe_diff(since_seq).await
        }

        async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
            if self.failure == TransportFailurePoint::Act {
                return Err(TransportError::Other("act failed".into()));
            }
            self.inner.act(action).await
        }

        async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            if self.failure == TransportFailurePoint::Act {
                return Err(TransportError::Other("act failed".into()));
            }
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, tempo_driver::Unsupported> {
            self.inner.fork().await
        }

        async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
            self.inner.extract(node).await
        }

        async fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<serde_json::Value, TransportError> {
            self.inner.evaluate_script(expression, await_promise).await
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            self.inner.screenshot().await
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.inner.close().await
        }
    }

    fn has_transport_error(entries: &[JournalEntry], context: &str, reason: &str) -> bool {
        entries.iter().any(|entry| {
            matches!(
                &entry.event,
                JournalEvent::TransportError {
                    context: recorded_context,
                    reason: recorded_reason,
                } if recorded_context == context && recorded_reason.contains(reason)
            )
        })
    }

    fn diff(since_seq: u64, seq: u64) -> ObservationDiff {
        ObservationDiff {
            since_seq,
            seq,
            added: vec![],
            removed: vec![],
            changed: vec![],
        }
    }

    fn button(id: &str) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(id.into()),
            role: "button".into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: "Submit".into(),
            }],
            value: vec![],
            bounds: Some([0.0, 0.0, 100.0, 30.0]),
            rank: 1.0,
        }
    }

    fn click_skill(name: &str, version: &str) -> SkillDefinition {
        SkillDefinition {
            name: name.into(),
            version: version.into(),
            description: "click a parameterized target".into(),
            side_effect: SideEffect::Write,
            inputs: vec![SkillInput::required("target")],
            quiescence: QuiescencePolicy::Composite,
            steps: vec![ActionTemplate::Click {
                node: TemplateString::param("target"),
            }],
        }
    }

    fn nested_click_skill(version: &str) -> SkillDefinition {
        SkillDefinition {
            name: "click_saved_target".into(),
            version: version.into(),
            description: "delegate click to an inner skill".into(),
            side_effect: SideEffect::Write,
            inputs: Vec::new(),
            quiescence: QuiescencePolicy::Composite,
            steps: vec![ActionTemplate::Skill {
                name: TemplateString::literal("click_inner"),
                input: serde_json::json!({"target": "submit"}),
            }],
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-agent-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn serve_once(body: &'static str) -> Result<String, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Ok(format!("http://{addr}/"))
    }
}
