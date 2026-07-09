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
use tempo_net::resolve_url_target;
use tempo_policy::{
    ConfirmationGate, InputTaint, Origin, OriginError, OriginPolicy, OriginRuleMode,
};
use tempo_schema::{Action, ActionBatch, CompiledObservation, ObservationDiff, SideEffect};
use tempo_session::{
    durable_retention_policy_from_env, read_journal_entries_with_retention_policy,
    DurableRetentionPolicy, JournalEntry, JournalError, JournalEvent, RunId, SessionId,
    SessionJournal,
};
use tempo_skills::{SkillError, SkillStore};
use tempo_taint::serialize_compact_observation_for_model;
use thiserror::Error;

pub mod decider;

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

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MCP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_PROTOCOL_VERSION_HEADER: &str = "MCP-Protocol-Version";
const MCP_SESSION_ID_HEADER: &str = "Mcp-Session-Id";
const CURRENT_LOCATION_SCRIPT: &str = "window.location.href";

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

    pub fn supports_driver_task(&self, task: &DriverTask) -> bool {
        if !matches!(
            (self.lane, self.signal),
            (StructuredLane::Mcp, StructuredSignal::McpCatalog)
        ) {
            return false;
        }
        if self.mcp_endpoint_path().is_none() {
            return false;
        }
        task.steps
            .iter()
            .all(|step| matches!(step.action, Action::Skill { .. }))
    }

    fn mcp_endpoint_url(&self) -> Result<reqwest::Url, AgentError> {
        let endpoint_path =
            self.mcp_endpoint_path()
                .ok_or_else(|| AgentError::StructuredFastPathUnsupported {
                    reason: format!(
                        "structured MCP source is not an executable catalog endpoint: {}",
                        self.source
                    ),
                })?;
        let mut endpoint = reqwest::Url::parse(&self.origin).map_err(|error| {
            AgentError::InvalidStructuredEndpoint {
                value: self.origin.clone(),
                reason: error.to_string(),
            }
        })?;
        endpoint.set_path(endpoint_path);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }

    fn mcp_endpoint_path(&self) -> Option<&str> {
        let source = self.source.trim();
        source
            .strip_suffix("/catalog.json")
            .filter(|path| !path.is_empty() && path.starts_with('/'))
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

    pub fn ensure_available(&self, tokens: u64) -> Result<(), AgentError> {
        let attempted = self.used_tokens.saturating_add(tokens);
        if attempted > self.max_tokens {
            return Err(AgentError::TokenBudgetExceeded {
                attempted,
                max: self.max_tokens,
            });
        }
        Ok(())
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
                | JournalEvent::StructuredFastPathSelected { .. }
                | JournalEvent::Observation { .. }
                | JournalEvent::ModelDecision { .. }
                | JournalEvent::HumanTakeoverRequired { .. }
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
        let retention_policy = durable_retention_policy_from_env()?;
        Self::open_with_retention_policy(
            journal_path,
            run_id,
            session_id,
            plan,
            budget,
            retention_policy,
        )
    }

    pub fn open_plaintext_unsafe(
        journal_path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        plan: TaskPlan,
        budget: TokenBudget,
    ) -> Result<Self, AgentError> {
        Self::open_with_retention_policy(
            journal_path,
            run_id,
            session_id,
            plan,
            budget,
            DurableRetentionPolicy::PlaintextUnsafe,
        )
    }

    pub fn open_with_retention_policy(
        journal_path: impl AsRef<Path>,
        run_id: RunId,
        session_id: SessionId,
        plan: TaskPlan,
        budget: TokenBudget,
        retention_policy: DurableRetentionPolicy,
    ) -> Result<Self, AgentError> {
        let journal_path = journal_path.as_ref().to_path_buf();
        let journal = SessionJournal::open_with_retention_policy(
            &journal_path,
            run_id,
            session_id,
            retention_policy.clone(),
        )?;
        let entries = read_journal_entries_with_retention_policy(&journal_path, &retention_policy)?;
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

    pub fn ensure_next_step_budget(&self) -> Result<(), AgentError> {
        let step = self.next_step().ok_or(AgentError::PlanComplete)?;
        self.budget.ensure_available(step.estimated_tokens)
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

    pub fn record_structured_fast_path_selected(
        &mut self,
        decision: &StructuredFastPathDecision,
    ) -> Result<(), AgentError> {
        self.journal
            .append(JournalEvent::StructuredFastPathSelected {
                origin: decision.origin.clone(),
                lane: decision.lane_name().to_string(),
                signal: decision.signal_name().to_string(),
                source: decision.source.clone(),
            })?;
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

/// Measured compact model-facing projection size for evals and benchmark reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInputBudget {
    pub bytes: usize,
    pub estimated_tokens: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservationUse {
    ModelInput,
    AuditOnly,
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
    retention_policy: Option<DurableRetentionPolicy>,
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
            retention_policy: None,
        }
    }

    pub fn new_plaintext_unsafe(journal_path: impl AsRef<Path>, ids: AgentRunIds) -> Self {
        Self::new(journal_path, ids).with_retention_policy(DurableRetentionPolicy::PlaintextUnsafe)
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

    pub fn with_retention_policy(mut self, retention_policy: DurableRetentionPolicy) -> Self {
        self.retention_policy = Some(retention_policy);
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
        let (mut agent, initial_entries, mut report) =
            self.open_agent_report(AgentRunEngine::Driver(driver.engine()), task)?;

        if self.apply_resume_terminal_status(&agent, &mut report) {
            return Ok(report);
        }

        if let Some(decision) = structured_fast_path_decision_from_entries(&initial_entries)? {
            if !decision.skips_render() || !decision.supports_driver_task(task) {
                return Err(AgentError::StructuredFastPathUnsupported {
                    reason: format!(
                        "journaled lane={} signal={} cannot execute this task without a browser",
                        decision.lane_name(),
                        decision.signal_name()
                    ),
                });
            }
            report.engine = AgentRunEngine::Structured;
            return self
                .run_structured_agent_task(agent, report, &initial_entries, task, decision)
                .await;
        }

        let mut current_origin;
        if !has_session_started(&initial_entries) {
            if let Some(decision) = self.structured_fast_path.probe_target(&task.start_url)
                && decision.skips_render()
                && decision.supports_driver_task(task)
            {
                report.engine = AgentRunEngine::Structured;
                return self
                    .run_structured_agent_task(agent, report, &initial_entries, task, decision)
                    .await;
            }

            let observation = driver
                .goto(&task.start_url)
                .await
                .map_err(|source| journal_transport_error(&mut agent, "initial goto", source))?;
            current_origin = self.origin_for_url("initial observation", &observation.url)?;
            agent.record_session_started(task.start_url.clone())?;
            self.record_observation(
                &mut agent,
                &mut report,
                observation,
                ObservationUse::ModelInput,
            )?;
        } else {
            let observation = driver
                .observe()
                .await
                .map_err(|source| journal_transport_error(&mut agent, "resume observe", source))?;
            current_origin = self.origin_for_url("resume observation", &observation.url)?;
            self.record_observation(
                &mut agent,
                &mut report,
                observation,
                ObservationUse::ModelInput,
            )?;
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

            agent.ensure_next_step_budget()?;

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
            // the step exactly like a plain StepError (never a replayable no-op).
            // The side effects are already captured by the execution diff; the
            // post-action path refreshes origin cheaply unless the driver cannot
            // expose the current URL without a full observation.
            let side_effects_may_have_occurred = execution.applied_side_effects();
            let outcome = match execution.status {
                ExecutionStatus::Applied => StepOutcome::Applied {
                    diff: execution.diff,
                },
                ExecutionStatus::PartiallyApplied { reason }
                | ExecutionStatus::StepError { reason } => StepOutcome::StepError { reason },
            };
            let triple = agent.record_next_outcome(outcome)?;
            report.actions_completed += 1;

            let (next_origin, observation_budget) = self
                .refresh_post_action_origin(
                    &mut agent,
                    &mut report,
                    driver,
                    current_origin.as_ref(),
                    &planned.action,
                    side_effects_may_have_occurred,
                )
                .await?;
            current_origin = next_origin;
            let step_error = match &triple.outcome {
                StepTripleOutcome::StepError { reason } => Some(reason.clone()),
                StepTripleOutcome::Applied { .. } => None,
            };
            report.steps.push(AgentStepReport {
                index,
                policy,
                triple,
                observation_budget,
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

    pub async fn run_structured_task(
        &self,
        task: &DriverTask,
        decision: StructuredFastPathDecision,
    ) -> Result<AgentRunReport, AgentError> {
        if !decision.skips_render() || !decision.supports_driver_task(task) {
            return Err(AgentError::StructuredFastPathUnsupported {
                reason: format!(
                    "lane={} signal={} cannot execute this task without a browser",
                    decision.lane_name(),
                    decision.signal_name()
                ),
            });
        }

        let (agent, initial_entries, mut report) =
            self.open_agent_report(AgentRunEngine::Structured, task)?;
        if self.apply_resume_terminal_status(&agent, &mut report) {
            return Ok(report);
        }

        self.run_structured_agent_task(agent, report, &initial_entries, task, decision)
            .await
    }

    fn open_agent_report(
        &self,
        engine: AgentRunEngine,
        task: &DriverTask,
    ) -> Result<(AgentLoop, Vec<JournalEntry>, AgentRunReport), AgentError> {
        let plan = task.task_plan()?;
        let retention_policy = self.resolved_retention_policy()?;
        let agent = AgentLoop::open_with_retention_policy(
            &self.journal_path,
            self.ids.run_id.clone(),
            self.ids.session_id.clone(),
            plan,
            self.token_budget.clone(),
            retention_policy.clone(),
        )?;
        let initial_entries =
            read_journal_entries_with_retention_policy(agent.journal_path(), &retention_policy)?;
        let report = AgentRunReport::new(
            engine,
            agent.journal_path().to_path_buf(),
            initial_entries.len(),
            agent.cursor().completed_steps,
        );
        Ok((agent, initial_entries, report))
    }

    fn resolved_retention_policy(&self) -> Result<DurableRetentionPolicy, AgentError> {
        match &self.retention_policy {
            Some(retention_policy) => Ok(retention_policy.clone()),
            None => Ok(durable_retention_policy_from_env()?),
        }
    }

    fn apply_resume_terminal_status(&self, agent: &AgentLoop, report: &mut AgentRunReport) -> bool {
        if agent.cursor().closed && agent.is_complete() {
            report.status = AgentRunStatus::AlreadyComplete;
            return true;
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
            return true;
        }

        false
    }

    async fn run_structured_agent_task(
        &self,
        mut agent: AgentLoop,
        mut report: AgentRunReport,
        initial_entries: &[JournalEntry],
        task: &DriverTask,
        decision: StructuredFastPathDecision,
    ) -> Result<AgentRunReport, AgentError> {
        let current_origin = self.origin_for_url("structured fast path", &decision.origin)?;
        if !has_session_started(initial_entries) {
            agent.record_session_started(task.start_url.clone())?;
        }
        if !has_structured_fast_path_selected(initial_entries) {
            agent.record_structured_fast_path_selected(&decision)?;
        }

        while let Some(planned) = agent.next_step().cloned() {
            let index = agent.cursor().next_step;
            let driver_step = task
                .steps
                .get(index)
                .ok_or(AgentError::JournalHasExtraStep { index })?;

            if agent.next_step_already_attempted() {
                let policy = self.step_policy(
                    driver_step,
                    &planned.key,
                    current_origin.as_ref(),
                    structured_remote_side_effect(&driver_step.action),
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

            let policy = self.step_policy(
                driver_step,
                &planned.key,
                current_origin.as_ref(),
                structured_remote_side_effect(&driver_step.action),
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

            agent.ensure_next_step_budget()?;

            agent.plan_next_step()?;
            let outcome = match &planned.action {
                Action::Skill { name, input } => {
                    let call = self
                        .execute_structured_mcp_tool(&decision, &planned.key, name, input)
                        .await
                        .map_err(|reason| {
                            structured_transport_error(
                                &mut agent,
                                "structured mcp tools/call",
                                reason,
                            )
                        })?;
                    if call.is_error {
                        StepOutcome::StepError {
                            reason: call.error_reason(),
                        }
                    } else {
                        StepOutcome::Applied {
                            diff: empty_structured_diff(index as u64),
                        }
                    }
                }
                other => {
                    return Err(AgentError::StructuredFastPathUnsupported {
                        reason: format!("unsupported structured action: {other:?}"),
                    });
                }
            };
            let triple = agent.record_next_outcome(outcome)?;
            report.actions_completed += 1;

            let step_error = match &triple.outcome {
                StepTripleOutcome::StepError { reason } => Some(reason.clone()),
                StepTripleOutcome::Applied { .. } => None,
            };
            report.steps.push(AgentStepReport {
                index,
                policy,
                triple,
                observation_budget: None,
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
        report.status = AgentRunStatus::StructuredFastPath(decision);
        Ok(report)
    }

    async fn execute_structured_mcp_tool(
        &self,
        decision: &StructuredFastPathDecision,
        key: &IdempotencyKey,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<StructuredMcpToolCall, String> {
        let endpoint = decision
            .mcp_endpoint_url()
            .map_err(|error| error.to_string())?;
        let resolved_endpoint =
            resolve_url_target(&endpoint, &self.structured_fast_path.config.url_policy)
                .map_err(|error| error.to_string())?;
        let max_body_bytes = self.structured_fast_path.config.max_body_bytes;
        // Hosted OAuth belongs to the central ecosystem issuer. This fast path
        // must only use an explicit scoped grant from a future auth broker; it
        // must not mint credentials, scrape page text, or replay ambient browser
        // secrets into remote MCP calls.
        let client = reqwest::Client::builder()
            .timeout(self.structured_fast_path.config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(resolved_endpoint.host(), resolved_endpoint.sockets())
            .build()
            .map_err(|error| error.to_string())?;

        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("{}:initialize", key.0),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "tempo-agent", "version": env!("CARGO_PKG_VERSION")},
            },
        });
        let initialize = post_mcp_json(
            &client,
            endpoint.as_str(),
            &initialize,
            None,
            false,
            max_body_bytes,
        )
        .await?;
        if let Some(error) = initialize.body.get("error") {
            return Err(format!(
                "MCP initialize failed: {}",
                json_rpc_error_message(error)
            ));
        }
        validate_mcp_initialize_response(&initialize.body)?;
        let mut session_id = initialize.session_id;

        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        let initialized = post_mcp_json(
            &client,
            endpoint.as_str(),
            &initialized,
            session_id.as_deref(),
            true,
            max_body_bytes,
        )
        .await?;
        if let Some(error) = initialized.body.get("error") {
            return Err(format!(
                "MCP initialized notification failed: {}",
                json_rpc_error_message(error)
            ));
        }
        if initialized.session_id.is_some() {
            session_id = initialized.session_id;
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": key.0,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": input,
            },
        });
        let response = post_mcp_json(
            &client,
            endpoint.as_str(),
            &request,
            session_id.as_deref(),
            true,
            max_body_bytes,
        )
        .await?;
        if let Some(error) = response.body.get("error") {
            return Ok(StructuredMcpToolCall::error(json_rpc_error_message(error)));
        }
        StructuredMcpToolCall::from_json_rpc_response(response.body)
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
        observation_use: ObservationUse,
    ) -> Result<ObservationBudget, AgentError> {
        let budget = self.observation_budget.validate(&observation)?;
        report.observations += 1;
        report.max_observation_bytes = report.max_observation_bytes.max(budget.bytes);
        report.max_observation_tokens = report.max_observation_tokens.max(budget.estimated_tokens);
        let compact_observation = compact_observation_budget(&observation);
        report.max_compact_observation_bytes = report
            .max_compact_observation_bytes
            .max(compact_observation.bytes);
        report.max_compact_observation_tokens = report
            .max_compact_observation_tokens
            .max(compact_observation.estimated_tokens);
        if observation_use == ObservationUse::ModelInput {
            report.model_input_observations += 1;
            report.max_model_input_bytes =
                report.max_model_input_bytes.max(compact_observation.bytes);
            report.max_model_input_tokens = report
                .max_model_input_tokens
                .max(compact_observation.estimated_tokens);
            report.total_model_input_bytes += compact_observation.bytes;
            report.total_model_input_tokens += compact_observation.estimated_tokens;
        }
        agent.record_observation(observation)?;
        Ok(budget)
    }

    async fn refresh_post_action_origin<D>(
        &self,
        agent: &mut AgentLoop,
        report: &mut AgentRunReport,
        driver: &mut D,
        current_origin: Option<&Origin>,
        action: &Action,
        side_effects_may_have_occurred: bool,
    ) -> Result<(Option<Origin>, Option<ObservationBudget>), AgentError>
    where
        D: DriverTrait + ?Sized,
    {
        if !side_effects_may_have_occurred {
            return Ok((current_origin.cloned(), None));
        }

        if !matches!(action, Action::Goto { .. })
            && let Ok(value) = driver.evaluate_script(CURRENT_LOCATION_SCRIPT, true).await
            && let Some(url) = value.as_str()
        {
            return self
                .origin_for_url("post-action location", url)
                .map(|origin| (origin, None));
        }

        let observation = driver
            .observe()
            .await
            .map_err(|source| journal_transport_error(agent, "post-action observe", source))?;
        let origin = self.origin_for_url("post-action observation", &observation.url)?;
        let budget =
            self.record_observation(agent, report, observation, ObservationUse::AuditOnly)?;
        Ok((origin, Some(budget)))
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

/// Runtime lane used for one durable run attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRunEngine {
    Driver(Engine),
    Structured,
}

impl PartialEq<Engine> for AgentRunEngine {
    fn eq(&self, other: &Engine) -> bool {
        matches!(self, Self::Driver(engine) if engine == other)
    }
}

/// Durable report for one live-driver or no-render structured run attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRunReport {
    pub engine: AgentRunEngine,
    pub journal_path: PathBuf,
    pub status: AgentRunStatus,
    pub initial_journal_entries: usize,
    pub actions_completed: usize,
    pub observations: usize,
    pub model_input_observations: usize,
    pub max_observation_bytes: usize,
    pub max_observation_tokens: usize,
    pub max_compact_observation_bytes: usize,
    pub max_compact_observation_tokens: usize,
    pub max_model_input_bytes: usize,
    pub max_model_input_tokens: usize,
    pub total_model_input_bytes: usize,
    pub total_model_input_tokens: usize,
    pub steps: Vec<AgentStepReport>,
}

impl AgentRunReport {
    fn new(
        engine: AgentRunEngine,
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
            model_input_observations: 0,
            max_observation_bytes: 0,
            max_observation_tokens: 0,
            max_compact_observation_bytes: 0,
            max_compact_observation_tokens: 0,
            max_model_input_bytes: 0,
            max_model_input_tokens: 0,
            total_model_input_bytes: 0,
            total_model_input_tokens: 0,
            steps: Vec::new(),
        }
    }

    pub fn succeeded(&self) -> bool {
        matches!(
            self.status,
            AgentRunStatus::Completed
                | AgentRunStatus::AlreadyComplete
                | AgentRunStatus::StructuredFastPath(_)
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
    let retention_policy = durable_retention_policy_from_env()?;
    step_triples_from_journal_with_retention_policy(journal_path, plan, &retention_policy)
}

pub fn step_triples_from_journal_plaintext_unsafe(
    journal_path: impl AsRef<Path>,
    plan: &TaskPlan,
) -> Result<Vec<StepTriple>, AgentError> {
    step_triples_from_journal_with_retention_policy(
        journal_path,
        plan,
        &DurableRetentionPolicy::PlaintextUnsafe,
    )
}

pub fn step_triples_from_journal_with_retention_policy(
    journal_path: impl AsRef<Path>,
    plan: &TaskPlan,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<StepTriple>, AgentError> {
    let entries = read_journal_entries_with_retention_policy(journal_path, retention_policy)?;
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
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::Observation { .. }
            | JournalEvent::ModelDecision { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::HumanTakeoverRequired { .. }
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
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::Observation { .. }
            | JournalEvent::ModelDecision { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::HumanTakeoverRequired { .. }
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
    let retention_policy = durable_retention_policy_from_env()?;
    step_triples_from_journal_without_plan_with_retention_policy(journal_path, &retention_policy)
}

pub fn step_triples_from_journal_without_plan_plaintext_unsafe(
    journal_path: impl AsRef<Path>,
) -> Result<Vec<StepTriple>, AgentError> {
    step_triples_from_journal_without_plan_with_retention_policy(
        journal_path,
        &DurableRetentionPolicy::PlaintextUnsafe,
    )
}

pub fn step_triples_from_journal_without_plan_with_retention_policy(
    journal_path: impl AsRef<Path>,
    retention_policy: &DurableRetentionPolicy,
) -> Result<Vec<StepTriple>, AgentError> {
    let entries = read_journal_entries_with_retention_policy(journal_path, retention_policy)?;
    step_triples_from_journal_entries(&entries)
}

#[derive(Clone, Debug, PartialEq)]
struct StructuredMcpToolCall {
    is_error: bool,
    structured_content: serde_json::Value,
    content: serde_json::Value,
}

impl StructuredMcpToolCall {
    fn error(reason: String) -> Self {
        Self {
            is_error: true,
            structured_content: serde_json::json!({ "error": reason.clone() }),
            content: serde_json::json!([{"type": "text", "text": reason}]),
        }
    }

    fn from_json_rpc_response(response: serde_json::Value) -> Result<Self, String> {
        let result = response
            .get("result")
            .ok_or_else(|| "MCP tools/call response missing result".to_string())?;
        let is_error = result
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let content = result
            .get("content")
            .cloned()
            .ok_or_else(|| "MCP tools/call response missing content".to_string())?;
        if !content.is_array() {
            return Err("MCP tools/call response content must be an array".to_string());
        }
        let structured_content = result.get("structuredContent").cloned().unwrap_or_else(|| {
            serde_json::json!({
                "content": content.clone()
            })
        });
        Ok(Self {
            is_error,
            structured_content,
            content,
        })
    }

    fn error_reason(&self) -> String {
        self.structured_content
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .or_else(|| mcp_content_text(&self.content))
            .unwrap_or_else(|| self.structured_content.to_string())
    }
}

#[derive(Clone, Debug, PartialEq)]
struct McpHttpResponse {
    body: serde_json::Value,
    session_id: Option<String>,
}

async fn post_mcp_json(
    client: &reqwest::Client,
    endpoint: &str,
    request: &serde_json::Value,
    session_id: Option<&str>,
    include_protocol_version: bool,
    max_body_bytes: usize,
) -> Result<McpHttpResponse, String> {
    let mut request_builder = client
        .post(endpoint)
        .header(reqwest::header::ACCEPT, MCP_ACCEPT)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    if include_protocol_version {
        request_builder = request_builder.header(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION);
    }
    if let Some(session_id) = session_id {
        request_builder = request_builder.header(MCP_SESSION_ID_HEADER, session_id);
    }

    let response = request_builder
        .json(request)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let session_id = response
        .headers()
        .get(MCP_SESSION_ID_HEADER)
        .or_else(|| response.headers().get("MCP-Session-Id"))
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = read_mcp_body_capped(response, max_body_bytes).await?;
    if !status.is_success() {
        let detail = body.trim();
        if detail.is_empty() {
            return Err(format!("MCP endpoint returned HTTP {status}"));
        }
        return Err(format!("MCP endpoint returned HTTP {status}: {detail}"));
    }
    Ok(McpHttpResponse {
        body: parse_mcp_response_body(&content_type, &body, request.get("id"))?,
        session_id,
    })
}

/// MCP-flavored wrapper over [`read_body_capped`]: collapses the typed cap
/// errors onto this client's string-error plumbing.
async fn read_mcp_body_capped(
    response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<String, String> {
    read_body_capped(response, max_body_bytes)
        .await
        .map_err(|error| match error {
            CappedBodyError::TooLarge { max_bytes } => {
                format!("MCP response body exceeded {max_bytes} bytes")
            }
            CappedBodyError::Transport(reason) => reason,
        })
}

/// Typed failure from [`read_body_capped`], so callers can distinguish a
/// retryable transport fault from a fatal size-cap breach.
pub(crate) enum CappedBodyError {
    TooLarge { max_bytes: usize },
    Transport(String),
}

/// Reads an HTTP response body into a `String` while enforcing a hard byte
/// cap, so an attacker-controlled endpoint cannot exhaust memory by streaming
/// an unbounded body (see issue #212). Mirrors the probe path's `take`-style
/// bound in `tempo-handshake`, but for the async client: rejects early when
/// the advertised `Content-Length` already exceeds the cap, then accumulates
/// chunks and errors as soon as the received bytes would cross the cap.
/// Shared by the MCP client above and the Anthropic decider (#248); each
/// caller maps [`CappedBodyError`] onto its own error type.
pub(crate) async fn read_body_capped(
    response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<String, CappedBodyError> {
    let cap = max_body_bytes as u64;
    if let Some(content_length) = response.content_length()
        && content_length > cap
    {
        return Err(CappedBodyError::TooLarge {
            max_bytes: max_body_bytes,
        });
    }

    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| CappedBodyError::Transport(error.to_string()))?
    {
        if body.len() as u64 + chunk.len() as u64 > cap {
            return Err(CappedBodyError::TooLarge {
                max_bytes: max_body_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn parse_mcp_response_body(
    content_type: &str,
    body: &str,
    expected_id: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        if let Some(expected_id) = expected_id {
            return Err(format!(
                "MCP response missing body for request id {}",
                json_value_label(expected_id)
            ));
        }
        return Ok(serde_json::Value::Null);
    }

    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("text/event-stream")
        || trimmed.starts_with("event:")
        || trimmed.starts_with("data:")
    {
        return parse_mcp_sse_response(trimmed, expected_id);
    }

    let response =
        serde_json::from_str::<serde_json::Value>(trimmed).map_err(|error| error.to_string())?;
    if let Some(expected_id) = expected_id {
        validate_json_rpc_response_id(&response, expected_id)?;
    }
    Ok(response)
}

fn parse_mcp_sse_response(
    body: &str,
    expected_id: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let normalized = body.replace("\r\n", "\n");
    let mut saw_data = false;
    for event in normalized.split("\n\n") {
        let data = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        saw_data = true;
        let response =
            serde_json::from_str::<serde_json::Value>(data).map_err(|error| error.to_string())?;
        let Some(expected_id) = expected_id else {
            return Ok(response);
        };
        if response.get("id") == Some(expected_id) {
            return Ok(response);
        }
    }

    if let Some(expected_id) = expected_id {
        let detail = if saw_data {
            "JSON-RPC response"
        } else {
            "data JSON"
        };
        return Err(format!(
            "MCP SSE response missing {detail} for request id {}",
            json_value_label(expected_id)
        ));
    }
    Err("MCP SSE response missing data JSON".to_string())
}

fn validate_json_rpc_response_id(
    response: &serde_json::Value,
    expected_id: &serde_json::Value,
) -> Result<(), String> {
    match response.get("id") {
        Some(actual_id) if actual_id == expected_id => Ok(()),
        Some(actual_id) => Err(format!(
            "MCP response id {} did not match request id {}",
            json_value_label(actual_id),
            json_value_label(expected_id)
        )),
        None => Err(format!(
            "MCP response missing id for request id {}",
            json_value_label(expected_id)
        )),
    }
}

fn json_value_label(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn mcp_content_text(content: &serde_json::Value) -> Option<String> {
    let text = content
        .as_array()?
        .iter()
        .filter_map(|item| item.get("text")?.as_str())
        .collect::<Vec<_>>();
    if text.is_empty() {
        None
    } else {
        Some(text.join("\n"))
    }
}

fn json_rpc_error_message(error: &serde_json::Value) -> String {
    error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| error.to_string())
}

fn validate_mcp_initialize_response(response: &serde_json::Value) -> Result<(), String> {
    let result = response
        .get("result")
        .ok_or_else(|| "MCP initialize response missing result".to_string())?;
    let protocol_version = result
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "MCP initialize response missing protocolVersion".to_string())?;
    if protocol_version != MCP_PROTOCOL_VERSION {
        return Err(format!(
            "MCP server negotiated unsupported protocol version {protocol_version}; expected {MCP_PROTOCOL_VERSION}"
        ));
    }

    let capabilities = result
        .get("capabilities")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "MCP initialize response missing capabilities".to_string())?;
    let Some(tools) = capabilities.get("tools") else {
        return Err("MCP initialize response missing tools capability".to_string());
    };
    if !tools.is_object() {
        return Err("MCP initialize response tools capability must be an object".to_string());
    }

    Ok(())
}

fn empty_structured_diff(since_seq: u64) -> ObservationDiff {
    ObservationDiff {
        since_seq,
        seq: since_seq.saturating_add(1),
        omitted: 0,
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    }
}

fn structured_transport_error(
    agent: &mut AgentLoop,
    context: &'static str,
    reason: String,
) -> AgentError {
    let source = TransportError::Other(reason);
    match agent.record_transport_error(context, &source) {
        Ok(()) => AgentError::transport(context, source),
        Err(error) => error,
    }
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

fn has_structured_fast_path_selected(entries: &[JournalEntry]) -> bool {
    entries
        .iter()
        .any(|entry| matches!(entry.event, JournalEvent::StructuredFastPathSelected { .. }))
}

fn structured_fast_path_decision_from_entries(
    entries: &[JournalEntry],
) -> Result<Option<StructuredFastPathDecision>, AgentError> {
    let Some((origin, lane, signal, source)) = entries.iter().rev().find_map(|entry| {
        if let JournalEvent::StructuredFastPathSelected {
            origin,
            lane,
            signal,
            source,
        } = &entry.event
        {
            Some((origin, lane, signal, source))
        } else {
            None
        }
    }) else {
        return Ok(None);
    };

    let lane = structured_lane_from_name(lane).ok_or_else(|| {
        AgentError::StructuredFastPathUnsupported {
            reason: format!("journaled structured lane is unknown: {lane}"),
        }
    })?;
    let signal = structured_signal_from_name(signal).ok_or_else(|| {
        AgentError::StructuredFastPathUnsupported {
            reason: format!("journaled structured signal is unknown: {signal}"),
        }
    })?;
    Ok(Some(StructuredFastPathDecision::new(
        origin.clone(),
        lane,
        signal,
        source.clone(),
    )))
}

fn structured_lane_from_name(name: &str) -> Option<StructuredLane> {
    match name {
        "render" => Some(StructuredLane::Render),
        "api" => Some(StructuredLane::Api),
        "mcp" => Some(StructuredLane::Mcp),
        _ => None,
    }
}

fn structured_signal_from_name(name: &str) -> Option<StructuredSignal> {
    match name {
        "beater_json" => Some(StructuredSignal::BeaterJson),
        "agent_card" => Some(StructuredSignal::AgentCard),
        "llms_txt" => Some(StructuredSignal::LlmsTxt),
        "openapi" => Some(StructuredSignal::OpenApi),
        "mcp_catalog" => Some(StructuredSignal::McpCatalog),
        "web_mcp" => Some(StructuredSignal::WebMcp),
        _ => None,
    }
}

fn structured_remote_side_effect(action: &Action) -> SideEffect {
    match action {
        // Remote MCP catalogs do not carry a trusted Tempo side-effect
        // declaration yet. Treat unknown remote tools as maximally destructive
        // so threshold origin rules for Purchase/Delete cannot be bypassed.
        Action::Skill { .. } => SideEffect::Delete,
        other => other.side_effect(),
    }
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

fn compact_observation_budget(observation: &CompiledObservation) -> ModelInputBudget {
    let bytes = serialize_compact_observation_for_model(observation).len();
    ModelInputBudget {
        bytes,
        estimated_tokens: estimate_tokens(bytes),
    }
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
    #[error("structured fast path cannot execute this task: {reason}")]
    StructuredFastPathUnsupported { reason: String },
    #[error("invalid structured fast path endpoint {value}: {reason}")]
    InvalidStructuredEndpoint { value: String, reason: String },
    #[error("invalid origin during {context}: {url}: {reason}")]
    InvalidOrigin {
        context: &'static str,
        url: String,
        reason: OriginError,
    },
    #[error("token budget exceeded: attempted {attempted}, max {max}")]
    TokenBudgetExceeded { attempted: u64, max: u64 },
    #[error("model decider failed: {0}")]
    Decider(#[from] decider::DeciderError),
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
    use tempo_session::{read_journal_entries, DurableEncryptionKey};
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
        let mut agent = AgentLoop::open_plaintext_unsafe(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            plan.clone(),
            TokenBudget::new(20),
        )?;

        let triple = agent.record_next_outcome(StepOutcome::Applied { diff: diff(0, 1) })?;
        let entries = read_journal_entries(&journal_path)?;
        let triples = step_triples_from_journal_plaintext_unsafe(&journal_path, &plan)?;

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
        let path_triples = step_triples_from_journal_without_plan_plaintext_unsafe(&journal_path)?;

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

        let triples = step_triples_from_journal_without_plan_plaintext_unsafe(&journal_path)?;

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

        let mut agent = AgentLoop::open_plaintext_unsafe(
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
            AgentLoop::open_plaintext_unsafe(
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

        let agent = AgentLoop::open_plaintext_unsafe(
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

        let agent = AgentLoop::open_plaintext_unsafe(
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

        let mut agent = AgentLoop::open_plaintext_unsafe(
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
            AgentLoop::open_plaintext_unsafe(
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
        let mut agent = AgentLoop::open_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-test-driver", "session-test-driver"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.engine, Engine::Test);
        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.observations, 1);
        assert_eq!(report.model_input_observations, 1);
        assert!(report.steps[0].observation_budget.is_none());
        assert!(report.max_observation_bytes > 0);
        assert!(report.max_compact_observation_bytes > 0);
        assert!(report.max_compact_observation_tokens > 0);
        assert!(report.max_compact_observation_bytes <= report.max_observation_bytes);
        assert!(report.max_model_input_bytes > 0);
        assert!(report.max_model_input_tokens > 0);
        assert_eq!(
            report.max_model_input_bytes,
            report.max_compact_observation_bytes
        );
        assert_eq!(report.total_model_input_bytes, report.max_model_input_bytes);
        assert_eq!(
            report.total_model_input_tokens,
            report.max_model_input_tokens
        );
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
    async fn runner_refreshes_origin_without_post_action_full_observe() -> TestResult {
        let root = unique_dir("runner-cheap-post-action-origin")?;
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
            FailingDriver::new(TransportFailurePoint::None).with_elements(vec![button("submit")]);
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-cheap-origin", "session-cheap-origin"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.observations, 1);
        assert_eq!(report.steps[0].observation_budget, None);
        assert_eq!(
            driver.observe_calls, 1,
            "execute_action should still ground from a pre-action observe, but the runner should not issue a redundant post-action full observe"
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_writes_encrypted_journal_when_retention_policy_is_secure() -> TestResult {
        let root = unique_dir("runner-encrypted")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let retention_policy =
            DurableRetentionPolicy::encrypted(DurableEncryptionKey::from_bytes([42; 32]));
        let task = DriverTask::new(
            "https://example.com/private?token=secret",
            vec![Action::Click {
                node: NodeId("submit".into()),
            }],
        );
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-encrypted", "session-encrypted"),
        )
        .with_retention_policy(retention_policy.clone());

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert_eq!(report.status, AgentRunStatus::Completed);
        assert!(matches!(
            read_journal_entries(&journal_path),
            Err(JournalError::EncryptedRecordRequiresKey)
        ));
        let entries = read_journal_entries_with_retention_policy(&journal_path, &retention_policy)?;
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));
        let bytes = fs::read(&journal_path)?;
        assert!(!contains_bytes(&bytes, b"token=secret"));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_structured_fast_path_executes_remote_mcp_skill_without_navigation() -> TestResult
    {
        let root = unique_dir("runner-structured-fast-path")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let (origin, server) = serve_structured_mcp_fixture()?;
        let task = DriverTask::new(
            format!("{origin}/app"),
            vec![Action::Skill {
                name: "search".into(),
                input: serde_json::json!({"q": "tempo"}),
            }],
        );
        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-structured", "session-structured"),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_structured_fast_path(
            StructuredFastPath::with_probe(fake_mcp_fast_path_probe).allow_private_network_access(),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;
        server
            .join()
            .map_err(|_| "structured MCP fixture thread panicked")??;

        assert_eq!(
            report.status,
            AgentRunStatus::StructuredFastPath(StructuredFastPathDecision::new(
                origin.clone(),
                StructuredLane::Mcp,
                StructuredSignal::McpCatalog,
                "/mcp/catalog.json"
            ))
        );
        assert_eq!(report.engine, AgentRunEngine::Structured);
        assert_eq!(driver.goto_calls, 0);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.observations, 0);
        let entries = read_journal_entries(&journal_path)?;
        assert!(matches!(
            entries.first().map(|entry| &entry.event),
            Some(JournalEvent::SessionStarted { .. })
        ));
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StructuredFastPathSelected { .. })));
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
    async fn runner_mcp_fast_path_treats_unknown_remote_tools_as_destructive() -> TestResult {
        let root = unique_dir("runner-structured-fast-path-policy")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let task = DriverTask::new(
            "http://127.0.0.1:9/app",
            vec![Action::Skill {
                name: "send_email".into(),
                input: serde_json::json!({"to": "user@example.com"}),
            }],
        );
        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-structured-policy", "session-structured-policy"),
        )
        .with_structured_fast_path(StructuredFastPath::with_probe(fake_mcp_fast_path_probe));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::PolicyDenied { .. }));
        assert_eq!(report.engine, AgentRunEngine::Structured);
        assert_eq!(driver.goto_calls, 0);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.steps[0].policy.side_effect, SideEffect::Delete);
        assert_eq!(
            report.steps[0].policy.confirmation_gate,
            ConfirmationGate::Confirm
        );
        assert!(!report.steps[0].policy.confirmed);
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_mcp_fast_path_purchase_origin_rule_blocks_unknown_remote_tools() -> TestResult {
        let root = unique_dir("runner-structured-fast-path-origin-rule")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let origin = "http://127.0.0.1:9";
        let task = DriverTask::new(
            format!("{origin}/app"),
            vec![Action::Skill {
                name: "delete_account".into(),
                input: serde_json::json!({"account_id": "acct-123"}),
            }],
        );
        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new(
                "run-structured-origin-rule",
                "session-structured-origin-rule",
            ),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_origin_policy(OriginPolicy::new(vec![OriginRule::new(
            Origin::parse(origin)?,
            SideEffect::Purchase,
            OriginRuleMode::Block,
        )]))
        .with_structured_fast_path(StructuredFastPath::with_probe(fake_mcp_fast_path_probe));

        let report = runner.run_driver_task(&mut driver, &task).await?;

        assert!(matches!(report.status, AgentRunStatus::PolicyDenied { .. }));
        assert_eq!(report.engine, AgentRunEngine::Structured);
        assert_eq!(driver.goto_calls, 0);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.steps[0].policy.side_effect, SideEffect::Delete);
        assert!(report.steps[0].policy.denied);
        assert_eq!(report.steps[0].policy.origin_rules_matched, 1);
        assert_eq!(
            report.steps[0].policy.origin_rule_mode,
            OriginRuleMode::Block
        );
        assert_eq!(report.steps[0].policy.origin.as_deref(), Some(origin));
        assert!(!read_journal_entries(&journal_path)?
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_resumes_journaled_mcp_fast_path_without_browser_observe() -> TestResult {
        let root = unique_dir("runner-structured-fast-path-resume")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let (origin, server) = serve_structured_mcp_fixture()?;
        let action = Action::Skill {
            name: "search".into(),
            input: serde_json::json!({"q": "tempo"}),
        };
        let task = DriverTask::new(format!("{origin}/app"), vec![action]);
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run-structured-resume".into()),
            SessionId("session-structured-resume".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: format!("{origin}/app"),
        })?;
        journal.append(JournalEvent::StructuredFastPathSelected {
            origin: origin.clone(),
            lane: "mcp".into(),
            signal: "mcp_catalog".into(),
            source: "/mcp/catalog.json".into(),
        })?;
        drop(journal);

        let mut driver = FailingDriver::new(TransportFailurePoint::Goto);
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-structured-resume", "session-structured-resume"),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_structured_fast_path(StructuredFastPath::disabled().allow_private_network_access());

        let result = runner.run_driver_task(&mut driver, &task).await;
        let server_result = server
            .join()
            .map_err(|_| "structured MCP fixture thread panicked")?;
        server_result?;
        let report = result?;

        assert_eq!(
            report.status,
            AgentRunStatus::StructuredFastPath(StructuredFastPathDecision::new(
                origin,
                StructuredLane::Mcp,
                StructuredSignal::McpCatalog,
                "/mcp/catalog.json"
            ))
        );
        assert_eq!(report.engine, AgentRunEngine::Structured);
        assert_eq!(driver.goto_calls, 0);
        assert_eq!(driver.observe_calls, 0);
        assert_eq!(report.actions_completed, 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runner_mcp_fast_path_unsupported_actions_fall_through_to_driver() -> TestResult {
        let root = unique_dir("runner-structured-fast-path-fallback")?;
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
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-structured-fallback", "session-structured-fallback"),
        )
        .with_structured_fast_path(StructuredFastPath::with_probe(fake_mcp_fast_path_probe));

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert_eq!(driver.goto_calls, 1);
        assert!(matches!(
            error,
            Some(AgentError::Transport {
                context,
                source: TransportError::NavTimeout,
            }) if context == "initial goto"
        ));
        let entries = read_journal_entries(&journal_path)?;
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StructuredFastPathSelected { .. })));
        assert!(has_transport_error(
            &entries,
            "initial goto",
            "navigation timed out"
        ));

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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let first_runner = AgentRunner::new_plaintext_unsafe(&journal_path, ids.clone());
        let first = first_runner
            .run_driver_task(&mut first_driver, &task)
            .await?;
        assert_eq!(first.status, AgentRunStatus::Completed);
        let entry_count = read_journal_entries(&journal_path)?.len();

        let mut second_driver = TestDriver::new().with_elements(vec![button("submit")]);
        let second_runner = AgentRunner::new_plaintext_unsafe(&journal_path, ids);
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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

    #[tokio::test]
    async fn runner_budget_exhaustion_preempts_driver_action_execution() -> TestResult {
        let root = unique_dir("runner-action-budget-preexecute")?;
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
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new(
                "run-action-budget-preexecute",
                "session-action-budget-preexecute",
            ),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_token_budget(TokenBudget::new(0));

        let error = runner.run_driver_task(&mut driver, &task).await.err();

        assert!(matches!(
            error,
            Some(AgentError::TokenBudgetExceeded { max: 0, .. })
        ));
        assert_eq!(driver.goto_calls, 1);
        assert_eq!(driver.act_calls, 0);
        let entries = read_journal_entries(&journal_path)?;
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn structured_budget_exhaustion_preempts_mcp_tool_call() -> TestResult {
        let root = unique_dir("structured-budget-preempts-mcp")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let origin = "http://127.0.0.1:9";
        let task = DriverTask::new(
            format!("{origin}/app"),
            vec![Action::Skill {
                name: "search".into(),
                input: serde_json::json!({"q": "tempo"}),
            }],
        );
        let decision = StructuredFastPathDecision::new(
            origin,
            StructuredLane::Mcp,
            StructuredSignal::McpCatalog,
            "/mcp/catalog.json",
        );
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new(
                "run-structured-budget-preexecute",
                "session-structured-budget-preexecute",
            ),
        )
        .with_confirmation_mode(ConfirmationMode::AutoConfirmAll)
        .with_token_budget(TokenBudget::new(0));

        let error = runner.run_structured_task(&task, decision).await.err();

        assert!(matches!(
            error,
            Some(AgentError::TokenBudgetExceeded { max: 0, .. })
        ));
        let entries = read_journal_entries(&journal_path)?;
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StructuredFastPathSelected { .. })));
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. })));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_cdp_runner_completes_scripted_task_and_journals_it() -> TestResult {
        let Some(chrome) = std::env::var("TEMPO_CDP_CHROME").ok() else {
            eprintln!("skipping live CDP agent smoke; TEMPO_CDP_CHROME is not set");
            return Ok(());
        };

        let url = serve_times(
            r#"<!doctype html>
            <html>
              <body>
                <input id="name" aria-label="Name">
                <select id="plan" aria-label="Plan">
                  <option value="free">Free</option>
                  <option value="pro">Pro</option>
                </select>
                <button id="add" onclick="document.body.dataset.count = String(Number(document.body.dataset.count || '0') + 1);">Add</button>
                <button id="finish" onclick="document.body.dataset.finished='yes'; document.getElementById('summary').textContent = document.getElementById('name').value + ':' + document.getElementById('plan').value + ':' + (document.body.dataset.count || '0');">Finish</button>
                <div id="summary" tabindex="0" aria-label="Summary"></div>
              </body>
            </html>"#,
            4,
        )?;
        let root = unique_dir("runner-live-cdp")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let mut driver = CdpTempoDriver::launch_with(
            CdpConfig::default()
                .with_executable(chrome)
                .with_no_sandbox_env_opt_in(),
        )
        .await?
        .allow_private_network_access();
        let observation = driver.goto(&url).await?;
        let node_named = |name: &str| -> Result<NodeId, std::io::Error> {
            observation
                .elements
                .iter()
                .find(|element| element.name.first().map(|span| span.text.as_str()) == Some(name))
                .map(|element| element.node_id.clone())
                .ok_or_else(|| std::io::Error::other(format!("missing observed node: {name}")))
        };
        let task = DriverTask::new(
            url,
            vec![
                Action::Type {
                    node: node_named("Name")?,
                    text: "Ada".into(),
                },
                Action::Select {
                    node: node_named("Plan")?,
                    value: "pro".into(),
                },
                Action::Click {
                    node: node_named("Add")?,
                },
                Action::Click {
                    node: node_named("Finish")?,
                },
                Action::Extract {
                    node: node_named("Summary")?,
                },
            ],
        );
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-live-cdp", "session-live-cdp"),
        );

        let report = runner.run_driver_task(&mut driver, &task).await?;
        let final_state = driver
            .evaluate_script(
                r#"(() => ({
                    name: document.querySelector('#name').value,
                    plan: document.querySelector('#plan').value,
                    count: Number(document.body.dataset.count || '0'),
                    finished: document.body.dataset.finished,
                    summary: document.querySelector('#summary').textContent.trim()
                }))()"#,
                true,
            )
            .await?;
        driver.close().await?;

        assert_eq!(report.engine, Engine::Cdp);
        assert_eq!(report.status, AgentRunStatus::Completed);
        assert_eq!(report.actions_completed, 5);
        assert_eq!(report.steps.len(), 5);
        assert_eq!(final_state["name"], serde_json::json!("Ada"));
        assert_eq!(final_state["plan"], serde_json::json!("pro"));
        assert_eq!(final_state["count"], serde_json::json!(1));
        assert_eq!(final_state["finished"], serde_json::json!("yes"));
        assert_eq!(final_state["summary"], serde_json::json!("Ada:pro:1"));

        let entries = read_journal_entries(&journal_path)?;
        assert_eq!(
            entries
                .iter()
                .filter(|entry| matches!(entry.event, JournalEvent::StepApplied { .. }))
                .count(),
            5
        );
        let plan = task.task_plan()?;
        let replayed = step_triples_from_journal_plaintext_unsafe(&journal_path, &plan)?;
        let reported = report
            .steps
            .iter()
            .map(|step| step.triple.clone())
            .collect::<Vec<_>>();
        assert_eq!(replayed, reported);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_runner_resume_does_not_duplicate_completed_steps() -> TestResult {
        let Some(chrome) = std::env::var("TEMPO_CDP_CHROME").ok() else {
            eprintln!("skipping live CDP agent resume smoke; TEMPO_CDP_CHROME is not set");
            return Ok(());
        };

        let url = serve_times(
            r#"<!doctype html>
            <html>
              <body>
                <input id="name" aria-label="Name">
                <button id="finish" onclick="document.body.dataset.finished='yes'; document.getElementById('summary').textContent = document.getElementById('name').value;">Finish</button>
                <div id="summary" tabindex="0" aria-label="Summary"></div>
              </body>
            </html>"#,
            3,
        )?;
        let root = unique_dir("runner-live-cdp-resume")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let ids = AgentRunIds::new("run-live-cdp-resume", "session-live-cdp-resume");

        let mut first_driver = CdpTempoDriver::launch_with(
            CdpConfig::default()
                .with_executable(chrome.clone())
                .with_no_sandbox_env_opt_in(),
        )
        .await?
        .allow_private_network_access();
        let observation = first_driver.goto(&url).await?;
        let node_named = |name: &str| -> Result<NodeId, std::io::Error> {
            observation
                .elements
                .iter()
                .find(|element| element.name.first().map(|span| span.text.as_str()) == Some(name))
                .map(|element| element.node_id.clone())
                .ok_or_else(|| std::io::Error::other(format!("missing observed node: {name}")))
        };
        let task = DriverTask::new(
            url,
            vec![
                Action::Type {
                    node: node_named("Name")?,
                    text: "Grace".into(),
                },
                Action::Click {
                    node: node_named("Finish")?,
                },
                Action::Extract {
                    node: node_named("Summary")?,
                },
            ],
        );
        let first_runner = AgentRunner::new_plaintext_unsafe(&journal_path, ids.clone());
        let first = first_runner
            .run_driver_task(&mut first_driver, &task)
            .await?;
        let final_state = first_driver
            .evaluate_script(
                r#"(() => ({
                    name: document.querySelector('#name').value,
                    finished: document.body.dataset.finished,
                    summary: document.querySelector('#summary').textContent.trim()
                }))()"#,
                true,
            )
            .await?;
        first_driver.close().await?;

        assert_eq!(first.status, AgentRunStatus::Completed);
        assert_eq!(first.actions_completed, 3);
        assert_eq!(final_state["name"], serde_json::json!("Grace"));
        assert_eq!(final_state["finished"], serde_json::json!("yes"));
        assert_eq!(final_state["summary"], serde_json::json!("Grace"));
        let entry_count = read_journal_entries(&journal_path)?.len();

        let mut second_driver = FailingDriver::new(TransportFailurePoint::Goto);
        let second_runner = AgentRunner::new_plaintext_unsafe(&journal_path, ids);
        let second = second_runner
            .run_driver_task(&mut second_driver, &task)
            .await?;

        assert_eq!(second.status, AgentRunStatus::AlreadyComplete);
        assert_eq!(second.actions_completed, 3);
        assert_eq!(read_journal_entries(&journal_path)?.len(), entry_count);
        assert_eq!(second_driver.goto_calls, 0);
        assert_eq!(second_driver.observe_calls, 0);
        assert_eq!(second_driver.act_calls, 0);

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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
            &journal_path,
            AgentRunIds::new("run-snap", "session-snap"),
        )
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

    #[test]
    fn mcp_tool_call_accepts_content_only_results() -> TestResult {
        let call = StructuredMcpToolCall::from_json_rpc_response(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fixture",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            }
        }))
        .map_err(std::io::Error::other)?;

        assert!(!call.is_error);
        assert_eq!(
            call.structured_content,
            serde_json::json!({"content": [{"type": "text", "text": "ok"}]})
        );
        Ok(())
    }

    #[test]
    fn mcp_tool_call_uses_text_content_for_error_reason() -> TestResult {
        let call = StructuredMcpToolCall::from_json_rpc_response(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fixture",
            "result": {
                "content": [{"type": "text", "text": "permission denied"}],
                "isError": true
            }
        }))
        .map_err(std::io::Error::other)?;

        assert!(call.is_error);
        assert_eq!(call.error_reason(), "permission denied");
        Ok(())
    }

    #[test]
    fn mcp_tool_call_rejects_missing_content() -> TestResult {
        let error = match StructuredMcpToolCall::from_json_rpc_response(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fixture",
            "result": {
                "isError": false
            }
        })) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "missing content response unexpectedly succeeded",
                )
                .into())
            }
            Err(error) => error,
        };

        assert_eq!(error, "MCP tools/call response missing content");
        Ok(())
    }

    #[test]
    fn mcp_initialize_response_requires_protocol_and_tools_capability() -> TestResult {
        validate_mcp_initialize_response(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fixture",
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}}
            }
        }))
        .map_err(std::io::Error::other)?;

        let error = match validate_mcp_initialize_response(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fixture",
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {}
            }
        })) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "missing tools capability unexpectedly succeeded",
                )
                .into())
            }
            Err(error) => error,
        };
        assert_eq!(error, "MCP initialize response missing tools capability");
        Ok(())
    }

    #[test]
    fn mcp_response_parser_accepts_sse_json_data() -> TestResult {
        let parsed = parse_mcp_response_body(
            "text/event-stream",
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"content\":[]}}\n\n",
            None,
        )
        .map_err(std::io::Error::other)?;

        assert_eq!(
            parsed,
            serde_json::json!({"jsonrpc":"2.0","result":{"content":[]}})
        );
        Ok(())
    }

    #[test]
    fn mcp_response_parser_skips_sse_events_until_expected_id() -> TestResult {
        let expected_id = serde_json::json!("wanted");
        let parsed = parse_mcp_response_body(
            "text/event-stream",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":\"other\",\"result\":{\"content\":[]}}\n\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":\"wanted\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n\n",
            Some(&expected_id),
        )
        .map_err(std::io::Error::other)?;

        assert_eq!(
            parsed,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wanted",
                "result": {"content": [{"type": "text", "text": "ok"}]}
            })
        );
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        let runner = AgentRunner::new_plaintext_unsafe(
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
        None,
        Goto,
        Act,
        PostActionObserve,
    }

    type FixtureHandle = thread::JoinHandle<std::io::Result<()>>;

    fn serve_structured_mcp_fixture() -> std::io::Result<(String, FixtureHandle)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut handled = 0_usize;
            let mut saw_initialize = false;
            let mut saw_initialized = false;
            let mut saw_tool_call = false;
            while !saw_tool_call && handled < 16 && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        handled += 1;
                        // Accepted sockets can inherit the listener's
                        // nonblocking flag (macOS), flaking reads with
                        // WouldBlock; force blocking mode explicitly.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
                        let request = read_http_request(&mut stream)?;
                        let response = if request.starts_with("GET /mcp/catalog.json ") {
                            http_fixture_response(
                                "200 OK",
                                "application/json",
                                r#"{"tools":[{"name":"search"}]}"#,
                            )
                        } else if request.starts_with("POST /mcp ")
                            && request.contains(r#""method":"initialize""#)
                        {
                            assert_header_contains(&request, "accept", "application/json");
                            assert_header_contains(&request, "accept", "text/event-stream");
                            let request_id = json_rpc_request_id(&request)?;
                            saw_initialize = true;
                            http_fixture_response(
                                "200 OK",
                                "application/json",
                                serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": request_id,
                                    "result": {
                                        "protocolVersion": MCP_PROTOCOL_VERSION,
                                        "capabilities": {"tools": {}},
                                        "serverInfo": {"name": "fixture", "version": "1"}
                                    }
                                })
                                .to_string(),
                            )
                            .with_header(MCP_SESSION_ID_HEADER, "fixture-session")
                        } else if request.starts_with("POST /mcp ")
                            && request.contains(r#""method":"notifications/initialized""#)
                        {
                            assert!(saw_initialize);
                            assert_request_header(
                                &request,
                                MCP_SESSION_ID_HEADER,
                                "fixture-session",
                            );
                            assert_request_header(
                                &request,
                                MCP_PROTOCOL_VERSION_HEADER,
                                MCP_PROTOCOL_VERSION,
                            );
                            saw_initialized = true;
                            http_fixture_response("202 Accepted", "text/plain", "")
                        } else if request.starts_with("POST /mcp ")
                            && request.contains(r#""method":"tools/call""#)
                            && request.contains(r#""name":"search""#)
                            && request.contains(r#""q":"tempo""#)
                        {
                            assert!(saw_initialized);
                            assert_request_header(
                                &request,
                                MCP_SESSION_ID_HEADER,
                                "fixture-session",
                            );
                            assert_request_header(
                                &request,
                                MCP_PROTOCOL_VERSION_HEADER,
                                MCP_PROTOCOL_VERSION,
                            );
                            let request_id = json_rpc_request_id(&request)?;
                            saw_tool_call = true;
                            let response = serde_json::json!({
                                "jsonrpc": "2.0",
                                "method": "notifications/progress",
                                "params": {"progress": 1}
                            })
                            .to_string();
                            let result = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": request_id,
                                "result": {
                                    "content": [{"type": "text", "text": "{\"ok\":true}"}],
                                    "isError": false
                                }
                            })
                            .to_string();
                            http_fixture_response(
                                "200 OK",
                                "application/json",
                                format!("data: {response}\n\ndata: {result}\n\n"),
                            )
                            .with_content_type("text/event-stream")
                        } else {
                            http_fixture_response("404 Not Found", "text/plain", "not found")
                        };
                        stream.write_all(response.to_http().as_bytes())?;
                        stream.flush()?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            if saw_tool_call {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "structured MCP fixture did not receive tools/call",
                ))
            }
        });
        Ok((origin, handle))
    }

    /// Serves a single `POST /mcp` request with the supplied JSON body, then
    /// exits. Used to exercise `post_mcp_json`'s response-body size cap (#212).
    fn serve_single_mcp_response(body: String) -> std::io::Result<(String, FixtureHandle)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        // Accepted sockets can inherit the listener's
                        // nonblocking flag (macOS), flaking reads with
                        // WouldBlock; force blocking mode explicitly.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
                        let _request = read_http_request(&mut stream)?;
                        let response =
                            http_fixture_response("200 OK", "application/json", body.clone());
                        stream.write_all(response.to_http().as_bytes())?;
                        stream.flush()?;
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "single MCP fixture did not receive a request",
            ))
        });
        Ok((origin, handle))
    }

    /// Serves a single `POST /mcp` request with the supplied JSON body but
    /// deliberately OMITS `Content-Length`, streaming an HTTP/1.0-style
    /// close-delimited body (the connection is closed to signal end-of-body).
    /// This exercises the chunk-accumulation branch of `read_mcp_body_capped`
    /// rather than the early `Content-Length > cap` rejection (#212 review).
    fn serve_single_mcp_response_no_content_length(
        body: String,
    ) -> std::io::Result<(String, FixtureHandle)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        // Accepted sockets can inherit the listener's
                        // nonblocking flag (macOS), flaking reads with
                        // WouldBlock; force blocking mode explicitly.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
                        let _request = read_http_request(&mut stream)?;
                        // Status + headers WITHOUT Content-Length; `Connection: close`
                        // means the client reads the body until EOF.
                        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
                        stream.write_all(head.as_bytes())?;
                        stream.write_all(body.as_bytes())?;
                        stream.flush()?;
                        // Dropping the stream closes the connection, delimiting the body.
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "single MCP fixture did not receive a request",
            ))
        });
        Ok((origin, handle))
    }

    #[tokio::test]
    async fn post_mcp_json_rejects_body_over_cap() -> TestResult {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "method": "tools/call",
        });
        // Otherwise-valid JSON-RPC response whose body dwarfs the cap.
        let oversized = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "result": {"content": [{"type": "text", "text": "x".repeat(256 * 1024)}]},
        })
        .to_string();
        assert!(oversized.len() > 64 * 1024);

        let (origin, server) = serve_single_mcp_response(oversized)?;
        let endpoint = format!("{origin}/mcp");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;

        let result = post_mcp_json(&client, &endpoint, &request, None, false, 64 * 1024).await;
        server
            .join()
            .map_err(|_| "single MCP fixture thread panicked")??;

        let Err(error) = result else {
            return Err("oversized MCP response body must be rejected".into());
        };
        assert!(
            error.contains("exceeded"),
            "unexpected error message: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn post_mcp_json_accepts_body_under_cap() -> TestResult {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "method": "tools/call",
        });
        let small = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        })
        .to_string();
        assert!(small.len() <= 64 * 1024);

        let (origin, server) = serve_single_mcp_response(small)?;
        let endpoint = format!("{origin}/mcp");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;

        let response = post_mcp_json(&client, &endpoint, &request, None, false, 64 * 1024).await?;
        server
            .join()
            .map_err(|_| "single MCP fixture thread panicked")??;

        assert_eq!(
            response.body.get("id").and_then(|id| id.as_str()),
            Some("cap-test")
        );
        Ok(())
    }

    /// Regression for #212 review: a response that OMITS `Content-Length` and
    /// streams an oversized close-delimited body must still be rejected by the
    /// chunk-accumulation guard in `read_mcp_body_capped`. Because there is no
    /// advertised length, the early `content_length() > cap` check is skipped,
    /// so this only passes when the accumulation loop enforces the cap. A naive
    /// unbounded `.text()` reader would slurp the whole body and fail this test.
    #[tokio::test]
    async fn post_mcp_json_rejects_streamed_body_over_cap_without_content_length() -> TestResult {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "method": "tools/call",
        });
        // Otherwise-valid JSON-RPC response whose body dwarfs the cap.
        let oversized = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cap-test",
            "result": {"content": [{"type": "text", "text": "x".repeat(256 * 1024)}]},
        })
        .to_string();
        assert!(oversized.len() > 64 * 1024);

        let (origin, server) = serve_single_mcp_response_no_content_length(oversized)?;
        let endpoint = format!("{origin}/mcp");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;

        let result = post_mcp_json(&client, &endpoint, &request, None, false, 64 * 1024).await;
        server
            .join()
            .map_err(|_| "single MCP fixture thread panicked")??;

        let Err(error) = result else {
            return Err("oversized streamed MCP response body must be rejected".into());
        };
        assert!(
            error.contains("exceeded"),
            "unexpected error message: {error}"
        );
        Ok(())
    }

    pub(crate) struct HttpFixtureResponse {
        status: &'static str,
        content_type: &'static str,
        body: String,
        headers: Vec<(&'static str, &'static str)>,
    }

    impl HttpFixtureResponse {
        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }

        fn with_content_type(mut self, content_type: &'static str) -> Self {
            self.content_type = content_type;
            self
        }

        pub(crate) fn to_http(&self) -> String {
            let mut response = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                self.status,
                self.content_type,
                self.body.len()
            );
            for (name, value) in &self.headers {
                response.push_str(name);
                response.push_str(": ");
                response.push_str(value);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            response.push_str(&self.body);
            response
        }
    }

    pub(crate) fn http_fixture_response(
        status: &'static str,
        content_type: &'static str,
        body: impl Into<String>,
    ) -> HttpFixtureResponse {
        HttpFixtureResponse {
            status,
            content_type,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub(crate) fn read_http_request(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn json_rpc_request_id(request: &str) -> std::io::Result<serde_json::Value> {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP request missing body delimiter",
                )
            })?;
        let request = serde_json::from_str::<serde_json::Value>(body).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        request.get("id").cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "JSON-RPC request missing id",
            )
        })
    }

    fn assert_request_header(request: &str, name: &str, expected: &str) {
        let actual =
            request_header(request, name).unwrap_or_else(|| panic!("missing {name} header"));
        assert_eq!(actual, expected);
    }

    fn assert_header_contains(request: &str, name: &str, expected: &str) {
        let actual =
            request_header(request, name).unwrap_or_else(|| panic!("missing {name} header"));
        assert!(
            actual.contains(expected),
            "expected {name} header {actual:?} to contain {expected:?}"
        );
    }

    fn request_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            if header_name.eq_ignore_ascii_case(name) {
                Some(value.trim())
            } else {
                None
            }
        })
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn fake_mcp_fast_path_probe(
        target: &str,
        _config: HttpProbeConfig,
    ) -> Option<StructuredFastPathDecision> {
        let origin = reqwest::Url::parse(target)
            .ok()?
            .origin()
            .ascii_serialization();
        Some(StructuredFastPathDecision::new(
            origin,
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
        act_calls: usize,
    }

    impl FailingDriver {
        fn new(failure: TransportFailurePoint) -> Self {
            Self {
                inner: TestDriver::new(),
                failure,
                goto_calls: 0,
                observe_calls: 0,
                act_calls: 0,
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
            self.act_calls += 1;
            if self.failure == TransportFailurePoint::Act {
                return Err(TransportError::Other("act failed".into()));
            }
            self.inner.act(action).await
        }

        async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
            self.act_calls += batch.actions.len();
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
            if self.failure == TransportFailurePoint::PostActionObserve {
                return Ok(serde_json::Value::Null);
            }
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
            omitted: 0,
            added: vec![],
            removed: vec![],
            changed: vec![],
        }
    }

    pub(crate) fn button(id: &str) -> InteractiveElement {
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

    pub(crate) fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-agent-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    pub(crate) fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn serve_times(body: &'static str, max_requests: usize) -> Result<String, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for _ in 0..max_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
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
