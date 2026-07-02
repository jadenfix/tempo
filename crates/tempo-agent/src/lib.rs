//! tempo-agent — durable task loop primitives.
//!
//! The model client and engine executor sit above this crate. This layer owns the
//! crash-safe runtime contract: token budgeting, stable idempotency keys, journal
//! resume, and StepTriple extraction from durable session records.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tempo_act::{execute_action, execute_batch, ActionExecution, ExecutionStatus};
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError};
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

/// Stable key for retrying a planned step without duplicating side effects.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn for_action(index: usize, action: &Action) -> Result<Self, AgentError> {
        let mut hash = Fnv1a64::new();
        hash.update(&(index as u64).to_be_bytes());
        hash.update(&[0]);
        hash.update(&serde_json::to_vec(action)?);
        Ok(Self(format!("{:016x}", hash.finish())))
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
            let observation = driver
                .goto(&task.start_url)
                .await
                .map_err(|source| AgentError::transport("initial goto", source))?;
            current_origin = self.origin_for_url("initial observation", &observation.url)?;
            agent.record_session_started(task.start_url.clone())?;
            self.record_observation(&mut agent, &mut report, observation)?;
        } else {
            let observation = driver
                .observe()
                .await
                .map_err(|source| AgentError::transport("resume observe", source))?;
            current_origin = self.origin_for_url("resume observation", &observation.url)?;
            self.record_observation(&mut agent, &mut report, observation)?;
        }

        while let Some(planned) = agent.next_step().cloned() {
            let index = agent.cursor().next_step;
            let driver_step = task
                .steps
                .get(index)
                .ok_or(AgentError::JournalHasExtraStep { index })?;
            let policy_origin = self.origin_for_step(driver_step, current_origin.as_ref())?;
            let policy = self.step_policy(driver_step, &planned.key, policy_origin.as_ref())?;

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

            let execution = self.execute_driver_step(driver, &planned.action).await?;
            let outcome = match execution.status {
                ExecutionStatus::Applied => StepOutcome::Applied {
                    diff: execution.diff,
                },
                ExecutionStatus::StepError { reason } => StepOutcome::StepError { reason },
            };
            let triple = agent.record_next_outcome(outcome)?;
            report.actions_completed += 1;

            let observation = driver
                .observe()
                .await
                .map_err(|source| AgentError::transport("post-action observe", source))?;
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

    async fn execute_driver_step<D>(
        &self,
        driver: &mut D,
        action: &Action,
    ) -> Result<ActionExecution, AgentError>
    where
        D: DriverTrait + ?Sized,
    {
        match action {
            Action::Skill { name, input } => {
                let batch = self.compile_skill(name, input)?;
                execute_batch(driver, &batch)
                    .await
                    .map_err(|source| AgentError::transport("execute skill", source))
            }
            _ => execute_action(driver, action)
                .await
                .map_err(|source| AgentError::transport("execute action", source)),
        }
    }

    fn compile_skill(
        &self,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<ActionBatch, AgentError> {
        let root = self
            .skill_store_root
            .as_ref()
            .ok_or_else(|| AgentError::SkillStoreNotConfigured(name.to_string()))?;
        let store = SkillStore::open(root)?;
        let mut stack = Vec::new();
        compile_skill_from_store(&store, name, input, &mut stack)
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
    ) -> Result<StepPolicyReport, AgentError> {
        let side_effect = self.side_effect_for_action(&step.action)?;
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

    fn side_effect_for_action(&self, action: &Action) -> Result<SideEffect, AgentError> {
        match action {
            Action::Skill { name, .. } => self.skill_side_effect(name),
            _ => Ok(action.side_effect()),
        }
    }

    fn skill_side_effect(&self, name: &str) -> Result<SideEffect, AgentError> {
        let root = self
            .skill_store_root
            .as_ref()
            .ok_or_else(|| AgentError::SkillStoreNotConfigured(name.to_string()))?;
        let store = SkillStore::open(root)?;
        let key = store.resolve(name)?;
        Ok(store.get(&key)?.side_effect)
    }
}

fn compile_skill_from_store(
    store: &SkillStore,
    name: &str,
    input: &serde_json::Value,
    stack: &mut Vec<String>,
) -> Result<ActionBatch, AgentError> {
    if stack.iter().any(|active| active == name) {
        return Err(AgentError::SkillCycle(name.to_string()));
    }
    stack.push(name.to_string());

    let result = (|| {
        let key = store.resolve(name)?;
        let batch = store.compile(&key, input)?;
        let mut actions = Vec::new();
        for action in batch.actions {
            match action {
                Action::Skill { name, input } => {
                    let nested = compile_skill_from_store(store, &name, &input, stack)?;
                    actions.extend(nested.actions);
                }
                other => actions.push(other),
            }
        }
        Ok(ActionBatch {
            actions,
            quiescence: batch.quiescence,
        })
    })();

    stack.pop();
    result
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
    StepError { action_index: usize, reason: String },
    PolicyDenied { action_index: usize, reason: String },
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

struct Fnv1a64(u64);

impl Fnv1a64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;

    fn new() -> Self {
        Self(Self::OFFSET)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
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

        agent.record_next_outcome(StepOutcome::StepError {
            reason: "not present".into(),
        })?;
        let entries = read_journal_entries(&journal_path)?;

        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[3].event, JournalEvent::StepError { .. }));

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
        assert!(report.steps[0].policy.idempotency_key.0.len() >= 16);

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
