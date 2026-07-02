//! tempo-agent — durable task loop primitives.
//!
//! The model client and engine executor sit above this crate. This layer owns the
//! crash-safe runtime contract: token budgeting, stable idempotency keys, journal
//! resume, and StepTriple extraction from durable session records.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use tempo_driver::StepOutcome;
use tempo_schema::{Action, ObservationDiff};
use tempo_session::{
    read_journal_entries, JournalEntry, JournalError, JournalEvent, RunId, SessionId,
    SessionJournal,
};
use thiserror::Error;

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
}

impl ResumeCursor {
    pub fn from_entries(plan: &TaskPlan, entries: &[JournalEntry]) -> Result<Self, AgentError> {
        let mut completed_steps = 0_usize;
        let mut pending_plan_index = None;

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
                JournalEvent::StepApplied { action, .. }
                | JournalEvent::StepError { action, .. } => {
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
                JournalEvent::SessionStarted { .. }
                | JournalEvent::Observation { .. }
                | JournalEvent::TransportError { .. }
                | JournalEvent::CassetteRecorded { .. }
                | JournalEvent::SessionClosed => {}
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
        self.cursor.completed_steps += 1;
        self.cursor.next_step += 1;
        self.cursor.pending_planned = None;

        StepTriple::from_event(step.key, entry.seq, step.action, event)
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

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "durable agent loop core with token budgets, idempotent resume, and StepTriple extraction"
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("agent JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("token budget exceeded: attempted {attempted}, max {max}")]
    TokenBudgetExceeded { attempted: u64, max: u64 },
    #[error("task plan is already complete")]
    PlanComplete,
    #[error("journal action diverged from plan at step {index}")]
    JournalDiverged { index: usize },
    #[error("journal contains extra step at index {index}")]
    JournalHasExtraStep { index: usize },
    #[error("journal event at seq {seq} is not a step outcome")]
    JournalEventIsNotStep { seq: u64 },
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
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_schema::ObservationDiff;

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

    fn diff(since_seq: u64, seq: u64) -> ObservationDiff {
        ObservationDiff {
            since_seq,
            seq,
            added: vec![],
            removed: vec![],
            changed: vec![],
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
}
