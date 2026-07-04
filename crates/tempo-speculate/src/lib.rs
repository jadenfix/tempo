//! tempo-speculate — replay-fork planning and k-branch scheduling.
//!
//! Native engine forking is optional. The v1 path is replay-fork: load a durable
//! session journal, verify the required cassette records exist, then create branch
//! plans that can replay the prefix before applying speculative action batches.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use tempo_act::{execute_action, execute_batch, ActionExecution, ExecutionStatus};
use tempo_driver::{DriverTrait, Engine, TransportError, Unsupported};
use tempo_schema::{Action, ActionBatch, ObservationDiff};
use tempo_session::{
    read_cassettes, read_journal_entries, CassetteKey, JournalEntry, JournalError, JournalEvent,
    ResponseCassette,
};
use thiserror::Error;

/// Stable identifier for one speculative branch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BranchId(pub String);

/// One requested speculative branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BranchRequest {
    pub id: BranchId,
    pub batch: ActionBatch,
}

/// Replayable branch plan. It contains only durable journal and cassette data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayBranch {
    pub id: BranchId,
    pub prefix: Vec<ReplayStep>,
    pub cassettes: Vec<ResponseCassette>,
    pub batch: ActionBatch,
}

/// A replay plan for k requested branches.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayForkPlan {
    pub journal_path: PathBuf,
    pub cassette_path: PathBuf,
    pub start_url: String,
    pub branches: Vec<ReplayBranch>,
}

impl ReplayForkPlan {
    pub fn from_paths(
        journal_path: impl AsRef<Path>,
        cassette_path: impl AsRef<Path>,
        branches: Vec<BranchRequest>,
    ) -> Result<Self, SpeculateError> {
        let journal_path = journal_path.as_ref().to_path_buf();
        let cassette_path = cassette_path.as_ref().to_path_buf();
        let entries = read_journal_entries(&journal_path)?;
        let cassettes = read_cassettes(&cassette_path)?;
        Self::from_records(journal_path, cassette_path, entries, cassettes, branches)
    }

    pub fn from_records(
        journal_path: PathBuf,
        cassette_path: PathBuf,
        entries: Vec<JournalEntry>,
        cassettes: Vec<ResponseCassette>,
        branches: Vec<BranchRequest>,
    ) -> Result<Self, SpeculateError> {
        validate_branch_ids(&branches)?;
        let start_url = session_start_url(&entries)?;
        let prefix = replay_steps(&entries);
        let required = required_cassette_keys(&entries);
        let available = cassette_map(cassettes);
        let mut replay_cassettes = Vec::with_capacity(required.len());

        for key in required {
            let cassette = available
                .get(&key.0)
                .ok_or_else(|| SpeculateError::MissingCassette(key.clone()))?;
            replay_cassettes.push(cassette.clone());
        }

        let mut replay_branches = Vec::with_capacity(branches.len());
        for branch in branches {
            replay_branches.push(ReplayBranch {
                id: branch.id,
                prefix: prefix.clone(),
                cassettes: replay_cassettes.clone(),
                batch: branch.batch,
            });
        }

        Ok(Self {
            journal_path,
            cassette_path,
            start_url,
            branches: replay_branches,
        })
    }
}

/// One journaled action outcome that can be compared across engines.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayStep {
    Applied {
        seq: u64,
        action: Action,
        diff: ObservationDiff,
    },
    StepError {
        seq: u64,
        action: Action,
        reason: String,
    },
}

impl ReplayStep {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Applied { seq, .. } | Self::StepError { seq, .. } => *seq,
        }
    }

    pub fn action(&self) -> &Action {
        match self {
            Self::Applied { action, .. } | Self::StepError { action, .. } => action,
        }
    }

    pub fn outcome(&self) -> ReplayStepOutcome {
        match self {
            Self::Applied { diff, .. } => ReplayStepOutcome::Applied { diff: diff.clone() },
            Self::StepError { reason, .. } => ReplayStepOutcome::StepError {
                reason: reason.clone(),
            },
        }
    }
}

/// The replay-comparable part of a driver step. Journal sequence numbers are
/// intentionally excluded because replay produces fresh journal records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayStepOutcome {
    Applied { diff: ObservationDiff },
    StepError { reason: String },
}

/// Verification result for one replayed historical step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayedPrefixStep {
    pub expected_seq: u64,
    pub action: Action,
    pub outcome: ReplayStepOutcome,
}

/// Execution result for the speculative branch batch after the prefix replay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BranchBatchExecution {
    pub action_count: usize,
    pub outcome: ReplayStepOutcome,
}

/// Concrete replay-fork execution report for one branch lane.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayBranchExecution {
    pub id: BranchId,
    pub engine: Engine,
    pub start_url: String,
    pub prefix: Vec<ReplayedPrefixStep>,
    pub branch: BranchBatchExecution,
}

impl ReplayBranchExecution {
    pub fn evidence(&self) -> ReplayBranchEvidence {
        ReplayBranchEvidence {
            id: self.id.clone(),
            engine: engine_name(self.engine),
            start_url: self.start_url.clone(),
            prefix: self.prefix.clone(),
            branch: self.branch.clone(),
        }
    }
}

/// Concrete k-branch execution report from the replay-fork orchestrator.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayForkExecution {
    pub schedule: BranchSchedule,
    pub branches: Vec<ReplayBranchExecution>,
}

impl ReplayForkExecution {
    pub fn evidence(&self) -> ReplayForkEvidence {
        let branches = self
            .branches
            .iter()
            .map(ReplayBranchExecution::evidence)
            .collect::<Vec<_>>();
        ReplayForkEvidence {
            schedule: self.schedule.clone(),
            branch_count: branches.len(),
            replayed_prefix_steps: branches.iter().map(|branch| branch.prefix.len()).sum(),
            branch_action_count: branches
                .iter()
                .map(|branch| branch.branch.action_count)
                .sum(),
            branches,
        }
    }
}

/// Serializable replay-fork evidence for one branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayBranchEvidence {
    pub id: BranchId,
    pub engine: String,
    pub start_url: String,
    pub prefix: Vec<ReplayedPrefixStep>,
    pub branch: BranchBatchExecution,
}

/// Serializable replay-fork evidence for one k-branch execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayForkEvidence {
    pub schedule: BranchSchedule,
    pub branch_count: usize,
    pub replayed_prefix_steps: usize,
    pub branch_action_count: usize,
    pub branches: Vec<ReplayBranchEvidence>,
}

fn engine_name(engine: Engine) -> String {
    format!("{engine:?}").to_ascii_lowercase()
}

/// Replay output for one engine lane.
#[derive(Clone, Debug, PartialEq)]
pub struct EngineReplay {
    pub engine: Engine,
    pub steps: Vec<ReplayStep>,
}

/// Branch execution order chosen for the current engine capabilities.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BranchSchedule {
    Parallel {
        branches: Vec<BranchId>,
    },
    Sequential {
        branches: Vec<BranchId>,
        reason: String,
    },
}

impl BranchSchedule {
    pub fn branches(&self) -> &[BranchId] {
        match self {
            Self::Parallel { branches } | Self::Sequential { branches, .. } => branches,
        }
    }

    pub fn is_sequential(&self) -> bool {
        matches!(self, Self::Sequential { .. })
    }
}

/// Choose k-branch execution mode. Native fork support allows parallel scheduling;
/// `Unsupported` degrades to deterministic sequential order.
pub fn schedule_branches(
    branches: &[BranchRequest],
    native_fork: Result<(), Unsupported>,
) -> Result<BranchSchedule, SpeculateError> {
    validate_branch_ids(branches)?;
    let ids = sorted_branch_ids(branches);
    match native_fork {
        Ok(()) => Ok(BranchSchedule::Parallel { branches: ids }),
        Err(err) => Ok(BranchSchedule::Sequential {
            branches: ids,
            reason: err.to_string(),
        }),
    }
}

/// Prove that two engine lanes reproduced the same journaled step triples.
pub fn assert_identical_replay(
    left: &EngineReplay,
    right: &EngineReplay,
) -> Result<(), SpeculateError> {
    if left.steps == right.steps {
        Ok(())
    } else {
        Err(SpeculateError::ReplayDiverged {
            left: left.engine,
            right: right.engine,
        })
    }
}

/// Execute one replay-fork branch on a fresh driver lane.
///
/// The caller owns driver provisioning. For engines without native page-state
/// fork, call this once per branch with a newly-created driver so each branch
/// starts from the same durable session state.
pub async fn execute_replay_branch<D>(
    driver: &mut D,
    plan: &ReplayForkPlan,
    branch: &ReplayBranch,
) -> Result<ReplayBranchExecution, SpeculateError>
where
    D: DriverTrait + ?Sized,
{
    let engine = driver.engine();
    driver
        .goto(&plan.start_url)
        .await
        .map_err(|source| SpeculateError::DriverTransport {
            context: "replay goto",
            source,
        })?;

    let mut prefix = Vec::with_capacity(branch.prefix.len());
    for expected in &branch.prefix {
        let execution = execute_action(driver, expected.action())
            .await
            .map_err(|source| SpeculateError::DriverTransport {
                context: "replay action",
                source,
            })?;
        let actual = replay_outcome_from_execution(execution);
        let expected_outcome = expected.outcome();
        if !replay_outcomes_match(&actual, &expected_outcome) {
            return Err(SpeculateError::ReplayStepDiverged {
                branch: branch.id.clone(),
                seq: expected.seq(),
            });
        }
        prefix.push(ReplayedPrefixStep {
            expected_seq: expected.seq(),
            action: expected.action().clone(),
            outcome: actual,
        });
    }

    let branch_execution = execute_batch(driver, &branch.batch)
        .await
        .map_err(|source| SpeculateError::DriverTransport {
            context: "branch batch",
            source,
        })?;
    let branch_result = BranchBatchExecution {
        action_count: branch_execution.action_count,
        outcome: replay_outcome_from_execution(branch_execution),
    };

    Ok(ReplayBranchExecution {
        id: branch.id.clone(),
        engine,
        start_url: plan.start_url.clone(),
        prefix,
        branch: branch_result,
    })
}

/// Execute every branch in a replay-fork plan.
///
/// Drivers with native `fork()` support get one branch-local driver per branch and
/// run the replay jobs concurrently. Engines that return `Unsupported` degrade to
/// deterministic sequential replay: `provision_branch_driver` is invoked once per
/// branch to obtain a *fresh* driver, so each branch starts from clean durable
/// session state (no cookies, storage, or login left over from a sibling branch)
/// before replaying `plan.start_url` and the same journaled prefix. Each provisioned
/// driver is closed after its branch completes.
pub async fn execute_replay_fork<D, F, Fut>(
    driver: &mut D,
    plan: &ReplayForkPlan,
    provision_branch_driver: F,
) -> Result<ReplayForkExecution, SpeculateError>
where
    D: DriverTrait + ?Sized,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Box<dyn DriverTrait>, SpeculateError>>,
{
    let requests = branch_requests(&plan.branches);
    validate_branch_ids(&requests)?;
    let branch_count = requests.len();

    match fork_branch_drivers(driver, branch_count).await {
        Ok(branch_drivers) => {
            let schedule = schedule_branches(&requests, Ok(()))?;
            let branches =
                execute_parallel_replay_branches(plan, schedule.branches(), branch_drivers).await?;
            Ok(ReplayForkExecution { schedule, branches })
        }
        Err(err) => {
            let schedule = schedule_branches(&requests, Err(err))?;
            let branches = execute_sequential_replay_branches(
                plan,
                schedule.branches(),
                provision_branch_driver,
            )
            .await?;
            Ok(ReplayForkExecution { schedule, branches })
        }
    }
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "replay-fork execution from durable journals and deterministic k-branch fallback scheduling"
}

async fn fork_branch_drivers<D>(
    driver: &mut D,
    count: usize,
) -> Result<Vec<Box<dyn DriverTrait>>, Unsupported>
where
    D: DriverTrait + ?Sized,
{
    let mut drivers = Vec::with_capacity(count);
    for _ in 0..count {
        match driver.fork().await {
            Ok(forked) => drivers.push(forked),
            Err(unsupported) => {
                // A later fork failed: close the drivers already forked so a partial
                // fork set does not leak page/target handles before we fall back.
                close_branch_drivers(drivers).await;
                return Err(unsupported);
            }
        }
    }
    Ok(drivers)
}

async fn execute_parallel_replay_branches(
    plan: &ReplayForkPlan,
    branch_ids: &[BranchId],
    branch_drivers: Vec<Box<dyn DriverTrait>>,
) -> Result<Vec<ReplayBranchExecution>, SpeculateError> {
    let mut branches = replay_branch_map(&plan.branches)?;
    let mut jobs = Vec::with_capacity(branch_ids.len());

    for (id, branch_driver) in branch_ids.iter().cloned().zip(branch_drivers) {
        let branch = branches
            .remove(&id)
            .ok_or_else(|| SpeculateError::MissingBranch(id.clone()))?;
        jobs.push(run_and_close_branch(branch_driver, plan, branch));
    }

    // Run every branch to completion (rather than short-circuiting) so each forked
    // driver is closed by its own job even when a sibling branch diverges. Only then
    // surface the first failure, preserving deterministic branch order in the result.
    let results = futures::future::join_all(jobs).await;
    let mut executions = Vec::with_capacity(results.len());
    for result in results {
        executions.push(result?);
    }
    Ok(executions)
}

/// Run one branch on its forked driver and close that driver afterward, on both the
/// success and error paths. A fork is a real page/target/process, so it must be
/// closed explicitly rather than relying on `Drop`, which cannot await.
async fn run_and_close_branch(
    mut branch_driver: Box<dyn DriverTrait>,
    plan: &ReplayForkPlan,
    branch: ReplayBranch,
) -> Result<ReplayBranchExecution, SpeculateError> {
    let result = execute_replay_branch(branch_driver.as_mut(), plan, &branch).await;
    // Best-effort close: never mask the branch outcome with a teardown error.
    let _ = branch_driver.close().await;
    result
}

/// Best-effort close of a set of branch drivers, ignoring teardown errors.
async fn close_branch_drivers(drivers: Vec<Box<dyn DriverTrait>>) {
    for mut driver in drivers {
        let _ = driver.close().await;
    }
}

async fn execute_sequential_replay_branches<F, Fut>(
    plan: &ReplayForkPlan,
    branch_ids: &[BranchId],
    mut provision_branch_driver: F,
) -> Result<Vec<ReplayBranchExecution>, SpeculateError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Box<dyn DriverTrait>, SpeculateError>>,
{
    let mut branches = replay_branch_map(&plan.branches)?;
    let mut executions = Vec::with_capacity(branch_ids.len());

    for id in branch_ids {
        let branch = branches
            .remove(id)
            .ok_or_else(|| SpeculateError::MissingBranch(id.clone()))?;
        // Fresh driver per branch: each speculative branch must start from clean
        // durable session state, never one contaminated by a prior branch.
        let mut branch_driver = provision_branch_driver().await?;
        let result = execute_replay_branch(branch_driver.as_mut(), plan, &branch).await;
        // Best-effort close: never mask the branch outcome with a teardown error.
        let _ = branch_driver.close().await;
        executions.push(result?);
    }

    Ok(executions)
}

fn session_start_url(entries: &[JournalEntry]) -> Result<String, SpeculateError> {
    entries
        .iter()
        .find_map(|entry| match &entry.event {
            JournalEvent::SessionStarted { url } => Some(url.clone()),
            JournalEvent::Observation { .. }
            | JournalEvent::ModelDecision { .. }
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::StepApplied { .. }
            | JournalEvent::StepError { .. }
            | JournalEvent::TransportError { .. }
            | JournalEvent::CassetteRecorded { .. }
            | JournalEvent::SessionClosed => None,
        })
        .ok_or(SpeculateError::MissingSessionStart)
}

fn replay_steps(entries: &[JournalEntry]) -> Vec<ReplayStep> {
    let mut steps = Vec::new();
    for entry in entries {
        match &entry.event {
            JournalEvent::StepApplied { action, diff } => steps.push(ReplayStep::Applied {
                seq: entry.seq,
                action: action.clone(),
                diff: diff.clone(),
            }),
            JournalEvent::StepError { action, reason } => steps.push(ReplayStep::StepError {
                seq: entry.seq,
                action: action.clone(),
                reason: reason.clone(),
            }),
            JournalEvent::SessionStarted { .. }
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::Observation { .. }
            | JournalEvent::ModelDecision { .. }
            | JournalEvent::ActionPlanned { .. }
            | JournalEvent::TransportError { .. }
            | JournalEvent::CassetteRecorded { .. }
            | JournalEvent::SessionClosed => {}
        }
    }
    steps
}

fn required_cassette_keys(entries: &[JournalEntry]) -> Vec<CassetteKey> {
    let mut keys = BTreeMap::new();
    for entry in entries {
        if let JournalEvent::CassetteRecorded { key } = &entry.event {
            keys.insert(key.0.clone(), key.clone());
        }
    }
    keys.into_values().collect()
}

fn cassette_map(cassettes: Vec<ResponseCassette>) -> BTreeMap<String, ResponseCassette> {
    let mut map = BTreeMap::new();
    for cassette in cassettes {
        map.insert(cassette.key.0.clone(), cassette);
    }
    map
}

/// Compare a replayed step outcome against the journaled one on replay-stable
/// content identity only. The `since_seq`/`seq` counters on `ObservationDiff` are
/// relative to the original run: replay re-executes only journaled actions and does
/// not reproduce the standalone `observe()` calls (and real compilers bump `seq` on
/// every compile), so those counters legitimately drift even for identical replays.
/// Comparing added/removed/changed elements (and the step status/reason) avoids the
/// spurious `ReplayStepDiverged` that a raw equality check would produce.
fn replay_outcomes_match(actual: &ReplayStepOutcome, expected: &ReplayStepOutcome) -> bool {
    match (actual, expected) {
        (
            ReplayStepOutcome::Applied { diff: actual_diff },
            ReplayStepOutcome::Applied {
                diff: expected_diff,
            },
        ) => {
            actual_diff.added == expected_diff.added
                && actual_diff.removed == expected_diff.removed
                && actual_diff.changed == expected_diff.changed
        }
        (
            ReplayStepOutcome::StepError {
                reason: actual_reason,
            },
            ReplayStepOutcome::StepError {
                reason: expected_reason,
            },
        ) => actual_reason == expected_reason,
        _ => false,
    }
}

fn replay_outcome_from_execution(execution: ActionExecution) -> ReplayStepOutcome {
    // A `PartiallyApplied` batch step-errored after earlier actions grounded; for
    // replay-divergence purposes it did not fully ground, so it maps to the same
    // StepError outcome as a clean no-op step error.
    match execution.status {
        ExecutionStatus::Applied => ReplayStepOutcome::Applied {
            diff: execution.diff,
        },
        ExecutionStatus::PartiallyApplied { reason } | ExecutionStatus::StepError { reason } => {
            ReplayStepOutcome::StepError { reason }
        }
    }
}

fn sorted_branch_ids(branches: &[BranchRequest]) -> Vec<BranchId> {
    let mut ids: Vec<_> = branches.iter().map(|branch| branch.id.clone()).collect();
    ids.sort();
    ids
}

fn branch_requests(branches: &[ReplayBranch]) -> Vec<BranchRequest> {
    branches
        .iter()
        .map(|branch| BranchRequest {
            id: branch.id.clone(),
            batch: branch.batch.clone(),
        })
        .collect()
}

fn replay_branch_map(
    branches: &[ReplayBranch],
) -> Result<BTreeMap<BranchId, ReplayBranch>, SpeculateError> {
    let mut by_id = BTreeMap::new();
    for branch in branches {
        if by_id.insert(branch.id.clone(), branch.clone()).is_some() {
            return Err(SpeculateError::DuplicateBranchId(branch.id.clone()));
        }
    }
    Ok(by_id)
}

fn validate_branch_ids(branches: &[BranchRequest]) -> Result<(), SpeculateError> {
    let mut ids = BTreeSet::new();
    for branch in branches {
        if branch.id.0.is_empty() {
            return Err(SpeculateError::InvalidBranchId(branch.id.clone()));
        }
        if !ids.insert(branch.id.clone()) {
            return Err(SpeculateError::DuplicateBranchId(branch.id.clone()));
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SpeculateError {
    #[error("session replay data failed: {0}")]
    Journal(#[from] JournalError),
    #[error("journal has no session start URL")]
    MissingSessionStart,
    #[error("missing cassette required by journal: {0:?}")]
    MissingCassette(CassetteKey),
    #[error("duplicate branch id: {0:?}")]
    DuplicateBranchId(BranchId),
    #[error("invalid branch id: {0:?}")]
    InvalidBranchId(BranchId),
    #[error("replay plan is missing branch: {0:?}")]
    MissingBranch(BranchId),
    #[error("{context} failed: {source}")]
    DriverTransport {
        context: &'static str,
        #[source]
        source: TransportError,
    },
    #[error("replay diverged in branch {branch:?} at journal seq {seq}")]
    ReplayStepDiverged { branch: BranchId, seq: u64 },
    #[error("replay diverged between {left:?} and {right:?}")]
    ReplayDiverged { left: Engine, right: Engine },
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::error::Error;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_driver::TestDriver;
    use tempo_schema::QuiescencePolicy;
    use tempo_session::{CassetteStore, RunId, SessionId, SessionJournal};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn replay_plan_loads_journal_prefix_and_required_cassettes_from_disk() -> TestResult {
        let root = unique_dir("plan")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let cassette_path = root.join("cassettes.jsonl");

        let cassette = ResponseCassette::for_request(
            "GET",
            "https://example.com/data",
            [],
            200,
            vec![("content-type".into(), "application/json".into())],
            br#"{"ok":true}"#.to_vec(),
        );
        let cassette_store = CassetteStore::open(&cassette_path)?;
        cassette_store.record(&cassette)?;

        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        journal.append(JournalEvent::CassetteRecorded {
            key: cassette.key.clone(),
        })?;
        let diff = empty_diff(1, 2);
        let action = Action::Scroll { x: 0.0, y: 120.0 };
        journal.append(JournalEvent::StepApplied {
            action: action.clone(),
            diff: diff.clone(),
        })?;

        let branch = branch(
            "branch-b",
            Action::Click {
                node: tempo_schema::NodeId("buy".into()),
            },
        );
        let plan = ReplayForkPlan::from_paths(&journal_path, &cassette_path, vec![branch])?;

        assert_eq!(plan.branches.len(), 1);
        assert_eq!(plan.start_url, "https://example.com");
        assert_eq!(plan.branches[0].cassettes, vec![cassette]);
        assert_eq!(
            plan.branches[0].prefix,
            vec![ReplayStep::Applied {
                seq: 2,
                action,
                diff,
            }]
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn missing_required_cassette_rejects_replay_plan() -> TestResult {
        let root = unique_dir("missing-cassette")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let cassette_path = root.join("cassettes.jsonl");
        CassetteStore::open(&cassette_path)?;

        let key = CassetteKey("required".into());
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://example.com".into(),
        })?;
        journal.append(JournalEvent::CassetteRecorded { key: key.clone() })?;

        let err = ReplayForkPlan::from_paths(
            &journal_path,
            &cassette_path,
            vec![branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 })],
        );
        assert!(matches!(err, Err(SpeculateError::MissingCassette(found)) if found == key));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn missing_session_start_rejects_replay_plan() -> TestResult {
        let root = unique_dir("missing-start")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let cassette_path = root.join("cassettes.jsonl");
        CassetteStore::open(&cassette_path)?;

        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::SessionClosed)?;

        let err = ReplayForkPlan::from_paths(
            &journal_path,
            &cassette_path,
            vec![branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 })],
        );
        assert!(matches!(err, Err(SpeculateError::MissingSessionStart)));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn replay_branch_executes_prefix_and_branch_batch_on_driver() -> TestResult {
        let prefix_action = Action::Scroll { x: 0.0, y: 1.0 };
        let request = BranchRequest {
            id: BranchId("branch-a".into()),
            batch: ActionBatch {
                actions: vec![Action::Scroll { x: 0.0, y: 2.0 }],
                quiescence: QuiescencePolicy::Composite,
            },
        };
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![
                journal_entry(
                    0,
                    JournalEvent::SessionStarted {
                        url: "https://example.com".into(),
                    },
                ),
                journal_entry(
                    1,
                    JournalEvent::StepApplied {
                        action: prefix_action.clone(),
                        diff: empty_diff(1, 2),
                    },
                ),
            ],
            vec![],
            vec![request],
        )?;

        let mut driver = TestDriver::new();
        let report = futures::executor::block_on(execute_replay_branch(
            &mut driver,
            &plan,
            &plan.branches[0],
        ))?;

        assert_eq!(report.id, BranchId("branch-a".into()));
        assert_eq!(report.engine, Engine::Test);
        assert_eq!(report.start_url, "https://example.com");
        assert_eq!(
            report.prefix,
            vec![ReplayedPrefixStep {
                expected_seq: 1,
                action: prefix_action,
                outcome: ReplayStepOutcome::Applied {
                    diff: empty_diff(1, 2),
                },
            }]
        );
        assert_eq!(
            report.branch,
            BranchBatchExecution {
                action_count: 1,
                outcome: ReplayStepOutcome::Applied {
                    diff: empty_diff(2, 3),
                },
            }
        );
        Ok(())
    }

    #[test]
    fn replay_branch_reports_prefix_divergence() -> TestResult {
        let request = BranchRequest {
            id: BranchId("branch-a".into()),
            batch: ActionBatch {
                actions: vec![Action::Scroll { x: 0.0, y: 2.0 }],
                quiescence: QuiescencePolicy::Composite,
            },
        };
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![
                journal_entry(
                    0,
                    JournalEvent::SessionStarted {
                        url: "https://example.com".into(),
                    },
                ),
                journal_entry(
                    7,
                    JournalEvent::StepError {
                        action: Action::Scroll { x: 0.0, y: 1.0 },
                        reason: "historical error".into(),
                    },
                ),
            ],
            vec![],
            vec![request],
        )?;

        let mut driver = TestDriver::new();
        let err = futures::executor::block_on(execute_replay_branch(
            &mut driver,
            &plan,
            &plan.branches[0],
        ));

        assert!(matches!(
            err,
            Err(SpeculateError::ReplayStepDiverged {
                branch,
                seq: 7
            }) if branch == BranchId("branch-a".into())
        ));
        Ok(())
    }

    #[test]
    fn unsupported_native_fork_degrades_to_sorted_sequential_schedule() -> TestResult {
        let requests = vec![
            branch("branch-c", Action::Scroll { x: 0.0, y: 3.0 }),
            branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
            branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
        ];

        let schedule = schedule_branches(&requests, Err(Unsupported("native fork")))?;

        assert_eq!(
            schedule,
            BranchSchedule::Sequential {
                branches: vec![
                    BranchId("branch-a".into()),
                    BranchId("branch-b".into()),
                    BranchId("branch-c".into()),
                ],
                reason: "capability unsupported by this engine: native fork".into(),
            }
        );
        assert!(schedule.is_sequential());
        Ok(())
    }

    #[test]
    fn native_fork_schedules_sorted_parallel_branches() -> TestResult {
        let requests = vec![
            branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
            branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
        ];

        let schedule = schedule_branches(&requests, Ok(()))?;

        assert_eq!(
            schedule,
            BranchSchedule::Parallel {
                branches: vec![BranchId("branch-a".into()), BranchId("branch-b".into())],
            }
        );
        Ok(())
    }

    #[test]
    fn replay_fork_orchestrator_runs_parallel_when_fork_supported() -> TestResult {
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![journal_entry(
                0,
                JournalEvent::SessionStarted {
                    url: "https://example.com".into(),
                },
            )],
            vec![],
            vec![
                branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
                branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
            ],
        )?;
        let mut driver = TestDriver::new();

        let report =
            futures::executor::block_on(execute_replay_fork(&mut driver, &plan, || async {
                Ok(Box::new(TestDriver::new()) as Box<dyn DriverTrait>)
            }))?;

        assert_eq!(
            report.schedule,
            BranchSchedule::Parallel {
                branches: vec![BranchId("branch-a".into()), BranchId("branch-b".into())],
            }
        );
        assert_eq!(
            execution_ids(&report.branches),
            vec!["branch-a", "branch-b"]
        );
        assert!(report
            .branches
            .iter()
            .all(|branch| branch.engine == Engine::Test && branch.branch.action_count == 1));
        Ok(())
    }

    #[test]
    fn replay_fork_orchestrator_degrades_unsupported_driver_to_sequential() -> TestResult {
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![journal_entry(
                0,
                JournalEvent::SessionStarted {
                    url: "https://example.com".into(),
                },
            )],
            vec![],
            vec![
                branch("branch-c", Action::Scroll { x: 0.0, y: 3.0 }),
                branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
                branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
            ],
        )?;
        let mut driver = NoForkDriver::new();

        let report =
            futures::executor::block_on(execute_replay_fork(&mut driver, &plan, || async {
                Ok(Box::new(TestDriver::new()) as Box<dyn DriverTrait>)
            }))?;

        assert_eq!(
            report.schedule,
            BranchSchedule::Sequential {
                branches: vec![
                    BranchId("branch-a".into()),
                    BranchId("branch-b".into()),
                    BranchId("branch-c".into()),
                ],
                reason: "capability unsupported by this engine: native fork".into(),
            }
        );
        assert_eq!(
            execution_ids(&report.branches),
            vec!["branch-a", "branch-b", "branch-c"]
        );
        assert!(report
            .branches
            .iter()
            .all(|branch| branch.engine == Engine::Test && branch.branch.action_count == 1));
        Ok(())
    }

    #[test]
    fn replay_fork_evidence_serializes_schedule_and_branch_outcomes() -> TestResult {
        let execution = ReplayForkExecution {
            schedule: BranchSchedule::Sequential {
                branches: vec![BranchId("branch-a".into())],
                reason: "capability unsupported by this engine: native fork".into(),
            },
            branches: vec![ReplayBranchExecution {
                id: BranchId("branch-a".into()),
                engine: Engine::Test,
                start_url: "https://example.com".into(),
                prefix: vec![ReplayedPrefixStep {
                    expected_seq: 1,
                    action: Action::Scroll { x: 0.0, y: 1.0 },
                    outcome: ReplayStepOutcome::Applied {
                        diff: empty_diff(1, 2),
                    },
                }],
                branch: BranchBatchExecution {
                    action_count: 2,
                    outcome: ReplayStepOutcome::Applied {
                        diff: empty_diff(2, 3),
                    },
                },
            }],
        };

        let evidence = execution.evidence();
        let value = serde_json::to_value(&evidence)?;

        assert_eq!(evidence.branch_count, 1);
        assert_eq!(evidence.replayed_prefix_steps, 1);
        assert_eq!(evidence.branch_action_count, 2);
        assert_eq!(value["schedule"]["mode"], "sequential");
        assert_eq!(value["branches"][0]["engine"], "test");
        assert_eq!(value["branches"][0]["prefix"][0]["expected_seq"], 1);
        assert_eq!(value["branches"][0]["branch"]["action_count"], 2);
        Ok(())
    }

    #[test]
    fn reusing_one_driver_across_branches_contaminates_state() -> TestResult {
        // Directly documents the hazard the sequential fallback must avoid: a driver
        // whose durable state survives `goto` diverges on the second branch because it
        // carries residue from the first. This is exactly why each branch needs a
        // fresh/clean driver.
        let plan = single_step_prefix_plan("branch-a");
        let closes = Arc::new(AtomicUsize::new(0));
        let mut driver = StatefulDriver::new(Arc::clone(&closes));

        // First branch on a clean driver replays cleanly.
        futures::executor::block_on(execute_replay_branch(&mut driver, &plan, &plan.branches[0]))?;

        // Reusing the same driver for a second branch diverges on the prefix: leftover
        // state from branch one shows up as extra observed content.
        let err = futures::executor::block_on(execute_replay_branch(
            &mut driver,
            &plan,
            &plan.branches[0],
        ));
        assert!(matches!(
            err,
            Err(SpeculateError::ReplayStepDiverged { branch, .. })
                if branch == BranchId("branch-a".into())
        ));
        Ok(())
    }

    #[test]
    fn sequential_fallback_provisions_fresh_closed_driver_per_branch() -> TestResult {
        // #111 + #113 (sequential path): the fork-less orchestrator must hand every
        // branch a freshly provisioned, clean driver and close it afterward. Using
        // `StatefulDriver` (whose state would contaminate a reused instance) proves the
        // branches stay isolated: if any branch reused a prior driver, its prefix would
        // diverge.
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![
                journal_entry(
                    0,
                    JournalEvent::SessionStarted {
                        url: "https://example.com".into(),
                    },
                ),
                journal_entry(
                    1,
                    JournalEvent::StepApplied {
                        action: Action::Scroll { x: 0.0, y: 1.0 },
                        diff: empty_diff(1, 2),
                    },
                ),
            ],
            vec![],
            vec![
                branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
                branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
            ],
        )?;
        // Fork source reports Unsupported so the orchestrator takes the sequential path.
        let mut fork_source = NoForkDriver::new();
        let provisioned = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));
        let provisioned_for_closure = Arc::clone(&provisioned);
        let closes_for_closure = Arc::clone(&closes);

        let report =
            futures::executor::block_on(execute_replay_fork(&mut fork_source, &plan, move || {
                provisioned_for_closure.fetch_add(1, Ordering::SeqCst);
                let closes = Arc::clone(&closes_for_closure);
                async move { Ok(Box::new(StatefulDriver::new(closes)) as Box<dyn DriverTrait>) }
            }))?;

        assert!(report.schedule.is_sequential());
        assert_eq!(
            execution_ids(&report.branches),
            vec!["branch-a", "branch-b"]
        );
        // One fresh driver provisioned and closed per branch.
        assert_eq!(provisioned.load(Ordering::SeqCst), 2);
        assert_eq!(closes.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn identical_replay_with_drifting_seq_is_not_divergent_but_content_change_is() -> TestResult {
        // #112: replay diffs carry run-relative `since_seq`/`seq` counters that drift
        // (real compilers bump `seq` on every observe). Identical content must NOT be
        // flagged divergent, while a genuine content change still must be.
        let plan = single_step_prefix_plan("branch-a");

        // Same content, but the observation counters drift by 5 as a live compiler
        // would: this must replay cleanly.
        let mut drifted = RecompilingDriver::new(5, vec![]);
        let report = futures::executor::block_on(execute_replay_branch(
            &mut drifted,
            &plan,
            &plan.branches[0],
        ))?;
        assert_eq!(report.id, BranchId("branch-a".into()));

        // A real content change (an extra observed element) must still diverge.
        let mut changed = RecompilingDriver::new(0, vec![marker_element("leaked")]);
        let err = futures::executor::block_on(execute_replay_branch(
            &mut changed,
            &plan,
            &plan.branches[0],
        ));
        assert!(matches!(
            err,
            Err(SpeculateError::ReplayStepDiverged { branch, .. })
                if branch == BranchId("branch-a".into())
        ));
        Ok(())
    }

    #[test]
    fn parallel_replay_fork_closes_every_forked_driver() -> TestResult {
        // #113 (parallel path): each forked branch driver must be closed after its
        // branch completes.
        let plan = ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            vec![journal_entry(
                0,
                JournalEvent::SessionStarted {
                    url: "https://example.com".into(),
                },
            )],
            vec![],
            vec![
                branch("branch-a", Action::Scroll { x: 0.0, y: 1.0 }),
                branch("branch-b", Action::Scroll { x: 0.0, y: 2.0 }),
            ],
        )?;
        let closes = Arc::new(AtomicUsize::new(0));
        let mut fork_source = CountingForkDriver::new(Arc::clone(&closes));

        let report =
            futures::executor::block_on(execute_replay_fork(&mut fork_source, &plan, || async {
                Ok(Box::new(TestDriver::new()) as Box<dyn DriverTrait>)
            }))?;

        assert!(!report.schedule.is_sequential());
        assert_eq!(
            execution_ids(&report.branches),
            vec!["branch-a", "branch-b"]
        );
        // Both forked branch drivers were closed (the fork source itself is not).
        assert_eq!(closes.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn replay_comparison_accepts_identical_steps_across_engines() -> TestResult {
        let steps = vec![ReplayStep::Applied {
            seq: 7,
            action: Action::Extract {
                node: tempo_schema::NodeId("main".into()),
            },
            diff: empty_diff(6, 7),
        }];

        assert_identical_replay(
            &EngineReplay {
                engine: Engine::Cdp,
                steps: steps.clone(),
            },
            &EngineReplay {
                engine: Engine::Servo,
                steps,
            },
        )?;
        Ok(())
    }

    #[test]
    fn replay_comparison_rejects_divergent_steps() {
        let left = EngineReplay {
            engine: Engine::Cdp,
            steps: vec![ReplayStep::StepError {
                seq: 1,
                action: Action::Scroll { x: 0.0, y: 1.0 },
                reason: "left".into(),
            }],
        };
        let right = EngineReplay {
            engine: Engine::Servo,
            steps: vec![ReplayStep::StepError {
                seq: 1,
                action: Action::Scroll { x: 0.0, y: 1.0 },
                reason: "right".into(),
            }],
        };

        assert!(matches!(
            assert_identical_replay(&left, &right),
            Err(SpeculateError::ReplayDiverged {
                left: Engine::Cdp,
                right: Engine::Servo
            })
        ));
    }

    #[test]
    fn duplicate_branch_ids_are_rejected() {
        let requests = vec![
            branch("same", Action::Scroll { x: 0.0, y: 1.0 }),
            branch("same", Action::Scroll { x: 0.0, y: 2.0 }),
        ];

        assert!(matches!(
            schedule_branches(&requests, Ok(())),
            Err(SpeculateError::DuplicateBranchId(id)) if id == BranchId("same".into())
        ));
    }

    fn branch(id: &str, action: Action) -> BranchRequest {
        BranchRequest {
            id: BranchId(id.into()),
            batch: ActionBatch {
                actions: vec![action],
                quiescence: QuiescencePolicy::Composite,
            },
        }
    }

    /// A one-branch plan whose prefix is a single applied Scroll with an empty diff,
    /// starting from `https://example.com`.
    fn single_step_prefix_plan(branch_id: &str) -> ReplayForkPlan {
        let entries = vec![
            journal_entry(
                0,
                JournalEvent::SessionStarted {
                    url: "https://example.com".into(),
                },
            ),
            journal_entry(
                1,
                JournalEvent::StepApplied {
                    action: Action::Scroll { x: 0.0, y: 1.0 },
                    diff: empty_diff(1, 2),
                },
            ),
        ];
        match ReplayForkPlan::from_records(
            PathBuf::from("session.jsonl"),
            PathBuf::from("cassettes.jsonl"),
            entries,
            vec![],
            vec![branch(branch_id, Action::Scroll { x: 0.0, y: 2.0 })],
        ) {
            Ok(plan) => plan,
            Err(err) => unreachable!("valid fixture plan should build: {err:?}"),
        }
    }

    fn marker_element(node: &str) -> tempo_schema::InteractiveElement {
        tempo_schema::InteractiveElement {
            node_id: tempo_schema::NodeId(node.into()),
            role: "button".into(),
            name: vec![],
            value: vec![],
            bounds: None,
            rank: 0.0,
        }
    }

    fn empty_diff(since_seq: u64, seq: u64) -> ObservationDiff {
        ObservationDiff {
            since_seq,
            seq,
            added: vec![],
            removed: vec![],
            changed: vec![],
        }
    }

    fn journal_entry(seq: u64, event: JournalEvent) -> JournalEntry {
        JournalEntry {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            run_id: RunId("run".into()),
            session_id: SessionId("session".into()),
            seq,
            timestamp_ms: 0,
            event,
        }
    }

    fn execution_ids(executions: &[ReplayBranchExecution]) -> Vec<&str> {
        executions
            .iter()
            .map(|execution| execution.id.0.as_str())
            .collect()
    }

    struct NoForkDriver {
        inner: TestDriver,
    }

    impl NoForkDriver {
        fn new() -> Self {
            Self {
                inner: TestDriver::new(),
            }
        }
    }

    #[async_trait]
    impl DriverTrait for NoForkDriver {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(
            &mut self,
            url: &str,
        ) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.inner.observe_diff(since_seq).await
        }

        async fn act(
            &mut self,
            action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(
            &mut self,
            batch: &ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("native fork"))
        }

        async fn extract(
            &mut self,
            node: &tempo_schema::NodeId,
        ) -> Result<serde_json::Value, TransportError> {
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

    /// Driver whose durable state (a navigation counter) survives `goto`, so reuse
    /// across branches leaks observable content. Never forks (forces the sequential
    /// path) and counts `close()` calls.
    struct StatefulDriver {
        inner: TestDriver,
        navigations: u64,
        closes: Arc<AtomicUsize>,
    }

    impl StatefulDriver {
        fn new(closes: Arc<AtomicUsize>) -> Self {
            Self {
                inner: TestDriver::new(),
                navigations: 0,
                closes,
            }
        }
    }

    #[async_trait]
    impl DriverTrait for StatefulDriver {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(
            &mut self,
            url: &str,
        ) -> Result<tempo_schema::CompiledObservation, TransportError> {
            // Real engines do not drop cookies/storage on navigation; model that by
            // accumulating state across gotos rather than resetting.
            self.navigations += 1;
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            let mut diff = self.inner.observe_diff(since_seq).await?;
            // Residual content from prior branches: zero on a freshly provisioned
            // driver (one navigation), non-empty once reused.
            let residual = self.navigations.saturating_sub(1);
            diff.added = (0..residual)
                .map(|i| marker_element(&format!("residual-{i}")))
                .collect();
            Ok(diff)
        }

        async fn act(
            &mut self,
            action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(
            &mut self,
            batch: &ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("native fork"))
        }

        async fn extract(
            &mut self,
            node: &tempo_schema::NodeId,
        ) -> Result<serde_json::Value, TransportError> {
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
            self.closes.fetch_add(1, Ordering::SeqCst);
            self.inner.close().await
        }
    }

    /// Driver that simulates a live compiler: `observe_diff` drifts the run-relative
    /// `since_seq`/`seq` counters and can inject a genuine content change, without
    /// touching the replay-stable added/removed/changed sets unless asked.
    struct RecompilingDriver {
        inner: TestDriver,
        seq_drift: u64,
        injected_added: Vec<tempo_schema::InteractiveElement>,
    }

    impl RecompilingDriver {
        fn new(seq_drift: u64, injected_added: Vec<tempo_schema::InteractiveElement>) -> Self {
            Self {
                inner: TestDriver::new(),
                seq_drift,
                injected_added,
            }
        }
    }

    #[async_trait]
    impl DriverTrait for RecompilingDriver {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(
            &mut self,
            url: &str,
        ) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            let mut diff = self.inner.observe_diff(since_seq).await?;
            diff.since_seq += self.seq_drift;
            diff.seq += self.seq_drift;
            diff.added = self.injected_added.clone();
            Ok(diff)
        }

        async fn act(
            &mut self,
            action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(
            &mut self,
            batch: &ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("native fork"))
        }

        async fn extract(
            &mut self,
            node: &tempo_schema::NodeId,
        ) -> Result<serde_json::Value, TransportError> {
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

    /// Fork source whose forked children count their own `close()` calls, letting the
    /// parallel path assert every branch driver is torn down.
    struct CountingForkDriver {
        inner: TestDriver,
        closes: Arc<AtomicUsize>,
    }

    impl CountingForkDriver {
        fn new(closes: Arc<AtomicUsize>) -> Self {
            Self {
                inner: TestDriver::new(),
                closes,
            }
        }
    }

    /// A forked child of `CountingForkDriver` that records when it is closed.
    struct CountingForkChild {
        inner: TestDriver,
        closes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DriverTrait for CountingForkDriver {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(
            &mut self,
            url: &str,
        ) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.inner.observe_diff(since_seq).await
        }

        async fn act(
            &mut self,
            action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(
            &mut self,
            batch: &ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Ok(Box::new(CountingForkChild {
                inner: TestDriver::new(),
                closes: Arc::clone(&self.closes),
            }))
        }

        async fn extract(
            &mut self,
            node: &tempo_schema::NodeId,
        ) -> Result<serde_json::Value, TransportError> {
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

    #[async_trait]
    impl DriverTrait for CountingForkChild {
        fn engine(&self) -> Engine {
            self.inner.engine()
        }

        async fn goto(
            &mut self,
            url: &str,
        ) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.goto(url).await
        }

        async fn observe(&mut self) -> Result<tempo_schema::CompiledObservation, TransportError> {
            self.inner.observe().await
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.inner.observe_diff(since_seq).await
        }

        async fn act(
            &mut self,
            action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act(action).await
        }

        async fn act_batch(
            &mut self,
            batch: &ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.inner.act_batch(batch).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            Err(Unsupported("native fork"))
        }

        async fn extract(
            &mut self,
            node: &tempo_schema::NodeId,
        ) -> Result<serde_json::Value, TransportError> {
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
            self.closes.fetch_add(1, Ordering::SeqCst);
            self.inner.close().await
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-speculate-{label}-{}-{nanos}",
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
