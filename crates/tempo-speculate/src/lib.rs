//! tempo-speculate — replay-fork planning and k-branch scheduling.
//!
//! Native engine forking is optional. The v1 path is replay-fork: load a durable
//! session journal, verify the required cassette records exist, then create branch
//! plans that can replay the prefix before applying speculative action batches.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tempo_driver::{Engine, Unsupported};
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

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "replay-fork planning from durable journals and deterministic k-branch fallback scheduling"
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
            | JournalEvent::Observation { .. }
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

fn sorted_branch_ids(branches: &[BranchRequest]) -> Vec<BranchId> {
    let mut ids: Vec<_> = branches.iter().map(|branch| branch.id.clone()).collect();
    ids.sort();
    ids
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
    #[error("missing cassette required by journal: {0:?}")]
    MissingCassette(CassetteKey),
    #[error("duplicate branch id: {0:?}")]
    DuplicateBranchId(BranchId),
    #[error("invalid branch id: {0:?}")]
    InvalidBranchId(BranchId),
    #[error("replay diverged between {left:?} and {right:?}")]
    ReplayDiverged { left: Engine, right: Engine },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
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
        assert_eq!(plan.branches[0].cassettes, vec![cassette]);
        assert_eq!(
            plan.branches[0].prefix,
            vec![ReplayStep::Applied {
                seq: 1,
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

    fn empty_diff(since_seq: u64, seq: u64) -> ObservationDiff {
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
