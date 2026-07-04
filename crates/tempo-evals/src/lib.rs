//! tempo-evals — scorecards and regression gates for persisted tempo runs.
//!
//! This crate consumes real eval artifacts: JSONL records emitted by CI/nightly
//! suites and durable `tempo-session` journals. It computes budget percentiles,
//! per-origin lane choices, fallback rates, and typed gate violations.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tempo_session::{
    read_journal_entries_with_retention_policy, DurableRetentionPolicy, JournalEntry, JournalError,
    JournalEvent,
};
use thiserror::Error;

/// Runtime lane used for an eval case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Api,
    Servo,
    Cdp,
}

/// One persisted case result from an eval run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRecord {
    pub suite: String,
    pub case_id: String,
    pub origin: String,
    pub lane: Lane,
    pub success: bool,
    pub fallback_used: bool,
    pub max_observation_bytes: u64,
    pub max_observation_tokens: u64,
    /// Raw per-observation observe latencies (ms). Retained (not collapsed to a
    /// per-case p95) so scorecard percentiles are computed over real samples.
    pub observe_latencies_ms: Vec<u64>,
    /// Raw per-action apply latencies (ms), retained for the same reason.
    pub action_latencies_ms: Vec<u64>,
    pub wall_clock_ms: u64,
    #[serde(default)]
    pub baseline_wall_clock_ms: Option<u64>,
    #[serde(default)]
    pub unconfirmed_high_risk_actions: u64,
    #[serde(default)]
    pub step_count: u64,
}

/// Metadata needed to convert a durable session journal into one eval record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvalDescriptor {
    pub suite: String,
    pub case_id: String,
    pub origin: String,
    pub lane: Lane,
    pub success: bool,
    pub fallback_used: bool,
    #[serde(default)]
    pub baseline_wall_clock_ms: Option<u64>,
    #[serde(default)]
    pub unconfirmed_high_risk_actions: u64,
}

/// Budget thresholds enforced by CI and nightly scorecards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalBudget {
    pub min_success_rate: f64,
    pub max_fallback_rate: f64,
    pub max_observation_bytes_p50: u64,
    pub max_observation_bytes_p95: u64,
    pub max_observation_tokens_p50: u64,
    pub max_observe_latency_ms_p50: u64,
    pub max_observe_latency_ms_p95: u64,
    pub max_action_latency_ms_p50: u64,
    pub max_unconfirmed_high_risk_actions: u64,
    #[serde(default = "default_speculation_reduction")]
    pub min_speculation_reduction: Option<f64>,
}

impl Default for EvalBudget {
    fn default() -> Self {
        Self {
            min_success_rate: 0.0,
            max_fallback_rate: 1.0,
            max_observation_bytes_p50: 4 * 1024,
            max_observation_bytes_p95: 8 * 1024,
            max_observation_tokens_p50: 1_500,
            max_observe_latency_ms_p50: 150,
            max_observe_latency_ms_p95: 500,
            max_action_latency_ms_p50: 1_200,
            max_unconfirmed_high_risk_actions: 0,
            min_speculation_reduction: default_speculation_reduction(),
        }
    }
}

/// Aggregated scorecard for one eval run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Scorecard {
    pub total_cases: usize,
    pub success_rate: f64,
    pub fallback_rate: f64,
    pub observation_bytes_p50: u64,
    pub observation_bytes_p95: u64,
    pub observation_tokens_p50: u64,
    pub observe_latency_ms_p50: u64,
    pub observe_latency_ms_p95: u64,
    pub action_latency_ms_p50: u64,
    pub max_unconfirmed_high_risk_actions: u64,
    #[serde(default)]
    pub speculation_reduction_p50: Option<f64>,
    pub suites: Vec<SuiteScore>,
    pub lanes: Vec<LaneScore>,
    pub origins: Vec<OriginLaneScore>,
    pub violations: Vec<GateViolation>,
}

/// Per-suite scorecard row for WebVoyager/WebArena/Mind2Web-style gates.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SuiteScore {
    pub suite: String,
    pub total_cases: usize,
    pub success_rate: f64,
    pub fallback_rate: f64,
    pub speculation_reduction_p50: Option<f64>,
    pub max_unconfirmed_high_risk_actions: u64,
}

/// Per-runtime-lane scorecard row used to compare Servo/CDP/API behavior.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LaneScore {
    pub lane: Lane,
    pub total_cases: usize,
    pub success_rate: f64,
    pub fallback_rate: f64,
}

/// Per-origin lane table entry consumed by runtime fallback selection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OriginLaneScore {
    pub origin: String,
    pub selected_lane: Lane,
    pub total_cases: usize,
    pub success_rate: f64,
    pub fallback_rate: f64,
}

/// A typed regression gate failure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum GateViolation {
    SuccessRate { observed: f64, min: f64 },
    FallbackRate { observed: f64, max: f64 },
    ObservationBytesP50 { observed: u64, max: u64 },
    ObservationBytesP95 { observed: u64, max: u64 },
    ObservationTokensP50 { observed: u64, max: u64 },
    ObserveLatencyP50 { observed: u64, max: u64 },
    ObserveLatencyP95 { observed: u64, max: u64 },
    ActionLatencyP50 { observed: u64, max: u64 },
    UnconfirmedHighRiskActions { observed: u64, max: u64 },
    MissingSpeculationData { min: f64 },
    SpeculationReduction { observed: f64, min: f64 },
}

impl Scorecard {
    pub fn from_records(records: &[EvalRecord], budget: &EvalBudget) -> Result<Self, EvalError> {
        if records.is_empty() {
            return Err(EvalError::EmptyRun);
        }

        let total_cases = records.len();
        let success_rate = rate(
            records.iter().filter(|record| record.success).count(),
            total_cases,
        );
        let fallback_rate = rate(
            records.iter().filter(|record| record.fallback_used).count(),
            total_cases,
        );
        let observation_bytes_p50 = percentile_u64(
            records.iter().map(|record| record.max_observation_bytes),
            0.50,
        );
        let observation_bytes_p95 = percentile_u64(
            records.iter().map(|record| record.max_observation_bytes),
            0.95,
        );
        let observation_tokens_p50 = percentile_u64(
            records.iter().map(|record| record.max_observation_tokens),
            0.50,
        );
        // Pool raw per-observation samples across every record, then take true
        // percentiles. Percentiling the already-collapsed per-case p95s would
        // make "p50" a median-of-p95s (see issue #115).
        let observe_latency_ms_p50 = percentile_u64(
            records
                .iter()
                .flat_map(|record| record.observe_latencies_ms.iter().copied()),
            0.50,
        );
        let observe_latency_ms_p95 = percentile_u64(
            records
                .iter()
                .flat_map(|record| record.observe_latencies_ms.iter().copied()),
            0.95,
        );
        let action_latency_ms_p50 = percentile_u64(
            records
                .iter()
                .flat_map(|record| record.action_latencies_ms.iter().copied()),
            0.50,
        );
        let max_unconfirmed_high_risk_actions = records
            .iter()
            .map(|record| record.unconfirmed_high_risk_actions)
            .max()
            .unwrap_or(0);
        let speculation_reduction_p50 = speculation_reduction_p50(records);
        let suites = suite_table(records);
        let lanes = lane_table(records);
        let origins = origin_lane_table(records);

        let mut scorecard = Self {
            total_cases,
            success_rate,
            fallback_rate,
            observation_bytes_p50,
            observation_bytes_p95,
            observation_tokens_p50,
            observe_latency_ms_p50,
            observe_latency_ms_p95,
            action_latency_ms_p50,
            max_unconfirmed_high_risk_actions,
            speculation_reduction_p50,
            suites,
            lanes,
            origins,
            violations: Vec::new(),
        };

        scorecard.violations = gate_violations(&scorecard, budget);
        Ok(scorecard)
    }

    pub fn passes(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Read line-delimited eval records from disk.
pub fn read_eval_records(path: impl AsRef<Path>) -> Result<Vec<EvalRecord>, EvalError> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(|source| EvalError::Io {
        path: path.clone(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| EvalError::Io {
            path: path.clone(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str(&line).map_err(|source| EvalError::JsonLine {
            path: path.clone(),
            line: line_number,
            source,
        })?;
        records.push(record);
    }

    Ok(records)
}

/// Write a scorecard JSON artifact to disk.
pub fn write_scorecard(path: impl AsRef<Path>, scorecard: &Scorecard) -> Result<(), EvalError> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| EvalError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let file = File::create(&path).map_err(|source| EvalError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::to_writer_pretty(file, scorecard)
        .map_err(|source| EvalError::JsonWrite { path, source })
}

/// Convert a real session journal into one eval record.
pub fn eval_record_from_session_journal(
    journal_path: impl AsRef<Path>,
    descriptor: SessionEvalDescriptor,
) -> Result<EvalRecord, EvalError> {
    eval_record_from_session_journal_with_retention_policy(
        journal_path,
        descriptor,
        &DurableRetentionPolicy::PlaintextUnsafe,
    )
}

/// Convert a real session journal into one eval record using the caller's durable
/// retention policy.
pub fn eval_record_from_session_journal_with_retention_policy(
    journal_path: impl AsRef<Path>,
    descriptor: SessionEvalDescriptor,
    retention_policy: &DurableRetentionPolicy,
) -> Result<EvalRecord, EvalError> {
    let entries = read_journal_entries_with_retention_policy(journal_path, retention_policy)?;
    eval_record_from_journal_entries(&entries, descriptor)
}

fn eval_record_from_journal_entries(
    entries: &[JournalEntry],
    descriptor: SessionEvalDescriptor,
) -> Result<EvalRecord, EvalError> {
    let mut observation_bytes = Vec::new();
    let mut observation_tokens = Vec::new();
    let mut observe_latencies = Vec::new();
    let mut action_latencies = Vec::new();
    let mut step_count = 0_u64;
    let mut session_start_ms = None;
    let mut last_observe_start_ms = None;
    let mut last_action_start_ms = None;
    let mut end_ms = None;

    for entry in entries {
        end_ms = Some(entry.timestamp_ms);
        match &entry.event {
            JournalEvent::SessionStarted { .. } => {
                session_start_ms = Some(entry.timestamp_ms);
                last_observe_start_ms = Some(entry.timestamp_ms);
            }
            JournalEvent::Observation { observation } => {
                let bytes = serde_json::to_vec(observation)
                    .map_err(|source| EvalError::ObservationSerialize { source })?
                    .len() as u64;
                observation_bytes.push(bytes);
                observation_tokens.push(estimated_tokens(bytes));
                if let Some(start) = last_observe_start_ms.take() {
                    observe_latencies.push(duration_ms(start, entry.timestamp_ms));
                }
            }
            JournalEvent::ActionPlanned { .. } => {
                last_action_start_ms = Some(entry.timestamp_ms);
            }
            JournalEvent::StepApplied { .. } | JournalEvent::StepError { .. } => {
                step_count = step_count.saturating_add(1);
                if let Some(start) = last_action_start_ms.take() {
                    action_latencies.push(duration_ms(start, entry.timestamp_ms));
                }
                last_observe_start_ms = Some(entry.timestamp_ms);
            }
            JournalEvent::TransportError { .. }
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::CassetteRecorded { .. }
            | JournalEvent::SessionClosed => {}
        }
    }

    // A journal without a `SessionStarted` event has no wall-clock anchor.
    // Treat that as an error rather than silently emitting `wall_clock_ms = 0`,
    // which would fake a 100% speculation reduction against a baseline (#115).
    let wall_clock_ms = match (session_start_ms, end_ms) {
        (Some(start), Some(end)) => duration_ms(start, end),
        _ => return Err(EvalError::MissingSessionStart),
    };

    Ok(EvalRecord {
        suite: descriptor.suite,
        case_id: descriptor.case_id,
        origin: descriptor.origin,
        lane: descriptor.lane,
        success: descriptor.success,
        fallback_used: descriptor.fallback_used,
        max_observation_bytes: observation_bytes.into_iter().max().unwrap_or(0),
        max_observation_tokens: observation_tokens.into_iter().max().unwrap_or(0),
        // Retain every raw sample; percentiles are computed downstream.
        observe_latencies_ms: observe_latencies,
        action_latencies_ms: action_latencies,
        wall_clock_ms,
        baseline_wall_clock_ms: descriptor.baseline_wall_clock_ms,
        unconfirmed_high_risk_actions: descriptor.unconfirmed_high_risk_actions,
        step_count,
    })
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "scorecard regression gates over persisted eval records and tempo session journals"
}

fn suite_table(records: &[EvalRecord]) -> Vec<SuiteScore> {
    let mut by_suite: BTreeMap<&str, SuiteAccumulator> = BTreeMap::new();
    for record in records {
        by_suite.entry(&record.suite).or_default().push(record);
    }

    by_suite
        .into_iter()
        .map(|(suite, acc)| acc.score(suite))
        .collect()
}

fn lane_table(records: &[EvalRecord]) -> Vec<LaneScore> {
    let mut by_lane: BTreeMap<Lane, LaneAccumulator> = BTreeMap::new();
    for record in records {
        by_lane.entry(record.lane).or_default().push(record);
    }

    by_lane
        .into_iter()
        .map(|(lane, acc)| acc.lane_score(lane))
        .collect()
}

fn origin_lane_table(records: &[EvalRecord]) -> Vec<OriginLaneScore> {
    let mut by_origin_lane: BTreeMap<(&str, Lane), LaneAccumulator> = BTreeMap::new();
    for record in records {
        by_origin_lane
            .entry((&record.origin, record.lane))
            .or_default()
            .push(record);
    }

    let mut by_origin: BTreeMap<&str, Vec<OriginLaneScore>> = BTreeMap::new();
    for ((origin, lane), acc) in by_origin_lane {
        by_origin
            .entry(origin)
            .or_default()
            .push(acc.origin_score(origin, lane));
    }

    let mut table = Vec::new();
    for (_origin, mut lanes) in by_origin {
        lanes.sort_by(compare_lane_scores);
        if let Some(score) = lanes.into_iter().next() {
            table.push(score);
        }
    }
    table
}

fn compare_lane_scores(left: &OriginLaneScore, right: &OriginLaneScore) -> Ordering {
    right
        .success_rate
        .total_cmp(&left.success_rate)
        .then_with(|| left.fallback_rate.total_cmp(&right.fallback_rate))
        .then_with(|| right.total_cases.cmp(&left.total_cases))
        .then_with(|| left.selected_lane.cmp(&right.selected_lane))
}

#[derive(Default)]
struct SuiteAccumulator {
    total: usize,
    successes: usize,
    fallbacks: usize,
    max_unconfirmed_high_risk_actions: u64,
    speculation_reductions: Vec<f64>,
}

impl SuiteAccumulator {
    fn push(&mut self, record: &EvalRecord) {
        self.total += 1;
        if record.success {
            self.successes += 1;
        }
        if record.fallback_used {
            self.fallbacks += 1;
        }
        self.max_unconfirmed_high_risk_actions = self
            .max_unconfirmed_high_risk_actions
            .max(record.unconfirmed_high_risk_actions);
        if let Some(reduction) = record_speculation_reduction(record) {
            self.speculation_reductions.push(reduction);
        }
    }

    fn score(self, suite: &str) -> SuiteScore {
        SuiteScore {
            suite: suite.into(),
            total_cases: self.total,
            success_rate: rate(self.successes, self.total),
            fallback_rate: rate(self.fallbacks, self.total),
            speculation_reduction_p50: percentile_f64(self.speculation_reductions, 0.50),
            max_unconfirmed_high_risk_actions: self.max_unconfirmed_high_risk_actions,
        }
    }
}

#[derive(Default)]
struct LaneAccumulator {
    total: usize,
    successes: usize,
    fallbacks: usize,
}

impl LaneAccumulator {
    fn push(&mut self, record: &EvalRecord) {
        self.total += 1;
        if record.success {
            self.successes += 1;
        }
        if record.fallback_used {
            self.fallbacks += 1;
        }
    }

    fn lane_score(&self, lane: Lane) -> LaneScore {
        LaneScore {
            lane,
            total_cases: self.total,
            success_rate: rate(self.successes, self.total),
            fallback_rate: rate(self.fallbacks, self.total),
        }
    }

    fn origin_score(&self, origin: &str, lane: Lane) -> OriginLaneScore {
        OriginLaneScore {
            origin: origin.into(),
            selected_lane: lane,
            total_cases: self.total,
            success_rate: rate(self.successes, self.total),
            fallback_rate: rate(self.fallbacks, self.total),
        }
    }
}

fn gate_violations(scorecard: &Scorecard, budget: &EvalBudget) -> Vec<GateViolation> {
    let mut violations = Vec::new();

    if scorecard.success_rate < budget.min_success_rate {
        violations.push(GateViolation::SuccessRate {
            observed: scorecard.success_rate,
            min: budget.min_success_rate,
        });
    }
    if scorecard.fallback_rate > budget.max_fallback_rate {
        violations.push(GateViolation::FallbackRate {
            observed: scorecard.fallback_rate,
            max: budget.max_fallback_rate,
        });
    }
    if scorecard.observation_bytes_p50 > budget.max_observation_bytes_p50 {
        violations.push(GateViolation::ObservationBytesP50 {
            observed: scorecard.observation_bytes_p50,
            max: budget.max_observation_bytes_p50,
        });
    }
    if scorecard.observation_bytes_p95 > budget.max_observation_bytes_p95 {
        violations.push(GateViolation::ObservationBytesP95 {
            observed: scorecard.observation_bytes_p95,
            max: budget.max_observation_bytes_p95,
        });
    }
    if scorecard.observation_tokens_p50 > budget.max_observation_tokens_p50 {
        violations.push(GateViolation::ObservationTokensP50 {
            observed: scorecard.observation_tokens_p50,
            max: budget.max_observation_tokens_p50,
        });
    }
    if scorecard.observe_latency_ms_p50 > budget.max_observe_latency_ms_p50 {
        violations.push(GateViolation::ObserveLatencyP50 {
            observed: scorecard.observe_latency_ms_p50,
            max: budget.max_observe_latency_ms_p50,
        });
    }
    if scorecard.observe_latency_ms_p95 > budget.max_observe_latency_ms_p95 {
        violations.push(GateViolation::ObserveLatencyP95 {
            observed: scorecard.observe_latency_ms_p95,
            max: budget.max_observe_latency_ms_p95,
        });
    }
    if scorecard.action_latency_ms_p50 > budget.max_action_latency_ms_p50 {
        violations.push(GateViolation::ActionLatencyP50 {
            observed: scorecard.action_latency_ms_p50,
            max: budget.max_action_latency_ms_p50,
        });
    }
    if scorecard.max_unconfirmed_high_risk_actions > budget.max_unconfirmed_high_risk_actions {
        violations.push(GateViolation::UnconfirmedHighRiskActions {
            observed: scorecard.max_unconfirmed_high_risk_actions,
            max: budget.max_unconfirmed_high_risk_actions,
        });
    }
    if let Some(min) = budget.min_speculation_reduction {
        match scorecard.speculation_reduction_p50 {
            Some(observed) if observed < min => {
                violations.push(GateViolation::SpeculationReduction { observed, min });
            }
            Some(_) => {}
            None => violations.push(GateViolation::MissingSpeculationData { min }),
        }
    }

    violations
}

fn percentile_u64(values: impl IntoIterator<Item = u64>, percentile: f64) -> u64 {
    let mut values: Vec<_> = values.into_iter().collect();
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let rank = (percentile * values.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(values.len() - 1);
    values[index]
}

fn speculation_reduction_p50(records: &[EvalRecord]) -> Option<f64> {
    let reductions: Vec<_> = records
        .iter()
        .filter_map(record_speculation_reduction)
        .collect();
    percentile_f64(reductions, 0.50)
}

fn record_speculation_reduction(record: &EvalRecord) -> Option<f64> {
    // A zero wall clock (e.g. a journal missing `SessionStarted`) would compute
    // a fake 100% reduction; exclude such records entirely (#115).
    if record.wall_clock_ms == 0 {
        return None;
    }
    record
        .baseline_wall_clock_ms
        .filter(|baseline| *baseline > 0)
        .map(|baseline| 1.0 - record.wall_clock_ms as f64 / baseline as f64)
}

fn percentile_f64(mut values: Vec<f64>, percentile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let rank = (percentile * values.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(values.len() - 1);
    Some(values[index])
}

fn estimated_tokens(bytes: u64) -> u64 {
    bytes.saturating_add(3) / 4
}

fn duration_ms(start: u128, end: u128) -> u64 {
    end.saturating_sub(start).min(u64::MAX as u128) as u64
}

fn rate(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

fn default_speculation_reduction() -> Option<f64> {
    Some(0.15)
}

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("eval run contains no records")]
    EmptyRun,
    #[error("session journal has no SessionStarted event; cannot derive wall-clock latency")]
    MissingSessionStart,
    #[error("eval artifact I/O failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("eval JSONL parse failed at {path:?}:{line}: {source}")]
    JsonLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("scorecard JSON write failed at {path:?}: {source}")]
    JsonWrite {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("observation serialization failed: {source}")]
    ObservationSerialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_schema::{
        Action, CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance,
        TaintSpan,
    };
    use tempo_session::{
        DurableEncryptionKey, DurableRetentionPolicy, RunId, SessionId, SessionJournal,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn scorecard_computes_budget_metrics_and_origin_lane_table() -> TestResult {
        let records = vec![
            with_suite(
                record(
                    "a",
                    "https://one.test",
                    Lane::Servo,
                    true,
                    false,
                    1_000,
                    100,
                ),
                "webvoyager",
            ),
            with_suite(
                record("b", "https://one.test", Lane::Cdp, true, true, 6_000, 220),
                "webarena",
            ),
            with_suite(
                record(
                    "c",
                    "https://two.test",
                    Lane::Servo,
                    false,
                    true,
                    2_000,
                    300,
                ),
                "webvoyager",
            ),
            with_suite(
                record("d", "https://two.test", Lane::Cdp, true, false, 3_000, 120),
                "webarena",
            ),
        ];
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };

        let scorecard = Scorecard::from_records(&records, &budget)?;

        assert_eq!(scorecard.total_cases, 4);
        assert_eq!(scorecard.observation_bytes_p50, 2_000);
        assert_eq!(scorecard.observation_bytes_p95, 6_000);
        assert_eq!(scorecard.observation_tokens_p50, 500);
        assert_eq!(scorecard.observe_latency_ms_p50, 120);
        assert_eq!(scorecard.observe_latency_ms_p95, 300);
        assert_eq!(
            scorecard.suites,
            vec![
                SuiteScore {
                    suite: "webarena".into(),
                    total_cases: 2,
                    success_rate: 1.0,
                    fallback_rate: 0.5,
                    speculation_reduction_p50: None,
                    max_unconfirmed_high_risk_actions: 0,
                },
                SuiteScore {
                    suite: "webvoyager".into(),
                    total_cases: 2,
                    success_rate: 0.5,
                    fallback_rate: 0.5,
                    speculation_reduction_p50: None,
                    max_unconfirmed_high_risk_actions: 0,
                }
            ]
        );
        assert_eq!(
            scorecard.lanes,
            vec![
                LaneScore {
                    lane: Lane::Servo,
                    total_cases: 2,
                    success_rate: 0.5,
                    fallback_rate: 0.5,
                },
                LaneScore {
                    lane: Lane::Cdp,
                    total_cases: 2,
                    success_rate: 1.0,
                    fallback_rate: 0.5,
                }
            ]
        );
        assert_eq!(
            scorecard.origins,
            vec![
                OriginLaneScore {
                    origin: "https://one.test".into(),
                    selected_lane: Lane::Servo,
                    total_cases: 1,
                    success_rate: 1.0,
                    fallback_rate: 0.0,
                },
                OriginLaneScore {
                    origin: "https://two.test".into(),
                    selected_lane: Lane::Cdp,
                    total_cases: 1,
                    success_rate: 1.0,
                    fallback_rate: 0.0,
                }
            ]
        );
        assert!(scorecard.passes());
        Ok(())
    }

    #[test]
    fn gate_reports_budget_injection_and_speculation_violations() -> TestResult {
        let mut slow = record(
            "slow",
            "https://risk.test",
            Lane::Servo,
            false,
            true,
            9_000,
            900,
        );
        slow.unconfirmed_high_risk_actions = 1;
        slow.wall_clock_ms = 950;
        slow.baseline_wall_clock_ms = Some(1_000);
        let budget = EvalBudget {
            min_success_rate: 1.0,
            max_fallback_rate: 0.0,
            max_observation_bytes_p50: 4_000,
            max_observation_bytes_p95: 8_000,
            max_observation_tokens_p50: 1_500,
            max_observe_latency_ms_p50: 150,
            max_observe_latency_ms_p95: 500,
            max_action_latency_ms_p50: 800,
            max_unconfirmed_high_risk_actions: 0,
            min_speculation_reduction: Some(0.15),
        };

        let scorecard = Scorecard::from_records(&[slow], &budget)?;

        assert_eq!(
            scorecard.violations,
            vec![
                GateViolation::SuccessRate {
                    observed: 0.0,
                    min: 1.0,
                },
                GateViolation::FallbackRate {
                    observed: 1.0,
                    max: 0.0,
                },
                GateViolation::ObservationBytesP50 {
                    observed: 9_000,
                    max: 4_000,
                },
                GateViolation::ObservationBytesP95 {
                    observed: 9_000,
                    max: 8_000,
                },
                GateViolation::ObservationTokensP50 {
                    observed: 2_250,
                    max: 1_500,
                },
                GateViolation::ObserveLatencyP50 {
                    observed: 900,
                    max: 150,
                },
                GateViolation::ObserveLatencyP95 {
                    observed: 900,
                    max: 500,
                },
                GateViolation::ActionLatencyP50 {
                    observed: 900,
                    max: 800,
                },
                GateViolation::UnconfirmedHighRiskActions {
                    observed: 1,
                    max: 0,
                },
                GateViolation::SpeculationReduction {
                    observed: 0.050000000000000044,
                    min: 0.15,
                }
            ]
        );
        assert!(!scorecard.passes());
        Ok(())
    }

    #[test]
    fn read_eval_records_loads_jsonl_from_disk() -> TestResult {
        let root = unique_dir("records")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let path = root.join("records.jsonl");
        let records = vec![
            record("one", "https://one.test", Lane::Api, true, false, 100, 10),
            record("two", "https://two.test", Lane::Cdp, false, true, 200, 20),
        ];
        {
            let mut file = File::create(&path)?;
            for record in &records {
                serde_json::to_writer(&mut file, record)?;
                file.write_all(b"\n")?;
            }
        }

        assert_eq!(read_eval_records(&path)?, records);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn scorecard_json_writes_to_disk() -> TestResult {
        let root = unique_dir("scorecard")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("out").join("scorecard.json");
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };
        let scorecard = Scorecard::from_records(
            &[record(
                "one",
                "https://score.test",
                Lane::Servo,
                true,
                false,
                100,
                10,
            )],
            &budget,
        )?;

        write_scorecard(&path, &scorecard)?;
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;

        assert_eq!(json["total_cases"], json!(1));
        assert_eq!(json["suites"][0]["suite"], json!("suite"));
        assert_eq!(json["lanes"][0]["lane"], json!("servo"));
        assert_eq!(json["origins"][0]["selected_lane"], json!("servo"));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn suite_summary_uses_real_baselines_and_high_risk_counts() -> TestResult {
        let mut fast = with_suite(
            record(
                "fast",
                "https://tasks.test",
                Lane::Api,
                true,
                false,
                400,
                40,
            ),
            "mind2web-live",
        );
        fast.wall_clock_ms = 700;
        fast.baseline_wall_clock_ms = Some(1_000);
        let mut risky = with_suite(
            record(
                "risky",
                "https://tasks.test",
                Lane::Api,
                false,
                true,
                500,
                50,
            ),
            "mind2web-live",
        );
        risky.wall_clock_ms = 900;
        risky.baseline_wall_clock_ms = Some(1_000);
        risky.unconfirmed_high_risk_actions = 2;
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };

        let scorecard = Scorecard::from_records(&[fast, risky], &budget)?;

        assert_eq!(
            scorecard.suites,
            vec![SuiteScore {
                suite: "mind2web-live".into(),
                total_cases: 2,
                success_rate: 0.5,
                fallback_rate: 0.5,
                speculation_reduction_p50: Some(0.09999999999999998),
                max_unconfirmed_high_risk_actions: 2,
            }]
        );
        Ok(())
    }

    #[test]
    fn session_journal_adapter_derives_eval_record_from_real_journal() -> TestResult {
        let root = unique_dir("journal")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://journal.test".into(),
        })?;
        journal.append(JournalEvent::Observation {
            observation: observation(),
        })?;
        let action = Action::Click {
            node: NodeId("submit".into()),
        };
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action,
            diff: ObservationDiff {
                since_seq: 1,
                seq: 2,
                added: vec![],
                removed: vec![],
                changed: vec![],
            },
        })?;

        let record = eval_record_from_session_journal(
            &journal_path,
            SessionEvalDescriptor {
                suite: "journal-suite".into(),
                case_id: "case-1".into(),
                origin: "https://journal.test".into(),
                lane: Lane::Servo,
                success: true,
                fallback_used: false,
                baseline_wall_clock_ms: Some(200),
                unconfirmed_high_risk_actions: 0,
            },
        )?;

        assert_eq!(record.suite, "journal-suite");
        assert_eq!(record.case_id, "case-1");
        assert_eq!(record.lane, Lane::Servo);
        assert!(record.max_observation_bytes > 0);
        assert!(record.max_observation_tokens > 0);
        assert_eq!(record.step_count, 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn session_journal_adapter_reads_encrypted_journal() -> TestResult {
        let root = unique_dir("encrypted-journal")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let policy = DurableRetentionPolicy::encrypted(DurableEncryptionKey::from_bytes([31; 32]));
        let mut journal = SessionJournal::open_with_retention_policy(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
            policy.clone(),
        )?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://journal.test".into(),
        })?;
        journal.append(JournalEvent::Observation {
            observation: observation(),
        })?;
        let action = Action::Click {
            node: NodeId("submit".into()),
        };
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action,
            diff: ObservationDiff {
                since_seq: 1,
                seq: 2,
                added: vec![],
                removed: vec![],
                changed: vec![],
            },
        })?;
        drop(journal);

        let record = eval_record_from_session_journal_with_retention_policy(
            &journal_path,
            SessionEvalDescriptor {
                suite: "journal-suite".into(),
                case_id: "case-1".into(),
                origin: "https://journal.test".into(),
                lane: Lane::Servo,
                success: true,
                fallback_used: false,
                baseline_wall_clock_ms: Some(200),
                unconfirmed_high_risk_actions: 0,
            },
            &policy,
        )?;

        assert_eq!(record.suite, "journal-suite");
        assert_eq!(record.step_count, 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn latency_percentiles_pool_raw_samples_not_per_case_p95() -> TestResult {
        // Two cases, each with a tail spike. Pooling the raw samples yields a
        // p50 of 20; percentiling the per-case p95s (the bug) would yield 1000.
        let mut a = record("a", "https://one.test", Lane::Servo, true, false, 1_000, 0);
        a.observe_latencies_ms = vec![10, 10, 10, 1_000];
        a.action_latencies_ms = vec![10, 10, 10, 1_000];
        let mut b = record("b", "https://two.test", Lane::Cdp, true, false, 1_000, 0);
        b.observe_latencies_ms = vec![20, 20, 20, 2_000];
        b.action_latencies_ms = vec![20, 20, 20, 2_000];
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };

        let scorecard = Scorecard::from_records(&[a, b], &budget)?;

        assert_eq!(scorecard.observe_latency_ms_p50, 20);
        assert_eq!(scorecard.observe_latency_ms_p95, 2_000);
        assert_eq!(scorecard.action_latency_ms_p50, 20);
        Ok(())
    }

    #[test]
    fn speculation_reduction_excludes_zero_wall_clock_records() -> TestResult {
        let zero_a = spec_record(0, Some(1_000));
        let zero_b = spec_record(0, Some(1_000));
        let real = spec_record(800, Some(1_000));

        // Only the real 0.2 reduction counts; the zero-wall records must not
        // contribute a fake 1.0 reduction.
        let reduction = speculation_reduction_p50(&[zero_a, zero_b, real])
            .ok_or("expected a speculation reduction")?;
        assert!((reduction - 0.2).abs() < 1e-9, "got {reduction}");

        // With no positive-wall-clock records, there is simply no data.
        assert_eq!(
            speculation_reduction_p50(&[spec_record(0, Some(1_000))]),
            None
        );
        Ok(())
    }

    #[test]
    fn journal_without_session_start_is_error() -> TestResult {
        let root = unique_dir("no-start")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        let mut journal = SessionJournal::open(
            &journal_path,
            RunId("run".into()),
            SessionId("session".into()),
        )?;
        // No SessionStarted event: only an observation.
        journal.append(JournalEvent::Observation {
            observation: observation(),
        })?;

        let result = eval_record_from_session_journal(
            &journal_path,
            SessionEvalDescriptor {
                suite: "s".into(),
                case_id: "c".into(),
                origin: "https://journal.test".into(),
                lane: Lane::Servo,
                success: true,
                fallback_used: false,
                baseline_wall_clock_ms: Some(200),
                unconfirmed_high_risk_actions: 0,
            },
        );
        assert!(matches!(result, Err(EvalError::MissingSessionStart)));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn empty_run_is_rejected() {
        assert!(matches!(
            Scorecard::from_records(&[], &EvalBudget::default()),
            Err(EvalError::EmptyRun)
        ));
    }

    fn record(
        case_id: &str,
        origin: &str,
        lane: Lane,
        success: bool,
        fallback_used: bool,
        max_observation_bytes: u64,
        latency: u64,
    ) -> EvalRecord {
        EvalRecord {
            suite: "suite".into(),
            case_id: case_id.into(),
            origin: origin.into(),
            lane,
            success,
            fallback_used,
            max_observation_bytes,
            max_observation_tokens: estimated_tokens(max_observation_bytes),
            observe_latencies_ms: vec![latency],
            action_latencies_ms: vec![latency],
            wall_clock_ms: latency.saturating_mul(2),
            baseline_wall_clock_ms: None,
            unconfirmed_high_risk_actions: 0,
            step_count: 1,
        }
    }

    fn with_suite(mut record: EvalRecord, suite: &str) -> EvalRecord {
        record.suite = suite.into();
        record
    }

    fn spec_record(wall_clock_ms: u64, baseline_wall_clock_ms: Option<u64>) -> EvalRecord {
        let mut record = record(
            "spec",
            "https://spec.test",
            Lane::Servo,
            true,
            false,
            100,
            10,
        );
        record.wall_clock_ms = wall_clock_ms;
        record.baseline_wall_clock_ms = baseline_wall_clock_ms;
        record
    }

    fn observation() -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://journal.test".into(),
            seq: 1,
            elements: vec![InteractiveElement {
                node_id: NodeId("submit".into()),
                role: "button".into(),
                name: vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: "Submit".into(),
                }],
                value: vec![],
                bounds: Some([0.0, 0.0, 80.0, 24.0]),
                rank: 1.0,
            }],
            marks: vec![],
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-evals-{label}-{}-{nanos}",
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
