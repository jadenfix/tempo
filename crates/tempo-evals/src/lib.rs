//! tempo-evals — scorecards and regression gates for persisted tempo runs.
//!
//! This crate consumes real eval artifacts: JSONL records emitted by CI/nightly
//! suites and durable `tempo-session` journals. It computes budget percentiles,
//! per-origin lane choices, fallback rates, and typed gate violations.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tempo_observe::{ObservationInput, StableIdMapper};
use tempo_schema::{
    Action, CompiledObservation, InteractiveElement, NodeId, QuiescencePolicy, SideEffect,
    StepStatus, StepTriple,
};
use tempo_session::{
    read_journal_entries_with_retention_policy, DurableRetentionPolicy, JournalEntry, JournalError,
    JournalEvent,
};
use tempo_skills::{ActionTemplate, SkillDefinition, SkillInput, TemplateString};
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
    /// Maximum allowed gap between the nominal success rate and
    /// Completion-under-Policy (`success_rate - cup`) before the
    /// `CuPBelowNominal` gate fires. Zero means any successful-but-unconfirmed-
    /// high-risk case is a gate failure.
    #[serde(default = "default_max_cup_gap")]
    pub max_cup_gap: f64,
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
            max_cup_gap: default_max_cup_gap(),
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
    /// Completion-under-Policy: the success rate computed only over cases with
    /// zero `unconfirmed_high_risk_actions`. A case that "succeeded" by taking
    /// an unconfirmed high-risk action does not count as completion under
    /// policy, so `cup` can be lower than `success_rate` (never higher).
    #[serde(default)]
    pub cup: f64,
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
    SuccessRate {
        observed: f64,
        min: f64,
    },
    FallbackRate {
        observed: f64,
        max: f64,
    },
    ObservationBytesP50 {
        observed: u64,
        max: u64,
    },
    ObservationBytesP95 {
        observed: u64,
        max: u64,
    },
    ObservationTokensP50 {
        observed: u64,
        max: u64,
    },
    ObserveLatencyP50 {
        observed: u64,
        max: u64,
    },
    ObserveLatencyP95 {
        observed: u64,
        max: u64,
    },
    ActionLatencyP50 {
        observed: u64,
        max: u64,
    },
    UnconfirmedHighRiskActions {
        observed: u64,
        max: u64,
    },
    MissingSpeculationData {
        min: f64,
    },
    SpeculationReduction {
        observed: f64,
        min: f64,
    },
    CuPBelowNominal {
        observed: f64,
        nominal: f64,
        max_gap: f64,
    },
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
        let cup = cup_rate(records);
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
            cup,
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
            | JournalEvent::ModelDecision { .. }
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::HumanTakeoverRequired { .. }
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
    let cup_gap = scorecard.success_rate - scorecard.cup;
    if cup_gap > budget.max_cup_gap {
        violations.push(GateViolation::CuPBelowNominal {
            observed: scorecard.cup,
            nominal: scorecard.success_rate,
            max_gap: budget.max_cup_gap,
        });
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

/// Completion-under-Policy: success rate restricted to cases with zero
/// unconfirmed high-risk actions. A case that succeeded only by taking an
/// unconfirmed high-risk action is excluded from both the numerator and the
/// denominator, so `cup` reflects success achieved without policy exposure.
fn cup_rate(records: &[EvalRecord]) -> f64 {
    let clean = records
        .iter()
        .filter(|record| record.unconfirmed_high_risk_actions == 0);
    let mut total = 0usize;
    let mut successes = 0usize;
    for record in clean {
        total += 1;
        if record.success {
            successes += 1;
        }
    }
    rate(successes, total)
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

/// Approximate token count from a byte length: the crate's existing
/// `~4 bytes/token` heuristic, used both for `EvalRecord::max_observation_tokens`
/// budgets and for the differential report below (#361) so "tokens" means the
/// same thing in both places. This is a documented approximation, not a real
/// tokenizer — good enough for relative/differential comparisons, and adding
/// no new dependency.
pub fn estimated_tokens(bytes: u64) -> u64 {
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

fn default_max_cup_gap() -> f64 {
    0.0
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
    #[error("differential fixture JSON parse failed at {path:?}: {source}")]
    JsonRead {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "skill drift case {case:?} names target_index {index} but the pre-drift page only has \
         {len} element(s)"
    )]
    DriftTargetIndexOutOfBounds {
        case: String,
        index: usize,
        len: usize,
    },
    #[error("skill drift case {case:?} failed to compile its recorded skill: {source}")]
    DriftSkillCompile {
        case: String,
        #[source]
        source: tempo_skills::SkillError,
    },
}

/// Minimal task description consumed by a [`Judge`]: the natural-language goal
/// plus deterministic terminal-state markers a rule-based judge can check for
/// (WebJudge-style, arXiv 2504.01382, per #240/#357).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    /// Human-readable task goal, e.g. "book a flight from SFO to JFK".
    pub goal: String,
    /// Case-insensitive substrings that, if present in an element name of any
    /// post-action observation, indicate the task's goal state was reached
    /// (e.g. "order confirmed", "thank you for your purchase").
    #[serde(default)]
    pub success_markers: Vec<String>,
}

/// A judge's verdict on one trajectory against one [`TaskSpec`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub success: bool,
    /// Judge's confidence in `success`, in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Human-readable justification for the verdict.
    pub rationale: String,
}

/// Oracle that scores an agent trajectory against a task. Modeled on the
/// WebJudge pattern from Online-Mind2Web (arXiv 2504.01382, referenced by
/// #240). [`MockJudge`] below is a deterministic, rule-based stand-in used as
/// a test oracle; a real LLM-backed implementation is an explicit gated
/// follow-up (#363) that plugs into this same trait without any redesign.
pub trait Judge {
    fn verdict(&self, task: &TaskSpec, trajectory: &[StepTriple]) -> Verdict;
}

/// Deterministic, rule-based test oracle — NOT a real judge. Evaluates canned
/// fixture trajectories with four ordered, documented rules; no network calls,
/// no model calls, same input always yields the same [`Verdict`].
///
/// Rules, checked in this order:
/// 1. Empty trajectory -> failure, confidence `1.0` (no work was done).
/// 2. The last step's outcome is [`StepStatus::Error`] -> failure, confidence
///    `0.9` (the agent did not end in a working state).
/// 3. Any step's post-action observation has an element whose name contains
///    (case-insensitively) one of `task.success_markers` -> success,
///    confidence `0.95` (an explicit terminal-state signal was observed).
/// 4. Otherwise (ran to completion without error, but no configured success
///    marker was ever observed) -> failure, confidence `0.6` (weak signal:
///    absence of evidence, not evidence of failure).
#[derive(Clone, Copy, Debug, Default)]
pub struct MockJudge;

impl Judge for MockJudge {
    fn verdict(&self, task: &TaskSpec, trajectory: &[StepTriple]) -> Verdict {
        if trajectory.is_empty() {
            return Verdict {
                success: false,
                confidence: 1.0,
                rationale: "empty trajectory: no steps were taken".into(),
            };
        }

        match trajectory.last() {
            Some(last) if last.outcome.status == StepStatus::Error => {
                let reason = last
                    .outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "unknown error".into());
                return Verdict {
                    success: false,
                    confidence: 0.9,
                    rationale: format!("final step (seq {}) errored: {reason}", last.seq),
                };
            }
            Some(_) | None => {}
        }

        if let Some((seq, marker)) = find_success_marker(task, trajectory) {
            return Verdict {
                success: true,
                confidence: 0.95,
                rationale: format!("observed success marker {marker:?} at step seq {seq}"),
            };
        }

        Verdict {
            success: false,
            confidence: 0.6,
            rationale: "trajectory completed without error but no configured success marker \
                was ever observed"
                .into(),
        }
    }
}

/// Rule 3 helper: scan every step's post-action observation for a configured
/// success marker, returning the first (step seq, marker) match.
fn find_success_marker<'a>(
    task: &'a TaskSpec,
    trajectory: &[StepTriple],
) -> Option<(u64, &'a str)> {
    if task.success_markers.is_empty() {
        return None;
    }
    for step in trajectory {
        for marker in &task.success_markers {
            if observation_contains_marker(&step.outcome.observation, marker) {
                return Some((step.seq, marker.as_str()));
            }
        }
    }
    None
}

fn observation_contains_marker(observation: &CompiledObservation, marker: &str) -> bool {
    let marker = marker.to_lowercase();
    observation.elements.iter().any(|element| {
        element
            .name
            .iter()
            .any(|span| span.text.to_lowercase().contains(&marker))
    })
}

// ---------------------------------------------------------------------------
// Differential observation-size/recall metric (#361, hermetic core of #241).
//
// This is the hermetic slice only: `tempo_obs` plus each baseline are RECORDED
// static, versioned fixtures committed under `fixtures/evals/differential/`,
// not produced by invoking a live Playwright-MCP or browser-use process at
// test time. Live third-party-tool invocation is explicit deferred scope,
// tracked separately by #363. See `fixtures/evals/differential/README.md` for
// the fixture set and the out-of-cargo regeneration seam.
// ---------------------------------------------------------------------------

/// Ground-truth (or observed) interactive-element identity used for recall
/// comparisons: role + case-insensitive accessible name. This is deliberately
/// coarser than a full AX-node diff so it is comparable across three very
/// different serialization formats — tempo's own schema, a Playwright-MCP-
/// style nested a11y tree, and a browser-use-style flat DOM list — all scored
/// against the same CDP AX tree oracle.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ElementId {
    pub role: String,
    pub name: String,
}

impl ElementId {
    /// Normalizes role/name to trimmed lowercase so recall matching is not
    /// sensitive to whitespace or casing differences between the oracle and a
    /// given observation/baseline (mirrors the case-insensitive matching
    /// `MockJudge` already uses for success markers).
    pub fn new(role: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            role: role.into().trim().to_lowercase(),
            name: name.into().trim().to_lowercase(),
        }
    }
}

/// Which recorded baseline a [`BaselineSnapshot`] represents. Both are static,
/// versioned, hand-authored representative fixtures (see
/// `fixtures/evals/differential/README.md`) captured offline — not live
/// third-party-tool invocations (those are gated separately, #363).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    /// A Playwright MCP `browser_snapshot`-style accessibility snapshot, in the
    /// tool's real LLM-facing compact YAML aria-tree wire format
    /// (`- role "name" [ref=eN]`), NOT a bloated internal JSON tree.
    PlaywrightMcpA11ySnapshot,
    /// A browser-use `dom/serializer`-style serialization, in the tool's real
    /// LLM-facing compact indexed bracket-line wire format
    /// (`[i]<tag attrs>name</tag>` for interactive elements, interleaved with
    /// plain visible-text lines), NOT a bloated internal JSON list.
    BrowserUseDomSerializer,
}

impl BaselineKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PlaywrightMcpA11ySnapshot => "playwright-mcp-a11y-snapshot",
            Self::BrowserUseDomSerializer => "browser-use-dom-serializer",
        }
    }
}

/// One recorded baseline serialization for a fixture page: its kind, the
/// interactive elements it exposes, and the byte length of the tool's real
/// LLM-facing wire payload. Both `compact_bytes` and `elements` are derived
/// from the *same* committed wire-format text, so a reviewer can eyeball that
/// the counted payload and the recall-scored elements are the one artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub kind: BaselineKind,
    /// Byte length of the baseline tool's real LLM-facing wire payload — the
    /// exact text the tool would hand a model (Playwright's compact aria YAML;
    /// browser-use's indexed bracket-lines), trimmed of any trailing
    /// whitespace. This is what the model actually pays tokens for, so it is
    /// the honest quantity to compare against tempo's compiled-observation
    /// serialization. (Earlier revisions counted a bloated internal JSON tree
    /// with xpath + full attribute dicts + per-leaf `"children": []`, which
    /// overstated both baselines' cost; see #361 review.)
    pub compact_bytes: u64,
    pub elements: Vec<ElementId>,
}

/// Byte/token counts for one format on one fixture page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FormatTokens {
    pub bytes: u64,
    pub tokens: u64,
}

impl FormatTokens {
    fn from_bytes(bytes: u64) -> Self {
        Self {
            bytes,
            tokens: estimated_tokens(bytes),
        }
    }
}

/// One baseline's token counts and element recall against the oracle, for a
/// single fixture page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub kind: BaselineKind,
    pub tokens: FormatTokens,
    /// Fraction of the oracle's ground-truth interactive elements this
    /// baseline surfaces, in `[0.0, 1.0]`.
    pub recall: f64,
}

/// Differential report for one fixture page: tempo's compiled observation vs
/// each recorded baseline, on both size (`tokens_per_observation`, split as
/// `tempo`/`baselines[].tokens`) and interactive-element recall against the
/// CDP AX tree oracle (`element_recall`, split as `tempo_recall`/
/// `baselines[].recall`) — the two DoD metrics from #361/#241.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DifferentialReport {
    pub page: String,
    pub oracle_element_count: usize,
    pub tempo: FormatTokens,
    pub tempo_recall: f64,
    pub baselines: Vec<BaselineComparison>,
}

impl DifferentialReport {
    /// True if tempo's compiled observation is strictly smaller, by the
    /// crate's approx-token heuristic, than every recorded baseline on this
    /// page.
    pub fn tempo_tokens_lower_than_all_baselines(&self) -> bool {
        self.baselines
            .iter()
            .all(|baseline| self.tempo.tokens < baseline.tokens.tokens)
    }

    /// True if tempo's recall against the oracle is at least as good as every
    /// recorded baseline's recall on this page.
    pub fn tempo_recall_at_least_baselines(&self) -> bool {
        self.baselines
            .iter()
            .all(|baseline| self.tempo_recall >= baseline.recall)
    }
}

/// Compute a [`DifferentialReport`] for one fixture page: `tempo_obs` vs
/// `baselines`, both scored for interactive-element recall against `oracle`
/// (the CDP AX tree ground-truth set). This is the `differential_report`
/// entry point from #361's DoD; `page` and `oracle` are required in addition
/// to `tempo_obs`/`baselines` because recall is undefined without a
/// ground-truth set to score against.
pub fn differential_report(
    page: impl Into<String>,
    tempo_obs: &CompiledObservation,
    baselines: &[BaselineSnapshot],
    oracle: &[ElementId],
) -> Result<DifferentialReport, EvalError> {
    let tempo_bytes = serde_json::to_vec(tempo_obs)
        .map_err(|source| EvalError::ObservationSerialize { source })?
        .len() as u64;
    let tempo_elements: BTreeSet<ElementId> =
        tempo_obs.elements.iter().map(tempo_element_id).collect();
    let oracle_set: BTreeSet<ElementId> = oracle.iter().cloned().collect();
    let tempo_recall = recall(&oracle_set, &tempo_elements);

    let baseline_comparisons = baselines
        .iter()
        .map(|baseline| {
            let observed: BTreeSet<ElementId> = baseline.elements.iter().cloned().collect();
            BaselineComparison {
                kind: baseline.kind,
                tokens: FormatTokens::from_bytes(baseline.compact_bytes),
                recall: recall(&oracle_set, &observed),
            }
        })
        .collect();

    Ok(DifferentialReport {
        page: page.into(),
        oracle_element_count: oracle_set.len(),
        tempo: FormatTokens::from_bytes(tempo_bytes),
        tempo_recall,
        baselines: baseline_comparisons,
    })
}

fn tempo_element_id(element: &InteractiveElement) -> ElementId {
    let name = element
        .name
        .iter()
        .map(|span| span.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    ElementId::new(element.role.clone(), name)
}

/// Fraction of `oracle` elements present in `observed`. Vacuously `1.0` when
/// the oracle set is empty (nothing to miss) — this does not arise for real
/// fixture pages, which always define at least one ground-truth interactive
/// element, but is documented rather than left to divide-by-zero.
fn recall(oracle: &BTreeSet<ElementId>, observed: &BTreeSet<ElementId>) -> f64 {
    if oracle.is_empty() {
        return 1.0;
    }
    let hits = oracle.intersection(observed).count();
    hits as f64 / oracle.len() as f64
}

/// AX/ARIA roles the fixture parsers below treat as "interactive" — mirrors
/// the interactive-widget subset of the ARIA role taxonomy, excluding
/// structural/decorative roles (`"generic"`, `"heading"`, `"img"`,
/// `"paragraph"`, `"list"`, `"listitem"`, `"navigation"`, `"banner"`,
/// `"contentinfo"`, ...) that both recorded baseline wire formats also emit
/// but that are not agent-actionable.
const INTERACTIVE_ROLES: &[&str] = &[
    "button",
    "link",
    "textbox",
    "searchbox",
    "checkbox",
    "radio",
    "combobox",
    "switch",
    "slider",
    "menuitem",
    "tab",
];

fn read_json_fixture<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, EvalError> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(|source| EvalError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|source| EvalError::JsonRead { path, source })
}

fn read_text_fixture(path: impl AsRef<Path>) -> Result<String, EvalError> {
    let path = path.as_ref().to_path_buf();
    std::fs::read_to_string(&path).map_err(|source| EvalError::Io { path, source })
}

/// Load a tempo `CompiledObservation` fixture (a recorded serialization of
/// tempo's own structured observation for one fixture page).
pub fn read_tempo_observation_fixture(
    path: impl AsRef<Path>,
) -> Result<CompiledObservation, EvalError> {
    read_json_fixture(path)
}

/// Load a checked-in Playwright-MCP-style accessibility snapshot fixture, in
/// the tool's real compact aria-YAML wire format, and extract its
/// [`BaselineSnapshot`]. Every line of the form `- <role> "<name>" [...]`
/// whose `<role>` is in [`INTERACTIVE_ROLES`] contributes one [`ElementId`];
/// structural lines (`- banner:`, `- text: ...`, `- heading "..."`) are
/// counted toward the byte payload but never surface an interactive element.
/// `compact_bytes` is the trimmed byte length of the whole wire text — what a
/// model actually reads.
pub fn read_playwright_a11y_fixture(path: impl AsRef<Path>) -> Result<BaselineSnapshot, EvalError> {
    let text = read_text_fixture(path)?;
    Ok(BaselineSnapshot {
        kind: BaselineKind::PlaywrightMcpA11ySnapshot,
        compact_bytes: text.trim_end().len() as u64,
        elements: parse_playwright_aria_snapshot(&text),
    })
}

fn parse_playwright_aria_snapshot(text: &str) -> Vec<ElementId> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("- ") else {
            continue;
        };
        // Role is the first token, delimited by a space or a trailing colon.
        let role = rest.split([' ', ':']).next().unwrap_or("").trim();
        if role.is_empty() || !INTERACTIVE_ROLES.contains(&role) {
            continue;
        }
        if let Some(name) = first_quoted(rest)
            && !name.is_empty()
        {
            out.push(ElementId::new(role, name));
        }
    }
    out
}

/// Return the text between the first pair of double quotes in `s`, if any.
fn first_quoted(s: &str) -> Option<&str> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Load a checked-in browser-use-style DOM-serialization fixture, in the
/// tool's real compact indexed bracket-line wire format, and extract its
/// [`BaselineSnapshot`]. Interactive elements are lines of the form
/// `[i]<tag attrs>name</tag>` (or self-closing `[i]<tag attrs/>name`);
/// browser-use's real `is_interactive` treats a native interactive tag, an
/// interactive ARIA `role=`, or a `tabindex` as sufficient, so a
/// `<div role=checkbox tabindex=0>` and a `<span role=link tabindex=0>` are
/// surfaced here exactly as its real detector would. Plain visible-text lines
/// (page copy between the indexed elements) are counted toward the byte
/// payload but surface no element.
pub fn read_browser_use_dom_fixture(path: impl AsRef<Path>) -> Result<BaselineSnapshot, EvalError> {
    let text = read_text_fixture(path)?;
    Ok(BaselineSnapshot {
        kind: BaselineKind::BrowserUseDomSerializer,
        compact_bytes: text.trim_end().len() as u64,
        elements: parse_browser_use_serialization(&text),
    })
}

fn parse_browser_use_serialization(text: &str) -> Vec<ElementId> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(after_marker) = strip_index_marker(line.trim_start()) else {
            continue;
        };
        let Some(inner) = after_marker.strip_prefix('<') else {
            continue;
        };
        let Some(gt) = inner.find('>') else {
            continue;
        };
        let tag_block = inner[..gt].trim_end_matches('/').trim();
        let name = inner_text(&inner[gt + 1..]);
        if let Some(role) = browser_use_role(tag_block)
            && INTERACTIVE_ROLES.contains(&role.as_str())
            && !name.is_empty()
        {
            out.push(ElementId::new(role, name));
        }
    }
    out
}

/// Strip a leading `[<digits>]` or `*[<digits>]` browser-use index marker,
/// returning the remainder of the line. `None` if the line is not an indexed
/// element line (i.e. plain page text).
fn strip_index_marker(s: &str) -> Option<&str> {
    let s = s.strip_prefix('*').unwrap_or(s);
    let rest = s.strip_prefix('[')?;
    let close = rest.find(']')?;
    let digits = &rest[..close];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(rest[close + 1..].trim_start())
}

/// Map a browser-use bracket-line tag block (e.g. `input type=email`,
/// `div role=checkbox tabindex=0`) to an ARIA role. An explicit `role=`
/// attribute wins; otherwise the tag (plus `type=` for inputs) is mapped.
fn browser_use_role(tag_block: &str) -> Option<String> {
    for token in tag_block.split_whitespace() {
        if let Some(role) = token.strip_prefix("role=") {
            return Some(role.trim_matches('"').to_string());
        }
    }
    let tag = tag_block.split_whitespace().next()?.to_ascii_lowercase();
    let role = match tag.as_str() {
        "a" => "link",
        "button" => "button",
        "select" => "combobox",
        "textarea" => "textbox",
        "input" => {
            let mut input_type = "text".to_string();
            for token in tag_block.split_whitespace() {
                if let Some(value) = token.strip_prefix("type=") {
                    input_type = value.trim_matches('"').to_string();
                }
            }
            match input_type.as_str() {
                "search" => "searchbox",
                "checkbox" => "checkbox",
                "radio" => "radio",
                _ => "textbox",
            }
        }
        _ => return None,
    };
    Some(role.to_string())
}

/// The visible text of a bracket-line element: everything before a closing
/// `</...>` tag (or the whole remainder for a self-closing element), trimmed.
fn inner_text(s: &str) -> String {
    let end = s.find("</").unwrap_or(s.len());
    s[..end].trim().to_string()
}

/// Load the CDP AX tree oracle fixture: the ground-truth set of interactive
/// elements for one fixture page, against which tempo and both recorded
/// baselines are scored for recall.
pub fn read_oracle_fixture(path: impl AsRef<Path>) -> Result<Vec<ElementId>, EvalError> {
    #[derive(Deserialize)]
    struct OracleFixture {
        elements: Vec<OracleElement>,
    }
    #[derive(Deserialize)]
    struct OracleElement {
        role: String,
        name: String,
    }
    let fixture: OracleFixture = read_json_fixture(path)?;
    Ok(fixture
        .elements
        .into_iter()
        .map(|element| ElementId::new(element.role, element.name))
        .collect())
}

// ---------------------------------------------------------------------------
// Synthetic skill-replay-after-drift metric (#362).
//
// HONESTY (see `fixtures/evals/skill_drift/README.md` for the long version):
// this is an explicit SYNTHETIC PROXY for the real claim — that a recorded
// skill/cassette still resolves after a *genuine*, live, time-separated
// re-crawl of a real site. The `pre`/`post` fixture pages below are
// hand-authored to simulate one kind of DOM/selector drift each; they are NOT
// two captures of the same real site taken at different times. That real
// measurement needs live web access and is deferred to #363. Nothing computed
// here should be read as evidence about real-world drift resilience.
//
// What is real: the replay primitive. `tempo_skills::SkillDefinition::compile`
// is tempo's actual (only) skill-expansion path today, and it is pure
// template substitution — a stored step's target is a literal (or
// once-bound-parameter) `NodeId` string baked in at authoring time; `compile`
// does not itself look anything up against a live page. The thing that can
// survive or fail to survive drift is that baked-in `NodeId`, which
// `tempo_observe::StableIdMapper` derives from a *fingerprint* of the
// element's stable DOM hint (if the engine supplied one) or else its
// role+name+value — deliberately independent of DOM position/order. So:
//
// - A pure position/order/bounds move (the "moved" case) does not change the
//   fingerprint -> the skill's recorded `NodeId` re-binds -> it survives.
// - A renamed element (its accessible name/text changes) DOES change the
//   fingerprint -> a "new" NodeId is allocated -> the recorded target is not
//   found -> replay fails. Caveat: this is indistinguishable, under this
//   scheme, from the element having been removed and a same-shaped one added
//   in its place; tempo's replay cannot tell "renamed" apart from
//   "replaced". A live, continuously-tracked session could still resolve a
//   rename via its engine-native `source_id` (`StableIdMapper::by_source`),
//   but that requires session continuity that a genuine time-separated
//   re-crawl (#363's real subject) would not have either, so this metric
//   intentionally uses a *fresh* `StableIdMapper` per fixture page rather than
//   carrying one across `pre`/`post`.
// - A genuinely removed element (the "removed" case) is simply absent from
//   the post-drift fingerprint set -> replay fails.
// ---------------------------------------------------------------------------

/// One synthetic replay-after-drift case: a recorded skill's click target,
/// resolved once against a hand-authored "pre-drift" fixture page, replayed
/// against a hand-authored "post-drift" fixture page that simulates one kind
/// of DOM/selector change. See the module-level note above — this is a
/// synthetic proxy (#362), not a live re-crawl (deferred to #363).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillDriftCase {
    /// Case label, e.g. `"moved-position"`.
    pub name: String,
    /// Free-text note on which kind of drift this simulates, for humans
    /// reading a report; not consumed by the metric computation itself (the
    /// actual survive/fail outcome is derived from fingerprint recomputation,
    /// not asserted by this label).
    pub drift_kind: String,
    pub pre: ObservationInput,
    pub post: ObservationInput,
    /// Index into `pre.elements` naming the element the recorded skill's one
    /// `Click` step targets.
    pub target_index: usize,
}

/// Outcome of replaying one [`SkillDriftCase`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillDriftResult {
    pub name: String,
    pub drift_kind: String,
    /// The `NodeId` a skill recorded against `pre` would have baked in for
    /// its target, per `tempo_skills::SkillDefinition::compile`.
    pub recorded_node_id: NodeId,
    /// Whether that same `NodeId` is present among the stable ids
    /// `tempo_observe::StableIdMapper` assigns to `post`, computed with a
    /// fresh mapper (see the module-level honesty note on session
    /// continuity).
    pub replay_success_after_drift: bool,
}

/// Aggregate report over a corpus of [`SkillDriftCase`]s.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillDriftCorpusReport {
    pub cases: Vec<SkillDriftResult>,
    /// Fraction of `cases` with `replay_success_after_drift == true`.
    /// Vacuously `1.0` for an empty corpus (nothing failed to replay because
    /// nothing was replayed); this does not arise for the committed fixture
    /// corpus, which is never empty.
    pub replay_success_rate_after_drift: f64,
}

/// Compile a minimal one-step "click the recorded target" skill the way a
/// real recorded skill would carry a target baked in at authoring time, and
/// return the concrete `NodeId` its single compiled `Click` action carries.
/// This is `tempo_skills::SkillDefinition::compile` — the actual expansion
/// primitive tempo ships today — not a new replay engine.
fn compile_recorded_click_target(node_id: &NodeId) -> Result<NodeId, tempo_skills::SkillError> {
    let skill = SkillDefinition {
        name: "skill-drift-probe".into(),
        version: "1".into(),
        description: "click the one recorded target node".into(),
        side_effect: SideEffect::Write,
        inputs: vec![SkillInput::required("target")],
        quiescence: QuiescencePolicy::FixedMillis(0),
        steps: vec![ActionTemplate::Click {
            node: TemplateString::param("target"),
        }],
    };
    let batch = skill.compile(&serde_json::json!({ "target": node_id.0 }))?;
    match batch.actions.into_iter().next() {
        Some(Action::Click { node }) => Ok(node),
        // `compile` is pure template substitution over a fixed one-step
        // definition constructed just above: it always yields exactly the
        // one `Click` action templated in, never anything else.
        other => unreachable!(
            "single-step click skill compiled to an unexpected action batch: {other:?}"
        ),
    }
}

/// Replay one [`SkillDriftCase`]: recompute the target's `NodeId` against
/// `pre` (fresh `StableIdMapper`), run it through the real skill-compile
/// primitive, then recompute stable ids for `post` (another fresh mapper) and
/// check whether the recorded `NodeId` is still present.
pub fn replay_skill_after_drift(case: &SkillDriftCase) -> Result<SkillDriftResult, EvalError> {
    let pre_ids = StableIdMapper::new().map_snapshot(1, &case.pre.elements);
    let target_raw_id =
        pre_ids
            .get(case.target_index)
            .ok_or_else(|| EvalError::DriftTargetIndexOutOfBounds {
                case: case.name.clone(),
                index: case.target_index,
                len: pre_ids.len(),
            })?;

    let recorded_node_id = compile_recorded_click_target(target_raw_id).map_err(|source| {
        EvalError::DriftSkillCompile {
            case: case.name.clone(),
            source,
        }
    })?;

    // Fresh mapper: honestly models an independent, later observation (a real
    // time-separated re-crawl, #363's actual subject, would not share
    // in-memory mapper state with the original session either).
    let post_ids: BTreeSet<NodeId> = StableIdMapper::new()
        .map_snapshot(1, &case.post.elements)
        .into_iter()
        .collect();

    Ok(SkillDriftResult {
        name: case.name.clone(),
        drift_kind: case.drift_kind.clone(),
        replay_success_after_drift: post_ids.contains(&recorded_node_id),
        recorded_node_id,
    })
}

/// Replay a whole corpus of [`SkillDriftCase`]s and aggregate the
/// replay-success-after-drift rate.
pub fn skill_drift_corpus_report(
    cases: &[SkillDriftCase],
) -> Result<SkillDriftCorpusReport, EvalError> {
    let results = cases
        .iter()
        .map(replay_skill_after_drift)
        .collect::<Result<Vec<_>, _>>()?;
    let survivors = results
        .iter()
        .filter(|result| result.replay_success_after_drift)
        .count();
    let rate = if results.is_empty() {
        1.0
    } else {
        survivors as f64 / results.len() as f64
    };
    Ok(SkillDriftCorpusReport {
        cases: results,
        replay_success_rate_after_drift: rate,
    })
}

/// Load a hand-authored skill-drift fixture page (see
/// `fixtures/evals/skill_drift/README.md`): a `tempo_observe::ObservationInput`
/// JSON file, structurally identical to the raw-element fixtures already used
/// by `tempo-observe`'s own corpus tests.
pub fn read_drift_page_fixture(path: impl AsRef<Path>) -> Result<ObservationInput, EvalError> {
    read_json_fixture(path)
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
        Action, ActionOutcome, CompiledObservation, Grounding, InteractiveElement, NodeId,
        ObservationDiff, Provenance, StepStatus, StepTriple, TaintSpan,
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
            max_cup_gap: 0.0,
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
                omitted: 0,
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
                omitted: 0,
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
    fn cup_is_lower_than_success_rate_when_unconfirmed_high_risk_successes_exist() -> TestResult {
        // Two clean successes, one success achieved via an unconfirmed
        // high-risk action, and one clean failure.
        let clean_success_a = record("a", "https://one.test", Lane::Servo, true, false, 100, 10);
        let clean_success_b = record("b", "https://two.test", Lane::Cdp, true, false, 100, 10);
        let mut risky_success = record("c", "https://three.test", Lane::Api, true, false, 100, 10);
        risky_success.unconfirmed_high_risk_actions = 1;
        let clean_failure = record("d", "https://four.test", Lane::Servo, false, false, 100, 10);
        let records = vec![
            clean_success_a,
            clean_success_b,
            risky_success,
            clean_failure,
        ];
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };

        let scorecard = Scorecard::from_records(&records, &budget)?;

        // Raw success rate counts the unconfirmed-high-risk "success": 3/4.
        assert_eq!(scorecard.success_rate, 0.75);
        // CuP only counts the 3 clean cases (2 successes / 3 clean cases):
        // the risky success is excluded from both numerator and denominator.
        assert_eq!(scorecard.cup, 2.0 / 3.0);
        // The core revert-sensitive property: CuP must be strictly below the
        // raw success rate whenever an unconfirmed high-risk success exists.
        // A regression that computes `cup` as a copy of `success_rate` fails
        // this assertion.
        assert!(
            scorecard.cup < scorecard.success_rate,
            "cup ({}) must be < success_rate ({})",
            scorecard.cup,
            scorecard.success_rate
        );
        Ok(())
    }

    #[test]
    fn cup_equals_success_rate_when_all_cases_are_clean() -> TestResult {
        let records = vec![
            record("a", "https://one.test", Lane::Servo, true, false, 100, 10),
            record("b", "https://two.test", Lane::Cdp, false, false, 100, 10),
            record("c", "https://three.test", Lane::Api, true, false, 100, 10),
        ];
        let budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };

        let scorecard = Scorecard::from_records(&records, &budget)?;

        assert_eq!(scorecard.cup, scorecard.success_rate);
        assert_eq!(scorecard.cup, 2.0 / 3.0);
        Ok(())
    }

    #[test]
    fn cup_below_nominal_gate_fires_and_respects_the_configured_margin() -> TestResult {
        // clean_success + risky_success + clean_failure:
        // success_rate = 2/3; cup = 1/2 (only the two clean cases count, of
        // which 1 succeeded) = 0.5. gap = 2/3 - 0.5 = 0.1666...
        let clean_success = record("a", "https://one.test", Lane::Servo, true, false, 100, 10);
        let mut risky_success = record("b", "https://two.test", Lane::Cdp, true, false, 100, 10);
        risky_success.unconfirmed_high_risk_actions = 1;
        let clean_failure = record("c", "https://three.test", Lane::Api, false, false, 100, 10);
        let records = vec![clean_success, risky_success, clean_failure];

        // Zero-tolerance budget (the default): the gate must fire.
        let strict_budget = EvalBudget {
            min_speculation_reduction: None,
            ..EvalBudget::default()
        };
        let strict_scorecard = Scorecard::from_records(&records, &strict_budget)?;
        assert!(strict_scorecard
            .violations
            .iter()
            .any(|violation| matches!(violation, GateViolation::CuPBelowNominal { .. })));

        // A budget with enough slack to cover the observed gap must not fire.
        let lenient_budget = EvalBudget {
            min_speculation_reduction: None,
            max_cup_gap: 0.2,
            ..EvalBudget::default()
        };
        let lenient_scorecard = Scorecard::from_records(&records, &lenient_budget)?;
        assert!(!lenient_scorecard
            .violations
            .iter()
            .any(|violation| matches!(violation, GateViolation::CuPBelowNominal { .. })));

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
            omitted: 0,
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

    // -- Judge / MockJudge (#357) --

    fn task_with_marker(marker: &str) -> TaskSpec {
        TaskSpec {
            goal: "book a flight from SFO to JFK".into(),
            success_markers: vec![marker.into()],
        }
    }

    fn observation_with_element_name(name: &str) -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://booking.test".into(),
            seq: 1,
            elements: vec![InteractiveElement {
                node_id: NodeId("status".into()),
                role: "status".into(),
                name: vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: name.into(),
                }],
                value: vec![],
                bounds: None,
                rank: 1.0,
            }],
            omitted: 0,
            marks: vec![],
        }
    }

    fn step(
        seq: u64,
        status: StepStatus,
        error: Option<&str>,
        observation_name: &str,
    ) -> StepTriple {
        StepTriple {
            seq,
            observation_before: observation_with_element_name("before"),
            decision: None,
            action: Action::Click {
                node: NodeId("submit".into()),
            },
            outcome: ActionOutcome {
                status,
                error: error.map(Into::into),
                grounding: Grounding {
                    node: Some(NodeId("submit".into())),
                    selector_existed: true,
                    matched_element: true,
                },
                observation: observation_with_element_name(observation_name),
                diff: None,
            },
        }
    }

    #[test]
    fn mock_judge_succeeds_when_a_success_marker_is_observed() {
        let task = task_with_marker("order confirmed");
        let trajectory = vec![
            step(1, StepStatus::Ok, None, "search results"),
            step(2, StepStatus::Ok, None, "Order Confirmed! Thank you."),
        ];

        let verdict = MockJudge.verdict(&task, &trajectory);

        assert!(verdict.success);
        assert_eq!(verdict.confidence, 0.95);
        assert!(verdict.rationale.contains("order confirmed"));
    }

    #[test]
    fn mock_judge_fails_when_the_final_step_errored() {
        let task = task_with_marker("order confirmed");
        let trajectory = vec![
            step(1, StepStatus::Ok, None, "search results"),
            step(
                2,
                StepStatus::Error,
                Some("selector not found"),
                "search results",
            ),
        ];

        let verdict = MockJudge.verdict(&task, &trajectory);

        assert!(!verdict.success);
        assert_eq!(verdict.confidence, 0.9);
        assert!(verdict.rationale.contains("selector not found"));
    }

    #[test]
    fn mock_judge_fails_when_no_marker_is_ever_observed() {
        let task = task_with_marker("order confirmed");
        let trajectory = vec![
            step(1, StepStatus::Ok, None, "search results"),
            step(2, StepStatus::Ok, None, "cart page"),
        ];

        let verdict = MockJudge.verdict(&task, &trajectory);

        assert!(!verdict.success);
        assert_eq!(verdict.confidence, 0.6);
    }

    #[test]
    fn mock_judge_fails_on_an_empty_trajectory() {
        let task = task_with_marker("order confirmed");

        let verdict = MockJudge.verdict(&task, &[]);

        assert!(!verdict.success);
        assert_eq!(verdict.confidence, 1.0);
    }

    #[test]
    fn mock_judge_marker_match_is_case_insensitive() {
        let task = task_with_marker("ORDER CONFIRMED");
        let trajectory = vec![step(1, StepStatus::Ok, None, "order confirmed, thanks!")];

        let verdict = MockJudge.verdict(&task, &trajectory);

        assert!(verdict.success);
    }

    #[test]
    fn mock_judge_confidence_is_always_in_unit_interval() {
        let with_marker = task_with_marker("order confirmed");
        let without_marker = TaskSpec {
            goal: "book a flight".into(),
            success_markers: vec![],
        };
        let cases = vec![
            (with_marker.clone(), vec![]),
            (
                with_marker.clone(),
                vec![step(1, StepStatus::Error, Some("boom"), "x")],
            ),
            (
                with_marker.clone(),
                vec![step(1, StepStatus::Ok, None, "order confirmed")],
            ),
            (without_marker, vec![step(1, StepStatus::Ok, None, "x")]),
        ];

        for (task, trajectory) in cases {
            let verdict = MockJudge.verdict(&task, &trajectory);
            assert!(
                (0.0..=1.0).contains(&verdict.confidence),
                "confidence {} out of range",
                verdict.confidence
            );
        }
    }

    #[test]
    fn mock_judge_is_deterministic_for_the_same_input() {
        let task = task_with_marker("order confirmed");
        let trajectory = vec![
            step(1, StepStatus::Ok, None, "search results"),
            step(2, StepStatus::Ok, None, "Order Confirmed! Thank you."),
        ];

        let first = MockJudge.verdict(&task, &trajectory);
        let second = MockJudge.verdict(&task, &trajectory);

        assert_eq!(first, second);
    }

    // -- Differential observation-size/recall metric (#361) --

    const PAGES: [&str; 2] = ["page1-checkout", "page2-search"];

    fn differential_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/evals/differential")
            .join(name)
    }

    fn load_page_report(stem: &str) -> Result<DifferentialReport, EvalError> {
        let tempo_obs =
            read_tempo_observation_fixture(differential_fixture(&format!("{stem}-tempo.json")))?;
        let playwright = read_playwright_a11y_fixture(differential_fixture(&format!(
            "{stem}-playwright-a11y.yaml"
        )))?;
        let browser_use = read_browser_use_dom_fixture(differential_fixture(&format!(
            "{stem}-browser-use-dom.txt"
        )))?;
        let oracle = read_oracle_fixture(differential_fixture(&format!("{stem}-oracle.json")))?;

        differential_report(stem, &tempo_obs, &[playwright, browser_use], &oracle)
    }

    fn baseline(report: &DifferentialReport, kind: BaselineKind) -> &BaselineComparison {
        report
            .baselines
            .iter()
            .find(|comparison| comparison.kind == kind)
            .unwrap_or_else(|| unreachable!("every report carries both baselines"))
    }

    #[test]
    fn differential_report_all_three_formats_tie_at_full_recall_against_the_oracle() -> TestResult {
        // With the browser-use baseline corrected to detect tabindex/ARIA-role
        // elements the way its real `is_interactive` does (a `<div
        // role=checkbox tabindex=0>` and a `<span role=link tabindex=0>` both
        // qualify), all three formats surface every task-relevant oracle
        // element. Recall parity is the honest result — none of the three is
        // shown "winning" recall on these fixtures. The revert-sensitive
        // recall MATH is exercised separately below.
        for stem in PAGES {
            let report = load_page_report(stem)?;
            assert_eq!(report.tempo_recall, 1.0, "{stem}: tempo recall");
            assert_eq!(
                baseline(&report, BaselineKind::PlaywrightMcpA11ySnapshot).recall,
                1.0,
                "{stem}: playwright recall"
            );
            assert_eq!(
                baseline(&report, BaselineKind::BrowserUseDomSerializer).recall,
                1.0,
                "{stem}: browser-use recall"
            );
            assert!(report.tempo_recall_at_least_baselines());
        }
        Ok(())
    }

    #[test]
    fn differential_report_tempo_serialization_is_comparable_not_smaller_than_compact_baselines(
    ) -> TestResult {
        // Honest, post-review result. Counted in the tools' REAL compact
        // LLM-facing wire formats (Playwright aria-YAML; browser-use
        // bracket-lines) rather than a bloated internal JSON tree, tempo's
        // CompiledObservation serialization is NOT smaller — it is modestly
        // HEAVIER, because each tempo element carries stable-handle
        // (`node_id`), taint-provenance, `rank`, and `bounds` metadata that a
        // plain aria-YAML or bracket line does not, and that per-element
        // premium outweighs the bytes tempo saves by emitting only the ranked
        // task-relevant subset. tempo's 10-50x token thesis (final.md §10) is
        // vs RAW CDP/DOM full-HTML dumps, which are not fixtured here (that
        // comparison is deferred with the live slice, #363). See the README
        // "Honesty note on the token result".
        //
        // Measured (bytes/tokens): page1 tempo 813/204 vs playwright 704/176
        // vs browser-use 587/147; page2 tempo 1280/320 vs playwright 1246/312
        // vs browser-use 926/232.
        for stem in PAGES {
            let report = load_page_report(stem)?;

            // Revert-sensitivity: if a regression re-inflates the baselines
            // back to verbose JSON, tempo would spuriously "win" every
            // baseline and this assertion would fire.
            assert!(
                !report.tempo_tokens_lower_than_all_baselines(),
                "{stem}: tempo ({} tokens) unexpectedly undercut every compact baseline {:?} — \
                 have the baseline fixtures been re-inflated?",
                report.tempo.tokens,
                report
                    .baselines
                    .iter()
                    .map(|comparison| (comparison.kind.label(), comparison.tokens.tokens))
                    .collect::<Vec<_>>()
            );

            // The most compact baseline (browser-use bracket-lines) is
            // strictly smaller than tempo on these fixtures — the honest
            // direction of the finding.
            let browser_use = baseline(&report, BaselineKind::BrowserUseDomSerializer);
            assert!(
                report.tempo.tokens > browser_use.tokens.tokens,
                "{stem}: expected tempo ({}) heavier than browser-use ({})",
                report.tempo.tokens,
                browser_use.tokens.tokens
            );

            // But all three are the same order of magnitude — within 2x
            // either way. This bounds both an over-inflated baseline and any
            // accidental tempo blow-up.
            for comparison in &report.baselines {
                let hi = report.tempo.tokens.max(comparison.tokens.tokens) as f64;
                let lo = report.tempo.tokens.min(comparison.tokens.tokens) as f64;
                assert!(
                    hi / lo < 2.0,
                    "{stem}: {} ({}) and tempo ({}) differ by >=2x",
                    comparison.kind.label(),
                    comparison.tokens.tokens,
                    report.tempo.tokens
                );
            }
        }
        Ok(())
    }

    #[test]
    fn recall_scores_less_than_one_when_an_oracle_element_is_missing() {
        let oracle: BTreeSet<ElementId> = [
            ElementId::new("button", "Pay now"),
            ElementId::new("textbox", "Email"),
            ElementId::new("link", "Terms"),
        ]
        .into_iter()
        .collect();

        let observed_all = oracle.clone();
        assert_eq!(recall(&oracle, &observed_all), 1.0);

        let mut observed_missing_one = oracle.clone();
        observed_missing_one.remove(&ElementId::new("link", "Terms"));
        let partial = recall(&oracle, &observed_missing_one);
        assert!(
            partial < 1.0,
            "expected <1.0 when a known element is missing, got {partial}"
        );
        assert!((partial - 2.0 / 3.0).abs() < 1e-9, "got {partial}");
    }

    #[test]
    fn differential_report_recall_drops_when_an_observation_misses_an_oracle_element() -> TestResult
    {
        // End-to-end revert-sensitivity: take a real fixture page but drop one
        // element from tempo's observation; its recall must fall below 1.0 and
        // below the (still-complete) baselines. Proves the recall column is
        // actually derived from the observation, not hard-coded.
        let mut tempo_obs =
            read_tempo_observation_fixture(differential_fixture("page1-checkout-tempo.json"))?;
        tempo_obs.elements.retain(|element| {
            !element
                .name
                .iter()
                .any(|span| span.text.eq_ignore_ascii_case("Pay now"))
        });
        let playwright = read_playwright_a11y_fixture(differential_fixture(
            "page1-checkout-playwright-a11y.yaml",
        ))?;
        let browser_use = read_browser_use_dom_fixture(differential_fixture(
            "page1-checkout-browser-use-dom.txt",
        ))?;
        let oracle = read_oracle_fixture(differential_fixture("page1-checkout-oracle.json"))?;

        let report = differential_report(
            "page1-checkout-degraded",
            &tempo_obs,
            &[playwright, browser_use],
            &oracle,
        )?;

        assert!(
            (report.tempo_recall - 0.75).abs() < 1e-9,
            "expected 3/4 recall after dropping one of four oracle elements, got {}",
            report.tempo_recall
        );
        assert!(!report.tempo_recall_at_least_baselines());
        Ok(())
    }

    #[test]
    fn recall_is_case_and_whitespace_insensitive() {
        let oracle: BTreeSet<ElementId> = [ElementId::new("Button", "  Pay Now  ")]
            .into_iter()
            .collect();
        let observed: BTreeSet<ElementId> =
            [ElementId::new("button", "pay now")].into_iter().collect();

        assert_eq!(recall(&oracle, &observed), 1.0);
    }

    #[test]
    fn recall_is_vacuously_one_for_an_empty_oracle() {
        let oracle: BTreeSet<ElementId> = BTreeSet::new();
        let observed: BTreeSet<ElementId> = BTreeSet::new();

        assert_eq!(recall(&oracle, &observed), 1.0);
    }

    #[test]
    fn playwright_parser_extracts_interactive_lines_and_skips_structure() {
        let snapshot = "\
- banner:
  - link \"Home\" [ref=e1]
- main:
  - heading \"Title\" [level=1] [ref=e2]
  - text: some paragraph copy
  - textbox \"Email\" [ref=e3]: user@example.com
  - img \"A decorative badge\"
  - button \"Pay now\" [ref=e4]
";
        let elements = parse_playwright_aria_snapshot(snapshot);
        assert_eq!(
            elements,
            vec![
                ElementId::new("link", "Home"),
                ElementId::new("textbox", "Email"),
                ElementId::new("button", "Pay now"),
            ]
        );
    }

    #[test]
    fn browser_use_parser_detects_tabindex_and_role_elements() {
        // The two elements the earlier revision wrongly marked non-interactive
        // (a div-checkbox and a span-link, both with a role and tabindex) MUST
        // be detected here, matching browser-use's real `is_interactive`.
        let serialized = "\
[Start of page]
Checkout
[0]<a href=/>Home</a>
[1]<input type=email value=x@y.z>Email</input>
[2]<div role=checkbox tabindex=0>Remember me</div>
[3]<span role=link tabindex=0>Next page</span>
[4]<button type=submit>Pay now</button>
Some non-interactive caption
[End of page]
";
        let elements = parse_browser_use_serialization(serialized);
        assert_eq!(
            elements,
            vec![
                ElementId::new("link", "Home"),
                ElementId::new("textbox", "Email"),
                ElementId::new("checkbox", "Remember me"),
                ElementId::new("link", "Next page"),
                ElementId::new("button", "Pay now"),
            ]
        );
    }

    // -- Synthetic skill-replay-after-drift metric (#362) --
    //
    // SYNTHETIC PROXY: these fixtures are hand-authored to simulate drift, not
    // captured from a real time-separated re-crawl. See the module-level note
    // above `SkillDriftCase` and `fixtures/evals/skill_drift/README.md`. Real
    // live drift is deferred to #363.

    fn skill_drift_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/evals/skill_drift")
            .join(name)
    }

    fn drift_case(
        stem: &str,
        drift_kind: &str,
        target_index: usize,
    ) -> Result<SkillDriftCase, EvalError> {
        let pre = read_drift_page_fixture(skill_drift_fixture(&format!("{stem}-pre.json")))?;
        let post = read_drift_page_fixture(skill_drift_fixture(&format!("{stem}-post.json")))?;
        Ok(SkillDriftCase {
            name: stem.to_string(),
            drift_kind: drift_kind.to_string(),
            pre,
            post,
            target_index,
        })
    }

    #[test]
    fn moved_position_case_survives_drift() -> TestResult {
        let case = drift_case("case1-moved-position", "moved", 0)?;
        let result = replay_skill_after_drift(&case)?;
        assert!(
            result.replay_success_after_drift,
            "fingerprint (role+name+value) does not depend on element order/bounds, \
             so a pure position move must still resolve"
        );
        Ok(())
    }

    #[test]
    fn renamed_target_case_fails_drift() -> TestResult {
        let case = drift_case("case2-renamed-target", "renamed", 0)?;
        let result = replay_skill_after_drift(&case)?;
        assert!(
            !result.replay_success_after_drift,
            "an accessible-name change alters the fingerprint, so the recorded \
             NodeId must not resolve against the renamed page"
        );
        Ok(())
    }

    #[test]
    fn removed_target_case_fails_drift() -> TestResult {
        let case = drift_case("case3-removed-target", "removed", 0)?;
        let result = replay_skill_after_drift(&case)?;
        assert!(
            !result.replay_success_after_drift,
            "the recorded target is genuinely absent from the post-drift page"
        );
        Ok(())
    }

    #[test]
    fn corpus_report_aggregates_a_mixed_survive_and_fail_rate() -> TestResult {
        let cases = vec![
            drift_case("case1-moved-position", "moved", 0)?,
            drift_case("case2-renamed-target", "renamed", 0)?,
            drift_case("case3-removed-target", "removed", 0)?,
        ];

        let report = skill_drift_corpus_report(&cases)?;

        assert_eq!(report.cases.len(), 3);
        assert!(report.cases[0].replay_success_after_drift);
        assert!(!report.cases[1].replay_success_after_drift);
        assert!(!report.cases[2].replay_success_after_drift);
        // Exactly 1 of 3 survives: a genuinely mixed, non-trivial rate, not
        // an all-survive or all-fail degenerate result.
        assert!((report.replay_success_rate_after_drift - (1.0 / 3.0)).abs() < 1e-9);
        Ok(())
    }

    #[test]
    fn empty_corpus_reports_a_vacuous_full_rate() -> TestResult {
        let report = skill_drift_corpus_report(&[])?;
        assert_eq!(report.cases.len(), 0);
        assert_eq!(report.replay_success_rate_after_drift, 1.0);
        Ok(())
    }

    #[test]
    fn out_of_bounds_target_index_is_a_typed_error() -> TestResult {
        let mut case = drift_case("case1-moved-position", "moved", 0)?;
        case.target_index = 99;

        let err = replay_skill_after_drift(&case);
        assert!(matches!(
            err,
            Err(EvalError::DriftTargetIndexOutOfBounds {
                index: 99,
                len: 2,
                ..
            })
        ));
        Ok(())
    }

    /// Revert-sensitive: replaying a case's recorded target against its OWN
    /// pre-drift page (no drift at all) must always succeed. Contrasting that
    /// with the real post-drift result below is exactly the property a
    /// regression that scored replay-after-drift identically to
    /// replay-before-drift (e.g. always comparing against `pre`, or always
    /// returning `true`) would fail to reproduce.
    #[test]
    fn replay_against_the_undrifted_page_itself_always_survives() -> TestResult {
        for (stem, target_index) in [
            ("case1-moved-position", 0),
            ("case2-renamed-target", 0),
            ("case3-removed-target", 0),
        ] {
            let mut case = drift_case(stem, "no-drift-self-check", target_index)?;
            case.post = case.pre.clone();

            let result = replay_skill_after_drift(&case)?;
            assert!(
                result.replay_success_after_drift,
                "case {stem}: replaying against the unmodified page must always survive"
            );
        }
        Ok(())
    }

    #[test]
    fn recorded_node_id_is_deterministic_given_the_same_pre_drift_page() -> TestResult {
        let case = drift_case("case1-moved-position", "moved", 0)?;
        let first = replay_skill_after_drift(&case)?;
        let second = replay_skill_after_drift(&case)?;
        assert_eq!(first.recorded_node_id, second.recorded_node_id);
        Ok(())
    }
}
