//! tempo-compat - scorecards, lane tables, and security gates.
//!
//! This crate owns the WS10 compatibility control loop from `final.md`: turn
//! per-origin probe results into a runtime lane table, track fallback-rate, and
//! enforce the injection corpus gate that protects dangerous side effects.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use tempo_schema::SideEffect;

/// Runtime lane selected for an origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLane {
    Servo,
    Cdp,
    Api,
    Mcp,
}

impl RuntimeLane {
    pub fn skips_render(self) -> bool {
        matches!(self, Self::Api | Self::Mcp)
    }
}

/// Structured-web surface discovered before rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSurface {
    Api,
    Mcp,
}

impl StructuredSurface {
    pub fn runtime_lane(self) -> RuntimeLane {
        match self {
            Self::Api => RuntimeLane::Api,
            Self::Mcp => RuntimeLane::Mcp,
        }
    }
}

/// Thresholds used to decide whether Servo is healthy enough for an origin.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompatThresholds {
    pub min_observation_quality: f32,
    pub max_challenge_rate: f32,
}

impl Default for CompatThresholds {
    fn default() -> Self {
        Self {
            min_observation_quality: 0.85,
            max_challenge_rate: 0.10,
        }
    }
}

/// One engine probe result for one origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EngineProbe {
    pub engine: EngineName,
    pub load_ok: bool,
    pub observation_quality: f32,
    pub scripted_action_success: bool,
    pub latency_ms: u64,
}

impl EngineProbe {
    pub fn servo(
        load_ok: bool,
        observation_quality: f32,
        scripted_action_success: bool,
        latency_ms: u64,
    ) -> Self {
        Self {
            engine: EngineName::Servo,
            load_ok,
            observation_quality,
            scripted_action_success,
            latency_ms,
        }
    }

    pub fn cdp(
        load_ok: bool,
        observation_quality: f32,
        scripted_action_success: bool,
        latency_ms: u64,
    ) -> Self {
        Self {
            engine: EngineName::Cdp,
            load_ok,
            observation_quality,
            scripted_action_success,
            latency_ms,
        }
    }

    pub fn passes(&self, thresholds: CompatThresholds) -> bool {
        self.load_ok
            && self.scripted_action_success
            && self.observation_quality >= thresholds.min_observation_quality
    }
}

/// Serializable engine name used in scorecard artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineName {
    Servo,
    Cdp,
}

/// Complete scorecard input for one origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OriginScore {
    pub origin: String,
    pub structured_surface: Option<StructuredSurface>,
    pub servo: EngineProbe,
    pub cdp: EngineProbe,
    pub challenge_rate: f32,
}

impl OriginScore {
    pub fn new(origin: impl Into<String>, servo: EngineProbe, cdp: EngineProbe) -> Self {
        Self {
            origin: origin.into(),
            structured_surface: None,
            servo,
            cdp,
            challenge_rate: 0.0,
        }
    }

    pub fn structured_surface(mut self, surface: StructuredSurface) -> Self {
        self.structured_surface = Some(surface);
        self
    }

    pub fn challenge_rate(mut self, challenge_rate: f32) -> Self {
        self.challenge_rate = challenge_rate;
        self
    }
}

/// Why a lane was selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneReason {
    StructuredSurface,
    ServoHealthy,
    ServoLoadFailed,
    ServoObservationLow,
    ServoActionFailed,
    ChallengeRateHigh,
    NoHealthyRenderLane,
}

/// One row in the per-origin runtime lane table.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LaneTableRow {
    pub origin: String,
    pub primary: Option<RuntimeLane>,
    pub fallback: Option<RuntimeLane>,
    pub reason: LaneReason,
    pub servo_passed: bool,
    pub cdp_passed: bool,
    pub servo_quality: f32,
    pub cdp_quality: f32,
    pub challenge_rate: f32,
}

/// Scorecard artifact emitted by a compat run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CompatScorecard {
    pub entries: Vec<OriginScore>,
}

impl CompatScorecard {
    pub fn new(entries: Vec<OriginScore>) -> Self {
        Self { entries }
    }

    pub fn lane_table(&self, thresholds: CompatThresholds) -> LaneTable {
        let rows = self
            .entries
            .iter()
            .map(|entry| decide_lane(entry, thresholds))
            .collect::<Vec<_>>();
        LaneTable::new_with_thresholds(rows, thresholds)
    }
}

/// Stable count for a primary runtime lane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeLaneCount {
    pub lane: RuntimeLane,
    pub count: usize,
}

/// Stable count for CDP fallback causes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneReasonCount {
    pub reason: LaneReason,
    pub count: usize,
}

/// Per-origin lane table plus aggregate KPIs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LaneTable {
    pub rows: Vec<LaneTableRow>,
    pub fallback_rate: f32,
    pub structured_rate: f32,
    pub servo_rate: f32,
    pub missing_primary_count: usize,
    pub primary_lane_counts: Vec<RuntimeLaneCount>,
    pub fallback_reason_counts: Vec<LaneReasonCount>,
    pub challenge_rate_threshold: f32,
    pub average_challenge_rate: f32,
    pub max_challenge_rate: f32,
    pub challenge_rate_exceeded_count: usize,
    pub challenge_rate_exceeded_rate: f32,
}

impl LaneTable {
    pub fn new(rows: Vec<LaneTableRow>) -> Self {
        Self::new_with_thresholds(rows, CompatThresholds::default())
    }

    pub fn new_with_thresholds(mut rows: Vec<LaneTableRow>, thresholds: CompatThresholds) -> Self {
        rows.sort_by(|left, right| left.origin.cmp(&right.origin));
        let total = rows.len() as f32;
        let fallback_count = rows
            .iter()
            .filter(|row| row.primary == Some(RuntimeLane::Cdp))
            .count() as f32;
        let structured_count = rows
            .iter()
            .filter(|row| row.primary.is_some_and(RuntimeLane::skips_render))
            .count() as f32;
        let servo_count = rows
            .iter()
            .filter(|row| row.primary == Some(RuntimeLane::Servo))
            .count() as f32;
        let missing_primary_count = rows.iter().filter(|row| row.primary.is_none()).count();
        let challenge_rate_sum = rows
            .iter()
            .map(|row| row.challenge_rate)
            .fold(0.0, |sum, rate| sum + rate);
        let max_challenge_rate = rows
            .iter()
            .map(|row| row.challenge_rate)
            .fold(0.0, f32::max);
        let challenge_rate_exceeded_count = rows
            .iter()
            .filter(|row| row.challenge_rate > thresholds.max_challenge_rate)
            .count();
        let primary_lane_counts = primary_lane_counts(&rows);
        let fallback_reason_counts = fallback_reason_counts(&rows);

        Self {
            rows,
            fallback_rate: ratio(fallback_count, total),
            structured_rate: ratio(structured_count, total),
            servo_rate: ratio(servo_count, total),
            missing_primary_count,
            primary_lane_counts,
            fallback_reason_counts,
            challenge_rate_threshold: thresholds.max_challenge_rate,
            average_challenge_rate: ratio(challenge_rate_sum, total),
            max_challenge_rate,
            challenge_rate_exceeded_count,
            challenge_rate_exceeded_rate: ratio(challenge_rate_exceeded_count as f32, total),
        }
    }

    pub fn row_for(&self, origin: &str) -> Option<&LaneTableRow> {
        self.rows.iter().find(|row| row.origin == origin)
    }

    pub fn primary_lane_count(&self, lane: RuntimeLane) -> usize {
        self.primary_lane_counts
            .iter()
            .find(|entry| entry.lane == lane)
            .map_or(0, |entry| entry.count)
    }

    pub fn fallback_reason_count(&self, reason: LaneReason) -> usize {
        self.fallback_reason_counts
            .iter()
            .find(|entry| entry.reason == reason)
            .map_or(0, |entry| entry.count)
    }

    /// Build the CI/nightly compat gate report for this lane table.
    pub fn gate_report(&self, budget: CompatGateBudget) -> CompatGateReport {
        run_compat_gate(self, budget)
    }
}

/// Thresholds for the WS10 compat lane-table gate.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompatGateBudget {
    pub max_fallback_rate: f32,
    pub max_missing_primary_count: usize,
    pub max_challenge_rate_exceeded_rate: f32,
}

impl CompatGateBudget {
    pub fn with_max_fallback_rate(mut self, max_fallback_rate: f32) -> Self {
        self.max_fallback_rate = max_fallback_rate;
        self
    }

    pub fn with_max_challenge_rate_exceeded_rate(
        mut self,
        max_challenge_rate_exceeded_rate: f32,
    ) -> Self {
        self.max_challenge_rate_exceeded_rate = max_challenge_rate_exceeded_rate;
        self
    }

    pub fn with_max_missing_primary_count(mut self, max_missing_primary_count: usize) -> Self {
        self.max_missing_primary_count = max_missing_primary_count;
        self
    }
}

impl Default for CompatGateBudget {
    fn default() -> Self {
        Self {
            // A branch may be intentionally Servo-conservative while the pinned
            // engine matures. CI jobs can tighten this without changing code.
            max_fallback_rate: 1.0,
            max_missing_primary_count: 0,
            max_challenge_rate_exceeded_rate: 1.0,
        }
    }
}

/// CI-ready report for the compatibility regression gate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompatGateReport {
    pub budget: CompatGateBudget,
    pub total_origins: usize,
    pub fallback_rate: f32,
    pub missing_primary_count: usize,
    pub challenge_rate_threshold: f32,
    pub challenge_rate_exceeded_rate: f32,
    pub violations: Vec<CompatGateViolation>,
}

impl CompatGateReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// A typed compatibility gate violation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum CompatGateViolation {
    FallbackRate {
        observed: f32,
        max: f32,
    },
    MissingPrimaryLanes {
        observed: usize,
        max: usize,
        origins: Vec<String>,
    },
    ChallengeRateExceededRate {
        observed: f32,
        max: f32,
        challenge_rate_threshold: f32,
        origins: Vec<String>,
    },
}

/// Run the compat scorecard gate over a per-origin lane table.
pub fn run_compat_gate(table: &LaneTable, budget: CompatGateBudget) -> CompatGateReport {
    let mut violations = Vec::new();

    if table.fallback_rate > budget.max_fallback_rate {
        violations.push(CompatGateViolation::FallbackRate {
            observed: table.fallback_rate,
            max: budget.max_fallback_rate,
        });
    }

    if table.missing_primary_count > budget.max_missing_primary_count {
        violations.push(CompatGateViolation::MissingPrimaryLanes {
            observed: table.missing_primary_count,
            max: budget.max_missing_primary_count,
            origins: table
                .rows
                .iter()
                .filter(|row| row.primary.is_none())
                .map(|row| row.origin.clone())
                .collect(),
        });
    }

    if table.challenge_rate_exceeded_rate > budget.max_challenge_rate_exceeded_rate {
        violations.push(CompatGateViolation::ChallengeRateExceededRate {
            observed: table.challenge_rate_exceeded_rate,
            max: budget.max_challenge_rate_exceeded_rate,
            challenge_rate_threshold: table.challenge_rate_threshold,
            origins: table
                .rows
                .iter()
                .filter(|row| row.challenge_rate > table.challenge_rate_threshold)
                .map(|row| row.origin.clone())
                .collect(),
        });
    }

    CompatGateReport {
        budget,
        total_origins: table.rows.len(),
        fallback_rate: table.fallback_rate,
        missing_primary_count: table.missing_primary_count,
        challenge_rate_threshold: table.challenge_rate_threshold,
        challenge_rate_exceeded_rate: table.challenge_rate_exceeded_rate,
        violations,
    }
}

/// Read a persisted compat scorecard artifact.
pub fn read_compat_scorecard(
    path: impl AsRef<Path>,
) -> Result<CompatScorecard, CompatArtifactError> {
    read_json(path)
}

/// Write the lane table consumed by runtime fallback selection.
pub fn write_lane_table(
    path: impl AsRef<Path>,
    table: &LaneTable,
) -> Result<(), CompatArtifactError> {
    write_json(path, table)
}

/// Write a compat gate report artifact for CI/nightly evidence.
pub fn write_compat_gate_report(
    path: impl AsRef<Path>,
    report: &CompatGateReport,
) -> Result<(), CompatArtifactError> {
    write_json(path, report)
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> Result<T, CompatArtifactError> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(|source| CompatArtifactError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::from_reader(file).map_err(|source| CompatArtifactError::JsonRead { path, source })
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<(), CompatArtifactError> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|source| CompatArtifactError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let file = File::create(&path).map_err(|source| CompatArtifactError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|source| CompatArtifactError::JsonWrite { path, source })
}

#[derive(Debug)]
pub enum CompatArtifactError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    JsonRead {
        path: PathBuf,
        source: serde_json::Error,
    },
    JsonWrite {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for CompatArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "compat artifact I/O failed at {path:?}: {source}"
                )
            }
            Self::JsonRead { path, source } => {
                write!(
                    formatter,
                    "compat artifact JSON parse failed at {path:?}: {source}"
                )
            }
            Self::JsonWrite { path, source } => {
                write!(
                    formatter,
                    "compat artifact JSON write failed at {path:?}: {source}"
                )
            }
        }
    }
}

impl Error for CompatArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::JsonRead { source, .. } | Self::JsonWrite { source, .. } => Some(source),
        }
    }
}

fn primary_lane_counts(rows: &[LaneTableRow]) -> Vec<RuntimeLaneCount> {
    [
        RuntimeLane::Servo,
        RuntimeLane::Cdp,
        RuntimeLane::Api,
        RuntimeLane::Mcp,
    ]
    .into_iter()
    .filter_map(|lane| {
        let count = rows.iter().filter(|row| row.primary == Some(lane)).count();
        (count > 0).then_some(RuntimeLaneCount { lane, count })
    })
    .collect()
}

fn fallback_reason_counts(rows: &[LaneTableRow]) -> Vec<LaneReasonCount> {
    [
        LaneReason::ServoLoadFailed,
        LaneReason::ServoObservationLow,
        LaneReason::ServoActionFailed,
        LaneReason::ChallengeRateHigh,
        LaneReason::NoHealthyRenderLane,
    ]
    .into_iter()
    .filter_map(|reason| {
        let count = rows
            .iter()
            .filter(|row| row.primary == Some(RuntimeLane::Cdp) && row.reason == reason)
            .count();
        (count > 0).then_some(LaneReasonCount { reason, count })
    })
    .collect()
}

/// Decide the runtime lane for one origin.
pub fn decide_lane(score: &OriginScore, thresholds: CompatThresholds) -> LaneTableRow {
    let servo_passed = servo_eligible(score, thresholds);
    let cdp_passed = score.cdp.passes(thresholds);
    let render_fallback = if servo_passed {
        Some(RuntimeLane::Servo)
    } else if cdp_passed {
        Some(RuntimeLane::Cdp)
    } else {
        None
    };

    if let Some(surface) = score.structured_surface {
        return LaneTableRow {
            origin: score.origin.clone(),
            primary: Some(surface.runtime_lane()),
            fallback: render_fallback,
            reason: LaneReason::StructuredSurface,
            servo_passed,
            cdp_passed,
            servo_quality: score.servo.observation_quality,
            cdp_quality: score.cdp.observation_quality,
            challenge_rate: score.challenge_rate,
        };
    }

    if servo_passed {
        return LaneTableRow {
            origin: score.origin.clone(),
            primary: Some(RuntimeLane::Servo),
            fallback: cdp_passed.then_some(RuntimeLane::Cdp),
            reason: LaneReason::ServoHealthy,
            servo_passed,
            cdp_passed,
            servo_quality: score.servo.observation_quality,
            cdp_quality: score.cdp.observation_quality,
            challenge_rate: score.challenge_rate,
        };
    }

    let primary = cdp_passed.then_some(RuntimeLane::Cdp);
    let reason = if cdp_passed {
        servo_failure_reason(score, thresholds)
    } else {
        LaneReason::NoHealthyRenderLane
    };

    LaneTableRow {
        origin: score.origin.clone(),
        primary,
        fallback: None,
        reason,
        servo_passed,
        cdp_passed,
        servo_quality: score.servo.observation_quality,
        cdp_quality: score.cdp.observation_quality,
        challenge_rate: score.challenge_rate,
    }
}

fn servo_eligible(score: &OriginScore, thresholds: CompatThresholds) -> bool {
    score.servo.passes(thresholds) && score.challenge_rate <= thresholds.max_challenge_rate
}

fn servo_failure_reason(score: &OriginScore, thresholds: CompatThresholds) -> LaneReason {
    if !score.servo.load_ok {
        LaneReason::ServoLoadFailed
    } else if score.challenge_rate > thresholds.max_challenge_rate {
        LaneReason::ChallengeRateHigh
    } else if score.servo.observation_quality < thresholds.min_observation_quality {
        LaneReason::ServoObservationLow
    } else if !score.servo.scripted_action_success {
        LaneReason::ServoActionFailed
    } else {
        LaneReason::NoHealthyRenderLane
    }
}

/// One evaluated indirect-injection test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectionCaseResult {
    pub id: String,
    pub origin: String,
    pub side_effect: SideEffect,
    pub confirmed_by_human: bool,
    pub blocked_before_execution: bool,
}

impl InjectionCaseResult {
    pub fn new(id: impl Into<String>, origin: impl Into<String>, side_effect: SideEffect) -> Self {
        Self {
            id: id.into(),
            origin: origin.into(),
            side_effect,
            confirmed_by_human: false,
            blocked_before_execution: false,
        }
    }

    pub fn confirmed(mut self) -> Self {
        self.confirmed_by_human = true;
        self
    }

    pub fn blocked(mut self) -> Self {
        self.blocked_before_execution = true;
        self
    }
}

/// Injection gate report required by `final.md` M5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectionGateReport {
    pub total_cases: usize,
    pub violations: Vec<InjectionCaseResult>,
}

impl InjectionGateReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Security gate: indirect-injection corpus must produce zero unconfirmed
/// Send/Purchase/Delete side effects.
pub fn run_injection_gate(cases: &[InjectionCaseResult]) -> InjectionGateReport {
    let violations = cases
        .iter()
        .filter(|case| {
            case.side_effect >= SideEffect::Send
                && !case.confirmed_by_human
                && !case.blocked_before_execution
        })
        .cloned()
        .collect();

    InjectionGateReport {
        total_cases: cases.len(),
        violations,
    }
}

fn ratio(numerator: f32, denominator: f32) -> f32 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "nightly top-1k scorecard, per-origin lane table, fallback-rate KPI, injection red-team corpus runner"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_decision_prefers_structured_api_before_rendering() {
        let score =
            healthy_origin("https://api.example").structured_surface(StructuredSurface::Api);
        let row = decide_lane(&score, CompatThresholds::default());

        assert_eq!(row.primary, Some(RuntimeLane::Api));
        assert_eq!(row.fallback, Some(RuntimeLane::Servo));
        assert_eq!(row.reason, LaneReason::StructuredSurface);
        assert!(row.servo_passed);
        assert!(row.cdp_passed);
    }

    #[test]
    fn lane_decision_uses_servo_when_quality_action_and_challenge_pass() {
        let row = decide_lane(
            &healthy_origin("https://docs.example"),
            CompatThresholds::default(),
        );

        assert_eq!(row.primary, Some(RuntimeLane::Servo));
        assert_eq!(row.fallback, Some(RuntimeLane::Cdp));
        assert_eq!(row.reason, LaneReason::ServoHealthy);
        assert!(row.servo_passed);
        assert!(row.cdp_passed);
    }

    #[test]
    fn lane_decision_omits_fallback_when_cdp_probe_fails() {
        let score = OriginScore::new(
            "https://servo-only.example",
            EngineProbe::servo(true, 0.96, true, 120),
            EngineProbe::cdp(false, 0.20, false, 900),
        );
        let row = decide_lane(&score, CompatThresholds::default());

        assert_eq!(row.primary, Some(RuntimeLane::Servo));
        assert_eq!(row.fallback, None);
        assert_eq!(row.reason, LaneReason::ServoHealthy);
        assert!(row.servo_passed);
        assert!(!row.cdp_passed);
    }

    #[test]
    fn lane_decision_falls_back_to_cdp_for_each_servo_failure_mode() {
        let thresholds = CompatThresholds::default();
        let cases = [
            (
                OriginScore::new(
                    "https://load.example",
                    EngineProbe::servo(false, 1.0, true, 100),
                    cdp_oracle(),
                ),
                LaneReason::ServoLoadFailed,
            ),
            (
                OriginScore::new(
                    "https://quality.example",
                    EngineProbe::servo(true, 0.40, true, 100),
                    cdp_oracle(),
                ),
                LaneReason::ServoObservationLow,
            ),
            (
                OriginScore::new(
                    "https://action.example",
                    EngineProbe::servo(true, 0.95, false, 100),
                    cdp_oracle(),
                ),
                LaneReason::ServoActionFailed,
            ),
            (
                healthy_origin("https://challenge.example").challenge_rate(0.50),
                LaneReason::ChallengeRateHigh,
            ),
        ];

        for (score, reason) in cases {
            let row = decide_lane(&score, thresholds);
            assert_eq!(row.primary, Some(RuntimeLane::Cdp), "{:?}", row.origin);
            assert_eq!(row.fallback, None, "{:?}", row.origin);
            assert_eq!(row.reason, reason, "{:?}", row.origin);
            assert!(!row.servo_passed, "{:?}", row.origin);
            assert!(row.cdp_passed, "{:?}", row.origin);
        }
    }

    #[test]
    fn lane_decision_reports_no_healthy_render_lane() {
        let score = OriginScore::new(
            "https://down.example",
            EngineProbe::servo(false, 0.0, false, 900),
            EngineProbe::cdp(false, 0.0, false, 900),
        );
        let row = decide_lane(&score, CompatThresholds::default());

        assert_eq!(row.primary, None);
        assert_eq!(row.fallback, None);
        assert_eq!(row.reason, LaneReason::NoHealthyRenderLane);
        assert!(!row.servo_passed);
        assert!(!row.cdp_passed);
    }

    #[test]
    fn scorecard_emits_sorted_lane_table_and_rates() -> Result<(), String> {
        let scorecard = CompatScorecard::new(vec![
            OriginScore::new(
                "https://fallback.example",
                EngineProbe::servo(false, 0.0, false, 500),
                cdp_oracle(),
            ),
            healthy_origin("https://servo.example"),
            healthy_origin("https://mcp.example").structured_surface(StructuredSurface::Mcp),
            OriginScore::new(
                "https://challenge.example",
                EngineProbe::servo(true, 0.98, true, 90),
                cdp_oracle(),
            )
            .challenge_rate(0.42),
        ]);

        let table = scorecard.lane_table(CompatThresholds::default());
        assert_eq!(table.rows.len(), 4);
        assert_eq!(table.rows[0].origin, "https://challenge.example");
        assert_eq!(table.rows[1].origin, "https://fallback.example");
        assert_eq!(table.rows[2].origin, "https://mcp.example");
        assert_eq!(table.rows[3].origin, "https://servo.example");
        assert_close(table.fallback_rate, 2.0 / 4.0)?;
        assert_close(table.structured_rate, 1.0 / 4.0)?;
        assert_close(table.servo_rate, 1.0 / 4.0)?;
        assert_eq!(table.missing_primary_count, 0);
        assert_eq!(table.primary_lane_count(RuntimeLane::Servo), 1);
        assert_eq!(table.primary_lane_count(RuntimeLane::Cdp), 2);
        assert_eq!(table.primary_lane_count(RuntimeLane::Mcp), 1);
        assert_eq!(table.fallback_reason_count(LaneReason::ServoLoadFailed), 1);
        assert_eq!(
            table.fallback_reason_count(LaneReason::ChallengeRateHigh),
            1
        );
        assert_close(table.challenge_rate_threshold, 0.10)?;
        assert_close(table.max_challenge_rate, 0.42)?;
        assert_eq!(table.challenge_rate_exceeded_count, 1);
        assert_close(table.challenge_rate_exceeded_rate, 1.0 / 4.0)?;
        assert_eq!(
            table.row_for("https://mcp.example").map(|row| row.primary),
            Some(Some(RuntimeLane::Mcp))
        );
        Ok(())
    }

    #[test]
    fn compat_gate_reports_fallback_missing_lane_and_challenge_violations() {
        let table = LaneTable::new(vec![
            decide_lane(
                &OriginScore::new(
                    "https://fallback.example",
                    EngineProbe::servo(false, 0.0, false, 500),
                    cdp_oracle(),
                ),
                CompatThresholds::default(),
            ),
            decide_lane(
                &healthy_origin("https://challenge.example").challenge_rate(0.42),
                CompatThresholds::default(),
            ),
            decide_lane(
                &OriginScore::new(
                    "https://down.example",
                    EngineProbe::servo(false, 0.0, false, 900),
                    EngineProbe::cdp(false, 0.0, false, 900),
                ),
                CompatThresholds::default(),
            ),
        ]);
        let budget = CompatGateBudget {
            max_fallback_rate: 0.25,
            max_missing_primary_count: 0,
            max_challenge_rate_exceeded_rate: 0.25,
        };

        let report = run_compat_gate(&table, budget);

        assert!(!report.passed());
        assert_eq!(
            report.violations,
            vec![
                CompatGateViolation::FallbackRate {
                    observed: 2.0 / 3.0,
                    max: 0.25,
                },
                CompatGateViolation::MissingPrimaryLanes {
                    observed: 1,
                    max: 0,
                    origins: vec!["https://down.example".into()],
                },
                CompatGateViolation::ChallengeRateExceededRate {
                    observed: 1.0 / 3.0,
                    max: 0.25,
                    challenge_rate_threshold: 0.10,
                    origins: vec!["https://challenge.example".into()],
                },
            ]
        );
    }

    #[test]
    fn compat_artifact_io_round_trips_scorecard_lane_table_and_gate_report() -> Result<(), String> {
        let root = unique_dir("compat-artifacts");
        remove_dir_if_exists(&root).map_err(|error| error.to_string())?;
        std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let scorecard_path = root.join("scorecard.json");
        let lane_table_path = root.join("out").join("lanes.json");
        let gate_report_path = root.join("out").join("gate.json");
        let scorecard = CompatScorecard::new(vec![healthy_origin("https://servo.example")]);
        write_scorecard_fixture(&scorecard_path, &scorecard).map_err(|error| error.to_string())?;

        let loaded = read_compat_scorecard(&scorecard_path).map_err(|error| error.to_string())?;
        let table = loaded.lane_table(CompatThresholds::default());
        let report = table.gate_report(CompatGateBudget {
            max_fallback_rate: 0.0,
            ..CompatGateBudget::default()
        });

        write_lane_table(&lane_table_path, &table).map_err(|error| error.to_string())?;
        write_compat_gate_report(&gate_report_path, &report).map_err(|error| error.to_string())?;

        assert!(report.passed());
        let lane_bytes =
            std::fs::read_to_string(&lane_table_path).map_err(|error| error.to_string())?;
        let gate_bytes =
            std::fs::read_to_string(&gate_report_path).map_err(|error| error.to_string())?;
        assert!(lane_bytes.contains("\"servo_rate\""));
        assert!(gate_bytes.contains("\"violations\""));

        remove_dir_if_exists(&root).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn lane_table_reports_missing_lanes_as_ci_evidence() {
        let table = LaneTable::new(vec![LaneTableRow {
            origin: "https://down.example".to_string(),
            primary: None,
            fallback: None,
            reason: LaneReason::NoHealthyRenderLane,
            servo_passed: false,
            cdp_passed: false,
            servo_quality: 0.0,
            cdp_quality: 0.0,
            challenge_rate: 0.0,
        }]);

        assert_eq!(table.missing_primary_count, 1);
        assert_eq!(table.primary_lane_count(RuntimeLane::Servo), 0);
        assert_eq!(
            table.fallback_reason_count(LaneReason::NoHealthyRenderLane),
            0
        );
    }

    #[test]
    fn injection_gate_passes_confirmed_or_blocked_dangerous_effects() {
        let cases = [
            InjectionCaseResult::new("read", "https://example", SideEffect::Read),
            InjectionCaseResult::new("send", "https://example", SideEffect::Send).confirmed(),
            InjectionCaseResult::new("buy", "https://example", SideEffect::Purchase).blocked(),
        ];

        let report = run_injection_gate(&cases);
        assert!(report.passed());
        assert_eq!(report.total_cases, 3);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn injection_gate_flags_unconfirmed_dangerous_effects() {
        let cases = [
            InjectionCaseResult::new("draft", "https://example", SideEffect::Draft),
            InjectionCaseResult::new("send", "https://example", SideEffect::Send),
            InjectionCaseResult::new("delete", "https://example", SideEffect::Delete).confirmed(),
        ];

        let report = run_injection_gate(&cases);
        assert!(!report.passed());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].id, "send");
    }

    fn healthy_origin(origin: &str) -> OriginScore {
        OriginScore::new(
            origin,
            EngineProbe::servo(true, 0.96, true, 120),
            cdp_oracle(),
        )
    }

    fn cdp_oracle() -> EngineProbe {
        EngineProbe::cdp(true, 0.99, true, 160)
    }

    fn assert_close(actual: f32, expected: f32) -> Result<(), String> {
        if (actual - expected).abs() <= 0.0001 {
            Ok(())
        } else {
            Err(format!("expected {expected}, got {actual}"))
        }
    }

    fn unique_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("tempo-compat-{name}-{nanos}"))
    }

    fn remove_dir_if_exists(path: &std::path::Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn write_scorecard_fixture(
        path: &std::path::Path,
        scorecard: &CompatScorecard,
    ) -> Result<(), serde_json::Error> {
        let file = std::fs::File::create(path).map_err(serde_json::Error::io)?;
        serde_json::to_writer_pretty(file, scorecard)
    }
}
