//! tempo-cli - command-line entry points for tempo artifacts.
//!
//! The binary intentionally exposes only operations backed by implemented crates:
//! schema emission, eval scorecards, session journal adaptation, compat lane
//! tables, and replay summaries.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tempo_compat::{CompatScorecard, CompatThresholds};
use tempo_evals::{
    eval_record_from_session_journal, read_eval_records, write_scorecard, EvalBudget, EvalError,
    Lane, Scorecard, SessionEvalDescriptor,
};
use tempo_session::{read_journal_entries, JournalEntry, JournalError, JournalEvent};
use thiserror::Error;

const USAGE: &str = "\
tempo-cli

Commands:
  schema [--output PATH]
  scorecard --input PATH [--output PATH] [--allow-missing-speculation]
            [--min-success-rate N] [--max-fallback-rate N]
  session-eval --journal PATH --suite NAME --case-id ID --origin URL
            --lane api|servo|cdp --success BOOL --fallback-used BOOL
            [--baseline-wall-clock-ms N] [--unconfirmed-high-risk-actions N]
            [--output PATH]
  compat-lanes --input PATH [--output PATH]
            [--min-observation-quality N] [--max-challenge-rate N]
  replay --journal PATH [--output PATH]
";

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();

    match run_with_writer(env::args().skip(1), &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run_with_writer<I, S>(args: I, stdout: &mut dyn Write) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Command::parse(args)?.execute(stdout)
}

#[derive(Debug, PartialEq)]
enum Command {
    Help,
    Schema {
        output: Output,
    },
    Scorecard {
        input: PathBuf,
        output: Output,
        budget: EvalBudget,
    },
    SessionEval {
        journal: PathBuf,
        descriptor: SessionEvalDescriptor,
        output: Output,
    },
    CompatLanes {
        input: PathBuf,
        output: Output,
        thresholds: CompatThresholds,
    },
    Replay {
        journal: PathBuf,
        output: Output,
    },
}

impl Command {
    fn parse<I, S>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let Some((command, options)) = args.split_first() else {
            return Ok(Self::Help);
        };

        match command.as_str() {
            "-h" | "--help" | "help" => Ok(Self::Help),
            "schema" => parse_schema(options),
            "scorecard" => parse_scorecard(options),
            "session-eval" => parse_session_eval(options),
            "compat-lanes" => parse_compat_lanes(options),
            "replay" => parse_replay(options),
            other => Err(CliError::Usage(format!(
                "unknown command: {other}\n\n{USAGE}"
            ))),
        }
    }

    fn execute(self, stdout: &mut dyn Write) -> Result<(), CliError> {
        match self {
            Self::Help => {
                stdout.write_all(USAGE.as_bytes())?;
                Ok(())
            }
            Self::Schema { output } => {
                let schema = tempo_schema::schema_bundle_json_schema();
                write_json(&output, &schema, stdout)
            }
            Self::Scorecard {
                input,
                output,
                budget,
            } => {
                let records = read_eval_records(&input)?;
                let scorecard = Scorecard::from_records(&records, &budget)?;
                match &output {
                    Output::Stdout => write_json(&output, &scorecard, stdout)?,
                    Output::Path(path) => write_scorecard(path, &scorecard)?,
                }
                if scorecard.passes() {
                    Ok(())
                } else {
                    Err(CliError::GateFailed {
                        violations: scorecard.violations.len(),
                    })
                }
            }
            Self::SessionEval {
                journal,
                descriptor,
                output,
            } => {
                let record = eval_record_from_session_journal(journal, descriptor)?;
                write_json(&output, &record, stdout)
            }
            Self::CompatLanes {
                input,
                output,
                thresholds,
            } => {
                let scorecard: CompatScorecard = read_json(&input)?;
                let lane_table = scorecard.lane_table(thresholds);
                write_json(&output, &lane_table, stdout)
            }
            Self::Replay { journal, output } => {
                let entries = read_journal_entries(&journal)?;
                let summary = ReplaySummary::from_entries(&journal, &entries);
                write_json(&output, &summary, stdout)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Output {
    Stdout,
    Path(PathBuf),
}

fn parse_schema(options: &[String]) -> Result<Command, CliError> {
    let mut output = Output::Stdout;
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--output" => output = Output::Path(PathBuf::from(take_value(options, &mut index)?)),
            "-h" | "--help" => return Ok(Command::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }
    Ok(Command::Schema { output })
}

fn parse_scorecard(options: &[String]) -> Result<Command, CliError> {
    let mut input = None;
    let mut output = Output::Stdout;
    let mut budget = EvalBudget::default();
    let mut index = 0;

    while index < options.len() {
        match options[index].as_str() {
            "--input" => input = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--output" => output = Output::Path(PathBuf::from(take_value(options, &mut index)?)),
            "--allow-missing-speculation" => budget.min_speculation_reduction = None,
            "--min-success-rate" => {
                budget.min_success_rate =
                    parse_f64("--min-success-rate", take_value(options, &mut index)?)?;
            }
            "--max-fallback-rate" => {
                budget.max_fallback_rate =
                    parse_f64("--max-fallback-rate", take_value(options, &mut index)?)?;
            }
            "-h" | "--help" => return Ok(Command::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    Ok(Command::Scorecard {
        input: required_path("--input", input)?,
        output,
        budget,
    })
}

fn parse_session_eval(options: &[String]) -> Result<Command, CliError> {
    let mut journal = None;
    let mut suite = None;
    let mut case_id = None;
    let mut origin = None;
    let mut lane = None;
    let mut success = None;
    let mut fallback_used = None;
    let mut baseline_wall_clock_ms = None;
    let mut unconfirmed_high_risk_actions = 0;
    let mut output = Output::Stdout;
    let mut index = 0;

    while index < options.len() {
        match options[index].as_str() {
            "--journal" => journal = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--suite" => suite = Some(take_value(options, &mut index)?),
            "--case-id" => case_id = Some(take_value(options, &mut index)?),
            "--origin" => origin = Some(take_value(options, &mut index)?),
            "--lane" => lane = Some(parse_lane(take_value(options, &mut index)?)?),
            "--success" => {
                success = Some(parse_bool("--success", take_value(options, &mut index)?)?)
            }
            "--fallback-used" => {
                fallback_used = Some(parse_bool(
                    "--fallback-used",
                    take_value(options, &mut index)?,
                )?);
            }
            "--baseline-wall-clock-ms" => {
                baseline_wall_clock_ms = Some(parse_u64(
                    "--baseline-wall-clock-ms",
                    take_value(options, &mut index)?,
                )?);
            }
            "--unconfirmed-high-risk-actions" => {
                unconfirmed_high_risk_actions = parse_u64(
                    "--unconfirmed-high-risk-actions",
                    take_value(options, &mut index)?,
                )?;
            }
            "--output" => output = Output::Path(PathBuf::from(take_value(options, &mut index)?)),
            "-h" | "--help" => return Ok(Command::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    Ok(Command::SessionEval {
        journal: required_path("--journal", journal)?,
        descriptor: SessionEvalDescriptor {
            suite: required_string("--suite", suite)?,
            case_id: required_string("--case-id", case_id)?,
            origin: required_string("--origin", origin)?,
            lane: required_value("--lane", lane)?,
            success: required_value("--success", success)?,
            fallback_used: required_value("--fallback-used", fallback_used)?,
            baseline_wall_clock_ms,
            unconfirmed_high_risk_actions,
        },
        output,
    })
}

fn parse_compat_lanes(options: &[String]) -> Result<Command, CliError> {
    let mut input = None;
    let mut output = Output::Stdout;
    let mut thresholds = CompatThresholds::default();
    let mut index = 0;

    while index < options.len() {
        match options[index].as_str() {
            "--input" => input = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--output" => output = Output::Path(PathBuf::from(take_value(options, &mut index)?)),
            "--min-observation-quality" => {
                thresholds.min_observation_quality = parse_f32(
                    "--min-observation-quality",
                    take_value(options, &mut index)?,
                )?;
            }
            "--max-challenge-rate" => {
                thresholds.max_challenge_rate =
                    parse_f32("--max-challenge-rate", take_value(options, &mut index)?)?;
            }
            "-h" | "--help" => return Ok(Command::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    Ok(Command::CompatLanes {
        input: required_path("--input", input)?,
        output,
        thresholds,
    })
}

fn parse_replay(options: &[String]) -> Result<Command, CliError> {
    let mut journal = None;
    let mut output = Output::Stdout;
    let mut index = 0;

    while index < options.len() {
        match options[index].as_str() {
            "--journal" => journal = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--output" => output = Output::Path(PathBuf::from(take_value(options, &mut index)?)),
            "-h" | "--help" => return Ok(Command::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    Ok(Command::Replay {
        journal: required_path("--journal", journal)?,
        output,
    })
}

fn take_value(options: &[String], index: &mut usize) -> Result<String, CliError> {
    let flag = options[*index].clone();
    *index += 1;
    options
        .get(*index)
        .cloned()
        .ok_or_else(|| CliError::Usage(format!("missing value for {flag}\n\n{USAGE}")))
}

fn required_path(flag: &'static str, value: Option<PathBuf>) -> Result<PathBuf, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required {flag}\n\n{USAGE}")))
}

fn required_string(flag: &'static str, value: Option<String>) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required {flag}\n\n{USAGE}")))
}

fn required_value<T>(flag: &'static str, value: Option<T>) -> Result<T, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required {flag}\n\n{USAGE}")))
}

fn unknown_flag(flag: &str) -> CliError {
    CliError::Usage(format!("unknown flag: {flag}\n\n{USAGE}"))
}

fn parse_bool(flag: &'static str, value: String) -> Result<bool, CliError> {
    match value.as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(CliError::InvalidValue { flag, value }),
    }
}

fn parse_lane(value: String) -> Result<Lane, CliError> {
    match value.as_str() {
        "api" => Ok(Lane::Api),
        "servo" => Ok(Lane::Servo),
        "cdp" => Ok(Lane::Cdp),
        _ => Err(CliError::InvalidValue {
            flag: "--lane",
            value,
        }),
    }
}

fn parse_f64(flag: &'static str, value: String) -> Result<f64, CliError> {
    value
        .parse()
        .map_err(|_| CliError::InvalidValue { flag, value })
}

fn parse_f32(flag: &'static str, value: String) -> Result<f32, CliError> {
    value
        .parse()
        .map_err(|_| CliError::InvalidValue { flag, value })
}

fn parse_u64(flag: &'static str, value: String) -> Result<u64, CliError> {
    value
        .parse()
        .map_err(|_| CliError::InvalidValue { flag, value })
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let file = File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_reader(file).map_err(|source| CliError::JsonRead {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json<T: Serialize>(
    output: &Output,
    value: &T,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    match output {
        Output::Stdout => {
            serde_json::to_writer_pretty(&mut *stdout, value)?;
            stdout.write_all(b"\n")?;
        }
        Output::Path(path) => {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).map_err(|source| CliError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            let file = File::create(path).map_err(|source| CliError::Io {
                path: path.clone(),
                source,
            })?;
            serde_json::to_writer_pretty(file, value).map_err(|source| CliError::JsonWrite {
                path: path.clone(),
                source,
            })?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ReplaySummary {
    journal: String,
    entries: usize,
    last_seq: Option<u64>,
    session_started: bool,
    session_closed: bool,
    observations: usize,
    planned_actions: usize,
    applied_steps: usize,
    step_errors: usize,
    transport_errors: usize,
    cassettes: usize,
}

impl ReplaySummary {
    fn from_entries(path: &Path, entries: &[JournalEntry]) -> Self {
        let mut summary = Self {
            journal: path.display().to_string(),
            entries: entries.len(),
            last_seq: entries.last().map(|entry| entry.seq),
            session_started: false,
            session_closed: false,
            observations: 0,
            planned_actions: 0,
            applied_steps: 0,
            step_errors: 0,
            transport_errors: 0,
            cassettes: 0,
        };

        for entry in entries {
            match &entry.event {
                JournalEvent::SessionStarted { .. } => summary.session_started = true,
                JournalEvent::Observation { .. } => summary.observations += 1,
                JournalEvent::ActionPlanned { .. } => summary.planned_actions += 1,
                JournalEvent::StepApplied { .. } => summary.applied_steps += 1,
                JournalEvent::StepError { .. } => summary.step_errors += 1,
                JournalEvent::TransportError { .. } => summary.transport_errors += 1,
                JournalEvent::CassetteRecorded { .. } => summary.cassettes += 1,
                JournalEvent::SessionClosed => summary.session_closed = true,
            }
        }

        summary
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("file I/O failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("JSON parse failed at {path:?}: {source}")]
    JsonRead {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("JSON write failed at {path:?}: {source}")]
    JsonWrite {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("eval operation failed: {0}")]
    Eval(#[from] EvalError),
    #[error("journal operation failed: {0}")]
    Journal(#[from] JournalError),
    #[error("scorecard gate failed with {violations} violation(s)")]
    GateFailed { violations: usize },
    #[error("invalid value for {flag}: {value}")]
    InvalidValue { flag: &'static str, value: String },
}

impl From<io::Error> for CliError {
    fn from(source: io::Error) -> Self {
        Self::Io {
            path: PathBuf::from("<stdio>"),
            source,
        }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(source: serde_json::Error) -> Self {
        Self::JsonWrite {
            path: PathBuf::from("<stdout>"),
            source,
        }
    }
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::InvalidValue { .. } => 2,
            Self::GateFailed { .. }
            | Self::Io { .. }
            | Self::JsonRead { .. }
            | Self::JsonWrite { .. }
            | Self::Eval(_)
            | Self::Journal(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::error::Error;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_compat::{EngineProbe, OriginScore};
    use tempo_schema::{
        Action, CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance,
        TaintSpan, SCHEMA_VERSION,
    };
    use tempo_session::{RunId, SessionId, SessionJournal};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn schema_command_writes_schema_bundle_to_stdout() -> TestResult {
        let mut stdout = Vec::new();

        run_with_writer(["schema"], &mut stdout)?;

        let value: Value = serde_json::from_slice(&stdout)?;
        assert_eq!(value["title"], "tempo C1/C2 schema bundle");
        Ok(())
    }

    #[test]
    fn scorecard_command_reads_records_and_writes_gate_output() -> TestResult {
        let dir = unique_dir("scorecard")?;
        let input = dir.join("records.jsonl");
        let output = dir.join("scorecard.json");
        write_records(
            &input,
            &[EvalRecordBuilder::new("case-a")
                .success(true)
                .baseline_wall_clock_ms(2_000)
                .wall_clock_ms(1_000)
                .build()],
        )?;
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "scorecard".to_string(),
                "--input".into(),
                input_string(&input),
                "--output".into(),
                input_string(&output),
            ],
            &mut stdout,
        )?;

        let scorecard: Scorecard = serde_json::from_reader(File::open(&output)?)?;
        assert!(stdout.is_empty());
        assert_eq!(scorecard.total_cases, 1);
        assert!(scorecard.passes());
        remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn scorecard_command_writes_then_reports_gate_failures() -> TestResult {
        let dir = unique_dir("scorecard-fail")?;
        let input = dir.join("records.jsonl");
        let output = dir.join("scorecard.json");
        write_records(
            &input,
            &[EvalRecordBuilder::new("case-a").success(false).build()],
        )?;
        let mut stdout = Vec::new();

        let result = run_with_writer(
            [
                "scorecard".to_string(),
                "--input".into(),
                input_string(&input),
                "--output".into(),
                input_string(&output),
                "--allow-missing-speculation".into(),
                "--min-success-rate".into(),
                "1.0".into(),
            ],
            &mut stdout,
        );

        match result {
            Err(CliError::GateFailed { violations }) => assert_eq!(violations, 1),
            other => return Err(unexpected_result(other)),
        }
        assert!(output.exists());
        remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn compat_lanes_command_reads_scorecard_and_writes_lane_table() -> TestResult {
        let dir = unique_dir("compat")?;
        let input = dir.join("compat.json");
        let output = dir.join("lanes.json");
        let scorecard = CompatScorecard::new(vec![
            OriginScore::new(
                "https://fallback.test",
                EngineProbe::servo(false, 0.0, false, 200),
                EngineProbe::cdp(true, 0.99, true, 120),
            ),
            OriginScore::new(
                "https://servo.test",
                EngineProbe::servo(true, 0.99, true, 100),
                EngineProbe::cdp(true, 0.99, true, 120),
            ),
        ]);
        write_json_file(&input, &scorecard)?;
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "compat-lanes".to_string(),
                "--input".into(),
                input_string(&input),
                "--output".into(),
                input_string(&output),
            ],
            &mut stdout,
        )?;

        let value: Value = serde_json::from_reader(File::open(&output)?)?;
        assert_eq!(value["fallback_rate"], 0.5);
        assert_eq!(value["rows"][0]["primary"], "cdp");
        remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn session_eval_command_adapts_real_journal() -> TestResult {
        let dir = unique_dir("session-eval")?;
        let journal = dir.join("session.jsonl");
        let output = dir.join("record.json");
        write_journal(&journal)?;
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "session-eval".to_string(),
                "--journal".into(),
                input_string(&journal),
                "--suite".into(),
                "journal".into(),
                "--case-id".into(),
                "case-a".into(),
                "--origin".into(),
                "https://session.test".into(),
                "--lane".into(),
                "servo".into(),
                "--success".into(),
                "true".into(),
                "--fallback-used".into(),
                "false".into(),
                "--output".into(),
                input_string(&output),
            ],
            &mut stdout,
        )?;

        let record: tempo_evals::EvalRecord = serde_json::from_reader(File::open(&output)?)?;
        assert_eq!(record.suite, "journal");
        assert_eq!(record.step_count, 1);
        assert!(record.max_observation_bytes > 0);
        remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn replay_command_summarizes_journal_events() -> TestResult {
        let dir = unique_dir("replay")?;
        let journal = dir.join("session.jsonl");
        write_journal(&journal)?;
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "replay".to_string(),
                "--journal".into(),
                input_string(&journal),
            ],
            &mut stdout,
        )?;

        let value: Value = serde_json::from_slice(&stdout)?;
        assert_eq!(value["entries"], 5);
        assert_eq!(value["session_started"], true);
        assert_eq!(value["session_closed"], true);
        assert_eq!(value["applied_steps"], 1);
        remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn command_parse_rejects_unknown_flags() -> TestResult {
        let result = run_with_writer(["schema", "--bad"], &mut Vec::new());

        match result {
            Err(CliError::Usage(message)) => assert!(message.contains("unknown flag")),
            other => return Err(unexpected_result(other)),
        }
        Ok(())
    }

    struct EvalRecordBuilder {
        record: tempo_evals::EvalRecord,
    }

    impl EvalRecordBuilder {
        fn new(case_id: &str) -> Self {
            Self {
                record: tempo_evals::EvalRecord {
                    suite: "suite".into(),
                    case_id: case_id.into(),
                    origin: "https://eval.test".into(),
                    lane: Lane::Servo,
                    success: true,
                    fallback_used: false,
                    max_observation_bytes: 512,
                    max_observation_tokens: 128,
                    observe_latency_ms: 20,
                    action_latency_ms: 30,
                    wall_clock_ms: 100,
                    baseline_wall_clock_ms: None,
                    unconfirmed_high_risk_actions: 0,
                    step_count: 1,
                },
            }
        }

        fn success(mut self, success: bool) -> Self {
            self.record.success = success;
            self
        }

        fn wall_clock_ms(mut self, wall_clock_ms: u64) -> Self {
            self.record.wall_clock_ms = wall_clock_ms;
            self
        }

        fn baseline_wall_clock_ms(mut self, baseline_wall_clock_ms: u64) -> Self {
            self.record.baseline_wall_clock_ms = Some(baseline_wall_clock_ms);
            self
        }

        fn build(self) -> tempo_evals::EvalRecord {
            self.record
        }
    }

    fn write_records(path: &Path, records: &[tempo_evals::EvalRecord]) -> TestResult {
        let mut file = File::create(path)?;
        for record in records {
            serde_json::to_writer(&mut file, record)?;
            writeln!(file)?;
        }
        Ok(())
    }

    fn write_json_file<T: Serialize>(path: &Path, value: &T) -> TestResult {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, value)?;
        Ok(())
    }

    fn write_journal(path: &Path) -> TestResult {
        let mut journal =
            SessionJournal::open(path, RunId("run-a".into()), SessionId("session-a".into()))?;
        let action = Action::Scroll { x: 0.0, y: 10.0 };
        journal.append(JournalEvent::SessionStarted {
            url: "https://session.test".into(),
        })?;
        journal.append(JournalEvent::Observation {
            observation: observation(0),
        })?;
        journal.append(JournalEvent::ActionPlanned {
            action: action.clone(),
        })?;
        journal.append(JournalEvent::StepApplied {
            action,
            diff: ObservationDiff {
                since_seq: 0,
                seq: 1,
                added: Vec::new(),
                removed: Vec::new(),
                changed: Vec::new(),
            },
        })?;
        journal.append(JournalEvent::SessionClosed)?;
        Ok(())
    }

    fn observation(seq: u64) -> CompiledObservation {
        CompiledObservation {
            schema_version: SCHEMA_VERSION.into(),
            url: "https://session.test".into(),
            seq,
            elements: vec![InteractiveElement {
                node_id: NodeId("button:submit".into()),
                role: "button".into(),
                name: vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: "Submit".into(),
                }],
                value: Vec::new(),
                bounds: None,
                rank: 1.0,
            }],
            marks: Vec::new(),
        }
    }

    fn unique_dir(prefix: &str) -> Result<PathBuf, io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path =
            env::temp_dir().join(format!("tempo-cli-{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn remove_dir(path: &Path) -> Result<(), io::Error> {
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
        Ok(())
    }

    fn input_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn unexpected_result(result: Result<(), CliError>) -> Box<dyn Error> {
        Box::new(io::Error::other(format!("unexpected result: {result:?}")))
    }
}
