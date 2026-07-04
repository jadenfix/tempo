//! Model-backed deciding for the durable agent loop (#248).
//!
//! The scripted runner in `lib.rs` executes a pre-supplied plan; this module
//! adds the `Decider` seam so the observe → decide → act loop can ask a model
//! for its next action batch. Two implementations exist and are the whole
//! abstraction: [`ScriptedDecider`] (pre-supplied batches; the default,
//! hermetic test path) and [`AnthropicDecider`] (a thin Messages-API client —
//! no SDK).
//!
//! Durability contract:
//! * every decision is journaled (`JournalEvent::ModelDecision`) *before* any
//!   of its actions execute (journal-before-effect, #99), so resume re-uses a
//!   journaled-but-unexecuted decision instead of re-inferring it;
//! * model token usage — including `cache_read_input_tokens` — is journaled
//!   per decision so prompt-cache hit rate is observable (#218);
//! * actual usage is charged against the run [`TokenBudget`]; hitting the
//!   ceiling is a typed, journal-derived stop, never a panic.

use crate::{
    is_policy_denial_reason, policy_denied_reason, read_body_capped, AgentError, AgentRunner,
    CappedBodyError, DriverStep, IdempotencyKey, TokenBudget, RESUME_INTERRUPTED_REASON,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Duration;
use tempo_act::{detect_human_takeover, execute_action, ExecutionStatus};
use tempo_driver::{DriverTrait, TransportError};
use tempo_policy::Origin;
use tempo_schema::{Action, CompiledObservation, HumanTakeover, ObservationDiff};
use tempo_session::{read_journal_entries, JournalEntry, JournalEvent, SessionJournal};
use thiserror::Error;

/// Default model for [`AnthropicDecider`].
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-5";

/// Default Messages-API origin for [`AnthropicDecider`].
pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// Hard cap on a model HTTP response body, mirroring the `max_body_bytes`
/// pattern from the MCP client (#212/#215): a hostile or broken endpoint must
/// not be able to exhaust memory by streaming an unbounded body.
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// Default ceiling on decide rounds per run, bounding a looping model.
pub const DEFAULT_MAX_DECISION_ROUNDS: usize = 16;

const ANTHROPIC_VERSION: &str = "2023-06-01";
const DECIDE_TOOL_NAME: &str = "decide_actions";
const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 2048;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_RETRIES: u32 = 2;
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(250);
const MAX_API_ERROR_DETAIL_BYTES: usize = 512;

/// Provider token usage for one decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionUsage {
    /// Uncached input tokens billed for the request.
    pub input_tokens: u64,
    /// Output tokens billed for the request.
    pub output_tokens: u64,
    /// Input tokens served from the provider prompt cache (#218 observability).
    pub cache_read_input_tokens: u64,
}

impl DecisionUsage {
    /// Total tokens the model processed for this decision; this is what the
    /// run token budget is charged.
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_read_input_tokens)
            .saturating_add(self.output_tokens)
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_add(other.input_tokens),
            output_tokens: self.output_tokens.saturating_add(other.output_tokens),
            cache_read_input_tokens: self
                .cache_read_input_tokens
                .saturating_add(other.cache_read_input_tokens),
        }
    }
}

/// Everything one decide step may condition on: the run goal and action
/// schemas (stable prefix), the compiled observation (volatile tail), and the
/// remaining budget.
#[derive(Debug)]
pub struct DecisionRequest<'a> {
    /// Natural-language goal for the run. Stable across steps of one run.
    pub goal: &'a str,
    /// JSON Schema for one `Action`. Stable across steps.
    pub action_schema: &'a serde_json::Value,
    /// Latest compiled observation. Volatile; changes every step.
    pub observation: &'a CompiledObservation,
    /// Tokens the run may still spend.
    pub budget_remaining: u64,
}

/// One decided action batch. An empty `actions` vector means the decider
/// considers the goal complete.
#[derive(Clone, Debug, PartialEq)]
pub struct DecidedBatch {
    /// Actions to execute next, in order.
    pub actions: Vec<Action>,
    /// Optional model-provided reason for this batch.
    pub rationale: Option<String>,
    /// Provider token usage for producing this decision.
    pub usage: DecisionUsage,
}

/// The decide step of observe → decide → act.
#[async_trait]
pub trait Decider {
    /// Produce the next action batch for `request`. Returning an empty batch
    /// signals the task is complete.
    async fn decide(&mut self, request: &DecisionRequest<'_>)
        -> Result<DecidedBatch, DeciderError>;
}

/// Pre-supplied batches, returned in order; the default decider for tests and
/// scripted runs. Once the script is exhausted it reports completion.
#[derive(Clone, Debug, Default)]
pub struct ScriptedDecider {
    batches: VecDeque<Vec<Action>>,
}

impl ScriptedDecider {
    /// Queue `batches` to be returned by successive `decide` calls.
    pub fn new(batches: Vec<Vec<Action>>) -> Self {
        Self {
            batches: batches.into(),
        }
    }
}

#[async_trait]
impl Decider for ScriptedDecider {
    async fn decide(
        &mut self,
        _request: &DecisionRequest<'_>,
    ) -> Result<DecidedBatch, DeciderError> {
        Ok(DecidedBatch {
            actions: self.batches.pop_front().unwrap_or_default(),
            rationale: None,
            usage: DecisionUsage::default(),
        })
    }
}

/// Typed decider failures. Malformed model output and transport failures are
/// retried up to the configured bound before surfacing here.
#[derive(Debug, Error)]
pub enum DeciderError {
    /// The decider was misconfigured (missing API key, bad base URL, …).
    #[error("decider configuration invalid: {0}")]
    Config(String),
    /// The HTTP transport failed on every attempt.
    #[error("model transport failed after {attempts} attempt(s): {reason}")]
    Transport {
        /// Attempts made, including the first.
        attempts: u32,
        /// Last transport failure.
        reason: String,
    },
    /// The Messages API returned a non-success status.
    #[error("model API returned HTTP {status}: {detail}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Truncated response body.
        detail: String,
    },
    /// The response body exceeded the configured size cap (#215 pattern).
    #[error("model response body exceeded {max_bytes} bytes")]
    ResponseTooLarge {
        /// Configured cap in bytes.
        max_bytes: usize,
    },
    /// The model output did not parse into a decision on any attempt.
    #[error("model produced a malformed decision after {attempts} attempt(s): {reason}")]
    MalformedDecision {
        /// Attempts made, including the first.
        attempts: u32,
        /// Last parse failure.
        reason: String,
    },
}

/// Configuration for [`AnthropicDecider`]. Model, API key, and base URL come
/// from the environment via [`AnthropicConfig::from_env`] or from builders.
#[derive(Clone, Debug)]
pub struct AnthropicConfig {
    /// `x-api-key` value (`ANTHROPIC_API_KEY`).
    pub api_key: String,
    /// Model id; defaults to [`DEFAULT_ANTHROPIC_MODEL`].
    pub model: String,
    /// API origin; defaults to [`DEFAULT_ANTHROPIC_BASE_URL`].
    pub base_url: String,
    /// `max_tokens` per decision response.
    pub max_output_tokens: u64,
    /// Response body size cap (see [`DEFAULT_MAX_RESPONSE_BODY_BYTES`]).
    pub max_body_bytes: usize,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Retries after the first attempt for transport/429/5xx/malformed output.
    pub max_retries: u32,
    /// Base backoff between attempts (doubled per retry).
    pub retry_backoff: Duration,
}

impl AnthropicConfig {
    /// A config with defaults and the given API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: DEFAULT_ANTHROPIC_MODEL.into(),
            base_url: DEFAULT_ANTHROPIC_BASE_URL.into(),
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            max_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_backoff: DEFAULT_RETRY_BACKOFF,
        }
    }

    /// Read `ANTHROPIC_API_KEY` (required) plus optional `ANTHROPIC_MODEL`
    /// and `ANTHROPIC_BASE_URL` overrides.
    pub fn from_env() -> Result<Self, DeciderError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| DeciderError::Config("ANTHROPIC_API_KEY is not set".into()))?;
        let mut config = Self::new(api_key);
        if let Ok(model) = std::env::var("ANTHROPIC_MODEL") {
            config.model = model;
        }
        if let Ok(base_url) = std::env::var("ANTHROPIC_BASE_URL") {
            config.base_url = base_url;
        }
        Ok(config)
    }

    /// Override the model id.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Override the API origin (used by tests to point at a local fixture).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Override the response body cap.
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Override the retry bound.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Override the base retry backoff.
    pub fn with_retry_backoff(mut self, retry_backoff: Duration) -> Self {
        self.retry_backoff = retry_backoff;
        self
    }
}

/// Thin Anthropic Messages-API decider over the crate's existing `reqwest`
/// dependency. Decisions use a forced `decide_actions` tool call so the model
/// output parses deterministically; the prompt keeps a byte-stable
/// tools + system prefix (with a `cache_control` breakpoint) and puts the
/// volatile observation last, per the #218 cache-alignment principle.
pub struct AnthropicDecider {
    config: AnthropicConfig,
    client: reqwest::Client,
}

impl AnthropicDecider {
    /// Build a decider from `config`. Fails on an empty API key or a broken
    /// TLS/client setup.
    pub fn new(config: AnthropicConfig) -> Result<Self, DeciderError> {
        if config.api_key.trim().is_empty() {
            return Err(DeciderError::Config("API key is empty".into()));
        }
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| DeciderError::Config(error.to_string()))?;
        Ok(Self { config, client })
    }

    async fn attempt_decide(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> Result<DecidedBatch, AttemptError> {
        let response = self
            .client
            .post(endpoint)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await
            .map_err(|error| AttemptError::Retryable(Failure::Transport(error.to_string())))?;

        let status = response.status();
        let text = read_body_capped(response, self.config.max_body_bytes)
            .await
            .map_err(|error| match error {
                CappedBodyError::TooLarge { max_bytes } => {
                    AttemptError::Fatal(DeciderError::ResponseTooLarge { max_bytes })
                }
                CappedBodyError::Transport(reason) => {
                    AttemptError::Retryable(Failure::Transport(reason))
                }
            })?;

        if !status.is_success() {
            let detail = truncate_detail(&text);
            let api_failure = Failure::Api {
                status: status.as_u16(),
                detail: detail.clone(),
            };
            return if status.as_u16() == 429 || status.as_u16() == 408 || status.is_server_error() {
                Err(AttemptError::Retryable(api_failure))
            } else {
                Err(AttemptError::Fatal(DeciderError::Api {
                    status: status.as_u16(),
                    detail,
                }))
            };
        }

        let response = serde_json::from_str::<serde_json::Value>(&text).map_err(|error| {
            AttemptError::Retryable(Failure::Malformed(format!("response is not JSON: {error}")))
        })?;
        parse_decided_batch(&response)
            .map_err(|reason| AttemptError::Retryable(Failure::Malformed(reason)))
    }
}

#[async_trait]
impl Decider for AnthropicDecider {
    async fn decide(
        &mut self,
        request: &DecisionRequest<'_>,
    ) -> Result<DecidedBatch, DeciderError> {
        let body = decide_request_body(&self.config, request)?;
        let endpoint = format!("{}/v1/messages", self.config.base_url.trim_end_matches('/'));

        let max_attempts = self.config.max_retries.saturating_add(1).max(1);
        let mut last_failure = Failure::Transport("no attempt was made".into());
        for attempt in 1..=max_attempts {
            if attempt > 1 && !self.config.retry_backoff.is_zero() {
                let exponent = (attempt - 2).min(8);
                tokio::time::sleep(self.config.retry_backoff.saturating_mul(1 << exponent)).await;
            }
            match self.attempt_decide(&endpoint, &body).await {
                Ok(batch) => return Ok(batch),
                Err(AttemptError::Fatal(error)) => return Err(error),
                Err(AttemptError::Retryable(failure)) => last_failure = failure,
            }
        }
        Err(match last_failure {
            Failure::Transport(reason) => DeciderError::Transport {
                attempts: max_attempts,
                reason,
            },
            Failure::Api { status, detail } => DeciderError::Api { status, detail },
            Failure::Malformed(reason) => DeciderError::MalformedDecision {
                attempts: max_attempts,
                reason,
            },
        })
    }
}

enum AttemptError {
    Fatal(DeciderError),
    Retryable(Failure),
}

enum Failure {
    Transport(String),
    Api { status: u16, detail: String },
    Malformed(String),
}

fn truncate_detail(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= MAX_API_ERROR_DETAIL_BYTES {
        return trimmed.to_string();
    }
    let mut end = MAX_API_ERROR_DETAIL_BYTES;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &trimmed[..end])
}

fn decider_system_text(goal: &str) -> String {
    format!(
        "You drive a web browser through the structured tempo action space.\n\
         Decide the next batch of actions that makes progress toward the goal, \
         using only NodeIds present in the current observation. Call the \
         `decide_actions` tool exactly once per turn. When the goal is complete, \
         set `done` to true and return an empty `actions` array.\n\nGoal: {goal}"
    )
}

fn decide_tool(action_schema: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "name": DECIDE_TOOL_NAME,
        "description": "Report the next batch of browser actions to execute, or completion.",
        "input_schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "done": {
                    "type": "boolean",
                    "description": "True when the goal is complete and no further actions are needed."
                },
                "rationale": {
                    "type": "string",
                    "description": "Brief reason for this decision."
                },
                "actions": {
                    "type": "array",
                    "description": "Actions to execute next, in order. Empty when done.",
                    "items": action_schema
                }
            },
            "required": ["done", "actions"]
        }
    })
}

/// Builds the Messages-API request. Prompt-cache alignment (#218): the
/// provider renders `tools` → `system` → `messages`, and the `cache_control`
/// breakpoint on the system block caches the tools + system prefix, which is
/// byte-stable across every step of a run (goal and schemas do not change).
/// The volatile observation and remaining budget appear only in the final
/// user message, after the cached prefix.
fn decide_request_body(
    config: &AnthropicConfig,
    request: &DecisionRequest<'_>,
) -> Result<serde_json::Value, DeciderError> {
    let observation = serde_json::to_string(request.observation).map_err(|error| {
        DeciderError::Config(format!("observation failed to serialize: {error}"))
    })?;
    Ok(serde_json::json!({
        "model": config.model,
        "max_tokens": config.max_output_tokens,
        "system": [{
            "type": "text",
            "text": decider_system_text(request.goal),
            "cache_control": { "type": "ephemeral" }
        }],
        "tools": [decide_tool(request.action_schema)],
        "tool_choice": { "type": "tool", "name": DECIDE_TOOL_NAME },
        // Forced tool choice wants a plain structured decision, not thinking.
        "thinking": { "type": "disabled" },
        "messages": [{
            "role": "user",
            "content": [{
                "type": "text",
                "text": format!(
                    "Current observation (volatile, latest page state):\n{observation}\n\n\
                     Remaining run token budget: {}",
                    request.budget_remaining
                )
            }]
        }]
    }))
}

fn parse_decided_batch(response: &serde_json::Value) -> Result<DecidedBatch, String> {
    let content = response
        .get("content")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "response missing content array".to_string())?;
    let tool_use = content
        .iter()
        .find(|block| {
            block.get("type").and_then(serde_json::Value::as_str) == Some("tool_use")
                && block.get("name").and_then(serde_json::Value::as_str) == Some(DECIDE_TOOL_NAME)
        })
        .ok_or_else(|| {
            format!(
                "response has no {DECIDE_TOOL_NAME} tool_use block (stop_reason: {})",
                response
                    .get("stop_reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
            )
        })?;
    let input = tool_use
        .get("input")
        .ok_or_else(|| "tool_use block missing input".to_string())?;
    let done = input
        .get("done")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "decision missing boolean `done`".to_string())?;
    let actions = input
        .get("actions")
        .cloned()
        .ok_or_else(|| "decision missing `actions`".to_string())?;
    let actions: Vec<Action> = serde_json::from_value(actions)
        .map_err(|error| format!("decision actions failed to parse: {error}"))?;
    let rationale = input
        .get("rationale")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let usage = response
        .get("usage")
        .ok_or_else(|| "response missing usage".to_string())?;
    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "usage missing input_tokens".to_string())?;
    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "usage missing output_tokens".to_string())?;
    let cache_read_input_tokens = usage
        .get("cache_read_input_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Ok(DecidedBatch {
        // A `done` decision never executes leftover actions.
        actions: if done { Vec::new() } else { actions },
        rationale,
        usage: DecisionUsage {
            input_tokens,
            output_tokens,
            cache_read_input_tokens,
        },
    })
}

/// One model-decided task: where to start and what to accomplish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecidedTaskSpec {
    /// URL the driver navigates to before the first decision.
    pub start_url: String,
    /// Natural-language goal handed to the decider each round.
    pub goal: String,
    /// Ceiling on total decide rounds (including journaled ones on resume).
    pub max_rounds: usize,
}

impl DecidedTaskSpec {
    /// A spec with the default round ceiling.
    pub fn new(start_url: impl Into<String>, goal: impl Into<String>) -> Self {
        Self {
            start_url: start_url.into(),
            goal: goal.into(),
            max_rounds: DEFAULT_MAX_DECISION_ROUNDS,
        }
    }

    /// Override the round ceiling.
    pub fn with_max_rounds(mut self, max_rounds: usize) -> Self {
        self.max_rounds = max_rounds;
        self
    }
}

/// Terminal state of one decided run attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecidedRunStatus {
    /// The decider reported completion and the session was closed.
    Completed,
    /// The journal already records a closed session.
    AlreadyComplete,
    /// Charging a journaled decision's usage would exceed the run budget.
    /// Deterministic on resume: the same journal produces the same stop.
    TokenBudgetExhausted {
        /// Tokens the run would have used.
        used: u64,
        /// Configured budget ceiling.
        max: u64,
    },
    /// The decide-round ceiling was reached without completion.
    RoundLimitReached {
        /// Configured ceiling.
        max_rounds: usize,
    },
    /// A decided action failed; its error is journaled.
    StepError {
        /// Journaled failure reason.
        reason: String,
    },
    /// Policy refused a decided action before execution.
    PolicyDenied {
        /// Journaled denial reason.
        reason: String,
    },
    /// A CAPTCHA / auth-wall / login state was detected: the run hard-paused and
    /// is waiting for a human to take over (#244). This is a terminal stop for
    /// the automated loop — never a retry, never a solve. The seam where a
    /// windowed-shell takeover UI (#247) will adopt the session attaches here.
    HumanTakeoverRequired {
        /// The typed detection signal (kind, reason, URL).
        takeover: HumanTakeover,
    },
    /// A prior run journaled intent for an action but not its outcome; resume
    /// refused to re-execute it (#99).
    Interrupted {
        /// Journaled interruption reason.
        reason: String,
    },
}

/// One decide round in a [`DecidedRunReport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRoundReport {
    /// Number of actions in the decided batch.
    pub actions: usize,
    /// Model-provided rationale, if any.
    pub rationale: Option<String>,
    /// Provider token usage for this decision.
    pub usage: DecisionUsage,
    /// True when this decision was replayed from the journal rather than
    /// re-inferred.
    pub resumed: bool,
}

/// Durable report for one decided run attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct DecidedRunReport {
    /// Journal backing the run.
    pub journal_path: PathBuf,
    /// Terminal state.
    pub status: DecidedRunStatus,
    /// Every decision that shaped this run, journaled ones included.
    pub rounds: Vec<DecisionRoundReport>,
    /// Actions with a journaled outcome during this attempt.
    pub actions_completed: usize,
    /// Token usage summed over all journaled decisions.
    pub usage: DecisionUsage,
}

struct DecidedRunState {
    journal: SessionJournal,
    budget: TokenBudget,
    usage: DecisionUsage,
    rounds: Vec<DecisionRoundReport>,
    actions_completed: usize,
    /// Run-global step counter (journaled outcomes across all decisions,
    /// prior runs included) so idempotency keys stay unique across rounds,
    /// matching every other `IdempotencyKey::for_action` call site.
    steps_executed: usize,
    current_origin: Option<Origin>,
}

struct ResumedRound {
    actions: Vec<Action>,
    rationale: Option<String>,
    usage: DecisionUsage,
    executed: usize,
    dangling_planned: bool,
}

struct DecidedResume {
    session_started: bool,
    closed: bool,
    completed: Vec<ResumedRound>,
    pending: Option<ResumedRound>,
    last_step_error: Option<String>,
    /// A journaled human-takeover pause (#244). When set, resume surfaces the
    /// hard-pause terminal status instead of re-observing and continuing.
    human_takeover: Option<HumanTakeover>,
}

impl AgentRunner {
    /// Run one model-decided task: observe → decide → act until the decider
    /// reports completion, the token budget or round ceiling is hit, or a
    /// step fails.
    ///
    /// Resume semantics compose with the scripted loop's (#99): each decision
    /// is journaled before its actions run, so a journaled-but-unexecuted
    /// decision is replayed from the journal — never re-inferred — and a
    /// dangling `ActionPlanned` marker stops the run instead of repeating a
    /// side effect.
    pub async fn run_decided_task<D, M>(
        &self,
        driver: &mut D,
        decider: &mut M,
        spec: &DecidedTaskSpec,
    ) -> Result<DecidedRunReport, AgentError>
    where
        D: DriverTrait + ?Sized,
        M: Decider + ?Sized,
    {
        let journal = SessionJournal::open(
            &self.journal_path,
            self.ids.run_id.clone(),
            self.ids.session_id.clone(),
        )?;
        let entries = read_journal_entries(&self.journal_path)?;
        let resume = decided_resume_from_entries(&entries)?;

        let mut state = DecidedRunState {
            journal,
            budget: TokenBudget::new(self.token_budget.max_tokens),
            usage: DecisionUsage::default(),
            rounds: Vec::new(),
            actions_completed: 0,
            steps_executed: resume
                .completed
                .iter()
                .chain(resume.pending.iter())
                .map(|round| round.executed)
                .sum(),
            current_origin: None,
        };

        for round in resume.completed.iter().chain(resume.pending.iter()) {
            state.usage = state.usage.saturating_add(round.usage);
            state.rounds.push(DecisionRoundReport {
                actions: round.actions.len(),
                rationale: round.rationale.clone(),
                usage: round.usage,
                resumed: true,
            });
        }

        if resume.closed {
            return Ok(self.decided_report(state, DecidedRunStatus::AlreadyComplete));
        }
        // A journaled human-takeover pause is a hard stop: never re-observe or
        // continue past it on resume — a human must still take over (#244).
        if let Some(takeover) = resume.human_takeover {
            return Ok(
                self.decided_report(state, DecidedRunStatus::HumanTakeoverRequired { takeover })
            );
        }
        if let Some(reason) = resume.last_step_error {
            let status = terminal_status_for_step_error(reason);
            return Ok(self.decided_report(state, status));
        }

        // Restore the budget from journaled decisions before anything runs, so
        // a decision that overran the ceiling stops the run deterministically
        // on every resume (the journaled usage *is* the durable stop marker).
        for round in resume.completed.iter().chain(resume.pending.iter()) {
            if let Some(status) = charge_decision(&mut state.budget, round.usage)? {
                return Ok(self.decided_report(state, status));
            }
        }

        let mut observation = if resume.session_started {
            let observation = driver.observe().await.map_err(|source| {
                decided_transport_error(&mut state.journal, "decided resume observe", source)
            })?;
            self.record_decided_observation(&mut state, observation, "decided resume observation")?
        } else {
            let observation = driver.goto(&spec.start_url).await.map_err(|source| {
                decided_transport_error(&mut state.journal, "decided initial goto", source)
            })?;
            state.journal.append(JournalEvent::SessionStarted {
                url: spec.start_url.clone(),
            })?;
            self.record_decided_observation(&mut state, observation, "decided initial observation")?
        };

        // A challenge may be present the moment we land (or on the resumed page):
        // pause before asking the decider to act on it (#244).
        if let Some(status) = self.detect_takeover(&mut state, &observation)? {
            return Ok(self.decided_report(state, status));
        }

        let mut total_decisions = resume.completed.len() + usize::from(resume.pending.is_some());

        // Replay a journaled-but-unexecuted decision instead of re-inferring it.
        if let Some(pending) = resume.pending {
            if pending.actions.is_empty() {
                state.journal.append(JournalEvent::SessionClosed)?;
                return Ok(self.decided_report(state, DecidedRunStatus::Completed));
            }
            if let Some(status) = self
                .run_decided_batch(
                    driver,
                    &mut state,
                    &mut observation,
                    &pending.actions,
                    pending.executed,
                    pending.dangling_planned,
                )
                .await?
            {
                return Ok(self.decided_report(state, status));
            }
        }

        let action_schema = tempo_schema::action_json_schema();
        while total_decisions < spec.max_rounds {
            let decided = {
                let request = DecisionRequest {
                    goal: &spec.goal,
                    action_schema: &action_schema,
                    observation: &observation,
                    budget_remaining: state.budget.remaining(),
                };
                decider.decide(&request).await?
            };
            total_decisions += 1;

            // Journal-before-effect: the decision (and its usage) is durable
            // before the budget charge and before any action executes.
            state.journal.append(JournalEvent::ModelDecision {
                actions: decided.actions.clone(),
                rationale: decided.rationale.clone(),
                input_tokens: decided.usage.input_tokens,
                output_tokens: decided.usage.output_tokens,
                cache_read_input_tokens: decided.usage.cache_read_input_tokens,
            })?;
            state.usage = state.usage.saturating_add(decided.usage);
            state.rounds.push(DecisionRoundReport {
                actions: decided.actions.len(),
                rationale: decided.rationale.clone(),
                usage: decided.usage,
                resumed: false,
            });

            if let Some(status) = charge_decision(&mut state.budget, decided.usage)? {
                return Ok(self.decided_report(state, status));
            }

            if decided.actions.is_empty() {
                state.journal.append(JournalEvent::SessionClosed)?;
                return Ok(self.decided_report(state, DecidedRunStatus::Completed));
            }

            if let Some(status) = self
                .run_decided_batch(
                    driver,
                    &mut state,
                    &mut observation,
                    &decided.actions,
                    0,
                    false,
                )
                .await?
            {
                return Ok(self.decided_report(state, status));
            }
        }

        Ok(self.decided_report(
            state,
            DecidedRunStatus::RoundLimitReached {
                max_rounds: spec.max_rounds,
            },
        ))
    }

    /// Execute one decided batch from `executed` onward, journaling intent
    /// before each side effect (#99) and re-observing after each action.
    /// Returns a terminal status when the batch cannot continue.
    async fn run_decided_batch<D>(
        &self,
        driver: &mut D,
        state: &mut DecidedRunState,
        observation: &mut CompiledObservation,
        actions: &[Action],
        executed: usize,
        dangling_planned: bool,
    ) -> Result<Option<DecidedRunStatus>, AgentError>
    where
        D: DriverTrait + ?Sized,
    {
        for (index, action) in actions.iter().enumerate().skip(executed) {
            let intent_already_journaled = dangling_planned && index == executed;

            // Model-decided skills are out of scope for the first decided loop:
            // fail the step with a typed, journaled error rather than silently
            // skipping the skill store and its policy snapshot machinery (#98).
            // This precedes the interruption check: rejecting a skill never
            // runs a side effect, so crash-recovery surfaces the same typed
            // reason as live execution instead of a generic interruption.
            if matches!(action, Action::Skill { .. }) {
                let reason =
                    "decided loop does not execute skill actions; decide concrete actions instead"
                        .to_string();
                if !intent_already_journaled {
                    state.journal.append(JournalEvent::ActionPlanned {
                        action: action.clone(),
                    })?;
                }
                state.journal.append(JournalEvent::StepError {
                    action: action.clone(),
                    reason: reason.clone(),
                })?;
                state.actions_completed += 1;
                state.steps_executed += 1;
                return Ok(Some(DecidedRunStatus::StepError { reason }));
            }

            // A step whose intent was journaled in a prior run but never
            // completed may already have run its side effect: do not repeat it.
            if intent_already_journaled {
                let reason = RESUME_INTERRUPTED_REASON.to_string();
                state.journal.append(JournalEvent::StepError {
                    action: action.clone(),
                    reason: reason.clone(),
                })?;
                state.actions_completed += 1;
                state.steps_executed += 1;
                return Ok(Some(DecidedRunStatus::Interrupted { reason }));
            }

            let step = DriverStep::clean(action.clone());
            let key = IdempotencyKey::for_action(state.steps_executed, action)?;
            let policy_origin = self.origin_for_step(&step, state.current_origin.as_ref())?;
            let policy =
                self.step_policy(&step, &key, policy_origin.as_ref(), action.side_effect())?;
            if !policy.confirmed {
                let reason = policy_denied_reason(&policy);
                state.journal.append(JournalEvent::ActionPlanned {
                    action: action.clone(),
                })?;
                state.journal.append(JournalEvent::StepError {
                    action: action.clone(),
                    reason: reason.clone(),
                })?;
                state.actions_completed += 1;
                state.steps_executed += 1;
                return Ok(Some(DecidedRunStatus::PolicyDenied { reason }));
            }

            // Journal intent before the side effect runs (#99).
            state.journal.append(JournalEvent::ActionPlanned {
                action: action.clone(),
            })?;
            let execution = execute_action(driver, action).await.map_err(|source| {
                decided_transport_error(&mut state.journal, "decided execute action", source)
            })?;
            let (outcome, step_error) = match execution.status {
                ExecutionStatus::Applied => (
                    JournalEvent::StepApplied {
                        action: action.clone(),
                        diff: execution.diff,
                    },
                    None,
                ),
                ExecutionStatus::PartiallyApplied { reason }
                | ExecutionStatus::StepError { reason } => (
                    JournalEvent::StepError {
                        action: action.clone(),
                        reason: reason.clone(),
                    },
                    Some(reason),
                ),
            };
            state.journal.append(outcome)?;
            state.actions_completed += 1;
            state.steps_executed += 1;

            *observation = self
                .reobserve_after_action(driver, state, observation, action)
                .await?;

            // Hard-pause on a CAPTCHA / auth-wall / login state before running
            // any further queued action (#244). Takes precedence over a plain
            // step error: the challenge is the actionable reason to stop.
            if let Some(status) = self.detect_takeover(state, observation)? {
                return Ok(Some(status));
            }

            if let Some(reason) = step_error {
                return Ok(Some(DecidedRunStatus::StepError { reason }));
            }
        }
        Ok(None)
    }

    /// Hard-pause if the observation is a CAPTCHA / auth-wall / login state
    /// (#244). This is pure detection over the compiled observation — tempo
    /// never solves the challenge or answers it automatically. On a hit it
    /// journals the typed [`JournalEvent::HumanTakeoverRequired`] (so a resumed
    /// run stops here too) and returns the terminal
    /// [`DecidedRunStatus::HumanTakeoverRequired`], which stops the loop before
    /// any further queued action runs and before the decider is asked to act on
    /// the challenge page (so no blind click on a checkbox).
    fn detect_takeover(
        &self,
        state: &mut DecidedRunState,
        observation: &CompiledObservation,
    ) -> Result<Option<DecidedRunStatus>, AgentError> {
        let Some(takeover) = detect_human_takeover(observation) else {
            return Ok(None);
        };
        state.journal.append(JournalEvent::HumanTakeoverRequired {
            takeover: takeover.clone(),
        })?;
        Ok(Some(DecidedRunStatus::HumanTakeoverRequired { takeover }))
    }

    /// Re-observe the page after an action, recording the observation the next
    /// decision (and the #343 takeover detector and #254 origin/taint
    /// recomputation) will run on.
    ///
    /// Incremental fast path (#235): for a same-document action, ask the driver
    /// for an [`ObservationDiff`] relative to the pre-action observation and
    /// reconstruct the full observation locally, instead of paying a full
    /// re-observe. This shrinks the post-action re-observation (only the delta
    /// crosses the driver transport) without changing what the consumers see:
    /// [`reconstruct_observation`] rebuilds the element set exactly and carries
    /// the URL/marks forward, which is equivalent to a full observe precisely
    /// because a same-document action cannot change the origin (the browser's
    /// same-origin history invariant) — so the recomputed policy origin is
    /// unchanged.
    ///
    /// Correctness gates (any failure falls back to a full `observe()`):
    ///   * navigating actions (`Goto`/`Click`/`Skill`) always full-observe — a
    ///     diff carries no URL, so the post-navigation origin must be read fresh;
    ///   * a diff that was not computed against our exact base, or that a page
    ///     with a set-of-marks overlay cannot reproduce, is rejected by
    ///     [`reconstruct_observation`] and full-observed instead.
    async fn reobserve_after_action<D>(
        &self,
        driver: &mut D,
        state: &mut DecidedRunState,
        base: &CompiledObservation,
        action: &Action,
    ) -> Result<CompiledObservation, AgentError>
    where
        D: DriverTrait + ?Sized,
    {
        if !action_may_navigate(action) {
            let diff = driver.observe_diff(base.seq).await.map_err(|source| {
                decided_transport_error(
                    &mut state.journal,
                    "decided post-action observe_diff",
                    source,
                )
            })?;
            if let Some(observation) = reconstruct_observation(base, &diff) {
                return self.record_decided_observation(
                    state,
                    observation,
                    "decided post-action observation (diff)",
                );
            }
            // The diff could not be applied equivalently: fall back to a full
            // observe (correctness > latency).
        }

        let next = driver.observe().await.map_err(|source| {
            decided_transport_error(&mut state.journal, "decided post-action observe", source)
        })?;
        self.record_decided_observation(state, next, "decided post-action observation")
    }

    /// Validate the observation budget, journal the observation, and update
    /// the tracked origin. Returns the observation for the next decision.
    fn record_decided_observation(
        &self,
        state: &mut DecidedRunState,
        observation: CompiledObservation,
        context: &'static str,
    ) -> Result<CompiledObservation, AgentError> {
        self.observation_budget.validate(&observation)?;
        state.current_origin = self.origin_for_url(context, &observation.url)?;
        state.journal.append(JournalEvent::Observation {
            observation: observation.clone(),
        })?;
        Ok(observation)
    }

    fn decided_report(&self, state: DecidedRunState, status: DecidedRunStatus) -> DecidedRunReport {
        DecidedRunReport {
            journal_path: self.journal_path.clone(),
            status,
            rounds: state.rounds,
            actions_completed: state.actions_completed,
            usage: state.usage,
        }
    }
}

/// Whether executing `action` can cause a cross-document navigation, i.e. move
/// the page to a new URL/origin.
///
/// Only these actions force a full post-action re-observe (#235): an
/// [`ObservationDiff`] carries element deltas + `seq` but not the URL, and the
/// tracked policy origin (#254 taint / policy gating) is derived from
/// `observation.url`. Same-document actions cannot change the origin — the
/// browser only permits same-origin history mutation — so their post-action URL
/// is unchanged and a diff-based reconstruction is equivalent to a full observe.
/// `Skill` is included defensively: the decided loop rejects skills before they
/// execute, so it never reaches the post-action re-observe.
fn action_may_navigate(action: &Action) -> bool {
    matches!(
        action,
        Action::Goto { .. } | Action::Click { .. } | Action::Skill { .. }
    )
}

/// Rebuild the full post-action observation from the pre-action observation
/// `base` and the `diff` describing what changed, or return `None` when the diff
/// cannot be applied equivalently to a full re-observe (so the caller falls back
/// to a full `observe()`).
///
/// Equivalence argument. Elements are identified by stable `NodeId`, so applying
/// `removed`/`changed`/`added` to `base.elements` reproduces the engine's current
/// element set with its current per-element content exactly — this is the inverse
/// of the engine's diff. `seq` is taken from the diff; `url`, `marks`, and
/// `schema_version` are carried from `base`. The caller only takes this path for
/// same-document actions, so the URL (hence the policy origin, #254) is unchanged;
/// and the takeover detector (#343) and taint recomputation both read the element
/// set / URL, which are preserved. Surviving elements keep their base order and
/// additions are appended, a deterministic order the order-insensitive consumers
/// do not depend on.
///
/// Fallback conditions (return `None`):
///   * `diff.since_seq != base.seq` — the diff was not computed against our base
///     (a stale/evicted base or a diff-unsupported engine), so applying it is
///     unsound;
///   * the delta is structurally inconsistent with `base` (a `changed`/`removed`
///     node absent from `base`, or an `added` node already present) — again a
///     sign the diff was taken against a different base;
///   * `base` carries a set-of-marks overlay, which the diff cannot reproduce.
fn reconstruct_observation(
    base: &CompiledObservation,
    diff: &ObservationDiff,
) -> Option<CompiledObservation> {
    if diff.since_seq != base.seq {
        return None;
    }
    // A diff carries no set-of-marks overlay; only reconstruct when there is
    // none to preserve.
    if !base.marks.is_empty() {
        return None;
    }

    let base_ids: HashSet<&str> = base
        .elements
        .iter()
        .map(|element| element.node_id.0.as_str())
        .collect();
    let removed: HashSet<&str> = diff.removed.iter().map(|node| node.0.as_str()).collect();

    // Structural consistency: the delta must reference exactly the base it
    // claims to. A mismatch means the diff was computed against a different
    // observation, so reconstruction would be wrong.
    if !removed.iter().all(|node| base_ids.contains(node)) {
        return None;
    }
    if !diff
        .changed
        .iter()
        .all(|element| base_ids.contains(element.node_id.0.as_str()))
    {
        return None;
    }
    if diff
        .added
        .iter()
        .any(|element| base_ids.contains(element.node_id.0.as_str()))
    {
        return None;
    }

    let changed: std::collections::HashMap<&str, &tempo_schema::InteractiveElement> = diff
        .changed
        .iter()
        .map(|element| (element.node_id.0.as_str(), element))
        .collect();

    let mut elements = Vec::with_capacity(base.elements.len() + diff.added.len());
    for element in &base.elements {
        let id = element.node_id.0.as_str();
        if removed.contains(id) {
            continue;
        }
        match changed.get(id) {
            Some(updated) => elements.push((*updated).clone()),
            None => elements.push(element.clone()),
        }
    }
    elements.extend(diff.added.iter().cloned());

    Some(CompiledObservation {
        schema_version: base.schema_version.clone(),
        url: base.url.clone(),
        seq: diff.seq,
        elements,
        marks: base.marks.clone(),
    })
}

fn charge_decision(
    budget: &mut TokenBudget,
    usage: DecisionUsage,
) -> Result<Option<DecidedRunStatus>, AgentError> {
    match budget.charge(usage.total_tokens()) {
        Ok(()) => Ok(None),
        Err(AgentError::TokenBudgetExceeded { attempted, max }) => {
            Ok(Some(DecidedRunStatus::TokenBudgetExhausted {
                used: attempted,
                max,
            }))
        }
        Err(error) => Err(error),
    }
}

fn terminal_status_for_step_error(reason: String) -> DecidedRunStatus {
    if reason == RESUME_INTERRUPTED_REASON {
        DecidedRunStatus::Interrupted { reason }
    } else if is_policy_denial_reason(&reason) {
        DecidedRunStatus::PolicyDenied { reason }
    } else {
        DecidedRunStatus::StepError { reason }
    }
}

fn decided_transport_error(
    journal: &mut SessionJournal,
    context: &'static str,
    source: TransportError,
) -> AgentError {
    match journal.append(JournalEvent::from_transport_error(context, &source)) {
        Ok(_) => AgentError::transport(context, source),
        Err(error) => error.into(),
    }
}

/// Rebuild the decided-loop cursor from journal entries: which decisions are
/// fully executed, which one is pending, and whether a step's intent was
/// journaled without an outcome.
fn decided_resume_from_entries(entries: &[JournalEntry]) -> Result<DecidedResume, AgentError> {
    let mut resume = DecidedResume {
        session_started: false,
        closed: false,
        completed: Vec::new(),
        pending: None,
        last_step_error: None,
        human_takeover: None,
    };

    for entry in entries {
        match &entry.event {
            JournalEvent::SessionStarted { .. } => resume.session_started = true,
            JournalEvent::SessionClosed => resume.closed = true,
            JournalEvent::ModelDecision {
                actions,
                rationale,
                input_tokens,
                output_tokens,
                cache_read_input_tokens,
            } => {
                if resume.pending.is_some() {
                    return Err(AgentError::JournalDiverged {
                        index: resume.completed.len(),
                    });
                }
                resume.pending = Some(ResumedRound {
                    actions: actions.clone(),
                    rationale: rationale.clone(),
                    usage: DecisionUsage {
                        input_tokens: *input_tokens,
                        output_tokens: *output_tokens,
                        cache_read_input_tokens: *cache_read_input_tokens,
                    },
                    executed: 0,
                    dangling_planned: false,
                });
            }
            JournalEvent::ActionPlanned { action } => {
                let Some(pending) = resume.pending.as_mut() else {
                    return Err(AgentError::JournalDiverged {
                        index: resume.completed.len(),
                    });
                };
                match pending.actions.get(pending.executed) {
                    Some(expected) if expected == action => pending.dangling_planned = true,
                    _ => {
                        return Err(AgentError::JournalDiverged {
                            index: resume.completed.len(),
                        })
                    }
                }
            }
            JournalEvent::StepApplied { action, .. } | JournalEvent::StepError { action, .. } => {
                let complete = {
                    let Some(pending) = resume.pending.as_mut() else {
                        return Err(AgentError::JournalDiverged {
                            index: resume.completed.len(),
                        });
                    };
                    match pending.actions.get(pending.executed) {
                        Some(expected) if expected == action => {}
                        _ => {
                            return Err(AgentError::JournalDiverged {
                                index: resume.completed.len(),
                            })
                        }
                    }
                    if let JournalEvent::StepError { reason, .. } = &entry.event {
                        resume.last_step_error = Some(reason.clone());
                    }
                    pending.executed += 1;
                    pending.dangling_planned = false;
                    pending.executed == pending.actions.len()
                };
                if complete && let Some(done) = resume.pending.take() {
                    resume.completed.push(done);
                }
            }
            JournalEvent::HumanTakeoverRequired { takeover } => {
                resume.human_takeover = Some(takeover.clone());
            }
            JournalEvent::Observation { .. }
            | JournalEvent::StructuredFastPathSelected { .. }
            | JournalEvent::TransportError { .. }
            | JournalEvent::CassetteRecorded { .. } => {}
        }
    }

    Ok(resume)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        button, http_fixture_response, read_http_request, remove_dir_if_exists, unique_dir,
    };
    use crate::{AgentRunIds, TokenBudget};
    use std::error::Error;
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;
    use tempo_driver::TestDriver;
    use tempo_schema::NodeId;
    use tempo_session::{RunId, SessionId};

    type TestResult = Result<(), Box<dyn Error>>;
    type FixtureHandle = thread::JoinHandle<std::io::Result<()>>;
    /// Origin, captured raw requests, and the serving thread handle.
    type MessagesFixture = (String, Arc<Mutex<Vec<String>>>, FixtureHandle);

    fn click(node: &str) -> Action {
        Action::Click {
            node: NodeId(node.into()),
        }
    }

    fn journal_root(label: &str) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
        let root = unique_dir(label)?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal = root.join("session.jsonl");
        Ok((root, journal))
    }

    fn observation(url: &str, seq: u64) -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: url.into(),
            seq,
            elements: vec![button("submit")],
            marks: vec![],
        }
    }

    fn decision_response(
        actions: serde_json::Value,
        done: bool,
        usage: (u64, u64, u64),
    ) -> serde_json::Value {
        serde_json::json!({
            "id": "msg_fixture",
            "type": "message",
            "role": "assistant",
            "model": DEFAULT_ANTHROPIC_MODEL,
            "content": [{
                "type": "tool_use",
                "id": "toolu_fixture",
                "name": DECIDE_TOOL_NAME,
                "input": { "done": done, "actions": actions, "rationale": "fixture" }
            }],
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": usage.0,
                "output_tokens": usage.1,
                "cache_read_input_tokens": usage.2
            }
        })
    }

    /// Serves `responses` to sequential `POST /v1/messages` requests, capturing
    /// each raw request for inspection.
    fn serve_messages_api(
        responses: Vec<(&'static str, String)>,
    ) -> std::io::Result<MessagesFixture> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut served = 0_usize;
            while served < responses.len() && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                        let request = read_http_request(&mut stream)?;
                        captured
                            .lock()
                            .map_err(|_| std::io::Error::other("request log poisoned"))?
                            .push(request);
                        let (status, body) = &responses[served];
                        let response =
                            http_fixture_response(status, "application/json", body.clone());
                        // Best-effort write: a client that rejects the body
                        // early (e.g. the size cap) may hang up mid-response.
                        let written = stream.write_all(response.to_http().as_bytes());
                        if written.is_ok() {
                            stream.flush()?;
                        }
                        served += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            if served == responses.len() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "messages fixture did not receive all expected requests",
                ))
            }
        });
        Ok((origin, requests, handle))
    }

    fn fixture_config(origin: &str) -> AnthropicConfig {
        AnthropicConfig::new("test-key")
            .with_base_url(origin)
            .with_retry_backoff(Duration::ZERO)
    }

    fn request_body_json(request: &str) -> Result<serde_json::Value, Box<dyn Error>> {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .ok_or("request missing body")?;
        Ok(serde_json::from_str(body)?)
    }

    /// A decider with fixed actions and usage, counting how often it is asked.
    struct FixedUsageDecider {
        actions: Vec<Action>,
        usage: DecisionUsage,
        calls: usize,
    }

    #[async_trait]
    impl Decider for FixedUsageDecider {
        async fn decide(
            &mut self,
            _request: &DecisionRequest<'_>,
        ) -> Result<DecidedBatch, DeciderError> {
            self.calls += 1;
            Ok(DecidedBatch {
                actions: self.actions.clone(),
                rationale: None,
                usage: self.usage,
            })
        }
    }

    #[tokio::test]
    async fn scripted_decider_drives_hermetic_decided_run() -> TestResult {
        let (root, journal_path) = journal_root("decided-scripted")?;
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-decided-scripted", "session-decided-scripted"),
        );
        let mut decider = ScriptedDecider::new(vec![vec![click("submit")]]);
        let spec = DecidedTaskSpec::new("https://example.com", "click submit");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        assert_eq!(report.status, DecidedRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(report.rounds.len(), 2);
        assert!(!report.rounds[0].resumed);
        assert_eq!(report.usage, DecisionUsage::default());

        let entries = read_journal_entries(&journal_path)?;
        let decisions = entries
            .iter()
            .filter(|entry| matches!(entry.event, JournalEvent::ModelDecision { .. }))
            .count();
        assert_eq!(decisions, 2);
        assert!(matches!(
            entries.last().map(|entry| &entry.event),
            Some(JournalEvent::SessionClosed)
        ));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    /// A driver that serves a benign page until the first action runs, then
    /// exposes a reCAPTCHA widget on every subsequent observation — modelling a
    /// challenge that appears mid-task (#244).
    struct ChallengeAfterActionDriver {
        seq: u64,
        challenged: bool,
    }

    impl ChallengeAfterActionDriver {
        fn new() -> Self {
            Self {
                seq: 0,
                challenged: false,
            }
        }

        fn snapshot(&self) -> CompiledObservation {
            let elements = if self.challenged {
                vec![
                    button("submit"),
                    tempo_schema::InteractiveElement {
                        node_id: NodeId("captcha".into()),
                        role: "iframe".into(),
                        name: vec![tempo_schema::TaintSpan {
                            provenance: tempo_schema::Provenance::Page,
                            text: "reCAPTCHA".into(),
                        }],
                        value: Vec::new(),
                        bounds: None,
                        rank: 1.0,
                    },
                ]
            } else {
                vec![button("submit")]
            };
            CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: "https://example.com/".into(),
                seq: self.seq,
                elements,
                marks: vec![],
            }
        }

        fn grounded_diff(&self, since_seq: u64) -> tempo_schema::ObservationDiff {
            tempo_schema::ObservationDiff {
                since_seq,
                seq: self.seq,
                added: Vec::new(),
                removed: Vec::new(),
                changed: vec![button("submit")],
            }
        }
    }

    #[async_trait]
    impl DriverTrait for ChallengeAfterActionDriver {
        fn engine(&self) -> tempo_driver::Engine {
            tempo_driver::Engine::Test
        }

        async fn goto(&mut self, _url: &str) -> Result<CompiledObservation, TransportError> {
            self.seq += 1;
            Ok(self.snapshot())
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            Ok(self.snapshot())
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<tempo_schema::ObservationDiff, TransportError> {
            Ok(self.grounded_diff(since_seq))
        }

        async fn act(
            &mut self,
            _action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            self.seq += 1;
            // The challenge appears as a result of this action.
            self.challenged = true;
            Ok(tempo_driver::StepOutcome::Applied {
                diff: self.grounded_diff(self.seq - 1),
            })
        }

        async fn act_batch(
            &mut self,
            batch: &tempo_schema::ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            let mut last = tempo_driver::StepOutcome::Applied {
                diff: self.grounded_diff(self.seq),
            };
            for action in &batch.actions {
                last = self.act(action).await?;
            }
            Ok(last)
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, tempo_driver::Unsupported> {
            Err(tempo_driver::Unsupported("challenge driver does not fork"))
        }

        async fn extract(&mut self, _node: &NodeId) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }

        async fn evaluate_script(
            &mut self,
            _expression: &str,
            _await_promise: bool,
        ) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(Vec::new())
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn decided_run_hard_pauses_on_detected_captcha_without_running_further_actions(
    ) -> TestResult {
        let (root, journal_path) = journal_root("decided-captcha-pause")?;
        let mut driver = ChallengeAfterActionDriver::new();
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-captcha", "session-captcha"),
        );
        // Two actions queued in one batch. The CAPTCHA appears after the first,
        // so the second must NEVER execute.
        let mut decider = ScriptedDecider::new(vec![vec![click("submit"), click("submit")]]);
        let spec = DecidedTaskSpec::new("https://example.com", "click submit twice");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        // The typed hard-pause outcome, not a StepError, not a retry.
        let DecidedRunStatus::HumanTakeoverRequired { takeover } = &report.status else {
            return Err(format!("expected HumanTakeoverRequired, got {:?}", report.status).into());
        };
        assert_eq!(takeover.kind, tempo_schema::TakeoverKind::Captcha);
        assert_eq!(takeover.url, "https://example.com/");
        // Exactly one action ran; the second queued action was not executed.
        assert_eq!(report.actions_completed, 1);

        let entries = read_journal_entries(&journal_path)?;
        let planned = entries
            .iter()
            .filter(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. }))
            .count();
        assert_eq!(planned, 1, "second action must not be planned or run");
        let takeovers = entries
            .iter()
            .filter(|entry| matches!(entry.event, JournalEvent::HumanTakeoverRequired { .. }))
            .count();
        assert_eq!(takeovers, 1);
        // The pause is journaled and the session is NOT closed (a human owes work).
        assert!(!matches!(
            entries.last().map(|entry| &entry.event),
            Some(JournalEvent::SessionClosed)
        ));

        // Resume must re-surface the hard pause and never auto-continue — even
        // with a driver whose page is now benign.
        let mut resumed_driver = TestDriver::new().with_elements(vec![button("submit")]);
        let mut resumed_decider = ScriptedDecider::new(vec![vec![click("submit")]]);
        let resumed = runner
            .run_decided_task(&mut resumed_driver, &mut resumed_decider, &spec)
            .await?;
        assert!(matches!(
            resumed.status,
            DecidedRunStatus::HumanTakeoverRequired { .. }
        ));
        // The resume ran no new actions.
        assert_eq!(resumed.actions_completed, 0);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn anthropic_decider_completes_run_and_journals_cache_reads() -> TestResult {
        let (root, journal_path) = journal_root("decided-anthropic")?;
        let (origin, requests, server) = serve_messages_api(vec![
            (
                "200 OK",
                decision_response(
                    serde_json::json!([{ "kind": "click", "node": "submit" }]),
                    false,
                    (100, 10, 0),
                )
                .to_string(),
            ),
            (
                "200 OK",
                decision_response(serde_json::json!([]), true, (50, 5, 40)).to_string(),
            ),
        ])?;

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-decided-anthropic", "session-decided-anthropic"),
        )
        .with_token_budget(TokenBudget::new(1_000));
        let mut decider = AnthropicDecider::new(fixture_config(&origin))?;
        let spec = DecidedTaskSpec::new("https://example.com", "click the submit button");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        assert_eq!(report.status, DecidedRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert_eq!(
            report.usage,
            DecisionUsage {
                input_tokens: 150,
                output_tokens: 15,
                cache_read_input_tokens: 40
            }
        );

        // The decision — including cache_read_input_tokens — is journaled per
        // step, before the actions it produced.
        let entries = read_journal_entries(&journal_path)?;
        let cache_reads: Vec<u64> = entries
            .iter()
            .filter_map(|entry| match &entry.event {
                JournalEvent::ModelDecision {
                    cache_read_input_tokens,
                    ..
                } => Some(*cache_read_input_tokens),
                _ => None,
            })
            .collect();
        assert_eq!(cache_reads, vec![0, 40]);
        let first_decision = entries
            .iter()
            .position(|entry| matches!(entry.event, JournalEvent::ModelDecision { .. }))
            .ok_or("no journaled decision")?;
        let first_planned = entries
            .iter()
            .position(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. }))
            .ok_or("no journaled plan")?;
        assert!(first_decision < first_planned);

        server.join().map_err(|_| "fixture thread panicked")??;
        let requests = requests.lock().map_err(|_| "request log poisoned")?;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("x-api-key: test-key"));
        assert!(requests[0].contains("anthropic-version: 2023-06-01"));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn anthropic_prompt_keeps_stable_prefix_and_volatile_tail() -> TestResult {
        let done = decision_response(serde_json::json!([]), true, (10, 1, 0)).to_string();
        let (origin, requests, server) =
            serve_messages_api(vec![("200 OK", done.clone()), ("200 OK", done)])?;
        let mut decider = AnthropicDecider::new(fixture_config(&origin))?;
        let schema = tempo_schema::action_json_schema();

        let first_observation = observation("https://example.com/step-one", 1);
        let second_observation = observation("https://example.com/step-two", 2);
        for (obs, budget) in [(&first_observation, 900_u64), (&second_observation, 800)] {
            let request = DecisionRequest {
                goal: "click the submit button",
                action_schema: &schema,
                observation: obs,
                budget_remaining: budget,
            };
            decider.decide(&request).await?;
        }
        server.join().map_err(|_| "fixture thread panicked")??;

        let requests = requests.lock().map_err(|_| "request log poisoned")?;
        let first = request_body_json(&requests[0])?;
        let second = request_body_json(&requests[1])?;

        // Stable prefix: system + tool schemas are byte-identical across steps.
        assert_eq!(
            serde_json::to_string(&first["system"])?,
            serde_json::to_string(&second["system"])?
        );
        assert_eq!(
            serde_json::to_string(&first["tools"])?,
            serde_json::to_string(&second["tools"])?
        );
        assert_eq!(first["tool_choice"], second["tool_choice"]);
        assert_eq!(first["model"], serde_json::json!(DEFAULT_ANTHROPIC_MODEL));
        assert_eq!(
            first["system"][0]["cache_control"],
            serde_json::json!({ "type": "ephemeral" })
        );

        // Volatile tail: the observation only appears in the final message.
        assert_ne!(first["messages"], second["messages"]);
        let first_stable = format!(
            "{}{}",
            serde_json::to_string(&first["system"])?,
            serde_json::to_string(&first["tools"])?
        );
        assert!(!first_stable.contains("step-one"));
        assert!(serde_json::to_string(&first["messages"])?.contains("step-one"));
        assert!(serde_json::to_string(&second["messages"])?.contains("step-two"));
        Ok(())
    }

    #[tokio::test]
    async fn anthropic_decider_types_malformed_output_after_bounded_retries() -> TestResult {
        let malformed = serde_json::json!({
            "id": "msg_fixture",
            "type": "message",
            "content": [{ "type": "text", "text": "I refuse to use tools." }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 5, "output_tokens": 5 }
        })
        .to_string();
        let (origin, requests, server) = serve_messages_api(vec![
            ("200 OK", malformed.clone()),
            ("200 OK", malformed.clone()),
            ("200 OK", malformed),
        ])?;
        let mut decider = AnthropicDecider::new(fixture_config(&origin).with_max_retries(2))?;
        let schema = tempo_schema::action_json_schema();
        let obs = observation("https://example.com", 1);
        let request = DecisionRequest {
            goal: "click submit",
            action_schema: &schema,
            observation: &obs,
            budget_remaining: 100,
        };

        let error = match decider.decide(&request).await {
            Err(error) => error,
            Ok(_) => return Err("expected a malformed-decision error".into()),
        };
        assert!(
            matches!(error, DeciderError::MalformedDecision { attempts: 3, .. }),
            "expected malformed decision after 3 attempts, got: {error:?}"
        );
        server.join().map_err(|_| "fixture thread panicked")??;
        assert_eq!(requests.lock().map_err(|_| "poisoned")?.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn anthropic_decider_caps_oversized_response_body() -> TestResult {
        let oversized = decision_response(
            serde_json::json!([{ "kind": "wait", "millis": 1 }]),
            false,
            (1, 1, 0),
        )
        .to_string()
        .replace("fixture", &"x".repeat(256 * 1024));
        let (origin, _requests, server) = serve_messages_api(vec![("200 OK", oversized)])?;
        let mut decider =
            AnthropicDecider::new(fixture_config(&origin).with_max_body_bytes(64 * 1024))?;
        let schema = tempo_schema::action_json_schema();
        let obs = observation("https://example.com", 1);
        let request = DecisionRequest {
            goal: "wait",
            action_schema: &schema,
            observation: &obs,
            budget_remaining: 100,
        };

        let error = match decider.decide(&request).await {
            Err(error) => error,
            Ok(_) => return Err("expected a response-size error".into()),
        };
        assert!(matches!(
            error,
            DeciderError::ResponseTooLarge { max_bytes: 65_536 }
        ));
        server.join().map_err(|_| "fixture thread panicked")??;
        Ok(())
    }

    /// Serves one request with a close-delimited body that OMITS
    /// `Content-Length`, so the early advertised-length rejection in
    /// `read_body_capped` is skipped and only the chunk-accumulation guard can
    /// enforce the cap (mirrors the #215 MCP regression test).
    fn serve_streamed_response_without_content_length(
        body: String,
    ) -> std::io::Result<(String, FixtureHandle)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                        let _request = read_http_request(&mut stream)?;
                        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
                        // Best-effort writes: the client aborts mid-body once
                        // the accumulated bytes cross the cap.
                        let _ = stream
                            .write_all(head.as_bytes())
                            .and_then(|()| stream.write_all(body.as_bytes()))
                            .and_then(|()| stream.flush());
                        // Dropping the stream closes the connection, delimiting the body.
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "streamed fixture did not receive a request",
            ))
        });
        Ok((origin, handle))
    }

    #[tokio::test]
    async fn anthropic_decider_caps_streamed_body_without_content_length() -> TestResult {
        let oversized = decision_response(
            serde_json::json!([{ "kind": "wait", "millis": 1 }]),
            false,
            (1, 1, 0),
        )
        .to_string()
        .replace("fixture", &"x".repeat(256 * 1024));
        let (origin, server) = serve_streamed_response_without_content_length(oversized)?;
        let mut decider =
            AnthropicDecider::new(fixture_config(&origin).with_max_body_bytes(64 * 1024))?;
        let schema = tempo_schema::action_json_schema();
        let obs = observation("https://example.com", 1);
        let request = DecisionRequest {
            goal: "wait",
            action_schema: &schema,
            observation: &obs,
            budget_remaining: 100,
        };

        let error = match decider.decide(&request).await {
            Err(error) => error,
            Ok(_) => return Err("expected a response-size error".into()),
        };
        assert!(
            matches!(error, DeciderError::ResponseTooLarge { max_bytes: 65_536 }),
            "expected size-cap rejection from the accumulation guard, got: {error:?}"
        );
        server.join().map_err(|_| "fixture thread panicked")??;
        Ok(())
    }

    #[tokio::test]
    async fn decided_run_stops_typed_at_budget_ceiling_and_resumes_without_reinference(
    ) -> TestResult {
        let (root, journal_path) = journal_root("decided-budget")?;
        let ids = AgentRunIds::new("run-decided-budget", "session-decided-budget");
        let runner = AgentRunner::new(&journal_path, ids).with_token_budget(TokenBudget::new(100));
        let spec = DecidedTaskSpec::new("https://example.com", "click submit");
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let usage = DecisionUsage {
            input_tokens: 80,
            output_tokens: 40,
            cache_read_input_tokens: 0,
        };

        let mut decider = FixedUsageDecider {
            actions: vec![click("submit")],
            usage,
            calls: 0,
        };
        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;
        assert_eq!(
            report.status,
            DecidedRunStatus::TokenBudgetExhausted {
                used: 120,
                max: 100
            }
        );
        assert_eq!(decider.calls, 1);

        // The over-budget decision is journaled, but none of its actions ran.
        let entries = read_journal_entries(&journal_path)?;
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::ModelDecision { .. })));
        assert!(!entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. })));

        // Resume replays the journaled stop deterministically: no model call.
        let mut resumed_decider = FixedUsageDecider {
            actions: vec![click("submit")],
            usage,
            calls: 0,
        };
        let resumed = runner
            .run_decided_task(&mut driver, &mut resumed_decider, &spec)
            .await?;
        assert_eq!(
            resumed.status,
            DecidedRunStatus::TokenBudgetExhausted {
                used: 120,
                max: 100
            }
        );
        assert_eq!(resumed_decider.calls, 0);
        assert!(resumed.rounds.iter().all(|round| round.resumed));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn decided_resume_reuses_journaled_decision_instead_of_reinfering() -> TestResult {
        let (root, journal_path) = journal_root("decided-resume")?;
        let ids = AgentRunIds::new("run-decided-resume", "session-decided-resume");
        {
            // A prior run journaled a decision but crashed before executing it.
            let mut journal = SessionJournal::open(
                &journal_path,
                RunId(ids.run_id.0.clone()),
                SessionId(ids.session_id.0.clone()),
            )?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
            journal.append(JournalEvent::Observation {
                observation: observation("https://example.com", 0),
            })?;
            journal.append(JournalEvent::ModelDecision {
                actions: vec![click("submit")],
                rationale: Some("journaled before crash".into()),
                input_tokens: 10,
                output_tokens: 5,
                cache_read_input_tokens: 0,
            })?;
        }

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        // Force a real navigation so the driver has page state to observe.
        driver.goto("https://example.com").await?;
        let runner = AgentRunner::new(&journal_path, ids).with_token_budget(TokenBudget::new(100));
        let mut decider = FixedUsageDecider {
            actions: Vec::new(),
            usage: DecisionUsage::default(),
            calls: 0,
        };
        let spec = DecidedTaskSpec::new("https://example.com", "click submit");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        assert_eq!(report.status, DecidedRunStatus::Completed);
        assert_eq!(report.actions_completed, 1);
        assert!(report.rounds[0].resumed);
        // Exactly one fresh decision (the done round) — the pending one was
        // replayed from the journal, not re-inferred.
        assert_eq!(decider.calls, 1);

        let entries = read_journal_entries(&journal_path)?;
        let decisions = entries
            .iter()
            .filter(|entry| matches!(entry.event, JournalEvent::ModelDecision { .. }))
            .count();
        assert_eq!(decisions, 2);
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn decided_resume_refuses_to_repeat_planned_but_unjournaled_step() -> TestResult {
        let (root, journal_path) = journal_root("decided-interrupt")?;
        let ids = AgentRunIds::new("run-decided-interrupt", "session-decided-interrupt");
        {
            let mut journal = SessionJournal::open(
                &journal_path,
                RunId(ids.run_id.0.clone()),
                SessionId(ids.session_id.0.clone()),
            )?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
            journal.append(JournalEvent::ModelDecision {
                actions: vec![click("submit")],
                rationale: None,
                input_tokens: 10,
                output_tokens: 5,
                cache_read_input_tokens: 0,
            })?;
            // Intent journaled, outcome missing: the side effect may have run.
            journal.append(JournalEvent::ActionPlanned {
                action: click("submit"),
            })?;
        }

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        driver.goto("https://example.com").await?;
        let runner = AgentRunner::new(&journal_path, ids).with_token_budget(TokenBudget::new(100));
        let mut decider = FixedUsageDecider {
            actions: Vec::new(),
            usage: DecisionUsage::default(),
            calls: 0,
        };
        let spec = DecidedTaskSpec::new("https://example.com", "click submit");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        assert_eq!(
            report.status,
            DecidedRunStatus::Interrupted {
                reason: RESUME_INTERRUPTED_REASON.to_string()
            }
        );
        assert_eq!(decider.calls, 0);
        let entries = read_journal_entries(&journal_path)?;
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::StepError { reason, .. } if reason == RESUME_INTERRUPTED_REASON
        )));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn decided_resume_surfaces_skill_rejection_after_crash() -> TestResult {
        let (root, journal_path) = journal_root("decided-skill-crash")?;
        let ids = AgentRunIds::new("run-decided-skill", "session-decided-skill");
        let skill = Action::Skill {
            name: "search".into(),
            input: serde_json::json!({ "q": "tempo" }),
        };
        {
            // A prior run journaled the skill rejection's intent but crashed
            // before its StepError outcome landed.
            let mut journal = SessionJournal::open(
                &journal_path,
                RunId(ids.run_id.0.clone()),
                SessionId(ids.session_id.0.clone()),
            )?;
            journal.append(JournalEvent::SessionStarted {
                url: "https://example.com".into(),
            })?;
            journal.append(JournalEvent::ModelDecision {
                actions: vec![skill.clone()],
                rationale: None,
                input_tokens: 10,
                output_tokens: 5,
                cache_read_input_tokens: 0,
            })?;
            journal.append(JournalEvent::ActionPlanned {
                action: skill.clone(),
            })?;
        }

        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        driver.goto("https://example.com").await?;
        let runner = AgentRunner::new(&journal_path, ids).with_token_budget(TokenBudget::new(100));
        let mut decider = FixedUsageDecider {
            actions: Vec::new(),
            usage: DecisionUsage::default(),
            calls: 0,
        };
        let spec = DecidedTaskSpec::new("https://example.com", "search");

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        // Skill rejection never runs a side effect, so crash-recovery surfaces
        // the same typed reason as live execution — not a generic Interrupted.
        let DecidedRunStatus::StepError { reason } = &report.status else {
            return Err(format!("expected skill StepError, got: {:?}", report.status).into());
        };
        assert!(reason.contains("does not execute skill actions"));
        assert_eq!(decider.calls, 0);
        let entries = read_journal_entries(&journal_path)?;
        assert!(entries.iter().any(|entry| matches!(
            &entry.event,
            JournalEvent::StepError { reason, .. }
                if reason.contains("does not execute skill actions")
        )));
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[tokio::test]
    async fn decided_run_respects_configured_round_ceiling() -> TestResult {
        let (root, journal_path) = journal_root("decided-round-limit")?;
        let mut driver = TestDriver::new().with_elements(vec![button("submit")]);
        let runner = AgentRunner::new(
            &journal_path,
            AgentRunIds::new("run-decided-rounds", "session-decided-rounds"),
        )
        .with_token_budget(TokenBudget::new(1_000));
        // Never reports done, so only the configured ceiling can stop the run.
        let mut decider = FixedUsageDecider {
            actions: vec![click("submit")],
            usage: DecisionUsage::default(),
            calls: 0,
        };
        let spec = DecidedTaskSpec::new("https://example.com", "click submit").with_max_rounds(2);

        let report = runner
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        assert_eq!(
            report.status,
            DecidedRunStatus::RoundLimitReached { max_rounds: 2 }
        );
        assert_eq!(decider.calls, 2);
        assert_eq!(report.rounds.len(), 2);
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn config_model_override_reaches_the_request_body() -> TestResult {
        let config = AnthropicConfig::new("test-key").with_model("claude-custom-model");
        let schema = tempo_schema::action_json_schema();
        let obs = observation("https://example.com", 1);
        let request = DecisionRequest {
            goal: "click submit",
            action_schema: &schema,
            observation: &obs,
            budget_remaining: 100,
        };

        let body = decide_request_body(&config, &request)
            .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
        assert_eq!(body["model"], serde_json::json!("claude-custom-model"));
        Ok(())
    }

    #[test]
    fn parse_decided_batch_lets_done_win_over_leftover_actions() -> TestResult {
        let response = decision_response(
            serde_json::json!([{ "kind": "click", "node": "submit" }]),
            true,
            (10, 2, 1),
        );
        let batch =
            parse_decided_batch(&response).map_err(|reason| -> Box<dyn Error> { reason.into() })?;
        assert!(batch.actions.is_empty());
        assert_eq!(batch.usage.cache_read_input_tokens, 1);
        Ok(())
    }

    /// Live end-to-end decide against the real Messages API. Hermetic CI never
    /// runs this: it is `#[ignore]` and additionally gated on
    /// `TEMPO_LIVE_MODEL=1` (plus `ANTHROPIC_API_KEY`).
    #[tokio::test]
    #[ignore = "live model call; run with TEMPO_LIVE_MODEL=1 and ANTHROPIC_API_KEY set"]
    async fn live_model_decides_next_action_for_fixture_observation() -> TestResult {
        if std::env::var("TEMPO_LIVE_MODEL").ok().as_deref() != Some("1") {
            return Ok(());
        }
        let mut decider = AnthropicDecider::new(AnthropicConfig::from_env()?)?;
        let schema = tempo_schema::action_json_schema();
        let obs = observation("https://example.com/login", 1);
        let request = DecisionRequest {
            goal: "Click the submit button on the page",
            action_schema: &schema,
            observation: &obs,
            budget_remaining: 50_000,
        };

        let decided = decider.decide(&request).await?;
        assert!(decided.usage.input_tokens > 0);
        assert!(decided.usage.output_tokens > 0);
        Ok(())
    }

    // --- #235: incremental observe_diff in the decided step loop -------------

    fn el(id: &str, rank: f32) -> tempo_schema::InteractiveElement {
        let mut element = button(id);
        element.rank = rank;
        element
    }

    fn captcha_element() -> tempo_schema::InteractiveElement {
        tempo_schema::InteractiveElement {
            node_id: NodeId("captcha".into()),
            role: "iframe".into(),
            name: vec![tempo_schema::TaintSpan {
                provenance: tempo_schema::Provenance::Page,
                text: "reCAPTCHA".into(),
            }],
            value: Vec::new(),
            bounds: None,
            rank: 1.0,
        }
    }

    fn type_action(node: &str) -> Action {
        Action::Type {
            node: NodeId(node.into()),
            text: "hello".into(),
        }
    }

    /// A scripted driver whose `observe` and `observe_diff` are mutually
    /// consistent: each `act` swaps to the next page state, and `observe_diff`
    /// returns the exact element delta from a recorded base (as a real engine
    /// does). `reject_diff` makes `observe_diff` return the "no base" full-add
    /// shape a real engine emits when it lacks the requested base seq, which the
    /// loop must detect and fall back on.
    struct DiffDriver {
        url: String,
        seq: u64,
        elements: Vec<tempo_schema::InteractiveElement>,
        pages: VecDeque<Vec<tempo_schema::InteractiveElement>>,
        history: std::collections::HashMap<u64, CompiledObservation>,
        reject_diff: bool,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl DiffDriver {
        fn new(
            initial: Vec<tempo_schema::InteractiveElement>,
            pages: Vec<Vec<tempo_schema::InteractiveElement>>,
            reject_diff: bool,
        ) -> Self {
            Self {
                url: "https://example.com/".into(),
                seq: 0,
                elements: initial,
                pages: pages.into(),
                history: std::collections::HashMap::new(),
                reject_diff,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn snapshot(&mut self) -> CompiledObservation {
            let observation = CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: self.url.clone(),
                seq: self.seq,
                elements: self.elements.clone(),
                marks: vec![],
            };
            self.history
                .entry(self.seq)
                .or_insert_with(|| observation.clone());
            observation
        }

        /// Exact element delta between the recorded base and the current page.
        fn true_diff(&self, since_seq: u64) -> ObservationDiff {
            let current = CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.into(),
                url: self.url.clone(),
                seq: self.seq,
                elements: self.elements.clone(),
                marks: vec![],
            };
            let base =
                self.history
                    .get(&since_seq)
                    .cloned()
                    .unwrap_or_else(|| CompiledObservation {
                        schema_version: tempo_schema::SCHEMA_VERSION.into(),
                        url: self.url.clone(),
                        seq: since_seq,
                        elements: Vec::new(),
                        marks: vec![],
                    });
            let before: HashSet<&str> =
                base.elements.iter().map(|e| e.node_id.0.as_str()).collect();
            let after: HashSet<&str> = current
                .elements
                .iter()
                .map(|e| e.node_id.0.as_str())
                .collect();
            let added = current
                .elements
                .iter()
                .filter(|e| !before.contains(e.node_id.0.as_str()))
                .cloned()
                .collect();
            let removed = base
                .elements
                .iter()
                .filter(|e| !after.contains(e.node_id.0.as_str()))
                .map(|e| e.node_id.clone())
                .collect();
            let changed = current
                .elements
                .iter()
                .filter(|e| {
                    base.elements
                        .iter()
                        .any(|b| b.node_id == e.node_id && b != *e)
                })
                .cloned()
                .collect();
            ObservationDiff {
                since_seq,
                seq: self.seq,
                added,
                removed,
                changed,
            }
        }
    }

    #[async_trait]
    impl DriverTrait for DiffDriver {
        fn engine(&self) -> tempo_driver::Engine {
            tempo_driver::Engine::Test
        }

        async fn goto(&mut self, _url: &str) -> Result<CompiledObservation, TransportError> {
            self.seq += 1;
            Ok(self.snapshot())
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            self.calls
                .lock()
                .map_err(|_| TransportError::Other("poisoned".into()))?
                .push("observe");
            Ok(self.snapshot())
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            self.calls
                .lock()
                .map_err(|_| TransportError::Other("poisoned".into()))?
                .push("observe_diff");
            let _ = self.snapshot();
            if self.reject_diff {
                // The "no base" shape: every current element reported as added.
                // Applied to a non-empty base this double-counts, so the loop
                // must reject it and full-observe instead.
                return Ok(ObservationDiff {
                    since_seq,
                    seq: self.seq,
                    added: self.elements.clone(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                });
            }
            Ok(self.true_diff(since_seq))
        }

        async fn act(
            &mut self,
            _action: &Action,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            if let Some(next) = self.pages.pop_front() {
                self.elements = next;
            }
            self.seq += 1;
            let _ = self.snapshot();
            Ok(tempo_driver::StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.seq - 1,
                    seq: self.seq,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                },
            })
        }

        async fn act_batch(
            &mut self,
            batch: &tempo_schema::ActionBatch,
        ) -> Result<tempo_driver::StepOutcome, TransportError> {
            let mut last = tempo_driver::StepOutcome::Applied {
                diff: self.true_diff(self.seq),
            };
            for action in &batch.actions {
                last = self.act(action).await?;
            }
            Ok(last)
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, tempo_driver::Unsupported> {
            Err(tempo_driver::Unsupported("diff driver does not fork"))
        }

        async fn extract(&mut self, _node: &NodeId) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }

        async fn evaluate_script(
            &mut self,
            _expression: &str,
            _await_promise: bool,
        ) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(Vec::new())
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn observation_events(entries: &[JournalEntry]) -> Vec<CompiledObservation> {
        entries
            .iter()
            .filter_map(|entry| match &entry.event {
                JournalEvent::Observation { observation } => Some(observation.clone()),
                _ => None,
            })
            .collect()
    }

    fn decision_actions(entries: &[JournalEntry]) -> Vec<Vec<Action>> {
        entries
            .iter()
            .filter_map(|entry| match &entry.event {
                JournalEvent::ModelDecision { actions, .. } => Some(actions.clone()),
                _ => None,
            })
            .collect()
    }

    /// (a) Equivalence: a decided run that reconstructs from `observe_diff`
    /// journals byte-identical observations and decisions to one forced onto the
    /// full-observe fallback, over the same scripted multi-step page script.
    #[tokio::test]
    async fn decided_incremental_observe_matches_full_observe() -> TestResult {
        // Two same-document (`Type`) steps: element mutates, then one is added.
        let script = || {
            (
                vec![el("a", 0.9)],
                vec![
                    vec![el("a", 0.5)],               // step 1: change rank of "a"
                    vec![el("a", 0.5), el("b", 0.7)], // step 2: add "b"
                ],
            )
        };
        let batches = || vec![vec![type_action("a")], vec![type_action("a")], vec![]];
        let spec = DecidedTaskSpec::new("https://example.com", "fill the form");

        let (root_inc, journal_inc) = journal_root("incremental-observe-inc")?;
        let (init, pages) = script();
        let mut inc_driver = DiffDriver::new(init, pages, false);
        let inc_calls = Arc::clone(&inc_driver.calls);
        let mut inc_decider = ScriptedDecider::new(batches());
        AgentRunner::new(&journal_inc, AgentRunIds::new("run-inc", "session-inc"))
            .run_decided_task(&mut inc_driver, &mut inc_decider, &spec)
            .await?;
        let inc_entries = read_journal_entries(&journal_inc)?;

        let (root_full, journal_full) = journal_root("incremental-observe-full")?;
        let (init, pages) = script();
        let mut full_driver = DiffDriver::new(init, pages, true);
        let full_calls = Arc::clone(&full_driver.calls);
        let mut full_decider = ScriptedDecider::new(batches());
        AgentRunner::new(&journal_full, AgentRunIds::new("run-full", "session-full"))
            .run_decided_task(&mut full_driver, &mut full_decider, &spec)
            .await?;
        let full_entries = read_journal_entries(&journal_full)?;

        // The reconstructed observations equal the full-observe ones.
        assert_eq!(
            observation_events(&inc_entries),
            observation_events(&full_entries),
            "reconstructed observations diverged from full observe"
        );
        assert_eq!(
            decision_actions(&inc_entries),
            decision_actions(&full_entries),
            "decisions diverged"
        );

        // The incremental run actually took the diff path and paid fewer full
        // observes than the forced-fallback run.
        let inc_calls = inc_calls.lock().map_err(|_| "poisoned")?.clone();
        let full_calls = full_calls.lock().map_err(|_| "poisoned")?.clone();
        assert!(
            inc_calls.contains(&"observe_diff"),
            "incremental run never issued observe_diff"
        );
        let inc_full = inc_calls.iter().filter(|c| **c == "observe").count();
        let fallback_full = full_calls.iter().filter(|c| **c == "observe").count();
        assert!(
            inc_full < fallback_full,
            "incremental run did not reduce full observes ({inc_full} vs {fallback_full})"
        );

        remove_dir_if_exists(&root_inc)?;
        remove_dir_if_exists(&root_full)?;
        Ok(())
    }

    /// (c) A CAPTCHA that appears as a diff `added` element after a same-document
    /// action is still detected: the takeover detector runs on the reconstructed
    /// observation, so the run hard-pauses without a full re-observe.
    #[tokio::test]
    async fn decided_incremental_observe_still_detects_takeover_mid_run() -> TestResult {
        let (root, journal) = journal_root("incremental-observe-takeover")?;
        let mut driver = DiffDriver::new(
            vec![el("a", 0.9)],
            vec![vec![el("a", 0.9), captcha_element()]],
            false,
        );
        let calls = Arc::clone(&driver.calls);
        let mut decider = ScriptedDecider::new(vec![vec![type_action("a")], vec![]]);
        let spec = DecidedTaskSpec::new("https://example.com", "type then stop");

        let report = AgentRunner::new(&journal, AgentRunIds::new("run-tk", "session-tk"))
            .run_decided_task(&mut driver, &mut decider, &spec)
            .await?;

        let DecidedRunStatus::HumanTakeoverRequired { takeover } = &report.status else {
            return Err(format!("expected HumanTakeoverRequired, got {:?}", report.status).into());
        };
        assert_eq!(takeover.kind, tempo_schema::TakeoverKind::Captcha);
        // The takeover was surfaced from the diff path, not a full re-observe.
        let calls = calls.lock().map_err(|_| "poisoned")?.clone();
        assert!(calls.contains(&"observe_diff"));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    /// (d) Overlap/ordering: effects are never reordered by the incremental path
    /// and each decision is made on the recorded (settled) observation. Two
    /// identical runs also produce byte-identical journals (determinism).
    #[tokio::test]
    async fn decided_incremental_observe_preserves_effect_ordering() -> TestResult {
        let run = |label: String| async move {
            let spec = DecidedTaskSpec::new("https://example.com", "two steps");
            let (root, journal) = journal_root(&label)?;
            let mut driver = DiffDriver::new(
                vec![el("a", 0.9)],
                vec![vec![el("a", 0.5)], vec![el("a", 0.5), el("b", 0.7)]],
                false,
            );
            let mut decider =
                ScriptedDecider::new(vec![vec![type_action("a")], vec![type_action("a")], vec![]]);
            AgentRunner::new(&journal, AgentRunIds::new(&label, &label))
                .run_decided_task(&mut driver, &mut decider, &spec)
                .await?;
            let entries = read_journal_entries(&journal)?;
            remove_dir_if_exists(&root)?;
            Ok::<Vec<JournalEntry>, Box<dyn Error>>(entries)
        };

        let first = run("incremental-observe-order-1".to_string()).await?;
        let second = run("incremental-observe-order-2".to_string()).await?;

        // Determinism: identical inputs -> identical journals.
        let kinds = |entries: &[JournalEntry]| {
            entries
                .iter()
                .map(|entry| std::mem::discriminant(&entry.event))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kinds(&first),
            kinds(&second),
            "journal ordering not deterministic"
        );

        // Within each executed step the effect order holds: a decision precedes
        // its planned action, which precedes the applied effect, which precedes
        // the observation the next decision runs on.
        let mut planned_before_applied = false;
        let mut prev_was_observation = false;
        let mut seen_first_decision = false;
        for entry in &first {
            match &entry.event {
                JournalEvent::ModelDecision { .. } => {
                    // Every decision after the first must run on a freshly
                    // recorded (settled) observation.
                    if seen_first_decision {
                        assert!(
                            prev_was_observation,
                            "decision made before the prior observation settled"
                        );
                    }
                    seen_first_decision = true;
                }
                JournalEvent::ActionPlanned { .. } => planned_before_applied = true,
                JournalEvent::StepApplied { .. } => {
                    assert!(
                        planned_before_applied,
                        "effect applied before it was planned"
                    );
                    planned_before_applied = false;
                }
                _ => {}
            }
            prev_was_observation = matches!(entry.event, JournalEvent::Observation { .. });
        }
        Ok(())
    }

    #[test]
    fn reconstruct_observation_inverts_a_consistent_diff() {
        let base = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.com/".into(),
            seq: 4,
            elements: vec![el("a", 0.9), el("b", 0.5)],
            marks: vec![],
        };
        // Change "a", remove "b", add "c".
        let diff = ObservationDiff {
            since_seq: 4,
            seq: 5,
            added: vec![el("c", 0.7)],
            removed: vec![NodeId("b".into())],
            changed: vec![el("a", 0.2)],
        };
        let Some(rebuilt) = reconstruct_observation(&base, &diff) else {
            panic!("consistent diff must reconstruct");
        };
        assert_eq!(rebuilt.seq, 5);
        assert_eq!(rebuilt.url, base.url);
        let ids: Vec<&str> = rebuilt
            .elements
            .iter()
            .map(|e| e.node_id.0.as_str())
            .collect();
        assert_eq!(ids, vec!["a", "c"]);
        assert_eq!(rebuilt.elements[0].rank, 0.2, "changed content not applied");
    }

    #[test]
    fn reconstruct_observation_falls_back_on_inequivalent_diffs() {
        let base = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.com/".into(),
            seq: 4,
            elements: vec![el("a", 0.9)],
            marks: vec![],
        };
        let ok = ObservationDiff {
            since_seq: 4,
            seq: 5,
            added: vec![],
            removed: vec![],
            changed: vec![],
        };
        // since_seq mismatch: diff not computed against our base.
        assert!(reconstruct_observation(
            &base,
            &ObservationDiff {
                since_seq: 3,
                ..ok.clone()
            }
        )
        .is_none());
        // "no base" full-add: an added node already present in the base.
        assert!(reconstruct_observation(
            &base,
            &ObservationDiff {
                added: vec![el("a", 0.9)],
                ..ok.clone()
            }
        )
        .is_none());
        // changed/removed referencing an unknown node.
        assert!(reconstruct_observation(
            &base,
            &ObservationDiff {
                changed: vec![el("z", 0.1)],
                ..ok.clone()
            }
        )
        .is_none());
        assert!(reconstruct_observation(
            &base,
            &ObservationDiff {
                removed: vec![NodeId("z".into())],
                ..ok.clone()
            }
        )
        .is_none());
        // A set-of-marks overlay the diff cannot reproduce.
        let marked = CompiledObservation {
            marks: vec![(NodeId("a".into()), 1)],
            ..base.clone()
        };
        assert!(reconstruct_observation(&marked, &ok).is_none());
    }

    #[test]
    fn only_navigating_actions_force_full_observe() {
        assert!(action_may_navigate(&click("x")));
        assert!(action_may_navigate(&Action::Goto {
            url: "https://e.com".into()
        }));
        assert!(action_may_navigate(&Action::Skill {
            name: "s".into(),
            input: serde_json::Value::Null
        }));
        assert!(!action_may_navigate(&type_action("x")));
        assert!(!action_may_navigate(&Action::Select {
            node: NodeId("x".into()),
            value: "v".into()
        }));
        assert!(!action_may_navigate(&Action::Scroll { x: 0.0, y: 1.0 }));
        assert!(!action_may_navigate(&Action::Wait { millis: 1 }));
        assert!(!action_may_navigate(&Action::Extract {
            node: NodeId("x".into())
        }));
    }
}
