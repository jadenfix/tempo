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
    is_policy_denial_reason, policy_denied_reason, AgentError, AgentRunner, DriverStep,
    IdempotencyKey, TokenBudget, RESUME_INTERRUPTED_REASON,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tempo_act::{execute_action, ExecutionStatus};
use tempo_driver::{DriverTrait, TransportError};
use tempo_policy::Origin;
use tempo_schema::{Action, CompiledObservation};
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

enum CappedBodyError {
    TooLarge { max_bytes: usize },
    Transport(String),
}

/// Reads a response body while enforcing a hard byte cap, mirroring the MCP
/// client's `max_body_bytes` guard (#212/#215): reject early when the
/// advertised `Content-Length` exceeds the cap, then accumulate chunks and
/// error as soon as the received bytes would cross it.
async fn read_body_capped(
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
            // A step whose intent was journaled in a prior run but never
            // completed may already have run its side effect: do not repeat it.
            if dangling_planned && index == executed {
                let reason = RESUME_INTERRUPTED_REASON.to_string();
                state.journal.append(JournalEvent::StepError {
                    action: action.clone(),
                    reason: reason.clone(),
                })?;
                state.actions_completed += 1;
                return Ok(Some(DecidedRunStatus::Interrupted { reason }));
            }

            // Model-decided skills are out of scope for the first decided loop:
            // fail the step with a typed, journaled error rather than silently
            // skipping the skill store and its policy snapshot machinery (#98).
            if matches!(action, Action::Skill { .. }) {
                let reason =
                    "decided loop does not execute skill actions; decide concrete actions instead"
                        .to_string();
                state.journal.append(JournalEvent::ActionPlanned {
                    action: action.clone(),
                })?;
                state.journal.append(JournalEvent::StepError {
                    action: action.clone(),
                    reason: reason.clone(),
                })?;
                state.actions_completed += 1;
                return Ok(Some(DecidedRunStatus::StepError { reason }));
            }

            let step = DriverStep::clean(action.clone());
            let key = IdempotencyKey::for_action(index, action)?;
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

            let next = driver.observe().await.map_err(|source| {
                decided_transport_error(&mut state.journal, "decided post-action observe", source)
            })?;
            *observation =
                self.record_decided_observation(state, next, "decided post-action observation")?;

            if let Some(reason) = step_error {
                return Ok(Some(DecidedRunStatus::StepError { reason }));
            }
        }
        Ok(None)
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
}
