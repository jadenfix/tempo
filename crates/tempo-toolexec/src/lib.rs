//! tempo-toolexec - beatbox bridge for sandboxed compute.
//!
//! Browser observation and action stay in tempo. Non-browser compute that may
//! touch untrusted page data is sent to the real beatbox client with a policy
//! that removes network and secret access by construction.

use std::{net::IpAddr, path::PathBuf};

pub use beatbox_client::{
    Client as BeatboxClient, ClientError as BeatboxClientError, CreateJobResponse, Determinism,
    EffectiveIsolation, EgressRecord, ErrorBody, ExecuteRequest, ExecutionResult, ExecutionStatus,
    FsPolicy, JobRecord, JobStatus, Lane, Limits, Metrics, Mount, MountMode, NetPolicy, Policy,
    Secret, Source,
};
use tempo_driver::StepOutcome;
use tempo_schema::ObservationDiff;
use tempo_schema::TaintSpan;
use thiserror::Error;
use url::{Host, Url};

/// Default wall-clock cap for transforms over tainted page content.
pub const TAINTED_WALL_MS: u64 = 2_000;

/// Default CPU cap for transforms over tainted page content.
pub const TAINTED_CPU_MS: u64 = 2_000;

/// Default memory cap for transforms over tainted page content.
pub const TAINTED_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Default stdout/stderr cap for transforms over tainted page content.
pub const TAINTED_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Default scratch-disk cap for transforms over tainted page content.
pub const TAINTED_DISK_BYTES: u64 = 64 * 1024 * 1024;

/// Default deterministic fuel cap for transforms over tainted page content.
pub const TAINTED_FUEL: u64 = 10_000_000;

/// Thin typed bridge over beatbox's real HTTP client.
#[derive(Clone)]
pub struct ToolExecClient {
    client: BeatboxClient,
    endpoint: BeatboxEndpoint,
}

/// Compatibility alias for callers that prefer the executor naming.
pub type ToolExecutor = ToolExecClient;

impl ToolExecClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, ToolExecError> {
        let endpoint = BeatboxEndpoint::parse(base_url)?;
        Ok(Self {
            client: BeatboxClient::new(endpoint.as_str()),
            endpoint,
        })
    }

    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Result<Self, ToolExecError> {
        self.endpoint.ensure_api_key_allowed()?;
        self.client = self.client.with_api_key(api_key);
        Ok(self)
    }

    /// Wrap an already-built beatbox client after validating the caller's
    /// endpoint metadata. Because the raw client may already carry credentials,
    /// injected clients are only accepted for endpoints where bearer transport
    /// is safe.
    pub fn from_validated_client(
        client: BeatboxClient,
        base_url: impl Into<String>,
    ) -> Result<Self, ToolExecError> {
        let endpoint = BeatboxEndpoint::parse(base_url)?;
        endpoint.ensure_api_key_allowed()?;
        Ok(Self { client, endpoint })
    }

    /// Compatibility constructor for dependency injection. A raw beatbox client
    /// does not expose enough endpoint/auth metadata for Tempo to prove bearer
    /// tokens cannot leak, so clients built this way are quarantined and cannot
    /// dispatch HTTP requests.
    pub fn from_client(client: BeatboxClient) -> Self {
        Self {
            client,
            endpoint: BeatboxEndpoint::unknown(),
        }
    }

    /// Execute a caller-built request whose policy has already been selected by
    /// trusted Tempo code.
    pub async fn execute_trusted_request(
        &self,
        request: &ExecuteRequest,
    ) -> Result<ToolExecution, ToolExecError> {
        self.endpoint.ensure_request_allowed()?;
        let result = self.client.execute(request).await?;
        Ok(ToolExecution::from_result(result))
    }

    /// Execute page-derived input through the tainted transform builder before
    /// dispatching to beatbox.
    pub async fn execute_tainted_transform(
        &self,
        transform: TaintedTransform,
    ) -> Result<ToolExecution, ToolExecError> {
        let request = transform.try_into_request()?;
        self.execute_trusted_request(&request).await
    }

    /// Create an async beatbox job from a trusted caller-built request.
    pub async fn create_trusted_job(
        &self,
        request: &ExecuteRequest,
    ) -> Result<CreateJobResponse, ToolExecError> {
        self.endpoint.ensure_request_allowed()?;
        Ok(self.client.create_job(request).await?)
    }

    /// Create an async beatbox job for page-derived input through the locked
    /// tainted transform policy.
    pub async fn create_tainted_transform_job(
        &self,
        transform: TaintedTransform,
    ) -> Result<CreateJobResponse, ToolExecError> {
        let request = transform.try_into_request()?;
        self.create_trusted_job(&request).await
    }

    pub async fn get_job(&self, job_id: &str) -> Result<JobRecord, ToolExecError> {
        self.endpoint.ensure_request_allowed()?;
        Ok(self.client.get_job(job_id).await?)
    }

    /// Fetch an async beatbox job and map it into Tempo's tool-step status and
    /// audit model when the job has produced an execution result.
    pub async fn get_tool_job(&self, job_id: &str) -> Result<ToolJob, ToolExecError> {
        let record = self.get_job(job_id).await?;
        Ok(ToolJob::from_record(record))
    }

    pub async fn cancel_job(&self, job_id: &str) -> Result<(), ToolExecError> {
        self.endpoint.ensure_request_allowed()?;
        Ok(self.client.cancel_job(job_id).await?)
    }
}

#[derive(Debug, Error)]
pub enum ToolExecError {
    #[error("tainted transform requires at least one page-derived C1 span")]
    UntaintedInput,
    #[error(transparent)]
    Endpoint(#[from] BeatboxEndpointError),
    #[error(transparent)]
    Beatbox(#[from] BeatboxClientError),
}

#[derive(Clone, Debug)]
struct BeatboxEndpoint {
    base_url: String,
    scheme: EndpointScheme,
    host: EndpointHost,
    validated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointScheme {
    Http,
    Https,
}

#[derive(Clone, Debug)]
enum EndpointHost {
    Ip(IpAddr),
    Domain(String),
    Unknown,
}

impl BeatboxEndpoint {
    fn parse(base_url: impl Into<String>) -> Result<Self, BeatboxEndpointError> {
        let base_url = base_url.into();
        let parsed = Url::parse(&base_url).map_err(|_| BeatboxEndpointError::InvalidBaseUrl)?;
        let scheme = match parsed.scheme() {
            "http" => EndpointScheme::Http,
            "https" => EndpointScheme::Https,
            _ => return Err(BeatboxEndpointError::UnsupportedScheme),
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(BeatboxEndpointError::ForbiddenUrlComponent("userinfo"));
        }
        if parsed.path() != "/" {
            return Err(BeatboxEndpointError::ForbiddenUrlComponent("path"));
        }
        if parsed.query().is_some() {
            return Err(BeatboxEndpointError::ForbiddenUrlComponent("query"));
        }
        if parsed.fragment().is_some() {
            return Err(BeatboxEndpointError::ForbiddenUrlComponent("fragment"));
        }
        let host = parsed
            .host()
            .ok_or(BeatboxEndpointError::MissingAuthority)
            .map(EndpointHost::from)?;

        Ok(Self {
            base_url,
            scheme,
            host,
            validated: true,
        })
    }

    fn unknown() -> Self {
        Self {
            base_url: String::new(),
            scheme: EndpointScheme::Http,
            host: EndpointHost::Unknown,
            validated: false,
        }
    }

    fn as_str(&self) -> &str {
        &self.base_url
    }

    fn ensure_api_key_allowed(&self) -> Result<(), BeatboxEndpointError> {
        self.ensure_request_allowed()?;
        if self.scheme == EndpointScheme::Https || self.host.is_loopback() {
            return Ok(());
        }
        Err(BeatboxEndpointError::PlaintextRemoteBearer)
    }

    fn ensure_request_allowed(&self) -> Result<(), BeatboxEndpointError> {
        if self.validated {
            Ok(())
        } else {
            Err(BeatboxEndpointError::UnvalidatedClient)
        }
    }
}

impl EndpointHost {
    fn is_loopback(&self) -> bool {
        match self {
            Self::Ip(ip) => ip.is_loopback(),
            Self::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            Self::Unknown => false,
        }
    }
}

impl From<Host<&str>> for EndpointHost {
    fn from(host: Host<&str>) -> Self {
        match host {
            Host::Domain(domain) => Self::Domain(domain.to_owned()),
            Host::Ipv4(addr) => Self::Ip(IpAddr::V4(addr)),
            Host::Ipv6(addr) => Self::Ip(IpAddr::V6(addr)),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BeatboxEndpointError {
    #[error("beatbox base URL must be a valid absolute URL")]
    InvalidBaseUrl,
    #[error("beatbox base URL must use http or https")]
    UnsupportedScheme,
    #[error("beatbox base URL must include an authority")]
    MissingAuthority,
    #[error("beatbox base URL must not include {0}")]
    ForbiddenUrlComponent(&'static str),
    #[error("beatbox API keys require https or explicit loopback http")]
    PlaintextRemoteBearer,
    #[error("beatbox API keys require a Tempo-validated endpoint")]
    UnvalidatedClient,
}

/// Tempo-facing execution result. It keeps the original beatbox result intact
/// and adds the policy/audit interpretation tempo journals per step.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolExecution {
    pub result: ExecutionResult,
    pub step_status: ToolStepStatus,
    pub audit: ToolAudit,
}

impl ToolExecution {
    pub fn from_result(result: ExecutionResult) -> Self {
        let step_status = ToolStepStatus::from_result(&result);
        let audit = ToolAudit::from_result(&result);
        Self {
            result,
            step_status,
            audit,
        }
    }

    /// Convert the beatbox result into the canonical driver step model used by
    /// session journals. Tool execution does not mutate browser state, so a
    /// successful tool step carries an empty diff at the caller-supplied cursor.
    pub fn to_step_outcome(&self, since_seq: u64, seq: u64) -> StepOutcome {
        self.step_status.to_step_outcome(since_seq, seq)
    }
}

/// Step-level status tempo records for tool execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolStepStatus {
    Applied,
    StepError { reason: String },
}

impl ToolStepStatus {
    pub fn from_result(result: &ExecutionResult) -> Self {
        match result.status {
            ExecutionStatus::Ok => Self::Applied,
            ExecutionStatus::Denied => {
                Self::step_error(result, "beatbox denied execution by policy")
            }
            ExecutionStatus::Timeout => Self::step_error(result, "beatbox execution timed out"),
            ExecutionStatus::Oom => Self::step_error(result, "beatbox execution exceeded memory"),
            ExecutionStatus::Killed => Self::step_error(result, "beatbox execution was killed"),
            ExecutionStatus::Error => Self::step_error(result, "beatbox execution failed"),
        }
    }

    fn step_error(result: &ExecutionResult, fallback: &str) -> Self {
        let reason = result
            .error
            .as_ref()
            .map(|error| error.message.clone())
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| fallback.into());
        Self::StepError { reason }
    }

    pub fn to_step_outcome(&self, since_seq: u64, seq: u64) -> StepOutcome {
        match self {
            Self::Applied => StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq,
                    seq,
                    omitted: 0,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                },
            },
            Self::StepError { reason } => StepOutcome::StepError {
                reason: reason.clone(),
            },
        }
    }
}

/// Tempo-facing async job record. The raw beatbox record is preserved, while
/// `state` exposes the step/audit interpretation callers need for journaling.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolJob {
    pub record: JobRecord,
    pub state: ToolJobState,
}

impl ToolJob {
    pub fn from_record(record: JobRecord) -> Self {
        let state = ToolJobState::from_record(&record);
        Self { record, state }
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// Async beatbox job state after translating terminal records into Tempo's
/// tool-step model.
#[derive(Clone, Debug, PartialEq)]
pub enum ToolJobState {
    Pending { status: JobStatus },
    Finished { execution: Box<ToolExecution> },
    StepError { status: JobStatus, reason: String },
}

impl ToolJobState {
    pub fn from_record(record: &JobRecord) -> Self {
        match record.status {
            JobStatus::Queued | JobStatus::Running => Self::Pending {
                status: record.status.clone(),
            },
            JobStatus::Succeeded => match record.result.clone() {
                Some(result) => Self::Finished {
                    execution: Box::new(ToolExecution::from_result(result)),
                },
                None => Self::StepError {
                    status: JobStatus::Succeeded,
                    reason: "beatbox job succeeded without an execution result".into(),
                },
            },
            JobStatus::Failed => Self::StepError {
                status: JobStatus::Failed,
                reason: job_error_reason(
                    record,
                    "beatbox job failed before an execution result was produced",
                ),
            },
            JobStatus::Canceled => Self::StepError {
                status: JobStatus::Canceled,
                reason: job_error_reason(record, "beatbox job was canceled"),
            },
        }
    }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }
}

fn job_error_reason(record: &JobRecord, fallback: &str) -> String {
    record
        .error
        .as_ref()
        .map(|error| error.message.clone())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| fallback.into())
}

/// Audit subset tempo joins with session and network records.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolAudit {
    pub status: ExecutionStatus,
    pub lane: Lane,
    pub deterministic: bool,
    pub inputs_digest: String,
    pub engine_version: String,
    pub beatbox_version: String,
    pub metrics: Metrics,
    pub effective_isolation: EffectiveIsolation,
    pub egress: Vec<EgressRecord>,
}

impl ToolAudit {
    pub fn from_result(result: &ExecutionResult) -> Self {
        Self {
            status: result.status.clone(),
            lane: result.lane.clone(),
            deterministic: result.deterministic,
            inputs_digest: result.inputs_digest.clone(),
            engine_version: result.engine_version.clone(),
            beatbox_version: result.beatbox_version.clone(),
            metrics: result.metrics.clone(),
            effective_isolation: result.effective_isolation.clone(),
            egress: result.egress.clone(),
        }
    }

    pub fn has_egress(&self) -> bool {
        !self.egress.is_empty()
    }

    pub fn isolation_downgraded(&self) -> bool {
        !self.effective_isolation.downgrades.is_empty()
    }
}

/// Typed evidence for the final.md taint x sandbox canary.
///
/// The caller owns the canary endpoint and passes the observed hit count after
/// executing a tainted transform through beatbox. A passing report means tempo
/// sent the transform with a sealed beatbox policy and beatbox reported no
/// egress while the canary observed no traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintedSandboxCanaryReport {
    pub policy_net_denied: bool,
    pub secrets_empty: bool,
    pub beatbox_status: ExecutionStatus,
    pub beatbox_egress_empty: bool,
    pub canary_hit_count: usize,
    pub violations: Vec<TaintedSandboxViolation>,
}

impl TaintedSandboxCanaryReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Concrete reason the tainted sandbox canary failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaintedSandboxViolation {
    NetworkPolicyAllowed,
    SecretsInScope,
    BeatboxReportedEgress,
    CanaryEndpointHit { hit_count: usize },
}

/// Build the evidence object for a live tainted-transform canary run.
pub fn tainted_sandbox_canary_report(
    request: &ExecuteRequest,
    execution: &ToolExecution,
    canary_hit_count: usize,
) -> TaintedSandboxCanaryReport {
    let policy_net_denied = matches!(request.policy.net, NetPolicy::Deny);
    let secrets_empty = request.policy.secrets.is_empty();
    let beatbox_egress_empty = execution.audit.egress.is_empty();
    let mut violations = Vec::new();

    if !policy_net_denied {
        violations.push(TaintedSandboxViolation::NetworkPolicyAllowed);
    }
    if !secrets_empty {
        violations.push(TaintedSandboxViolation::SecretsInScope);
    }
    if !beatbox_egress_empty {
        violations.push(TaintedSandboxViolation::BeatboxReportedEgress);
    }
    if canary_hit_count > 0 {
        violations.push(TaintedSandboxViolation::CanaryEndpointHit {
            hit_count: canary_hit_count,
        });
    }

    TaintedSandboxCanaryReport {
        policy_net_denied,
        secrets_empty,
        beatbox_status: execution.audit.status.clone(),
        beatbox_egress_empty,
        canary_hit_count,
        violations,
    }
}

/// Input value plus C1 provenance spans.
#[derive(Clone, Debug, PartialEq)]
pub struct ProvenancedInput {
    pub value: serde_json::Value,
    pub spans: Vec<TaintSpan>,
}

impl ProvenancedInput {
    pub fn new(value: serde_json::Value, spans: Vec<TaintSpan>) -> Self {
        Self { value, spans }
    }

    pub fn contains_taint(&self) -> bool {
        input_contains_taint(&self.spans)
    }
}

/// Builder for the taint x sandbox rule in `final.md` §6.2.
#[derive(Clone, Debug, PartialEq)]
pub struct TaintedTransform {
    pub lane: Lane,
    pub source: Source,
    pub input: ProvenancedInput,
    pub session_scratch: Option<PathBuf>,
    pub idempotency_key: String,
    pub determinism: Determinism,
}

impl TaintedTransform {
    /// Build the exact beatbox request for page-derived content.
    pub fn try_into_request(self) -> Result<ExecuteRequest, ToolExecError> {
        if !self.input.contains_taint() {
            return Err(ToolExecError::UntaintedInput);
        }

        Ok(tainted_transform_request(
            self.lane,
            self.source,
            self.input.value,
            self.session_scratch,
            self.idempotency_key,
            self.determinism,
        ))
    }
}

/// Build the locked-down request required for transforms over tainted page data.
pub fn tainted_transform_request(
    lane: Lane,
    source: Source,
    input: serde_json::Value,
    session_scratch: Option<PathBuf>,
    idempotency_key: impl Into<String>,
    determinism: Determinism,
) -> ExecuteRequest {
    ExecuteRequest {
        lane,
        source,
        entrypoint: None,
        input,
        stdin: String::new(),
        policy: tainted_transform_policy(session_scratch, determinism),
        idempotency_key: Some(idempotency_key.into()),
    }
}

/// Policy for tainted page transforms: no network, no secrets, bounded resources,
/// deterministic when requested, and double-jail enabled.
pub fn tainted_transform_policy(
    session_scratch: Option<PathBuf>,
    determinism: Determinism,
) -> Policy {
    Policy {
        fs: FsPolicy {
            workspace: session_scratch,
            mounts: Vec::new(),
        },
        net: NetPolicy::Deny,
        env: Default::default(),
        secrets: Vec::new(),
        limits: Limits {
            wall_ms: TAINTED_WALL_MS,
            cpu_ms: TAINTED_CPU_MS,
            memory_bytes: TAINTED_MEMORY_BYTES,
            output_bytes: TAINTED_OUTPUT_BYTES,
            pids: 1,
            disk_bytes: TAINTED_DISK_BYTES,
            fuel: Some(TAINTED_FUEL),
        },
        determinism,
        double_jail: true,
    }
}

/// Collapse schema spans into the routing predicate used by callers before they
/// decide whether to apply the locked-down tainted transform policy.
pub fn input_contains_taint<'a>(spans: impl IntoIterator<Item = &'a TaintSpan>) -> bool {
    spans.into_iter().any(TaintSpan::is_tainted)
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "sandboxed tool exec bridge to beatbox (wasmtime/python/js/exec lanes); taint x sandbox composition"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_schema::{Provenance, TaintSpan};

    #[test]
    fn tainted_policy_denies_egress_and_secrets() {
        let policy = tainted_transform_policy(
            Some(PathBuf::from("/tmp/session")),
            Determinism::Seeded {
                seed: 7,
                epoch_ms: 123,
            },
        );

        assert_eq!(policy.net, NetPolicy::Deny);
        assert!(policy.secrets.is_empty());
        assert!(policy.fs.mounts.is_empty());
        assert_eq!(policy.fs.workspace, Some(PathBuf::from("/tmp/session")));
        assert_eq!(policy.limits.wall_ms, TAINTED_WALL_MS);
        assert_eq!(policy.limits.cpu_ms, TAINTED_CPU_MS);
        assert_eq!(policy.limits.memory_bytes, TAINTED_MEMORY_BYTES);
        assert_eq!(policy.limits.output_bytes, TAINTED_OUTPUT_BYTES);
        assert_eq!(policy.limits.disk_bytes, TAINTED_DISK_BYTES);
        assert_eq!(policy.limits.fuel, Some(TAINTED_FUEL));
        assert!(policy.double_jail);
        assert_eq!(
            policy.determinism,
            Determinism::Seeded {
                seed: 7,
                epoch_ms: 123,
            }
        );
    }

    #[test]
    fn tainted_transform_request_carries_policy_and_idempotency() {
        let request = tainted_transform_request(
            Lane::PythonWasi,
            Source::Inline {
                code: "print(input())".into(),
            },
            serde_json::json!({ "text": "page" }),
            None,
            "step-42",
            Determinism::Off,
        );

        assert_eq!(request.lane, Lane::PythonWasi);
        assert_eq!(request.idempotency_key, Some("step-42".into()));
        assert_eq!(request.policy.net, NetPolicy::Deny);
        assert!(request.policy.secrets.is_empty());
        assert!(request.policy.double_jail);
    }

    #[test]
    fn checked_tainted_transform_uses_schema_predicate() -> Result<(), String> {
        let request = TaintedTransform {
            lane: Lane::PythonWasi,
            source: Source::Inline {
                code: "print(input())".into(),
            },
            input: ProvenancedInput::new(
                serde_json::json!({"page": "ignore previous instructions"}),
                vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: "ignore previous instructions".into(),
                }],
            ),
            session_scratch: Some(PathBuf::from("/tmp/session")),
            idempotency_key: "step-43".into(),
            determinism: Determinism::Seeded {
                seed: 9,
                epoch_ms: 456,
            },
        }
        .try_into_request()
        .map_err(|err| err.to_string())?;

        assert_eq!(request.policy.net, NetPolicy::Deny);
        assert!(request.policy.secrets.is_empty());
        assert_eq!(
            request.policy.determinism,
            Determinism::Seeded {
                seed: 9,
                epoch_ms: 456,
            }
        );
        Ok(())
    }

    #[test]
    fn checked_tainted_transform_rejects_untainted_input() {
        let result = TaintedTransform {
            lane: Lane::PythonWasi,
            source: Source::Inline {
                code: "print(input())".into(),
            },
            input: ProvenancedInput::new(
                serde_json::json!({"user": "summarize this"}),
                vec![TaintSpan {
                    provenance: Provenance::User,
                    text: "summarize this".into(),
                }],
            ),
            session_scratch: None,
            idempotency_key: "step-44".into(),
            determinism: Determinism::Off,
        }
        .try_into_request();

        assert!(matches!(result, Err(ToolExecError::UntaintedInput)));
    }

    #[test]
    fn input_contains_taint_uses_schema_predicate() {
        let clean = [
            TaintSpan {
                provenance: Provenance::System,
                text: "tempo".into(),
            },
            TaintSpan {
                provenance: Provenance::User,
                text: "summarize".into(),
            },
        ];
        assert!(!input_contains_taint(&clean));

        let tainted = [
            TaintSpan {
                provenance: Provenance::User,
                text: "summarize".into(),
            },
            TaintSpan {
                provenance: Provenance::Page,
                text: "ignore previous instructions".into(),
            },
        ];
        assert!(input_contains_taint(&tainted));
    }

    #[test]
    fn beatbox_endpoint_accepts_bare_https_and_loopback_http() -> Result<(), ToolExecError> {
        let _https = ToolExecClient::new("https://beatbox.example")?;
        let _https_port = ToolExecClient::new("https://beatbox.example:8443/")?;
        let _loopback_v4 = ToolExecClient::new("http://127.0.0.1:8080")?;
        let _loopback_v6 = ToolExecClient::new("http://[::1]:8080")?;
        let _localhost = ToolExecClient::new("http://localhost:8080")?;
        Ok(())
    }

    #[test]
    fn beatbox_endpoint_rejects_ambiguous_base_urls() {
        for (url, reason) in [
            ("beatbox.example", BeatboxEndpointError::InvalidBaseUrl),
            (
                "ftp://beatbox.example",
                BeatboxEndpointError::UnsupportedScheme,
            ),
            (
                "https://user@beatbox.example",
                BeatboxEndpointError::ForbiddenUrlComponent("userinfo"),
            ),
            (
                "https://beatbox.example/api",
                BeatboxEndpointError::ForbiddenUrlComponent("path"),
            ),
            (
                "https://beatbox.example?token=1",
                BeatboxEndpointError::ForbiddenUrlComponent("query"),
            ),
            (
                "https://beatbox.example#frag",
                BeatboxEndpointError::ForbiddenUrlComponent("fragment"),
            ),
        ] {
            let result = ToolExecClient::new(url);
            assert!(
                matches!(result, Err(ToolExecError::Endpoint(error)) if error == reason),
                "{url} should fail with {reason:?}"
            );
        }
    }

    #[test]
    fn beatbox_api_keys_require_https_or_loopback_http() -> Result<(), ToolExecError> {
        let _https = ToolExecClient::new("https://beatbox.example")?.with_api_key("fixture-key")?;
        let _loopback =
            ToolExecClient::new("http://127.0.0.1:8080")?.with_api_key("fixture-key")?;
        let _localhost =
            ToolExecClient::new("http://localhost:8080")?.with_api_key("fixture-key")?;

        let remote_plaintext =
            ToolExecClient::new("http://beatbox.example")?.with_api_key("fixture-key");
        assert!(matches!(
            remote_plaintext,
            Err(ToolExecError::Endpoint(
                BeatboxEndpointError::PlaintextRemoteBearer
            ))
        ));

        let injected = ToolExecClient::from_client(BeatboxClient::new("https://beatbox.example"))
            .with_api_key("fixture-key");
        assert!(matches!(
            injected,
            Err(ToolExecError::Endpoint(
                BeatboxEndpointError::UnvalidatedClient
            ))
        ));
        Ok(())
    }

    #[test]
    fn beatbox_validated_injected_clients_require_credential_safe_endpoint(
    ) -> Result<(), ToolExecError> {
        let _https = ToolExecClient::from_validated_client(
            BeatboxClient::new("https://beatbox.example").with_api_key("fixture-key"),
            "https://beatbox.example",
        )?;
        let _loopback = ToolExecClient::from_validated_client(
            BeatboxClient::new("http://127.0.0.1:8080").with_api_key("fixture-key"),
            "http://127.0.0.1:8080",
        )?;

        let remote_plaintext = ToolExecClient::from_validated_client(
            BeatboxClient::new("http://beatbox.example").with_api_key("fixture-key"),
            "http://beatbox.example",
        );
        assert!(matches!(
            remote_plaintext,
            Err(ToolExecError::Endpoint(
                BeatboxEndpointError::PlaintextRemoteBearer
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn raw_injected_clients_reject_dispatch_before_network() {
        let raw = BeatboxClient::new("http://203.0.113.1:9").with_api_key("fixture-key");
        let executor = ToolExecClient::from_client(raw);

        let result = executor
            .execute_trusted_request(&live_smoke_request("tempo-toolexec-raw-injected"))
            .await;

        assert!(matches!(
            result,
            Err(ToolExecError::Endpoint(
                BeatboxEndpointError::UnvalidatedClient
            ))
        ));
    }

    #[test]
    fn denied_result_maps_to_step_error_and_preserves_audit() {
        let result = execution_result(
            ExecutionStatus::Denied,
            Some(ErrorBody::new("policy_denied", "network denied")),
            Vec::new(),
        );
        let execution = ToolExecution::from_result(result);

        assert_eq!(
            execution.step_status,
            ToolStepStatus::StepError {
                reason: "network denied".into(),
            }
        );
        assert_eq!(execution.audit.status, ExecutionStatus::Denied);
        assert_eq!(execution.audit.lane, Lane::PythonWasi);
        assert_eq!(execution.audit.metrics.wall_time_ms, 10);
        assert!(!execution.audit.has_egress());
        assert!(!execution.audit.isolation_downgraded());
        match execution.to_step_outcome(7, 8) {
            StepOutcome::StepError { reason } => assert_eq!(reason, "network denied"),
            other => panic!("expected canonical step error, got {other:?}"),
        }
    }

    #[test]
    fn ok_result_maps_to_applied_and_records_egress() {
        let result = execution_result(
            ExecutionStatus::Ok,
            None,
            vec![EgressRecord {
                domain: "example.com".into(),
                port: 443,
                bytes: 100,
            }],
        );
        let execution = ToolExecution::from_result(result);

        assert_eq!(execution.step_status, ToolStepStatus::Applied);
        assert!(execution.audit.has_egress());
        assert_eq!(execution.audit.inputs_digest, "sha256:test");
        match execution.to_step_outcome(12, 13) {
            StepOutcome::Applied { diff } => {
                assert_eq!(diff.since_seq, 12);
                assert_eq!(diff.seq, 13);
                assert!(diff.added.is_empty());
                assert!(diff.removed.is_empty());
                assert!(diff.changed.is_empty());
            }
            other => panic!("expected canonical applied outcome, got {other:?}"),
        }
    }

    #[test]
    fn succeeded_job_maps_result_to_tool_execution() {
        let record = job_record(
            JobStatus::Succeeded,
            Some(execution_result(ExecutionStatus::Ok, None, Vec::new())),
            None,
        );
        let job = ToolJob::from_record(record);

        assert!(job.is_terminal());
        match job.state {
            ToolJobState::Finished { execution } => {
                assert_eq!(execution.step_status, ToolStepStatus::Applied);
                assert_eq!(execution.audit.inputs_digest, "sha256:test");
            }
            other => panic!("expected finished job, got {other:?}"),
        }
    }

    #[test]
    fn running_job_remains_pending() {
        let record = job_record(JobStatus::Running, None, None);
        let job = ToolJob::from_record(record);

        assert!(!job.is_terminal());
        assert_eq!(
            job.state,
            ToolJobState::Pending {
                status: JobStatus::Running
            }
        );
    }

    #[test]
    fn failed_job_maps_error_body_to_step_error() {
        let record = job_record(
            JobStatus::Failed,
            None,
            Some(ErrorBody::new("worker", "worker crashed")),
        );
        let job = ToolJob::from_record(record);

        assert!(job.is_terminal());
        assert_eq!(
            job.state,
            ToolJobState::StepError {
                status: JobStatus::Failed,
                reason: "worker crashed".into(),
            }
        );
    }

    #[test]
    fn succeeded_job_without_result_is_step_error() {
        let record = job_record(JobStatus::Succeeded, None, None);
        let job = ToolJob::from_record(record);

        assert!(job.is_terminal());
        assert_eq!(
            job.state,
            ToolJobState::StepError {
                status: JobStatus::Succeeded,
                reason: "beatbox job succeeded without an execution result".into(),
            }
        );
    }

    #[tokio::test]
    async fn tainted_transform_execution_rejects_untainted_input_before_dispatch(
    ) -> Result<(), ToolExecError> {
        let executor = ToolExecClient::new("http://127.0.0.1:1")?;
        let result = executor
            .execute_tainted_transform(TaintedTransform {
                lane: Lane::PythonWasi,
                source: Source::Inline {
                    code: "print(input())".into(),
                },
                input: ProvenancedInput::new(
                    serde_json::json!({"user": "summarize this"}),
                    vec![TaintSpan {
                        provenance: Provenance::User,
                        text: "summarize this".into(),
                    }],
                ),
                session_scratch: None,
                idempotency_key: "step-45".into(),
                determinism: Determinism::Off,
            })
            .await;

        assert!(matches!(result, Err(ToolExecError::UntaintedInput)));
        Ok(())
    }

    #[tokio::test]
    async fn tainted_transform_job_rejects_untainted_input_before_dispatch(
    ) -> Result<(), ToolExecError> {
        let executor = ToolExecClient::new("http://127.0.0.1:1")?;
        let result = executor
            .create_tainted_transform_job(TaintedTransform {
                lane: Lane::PythonWasi,
                source: Source::Inline {
                    code: "print(input())".into(),
                },
                input: ProvenancedInput::new(
                    serde_json::json!({"user": "summarize this"}),
                    vec![TaintSpan {
                        provenance: Provenance::User,
                        text: "summarize this".into(),
                    }],
                ),
                session_scratch: None,
                idempotency_key: "step-46".into(),
                determinism: Determinism::Off,
            })
            .await;

        assert!(matches!(result, Err(ToolExecError::UntaintedInput)));
        Ok(())
    }

    #[test]
    fn tainted_canary_report_flags_policy_and_egress_violations() {
        let mut request = live_smoke_request("tempo-toolexec-canary-violation");
        request.policy.net = NetPolicy::Proxy {
            allow_domains: vec!["example.com".into()],
            allow_ports: vec![443],
        };
        let execution = ToolExecution::from_result(execution_result(
            ExecutionStatus::Ok,
            None,
            vec![EgressRecord {
                domain: "example.com".into(),
                port: 443,
                bytes: 10,
            }],
        ));

        let report = tainted_sandbox_canary_report(&request, &execution, 1);

        assert!(!report.passed());
        assert_eq!(
            report.violations,
            vec![
                TaintedSandboxViolation::NetworkPolicyAllowed,
                TaintedSandboxViolation::BeatboxReportedEgress,
                TaintedSandboxViolation::CanaryEndpointHit { hit_count: 1 },
            ]
        );
    }

    fn live_smoke_request(idempotency_key: &str) -> ExecuteRequest {
        ExecuteRequest {
            lane: Lane::Wasm,
            source: Source::WasmWat {
                text: r#"
                    (module
                      (func (export "run") (result i64)
                        i64.const 42))
                "#
                .into(),
            },
            entrypoint: None,
            input: serde_json::Value::Null,
            stdin: String::new(),
            policy: Policy::default(),
            idempotency_key: Some(idempotency_key.into()),
        }
    }

    fn execution_result(
        status: ExecutionStatus,
        error: Option<ErrorBody>,
        egress: Vec<EgressRecord>,
    ) -> ExecutionResult {
        ExecutionResult {
            status,
            value: serde_json::Value::Null,
            exit_code: None,
            stdout: String::new(),
            stdout_truncated: false,
            stderr: String::new(),
            stderr_truncated: false,
            error,
            metrics: Metrics {
                wall_time_ms: 10,
                cpu_time_ms: 8,
                fuel_used: Some(100),
                peak_memory_bytes: Some(1024),
            },
            lane: Lane::PythonWasi,
            deterministic: true,
            inputs_digest: "sha256:test".into(),
            engine_version: "engine-test".into(),
            beatbox_version: "beatbox-test".into(),
            effective_isolation: EffectiveIsolation {
                os: "linux".into(),
                mechanisms: vec!["landlock".into()],
                landlock_abi: Some(3),
                downgrades: Vec::new(),
            },
            egress,
        }
    }

    fn job_record(
        status: JobStatus,
        result: Option<ExecutionResult>,
        error: Option<ErrorBody>,
    ) -> JobRecord {
        JobRecord {
            job_id: "job-test".into(),
            status,
            request: live_smoke_request("tempo-toolexec-job-record"),
            result,
            error,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:01Z".into(),
        }
    }
}
