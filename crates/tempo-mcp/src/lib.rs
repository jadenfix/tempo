//! tempo-mcp - MCP protocol core for driving a tempo session.
//!
//! This crate is transport-neutral: `tempod` owns HTTP sockets, while this
//! module owns Streamable HTTP JSON-RPC semantics, Origin validation, tool
//! descriptors, and calls into the real `DriverTrait` and handshake contracts.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use tempo_driver::{
    output_cap_message, DriverTrait, Engine, StepOutcome, MAX_EXTRACT_JSON_BYTES,
    MAX_PROTOCOL_RESPONSE_BYTES, MAX_SCREENSHOT_BYTES,
};
use tempo_handshake::{
    decide_lane, probe_http_origin, probe_urls, HttpProbeConfig, HttpProbeFailure,
    Lane as HandshakeLane, ProbeHit, ProbeReport, ProbeResponse, StructuredSignal, WebMcpDetection,
    WEB_MCP_DETECTION_SCRIPT,
};
use tempo_observe::composite_set_of_marks_png;
use tempo_policy::trust::{
    action_caller_texts, gate_boundary_action, requires_observation_evidence, CallerPolicyClaims,
    ConfirmationRequired,
};
use tempo_policy::Origin;
use tempo_schema::{action_json_schema, Action, ActionBatch, NodeId};
use thiserror::Error;
use url::{Host, Url};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub const A2A_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
pub const A2A_AGENT_JSON_PATH: &str = "/.well-known/agent.json";
pub const A2A_AGENT_CARD_CONTENT_TYPE: &str = "application/a2a+json";
const DRIVER_REQUIRED_ERROR_CODE: i64 = -32002;
const RESPONSE_TOO_LARGE_ERROR_CODE: i64 = -32003;
/// The targeted driver (root or fork) is owned by another in-flight tool call
/// and was not returned within [`DRIVER_LEASE_TIMEOUT`].
const DRIVER_BUSY_ERROR_CODE: i64 = -32004;
const TOOL_TEXT_SUMMARY_MAX_CHARS: usize = 240;
const HANDSHAKE_PROBE_LIMIT_ERROR_CODE: &str = "handshake_probe_limit";
/// Upper bound on concurrently live forked drivers per session. Forks each hold a
/// live browser context/target for real engines, so refuse to accumulate beyond
/// this cap and require the client to `close_fork` before creating more.
const MAX_LIVE_FORKS: usize = 32;
/// Process/default cap on simultaneous live HTTP handshake probe runs. Each run
/// fans out to several blocking HTTP workers, so this bounds the inner thread
/// multiplier instead of only bounding request body size.
pub const MAX_CONCURRENT_HANDSHAKE_PROBES: usize = 4;
/// Bound on how long a tool call waits for another in-flight call on the SAME
/// driver (root or fork) before failing (issue #230). Tool calls on different
/// drivers never wait on each other; this bound only serializes same-driver
/// calls, and each in-flight call is itself bounded by the engine IPC timeout,
/// so the wait always terminates. The production value covers one full
/// worst-case engine round-trip plus margin.
#[cfg(not(test))]
const DRIVER_LEASE_TIMEOUT: Duration = Duration::from_secs(35);
#[cfg(test)]
const DRIVER_LEASE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpHttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl McpHttpResponse {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: value.to_string().into_bytes(),
        }
    }

    pub fn text(status: u16, value: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: value.into().into_bytes(),
        }
    }

    pub fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: Vec::new(),
        }
    }

    pub fn json_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

/// tempo's MCP session router over one driver instance.
///
/// Concurrency contract (issue #230): `handle_post` takes `&self`, so one
/// server instance can execute many tool calls at once. Tool calls that target
/// DIFFERENT drivers (the root driver or distinct forks) run concurrently; a
/// tool call that targets a driver already mid-call waits — bounded by
/// [`DRIVER_LEASE_TIMEOUT`] — for the in-flight call to finish, preserving
/// per-driver ordering. This is a plain lease (take the driver out under a
/// short-held lock, run the ops while owning it, put it back): no lock is held
/// across an engine round-trip and no queue/actor machinery is involved.
pub struct TempoMcpServer<D> {
    root: DriverSlot<D>,
    forks: ForkSlots,
    handshake_report: ProbeReport,
    handshake_probe_config: HttpProbeConfig,
    handshake_probe_limiter: HandshakeProbeLimiter,
}

impl<D> TempoMcpServer<D> {
    pub fn new(driver: D) -> Self {
        Self {
            root: DriverSlot::new(driver),
            forks: ForkSlots::default(),
            handshake_report: ProbeReport::new(),
            handshake_probe_config: HttpProbeConfig::default(),
            handshake_probe_limiter: HandshakeProbeLimiter::default(),
        }
    }

    pub fn with_handshake_report(mut self, report: ProbeReport) -> Self {
        self.handshake_report = report;
        self
    }

    pub fn with_handshake_probe_config(mut self, config: HttpProbeConfig) -> Self {
        self.handshake_probe_config = config;
        self
    }

    pub fn with_handshake_probe_limit(mut self, max_concurrent: usize) -> Self {
        self.handshake_probe_limiter = HandshakeProbeLimiter::new(max_concurrent);
        self
    }
}

#[derive(Clone)]
struct HandshakeProbeLimiter {
    max_concurrent: usize,
    in_flight: Arc<Mutex<usize>>,
}

impl HandshakeProbeLimiter {
    fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent,
            in_flight: Arc::new(Mutex::new(0)),
        }
    }

    fn try_acquire(&self) -> Result<HandshakeProbePermit, HandshakeProbeLimitReached> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *in_flight >= self.max_concurrent {
            return Err(HandshakeProbeLimitReached {
                max_concurrent: self.max_concurrent,
            });
        }
        *in_flight += 1;
        Ok(HandshakeProbePermit {
            in_flight: Arc::clone(&self.in_flight),
        })
    }
}

impl Default for HandshakeProbeLimiter {
    fn default() -> Self {
        Self::new(MAX_CONCURRENT_HANDSHAKE_PROBES)
    }
}

struct HandshakeProbePermit {
    in_flight: Arc<Mutex<usize>>,
}

impl Drop for HandshakeProbePermit {
    fn drop(&mut self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *in_flight = in_flight.saturating_sub(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HandshakeProbeLimitReached {
    max_concurrent: usize,
}

enum HandshakeProbeOutcome {
    NotRequested,
    Completed(Result<tempo_handshake::HttpProbeRun, String>),
    LimitReached(HandshakeProbeLimitReached),
}

static DRIVERLESS_HANDSHAKE_PROBE_LIMITER: OnceLock<HandshakeProbeLimiter> = OnceLock::new();

fn driverless_handshake_probe_limiter() -> &'static HandshakeProbeLimiter {
    DRIVERLESS_HANDSHAKE_PROBE_LIMITER.get_or_init(HandshakeProbeLimiter::default)
}

/// Why a driver could not be leased for a tool call.
enum LeaseError {
    /// No driver is registered under the requested id.
    Unknown,
    /// The driver exists but another call held it for the whole bounded wait.
    Busy,
    /// A lease lock was poisoned by a panicking holder.
    Poisoned,
}

/// Exclusive lease slot for the root driver: `Some` when idle, `None` while a
/// tool call owns the driver. Waiters block on the condvar, bounded by the
/// caller-supplied timeout, so a same-driver burst serializes without any lock
/// being held across the leased engine round-trips.
struct DriverSlot<D> {
    slot: Mutex<Option<D>>,
    returned: Condvar,
}

impl<D> DriverSlot<D> {
    fn new(driver: D) -> Self {
        Self {
            slot: Mutex::new(Some(driver)),
            returned: Condvar::new(),
        }
    }

    fn take(&self, timeout: Duration) -> Result<D, LeaseError> {
        let deadline = Instant::now().checked_add(timeout);
        // Recover poison (`into_inner`) rather than treat it as fatal: the
        // guarded state is `Option<D>` with no invariant a panicking holder can
        // break, and surfacing poison would wedge every later tool call behind a
        // one-off panic. Same justification as [`OpGate`] in tempo-headless.
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(driver) = slot.take() {
                return Ok(driver);
            }
            let Some(remaining) =
                deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            else {
                return Err(LeaseError::Busy);
            };
            slot = match self.returned.wait_timeout(slot, remaining) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn put(&self, driver: D) {
        // Poison recovery (see `take`): dropping the driver on a poisoned lock
        // would strand the slot empty and brick every later lease for the full
        // lease timeout.
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(driver);
        self.returned.notify_one();
    }
}

/// A registered fork: idle (leasable) or currently owned by a tool call.
enum ForkEntry {
    Idle(Box<dyn DriverTrait>),
    Leased,
}

struct ForkMap {
    entries: BTreeMap<String, ForkEntry>,
    next_fork_id: u64,
    /// Set permanently by [`ForkSlots::retire`] when the server's forks are
    /// being torn down (drain/detach). A `fork` tool call whose engine
    /// round-trip completes AFTER the teardown snapshot must not register into
    /// a registry nobody will close again — registration is refused and the
    /// caller closes the fresh fork instead (#230 review blocker: the
    /// lock-split made this race reachable; pre-#230 the global locks made it
    /// impossible). Mirrors the BiDi CreateContext re-check-after-unlock.
    retired: bool,
}

impl Default for ForkMap {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_fork_id: 1,
            retired: false,
        }
    }
}

/// Fork registry with per-fork leasing. The registry lock is only held for map
/// bookkeeping (register/lease/restore/remove); leased drivers are owned by the
/// calling task, so calls on distinct forks proceed fully in parallel.
#[derive(Default)]
struct ForkSlots {
    inner: Mutex<ForkMap>,
    returned: Condvar,
}

/// A fork that could not be registered, handed back so the caller can close it
/// instead of leaking the engine-side context.
struct ForkRegisterRejection {
    forked: Box<dyn DriverTrait>,
    reason: String,
}

impl ForkSlots {
    fn register(&self, forked: Box<dyn DriverTrait>) -> Result<String, ForkRegisterRejection> {
        // Recover poison (`into_inner`, as in `DriverSlot::take`): the guarded
        // `ForkMap` has no invariant a panicking holder can break, so rejecting
        // the fork here would leak its engine-side context needlessly.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        // Retirement, cap check, and registration are all atomic under the
        // registry lock: a fork either registers before the teardown snapshot
        // (and is closed by it) or is refused here (and closed by its caller).
        if map.retired {
            return Err(ForkRegisterRejection {
                forked,
                reason: "MCP forks are shut down (drain/detach); the new fork was closed".into(),
            });
        }
        if map.entries.len() >= MAX_LIVE_FORKS {
            return Err(ForkRegisterRejection {
                forked,
                reason: format!(
                    "fork limit reached ({MAX_LIVE_FORKS} live forks); close_fork before creating another"
                ),
            });
        }
        let fork_id = map.next_fork_id;
        let Some(next_id) = fork_id.checked_add(1) else {
            return Err(ForkRegisterRejection {
                forked,
                reason: "MCP fork driver id counter exhausted".into(),
            });
        };
        map.next_fork_id = next_id;
        let driver_id = format!("fork-{fork_id}");
        map.entries
            .insert(driver_id.clone(), ForkEntry::Idle(forked));
        Ok(driver_id)
    }

    fn lease(
        &self,
        driver_id: &str,
        timeout: Duration,
    ) -> Result<Box<dyn DriverTrait>, LeaseError> {
        let deadline = Instant::now().checked_add(timeout);
        // Poison recovery, see `register`.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match map.entries.get_mut(driver_id) {
                None => return Err(LeaseError::Unknown),
                Some(entry @ ForkEntry::Idle(_)) => {
                    let ForkEntry::Idle(driver) = std::mem::replace(entry, ForkEntry::Leased)
                    else {
                        return Err(LeaseError::Poisoned);
                    };
                    return Ok(driver);
                }
                Some(ForkEntry::Leased) => {}
            }
            let Some(remaining) =
                deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            else {
                return Err(LeaseError::Busy);
            };
            map = match self.returned.wait_timeout(map, remaining) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn restore(&self, driver_id: &str, driver: Box<dyn DriverTrait>) {
        // Poison recovery (see `register`): dropping the driver on a poisoned
        // lock would leave the entry stuck `Leased`, so every later lease of
        // this fork blocks the full lease timeout and then fails Busy.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.entries.get_mut(driver_id) {
            // `remove` waits for idle entries, so a leased entry is still
            // present until it is restored here.
            *entry = ForkEntry::Idle(driver);
        }
        drop(map);
        self.returned.notify_all();
    }

    /// Wait (bounded) for the fork to be idle, then take it out of the registry.
    fn remove(
        &self,
        driver_id: &str,
        timeout: Duration,
    ) -> Result<Box<dyn DriverTrait>, LeaseError> {
        let deadline = Instant::now().checked_add(timeout);
        // Poison recovery, see `register`.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match map.entries.get(driver_id) {
                None => return Err(LeaseError::Unknown),
                Some(ForkEntry::Idle(_)) => {
                    let Some(ForkEntry::Idle(driver)) = map.entries.remove(driver_id) else {
                        return Err(LeaseError::Poisoned);
                    };
                    return Ok(driver);
                }
                Some(ForkEntry::Leased) => {}
            }
            let Some(remaining) =
                deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            else {
                return Err(LeaseError::Busy);
            };
            map = match self.returned.wait_timeout(map, remaining) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Permanently refuse new registrations and return the ids live at the
    /// moment of retirement. Setting the flag and taking the snapshot under
    /// ONE lock acquisition closes the in-flight-`fork`-across-drain race:
    /// every fork is either in this snapshot (closed by the caller of
    /// [`TempoMcpServer::close_all_forks`]) or refused at registration
    /// (closed by the `fork` tool call itself).
    fn retire(&self) -> Vec<String> {
        // Poison recovery (see `register`): returning an empty snapshot on
        // poison would leak every live fork's engine-side context past teardown.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        map.retired = true;
        map.entries.keys().cloned().collect()
    }
}

/// Exclusive, self-returning lease on the root driver or a fork. The leased
/// driver is owned by the tool call for its whole duration (including
/// multi-round-trip tools such as `screenshot` with set-of-marks), and is put
/// back on drop so an early return can never strand a driver as busy.
enum LeasedDriver<'a, D: DriverTrait> {
    Root(&'a DriverSlot<D>, Option<D>),
    Fork(&'a ForkSlots, String, Option<Box<dyn DriverTrait>>),
}

impl<D: DriverTrait> LeasedDriver<'_, D> {
    fn driver_mut(&mut self) -> Option<&mut (dyn DriverTrait + '_)> {
        match self {
            Self::Root(_, driver) => driver
                .as_mut()
                .map(|driver| driver as &mut (dyn DriverTrait + '_)),
            Self::Fork(_, _, driver) => driver
                .as_mut()
                .map(|driver| &mut **driver as &mut (dyn DriverTrait + '_)),
        }
    }
}

impl<D: DriverTrait> Drop for LeasedDriver<'_, D> {
    fn drop(&mut self) {
        match self {
            Self::Root(slot, driver) => {
                if let Some(driver) = driver.take() {
                    slot.put(driver);
                }
            }
            Self::Fork(slots, driver_id, driver) => {
                if let Some(driver) = driver.take() {
                    slots.restore(driver_id, driver);
                }
            }
        }
    }
}

impl<D> TempoMcpServer<D>
where
    D: DriverTrait,
{
    /// Close and drop every live fork, and permanently retire the fork
    /// registry so a `fork` tool call still in flight cannot register (and
    /// leak) a context after this snapshot — it is refused at registration and
    /// closes its own fork instead. Call when a session ends so forked engine
    /// contexts do not leak for the process lifetime. Returns per-fork close
    /// errors. Waits (bounded) for any fork still owned by an in-flight call.
    pub async fn close_all_forks(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for driver_id in self.forks.retire() {
            match self.forks.remove(&driver_id, DRIVER_LEASE_TIMEOUT) {
                Ok(mut forked) => {
                    if let Err(error) = forked.close().await {
                        errors.push(format!("{driver_id}: {error}"));
                    }
                }
                // Removed by a concurrent close_fork; nothing left to release.
                Err(LeaseError::Unknown) => {}
                Err(LeaseError::Busy | LeaseError::Poisoned) => {
                    errors.push(format!(
                        "{driver_id}: fork was not returned by its in-flight call within {DRIVER_LEASE_TIMEOUT:?}"
                    ));
                }
            }
        }
        errors
    }
}

impl<D> TempoMcpServer<D>
where
    D: DriverTrait,
{
    fn lease_driver(&self, driver_id: Option<&str>) -> Result<LeasedDriver<'_, D>, JsonRpcError> {
        match driver_id {
            None => match self.root.take(DRIVER_LEASE_TIMEOUT) {
                Ok(driver) => Ok(LeasedDriver::Root(&self.root, Some(driver))),
                Err(_) => Err(JsonRpcError::driver_busy(
                    "the root driver is busy with another tool call; retry shortly",
                )),
            },
            Some(driver_id) => match self.forks.lease(driver_id, DRIVER_LEASE_TIMEOUT) {
                Ok(driver) => Ok(LeasedDriver::Fork(
                    &self.forks,
                    driver_id.to_string(),
                    Some(driver),
                )),
                Err(LeaseError::Unknown) => Err(JsonRpcError::invalid_params(format!(
                    "unknown driver_id: {driver_id}"
                ))),
                Err(LeaseError::Busy | LeaseError::Poisoned) => Err(JsonRpcError::driver_busy(
                    format!("driver {driver_id} is busy with another tool call; retry shortly"),
                )),
            },
        }
    }

    /// Handle one MCP POST body. `origin` is the HTTP Origin header when present.
    pub async fn handle_post(&self, origin: Option<&str>, body: &[u8]) -> McpHttpResponse {
        if !origin_allowed(origin) {
            return McpHttpResponse::json(
                403,
                json_rpc_error(Value::Null, -32600, "origin not allowed"),
            );
        }

        let message: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(error) => {
                return McpHttpResponse::json(
                    400,
                    json_rpc_error(Value::Null, -32700, format!("parse error: {error}")),
                );
            }
        };

        let id = match json_rpc_response_id(&message) {
            Ok(Some(id)) => id,
            Ok(None) => return McpHttpResponse::empty(202),
            Err(response) => return response,
        };

        let reply = self.handle_message(&message).await;
        match reply {
            Ok(result) => json_rpc_success_response(id, result),
            Err(error) => McpHttpResponse::json(200, json_rpc_error(id, error.code, error.message)),
        }
    }

    async fn handle_message(&self, message: &Value) -> Result<Value, JsonRpcError> {
        if !message.is_object() {
            return Err(JsonRpcError::invalid_request(
                "JSON-RPC message must be an object",
            ));
        }

        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_request("JSON-RPC method is required"))?;
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => Ok(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tempo", "version": env!("CARGO_PKG_VERSION")},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tool_descriptor_json()})),
            "tools/call" => self.tools_call(&params).await,
            other => Err(JsonRpcError::method_not_found(format!(
                "method not found: {other}"
            ))),
        }
    }

    async fn tools_call(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("tools/call requires params.name"))?;
        if !tools().iter().any(|tool| tool.name == name) {
            return Err(JsonRpcError::invalid_params(format!(
                "unknown tool: {name}"
            )));
        }

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let call = self.call_tool(name, arguments).await?;
        tool_call_json(call)
    }

    async fn call_tool(&self, name: &str, arguments: Value) -> Result<ToolCall, JsonRpcError> {
        match name {
            "observe" => {
                let args: DriverTargetArgs = parse_args(arguments)?;
                let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                match driver.observe().await {
                    Ok(observation) => Ok(ToolCall::success(json!(observation))),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "observe_diff" => {
                let args: ObserveDiffArgs = parse_args(arguments)?;
                let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                match driver.observe_diff(args.since_seq).await {
                    Ok(diff) => Ok(ToolCall::success(json!(diff))),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "act" => {
                let args: ActArgs = parse_args(arguments)?;
                let claims = args.claims()?;
                // Trust boundary (#254): caller taint/confirmed claims are
                // advisory (see tempo_policy::trust). Denials that need no
                // page evidence return before leasing the driver.
                let needs_evidence = requires_observation_evidence(
                    args.action.side_effect(),
                    &action_caller_texts(&args.action),
                    claims,
                );
                if !needs_evidence
                    && let Err(required) = gate_boundary_action(&args.action, None, claims)
                {
                    return Ok(ToolCall::confirmation_required(&required));
                }
                let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                if needs_evidence {
                    // Recompute taint from the live observation; the caller's
                    // clean claim cannot override page-derived evidence.
                    let observation = match driver.observe().await {
                        Ok(observation) => observation,
                        Err(error) => return Ok(observe_evidence_error(&error)),
                    };
                    if let Err(required) =
                        gate_boundary_action(&args.action, Some(&observation), claims)
                    {
                        return Ok(ToolCall::confirmation_required(&required));
                    }
                }
                match driver.act(&args.action).await {
                    Ok(outcome) => Ok(step_outcome_tool_call(outcome)),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "act_batch" => {
                let args: ActBatchArgs = parse_args(arguments)?;
                let claims = args.claims()?;
                let needs_evidence = args.batch.actions.iter().any(|action| {
                    requires_observation_evidence(
                        action.side_effect(),
                        &action_caller_texts(action),
                        claims,
                    )
                });
                if !needs_evidence
                    && let Some(required) = args
                        .batch
                        .actions
                        .iter()
                        .find_map(|action| gate_boundary_action(action, None, claims).err())
                {
                    return Ok(ToolCall::confirmation_required(&required));
                }
                let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                if needs_evidence {
                    let observation = match driver.observe().await {
                        Ok(observation) => observation,
                        Err(error) => return Ok(observe_evidence_error(&error)),
                    };
                    if let Some(required) = args.batch.actions.iter().find_map(|action| {
                        gate_boundary_action(action, Some(&observation), claims).err()
                    }) {
                        return Ok(ToolCall::confirmation_required(&required));
                    }
                }
                match driver.act_batch(&args.batch).await {
                    Ok(outcome) => Ok(step_outcome_tool_call(outcome)),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "fork" => {
                let args: ForkArgs = parse_args(arguments)?;
                let forked = {
                    let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                    let Some(driver) = lease.driver_mut() else {
                        return Err(JsonRpcError::invalid_request("driver lease was empty"));
                    };
                    // The parent lease is dropped (returned) before registration,
                    // so a slow fork does not hold the parent hostage afterwards.
                    driver.fork().await
                };
                match forked {
                    Ok(forked) => {
                        let engine = engine_name(forked.engine());
                        match self.forks.register(forked) {
                            Ok(driver_id) => Ok(ToolCall::success(json!({
                                "supported": true,
                                "driver_id": driver_id,
                                "engine": engine,
                            }))),
                            Err(ForkRegisterRejection { mut forked, reason }) => {
                                // Refuse to accumulate: close the fork we just
                                // created so it does not leak.
                                let mut reason = reason;
                                if let Err(error) = forked.close().await {
                                    reason.push_str(&format!(
                                        "; also failed to close new fork: {error}"
                                    ));
                                }
                                Ok(ToolCall::error(reason))
                            }
                        }
                    }
                    Err(error) => Ok(ToolCall::success(json!({
                        "supported": false,
                        "reason": error.to_string(),
                    }))),
                }
            }
            "close_fork" => {
                let args: CloseForkArgs = parse_args(arguments)?;
                match self.forks.remove(&args.driver_id, DRIVER_LEASE_TIMEOUT) {
                    Ok(mut forked) => match forked.close().await {
                        Ok(()) => Ok(ToolCall::success(json!({
                            "closed": true,
                            "driver_id": args.driver_id,
                        }))),
                        Err(error) => Ok(ToolCall::error(error.to_string())),
                    },
                    Err(LeaseError::Unknown) => Ok(ToolCall::error(format!(
                        "unknown driver_id: {}",
                        args.driver_id
                    ))),
                    Err(LeaseError::Busy | LeaseError::Poisoned) => Ok(ToolCall::error(format!(
                        "driver {} is busy with another tool call; retry shortly",
                        args.driver_id
                    ))),
                }
            }
            "extract" => {
                let args: ExtractArgs = parse_args(arguments)?;
                let driver_id = args.driver_id.clone();
                let mut lease = self.lease_driver(driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                match driver.extract(&args.node).await {
                    Ok(value) => Ok(ToolCall::success_json_bounded(
                        "extract_json",
                        value,
                        MAX_EXTRACT_JSON_BYTES,
                    )),
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "screenshot" => {
                let args: ScreenshotArgs = parse_args(arguments)?;
                let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                let Some(driver) = lease.driver_mut() else {
                    return Err(JsonRpcError::invalid_request("driver lease was empty"));
                };
                let observation = if args.set_of_marks {
                    match driver.observe().await {
                        Ok(observation) => Some(observation),
                        Err(error) => return Ok(ToolCall::error(error.to_string())),
                    }
                } else {
                    None
                };
                match driver.screenshot().await {
                    Ok(bytes) => {
                        let bytes = match validate_screenshot_bytes(bytes) {
                            Ok(bytes) => bytes,
                            Err(call) => return Ok(call),
                        };
                        let bytes = match observation {
                            Some(observation) => {
                                match composite_set_of_marks_png(&bytes, &observation) {
                                    Ok(bytes) => match validate_screenshot_bytes(bytes) {
                                        Ok(bytes) => bytes,
                                        Err(call) => return Ok(call),
                                    },
                                    Err(error) => return Ok(ToolCall::error(error.to_string())),
                                }
                            }
                            None => bytes,
                        };
                        if base64_encoded_len(bytes.len())
                            .map(|len| len > MAX_PROTOCOL_RESPONSE_BYTES)
                            .unwrap_or(true)
                        {
                            return Ok(ToolCall::cap_error(
                                "screenshot_base64",
                                base64_encoded_len(bytes.len()).unwrap_or(usize::MAX),
                                MAX_PROTOCOL_RESPONSE_BYTES,
                            ));
                        }
                        Ok(ToolCall::image(
                            "image/png",
                            args.set_of_marks,
                            base64::engine::general_purpose::STANDARD.encode(bytes),
                        ))
                    }
                    Err(error) => Ok(ToolCall::error(error.to_string())),
                }
            }
            "handshake" => {
                let args: HandshakeArgs = parse_args(arguments)?;
                let probe = match run_handshake_probe(
                    &args,
                    &self.handshake_probe_config,
                    &self.handshake_probe_limiter,
                )
                .await
                {
                    HandshakeProbeOutcome::NotRequested => None,
                    HandshakeProbeOutcome::Completed(result) => Some(result),
                    HandshakeProbeOutcome::LimitReached(limit) => {
                        return Ok(ToolCall::handshake_probe_limit(limit));
                    }
                };
                let web_mcp = {
                    let mut lease = self.lease_driver(args.driver_id.as_deref())?;
                    let Some(driver) = lease.driver_mut() else {
                        return Err(JsonRpcError::invalid_request("driver lease was empty"));
                    };
                    Some(run_origin_bound_web_mcp_detection(&args, driver).await)
                };
                Ok(ToolCall::success(handshake_result_json(
                    &self.handshake_report,
                    args,
                    probe,
                    web_mcp,
                )))
            }
            _ => Err(JsonRpcError::invalid_params("unknown tool")),
        }
    }
}

pub fn handle_get() -> McpHttpResponse {
    McpHttpResponse::text(
        405,
        "this MCP endpoint does not offer a server-initiated stream",
    )
}

/// Publish tempo as an addressable agent resource.
///
/// The card is intentionally honest about the transport tempo serves today:
/// clients should connect through the MCP endpoint rather than unsupported A2A
/// task methods.
pub fn agent_card(base_url: &str) -> Value {
    let base_url = base_url.trim_end_matches('/');
    let mcp_url = format!("{base_url}/mcp");
    json!({
        "protocolVersion": "0.3.0",
        "name": "tempo",
        "description": "AI-agent-native browser control plane for live web sessions.",
        "url": mcp_url,
        "provider": {
            "organization": "tempo",
            "url": "https://github.com/jadenfix/tempo",
        },
        "version": env!("CARGO_PKG_VERSION"),
        "preferredTransport": "MCP",
        "additionalInterfaces": [{
            "transport": "MCP",
            "url": mcp_url,
        }],
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "stateTransitionHistory": false,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json", "image/png"],
        "skills": tools().into_iter().map(agent_card_skill_json).collect::<Vec<_>>(),
    })
}

pub fn agent_card_response(base_url: &str) -> McpHttpResponse {
    McpHttpResponse {
        status: 200,
        content_type: A2A_AGENT_CARD_CONTENT_TYPE,
        body: agent_card(base_url).to_string().into_bytes(),
    }
}

/// Handle MCP POST messages that do not require a page driver.
///
/// This keeps pre-render discovery available before an engine is attached:
/// initialize, ping, tools/list, and the handshake tool work; page-driving tools
/// return a JSON-RPC error instead of silently creating a browser stand-in.
pub fn handle_post_driverless(origin: Option<&str>, body: &[u8]) -> McpHttpResponse {
    handle_post_driverless_with_config(origin, body, HttpProbeConfig::default())
}

pub fn handle_post_driverless_with_config(
    origin: Option<&str>,
    body: &[u8],
    handshake_probe_config: HttpProbeConfig,
) -> McpHttpResponse {
    if !origin_allowed(origin) {
        return McpHttpResponse::json(
            403,
            json_rpc_error(Value::Null, -32600, "origin not allowed"),
        );
    }

    let message: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return McpHttpResponse::json(
                400,
                json_rpc_error(Value::Null, -32700, format!("parse error: {error}")),
            );
        }
    };

    let id = match json_rpc_response_id(&message) {
        Ok(Some(id)) => id,
        Ok(None) => return McpHttpResponse::empty(202),
        Err(response) => return response,
    };

    let reply = handle_driverless_message(&message, handshake_probe_config);
    match reply {
        Ok(result) => json_rpc_success_response(id, result),
        Err(error) => McpHttpResponse::json(200, json_rpc_error(id, error.code, error.message)),
    }
}

/// Origin is optional for non-browser clients; when present, only loopback
/// origins are accepted to block DNS-rebinding attacks.
pub fn origin_allowed(origin: Option<&str>) -> bool {
    origin.map(loopback_origin_allowed).unwrap_or(true)
}

pub fn tools() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            name: "observe",
            description: "Return the current compiled observation.",
            input_schema: object_schema(vec![("driver_id", json!({"type": "string"}))], &[]),
        },
        ToolDescriptor {
            name: "observe_diff",
            description: "Return the observation diff since a known sequence number.",
            input_schema: object_schema(
                vec![
                    ("since_seq", json!({"type": "integer", "minimum": 0})),
                    ("driver_id", json!({"type": "string"})),
                ],
                &["since_seq"],
            ),
        },
        ToolDescriptor {
            name: "act",
            description: "Execute one tempo semantic action. input_tainted/confirmed are advisory: taint is recomputed server-side and can only be escalated by the caller.",
            input_schema: with_node_id_defs(object_schema(
                vec![
                    ("action", action_tool_schema()),
                    ("input_tainted", input_tainted_tool_schema()),
                    ("confirmed", confirmed_tool_schema()),
                    (
                        "driver_id",
                        json!({
                            "type": "string",
                            "description": "Optional fork driver id returned by fork; omit to target the root driver."
                        }),
                    ),
                ],
                &["action", "input_tainted"],
            )),
        },
        ToolDescriptor {
            name: "act_batch",
            description:
                "Execute a batch of tempo semantic actions. input_tainted/confirmed are advisory: taint is recomputed server-side and can only be escalated by the caller.",
            input_schema: with_node_id_defs(object_schema(
                vec![
                    ("batch", action_batch_tool_schema()),
                    ("input_tainted", input_tainted_tool_schema()),
                    ("confirmed", confirmed_tool_schema()),
                    (
                        "driver_id",
                        json!({
                            "type": "string",
                            "description": "Optional fork driver id returned by fork; omit to target the root driver."
                        }),
                    ),
                ],
                &["batch", "input_tainted"],
            )),
        },
        ToolDescriptor {
            name: "fork",
            description: "Fork the current page state when the active driver supports it.",
            input_schema: object_schema(vec![("driver_id", json!({"type": "string"}))], &[]),
        },
        ToolDescriptor {
            name: "close_fork",
            description: "Close a forked driver and release its engine resources.",
            input_schema: object_schema(
                vec![("driver_id", json!({"type": "string"}))],
                &["driver_id"],
            ),
        },
        ToolDescriptor {
            name: "extract",
            description: "Extract structured data rooted at a stable node id from observe/observe_diff.",
            input_schema: object_schema(
                vec![
                    (
                        "node",
                        json!({
                            "type": "string",
                            "description": "Stable node id from observe/observe_diff, for example \"button.primary\"."
                        }),
                    ),
                    ("driver_id", json!({"type": "string"})),
                ],
                &["node"],
            ),
        },
        ToolDescriptor {
            name: "screenshot",
            description: "Capture a PNG screenshot as MCP image content.",
            input_schema: object_schema(
                vec![
                    ("set_of_marks", json!({"type": "boolean"})),
                    ("driver_id", json!({"type": "string"})),
                ],
                &[],
            ),
        },
        ToolDescriptor {
            name: "handshake",
            description: "Evaluate structured-web probe evidence and lane decision.",
            input_schema: object_schema(
                vec![
                    ("origin", json!({"type": "string"})),
                    ("live_http", json!({"type": "boolean"})),
                    ("driver_id", json!({"type": "string"})),
                    ("responses", json!({"type": "array"})),
                ],
                &[],
            ),
        },
    ]
}

pub fn describe() -> &'static str {
    "tempo MCP server core: initialize/ping/tools/list/tools/call for observe, observe_diff, act, act_batch, fork, close_fork, extract, screenshot, and handshake"
}

#[derive(Debug, Error)]
#[error("JSON-RPC {code}: {message}")]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn driver_required(message: impl Into<String>) -> Self {
        Self {
            code: DRIVER_REQUIRED_ERROR_CODE,
            message: message.into(),
        }
    }

    fn driver_busy(message: impl Into<String>) -> Self {
        Self {
            code: DRIVER_BUSY_ERROR_CODE,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ToolCall {
    is_error: bool,
    structured_content: Value,
    content: Vec<Value>,
}

impl ToolCall {
    fn success(value: Value) -> Self {
        let summary = tool_content_summary(&value);
        Self {
            is_error: false,
            structured_content: value,
            content: vec![text_content_block(summary)],
        }
    }

    fn error(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            is_error: true,
            structured_content: json!({"error": message.clone()}),
            content: vec![text_content_block(format!(
                "error: {}",
                truncate_summary(&message)
            ))],
        }
    }

    fn image(mime_type: &'static str, set_of_marks: bool, data: String) -> Self {
        Self {
            is_error: false,
            structured_content: json!({
                "mime_type": mime_type,
                "set_of_marks": set_of_marks,
            }),
            content: vec![json!({
                "type": "image",
                "data": data,
                "mimeType": mime_type,
            })],
        }
    }

    fn handshake_probe_limit(limit: HandshakeProbeLimitReached) -> Self {
        let message = format!(
            "live HTTP handshake probe limit reached (max {})",
            limit.max_concurrent
        );
        Self {
            is_error: true,
            structured_content: json!({
                "error": {
                    "type": HANDSHAKE_PROBE_LIMIT_ERROR_CODE,
                    "max_concurrent": limit.max_concurrent,
                    "message": message.clone(),
                }
            }),
            content: vec![text_content_block(format!("error: {message}"))],
        }
    }

    fn success_json_bounded(artifact: &'static str, value: Value, max_bytes: usize) -> Self {
        match serde_json::to_vec(&value) {
            Ok(bytes) if bytes.len() <= max_bytes => Self::success(value),
            Ok(bytes) => Self::cap_error(artifact, bytes.len(), max_bytes),
            Err(error) => Self::error(error.to_string()),
        }
    }

    /// Typed error for a request the policy gate refused pending human
    /// confirmation (#254). Caller-supplied `confirmed` can never clear this;
    /// see `tempo_policy::trust`.
    fn confirmation_required(required: &ConfirmationRequired) -> Self {
        Self {
            is_error: true,
            structured_content: json!({
                "error": {
                    "type": "confirmation_required",
                    "side_effect": required.decision.side_effect,
                    "input_tainted": required.decision.input_taint.is_tainted(),
                    "gate": required.gate_name(),
                    "message": required.message(),
                }
            }),
            content: vec![text_content_block(required.message())],
        }
    }

    fn cap_error(artifact: &'static str, bytes: usize, max_bytes: usize) -> Self {
        let message = output_cap_message(artifact, bytes, max_bytes);
        Self {
            is_error: true,
            structured_content: json!({
                "error": {
                    "type": "response_too_large",
                    "artifact": artifact,
                    "bytes": bytes,
                    "max_bytes": max_bytes,
                    "message": message.clone(),
                }
            }),
            content: vec![text_content_block(message)],
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct DriverTargetArgs {
    #[serde(default)]
    driver_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ObserveDiffArgs {
    #[serde(default)]
    driver_id: Option<String>,
    since_seq: u64,
}

#[derive(Debug, Deserialize)]
struct ActArgs {
    #[serde(default)]
    driver_id: Option<String>,
    action: Action,
    input_tainted: Option<bool>,
    #[serde(default)]
    confirmed: bool,
}

impl ActArgs {
    fn claims(&self) -> Result<CallerPolicyClaims, JsonRpcError> {
        required_caller_claims(self.input_tainted, self.confirmed)
    }
}

#[derive(Debug, Deserialize)]
struct ActBatchArgs {
    #[serde(default)]
    driver_id: Option<String>,
    batch: ActionBatch,
    input_tainted: Option<bool>,
    #[serde(default)]
    confirmed: bool,
}

impl ActBatchArgs {
    fn claims(&self) -> Result<CallerPolicyClaims, JsonRpcError> {
        required_caller_claims(self.input_tainted, self.confirmed)
    }
}

#[derive(Debug, Default, Deserialize)]
struct ForkArgs {
    #[serde(default)]
    driver_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloseForkArgs {
    driver_id: String,
}

#[derive(Debug, Deserialize)]
struct ExtractArgs {
    #[serde(default)]
    driver_id: Option<String>,
    node: NodeId,
}

#[derive(Debug, Default, Deserialize)]
struct ScreenshotArgs {
    #[serde(default)]
    driver_id: Option<String>,
    #[serde(default)]
    set_of_marks: bool,
}

#[derive(Debug, Default, Deserialize)]
struct HandshakeArgs {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    driver_id: Option<String>,
    #[serde(default)]
    live_http: Option<bool>,
    #[serde(default)]
    responses: Vec<ProbeResponseInput>,
}

#[derive(Debug, Default)]
struct WebMcpOriginBinding {
    requested_origin: Option<String>,
    page_origin: Option<String>,
}

#[derive(Debug)]
enum WebMcpEvidence {
    Checked {
        result: Result<WebMcpDetection, String>,
        binding: WebMcpOriginBinding,
    },
    Skipped {
        reason: String,
        binding: WebMcpOriginBinding,
    },
}

#[derive(Debug)]
struct CanonicalWebOrigin {
    origin: Origin,
    label: String,
}

#[derive(Debug, Deserialize)]
struct ProbeResponseInput {
    path: String,
    status: u16,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    body: String,
}

impl From<ProbeResponseInput> for ProbeResponse {
    fn from(value: ProbeResponseInput) -> Self {
        let response = ProbeResponse::new(value.path, value.status, value.body);
        match value.content_type {
            Some(content_type) => response.with_content_type(content_type),
            None => response,
        }
    }
}

fn parse_args<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, JsonRpcError> {
    serde_json::from_value(value).map_err(|error| JsonRpcError::invalid_params(error.to_string()))
}

/// Parse caller policy claims, keeping `input_tainted` a REQUIRED wire field
/// so callers must state their claim explicitly. Both fields are advisory:
/// they are sanitized by `tempo_policy::trust` and can only escalate.
fn required_caller_claims(
    input_tainted: Option<bool>,
    confirmed: bool,
) -> Result<CallerPolicyClaims, JsonRpcError> {
    if input_tainted.is_none() {
        return Err(JsonRpcError::invalid_params(
            "input_tainted is required for act tools",
        ));
    }
    Ok(CallerPolicyClaims::new(input_tainted, confirmed))
}

/// Observe failure while gathering trust-boundary taint evidence: fail the
/// tool call rather than weaken the gate.
fn observe_evidence_error(error: &dyn std::fmt::Display) -> ToolCall {
    ToolCall::error(format!(
        "policy taint recomputation requires an observation, but observe failed: {error}"
    ))
}

fn validate_screenshot_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, ToolCall> {
    if bytes.len() > MAX_SCREENSHOT_BYTES {
        return Err(ToolCall::cap_error(
            "screenshot",
            bytes.len(),
            MAX_SCREENSHOT_BYTES,
        ));
    }
    Ok(bytes)
}

fn base64_encoded_len(bytes: usize) -> Option<usize> {
    bytes.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

/// The origin to run a live HTTP probe against, if these handshake args request
/// one. Live probing defaults on when an origin is supplied without inline
/// responses, and can be forced on or off with the explicit `live_http` flag.
fn handshake_probe_target(args: &HandshakeArgs) -> Option<String> {
    let live_http_requested = args
        .live_http
        .unwrap_or_else(|| args.origin.is_some() && args.responses.is_empty());
    if live_http_requested {
        args.origin.clone()
    } else {
        None
    }
}

/// Run the blocking HTTP probe from the async `call_tool` path.
///
/// This path is runtime-agnostic on purpose: the production caller drives the
/// async MCP server with `futures::executor::block_on` (see
/// `tempo-headless::route_mcp`), so there is no tokio runtime available and
/// `tokio::task::spawn_blocking` would panic. `probe_http_origin` uses a
/// blocking HTTP client, so it is run on its own std thread and joined, which
/// works under any executor. Because the surrounding server is always driven by
/// a synchronous `block_on`, parking the current thread on that join is correct
/// here.
async fn run_handshake_probe(
    args: &HandshakeArgs,
    config: &HttpProbeConfig,
    limiter: &HandshakeProbeLimiter,
) -> HandshakeProbeOutcome {
    run_handshake_probe_blocking(args, config, limiter)
}

async fn run_web_mcp_detection(driver: &mut dyn DriverTrait) -> Result<WebMcpDetection, String> {
    let value = driver
        .evaluate_script(WEB_MCP_DETECTION_SCRIPT, false)
        .await
        .map_err(|error| error.to_string())?;
    Ok(WebMcpDetection::from_script_result(&value))
}

async fn run_origin_bound_web_mcp_detection(
    args: &HandshakeArgs,
    driver: &mut dyn DriverTrait,
) -> WebMcpEvidence {
    let Some(requested_origin) = args.origin.as_deref() else {
        return WebMcpEvidence::Checked {
            result: run_web_mcp_detection(driver).await,
            binding: WebMcpOriginBinding::default(),
        };
    };

    let requested_origin = match canonical_web_origin(requested_origin) {
        Ok(origin) => origin,
        Err(error) => {
            return WebMcpEvidence::Skipped {
                reason: format!("requested origin is not a canonical web origin: {error}"),
                binding: WebMcpOriginBinding::default(),
            };
        }
    };

    let observation = match driver.observe().await {
        Ok(observation) => observation,
        Err(error) => {
            return WebMcpEvidence::Skipped {
                reason: format!("current page URL unavailable: {error}"),
                binding: WebMcpOriginBinding {
                    requested_origin: Some(requested_origin.label),
                    page_origin: None,
                },
            };
        }
    };

    let page_origin = match canonical_web_origin(&observation.url) {
        Ok(origin) => origin,
        Err(error) => {
            return WebMcpEvidence::Skipped {
                reason: format!("current page URL is not a canonical web origin: {error}"),
                binding: WebMcpOriginBinding {
                    requested_origin: Some(requested_origin.label),
                    page_origin: None,
                },
            };
        }
    };

    let binding = WebMcpOriginBinding {
        requested_origin: Some(requested_origin.label.clone()),
        page_origin: Some(page_origin.label.clone()),
    };

    if requested_origin.origin != page_origin.origin {
        return WebMcpEvidence::Skipped {
            reason: "current page origin does not match requested origin".into(),
            binding,
        };
    }

    WebMcpEvidence::Checked {
        result: run_web_mcp_detection(driver).await,
        binding,
    }
}

fn canonical_web_origin(url: &str) -> Result<CanonicalWebOrigin, String> {
    let origin = Origin::parse(url).map_err(|error| error.to_string())?;
    if !matches!(origin.scheme.as_str(), "http" | "https") {
        return Err(format!("unsupported scheme: {}", origin.scheme));
    }
    let label = canonical_origin_label(&origin);
    Ok(CanonicalWebOrigin { origin, label })
}

fn canonical_origin_label(origin: &Origin) -> String {
    let default_port = matches!(
        (origin.scheme.as_str(), origin.port),
        ("http", Some(80)) | ("https", Some(443)) | (_, None)
    );
    if default_port {
        format!("{}://{}", origin.scheme, origin.host)
    } else {
        format!(
            "{}://{}:{}",
            origin.scheme,
            origin.host,
            origin.port.unwrap_or_default()
        )
    }
}

fn run_handshake_probe_thread(
    origin: String,
    config: HttpProbeConfig,
    _permit: HandshakeProbePermit,
) -> Result<tempo_handshake::HttpProbeRun, String> {
    match std::thread::spawn(move || probe_http_origin(&origin, config)).join() {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => Err("HTTP probe worker panicked".into()),
    }
}

/// Blocking-context variant of [`run_handshake_probe`] for the driverless path,
/// which runs outside a tokio worker. The blocking HTTP client must not be
/// driven from within an async runtime, so it is run on its own std thread.
fn run_handshake_probe_blocking(
    args: &HandshakeArgs,
    config: &HttpProbeConfig,
    limiter: &HandshakeProbeLimiter,
) -> HandshakeProbeOutcome {
    let Some(origin) = handshake_probe_target(args) else {
        return HandshakeProbeOutcome::NotRequested;
    };
    let permit = match limiter.try_acquire() {
        Ok(permit) => permit,
        Err(limit) => return HandshakeProbeOutcome::LimitReached(limit),
    };
    let config = config.clone();
    HandshakeProbeOutcome::Completed(run_handshake_probe_thread(origin, config, permit))
}

fn handle_driverless_message(
    message: &Value,
    handshake_probe_config: HttpProbeConfig,
) -> Result<Value, JsonRpcError> {
    if !message.is_object() {
        return Err(JsonRpcError::invalid_request(
            "JSON-RPC message must be an object",
        ));
    }

    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_request("JSON-RPC method is required"))?;
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => Ok(json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tempo", "version": env!("CARGO_PKG_VERSION")},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_descriptor_json()})),
        "tools/call" => driverless_tools_call(&params, handshake_probe_config),
        other => Err(JsonRpcError::method_not_found(format!(
            "method not found: {other}"
        ))),
    }
}

fn driverless_tools_call(
    params: &Value,
    handshake_probe_config: HttpProbeConfig,
) -> Result<Value, JsonRpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_params("tools/call requires params.name"))?;
    if !tools().iter().any(|tool| tool.name == name) {
        return Err(JsonRpcError::invalid_params(format!(
            "unknown tool: {name}"
        )));
    }

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if name != "handshake" {
        return Err(JsonRpcError::driver_required(format!(
            "MCP tool call requires an attached engine driver: {name}"
        )));
    }

    let args: HandshakeArgs = parse_args(arguments)?;
    let probe = match run_handshake_probe_blocking(
        &args,
        &handshake_probe_config,
        driverless_handshake_probe_limiter(),
    ) {
        HandshakeProbeOutcome::NotRequested => None,
        HandshakeProbeOutcome::Completed(result) => Some(result),
        HandshakeProbeOutcome::LimitReached(limit) => {
            return tool_call_json(ToolCall::handshake_probe_limit(limit));
        }
    };
    tool_call_json(ToolCall::success(handshake_result_json(
        &ProbeReport::new(),
        args,
        probe,
        None,
    )))
}

/// Build the handshake tool result. `probe` carries the outcome of the live HTTP
/// probe (already run off the async executor by the caller), or `None` when no
/// live probe was requested.
fn handshake_result_json(
    handshake_report: &ProbeReport,
    args: HandshakeArgs,
    probe: Option<Result<tempo_handshake::HttpProbeRun, String>>,
    web_mcp: Option<WebMcpEvidence>,
) -> Value {
    let mut report = ProbeReport::from_hits(handshake_report.hits().to_vec());
    let origin = args.origin.clone();
    let response_report = ProbeReport::from_responses(args.responses.into_iter().map(Into::into));
    for hit in response_report.hits() {
        report.add_hit(hit.clone());
    }

    let mut live_http = false;
    let mut probe_responses = Vec::new();
    let mut probe_failures = Vec::new();
    let mut probe_error = None;
    if let Some(result) = probe {
        live_http = true;
        match result {
            Ok(run) => {
                for hit in run.report.hits() {
                    report.add_hit(hit.clone());
                }
                probe_responses = run
                    .responses
                    .iter()
                    .map(probe_response_json)
                    .collect::<Vec<_>>();
                probe_failures = run
                    .failures
                    .iter()
                    .map(probe_failure_json)
                    .collect::<Vec<_>>();
            }
            Err(error) => {
                probe_error = Some(error);
            }
        }
    }
    let mut web_mcp_checked = false;
    let mut web_mcp_available = false;
    let mut web_mcp_value_type = None;
    let mut web_mcp_has_tools = false;
    let mut web_mcp_error = None;
    let mut web_mcp_skipped_reason = None;
    let mut web_mcp_requested_origin = None;
    let mut web_mcp_page_origin = None;
    if let Some(evidence) = web_mcp {
        match evidence {
            WebMcpEvidence::Checked { result, binding } => {
                web_mcp_checked = true;
                web_mcp_requested_origin = binding.requested_origin;
                web_mcp_page_origin = binding.page_origin;
                match result {
                    Ok(detection) => {
                        report.record_web_mcp_detection(&detection);
                        web_mcp_available = detection.available;
                        web_mcp_value_type = detection.value_type;
                        web_mcp_has_tools = detection.has_tools;
                    }
                    Err(error) => {
                        web_mcp_error = Some(error);
                    }
                }
            }
            WebMcpEvidence::Skipped { reason, binding } => {
                web_mcp_skipped_reason = Some(reason);
                web_mcp_requested_origin = binding.requested_origin;
                web_mcp_page_origin = binding.page_origin;
            }
        }
    }

    let decision = decide_lane(&report);
    json!({
        "lane": handshake_lane_name(decision.lane),
        "skips_render": decision.skips_render(),
        "selected": decision.selected.as_ref().map(probe_hit_json),
        "hits": report.hits().iter().map(probe_hit_json).collect::<Vec<_>>(),
        "probe_urls": origin.as_deref().map(probe_urls).unwrap_or_default(),
        "live_http": live_http,
        "probe_responses": probe_responses,
        "probe_failures": probe_failures,
        "probe_error": probe_error,
        "web_mcp": {
            "checked": web_mcp_checked,
            "available": web_mcp_available,
            "source": "navigator.modelContext",
            "type": web_mcp_value_type,
            "has_tools": web_mcp_has_tools,
            "error": web_mcp_error,
            "skipped_reason": web_mcp_skipped_reason,
            "requested_origin": web_mcp_requested_origin,
            "page_origin": web_mcp_page_origin,
        },
    })
}

fn json_rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn json_rpc_response_id(message: &Value) -> Result<Option<Value>, McpHttpResponse> {
    let Some(id) = message.get("id") else {
        return Ok(None);
    };
    if !(id.is_null() || id.is_string() || id.is_number()) {
        return Err(McpHttpResponse::json(
            400,
            json_rpc_error(Value::Null, -32600, "id must be a string, number, or null"),
        ));
    }
    if id.is_null() {
        return Ok(None);
    }
    Ok(Some(id.clone()))
}

fn json_rpc_success_response(id: Value, result: Value) -> McpHttpResponse {
    let value = json_rpc_result(id.clone(), result);
    match json_response_with_cap(200, value, MAX_PROTOCOL_RESPONSE_BYTES) {
        Ok(response) => response,
        Err(message) => McpHttpResponse::json(
            200,
            json_rpc_error(id, RESPONSE_TOO_LARGE_ERROR_CODE, message),
        ),
    }
}

fn json_response_with_cap(
    status: u16,
    value: Value,
    max_bytes: usize,
) -> Result<McpHttpResponse, String> {
    match serde_json::to_vec(&value) {
        Ok(body) if body.len() <= max_bytes => Ok(McpHttpResponse {
            status,
            content_type: "application/json",
            body,
        }),
        Ok(body) => Err(output_cap_message("mcp_response", body.len(), max_bytes)),
        Err(error) => Err(error.to_string()),
    }
}

fn tool_call_json(call: ToolCall) -> Result<Value, JsonRpcError> {
    Ok(json!({
        "content": call.content,
        "structuredContent": call.structured_content,
        "isError": call.is_error,
    }))
}

fn text_content_block(text: impl Into<String>) -> Value {
    json!({"type": "text", "text": text.into()})
}

fn tool_content_summary(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return match value {
            Value::Null => "null".into(),
            Value::Bool(value) => format!("boolean {value}"),
            Value::Number(value) => format!("number {value}"),
            Value::String(value) => truncate_summary(value),
            Value::Array(values) => format!("array {} items", values.len()),
            Value::Object(object) => format!("object fields={}", object.len()),
        };
    };

    if let Some(error) = object.get("error") {
        return format!("error: {}", error_summary(error));
    }

    if object.contains_key("schema_version")
        && object.contains_key("seq")
        && object.contains_key("elements")
    {
        let seq = display_json_scalar(object.get("seq"));
        let elements = json_array_len(object.get("elements"));
        let omitted = object.get("omitted").and_then(Value::as_u64).unwrap_or(0);
        return format!("observation seq={seq}, elements={elements}, omitted={omitted}");
    }

    if object.contains_key("since_seq")
        && object.contains_key("seq")
        && object.contains_key("added")
        && object.contains_key("removed")
        && object.contains_key("changed")
    {
        let seq = display_json_scalar(object.get("seq"));
        return format!(
            "observation_diff seq={seq}, added={}, changed={}, removed={}",
            json_array_len(object.get("added")),
            json_array_len(object.get("changed")),
            json_array_len(object.get("removed"))
        );
    }

    if let Some(status) = object.get("status").and_then(Value::as_str) {
        if let Some(diff) = object.get("diff") {
            return format!(
                "action status={status}, diff {}",
                tool_content_summary(diff)
            );
        }
        return format!("action status={status}");
    }

    if let Some(node) = object.get("node").and_then(Value::as_str) {
        return format!("extract node={node}, fields={}", object.len());
    }

    if let Some(driver_id) = object.get("driver_id").and_then(Value::as_str) {
        return format!("fork driver_id={driver_id}");
    }

    if object.contains_key("lane") || object.contains_key("lane_decision") {
        return format!("handshake fields={}", object.len());
    }

    format!("object fields={}", object.len())
}

fn error_summary(error: &Value) -> String {
    match error {
        Value::String(message) => truncate_summary(message),
        Value::Object(object) => object
            .get("message")
            .and_then(Value::as_str)
            .map(truncate_summary)
            .or_else(|| {
                object
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|kind| kind.to_string())
            })
            .unwrap_or_else(|| format!("object fields={}", object.len())),
        other => tool_content_summary(other),
    }
}

fn display_json_scalar(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Null) | None => "unknown".into(),
        Some(Value::Array(values)) => format!("array:{}", values.len()),
        Some(Value::Object(object)) => format!("object:{}", object.len()),
    }
}

fn json_array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}

fn truncate_summary(text: &str) -> String {
    if text.chars().count() <= TOOL_TEXT_SUMMARY_MAX_CHARS {
        return text.to_string();
    }
    let mut truncated = text
        .chars()
        .take(TOOL_TEXT_SUMMARY_MAX_CHARS.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn tool_descriptor_json() -> Vec<Value> {
    tools()
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            })
        })
        .collect()
}

fn agent_card_skill_json(tool: ToolDescriptor) -> Value {
    json!({
        "id": tool.name,
        "name": tool.name,
        "description": tool.description,
        "tags": ["browser", "mcp", "tempo"],
        "inputModes": ["application/json"],
        "outputModes": if tool.name == "screenshot" {
            vec!["application/json", "image/png"]
        } else {
            vec!["application/json"]
        },
    })
}

fn object_schema(properties: Vec<(&'static str, Value)>, required: &[&'static str]) -> Value {
    let required = required
        .iter()
        .map(|name| Value::String((*name).to_string()))
        .collect::<Vec<_>>();
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_string(), schema))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn with_node_id_defs(mut schema: Value) -> Value {
    if let Value::Object(map) = &mut schema {
        map.insert(
            "$defs".into(),
            json!({
                "NodeId": {
                    "title": "NodeId",
                    "type": "string",
                    "description": "Stable node id emitted by observe/observe_diff."
                }
            }),
        );
    }
    schema
}

fn action_tool_schema() -> Value {
    let mut schema = action_json_schema();
    if let Value::Object(map) = &mut schema {
        map.insert(
            "description".into(),
            Value::String(
                "One tempo semantic action. Select exactly one variant by its kind field.".into(),
            ),
        );
    }
    schema
}

fn action_batch_tool_schema() -> Value {
    json!({
        "title": "ActionBatch",
        "type": "object",
        "additionalProperties": true,
        "required": ["actions", "quiescence"],
        "properties": {
            "actions": {
                "type": "array",
                "items": action_tool_schema()
            },
            "quiescence": quiescence_tool_schema()
        }
    })
}

fn quiescence_tool_schema() -> Value {
    json!({
        "title": "QuiescencePolicy",
        "description": "How tempo decides the page has settled after the batch.",
        "oneOf": [
            {
                "type": "string",
                "const": "composite",
                "description": "Wait for network idle, layout stability, and JS/microtask quiescence."
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["fixed_millis"],
                "properties": {
                    "fixed_millis": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Fallback fixed wait in milliseconds."
                    }
                }
            }
        ]
    })
}

fn input_tainted_tool_schema() -> Value {
    json!({
        "type": "boolean",
        "description": "Set true when any action argument comes from page-derived, user-provided, or otherwise untrusted content. Use false only for caller-authored constants; the server recomputes live observation taint and may escalate this claim."
    })
}

fn confirmed_tool_schema() -> Value {
    json!({
        "type": "boolean",
        "description": "Set true only after an explicit human confirmation for a policy-gated action."
    })
}

fn step_outcome_json(outcome: StepOutcome) -> Value {
    match outcome {
        StepOutcome::Applied { diff } => {
            json!({"status": "applied", "diff": diff})
        }
        StepOutcome::StepError { reason } => {
            json!({"status": "step_error", "reason": reason})
        }
    }
}

fn step_outcome_tool_call(outcome: StepOutcome) -> ToolCall {
    let is_error = matches!(outcome, StepOutcome::StepError { .. });
    let structured_content = step_outcome_json(outcome);
    let summary = tool_content_summary(&structured_content);
    ToolCall {
        is_error,
        structured_content,
        content: vec![text_content_block(summary)],
    }
}

fn probe_hit_json(hit: &ProbeHit) -> Value {
    json!({
        "signal": signal_name(hit.signal),
        "source": hit.source,
        "lane": handshake_lane_name(hit.signal.lane()),
    })
}

fn probe_response_json(response: &ProbeResponse) -> Value {
    json!({
        "path": &response.path,
        "status": response.status,
        "content_type": &response.content_type,
        "body_bytes": response.body.len(),
    })
}

fn probe_failure_json(failure: &HttpProbeFailure) -> Value {
    json!({
        "path": &failure.path,
        "url": &failure.url,
        "reason": &failure.reason,
    })
}

fn signal_name(signal: StructuredSignal) -> &'static str {
    match signal {
        StructuredSignal::BeaterJson => "beater_json",
        StructuredSignal::AgentCard => "agent_card",
        StructuredSignal::LlmsTxt => "llms_txt",
        StructuredSignal::OpenApi => "openapi",
        StructuredSignal::McpCatalog => "mcp_catalog",
        StructuredSignal::WebMcp => "web_mcp",
    }
}

fn handshake_lane_name(lane: HandshakeLane) -> &'static str {
    match lane {
        HandshakeLane::Render => "render",
        HandshakeLane::Api => "api",
        HandshakeLane::Mcp => "mcp",
    }
}

fn engine_name(engine: Engine) -> &'static str {
    if engine == Engine::Servo {
        "servo"
    } else if engine == Engine::Cdp {
        "cdp"
    } else {
        "test"
    }
}

fn loopback_origin_allowed(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(addr)) => addr == Ipv6Addr::LOCALHOST,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use base64::Engine as _;
    use serde_json::json;
    use tempo_driver::{TransportError, Unsupported};
    use tempo_net::UrlPolicy;
    use tempo_schema::{
        CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
    };

    use super::*;

    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    const TEST_SCREENSHOT_PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D',
        b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', 0x78, 0x9c, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, b'I',
        b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
    ];

    fn tool_input_schema(name: &str) -> Result<Value, String> {
        tool_descriptor_json()
            .into_iter()
            .find(|tool| tool["name"] == name)
            .map(|tool| tool["inputSchema"].clone())
            .ok_or_else(|| format!("missing tool schema for {name}"))
    }

    /// Poison a mutex by locking it on a thread that then panics; the guard's
    /// drop during unwind marks the mutex poisoned. Panic output is suppressed
    /// so the deliberate panic does not clutter the test log.
    fn poison_via_panicking_holder<T: Send>(mutex: &Mutex<T>) {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        // The panic unwinds while the guard is held, so its drop marks the
        // mutex poisoned; the scoped thread is joined here so the scope does
        // not resume the panic.
        let joined = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = match mutex.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    panic!("poison the lease mutex");
                })
                .join()
        });
        std::panic::set_hook(prev);
        assert!(joined.is_err(), "holder should have panicked");
        assert!(mutex.is_poisoned(), "mutex should now be poisoned");
    }

    #[test]
    fn poisoned_root_lease_slot_still_serves_the_driver() {
        // #443: a panic that poisons the lease mutex must not brick the slot.
        // The guarded `Option<D>` invariant survives the panic, so put/take
        // recover via `into_inner` instead of dropping the driver (which would
        // strand the slot empty and fail every later tool call with Busy).
        let slot = DriverSlot::new(7u32);
        poison_via_panicking_holder(&slot.slot);

        let driver = slot
            .take(Duration::from_millis(50))
            .unwrap_or_else(|_| panic!("take must recover from poison, not surface it as error"));
        assert_eq!(driver, 7);

        // put must return the driver rather than drop it on the poisoned lock...
        slot.put(driver);
        let again = slot
            .take(Duration::from_millis(50))
            .unwrap_or_else(|_| panic!("driver must still be leasable after put on poisoned slot"));
        assert_eq!(again, 7);
    }

    #[test]
    fn poisoned_fork_registry_still_leases_and_restores() {
        // #443 (same defect in `ForkSlots::restore`): a poisoned registry must
        // still lease and restore forks instead of dropping the driver and
        // stranding the entry `Leased` forever.
        let slots = ForkSlots::default();
        let driver_id = slots
            .register(Box::new(MemoryDriver::new()))
            .unwrap_or_else(|rejection| panic!("register failed: {}", rejection.reason));

        poison_via_panicking_holder(&slots.inner);

        let driver = slots
            .lease(&driver_id, Duration::from_millis(50))
            .unwrap_or_else(|_| panic!("lease must recover from poison"));
        slots.restore(&driver_id, driver);

        let again = slots
            .lease(&driver_id, Duration::from_millis(50))
            .unwrap_or_else(|_| {
                panic!("fork must still be leasable after restore on poisoned map")
            });
        slots.restore(&driver_id, again);
    }

    #[tokio::test]
    async fn initialize_and_tool_list_follow_mcp_shape() -> Result<(), String> {
        let server = TempoMcpServer::new(MemoryDriver::new());
        let initialize = server
            .handle_post(None, br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            .await
            .json_value()
            .map_err(|error| error.to_string())?;
        assert_eq!(
            initialize["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );

        let tools = server
            .handle_post(None, br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .await
            .json_value()
            .map_err(|error| error.to_string())?;
        let names = tools["result"]["tools"]
            .as_array()
            .ok_or("tools/list result must be an array")?
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "observe",
                "observe_diff",
                "act",
                "act_batch",
                "fork",
                "close_fork",
                "extract",
                "screenshot",
                "handshake"
            ]
        );
        Ok(())
    }

    #[test]
    fn tool_schemas_describe_action_batch_and_extract_inputs() -> Result<(), String> {
        let act = tool_input_schema("act")?;
        let action_variants = act["properties"]["action"]["oneOf"]
            .as_array()
            .ok_or("act action schema must enumerate action variants")?;
        assert!(
            action_variants
                .iter()
                .any(|variant| variant["properties"]["kind"]["const"] == "click"
                    && variant["properties"]["node"]["$ref"] == "#/$defs/NodeId"),
            "act action schema must expose click node shape"
        );
        assert_eq!(act["$defs"]["NodeId"]["type"], "string");
        assert!(
            act["properties"]["input_tainted"]["description"]
                .as_str()
                .map(|description| description.contains("caller-authored constants"))
                .unwrap_or(false),
            "input_tainted must tell callers how to compute the claim"
        );

        let batch = tool_input_schema("act_batch")?;
        let batch_action_items = &batch["properties"]["batch"]["properties"]["actions"]["items"];
        let batch_action_variants = batch_action_items["oneOf"]
            .as_array()
            .ok_or("act_batch actions.items schema must enumerate action variants")?;
        assert!(
            batch_action_variants
                .iter()
                .any(|variant| variant["properties"]["kind"]["const"] == "type"
                    && variant["properties"]["node"]["$ref"] == "#/$defs/NodeId"
                    && variant["properties"]["text"]["type"] == "string"),
            "act_batch actions.items must inline the action schema"
        );
        assert_eq!(batch["$defs"]["NodeId"]["type"], "string");
        assert_eq!(
            batch["properties"]["batch"]["properties"]["quiescence"]["oneOf"][0]["const"],
            "composite"
        );

        let extract = tool_input_schema("extract")?;
        assert_eq!(extract["required"], json!(["node"]));
        let extract_properties = extract["properties"]
            .as_object()
            .ok_or("extract properties must be an object")?;
        assert!(extract_properties.contains_key("node"));
        assert!(!extract_properties.contains_key("node_id"));
        assert!(
            extract["properties"]["node"]["description"]
                .as_str()
                .map(|description| description.contains("observe/observe_diff"))
                .unwrap_or(false),
            "extract node must explain where the id comes from"
        );
        Ok(())
    }

    #[test]
    fn agent_card_advertises_real_mcp_interface_and_tools() -> Result<(), String> {
        let response = agent_card_response("http://127.0.0.1:8787/");
        let card = response.json_value().map_err(|error| error.to_string())?;
        let skills = card["skills"]
            .as_array()
            .ok_or("agent-card skills must be an array")?;

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, A2A_AGENT_CARD_CONTENT_TYPE);
        assert_eq!(card["name"], "tempo");
        assert_eq!(card["url"], "http://127.0.0.1:8787/mcp");
        assert_eq!(card["preferredTransport"], "MCP");
        assert_eq!(
            card["additionalInterfaces"][0]["url"],
            "http://127.0.0.1:8787/mcp"
        );
        assert!(skills.iter().any(|skill| skill["id"] == "observe"));
        assert!(skills.iter().any(|skill| skill["id"] == "observe_diff"));
        assert!(skills.iter().any(|skill| skill["id"] == "handshake"));
        Ok(())
    }

    #[tokio::test]
    async fn observe_act_extract_and_screenshot_call_real_driver_trait() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let observe = call_tool(&mut server, "observe", json!({})).await?;
        assert_eq!(observe["url"], "https://example.test/");

        let diff = call_tool(&mut server, "observe_diff", json!({"since_seq": 0})).await?;
        assert_eq!(diff["since_seq"], 0);
        assert_eq!(diff["seq"], 1);
        assert_eq!(diff["changed"][0]["node_id"], "button.primary");

        let act = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(act["status"], "applied");
        assert_eq!(act["diff"]["seq"], 2);

        let batch = call_tool(
            &mut server,
            "act_batch",
            json!({
                "batch": {
                    "actions": [{"kind": "scroll", "x": 0.0, "y": 12.0}],
                    "quiescence": "composite"
                },
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(batch["status"], "applied");
        assert_eq!(batch["diff"]["seq"], 3);

        let extract = call_tool(&mut server, "extract", json!({"node": "button.primary"})).await?;
        assert_eq!(extract["node"], "button.primary");

        let screenshot = call_tool_envelope(&mut server, "screenshot", json!({})).await?;
        let screenshot_meta = &screenshot["result"]["structuredContent"];
        assert_eq!(screenshot_meta["mime_type"], "image/png");
        assert_eq!(screenshot_meta["set_of_marks"], false);
        assert!(screenshot_meta.get("data").is_none());
        assert!(screenshot_meta.get("encoding").is_none());
        let bytes = decode_image_content(&screenshot)?;
        assert_eq!(bytes, TEST_SCREENSHOT_PNG);
        Ok(())
    }

    #[tokio::test]
    async fn tool_result_text_content_is_summary_not_structured_payload() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let envelope = call_tool_envelope(&mut server, "observe", json!({})).await?;
        let result = &envelope["result"];
        let structured = &result["structuredContent"];
        let summary = result["content"][0]["text"]
            .as_str()
            .ok_or("tool result text content must be text")?;
        let structured_json =
            serde_json::to_string(structured).map_err(|error| error.to_string())?;

        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(summary, "observation seq=1, elements=1, omitted=0");
        assert!(summary.len() < structured_json.len());
        assert_ne!(summary, structured_json);
        assert!(!summary.contains("button.primary"));
        Ok(())
    }

    #[tokio::test]
    async fn act_requires_explicit_input_taint_evidence() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let error = call_tool(
            &mut server,
            "act",
            json!({"action": {"kind": "click", "node": "button.primary"}}),
        )
        .await
        .err()
        .ok_or("act without input_tainted should fail")?;

        assert!(error.contains("input_tainted is required"));
        Ok(())
    }

    #[tokio::test]
    async fn act_step_error_sets_mcp_error_envelope() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new().with_step_error("node not found"));

        let response = call_tool_envelope(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;

        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["status"],
            "step_error"
        );
        assert_eq!(
            response["result"]["structuredContent"]["reason"],
            "node not found"
        );
        Ok(())
    }

    #[tokio::test]
    async fn act_batch_step_error_sets_mcp_error_envelope() -> Result<(), String> {
        let mut server =
            TempoMcpServer::new(MemoryDriver::new().with_step_error("not interactable"));

        let response = call_tool_envelope(
            &mut server,
            "act_batch",
            json!({
                "batch": {
                    "actions": [{"kind": "scroll", "x": 0.0, "y": 12.0}],
                    "quiescence": "composite"
                },
                "input_tainted": false
            }),
        )
        .await?;

        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["status"],
            "step_error"
        );
        assert_eq!(
            response["result"]["structuredContent"]["reason"],
            "not interactable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn act_denies_unconfirmed_tainted_write_before_driver_execution() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        // Escalate path: the caller CAN mark input more tainted than the
        // server sees, and the gate honors it.
        let denied = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "click", "node": "button.primary"},
                "input_tainted": true
            }),
        )
        .await?;
        assert_eq!(denied["error"]["type"], "confirmation_required");
        assert_eq!(denied["error"]["input_tainted"], true);
        let denial = denied["error"]["message"]
            .as_str()
            .ok_or("policy denial should carry a message")?;
        assert!(denial.contains("policy denied"));

        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["status"], "applied");
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn act_batch_denies_unconfirmed_tainted_action_before_driver_execution(
    ) -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let denied = call_tool(
            &mut server,
            "act_batch",
            json!({
                "batch": {
                    "actions": [{"kind": "click", "node": "button.primary"}],
                    "quiescence": "composite"
                },
                "input_tainted": true
            }),
        )
        .await?;
        assert_eq!(denied["error"]["type"], "confirmation_required");
        let denial = denied["error"]["message"]
            .as_str()
            .ok_or("policy denial should carry a message")?;
        assert!(denial.contains("policy denied"));

        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["status"], "applied");
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn act_confirmed_claim_cannot_bypass_gate_without_confirmation_channel(
    ) -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        // Pre-#254 this was allowed: a bare confirmed=true from the same
        // caller requesting the action bypassed the human gate. Now the flag
        // is advisory and the gate stays closed until a server-attributable
        // confirmation channel exists.
        let denied = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "click", "node": "button.primary"},
                "input_tainted": false,
                "confirmed": true
            }),
        )
        .await?;

        assert_eq!(denied["error"]["type"], "confirmation_required");
        assert_eq!(denied["error"]["gate"], "confirm");
        assert_eq!(denied["error"]["input_tainted"], true);
        let message = denied["error"]["message"]
            .as_str()
            .ok_or("denial should carry a message")?;
        assert!(message.contains("confirmed=true was ignored"));

        // The driver never executed the action: the next clean act is seq 2.
        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn act_denies_client_claimed_clean_skill_without_confirmation_channel(
    ) -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let denied = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "skill", "name": "checkout", "input": {"account": "fresh-user-value"}},
                "input_tainted": false,
                "confirmed": true
            }),
        )
        .await?;

        assert_eq!(denied["error"]["type"], "confirmation_required");
        assert_eq!(denied["error"]["side_effect"], "write");
        assert_eq!(denied["error"]["input_tainted"], true);
        let message = denied["error"]["message"]
            .as_str()
            .ok_or("denial should carry a message")?;
        assert!(message.contains("confirmed=true was ignored"));

        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn act_recomputes_taint_from_observation_and_blocks_clean_claim() -> Result<(), String> {
        // The MemoryDriver observation carries the page-provenance span
        // "Continue". Navigating to a case-only variant derived from it while
        // claiming input_tainted=false must be blocked by server-side
        // recomputation; this fails if recomputation is removed or
        // case-sensitive.
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let denied = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "goto", "url": "https://evil.example/continue"},
                "input_tainted": false,
                "confirmed": true
            }),
        )
        .await?;
        assert_eq!(denied["error"]["type"], "confirmation_required");
        assert_eq!(denied["error"]["input_tainted"], true);
        assert_eq!(denied["error"]["side_effect"], "read");

        // Unmatched clean reads still execute: recomputation is evidence-based,
        // while external writes fail closed until a confirmation channel exists.
        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "goto", "url": "https://fresh.example/"},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["status"], "applied");
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn act_batch_recomputes_taint_from_observation_and_blocks_clean_claim(
    ) -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let denied = call_tool(
            &mut server,
            "act_batch",
            json!({
                "batch": {
                    "actions": [
                        {"kind": "scroll", "x": 0.0, "y": 12.0},
                        {"kind": "goto", "url": "https://evil.example/continue"}
                    ],
                    "quiescence": "composite"
                },
                "input_tainted": false,
                "confirmed": true
            }),
        )
        .await?;
        assert_eq!(denied["error"]["type"], "confirmation_required");
        assert_eq!(denied["error"]["input_tainted"], true);

        // The batch never executed.
        let clean = call_tool(
            &mut server,
            "act",
            json!({
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        assert_eq!(clean["diff"]["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn screenshot_tool_can_overlay_set_of_marks() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let raw = call_tool_envelope(&mut server, "screenshot", json!({})).await?;
        let marked =
            call_tool_envelope(&mut server, "screenshot", json!({"set_of_marks": true})).await?;

        assert_eq!(
            marked["result"]["structuredContent"]["mime_type"],
            "image/png"
        );
        assert_eq!(marked["result"]["structuredContent"]["set_of_marks"], true);
        assert!(marked["result"]["structuredContent"].get("data").is_none());
        let raw_bytes = decode_image_content(&raw)?;
        let marked_bytes = decode_image_content(&marked)?;
        assert!(marked_bytes.starts_with(PNG_SIGNATURE));
        assert_ne!(marked_bytes, raw_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn extract_tool_rejects_oversized_json() -> Result<(), String> {
        let mut server = TempoMcpServer::new(
            MemoryDriver::new().with_extract(json!({"blob": "x".repeat(MAX_EXTRACT_JSON_BYTES)})),
        );

        let result = call_tool(&mut server, "extract", json!({"node": "button.primary"})).await?;
        assert_eq!(result["error"]["type"], "response_too_large");
        assert_eq!(result["error"]["artifact"], "extract_json");
        assert_eq!(result["error"]["max_bytes"], MAX_EXTRACT_JSON_BYTES);
        Ok(())
    }

    #[tokio::test]
    async fn screenshot_tool_rejects_oversized_bytes_before_base64() -> Result<(), String> {
        let mut server =
            TempoMcpServer::new(
                MemoryDriver::new().with_screenshot(vec![0_u8; MAX_SCREENSHOT_BYTES + 1]),
            );

        let result = call_tool(&mut server, "screenshot", json!({})).await?;
        assert_eq!(result["error"]["type"], "response_too_large");
        assert_eq!(result["error"]["artifact"], "screenshot");
        assert_eq!(result["error"]["bytes"], MAX_SCREENSHOT_BYTES + 1);
        assert_eq!(result["error"]["max_bytes"], MAX_SCREENSHOT_BYTES);
        Ok(())
    }

    #[test]
    fn mcp_json_rpc_response_serialization_is_capped() -> Result<(), String> {
        let response = json_rpc_success_response(
            json!(99),
            json!({"blob": "x".repeat(MAX_PROTOCOL_RESPONSE_BYTES)}),
        );
        let value = response.json_value().map_err(|error| error.to_string())?;

        assert_eq!(response.status, 200);
        assert_eq!(value["error"]["code"], RESPONSE_TOO_LARGE_ERROR_CODE);
        assert!(value["error"]["message"]
            .as_str()
            .ok_or("missing cap message")?
            .contains("mcp_response exceeded output cap"));
        Ok(())
    }

    #[tokio::test]
    async fn fork_returns_driver_id_and_routes_targeted_tools() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let fork = call_tool(&mut server, "fork", json!({})).await?;
        let driver_id = fork["driver_id"]
            .as_str()
            .ok_or("fork response must include driver_id")?
            .to_string();
        assert_eq!(fork["supported"], true);
        assert_eq!(driver_id, "fork-1");
        assert_eq!(fork["engine"], "cdp");

        let fork_act = call_tool(
            &mut server,
            "act",
            json!({
                "driver_id": driver_id.clone(),
                "action": {"kind": "scroll", "x": 0.0, "y": 12.0},
                "input_tainted": false
            }),
        )
        .await?;
        let root_observe = call_tool(&mut server, "observe", json!({})).await?;
        let fork_observe = call_tool(
            &mut server,
            "observe",
            json!({"driver_id": driver_id.clone()}),
        )
        .await?;
        let fork_diff = call_tool(
            &mut server,
            "observe_diff",
            json!({"driver_id": driver_id, "since_seq": 1}),
        )
        .await?;

        assert_eq!(fork_act["status"], "applied");
        assert_eq!(fork_act["diff"]["seq"], 2);
        assert_eq!(root_observe["seq"], 1);
        assert_eq!(fork_observe["seq"], 2);
        assert_eq!(fork_diff["since_seq"], 1);
        assert_eq!(fork_diff["seq"], 2);
        Ok(())
    }

    #[tokio::test]
    async fn close_fork_closes_and_removes_forked_driver() -> Result<(), String> {
        let driver = MemoryDriver::new();
        let closed_counter = Arc::clone(&driver.closed);
        let mut server = TempoMcpServer::new(driver);

        let fork = call_tool(&mut server, "fork", json!({})).await?;
        let driver_id = fork["driver_id"]
            .as_str()
            .ok_or("fork response must include driver_id")?
            .to_string();

        let closed = call_tool(
            &mut server,
            "close_fork",
            json!({"driver_id": driver_id.clone()}),
        )
        .await?;
        assert_eq!(closed["closed"], true);
        // The forked driver's close() ran (fork shares the counter handle).
        assert_eq!(closed_counter.load(Ordering::SeqCst), 1);

        // The fork is gone: targeting it now errors, and a repeat close reports it missing.
        let reuse = call_tool(
            &mut server,
            "observe",
            json!({"driver_id": driver_id.clone()}),
        )
        .await;
        assert!(reuse.is_err(), "targeting a closed fork must fail");

        let missing = call_tool(&mut server, "close_fork", json!({"driver_id": driver_id})).await?;
        assert!(missing["error"]
            .as_str()
            .ok_or("close_fork on unknown id must return error text")?
            .contains("unknown driver_id"));
        Ok(())
    }

    #[tokio::test]
    async fn fork_limit_is_enforced_and_rejected_fork_is_closed() -> Result<(), String> {
        let driver = MemoryDriver::new();
        let closed_counter = Arc::clone(&driver.closed);
        let mut server = TempoMcpServer::new(driver);
        for _ in 0..MAX_LIVE_FORKS {
            let fork = call_tool(&mut server, "fork", json!({})).await?;
            assert_eq!(fork["supported"], true);
        }

        let over_limit = call_tool(&mut server, "fork", json!({})).await?;
        let reason = over_limit["error"]
            .as_str()
            .ok_or("fork past the limit must return an error")?;
        assert!(reason.contains("fork limit reached"), "{reason}");
        // The rejected fork was closed instead of leaking.
        assert_eq!(closed_counter.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn close_all_forks_closes_every_live_fork() -> Result<(), String> {
        let driver = MemoryDriver::new();
        let closed_counter = Arc::clone(&driver.closed);
        let mut server = TempoMcpServer::new(driver);
        for _ in 0..3 {
            call_tool(&mut server, "fork", json!({})).await?;
        }

        let errors = server.close_all_forks().await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(closed_counter.load(Ordering::SeqCst), 3);

        // Every fork was dropped from the session map.
        let missing = call_tool(&mut server, "close_fork", json!({"driver_id": "fork-1"})).await?;
        assert!(missing["error"]
            .as_str()
            .ok_or("expected error text")?
            .contains("unknown driver_id"));
        Ok(())
    }

    #[test]
    fn handshake_probe_target_follows_live_http_intent() {
        // An origin without inline responses probes live by default.
        let default_on = HandshakeArgs {
            origin: Some("https://example.test".into()),
            ..Default::default()
        };
        assert_eq!(
            handshake_probe_target(&default_on).as_deref(),
            Some("https://example.test")
        );

        // Explicitly disabled: no probe even with an origin present.
        let disabled = HandshakeArgs {
            origin: Some("https://example.test".into()),
            live_http: Some(false),
            ..Default::default()
        };
        assert_eq!(handshake_probe_target(&disabled), None);

        // Inline responses suppress the default live probe.
        let with_responses = HandshakeArgs {
            origin: Some("https://example.test".into()),
            responses: vec![ProbeResponseInput {
                path: "/openapi.json".into(),
                status: 200,
                content_type: None,
                body: String::new(),
            }],
            ..Default::default()
        };
        assert_eq!(handshake_probe_target(&with_responses), None);

        // No origin: nothing to probe even when forced on.
        let forced = HandshakeArgs {
            live_http: Some(true),
            ..Default::default()
        };
        assert_eq!(handshake_probe_target(&forced), None);
    }

    #[tokio::test]
    async fn handshake_tool_uses_probe_report_and_lane_decision() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());
        let result = call_tool(
            &mut server,
            "handshake",
            json!({
                "origin": "https://example.test",
                "responses": [{
                    "path": "/mcp/catalog.json",
                    "status": 200,
                    "content_type": "application/json",
                    "body": "{\"tools\":[]}"
                }]
            }),
        )
        .await?;

        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        assert_eq!(
            result["probe_urls"][0],
            "https://example.test/.well-known/beater.json"
        );
        assert_eq!(result["live_http"], false);
        assert_eq!(result["web_mcp"]["checked"], true);
        assert_eq!(result["web_mcp"]["available"], false);
        assert!(result["probe_responses"]
            .as_array()
            .ok_or("probe_responses must be an array")?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_detects_web_mcp_from_driver_script() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new().with_web_mcp());
        let result = call_tool(
            &mut server,
            "handshake",
            json!({"origin": "https://example.test", "live_http": false}),
        )
        .await?;

        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "web_mcp");
        assert_eq!(result["selected"]["source"], "navigator.modelContext");
        assert_eq!(result["web_mcp"]["checked"], true);
        assert_eq!(result["web_mcp"]["available"], true);
        assert_eq!(result["web_mcp"]["type"], "object");
        assert_eq!(result["web_mcp"]["has_tools"], true);
        assert_eq!(result["web_mcp"]["skipped_reason"], Value::Null);
        assert_eq!(
            result["web_mcp"]["requested_origin"],
            "https://example.test"
        );
        assert_eq!(result["web_mcp"]["page_origin"], "https://example.test");
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_skips_web_mcp_when_driver_origin_mismatches() -> Result<(), String> {
        let mut server = TempoMcpServer::new(
            MemoryDriver::new()
                .with_url("https://current.example/app")
                .with_web_mcp(),
        );
        let result = call_tool(
            &mut server,
            "handshake",
            json!({
                "origin": "https://api.example",
                "responses": [{
                    "path": "/openapi.json",
                    "status": 200,
                    "content_type": "application/json",
                    "body": "{\"openapi\":\"3.1.0\"}"
                }]
            }),
        )
        .await?;

        assert_eq!(result["lane"], "api");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "openapi");
        assert_eq!(result["web_mcp"]["checked"], false);
        assert_eq!(result["web_mcp"]["available"], false);
        assert_eq!(
            result["web_mcp"]["skipped_reason"],
            "current page origin does not match requested origin"
        );
        assert_eq!(result["web_mcp"]["requested_origin"], "https://api.example");
        assert_eq!(result["web_mcp"]["page_origin"], "https://current.example");
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_without_origin_preserves_current_page_web_mcp() -> Result<(), String> {
        let mut server = TempoMcpServer::new(
            MemoryDriver::new()
                .with_url("https://current.example/app")
                .with_web_mcp(),
        );
        let result = call_tool(&mut server, "handshake", json!({})).await?;

        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["selected"]["signal"], "web_mcp");
        assert_eq!(result["web_mcp"]["checked"], true);
        assert_eq!(result["web_mcp"]["available"], true);
        assert_eq!(result["web_mcp"]["skipped_reason"], Value::Null);
        assert_eq!(result["web_mcp"]["requested_origin"], Value::Null);
        assert_eq!(result["web_mcp"]["page_origin"], Value::Null);
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_does_not_select_unusable_web_mcp_object() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new().with_unusable_web_mcp());
        let result = call_tool(
            &mut server,
            "handshake",
            json!({"origin": "https://example.test", "live_http": false}),
        )
        .await?;

        assert_ne!(result["selected"]["signal"], "web_mcp");
        assert_eq!(result["lane"], "render");
        assert_eq!(result["skips_render"], false);
        assert_eq!(result["web_mcp"]["checked"], true);
        assert_eq!(result["web_mcp"]["available"], true);
        assert_eq!(result["web_mcp"]["type"], "object");
        assert_eq!(result["web_mcp"]["has_tools"], false);
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_does_not_select_method_only_web_mcp() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new().with_method_only_web_mcp());
        let result = call_tool(
            &mut server,
            "handshake",
            json!({"origin": "https://example.test", "live_http": false}),
        )
        .await?;

        assert_ne!(result["selected"]["signal"], "web_mcp");
        assert_eq!(result["lane"], "render");
        assert_eq!(result["skips_render"], false);
        assert_eq!(result["web_mcp"]["checked"], true);
        assert_eq!(result["web_mcp"]["available"], true);
        assert_eq!(result["web_mcp"]["type"], "object");
        assert_eq!(result["web_mcp"]["has_tools"], false);
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_runs_live_http_probe_for_origin() -> Result<(), String> {
        let (origin, server) = serve_handshake_fixture().map_err(|error| error.to_string())?;
        let mut server_under_test = TempoMcpServer::new(MemoryDriver::new())
            .with_handshake_probe_config(
                HttpProbeConfig::default().with_url_policy(UrlPolicy::allow_all()),
            );

        let result = call_tool(
            &mut server_under_test,
            "handshake",
            json!({"origin": origin}),
        )
        .await?;
        join_server(server)?;

        assert_eq!(result["live_http"], true);
        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        assert_eq!(
            result["probe_responses"]
                .as_array()
                .ok_or("probe_responses must be an array")?
                .len(),
            tempo_handshake::DEFAULT_HTTP_PROBES.len()
        );
        assert!(result["probe_failures"]
            .as_array()
            .ok_or("probe_failures must be an array")?
            .is_empty());
        Ok(())
    }

    #[test]
    fn handshake_live_probe_runs_without_a_tokio_runtime() -> Result<(), String> {
        // Regression guard for the production tempod path (#94/#121 follow-up):
        // `tempo-headless::route_mcp` drives this async server with
        // `futures::executor::block_on` and there is NO tokio runtime present.
        // The live handshake probe must therefore not use
        // `tokio::task::spawn_blocking`, which panics ("must be called from the
        // context of a Tokio 1.x runtime") outside a tokio runtime. This test
        // deliberately runs as a plain `#[test]` (not `#[tokio::test]`) and
        // drives the probe via `block_on`, exactly like the daemon does.
        //
        // Against the pre-fix code this call panicked inside `block_on`, failing
        // the test; the fix runs the blocking probe on a std thread instead.
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "regression guard must run without a tokio runtime"
        );

        let (origin, fixture) = serve_handshake_fixture().map_err(|error| error.to_string())?;
        let server = TempoMcpServer::new(MemoryDriver::new()).with_handshake_probe_config(
            HttpProbeConfig::default().with_url_policy(UrlPolicy::allow_all()),
        );
        let body = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "handshake", "arguments": {"origin": origin}},
        });
        let response =
            futures::executor::block_on(server.handle_post(None, body.to_string().as_bytes()));
        join_server(fixture)?;

        let value = response.json_value().map_err(|error| error.to_string())?;
        assert!(
            value.get("error").is_none(),
            "handshake returned an error: {value}"
        );
        let result = &value["result"]["structuredContent"];
        assert_eq!(result["live_http"], true);
        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        Ok(())
    }

    #[tokio::test]
    async fn handshake_tool_reports_url_policy_failures() -> Result<(), String> {
        let mut server = TempoMcpServer::new(MemoryDriver::new());

        let result = call_tool(
            &mut server,
            "handshake",
            json!({"origin": "http://127.0.0.1:9"}),
        )
        .await?;

        assert_eq!(result["live_http"], true);
        assert_eq!(result["lane"], "render");
        assert!(result["probe_responses"]
            .as_array()
            .ok_or("probe_responses must be an array")?
            .is_empty());
        let failures = result["probe_failures"]
            .as_array()
            .ok_or("probe_failures must be an array")?;
        assert_eq!(failures.len(), tempo_handshake::DEFAULT_HTTP_PROBES.len());
        assert!(failures.iter().all(|failure| failure["reason"]
            .as_str()
            .map(|reason| reason.contains("URL blocked"))
            .unwrap_or(false)));
        Ok(())
    }

    #[test]
    fn driverless_mcp_serves_metadata_and_handshake_without_engine() -> Result<(), String> {
        let tools =
            handle_post_driverless(None, br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
                .json_value()
                .map_err(|error| error.to_string())?;
        assert_eq!(tools["result"]["tools"][0]["name"], "observe");

        let handshake = handle_post_driverless(
            None,
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"handshake","arguments":{"origin":"https://example.test","responses":[{"path":"/openapi.json","status":200,"content_type":"application/json","body":"{\"openapi\":\"3.1.0\"}"}]}}}"#,
        )
        .json_value()
        .map_err(|error| error.to_string())?;
        let result = &handshake["result"]["structuredContent"];
        assert_eq!(result["lane"], "api");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "openapi");

        let observe = handle_post_driverless(
            None,
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#,
        )
        .json_value()
        .map_err(|error| error.to_string())?;
        assert_eq!(observe["error"]["code"], DRIVER_REQUIRED_ERROR_CODE);
        assert!(observe["error"]["message"]
            .as_str()
            .ok_or("missing driver-required message")?
            .contains("attached engine driver"));
        Ok(())
    }

    #[tokio::test]
    async fn protocol_errors_and_notifications_have_http_semantics() -> Result<(), String> {
        let server = TempoMcpServer::new(MemoryDriver::new());
        let malformed = server.handle_post(None, b"{not-json").await;
        assert_eq!(malformed.status, 400);
        assert_eq!(
            malformed.json_value().map_err(|error| error.to_string())?["error"]["code"],
            -32700
        );

        let notification = server
            .handle_post(None, br#"{"jsonrpc":"2.0","method":"ping"}"#)
            .await;
        assert_eq!(notification.status, 202);
        assert!(notification.body.is_empty());

        let invalid_id = server
            .handle_post(
                None,
                br#"{"jsonrpc":"2.0","id":{"bad":true},"method":"ping"}"#,
            )
            .await;
        assert_eq!(invalid_id.status, 400);
        let invalid_id_body = invalid_id.json_value().map_err(|error| error.to_string())?;
        assert_eq!(invalid_id_body["error"]["code"], -32600);
        assert!(invalid_id_body["error"]["message"]
            .as_str()
            .ok_or("missing invalid id message")?
            .contains("id must be"));

        let get = handle_get();
        assert_eq!(get.status, 405);
        assert_eq!(get.content_type, "text/plain; charset=utf-8");
        Ok(())
    }

    #[test]
    fn origin_validation_accepts_only_loopback_origins() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://localhost")));
        assert!(origin_allowed(Some("https://localhost:3000")));
        assert!(origin_allowed(Some("http://127.0.0.1:5173")));
        assert!(origin_allowed(Some("http://[::1]:3000")));

        for origin in [
            "http://localhost.evil.test",
            "http://127.0.0.1.evil.test",
            "https://example.test",
            "file:///tmp/page.html",
            "http://user@localhost",
            "http://localhost/path",
            "null",
        ] {
            assert!(!origin_allowed(Some(origin)), "{origin}");
        }
    }

    fn tool_call_body(id: u64, name: &str, arguments: Value) -> Vec<u8> {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        })
        .to_string()
        .into_bytes()
    }

    fn blocking_tool_call(
        server: &Arc<TempoMcpServer<MemoryDriver>>,
        id: u64,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let response = futures::executor::block_on(
            server.handle_post(None, &tool_call_body(id, name, arguments)),
        );
        response.json_value().map_err(|error| error.to_string())
    }

    #[test]
    fn tool_calls_on_distinct_drivers_run_concurrently() -> Result<(), String> {
        // Root + fork each take ~200ms to observe. If the server still
        // serialized all tool calls behind one lock (pre-#230), the pair would
        // take >=400ms; concurrent dispatch finishes in ~200ms.
        let driver = MemoryDriver::new().with_observe_delay(Duration::from_millis(200));
        let server = Arc::new(TempoMcpServer::new(driver));

        let fork = blocking_tool_call(&server, 1, "fork", json!({}))?;
        let fork_id = fork["result"]["structuredContent"]["driver_id"]
            .as_str()
            .ok_or("fork must return a driver_id")?
            .to_string();

        let started = Instant::now();
        let root_server = Arc::clone(&server);
        let root_call =
            std::thread::spawn(move || blocking_tool_call(&root_server, 2, "observe", json!({})));
        let fork_server = Arc::clone(&server);
        let fork_call = std::thread::spawn(move || {
            blocking_tool_call(&fork_server, 3, "observe", json!({"driver_id": fork_id}))
        });
        let root_result = root_call.join().map_err(|_| "root call panicked")??;
        let fork_result = fork_call.join().map_err(|_| "fork call panicked")??;
        let elapsed = started.elapsed();

        assert!(root_result.get("error").is_none(), "{root_result}");
        assert!(fork_result.get("error").is_none(), "{fork_result}");
        assert!(
            elapsed < Duration::from_millis(350),
            "tool calls on distinct drivers did not overlap: {elapsed:?}"
        );
        Ok(())
    }

    #[test]
    fn same_driver_tool_calls_stay_serialized() -> Result<(), String> {
        // Two concurrent observes on the ROOT driver must not interleave: the
        // per-driver lease keeps same-driver ordering while releasing
        // unrelated drivers (issue #230).
        let driver = MemoryDriver::new().with_observe_delay(Duration::from_millis(150));
        let spans = Arc::clone(&driver.observe_spans);
        let server = Arc::new(TempoMcpServer::new(driver));

        let first_server = Arc::clone(&server);
        let first =
            std::thread::spawn(move || blocking_tool_call(&first_server, 1, "observe", json!({})));
        let second_server = Arc::clone(&server);
        let second =
            std::thread::spawn(move || blocking_tool_call(&second_server, 2, "observe", json!({})));
        let first_result = first.join().map_err(|_| "first call panicked")??;
        let second_result = second.join().map_err(|_| "second call panicked")??;
        assert!(first_result.get("error").is_none(), "{first_result}");
        assert!(second_result.get("error").is_none(), "{second_result}");

        let mut spans = spans.lock().map_err(|_| "span log poisoned")?.clone();
        spans.sort_by_key(|(start, _)| *start);
        assert_eq!(spans.len(), 2);
        assert!(
            spans[1].0 >= spans[0].1,
            "same-driver observes overlapped: {spans:?}"
        );
        Ok(())
    }

    #[test]
    fn same_driver_call_beyond_lease_bound_fails_driver_busy() -> Result<(), String> {
        // An op that outlives DRIVER_LEASE_TIMEOUT makes a queued same-driver
        // call fail with the bounded driver-busy error instead of waiting
        // forever.
        let driver = MemoryDriver::new()
            .with_observe_delay(DRIVER_LEASE_TIMEOUT + Duration::from_millis(300));
        let server = Arc::new(TempoMcpServer::new(driver));

        let long_server = Arc::clone(&server);
        let long_call =
            std::thread::spawn(move || blocking_tool_call(&long_server, 1, "observe", json!({})));
        // Lose the race deterministically.
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let busy = blocking_tool_call(&server, 2, "observe", json!({}))?;
        let waited = started.elapsed();

        assert_eq!(busy["error"]["code"], DRIVER_BUSY_ERROR_CODE, "{busy}");
        assert!(
            waited < DRIVER_LEASE_TIMEOUT + Duration::from_millis(400),
            "driver-busy wait was not bounded: {waited:?}"
        );
        let long_result = long_call.join().map_err(|_| "long call panicked")??;
        assert!(long_result.get("error").is_none(), "{long_result}");
        Ok(())
    }

    #[test]
    fn handshake_live_probe_cap_returns_structured_tool_error() -> Result<(), String> {
        let server =
            Arc::new(TempoMcpServer::new(MemoryDriver::new()).with_handshake_probe_limit(1));
        let permit = server
            .handshake_probe_limiter
            .try_acquire()
            .map_err(|limit| format!("unexpected limiter rejection: {limit:?}"))?;

        let value = blocking_tool_call(
            &server,
            42,
            "handshake",
            json!({"origin": "https://example.test"}),
        )?;

        assert!(value.get("error").is_none(), "{value}");
        let result = &value["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["type"],
            HANDSHAKE_PROBE_LIMIT_ERROR_CODE
        );
        assert_eq!(result["structuredContent"]["error"]["max_concurrent"], 1);
        assert!(result["content"][0]["text"]
            .as_str()
            .ok_or("text content must be a string")?
            .contains("live HTTP handshake probe limit reached"));

        drop(permit);
        assert!(
            server.handshake_probe_limiter.try_acquire().is_ok(),
            "permit drop must release limiter capacity"
        );
        Ok(())
    }

    #[test]
    fn fork_in_flight_across_close_all_forks_is_closed_not_leaked() -> Result<(), String> {
        // #230 review blocker: a `fork` whose engine round-trip completes
        // AFTER close_all_forks took its teardown snapshot must not register
        // into a registry nobody will close again. The retired registry
        // refuses the late registration and the tool call closes its own
        // fork. Reverted (no retirement), the late fork registers
        // successfully and is never closed — both assertions below fail.
        let driver = MemoryDriver::new().with_fork_delay(Duration::from_millis(300));
        let closed_counter = Arc::clone(&driver.closed);
        let server = Arc::new(TempoMcpServer::new(driver));

        let fork_server = Arc::clone(&server);
        let in_flight =
            std::thread::spawn(move || blocking_tool_call(&fork_server, 1, "fork", json!({})));
        // Let the fork reach its engine round-trip, then tear down (drain).
        std::thread::sleep(Duration::from_millis(100));
        let errors = futures::executor::block_on(server.close_all_forks());
        assert!(errors.is_empty(), "{errors:?}");

        let fork_result = in_flight.join().map_err(|_| "fork call panicked")??;
        let error_text = fork_result["result"]["structuredContent"]["error"]
            .as_str()
            .ok_or_else(|| {
                format!("late fork must be refused after close_all_forks: {fork_result}")
            })?;
        assert!(error_text.contains("shut down"), "{error_text}");
        // The refused fork was closed, not leaked.
        assert_eq!(closed_counter.load(Ordering::SeqCst), 1);
        Ok(())
    }

    async fn call_tool(
        server: &mut TempoMcpServer<MemoryDriver>,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let value = call_tool_envelope(server, name, arguments).await?;
        if value.get("error").is_some() {
            return Err(value.to_string());
        }
        Ok(value["result"]["structuredContent"].clone())
    }

    async fn call_tool_envelope(
        server: &mut TempoMcpServer<MemoryDriver>,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        });
        let response = server.handle_post(None, body.to_string().as_bytes()).await;
        response.json_value().map_err(|error| error.to_string())
    }

    fn decode_base64_field(value: &Value, field: &str) -> Result<Vec<u8>, String> {
        let encoded = value[field]
            .as_str()
            .ok_or_else(|| format!("{field} must be a string"))?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| error.to_string())
    }

    fn decode_image_content(envelope: &Value) -> Result<Vec<u8>, String> {
        let image = &envelope["result"]["content"][0];
        if image["type"] != "image" {
            return Err(format!("expected MCP image content, got {image}"));
        }
        if image["mimeType"] != "image/png" {
            return Err(format!("expected image/png content, got {image}"));
        }
        decode_base64_field(image, "data")
    }

    fn serve_handshake_fixture(
    ) -> Result<(String, thread::JoinHandle<Result<(), io::Error>>), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), io::Error> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut handled = 0;
            while handled < tempo_handshake::DEFAULT_HTTP_PROBES.len() {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        handle_probe_stream(stream)?;
                        handled += 1;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "timed out waiting for live handshake probes",
                            ));
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok((format!("http://{addr}"), handle))
    }

    fn handle_probe_stream(mut stream: TcpStream) -> Result<(), io::Error> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(io::Error::other("request headers exceeded fixture cap"));
            }
        }

        let request = String::from_utf8_lossy(&request);
        let first_line = request
            .lines()
            .next()
            .ok_or_else(|| io::Error::other("missing request line"))?;
        let path = first_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| io::Error::other("missing request path"))?;

        let (status, content_type, body) = match path {
            "/.well-known/beater.json" => (
                "200 OK",
                "application/json",
                r#"{"version":"1","tools":[]}"#,
            ),
            "/agent-card.json" => ("404 Not Found", "text/plain", ""),
            "/llms.txt" => ("200 OK", "text/plain", "# Fixture"),
            "/openapi.json" => ("404 Not Found", "text/plain", ""),
            "/mcp/catalog.json" => ("200 OK", "application/json", r#"{"tools":[]}"#),
            _ => ("404 Not Found", "text/plain", ""),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()
    }

    fn join_server(handle: thread::JoinHandle<Result<(), io::Error>>) -> Result<(), String> {
        match handle.join() {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("fixture server panicked".into()),
        }
    }

    #[derive(Clone)]
    struct MemoryDriver {
        observation: CompiledObservation,
        web_mcp_available: bool,
        web_mcp_has_tools: bool,
        web_mcp_method_only: bool,
        extract_value: Option<Value>,
        screenshot_bytes: Option<Vec<u8>>,
        step_error: Option<String>,
        // Shared across forks (fork() clones this handle) so tests can assert that
        // close() actually ran on a forked driver rather than it merely being dropped.
        closed: Arc<AtomicUsize>,
        /// When set, `observe` blocks this long — used by the issue #230
        /// concurrency tests to prove overlap/serialization.
        observe_delay: Option<Duration>,
        /// When set, `fork` blocks this long — used to race an in-flight fork
        /// against `close_all_forks` (#230 review blocker).
        fork_delay: Option<Duration>,
        /// Start/end instants of every delayed `observe`, shared across forks.
        observe_spans: Arc<Mutex<Vec<(Instant, Instant)>>>,
    }

    impl MemoryDriver {
        fn new() -> Self {
            Self {
                closed: Arc::new(AtomicUsize::new(0)),
                observe_delay: None,
                fork_delay: None,
                observe_spans: Arc::new(Mutex::new(Vec::new())),
                web_mcp_available: false,
                web_mcp_has_tools: false,
                web_mcp_method_only: false,
                extract_value: None,
                screenshot_bytes: None,
                step_error: None,
                observation: CompiledObservation {
                    schema_version: tempo_schema::SCHEMA_VERSION.into(),
                    url: "https://example.test/".into(),
                    seq: 1,
                    elements: vec![InteractiveElement {
                        node_id: NodeId("button.primary".into()),
                        role: "button".into(),
                        name: vec![TaintSpan {
                            provenance: Provenance::Page,
                            text: "Continue".into(),
                        }],
                        value: Vec::new(),
                        bounds: Some([0.0, 0.0, 120.0, 32.0]),
                        rank: 1.0,
                    }],
                    omitted: 0,
                    marks: vec![(NodeId("button.primary".into()), 1)],
                },
            }
        }

        fn with_web_mcp(mut self) -> Self {
            self.web_mcp_available = true;
            self.web_mcp_has_tools = true;
            self
        }

        fn with_url(mut self, url: impl Into<String>) -> Self {
            self.observation.url = url.into();
            self
        }

        fn with_unusable_web_mcp(mut self) -> Self {
            self.web_mcp_available = true;
            self.web_mcp_has_tools = false;
            self
        }

        fn with_method_only_web_mcp(mut self) -> Self {
            self.web_mcp_available = true;
            self.web_mcp_has_tools = false;
            self.web_mcp_method_only = true;
            self
        }

        fn with_extract(mut self, value: Value) -> Self {
            self.extract_value = Some(value);
            self
        }

        fn with_screenshot(mut self, bytes: Vec<u8>) -> Self {
            self.screenshot_bytes = Some(bytes);
            self
        }

        fn with_step_error(mut self, reason: impl Into<String>) -> Self {
            self.step_error = Some(reason.into());
            self
        }

        fn with_observe_delay(mut self, delay: Duration) -> Self {
            self.observe_delay = Some(delay);
            self
        }

        fn with_fork_delay(mut self, delay: Duration) -> Self {
            self.fork_delay = Some(delay);
            self
        }
    }

    #[async_trait]
    impl DriverTrait for MemoryDriver {
        fn engine(&self) -> Engine {
            Engine::Cdp
        }

        async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
            self.observation.url = url.to_string();
            self.observation.seq += 1;
            Ok(self.observation.clone())
        }

        async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
            if let Some(delay) = self.observe_delay {
                let start = Instant::now();
                std::thread::sleep(delay);
                if let Ok(mut spans) = self.observe_spans.lock() {
                    spans.push((start, Instant::now()));
                }
            }
            Ok(self.observation.clone())
        }

        async fn observe_diff(
            &mut self,
            since_seq: u64,
        ) -> Result<ObservationDiff, TransportError> {
            Ok(ObservationDiff {
                since_seq,
                seq: self.observation.seq,
                omitted: 0,
                added: Vec::new(),
                removed: Vec::new(),
                changed: self.observation.elements.clone(),
            })
        }

        async fn act(&mut self, _action: &Action) -> Result<StepOutcome, TransportError> {
            if let Some(reason) = &self.step_error {
                return Ok(StepOutcome::StepError {
                    reason: reason.clone(),
                });
            }
            self.observation.seq += 1;
            Ok(StepOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: self.observation.seq - 1,
                    seq: self.observation.seq,
                    omitted: 0,
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: self.observation.elements.clone(),
                },
            })
        }

        async fn act_batch(
            &mut self,
            _batch: &tempo_schema::ActionBatch,
        ) -> Result<StepOutcome, TransportError> {
            self.act(&Action::Scroll { x: 0.0, y: 0.0 }).await
        }

        async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
            if let Some(delay) = self.fork_delay {
                std::thread::sleep(delay);
            }
            Ok(Box::new(self.clone()))
        }

        async fn extract(&mut self, node: &NodeId) -> Result<Value, TransportError> {
            Ok(self
                .extract_value
                .clone()
                .unwrap_or_else(|| json!({"node": node.0, "text": "Continue"})))
        }

        async fn evaluate_script(
            &mut self,
            expression: &str,
            await_promise: bool,
        ) -> Result<Value, TransportError> {
            if expression == WEB_MCP_DETECTION_SCRIPT {
                return Ok(json!({
                    "available": self.web_mcp_available,
                    "type": if self.web_mcp_available { Some("object") } else { None },
                    "hasTools": self.web_mcp_has_tools,
                    "methods": if self.web_mcp_method_only {
                        vec!["listTools", "callTool"]
                    } else {
                        Vec::<&str>::new()
                    },
                }));
            }
            Ok(json!({
                "expression": expression,
                "awaitPromise": await_promise,
            }))
        }

        async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(self
                .screenshot_bytes
                .clone()
                .unwrap_or_else(|| TEST_SCREENSHOT_PNG.to_vec()))
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.closed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}
