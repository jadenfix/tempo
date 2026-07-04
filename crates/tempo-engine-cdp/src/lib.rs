//! tempo-engine-cdp — compat fallback lane: adapts Chromium CDP to DriverTrait v2.
//!
//! This crate is the real CDP fallback lane. It launches a headless
//! Chromium-family browser through `chromiumoxide` and adapts it to tempo's C3
//! driver contract. NodeIds in this lane are stable observation IDs mapped to
//! live CSS selectors inside the adapter.

use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig, HeadlessMode};
use chromiumoxide::cdp::browser_protocol::accessibility::{
    AxNode, AxValue, GetPartialAxTreeParams,
};
use chromiumoxide::cdp::browser_protocol::browser::BrowserContextId;
use chromiumoxide::cdp::browser_protocol::dom::{
    GetDocumentParams, NodeId as DomNodeId, QuerySelectorParams,
};
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, EnableParams as FetchEnableParams, EventRequestPaused,
    FailRequestParams, RequestPattern, RequestStage,
};
use chromiumoxide::cdp::browser_protocol::network::ErrorReason;
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, CreateIsolatedWorldParams, Viewport,
};
use chromiumoxide::cdp::browser_protocol::target::{
    CreateBrowserContextParams, CreateTargetParams,
};
use chromiumoxide::cdp::js_protocol::runtime::{EvaluateParams, ExecutionContextId};
use chromiumoxide::error::CdpError;
use chromiumoxide::handler::HandlerConfig;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::{future::join_all, StreamExt};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempo_driver::{
    BrowsingContextCreateOptions, DriverTrait, Engine, StepOutcome, TransportError, Unsupported,
    MAX_SCREENSHOT_BYTES, MAX_SCREENSHOT_HEIGHT, MAX_SCREENSHOT_WIDTH,
};
use tempo_net::UrlPolicy;
use tempo_observe::{RawElement, StableIdMapper};
use tempo_schema::{
    Action, ActionBatch, CompiledObservation, InteractiveElement, NodeId, ObservationDiff,
    Provenance, QuiescencePolicy, TaintSpan,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Maximum number of interactive elements that receive expensive per-element
/// accessibility-tree enrichment per snapshot.
///
/// `observation.elements` comes straight from `extract_interactive_elements`
/// and is uncapped, so a hostile page with tens of thousands of interactive
/// elements would otherwise trigger three sequential CDP round-trips each
/// (querySelector -> describeNode -> getPartialAXTree), pinning the driver for
/// minutes and re-firing on every observe/goto (#201). Enrichment is bounded to
/// the highest-ranked elements — the same bound the observe pipeline uses to
/// pick set-of-marks labels (`tempo_observe::DEFAULT_MAX_MARKS`, currently 16) —
/// so every element that actually survives into the marked observation is still
/// enriched, while the long tail stays present but without an AX overlay.
const MAX_AX_ENRICHED_ELEMENTS: usize = 16;
/// How many recent compiled observations to retain for diff bases. Diffs are only
/// ever requested against recent seqs (`previous_seq`, `batch_base_seq`, a
/// client-supplied `since_seq`), and `diff_from_base(None, ...)` already degrades a
/// missing base to a full snapshot, so evicting older entries is safe. Without this
/// bound `history` grew by one full observation clone on every observe and was never
/// pruned — a steady RSS leak on long-lived sessions (and each live fork keeps its
/// own driver + history). Mirrors `StableIdMapper`'s retention window (#107).
const HISTORY_RETENTION_SNAPSHOTS: u64 = 16;
const MAX_BLOCKED_REQUESTS: usize = 64;
const REQUEST_POLICY_EVENT_GRACE: Duration = Duration::from_millis(25);
const BLOCKED_REQUEST_SETTLE_TIMEOUT: Duration = Duration::from_millis(750);
const POLICY_PROXY_MAX_HEADER_BYTES: usize = 64 * 1024;
const CDP_POLICY_PROXY_ARGS: [&str; 6] = [
    "--host-resolver-rules",
    "--no-proxy-server",
    "--proxy-auto-detect",
    "--proxy-bypass-list",
    "--proxy-pac-url",
    "--proxy-server",
];
const CDP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const TIMED_OUT_NAVIGATION_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const TIMED_OUT_NAVIGATION_RECOVERY_INTERVAL: Duration = Duration::from_millis(50);

/// Explicit opt-out for Chromium sandboxing in constrained CI/container setups.
pub const TEMPO_CDP_NO_SANDBOX_ENV: &str = "TEMPO_CDP_NO_SANDBOX";

/// Launch configuration for the CDP fallback lane.
#[derive(Clone, Debug)]
pub struct CdpConfig {
    /// Explicit path to a Chrome/Chromium binary. When unset, chromiumoxide
    /// tries its platform auto-detection.
    pub executable: Option<String>,
    /// Run Chrome with `--no-sandbox`. This is less secure and should only be
    /// used for constrained CI/container fixtures that cannot run Chromium's
    /// sandbox.
    pub no_sandbox: bool,
    /// How long to wait for the browser process to expose DevTools.
    pub launch_timeout: Duration,
    /// Extra Chromium command-line arguments. Intended for narrowly scoped
    /// fixtures and platform integration knobs.
    pub args: Vec<String>,
}

impl CdpConfig {
    pub fn with_executable(mut self, path: impl Into<String>) -> Self {
        self.executable = Some(path.into());
        self
    }

    pub fn with_no_sandbox_for_ci(mut self) -> Self {
        self.no_sandbox = true;
        self
    }

    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Honor the explicit no-sandbox opt-in environment variable.
    ///
    /// This keeps production/default launches sandboxed while allowing live CI
    /// fixtures to run on hosted Linux runners that cannot provide Chromium's
    /// sandbox.
    pub fn with_no_sandbox_env_opt_in(self) -> Self {
        if env_flag_enabled(TEMPO_CDP_NO_SANDBOX_ENV) {
            self.with_no_sandbox_for_ci()
        } else {
            self
        }
    }

    fn browser_config(&self, user_data_dir: &Path) -> Result<BrowserConfig, TransportError> {
        let mut builder = BrowserConfig::builder()
            .headless_mode(HeadlessMode::New)
            .launch_timeout(self.launch_timeout)
            .request_timeout(CDP_REQUEST_TIMEOUT)
            .user_data_dir(user_data_dir)
            .incognito()
            .enable_request_intercept()
            .disable_cache();
        if self.no_sandbox {
            builder = builder.no_sandbox();
        }
        if let Some(path) = &self.executable {
            builder = builder.chrome_executable(path);
        }
        if !self.args.is_empty() {
            builder = builder.args(self.args.clone());
        }
        builder.build().map_err(TransportError::Other)
    }

    fn validate_policy_proxy_args(&self) -> Result<(), TransportError> {
        if let Some(arg) = self
            .args
            .iter()
            .find(|arg| is_policy_proxy_arg(arg.as_str()))
        {
            return Err(TransportError::Other(format!(
                "CDP launch arg {arg:?} conflicts with the mandatory policy proxy"
            )));
        }
        Ok(())
    }
}

impl Default for CdpConfig {
    fn default() -> Self {
        Self {
            executable: None,
            no_sandbox: false,
            launch_timeout: Duration::from_secs(20),
            args: Vec::new(),
        }
    }
}

/// CDP-backed tempo driver. Construct it with [`CdpTempoDriver::launch`].
pub struct CdpTempoDriver {
    browser: Browser,
    page: Option<Page>,
    handler_task: JoinHandle<()>,
    request_policy_task: Option<JoinHandle<()>>,
    policy_proxy: Option<PolicyProxy>,
    browser_context_id: Option<BrowserContextId>,
    profile_dir: Option<tempfile::TempDir>,
    owns_browser: bool,
    seq: u64,
    history: BTreeMap<u64, CompiledObservation>,
    stable_id_mapper: StableIdMapper,
    selectors_by_node: BTreeMap<NodeId, String>,
    url_policy: Arc<Mutex<UrlPolicy>>,
    blocked_request_url: Arc<Mutex<Option<String>>>,
    request_policy_tracker: Arc<RequestPolicyTracker>,
    /// Cached isolated-world execution context for the stability probe.
    /// Invalidated by navigation; recreated on demand.
    probe_context: Mutex<Option<ExecutionContextId>>,
}

impl CdpTempoDriver {
    /// Launch a real headless Chromium-family browser.
    pub async fn launch() -> Result<Self, TransportError> {
        Self::launch_with(CdpConfig::default()).await
    }

    /// Launch a real browser with an explicit CDP configuration.
    pub async fn launch_with(config: CdpConfig) -> Result<Self, TransportError> {
        config.validate_policy_proxy_args()?;
        let profile_dir = tempfile::Builder::new()
            .prefix("tempo-cdp-profile-")
            .tempdir()
            .map_err(|error| {
                TransportError::Other(format!("failed to create private CDP profile: {error}"))
            })?;
        let url_policy = Arc::new(Mutex::new(UrlPolicy::block_private()));
        let blocked_request_url = Arc::new(Mutex::new(None));
        let request_policy_tracker = Arc::new(RequestPolicyTracker::new());
        let policy_proxy = PolicyProxy::start(
            url_policy.clone(),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await?;
        let mut config = config;
        config.args.extend([
            format!("--proxy-server=http://{}", policy_proxy.addr),
            "--proxy-bypass-list=<-loopback>".to_string(),
            "--disable-quic".to_string(),
            "--dns-prefetch-disable".to_string(),
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1".to_string(),
        ]);
        let browser_config = config.browser_config(profile_dir.path())?;
        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(map_cdp_error)?;
        let handler_task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let page = match browser.new_page("about:blank").await {
            Ok(page) => page,
            Err(error) => {
                let _ = browser.close().await;
                let _ = browser.wait().await;
                handler_task.abort();
                return Err(map_cdp_error(error));
            }
        };
        let request_policy_task = match install_request_policy(
            &page,
            url_policy.clone(),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await
        {
            Ok(task) => task,
            Err(error) => {
                let _ = browser.close().await;
                let _ = browser.wait().await;
                handler_task.abort();
                return Err(error);
            }
        };

        Ok(Self {
            browser,
            page: Some(page),
            handler_task,
            request_policy_task: Some(request_policy_task),
            policy_proxy: Some(policy_proxy),
            browser_context_id: None,
            profile_dir: Some(profile_dir),
            owns_browser: true,
            seq: 0,
            history: BTreeMap::new(),
            stable_id_mapper: StableIdMapper::new(),
            selectors_by_node: BTreeMap::new(),
            url_policy,
            blocked_request_url,
            request_policy_tracker,
            probe_context: Mutex::new(None),
        })
    }

    /// Allow loopback/private navigation for trusted live fixtures.
    pub fn allow_private_network_access(mut self) -> Self {
        self.set_url_policy(UrlPolicy::allow_all());
        self
    }

    /// Override the shared pre-navigation URL policy used by the CDP lane.
    pub fn with_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.set_url_policy(url_policy);
        self
    }

    fn set_url_policy(&mut self, url_policy: UrlPolicy) {
        if let Ok(mut active_policy) = self.url_policy.lock() {
            *active_policy = url_policy;
        }
    }

    fn current_url_policy(&self) -> Result<UrlPolicy, TransportError> {
        self.url_policy
            .lock()
            .map(|policy| policy.clone())
            .map_err(|_error| TransportError::Other("CDP URL policy lock poisoned".into()))
    }

    fn enforce_url_policy(&self, url: &str) -> Result<(), TransportError> {
        enforce_url_policy(url, &self.current_url_policy()?)
    }

    fn clear_blocked_request(&self) -> Result<(), TransportError> {
        *self.blocked_request_url.lock().map_err(|_error| {
            TransportError::Other("CDP blocked request lock poisoned".into())
        })? = None;
        Ok(())
    }

    fn take_blocked_request(&self) -> Result<Option<String>, TransportError> {
        Ok(self
            .blocked_request_url
            .lock()
            .map_err(|_error| TransportError::Other("CDP blocked request lock poisoned".into()))?
            .take())
    }

    fn request_policy_cursor(&self) -> u64 {
        self.request_policy_tracker.cursor()
    }

    fn enforce_current_url_policy_value(&self, url: &str) -> Result<(), TransportError> {
        if url.is_empty() || url == "about:blank" {
            return Ok(());
        }
        self.enforce_url_policy(url)
    }

    fn enforce_no_blocked_request_since(&self, cursor: u64) -> Result<(), TransportError> {
        if self.request_policy_tracker.has_blocked_since(cursor) {
            Err(TransportError::UrlBlocked)
        } else {
            Ok(())
        }
    }

    async fn enforce_no_blocked_request_soon_since(
        &self,
        cursor: u64,
    ) -> Result<(), TransportError> {
        wait_for_no_blocked_request_since(&self.request_policy_tracker, cursor).await
    }

    async fn map_cdp_result_since<T>(
        &self,
        cursor: u64,
        result: Result<T, CdpError>,
    ) -> Result<T, TransportError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                Err(map_cdp_error(error))
            }
        }
    }

    async fn recover_timed_out_navigation_since(
        &self,
        cursor: u64,
        requested_url: &str,
    ) -> Result<(), TransportError> {
        let deadline = Instant::now() + TIMED_OUT_NAVIGATION_RECOVERY_TIMEOUT;
        loop {
            self.enforce_no_blocked_request_soon_since(cursor).await?;
            let current_url = self.current_url().await?;
            self.enforce_current_url_policy_value(&current_url)?;
            self.enforce_no_blocked_request_since(cursor)?;
            if let Some(ready_state) = self.document_ready_state_since(cursor).await?
                && timed_out_navigation_recovered(requested_url, &current_url, &ready_state)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TransportError::NavTimeout);
            }
            tokio::time::sleep(TIMED_OUT_NAVIGATION_RECOVERY_INTERVAL).await;
        }
    }

    fn page(&self) -> Result<&Page, TransportError> {
        self.page
            .as_ref()
            .ok_or_else(|| TransportError::Other("CDP page is closed".into()))
    }

    async fn current_url(&self) -> Result<String, TransportError> {
        Ok(self
            .page()?
            .url()
            .await
            .map_err(map_cdp_error)?
            .unwrap_or_default())
    }

    async fn document_ready_state_since(
        &self,
        cursor: u64,
    ) -> Result<Option<String>, TransportError> {
        match self.page()?.evaluate("document.readyState").await {
            Ok(remote_object) => {
                self.enforce_no_blocked_request_since(cursor)?;
                Ok(remote_object.into_value::<String>().ok())
            }
            Err(_error) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                Ok(None)
            }
        }
    }

    async fn enforce_current_url_policy(&self) -> Result<String, TransportError> {
        let url = self.current_url().await?;
        self.enforce_current_url_policy_value(&url)?;
        Ok(url)
    }

    async fn snapshot_since(&self, cursor: u64) -> Result<(String, String), TransportError> {
        let url = self.current_url().await?;
        self.enforce_current_url_policy_value(&url)?;
        self.enforce_no_blocked_request_since(cursor)?;
        let dom_html = match self.page()?.content().await {
            Ok(dom_html) => dom_html,
            Err(error) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                return Err(map_cdp_error(error));
            }
        };
        self.enforce_no_blocked_request_since(cursor)?;
        Ok((url, dom_html))
    }

    async fn record_snapshot(
        &mut self,
        url: String,
        dom_html: String,
    ) -> Result<CompiledObservation, TransportError> {
        self.seq += 1;
        let (mut compiled, selectors_by_node) =
            compile_observation(&mut self.stable_id_mapper, url, dom_html, self.seq);
        self.selectors_by_node = selectors_by_node;
        self.enrich_observation_from_ax_tree(&mut compiled).await?;
        self.history.insert(compiled.seq, compiled.clone());
        prune_observation_history(&mut self.history, compiled.seq);
        Ok(compiled)
    }

    async fn record_snapshot_since(
        &mut self,
        cursor: u64,
        url: String,
        dom_html: String,
    ) -> Result<CompiledObservation, TransportError> {
        let compiled = self.record_snapshot(url, dom_html).await?;
        // Every `_since` caller has already served the full 25ms event grace
        // for this same cursor immediately after its action command returned
        // (click/type/select/scroll/wait/goto/fixed-millis), so this side only
        // drains still-pending requests to surface a blocked verdict — it does
        // not re-pay the grace floor.
        wait_for_no_blocked_request_settled(&self.request_policy_tracker, cursor).await?;
        Ok(compiled)
    }

    async fn record_current_observation(&mut self) -> Result<CompiledObservation, TransportError> {
        let cursor = self.request_policy_cursor();
        // Bare observes (no preceding action wait) keep the full event grace as
        // the policy watchdog before the snapshot is trusted.
        self.enforce_no_blocked_request_soon_since(cursor).await?;
        self.record_current_observation_since(cursor).await
    }

    async fn record_current_observation_since(
        &mut self,
        cursor: u64,
    ) -> Result<CompiledObservation, TransportError> {
        let (url, dom_html) = self.snapshot_since(cursor).await?;
        self.record_snapshot_since(cursor, url, dom_html).await
    }

    async fn enrich_observation_from_ax_tree(
        &self,
        observation: &mut CompiledObservation,
    ) -> Result<(), TransportError> {
        if observation.elements.is_empty() {
            return Ok(());
        }

        self.enforce_current_url_policy().await?;
        let page = self.page()?;
        let root = page
            .execute(GetDocumentParams::default())
            .await
            .map_err(map_cdp_error)?
            .result
            .root
            .node_id;

        // Bound the expensive AX round-trips to the highest-ranked elements so a
        // hostile page cannot pin the driver with an unbounded element list
        // (#201). The rest of `observation.elements` is left untouched.
        enrich_elements(
            &mut observation.elements,
            MAX_AX_ENRICHED_ELEMENTS,
            |node_id| async move {
                let Some(selector) = self.selectors_by_node.get(&node_id).cloned() else {
                    return Ok(None);
                };
                self.ax_summary_for_selector(root, &selector).await
            },
        )
        .await
    }

    /// URL policy is enforced once by `enrich_observation_from_ax_tree` before
    /// the per-element fan-out — not re-checked per element. A mid-enrichment
    /// navigation invalidates the DOM node ids (querySelector/getPartialAXTree
    /// fail soft to `None`), policy-blocked loads are still caught at the
    /// network layer by the request tracker, and every observe path ends in a
    /// blocked-request check before the observation is returned. Re-issuing
    /// `page.url()` here cost one extra CDP round-trip per enriched element
    /// (up to 16 per observation).
    async fn ax_summary_for_selector(
        &self,
        root: DomNodeId,
        selector: &str,
    ) -> Result<Option<AxSummary>, TransportError> {
        let page = self.page()?;
        let queried = match page.execute(QuerySelectorParams::new(root, selector)).await {
            Ok(response) => response.result,
            Err(error)
                if matches!(error, CdpError::NotFound)
                    || is_node_not_found_msg(&error.to_string()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(map_cdp_error(error)),
        };
        if *queried.node_id.inner() == 0 {
            return Ok(None);
        }

        // `Accessibility.getPartialAXTree` accepts a DOM node id directly, so the
        // querySelector result feeds straight into it. The previous pipeline also
        // issued a `DOM.describeNode` between the two purely to translate the DOM
        // node id into a backend node id; that hop is redundant and is dropped
        // here, cutting one dependent CDP round-trip per enriched element on the
        // observation hot path (#299). `fetch_relatives(false)` scopes the reply
        // to the queried node alone — no ancestors, siblings, or children — so
        // the response describes exactly that element's own AX node.
        let ax_nodes = match page
            .execute(
                GetPartialAxTreeParams::builder()
                    .node_id(queried.node_id)
                    .fetch_relatives(false)
                    .build(),
            )
            .await
        {
            Ok(response) => response.result.nodes,
            Err(error)
                if matches!(error, CdpError::NotFound)
                    || is_uninteresting_ax_node_msg(&error.to_string())
                    || is_node_not_found_msg(&error.to_string()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(map_cdp_error(error)),
        };

        Ok(sole_ax_summary(&ax_nodes))
    }

    async fn with_element<F, Fut>(&self, selector: &str, op: F) -> Result<bool, TransportError>
    where
        F: FnOnce(chromiumoxide::Element) -> Fut,
        Fut: std::future::Future<Output = Result<(), TransportError>>,
    {
        self.enforce_current_url_policy().await?;
        match self.page()?.find_element(selector).await {
            Ok(element) => match op(element).await {
                Ok(()) => Ok(true),
                Err(TransportError::Other(message)) if is_selector_grounding_miss_msg(&message) => {
                    Ok(false)
                }
                Err(other) => Err(other),
            },
            Err(CdpError::NotFound) => Ok(false),
            Err(error) if is_selector_grounding_miss_msg(&error.to_string()) => Ok(false),
            Err(error) => Err(map_cdp_error(error)),
        }
    }

    fn selector_for_node(&self, node: &NodeId) -> Option<String> {
        selector_or_legacy_fallback(&self.selectors_by_node, node)
    }

    async fn refresh_selector_for_node(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<String>, TransportError> {
        let _ = self.record_current_observation().await?;
        Ok(self.selectors_by_node.get(node).cloned())
    }

    async fn with_node_element<F, Fut>(
        &mut self,
        node: &NodeId,
        mut op: F,
    ) -> Result<NodeGrounding, TransportError>
    where
        F: FnMut(chromiumoxide::Element) -> Fut,
        Fut: std::future::Future<Output = Result<(), TransportError>>,
    {
        if let Some(selector) = self.selector_for_node(node) {
            if self.with_element(&selector, &mut op).await? {
                return Ok(NodeGrounding {
                    target: selector,
                    grounded: true,
                });
            }

            if let Some(refreshed) = self.refresh_selector_for_node(node).await?
                && refreshed != selector
            {
                let grounded = self.with_element(&refreshed, &mut op).await?;
                return Ok(NodeGrounding {
                    target: refreshed,
                    grounded,
                });
            }

            return Ok(NodeGrounding {
                target: selector,
                grounded: false,
            });
        }

        let refreshed = self.refresh_selector_for_node(node).await?;
        let Some(selector) = refreshed else {
            return Ok(NodeGrounding {
                target: node.0.clone(),
                grounded: false,
            });
        };
        let grounded = self.with_element(&selector, op).await?;
        Ok(NodeGrounding {
            target: selector,
            grounded,
        })
    }

    async fn extract_with_selector(
        &self,
        selector: &str,
    ) -> Result<serde_json::Value, TransportError> {
        self.enforce_current_url_policy().await?;
        self.page()?
            .evaluate(extraction_script(selector)?)
            .await
            .map_err(map_cdp_error)?
            .into_value::<serde_json::Value>()
            .map_err(|error| TransportError::Other(error.to_string()))
    }

    async fn node_outcome_since(
        &mut self,
        previous_seq: u64,
        target: &str,
        grounded: bool,
        cursor: u64,
    ) -> Result<StepOutcome, TransportError> {
        let compiled = self.record_current_observation_since(cursor).await?;
        if grounded {
            Ok(StepOutcome::Applied {
                diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
            })
        } else {
            Ok(StepOutcome::StepError {
                reason: format!("node not found: {target}"),
            })
        }
    }

    async fn run_one(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        let previous_seq = self.seq;
        match action {
            Action::Goto { url } => {
                let compiled = self.goto(url).await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
                })
            }
            Action::Click { node } => {
                let cursor = self.request_policy_cursor();
                let grounding = self
                    .with_node_element(node, |element| async move {
                        element.click().await.map_err(map_cdp_error)?;
                        Ok(())
                    })
                    .await?;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                self.node_outcome_since(previous_seq, &grounding.target, grounding.grounded, cursor)
                    .await
            }
            Action::Type { node, text } => {
                let cursor = self.request_policy_cursor();
                let text = text.clone();
                let grounding = self
                    .with_node_element(node, |element| {
                        let text = text.clone();
                        async move {
                            element.focus().await.map_err(map_cdp_error)?;
                            element.type_str(&text).await.map_err(map_cdp_error)?;
                            Ok(())
                        }
                    })
                    .await?;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                self.node_outcome_since(previous_seq, &grounding.target, grounding.grounded, cursor)
                    .await
            }
            Action::Select { node, value } => {
                let cursor = self.request_policy_cursor();
                let encoded = serde_json::to_string(value)
                    .map_err(|error| TransportError::Other(error.to_string()))?;
                let grounding = self
                    .with_node_element(node, |element| {
                        let encoded = encoded.clone();
                        async move {
                            let function = format!(
                                "function() {{ this.value = {encoded}; \
                             this.dispatchEvent(new Event('change', {{ bubbles: true }})); }}"
                            );
                            element
                                .call_js_fn(function, false)
                                .await
                                .map_err(map_cdp_error)?;
                            Ok(())
                        }
                    })
                    .await?;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                self.node_outcome_since(previous_seq, &grounding.target, grounding.grounded, cursor)
                    .await
            }
            Action::Scroll { x, y } => {
                self.enforce_current_url_policy().await?;
                let cursor = self.request_policy_cursor();
                self.page()?
                    .evaluate(format!("window.scrollTo({}, {});", *x as i64, *y as i64))
                    .await
                    .map_err(map_cdp_error)?;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                let compiled = self.record_current_observation_since(cursor).await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
                })
            }
            Action::Wait { millis } => {
                let cursor = self.request_policy_cursor();
                tokio::time::sleep(Duration::from_millis(*millis)).await;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                let compiled = self.record_current_observation_since(cursor).await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
                })
            }
            Action::Extract { node } => {
                let cursor = self.request_policy_cursor();
                let grounding = self
                    .with_node_element(node, |_element| async move { Ok(()) })
                    .await?;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                self.node_outcome_since(previous_seq, &grounding.target, grounding.grounded, cursor)
                    .await
            }
            Action::Skill { name, .. } => Ok(StepOutcome::StepError {
                reason: format!("skill action {name:?} is handled by tempo-skills, not CDP"),
            }),
        }
    }

    async fn wait_for_composite_quiescence(&self) -> Result<(), TransportError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut tracker = CompositeQuiescenceTracker::new(3);

        // Ramp the sampling interval instead of a fixed 50ms: a page that is
        // already quiet settles after ~75ms of evidence instead of ~100ms,
        // while a busy page converges to the same 50ms cadence. The ramp is
        // deliberately conservative — the quiet-evidence window stays within
        // 25% of the legacy 100ms so late-starting JS (hydration, analytics)
        // has nearly the same chance to be observed before settle.
        let mut poll_index = 0_usize;
        loop {
            // URL policy is enforced inside each stability sample (from the
            // probe-reported href on the isolated path, or an explicit
            // page.url() on the fallback path) — no separate per-poll
            // round-trip here.
            let cursor = self.request_policy_cursor();
            let sample = self.sample_page_stability_since(cursor).await?;
            if tracker.observe(sample) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TransportError::NavTimeout);
            }
            let interval = QUIESCENCE_POLL_INTERVALS_MS
                .get(poll_index)
                .copied()
                .unwrap_or(QUIESCENCE_POLL_INTERVAL_CAP_MS);
            poll_index += 1;
            tokio::time::sleep(Duration::from_millis(interval)).await;
        }
    }

    /// One O(1) stability sample: a single `Runtime.evaluate` in a CDP
    /// isolated world that installs or reuses a page-wide MutationObserver and
    /// returns `readyState|mutationGen`.
    ///
    /// The previous sampler pulled the full serialized DOM over CDP and hashed
    /// it on every poll — O(page size) CPU and transfer per tick, which
    /// dominated settle latency on large pages. The observer generation is
    /// also more sensitive: two polls that straddle a mutate-and-revert see a
    /// generation bump where equal DOM hashes would alias.
    ///
    /// The probe runs in an isolated world so page JS cannot read or freeze
    /// the counter (main-world globals like `__tempoMutGen` would be page-
    /// writable, letting a hostile page fake stability while still mutating).
    /// Isolated-world reads of `document.readyState` also bypass main-world
    /// getter monkey-patching. If the isolated world or observer cannot be
    /// set up, the sampler falls back to the CDP-trusted DOM-hash path.
    async fn sample_page_stability_since(
        &self,
        cursor: u64,
    ) -> Result<PageStabilitySample, TransportError> {
        if let Some(probe) = self.probe_stability_isolated(cursor).await? {
            // The probe reports the frame's location.href from the isolated
            // world, so URL policy is enforced on every sample without the
            // extra per-poll `page.url()` round-trip; older probe payloads
            // without a URL keep the round-trip.
            match &probe.url {
                Some(url) => self.enforce_current_url_policy_value(url)?,
                None => {
                    self.enforce_current_url_policy().await?;
                }
            }
            self.enforce_no_blocked_request_since(cursor)?;
            return Ok(probe.sample);
        }
        self.enforce_no_blocked_request_since(cursor)?;

        // Fallback: readyState + full-DOM hash via CDP (the legacy sampler).
        let ready_result = self.page()?.evaluate("document.readyState").await;
        let ready_state = self
            .map_cdp_result_since(cursor, ready_result)
            .await?
            .into_value::<String>()
            .map_err(|error| TransportError::Other(error.to_string()))?;
        self.enforce_current_url_policy().await?;
        let content_result = self.page()?.content().await;
        let dom_html = self.map_cdp_result_since(cursor, content_result).await?;
        self.enforce_no_blocked_request_since(cursor)?;
        Ok(PageStabilitySample {
            ready: ready_state != "loading",
            dom_hash: fnv1a64(dom_html.as_bytes()),
        })
    }

    /// Evaluate the stability probe in the cached isolated world, recreating
    /// the world once if navigation invalidated the execution context.
    /// Returns `Ok(None)` when the isolated-world path is unavailable and the
    /// caller should use the fallback sampler.
    async fn probe_stability_isolated(
        &self,
        cursor: u64,
    ) -> Result<Option<ParsedStabilityProbe>, TransportError> {
        for recreate in [false, true] {
            let Some(context_id) = self.probe_context_id(recreate, cursor).await? else {
                return Ok(None);
            };
            let params = match EvaluateParams::builder()
                .expression(STABILITY_PROBE_SCRIPT)
                .context_id(context_id)
                .return_by_value(true)
                .build()
            {
                Ok(params) => params,
                Err(_) => return Ok(None),
            };
            let evaluated = match self.page()?.execute(params).await {
                Ok(response) => response.result,
                // Stale context after navigation: recreate the world once.
                Err(_) if !recreate => {
                    self.enforce_no_blocked_request_soon_since(cursor).await?;
                    continue;
                }
                Err(_) => {
                    self.enforce_no_blocked_request_soon_since(cursor).await?;
                    return Ok(None);
                }
            };
            if evaluated.exception_details.is_some() {
                return Ok(None);
            }
            let Some(probe) = evaluated
                .result
                .value
                .as_ref()
                .and_then(serde_json::Value::as_str)
            else {
                // No value usually means the context died mid-eval; retry once.
                if !recreate {
                    continue;
                }
                return Ok(None);
            };
            return Ok(parse_stability_probe(probe));
        }
        Ok(None)
    }

    /// Cached isolated-world context for the probe; created lazily and
    /// recreated on demand after navigation destroys it.
    async fn probe_context_id(
        &self,
        recreate: bool,
        cursor: u64,
    ) -> Result<Option<ExecutionContextId>, TransportError> {
        if !recreate
            && let Ok(guard) = self.probe_context.lock()
            && let Some(id) = *guard
        {
            return Ok(Some(id));
        }

        let page = self.page()?;
        let frame_id = match page.mainframe().await {
            Ok(Some(frame_id)) => frame_id,
            Ok(None) => return Ok(None),
            Err(_) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                return Ok(None);
            }
        };
        let created = match page
            .execute(CreateIsolatedWorldParams {
                frame_id,
                world_name: Some("__tempo_stability_probe".into()),
                grant_univeral_access: None,
            })
            .await
        {
            Ok(response) => response.result,
            Err(_) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                return Ok(None);
            }
        };
        let id = created.execution_context_id;
        if let Ok(mut guard) = self.probe_context.lock() {
            *guard = Some(id);
        }
        Ok(Some(id))
    }
}

/// Stability probe parse result: the sample plus the frame URL reported from
/// the isolated world (absent on older two-field probe payloads).
#[derive(Debug, PartialEq)]
struct ParsedStabilityProbe {
    sample: PageStabilitySample,
    url: Option<String>,
}

/// Parse a `readyState|generation|href` probe string into a stability sample.
/// `generation < 0` (observer unavailable) and malformed strings yield `None`,
/// which routes the caller to the DOM-hash fallback. The URL is the remainder
/// after the second separator, so an href containing `|` stays intact.
fn parse_stability_probe(probe: &str) -> Option<ParsedStabilityProbe> {
    let mut parts = probe.splitn(3, '|');
    let ready_state = parts.next()?;
    let generation = parts.next()?.parse::<i64>().ok()?;
    if generation < 0 {
        return None;
    }
    let url = parts.next().map(str::to_owned);
    Some(ParsedStabilityProbe {
        sample: PageStabilitySample {
            ready: ready_state != "loading",
            dom_hash: generation as u64,
        },
        url,
    })
}

/// Poll ramp for composite quiescence sampling, capped at the legacy 50ms.
/// Quiet pages produce three stable samples spanning ~75ms (vs 100ms before)
/// with O(1) sampling cost.
const QUIESCENCE_POLL_INTERVALS_MS: [u64; 2] = [25, 50];
const QUIESCENCE_POLL_INTERVAL_CAP_MS: u64 = 50;

/// In-page probe: installs a document-wide MutationObserver, rebinds it if the
/// document root is replaced, and reports `readyState|generation`
/// (`generation = -1` when the observer cannot run, signalling the caller to
/// use the DOM-hash fallback).
const STABILITY_PROBE_SCRIPT: &str = r#"(() => {
  const w = window;
  const target = document.documentElement || document;
  if (w.__tempoMutObs === undefined || w.__tempoMutTarget !== target) {
    if (w.__tempoMutObs && typeof w.__tempoMutObs.disconnect === 'function') {
      try { w.__tempoMutObs.disconnect(); } catch (e) {}
    }
    w.__tempoMutTarget = target;
    w.__tempoMutGen = typeof w.__tempoMutGen === 'number' ? w.__tempoMutGen + 1 : 0;
    try {
      const obs = new MutationObserver(() => { w.__tempoMutGen += 1; });
      obs.observe(target, { subtree: true, childList: true, attributes: true, characterData: true });
      w.__tempoMutObs = obs;
    } catch (e) {
      w.__tempoMutObs = null;
    }
  }
  const gen = w.__tempoMutObs ? w.__tempoMutGen : -1;
  return `${document.readyState}|${gen}|${location.href}`;
})()"#;

fn is_policy_proxy_arg(arg: &str) -> bool {
    let name = arg
        .split_once('=')
        .map(|(name, _value)| name)
        .unwrap_or(arg);
    CDP_POLICY_PROXY_ARGS.contains(&name)
}

impl Drop for CdpTempoDriver {
    fn drop(&mut self) {
        self.handler_task.abort();
        if let Some(task) = self.request_policy_task.take() {
            task.abort();
        }
        self.policy_proxy.take();
    }
}

#[async_trait]
impl DriverTrait for CdpTempoDriver {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        self.enforce_url_policy(url)?;
        self.clear_blocked_request()?;
        let cursor = self.request_policy_cursor();
        match self.page()?.goto(url).await {
            Ok(_page) => {}
            Err(CdpError::Timeout) => {
                self.recover_timed_out_navigation_since(cursor, url).await?;
            }
            Err(error) => {
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                return Err(map_cdp_error(error));
            }
        }
        self.enforce_no_blocked_request_soon_since(cursor).await?;
        if self.take_blocked_request()?.is_some() {
            return Err(TransportError::UrlBlocked);
        }
        // Pre-warm the stability-probe isolated world for the destination
        // document. Without this, the first composite-quiescence sample after
        // navigation pays the stale-context miss (failed evaluate + mainframe
        // + createIsolatedWorld) inside the settle loop itself. Best-effort:
        // the sampler still recreates on demand if this fails.
        let _ = self.probe_context_id(true, cursor).await;
        let (final_url, dom_html) = self.snapshot_since(cursor).await?;
        self.record_snapshot_since(cursor, final_url, dom_html)
            .await
    }

    async fn observe(&mut self) -> Result<CompiledObservation, TransportError> {
        self.record_current_observation().await
    }

    async fn observe_diff(&mut self, since_seq: u64) -> Result<ObservationDiff, TransportError> {
        let observation = self.observe().await?;
        Ok(diff_from_base(
            self.history.get(&since_seq),
            &observation,
            since_seq,
        ))
    }

    async fn act(&mut self, action: &Action) -> Result<StepOutcome, TransportError> {
        self.run_one(action).await
    }

    async fn act_batch(&mut self, batch: &ActionBatch) -> Result<StepOutcome, TransportError> {
        let batch_base_seq = self.seq;
        for action in &batch.actions {
            let outcome = self.run_one(action).await?;
            if matches!(outcome, StepOutcome::StepError { .. }) {
                return Ok(outcome);
            }
        }

        match batch.quiescence {
            QuiescencePolicy::FixedMillis(millis) => {
                let cursor = self.request_policy_cursor();
                tokio::time::sleep(Duration::from_millis(millis)).await;
                self.enforce_no_blocked_request_soon_since(cursor).await?;
                let compiled = self.record_current_observation_since(cursor).await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(
                        self.history.get(&batch_base_seq),
                        &compiled,
                        batch_base_seq,
                    ),
                })
            }
            QuiescencePolicy::Composite => {
                self.wait_for_composite_quiescence().await?;
                let compiled = self.record_current_observation().await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(
                        self.history.get(&batch_base_seq),
                        &compiled,
                        batch_base_seq,
                    ),
                })
            }
        }
    }

    async fn fork(&mut self) -> Result<Box<dyn DriverTrait>, Unsupported> {
        Err(Unsupported("native CDP page-state fork"))
    }

    async fn create_browsing_context(
        &mut self,
        _options: BrowsingContextCreateOptions,
    ) -> Result<Box<dyn DriverTrait>, Unsupported> {
        let browser_context_id = self
            .browser
            .create_browser_context(
                CreateBrowserContextParams::builder()
                    .dispose_on_detach(true)
                    .build(),
            )
            .await
            .map_err(|_error| Unsupported("fresh CDP browsing context"))?;
        let browser_ws = self.browser.websocket_address().clone();
        let handler_config = HandlerConfig {
            context_ids: vec![browser_context_id.clone()],
            request_timeout: CDP_REQUEST_TIMEOUT,
            ..HandlerConfig::default()
        };
        let (browser, mut handler) =
            match Browser::connect_with_config(browser_ws, handler_config).await {
                Ok(pair) => pair,
                Err(_error) => {
                    let _ = self
                        .browser
                        .dispose_browser_context(browser_context_id.clone())
                        .await;
                    return Err(Unsupported("fresh CDP browsing context"));
                }
            };
        let handler_task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let page_params = match CreateTargetParams::builder()
            .url("about:blank")
            .browser_context_id(browser_context_id.clone())
            .build()
        {
            Ok(params) => params,
            Err(_error) => {
                let _ = browser
                    .dispose_browser_context(browser_context_id.clone())
                    .await;
                handler_task.abort();
                return Err(Unsupported("fresh CDP browsing context"));
            }
        };
        let page = match browser.new_page(page_params).await {
            Ok(page) => page,
            Err(_error) => {
                let _ = browser
                    .dispose_browser_context(browser_context_id.clone())
                    .await;
                handler_task.abort();
                return Err(Unsupported("fresh CDP browsing context"));
            }
        };
        let blocked_request_url = Arc::new(Mutex::new(None));
        let request_policy_tracker = Arc::new(RequestPolicyTracker::new());
        let request_policy_task = match install_request_policy(
            &page,
            self.url_policy.clone(),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await
        {
            Ok(task) => task,
            Err(_error) => {
                let _ = page.close().await;
                let _ = browser
                    .dispose_browser_context(browser_context_id.clone())
                    .await;
                handler_task.abort();
                return Err(Unsupported("fresh CDP browsing context"));
            }
        };

        Ok(Box::new(Self {
            browser,
            page: Some(page),
            handler_task,
            request_policy_task: Some(request_policy_task),
            policy_proxy: None,
            browser_context_id: Some(browser_context_id),
            profile_dir: None,
            owns_browser: false,
            seq: 0,
            history: BTreeMap::new(),
            stable_id_mapper: StableIdMapper::new(),
            selectors_by_node: BTreeMap::new(),
            url_policy: self.url_policy.clone(),
            blocked_request_url,
            request_policy_tracker,
            probe_context: Mutex::new(None),
        }))
    }

    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
        let Some(selector) = self.selector_for_node(node) else {
            let Some(refreshed) = self.refresh_selector_for_node(node).await? else {
                return Ok(node_not_found_extraction(node));
            };
            return self.extract_with_selector(&refreshed).await;
        };

        let extracted = self.extract_with_selector(&selector).await?;
        if extraction_found(&extracted) {
            return Ok(extracted);
        }

        if let Some(refreshed) = self.refresh_selector_for_node(node).await?
            && refreshed != selector
        {
            return self.extract_with_selector(&refreshed).await;
        }

        Ok(extracted)
    }

    async fn evaluate_script(
        &mut self,
        expression: &str,
        await_promise: bool,
    ) -> Result<serde_json::Value, TransportError> {
        let params = EvaluateParams::builder()
            .expression(expression)
            .return_by_value(true)
            .await_promise(await_promise)
            .build()
            .map_err(TransportError::Other)?;
        self.enforce_current_url_policy().await?;
        let cursor = self.request_policy_cursor();
        let evaluate_result = self.page()?.evaluate(params).await;
        let remote_object = self.map_cdp_result_since(cursor, evaluate_result).await?;
        self.enforce_no_blocked_request_soon_since(cursor).await?;
        remote_object
            .into_value::<serde_json::Value>()
            .map_err(|error| TransportError::Other(error.to_string()))
    }

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
        let params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .clip(screenshot_viewport_clip()?)
            .capture_beyond_viewport(false)
            .build();
        self.enforce_current_url_policy().await?;
        let bytes = self
            .page()?
            .screenshot(params)
            .await
            .map_err(map_cdp_error)?;
        validate_screenshot_bytes(bytes)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(task) = self.request_policy_task.take() {
            task.abort();
        }
        if self.owns_browser {
            self.browser.close().await.map_err(map_cdp_error)?;
            let _ = self.browser.wait().await;
            self.policy_proxy.take();
        } else {
            let page_result = if let Some(page) = self.page.take() {
                page.close().await.map_err(map_cdp_error)
            } else {
                Ok(())
            };
            let context_result = if let Some(browser_context_id) = self.browser_context_id.take() {
                self.browser
                    .dispose_browser_context(browser_context_id)
                    .await
                    .map_err(map_cdp_error)
            } else {
                Ok(())
            };
            page_result?;
            context_result?;
        }
        self.handler_task.abort();
        self.profile_dir.take();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockedRequest {
    seq: u64,
    url: String,
}

#[derive(Debug, Default)]
struct RequestPolicyState {
    next_seq: u64,
    pending: BTreeSet<u64>,
    blocked: VecDeque<BlockedRequest>,
}

struct RequestPolicyTracker {
    inner: Mutex<RequestPolicyState>,
    notify: Notify,
}

impl RequestPolicyTracker {
    fn new() -> Self {
        Self {
            inner: Mutex::new(RequestPolicyState::default()),
            notify: Notify::new(),
        }
    }

    fn cursor(&self) -> u64 {
        self.lock().next_seq
    }

    fn start_request(&self) -> u64 {
        let mut guard = self.lock();
        let seq = guard.next_seq;
        guard.next_seq = guard.next_seq.saturating_add(1);
        guard.pending.insert(seq);
        drop(guard);
        self.notify.notify_waiters();
        seq
    }

    fn finish_request(&self, seq: u64, blocked_url: Option<String>) {
        let mut guard = self.lock();
        guard.pending.remove(&seq);
        Self::push_blocked(&mut guard, seq, blocked_url);
        drop(guard);
        self.notify.notify_waiters();
    }

    fn record_blocked(&self, blocked_url: String) {
        let mut guard = self.lock();
        let seq = guard.next_seq;
        guard.next_seq = guard.next_seq.saturating_add(1);
        Self::push_blocked(&mut guard, seq, Some(blocked_url));
        drop(guard);
        self.notify.notify_waiters();
    }

    fn has_blocked_since(&self, cursor: u64) -> bool {
        self.lock()
            .blocked
            .iter()
            .any(|request| request.seq >= cursor && !request.url.is_empty())
    }

    fn has_pending_since(&self, cursor: u64) -> bool {
        self.lock().pending.range(cursor..).next().is_some()
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }

    #[cfg(test)]
    fn blocked_len(&self) -> usize {
        self.lock().blocked.len()
    }

    fn push_blocked(guard: &mut RequestPolicyState, seq: u64, blocked_url: Option<String>) {
        if let Some(url) = blocked_url {
            guard.blocked.push_back(BlockedRequest { seq, url });
            while guard.blocked.len() > MAX_BLOCKED_REQUESTS {
                guard.blocked.pop_front();
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RequestPolicyState> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

async fn wait_for_no_blocked_request_since(
    tracker: &RequestPolicyTracker,
    cursor: u64,
) -> Result<(), TransportError> {
    wait_for_no_blocked_request_with_grace(tracker, cursor, REQUEST_POLICY_EVENT_GRACE).await
}

/// Settle variant with no minimum event grace: drains pending requests since
/// `cursor` so a policy-blocked verdict still surfaces, but returns as soon as
/// nothing is pending. Sound ONLY when a full `REQUEST_POLICY_EVENT_GRACE` has
/// already been served for the same `cursor` (every `record_*_since` caller
/// waits right after its action command returns), so re-paying the 25ms floor
/// on the observation side of the same action would watch a window the first
/// wait already covered.
async fn wait_for_no_blocked_request_settled(
    tracker: &RequestPolicyTracker,
    cursor: u64,
) -> Result<(), TransportError> {
    wait_for_no_blocked_request_with_grace(tracker, cursor, Duration::ZERO).await
}

async fn wait_for_no_blocked_request_with_grace(
    tracker: &RequestPolicyTracker,
    cursor: u64,
    grace: Duration,
) -> Result<(), TransportError> {
    let event_deadline = Instant::now() + grace;
    let deadline = Instant::now() + BLOCKED_REQUEST_SETTLE_TIMEOUT;
    loop {
        if tracker.has_blocked_since(cursor) {
            return Err(TransportError::UrlBlocked);
        }
        if !tracker.has_pending_since(cursor) {
            if Instant::now() >= event_deadline {
                return Ok(());
            }
        } else if Instant::now() >= deadline {
            return Err(TransportError::UrlBlocked);
        }
        tokio::select! {
            () = tracker.notified() => {}
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
}

async fn install_request_policy(
    page: &Page,
    url_policy: Arc<Mutex<UrlPolicy>>,
    blocked_request_url: Arc<Mutex<Option<String>>>,
    request_policy_tracker: Arc<RequestPolicyTracker>,
) -> Result<JoinHandle<()>, TransportError> {
    let mut request_paused = page
        .event_listener::<EventRequestPaused>()
        .await
        .map_err(map_cdp_error)?;
    page.execute(
        FetchEnableParams::builder()
            .pattern(
                RequestPattern::builder()
                    .url_pattern("*")
                    .request_stage(RequestStage::Request)
                    .build(),
            )
            .build(),
    )
    .await
    .map_err(map_cdp_error)?;

    let page = page.clone();
    Ok(tokio::spawn(async move {
        while let Some(event) = request_paused.next().await {
            let seq = request_policy_tracker.start_request();
            let request_url = event.request.url.clone();
            let policy = match url_policy.lock() {
                Ok(policy) => Some(policy.clone()),
                Err(_error) => None,
            };
            let allowed = match policy {
                Some(policy) => enforce_url_policy(&request_url, &policy).is_ok(),
                None => false,
            };

            let (request_handled, blocked_url) = if allowed {
                (
                    page.execute(ContinueRequestParams::new(event.request_id.clone()))
                        .await
                        .is_ok(),
                    None,
                )
            } else {
                mark_blocked_request_url(&blocked_request_url, &request_url);
                (
                    page.execute(FailRequestParams::new(
                        event.request_id.clone(),
                        ErrorReason::BlockedByClient,
                    ))
                    .await
                    .is_ok(),
                    Some(request_url),
                )
            };
            request_policy_tracker.finish_request(seq, blocked_url);

            if !request_handled {
                break;
            }
        }
    }))
}

struct PolicyProxy {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl PolicyProxy {
    async fn start(
        url_policy: Arc<Mutex<UrlPolicy>>,
        blocked_request_url: Arc<Mutex<Option<String>>>,
        request_policy_tracker: Arc<RequestPolicyTracker>,
    ) -> Result<Self, TransportError> {
        let listener = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| {
                TransportError::Other(format!("failed to bind CDP policy proxy: {error}"))
            })?;
        let addr = listener.local_addr().map_err(|error| {
            TransportError::Other(format!("failed to read CDP policy proxy address: {error}"))
        })?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                let url_policy = url_policy.clone();
                let blocked_request_url = blocked_request_url.clone();
                let request_policy_tracker = request_policy_tracker.clone();
                tokio::spawn(async move {
                    handle_policy_proxy_connection(
                        stream,
                        url_policy,
                        blocked_request_url,
                        request_policy_tracker,
                    )
                    .await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

impl Drop for PolicyProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body_prefix: Vec<u8>,
}

async fn handle_policy_proxy_connection(
    mut client: TcpStream,
    url_policy: Arc<Mutex<UrlPolicy>>,
    blocked_request_url: Arc<Mutex<Option<String>>>,
    request_policy_tracker: Arc<RequestPolicyTracker>,
) {
    let request = match read_proxy_request(&mut client).await {
        Some(request) => request,
        None => {
            let _ = write_proxy_response(&mut client, 400, "Bad Request").await;
            return;
        }
    };
    let policy = {
        match url_policy.lock() {
            Ok(policy) => Some(policy.clone()),
            Err(_error) => None,
        }
    };
    let Some(policy) = policy else {
        let _ = write_proxy_response(&mut client, 403, "Forbidden").await;
        return;
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_proxy_request(
            client,
            request,
            &policy,
            blocked_request_url,
            request_policy_tracker,
        )
        .await;
    } else {
        handle_http_proxy_request(
            client,
            request,
            &policy,
            blocked_request_url,
            request_policy_tracker,
        )
        .await;
    }
}

async fn read_proxy_request(client: &mut TcpStream) -> Option<ProxyRequest> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() >= POLICY_PROXY_MAX_HEADER_BYTES {
            return None;
        }
        let mut chunk = [0_u8; 1024];
        let read = client.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let target = request_line.next()?.to_string();
    let version = request_line.next()?.to_string();
    if request_line.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Some(ProxyRequest {
        method,
        target,
        version,
        headers,
        body_prefix: buffer[header_end + 4..].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn handle_connect_proxy_request(
    mut client: TcpStream,
    request: ProxyRequest,
    policy: &UrlPolicy,
    blocked_request_url: Arc<Mutex<Option<String>>>,
    request_policy_tracker: Arc<RequestPolicyTracker>,
) {
    let Some((policy_url, host, port)) = connect_target(&request.target) else {
        let _ = write_proxy_response(&mut client, 400, "Bad Request").await;
        return;
    };
    let mut upstream = match connect_policy_target(&policy_url, &host, port, policy).await {
        Ok(upstream) => upstream,
        Err(PolicyProxyConnectError::PolicyBlocked) => {
            record_blocked_request(&blocked_request_url, &request_policy_tracker, &policy_url);
            let _ = write_proxy_response(&mut client, 403, "Forbidden").await;
            return;
        }
        Err(PolicyProxyConnectError::UpstreamUnavailable) => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway").await;
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn handle_http_proxy_request(
    mut client: TcpStream,
    request: ProxyRequest,
    policy: &UrlPolicy,
    blocked_request_url: Arc<Mutex<Option<String>>>,
    request_policy_tracker: Arc<RequestPolicyTracker>,
) {
    let parsed = match url::Url::parse(&request.target) {
        Ok(parsed) if parsed.scheme() == "http" => parsed,
        _ => {
            let _ = write_proxy_response(&mut client, 400, "Bad Request").await;
            return;
        }
    };
    let Some(host) = parsed.host_str().map(str::to_string) else {
        let _ = write_proxy_response(&mut client, 400, "Bad Request").await;
        return;
    };
    let Some(port) = parsed.port_or_known_default() else {
        let _ = write_proxy_response(&mut client, 400, "Bad Request").await;
        return;
    };
    let mut upstream = match connect_policy_target(parsed.as_str(), &host, port, policy).await {
        Ok(upstream) => upstream,
        Err(PolicyProxyConnectError::PolicyBlocked) => {
            record_blocked_request(
                &blocked_request_url,
                &request_policy_tracker,
                parsed.as_str(),
            );
            let _ = write_proxy_response(&mut client, 403, "Forbidden").await;
            return;
        }
        Err(PolicyProxyConnectError::UpstreamUnavailable) => {
            let _ = write_proxy_response(&mut client, 502, "Bad Gateway").await;
            return;
        }
    };
    let origin_form = origin_form(&parsed);
    let mut forwarded = format!("{} {} {}\r\n", request.method, origin_form, request.version);
    let mut has_host = false;
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "proxy-authorization" || lower == "proxy-connection" {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        forwarded.push_str(name);
        forwarded.push_str(": ");
        forwarded.push_str(value);
        forwarded.push_str("\r\n");
    }
    if !has_host {
        forwarded.push_str("Host: ");
        forwarded.push_str(parsed.host_str().unwrap_or_default());
        if let Some(port) = parsed.port() {
            forwarded.push(':');
            forwarded.push_str(&port.to_string());
        }
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("\r\n");
    if upstream.write_all(forwarded.as_bytes()).await.is_err() {
        let _ = write_proxy_response(&mut client, 502, "Bad Gateway").await;
        return;
    }
    if !request.body_prefix.is_empty() && upstream.write_all(&request.body_prefix).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

fn mark_blocked_request_url(blocked_request_url: &Arc<Mutex<Option<String>>>, url: &str) {
    if let Ok(mut blocked) = blocked_request_url.lock() {
        *blocked = Some(url.to_string());
    }
}

fn record_blocked_request(
    blocked_request_url: &Arc<Mutex<Option<String>>>,
    request_policy_tracker: &Arc<RequestPolicyTracker>,
    url: &str,
) {
    mark_blocked_request_url(blocked_request_url, url);
    request_policy_tracker.record_blocked(url.to_string());
}

fn connect_target(authority: &str) -> Option<(String, String, u16)> {
    if authority.contains('/') || authority.contains('@') {
        return None;
    }
    let policy_url = format!("https://{authority}/");
    let parsed = url::Url::parse(&policy_url).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default()?;
    Some((policy_url, host, port))
}

fn origin_form(parsed: &url::Url) -> String {
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyProxyConnectError {
    PolicyBlocked,
    UpstreamUnavailable,
}

async fn connect_policy_target(
    url: &str,
    host: &str,
    port: u16,
    policy: &UrlPolicy,
) -> Result<TcpStream, PolicyProxyConnectError> {
    enforce_url_policy(url, policy).map_err(|_error| PolicyProxyConnectError::PolicyBlocked)?;
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_error| PolicyProxyConnectError::UpstreamUnavailable)?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(PolicyProxyConnectError::UpstreamUnavailable);
    }
    addrs.sort_unstable();
    addrs.dedup();
    for resolved_socket in &addrs {
        enforce_url_policy_with_resolved_socket(url, policy, *resolved_socket)
            .map_err(|_error| PolicyProxyConnectError::PolicyBlocked)?;
    }
    for resolved_socket in addrs {
        if let Ok(stream) = TcpStream::connect(resolved_socket).await {
            return Ok(stream);
        }
    }
    Err(PolicyProxyConnectError::UpstreamUnavailable)
}

async fn write_proxy_response(
    client: &mut TcpStream,
    status: u16,
    reason: &str,
) -> Result<(), std::io::Error> {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(response.as_bytes()).await
}

fn enforce_url_policy_with_resolved_socket(
    url: &str,
    policy: &UrlPolicy,
    resolved_socket: SocketAddr,
) -> Result<(), TransportError> {
    policy
        .enforce_resolved_socket(url, resolved_socket)
        .map_err(|_error| TransportError::UrlBlocked)
}

fn screenshot_viewport_clip() -> Result<Viewport, TransportError> {
    Viewport::builder()
        .x(0.0)
        .y(0.0)
        .width(f64::from(MAX_SCREENSHOT_WIDTH))
        .height(f64::from(MAX_SCREENSHOT_HEIGHT))
        .scale(1.0)
        .build()
        .map_err(TransportError::Other)
}

fn validate_screenshot_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, TransportError> {
    if bytes.len() > MAX_SCREENSHOT_BYTES {
        return Err(TransportError::OutputTooLarge {
            artifact: "screenshot",
            bytes: bytes.len(),
            max_bytes: MAX_SCREENSHOT_BYTES,
        });
    }
    Ok(bytes)
}

fn map_cdp_error(error: CdpError) -> TransportError {
    TransportError::Other(error.to_string())
}

fn navigation_urls_match(requested_url: &str, current_url: &str) -> bool {
    if requested_url == current_url {
        return true;
    }
    match (url::Url::parse(requested_url), url::Url::parse(current_url)) {
        (Ok(requested), Ok(current)) => requested == current,
        _ => false,
    }
}

fn timed_out_navigation_recovered(
    requested_url: &str,
    current_url: &str,
    ready_state: &str,
) -> bool {
    ready_state == "complete" && navigation_urls_match(requested_url, current_url)
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn is_node_not_found_msg(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("could not find node") || lowered.contains("no node with given id")
}

fn is_selector_grounding_miss_msg(message: &str) -> bool {
    let lowered = message.to_lowercase();
    is_node_not_found_msg(&lowered)
        || lowered.contains("invalid selector")
        || lowered.contains("not a valid selector")
        || lowered.contains("dom error while querying")
}

fn is_uninteresting_ax_node_msg(message: &str) -> bool {
    message.to_lowercase().contains("uninteresting")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeGrounding {
    target: String,
    grounded: bool,
}

fn grounded_selector(
    selectors_by_node: &BTreeMap<NodeId, String>,
    node: &NodeId,
) -> Option<String> {
    selectors_by_node.get(node).cloned()
}

/// Beater compatibility boundary: tempo-schema's
/// `From<beater_browser::BrowserAction>` still emits raw CSS selectors as
/// NodeIds that never passed through StableIdMapper. Those legacy selectors may
/// be tried as querySelector inputs, but tempo-owned `node:*` IDs are opaque
/// capabilities and must never fall through to raw selector lookup.
fn selector_or_legacy_fallback(
    selectors_by_node: &BTreeMap<NodeId, String>,
    node: &NodeId,
) -> Option<String> {
    grounded_selector(selectors_by_node, node).or_else(|| {
        if node.0.starts_with("node:") {
            None
        } else {
            Some(node.0.clone())
        }
    })
}

fn extraction_found(value: &serde_json::Value) -> bool {
    value
        .get("found")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn node_not_found_extraction(node: &NodeId) -> serde_json::Value {
    serde_json::json!({
        "selector": node.0,
        "found": false,
        "error": "node id not found",
    })
}

fn enforce_url_policy(url: &str, policy: &UrlPolicy) -> Result<(), TransportError> {
    policy
        .enforce(url)
        .map_err(|_error| TransportError::UrlBlocked)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageStabilitySample {
    ready: bool,
    dom_hash: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompositeQuiescenceTracker {
    required_stable_samples: u8,
    last_dom_hash: Option<u64>,
    stable_samples: u8,
}

impl CompositeQuiescenceTracker {
    fn new(required_stable_samples: u8) -> Self {
        Self {
            required_stable_samples: required_stable_samples.max(1),
            last_dom_hash: None,
            stable_samples: 0,
        }
    }

    fn observe(&mut self, sample: PageStabilitySample) -> bool {
        if !sample.ready {
            self.last_dom_hash = Some(sample.dom_hash);
            self.stable_samples = 0;
            return false;
        }

        self.stable_samples = if self.last_dom_hash == Some(sample.dom_hash) {
            self.stable_samples.saturating_add(1)
        } else {
            1
        };
        self.last_dom_hash = Some(sample.dom_hash);
        self.stable_samples >= self.required_stable_samples
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn extraction_script(selector: &str) -> Result<String, TransportError> {
    let selector_json = serde_json::to_string(selector)
        .map_err(|error| TransportError::Other(error.to_string()))?;
    Ok(format!(
        r#"(() => {{
  const selector = {selector_json};
  function compact(value, max) {{
    return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
  }}
  function ownText(element) {{
    return Array.from(element.childNodes)
      .filter((node) => node.nodeType === Node.TEXT_NODE)
      .map((node) => compact(node.textContent, 512))
      .filter(Boolean)
      .join(' ');
  }}
  function formLabels(element) {{
    if (!element.labels) {{
      return '';
    }}
    return Array.from(element.labels)
      .map((label) => compact(label.textContent, 256))
      .filter(Boolean)
      .join(' ');
  }}
  function inferredRole(element) {{
    const explicit = element.getAttribute('role');
    if (explicit) {{
      return explicit;
    }}
    const tag = element.tagName.toLowerCase();
    if (tag === 'a' && element.hasAttribute('href')) {{
      return 'link';
    }}
    if (tag === 'button') {{
      return 'button';
    }}
    if (tag === 'select') {{
      return 'combobox';
    }}
    if (tag === 'textarea') {{
      return 'textbox';
    }}
    if (tag === 'input') {{
      const type = (element.getAttribute('type') || 'text').toLowerCase();
      if (type === 'checkbox') {{
        return 'checkbox';
      }}
      if (type === 'radio') {{
        return 'radio';
      }}
      if (type === 'submit' || type === 'button') {{
        return 'button';
      }}
      return 'textbox';
    }}
    return tag;
  }}
  function accessibleName(element) {{
    return compact(
      element.getAttribute('aria-label') ||
      element.getAttribute('title') ||
      element.getAttribute('alt') ||
      element.getAttribute('placeholder') ||
      formLabels(element) ||
      ownText(element) ||
      element.textContent,
      512
    );
  }}
  function attributes(element) {{
    const names = ['id', 'name', 'type', 'href', 'role', 'aria-label', 'title', 'placeholder', 'value', 'data-testid'];
    const output = {{}};
    for (const name of names) {{
      if (element.hasAttribute(name)) {{
        output[name] = element.getAttribute(name);
      }}
    }}
    return output;
  }}
  function serialize(element, depth) {{
    const children = depth >= 2
      ? []
      : Array.from(element.children)
          .slice(0, 25)
          .map((child) => serialize(child, depth + 1));
    return {{
      tag: element.tagName.toLowerCase(),
      role: inferredRole(element),
      name: accessibleName(element),
      text: compact(element.innerText || element.textContent, 4096),
      value: 'value' in element ? String(element.value) : null,
      attributes: attributes(element),
      visible: Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length),
      enabled: !Boolean(element.disabled),
      children,
    }};
  }}
  let root = null;
  try {{
    root = document.querySelector(selector);
  }} catch (error) {{
    return {{
      selector,
      found: false,
      error: `invalid selector: ${{error && error.message ? error.message : error}}`,
    }};
  }}
  if (!root) {{
    return {{
      selector,
      found: false,
      error: 'selector not found',
    }};
  }}
  return {{
    selector,
    found: true,
    node: serialize(root, 0),
  }};
}})()"#
    ))
}

fn compile_observation(
    mapper: &mut StableIdMapper,
    url: String,
    dom_html: String,
    seq: u64,
) -> (CompiledObservation, BTreeMap<NodeId, String>) {
    let mut elements = extract_interactive_elements(&dom_html);
    let raw_elements: Vec<_> = elements
        .iter()
        .map(raw_element_from_selector_element)
        .collect();
    let node_ids = mapper.map_snapshot(seq, &raw_elements);
    let mut selectors_by_node = BTreeMap::new();
    for (element, node_id) in elements.iter_mut().zip(node_ids) {
        let selector = element.node_id.0.clone();
        element.node_id = node_id.clone();
        selectors_by_node.insert(node_id, selector);
    }

    (
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url,
            seq,
            elements,
            omitted: 0,
            marks: Vec::new(),
        },
        selectors_by_node,
    )
}

fn raw_element_from_selector_element(element: &InteractiveElement) -> RawElement {
    let mut raw = RawElement::new(element.role.clone(), "")
        .source_id(element.node_id.0.clone())
        .name_spans(element.name.clone())
        .value_spans(element.value.clone());
    if let Some(bounds) = element.bounds {
        raw = raw.bounds(bounds);
    }
    raw
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AxSummary {
    role: Option<String>,
    name: Option<String>,
    value: Option<String>,
}

/// The AX summary of the single node described by a `GetPartialAXTree` reply
/// fetched with `fetch_relatives = false`.
///
/// With relatives disabled the reply carries only the queried element's own AX
/// node (ancestors/siblings/children are not fetched), so
/// `ax_summaries_by_backend_id` — which already skips ignored nodes and those
/// with no role/name/value — yields at most one entry: that element's summary.
/// Taking it is therefore exactly equivalent to the previous
/// `backend_node_id`-keyed lookup, which selected that same node, while no
/// longer needing the backend node id from a separate `DOM.describeNode` call.
fn sole_ax_summary(nodes: &[AxNode]) -> Option<AxSummary> {
    ax_summaries_by_backend_id(nodes).into_values().next()
}

fn ax_summaries_by_backend_id(nodes: &[AxNode]) -> BTreeMap<i64, AxSummary> {
    let mut summaries = BTreeMap::new();
    for node in nodes {
        if node.ignored {
            continue;
        }
        let Some(backend_dom_node_id) = node.backend_dom_node_id else {
            continue;
        };

        let summary = AxSummary {
            role: node
                .role
                .as_ref()
                .and_then(ax_value_string)
                .map(normalize_ax_role),
            name: node
                .name
                .as_ref()
                .and_then(ax_value_string)
                .filter(|value| !value.trim().is_empty()),
            value: node
                .value
                .as_ref()
                .and_then(ax_value_string)
                .filter(|value| !value.trim().is_empty()),
        };

        if summary.role.is_some() || summary.name.is_some() || summary.value.is_some() {
            summaries
                .entry(*backend_dom_node_id.inner())
                .or_insert(summary);
        }
    }
    summaries
}

fn ax_value_string(value: &AxValue) -> Option<String> {
    let string = match value.value.as_ref()? {
        serde_json::Value::String(value) => value.trim().to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        _ => return None,
    };
    if string.is_empty() {
        None
    } else {
        Some(string)
    }
}

fn normalize_ax_role(role: String) -> String {
    match role.trim() {
        "textField" | "text field" => "textbox".to_string(),
        "comboBox" => "combobox".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn apply_ax_summary(element: &mut InteractiveElement, summary: &AxSummary) {
    if let Some(role) = &summary.role {
        element.role = role.clone();
        element.rank = element.rank.max(rank_for_ax_role(role));
    }
    if let Some(name) = &summary.name {
        element.name = page_taint(name);
    }
    if let Some(value) = &summary.value {
        element.value = page_taint(value);
    }
}

/// Enrich at most `max_enriched` elements with an AX summary, chosen as the
/// highest-ranked elements (ties broken by document order). `lookup` performs
/// the per-element CDP round-trips; it is only invoked for the elements that are
/// selected, so the number of round-trips is bounded by `max_enriched`
/// regardless of how many interactive elements the page exposes (#201).
async fn enrich_elements<F, Fut>(
    elements: &mut [InteractiveElement],
    max_enriched: usize,
    mut lookup: F,
) -> Result<(), TransportError>
where
    F: FnMut(NodeId) -> Fut,
    Fut: std::future::Future<Output = Result<Option<AxSummary>, TransportError>>,
{
    let mut jobs = Vec::new();
    for index in top_ranked_indices(elements, max_enriched) {
        let Some(element) = elements.get(index) else {
            continue;
        };
        let node_id = element.node_id.clone();
        jobs.push((index, lookup(node_id)));
    }

    // The selected set is capped at `max_enriched`, so running these lookups
    // together bounds concurrency while avoiding serial CDP round-trip waits.
    let results = join_all(
        jobs.into_iter()
            .map(|(index, lookup)| async move { (index, lookup.await) }),
    )
    .await;
    for (index, summary) in results {
        if let Some(summary) = summary? {
            let Some(element) = elements.get_mut(index) else {
                continue;
            };
            apply_ax_summary(element, &summary);
        }
    }
    Ok(())
}

/// Indices of the up-to-`limit` highest-ranked elements, returned in document
/// order. Rank ties keep document order, mirroring how the observe pipeline
/// selects which elements become set-of-marks labels, so enrichment covers the
/// same elements that survive into the compiled observation.
fn top_ranked_indices(elements: &[InteractiveElement], limit: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..elements.len()).collect();
    // Stable sort by rank descending; equal ranks retain their original
    // (document) order, matching the marks compositor's selection.
    indices.sort_by(|&a, &b| elements[b].rank.total_cmp(&elements[a].rank));
    indices.truncate(limit);
    // Enrich in document order for deterministic, natural traversal.
    indices.sort_unstable();
    indices
}

fn page_taint(value: &str) -> Vec<TaintSpan> {
    vec![TaintSpan {
        provenance: Provenance::Page,
        text: value.to_string(),
    }]
}

fn rank_for_ax_role(role: &str) -> f32 {
    match role {
        "button" => 1.0,
        "textbox" | "checkbox" | "radio" | "combobox" => 0.9,
        "link" => 0.8,
        _ => 0.5,
    }
}

fn diff_from_base(
    base: Option<&CompiledObservation>,
    current: &CompiledObservation,
    since_seq: u64,
) -> ObservationDiff {
    let Some(base) = base else {
        return ObservationDiff {
            since_seq,
            seq: current.seq,
            omitted: current.omitted,
            added: current.elements.clone(),
            removed: Vec::new(),
            changed: Vec::new(),
        };
    };

    let before: HashMap<_, _> = base
        .elements
        .iter()
        .map(|element| (element.node_id.0.clone(), element))
        .collect();
    let after: HashMap<_, _> = current
        .elements
        .iter()
        .map(|element| (element.node_id.0.clone(), element))
        .collect();

    let added = after
        .iter()
        .filter(|(node, _)| !before.contains_key(*node))
        .map(|(_, element)| (*element).clone())
        .collect();
    let removed = before
        .iter()
        .filter(|(node, _)| !after.contains_key(*node))
        .map(|(_, element)| element.node_id.clone())
        .collect();
    let changed = after
        .iter()
        .filter_map(|(node, element)| {
            before
                .get(node)
                .filter(|previous| *previous != element)
                .map(|_| (*element).clone())
        })
        .collect();

    ObservationDiff {
        since_seq,
        seq: current.seq,
        omitted: current.omitted,
        added,
        removed,
        changed,
    }
}

fn extract_interactive_elements(html: &str) -> Vec<InteractiveElement> {
    // Track the open-element stack so `:nth-of-type` fallback indices are scoped
    // to siblings under the same parent (issue #104), not a document-global
    // counter. Each frame records how many of each tag have opened directly
    // under it so far.
    struct Frame {
        tag: String,
        child_counts: BTreeMap<String, usize>,
        selector_path: String,
    }

    // Pre-size from a cheap density estimate (~1 interactive element per 400
    // bytes of HTML, capped) so a big page doesn't pay repeated grow-copies of
    // the element vector while streaming.
    let mut elements = Vec::with_capacity((html.len() / 400).clamp(8, 1024));
    let mut search_from = 0;
    // Sentinel document-root frame; its empty tag never matches a real close tag.
    let mut stack: Vec<Frame> = vec![Frame {
        tag: String::new(),
        child_counts: BTreeMap::new(),
        selector_path: String::new(),
    }];

    while let Some(start_offset) = html[search_from..].find('<') {
        let start = search_from + start_offset;
        let Some(end_offset) = html[start..].find('>') else {
            break;
        };
        let end = start + end_offset;
        let raw_tag = html[start + 1..end].trim();
        search_from = end + 1;

        if raw_tag.is_empty() || raw_tag.starts_with('!') || raw_tag.starts_with('?') {
            continue;
        }

        // Close tag: pop the stack back to the matching open element so sibling
        // counting resumes in the correct parent scope.
        if let Some(name) = raw_tag.strip_prefix('/') {
            let name = name.trim().to_ascii_lowercase();
            if let Some(position) = stack.iter().rposition(|frame| frame.tag == name)
                && position > 0
            {
                stack.truncate(position);
            }
            continue;
        }

        let self_closing = raw_tag.ends_with('/');
        let raw_tag = raw_tag.trim_end_matches('/').trim();
        let Some((tag, attrs_raw)) = split_tag(raw_tag) else {
            continue;
        };
        let tag = tag.to_ascii_lowercase();
        let attrs = parse_attrs(attrs_raw);

        // Count this element among its same-tag siblings under the current
        // parent; this is the element's 1-based `:nth-of-type` index.
        let (nth_of_type, parent_selector_path) = {
            let Some(parent) = stack.last_mut() else {
                break;
            };
            let count = parent.child_counts.entry(tag.clone()).or_insert(0);
            *count += 1;
            (*count, parent.selector_path.clone())
        };
        let selector_segment = format!("{tag}:nth-of-type({nth_of_type})");
        let fallback_selector = child_structural_selector(&parent_selector_path, &selector_segment);

        // Container elements open a new sibling scope; void/self-closing ones
        // never have children and are not pushed.
        if !(self_closing || is_void_element(&tag)) {
            stack.push(Frame {
                tag: tag.clone(),
                child_counts: BTreeMap::new(),
                selector_path: fallback_selector.clone(),
            });
        }

        let role_attr = attrs.get("role").map(String::as_str);
        if !is_interactive(&tag, role_attr, &attrs) {
            continue;
        }

        let text = element_text(html, search_from, &tag).unwrap_or_default();
        let name = attrs
            .get("aria-label")
            .or_else(|| attrs.get("title"))
            .or_else(|| attrs.get("value"))
            .cloned()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| text.trim().to_string());
        let selector = selector_for(&tag, &attrs).unwrap_or(fallback_selector);
        let role = role_attr
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| implicit_role(&tag, &attrs));

        elements.push(InteractiveElement {
            node_id: NodeId(selector),
            role,
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: name,
            }],
            value: attrs
                .get("value")
                .map(|value| {
                    vec![TaintSpan {
                        provenance: Provenance::Page,
                        text: value.clone(),
                    }]
                })
                .unwrap_or_default(),
            bounds: None,
            rank: rank_for(&tag, role_attr),
        });
    }

    elements
}

fn is_void_element(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn child_structural_selector(parent_path: &str, segment: &str) -> String {
    if parent_path.is_empty() {
        segment.to_string()
    } else {
        format!("{parent_path} > {segment}")
    }
}

fn split_tag(raw_tag: &str) -> Option<(&str, &str)> {
    let mut parts = raw_tag.splitn(2, char::is_whitespace);
    let tag = parts.next()?.trim();
    if tag.is_empty() {
        return None;
    }
    Some((tag, parts.next().unwrap_or("").trim()))
}

fn parse_attrs(raw: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let bytes = raw.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if key_start == i {
            i += 1;
            continue;
        }
        let key = raw[key_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let value_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let value = raw[value_start..i].to_string();
                if i < bytes.len() {
                    i += 1;
                }
                value
            } else {
                let value_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
                    i += 1;
                }
                raw[value_start..i].to_string()
            }
        } else {
            String::new()
        };
        attrs.insert(key, decode_entities(&value));
    }

    attrs
}

fn is_interactive(tag: &str, role: Option<&str>, attrs: &BTreeMap<String, String>) -> bool {
    matches!(tag, "a" | "button" | "input" | "select" | "textarea")
        || matches!(
            role,
            Some("button" | "link" | "textbox" | "checkbox" | "menuitem")
        )
        || attrs.contains_key("onclick")
        || attrs.contains_key("tabindex")
}

fn selector_for(tag: &str, attrs: &BTreeMap<String, String>) -> Option<String> {
    if let Some(id) = attrs.get("id").filter(|value| !value.is_empty()) {
        return Some(format!("[id=\"{}\"]", css_attr_escape(id)));
    }
    if let Some(name) = attrs.get("name").filter(|value| !value.is_empty()) {
        return Some(format!("{tag}[name=\"{}\"]", css_attr_escape(name)));
    }
    if tag == "a"
        && let Some(href) = attrs.get("href").filter(|value| !value.is_empty())
    {
        return Some(format!("a[href=\"{}\"]", css_attr_escape(href)));
    }
    None
}

fn implicit_role(tag: &str, attrs: &BTreeMap<String, String>) -> String {
    match tag {
        "a" => "link",
        "button" => "button",
        "textarea" => "textbox",
        "select" => "combobox",
        "input" => match attrs.get("type").map(|value| value.as_str()) {
            Some("checkbox") => "checkbox",
            Some("radio") => "radio",
            Some("submit" | "button" | "reset") => "button",
            _ => "textbox",
        },
        _ => attrs
            .get("role")
            .map(String::as_str)
            .unwrap_or("interactive"),
    }
    .to_string()
}

fn rank_for(tag: &str, role: Option<&str>) -> f32 {
    match (tag, role) {
        ("button", _) | ("input", Some("button")) | (_, Some("button")) => 1.0,
        ("input", _) | ("textarea", _) | ("select", _) => 0.9,
        ("a", _) | (_, Some("link")) => 0.8,
        _ => 0.5,
    }
}

fn element_text(html: &str, from: usize, tag: &str) -> Option<String> {
    if matches!(tag, "input" | "select") {
        return None;
    }
    // Find the "</tag" close marker with a single, allocation-free, ASCII-case-
    // insensitive scan of the remaining bytes. The previous form
    // `html[from..].to_ascii_lowercase().find(...)` allocated and byte-copied the
    // entire document tail *for every interactive element*, i.e. O(elements ×
    // html_len) per observe — tens of MB of transient allocation on a large page.
    // `tag` is already lowercased by the caller; we compare case-insensitively for
    // robustness. Behavior (including a prefix match like `</a` inside `</abbr`) is
    // identical to the old `str::find`.
    let rest = &html[from..];
    let end_offset = find_close_tag(rest.as_bytes(), tag.as_bytes())?;
    Some(strip_tags(&rest[..end_offset]))
}

/// Byte offset of the next `</tag` (ASCII-case-insensitive) in `haystack`, or `None`.
///
/// Single linear pass: the scan advances strictly past each `<` it inspects, so every
/// byte is examined at most once — O(haystack.len()), not O(len) per candidate. `<` is
/// ASCII, so every returned offset is a UTF-8 char boundary (safe to slice at).
fn find_close_tag(haystack: &[u8], tag: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(rel) = haystack[i..].iter().position(|&b| b == b'<') {
        let open = i + rel;
        let name = open + 2; // skip past "</"
        if haystack.get(open + 1) == Some(&b'/')
            && name + tag.len() <= haystack.len()
            && haystack[name..name + tag.len()].eq_ignore_ascii_case(tag)
        {
            return Some(open);
        }
        i = open + 1;
    }
    None
}

/// Evict compiled observations older than the retention window, keeping the most
/// recent `HISTORY_RETENTION_SNAPSHOTS` seqs (those up to and including `newest_seq`).
/// Pure and O(retained) — the map never exceeds the window after the first prune.
fn prune_observation_history(history: &mut BTreeMap<u64, CompiledObservation>, newest_seq: u64) {
    let cutoff = newest_seq.saturating_sub(HISTORY_RETENTION_SNAPSHOTS - 1);
    if cutoff == 0 {
        return; // still within the first window; nothing to evict
    }
    history.retain(|&seq, _| seq >= cutoff);
}

fn strip_tags(input: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    decode_entities(out.trim())
}

fn css_attr_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

fn decode_entities(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "compat fallback lane: adapts Chromium CDP to DriverTrait v2"
}

#[cfg(test)]
mod tests {
    use super::*;
    use chromiumoxide::cdp::browser_protocol::accessibility::{AxNodeId, AxValueType};
    use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn navigation_url_match_accepts_chromium_normalization_only() {
        assert!(navigation_urls_match(
            "http://example.test",
            "http://example.test/"
        ));
        assert!(navigation_urls_match(
            "https://example.test/path?q=1",
            "https://example.test/path?q=1"
        ));
        assert!(!navigation_urls_match(
            "https://example.test/path?q=1",
            "https://example.test/path?q=2"
        ));
        assert!(!navigation_urls_match(
            "https://example.test/path",
            "https://other.test/path"
        ));
    }

    #[test]
    fn timed_out_navigation_recovery_requires_complete_ready_state() {
        assert!(timed_out_navigation_recovered(
            "http://example.test",
            "http://example.test/",
            "complete"
        ));
        for ready_state in ["loading", "interactive", ""] {
            assert!(
                !timed_out_navigation_recovered(
                    "http://example.test",
                    "http://example.test/",
                    ready_state
                ),
                "readyState={ready_state:?} must not recover a timed-out navigation"
            );
        }
        assert!(!timed_out_navigation_recovered(
            "http://example.test/a",
            "http://example.test/b",
            "complete"
        ));
    }

    #[test]
    fn extracts_selector_backed_interactive_elements_from_real_dom_html() {
        let html = r#"
            <main>
              <button id="save">Save</button>
              <input name="email" value="me@example.com">
              <a href="/next">Next</a>
              <div role="button" aria-label="Menu"></div>
            </main>
        "#;

        let elements = extract_interactive_elements(html);
        let ids: Vec<_> = elements
            .iter()
            .map(|element| element.node_id.0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "[id=\"save\"]",
                "input[name=\"email\"]",
                "a[href=\"/next\"]",
                "main:nth-of-type(1) > div:nth-of-type(1)"
            ]
        );
        assert_eq!(elements[0].name[0].text, "Save");
        assert_eq!(elements[1].value[0].text, "me@example.com");
        assert_eq!(elements[3].role, "button");
    }

    #[test]
    fn find_close_tag_matches_case_insensitively_in_one_pass() {
        // Case-insensitive, returns the byte offset of the '<' of "</tag".
        assert_eq!(find_close_tag(b"hi</A>", b"a"), Some(2));
        assert_eq!(find_close_tag(b"x<span>y</SPAN>z", b"span"), Some(8));
        // First matching close wins; earlier non-matching '<' are skipped.
        assert_eq!(find_close_tag(b"<b>bold</i></b>", b"b"), Some(11));
        // No close tag present.
        assert_eq!(find_close_tag(b"<b>unterminated", b"b"), None);
        // Prefix-match quirk preserved from the old str::find form: "</a" matches
        // inside "</abbr" (harmless — identical to prior behavior).
        assert_eq!(find_close_tag(b"x</abbr>", b"a"), Some(1));
    }

    #[test]
    fn element_text_reads_inner_text_without_allocating_the_tail() {
        // `from` points just past the element's open tag; text runs to "</tag".
        let html = "<p>lead</p><button>Click <b>me</b></button>tail";
        let open = "<p>lead</p><button>".len();
        assert_eq!(
            element_text(html, open, "button").as_deref(),
            Some("Click me")
        );
        // input/select never carry inner text.
        assert_eq!(element_text("<input>", 7, "input"), None);
    }

    #[test]
    fn observation_history_stays_bounded_to_the_retention_window() {
        fn obs(seq: u64) -> CompiledObservation {
            CompiledObservation {
                schema_version: tempo_schema::SCHEMA_VERSION.to_string(),
                url: "https://example.test/".to_string(),
                seq,
                elements: Vec::new(),
                marks: Vec::new(),
                omitted: 0,
            }
        }
        let mut history: BTreeMap<u64, CompiledObservation> = BTreeMap::new();
        for seq in 1..=100 {
            history.insert(seq, obs(seq));
            prune_observation_history(&mut history, seq);
        }
        // Never exceeds the window, and keeps exactly the most-recent K seqs.
        assert_eq!(history.len() as u64, HISTORY_RETENTION_SNAPSHOTS);
        assert_eq!(
            *history.keys().next().unwrap(),
            100 - HISTORY_RETENTION_SNAPSHOTS + 1
        );
        assert_eq!(*history.keys().next_back().unwrap(), 100);
        // Early seqs (before the window fills) are all retained.
        let mut early: BTreeMap<u64, CompiledObservation> = BTreeMap::new();
        for seq in 1..=3 {
            early.insert(seq, obs(seq));
            prune_observation_history(&mut early, seq);
        }
        assert_eq!(early.len(), 3);
    }

    #[test]
    fn nth_of_type_fallback_selectors_are_scoped_per_parent() {
        // Spans have no id/name/href, so they fall back to a structural path.
        // The selector must include the parent path and sibling-scoped index so
        // two matching subtrees do not produce duplicate node ids.
        let html = r#"
            <section>
              <p>intro</p>
              <span tabindex="0">a</span>
              <span tabindex="0">b</span>
            </section>
            <section>
              <span tabindex="0">c</span>
            </section>
        "#;

        let elements = extract_interactive_elements(html);
        let ids: Vec<_> = elements
            .iter()
            .map(|element| element.node_id.0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "section:nth-of-type(1) > span:nth-of-type(1)",
                "section:nth-of-type(1) > span:nth-of-type(2)",
                "section:nth-of-type(2) > span:nth-of-type(1)",
            ]
        );
        let unique_ids: std::collections::HashSet<_> = ids.iter().copied().collect();
        assert_eq!(unique_ids.len(), ids.len());
    }

    #[test]
    fn computes_added_removed_and_changed_diffs() {
        let before = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.com".into(),
            seq: 1,
            elements: extract_interactive_elements(
                r#"<button id="save">Save</button><a href="/a">A</a>"#,
            ),
            omitted: 0,
            marks: Vec::new(),
        };
        let after = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.com".into(),
            seq: 2,
            elements: extract_interactive_elements(
                r#"<button id="save">Saved</button><input name="q" value="">"#,
            ),
            omitted: 0,
            marks: Vec::new(),
        };

        let diff = diff_from_base(Some(&before), &after, before.seq);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed, vec![NodeId("a[href=\"/a\"]".into())]);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].node_id, NodeId("[id=\"save\"]".into()));
    }

    #[test]
    fn composite_quiescence_requires_ready_and_stable_dom() {
        let hash_a = fnv1a64(b"<button>A</button>");
        let hash_b = fnv1a64(b"<button>B</button>");
        let mut tracker = CompositeQuiescenceTracker::new(3);

        assert!(!tracker.observe(PageStabilitySample {
            ready: false,
            dom_hash: hash_a,
        }));
        assert!(!tracker.observe(PageStabilitySample {
            ready: true,
            dom_hash: hash_a,
        }));
        assert!(!tracker.observe(PageStabilitySample {
            ready: true,
            dom_hash: hash_b,
        }));
        assert!(!tracker.observe(PageStabilitySample {
            ready: true,
            dom_hash: hash_b,
        }));
        assert!(tracker.observe(PageStabilitySample {
            ready: true,
            dom_hash: hash_b,
        }));
    }

    #[test]
    fn stability_probe_parses_ready_state_and_generation() {
        assert_eq!(
            parse_stability_probe("complete|42"),
            Some(ParsedStabilityProbe {
                sample: PageStabilitySample {
                    ready: true,
                    dom_hash: 42,
                },
                url: None,
            })
        );
        assert_eq!(
            parse_stability_probe("loading|7"),
            Some(ParsedStabilityProbe {
                sample: PageStabilitySample {
                    ready: false,
                    dom_hash: 7,
                },
                url: None,
            })
        );
        assert_eq!(
            parse_stability_probe("interactive|0"),
            Some(ParsedStabilityProbe {
                sample: PageStabilitySample {
                    ready: true,
                    dom_hash: 0,
                },
                url: None,
            })
        );
    }

    #[test]
    fn stability_probe_parses_frame_url_including_pipe_characters() {
        assert_eq!(
            parse_stability_probe("complete|42|https://example.test/search?q=a"),
            Some(ParsedStabilityProbe {
                sample: PageStabilitySample {
                    ready: true,
                    dom_hash: 42,
                },
                url: Some("https://example.test/search?q=a".into()),
            })
        );
        // An href containing the separator stays intact: only the first two
        // fields split, the remainder is the URL.
        assert_eq!(
            parse_stability_probe("interactive|3|https://example.test/?q=a|b|c"),
            Some(ParsedStabilityProbe {
                sample: PageStabilitySample {
                    ready: true,
                    dom_hash: 3,
                },
                url: Some("https://example.test/?q=a|b|c".into()),
            })
        );
        // Malformed generation still rejects even with a URL present.
        assert_eq!(parse_stability_probe("complete|-1|https://x.test"), None);
    }

    #[test]
    fn stability_probe_script_reports_frame_url() {
        assert!(STABILITY_PROBE_SCRIPT.contains("location.href"));
    }

    #[tokio::test]
    async fn settled_wait_returns_immediately_when_nothing_pending(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tracker = RequestPolicyTracker::new();
        let cursor = tracker.cursor();
        let started = Instant::now();
        wait_for_no_blocked_request_settled(&tracker, cursor).await?;
        // No event grace: an idle tracker settles without the 25ms floor.
        assert!(started.elapsed() < REQUEST_POLICY_EVENT_GRACE);
        Ok(())
    }

    #[tokio::test]
    async fn settled_wait_still_surfaces_blocked_requests() {
        let tracker = RequestPolicyTracker::new();
        let cursor = tracker.cursor();
        let seq = tracker.start_request();
        tracker.finish_request(seq, Some("https://blocked.test/".into()));
        let result = wait_for_no_blocked_request_settled(&tracker, cursor).await;
        assert!(matches!(result, Err(TransportError::UrlBlocked)));
    }

    #[tokio::test]
    async fn settled_wait_drains_pending_before_returning() -> Result<(), Box<dyn std::error::Error>>
    {
        let tracker = std::sync::Arc::new(RequestPolicyTracker::new());
        let cursor = tracker.cursor();
        let seq = tracker.start_request();
        let finisher = {
            let tracker = tracker.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                tracker.finish_request(seq, Some("https://blocked.test/".into()));
            })
        };
        // The pending request forces the settled wait to keep watching; the
        // blocked verdict registered while draining must still surface.
        let result = wait_for_no_blocked_request_settled(&tracker, cursor).await;
        assert!(matches!(result, Err(TransportError::UrlBlocked)));
        finisher.await?;
        Ok(())
    }

    #[test]
    fn stability_probe_rejects_unavailable_or_malformed_probes() {
        // Observer unavailable: route to the DOM-hash fallback.
        assert_eq!(parse_stability_probe("complete|-1"), None);
        // Malformed shapes a broken page could produce.
        assert_eq!(parse_stability_probe("complete"), None);
        assert_eq!(parse_stability_probe("complete|"), None);
        assert_eq!(parse_stability_probe("complete|abc"), None);
        assert_eq!(parse_stability_probe(""), None);
        assert_eq!(parse_stability_probe("|"), None);
    }

    #[test]
    fn stability_probe_rebinds_when_document_root_changes() {
        assert!(STABILITY_PROBE_SCRIPT.contains("__tempoMutTarget !== target"));
        assert!(STABILITY_PROBE_SCRIPT.contains("__tempoMutObs.disconnect()"));
        assert!(STABILITY_PROBE_SCRIPT
            .contains("typeof w.__tempoMutGen === 'number' ? w.__tempoMutGen + 1 : 0"));
    }

    #[test]
    fn quiescence_poll_ramp_is_bounded_by_legacy_cap() {
        for interval in QUIESCENCE_POLL_INTERVALS_MS {
            assert!(interval <= QUIESCENCE_POLL_INTERVAL_CAP_MS);
        }
        // Three stable samples must span at least 75ms of quiet evidence so
        // late-starting JS keeps close to the legacy 100ms observation window.
        let evidence_span: u64 = QUIESCENCE_POLL_INTERVALS_MS.iter().sum();
        assert!(evidence_span >= 75);
    }

    #[test]
    fn extraction_script_json_encodes_selector() -> Result<(), Box<dyn std::error::Error>> {
        let selector = "[id=\"save\"]";
        let script = extraction_script(selector)?;
        let encoded = serde_json::to_string(selector)?;

        assert!(script.contains(&format!("const selector = {encoded};")));
        assert!(script.contains("document.querySelector(selector)"));
        assert!(script.contains("serialize(root, 0)"));
        Ok(())
    }

    #[test]
    fn compiled_observation_uses_stable_ids_with_private_selector_lookup() {
        let mut mapper = StableIdMapper::new();
        let (first, first_lookup) = compile_observation(
            &mut mapper,
            "https://example.test".into(),
            r#"<button id="save">Save</button>"#.into(),
            1,
        );
        let save_id = first.elements[0].node_id.clone();

        assert!(save_id.0.starts_with("node:"));
        assert_eq!(
            first_lookup.get(&save_id).map(String::as_str),
            Some("[id=\"save\"]")
        );

        let (second, second_lookup) = compile_observation(
            &mut mapper,
            "https://example.test".into(),
            r#"<button id="renamed">Save</button>"#.into(),
            2,
        );

        assert_eq!(second.elements[0].node_id, save_id);
        assert_eq!(
            second_lookup.get(&save_id).map(String::as_str),
            Some("[id=\"renamed\"]")
        );
    }

    #[test]
    fn selector_shaped_node_id_without_grounding_falls_back_for_legacy_actions() {
        let selectors = BTreeMap::new();
        assert_eq!(
            grounded_selector(&selectors, &NodeId("[id=\"save\"]".into())),
            None
        );
        assert_eq!(
            selector_or_legacy_fallback(&selectors, &NodeId("[id=\"save\"]".into())),
            Some("[id=\"save\"]".into())
        );
        assert_eq!(
            selector_or_legacy_fallback(&selectors, &NodeId("node:abc123".into())),
            None
        );
    }

    #[test]
    fn screenshot_clip_uses_max_dimensions() -> Result<(), Box<dyn std::error::Error>> {
        let clip = screenshot_viewport_clip()?;

        assert_eq!(clip.x, 0.0);
        assert_eq!(clip.y, 0.0);
        assert_eq!(clip.width, f64::from(MAX_SCREENSHOT_WIDTH));
        assert_eq!(clip.height, f64::from(MAX_SCREENSHOT_HEIGHT));
        assert_eq!(clip.scale, 1.0);
        Ok(())
    }

    #[test]
    fn screenshot_bytes_are_capped() -> Result<(), Box<dyn std::error::Error>> {
        let error = validate_screenshot_bytes(vec![0_u8; MAX_SCREENSHOT_BYTES + 1])
            .err()
            .ok_or("oversized screenshot unexpectedly succeeded")?;

        match error {
            TransportError::OutputTooLarge {
                artifact,
                bytes,
                max_bytes,
            } => {
                assert_eq!(artifact, "screenshot");
                assert_eq!(bytes, MAX_SCREENSHOT_BYTES + 1);
                assert_eq!(max_bytes, MAX_SCREENSHOT_BYTES);
            }
            other => return Err(format!("unexpected error: {other}").into()),
        }
        Ok(())
    }

    #[test]
    fn ax_summary_overlays_dom_fallback_name_role_and_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let html = r#"
            <label for="email">Email Address</label>
            <input id="email" value="me@example.com">
        "#;
        let mut element = extract_interactive_elements(html)
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("missing input element"))?;
        assert_eq!(element.role, "textbox");
        assert_eq!(element.name[0].text, "me@example.com");

        let mut ax_node = AxNode::new(AxNodeId::new("email"), false);
        ax_node.backend_dom_node_id = Some(BackendNodeId::new(42));
        ax_node.role = Some(test_ax_value(
            AxValueType::Role,
            serde_json::json!("textField"),
        ));
        ax_node.name = Some(test_ax_value(
            AxValueType::ComputedString,
            serde_json::json!("Email Address"),
        ));
        ax_node.value = Some(test_ax_value(
            AxValueType::String,
            serde_json::json!("me@example.com"),
        ));

        let summaries = ax_summaries_by_backend_id(&[ax_node]);
        let summary = summaries
            .get(&42)
            .ok_or_else(|| std::io::Error::other("missing AX summary"))?;
        apply_ax_summary(&mut element, summary);

        assert_eq!(element.role, "textbox");
        assert_eq!(element.name[0].text, "Email Address");
        assert_eq!(element.value[0].text, "me@example.com");
        Ok(())
    }

    /// `sole_ax_summary` must return exactly what the old
    /// `ax_summaries_by_backend_id(..).get(backend_id)` lookup returned. Dropping
    /// the `DOM.describeNode` round-trip (#299) means the backend node id is no
    /// longer known ahead of time, so enrichment now takes the single node a
    /// `fetch_relatives = false` reply describes instead of keying by backend id.
    /// This asserts the two selections agree on a reply shaped like the real
    /// getPartialAXTree(fetch_relatives=false) output: the queried element plus
    /// the ignored/uninteresting nodes that carry no summary.
    #[test]
    fn sole_ax_summary_matches_backend_id_keyed_selection() {
        let target_backend_id = 42_i64;

        // The queried element's own AX node — the only summarizable node in a
        // fetch_relatives=false reply.
        let mut target = AxNode::new(AxNodeId::new("target"), false);
        target.backend_dom_node_id = Some(BackendNodeId::new(target_backend_id));
        target.role = Some(test_ax_value(
            AxValueType::Role,
            serde_json::json!("button"),
        ));
        target.name = Some(test_ax_value(
            AxValueType::ComputedString,
            serde_json::json!("Submit"),
        ));

        // An ignored node (e.g. a wrapper) that carries a backend id but no
        // summary — present in real replies, filtered by the summary builder.
        let mut ignored = AxNode::new(AxNodeId::new("ignored"), true);
        ignored.backend_dom_node_id = Some(BackendNodeId::new(7));
        ignored.role = Some(test_ax_value(AxValueType::Role, serde_json::json!("none")));

        // A non-ignored node with no role/name/value — also filtered out.
        let empty = AxNode::new(AxNodeId::new("empty"), false);

        let nodes = vec![ignored, target, empty];

        // Old selection: build the map, key by the target's backend id.
        let old = ax_summaries_by_backend_id(&nodes)
            .get(&target_backend_id)
            .cloned();
        // New selection: take the single summarizable node.
        let new = sole_ax_summary(&nodes);

        assert!(old.is_some(), "the queried element must have a summary");
        assert_eq!(new, old, "sole_ax_summary must equal the backend-id lookup");
    }

    /// When the queried element itself is not in the accessibility tree (ignored
    /// or summary-less), both the old backend-id lookup and `sole_ax_summary`
    /// yield `None` — no enrichment is applied, matching prior behavior.
    #[test]
    fn sole_ax_summary_is_none_when_no_summarizable_node() {
        let mut ignored = AxNode::new(AxNodeId::new("ignored"), true);
        ignored.backend_dom_node_id = Some(BackendNodeId::new(9));
        ignored.name = Some(test_ax_value(
            AxValueType::ComputedString,
            serde_json::json!("hidden"),
        ));

        let nodes = vec![ignored];
        assert_eq!(sole_ax_summary(&nodes), None);
        assert!(ax_summaries_by_backend_id(&nodes).is_empty());
    }

    #[test]
    fn blocks_private_navigation_by_default() {
        let policy = UrlPolicy::block_private();
        for url in [
            "http://127.0.0.1",
            "http://localhost",
            "https://app.localhost/path",
            "http://10.0.0.1",
            "http://169.254.169.254/latest/meta-data",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(
                    enforce_url_policy(url, &policy),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        assert!(enforce_url_policy("https://example.com", &policy).is_ok());
        assert!(enforce_url_policy("http://127.0.0.1", &UrlPolicy::allow_all()).is_ok());
    }

    #[test]
    fn blocks_ipv6_and_ipv4_mapped_navigation() {
        let policy = UrlPolicy::block_private();
        // Issue #81: bracketed IPv6 literals and IPv4-mapped IPv6 must be
        // guarded, including the metadata endpoint reached via `::ffff:`.
        for url in [
            "http://[::1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[ff02::1]/",
            "http://[::]/",
        ] {
            assert!(
                matches!(
                    enforce_url_policy(url, &policy),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        // A global-unicast IPv6 literal is still permitted.
        assert!(enforce_url_policy("http://[2606:4700:4700::1111]/", &policy).is_ok());
    }

    #[test]
    fn blocks_cgnat_and_reserved_ipv4_navigation() {
        let policy = UrlPolicy::block_private();
        // Issue #82 parity in the CDP guard.
        for url in ["http://100.64.0.1/", "http://240.0.0.1/"] {
            assert!(
                matches!(
                    enforce_url_policy(url, &policy),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
    }

    #[test]
    fn blocks_non_http_schemes_via_allowlist() {
        let policy = UrlPolicy::block_private();
        // GAP A: opaque / non-http(s) schemes must be blocked. Previously the
        // denylist only caught `file`/`ftp`, and schemes whose host parses as
        // `None` (e.g. `view-source:...`) were waved through.
        for url in [
            "view-source:http://169.254.169.254/",
            "data:text/html,<h1>hi</h1>",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://example.com/",
        ] {
            assert!(
                matches!(
                    enforce_url_policy(url, &policy),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        // http/https remain allowed.
        assert!(enforce_url_policy("http://example.com", &policy).is_ok());
        assert!(enforce_url_policy("https://example.com", &policy).is_ok());
    }

    #[tokio::test]
    async fn request_policy_tracker_clean_path_returns_without_settle_delay() {
        let tracker = RequestPolicyTracker::new();
        let cursor = tracker.cursor();

        match tokio::time::timeout(
            Duration::from_millis(75),
            wait_for_no_blocked_request_since(&tracker, cursor),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("clean policy tracker reported a block: {error}"),
            Err(_elapsed) => {
                panic!("clean policy tracker waited for the full settle deadline");
            }
        }
    }

    #[tokio::test]
    async fn request_policy_tracker_pending_request_fails_closed_after_settle_delay() {
        let tracker = RequestPolicyTracker::new();
        let cursor = tracker.cursor();
        let _seq = tracker.start_request();

        let result = wait_for_no_blocked_request_since(&tracker, cursor).await;

        assert!(matches!(result, Err(TransportError::UrlBlocked)));
    }

    #[tokio::test]
    async fn request_policy_tracker_catches_event_registered_during_grace() {
        let tracker = Arc::new(RequestPolicyTracker::new());
        let cursor = tracker.cursor();
        let delayed_tracker = tracker.clone();
        let finisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let seq = delayed_tracker.start_request();
            tokio::time::sleep(Duration::from_millis(5)).await;
            delayed_tracker.finish_request(seq, Some("http://127.0.0.1/private".into()));
        });

        let result = wait_for_no_blocked_request_since(&tracker, cursor).await;

        assert!(matches!(result, Err(TransportError::UrlBlocked)));
        match finisher.await {
            Ok(()) => {}
            Err(error) => panic!("late request finisher task failed: {error}"),
        }
    }

    #[test]
    fn request_policy_tracker_scopes_blocks_to_operation_cursor() {
        let tracker = RequestPolicyTracker::new();
        let first_cursor = tracker.cursor();
        tracker.record_blocked("http://127.0.0.1/private".into());

        assert!(tracker.has_blocked_since(first_cursor));

        let later_cursor = tracker.cursor();
        assert!(
            !tracker.has_blocked_since(later_cursor),
            "a stale blocked request must not poison a later unrelated operation"
        );
    }

    #[test]
    fn request_policy_tracker_caps_blocked_request_log() {
        let tracker = RequestPolicyTracker::new();
        for index in 0..(MAX_BLOCKED_REQUESTS + 8) {
            tracker.record_blocked(format!("http://127.0.0.1/{index}"));
        }

        assert_eq!(tracker.blocked_len(), MAX_BLOCKED_REQUESTS);
    }

    #[test]
    fn blocks_full_zero_ipv4_block() {
        let policy = UrlPolicy::block_private();
        // GAP B: the whole 0.0.0.0/8 must be blocked, not just 0.0.0.0.
        for url in ["http://0.0.0.0/", "http://0.1.2.3/"] {
            assert!(
                matches!(
                    enforce_url_policy(url, &policy),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        // A normal public IP is still permitted.
        assert!(enforce_url_policy("http://93.184.216.34/", &policy).is_ok());
    }

    #[test]
    fn rejects_launch_args_that_bypass_the_policy_proxy() {
        for arg in [
            "--proxy-server=http://proxy.example",
            "--proxy-server",
            "--no-proxy-server",
            "--proxy-pac-url=http://proxy.example/proxy.pac",
            "--proxy-auto-detect",
            "--proxy-bypass-list=*",
            "--host-resolver-rules=MAP * 127.0.0.1",
        ] {
            let config = CdpConfig::default().with_arg(arg);
            assert!(
                matches!(
                    config.validate_policy_proxy_args(),
                    Err(TransportError::Other(_))
                ),
                "expected proxy arg rejection for {arg}"
            );
        }
        assert!(CdpConfig::default()
            .with_arg("--user-agent=tempo-test")
            .validate_policy_proxy_args()
            .is_ok());
    }

    #[test]
    fn blocks_public_hostname_when_resolved_socket_is_private(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = UrlPolicy::block_private();
        let loopback = SocketAddr::from(([127, 0, 0, 1], 443));
        let public = SocketAddr::from(([93, 184, 216, 34], 443));

        assert!(matches!(
            enforce_url_policy_with_resolved_socket("https://public.example/", &policy, loopback),
            Err(TransportError::UrlBlocked)
        ));
        assert!(enforce_url_policy_with_resolved_socket(
            "https://public.example/",
            &policy,
            public
        )
        .is_ok());
        assert!(enforce_url_policy_with_resolved_socket(
            "https://public.example/",
            &UrlPolicy::allow_all(),
            loopback,
        )
        .is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn policy_proxy_blocks_private_connect_before_origin_socket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let origin = TokioTcpListener::bind(("127.0.0.1", 0)).await?;
        let origin_addr = origin.local_addr()?;
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_probe = accepted.clone();
        let accept_task = tokio::spawn(async move {
            if let Ok(Ok((_stream, _peer))) =
                tokio::time::timeout(Duration::from_millis(150), origin.accept()).await
            {
                accepted_probe.store(true, Ordering::SeqCst);
            }
        });

        let blocked_request_url = Arc::new(Mutex::new(None));
        let request_policy_tracker = Arc::new(RequestPolicyTracker::new());
        let cursor = request_policy_tracker.cursor();
        let proxy = PolicyProxy::start(
            Arc::new(Mutex::new(UrlPolicy::block_private())),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await?;
        let mut client = TcpStream::connect(proxy.addr).await?;
        let request = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
        client.write_all(request.as_bytes()).await?;
        let mut response = [0_u8; 128];
        let read = client.read(&mut response).await?;
        let response = std::str::from_utf8(&response[..read])?;
        let expected_blocked_url = format!("https://{origin_addr}/");

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(
            blocked_request_url
                .lock()
                .map_err(|_error| std::io::Error::other("blocked URL lock poisoned"))?
                .as_deref(),
            Some(expected_blocked_url.as_str())
        );
        assert!(request_policy_tracker.has_blocked_since(cursor));
        accept_task.await?;
        assert!(!accepted.load(Ordering::SeqCst));
        drop(proxy);
        Ok(())
    }

    #[tokio::test]
    async fn policy_proxy_marks_http_socket_blocks_for_navigation_mapping(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let origin = TokioTcpListener::bind(("127.0.0.1", 0)).await?;
        let origin_addr = origin.local_addr()?;
        let blocked_request_url = Arc::new(Mutex::new(None));
        let request_policy_tracker = Arc::new(RequestPolicyTracker::new());
        let cursor = request_policy_tracker.cursor();
        let proxy = PolicyProxy::start(
            Arc::new(Mutex::new(UrlPolicy::block_private())),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await?;
        let mut client = TcpStream::connect(proxy.addr).await?;
        let request = format!(
            "GET http://{origin_addr}/blocked HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await?;
        let mut response = [0_u8; 128];
        let read = client.read(&mut response).await?;
        let response = std::str::from_utf8(&response[..read])?;
        let expected_blocked_url = format!("http://{origin_addr}/blocked");

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(
            blocked_request_url
                .lock()
                .map_err(|_error| std::io::Error::other("blocked URL lock poisoned"))?
                .as_deref(),
            Some(expected_blocked_url.as_str())
        );
        assert!(request_policy_tracker.has_blocked_since(cursor));
        drop(proxy);
        Ok(())
    }

    #[tokio::test]
    async fn policy_proxy_keeps_upstream_failures_out_of_block_mapping(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let reserved = TokioTcpListener::bind(("127.0.0.1", 0)).await?;
        let origin_addr = reserved.local_addr()?;
        drop(reserved);

        let blocked_request_url = Arc::new(Mutex::new(None));
        let request_policy_tracker = Arc::new(RequestPolicyTracker::new());
        let cursor = request_policy_tracker.cursor();
        let proxy = PolicyProxy::start(
            Arc::new(Mutex::new(UrlPolicy::allow_all())),
            blocked_request_url.clone(),
            request_policy_tracker.clone(),
        )
        .await?;
        let mut client = TcpStream::connect(proxy.addr).await?;
        let request = format!(
            "GET http://{origin_addr}/missing HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await?;
        let mut response = [0_u8; 128];
        let read = client.read(&mut response).await?;
        let response = std::str::from_utf8(&response[..read])?;

        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert_eq!(
            blocked_request_url
                .lock()
                .map_err(|_error| std::io::Error::other("blocked URL lock poisoned"))?
                .as_deref(),
            None
        );
        assert!(!request_policy_tracker.has_blocked_since(cursor));
        drop(proxy);
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_default_blocks_private_fixture_before_origin_socket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP default private block test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let origin = TokioTcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}/", origin.local_addr()?);
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_probe = accepted.clone();
        let accept_task = tokio::spawn(async move {
            if let Ok(Ok((_stream, _peer))) =
                tokio::time::timeout(Duration::from_millis(300), origin.accept()).await
            {
                accepted_probe.store(true, Ordering::SeqCst);
            }
        });

        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config).await?;
        let result = driver.goto(&url).await;

        assert!(matches!(result, Err(TransportError::UrlBlocked)));
        accept_task.await?;
        assert!(!accepted.load(Ordering::SeqCst));
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_driver_blocks_page_triggered_private_navigation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP page navigation policy test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let fixture = serve_policy_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        let observation = driver.goto(&fixture.allowed_url("/page-nav")).await?;
        let go_node = observation
            .elements
            .iter()
            .find(|element| {
                element.role == "link"
                    && element.name.first().map(|span| span.text.as_str()) == Some("Go")
            })
            .map(|element| element.node_id.clone())
            .ok_or_else(|| std::io::Error::other("missing page-nav link"))?;
        driver = driver.with_url_policy(UrlPolicy::block_private());

        let result = driver.act(&Action::Click { node: go_node }).await;

        assert!(
            matches!(result, Err(TransportError::UrlBlocked)),
            "expected page-triggered loopback navigation to be blocked, got {result:?}"
        );
        assert!(
            !fixture.private_requested.load(Ordering::SeqCst),
            "page-triggered loopback navigation reached the fixture"
        );
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_click_prevent_default_does_not_preblock_private_href(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP preventDefault policy test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config).await?;
        driver
            .evaluate_script(
                r#"(() => {
                    document.body.innerHTML = '<a id="go" href="http://127.0.0.1:1/private">Stay</a>';
                    document.getElementById('go').addEventListener('click', (event) => {
                        event.preventDefault();
                        document.body.dataset.clicked = 'yes';
                    });
                    return true;
                })()"#,
                true,
            )
            .await?;
        let observation = driver.observe().await?;
        let go_node = observation
            .elements
            .iter()
            .find(|element| element.name.first().map(|span| span.text.as_str()) == Some("Stay"))
            .map(|element| element.node_id.clone())
            .ok_or_else(|| std::io::Error::other("missing prevented private link"))?;

        let outcome = driver.act(&Action::Click { node: go_node }).await?;

        assert!(matches!(outcome, StepOutcome::Applied { .. }));
        let clicked = driver
            .evaluate_script("Promise.resolve(document.body.dataset.clicked)", true)
            .await?;
        assert_eq!(clicked, serde_json::json!("yes"));
        driver.close().await?;
        Ok(())
    }

    /// End-to-end guard for the #299 round-trip cut: after dropping the
    /// `DOM.describeNode` hop and feeding the querySelector DOM node id straight
    /// into `GetPartialAXTree`, the observation must still carry the real
    /// accessibility-tree overlay. The fixture names its controls only through
    /// `aria-labelledby`, which the raw DOM extractor does not resolve (it reads
    /// `aria-label`/`title`/`value`/text) — so the asserted names can *only* come
    /// from the accessibility tree, proving the batched path produces output
    /// identical to the sequential one.
    #[tokio::test]
    async fn live_cdp_ax_enrichment_survives_describe_node_drop(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP AX enrichment test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config).await?;
        driver
            .evaluate_script(
                r#"(() => {
                    document.body.innerHTML =
                        '<span id="save-label">Save document</span>' +
                        '<button id="save" aria-labelledby="save-label"></button>' +
                        '<span id="email-label">Email address</span>' +
                        '<input id="email" type="text" aria-labelledby="email-label" value="me@example.com">';
                    return true;
                })()"#,
                true,
            )
            .await?;

        let observation = driver.observe().await?;

        let save = observation
            .elements
            .iter()
            .find(|element| element.role == "button")
            .ok_or_else(|| std::io::Error::other("missing save button"))?;
        // Raw extraction would leave this name empty (no aria-label/title/value/
        // text); "Save document" is resolved from aria-labelledby by the AX tree.
        assert_eq!(
            save.name.first().map(|span| span.text.as_str()),
            Some("Save document"),
            "AX-tree accessible name must survive the describeNode drop"
        );

        let email = observation
            .elements
            .iter()
            .find(|element| element.role == "textbox")
            .ok_or_else(|| std::io::Error::other("missing email input"))?;
        // Raw extraction would name this element after its value; the AX tree
        // overrides it with the aria-labelledby target.
        assert_eq!(
            email.name.first().map(|span| span.text.as_str()),
            Some("Email address"),
            "AX-tree accessible name must override the raw value-derived name"
        );
        assert_eq!(
            email.value.first().map(|span| span.text.as_str()),
            Some("me@example.com"),
        );

        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_driver_blocks_script_triggered_private_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP script request policy test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let fixture = serve_policy_fixture()?;
        let private_url = serde_json::to_string(&fixture.private_url)?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config).await?;

        let result = driver
            .evaluate_script(&format!("fetch({private_url}).catch(() => null)"), true)
            .await;

        assert!(
            matches!(result, Err(TransportError::UrlBlocked)),
            "expected script-triggered loopback request to be blocked, got {result:?}"
        );
        assert!(
            !fixture.private_requested.load(Ordering::SeqCst),
            "script-triggered loopback request reached the fixture"
        );
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_driver_blocks_private_requests_during_wait_windows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP wait-window policy test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let fixture = serve_policy_fixture()?;
        let private_url = serde_json::to_string(&fixture.private_url)?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config).await?;

        let script =
            format!("setTimeout(() => fetch({private_url}).catch(() => null), 100); 'scheduled'");
        assert_eq!(
            driver.evaluate_script(&script, true).await?,
            serde_json::json!("scheduled")
        );
        let result = driver.act(&Action::Wait { millis: 250 }).await;

        assert!(
            matches!(result, Err(TransportError::UrlBlocked)),
            "expected wait-window private request to be blocked, got {result:?}"
        );
        assert!(
            !fixture.private_requested.load(Ordering::SeqCst),
            "wait-window private request reached the fixture"
        );
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_current_url_guard_rejects_redirected_private_url_before_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!(
                "skipping live CDP redirected current URL guard test; TEMPO_CDP_CHROME is unset"
            );
            return Ok(());
        };
        let fixture = serve_policy_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        driver
            .goto(&fixture.allowed_url("/redirect-private"))
            .await?;
        assert!(
            fixture.private_requested.load(Ordering::SeqCst),
            "redirect fixture did not land on the private target"
        );
        driver = driver.with_url_policy(UrlPolicy::block_private());

        let observe_result = driver.observe().await;
        assert!(
            matches!(observe_result, Err(TransportError::UrlBlocked)),
            "expected snapshot path to reject the private current URL before reading DOM, got {observe_result:?}"
        );

        let wait_result = driver
            .act_batch(&ActionBatch {
                actions: Vec::new(),
                quiescence: QuiescencePolicy::Composite,
            })
            .await;

        assert!(
            matches!(wait_result, Err(TransportError::UrlBlocked)),
            "expected composite quiescence to reject the private current URL before reading DOM, got {wait_result:?}"
        );
        driver.close().await?;
        Ok(())
    }

    /// Unmasked guard coverage for `with_element` and `Action::Scroll` (#321),
    /// complementing `live_cdp_current_url_guard_rejects_redirected_private_url_before_snapshot`
    /// above (which never issues a Click or Scroll).
    ///
    /// Both call sites have a *downstream* re-check that fires regardless of
    /// whether the site's own guard ran: after the action executes, every path
    /// calls `record_current_observation_since` -> `snapshot_since`, whose own
    /// `enforce_current_url_policy_value` also returns `UrlBlocked`. So a test
    /// that only asserts the final `Err(UrlBlocked)` cannot tell "blocked
    /// before touching the page" apart from "clicked/scrolled the page, then
    /// blocked afterward" — reverting the guard at the top of `with_element`
    /// or in the `Action::Scroll` arm would keep such a test green while the
    /// interaction silently lands on the blocked page.
    ///
    /// This test therefore asserts the *converse* as well: after the blocked
    /// Click/Scroll attempts, the page-side effects (`document.body.dataset.clicked`,
    /// `window.scrollY`) must be absent. It also keeps a direct call to
    /// `wait_for_composite_quiescence()` so the quiescence loop's own guard is
    /// exercised without `act_batch`'s post-quiescence observation guard in
    /// the way, and ends with an allow-case control proving the very same
    /// probes do fire once the policy permits — so the negative assertions
    /// cannot pass vacuously.
    #[tokio::test]
    async fn live_cdp_current_url_guard_prevents_click_and_scroll_side_effects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP guard side-effect test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_click_scroll_probe_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        let observation = driver.goto(&url).await?;
        let save_node = observation
            .elements
            .iter()
            .find(|element| {
                element.role == "button"
                    && element.name.first().map(|span| span.text.as_str()) == Some("Save")
            })
            .map(|element| element.node_id.clone())
            .ok_or_else(|| std::io::Error::other("missing probe save button"))?;

        // The driver now sits on a loopback URL; narrowing the policy makes
        // the *current* page blocked without any further navigation.
        driver = driver.with_url_policy(UrlPolicy::block_private());

        // Click through with_element: must fail AND must not have clicked.
        let click_result = driver
            .act(&Action::Click {
                node: save_node.clone(),
            })
            .await;
        assert!(
            matches!(click_result, Err(TransportError::UrlBlocked)),
            "expected blocked-policy click to return UrlBlocked, got {click_result:?}"
        );

        // Scroll through the Action::Scroll arm: must fail AND must not have
        // scrolled.
        let scroll_result = driver.act(&Action::Scroll { x: 0.0, y: 400.0 }).await;
        assert!(
            matches!(scroll_result, Err(TransportError::UrlBlocked)),
            "expected blocked-policy scroll to return UrlBlocked, got {scroll_result:?}"
        );

        // Quiescence loop guard, called directly so the assertion is scoped
        // to the loop's own check rather than act_batch's post-quiescence
        // observation guard.
        let quiescence_result = driver.wait_for_composite_quiescence().await;
        assert!(
            matches!(quiescence_result, Err(TransportError::UrlBlocked)),
            "expected blocked-policy quiescence poll to return UrlBlocked, got {quiescence_result:?}"
        );

        // Re-widen the policy so the probes themselves may be read; the page
        // was never navigated away, so any side effect the blocked attempts
        // leaked is still observable here.
        driver = driver.with_url_policy(UrlPolicy::allow_all());
        assert_eq!(
            driver
                .evaluate_script(
                    "Promise.resolve(document.body.dataset.clicked ?? 'unset')",
                    true
                )
                .await?,
            serde_json::json!("unset"),
            "blocked-policy click still landed on the page: with_element's own \
             URL-policy guard did not fire before the click"
        );
        let blocked_scroll_y = driver
            .evaluate_script("Promise.resolve(window.scrollY)", true)
            .await?;
        assert_eq!(
            blocked_scroll_y.as_f64(),
            Some(0.0),
            "blocked-policy scroll still moved the page: Action::Scroll's own \
             URL-policy guard did not fire before window.scrollTo"
        );

        // Allow-case control: the same probes fire once the policy permits,
        // proving the negative assertions above are not vacuous.
        assert!(matches!(
            driver.act(&Action::Click { node: save_node }).await?,
            StepOutcome::Applied { .. }
        ));
        assert_eq!(
            driver
                .evaluate_script(
                    "Promise.resolve(document.body.dataset.clicked ?? 'unset')",
                    true
                )
                .await?,
            serde_json::json!("yes")
        );
        assert!(matches!(
            driver.act(&Action::Scroll { x: 0.0, y: 400.0 }).await?,
            StepOutcome::Applied { .. }
        ));
        let allowed_scroll_y = driver
            .evaluate_script("Promise.resolve(window.scrollY)", true)
            .await?;
        assert!(
            allowed_scroll_y.as_f64().unwrap_or_default() > 0.0,
            "allow-case scroll control did not move the page; the scroll probe is broken"
        );

        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_driver_navigates_observes_acts_and_screenshots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        let observation = driver.goto(&url).await?;
        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        let save = observation
            .elements
            .iter()
            .find(|element| {
                element.role == "button"
                    && element.name.first().map(|span| span.text.as_str()) == Some("Save")
            })
            .ok_or_else(|| std::io::Error::other("missing save button"))?;
        let save_node = save.node_id.clone();
        assert!(save_node.0.starts_with("node:"));
        let email = observation
            .elements
            .iter()
            .find(|element| element.role == "textbox")
            .ok_or_else(|| std::io::Error::other("missing email input"))?;
        let email_name = email
            .name
            .first()
            .ok_or_else(|| std::io::Error::other("missing email accessible name"))?;
        let email_value = email
            .value
            .first()
            .ok_or_else(|| std::io::Error::other("missing email value"))?;
        assert_eq!(email.role, "textbox");
        assert_eq!(email_name.text, "Email Address");
        assert_eq!(email_value.text, "me@example.com");

        let extracted = driver.extract(&save_node).await?;
        assert_eq!(extracted["selector"], "[id=\"save\"]");
        assert_eq!(extracted["found"], true);
        assert_eq!(extracted["node"]["tag"], "button");
        assert_eq!(extracted["node"]["role"], "button");
        assert_eq!(extracted["node"]["name"], "Save");
        assert_eq!(extracted["node"]["attributes"]["id"], "save");

        let outcome = driver.act(&Action::Click { node: save_node }).await?;
        assert!(matches!(outcome, StepOutcome::Applied { .. }));

        let evaluated = driver
            .evaluate_script("Promise.resolve(document.body.dataset.clicked)", true)
            .await?;
        assert_eq!(evaluated, serde_json::json!("yes"));

        let screenshot = driver.screenshot().await?;
        assert!(screenshot.starts_with(b"\x89PNG\r\n\x1a\n"));

        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_stable_node_id_survives_selector_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP stable NodeId test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        let observation = driver.goto(&url).await?;
        let save_node = observation
            .elements
            .iter()
            .find(|element| {
                element.role == "button"
                    && element.name.first().map(|span| span.text.as_str()) == Some("Save")
            })
            .map(|element| element.node_id.clone())
            .ok_or_else(|| std::io::Error::other("missing save button"))?;
        assert!(save_node.0.starts_with("node:"));

        driver
            .evaluate_script(
                "(() => { document.getElementById('save').id = 'renamed-save'; return true; })()",
                false,
            )
            .await?;
        let outcome = driver.act(&Action::Click { node: save_node }).await?;
        assert!(matches!(outcome, StepOutcome::Applied { .. }));

        let clicked = driver
            .evaluate_script("Promise.resolve(document.body.dataset.clicked)", true)
            .await?;
        assert_eq!(clicked, serde_json::json!("yes"));
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_invalid_legacy_node_ids_are_step_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP invalid legacy NodeId test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        driver.goto(&url).await?;
        let bad_node = NodeId("button:message".into());

        assert_step_error(
            driver
                .act(&Action::Click {
                    node: bad_node.clone(),
                })
                .await?,
        );
        assert_step_error(
            driver
                .act(&Action::Type {
                    node: bad_node.clone(),
                    text: "secret".into(),
                })
                .await?,
        );
        assert_step_error(
            driver
                .act(&Action::Select {
                    node: bad_node.clone(),
                    value: "option".into(),
                })
                .await?,
        );
        assert_step_error(driver.act(&Action::Extract { node: bad_node }).await?);

        driver.close().await?;
        Ok(())
    }

    fn assert_step_error(outcome: StepOutcome) {
        assert!(
            matches!(outcome, StepOutcome::StepError { .. }),
            "expected recoverable StepError for malformed legacy NodeId, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn live_cdp_child_browsing_context_isolates_storage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP context isolation test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        driver.goto(&url).await?;
        let root_value = driver
            .evaluate_script(
                "Promise.resolve((() => { localStorage.setItem('tempoIsolation', 'root'); document.cookie = 'tempoIsolation=root; SameSite=Lax'; return localStorage.getItem('tempoIsolation'); })())",
                true,
            )
            .await?;
        assert_eq!(root_value, serde_json::json!("root"));

        let mut child = driver
            .create_browsing_context(tempo_driver::BrowsingContextCreateOptions {
                kind: tempo_driver::BrowsingContextKind::Tab,
                background: false,
            })
            .await
            .map_err(|error| std::io::Error::other(error.0))?;
        child.goto(&url).await?;
        let child_value = child
            .evaluate_script(
                "Promise.resolve(localStorage.getItem('tempoIsolation') === null ? '__missing__' : localStorage.getItem('tempoIsolation'))",
                true,
            )
            .await?;
        let child_cookie = child
            .evaluate_script("Promise.resolve(document.cookie)", true)
            .await?;

        assert_eq!(child_value, serde_json::json!("__missing__"));
        assert_eq!(child_cookie, serde_json::json!(""));

        child.close().await?;
        driver.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn live_cdp_driver_passes_conformance_v2() -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP conformance test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        tempo_driver::conformance::assert_driver_conformance_with(
            &mut driver,
            tempo_driver::conformance::ConformanceConfig::new(url)
                .with_fork(tempo_driver::conformance::ForkExpectation::Unsupported),
        )
        .await
        .map_err(std::io::Error::other)?;
        Ok(())
    }

    fn serve_fixture() -> Result<String, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        std::thread::spawn(move || {
            let body = r#"<!doctype html>
                <html>
                  <body>
                    <button id="save" onclick="document.body.dataset.clicked='yes'">
                      <span>Save</span>
                    </button>
                    <label for="email">Email Address</label>
                    <input id="email" value="me@example.com">
                  </body>
                </html>"#;
            for stream in listener.incoming().take(16) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Ok(format!("http://{addr}/"))
    }

    /// Like [`serve_fixture`] (same `dataset.clicked` click probe on the Save
    /// button) plus a tall spacer so `window.scrollTo` has room to move and
    /// `window.scrollY` doubles as a scroll-landed probe (#321).
    fn serve_click_scroll_probe_fixture() -> Result<String, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        std::thread::spawn(move || {
            let body = r#"<!doctype html>
                <html>
                  <body>
                    <button id="save" onclick="document.body.dataset.clicked='yes'">
                      <span>Save</span>
                    </button>
                    <div style="height: 4000px"></div>
                  </body>
                </html>"#;
            for stream in listener.incoming().take(16) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Ok(format!("http://{addr}/"))
    }

    struct PolicyFixture {
        origin: String,
        private_url: String,
        private_requested: Arc<AtomicBool>,
    }

    impl PolicyFixture {
        fn allowed_url(&self, path: &str) -> String {
            format!("{}{}", self.origin, path)
        }
    }

    fn serve_policy_fixture() -> Result<PolicyFixture, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let private_url = format!("http://{addr}/private");
        let private_requested = Arc::new(AtomicBool::new(false));
        let requested = private_requested.clone();
        let thread_private_url = private_url.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming().take(64) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let path = read_request_path(&mut stream).unwrap_or_default();
                let response = match path.as_str() {
                    "/page-nav" => {
                        let body = format!(
                            r#"<!doctype html><html><body><a id="go" href="{thread_private_url}">Go</a></body></html>"#
                        );
                        http_response("200 OK", "text/html", &body)
                    }
                    "/redirect-private" => {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {thread_private_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    }
                    "/private" => {
                        requested.store(true, Ordering::SeqCst);
                        http_response("200 OK", "text/plain", "private")
                    }
                    _ => http_response("200 OK", "text/plain", "ok"),
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Ok(PolicyFixture {
            origin: format!("http://{addr}"),
            private_url,
            private_requested,
        })
    }

    fn http_response(status: &str, content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn read_request_path(stream: &mut StdTcpStream) -> Result<String, std::io::Error> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        let first_line = request.lines().next().unwrap_or_default();
        Ok(first_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string())
    }

    fn sample_element(id: &str, rank: f32) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(id.to_string()),
            role: "button".into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: "orig".into(),
            }],
            value: Vec::new(),
            bounds: None,
            rank,
        }
    }

    fn enriched_summary() -> AxSummary {
        AxSummary {
            role: None,
            name: Some("enriched".to_string()),
            value: None,
        }
    }

    #[test]
    fn top_ranked_indices_picks_highest_ranks_in_document_order() {
        let elements = vec![
            sample_element("#a", 0.1),
            sample_element("#b", 0.9),
            sample_element("#c", 0.9),
            sample_element("#d", 0.5),
            sample_element("#e", 0.9),
        ];
        // Cap of 2: the two highest ranks are the three 0.9s; ties break by
        // document order, so indices 1 and 2 win and are returned in order.
        assert_eq!(top_ranked_indices(&elements, 2), vec![1, 2]);
        // A cap at/above the length keeps every index in document order.
        assert_eq!(top_ranked_indices(&elements, 16), vec![0, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn enrichment_is_bounded_to_the_top_ranked_cap() -> Result<(), TransportError> {
        // A large interactive-element list (as a hostile page could produce):
        // a low-rank bulk up front and a higher-rank tail at the END of the
        // document. A first-N cap would enrich the bulk; the rank-aware cap must
        // enrich the tail instead, and must issue at most `cap` AX lookups.
        let total = 5000usize;
        let high_rank_start = total - 20; // indices 4980..=4999 carry the high rank
        let mut elements: Vec<InteractiveElement> = (0..total)
            .map(|i| {
                let rank = if i >= high_rank_start { 0.9 } else { 0.1 };
                sample_element(&format!("#el{i}"), rank)
            })
            .collect();

        let mut calls: Vec<String> = Vec::new();
        enrich_elements(&mut elements, MAX_AX_ENRICHED_ELEMENTS, |node_id| {
            calls.push(node_id.0);
            async move { Ok::<_, TransportError>(Some(enriched_summary())) }
        })
        .await?;

        // The expensive AX round-trips are bounded by the cap, not the 5000
        // elements the page exposed.
        assert_eq!(calls.len(), MAX_AX_ENRICHED_ELEMENTS);
        // The enriched set is exactly the highest-ranked elements (the front of
        // the high-rank tail), in document order — proving the cap is rank-aware
        // rather than "first N in the list".
        let expected: Vec<String> = (high_rank_start..high_rank_start + MAX_AX_ENRICHED_ELEMENTS)
            .map(|i| format!("#el{i}"))
            .collect();
        assert_eq!(calls, expected);

        // The low-rank bulk at the front is left present but un-enriched.
        assert_eq!(elements[0].name[0].text, "orig");
        // A high-rank element inside the cap is enriched.
        assert_eq!(elements[high_rank_start].name[0].text, "enriched");
        // A high-rank element just beyond the cap is still present, un-enriched.
        assert_eq!(
            elements[high_rank_start + MAX_AX_ENRICHED_ELEMENTS].name[0].text,
            "orig"
        );
        // Nothing is dropped from the observation.
        assert_eq!(elements.len(), total);
        Ok(())
    }

    #[tokio::test]
    async fn enrichment_covers_all_elements_below_the_cap() -> Result<(), TransportError> {
        let mut elements = vec![
            sample_element("#a", 0.5),
            sample_element("#b", 0.9),
            sample_element("#c", 0.8),
            sample_element("#d", 1.0),
            sample_element("#e", 0.2),
        ];
        let element_count = elements.len();

        let mut calls = 0usize;
        enrich_elements(
            &mut elements,
            MAX_AX_ENRICHED_ELEMENTS,
            |_node_id: NodeId| {
                calls += 1;
                async move { Ok::<_, TransportError>(Some(enriched_summary())) }
            },
        )
        .await?;

        // Under the cap, every element is enriched exactly once.
        assert_eq!(calls, element_count);
        assert!(elements
            .iter()
            .all(|element| element.name[0].text == "enriched"));
        Ok(())
    }

    #[tokio::test]
    async fn enrichment_lookups_run_concurrently_within_the_cap() -> Result<(), TransportError> {
        let mut elements = vec![
            sample_element("#a", 0.5),
            sample_element("#b", 0.9),
            sample_element("#c", 0.8),
            sample_element("#d", 1.0),
        ];
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        enrich_elements(&mut elements, MAX_AX_ENRICHED_ELEMENTS, {
            let in_flight = in_flight.clone();
            let max_in_flight = max_in_flight.clone();
            move |_node_id: NodeId| {
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                async move {
                    let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, TransportError>(Some(enriched_summary()))
                }
            }
        })
        .await?;

        assert!(
            max_in_flight.load(Ordering::SeqCst) > 1,
            "AX enrichment lookups were still serialized"
        );
        assert!(elements
            .iter()
            .all(|element| element.name[0].text == "enriched"));
        Ok(())
    }

    fn test_ax_value(r#type: AxValueType, value: serde_json::Value) -> AxValue {
        AxValue {
            r#type,
            value: Some(value),
            related_nodes: None,
            sources: None,
        }
    }
}
