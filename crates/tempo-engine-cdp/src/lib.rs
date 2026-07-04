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
    DescribeNodeParams, GetDocumentParams, NodeId as DomNodeId, QuerySelectorParams,
};
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, EnableParams as FetchEnableParams, EventRequestPaused,
    FailRequestParams, RequestPattern,
};
use chromiumoxide::cdp::browser_protocol::network::ErrorReason;
use chromiumoxide::cdp::browser_protocol::page::{CaptureScreenshotFormat, Viewport};
use chromiumoxide::cdp::browser_protocol::target::{
    CreateBrowserContextParams, CreateTargetParams,
};
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use chromiumoxide::error::CdpError;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
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

    async fn enforce_current_url_policy(&self) -> Result<String, TransportError> {
        let url = self.current_url().await?;
        self.enforce_current_url_policy_value(&url)?;
        Ok(url)
    }

    async fn snapshot(&self) -> Result<(String, String), TransportError> {
        let cursor = self.request_policy_cursor();
        self.snapshot_since(cursor).await
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
        Ok(compiled)
    }

    async fn record_current_observation(&mut self) -> Result<CompiledObservation, TransportError> {
        let (url, dom_html) = self.snapshot().await?;
        self.record_snapshot(url, dom_html).await
    }

    async fn record_current_observation_since(
        &mut self,
        cursor: u64,
    ) -> Result<CompiledObservation, TransportError> {
        let (url, dom_html) = self.snapshot_since(cursor).await?;
        self.record_snapshot(url, dom_html).await
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

    async fn ax_summary_for_selector(
        &self,
        root: DomNodeId,
        selector: &str,
    ) -> Result<Option<AxSummary>, TransportError> {
        self.enforce_current_url_policy().await?;
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

        let described = match page
            .execute(
                DescribeNodeParams::builder()
                    .node_id(queried.node_id)
                    .build(),
            )
            .await
        {
            Ok(response) => response.result,
            Err(error)
                if matches!(error, CdpError::NotFound)
                    || is_node_not_found_msg(&error.to_string()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(map_cdp_error(error)),
        };

        let backend_node_id = described.node.backend_node_id;
        let ax_nodes = match page
            .execute(
                GetPartialAxTreeParams::builder()
                    .backend_node_id(backend_node_id)
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
        let summaries = ax_summaries_by_backend_id(&ax_nodes);

        Ok(summaries.get(backend_node_id.inner()).cloned())
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

        loop {
            self.enforce_current_url_policy().await?;
            let cursor = self.request_policy_cursor();
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
            let sample = PageStabilitySample {
                ready: ready_state != "loading",
                dom_hash: fnv1a64(dom_html.as_bytes()),
            };
            if tracker.observe(sample) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TransportError::NavTimeout);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

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
        let goto_result = self.page()?.goto(url).await;
        self.map_cdp_result_since(cursor, goto_result).await?;
        self.enforce_no_blocked_request_soon_since(cursor).await?;
        if self.take_blocked_request()?.is_some() {
            return Err(TransportError::UrlBlocked);
        }
        let (final_url, dom_html) = self.snapshot_since(cursor).await?;
        self.record_snapshot(final_url, dom_html).await
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
        let browser_ws = self.browser.websocket_address().clone();
        let (browser, mut handler) = Browser::connect(browser_ws)
            .await
            .map_err(|_error| Unsupported("fresh CDP browsing context"))?;
        let handler_task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let browser_context_id = browser
            .create_browser_context(
                CreateBrowserContextParams::builder()
                    .dispose_on_detach(true)
                    .build(),
            )
            .await
            .map_err(|_error| {
                handler_task.abort();
                Unsupported("fresh CDP browsing context")
            })?;
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
    let event_deadline = Instant::now() + REQUEST_POLICY_EVENT_GRACE;
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
            .pattern(RequestPattern::builder().url_pattern("*").build())
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
    for index in top_ranked_indices(elements, max_enriched) {
        let Some(element) = elements.get_mut(index) else {
            continue;
        };
        let node_id = element.node_id.clone();
        if let Some(summary) = lookup(node_id).await? {
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

    let mut elements = Vec::new();
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
    let close = format!("</{tag}");
    let end_offset = html[from..].to_ascii_lowercase().find(&close)?;
    Some(strip_tags(&html[from..from + end_offset]))
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
            marks: Vec::new(),
        };
        let after = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://example.com".into(),
            seq: 2,
            elements: extract_interactive_elements(
                r#"<button id="save">Saved</button><input name="q" value="">"#,
            ),
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

    fn test_ax_value(r#type: AxValueType, value: serde_json::Value) -> AxValue {
        AxValue {
            r#type,
            value: Some(value),
            related_nodes: None,
            sources: None,
        }
    }
}
