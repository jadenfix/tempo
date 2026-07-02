//! tempo-engine-cdp — compat fallback lane: adapts Chromium CDP to DriverTrait v2.
//!
//! This crate is the real CDP fallback lane. It launches a headless
//! Chromium-family browser through `chromiumoxide` and adapts it to tempo's C3
//! driver contract. NodeIds in this lane are stable CSS selectors compiled from
//! the live page DOM.

use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig, HeadlessMode};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use chromiumoxide::error::CdpError;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tempo_driver::{DriverTrait, Engine, StepOutcome, TransportError, Unsupported};
use tempo_schema::{
    Action, ActionBatch, CompiledObservation, InteractiveElement, NodeId, ObservationDiff,
    Provenance, QuiescencePolicy, TaintSpan,
};
use tokio::task::JoinHandle;

/// Launch configuration for the CDP fallback lane.
#[derive(Clone, Debug)]
pub struct CdpConfig {
    /// Explicit path to a Chrome/Chromium binary. When unset, chromiumoxide
    /// tries its platform auto-detection.
    pub executable: Option<String>,
    /// Run Chrome with `--no-sandbox`, which is required in many CI containers.
    pub no_sandbox: bool,
    /// How long to wait for the browser process to expose DevTools.
    pub launch_timeout: Duration,
}

impl CdpConfig {
    pub fn with_executable(mut self, path: impl Into<String>) -> Self {
        self.executable = Some(path.into());
        self
    }

    fn browser_config(&self) -> Result<BrowserConfig, TransportError> {
        let mut builder = BrowserConfig::builder()
            .headless_mode(HeadlessMode::New)
            .launch_timeout(self.launch_timeout);
        if self.no_sandbox {
            builder = builder.no_sandbox();
        }
        if let Some(path) = &self.executable {
            builder = builder.chrome_executable(path);
        }
        builder.build().map_err(TransportError::Other)
    }
}

impl Default for CdpConfig {
    fn default() -> Self {
        Self {
            executable: None,
            no_sandbox: true,
            launch_timeout: Duration::from_secs(20),
        }
    }
}

/// CDP-backed tempo driver. Construct it with [`CdpTempoDriver::launch`].
pub struct CdpTempoDriver {
    browser: Browser,
    page: Page,
    handler_task: JoinHandle<()>,
    seq: u64,
    history: BTreeMap<u64, CompiledObservation>,
    allow_private_networks: bool,
}

impl CdpTempoDriver {
    /// Launch a real headless Chromium-family browser.
    pub async fn launch() -> Result<Self, TransportError> {
        Self::launch_with(CdpConfig::default()).await
    }

    /// Launch a real browser with an explicit CDP configuration.
    pub async fn launch_with(config: CdpConfig) -> Result<Self, TransportError> {
        let browser_config = config.browser_config()?;
        let (browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(map_cdp_error)?;
        let handler_task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(map_cdp_error)?;

        Ok(Self {
            browser,
            page,
            handler_task,
            seq: 0,
            history: BTreeMap::new(),
            allow_private_networks: false,
        })
    }

    /// Allow loopback/private navigation for trusted live fixtures.
    pub fn allow_private_network_access(mut self) -> Self {
        self.allow_private_networks = true;
        self
    }

    fn enforce_url_policy(&self, url: &str) -> Result<(), TransportError> {
        enforce_url_policy(url, self.allow_private_networks)
    }

    async fn current_url(&self) -> Result<String, TransportError> {
        Ok(self
            .page
            .url()
            .await
            .map_err(map_cdp_error)?
            .unwrap_or_default())
    }

    async fn snapshot(&self) -> Result<(String, String), TransportError> {
        let url = self.current_url().await?;
        let dom_html = self.page.content().await.map_err(map_cdp_error)?;
        Ok((url, dom_html))
    }

    fn record_snapshot(&mut self, url: String, dom_html: String) -> CompiledObservation {
        self.seq += 1;
        let compiled = compile_observation(url, dom_html, self.seq);
        self.history.insert(compiled.seq, compiled.clone());
        compiled
    }

    async fn record_current_observation(&mut self) -> Result<CompiledObservation, TransportError> {
        let (url, dom_html) = self.snapshot().await?;
        Ok(self.record_snapshot(url, dom_html))
    }

    async fn with_element<F, Fut>(&self, selector: &str, op: F) -> Result<bool, TransportError>
    where
        F: FnOnce(chromiumoxide::Element) -> Fut,
        Fut: std::future::Future<Output = Result<(), TransportError>>,
    {
        match self.page.find_element(selector).await {
            Ok(element) => match op(element).await {
                Ok(()) => Ok(true),
                Err(TransportError::Other(message)) if is_node_not_found_msg(&message) => Ok(false),
                Err(other) => Err(other),
            },
            Err(CdpError::NotFound) => Ok(false),
            Err(error) if is_node_not_found_msg(&error.to_string()) => Ok(false),
            Err(error) => Err(map_cdp_error(error)),
        }
    }

    async fn selector_outcome(
        &mut self,
        previous_seq: u64,
        selector: &str,
        grounded: bool,
    ) -> Result<StepOutcome, TransportError> {
        let compiled = self.record_current_observation().await?;
        if grounded {
            Ok(StepOutcome::Applied {
                diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
            })
        } else {
            Ok(StepOutcome::StepError {
                reason: format!("selector not found: {selector}"),
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
                let selector = node.0.clone();
                let grounded = self
                    .with_element(&selector, |element| async move {
                        element.click().await.map_err(map_cdp_error)?;
                        Ok(())
                    })
                    .await?;
                self.selector_outcome(previous_seq, &selector, grounded)
                    .await
            }
            Action::Type { node, text } => {
                let selector = node.0.clone();
                let text = text.clone();
                let grounded = self
                    .with_element(&selector, |element| async move {
                        element.focus().await.map_err(map_cdp_error)?;
                        element.type_str(&text).await.map_err(map_cdp_error)?;
                        Ok(())
                    })
                    .await?;
                self.selector_outcome(previous_seq, &selector, grounded)
                    .await
            }
            Action::Select { node, value } => {
                let selector = node.0.clone();
                let encoded = serde_json::to_string(value)
                    .map_err(|error| TransportError::Other(error.to_string()))?;
                let grounded = self
                    .with_element(&selector, |element| async move {
                        let function = format!(
                            "function() {{ this.value = {encoded}; \
                             this.dispatchEvent(new Event('change', {{ bubbles: true }})); }}"
                        );
                        element
                            .call_js_fn(function, false)
                            .await
                            .map_err(map_cdp_error)?;
                        Ok(())
                    })
                    .await?;
                self.selector_outcome(previous_seq, &selector, grounded)
                    .await
            }
            Action::Scroll { x, y } => {
                self.page
                    .evaluate(format!("window.scrollTo({}, {});", *x as i64, *y as i64))
                    .await
                    .map_err(map_cdp_error)?;
                let compiled = self.record_current_observation().await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
                })
            }
            Action::Wait { millis } => {
                tokio::time::sleep(Duration::from_millis(*millis)).await;
                let compiled = self.record_current_observation().await?;
                Ok(StepOutcome::Applied {
                    diff: diff_from_base(self.history.get(&previous_seq), &compiled, previous_seq),
                })
            }
            Action::Extract { node } => {
                let selector = node.0.clone();
                let grounded = self
                    .with_element(&selector, |_element| async move { Ok(()) })
                    .await?;
                self.selector_outcome(previous_seq, &selector, grounded)
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
            let ready_state = self
                .page
                .evaluate("document.readyState")
                .await
                .map_err(map_cdp_error)?
                .into_value::<String>()
                .map_err(|error| TransportError::Other(error.to_string()))?;
            let dom_html = self.page.content().await.map_err(map_cdp_error)?;
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

impl Drop for CdpTempoDriver {
    fn drop(&mut self) {
        self.handler_task.abort();
    }
}

#[async_trait]
impl DriverTrait for CdpTempoDriver {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    async fn goto(&mut self, url: &str) -> Result<CompiledObservation, TransportError> {
        self.enforce_url_policy(url)?;
        self.page
            .goto(url)
            .await
            .map_err(|error| TransportError::Other(error.to_string()))?;
        self.page
            .wait_for_navigation()
            .await
            .map_err(|error| TransportError::Other(error.to_string()))?;
        let (_, dom_html) = self.snapshot().await?;
        Ok(self.record_snapshot(url.to_string(), dom_html))
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
                tokio::time::sleep(Duration::from_millis(millis)).await;
                let compiled = self.record_current_observation().await?;
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

    async fn extract(&mut self, node: &NodeId) -> Result<serde_json::Value, TransportError> {
        self.page
            .evaluate(extraction_script(&node.0)?)
            .await
            .map_err(map_cdp_error)?
            .into_value::<serde_json::Value>()
            .map_err(|error| TransportError::Other(error.to_string()))
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
        self.page
            .evaluate(params)
            .await
            .map_err(map_cdp_error)?
            .into_value::<serde_json::Value>()
            .map_err(|error| TransportError::Other(error.to_string()))
    }

    async fn screenshot(&mut self) -> Result<Vec<u8>, TransportError> {
        let params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build();
        self.page.screenshot(params).await.map_err(map_cdp_error)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.browser.close().await.map_err(map_cdp_error)?;
        let _ = self.browser.wait().await;
        self.handler_task.abort();
        Ok(())
    }
}

fn map_cdp_error(error: CdpError) -> TransportError {
    TransportError::Other(error.to_string())
}

fn is_node_not_found_msg(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("could not find node") || lowered.contains("no node with given id")
}

fn enforce_url_policy(url: &str, allow_private_networks: bool) -> Result<(), TransportError> {
    if allow_private_networks {
        return Ok(());
    }

    let parsed = url::Url::parse(url)
        .map_err(|error| TransportError::Other(format!("invalid URL: {error}")))?;
    if matches!(parsed.scheme(), "file" | "ftp") {
        return Err(TransportError::UrlBlocked);
    }
    // Use the typed `Host` enum rather than `host_str()`. For IPv6 literals
    // `host_str()` returns the bracketed form (e.g. `"[::1]"`) which never
    // parses as an `IpAddr`, so IPv6 loopback / ULA / link-local and
    // IPv4-mapped metadata targets (`[::ffff:169.254.169.254]`) would slip
    // through the guard entirely (issue #81).
    match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            if domain
                .trim_end_matches('.')
                .eq_ignore_ascii_case("localhost")
            {
                return Err(TransportError::UrlBlocked);
            }
        }
        Some(url::Host::Ipv4(ip)) => {
            if is_blocked_ip(IpAddr::V4(ip)) {
                return Err(TransportError::UrlBlocked);
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if is_blocked_ip(IpAddr::V6(ip)) {
                return Err(TransportError::UrlBlocked);
            }
        }
        None => return Ok(()),
    }
    Ok(())
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                // Carrier-grade NAT 100.64.0.0/10.
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                // Reserved 240.0.0.0/4.
                || octets[0] >= 240
        }
        IpAddr::V6(ip) => {
            // Canonicalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to its embedded
            // IPv4 so metadata / private targets cannot be reached via the
            // mapped form.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
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

fn compile_observation(url: String, dom_html: String, seq: u64) -> CompiledObservation {
    CompiledObservation {
        schema_version: tempo_schema::SCHEMA_VERSION.into(),
        url,
        seq,
        elements: extract_interactive_elements(&dom_html),
        marks: Vec::new(),
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
            if let Some(position) = stack.iter().rposition(|frame| frame.tag == name) {
                if position > 0 {
                    stack.truncate(position);
                }
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
    if tag == "a" {
        if let Some(href) = attrs.get("href").filter(|value| !value.is_empty()) {
            return Some(format!("a[href=\"{}\"]", css_attr_escape(href)));
        }
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
    use std::io::Write;
    use std::net::TcpListener;

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
    fn blocks_private_navigation_by_default() {
        for url in [
            "http://127.0.0.1",
            "http://localhost",
            "http://10.0.0.1",
            "http://169.254.169.254/latest/meta-data",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(
                    enforce_url_policy(url, false),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        assert!(enforce_url_policy("https://example.com", false).is_ok());
        assert!(enforce_url_policy("http://127.0.0.1", true).is_ok());
    }

    #[test]
    fn blocks_ipv6_and_ipv4_mapped_navigation() {
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
                    enforce_url_policy(url, false),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
        // A global-unicast IPv6 literal is still permitted.
        assert!(enforce_url_policy("http://[2606:4700:4700::1111]/", false).is_ok());
    }

    #[test]
    fn blocks_cgnat_and_reserved_ipv4_navigation() {
        // Issue #82 parity in the CDP guard.
        for url in ["http://100.64.0.1/", "http://240.0.0.1/"] {
            assert!(
                matches!(
                    enforce_url_policy(url, false),
                    Err(TransportError::UrlBlocked)
                ),
                "expected URL policy block for {url}"
            );
        }
    }

    #[tokio::test]
    async fn live_cdp_driver_navigates_observes_acts_and_screenshots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default().with_executable(chrome.to_string_lossy());
        let mut driver = CdpTempoDriver::launch_with(config)
            .await?
            .allow_private_network_access();

        let observation = driver.goto(&url).await?;
        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        assert!(observation
            .elements
            .iter()
            .any(|element| element.node_id == NodeId("[id=\"save\"]".into())));

        let extracted = driver.extract(&NodeId("[id=\"save\"]".into())).await?;
        assert_eq!(extracted["selector"], "[id=\"save\"]");
        assert_eq!(extracted["found"], true);
        assert_eq!(extracted["node"]["tag"], "button");
        assert_eq!(extracted["node"]["role"], "button");
        assert_eq!(extracted["node"]["name"], "Save");
        assert_eq!(extracted["node"]["attributes"]["id"], "save");

        let outcome = driver
            .act(&Action::Click {
                node: NodeId("[id=\"save\"]".into()),
            })
            .await?;
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
    async fn live_cdp_driver_passes_conformance_v2() -> Result<(), Box<dyn std::error::Error>> {
        let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
            eprintln!("skipping live CDP conformance test; TEMPO_CDP_CHROME is unset");
            return Ok(());
        };
        let url = serve_fixture()?;
        let config = CdpConfig::default().with_executable(chrome.to_string_lossy());
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
}
