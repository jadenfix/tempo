//! tempo-observe - engine-agnostic observation compiler core.
//!
//! This crate owns the WS4 observation spine from `final.md`: stable NodeIds,
//! interactive-element ranking, changed-subtree diffs, set-of-marks metadata,
//! and token/byte budgeting. Live Servo/CDP adapters feed raw nodes into this
//! pure compiler; tests exercise the same path with AccessKit-style fixtures.

use std::collections::{HashMap, HashSet};

use tempo_schema::{
    CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
};

/// Default serialized observation budget from `final.md` section 8.
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024;

/// Approximate token budget from `final.md` section 8.
pub const DEFAULT_MAX_TOKENS: usize = 1_500;

/// Default number of ranked elements that receive set-of-marks labels.
pub const DEFAULT_MAX_MARKS: usize = 16;

/// Compiler controls for observation size and set-of-marks output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileOptions {
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub max_marks: usize,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: DEFAULT_MAX_MARKS,
        }
    }
}

/// One raw interactive candidate emitted by an engine adapter or recorded fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct RawElement {
    pub source_id: Option<String>,
    pub stable_hint: Option<String>,
    pub role: String,
    pub name: Vec<TaintSpan>,
    pub value: Vec<TaintSpan>,
    pub bounds: Option<[f32; 4]>,
    pub visible: bool,
    pub enabled: bool,
    pub interactive: bool,
}

impl RawElement {
    /// Construct a visible, enabled, page-derived interactive candidate.
    pub fn new(role: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            source_id: None,
            stable_hint: None,
            role: role.into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: name.into(),
            }],
            value: Vec::new(),
            bounds: None,
            visible: true,
            enabled: true,
            interactive: true,
        }
    }

    pub fn source_id(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into());
        self
    }

    pub fn stable_hint(mut self, stable_hint: impl Into<String>) -> Self {
        self.stable_hint = Some(stable_hint.into());
        self
    }

    pub fn name_spans(mut self, name: Vec<TaintSpan>) -> Self {
        self.name = name;
        self
    }

    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = vec![TaintSpan {
            provenance: Provenance::Page,
            text: value.into(),
        }];
        self
    }

    pub fn value_spans(mut self, value: Vec<TaintSpan>) -> Self {
        self.value = value;
        self
    }

    pub fn bounds(mut self, bounds: [f32; 4]) -> Self {
        self.bounds = Some(bounds);
        self
    }

    pub fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    fn source_key(&self) -> Option<String> {
        self.source_id.as_ref().map(|id| format!("source:{id}"))
    }

    fn fingerprint_key(&self) -> String {
        if let Some(stable_hint) = &self.stable_hint {
            return format!("hint:{}", normalize(stable_hint));
        }

        format!(
            "fp:role={};name={};value={}",
            normalize(&self.role),
            normalize(&span_text(&self.name)),
            normalize(&span_text(&self.value))
        )
    }

    fn allocation_key(&self) -> String {
        self.stable_hint
            .as_ref()
            .map(|hint| format!("hint:{}", normalize(hint)))
            .or_else(|| self.source_key())
            .unwrap_or_else(|| self.fingerprint_key())
    }
}

/// Raw observation input for one page snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservationInput {
    pub url: String,
    pub elements: Vec<RawElement>,
}

impl ObservationInput {
    pub fn new(url: impl Into<String>, elements: Vec<RawElement>) -> Self {
        Self {
            url: url.into(),
            elements,
        }
    }
}

/// Stateful compiler. The mapper remembers identities across snapshots so NodeIds
/// survive relayout, reorder, and re-render when either engine IDs or stable DOM
/// hints/fingerprints line up.
#[derive(Debug, Default)]
pub struct ObservationCompiler {
    seq: u64,
    mapper: StableIdMapper,
    options: CompileOptions,
}

impl ObservationCompiler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: CompileOptions) -> Self {
        Self {
            seq: 0,
            mapper: StableIdMapper::default(),
            options,
        }
    }

    /// Compile one raw snapshot into the frozen schema observation.
    pub fn compile(&mut self, input: ObservationInput) -> CompiledObservation {
        self.seq += 1;

        let mut elements: Vec<_> = input
            .elements
            .into_iter()
            .filter(|raw| raw.visible && raw.interactive)
            .map(|raw| {
                let node_id = self.mapper.node_id_for(&raw);
                let rank = rank_raw_element(&raw);
                InteractiveElement {
                    node_id,
                    role: raw.role,
                    name: raw.name,
                    value: raw.value,
                    bounds: raw.bounds,
                    rank,
                }
            })
            .collect();

        elements.sort_by(|left, right| {
            right
                .rank
                .total_cmp(&left.rank)
                .then_with(|| left.node_id.0.cmp(&right.node_id.0))
        });

        apply_budget(input.url, self.seq, elements, self.options)
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// Map source IDs and stable fingerprints to schema NodeIds.
#[derive(Debug, Default)]
pub struct StableIdMapper {
    by_source: HashMap<String, NodeId>,
    by_fingerprint: HashMap<String, NodeId>,
    allocated: HashSet<String>,
}

impl StableIdMapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_id_for(&mut self, raw: &RawElement) -> NodeId {
        if let Some(source_key) = raw.source_key() {
            if let Some(node_id) = self.by_source.get(&source_key) {
                return node_id.clone();
            }
        }

        let fingerprint = raw.fingerprint_key();
        if let Some(node_id) = self.by_fingerprint.get(&fingerprint) {
            if let Some(source_key) = raw.source_key() {
                self.by_source.insert(source_key, node_id.clone());
            }
            return node_id.clone();
        }

        let node_id = self.allocate(&raw.allocation_key());
        if let Some(source_key) = raw.source_key() {
            self.by_source.insert(source_key, node_id.clone());
        }
        self.by_fingerprint.insert(fingerprint, node_id.clone());
        node_id
    }

    fn allocate(&mut self, key: &str) -> NodeId {
        let base = format!("node:{:016x}", fnv1a64(key.as_bytes()));
        if self.allocated.insert(base.clone()) {
            return NodeId(base);
        }

        let mut suffix = 1_u64;
        loop {
            let candidate = format!("{base}-{suffix}");
            if self.allocated.insert(candidate.clone()) {
                return NodeId(candidate);
            }
            suffix += 1;
        }
    }
}

/// Deterministic ranker for interactive candidates.
pub fn rank_raw_element(raw: &RawElement) -> f32 {
    let role = raw.role.to_ascii_lowercase();
    let role_score = match role.as_str() {
        "textbox" | "searchbox" | "combobox" => 1.0,
        "button" | "menuitem" | "option" => 0.92,
        "link" => 0.78,
        "checkbox" | "radio" | "switch" | "slider" => 0.72,
        "tab" | "listbox" => 0.64,
        _ => 0.35,
    };

    let label_score = if span_text(&raw.name).trim().is_empty() {
        0.0
    } else {
        0.12
    };
    let value_score = if raw.value.is_empty() { 0.0 } else { 0.04 };
    let enabled_score = if raw.enabled { 0.04 } else { -0.20 };
    let area_score = raw.bounds.map(area_bonus).unwrap_or(0.0);

    (role_score + label_score + value_score + enabled_score + area_score).clamp(0.0, 1.25)
}

/// Build a diff between two compiled observations.
pub fn diff_observations(
    previous: &CompiledObservation,
    current: &CompiledObservation,
) -> ObservationDiff {
    let previous_by_id: HashMap<_, _> = previous
        .elements
        .iter()
        .map(|element| (element.node_id.clone(), element))
        .collect();
    let current_ids: HashSet<_> = current
        .elements
        .iter()
        .map(|element| element.node_id.clone())
        .collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for element in &current.elements {
        match previous_by_id.get(&element.node_id) {
            None => added.push(element.clone()),
            Some(previous_element) if *previous_element != element => changed.push(element.clone()),
            Some(_) => {}
        }
    }

    let removed = previous
        .elements
        .iter()
        .filter(|element| !current_ids.contains(&element.node_id))
        .map(|element| element.node_id.clone())
        .collect();

    ObservationDiff {
        since_seq: previous.seq,
        seq: current.seq,
        added,
        removed,
        changed,
    }
}

/// Serialized JSON byte length for a compiled observation.
pub fn serialized_len(observation: &CompiledObservation) -> usize {
    match serde_json::to_vec(observation) {
        Ok(bytes) => bytes.len(),
        Err(_) => usize::MAX,
    }
}

/// Coarse token estimate used for the budget gate.
pub fn estimated_tokens(observation: &CompiledObservation) -> usize {
    serialized_len(observation).div_ceil(4)
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "observation compiler: stable-ID mapper, interactive-element ranker, diff engine, set-of-marks compositor, token budgeter"
}

fn apply_budget(
    url: String,
    seq: u64,
    mut elements: Vec<InteractiveElement>,
    options: CompileOptions,
) -> CompiledObservation {
    loop {
        let observation = make_observation(&url, seq, elements.clone(), options.max_marks);
        let within_byte_budget =
            options.max_bytes == 0 || serialized_len(&observation) <= options.max_bytes;
        let within_token_budget =
            options.max_tokens == 0 || estimated_tokens(&observation) <= options.max_tokens;

        if elements.is_empty() || (within_byte_budget && within_token_budget) {
            return observation;
        }

        elements.pop();
    }
}

fn make_observation(
    url: &str,
    seq: u64,
    elements: Vec<InteractiveElement>,
    max_marks: usize,
) -> CompiledObservation {
    let marks = elements
        .iter()
        .take(max_marks)
        .enumerate()
        .map(|(index, element)| (element.node_id.clone(), (index + 1) as u32))
        .collect();

    CompiledObservation {
        schema_version: tempo_schema::SCHEMA_VERSION.into(),
        url: url.into(),
        seq,
        elements,
        marks,
    }
}

fn area_bonus(bounds: [f32; 4]) -> f32 {
    let area = (bounds[2].max(0.0) * bounds[3].max(0.0)).min(40_000.0);
    (area / 40_000.0) * 0.08
}

fn span_text(spans: &[TaintSpan]) -> String {
    let mut out = String::new();
    for span in spans {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&span.text);
    }
    out
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_span(text: &str) -> TaintSpan {
        TaintSpan {
            provenance: Provenance::Page,
            text: text.into(),
        }
    }

    fn user_span(text: &str) -> TaintSpan {
        TaintSpan {
            provenance: Provenance::User,
            text: text.into(),
        }
    }

    fn checkout_fixture() -> ObservationInput {
        ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("button", "Pay now")
                    .source_id("ax:pay")
                    .stable_hint("button#pay")
                    .bounds([320.0, 700.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email")
                    .source_id("ax:email")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([120.0, 180.0, 360.0, 38.0]),
                RawElement::new("link", "Terms")
                    .source_id("ax:terms")
                    .stable_hint("a[href=/terms]")
                    .bounds([80.0, 760.0, 80.0, 22.0]),
            ],
        )
    }

    #[test]
    fn compiles_schema_observation_with_page_taint() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(checkout_fixture());

        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        assert_eq!(observation.url, "https://shop.example/checkout");
        assert_eq!(observation.seq, 1);
        assert_eq!(observation.elements.len(), 3);
        assert!(observation
            .elements
            .iter()
            .all(|element| element.name.iter().all(TaintSpan::is_tainted)));
        assert_eq!(observation.marks.len(), 3);
    }

    #[test]
    fn stable_ids_survive_relayout_rerender_and_reorder() {
        let mut compiler = ObservationCompiler::new();
        let first = compiler.compile(checkout_fixture());

        let second = compiler.compile(ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("link", "Terms")
                    .source_id("new-terms-source")
                    .stable_hint("a[href=/terms]")
                    .bounds([88.0, 780.0, 80.0, 22.0]),
                RawElement::new("button", "Pay now")
                    .source_id("new-pay-source")
                    .stable_hint("button#pay")
                    .bounds([340.0, 720.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email")
                    .source_id("new-email-source")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([122.0, 185.0, 360.0, 38.0]),
            ],
        ));

        for first_element in &first.elements {
            let matching = second
                .elements
                .iter()
                .find(|candidate| candidate.role == first_element.role);
            assert!(
                matching
                    .map(|candidate| candidate.node_id == first_element.node_id)
                    .unwrap_or(false),
                "{first_element:?}"
            );
        }
    }

    #[test]
    fn ranker_prioritizes_form_controls_and_usable_labels() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(ObservationInput::new(
            "https://example.test",
            vec![
                RawElement::new("generic", "").stable_hint("generic"),
                RawElement::new("button", "Continue").stable_hint("continue"),
                RawElement::new("textbox", "Search")
                    .stable_hint("search")
                    .bounds([0.0, 0.0, 300.0, 32.0]),
            ],
        ));

        assert_eq!(observation.elements[0].role, "textbox");
        assert!(observation.elements[0].rank > observation.elements[1].rank);
        assert!(observation.elements[1].rank > observation.elements[2].rank);
    }

    #[test]
    fn diff_reports_only_added_removed_and_changed_elements() {
        let mut compiler = ObservationCompiler::new();
        let previous = compiler.compile(checkout_fixture());
        let current = compiler.compile(ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("button", "Pay now")
                    .source_id("ax:pay")
                    .stable_hint("button#pay")
                    .bounds([320.0, 700.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email address")
                    .source_id("ax:email")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([120.0, 180.0, 360.0, 38.0]),
                RawElement::new("button", "Apply coupon")
                    .source_id("ax:coupon")
                    .stable_hint("button#coupon")
                    .bounds([120.0, 240.0, 140.0, 38.0]),
            ],
        ));

        let diff = diff_observations(&previous, &current);

        assert_eq!(diff.since_seq, previous.seq);
        assert_eq!(diff.seq, current.seq);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name[0].text, "Apply coupon");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].name[0].text, "Email address");
    }

    #[test]
    fn budgeter_keeps_high_ranked_elements_under_limit() {
        let mut elements = Vec::new();
        for index in 0..80 {
            elements.push(
                RawElement::new("link", format!("Secondary navigation item {index}"))
                    .stable_hint(format!("nav-{index}"))
                    .bounds([0.0, index as f32, 120.0, 24.0]),
            );
        }
        elements.push(
            RawElement::new("textbox", "Search entire catalog")
                .stable_hint("search")
                .bounds([0.0, 0.0, 420.0, 36.0]),
        );

        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: 1_200,
            max_tokens: 400,
            max_marks: 4,
        });
        let observation = compiler.compile(ObservationInput::new("https://example.test", elements));

        assert!(
            serialized_len(&observation) <= 1_200,
            "{}",
            serialized_len(&observation)
        );
        assert!(estimated_tokens(&observation) <= 400);
        assert_eq!(observation.elements[0].role, "textbox");
        assert!(observation.elements.len() < 81);
        assert_eq!(observation.marks.len(), 4.min(observation.elements.len()));
    }

    #[test]
    fn fixture_corpus_stays_inside_default_budget() {
        let fixtures = vec![
            checkout_fixture(),
            ObservationInput::new(
                "https://mail.example/inbox",
                (0..18)
                    .map(|index| {
                        RawElement::new("button", format!("Archive message {index}"))
                            .stable_hint(format!("archive-{index}"))
                            .bounds([20.0, 40.0 + index as f32 * 28.0, 120.0, 24.0])
                    })
                    .collect(),
            ),
            ObservationInput::new(
                "https://docs.example",
                vec![
                    RawElement::new("textbox", "Search docs").stable_hint("docs-search"),
                    RawElement::new("link", "API Reference").stable_hint("api-reference"),
                    RawElement::new("button", "Copy install command").stable_hint("copy-install"),
                ],
            ),
        ];

        let mut compiler = ObservationCompiler::new();
        for fixture in fixtures {
            let observation = compiler.compile(fixture);
            assert!(serialized_len(&observation) <= DEFAULT_MAX_BYTES);
            assert!(estimated_tokens(&observation) <= DEFAULT_MAX_TOKENS);
        }
    }

    #[test]
    fn preserves_non_page_provenance_from_inputs() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(ObservationInput::new(
            "https://example.test",
            vec![RawElement::new("textbox", "Task")
                .stable_hint("task")
                .name_spans(vec![user_span("Find invoices")])
                .value_spans(vec![page_span("Invoice table")])],
        ));

        assert_eq!(observation.elements[0].name[0].provenance, Provenance::User);
        assert_eq!(
            observation.elements[0].value[0].provenance,
            Provenance::Page
        );
    }
}
