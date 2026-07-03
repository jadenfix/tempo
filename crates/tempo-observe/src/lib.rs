//! tempo-observe - engine-agnostic observation compiler core.
//!
//! This crate owns the WS4 observation spine from `final.md`: stable NodeIds,
//! interactive-element ranking, changed-subtree diffs, set-of-marks metadata,
//! and token/byte budgeting. Live Servo/CDP adapters feed raw nodes into this
//! pure compiler; tests exercise the same path with AccessKit-style fixtures.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Cursor;

use tempo_schema::{
    CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
};

/// Default serialized observation budget from `final.md` section 8.
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024;

/// Approximate token budget from `final.md` section 8.
pub const DEFAULT_MAX_TOKENS: usize = 1_500;

/// Default number of ranked elements that receive set-of-marks labels.
pub const DEFAULT_MAX_MARKS: usize = 16;

/// Minimum snapshots needed for corpus gates to prove any cross-snapshot behavior.
pub const MIN_CORPUS_SNAPSHOTS: usize = 2;

/// Minimum repeated identities needed to claim stable-ID survival evidence.
pub const MIN_STABLE_ID_OPPORTUNITIES: usize = 1;

/// Minimum adjacent snapshot diffs needed to claim diff reconstruction evidence.
pub const MIN_DIFF_SNAPSHOTS: usize = 1;

/// Compiler controls for observation size and set-of-marks output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawElement {
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default)]
    pub stable_hint: Option<String>,
    pub role: String,
    #[serde(default)]
    pub name: Vec<TaintSpan>,
    #[serde(default)]
    pub value: Vec<TaintSpan>,
    #[serde(default)]
    pub bounds: Option<[f32; 4]>,
    #[serde(default = "default_true")]
    pub visible: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub interactive: bool,
}

fn default_true() -> bool {
    true
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// Evidence summary for a recorded observation fixture corpus.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationCorpusReport {
    pub snapshots: usize,
    pub bytes_p50: usize,
    pub bytes_p95: usize,
    pub tokens_p50: usize,
    pub tokens_p95: usize,
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub stable_id_opportunities: usize,
    pub stable_id_survivors: usize,
    pub stable_id_survival_rate: f64,
    pub diff_snapshots: usize,
    pub diff_reconstructable_snapshots: usize,
}

impl ObservationCorpusReport {
    pub fn snapshot_evidence_passed(&self) -> bool {
        self.snapshots >= MIN_CORPUS_SNAPSHOTS
    }

    pub fn budget_p50_passed(&self) -> bool {
        self.bytes_p50 <= self.max_bytes && self.tokens_p50 <= self.max_tokens
    }

    pub fn budget_p95_passed(&self) -> bool {
        self.bytes_p95 <= self.max_bytes && self.tokens_p95 <= self.max_tokens
    }

    pub fn budget_gate_passed(&self) -> bool {
        self.budget_p50_passed() && self.budget_p95_passed()
    }

    pub fn stable_id_gate_passed(&self) -> bool {
        self.stable_id_opportunities >= MIN_STABLE_ID_OPPORTUNITIES
            && self.stable_id_survival_rate >= 0.99
    }

    pub fn diff_gate_passed(&self) -> bool {
        self.diff_snapshots >= MIN_DIFF_SNAPSHOTS
            && self.diff_snapshots == self.diff_reconstructable_snapshots
    }

    pub fn final_md_gate_passed(&self) -> bool {
        self.snapshot_evidence_passed()
            && self.budget_gate_passed()
            && self.stable_id_gate_passed()
            && self.diff_gate_passed()
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
        self.compile_with_identities(input).observation
    }

    fn compile_with_identities(&mut self, input: ObservationInput) -> CompiledSnapshot {
        self.seq += 1;
        self.mapper.begin_snapshot(self.seq);

        let mut identities = Vec::new();
        let mut elements = Vec::new();
        for raw in input
            .elements
            .into_iter()
            .filter(|raw| raw.visible && raw.interactive)
        {
            let report_key = corpus_identity_key(&raw);
            let node_id = self.mapper.node_id_for(&raw);
            identities.push((report_key, node_id.clone()));
            let rank = rank_raw_element(&raw);
            elements.push(InteractiveElement {
                node_id,
                role: raw.role,
                name: raw.name,
                value: raw.value,
                bounds: raw.bounds,
                rank,
            });
        }

        self.mapper.evict_stale();

        elements.sort_by(|left, right| {
            right
                .rank
                .total_cmp(&left.rank)
                .then_with(|| left.node_id.0.cmp(&right.node_id.0))
        });

        let observation = apply_budget(input.url, self.seq, elements, self.options);
        let emitted_ids: HashSet<_> = observation
            .elements
            .iter()
            .map(|element| element.node_id.clone())
            .collect();
        identities.retain(|(_, node_id)| emitted_ids.contains(node_id));

        CompiledSnapshot {
            observation,
            identities,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

struct CompiledSnapshot {
    observation: CompiledObservation,
    identities: Vec<(String, NodeId)>,
}

/// Number of snapshots an unseen mapping is retained before eviction. Keeps the
/// mapper bounded on long-lived sessions over dynamic pages (issue #107) while
/// still surviving elements that flicker out of a few intermediate snapshots.
const RETENTION_SNAPSHOTS: u64 = 8;

/// A NodeId together with the last snapshot sequence it was observed in, used to
/// drive generation-based eviction.
#[derive(Debug, Clone)]
struct MappedId {
    node_id: NodeId,
    last_seen: u64,
}

/// Map source IDs and stable fingerprints to schema NodeIds.
///
/// Mappings are generation-stamped with the snapshot sequence they were last seen
/// in and pruned by [`StableIdMapper::evict_stale`], so the maps stay bounded
/// across a long-lived session (issue #107). Within a single snapshot, identical
/// fingerprints are disambiguated by occurrence index so distinct elements never
/// collapse onto one NodeId (issue #105).
#[derive(Debug, Default)]
pub struct StableIdMapper {
    by_source: HashMap<String, MappedId>,
    by_fingerprint: HashMap<String, MappedId>,
    allocated: HashSet<String>,
    seq: u64,
    occurrences: HashMap<String, usize>,
}

impl StableIdMapper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a new snapshot generation. Resets the per-snapshot occurrence
    /// counters used to disambiguate colliding fingerprints.
    fn begin_snapshot(&mut self, seq: u64) {
        self.seq = seq;
        self.occurrences.clear();
    }

    pub fn node_id_for(&mut self, raw: &RawElement) -> NodeId {
        let seq = self.seq;

        // Disambiguate elements that share a fingerprint within this snapshot: the
        // Nth occurrence gets its own lookup key so two genuinely distinct
        // elements never resolve to the same NodeId (issue #105).
        let base_fingerprint = raw.fingerprint_key();
        let occurrence = {
            let counter = self
                .occurrences
                .entry(base_fingerprint.clone())
                .or_insert(0);
            let current = *counter;
            *counter += 1;
            current
        };
        let fingerprint = format!("{base_fingerprint}#{occurrence}");

        if let Some(source_key) = raw.source_key()
            && let Some(entry) = self.by_source.get_mut(&source_key)
        {
            entry.last_seen = seq;
            let node_id = entry.node_id.clone();
            if let Some(entry) = self.by_fingerprint.get_mut(&fingerprint) {
                entry.last_seen = seq;
            }
            return node_id;
        }

        if let Some(entry) = self.by_fingerprint.get_mut(&fingerprint) {
            entry.last_seen = seq;
            let node_id = entry.node_id.clone();
            if let Some(source_key) = raw.source_key() {
                self.by_source.insert(
                    source_key,
                    MappedId {
                        node_id: node_id.clone(),
                        last_seen: seq,
                    },
                );
            }
            return node_id;
        }

        let node_id = self.allocate(&raw.allocation_key());
        if let Some(source_key) = raw.source_key() {
            self.by_source.insert(
                source_key,
                MappedId {
                    node_id: node_id.clone(),
                    last_seen: seq,
                },
            );
        }
        self.by_fingerprint.insert(
            fingerprint,
            MappedId {
                node_id: node_id.clone(),
                last_seen: seq,
            },
        );
        node_id
    }

    /// Drop mappings not seen within the last [`RETENTION_SNAPSHOTS`] snapshots and
    /// rebuild the allocated-id set from the survivors so it never grows without
    /// bound (issue #107).
    fn evict_stale(&mut self) {
        let seq = self.seq;
        let retained = |entry: &MappedId| seq.saturating_sub(entry.last_seen) < RETENTION_SNAPSHOTS;
        self.by_source.retain(|_, entry| retained(entry));
        self.by_fingerprint.retain(|_, entry| retained(entry));

        self.allocated.clear();
        for entry in self.by_source.values() {
            self.allocated.insert(entry.node_id.0.clone());
        }
        for entry in self.by_fingerprint.values() {
            self.allocated.insert(entry.node_id.0.clone());
        }
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

/// Compile a recorded fixture corpus and emit budget, stable-ID, and diff evidence.
pub fn observation_corpus_report(
    inputs: &[ObservationInput],
    options: CompileOptions,
) -> ObservationCorpusReport {
    let mut compiler = ObservationCompiler::with_options(options);
    let mut bytes = Vec::with_capacity(inputs.len());
    let mut tokens = Vec::with_capacity(inputs.len());
    let mut previous_observation = None;
    let mut previous_identities = HashMap::new();
    let mut stable_id_opportunities = 0usize;
    let mut stable_id_survivors = 0usize;
    let mut diff_snapshots = 0usize;
    let mut diff_reconstructable_snapshots = 0usize;

    for input in inputs.iter().cloned() {
        let snapshot = compiler.compile_with_identities(input);
        bytes.push(serialized_len(&snapshot.observation));
        tokens.push(estimated_tokens(&snapshot.observation));
        let current_identities = unique_identity_map(snapshot.identities);

        for (key, node_id) in &current_identities {
            if let Some(previous_node_id) = previous_identities.get(key) {
                stable_id_opportunities += 1;
                if previous_node_id == node_id {
                    stable_id_survivors += 1;
                }
            }
        }

        if let Some(previous) = &previous_observation {
            diff_snapshots += 1;
            let diff = diff_observations(previous, &snapshot.observation);
            if diff_reconstructs_current(previous, &snapshot.observation, &diff, options.max_marks)
            {
                diff_reconstructable_snapshots += 1;
            }
        }

        previous_identities = current_identities;
        previous_observation = Some(snapshot.observation);
    }

    ObservationCorpusReport {
        snapshots: inputs.len(),
        bytes_p50: percentile_usize(bytes.clone(), 0.50),
        bytes_p95: percentile_usize(bytes, 0.95),
        tokens_p50: percentile_usize(tokens.clone(), 0.50),
        tokens_p95: percentile_usize(tokens, 0.95),
        max_bytes: options.max_bytes,
        max_tokens: options.max_tokens,
        stable_id_opportunities,
        stable_id_survivors,
        stable_id_survival_rate: ratio(stable_id_survivors, stable_id_opportunities),
        diff_snapshots,
        diff_reconstructable_snapshots,
    }
}

fn unique_identity_map(identities: Vec<(String, NodeId)>) -> HashMap<String, NodeId> {
    let mut counts = HashMap::new();
    for (key, _) in &identities {
        *counts.entry(key.clone()).or_insert(0usize) += 1;
    }

    let mut unique = HashMap::new();
    for (key, node_id) in identities {
        if counts.get(&key).copied() == Some(1) {
            unique.insert(key, node_id);
        }
    }
    unique
}

fn diff_reconstructs_current(
    previous: &CompiledObservation,
    current: &CompiledObservation,
    diff: &ObservationDiff,
    max_marks: usize,
) -> bool {
    if diff.since_seq != previous.seq || diff.seq != current.seq {
        return false;
    }
    if previous.schema_version != current.schema_version || previous.url != current.url {
        return false;
    }

    let removed_ids: HashSet<_> = diff.removed.iter().cloned().collect();
    if removed_ids.len() != diff.removed.len() {
        return false;
    }
    let mut elements = previous.elements.clone();
    let previous_len = elements.len();
    elements.retain(|element| !removed_ids.contains(&element.node_id));
    if previous_len.saturating_sub(elements.len()) != removed_ids.len() {
        return false;
    }

    let mut changed_ids = HashSet::new();
    for changed in &diff.changed {
        if !changed_ids.insert(changed.node_id.clone()) {
            return false;
        }
        let Some(slot) = elements
            .iter_mut()
            .find(|element| element.node_id == changed.node_id)
        else {
            return false;
        };
        *slot = changed.clone();
    }

    let mut ids: HashSet<_> = elements
        .iter()
        .map(|element| element.node_id.clone())
        .collect();
    if ids.len() != elements.len() {
        return false;
    }
    for added in &diff.added {
        if !ids.insert(added.node_id.clone()) {
            return false;
        }
        elements.push(added.clone());
    }

    let reconstructed = make_observation(&previous.url, diff.seq, elements, max_marks);
    serialized_observations_equal(&reconstructed, current)
}

fn corpus_identity_key(raw: &RawElement) -> String {
    if let Some(stable_hint) = &raw.stable_hint {
        return format!("hint:{}", normalize(stable_hint));
    }
    raw.source_key().unwrap_or_else(|| raw.fingerprint_key())
}

/// Errors returned by the set-of-marks bitmap compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkCompositorError {
    InvalidDimensions { width: u32, height: u32 },
    InvalidBufferLength { expected: usize, actual: usize },
    PngDecode(String),
    PngEncode(String),
}

impl fmt::Display for MarkCompositorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions { width, height } => {
                write!(formatter, "invalid screenshot dimensions: {width}x{height}")
            }
            Self::InvalidBufferLength { expected, actual } => write!(
                formatter,
                "invalid RGBA screenshot buffer length: expected {expected}, got {actual}"
            ),
            Self::PngDecode(error) => write!(formatter, "failed to decode PNG screenshot: {error}"),
            Self::PngEncode(error) => write!(formatter, "failed to encode PNG screenshot: {error}"),
        }
    }
}

impl std::error::Error for MarkCompositorError {}

/// Composite set-of-marks labels and bounds onto a PNG screenshot.
///
/// Driver screenshots are exposed as PNG bytes, while engines and tests may use
/// raw RGBA buffers internally. This helper decodes the PNG, applies the same
/// compositor as [`composite_set_of_marks_rgba`], then returns a PNG suitable for
/// MCP/BiDi screenshot surfaces.
pub fn composite_set_of_marks_png(
    screenshot_png: &[u8],
    observation: &CompiledObservation,
) -> Result<Vec<u8>, MarkCompositorError> {
    let decoded = decode_png_to_rgba(screenshot_png)?;
    let composited =
        composite_set_of_marks_rgba(&decoded.rgba, decoded.width, decoded.height, observation)?;
    encode_rgba_png(&composited, decoded.width, decoded.height)
}

/// Composite set-of-marks labels and bounds onto a raw RGBA screenshot.
///
/// The compositor uses the observation's `marks` list as the source of truth and
/// draws only elements that still have concrete bounds. Coordinates are clipped to
/// the screenshot so partially-visible elements still receive usable marks.
pub fn composite_set_of_marks_rgba(
    screenshot_rgba: &[u8],
    width: u32,
    height: u32,
    observation: &CompiledObservation,
) -> Result<Vec<u8>, MarkCompositorError> {
    let expected = rgba_len(width, height)?;
    if screenshot_rgba.len() != expected {
        return Err(MarkCompositorError::InvalidBufferLength {
            expected,
            actual: screenshot_rgba.len(),
        });
    }

    let mut output = screenshot_rgba.to_vec();
    let mut canvas = RgbaCanvas {
        pixels: &mut output,
        width,
        height,
    };
    for (node_id, label) in &observation.marks {
        let Some(element) = observation
            .elements
            .iter()
            .find(|candidate| candidate.node_id == *node_id)
        else {
            continue;
        };
        let Some(bounds) = element.bounds else {
            continue;
        };
        draw_mark(&mut canvas, bounds, *label);
    }
    Ok(output)
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

fn percentile_usize(mut values: Vec<usize>, percentile: f64) -> usize {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let rank = (percentile * values.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(values.len() - 1);
    values[index]
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn serialized_observations_equal(left: &CompiledObservation, right: &CompiledObservation) -> bool {
    let Ok(left) = serde_json::to_vec(left) else {
        return false;
    };
    let Ok(right) = serde_json::to_vec(right) else {
        return false;
    };
    left == right
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "observation compiler: stable-ID mapper, interactive-element ranker, diff engine, set-of-marks compositor, token budgeter"
}

fn apply_budget(
    url: String,
    seq: u64,
    elements: Vec<InteractiveElement>,
    options: CompileOptions,
) -> CompiledObservation {
    // Elements are pre-sorted by rank descending, so the kept set is always a
    // prefix and serialized size grows monotonically with prefix length. Rather
    // than re-serializing after popping one element at a time (O(n^2), issue
    // #106), binary-search for the longest prefix that fits the budget: O(log n)
    // serializations, each computed once and reused for both the byte and token
    // gate.
    let full = make_observation(&url, seq, elements.clone(), options.max_marks);
    if elements.is_empty() || within_budget(&full, &options) {
        return full;
    }

    // Invariant: prefix of length `hi` is known not to fit; `lo` tracks the
    // longest prefix confirmed to fit (0 as a fallback when nothing fits).
    let mut lo = 0usize;
    let mut hi = elements.len();
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        let candidate = make_observation(&url, seq, elements[..mid].to_vec(), options.max_marks);
        if within_budget(&candidate, &options) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    make_observation(&url, seq, elements[..lo].to_vec(), options.max_marks)
}

/// Whether a compiled observation fits both the byte and token budgets, computing
/// the serialized length exactly once (previously serialized twice per gate).
fn within_budget(observation: &CompiledObservation, options: &CompileOptions) -> bool {
    let serialized = serialized_len(observation);
    let within_bytes = options.max_bytes == 0 || serialized <= options.max_bytes;
    let within_tokens = options.max_tokens == 0 || serialized.div_ceil(4) <= options.max_tokens;
    within_bytes && within_tokens
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

fn rgba_len(width: u32, height: u32) -> Result<usize, MarkCompositorError> {
    if width == 0 || height == 0 {
        return Err(MarkCompositorError::InvalidDimensions { width, height });
    }
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(MarkCompositorError::InvalidDimensions { width, height })?;
    Ok(pixels)
}

struct DecodedRgbaImage {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

fn decode_png_to_rgba(screenshot_png: &[u8]) -> Result<DecodedRgbaImage, MarkCompositorError> {
    let mut decoder = png::Decoder::new(Cursor::new(screenshot_png));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|error| MarkCompositorError::PngDecode(error.to_string()))?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buffer)
        .map_err(|error| MarkCompositorError::PngDecode(error.to_string()))?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(MarkCompositorError::PngDecode(format!(
            "unsupported PNG bit depth after expansion: {:?}",
            info.bit_depth
        )));
    }

    let pixels = &buffer[..info.buffer_size()];
    let rgba = png_frame_to_rgba(pixels, info.width, info.height, info.color_type)?;
    Ok(DecodedRgbaImage {
        width: info.width,
        height: info.height,
        rgba,
    })
}

fn png_frame_to_rgba(
    pixels: &[u8],
    width: u32,
    height: u32,
    color_type: png::ColorType,
) -> Result<Vec<u8>, MarkCompositorError> {
    let pixel_count = rgba_len(width, height)? / 4;
    match color_type {
        png::ColorType::Rgba => {
            let expected = pixel_count * 4;
            if pixels.len() != expected {
                return Err(MarkCompositorError::PngDecode(format!(
                    "RGBA frame length mismatch: expected {expected}, got {}",
                    pixels.len()
                )));
            }
            Ok(pixels.to_vec())
        }
        png::ColorType::Rgb => {
            validate_png_frame_len(pixels, pixel_count, 3, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for chunk in pixels.chunks_exact(3) {
                rgba.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            Ok(rgba)
        }
        png::ColorType::Grayscale => {
            validate_png_frame_len(pixels, pixel_count, 1, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for gray in pixels {
                rgba.extend_from_slice(&[*gray, *gray, *gray, 255]);
            }
            Ok(rgba)
        }
        png::ColorType::GrayscaleAlpha => {
            validate_png_frame_len(pixels, pixel_count, 2, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for chunk in pixels.chunks_exact(2) {
                rgba.extend_from_slice(&[chunk[0], chunk[0], chunk[0], chunk[1]]);
            }
            Ok(rgba)
        }
        png::ColorType::Indexed => Err(MarkCompositorError::PngDecode(
            "indexed PNG frame was not expanded to RGB".into(),
        )),
    }
}

fn validate_png_frame_len(
    pixels: &[u8],
    pixel_count: usize,
    channels: usize,
    color_type: png::ColorType,
) -> Result<(), MarkCompositorError> {
    let expected = pixel_count * channels;
    if pixels.len() == expected {
        Ok(())
    } else {
        Err(MarkCompositorError::PngDecode(format!(
            "{color_type:?} frame length mismatch: expected {expected}, got {}",
            pixels.len()
        )))
    }
}

fn encode_rgba_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, MarkCompositorError> {
    let expected = rgba_len(width, height)?;
    if rgba.len() != expected {
        return Err(MarkCompositorError::InvalidBufferLength {
            expected,
            actual: rgba.len(),
        });
    }

    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
        writer
            .write_image_data(rgba)
            .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct Rect {
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
}

struct RgbaCanvas<'a> {
    pixels: &'a mut [u8],
    width: u32,
    height: u32,
}

impl RgbaCanvas<'_> {
    fn draw_rect_outline(&mut self, rect: Rect, thickness: u32, color: [u8; 4]) {
        let x1 = rect.x1.min(self.width);
        let y1 = rect.y1.min(self.height);
        for offset in 0..thickness {
            let left = rect.x0.saturating_add(offset);
            let top = rect.y0.saturating_add(offset);
            if left >= x1 || top >= y1 {
                break;
            }
            self.draw_horizontal_line(rect.x0, x1, top, color);
            let bottom = y1.saturating_sub(offset + 1);
            self.draw_horizontal_line(rect.x0, x1, bottom, color);
            self.draw_vertical_line(left, rect.y0, y1, color);
            let right = x1.saturating_sub(offset + 1);
            self.draw_vertical_line(right, rect.y0, y1, color);
        }
    }

    fn draw_horizontal_line(&mut self, x0: u32, x1: u32, y: u32, color: [u8; 4]) {
        if y >= self.height {
            return;
        }
        for x in x0.min(self.width)..x1.min(self.width) {
            self.blend_pixel(x, y, color);
        }
    }

    fn draw_vertical_line(&mut self, x: u32, y0: u32, y1: u32, color: [u8; 4]) {
        if x >= self.width {
            return;
        }
        for y in y0.min(self.height)..y1.min(self.height) {
            self.blend_pixel(x, y, color);
        }
    }

    fn draw_label_badge(&mut self, x: u32, y: u32, label: u32, colors: MarkColors) {
        let label = label.to_string();
        let digit_count = label.chars().filter(|ch| ch.is_ascii_digit()).count() as u32;
        if digit_count == 0 {
            return;
        }
        let scale = 2;
        let padding = 2;
        let digit_width = 3 * scale;
        let digit_height = 5 * scale;
        let spacing = scale;
        let badge_width =
            padding * 2 + digit_count * digit_width + digit_count.saturating_sub(1) * spacing;
        let badge_height = padding * 2 + digit_height;
        self.fill_rect(
            Rect {
                x0: x,
                y0: y,
                x1: x.saturating_add(badge_width),
                y1: y.saturating_add(badge_height),
            },
            colors.badge,
        );

        let mut cursor = x.saturating_add(padding);
        let digit_y = y.saturating_add(padding);
        for ch in label.chars() {
            let Some(bitmap) = digit_bitmap(ch) else {
                continue;
            };
            self.draw_digit(cursor, digit_y, scale, bitmap, colors.text);
            cursor = cursor.saturating_add(digit_width + spacing);
        }
    }

    fn fill_rect(&mut self, rect: Rect, color: [u8; 4]) {
        for y in rect.y0.min(self.height)..rect.y1.min(self.height) {
            for x in rect.x0.min(self.width)..rect.x1.min(self.width) {
                self.blend_pixel(x, y, color);
            }
        }
    }

    fn draw_digit(&mut self, x0: u32, y0: u32, scale: u32, bitmap: [u8; 15], color: [u8; 4]) {
        for row in 0..5 {
            for column in 0..3 {
                if bitmap[row * 3 + column] == 0 {
                    continue;
                }
                let x = x0.saturating_add(column as u32 * scale);
                let y = y0.saturating_add(row as u32 * scale);
                self.fill_rect(
                    Rect {
                        x0: x,
                        y0: y,
                        x1: x.saturating_add(scale),
                        y1: y.saturating_add(scale),
                    },
                    color,
                );
            }
        }
    }

    fn blend_pixel(&mut self, x: u32, y: u32, color: [u8; 4]) {
        let index = ((y as usize * self.width as usize) + x as usize) * 4;
        if index + 3 >= self.pixels.len() {
            return;
        }
        let alpha = u16::from(color[3]);
        let inverse = 255_u16.saturating_sub(alpha);
        for (channel, src) in color.iter().take(3).enumerate() {
            let src = u16::from(*src);
            let dst = u16::from(self.pixels[index + channel]);
            self.pixels[index + channel] = ((src * alpha + dst * inverse + 127) / 255) as u8;
        }
        self.pixels[index + 3] = self.pixels[index + 3].max(color[3]);
    }
}

#[derive(Clone, Copy)]
struct MarkColors {
    badge: [u8; 4],
    text: [u8; 4],
}

fn draw_mark(canvas: &mut RgbaCanvas<'_>, bounds: [f32; 4], label: u32) {
    let x0 = clamp_floor(bounds[0], canvas.width);
    let y0 = clamp_floor(bounds[1], canvas.height);
    let x1 = clamp_ceil(bounds[0] + bounds[2], canvas.width);
    let y1 = clamp_ceil(bounds[1] + bounds[3], canvas.height);
    if x1 <= x0 || y1 <= y0 {
        return;
    }

    let border = [255, 42, 42, 255];
    let colors = MarkColors {
        badge: [255, 42, 42, 230],
        text: [255, 255, 255, 255],
    };
    canvas.draw_rect_outline(Rect { x0, y0, x1, y1 }, 2, border);
    canvas.draw_label_badge(x0, y0, label, colors);
}

fn clamp_floor(value: f32, upper: u32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.floor().min(upper as f32) as u32
    }
}

fn clamp_ceil(value: f32, upper: u32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.ceil().min(upper as f32) as u32
    }
}

fn digit_bitmap(ch: char) -> Option<[u8; 15]> {
    match ch {
        '0' => Some([1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1]),
        '1' => Some([0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1]),
        '2' => Some([1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1]),
        '3' => Some([1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        '4' => Some([1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1]),
        '5' => Some([1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        '6' => Some([1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1]),
        '7' => Some([1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0]),
        '8' => Some([1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1]),
        '9' => Some([1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        _ => None,
    }
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

    fn test_element(node_id: &str, role: &str, rank: f32) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(node_id.into()),
            role: role.into(),
            name: vec![page_span(node_id)],
            value: Vec::new(),
            bounds: Some([0.0, 0.0, 10.0, 10.0]),
            rank,
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

    fn checkout_relayout_fixture() -> ObservationInput {
        ObservationInput::new(
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
        )
    }

    fn checkout_mutation_fixture() -> ObservationInput {
        ObservationInput::new(
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
    fn corpus_report_measures_budget_stable_ids_and_diffs() {
        let fixtures = vec![
            checkout_fixture(),
            checkout_relayout_fixture(),
            checkout_mutation_fixture(),
        ];

        let report = observation_corpus_report(&fixtures, CompileOptions::default());

        assert_eq!(report.snapshots, 3);
        assert!(
            report.bytes_p50 <= DEFAULT_MAX_BYTES,
            "{}",
            report.bytes_p50
        );
        assert!(
            report.tokens_p50 <= DEFAULT_MAX_TOKENS,
            "{}",
            report.tokens_p50
        );
        assert!(
            report.bytes_p95 <= DEFAULT_MAX_BYTES,
            "{}",
            report.bytes_p95
        );
        assert!(
            report.tokens_p95 <= DEFAULT_MAX_TOKENS,
            "{}",
            report.tokens_p95
        );
        assert_eq!(report.stable_id_opportunities, 5);
        assert_eq!(report.stable_id_survivors, 5);
        assert_eq!(report.stable_id_survival_rate, 1.0);
        assert_eq!(report.diff_snapshots, 2);
        assert_eq!(report.diff_reconstructable_snapshots, 2);
        assert!(report.final_md_gate_passed());
    }

    #[test]
    fn corpus_report_requires_cross_snapshot_evidence() {
        let empty = observation_corpus_report(&[], CompileOptions::default());
        assert!(!empty.snapshot_evidence_passed());
        assert!(!empty.stable_id_gate_passed());
        assert!(!empty.diff_gate_passed());
        assert!(!empty.final_md_gate_passed());

        let single = observation_corpus_report(&[checkout_fixture()], CompileOptions::default());
        assert!(single.budget_gate_passed());
        assert!(!single.snapshot_evidence_passed());
        assert_eq!(single.stable_id_opportunities, 0);
        assert_eq!(single.stable_id_survival_rate, 0.0);
        assert!(!single.stable_id_gate_passed());
        assert_eq!(single.diff_snapshots, 0);
        assert!(!single.diff_gate_passed());
        assert!(!single.final_md_gate_passed());

        let no_repeated_identity = observation_corpus_report(
            &[
                ObservationInput::new(
                    "https://stable.example",
                    vec![RawElement::new("button", "First").stable_hint("first")],
                ),
                ObservationInput::new(
                    "https://stable.example",
                    vec![RawElement::new("button", "Second").stable_hint("second")],
                ),
            ],
            CompileOptions::default(),
        );
        assert!(no_repeated_identity.snapshot_evidence_passed());
        assert_eq!(no_repeated_identity.stable_id_opportunities, 0);
        assert!(!no_repeated_identity.stable_id_gate_passed());
        assert!(no_repeated_identity.diff_gate_passed());
        assert!(!no_repeated_identity.final_md_gate_passed());
    }

    #[test]
    fn diff_reconstruction_requires_full_serialized_observation() {
        let previous = make_observation(
            "https://order.example",
            1,
            vec![
                test_element("node:a", "button", 1.0),
                test_element("node:b", "link", 0.9),
            ],
            2,
        );
        let current = make_observation(
            "https://order.example",
            2,
            vec![
                test_element("node:b", "link", 0.9),
                test_element("node:a", "button", 1.0),
            ],
            2,
        );
        let lossy_diff = ObservationDiff {
            since_seq: previous.seq,
            seq: current.seq,
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
        };

        assert!(!diff_reconstructs_current(
            &previous,
            &current,
            &lossy_diff,
            2
        ));
    }

    #[test]
    fn colliding_fingerprints_get_distinct_node_ids_within_snapshot() {
        // Two per-row "Delete" buttons share role/name/value and carry no stable
        // hint; only their engine source ids differ (issue #105).
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(ObservationInput::new(
            "https://rows.example/list",
            vec![
                RawElement::new("button", "Delete")
                    .source_id("row-1-delete")
                    .bounds([0.0, 0.0, 60.0, 24.0]),
                RawElement::new("button", "Delete")
                    .source_id("row-2-delete")
                    .bounds([0.0, 30.0, 60.0, 24.0]),
            ],
        ));

        assert_eq!(observation.elements.len(), 2);
        assert_ne!(
            observation.elements[0].node_id, observation.elements[1].node_id,
            "distinct elements must not collapse onto one NodeId"
        );

        // Set-of-marks must label both elements distinctly, not the first twice.
        assert_eq!(observation.marks.len(), 2);
        let marked: HashSet<_> = observation
            .marks
            .iter()
            .map(|(node_id, _)| node_id.clone())
            .collect();
        assert_eq!(marked.len(), 2);

        // The distinct identities persist across snapshots via their source ids.
        let next = compiler.compile(ObservationInput::new(
            "https://rows.example/list",
            vec![
                RawElement::new("button", "Delete")
                    .source_id("row-1-delete")
                    .bounds([0.0, 0.0, 60.0, 24.0]),
                RawElement::new("button", "Delete")
                    .source_id("row-2-delete")
                    .bounds([0.0, 30.0, 60.0, 24.0]),
            ],
        ));
        assert_ne!(next.elements[0].node_id, next.elements[1].node_id);
    }

    #[test]
    fn budget_scales_to_many_elements_and_preserves_ranking() {
        // A page with thousands of interactive elements must not force O(n^2)
        // re-serialization (issue #106) and must still keep the highest-ranked
        // elements under budget in rank order.
        let mut elements = vec![RawElement::new("textbox", "Search entire catalog")
            .stable_hint("search")
            .bounds([0.0, 0.0, 420.0, 36.0])];
        for index in 0..5_000 {
            elements.push(
                RawElement::new("link", format!("Footer navigation link {index}"))
                    .stable_hint(format!("footer-{index}"))
                    .bounds([0.0, index as f32, 80.0, 18.0]),
            );
        }

        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: 2_000,
            max_tokens: 500,
            max_marks: 8,
        });
        let observation = compiler.compile(ObservationInput::new("https://big.example", elements));

        assert!(
            serialized_len(&observation) <= 2_000,
            "{}",
            serialized_len(&observation)
        );
        assert!(estimated_tokens(&observation) <= 500);
        // Highest-ranked element survives truncation and stays first.
        assert_eq!(observation.elements[0].role, "textbox");
        assert!(!observation.elements.is_empty());
        assert!(observation.elements.len() < 5_001);
        // Relative ordering is preserved: ranks are non-increasing.
        for pair in observation.elements.windows(2) {
            assert!(pair[0].rank >= pair[1].rank);
        }
        assert_eq!(observation.marks.len(), 8.min(observation.elements.len()));
    }

    #[test]
    fn stable_id_mapper_evicts_stale_entries_and_stays_bounded() {
        // A long-lived session over a page whose text changes every render (issue
        // #107): every snapshot renders entirely fresh source ids and fingerprints.
        let mut compiler = ObservationCompiler::new();
        let per_snapshot = 4usize;
        let snapshots = (RETENTION_SNAPSHOTS as usize) * 6;
        for snapshot in 0..snapshots {
            let elements = (0..per_snapshot)
                .map(|slot| {
                    RawElement::new("button", format!("tick {snapshot}-{slot}"))
                        .source_id(format!("src-{snapshot}-{slot}"))
                })
                .collect();
            compiler.compile(ObservationInput::new("https://ticker.example", elements));
        }

        // Only mappings from the most recent RETENTION_SNAPSHOTS survive, so the
        // maps stay bounded instead of growing with the number of snapshots.
        let bound = per_snapshot * RETENTION_SNAPSHOTS as usize;
        assert!(
            compiler.mapper.by_source.len() <= bound,
            "by_source={}",
            compiler.mapper.by_source.len()
        );
        assert!(
            compiler.mapper.by_fingerprint.len() <= bound,
            "by_fingerprint={}",
            compiler.mapper.by_fingerprint.len()
        );
        assert!(
            compiler.mapper.allocated.len() <= bound,
            "allocated={}",
            compiler.mapper.allocated.len()
        );
        // Without eviction this would hold snapshots * per_snapshot entries.
        assert!(compiler.mapper.by_source.len() < snapshots * per_snapshot);
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

    #[test]
    fn set_of_marks_compositor_draws_bounds_and_label_pixels() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 2,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![
                RawElement::new("button", "Continue")
                    .stable_hint("continue")
                    .bounds([10.0, 8.0, 22.0, 16.0]),
                RawElement::new("link", "Help")
                    .stable_hint("help")
                    .bounds([40.0, 20.0, 10.0, 10.0]),
            ],
        ));
        let input = solid_rgba(64, 48, [240, 240, 240, 255]);

        let output = composite_set_of_marks_rgba(&input, 64, 48, &observation)?;

        assert_ne!(output, input);
        assert_eq!(pixel_rgba(&input, 64, 1, 1)?, [240, 240, 240, 255]);
        assert_eq!(pixel_rgba(&output, 64, 1, 1)?, [240, 240, 240, 255]);
        let border = pixel_rgba(&output, 64, 10, 8)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        let badge = pixel_rgba(&output, 64, 11, 9)?;
        assert!(badge[0] > 245);
        assert!(badge[1] < 100);
        assert!(badge[2] < 100);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_clips_bounds_to_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("button", "Partly visible")
                .stable_hint("partial")
                .bounds([-4.0, -3.0, 12.0, 10.0])],
        ));
        let input = solid_rgba(24, 16, [20, 20, 20, 255]);

        let output = composite_set_of_marks_rgba(&input, 24, 16, &observation)?;

        let top_left = pixel_rgba(&output, 24, 0, 0)?;
        assert!(top_left[0] > 150);
        assert!(top_left[1] < 80);
        assert!(top_left[2] < 80);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_rejects_invalid_rgba_buffer() {
        let observation = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://marks.test".into(),
            seq: 1,
            elements: Vec::new(),
            marks: Vec::new(),
        };

        let error = composite_set_of_marks_rgba(&[0, 1, 2], 8, 8, &observation);

        assert!(matches!(
            error,
            Err(MarkCompositorError::InvalidBufferLength {
                expected: 256,
                actual: 3
            })
        ));
    }

    #[test]
    fn set_of_marks_compositor_overlays_png_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("button", "Continue")
                .stable_hint("continue")
                .bounds([4.0, 3.0, 12.0, 8.0])],
        ));
        let input = solid_rgba(32, 24, [12, 34, 56, 255]);
        let input_png = encode_rgba_png(&input, 32, 24)?;

        let output_png = composite_set_of_marks_png(&input_png, &observation)?;
        let decoded = decode_png_to_rgba(&output_png)?;

        assert_eq!(decoded.width, 32);
        assert_eq!(decoded.height, 24);
        assert_eq!(pixel_rgba(&decoded.rgba, 32, 31, 23)?, [12, 34, 56, 255]);
        let border = pixel_rgba(&decoded.rgba, 32, 4, 3)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_accepts_rgb_png_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("link", "Details")
                .stable_hint("details")
                .bounds([6.0, 5.0, 10.0, 8.0])],
        ));
        let input_png = encode_rgb_png(&solid_rgb(24, 18, [90, 100, 110]), 24, 18)?;

        let output_png = composite_set_of_marks_png(&input_png, &observation)?;
        let decoded = decode_png_to_rgba(&output_png)?;

        assert_eq!(pixel_rgba(&decoded.rgba, 24, 23, 17)?, [90, 100, 110, 255]);
        let border = pixel_rgba(&decoded.rgba, 24, 6, 5)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        Ok(())
    }

    fn solid_rgba(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity((width as usize) * (height as usize) * 4);
        for _ in 0..(width as usize * height as usize) {
            pixels.extend_from_slice(&color);
        }
        pixels
    }

    fn solid_rgb(width: u32, height: u32, color: [u8; 3]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity((width as usize) * (height as usize) * 3);
        for _ in 0..(width as usize * height as usize) {
            pixels.extend_from_slice(&color);
        }
        pixels
    }

    fn encode_rgb_png(rgb: &[u8], width: u32, height: u32) -> Result<Vec<u8>, MarkCompositorError> {
        let expected = (width as usize) * (height as usize) * 3;
        if rgb.len() != expected {
            return Err(MarkCompositorError::InvalidBufferLength {
                expected,
                actual: rgb.len(),
            });
        }

        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder
                .write_header()
                .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
            writer
                .write_image_data(rgb)
                .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
        }
        Ok(output)
    }

    fn pixel_rgba(
        pixels: &[u8],
        width: u32,
        x: u32,
        y: u32,
    ) -> Result<[u8; 4], MarkCompositorError> {
        let index = ((y as usize * width as usize) + x as usize) * 4;
        if index + 3 >= pixels.len() {
            return Err(MarkCompositorError::InvalidBufferLength {
                expected: index + 4,
                actual: pixels.len(),
            });
        }
        Ok([
            pixels[index],
            pixels[index + 1],
            pixels[index + 2],
            pixels[index + 3],
        ])
    }
}
