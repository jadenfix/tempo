//! tempo-schema — Contract **C1** (ObservationSchema v2) and **C2** (ActionSchema v2).
//!
//! This crate is the single freeze-first artifact that unblocks the whole org (see
//! `final.md` §5). It defines the wire types every other crate agrees on: the
//! compiled observation handed to agents, the semantic action space, taint/provenance
//! labels, and the diff format. Types here MUST stay serde-stable behind `SCHEMA_VERSION`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::error::Error;
use std::fmt;

/// Frozen schema version. Bumped only by a deliberate contract change (final.md §8.2 M0).
pub const SCHEMA_VERSION: &str = "2.0.0";

/// Stable identifier for a page element that survives relayout / re-render.
///
/// Grounding contract: an action planned against a `NodeId` in observation N must still
/// resolve at execution; a miss is a *step error*, never a transport error.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Provenance of a span of observed text. The core of the trust boundary (final.md §2.7):
/// page-derived content is *data*, never *instructions*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Emitted by tempo itself (safe to treat as system context).
    System,
    /// Supplied by the human user.
    User,
    /// Derived from the page — untrusted; drives taint-escalation (final.md §6.2).
    Page,
}

/// A labeled span of text within an observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSpan {
    pub provenance: Provenance,
    pub text: String,
}

impl TaintSpan {
    /// The C1 taint predicate consumed by `tempo-policy` and `tempo-toolexec`.
    pub fn is_tainted(&self) -> bool {
        matches!(self.provenance, Provenance::Page)
    }
}

/// One ranked, interactive element in the compiled observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InteractiveElement {
    pub node_id: NodeId,
    /// AX role, e.g. "button", "textbox", "link".
    pub role: String,
    /// Accessible name / label, taint-labeled.
    pub name: Vec<TaintSpan>,
    /// Current value where applicable (inputs, selects), taint-labeled.
    ///
    /// Omitted from the wire when empty (the common case — most elements have no
    /// value); `#[serde(default)]` reconstructs the empty vec on read. The field
    /// is already non-`required` in the published JSON Schema, so this is a
    /// pure byte-size reduction, not a contract change (see the schema below).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<TaintSpan>,
    /// Bounding box in CSS pixels: [x, y, w, h]. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds: Option<[f32; 4]>,
    /// Ranker score — higher means more likely to be task-relevant.
    pub rank: f32,
}

/// The compiled observation handed to an agent: structured, ranked, stably-identified,
/// taint-labeled. Target budget ≤ 4KB / ≤ 1.5K tokens p50 (final.md §8.1, §10).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompiledObservation {
    pub schema_version: String,
    pub url: String,
    /// Monotonic observation sequence; `ObservationDiff` is expressed relative to one.
    pub seq: u64,
    pub elements: Vec<InteractiveElement>,
    /// Ranked elements omitted by the observation budgeter. Zero means the
    /// compiled observation contains every candidate the compiler considered.
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub omitted: u32,
    /// Optional set-of-marks overlay: NodeId -> mark label drawn over the screenshot.
    /// Omitted from the wire when empty; already non-`required` in the JSON Schema.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<(NodeId, u32)>,
}

fn u32_is_zero(value: &u32) -> bool {
    *value == 0
}

/// Diff-based re-observation: only what changed since `since_seq` (final.md §2.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationDiff {
    pub since_seq: u64,
    pub seq: u64,
    /// Ranked elements omitted from the current observation after applying the
    /// diff. Zero means the current observation contains every candidate the
    /// compiler considered.
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub omitted: u32,
    pub added: Vec<InteractiveElement>,
    pub removed: Vec<NodeId>,
    pub changed: Vec<InteractiveElement>,
}

/// Side-effect classification, mirrored from `beater_connect::SideEffect`. Drives the
/// policy gate: Send/Purchase/Delete confirm-by-default (final.md §3.2 tempo-policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    Read,
    Draft,
    Write,
    Send,
    Purchase,
    Delete,
}

/// Why a run must stop and hand control to a human (final.md §7 session handoff, #244).
///
/// tempo NEVER integrates a CAPTCHA-solving service or any automated
/// challenge-answering: the only correct response to one of these states is to
/// pause and let a person take the wheel. This enum names *what* was detected so
/// a takeover UI can explain the pause; it is deliberately coarse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakeoverKind {
    /// A CAPTCHA / bot challenge widget (reCAPTCHA, hCaptcha, Cloudflare
    /// Turnstile, "I'm not a robot", interstitial "verify you are human").
    Captcha,
    /// An access wall: the page reports the request is unauthorized / forbidden
    /// / the session expired, so no further automated action can proceed.
    AuthWall,
    /// A credential or one-time-code form the human must fill (login / OTP / 2FA).
    LoginRequired,
}

impl TakeoverKind {
    /// Stable, human-facing label for logs and takeover UI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Captcha => "captcha",
            Self::AuthWall => "auth_wall",
            Self::LoginRequired => "login_required",
        }
    }
}

/// A detected human-takeover requirement: the typed hard-pause signal produced by
/// the challenge/auth-wall classifier (`tempo_act::detect`) and journaled so a
/// resumed run never auto-continues past it (#244).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanTakeover {
    pub kind: TakeoverKind,
    /// Short, human-readable explanation of the detection (which cue fired).
    pub reason: String,
    /// URL of the page the human is being asked to take over.
    pub url: String,
}

/// The semantic action space (C2). Actions target stable `NodeId`s, not coordinates.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Goto {
        url: String,
    },
    Click {
        node: NodeId,
    },
    Type {
        node: NodeId,
        text: String,
    },
    Select {
        node: NodeId,
        value: String,
    },
    Scroll {
        x: f32,
        y: f32,
    },
    /// Fixed wait fallback. Prefer `QuiescencePolicy::Composite`; this exists
    /// to preserve compatibility with beater's legacy `BrowserAction::Wait`.
    Wait {
        millis: u64,
    },
    Extract {
        node: NodeId,
    },
    /// Invoke a named macro/skill from the skill store (final.md tempo-skills).
    Skill {
        name: String,
        input: serde_json::Value,
    },
}

impl Action {
    /// Static side-effect class for this action (before argument-derived escalation).
    pub fn side_effect(&self) -> SideEffect {
        match self {
            Action::Goto { .. }
            | Action::Scroll { .. }
            | Action::Wait { .. }
            | Action::Extract { .. } => SideEffect::Read,
            Action::Click { .. } | Action::Type { .. } | Action::Select { .. } => SideEffect::Write,
            // Skills declare their own class; default to the safe-but-gated Write.
            Action::Skill { .. } => SideEffect::Write,
        }
    }
}

/// Step status preserved when converting beater `StepTriple`s into tempo's schema layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Error,
}

/// Grounding evidence for a semantic action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grounding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    pub selector_existed: bool,
    pub matched_element: bool,
}

/// Outcome of one action after execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub status: StepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub grounding: Grounding,
    pub observation: CompiledObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<ObservationDiff>,
}

/// Contract-level observe → decide → act record used for beater StepTriple interop.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StepTriple {
    pub seq: u64,
    pub observation_before: CompiledObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Value>,
    pub action: Action,
    pub outcome: ActionOutcome,
}

/// Error returned when a tempo action or StepTriple cannot be expressed in beater's
/// legacy browser contract without losing meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaterCompatError {
    UnsupportedSkillAction { name: String },
    UnsupportedScrollCoordinates { x: String, y: String },
    UnsupportedDiff { since_seq: u64, seq: u64 },
    InvalidDecision { reason: String },
}

impl fmt::Display for BeaterCompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSkillAction { name } => {
                write!(
                    f,
                    "tempo skill action cannot convert to beater BrowserAction: {name}"
                )
            }
            Self::UnsupportedScrollCoordinates { x, y } => {
                write!(
                    f,
                    "tempo scroll coordinates cannot convert losslessly to beater BrowserAction: x={x}, y={y}"
                )
            }
            Self::UnsupportedDiff { since_seq, seq } => {
                write!(
                    f,
                    "tempo ActionOutcome diff cannot convert to beater StepOutcome: since_seq={since_seq}, seq={seq}"
                )
            }
            Self::InvalidDecision { reason } => {
                write!(
                    f,
                    "tempo StepTriple decision is not a beater LlmDecision: {reason}"
                )
            }
        }
    }
}

impl Error for BeaterCompatError {}

impl From<beater_browser::BrowserAction> for Action {
    fn from(action: beater_browser::BrowserAction) -> Self {
        match action {
            beater_browser::BrowserAction::Goto { url } => Self::Goto { url },
            beater_browser::BrowserAction::Click { selector } => Self::Click {
                node: NodeId(selector),
            },
            beater_browser::BrowserAction::Type { selector, text } => Self::Type {
                node: NodeId(selector),
                text,
            },
            beater_browser::BrowserAction::Scroll { x, y } => Self::Scroll {
                x: x as f32,
                y: y as f32,
            },
            beater_browser::BrowserAction::Select { selector, value } => Self::Select {
                node: NodeId(selector),
                value,
            },
            beater_browser::BrowserAction::Wait { millis } => Self::Wait { millis },
            beater_browser::BrowserAction::Extract { selector } => Self::Extract {
                node: NodeId(selector),
            },
        }
    }
}

impl TryFrom<Action> for beater_browser::BrowserAction {
    type Error = BeaterCompatError;

    fn try_from(action: Action) -> Result<Self, Self::Error> {
        match action {
            Action::Goto { url } => Ok(Self::Goto { url }),
            Action::Click { node } => Ok(Self::Click { selector: node.0 }),
            Action::Type { node, text } => Ok(Self::Type {
                selector: node.0,
                text,
            }),
            Action::Select { node, value } => Ok(Self::Select {
                selector: node.0,
                value,
            }),
            Action::Scroll { x, y } => Ok(Self::Scroll {
                x: scroll_component_to_i64(x).ok_or_else(|| {
                    BeaterCompatError::UnsupportedScrollCoordinates {
                        x: x.to_string(),
                        y: y.to_string(),
                    }
                })?,
                y: scroll_component_to_i64(y).ok_or_else(|| {
                    BeaterCompatError::UnsupportedScrollCoordinates {
                        x: x.to_string(),
                        y: y.to_string(),
                    }
                })?,
            }),
            Action::Wait { millis } => Ok(Self::Wait { millis }),
            Action::Extract { node } => Ok(Self::Extract { selector: node.0 }),
            Action::Skill { name, .. } => Err(BeaterCompatError::UnsupportedSkillAction { name }),
        }
    }
}

impl From<beater_browser::Observation> for CompiledObservation {
    fn from(observation: beater_browser::Observation) -> Self {
        let mut elements = Vec::new();
        if let Some(title) = observation.title.filter(|title| !title.is_empty()) {
            elements.push(compat_element("beater:title", "document_title", title, 1.0));
        }
        if let Some(accessibility_tree) = observation.accessibility_tree {
            elements.push(compat_element(
                "beater:accessibility_tree",
                "accessibility_tree",
                accessibility_tree.to_string(),
                0.8,
            ));
        }
        if let Some(dom_html) = observation.dom_html.filter(|dom_html| !dom_html.is_empty()) {
            elements.push(compat_element(
                "beater:dom_html",
                "document",
                dom_html,
                0.25,
            ));
        }
        if !observation.console.is_empty()
            && let Some(element) = compat_json_element(
                "beater:console",
                "console_messages",
                &observation.console,
                0.2,
            )
        {
            elements.push(element);
        }
        if !observation.network.is_empty()
            && let Some(element) = compat_json_element(
                "beater:network",
                "network_requests",
                &observation.network,
                0.2,
            )
        {
            elements.push(element);
        }

        Self {
            schema_version: SCHEMA_VERSION.into(),
            url: observation.url,
            seq: 0,
            elements,
            omitted: 0,
            marks: vec![],
        }
    }
}

impl From<CompiledObservation> for beater_browser::Observation {
    fn from(observation: CompiledObservation) -> Self {
        let title = compat_text_from(&observation.elements, "beater:title");
        let dom_html = compat_text_from(&observation.elements, "beater:dom_html");
        let accessibility_tree =
            compat_json_from(&observation.elements, "beater:accessibility_tree")
                .or_else(|| serde_json::to_value(&observation.elements).ok());
        let console = compat_json_from(&observation.elements, "beater:console").unwrap_or_default();
        let network = compat_json_from(&observation.elements, "beater:network").unwrap_or_default();

        Self {
            url: observation.url,
            title,
            dom_html,
            accessibility_tree,
            console,
            network,
        }
    }
}

impl From<beater_browser::StepStatus> for StepStatus {
    fn from(status: beater_browser::StepStatus) -> Self {
        match status {
            beater_browser::StepStatus::Ok => Self::Ok,
            beater_browser::StepStatus::Error => Self::Error,
        }
    }
}

impl From<StepStatus> for beater_browser::StepStatus {
    fn from(status: StepStatus) -> Self {
        match status {
            StepStatus::Ok => Self::Ok,
            StepStatus::Error => Self::Error,
        }
    }
}

impl From<beater_browser::Grounding> for Grounding {
    fn from(grounding: beater_browser::Grounding) -> Self {
        Self {
            node: grounding.selector.map(NodeId),
            selector_existed: grounding.selector_existed,
            matched_element: grounding.matched_element,
        }
    }
}

impl From<Grounding> for beater_browser::Grounding {
    fn from(grounding: Grounding) -> Self {
        Self {
            selector: grounding.node.map(|node| node.0),
            selector_existed: grounding.selector_existed,
            matched_element: grounding.matched_element,
        }
    }
}

impl From<beater_browser::StepOutcome> for ActionOutcome {
    fn from(outcome: beater_browser::StepOutcome) -> Self {
        Self {
            status: outcome.status.into(),
            error: outcome.error,
            grounding: outcome.grounding.into(),
            observation: outcome.observation.into(),
            diff: None,
        }
    }
}

impl TryFrom<ActionOutcome> for beater_browser::StepOutcome {
    type Error = BeaterCompatError;

    fn try_from(outcome: ActionOutcome) -> Result<Self, Self::Error> {
        if let Some(diff) = outcome.diff {
            return Err(BeaterCompatError::UnsupportedDiff {
                since_seq: diff.since_seq,
                seq: diff.seq,
            });
        }

        Ok(Self {
            status: outcome.status.into(),
            error: outcome.error,
            grounding: outcome.grounding.into(),
            observation: outcome.observation.into(),
        })
    }
}

impl From<beater_browser::StepTriple> for StepTriple {
    fn from(triple: beater_browser::StepTriple) -> Self {
        let decision = triple
            .decision
            .and_then(|decision| serde_json::to_value(decision).ok());
        Self {
            seq: triple.seq,
            observation_before: triple.observation_before.into(),
            decision,
            action: triple.action.into(),
            outcome: triple.outcome.into(),
        }
    }
}

impl TryFrom<StepTriple> for beater_browser::StepTriple {
    type Error = BeaterCompatError;

    fn try_from(triple: StepTriple) -> Result<Self, Self::Error> {
        let decision = match triple.decision {
            Some(value) => Some(serde_json::from_value(value).map_err(|error| {
                BeaterCompatError::InvalidDecision {
                    reason: error.to_string(),
                }
            })?),
            None => None,
        };

        Ok(Self {
            seq: triple.seq,
            observation_before: triple.observation_before.into(),
            decision,
            action: beater_browser::BrowserAction::try_from(triple.action)?,
            outcome: beater_browser::StepOutcome::try_from(triple.outcome)?,
        })
    }
}

fn scroll_component_to_i64(value: f32) -> Option<i64> {
    let value = f64::from(value);
    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }
    if value < i64::MIN as f64 || value > i64::MAX as f64 {
        return None;
    }
    Some(value as i64)
}

fn compat_element(
    node_id: impl Into<String>,
    role: impl Into<String>,
    text: impl Into<String>,
    rank: f32,
) -> InteractiveElement {
    InteractiveElement {
        node_id: NodeId(node_id.into()),
        role: role.into(),
        name: vec![TaintSpan {
            provenance: Provenance::Page,
            text: text.into(),
        }],
        value: vec![],
        bounds: None,
        rank,
    }
}

fn compat_json_element<T: Serialize>(
    node_id: impl Into<String>,
    role: impl Into<String>,
    value: &T,
    rank: f32,
) -> Option<InteractiveElement> {
    serde_json::to_string(value)
        .ok()
        .map(|text| compat_element(node_id, role, text, rank))
}

fn compat_text_from(elements: &[InteractiveElement], node_id: &str) -> Option<String> {
    elements
        .iter()
        .find(|element| element.node_id.0 == node_id)
        .map(|element| flatten_spans(&element.name))
}

fn compat_json_from<T: for<'de> Deserialize<'de>>(
    elements: &[InteractiveElement],
    node_id: &str,
) -> Option<T> {
    compat_text_from(elements, node_id).and_then(|text| serde_json::from_str(&text).ok())
}

fn flatten_spans(spans: &[TaintSpan]) -> String {
    spans
        .iter()
        .map(|span| span.text.as_str())
        .collect::<Vec<_>>()
        .join("")
}

/// How the executor decides a page has settled after a batch (final.md §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescencePolicy {
    /// Network-idle AND layout-stable AND no pending JS/microtasks, with a timeout ladder.
    Composite,
    /// Fixed wait (fallback only; discouraged).
    FixedMillis(u64),
}

/// A batch of actions executed with a single settle policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionBatch {
    pub actions: Vec<Action>,
    pub quiescence: QuiescencePolicy,
}

/// JSON Schema draft used for the published C1/C2 contract.
pub const JSON_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Emit a bundled JSON Schema for every frozen tempo wire type.
pub fn schema_bundle_json_schema() -> Value {
    let mut defs = serde_json::Map::new();
    defs.insert("NodeId".into(), node_id_json_schema());
    defs.insert("Provenance".into(), provenance_json_schema());
    defs.insert("TaintSpan".into(), taint_span_json_schema());
    defs.insert(
        "InteractiveElement".into(),
        interactive_element_json_schema(),
    );
    defs.insert(
        "CompiledObservation".into(),
        compiled_observation_json_schema(),
    );
    defs.insert("ObservationDiff".into(), observation_diff_json_schema());
    defs.insert("SideEffect".into(), side_effect_json_schema());
    defs.insert("Action".into(), action_json_schema());
    defs.insert("QuiescencePolicy".into(), quiescence_policy_json_schema());
    defs.insert("ActionBatch".into(), action_batch_json_schema());
    defs.insert("StepStatus".into(), step_status_json_schema());
    defs.insert("Grounding".into(), grounding_json_schema());
    defs.insert("ActionOutcome".into(), action_outcome_json_schema());
    defs.insert("StepTriple".into(), step_triple_json_schema());

    json!({
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": format!("https://tempo.dev/schemas/{SCHEMA_VERSION}/tempo.schema.json"),
        "title": "tempo C1/C2 schema bundle",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "compiled_observation": { "$ref": "#/$defs/CompiledObservation" },
            "observation_diff": { "$ref": "#/$defs/ObservationDiff" },
            "action": { "$ref": "#/$defs/Action" },
            "action_batch": { "$ref": "#/$defs/ActionBatch" },
            "step_triple": { "$ref": "#/$defs/StepTriple" }
        },
        "$defs": defs
    })
}

/// JSON Schema for C1 `CompiledObservation`.
pub fn compiled_observation_json_schema() -> Value {
    json!({
        "title": "CompiledObservation",
        "type": "object",
        // `CompiledObservation` does not use `#[serde(deny_unknown_fields)]`, so
        // unknown keys are ignored on deserialization — mirror that here.
        "additionalProperties": true,
        // `omitted`/`marks` carry `#[serde(default)]`, so they are optional on
        // the wire for older artifacts.
        "required": ["schema_version", "url", "seq", "elements"],
        "properties": {
            "schema_version": { "type": "string", "const": SCHEMA_VERSION },
            "url": { "type": "string", "format": "uri-reference" },
            "seq": { "type": "integer", "minimum": 0 },
            "elements": {
                "type": "array",
                "items": { "$ref": "#/$defs/InteractiveElement" }
            },
            "omitted": { "type": "integer", "minimum": 0, "maximum": u32::MAX },
            "marks": {
                "type": "array",
                "items": {
                    "type": "array",
                    "prefixItems": [
                        { "$ref": "#/$defs/NodeId" },
                        // Mark labels are `u32` in Rust; bound the schema so it
                        // rejects values that would fail deserialization.
                        { "type": "integer", "minimum": 0, "maximum": u32::MAX }
                    ],
                    "minItems": 2,
                    "maxItems": 2
                }
            }
        }
    })
}

/// JSON Schema for C1 `ObservationDiff`.
pub fn observation_diff_json_schema() -> Value {
    json!({
        "title": "ObservationDiff",
        "type": "object",
        "additionalProperties": true,
        "required": ["since_seq", "seq", "added", "removed", "changed"],
        "properties": {
            "since_seq": { "type": "integer", "minimum": 0 },
            "seq": { "type": "integer", "minimum": 0 },
            "omitted": { "type": "integer", "minimum": 0, "maximum": u32::MAX },
            "added": {
                "type": "array",
                "items": { "$ref": "#/$defs/InteractiveElement" }
            },
            "removed": {
                "type": "array",
                "items": { "$ref": "#/$defs/NodeId" }
            },
            "changed": {
                "type": "array",
                "items": { "$ref": "#/$defs/InteractiveElement" }
            }
        }
    })
}

/// JSON Schema for C2 `Action`.
pub fn action_json_schema() -> Value {
    json!({
        "title": "Action",
        "oneOf": [
            action_variant_schema("goto", json!({
                "url": { "type": "string", "format": "uri-reference" }
            })),
            action_variant_schema("click", json!({
                "node": { "$ref": "#/$defs/NodeId" }
            })),
            action_variant_schema("type", json!({
                "node": { "$ref": "#/$defs/NodeId" },
                "text": { "type": "string" }
            })),
            action_variant_schema("select", json!({
                "node": { "$ref": "#/$defs/NodeId" },
                "value": { "type": "string" }
            })),
            action_variant_schema("scroll", json!({
                "x": { "type": "number" },
                "y": { "type": "number" }
            })),
            action_variant_schema("wait", json!({
                "millis": { "type": "integer", "minimum": 0 }
            })),
            action_variant_schema("extract", json!({
                "node": { "$ref": "#/$defs/NodeId" }
            })),
            action_variant_schema("skill", json!({
                "name": { "type": "string" },
                "input": true
            }))
        ]
    })
}

fn step_status_json_schema() -> Value {
    json!({
        "title": "StepStatus",
        "type": "string",
        "enum": ["ok", "error"]
    })
}

fn grounding_json_schema() -> Value {
    json!({
        "title": "Grounding",
        "type": "object",
        "additionalProperties": false,
        "required": ["selector_existed", "matched_element"],
        "properties": {
            "node": {
                "anyOf": [
                    { "type": "null" },
                    { "$ref": "#/$defs/NodeId" }
                ]
            },
            "selector_existed": { "type": "boolean" },
            "matched_element": { "type": "boolean" }
        }
    })
}

fn action_outcome_json_schema() -> Value {
    json!({
        "title": "ActionOutcome",
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "grounding", "observation"],
        "properties": {
            "status": { "$ref": "#/$defs/StepStatus" },
            "error": {
                "anyOf": [
                    { "type": "null" },
                    { "type": "string" }
                ]
            },
            "grounding": { "$ref": "#/$defs/Grounding" },
            "observation": { "$ref": "#/$defs/CompiledObservation" },
            "diff": {
                "anyOf": [
                    { "type": "null" },
                    { "$ref": "#/$defs/ObservationDiff" }
                ]
            }
        }
    })
}

fn step_triple_json_schema() -> Value {
    json!({
        "title": "StepTriple",
        "type": "object",
        "additionalProperties": false,
        "required": ["seq", "observation_before", "action", "outcome"],
        "properties": {
            "seq": { "type": "integer", "minimum": 0 },
            "observation_before": { "$ref": "#/$defs/CompiledObservation" },
            "decision": true,
            "action": { "$ref": "#/$defs/Action" },
            "outcome": { "$ref": "#/$defs/ActionOutcome" }
        }
    })
}

/// JSON Schema for C2 `ActionBatch`.
pub fn action_batch_json_schema() -> Value {
    json!({
        "title": "ActionBatch",
        "type": "object",
        "additionalProperties": true,
        "required": ["actions", "quiescence"],
        "properties": {
            "actions": {
                "type": "array",
                "items": { "$ref": "#/$defs/Action" }
            },
            "quiescence": { "$ref": "#/$defs/QuiescencePolicy" }
        }
    })
}

fn node_id_json_schema() -> Value {
    json!({
        "title": "NodeId",
        // `NodeId(pub String)` deserializes from any string, empty included.
        "type": "string"
    })
}

fn provenance_json_schema() -> Value {
    json!({
        "title": "Provenance",
        "type": "string",
        "enum": ["system", "user", "page"]
    })
}

fn taint_span_json_schema() -> Value {
    json!({
        "title": "TaintSpan",
        "type": "object",
        "additionalProperties": true,
        "required": ["provenance", "text"],
        "properties": {
            "provenance": { "$ref": "#/$defs/Provenance" },
            "text": { "type": "string" }
        }
    })
}

fn interactive_element_json_schema() -> Value {
    json!({
        "title": "InteractiveElement",
        "type": "object",
        // No `#[serde(deny_unknown_fields)]`: unknown keys are ignored.
        "additionalProperties": true,
        // `value` and `bounds` carry `#[serde(default)]`, so both are optional.
        "required": ["node_id", "role", "name", "rank"],
        "properties": {
            "node_id": { "$ref": "#/$defs/NodeId" },
            // serde accepts empty strings; do not impose `minLength`.
            "role": { "type": "string" },
            "name": {
                "type": "array",
                "items": { "$ref": "#/$defs/TaintSpan" }
            },
            "value": {
                "type": "array",
                "items": { "$ref": "#/$defs/TaintSpan" }
            },
            "bounds": {
                "anyOf": [
                    { "type": "null" },
                    {
                        "type": "array",
                        "items": { "type": "number" },
                        "minItems": 4,
                        "maxItems": 4
                    }
                ]
            },
            "rank": { "type": "number" }
        }
    })
}

fn side_effect_json_schema() -> Value {
    json!({
        "title": "SideEffect",
        "type": "string",
        "enum": ["read", "draft", "write", "send", "purchase", "delete"]
    })
}

fn quiescence_policy_json_schema() -> Value {
    json!({
        "title": "QuiescencePolicy",
        "oneOf": [
            { "type": "string", "const": "composite" },
            {
                "type": "object",
                // Externally-tagged `QuiescencePolicy` deserializes exactly one
                // key and then requires end-of-object: serde denies unknown
                // fields, so the schema must too (see #114).
                "additionalProperties": false,
                "required": ["fixed_millis"],
                "properties": {
                    "fixed_millis": { "type": "integer", "minimum": 0, "maximum": u64::MAX }
                }
            }
        ]
    })
}

fn action_variant_schema(kind: &'static str, properties: Value) -> Value {
    let mut required = vec![Value::String("kind".into())];
    let mut merged = serde_json::Map::new();
    merged.insert(
        "kind".into(),
        json!({
            "type": "string",
            "const": kind
        }),
    );

    if let Value::Object(map) = properties {
        for (key, value) in map {
            required.push(Value::String(key.clone()));
            merged.insert(key, value);
        }
    }

    json!({
        "type": "object",
        // Internally-tagged `Action` variants ignore unknown fields on the wire.
        "additionalProperties": true,
        "required": required,
        "properties": merged
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_predicate_flags_page_content() {
        let span = TaintSpan {
            provenance: Provenance::Page,
            text: "x".into(),
        };
        assert!(span.is_tainted());
        let sys = TaintSpan {
            provenance: Provenance::System,
            text: "x".into(),
        };
        assert!(!sys.is_tainted());
    }

    #[test]
    fn side_effect_ordering_holds() {
        assert!(SideEffect::Read < SideEffect::Send);
        assert!(SideEffect::Send < SideEffect::Delete);
    }

    #[test]
    fn observation_round_trips() -> Result<(), serde_json::Error> {
        let obs = CompiledObservation {
            schema_version: SCHEMA_VERSION.into(),
            url: "https://example.com".into(),
            seq: 1,
            elements: vec![InteractiveElement {
                node_id: NodeId("n1".into()),
                role: "button".into(),
                name: vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: "Buy".into(),
                }],
                value: vec![],
                bounds: Some([0.0, 0.0, 10.0, 10.0]),
                rank: 0.9,
            }],
            omitted: 0,
            marks: vec![],
        };
        let s = serde_json::to_string(&obs)?;
        assert!(
            !s.contains("\"omitted\""),
            "zero omitted count should stay out of the wire: {s}"
        );
        let back: CompiledObservation = serde_json::from_str(&s)?;
        assert_eq!(obs, back);

        let truncated = CompiledObservation { omitted: 7, ..obs };
        let s = serde_json::to_string(&truncated)?;
        assert!(
            s.contains("\"omitted\":7"),
            "nonzero omitted count must be visible to agents: {s}"
        );
        let back: CompiledObservation = serde_json::from_str(&s)?;
        assert_eq!(truncated, back);
        Ok(())
    }

    #[test]
    fn defaulted_optional_fields_serialize_compactly() -> Result<(), serde_json::Error> {
        let observation = CompiledObservation {
            schema_version: SCHEMA_VERSION.into(),
            url: "https://example.com".into(),
            seq: 1,
            elements: vec![InteractiveElement {
                node_id: NodeId("n1".into()),
                role: "button".into(),
                name: vec![TaintSpan {
                    provenance: Provenance::Page,
                    text: "Buy".into(),
                }],
                value: vec![],
                bounds: None,
                rank: 0.9,
            }],
            omitted: 0,
            marks: vec![],
        };

        let observation_wire = serde_json::to_value(&observation)?;
        assert_eq!(
            observation_wire["elements"]
                .as_array()
                .map(|elements| elements.len()),
            Some(1)
        );
        assert!(observation_wire.get("marks").is_none());
        assert!(observation_wire["elements"][0].get("value").is_none());
        assert!(observation_wire["elements"][0].get("bounds").is_none());

        let verbose_observation = json!({
            "schema_version": SCHEMA_VERSION,
            "url": "https://example.com",
            "seq": 1,
            "elements": [{
                "node_id": "n1",
                "role": "button",
                "name": [{"provenance": "page", "text": "Buy"}],
                "value": [],
                "bounds": null,
                "rank": 0.9
            }],
            "marks": []
        });
        let back: CompiledObservation = serde_json::from_value(verbose_observation.clone())?;
        assert_eq!(observation, back);

        let outcome = ActionOutcome {
            status: StepStatus::Ok,
            error: None,
            grounding: Grounding {
                node: None,
                selector_existed: true,
                matched_element: true,
            },
            observation: observation.clone(),
            diff: None,
        };
        let step = StepTriple {
            seq: 1,
            observation_before: observation,
            decision: None,
            action: Action::Wait { millis: 1 },
            outcome,
        };

        let step_wire = serde_json::to_value(&step)?;
        assert!(step_wire.get("decision").is_none());
        assert!(step_wire["outcome"].get("error").is_none());
        assert!(step_wire["outcome"].get("diff").is_none());
        assert!(step_wire["outcome"]["grounding"].get("node").is_none());

        let verbose_step: StepTriple = serde_json::from_value(json!({
            "seq": 1,
            "observation_before": verbose_observation,
            "decision": null,
            "action": {"kind": "wait", "millis": 1},
            "outcome": {
                "status": "ok",
                "error": null,
                "grounding": {
                    "node": null,
                    "selector_existed": true,
                    "matched_element": true
                },
                "observation": {
                    "schema_version": SCHEMA_VERSION,
                    "url": "https://example.com",
                    "seq": 1,
                    "elements": [],
                    "marks": []
                },
                "diff": null
            }
        }))?;
        assert!(verbose_step.decision.is_none());
        assert!(verbose_step.outcome.error.is_none());
        assert!(verbose_step.outcome.diff.is_none());
        assert!(verbose_step.outcome.grounding.node.is_none());

        Ok(())
    }

    #[test]
    fn schema_bundle_exports_all_contract_defs() -> Result<(), String> {
        let schema = schema_bundle_json_schema();
        assert_eq!(schema["$schema"], JSON_SCHEMA_DRAFT);
        assert_eq!(
            schema["$id"],
            format!("https://tempo.dev/schemas/{SCHEMA_VERSION}/tempo.schema.json")
        );

        let defs = schema["$defs"]
            .as_object()
            .ok_or_else(|| "schema defs missing".to_string())?;
        for name in [
            "NodeId",
            "Provenance",
            "TaintSpan",
            "InteractiveElement",
            "CompiledObservation",
            "ObservationDiff",
            "SideEffect",
            "Action",
            "QuiescencePolicy",
            "ActionBatch",
            "StepStatus",
            "Grounding",
            "ActionOutcome",
            "StepTriple",
        ] {
            assert!(defs.contains_key(name), "missing {name}");
        }
        Ok(())
    }

    #[test]
    fn observation_schema_freezes_current_version_tag() {
        let schema = compiled_observation_json_schema();
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            SCHEMA_VERSION
        );
        // serde ignores unknown fields, so the schema must not forbid them.
        assert_eq!(schema["additionalProperties"], true);
        assert_eq!(
            schema["properties"]["elements"]["items"]["$ref"],
            "#/$defs/InteractiveElement"
        );
    }

    #[test]
    fn schema_optionality_matches_serde_defaults() -> Result<(), serde_json::Error> {
        // Fields carrying `#[serde(default)]` must not be schema-`required`.
        let element = interactive_element_json_schema();
        let element_required: Vec<&str> = element["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(element_required, ["node_id", "role", "name", "rank"]);
        assert!(!element_required.contains(&"value"));
        assert!(!element_required.contains(&"bounds"));

        let observation = compiled_observation_json_schema();
        let observation_required: Vec<&str> = observation["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert!(!observation_required.contains(&"marks"));

        let diff = observation_diff_json_schema();
        let diff_required: Vec<&str> = diff["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert!(!diff_required.contains(&"omitted"));

        let grounding = grounding_json_schema();
        let grounding_required: Vec<&str> = grounding["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(grounding_required, ["selector_existed", "matched_element"]);
        assert!(!grounding_required.contains(&"node"));

        let outcome = action_outcome_json_schema();
        let outcome_required: Vec<&str> = outcome["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(outcome_required, ["status", "grounding", "observation"]);
        assert!(!outcome_required.contains(&"error"));
        assert!(!outcome_required.contains(&"diff"));

        let step_triple = step_triple_json_schema();
        let step_triple_required: Vec<&str> = step_triple["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            step_triple_required,
            ["seq", "observation_before", "action", "outcome"]
        );
        assert!(!step_triple_required.contains(&"decision"));

        let grounding: Grounding =
            serde_json::from_value(json!({"selector_existed": true, "matched_element": false}))?;
        assert!(grounding.node.is_none());

        let observation = json!({
            "schema_version": SCHEMA_VERSION,
            "url": "https://example.test",
            "seq": 1,
            "elements": []
        });
        let outcome: ActionOutcome = serde_json::from_value(json!({
            "status": "ok",
            "grounding": {"selector_existed": true, "matched_element": true},
            "observation": observation
        }))?;
        assert!(outcome.error.is_none());
        assert!(outcome.diff.is_none());
        assert!(outcome.grounding.node.is_none());

        let step: StepTriple = serde_json::from_value(json!({
            "seq": 1,
            "observation_before": outcome.observation,
            "action": {"kind": "wait", "millis": 1},
            "outcome": outcome
        }))?;
        assert!(step.decision.is_none());
        assert!(step.outcome.error.is_none());
        assert!(step.outcome.diff.is_none());
        Ok(())
    }

    #[test]
    fn schema_does_not_reject_serde_accepted_payloads() -> Result<(), serde_json::Error> {
        // serde ignores unknown fields, accepts empty strings, and defaults
        // `value`/`bounds`/`marks`. The published schema must reflect that:
        // no `additionalProperties: false`, no `minLength`.
        assert_eq!(node_id_json_schema().get("minLength"), None);
        assert_eq!(
            interactive_element_json_schema()["properties"]["role"].get("minLength"),
            None
        );
        for schema in [
            interactive_element_json_schema(),
            compiled_observation_json_schema(),
            observation_diff_json_schema(),
            action_batch_json_schema(),
            taint_span_json_schema(),
        ] {
            assert_eq!(
                schema["additionalProperties"], true,
                "{} must allow unknown fields",
                schema["title"]
            );
        }

        // These payloads all deserialize under the serde contract, proving the
        // loosened schema is not narrower than the reference implementation.
        let element: InteractiveElement = serde_json::from_str(
            r#"{"node_id":"n1","role":"","name":[],"rank":0.5,"unknown_field":true}"#,
        )?;
        assert!(element.value.is_empty());
        assert!(element.bounds.is_none());

        let observation: CompiledObservation = serde_json::from_str(&format!(
            r#"{{"schema_version":"{SCHEMA_VERSION}","url":"u","seq":1,"elements":[],"extra":42}}"#
        ))?;
        assert_eq!(observation.omitted, 0);
        assert!(observation.marks.is_empty());
        Ok(())
    }

    #[test]
    fn schema_bounds_mark_labels_to_u32() {
        // The schema must reject mark labels serde would reject (`u32` overflow).
        let observation = compiled_observation_json_schema();
        let label = &observation["properties"]["marks"]["items"]["prefixItems"][1];
        assert_eq!(label["maximum"], u32::MAX);

        let overflow = format!(
            r#"{{"schema_version":"{SCHEMA_VERSION}","url":"u","seq":1,"elements":[],"marks":[["n",{}]]}}"#,
            u64::from(u32::MAX) + 1
        );
        assert!(serde_json::from_str::<CompiledObservation>(&overflow).is_err());
    }

    #[test]
    fn action_schema_covers_real_serde_kinds() -> Result<(), String> {
        let actions = [
            Action::Goto {
                url: "https://example.com".into(),
            },
            Action::Click {
                node: NodeId("n1".into()),
            },
            Action::Type {
                node: NodeId("n1".into()),
                text: "hello".into(),
            },
            Action::Select {
                node: NodeId("n1".into()),
                value: "a".into(),
            },
            Action::Scroll { x: 1.0, y: 2.0 },
            Action::Wait { millis: 250 },
            Action::Extract {
                node: NodeId("n1".into()),
            },
            Action::Skill {
                name: "checkout".into(),
                input: serde_json::Value::Null,
            },
        ];

        let schema = action_json_schema();
        let variants = schema["oneOf"]
            .as_array()
            .ok_or_else(|| "action oneOf missing".to_string())?;
        assert_eq!(variants.len(), actions.len());

        for action in actions {
            let value = serde_json::to_value(action).map_err(|error| error.to_string())?;
            let kind = value["kind"]
                .as_str()
                .ok_or_else(|| "action kind missing".to_string())?;
            let Some(schema_variant) = variants
                .iter()
                .find(|variant| variant["properties"]["kind"]["const"] == kind)
            else {
                return Err(format!("missing schema variant for {kind}"));
            };
            let fields = value
                .as_object()
                .ok_or_else(|| "action object missing".to_string())?;
            let required = schema_variant["required"]
                .as_array()
                .ok_or_else(|| format!("required fields missing for {kind}"))?;
            for field in fields.keys() {
                assert!(
                    required
                        .iter()
                        .any(|required| required.as_str() == Some(field.as_str())),
                    "{kind} missing required field {field}"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn quiescence_schema_matches_real_serde_shape() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_value(QuiescencePolicy::Composite)?,
            serde_json::Value::String("composite".into())
        );
        assert_eq!(
            serde_json::to_value(QuiescencePolicy::FixedMillis(250))?,
            serde_json::json!({ "fixed_millis": 250 })
        );

        let schema = quiescence_policy_json_schema();
        assert_eq!(schema["oneOf"][0]["const"], "composite");
        assert_eq!(
            schema["oneOf"][1]["properties"]["fixed_millis"]["type"],
            "integer"
        );
        Ok(())
    }

    #[test]
    fn quiescence_schema_denies_unknown_fields_like_serde() -> Result<(), serde_json::Error> {
        // `QuiescencePolicy` is externally tagged: serde reads exactly one key
        // and then requires end-of-object, so an extra key is a deserialize
        // error. The published schema must forbid unknown fields to match (#114).
        let schema = quiescence_policy_json_schema();
        assert_eq!(
            schema["oneOf"][1]["additionalProperties"], false,
            "QuiescencePolicy object variant must forbid unknown fields"
        );

        // serde agrees: the extra key is rejected, the exact shape is accepted.
        assert!(serde_json::from_value::<QuiescencePolicy>(
            json!({"fixed_millis": 100, "extra": 1})
        )
        .is_err());
        assert_eq!(
            serde_json::from_value::<QuiescencePolicy>(json!({"fixed_millis": 100}))?,
            QuiescencePolicy::FixedMillis(100)
        );
        Ok(())
    }

    #[test]
    fn action_batch_schema_references_action_and_quiescence_contracts() {
        let schema = action_batch_json_schema();
        assert_eq!(
            schema["properties"]["actions"]["items"]["$ref"],
            "#/$defs/Action"
        );
        assert_eq!(
            schema["properties"]["quiescence"]["$ref"],
            "#/$defs/QuiescencePolicy"
        );
    }

    #[test]
    fn beater_browser_actions_round_trip_through_tempo_actions() -> Result<(), BeaterCompatError> {
        let actions = [
            beater_browser::BrowserAction::Goto {
                url: "https://example.com".into(),
            },
            beater_browser::BrowserAction::Click {
                selector: "#submit".into(),
            },
            beater_browser::BrowserAction::Type {
                selector: "#q".into(),
                text: "tempo".into(),
            },
            beater_browser::BrowserAction::Scroll { x: 1, y: 2 },
            beater_browser::BrowserAction::Select {
                selector: "#kind".into(),
                value: "agent".into(),
            },
            beater_browser::BrowserAction::Wait { millis: 125 },
            beater_browser::BrowserAction::Extract {
                selector: "main".into(),
            },
        ];

        for original in actions {
            let tempo = Action::from(original.clone());
            let back = beater_browser::BrowserAction::try_from(tempo)?;
            assert_eq!(back, original);
        }
        Ok(())
    }

    #[test]
    fn skill_actions_do_not_silently_convert_to_beater_browser_actions() {
        let err = beater_browser::BrowserAction::try_from(Action::Skill {
            name: "checkout".into(),
            input: serde_json::Value::Null,
        });
        assert!(matches!(
            err,
            Err(BeaterCompatError::UnsupportedSkillAction { name }) if name == "checkout"
        ));
    }

    #[test]
    fn lossy_scroll_actions_do_not_silently_convert_to_beater_browser_actions() {
        let err = beater_browser::BrowserAction::try_from(Action::Scroll { x: 1.5, y: 2.0 });
        assert!(matches!(
            err,
            Err(BeaterCompatError::UnsupportedScrollCoordinates { .. })
        ));
    }

    #[test]
    fn beater_observation_converts_to_tainted_compiled_observation() {
        let beater = beater_browser::Observation {
            url: "https://example.com".into(),
            title: Some("Example".into()),
            dom_html: Some("<button>Buy</button>".into()),
            accessibility_tree: Some(json!({"role": "button", "name": "Buy"})),
            console: vec![],
            network: vec![],
        };

        let compiled = CompiledObservation::from(beater);
        assert_eq!(compiled.schema_version, SCHEMA_VERSION);
        assert_eq!(compiled.url, "https://example.com");
        assert!(compiled
            .elements
            .iter()
            .flat_map(|element| &element.name)
            .all(TaintSpan::is_tainted));
        assert!(compiled
            .elements
            .iter()
            .any(|element| element.node_id.0 == "beater:dom_html"));
    }

    #[test]
    fn beater_observation_round_trip_preserves_console_network_and_ax() {
        let original = beater_browser::Observation {
            url: "https://example.com".into(),
            title: Some("Example".into()),
            dom_html: Some("<button>Buy</button>".into()),
            accessibility_tree: Some(json!({"role": "button", "name": "Buy"})),
            console: vec![beater_browser::ConsoleMessage {
                level: "error".into(),
                text: "boom".into(),
            }],
            network: vec![beater_browser::NetworkRequest {
                method: "POST".into(),
                url: "https://example.com/api".into(),
                status: Some(500),
                resource_type: Some("fetch".into()),
                failed: false,
            }],
        };

        let compiled = CompiledObservation::from(original.clone());
        assert!(compiled
            .elements
            .iter()
            .any(|element| element.node_id.0 == "beater:console"));
        assert!(compiled
            .elements
            .iter()
            .any(|element| element.node_id.0 == "beater:network"));

        let back = beater_browser::Observation::from(compiled);
        assert_eq!(back, original);
    }

    #[test]
    fn tempo_outcome_with_diff_does_not_silently_convert_to_beater_outcome() {
        let outcome = ActionOutcome {
            status: StepStatus::Ok,
            error: None,
            grounding: Grounding {
                node: Some(NodeId("#go".into())),
                selector_existed: true,
                matched_element: true,
            },
            observation: CompiledObservation {
                schema_version: SCHEMA_VERSION.into(),
                url: "https://example.com".into(),
                seq: 3,
                elements: vec![],
                omitted: 0,
                marks: vec![],
            },
            diff: Some(ObservationDiff {
                since_seq: 2,
                seq: 3,
                omitted: 0,
                added: vec![],
                removed: vec![],
                changed: vec![],
            }),
        };

        let err = beater_browser::StepOutcome::try_from(outcome);
        assert!(matches!(
            err,
            Err(BeaterCompatError::UnsupportedDiff {
                since_seq: 2,
                seq: 3
            })
        ));
    }

    #[test]
    fn beater_step_triple_round_trip_preserves_supported_action() -> Result<(), BeaterCompatError> {
        let before = beater_browser::Observation {
            url: "https://example.com".into(),
            title: Some("Example".into()),
            dom_html: Some("<button id=\"go\">Go</button>".into()),
            accessibility_tree: None,
            console: vec![],
            network: vec![],
        };
        let outcome = beater_browser::StepOutcome {
            status: beater_browser::StepStatus::Ok,
            error: None,
            grounding: beater_browser::Grounding {
                selector: Some("#go".into()),
                selector_existed: true,
                matched_element: true,
            },
            observation: before.clone(),
        };
        let original = beater_browser::StepTriple {
            seq: 7,
            observation_before: before,
            decision: None,
            action: beater_browser::BrowserAction::Click {
                selector: "#go".into(),
            },
            outcome,
        };

        let tempo = StepTriple::from(original.clone());
        let back = beater_browser::StepTriple::try_from(tempo)?;
        assert_eq!(back.seq, original.seq);
        assert_eq!(back.action, original.action);
        assert_eq!(back.outcome.status, original.outcome.status);
        assert_eq!(back.outcome.grounding, original.outcome.grounding);
        Ok(())
    }
}
