//! tempo-schema — Contract **C1** (ObservationSchema v2) and **C2** (ActionSchema v2).
//!
//! This crate is the single freeze-first artifact that unblocks the whole org (see
//! `final.md` §5). It defines the wire types every other crate agrees on: the
//! compiled observation handed to agents, the semantic action space, taint/provenance
//! labels, and the diff format. Types here MUST stay serde-stable behind `SCHEMA_VERSION`.

use serde::{Deserialize, Serialize};

/// Frozen schema version. Bumped only by a deliberate contract change (final.md §8.2 M0).
pub const SCHEMA_VERSION: &str = "2.0.0-draft";

/// Stable identifier for a page element that survives relayout / re-render.
///
/// Grounding contract: an action planned against a `NodeId` in observation N must still
/// resolve at execution; a miss is a *step error*, never a transport error.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    #[serde(default)]
    pub value: Vec<TaintSpan>,
    /// Bounding box in CSS pixels: [x, y, w, h].
    #[serde(default)]
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
    /// Optional set-of-marks overlay: NodeId -> mark label drawn over the screenshot.
    #[serde(default)]
    pub marks: Vec<(NodeId, u32)>,
}

/// Diff-based re-observation: only what changed since `since_seq` (final.md §2.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationDiff {
    pub since_seq: u64,
    pub seq: u64,
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
            Action::Goto { .. } | Action::Scroll { .. } | Action::Extract { .. } => {
                SideEffect::Read
            }
            Action::Click { .. } | Action::Type { .. } | Action::Select { .. } => SideEffect::Write,
            // Skills declare their own class; default to the safe-but-gated Write.
            Action::Skill { .. } => SideEffect::Write,
        }
    }
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
            marks: vec![],
        };
        let s = serde_json::to_string(&obs)?;
        let back: CompiledObservation = serde_json::from_str(&s)?;
        assert_eq!(obs, back);
        Ok(())
    }
}
