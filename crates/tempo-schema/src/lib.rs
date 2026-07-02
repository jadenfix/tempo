//! tempo-schema — Contract **C1** (ObservationSchema v2) and **C2** (ActionSchema v2).
//!
//! This crate is the single freeze-first artifact that unblocks the whole org (see
//! `final.md` §5). It defines the wire types every other crate agrees on: the
//! compiled observation handed to agents, the semantic action space, taint/provenance
//! labels, and the diff format. Types here MUST stay serde-stable behind `SCHEMA_VERSION`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
            "action_batch": { "$ref": "#/$defs/ActionBatch" }
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
        // `marks` carries `#[serde(default)]`, so it is optional on the wire.
        "required": ["schema_version", "url", "seq", "elements"],
        "properties": {
            "schema_version": { "type": "string", "const": SCHEMA_VERSION },
            "url": { "type": "string", "format": "uri-reference" },
            "seq": { "type": "integer", "minimum": 0 },
            "elements": {
                "type": "array",
                "items": { "$ref": "#/$defs/InteractiveElement" }
            },
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
                "additionalProperties": true,
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
            marks: vec![],
        };
        let s = serde_json::to_string(&obs)?;
        let back: CompiledObservation = serde_json::from_str(&s)?;
        assert_eq!(obs, back);
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
    fn schema_optionality_matches_serde_defaults() {
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
}
