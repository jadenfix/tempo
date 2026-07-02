//! tempo-policy - pure action policy decisions keyed on `SideEffect`.
//!
//! The policy gate is intentionally a pure decision layer: callers provide the
//! action/effect plus whether any parameter was derived from tainted page spans,
//! and this crate returns the exact human-confirmation and idempotency
//! requirements. Execution, UI, and persistence stay outside this crate.

use tempo_schema::{Action, SideEffect, TaintSpan};

/// Stable table of side-effect levels handled by this policy crate.
pub const SIDE_EFFECTS: [SideEffect; 6] = [
    SideEffect::Read,
    SideEffect::Draft,
    SideEffect::Write,
    SideEffect::Send,
    SideEffect::Purchase,
    SideEffect::Delete,
];

/// Human gate required before an action can execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfirmationGate {
    /// No human confirmation is required by policy.
    None,
    /// A normal human confirmation is required.
    Confirm,
    /// Confirmation must make the tainted-input provenance explicit.
    ConfirmWithTaintReview,
}

impl ConfirmationGate {
    /// Returns true when any human confirmation UI must run.
    pub const fn requires_human(self) -> bool {
        match self {
            Self::None => false,
            Self::Confirm | Self::ConfirmWithTaintReview => true,
        }
    }

    /// Bump exactly one confirmation level for parameters derived from tainted spans.
    pub const fn escalate_for_taint(self) -> Self {
        match self {
            Self::None => Self::Confirm,
            Self::Confirm | Self::ConfirmWithTaintReview => Self::ConfirmWithTaintReview,
        }
    }
}

/// Evidence that action parameters were, or were not, derived from tainted page spans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputTaint {
    tainted: bool,
}

impl InputTaint {
    /// No parameters came from page-derived spans.
    pub const CLEAN: Self = Self { tainted: false };

    /// At least one parameter came from page-derived spans.
    pub const TAINTED: Self = Self { tainted: true };

    /// Construct explicit taint evidence.
    pub const fn new(tainted: bool) -> Self {
        Self { tainted }
    }

    /// Returns true when this evidence contains page-derived input.
    pub const fn is_tainted(self) -> bool {
        self.tainted
    }

    /// Collapse schema taint spans into action-input evidence.
    pub fn from_spans<'a>(spans: impl IntoIterator<Item = &'a TaintSpan>) -> Self {
        Self {
            tainted: spans.into_iter().any(TaintSpan::is_tainted),
        }
    }
}

/// A deterministic policy decision for one action/effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Static side-effect class before taint escalation.
    pub side_effect: SideEffect,
    /// Whether action parameters carried page-derived taint.
    pub input_taint: InputTaint,
    /// Human confirmation gate required by policy.
    pub gate: ConfirmationGate,
    /// Whether callers must attach an idempotency key.
    pub idempotency_required: bool,
}

impl PolicyDecision {
    /// Returns true when policy requires human confirmation.
    pub const fn requires_confirmation(self) -> bool {
        self.gate.requires_human()
    }

    /// Returns true when the confirmation UI must expose tainted-input provenance.
    pub const fn requires_taint_review(self) -> bool {
        matches!(self.gate, ConfirmationGate::ConfirmWithTaintReview)
    }
}

/// Decide policy for a schema action using its static side-effect classification.
pub fn decide_action(action: &Action, input_taint: InputTaint) -> PolicyDecision {
    decide_effect(action.side_effect(), input_taint)
}

/// Decide policy directly for a side-effect class.
pub const fn decide_effect(effect: SideEffect, input_taint: InputTaint) -> PolicyDecision {
    let base_gate = default_confirmation_gate(effect);
    let gate = if input_taint.is_tainted() {
        base_gate.escalate_for_taint()
    } else {
        base_gate
    };

    PolicyDecision {
        side_effect: effect,
        input_taint,
        gate,
        idempotency_required: requires_idempotency(effect),
    }
}

/// Default human gate before taint escalation.
pub const fn default_confirmation_gate(effect: SideEffect) -> ConfirmationGate {
    match effect {
        SideEffect::Read | SideEffect::Draft | SideEffect::Write => ConfirmationGate::None,
        SideEffect::Send | SideEffect::Purchase | SideEffect::Delete => ConfirmationGate::Confirm,
    }
}

/// Mirrors beater-connect: Send/Purchase/Delete require confirmation by default.
pub const fn requires_confirmation_by_default(effect: SideEffect) -> bool {
    match effect {
        SideEffect::Read | SideEffect::Draft | SideEffect::Write => false,
        SideEffect::Send | SideEffect::Purchase | SideEffect::Delete => true,
    }
}

/// Mirrors beater-connect idempotency semantics.
pub const fn requires_idempotency(effect: SideEffect) -> bool {
    match effect {
        SideEffect::Read | SideEffect::Draft => false,
        SideEffect::Write | SideEffect::Send | SideEffect::Purchase | SideEffect::Delete => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_schema::{NodeId, Provenance};

    #[test]
    fn confirmation_defaults_match_side_effect_table() {
        let cases = [
            (SideEffect::Read, false),
            (SideEffect::Draft, false),
            (SideEffect::Write, false),
            (SideEffect::Send, true),
            (SideEffect::Purchase, true),
            (SideEffect::Delete, true),
        ];

        for (effect, expected) in cases {
            assert_eq!(requires_confirmation_by_default(effect), expected);
            assert_eq!(
                default_confirmation_gate(effect).requires_human(),
                expected,
                "{effect:?}"
            );
        }
    }

    #[test]
    fn idempotency_defaults_match_beater_connect() {
        let cases = [
            (SideEffect::Read, false),
            (SideEffect::Draft, false),
            (SideEffect::Write, true),
            (SideEffect::Send, true),
            (SideEffect::Purchase, true),
            (SideEffect::Delete, true),
        ];

        for (effect, expected) in cases {
            assert_eq!(requires_idempotency(effect), expected, "{effect:?}");
            assert_eq!(
                decide_effect(effect, InputTaint::CLEAN).idempotency_required,
                expected,
                "{effect:?}"
            );
        }
    }

    #[test]
    fn taint_escalates_every_side_effect_gate() {
        for effect in SIDE_EFFECTS {
            let clean = decide_effect(effect, InputTaint::CLEAN);
            let tainted = decide_effect(effect, InputTaint::TAINTED);

            assert!(tainted.gate > clean.gate, "{effect:?}");
            assert_eq!(tainted.gate, clean.gate.escalate_for_taint(), "{effect:?}");
        }
    }

    #[test]
    fn tainted_dangerous_effects_require_explicit_taint_review() {
        for effect in [SideEffect::Send, SideEffect::Purchase, SideEffect::Delete] {
            let decision = decide_effect(effect, InputTaint::TAINTED);
            assert!(decision.requires_confirmation(), "{effect:?}");
            assert!(decision.requires_taint_review(), "{effect:?}");
        }
    }

    #[test]
    fn clean_read_and_draft_are_not_confirmed_or_idempotent() {
        for effect in [SideEffect::Read, SideEffect::Draft] {
            let decision = decide_effect(effect, InputTaint::CLEAN);
            assert!(!decision.requires_confirmation(), "{effect:?}");
            assert!(!decision.idempotency_required, "{effect:?}");
        }
    }

    #[test]
    fn action_decision_uses_schema_side_effect_classification() {
        let actions = [
            (
                Action::Goto {
                    url: "https://example.com".into(),
                },
                SideEffect::Read,
            ),
            (
                Action::Click {
                    node: NodeId("button".into()),
                },
                SideEffect::Write,
            ),
            (
                Action::Type {
                    node: NodeId("textbox".into()),
                    text: "hello".into(),
                },
                SideEffect::Write,
            ),
            (
                Action::Select {
                    node: NodeId("select".into()),
                    value: "a".into(),
                },
                SideEffect::Write,
            ),
            (Action::Scroll { x: 0.0, y: 100.0 }, SideEffect::Read),
            (
                Action::Extract {
                    node: NodeId("main".into()),
                },
                SideEffect::Read,
            ),
            (
                Action::Skill {
                    name: "checkout".into(),
                    input: serde_json::Value::Null,
                },
                SideEffect::Write,
            ),
        ];

        for (action, expected) in actions {
            let decision = decide_action(&action, InputTaint::CLEAN);
            assert_eq!(decision.side_effect, expected);
        }
    }

    #[test]
    fn input_taint_collapses_schema_spans() {
        let clean = [
            TaintSpan {
                provenance: Provenance::System,
                text: "tempo".into(),
            },
            TaintSpan {
                provenance: Provenance::User,
                text: "user intent".into(),
            },
        ];
        assert!(!InputTaint::from_spans(&clean).is_tainted());

        let tainted = [
            TaintSpan {
                provenance: Provenance::User,
                text: "user intent".into(),
            },
            TaintSpan {
                provenance: Provenance::Page,
                text: "page text".into(),
            },
        ];
        assert!(InputTaint::from_spans(&tainted).is_tainted());
    }

    #[test]
    fn decisions_are_deterministic() {
        for effect in SIDE_EFFECTS {
            let first = decide_effect(effect, InputTaint::TAINTED);
            let second = decide_effect(effect, InputTaint::TAINTED);
            assert_eq!(first, second, "{effect:?}");
        }
    }
}
