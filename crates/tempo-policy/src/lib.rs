//! tempo-policy - pure action policy decisions keyed on `SideEffect`.
//!
//! The policy gate is intentionally a pure decision layer: callers provide the
//! action/effect plus whether any parameter was derived from tainted page spans,
//! and this crate returns the exact human-confirmation and idempotency
//! requirements. Execution, UI, and persistence stay outside this crate.

use tempo_schema::{Action, SideEffect, TaintSpan};
use thiserror::Error;

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

/// Canonical web origin used for origin-scoped policy rules.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl Origin {
    pub fn parse(url: &str) -> Result<Self, OriginError> {
        let parsed = url::Url::parse(url)?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let lowercased = parsed
            .host_str()
            .ok_or(OriginError::MissingHost)?
            .to_ascii_lowercase();
        // Canonicalize the fully-qualified form `example.com.` to `example.com`
        // so exact-equality matching cannot be bypassed with a trailing dot.
        let host = lowercased.strip_suffix('.').unwrap_or(&lowercased);
        if host.is_empty() {
            return Err(OriginError::MissingHost);
        }
        let port = parsed.port_or_known_default();
        Ok(Self {
            scheme,
            host: host.to_owned(),
            port,
        })
    }

    pub fn matches_url(&self, url: &str) -> Result<bool, OriginError> {
        Ok(&Self::parse(url)? == self)
    }
}

#[derive(Debug, Error)]
pub enum OriginError {
    #[error("invalid URL for origin policy: {0}")]
    Url(#[from] url::ParseError),
    #[error("URL has no host for origin policy")]
    MissingHost,
}

/// Per-origin action taken for effects at or above a configured side-effect level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OriginRuleMode {
    /// Apply normal side-effect and taint rules.
    Default,
    /// Require a human confirmation even for lower-risk effects.
    RequireConfirmation,
    /// Require the confirmation UI to expose page-derived input provenance.
    RequireTaintReview,
    /// Reject the action before execution.
    Block,
}

/// One deterministic origin-scoped policy rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginRule {
    pub origin: Origin,
    pub applies_from: SideEffect,
    pub mode: OriginRuleMode,
}

impl OriginRule {
    pub fn new(origin: Origin, applies_from: SideEffect, mode: OriginRuleMode) -> Self {
        Self {
            origin,
            applies_from,
            mode,
        }
    }

    pub fn applies_to(&self, origin: &Origin, effect: SideEffect) -> bool {
        &self.origin == origin && effect >= self.applies_from
    }
}

/// Pure rule table for origin-specific policy decisions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginPolicy {
    rules: Vec<OriginRule>,
}

impl OriginPolicy {
    pub fn new(rules: Vec<OriginRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[OriginRule] {
        &self.rules
    }

    pub fn push(&mut self, rule: OriginRule) {
        self.rules.push(rule);
    }

    pub fn decide_effect(
        &self,
        origin: Option<&Origin>,
        effect: SideEffect,
        input_taint: InputTaint,
    ) -> ScopedPolicyDecision {
        let mut decision = decide_effect(effect, InputTaint::CLEAN);
        let mut strongest_rule = OriginRuleMode::Default;
        let mut matched_rules = 0_usize;

        if let Some(origin) = origin {
            for rule in &self.rules {
                if rule.applies_to(origin, effect) {
                    matched_rules += 1;
                    strongest_rule = strongest_rule.max(rule.mode);
                }
            }
        }

        match strongest_rule {
            OriginRuleMode::Default => {}
            OriginRuleMode::RequireConfirmation => {
                decision.gate = decision.gate.max(ConfirmationGate::Confirm);
            }
            OriginRuleMode::RequireTaintReview => {
                decision.gate = decision.gate.max(ConfirmationGate::ConfirmWithTaintReview);
            }
            OriginRuleMode::Block => {}
        }
        if input_taint.is_tainted() {
            decision.gate = decision.gate.escalate_for_taint();
        }
        decision.input_taint = input_taint;

        ScopedPolicyDecision {
            decision,
            origin: origin.cloned(),
            matched_rules,
            rule_mode: strongest_rule,
        }
    }

    pub fn decide_action(
        &self,
        origin: Option<&Origin>,
        action: &Action,
        input_taint: InputTaint,
    ) -> ScopedPolicyDecision {
        self.decide_effect(origin, action.side_effect(), input_taint)
    }
}

/// Policy decision after origin-scoped rules have been applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedPolicyDecision {
    pub decision: PolicyDecision,
    pub origin: Option<Origin>,
    pub matched_rules: usize,
    pub rule_mode: OriginRuleMode,
}

impl ScopedPolicyDecision {
    pub fn blocked(&self) -> bool {
        self.rule_mode == OriginRuleMode::Block
    }

    pub fn requires_confirmation(&self) -> bool {
        !self.blocked() && self.decision.requires_confirmation()
    }
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
    use proptest::prelude::*;
    use tempo_schema::{NodeId, Provenance};

    fn side_effect_strategy() -> impl Strategy<Value = SideEffect> {
        prop_oneof![
            Just(SideEffect::Read),
            Just(SideEffect::Draft),
            Just(SideEffect::Write),
            Just(SideEffect::Send),
            Just(SideEffect::Purchase),
            Just(SideEffect::Delete),
        ]
    }

    fn provenance_strategy() -> impl Strategy<Value = Provenance> {
        prop_oneof![
            Just(Provenance::System),
            Just(Provenance::User),
            Just(Provenance::Page),
        ]
    }

    fn origin_rule_mode_strategy() -> impl Strategy<Value = OriginRuleMode> {
        prop_oneof![
            Just(OriginRuleMode::Default),
            Just(OriginRuleMode::RequireConfirmation),
            Just(OriginRuleMode::RequireTaintReview),
            Just(OriginRuleMode::Block),
        ]
    }

    fn stable_test_origin() -> Origin {
        Origin {
            scheme: "https".into(),
            host: "bank.example".into(),
            port: Some(443),
        }
    }

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
            (Action::Wait { millis: 250 }, SideEffect::Read),
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

    #[test]
    fn origin_parsing_canonicalizes_scheme_host_and_default_port() -> Result<(), OriginError> {
        let origin = Origin::parse("HTTPS://Example.COM/path?x=1")?;

        assert_eq!(
            origin,
            Origin {
                scheme: "https".into(),
                host: "example.com".into(),
                port: Some(443),
            }
        );
        assert!(origin.matches_url("https://example.com:443/other")?);
        Ok(())
    }

    #[test]
    fn origin_parse_strips_trailing_dot_fqdn() -> Result<(), OriginError> {
        // A trailing-dot FQDN canonicalizes to the same origin as its
        // dotless form, including with mixed case.
        let dotted = Origin::parse("https://a.")?;
        let plain = Origin::parse("https://a")?;
        assert_eq!(dotted, plain);
        assert_eq!(dotted.host, "a");

        assert_eq!(
            Origin::parse("https://SHOP.EXAMPLE.")?,
            Origin::parse("https://shop.example")?
        );
        Ok(())
    }

    #[test]
    fn origin_parse_rejects_empty_or_dot_only_host() {
        // A host that is empty after stripping the trailing dot must be rejected
        // rather than canonicalizing to an empty string that could match loosely.
        assert!(matches!(
            Origin::parse("https://./path"),
            Err(OriginError::MissingHost) | Err(OriginError::Url(_))
        ));
    }

    #[test]
    fn block_rule_matches_trailing_dot_navigation() -> Result<(), OriginError> {
        // Regression for #169: a Block rule for `https://shop.example` must gate
        // a navigation to the same DNS server addressed as `https://shop.example.`.
        let rule_origin = Origin::parse("https://shop.example")?;
        let policy = OriginPolicy::new(vec![OriginRule::new(
            rule_origin,
            SideEffect::Purchase,
            OriginRuleMode::Block,
        )]);

        for url in [
            "https://shop.example./checkout",
            "https://SHOP.EXAMPLE./checkout",
        ] {
            let request_origin = Origin::parse(url)?;
            let decision = policy.decide_effect(
                Some(&request_origin),
                SideEffect::Purchase,
                InputTaint::CLEAN,
            );
            assert!(
                decision.blocked(),
                "trailing-dot origin must be blocked: {url}"
            );
            assert_eq!(decision.matched_rules, 1, "{url}");
        }
        Ok(())
    }

    #[test]
    fn matches_url_treats_trailing_dot_host_as_equal() -> Result<(), OriginError> {
        let origin = Origin::parse("https://shop.example")?;
        assert!(origin.matches_url("https://shop.example./checkout")?);
        assert!(origin.matches_url("https://SHOP.EXAMPLE.")?);
        Ok(())
    }

    #[test]
    fn origin_rule_can_require_confirmation_for_write_actions() -> Result<(), OriginError> {
        let origin = Origin::parse("https://accounts.example")?;
        let policy = OriginPolicy::new(vec![OriginRule::new(
            origin.clone(),
            SideEffect::Write,
            OriginRuleMode::RequireConfirmation,
        )]);

        let decision = policy.decide_effect(Some(&origin), SideEffect::Write, InputTaint::CLEAN);

        assert_eq!(decision.matched_rules, 1);
        assert_eq!(decision.rule_mode, OriginRuleMode::RequireConfirmation);
        assert_eq!(decision.decision.gate, ConfirmationGate::Confirm);
        assert!(decision.requires_confirmation());
        Ok(())
    }

    #[test]
    fn origin_rule_can_block_high_risk_effects() -> Result<(), OriginError> {
        let origin = Origin::parse("https://shop.example")?;
        let policy = OriginPolicy::new(vec![OriginRule::new(
            origin.clone(),
            SideEffect::Purchase,
            OriginRuleMode::Block,
        )]);

        let decision = policy.decide_effect(Some(&origin), SideEffect::Purchase, InputTaint::CLEAN);

        assert!(decision.blocked());
        assert!(!decision.requires_confirmation());
        assert!(decision.decision.idempotency_required);
        Ok(())
    }

    #[test]
    fn taint_and_origin_rules_compose_to_taint_review() -> Result<(), OriginError> {
        let origin = Origin::parse("https://mail.example")?;
        let policy = OriginPolicy::new(vec![OriginRule::new(
            origin.clone(),
            SideEffect::Write,
            OriginRuleMode::RequireConfirmation,
        )]);

        let decision = policy.decide_effect(Some(&origin), SideEffect::Write, InputTaint::TAINTED);

        assert_eq!(
            decision.decision.gate,
            ConfirmationGate::ConfirmWithTaintReview
        );
        assert!(decision.decision.requires_taint_review());
        Ok(())
    }

    #[test]
    fn strongest_matching_origin_rule_wins_independent_of_order() -> Result<(), OriginError> {
        let origin = Origin::parse("https://bank.example")?;
        let weaker = OriginRule::new(
            origin.clone(),
            SideEffect::Write,
            OriginRuleMode::RequireConfirmation,
        );
        let stronger = OriginRule::new(
            origin.clone(),
            SideEffect::Write,
            OriginRuleMode::RequireTaintReview,
        );
        let first = OriginPolicy::new(vec![weaker.clone(), stronger.clone()]);
        let second = OriginPolicy::new(vec![stronger, weaker]);

        let first_decision =
            first.decide_effect(Some(&origin), SideEffect::Send, InputTaint::CLEAN);
        let second_decision =
            second.decide_effect(Some(&origin), SideEffect::Send, InputTaint::CLEAN);

        assert_eq!(first_decision, second_decision);
        assert_eq!(
            first_decision.decision.gate,
            ConfirmationGate::ConfirmWithTaintReview
        );
        assert_eq!(first_decision.matched_rules, 2);
        Ok(())
    }

    proptest! {
        #[test]
        fn taint_escalation_is_exact_for_every_side_effect(effect in side_effect_strategy()) {
            let clean = decide_effect(effect, InputTaint::CLEAN);
            let tainted = decide_effect(effect, InputTaint::TAINTED);

            prop_assert_eq!(tainted.side_effect, clean.side_effect);
            prop_assert_eq!(tainted.input_taint, InputTaint::TAINTED);
            prop_assert_eq!(tainted.idempotency_required, clean.idempotency_required);
            prop_assert_eq!(tainted.gate, clean.gate.escalate_for_taint());
            prop_assert!(tainted.gate > clean.gate);
        }

        #[test]
        fn dangerous_effects_are_confirm_by_default_and_taint_review_when_tainted(
            effect in side_effect_strategy(),
        ) {
            let clean = decide_effect(effect, InputTaint::CLEAN);
            let tainted = decide_effect(effect, InputTaint::TAINTED);
            let dangerous = matches!(
                effect,
                SideEffect::Send | SideEffect::Purchase | SideEffect::Delete
            );

            prop_assert_eq!(requires_confirmation_by_default(effect), dangerous);
            prop_assert_eq!(clean.requires_confirmation(), dangerous);
            prop_assert_eq!(clean.gate, default_confirmation_gate(effect));

            if dangerous {
                prop_assert_eq!(clean.gate, ConfirmationGate::Confirm);
                prop_assert_eq!(tainted.gate, ConfirmationGate::ConfirmWithTaintReview);
                prop_assert!(tainted.requires_taint_review());
            } else {
                prop_assert_eq!(clean.gate, ConfirmationGate::None);
                prop_assert_eq!(tainted.gate, ConfirmationGate::Confirm);
                prop_assert!(!tainted.requires_taint_review());
            }
        }

        #[test]
        fn span_taint_collapses_to_any_page_provenance(
            provenances in prop::collection::vec(provenance_strategy(), 0..64),
        ) {
            let spans = provenances
                .iter()
                .enumerate()
                .map(|(index, provenance)| TaintSpan {
                    provenance: *provenance,
                    text: format!("span-{index}"),
                })
                .collect::<Vec<_>>();
            let expected = provenances
                .iter()
                .any(|provenance| matches!(provenance, Provenance::Page));

            prop_assert_eq!(InputTaint::from_spans(&spans).is_tainted(), expected);
        }

        #[test]
        fn origin_policy_decisions_are_deterministic_for_any_rule_set(
            effect in side_effect_strategy(),
            tainted in any::<bool>(),
            rules in prop::collection::vec(
                (side_effect_strategy(), origin_rule_mode_strategy()),
                0..32,
            ),
        ) {
            let origin = stable_test_origin();
            let rules = rules
                .into_iter()
                .map(|(applies_from, mode)| OriginRule::new(origin.clone(), applies_from, mode))
                .collect::<Vec<_>>();
            let policy = OriginPolicy::new(rules);
            let input_taint = InputTaint::new(tainted);

            let first = policy.decide_effect(Some(&origin), effect, input_taint);
            let second = policy.decide_effect(Some(&origin), effect, input_taint);

            prop_assert_eq!(first, second);
        }

        #[test]
        fn strongest_origin_rule_is_order_independent(
            effect in side_effect_strategy(),
            tainted in any::<bool>(),
            rules in prop::collection::vec(
                (side_effect_strategy(), origin_rule_mode_strategy()),
                0..32,
            ),
        ) {
            let origin = stable_test_origin();
            let forward_rules = rules
                .iter()
                .copied()
                .map(|(applies_from, mode)| OriginRule::new(origin.clone(), applies_from, mode))
                .collect::<Vec<_>>();
            let reverse_rules = rules
                .iter()
                .rev()
                .copied()
                .map(|(applies_from, mode)| OriginRule::new(origin.clone(), applies_from, mode))
                .collect::<Vec<_>>();
            let forward = OriginPolicy::new(forward_rules);
            let reverse = OriginPolicy::new(reverse_rules);
            let input_taint = InputTaint::new(tainted);

            let forward_decision = forward.decide_effect(Some(&origin), effect, input_taint);
            let reverse_decision = reverse.decide_effect(Some(&origin), effect, input_taint);

            prop_assert_eq!(forward_decision, reverse_decision);
        }

        #[test]
        fn origin_rules_and_taint_escalation_compose_exactly_once(
            effect in side_effect_strategy(),
            rules in prop::collection::vec(
                (side_effect_strategy(), origin_rule_mode_strategy()),
                0..32,
            ),
        ) {
            let origin = stable_test_origin();
            let policy = OriginPolicy::new(
                rules
                    .into_iter()
                    .map(|(applies_from, mode)| {
                        OriginRule::new(origin.clone(), applies_from, mode)
                    })
                    .collect(),
            );

            let clean = policy.decide_effect(Some(&origin), effect, InputTaint::CLEAN);
            let tainted = policy.decide_effect(Some(&origin), effect, InputTaint::TAINTED);

            prop_assert_eq!(&tainted.origin, &clean.origin);
            prop_assert_eq!(tainted.matched_rules, clean.matched_rules);
            prop_assert_eq!(tainted.rule_mode, clean.rule_mode);
            prop_assert_eq!(tainted.blocked(), clean.blocked());
            prop_assert_eq!(
                tainted.decision.gate,
                clean.decision.gate.escalate_for_taint()
            );
        }
    }
}
