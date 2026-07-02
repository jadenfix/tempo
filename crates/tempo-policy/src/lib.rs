//! tempo-policy - pure action policy decisions keyed on `SideEffect`.
//!
//! The policy gate is intentionally a pure decision layer: callers provide the
//! action/effect plus whether any parameter was derived from tainted page spans,
//! and this crate returns the exact human-confirmation and idempotency
//! requirements. Execution, UI, and persistence stay outside this crate.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use tempo_schema::{Action, SideEffect, TaintSpan};
use url::{Host, Url};

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

    /// Raise the confirmation gate to at least `minimum` without weakening stricter gates.
    pub fn with_minimum_gate(mut self, minimum: ConfirmationGate) -> Self {
        if self.gate < minimum {
            self.gate = minimum;
        }
        self
    }
}

/// Canonical HTTP(S) origin used to key per-origin policy rules.
///
/// Values are serialized as `scheme://host[:non_default_port]`, with domains
/// lowercased, default ports omitted, and no path/query/fragment material.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin(String);

impl Origin {
    /// Parse an origin literal such as `https://example.com:8443`.
    pub fn parse(value: &str) -> Result<Self, OriginError> {
        let url = Url::parse(value).map_err(OriginError::invalid_url)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(OriginError::new(
                "origin rule must not include credentials, path, query, or fragment",
            ));
        }
        Self::from_parsed_url(url)
    }

    /// Extract and canonicalize the origin from a full URL.
    pub fn from_url(value: &str) -> Result<Self, OriginError> {
        let url = Url::parse(value).map_err(OriginError::invalid_url)?;
        Self::from_parsed_url(url)
    }

    /// Return the canonical origin string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_parsed_url(url: Url) -> Result<Self, OriginError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(OriginError::new(format!(
                "unsupported origin scheme {:?}",
                url.scheme()
            )));
        }

        let host = canonical_host(&url)?;
        let value = match url.port() {
            Some(port) => format!("{}://{}:{port}", url.scheme(), host),
            None => format!("{}://{}", url.scheme(), host),
        };
        Ok(Self(value))
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Origin {
    type Error = OriginError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl std::str::FromStr for Origin {
    type Err = OriginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn canonical_host(url: &Url) -> Result<String, OriginError> {
    match url.host() {
        Some(Host::Domain(host)) => Ok(host.to_ascii_lowercase()),
        Some(Host::Ipv4(addr)) => Ok(addr.to_string()),
        Some(Host::Ipv6(addr)) => Ok(format!("[{addr}]")),
        None => Err(OriginError::new("origin URL has no host")),
    }
}

/// Origin parse/canonicalization failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginError {
    reason: String,
}

impl OriginError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn invalid_url(error: url::ParseError) -> Self {
        Self::new(format!("invalid URL: {error}"))
    }

    /// Human-readable reason suitable for logs and policy-denial reports.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl Error for OriginError {}

/// Per-origin override applied after the global side-effect and taint policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginPolicyOverride {
    /// Do not add any origin-specific restriction; the global policy still applies.
    Allow,
    /// Require at least this confirmation level for the matching origin/effect.
    Require(ConfirmationGate),
    /// Block the action for the matching origin/effect.
    Deny { reason: String },
}

/// One deterministic origin-scoped policy rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPolicyRule {
    pub origin: Origin,
    /// `None` applies to all side effects for this origin.
    pub side_effect: Option<SideEffect>,
    pub override_: OriginPolicyOverride,
}

impl OriginPolicyRule {
    /// Construct a rule for one origin and optional side-effect class.
    pub fn new(
        origin: Origin,
        side_effect: Option<SideEffect>,
        override_: OriginPolicyOverride,
    ) -> Self {
        Self {
            origin,
            side_effect,
            override_,
        }
    }

    /// Construct a rule that applies to every side-effect class for an origin.
    pub fn for_origin(origin: Origin, override_: OriginPolicyOverride) -> Self {
        Self::new(origin, None, override_)
    }

    /// Construct a rule that applies to one side-effect class for an origin.
    pub fn for_effect(
        origin: Origin,
        side_effect: SideEffect,
        override_: OriginPolicyOverride,
    ) -> Self {
        Self::new(origin, Some(side_effect), override_)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OriginRuleKey {
    origin: Origin,
    side_effect: Option<SideEffect>,
}

impl OriginRuleKey {
    fn new(origin: Origin, side_effect: Option<SideEffect>) -> Self {
        Self {
            origin,
            side_effect,
        }
    }
}

/// Deterministic set of exact-origin policy rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginPolicySet {
    rules: BTreeMap<OriginRuleKey, OriginPolicyRule>,
}

impl OriginPolicySet {
    /// Empty policy set: only the global side-effect/taint policy applies.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a policy set from rules. Later rules replace earlier rules with the same key.
    pub fn from_rules(rules: impl IntoIterator<Item = OriginPolicyRule>) -> Self {
        let mut set = Self::new();
        for rule in rules {
            set.insert(rule);
        }
        set
    }

    /// Insert or replace one exact-origin rule.
    pub fn insert(&mut self, rule: OriginPolicyRule) {
        let key = OriginRuleKey::new(rule.origin.clone(), rule.side_effect);
        self.rules.insert(key, rule);
    }

    /// Returns true when there are no origin-specific rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of stored rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Decide policy for a schema action at a canonical origin.
    pub fn decide_action(
        &self,
        origin: &Origin,
        action: &Action,
        input_taint: InputTaint,
    ) -> OriginPolicyOutcome {
        self.decide_effect(origin, action.side_effect(), input_taint)
    }

    /// Decide policy for a side-effect class at a canonical origin.
    pub fn decide_effect(
        &self,
        origin: &Origin,
        effect: SideEffect,
        input_taint: InputTaint,
    ) -> OriginPolicyOutcome {
        let decision = decide_effect(effect, input_taint);
        let Some(rule) = self.rule_for(origin, effect) else {
            return OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                origin: origin.clone(),
                decision,
            });
        };

        match &rule.override_ {
            OriginPolicyOverride::Allow => OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                origin: origin.clone(),
                decision,
            }),
            OriginPolicyOverride::Require(gate) => {
                OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                    origin: origin.clone(),
                    decision: decision.with_minimum_gate(*gate),
                })
            }
            OriginPolicyOverride::Deny { reason } => {
                OriginPolicyOutcome::Deny(OriginPolicyDenial {
                    origin: origin.clone(),
                    decision,
                    reason: reason.clone(),
                })
            }
        }
    }

    fn rule_for(&self, origin: &Origin, effect: SideEffect) -> Option<&OriginPolicyRule> {
        let exact = OriginRuleKey::new(origin.clone(), Some(effect));
        self.rules.get(&exact).or_else(|| {
            let wildcard = OriginRuleKey::new(origin.clone(), None);
            self.rules.get(&wildcard)
        })
    }
}

/// Origin-aware policy decision when an action is allowed to proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginScopedPolicyDecision {
    pub origin: Origin,
    pub decision: PolicyDecision,
}

/// Origin-aware policy denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPolicyDenial {
    pub origin: Origin,
    pub decision: PolicyDecision,
    pub reason: String,
}

/// Result of applying origin-scoped rules after global policy classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginPolicyOutcome {
    Allow(OriginScopedPolicyDecision),
    Deny(OriginPolicyDenial),
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

    #[test]
    fn origin_from_url_canonicalizes_without_sensitive_parts() -> Result<(), OriginError> {
        let origin = Origin::from_url("https://User:Secret@Example.COM:443/path?q=secret#frag")?;
        assert_eq!(origin.as_str(), "https://example.com");
        assert!(!origin.as_str().contains("Secret"));
        assert!(!origin.as_str().contains("path"));

        let custom = Origin::from_url("http://[::1]:3000/page")?;
        assert_eq!(custom.as_str(), "http://[::1]:3000");
        Ok(())
    }

    #[test]
    fn origin_rule_literals_reject_non_origin_material() {
        for value in [
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com?q=secret",
            "https://example.com#frag",
            "file:///tmp/page.html",
        ] {
            assert!(Origin::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn origin_policy_requires_minimum_gate_without_weakening_taint() -> Result<(), OriginError> {
        let origin = Origin::parse("https://checkout.example")?;
        let policies = OriginPolicySet::from_rules([OriginPolicyRule::for_origin(
            origin.clone(),
            OriginPolicyOverride::Require(ConfirmationGate::Confirm),
        )]);

        let clean = policies.decide_effect(&origin, SideEffect::Write, InputTaint::CLEAN);
        let tainted = policies.decide_effect(&origin, SideEffect::Write, InputTaint::TAINTED);
        let dangerous_tainted =
            policies.decide_effect(&origin, SideEffect::Send, InputTaint::TAINTED);

        assert_eq!(
            clean,
            OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                origin: origin.clone(),
                decision: PolicyDecision {
                    side_effect: SideEffect::Write,
                    input_taint: InputTaint::CLEAN,
                    gate: ConfirmationGate::Confirm,
                    idempotency_required: true,
                },
            })
        );
        assert_eq!(
            tainted,
            OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                origin,
                decision: PolicyDecision {
                    side_effect: SideEffect::Write,
                    input_taint: InputTaint::TAINTED,
                    gate: ConfirmationGate::Confirm,
                    idempotency_required: true,
                },
            })
        );
        assert!(matches!(
            dangerous_tainted,
            OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                decision: PolicyDecision {
                    gate: ConfirmationGate::ConfirmWithTaintReview,
                    ..
                },
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn specific_origin_rule_overrides_origin_wildcard() -> Result<(), OriginError> {
        let origin = Origin::parse("https://mail.example")?;
        let policies = OriginPolicySet::from_rules([
            OriginPolicyRule::for_origin(
                origin.clone(),
                OriginPolicyOverride::Require(ConfirmationGate::Confirm),
            ),
            OriginPolicyRule::for_effect(
                origin.clone(),
                SideEffect::Send,
                OriginPolicyOverride::Deny {
                    reason: "sending disabled for this origin".into(),
                },
            ),
        ]);

        let write = policies.decide_effect(&origin, SideEffect::Write, InputTaint::CLEAN);
        let send = policies.decide_effect(&origin, SideEffect::Send, InputTaint::CLEAN);

        assert!(matches!(
            write,
            OriginPolicyOutcome::Allow(OriginScopedPolicyDecision {
                decision: PolicyDecision {
                    gate: ConfirmationGate::Confirm,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            send,
            OriginPolicyOutcome::Deny(OriginPolicyDenial {
                decision: PolicyDecision {
                    side_effect: SideEffect::Send,
                    ..
                },
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn origin_policy_is_exact_origin_scoped() -> Result<(), OriginError> {
        let origin = Origin::parse("https://example.com")?;
        let different_port = Origin::parse("https://example.com:8443")?;
        let policies = OriginPolicySet::from_rules([OriginPolicyRule::for_origin(
            origin.clone(),
            OriginPolicyOverride::Deny {
                reason: "blocked".into(),
            },
        )]);

        assert!(matches!(
            policies.decide_effect(&origin, SideEffect::Read, InputTaint::CLEAN),
            OriginPolicyOutcome::Deny(_)
        ));
        assert!(matches!(
            policies.decide_effect(&different_port, SideEffect::Read, InputTaint::CLEAN),
            OriginPolicyOutcome::Allow(_)
        ));
        Ok(())
    }
}
