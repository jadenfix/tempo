//! Window-free agent-panel logic: the journal/event stream, the set-of-marks
//! toggle state, and the taint-badge derivation.
//!
//! Like [`crate::tab`] and [`crate::ui`], every type here is pure data with pure
//! methods — no winit/egui, no socket, no I/O — so the agent panel's behaviour is
//! unit-testable in headless CI. The eframe loop in [`crate::window`] only renders
//! these structs.
//!
//! Nothing here introduces new backend state. The journal is the *existing*
//! `/sessions/{id}/events` stream ([`TempodSessionEvent`]); the taint badge is
//! [`tempo_taint::contains_untrusted`] evaluated over the taint spans already
//! carried on the step observation-diff those events emit.

use std::collections::HashSet;
#[cfg(test)]
use tempo_headless::SessionStepKey;
use tempo_headless::{
    SessionStepOutcome, SessionStepTriple, TempodSessionEvent, TempodSessionEventKind,
};
use tempo_schema::{Action, HumanTakeover, InteractiveElement, NodeId, ObservationDiff, TaintSpan};

/// The taint badge state, derived from the latest step's observation spans.
/// Always visible in the chrome; `Unknown` until the first observation-bearing
/// event arrives for the active session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TaintState {
    /// No observation seen yet for the active session.
    #[default]
    Unknown,
    /// The latest step's observation spans are all trusted (system/user).
    Clean,
    /// The latest step's observation contains untrusted page-derived spans.
    Tainted,
}

impl TaintState {
    /// Short, stable label for the badge.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "taint: unknown",
            Self::Clean => "taint: clean",
            Self::Tainted => "taint: UNTRUSTED",
        }
    }

    /// Whether the badge should read as "on" (untrusted content present).
    pub const fn is_tainted(self) -> bool {
        matches!(self, Self::Tainted)
    }

    /// Whether a single observation diff *introduces* untrusted content: `Tainted`
    /// iff any added/changed element's name/value spans cross the untrusted page
    /// boundary. This is a per-step predicate (used for the journal line flag);
    /// the always-visible session badge is [`JournalLog::taint`], which is sticky
    /// across steps because a diff is a delta (see [`JournalLog`]).
    pub fn from_diff(diff: &ObservationDiff) -> Self {
        if tempo_taint::contains_untrusted(diff_spans(diff)) {
            Self::Tainted
        } else {
            Self::Clean
        }
    }
}

/// Every taint-labeled span an observation diff introduces or changes, in element
/// order (name spans then value spans). This is the span set the trust boundary
/// labels; the badge collapses it with [`tempo_taint::contains_untrusted`].
pub fn diff_spans(diff: &ObservationDiff) -> impl Iterator<Item = &TaintSpan> {
    element_spans(&diff.added).chain(element_spans(&diff.changed))
}

fn element_spans(elements: &[InteractiveElement]) -> impl Iterator<Item = &TaintSpan> {
    elements
        .iter()
        .flat_map(|element| element.name.iter().chain(element.value.iter()))
}

/// Whether a single element carries untrusted page-derived spans.
fn element_is_tainted(element: &InteractiveElement) -> bool {
    tempo_taint::contains_untrusted(element.name.iter().chain(element.value.iter()))
}

/// One rendered line in the journal log: the ordered, display-flattened form of a
/// [`TempodSessionEvent`], matching the `SessionRow` pattern so the renderer stays
/// trivial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub seq: u64,
    /// Short event-kind label (`session_created`, `step`, …).
    pub kind: String,
    /// One-line human summary (url, action → outcome).
    pub detail: String,
    /// Whether this event carried an untrusted observation.
    pub tainted: bool,
}

impl JournalEntry {
    fn from_event(event: &TempodSessionEvent) -> Self {
        let (kind, detail, tainted) = match &event.event {
            TempodSessionEventKind::SessionCreated { url } => {
                ("session_created", url.clone(), false)
            }
            TempodSessionEventKind::SessionAdopted => ("session_adopted", String::new(), false),
            TempodSessionEventKind::SessionResumed => ("session_resumed", String::new(), false),
            TempodSessionEventKind::SessionKilled => ("session_killed", String::new(), false),
            TempodSessionEventKind::SessionDrained => ("session_drained", String::new(), false),
            TempodSessionEventKind::StepTriple { triple } => {
                ("step", step_detail(triple), step_is_tainted(triple))
            }
            TempodSessionEventKind::HumanTakeoverRequired { takeover } => (
                "human_takeover_required",
                format!("{} — {}", takeover.kind.label(), takeover.url),
                false,
            ),
            TempodSessionEventKind::BrowserHardeningBlocked { block } => (
                "browser_hardening_blocked",
                format!("{}: {}", block.reason, block.url),
                false,
            ),
        };
        Self {
            seq: event.seq,
            kind: kind.to_string(),
            detail,
            tainted,
        }
    }
}

/// Whether a step's applied observation diff carries untrusted page spans. A
/// step error carries no new observation, so it is treated as untainted.
fn step_is_tainted(triple: &SessionStepTriple) -> bool {
    match &triple.outcome {
        SessionStepOutcome::Applied { diff } => tempo_taint::contains_untrusted(diff_spans(diff)),
        SessionStepOutcome::StepError { .. } => false,
    }
}

fn step_detail(triple: &SessionStepTriple) -> String {
    let outcome = match &triple.outcome {
        SessionStepOutcome::Applied { .. } => "applied".to_string(),
        SessionStepOutcome::StepError { reason } => format!("error: {reason}"),
    };
    format!("{} → {outcome}", action_kind(&triple.action))
}

fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::Goto { .. } => "goto",
        Action::Click { .. } => "click",
        Action::Type { .. } => "type",
        Action::Select { .. } => "select",
        Action::Scroll { .. } => "scroll",
        Action::Wait { .. } => "wait",
        Action::Extract { .. } => "extract",
        Action::Skill { .. } => "skill",
    }
}

/// The blocking human-takeover banner state, derived purely from the session
/// event stream (#354, over the #343 seam).
///
/// When [`TempodSessionEventKind::HumanTakeoverRequired`] surfaces for the active
/// session, [`Self::raise`] latches the [`HumanTakeover`] and [`Self::is_blocking`]
/// reads `true`. It stays blocking — the shell must not auto-advance the agent —
/// until a human explicitly clicks Resume ([`Self::resume`]).
///
/// **Never auto-continues (#343 semantics):** [`Self::resume`] only clears the
/// *local* block. Takeover detection is pure over the observation, so a resumed
/// run that re-observes the same unresolved challenge journals the takeover again,
/// which re-surfaces here on the next poll. The banner therefore re-appears until
/// the human has actually cleared the challenge in the page — it never silently
/// waves the agent past an unresolved CAPTCHA/auth-wall.
///
/// **Resume transport:** the shell can now POST an auditable resume signal to
/// tempod. That signal does not solve the challenge or force an agent step; it
/// records that the human handed control back, and the next observation can
/// still raise a fresh takeover event if the challenge remains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TakeoverBanner {
    /// The latched takeover the human must resolve, if any.
    pending: Option<HumanTakeover>,
}

impl TakeoverBanner {
    /// The pending takeover the human must resolve, if the banner is up.
    pub fn pending(&self) -> Option<&HumanTakeover> {
        self.pending.as_ref()
    }

    /// Whether the shell is blocked on a human takeover (banner up). While this is
    /// `true` the agent must not be auto-advanced.
    pub fn is_blocking(&self) -> bool {
        self.pending.is_some()
    }

    /// The takeover-kind label (`captcha` / `auth_wall` / `login_required`) for
    /// the banner heading, if a takeover is pending.
    pub fn reason_label(&self) -> Option<&'static str> {
        self.pending.as_ref().map(|takeover| takeover.kind.label())
    }

    /// A single-line banner summary — kind, reason, and URL — for the renderer, if
    /// a takeover is pending. Kept here (not in the winit glue) so it is testable.
    pub fn banner_line(&self) -> Option<String> {
        self.pending.as_ref().map(|takeover| {
            format!(
                "Human takeover required ({}): {} — {}",
                takeover.kind.label(),
                takeover.reason,
                takeover.url
            )
        })
    }

    /// Latch a detected takeover. Idempotent for the same page: re-raising simply
    /// keeps the latest detection.
    fn raise(&mut self, takeover: HumanTakeover) {
        self.pending = Some(takeover);
    }

    /// Human clicked Resume: clear the local block. See the type docs — this does
    /// not auto-continue past an unresolved challenge, and the actual run-resume
    /// wire call is a documented follow-up.
    pub fn resume(&mut self) {
        self.pending = None;
    }
}

/// The ordered, deduplicated journal-event log for one session, plus the session
/// taint state accumulated across its observation-bearing events.
///
/// The log is append-only within a session: [`Self::ingest`] takes a page of
/// events fetched with `after_seq = cursor` and drops any it has already seen, so
/// re-polling never duplicates a line. Switching the active session
/// ([`Self::follow`]) resets the log and the cursor.
///
/// The taint badge is **sticky**, because an [`ObservationDiff`] is a delta: an
/// untrusted element that stays on the page unchanged across steps appears in
/// neither `added` nor `changed`, so recomputing per-step would flip the badge
/// back to `Clean` while the threat is still present — a security false-negative.
/// Instead we track the *identities* ([`NodeId`]) of currently-untrusted
/// elements: each step adds newly-tainted added/changed nodes, drops nodes that
/// became clean (re-observed in `changed`) or left the page (`removed`), and the
/// badge reads [`TaintState::Tainted`] iff that set is non-empty. Persistence
/// stays tainted; the badge clears only when the untrusted content actually goes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalLog {
    /// The session this log is currently following, if any.
    pub session_id: Option<String>,
    /// Entries in seq order (oldest first) — the scrolling log.
    pub entries: Vec<JournalEntry>,
    /// Highest seq ingested; the `after_seq` cursor for the next poll.
    pub cursor: Option<u64>,
    /// Node identities currently carrying untrusted page-derived spans.
    tainted_nodes: HashSet<NodeId>,
    /// Whether any observation-bearing step has been seen for this session.
    observed: bool,
    /// The blocking human-takeover banner for this session (#354). Set when a
    /// `HumanTakeoverRequired` event is ingested; cleared on Resume or a session
    /// switch.
    takeover: TakeoverBanner,
}

impl JournalLog {
    /// The always-visible session taint badge: `Unknown` until the first
    /// observation-bearing step, then `Tainted` while any untrusted element is
    /// present on the page and `Clean` once they are all gone.
    pub fn taint(&self) -> TaintState {
        if !self.observed {
            TaintState::Unknown
        } else if self.tainted_nodes.is_empty() {
            TaintState::Clean
        } else {
            TaintState::Tainted
        }
    }

    /// The blocking human-takeover banner for the active session (#354).
    pub fn takeover(&self) -> &TakeoverBanner {
        &self.takeover
    }

    /// Human clicked Resume after the backend accepted the signal: clear the
    /// blocking takeover banner. See [`TakeoverBanner::resume`] — this never
    /// auto-continues past an unresolved challenge.
    pub fn resume_takeover(&mut self) {
        self.takeover.resume();
    }

    /// Point the log at `session_id`, clearing entries/cursor/taint/takeover if it
    /// changed. Returns the cursor the next poll should use (`None` on a fresh
    /// session).
    pub fn follow(&mut self, session_id: &str) -> Option<u64> {
        if self.session_id.as_deref() != Some(session_id) {
            self.session_id = Some(session_id.to_string());
            self.entries.clear();
            self.cursor = None;
            self.tainted_nodes.clear();
            self.observed = false;
            self.takeover = TakeoverBanner::default();
        }
        self.cursor
    }

    /// Append a fetched page of events in seq order, skipping any at or below the
    /// cursor, and fold each step's observation diff into the sticky taint set.
    pub fn ingest(&mut self, events: &[TempodSessionEvent]) {
        let mut fresh: Vec<&TempodSessionEvent> = events
            .iter()
            .filter(|event| self.cursor.is_none_or(|cursor| event.seq > cursor))
            .collect();
        fresh.sort_by_key(|event| event.seq);
        for event in fresh {
            match &event.event {
                TempodSessionEventKind::StepTriple { triple } => {
                    if let SessionStepOutcome::Applied { diff } = &triple.outcome {
                        self.accumulate_taint(diff);
                    }
                }
                TempodSessionEventKind::HumanTakeoverRequired { takeover } => {
                    self.takeover.raise(takeover.clone());
                }
                _ => {}
            }
            self.cursor = Some(
                self.cursor
                    .map_or(event.seq, |cursor| cursor.max(event.seq)),
            );
            self.entries.push(JournalEntry::from_event(event));
        }
    }

    /// Fold one applied observation diff into the tainted-node set: add
    /// newly-untrusted added/changed nodes, drop nodes that became clean or were
    /// removed. `removed` is applied last so a removal always wins.
    fn accumulate_taint(&mut self, diff: &ObservationDiff) {
        self.observed = true;
        for element in diff.added.iter().chain(diff.changed.iter()) {
            if element_is_tainted(element) {
                self.tainted_nodes.insert(element.node_id.clone());
            } else {
                self.tainted_nodes.remove(&element.node_id);
            }
        }
        for node in &diff.removed {
            self.tainted_nodes.remove(node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_headless::TempodSessionId;
    use tempo_schema::{NodeId, Provenance, TakeoverKind};

    fn span(provenance: Provenance, text: &str) -> TaintSpan {
        TaintSpan {
            provenance,
            text: text.to_string(),
        }
    }

    fn element(node_id: &str, spans: Vec<TaintSpan>) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(node_id.to_string()),
            role: "textbox".to_string(),
            name: spans,
            value: Vec::new(),
            bounds: None,
            rank: 1.0,
        }
    }

    fn diff_with(added: Vec<InteractiveElement>) -> ObservationDiff {
        ObservationDiff {
            since_seq: 0,
            seq: 1,
            omitted: 0,
            added,
            removed: Vec::new(),
            changed: Vec::new(),
        }
    }

    fn diff_added_changed_removed(
        added: Vec<InteractiveElement>,
        changed: Vec<InteractiveElement>,
        removed: Vec<NodeId>,
    ) -> ObservationDiff {
        ObservationDiff {
            since_seq: 0,
            seq: 1,
            omitted: 0,
            added,
            removed,
            changed,
        }
    }

    fn step_event(seq: u64, diff: ObservationDiff) -> TempodSessionEvent {
        let triple = SessionStepTriple {
            key: SessionStepKey("step-key".to_string()),
            seq,
            action: Action::Goto {
                url: "https://step.test".to_string(),
            },
            outcome: SessionStepOutcome::Applied { diff },
        };
        TempodSessionEvent {
            session_id: TempodSessionId("session-0".to_string()),
            seq,
            timestamp_ms: 0,
            event: TempodSessionEventKind::StepTriple { triple },
        }
    }

    fn created_event(seq: u64) -> TempodSessionEvent {
        TempodSessionEvent {
            session_id: TempodSessionId("session-0".to_string()),
            seq,
            timestamp_ms: 0,
            event: TempodSessionEventKind::SessionCreated {
                url: "https://created.test".to_string(),
            },
        }
    }

    fn takeover_event(seq: u64, kind: TakeoverKind) -> TempodSessionEvent {
        TempodSessionEvent {
            session_id: TempodSessionId("session-0".to_string()),
            seq,
            timestamp_ms: 0,
            event: TempodSessionEventKind::HumanTakeoverRequired {
                takeover: HumanTakeover {
                    kind,
                    reason: "challenge detected".to_string(),
                    url: "https://takeover.test/challenge".to_string(),
                },
            },
        }
    }

    #[test]
    fn takeover_event_raises_blocking_banner_with_kind_and_url() {
        let mut log = JournalLog::default();
        log.follow("session-0");
        assert!(!log.takeover().is_blocking(), "no banner before any event");

        log.ingest(&[takeover_event(0, TakeoverKind::Captcha)]);

        assert!(log.takeover().is_blocking());
        let Some(pending) = log.takeover().pending() else {
            panic!("takeover pending");
        };
        assert_eq!(pending.kind, TakeoverKind::Captcha);
        assert_eq!(pending.url, "https://takeover.test/challenge");
        assert_eq!(log.takeover().reason_label(), Some("captcha"));
        assert_eq!(
            log.takeover().banner_line().as_deref(),
            Some("Human takeover required (captcha): challenge detected — https://takeover.test/challenge")
        );
        // It is also recorded as a journal line.
        assert_eq!(
            log.entries.last().map(|entry| entry.kind.as_str()),
            Some("human_takeover_required")
        );
    }

    #[test]
    fn non_takeover_events_do_not_raise_the_banner() {
        let mut log = JournalLog::default();
        log.follow("session-0");
        log.ingest(&[
            created_event(0),
            step_event(
                1,
                diff_with(vec![element("n0", vec![span(Provenance::Page, "evil")])]),
            ),
        ]);
        assert!(
            !log.takeover().is_blocking(),
            "session/step events must not raise the takeover banner"
        );
        assert!(log.takeover().pending().is_none());
        assert!(log.takeover().banner_line().is_none());
    }

    #[test]
    fn resume_clears_the_blocking_banner() {
        let mut log = JournalLog::default();
        log.follow("session-0");
        log.ingest(&[takeover_event(0, TakeoverKind::LoginRequired)]);
        assert!(log.takeover().is_blocking());

        log.resume_takeover();
        assert!(
            !log.takeover().is_blocking(),
            "Resume clears the local block"
        );
        assert!(log.takeover().pending().is_none());
    }

    #[test]
    fn resume_never_auto_continues_when_challenge_persists() {
        // #343 act-loop scenario: the human resumes, but the challenge is still on
        // the page, so the agent re-detects it and re-journals the takeover. The
        // next poll must re-raise the banner — never silently wave the agent past.
        let mut log = JournalLog::default();
        log.follow("session-0");
        log.ingest(&[takeover_event(0, TakeoverKind::AuthWall)]);
        assert!(log.takeover().is_blocking());

        log.resume_takeover();
        assert!(!log.takeover().is_blocking());

        // A later, unresolved re-detection surfaces as a fresh event on the stream.
        log.ingest(&[takeover_event(1, TakeoverKind::AuthWall)]);
        assert!(
            log.takeover().is_blocking(),
            "an unresolved challenge must re-raise the banner after resume"
        );
    }

    #[test]
    fn switching_sessions_clears_the_takeover_banner() {
        let mut log = JournalLog::default();
        log.follow("session-0");
        log.ingest(&[takeover_event(0, TakeoverKind::Captcha)]);
        assert!(log.takeover().is_blocking());

        // Following a different session resets the per-session banner.
        log.follow("session-1");
        assert!(!log.takeover().is_blocking());
    }

    #[test]
    fn taint_state_reflects_untrusted_page_spans() {
        let clean = diff_with(vec![element("n0", vec![span(Provenance::System, "ok")])]);
        assert_eq!(TaintState::from_diff(&clean), TaintState::Clean);
        assert!(!TaintState::from_diff(&clean).is_tainted());

        let tainted = diff_with(vec![element(
            "n0",
            vec![
                span(Provenance::User, "typed"),
                span(Provenance::Page, "attacker-controlled"),
            ],
        )]);
        assert_eq!(TaintState::from_diff(&tainted), TaintState::Tainted);
        assert!(TaintState::from_diff(&tainted).is_tainted());
    }

    #[test]
    fn ingest_orders_and_dedupes_events() {
        let mut log = JournalLog::default();
        log.follow("session-0");
        // Delivered out of order; ingest sorts by seq.
        log.ingest(&[created_event(1), created_event(0)]);
        assert_eq!(
            log.entries
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(log.cursor, Some(1));

        // A re-poll that re-delivers seen events plus a new one appends only the new.
        log.ingest(&[created_event(1), created_event(2)]);
        assert_eq!(
            log.entries
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(log.cursor, Some(2));
    }

    #[test]
    fn follow_resets_on_session_change() {
        let mut log = JournalLog::default();
        assert_eq!(log.follow("session-0"), None);
        log.ingest(&[created_event(0)]);
        assert_eq!(
            log.follow("session-0"),
            Some(0),
            "same session keeps cursor"
        );

        // Switching sessions clears the log and cursor.
        assert_eq!(log.follow("session-1"), None);
        assert!(log.entries.is_empty());
        assert_eq!(log.cursor, None);
        assert_eq!(log.taint(), TaintState::Unknown);
    }

    #[test]
    fn ingest_updates_taint_badge_from_latest_step() {
        let mut log = JournalLog::default();
        log.follow("session-0");

        log.ingest(&[step_event(
            0,
            diff_with(vec![element("n0", vec![span(Provenance::System, "safe")])]),
        )]);
        assert_eq!(log.taint(), TaintState::Clean);
        assert!(!log.entries[0].tainted);

        // A later step that adds a page-derived element flips the badge on.
        log.ingest(&[step_event(
            1,
            diff_with(vec![element("n1", vec![span(Provenance::Page, "evil")])]),
        )]);
        assert_eq!(log.taint(), TaintState::Tainted);
        assert!(log.entries[1].tainted);
        assert_eq!(log.entries[1].kind, "step");
        assert_eq!(log.entries[1].detail, "goto → applied");
    }

    #[test]
    fn taint_badge_stays_sticky_while_untrusted_element_persists() {
        let mut log = JournalLog::default();
        log.follow("session-0");

        // Step 0: an untrusted element `n1` appears on the page.
        log.ingest(&[step_event(
            0,
            diff_with(vec![element("n1", vec![span(Provenance::Page, "evil")])]),
        )]);
        assert_eq!(log.taint(), TaintState::Tainted);

        // Step 1: a diff that neither adds nor changes `n1` — it is still on the
        // page, unchanged. A delta-only recompute would wrongly clear the badge;
        // the sticky set keeps it Tainted.
        log.ingest(&[step_event(
            1,
            diff_with(vec![element("n2", vec![span(Provenance::System, "safe")])]),
        )]);
        assert_eq!(
            log.taint(),
            TaintState::Tainted,
            "untrusted content still present must keep the badge on"
        );
    }

    #[test]
    fn taint_badge_clears_when_untrusted_element_is_removed() {
        let mut log = JournalLog::default();
        log.follow("session-0");

        log.ingest(&[step_event(
            0,
            diff_with(vec![element("n1", vec![span(Provenance::Page, "evil")])]),
        )]);
        assert_eq!(log.taint(), TaintState::Tainted);

        // The untrusted element leaves the page (appears in `removed`).
        log.ingest(&[step_event(
            1,
            diff_added_changed_removed(Vec::new(), Vec::new(), vec![NodeId("n1".to_string())]),
        )]);
        assert_eq!(
            log.taint(),
            TaintState::Clean,
            "badge clears only when the untrusted element actually leaves"
        );

        // A `changed` re-observation that is now clean also clears its node.
        log.ingest(&[step_event(
            2,
            diff_with(vec![element("n3", vec![span(Provenance::Page, "evil2")])]),
        )]);
        assert_eq!(log.taint(), TaintState::Tainted);
        log.ingest(&[step_event(
            3,
            diff_added_changed_removed(
                Vec::new(),
                vec![element("n3", vec![span(Provenance::System, "sanitized")])],
                Vec::new(),
            ),
        )]);
        assert_eq!(log.taint(), TaintState::Clean);
    }
}
