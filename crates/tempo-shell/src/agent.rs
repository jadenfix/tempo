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

#[cfg(test)]
use tempo_headless::SessionStepKey;
use tempo_headless::{
    SessionStepOutcome, SessionStepTriple, TempodSessionEvent, TempodSessionEventKind,
};
use tempo_schema::{Action, InteractiveElement, ObservationDiff, TaintSpan};

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

    /// Derive from an observation diff: `Tainted` iff any added/changed element's
    /// name/value spans cross the untrusted page boundary.
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
            TempodSessionEventKind::SessionKilled => ("session_killed", String::new(), false),
            TempodSessionEventKind::SessionDrained => ("session_drained", String::new(), false),
            TempodSessionEventKind::StepTriple { triple } => {
                ("step", step_detail(triple), step_is_tainted(triple))
            }
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

/// The ordered, deduplicated journal-event log for one session, plus the taint
/// state derived from its most recent observation-bearing event.
///
/// The log is append-only within a session: [`Self::ingest`] takes a page of
/// events fetched with `after_seq = cursor` and drops any it has already seen, so
/// re-polling never duplicates a line. Switching the active session
/// ([`Self::follow`]) resets the log and the cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalLog {
    /// The session this log is currently following, if any.
    pub session_id: Option<String>,
    /// Entries in seq order (oldest first) — the scrolling log.
    pub entries: Vec<JournalEntry>,
    /// Highest seq ingested; the `after_seq` cursor for the next poll.
    pub cursor: Option<u64>,
    /// Badge state from the most recent observation-bearing event.
    pub taint: TaintState,
}

impl JournalLog {
    /// Point the log at `session_id`, clearing entries/cursor/taint if it changed.
    /// Returns the cursor the next poll should use (`None` on a fresh session).
    pub fn follow(&mut self, session_id: &str) -> Option<u64> {
        if self.session_id.as_deref() != Some(session_id) {
            self.session_id = Some(session_id.to_string());
            self.entries.clear();
            self.cursor = None;
            self.taint = TaintState::Unknown;
        }
        self.cursor
    }

    /// Append a fetched page of events in seq order, skipping any at or below the
    /// cursor, and refresh the taint badge from the newest step observation seen.
    pub fn ingest(&mut self, events: &[TempodSessionEvent]) {
        let mut fresh: Vec<&TempodSessionEvent> = events
            .iter()
            .filter(|event| self.cursor.is_none_or(|cursor| event.seq > cursor))
            .collect();
        fresh.sort_by_key(|event| event.seq);
        for event in fresh {
            if let TempodSessionEventKind::StepTriple { triple } = &event.event
                && let SessionStepOutcome::Applied { diff } = &triple.outcome
            {
                self.taint = TaintState::from_diff(diff);
            }
            self.cursor = Some(
                self.cursor
                    .map_or(event.seq, |cursor| cursor.max(event.seq)),
            );
            self.entries.push(JournalEntry::from_event(event));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_headless::TempodSessionId;
    use tempo_schema::{NodeId, Provenance};

    fn span(provenance: Provenance, text: &str) -> TaintSpan {
        TaintSpan {
            provenance,
            text: text.to_string(),
        }
    }

    fn element(spans: Vec<TaintSpan>) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId("n0".to_string()),
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
            added,
            removed: Vec::new(),
            changed: Vec::new(),
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

    #[test]
    fn taint_state_reflects_untrusted_page_spans() {
        let clean = diff_with(vec![element(vec![span(Provenance::System, "ok")])]);
        assert_eq!(TaintState::from_diff(&clean), TaintState::Clean);
        assert!(!TaintState::from_diff(&clean).is_tainted());

        let tainted = diff_with(vec![element(vec![
            span(Provenance::User, "typed"),
            span(Provenance::Page, "attacker-controlled"),
        ])]);
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
        assert_eq!(log.taint, TaintState::Unknown);
    }

    #[test]
    fn ingest_updates_taint_badge_from_latest_step() {
        let mut log = JournalLog::default();
        log.follow("session-0");

        log.ingest(&[step_event(
            0,
            diff_with(vec![element(vec![span(Provenance::System, "safe")])]),
        )]);
        assert_eq!(log.taint, TaintState::Clean);
        assert!(!log.entries[0].tainted);

        // A later step with page-derived spans flips the badge on.
        log.ingest(&[step_event(
            1,
            diff_with(vec![element(vec![span(Provenance::Page, "evil")])]),
        )]);
        assert_eq!(log.taint, TaintState::Tainted);
        assert!(log.entries[1].tainted);
        assert_eq!(log.entries[1].kind, "step");
        assert_eq!(log.entries[1].detail, "goto → applied");
    }
}
