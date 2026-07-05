//! Pure foreground-surface state for the desktop shell.
//!
//! The current window still paints a screenshot snapshot, but the shell model
//! should not assume screenshots are the only possible page pane. This module is
//! the engine-neutral state that a Servo/WebView foreground surface will reuse:
//! current URL/title/loading, owner, run state, takeover, confirmation, taint
//! badge inputs, and marks-overlay request state. It has no egui/winit/socket
//! dependencies, so it is unit-testable in headless CI.

use serde_json::Value;
use tempo_headless::{TempodSessionEvent, TempodSessionEventKind};
use tempo_schema::HumanTakeover;

use crate::ShellError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceMode {
    /// Current implementation: single-shot MCP screenshot frames.
    Snapshot,
    /// Target implementation: a live foreground browser surface embedded in the
    /// native window.
    Foreground,
}

impl SurfaceMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Foreground => "foreground",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceEngine {
    McpScreenshot,
    Servo,
    WebView2,
}

impl SurfaceEngine {
    pub const fn label(self) -> &'static str {
        match self {
            Self::McpScreenshot => "mcp-screenshot",
            Self::Servo => "servo",
            Self::WebView2 => "webview2",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceLoadState {
    Idle,
    Loading,
    Ready,
    Failed,
}

impl SurfaceLoadState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Loading => "loading",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlOwner {
    Agent,
    Human,
    None,
    Unknown,
}

impl ControlOwner {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Human => "human",
            Self::None => "none",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceRunState {
    Idle,
    AgentControl,
    HumanControl,
    HumanTakeoverRequired,
    AwaitingConfirmation,
    Killed,
}

impl SurfaceRunState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::AgentControl => "agent-control",
            Self::HumanControl => "human-control",
            Self::HumanTakeoverRequired => "takeover-required",
            Self::AwaitingConfirmation => "awaiting-confirmation",
            Self::Killed => "killed",
        }
    }
}

/// Native-shell representation of a server policy gate.
///
/// This is intentionally not a bypass token. Until Terminal 1 lands server-
/// minted grants, confirming in the shell can only acknowledge/dismiss this
/// local state; it must not resubmit an action with advisory `confirmed=true`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConfirmation {
    pub action_label: String,
    pub reason: String,
    pub gate: String,
    pub input_tainted: Option<bool>,
    pub grant_required: bool,
}

impl PendingConfirmation {
    pub fn from_error(action_label: impl Into<String>, error: &ShellError) -> Option<Self> {
        let action_label = action_label.into();
        match error {
            ShellError::Http { status: 403, body } => {
                Self::from_policy_json(action_label.clone(), body).or_else(|| {
                    confirmation_text(body).then(|| Self::from_message(action_label, body))
                })
            }
            ShellError::Mcp(message) => {
                confirmation_text(message).then(|| Self::from_message(action_label, message))
            }
            _ => None,
        }
    }

    fn from_policy_json(action_label: String, body: &str) -> Option<Self> {
        let value = serde_json::from_str::<Value>(body).ok()?;
        let policy = value.get("policy")?;
        let confirmation_required = policy
            .get("confirmation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let confirmed_claim_ignored = policy
            .get("confirmed_claim_ignored")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !confirmation_required && !confirmed_claim_ignored {
            return None;
        }

        let denied_action = value
            .get("denied_action_kind")
            .and_then(Value::as_str)
            .filter(|label| !label.is_empty())
            .unwrap_or(&action_label);
        let reason = value
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| value.get("error").and_then(Value::as_str))
            .unwrap_or("policy requires native confirmation")
            .to_string();
        let gate = policy
            .get("strongest_gate")
            .and_then(Value::as_str)
            .unwrap_or("confirm")
            .to_string();
        let input_tainted = policy
            .get("input_tainted_effective")
            .and_then(Value::as_bool);

        Some(Self {
            action_label: denied_action.to_string(),
            reason,
            gate,
            input_tainted,
            grant_required: true,
        })
    }

    fn from_message(action_label: String, message: &str) -> Self {
        Self {
            action_label,
            reason: message.to_string(),
            gate: "confirm".to_string(),
            input_tainted: None,
            grant_required: true,
        }
    }
}

fn confirmation_text(message: &str) -> bool {
    message.to_ascii_lowercase().contains("confirmation")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserSurface {
    pub surface_id: String,
    pub mode: SurfaceMode,
    pub engine: SurfaceEngine,
    pub current_url: String,
    pub title: Option<String>,
    pub load_state: SurfaceLoadState,
    pub owner: ControlOwner,
    pub run_state: SurfaceRunState,
    pub pending_takeover: Option<HumanTakeover>,
    pub pending_confirmation: Option<PendingConfirmation>,
    pub marks_overlay: bool,
    pub last_snapshot_seq: u64,
}

impl BrowserSurface {
    pub fn human_snapshot(
        session_id: impl Into<String>,
        driver_id: Option<&str>,
        initial_url: impl Into<String>,
    ) -> Self {
        let session_id = session_id.into();
        let surface_id = driver_id.unwrap_or(&session_id).to_string();
        Self {
            surface_id,
            mode: SurfaceMode::Snapshot,
            engine: SurfaceEngine::McpScreenshot,
            current_url: initial_url.into(),
            title: None,
            load_state: SurfaceLoadState::Idle,
            owner: ControlOwner::Human,
            run_state: SurfaceRunState::HumanControl,
            pending_takeover: None,
            pending_confirmation: None,
            marks_overlay: false,
            last_snapshot_seq: 0,
        }
    }

    pub fn title_or_url(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.current_url)
    }

    pub fn set_foreground_servo(&mut self) {
        self.mode = SurfaceMode::Foreground;
        self.engine = SurfaceEngine::Servo;
    }

    pub fn begin_navigation(&mut self, url: impl Into<String>) {
        self.current_url = url.into();
        self.load_state = SurfaceLoadState::Loading;
        self.pending_confirmation = None;
    }

    pub fn navigation_applied(&mut self, url: impl Into<String>) {
        self.current_url = url.into();
        self.load_state = SurfaceLoadState::Ready;
        self.pending_confirmation = None;
        if self.owner == ControlOwner::Human {
            self.run_state = SurfaceRunState::HumanControl;
        }
    }

    pub fn navigation_failed(&mut self, action_label: &str, error: &ShellError) {
        self.load_state = SurfaceLoadState::Failed;
        if let Some(confirmation) = PendingConfirmation::from_error(action_label, error) {
            self.pending_confirmation = Some(confirmation);
            self.run_state = SurfaceRunState::AwaitingConfirmation;
        }
    }

    pub fn record_snapshot(&mut self, set_of_marks: bool, seq: u64) {
        self.marks_overlay = set_of_marks;
        self.last_snapshot_seq = seq;
        if self.load_state != SurfaceLoadState::Loading {
            self.load_state = SurfaceLoadState::Ready;
        }
    }

    pub fn set_marks_overlay(&mut self, enabled: bool) {
        self.marks_overlay = enabled;
    }

    pub fn adopted_by_human(&mut self) {
        self.owner = ControlOwner::Human;
        self.run_state = SurfaceRunState::HumanControl;
    }

    pub fn killed(&mut self) {
        self.owner = ControlOwner::None;
        self.run_state = SurfaceRunState::Killed;
        self.load_state = SurfaceLoadState::Idle;
        self.pending_takeover = None;
        self.pending_confirmation = None;
    }

    pub fn clear_takeover(&mut self) {
        self.pending_takeover = None;
        self.run_state = if self.owner == ControlOwner::Human {
            SurfaceRunState::HumanControl
        } else {
            SurfaceRunState::Idle
        };
    }

    pub fn dismiss_confirmation(&mut self) {
        self.pending_confirmation = None;
        self.run_state = if self.owner == ControlOwner::Human {
            SurfaceRunState::HumanControl
        } else {
            SurfaceRunState::Idle
        };
    }

    pub fn ingest_events<'a>(&mut self, events: impl IntoIterator<Item = &'a TempodSessionEvent>) {
        for event in events {
            self.ingest_event(&event.event);
        }
    }

    fn ingest_event(&mut self, event: &TempodSessionEventKind) {
        match event {
            TempodSessionEventKind::SessionCreated { url } => {
                self.current_url = url.clone();
                self.load_state = SurfaceLoadState::Ready;
            }
            TempodSessionEventKind::SessionAdopted => self.adopted_by_human(),
            TempodSessionEventKind::SessionKilled => self.killed(),
            TempodSessionEventKind::SessionDrained => {
                self.run_state = SurfaceRunState::Idle;
            }
            TempodSessionEventKind::StepTriple { .. } => {
                if self.owner != ControlOwner::Human {
                    self.owner = ControlOwner::Agent;
                    self.run_state = SurfaceRunState::AgentControl;
                }
            }
            TempodSessionEventKind::HumanTakeoverRequired { takeover } => {
                self.owner = ControlOwner::Agent;
                self.run_state = SurfaceRunState::HumanTakeoverRequired;
                self.pending_takeover = Some(takeover.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempo_headless::{TempodSessionEvent, TempodSessionId};
    use tempo_schema::{HumanTakeover, TakeoverKind};

    fn event(seq: u64, kind: TempodSessionEventKind) -> TempodSessionEvent {
        TempodSessionEvent {
            session_id: TempodSessionId("session-0".to_string()),
            seq,
            timestamp_ms: 0,
            event: kind,
        }
    }

    #[test]
    fn human_snapshot_is_a_foreground_ready_contract_not_a_window_dependency() {
        let surface =
            BrowserSurface::human_snapshot("session-0", Some("driver-1"), "https://a.test");

        assert_eq!(surface.surface_id, "driver-1");
        assert_eq!(surface.mode, SurfaceMode::Snapshot);
        assert_eq!(surface.engine, SurfaceEngine::McpScreenshot);
        assert_eq!(surface.owner, ControlOwner::Human);
        assert_eq!(surface.run_state, SurfaceRunState::HumanControl);
        assert_eq!(surface.title_or_url(), "https://a.test");
    }

    #[test]
    fn takeover_event_marks_agent_pause_until_human_clears_it() {
        let mut surface = BrowserSurface::human_snapshot("session-0", None, "https://a.test");
        let takeover = HumanTakeover {
            kind: TakeoverKind::Captcha,
            reason: "challenge detected".to_string(),
            url: "https://a.test/verify".to_string(),
        };

        surface.ingest_events(
            [event(
                1,
                TempodSessionEventKind::HumanTakeoverRequired {
                    takeover: takeover.clone(),
                },
            )]
            .iter(),
        );

        assert_eq!(surface.owner, ControlOwner::Agent);
        assert_eq!(surface.run_state, SurfaceRunState::HumanTakeoverRequired);
        assert_eq!(surface.pending_takeover.as_ref(), Some(&takeover));

        surface.adopted_by_human();
        surface.clear_takeover();

        assert_eq!(surface.owner, ControlOwner::Human);
        assert_eq!(surface.run_state, SurfaceRunState::HumanControl);
        assert!(surface.pending_takeover.is_none());
    }

    #[test]
    fn policy_denial_becomes_native_confirmation_state() {
        let body = json!({
            "reason": "requires server-attributable confirmation before execution; confirmed=true was ignored",
            "denied_action_kind": "click",
            "policy": {
                "strongest_gate": "confirm_with_taint_review",
                "confirmation_required": true,
                "confirmed_claim_ignored": true,
                "input_tainted_effective": true
            }
        })
        .to_string();
        let mut surface = BrowserSurface::human_snapshot("session-0", None, "https://a.test");
        let error = ShellError::Http { status: 403, body };

        surface.navigation_failed("navigate", &error);

        assert_eq!(surface.run_state, SurfaceRunState::AwaitingConfirmation);
        let Some(confirmation) = surface.pending_confirmation.as_ref() else {
            panic!("confirmation should be pending");
        };
        assert_eq!(confirmation.action_label, "click");
        assert_eq!(confirmation.gate, "confirm_with_taint_review");
        assert_eq!(confirmation.input_tainted, Some(true));
        assert!(confirmation.grant_required);

        surface.dismiss_confirmation();
        assert!(surface.pending_confirmation.is_none());
        assert_eq!(surface.run_state, SurfaceRunState::HumanControl);
    }
}
