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
use tempo_schema::{
    AgentRunState, ConfirmationRequest, ControlOwner as SchemaControlOwner, HumanTakeover,
    ManagerEvent,
};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConfirmation {
    pub request: Option<ConfirmationRequest>,
    pub replay: Option<PendingConfirmationReplay>,
    pub action_label: String,
    pub reason: String,
    pub gate: String,
    pub input_tainted: Option<bool>,
    pub grant_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingConfirmationReplay {
    Navigate { session_id: String, url: String },
}

impl PendingConfirmation {
    pub fn from_request(request: ConfirmationRequest, input_tainted: Option<bool>) -> Self {
        Self {
            action_label: request.action_kind.clone(),
            reason: request.reason.clone(),
            gate: request.gate.clone(),
            input_tainted,
            grant_required: true,
            replay: None,
            request: Some(request),
        }
    }

    pub fn with_replay(mut self, replay: PendingConfirmationReplay) -> Self {
        self.replay = Some(replay);
        self
    }

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
        if let Some(request) = value
            .get("confirmation_request")
            .and_then(|request| serde_json::from_value::<ConfirmationRequest>(request.clone()).ok())
        {
            return Some(Self::from_request(request, input_tainted));
        }

        Some(Self {
            request: None,
            replay: None,
            action_label: denied_action.to_string(),
            reason,
            gate,
            input_tainted,
            grant_required: true,
        })
    }

    fn from_message(action_label: String, message: &str) -> Self {
        Self {
            request: None,
            replay: None,
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
    pub active_run_id: Option<String>,
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
            active_run_id: None,
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
        self.navigation_failed_with_replay(action_label, error, None);
    }

    pub fn navigation_failed_with_replay(
        &mut self,
        action_label: &str,
        error: &ShellError,
        replay: Option<PendingConfirmationReplay>,
    ) {
        self.load_state = SurfaceLoadState::Failed;
        if let Some(confirmation) = PendingConfirmation::from_error(action_label, error) {
            self.pending_confirmation = Some(match replay {
                Some(replay) => confirmation.with_replay(replay),
                None => confirmation,
            });
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

    pub fn handed_off_to_agent(&mut self) {
        self.owner = ControlOwner::Agent;
        self.run_state = SurfaceRunState::AgentControl;
        self.pending_takeover = None;
    }

    pub fn killed(&mut self) {
        self.owner = ControlOwner::None;
        self.run_state = SurfaceRunState::Killed;
        self.active_run_id = None;
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
            TempodSessionEventKind::SessionHandoff => {
                self.handed_off_to_agent();
            }
            TempodSessionEventKind::SessionKilled => self.killed(),
            TempodSessionEventKind::SessionDrained => {
                self.run_state = SurfaceRunState::Idle;
            }
            TempodSessionEventKind::Manager { event } => self.ingest_manager_event(event),
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

    fn ingest_manager_event(&mut self, event: &ManagerEvent) {
        match event {
            ManagerEvent::OwnerChanged { owner } => {
                self.owner = surface_owner(owner);
                match owner {
                    SchemaControlOwner::Agent { run_id } => {
                        self.active_run_id = run_id.as_ref().map(|run_id| run_id.0.clone());
                    }
                    SchemaControlOwner::Unowned => {
                        self.active_run_id = None;
                    }
                    SchemaControlOwner::Human { .. } => {}
                }
                self.run_state = match self.owner {
                    ControlOwner::Agent => SurfaceRunState::AgentControl,
                    ControlOwner::Human => SurfaceRunState::HumanControl,
                    ControlOwner::None | ControlOwner::Unknown => SurfaceRunState::Idle,
                };
            }
            ManagerEvent::ConfirmationRequested { request } => {
                self.pending_confirmation =
                    Some(PendingConfirmation::from_request(request.clone(), None));
                self.run_state = SurfaceRunState::AwaitingConfirmation;
            }
            ManagerEvent::ConfirmationGranted {
                confirmation_id, ..
            } => {
                if self
                    .pending_confirmation
                    .as_ref()
                    .and_then(|pending| pending.request.as_ref())
                    .is_some_and(|request| request.confirmation_id == *confirmation_id)
                {
                    self.dismiss_confirmation();
                }
            }
            ManagerEvent::RunStateChanged { run } => {
                let run_id = run.run_id.0.clone();
                self.run_state = run_state(run.state);
                if matches!(
                    run.state,
                    AgentRunState::Completed | AgentRunState::Failed | AgentRunState::Cancelled
                ) {
                    if self.active_run_id.as_deref() == Some(run_id.as_str()) {
                        self.active_run_id = None;
                    }
                } else {
                    self.active_run_id = Some(run_id);
                }
            }
            ManagerEvent::HumanTakeover { takeover } => {
                self.owner = ControlOwner::Agent;
                self.run_state = SurfaceRunState::HumanTakeoverRequired;
                self.pending_takeover = Some(takeover.clone());
            }
            ManagerEvent::NativePromptRequested { .. } => {
                self.run_state = SurfaceRunState::AwaitingConfirmation;
            }
            ManagerEvent::SurfaceRegistered { .. }
            | ManagerEvent::SurfaceRemoved { .. }
            | ManagerEvent::NativePromptResolved { .. } => {}
        }
    }
}

fn surface_owner(owner: &SchemaControlOwner) -> ControlOwner {
    match owner {
        SchemaControlOwner::Agent { .. } => ControlOwner::Agent,
        SchemaControlOwner::Human { .. } => ControlOwner::Human,
        SchemaControlOwner::Unowned => ControlOwner::None,
    }
}

fn run_state(state: AgentRunState) -> SurfaceRunState {
    match state {
        AgentRunState::Queued | AgentRunState::Running => SurfaceRunState::AgentControl,
        AgentRunState::WaitingForHuman => SurfaceRunState::HumanTakeoverRequired,
        AgentRunState::Completed | AgentRunState::Failed | AgentRunState::Cancelled => {
            SurfaceRunState::Idle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempo_headless::{TempodSessionEvent, TempodSessionId};
    use tempo_schema::{ConfirmationRequest, HumanTakeover, SideEffect, TakeoverKind};

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
            "confirmation_request": {
                "confirmation_id": "confirmation-1",
                "session_id": "session-0",
                "side_effect": "purchase",
                "gate": "confirm_with_taint_review",
                "action_index": 0,
                "action_kind": "click",
                "reason": "requires server-attributable confirmation before execution",
                "created_ms": 10,
                "expires_ms": 20
            },
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
        assert_eq!(
            confirmation
                .request
                .as_ref()
                .map(|request| request.confirmation_id.as_str()),
            Some("confirmation-1")
        );

        surface.dismiss_confirmation();
        assert!(surface.pending_confirmation.is_none());
        assert_eq!(surface.run_state, SurfaceRunState::HumanControl);
    }

    #[test]
    fn manager_confirmation_events_drive_native_confirmation_state() {
        let request = ConfirmationRequest {
            confirmation_id: "confirmation-7".to_string(),
            session_id: "session-0".to_string(),
            side_effect: SideEffect::Send,
            gate: "confirm_send".to_string(),
            action_index: 0,
            action_kind: "click".to_string(),
            reason: "send message".to_string(),
            created_ms: 10,
            expires_ms: 20,
        };
        let mut surface = BrowserSurface::human_snapshot("session-0", None, "https://a.test");

        surface.ingest_events(
            [event(
                1,
                TempodSessionEventKind::Manager {
                    event: ManagerEvent::ConfirmationRequested {
                        request: request.clone(),
                    },
                },
            )]
            .iter(),
        );

        assert_eq!(surface.run_state, SurfaceRunState::AwaitingConfirmation);
        assert_eq!(
            surface
                .pending_confirmation
                .as_ref()
                .and_then(|pending| pending.request.as_ref()),
            Some(&request)
        );

        surface.ingest_events(
            [event(
                2,
                TempodSessionEventKind::Manager {
                    event: ManagerEvent::ConfirmationGranted {
                        confirmation_id: request.confirmation_id.clone(),
                        grant: tempo_schema::ConfirmationGrant {
                            confirmation_id: request.confirmation_id.clone(),
                            grant_token: "grant-token-test".to_string(),
                            issued_ms: 11,
                            expires_ms: 20,
                        },
                    },
                },
            )]
            .iter(),
        );

        assert!(surface.pending_confirmation.is_none());
        assert_eq!(surface.run_state, SurfaceRunState::HumanControl);
    }
}
