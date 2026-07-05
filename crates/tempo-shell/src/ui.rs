//! Window-free UI logic for the tempo-shell session browser.
//!
//! This module owns the session-list state model, the poll/refresh reducer, and
//! action dispatch. It deliberately depends on nothing from winit/egui so it can
//! be unit tested in headless CI (no display, no GL). The eframe event loop in
//! [`crate::window`] is a thin shell that renders this model and forwards user
//! actions into [`ShellUiModel::dispatch`].
//!
//! The reducer never opens its own socket: it talks to a [`SessionService`],
//! whose only production implementor is [`ShellClient`]. That keeps the HTTP
//! transport a single implementation (no reimplementation) and lets tests inject
//! a mock without a network.

use crate::agent::JournalLog;
use crate::surface::PendingConfirmationReplay;
use crate::tab::{ScreenshotImage, Tab};
use crate::{HealthResponse, ShellClient, ShellError};
#[cfg(test)]
use tempo_headless::TempodSessionEvent;
use tempo_headless::{TempodSession, TempodSessionEvents, TempodSessionState};
use tempo_schema::ConfirmationGrant;

/// One session row as shown in the list: the id/state/url triple the DoD asks
/// for, flattened to display strings so the render layer stays trivial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub state: String,
    pub url: String,
}

impl From<&TempodSession> for SessionRow {
    fn from(session: &TempodSession) -> Self {
        Self {
            id: session.id.0.clone(),
            state: session_state_label(session.state).to_string(),
            url: session.url.clone(),
        }
    }
}

fn session_state_label(state: TempodSessionState) -> &'static str {
    match state {
        TempodSessionState::Running => "running",
        TempodSessionState::Adopted => "adopted",
        TempodSessionState::Killed => "killed",
    }
}

/// The slice of [`ShellClient`] the window needs. Expressed as a trait so the
/// reducer is testable against a mock without opening a socket — and so the
/// transport is never reimplemented: [`ShellClient`] is the only production
/// implementor.
pub trait SessionService {
    fn health(&self) -> Result<HealthResponse, ShellError>;
    fn sessions(&self) -> Result<Vec<TempodSession>, ShellError>;
    fn open(&self, url: &str) -> Result<TempodSession, ShellError>;
    fn adopt(&self, session_id: &str) -> Result<TempodSession, ShellError>;
    fn close(&self, session_id: &str) -> Result<TempodSession, ShellError>;
    /// Navigate a tab's shared tempod session to `url` (omnibox / back / forward).
    fn goto(&self, session_id: &str, url: &str) -> Result<(), ShellError>;
    /// Replay a previously gated foreground navigation with a server grant.
    fn goto_confirmed(
        &self,
        session_id: &str,
        url: &str,
        grant: &ConfirmationGrant,
    ) -> Result<(), ShellError>;
    /// Fetch a single-shot page snapshot for a tab's shared session, optionally
    /// with the set-of-marks overlay drawn on it.
    fn screenshot(
        &self,
        session_id: &str,
        set_of_marks: bool,
    ) -> Result<ScreenshotImage, ShellError>;
    /// Poll the session's journal/event stream after `after_seq` (the agent panel).
    fn events(
        &self,
        session_id: &str,
        after_seq: Option<u64>,
    ) -> Result<TempodSessionEvents, ShellError>;
    /// Mint a server-side grant for a native confirmation request.
    fn confirm(
        &self,
        session_id: &str,
        confirmation_id: &str,
    ) -> Result<ConfirmationGrant, ShellError>;
}

impl SessionService for ShellClient {
    fn health(&self) -> Result<HealthResponse, ShellError> {
        ShellClient::health(self)
    }

    fn sessions(&self) -> Result<Vec<TempodSession>, ShellError> {
        ShellClient::sessions(self)
    }

    fn open(&self, url: &str) -> Result<TempodSession, ShellError> {
        ShellClient::open(self, url)
    }

    fn adopt(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        ShellClient::adopt(self, session_id)
    }

    fn close(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        ShellClient::close(self, session_id)
    }

    fn goto(&self, session_id: &str, url: &str) -> Result<(), ShellError> {
        ShellClient::goto_session(self, session_id, url)
    }

    fn goto_confirmed(
        &self,
        session_id: &str,
        url: &str,
        grant: &ConfirmationGrant,
    ) -> Result<(), ShellError> {
        ShellClient::goto_session_confirmed(self, session_id, url, grant)
    }

    fn screenshot(
        &self,
        session_id: &str,
        set_of_marks: bool,
    ) -> Result<ScreenshotImage, ShellError> {
        ShellClient::screenshot_session(self, session_id, set_of_marks)
    }

    fn events(
        &self,
        session_id: &str,
        after_seq: Option<u64>,
    ) -> Result<TempodSessionEvents, ShellError> {
        ShellClient::events(self, session_id, after_seq)
    }

    fn confirm(
        &self,
        session_id: &str,
        confirmation_id: &str,
    ) -> Result<ConfirmationGrant, ShellError> {
        ShellClient::confirm(self, session_id, confirmation_id)
    }
}

/// A user intent produced by the window chrome and consumed by the reducer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiAction {
    /// Poll `/health` + `/sessions` and rebuild the list. Driven by the button
    /// and the poll timer.
    Refresh,
    /// Open the URL currently in [`ShellUiModel::open_url`].
    Open,
    /// Adopt the given session id.
    Adopt(String),
    /// Close the given session id.
    Close(String),
    /// Open the URL in [`ShellUiModel::open_url`] as a new tab (opens a tempod
    /// session and makes it active).
    NewTab,
    /// Make the tab at the given index active.
    SelectTab(usize),
    /// Close the tab at the given index (and its tempod session).
    CloseTab(usize),
    /// Navigate the active tab to its omnibox URL (pushes history).
    Navigate,
    /// Move the active tab back one history entry (re-issues goto).
    Back,
    /// Move the active tab forward one history entry (re-issues goto).
    Forward,
    /// Refresh the active tab's page-state screenshot.
    RefreshScreenshot,
    /// Poll the active tab's journal/event stream and append new events.
    PollEvents,
    /// Toggle the set-of-marks overlay for the page-state screenshot.
    ToggleMarks,
    /// Human clicked Resume on the blocking takeover banner (#354): clear the
    /// local block. Never auto-continues past an unresolved challenge; the actual
    /// run-resume wire call is a documented follow-up (no tempod resume endpoint /
    /// `ShellClient::resume` yet).
    ResumeTakeover,
    /// Mint a server-side grant for the active native confirmation request.
    ConfirmPendingConfirmation,
    /// Dismiss the native confirmation panel without minting a grant.
    DismissConfirmation,
}

impl UiAction {
    /// Whether this action is a pure chrome/model update that never needs the
    /// tempod transport. The window transport applies these immediately so
    /// local controls stay responsive while backend I/O is slow or unhealthy.
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::SelectTab(_)
                | Self::ToggleMarks
                | Self::ResumeTakeover
                | Self::DismissConfirmation
        )
    }
}

/// Which way [`ShellUiModel::step_history`] walks the active tab's stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HistoryStep {
    Back,
    Forward,
}

impl HistoryStep {
    fn label(self) -> &'static str {
        match self {
            Self::Back => "back",
            Self::Forward => "forward",
        }
    }

    fn label_capitalized(self) -> &'static str {
        match self {
            Self::Back => "Back",
            Self::Forward => "Forward",
        }
    }
}

/// The observable UI state: the base-url/open-url fields, the session list, the
/// last known health, and a single status line that surfaces both progress and
/// errors (no panics — every failure path lands here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellUiModel {
    pub base_url: String,
    pub open_url: String,
    pub sessions: Vec<SessionRow>,
    pub status: String,
    pub healthy: Option<bool>,
    /// One tab per tempod session, each with its own history/omnibox/snapshot.
    pub tabs: Vec<Tab>,
    /// Index into [`Self::tabs`] of the tab whose chrome is shown, if any.
    pub active_tab: Option<usize>,
    /// The agent panel's live journal/event stream + taint badge for the active
    /// session. Rebuilt when the active session changes.
    pub journal: JournalLog,
    /// Whether the page-state screenshot is requested with the set-of-marks
    /// overlay. Flipped by [`UiAction::ToggleMarks`].
    pub marks_overlay: bool,
}

impl Default for ShellUiModel {
    fn default() -> Self {
        Self {
            base_url: crate::DEFAULT_TEMPOD_ADDR.to_string(),
            open_url: String::new(),
            sessions: Vec::new(),
            status: "Idle — press Refresh to list sessions.".to_string(),
            healthy: None,
            tabs: Vec::new(),
            active_tab: None,
            journal: JournalLog::default(),
            marks_overlay: false,
        }
    }
}

impl ShellUiModel {
    /// Build a model pointed at `base_url`, everything else default.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    /// Apply one action against `service`, updating the model in place. The
    /// event loop builds `service` from [`Self::base_url`] before calling; tests
    /// pass a mock.
    pub fn dispatch(&mut self, action: UiAction, service: &dyn SessionService) {
        match action {
            UiAction::Refresh => self.refresh(service),
            UiAction::Open => self.open(service),
            UiAction::Adopt(session_id) => self.adopt(service, &session_id),
            UiAction::Close(session_id) => self.close(service, &session_id),
            UiAction::NewTab => self.new_tab(service),
            UiAction::SelectTab(index) => self.select_tab(index),
            UiAction::CloseTab(index) => self.close_tab(service, index),
            UiAction::Navigate => self.navigate(service),
            UiAction::Back => self.step_history(service, HistoryStep::Back),
            UiAction::Forward => self.step_history(service, HistoryStep::Forward),
            UiAction::RefreshScreenshot => self.refresh_screenshot(service),
            UiAction::PollEvents => self.poll_events(service),
            UiAction::ToggleMarks => self.toggle_marks(),
            UiAction::ResumeTakeover => self.resume_takeover(),
            UiAction::ConfirmPendingConfirmation => self.confirm_pending_confirmation(service),
            UiAction::DismissConfirmation => self.dismiss_confirmation(),
        }
    }

    /// Apply a pure local action without requiring a [`SessionService`]. Returns
    /// `false` for transport-backed actions so callers do not accidentally route
    /// I/O through the local path.
    pub fn dispatch_local(&mut self, action: UiAction) -> bool {
        match action {
            UiAction::SelectTab(index) => self.select_tab(index),
            UiAction::ToggleMarks => self.toggle_marks(),
            UiAction::ResumeTakeover => self.resume_takeover(),
            UiAction::DismissConfirmation => self.dismiss_confirmation(),
            _ => return false,
        }
        true
    }

    /// The active tab, if any.
    pub fn active_tab(&self) -> Option<&Tab> {
        self.active_tab.and_then(|index| self.tabs.get(index))
    }

    fn new_tab(&mut self, service: &dyn SessionService) {
        let url = self.open_url.trim().to_string();
        if url.is_empty() {
            self.status = "Enter a URL for the new tab.".to_string();
            return;
        }
        match service.open(&url) {
            Ok(session) => {
                let row = SessionRow::from(&session);
                // A new tab targets its tempod session; root MCP is reserved for
                // CLI/legacy attached-driver calls.
                let tab = Tab::new(row.id.clone(), None, session.url.clone());
                self.status = format!("Opened tab {} → {}", row.id, row.url);
                self.upsert(row);
                self.tabs.push(tab);
                self.active_tab = Some(self.tabs.len() - 1);
                self.open_url.clear();
            }
            Err(err) => self.set_error("new tab", &err),
        }
    }

    fn select_tab(&mut self, index: usize) {
        if let Some(tab) = self.tabs.get(index) {
            self.status = format!("Switched to tab {}", tab.session_id);
            self.active_tab = Some(index);
            self.marks_overlay = tab.surface.marks_overlay;
        } else {
            self.status = format!("No tab at index {index}");
        }
    }

    fn close_tab(&mut self, service: &dyn SessionService, index: usize) {
        let Some(session_id) = self.tabs.get(index).map(|tab| tab.session_id.clone()) else {
            self.status = format!("No tab at index {index}");
            return;
        };
        match service.close(&session_id) {
            Ok(session) => {
                self.upsert(SessionRow::from(&session));
                self.tabs.remove(index);
                self.active_tab = match self.active_tab {
                    _ if self.tabs.is_empty() => None,
                    Some(active) if active > index => Some(active - 1),
                    Some(active) => Some(active.min(self.tabs.len() - 1)),
                    None => None,
                };
                self.marks_overlay = self
                    .active_tab()
                    .map(|tab| tab.surface.marks_overlay)
                    .unwrap_or(false);
                self.status = format!("Closed tab {session_id}");
            }
            Err(err) => self.set_error("close tab", &err),
        }
    }

    fn navigate(&mut self, service: &dyn SessionService) {
        let Some(active) = self.active_tab else {
            self.status = "No active tab to navigate.".to_string();
            return;
        };
        let outcome = {
            let Some(tab) = self.tabs.get_mut(active) else {
                self.status = "No active tab to navigate.".to_string();
                return;
            };
            let url = tab.omnibox.trim().to_string();
            if url.is_empty() {
                tab.status = "Enter a URL.".to_string();
                self.status = "Enter a URL.".to_string();
                return;
            }
            let session_id = tab.session_id.clone();
            tab.surface.begin_navigation(url.clone());
            match service.goto(&session_id, &url) {
                Ok(()) => {
                    tab.history.push(url.clone());
                    tab.surface.navigation_applied(url.clone());
                    tab.status = format!("Navigated to {url}");
                    Ok((session_id, url))
                }
                Err(err) => {
                    tab.surface.navigation_failed_with_replay(
                        "goto",
                        &err,
                        Some(PendingConfirmationReplay::Navigate {
                            session_id: session_id.clone(),
                            url: url.clone(),
                        }),
                    );
                    tab.status = format!("goto failed: {err}");
                    Err(err)
                }
            }
        };
        match outcome {
            Ok((session_id, url)) => self.status = format!("Tab {session_id} → {url}"),
            Err(err) => self.set_error("goto", &err),
        }
    }

    fn step_history(&mut self, service: &dyn SessionService, step: HistoryStep) {
        let Some(active) = self.active_tab else {
            self.status = "No active tab.".to_string();
            return;
        };
        let target = self.tabs.get_mut(active).and_then(|tab| match step {
            HistoryStep::Back => tab.history.back().map(str::to_string),
            HistoryStep::Forward => tab.history.forward().map(str::to_string),
        });
        let Some(url) = target else {
            self.status = format!("Nothing to go {}.", step.label());
            return;
        };
        let outcome = {
            let Some(tab) = self.tabs.get_mut(active) else {
                return;
            };
            let session_id = tab.session_id.clone();
            tab.omnibox = url.clone();
            tab.surface.begin_navigation(url.clone());
            match service.goto(&session_id, &url) {
                Ok(()) => {
                    tab.surface.navigation_applied(url.clone());
                    tab.status = format!("{} to {url}", step.label_capitalized());
                    Ok(session_id)
                }
                Err(err) => {
                    tab.surface.navigation_failed_with_replay(
                        step.label(),
                        &err,
                        Some(PendingConfirmationReplay::Navigate {
                            session_id: session_id.clone(),
                            url: url.clone(),
                        }),
                    );
                    tab.status = format!("goto failed: {err}");
                    Err(err)
                }
            }
        };
        match outcome {
            Ok(session_id) => {
                self.status = format!("{}: tab {session_id} → {url}", step.label_capitalized());
            }
            Err(err) => self.set_error("goto", &err),
        }
    }

    fn refresh_screenshot(&mut self, service: &dyn SessionService) {
        let Some(active) = self.active_tab else {
            self.status = "No active tab to snapshot.".to_string();
            return;
        };
        let outcome = {
            let Some(tab) = self.tabs.get_mut(active) else {
                return;
            };
            let session_id = tab.session_id.clone();
            match service.screenshot(&session_id, self.marks_overlay) {
                Ok(image) => {
                    tab.screenshot = Some(image);
                    tab.screenshot_seq += 1;
                    if let Some(image) = tab.screenshot.as_ref() {
                        tab.surface
                            .record_snapshot(image.set_of_marks, tab.screenshot_seq);
                    }
                    tab.status = "Screenshot refreshed.".to_string();
                    Ok(session_id)
                }
                Err(err) => {
                    tab.status = format!("screenshot failed: {err}");
                    Err(err)
                }
            }
        };
        match outcome {
            Ok(session_id) => self.status = format!("Screenshot refreshed for tab {session_id}"),
            Err(err) => self.set_error("screenshot", &err),
        }
    }

    /// Poll the active tab's `/sessions/{id}/events` stream and append the new
    /// events to the journal log, refreshing the taint badge. A no-op when there
    /// is no active tab. The journal resets itself when the active session
    /// changes ([`JournalLog::follow`]).
    fn poll_events(&mut self, service: &dyn SessionService) {
        let Some(session_id) = self.active_tab().map(|tab| tab.session_id.clone()) else {
            return;
        };
        let after_seq = self.journal.follow(&session_id);
        match service.events(&session_id, after_seq) {
            Ok(events) => {
                self.journal.ingest(&events.events);
                if let Some(active) = self.active_tab
                    && let Some(tab) = self.tabs.get_mut(active)
                {
                    tab.surface.ingest_events(&events.events);
                }
            }
            Err(err) => self.set_error("events", &err),
        }
    }

    /// Resume from the blocking human-takeover banner (#354). Clears the local
    /// block only; because takeover detection is pure over the observation, a
    /// resumed run that re-observes an unresolved challenge re-journals the
    /// takeover, which re-raises the banner on the next poll — it never
    /// auto-continues past an unresolved CAPTCHA/auth-wall. The actual run-resume
    /// wire call is a documented follow-up: there is no tempod resume endpoint or
    /// `ShellClient::resume` today, so there is nothing to POST yet.
    fn resume_takeover(&mut self) {
        if self.journal.takeover().is_blocking() {
            self.journal.resume_takeover();
            if let Some(active) = self.active_tab
                && let Some(tab) = self.tabs.get_mut(active)
            {
                tab.surface.clear_takeover();
            }
            self.status =
                "Challenge dismissed locally — this build has no resume signal to the agent yet (follow-up)."
                    .to_string();
        }
    }

    fn dismiss_confirmation(&mut self) {
        let Some(active) = self.active_tab else {
            return;
        };
        let Some(tab) = self.tabs.get_mut(active) else {
            return;
        };
        if tab.surface.pending_confirmation.is_some() {
            tab.surface.dismiss_confirmation();
            tab.status = "Confirmation dismissed; action was not resubmitted.".to_string();
            self.status = "Confirmation dismissed; no advisory confirmation was sent.".to_string();
        }
    }

    fn confirm_pending_confirmation(&mut self, service: &dyn SessionService) {
        let Some(active) = self.active_tab else {
            self.status = "No active tab.".to_string();
            return;
        };
        let Some(tab) = self.tabs.get(active) else {
            self.status = "No active tab.".to_string();
            return;
        };
        let Some(confirmation) = tab.surface.pending_confirmation.clone() else {
            self.status = "No pending confirmation.".to_string();
            return;
        };
        let replay = confirmation.replay.clone();
        let Some(request) = confirmation.request else {
            self.status = "Pending confirmation has no server request.".to_string();
            return;
        };

        match service.confirm(&request.session_id, &request.confirmation_id) {
            Ok(grant) => {
                if let Some(PendingConfirmationReplay::Navigate { session_id, url }) = replay {
                    match service.goto_confirmed(&session_id, &url, &grant) {
                        Ok(()) => {
                            if let Some(tab) = self.tabs.get_mut(active) {
                                tab.history.push(url.clone());
                                tab.surface.navigation_applied(url.clone());
                                tab.surface.dismiss_confirmation();
                                tab.status =
                                    format!("Confirmed {} and navigated", grant.confirmation_id);
                            }
                            self.status = format!(
                                "Confirmed {} and replayed navigation",
                                grant.confirmation_id
                            );
                        }
                        Err(err) => {
                            if let Some(tab) = self.tabs.get_mut(active) {
                                tab.surface.dismiss_confirmation();
                                tab.status = format!("confirmed replay failed: {err}");
                            }
                            self.set_error("confirmed replay", &err);
                        }
                    }
                    return;
                }
                if let Some(tab) = self.tabs.get_mut(active) {
                    tab.surface.dismiss_confirmation();
                    tab.status = format!("Confirmed {}", grant.confirmation_id);
                }
                self.status = format!("Confirmed {}", grant.confirmation_id);
            }
            Err(err) => self.set_error("confirm", &err),
        }
    }

    /// Flip the set-of-marks overlay flag. The next screenshot refresh requests
    /// the overlaid image; this only touches request state (no I/O here).
    fn toggle_marks(&mut self) {
        self.marks_overlay = !self.marks_overlay;
        if let Some(active) = self.active_tab
            && let Some(tab) = self.tabs.get_mut(active)
        {
            tab.surface.set_marks_overlay(self.marks_overlay);
        }
        self.status = if self.marks_overlay {
            "Set-of-marks overlay ON — refresh page to apply.".to_string()
        } else {
            "Set-of-marks overlay OFF — refresh page to apply.".to_string()
        };
    }

    fn refresh(&mut self, service: &dyn SessionService) {
        match service.health() {
            Ok(health) => self.healthy = Some(health.ok),
            Err(err) => {
                self.healthy = Some(false);
                self.set_error("health", &err);
                return;
            }
        }
        match service.sessions() {
            Ok(sessions) => {
                self.sessions = sessions.iter().map(SessionRow::from).collect();
                self.status = format!("Listed {} session(s).", self.sessions.len());
            }
            Err(err) => self.set_error("sessions", &err),
        }
    }

    fn open(&mut self, service: &dyn SessionService) {
        let url = self.open_url.trim().to_string();
        if url.is_empty() {
            self.status = "Enter a URL to open.".to_string();
            return;
        }
        match service.open(&url) {
            Ok(session) => {
                let row = SessionRow::from(&session);
                self.status = format!("Opened {} → {}", row.id, row.url);
                self.upsert(row);
                self.open_url.clear();
            }
            Err(err) => self.set_error("open", &err),
        }
    }

    fn adopt(&mut self, service: &dyn SessionService, session_id: &str) {
        match service.adopt(session_id) {
            Ok(session) => {
                let row = SessionRow::from(&session);
                self.status = format!("Adopted {}", row.id);
                self.upsert(row);
                self.ensure_adopted_tab(&session);
            }
            Err(err) => self.set_error("adopt", &err),
        }
    }

    fn close(&mut self, service: &dyn SessionService, session_id: &str) {
        match service.close(session_id) {
            Ok(session) => {
                let row = SessionRow::from(&session);
                self.status = format!("Closed {}", row.id);
                self.upsert(row);
                self.remove_tab_for_session(session_id);
            }
            Err(err) => self.set_error("close", &err),
        }
    }

    fn ensure_adopted_tab(&mut self, session: &TempodSession) {
        let session_id = session.id.0.as_str();
        if let Some(index) = self
            .tabs
            .iter()
            .position(|tab| tab.session_id == session_id)
        {
            if let Some(tab) = self.tabs.get_mut(index) {
                tab.surface.adopted_by_human();
                tab.surface.current_url = session.url.clone();
                tab.omnibox = session.url.clone();
                if tab.history.current() != Some(session.url.as_str()) {
                    tab.history.push(session.url.clone());
                }
                tab.status = "Adopted for human control.".to_string();
                self.marks_overlay = tab.surface.marks_overlay;
            }
            self.active_tab = Some(index);
            return;
        }

        let mut tab = Tab::new(session.id.0.clone(), None, session.url.clone());
        tab.surface.adopted_by_human();
        tab.status = "Adopted for human control.".to_string();
        self.tabs.push(tab);
        self.active_tab = Some(self.tabs.len() - 1);
        self.marks_overlay = false;
    }

    fn remove_tab_for_session(&mut self, session_id: &str) {
        let Some(index) = self
            .tabs
            .iter()
            .position(|tab| tab.session_id == session_id)
        else {
            return;
        };
        self.tabs.remove(index);
        self.active_tab = match self.active_tab {
            _ if self.tabs.is_empty() => None,
            Some(active) if active > index => Some(active - 1),
            Some(active) => Some(active.min(self.tabs.len() - 1)),
            None => None,
        };
        self.marks_overlay = self
            .active_tab()
            .map(|tab| tab.surface.marks_overlay)
            .unwrap_or(false);
    }

    /// Replace the row with the same id, or append it. Keeps the list a faithful
    /// mirror of the last server response for each session without a full
    /// re-poll on every mutation.
    fn upsert(&mut self, row: SessionRow) {
        match self
            .sessions
            .iter_mut()
            .find(|existing| existing.id == row.id)
        {
            Some(existing) => *existing = row,
            None => self.sessions.push(row),
        }
    }

    fn set_error(&mut self, op: &str, err: &ShellError) {
        self.status = format!("{op} failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::{ControlOwner, SurfaceRunState};
    use std::cell::RefCell;
    use std::error::Error;
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempo_driver::{Engine, TestDriver};
    use tempo_engine_host::{
        serve_driver_connection, EngineHostError, EngineIpcClient, EngineIpcConnection,
    };
    use tempo_headless::{serve_forever, SessionPool, TempodSessionEventKind, TempodSessionId};

    type TestResult = Result<(), Box<dyn Error>>;

    fn created_event(session_id: &str, seq: u64, url: &str) -> TempodSessionEvent {
        TempodSessionEvent {
            session_id: TempodSessionId(session_id.to_string()),
            seq,
            timestamp_ms: 0,
            event: TempodSessionEventKind::SessionCreated {
                url: url.to_string(),
            },
        }
    }

    fn takeover_event(session_id: &str, seq: u64) -> TempodSessionEvent {
        use tempo_schema::{HumanTakeover, TakeoverKind};
        TempodSessionEvent {
            session_id: TempodSessionId(session_id.to_string()),
            seq,
            timestamp_ms: 0,
            event: TempodSessionEventKind::HumanTakeoverRequired {
                takeover: HumanTakeover {
                    kind: TakeoverKind::Captcha,
                    reason: "turnstile challenge".to_string(),
                    url: "https://a.test/verify".to_string(),
                },
            },
        }
    }

    fn session(id: &str, url: &str, state: TempodSessionState) -> TempodSession {
        TempodSession {
            id: TempodSessionId(id.to_string()),
            url: url.to_string(),
            state,
            created_ms: 0,
        }
    }

    /// Records every call and returns canned responses, failing whichever op is
    /// named in `fail`. No socket, so it runs in headless CI.
    #[derive(Default)]
    struct MockService {
        calls: RefCell<Vec<String>>,
        canned_sessions: Vec<TempodSession>,
        canned_events: Vec<TempodSessionEvent>,
        fail: Option<&'static str>,
        confirm_on_goto: bool,
    }

    impl MockService {
        fn record(&self, call: impl Into<String>) {
            self.calls.borrow_mut().push(call.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn maybe_fail(&self, op: &'static str) -> Result<(), ShellError> {
            if self.fail == Some(op) {
                Err(ShellError::Http {
                    status: 500,
                    body: format!("{op} boom"),
                })
            } else {
                Ok(())
            }
        }
    }

    impl SessionService for MockService {
        fn health(&self) -> Result<HealthResponse, ShellError> {
            self.record("health");
            self.maybe_fail("health")?;
            Ok(HealthResponse { ok: true })
        }

        fn sessions(&self) -> Result<Vec<TempodSession>, ShellError> {
            self.record("sessions");
            self.maybe_fail("sessions")?;
            Ok(self.canned_sessions.clone())
        }

        fn open(&self, url: &str) -> Result<TempodSession, ShellError> {
            self.record(format!("open:{url}"));
            self.maybe_fail("open")?;
            Ok(session("session-new", url, TempodSessionState::Running))
        }

        fn adopt(&self, session_id: &str) -> Result<TempodSession, ShellError> {
            self.record(format!("adopt:{session_id}"));
            self.maybe_fail("adopt")?;
            Ok(session(
                session_id,
                "https://adopted.test",
                TempodSessionState::Adopted,
            ))
        }

        fn close(&self, session_id: &str) -> Result<TempodSession, ShellError> {
            self.record(format!("close:{session_id}"));
            self.maybe_fail("close")?;
            Ok(session(
                session_id,
                "https://closed.test",
                TempodSessionState::Killed,
            ))
        }

        fn goto(&self, session_id: &str, url: &str) -> Result<(), ShellError> {
            self.record(format!("goto:{session_id}:{url}"));
            if self.confirm_on_goto {
                return Err(ShellError::Http {
                    status: 403,
                    body: serde_json::json!({
                        "error": "policy denied",
                        "reason": "purchase requires native confirmation",
                        "denied_action_index": 0,
                        "denied_action_kind": "goto",
                        "policy": {
                            "confirmation_required": true,
                            "confirmed_claim_ignored": true,
                            "strongest_gate": "confirm_purchase",
                            "input_tainted_effective": false
                        },
                        "confirmation_request": {
                            "confirmation_id": "confirmation-1",
                            "session_id": session_id,
                            "side_effect": "purchase",
                            "gate": "confirm_purchase",
                            "action_index": 0,
                            "action_kind": "goto",
                            "reason": "purchase requires native confirmation",
                            "created_ms": 10,
                            "expires_ms": 20
                        }
                    })
                    .to_string(),
                });
            }
            self.maybe_fail("goto")?;
            Ok(())
        }

        fn goto_confirmed(
            &self,
            session_id: &str,
            url: &str,
            grant: &ConfirmationGrant,
        ) -> Result<(), ShellError> {
            self.record(format!(
                "goto_confirmed:{session_id}:{url}:{}",
                grant.confirmation_id
            ));
            self.maybe_fail("goto_confirmed")?;
            Ok(())
        }

        fn screenshot(
            &self,
            session_id: &str,
            set_of_marks: bool,
        ) -> Result<ScreenshotImage, ShellError> {
            self.record(format!("screenshot:{session_id}:marks={set_of_marks}"));
            self.maybe_fail("screenshot")?;
            Ok(ScreenshotImage {
                mime_type: "image/png".to_string(),
                encoding: "base64".to_string(),
                set_of_marks,
                data: "QUJD".to_string(),
            })
        }

        fn events(
            &self,
            session_id: &str,
            after_seq: Option<u64>,
        ) -> Result<TempodSessionEvents, ShellError> {
            self.record(format!(
                "events:{session_id}:{}",
                after_seq.map_or_else(|| "-".to_string(), |seq| seq.to_string())
            ));
            self.maybe_fail("events")?;
            Ok(TempodSessionEvents {
                events: self
                    .canned_events
                    .iter()
                    .filter(|event| after_seq.is_none_or(|seq| event.seq > seq))
                    .cloned()
                    .collect(),
                truncated_before_seq: None,
            })
        }

        fn confirm(
            &self,
            session_id: &str,
            confirmation_id: &str,
        ) -> Result<ConfirmationGrant, ShellError> {
            self.record(format!("confirm:{session_id}:{confirmation_id}"));
            self.maybe_fail("confirm")?;
            Ok(ConfirmationGrant {
                confirmation_id: confirmation_id.to_string(),
                grant_token: "grant-token-test".to_string(),
                issued_ms: 1,
                expires_ms: 2,
            })
        }
    }

    #[test]
    fn refresh_populates_session_list_from_service() {
        let service = MockService {
            canned_sessions: vec![
                session("session-0", "https://a.test", TempodSessionState::Running),
                session("session-1", "https://b.test", TempodSessionState::Adopted),
            ],
            ..MockService::default()
        };
        let mut model = ShellUiModel::default();

        model.dispatch(UiAction::Refresh, &service);

        assert_eq!(service.calls(), vec!["health", "sessions"]);
        assert_eq!(model.healthy, Some(true));
        assert_eq!(
            model.sessions,
            vec![
                SessionRow {
                    id: "session-0".into(),
                    state: "running".into(),
                    url: "https://a.test".into(),
                },
                SessionRow {
                    id: "session-1".into(),
                    state: "adopted".into(),
                    url: "https://b.test".into(),
                },
            ]
        );
        assert!(model.status.contains("Listed 2"));
    }

    #[test]
    fn open_dispatches_open_and_adds_row() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            open_url: "https://open.test".into(),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Open, &service);

        assert_eq!(service.calls(), vec!["open:https://open.test"]);
        assert_eq!(model.sessions.len(), 1);
        assert_eq!(model.sessions[0].url, "https://open.test");
        assert!(model.open_url.is_empty());
        assert!(model.status.contains("Opened"));
    }

    #[test]
    fn open_without_url_does_not_call_service() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            open_url: "   ".into(),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Open, &service);

        assert!(service.calls().is_empty());
        assert!(model.sessions.is_empty());
        assert!(model.status.contains("Enter a URL"));
    }

    #[test]
    fn adopt_dispatches_adopt_and_updates_state() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            sessions: vec![SessionRow {
                id: "session-0".into(),
                state: "running".into(),
                url: "https://a.test".into(),
            }],
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Adopt("session-0".into()), &service);

        assert_eq!(service.calls(), vec!["adopt:session-0"]);
        assert_eq!(model.sessions[0].state, "adopted");
        assert_eq!(model.tabs.len(), 1);
        assert_eq!(model.active_tab, Some(0));
        assert_eq!(model.tabs[0].session_id, "session-0");
        assert_eq!(model.tabs[0].surface.owner, ControlOwner::Human);
        assert!(model.status.contains("Adopted"));
    }

    #[test]
    fn adopting_existing_tab_selects_it_without_duplicating_surface() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://old.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Adopt("session-0".into()), &service);

        assert_eq!(service.calls(), vec!["adopt:session-0"]);
        assert_eq!(model.tabs.len(), 1);
        assert_eq!(model.active_tab, Some(0));
        assert_eq!(model.tabs[0].current_url(), Some("https://adopted.test"));
        assert_eq!(model.tabs[0].surface.current_url, "https://adopted.test");
        assert_eq!(model.tabs[0].surface.owner, ControlOwner::Human);
    }

    #[test]
    fn close_dispatches_close_and_updates_state() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            sessions: vec![SessionRow {
                id: "session-0".into(),
                state: "running".into(),
                url: "https://a.test".into(),
            }],
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Close("session-0".into()), &service);

        assert_eq!(service.calls(), vec!["close:session-0"]);
        assert_eq!(model.sessions[0].state, "killed");
        assert!(model.status.contains("Closed"));
    }

    #[test]
    fn closing_session_removes_matching_managed_tab() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            sessions: vec![SessionRow {
                id: "session-0".into(),
                state: "adopted".into(),
                url: "https://a.test".into(),
            }],
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            marks_overlay: true,
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Close("session-0".into()), &service);

        assert_eq!(service.calls(), vec!["close:session-0"]);
        assert!(model.tabs.is_empty());
        assert_eq!(model.active_tab, None);
        assert!(!model.marks_overlay);
    }

    #[test]
    fn error_surfaces_to_status_line() {
        let service = MockService {
            fail: Some("sessions"),
            ..MockService::default()
        };
        let mut model = ShellUiModel::default();

        model.dispatch(UiAction::Refresh, &service);

        assert_eq!(service.calls(), vec!["health", "sessions"]);
        assert!(model.sessions.is_empty());
        assert!(
            model.status.contains("sessions failed"),
            "status was {:?}",
            model.status
        );
    }

    #[test]
    fn new_tab_opens_session_and_becomes_active() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            open_url: "https://tab.test".into(),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::NewTab, &service);

        assert_eq!(service.calls(), vec!["open:https://tab.test"]);
        assert_eq!(model.tabs.len(), 1);
        assert_eq!(model.active_tab, Some(0));
        assert_eq!(model.tabs[0].session_id, "session-new");
        assert_eq!(model.tabs[0].current_url(), Some("https://tab.test"));
        // Opening a tab also mirrors into the session list.
        assert_eq!(model.sessions.len(), 1);
        assert!(model.open_url.is_empty());
    }

    #[test]
    fn new_tab_without_url_does_not_call_service() {
        let service = MockService::default();
        let mut model = ShellUiModel::default();

        model.dispatch(UiAction::NewTab, &service);

        assert!(service.calls().is_empty());
        assert!(model.tabs.is_empty());
        assert_eq!(model.active_tab, None);
    }

    #[test]
    fn select_tab_updates_active() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![
                Tab::new("session-0", None, "https://a.test"),
                Tab::new("session-1", None, "https://b.test"),
            ],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::SelectTab(1), &service);
        assert_eq!(model.active_tab, Some(1));

        // Out-of-range selection is a no-op on the active index.
        model.dispatch(UiAction::SelectTab(5), &service);
        assert_eq!(model.active_tab, Some(1));
    }

    #[test]
    fn close_tab_closes_session_and_reindexes_active() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![
                Tab::new("session-0", None, "https://a.test"),
                Tab::new("session-1", None, "https://b.test"),
                Tab::new("session-2", None, "https://c.test"),
            ],
            active_tab: Some(2),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::CloseTab(0), &service);

        assert_eq!(service.calls(), vec!["close:session-0"]);
        assert_eq!(model.tabs.len(), 2);
        assert_eq!(model.tabs[0].session_id, "session-1");
        // Active shifts down with the removed lower-indexed tab.
        assert_eq!(model.active_tab, Some(1));
    }

    #[test]
    fn navigate_dispatches_goto_to_active_tab_and_pushes_history() {
        let service = MockService::default();
        let mut tab = Tab::new("session-0", None, "https://a.test");
        tab.omnibox = "https://b.test".into();
        let mut model = ShellUiModel {
            tabs: vec![tab],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Navigate, &service);

        assert_eq!(service.calls(), vec!["goto:session-0:https://b.test"]);
        assert_eq!(model.tabs[0].current_url(), Some("https://b.test"));
        assert_eq!(model.tabs[0].surface.current_url, "https://b.test");
        assert_eq!(
            model.tabs[0].surface.run_state,
            SurfaceRunState::HumanControl
        );
        assert!(model.tabs[0].history.can_back());
        assert!(model.status.contains("session-0"));
    }

    #[test]
    fn navigate_confirmation_gate_sets_native_confirmation_without_resubmit() {
        let service = MockService {
            confirm_on_goto: true,
            ..MockService::default()
        };
        let mut tab = Tab::new("session-0", None, "https://a.test");
        tab.omnibox = "https://pay.test".into();
        let mut model = ShellUiModel {
            tabs: vec![tab],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Navigate, &service);

        assert_eq!(service.calls(), vec!["goto:session-0:https://pay.test"]);
        assert_eq!(
            model.tabs[0].surface.run_state,
            SurfaceRunState::AwaitingConfirmation
        );
        let pending = model.tabs[0]
            .surface
            .pending_confirmation
            .as_ref()
            .expect("navigation gate should create pending confirmation");
        assert!(matches!(
            pending.replay,
            Some(PendingConfirmationReplay::Navigate { ref session_id, ref url })
                if session_id == "session-0" && url == "https://pay.test"
        ));

        model.dispatch(UiAction::DismissConfirmation, &service);

        assert!(
            model.tabs[0].surface.pending_confirmation.is_none(),
            "dismiss must only clear local native state"
        );
        assert_eq!(
            service.calls(),
            vec!["goto:session-0:https://pay.test"],
            "dismiss must not resubmit with advisory confirmation"
        );
        assert!(model.status.contains("no advisory confirmation"));
    }

    #[test]
    fn confirm_pending_confirmation_mints_grant_and_replays_blocked_navigation() {
        let service = MockService::default();
        let request = tempo_schema::ConfirmationRequest {
            confirmation_id: "confirmation-1".to_string(),
            session_id: "session-0".to_string(),
            side_effect: tempo_schema::SideEffect::Purchase,
            gate: "confirm_purchase".to_string(),
            action_index: 0,
            action_kind: "click".to_string(),
            reason: "purchase requires native confirmation".to_string(),
            created_ms: 10,
            expires_ms: 20,
        };
        let mut tab = Tab::new("session-0", None, "https://pay.test");
        tab.surface.pending_confirmation = Some(
            crate::surface::PendingConfirmation::from_request(request.clone(), Some(false))
                .with_replay(PendingConfirmationReplay::Navigate {
                    session_id: "session-0".to_string(),
                    url: "https://pay.test/confirmed".to_string(),
                }),
        );
        let mut model = ShellUiModel {
            tabs: vec![tab],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::ConfirmPendingConfirmation, &service);

        assert_eq!(
            service.calls(),
            vec![
                "confirm:session-0:confirmation-1",
                "goto_confirmed:session-0:https://pay.test/confirmed:confirmation-1"
            ],
            "confirm must mint a server grant before replaying the original action"
        );
        assert!(model.tabs[0].surface.pending_confirmation.is_none());
        assert_eq!(
            model.tabs[0].surface.current_url,
            "https://pay.test/confirmed"
        );
        assert!(model.status.contains("replayed navigation"));
    }

    #[test]
    fn navigate_targets_each_tabs_own_session() {
        let service = MockService::default();
        let mut first = Tab::new("session-0", Some("fork-0".into()), "https://a.test");
        first.omnibox = "https://wrong.test".into();
        let mut second = Tab::new("session-1", Some("fork-7".into()), "https://b.test");
        second.omnibox = "https://c.test".into();
        let mut model = ShellUiModel {
            tabs: vec![first, second],
            active_tab: Some(1),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Navigate, &service);

        // The active tab's session id is forwarded, so foreground browsing does
        // not escape to root MCP or another tab's attached driver.
        assert_eq!(service.calls(), vec!["goto:session-1:https://c.test"]);
    }

    #[test]
    fn back_and_forward_reissue_goto_for_active_tab() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };
        // Navigate forward twice to build a stack: a -> b -> c.
        model.tabs[0].omnibox = "https://b.test".into();
        model.dispatch(UiAction::Navigate, &service);
        model.tabs[0].omnibox = "https://c.test".into();
        model.dispatch(UiAction::Navigate, &service);

        model.dispatch(UiAction::Back, &service);
        assert_eq!(model.tabs[0].current_url(), Some("https://b.test"));
        assert_eq!(model.tabs[0].omnibox, "https://b.test");

        model.dispatch(UiAction::Forward, &service);
        assert_eq!(model.tabs[0].current_url(), Some("https://c.test"));

        assert_eq!(
            service.calls(),
            vec![
                "goto:session-0:https://b.test", // navigate to b
                "goto:session-0:https://c.test", // navigate to c
                "goto:session-0:https://b.test", // back to b
                "goto:session-0:https://c.test", // forward to c
            ]
        );
    }

    #[test]
    fn back_at_oldest_entry_is_a_no_op() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::Back, &service);

        assert!(
            service.calls().is_empty(),
            "no goto when nothing to go back to"
        );
        assert!(model.status.contains("Nothing to go back"));
    }

    #[test]
    fn refresh_screenshot_requests_active_tabs_session_and_stores_image() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![Tab::new(
                "session-9",
                Some("fork-2".into()),
                "https://a.test",
            )],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::RefreshScreenshot, &service);

        assert_eq!(service.calls(), vec!["screenshot:session-9:marks=false"]);
        let shot = model.tabs[0].screenshot.as_ref();
        assert_eq!(
            shot.map(|image| image.mime_type.as_str()),
            Some("image/png")
        );
        assert_eq!(model.tabs[0].screenshot_seq, 1);
        assert_eq!(model.tabs[0].surface.last_snapshot_seq, 1);
    }

    #[test]
    fn screenshot_error_surfaces_to_status_and_leaves_no_image() {
        let service = MockService {
            fail: Some("screenshot"),
            ..MockService::default()
        };
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::RefreshScreenshot, &service);

        assert!(model.tabs[0].screenshot.is_none());
        assert!(model.status.contains("screenshot failed"));
    }

    #[test]
    fn toggle_marks_flips_screenshot_request_flag() {
        let service = MockService::default();
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };
        assert!(!model.marks_overlay);

        // Toggling flips the flag with no I/O.
        model.dispatch(UiAction::ToggleMarks, &service);
        assert!(model.marks_overlay);
        assert!(model.tabs[0].surface.marks_overlay);
        assert!(service.calls().is_empty());

        // The next screenshot refresh requests the set-of-marks overlay.
        model.dispatch(UiAction::RefreshScreenshot, &service);
        assert_eq!(service.calls(), vec!["screenshot:session-0:marks=true"]);
        assert!(model.tabs[0]
            .screenshot
            .as_ref()
            .is_some_and(|image| image.set_of_marks));

        // Toggling back requests the plain image again.
        model.dispatch(UiAction::ToggleMarks, &service);
        assert!(!model.marks_overlay);
        assert!(!model.tabs[0].surface.marks_overlay);
        model.dispatch(UiAction::RefreshScreenshot, &service);
        assert_eq!(
            service.calls(),
            vec![
                "screenshot:session-0:marks=true",
                "screenshot:session-0:marks=false",
            ]
        );
    }

    #[test]
    fn selecting_tab_restores_that_tabs_marks_state() {
        let service = MockService::default();
        let mut first = Tab::new("session-0", None, "https://a.test");
        first.surface.set_marks_overlay(true);
        let second = Tab::new("session-1", None, "https://b.test");
        let mut model = ShellUiModel {
            tabs: vec![first, second],
            active_tab: Some(0),
            marks_overlay: true,
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::SelectTab(1), &service);
        assert!(!model.marks_overlay);

        model.dispatch(UiAction::SelectTab(0), &service);
        assert!(model.marks_overlay);
    }

    #[test]
    fn poll_events_populates_ordered_journal_for_active_tab() {
        let service = MockService {
            canned_events: vec![
                created_event("session-0", 0, "https://a.test"),
                created_event("session-0", 1, "https://a.test"),
            ],
            ..MockService::default()
        };
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::PollEvents, &service);

        // First poll uses no cursor; the journal follows the active session.
        assert_eq!(service.calls(), vec!["events:session-0:-"]);
        assert_eq!(model.journal.session_id.as_deref(), Some("session-0"));
        assert_eq!(
            model
                .journal
                .entries
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(model.journal.cursor, Some(1));

        // A second poll advances the cursor and appends only newer events.
        model.dispatch(UiAction::PollEvents, &service);
        assert_eq!(
            service.calls(),
            vec!["events:session-0:-", "events:session-0:1"]
        );
        assert_eq!(model.journal.entries.len(), 2);
    }

    #[test]
    fn poll_events_raises_blocking_takeover_banner_then_resume_clears_it() {
        use tempo_schema::TakeoverKind;

        // A takeover surfaces on the same /events poll the agent panel runs.
        let service = MockService {
            canned_events: vec![
                created_event("session-0", 0, "https://a.test"),
                takeover_event("session-0", 1),
            ],
            ..MockService::default()
        };
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::PollEvents, &service);

        // The banner is up and blocking, naming the reason variant + URL.
        let banner = model.journal.takeover();
        assert!(banner.is_blocking(), "takeover must block the shell");
        let Some(pending) = banner.pending() else {
            panic!("takeover pending");
        };
        assert_eq!(pending.kind, TakeoverKind::Captcha);
        assert_eq!(pending.url, "https://a.test/verify");
        assert_eq!(banner.reason_label(), Some("captcha"));
        assert_eq!(
            model.tabs[0].surface.run_state,
            SurfaceRunState::HumanTakeoverRequired
        );
        assert_eq!(model.tabs[0].surface.owner, ControlOwner::Agent);
        assert!(model.tabs[0].surface.pending_takeover.is_some());

        // The human clicks Resume: the local block clears, and the status is
        // truthful that the agent is not yet signalled (no resume RPC exists).
        model.dispatch(UiAction::ResumeTakeover, &service);
        assert!(
            !model.journal.takeover().is_blocking(),
            "Resume clears the local block"
        );
        assert!(model.tabs[0].surface.pending_takeover.is_none());
        assert!(model.status.contains("dismissed locally"));
        assert!(model.status.contains("no resume signal to the agent"));
    }

    #[test]
    fn poll_events_without_takeover_does_not_raise_the_banner() {
        let service = MockService {
            canned_events: vec![
                created_event("session-0", 0, "https://a.test"),
                created_event("session-0", 1, "https://a.test"),
            ],
            ..MockService::default()
        };
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::PollEvents, &service);

        assert!(
            !model.journal.takeover().is_blocking(),
            "ordinary events must not raise the takeover banner"
        );
    }

    #[test]
    fn resume_takeover_without_a_pending_banner_is_a_no_op() {
        let service = MockService::default();
        let mut model = ShellUiModel::default();
        let before = model.status.clone();

        model.dispatch(UiAction::ResumeTakeover, &service);

        assert!(!model.journal.takeover().is_blocking());
        assert_eq!(model.status, before, "no spurious status change");
    }

    #[test]
    fn poll_events_without_active_tab_is_a_no_op() {
        let service = MockService::default();
        let mut model = ShellUiModel::default();

        model.dispatch(UiAction::PollEvents, &service);

        assert!(service.calls().is_empty());
        assert!(model.journal.entries.is_empty());
    }

    #[test]
    fn poll_events_error_surfaces_to_status_line() {
        let service = MockService {
            fail: Some("events"),
            ..MockService::default()
        };
        let mut model = ShellUiModel {
            tabs: vec![Tab::new("session-0", None, "https://a.test")],
            active_tab: Some(0),
            ..ShellUiModel::default()
        };

        model.dispatch(UiAction::PollEvents, &service);

        assert!(model.journal.entries.is_empty());
        assert!(model.status.contains("events failed"));
    }

    /// The reducer drives a real tempod over the existing ShellClient transport,
    /// mirroring `client_drives_real_tempod_session_lifecycle`.
    #[test]
    fn model_drives_real_tempod_lifecycle() -> TestResult {
        let pool = Arc::new(Mutex::new(
            SessionPool::default().with_navigation_url_policy(tempo_net::UrlPolicy::allow_all()),
        ));
        let driver_handle = attach_test_driver(&pool)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::clone(&pool);
        // serve_forever loops until the process exits; the test never joins it.
        thread::spawn(move || {
            let _ = serve_forever(listener, server_pool);
        });

        let client = ShellClient::new(addr.to_string());
        let mut model = ShellUiModel::new(addr.to_string());

        model.dispatch(UiAction::Refresh, &client);
        assert_eq!(model.healthy, Some(true));
        assert!(model.sessions.is_empty());

        model.open_url = "https://example.com/tempo".into();
        model.dispatch(UiAction::Open, &client);
        assert_eq!(model.sessions.len(), 1);
        let session_id = model.sessions[0].id.clone();
        assert_eq!(model.sessions[0].url, "https://example.com/tempo");

        model.dispatch(UiAction::Adopt(session_id.clone()), &client);
        assert_eq!(model.sessions[0].state, "adopted");

        model.dispatch(UiAction::Close(session_id), &client);
        assert_eq!(model.sessions[0].state, "killed");
        detach_test_driver(&pool, driver_handle)?;
        Ok(())
    }

    fn attach_test_driver(
        pool: &Arc<Mutex<SessionPool>>,
    ) -> Result<thread::JoinHandle<Result<(), EngineHostError>>, Box<dyn Error>> {
        let (client_stream, server_stream) = UnixStream::pair()?;
        pool.lock()
            .map_err(|_| "session pool lock failed")?
            .attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
        Ok(thread::spawn(move || {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new().allow_private_network_access();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        }))
    }

    fn join_driver(
        handle: thread::JoinHandle<Result<(), EngineHostError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("driver thread failed".into()),
        }
    }

    fn detach_test_driver(
        pool: &Arc<Mutex<SessionPool>>,
        handle: thread::JoinHandle<Result<(), EngineHostError>>,
    ) -> Result<(), Box<dyn Error>> {
        pool.lock()
            .map_err(|_| "session pool lock failed")?
            .detach_engine_driver();
        join_driver(handle)
    }
}
