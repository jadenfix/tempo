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

use crate::{HealthResponse, ShellClient, ShellError};
use tempo_headless::{TempodSession, TempodSessionState};

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
}

impl Default for ShellUiModel {
    fn default() -> Self {
        Self {
            base_url: crate::DEFAULT_TEMPOD_ADDR.to_string(),
            open_url: String::new(),
            sessions: Vec::new(),
            status: "Idle — press Refresh to list sessions.".to_string(),
            healthy: None,
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
        }
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
            }
            Err(err) => self.set_error("close", &err),
        }
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
    use std::cell::RefCell;
    use std::error::Error;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempo_headless::{serve_forever, SessionPool, TempodSessionId};

    type TestResult = Result<(), Box<dyn Error>>;

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
        fail: Option<&'static str>,
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
        assert!(model.status.contains("Adopted"));
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

    /// The reducer drives a real tempod over the existing ShellClient transport,
    /// mirroring `client_drives_real_tempod_session_lifecycle`.
    #[test]
    fn model_drives_real_tempod_lifecycle() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
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

        model.open_url = "https://tempo.test".into();
        model.dispatch(UiAction::Open, &client);
        assert_eq!(model.sessions.len(), 1);
        let session_id = model.sessions[0].id.clone();
        assert_eq!(model.sessions[0].url, "https://tempo.test");

        model.dispatch(UiAction::Adopt(session_id.clone()), &client);
        assert_eq!(model.sessions[0].state, "adopted");

        model.dispatch(UiAction::Close(session_id), &client);
        assert_eq!(model.sessions[0].state, "killed");
        Ok(())
    }
}
