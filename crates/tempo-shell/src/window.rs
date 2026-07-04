//! Thin winit+egui event loop over the tested [`crate::ui`] logic.
//!
//! This module is gated behind the non-default `window` feature: it pulls in the
//! first GUI stack in this crate (`eframe` = winit + egui + glow). CI's `check`
//! job has no display or GL system libraries, so keeping it off the default
//! feature set means `cargo check/build/test --workspace` never compile it.
//!
//! Everything with behaviour worth testing lives in [`crate::ui`]; this file is
//! the render/event glue and stays deliberately dumb. It builds a [`ShellClient`]
//! from the (editable) base-url field on every dispatch, so the transport is the
//! one already-tested [`ShellClient`], not a reimplementation.

use std::time::{Duration, Instant};

use eframe::egui;
use tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV;
use thiserror::Error;

use crate::ui::{ShellUiModel, UiAction};
use crate::{validate_auth_token, ShellClient, ShellError, DEFAULT_TEMPOD_ADDR};

const DEFAULT_POLL_SECONDS: u64 = 3;

/// How to reach tempod plus the poll cadence. Parsed from args/env by
/// [`WindowConfig::from_args_env`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowConfig {
    pub base_url: String,
    pub auth_token: Option<String>,
    pub poll_interval: Duration,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_TEMPOD_ADDR.to_string(),
            auth_token: None,
            poll_interval: Duration::from_secs(DEFAULT_POLL_SECONDS),
        }
    }
}

impl WindowConfig {
    /// Parse `--tempod ADDR`, `--auth-token TOKEN`, `--poll-seconds N`, falling
    /// back to the `TEMPO_TEMPOD_AUTH_TOKEN` env var for the token.
    pub fn from_args_env<I, S>(args: I) -> Result<Self, ShellError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::parse_with_env(args, std::env::var(TEMPO_TEMPOD_AUTH_TOKEN_ENV).ok())
    }

    fn parse_with_env<I, S>(args: I, env_auth_token: Option<String>) -> Result<Self, ShellError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut config = Self {
            auth_token: env_auth_token.filter(|token| !token.is_empty()),
            ..Self::default()
        };
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--tempod" => {
                    index += 1;
                    config.base_url = args
                        .get(index)
                        .ok_or_else(|| ShellError::Usage("--tempod requires ADDR".into()))?
                        .clone();
                }
                "--auth-token" => {
                    index += 1;
                    let token = args
                        .get(index)
                        .ok_or_else(|| ShellError::Usage("--auth-token requires TOKEN".into()))?
                        .clone();
                    validate_auth_token(&token)?;
                    config.auth_token = Some(token);
                }
                "--poll-seconds" => {
                    index += 1;
                    let raw = args
                        .get(index)
                        .ok_or_else(|| ShellError::Usage("--poll-seconds requires N".into()))?;
                    let seconds = raw.parse::<u64>().map_err(|err| {
                        ShellError::Usage(format!("--poll-seconds must be a u64: {err}"))
                    })?;
                    if seconds == 0 {
                        return Err(ShellError::Usage("--poll-seconds must be >= 1".into()));
                    }
                    config.poll_interval = Duration::from_secs(seconds);
                }
                other => {
                    return Err(ShellError::Usage(format!("unknown option: {other}")));
                }
            }
            index += 1;
        }
        Ok(config)
    }
}

/// Errors from launching the window. Transport/usage errors surface in the
/// in-window status line instead; these are the ones that stop the loop from
/// ever starting.
#[derive(Debug, Error)]
pub enum WindowError {
    #[error("{0}")]
    Config(#[from] ShellError),
    #[error("window backend failed: {0}")]
    Backend(String),
}

/// Open the window and run the event loop until the user closes it.
pub fn run(config: WindowConfig) -> Result<(), WindowError> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "tempo-shell",
        options,
        Box::new(|_cc| Ok(Box::new(ShellApp::new(config)) as Box<dyn eframe::App>)),
    )
    .map_err(|err| WindowError::Backend(err.to_string()))
}

/// The winit/egui application: owns the tested [`ShellUiModel`] and forwards
/// user actions and the poll timer into its reducer.
struct ShellApp {
    model: ShellUiModel,
    auth_token: Option<String>,
    poll_interval: Duration,
    last_poll: Option<Instant>,
}

impl ShellApp {
    fn new(config: WindowConfig) -> Self {
        Self {
            model: ShellUiModel::new(config.base_url),
            auth_token: config.auth_token,
            poll_interval: config.poll_interval,
            last_poll: None,
        }
    }

    /// Build the transport from the current base-url field and run one action
    /// through the reducer. All error handling lives in the reducer (status
    /// line); nothing here can panic.
    fn dispatch(&mut self, action: UiAction) {
        let mut client = ShellClient::new(self.model.base_url.clone());
        if let Some(token) = &self.auth_token {
            client = client.with_auth_token(token.clone());
        }
        self.model.dispatch(action, &client);
    }

    fn due_for_poll(&self) -> bool {
        match self.last_poll {
            None => true,
            Some(at) => at.elapsed() >= self.poll_interval,
        }
    }
}

impl eframe::App for ShellApp {
    // egui 0.35: `ui` receives the root `Ui` (the central area) directly; the
    // `Context` is reached via `ui.ctx()`.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.due_for_poll() {
            self.dispatch(UiAction::Refresh);
            self.last_poll = Some(Instant::now());
        }

        let mut pending: Option<UiAction> = None;
        {
            let model = &mut self.model;
            ui.heading("tempo-shell");
            ui.horizontal(|ui| {
                ui.label("tempod:");
                ui.text_edit_singleline(&mut model.base_url);
                if ui.button("Refresh").clicked() {
                    pending = Some(UiAction::Refresh);
                }
            });
            ui.horizontal(|ui| {
                ui.label("open URL:");
                ui.text_edit_singleline(&mut model.open_url);
                if ui.button("Open").clicked() {
                    pending = Some(UiAction::Open);
                }
            });
            ui.separator();
            let health = match model.healthy {
                Some(true) => "health: ok",
                Some(false) => "health: DOWN",
                None => "health: unknown",
            };
            ui.label(health);
            if model.sessions.is_empty() {
                ui.label("(no live sessions)");
            } else {
                for row in &model.sessions {
                    ui.horizontal(|ui| {
                        ui.monospace(&row.id);
                        ui.label(&row.state);
                        ui.label(&row.url);
                        if ui.button("Adopt").clicked() {
                            pending = Some(UiAction::Adopt(row.id.clone()));
                        }
                        if ui.button("Close").clicked() {
                            pending = Some(UiAction::Close(row.id.clone()));
                        }
                    });
                }
            }
            ui.separator();
            ui.label(&model.status);
        }

        if let Some(action) = pending {
            self.dispatch(action);
        }

        // Keep the poll cadence alive even when the user is idle.
        ui.ctx().request_repaint_after(self.poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_window_options_and_env_token() -> Result<(), ShellError> {
        let config = WindowConfig::parse_with_env(
            ["--tempod", "127.0.0.1:9000", "--poll-seconds", "5"],
            Some("env-token".into()),
        )?;
        assert_eq!(config.base_url, "127.0.0.1:9000");
        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.auth_token.as_deref(), Some("env-token"));
        Ok(())
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let err = WindowConfig::parse_with_env(["--poll-seconds", "0"], None);
        assert!(matches!(err, Err(ShellError::Usage(_))));
    }

    /// Smoke test: the window module compiles and the app constructs from a
    /// config without opening a window (no display required in CI).
    #[test]
    fn shell_app_constructs_from_config() {
        let app = ShellApp::new(WindowConfig::default());
        assert_eq!(app.model.base_url, DEFAULT_TEMPOD_ADDR);
        assert!(app.last_poll.is_none());
        assert!(app.due_for_poll());
    }
}
