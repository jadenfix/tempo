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

use crate::tab::ScreenshotImage;
use crate::transport::TransportClient;
use crate::ui::{SessionService, UiAction};
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
                    return Err(ShellError::Usage(format!(
                        "unknown option: {other}\nRun with --help for usage."
                    )));
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
        Box::new(|cc| {
            Ok(Box::new(ShellApp::new(config, cc.egui_ctx.clone())) as Box<dyn eframe::App>)
        }),
    )
    .map_err(|err| WindowError::Backend(err.to_string()))
}

/// The winit/egui application. It owns no transport of its own: all tempod
/// round-trips run on the [`TransportClient`] worker thread, so a slow or
/// unreachable tempod never blocks the render thread (#404). Each frame it drains
/// completed results into the last-known model and renders that, forwarding user
/// actions and the poll timer to the worker.
struct ShellApp {
    transport: TransportClient,
    poll_interval: Duration,
    last_poll: Option<Instant>,
    /// Decoded texture for the active tab's latest snapshot, plus the
    /// `(session_id, screenshot_seq)` it was decoded from so we only re-decode
    /// when a fresh snapshot arrives (not every repaint).
    screenshot_texture: Option<egui::TextureHandle>,
    rendered_snapshot: Option<(String, u64)>,
}

impl ShellApp {
    fn new(config: WindowConfig, ctx: egui::Context) -> Self {
        // The worker rebuilds the transport from the (editable) base URL on every
        // dispatch, exactly as the old inline path did; the auth token is folded
        // in here. Injected as a factory so the worker owns no egui/window types.
        let auth_token = config.auth_token;
        let factory = move |base_url: &str| -> Box<dyn SessionService> {
            let mut client = ShellClient::new(base_url.to_string());
            if let Some(token) = &auth_token {
                client = client.with_auth_token(token.clone());
            }
            Box::new(client)
        };
        // Wake the UI thread when a result lands so it repaints promptly instead of
        // waiting out the poll timer.
        let transport =
            TransportClient::spawn(config.base_url, factory, move || ctx.request_repaint());
        Self {
            transport,
            poll_interval: config.poll_interval,
            last_poll: None,
            screenshot_texture: None,
            rendered_snapshot: None,
        }
    }

    fn due_for_poll(&self) -> bool {
        match self.last_poll {
            None => true,
            Some(at) => at.elapsed() >= self.poll_interval,
        }
    }

    /// Render the active tab's page-state image: the latest single-shot
    /// screenshot, decoded to a texture. Deliberately not interactive — no input
    /// is forwarded into the image (the live viewport is deferred to #349/#246).
    /// Decode failures surface as a label; nothing here panics.
    fn show_page_state(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.transport.model.active_tab().and_then(|tab| {
            tab.screenshot
                .as_ref()
                .map(|image| (tab.session_id.clone(), tab.screenshot_seq, image.clone()))
        });
        let Some((session_id, seq, image)) = snapshot else {
            ui.label("(no page snapshot yet — press \"Refresh page\")");
            return;
        };

        let key = (session_id, seq);
        if self.rendered_snapshot.as_ref() != Some(&key) {
            match decode_screenshot(ui.ctx(), &image) {
                Ok(texture) => {
                    self.screenshot_texture = Some(texture);
                    self.rendered_snapshot = Some(key);
                }
                Err(err) => {
                    ui.label(format!("page snapshot decode failed: {err}"));
                    return;
                }
            }
        }

        if let Some(texture) = &self.screenshot_texture {
            let marked = self
                .transport
                .model
                .active_tab()
                .and_then(|tab| tab.screenshot.as_ref())
                .is_some_and(|image| image.set_of_marks);
            let caption = if marked {
                "page state (periodic snapshot, set-of-marks overlay — not a live viewport):"
            } else {
                "page state (periodic snapshot — not a live viewport):"
            };
            ui.label(caption);
            let sized = egui::load::SizedTexture::from_handle(texture);
            ui.add(egui::Image::new(sized).max_width(ui.available_width()));
        }
    }

    /// Render the agent panel's journal/event stream: a scrolling, ordered log of
    /// the active session's `/sessions/{id}/events`. Read-only; the reducer owns
    /// all state. Tainted steps are flagged inline.
    fn show_agent_journal(&self, ui: &mut egui::Ui) {
        ui.separator();
        ui.label("agent journal (session events):");
        if self.transport.model.journal.entries.is_empty() {
            ui.label("(no events yet)");
            return;
        }
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in &self.transport.model.journal.entries {
                    let mut line = format!("#{} {}", entry.seq, entry.kind);
                    if !entry.detail.is_empty() {
                        line.push_str(&format!(" — {}", entry.detail));
                    }
                    let text = egui::RichText::new(line).monospace();
                    let text = if entry.tainted {
                        text.color(egui::Color32::from_rgb(220, 50, 50))
                    } else {
                        text
                    };
                    ui.label(text);
                }
            });
    }
}

/// Decode a [`ScreenshotImage`] (base64 PNG) into an egui texture. Window-only:
/// the pure model never touches pixels.
fn decode_screenshot(
    ctx: &egui::Context,
    image: &ScreenshotImage,
) -> Result<egui::TextureHandle, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(image.data.as_bytes())
        .map_err(|err| err.to_string())?;
    let color_image = decode_png_to_color_image(&bytes)?;
    Ok(ctx.load_texture(
        "tab-page-state",
        color_image,
        egui::TextureOptions::default(),
    ))
}

/// Decode 8-bit PNG bytes into an RGBA [`egui::ColorImage`]. Mirrors the
/// expand/strip transforms tempo-observe uses so grayscale/indexed/16-bit
/// screenshots still render.
fn decode_png_to_color_image(png_bytes: &[u8]) -> Result<egui::ColorImage, String> {
    let mut decoder = png::Decoder::new(png_bytes);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|err| err.to_string())?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buffer)
        .map_err(|err| err.to_string())?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(format!("unsupported PNG bit depth: {:?}", info.bit_depth));
    }

    let pixels = &buffer[..info.buffer_size()];
    let width = info.width as usize;
    let height = info.height as usize;
    let expected = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| "PNG dimensions overflow".to_string())?;

    let rgba = match info.color_type {
        png::ColorType::Rgba => pixels.to_vec(),
        png::ColorType::Rgb => {
            let mut out = Vec::with_capacity(expected);
            for chunk in pixels.chunks_exact(3) {
                out.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            out
        }
        png::ColorType::Grayscale => {
            let mut out = Vec::with_capacity(expected);
            for gray in pixels {
                out.extend_from_slice(&[*gray, *gray, *gray, 255]);
            }
            out
        }
        png::ColorType::GrayscaleAlpha => {
            let mut out = Vec::with_capacity(expected);
            for chunk in pixels.chunks_exact(2) {
                out.extend_from_slice(&[chunk[0], chunk[0], chunk[0], chunk[1]]);
            }
            out
        }
        other => return Err(format!("unsupported PNG color type: {other:?}")),
    };

    if rgba.len() != expected {
        return Err(format!(
            "PNG frame size mismatch: got {}, expected {expected}",
            rgba.len()
        ));
    }
    Ok(egui::ColorImage::from_rgba_unmultiplied(
        [width, height],
        &rgba,
    ))
}

impl eframe::App for ShellApp {
    // egui 0.35: `ui` receives the root `Ui` (the central area) directly; the
    // `Context` is reached via `ui.ctx()`.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Apply everything the worker finished since the last frame, then render
        // the last-known model. This never blocks on the socket (#404).
        self.transport.drain();

        if self.due_for_poll() {
            self.transport.enqueue(UiAction::Refresh);
            // Keep the active tab's page-state snapshot and journal/event stream
            // fresh on the same cadence (the DoD's "refreshed on an interval"; the
            // buttons below are the manual paths). The worker coalesces a poll of a
            // kind already in flight so a slow tempod can't make them pile up.
            if self.transport.model.active_tab().is_some() {
                self.transport.enqueue(UiAction::RefreshScreenshot);
                self.transport.enqueue(UiAction::PollEvents);
            }
            self.last_poll = Some(Instant::now());
        }

        let mut pending: Option<UiAction> = None;
        {
            ui.heading("tempo-shell");

            // Blocking human-takeover banner (#354): when the session event stream
            // surfaces a HumanTakeoverRequired, the agent is paused and this banner
            // stays up until the human clicks Resume. It never auto-continues — see
            // `TakeoverBanner`. Rendered first, above the rest of the chrome.
            let banner_line = self.transport.model.journal.takeover().banner_line();
            if let Some(line) = banner_line {
                ui.group(|ui| {
                    ui.label(
                        egui::RichText::new("⚠ HUMAN TAKEOVER REQUIRED")
                            .heading()
                            .strong()
                            .color(egui::Color32::from_rgb(220, 50, 50)),
                    );
                    ui.label(egui::RichText::new(&line).strong());
                    ui.label(
                        "The agent is paused and will NOT auto-continue. Resolve the challenge \
                         in the page, then click Resume.",
                    );
                    if ui.button("Resume").clicked() {
                        pending = Some(UiAction::ResumeTakeover);
                    }
                });
                ui.separator();
            }

            // Read-only display values are pulled off the last-known model before
            // the row so the editable buffers (base_url/open_url/omnibox) are the
            // only fields borrowed mutably inside the closures.
            let health = match self.transport.model.healthy {
                Some(true) => "health: ok",
                Some(false) => "health: DOWN",
                None => "health: unknown",
            };
            // Always-visible taint badge: reflects contains_untrusted over the
            // active session's latest observation (from the events stream).
            let taint = self.transport.model.journal.taint();
            ui.horizontal(|ui| {
                ui.label("tempod:");
                ui.text_edit_singleline(&mut self.transport.base_url);
                if ui.button("Refresh").clicked() {
                    pending = Some(UiAction::Refresh);
                }
                ui.label(health);
                let badge = egui::RichText::new(taint.label());
                let badge = if taint.is_tainted() {
                    badge.color(egui::Color32::from_rgb(220, 50, 50)).strong()
                } else {
                    badge
                };
                ui.label(badge);
            });
            ui.horizontal(|ui| {
                ui.label("new tab URL:");
                ui.text_edit_singleline(&mut self.transport.open_url);
                if ui.button("New Tab").clicked() {
                    pending = Some(UiAction::NewTab);
                }
            });

            ui.separator();

            // Tab strip: one selectable per tempod session, with a close button.
            ui.horizontal_wrapped(|ui| {
                if self.transport.model.tabs.is_empty() {
                    ui.label("(no tabs — open one above)");
                }
                for (index, tab) in self.transport.model.tabs.iter().enumerate() {
                    let is_active = self.transport.model.active_tab == Some(index);
                    let title = tab.current_url().unwrap_or(&tab.session_id);
                    if ui.selectable_label(is_active, title).clicked() {
                        pending = Some(UiAction::SelectTab(index));
                    }
                    if ui.small_button("x").clicked() {
                        pending = Some(UiAction::CloseTab(index));
                    }
                }
            });

            // Active-tab chrome: omnibox + back/forward + refresh, then the
            // periodically-refreshed page-state image (NOT a live viewport). The
            // omnibox binds to the UI-thread buffer; read-only history/status come
            // off the snapshot (last-known while a request is in flight).
            if let Some(active) = self.transport.model.active_tab {
                let chrome = self.transport.model.tabs.get(active).map(|tab| {
                    (
                        tab.history.can_back(),
                        tab.history.can_forward(),
                        tab.status.clone(),
                    )
                });
                if let Some((can_back, can_forward, tab_status)) = chrome {
                    let marks_overlay = self.transport.model.marks_overlay;
                    ui.horizontal(|ui| {
                        if ui.add_enabled(can_back, egui::Button::new("←")).clicked() {
                            pending = Some(UiAction::Back);
                        }
                        if ui
                            .add_enabled(can_forward, egui::Button::new("→"))
                            .clicked()
                        {
                            pending = Some(UiAction::Forward);
                        }
                        ui.text_edit_singleline(&mut self.transport.omnibox);
                        if ui.button("Go").clicked() {
                            pending = Some(UiAction::Navigate);
                        }
                        if ui.button("Refresh page").clicked() {
                            pending = Some(UiAction::RefreshScreenshot);
                        }
                        // Set-of-marks overlay toggle; the flip re-requests the
                        // image on the next screenshot refresh.
                        let mut marks = marks_overlay;
                        if ui.checkbox(&mut marks, "set-of-marks").changed() {
                            pending = Some(UiAction::ToggleMarks);
                        }
                    });
                    ui.label(tab_status);
                }
            }

            ui.separator();
            ui.label(&self.transport.model.status);
            if self.transport.is_down() {
                ui.label(
                    egui::RichText::new("transport worker stopped — showing last-known state")
                        .color(egui::Color32::from_rgb(220, 50, 50)),
                );
            }
        }

        if let Some(action) = pending {
            self.transport.enqueue(action);
        }

        self.show_page_state(ui);
        self.show_agent_journal(ui);

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
    /// config without opening a window (no display required in CI). The transport
    /// worker is spawned but idle until an action is enqueued.
    #[test]
    fn shell_app_constructs_from_config() {
        let app = ShellApp::new(WindowConfig::default(), egui::Context::default());
        assert_eq!(app.transport.model.base_url, DEFAULT_TEMPOD_ADDR);
        assert_eq!(app.transport.base_url, DEFAULT_TEMPOD_ADDR);
        assert!(app.last_poll.is_none());
        assert!(app.due_for_poll());
        assert!(app.screenshot_texture.is_none());
    }

    /// The screenshot-pane decode path is pure (no display) and expands RGB to
    /// RGBA, so it can be unit tested without opening a window.
    #[test]
    fn decodes_rgb_png_to_rgba_color_image() -> Result<(), String> {
        let mut png_bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png_bytes, 2, 1);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().map_err(|err| err.to_string())?;
            writer
                .write_image_data(&[10, 20, 30, 40, 50, 60])
                .map_err(|err| err.to_string())?;
        }

        let color = decode_png_to_color_image(&png_bytes)?;
        assert_eq!(color.size, [2, 1]);
        assert_eq!(
            color.pixels[0],
            egui::Color32::from_rgba_unmultiplied(10, 20, 30, 255)
        );
        assert_eq!(
            color.pixels[1],
            egui::Color32::from_rgba_unmultiplied(40, 50, 60, 255)
        );
        Ok(())
    }
}
