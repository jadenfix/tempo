//! Window-free tab, client-tracked history, and screenshot-image model.
//!
//! Every type here is pure data with pure methods: no winit/egui, no socket, no
//! I/O. That keeps the browser-chrome logic (per-tab history stack, omnibox
//! target, screenshot snapshot) unit-testable in headless CI, exactly like the
//! [`crate::ui`] reducer it feeds. The eframe event loop in [`crate::window`] is
//! a thin renderer over these structs.
//!
//! Two framing notes the DoD calls for:
//!
//! * Back/forward is **client-tracked**. `DriverTrait` exposes no native
//!   browser-history primitive, so [`History`] keeps the URL stack itself and the
//!   reducer re-issues a `goto` on back/forward.
//! * The screenshot is a **single-shot snapshot**, not a live viewport. A
//!   [`ScreenshotImage`] is the base64 PNG returned by the `screenshot` MCP tool,
//!   refreshed on an interval or a button — there is no input forwarding into it.
//!   The live pixel-interactive viewport is deferred to #349/#246.

use serde_json::Value;

use crate::surface::BrowserSurface;
use crate::ShellError;

/// A client-tracked URL history stack with standard back/forward semantics.
///
/// `entries` is the ordered navigation list and `cursor` points at the currently
/// shown entry. Pushing a new navigation truncates everything after the cursor
/// (the forward stack), matching how a browser discards forward history once you
/// navigate somewhere new.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    entries: Vec<String>,
    cursor: usize,
}

impl History {
    /// An empty history (no current entry).
    pub fn new() -> Self {
        Self::default()
    }

    /// A history seeded with `url` as the current (and only) entry.
    pub fn with_current(url: impl Into<String>) -> Self {
        Self {
            entries: vec![url.into()],
            cursor: 0,
        }
    }

    /// The URL currently shown, or `None` if the history is empty.
    pub fn current(&self) -> Option<&str> {
        self.entries.get(self.cursor).map(String::as_str)
    }

    /// Whether a `back` would move (there is an older entry).
    pub fn can_back(&self) -> bool {
        self.cursor > 0
    }

    /// Whether a `forward` would move (there is a newer entry).
    pub fn can_forward(&self) -> bool {
        self.cursor + 1 < self.entries.len()
    }

    /// Number of entries in the stack.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the stack has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Push a new navigation: drop any forward entries, append `url`, and make it
    /// current. This is the "typed a new URL / clicked a link" path.
    pub fn push(&mut self, url: impl Into<String>) {
        let url = url.into();
        if self.entries.is_empty() {
            self.entries.push(url);
            self.cursor = 0;
            return;
        }
        self.entries.truncate(self.cursor + 1);
        self.entries.push(url);
        self.cursor = self.entries.len() - 1;
    }

    /// Move back one entry, returning the now-current URL, or `None` if already at
    /// the oldest entry.
    pub fn back(&mut self) -> Option<&str> {
        if self.can_back() {
            self.cursor -= 1;
            self.current()
        } else {
            None
        }
    }

    /// Move forward one entry, returning the now-current URL, or `None` if already
    /// at the newest entry.
    pub fn forward(&mut self) -> Option<&str> {
        if self.can_forward() {
            self.cursor += 1;
            self.current()
        } else {
            None
        }
    }
}

/// A single-shot page snapshot: the base64 PNG returned by the `screenshot` MCP
/// tool. Deliberately not a live frame — see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenshotImage {
    pub mime_type: String,
    pub encoding: String,
    /// Whether this snapshot has the set-of-marks overlay drawn on it, as
    /// reported by the tool. Lets the renderer label the overlaid image.
    pub set_of_marks: bool,
    /// Base64-encoded image bytes, exactly as the MCP tool returned them. The
    /// window decodes this for display; the model never needs the raw pixels.
    pub data: String,
}

impl ScreenshotImage {
    /// Parse the `structuredContent` payload of a `screenshot` tool result.
    pub fn from_structured(value: &Value) -> Result<Self, ShellError> {
        let field = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| ShellError::Protocol(format!("screenshot response missing {key}")))
        };
        Ok(Self {
            mime_type: field("mime_type")?.to_string(),
            encoding: field("encoding")?.to_string(),
            // The tool always reports this; default false if an older peer omits it.
            set_of_marks: value
                .get("set_of_marks")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            data: field("data")?.to_string(),
        })
    }
}

/// One browser tab, driving one tempod session.
///
/// `driver_id` is the MCP driver this tab's `goto`/`screenshot` calls target:
/// `None` is tempod's default attached driver. Per-tab independent drivers
/// (so every tab renders its own session concurrently) are the shared-session
/// substrate deferred to #246; the field is the routing handle that lands ready
/// for it, and the reducer already forwards it to every call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tab {
    /// The tempod session id this tab owns (for display and close).
    pub session_id: String,
    /// The MCP driver target for this tab's navigation/screenshot calls.
    pub driver_id: Option<String>,
    /// The editable omnibox text for this tab.
    pub omnibox: String,
    /// Client-tracked back/forward URL stack.
    pub history: History,
    /// The most recent page snapshot, if one has been fetched.
    pub screenshot: Option<ScreenshotImage>,
    /// Bumped on every successful screenshot refresh so the renderer can tell a
    /// new snapshot from a repaint without diffing image bytes.
    pub screenshot_seq: u64,
    /// Per-tab status line (errors and progress; never a panic).
    pub status: String,
    /// Engine-neutral foreground page state. Today this describes the screenshot
    /// pane; the same state is what a live Servo/WebView surface will update.
    pub surface: BrowserSurface,
}

impl Tab {
    /// Build a tab for `session_id` seeded at `initial_url`, targeting
    /// `driver_id` for its MCP calls.
    pub fn new(
        session_id: impl Into<String>,
        driver_id: Option<String>,
        initial_url: impl Into<String>,
    ) -> Self {
        let session_id = session_id.into();
        let url = initial_url.into();
        let surface =
            BrowserSurface::human_snapshot(session_id.clone(), driver_id.as_deref(), url.clone());
        Self {
            session_id,
            driver_id,
            omnibox: url.clone(),
            history: History::with_current(url),
            screenshot: None,
            screenshot_seq: 0,
            status: "New tab.".to_string(),
            surface,
        }
    }

    /// The URL currently shown in this tab, if any.
    pub fn current_url(&self) -> Option<&str> {
        self.history.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_history_has_no_current_and_cannot_move() {
        let history = History::new();
        assert!(history.is_empty());
        assert_eq!(history.current(), None);
        assert!(!history.can_back());
        assert!(!history.can_forward());
    }

    #[test]
    fn push_advances_current_and_stack_grows() {
        let mut history = History::new();
        history.push("https://a.test");
        assert_eq!(history.current(), Some("https://a.test"));
        assert_eq!(history.len(), 1);
        assert!(!history.can_back());

        history.push("https://b.test");
        assert_eq!(history.current(), Some("https://b.test"));
        assert_eq!(history.len(), 2);
        assert!(history.can_back());
        assert!(!history.can_forward());
    }

    #[test]
    fn back_and_forward_walk_the_stack() {
        let mut history = History::with_current("https://a.test");
        history.push("https://b.test");
        history.push("https://c.test");

        assert_eq!(history.back(), Some("https://b.test"));
        assert_eq!(history.current(), Some("https://b.test"));
        assert!(history.can_forward());

        assert_eq!(history.back(), Some("https://a.test"));
        assert_eq!(history.back(), None, "already at oldest entry");
        assert_eq!(history.current(), Some("https://a.test"));

        assert_eq!(history.forward(), Some("https://b.test"));
        assert_eq!(history.forward(), Some("https://c.test"));
        assert_eq!(history.forward(), None, "already at newest entry");
    }

    #[test]
    fn push_truncates_forward_stack() {
        let mut history = History::with_current("https://a.test");
        history.push("https://b.test");
        history.push("https://c.test");
        // Walk back, then navigate somewhere new: forward history is discarded.
        history.back();
        history.back();
        assert_eq!(history.current(), Some("https://a.test"));
        assert!(history.can_forward());

        history.push("https://d.test");
        assert_eq!(history.current(), Some("https://d.test"));
        assert_eq!(history.len(), 2, "b/c dropped, only a + d remain");
        assert!(!history.can_forward());
        assert_eq!(history.back(), Some("https://a.test"));
    }

    #[test]
    fn tab_seeds_history_and_omnibox_from_initial_url() {
        let tab = Tab::new("session-0", None, "https://start.test");
        assert_eq!(tab.session_id, "session-0");
        assert_eq!(tab.omnibox, "https://start.test");
        assert_eq!(tab.current_url(), Some("https://start.test"));
        assert!(tab.screenshot.is_none());
        assert_eq!(tab.screenshot_seq, 0);
    }

    #[test]
    fn screenshot_image_parses_structured_content() -> Result<(), ShellError> {
        let value = json!({
            "mime_type": "image/png",
            "encoding": "base64",
            "set_of_marks": true,
            "data": "QUJD",
        });
        let image = ScreenshotImage::from_structured(&value)?;
        assert_eq!(image.mime_type, "image/png");
        assert_eq!(image.encoding, "base64");
        assert!(image.set_of_marks);
        assert_eq!(image.data, "QUJD");
        Ok(())
    }

    #[test]
    fn screenshot_image_rejects_missing_data() {
        let value = json!({ "mime_type": "image/png", "encoding": "base64" });
        assert!(matches!(
            ScreenshotImage::from_structured(&value),
            Err(ShellError::Protocol(_))
        ));
    }
}
