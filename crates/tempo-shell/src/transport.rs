//! Off-UI-thread transport for the egui shell (#404).
//!
//! The [`crate::ui`] reducer talks to tempod through a synchronous
//! [`SessionService`] (the blocking [`crate::ShellClient`]). Driving it inline on
//! the egui render thread — as the window used to — froze the whole browser
//! whenever tempod was slow or unreachable, exactly when a human takeover matters
//! most: each 3s poll fires up to four blocking round-trips (`Refresh`,
//! `RefreshScreenshot`, `PollEvents`) on the render thread.
//!
//! This module moves every network round-trip onto a background worker thread. It
//! owns the authoritative [`ShellUiModel`] and runs the *unchanged* reducer there;
//! the UI thread sends [`UiAction`]s over a channel and drains freshly-mutated
//! model snapshots back, never blocking on the socket. It renders last-known state
//! while a request is in flight and coalesces duplicate in-flight poll requests so
//! a slow tempod cannot make them pile up.
//!
//! It deliberately depends on nothing from winit/egui (the render glue in
//! [`crate::window`] injects a repaint callback as a plain `Fn`), so the whole
//! transport seam is unit-testable in headless CI without a display or a live
//! tempod.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::ui::{SessionService, ShellUiModel, UiAction};

/// Builds a fresh [`SessionService`] for a tempod base URL. The worker rebuilds
/// the transport per dispatch because the base URL is a user-editable field —
/// mirroring the old inline `ShellApp::dispatch`, which built a `ShellClient`
/// from `model.base_url` on every action.
pub trait ServiceFactory: Send + 'static {
    fn make(&self, base_url: &str) -> Box<dyn SessionService>;
}

impl<F> ServiceFactory for F
where
    F: Fn(&str) -> Box<dyn SessionService> + Send + 'static,
{
    fn make(&self, base_url: &str) -> Box<dyn SessionService> {
        (self)(base_url)
    }
}

/// A unit of work for the worker. Carries the UI thread's editable text buffers so
/// the worker's model reflects the user's latest input before the reducer reads
/// it (the reducer takes these fields from the model: `base_url` to build the
/// client, `open_url` for open/new-tab, the active tab's `omnibox` for navigate).
enum WorkerRequest {
    Dispatch {
        action: UiAction,
        base_url: String,
        open_url: String,
        omnibox: String,
    },
    Shutdown,
}

/// The worker's reply after processing one request: the freshly-mutated model and
/// the action that produced it (so the UI can clear the coalescing flag and decide
/// whether to resync its input buffers).
struct WorkerUpdate {
    model: ShellUiModel,
    completed: UiAction,
}

/// The three periodic poll actions. Only these are coalesced — user actions are
/// discrete clicks and each is its own request, exactly as before.
fn is_poll(action: &UiAction) -> bool {
    matches!(
        action,
        UiAction::Refresh | UiAction::RefreshScreenshot | UiAction::PollEvents
    )
}

/// Which poll kinds are currently in flight, so a new poll of the same kind is
/// dropped instead of piling up behind a slow tempod.
#[derive(Default)]
struct PollGate {
    refresh: bool,
    screenshot: bool,
    events: bool,
}

impl PollGate {
    /// The in-flight flag for a poll action, or `None` for non-poll (user)
    /// actions, which are never coalesced.
    fn slot(&mut self, action: &UiAction) -> Option<&mut bool> {
        match action {
            UiAction::Refresh => Some(&mut self.refresh),
            UiAction::RefreshScreenshot => Some(&mut self.screenshot),
            UiAction::PollEvents => Some(&mut self.events),
            _ => None,
        }
    }
}

/// Outcome of [`TransportClient::enqueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// The request was handed to the worker.
    Sent,
    /// A poll of this kind is already in flight; this duplicate was dropped.
    Coalesced,
    /// The worker is gone; nothing was sent (last-known state still renders).
    Disconnected,
}

/// The UI-thread handle to the transport worker.
///
/// Holds the last-known [`ShellUiModel`] snapshot (rendered while requests are in
/// flight) and the UI-thread-owned editable text buffers. The buffers are never
/// clobbered by poll results — polls never touch these fields — so typing survives
/// the 3s refresh cadence; they are resynced from the model only after a user
/// action that can change them (open clears `open_url`; back/forward and tab
/// switches set `omnibox`).
pub struct TransportClient {
    tx: Sender<WorkerRequest>,
    rx: Receiver<WorkerUpdate>,
    worker: Option<JoinHandle<()>>,
    /// Last model snapshot from the worker; the render source of truth.
    pub model: ShellUiModel,
    /// Editable tempod address (client is rebuilt from it per dispatch).
    pub base_url: String,
    /// Editable "open URL" / "new tab URL" field.
    pub open_url: String,
    /// Editable omnibox of the active tab.
    pub omnibox: String,
    gate: PollGate,
    down: bool,
}

impl TransportClient {
    /// Spawn the worker thread and return the UI-thread handle. `factory` builds
    /// the transport for a base URL; `wake` is invoked after each result so the UI
    /// repaints promptly (in the window it is `egui::Context::request_repaint`).
    pub fn spawn<F, W>(base_url: impl Into<String>, factory: F, wake: W) -> Self
    where
        F: ServiceFactory,
        W: Fn() + Send + 'static,
    {
        let base_url = base_url.into();
        let model = ShellUiModel::new(base_url.clone());
        let (req_tx, req_rx) = mpsc::channel::<WorkerRequest>();
        let (up_tx, up_rx) = mpsc::channel::<WorkerUpdate>();
        let worker_model = model.clone();
        let factory: Box<dyn ServiceFactory> = Box::new(factory);
        let wake: Box<dyn Fn() + Send + 'static> = Box::new(wake);
        let worker = thread::spawn(move || run_worker(worker_model, factory, req_rx, up_tx, wake));
        Self {
            tx: req_tx,
            rx: up_rx,
            worker: Some(worker),
            model,
            base_url,
            open_url: String::new(),
            omnibox: String::new(),
            gate: PollGate::default(),
            down: false,
        }
    }

    /// Whether the worker/channel has disconnected. The UI keeps rendering the
    /// last-known model in that case rather than panicking.
    pub fn is_down(&self) -> bool {
        self.down
    }

    /// Queue `action` for the worker without blocking. Poll actions already in
    /// flight are coalesced away; a dead worker yields [`Enqueued::Disconnected`].
    pub fn enqueue(&mut self, action: UiAction) -> Enqueued {
        if self.down {
            return Enqueued::Disconnected;
        }
        if let Some(flag) = self.gate.slot(&action)
            && *flag
        {
            return Enqueued::Coalesced;
        }
        let request = WorkerRequest::Dispatch {
            action: action.clone(),
            base_url: self.base_url.clone(),
            open_url: self.open_url.clone(),
            omnibox: self.omnibox.clone(),
        };
        match self.tx.send(request) {
            Ok(()) => {
                if let Some(flag) = self.gate.slot(&action) {
                    *flag = true;
                }
                Enqueued::Sent
            }
            Err(_) => {
                self.down = true;
                Enqueued::Disconnected
            }
        }
    }

    /// Apply every result the worker has finished since the last frame. Never
    /// blocks: it only drains what is already waiting.
    pub fn drain(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(update) => self.apply(update),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.down = true;
                    break;
                }
            }
        }
    }

    fn apply(&mut self, update: WorkerUpdate) {
        if let Some(flag) = self.gate.slot(&update.completed) {
            *flag = false;
        }
        let resync = !is_poll(&update.completed);
        self.model = update.model;
        if resync {
            // A user action may have cleared open_url (open/new-tab) or moved the
            // omnibox (back/forward, tab switch); adopt those. Poll results skip
            // this, so in-progress typing survives the refresh cadence.
            self.open_url = self.model.open_url.clone();
            self.omnibox = self
                .model
                .active_tab()
                .map(|tab| tab.omnibox.clone())
                .unwrap_or_default();
        }
    }

    /// Block up to `timeout` for the next result and apply it, returning the
    /// action that completed. The window loop uses [`Self::drain`] instead; this
    /// is for callers/tests that want to await one round-trip deterministically.
    pub fn wait_and_apply(&mut self, timeout: Duration) -> Option<UiAction> {
        match self.rx.recv_timeout(timeout) {
            Ok(update) => {
                let completed = update.completed.clone();
                self.apply(update);
                Some(completed)
            }
            Err(_) => None,
        }
    }

    /// Ask the worker to stop and wait for it. Idempotent; also run on drop. After
    /// this, [`Self::enqueue`] reports [`Enqueued::Disconnected`].
    pub fn shutdown(&mut self) {
        let _ = self.tx.send(WorkerRequest::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for TransportClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The worker thread: owns the authoritative model and runs the reducer against a
/// freshly-built transport for each request, off the UI thread.
fn run_worker(
    mut model: ShellUiModel,
    factory: Box<dyn ServiceFactory>,
    rx: Receiver<WorkerRequest>,
    tx: Sender<WorkerUpdate>,
    wake: Box<dyn Fn() + Send + 'static>,
) {
    while let Ok(request) = rx.recv() {
        let WorkerRequest::Dispatch {
            action,
            base_url,
            open_url,
            omnibox,
        } = request
        else {
            break; // Shutdown.
        };

        // Fold the UI thread's latest edits into the model before the reducer
        // reads them (it takes these straight off the model, as it always has).
        model.base_url = base_url;
        model.open_url = open_url;
        if let Some(active) = model.active_tab
            && let Some(tab) = model.tabs.get_mut(active)
        {
            tab.omnibox = omnibox;
        }

        let service = factory.make(&model.base_url);
        model.dispatch(action.clone(), service.as_ref());

        let update = WorkerUpdate {
            model: model.clone(),
            completed: action,
        };
        if tx.send(update).is_err() {
            break; // UI hung up.
        }
        wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tab::ScreenshotImage;
    use crate::{HealthResponse, ShellError};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tempo_headless::{TempodSession, TempodSessionEvent};

    /// A fake transport with no socket: records the calls it receives and returns
    /// canned health/sessions. `delay` lets a test hold a request "in flight" to
    /// prove the caller never blocks on it. Shared via `Arc` so a factory can
    /// clone it into every produced service and the test can inspect it after.
    #[derive(Clone, Default)]
    struct FakeService {
        calls: Arc<Mutex<Vec<String>>>,
        delay: Duration,
    }

    impl FakeService {
        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .unwrap_or_default()
        }

        fn record(&self, call: &str) {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(call.to_string());
            }
        }

        fn factory(&self) -> impl Fn(&str) -> Box<dyn SessionService> + Send + 'static {
            let template = self.clone();
            move |_base_url| Box::new(template.clone()) as Box<dyn SessionService>
        }
    }

    impl SessionService for FakeService {
        fn health(&self) -> Result<HealthResponse, ShellError> {
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            self.record("health");
            Ok(HealthResponse { ok: true })
        }

        fn sessions(&self) -> Result<Vec<TempodSession>, ShellError> {
            self.record("sessions");
            Ok(Vec::new())
        }

        fn open(&self, url: &str) -> Result<TempodSession, ShellError> {
            self.record(&format!("open:{url}"));
            Err(ShellError::Usage("open unused in transport tests".into()))
        }

        fn adopt(&self, session_id: &str) -> Result<TempodSession, ShellError> {
            self.record(&format!("adopt:{session_id}"));
            Err(ShellError::Usage("adopt unused in transport tests".into()))
        }

        fn close(&self, session_id: &str) -> Result<TempodSession, ShellError> {
            self.record(&format!("close:{session_id}"));
            Err(ShellError::Usage("close unused in transport tests".into()))
        }

        fn goto(&self, driver_id: Option<&str>, url: &str) -> Result<(), ShellError> {
            self.record(&format!("goto:{}:{url}", driver_id.unwrap_or("-")));
            Ok(())
        }

        fn screenshot(
            &self,
            driver_id: Option<&str>,
            set_of_marks: bool,
        ) -> Result<ScreenshotImage, ShellError> {
            self.record(&format!(
                "screenshot:{}:marks={set_of_marks}",
                driver_id.unwrap_or("-")
            ));
            Err(ShellError::Usage(
                "screenshot unused in transport tests".into(),
            ))
        }

        fn events(
            &self,
            session_id: &str,
            _after_seq: Option<u64>,
        ) -> Result<Vec<TempodSessionEvent>, ShellError> {
            self.record(&format!("events:{session_id}"));
            Ok(Vec::new())
        }
    }

    #[test]
    fn dispatch_runs_off_thread_and_applies_result_to_the_model() {
        let fake = FakeService::default();
        let mut client = TransportClient::spawn("127.0.0.1:0", fake.factory(), || {});

        assert_eq!(client.model.healthy, None, "no round-trip has run yet");
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Sent);

        // The reducer ran on the worker thread; its model update comes back here.
        assert_eq!(
            client.wait_and_apply(Duration::from_secs(5)),
            Some(UiAction::Refresh)
        );
        assert_eq!(client.model.healthy, Some(true));
        assert_eq!(fake.calls(), vec!["health", "sessions"]);
    }

    #[test]
    fn a_slow_request_never_blocks_the_caller() {
        let fake = FakeService {
            delay: Duration::from_millis(400),
            ..FakeService::default()
        };
        let mut client = TransportClient::spawn("127.0.0.1:0", fake.factory(), || {});

        let started = Instant::now();
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Sent);
        let enqueue_took = started.elapsed();
        assert!(
            enqueue_took < Duration::from_millis(200),
            "enqueue must return immediately, took {enqueue_took:?}"
        );

        // The worker is still inside the 400ms request: draining yields nothing and
        // the last-known model is unchanged. The UI thread stayed responsive.
        client.drain();
        assert_eq!(client.model.healthy, None);

        // The result still lands once the slow request completes.
        assert_eq!(
            client.wait_and_apply(Duration::from_secs(5)),
            Some(UiAction::Refresh)
        );
        assert_eq!(client.model.healthy, Some(true));
    }

    #[test]
    fn duplicate_in_flight_poll_requests_are_coalesced() {
        let fake = FakeService {
            // Hold the first Refresh in flight so the duplicate races it.
            delay: Duration::from_millis(300),
            ..FakeService::default()
        };
        let mut client = TransportClient::spawn("127.0.0.1:0", fake.factory(), || {});

        // First poll is sent; a second of the same kind, still in flight, is
        // dropped instead of piling up behind the slow tempod.
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Sent);
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Coalesced);

        // Once it completes and is applied, the gate reopens for the next poll.
        assert_eq!(
            client.wait_and_apply(Duration::from_secs(5)),
            Some(UiAction::Refresh)
        );
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Sent);

        // Exactly two Refreshes reached the transport, not three.
        client.wait_and_apply(Duration::from_secs(5));
        assert_eq!(
            fake.calls(),
            vec!["health", "sessions", "health", "sessions"]
        );
    }

    #[test]
    fn a_dead_worker_is_reported_not_panicked() {
        let fake = FakeService::default();
        let mut client = TransportClient::spawn("127.0.0.1:0", fake.factory(), || {});

        client.shutdown();

        // With the worker gone, enqueue degrades gracefully and the last-known
        // model still renders — no panic.
        assert_eq!(client.enqueue(UiAction::Refresh), Enqueued::Disconnected);
        assert!(client.is_down());
        client.drain();
    }
}
