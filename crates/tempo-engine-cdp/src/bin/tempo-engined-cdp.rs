//! `tempo-engined-cdp` — the runnable CDP-backed engine host for the human loop.
//!
//! It launches a headless Chromium via [`CdpTempoDriver`], binds the driver-UDS
//! named by `TEMPO_ENGINE_HOST_SOCKET`, and serves `DriverTrait` commands over it
//! until the daemon disconnects. Pair it with the daemon:
//!
//! ```text
//! SOCKET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tempo-engined-cdp.XXXXXX")"
//! TEMPO_ENGINE_HOST_SOCKET="$SOCKET_DIR/engine.sock" \
//!   TEMPO_CDP_CHROME=/path/to/chrome tempo-engined-cdp &
//! # wait for "listening on ...", then attach:
//! tempod --engine cdp --engine-socket "$SOCKET_DIR/engine.sock"
//! ```
//!
//! The socket path must live under a private directory; the server rejects
//! world-accessible parents such as `/tmp`.
//!
//! The engine binds and the daemon connects (its `connect_engine_ipc` client),
//! so this process must start first.
use std::process::ExitCode;
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{serve_driver_connection, EngineIpcServer, ENGINE_HOST_SOCKET_ENV};

const CDP_CHROME_ENV: &str = "TEMPO_CDP_CHROME";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let chrome_pid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    spawn_parent_death_watch(std::sync::Arc::clone(&chrome_pid));

    let socket_path = std::env::var(ENGINE_HOST_SOCKET_ENV)
        .map_err(|_| format!("{ENGINE_HOST_SOCKET_ENV} is required"))?;

    let mut config = CdpConfig::default();
    if let Ok(chrome) = std::env::var(CDP_CHROME_ENV)
        && !chrome.trim().is_empty()
    {
        config = config.with_executable(chrome);
    }
    config = config.with_no_sandbox_env_opt_in();

    // Launch the browser first so the socket is advertised as "listening" only
    // once we can actually serve driver commands over it.
    let mut driver = CdpTempoDriver::launch_with(config)
        .await
        .map_err(|error| error.to_string())?;
    chrome_pid.store(
        driver.chrome_pid().unwrap_or_default(),
        std::sync::atomic::Ordering::Relaxed,
    );

    // The engine binds; the daemon's `connect_engine_ipc` connects. The socket is
    // hardened (0600, private parent, peer-uid checked) but tokenless because the
    // shipped daemon attach client does not authenticate — hence
    // `accept_unauthenticated`.
    let server = EngineIpcServer::bind(&socket_path).map_err(|error| error.to_string())?;
    eprintln!(
        "tempo-engined-cdp: listening on {socket_path}; attach with `tempod --engine cdp --engine-socket {socket_path}`"
    );
    let mut connection = server
        .accept_unauthenticated()
        .map_err(|error| error.to_string())?;
    serve_driver_connection(&mut connection, &mut driver)
        .await
        .map_err(|error| error.to_string())
}

/// Exit when the spawning daemon dies. tempod's auto-start (#397) owns this
/// process, but a SIGTERM/SIGKILL to the daemon runs no drops — without a
/// parent watch, every daemon restart leaks one engine plus its Chrome tree,
/// stuck in `accept_unauthenticated` with no client ever coming back.
/// Reparenting (getppid changes) is the death signal; it also covers the
/// window before the daemon connects and any launch hang.
///
/// `chrome_pid` carries the launched browser's pid once known (0 = not yet
/// launched). `process::exit` runs no drops, so the watch must reap the
/// browser tree itself before exiting or the leak just moves one level down;
/// `/bin/kill` is used because std cannot signal an arbitrary pid and the
/// driver's async `close` is unreachable from this thread.
#[cfg(unix)]
fn spawn_parent_death_watch(chrome_pid: std::sync::Arc<std::sync::atomic::AtomicU32>) {
    let parent = std::os::unix::process::parent_id();
    // Started detached (or via a launcher that already exited): there is no
    // owning daemon to watch, and exiting would break deliberate manual runs.
    if parent == 1 {
        return;
    }
    std::thread::spawn(move || loop {
        if std::os::unix::process::parent_id() != parent {
            eprintln!("tempo-engined-cdp: spawning daemon exited; shutting down");
            let pid = chrome_pid.load(std::sync::atomic::Ordering::Relaxed);
            if pid != 0 {
                let _ = std::process::Command::new("/bin/kill")
                    .arg(pid.to_string())
                    .status();
            }
            std::process::exit(0);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
}

#[cfg(not(unix))]
fn spawn_parent_death_watch(_chrome_pid: std::sync::Arc<std::sync::atomic::AtomicU32>) {}
