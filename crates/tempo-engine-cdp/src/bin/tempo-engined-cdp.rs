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
use std::{path::Path, process::ExitCode};
use tempo_driver::DriverTrait;
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
    let socket_path = std::env::var(ENGINE_HOST_SOCKET_ENV)
        .map_err(|_| format!("{ENGINE_HOST_SOCKET_ENV} is required"))?;

    let mut config = CdpConfig::default();
    if let Ok(chrome) = std::env::var(CDP_CHROME_ENV)
        && !chrome.trim().is_empty()
    {
        let chrome = normalize_tempo_cdp_chrome(chrome);
        if !Path::new(&chrome).exists() {
            return Err(format!(
                "TEMPO_CDP_CHROME path does not exist: {chrome:?} (after shell-escape unquoting)"
            ));
        }
        config = config.with_executable(chrome);
    }
    config = config.with_no_sandbox_env_opt_in();

    // Launch the browser first so the socket is advertised as "listening" only
    // once we can actually serve driver commands over it.
    let mut driver = CdpTempoDriver::launch_with(config)
        .await
        .map_err(|error| error.to_string())?;

    serve_driver_over_bound_socket(&socket_path, &mut driver).await
}

fn normalize_tempo_cdp_chrome(path: impl AsRef<str>) -> String {
    path.as_ref()
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .replace("\\ ", " ")
}

async fn serve_driver_over_bound_socket<D>(
    socket_path: impl AsRef<Path>,
    driver: &mut D,
) -> Result<(), String>
where
    D: DriverTrait + ?Sized,
{
    let socket_path = socket_path.as_ref();

    // The engine binds; the daemon's `connect_engine_ipc` connects. The socket is
    // hardened (0600, private parent, peer-uid checked) but tokenless because the
    // shipped daemon attach client does not authenticate — hence
    // `accept_unauthenticated`.
    let server = EngineIpcServer::bind(socket_path).map_err(|error| error.to_string())?;
    eprintln!(
        "tempo-engined-cdp: listening on {}; attach with `tempod --engine cdp --engine-socket {}`",
        socket_path.display(),
        socket_path.display()
    );
    let mut connection = server
        .accept_unauthenticated()
        .map_err(|error| error.to_string())?;
    serve_driver_connection(&mut connection, driver)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs, io,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        path::Path,
        thread,
        time::{Duration, Instant},
    };
    use tempo_driver::TestDriver;
    use tempo_engine_host::{DriverCommand, DriverResponse, EngineHostError, EngineIpcClient};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cdp_host_binds_socket_for_tokenless_daemon_attach(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let socket_path = dir.path().join("engine.sock");
        let client_path = socket_path.clone();

        let server = tokio::spawn(async move {
            let mut driver = TestDriver::new().allow_private_network_access();
            serve_driver_over_bound_socket(socket_path, &mut driver).await
        });
        let client = tokio::task::spawn_blocking(
            move || -> Result<(DriverResponse, DriverResponse), EngineHostError> {
                wait_for_socket(&client_path)?;
                let mut client = EngineIpcClient::from_stream(UnixStream::connect(client_path)?);
                let observed = client.request(DriverCommand::Observe)?;
                let closed = client.request(DriverCommand::Close)?;
                Ok((observed, closed))
            },
        );

        let (server_result, client_result) = tokio::join!(server, client);
        server_result
            .map_err(|error| io::Error::other(format!("server task failed: {error}")))?
            .map_err(|error| io::Error::other(format!("server serve failed: {error}")))?;
        let (observed, closed) = client_result
            .map_err(|error| io::Error::other(format!("client task failed: {error}")))?
            .map_err(io::Error::other)?;

        match observed {
            DriverResponse::Observation { observation } => {
                assert_eq!(observation.url, "about:blank");
            }
            other => return Err(format!("unexpected observation response: {other:?}").into()),
        }
        assert_eq!(closed, DriverResponse::Closed);
        Ok(())
    }

    fn wait_for_socket(path: &Path) -> Result<(), EngineHostError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if path.exists() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(EngineHostError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "tempo-engined-cdp did not bind its engine socket",
        )))
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    #[tokio::test]
    async fn cdp_host_binds_socket_for_tokenless_daemon_attach() {
        // Unix-domain socket IPC for tokenless attach is not available on non-Unix
        // targets. Keep a covered test placeholder so build/test remains stable
        // across supported platforms.
    }
}
