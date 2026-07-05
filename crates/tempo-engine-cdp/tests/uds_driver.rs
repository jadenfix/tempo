use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempo_driver::{BrowsingContextCreateOptions, BrowsingContextKind};
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{
    serve_driver_connection, DriverCommand, DriverResponse, EngineIpcClient, EngineIpcConnection,
};

#[tokio::test]
async fn cdp_driver_serves_commands_over_engine_host_uds() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live CDP UDS test; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };
    let url = serve_fixture()?;
    let (client_stream, server_stream) = UnixStream::pair()?;
    let client = tokio::task::spawn_blocking(
        move || -> Result<
            (
                DriverResponse,
                DriverResponse,
                DriverResponse,
                DriverResponse,
            ),
            tempo_engine_host::EngineHostError,
        > {
            let mut client = EngineIpcClient::from_stream(client_stream);
            let observed = client.request(DriverCommand::Goto { url })?;
            let created = client.request(DriverCommand::CreateBrowsingContext {
                options: BrowsingContextCreateOptions {
                    kind: BrowsingContextKind::Tab,
                    background: false,
                },
            })?;
            let DriverResponse::BrowsingContextCreated { driver_id } = created else {
                return Err(tempo_engine_host::EngineHostError::Io(
                    std::io::Error::other(format!("unexpected context response: {created:?}")),
                ));
            };
            let child_observed = client.request_for(Some(&driver_id), DriverCommand::Observe)?;
            let child_closed = client.request_for(Some(&driver_id), DriverCommand::Close)?;
            let closed = client.request(DriverCommand::Close)?;
            Ok((observed, child_observed, child_closed, closed))
        },
    );

    let config = CdpConfig::default()
        .with_executable(chrome.to_string_lossy())
        .with_no_sandbox_env_opt_in();
    let mut driver = CdpTempoDriver::launch_with(config)
        .await?
        .allow_private_network_access();
    let mut connection = EngineIpcConnection::from_stream(server_stream);
    serve_driver_connection(&mut connection, &mut driver).await?;
    let (observed, child_observed, child_closed, closed) = client.await??;

    match observed {
        DriverResponse::Observation { observation } => {
            assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
            let save = observation
                .elements
                .iter()
                .find(|element| {
                    element.role == "button"
                        && element.name.first().map(|span| span.text.as_str()) == Some("Save")
                })
                .ok_or_else(|| std::io::Error::other("missing save button"))?;
            assert!(save.node_id.0.starts_with("node:"));
        }
        other => return Err(format!("unexpected driver response: {other:?}").into()),
    }
    match child_observed {
        DriverResponse::Observation { observation } => {
            assert_eq!(observation.url, "about:blank");
            assert_eq!(observation.seq, 1);
        }
        other => return Err(format!("unexpected child driver response: {other:?}").into()),
    }
    assert_eq!(child_closed, DriverResponse::Closed);
    assert_eq!(closed, DriverResponse::Closed);
    Ok(())
}

/// Reverted-fix-sensitive regression test for #397's actual failure seam: the
/// shipped `tempo-engined-cdp` binary must *bind* the driver UDS named by
/// `TEMPO_ENGINE_HOST_SOCKET` so a `tempod`-style client can *connect* to it.
///
/// Unlike [`cdp_driver_serves_commands_over_engine_host_uds`] above (which
/// pre-creates a `UnixStream::pair` and calls `serve_driver_connection`
/// directly, never touching a filesystem socket or the binary), this test
/// spawns the actual compiled `tempo-engined-cdp` executable and connects to
/// it exactly the way `tempod`'s `connect_engine_ipc` does: a bare
/// `UnixStream::connect` with no auth frame.
///
/// If the binary is ever reverted to its pre-fix shape
/// (`EngineIpcConnection::connect(socket_path)` instead of
/// `EngineIpcServer::bind(&socket_path)`), nothing ever creates the socket
/// file at `socket_path` -- the binary itself would be the one waiting to
/// connect to it -- so every connect attempt below fails with ENOENT until
/// the deadline, and this test fails instead of silently passing.
#[test]
fn tempo_engined_cdp_binary_binds_socket_for_tempod_style_connect(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live CDP UDS test; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };

    let root = tempfile::tempdir()?;
    // `EngineIpcServer::bind` requires a private (mode 0700) parent directory
    // and creates one itself when absent; pointing the socket at a directory
    // that does not exist yet (rather than `root` itself, whose mode comes
    // from the process umask) exercises that same path the shipped binary
    // relies on.
    let socket_path = root.path().join("host").join("engine.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tempo-engined-cdp"))
        .env("TEMPO_ENGINE_HOST_SOCKET", &socket_path)
        .env("TEMPO_CDP_CHROME", &chrome)
        .env("TEMPO_CDP_NO_SANDBOX", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let connected = loop {
        if UnixStream::connect(&socket_path).is_ok() {
            break true;
        }
        if let Some(status) = child.try_wait()? {
            let _ = child.wait();
            return Err(format!(
                "tempo-engined-cdp exited ({status}) before binding {}",
                socket_path.display()
            )
            .into());
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let _ = child.kill();
    let _ = child.wait();

    if !connected {
        return Err(format!(
            "timed out waiting for tempo-engined-cdp to accept connections on {}",
            socket_path.display()
        )
        .into());
    }
    Ok(())
}

/// Reverted-fix-sensitive test for the auto-start teardown seam: a
/// `tempo-engined-cdp` whose spawning daemon dies must exit on its own.
///
/// tempod owns the auto-started engine (#397), but a SIGTERM/SIGKILL to the
/// daemon runs no drops, and a freshly (re)started engine sits blocked in
/// `accept_unauthenticated` with no client ever coming back — before the
/// parent-death watch, every daemon restart leaked one engine plus its whole
/// Chrome tree. This test reproduces that exact state: an intermediate shell
/// spawns the engine, waits for the socket to be bound (engine is now
/// accept-blocked), and exits — reparenting the engine. Without the watch the
/// engine blocks in accept forever and the liveness poll below hits its
/// deadline; with it, the engine notices the reparenting and exits.
#[test]
fn tempo_engined_cdp_binary_exits_when_spawning_daemon_dies(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live CDP parent-death test; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };

    let root = tempfile::tempdir()?;
    let socket_path = root.path().join("host").join("engine.sock");
    let pid_path = root.path().join("engine.pid");

    // The intermediate parent: spawn the engine (stdio detached — an
    // inherited pipe held open by the engine or its Chrome tree would block
    // this test on the very leak it checks for), record its pid to a file,
    // hold on until the engine has bound its socket (so it is parked in
    // accept), then exit, reparenting the engine away from us. TMPDIR is
    // pointed into the tempdir so the engine's Chrome profile — and thus its
    // process tree — is uniquely attributable to this test.
    let script = r#"
        "$ENGINE_BIN" >/dev/null 2>&1 & pid=$!
        printf '%s' "$pid" > "$ENGINE_PID_FILE"
        i=0
        while [ ! -S "$ENGINE_SOCK" ] && [ "$i" -lt 600 ]; do
            sleep 0.1
            i=$((i+1))
        done
        [ -S "$ENGINE_SOCK" ] || exit 70
        exit 0
    "#;
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env("ENGINE_BIN", env!("CARGO_BIN_EXE_tempo-engined-cdp"))
        .env("ENGINE_SOCK", &socket_path)
        .env("ENGINE_PID_FILE", &pid_path)
        .env("TEMPO_ENGINE_HOST_SOCKET", &socket_path)
        .env("TEMPO_CDP_CHROME", &chrome)
        .env("TEMPO_CDP_NO_SANDBOX", "1")
        .env("TMPDIR", root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    let engine_pid: u32 = std::fs::read_to_string(&pid_path)?.trim().parse()?;
    let engine_alive = || {
        Command::new("kill")
            .args(["-0", &engine_pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    };
    if !status.success() {
        // The engine never bound its socket; clean up before failing.
        let _ = Command::new("kill").arg(engine_pid.to_string()).status();
        return Err(format!(
            "intermediate parent failed ({status}): engine never bound {}",
            socket_path.display()
        )
        .into());
    }

    // Parent is gone; the watch polls every 2s, so well within this deadline
    // the engine must notice the reparenting and exit.
    let deadline = Instant::now() + Duration::from_secs(15);
    while engine_alive() {
        if Instant::now() >= deadline {
            let _ = Command::new("kill").arg(engine_pid.to_string()).status();
            return Err(
                "engine outlived its dead parent: auto-started engine would leak on daemon restart"
                    .into(),
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // The watch must reap the Chrome tree too (its profile lives under this
    // test's unique TMPDIR): a leak that merely moves from the engine to an
    // orphaned browser is still a leak.
    let profile_marker = root.path().display().to_string();
    let chrome_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let leftovers = Command::new("pgrep")
            .args(["-f", &profile_marker])
            .stderr(Stdio::null())
            .output()?;
        if !leftovers.status.success() {
            break;
        }
        if Instant::now() >= chrome_deadline {
            let _ = Command::new("pkill").args(["-f", &profile_marker]).status();
            return Err(
                "Chrome tree outlived the reaped engine: browser leak on daemon restart".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn serve_fixture() -> Result<String, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    std::thread::spawn(move || {
        let body = r#"<!doctype html>
            <html>
              <body>
                <button id="save">Save</button>
              </body>
            </html>"#;
        for stream in listener.incoming().take(16) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    Ok(format!("http://{addr}/"))
}
