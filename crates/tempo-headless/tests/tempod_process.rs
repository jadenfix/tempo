use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const AUTH_TOKEN: &str = "process-smoke-token";

#[test]
fn tempod_binary_serves_authenticated_control_plane_and_drains() -> TestResult {
    let addr = reserve_loopback_addr()?;
    let mut tempod = TempodProcess::spawn(&addr, AUTH_TOKEN)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let base_url = format!("http://{addr}");

    wait_for_health(&client, &base_url, &mut tempod)?;

    let health = get_json(&client, &base_url, "/health", None)?;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body["ok"], true);

    let unauthenticated_ready = client.get(format!("{base_url}/ready")).send()?;
    assert_eq!(unauthenticated_ready.status(), StatusCode::UNAUTHORIZED);

    let ready = get_json(&client, &base_url, "/ready", Some(AUTH_TOKEN))?;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.body["ready"], false);
    assert_eq!(ready.body["engine_attached"], false);
    assert!(
        ready.body["reasons"]
            .as_array()
            .ok_or("ready reasons must be an array")?
            .iter()
            .any(|reason| reason == "engine_detached"),
        "ready response should report engine_detached: {}",
        ready.body
    );

    let unauthenticated_sessions = client.get(format!("{base_url}/sessions")).send()?;
    assert_eq!(unauthenticated_sessions.status(), StatusCode::UNAUTHORIZED);

    let sessions = get_json(&client, &base_url, "/sessions", Some(AUTH_TOKEN))?;
    assert_eq!(sessions.status, StatusCode::OK);
    assert_eq!(sessions.body, json!([]));

    let created = post_json(
        &client,
        &base_url,
        "/sessions",
        Some(AUTH_TOKEN),
        r#"{"url":"https://resume-process.test"}"#,
    )?;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "session response: {}",
        created.body
    );
    let session_id = created.body["id"]
        .as_str()
        .ok_or("session create response missing id")?;
    let adopted = post_json(
        &client,
        &base_url,
        &format!("/sessions/{session_id}/adopt"),
        Some(AUTH_TOKEN),
        "{}",
    )?;
    assert_eq!(adopted.status, StatusCode::OK);
    assert_eq!(adopted.body["state"], "adopted");
    let resumed = post_json(
        &client,
        &base_url,
        &format!("/sessions/{session_id}/resume"),
        Some(AUTH_TOKEN),
        "{}",
    )?;
    assert_eq!(resumed.status, StatusCode::OK);
    assert_eq!(resumed.body["state"], "running");
    let events = get_json(
        &client,
        &base_url,
        &format!("/sessions/{session_id}/events"),
        Some(AUTH_TOKEN),
    )?;
    assert_eq!(events.status, StatusCode::OK);
    let event_kinds = events.body.as_array().ok_or("events must be an array")?;
    assert!(
        event_kinds
            .iter()
            .any(|event| event["event"]["kind"] == "session_resumed"),
        "resume event missing from process event stream: {}",
        events.body
    );

    let unauthenticated_mcp = post_json(
        &client,
        &base_url,
        "/mcp",
        None,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )?;
    assert_eq!(unauthenticated_mcp.status, StatusCode::UNAUTHORIZED);

    let tools = post_json(
        &client,
        &base_url,
        "/mcp",
        Some(AUTH_TOKEN),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )?;
    assert_eq!(tools.status, StatusCode::OK);
    assert_eq!(tools.body["jsonrpc"], "2.0");
    assert!(
        tools.body["result"]["tools"]
            .as_array()
            .ok_or("MCP tools must be an array")?
            .iter()
            .any(|tool| tool["name"] == "observe"),
        "MCP tools/list should expose observe: {}",
        tools.body
    );

    let bidi_status = post_json(
        &client,
        &base_url,
        "/bidi",
        Some(AUTH_TOKEN),
        r#"{"id":3,"method":"session.status","params":{}}"#,
    )?;
    assert_eq!(bidi_status.status, StatusCode::OK);
    assert_eq!(bidi_status.body["type"], "success");
    assert_eq!(bidi_status.body["id"], 3);
    assert_eq!(bidi_status.body["result"]["ready"], true);

    let drain = post_json(&client, &base_url, "/drain", Some(AUTH_TOKEN), "{}")?;
    assert_eq!(drain.status, StatusCode::OK);
    assert_eq!(drain.body["draining"], true);
    assert_eq!(drain.body["sessions"][0]["id"], session_id);
    assert_eq!(drain.body["sessions"][0]["state"], "killed");

    let ready_after_drain = get_json(&client, &base_url, "/ready", Some(AUTH_TOKEN))?;
    assert_eq!(ready_after_drain.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready_after_drain.body["draining"], true);

    Ok(())
}

#[test]
fn tempod_binary_live_cdp_spawns_engine_and_drives_agent_protocols() -> TestResult {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live tempod process/CDP smoke; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };
    let Some(engine_program) = tempo_engined_cdp_path() else {
        eprintln!(
            "skipping live tempod process/CDP smoke; build tempo-engined-cdp first or set CARGO_BIN_EXE_tempo-engined-cdp"
        );
        return Ok(());
    };

    let fixture = FixtureServer::start()?;
    let addr = reserve_loopback_addr()?;
    let mut tempod =
        TempodProcess::spawn_with_cdp_engine(&addr, AUTH_TOKEN, &engine_program, &chrome)?;
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let base_url = format!("http://{addr}");

    wait_for_health(&client, &base_url, &mut tempod)?;

    let ready = get_json(&client, &base_url, "/ready", Some(AUTH_TOKEN))?;
    assert_eq!(ready.status, StatusCode::OK);
    assert_eq!(ready.body["ready"], true);
    assert_eq!(ready.body["engine_attached"], true);

    let create_body = json!({ "url": fixture.url("/") }).to_string();
    let session = post_json(
        &client,
        &base_url,
        "/sessions",
        Some(AUTH_TOKEN),
        &create_body,
    )?;
    assert_eq!(
        session.status,
        StatusCode::CREATED,
        "session response: {}",
        session.body
    );
    let session_id = session.body["id"]
        .as_str()
        .ok_or("session create response missing id")?;

    let observation = get_json(
        &client,
        &base_url,
        &format!("/sessions/{session_id}/observe"),
        Some(AUTH_TOKEN),
    )?;
    assert_eq!(observation.status, StatusCode::OK);
    assert_eq!(observation.body["url"], fixture.url("/"));
    assert_json_contains(&observation.body, "Agent Name")?;
    assert_json_contains(&observation.body, "Save")?;

    let mcp_goto_body = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "act",
            "arguments": {
                "action": { "kind": "goto", "url": fixture.url("/mcp") },
                "input_tainted": false
            }
        }
    })
    .to_string();
    let mcp_goto = post_json(&client, &base_url, "/mcp", Some(AUTH_TOKEN), &mcp_goto_body)?;
    assert_eq!(mcp_goto.status, StatusCode::OK);
    assert_eq!(
        mcp_goto.body["result"]["structuredContent"]["status"],
        "applied"
    );

    let mcp_observe = post_json(
        &client,
        &base_url,
        "/mcp",
        Some(AUTH_TOKEN),
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"observe","arguments":{}}}"#,
    )?;
    assert_eq!(mcp_observe.status, StatusCode::OK);
    assert_eq!(mcp_observe.body["jsonrpc"], "2.0");
    assert_eq!(
        mcp_observe.body["result"]["structuredContent"]["url"],
        fixture.url("/mcp")
    );
    assert_json_contains(&mcp_observe.body, "Agent Name")?;

    let bidi_create = post_json(
        &client,
        &base_url,
        "/bidi",
        Some(AUTH_TOKEN),
        r#"{"id":5,"method":"browsingContext.create","params":{"type":"tab"}}"#,
    )?;
    assert_eq!(bidi_create.status, StatusCode::OK);
    assert_eq!(bidi_create.body["type"], "success");
    let bidi_context = bidi_create.body["result"]["context"]
        .as_str()
        .ok_or("BiDi create response missing context")?;
    let bidi_navigate_body = json!({
        "id": 6,
        "method": "browsingContext.navigate",
        "params": {
            "context": bidi_context,
            "url": fixture.url("/bidi"),
            "inputTainted": false
        }
    })
    .to_string();
    let bidi_navigate = post_json(
        &client,
        &base_url,
        "/bidi",
        Some(AUTH_TOKEN),
        &bidi_navigate_body,
    )?;
    assert_eq!(bidi_navigate.status, StatusCode::OK);
    assert_eq!(bidi_navigate.body["type"], "success");
    assert_eq!(bidi_navigate.body["result"]["url"], fixture.url("/bidi"));

    let bidi_status = post_json(
        &client,
        &base_url,
        "/bidi",
        Some(AUTH_TOKEN),
        r#"{"id":7,"method":"session.status","params":{}}"#,
    )?;
    assert_eq!(bidi_status.status, StatusCode::OK);
    assert_eq!(bidi_status.body["type"], "success");
    assert_eq!(bidi_status.body["result"]["ready"], true);

    let bidi_close_body = json!({
        "id": 8,
        "method": "browsingContext.close",
        "params": { "context": bidi_context }
    })
    .to_string();
    let bidi_close = post_json(
        &client,
        &base_url,
        "/bidi",
        Some(AUTH_TOKEN),
        &bidi_close_body,
    )?;
    assert_eq!(bidi_close.status, StatusCode::OK);
    assert_eq!(bidi_close.body["type"], "success");

    let drain = post_json(&client, &base_url, "/drain", Some(AUTH_TOKEN), "{}")?;
    assert_eq!(drain.status, StatusCode::OK);
    assert_eq!(drain.body["draining"], true);

    Ok(())
}

#[test]
#[cfg(unix)]
fn tempod_binary_live_cdp_recovers_after_spawned_engine_death() -> TestResult {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live tempod process/CDP recovery smoke; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };
    let Some(engine_program) = tempo_engined_cdp_path() else {
        eprintln!(
            "skipping live tempod process/CDP recovery smoke; build tempo-engined-cdp first or set CARGO_BIN_EXE_tempo-engined-cdp"
        );
        return Ok(());
    };

    let fixture = FixtureServer::start()?;
    let root = unique_temp_dir("tempod-cdp-recovery")?;
    let pid_file = root.join("engine.pid");
    let wrapper = cdp_engine_pid_wrapper(&root, &engine_program, &pid_file)?;
    let addr = reserve_loopback_addr()?;
    let mut tempod = TempodProcess::spawn_with_cdp_engine(&addr, AUTH_TOKEN, &wrapper, &chrome)?;
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let base_url = format!("http://{addr}");

    wait_for_health(&client, &base_url, &mut tempod)?;
    wait_for_ready(&client, &base_url, &mut tempod)?;

    let first_pid = wait_for_engine_pid(&pid_file, None, &mut tempod)?;
    create_and_observe_session(
        &client,
        &base_url,
        &fixture.url("/before-restart"),
        "Agent Name",
    )?;

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(first_pid.to_string())
        .status()?;
    assert!(
        status.success(),
        "failed to terminate engine pid {first_pid}"
    );

    let restarted_pid = wait_for_engine_pid(&pid_file, Some(first_pid), &mut tempod)?;
    assert_ne!(first_pid, restarted_pid);
    wait_for_ready(&client, &base_url, &mut tempod)?;
    create_and_observe_session(
        &client,
        &base_url,
        &fixture.url("/after-restart"),
        "Agent Name",
    )?;

    let drain = post_json(&client, &base_url, "/drain", Some(AUTH_TOKEN), "{}")?;
    assert_eq!(drain.status, StatusCode::OK);
    assert_eq!(drain.body["draining"], true);

    fs::remove_dir_all(root)?;
    Ok(())
}

struct TempodProcess {
    child: Child,
}

impl TempodProcess {
    fn spawn(addr: &str, token: &str) -> TestResult<Self> {
        let child = Command::new(env!("CARGO_BIN_EXE_tempod"))
            .env_clear()
            .arg(addr)
            .arg("--auth-token")
            .arg(token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self { child })
    }

    fn spawn_with_cdp_engine(
        addr: &str,
        token: &str,
        engine_program: &Path,
        chrome: &std::ffi::OsStr,
    ) -> TestResult<Self> {
        let child = Command::new(env!("CARGO_BIN_EXE_tempod"))
            .arg(addr)
            .arg("--auth-token")
            .arg(token)
            .arg("--allow-private-network")
            .arg("--engine")
            .arg("cdp")
            .arg("--engine-program")
            .arg(engine_program)
            .env_remove("TEMPO_CONFIG")
            .env_remove("TEMPO_ENGINE_SOCKET")
            .env_remove("TEMPO_TEMPOD_AUTH_TOKEN")
            .env_remove("TEMPO_TEMPOD_AUTH_TOKEN_FILE")
            .env("TEMPO_CDP_CHROME", chrome)
            .env("TEMPO_CDP_NO_SANDBOX", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self { child })
    }

    fn assert_running(&mut self) -> TestResult {
        if let Some(status) = self.child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut stream) = self.child.stderr.take() {
                let _ = stream.read_to_string(&mut stderr);
            }
            return Err(format!("tempod exited early with {status}; stderr:\n{stderr}").into());
        }
        Ok(())
    }
}

impl Drop for TempodProcess {
    fn drop(&mut self) {
        if let Ok(Some(_status)) = self.child.try_wait() {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct JsonResponse {
    status: StatusCode,
    body: Value,
}

struct FixtureServer {
    addr: String,
}

impl FixtureServer {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?.to_string();
        thread::spawn(move || {
            for stream in listener.incoming().take(64) {
                let Ok(stream) = stream else {
                    continue;
                };
                thread::spawn(move || {
                    let _ignored = serve_fixture_connection(stream);
                });
            }
        });
        Ok(Self { addr })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

fn serve_fixture_connection(mut stream: TcpStream) -> Result<(), std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0_u8; 1024];
    let bytes = stream.read(&mut request).unwrap_or(0);
    let request = String::from_utf8_lossy(&request[..bytes]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let body = format!(
        r#"<!doctype html>
<html>
  <head><title>Tempo Process {path}</title></head>
  <body>
    <main>
      <label for="agent-name">Agent Name</label>
      <input id="agent-name" aria-label="Agent Name" value="">
      <button id="save" onclick="this.dataset.saved = 'true'">Save</button>
    </main>
  </body>
</html>"#
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn create_and_observe_session(
    client: &Client,
    base_url: &str,
    url: &str,
    expected_text: &str,
) -> TestResult {
    let create_body = json!({ "url": url }).to_string();
    let session = post_json(
        client,
        base_url,
        "/sessions",
        Some(AUTH_TOKEN),
        &create_body,
    )?;
    assert_eq!(
        session.status,
        StatusCode::CREATED,
        "session response: {}",
        session.body
    );
    let session_id = session.body["id"]
        .as_str()
        .ok_or("session create response missing id")?;
    let observation = get_json(
        client,
        base_url,
        &format!("/sessions/{session_id}/observe"),
        Some(AUTH_TOKEN),
    )?;
    assert_eq!(observation.status, StatusCode::OK);
    assert_eq!(observation.body["url"], url);
    assert_json_contains(&observation.body, expected_text)
}

fn reserve_loopback_addr() -> TestResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

fn wait_for_health(client: &Client, base_url: &str, tempod: &mut TempodProcess) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        tempod.assert_running()?;
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == StatusCode::OK => return Ok(()),
            Ok(_response) => {}
            Err(_error) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    tempod.assert_running()?;
    Err("timed out waiting for tempod /health".into())
}

fn wait_for_ready(client: &Client, base_url: &str, tempod: &mut TempodProcess) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        tempod.assert_running()?;
        match get_json(client, base_url, "/ready", Some(AUTH_TOKEN)) {
            Ok(response)
                if response.status == StatusCode::OK
                    && response.body["ready"] == true
                    && response.body["engine_attached"] == true =>
            {
                return Ok(())
            }
            Ok(_response) => {}
            Err(_error) => {}
        }
        thread::sleep(Duration::from_millis(100));
    }
    tempod.assert_running()?;
    Err("timed out waiting for tempod /ready".into())
}

fn get_json(
    client: &Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
) -> TestResult<JsonResponse> {
    let mut request = client.get(format!("{base_url}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    response_json(request.send()?)
}

fn post_json(
    client: &Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> TestResult<JsonResponse> {
    let mut request = client
        .post(format!("{base_url}{path}"))
        .header("content-type", "application/json")
        .body(body.to_owned());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    response_json(request.send()?)
}

fn response_json(response: Response) -> TestResult<JsonResponse> {
    let status = response.status();
    let text = response.text()?;
    let body = serde_json::from_str(&text)
        .map_err(|error| format!("response body should be JSON ({status}): {error}: {text}"))?;
    Ok(JsonResponse { status, body })
}

fn tempo_engined_cdp_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_tempo-engined-cdp").map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }

    let mut path = std::env::current_exe().ok()?;
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.push(format!("tempo-engined-cdp{}", std::env::consts::EXE_SUFFIX));
    path.is_file().then_some(path)
}

fn assert_json_contains(value: &Value, needle: &str) -> TestResult {
    if value.to_string().contains(needle) {
        Ok(())
    } else {
        Err(format!("JSON response did not contain {needle:?}: {value}").into())
    }
}

#[cfg(unix)]
fn cdp_engine_pid_wrapper(
    root: &Path,
    engine_program: &Path,
    pid_file: &Path,
) -> TestResult<PathBuf> {
    let script = root.join("tempo-engined-cdp-wrapper.sh");
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > {}\nexec {} \"$@\"\n",
        shell_quote(pid_file),
        shell_quote(engine_program)
    );
    fs::write(&script, body)?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    Ok(script)
}

#[cfg(unix)]
fn wait_for_engine_pid(
    pid_file: &Path,
    previous: Option<u32>,
    tempod: &mut TempodProcess,
) -> TestResult<u32> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        tempod.assert_running()?;
        if let Ok(text) = fs::read_to_string(pid_file)
            && let Ok(pid) = text.trim().parse::<u32>()
            && Some(pid) != previous
        {
            return Ok(pid);
        }
        thread::sleep(Duration::from_millis(100));
    }
    tempod.assert_running()?;
    Err(format!(
        "timed out waiting for engine pid file {}",
        pid_file.display()
    )
    .into())
}

#[cfg(unix)]
fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir(&root)?;
    Ok(root)
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}
