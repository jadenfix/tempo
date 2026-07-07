use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::error::Error;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    assert_eq!(drain.body["sessions"], json!([]));

    let ready_after_drain = get_json(&client, &base_url, "/ready", Some(AUTH_TOKEN))?;
    assert_eq!(ready_after_drain.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready_after_drain.body["draining"], true);

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

fn reserve_loopback_addr() -> TestResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

fn wait_for_health(client: &Client, base_url: &str, tempod: &mut TempodProcess) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(8);
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
    body: &'static str,
) -> TestResult<JsonResponse> {
    let mut request = client
        .post(format!("{base_url}{path}"))
        .header("content-type", "application/json")
        .body(body);
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
