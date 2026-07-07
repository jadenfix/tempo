use serde_json::{json, Value};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempo_driver::Engine;
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{serve_driver_connection, EngineIpcConnection};
use tempo_net::UrlPolicy;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn tempod_http_mcp_and_bidi_drive_live_cdp_browser() -> TestResult {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live tempod/CDP E2E; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };

    let fixture = FixtureServer::start()?;
    let socket_root = tempfile::tempdir()?;
    let socket_path = socket_root.path().join("engine.sock");
    let listener = UnixListener::bind(&socket_path)?;
    let engine = spawn_cdp_engine(listener, PathBuf::from(chrome));

    let addr = unused_loopback_addr()?;
    let tempod_addr = addr.to_string();
    let tempod_socket = socket_path.clone();
    thread::spawn(move || {
        if let Err(error) =
            tempo_headless::run_tempod_with_attached_driver_config_and_navigation_url_policy(
                &tempod_addr,
                tempo_headless::TempodServerConfig::new(),
                Engine::Cdp,
                tempod_socket,
                UrlPolicy::allow_all(),
            )
        {
            eprintln!("live tempod/CDP E2E tempod exited: {error}");
        }
    });

    wait_for_engine_ready(&engine)?;
    wait_for_health(addr, &engine.done)?;

    let session = http_json(
        addr,
        "POST",
        "/sessions",
        Some(json!({ "url": fixture.url("/") })),
    )?;
    let session_id = session["id"]
        .as_str()
        .ok_or("session create response missing id")?;
    let observation = http_json(
        addr,
        "GET",
        &format!("/sessions/{session_id}/observe"),
        None,
    )?;
    find_node_id(&observation, "textbox", "Name")?;
    find_node_id(&observation, "button", "Save")?;

    let acted = http_json(
        addr,
        "POST",
        &format!("/sessions/{session_id}/act_batch"),
        Some(json!({
            "batch": {
                "actions": [
                    { "kind": "goto", "url": fixture.url("/rest") }
                ],
                "quiescence": "composite"
            },
            "input_tainted": false,
            "idempotency_key": "live-tempod-cdp-rest-goto"
        })),
    )?;
    assert_eq!(acted["status"], "applied");

    let post_action = http_json(
        addr,
        "GET",
        &format!("/sessions/{session_id}/observe"),
        None,
    )?;
    assert_eq!(post_action["url"], fixture.url("/rest"));

    let tools = mcp(addr, 1, "tools/list", json!({}))?;
    let tool_names = tools["result"]["tools"]
        .as_array()
        .ok_or("tools/list result missing tools")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "observe",
        "observe_diff",
        "act",
        "act_batch",
        "fork",
        "close_fork",
        "extract",
        "screenshot",
        "handshake",
    ] {
        assert!(
            tool_names.contains(&expected),
            "tools/list did not include {expected}: {tool_names:?}"
        );
    }
    let root_goto = mcp_tool(
        addr,
        2,
        "act",
        json!({
            "action": { "kind": "goto", "url": fixture.url("/") },
            "input_tainted": false
        }),
    )?;
    assert_eq!(root_goto["status"], "applied");

    let root_observe = mcp_tool(addr, 3, "observe", json!({}))?;
    let root_button = find_node_id(&root_observe, "button", "Save")?;
    let extracted = mcp_tool(addr, 4, "extract", json!({ "node": root_button }))?;
    assert!(
        extracted.is_object(),
        "extract should return structured JSON, got {extracted}"
    );

    let screenshot = mcp(
        addr,
        5,
        "tools/call",
        tool_call("screenshot", json!({ "format": "png" })),
    )?;
    let screenshot_content = screenshot["result"]["content"]
        .as_array()
        .ok_or("screenshot result missing content")?;
    assert!(
        screenshot_content
            .iter()
            .any(|content| content["type"] == "image" && content["mimeType"] == "image/png"),
        "screenshot result did not include a PNG image: {screenshot}"
    );

    let fork = mcp_tool(addr, 6, "fork", json!({}))?;
    assert_eq!(fork["supported"], false);
    assert!(
        fork["reason"]
            .as_str()
            .map(|reason| reason.contains("unsupported"))
            .unwrap_or(false),
        "unexpected CDP fork response: {fork}"
    );

    let status = bidi(
        addr,
        json!({"id": 11, "method": "session.status", "params": {}}),
    )?;
    assert_eq!(status["id"], 11);
    let seeded = mcp_tool(
        addr,
        7,
        "act",
        json!({
            "action": { "kind": "goto", "url": fixture.url("/seed-storage") },
            "input_tainted": false
        }),
    )?;
    assert_eq!(seeded["status"], "applied");
    let seeded_path = fixture.wait_for_request("/storage-seeded?", Duration::from_secs(10))?;
    assert!(
        seeded_path.contains("local=present"),
        "root context did not establish localStorage: {seeded_path}"
    );
    assert!(
        seeded_path.contains("cookie=present"),
        "root context did not establish cookie: {seeded_path}"
    );
    let created = bidi(
        addr,
        json!({"id": 12, "method": "browsingContext.create", "params": {"type": "tab"}}),
    )?;
    let context = created["result"]["context"]
        .as_str()
        .ok_or("BiDi create response missing context")?;
    let storage_report = bidi(
        addr,
        json!({
            "id": 17,
            "method": "browsingContext.navigate",
            "params": {
                "context": context,
                "url": fixture.url("/storage-report"),
                "inputTainted": false
            }
        }),
    )?;
    assert_eq!(storage_report["id"], 17);
    let report_path = fixture.wait_for_request("/storage-result?", Duration::from_secs(10))?;
    assert!(
        report_path.contains("local=missing"),
        "child context inherited parent localStorage: {report_path}"
    );
    assert!(
        report_path.contains("cookie=absent"),
        "child context inherited parent cookie: {report_path}"
    );
    let navigated = bidi(
        addr,
        json!({
            "id": 13,
            "method": "browsingContext.navigate",
            "params": {
                "context": context,
                "url": fixture.url("/bidi"),
                "inputTainted": false
            }
        }),
    )?;
    assert_eq!(navigated["result"]["url"], fixture.url("/bidi"));
    let evaluated = bidi_raw(
        addr,
        json!({
            "id": 14,
            "method": "script.evaluate",
            "params": {
                "expression": "document.title",
                "target": { "context": context },
                "awaitPromise": true,
                "inputTainted": false
            }
        }),
    )?;
    assert_eq!(evaluated["error"], "invalid argument");
    assert!(
        evaluated["message"]
            .as_str()
            .map(|message| message.contains("confirmation required"))
            .unwrap_or(false),
        "unexpected BiDi script denial: {evaluated}"
    );
    let bidi_screenshot = bidi(
        addr,
        json!({
            "id": 15,
            "method": "browsingContext.captureScreenshot",
            "params": { "context": context }
        }),
    )?;
    assert!(
        bidi_screenshot["result"]["data"]
            .as_str()
            .map(|data| !data.is_empty())
            .unwrap_or(false),
        "BiDi screenshot returned no data"
    );
    let closed_context = bidi(
        addr,
        json!({
            "id": 16,
            "method": "browsingContext.close",
            "params": { "context": context }
        }),
    )?;
    assert_eq!(closed_context["id"], 16);

    let _killed = http_json(addr, "DELETE", &format!("/sessions/{session_id}"), None)?;
    let _drained = http_json(addr, "POST", "/drain", Some(json!({})))?;
    match engine.done.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error.into()),
        Err(error) => {
            return Err(format!("CDP engine did not shut down after drain: {error}").into())
        }
    }

    Ok(())
}

struct EngineHandle {
    ready: mpsc::Receiver<Result<(), String>>,
    done: mpsc::Receiver<Result<(), String>>,
}

fn spawn_cdp_engine(listener: UnixListener, chrome: PathBuf) -> EngineHandle {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let launch_failed_tx = ready_tx.clone();
        let result = run_cdp_engine(listener, chrome, ready_tx);
        if let Err(error) = &result {
            let _ignored = launch_failed_tx.send(Err(error.clone()));
        }
        let _ignored = done_tx.send(result);
    });
    EngineHandle {
        ready: ready_rx,
        done: done_rx,
    }
}

fn run_cdp_engine(
    listener: UnixListener,
    chrome: PathBuf,
    ready_tx: mpsc::Sender<Result<(), String>>,
) -> Result<(), String> {
    let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        let config = CdpConfig::default()
            .with_executable(chrome.to_string_lossy())
            .with_no_sandbox_env_opt_in();
        let mut driver = CdpTempoDriver::launch_with(config)
            .await
            .map_err(|error| error.to_string())?
            .allow_private_network_access();
        let _ignored = ready_tx.send(Ok(()));
        let mut connection = EngineIpcConnection::from_stream(stream);
        serve_driver_connection(&mut connection, &mut driver)
            .await
            .map_err(|error| error.to_string())
    })
}

struct FixtureServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FixtureServer {
    fn start() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().take(128) {
                let Ok(stream) = stream else {
                    continue;
                };
                let connection_requests = Arc::clone(&server_requests);
                thread::spawn(move || {
                    let _ignored = serve_fixture_connection(stream, connection_requests);
                });
            }
        });
        Ok(Self { addr, requests })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    fn wait_for_request(&self, prefix: &str, timeout: Duration) -> TestResult<String> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let requests = self
                    .requests
                    .lock()
                    .map_err(|_| "fixture request log mutex poisoned")?;
                if let Some(path) = requests.iter().find(|path| path.starts_with(prefix)) {
                    return Ok(path.clone());
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for fixture request {prefix:?}").into());
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

fn serve_fixture_connection(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<String>>>,
) -> Result<(), std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0_u8; 1024];
    let bytes = stream.read(&mut request).unwrap_or(0);
    let request = String::from_utf8_lossy(&request[..bytes]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    if let Ok(mut requests) = requests.lock() {
        requests.push(path.to_owned());
    }
    let body = fixture_page(path);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn fixture_page(path: &str) -> String {
    if path == "/seed-storage" {
        return r#"<!doctype html>
<html>
  <head>
    <title>Tempo Fixture Seed Storage</title>
    <script>
      localStorage.setItem('tempoIsolation', 'root');
      document.cookie = 'tempoIsolation=root; SameSite=Lax';
      const local = localStorage.getItem('tempoIsolation') === 'root' ? 'present' : 'missing';
      const cookie = document.cookie.includes('tempoIsolation=root') ? 'present' : 'absent';
      location.replace(`/storage-seeded?local=${local}&cookie=${cookie}`);
    </script>
  </head>
  <body>seeded</body>
</html>"#
            .to_owned();
    }
    if path == "/storage-report" {
        return r#"<!doctype html>
<html>
  <head>
    <title>Tempo Fixture Storage Report</title>
    <script>
      const local = localStorage.getItem('tempoIsolation') === null ? 'missing' : 'present';
      const cookie = document.cookie.includes('tempoIsolation=root') ? 'present' : 'absent';
      location.replace(`/storage-result?local=${local}&cookie=${cookie}`);
    </script>
  </head>
  <body>reporting</body>
</html>"#
            .to_owned();
    }
    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>Tempo Fixture {path}</title>
  </head>
  <body>
    <main>
      <label for="name">Name</label>
      <input id="name" aria-label="Name" value="">
      <button id="save" onclick="this.textContent = 'Saved ' + document.getElementById('name').value">Save</button>
      <a href="/fork">Fork page</a>
    </main>
  </body>
</html>"#
    )
}

fn unused_loopback_addr() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

fn wait_for_engine_ready(engine: &EngineHandle) -> TestResult {
    match engine.ready.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("CDP engine failed to launch: {error}").into()),
        Err(error) => Err(format!("timed out waiting for CDP engine launch: {error}").into()),
    }
}

fn wait_for_health(
    addr: SocketAddr,
    engine_done: &mpsc::Receiver<Result<(), String>>,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(result) = engine_done.try_recv() {
            return match result {
                Ok(()) => Err("CDP engine exited before tempod became healthy".into()),
                Err(error) => {
                    Err(format!("CDP engine failed before tempod became healthy: {error}").into())
                }
            };
        }
        if let Ok((200, _)) = http_request(addr, "GET", "/health", None) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for tempod health".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn http_json(addr: SocketAddr, method: &str, path: &str, body: Option<Value>) -> TestResult<Value> {
    let body = body.map(|value| value.to_string());
    let (status, bytes) = http_request(addr, method, path, body.as_deref())
        .map_err(|error| format!("{method} {path} failed: {error}"))?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "{method} {path} returned HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response_complete(&response) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let header_end = find_header_end(&response).ok_or("HTTP response missing header terminator")?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP response missing status")?
        .parse::<u16>()?;
    Ok((status, response[header_end + 4..].to_vec()))
}

fn response_complete(response: &[u8]) -> bool {
    let Some(header_end) = find_header_end(response) else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let Some(length) = headers.lines().find_map(content_length) else {
        return false;
    };
    response.len().saturating_sub(header_end + 4) >= length
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(line: &str) -> Option<usize> {
    let (name, value) = line.split_once(':')?;
    if name.eq_ignore_ascii_case("content-length") {
        value.trim().parse().ok()
    } else {
        None
    }
}

fn mcp(addr: SocketAddr, id: u64, method: &str, params: Value) -> TestResult<Value> {
    let value = http_json(
        addr,
        "POST",
        "/mcp",
        Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        })),
    )?;
    if value.get("error").is_some() {
        return Err(format!("MCP {method} returned error: {value}").into());
    }
    Ok(value)
}

fn mcp_tool(addr: SocketAddr, id: u64, name: &str, arguments: Value) -> TestResult<Value> {
    let value = mcp(addr, id, "tools/call", tool_call(name, arguments))?;
    let structured = &value["result"]["structuredContent"];
    if structured.get("error").is_some() {
        return Err(format!("MCP tool {name} returned error: {value}").into());
    }
    Ok(structured.clone())
}

fn tool_call(name: &str, arguments: Value) -> Value {
    json!({
        "name": name,
        "arguments": arguments
    })
}

fn bidi(addr: SocketAddr, command: Value) -> TestResult<Value> {
    let value = bidi_raw(addr, command)?;
    if value.get("error").is_some() {
        return Err(format!("BiDi returned error: {value}").into());
    }
    Ok(value)
}

fn bidi_raw(addr: SocketAddr, command: Value) -> TestResult<Value> {
    http_json(addr, "POST", "/bidi", Some(command))
}

fn find_node_id(observation: &Value, role: &str, text: &str) -> TestResult<String> {
    let elements = observation["elements"]
        .as_array()
        .ok_or("observation missing elements array")?;
    for element in elements {
        if element["role"] == role && element_name(element).contains(text) {
            return element["node_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "matching element missing node_id".into());
        }
    }
    Err(format!("missing element role={role:?} text={text:?} in {observation}").into())
}

fn element_name(element: &Value) -> String {
    element["name"]
        .as_array()
        .map(|spans| {
            spans
                .iter()
                .filter_map(|span| span["text"].as_str())
                .collect::<String>()
        })
        .unwrap_or_default()
}
