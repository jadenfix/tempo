//! tempo-headless — headless `tempod` control plane.
//!
//! The daemon owns session lifecycle, engine-host supervision, graceful drain,
//! and JSONL export for StepTriples. The HTTP layer here is intentionally small:
//! it uses the standard library so the control surface works before a larger web
//! framework is selected for production packaging.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempo_agent::StepTriple;
use tempo_bidi::{BidiErrorCode, BidiMessage, BidiRouter, RoutedCommand};
use tempo_engine_host::{EngineHost, EngineHostConfig, EngineHostError};
use thiserror::Error;

const MAX_HTTP_BYTES: usize = 64 * 1024;

/// Stable tempod session id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TempodSessionId(pub String);

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TempodSessionState {
    Running,
    Adopted,
    Killed,
}

/// Session record returned by the control API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempodSession {
    pub id: TempodSessionId,
    pub url: String,
    pub state: TempodSessionState,
    pub created_ms: u128,
}

/// In-memory session pool for a tempod process.
#[derive(Clone, Debug, Default)]
pub struct SessionPool {
    sessions: BTreeMap<TempodSessionId, TempodSession>,
    bidi: BidiRouter,
    next_id: u64,
    draining: bool,
}

impl SessionPool {
    pub fn create(&mut self, url: impl Into<String>) -> TempodSession {
        let id = TempodSessionId(format!("session-{}", self.next_id));
        self.next_id = self.next_id.saturating_add(1);
        let session = TempodSession {
            id: id.clone(),
            url: url.into(),
            state: TempodSessionState::Running,
            created_ms: current_time_ms(),
        };
        self.sessions.insert(id, session.clone());
        session
    }

    pub fn list(&self) -> Vec<TempodSession> {
        self.sessions.values().cloned().collect()
    }

    pub fn adopt(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
        session.state = TempodSessionState::Adopted;
        Ok(session.clone())
    }

    pub fn kill(&mut self, id: &TempodSessionId) -> Result<TempodSession, TempodError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| TempodError::SessionNotFound(id.clone()))?;
        session.state = TempodSessionState::Killed;
        Ok(session.clone())
    }

    pub fn drain(&mut self) {
        self.draining = true;
        for session in self.sessions.values_mut() {
            if session.state == TempodSessionState::Running {
                session.state = TempodSessionState::Killed;
            }
        }
    }

    pub fn draining(&self) -> bool {
        self.draining
    }
}

/// Supervised engine host registry used by tempod.
pub struct EngineSupervisor {
    hosts: BTreeMap<String, EngineHost>,
}

impl EngineSupervisor {
    pub fn new() -> Self {
        Self {
            hosts: BTreeMap::new(),
        }
    }

    pub fn start(
        &mut self,
        id: impl Into<String>,
        config: EngineHostConfig,
    ) -> Result<u32, TempodError> {
        let id = id.into();
        let host = EngineHost::spawn(config)?;
        let pid = host.pid();
        self.hosts.insert(id, host);
        Ok(pid)
    }

    pub fn kill(&mut self, id: &str) -> Result<(), TempodError> {
        let host = self
            .hosts
            .get_mut(id)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))?;
        host.kill()?;
        Ok(())
    }

    pub fn restart_if_exited(&mut self, id: &str) -> Result<bool, TempodError> {
        let host = self
            .hosts
            .get_mut(id)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))?;
        Ok(host.restart_if_exited()?)
    }

    pub fn pid(&self, id: &str) -> Result<u32, TempodError> {
        self.hosts
            .get(id)
            .map(EngineHost::pid)
            .ok_or_else(|| TempodError::EngineNotFound(id.into()))
    }
}

impl Default for EngineSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// JSONL exporter for StepTriple telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtlpJsonExporter {
    path: PathBuf,
}

impl OtlpJsonExporter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn export_step(&self, triple: &StepTriple) -> Result<(), TempodError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(
            &mut file,
            &json!({
                "resource": {
                    "service.name": "tempod",
                },
                "name": "tempo.step",
                "body": triple,
            }),
        )?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Run tempod forever on an address such as `127.0.0.1:8787`.
pub fn run_tempod(addr: &str) -> Result<(), TempodError> {
    let listener = TcpListener::bind(addr)?;
    let pool = Arc::new(Mutex::new(SessionPool::default()));
    serve_forever(listener, pool)
}

/// Serve requests until the listener fails or the process is stopped.
pub fn serve_forever(
    listener: TcpListener,
    pool: Arc<Mutex<SessionPool>>,
) -> Result<(), TempodError> {
    for stream in listener.incoming() {
        handle_stream(stream?, &pool)?;
    }
    Ok(())
}

/// Serve exactly one HTTP request. Tests use this against a real TCP listener.
pub fn serve_one(listener: TcpListener, pool: Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let (stream, _addr) = listener.accept()?;
    handle_stream(stream, &pool)
}

fn handle_stream(mut stream: TcpStream, pool: &Arc<Mutex<SessionPool>>) -> Result<(), TempodError> {
    let request = read_http_request(&mut stream)?;
    let response = {
        let mut pool = pool.lock().map_err(|_| TempodError::PoolLock)?;
        handle_http_request(&mut pool, request)
    };
    stream.write_all(response.to_bytes().as_slice())?;
    stream.flush()?;
    Ok(())
}

fn handle_http_request(pool: &mut SessionPool, request: HttpRequest) -> HttpResponse {
    match route_http_request(pool, request) {
        Ok(response) => response,
        Err(err) => HttpResponse::json(
            err.status(),
            json!({
                "error": err.to_string(),
            }),
        ),
    }
}

fn route_http_request(
    pool: &mut SessionPool,
    request: HttpRequest,
) -> Result<HttpResponse, TempodError> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/health") => Ok(HttpResponse::json(200, json!({"ok": true}))),
        ("GET", "/mcp") => Ok(HttpResponse::from_mcp(tempo_mcp::handle_get())),
        ("POST", "/mcp") => Ok(mcp_requires_driver(&request.body)),
        ("POST", "/bidi") => Ok(route_bidi(pool, request.body)),
        ("GET", "/sessions") => Ok(HttpResponse::json(200, pool.list())),
        ("POST", "/sessions") => {
            let body: CreateSessionRequest = serde_json::from_slice(&request.body)?;
            if body.url.trim().is_empty() {
                return Err(TempodError::BadRequest("session url is required".into()));
            }
            Ok(HttpResponse::json(201, pool.create(body.url)))
        }
        ("POST", "/drain") => {
            pool.drain();
            Ok(HttpResponse::json(
                200,
                json!({
                    "draining": pool.draining(),
                    "sessions": pool.list(),
                }),
            ))
        }
        _ => {
            if request.method == "POST" && request.path.ends_with("/adopt") {
                let id = session_id_from_action_path(&request.path, "adopt")?;
                return Ok(HttpResponse::json(200, pool.adopt(&id)?));
            }
            if request.method == "DELETE" {
                let id = session_id_from_path(&request.path)?;
                return Ok(HttpResponse::json(200, pool.kill(&id)?));
            }
            Err(TempodError::BadRequest(format!(
                "unsupported route: {} {}",
                request.method, request.path
            )))
        }
    }
}

fn route_bidi(pool: &mut SessionPool, body: Vec<u8>) -> HttpResponse {
    match pool.bidi.route_json(&body) {
        Ok(RoutedCommand::Immediate(message)) => bidi_response(200, message),
        Ok(RoutedCommand::Driver { id, .. }) => bidi_response(
            503,
            BidiMessage::error(
                Some(id),
                BidiErrorCode::UnknownError,
                "driver command requires an attached engine driver",
            ),
        ),
        Err(error) => bidi_response(
            400,
            BidiMessage::error(None, BidiErrorCode::InvalidArgument, error.to_string()),
        ),
    }
}

fn bidi_response(status: u16, message: BidiMessage) -> HttpResponse {
    match serde_json::to_vec(&message) {
        Ok(body) => HttpResponse::new(status, "application/json", body),
        Err(error) => HttpResponse::json(
            500,
            json!({
                "error": error.to_string(),
            }),
        ),
    }
}

fn mcp_requires_driver(body: &[u8]) -> HttpResponse {
    let id = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    HttpResponse::json(
        503,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32002,
                "message": "MCP tool calls require an attached engine driver",
            }
        }),
    )
}

fn session_id_from_action_path(path: &str, action: &str) -> Result<TempodSessionId, TempodError> {
    let suffix = format!("/{action}");
    let path = path
        .strip_suffix(&suffix)
        .ok_or_else(|| TempodError::BadRequest(format!("invalid session action path: {path}")))?;
    session_id_from_path(path)
}

fn session_id_from_path(path: &str) -> Result<TempodSessionId, TempodError> {
    let id = path
        .strip_prefix("/sessions/")
        .ok_or_else(|| TempodError::BadRequest(format!("invalid session path: {path}")))?;
    if id.is_empty() {
        return Err(TempodError::BadRequest("session id is required".into()));
    }
    Ok(TempodSessionId(id.into()))
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, TempodError> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err(TempodError::BadRequest("HTTP request is too large".into()));
        }
        if header_end(&bytes).is_some() {
            break;
        }
    }

    let header_end =
        header_end(&bytes).ok_or_else(|| TempodError::BadRequest("missing HTTP headers".into()))?;
    let headers = String::from_utf8(bytes[..header_end].to_vec())
        .map_err(|err| TempodError::BadRequest(err.to_string()))?;
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing method".into()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| TempodError::BadRequest("missing path".into()))?
        .to_string();
    let content_len = content_length(headers.lines())?;
    let body_start = header_end + 4;
    while bytes.len() < body_start + content_len {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err(TempodError::BadRequest("HTTP request is too large".into()));
        }
    }
    if bytes.len() < body_start + content_len {
        return Err(TempodError::BadRequest("incomplete HTTP body".into()));
    }

    Ok(HttpRequest {
        method,
        path,
        body: bytes[body_start..body_start + content_len].to_vec(),
    })
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length<'a>(lines: impl Iterator<Item = &'a str>) -> Result<usize, TempodError> {
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse()
                    .map_err(|err: std::num::ParseIntError| {
                        TempodError::BadRequest(err.to_string())
                    });
            }
        }
    }
    Ok(0)
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    fn json(status: u16, body: impl Serialize) -> Self {
        let body = match serde_json::to_vec(&body) {
            Ok(body) => body,
            Err(err) => format!("{{\"error\":\"{err}\"}}").into_bytes(),
        };
        Self::new(status, "application/json", body)
    }

    fn from_mcp(response: tempo_mcp::McpHttpResponse) -> Self {
        Self::new(response.status, response.content_type, response.body)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "OK",
        };
        let mut bytes = format!(
            "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

#[derive(Debug, Error)]
pub enum TempodError {
    #[error("tempod I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("tempod JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("session not found: {0:?}")]
    SessionNotFound(TempodSessionId),
    #[error("engine not found: {0}")]
    EngineNotFound(String),
    #[error("session pool lock failed")]
    PoolLock,
    #[error("engine host failed: {0}")]
    Engine(#[from] EngineHostError),
}

impl TempodError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::SessionNotFound(_) | Self::EngineNotFound(_) => 404,
            Self::Io(_) | Self::Json(_) | Self::PoolLock | Self::Engine(_) => 500,
        }
    }
}

fn current_time_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_agent::{IdempotencyKey, StepTripleOutcome};
    use tempo_engine_host::RestartPolicy;
    use tempo_schema::{Action, ObservationDiff};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn session_pool_create_list_adopt_kill_and_drain() -> TestResult {
        let mut pool = SessionPool::default();

        let session = pool.create("https://pool.test");
        let adopted = pool.adopt(&session.id)?;
        let killed = pool.kill(&session.id)?;
        pool.drain();

        assert_eq!(pool.list().len(), 1);
        assert_eq!(adopted.state, TempodSessionState::Adopted);
        assert_eq!(killed.state, TempodSessionState::Killed);
        assert!(pool.draining());
        Ok(())
    }

    #[test]
    fn http_create_and_list_sessions_over_tcp() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one(listener, server_pool));

        let response = send_http(
            addr,
            "POST /sessions HTTP/1.1\r\ncontent-length: 26\r\n\r\n{\"url\":\"https://one.test\"}",
        )?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 201 Created"));
        assert!(response.contains("\"id\":\"session-0\""));

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::clone(&pool);
        let handle = thread::spawn(move || serve_one(listener, server_pool));

        let response = send_http(addr, "GET /sessions HTTP/1.1\r\n\r\n")?;
        join_server(handle)?;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https://one.test"));
        Ok(())
    }

    #[test]
    fn bidi_endpoint_routes_immediate_protocol_commands() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                body: br#"{"id":1,"method":"session.status","params":{}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ready"], true);
        Ok(())
    }

    #[test]
    fn bidi_endpoint_requires_driver_for_engine_commands() -> TestResult {
        let mut pool = SessionPool::default();
        let response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/bidi".into(),
                body: br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"ctx","url":"https://example.test"}}"#.to_vec(),
            },
        )?;

        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 7);
        Ok(())
    }

    #[test]
    fn mcp_endpoint_exposes_http_semantics_without_driver() -> TestResult {
        let mut pool = SessionPool::default();
        let get_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "GET".into(),
                path: "/mcp".into(),
                body: Vec::new(),
            },
        )?;
        let post_response = route_http_request(
            &mut pool,
            HttpRequest {
                method: "POST".into(),
                path: "/mcp".into(),
                body: br#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#.to_vec(),
            },
        )?;

        assert_eq!(get_response.status, 405);
        assert_eq!(get_response.content_type, "text/plain; charset=utf-8");
        assert_eq!(post_response.status, 503);
        let value: Value = serde_json::from_slice(&post_response.body)?;
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["id"], 9);
        Ok(())
    }

    #[test]
    fn otlp_export_writes_step_triple_jsonl() -> TestResult {
        let root = unique_dir("otlp")?;
        remove_dir_if_exists(&root)?;
        let path = root.join("steps.jsonl");
        let exporter = OtlpJsonExporter::new(&path);
        let triple = StepTriple {
            key: IdempotencyKey("step-1".into()),
            seq: 1,
            action: Action::Scroll { x: 0.0, y: 1.0 },
            outcome: StepTripleOutcome::Applied {
                diff: ObservationDiff {
                    since_seq: 0,
                    seq: 1,
                    added: vec![],
                    removed: vec![],
                    changed: vec![],
                },
            },
        };

        exporter.export_step(&triple)?;
        let bytes = std::fs::read(&path)?;
        let value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap_or(&bytes))?;

        assert_eq!(value["resource"]["service.name"], "tempod");
        assert_eq!(value["name"], "tempo.step");
        assert_eq!(value["body"]["seq"], 1);

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn engine_supervisor_starts_and_restarts_child() -> TestResult {
        let mut supervisor = EngineSupervisor::new();
        let config = EngineHostConfig::new("sh")
            .arg("-c")
            .arg("sleep 20")
            .restart(RestartPolicy::Always { max_restarts: 1 });
        let first_pid = supervisor.start("engine-a", config)?;

        supervisor.kill("engine-a")?;
        let restarted = supervisor.restart_if_exited("engine-a")?;
        let second_pid = supervisor.pid("engine-a")?;

        assert!(restarted);
        assert_ne!(first_pid, second_pid);
        supervisor.kill("engine-a")?;
        Ok(())
    }

    fn send_http(addr: std::net::SocketAddr, request: &str) -> Result<String, std::io::Error> {
        let mut stream = TcpStream::connect(addr)?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn join_server(
        handle: thread::JoinHandle<Result<(), TempodError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("server thread failed".into()),
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-headless-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}
