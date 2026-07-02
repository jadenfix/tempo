//! tempod - headless tempo daemon and control commands.
//!
//! This binary owns the transport edge: local HTTP routing for health, BiDi,
//! and MCP endpoints, plus engine-host supervision and session recovery commands.

use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;
use tempo_bidi::{BidiErrorCode, BidiMessage, BidiRouter, RoutedCommand};
use tempo_engine_host::{EngineHost, EngineHostConfig, EngineHostError, RestartPolicy};
use tempo_session::{JournalError, RunId, SessionId, SessionJournal};
use thiserror::Error;

const USAGE: &str = "\
tempod

Commands:
  serve --addr HOST:PORT
  status
  resume --journal PATH --run-id ID --session-id ID
  supervise --program PATH [--arg VALUE ...] [--journal PATH]
            [--max-restarts N] [--probe-ms N]
";

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();

    match run_with_writer(env::args().skip(1), &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run_with_writer<I, S>(args: I, stdout: &mut dyn Write) -> Result<(), HeadlessError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    CommandLine::parse(args)?.execute(stdout)
}

#[derive(Debug, PartialEq, Eq)]
enum CommandLine {
    Help,
    Status,
    Serve {
        addr: SocketAddr,
    },
    Resume {
        journal: PathBuf,
        run_id: String,
        session_id: String,
    },
    Supervise {
        config: EngineHostConfig,
        probe_ms: u64,
    },
}

impl CommandLine {
    fn parse<I, S>(args: I) -> Result<Self, HeadlessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let Some((command, options)) = args.split_first() else {
            return Ok(Self::Help);
        };

        match command.as_str() {
            "-h" | "--help" | "help" => Ok(Self::Help),
            "status" => parse_status(options),
            "serve" => parse_serve(options),
            "resume" => parse_resume(options),
            "supervise" => parse_supervise(options),
            other => Err(HeadlessError::Usage(format!(
                "unknown command: {other}\n\n{USAGE}"
            ))),
        }
    }

    fn execute(self, stdout: &mut dyn Write) -> Result<(), HeadlessError> {
        match self {
            Self::Help => {
                stdout.write_all(USAGE.as_bytes())?;
                Ok(())
            }
            Self::Status => write_json(stdout, &HeadlessStatus::current()),
            Self::Serve { addr } => serve(addr),
            Self::Resume {
                journal,
                run_id,
                session_id,
            } => {
                let resumed = SessionJournal::resume(
                    &journal,
                    RunId(run_id.clone()),
                    SessionId(session_id.clone()),
                )?;
                write_json(
                    stdout,
                    &ResumeReport {
                        journal: resumed.path.display().to_string(),
                        run_id,
                        session_id,
                        next_seq: resumed.next_seq,
                        entries: resumed.entries.len(),
                    },
                )
            }
            Self::Supervise { config, probe_ms } => {
                let report = supervise_once(config, probe_ms)?;
                write_json(stdout, &report)
            }
        }
    }
}

fn parse_status(options: &[String]) -> Result<CommandLine, HeadlessError> {
    reject_options(options)?;
    Ok(CommandLine::Status)
}

fn parse_serve(options: &[String]) -> Result<CommandLine, HeadlessError> {
    let mut addr = None;
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--addr" => addr = Some(parse_addr(take_value(options, &mut index)?)?),
            "-h" | "--help" => return Ok(CommandLine::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }
    Ok(CommandLine::Serve {
        addr: required("--addr", addr)?,
    })
}

fn parse_resume(options: &[String]) -> Result<CommandLine, HeadlessError> {
    let mut journal = None;
    let mut run_id = None;
    let mut session_id = None;
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--journal" => journal = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--run-id" => run_id = Some(take_value(options, &mut index)?),
            "--session-id" => session_id = Some(take_value(options, &mut index)?),
            "-h" | "--help" => return Ok(CommandLine::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    Ok(CommandLine::Resume {
        journal: required("--journal", journal)?,
        run_id: required("--run-id", run_id)?,
        session_id: required("--session-id", session_id)?,
    })
}

fn parse_supervise(options: &[String]) -> Result<CommandLine, HeadlessError> {
    let mut program = None;
    let mut args = Vec::new();
    let mut journal = None;
    let mut max_restarts = 0;
    let mut probe_ms = 50;
    let mut index = 0;

    while index < options.len() {
        match options[index].as_str() {
            "--program" => program = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--arg" => args.push(take_value(options, &mut index)?),
            "--journal" => journal = Some(PathBuf::from(take_value(options, &mut index)?)),
            "--max-restarts" => {
                max_restarts = parse_u32("--max-restarts", take_value(options, &mut index)?)?;
            }
            "--probe-ms" => probe_ms = parse_u64("--probe-ms", take_value(options, &mut index)?)?,
            "-h" | "--help" => return Ok(CommandLine::Help),
            flag => return Err(unknown_flag(flag)),
        }
        index += 1;
    }

    let mut config = EngineHostConfig::new(required("--program", program)?);
    for arg in args {
        config = config.arg(arg);
    }
    if max_restarts > 0 {
        config = config.restart(RestartPolicy::Always { max_restarts });
    }
    if let Some(path) = journal {
        config = config.session_journal(path);
    }

    Ok(CommandLine::Supervise { config, probe_ms })
}

fn serve(addr: SocketAddr) -> Result<(), HeadlessError> {
    let listener = TcpListener::bind(addr)?;
    let mut state = HeadlessState::new();
    for stream in listener.incoming() {
        let mut stream = stream?;
        let request = read_http_request(&mut stream)?;
        let response = state.handle(request);
        stream.write_all(&response.to_bytes())?;
        stream.flush()?;
    }
    Ok(())
}

fn supervise_once(
    config: EngineHostConfig,
    probe_ms: u64,
) -> Result<SuperviseReport, HeadlessError> {
    let mut host = EngineHost::spawn(config)?;
    let pid = host.pid();
    if probe_ms > 0 {
        thread::sleep(Duration::from_millis(probe_ms));
    }

    let exited = host.try_wait()?.is_some();
    let mut restarted = false;
    if exited {
        restarted = match host.restart_if_exited() {
            Ok(value) => value,
            Err(EngineHostError::ProcessExited { .. }) => false,
            Err(error) => return Err(error.into()),
        };
    }

    let restart_count = host.restart_count();
    host.kill()?;
    Ok(SuperviseReport {
        pid,
        exited,
        restarted,
        restart_count,
    })
}

struct HeadlessState {
    bidi: BidiRouter,
}

impl HeadlessState {
    fn new() -> Self {
        Self {
            bidi: BidiRouter::new(),
        }
    }

    fn handle(&mut self, request: HttpRequest) -> HttpResponse {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/healthz") | ("GET", "/readyz") => {
                HttpResponse::json(200, json!(HeadlessStatus::current()))
            }
            ("GET", "/mcp") => HttpResponse::from_mcp(tempo_mcp::handle_get()),
            ("POST", "/mcp") => self.mcp_requires_driver(&request),
            ("POST", "/bidi") => self.handle_bidi(request.body),
            _ => HttpResponse::json(
                404,
                json!({
                    "error": "not_found",
                    "path": request.path,
                }),
            ),
        }
    }

    fn handle_bidi(&mut self, body: Vec<u8>) -> HttpResponse {
        match self.bidi.route_json(&body) {
            Ok(RoutedCommand::Immediate(message)) => match serde_json::to_vec(&message) {
                Ok(body) => HttpResponse::new(200, "application/json", body),
                Err(error) => HttpResponse::json(
                    500,
                    json!({
                        "error": "bidi_serialize_failed",
                        "message": error.to_string(),
                    }),
                ),
            },
            Ok(RoutedCommand::Driver { id, .. }) => {
                let message = BidiMessage::error(
                    Some(id),
                    BidiErrorCode::UnknownError,
                    "driver command requires an attached engine driver",
                );
                match serde_json::to_vec(&message) {
                    Ok(body) => HttpResponse::new(503, "application/json", body),
                    Err(error) => HttpResponse::json(
                        500,
                        json!({
                            "error": "bidi_serialize_failed",
                            "message": error.to_string(),
                        }),
                    ),
                }
            }
            Err(error) => {
                let message =
                    BidiMessage::error(None, BidiErrorCode::InvalidArgument, error.to_string());
                match serde_json::to_vec(&message) {
                    Ok(body) => HttpResponse::new(400, "application/json", body),
                    Err(error) => HttpResponse::json(
                        500,
                        json!({
                            "error": "bidi_serialize_failed",
                            "message": error.to_string(),
                        }),
                    ),
                }
            }
        }
    }

    fn mcp_requires_driver(&self, request: &HttpRequest) -> HttpResponse {
        let id = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|value| value.get("id").cloned())
            .unwrap_or(Value::Null);
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, content_type: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body,
        }
    }

    fn json(status: u16, value: Value) -> Self {
        Self::new(status, "application/json", value.to_string().into_bytes())
    }

    fn from_mcp(response: tempo_mcp::McpHttpResponse) -> Self {
        Self::new(response.status, response.content_type, response.body)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let reason = status_reason(self.status);
        let mut bytes = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.status,
            reason,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, HeadlessError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(HeadlessError::Http(
                "connection closed before headers".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() > 64 * 1024 {
            return Err(HeadlessError::Http("HTTP headers exceed 64 KiB".into()));
        }
    };

    let (head, rest) = buffer.split_at(header_end + 4);
    let mut request = parse_http_request_head(head)?;
    let content_length = content_length(&request)?;
    request.body.extend_from_slice(rest);
    while request.body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(HeadlessError::Http("connection closed before body".into()));
        }
        request.body.extend_from_slice(&chunk[..read]);
    }
    request.body.truncate(content_length);
    Ok(request)
}

#[cfg(test)]
fn parse_http_request(raw: &[u8]) -> Result<HttpRequest, HeadlessError> {
    let Some(header_end) = find_header_end(raw) else {
        return Err(HeadlessError::Http("missing HTTP header terminator".into()));
    };
    let (head, rest) = raw.split_at(header_end + 4);
    let mut request = parse_http_request_head(head)?;
    let length = content_length(&request)?;
    if rest.len() < length {
        return Err(HeadlessError::Http(
            "body shorter than content-length".into(),
        ));
    }
    request.body.extend_from_slice(&rest[..length]);
    Ok(request)
}

fn parse_http_request_head(head: &[u8]) -> Result<HttpRequest, HeadlessError> {
    let text = std::str::from_utf8(head)
        .map_err(|error| HeadlessError::Http(format!("HTTP headers are not UTF-8: {error}")))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HeadlessError::Http("missing request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HeadlessError::Http("missing method".into()))?;
    let path = parts
        .next()
        .ok_or_else(|| HeadlessError::Http("missing path".into()))?;
    let version = parts
        .next()
        .ok_or_else(|| HeadlessError::Http("missing version".into()))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HeadlessError::Http(format!(
            "unsupported HTTP version: {version}"
        )));
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(HeadlessError::Http(format!("malformed header: {line}")));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().into()));
    }

    Ok(HttpRequest {
        method: method.into(),
        path: path.into(),
        headers,
        body: Vec::new(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(request: &HttpRequest) -> Result<usize, HeadlessError> {
    request
        .headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| {
            value
                .parse()
                .map_err(|_| HeadlessError::Http(format!("invalid content-length: {value}")))
        })
        .unwrap_or(Ok(0))
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn write_json<T: Serialize>(writer: &mut dyn Write, value: &T) -> Result<(), HeadlessError> {
    serde_json::to_writer_pretty(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn reject_options(options: &[String]) -> Result<(), HeadlessError> {
    if let Some(flag) = options.first() {
        Err(unknown_flag(flag))
    } else {
        Ok(())
    }
}

fn take_value(options: &[String], index: &mut usize) -> Result<String, HeadlessError> {
    let flag = options[*index].clone();
    *index += 1;
    options
        .get(*index)
        .cloned()
        .ok_or_else(|| HeadlessError::Usage(format!("missing value for {flag}\n\n{USAGE}")))
}

fn required<T>(flag: &'static str, value: Option<T>) -> Result<T, HeadlessError> {
    value.ok_or_else(|| HeadlessError::Usage(format!("missing required {flag}\n\n{USAGE}")))
}

fn unknown_flag(flag: &str) -> HeadlessError {
    HeadlessError::Usage(format!("unknown flag: {flag}\n\n{USAGE}"))
}

fn parse_addr(value: String) -> Result<SocketAddr, HeadlessError> {
    value.parse().map_err(|_| HeadlessError::InvalidValue {
        flag: "--addr",
        value,
    })
}

fn parse_u32(flag: &'static str, value: String) -> Result<u32, HeadlessError> {
    value
        .parse()
        .map_err(|_| HeadlessError::InvalidValue { flag, value })
}

fn parse_u64(flag: &'static str, value: String) -> Result<u64, HeadlessError> {
    value
        .parse()
        .map_err(|_| HeadlessError::InvalidValue { flag, value })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct HeadlessStatus {
    service: &'static str,
    version: &'static str,
    ready: bool,
    protocols: Vec<&'static str>,
}

impl HeadlessStatus {
    fn current() -> Self {
        Self {
            service: "tempod",
            version: env!("CARGO_PKG_VERSION"),
            ready: true,
            protocols: vec!["bidi", "mcp"],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ResumeReport {
    journal: String,
    run_id: String,
    session_id: String,
    next_seq: u64,
    entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SuperviseReport {
    pid: u32,
    exited: bool,
    restarted: bool,
    restart_count: u32,
}

#[derive(Debug, Error)]
enum HeadlessError {
    #[error("{0}")]
    Usage(String),
    #[error("invalid value for {flag}: {value}")]
    InvalidValue { flag: &'static str, value: String },
    #[error("headless I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("headless JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engine host failed: {0}")]
    EngineHost(#[from] EngineHostError),
    #[error("session journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("HTTP request failed: {0}")]
    Http(String),
}

impl HeadlessError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::InvalidValue { .. } => 2,
            Self::Io(_)
            | Self::Json(_)
            | Self::EngineHost(_)
            | Self::Journal(_)
            | Self::Http(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::error::Error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_session::JournalEvent;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn status_command_outputs_protocols() -> TestResult {
        let mut stdout = Vec::new();

        run_with_writer(["status"], &mut stdout)?;

        let value: Value = serde_json::from_slice(&stdout)?;
        assert_eq!(value["service"], "tempod");
        assert_eq!(value["protocols"][0], "bidi");
        assert_eq!(value["protocols"][1], "mcp");
        Ok(())
    }

    #[test]
    fn bidi_http_routes_immediate_command() -> TestResult {
        let body = br#"{"id":1,"method":"session.status","params":{}}"#;
        let request = http_request("POST", "/bidi", body)?;
        let mut state = HeadlessState::new();

        let response = state.handle(request);

        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "success");
        assert_eq!(value["id"], 1);
        Ok(())
    }

    #[test]
    fn bidi_http_rejects_driver_command_without_attached_engine() -> TestResult {
        let body = br#"{"id":7,"method":"browsingContext.navigate","params":{"context":"ctx","url":"https://example.test"}}"#;
        let request = http_request("POST", "/bidi", body)?;
        let mut state = HeadlessState::new();

        let response = state.handle(request);

        assert_eq!(response.status, 503);
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["type"], "error");
        assert_eq!(value["id"], 7);
        Ok(())
    }

    #[test]
    fn mcp_get_uses_protocol_response() -> TestResult {
        let request = http_request("GET", "/mcp", b"")?;
        let mut state = HeadlessState::new();

        let response = state.handle(request);

        assert_eq!(response.status, 405);
        assert_eq!(
            std::str::from_utf8(&response.body)?,
            "this MCP endpoint does not offer a server-initiated stream"
        );
        Ok(())
    }

    #[test]
    fn resume_command_reads_real_journal() -> TestResult {
        let root = unique_dir("resume")?;
        remove_dir_if_exists(&root)?;
        fs::create_dir_all(&root)?;
        let journal_path = root.join("session.jsonl");
        write_journal(&journal_path)?;
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "resume".to_string(),
                "--journal".into(),
                path_string(&journal_path),
                "--run-id".into(),
                "run-a".into(),
                "--session-id".into(),
                "session-a".into(),
            ],
            &mut stdout,
        )?;

        let value: Value = serde_json::from_slice(&stdout)?;
        assert_eq!(value["entries"], 2);
        assert_eq!(value["next_seq"], 2);
        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn supervise_command_spawns_real_child() -> TestResult {
        let mut stdout = Vec::new();

        run_with_writer(
            [
                "supervise",
                "--program",
                "sh",
                "--arg",
                "-c",
                "--arg",
                "exit 0",
                "--probe-ms",
                "20",
            ],
            &mut stdout,
        )?;

        let value: Value = serde_json::from_slice(&stdout)?;
        assert!(value["pid"].as_u64().unwrap_or(0) > 0);
        assert_eq!(value["exited"], true);
        assert_eq!(value["restart_count"], 0);
        Ok(())
    }

    #[test]
    fn http_parser_reads_headers_and_body() -> TestResult {
        let request = parse_http_request(
            b"POST /bidi HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\n\r\n{}",
        )?;

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/bidi");
        assert_eq!(request.body, b"{}");
        Ok(())
    }

    fn http_request(method: &str, path: &str, body: &[u8]) -> Result<HttpRequest, HeadlessError> {
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        parse_http_request(&raw)
    }

    fn write_journal(path: &std::path::Path) -> TestResult {
        let mut journal =
            SessionJournal::open(path, RunId("run-a".into()), SessionId("session-a".into()))?;
        journal.append(JournalEvent::SessionStarted {
            url: "https://headless.test".into(),
        })?;
        journal.append(JournalEvent::SessionClosed)?;
        Ok(())
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = env::temp_dir();
        path.push(format!(
            "tempo-headless-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &std::path::Path) -> Result<(), io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn path_string(path: &std::path::Path) -> String {
        path.to_string_lossy().into_owned()
    }
}
