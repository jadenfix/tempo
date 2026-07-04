//! tempo-shell - loopback shell client for human-visible tempo sessions.
//!
//! The GUI chrome will sit above this crate. This layer is already real: it
//! speaks tempod's HTTP control API over TCP, opens/adopts/closes sessions, and
//! renders session state against the live daemon protocol.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tempo_headless::{TempodSession, TempodSessionEvent, TempodSessionId};
use thiserror::Error;

pub const DEFAULT_TEMPOD_ADDR: &str = "127.0.0.1:8787";
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

const USAGE: &str = "\
tempo-shell

Commands:
  health
  sessions
  open URL
  adopt SESSION_ID
  events SESSION_ID [AFTER_SEQ]
  close SESSION_ID
  agent-card
  handshake ORIGIN
  tool NAME [ARGS_JSON]
  drain

Options:
  --tempod ADDR   tempod address, default 127.0.0.1:8787
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellOptions {
    pub tempod_addr: String,
    pub command: ShellCommand,
}

impl ShellOptions {
    pub fn parse<I, S>(args: I) -> Result<Self, ShellError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut tempod_addr = DEFAULT_TEMPOD_ADDR.to_string();
        let mut index = 0;

        while index < args.len() {
            match args[index].as_str() {
                "--tempod" => {
                    index += 1;
                    tempod_addr = args
                        .get(index)
                        .ok_or_else(|| ShellError::Usage("--tempod requires ADDR".into()))?
                        .clone();
                    index += 1;
                }
                "-h" | "--help" | "help" => {
                    return Ok(Self {
                        tempod_addr,
                        command: ShellCommand::Help,
                    });
                }
                _ => break,
            }
        }

        let command = parse_command(&args[index..])?;
        Ok(Self {
            tempod_addr,
            command,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellCommand {
    Help,
    Health,
    Sessions,
    Open {
        url: String,
    },
    Adopt {
        session_id: String,
    },
    Events {
        session_id: String,
        after_seq: Option<u64>,
    },
    Close {
        session_id: String,
    },
    AgentCard,
    Handshake {
        origin: String,
    },
    Tool {
        name: String,
        arguments: Value,
    },
    Drain,
}

impl ShellCommand {
    fn execute(&self, client: &ShellClient, stdout: &mut dyn Write) -> Result<(), ShellError> {
        match self {
            Self::Help => {
                stdout.write_all(USAGE.as_bytes())?;
                Ok(())
            }
            Self::Health => write_json(stdout, &client.health()?),
            Self::Sessions => write_json(stdout, &client.sessions()?),
            Self::Open { url } => write_json(stdout, &client.open(url)?),
            Self::Adopt { session_id } => write_json(stdout, &client.adopt(session_id)?),
            Self::Events {
                session_id,
                after_seq,
            } => write_json(stdout, &client.events(session_id, *after_seq)?),
            Self::Close { session_id } => write_json(stdout, &client.close(session_id)?),
            Self::AgentCard => write_json(stdout, &client.agent_card()?),
            Self::Handshake { origin } => write_json(stdout, &client.handshake(origin)?),
            Self::Tool { name, arguments } => {
                write_json(stdout, &client.mcp_tool(name, arguments.clone())?)
            }
            Self::Drain => write_json(stdout, &client.drain()?),
        }
    }
}

pub fn run_cli<I, S>(args: I, stdout: &mut dyn Write) -> Result<(), ShellError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let options = ShellOptions::parse(args)?;
    let client = ShellClient::new(options.tempod_addr);
    options.command.execute(&client, stdout)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellClient {
    tempod_addr: String,
    timeout: Duration,
    max_response_bytes: usize,
}

impl ShellClient {
    pub fn new(tempod_addr: impl Into<String>) -> Self {
        Self {
            tempod_addr: tempod_addr.into(),
            timeout: Duration::from_secs(5),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn health(&self) -> Result<HealthResponse, ShellError> {
        self.request_json("GET", "/health", None::<serde_json::Value>)
    }

    pub fn sessions(&self) -> Result<Vec<TempodSession>, ShellError> {
        self.request_json("GET", "/sessions", None::<serde_json::Value>)
    }

    pub fn open(&self, url: &str) -> Result<TempodSession, ShellError> {
        self.request_json("POST", "/sessions", Some(json!({ "url": url })))
    }

    pub fn adopt(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        let path = format!("/sessions/{}/adopt", safe_path_segment(session_id)?);
        self.request_json("POST", &path, None::<serde_json::Value>)
    }

    pub fn events(
        &self,
        session_id: &str,
        after_seq: Option<u64>,
    ) -> Result<Vec<TempodSessionEvent>, ShellError> {
        let mut path = format!("/sessions/{}/events", safe_path_segment(session_id)?);
        if let Some(after_seq) = after_seq {
            path.push_str("?after_seq=");
            path.push_str(&after_seq.to_string());
        }
        self.request_json("GET", &path, None::<serde_json::Value>)
    }

    pub fn close(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        let path = format!("/sessions/{}", safe_path_segment(session_id)?);
        self.request_json("DELETE", &path, None::<serde_json::Value>)
    }

    pub fn drain(&self) -> Result<DrainResponse, ShellError> {
        self.request_json("POST", "/drain", None::<serde_json::Value>)
    }

    pub fn agent_card(&self) -> Result<Value, ShellError> {
        self.request_json(
            "GET",
            tempo_mcp::A2A_AGENT_CARD_PATH,
            None::<serde_json::Value>,
        )
    }

    pub fn handshake(&self, origin: &str) -> Result<Value, ShellError> {
        if origin.trim().is_empty() {
            return Err(ShellError::Usage("handshake ORIGIN is required".into()));
        }
        self.mcp_tool("handshake", json!({ "origin": origin }))
    }

    pub fn mcp_tool(&self, name: &str, arguments: Value) -> Result<Value, ShellError> {
        let envelope: Value = self.request_json(
            "POST",
            "/mcp",
            Some(json!({
                "jsonrpc": "2.0",
                "id": "tempo-shell",
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            })),
        )?;
        if let Some(error) = envelope.get("error") {
            return Err(ShellError::Mcp(error.to_string()));
        }
        envelope
            .pointer("/result/structuredContent")
            .cloned()
            .ok_or_else(|| ShellError::Protocol("MCP response missing structuredContent".into()))
    }

    fn request_json<T, B>(&self, method: &str, path: &str, body: Option<B>) -> Result<T, ShellError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let body = match body {
            Some(body) => serde_json::to_vec(&body)?,
            None => Vec::new(),
        };
        let response = self.request(method, path, &body)?;
        if !(200..300).contains(&response.status) {
            return Err(ShellError::Http {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).to_string(),
            });
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<HttpResponse, ShellError> {
        let mut stream = TcpStream::connect(&self.tempod_addr)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.tempod_addr,
            body.len()
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;
        stream.shutdown(std::net::Shutdown::Write)?;

        let mut bytes = Vec::new();
        let limit = u64::try_from(self.max_response_bytes)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        stream.take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > self.max_response_bytes {
            return Err(ShellError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }
        parse_http_response(&bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainResponse {
    pub draining: bool,
    pub sessions: Vec<TempodSession>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_command(args: &[String]) -> Result<ShellCommand, ShellError> {
    let Some((command, rest)) = args.split_first() else {
        return Ok(ShellCommand::Help);
    };
    match command.as_str() {
        "health" => no_args(rest, ShellCommand::Health),
        "sessions" => no_args(rest, ShellCommand::Sessions),
        "open" => one_arg(rest, "open URL", |url| ShellCommand::Open { url }),
        "adopt" => one_arg(rest, "adopt SESSION_ID", |session_id| ShellCommand::Adopt {
            session_id,
        }),
        "events" => parse_events_command(rest),
        "close" => one_arg(rest, "close SESSION_ID", |session_id| ShellCommand::Close {
            session_id,
        }),
        "agent-card" => no_args(rest, ShellCommand::AgentCard),
        "handshake" => one_arg(rest, "handshake ORIGIN", |origin| ShellCommand::Handshake {
            origin,
        }),
        "tool" => parse_tool_command(rest),
        "drain" => no_args(rest, ShellCommand::Drain),
        "-h" | "--help" | "help" => Ok(ShellCommand::Help),
        other => Err(ShellError::Usage(format!(
            "unknown command: {other}\n\n{USAGE}"
        ))),
    }
}

fn parse_events_command(rest: &[String]) -> Result<ShellCommand, ShellError> {
    match rest {
        [session_id] => Ok(ShellCommand::Events {
            session_id: session_id.clone(),
            after_seq: None,
        }),
        [session_id, after_seq] => Ok(ShellCommand::Events {
            session_id: session_id.clone(),
            after_seq: Some(after_seq.parse().map_err(|err: std::num::ParseIntError| {
                ShellError::Usage(format!("events AFTER_SEQ must be a u64: {err}"))
            })?),
        }),
        [] => Err(ShellError::Usage(
            "events SESSION_ID [AFTER_SEQ] requires a session id".into(),
        )),
        [_, _, extra, ..] => Err(ShellError::Usage(format!("unexpected argument: {extra}"))),
    }
}

fn parse_tool_command(rest: &[String]) -> Result<ShellCommand, ShellError> {
    match rest {
        [name] => Ok(ShellCommand::Tool {
            name: name.clone(),
            arguments: json!({}),
        }),
        [name, arguments] => Ok(ShellCommand::Tool {
            name: name.clone(),
            arguments: serde_json::from_str(arguments)?,
        }),
        [] => Err(ShellError::Usage(
            "tool NAME [ARGS_JSON] requires a tool name".into(),
        )),
        [_, _, extra, ..] => Err(ShellError::Usage(format!("unexpected argument: {extra}"))),
    }
}

fn no_args(rest: &[String], command: ShellCommand) -> Result<ShellCommand, ShellError> {
    if rest.is_empty() {
        Ok(command)
    } else {
        Err(ShellError::Usage(format!(
            "unexpected argument: {}",
            rest[0]
        )))
    }
}

fn one_arg<F>(rest: &[String], usage: &str, build: F) -> Result<ShellCommand, ShellError>
where
    F: FnOnce(String) -> ShellCommand,
{
    match rest {
        [value] => Ok(build(value.clone())),
        [] => Err(ShellError::Usage(format!("{usage} requires an argument"))),
        [_, extra, ..] => Err(ShellError::Usage(format!("unexpected argument: {extra}"))),
    }
}

fn parse_http_response(bytes: &[u8]) -> Result<HttpResponse, ShellError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ShellError::Protocol("missing HTTP response headers".into()))?;
    let headers = String::from_utf8(bytes[..header_end].to_vec())
        .map_err(|err| ShellError::Protocol(err.to_string()))?;
    let mut lines = headers.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| ShellError::Protocol("missing HTTP status".into()))?;
    let mut status_parts = status_line.split_ascii_whitespace();
    let version = status_parts
        .next()
        .ok_or_else(|| ShellError::Protocol("missing HTTP version".into()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ShellError::Protocol(format!(
            "unsupported HTTP version: {version}"
        )));
    }
    let status = status_parts
        .next()
        .ok_or_else(|| ShellError::Protocol("missing HTTP status".into()))?
        .parse()
        .map_err(|err: std::num::ParseIntError| ShellError::Protocol(err.to_string()))?;
    if !(100..=599).contains(&status) {
        return Err(ShellError::Protocol(format!(
            "invalid HTTP status: {status}"
        )));
    }

    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ShellError::Protocol(format!("malformed HTTP header: {line}")))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(ShellError::Protocol("empty HTTP header name".into()));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .parse::<usize>()
                .map_err(|err| ShellError::Protocol(format!("invalid content-length: {err}")))?;
            if content_length.is_some_and(|existing| existing != length) {
                return Err(ShellError::Protocol(
                    "conflicting content-length headers".into(),
                ));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && !value
                .split(',')
                .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(ShellError::Protocol(format!(
                "unsupported transfer-encoding: {value}"
            )));
        }
    }

    let body = &bytes[header_end + 4..];
    let body = if let Some(length) = content_length {
        match body.len().cmp(&length) {
            std::cmp::Ordering::Less => {
                return Err(ShellError::Protocol("truncated HTTP response body".into()));
            }
            std::cmp::Ordering::Greater => {
                return Err(ShellError::Protocol(
                    "HTTP response body exceeds content-length".into(),
                ));
            }
            std::cmp::Ordering::Equal => body.to_vec(),
        }
    } else {
        body.to_vec()
    };

    Ok(HttpResponse { status, body })
}

fn safe_path_segment(segment: &str) -> Result<&str, ShellError> {
    let is_safe = !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if is_safe {
        Ok(segment)
    } else {
        Err(ShellError::Usage(format!("invalid session id: {segment}")))
    }
}

fn write_json<T: Serialize>(stdout: &mut dyn Write, value: &T) -> Result<(), ShellError> {
    serde_json::to_writer_pretty(&mut *stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("{0}")]
    Usage(String),
    #[error("shell I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("shell JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tempod returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("tempod MCP failed: {0}")]
    Mcp(String),
    #[error("tempod response exceeded {max_bytes} bytes")]
    ResponseTooLarge { max_bytes: usize },
    #[error("invalid tempod HTTP response: {0}")]
    Protocol(String),
}

impl ShellError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Io(_)
            | Self::Json(_)
            | Self::Http { .. }
            | Self::Mcp(_)
            | Self::ResponseTooLarge { .. }
            | Self::Protocol(_) => 1,
        }
    }
}

#[allow(dead_code)]
fn _assert_session_id_shape(id: &TempodSessionId) -> &str {
    &id.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error;
    use std::net::{SocketAddr, TcpListener};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempo_driver::{Engine, TestDriver};
    use tempo_engine_host::{
        serve_driver_connection, EngineHostError, EngineIpcClient, EngineIpcConnection,
    };
    use tempo_headless::{
        serve_one, SessionPool, TempodError, TempodSessionEventKind, TempodSessionState,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn parses_commands_with_tempod_option() -> TestResult {
        let options =
            ShellOptions::parse(["--tempod", "127.0.0.1:9999", "open", "https://example.com"])?;

        assert_eq!(options.tempod_addr, "127.0.0.1:9999");
        assert_eq!(
            options.command,
            ShellCommand::Open {
                url: "https://example.com".into()
            }
        );
        Ok(())
    }

    #[test]
    fn parses_handshake_command() -> TestResult {
        let options = ShellOptions::parse(["handshake", "https://example.com"])?;

        assert_eq!(
            options.command,
            ShellCommand::Handshake {
                origin: "https://example.com".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn parses_agent_card_command() -> TestResult {
        let options = ShellOptions::parse(["agent-card"])?;

        assert_eq!(options.command, ShellCommand::AgentCard);
        Ok(())
    }

    #[test]
    fn parses_events_command_with_cursor() -> TestResult {
        let options = ShellOptions::parse(["events", "session-0", "7"])?;

        assert_eq!(
            options.command,
            ShellCommand::Events {
                session_id: "session-0".into(),
                after_seq: Some(7),
            }
        );
        Ok(())
    }

    #[test]
    fn parses_mcp_tool_command_with_json_arguments() -> TestResult {
        let options = ShellOptions::parse(["tool", "screenshot", r#"{"set_of_marks":true}"#])?;

        assert_eq!(
            options.command,
            ShellCommand::Tool {
                name: "screenshot".into(),
                arguments: json!({"set_of_marks": true}),
            }
        );
        Ok(())
    }

    #[test]
    fn parse_http_response_respects_content_length() -> TestResult {
        let response = parse_http_response(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")?;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        Ok(())
    }

    #[test]
    fn parse_http_response_rejects_incomplete_content_length_body() -> TestResult {
        let err = match parse_http_response(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhell") {
            Ok(_) => return Err("truncated body should be rejected".into()),
            Err(err) => err,
        };

        assert!(matches!(err, ShellError::Protocol(message) if message.contains("truncated")));
        Ok(())
    }

    #[test]
    fn parse_http_response_rejects_extra_content_length_body() -> TestResult {
        let err = match parse_http_response(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nhello") {
            Ok(_) => return Err("extra body bytes should be rejected".into()),
            Err(err) => err,
        };

        assert!(
            matches!(err, ShellError::Protocol(message) if message.contains("exceeds content-length"))
        );
        Ok(())
    }

    #[test]
    fn parse_http_response_rejects_unsupported_transfer_encoding() -> TestResult {
        let err = match parse_http_response(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        ) {
            Ok(_) => return Err("chunked response should be rejected".into()),
            Err(err) => err,
        };

        assert!(
            matches!(err, ShellError::Protocol(message) if message.contains("transfer-encoding"))
        );
        Ok(())
    }

    #[test]
    fn client_drives_real_tempod_session_lifecycle() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));

        let health = with_tempod(&pool, |addr| ShellClient::new(addr.to_string()).health())?;
        assert!(health.ok);

        let opened = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).open("https://tempo.test")
        })?;
        assert_eq!(opened.id.0, "session-0");
        assert_eq!(opened.url, "https://tempo.test");

        let sessions = with_tempod(&pool, |addr| ShellClient::new(addr.to_string()).sessions())?;
        assert_eq!(sessions.len(), 1);

        let adopted = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).adopt("session-0")
        })?;
        assert_eq!(adopted.state, TempodSessionState::Adopted);

        let closed = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).close("session-0")
        })?;
        assert_eq!(closed.state, TempodSessionState::Killed);

        let drained = with_tempod(&pool, |addr| ShellClient::new(addr.to_string()).drain())?;
        assert!(drained.draining);
        assert_eq!(drained.sessions[0].state, TempodSessionState::Killed);
        Ok(())
    }

    #[test]
    fn client_reads_real_tempod_agent_card() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let card = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).agent_card()
        })?;

        assert_eq!(card["name"], "tempo");
        assert_eq!(card["preferredTransport"], "MCP");
        assert_eq!(card["skills"][0]["id"], "observe");
        assert!(card["skills"]
            .as_array()
            .is_some_and(|skills| skills.iter().any(|skill| skill["id"] == "handshake")));
        Ok(())
    }

    #[test]
    fn client_reads_real_tempod_session_events_with_cursor() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let opened = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).open("https://events.test")
        })?;

        let initial = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).events(&opened.id.0, None)
        })?;
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].seq, 0);
        assert!(matches!(
            initial[0].event,
            TempodSessionEventKind::SessionCreated { .. }
        ));

        with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).adopt(&opened.id.0)
        })?;
        let after_create = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).events(&opened.id.0, Some(0))
        })?;

        assert_eq!(after_create.len(), 1);
        assert_eq!(after_create[0].seq, 1);
        assert!(matches!(
            after_create[0].event,
            TempodSessionEventKind::SessionAdopted
        ));
        Ok(())
    }

    #[test]
    fn client_runs_driverless_handshake_through_real_tempod_mcp() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let result = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).mcp_tool(
                "handshake",
                json!({
                    "origin": "https://tempo.test",
                    "responses": [{
                        "path": "/mcp/catalog.json",
                        "status": 200,
                        "content_type": "application/json",
                        "body": "{\"tools\":[]}",
                    }],
                }),
            )
        })?;

        assert_eq!(result["lane"], "mcp");
        assert_eq!(result["skips_render"], true);
        assert_eq!(result["selected"]["signal"], "mcp_catalog");
        Ok(())
    }

    #[test]
    fn run_cli_invokes_attached_driver_mcp_tool_through_real_tempod() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let driver_handle = attach_test_driver(&pool)?;
        let mut output = Vec::new();

        with_tempod(&pool, |addr| {
            run_cli(
                ["--tempod", &addr.to_string(), "tool", "observe"],
                &mut output,
            )
        })?;
        pool.lock()
            .map_err(|_| "session pool lock failed")?
            .detach_engine_driver();
        join_driver(driver_handle)?;

        let value: Value = serde_json::from_slice(&output)?;
        assert_eq!(value["url"], "about:blank");
        assert_eq!(value["seq"], 0);
        Ok(())
    }

    #[test]
    fn run_cli_writes_json_from_real_tempod() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let mut output = Vec::new();
        with_tempod(&pool, |addr| {
            run_cli(["--tempod", &addr.to_string(), "sessions"], &mut output)
        })?;

        assert_eq!(String::from_utf8(output)?, "[]\n");
        Ok(())
    }

    #[test]
    fn client_rejects_oversized_tempod_response() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request)?;
            let mut response =
                b"HTTP/1.1 200 OK\r\ncontent-length: 32\r\nconnection: close\r\n\r\n".to_vec();
            response.extend([b'x'; 32]);
            match stream.write_all(&response) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(err) => Err(err),
            }
        });

        let err = match ShellClient::new(addr.to_string())
            .with_max_response_bytes(64)
            .health()
        {
            Ok(_) => return Err("oversized response should be rejected before JSON parse".into()),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ShellError::ResponseTooLarge { max_bytes: 64 }
        ));
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("server thread failed".into()),
        }
        Ok(())
    }

    #[test]
    fn rejects_unsafe_session_path_segments() {
        for unsafe_segment in [
            "../session",
            "",
            "s1\r\nX: 1",
            "a b",
            "a?b",
            "a#b",
            "..",
            ".",
            "a/b",
            "a\\b",
            "sessão",
            "a\u{0007}b",
        ] {
            assert!(
                matches!(safe_path_segment(unsafe_segment), Err(ShellError::Usage(_))),
                "expected rejection for {unsafe_segment:?}"
            );
        }
    }

    #[test]
    fn accepts_safe_session_path_segment() {
        assert!(matches!(
            safe_path_segment("session-123_ABC.def"),
            Ok("session-123_ABC.def")
        ));
    }

    #[test]
    fn adopt_events_close_work_for_valid_session_id() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let opened = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).open("https://valid.test")
        })?;
        let session_id = opened.id.0.clone();
        assert!(matches!(
            safe_path_segment(&session_id),
            Ok(id) if id == session_id
        ));

        let adopted = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).adopt(&session_id)
        })?;
        assert_eq!(adopted.state, TempodSessionState::Adopted);

        let events = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).events(&session_id, None)
        })?;
        assert!(!events.is_empty());

        let closed = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).close(&session_id)
        })?;
        assert_eq!(closed.state, TempodSessionState::Killed);
        Ok(())
    }

    fn with_tempod<T, F>(pool: &Arc<Mutex<SessionPool>>, call: F) -> Result<T, Box<dyn Error>>
    where
        F: FnOnce(SocketAddr) -> Result<T, ShellError>,
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::clone(pool);
        let handle = thread::spawn(move || serve_one(listener, server_pool));
        let result = call(addr);
        join_server(handle)?;
        Ok(result?)
    }

    fn join_server(
        handle: thread::JoinHandle<Result<(), TempodError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("server thread failed".into()),
        }
    }

    fn attach_test_driver(
        pool: &Arc<Mutex<SessionPool>>,
    ) -> Result<thread::JoinHandle<Result<(), EngineHostError>>, Box<dyn Error>> {
        let (client_stream, server_stream) = UnixStream::pair()?;
        pool.lock()
            .map_err(|_| "session pool lock failed")?
            .attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream));
        Ok(thread::spawn(move || {
            let mut connection = EngineIpcConnection::from_stream(server_stream);
            let mut driver = TestDriver::new();
            futures::executor::block_on(serve_driver_connection(&mut connection, &mut driver))
        }))
    }

    fn join_driver(
        handle: thread::JoinHandle<Result<(), EngineHostError>>,
    ) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => Ok(result?),
            Err(_) => Err("driver thread failed".into()),
        }
    }
}
