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

pub mod agent;
pub mod tab;
pub mod ui;
#[cfg(feature = "window")]
pub mod window;

pub const DEFAULT_TEMPOD_ADDR: &str = "127.0.0.1:8787";
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
// Mirrors tempo-engine-host::MAX_SCREENSHOT_BYTES without depending on that crate
// from production shell code. MCP screenshot results base64-encode that raw
// screenshot and wrap it in JSON, so the response cap must allow the encoded
// 64 MiB engine-host screenshot ceiling plus envelope/header overhead.
const ENGINE_HOST_MAX_SCREENSHOT_BYTES: usize = 64 * 1024 * 1024;
const MCP_SCREENSHOT_RESPONSE_OVERHEAD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_MCP_RESPONSE_BYTES: usize =
    ENGINE_HOST_MAX_SCREENSHOT_BYTES.div_ceil(3) * 4 + MCP_SCREENSHOT_RESPONSE_OVERHEAD_BYTES;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

const USAGE: &str = "\
tempo-shell

Commands:
  health
  sessions
  open URL
  adopt SESSION_ID
  resume SESSION_ID
  events SESSION_ID [AFTER_SEQ]
  close SESSION_ID
  agent-card
  handshake ORIGIN
  tool NAME [ARGS_JSON]
  drain

Options:
  --tempod ADDR   tempod address, default 127.0.0.1:8787
  --auth-token TOKEN (default: TEMPO_TEMPOD_AUTH_TOKEN or tempod runtime token file)
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellOptions {
    pub tempod_addr: String,
    pub auth_token: Option<String>,
    pub command: ShellCommand,
}

impl ShellOptions {
    pub fn parse<I, S>(args: I) -> Result<Self, ShellError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::parse_with_env(
            args,
            std::env::var(tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV).ok(),
        )
    }

    fn parse_with_env<I, S>(args: I, env_auth_token: Option<String>) -> Result<Self, ShellError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut tempod_addr = DEFAULT_TEMPOD_ADDR.to_string();
        let mut auth_token = env_auth_token.filter(|token| !token.is_empty());
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
                "--auth-token" => {
                    index += 1;
                    let token = args
                        .get(index)
                        .ok_or_else(|| ShellError::Usage("--auth-token requires TOKEN".into()))?
                        .clone();
                    validate_auth_token(&token)?;
                    auth_token = Some(token);
                    index += 1;
                }
                "-h" | "--help" | "help" => {
                    return Ok(Self {
                        tempod_addr,
                        auth_token,
                        command: ShellCommand::Help,
                    });
                }
                _ => break,
            }
        }

        let command = parse_command(&args[index..])?;
        Ok(Self {
            tempod_addr,
            auth_token,
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
    Resume {
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
            Self::Resume { session_id } => write_json(stdout, &client.resume(session_id)?),
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
    let client = ShellClient::new(options.tempod_addr).with_optional_auth_token(options.auth_token);
    options.command.execute(&client, stdout)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellClient {
    tempod_addr: String,
    auth_token: Option<String>,
    timeout: Duration,
    max_response_bytes: usize,
    max_mcp_response_bytes: usize,
}

impl ShellClient {
    pub fn new(tempod_addr: impl Into<String>) -> Self {
        Self::new_with_discovered_auth_token(
            tempod_addr,
            tempo_headless::load_tempod_runtime_auth_token()
                .ok()
                .flatten()
                .map(|runtime| runtime.token),
        )
    }

    fn new_with_discovered_auth_token(
        tempod_addr: impl Into<String>,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            tempod_addr: tempod_addr.into(),
            auth_token,
            timeout: Duration::from_secs(5),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_mcp_response_bytes: DEFAULT_MAX_MCP_RESPONSE_BYTES,
        }
    }

    pub fn with_auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = Some(auth_token.into());
        self
    }

    fn with_optional_auth_token(mut self, auth_token: Option<String>) -> Self {
        if let Some(auth_token) = auth_token {
            self.auth_token = Some(auth_token);
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self.max_mcp_response_bytes = max_response_bytes;
        self
    }

    pub fn with_max_mcp_response_bytes(mut self, max_mcp_response_bytes: usize) -> Self {
        self.max_mcp_response_bytes = max_mcp_response_bytes;
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

    pub fn resume(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        let path = format!("/sessions/{}/resume", safe_path_segment(session_id)?);
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

    /// Navigate `driver_id` (or the default attached driver) to `url` via the
    /// `act` MCP tool with an [`Action::Goto`]. This is the omnibox/back/forward
    /// primitive: there is no native history in `DriverTrait`, so the shell
    /// re-issues a `goto` for every navigation.
    pub fn goto(&self, driver_id: Option<&str>, url: &str) -> Result<(), ShellError> {
        let action = serde_json::to_value(tempo_schema::Action::Goto {
            url: url.to_string(),
        })?;
        let mut arguments = json!({ "action": action });
        if let Some(driver_id) = driver_id {
            arguments["driver_id"] = json!(driver_id);
        }
        self.mcp_tool("act", arguments)?;
        Ok(())
    }

    /// Fetch a single-shot page snapshot from `driver_id` (or the default
    /// attached driver) via the `screenshot` MCP tool. Not a live frame — the
    /// caller refreshes it on an interval or a button. When `set_of_marks` is
    /// set, the tool overlays the ranked set-of-marks labels on the image (the
    /// agent-panel debug overlay).
    pub fn screenshot(
        &self,
        driver_id: Option<&str>,
        set_of_marks: bool,
    ) -> Result<tab::ScreenshotImage, ShellError> {
        let mut arguments = json!({});
        if let Some(driver_id) = driver_id {
            arguments["driver_id"] = json!(driver_id);
        }
        if set_of_marks {
            arguments["set_of_marks"] = json!(true);
        }
        let structured = self.mcp_tool("screenshot", arguments)?;
        tab::ScreenshotImage::from_structured(&structured)
    }

    pub fn mcp_tool(&self, name: &str, arguments: Value) -> Result<Value, ShellError> {
        let envelope: Value = self.request_json_with_max_response_bytes(
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
            self.max_mcp_response_bytes,
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
        self.request_json_with_max_response_bytes(method, path, body, self.max_response_bytes)
    }

    fn request_json_with_max_response_bytes<T, B>(
        &self,
        method: &str,
        path: &str,
        body: Option<B>,
        max_response_bytes: usize,
    ) -> Result<T, ShellError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let body = match body {
            Some(body) => serde_json::to_vec(&body)?,
            None => Vec::new(),
        };
        let response = self.request(method, path, &body, max_response_bytes)?;
        if !(200..300).contains(&response.status) {
            return Err(ShellError::Http {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).to_string(),
            });
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<HttpResponse, ShellError> {
        let mut stream = TcpStream::connect(&self.tempod_addr)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
            self.tempod_addr,
            body.len()
        );
        if let Some(auth_token) = &self.auth_token {
            validate_auth_token(auth_token)?;
            request.push_str("authorization: Bearer ");
            request.push_str(auth_token);
            request.push_str("\r\n");
        }
        request.push_str("connection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;
        match stream.shutdown(std::net::Shutdown::Write) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotConnected => {}
            Err(err) => return Err(err.into()),
        }

        read_http_response(&mut stream, max_response_bytes)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HttpResponseHead {
    status: u16,
    content_length: Option<usize>,
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
        "resume" => one_arg(rest, "resume SESSION_ID", |session_id| {
            ShellCommand::Resume { session_id }
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
    let header_end = response_header_end(bytes)
        .ok_or_else(|| ShellError::Protocol("missing HTTP response headers".into()))?;
    let head = parse_http_response_head(&bytes[..header_end])?;

    let body = &bytes[header_end + 4..];
    let body = if let Some(length) = head.content_length {
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

    Ok(HttpResponse {
        status: head.status,
        body,
    })
}

fn read_http_response(
    stream: &mut TcpStream,
    max_response_bytes: usize,
) -> Result<HttpResponse, ShellError> {
    let mut bytes = Vec::new();
    let header_end = read_response_headers(stream, &mut bytes)?;
    let head = parse_http_response_head(&bytes[..header_end])?;

    if let Some(content_length) = head.content_length {
        let response_len = (header_end + 4)
            .checked_add(content_length)
            .ok_or_else(|| ShellError::Protocol("HTTP response length overflow".into()))?;
        if response_len > max_response_bytes {
            return Err(ShellError::ResponseTooLarge {
                max_bytes: max_response_bytes,
            });
        }
        read_exact_response_len(stream, &mut bytes, response_len)?;
    } else {
        read_close_delimited_response(stream, &mut bytes, max_response_bytes)?;
    }

    parse_http_response(&bytes)
}

fn read_response_headers(stream: &mut TcpStream, bytes: &mut Vec<u8>) -> Result<usize, ShellError> {
    let mut buf = [0_u8; 1024];
    loop {
        if let Some(header_end) = response_header_end(bytes) {
            if header_end > MAX_RESPONSE_HEADER_BYTES {
                return Err(ShellError::Protocol(
                    "HTTP response headers too large".into(),
                ));
            }
            return Ok(header_end);
        }
        if bytes.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(ShellError::Protocol(
                "HTTP response headers too large".into(),
            ));
        }

        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(ShellError::Protocol("missing HTTP response headers".into()));
        }
        bytes.extend_from_slice(&buf[..read]);
    }
}

fn read_exact_response_len(
    stream: &mut TcpStream,
    bytes: &mut Vec<u8>,
    response_len: usize,
) -> Result<(), ShellError> {
    let mut buf = [0_u8; 1024];
    while bytes.len() < response_len {
        let remaining = response_len - bytes.len();
        let read_len = remaining.min(buf.len());
        let read = stream.read(&mut buf[..read_len])?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
    }
    Ok(())
}

fn read_close_delimited_response(
    stream: &mut TcpStream,
    bytes: &mut Vec<u8>,
    max_response_bytes: usize,
) -> Result<(), ShellError> {
    let mut buf = [0_u8; 1024];
    loop {
        if bytes.len() > max_response_bytes {
            return Err(ShellError::ResponseTooLarge {
                max_bytes: max_response_bytes,
            });
        }
        let remaining = max_response_bytes
            .saturating_sub(bytes.len())
            .saturating_add(1);
        let read_len = remaining.min(buf.len());
        let read = stream.read(&mut buf[..read_len])?;
        if read == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&buf[..read]);
        if bytes.len() > max_response_bytes {
            return Err(ShellError::ResponseTooLarge {
                max_bytes: max_response_bytes,
            });
        }
    }
}

fn response_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_response_head(bytes: &[u8]) -> Result<HttpResponseHead, ShellError> {
    let headers =
        String::from_utf8(bytes.to_vec()).map_err(|err| ShellError::Protocol(err.to_string()))?;
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

    Ok(HttpResponseHead {
        status,
        content_length,
    })
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

pub(crate) fn validate_auth_token(token: &str) -> Result<(), ShellError> {
    if token.is_empty() {
        return Err(ShellError::Usage("auth token is required".into()));
    }
    if token.trim() != token
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ShellError::Usage(
            "auth token must not contain whitespace or control characters".into(),
        ));
    }
    Ok(())
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
        serve_one, serve_one_with_auth, SessionPool, TempodAuth, TempodError,
        TempodSessionEventKind, TempodSessionState,
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
    fn parses_auth_token_option_and_env_default() -> TestResult {
        let from_option = ShellOptions::parse_with_env(
            ["--auth-token", "cli-token", "sessions"],
            Some("env-token".into()),
        )?;
        assert_eq!(from_option.auth_token.as_deref(), Some("cli-token"));

        let from_env = ShellOptions::parse_with_env(["sessions"], Some("env-token".into()))?;
        assert_eq!(from_env.auth_token.as_deref(), Some("env-token"));
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
    fn parses_resume_command() -> TestResult {
        let options = ShellOptions::parse(["resume", "session-0"])?;

        assert_eq!(
            options.command,
            ShellCommand::Resume {
                session_id: "session-0".into(),
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
    fn client_sends_auth_token_to_real_tempod() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let auth = TempodAuth::bearer("secret-token")?;

        let opened = with_tempod_auth(&pool, auth, |addr| {
            ShellClient::new(addr.to_string())
                .with_auth_token("secret-token")
                .open("https://auth.test")
        })?;

        assert_eq!(opened.id.0, "session-0");
        assert_eq!(opened.url, "https://auth.test");
        Ok(())
    }

    #[test]
    fn client_uses_discovered_runtime_auth_token_to_real_tempod() -> TestResult {
        let pool = Arc::new(Mutex::new(SessionPool::default()));
        let auth = TempodAuth::bearer("runtime-token")?;

        let opened = with_tempod_auth(&pool, auth, |addr| {
            ShellClient::new_with_discovered_auth_token(
                addr.to_string(),
                Some("runtime-token".into()),
            )
            .open("https://runtime-auth.test")
        })?;

        assert_eq!(opened.id.0, "session-0");
        assert_eq!(opened.url, "https://runtime-auth.test");
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

        let resumed = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).resume(&opened.id.0)
        })?;
        assert_eq!(resumed.state, TempodSessionState::Running);
        let after_adopt = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).events(&opened.id.0, Some(1))
        })?;
        assert_eq!(after_adopt.len(), 1);
        assert_eq!(after_adopt[0].seq, 2);
        assert!(matches!(
            after_adopt[0].event,
            TempodSessionEventKind::SessionResumed
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

        assert!(
            matches!(err, ShellError::ResponseTooLarge { max_bytes: 64 }),
            "{err:?}"
        );
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("server thread failed".into()),
        }
        Ok(())
    }

    #[test]
    fn client_rejects_oversized_content_length_before_body_read() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 1024\r\nconnection: close\r\n\r\n",
            )?;
            let _ = done_rx.recv_timeout(Duration::from_secs(1));
            Ok(())
        });

        let err = match ShellClient::new(addr.to_string())
            .with_timeout(Duration::from_millis(200))
            .with_max_response_bytes(64)
            .health()
        {
            Ok(_) => return Err("advertised oversized response should be rejected".into()),
            Err(err) => err,
        };
        let _ = done_tx.send(());

        assert!(matches!(
            err,
            ShellError::ResponseTooLarge { max_bytes: 64 }
        ));
        match handle.join() {
            Ok(result) => result.map_err(|err| err.to_string())?,
            Err(_) => return Err("server thread failed".into()),
        }
        Ok(())
    }

    #[test]
    fn client_accepts_full_engine_host_sized_mcp_base64_screenshot_payload() -> TestResult {
        let raw_screenshot_len = ENGINE_HOST_MAX_SCREENSHOT_BYTES;
        let base64_len = raw_screenshot_len.div_ceil(3) * 4;
        let encoded = "A".repeat(base64_len);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "tempo-shell",
            "result": {
                "structuredContent": {
                    "mime_type": "image/png",
                    "encoding": "base64",
                    "set_of_marks": false,
                    "data": encoded,
                }
            }
        }))?;
        assert!(body.len() > DEFAULT_MAX_RESPONSE_BYTES);
        assert!(body.len() <= DEFAULT_MAX_MCP_RESPONSE_BYTES);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let expected_len = base64_len;
        let handle = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            write_fixture_response(&mut stream, header.as_bytes())?;
            write_fixture_response(&mut stream, &body)
        });

        let result = ShellClient::new(addr.to_string()).mcp_tool("screenshot", json!({}))?;

        assert_eq!(result["encoding"], "base64");
        assert_eq!(result["data"].as_str().map(str::len), Some(expected_len));
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("server thread failed".into()),
        }
        Ok(())
    }

    #[test]
    fn mcp_client_rejects_oversized_content_length_before_body_read() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let content_length = DEFAULT_MAX_MCP_RESPONSE_BYTES + 1;
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {content_length}\r\nconnection: close\r\n\r\n"
            );
            stream.write_all(header.as_bytes())?;
            let _ = done_rx.recv_timeout(Duration::from_secs(1));
            Ok(())
        });

        let err = match ShellClient::new(addr.to_string())
            .with_timeout(Duration::from_millis(200))
            .mcp_tool("screenshot", json!({}))
        {
            Ok(_) => return Err("advertised oversized MCP response should be rejected".into()),
            Err(err) => err,
        };
        let _ = done_tx.send(());

        assert!(matches!(
            err,
            ShellError::ResponseTooLarge {
                max_bytes: DEFAULT_MAX_MCP_RESPONSE_BYTES
            }
        ));
        match handle.join() {
            Ok(result) => result.map_err(|err| err.to_string())?,
            Err(_) => return Err("server thread failed".into()),
        }
        Ok(())
    }

    fn write_fixture_response(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), std::io::Error> {
        match stream.write_all(bytes) {
            Ok(()) => Ok(()),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
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
    fn adopt_resume_events_close_work_for_valid_session_id() -> TestResult {
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

        let resumed = with_tempod(&pool, |addr| {
            ShellClient::new(addr.to_string()).resume(&session_id)
        })?;
        assert_eq!(resumed.state, TempodSessionState::Running);

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

    fn with_tempod_auth<T, F>(
        pool: &Arc<Mutex<SessionPool>>,
        auth: TempodAuth,
        call: F,
    ) -> Result<T, Box<dyn Error>>
    where
        F: FnOnce(SocketAddr) -> Result<T, ShellError>,
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_pool = Arc::clone(pool);
        let handle = thread::spawn(move || serve_one_with_auth(listener, server_pool, auth));
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
            .attach_engine_driver(Engine::Cdp, EngineIpcClient::from_stream(client_stream))?;
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
