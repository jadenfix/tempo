//! tempo-shell - loopback shell client for human-visible tempo sessions.
//!
//! The GUI chrome will sit above this crate. This layer is already real: it
//! speaks tempod's HTTP control API over TCP, opens/adopts/closes sessions, and
//! renders session state against the live daemon protocol.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tempo_headless::{TempodSession, TempodSessionId};
use thiserror::Error;

pub const DEFAULT_TEMPOD_ADDR: &str = "127.0.0.1:8787";

const USAGE: &str = "\
tempo-shell

Commands:
  health
  sessions
  open URL
  adopt SESSION_ID
  close SESSION_ID
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
    Open { url: String },
    Adopt { session_id: String },
    Close { session_id: String },
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
            Self::Close { session_id } => write_json(stdout, &client.close(session_id)?),
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
}

impl ShellClient {
    pub fn new(tempod_addr: impl Into<String>) -> Self {
        Self {
            tempod_addr: tempod_addr.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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

    pub fn close(&self, session_id: &str) -> Result<TempodSession, ShellError> {
        let path = format!("/sessions/{}", safe_path_segment(session_id)?);
        self.request_json("DELETE", &path, None::<serde_json::Value>)
    }

    pub fn drain(&self) -> Result<DrainResponse, ShellError> {
        self.request_json("POST", "/drain", None::<serde_json::Value>)
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
        stream.read_to_end(&mut bytes)?;
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
        "close" => one_arg(rest, "close SESSION_ID", |session_id| ShellCommand::Close {
            session_id,
        }),
        "drain" => no_args(rest, ShellCommand::Drain),
        "-h" | "--help" | "help" => Ok(ShellCommand::Help),
        other => Err(ShellError::Usage(format!(
            "unknown command: {other}\n\n{USAGE}"
        ))),
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
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| ShellError::Protocol("missing HTTP status".into()))?
        .parse()
        .map_err(|err: std::num::ParseIntError| ShellError::Protocol(err.to_string()))?;
    Ok(HttpResponse {
        status,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn safe_path_segment(segment: &str) -> Result<&str, ShellError> {
    if segment.is_empty() || segment.contains('/') || segment.contains('\\') {
        Err(ShellError::Usage(format!("invalid session id: {segment}")))
    } else {
        Ok(segment)
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
    #[error("invalid tempod HTTP response: {0}")]
    Protocol(String),
}

impl ShellError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Io(_) | Self::Json(_) | Self::Http { .. } | Self::Protocol(_) => 1,
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
    use std::error::Error;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempo_headless::{serve_one, SessionPool, TempodError, TempodSessionState};

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
    fn rejects_unsafe_session_path_segments() {
        assert!(matches!(
            safe_path_segment("../session"),
            Err(ShellError::Usage(_))
        ));
        assert!(matches!(safe_path_segment(""), Err(ShellError::Usage(_))));
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
}
