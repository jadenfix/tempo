//! tempo-config — layered, validated configuration for tempo binaries.
//!
//! Today tempod is configured through scattered positional args and ad-hoc
//! environment variables; a fleet operator has no config file, no single
//! documented surface, and no validation before bind time. This crate is the
//! canonical configuration layer:
//!
//! **Precedence (lowest → highest):** built-in defaults → JSON config file →
//! `TEMPO_*` environment variables. CLI flags, where a binary has them, apply
//! on top of the loaded [`TempodConfig`] so existing invocations keep working.
//!
//! The file format is JSON (the only serialization dependency this workspace
//! carries) with strict unknown-key rejection, so a typo fails loudly at
//! startup instead of silently running with defaults. Every environment
//! variable is a documented `ENV_*` constant here — this crate is the
//! registry, and the names match the strings the daemon already honors
//! (`TEMPO_OTLP_JSONL`, `TEMPO_STEALTH_MODE`, `TEMPO_LOG`).
//!
//! ```
//! use tempo_config::TempodConfig;
//!
//! let env = |key: &str| match key {
//!     "TEMPO_MAX_SESSIONS" => Some("8".to_string()),
//!     _ => None,
//! };
//! let config = TempodConfig::load_with(None, &env).unwrap_or_default();
//! assert_eq!(config.limits.max_sessions, 8);
//! assert_eq!(config.bind_addr, "127.0.0.1:8787");
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Path to a JSON config file; highest-priority way to point tempod at one.
pub const ENV_CONFIG_PATH: &str = "TEMPO_CONFIG";
/// Socket address tempod binds (`host:port`).
pub const ENV_BIND_ADDR: &str = "TEMPO_BIND_ADDR";
/// Engine lane: `cdp` or `servo`.
pub const ENV_ENGINE: &str = "TEMPO_ENGINE";
/// UDS path of a pre-started engine host.
pub const ENV_ENGINE_SOCKET: &str = "TEMPO_ENGINE_SOCKET";
/// JSONL file for OTLP step export (already honored by tempod).
pub const ENV_OTLP_JSONL: &str = "TEMPO_OTLP_JSONL";
/// Disables durable session events (already honored by tempod).
pub const ENV_STEALTH_MODE: &str = "TEMPO_STEALTH_MODE";
/// Minimum structured-log level (`trace|debug|info|warn|error`).
pub const ENV_LOG_LEVEL: &str = "TEMPO_LOG";
/// Maximum concurrent sessions the daemon admits.
pub const ENV_MAX_SESSIONS: &str = "TEMPO_MAX_SESSIONS";
/// Idle seconds after which a session is eligible for eviction.
pub const ENV_SESSION_IDLE_TIMEOUT_SECS: &str = "TEMPO_SESSION_IDLE_TIMEOUT_SECS";
/// Request/response body cap in bytes.
pub const ENV_MAX_BODY_BYTES: &str = "TEMPO_MAX_BODY_BYTES";
/// Enables/disables the Prometheus exposition endpoint.
pub const ENV_METRICS_ENABLED: &str = "TEMPO_METRICS";

const VALID_LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// Which rendering lane a session runs on by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    #[default]
    Cdp,
    Servo,
}

impl FromStr for EngineKind {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cdp" => Ok(EngineKind::Cdp),
            "servo" => Ok(EngineKind::Servo),
            _ => Err(ConfigError::InvalidEnvVar {
                var: ENV_ENGINE,
                value: value.to_string(),
                expected: "cdp | servo",
            }),
        }
    }
}

impl EngineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EngineKind::Cdp => "cdp",
            EngineKind::Servo => "servo",
        }
    }
}

/// Admission and payload limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum concurrent sessions admitted by the pool.
    pub max_sessions: u32,
    /// Seconds of inactivity before a session may be evicted.
    pub session_idle_timeout_secs: u64,
    /// HTTP request/response body cap in bytes (mirrors tempod's 64 KiB cap).
    pub max_body_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            session_idle_timeout_secs: 900,
            max_body_bytes: 64 * 1024,
        }
    }
}

/// Observability toggles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Serve Prometheus exposition from the daemon.
    pub metrics_enabled: bool,
    /// Minimum structured-log level: trace | debug | info | warn | error.
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            log_level: "info".to_string(),
        }
    }
}

/// Full tempod configuration after layering defaults, file, and environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TempodConfig {
    /// Socket address the daemon binds.
    pub bind_addr: String,
    /// Default engine lane for new sessions.
    pub engine: EngineKind,
    /// UDS path of a pre-started engine host, if any.
    pub engine_socket: Option<String>,
    /// JSONL path for OTLP step export, if enabled.
    pub otlp_jsonl_path: Option<String>,
    /// Disable durable session events.
    pub stealth_mode: bool,
    pub limits: LimitsConfig,
    pub telemetry: TelemetryConfig,
}

impl Default for TempodConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8787".to_string(),
            engine: EngineKind::default(),
            engine_socket: None,
            otlp_jsonl_path: None,
            stealth_mode: false,
            limits: LimitsConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl TempodConfig {
    /// Loads from the real process environment. The config file is taken from
    /// `TEMPO_CONFIG` when set.
    pub fn load_from_process_env() -> Result<Self, ConfigError> {
        let env = |key: &str| std::env::var(key).ok();
        let file_path = env(ENV_CONFIG_PATH);
        Self::load_with(file_path.as_deref().map(Path::new), &env)
    }

    /// Loads with an injected environment lookup (testable, hermetic).
    /// Layering: defaults → `file` (when provided) → `env`.
    pub fn load_with(
        file: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let mut config = match file {
            Some(path) => Self::from_file(path)?,
            None => Self::default(),
        };
        config.apply_env(env)?;
        config.validate()?;
        Ok(config)
    }

    /// Parses a JSON config file over the defaults. Unknown keys are errors.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ConfigError::ParseFile {
            path: path.display().to_string(),
            source,
        })
    }

    fn apply_env(&mut self, env: &dyn Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        if let Some(value) = env(ENV_BIND_ADDR) {
            self.bind_addr = value;
        }
        if let Some(value) = env(ENV_ENGINE) {
            self.engine = value.parse()?;
        }
        if let Some(value) = env(ENV_ENGINE_SOCKET) {
            self.engine_socket = Some(value);
        }
        if let Some(value) = env(ENV_OTLP_JSONL) {
            self.otlp_jsonl_path = Some(value);
        }
        if let Some(value) = env(ENV_STEALTH_MODE) {
            self.stealth_mode = parse_bool(ENV_STEALTH_MODE, &value)?;
        }
        if let Some(value) = env(ENV_MAX_SESSIONS) {
            self.limits.max_sessions = parse_number(ENV_MAX_SESSIONS, &value)?;
        }
        if let Some(value) = env(ENV_SESSION_IDLE_TIMEOUT_SECS) {
            self.limits.session_idle_timeout_secs =
                parse_number(ENV_SESSION_IDLE_TIMEOUT_SECS, &value)?;
        }
        if let Some(value) = env(ENV_MAX_BODY_BYTES) {
            self.limits.max_body_bytes = parse_number(ENV_MAX_BODY_BYTES, &value)?;
        }
        if let Some(value) = env(ENV_METRICS_ENABLED) {
            self.telemetry.metrics_enabled = parse_bool(ENV_METRICS_ENABLED, &value)?;
        }
        if let Some(value) = env(ENV_LOG_LEVEL) {
            self.telemetry.log_level = value.trim().to_ascii_lowercase();
        }
        Ok(())
    }

    /// Structural validation with actionable messages; run after layering.
    pub fn validate(&self) -> Result<(), ConfigError> {
        SocketAddr::from_str(&self.bind_addr).map_err(|_| ConfigError::InvalidField {
            field: "bind_addr",
            reason: format!(
                "`{}` is not a socket address (expected host:port, e.g. 127.0.0.1:8787)",
                self.bind_addr
            ),
        })?;
        if self.limits.max_sessions == 0 {
            return Err(ConfigError::InvalidField {
                field: "limits.max_sessions",
                reason: "must be at least 1".to_string(),
            });
        }
        if self.limits.session_idle_timeout_secs == 0 {
            return Err(ConfigError::InvalidField {
                field: "limits.session_idle_timeout_secs",
                reason: "must be at least 1 second".to_string(),
            });
        }
        if self.limits.max_body_bytes < 1024 {
            return Err(ConfigError::InvalidField {
                field: "limits.max_body_bytes",
                reason: "must be at least 1024 bytes".to_string(),
            });
        }
        if !VALID_LOG_LEVELS.contains(&self.telemetry.log_level.as_str()) {
            return Err(ConfigError::InvalidField {
                field: "telemetry.log_level",
                reason: format!(
                    "`{}` is not one of trace|debug|info|warn|error",
                    self.telemetry.log_level
                ),
            });
        }
        if let Some(socket) = &self.engine_socket
            && socket.trim().is_empty()
        {
            return Err(ConfigError::InvalidField {
                field: "engine_socket",
                reason: "must be a non-empty path when set".to_string(),
            });
        }
        Ok(())
    }

    /// The parsed bind address; call after [`validate`](Self::validate).
    pub fn bind_socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        SocketAddr::from_str(&self.bind_addr).map_err(|_| ConfigError::InvalidField {
            field: "bind_addr",
            reason: format!("`{}` is not a socket address", self.bind_addr),
        })
    }

    /// Pretty JSON of the effective config — startup logging / `--print-config`.
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Every environment variable this crate honors, for docs and `--help`.
    pub fn env_vars() -> BTreeSet<&'static str> {
        BTreeSet::from([
            ENV_CONFIG_PATH,
            ENV_BIND_ADDR,
            ENV_ENGINE,
            ENV_ENGINE_SOCKET,
            ENV_OTLP_JSONL,
            ENV_STEALTH_MODE,
            ENV_LOG_LEVEL,
            ENV_MAX_SESSIONS,
            ENV_SESSION_IDLE_TIMEOUT_SECS,
            ENV_MAX_BODY_BYTES,
            ENV_METRICS_ENABLED,
        ])
    }
}

fn parse_bool(var: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidEnvVar {
            var,
            value: value.to_string(),
            expected: "1|true|yes|on or 0|false|no|off",
        }),
    }
}

fn parse_number<T: FromStr>(var: &'static str, value: &str) -> Result<T, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidEnvVar {
            var,
            value: value.to_string(),
            expected: "a non-negative integer",
        })
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse config file {path}: {source}")]
    ParseFile {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid {var}={value} (expected {expected})")]
    InvalidEnvVar {
        var: &'static str,
        value: String,
        expected: &'static str,
    },
    #[error("invalid config field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write;

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: BTreeMap<&str, &str> = pairs.iter().copied().collect();
        move |key: &str| map.get(key).map(|v| (*v).to_string())
    }

    fn write_config(json: &str) -> Result<tempfile::NamedTempFile, std::io::Error> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(json.as_bytes())?;
        Ok(file)
    }

    #[test]
    fn defaults_are_valid_and_loopback() -> Result<(), ConfigError> {
        let config = TempodConfig::load_with(None, &no_env)?;
        assert_eq!(config.bind_addr, "127.0.0.1:8787");
        assert_eq!(config.engine, EngineKind::Cdp);
        assert_eq!(config.limits.max_sessions, 64);
        assert_eq!(config.limits.max_body_bytes, 65536);
        assert!(config.telemetry.metrics_enabled);
        assert!(config.bind_socket_addr()?.ip().is_loopback());
        Ok(())
    }

    #[test]
    fn partial_file_overlays_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let file = write_config(
            r#"{ "engine": "servo", "limits": { "max_sessions": 4 }, "stealth_mode": true }"#,
        )?;
        let config = TempodConfig::load_with(Some(file.path()), &no_env)?;
        assert_eq!(config.engine, EngineKind::Servo);
        assert_eq!(config.limits.max_sessions, 4);
        assert!(config.stealth_mode);
        // Untouched fields keep their defaults.
        assert_eq!(config.bind_addr, "127.0.0.1:8787");
        assert_eq!(config.limits.session_idle_timeout_secs, 900);
        Ok(())
    }

    #[test]
    fn env_overrides_file() -> Result<(), Box<dyn std::error::Error>> {
        let file = write_config(r#"{ "limits": { "max_sessions": 4 }, "engine": "servo" }"#)?;
        let env = env_of(&[
            (ENV_MAX_SESSIONS, "9"),
            (ENV_ENGINE, "cdp"),
            (ENV_BIND_ADDR, "0.0.0.0:9000"),
            (ENV_STEALTH_MODE, "on"),
            (ENV_METRICS_ENABLED, "off"),
            (ENV_LOG_LEVEL, "DEBUG"),
            (ENV_OTLP_JSONL, "/tmp/otlp.jsonl"),
        ]);
        let config = TempodConfig::load_with(Some(file.path()), &env)?;
        assert_eq!(config.limits.max_sessions, 9);
        assert_eq!(config.engine, EngineKind::Cdp);
        assert_eq!(config.bind_addr, "0.0.0.0:9000");
        assert!(config.stealth_mode);
        assert!(!config.telemetry.metrics_enabled);
        assert_eq!(config.telemetry.log_level, "debug");
        assert_eq!(config.otlp_jsonl_path.as_deref(), Some("/tmp/otlp.jsonl"));
        Ok(())
    }

    #[test]
    fn unknown_file_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let file = write_config(r#"{ "bind_adr": "127.0.0.1:1" }"#)?;
        let error = TempodConfig::load_with(Some(file.path()), &no_env);
        match error {
            Err(ConfigError::ParseFile { .. }) => Ok(()),
            other => panic!("expected ParseFile error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_env_names_the_variable() {
        let env = env_of(&[(ENV_MAX_SESSIONS, "lots")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidEnvVar { var, .. }) => assert_eq!(var, ENV_MAX_SESSIONS),
            other => panic!("expected InvalidEnvVar, got {other:?}"),
        }
        let env = env_of(&[(ENV_STEALTH_MODE, "maybe")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidEnvVar { var, .. }) => assert_eq!(var, ENV_STEALTH_MODE),
            other => panic!("expected InvalidEnvVar, got {other:?}"),
        }
        let env = env_of(&[(ENV_ENGINE, "chrome")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidEnvVar { var, .. }) => assert_eq!(var, ENV_ENGINE),
            other => panic!("expected InvalidEnvVar, got {other:?}"),
        }
    }

    #[test]
    fn validation_rejects_bad_values() {
        let env = env_of(&[(ENV_BIND_ADDR, "not-an-addr")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => assert_eq!(field, "bind_addr"),
            other => panic!("expected InvalidField(bind_addr), got {other:?}"),
        }
        let env = env_of(&[(ENV_MAX_SESSIONS, "0")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => {
                assert_eq!(field, "limits.max_sessions");
            }
            other => panic!("expected InvalidField(max_sessions), got {other:?}"),
        }
        let env = env_of(&[(ENV_LOG_LEVEL, "loud")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => {
                assert_eq!(field, "telemetry.log_level");
            }
            other => panic!("expected InvalidField(log_level), got {other:?}"),
        }
        let env = env_of(&[(ENV_MAX_BODY_BYTES, "10")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => {
                assert_eq!(field, "limits.max_body_bytes");
            }
            other => panic!("expected InvalidField(max_body_bytes), got {other:?}"),
        }
    }

    #[test]
    fn bool_parsing_accepts_common_spellings() -> Result<(), ConfigError> {
        for (spelling, expected) in [
            ("1", true),
            ("TRUE", true),
            ("Yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("NO", false),
            ("off", false),
        ] {
            assert_eq!(parse_bool(ENV_STEALTH_MODE, spelling)?, expected);
        }
        Ok(())
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let missing = Path::new("/nonexistent/tempo-config-test.json");
        match TempodConfig::load_with(Some(missing), &no_env) {
            Err(ConfigError::ReadFile { .. }) => {}
            other => panic!("expected ReadFile error, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_through_pretty_json() -> Result<(), Box<dyn std::error::Error>> {
        let config = TempodConfig {
            engine: EngineKind::Servo,
            limits: LimitsConfig {
                max_sessions: 3,
                ..LimitsConfig::default()
            },
            ..TempodConfig::default()
        };
        let json = config.to_pretty_json();
        let reparsed: TempodConfig = serde_json::from_str(&json)?;
        assert_eq!(reparsed, config);
        Ok(())
    }

    #[test]
    fn env_var_registry_is_complete() {
        let vars = TempodConfig::env_vars();
        assert!(vars.contains(ENV_CONFIG_PATH));
        assert!(vars.contains(ENV_OTLP_JSONL));
        assert!(vars.contains(ENV_STEALTH_MODE));
        assert_eq!(vars.len(), 11);
    }
}
