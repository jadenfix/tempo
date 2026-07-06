//! tempo-config — layered, validated configuration for tempo binaries.
//!
//! Today tempod startup is configured through scattered positional args and
//! ad-hoc environment variables; a fleet operator has no config file, no
//! single documented surface for those startup knobs, and no validation before
//! bind time. This crate is the layered configuration layer for the tempod
//! fields it actually applies:
//!
//! **Precedence (lowest → highest):** built-in defaults → JSON config file →
//! `TEMPO_*` environment variables. CLI flags, where a binary has them, apply
//! on top of the loaded [`TempodConfig`] so existing invocations keep working.
//!
//! The file format is JSON (the only serialization dependency this workspace
//! carries) with strict unknown-key rejection, so a typo fails loudly at
//! startup instead of silently running with defaults. Every environment
//! variable layered by this crate is a documented `ENV_*` constant here. Env
//! knobs owned by lower-level crates stay there until tempod consumes them
//! through [`TempodConfig`]. See [`documented_env_registry`] for the full
//! cross-crate `TEMPO_*` surface operators may set at startup.
//!
//! ```
//! use tempo_config::TempodConfig;
//!
//! # fn main() -> Result<(), tempo_config::ConfigError> {
//! let env = |key: &str| match key {
//!     "TEMPO_METRICS" => Some("off".to_string()),
//!     _ => None,
//! };
//! // Propagate errors — a misconfiguration should stop startup, not be
//! // silently replaced with defaults.
//! let config = TempodConfig::load_with(None, &env)?;
//! assert!(!config.telemetry.metrics_enabled);
//! assert_eq!(config.bind_addr, "127.0.0.1:8787");
//! # Ok(())
//! # }
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
/// Minimum structured-log level (`trace|debug|info|warn|error`).
pub const ENV_LOG_LEVEL: &str = "TEMPO_LOG";
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
    pub telemetry: TelemetryConfig,
}

/// CLI values that should be applied after file/env config and validated with
/// the final effective configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TempodConfigOverrides {
    pub bind_addr: Option<String>,
    pub engine: Option<EngineKind>,
    pub engine_socket: Option<String>,
}

impl Default for TempodConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8787".to_string(),
            engine: EngineKind::default(),
            engine_socket: None,
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

    /// Loads from the real process environment, then applies CLI overrides
    /// before final validation.
    pub fn load_from_process_env_with_overrides(
        overrides: &TempodConfigOverrides,
    ) -> Result<Self, ConfigError> {
        let env = |key: &str| std::env::var(key).ok();
        let file_path = env(ENV_CONFIG_PATH);
        Self::load_with_overrides(file_path.as_deref().map(Path::new), &env, overrides)
    }

    /// Loads with an injected environment lookup (testable, hermetic).
    /// Layering: defaults → `file` (when provided) → `env`.
    pub fn load_with(
        file: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        Self::load_with_overrides(file, env, &TempodConfigOverrides::default())
    }

    /// Loads with explicit top-layer overrides. CLI callers use this so a
    /// lower-precedence env value cannot fail validation before the CLI value
    /// that replaces it has been applied.
    pub fn load_with_overrides(
        file: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
        overrides: &TempodConfigOverrides,
    ) -> Result<Self, ConfigError> {
        let mut config = match file {
            Some(path) => Self::from_file(path)?,
            None => Self::default(),
        };
        config.apply_env(env, overrides)?;
        config.apply_overrides(overrides);
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

    fn apply_env(
        &mut self,
        env: &dyn Fn(&str) -> Option<String>,
        overrides: &TempodConfigOverrides,
    ) -> Result<(), ConfigError> {
        if overrides.bind_addr.is_none()
            && let Some(value) = env(ENV_BIND_ADDR)
        {
            self.bind_addr = value;
        }
        if overrides.engine.is_none()
            && let Some(value) = env(ENV_ENGINE)
        {
            self.engine = value.parse()?;
        }
        if overrides.engine_socket.is_none()
            && let Some(value) = env(ENV_ENGINE_SOCKET)
        {
            self.engine_socket = Some(value);
        }
        if let Some(value) = env(ENV_METRICS_ENABLED) {
            self.telemetry.metrics_enabled = parse_bool(ENV_METRICS_ENABLED, &value)?;
        }
        if let Some(value) = env(ENV_LOG_LEVEL) {
            let level = value.trim().to_ascii_lowercase();
            // The logger itself accepts "warning" as an alias; normalize so
            // validation and the logger agree.
            self.telemetry.log_level = if level == "warning" {
                "warn".to_string()
            } else {
                level
            };
        }
        Ok(())
    }

    fn apply_overrides(&mut self, overrides: &TempodConfigOverrides) {
        if let Some(bind_addr) = &overrides.bind_addr {
            self.bind_addr = bind_addr.clone();
        }
        if let Some(engine) = overrides.engine {
            self.engine = engine;
        }
        if let Some(engine_socket) = &overrides.engine_socket {
            self.engine_socket = Some(engine_socket.clone());
        }
    }

    /// Structural validation with actionable messages; run after layering.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.bind_socket_addr()?;
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
        if self.engine == EngineKind::Servo && self.engine_socket.is_none() {
            return Err(ConfigError::InvalidField {
                field: "engine_socket",
                reason: "must be set when engine is servo".to_string(),
            });
        }
        Ok(())
    }

    /// The parsed bind address. Accepts a literal socket address first and
    /// falls back to `host:port` resolution so `localhost:8787` — which
    /// `TcpListener::bind` accepts today — keeps working when wired.
    pub fn bind_socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        if let Ok(addr) = SocketAddr::from_str(&self.bind_addr) {
            return Ok(addr);
        }
        use std::net::ToSocketAddrs;
        self.bind_addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| ConfigError::InvalidField {
                field: "bind_addr",
                reason: format!(
                    "`{}` is not a socket address (expected host:port, e.g. 127.0.0.1:8787)",
                    self.bind_addr
                ),
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
            ENV_LOG_LEVEL,
            ENV_METRICS_ENABLED,
        ])
    }
}

/// Cross-crate `TEMPO_*` registry for operators and docs. Tuple is
/// `(variable, owning crate, purpose)`. Parsing may live in the owning crate;
/// this list is documentation-only.
pub fn documented_env_registry() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        (ENV_CONFIG_PATH, "tempo-config", "JSON config file path"),
        (ENV_BIND_ADDR, "tempo-config", "tempod listen address"),
        (ENV_ENGINE, "tempo-config", "engine kind: cdp or servo"),
        (ENV_ENGINE_SOCKET, "tempo-config", "UDS path to engine host"),
        (ENV_LOG_LEVEL, "tempo-config", "log level"),
        (ENV_METRICS_ENABLED, "tempo-config", "metrics on/off"),
        (
            "TEMPO_TEMPOD_AUTH_TOKEN",
            "tempo-headless",
            "bearer token for tempod",
        ),
        (
            "TEMPO_TEMPOD_AUTH_TOKEN_FILE",
            "tempo-headless",
            "owner-only runtime token file",
        ),
        (
            "TEMPO_STEALTH_MODE",
            "tempo-headless / tempo-session",
            "privacy mode; suppresses durable state",
        ),
        (
            "TEMPO_OTLP_ENDPOINT",
            "tempo-headless",
            "OTLP/HTTP trace export endpoint",
        ),
        (
            "TEMPO_OTLP_JSONL",
            "tempo-headless",
            "JSONL trace export fallback path",
        ),
        (
            "TEMPO_ENGINE_HOST_SOCKET",
            "tempo-engine-host",
            "engine daemon UDS path",
        ),
        (
            "TEMPO_ENGINE_HOST_TOKEN",
            "tempo-engine-host",
            "engine IPC auth token",
        ),
        (
            "TEMPO_CDP_CHROME",
            "tempo-engine-cdp",
            "Chrome/Chromium binary path",
        ),
        (
            "TEMPO_CDP_NO_SANDBOX",
            "tempo-engine-cdp",
            "opt-in no-sandbox (CI only)",
        ),
        (
            "TEMPO_DURABLE_RETENTION",
            "tempo-session",
            "cassette/journal retention policy",
        ),
        (
            "TEMPO_DURABLE_ENCRYPTION_KEY_HEX",
            "tempo-session",
            "AEAD key for encrypted retention",
        ),
        (
            "TEMPO_LIVE_MODEL",
            "tempo-agent",
            "opt-in live LLM tests (=1)",
        ),
    ]
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
    use std::collections::{BTreeMap, BTreeSet};
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
    fn documented_env_registry_includes_config_vars() {
        let names: BTreeSet<_> = documented_env_registry()
            .iter()
            .map(|(name, _, _)| *name)
            .collect();
        for var in TempodConfig::env_vars() {
            assert!(names.contains(var), "registry missing {var}");
        }
        assert!(
            documented_env_registry().len() >= 17,
            "registry should list tempo-config plus cross-crate runtime vars"
        );
        assert!(names.contains("TEMPO_TEMPOD_AUTH_TOKEN"));
        assert!(names.contains("TEMPO_CDP_CHROME"));
    }

    #[test]
    fn environment_docs_cover_registered_tempo_vars() {
        let docs = include_str!("../../../docs/ENVIRONMENT.md");
        for (var, _, _) in documented_env_registry() {
            assert!(docs.contains(var), "docs/ENVIRONMENT.md is missing {var}");
        }
    }

    #[test]
    fn defaults_are_valid_and_loopback() -> Result<(), ConfigError> {
        let config = TempodConfig::load_with(None, &no_env)?;
        assert_eq!(config.bind_addr, "127.0.0.1:8787");
        assert_eq!(config.engine, EngineKind::Cdp);
        assert!(config.telemetry.metrics_enabled);
        assert!(config.bind_socket_addr()?.ip().is_loopback());
        Ok(())
    }

    #[test]
    fn partial_file_overlays_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let file = write_config(
            r#"{ "engine": "servo", "engine_socket": "/tmp/tempo-engine.sock", "telemetry": { "metrics_enabled": false, "log_level": "debug" } }"#,
        )?;
        let config = TempodConfig::load_with(Some(file.path()), &no_env)?;
        assert_eq!(config.engine, EngineKind::Servo);
        assert_eq!(
            config.engine_socket.as_deref(),
            Some("/tmp/tempo-engine.sock")
        );
        assert!(!config.telemetry.metrics_enabled);
        assert_eq!(config.telemetry.log_level, "debug");
        // Untouched fields keep their defaults.
        assert_eq!(config.bind_addr, "127.0.0.1:8787");
        Ok(())
    }

    #[test]
    fn env_overrides_file() -> Result<(), Box<dyn std::error::Error>> {
        let file = write_config(
            r#"{ "engine": "servo", "engine_socket": "/tmp/file.sock", "telemetry": { "metrics_enabled": true, "log_level": "warn" } }"#,
        )?;
        let env = env_of(&[
            (ENV_ENGINE, "cdp"),
            (ENV_ENGINE_SOCKET, "/tmp/env.sock"),
            (ENV_BIND_ADDR, "0.0.0.0:9000"),
            (ENV_METRICS_ENABLED, "off"),
            (ENV_LOG_LEVEL, "DEBUG"),
        ]);
        let config = TempodConfig::load_with(Some(file.path()), &env)?;
        assert_eq!(config.engine, EngineKind::Cdp);
        assert_eq!(config.engine_socket.as_deref(), Some("/tmp/env.sock"));
        assert_eq!(config.bind_addr, "0.0.0.0:9000");
        assert!(!config.telemetry.metrics_enabled);
        assert_eq!(config.telemetry.log_level, "debug");
        Ok(())
    }

    #[test]
    fn overrides_apply_before_env_validation() -> Result<(), Box<dyn std::error::Error>> {
        let env = env_of(&[
            (ENV_BIND_ADDR, "not-an-addr"),
            (ENV_ENGINE, "chrome"),
            (ENV_ENGINE_SOCKET, ""),
        ]);
        let overrides = TempodConfigOverrides {
            bind_addr: Some("127.0.0.1:8787".to_string()),
            engine: Some(EngineKind::Servo),
            engine_socket: Some("/tmp/tempo-engine.sock".to_string()),
        };

        let config = TempodConfig::load_with_overrides(None, &env, &overrides)?;
        assert_eq!(config.bind_addr, "127.0.0.1:8787");
        assert_eq!(config.engine, EngineKind::Servo);
        assert_eq!(
            config.engine_socket.as_deref(),
            Some("/tmp/tempo-engine.sock")
        );
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
    fn unsupported_operational_file_keys_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        for json in [
            r#"{ "limits": { "max_sessions": 4 } }"#,
            r#"{ "stealth_mode": true }"#,
            r#"{ "otlp_jsonl_path": "/tmp/otlp.jsonl" }"#,
        ] {
            let file = write_config(json)?;
            let error = TempodConfig::load_with(Some(file.path()), &no_env);
            match error {
                Err(ConfigError::ParseFile { .. }) => {}
                other => panic!("expected ParseFile error for {json}, got {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_env_names_the_variable() {
        let env = env_of(&[(ENV_METRICS_ENABLED, "maybe")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidEnvVar { var, .. }) => assert_eq!(var, ENV_METRICS_ENABLED),
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
        let env = env_of(&[(ENV_LOG_LEVEL, "loud")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => {
                assert_eq!(field, "telemetry.log_level");
            }
            other => panic!("expected InvalidField(log_level), got {other:?}"),
        }
        let env = env_of(&[(ENV_ENGINE, "servo")]);
        match TempodConfig::load_with(None, &env) {
            Err(ConfigError::InvalidField { field, .. }) => {
                assert_eq!(field, "engine_socket");
            }
            other => panic!("expected InvalidField(engine_socket), got {other:?}"),
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
            assert_eq!(parse_bool(ENV_METRICS_ENABLED, spelling)?, expected);
        }
        Ok(())
    }

    #[test]
    fn log_level_warning_alias_normalizes_to_warn() -> Result<(), ConfigError> {
        let env = env_of(&[(ENV_LOG_LEVEL, "WARNING")]);
        let config = TempodConfig::load_with(None, &env)?;
        assert_eq!(config.telemetry.log_level, "warn");
        Ok(())
    }

    #[test]
    fn bind_addr_accepts_resolvable_host_port() -> Result<(), ConfigError> {
        // TcpListener::bind accepts `localhost:port` today; the config layer
        // must not regress that when wired into tempod.
        let env = env_of(&[(ENV_BIND_ADDR, "localhost:8787")]);
        let config = TempodConfig::load_with(None, &env)?;
        assert!(config.bind_socket_addr()?.ip().is_loopback());
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
            engine_socket: Some("/tmp/tempo-engine.sock".to_string()),
            telemetry: TelemetryConfig {
                metrics_enabled: false,
                ..TelemetryConfig::default()
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
        assert!(vars.contains(ENV_METRICS_ENABLED));
        assert_eq!(vars.len(), 6);
    }
}
