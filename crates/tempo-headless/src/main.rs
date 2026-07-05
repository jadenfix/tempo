use std::path::PathBuf;
use tempo_config::TempodConfig;
use tempo_driver::Engine;
use tempo_net::UrlPolicy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        eprintln!("{}", usage());
        std::process::exit(0);
    }
    let config_overrides = match TempodOptions::config_overrides(&args) {
        Ok(overrides) => overrides,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    // Layered configuration: built-in defaults < JSON file named by
    // TEMPO_CONFIG < TEMPO_* environment variables. The CLI flags parsed
    // below are the top layer and override whatever the layers produced.
    let layered = match TempodConfig::load_from_process_env_with_overrides(&config_overrides) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("tempod configuration error: {err}");
            std::process::exit(2);
        }
    };
    let options = match TempodOptions::parse(args, &layered) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let config = match options.server_config() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let privacy_mode = tempo_headless::privacy_mode_from_env();
    let effective_metrics_enabled = tempo_headless::configure_process_telemetry_for_privacy(
        privacy_mode,
        layered.telemetry.metrics_enabled,
    );
    if let Some(level) = tempo_telemetry::Level::parse(&layered.telemetry.log_level) {
        tempo_telemetry::logger().set_min_level(level);
    }
    let navigation_url_policy = options.navigation_url_policy();
    tempo_telemetry::logger()
        .event(tempo_telemetry::Level::Info, "tempod", "starting")
        .field("addr", options.addr.clone())
        .field("engine", format!("{:?}", options.engine))
        .field("attached_engine", options.engine_socket.is_some())
        .field("metrics_enabled", effective_metrics_enabled)
        .field("privacy_mode", format!("{privacy_mode:?}"))
        .field("allow_private_network", options.allow_private_network)
        .emit();

    let result = match options.engine_socket {
        Some(socket_path) => {
            tempo_headless::run_tempod_with_attached_driver_config_and_navigation_url_policy(
                &options.addr,
                config,
                options.engine,
                socket_path,
                navigation_url_policy,
            )
        }
        None => tempo_headless::run_tempod_with_config_and_navigation_url_policy(
            &options.addr,
            config,
            navigation_url_policy,
        ),
    };

    if let Err(err) = result {
        eprintln!("tempod failed: {err}");
        std::process::exit(1);
    }
}

struct TempodOptions {
    addr: String,
    engine: Engine,
    engine_socket: Option<PathBuf>,
    allow_remote: bool,
    allow_private_network: bool,
    auth_token: Option<String>,
}

impl TempodOptions {
    fn config_overrides(args: &[String]) -> Result<tempo_config::TempodConfigOverrides, String> {
        let mut overrides = tempo_config::TempodConfigOverrides::default();
        let mut args = args.iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--engine" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--engine requires cdp or servo".to_string())?;
                    overrides.engine = Some(match value.as_str() {
                        "cdp" => tempo_config::EngineKind::Cdp,
                        "servo" => tempo_config::EngineKind::Servo,
                        _ => {
                            return Err(format!(
                                "unknown engine: {value}\nRun tempod --help for usage."
                            ));
                        }
                    });
                }
                "--engine-socket" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--engine-socket requires a path".to_string())?;
                    overrides.engine_socket = Some(value.clone());
                }
                "--allow-remote" | "--allow-private-network" => {}
                "--auth-token" => {
                    args.next()
                        .ok_or_else(|| "--auth-token requires a bearer token".to_string())?;
                }
                "-h" | "--help" => {}
                value if value.starts_with('-') => {
                    return Err(format!(
                        "unknown tempod option: {value}\nRun tempod --help for usage."
                    ));
                }
                value => {
                    if overrides.bind_addr.replace(value.to_string()).is_some() {
                        return Err(format!("tempod accepts at most one address\n{}", usage()));
                    }
                }
            }
        }

        Ok(overrides)
    }

    fn parse(
        args: impl IntoIterator<Item = String>,
        defaults: &TempodConfig,
    ) -> Result<Self, String> {
        Self::parse_with_env(
            args,
            std::env::var(tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV).ok(),
            defaults,
        )
    }

    fn parse_with_env(
        args: impl IntoIterator<Item = String>,
        env_auth_token: Option<String>,
        defaults: &TempodConfig,
    ) -> Result<Self, String> {
        let mut addr = None;
        let mut engine = engine_from_config(defaults.engine);
        let mut engine_was_set = false;
        let mut engine_socket = defaults.engine_socket.clone().map(PathBuf::from);
        let mut allow_remote = false;
        let mut allow_private_network = false;
        let mut auth_token = env_auth_token.filter(|token| !token.is_empty());
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--engine" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--engine requires cdp or servo".to_string())?;
                    engine = parse_engine(&value)?;
                    engine_was_set = true;
                }
                "--engine-socket" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--engine-socket requires a path".to_string())?;
                    engine_socket = Some(PathBuf::from(value));
                }
                "--allow-remote" => {
                    allow_remote = true;
                }
                "--allow-private-network" => {
                    allow_private_network = true;
                }
                "--auth-token" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--auth-token requires a bearer token".to_string())?;
                    auth_token = Some(value);
                }
                "-h" | "--help" => return Err(usage()),
                value if value.starts_with('-') => {
                    return Err(format!(
                        "unknown tempod option: {value}\nRun tempod --help for usage."
                    ));
                }
                value => {
                    if addr.replace(value.to_string()).is_some() {
                        return Err(format!("tempod accepts at most one address\n{}", usage()));
                    }
                }
            }
        }

        if engine_socket.is_none() && engine_was_set {
            return Err(format!(
                "--engine only applies with --engine-socket; otherwise tempod starts without an attached engine\n{}",
                usage()
            ));
        }
        if engine_socket.is_none() && engine != Engine::Cdp {
            return Err(format!(
                "configured engine {} requires --engine-socket or {}\n{}",
                defaults.engine.as_str(),
                tempo_config::ENV_ENGINE_SOCKET,
                usage()
            ));
        }

        Ok(Self {
            addr: addr.unwrap_or_else(|| defaults.bind_addr.clone()),
            engine,
            engine_socket,
            allow_remote,
            allow_private_network,
            auth_token,
        })
    }

    fn navigation_url_policy(&self) -> UrlPolicy {
        if self.allow_private_network {
            UrlPolicy::allow_all()
        } else {
            UrlPolicy::block_private()
        }
    }

    fn server_config(&self) -> Result<tempo_headless::TempodServerConfig, String> {
        self.server_config_with_runtime_auth(|| {
            tempo_headless::load_or_create_tempod_runtime_auth_token().map(|runtime| runtime.token)
        })
    }

    fn server_config_with_runtime_auth(
        &self,
        runtime_auth_token: impl FnOnce() -> Result<String, tempo_headless::TempodError>,
    ) -> Result<tempo_headless::TempodServerConfig, String> {
        let mut config = tempo_headless::TempodServerConfig::new();
        if self.allow_remote {
            config = config.allow_remote_binds();
        }
        let token = match &self.auth_token {
            Some(token) => token.clone(),
            None => runtime_auth_token().map_err(|error| {
                format!(
                    "failed to load tempod runtime auth token: {error}\n{}",
                    usage()
                )
            })?,
        };
        config = config.with_auth(
            tempo_headless::TempodAuth::bearer(token)
                .map_err(|error| format!("invalid tempod auth token: {error}\n{}", usage()))?,
        );
        Ok(config)
    }
}

fn engine_from_config(engine: tempo_config::EngineKind) -> Engine {
    match engine {
        tempo_config::EngineKind::Cdp => Engine::Cdp,
        tempo_config::EngineKind::Servo => Engine::Servo,
    }
}

fn parse_engine(value: &str) -> Result<Engine, String> {
    match value {
        "cdp" => Ok(Engine::Cdp),
        "servo" => Ok(Engine::Servo),
        _ => Err(format!(
            "unknown engine: {value}\nRun tempod --help for usage."
        )),
    }
}

fn usage() -> String {
    format!(
        "usage: tempod [ADDR] [--engine cdp|servo] [--engine-socket PATH] [--allow-remote] [--auth-token TOKEN]\n\
         [--allow-private-network]\n\
         \n\
         layered config: defaults < JSON file named by {config_env} < TEMPO_* env < flags\n\
         tempod requires bearer auth even on loopback; without --auth-token or {env}, it creates/uses an owner-only runtime token file ({file_env})\n\
         non-loopback binds require --allow-remote plus bearer auth",
        config_env = tempo_config::ENV_CONFIG_PATH,
        env = tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV,
        file_env = tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_FILE_ENV,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_auth_options() -> Result<(), String> {
        let options = TempodOptions::parse_with_env(
            [
                "0.0.0.0:8787".to_string(),
                "--allow-remote".to_string(),
                "--auth-token".to_string(),
                "secret-token".to_string(),
            ],
            None,
            &TempodConfig::default(),
        )?;

        assert_eq!(options.addr, "0.0.0.0:8787");
        assert!(options.allow_remote);
        assert_eq!(options.auth_token.as_deref(), Some("secret-token"));
        Ok(())
    }

    #[test]
    fn auth_token_defaults_from_env() -> Result<(), String> {
        let options = TempodOptions::parse_with_env(
            std::iter::empty(),
            Some("env-token".into()),
            &TempodConfig::default(),
        )?;

        assert_eq!(options.auth_token.as_deref(), Some("env-token"));
        Ok(())
    }

    #[test]
    fn server_config_defaults_to_runtime_auth_token() -> Result<(), String> {
        let options = TempodOptions {
            addr: "127.0.0.1:8787".into(),
            engine: Engine::Cdp,
            engine_socket: None,
            allow_remote: true,
            allow_private_network: false,
            auth_token: None,
        };

        let config = options.server_config_with_runtime_auth(|| Ok("runtime-token".into()))?;
        assert!(config.auth_is_required());
        Ok(())
    }

    #[test]
    fn explicit_auth_token_overrides_runtime_auth_token() -> Result<(), String> {
        let options = TempodOptions {
            addr: "127.0.0.1:8787".into(),
            engine: Engine::Cdp,
            engine_socket: None,
            allow_remote: true,
            allow_private_network: false,
            auth_token: Some("cli-token".into()),
        };

        let config = options.server_config_with_runtime_auth(|| {
            Err(tempo_headless::TempodError::BadRequest(
                "runtime token should not be loaded".into(),
            ))
        })?;
        assert!(config.auth_is_required());
        Ok(())
    }

    #[test]
    fn layered_config_supplies_defaults_and_flags_override() -> Result<(), String> {
        let defaults = TempodConfig {
            bind_addr: "127.0.0.1:9999".to_string(),
            engine: tempo_config::EngineKind::Servo,
            engine_socket: Some("/tmp/config-engine.sock".to_string()),
            ..TempodConfig::default()
        };

        // No args: config supplies addr, engine, and socket.
        let options = TempodOptions::parse_with_env(std::iter::empty(), None, &defaults)?;
        assert_eq!(options.addr, "127.0.0.1:9999");
        assert_eq!(options.engine, Engine::Servo);
        assert_eq!(
            options.engine_socket,
            Some(PathBuf::from("/tmp/config-engine.sock"))
        );

        // Flags override the config layer.
        let options = TempodOptions::parse_with_env(
            [
                "127.0.0.1:1234".to_string(),
                "--engine".to_string(),
                "cdp".to_string(),
                "--engine-socket".to_string(),
                "/tmp/flag-engine.sock".to_string(),
            ],
            None,
            &defaults,
        )?;
        assert_eq!(options.addr, "127.0.0.1:1234");
        assert_eq!(options.engine, Engine::Cdp);
        assert_eq!(
            options.engine_socket,
            Some(PathBuf::from("/tmp/flag-engine.sock"))
        );
        Ok(())
    }

    #[test]
    fn cli_overrides_are_visible_before_config_validation() -> Result<(), String> {
        let overrides = TempodOptions::config_overrides(&[
            "127.0.0.1:1234".to_string(),
            "--engine".to_string(),
            "servo".to_string(),
            "--engine-socket".to_string(),
            "/tmp/flag-engine.sock".to_string(),
            "--allow-private-network".to_string(),
            "--auth-token".to_string(),
            "secret-token".to_string(),
        ])?;

        assert_eq!(overrides.bind_addr.as_deref(), Some("127.0.0.1:1234"));
        assert_eq!(overrides.engine, Some(tempo_config::EngineKind::Servo));
        assert_eq!(
            overrides.engine_socket.as_deref(),
            Some("/tmp/flag-engine.sock")
        );
        Ok(())
    }

    #[test]
    fn configured_engine_requires_engine_socket() {
        let defaults = TempodConfig {
            engine: tempo_config::EngineKind::Servo,
            ..TempodConfig::default()
        };
        let error = match TempodOptions::parse_with_env(std::iter::empty(), None, &defaults) {
            Ok(_) => panic!("configured servo without engine_socket should be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("configured engine servo requires"));
    }

    #[test]
    fn explicit_engine_requires_engine_socket() {
        let error = match TempodOptions::parse_with_env(
            ["--engine".to_string(), "servo".to_string()],
            None,
            &TempodConfig::default(),
        ) {
            Ok(_) => panic!("--engine without --engine-socket should be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("--engine only applies with --engine-socket"));
    }

    #[test]
    fn explicit_engine_with_socket_is_accepted() {
        let options = match TempodOptions::parse_with_env(
            [
                "--engine".to_string(),
                "servo".to_string(),
                "--engine-socket".to_string(),
                "/tmp/tempo-engine.sock".to_string(),
            ],
            None,
            &TempodConfig::default(),
        ) {
            Ok(options) => options,
            Err(error) => panic!("--engine with --engine-socket should parse: {error}"),
        };

        assert_eq!(options.engine, Engine::Servo);
        assert_eq!(
            options.engine_socket,
            Some(PathBuf::from("/tmp/tempo-engine.sock"))
        );
    }
}
