use std::path::PathBuf;
use tempo_driver::Engine;

fn main() {
    let options = match TempodOptions::parse(std::env::args().skip(1)) {
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

    let result = match options.engine_socket {
        Some(socket_path) => tempo_headless::run_tempod_with_attached_driver_config(
            &options.addr,
            config,
            options.engine,
            socket_path,
        ),
        None => tempo_headless::run_tempod_with_config(&options.addr, config),
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
    auth_token: Option<String>,
}

impl TempodOptions {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        Self::parse_with_env(
            args,
            std::env::var(tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV).ok(),
        )
    }

    fn parse_with_env(
        args: impl IntoIterator<Item = String>,
        env_auth_token: Option<String>,
    ) -> Result<Self, String> {
        let mut addr = None;
        let mut engine = Engine::Cdp;
        let mut engine_was_set = false;
        let mut engine_socket = None;
        let mut allow_remote = false;
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
                "--auth-token" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--auth-token requires a bearer token".to_string())?;
                    auth_token = Some(value);
                }
                "-h" | "--help" => return Err(usage()),
                value if value.starts_with('-') => {
                    return Err(format!("unknown tempod option: {value}\n{}", usage()));
                }
                value => {
                    if addr.replace(value.to_string()).is_some() {
                        return Err(format!("tempod accepts at most one address\n{}", usage()));
                    }
                }
            }
        }

        if engine_was_set && engine_socket.is_none() {
            return Err(format!(
                "--engine only applies with --engine-socket; otherwise tempod starts without an attached engine\n{}",
                usage()
            ));
        }

        Ok(Self {
            addr: addr.unwrap_or_else(|| "127.0.0.1:8787".into()),
            engine,
            engine_socket,
            allow_remote,
            auth_token,
        })
    }

    fn server_config(&self) -> Result<tempo_headless::TempodServerConfig, String> {
        let mut config = tempo_headless::TempodServerConfig::new();
        if self.allow_remote {
            config = config.allow_remote_binds();
        }
        if let Some(token) = &self.auth_token {
            config = config.with_auth(
                tempo_headless::TempodAuth::bearer(token.clone())
                    .map_err(|error| format!("invalid tempod auth token: {error}\n{}", usage()))?,
            );
        }
        Ok(config)
    }
}

fn parse_engine(value: &str) -> Result<Engine, String> {
    match value {
        "cdp" => Ok(Engine::Cdp),
        "servo" => Ok(Engine::Servo),
        _ => Err(format!("unknown engine: {value}\n{}", usage())),
    }
}

fn usage() -> String {
    format!(
        "usage: tempod [ADDR] [--engine cdp|servo] [--engine-socket PATH] [--allow-remote] [--auth-token TOKEN]\n\
         \n\
         non-loopback binds require --allow-remote plus --auth-token TOKEN or {env}",
        env = tempo_headless::TEMPO_TEMPOD_AUTH_TOKEN_ENV,
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
        )?;

        assert_eq!(options.addr, "0.0.0.0:8787");
        assert!(options.allow_remote);
        assert_eq!(options.auth_token.as_deref(), Some("secret-token"));
        Ok(())
    }

    #[test]
    fn auth_token_defaults_from_env() -> Result<(), String> {
        let options = TempodOptions::parse_with_env(std::iter::empty(), Some("env-token".into()))?;

        assert_eq!(options.auth_token.as_deref(), Some("env-token"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_engine_requires_engine_socket() {
        let error = TempodOptions::parse(["--engine".to_string(), "servo".to_string()])
            .err()
            .expect("--engine without --engine-socket should be rejected");

        assert!(error.contains("--engine only applies with --engine-socket"));
    }

    #[test]
    fn explicit_engine_with_socket_is_accepted() {
        let options = TempodOptions::parse([
            "--engine".to_string(),
            "servo".to_string(),
            "--engine-socket".to_string(),
            "/tmp/tempo-engine.sock".to_string(),
        ])
        .expect("--engine with --engine-socket should parse");

        assert_eq!(options.engine, Engine::Servo);
        assert_eq!(
            options.engine_socket,
            Some(PathBuf::from("/tmp/tempo-engine.sock"))
        );
    }
}
