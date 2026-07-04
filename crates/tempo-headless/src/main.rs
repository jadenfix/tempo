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

    let result = match options.engine_socket {
        Some(socket_path) => tempo_headless::run_tempod_with_attached_driver(
            &options.addr,
            options.engine,
            socket_path,
        ),
        None => tempo_headless::run_tempod(&options.addr),
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
}

impl TempodOptions {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut addr = None;
        let mut engine = Engine::Cdp;
        let mut engine_was_set = false;
        let mut engine_socket = None;
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
        })
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
    "usage: tempod [ADDR] [--engine cdp|servo] [--engine-socket PATH]".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_engine_requires_engine_socket() -> Result<(), String> {
        let Err(error) = TempodOptions::parse(["--engine".to_string(), "servo".to_string()]) else {
            return Err("--engine without --engine-socket should be rejected".into());
        };

        assert!(error.contains("--engine only applies with --engine-socket"));
        Ok(())
    }

    #[test]
    fn explicit_engine_with_socket_is_accepted() -> Result<(), String> {
        let options = TempodOptions::parse([
            "--engine".to_string(),
            "servo".to_string(),
            "--engine-socket".to_string(),
            "/tmp/tempo-engine.sock".to_string(),
        ])?;

        assert_eq!(options.engine, Engine::Servo);
        assert_eq!(
            options.engine_socket,
            Some(PathBuf::from("/tmp/tempo-engine.sock"))
        );
        Ok(())
    }
}
