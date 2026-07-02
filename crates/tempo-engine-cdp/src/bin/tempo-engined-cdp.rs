use std::process::ExitCode;
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{serve_driver_connection, EngineIpcConnection, ENGINE_HOST_SOCKET_ENV};

const CDP_CHROME_ENV: &str = "TEMPO_CDP_CHROME";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let socket_path = std::env::var(ENGINE_HOST_SOCKET_ENV)
        .map_err(|_| format!("{ENGINE_HOST_SOCKET_ENV} is required"))?;
    let mut config = CdpConfig::default();
    if let Ok(chrome) = std::env::var(CDP_CHROME_ENV) {
        if !chrome.trim().is_empty() {
            config = config.with_executable(chrome);
        }
    }

    let mut driver = CdpTempoDriver::launch_with(config)
        .await
        .map_err(|error| error.to_string())?;
    let connection =
        EngineIpcConnection::connect(socket_path).map_err(|error| error.to_string())?;
    serve_driver_connection(connection, &mut driver)
        .await
        .map_err(|error| error.to_string())
}
