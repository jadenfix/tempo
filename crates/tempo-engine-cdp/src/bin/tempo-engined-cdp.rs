use std::process::ExitCode;
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{
    serve_driver_connection, EngineIpcConnection, ENGINE_HOST_SOCKET_ENV, ENGINE_HOST_TOKEN_ENV,
};

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
    let allow_private_network = std::env::args()
        .skip(1)
        .any(|arg| arg == "--allow-private-network");
    let socket_path = std::env::var(ENGINE_HOST_SOCKET_ENV)
        .map_err(|_| format!("{ENGINE_HOST_SOCKET_ENV} is required"))?;
    let mut config = CdpConfig::default();
    if let Ok(chrome) = std::env::var(CDP_CHROME_ENV)
        && !chrome.trim().is_empty()
    {
        config = config.with_executable(chrome);
    }
    config = config.with_no_sandbox_env_opt_in();

    let mut driver = CdpTempoDriver::launch_with(config)
        .await
        .map_err(|error| error.to_string())?;
    if allow_private_network {
        driver = driver.allow_private_network_access();
    }
    let mut connection = match std::env::var(ENGINE_HOST_TOKEN_ENV) {
        Ok(token) => EngineIpcConnection::connect_authenticated(socket_path, &token)
            .map_err(|error| error.to_string())?,
        Err(_) => EngineIpcConnection::connect(socket_path).map_err(|error| error.to_string())?,
    };
    serve_driver_connection(&mut connection, &mut driver)
        .await
        .map_err(|error| error.to_string())
}
