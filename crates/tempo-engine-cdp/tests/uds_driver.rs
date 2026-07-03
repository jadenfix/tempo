use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use tempo_driver::{BrowsingContextCreateOptions, BrowsingContextKind};
use tempo_engine_cdp::{CdpConfig, CdpTempoDriver};
use tempo_engine_host::{
    serve_driver_connection, DriverCommand, DriverResponse, EngineIpcClient, EngineIpcConnection,
};

#[tokio::test]
async fn cdp_driver_serves_commands_over_engine_host_uds() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping live CDP UDS test; TEMPO_CDP_CHROME is unset");
        return Ok(());
    };
    let url = serve_fixture()?;
    let (client_stream, server_stream) = UnixStream::pair()?;
    let client = tokio::task::spawn_blocking(
        move || -> Result<
            (
                DriverResponse,
                DriverResponse,
                DriverResponse,
                DriverResponse,
            ),
            tempo_engine_host::EngineHostError,
        > {
            let mut client = EngineIpcClient::from_stream(client_stream);
            let observed = client.request(DriverCommand::Goto { url })?;
            let created = client.request(DriverCommand::CreateBrowsingContext {
                options: BrowsingContextCreateOptions {
                    kind: BrowsingContextKind::Tab,
                    background: false,
                },
            })?;
            let DriverResponse::BrowsingContextCreated { driver_id } = created else {
                return Err(tempo_engine_host::EngineHostError::Io(
                    std::io::Error::other(format!("unexpected context response: {created:?}")),
                ));
            };
            let child_observed = client.request_for(Some(&driver_id), DriverCommand::Observe)?;
            let child_closed = client.request_for(Some(&driver_id), DriverCommand::Close)?;
            let closed = client.request(DriverCommand::Close)?;
            Ok((observed, child_observed, child_closed, closed))
        },
    );

    let config = CdpConfig::default().with_executable(chrome.to_string_lossy());
    let mut driver = CdpTempoDriver::launch_with(config)
        .await?
        .allow_private_network_access();
    let mut connection = EngineIpcConnection::from_stream(server_stream);
    serve_driver_connection(&mut connection, &mut driver).await?;
    let (observed, child_observed, child_closed, closed) = client.await??;

    match observed {
        DriverResponse::Observation { observation } => {
            assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
            assert!(observation.elements.iter().any(|element| {
                element.node_id == tempo_schema::NodeId("[id=\"save\"]".into())
            }));
        }
        other => return Err(format!("unexpected driver response: {other:?}").into()),
    }
    match child_observed {
        DriverResponse::Observation { observation } => {
            assert_eq!(observation.url, "about:blank");
            assert_eq!(observation.seq, 0);
        }
        other => return Err(format!("unexpected child driver response: {other:?}").into()),
    }
    assert_eq!(child_closed, DriverResponse::Closed);
    assert_eq!(closed, DriverResponse::Closed);
    Ok(())
}

fn serve_fixture() -> Result<String, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    std::thread::spawn(move || {
        let body = r#"<!doctype html>
            <html>
              <body>
                <button id="save">Save</button>
              </body>
            </html>"#;
        for stream in listener.incoming().take(16) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    Ok(format!("http://{addr}/"))
}
