use serde_json::Value;
use std::error::Error;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempo_session::{read_journal_entries, JournalEvent};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn run_decided_task_binary_drives_live_cdp_with_scripted_decider() -> TestResult {
    let Some(chrome) = std::env::var_os("TEMPO_CDP_CHROME") else {
        eprintln!("skipping run-decided-task live CDP test: TEMPO_CDP_CHROME is unset");
        return Ok(());
    };
    let dir = unique_dir("run-decided-task-live")?;
    let decisions = dir.join("decisions.json");
    let journal = dir.join("session.jsonl");
    let output = dir.join("report.json");
    let eval_record = dir.join("eval-record.jsonl");
    let e2e_budget = dir.join("e2e-budget.json");
    write_json(
        &decisions,
        &serde_json::json!([
            [
                { "kind": "wait", "millis": 1 },
                { "kind": "scroll", "x": 0.0, "y": 10.0 }
            ],
            []
        ]),
    )?;
    let (url, server) = serve_fixture_page()?;

    let status = Command::new(env!("CARGO_BIN_EXE_tempo-cli"))
        .args([
            "run-decided-task",
            "--start-url",
            &url,
            "--goal",
            "wait and scroll then finish",
            "--decider",
            "scripted",
            "--decisions",
            &path_string(&decisions),
            "--journal",
            &path_string(&journal),
            "--output",
            &path_string(&output),
            "--run-id",
            "run-decided-live",
            "--session-id",
            "session-decided-live",
            "--chrome",
            &path_string(Path::new(&chrome)),
            "--allow-private-network",
            "--confirmation-mode",
            "auto-clean",
            "--max-rounds",
            "4",
        ])
        .env("TEMPO_CDP_NO_SANDBOX", "1")
        .env("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
        .status()?;

    server.join().map_err(|_| "fixture server panicked")??;
    assert!(status.success(), "tempo-cli exited with {status}");
    let report: Value = serde_json::from_reader(File::open(&output)?)?;
    assert_eq!(report["status"]["state"], "completed");
    assert_eq!(report["actions_completed"], 2);
    assert_eq!(report["llm_round_trips"], 2);
    assert_eq!(report["live_llm_round_trips"], 2);
    assert_eq!(report["llm_round_trips_per_completed_task"], 2);
    assert_eq!(report["rounds"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["usage"]["total_tokens"], 0);

    let entries = read_journal_entries(&journal)?;
    assert!(entries
        .iter()
        .any(|entry| matches!(entry.event, JournalEvent::ModelDecision { .. })));
    assert!(entries
        .iter()
        .any(|entry| matches!(entry.event, JournalEvent::ActionPlanned { .. })));
    assert!(entries
        .iter()
        .any(|entry| matches!(entry.event, JournalEvent::StepApplied { .. })));
    assert!(matches!(
        entries.last().map(|entry| &entry.event),
        Some(JournalEvent::SessionClosed)
    ));

    let status = Command::new(env!("CARGO_BIN_EXE_tempo-cli"))
        .args([
            "session-eval",
            "--journal",
            &path_string(&journal),
            "--suite",
            "live-cdp",
            "--case-id",
            "run-decided-task",
            "--origin",
            &url,
            "--lane",
            "cdp",
            "--success",
            "true",
            "--fallback-used",
            "false",
            "--output",
            &path_string(&eval_record),
        ])
        .env("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
        .status()?;
    assert!(status.success(), "session-eval exited with {status}");

    let eval: Value = serde_json::from_reader(File::open(&eval_record)?)?;
    assert_eq!(eval["lane"], "cdp");
    assert_eq!(eval["step_count"], 2);
    assert_eq!(eval["round_trips"], 2);
    assert!(eval["observe_latencies_ms"]
        .as_array()
        .is_some_and(|samples| !samples.is_empty()));
    assert!(eval["action_latencies_ms"]
        .as_array()
        .is_some_and(|samples| !samples.is_empty()));
    assert!(eval["wall_clock_ms"].as_u64().is_some_and(|ms| ms > 0));

    let status = Command::new(env!("CARGO_BIN_EXE_tempo-cli"))
        .args([
            "e2e-budget",
            "--input",
            &path_string(&eval_record),
            "--output",
            &path_string(&e2e_budget),
            "--max-observe-p50-ms",
            "10000",
            "--max-act-to-settled-p50-ms",
            "10000",
        ])
        .status()?;
    assert!(status.success(), "e2e-budget exited with {status}");
    let budget: Value = serde_json::from_reader(File::open(&e2e_budget)?)?;
    assert_eq!(budget["total_cases"], 1);
    assert_eq!(budget["completed_cases"], 1);
    assert_eq!(budget["total_steps"], 2);
    assert_eq!(budget["total_round_trips"], 2);
    assert_eq!(budget["llm_round_trips_per_completed_task"], 2.0);
    assert!(budget["violations"]
        .as_array()
        .is_some_and(|violations| violations.is_empty()));
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn serve_fixture_page() -> std::io::Result<(String, thread::JoinHandle<std::io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("http://{}", listener.local_addr()?);
    let handle = thread::spawn(move || -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let body = "<!doctype html><title>tempo fixture</title><main style=\"height:2000px\"><button id=\"finish\">Finish</button></main>";
        let mut served = 0;
        let mut last_served: Option<Instant> = None;
        while served < 8 && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if let Some(last_served) = last_served
                        && last_served.elapsed() >= Duration::from_millis(500)
                    {
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error),
            };
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )?;
            stream.flush()?;
            served += 1;
            last_served = Some(Instant::now());
        }
        Ok(())
    });
    Ok((url, handle))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, value)?;
    Ok(())
}

fn unique_dir(prefix: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("tempo-cli-{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
