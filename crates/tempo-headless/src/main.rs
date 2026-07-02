fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".into());
    if let Err(err) = tempo_headless::run_tempod(&addr) {
        eprintln!("tempod failed: {err}");
        std::process::exit(1);
    }
}
