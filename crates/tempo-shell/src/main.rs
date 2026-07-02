use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();

    match tempo_shell::run_cli(std::env::args().skip(1), &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            ExitCode::from(err.exit_code())
        }
    }
}
