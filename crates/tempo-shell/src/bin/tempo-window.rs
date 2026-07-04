//! `tempo-window` — the winit+egui session browser over the tempod HTTP API.
//!
//! Thin shell around [`tempo_shell::window`]: parse config, open the window.
//! All behaviour worth testing lives in `tempo_shell::ui`, exercised headlessly.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match tempo_shell::window::WindowConfig::from_args_env(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => return fail(&err),
    };
    match tempo_shell::window::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(&err),
    }
}

fn fail(err: &dyn std::fmt::Display) -> ExitCode {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{err}");
    ExitCode::FAILURE
}
