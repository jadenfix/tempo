use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() <= 1 {
        let options = eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1024.0, 768.0])
                .with_title("tempo-shell"),
            ..Default::default()
        };
        
        let client = tempo_shell::ShellClient::new(tempo_shell::DEFAULT_TEMPOD_ADDR);
        
        let result = eframe::run_native(
            "tempo-shell",
            options,
            Box::new(|cc| Ok(Box::new(tempo_shell::app::TempoShellApp::new(cc, client)))),
        );
        
        match result {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    } else {
        let mut stdout = io::stdout().lock();
        let mut stderr = io::stderr().lock();

        match tempo_shell::run_cli(args.into_iter().skip(1), &mut stdout) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                let _ = writeln!(stderr, "{err}");
                ExitCode::from(err.exit_code())
            }
        }
    }
}
