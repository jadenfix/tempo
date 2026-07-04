use eframe::egui;
use crate::ShellClient;

pub struct TempoShellApp {
    client: ShellClient,
    url_input: String,
    sessions: Vec<tempo_headless::TempodSession>,
    last_error: Option<String>,
}

impl TempoShellApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, client: ShellClient) -> Self {
        let mut app = Self {
            client,
            url_input: String::from("https://example.com"),
            sessions: Vec::new(),
            last_error: None,
        };
        app.refresh_sessions();
        app
    }

    fn refresh_sessions(&mut self) {
        match self.client.sessions() {
            Ok(s) => {
                self.sessions = s;
                self.last_error = None;
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
            }
        }
    }
}

impl eframe::App for TempoShellApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("URL:");
                let response = ui.add(egui::TextEdit::singleline(&mut self.url_input).desired_width(500.0));
                
                if ui.button("Go").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    match self.client.open(&self.url_input) {
                        Ok(_) => {
                            self.refresh_sessions();
                        }
                        Err(e) => self.last_error = Some(e.to_string()),
                    }
                }
                
                if ui.button("Refresh").clicked() {
                    self.refresh_sessions();
                }
            });
        });

        egui::SidePanel::left("agent_panel")
            .resizable(true)
            .default_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Agent Panel");
                ui.separator();
                
                if let Some(err) = &self.last_error {
                    ui.colored_label(egui::Color32::RED, format!("Error: {}", err));
                }
                
                ui.label("Active Sessions:");
                for session in &self.sessions {
                    ui.group(|ui| {
                        ui.label(format!("ID: {}", session.id.0));
                        ui.label(format!("URL: {}", session.url));
                        ui.label(format!("State: {:?}", session.state));
                        ui.horizontal(|ui| {
                            if ui.button("Close").clicked() {
                                let _ = self.client.close(&session.id.0);
                                // Force a refresh after clicking close (will update next frame)
                            }
                        });
                    });
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("WebView Area");
            ui.label("Placeholder for embedded Servo WebView (WS2).");
            ui.label("Once WS2 is mature, the in-proc WebView frames will render here.");
        });
    }
}
