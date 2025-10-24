use crate::ipc::{listen_for_alerts, ProcessAlert};
use crate::learning::Baseline;
use crate::policies::{Action, Policy};
use crate::signatures::generate_signature;
use eframe::egui;
use rfd::FileDialog;
use std::sync::mpsc;
use std::thread;

#[derive(PartialEq)]
enum Mode {
    Learning,
    ZeroTrust,
}

pub struct CommunicatorApp {
    mode: Mode,
    baseline_path: String,
    alerts: Vec<String>,
    signature_file_path: Option<String>,
    signature_hash: Option<String>,
    baseline: Baseline,
    policy: Policy,
    alert_rx: mpsc::Receiver<ProcessAlert>,
}

impl Default for CommunicatorApp {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let rt = tokio::runtime::Runtime::new().unwrap();
        thread::spawn(move || {
            rt.block_on(async {
                let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel(100);
                tokio::spawn(listen_for_alerts(tokio_tx));
                while let Some(alert) = tokio_rx.recv().await {
                    if tx.send(alert).is_err() {
                        break;
                    }
                }
            });
        });

        Self {
            mode: Mode::ZeroTrust,
            baseline_path: "baseline.json".to_string(),
            alerts: Vec::new(),
            signature_file_path: None,
            signature_hash: None,
            baseline: Baseline::new(),
            policy: Policy::new(),
            alert_rx: rx,
        }
    }
}

impl eframe::App for CommunicatorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for new alerts
        if let Ok(alert) = self.alert_rx.try_recv() {
            let alert_string = format!("{:?}", alert);
            if self.mode == Mode::Learning {
                self.baseline.add_trusted(&alert);
                self.alerts.push(format!("[Learning] {}", alert_string));
            } else {
                match self.policy.decide(&alert, &self.baseline) {
                    Action::Allow => self.alerts.push(format!("[Allowed] {}", alert_string)),
                    Action::Block => self.alerts.push(format!("[Blocked] {}", alert_string)),
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ElorahtZeroTrust Communicator");

            ui.separator();

            // Mode selection
            ui.horizontal(|ui| {
                if ui.selectable_value(&mut self.mode, Mode::Learning, "Learning Mode").changed() {
                    if let Err(e) = self.baseline.save(&self.baseline_path) {
                        self.alerts.push(format!("[Error] Failed to save baseline: {}", e));
                    }
                }
                ui.selectable_value(&mut self.mode, Mode::ZeroTrust, "Zero-Trust Mode");
            });

            // Baseline path
            ui.horizontal(|ui| {
                ui.label("Baseline Path:");
                ui.text_edit_singleline(&mut self.baseline_path);
                if ui.button("Load Baseline").clicked() {
                    match Baseline::load(&self.baseline_path) {
                        Ok(baseline) => self.baseline = baseline,
                        Err(e) => self.alerts.push(format!("[Error] Failed to load baseline: {}", e)),
                    }
                }
            });

            ui.separator();

            // Alert log
            ui.heading("Alert Log");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for alert in &self.alerts {
                    ui.label(alert);
                }
            });

            ui.separator();

            // Signature generation
            ui.heading("Signature Generation");
            ui.horizontal(|ui| {
                if ui.button("Select File").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        self.signature_file_path = Some(path.display().to_string());
                        match generate_signature(path) {
                            Ok(hash) => self.signature_hash = Some(hash),
                            Err(e) => self.alerts.push(format!("[Error] Failed to generate signature: {}", e)),
                        }
                    }
                }
                if let Some(path) = &self.signature_file_path {
                    ui.label(path);
                }
            });
            if let Some(hash) = &self.signature_hash {
                ui.label(format!("Signature: {}", hash));
            }
        });
    }
}
