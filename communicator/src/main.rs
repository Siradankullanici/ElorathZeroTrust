use crate::gui::CommunicatorApp;
use eframe::egui;

mod error;
mod gui;
mod ipc;
mod ipc_error;
mod learning;
mod policies;
mod signatures;

pub use error::{Error, Result};

fn main() -> Result<()> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };
    eframe::run_native(
        "ElorahtZeroTrust Communicator",
        options,
        Box::new(|_cc| Box::new(CommunicatorApp::default())),
    )?;
    Ok(())
}
