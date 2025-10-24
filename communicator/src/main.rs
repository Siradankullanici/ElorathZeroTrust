use std::env;
use thiserror::Error;
use tokio::sync::mpsc;
use crate::learning::Baseline;
use crate::policies::{Action, Policy};
use crate::signatures::generate_signature;

mod ipc;
mod learning;
mod policies;
mod signatures;

#[derive(Error, Debug)]
pub enum Error {
    #[error("an unhandled io error occurred")]
    Io(#[from] std::io::Error),
    #[error("an unhandled serialization error occurred")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The main entry point for the communicator application.
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if let Some(i) = args.iter().position(|arg| arg == "--generate-signature") {
        if let Some(path) = args.get(i + 1) {
            let signature = generate_signature(path)?;
            println!("Signature for {}: {}", path, signature);
            return Ok(());
        }
    }

    println!("Starting ElorahtZeroTrust Communicator...");

    let learning_mode = args.contains(&"--learn".to_string());
    let baseline_path = "baseline.json";
    let mut baseline = Baseline::load(baseline_path)?;
    let policy = Policy::new();

    let (tx, mut rx) = mpsc::channel(100);

    // Spawn a task to listen for alerts
    tokio::spawn(async move {
        if let Err(e) = ipc::listen_for_alerts(tx).await {
            eprintln!("Error listening for alerts: {}", e);
        }
    });

    println!("Waiting for alerts...");
    while let Some(alert) = rx.recv().await {
        if learning_mode {
            println!("Learning: adding alert to baseline for attacker '{}' and protected file '{}'", alert.attacker_path, alert.protected_file);
            baseline.add_trusted(&alert);
        } else {
            match policy.decide(&alert, &baseline) {
                Action::Allow => {
                    println!("Policy: allowing alert for attacker '{}' and protected file '{}'", alert.attacker_path, alert.protected_file);
                }
                Action::Block => {
                    println!("Policy: blocking alert for attacker '{}' and protected file '{}'", alert.attacker_path, alert.protected_file);
                    // In a real application, you would block the process here.
                }
            }
        }
    }

    if learning_mode {
        println!("Saving baseline to {}", baseline_path);
        baseline.save(baseline_path)?;
    }

    Ok(())
}
