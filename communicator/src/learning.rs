use serde::{Deserialize, Serialize};
use crate::ipc::ProcessAlert;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use crate::error::Result;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Baseline {
    trusted: HashSet<String>,
}

impl Baseline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            let data = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::new())
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        Ok(fs::write(path, data)?)
    }

    pub fn add_trusted(&mut self, alert: &ProcessAlert) {
        self.trusted.insert(self.get_key(alert));
    }

    pub fn is_trusted(&self, alert: &ProcessAlert) -> bool {
        self.trusted.contains(&self.get_key(alert))
    }

    fn get_key(&self, alert: &ProcessAlert) -> String {
        format!("{}:{}", alert.attacker_path, alert.protected_file)
    }
}
