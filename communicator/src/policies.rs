use crate::ipc::ProcessAlert;
use crate::learning::Baseline;

pub enum Action {
    Allow,
    Block,
}

pub struct Policy;

impl Policy {
    pub fn new() -> Self {
        Self
    }

    pub fn decide(&self, alert: &ProcessAlert, baseline: &Baseline) -> Action {
        if baseline.is_trusted(alert) {
            Action::Allow
        } else {
            Action::Block
        }
    }
}
