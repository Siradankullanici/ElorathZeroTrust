use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use crate::Result;

pub fn generate_signature<P: AsRef<Path>>(path: P) -> Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
