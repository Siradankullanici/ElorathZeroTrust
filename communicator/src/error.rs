use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("an unhandled io error occurred")]
    Io(#[from] std::io::Error),
    #[error("an unhandled serialization error occurred")]
    Serde(#[from] serde_json::Error),
    #[error("an unhandled eframe error occurred")]
    Eframe(#[from] eframe::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
