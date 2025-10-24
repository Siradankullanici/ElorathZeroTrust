use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("an unhandled io error occurred")]
    Io(#[from] std::io::Error),
    #[error("an unhandled channel error occurred")]
    Channel,
}

pub type IpcResult<T> = std::result::Result<T, IpcError>;
