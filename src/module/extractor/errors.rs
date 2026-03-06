use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    NotFound(String),
    PermissionDenied(String),
    InvalidData(String),
    IoError(String),
    PlatformNotSupported(String),
    Locked(String),
    DecodeError(String),
}

impl Display for ExtractionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            Self::IoError(msg) => write!(f, "io error: {msg}"),
            Self::PlatformNotSupported(msg) => write!(f, "platform not supported: {msg}"),
            Self::Locked(msg) => write!(f, "resource locked: {msg}"),
            Self::DecodeError(msg) => write!(f, "decode error: {msg}"),
        }
    }
}

impl Error for ExtractionError {}

impl From<std::io::Error> for ExtractionError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => {
                Self::NotFound(err.to_string())
            }
            std::io::ErrorKind::PermissionDenied => {
                Self::PermissionDenied(err.to_string())
            }
            _ => Self::IoError(err.to_string()),
        }
    }
}
