use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessingError {
    InvalidConfig(String),
    InvalidData(String),
    Encryption(String),
    Compression(String),
    Io(String),
}

impl Display for ProcessingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid processing config: {msg}"),
            Self::InvalidData(msg) => write!(f, "invalid processing data: {msg}"),
            Self::Encryption(msg) => write!(f, "encryption error: {msg}"),
            Self::Compression(msg) => write!(f, "compression error: {msg}"),
            Self::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl Error for ProcessingError {}

impl From<std::io::Error> for ProcessingError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
