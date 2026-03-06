use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    InvalidConfig(String),
    Parse(String),
    NotFound(String),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::InvalidConfig(msg) => write!(f, "invalid storage config: {msg}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
