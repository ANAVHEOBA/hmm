use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum TransportError {
    InvalidConfig(String),
    InvalidEndpoint(String),
    Io(std::io::Error),
    Protocol(String),
    UploadFailed(u16),
}

impl Display for TransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid transport config: {msg}"),
            Self::InvalidEndpoint(msg) => write!(f, "invalid endpoint: {msg}"),
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::UploadFailed(code) => write!(f, "upload failed with status code {code}"),
        }
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
