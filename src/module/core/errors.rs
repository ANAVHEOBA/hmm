use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidConfig(String),
    AlreadyRunning,
    TaskFailed { task: String, reason: String },
    Cancelled,
}

impl Display for CoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::AlreadyRunning => write!(f, "orchestrator is already running"),
            Self::TaskFailed { task, reason } => {
                write!(f, "task `{task}` failed: {reason}")
            }
            Self::Cancelled => write!(f, "operation cancelled"),
        }
    }
}

impl Error for CoreError {}
