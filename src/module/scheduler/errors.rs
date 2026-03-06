use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    InvalidWorkerCount(usize),
    TaskFailed { task: String, reason: String },
    WorkerChannelClosed,
}

impl Display for SchedulerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWorkerCount(count) => {
                write!(f, "invalid worker count: {count} (must be >= 1)")
            }
            Self::TaskFailed { task, reason } => write!(f, "task `{task}` failed: {reason}"),
            Self::WorkerChannelClosed => write!(f, "worker channel closed unexpectedly"),
        }
    }
}

impl Error for SchedulerError {}
