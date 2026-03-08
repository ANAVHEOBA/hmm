use std::fmt;

/// Errors that can occur during persistence operations
#[derive(Debug, Clone)]
pub enum PersistenceError {
    /// Failed to access registry (Windows)
    Registry(String),
    /// Failed to create scheduled task
    ScheduledTask(String),
    /// Failed to access file system
    FileSystem(String),
    /// Failed to install/manage service
    Service(String),
    /// Permission denied
    PermissionDenied(String),
    /// Invalid path or name
    InvalidPath(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::Registry(msg) => write!(f, "Registry error: {}", msg),
            PersistenceError::ScheduledTask(msg) => write!(f, "Scheduled task error: {}", msg),
            PersistenceError::FileSystem(msg) => write!(f, "File system error: {}", msg),
            PersistenceError::Service(msg) => write!(f, "Service error: {}", msg),
            PersistenceError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            PersistenceError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            PersistenceError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for PersistenceError {}
