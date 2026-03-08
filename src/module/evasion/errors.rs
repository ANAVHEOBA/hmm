use std::fmt;

/// Errors that can occur during evasion checks
#[derive(Debug, Clone)]
pub enum EvasionError {
    /// Failed to read system information
    SystemInfo(String),
    /// Failed to access registry (Windows)
    Registry(String),
    /// Failed to enumerate processes
    ProcessEnumeration(String),
    /// Failed to read file system
    FileSystem(String),
    /// Timing check failed
    Timing(String),
    /// API hashing/resolution failed
    ApiResolution(String),
    /// Packing/unpacking failed
    Packing(String),
    /// Fileless execution failed
    FilelessExec(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for EvasionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvasionError::SystemInfo(msg) => write!(f, "System info error: {}", msg),
            EvasionError::Registry(msg) => write!(f, "Registry error: {}", msg),
            EvasionError::ProcessEnumeration(msg) => write!(f, "Process enumeration error: {}", msg),
            EvasionError::FileSystem(msg) => write!(f, "File system error: {}", msg),
            EvasionError::Timing(msg) => write!(f, "Timing error: {}", msg),
            EvasionError::ApiResolution(msg) => write!(f, "API resolution error: {}", msg),
            EvasionError::Packing(msg) => write!(f, "Packing error: {}", msg),
            EvasionError::FilelessExec(msg) => write!(f, "Fileless execution error: {}", msg),
            EvasionError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for EvasionError {}
