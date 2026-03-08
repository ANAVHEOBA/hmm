//! Persistence Module
//!
//! Provides various persistence techniques for maintaining access:
//! - Registry Run keys (Windows)
//! - Scheduled tasks (Windows/Linux)
//! - Startup folder (Windows)
//! - Service installation (Windows/Linux)
//!
//! WARNING: These techniques are highly detectable by modern AV/EDR.
//! Use only for educational/defensive research purposes.

pub mod errors;
pub mod registry;
pub mod scheduled_task;
pub mod startup;
pub mod service;

pub use errors::PersistenceError;
pub use registry::RegistryPersistence;
pub use scheduled_task::ScheduledTaskPersistence;
pub use startup::StartupFolderPersistence;
pub use service::ServicePersistence;

/// Persistence method types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMethod {
    RegistryRun,
    ScheduledTask,
    StartupFolder,
    Service,
}

/// Persistence installation result
#[derive(Debug, Clone)]
pub struct PersistenceResult {
    pub success: bool,
    pub method: PersistenceMethod,
    pub identifier: Option<String>, // Task name, service name, etc.
    pub cleanup_command: Option<String>,
    pub error: Option<String>,
}

/// Check if a persistence method is available on this platform
pub fn is_method_available(method: PersistenceMethod) -> bool {
    match method {
        PersistenceMethod::RegistryRun => cfg!(target_os = "windows"),
        PersistenceMethod::ScheduledTask => cfg!(any(target_os = "windows", target_os = "linux")),
        PersistenceMethod::StartupFolder => cfg!(target_os = "windows"),
        PersistenceMethod::Service => cfg!(any(target_os = "windows", target_os = "linux")),
    }
}

/// Get all available persistence methods for this platform
pub fn available_methods() -> Vec<PersistenceMethod> {
    let mut methods = Vec::new();
    
    if cfg!(target_os = "windows") {
        methods.push(PersistenceMethod::RegistryRun);
        methods.push(PersistenceMethod::ScheduledTask);
        methods.push(PersistenceMethod::StartupFolder);
        methods.push(PersistenceMethod::Service);
    } else if cfg!(target_os = "linux") {
        methods.push(PersistenceMethod::ScheduledTask);
        methods.push(PersistenceMethod::Service);
    }
    
    methods
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_methods_windows() {
        let methods = available_methods();
        
        #[cfg(target_os = "windows")]
        {
            assert!(methods.contains(&PersistenceMethod::RegistryRun));
            assert!(methods.contains(&PersistenceMethod::ScheduledTask));
            assert!(methods.contains(&PersistenceMethod::StartupFolder));
            assert!(methods.contains(&PersistenceMethod::Service));
        }
        
        #[cfg(target_os = "linux")]
        {
            assert!(!methods.contains(&PersistenceMethod::RegistryRun));
            assert!(methods.contains(&PersistenceMethod::ScheduledTask));
            assert!(!methods.contains(&PersistenceMethod::StartupFolder));
            assert!(methods.contains(&PersistenceMethod::Service));
        }
    }

    #[test]
    fn test_method_availability() {
        // Just verify the function doesn't panic
        let _ = is_method_available(PersistenceMethod::RegistryRun);
        let _ = is_method_available(PersistenceMethod::ScheduledTask);
        let _ = is_method_available(PersistenceMethod::StartupFolder);
        let _ = is_method_available(PersistenceMethod::Service);
    }
}
