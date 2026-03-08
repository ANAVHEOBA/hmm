//! Service Installation Persistence
//!
//! Installs system services for automatic execution:
//! - Windows: Windows Service Control Manager
//! - Linux: systemd service
//!
//! Provides the most robust persistence with system-level execution.

use super::errors::PersistenceError;

/// Service startup type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStartup {
    /// Started by the service controller (Windows) / enabled (Linux)
    Automatic,
    /// Started automatically when the system boots (Windows only)
    Boot,
    /// Started during system startup (Windows only)
    SystemStart,
    /// Started manually by user or dependent service
    Manual,
    /// Service is disabled
    Disabled,
}

/// Service type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// Own process service
    OwnProcess,
    /// Shared process service
    SharedProcess,
    /// Kernel driver (Windows only)
    KernelDriver,
    /// File system driver (Windows only)
    FileSystemDriver,
}

/// Configuration for service persistence
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name (internal identifier)
    pub name: String,
    /// Display name (shown in service manager)
    pub display_name: String,
    /// Full path to the executable
    pub executable_path: String,
    /// Optional command-line arguments
    pub arguments: Option<String>,
    /// Service description
    pub description: Option<String>,
    /// Service startup type
    pub startup: ServiceStartup,
    /// Service type
    pub service_type: ServiceType,
    /// Service account (Windows: "LocalSystem", "NetworkService", etc.)
    pub account: Option<String>,
    /// Account password (if required)
    pub password: Option<String>,
    /// Dependencies (other services that must start first)
    pub dependencies: Vec<String>,
    /// Restart on failure
    pub restart_on_failure: bool,
    /// Restart delay in seconds
    pub restart_delay: u32,
}

impl ServiceConfig {
    /// Create a new service config with automatic startup
    pub fn new(name: &str, display_name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            description: None,
            startup: ServiceStartup::Automatic,
            service_type: ServiceType::OwnProcess,
            account: None,
            password: None,
            dependencies: Vec::new(),
            restart_on_failure: true,
            restart_delay: 30,
        }
    }

    /// Set service description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set startup type
    pub fn with_startup(mut self, startup: ServiceStartup) -> Self {
        self.startup = startup;
        self
    }

    /// Set command-line arguments
    pub fn with_arguments(mut self, args: &str) -> Self {
        self.arguments = Some(args.to_string());
        self
    }

    /// Set service account
    pub fn with_account(mut self, account: &str, password: Option<&str>) -> Self {
        self.account = Some(account.to_string());
        self.password = password.map(|p| p.to_string());
        self
    }

    /// Add a dependency
    pub fn with_dependency(mut self, dependency: &str) -> Self {
        self.dependencies.push(dependency.to_string());
        self
    }

    /// Set restart on failure
    pub fn with_restart_on_failure(mut self, restart: bool, delay: u32) -> Self {
        self.restart_on_failure = restart;
        self.restart_delay = delay;
        self
    }

    /// Get the full command line
    pub fn full_command(&self) -> String {
        let mut cmd = self.executable_path.clone();
        if let Some(args) = &self.arguments {
            cmd.push(' ');
            cmd.push_str(args);
        }
        cmd
    }
}

/// Service persistence manager
pub struct ServicePersistence;

impl ServicePersistence {
    /// Check if service persistence is available
    pub fn is_available() -> bool {
        cfg!(any(target_os = "windows", target_os = "linux"))
    }

    /// Install service persistence
    pub fn install(config: &ServiceConfig) -> Result<super::PersistenceResult, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::install_windows(config)
        }
        #[cfg(target_os = "linux")]
        {
            Self::install_linux(config)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(PersistenceError::Internal(
                "Service persistence is not available on this platform".to_string(),
            ))
        }
    }

    /// Remove service persistence
    pub fn remove(name: &str) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::remove_windows(name)
        }
        #[cfg(target_os = "linux")]
        {
            Self::remove_linux(name)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(PersistenceError::Internal(
                "Service persistence is not available on this platform".to_string(),
            ))
        }
    }

    /// Check if a service exists
    pub fn exists(name: &str) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::exists_windows(name)
        }
        #[cfg(target_os = "linux")]
        {
            Self::exists_linux(name)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Ok(false)
        }
    }

    /// Start the service
    pub fn start(name: &str) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::start_windows(name)
        }
        #[cfg(target_os = "linux")]
        {
            Self::start_linux(name)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(PersistenceError::Internal(
                "Service persistence is not available on this platform".to_string(),
            ))
        }
    }

    /// Stop the service
    pub fn stop(name: &str) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::stop_windows(name)
        }
        #[cfg(target_os = "linux")]
        {
            Self::stop_linux(name)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(PersistenceError::Internal(
                "Service persistence is not available on this platform".to_string(),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn install_windows(config: &ServiceConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
        use winapi::shared::winerror::{ERROR_SUCCESS, ERROR_SERVICE_EXISTS};
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::winnt::{
            SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_BOOT_START,
            SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_SYSTEM_START,
            SERVICE_WIN32_OWN_PROCESS,
        };
        use winapi::um::winsvc::{
            CloseServiceHandle, CreateServiceA, OpenSCManagerA,
            SC_MANAGER_ALL_ACCESS, SC_MANAGER_CREATE_SERVICE, SERVICE_HANDLE,
        };

        unsafe {
            // Open Service Control Manager
            let sc_manager = OpenSCManagerA(
                ptr::null_mut(),
                ptr::null_mut(),
                SC_MANAGER_ALL_ACCESS,
            );

            if sc_manager.is_null() {
                return Err(PersistenceError::Service(
                    "Failed to open Service Control Manager".to_string(),
                ));
            }

            // Determine startup type
            let start_type = match config.startup {
                ServiceStartup::Automatic => SERVICE_AUTO_START,
                ServiceStartup::Boot => SERVICE_BOOT_START,
                ServiceStartup::SystemStart => SERVICE_SYSTEM_START,
                ServiceStartup::Manual => SERVICE_DEMAND_START,
                ServiceStartup::Disabled => SERVICE_DISABLED,
            };

            // Determine service type
            let service_type = match config.service_type {
                ServiceType::OwnProcess => SERVICE_WIN32_OWN_PROCESS,
                ServiceType::SharedProcess => SERVICE_WIN32_SHARE_PROCESS,
                ServiceType::KernelDriver => 1, // SERVICE_KERNEL_DRIVER
                ServiceType::FileSystemDriver => 2, // SERVICE_FILE_SYSTEM_DRIVER
            };

            // Build binary path
            let binary_path = config.full_command();
            let binary_path_c = std::ffi::CString::new(binary_path)
                .map_err(|_| PersistenceError::InvalidPath("Invalid binary path".to_string()))?;

            let name_c = std::ffi::CString::new(config.name.as_str())
                .map_err(|_| PersistenceError::InvalidPath("Invalid service name".to_string()))?;

            let display_name_c = std::ffi::CString::new(config.display_name.as_str())
                .map_err(|_| PersistenceError::InvalidPath("Invalid display name".to_string()))?;

            // Create the service
            let service = CreateServiceA(
                sc_manager,
                name_c.as_ptr(),
                display_name_c.as_ptr(),
                SERVICE_ALL_ACCESS,
                service_type,
                start_type,
                0, // SERVICE_ERROR_NORMAL
                binary_path_c.as_ptr(),
                ptr::null(), // No load ordering group
                ptr::null_mut(), // No tag ID
                ptr::null(), // No dependencies
                ptr::null(), // LocalSystem account
                ptr::null(), // No password
            );

            if service.is_null() {
                CloseServiceHandle(sc_manager);
                
                // Check if service already exists
                let last_error = winapi::um::errhandlingapi::GetLastError();
                if last_error == ERROR_SERVICE_EXISTS {
                    return Err(PersistenceError::Service(
                        "Service already exists".to_string(),
                    ));
                }
                
                return Err(PersistenceError::Service(
                    format!("Failed to create service: {}", last_error),
                ));
            }

            // Set service description
            if let Some(ref desc) = config.description {
                use winapi::um::winsvc::{ChangeServiceConfig2A, SERVICE_CONFIG_DESCRIPTION};
                
                let desc_c = std::ffi::CString::new(desc.as_str())
                    .map_err(|_| PersistenceError::InvalidPath("Invalid description".to_string()))?;
                
                let mut service_desc = winapi::um::winsvc::SERVICE_DESCRIPTIONA {
                    lpDescription: desc_c.as_ptr() as *mut i8,
                };
                
                ChangeServiceConfig2A(
                    service,
                    SERVICE_CONFIG_DESCRIPTION,
                    &mut service_desc as *mut _ as _,
                );
            }

            // Set failure actions (restart on failure)
            if config.restart_on_failure {
                use winapi::um::winsvc::{ChangeServiceConfig2A, SERVICE_CONFIG_FAILURE_ACTIONS};
                
                let actions = [
                    winapi::um::winsvc::SC_ACTION {
                        Type: 1, // SC_ACTION_RESTART
                        Delay: config.restart_delay * 1000, // milliseconds
                    },
                    winapi::um::winsvc::SC_ACTION {
                        Type: 0, // SC_ACTION_NONE
                        Delay: 0,
                    },
                    winapi::um::winsvc::SC_ACTION {
                        Type: 0,
                        Delay: 0,
                    },
                ];
                
                let mut failure_actions = winapi::um::winsvc::SERVICE_FAILURE_ACTIONSA {
                    dwResetPeriod: 86400, // Reset after 24 hours
                    lpRebootMsg: ptr::null_mut(),
                    lpCommand: ptr::null_mut(),
                    cActions: 3,
                    lpsaActions: actions.as_ptr() as *mut _,
                };
                
                ChangeServiceConfig2A(
                    service,
                    SERVICE_CONFIG_FAILURE_ACTIONS,
                    &mut failure_actions as *mut _ as _,
                );
            }

            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);

            Ok(super::PersistenceResult {
                success: true,
                method: super::PersistenceMethod::Service,
                identifier: Some(config.name.clone()),
                cleanup_command: Some(format!("sc delete \"{}\"", config.name)),
                error: None,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn install_linux(config: &ServiceConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::fs::File;
        use std::io::Write;
        use std::process::Command;

        // Create systemd unit file
        let unit_content = format!(
            r#"[Unit]
Description={}
{}
After=network.target

[Service]
Type=simple
ExecStart={}
{}
Restart={}
RestartSec={}

[Install]
WantedBy=multi-user.target
"#,
            config.display_name,
            config.description.as_ref().map(|d| format!("Documentation={}", d)).unwrap_or_default(),
            config.full_command(),
            if config.dependencies.is_empty() {
                String::new()
            } else {
                format!("Requires={}", config.dependencies.join(" "))
            },
            if config.restart_on_failure { "on-failure" } else { "no" },
            config.restart_delay,
        );

        // Write to /etc/systemd/system/
        let unit_path = format!("/etc/systemd/system/{}.service", config.name);
        
        let mut file = File::create(&unit_path)
            .map_err(|e| PersistenceError::Service(
                format!("Failed to create unit file: {}", e),
            ))?;

        file.write_all(unit_content.as_bytes())
            .map_err(|e| PersistenceError::Service(
                format!("Failed to write unit file: {}", e),
            ))?;

        // Reload systemd daemon
        let output = Command::new("systemctl")
            .arg("daemon-reload")
            .output()
            .map_err(|e| PersistenceError::Service(
                format!("Failed to reload systemd: {}", e),
            ))?;

        if !output.status.success() {
            return Err(PersistenceError::Service(
                format!("systemctl daemon-reload failed: {}", 
                    String::from_utf8_lossy(&output.stderr)),
            ));
        }

        // Enable the service
        let output = Command::new("systemctl")
            .arg("enable")
            .arg(&format!("{}.service", config.name))
            .output()
            .map_err(|e| PersistenceError::Service(
                format!("Failed to enable service: {}", e),
            ))?;

        if !output.status.success() {
            return Err(PersistenceError::Service(
                format!("systemctl enable failed: {}", 
                    String::from_utf8_lossy(&output.stderr)),
            ));
        }

        Ok(super::PersistenceResult {
            success: true,
            method: super::PersistenceMethod::Service,
            identifier: Some(config.name.clone()),
            cleanup_command: Some(format!(
                "systemctl disable {}.service && rm /etc/systemd/system/{}.service",
                config.name, config.name
            )),
            error: None,
        })
    }

    #[cfg(target_os = "windows")]
    fn remove_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::winsvc::{
            CloseServiceHandle, DeleteService, OpenSCManagerA, OpenServiceA,
            SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
        };

        unsafe {
            let sc_manager = OpenSCManagerA(
                ptr::null_mut(),
                ptr::null_mut(),
                SC_MANAGER_ALL_ACCESS,
            );

            if sc_manager.is_null() {
                return Err(PersistenceError::Service(
                    "Failed to open Service Control Manager".to_string(),
                ));
            }

            let name_c = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid service name".to_string()))?;

            let service = OpenServiceA(
                sc_manager,
                name_c.as_ptr(),
                SERVICE_ALL_ACCESS,
            );

            if service.is_null() {
                CloseServiceHandle(sc_manager);
                return Err(PersistenceError::Service(
                    "Service not found".to_string(),
                ));
            }

            let result = DeleteService(service);
            
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);

            Ok(result != 0)
        }
    }

    #[cfg(target_os = "linux")]
    fn remove_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::fs;
        use std::process::Command;

        // Disable the service
        let output = Command::new("systemctl")
            .arg("disable")
            .arg(&format!("{}.service", name))
            .output()
            .map_err(|e| PersistenceError::Service(
                format!("Failed to disable service: {}", e),
            ))?;

        // Remove the unit file
        let unit_path = format!("/etc/systemd/system/{}.service", name);
        let _ = fs::remove_file(&unit_path);

        // Reload systemd
        let _ = Command::new("systemctl").arg("daemon-reload").output();

        Ok(output.status.success())
    }

    #[cfg(target_os = "windows")]
    fn exists_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::um::winsvc::{
            CloseServiceHandle, OpenSCManagerA, OpenServiceA,
            SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS,
        };

        unsafe {
            let sc_manager = OpenSCManagerA(
                ptr::null_mut(),
                ptr::null_mut(),
                SC_MANAGER_ENUMERATE_SERVICE,
            );

            if sc_manager.is_null() {
                return Ok(false);
            }

            let name_c = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid service name".to_string()))?;

            let service = OpenServiceA(
                sc_manager,
                name_c.as_ptr(),
                SERVICE_QUERY_STATUS,
            );

            CloseServiceHandle(sc_manager);

            if service.is_null() {
                return Ok(false);
            }

            CloseServiceHandle(service);
            Ok(true)
        }
    }

    #[cfg(target_os = "linux")]
    fn exists_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("systemctl")
            .arg("is-enabled")
            .arg(&format!("{}.service", name))
            .output();

        match output {
            Ok(out) => Ok(out.status.success()),
            Err(_) => Ok(false),
        }
    }

    #[cfg(target_os = "windows")]
    fn start_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::um::winsvc::{
            CloseServiceHandle, OpenSCManagerA, OpenServiceA, StartServiceA,
            SC_MANAGER_CONNECT, SERVICE_START,
        };

        unsafe {
            let sc_manager = OpenSCManagerA(
                ptr::null_mut(),
                ptr::null_mut(),
                SC_MANAGER_CONNECT,
            );

            if sc_manager.is_null() {
                return Err(PersistenceError::Service(
                    "Failed to open Service Control Manager".to_string(),
                ));
            }

            let name_c = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid service name".to_string()))?;

            let service = OpenServiceA(
                sc_manager,
                name_c.as_ptr(),
                SERVICE_START,
            );

            if service.is_null() {
                CloseServiceHandle(sc_manager);
                return Err(PersistenceError::Service(
                    "Service not found".to_string(),
                ));
            }

            let result = StartServiceA(
                service,
                0,
                ptr::null(),
            );

            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);

            Ok(result != 0)
        }
    }

    #[cfg(target_os = "linux")]
    fn start_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("systemctl")
            .arg("start")
            .arg(&format!("{}.service", name))
            .output()
            .map_err(|e| PersistenceError::Service(
                format!("Failed to start service: {}", e),
            ))?;

        Ok(output.status.success())
    }

    #[cfg(target_os = "windows")]
    fn stop_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::um::winsvc::{
            CloseServiceHandle, ControlService, OpenSCManagerA, OpenServiceA,
            SC_MANAGER_CONNECT, SERVICE_STOP, SERVICE_CONTROL_STOP, SERVICE_STATUS,
        };

        unsafe {
            let sc_manager = OpenSCManagerA(
                ptr::null_mut(),
                ptr::null_mut(),
                SC_MANAGER_CONNECT,
            );

            if sc_manager.is_null() {
                return Err(PersistenceError::Service(
                    "Failed to open Service Control Manager".to_string(),
                ));
            }

            let name_c = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid service name".to_string()))?;

            let service = OpenServiceA(
                sc_manager,
                name_c.as_ptr(),
                SERVICE_STOP,
            );

            if service.is_null() {
                CloseServiceHandle(sc_manager);
                return Err(PersistenceError::Service(
                    "Service not found".to_string(),
                ));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let result = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);

            Ok(result != 0)
        }
    }

    #[cfg(target_os = "linux")]
    fn stop_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("systemctl")
            .arg("stop")
            .arg(&format!("{}.service", name))
            .output()
            .map_err(|e| PersistenceError::Service(
                format!("Failed to stop service: {}", e),
            ))?;

        Ok(output.status.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_availability() {
        let available = ServicePersistence::is_available();
        assert!(available || cfg!(not(any(target_os = "windows", target_os = "linux"))));
    }

    #[test]
    fn test_service_config_creation() {
        let config = ServiceConfig::new(
            "TestService",
            "Test Service Display",
            "/path/to/executable",
        );

        assert_eq!(config.name, "TestService");
        assert_eq!(config.display_name, "Test Service Display");
        assert_eq!(config.startup, ServiceStartup::Automatic);
        assert_eq!(config.service_type, ServiceType::OwnProcess);
        assert!(config.restart_on_failure);
        assert_eq!(config.restart_delay, 30);
    }

    #[test]
    fn test_service_config_with_description() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_description("A test service");

        assert_eq!(config.description, Some("A test service".to_string()));
    }

    #[test]
    fn test_service_config_with_startup() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_startup(ServiceStartup::Manual);

        assert_eq!(config.startup, ServiceStartup::Manual);
    }

    #[test]
    fn test_service_config_with_arguments() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_arguments("-silent");

        assert_eq!(config.arguments, Some("-silent".to_string()));
    }

    #[test]
    fn test_service_config_with_account() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_account("LocalSystem", None);

        assert_eq!(config.account, Some("LocalSystem".to_string()));
        assert!(config.password.is_none());
    }

    #[test]
    fn test_service_config_with_dependency() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_dependency("RpcSs")
            .with_dependency("LanmanServer");

        assert_eq!(config.dependencies.len(), 2);
        assert!(config.dependencies.contains(&"RpcSs".to_string()));
        assert!(config.dependencies.contains(&"LanmanServer".to_string()));
    }

    #[test]
    fn test_service_config_with_restart() {
        let config = ServiceConfig::new("test", "Test", "/test")
            .with_restart_on_failure(true, 60);

        assert!(config.restart_on_failure);
        assert_eq!(config.restart_delay, 60);
    }

    #[test]
    fn test_full_command() {
        let config = ServiceConfig::new("test", "Test", "/path/to/exe")
            .with_arguments("-arg1 -arg2");

        assert_eq!(config.full_command(), "/path/to/exe -arg1 -arg2");
    }

    #[test]
    fn test_full_command_no_args() {
        let config = ServiceConfig::new("test", "Test", "/path/to/exe");
        assert_eq!(config.full_command(), "/path/to/exe");
    }

    #[test]
    fn test_not_available_on_non_standard_platform() {
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let config = ServiceConfig::new("test", "Test", "/test");
            let result = ServicePersistence::install(&config);
            assert!(result.is_err());
        }
    }
}
