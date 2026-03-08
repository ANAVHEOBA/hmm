//! Registry Run Keys Persistence
//!
//! Adds entries to Windows Registry Run keys for automatic execution at login.
//!
//! Registry locations:
//! - HKCU\Software\Microsoft\Windows\CurrentVersion\Run (current user)
//! - HKLM\Software\Microsoft\Windows\CurrentVersion\Run (all users, requires admin)
//! - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce (single execution)
//! - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce (single execution)

use super::errors::PersistenceError;

/// Registry persistence key locations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryKeyLocation {
    /// Current user Run key (no admin required)
    CurrentUserRun,
    /// Local machine Run key (requires admin)
    LocalMachineRun,
    /// Current user RunOnce key (single execution)
    CurrentUserRunOnce,
    /// Local machine RunOnce key (single execution)
    LocalMachineRunOnce,
}

impl RegistryKeyLocation {
    /// Get the registry path for this location
    pub fn path(&self) -> &'static str {
        match self {
            Self::CurrentUserRun => r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            Self::LocalMachineRun => r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            Self::CurrentUserRunOnce => r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            Self::LocalMachineRunOnce => r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        }
    }

    /// Get the hive and subkey separately
    pub fn hive_and_key(&self) -> (&'static str, &'static str) {
        match self {
            Self::CurrentUserRun => ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            Self::LocalMachineRun => ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            Self::CurrentUserRunOnce => ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            Self::LocalMachineRunOnce => ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        }
    }
}

/// Configuration for registry persistence
#[derive(Debug, Clone)]
pub struct RegistryPersistenceConfig {
    /// Display name for the entry
    pub name: String,
    /// Full path to the executable
    pub executable_path: String,
    /// Optional command-line arguments
    pub arguments: Option<String>,
    /// Registry key location
    pub location: RegistryKeyLocation,
}

impl RegistryPersistenceConfig {
    /// Create a new config for current user persistence
    pub fn for_current_user(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            location: RegistryKeyLocation::CurrentUserRun,
        }
    }

    /// Create a new config for all users (requires admin)
    pub fn for_all_users(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            location: RegistryKeyLocation::LocalMachineRun,
        }
    }

    /// Set command-line arguments
    pub fn with_arguments(mut self, args: &str) -> Self {
        self.arguments = Some(args.to_string());
        self
    }

    /// Get the full command line (executable + arguments)
    pub fn full_command(&self) -> String {
        let mut cmd = String::new();
        
        // Quote the executable path if it contains spaces
        if self.executable_path.contains(' ') {
            cmd.push('"');
            cmd.push_str(&self.executable_path);
            cmd.push('"');
        } else {
            cmd.push_str(&self.executable_path);
        }

        if let Some(args) = &self.arguments {
            cmd.push(' ');
            cmd.push_str(args);
        }

        cmd
    }
}

/// Registry persistence manager
pub struct RegistryPersistence;

impl RegistryPersistence {
    /// Check if registry persistence is available
    pub fn is_available() -> bool {
        cfg!(target_os = "windows")
    }

    /// Install registry persistence
    ///
    /// # Arguments
    /// * `config` - Persistence configuration
    ///
    /// # Returns
    /// Persistence result with cleanup information
    pub fn install(_config: &RegistryPersistenceConfig) -> Result<super::PersistenceResult, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::install_windows(_config)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(PersistenceError::Internal(
                "Registry persistence is only available on Windows".to_string(),
            ))
        }
    }

    /// Remove registry persistence
    ///
    /// # Arguments
    /// * `name` - The entry name to remove
    /// * `location` - The registry key location
    pub fn remove(_name: &str, _location: RegistryKeyLocation) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::remove_windows(_name, _location)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(PersistenceError::Internal(
                "Registry persistence is only available on Windows".to_string(),
            ))
        }
    }

    /// Check if a registry entry exists
    pub fn exists(_name: &str, _location: RegistryKeyLocation) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::exists_windows(_name, _location)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(false)
        }
    }

    #[cfg(target_os = "windows")]
    fn install_windows(config: &RegistryPersistenceConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::ffi::OsString;
        use std::ptr;
        use winapi::shared::minwindef::HKEY;
        use winapi::shared::winerror::{ERROR_SUCCESS, ERROR_ACCESS_DENIED};
        use winapi::um::winreg::{
            RegCloseKey, RegOpenKeyExA, RegSetValueExA,
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            KEY_SET_VALUE, REG_SZ,
        };

        let (hive, subkey) = config.location.hive_and_key();
        
        let hkey = match hive {
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            _ => return Err(PersistenceError::Registry("Invalid hive".to_string())),
        };

        unsafe {
            let mut h_key: HKEY = ptr::null_mut();
            let subkey_c = std::ffi::CString::new(subkey)
                .map_err(|_| PersistenceError::InvalidPath("Invalid registry path".to_string()))?;

            let result = RegOpenKeyExA(
                hkey,
                subkey_c.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut h_key,
            );

            if result != ERROR_SUCCESS as i32 {
                if result == ERROR_ACCESS_DENIED as i32 {
                    return Err(PersistenceError::PermissionDenied(
                        "Access denied - administrator privileges required".to_string(),
                    ));
                }
                return Err(PersistenceError::Registry(
                    format!("Failed to open registry key: {}", result),
                ));
            }

            let value_name = std::ffi::CString::new(config.name.as_str())
                .map_err(|_| PersistenceError::InvalidPath("Invalid entry name".to_string()))?;
            
            let command = config.full_command();
            let data = OsString::from(command);
            let data_bytes = data.as_os_str().as_encoded_bytes();

            let set_result = RegSetValueExA(
                h_key,
                value_name.as_ptr(),
                0,
                REG_SZ,
                data_bytes.as_ptr(),
                data_bytes.len() as u32,
            );

            RegCloseKey(h_key);

            if set_result != ERROR_SUCCESS as i32 {
                return Err(PersistenceError::Registry(
                    format!("Failed to set registry value: {}", set_result),
                ));
            }

            Ok(super::PersistenceResult {
                success: true,
                method: super::PersistenceMethod::RegistryRun,
                identifier: Some(config.name.clone()),
                cleanup_command: Some(format!(
                    "reg delete \"{}\" /v \"{}\" /f",
                    config.location.path(),
                    config.name
                )),
                error: None,
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn remove_windows(name: &str, location: RegistryKeyLocation) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::shared::minwindef::HKEY;
        use winapi::shared::winerror::ERROR_SUCCESS;
        use winapi::um::winreg::{
            RegCloseKey, RegDeleteValueA, RegOpenKeyExA,
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            KEY_SET_VALUE,
        };

        let (hive, subkey) = location.hive_and_key();
        
        let hkey = match hive {
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            _ => return Err(PersistenceError::Registry("Invalid hive".to_string())),
        };

        unsafe {
            let mut h_key: HKEY = ptr::null_mut();
            let subkey_c = std::ffi::CString::new(subkey)
                .map_err(|_| PersistenceError::InvalidPath("Invalid registry path".to_string()))?;

            let result = RegOpenKeyExA(
                hkey,
                subkey_c.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut h_key,
            );

            if result != ERROR_SUCCESS as i32 {
                return Err(PersistenceError::Registry(
                    format!("Failed to open registry key: {}", result),
                ));
            }

            let value_name = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid entry name".to_string()))?;

            let delete_result = RegDeleteValueA(h_key, value_name.as_ptr());
            RegCloseKey(h_key);

            if delete_result != ERROR_SUCCESS as i32 {
                return Err(PersistenceError::Registry(
                    format!("Failed to delete registry value: {}", delete_result),
                ));
            }

            Ok(true)
        }
    }

    #[cfg(target_os = "windows")]
    fn exists_windows(name: &str, location: RegistryKeyLocation) -> Result<bool, PersistenceError> {
        use std::ptr;
        use winapi::shared::minwindef::HKEY;
        use winapi::shared::winerror::{ERROR_SUCCESS, ERROR_FILE_NOT_FOUND};
        use winapi::um::winreg::{
            RegCloseKey, RegQueryValueExA, RegOpenKeyExA,
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            KEY_QUERY_VALUE,
        };

        let (hive, subkey) = location.hive_and_key();
        
        let hkey = match hive {
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            _ => return Err(PersistenceError::Registry("Invalid hive".to_string())),
        };

        unsafe {
            let mut h_key: HKEY = ptr::null_mut();
            let subkey_c = std::ffi::CString::new(subkey)
                .map_err(|_| PersistenceError::InvalidPath("Invalid registry path".to_string()))?;

            let result = RegOpenKeyExA(
                hkey,
                subkey_c.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut h_key,
            );

            if result != ERROR_SUCCESS as i32 {
                return Err(PersistenceError::Registry(
                    format!("Failed to open registry key: {}", result),
                ));
            }

            let value_name = std::ffi::CString::new(name)
                .map_err(|_| PersistenceError::InvalidPath("Invalid entry name".to_string()))?;

            let query_result = RegQueryValueExA(
                h_key,
                value_name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            RegCloseKey(h_key);

            if query_result == ERROR_SUCCESS as i32 {
                Ok(true)
            } else if query_result == ERROR_FILE_NOT_FOUND as i32 {
                Ok(false)
            } else {
                Err(PersistenceError::Registry(
                    format!("Failed to query registry value: {}", query_result),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_availability() {
        let available = RegistryPersistence::is_available();
        assert!(available || cfg!(not(target_os = "windows")));
    }

    #[test]
    fn test_registry_key_location_paths() {
        assert!(RegistryKeyLocation::CurrentUserRun.path().contains("Run"));
        assert!(RegistryKeyLocation::LocalMachineRun.path().contains("Run"));
        assert!(RegistryKeyLocation::CurrentUserRunOnce.path().contains("RunOnce"));
        assert!(RegistryKeyLocation::LocalMachineRunOnce.path().contains("RunOnce"));
    }

    #[test]
    fn test_config_creation() {
        let config = RegistryPersistenceConfig::for_current_user(
            "TestEntry",
            "C:\\Program Files\\MyApp\\app.exe",
        );

        assert_eq!(config.name, "TestEntry");
        assert_eq!(config.executable_path, "C:\\Program Files\\MyApp\\app.exe");
        assert_eq!(config.location, RegistryKeyLocation::CurrentUserRun);
        assert!(config.arguments.is_none());
    }

    #[test]
    fn test_config_with_arguments() {
        let config = RegistryPersistenceConfig::for_current_user(
            "TestEntry",
            "C:\\app.exe",
        )
        .with_arguments("-silent --background");

        assert_eq!(config.arguments, Some("-silent --background".to_string()));
    }

    #[test]
    fn test_full_command_quoted() {
        let config = RegistryPersistenceConfig {
            name: "Test".to_string(),
            executable_path: "C:\\Program Files\\My App\\app.exe".to_string(),
            arguments: Some("-v".to_string()),
            location: RegistryKeyLocation::CurrentUserRun,
        };

        let cmd = config.full_command();
        assert!(cmd.starts_with('"'));
        assert!(cmd.contains("-v"));
    }

    #[test]
    fn test_full_command_unquoted() {
        let config = RegistryPersistenceConfig {
            name: "Test".to_string(),
            executable_path: "C:\\app.exe".to_string(),
            arguments: None,
            location: RegistryKeyLocation::CurrentUserRun,
        };

        let cmd = config.full_command();
        assert_eq!(cmd, "C:\\app.exe");
    }

    #[test]
    fn test_for_all_users() {
        let config = RegistryPersistenceConfig::for_all_users(
            "SystemEntry",
            "C:\\Windows\\System32\\app.exe",
        );

        assert_eq!(config.location, RegistryKeyLocation::LocalMachineRun);
    }

    #[test]
    fn test_not_available_on_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let config = RegistryPersistenceConfig::for_current_user("test", "/test");
            let result = RegistryPersistence::install(&config);
            assert!(result.is_err());
        }
    }
}
