//! Startup Folder Persistence
//!
//! Creates shortcuts in the Windows Startup folder for automatic execution at login.
//!
//! Startup folder locations:
//! - User: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
//! - All Users: %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp

use super::errors::PersistenceError;

/// Startup folder scope
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupScope {
    /// Current user only (no admin required)
    CurrentUser,
    /// All users (requires admin)
    AllUsers,
}

impl StartupScope {
    /// Get the startup folder path
    pub fn path(&self) -> Result<String, PersistenceError> {
        match self {
            Self::CurrentUser => {
                // %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
                let appdata = std::env::var("APPDATA")
                    .map_err(|_| PersistenceError::FileSystem(
                        "APPDATA environment variable not set".to_string(),
                    ))?;
                Ok(format!(
                    "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    appdata
                ))
            }
            Self::AllUsers => {
                // %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp
                let programdata = std::env::var("PROGRAMDATA")
                    .map_err(|_| PersistenceError::FileSystem(
                        "PROGRAMDATA environment variable not set".to_string(),
                    ))?;
                Ok(format!(
                    "{}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
                    programdata
                ))
            }
        }
    }
}

/// Configuration for startup folder persistence
#[derive(Debug, Clone)]
pub struct StartupFolderConfig {
    /// Name of the shortcut file (without .lnk extension)
    pub name: String,
    /// Full path to the executable
    pub executable_path: String,
    /// Optional command-line arguments
    pub arguments: Option<String>,
    /// Optional working directory
    pub working_directory: Option<String>,
    /// Optional description
    pub description: Option<String>,
    /// Optional icon path
    pub icon_path: Option<String>,
    /// Show window state (normal, minimized, maximized)
    pub show_window: ShowWindowMode,
    /// Scope (current user or all users)
    pub scope: StartupScope,
}

/// Window show state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowWindowMode {
    /// Normal window
    Normal,
    /// Minimized window
    Minimized,
    /// Maximized window
    Maximized,
    /// Hidden
    Hidden,
}

impl ShowWindowMode {
    /// Get the SW_SHOW value for this mode
    pub fn sw_value(&self) -> i32 {
        match self {
            Self::Normal => 1,  // SW_SHOWNORMAL
            Self::Minimized => 2, // SW_SHOWMINIMIZED
            Self::Maximized => 3, // SW_SHOWMAXIMIZED
            Self::Hidden => 0,   // SW_HIDE
        }
    }
}

impl StartupFolderConfig {
    /// Create a new config for current user
    pub fn for_current_user(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            working_directory: None,
            description: None,
            icon_path: None,
            show_window: ShowWindowMode::Normal,
            scope: StartupScope::CurrentUser,
        }
    }

    /// Create a new config for all users
    pub fn for_all_users(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            working_directory: None,
            description: None,
            icon_path: None,
            show_window: ShowWindowMode::Normal,
            scope: StartupScope::AllUsers,
        }
    }

    /// Set command-line arguments
    pub fn with_arguments(mut self, args: &str) -> Self {
        self.arguments = Some(args.to_string());
        self
    }

    /// Set working directory
    pub fn with_working_directory(mut self, dir: &str) -> Self {
        self.working_directory = Some(dir.to_string());
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set icon path
    pub fn with_icon(mut self, icon_path: &str) -> Self {
        self.icon_path = Some(icon_path.to_string());
        self
    }

    /// Set window show mode
    pub fn with_window_mode(mut self, mode: ShowWindowMode) -> Self {
        self.show_window = mode;
        self
    }
}

/// Startup folder persistence manager
pub struct StartupFolderPersistence;

impl StartupFolderPersistence {
    /// Check if startup folder persistence is available
    pub fn is_available() -> bool {
        cfg!(target_os = "windows")
    }

    /// Install startup folder persistence
    pub fn install(_config: &StartupFolderConfig) -> Result<super::PersistenceResult, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::install_windows(_config)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(PersistenceError::Internal(
                "Startup folder persistence is only available on Windows".to_string(),
            ))
        }
    }

    /// Remove startup folder persistence
    pub fn remove(_name: &str, _scope: StartupScope) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::remove_windows(_name, _scope)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(PersistenceError::Internal(
                "Startup folder persistence is only available on Windows".to_string(),
            ))
        }
    }

    /// Check if a startup entry exists
    pub fn exists(_name: &str, _scope: StartupScope) -> Result<bool, PersistenceError> {
        #[cfg(target_os = "windows")]
        {
            Self::exists_windows(_name, _scope)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(false)
        }
    }

    #[cfg(target_os = "windows")]
    fn install_windows(config: &StartupFolderConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::path::Path;
        use winapi::shared::winerror::S_OK;
        use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
        use winapi::um::objbase::COINIT_APARTMENTTHREADED;
        use winapi::um::shellapi::ShellExecuteA;
        use winapi::um::winbase::INFINITE;
        use winapi::shared::guiddef::{GUID, REFIID};
        use winapi::shared::minwindef::DWORD;
        use winapi::um::winnt::HRESULT;

        // Initialize COM
        unsafe {
            let co_init = CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED);
            if co_init != S_OK && co_init != 0 {
                // S_FALSE (0) is also acceptable
            }

            let result = Self::create_shortcut_windows(config);

            CoUninitialize();
            result
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn create_shortcut_windows(config: &StartupFolderConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use winapi::shared::guiddef::IID;
        use winapi::shared::winerror::S_OK;
        use winapi::um::combaseapi::CoCreateInstance;
        use winapi::um::objbase::CLSCTX_INPROC_SERVER;
        use winapi::um::shobjidl::{IShellLinkW, CLSID_ShellLink};
        use winapi::um::shellapi::IPersistFile;
        use winapi::shared::minwindef::MAX_PATH;

        // CLSID for ShellLink
        const CLSID_ShellLink: GUID = GUID {
            Data1: 0x00021401,
            Data2: 0x0000,
            Data3: 0x0000,
            Data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };

        // IID for IShellLinkW
        const IID_IShellLinkW: IID = IID {
            Data1: 0x000214F9,
            Data2: 0x0000,
            Data3: 0x0000,
            Data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };

        // IID for IPersistFile
        const IID_IPersistFile: IID = IID {
            Data1: 0x0000010B,
            Data2: 0x0000,
            Data3: 0x0000,
            Data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };

        let mut shell_link: *mut IShellLinkW = std::ptr::null_mut();
        
        // Create ShellLink object
        let hr = CoCreateInstance(
            &CLSID_ShellLink as *const _ as REFIID,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IShellLinkW as *const _ as REFIID,
            &mut shell_link as *mut _ as *mut _,
        );

        if hr != S_OK {
            return Err(PersistenceError::FileSystem(
                format!("Failed to create ShellLink object: 0x{:X}", hr),
            ));
        }

        // Convert paths to wide strings
        let exe_path_wide: Vec<u16> = OsStr::new(&config.executable_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let args_wide: Option<Vec<u16>> = config.arguments.as_ref().map(|args| {
            OsStr::new(args).encode_wide().chain(Some(0)).collect()
        });

        let work_dir_wide: Option<Vec<u16>> = config.working_directory.as_ref().map(|dir| {
            OsStr::new(dir).encode_wide().chain(Some(0)).collect()
        });

        let desc_wide: Option<Vec<u16>> = config.description.as_ref().map(|desc| {
            OsStr::new(desc).encode_wide().chain(Some(0)).collect()
        });

        // Set the path
        (*shell_link).SetPath(exe_path_wide.as_ptr());

        // Set arguments
        if let Some(ref args) = args_wide {
            (*shell_link).SetArguments(args.as_ptr());
        }

        // Set working directory
        if let Some(ref work_dir) = work_dir_wide {
            (*shell_link).SetWorkingDirectory(work_dir.as_ptr());
        }

        // Set description
        if let Some(ref desc) = desc_wide {
            (*shell_link).SetDescription(desc.as_ptr());
        }

        // Set show command
        (*shell_link).SetShowCmd(config.show_window.sw_value() as u32);

        // Get IPersistFile interface
        let mut persist_file: *mut IPersistFile = std::ptr::null_mut();
        let hr = (*shell_link).QueryInterface(
            &IID_IPersistFile as *const _ as REFIID,
            &mut persist_file as *mut _ as *mut _,
        );

        if hr != S_OK {
            return Err(PersistenceError::FileSystem(
                format!("Failed to get IPersistFile: 0x{:X}", hr),
            ));
        }

        // Get startup folder path
        let startup_path = config.scope.path()?;
        let shortcut_path = format!("{}\\{}.lnk", startup_path, config.name);

        // Convert shortcut path to wide string
        let shortcut_path_wide: Vec<u16> = OsStr::new(&shortcut_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        // Save the shortcut
        let hr = (*persist_file).Save(
            shortcut_path_wide.as_ptr(),
            1, // TRUE - remember the link
        );

        // Release COM objects
        (*persist_file).Release();
        (*shell_link).Release();

        if hr != S_OK {
            return Err(PersistenceError::FileSystem(
                format!("Failed to save shortcut: 0x{:X}", hr),
            ));
        }

        Ok(super::PersistenceResult {
            success: true,
            method: super::PersistenceMethod::StartupFolder,
            identifier: Some(config.name.clone()),
            cleanup_command: Some(format!(
                "del /F \"{}\\{}.lnk\"",
                startup_path, config.name
            )),
            error: None,
        })
    }

    #[cfg(target_os = "windows")]
    fn remove_windows(name: &str, scope: StartupScope) -> Result<bool, PersistenceError> {
        use std::fs;

        let startup_path = scope.path()?;
        let shortcut_path = format!("{}\\{}.lnk", startup_path, name);

        match fs::remove_file(&shortcut_path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(PersistenceError::FileSystem(
                format!("Failed to remove shortcut: {}", e),
            )),
        }
    }

    #[cfg(target_os = "windows")]
    fn exists_windows(name: &str, scope: StartupScope) -> Result<bool, PersistenceError> {
        use std::fs;

        let startup_path = scope.path()?;
        let shortcut_path = format!("{}\\{}.lnk", startup_path, name);

        Ok(Path::new(&shortcut_path).exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_availability() {
        let available = StartupFolderPersistence::is_available();
        assert!(available || cfg!(not(target_os = "windows")));
    }

    #[test]
    fn test_show_window_mode_values() {
        assert_eq!(ShowWindowMode::Normal.sw_value(), 1);
        assert_eq!(ShowWindowMode::Minimized.sw_value(), 2);
        assert_eq!(ShowWindowMode::Maximized.sw_value(), 3);
        assert_eq!(ShowWindowMode::Hidden.sw_value(), 0);
    }

    #[test]
    fn test_config_for_current_user() {
        let config = StartupFolderConfig::for_current_user(
            "TestApp",
            "C:\\Program Files\\MyApp\\app.exe",
        );

        assert_eq!(config.name, "TestApp");
        assert_eq!(config.scope, StartupScope::CurrentUser);
        assert_eq!(config.show_window, ShowWindowMode::Normal);
    }

    #[test]
    fn test_config_for_all_users() {
        let config = StartupFolderConfig::for_all_users(
            "SystemApp",
            "C:\\Windows\\System32\\app.exe",
        );

        assert_eq!(config.scope, StartupScope::AllUsers);
    }

    #[test]
    fn test_config_with_arguments() {
        let config = StartupFolderConfig::for_current_user("test", "C:\\app.exe")
            .with_arguments("-silent --background");

        assert_eq!(config.arguments, Some("-silent --background".to_string()));
    }

    #[test]
    fn test_config_with_working_directory() {
        let config = StartupFolderConfig::for_current_user("test", "C:\\app.exe")
            .with_working_directory("C:\\Program Files\\MyApp");

        assert_eq!(config.working_directory, Some("C:\\Program Files\\MyApp".to_string()));
    }

    #[test]
    fn test_config_with_description() {
        let config = StartupFolderConfig::for_current_user("test", "C:\\app.exe")
            .with_description("My Application");

        assert_eq!(config.description, Some("My Application".to_string()));
    }

    #[test]
    fn test_config_with_icon() {
        let config = StartupFolderConfig::for_current_user("test", "C:\\app.exe")
            .with_icon("C:\\app.ico");

        assert_eq!(config.icon_path, Some("C:\\app.ico".to_string()));
    }

    #[test]
    fn test_config_with_window_mode() {
        let config = StartupFolderConfig::for_current_user("test", "C:\\app.exe")
            .with_window_mode(ShowWindowMode::Minimized);

        assert_eq!(config.show_window, ShowWindowMode::Minimized);
    }

    #[test]
    fn test_scope_path_format() {
        // On Windows, this would return actual paths
        // On other platforms, it returns an error
        #[cfg(target_os = "windows")]
        {
            let path = StartupScope::CurrentUser.path();
            assert!(path.is_ok());
            assert!(path.unwrap().contains("Startup"));
        }
    }

    #[test]
    fn test_not_available_on_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let config = StartupFolderConfig::for_current_user("test", "/test");
            let result = StartupFolderPersistence::install(&config);
            assert!(result.is_err());
        }
    }
}
