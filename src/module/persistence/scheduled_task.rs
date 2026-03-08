//! Scheduled Task Persistence
//!
//! Creates scheduled tasks for automatic execution:
//! - Windows: Task Scheduler (schtasks)
//! - Linux: cron jobs
//!
//! Provides various trigger options (logon, startup, daily, etc.)

use super::errors::PersistenceError;

/// Task trigger types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskTrigger {
    /// Run at user logon
    AtLogon,
    /// Run at system startup
    AtStartup,
    /// Run at a specific time
    AtTime { hour: u8, minute: u8 },
    /// Run daily at a specific time
    Daily { hour: u8, minute: u8 },
    /// Run weekly on specific days
    Weekly { days: Vec<u8>, hour: u8, minute: u8 },
    /// Run on idle
    OnIdle,
    /// Run on event (Windows only)
    OnEvent { log: String, source: String, id: u32 },
}

impl TaskTrigger {
    /// Create a daily trigger at midnight
    pub fn daily_midnight() -> Self {
        Self::Daily { hour: 0, minute: 0 }
    }

    /// Create a daily trigger at noon
    pub fn daily_noon() -> Self {
        Self::Daily { hour: 12, minute: 0 }
    }

    /// Create a logon trigger
    pub fn at_logon() -> Self {
        Self::AtLogon
    }

    /// Create a startup trigger
    pub fn at_startup() -> Self {
        Self::AtStartup
    }
}

/// Task run level (privilege level)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunLevel {
    /// Run with standard user privileges
    Standard,
    /// Run with highest privileges (admin/root)
    Highest,
}

/// Configuration for scheduled task persistence
#[derive(Debug, Clone)]
pub struct ScheduledTaskConfig {
    /// Task name
    pub name: String,
    /// Full path to the executable
    pub executable_path: String,
    /// Optional command-line arguments
    pub arguments: Option<String>,
    /// Optional working directory
    pub working_directory: Option<String>,
    /// Task trigger
    pub trigger: TaskTrigger,
    /// Run level (privileges)
    pub run_level: TaskRunLevel,
    /// Hidden task (don't show in UI)
    pub hidden: bool,
    /// Allow task to run if on battery power (laptops)
    pub allow_battery: bool,
    /// Stop task if runs longer than this (seconds, 0 = never)
    pub execution_time_limit: u32,
    /// Delay before running (seconds)
    pub delay: u32,
}

impl ScheduledTaskConfig {
    /// Create a new config for a logon task
    pub fn at_logon(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            working_directory: None,
            trigger: TaskTrigger::AtLogon,
            run_level: TaskRunLevel::Standard,
            hidden: false,
            allow_battery: true,
            execution_time_limit: 0,
            delay: 0,
        }
    }

    /// Create a new config for a startup task
    pub fn at_startup(name: &str, executable_path: &str) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            working_directory: None,
            trigger: TaskTrigger::AtStartup,
            run_level: TaskRunLevel::Standard,
            hidden: false,
            allow_battery: true,
            execution_time_limit: 0,
            delay: 0,
        }
    }

    /// Create a new config for a daily task
    pub fn daily(name: &str, executable_path: &str, hour: u8, minute: u8) -> Self {
        Self {
            name: name.to_string(),
            executable_path: executable_path.to_string(),
            arguments: None,
            working_directory: None,
            trigger: TaskTrigger::Daily { hour, minute },
            run_level: TaskRunLevel::Standard,
            hidden: false,
            allow_battery: true,
            execution_time_limit: 0,
            delay: 0,
        }
    }

    /// Set the task to run with highest privileges
    pub fn with_highest_privileges(mut self) -> Self {
        self.run_level = TaskRunLevel::Highest;
        self
    }

    /// Set the task as hidden
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
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

    /// Set execution time limit in seconds
    pub fn with_time_limit(mut self, seconds: u32) -> Self {
        self.execution_time_limit = seconds;
        self
    }

    /// Set delay before running in seconds
    pub fn with_delay(mut self, seconds: u32) -> Self {
        self.delay = seconds;
        self
    }
}

/// Scheduled task persistence manager
pub struct ScheduledTaskPersistence;

impl ScheduledTaskPersistence {
    /// Check if scheduled task persistence is available
    pub fn is_available() -> bool {
        cfg!(any(target_os = "windows", target_os = "linux"))
    }

    /// Install scheduled task persistence
    pub fn install(config: &ScheduledTaskConfig) -> Result<super::PersistenceResult, PersistenceError> {
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
                "Scheduled task persistence is not available on this platform".to_string(),
            ))
        }
    }

    /// Remove scheduled task persistence
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
                "Scheduled task persistence is not available on this platform".to_string(),
            ))
        }
    }

    /// Check if a scheduled task exists
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

    #[cfg(target_os = "windows")]
    fn install_windows(config: &ScheduledTaskConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::process::Command;

        let mut cmd = Command::new("schtasks");
        cmd.arg("/Create")
            .arg("/F") // Force creation
            .arg("/TN")
            .arg(&config.name)
            .arg("/TR")
            .arg(config.executable_path.clone());

        // Add arguments if present
        if let Some(args) = &config.arguments {
            cmd.arg(args);
        }

        // Set trigger
        match &config.trigger {
            TaskTrigger::AtLogon => {
                cmd.arg("/SC").arg("ONLOGON");
            }
            TaskTrigger::AtStartup => {
                cmd.arg("/SC").arg("ONSTARTUP");
            }
            TaskTrigger::AtTime { hour, minute } => {
                cmd.arg("/SC").arg("ONCE")
                    .arg("/ST")
                    .arg(format!("{:02}:{:02}", hour, minute));
            }
            TaskTrigger::Daily { hour, minute } => {
                cmd.arg("/SC").arg("DAILY")
                    .arg("/ST")
                    .arg(format!("{:02}:{:02}", hour, minute));
            }
            TaskTrigger::Weekly { days, hour, minute } => {
                let day_str = days.iter()
                    .map(|d| match d {
                        1 => "MON", 2 => "TUE", 3 => "WED", 4 => "THU",
                        5 => "FRI", 6 => "SAT", 0 | 7 => "SUN",
                        _ => "MON",
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                cmd.arg("/SC").arg("WEEKLY")
                    .arg("/D")
                    .arg(day_str)
                    .arg("/ST")
                    .arg(format!("{:02}:{:02}", hour, minute));
            }
            TaskTrigger::OnIdle => {
                cmd.arg("/SC").arg("ONIDLE");
            }
            TaskTrigger::OnEvent { log, source, id } => {
                // Event triggers require XML definition
                return Err(PersistenceError::ScheduledTask(
                    "Event triggers require XML task definition - not implemented".to_string(),
                ));
            }
        }

        // Set run level
        if config.run_level == TaskRunLevel::Highest {
            cmd.arg("/RL").arg("HIGHEST");
        }

        // Set hidden
        if config.hidden {
            // Hidden is set in the XML, not via command line
            // For simplicity, we'll skip this for now
        }

        // Set delay
        if config.delay > 0 {
            cmd.arg("/DELAY").arg(format!("{}:00", config.delay / 60));
        }

        let output = cmd.output()
            .map_err(|e| PersistenceError::ScheduledTask(
                format!("Failed to execute schtasks: {}", e),
            ))?;

        if output.status.success() {
            Ok(super::PersistenceResult {
                success: true,
                method: super::PersistenceMethod::ScheduledTask,
                identifier: Some(config.name.clone()),
                cleanup_command: Some(format!("schtasks /Delete /TN \"{}\" /F", config.name)),
                error: None,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PersistenceError::ScheduledTask(
                format!("schtasks failed: {}", stderr),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn install_linux(config: &ScheduledTaskConfig) -> Result<super::PersistenceResult, PersistenceError> {
        use std::fs::File;
        use std::io::Write;
        use std::process::Command;

        // Get current user
        let _user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "root".to_string());

        // Build cron entry
        let cron_schedule = match &config.trigger {
            TaskTrigger::AtLogon | TaskTrigger::AtStartup => {
                // For logon/startup on Linux, we use @reboot
                "@reboot".to_string()
            }
            TaskTrigger::AtTime { hour, minute } => {
                format!("{} {} * * *", minute, hour)
            }
            TaskTrigger::Daily { hour, minute } => {
                format!("{} {} * * *", minute, hour)
            }
            TaskTrigger::Weekly { days, hour, minute } => {
                let day_str = days.iter()
                    .map(|d| match d {
                        0 => "0", 1 => "1", 2 => "2", 3 => "3",
                        4 => "4", 5 => "5", 6 => "6", 7 => "0",
                        _ => "*",
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{} {} * * {}", minute, hour, day_str)
            }
            TaskTrigger::OnIdle => {
                // Idle detection not directly supported in cron
                // Use a frequent check with idle detection in the script
                "*/5 * * * *".to_string()
            }
            TaskTrigger::OnEvent { .. } => {
                return Err(PersistenceError::ScheduledTask(
                    "Event triggers not supported on Linux".to_string(),
                ));
            }
        };

        // Build command
        let mut command = config.executable_path.clone();
        if let Some(args) = &config.arguments {
            command.push(' ');
            command.push_str(args);
        }
        if let Some(dir) = &config.working_directory {
            command = format!("cd {} && {}", dir, command);
        }

        let cron_entry = format!("{} {}\n", cron_schedule, command);

        // Get user's crontab
        // Try to edit crontab using crontab command
        let mut temp_file = std::env::temp_dir();
        temp_file.push(format!("cron_{}_{}", config.name, std::process::id()));
        
        // Read existing crontab
        let output = Command::new("crontab")
            .arg("-l")
            .output();

        let mut existing = String::new();
        if let Ok(out) = output {
            existing = String::from_utf8_lossy(&out.stdout).to_string();
        }

        // Remove existing entry with same name (marked with comment)
        let marker = format!("# PERSISTENCE: {}", config.name);
        let mut lines: Vec<&str> = existing.lines().collect();
        let mut new_lines = Vec::new();
        let mut skip_next = false;
        
        for line in lines.drain(..) {
            if skip_next {
                skip_next = false;
                continue;
            }
            if line.contains(&marker) {
                skip_next = true;
                continue;
            }
            new_lines.push(line);
        }

        // Add new entry
        new_lines.push(&marker);
        new_lines.push(&cron_entry);

        // Write to temp file
        let mut file = File::create(&temp_file)
            .map_err(|e| PersistenceError::FileSystem(
                format!("Failed to create temp file: {}", e),
            ))?;
        
        for line in new_lines {
            writeln!(file, "{}", line)
                .map_err(|e| PersistenceError::FileSystem(
                    format!("Failed to write to temp file: {}", e),
                ))?;
        }

        // Install crontab
        let output = Command::new("crontab")
            .arg(&temp_file)
            .output()
            .map_err(|e| PersistenceError::ScheduledTask(
                format!("Failed to install crontab: {}", e),
            ))?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_file);

        if output.status.success() {
            Ok(super::PersistenceResult {
                success: true,
                method: super::PersistenceMethod::ScheduledTask,
                identifier: Some(config.name.clone()),
                cleanup_command: Some(format!("crontab -l | grep -v '{}' | crontab -", config.name)),
                error: None,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PersistenceError::ScheduledTask(
                format!("crontab failed: {}", stderr),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn remove_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("schtasks")
            .args(["/Delete", "/TN", name, "/F"])
            .output()
            .map_err(|e| PersistenceError::ScheduledTask(
                format!("Failed to execute schtasks: {}", e),
            ))?;

        Ok(output.status.success())
    }

    #[cfg(target_os = "linux")]
    fn remove_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let marker = format!("PERSISTENCE: {}", name);
        
        // Read current crontab
        let output = Command::new("crontab")
            .arg("-l")
            .output();

        if let Ok(out) = output {
            let existing = String::from_utf8_lossy(&out.stdout);
            let mut new_lines = Vec::new();
            let mut skip_next = false;

            for line in existing.lines() {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if line.contains(&marker) {
                    skip_next = true;
                    continue;
                }
                new_lines.push(line);
            }

            // Write new crontab
            let mut temp_file = std::env::temp_dir();
            temp_file.push(format!("cron_remove_{}", std::process::id()));

            if let Ok(mut file) = std::fs::File::create(&temp_file) {
                use std::io::Write;
                for line in new_lines {
                    let _ = writeln!(file, "{}", line);
                }

                let install_output = Command::new("crontab")
                    .arg(&temp_file)
                    .output();

                let _ = std::fs::remove_file(&temp_file);

                return Ok(install_output.map_or(false, |o| o.status.success()));
            }
        }

        Ok(false)
    }

    #[cfg(target_os = "windows")]
    fn exists_windows(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("schtasks")
            .args(["/Query", "/TN", name])
            .output()
            .map_err(|e| PersistenceError::ScheduledTask(
                format!("Failed to execute schtasks: {}", e),
            ))?;

        Ok(output.status.success())
    }

    #[cfg(target_os = "linux")]
    fn exists_linux(name: &str) -> Result<bool, PersistenceError> {
        use std::process::Command;

        let output = Command::new("crontab")
            .arg("-l")
            .output()
            .map_err(|e| PersistenceError::ScheduledTask(
                format!("Failed to execute crontab: {}", e),
            ))?;

        let content = String::from_utf8_lossy(&output.stdout);
        let marker = format!("PERSISTENCE: {}", name);
        
        Ok(content.contains(&marker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_availability() {
        let available = ScheduledTaskPersistence::is_available();
        assert!(available || cfg!(not(any(target_os = "windows", target_os = "linux"))));
    }

    #[test]
    fn test_trigger_creation() {
        let logon = TaskTrigger::at_logon();
        assert!(matches!(logon, TaskTrigger::AtLogon));

        let startup = TaskTrigger::at_startup();
        assert!(matches!(startup, TaskTrigger::AtStartup));

        let midnight = TaskTrigger::daily_midnight();
        assert!(matches!(midnight, TaskTrigger::Daily { hour: 0, minute: 0 }));

        let noon = TaskTrigger::daily_noon();
        assert!(matches!(noon, TaskTrigger::Daily { hour: 12, minute: 0 }));
    }

    #[test]
    fn test_config_at_logon() {
        let config = ScheduledTaskConfig::at_logon(
            "TestLogon",
            "/path/to/executable",
        );

        assert_eq!(config.name, "TestLogon");
        assert!(matches!(config.trigger, TaskTrigger::AtLogon));
        assert_eq!(config.run_level, TaskRunLevel::Standard);
    }

    #[test]
    fn test_config_at_startup() {
        let config = ScheduledTaskConfig::at_startup(
            "TestStartup",
            "/path/to/executable",
        );

        assert!(matches!(config.trigger, TaskTrigger::AtStartup));
    }

    #[test]
    fn test_config_daily() {
        let config = ScheduledTaskConfig::daily(
            "TestDaily",
            "/path/to/executable",
            14,
            30,
        );

        assert!(matches!(config.trigger, TaskTrigger::Daily { hour: 14, minute: 30 }));
    }

    #[test]
    fn test_config_with_highest_privileges() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .with_highest_privileges();

        assert_eq!(config.run_level, TaskRunLevel::Highest);
    }

    #[test]
    fn test_config_hidden() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .hidden();

        assert!(config.hidden);
    }

    #[test]
    fn test_config_with_arguments() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .with_arguments("-silent");

        assert_eq!(config.arguments, Some("-silent".to_string()));
    }

    #[test]
    fn test_config_with_working_directory() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .with_working_directory("/tmp");

        assert_eq!(config.working_directory, Some("/tmp".to_string()));
    }

    #[test]
    fn test_config_with_time_limit() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .with_time_limit(3600);

        assert_eq!(config.execution_time_limit, 3600);
    }

    #[test]
    fn test_config_with_delay() {
        let config = ScheduledTaskConfig::at_logon("test", "/test")
            .with_delay(300);

        assert_eq!(config.delay, 300);
    }

    #[test]
    fn test_not_available_on_non_standard_platform() {
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let config = ScheduledTaskConfig::at_logon("test", "/test");
            let result = ScheduledTaskPersistence::install(&config);
            assert!(result.is_err());
        }
    }
}
