//! Anti-Sandbox Detection Module
//!
//! Detects sandbox and analysis environments by checking for:
//! - Known sandbox artifacts (Cuckoo, Joe Sandbox, Any.Run, etc.)
//! - Analysis tools and processes
//! - Low user activity (sandboxes often have minimal interaction)
//! - Short system uptime (freshly booted VMs)
//! - Minimal installed applications

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::EvasionError;

/// Sandbox detection module
pub struct AntiSandbox;

impl AntiSandbox {
    /// Check if running in a sandbox environment
    /// Returns true if any sandbox indicator is detected
    pub fn is_sandbox() -> bool {
        Self::is_cuckoo()
            || Self::is_joe_sandbox()
            || Self::is_any_run()
            || Self::is_hybrid_analysis()
            || Self::check_sandbox_artifacts()
            || Self::check_analysis_tools()
            || Self::check_uptime()
            || Self::check_installed_apps()
            || !Self::has_user_activity()
            || !Self::sleep_delay_check()
    }

    /// Check for Cuckoo sandbox indicators
    pub fn is_cuckoo() -> bool {
        // Check hostname
        if let Ok(hostname) = hostname::get() {
            let hostname_str = hostname.to_string_lossy().to_lowercase();
            if hostname_str.contains("cuckoo") {
                return true;
            }
        }

        // Check for Cuckoo files/directories
        let cuckoo_paths = [
            "C:\\cuckoo",
            "C:\\python27\\cuckoo",
            "C:\\cuckoo\\storage",
            "/opt/cuckoo",
            "/home/cuckoo",
        ];

        for path in &cuckoo_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        // Check for Cuckoo processes
        let cuckoo_processes = ["cuckoo", "cuckoo.py", "cuckood.py"];
        if Self::check_processes(&cuckoo_processes) {
            return true;
        }

        // Check registry (Windows)
        #[cfg(target_os = "windows")]
        {
            if Self::registry_key_exists("SOFTWARE\\Cuckoo") {
                return true;
            }
        }

        false
    }

    /// Check for Joe Sandbox indicators
    pub fn is_joe_sandbox() -> bool {
        // Check hostname
        if let Ok(hostname) = hostname::get() {
            let hostname_str = hostname.to_string_lossy().to_lowercase();
            if hostname_str.contains("joe") || hostname_str.contains("jsandbox") {
                return true;
            }
        }

        // Check for Joe Sandbox files
        let joe_paths = [
            "C:\\JoeSandbox",
            "C:\\Program Files\\JoeSandbox",
            "C:\\joe",
        ];

        for path in &joe_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        // Check for Joe Sandbox processes
        let joe_processes = ["joeboxserver.exe", "joeboxcontrol.exe"];
        if Self::check_processes(&joe_processes) {
            return true;
        }

        false
    }

    /// Check for Any.Run sandbox indicators
    pub fn is_any_run() -> bool {
        // Check hostname
        if let Ok(hostname) = hostname::get() {
            let hostname_str = hostname.to_string_lossy().to_lowercase();
            if hostname_str.contains("anyrun") || hostname_str.contains("any-run") {
                return true;
            }
        }

        // Check for Any.Run processes
        let anyrun_processes = ["anyrun", "anyrun.exe"];
        if Self::check_processes(&anyrun_processes) {
            return true;
        }

        // Check for Any.Run artifacts
        let anyrun_paths = [
            "C:\\AnyRun",
            "C:\\ProgramData\\AnyRun",
        ];

        for path in &anyrun_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        false
    }

    /// Check for Hybrid Analysis sandbox indicators
    pub fn is_hybrid_analysis() -> bool {
        // Check hostname
        if let Ok(hostname) = hostname::get() {
            let hostname_str = hostname.to_string_lossy().to_lowercase();
            if hostname_str.contains("hybrid") || hostname_str.contains("analysis") {
                return true;
            }
        }

        // Check for Hybrid Analysis processes
        let ha_processes = [
            "hybridanalysis.exe",
            "ha-loader.exe",
            "jre7\\bin\\java.exe", // Often used by HA
        ];
        if Self::check_processes(&ha_processes) {
            return true;
        }

        // Check for Hybrid Analysis artifacts
        let ha_paths = [
            "C:\\HybridAnalysis",
            "C:\\Program Files\\Hybrid Analysis",
        ];

        for path in &ha_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        false
    }

    /// Check for general sandbox artifacts
    pub fn check_sandbox_artifacts() -> bool {
        // Check for sandbox-specific files
        let sandbox_paths = [
            "C:\\sandbox",
            "C:\\Documents and Settings\\Administrator\\Desktop\\sandbox.txt",
            "C:\\user\\current\\desktop\\sample.txt",
            "C:\\malware",
            "C:\\test",
            "C:\\eval",
        ];

        for path in &sandbox_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        // Check for suspicious usernames
        if let Ok(username) = env::var("USERNAME").or_else(|_| env::var("USER")) {
            let username_lower = username.to_lowercase();
            let suspicious_usernames = [
                "sandbox",
                "test",
                "admin",
                "user",
                "malware",
                "analysis",
                "sample",
                "cuckoo",
                "joe",
            ];

            for suspicious in &suspicious_usernames {
                if username_lower.contains(suspicious) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for analysis and reverse engineering tools
    pub fn check_analysis_tools() -> bool {
        let analysis_tools = [
            // Debuggers
            "ida",
            "ida64",
            "idaq",
            "idaq64",
            "ollydbg",
            "ollydbg.exe",
            "x64dbg",
            "x64dbg.exe",
            "x32dbg",
            "windbg",
            "windbg.exe",
            "gdb",
            "gdbserver",
            "lldb",
            // Disassemblers/Analyzers
            "ghidra",
            "radare2",
            "r2",
            "binaryninja",
            // Process monitors
            "processhacker",
            "processhacker.exe",
            "procmon",
            "procmon.exe",
            "procexp",
            "procexp.exe",
            "wireshark",
            "wireshark.exe",
            "fiddler",
            "fiddler.exe",
            // Sandboxes
            "cuckoo",
            "joebox",
            "anyrun",
        ];

        Self::check_processes(&analysis_tools)
    }

    /// Check for user activity (sandboxes often have none)
    pub fn has_user_activity() -> bool {
        let mut activity_score = 0;

        // Check for mouse clicks (would require platform-specific APIs)
        // Simplified: check for user directories
        if let Ok(home) = env::var("HOME").or_else(|_| env::var("USERPROFILE")) {
            let home_path = Path::new(&home);

            // Check for Documents directory
            let documents = home_path.join("Documents");
            if documents.exists() {
                activity_score += 1;
            }

            // Check for Desktop directory
            let desktop = home_path.join("Desktop");
            if desktop.exists() {
                activity_score += 1;
            }

            // Check for Downloads directory
            let downloads = home_path.join("Downloads");
            if downloads.exists() {
                activity_score += 1;
            }

            // Check for Pictures directory
            let pictures = home_path.join("Pictures");
            if pictures.exists() {
                activity_score += 1;
            }
        }

        // Check for browser history
        if Self::get_browser_history_count() > 0 {
            activity_score += 2;
        }

        // Check for recent files
        if Self::has_recent_files() {
            activity_score += 1;
        }

        // Score < 2 suggests sandbox environment
        activity_score >= 2
    }

    /// Check system uptime (sandboxes are often freshly booted)
    pub fn check_uptime() -> bool {
        if let Some(uptime_ms) = Self::get_system_uptime() {
            // Less than 5 minutes (300,000 ms) is suspicious
            if uptime_ms < 300_000 {
                return true;
            }

            // Less than 10 minutes is also suspicious for production systems
            if uptime_ms < 600_000 {
                // Additional check: if uptime is very low, more suspicious
                if uptime_ms < 60_000 {
                    return true;
                }
            }
        }

        false
    }

    /// Check for minimal installed applications
    pub fn check_installed_apps() -> bool {
        let app_count = Self::get_installed_application_count();

        // Less than 10 applications is suspicious
        if app_count < 10 {
            return true;
        }

        // Less than 5 is very suspicious
        if app_count < 5 {
            return true;
        }

        false
    }

    /// Sleep delay check - sandboxes often skip or accelerate sleep
    pub fn sleep_delay_check() -> bool {
        let sleep_duration = std::time::Duration::from_millis(5000); // 5 seconds
        let start = std::time::Instant::now();
        std::thread::sleep(sleep_duration);
        let elapsed = start.elapsed();

        // If sleep was significantly shorter than expected (< 3 seconds),
        // sandbox may have accelerated time
        if elapsed < std::time::Duration::from_millis(3000) {
            return false;
        }

        // If sleep took more than 2x expected, might be debugger
        if elapsed > sleep_duration * 2 {
            return false;
        }

        true
    }

    // Helper functions

    fn check_processes(processes: &[&str]) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy().to_lowercase();

                    if name_str.parse::<u32>().is_err() {
                        continue;
                    }

                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        let comm = comm.trim().to_lowercase();
                        for proc in processes {
                            if comm.contains(proc) {
                                return true;
                            }
                        }
                    }

                    // Also check cmdline
                    let cmdline_path = entry.path().join("cmdline");
                    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                        let cmdline = cmdline.to_lowercase();
                        for proc in processes {
                            if cmdline.contains(proc) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("tasklist").output() {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for proc in processes {
                    if output_str.contains(proc) {
                        return true;
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("ps").arg("-ax").output() {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for proc in processes {
                    if output_str.contains(proc) {
                        return true;
                    }
                }
            }
        }

        false
    }

    #[cfg(target_os = "linux")]
    fn get_browser_history_count() -> usize {
        let mut count = 0;

        if let Ok(home) = env::var("HOME") {
            let home_path = Path::new(&home);

            // Chrome history
            let chrome_history = home_path.join(".config/google-chrome/Default/History");
            if chrome_history.exists() {
                count += 1;
            }

            // Firefox history
            let firefox_dir = home_path.join(".mozilla/firefox");
            if let Ok(entries) = fs::read_dir(&firefox_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let history = entry.path().join("places.sqlite");
                        if history.exists() {
                            count += 1;
                        }
                    }
                }
            }
        }

        count
    }

    #[cfg(target_os = "windows")]
    fn get_browser_history_count() -> usize {
        let mut count = 0;

        if let Ok(appdata) = env::var("APPDATA") {
            // Chrome history
            let chrome_history = Path::new(&appdata)
                .join("..\\Local\\Google\\Chrome\\User Data\\Default\\History");
            if chrome_history.exists() {
                count += 1;
            }

            // Firefox history
            let firefox_dir = Path::new(&appdata).join("..\\Mozilla\\Firefox\\Profiles");
            if let Ok(entries) = fs::read_dir(&firefox_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let history = entry.path().join("places.sqlite");
                        if history.exists() {
                            count += 1;
                        }
                    }
                }
            }
        }

        count
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_browser_history_count() -> usize {
        0
    }

    fn has_recent_files() -> bool {
        // Check for recently modified files in common directories
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let one_day_secs = 86400;

        if let Ok(home) = env::var("HOME").or_else(|_| env::var("USERPROFILE")) {
            let home_path = Path::new(&home);

            // Check Desktop for recent files
            let desktop = home_path.join("Desktop");
            if let Ok(entries) = fs::read_dir(&desktop) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(secs) = modified.duration_since(UNIX_EPOCH) {
                                if now - secs.as_secs() < one_day_secs {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Check Documents for recent files
            let documents = home_path.join("Documents");
            if let Ok(entries) = fs::read_dir(&documents) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(secs) = modified.duration_since(UNIX_EPOCH) {
                                if now - secs.as_secs() < one_day_secs {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    #[cfg(target_os = "linux")]
    fn get_system_uptime() -> Option<u64> {
        // Read from /proc/uptime
        if let Ok(uptime_content) = fs::read_to_string("/proc/uptime") {
            let uptime_secs = uptime_content
                .split_whitespace()
                .next()?
                .parse::<f64>()
                .ok()?;
            return Some((uptime_secs * 1000.0) as u64);
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn get_system_uptime() -> Option<u64> {
        // Use GetTickCount64 via command
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-Command", "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime"])
            .output()
        {
            // Parse output - simplified, would need proper parsing
            return Some(0);
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn get_system_uptime() -> Option<u64> {
        if let Ok(output) = std::process::Command::new("uptime").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse uptime output - simplified
            if output_str.contains("up") {
                // Would need proper parsing
                return Some(0);
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn get_system_uptime() -> Option<u64> {
        None
    }

    #[cfg(target_os = "linux")]
    fn get_installed_application_count() -> usize {
        let mut count = 0;

        // Check /usr/bin
        if let Ok(entries) = fs::read_dir("/usr/bin") {
            count += entries.count();
        }

        // Check /usr/share/applications for .desktop files
        if let Ok(entries) = fs::read_dir("/usr/share/applications") {
            count += entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "desktop"))
                .count();
        }

        count
    }

    #[cfg(target_os = "windows")]
    fn get_installed_application_count() -> usize {
        // Check registry for installed applications
        let mut count = 0;

        let registry_paths = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ];

        for path in &registry_paths {
            if let Ok(entries) = Self::read_registry_subkeys(path) {
                count += entries.len();
            }
        }

        count
    }

    #[cfg(target_os = "macos")]
    fn get_installed_application_count() -> usize {
        let mut count = 0;

        // Check /Applications
        if let Ok(entries) = fs::read_dir("/Applications") {
            count += entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "app"))
                .count();
        }

        count
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn get_installed_application_count() -> usize {
        0
    }

    #[cfg(target_os = "windows")]
    fn read_registry_subkeys(path: &str) -> Result<Vec<String>, EvasionError> {
        use std::process::Command;

        let output = Command::new("reg")
            .args(["query", &format!("HKLM\\{}", path)])
            .output()
            .map_err(|e| EvasionError::Registry(e.to_string()))?;

        let mut keys = Vec::new();
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("HKEY") || line.trim().is_empty() {
                    continue;
                }
                if let Some(key) = line.split_whitespace().next() {
                    keys.push(key.to_string());
                }
            }
        }

        Ok(keys)
    }

    #[cfg(target_os = "windows")]
    fn registry_key_exists(path: &str) -> bool {
        use std::process::Command;

        Command::new("reg")
            .args(["query", &format!("HKLM\\{}", path)])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn registry_key_exists(_path: &str) -> bool {
        false
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn read_registry_subkeys(_path: &str) -> Result<Vec<String>, EvasionError> {
        Ok(Vec::new())
    }
}

use std::env;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_detection_api() {
        // These should not panic
        let _is_sandbox = AntiSandbox::is_sandbox();
        let _is_cuckoo = AntiSandbox::is_cuckoo();
        let _is_joe = AntiSandbox::is_joe_sandbox();
        let _is_anyrun = AntiSandbox::is_any_run();
        let _is_hybrid = AntiSandbox::is_hybrid_analysis();
        let _artifacts = AntiSandbox::check_sandbox_artifacts();
        let _tools = AntiSandbox::check_analysis_tools();
        let _uptime = AntiSandbox::check_uptime();
        let _apps = AntiSandbox::check_installed_apps();
        let _activity = AntiSandbox::has_user_activity();
        let _sleep = AntiSandbox::sleep_delay_check();
    }

    #[test]
    fn test_sleep_delay_check() {
        // This test will take 5 seconds
        let result = AntiSandbox::sleep_delay_check();
        // On a normal system, should return true
        // In a sandbox that accelerates time, might return false
        let _ = result;
    }

    #[test]
    fn test_uptime_check() {
        let result = AntiSandbox::check_uptime();
        // Should return false on normal systems (uptime > 5 minutes)
        // Should return true on freshly booted sandboxes
        let _ = result;
    }
}
