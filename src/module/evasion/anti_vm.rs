//! Anti-VM Detection Module
//!
//! Detects virtual machine environments by checking for:
//! - VM-specific drivers and services
//! - VM-specific hardware identifiers
//! - VM-specific MAC address prefixes
//! - VM-specific processes
//! - VM-specific registry keys (Windows)
//! - Low resource configurations typical of VMs

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Detected VM type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VMType {
    VirtualBox,
    VMware,
    Xen,
    QEMU,
    KVM,
    HyperV,
    Parallels,
    Unknown,
    None,
}

impl fmt::Display for VMType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMType::VirtualBox => write!(f, "VirtualBox"),
            VMType::VMware => write!(f, "VMware"),
            VMType::Xen => write!(f, "Xen"),
            VMType::QEMU => write!(f, "QEMU"),
            VMType::KVM => write!(f, "KVM"),
            VMType::HyperV => write!(f, "Hyper-V"),
            VMType::Parallels => write!(f, "Parallels"),
            VMType::Unknown => write!(f, "Unknown"),
            VMType::None => write!(f, "None"),
        }
    }
}

/// Virtual Machine detection module
pub struct AntiVM;

impl AntiVM {
    /// Check if running in a virtual machine
    /// Returns true if any VM indicator is detected
    pub fn is_virtual_machine() -> bool {
        Self::has_vm_drivers()
            || Self::has_vm_hardware()
            || Self::has_vm_mac_address()
            || Self::has_vm_processes()
            || Self::has_vm_registry_keys()
            || Self::has_low_resources()
    }

    /// Get the detected VM type
    pub fn get_vm_type() -> VMType {
        // Check drivers first (most reliable)
        if Self::has_vm_drivers() {
            let drivers = Self::get_vm_driver_names();
            if drivers.iter().any(|d| d.contains("VBox") || d.contains("vbox")) {
                return VMType::VirtualBox;
            }
            if drivers.iter().any(|d| d.contains("vmware") || d.contains("vmci")) {
                return VMType::VMware;
            }
            if drivers.iter().any(|d| d.contains("xen")) {
                return VMType::Xen;
            }
            if drivers.iter().any(|d| d.contains("virtio") || d.contains("kvm")) {
                return VMType::KVM;
            }
        }

        // Check MAC address
        if let Some(mac) = Self::get_mac_address() {
            let mac_upper = mac.to_uppercase();
            if mac_upper.starts_with("08:00:27") || mac_upper.starts_with("00:1C:42") {
                return VMType::VirtualBox;
            }
            if mac_upper.starts_with("00:0C:29")
                || mac_upper.starts_with("00:05:69")
                || mac_upper.starts_with("00:50:56")
            {
                return VMType::VMware;
            }
            if mac_upper.starts_with("00:16:3E") {
                return VMType::Xen;
            }
            if mac_upper.starts_with("00:15:5D") {
                return VMType::HyperV;
            }
        }

        // Check hardware/bios
        if let Some(bios) = Self::get_bios_vendor() {
            let bios_lower = bios.to_lowercase();
            if bios_lower.contains("innotek") {
                return VMType::VirtualBox;
            }
            if bios_lower.contains("vmware") {
                return VMType::VMware;
            }
            if bios_lower.contains("xen") {
                return VMType::Xen;
            }
            if bios_lower.contains("qemu") {
                return VMType::QEMU;
            }
        }

        // Check processes
        if Self::has_vm_processes() {
            let processes = Self::get_vm_process_names();
            if processes.iter().any(|p| p.contains("vbox")) {
                return VMType::VirtualBox;
            }
            if processes.iter().any(|p| p.contains("vmware") || p.contains("vmtools")) {
                return VMType::VMware;
            }
        }

        VMType::None
    }

    /// Check for VM-specific drivers
    pub fn has_vm_drivers() -> bool {
        let vm_drivers = [
            "VBoxMouse",
            "VBoxGuest",
            "VBoxService",
            "VBoxSF",
            "vmmouse",
            "VMTools",
            "VMware Service",
            "vmci",
            "vmmemctl",
            "virtio_pci",
            "virtio_net",
            "virtio_blk",
            "xenbus",
            "xenfs",
            "hv_kvp_daemon",
            "hv_vss_daemon",
        ];

        Self::check_drivers(&vm_drivers)
    }

    /// Get names of detected VM drivers
    pub fn get_vm_driver_names() -> Vec<String> {
        let vm_drivers = [
            "VBoxMouse", "VBoxGuest", "VBoxService", "VBoxSF", "vmmouse", "VMTools",
            "VMware Service", "vmci", "vmmemctl", "virtio_pci", "virtio_net",
            "virtio_blk", "xenbus", "xenfs", "hv_kvp_daemon", "hv_vss_daemon",
        ];

        Self::get_detected_drivers(&vm_drivers)
    }

    /// Check for VM-specific hardware indicators
    pub fn has_vm_hardware() -> bool {
        // Check BIOS vendor
        if let Some(bios) = Self::get_bios_vendor() {
            let bios_lower = bios.to_lowercase();
            if bios_lower.contains("innotek")
                || bios_lower.contains("vmware")
                || bios_lower.contains("xen")
                || bios_lower.contains("qemu")
                || bios_lower.contains("bochs")
            {
                return true;
            }
        }

        // Check BIOS version for VM indicators
        if let Some(version) = Self::get_bios_version() {
            let version_lower = version.to_lowercase();
            if version_lower.contains("virtualbox")
                || version_lower.contains("vmware")
                || version_lower.contains("xen")
                || version_lower.contains("qemu")
            {
                return true;
            }
        }

        // Check for VM-specific hardware
        #[cfg(target_os = "linux")]
        {
            // Check DMI tables for VM indicators
            if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
                let product_lower = product.to_lowercase();
                if product_lower.contains("virtualbox")
                    || product_lower.contains("vmware")
                    || product_lower.contains("xen")
                    || product_lower.contains("qemu")
                    || product_lower.contains("kvm")
                    || product_lower.contains("virtual machine")
                {
                    return true;
                }
            }

            // Check hypervisor CPU flag
            if let Ok(flags) = fs::read_to_string("/proc/cpuinfo") {
                if flags.contains("hypervisor") {
                    return true;
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Check WMI for VM indicators
            if let Ok(value) = Self::read_registry_string(
                "HARDWARE\\DESCRIPTION\\System\\BIOS",
                "SystemManufacturer",
            ) {
                let value_lower = value.to_lowercase();
                if value_lower.contains("microsoft")
                    || value_lower.contains("vmware")
                    || value_lower.contains("innotek")
                {
                    return true;
                }
            }
        }

        false
    }

    /// Check for VM-specific MAC address prefixes
    pub fn has_vm_mac_address() -> bool {
        if let Some(mac) = Self::get_mac_address() {
            let mac_upper = mac.to_uppercase();

            let vm_prefixes = [
                "00:0C:29", // VMware
                "00:05:69", // VMware
                "00:50:56", // VMware
                "08:00:27", // VirtualBox
                "00:1C:42", // Parallels
                "00:16:3E", // Xen
                "0A:00:27", // VirtualBox
                "00:15:5D", // Hyper-V
                "00:1D:D8", // Hyper-V
                "00:15:17", // QEMU
            ];

            for prefix in vm_prefixes {
                if mac_upper.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }

    /// Get the MAC address of the primary network interface
    pub fn get_mac_address() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            // Try to read from /sys/class/net
            if let Ok(entries) = fs::read_dir("/sys/class/net") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name == "lo" {
                        continue; // Skip loopback
                    }

                    let addr_path = entry.path().join("address");
                    if let Ok(mac) = fs::read_to_string(&addr_path) {
                        let mac = mac.trim().to_string();
                        if mac != "00:00:00:00:00:00" && !mac.is_empty() {
                            return Some(mac);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Use ipconfig to get MAC address
            if let Ok(output) = std::process::Command::new("ipconfig")
                .arg("/all")
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let line = line.trim();
                    if line.contains("Physical Address") {
                        if let Some(mac) = line.split(':').nth(1) {
                            let mac = mac.trim().to_string();
                            if !mac.is_empty() {
                                return Some(mac.replace('-', ":"));
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("ifconfig")
                .arg("-a")
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("ether") {
                        if let Some(mac) = line.split_whitespace().nth(1) {
                            return Some(mac.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Check for VM-specific processes
    pub fn has_vm_processes() -> bool {
        let vm_processes = [
            "vboxservice.exe",
            "vboxtray.exe",
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "vmwareuser.exe",
            "xenclient.exe",
            "qemu-ga.exe",
            "hvservice.exe",
        ];

        Self::check_processes(&vm_processes)
    }

    /// Get names of detected VM processes
    pub fn get_vm_process_names() -> Vec<String> {
        let vm_processes = [
            "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
            "vmwareuser.exe", "xenclient.exe", "qemu-ga.exe", "hvservice.exe",
        ];

        Self::get_detected_processes(&vm_processes)
    }

    /// Check for VM-specific registry keys (Windows)
    pub fn has_vm_registry_keys() -> bool {
        #[cfg(target_os = "windows")]
        {
            let vm_registry_keys = [
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                "SOFTWARE\\VMware, Inc.\\VMware Tools",
                "SOFTWARE\\XenProject Tools",
                "SOFTWARE\\QEMU Guest Agent",
                "HARDWARE\\ACPI\\DSDT\\VBOX__",
                "HARDWARE\\ACPI\\FADT\\VBOX__",
                "HARDWARE\\ACPI\\RSDT\\VBOX__",
            ];

            for key in vm_registry_keys {
                if Self::registry_key_exists(key) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for low resource configuration (typical of VMs)
    pub fn has_low_resources() -> bool {
        // Check CPU count
        let cpu_count = num_cpus::get();
        if cpu_count < 2 {
            return true;
        }

        // Check RAM amount
        if let Some(total_ram) = Self::get_total_memory() {
            // Less than 2GB RAM is suspicious
            if total_ram < 2 * 1024 * 1024 * 1024 {
                return true;
            }
        }

        false
    }

    // Platform-specific helper functions

    #[cfg(target_os = "linux")]
    fn check_drivers(drivers: &[&str]) -> bool {
        for driver in drivers {
            // Check if driver module exists
            let module_path = format!("/sys/module/{}", driver.to_lowercase());
            if Path::new(&module_path).exists() {
                return true;
            }

            // Check /proc/modules
            if let Ok(modules) = fs::read_to_string("/proc/modules") {
                if modules.contains(&driver.to_lowercase()) {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    fn check_drivers(drivers: &[&str]) -> bool {
        for driver in drivers {
            let key_path = format!("SYSTEM\\CurrentControlSet\\Services\\{}", driver);
            if Self::registry_key_exists(&key_path) {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn check_drivers(_drivers: &[&str]) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn get_detected_drivers(drivers: &[&str]) -> Vec<String> {
        let mut detected = Vec::new();
        for driver in drivers {
            let module_path = format!("/sys/module/{}", driver.to_lowercase());
            if Path::new(&module_path).exists() {
                detected.push(driver.to_string());
            }
        }
        detected
    }

    #[cfg(target_os = "windows")]
    fn get_detected_drivers(drivers: &[&str]) -> Vec<String> {
        let mut detected = Vec::new();
        for driver in drivers {
            let key_path = format!("SYSTEM\\CurrentControlSet\\Services\\{}", driver);
            if Self::registry_key_exists(&key_path) {
                detected.push(driver.to_string());
            }
        }
        detected
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_detected_drivers(_drivers: &[&str]) -> Vec<String> {
        Vec::new()
    }

    #[cfg(target_os = "linux")]
    fn check_processes(processes: &[&str]) -> bool {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_lowercase();

                // Check if it's a PID directory
                if name_str.parse::<u32>().is_err() {
                    continue;
                }

                let comm_path = entry.path().join("comm");
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let comm = comm.trim().to_lowercase();
                    for proc in processes {
                        if comm.contains(&proc.to_lowercase().replace(".exe", "")) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    fn check_processes(processes: &[&str]) -> bool {
        // Use tasklist command
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in processes {
                if output_str.contains(&proc.to_lowercase()) {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn check_processes(_processes: &[&str]) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn get_detected_processes(processes: &[&str]) -> Vec<String> {
        let mut detected = HashSet::new();
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
                        let proc_name = proc.to_lowercase().replace(".exe", "");
                        if comm.contains(&proc_name) {
                            detected.insert(proc.to_string());
                        }
                    }
                }
            }
        }
        detected.into_iter().collect()
    }

    #[cfg(target_os = "windows")]
    fn get_detected_processes(processes: &[&str]) -> Vec<String> {
        let mut detected = Vec::new();
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in processes {
                if output_str.contains(&proc.to_lowercase()) {
                    detected.push(proc.to_string());
                }
            }
        }
        detected
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_detected_processes(_processes: &[&str]) -> Vec<String> {
        Vec::new()
    }

    #[cfg(target_os = "linux")]
    fn get_bios_vendor() -> Option<String> {
        fs::read_to_string("/sys/class/dmi/id/bios_vendor").ok()
    }

    #[cfg(target_os = "windows")]
    fn get_bios_vendor() -> Option<String> {
        Self::read_registry_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor")
    }

    #[cfg(target_os = "macos")]
    fn get_bios_vendor() -> Option<String> {
        if let Ok(output) = std::process::Command::new("system_profiler")
            .arg("SPHardwareDataType")
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("Boot ROM Version") {
                    return Some(line.split(':').nth(1)?.trim().to_string());
                }
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn get_bios_vendor() -> Option<String> {
        None
    }

    #[cfg(target_os = "linux")]
    fn get_bios_version() -> Option<String> {
        fs::read_to_string("/sys/class/dmi/id/bios_version").ok()
    }

    #[cfg(target_os = "windows")]
    fn get_bios_version() -> Option<String> {
        Self::read_registry_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion")
    }

    #[cfg(target_os = "macos")]
    fn get_bios_version() -> Option<String> {
        Self::get_bios_vendor() // Same as vendor on macOS
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn get_bios_version() -> Option<String> {
        None
    }

    #[cfg(target_os = "linux")]
    fn get_total_memory() -> Option<u64> {
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
        None
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn get_total_memory() -> Option<u64> {
        // Would use sysinfo crate for full cross-platform support
        // For now, return None
        None
    }

    #[cfg(target_os = "windows")]
    fn registry_key_exists(path: &str) -> bool {
        use std::process::Command;

        // Use reg query command
        Command::new("reg")
            .args(["query", &format!("HKLM\\{}", path)])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "windows")]
    fn read_registry_string(path: &str, value: &str) -> Option<String> {
        use std::process::Command;

        let output = Command::new("reg")
            .args(["query", &format!("HKLM\\{}", path), "/v", value])
            .output()
            .ok()?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains(value) {
                    return Some(
                        line.split_whitespace()
                            .skip(2)
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn registry_key_exists(_path: &str) -> bool {
        false
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn read_registry_string(_path: &str, _value: &str) -> Option<String> {
        None
    }
}

use std::fmt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_detection_api() {
        // These should not panic
        let _is_vm = AntiVM::is_virtual_machine();
        let _vm_type = AntiVM::get_vm_type();
        let _has_drivers = AntiVM::has_vm_drivers();
        let _has_hardware = AntiVM::has_vm_hardware();
        let _has_mac = AntiVM::has_vm_mac_address();
        let _has_processes = AntiVM::has_vm_processes();
        let _has_registry = AntiVM::has_vm_registry_keys();
        let _has_low_resources = AntiVM::has_low_resources();
    }

    #[test]
    fn test_mac_address_retrieval() {
        // Should return Some or None without panicking
        let _mac = AntiVM::get_mac_address();
    }

    #[test]
    fn test_bios_info_retrieval() {
        // Should return Some or None without panicking
        let _vendor = AntiVM::get_bios_vendor();
        let _version = AntiVM::get_bios_version();
    }

    #[test]
    fn test_memory_detection() {
        // Should return Some or None without panicking
        let _memory = AntiVM::get_total_memory();
    }
}
