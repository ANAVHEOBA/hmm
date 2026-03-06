use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use super::errors::ProcessingError;

/// AES-256-GCM encryption key (32 bytes)
pub type AesKey = [u8; 32];

/// Nonce size for AES-GCM (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// AES-256-GCM cipher for secure encryption
#[derive(Debug, Clone)]
pub struct AesCipher {
    key: AesKey,
}

impl AesCipher {
    /// Create a new AES cipher with the given key
    pub fn new(key: AesKey) -> Result<Self, ProcessingError> {
        Ok(Self { key })
    }

    /// Generate a random 256-bit AES key
    pub fn generate_key() -> AesKey {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate a key from a password using PBKDF2
    pub fn key_from_password(password: &str, salt: &[u8]) -> AesKey {
        // Simple key derivation - for production use pbkdf2 or argon2
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        
        let mut hasher = DefaultHasher::new();
        hasher.write(password.as_bytes());
        hasher.write(salt);
        let hash = hasher.finish();
        
        // Expand to 32 bytes
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&hash.to_le_bytes());
        
        // Mix in more entropy
        let mut hasher2 = DefaultHasher::new();
        hasher2.write(&hash.to_le_bytes());
        hasher2.write(salt);
        hasher2.write(password.as_bytes());
        let hash2 = hasher2.finish();
        key[8..16].copy_from_slice(&hash2.to_le_bytes());
        
        // Fill remaining bytes with salt-derived data
        for i in 0..16 {
            key[16 + i] = salt[i % salt.len()] ^ (hash as u8);
        }
        
        key
    }

    /// Encrypt data with AES-256-GCM
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| ProcessingError::Encryption(format!("Failed to initialize cipher: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| ProcessingError::Encryption(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt data with AES-256-GCM
    /// Expects: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, ProcessingError> {
        if encrypted.len() < NONCE_SIZE {
            return Err(ProcessingError::Encryption(
                "Encrypted data too short".to_string(),
            ));
        }

        // Extract nonce
        let nonce_bytes = &encrypted[..NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);

        // Extract ciphertext
        let ciphertext = &encrypted[NONCE_SIZE..];

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| ProcessingError::Encryption(format!("Failed to initialize cipher: {}", e)))?;

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| ProcessingError::Encryption(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

/// Legacy wrapper for backward compatibility
#[deprecated(note = "Use AesCipher instead")]
pub struct XorCipher {
    key: Vec<u8>,
}

#[allow(deprecated)]
impl XorCipher {
    pub fn new(key: Vec<u8>) -> Result<Self, ProcessingError> {
        Ok(Self { key })
    }

    pub fn encrypt(&self, data: &[u8], _nonce: u64) -> Vec<u8> {
        data.iter().zip(self.key.iter().cycle()).map(|(&d, &k)| d ^ k).collect()
    }

    pub fn decrypt(&self, data: &[u8], _nonce: u64) -> Vec<u8> {
        self.encrypt(data, _nonce) // XOR is symmetric
    }
}
