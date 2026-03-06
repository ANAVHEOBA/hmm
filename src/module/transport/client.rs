use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;

use log::{debug, info, warn};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use super::config::TransportConfig;
use super::errors::TransportError;
use super::payload::{UploadRequest, UploadResponse};

pub struct TransportClient {
    config: TransportConfig,
    tls_config: Option<Arc<ClientConfig>>,
}

impl TransportClient {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        config.validate()?;
        
        // Initialize TLS config if HTTPS might be used
        let tls_config = if config.endpoint.as_ref().map_or(false, |e| e.starts_with("https://")) {
            Some(Self::create_tls_config()?)
        } else {
            None
        };
        
        Ok(Self { config, tls_config })
    }
    
    /// Create TLS configuration with webpki roots
    fn create_tls_config() -> Result<Arc<ClientConfig>, TransportError> {
        use rustls::RootCertStore;
        
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        Ok(Arc::new(config))
    }

    pub fn upload(&self, request: &UploadRequest) -> Result<UploadResponse, TransportError> {
        if !self.config.enabled {
            return Ok(UploadResponse::skipped());
        }

        let attempts = self.config.max_retries.saturating_add(1);
        let mut last_error: Option<TransportError> = None;

        for attempt in 1..=attempts {
            debug!(
                "upload attempt {}/{} to {:?}",
                attempt,
                attempts,
                self.config.endpoint
            );
            match self.upload_once(request) {
                Ok(response) => {
                    if attempt > 1 {
                        info!("upload succeeded on retry attempt {}", attempt);
                    }
                    return Ok(response);
                }
                Err(err) => {
                    let should_retry = is_retryable(&err) && attempt < attempts;
                    warn!(
                        "upload attempt {} failed (retryable={}): {}",
                        attempt, should_retry, err
                    );
                    last_error = Some(err);
                    if should_retry {
                        thread::sleep(self.config.retry_backoff);
                        continue;
                    }
                    break;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            TransportError::Protocol("upload failed without explicit error".to_string())
        }))
    }

    fn upload_once(&self, request: &UploadRequest) -> Result<UploadResponse, TransportError> {
        let endpoint = self
            .config
            .endpoint
            .as_deref()
            .ok_or_else(|| TransportError::InvalidConfig("endpoint is required".to_string()))?;

        let parsed = parse_http_endpoint(endpoint)?;
        let addr = format!("{}:{}", parsed.host, parsed.port);
        let socket_addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| TransportError::InvalidEndpoint("could not resolve host".to_string()))?;

        // Connect via TCP
        let tcp_stream = TcpStream::connect_timeout(&socket_addr, self.config.timeout)?;
        tcp_stream.set_read_timeout(Some(self.config.timeout))?;
        tcp_stream.set_write_timeout(Some(self.config.timeout))?;

        // Wrap in TLS if HTTPS
        let mut stream: TransportStream = if parsed.is_https {
            let tls_config = self.tls_config.as_ref()
                .ok_or_else(|| TransportError::Protocol("TLS config not initialized".to_string()))?;
            
            let server_name = ServerName::try_from(parsed.host.as_str())
                .map_err(|e| TransportError::InvalidEndpoint(format!("invalid hostname: {}", e)))?
                .to_owned();
            
            let tls_conn = rustls::ClientConnection::new(Arc::clone(tls_config), server_name)
                .map_err(|e| TransportError::Protocol(format!("TLS connection failed: {}", e)))?;
            
            TransportStream::Https(tls_conn, tcp_stream)
        } else {
            TransportStream::Http(tcp_stream)
        };

        // Build HTTP request
        let mut http = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            parsed.path,
            parsed.host,
            request.content_type,
            request.payload.len()
        );
        if let Some(api_key) = &self.config.api_key {
            http.push_str(&format!("X-API-Key: {api_key}\r\n"));
        }
        http.push_str("\r\n");

        stream.write_all(http.as_bytes())?;
        stream.write_all(&request.payload)?;
        stream.flush()?;

        let mut raw_response = Vec::new();
        stream.read_to_end(&mut raw_response)?;
        let (status_code, body) = parse_http_response(&raw_response)?;

        if !(200..300).contains(&status_code) {
            return Err(TransportError::UploadFailed(status_code));
        }

        Ok(UploadResponse {
            uploaded: true,
            status_code: Some(status_code),
            body,
        })
    }
}

fn is_retryable(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::Io(_) | TransportError::Protocol(_) | TransportError::UploadFailed(_)
    )
}

/// Enum to handle both HTTP and HTTPS streams
enum TransportStream {
    Http(TcpStream),
    Https(rustls::ClientConnection, TcpStream),
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TransportStream::Http(stream) => stream.write(buf),
            TransportStream::Https(conn, stream) => {
                // Complete TLS handshake if needed
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                
                let len = conn.writer().write(buf)?;
                
                // Flush TLS data to socket
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                
                Ok(len)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TransportStream::Http(stream) => stream.flush(),
            TransportStream::Https(conn, stream) => {
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                stream.flush()
            }
        }
    }
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TransportStream::Http(stream) => stream.read(buf),
            TransportStream::Https(conn, stream) => {
                // Complete TLS handshake if needed
                while conn.wants_read() {
                    let bytes_read = conn.read_tls(stream)?;
                    if bytes_read == 0 {
                        break;
                    }
                    conn.process_new_packets().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                }
                
                conn.reader().read(buf)
            }
        }
    }
}

struct ParsedEndpoint {
    host: String,
    port: u16,
    path: String,
    is_https: bool,
}

fn parse_http_endpoint(endpoint: &str) -> Result<ParsedEndpoint, TransportError> {
    let (without_scheme, is_https) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (rest, false)
    } else {
        return Err(TransportError::InvalidEndpoint(
            "missing http:// or https:// scheme".to_string(),
        ));
    };

    let (host_port, path) = match without_scheme.split_once('/') {
        Some((host_port, rest)) => (host_port, format!("/{}", rest)),
        None => (without_scheme, "/".to_string()),
    };

    if host_port.is_empty() {
        return Err(TransportError::InvalidEndpoint("host is empty".to_string()));
    }

    let (host, port) = match host_port.split_once(':') {
        Some((host, port_raw)) => {
            let port = port_raw.parse::<u16>().map_err(|_| {
                TransportError::InvalidEndpoint("invalid numeric port".to_string())
            })?;
            (host.to_string(), port)
        }
        None => {
            // Use default ports
            (host_port.to_string(), if is_https { 443 } else { 80 })
        }
    };

    if host.trim().is_empty() {
        return Err(TransportError::InvalidEndpoint("host is empty".to_string()));
    }

    Ok(ParsedEndpoint { host, port, path, is_https })
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
    let sep = b"\r\n\r\n";
    let body_start = raw
        .windows(sep.len())
        .position(|window| window == sep)
        .map(|idx| idx + sep.len())
        .ok_or_else(|| TransportError::Protocol("malformed HTTP response".to_string()))?;

    let header = &raw[..body_start - sep.len()];
    let header_text = String::from_utf8_lossy(header);
    let status_line = header_text
        .lines()
        .next()
        .ok_or_else(|| TransportError::Protocol("missing status line".to_string()))?;

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| TransportError::Protocol("missing status code".to_string()))?
        .parse::<u16>()
        .map_err(|_| TransportError::Protocol("invalid status code".to_string()))?;

    Ok((status_code, raw[body_start..].to_vec()))
}
