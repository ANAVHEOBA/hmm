use std::io::{BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::{debug, info, warn};
use rand::Rng;
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
                    let retry_decision = should_retry(&err, attempt, self.config.max_retries);
                    warn!(
                        "upload attempt {} failed (retryable={}, decision={:?}): {}",
                        attempt, is_retryable(&err), retry_decision, err
                    );
                    last_error = Some(err);
                    
                    if let RetryDecision::RetryWithDelay(delay) = retry_decision {
                        thread::sleep(delay);
                        continue;
                    } else {
                        break;
                    }
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

        // Build HTTP request with proper headers
        let mut http = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            parsed.path,
            parsed.host,
            request.content_type,
            request.payload.len()
        );
        if let Some(api_key) = &self.config.api_key {
            http.push_str(&format!("X-API-Key: {}\r\n", api_key));
        }
        http.push_str("\r\n");

        stream.write_all(http.as_bytes())?;
        stream.write_all(&request.payload)?;
        stream.flush()?;

        // Read and parse HTTP response properly
        let response = read_http_response(&mut stream, self.config.timeout)?;
        
        if !(200..300).contains(&response.status_code) {
            return Err(TransportError::UploadFailed(response.status_code));
        }

        Ok(UploadResponse {
            uploaded: true,
            status_code: Some(response.status_code),
            body: response.body,
        })
    }
}

/// Retry decision based on error type and attempt number
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetryDecision {
    /// Do not retry (fatal error or max retries exceeded)
    NoRetry,
    /// Retry after specified delay
    RetryWithDelay(Duration),
}

/// Determine if and how to retry based on error type
fn should_retry(err: &TransportError, attempt: usize, max_retries: usize) -> RetryDecision {
    if attempt > max_retries {
        return RetryDecision::NoRetry;
    }

    match err {
        // Network errors - retry with exponential backoff
        TransportError::Io(_) | TransportError::InvalidEndpoint(_) => {
            let delay = calculate_backoff(attempt, Duration::from_secs(1));
            RetryDecision::RetryWithDelay(delay)
        }
        // Protocol errors - may be temporary, retry with backoff
        TransportError::Protocol(_) => {
            let delay = calculate_backoff(attempt, Duration::from_millis(500));
            RetryDecision::RetryWithDelay(delay)
        }
        // HTTP status code based retry logic
        TransportError::UploadFailed(status) => {
            match *status {
                // 4xx client errors - generally don't retry (except 429)
                400..=499 => {
                    if *status == 429 {
                        // Rate limited - respect Retry-After if present, otherwise exponential backoff
                        let delay = calculate_backoff(attempt, Duration::from_secs(2));
                        RetryDecision::RetryWithDelay(delay)
                    } else {
                        RetryDecision::NoRetry
                    }
                }
                // 5xx server errors - retry with backoff
                500..=599 => {
                    let delay = calculate_backoff(attempt, Duration::from_secs(1));
                    RetryDecision::RetryWithDelay(delay)
                }
                // Other codes - don't retry
                _ => RetryDecision::NoRetry,
            }
        }
        // Configuration errors - don't retry
        TransportError::InvalidConfig(_) => RetryDecision::NoRetry,
    }
}

/// Check if an error is potentially retryable
fn is_retryable(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::Io(_) 
            | TransportError::Protocol(_) 
            | TransportError::UploadFailed(_)
            | TransportError::InvalidEndpoint(_)
    )
}

/// Calculate exponential backoff with jitter
fn calculate_backoff(attempt: usize, base_delay: Duration) -> Duration {
    // Exponential backoff: base_delay * 2^(attempt-1)
    let exponent = attempt.saturating_sub(1) as u32;
    let exponential_delay = base_delay.as_millis() as u64 * 2u64.saturating_pow(exponent);
    
    // Cap at 30 seconds to avoid excessive delays
    let capped_delay = exponential_delay.min(30_000);
    
    // Add jitter: +/- 25% random variation
    let mut rng = rand::thread_rng();
    let jitter_range = (capped_delay as f64 * 0.25) as u64;
    let jitter = if jitter_range > 0 {
        let jitter_val = rng.gen_range(0..jitter_range * 2);
        jitter_val as i64 - jitter_range as i64
    } else {
        0
    };
    
    let final_delay = (capped_delay as i64 + jitter).max(100) as u64;
    
    Duration::from_millis(final_delay)
}

/// HTTP response structure
struct HttpResponse {
    status_code: u16,
    body: Vec<u8>,
}

/// Read and parse HTTP response with proper handling
fn read_http_response<R: Read>(
    stream: &mut R,
    _timeout: Duration,
) -> Result<HttpResponse, TransportError> {
    use std::io::BufRead;

    // Set read timeout
    stream
        .read(&mut [0u8; 0])
        .ok(); // Dummy read to trigger timeout if needed

    let mut reader = std::io::BufReader::new(stream);

    // Read status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    
    if status_line.is_empty() {
        return Err(TransportError::Protocol("empty response".to_string()));
    }

    // Parse status line: HTTP/1.1 200 OK
    let parts: Vec<&str> = status_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(TransportError::Protocol("malformed status line".to_string()));
    }

    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| TransportError::Protocol(format!("invalid status code: {}", parts[1])))?;

    // Read headers
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;

    loop {
        let mut header_line = String::new();
        let bytes_read = reader.read_line(&mut header_line)?;
        
        if bytes_read == 0 {
            return Err(TransportError::Protocol("unexpected end of headers".to_string()));
        }

        let header_line = header_line.trim();
        if header_line.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = header_line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            
            if key == "content-length" {
                content_length = value.parse().ok();
            } else if key == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                is_chunked = true;
            }
            
        }
    }

    // Read body
    let body = if is_chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body)?;
        body
    } else {
        // No content-length, read until EOF
        let mut body = Vec::new();
        reader.read_to_end(&mut body)?;
        body
    };

    Ok(HttpResponse {
        status_code,
        body,
    })
}

/// Read chunked transfer encoding body
fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, TransportError> {
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;

        // Parse chunk size (hex)
        let size_str = size_line.trim().split(';').next().unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| TransportError::Protocol(format!("invalid chunk size: {}", size_str)))?;

        if chunk_size == 0 {
            // Final chunk - read trailing headers and CRLF
            loop {
                let mut trailer = String::new();
                reader.read_line(&mut trailer)?;
                if trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }

        // Read chunk data
        let mut chunk = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk)?;
        body.extend(chunk);

        // Read CRLF after chunk
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }

    Ok(body)
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
