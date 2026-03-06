use std::time::Duration;

use hmm_core_agent::module::transport::{
    TransportClient, TransportConfig, TransportError, UploadRequest,
};

#[test]
fn disabled_transport_skips_upload() {
    let client = TransportClient::new(TransportConfig::default()).expect("config should be valid");
    let resp = client
        .upload(&UploadRequest::binary(b"payload".to_vec()))
        .expect("disabled transport should not fail");

    assert!(!resp.uploaded);
    assert!(resp.status_code.is_none());
}

#[test]
fn rejects_invalid_endpoint_scheme() {
    // Test that non-http/https schemes are rejected
    let result = TransportClient::new(TransportConfig {
        enabled: true,
        endpoint: Some("ftp://example.com/upload".to_string()),
        api_key: None,
        timeout: Duration::from_secs(2),
    });
    assert!(matches!(result, Err(TransportError::InvalidConfig(_))));
}

#[test]
fn accepts_https_endpoint() {
    // HTTPS endpoints should be accepted
    let result = TransportClient::new(TransportConfig {
        enabled: false, // Don't actually connect
        endpoint: Some("https://example.com/upload".to_string()),
        api_key: None,
        timeout: Duration::from_secs(2),
    });
    assert!(result.is_ok());
}

#[test]
fn accepts_http_endpoint() {
    // HTTP endpoints should be accepted
    let result = TransportClient::new(TransportConfig {
        enabled: false,
        endpoint: Some("http://example.com/upload".to_string()),
        api_key: None,
        timeout: Duration::from_secs(2),
    });
    assert!(result.is_ok());
}

#[test]
fn returns_error_when_server_unreachable() {
    let client = TransportClient::new(TransportConfig {
        enabled: true,
        endpoint: Some("http://127.0.0.1:1/upload".to_string()),
        api_key: None,
        timeout: Duration::from_millis(250),
    })
    .expect("config should be valid");

    let err = client
        .upload(&UploadRequest::binary(b"payload".to_vec()))
        .expect_err("upload should fail");
    assert!(
        matches!(err, TransportError::Io(_) | TransportError::UploadFailed(_)),
        "expected io/upload error, got {err}"
    );
}

#[test]
fn https_config_creates_client() {
    // Test that HTTPS endpoint creates client successfully
    let config = TransportConfig {
        enabled: false, // Don't actually connect
        endpoint: Some("https://httpbin.org/post".to_string()),
        api_key: None,
        timeout: Duration::from_secs(5),
    };
    
    let client = TransportClient::new(config);
    assert!(client.is_ok());
}

#[test]
fn http_config_creates_client() {
    // Test that HTTP endpoint creates client successfully
    let config = TransportConfig {
        enabled: false,
        endpoint: Some("http://httpbin.org/post".to_string()),
        api_key: None,
        timeout: Duration::from_secs(5),
    };
    
    let client = TransportClient::new(config);
    assert!(client.is_ok());
}
