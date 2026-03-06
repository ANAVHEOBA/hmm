use std::time::{Duration, Instant};

use hmm_core_agent::module::transport::{
    TransportClient, TransportConfig, TransportError, UploadRequest,
};

fn make_config(enabled: bool, endpoint: Option<String>, timeout: Duration) -> TransportConfig {
    TransportConfig {
        enabled,
        endpoint,
        api_key: None,
        timeout,
        max_retries: 0,
        retry_backoff: Duration::from_millis(50),
    }
}

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
    let result = TransportClient::new(make_config(
        true,
        Some("ftp://example.com/upload".to_string()),
        Duration::from_secs(2),
    ));
    assert!(matches!(result, Err(TransportError::InvalidConfig(_))));
}

#[test]
fn accepts_https_endpoint() {
    // HTTPS endpoints should be accepted
    let result = TransportClient::new(make_config(
        false,
        Some("https://example.com/upload".to_string()),
        Duration::from_secs(2),
    ));
    assert!(result.is_ok());
}

#[test]
fn accepts_http_endpoint() {
    // HTTP endpoints should be accepted
    let result = TransportClient::new(make_config(
        false,
        Some("http://example.com/upload".to_string()),
        Duration::from_secs(2),
    ));
    assert!(result.is_ok());
}

#[test]
fn returns_error_when_server_unreachable() {
    let client = TransportClient::new(make_config(
        true,
        Some("http://127.0.0.1:1/upload".to_string()),
        Duration::from_millis(250),
    ))
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
    let config = make_config(
        false,
        Some("https://httpbin.org/post".to_string()),
        Duration::from_secs(5),
    );
    
    let client = TransportClient::new(config);
    assert!(client.is_ok());
}

#[test]
fn http_config_creates_client() {
    // Test that HTTP endpoint creates client successfully
    let config = make_config(
        false,
        Some("http://httpbin.org/post".to_string()),
        Duration::from_secs(5),
    );
    
    let client = TransportClient::new(config);
    assert!(client.is_ok());
}

#[test]
fn retries_apply_backoff_for_unreachable_server() {
    let client = TransportClient::new(TransportConfig {
        max_retries: 2,
        retry_backoff: Duration::from_millis(40),
        ..make_config(
            true,
            Some("http://127.0.0.1:1/upload".to_string()),
            Duration::from_millis(100),
        )
    })
    .expect("config should be valid");

    let start = Instant::now();
    let err = client
        .upload(&UploadRequest::binary(b"payload".to_vec()))
        .expect_err("upload should fail after retries");
    let elapsed = start.elapsed();

    assert!(matches!(err, TransportError::Io(_) | TransportError::UploadFailed(_)));
    assert!(
        elapsed >= Duration::from_millis(80),
        "expected at least two backoff periods, elapsed={:?}",
        elapsed
    );
}

#[test]
fn zero_retries_fail_faster_than_retried_upload() {
    let client = TransportClient::new(TransportConfig {
        max_retries: 0,
        retry_backoff: Duration::from_millis(20),
        ..make_config(
            true,
            Some("http://127.0.0.1:1/upload".to_string()),
            Duration::from_millis(100),
        )
    })
    .expect("config should be valid");

    let start = Instant::now();
    let err = client
        .upload(&UploadRequest::binary(b"payload".to_vec()))
        .expect_err("upload should fail immediately");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, TransportError::Io(_) | TransportError::UploadFailed(_)),
        "expected upload/io error, got {err}"
    );
    assert!(
        elapsed < Duration::from_millis(60),
        "expected quick failure without retries, elapsed={:?}",
        elapsed
    );
}
