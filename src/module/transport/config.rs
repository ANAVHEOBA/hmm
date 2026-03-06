use std::time::Duration;

use super::errors::TransportError;

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub max_retries: usize,
    pub retry_backoff: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            api_key: None,
            timeout: Duration::from_secs(5),
            max_retries: 0,
            retry_backoff: Duration::from_millis(200),
        }
    }
}

impl TransportConfig {
    pub fn validate(&self) -> Result<(), TransportError> {
        if !self.enabled {
            return Ok(());
        }

        if self.timeout.is_zero() {
            return Err(TransportError::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }
        if self.retry_backoff.is_zero() {
            return Err(TransportError::InvalidConfig(
                "retry_backoff must be greater than zero".to_string(),
            ));
        }

        let endpoint = self
            .endpoint
            .as_deref()
            .ok_or_else(|| TransportError::InvalidConfig("endpoint is required".to_string()))?;

        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(TransportError::InvalidConfig(
                "endpoint must start with http:// or https://".to_string(),
            ));
        }

        Ok(())
    }
}
