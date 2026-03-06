use std::time::Duration;

use super::errors::TransportError;

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            api_key: None,
            timeout: Duration::from_secs(5),
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
