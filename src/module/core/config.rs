use std::env;

use super::errors::CoreError;

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub app_name: String,
    pub max_concurrency: usize,
    pub module_timeout_ms: u64,
    pub dry_run: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            app_name: "hmm-core-agent".to_string(),
            max_concurrency: 4,
            module_timeout_ms: 30_000,
            dry_run: false,
        }
    }
}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.app_name.trim().is_empty() {
            return Err(CoreError::InvalidConfig(
                "app_name cannot be empty".to_string(),
            ));
        }
        if self.max_concurrency == 0 {
            return Err(CoreError::InvalidConfig(
                "max_concurrency must be greater than 0".to_string(),
            ));
        }
        if self.module_timeout_ms == 0 {
            return Err(CoreError::InvalidConfig(
                "module_timeout_ms must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, CoreError> {
        let mut cfg = Self::default();

        if let Ok(name) = env::var("HMM_CORE_APP_NAME") {
            cfg.app_name = name;
        }
        if let Ok(concurrency) = env::var("HMM_CORE_MAX_CONCURRENCY") {
            cfg.max_concurrency = concurrency.parse().map_err(|_| {
                CoreError::InvalidConfig(
                    "HMM_CORE_MAX_CONCURRENCY must be a positive integer".to_string(),
                )
            })?;
        }
        if let Ok(timeout) = env::var("HMM_CORE_TIMEOUT_MS") {
            cfg.module_timeout_ms = timeout.parse().map_err(|_| {
                CoreError::InvalidConfig(
                    "HMM_CORE_TIMEOUT_MS must be a positive integer".to_string(),
                )
            })?;
        }
        if let Ok(dry_run) = env::var("HMM_CORE_DRY_RUN") {
            cfg.dry_run = matches!(dry_run.as_str(), "1" | "true" | "TRUE" | "True");
        }

        cfg.validate()?;
        Ok(cfg)
    }
}
