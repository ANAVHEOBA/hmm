//! Cancellation Token for graceful task termination
//!
//! Provides a thread-safe cancellation mechanism that allows:
//! - Requesting cancellation from outside the task
//! - Periodic cancellation checks within the task
//! - Guaranteed cleanup on cancellation

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

/// Cancellation token that can be shared across threads
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Wait for cancellation with timeout
    /// Returns true if cancelled, false if timeout elapsed
    pub fn wait_for_cancel(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while !self.is_cancelled() {
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    /// Check cancellation and return error if cancelled
    pub fn check(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }
}

/// Error returned when operation is cancelled
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledError;

impl std::fmt::Display for CancelledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operation cancelled")
    }
}

impl std::error::Error for CancelledError {}

/// Guard that automatically cancels when dropped
pub struct CancelGuard {
    pub token: CancellationToken,
}

impl CancelGuard {
    pub fn new(token: CancellationToken) -> Self {
        Self { token }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_initial_state() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_token_cancel() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_token_clone_shares_state() {
        let token1 = CancellationToken::new();
        let token2 = token1.clone();

        token1.cancel();
        assert!(token2.is_cancelled());
    }

    #[test]
    fn test_check_ok() {
        let token = CancellationToken::new();
        assert!(token.check().is_ok());
    }

    #[test]
    fn test_check_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.check().is_err());
    }

    #[test]
    fn test_wait_for_cancel_timeout() {
        let token = CancellationToken::new();
        let result = token.wait_for_cancel(Duration::from_millis(50));
        assert!(!result); // Should timeout
    }

    #[test]
    fn test_wait_for_cancel_success() {
        let token = CancellationToken::new();
        let token_clone = token.clone();

        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            token_clone.cancel();
        });

        let result = token.wait_for_cancel(Duration::from_secs(1));
        assert!(result); // Should be cancelled
    }

    #[test]
    fn test_cancel_guard() {
        let token = CancellationToken::new();
        {
            let _guard = CancelGuard::new(token.clone());
            assert!(!token.is_cancelled());
        }
        // Guard dropped, should be cancelled
        assert!(token.is_cancelled());
    }
}
