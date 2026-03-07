use super::cancellation::CancellationToken;
use super::config::CoreConfig;
use super::errors::CoreError;

pub trait CoreTask: Send + Sync {
    fn name(&self) -> &str;
    
    /// Run the task (default implementation ignores cancellation)
    fn run(&self, config: &CoreConfig) -> Result<(), CoreError> {
        self.run_with_cancel(config, &CancellationToken::new())
    }
    
    /// Run the task with cancellation support
    fn run_with_cancel(
        &self,
        config: &CoreConfig,
        cancel_token: &CancellationToken,
    ) -> Result<(), CoreError>;
}

type TaskAction = dyn Fn(&CoreConfig, &CancellationToken) -> Result<(), CoreError> + Send + Sync;

pub struct FnTask {
    name: String,
    action: Box<TaskAction>,
}

impl FnTask {
    pub fn new<N, F>(name: N, action: F) -> Self
    where
        N: Into<String>,
        F: Fn(&CoreConfig, &CancellationToken) -> Result<(), CoreError> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            action: Box::new(action),
        }
    }
    
    /// Create a task that doesn't use cancellation
    pub fn new_simple<N, F>(name: N, action: F) -> Self
    where
        N: Into<String>,
        F: Fn(&CoreConfig) -> Result<(), CoreError> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            action: Box::new(move |cfg, _| action(cfg)),
        }
    }
}

impl CoreTask for FnTask {
    fn name(&self) -> &str {
        &self.name
    }

    fn run_with_cancel(
        &self,
        config: &CoreConfig,
        cancel_token: &CancellationToken,
    ) -> Result<(), CoreError> {
        (self.action)(config, cancel_token)
    }
}
