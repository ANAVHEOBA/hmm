use super::config::CoreConfig;
use super::errors::CoreError;

pub trait CoreTask: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, config: &CoreConfig) -> Result<(), CoreError>;
}

type TaskAction = dyn Fn(&CoreConfig) -> Result<(), CoreError> + Send + Sync;

pub struct FnTask {
    name: String,
    action: Box<TaskAction>,
}

impl FnTask {
    pub fn new<N, F>(name: N, action: F) -> Self
    where
        N: Into<String>,
        F: Fn(&CoreConfig) -> Result<(), CoreError> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            action: Box::new(action),
        }
    }
}

impl CoreTask for FnTask {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, config: &CoreConfig) -> Result<(), CoreError> {
        (self.action)(config)
    }
}
