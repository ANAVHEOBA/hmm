use std::sync::Arc;

use super::errors::SchedulerError;

pub trait SchedulerTask: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self) -> Result<(), SchedulerError>;
}

type SchedulerTaskAction = dyn Fn() -> Result<(), SchedulerError> + Send + Sync;

#[derive(Clone)]
pub struct FnSchedulerTask {
    name: String,
    action: Arc<SchedulerTaskAction>,
}

impl FnSchedulerTask {
    pub fn new<N, F>(name: N, action: F) -> Self
    where
        N: Into<String>,
        F: Fn() -> Result<(), SchedulerError> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            action: Arc::new(action),
        }
    }
}

impl SchedulerTask for FnSchedulerTask {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self) -> Result<(), SchedulerError> {
        (self.action)()
    }
}
