use std::time::SystemTime;

use super::config::CoreConfig;
use super::errors::CoreError;
use super::state::{CoreStats, OrchestratorState};
use super::task::CoreTask;

pub struct Orchestrator {
    config: CoreConfig,
    tasks: Vec<Box<dyn CoreTask>>,
    state: OrchestratorState,
    stats: CoreStats,
}

impl Orchestrator {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        config.validate()?;
        Ok(Self {
            config,
            tasks: Vec::new(),
            state: OrchestratorState::Created,
            stats: CoreStats::default(),
        })
    }

    pub fn initialize(&mut self) -> Result<(), CoreError> {
        self.config.validate()?;
        self.state = OrchestratorState::Initialized;
        Ok(())
    }

    pub fn register_task<T: CoreTask + 'static>(&mut self, task: T) {
        self.tasks.push(Box::new(task));
        self.stats.tasks_total = self.tasks.len();
    }

    pub fn state(&self) -> OrchestratorState {
        self.state
    }

    pub fn stats(&self) -> &CoreStats {
        &self.stats
    }

    pub fn run(&mut self) -> Result<CoreStats, CoreError> {
        if self.state == OrchestratorState::Running {
            return Err(CoreError::AlreadyRunning);
        }
        if self.state == OrchestratorState::Created {
            self.initialize()?;
        }

        self.state = OrchestratorState::Running;
        self.stats.started_at = Some(SystemTime::now());
        self.stats.tasks_failed = 0;
        self.stats.tasks_succeeded = 0;
        self.stats.tasks_total = self.tasks.len();

        for task in &self.tasks {
            let result = if self.config.dry_run {
                Ok(())
            } else {
                task.run(&self.config)
            };

            match result {
                Ok(()) => {
                    self.stats.tasks_succeeded += 1;
                }
                Err(CoreError::TaskFailed { task, reason }) => {
                    self.stats.tasks_failed += 1;
                    self.state = OrchestratorState::Failed;
                    self.stats.finished_at = Some(SystemTime::now());
                    return Err(CoreError::TaskFailed { task, reason });
                }
                Err(other) => {
                    self.stats.tasks_failed += 1;
                    self.state = OrchestratorState::Failed;
                    self.stats.finished_at = Some(SystemTime::now());
                    return Err(CoreError::TaskFailed {
                        task: task.name().to_string(),
                        reason: other.to_string(),
                    });
                }
            }
        }

        self.state = OrchestratorState::Completed;
        self.stats.finished_at = Some(SystemTime::now());
        Ok(self.stats.clone())
    }
}
