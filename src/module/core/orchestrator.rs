use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use std::time::SystemTime;

use crate::module::scheduler::{Scheduler, SchedulerError, SchedulerTask};
use log::{debug, error, info, warn};

use super::config::CoreConfig;
use super::errors::CoreError;
use super::state::{CoreStats, OrchestratorState};
use super::task::CoreTask;

pub struct Orchestrator {
    config: CoreConfig,
    tasks: Vec<Arc<dyn CoreTask>>,
    state: OrchestratorState,
    stats: CoreStats,
}

impl Orchestrator {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        config.validate()?;
        info!(
            "orchestrator created: app_name={}, max_concurrency={}, timeout_ms={}, dry_run={}",
            config.app_name, config.max_concurrency, config.module_timeout_ms, config.dry_run
        );
        Ok(Self {
            config,
            tasks: Vec::new(),
            state: OrchestratorState::Created,
            stats: CoreStats::default(),
        })
    }

    pub fn initialize(&mut self) -> Result<(), CoreError> {
        self.config.validate()?;
        debug!("orchestrator initialized");
        self.state = OrchestratorState::Initialized;
        Ok(())
    }

    pub fn register_task<T: CoreTask + 'static>(&mut self, task: T) {
        debug!("registered task: {}", task.name());
        self.tasks.push(Arc::new(task));
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
            warn!("orchestrator run requested while already running");
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
        info!(
            "orchestrator run started: tasks={}, workers={}, timeout_ms={}",
            self.stats.tasks_total, self.config.max_concurrency, self.config.module_timeout_ms
        );

        if self.stats.tasks_total == 0 {
            self.state = OrchestratorState::Completed;
            self.stats.finished_at = Some(SystemTime::now());
            info!("orchestrator run completed: no tasks registered");
            return Ok(self.stats.clone());
        }

        if self.config.dry_run {
            self.stats.tasks_succeeded = self.stats.tasks_total;
            self.state = OrchestratorState::Completed;
            self.stats.finished_at = Some(SystemTime::now());
            info!("orchestrator run completed in dry_run mode");
            return Ok(self.stats.clone());
        }

        let report = self.execute_with_scheduler()?;
        self.stats.tasks_succeeded = report.successes;
        self.stats.tasks_failed = report.failures;

        if report.failures > 0 {
            self.state = OrchestratorState::Failed;
            self.stats.finished_at = Some(SystemTime::now());
            error!(
                "orchestrator run failed: successes={}, failures={}",
                self.stats.tasks_succeeded, self.stats.tasks_failed
            );
            if let Some(outcome) = report.outcomes.iter().find(|outcome| !outcome.success) {
                return Err(CoreError::TaskFailed {
                    task: outcome.task_name.clone(),
                    reason: outcome
                        .error
                        .clone()
                        .unwrap_or_else(|| "task failed".to_string()),
                });
            }
            return Err(CoreError::TaskFailed {
                task: "unknown".to_string(),
                reason: "scheduler reported failure without outcome details".to_string(),
            });
        }

        self.state = OrchestratorState::Completed;
        self.stats.finished_at = Some(SystemTime::now());
        info!(
            "orchestrator run completed: successes={}, failures={}",
            self.stats.tasks_succeeded, self.stats.tasks_failed
        );
        Ok(self.stats.clone())
    }

    fn execute_with_scheduler(
        &self,
    ) -> Result<crate::module::scheduler::SchedulerReport, CoreError> {
        let workers = self.config.max_concurrency.min(self.tasks.len());
        debug!(
            "dispatching {} tasks to scheduler with {} workers",
            self.tasks.len(),
            workers
        );
        let scheduler = Scheduler::new(workers).map_err(|err| CoreError::TaskFailed {
            task: "scheduler".to_string(),
            reason: err.to_string(),
        })?;

        let mut jobs: Vec<Box<dyn SchedulerTask>> = Vec::with_capacity(self.tasks.len());
        for task in &self.tasks {
            jobs.push(Box::new(ScheduledCoreTask::new(
                Arc::clone(task),
                self.config.clone(),
            )));
        }

        scheduler
            .execute(jobs)
            .map_err(|err| CoreError::TaskFailed {
                task: "scheduler".to_string(),
                reason: err.to_string(),
            })
    }
}

struct ScheduledCoreTask {
    name: String,
    task: Arc<dyn CoreTask>,
    config: CoreConfig,
}

impl ScheduledCoreTask {
    fn new(task: Arc<dyn CoreTask>, config: CoreConfig) -> Self {
        Self {
            name: task.name().to_string(),
            task,
            config,
        }
    }
}

impl SchedulerTask for ScheduledCoreTask {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self) -> Result<(), SchedulerError> {
        let (tx, rx) = mpsc::channel::<Result<(), CoreError>>();
        let task = Arc::clone(&self.task);
        let config = self.config.clone();
        let name = self.name.clone();
        let timeout = Duration::from_millis(self.config.module_timeout_ms);

        std::thread::spawn(move || {
            let _ = tx.send(task.run(&config));
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(())) => {
                debug!("task succeeded: {}", self.name);
                Ok(())
            }
            Ok(Err(err)) => {
                warn!("task failed: {} ({})", self.name, err);
                Err(match err {
                    CoreError::TaskFailed { task, reason } => {
                        SchedulerError::TaskFailed { task, reason }
                    }
                    other => SchedulerError::TaskFailed {
                        task: self.name.clone(),
                        reason: other.to_string(),
                    },
                })
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                warn!(
                    "task timed out: {} after {}ms",
                    name, self.config.module_timeout_ms
                );
                Err(SchedulerError::TaskFailed {
                    task: name,
                    reason: format!("timed out after {}ms", self.config.module_timeout_ms),
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SchedulerError::TaskFailed {
                task: self.name.clone(),
                reason: "task channel disconnected".to_string(),
            }),
        }
    }
}
