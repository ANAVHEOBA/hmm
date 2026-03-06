use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::errors::SchedulerError;
use super::task::SchedulerTask;

type TaskBox = Box<dyn SchedulerTask>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    pub task_name: String,
    pub success: bool,
    pub error: Option<String>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct SchedulerReport {
    pub workers: usize,
    pub total_jobs: usize,
    pub successes: usize,
    pub failures: usize,
    pub outcomes: Vec<JobOutcome>,
}

pub struct Scheduler {
    workers: usize,
}

impl Scheduler {
    pub fn new(workers: usize) -> Result<Self, SchedulerError> {
        if workers == 0 {
            return Err(SchedulerError::InvalidWorkerCount(workers));
        }
        Ok(Self { workers })
    }

    pub fn workers(&self) -> usize {
        self.workers
    }

    pub fn execute(&self, tasks: Vec<TaskBox>) -> Result<SchedulerReport, SchedulerError> {
        let total_jobs = tasks.len();
        if total_jobs == 0 {
            return Ok(SchedulerReport {
                workers: self.workers,
                total_jobs,
                successes: 0,
                failures: 0,
                outcomes: Vec::new(),
            });
        }

        let (job_tx, job_rx) = mpsc::channel::<TaskBox>();
        let (result_tx, result_rx) = mpsc::channel::<JobOutcome>();
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let mut handles = Vec::with_capacity(self.workers);

        for _ in 0..self.workers {
            let rx = Arc::clone(&shared_rx);
            let tx = result_tx.clone();
            handles.push(thread::spawn(move || loop {
                let maybe_task = {
                    let guard = match rx.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    guard.recv().ok()
                };

                let Some(task) = maybe_task else {
                    break;
                };

                let start = Instant::now();
                let outcome = match task.run() {
                    Ok(()) => JobOutcome {
                        task_name: task.name().to_string(),
                        success: true,
                        error: None,
                        elapsed_ms: start.elapsed().as_millis(),
                    },
                    Err(err) => JobOutcome {
                        task_name: task.name().to_string(),
                        success: false,
                        error: Some(err.to_string()),
                        elapsed_ms: start.elapsed().as_millis(),
                    },
                };

                if tx.send(outcome).is_err() {
                    break;
                }
            }));
        }
        drop(result_tx);

        for task in tasks {
            if job_tx.send(task).is_err() {
                return Err(SchedulerError::WorkerChannelClosed);
            }
        }
        drop(job_tx);

        let mut outcomes = Vec::with_capacity(total_jobs);
        for _ in 0..total_jobs {
            match result_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(outcome) => outcomes.push(outcome),
                Err(_) => return Err(SchedulerError::WorkerChannelClosed),
            }
        }

        for handle in handles {
            let _ = handle.join();
        }

        let failures = outcomes.iter().filter(|o| !o.success).count();
        let successes = total_jobs - failures;

        Ok(SchedulerReport {
            workers: self.workers,
            total_jobs,
            successes,
            failures,
            outcomes,
        })
    }
}
