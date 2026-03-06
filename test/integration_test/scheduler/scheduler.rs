use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hmm_core_agent::module::scheduler::{FnSchedulerTask, Scheduler, SchedulerError};

#[test]
fn rejects_zero_workers() {
    assert!(matches!(
        Scheduler::new(0),
        Err(SchedulerError::InvalidWorkerCount(0))
    ));
}

#[test]
fn executes_all_jobs_successfully() {
    let scheduler = Scheduler::new(3).expect("worker count should be valid");
    let counter = Arc::new(AtomicUsize::new(0));

    let mut jobs = Vec::new();
    for idx in 0..6 {
        let ctr = Arc::clone(&counter);
        jobs.push(Box::new(FnSchedulerTask::new(format!("job_{idx}"), move || {
            ctr.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })) as Box<dyn hmm_core_agent::module::scheduler::SchedulerTask>);
    }

    let report = scheduler.execute(jobs).expect("jobs should complete");
    assert_eq!(report.workers, 3);
    assert_eq!(report.total_jobs, 6);
    assert_eq!(report.successes, 6);
    assert_eq!(report.failures, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 6);
}

#[test]
fn marks_failures_in_report() {
    let scheduler = Scheduler::new(2).expect("worker count should be valid");

    let jobs: Vec<Box<dyn hmm_core_agent::module::scheduler::SchedulerTask>> = vec![
        Box::new(FnSchedulerTask::new("ok_job", || Ok(()))),
        Box::new(FnSchedulerTask::new("bad_job", || {
            Err(SchedulerError::TaskFailed {
                task: "bad_job".to_string(),
                reason: "simulated".to_string(),
            })
        })),
    ];

    let report = scheduler.execute(jobs).expect("scheduler should produce report");
    assert_eq!(report.total_jobs, 2);
    assert_eq!(report.successes, 1);
    assert_eq!(report.failures, 1);
    assert!(
        report.outcomes.iter().any(|outcome| {
            outcome.task_name == "bad_job"
                && !outcome.success
                && outcome.error.as_deref().unwrap_or_default().contains("simulated")
        }),
        "expected failed outcome for bad_job"
    );
}
