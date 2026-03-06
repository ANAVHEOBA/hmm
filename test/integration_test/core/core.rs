use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hmm_core_agent::module::core::{CoreConfig, CoreError, FnTask, Orchestrator, OrchestratorState};

#[test]
fn core_runs_registered_tasks() {
    let mut orchestrator = Orchestrator::new(CoreConfig::default()).expect("config should be valid");

    orchestrator.register_task(FnTask::new("task_1", |_cfg| Ok(())));
    orchestrator.register_task(FnTask::new("task_2", |_cfg| Ok(())));

    let stats = orchestrator.run().expect("run should succeed");

    assert_eq!(stats.tasks_total, 2);
    assert_eq!(stats.tasks_succeeded, 2);
    assert_eq!(stats.tasks_failed, 0);
    assert_eq!(orchestrator.state(), OrchestratorState::Completed);
}

#[test]
fn core_propagates_task_failure() {
    let mut orchestrator = Orchestrator::new(CoreConfig::default()).expect("config should be valid");
    orchestrator.register_task(FnTask::new("failing_task", |_cfg| {
        Err(CoreError::TaskFailed {
            task: "failing_task".to_string(),
            reason: "forced failure".to_string(),
        })
    }));

    let err = orchestrator.run().expect_err("run should fail");
    assert!(
        matches!(err, CoreError::TaskFailed { .. }),
        "expected TaskFailed variant"
    );
    assert_eq!(orchestrator.state(), OrchestratorState::Failed);
}

#[test]
fn config_validation_rejects_bad_values() {
    let bad = CoreConfig {
        app_name: "".to_string(),
        max_concurrency: 0,
        module_timeout_ms: 0,
        dry_run: false,
    };
    let result = Orchestrator::new(bad);
    assert!(result.is_err(), "invalid config should be rejected");
}

#[test]
fn core_runs_tasks_in_parallel_using_scheduler() {
    let config = CoreConfig {
        app_name: "hmm-core-agent".to_string(),
        max_concurrency: 4,
        module_timeout_ms: 30_000,
        dry_run: false,
    };
    let mut orchestrator = Orchestrator::new(config).expect("config should be valid");
    let counter = Arc::new(AtomicUsize::new(0));

    for idx in 0..4 {
        let ctr = Arc::clone(&counter);
        orchestrator.register_task(FnTask::new(format!("parallel_task_{idx}"), move |_cfg| {
            thread::sleep(Duration::from_millis(120));
            ctr.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
    }

    let start = Instant::now();
    let stats = orchestrator.run().expect("run should succeed");
    let elapsed = start.elapsed();

    assert_eq!(stats.tasks_total, 4);
    assert_eq!(stats.tasks_succeeded, 4);
    assert_eq!(stats.tasks_failed, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 4);
    assert!(
        elapsed < Duration::from_millis(350),
        "expected parallel runtime under 350ms, got {:?}",
        elapsed
    );
}

#[test]
fn core_fails_task_that_exceeds_module_timeout() {
    let config = CoreConfig {
        app_name: "hmm-core-agent".to_string(),
        max_concurrency: 1,
        module_timeout_ms: 50,
        dry_run: false,
    };
    let mut orchestrator = Orchestrator::new(config).expect("config should be valid");
    orchestrator.register_task(FnTask::new("slow_task", |_cfg| {
        thread::sleep(Duration::from_millis(200));
        Ok(())
    }));

    let start = Instant::now();
    let err = orchestrator
        .run()
        .expect_err("run should fail due to timeout");
    let elapsed = start.elapsed();

    assert!(matches!(err, CoreError::TaskFailed { .. }));
    let CoreError::TaskFailed { task, reason } = err else {
        unreachable!("already asserted task failed");
    };
    assert_eq!(task, "slow_task");
    assert!(
        reason.contains("timed out"),
        "expected timeout reason, got: {reason}"
    );
    assert!(
        elapsed < Duration::from_millis(180),
        "expected timeout to stop waiting early, elapsed={:?}",
        elapsed
    );
    assert_eq!(orchestrator.state(), OrchestratorState::Failed);
}
