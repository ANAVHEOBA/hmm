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
