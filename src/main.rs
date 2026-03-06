use hmm_core_agent::module::core::{CoreConfig, FnTask, Orchestrator};

fn main() {
    let config = CoreConfig::from_env().unwrap_or_default();
    let mut orchestrator = Orchestrator::new(config).expect("valid orchestrator config");

    orchestrator.register_task(FnTask::new("bootstrap", |_cfg| Ok(())));

    match orchestrator.run() {
        Ok(stats) => {
            println!(
                "core completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
        }
        Err(err) => {
            eprintln!("core failed: {err}");
        }
    }
}
