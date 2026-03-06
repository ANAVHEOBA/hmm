use hmm_core_agent::module::core::{CoreConfig, FnTask, Orchestrator};
use log::{error, info};

fn main() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();

    let config = CoreConfig::from_env().unwrap_or_default();
    let mut orchestrator = Orchestrator::new(config).expect("valid orchestrator config");

    orchestrator.register_task(FnTask::new("bootstrap", |_cfg| Ok(())));

    match orchestrator.run() {
        Ok(stats) => {
            info!(
                "core completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
            println!(
                "core completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
        }
        Err(err) => {
            error!("core failed: {err}");
            eprintln!("core failed: {err}");
        }
    }
}
