use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorState {
    Created,
    Initialized,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct CoreStats {
    pub tasks_total: usize,
    pub tasks_succeeded: usize,
    pub tasks_failed: usize,
    pub started_at: Option<SystemTime>,
    pub finished_at: Option<SystemTime>,
}

impl Default for CoreStats {
    fn default() -> Self {
        Self {
            tasks_total: 0,
            tasks_succeeded: 0,
            tasks_failed: 0,
            started_at: None,
            finished_at: None,
        }
    }
}
