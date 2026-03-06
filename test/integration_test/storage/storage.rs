use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hmm_core_agent::module::storage::{LocalStore, LocalStoreConfig};

fn tmp_dir(prefix: &str) -> PathBuf {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!("hmm_{prefix}_{ns}"))
}

#[test]
fn save_and_load_archive() {
    let root = tmp_dir("store_save_load");
    let store = LocalStore::new(LocalStoreConfig {
        root_dir: root.clone(),
        max_archives: 10,
    })
    .expect("store should initialize");

    let payload = b"hello-storage".to_vec();
    let stored = store.save(&payload).expect("save should succeed");

    assert!(stored.path.exists());
    let loaded = store.load(&stored.id).expect("load should succeed");
    assert_eq!(loaded, payload);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn list_returns_saved_entries() {
    let root = tmp_dir("store_list");
    let store = LocalStore::new(LocalStoreConfig {
        root_dir: root.clone(),
        max_archives: 10,
    })
    .expect("store should initialize");

    store.save(b"one").expect("first save should succeed");
    store.save(b"two").expect("second save should succeed");

    let entries = store.list().expect("list should succeed");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| !e.id.is_empty()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retention_enforces_max_archives() {
    let root = tmp_dir("store_retention");
    let store = LocalStore::new(LocalStoreConfig {
        root_dir: root.clone(),
        max_archives: 2,
    })
    .expect("store should initialize");

    let first = store.save(b"first").expect("first save should succeed");
    let _second = store.save(b"second").expect("second save should succeed");
    let third = store.save(b"third").expect("third save should succeed");

    let entries = store.list().expect("list should succeed");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.id != first.id));
    assert!(entries.iter().any(|e| e.id == third.id));

    let first_archive_path = root.join("archive").join(format!("{}.bin", first.id));
    assert!(!first_archive_path.exists());

    let _ = std::fs::remove_dir_all(root);
}
