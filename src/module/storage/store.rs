use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::archive::ArchiveStore;
use super::errors::StorageError;
use super::index::{IndexEntry, IndexStore};
use super::retention::enforce_max_archives;

#[derive(Debug, Clone)]
pub struct LocalStoreConfig {
    pub root_dir: PathBuf,
    pub max_archives: usize,
}

impl LocalStoreConfig {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.max_archives == 0 {
            return Err(StorageError::InvalidConfig(
                "max_archives must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub id: String,
    pub path: PathBuf,
    pub created_at_epoch_secs: u64,
    pub bytes: usize,
}

pub struct LocalStore {
    config: LocalStoreConfig,
    archive: ArchiveStore,
    index: IndexStore,
}

impl LocalStore {
    pub fn new(config: LocalStoreConfig) -> Result<Self, StorageError> {
        config.validate()?;
        std::fs::create_dir_all(&config.root_dir)?;

        let archive = ArchiveStore::new(&config.root_dir)?;
        let index = IndexStore::new(&config.root_dir)?;

        Ok(Self {
            config,
            archive,
            index,
        })
    }

    pub fn save(&self, payload: &[u8]) -> Result<StoredRecord, StorageError> {
        let now = now_epoch_secs()?;
        let id = format!("{}_{}", now, now_epoch_nanos()?);
        let path = self.archive.write(&id, payload)?;

        let entry = IndexEntry {
            id: id.clone(),
            created_at_epoch_secs: now,
            bytes: payload.len(),
            file_name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("{id}.bin")),
        };
        self.index.append(&entry)?;

        let _ = enforce_max_archives(&self.index, &self.archive, self.config.max_archives)?;

        Ok(StoredRecord {
            id,
            path,
            created_at_epoch_secs: now,
            bytes: payload.len(),
        })
    }

    pub fn list(&self) -> Result<Vec<IndexEntry>, StorageError> {
        self.index.read_all()
    }

    pub fn load(&self, id: &str) -> Result<Vec<u8>, StorageError> {
        self.archive.read(id)
    }
}

fn now_epoch_secs() -> Result<u64, StorageError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| StorageError::Parse(err.to_string()))?
        .as_secs())
}

fn now_epoch_nanos() -> Result<u128, StorageError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| StorageError::Parse(err.to_string()))?
        .as_nanos())
}
