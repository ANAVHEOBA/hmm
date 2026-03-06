use std::fs;
use std::path::{Path, PathBuf};

use super::errors::StorageError;

pub struct ArchiveStore {
    archive_dir: PathBuf,
}

impl ArchiveStore {
    pub fn new(root: &Path) -> Result<Self, StorageError> {
        let archive_dir = root.join("archive");
        fs::create_dir_all(&archive_dir)?;
        Ok(Self { archive_dir })
    }

    pub fn path_for_id(&self, id: &str) -> PathBuf {
        self.archive_dir.join(format!("{id}.bin"))
    }

    pub fn write(&self, id: &str, payload: &[u8]) -> Result<PathBuf, StorageError> {
        let path = self.path_for_id(id);
        fs::write(&path, payload)?;
        Ok(path)
    }

    pub fn read(&self, id: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.path_for_id(id);
        if !path.exists() {
            return Err(StorageError::NotFound(format!("archive `{id}`")));
        }
        Ok(fs::read(path)?)
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        let path = self.path_for_id(id);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
