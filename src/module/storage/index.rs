use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::errors::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub id: String,
    pub created_at_epoch_secs: u64,
    pub bytes: usize,
    pub file_name: String,
}

impl IndexEntry {
    fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\n",
            self.id, self.created_at_epoch_secs, self.bytes, self.file_name
        )
    }

    fn from_line(line: &str) -> Result<Self, StorageError> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 4 {
            return Err(StorageError::Parse("invalid index line shape".to_string()));
        }
        let created_at_epoch_secs = parts[1]
            .parse::<u64>()
            .map_err(|_| StorageError::Parse("invalid timestamp in index".to_string()))?;
        let bytes = parts[2]
            .parse::<usize>()
            .map_err(|_| StorageError::Parse("invalid byte count in index".to_string()))?;

        Ok(Self {
            id: parts[0].to_string(),
            created_at_epoch_secs,
            bytes,
            file_name: parts[3].to_string(),
        })
    }
}

pub struct IndexStore {
    index_path: PathBuf,
}

impl IndexStore {
    pub fn new(root: &Path) -> Result<Self, StorageError> {
        fs::create_dir_all(root)?;
        let index_path = root.join("index.tsv");
        if !index_path.exists() {
            fs::write(&index_path, b"")?;
        }
        Ok(Self { index_path })
    }

    pub fn append(&self, entry: &IndexEntry) -> Result<(), StorageError> {
        let mut file = OpenOptions::new().append(true).open(&self.index_path)?;
        file.write_all(entry.to_line().as_bytes())?;
        Ok(())
    }

    pub fn read_all(&self) -> Result<Vec<IndexEntry>, StorageError> {
        let file = OpenOptions::new().read(true).open(&self.index_path)?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();

        for line in reader.lines() {
            let raw = line?;
            if raw.trim().is_empty() {
                continue;
            }
            out.push(IndexEntry::from_line(&raw)?);
        }

        Ok(out)
    }

    pub fn replace_all(&self, entries: &[IndexEntry]) -> Result<(), StorageError> {
        let mut content = String::new();
        for entry in entries {
            content.push_str(&entry.to_line());
        }
        fs::write(&self.index_path, content)?;
        Ok(())
    }
}
