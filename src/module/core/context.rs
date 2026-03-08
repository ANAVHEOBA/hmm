//! Shared Data Context
//!
//! Provides a thread-safe context for sharing data between tasks
//! in the extractor → processing → storage → transport pipeline.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::module::processing::types::DataRecord;

/// Shared context for data flow between tasks
#[derive(Debug, Clone, Default)]
pub struct DataContext {
    /// Extracted records from all sources
    records: Arc<Mutex<Vec<DataRecord>>>,
    /// Processing results (compressed/encrypted payloads)
    processed_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Storage paths for saved data
    storage_paths: Arc<Mutex<Vec<String>>>,
    /// Metadata about the extraction session
    metadata: Arc<Mutex<HashMap<String, String>>>,
}

impl DataContext {
    /// Create a new empty data context
    pub fn new() -> Self {
        Self::default()
    }

    /// Add extracted records to the context
    pub fn add_records(&self, mut records: Vec<DataRecord>) -> Result<(), DataContextError> {
        let mut store = self.records.lock().map_err(|_| DataContextError::LockError)?;
        store.append(&mut records);
        Ok(())
    }

    /// Get all extracted records
    pub fn get_records(&self) -> Result<Vec<DataRecord>, DataContextError> {
        let store = self.records.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.clone())
    }

    /// Get the count of extracted records
    pub fn record_count(&self) -> Result<usize, DataContextError> {
        let store = self.records.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.len())
    }

    /// Clear all records
    pub fn clear_records(&self) -> Result<(), DataContextError> {
        let mut store = self.records.lock().map_err(|_| DataContextError::LockError)?;
        store.clear();
        Ok(())
    }

    /// Add a processed payload
    pub fn add_payload(&self, payload: Vec<u8>) -> Result<(), DataContextError> {
        let mut store = self.processed_payloads.lock().map_err(|_| DataContextError::LockError)?;
        store.push(payload);
        Ok(())
    }

    /// Get all processed payloads
    pub fn get_payloads(&self) -> Result<Vec<Vec<u8>>, DataContextError> {
        let store = self.processed_payloads.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.clone())
    }

    /// Get the count of processed payloads
    pub fn payload_count(&self) -> Result<usize, DataContextError> {
        let store = self.processed_payloads.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.len())
    }

    /// Clear all payloads
    pub fn clear_payloads(&self) -> Result<(), DataContextError> {
        let mut store = self.processed_payloads.lock().map_err(|_| DataContextError::LockError)?;
        store.clear();
        Ok(())
    }

    /// Add a storage path
    pub fn add_storage_path(&self, path: String) -> Result<(), DataContextError> {
        let mut store = self.storage_paths.lock().map_err(|_| DataContextError::LockError)?;
        store.push(path);
        Ok(())
    }

    /// Get all storage paths
    pub fn get_storage_paths(&self) -> Result<Vec<String>, DataContextError> {
        let store = self.storage_paths.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.clone())
    }

    /// Set metadata value
    pub fn set_metadata(&self, key: String, value: String) -> Result<(), DataContextError> {
        let mut store = self.metadata.lock().map_err(|_| DataContextError::LockError)?;
        store.insert(key, value);
        Ok(())
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, DataContextError> {
        let store = self.metadata.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.get(key).cloned())
    }

    /// Get all metadata
    pub fn get_all_metadata(&self) -> Result<HashMap<String, String>, DataContextError> {
        let store = self.metadata.lock().map_err(|_| DataContextError::LockError)?;
        Ok(store.clone())
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> Result<ContextSummary, DataContextError> {
        let records = self.records.lock().map_err(|_| DataContextError::LockError)?;
        let payloads = self.processed_payloads.lock().map_err(|_| DataContextError::LockError)?;
        let paths = self.storage_paths.lock().map_err(|_| DataContextError::LockError)?;

        Ok(ContextSummary {
            record_count: records.len(),
            payload_count: payloads.len(),
            storage_path_count: paths.len(),
            total_payload_bytes: payloads.iter().map(|p| p.len()).sum(),
        })
    }
}

/// Summary statistics for the data context
#[derive(Debug, Clone, Default)]
pub struct ContextSummary {
    pub record_count: usize,
    pub payload_count: usize,
    pub storage_path_count: usize,
    pub total_payload_bytes: usize,
}

/// Errors that can occur with DataContext operations
#[derive(Debug, Clone)]
pub enum DataContextError {
    LockError,
}

impl std::fmt::Display for DataContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataContextError::LockError => write!(f, "Failed to acquire lock"),
        }
    }
}

impl std::error::Error for DataContextError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_records() {
        let ctx = DataContext::new();
        let records = vec![
            DataRecord {
                source: "test".to_string(),
                kind: "wallet".to_string(),
                payload: b"test data".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];

        ctx.add_records(records.clone()).unwrap();
        let retrieved = ctx.get_records().unwrap();

        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].source, "test");
    }

    #[test]
    fn test_record_count() {
        let ctx = DataContext::new();
        assert_eq!(ctx.record_count().unwrap(), 0);

        let records = vec![
            DataRecord {
                source: "test".to_string(),
                kind: "wallet".to_string(),
                payload: b"data1".to_vec(),
                metadata: BTreeMap::new(),
            },
            DataRecord {
                source: "test".to_string(),
                kind: "wallet".to_string(),
                payload: b"data2".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];

        ctx.add_records(records).unwrap();
        assert_eq!(ctx.record_count().unwrap(), 2);
    }

    #[test]
    fn test_clear_records() {
        let ctx = DataContext::new();
        let records = vec![DataRecord {
            source: "test".to_string(),
            kind: "wallet".to_string(),
            payload: b"test".to_vec(),
            metadata: BTreeMap::new(),
        }];

        ctx.add_records(records).unwrap();
        assert_eq!(ctx.record_count().unwrap(), 1);

        ctx.clear_records().unwrap();
        assert_eq!(ctx.record_count().unwrap(), 0);
    }

    #[test]
    fn test_payload_operations() {
        let ctx = DataContext::new();
        
        ctx.add_payload(vec![1, 2, 3]).unwrap();
        ctx.add_payload(vec![4, 5, 6, 7]).unwrap();

        assert_eq!(ctx.payload_count().unwrap(), 2);
        
        let payloads = ctx.get_payloads().unwrap();
        assert_eq!(payloads[0], vec![1, 2, 3]);
        assert_eq!(payloads[1], vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_metadata_operations() {
        let ctx = DataContext::new();

        ctx.set_metadata("key1".to_string(), "value1".to_string()).unwrap();
        ctx.set_metadata("key2".to_string(), "value2".to_string()).unwrap();

        assert_eq!(ctx.get_metadata("key1").unwrap(), Some("value1".to_string()));
        assert_eq!(ctx.get_metadata("key2").unwrap(), Some("value2".to_string()));
        assert_eq!(ctx.get_metadata("key3").unwrap(), None);
    }

    #[test]
    fn test_get_summary() {
        let ctx = DataContext::new();

        let records = vec![
            DataRecord {
                source: "test".to_string(),
                kind: "wallet".to_string(),
                payload: b"test".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];
        ctx.add_records(records).unwrap();
        ctx.add_payload(vec![1, 2, 3, 4, 5]).unwrap();

        let summary = ctx.get_summary().unwrap();
        assert_eq!(summary.record_count, 1);
        assert_eq!(summary.payload_count, 1);
        assert_eq!(summary.total_payload_bytes, 5);
    }

    #[test]
    fn test_thread_safety() {
        let ctx = Arc::new(DataContext::new());
        let mut handles = vec![];

        for i in 0..10 {
            let ctx_clone = Arc::clone(&ctx);
            let handle = std::thread::spawn(move || {
                let records = vec![DataRecord {
                    source: format!("thread_{}", i),
                    kind: "test".to_string(),
                    payload: vec![i as u8],
                    metadata: BTreeMap::new(),
                }];
                ctx_clone.add_records(records).unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(ctx.record_count().unwrap(), 10);
    }
}
