use std::collections::BTreeMap;

use hmm_core_agent::module::processing::{
    compress_gzip, compress_rle, decompress_gzip, decompress_rle,
    CompressionMode, DataRecord, ProcessingConfig, ProcessingPipeline,
    AesCipher, compress, dedupe_records, normalize_records,
};

#[test]
fn normalize_and_dedupe_records() {
    let mut a = DataRecord::new(" Browser ", "text", b" hello   world ".to_vec());
    a.metadata
        .insert(" User ".to_string(), " Alice ".to_string());

    let mut b = DataRecord::new("browser", "TEXT", b"hello world".to_vec());
    b.metadata.insert("user".to_string(), "Alice".to_string());

    let normalized = normalize_records(&[a, b]);
    let deduped = dedupe_records(&normalized);

    assert_eq!(normalized[0].source, "browser");
    assert_eq!(normalized[0].kind, "text");
    assert_eq!(normalized[0].payload, b"hello world".to_vec());
    assert_eq!(deduped.len(), 1);
}

#[test]
fn rle_compression_round_trip() {
    let raw = b"aaaaabbbbccccccccccccdddddd".to_vec();
    let compressed = compress_rle(&raw).expect("compression should work");
    let restored = decompress_rle(&compressed).expect("decompression should work");

    assert_eq!(restored, raw);
}

#[test]
fn gzip_compression_round_trip() {
    let raw = b"This is test data for GZIP compression round trip testing.".to_vec();
    let compressed = compress_gzip(&raw).expect("gzip compression should work");
    let restored = decompress_gzip(&compressed).expect("gzip decompression should work");

    assert_eq!(restored, raw);
}

#[test]
fn gzip_compresses_large_data() {
    // Create repetitive data that should compress well
    let mut raw = Vec::with_capacity(10000);
    for _ in 0..100 {
        raw.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    
    let compressed = compress_gzip(&raw).expect("gzip compression should work");
    
    // GZIP should compress this significantly
    assert!(compressed.len() < raw.len() / 2);
}

#[test]
fn gzip_best_vs_fast() {
    let data = b"This is some test data that should compress reasonably well with GZIP compression.";
    let fast = compress(data, CompressionMode::GzipFast).unwrap();
    let best = compress(data, CompressionMode::GzipBest).unwrap();
    
    // Best compression should produce smaller or equal output
    assert!(best.len() <= fast.len());
}

#[test]
fn encryption_round_trip_works() {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(b"test-key");
    let cipher = AesCipher::new(key).expect("cipher key should be valid");
    let plain = b"sample-payload";

    let encrypted = cipher.encrypt(plain).expect("encryption should work");
    let decrypted = cipher.decrypt(&encrypted).expect("decompression should work");

    assert_ne!(encrypted, plain);
    assert_eq!(decrypted, plain);
}

#[test]
fn pipeline_with_gzip() {
    let mut record = DataRecord::new(" System ", "text", b"  one   two  ".to_vec());
    record.metadata = BTreeMap::from([(String::from(" Host "), String::from(" local "))]);

    let config = ProcessingConfig {
        compression: CompressionMode::Gzip,
        encryption_key: Some(b"pipeline-key".to_vec()),
    };
    let pipeline = ProcessingPipeline::new(config).expect("config should be valid");
    let bundle = pipeline.process(&[record]).expect("processing should succeed");

    assert_eq!(bundle.records.len(), 1);
    assert_eq!(bundle.records[0].source, "system");
    assert_eq!(bundle.records[0].payload, b"one two".to_vec());
    assert!(bundle.compressed);
    assert!(bundle.encrypted);
    assert!(!bundle.payload.is_empty());
}

#[test]
fn pipeline_with_gzip_best() {
    let record = DataRecord::new("test", "data", b"test payload".to_vec());

    let config = ProcessingConfig {
        compression: CompressionMode::GzipBest,
        encryption_key: None,
    };
    let pipeline = ProcessingPipeline::new(config).expect("config should be valid");
    let bundle = pipeline.process(&[record]).expect("processing should succeed");

    assert!(bundle.compressed);
    assert!(!bundle.encrypted);
}

#[test]
fn pipeline_with_no_compression() {
    let record = DataRecord::new("test", "data", b"test payload".to_vec());

    let config = ProcessingConfig {
        compression: CompressionMode::None,
        encryption_key: None,
    };
    let pipeline = ProcessingPipeline::new(config).expect("config should be valid");
    let bundle = pipeline.process(&[record]).expect("processing should succeed");

    assert!(!bundle.compressed);
    assert!(!bundle.encrypted);
}
