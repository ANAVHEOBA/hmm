use std::collections::BTreeMap;

use super::compress::{compress, CompressionMode};
use super::dedupe::dedupe_records;
use super::encrypt::AesCipher;
use super::errors::ProcessingError;
use super::normalize::normalize_records;
use super::types::{DataRecord, NormalizedRecord};

#[derive(Debug, Clone)]
pub struct ProcessingConfig {
    pub compression: CompressionMode,
    pub encryption_key: Option<Vec<u8>>,
    pub nonce: u64,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            compression: CompressionMode::Gzip,
            encryption_key: None,
            nonce: 0,
        }
    }
}

impl ProcessingConfig {
    pub fn validate(&self) -> Result<(), ProcessingError> {
        if let Some(key) = &self.encryption_key {
            if key.is_empty() {
                return Err(ProcessingError::InvalidConfig(
                    "encryption key cannot be empty".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessedBundle {
    pub records: Vec<NormalizedRecord>,
    pub payload: Vec<u8>,
    pub compressed: bool,
    pub encrypted: bool,
}

pub struct ProcessingPipeline {
    config: ProcessingConfig,
}

impl ProcessingPipeline {
    pub fn new(config: ProcessingConfig) -> Result<Self, ProcessingError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn process(&self, input: &[DataRecord]) -> Result<ProcessedBundle, ProcessingError> {
        let normalized = normalize_records(input);
        let deduped = dedupe_records(&normalized);

        let mut payload = serialize_records(&deduped)?;
        let mut compressed = false;
        let mut encrypted = false;

        if self.config.compression != CompressionMode::None {
            payload = compress(&payload, self.config.compression)?;
            compressed = true;
        }

        if let Some(key) = &self.config.encryption_key {
            // Convert key bytes to AesKey (32 bytes)
            let mut aes_key = [0u8; 32];
            let copy_len = std::cmp::min(key.len(), 32);
            aes_key[..copy_len].copy_from_slice(&key[..copy_len]);
            
            let cipher = AesCipher::new(aes_key)?;
            payload = cipher.encrypt(&payload)?;
            encrypted = true;
        }

        Ok(ProcessedBundle {
            records: deduped,
            payload,
            compressed,
            encrypted,
        })
    }
}

fn serialize_records(records: &[NormalizedRecord]) -> Result<Vec<u8>, ProcessingError> {
    let mut out = Vec::new();
    write_u32(records.len() as u32, &mut out);

    for record in records {
        write_bytes(record.source.as_bytes(), &mut out)?;
        write_bytes(record.kind.as_bytes(), &mut out)?;
        write_bytes(&record.payload, &mut out)?;

        write_u32(record.metadata.len() as u32, &mut out);
        for (key, value) in &record.metadata {
            write_bytes(key.as_bytes(), &mut out)?;
            write_bytes(value.as_bytes(), &mut out)?;
        }
    }

    Ok(out)
}

fn write_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), ProcessingError> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        ProcessingError::InvalidData("record field is too large to serialize".to_string())
    })?;
    write_u32(len, out);
    out.extend_from_slice(bytes);
    Ok(())
}

#[allow(dead_code)]
pub fn deserialize_records(mut input: &[u8]) -> Result<Vec<NormalizedRecord>, ProcessingError> {
    let total = read_u32(&mut input)? as usize;
    let mut out = Vec::with_capacity(total);

    for _ in 0..total {
        let source = String::from_utf8(read_bytes(&mut input)?)
            .map_err(|_| ProcessingError::InvalidData("invalid utf8 source".to_string()))?;
        let kind = String::from_utf8(read_bytes(&mut input)?)
            .map_err(|_| ProcessingError::InvalidData("invalid utf8 kind".to_string()))?;
        let payload = read_bytes(&mut input)?;

        let metadata_len = read_u32(&mut input)? as usize;
        let mut metadata = BTreeMap::new();
        for _ in 0..metadata_len {
            let key = String::from_utf8(read_bytes(&mut input)?)
                .map_err(|_| ProcessingError::InvalidData("invalid utf8 key".to_string()))?;
            let value = String::from_utf8(read_bytes(&mut input)?)
                .map_err(|_| ProcessingError::InvalidData("invalid utf8 value".to_string()))?;
            metadata.insert(key, value);
        }

        out.push(NormalizedRecord {
            source,
            kind,
            payload,
            metadata,
        });
    }

    Ok(out)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, ProcessingError> {
    if input.len() < 4 {
        return Err(ProcessingError::InvalidData(
            "unexpected end of payload".to_string(),
        ));
    }
    let (head, tail) = input.split_at(4);
    *input = tail;
    Ok(u32::from_le_bytes([head[0], head[1], head[2], head[3]]))
}

fn read_bytes(input: &mut &[u8]) -> Result<Vec<u8>, ProcessingError> {
    let len = read_u32(input)? as usize;
    if input.len() < len {
        return Err(ProcessingError::InvalidData(
            "unexpected end of payload".to_string(),
        ));
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head.to_vec())
}
