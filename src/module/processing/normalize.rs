use std::collections::BTreeMap;

use super::types::{DataRecord, NormalizedRecord};

pub fn normalize_records(records: &[DataRecord]) -> Vec<NormalizedRecord> {
    records
        .iter()
        .map(|record| NormalizedRecord {
            source: normalize_token(&record.source),
            kind: normalize_token(&record.kind),
            payload: normalize_payload(&record.kind, &record.payload),
            metadata: normalize_metadata(&record.metadata),
        })
        .collect()
}

fn normalize_token(value: &str) -> String {
    value.trim().to_lowercase()
}

fn normalize_payload(kind: &str, payload: &[u8]) -> Vec<u8> {
    if kind.trim().eq_ignore_ascii_case("text") {
        let text = String::from_utf8_lossy(payload);
        normalize_whitespace(&text).into_bytes()
    } else {
        payload.to_vec()
    }
}

fn normalize_whitespace(input: &str) -> String {
    input
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn normalize_metadata(metadata: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut normalized = BTreeMap::new();
    for (key, value) in metadata {
        normalized.insert(normalize_token(key), value.trim().to_string());
    }
    normalized
}
