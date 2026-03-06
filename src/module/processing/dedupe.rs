use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use super::types::NormalizedRecord;

pub fn dedupe_records(records: &[NormalizedRecord]) -> Vec<NormalizedRecord> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for record in records {
        let fp = fingerprint(record);
        if seen.insert(fp) {
            deduped.push(record.clone());
        }
    }

    deduped
}

fn fingerprint(record: &NormalizedRecord) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    record.source.hash(&mut hasher);
    record.kind.hash(&mut hasher);
    record.payload.hash(&mut hasher);
    for (key, value) in &record.metadata {
        key.hash(&mut hasher);
        value.hash(&mut hasher);
    }
    hasher.finish()
}
