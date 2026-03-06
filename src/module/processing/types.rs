use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRecord {
    pub source: String,
    pub kind: String,
    pub payload: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

impl DataRecord {
    pub fn new<S: Into<String>, K: Into<String>>(source: S, kind: K, payload: Vec<u8>) -> Self {
        Self {
            source: source.into(),
            kind: kind.into(),
            payload,
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRecord {
    pub source: String,
    pub kind: String,
    pub payload: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}
