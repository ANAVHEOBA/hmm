#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRequest {
    pub content_type: String,
    pub payload: Vec<u8>,
}

impl UploadRequest {
    pub fn binary(payload: Vec<u8>) -> Self {
        Self {
            content_type: "application/octet-stream".to_string(),
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadResponse {
    pub uploaded: bool,
    pub status_code: Option<u16>,
    pub body: Vec<u8>,
}

impl UploadResponse {
    pub fn skipped() -> Self {
        Self {
            uploaded: false,
            status_code: None,
            body: Vec::new(),
        }
    }
}
