use flate2::{
    Compression,
    read::GzDecoder,
    write::GzEncoder as WriteGzEncoder,
};
use std::io::{Read, Write};

use super::errors::ProcessingError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode {
    None,
    Rle,
    Gzip,
    GzipBest,
    GzipFast,
}

impl Default for CompressionMode {
    fn default() -> Self {
        Self::Gzip
    }
}

/// RLE compression (simple, fast, for repetitive data)
pub fn compress_rle(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(data.len());
    let mut current = data[0];
    let mut count: u8 = 1;

    for &byte in &data[1..] {
        if byte == current && count < u8::MAX {
            count += 1;
        } else {
            out.push(count);
            out.push(current);
            current = byte;
            count = 1;
        }
    }

    out.push(count);
    out.push(current);
    Ok(out)
}

pub fn decompress_rle(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() % 2 != 0 {
        return Err(ProcessingError::Compression(
            "invalid RLE payload length".to_string(),
        ));
    }

    let mut out = Vec::new();
    for chunk in data.chunks_exact(2) {
        let count = chunk[0];
        let value = chunk[1];
        out.extend(std::iter::repeat_n(value, count as usize));
    }
    Ok(out)
}

/// GZIP compression (better ratio, slightly slower)
pub fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    compress_gzip_with_level(data, Compression::default())
}

/// GZIP with best compression (slowest, best ratio)
pub fn compress_gzip_best(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    compress_gzip_with_level(data, Compression::best())
}

/// GZIP with fast compression (fastest, lower ratio)
pub fn compress_gzip_fast(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    compress_gzip_with_level(data, Compression::fast())
}

/// GZIP with custom compression level
pub fn compress_gzip_with_level(
    data: &[u8],
    level: Compression,
) -> Result<Vec<u8>, ProcessingError> {
    let mut encoder = WriteGzEncoder::new(Vec::new(), level);
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

/// GZIP decompression
pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Generic compress function that selects algorithm based on mode
pub fn compress(data: &[u8], mode: CompressionMode) -> Result<Vec<u8>, ProcessingError> {
    match mode {
        CompressionMode::None => Ok(data.to_vec()),
        CompressionMode::Rle => compress_rle(data),
        CompressionMode::Gzip => compress_gzip(data),
        CompressionMode::GzipBest => compress_gzip_best(data),
        CompressionMode::GzipFast => compress_gzip_fast(data),
    }
}

/// Generic decompress function for GZIP
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    decompress_gzip(data)
}

/// Get compression ratio (percentage of original size)
pub fn compression_ratio(original: usize, compressed: usize) -> f64 {
    if original == 0 {
        return 0.0;
    }
    (compressed as f64 / original as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_round_trip() {
        let original = b"Hello, World! This is a test of GZIP compression.";
        let compressed = compress_gzip(original).unwrap();
        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(original, &decompressed[..]);
    }

    #[test]
    fn gzip_compresses_repetitive_data() {
        let original = vec![b'a'; 1000];
        let compressed = compress_gzip(&original).unwrap();
        assert!(compressed.len() < original.len());
        let ratio = compression_ratio(original.len(), compressed.len());
        assert!(ratio < 5.0); // Should be less than 5% of original
    }

    #[test]
    fn gzip_best_vs_fast() {
        let data = b"This is some test data that should compress reasonably well with GZIP.";
        let fast = compress_gzip_fast(data).unwrap();
        let best = compress_gzip_best(data).unwrap();
        // Best compression should produce smaller output
        assert!(best.len() <= fast.len());
    }

    #[test]
    fn compress_mode_none() {
        let data = b"test data";
        let result = compress(data, CompressionMode::None).unwrap();
        assert_eq!(data, &result[..]);
    }

    #[test]
    fn compress_mode_gzip() {
        let data = b"test data that should compress";
        let result = compress(data, CompressionMode::Gzip).unwrap();
        let decompressed = decompress_gzip(&result).unwrap();
        assert_eq!(data, &decompressed[..]);
    }
}
