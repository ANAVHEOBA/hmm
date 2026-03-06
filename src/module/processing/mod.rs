pub mod compress;
pub mod dedupe;
pub mod encrypt;
pub mod errors;
pub mod normalize;
pub mod pipeline;
pub mod types;

pub use compress::{
    compress, compress_gzip, compress_gzip_best, compress_gzip_fast, compress_rle,
    decompress_gzip, decompress_rle, CompressionMode,
};
pub use dedupe::dedupe_records;
pub use encrypt::{AesCipher, AesKey};
pub use errors::ProcessingError;
pub use normalize::normalize_records;
pub use pipeline::{ProcessedBundle, ProcessingConfig, ProcessingPipeline};
pub use types::{DataRecord, NormalizedRecord};
