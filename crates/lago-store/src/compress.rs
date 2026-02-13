use lago_core::LagoResult;

/// Default zstd compression level.
pub const COMPRESSION_LEVEL: i32 = 3;

/// Compress data using zstd at the default compression level.
pub fn compress(data: &[u8]) -> LagoResult<Vec<u8>> {
    zstd::encode_all(data, COMPRESSION_LEVEL)
        .map_err(|e| lago_core::LagoError::Store(format!("zstd compress failed: {e}")))
}

/// Decompress zstd-compressed data.
pub fn decompress(data: &[u8]) -> LagoResult<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| lago_core::LagoError::Store(format!("zstd decompress failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let compressed = compress(b"").unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn roundtrip_data() {
        let original = b"hello world, this is some test data for compression";
        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compressed_is_different_from_original() {
        let original = b"hello world, this is some test data for compression";
        let compressed = compress(original).unwrap();
        assert_ne!(compressed.as_slice(), original.as_slice());
    }

    #[test]
    fn decompress_invalid_data_fails() {
        let result = decompress(b"this is not valid zstd data");
        assert!(result.is_err());
    }
}
