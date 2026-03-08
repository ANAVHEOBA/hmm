//! Code Packing Module
//!
//! Provides executable packing techniques to evade detection:
//! - PE file packing with custom stub
//! - Section compression and encryption
//! - Import table obfuscation
//! - Runtime unpacking stub
//!
//! Packing compresses/encrypts the executable and adds a stub
//! that unpacks it at runtime, evading signature-based detection.

use std::io::{Read, Write};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};

use super::errors::EvasionError;

/// Packing configuration
#[derive(Debug, Clone)]
pub struct PackConfig {
    /// Compression level (0-9)
    pub compression_level: u32,
    /// Encrypt packed data
    pub encrypt: bool,
    /// Encryption key (if encrypt is true)
    pub encryption_key: Option<Vec<u8>>,
    /// Obfuscate import table
    pub obfuscate_imports: bool,
    /// Add anti-debugging to stub
    pub anti_debug: bool,
    /// Add anti-VM checks to stub
    pub anti_vm: bool,
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            compression_level: 9,
            encrypt: true,
            encryption_key: None,
            obfuscate_imports: true,
            anti_debug: false,
            anti_vm: false,
        }
    }
}

/// Packed executable result
#[derive(Debug, Clone)]
pub struct PackedExecutable {
    /// The packed/stub executable bytes
    pub data: Vec<u8>,
    /// Original entry point
    pub original_entry: u32,
    /// Packed section size
    pub packed_size: usize,
    /// Original size
    pub original_size: usize,
    /// Compression ratio
    pub compression_ratio: f64,
}

/// PE file packer
pub struct Packer;

impl Packer {
    /// Pack a PE executable
    ///
    /// # Arguments
    /// * `pe_data` - Raw PE file bytes
    /// * `config` - Packing configuration
    ///
    /// # Returns
    /// Packed executable with unpacking stub
    pub fn pack_pe(pe_data: &[u8], config: &PackConfig) -> Result<PackedExecutable, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::pack_pe_windows(pe_data, config)
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, we can still pack PE files but can't validate
            Self::pack_pe_generic(pe_data, config)
        }
    }

    /// Generic PE packing (works on all platforms)
    fn pack_pe_generic(pe_data: &[u8], config: &PackConfig) -> Result<PackedExecutable, EvasionError> {
        if pe_data.len() < 64 {
            return Err(EvasionError::Packing("Invalid PE file - too small".to_string()));
        }

        // Validate DOS header
        if &pe_data[0..2] != b"MZ" {
            return Err(EvasionError::Packing("Invalid DOS signature".to_string()));
        }

        // Get PE offset from DOS header
        let pe_offset = u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;
        
        if pe_offset + 4 > pe_data.len() {
            return Err(EvasionError::Packing("Invalid PE offset".to_string()));
        }

        // Validate PE signature
        if &pe_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(EvasionError::Packing("Invalid PE signature".to_string()));
        }

        // Extract original entry point
        let entry_point = u32::from_le_bytes([
            pe_data[pe_offset + 0x10],
            pe_data[pe_offset + 0x11],
            pe_data[pe_offset + 0x12],
            pe_data[pe_offset + 0x13],
        ]);

        // Compress the PE data
        let compressed = Self::compress_data(pe_data, config.compression_level)?;

        // Optionally encrypt
        let packed_data = if config.encrypt {
            let key = config.encryption_key.clone().unwrap_or_else(|| Self::generate_key());
            Self::xor_encrypt(&compressed, &key)
        } else {
            compressed
        };

        // Generate the unpacking stub
        let stub = Self::generate_unpacking_stub(&packed_data, entry_point, config);

        let original_size = pe_data.len();
        let packed_size = stub.len();

        Ok(PackedExecutable {
            data: stub,
            original_entry: entry_point,
            packed_size,
            original_size,
            compression_ratio: packed_size as f64 / original_size as f64 * 100.0,
        })
    }

    #[cfg(target_os = "windows")]
    fn pack_pe_windows(pe_data: &[u8], config: &PackConfig) -> Result<PackedExecutable, EvasionError> {
        Self::pack_pe_generic(pe_data, config)
    }

    /// Compress data using GZIP
    fn compress_data(data: &[u8], level: u32) -> Result<Vec<u8>, EvasionError> {
        let compression = match level {
            0..=3 => Compression::fast(),
            4..=6 => Compression::default(),
            _ => Compression::best(),
        };

        let mut encoder = GzEncoder::new(Vec::new(), compression);
        encoder.write_all(data)
            .map_err(|e| EvasionError::Packing(format!("Compression failed: {}", e)))?;
        
        encoder.finish()
            .map_err(|e| EvasionError::Packing(format!("Compression finish failed: {}", e)))
    }

    /// Decompress data
    pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, EvasionError> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| EvasionError::Packing(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }

    /// XOR encrypt/decrypt data
    fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .zip(key.iter().cycle())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }

    /// Generate encryption key
    fn generate_key() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let key_len = rng.gen_range(16..32);
        (0..key_len).map(|_| rng.gen::<u8>()).collect()
    }

    /// Generate the unpacking stub
    ///
    /// This creates a minimal PE executable that:
    /// 1. Allocates memory
    /// 2. Decrypts (if needed) and decompresses the payload
    /// 3. Transfers control to the original entry point
    fn generate_unpacking_stub(packed_data: &[u8], entry_point: u32, config: &PackConfig) -> Vec<u8> {
        // This is a simplified stub generator
        // A real implementation would generate a full PE with proper sections

        let mut stub = Vec::new();

        // DOS Header
        let mut dos_header = vec![0u8; 64];
        dos_header[0] = b'M';
        dos_header[1] = b'Z';
        
        // Point e_lfanew to PE header at offset 64
        let pe_offset: u32 = 64;
        dos_header[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        stub.extend_from_slice(&dos_header);

        // Pad to PE header
        while stub.len() < 64 {
            stub.push(0);
        }

        // PE Header
        let mut pe_header = vec![0u8; 248]; // Size of PE headers + optional header
        
        // PE signature
        pe_header[0] = b'P';
        pe_header[1] = b'E';
        pe_header[2] = 0;
        pe_header[3] = 0;

        // COFF header
        pe_header[4..6].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        pe_header[6..8].copy_from_slice(&3u16.to_le_bytes()); // NumberOfSections: 2 (.text, .packed)
        
        // Optional header starts at offset 24
        pe_header[24] = 0x0B; // Magic: PE32+

        // Entry point (will be set to our stub code)
        let stub_entry: u32 = 0x1000;
        pe_header[40..44].copy_from_slice(&stub_entry.to_le_bytes());

        // Image base (default for x64)
        let image_base: u64 = 0x140000000;
        pe_header[48..56].copy_from_slice(&image_base.to_le_bytes());

        // Section alignment
        pe_header[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
        
        // File alignment
        pe_header[60..64].copy_from_slice(&0x200u32.to_le_bytes());

        // Size of image
        let size_of_image: u32 = 0x5000;
        pe_header[80..84].copy_from_slice(&size_of_image.to_le_bytes());

        // Size of headers
        let size_of_headers: u32 = 0x200;
        pe_header[84..88].copy_from_slice(&size_of_headers.to_le_bytes());

        // Subsystem: Windows GUI
        pe_header[108..110].copy_from_slice(&2u16.to_le_bytes());

        // DllCharacteristics
        pe_header[110..112].copy_from_slice(&0x8160u16.to_le_bytes());

        // Size of stack reserve
        let stack_reserve: u64 = 0x100000;
        pe_header[112..120].copy_from_slice(&stack_reserve.to_le_bytes());

        // Size of stack commit
        let stack_commit: u64 = 0x1000;
        pe_header[120..128].copy_from_slice(&stack_commit.to_le_bytes());

        // Size of heap reserve
        let heap_reserve: u64 = 0x100000;
        pe_header[128..136].copy_from_slice(&heap_reserve.to_le_bytes());

        // Size of heap commit
        let heap_commit: u64 = 0x1000;
        pe_header[136..144].copy_from_slice(&heap_commit.to_le_bytes());

        // Number of RVA and sizes
        pe_header[144..148].copy_from_slice(&16u32.to_le_bytes());

        // Store packed data offset and size for the stub
        let packed_offset: u32 = 0x2000;
        let packed_size: u32 = packed_data.len() as u32;
        let original_entry: u32 = entry_point;

        // Embed metadata at the end of the PE header area
        // In a real implementation, this would be in a separate section
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&packed_offset.to_le_bytes());
        metadata.extend_from_slice(&packed_size.to_le_bytes());
        metadata.extend_from_slice(&original_entry.to_le_bytes());
        metadata.extend_from_slice(&(config.encrypt as u32).to_le_bytes());
        if config.encrypt {
            let key = config.encryption_key.clone().unwrap_or_else(|| Self::generate_key());
            metadata.extend_from_slice(&(key.len() as u32).to_le_bytes());
            metadata.extend_from_slice(&key);
        }
        metadata.extend_from_slice(packed_data);

        // Pad metadata to section boundary
        while (stub.len() + pe_header.len() + metadata.len()) % 0x200 != 0 {
            metadata.push(0);
        }

        stub.extend_from_slice(&pe_header);

        // .text section (stub code)
        let mut text_section = vec![0u8; 40];
        text_section[0..8].copy_from_slice(b".text\0\0\0");
        let code_size: u32 = 0x1000;
        text_section[8..12].copy_from_slice(&code_size.to_le_bytes()); // VirtualSize
        text_section[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        let raw_size: u32 = 0x200;
        text_section[16..20].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfRawData
        text_section[20..24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        text_section[36..40].copy_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics (CODE, EXECUTE, READ)
        stub.extend_from_slice(&text_section);

        // .packed section
        let mut packed_section = vec![0u8; 40];
        packed_section[0..8].copy_from_slice(b".packed\0");
        packed_section[8..12].copy_from_slice(&(metadata.len() as u32).to_le_bytes()); // VirtualSize
        packed_section[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        packed_section[16..20].copy_from_slice(&((metadata.len() as u32 + 0x1FF) & !0x1FF).to_le_bytes()); // SizeOfRawData
        packed_section[20..24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        packed_section[36..40].copy_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics (INITIALIZED_DATA, READ, WRITE)
        stub.extend_from_slice(&packed_section);

        // Pad to file alignment
        while stub.len() < 0x200 {
            stub.push(0);
        }

        // Stub code (x64 shellcode that unpacks and executes)
        let stub_code = Self::generate_stub_shellcode(config);
        let mut code_section = vec![0u8; 0x200 - stub_code.len()];
        code_section[0..stub_code.len()].copy_from_slice(&stub_code);
        stub.extend_from_slice(&code_section);

        // Pad to packed data offset
        while stub.len() < 0x2000 {
            stub.push(0);
        }

        // Add packed data and metadata
        stub.extend_from_slice(&metadata);

        stub
    }

    /// Generate the unpacking shellcode stub
    ///
    /// This x64 shellcode:
    /// 1. Finds the packed data in memory
    /// 2. Allocates executable memory
    /// 3. Decrypts (if needed) and decompresses
    /// 4. Transfers control to the unpacked code
    fn generate_stub_shellcode(_config: &PackConfig) -> Vec<u8> {
        let mut shellcode = Vec::new();

        // This is a template - real shellcode would need proper implementation
        // The stub would:
        // - Use GetModuleHandleA to find kernel32
        // - Use GetProcAddress to find VirtualAlloc, RtlDecompressBuffer
        // - Allocate RWX memory
        // - Decrypt/decompress the payload
        // - Jump to the original entry point

        // Minimal stub template (placeholder)
        // In practice, this would be a full unpacking routine
        
        // For now, we generate a simple stub that just returns
        // Real implementation would be much more complex
        
        shellcode.extend_from_slice(&[
            // xor rax, rax
            0x48, 0x31, 0xC0,
            // ret
            0xC3,
        ]);

        shellcode
    }

    /// Unpack a packed executable
    pub fn unpack(_pe_packed: &[u8]) -> Result<Vec<u8>, EvasionError> {
        // This would extract and unpack the payload
        // In a real implementation, you'd parse the PE and extract the .packed section
        Err(EvasionError::Packing(
            "Unpacking requires parsing the packed PE format - stub".to_string(),
        ))
    }
}

/// Unpacker for packed executables
pub struct Unpacker;

impl Unpacker {
    /// Unpack a packed executable in memory
    ///
    /// This simulates what the stub does at runtime:
    /// 1. Locate the packed section
    /// 2. Decrypt if needed
    /// 3. Decompress
    /// 4. Return the original PE
    pub fn unpack_in_memory(_packed: &PackedExecutable, _key: Option<&[u8]>) -> Result<Vec<u8>, EvasionError> {
        // This is a simplified unpacker
        // A real implementation would parse the stub's metadata

        Err(EvasionError::Packing(
            "In-memory unpacking requires stub metadata parsing - stub".to_string(),
        ))
    }

    /// Dump an unpacked process from memory
    ///
    /// After a packed executable runs, this can dump the unpacked
    /// image from the process memory.
    pub fn dump_process_memory(
        _process_id: u32,
        _image_base: usize,
    ) -> Result<Vec<u8>, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            use std::mem;
            use winapi::um::handleapi::CloseHandle;
            use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
            use winapi::um::processthreadsapi::OpenProcess;
            use winapi::um::winnt::{PROCESS_VM_READ, MEMORY_BASIC_INFORMATION};

            unsafe {
                let h_process = OpenProcess(PROCESS_VM_READ, 0, _process_id);
                if h_process.is_null() {
                    return Err(EvasionError::Packing(
                        "Failed to open process".to_string(),
                    ));
                }

                // Query memory region
                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                let result = VirtualQueryEx(
                    h_process,
                    _image_base as *const _,
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    CloseHandle(h_process);
                    return Err(EvasionError::Packing(
                        "Failed to query memory".to_string(),
                    ));
                }

                // Allocate buffer for the image
                let mut buffer = vec![0u8; mbi.RegionSize];
                
                // Read the memory
                let read_result = ReadProcessMemory(
                    h_process,
                    _image_base as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len(),
                    std::ptr::null_mut(),
                );

                CloseHandle(h_process);

                if read_result == 0 {
                    return Err(EvasionError::Packing(
                        "Failed to read process memory".to_string(),
                    ));
                }

                Ok(buffer)
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Packing(
                "Process memory dumping is primarily available on Windows".to_string(),
            ))
        }
    }
}

/// PE section utilities
pub mod pe_utils {
    /// Parse PE sections
    pub fn parse_sections(pe_data: &[u8]) -> Result<Vec<SectionInfo>, &'static str> {
        if pe_data.len() < 64 || &pe_data[0..2] != b"MZ" {
            return Err("Invalid PE file");
        }

        let pe_offset = u32::from_le_bytes([
            pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F],
        ]) as usize;

        if pe_offset + 24 > pe_data.len() || &pe_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err("Invalid PE signature");
        }

        let num_sections = u16::from_le_bytes([pe_data[pe_offset + 6], pe_data[pe_offset + 7]]) as usize;
        let optional_header_size = u16::from_le_bytes([
            pe_data[pe_offset + 20], pe_data[pe_offset + 21],
        ]) as usize;

        let sections_offset = pe_offset + 24 + optional_header_size;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let section_offset = sections_offset + (i * 40);
            if section_offset + 40 > pe_data.len() {
                return Err("Section table out of bounds");
            }

            let name = String::from_utf8_lossy(&pe_data[section_offset..section_offset + 8])
                .trim_end_matches('\0')
                .to_string();

            let virtual_size = u32::from_le_bytes([
                pe_data[section_offset + 8],
                pe_data[section_offset + 9],
                pe_data[section_offset + 10],
                pe_data[section_offset + 11],
            ]);

            let virtual_address = u32::from_le_bytes([
                pe_data[section_offset + 12],
                pe_data[section_offset + 13],
                pe_data[section_offset + 14],
                pe_data[section_offset + 15],
            ]);

            let raw_size = u32::from_le_bytes([
                pe_data[section_offset + 16],
                pe_data[section_offset + 17],
                pe_data[section_offset + 18],
                pe_data[section_offset + 19],
            ]);

            let raw_offset = u32::from_le_bytes([
                pe_data[section_offset + 20],
                pe_data[section_offset + 21],
                pe_data[section_offset + 22],
                pe_data[section_offset + 23],
            ]);

            sections.push(SectionInfo {
                name,
                virtual_size,
                virtual_address,
                raw_size,
                raw_offset,
            });
        }

        Ok(sections)
    }

    /// Section information
    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        pub name: String,
        pub virtual_size: u32,
        pub virtual_address: u32,
        pub raw_size: u32,
        pub raw_offset: u32,
    }

    /// Check if a file is a valid PE
    pub fn is_valid_pe(data: &[u8]) -> bool {
        data.len() >= 64 && &data[0..2] == b"MZ"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pe_detection() {
        // Valid DOS header
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80; // PE offset at 128
        
        // PE signature
        pe[0x80] = b'P';
        pe[0x81] = b'E';
        pe[0x82] = 0;
        pe[0x83] = 0;

        assert!(pe_utils::is_valid_pe(&pe));
    }

    #[test]
    fn test_invalid_pe_detection() {
        let invalid = vec![0u8; 512];
        assert!(!pe_utils::is_valid_pe(&invalid));
    }

    #[test]
    fn test_pack_config_default() {
        let config = PackConfig::default();
        assert_eq!(config.compression_level, 9);
        assert!(config.encrypt);
        assert!(config.obfuscate_imports);
    }

    #[test]
    fn test_xor_encrypt_decrypt() {
        let data = b"Hello, World!";
        let key = b"secret_key";
        
        let encrypted = Packer::xor_encrypt(data, key);
        let decrypted = Packer::xor_encrypt(&encrypted, key);
        
        assert_ne!(encrypted, data.as_slice());
        assert_eq!(decrypted, data.as_slice());
    }

    #[test]
    fn test_xor_with_empty_key() {
        let data = b"test data";
        let result = Packer::xor_encrypt(data, &[]);
        assert_eq!(result, data.as_slice());
    }

    #[test]
    fn test_compress_decompress_round_trip() {
        let original = b"This is test data that should compress well because it has repetition. This is test data that should compress well because it has repetition.";
        
        let compressed = Packer::compress_data(original, 9).unwrap();
        let decompressed = Packer::decompress_data(&compressed).unwrap();
        
        assert_eq!(original, &decompressed[..]);
        assert!(compressed.len() < original.len());
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Test data for compression testing. ".repeat(100);
        
        let fast = Packer::compress_data(&data, 1).unwrap();
        let best = Packer::compress_data(&data, 9).unwrap();
        
        // Best compression should produce smaller or equal output
        assert!(best.len() <= fast.len());
    }

    #[test]
    fn test_pack_invalid_pe() {
        let invalid = vec![0u8; 32];
        let result = Packer::pack_pe(&invalid, &PackConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_pe_missing_pe_signature() {
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        
        let result = Packer::pack_pe(&pe, &PackConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_section_parsing() {
        // Create minimal PE with one section
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        
        pe[0x80] = b'P';
        pe[0x81] = b'E';
        pe[0x82] = 0;
        pe[0x83] = 0;
        
        // Number of sections = 1
        pe[0x86] = 1;
        
        // Optional header size = 0 (simplified)
        pe[0x94] = 0;
        pe[0x95] = 0;
        
        // Section at offset 0x80 + 24 = 0x98
        // Section name
        pe[0x98..0xA0].copy_from_slice(b".text\0\0\0");
        // Virtual size
        pe[0xA0..0xA4].copy_from_slice(&0x1000u32.to_le_bytes());
        // Virtual address
        pe[0xA4..0xA8].copy_from_slice(&0x1000u32.to_le_bytes());
        // Raw size
        pe[0xA8..0xAC].copy_from_slice(&0x200u32.to_le_bytes());
        // Raw offset
        pe[0xAC..0xB0].copy_from_slice(&0x200u32.to_le_bytes());

        let sections = pe_utils::parse_sections(&pe);
        assert!(sections.is_ok());
        let secs = sections.unwrap();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name, ".text");
    }
}
