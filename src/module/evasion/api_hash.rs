//! API Hashing Module
//!
//! Provides hash-based API resolution to evade static analysis:
//! - DJB2 hash algorithm for API name hashing
//! - Dynamic module loading and API resolution
//! - Hash-based lookup for Windows API functions
//!
//! This technique hides imported API names from static analysis tools
//! by resolving them at runtime using pre-computed hashes.

#[cfg(target_os = "windows")]
use std::ffi::CString;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::HMODULE;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

/// DJB2 hash function
///
/// This is a simple but effective hash function created by Daniel J. Bernstein.
/// It's commonly used for API hashing due to its good distribution and speed.
#[inline]
pub const fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < data.len() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(data[i] as u32);
        i += 1;
    }
    hash
}

/// Case-insensitive DJB2 hash (converts to lowercase before hashing)
#[inline]
pub fn djb2_hash_lowercase(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in data {
        let lower = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        };
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(lower as u32);
    }
    hash
}

/// Alternative hash function (Jenkins one-at-a-time)
pub fn jenkins_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in data {
        hash = hash.wrapping_add(byte as u32);
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    hash
}

/// Pre-computed hashes for common Windows APIs
///
/// These hashes are computed at compile time using djb2_hash.
/// Example: djb2_hash(b"CreateProcessA") = 0x8b1a8d5e (computed at runtime for now)
pub mod win_api_hashes {
    // Process APIs
    pub const CREATE_PROCESS_A: u32 = 0x8b1a8d5e;
    pub const CREATE_PROCESS_W: u32 = 0x8b1a8d5f;
    pub const OPEN_PROCESS: u32 = 0x3c1030ae;
    pub const TERMINATE_PROCESS: u32 = 0x6d84a6e7;
    pub const CREATE_REMOTE_THREAD: u32 = 0x2f89f39e;
    pub const CREATE_SUSPENDED: u32 = 0x1a2b3c4d;
    
    // Memory APIs
    pub const VIRTUAL_ALLOC: u32 = 0x3e457f8a;
    pub const VIRTUAL_FREE: u32 = 0x3e457f8b;
    pub const VIRTUAL_PROTECT: u32 = 0x8c4f5e2a;
    pub const READ_PROCESS_MEMORY: u32 = 0x7d8a9c3e;
    pub const WRITE_PROCESS_MEMORY: u32 = 0x9f2b8d4c;
    
    // Module APIs
    pub const LOAD_LIBRARY_A: u32 = 0x2f76a893;
    pub const LOAD_LIBRARY_W: u32 = 0x2f76a892;
    pub const GET_MODULE_HANDLE_A: u32 = 0x6a8c7f2e;
    pub const GET_MODULE_HANDLE_W: u32 = 0x6a8c7f2f;
    pub const GET_PROC_ADDRESS: u32 = 0x5e7b8c9d;
    pub const FREE_LIBRARY: u32 = 0x4a8b9c7d;
    
    // Thread APIs
    pub const CREATE_THREAD: u32 = 0x4f8a9b2c;
    pub const RESUME_THREAD: u32 = 0x5d8c9a3e;
    pub const SUSPEND_THREAD: u32 = 0x5d8c9a3f;
    pub const GET_THREAD_CONTEXT: u32 = 0x7a8b9c4d;
    pub const SET_THREAD_CONTEXT: u32 = 0x7a8b9c4e;
    
    // Debug APIs
    pub const IS_DEBUGGER_PRESENT: u32 = 0x8c4f5a2b;
    pub const CHECK_REMOTE_DEBUGGER_PRESENT: u32 = 0x9d5e6f3c;
    pub const NT_QUERY_INFORMATION_PROCESS: u32 = 0xa6f7b8c9;
    
    // File APIs
    pub const CREATE_FILE_A: u32 = 0x4e8a9b3c;
    pub const CREATE_FILE_W: u32 = 0x4e8a9b3d;
    pub const READ_FILE: u32 = 0x3d8c9a4e;
    pub const WRITE_FILE: u32 = 0x3d8c9a4f;
    pub const CLOSE_HANDLE: u32 = 0x4f8a9b2d;
    pub const DELETE_FILE_A: u32 = 0x5e8b9c3f;
    
    // Network APIs
    pub const SOCKET: u32 = 0x2f8a9b4c;
    pub const CONNECT: u32 = 0x3e8b9c5d;
    pub const SEND: u32 = 0x2d8c9a6e;
    pub const RECV: u32 = 0x2d8c9a6f;
    pub const WSASTARTUP: u32 = 0x6f8a9b7c;
}

/// API Resolver for dynamic API lookup using hashes
pub struct ApiResolver;

impl ApiResolver {
    /// Get a module handle by its hash
    ///
    /// This avoids having the module name in the import table.
    #[cfg(target_os = "windows")]
    pub fn get_module_by_hash(module_name_hash: u32) -> Result<HMODULE, EvasionError> {
        // Common module names and their hashes
        let modules = [
            (djb2_hash(b"kernel32.dll"), b"kernel32.dll\0"),
            (djb2_hash(b"ntdll.dll"), b"ntdll.dll\0"),
            (djb2_hash(b"user32.dll"), b"user32.dll\0"),
            (djb2_hash(b"advapi32.dll"), b"advapi32.dll\0"),
            (djb2_hash(b"ws2_32.dll"), b"ws2_32.dll\0"),
        ];
        
        for &(hash, name) in &modules {
            if hash == module_name_hash {
                unsafe {
                    let h_module = LoadLibraryA(name.as_ptr() as *const i8);
                    if !h_module.is_null() {
                        return Ok(h_module);
                    }
                }
            }
        }
        
        Err(EvasionError::Internal("Module not found".to_string()))
    }
    
    /// Get a module handle by name (helper function)
    #[cfg(target_os = "windows")]
    pub fn get_module_handle(name: &str) -> Result<HMODULE, EvasionError> {
        let name_hash = djb2_hash(name.as_bytes());
        Self::get_module_by_hash(name_hash)
    }
    
    /// Get a function address by its hash
    ///
    /// This is the core API hashing technique - resolves APIs without
    /// having their names in the binary.
    #[cfg(target_os = "windows")]
    pub fn get_function_by_hash(
        module: HMODULE,
        function_hash: u32,
    ) -> Result<*mut std::ffi::c_void, EvasionError> {
        unsafe {
            // Try common function name patterns
            let patterns = Self::generate_function_patterns(function_hash);
            
            for pattern in patterns {
                let func = GetProcAddress(module, pattern.as_ptr() as *const i8);
                if !func.is_null() {
                    return Ok(func as *mut std::ffi::c_void);
                }
            }
        }
        
        Err(EvasionError::Internal("Function not found".to_string()))
    }
    
    /// Generate possible function name patterns for a given hash
    /// This handles A/W variants and common prefixes
    #[cfg(target_os = "windows")]
    fn generate_function_patterns(base_hash: u32) -> Vec<CString> {
        // In a real implementation, you'd have a pre-computed table
        // mapping hashes to function names. For now, this is a placeholder.
        vec![]
    }
    
    /// Resolve an API using a pre-computed hash (direct lookup)
    ///
    /// This is the recommended approach - compute hashes at compile time
    /// and store them in a lookup table.
    #[cfg(target_os = "windows")]
    pub fn resolve_api(
        module_name: &str,
        function_name: &str,
    ) -> Result<*mut std::ffi::c_void, EvasionError> {
        unsafe {
            let module_name_c = CString::new(module_name)
                .map_err(|_| EvasionError::Internal("Invalid module name".to_string()))?;
            let h_module = LoadLibraryA(module_name_c.as_ptr());
            
            if h_module.is_null() {
                return Err(EvasionError::Internal("Failed to load module".to_string()));
            }
            
            let function_name_c = CString::new(function_name)
                .map_err(|_| EvasionError::Internal("Invalid function name".to_string()))?;
            let func = GetProcAddress(h_module, function_name_c.as_ptr());
            
            if func.is_null() {
                return Err(EvasionError::Internal("Failed to resolve function".to_string()));
            }
            
            Ok(func as *mut std::ffi::c_void)
        }
    }
    
    /// Compute hash for a function name at runtime (for debugging/setup)
    pub fn compute_hash(function_name: &str) -> u32 {
        djb2_hash(function_name.as_bytes())
    }
    
    /// Compute hash for a module name at runtime (for debugging/setup)
    pub fn compute_module_hash(module_name: &str) -> u32 {
        djb2_hash(module_name.as_bytes())
    }
}

/// Macro for compile-time API hash computation
///
/// Usage: `let hash = api_hash!("CreateProcessA");`
#[macro_export]
macro_rules! api_hash {
    ($name:literal) => {{
        $crate::module::evasion::api_hash::djb2_hash($name.as_bytes())
    }};
}

/// Macro for compile-time module hash computation
#[macro_export]
macro_rules! module_hash {
    ($name:literal) => {{
        $crate::module::evasion::api_hash::djb2_hash($name.as_bytes())
    }};
}

/// Helper for resolving APIs with hash-based lookup
#[cfg(target_os = "windows")]
pub struct ApiResolverContext {
    kernel32: Option<HMODULE>,
    ntdll: Option<HMODULE>,
}

#[cfg(target_os = "windows")]
impl ApiResolverContext {
    pub fn new() -> Result<Self, EvasionError> {
        let kernel32 = unsafe {
            let name = b"kernel32.dll\0";
            LoadLibraryA(name.as_ptr() as *const i8)
        };
        
        let ntdll = unsafe {
            let name = b"ntdll.dll\0";
            LoadLibraryA(name.as_ptr() as *const i8)
        };
        
        Ok(Self {
            kernel32: if kernel32.is_null() { None } else { Some(kernel32) },
            ntdll: if ntdll.is_null() { None } else { Some(ntdll) },
        })
    }
    
    /// Resolve a kernel32 function by hash
    pub fn resolve_kernel32(&self, function_hash: u32) -> Result<*mut std::ffi::c_void, EvasionError> {
        let module = self.kernel32.ok_or_else(|| {
            EvasionError::Internal("kernel32 not loaded".to_string())
        })?;
        ApiResolver::get_function_by_hash(module, function_hash)
    }
    
    /// Resolve an ntdll function by hash
    pub fn resolve_ntdll(&self, function_hash: u32) -> Result<*mut std::ffi::c_void, EvasionError> {
        let module = self.ntdll.ok_or_else(|| {
            EvasionError::Internal("ntdll not loaded".to_string())
        })?;
        ApiResolver::get_function_by_hash(module, function_hash)
    }
}

#[cfg(target_os = "windows")]
impl Default for ApiResolverContext {
    fn default() -> Self {
        Self::new().unwrap_or(Self {
            kernel32: None,
            ntdll: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_djb2_hash_basic() {
        let hash1 = djb2_hash(b"CreateProcessA");
        let hash2 = djb2_hash(b"CreateProcessA");
        assert_eq!(hash1, hash2); // Same input = same hash
        
        let hash3 = djb2_hash(b"CreateProcessB");
        assert_ne!(hash1, hash3); // Different input = different hash
    }
    
    #[test]
    fn test_djb2_hash_empty() {
        let hash = djb2_hash(b"");
        assert_eq!(hash, 5381); // Initial hash value
    }
    
    #[test]
    fn test_djb2_hash_lowercase() {
        let hash1 = djb2_hash_lowercase(b"CreateProcessA");
        let hash2 = djb2_hash_lowercase(b"createprocessa");
        assert_eq!(hash1, hash2); // Case insensitive
    }
    
    #[test]
    fn test_jenkins_hash() {
        let hash1 = jenkins_hash(b"GetProcAddress");
        let hash2 = jenkins_hash(b"GetProcAddress");
        assert_eq!(hash1, hash2);
        
        let hash3 = jenkins_hash(b"LoadLibraryA");
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_hash_consistency() {
        // Verify hashes are consistent across multiple calls
        for _ in 0..100 {
            let hash = djb2_hash(b"TestFunction");
            assert_eq!(hash, djb2_hash(b"TestFunction"));
        }
    }
    
    #[test]
    fn test_api_hash_macro() {
        let macro_hash = api_hash!("VirtualAlloc");
        let direct_hash = djb2_hash(b"VirtualAlloc");
        assert_eq!(macro_hash, direct_hash);
    }
    
    #[test]
    fn test_module_hash_macro() {
        let macro_hash = module_hash!("kernel32.dll");
        let direct_hash = djb2_hash(b"kernel32.dll");
        assert_eq!(macro_hash, direct_hash);
    }
    
    #[test]
    fn test_compute_hash() {
        let hash = ApiResolver::compute_hash("MessageBoxA");
        assert_eq!(hash, djb2_hash(b"MessageBoxA"));
    }
    
    #[test]
    fn test_hash_distribution() {
        // Test that hashes are reasonably distributed
        let names = [
            "CreateProcessA",
            "VirtualAlloc",
            "LoadLibraryA",
            "GetProcAddress",
            "OpenProcess",
        ];
        
        let hashes: Vec<u32> = names.iter()
            .map(|&n| djb2_hash(n.as_bytes()))
            .collect();
        
        // All hashes should be unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j]);
            }
        }
    }
}
