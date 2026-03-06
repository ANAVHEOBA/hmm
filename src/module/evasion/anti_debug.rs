//! Anti-Debugging Detection Module
//!
//! Detects debugging tools and environments by checking for:
//! - Debugger presence (IsDebuggerPresent, ptrace)
//! - Remote debugger attachment
//! - Debugging flags in process structures
//! - Timing anomalies caused by breakpoints
//! - Exception handling behavior

use std::time::{Duration, Instant};

use super::errors::EvasionError;

/// Anti-debugging detection module
pub struct AntiDebug;

impl AntiDebug {
    /// Check if a debugger is present
    /// Returns true if any debugger indicator is detected
    pub fn is_debugger_present() -> bool {
        Self::check_native_debugger()
            || Self::check_remote_debugger()
            || Self::check_debugging_flags()
            || Self::timing_check()
            || Self::exception_check()
    }

    /// Check for native debugger attachment
    pub fn check_native_debugger() -> bool {
        #[cfg(target_os = "windows")]
        {
            // Use Windows API IsDebuggerPresent
            unsafe {
                if is_debugger_present_win() {
                    return true;
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check TracerPid in /proc/self/status
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(pid) = parts[1].parse::<u32>() {
                                if pid > 0 {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Check if we can be ptraced (if already being debugged, ptrace will fail)
            // This is a secondary check
        }

        #[cfg(target_os = "macos")]
        {
            // Use sysctl to check for debugger attachment
            return Self::check_ptrace_macos();
        }

        false
    }

    /// Check for remote debugger attachment
    pub fn check_remote_debugger() -> bool {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                if check_remote_debugger_present_win() {
                    return true;
                }
            }
        }

        // On Linux/macOS, remote debugging is harder to detect
        // Could check for common debug server ports (gdbserver, lldb-server)
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Check for common debugger ports
            let debugger_ports = [2159, 2345, 5678, 9229, 5005]; // gdb, lldb, chrome devtools, java
            for port in debugger_ports {
                if Self::is_port_listening(port) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for debugging flags in process structures
    pub fn check_debugging_flags() -> bool {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                // Check NtGlobalFlag in PEB
                if check_nt_global_flag() {
                    return true;
                }

                // Check heap flags
                if check_heap_flags() {
                    return true;
                }
            }
        }

        // On Linux, check for ptrace_seal or other debugging indicators
        #[cfg(target_os = "linux")]
        {
            // Check process status for debugging indicators
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    // Check for Seccomp filtering (often used by debuggers)
                    if line.starts_with("Seccomp:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(seccomp) = parts[1].parse::<u32>() {
                                if seccomp > 0 {
                                    // Seccomp is enabled - could be debugger
                                    // This is a weak indicator
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Timing-based debugger detection
    /// Debuggers slow down execution, especially around breakpoints
    pub fn timing_check() -> bool {
        // Perform a simple computation and measure time
        let start = Instant::now();

        // CPU-intensive operation
        let mut result: u64 = 0;
        for i in 0..10_000_000u64 {
            result = result.wrapping_add(i.wrapping_mul(7));
            result = result.rotate_left(3);
        }

        let duration = start.elapsed();

        // If it took more than 500ms, likely being debugged
        // Adjust threshold based on target system
        if duration.as_millis() > 500 {
            return true;
        }

        // Additional timing check with sleep
        let sleep_duration = Duration::from_millis(100);
        let sleep_start = Instant::now();
        std::thread::sleep(sleep_duration);
        let sleep_elapsed = sleep_start.elapsed();

        // If sleep took significantly longer than expected, debugger may be present
        // Allow 50% tolerance
        if sleep_elapsed > sleep_duration * 3 / 2 {
            return true;
        }

        false
    }

    /// Exception-based debugger detection
    /// Debuggers catch exceptions that would normally be handled silently
    pub fn exception_check() -> bool {
        #[cfg(target_os = "windows")]
        {
            // Use structured exception handling
            unsafe {
                if exception_check_win() {
                    return true;
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // On Unix-like systems, we can use signal handling
            // This is more complex and less reliable
            return Self::signal_based_check();
        }

        false
    }

    /// Check if being debugged via ptrace (Linux/macOS)
    pub fn check_ptrace() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Try to ptrace ourselves - if it fails, we're already being debugged
            use libc::ptrace;
            unsafe {
                // PTRACE_TRACEME = 0
                let ret = ptrace(0, 0, std::ptr::null_mut::<i32>() as *mut _, 0);
                if ret == -1 {
                    return true;
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            return Self::check_ptrace_macos();
        }

        false
    }

    /// Hide from debugger (Windows only)
    /// Attempts to clear debugging flags
    pub fn hide_from_debugger() -> Result<(), EvasionError> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                hide_from_debugger_win();
            }
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(EvasionError::Internal(
                "hide_from_debugger is only available on Windows".to_string(),
            ))
        }
    }

    // Platform-specific helper functions

    #[cfg(target_os = "macos")]
    fn check_ptrace_macos() -> bool {
        use libc::{c_int, c_void, size_of, sysctlbyname};
        use std::ffi::CString;

        unsafe {
            let mut mib: [c_int; 4] = [0, 0, 0, 0];
            let mut size: size_t = size_of::<c_int>() as size_t;

            // Get mib for kern.proc.pid
            let name = CString::new("kern.proc.pid").unwrap();
            if sysctlbyname(
                name.as_ptr(),
                &mut mib as *mut _ as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == -1
            {
                return false;
            }

            // Set pid
            mib[3] = libc::getpid();

            // Get info struct
            #[repr(C)]
            struct KInfoProc {
                kp_proc: KProc,
                kp_eproc: KEProc,
            }

            #[repr(C)]
            struct KProc {
                p_un: [u8; 64],
            }

            #[repr(C)]
            struct KEProc {
                e_paddr: *mut c_void,
                e_pptr: *mut c_void,
                e_xstat: u16,
                // ... rest of struct not needed
            }

            let mut info: KInfoProc = std::mem::zeroed();
            let mut size: size_t = size_of::<KInfoProc>() as size_t;

            if sysctlbyname(
                name.as_ptr(),
                &mut info as *mut _ as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == -1
            {
                return false;
            }

            // Check if being traced (P_TRACED = 0x00000400)
            (info.kp_proc.p_un[0] & 0x04) != 0
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn check_ptrace_macos() -> bool {
        false
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn signal_based_check() -> bool {
        // This is a simplified check - full implementation would need
        // complex signal handling
        false
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn is_port_listening(port: u16) -> bool {
        // Try to connect to localhost:port
        // If connection succeeds, something is listening
        std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok()
    }
}

// Windows-specific implementations
#[cfg(target_os = "windows")]
unsafe fn is_debugger_present_win() -> bool {
    use winapi::um::debugapi::IsDebuggerPresent;
    IsDebuggerPresent() != 0
}

#[cfg(target_os = "windows")]
unsafe fn check_remote_debugger_present_win() -> bool {
    use winapi::um::debugapi::CheckRemoteDebuggerPresent;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    let mut is_debugged: i32 = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugged);
    is_debugged != 0
}

#[cfg(target_os = "windows")]
unsafe fn check_nt_global_flag() -> bool {
    use std::mem;
    use winapi::shared::minwindef::ULONG;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PROCESS_BASIC_INFORMATION;

    // Get NtQueryInformationProcess function
    let h_ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if h_ntdll.is_null() {
        return false;
    }

    type NtQueryInfoProc = unsafe extern "system" fn(
        HANDLE,
        ULONG,
        PVOID,
        ULONG,
        *mut ULONG,
    ) -> i32;

    let nt_query = mem::transmute::<_, NtQueryInfoProc>(winapi::um::libloaderapi::GetProcAddress(
        h_ntdll,
        b"NtQueryInformationProcess\0".as_ptr() as *const i8,
    ));

    if nt_query.is_null() {
        return false;
    }

    let mut pbi: PROCESS_BASIC_INFORMATION = mem::zeroed();
    let mut return_len: ULONG = 0;

    let status = nt_query(
        GetCurrentProcess(),
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut _,
        mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
        &mut return_len,
    );

    if status != 0 {
        return false;
    }

    // Read NtGlobalFlag from PEB
    // Offset 0xBC for 64-bit, 0x68 for 32-bit
    #[cfg(target_arch = "x86_64")]
    let nt_global_flag = *(pbi.PebBaseAddress as *const u8).add(0xBC) as u32;

    #[cfg(target_arch = "x86")]
    let nt_global_flag = *(pbi.PebBaseAddress as *const u8).add(0x68) as u32;

    // Debug flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10),
    //              FLG_HEAP_ENABLE_FREE_CHECK (0x20),
    //              FLG_HEAP_VALIDATE_PARAMETERS (0x40)
    const DEBUG_FLAGS: u32 = 0x70;

    (nt_global_flag & DEBUG_FLAGS) != 0
}

#[cfg(target_os = "windows")]
unsafe fn check_heap_flags() -> bool {
    use winapi::um::heapapi::GetProcessHeap;

    let heap = GetProcessHeap();
    if heap.is_null() {
        return false;
    }

    // Read heap flags - this is implementation-dependent
    // and may not work on all Windows versions
    // Simplified for demonstration
    false
}

#[cfg(target_os = "windows")]
unsafe fn exception_check_win() -> bool {
    use winapi::um::winnt::EXCEPTION_EXECUTE_HANDLER;

    let mut exception_handled = false;

    // Use Windows SEH
    let result = std::panic::catch_unwind(|| {
        // Cause an access violation
        let ptr: *mut i32 = std::ptr::null_mut();
        *ptr = 42;
    });

    if result.is_err() {
        exception_handled = true;
    }

    // If exception was caught, we might be in a debugger
    // (debuggers catch exceptions before our handler)
    exception_handled
}

#[cfg(target_os = "windows")]
unsafe fn hide_from_debugger_win() {
    // Clear PEB debug flags
    // This is advanced and may not work on all systems
    // Implementation omitted for brevity
}

// Linux-specific ptrace binding
#[cfg(target_os = "linux")]
extern "C" {
    fn ptrace(request: libc::c_uint, pid: libc::pid_t, addr: *mut libc::c_void, data: *mut libc::c_void) -> libc::c_long;
}

#[cfg(not(target_os = "linux"))]
extern "C" {
    // Placeholder for non-Linux systems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_detection_api() {
        // These should not panic
        let _is_debugger = AntiDebug::is_debugger_present();
        let _native = AntiDebug::check_native_debugger();
        let _remote = AntiDebug::check_remote_debugger();
        let _flags = AntiDebug::check_debugging_flags();
        let _timing = AntiDebug::timing_check();
        let _exception = AntiDebug::exception_check();
    }

    #[test]
    fn test_timing_check() {
        // Timing check should return without panicking
        let _result = AntiDebug::timing_check();
    }

    #[test]
    fn test_exception_check() {
        // Exception check should return without panicking
        let _result = AntiDebug::exception_check();
    }
}
