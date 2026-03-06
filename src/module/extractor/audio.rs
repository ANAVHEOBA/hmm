//! Audio Recording Module
//!
//! Provides audio capture functionality:
//! - List available audio devices
//! - Record audio to file or memory
//! - Configurable sample rate and channels
//! - Multiple output formats (WAV, FLAC, etc.)
//!
//! Platform support:
//! - Windows: WASAPI / DirectSound
//! - Linux: ALSA / PulseAudio
//! - macOS: Core Audio
//!
//! Note: Full implementation requires platform-specific dependencies.
//! This module provides the API structure with basic implementations.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::module::evasion::errors::EvasionError;

/// Audio device information
#[derive(Debug, Clone)]
pub struct AudioDevice {
    /// Device name
    pub name: String,
    /// Device index
    pub index: u32,
    /// Whether this is an input device (microphone)
    pub is_input: bool,
    /// Whether device is available
    pub available: bool,
    /// Supported sample rates
    pub sample_rates: Vec<u32>,
    /// Supported channel counts
    pub channels: Vec<u8>,
}

/// Audio format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    Wav,
    Flac,
    Mp3,
    RawPcm,
    RawF32,
}

impl AudioFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            AudioFormat::Wav => "wav",
            AudioFormat::Flac => "flac",
            AudioFormat::Mp3 => "mp3",
            AudioFormat::RawPcm => "raw",
            AudioFormat::RawF32 => "raw",
        }
    }
}

/// Audio recording configuration
#[derive(Debug, Clone)]
pub struct AudioConfig {
    /// Device index (0 = default)
    pub device_index: u32,
    /// Sample rate in Hz (e.g., 44100, 48000)
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo)
    pub channels: u8,
    /// Bits per sample (16, 24, 32)
    pub bits_per_sample: u8,
    /// Output format
    pub format: AudioFormat,
    /// Recording duration (None = until stopped)
    pub duration: Option<Duration>,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            device_index: 0,
            sample_rate: 44100,
            channels: 1,
            bits_per_sample: 16,
            format: AudioFormat::Wav,
            duration: None,
        }
    }
}

/// Recorded audio data
#[derive(Debug, Clone)]
pub struct AudioRecording {
    /// Raw audio data
    pub data: Vec<u8>,
    /// Sample rate
    pub sample_rate: u32,
    /// Number of channels
    pub channels: u8,
    /// Bits per sample
    pub bits_per_sample: u8,
    /// Format of the audio
    pub format: AudioFormat,
    /// Duration in seconds
    pub duration_secs: f32,
    /// Timestamp when recording started
    pub timestamp: u64,
    /// Device index used
    pub device_index: u32,
}

impl AudioRecording {
    /// Save recording to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, EvasionError> {
        let mut file = fs::File::create(&path).map_err(|e| {
            EvasionError::FileSystem(format!("Failed to create file: {}", e))
        })?;

        file.write_all(&self.data).map_err(|e| {
            EvasionError::FileSystem(format!("Failed to write file: {}", e))
        })?;

        Ok(path.as_ref().to_path_buf())
    }

    /// Get the file extension for this recording's format
    pub fn extension(&self) -> &'static str {
        self.format.extension()
    }

    /// Get file size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Audio recording state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    Stopped,
    Recording,
    Paused,
}

/// Audio recording module
pub struct AudioRecorder {
    config: AudioConfig,
    state: RecordingState,
    current_recording: Option<AudioRecording>,
}

impl AudioRecorder {
    /// Create a new audio recorder with default config
    pub fn new() -> Self {
        Self::with_config(AudioConfig::default())
    }

    /// Create a new audio recorder with custom config
    pub fn with_config(config: AudioConfig) -> Self {
        Self {
            config,
            state: RecordingState::Stopped,
            current_recording: None,
        }
    }

    /// List available audio devices
    pub fn list_devices() -> Vec<AudioDevice> {
        #[cfg(target_os = "windows")]
        {
            Self::list_devices_windows()
        }

        #[cfg(target_os = "linux")]
        {
            Self::list_devices_linux()
        }

        #[cfg(target_os = "macos")]
        {
            Self::list_devices_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Vec::new()
        }
    }

    /// Start recording audio
    pub fn start(&mut self) -> Result<(), EvasionError> {
        if self.state == RecordingState::Recording {
            return Err(EvasionError::Internal("Already recording".to_string()));
        }

        #[cfg(target_os = "windows")]
        {
            self.start_windows()
        }

        #[cfg(target_os = "linux")]
        {
            self.start_linux()
        }

        #[cfg(target_os = "macos")]
        {
            self.start_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(EvasionError::SystemInfo(
                "Audio recording not supported on this platform".to_string(),
            ))
        }
    }

    /// Stop recording and return the result
    pub fn stop(&mut self) -> Result<Option<AudioRecording>, EvasionError> {
        if self.state != RecordingState::Recording {
            return Ok(None);
        }

        self.state = RecordingState::Stopped;

        #[cfg(target_os = "windows")]
        {
            self.stop_windows()
        }

        #[cfg(target_os = "linux")]
        {
            self.stop_linux()
        }

        #[cfg(target_os = "macos")]
        {
            self.stop_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Ok(self.current_recording.take())
        }
    }

    /// Pause recording (if supported)
    pub fn pause(&mut self) -> Result<(), EvasionError> {
        if self.state != RecordingState::Recording {
            return Err(EvasionError::Internal("Not recording".to_string()));
        }

        self.state = RecordingState::Paused;
        Ok(())
    }

    /// Resume recording after pause
    pub fn resume(&mut self) -> Result<(), EvasionError> {
        if self.state != RecordingState::Paused {
            return Err(EvasionError::Internal("Not paused".to_string()));
        }

        self.state = RecordingState::Recording;
        Ok(())
    }

    /// Get current recording state
    pub fn state(&self) -> RecordingState {
        self.state
    }

    /// Check if currently recording
    pub fn is_recording(&self) -> bool {
        self.state == RecordingState::Recording
    }

    /// Record for a specific duration
    pub fn record_duration(
        &mut self,
        duration: Duration,
    ) -> Result<AudioRecording, EvasionError> {
        self.config.duration = Some(duration);
        self.start()?;
        std::thread::sleep(duration);
        self.stop()?;

        self.current_recording
            .take()
            .ok_or_else(|| EvasionError::Internal("Recording failed".to_string()))
    }

    // Platform-specific implementations

    #[cfg(target_os = "windows")]
    fn list_devices_windows() -> Vec<AudioDevice> {
        // Windows: Would use WASAPI to enumerate devices
        vec![AudioDevice {
            name: "Default Microphone".to_string(),
            index: 0,
            is_input: true,
            available: true,
            sample_rates: vec![44100, 48000],
            channels: vec![1, 2],
        }]
    }

    #[cfg(target_os = "windows")]
    fn start_windows(&mut self) -> Result<(), EvasionError> {
        // Windows: Would use WASAPI CaptureClient
        self.state = RecordingState::Recording;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn stop_windows(&mut self) -> Result<Option<AudioRecording>, EvasionError> {
        Ok(self.current_recording.take())
    }

    #[cfg(target_os = "linux")]
    fn list_devices_linux() -> Vec<AudioDevice> {
        use std::process::Command;

        let mut devices = Vec::new();

        // Try pactl (PulseAudio)
        if let Ok(output) = Command::new("pactl")
            .args(["list", "sources", "short"])
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for (index, line) in output_str.lines().enumerate() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        devices.push(AudioDevice {
                            name: parts[1].to_string(),
                            index: index as u32,
                            is_input: true,
                            available: true,
                            sample_rates: vec![44100, 48000],
                            channels: vec![1, 2],
                        });
                    }
                }
            }
        }

        // Try arecord (ALSA)
        if devices.is_empty() {
            if let Ok(output) = Command::new("arecord")
                .args(["-l"])
                .output()
            {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    for line in output_str.lines() {
                        if line.starts_with("card") {
                            devices.push(AudioDevice {
                                name: line.to_string(),
                                index: devices.len() as u32,
                                is_input: true,
                                available: true,
                                sample_rates: vec![44100, 48000],
                                channels: vec![1, 2],
                            });
                        }
                    }
                }
            }
        }

        devices
    }

    #[cfg(target_os = "linux")]
    fn start_linux(&mut self) -> Result<(), EvasionError> {
        use std::process::Command;

        // Use arecord to capture audio
        let temp_path = format!(
            "/tmp/hmm_audio_{}.wav",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        );

        let mut cmd = Command::new("arecord");
        cmd.args([
            "-f", "cd",  // CD quality (16-bit, 44.1kHz, stereo)
            "-r", &self.config.sample_rate.to_string(),
            "-c", &self.config.channels.to_string(),
            "-D", &format!("hw:0,{}", self.config.device_index),
            &temp_path,
        ]);

        if let Some(duration) = self.config.duration {
            cmd.arg("-d").arg(&duration.as_secs().to_string());
        }

        // Start recording in background
        let _child = cmd.spawn().map_err(|e| {
            EvasionError::SystemInfo(format!("Failed to start arecord: {}", e))
        })?;

        self.state = RecordingState::Recording;

        // Store temp path for later
        // In a real implementation, we'd track the child process

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn stop_linux(&mut self) -> Result<Option<AudioRecording>, EvasionError> {
        // In a real implementation, we'd stop the recording process
        // and read the recorded data

        Ok(self.current_recording.take())
    }

    #[cfg(target_os = "macos")]
    fn list_devices_macos() -> Vec<AudioDevice> {
        // macOS: Would use Core Audio to enumerate devices
        vec![AudioDevice {
            name: "Built-in Microphone".to_string(),
            index: 0,
            is_input: true,
            available: true,
            sample_rates: vec![44100, 48000],
            channels: vec![1, 2],
        }]
    }

    #[cfg(target_os = "macos")]
    fn start_macos(&mut self) -> Result<(), EvasionError> {
        // macOS: Would use Core Audio AudioQueue
        self.state = RecordingState::Recording;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn stop_macos(&mut self) -> Result<Option<AudioRecording>, EvasionError> {
        Ok(self.current_recording.take())
    }
}

impl Default for AudioRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for quick recording
pub fn record_audio<P: AsRef<Path>>(
    duration: Duration,
    path: P,
) -> Result<PathBuf, EvasionError> {
    let mut recorder = AudioRecorder::new();
    let recording = recorder.record_duration(duration)?;
    recording.save(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_recorder_creation() {
        let _recorder = AudioRecorder::new();
        let _recorder_config = AudioRecorder::with_config(AudioConfig {
            device_index: 1,
            sample_rate: 48000,
            channels: 2,
            bits_per_sample: 24,
            format: AudioFormat::Flac,
            duration: Some(Duration::from_secs(30)),
        });
    }

    #[test]
    fn test_default_config() {
        let config = AudioConfig::default();
        assert_eq!(config.device_index, 0);
        assert_eq!(config.sample_rate, 44100);
        assert_eq!(config.channels, 1);
        assert_eq!(config.bits_per_sample, 16);
        assert_eq!(config.format, AudioFormat::Wav);
        assert!(config.duration.is_none());
    }

    #[test]
    fn test_audio_format_extension() {
        assert_eq!(AudioFormat::Wav.extension(), "wav");
        assert_eq!(AudioFormat::Flac.extension(), "flac");
        assert_eq!(AudioFormat::Mp3.extension(), "mp3");
        assert_eq!(AudioFormat::RawPcm.extension(), "raw");
    }

    #[test]
    fn test_audio_device() {
        let device = AudioDevice {
            name: "Test Mic".to_string(),
            index: 0,
            is_input: true,
            available: true,
            sample_rates: vec![44100, 48000],
            channels: vec![1, 2],
        };

        assert_eq!(device.name, "Test Mic");
        assert!(device.is_input);
        assert!(device.available);
        assert_eq!(device.sample_rates.len(), 2);
    }

    #[test]
    fn test_list_devices() {
        // This may return empty on headless systems
        let devices = AudioRecorder::list_devices();
        // Just verify it doesn't panic
        let _ = devices;
    }

    #[test]
    fn test_recorder_state() {
        let mut recorder = AudioRecorder::new();

        assert_eq!(recorder.state(), RecordingState::Stopped);
        assert!(!recorder.is_recording());

        // Start may fail on headless systems
        let _ = recorder.start();

        // Stop
        let _ = recorder.stop();
    }

    #[test]
    fn test_audio_recording() {
        let recording = AudioRecording {
            data: vec![0x52, 0x49, 0x46, 0x46], // WAV header start
            sample_rate: 44100,
            channels: 1,
            bits_per_sample: 16,
            format: AudioFormat::Wav,
            duration_secs: 5.0,
            timestamp: 0,
            device_index: 0,
        };

        assert_eq!(recording.sample_rate, 44100);
        assert_eq!(recording.channels, 1);
        assert_eq!(recording.format, AudioFormat::Wav);
        assert_eq!(recording.extension(), "wav");
        assert_eq!(recording.size(), 4);
    }

    #[test]
    fn test_recording_save() {
        let recording = AudioRecording {
            data: vec![0x52, 0x49, 0x46, 0x46, 0x00],
            sample_rate: 44100,
            channels: 1,
            bits_per_sample: 16,
            format: AudioFormat::Wav,
            duration_secs: 1.0,
            timestamp: 0,
            device_index: 0,
        };

        let temp_path = std::env::temp_dir().join("test_audio.wav");
        let result = recording.save(&temp_path);

        assert!(result.is_ok());
        assert!(temp_path.exists());

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_convenience_function() {
        let temp_path = std::env::temp_dir().join("test_record.wav");
        let result = record_audio(Duration::from_secs(1), &temp_path);

        // May fail on headless systems
        let _ = result;

        // Cleanup if created
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_pause_resume() {
        let mut recorder = AudioRecorder::new();

        // Should fail when not recording
        assert!(recorder.pause().is_err());
        assert!(recorder.resume().is_err());
    }
}
