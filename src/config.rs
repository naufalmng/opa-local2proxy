//! Configuration loading (env + defaults). No external config file required.

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    /// SOCKS5 listener addresses (one per sticky identity). Comma-separated.
    pub identities: Vec<String>,
    /// REST API control address.
    pub api_addr: String,
    /// Backend pool: "tor", "warp", or "both".
    pub backends: String,
    /// Tor SOCKS5 control address (upstream).
    pub tor_socks: String,
    /// Tor control port (for NEWNYM / circuit rotation).
    pub tor_control: String,
    /// Tor control password (optional; HashedControlPassword or CookieAuth).
    pub tor_control_password: String,
    /// Warp CLI path (warp-cli) — used to rotate (disconnect/connect).
    pub warp_binary: String,
    /// Warp SOCKS5 proxy address (proxy mode). Default 127.0.0.1:40000.
    pub warp_socks: String,
    /// HTTP proxy listener addresses (comma-separated). Empty = disabled.
    pub http_identities: Vec<String>,
    /// Rotate every N requests per identity (0 = disabled).
    pub rotate_every_reqs: u64,
    /// Rotate every N minutes per identity (0 = disabled).
    pub rotate_mins: u64,
}

impl Config {
    pub fn load() -> Self {
        let identities = env::var("RP_IDENTITIES")
            .unwrap_or_else(|_| "127.0.0.1:10800,127.0.0.1:10801,127.0.0.1:10802".to_string());
        Config {
            identities: identities
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            api_addr: env::var("RP_API").unwrap_or_else(|_| "127.0.0.1:10808".to_string()),
            backends: env::var("RP_BACKENDS").unwrap_or_else(|_| "both".to_string()),
            tor_socks: env::var("RP_TOR_SOCKS").unwrap_or_else(|_| "127.0.0.1:9050".to_string()),
            tor_control: env::var("RP_TOR_CONTROL").unwrap_or_else(|_| "127.0.0.1:9051".to_string()),
            tor_control_password: env::var("RP_TOR_CONTROL_PASSWORD").unwrap_or_default(),
            warp_binary: env::var("RP_WARP_BINARY").unwrap_or_else(|_| {
                if cfg!(target_os = "windows") {
                    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe".to_string()
                } else {
                    "warp-cli".to_string()
                }
            }),
            warp_socks: env::var("RP_WARP_SOCKS").unwrap_or_else(|_| "127.0.0.1:40000".to_string()),
            http_identities: env::var("RP_HTTP_IDENTITIES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            rotate_every_reqs: env::var("RP_ROTATE_EVERY_REQS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            rotate_mins: env::var("RP_ROTATE_MINS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    }
}
