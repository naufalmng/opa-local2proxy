//! Backend abstraction: Tor and Warp upstreams with rotation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::config::Config;

/// A backend is an upstream SOCKS5 (Tor) or a process-controlled tunnel (Warp).
/// It exposes: current exit IP, and a rotate() method that swaps the exit.
#[derive(Clone)]
pub enum Backend {
    Tor(TorBackend),
    Warp(WarpBackend),
}

#[derive(Clone)]
pub struct TorBackend {
    pub socks_addr: String,
    pub control_addr: String,
    pub control_password: String,
}

#[derive(Clone)]
pub struct WarpBackend {
    pub binary: String,
    pub socks_addr: String,
    pub current_ip: Arc<Mutex<Option<String>>>,
}

impl Backend {
    pub fn name(&self) -> &str {
        match self {
            Backend::Tor(_) => "tor",
            Backend::Warp(_) => "warp",
        }
    }

    /// The upstream SOCKS5 address to connect through. Both Tor and Warp expose
    /// a SOCKS5 endpoint (Tor's own daemon, Warp's proxy mode).
    pub fn upstream_socks(&self) -> Option<String> {
        match self {
            Backend::Tor(t) => Some(t.socks_addr.clone()),
            Backend::Warp(w) => Some(w.socks_addr.clone()),
        }
    }

    /// Rotate this backend's exit IP.
    pub async fn rotate(&self) -> Result<(), String> {
        match self {
            Backend::Tor(t) => t.rotate().await,
            Backend::Warp(w) => w.rotate().await,
        }
    }

    /// Current exit IP (best-effort; may be None if unknown).
    pub async fn current_ip(&self) -> Option<String> {
        match self {
            Backend::Tor(t) => t.current_ip().await,
            Backend::Warp(w) => w.current_ip().await,
        }
    }
}

impl TorBackend {
    /// Send NEWNYM to the Tor control port to force a fresh circuit (new exit IP).
    async fn rotate(&self) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(&self.control_addr)
            .await
            .map_err(|e| format!("tor control connect failed: {}", e))?;

        // Authenticate
        if !self.control_password.is_empty() {
            let cmd = format!("AUTHENTICATE \"{}\"\r\n", self.control_password);
            stream.write_all(cmd.as_bytes()).await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 128];
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if !resp.starts_with("250") {
                return Err(format!("tor auth failed: {}", resp));
            }
        } else {
            // Cookie auth unsupported in this minimal path; assume no-auth control
            let _ = &self;
        }

        // Request new identity
        stream.write_all(b"SIGNAL NEWNYM\r\n").await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        stream.write_all(b"QUIT\r\n").await.ok();

        if resp.starts_with("250") {
            info!("[tor] NEWNYM issued — new circuit");
            Ok(())
        } else {
            Err(format!("tor NEWNYM failed: {}", resp))
        }
    }

    async fn current_ip(&self) -> Option<String> {
        // Query via the SOCKS proxy itself (connect to an echo service)
        fetch_ip_via_socks(&self.socks_addr).await
    }
}

impl WarpBackend {
    /// Rotate Warp by reconnecting the tunnel (warp-cli disconnect/connect).
    async fn rotate(&self) -> Result<(), String> {
        use std::process::Command;

        info!("[warp] rotating tunnel (disconnect -> connect)");
        let out = Command::new(&self.binary).args(["disconnect"]).output();
        if let Err(e) = out {
            return Err(format!("warp disconnect failed: {}", e));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let out = Command::new(&self.binary).args(["connect"]).output();
        if let Err(e) = out {
            return Err(format!("warp connect failed: {}", e));
        }
        // Clear cached IP
        *self.current_ip.lock().await = None;
        Ok(())
    }

    async fn current_ip(&self) -> Option<String> {
        let cached = self.current_ip.lock().await.clone();
        if cached.is_some() {
            return cached;
        }
        let ip = fetch_ip_direct().await;
        if let Some(ref ip) = ip {
            *self.current_ip.lock().await = Some(ip.clone());
        }
        ip
    }
}

/// Build the backend pool based on config.
pub async fn build_backends(cfg: &Config) -> Result<Vec<Backend>, Box<dyn std::error::Error + Send + Sync>> {
    let mut v = Vec::new();
    if cfg.backends.contains("tor") || cfg.backends == "both" {
        v.push(Backend::Tor(TorBackend {
            socks_addr: cfg.tor_socks.clone(),
            control_addr: cfg.tor_control.clone(),
            control_password: cfg.tor_control_password.clone(),
        }));
    }
    if cfg.backends.contains("warp") || cfg.backends == "both" {
        v.push(Backend::Warp(WarpBackend {
            binary: cfg.warp_binary.clone(),
            socks_addr: cfg.warp_socks.clone(),
            current_ip: Arc::new(Mutex::new(None)),
        }));
    }
    if v.is_empty() {
        return Err("no backends configured".into());
    }
    Ok(v)
}

/// Round-robin / sticky router across backends.
pub struct BackendRouter {
    backends: Vec<Backend>,
    next: AtomicU64,
}

impl BackendRouter {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self {
            backends,
            next: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Pick the next backend round-robin.
    pub fn pick(&self) -> &Backend {
        let i = self.next.fetch_add(1, Ordering::Relaxed) as usize % self.backends.len();
        &self.backends[i]
    }

    /// Rotate ALL backends (full IP refresh).
    pub async fn rotate_all(&self) {
        for b in &self.backends {
            if let Err(e) = b.rotate().await {
                warn!("rotate {} failed: {}", b.name(), e);
            }
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────

#[allow(dead_code)]
async fn fetch_ip_direct() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = client.get("http://lumtest.com/myip.json").send().await.ok()?;
    let body = resp.text().await.ok()?;
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()?
        .get("ip")?
        .as_str()
        .map(|s| s.to_string())
}

#[allow(dead_code)]
async fn fetch_ip_via_socks(socks_addr: &str) -> Option<String> {
    // Minimal SOCKS5 handshake then fetch ip over the circuit.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut s = TcpStream::connect(socks_addr).await.ok()?;
    // greeting: v5, 1 method, no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.ok()?;
    if b != [0x05, 0x00] {
        return None;
    }
    // connect to lumtest.com:80 (domain)
    let domain = b"lumtest.com";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.ok()?;
    let mut resp = [0u8; 4];
    s.read_exact(&mut resp).await.ok()?;
    if resp[1] != 0x00 {
        return None;
    }
    // read remaining addr bytes based on type
    let atyp = resp[3];
    match atyp {
        0x01 => { let mut x = [0u8; 4]; s.read_exact(&mut x).await.ok()?; }
        0x03 => { let l = s.read_u8().await.ok()? as usize; let mut x = vec![0u8; l]; s.read_exact(&mut x).await.ok()?; }
        0x04 => { let mut x = [0u8; 16]; s.read_exact(&mut x).await.ok()?; }
        _ => return None,
    }
    let mut portb = [0u8; 2];
    s.read_exact(&mut portb).await.ok()?;

    // HTTP GET
    let req_str = "GET /myip.json HTTP/1.1\r\nHost: lumtest.com\r\nConnection: close\r\n\r\n";
    s.write_all(req_str.as_bytes()).await.ok()?;
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let body = String::from_utf8_lossy(&all).to_string();
    let json_start = body.find('{')?;
    serde_json::from_str::<serde_json::Value>(&body[json_start..])
        .ok()?
        .get("ip")?
        .as_str()
        .map(|s| s.to_string())
}
