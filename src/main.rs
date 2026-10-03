//! opa-local2proxy — rotating residential proxy (Tor + Warp) with multi-port sticky identities.
//!
//! Architecture:
//!   [client] -> SOCKS5 listener (127.0.0.1:10800..1080N, one per "identity")
//!                -> backend router (round-robin / sticky) -> Tor or Warp upstream
//!   REST API (127.0.0.1:10808) -> /status /ip /rotate
//!
//! Each listener port is a "sticky identity". Rotating that identity swaps the
//! upstream exit IP (Tor NEWNYM circuit, or Warp tunnel restart).

mod backend;
mod config;
mod socks5;
mod api;

use std::sync::Arc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "opa_local2proxy=info".into()),
        )
        .init();

    let cfg = config::Config::load();
    info!("opa-local2proxy starting: {:?}", cfg);

    // Build backends
    let backends = backend::build_backends(&cfg).await?;
    let router = Arc::new(backend::BackendRouter::new(backends));
    let state = api::AppState::new(router.clone(), cfg.clone());

    // Spawn SOCKS5 listeners (one per identity)
    let mut handles = Vec::new();
    for (i, listen) in cfg.identities.iter().enumerate() {
        let router = router.clone();
        let rotate_every_reqs = cfg.rotate_every_reqs;
        let rotate_mins = cfg.rotate_mins;
        let port_id = i;
        let addr: std::net::SocketAddr = listen.parse()?;
        handles.push(tokio::spawn(async move {
            if let Err(e) = socks5::run_listener(addr, router, port_id, rotate_every_reqs, rotate_mins).await {
                error!("SOCKS5 listener {} error: {}", addr, e);
            }
        }));
    }

    // Spawn REST API
    let api_addr = cfg.api_addr.parse()?;
    handles.push(tokio::spawn(async move {
        if let Err(e) = api::run(api_addr, state).await {
            error!("API server error: {}", e);
        }
    }));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
        _ = futures_wait(&mut handles) => {}
    }

    Ok(())
}

// helper to await all handles (so main stays alive)
async fn futures_wait(handles: &mut Vec<tokio::task::JoinHandle<()>>) {
    for h in handles.drain(..) {
        let _ = h.await;
    }
}
