//! SOCKS5 listener with per-identity sticky routing + auto-rotation.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::backend::BackendRouter;

pub async fn run_listener(
    addr: std::net::SocketAddr,
    router: Arc<BackendRouter>,
    port_id: usize,
    rotate_every_reqs: u64,
    rotate_mins: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("SOCKS5 listener #{} on {}", port_id, addr);

    let mut req_count: u64 = 0;
    let mut last_rotate = Instant::now();

    loop {
        let (client, client_addr) = listener.accept().await?;
        let router = router.clone();
        req_count += 1;

        // rotation triggers (per this identity/port)
        let should_rotate_reqs = rotate_every_reqs > 0 && req_count % rotate_every_reqs == 0;
        let should_rotate_time = rotate_mins > 0
            && last_rotate.elapsed() >= Duration::from_secs(rotate_mins * 60);

        if should_rotate_reqs || should_rotate_time {
            info!("[id:{}] rotating upstream (reqs={}, elapsed={:?})", port_id, req_count, last_rotate.elapsed());
            let r = router.clone();
            tokio::spawn(async move { r.rotate_all().await; });
            last_rotate = Instant::now();
        }

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, router).await {
                debug!("SOCKS5 conn from {} closed: {}", client_addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    router: Arc<BackendRouter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. negotiation
    let mut buf = [0u8; 256];
    client.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err("unsupported SOCKS version".into());
    }
    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods]).await?;
    // prefer no-auth
    let methods = &buf[..nmethods];
    if methods.contains(&0x00) {
        client.write_all(&[0x05, 0x00]).await?;
    } else {
        client.write_all(&[0x05, 0xFF]).await?;
        return Err("no acceptable auth".into());
    }

    // 2. request
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    let cmd = req[1];
    let atyp = req[3];
    if cmd != 0x01 {
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
        return Err("only CONNECT supported".into());
    }

    let target_host = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let l = client.read_u8().await? as usize;
            let mut d = vec![0u8; l];
            client.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            return Err("unsupported address type".into());
        }
    };
    let port = client.read_u16().await?;
    let target = format!("{}:{}", target_host, port);

    // 3. pick backend and connect upstream
    let backend = router.pick().clone();
    let mut upstream = match connect_upstream(&target, &backend).await {
        Ok(s) => s,
        Err(e) => {
            warn!("connect failed via {}: {}", backend.name(), e);
            client.write_all(&[0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            return Err(e.into());
        }
    };

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;

    // 4. bidirectional copy
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn connect_upstream(
    target: &str,
    backend: &crate::backend::Backend,
) -> Result<TcpStream, String> {
    match backend.upstream_socks() {
        Some(socks) => {
            // connect to Tor SOCKS5, then handshake CONNECT to target
            let mut s = TcpStream::connect(&socks).await.map_err(|e| e.to_string())?;
            s.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            if b != [0x05, 0x00] {
                return Err("tor no-auth rejected".into());
            }
            // build CONNECT request
            let (host, port) = split_host_port(target)?;
            let mut req = vec![0x05, 0x01, 0x00];
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                req.push(0x01);
                req.extend_from_slice(&ip.octets());
            } else {
                let d = host.as_bytes();
                req.push(0x03);
                req.push(d.len() as u8);
                req.extend_from_slice(d);
            }
            req.extend_from_slice(&port.to_be_bytes());
            s.write_all(&req).await.map_err(|e| e.to_string())?;
            let mut resp = [0u8; 4];
            s.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
            if resp[1] != 0x00 {
                return Err(format!("tor connect failed code {}", resp[1]));
            }
            // drain address
            let atyp = resp[3];
            match atyp {
                0x01 => { let mut x = [0u8;4]; s.read_exact(&mut x).await.map_err(|e| e.to_string())?; }
                0x03 => { let l = s.read_u8().await.map_err(|e| e.to_string())? as usize; let mut x=vec![0u8;l]; s.read_exact(&mut x).await.map_err(|e| e.to_string())?; }
                0x04 => { let mut x=[0u8;16]; s.read_exact(&mut x).await.map_err(|e| e.to_string())?; }
                _ => {}
            }
            let mut pb = [0u8;2];
            s.read_exact(&mut pb).await.map_err(|e| e.to_string())?;
            Ok(s)
        }
        None => {
            // Warp / direct: just connect directly (system tunnel routes it)
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target)
                .await
                .map_err(|e| e.to_string())?
                .collect();
            let a = addrs.first().ok_or("no addr")?;
            TcpStream::connect(a).await.map_err(|e| e.to_string())
        }
    }
}

fn split_host_port(target: &str) -> Result<(String, u16), String> {
    // handle IPv6 [::1]:80 vs host:80
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest.find(']').ok_or("bad ipv6")?;
        let host = &rest[..end];
        let port: u16 = rest[end + 1..].strip_prefix(':').ok_or("bad port")?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok((host.to_string(), port))
    } else {
        let (host, port) = target.rsplit_once(':').ok_or("bad host:port")?;
        let port: u16 = port.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok((host.to_string(), port))
    }
}
