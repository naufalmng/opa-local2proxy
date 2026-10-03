//! HTTP proxy listener (CONNECT tunnel + absolute-URI forwarding).
//! Reuses the same BackendRouter (Tor/Warp upstreams) as the SOCKS5 listener.

use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::backend::BackendRouter;

pub async fn run_http_listener(
    addr: std::net::SocketAddr,
    router: Arc<BackendRouter>,
    port_id: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("HTTP proxy listener #{} on {}", port_id, addr);

    loop {
        let (client, client_addr) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(client, router).await {
                debug!("HTTP conn from {} closed: {}", client_addr, e);
            }
        });
    }
}

async fn handle_http_connection(
    mut client: TcpStream,
    router: Arc<BackendRouter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read the request line + headers (bounded read).
    let mut buf = vec![0u8; 8192];
    let mut read = 0usize;
    loop {
        let n = client.read(&mut buf[read..]).await?;
        if n == 0 {
            return Err("client closed before request".into());
        }
        read += n;
        if read >= 8192 {
            return Err("request too large".into());
        }
        // look for end of headers (\r\n\r\n)
        if read >= 4 && &buf[read - 4..read] == b"\r\n\r\n" {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..read]).to_string();
    let first_line = head.lines().next().unwrap_or("");

    // Determine method / target
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("malformed request line".into());
    }
    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port -> open tunnel
        let backend = router.pick().clone();
        let mut upstream = connect_upstream(target, &backend).await.map_err(|e| {
            warn!("CONNECT {} via {} failed: {}", target, backend.name(), e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    } else {
        // absolute-URI forwarding: GET http://host/path HTTP/1.1
        // parse target into host + port + path, connect, forward modified request
        let (host, port, path) = parse_absolute_uri(target)?;
        let backend = router.pick().clone();
        let mut upstream = connect_upstream(&format!("{}:{}", host, port), &backend)
            .await
            .map_err(|e| {
                warn!("{} {} via {} failed: {}", method, target, backend.name(), e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;

        // rewrite request line to origin-form and strip proxy headers
        let rewritten = rewrite_request(&head, method, &path, &host)?;
        upstream.write_all(rewritten.as_bytes()).await?;
        // drain any remaining body bytes already buffered (rare for GET, but forward anyway)
        if read > head.len() {
            // head.len() includes \r\n\r\n; remaining bytes are body
            let body_start = head.len();
            let body = &buf[body_start..read];
            if !body.is_empty() {
                upstream.write_all(body).await?;
            }
        }
        copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }
}

/// Reuse the backend connect logic (same as SOCKS5 upstream connect).
async fn connect_upstream(
    target: &str,
    backend: &crate::backend::Backend,
) -> Result<TcpStream, String> {
    match backend.upstream_socks() {
        Some(socks) => {
            let mut s = TcpStream::connect(&socks).await.map_err(|e| e.to_string())?;
            s.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            if b != [0x05, 0x00] {
                return Err("upstream no-auth rejected".into());
            }
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
                return Err(format!("upstream connect failed code {}", resp[1]));
            }
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
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target)
                .await
                .map_err(|e| e.to_string())?
                .collect();
            let a = addrs.first().ok_or("no addr")?;
            TcpStream::connect(a).await.map_err(|e| e.to_string())
        }
    }
}

fn parse_absolute_uri(target: &str) -> Result<(String, u16, String), String> {
    // target like http://host:port/path or https://host/path
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .ok_or("unsupported scheme")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port")?),
        None => {
            // default port by scheme
            let is_https = target.starts_with("https://");
            (hostport.to_string(), if is_https { 443 } else { 80 })
        }
    };
    Ok((host, port, path.to_string()))
}

fn rewrite_request(head: &str, method: &str, path: &str, _host: &str) -> Result<String, String> {
    // rebuild request with origin-form path and drop proxy-specific headers
    let mut lines: Vec<String> = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            lines.push(format!("{} {} HTTP/1.1", method, path));
        } else {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("proxy-connection:") || lower.starts_with("connection:") {
                continue;
            }
            lines.push(line.to_string());
        }
    }
    // ensure Host header present
    Ok(lines.join("\r\n") + "\r\n\r\n")
}

fn split_host_port(target: &str) -> Result<(String, u16), String> {
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
