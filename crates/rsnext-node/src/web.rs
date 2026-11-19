//! Loopback HTTP + SSE bridge in front of the node's control plane (M3 WebUI / light terminals).
//!
//! Why a bridge instead of letting the UI talk to the socket: a browser webview (and any remote
//! thin terminal) cannot open a unix socket, and we refuse to make the control socket a TCP
//! listener because it can read messages and pull files. So this layer is explicitly the *only*
//! network-facing door, it binds 127.0.0.1 by default, and every request must carry the token the
//! node wrote next to its data.
//!
//! No new dependencies: a deliberately small HTTP/1.1 reader (GET/POST with Content-Length, no
//! chunked bodies, `Connection: close` on every reply) in front of the existing JSON-RPC methods.
use crate::rpc;
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAGE: &str = include_str!("../web/index.html");
const TOKEN_FILE: &str = "web.token";

pub fn token_path(dir: &str) -> Result<std::path::PathBuf> {
    Ok(crate::dir_paths(dir)?.join(TOKEN_FILE))
}

/// Read or create the bearer token. 0600, because it grants read/write access to the node.
pub fn ensure_token(dir: &str) -> Result<String> {
    let path = token_path(dir)?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let mut raw = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = hex::encode(raw);
    std::fs::write(&path, &token).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

pub async fn serve(dir: String, bind: String) -> Result<()> {
    let token = ensure_token(&dir)?;
    let listener = TcpListener::bind(&bind).await.map_err(|e| anyhow!("bind {bind}: {e}"))?;
    println!("web bridge        = http://{bind}");
    println!("bearer token      = {token}  (also in {})", token_path(&dir)?.display());
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[web] accept: {e}");
                continue;
            }
        };
        let d = dir.clone();
        let t = token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, d, t).await {
                net_vlog(&format!("[web] {peer} {e:#}"));
            }
        });
    }
}

fn net_vlog(msg: &str) {
    if std::env::var("RSNEXT_VERBOSE").map(|s| s != "0").unwrap_or(false) {
        eprintln!("{msg}");
    }
}

async fn handle(mut sock: TcpStream, dir: String, token: String) -> Result<()> {
    // read headers, then exactly Content-Length bytes of body
    let mut buf = vec![0u8; 8192];
    let mut filled = 0usize;
    let header_end = loop {
        let n = sock.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(anyhow!("client closed before headers"));
        }
        filled += n;
        if let Some(pos) = find_double_crlf(&buf[..filled]) {
            break pos;
        }
        if filled == buf.len() {
            return Err(anyhow!("headers too large"));
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_len = 0usize;
    let mut authed = false;
    for l in lines {
        let (k, v) = match l.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => content_len = v.parse().unwrap_or(0),
            "authorization" => {
                if v.strip_prefix("Bearer ").map(|t| constant_time_eq(t, &token)).unwrap_or(false) {
                    authed = true;
                }
            }
            _ => {}
        }
    }
    let mut body: Vec<u8> = Vec::new();
    if content_len > 0 {
        if content_len > 4 * 1024 * 1024 {
            return reply(&mut sock, 413, "text/plain", b"payload too large").await;
        }
        let have = filled - header_end - 4;
        body.extend_from_slice(&buf[header_end + 4..header_end + 4 + have.min(content_len)]);
        while body.len() < content_len {
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }

    // the UI shell needs no token in the URL, but every data path does
    let needs_auth = path.starts_with("/rpc") || path.starts_with("/events");
    if needs_auth && !authed {
        return reply(&mut sock, 401, "application/json", br#"{"error":"missing or bad bearer token"}"#).await;
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => reply(&mut sock, 200, "text/html; charset=utf-8", PAGE.as_bytes()).await,
        ("GET", "/health") => reply(&mut sock, 200, "application/json", br#"{"ok":true}"#).await,
        ("POST", "/rpc") => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
            let m = req["method"].as_str().unwrap_or("").to_string();
            if m.is_empty() {
                return reply(&mut sock, 400, "application/json", br#"{"error":"method required"}"#).await;
            }
            let params = req.get("params").cloned().unwrap_or_else(|| serde_json::json!({}));
            let out = match rpc::request(&dir, &m, &params.to_string()) {
                Ok(v) => v.to_string(),
                Err(e) => serde_json::json!({ "ok": false, "error": format!("{e:#}") }).to_string(),
            };
            reply(&mut sock, 200, "application/json", out.as_bytes()).await
        }
        ("GET", "/events") => sse(&mut sock, &dir).await,
        _ => reply(&mut sock, 404, "application/json", br#"{"error":"not found"}"#).await,
    }
}

/// Server-sent events: pump the node's own `events.subscribe` stream straight to the browser.
async fn sse(sock: &mut TcpStream, dir: &str) -> Result<()> {
    sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-store\r\nconnection: close\r\n\r\n")
        .await?;
    let path = rpc::socket_path(dir)?;
    let stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| anyhow!("node socket: {e}"))?;
    stream.set_nonblocking(true)?;
    let mut unix = tokio::net::UnixStream::from_std(stream)?;
    unix.write_all(b"{\"id\":1,\"method\":\"events.subscribe\"}\n").await?;
    let mut acc: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match unix.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                acc.extend_from_slice(&chunk[..n]);
                while let Some(pos) = acc.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    let payload = String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]).to_string();
                    if sock.write_all(format!("data: {payload}\n\n").as_bytes()).await.is_err() {
                        return Ok(());
                    }
                    let _ = sock.flush().await;
                }
            }
        }
    }
    Ok(())
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Compare tokens without leaking length/content timing to a local attacker.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

async fn reply(sock: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!("HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await?;
    Ok(())
}

