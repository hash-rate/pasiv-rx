//! The slice of XMRig's local HTTP API that Pasiv drives (pasiv-core's
//! `xmrig` contract): token-gated, loopback only, unrestricted.
//!   GET  /2/summary  hashrate + share counts
//!   GET  /1/config   the live pools (the fee reconcile's ground truth)
//!   PUT  /1/config   replace the pools — the fee slice's login hot-swap
//!   POST /json_rpc   {"method":"pause"|"resume"}
use crate::Miner;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub fn serve(m: Arc<Miner>, host: &str, port: u16, token: Option<String>) {
    let listener = match TcpListener::bind((host, port)) {
        Ok(l) => l,
        Err(e) => {
            // Same words as XMRig: the supervisor restarts on this line rather
            // than letting a miner hash on with no API (invisible to it).
            crate::log("http", &format!("HTTP API server failed to start. ({e})"));
            return;
        }
    };
    crate::log("http", &format!("API server listening on {host}:{port}"));
    let token = Arc::new(token);
    for stream in listener.incoming().flatten() {
        let (m, token) = (m.clone(), token.clone());
        std::thread::spawn(move || {
            let _ = handle(&m, stream, token.as_deref());
        });
    }
}

struct Request {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
}

fn read_request(s: &mut TcpStream) -> Option<Request> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let (mut len, mut auth) = (0usize, None);
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            len = v.parse().ok()?;
        } else if k == "authorization" {
            auth = v.strip_prefix("Bearer ").map(str::to_string);
        }
    }
    if len > 1 << 20 {
        return None;
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Some(Request { method, path, auth, body })
}

fn respond(s: &mut TcpStream, status: &str, body: Option<&Value>) -> std::io::Result<()> {
    let text = body.map(|b| b.to_string()).unwrap_or_default();
    write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )
}

/// Constant-time compare, so the token can't be learned a byte at a time.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn handle(m: &Miner, mut s: TcpStream, token: Option<&str>) -> std::io::Result<()> {
    let Some(req) = read_request(&mut s) else {
        return respond(&mut s, "400 Bad Request", None);
    };
    if let Some(t) = token {
        if !req.auth.as_deref().is_some_and(|a| same(a, t)) {
            return respond(&mut s, "401 Unauthorized", Some(&json!({"error": "unauthorized"})));
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/2/summary" | "/1/summary") => respond(&mut s, "200 OK", Some(&m.summary())),
        ("GET", "/1/config" | "/2/config") => respond(&mut s, "200 OK", Some(&m.config_json())),
        ("PUT", "/1/config" | "/2/config") => {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                return respond(&mut s, "400 Bad Request", Some(&json!({"error": "invalid JSON"})));
            };
            match m.apply_config(&v) {
                Ok(()) => respond(&mut s, "204 No Content", None),
                Err(e) => respond(&mut s, "400 Bad Request", Some(&json!({"error": e}))),
            }
        }
        ("POST", "/json_rpc") => {
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let id = v["id"].clone();
            match v["method"].as_str() {
                Some("pause") => m.set_paused(true),
                Some("resume") => m.set_paused(false),
                _ => {
                    return respond(
                        &mut s,
                        "200 OK",
                        Some(&json!({"id": id, "jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}})),
                    )
                }
            }
            respond(&mut s, "200 OK", Some(&json!({"id": id, "jsonrpc": "2.0", "result": {"status": "OK"}})))
        }
        _ => respond(&mut s, "404 Not Found", Some(&json!({"error": "not found"}))),
    }
}
