//! rsnext-node — M0/M1 CLI: identity, QR/深链加好友 payload, and a two-process
//! Noise_XX handshake + E2E chat over TCP-loopback (transport placeholder for iroh/QUIC in M2).
mod feed;
mod net;
mod rpc;
mod web;
use rsnext_core::channel::transport_pair;
use rsnext_core::handshake::{EphemeralPubHolder, XxHandshake};
use rsnext_core::identity::Identity;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn dir_paths(dir: &str) -> anyhow::Result<std::path::PathBuf> {
    let p = std::path::Path::new(dir);
    Ok(if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir()?.join(p) })
}

fn data_dir(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_else(|| ".rsnext".to_string())
}

/// Derive a channel-safe subscription name from a URL: last path segment, else the host.
pub(crate) fn default_feed_name(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next().unwrap_or("").trim_end_matches(".xml").trim_end_matches(".rss");
    let base = if tail.is_empty() || tail.contains(".php") || tail.contains('?') {
        trimmed.split('/').nth(3).unwrap_or("feed")
    } else {
        tail
    };
    let clean: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let clean = clean.trim_matches('-').to_string();
    if clean.is_empty() { "feed".to_string() } else { clean }
}
fn load_identity(dir: &str) -> Identity {
    let raw = std::fs::read_to_string(format!("{}/identity.json", dir)).expect("no identity: run `init` first");
    serde_json::from_str(&raw).unwrap()
}
fn save_json(path: &str, v: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}
fn read_exact_msg(r: &mut impl Read) -> Vec<u8> {
    let mut l = [0u8; 4];
    r.read_exact(&mut l).unwrap();
    let n = u32::from_le_bytes(l) as usize;
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).unwrap();
    b
}
fn write_msg(w: &mut impl Write, b: &[u8]) {
    w.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
    w.write_all(b).unwrap();
    w.flush().unwrap();
}

/// Peer-facing CLI verbs mapped onto control-plane methods, so the dial is performed by the
/// running node. A CLI that dials on its own binds a throwaway UDP port, and the peer would then
/// record *that* as our address — a dead endpoint the moment the command exits.
fn delegate_plan(cmd: &str, a: &[String]) -> Option<(&'static str, String)> {
    use serde_json::json;
    let g = |i: usize| a.get(i).cloned().unwrap_or_default();
    match cmd {
        // the explicit address must survive delegation, otherwise a user-supplied address is
        // silently ignored in favour of a possibly-stale stored one
        "p2p-send" => Some(("chat.send", json!({ "to": g(5), "addr": g(4), "text": g(6) }).to_string())),
        "p2p-ls" => Some(("files.ls_peer", json!({ "to": g(5), "addr": g(4) }).to_string())),
        "p2p-pull" => Some(("files.pull", json!({ "to": g(5), "addr": g(4), "name": g(6) }).to_string())),
        "p2p-pull-all" => Some(("files.pull_all", json!({ "to": g(5), "addr": g(4) }).to_string())),
        "p2p-push" => Some(("files.push", json!({ "to": g(5), "addr": g(4), "path": g(6) }).to_string())),
        "p2p-sync" => Some(("sync.peer", json!({ "to": g(5), "addr": g(4) }).to_string())),
        "hi" => {
            let spec = g(3);
            let (fp, addr) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
            Some(("node.hello", json!({ "to": fp, "addr": addr }).to_string()))
        }
        "sync-all" => {
            let mut m = serde_json::Map::new();
            for s in a.iter().skip(3) {
                if let Some((k, v)) = s.split_once('=') {
                    m.insert(k.to_string(), json!(v));
                }
            }
            Some(("sync.all", serde_json::Value::Object(m).to_string()))
        }
        _ => None,
    }
}

fn peers_path(dir: &str) -> String { format!("{}/peers.json", dir) }
fn load_peers(dir: &str) -> serde_json::Map<String, serde_json::Value> {
    std::fs::read_to_string(peers_path(dir)).map(|s| serde_json::from_str(&s).unwrap()).unwrap_or_default()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(|s| s.as_str()).unwrap_or("help");
    // ---- M2 iroh async commands (tokio runtime) ----
    {
        let iroh_cmds = ["net", "p2p-send", "p2p-push", "p2p-sync", "forum-post", "inbox",
                         "peers", "share", "unshare", "p2p-ls", "p2p-pull", "p2p-pull-all", "sync-all", "hi", "find",
                             "wot-sign", "wot-list", "wot-trust", "wot-sync"];
        if iroh_cmds.contains(&cmd) {
            // Prefer the live node (it owns the real listening endpoint); fall back to dialing
            // ourselves only when no daemon is running, so one-shot usage still works.
            if let Some((method, params)) = delegate_plan(cmd, &a) {
                let dir0 = data_dir(&a, 2);
                match rpc::request(&dir0, method, &params) {
                    Ok(v) => {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                        if v["ok"].as_bool() != Some(true) {
                            std::process::exit(2);
                        }
                        return;
                    }
                    Err(e) => println!("[note] no reachable node in {dir0} ({e:#}); dialing directly from this process"),
                }
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            let myfp = |dir: &str| -> String {
                let raw = std::fs::read_to_string(format!("{}/identity.json", dir)).unwrap();
                let id: Identity = serde_json::from_str(&raw).unwrap();
                id.fingerprint()
            };
            use rsnext_core::identity::Identity;
            use rsnext_core::store::Store;
            let _ = Identity::generate("x"); // ensure type import used even in odd builds
            match cmd {
                "net" => { let dir = data_dir(&a, 2);
                    // `net <dir> [udp-port]`: an explicit port is what makes an invite deep link
                    // remain dialable after a restart, so it must actually reach the endpoint.
                    let port: u16 = a.get(3).and_then(|p| p.parse().ok()).unwrap_or(0);
                    // one Store and one event bus for the whole process: the iroh daemon publishes,
                    // the control plane fans out to subscribers
                    let store = std::sync::Arc::new(Store::open(&format!("{}/rsnext.db", dir)).unwrap());
                    let (evtx, _) = tokio::sync::broadcast::channel::<serde_json::Value>(256);
                    rt.block_on(async {
                        // announce our declared state on every hi/heartbeat; the daemon owns the
                        // endpoint, so it is the only place that can set this
                        let (st0, idle0) = {
                            let raw = std::fs::read_to_string(format!("{dir}/status.json")).unwrap_or_default();
                            serde_json::from_str::<serde_json::Value>(&raw)
                                .map(|v| (v["state"].as_str().unwrap_or("online").to_string(), v["idle"].as_i64().unwrap_or(0)))
                                .unwrap_or_else(|_| ("online".to_string(), 0))
                        };
                        net::set_self_status(&st0, idle0);
                        let (daemon, _rpc) = tokio::join!(
                            net::daemon(dir.clone(), port, store.clone(), evtx.clone()),
                            rpc::serve(dir, store, evtx));
                        daemon
                    }).unwrap(); }
                "forum-post" => { let dir = data_dir(&a, 2); let text = a.get(3).cloned().unwrap_or_default(); let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap(); let seq = store.add_post(&myfp(&dir), &text).unwrap(); println!("posted seq {seq}"); }
                "inbox" => { let dir = data_dir(&a, 2); let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap(); for (seq, peer, text, ts) in store.messages(50) { println!("#{seq} [{ts}] {peer}: {text}"); } }
                "peers" => { let dir = data_dir(&a, 2); let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let ps = store.peers();
                    println!("{} bound peer(s):", ps.len());
                    for (fp, eid, pair, addr, ts) in ps {
                        let e = if eid.is_empty() { "-".to_string() } else { format!("{}…", &eid[..eid.len().min(16)]) };
                        let ad = if addr.is_empty() { "(addr unknown — peer has not contacted us yet)".to_string() } else { addr };
                        println!("  {fp}  endpoint={e}  pair={pair}  last_addr={ad}  bound_ts={ts}");
                    }
                }
                "share" => { let dir = data_dir(&a, 2); let p = a.get(3).cloned().unwrap_or_default();
                    let abs = dir_paths(&p).unwrap();
                    let bytes = std::fs::read(&abs).unwrap_or_else(|e| { println!("cannot read {}: {e}", abs.display()); std::process::exit(2) });
                    use sha2::{Digest, Sha256};
                    let sha = hex::encode(Sha256::digest(&bytes));
                    let name = abs.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "file.bin".into());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    store.set_shared(&name, bytes.len() as i64, &sha, &abs.to_string_lossy(), true).unwrap();
                    println!("sharing {name} ({}B sha={}…)", bytes.len(), &sha[..16]);
                }
                "unshare" => { let dir = data_dir(&a, 2); let name = a.get(3).cloned().unwrap_or_default();
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    println!("{}", if store.unshare(&name).unwrap() { format!("revoked {name}") } else { format!("not offered: {name}") });
                }
                "p2p-ls" => { let (dir, eid, addr, peer_fp) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer {peer_fp} not bound; run accept first"); std::process::exit(2); }
                    let mine = myfp(&dir);
                    let files = rt.block_on(net::list_offered(dir, eid, addr, mine, pair))
                        .unwrap_or_else(|e| { println!("ls failed: {e:#}"); std::process::exit(2); });
                    println!("{} shared file(s):", files.len());
                    for f in files { println!("  {:<28} {:>12} B  sha={}", f["name"].as_str().unwrap_or("?"), f["size"].as_i64().unwrap_or(0), f["sha"].as_str().unwrap_or("?")); } }
                "p2p-pull-all" => { let (dir, eid, addr, peer_fp) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap_or_default());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer {peer_fp} not bound; run accept first"); std::process::exit(2); }
                    let mine = myfp(&dir);
                    let v = rt.block_on(net::pull_all(dir, eid, addr, mine, pair))
                        .unwrap_or_else(|e| { println!("failed: {e:#}"); std::process::exit(2); });
                    println!("offered={} transferred={} skipped={} bytes={}",
                        v["offered"], v["transferred"], v["skipped"], v["bytes"]);
                    for ac in v["actions"].as_array().cloned().unwrap_or_default() {
                        println!("  {:<28} {}", ac["name"].as_str().unwrap_or("?"), ac["action"].as_str().unwrap_or("?")); } }
                "p2p-pull" => { let (dir, eid, addr, peer_fp, name) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap(), a.get(6).cloned().unwrap_or_default());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer {peer_fp} not bound; run accept first"); std::process::exit(2); }
                    let mine = myfp(&dir);
                    rt.block_on(net::pull_file(dir, eid, addr, name, mine, pair))
                        .unwrap_or_else(|e| { println!("failed: {e:#}"); std::process::exit(2); }); }
                "sync-all" => { let dir = data_dir(&a, 2); let mine = myfp(&dir);
                    // extra args of the form FINGERPRINT=ip:port override stale addresses
                    let overrides: Vec<(String, String)> = a.iter().skip(3)
                        .filter_map(|s| s.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
                    rt.block_on(net::sync_all(dir, mine, overrides)).unwrap(); }
                "wot-sign" => { let dir = data_dir(&a, 2); let target = a.get(3).cloned().unwrap_or_default();
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let me = load_identity(&dir);
                    let (ed, _pair, _addr, x25519) = store.peer_full(&target).unwrap_or_else(|| { println!("unknown peer {target}"); std::process::exit(2) });
                    if x25519.is_empty() {
                        // Signing half an identity would mint a certificate that vouches for the
                        // Ed25519 key only, while the Noise channel runs on X25519 - refuse rather
                        // than create trust that does not cover the key that matters.
                        println!("refusing to sign {target}: we have never learned its X25519 half (it must contact us once, or send an invite containing x25519=)");
                        std::process::exit(2);
                    }
                    let cert = rsnext_core::wot::CertInfo { subject_fp: target.clone(), subject_ed: ed, subject_x25519: x25519, ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) };
                    let sig = rsnext_core::wot::sign_cert(&me, &cert).unwrap();
                    let c = rsnext_core::wot::Cert { issuer_fp: me.fingerprint(), issuer_ed: me.ed25519_public.clone(), sig, cert };
                    store.put_cert(&c).unwrap();
                    println!("signed {target} as {} ({} bytes of identity, verifiable offline)", me.fingerprint(), 64); }
                "wot-list" => { let dir = data_dir(&a, 2); let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let certs = store.certs();
                    println!("{} certificate(s):", certs.len());
                    for c in &certs {
                        let status = if rsnext_core::wot::verify_cert(&c.issuer_ed, &c.cert, &c.sig).is_ok() { "OK" } else { "BAD  <-- not trustworthy" };
                        println!("  {} <- issuer {} [{}] ts={}", c.cert.subject_fp, c.issuer_fp, status, c.cert.ts);
                    } }
                "wot-trust" => { let dir = data_dir(&a, 2); let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let me = load_identity(&dir).fingerprint();
                    let edges = store.cert_edges();
                    let map = rsnext_core::wot::trust_map(&me, &edges);
                    if map.is_empty() { println!("no certificates signed yet - nothing to score (use wot-sign)"); }
                    for (who, score) in map {
                        println!("  {who}  trust={score:.3}");
                    }
                    if let Some(t) = a.get(3) {
                        match rsnext_core::wot::trust_score(&me, t, &edges) {
                            Some(v) => println!("trust in {t}: {v:.3}"),
                            None => println!("trust in {t}: none (no signature chain from us)"),
                        }
                    } }
                "wot-sync" => { let dir = data_dir(&a, 2); let mine = myfp(&dir);
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    for (fp, eid, pair, addr, _) in store.peers() {
                        if fp == mine || eid.is_empty() || addr.is_empty() { continue; }
                        print!("  {fp} @ {addr}: ");
                        match rt.block_on(net::wot_exchange(dir.clone(), eid.clone(), addr.clone(), mine.clone(), pair.clone())) {
                            Ok(n) => println!("+{n} cert(s)"),
                            Err(e) => println!("skipped ({e:#})"),
                        }
                    } }
                "find" => { let dir = data_dir(&a, 2); let target = a.get(3).cloned().unwrap_or_default();
                    match rt.block_on(net::find_peer(dir, target.clone())) {
                        Ok(Some(addr)) => println!("{target} is reachable at {addr}"),
                        Ok(None) => { println!("{target}: no friend could tell us where it is (make sure somebody mutual is online)"); std::process::exit(2); }
                        Err(e) => { println!("find failed: {e:#}"); std::process::exit(2); }
                    } }
                "hi" => { let dir = data_dir(&a, 2); let mine = myfp(&dir);
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let spec = a.get(3).cloned().unwrap_or_default();
                    let (fp, addr) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
                    let (eid, pair) = store.peer_by_fp(fp).unwrap_or_default();
                    if eid.is_empty() { println!("peer {fp} not bound; run accept first"); std::process::exit(2); }
                    match rt.block_on(net::say_hi(&dir, &eid, addr, &mine, &pair)) {
                        Ok(v) => println!("hello {fp} at {addr} -> {v}  (their record of us is now current)"),
                        Err(e) => { println!("hello {fp} at {addr} failed: {e:#}"); std::process::exit(2); }
                    } }
                "p2p-send" => { let (dir, eid, addr, peer_fp, text) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap(), a.get(6).cloned().unwrap_or_default());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer {peer_fp} not bound; run accept first"); std::process::exit(2); }
                    let mine = myfp(&dir); // compute before `dir` is moved into the async call
                    rt.block_on(net::send_msg(dir, eid, addr, text, mine, pair))
                        .unwrap_or_else(|e| { println!("failed: {e:#}"); std::process::exit(2); }); }
                "p2p-push" => { let (dir, eid, addr, peer_fp, path) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap(), a.get(6).cloned().unwrap_or_default());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer not bound"); std::process::exit(2); }
                    let mine = myfp(&dir);
                    rt.block_on(net::push_file(dir, eid, addr, path, mine, pair))
                        .unwrap_or_else(|e| { println!("failed: {e:#}"); std::process::exit(2); }); }
                "p2p-sync" => { let (dir, eid, addr, peer_fp) = (data_dir(&a,2), a.get(3).cloned().unwrap(), a.get(4).cloned().unwrap(), a.get(5).cloned().unwrap());
                    let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
                    let (pe, pair) = store.peer_by_fp(&peer_fp).unwrap_or_default();
                    if pe.is_empty() { println!("peer not bound"); std::process::exit(2); }
                    let mine = myfp(&dir);
                    rt.block_on(net::forum_sync(dir, eid, addr, mine, pair)).unwrap(); }
                _ => {}
            }
            return;
        }
    }
    match cmd {
        "channel-create" => { let dir = data_dir(&a, 2); let name = a.get(3).cloned().unwrap_or_default();
            let desc = a.get(4).cloned().unwrap_or_default();
            if name.is_empty() { println!("usage: channel-create <dir> <name> [desc]"); std::process::exit(2); }
            let me = load_identity(&dir).fingerprint();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let fresh = store.create_channel(&name, &me, &desc).unwrap();
            println!("{} channel {name}", if fresh { "created" } else { "already had" }); }
        "channel-post" => { let dir = data_dir(&a, 2); let name = a.get(3).cloned().unwrap_or_default(); let body = a.get(4).cloned().unwrap_or_default();
            let me = load_identity(&dir).fingerprint();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let _ = store.create_channel(&name, &me, "");
            let seq = store.add_post_to(&name, &me, &body).unwrap();
            println!("posted {name}/#{seq}"); }
        "channel-list" => { let dir = data_dir(&a, 2);
            let me = load_identity(&dir).fingerprint();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let subs = store.subs(&me);
            println!("{:<22} {:>6} {:>8} {:>8}  {}", "channel", "posts", "read", "unread", "by");
            let mut names: Vec<String> = store.channels().into_iter().map(|c| c.0).collect();
            names.push("general".into()); names.sort(); names.dedup();
            for n in names {
                let posts = store.post_count_in(&n);
                let last = subs.iter().find(|(c, _)| *c == n).map(|(_, v)| *v).unwrap_or(0);
                let unread = store.unread_for(&n, &me);
                let by = store.channels().into_iter().find(|c| c.0 == n).map(|c| c.1).unwrap_or_else(|| "-".into());
                println!("{n:<22} {posts:>6} {last:>8} {unread:>8}  {by}");
            } }
        "forum-read" => { let dir = data_dir(&a, 2); let name = a.get(3).cloned().unwrap_or_else(|| "general".into());
            let me = load_identity(&dir).fingerprint();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let top = store.max_seq_in(&name);
            let cursor = store.mark_read(&name, &me, top).unwrap();
            println!("marked {name} read (cursor {cursor}, up to author-seq {top})"); }
        "web" => {
            // loopback by default: the control plane can read messages and pull files
            let dir = data_dir(&a, 2);
            let bind = a.get(3).cloned().unwrap_or_else(|| "127.0.0.1:8780".into());
            if !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
                println!("[warn] binding {bind} is reachable off-host; the token in web/token is then the only protection");
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(web::serve(dir, bind)).unwrap();
        }
        "events" => {
            let dir = data_dir(&a, 2);
            if let Err(e) = rpc::subscribe(&dir) { println!("events error: {e:#}"); std::process::exit(2); }
        }
        "rpc" => {
            // one-shot control-plane client (what the future Tauri/mobile UI will call)
            let dir = data_dir(&a, 2);
            let method = a.get(3).cloned().unwrap_or_else(|| "node.info".into());
            let params = a.get(4).cloned().unwrap_or_default();
            if let Err(e) = rpc::call_one_shot(&dir, &method, &params) { println!("rpc error: {e:#}"); std::process::exit(2); }
        }
        "init" => {
            let name = a.get(2).cloned().unwrap_or("anonymous".into());
            let dir = data_dir(&a, 3);
            std::fs::create_dir_all(&dir).unwrap();
            let id = Identity::generate(&name);
            save_json(&format!("{}/identity.json", dir), &id);
            println!("node '{}' initialized in {}\nfingerprint: {}", name, dir, id.fingerprint());
        }
        "id" => {
            let dir = data_dir(&a, 2);
            let id = load_identity(&dir);
            println!("{}  fingerprint {}", id.name, id.fingerprint());
        }
        "invite" => {
            let dir = data_dir(&a, 2);
            let id = load_identity(&dir);
            let code: String = "ABCDEFGH23456789".chars().map(|_| "ABCDEFGH23456789".chars().nth(rand::random::<usize>() % 16).unwrap()).collect();
            let addr = a.get(3).cloned().unwrap_or("127.0.0.1:7777".into());
            save_json(&format!("{}/pairing.json", dir), &serde_json::json!({ "code": code, "issued_to": null }));
        }
        "invite2" => {
            // deterministic demo variant: fixed code stored, prints the deep-link/QR payload
            let dir = data_dir(&a, 2);
            let id = load_identity(&dir);
            let code = a.get(3).cloned().unwrap_or_else(|| "PAIR-DEMO".into());
            let addr = a.get(4).cloned().unwrap_or("127.0.0.1:7777".into());
            save_json(&format!("{}/pairing.json", dir), &serde_json::json!({ "code": code }));
            println!("{}", id.invite_payload(&code, &addr));
        }
        "accept" => {
            // friend side: paste the invite payload -> register peer binding
            let dir = data_dir(&a, 2);
            let payload = a.get(3).cloned().expect("accept <dir> <invite-payload>");
            let mut kv = std::collections::HashMap::new();
            for part in payload.trim_start_matches("rsnext://v1?").split('&') {
                let mut it = part.splitn(2, '=');
                kv.insert(it.next().unwrap().to_string(), it.next().unwrap_or("").to_string());
            }
            let fp = kv.get("id").cloned().unwrap_or_default();
            let mut peers = load_peers(&dir);
            peers.insert(fp.clone(), serde_json::json!({
                "ed": kv.get("ed"), "x25519": kv.get("x25519"), "pair": kv.get("pair"), "addr": kv.get("addr")
            }));
            save_json(&peers_path(&dir), &serde_json::Value::Object(peers));
            // M2 wiring: mirror the binding into SQLite so the iroh transport (p2p-send/push/sync)
            // sees the same peer set as the M1 TCP path. The invite payload's `ed` is the peer's
            // Ed25519 key, which IS its iroh EndpointId in hex (verified against `net` output).
            use rsnext_core::store::Store;
            let ed = kv.get("ed").cloned().unwrap_or_default();
            let pair = kv.get("pair").cloned().unwrap_or_default();
            let peer_addr = kv.get("addr").cloned().unwrap_or_default();
            let store = Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            store.bind_peer(&fp, &ed, &pair, &peer_addr).unwrap();
            let _ = store.set_peer_x25519(&fp, &kv.get("x25519").cloned().unwrap_or_default());
            println!("bound peer {fp} (pairing code {pair}, invite addr {peer_addr})");
        }
        "listen" => {
            let dir = data_dir(&a, 2);
            let addr = a.get(3).cloned().unwrap_or("127.0.0.1:7777".into());
            let id = load_identity(&dir);
            let srv = TcpListener::bind(&addr).unwrap();
            eprintln!("[{}] listening {}", id.name, addr);
            for conn in srv.incoming() {
                let mut sock = match conn { Ok(v) => v, Err(_) => continue };
                let peer_addr = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                let mut hs = XxHandshake::new(id.x25519_secret_bytes());
                // responder: msg1 (from peer), msg2 ->, msg3 <-
                let m1 = read_exact_msg(&mut sock);
                let eph = hs.read_msg1(&m1).unwrap();
                let m2 = hs.write_msg2(&eph);
                write_msg(&mut sock, &m2);
                let m3 = read_exact_msg(&mut sock);
                let (k, tempk, _h) = hs.read_msg3(&m3).unwrap();
                eprintln!("HS-KEYS listen k={} tempk={}", hex::encode(&k[..4]), hex::encode(&tempk[..4]));
                let (mut send, mut recv) = transport_pair(k, tempk, false);
                // binding proof frame: static pub + pairing code expected from us? initiator sends its fp+code sealed
                let first = recv.open(&read_exact_msg(&mut sock)).unwrap();
                let hello: serde_json::Value = serde_json::from_slice(&first).unwrap();
                let peer_fp = hello["fp"].as_str().unwrap_or_default().to_string();
                let code = hello["pair"].as_str().unwrap_or_default().to_string();
                // F2F magic-link semantics: whoever presents the issued one-time code binds (QR deep-link click = two-way trust)
                let issued: String = std::fs::read_to_string(format!("{}/pairing.json", dir))
                    .map(|t| serde_json::from_str::<serde_json::Value>(&t).ok().and_then(|j| j["code"].as_str().map(String::from)).unwrap_or_default()).unwrap_or_default();
                let mut peers = load_peers(&dir);
                let known = !issued.is_empty() && code == issued;
                if known && !peers.contains_key(&peer_fp) {
                    let x = std::collections::HashMap::<String, serde_json::Value>::new();
                    peers.insert(peer_fp.clone(), serde_json::json!({ "pair": code, "since": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0), "x25519": x }));
                    save_json(&peers_path(&dir), &serde_json::Value::Object(peers));
                    println!("[{}] bound new peer {} via one-time code", id.name, peer_fp);
                }
                let reply = serde_json::json!({ "ok": known, "fp": id.fingerprint(), "peer_addr": peer_addr.to_string() });
                let framed = send.seal(&serde_json::to_vec(&reply).unwrap()).unwrap();
                write_msg(&mut sock, &framed);
                if !known { eprintln!("!! unknown peer {} from {}", peer_fp, peer_addr); continue; }
                // message loop: sealed JSON lines -> inbox.json
                let mut inbox: Vec<serde_json::Value> = std::fs::read_to_string(format!("{}/inbox.json", dir))
                    .map(|s| serde_json::from_str(&s).unwrap()).unwrap_or_default();
                loop {
                    let ct = match read_exact_opt(&mut sock) { Some(v) => v, None => break };
                    match recv.open(&ct) {
                        Ok(pt) => {
                            let v: serde_json::Value = serde_json::from_slice(&pt).unwrap();
                            println!("E2E message from {}: {}", v["from"].as_str().unwrap_or("?"), v["text"].as_str().unwrap_or(""));
                            inbox.push(v);
                            save_json(&format!("{}/inbox.json", dir), &inbox);
                        }
                        Err(e) => { eprintln!("open error: {}", e); break; }
                    }
                }
            }
        }
        "talk" => {
            let dir = data_dir(&a, 2);
            let addr_s = a.get(3).cloned().expect("talk <dir> <addr> <text> [peer-fp]");
            let text = a.get(4).cloned().unwrap_or("hello".into());
            let peer_fp = a.get(5).cloned().unwrap_or_default();
            let id = load_identity(&dir);
            let mut sock = TcpStream::connect(&addr_s).unwrap();
            let mut hs = XxHandshake::new(id.x25519_secret_bytes());
            let m1 = hs.write_msg1();
            write_msg(&mut sock, &m1);
            let m2 = read_exact_msg(&mut sock);
            hs.read_msg2(&m2).unwrap();
            let (m3, (k, tempk, _h)) = hs.write_msg3();
            write_msg(&mut sock, &m3);
            eprintln!("HS-KEYS talk k={} tempk={}", hex::encode(&k[..4]), hex::encode(&tempk[..4]));
            let (mut send, mut recv) = transport_pair(k, tempk, true);
            // hello: our fp + pairing code we were told to present
            let peers = load_peers(&dir);
            let entry = peers.get(&peer_fp).cloned().unwrap_or_else(|| peers.values().next().cloned().unwrap_or(serde_json::json!({})));
            let paircode = entry["pair"].as_str().unwrap_or("").to_string();
            let hello = serde_json::json!({ "fp": id.fingerprint(), "pair": paircode });
            let framed = send.seal(&serde_json::to_vec(&hello).unwrap()).unwrap();
            write_msg(&mut sock, &framed);
            let ack = recv.open(&read_exact_msg(&mut sock)).unwrap();
            let ackv: serde_json::Value = serde_json::from_slice(&ack).unwrap();
            if ackv["ok"] != serde_json::json!(true) { println!("peer rejected pairing (unknown or wrong code): {}", ackv); std::process::exit(2); }
            println!("handshake ok -> bound to {}", ackv["fp"].as_str().unwrap_or("?"));
            let msg = serde_json::json!({ "from": id.fingerprint(), "text": text });
            let ct = send.seal(&serde_json::to_vec(&msg).unwrap()).unwrap();
            write_msg(&mut sock, &ct);
            println!("E2E message sent to {} (sealed {} bytes)", peer_fp, ct.len());
        }
        "demo-xx" => {
            let a = Identity::generate("A");
            let b = Identity::generate("B");
            let mut ha = XxHandshake::new(a.x25519_secret_bytes());
            let mut hb = XxHandshake::new(b.x25519_secret_bytes());
            let m1 = ha.write_msg1();
            let re = hb.read_msg1(&m1).unwrap();
            println!("step1 h match: {} (len m1 {})", ha.h() == hb.h(), m1.len());
            let m2 = hb.write_msg2(&re);
            let rs_a = match ha.read_msg2(&m2) { Ok(v) => v, Err(e) => { println!("read_msg2 FAIL: {}", e); std::process::exit(1); } };
            println!("step2 h match: {} (len m2 {}, rs seen {})", ha.h() == hb.h(), m2.len(), hex::encode(&rs_a[..4]));
            let (m3, (ka, ta, hka)) = ha.write_msg3();
            let hres = hb.read_msg3(&m3);
            match hres {
                Ok((kb, tb, hkb)) => {
                    println!("step3 h match: {}", hka == hkb);
                    println!("k match: {}  tempk match: {}", hex::encode(ka) == hex::encode(kb), hex::encode(ta) == hex::encode(tb));
                    let (mut sa, mut ra) = transport_pair(ka, ta, true);
                    let (mut sb, mut rb) = transport_pair(kb, tb, false);
                    let ct = sa.seal(b"hello").unwrap();
                    println!("a->b open: {:?}", String::from_utf8_lossy(&rb.open(&ct).unwrap_or_default()));
                    let ct2 = sb.seal(b"ack").unwrap();
                    println!("b->a open: {:?}", String::from_utf8_lossy(&ra.open(&ct2).unwrap_or_default()));
                }
                Err(e) => println!("read_msg3 FAIL: {}", e),
            }
        }
        "rss-add" => {
            let dir = data_dir(&a, 2);
            let url = a.get(3).cloned().unwrap_or_default();
            if url.is_empty() { println!("usage: rss-add <dir> <url> [name]"); std::process::exit(2); }
            let name = a.get(4).cloned().unwrap_or_else(|| default_feed_name(&url));
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let fresh = store.add_feed(&name, &url).unwrap();
            println!("feed {name} -> {url}  ({})", if fresh { "subscribed" } else { "url updated" });
        }
        "rss-fetch" => {
            let dir = data_dir(&a, 2);
            let only = a.get(3).cloned();
            match feed::rss_fetch(&dir, only.as_deref()) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { println!("rss fetch failed: {e:#}"); std::process::exit(2); }
            }
        }
        "rss-list" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let fs = store.feeds();
            if fs.is_empty() { println!("no subscriptions"); }
            for (n, u) in fs {
                println!("  {n:<22} seen={:<4} {u}", store.seen_count(&n));
            }
        }
        "search-rebuild" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let (posts, files) = store.deep_rebuild().unwrap_or_else(|e| { println!("rebuild failed: {e:#}"); std::process::exit(2); });
            let (docs, terms) = store.deep_stats();
            println!("rebuilt from truth: {posts} posts, {files} files -> {docs} docs / {terms} postings");
        }
        "search-status" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let (docs, terms) = store.deep_stats();
            // the invariant worth watching: indexed documents must equal real content. A gap here
            // means some write path stopped maintaining the index.
            println!("index: {docs} docs / {terms} postings | truth: {} posts + {} offered files ({} rows held)",
                store.post_count(), store.shared_count(), store.file_count());
        }
        "search" => {
            let dir = data_dir(&a, 2);
            let q = a.get(3).cloned().unwrap_or_default();
            if q.is_empty() { println!("usage: search <dir> <words> [channel]"); std::process::exit(2); }
            let ch = a.get(4).cloned();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let ranked = store.deep_search(&q, ch.as_deref(), 50)
                .unwrap_or_else(|e| { println!("search failed: {e:#}"); std::process::exit(2); });
            println!("{} hit(s) for {:?}{}", ranked.len(), q, ch.clone().map(|c| format!(" in {c}")).unwrap_or_default());
            for (url, w, snippet) in ranked {
                println!("  {w:.4}  {url}\n         {snippet}");
            }
            // substring lookup is a different question than "which documents contain these words",
            // so it is still available, just not mixed into the ranked list above
            let hits = store.search_posts(&q, ch.as_deref(), 50);
            println!("{} post(s) matching {:?}{}", hits.len(), q, ch.map(|c| format!(" in {c}")).unwrap_or_default());
            for (chan, seq, author, body, ts) in hits {
                let one: String = body.chars().take(90).collect();
                println!("  [{chan} #{seq}] {author} @ {ts}: {one}");
            }
            let files = store.search_files(&q, true, 20).unwrap_or_else(|e| { println!("file index unreadable: {e}"); Vec::new() });
            if !files.is_empty() {
                println!("{} shared file(s):", files.len());
                for (name, size, sha) in files { println!("  {name:<28} {size:>12} B  sha={}", &sha[..sha.len().min(16)]); }
            }
        }
        "wiki-list" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let pages = store.wiki_pages();
            if pages.is_empty() { println!("no wiki pages"); }
            for p in pages {
                let cur = store.wiki_current(&p);
                let hist = store.wiki_history(&p).len();
                match cur {
                    Some(r) => println!("  {p:<24} {hist:>3} rev(s)  current by {} @ {}", r.author, r.ts),
                    None => println!("  {p:<24}   0 rev(s)  (empty)"),
                }
            }
        }
        "wiki-show" => {
            let dir = data_dir(&a, 2);
            let page = a.get(3).cloned().unwrap_or_default();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            match store.wiki_current(&page) {
                Some(r) => { println!("page {page} - revision {} by {} @ {}", r.seq, r.author, r.ts); println!("{}", r.body); }
                None => { println!("no such page (or no revisions): {page:?}"); std::process::exit(2); }
            }
        }
        "wiki-history" => {
            let dir = data_dir(&a, 2);
            let page = a.get(3).cloned().unwrap_or_default();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let h = store.wiki_history(&page);
            if h.is_empty() { println!("no history for {page:?}"); std::process::exit(2); }
            for r in &h {
                let one: String = r.body.chars().take(60).collect();
                println!("  #{} {:<20} {}: {one}", r.seq, r.ts, r.author);
            }
            println!("{} revision(s); current = #{}", h.len(),
                rsnext_core::wiki::resolve_current(&h).map(|r| r.seq).unwrap_or(-1));
        }
        "wiki-save" => {
            let dir = data_dir(&a, 2);
            let page = a.get(3).cloned().unwrap_or_default();
            let text = a.get(4).cloned().unwrap_or_default();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let me = load_identity(&dir).fingerprint();
            match store.wiki_save(&page, &me, &text) {
                Ok(seq) => {
                    println!("saved {page} as revision {seq} ({} bytes)", text.len());
                    // a same-second revision by a "higher" author sorts first: say so, rather than
                    // letting the user conclude the save was dropped
                    if let Some(cur) = store.wiki_current(&page) {
                        if cur.author != me {
                            println!("note: current version is by {} (same-second tie); your revision #{} is in history",
                                cur.author, seq);
                        }
                    }
                }
                Err(e) => { println!("save failed: {e:#}"); std::process::exit(2); }
            }
        }
        "ban" => {
            let dir = data_dir(&a, 2);
            let fp = a.get(3).cloned().unwrap_or_default();
            if fp.is_empty() { println!("usage: ban <dir> <fingerprint> [reason]"); std::process::exit(2); }
            let reason = a.get(4).cloned().unwrap_or_else(|| "no reason given".into());
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let fresh = store.ban(&fp, &reason).unwrap();
            println!("{} {fp} ({reason})", if fresh { "banned" } else { "already banned" });
        }
        "unban" => {
            let dir = data_dir(&a, 2);
            let fp = a.get(3).cloned().unwrap_or_default();
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            println!("{}", if store.unban(&fp).unwrap() { "unbanned" } else { "was not banned" });
        }
        "bans" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let b = store.bans();
            if b.is_empty() { println!("no bans"); }
            for (fp, reason, ts) in b { println!("  {fp}  @{ts}  {reason}"); }
        }
        "presence" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let now = rsnext_core::presence::unix_now();
            let rows = store.all_presence(now);
            if rows.is_empty() { println!("no authenticated contact recorded yet"); }
            for (fp, _derived, seen) in rows {
                // same merged rule the control plane uses, so the two views cannot disagree
                let (state, source, _) = store.presence_merged(&fp, now, 300);
                let age = seen.map(|t| now - t).map(|x| format!("{x}s ago")).unwrap_or_else(|| "-".into());
                println!("  {fp}  {state:<8} [{source}] ({age})");
            }
        }
        "circle-create" => {
            let dir = data_dir(&a, 2);
            let name = a.get(3).cloned().unwrap_or_default();
            if name.is_empty() { println!("usage: circle-create <dir> <name>"); std::process::exit(2); }
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            println!("{}", if store.create_circle(&name).unwrap() { "created circle" } else { "circle already existed" });
        }
        "circle-add" => {
            let (dir, name, fp) = (data_dir(&a, 2), a.get(3).cloned().unwrap_or_default(), a.get(4).cloned().unwrap_or_default());
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            match store.circle_add(&name, &fp) {
                Ok(true) => println!("added {fp} to {name}"),
                Ok(false) => println!("{fp} was already in {name}"),
                Err(e) => { println!("{e:#}"); std::process::exit(2); }
            }
        }
        "circle-remove" => {
            let (dir, name, fp) = (data_dir(&a, 2), a.get(3).cloned().unwrap_or_default(), a.get(4).cloned().unwrap_or_default());
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            println!("{}", if store.circle_remove(&name, &fp).unwrap() { "removed" } else { "was not a member" });
        }
        "circles" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let cs = store.circles();
            if cs.is_empty() { println!("no circles (every channel is shared with all friends)"); }
            for (n, members) in cs {
                let restricted: Vec<String> = store.restricted_channels().into_iter()
                    .filter(|(_, c)| c == &n).map(|(ch, _)| ch).collect();
                println!("  {n}: {} member(s) [{}]{}{}", members.len(), members.join(", "),
                    if restricted.is_empty() { "" } else { " -> channels: " },
                    restricted.join(","));
            }
        }
        "restrict" => {
            let (dir, chan, circle) = (data_dir(&a, 2), a.get(3).cloned().unwrap_or_default(), a.get(4).cloned().unwrap_or_default());
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            match store.restrict_channel(&chan, &circle) {
                Ok(()) => println!("channel {chan} will only be sent to members of circle {circle}"),
                Err(e) => { println!("{e:#}"); std::process::exit(2); }
            }
        }
        "unrestrict" => {
            let (dir, chan) = (data_dir(&a, 2), a.get(3).cloned().unwrap_or_default());
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            println!("{}", if store.unrestrict_channel(&chan).unwrap() { "channel is public to friends again" } else { "channel was not restricted" });
        }
        "forget" => {
            // forget <dir> channel|peer <name|fingerprint>
            let (dir, kind, val) = (data_dir(&a, 2), a.get(3).cloned().unwrap_or_default(), a.get(4).cloned().unwrap_or_default());
            if val.is_empty() { println!("usage: forget <dir> channel|peer <name|fingerprint>"); std::process::exit(2); }
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let removed = match kind.as_str() {
                "channel" => store.forget_channel(&val),
                "peer" | "author" => store.forget_author(&val),
                other => { println!("scope must be channel or peer (got {other:?})"); std::process::exit(2); }
            };
            match removed {
                Ok(n) => {
                    println!("erased {n} local row(s) for {kind} {val:?}; they will not return on sync");
                    // an honest limit, said at the moment it matters: F2F replication has no
                    // distributed delete, so peers that already copied this still hold it
                    println!("note: this erases THIS node only - friends who replicated it still have their copy");
                }
                Err(e) => { println!("forget failed: {e:#}"); std::process::exit(2); }
            }
        }
        "forgotten" => {
            let dir = data_dir(&a, 2);
            let store = rsnext_core::store::Store::open(&format!("{}/rsnext.db", dir)).unwrap();
            let f = store.forgotten();
            if f.is_empty() { println!("nothing forgotten"); }
            for (chan, author, seq, ts) in f { println!("  {chan:<16} {author} #{seq} @{ts}"); }
        }
        "status" => {
            let dir = data_dir(&a, 2);
            let state = a.get(3).cloned().unwrap_or_else(|| "online".into());
            if !matches!(state.as_str(), "online" | "away" | "offline") {
                println!("state must be online|away|offline (got {state:?})"); std::process::exit(2);
            }
            let idle = a.get(4).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            // written, not pushed: the next heartbeat carries it, so no live connection is needed
            std::fs::write(format!("{dir}/status.json"), serde_json::json!({ "state": state, "idle": idle }).to_string()).unwrap();
            println!("declared state = {state} (idle {idle}s); carried on the next hi/heartbeat");
        }
        "help" => println!("rsnext-node: init|id|invite2|accept|listen|talk  (see PLAN.md M0/M1)"),
        // An unknown verb must not look like success: a gate that greps for output and checks the
        // exit code would otherwise pass against a stale binary or a typo.
        _ => {
            println!("unknown command '{cmd}'  (rsnext-node: init|id|invite2|accept|listen|talk|net|p2p-*|forum-*|channel-*|wot-*|peers|share|unshare|rpc|events|web)");
            std::process::exit(2);
        }
    }
}

fn read_exact_opt(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut l = [0u8; 4];
    match r.read_exact(&mut l) { Ok(()) => {}, Err(_) => return None }
    let n = u32::from_le_bytes(l) as usize;
    let mut b = vec![0u8; n];
    match r.read_exact(&mut b) { Ok(()) => Some(b), Err(_) => None }
}
