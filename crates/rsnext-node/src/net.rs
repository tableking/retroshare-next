//! iroh transport (M2): QUIC + hole-punching, identity = our Ed25519 key from identity.json.
//! Wire: 4-byte LE length + JSON frames; bulk file bytes stream raw after header.
//! F2F gating: a known (fp,pair) binding passes; an unknown peer presenting the still-unspent
//! one-time code auto-binds and the code is then consumed (a leaked deep link must not bind a
//! second stranger).
//!
//! iroh 1.4 API notes (verified against iroh-base 1.4.2 sources, not guessed):
//! - `EndpointId` is a type alias of `iroh_base::PublicKey`; its `Display` is lowercase hex.
//! - `SecretKey::from_bytes(&[u8; 32]) -> Self` (infallible; no Result to map).
//! - Addresses are built with `EndpointAddr::new(id).with_ip_addr(sa)` and read back with
//!   `.ip_addrs()`; `endpoint::TransportAddr` is a private re-export, so don't import it.
//! - Relays off = `RelayMode::Disabled`.
//! - Every request frame carries `my_addr`: a peer's own current IP:port, which is the only
//!   reliable way to keep `peers.addr` fresh (iroh binds an ephemeral port on each start).
use crate::dir_paths;
use anyhow::{anyhow, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use rsnext_core::merkle::{first_divergence, leaf_hash, merkle_root};
use rsnext_core::identity::Identity;
use rsnext_core::store::Store;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast;

/// Fire-and-forget node event for the control plane (`events.subscribe`).
/// Subscribers that fell behind are dropped rather than blocking the network path.
fn emit(events: &broadcast::Sender<serde_json::Value>, v: serde_json::Value) {
    let _ = events.send(v);
}

pub const ALPN: &[u8] = b"rsnext/1";
const CHUNK: usize = 256 * 1024;

/// Chatty per-connection logging, off by default; `RSNEXT_VERBOSE=1` turns it on.
pub fn vlog(args: std::fmt::Arguments) {
    if std::env::var("RSNEXT_VERBOSE").map(|s| s != "0").unwrap_or(false) {
        eprintln!("{args}");
    }
}

pub fn secret_from_dir(dir: &str) -> Result<SecretKey> {
    let id: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir_paths(dir)?.join("identity.json"))?)?;
    let bytes = hex::decode(id["ed25519_secret"].as_str().ok_or(anyhow!("no ed25519_secret"))?)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("bad seed len"))?;
    Ok(SecretKey::from_bytes(&arr))
}

/// Ephemeral port (what a dialing client wants: never fight the daemon for a fixed port).
pub async fn build_endpoint(dir: &str) -> Result<Endpoint> {
    build_endpoint_on(dir, 0).await
}

/// `port != 0` pins the UDP port. That is what makes an invite deep link genuinely reachable:
/// `net <dir> 7800` + `invite2 <dir> CODE ip:7800` works both ways from the first contact,
/// instead of waiting for the peer to call us back before we know its address.
/// Our X25519 public key, remembered the first time this process binds an endpoint. Every dial
/// and the daemon itself go through build_endpoint_on, so this is the one place to capture it.
static MY_X25519: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn my_x25519() -> String {
    MY_X25519.get().cloned().unwrap_or_default()
}

/// The X25519 half of the identity stored in `dir` (empty when unreadable).
pub fn x25519_of(dir: &str) -> String {
    let path = match dir_paths(dir) { Ok(p) => p.join("identity.json"), Err(_) => return String::new() };
    match std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Identity>(&t).ok()) {
        Some(i) => i.x25519_public,
        None => String::new(),
    }
}

async fn build_endpoint_on(dir: &str, port: u16) -> Result<Endpoint> {
    let sk = secret_from_dir(dir)?;
    let _ = MY_X25519.set(x25519_of(dir));
    // presets::Minimal, NOT presets::N0: N0 installs PkarrPublisher/PkarrResolver, which publishes
    // our endpoint_id -> current address to n0's public DNS. For a F2F network that claims "zero
    // cloud dependency" that is both an outside dependency and a metadata leak (it tells a public
    // resolver who is talking to whom). Discovery between bound friends is handled by our own
    // invite deep links + the `my_addr` field every request carries; a public name system is a
    // deliberate, self-hosted choice for later (see PLAN M5a "自托管 relay/DNS").
    let mut b = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(sk)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled);
    if port != 0 {
        // bind_addr REPLACES the pre-configured wildcard bind for that address family, so it must
        // be called *without* clear_ip_transports(): clearing the transports also discards the bind
        // request, and the endpoint then silently listens on a random port (verified by experiment;
        // this is what made U1 unsolvable for two rounds).
        b = b.bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?;
    }
    Ok(b.bind().await?)
}

/// The address we publish in `my_addr`, i.e. "dial me here later".
///
/// Only a process that will keep listening may answer that. A one-shot CLI dials from a
/// throwaway endpoint whose port dies the instant it exits; publishing it made peers store a
/// guaranteed-dead address and overwrote the good one (this is what kept U1 failing even after
/// the daemon-side sweep was fixed). So a CLI advertises nothing, and the record a peer keeps is
/// either a real daemon's listening address or the address a dial provably succeeded on.
/// The address this process may publish as its listening address. Only a daemon sets it (once, at
/// bind time). Every publisher reads THIS - never the socket a particular request happens to come
/// from, because a daemon also opens throwaway sockets to dial out, and publishing one of those is
/// exactly how a real listening port got replaced by a dead ephemeral one.
static ADVERTISED: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn advertised_addr() -> String {
    ADVERTISED.get().cloned().unwrap_or_default()
}

/// The daemon calls this once bound: from then on both requests and replies carry this address.
pub fn publish_listening_address(addr: &str) {
    if !addr.is_empty() {
        let _ = ADVERTISED.set(addr.to_string());
    }
}

/// The address to put in `my_addr` / `peer_addr`. Empty for CLIs (nothing to publish); for a
/// daemon this is the port it bound at startup, regardless of which socket is carrying the
/// current request.
fn my_addr_of(_ep: &Endpoint) -> String {
    advertised_addr()
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<serde_json::Value> {
    let mut l = [0u8; 4];
    r.read_exact(&mut l).await?;
    let n = u32::from_le_bytes(l) as usize;
    if n > 64 * 1024 * 1024 {
        return Err(anyhow!("frame too big"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(serde_json::from_slice(&b)?)
}

/// Server-side reply: attach our listening address so the dialer can record it.
async fn reply<W: AsyncWrite + Unpin>(w: &mut W, mut v: serde_json::Value) -> Result<()> {
    let adv = advertised_addr();
    if !adv.is_empty() {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("peer_addr".to_string(), serde_json::json!(adv));
        }
    }
    write_frame(w, &v).await
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, v: &serde_json::Value) -> Result<()> {
    let b = serde_json::to_vec(v)?;
    w.write_all(&(b.len() as u32).to_le_bytes()).await?;
    w.write_all(&b).await?;
    // iroh's SendStream buffers small writes: without an explicit flush the header frame sits in
    // the local buffer while the peer blocks in read_exact (deadlock: server waits for the frame,
    // client waits for the reply). Found by running the M2 path, not by reading it.
    w.flush().await?;
    Ok(())
}

/// Optional egress throttle so a bulk transfer cannot saturate the uplink (RetroShare has always
/// had this knob). `RSNEXT_MAX_KBPS=<kB/s>`, unset/0 = unlimited.
struct Pacer {
    max_bps: u64,
    sent: u64,
    start: std::time::Instant,
}

impl Pacer {
    fn new() -> Self {
        let max_bps = std::env::var("RSNEXT_MAX_KBPS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|k| k.saturating_mul(1024))
            .unwrap_or(0);
        Self { max_bps, sent: 0, start: std::time::Instant::now() }
    }
    async fn spend(&mut self, n: u64) {
        if self.max_bps == 0 {
            return;
        }
        self.sent += n;
        let want = std::time::Duration::from_secs_f64(self.sent as f64 / self.max_bps as f64);
        let elapsed = self.start.elapsed();
        if want > elapsed {
            tokio::time::sleep(want - elapsed).await;
        }
    }
}

/// Burn the one-time pairing code once it has produced a binding.
fn consume_pairing_code(dir: &str, used_by: &str) -> Result<()> {
    let path = dir_paths(dir)?.join("pairing.json");
    let txt = std::fs::read_to_string(&path).unwrap_or_default();
    let mut j: serde_json::Value = serde_json::from_str(&txt).unwrap_or_else(|_| serde_json::json!({}));
    j["code"] = serde_json::Value::Null;
    j["used_by"] = serde_json::json!(used_by);
    j["used_ts"] = serde_json::json!(chrono_free_now());
    std::fs::write(path, serde_json::to_string_pretty(&j)?)?;
    Ok(())
}

fn chrono_free_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Persist the second half of a friend's identity so a WoT certificate can cover the key the
/// Noise channel actually uses. Must be called once the peers row exists.
fn remember_x25519(store: &Store, fp: &str, peer_x25519: &str) {
    if peer_x25519.is_empty() {
        return;
    }
    let _ = store.set_peer_x25519(fp, peer_x25519);
}

pub async fn peer_gate(store: &Store, dir: &str, fp: &str, pair: &str, eid: &str, my_addr: &str, observed: &str, peer_x25519: &str, events: Option<&broadcast::Sender<serde_json::Value>>) -> Result<bool> {
    // A ban outranks everything below, including the already-bound branch: revoking a friend must
    // stop delivery on the next contact, not stay ineffective because the pairing proof still
    // checks out. Reversal is explicit (unban), never implicit.
    if store.is_banned(fp) {
        println!("[pairing] REFUSED {fp}: banned ({})", store.ban_reason(fp));
        return Ok(false);
    }
    // Which address do we believe?
    // - the peer's *advertised* listening address (`my_addr`): authoritative, but only since every
    //   peer-facing dial goes through the node's own daemon (see main::delegate_plan). A CLI used
    //   to dial from a throwaway endpoint, so its self-reported port died with the process and
    //   poisoned the record.
    // - the observed source address of the connection (recorded in handle_conn): a usable fallback,
    //   but iroh rotates source ports per path, so it can differ from the port the peer listens on.
    // So: advertise wins when present, observed is the floor, and a successful dial writes the
    // address that provably worked (dial()).
    // Asymmetric on purpose: an advertisement always wins; the observed source address is used
    // only to FILL an empty record on first contact (never to overwrite a known-good port).
    let best_addr: &str = if !my_addr.is_empty() { my_addr } else { observed };
    if let Some((stored_eid, _bound)) = store.peer_by_fp(fp) {
        // Already bound. iroh authenticated this connection against the peer's Ed25519 key, so the
        // endpoint id we observe IS cryptographic proof of who this is. Demanding the old pair code
        // here would turn a one-time code into a permanent shared secret: leak it later and you can
        // no longer reach your own friend (that exact fragility bit us during testing).
        if !stored_eid.is_empty() && stored_eid != eid {
            println!("[pairing] REFUSED {fp}: connection authenticated as {eid}, but that fingerprint is bound to {stored_eid}");
            return Ok(false);
        }
        // Refresh ONLY from an advertisement. The observed source address of a connection is the
        // sender's ephemeral socket whenever the contact came from a short-lived CLI, and filling
        // a good advertised port with that garbage is what made friends unreachable after a restart
        // (observed: alice's pinned 7801 overwritten by a throwaway 56670).
        if !my_addr.is_empty() {
            let _ = store.set_peer_addr(fp, my_addr);
        }
        remember_x25519(store, fp, peer_x25519);
        return Ok(true);
    }
    let issued: String = std::fs::read_to_string(dir_paths(dir)?.join("pairing.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|j| j["code"].as_str().map(String::from))
        .unwrap_or_default();
    if !issued.is_empty() && pair == issued {
        store.bind_peer(fp, eid, pair, best_addr)?;
        // AFTER bind_peer: the row must exist or this UPDATE matches nothing.
        remember_x25519(store, fp, peer_x25519);
        consume_pairing_code(dir, fp)?;
        println!("[pairing] bound new peer {fp} via one-time code (code now spent)");
        if let Some(ev) = events {
            emit(ev, serde_json::json!({ "type": "peer-bonded", "fingerprint": fp, "endpoint_id": eid }));
        }
        return Ok(true);
    }
    Ok(false)
}

/// Serve an inbound connection. `store` is the daemon's single shared handle (see store.rs).
///
/// A connection carries MULTIPLE request streams: `forum_sync` does a "sync" leg then a "sync2"
/// leg on the same connection. The first M2 build accepted exactly one stream and then returned,
/// which silently dropped the second leg. So: loop until the peer closes the connection.
/// `observed_addr` is the source address of this QUIC connection as seen by the listening side,
/// which IS the peer's current listening address (its packets come from that socket). Recording it
/// is the only honest way to learn where a friend lives, so nothing here trusts a frame field.
pub async fn handle_conn(dir: String, store: Arc<Store>, conn: iroh::endpoint::Connection, observed_addr: &str, events: broadcast::Sender<serde_json::Value>) -> Result<()> {
    let remote = conn.remote_id().to_string();
    // Fill-only: the observed source port of a connection is the sender's ephemeral socket whenever
    // the contact came from a short-lived CLI. Recording it unconditionally let a throwaway port
    // clobber a friend's real listening port (which is exactly how gate8d kept failing).
    if !observed_addr.is_empty() && store.peer_addr_by_endpoint(&remote).is_none() {
        let _ = store.set_peer_addr_by_endpoint(&remote, observed_addr);
    }
    vlog(format_args!("[daemon] connection up from {remote} at {observed_addr}"));
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(v) => v,
            Err(_) => break, // peer finished/closed the connection: normal end of session
        };
        match handle_request(&dir, &store, &remote, &observed_addr, &mut send, &mut recv, &events).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[req error] {e:#}");
                break;
            }
        }
        send.finish()?;
    }
    Ok(())
}

/// The local fingerprint, for deciding what a requester may receive. Read per call so it cannot
/// go stale if the identity is regenerated in a test harness.
fn my_fp_of(_store: &Store, dir: &str) -> String {
    crate::dir_paths(dir).ok()
        .and_then(|d| std::fs::read_to_string(d.join("identity.json")).ok())
        .and_then(|t| serde_json::from_str::<Identity>(&t).ok())
        .map(|i| i.fingerprint())
        .unwrap_or_default()
}

async fn handle_request(
    dir: &str,
    store: &Store,
    remote: &str,
    observed: &str,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    events: &broadcast::Sender<serde_json::Value>,
) -> Result<()> {
    let req = read_frame(recv).await?;
    let t = req["t"].as_str().unwrap_or("");
    let fp = req["fp"].as_str().unwrap_or("").to_string();
    let pair = req["pair"].as_str().unwrap_or("").to_string();
    let my_addr = req["my_addr"].as_str().unwrap_or("").to_string();
    vlog(format_args!("[daemon] request t={t} from {fp}"));
    if !peer_gate(store, dir, &fp, &pair, remote, &my_addr, observed, req["my_x25519"].as_str().unwrap_or(""), Some(events)).await? {
        reply(send, serde_json::json!({ "ok": false, "why": "not bound / bad code" })).await?;
        return Ok(());
    }
    // Presence is recorded only past this point: "seen" must mean "authenticated contact", and
    // peer_gate has two accept branches, so the caller side covers both with one statement.
    let _ = store.peer_seen(&fp, rsnext_core::presence::unix_now());
    // A peer-supplied file name is untrusted. Refuse a bad one with a proper frame instead of
    // letting the error tear down the connection (the client would then read EOF and panic).
    let raw_name = req["name"].as_str().unwrap_or("");
    let req_name = if raw_name.is_empty() {
        String::new()
    } else {
        match sanitize_name(raw_name) {
            Ok(n) => n,
            Err(e) => {
                reply(send, serde_json::json!({ "ok": false, "why": e.to_string() })).await?;
                return Ok(());
            }
        }
    };
    let name = req_name.as_str();
    match t {
        "msg" => {
            let text = req["text"].as_str().unwrap_or("");
            let seq = store.add_message(&fp, text)?;
            println!("[recv msg seq={seq} from {fp}] {text}");
            emit(events, serde_json::json!({ "type": "chat", "seq": seq, "peer": fp, "peer_fp": remote, "text": text }));
            reply(send, serde_json::json!({ "ok": true, "seq": seq })).await?;
        }
        "file" => {
            let name = sanitize_name(req["name"].as_str().unwrap_or("file.bin"))?;
            let size = req["size"].as_i64().unwrap_or(0);
            let sha = req["sha"].as_str().unwrap_or("").to_string();
            let files = dir_paths(dir)?.join("files");
            std::fs::create_dir_all(&files)?;
            let tmp = files.join(format!("{name}.part"));
            // Two concurrent transfers into one .part interleave and corrupt the file (we hit that
            // as a bogus sha mismatch in the harness). Claim the name exclusively: create_new fails
            // while a transfer is in flight, and the claim is released on success or corruption.
            let lock = files.join(format!("{name}.part.lock"));
            if std::fs::OpenOptions::new().create_new(true).write(true).open(&lock).is_err() {
                reply(send, serde_json::json!({ "ok": false, "why": format!("{name}: a transfer is already in flight") })).await?;
                return Ok(());
            }
            let have = std::fs::metadata(&tmp).map(|m| m.len() as i64).unwrap_or(0).min(size);
            reply(send, serde_json::json!({ "ok": true, "have": have })).await?;
            // append the rest straight into the part file
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&tmp)?;
            let mut got = have;
            let mut hasher = Sha256::new();
            // re-hash existing prefix for final verification
            {
                let mut pf = std::fs::File::open(&tmp)?;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut pf, &mut buf)?;
                hasher.update(&buf);
            }
            let mut chunk = vec![0u8; CHUNK];
            while got < size {
                let want = chunk.len().min((size - got) as usize);
                recv.read_exact(&mut chunk[..want]).await?;
                std::io::Write::write_all(&mut f, &chunk[..want])?;
                hasher.update(&chunk[..want]);
                got += want as i64;
            }
            std::io::Write::flush(&mut f)?;
            drop(f);
            let hexsha = hex::encode(hasher.finalize());
            if hexsha != sha {
                // a corrupt part file must not poison the next resume
                let _ = std::fs::remove_file(&tmp);
                let _ = std::fs::remove_file(&lock);
                reply(send, serde_json::json!({ "ok": false, "why": format!("sha mismatch got {hexsha} want {sha}") })).await?;
            } else {
                std::fs::rename(&tmp, files.join(&name))?;
                let _ = std::fs::remove_file(&lock);
                store.record_file(&name, size, &sha, "files")?;
                println!("[recv file {name} {size}B sha ok]");
                emit(events, serde_json::json!({ "type": "file", "name": name, "size": size, "sha256": sha, "from": fp }));
                reply(send, serde_json::json!({ "ok": true, "path": format!("files/{name}") })).await?;
            }
        }
        "ls" => {
            let files: Vec<serde_json::Value> = store
                .list_shared()
                .into_iter()
                .map(|(name, size, sha, _)| serde_json::json!({ "name": name, "size": size, "sha": sha }))
                .collect();
            reply(send, serde_json::json!({ "ok": true, "files": files })).await?;
        }
        "pull" => {
            let name = sanitize_name(req["name"].as_str().unwrap_or(""))?;
            let have = req["have"].as_i64().unwrap_or(0).max(0);
            let (size, sha, local_path) = store
                .shared_by_name(&name)
                .ok_or_else(|| anyhow!("not shared: {name}"))?;
            let src = if local_path.is_empty() { dir_paths(dir)?.join("files").join(&name) } else { std::path::PathBuf::from(&local_path) };
            let mut f = std::fs::File::open(&src).map_err(|e| anyhow!("open {}: {e}", src.display()))?;
            reply(send, serde_json::json!({ "ok": true, "size": size, "sha": sha, "resume": have.min(size) })).await?;
            if have < size {
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Start(have as u64))?;
            }
            let mut pacer = Pacer::new();
            let mut left = (size - have.max(0).min(size)) as u64;
            let mut buf = vec![0u8; CHUNK];
            while left > 0 {
                let want = (buf.len() as u64).min(left) as usize;
                let n = std::io::Read::read(&mut f, &mut buf[..want])?;
                if n == 0 {
                    return Err(anyhow!("short read on {}", src.display()));
                }
                send.write_all(&buf[..n]).await?;
                pacer.spend(n as u64).await;
                left -= n as u64;
            }
            send.flush().await?;
            println!("[sent file {name} {}..{size}B to {fp}]", have.max(0));
        }
        "sync" => {
            // client sends its leaf hashes; server reports divergence and hands over its whole log
            // (merge is idempotent on (author, seq), so sending everything is both simple and safe)
            let their: Vec<[u8; 32]> = req["leaves"].as_array().map(|a| {
                a.iter().map(|v| {
                    let bytes = hex::decode(v.as_str().unwrap_or("")).unwrap_or_default();
                    let mut arr = [0u8; 32];
                    if bytes.len() == 32 { arr.copy_from_slice(&bytes); }
                    arr
                }).collect()
            }).unwrap_or_default();
            let mine = local_leaves(store);
            let mine_slice: Vec<[u8; 32]> = mine.iter().map(|(_, h)| *h).collect();
            let divg = first_divergence(&mine_slice, &their);
            // only channels this peer may receive; see roots_for() for why the roots are filtered too
            let allowed: Vec<(String, i64, String, String, i64)> = store
                .posts_everywhere()
                .into_iter()
                .filter(|(channel, _, _, _, _)| store.may_send_channel(channel, &fp, &my_fp_of(store, dir)))
                .collect();
            let rows: Vec<serde_json::Value> = allowed.into_iter().map(|(channel, seq, author, body, ts)| serde_json::json!({ "channel": channel, "seq": seq, "author": author, "body": body, "ts": ts })).collect();
            let roots: std::collections::HashMap<String, String> = channel_roots(store)
                .into_iter()
                .filter(|(ch, _)| store.may_send_channel(ch, &fp, &my_fp_of(store, dir)))
                .collect();
            // Channel definitions travel with their posts in BOTH directions. The pull side has
            // always read resp["channels"], but this reply never included them, so a peer applied
            // posts into a channel it had never heard of: the merkle root still converged (roots
            // are computed from posts) while the channel list stayed empty - a divergence between
            // "the data agrees" and "the UI can show it", which no root assertion can catch.
            // Channel definitions are as sensitive as the posts: the name alone says a private
            // channel exists, `created_by` says who runs it.
            let chans: Vec<serde_json::Value> = store
                .channels()
                .into_iter()
                .filter(|(name, _, _, _)| store.may_send_channel(name, &fp, &my_fp_of(store, dir)))
                .map(|(name, by, created, desc)| serde_json::json!({ "name": name, "created_by": by, "created_ts": created, "desc": desc }))
                .collect();
            reply(send, serde_json::json!({ "ok": true, "divg": divg, "rows": rows, "roots": roots, "channels": chans, "root": roots.get("general").cloned().unwrap_or_default() })).await?;
            // second leg: client may push its rows via "sync2"
        }
        "sync2" => {
            let incoming_rows = req["rows"].as_array().cloned().unwrap_or_default();
            let mut applied = 0usize;
            let my = my_fp_of(store, dir);
            for r in incoming_rows {
                let channel = r["channel"].as_str().unwrap_or("general").to_string();
                // Defence in depth: an outsider must not be able to write into a channel we marked
                // private by pushing their own copy of it at us.
                if !store.may_send_channel(&channel, &fp, &my) {
                    continue;
                }
                if store.insert_post_row_in(&channel, r["seq"].as_i64().unwrap_or(0), r["author"].as_str().unwrap_or("?"), r["body"].as_str().unwrap_or(""), r["ts"].as_i64().unwrap_or(0)).is_ok() {
                    applied += 1;
                }
            }
            // channels travel with their posts, otherwise the peer can never render them
            for (name, by, created, desc) in req["channels"].as_array().cloned().unwrap_or_default()
                .into_iter()
                .filter_map(|c| Some((c["name"].as_str()?.to_string(), c["created_by"].as_str()?.to_string(), c["created_ts"].as_i64().unwrap_or(0), c["desc"].as_str().unwrap_or("").to_string()))) {
                let _ = store.import_channel(&name, &by, created, &desc);
            }
            // the ack goes back to the pushing peer, so it is scoped to that peer as well
            let roots: std::collections::HashMap<String, String> = channel_roots(store)
                .into_iter()
                .filter(|(ch, _)| store.may_send_channel(ch, &fp, &my_fp_of(store, dir)))
                .collect();
            if store.post_count() > 0 {
                emit(events, serde_json::json!({ "type": "forum", "posts": store.post_count(), "root": roots.get("general").cloned().unwrap_or_default(), "roots": roots, "with": fp, "applied": applied }));
            }
            reply(send, serde_json::json!({ "ok": true, "root": roots.get("general").cloned().unwrap_or_default(), "roots": roots, "applied": applied })).await?;
        }
        "wot" => {
            // Exchange certificates with a bound friend. We only accept signatures that verify
            // against the issuer key they claim, so a peer cannot mint trust for somebody else.
            let mine: Vec<serde_json::Value> = store.certs().into_iter().map(|c| serde_json::json!({
                "subject_fp": c.cert.subject_fp, "issuer_fp": c.issuer_fp, "issuer_ed": c.issuer_ed,
                "subject_ed": c.cert.subject_ed, "subject_x25519": c.cert.subject_x25519, "ts": c.cert.ts, "sig": c.sig
            })).collect();
            let mut accepted = 0usize;
            let mut rejected = 0usize;
            for v in req["certs"].as_array().cloned().unwrap_or_default() {
                let cert = rsnext_core::wot::CertInfo {
                    subject_fp: v["subject_fp"].as_str().unwrap_or("").to_string(),
                    subject_ed: v["subject_ed"].as_str().unwrap_or("").to_string(),
                    subject_x25519: v["subject_x25519"].as_str().unwrap_or("").to_string(),
                    ts: v["ts"].as_i64().unwrap_or(0),
                };
                let certw = rsnext_core::wot::Cert {
                    issuer_fp: v["issuer_fp"].as_str().unwrap_or("").to_string(),
                    issuer_ed: v["issuer_ed"].as_str().unwrap_or("").to_string(),
                    sig: v["sig"].as_str().unwrap_or("").to_string(),
                    cert,
                };
                if rsnext_core::wot::verify_cert(&certw.issuer_ed, &certw.cert, &certw.sig).is_err() {
                    rejected += 1;
                    continue;
                }
                if store.put_cert(&certw).is_ok() {
                    accepted += 1;
                }
            }
            if rejected > 0 {
                println!("[wot] {fp} forwarded {rejected} certificate(s) that failed verification - dropped");
            }
            reply(send, serde_json::json!({ "ok": true, "certs": mine, "accepted": accepted })).await?;
        }
        "peer-where" => {
            // Friend-assisted rendezvous: "my record of X is stale - where do you see X now?"
            // Answered only when BOTH the asker and the target are our own bound friends;
            // otherwise any stranger that connects could use this node as an address oracle.
            let target = req["target"].as_str().unwrap_or("").to_string();
            let addrs = rendezvous_reply(store, &fp, &target);
            vlog(format_args!("[rendezvous] {fp} asked about {target} -> {} addr(s)", addrs.len()));
            reply(send, serde_json::json!({ "ok": true, "addrs": addrs, "asker_known": store.is_bound(&fp) })).await?;
        }
        "hi" => {
            // a peer announcing itself after (re)starting, or a heartbeat. peer_gate already
            // refreshed this caller's `addr` row and recorded the contact on the way in, so the
            // only extra job here is to adopt what they say about themselves.
            if let Some(state) = req["state"].as_str() {
                let idle = req["idle"].as_i64().unwrap_or(0);
                let _ = store.declare(&fp, state, idle, rsnext_core::presence::unix_now());
                let _ = events.send(serde_json::json!({ "type": "presence", "peer": fp, "state": state, "idle": idle }));
            }
            reply(send, serde_json::json!({ "ok": true, "saw": fp, "my_addr": req["my_addr"].clone() })).await?;
        }
        _ => {
            reply(send, serde_json::json!({ "ok": false, "why": "unknown t" })).await?;
        }
    }
    Ok(())
}

/// reject path traversal in any peer-supplied file name
fn sanitize_name(raw: &str) -> Result<String> {
    let n = raw.trim();
    if n.is_empty() || n.contains('/') || n.contains('\\') || n.contains("..") || n.starts_with('.') {
        return Err(anyhow!("unsafe file name: {raw:?}"));
    }
    Ok(n.to_string())
}

/// Root per channel - the unit of convergence once channels exist.
pub fn channel_roots(store: &Store) -> std::collections::BTreeMap<String, String> {
    let mut map: std::collections::BTreeMap<String, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
    for (channel, seq, author, body, ts) in store.posts_everywhere() {
        map.entry(channel).or_default().push(leaf_hash(seq, &author, &body, ts));
    }
    // every known channel must appear, even an empty one, so peers agree on the set
    for (name, _, _, _) in store.channels() {
        map.entry(name).or_default();
    }
    map.entry("general".to_string()).or_default();
    map.into_iter().map(|(k, v)| (k, hex::encode(merkle_root(&v)))).collect()
}

pub fn local_leaves(store: &Store) -> Vec<(i64, [u8; 32])> {
    store.posts_all().into_iter().map(|(seq, author, body, ts)| (seq, leaf_hash(seq, &author, &body, ts))).collect()
}

pub async fn daemon(dir: String, port: u16, store: Arc<Store>, events: broadcast::Sender<serde_json::Value>) -> Result<()> {
    let endpoint = build_endpoint_on(&dir, port).await?;
    let id = endpoint.id();
    println!("iroh daemon up");
    println!("endpoint_id(hex) = {id}");
    let addrs: Vec<String> = endpoint.addr().ip_addrs().copied().map(|a| a.to_string()).collect();
    publish_listening_address(addrs.first().map(String::as_str).unwrap_or(""));
    // `local_addr` stays the first advertised address: it is what invites, the gates and
    // the UI dial. The full list is printed alongside for diagnosis (U1).
    println!("local_addr        = {}", addrs.first().cloned().unwrap_or_default());
    if addrs.len() > 1 {
        println!("ip_addrs (all)     = {}", addrs.join(", "));
    }
    vlog(format_args!("[daemon] listening, sharing {} file(s)", store.list_shared().len()));
    let my_fp = std::fs::read_to_string(dir_paths(&dir)?.join("identity.json")).ok()
        .and_then(|t| serde_json::from_str::<Identity>(&t).ok())
        .map(|i| i.fingerprint())
        .unwrap_or_default();
    // Opt-in heartbeat. The two freshness properties we want - "this friend is still up" and "they
    // know my current listening address" - both ride the already-gated `hi`, so the timer merely
    // repeats that broadcast. Off unless RSNEXT_STATUS_TICK=<secs>: dialling every friend on a
    // timer is real background traffic, and it has not been measured on lossy links yet.
    if let Some(secs) = std::env::var("RSNEXT_STATUS_TICK").ok().and_then(|s| s.parse::<u64>().ok()).filter(|s| *s > 0) {
        let ep = endpoint.clone();
        let st = store.clone();
        let fp = my_fp.clone();
        let d = dir.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                let (ok, bad) = status_round(&ep, &st, &d, &fp).await;
                vlog(format_args!("[heartbeat] refreshed {ok}, unreachable {bad}"));
            }
        });
        println!("[heartbeat] status tick every {secs}s");
    }
    // One-sided restart is the common case: the friend stayed up while we got a new UDP port.
    // Shout first, so their record of us is current before they try to reach us. Whoever we cannot
    // reach is reported with the concrete next step (root cause tracked as U1 in PLAN.md).
    {
        let st = store.clone();
        let fp = my_fp.clone();
        let ep = endpoint.clone();
        let advertised = my_addr_of(&endpoint);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            for (peer, eid, pair, addr, _) in st.peers() {
                if peer == fp || eid.is_empty() {
                    continue;
                }
                if addr.is_empty() {
                    println!("[startup] {peer} has no known address yet; it refreshes when they contact us");
                    continue;
                }
                match say_hi_with(&ep, &eid, &addr, &fp, &pair).await {
                    Ok(_) => println!("[startup] hi {peer} @ {addr} ok (they now hold our listening address {advertised})"),
                    Err(first) => {
                        // Our own record of them is stale too. Anyone we can still reach knows more
                        // than we do, so ask each reachable friend where they see this peer, and
                        // hello them at the answer. One reachable friend is enough to rebuild the
                        // whole local view - that is the point of friend-assisted rendezvous.
                        let mut healed = false;
                        for (ofp, oeid, opair, oaddr, _) in st.peers() {
                            if ofp == peer || oeid.is_empty() || oaddr.is_empty() {
                                continue;
                            }
                            let Ok(cands) = ask_where_with(&ep, &st, &fp, &oeid, &oaddr, &eid).await else { continue };
                            for c in cands {
                                if c == addr {
                                    continue;
                                }
                                if say_hi_with(&ep, &eid, &c, &fp, &pair).await.is_ok() {
                                    let _ = st.set_peer_addr_by_endpoint(&eid, &c);
                                    println!("[startup] {peer} was unreachable at {addr}; {ofp} pointed us at {c} and it answered (record repaired)");
                                    healed = true;
                                    break;
                                }
                            }
                            if healed {
                                break;
                            }
                        }
                        if !healed {
                            eprintln!("[startup] {peer} @ {addr} unreachable: {first:#} and no friend could place them (ask for a fresh invite, or: sync-all <dir> {peer}=<ip:port>)");
                        }
                    }
                }
            }
        });
    }
    let _ = port; // see U1: iroh 1.4.2 exposes no working way to pin this socket's port
    while let Some(incoming) = endpoint.accept().await {
        // read the source address BEFORE accept(): Incoming::accept() consumes it
        let observed = match incoming.remote_addr() {
            iroh::endpoint::IncomingAddr::Ip(a) => a.to_string(),
            other => {
                vlog(format_args!("[daemon] non-IP incoming {other:?}"));
                String::new()
            }
        };
        let accepting = match incoming.accept() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[daemon] reject: {e:?}");
                continue;
            }
        };
        let d = dir.clone();
        let store = store.clone();
        let evtx = events.clone();
        tokio::spawn(async move {
            let observed = observed.clone();
            let conn = match accepting.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("[accept error] {e:?}");
                    return;
                }
            };
            if let Err(e) = handle_conn(d, store, conn, &observed, evtx.clone()).await {
                eprintln!("[conn error] {e:#}");
            }
        });
    }
    Ok(())
}

/// Build a client endpoint and connect to `addr`.
///
/// The `Endpoint` is returned alongside the `Connection` ON PURPOSE: an iroh `Endpoint` owns the
/// UDP socket and the IO driver task, so dropping it at the end of this function would leave a
/// live-looking `Connection` with no transport behind it. That failure is silent and nasty:
/// `open_bi()` and `write_all()`+`flush()` return Ok locally, the peer never receives a single
/// stream frame, and its `accept_bi()` dies on the idle timeout. Callers must keep the returned
/// endpoint alive for as long as they use the connection (`let (_ep, conn) = dial(..)`).
pub async fn dial(dir: &str, id_hex: &str, addr_s: &str) -> Result<(Endpoint, iroh::endpoint::Connection)> {
    let endpoint = build_endpoint(dir).await?;
    let ib = hex::decode(id_hex)?;
    let arr: [u8; 32] = ib.try_into().map_err(|_| anyhow!("id len"))?;
    let eid = EndpointId::from_bytes(&arr).map_err(|_| anyhow!("bad id"))?;
    let sa: SocketAddr = addr_s.parse()?;
    let addr = EndpointAddr::new(eid).with_ip_addr(sa);
    let conn = endpoint.connect(addr, ALPN).await.map_err(|e| {
        anyhow!("connect {addr_s} failed: {e:?}")
    })?;
    // A dial that *succeeded* is proof the address works right now, so persist it against the
    // peer's endpoint id. Cheap, and it is what lets `sync-all` redial friends after a restart.
    if let Ok(store) = Store::open(&dir_paths(dir)?.join("rsnext.db").to_string_lossy()) {
        let _ = store.set_peer_addr_by_endpoint(id_hex, addr_s);
    }
    Ok((endpoint, conn))
}

async fn client_hello(conn: &iroh::endpoint::Connection, req: serde_json::Value) -> Result<serde_json::Value> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(&mut send, &req).await?;
    let resp = read_frame(&mut recv).await?;
    send.finish()?;
    Ok(resp)
}

/// one frame pair with `fp`/`pair`/`my_addr` filled in
async fn call(dir: &str, ep: &Endpoint, conn: &iroh::endpoint::Connection, mut req: serde_json::Value, fp: &str, pair: &str) -> Result<serde_json::Value> {
    req["fp"] = serde_json::json!(fp);
    req["pair"] = serde_json::json!(pair);
    req["my_addr"] = serde_json::json!(my_addr_of(ep));
    req["my_x25519"] = serde_json::json!(my_x25519());
    let resp = client_hello(conn, req).await?;
    // Learn the peer's listening address from its own reply - the only direction a CLI-initiated
    // contact could previously never cover.
    if let Some(adv) = resp["peer_addr"].as_str().filter(|a| !a.is_empty()) {
        let rid = conn.remote_id().to_string();
        if let Ok(store) = Store::open(&dir_paths(dir)?.join("rsnext.db").to_string_lossy()) {
            let _ = store.set_peer_addr_by_endpoint(&rid, adv);
        }
    }
    Ok(resp)
}

pub async fn send_msg(dir: String, id_hex: String, addr: String, text: String, fp: String, pair: String) -> Result<serde_json::Value> {
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let resp = call(&dir, &endpoint, &conn, serde_json::json!({ "t": "msg", "text": text }), &fp, &pair).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer refused: {}", resp["why"].as_str().unwrap_or("unknown")));
    }
    Ok(resp)
}

/// Ask a peer what it offers. Returns the list so callers (CLI, control plane, UI) get the data
/// instead of only a line printed somewhere; a refusal is an error, never a silent ok.
pub async fn list_offered(dir: String, id_hex: String, addr: String, fp: String, pair: String) -> Result<Vec<serde_json::Value>> {
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let resp = call(&dir, &endpoint, &conn, serde_json::json!({ "t": "ls" }), &fp, &pair).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer refused: {resp}"));
    }
    Ok(resp["files"].as_array().cloned().unwrap_or_default())
}

pub async fn push_file(dir: String, id_hex: String, addr: String, path: String, fp: String, pair: String) -> Result<serde_json::Value> {
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let data = std::fs::read(&path)?;
    let sha = hex::encode(Sha256::digest(&data));
    let name = std::path::Path::new(&path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or("file.bin".into());
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(&mut send, &serde_json::json!({
        "t": "file", "fp": fp, "pair": pair, "my_addr": my_addr_of(&endpoint), "my_x25519": my_x25519(),
        "name": name, "size": data.len() as i64, "sha": sha
    })).await?;
    let head = read_frame(&mut recv).await?;
    // Honour the peer's verdict BEFORE streaming bytes: it refuses a name that is already being
    // transferred. Skipping this check turned a clear, actionable refusal into an opaque
    // "sending stopped by peer" once our writes hit the closed stream.
    if head["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer refused {name}: {}", head["why"].as_str().unwrap_or("?")));
    }
    let have = head["have"].as_i64().unwrap_or(0).max(0) as usize;
    println!("server has {have}/{} bytes — sending remainder (resume)", data.len());
    let mut pacer = Pacer::new();
    let mut off = have;
    while off < data.len() {
        let n = CHUNK.min(data.len() - off);
        send.write_all(&data[off..off + n]).await?;
        pacer.spend(n as u64).await;
        off += n;
    }
    send.flush().await?;
    send.finish()?;
    let resp = read_frame(&mut recv).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer rejected the file: {}", resp["why"].as_str().unwrap_or("?")));
    }
    println!("file response: {resp}");
    Ok(resp)
}

/// download a shared file from a peer, resuming from our own `.part` if one exists
pub async fn pull_file(dir: String, id_hex: String, addr: String, name: String, fp: String, pair: String) -> Result<serde_json::Value> {
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let files = dir_paths(&dir)?.join("files");
    std::fs::create_dir_all(&files)?;
    let tmp = files.join(format!("{name}.part"));
    let have = std::fs::metadata(&tmp).map(|m| m.len() as i64).unwrap_or(0);
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(&mut send, &serde_json::json!({
        "t": "pull", "fp": fp, "pair": pair, "my_addr": my_addr_of(&endpoint), "my_x25519": my_x25519(), "name": name, "have": have
    })).await?;
    let head = read_frame(&mut recv).await?;
    if head["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer refused: {}", head["why"].as_str().unwrap_or("?")));
    }
    let size = head["size"].as_i64().unwrap_or(0);
    let sha = head["sha"].as_str().unwrap_or("").to_string();
    let resume = head["resume"].as_i64().unwrap_or(0).max(0);
    println!("peer offers {name} {size}B; resuming from {resume}B");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&tmp)?;
    let mut hasher = Sha256::new();
    {
        let mut pf = std::fs::File::open(&tmp)?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut pf, &mut buf)?;
        hasher.update(&buf);
    }
    let mut got = std::fs::metadata(&tmp).map(|m| m.len() as i64).unwrap_or(0).min(size);
    let mut buf = vec![0u8; CHUNK];
    while got < size {
        let want = buf.len().min((size - got) as usize);
        // iroh's RecvStream::read gives Ok(None) at end-of-stream (it is not AsyncRead::read)
        let Some(n) = recv.read(&mut buf[..want]).await? else { break };
        std::io::Write::write_all(&mut f, &buf[..n])?;
        hasher.update(&buf[..n]);
        got += n as i64;
    }
    std::io::Write::flush(&mut f)?;
    drop(f);
    let hexsha = hex::encode(hasher.finalize());
    if hexsha != sha {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("sha mismatch got {hexsha} want {sha} (part file discarded)"));
    }
    std::fs::rename(&tmp, files.join(&name))?;
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    store.record_file(&name, size, &sha, "files")?;
    println!("saved files/{name} (sha ok, {size}B)");
    Ok(serde_json::json!({ "name": name, "size": size, "sha256": sha }))
}

pub async fn forum_sync(dir: String, id_hex: String, addr: String, fp: String, pair: String) -> Result<()> {
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let leaves: Vec<String> = local_leaves(&store).into_iter().map(|(_, h)| hex::encode(h)).collect();
    let resp = call(&dir, &endpoint, &conn, serde_json::json!({ "t": "sync", "leaves": leaves }), &fp, &pair).await?;
    let mut got = 0usize;
    for r in resp["rows"].as_array().cloned().unwrap_or_default() {
        let channel = r["channel"].as_str().unwrap_or("general").to_string();
        if store.insert_post_row_in(&channel, r["seq"].as_i64().unwrap_or(0), r["author"].as_str().unwrap_or("?"), r["body"].as_str().unwrap_or(""), r["ts"].as_i64().unwrap_or(0)).is_ok() {
            got += 1;
        }
    }
    for c in resp["channels"].as_array().cloned().unwrap_or_default() {
        if let (Some(n), Some(b)) = (c["name"].as_str(), c["created_by"].as_str()) {
            let _ = store.import_channel(n, b, c["created_ts"].as_i64().unwrap_or(0), c["desc"].as_str().unwrap_or(""));
        }
    }
    // second leg on the SAME connection: push our whole log; receiver ignores duplicates
    let mine: Vec<serde_json::Value> = store.posts_everywhere().into_iter().map(|(channel, seq, author, body, ts)| serde_json::json!({ "channel": channel, "seq": seq, "author": author, "body": body, "ts": ts })).collect();
    let chans: Vec<serde_json::Value> = store.channels().into_iter().map(|(name, by, created, desc)| serde_json::json!({ "name": name, "created_by": by, "created_ts": created, "desc": desc })).collect();
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(&mut send, &serde_json::json!({ "t": "sync2", "fp": fp, "pair": pair, "my_addr": my_addr_of(&endpoint), "rows": mine, "channels": chans })).await?;
    let ack = read_frame(&mut recv).await?;
    send.finish()?;
    let after = local_leaves(&store);
    let slice: Vec<[u8; 32]> = after.iter().map(|(_, h)| *h).collect();
    let my_root = hex::encode(merkle_root(&slice));
    let my_roots = channel_roots(&store);
    let peer_roots = ack["roots"].clone();
    println!("pulled {got} rows; local roots {} (posts={}); peer after our push: {}", serde_json::to_string(&my_roots).unwrap_or_default(), store.post_count(), peer_roots);
    let same = match peer_roots.as_object() {
        Some(m) => m.iter().all(|(k, v)| my_roots.get(k).map(|x| x == v.as_str().unwrap_or("")).unwrap_or(false)),
        None => ack["root"].as_str() == Some(my_root.as_str()),
    };
    if same {
        println!("CONVERGED: both replicas hold the same log");
    }
    Ok(())
}

/// announce ourselves to one bound peer so it refreshes our address (used after a restart)
pub async fn say_hi(dir: &str, id_hex: &str, addr: &str, fp: &str, pair: &str) -> Result<serde_json::Value> {
    let (endpoint, conn) = dial(dir, id_hex, addr).await?;
    client_hello(&conn, serde_json::json!({ "t": "hi", "fp": fp, "pair": pair, "my_addr": my_addr_of(&endpoint), "my_x25519": my_x25519() })).await
}

/// Bring this node up to date with every bound peer (M2 "上线自动增量同步").
///
/// `overrides` lets the operator state "peer X is reachable at Y" explicitly. That matters because
/// with relays off and an ephemeral UDP port, a peer that restarted has a *new* address and neither
/// side can discover it alone — the stored `addr` is whatever it last advertised. One successful
/// contact (from either direction) makes `my_addr` refresh keep both rows current from then on.
pub async fn sync_all(dir: String, mine_fp: String, overrides: Vec<(String, String)>) -> Result<()> {
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    let peers = store.peers();
    println!("{} bound peer(s)", peers.len());
    for (fp, eid, pair, addr, _) in peers {
        if fp == mine_fp {
            continue;
        }
        let target = overrides.iter().find(|(k, _)| *k == fp).map(|(_, v)| v.clone()).or(if addr.is_empty() { None } else { Some(addr.clone()) });
        let Some(target) = target else {
            println!("  skip {fp}: no address (pass fp=ip:port to override)");
            continue;
        };
        print!("  sync {fp} via {target}: ");
        match forum_sync(dir.clone(), eid.clone(), target, mine_fp.clone(), pair).await {
            Ok(()) => {}
            Err(e) => println!("unreachable ({e:#})"),
        }
    }
    Ok(())
}

/// The rendezvous authorization rule, kept separate from the wire so it can be unit tested:
/// reveal a friend's current address only to another friend of ours. A node must never become a
/// public directory of who lives where - that is exactly the metadata leak this project avoids.
pub fn rendezvous_reply(store: &Store, asker_fp: &str, target_eid: &str) -> Vec<String> {
    if !store.is_bound(asker_fp) {
        return Vec::new();
    }
    store.peers().into_iter().filter(|(_, eid, _, addr, _)| *eid == target_eid && !addr.is_empty()).map(|(_, _, _, addr, _)| addr).collect()
}

/// Connect to `addr` using an endpoint we already own. This matters: a node's *listening*
/// endpoint is the only socket a peer can dial back to, so anything the daemon sends out must come
/// from it. Dialing from a freshly bound throwaway endpoint makes the peer record a port that dies
/// with the request - which is precisely what kept U1 alive after the startup sweep was added.
pub async fn dial_with(endpoint: &Endpoint, id_hex: &str, addr_s: &str) -> Result<iroh::endpoint::Connection> {
    let ib = hex::decode(id_hex)?;
    let arr: [u8; 32] = ib.try_into().map_err(|_| anyhow!("id len"))?;
    let eid = EndpointId::from_bytes(&arr).map_err(|_| anyhow!("bad id"))?;
    let sa: SocketAddr = addr_s.parse()?;
    let conn = endpoint.connect(EndpointAddr::new(eid).with_ip_addr(sa), ALPN).await
        .map_err(|e| anyhow!("connect {addr_s} failed: {e:?}"))?;
    Ok(conn)
}

/// `say_hi` from an endpoint we already own (daemon path).
/// The state put on the wire. A plain static because it is rewritten every round, not set once.
static SELF_STATUS: std::sync::Mutex<(String, i64)> = std::sync::Mutex::new((String::new(), 0));

pub fn set_self_status(state: &str, idle: i64) {
    if let Ok(mut g) = SELF_STATUS.lock() {
        *g = (state.to_string(), idle);
    }
}

fn self_status_of(_ep: &Endpoint) -> (String, i64) {
    match SELF_STATUS.lock() {
        Ok(g) if !g.0.is_empty() => g.clone(),
        _ => ("online".to_string(), 0),
    }
}

/// What we announce about ourselves. Read from the data dir on every broadcast so a change takes
/// effect on the next tick without restarting the node; absent means "online, not idle".
pub fn self_status(dir: &str) -> (String, i64) {
    std::fs::read_to_string(dir_paths(dir).unwrap_or_default().join("status.json")).ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .map(|v| (v["state"].as_str().unwrap_or("online").to_string(), v["idle"].as_i64().unwrap_or(0)))
        .unwrap_or_else(|| ("online".to_string(), 0))
}

/// A heartbeat round: re-broadcast `hi` to every friend we have an address for. Reusing `hi` means
/// the receiver refreshes address, presence and declared state through one already-gated path.
pub async fn status_round(endpoint: &Endpoint, store: &Store, dir: &str, my_fp: &str) -> (usize, usize) {
    // read the declaration each round so `rsnext-node status` takes effect without a restart
    let (state, idle) = self_status(dir);
    set_self_status(&state, idle);
    let mut ok = 0usize;
    let mut unreachable = 0usize;
    for (peer, eid, pair, addr, _) in store.peers() {
        if peer == my_fp || eid.is_empty() || addr.is_empty() {
            continue;
        }
        match say_hi_with(endpoint, &eid, &addr, my_fp, &pair).await {
            Ok(_) => ok += 1,
            Err(_) => unreachable += 1, // stale address: the startup sweep does the healing, not the tick
        }
    }
    (ok, unreachable)
}

pub async fn say_hi_with(endpoint: &Endpoint, target_eid: &str, target_addr: &str, my_fp: &str, pair: &str) -> Result<serde_json::Value> {
    let conn = dial_with(endpoint, target_eid, target_addr).await?;
    let (st, idle) = self_status_of(endpoint);
    client_hello(&conn, serde_json::json!({ "t": "hi", "fp": my_fp, "pair": pair, "state": st, "idle": idle, "my_addr": my_addr_of(endpoint), "my_x25519": my_x25519() })).await
}

/// `ask_where` from an endpoint we already own (daemon path).
pub async fn ask_where_with(endpoint: &Endpoint, store: &Store, my_fp: &str, relay_eid: &str, relay_addr: &str, target_hex: &str) -> Result<Vec<String>> {
    let (_eid, pair) = store.peer_by_eid(relay_eid).ok_or_else(|| anyhow!("relay {relay_eid} is not bound"))?;
    let conn = dial_with(endpoint, relay_eid, relay_addr).await?;
    let mine = my_fp;
    let resp = client_hello(&conn, serde_json::json!({ "t": "peer-where", "target": target_hex, "fp": mine, "pair": pair, "my_addr": my_addr_of(endpoint), "my_x25519": my_x25519() })).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("relay refused: {resp}"));
    }
    Ok(resp["addrs"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|a| a.as_str().map(String::from)).collect())
}

/// Ask one reachable friend "where do you see endpoint `target_hex` right now?".
pub async fn ask_where(dir: &str, relay_eid: &str, relay_addr: &str, relay_pair: &str, target_hex: &str) -> Result<Vec<String>> {
    let (endpoint, conn) = dial(dir, relay_eid, relay_addr).await?;
    let mine = fp_self(dir)?;
    let resp = call(dir, &endpoint, &conn, serde_json::json!({ "t": "peer-where", "target": target_hex }), &mine, relay_pair).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("relay refused the rendezvous query: {resp}"));
    }
    Ok(resp["addrs"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|a| a.as_str().map(String::from)).collect())
}

pub(crate) fn fp_self(dir: &str) -> Result<String> {
    let raw = std::fs::read_to_string(dir_paths(dir)?.join("identity.json"))?;
    Ok(serde_json::from_str::<Identity>(&raw)?.fingerprint())
}

/// Swap certificates with one friend: send ours, absorb theirs (each one is verified against the
/// issuer key it claims *before* it is stored, so a peer cannot launder trust for somebody else).
pub async fn wot_exchange(dir: String, id_hex: String, addr: String, fp: String, pair: String) -> Result<usize> {
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    let pack = |c: &rsnext_core::wot::Cert| serde_json::json!({
        "subject_fp": c.cert.subject_fp, "issuer_fp": c.issuer_fp, "issuer_ed": c.issuer_ed,
        "subject_ed": c.cert.subject_ed, "subject_x25519": c.cert.subject_x25519, "ts": c.cert.ts, "sig": c.sig });
    let mine: Vec<serde_json::Value> = store.certs().iter().map(pack).collect();
    let (endpoint, conn) = dial(&dir, &id_hex, &addr).await?;
    let resp = call(&dir, &endpoint, &conn, serde_json::json!({ "t": "wot", "certs": mine }), &fp, &pair).await?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(anyhow!("peer refused the certificate exchange: {resp}"));
    }
    let mut accepted = 0usize;
    for v in resp["certs"].as_array().cloned().unwrap_or_default() {
        let cert = rsnext_core::wot::CertInfo {
            subject_fp: v["subject_fp"].as_str().unwrap_or("").to_string(),
            subject_ed: v["subject_ed"].as_str().unwrap_or("").to_string(),
            subject_x25519: v["subject_x25519"].as_str().unwrap_or("").to_string(),
            ts: v["ts"].as_i64().unwrap_or(0),
        };
        let certw = rsnext_core::wot::Cert {
            issuer_fp: v["issuer_fp"].as_str().unwrap_or("").to_string(),
            issuer_ed: v["issuer_ed"].as_str().unwrap_or("").to_string(),
            sig: v["sig"].as_str().unwrap_or("").to_string(),
            cert,
        };
        if rsnext_core::wot::verify_cert(&certw.issuer_ed, &certw.cert, &certw.sig).is_err() {
            println!("[wot] dropped a certificate from {fp} that did not verify (issuer claimed {})", certw.issuer_fp);
            continue;
        }
        if store.put_cert(&certw).is_ok() {
            accepted += 1;
        }
    }
    println!("[wot] sent {}, peer offered {}, accepted {}", mine.len(), resp["certs"].as_array().map(|a| a.len()).unwrap_or(0), accepted);
    Ok(accepted)
}

/// Is this endpoint id actually reachable at `addr` right now? A successful connection is the
/// only honest test - and dial() writes the working address back into our record as a side effect.
pub async fn probe(dir: &str, eid_hex: &str, addr: &str) -> Result<()> {
    let (_endpoint, _conn) = dial(dir, eid_hex, addr).await?;
    Ok(())
}

/// Friend-assisted address resolution for one peer (U1 mitigation without any infrastructure).
///
/// Order: probe our own record; if it is dead, ask each reachable mutual friend and probe what
/// they report. The winning address is written back, so the next dial is direct.
pub async fn find_peer(dir: String, target_fp: String) -> Result<Option<String>> {
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    let (target_eid, _pair) = store.peer_by_fp(&target_fp).ok_or_else(|| anyhow!("{target_fp} is not a bound friend"))?;
    if let Some(a) = store.peer_addr_by_endpoint(&target_eid) {
        match probe(&dir, &target_eid, &a).await {
            Ok(()) => {
                println!("[find] {target_fp}: our own record {a} still works");
                return Ok(Some(a));
            }
            Err(_) => println!("[find] {target_fp}: our record {a} is dead, asking friends..."),
        }
    } else {
        println!("[find] {target_fp}: no address on record, asking friends...");
    }
    for (fp, eid, pair, addr, _) in store.peers() {
        if fp == target_fp || eid.is_empty() || addr.is_empty() {
            continue;
        }
        match ask_where(&dir, &eid, &addr, &pair, &target_eid).await {
            Ok(list) if !list.is_empty() => {
                for candidate in list {
                    if probe(&dir, &target_eid, &candidate).await.is_ok() {
                        println!("[find] {fp} reported {target_fp} at {candidate} and it answered");
                        store.set_peer_addr_by_endpoint(&target_eid, &candidate)?;
                        return Ok(Some(candidate));
                    }
                }
                println!("[find] {fp}'s suggestions were all stale too");
            }
            Ok(_) => println!("[find] {fp} does not know {target_fp} (not a mutual friend, or never contacted us)"),
            Err(e) => println!("[find] could not ask {fp}: {e:#}"),
        }
    }
    Ok(None)
}


// ---- batch transfer ---------------------------------------------------------------------------

/// What to do about one offered file. The decision is split from the transfer because the decision
/// is where the bugs live (rename-dedupe, stale-part bookkeeping) and it must be testable without
/// a network, a peer, or a filesystem.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PullAction {
    /// we already hold this exact content under this exact name
    Have,
    /// identical content is present under another name: copy it, never re-download it
    Dedup { from: String },
    /// a `.part` exists for a name we do not hold complete - continue it
    Resume { from: i64 },
    /// this name holds *different* content locally; that bytes cannot be reused, so discard and refetch
    Restart,
    /// nothing local, start from zero
    Fetch,
}

/// `by_sha` maps a content hash to a name we hold complete; `known_sha` is what we recorded for
/// this exact name; `name_present` says whether those bytes are actually still on disk; `part` is
/// the byte count sitting in `<name>.part`.
///
/// `name_present` exists because the database is only an index: a row whose file was deleted must
/// not be reported as "have it", or the library silently keeps a hole forever.
///
/// Note what is deliberately NOT here: a `.part` whose complete file is absent is resumed even
/// though we cannot know which revision its bytes came from. That is safe because `pull_file`
/// hashes the pre-existing part before appending and discards it on mismatch - correctness is
/// enforced by the digest, not by guessing.
pub fn plan_pull(
    sha: &str,
    by_sha: &std::collections::HashMap<String, String>,
    known_sha: Option<&str>,
    name_present: bool,
    part: i64,
) -> PullAction {
    if known_sha == Some(sha) && name_present {
        return PullAction::Have;
    }
    if known_sha.is_some() && known_sha != Some(sha) && name_present {
        return PullAction::Restart;
    }
    if let Some(from) = by_sha.get(sha) {
        return PullAction::Dedup { from: from.clone() };
    }
    if part > 0 {
        return PullAction::Resume { from: part };
    }
    PullAction::Fetch
}

/// Ask a friend what it offers, then take everything we do not already hold.
pub async fn pull_all(dir: String, id_hex: String, addr: String, fp: String, pair: String) -> Result<serde_json::Value> {
    let store = Store::open(&dir_paths(&dir)?.join("rsnext.db").to_string_lossy())?;
    let offers = list_offered(dir.clone(), id_hex.clone(), addr.clone(), fp.clone(), pair.clone()).await?;
    let files = dir_paths(&dir)?.join("files");
    std::fs::create_dir_all(&files)?;

    // content-addressed view of the local library, so a renamed duplicate costs zero bytes.
    // Only files that actually exist on disk count: a DB row whose bytes were deleted must not be
    // picked as a dedupe source, or the copy step falls through to a needless re-download.
    let mut by_sha: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut path_of: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, _size, sha, local) in store.inventory()? {
        let candidate = if local.is_empty() { files.join(&name) } else { std::path::PathBuf::from(&local) };
        if !candidate.is_file() {
            continue;
        }
        by_sha.entry(sha.clone()).or_insert_with(|| name.clone());
        path_of.entry(sha.clone()).or_insert_with(|| candidate.to_string_lossy().to_string());
    }

    let mut actions: Vec<serde_json::Value> = Vec::new();
    let mut bytes = 0i64;
    let mut fetched = 0usize;
    let mut skipped = 0usize;

    for off in &offers {
        let name = off["name"].as_str().unwrap_or("").to_string();
        let sha = off["sha"].as_str().unwrap_or("").to_string();
        let size = off["size"].as_i64().unwrap_or(0);
        if name.is_empty() || sha.is_empty() {
            continue;
        }
        let part = files.join(format!("{name}.part")).metadata().map(|m| m.len() as i64).unwrap_or(0);
        let known = store.known_sha(&name)?;
        let action = plan_pull(&sha, &by_sha, known.as_deref(), files.join(&name).is_file(), part);
        match action {
            PullAction::Have => {
                skipped += 1;
                actions.push(serde_json::json!({ "name": name, "action": "have" }));
            }
            PullAction::Dedup { from } => {
                // path_of already holds a resolved, existence-checked path; re-joining it under
                // files/ would produce a doubled path like a_dir/files/a_dir/files/x
                let src = std::path::PathBuf::from(path_of.get(&sha).cloned().unwrap_or(from));
                if src.is_file() {
                    std::fs::copy(&src, files.join(&name))?;
                    store.record_file(&name, size, &sha, "files")?;
                    skipped += 1;
                    actions.push(serde_json::json!({ "name": name, "action": "dedup", "source": sha }));
                } else {
                    // recorded as held but the bytes are gone: treat it as a plain download
                    let r = pull_file(dir.clone(), id_hex.clone(), addr.clone(), name.clone(), fp.clone(), pair.clone()).await?;
                    bytes += r["size"].as_i64().unwrap_or(0);
                    fetched += 1;
                    actions.push(serde_json::json!({ "name": name, "action": "fetched_after_missing" }));
                }
            }
            PullAction::Restart => {
                // same name, different content: the old bytes are useless for this digest
                let _ = std::fs::remove_file(files.join(format!("{name}.part")));
                let _ = std::fs::remove_file(files.join(&name));
                let r = pull_file(dir.clone(), id_hex.clone(), addr.clone(), name.clone(), fp.clone(), pair.clone()).await?;
                bytes += r["size"].as_i64().unwrap_or(0);
                fetched += 1;
                actions.push(serde_json::json!({ "name": name, "action": "replaced", "size": size }));
            }
            PullAction::Resume { from } => {
                let r = pull_file(dir.clone(), id_hex.clone(), addr.clone(), name.clone(), fp.clone(), pair.clone()).await?;
                bytes += r["size"].as_i64().unwrap_or(0);
                fetched += 1;
                actions.push(serde_json::json!({ "name": name, "action": "resumed", "from": from, "size": size }));
            }
            PullAction::Fetch => {
                let r = pull_file(dir.clone(), id_hex.clone(), addr.clone(), name.clone(), fp.clone(), pair.clone()).await?;
                bytes += r["size"].as_i64().unwrap_or(0);
                fetched += 1;
                actions.push(serde_json::json!({ "name": name, "action": "fetched", "size": size }));
            }
        }
    }

    Ok(serde_json::json!({
        "asked": id_hex,
        "offered": offers.len(),
        "transferred": fetched,
        "skipped": skipped,
        "bytes": bytes,
        "actions": actions,
    }))
}
#[cfg(test)]
mod tests {
    //! peer_gate is the F2F authorization decision, so it is tested directly rather than
    //! through the network: a live-dial test cannot tell "refused correctly" apart from
    //! "unreachable" (see U1), which is exactly the distinction that matters here.
    use super::*;
    use std::sync::Arc;

    struct Node {
        dir: std::path::PathBuf,
        store: Arc<Store>,
    }

    fn node(tag: &str, code: Option<&str>) -> Node {
        let dir = std::env::temp_dir().join(format!("rsnext-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let id = Identity::generate(tag);
        std::fs::write(dir.join("identity.json"), serde_json::to_string(&id).unwrap()).unwrap();
        if let Some(c) = code {
            std::fs::write(dir.join("pairing.json"), serde_json::json!({ "code": c }).to_string()).unwrap();
        }
        let store = Arc::new(Store::open(&dir.join("rsnext.db").to_string_lossy()).unwrap());
        Node { dir, store }
    }

    fn fp_of(dir: &std::path::Path) -> String {
        serde_json::from_str::<Identity>(&std::fs::read_to_string(dir.join("identity.json")).unwrap())
            .unwrap()
            .fingerprint()
    }

    fn rt<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn unknown_peer_with_live_code_binds_and_spends_the_code() {
        let n = node("bind", Some("P1"));
        let friend = Identity::generate("friend");
        let ffp = friend.fingerprint();
        let ok = rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &ffp, "P1", &friend.ed25519_public, "1.2.3.4:1", "", "", None)).unwrap();
        assert!(ok, "a presented live code must bind");
        let spent: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(n.dir.join("pairing.json")).unwrap()).unwrap();
        assert!(spent["code"].is_null(), "the one-time code must be spent after binding: {spent}");
        assert_eq!(n.store.peer_by_fp(&ffp).unwrap().1, "P1");
    }

    #[test]
    fn replayed_code_cannot_bind_a_second_stranger() {
        let n = node("replay", Some("P1"));
        let first = Identity::generate("first");
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &first.fingerprint(), "P1", &first.ed25519_public, "", "", "", None)).unwrap());
        let second = Identity::generate("mallory");
        assert!(!rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &second.fingerprint(), "P1", &second.ed25519_public, "", "", "", None)).unwrap(),
            "a spent code must never bind anybody else");
        assert_eq!(n.store.peers().len(), 1);
    }

    #[test]
    fn bound_friend_is_not_locked_out_when_the_pair_row_changes() {
        // U2: the pair code gates the FIRST binding only. Afterwards iroh has already proven
        // key possession, so a stale/rotated pair value must not break the friendship.
        let n = node("rotate", Some("P1"));
        let friend = Identity::generate("friend2");
        let ffp = friend.fingerprint();
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &ffp, "P1", &friend.ed25519_public, "", "", "", None)).unwrap());
        n.store.bind_peer(&ffp, &friend.ed25519_public, "ROTATED-AWAY", "").unwrap();
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &ffp, "anything", &friend.ed25519_public, "", "", "", None)).unwrap(),
            "identity, not the pair string, is the credential for an already-bound peer");
    }

    #[test]
    fn a_stranger_presenting_a_bound_fingerprint_is_refused() {
        let n = node("spoof", Some("P1"));
        let bob = Identity::generate("bob2");
        let mallory = Identity::generate("mallory2");
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &bob.fingerprint(), "P1", &bob.ed25519_public, "", "", "", None)).unwrap());
        assert!(!rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &bob.fingerprint(), "P1", &mallory.ed25519_public, "", "", "", None)).unwrap(),
            "claiming a friend's fingerprint while authenticating with a different key must fail");
    }

    #[test]
    fn unknown_peer_with_wrong_code_is_refused() {
        let n = node("badcode", Some("P1"));
        let x = Identity::generate("x");
        assert!(!rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &x.fingerprint(), "WRONG", &x.ed25519_public, "", "", "", None)).unwrap());
        assert!(n.store.peers().is_empty());
    }

    #[test]
    fn rendezvous_only_answers_to_our_own_friends() {
        let n = node("rv", Some("P1"));
        let friend = Identity::generate("friend-rv");
        let other = Identity::generate("other-rv");
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public, "10.1.2.3:900", "10.1.2.3:900", "", None)).unwrap();
        // a friend asking about that friend gets the address
        assert_eq!(rendezvous_reply(&n.store, &friend.fingerprint(), &friend.ed25519_public), vec!["10.1.2.3:900".to_string()]);
        // a stranger asking the same thing gets nothing at all
        assert!(rendezvous_reply(&n.store, &other.fingerprint(), &friend.ed25519_public).is_empty(),
            "unbound asker must not learn where our friends live");
        // even a friend asking about someone we have not bound gets nothing
        assert!(rendezvous_reply(&n.store, &friend.fingerprint(), &other.ed25519_public).is_empty());
    }

    #[test]
    fn a_first_contact_from_a_cli_only_peer_still_gets_an_address() {
        // A CLI advertises no address on purpose (its socket dies with the process), so the
        // observed source address is the only thing worth recording - and it has to be written by
        // whoever creates the row, not by an earlier UPDATE that matches nothing.
        let n = node("addr", Some("P1"));
        let friend = Identity::generate("friend-addr");
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public, "", "203.0.113.7:5555", "", None)).unwrap();
        let row = n.store.peer_full(&friend.fingerprint()).expect("peer row missing");
        assert_eq!(row.2, "203.0.113.7:5555", "observed address must survive the first bind");
        assert_eq!(row.3, "", "nothing was advertised this time");
        // a later contact that DOES advertise its X25519 half must land in the row - it is what a
        // WoT certificate signs, and losing it would make every cert cover only half an identity
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public,
                     "", "", &"cd".repeat(32), None)).unwrap();
        assert_eq!(n.store.peer_full(&friend.fingerprint()).unwrap().3, "cd".repeat(32),
            "X25519 half must be recorded on an existing row");
        // a mere observation must NOT overwrite an advertised (listening) port
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public,
                     "198.51.100.4:7801", "", "", None)).unwrap();
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public,
                     "", "198.51.100.9:31337", "", None)).unwrap();
        assert_eq!(n.store.peer_full(&friend.fingerprint()).unwrap().2, "198.51.100.4:7801",
            "an advertised listening port must survive a later CLI-side observation");
        // a fresher ADVERTISEMENT does replace it ...
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public, "203.0.113.9:1", "", "", None)).unwrap();
        assert_eq!(n.store.peer_full(&friend.fingerprint()).unwrap().2, "203.0.113.9:1");
        // ... but knowing nothing must never wipe a known-good address
        rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &friend.fingerprint(), "P1", &friend.ed25519_public, "", "", "", None)).unwrap();
        assert_eq!(n.store.peer_full(&friend.fingerprint()).unwrap().2, "203.0.113.9:1", "empty must never erase");
    }

    #[test]
    fn one_writer_per_part_file() {
        // U3: create_new is what keeps two concurrent transfers from interleaving into one .part
        let n = node("part", None);
        let files = n.dir.join("files");
        std::fs::create_dir_all(&files).unwrap();
        let lock = files.join("f.bin.part.lock");
        assert!(std::fs::OpenOptions::new().create_new(true).write(true).open(&lock).is_ok());
        assert!(std::fs::OpenOptions::new().create_new(true).write(true).open(&lock).is_err(), "second claim must fail while held");
        std::fs::remove_file(&lock).unwrap();
        assert!(std::fs::OpenOptions::new().create_new(true).write(true).open(&lock).is_ok(), "claim is released after the transfer");
        let _ = fp_of(&n.dir);
    }

    #[test]
    fn batch_pull_decides_by_content_not_by_name() {
        let mut by_sha = std::collections::HashMap::new();
        by_sha.insert("SHA-A".to_string(), "already-renamed.bin".to_string());

        // exact name + exact hash + bytes really on disk: nothing to do
        assert_eq!(plan_pull("SHA-A", &by_sha, Some("SHA-A"), true, 0), PullAction::Have);
        // same content under a different name: copy locally, never re-download
        assert_eq!(plan_pull("SHA-A", &by_sha, None, false, 0),
                   PullAction::Dedup { from: "already-renamed.bin".into() });
        // the index claims we hold it but the file was deleted: must NOT be reported as have,
        // and the duplicate under another name is the cheapest way to heal the hole
        assert_eq!(plan_pull("SHA-A", &by_sha, Some("SHA-A"), false, 0),
                   PullAction::Dedup { from: "already-renamed.bin".into() });
        // a name we hold with different content must NOT be resumed or skipped - the old bytes
        // cannot contribute to the new digest, so they have to go
        assert_eq!(plan_pull("SHA-B", &by_sha, Some("SHA-OLD"), true, 900), PullAction::Restart);
        // an unknown name with a partial is resumed
        assert_eq!(plan_pull("SHA-C", &by_sha, None, false, 4096), PullAction::Resume { from: 4096 });
        // nothing at all
        assert_eq!(plan_pull("SHA-D", &by_sha, None, false, 0), PullAction::Fetch);
        // Have wins over Dedup: holding it under this name already is strictly better
        assert_eq!(plan_pull("SHA-A", &by_sha, Some("SHA-A"), true, 1234), PullAction::Have);
        // deleted file AND no duplicate anywhere: fall back to a transfer, honouring any part
        assert_eq!(plan_pull("SHA-E", &std::collections::HashMap::new(), Some("SHA-E"), false, 700),
                   PullAction::Resume { from: 700 });
    }

    #[test]
    fn a_ban_outranks_an_existing_binding() {
        // the dangerous ordering would be "prove identity, then look at the ban list": an
        // authenticated friend could never be cut off, because authentication always succeeds
        let n = node("ban", Some("P1"));
        let friend = Identity::generate("friend");
        let fp = friend.fingerprint();
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &fp, "P1", &friend.ed25519_public,
                             "198.51.100.2:7801", "", "", None)).unwrap(), "bonding works before the ban");
        assert!(n.store.ban(&fp, "spam").unwrap());
        assert!(!rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &fp, "P1", &friend.ed25519_public,
                              "198.51.100.2:7801", "", "", None)).unwrap(), "a banned, already-bound peer is refused");
        assert!(n.store.is_banned(&fp));
        assert_eq!(n.store.ban_reason(&fp), "spam");
        // unban restores reachability - the ban must not corrupt the binding it suspended
        assert!(n.store.unban(&fp).unwrap());
        assert!(rt(peer_gate(&n.store, n.dir.to_str().unwrap(), &fp, "P1", &friend.ed25519_public,
                             "198.51.100.9:7802", "", "", None)).unwrap(), "after unban the peer is accepted again");
        assert_eq!(n.store.peer_full(&fp).unwrap().2, "198.51.100.9:7802", "address refresh works after unban");
    }
}
