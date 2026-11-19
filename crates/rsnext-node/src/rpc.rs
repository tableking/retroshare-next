//! Local control plane (M3 prerequisite): newline-delimited JSON-RPC over a unix socket inside
//! the node's data dir. Tauri, the CLI and a phone talking to a Home Node are all just clients of
//! this surface, so building it first keeps the daemon the single source of truth and everything
//! above it thin.
//!
//! Wire: one JSON object per line in, one per line out.
//!   -> {"id":1,"method":"node.info","params":{}}
//!   <- {"id":1,"ok":true,"result":{...}}   |   {"id":1,"ok":false,"error":"..."}
//!
//! Security: the socket is mode 0600 inside the data dir and is deliberately NOT a TCP listener —
//! it can read messages and pull files. Remote control (Home Node) comes later behind a tunnel.
use crate::dir_paths;
use crate::net;
use anyhow::{anyhow, Result};
use rsnext_core::identity::Identity;
use rsnext_core::merkle::merkle_root;
use rsnext_core::store::Store;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tokio::net::UnixListener;
use tokio::net::UnixStream;

pub fn socket_path(dir: &str) -> Result<std::path::PathBuf> {
    Ok(dir_paths(dir)?.join("rsnext.sock"))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn identity_of(dir: &str) -> Result<Identity> {
    let raw = std::fs::read_to_string(dir_paths(dir)?.join("identity.json"))?;
    Ok(serde_json::from_str(&raw)?)
}

pub async fn serve(dir: String, store: Arc<Store>, events: broadcast::Sender<serde_json::Value>) -> Result<()> {
    let path = socket_path(&dir)?;
    let _ = std::fs::remove_file(&path);
    // bind through tokio: `UnixListener::from_std` hands tokio a *blocking* fd, which tokio 1.54
    // refuses ("Registering a blocking socket with the tokio runtime is unsupported", tokio#7172)
    // and that panic takes the whole daemon down at startup.
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    println!("control socket      = {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let d = dir.clone();
                let s = store.clone();
                let ev = events.clone();
                tokio::spawn(async move {
                    if let Err(e) = session(stream, d, s, ev).await {
                        net::vlog(format_args!("[rpc] {e:#}"));
                    }
                });
            }
            Err(e) => eprintln!("[rpc accept] {e}"),
        }
    }
}

async fn session(stream: UnixStream, dir: String, store: Arc<Store>, events: broadcast::Sender<serde_json::Value>) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                let out = json!({"id": Value::Null, "ok": false, "error": format!("bad request: {e}")});
                w.write_all(format!("{out}\n").as_bytes()).await?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        // Push channel: a UI must not poll. Subscribe once, then read event lines forever.
        if method == "events.subscribe" {
            let mut rx = events.subscribe();
            w.write_all(format!("{}
", json!({"id": id, "ok": true, "result": {"subscribed": true}})).as_bytes()).await?;
            w.flush().await?;
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if w.write_all(format!("{ev}
").as_bytes()).await.is_err() || w.flush().await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // never let a slow UI stall the node: tell it that it missed n events
                        let _ = w.write_all(format!("{}
", json!({"event": "lagged", "dropped": n})).as_bytes()).await;
                    }
                    Err(_) => break,
                }
            }
            return Ok(());
        }
        let out = match dispatch(&dir, &store, &method, params, &events).await {
            Ok(result) => json!({"id": id, "ok": true, "result": result}),
            Err(e) => json!({"id": id, "ok": false, "error": format!("{e:#}")}),
        };
        w.write_all(format!("{out}\n").as_bytes()).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Dial a bound peer using the address that peer last advertised to us (`my_addr` frame field),
/// unless the caller passed an explicit `addr` (needed right after a peer restarts, because with
/// relays off and an ephemeral port nobody can discover a friend's new address on their own).
async fn peer_target(store: &Store, peer_fp: &str, addr_override: Option<&str>) -> Result<(String, String, String)> {
    let (eid, pair) = store.peer_by_fp(peer_fp).ok_or_else(|| anyhow!("peer {peer_fp} not bound"))?;
    let stored = store
        .peers()
        .into_iter()
        .find(|(fp, ..)| fp == peer_fp)
        .map(|(_, _, _, a, _)| a)
        .unwrap_or_default();
    let addr = addr_override.map(|s| s.to_string()).or_else(|| {
        if stored.is_empty() { None } else { Some(stored.clone()) }
    }).ok_or_else(|| anyhow!("no known address for {peer_fp}: it has never contacted us. Pass params.addr explicitly (ip:port)."))?;
    Ok((eid, addr, pair))
}

fn root_of(store: &Store) -> String {
    hex::encode(merkle_root(&net::local_leaves(store).into_iter().map(|(_, h)| h).collect::<Vec<_>>()))
}

async fn dispatch(
    dir: &str,
    store: &Store,
    method: &str,
    params: Value,
    events: &broadcast::Sender<serde_json::Value>,
) -> Result<Value> {
    let p = |k: &str| params.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    match method {
        // ---------- read-only ----------
        "node.info" => {
            let id = identity_of(dir)?;
            Ok(json!({
                "name": id.name,
                "fingerprint": id.fingerprint(),
                "endpoint_id": id.ed25519_public,
                "posts": store.post_count(),
                "forum_root": root_of(store),
                "channel_roots": crate::net::channel_roots(store),
                "shared_files": store.list_shared().len(),
                "peers": store.peers().len(),
                "data_dir": dir,
                "control_socket": socket_path(dir)?.display().to_string(),
            }))
        }
        "peers.list" => Ok(json!({"peers": store.peers().into_iter().map(|(fp, eid, pair, addr, ts)| json!({
            "fingerprint": fp, "endpoint_id": eid, "pair": pair, "last_addr": addr, "bound_ts": ts
        })).collect::<Vec<_>>() })),
        "forum.list" => {
            let ch = { let c = p("channel"); if c.is_empty() { "general".to_string() } else { c } };
            Ok(json!({"channel": ch, "posts": store.posts_in(&ch).into_iter().map(|(seq, author, body, ts)| json!({
                "seq": seq, "author": author, "body": body, "ts": ts
            })).collect::<Vec<_>>() }))
        }
        "channels.list" => {
            let me = identity_of(dir)?.fingerprint();
            let subs = store.subs(&me);
            let mut names: Vec<String> = store.channels().into_iter().map(|c| c.0).collect();
            names.push("general".into());
            names.sort();
            names.dedup();
            Ok(json!({"channels": names.into_iter().map(|n| json!({
                "name": n,
                "posts": store.post_count_in(&n),
                "unread": store.unread_for(&n, &me),
                "last_seq_read": subs.iter().find(|(c, _)| *c == n).map(|(_, v)| *v).unwrap_or(0)
            })).collect::<Vec<_>>()}))
        }
        "channels.create" => {
            let name = p("name");
            if name.is_empty() {
                return Err(anyhow!("params.name required"));
            }
            let me = identity_of(dir)?.fingerprint();
            let fresh = store.create_channel(&name, &me, &p("desc"))?;
            Ok(json!({"channel": name, "created": fresh}))
        }
        "forum.mark_read" => {
            let ch = { let c = p("channel"); if c.is_empty() { "general".to_string() } else { c } };
            let me = identity_of(dir)?.fingerprint();
            let top = store.max_seq_in(&ch);
            let cursor = store.mark_read(&ch, &me, top)?;
            Ok(json!({"channel": ch, "marked_up_to_seq": top, "cursor": cursor, "unread": store.unread_for(&ch, &me)}))
        }
        "chat.inbox" => Ok(json!({"messages": store.messages(params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50))
            .into_iter().map(|(seq, peer, text, ts)| json!({"seq": seq, "peer": peer, "text": text, "ts": ts})).collect::<Vec<_>>() })),
        "files.list" => Ok(json!({"shared": store.list_shared().into_iter().map(|(name, size, sha, path)| json!({
            "name": name, "size": size, "sha256": sha, "path": path
        })).collect::<Vec<_>>() })),

        // ---------- local mutations ----------
        "forum.post" => {
            let body = p("body");
            if body.is_empty() {
                return Err(anyhow!("params.body required"));
            }
            let author = identity_of(dir)?.fingerprint();
            let channel = { let c = p("channel"); if c.is_empty() { "general".to_string() } else { c } };
            if channel != "general" {
                let _ = store.create_channel(&channel, &author, "");
            }
            let seq = store.add_post_to(&channel, &author, &body)?;
            // a local post is an event too: a UI that only listened for peer pushes would never
            // see the user's own message appear
            let _ = events.send(json!({"type": "forum", "local": true, "seq": seq, "author": author, "body": body, "root": root_of(store), "posts": store.post_count()}));
            Ok(json!({"seq": seq, "root": root_of(store)}))
        }
        "files.share" => {
            let abs = dir_paths(&p("path"))?;
            let bytes = std::fs::read(&abs).map_err(|e| anyhow!("read {}: {e}", abs.display()))?;
            use sha2::{Digest, Sha256};
            let sha = hex::encode(Sha256::digest(&bytes));
            let name = abs.file_name().map(|s| s.to_string_lossy().to_string()).ok_or_else(|| anyhow!("bad path"))?;
            store.set_shared(&name, bytes.len() as i64, &sha, &abs.to_string_lossy(), true)?;
            Ok(json!({"name": name, "size": bytes.len(), "sha256": sha}))
        }
        "files.unshare" => Ok(json!({"revoked": store.unshare(&p("name"))?})),

        // ---------- network actions (dial the peer's last advertised address) ----------
        "chat.send" => {
            let to = p("to");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            net::send_msg(dir.into(), eid, addr, p("text"), identity_of(dir)?.fingerprint(), pair).await?;
            Ok(json!({"sent_to": to}))
        }
        "files.ls_peer" => {
            let to = p("to");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            let files = net::list_offered(dir.into(), eid, addr, identity_of(dir)?.fingerprint(), pair).await?;
            Ok(json!({"asked": to, "files": files}))
        }
        "search.posts" => {
            let q = p("query");
            if q.is_empty() { return Err(anyhow!("query required")); }
            let ch = params.get("channel").and_then(|v| v.as_str());
            let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50).clamp(1, 500);
            Ok(json!({"query": q, "hits": store.search_posts(&q, ch, limit).into_iter()
                .map(|(channel, seq, author, body, ts)| json!({"channel": channel, "seq": seq, "author": author, "body": body, "ts": ts}))
                .collect::<Vec<_>>()}))
        }
        "search.files" => {
            let q = p("query");
            if q.is_empty() { return Err(anyhow!("query required")); }
            let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50).clamp(1, 500);
            let hits = store.search_files(&q, true, limit)?;
            Ok(json!({"query": q, "hits": hits.into_iter()
                .map(|(name, size, sha)| json!({"name": name, "size": size, "sha256": sha}))
                .collect::<Vec<_>>()}))
        }
        "history.forget" => {
            let scope = params.get("scope").and_then(|v| v.as_str()).unwrap_or("channel");
            let value = params.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if value.is_empty() { return Err(anyhow!("value required")); }
            let removed = match scope {
                "channel" => store.forget_channel(value)?,
                "author" | "peer" => store.forget_author(value)?,
                other => return Err(anyhow!("unknown scope {other:?} (channel|author)")),
            };
            // the invariant the D-series gates assert, returned so a UI can prove the erase also
            // left the search index consistent rather than trusting that it did
            let (docs, _postings) = store.deep_stats();
            Ok(json!({"scope": scope, "value": value, "removed": removed,
                      "indexed_docs": docs, "posts": store.post_count(),
                      "note": "erases this node only; peers keep their copies"}))
        }
        "history.forgotten" => Ok(json!({"tombstones": store.forgotten().into_iter()
            .map(|(chan, author, seq, ts)| json!({"channel": chan, "author": author, "seq": seq, "ts": ts}))
            .collect::<Vec<_>>()})),
        "circles.list" => Ok(json!({"circles": store.circles().into_iter()
            .map(|(n, m)| json!({"name": n, "members": m}))
            .collect::<Vec<_>>(),
            "restricted": store.restricted_channels().into_iter()
            .map(|(ch, c)| json!({"channel": ch, "circle": c}))
            .collect::<Vec<_>>()})),
        "circles.create" => {
            let name = p("name");
            Ok(json!({"name": name, "created": store.create_circle(&name)?}))
        }
        "circles.add" => {
            let (name, fp) = (p("name"), p("fingerprint"));
            Ok(json!({"name": name, "fingerprint": fp, "added": store.circle_add(&name, &fp)?}))
        }
        "circles.restrict" => {
            let (chan, circle) = (p("channel"), p("circle"));
            store.restrict_channel(&chan, &circle)?;
            Ok(json!({"channel": chan, "circle": circle, "restricted": true}))
        }
        "peers.presence" => {
            let now = rsnext_core::presence::unix_now();
            // merged, not derived: a peer that says "away" is away; once that report goes stale we
            // fall back to what our own contact log supports. `source` tells the UI which it got.
            Ok(json!({"now": now, "peers": store.all_presence(now).into_iter()
                .map(|(fp, _derived, seen)| {
                    let (state, source, _) = store.presence_merged(&fp, now, 300);
                    json!({"fingerprint": fp, "state": state, "source": source, "last_seen": seen})
                })
                .collect::<Vec<_>>()}))
        }
        "api.methods" => {
            // The control plane's own surface, so a UI or script can check before calling.
            // This array is generated from the dispatch arms in this file (see
            // tools/publish docs), and gates_web.sh diffs the running node's answer against
            // those same arms - an inventory nobody verifies is worse than none.
            Ok(json!({"methods": [
                "api.methods",
                "channels.create",
                "channels.list",
                "chat.inbox",
                "chat.send",
                "circles.add",
                "circles.create",
                "circles.list",
                "circles.restrict",
                "files.list",
                "files.ls_peer",
                "files.pull",
                "files.pull_all",
                "files.push",
                "files.share",
                "files.unshare",
                "forum.list",
                "forum.mark_read",
                "forum.post",
                "history.forget",
                "history.forgotten",
                "node.hello",
                "node.info",
                "node.quit",
                "peers.ban",
                "peers.bans",
                "peers.list",
                "peers.presence",
                "peers.unban",
                "rss.add",
                "rss.fetch",
                "rss.list",
                "search.files",
                "search.posts",
                "search.query",
                "search.rebuild",
                "search.status",
                "sync.all",
                "sync.peer",
                "wiki.history",
                "wiki.list",
                "wiki.save",
                "wiki.show",
                "wot.list",
                "wot.sign",
                "wot.trust"
            ]}))
        }
        "peers.ban" => {
            let fp = p("fingerprint");
            if fp.is_empty() { return Err(anyhow!("fingerprint required")); }
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("no reason given").to_string();
            Ok(json!({"fingerprint": fp, "banned": store.ban(&fp, &reason)?, "reason": reason}))
        }
        "peers.unban" => {
            let fp = p("fingerprint");
            Ok(json!({"fingerprint": fp, "removed": store.unban(&fp)?}))
        }
        "peers.bans" => Ok(json!({"bans": store.bans().into_iter()
            .map(|(fp, reason, ts)| json!({"fingerprint": fp, "reason": reason, "ts": ts}))
            .collect::<Vec<_>>()})),
        "wiki.list" => {
            let mut out = Vec::new();
            for p in store.wiki_pages() {
                let cur = store.wiki_current(&p);
                out.push(json!({"page": p,
                    "revisions": store.wiki_history(&p).len(),
                    "current_author": cur.as_ref().map(|r| r.author.clone()).unwrap_or_default(),
                    "current_ts": cur.as_ref().map(|r| r.ts).unwrap_or(0)}));
            }
            Ok(json!({"pages": out}))
        }
        "wiki.show" => {
            let page = p("page");
            let cur = store.wiki_current(&page).ok_or_else(|| anyhow!("no such page: {page}"))?;
            Ok(json!({"page": page, "seq": cur.seq, "author": cur.author, "ts": cur.ts, "body": cur.body,
                      "revisions": store.wiki_history(&page).len()}))
        }
        "wiki.history" => {
            let page = p("page");
            Ok(json!({"page": page, "history": store.wiki_history(&page).into_iter()
                .map(|r| json!({"seq": r.seq, "author": r.author, "ts": r.ts, "body": r.body}))
                .collect::<Vec<_>>()}))
        }
        "wiki.save" => {
            let page = p("page");
            let body = p("body");
            let me = identity_of(dir)?.fingerprint();
            let seq = store.wiki_save(&page, &me, &body)?;
            let _ = events.send(json!({"type": "forum", "local": true, "channel": format!("wiki/{page}"), "seq": seq}));
            Ok(json!({"page": page, "seq": seq}))
        }
        "search.query" => {
            let q = p("query");
            if q.is_empty() { return Err(anyhow!("query required")); }
            let ch = params.get("channel").and_then(|v| v.as_str());
            let max = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50).clamp(1, 500);
            let hits = store.deep_search(&q, ch, max)?;
            Ok(json!({"query": q, "hits": hits.into_iter()
                .map(|(url, w, snippet)| json!({"url": url, "weight": (w * 1000.0).round() / 1000.0, "snippet": snippet}))
                .collect::<Vec<_>>()}))
        }
        "search.rebuild" => {
            let (posts, files) = store.deep_rebuild()?;
            let (docs, terms) = store.deep_stats();
            Ok(json!({"posts": posts, "files": files, "docs": docs, "postings": terms}))
        }
        "search.status" => {
            let (docs, terms) = store.deep_stats();
            // index vs truth in one response: a UI can warn the user instead of showing a short list
            Ok(json!({"docs": docs, "postings": terms, "posts": store.post_count(),
                "files": store.shared_count(), "held": store.file_count()}))
        }
        "rss.add" => {
            let url = p("url");
            let name = params.get("name").and_then(|v| v.as_str()).map(|s| s.to_string())
                .unwrap_or_else(|| crate::default_feed_name(&url));
            let fresh = store.add_feed(&name, &url)?;
            Ok(json!({"feed": name, "url": url, "subscribed": fresh}))
        }
        "rss.fetch" => {
            // blocking HTTP inside an async handler is deliberate for now: a poll is rare, bounded
            // by the 4 MiB cap, and the daemon has no other work to lose a worker thread to
            crate::feed::rss_fetch(dir, params.get("feed").and_then(|v| v.as_str()))
        }
        "rss.list" => {
            let rows: Vec<Value> = store.feeds().into_iter()
                .map(|(n, u)| json!({"name": n, "url": u, "seen": store.seen_count(&n)}))
                .collect();
            Ok(json!({"feeds": rows}))
        }
        "files.pull_all" => {
            // one ls, then only the content we do not already hold (hash-matched, so a renamed
            // duplicate costs zero bytes on the wire)
            let to = p("to");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            net::pull_all(dir.into(), eid, addr, identity_of(dir)?.fingerprint(), pair).await
        }
        "files.pull" => {
            let to = p("to");
            let name = p("name");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            net::pull_file(dir.into(), eid, addr, name.clone(), identity_of(dir)?.fingerprint(), pair).await?;
            Ok(json!({"pulled": name, "from": to}))
        }
        "sync.all" => {
            // params may carry explicit reachability: {"FP": "ip:port", ...} for peers whose
            // stored address went stale (they restarted while relays were off)
            let overrides: Vec<(String, String)> = params.as_object()
                .map(|m| m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .filter(|(_, v)| !v.is_empty())
                    .collect())
                .unwrap_or_default();
            net::sync_all(dir.into(), identity_of(dir)?.fingerprint(), overrides).await?;
            Ok(json!({"root": root_of(store), "posts": store.post_count()}))
        }
        "files.push" => {
            let to = p("to");
            let path = p("path");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            net::push_file(dir.into(), eid, addr, path.clone(), identity_of(dir)?.fingerprint(), pair).await?;
            Ok(json!({"pushed": path, "to": to}))
        }
        "sync.peer" => {
            let to = p("to");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            net::forum_sync(dir.into(), eid, addr, identity_of(dir)?.fingerprint(), pair).await?;
            Ok(json!({"synced_with": to, "root": root_of(store), "posts": store.post_count()}))
        }
        "node.hello" => {
            let to = p("to");
            let (eid, addr, pair) = peer_target(store, &to, params.get("addr").and_then(|a| a.as_str())).await?;
            let resp = net::say_hi(dir, &eid, &addr, &identity_of(dir)?.fingerprint(), &pair).await?;
            Ok(json!({"hello_to": to, "via": addr, "peer_says": resp}))
        }
        "wot.list" => Ok(json!({"certs": store.certs().into_iter().map(|c| json!({
            "subject_fp": c.cert.subject_fp, "issuer_fp": c.issuer_fp, "ts": c.cert.ts,
            "verified": rsnext_core::wot::verify_cert(&c.issuer_ed, &c.cert, &c.sig).is_ok()
        })).collect::<Vec<_>>()})),
        "wot.sign" => {
            let to = p("to");
            let me = identity_of(dir)?;
            let (ed, _pair, _addr, x25519) = store.peer_full(&to).ok_or_else(|| anyhow!("unknown peer {to}"))?;
            if x25519.is_empty() {
                // half an identity is not worth a certificate: the X25519 key is what the channel uses
                return Err(anyhow!("refusing to sign {to}: its X25519 half is unknown (it must contact us once)"));
            }
            let cert = rsnext_core::wot::CertInfo { subject_fp: to.clone(), subject_ed: ed, subject_x25519: x25519, ts: now_secs() };
            let sig = rsnext_core::wot::sign_cert(&me, &cert).map_err(|e| anyhow!("{e}"))?;
            store.put_cert(&rsnext_core::wot::Cert { issuer_fp: me.fingerprint(), issuer_ed: me.ed25519_public.clone(), sig, cert })?;
            Ok(json!({"signed": to, "issuer": me.fingerprint()}))
        }
        "wot.trust" => {
            let me = identity_of(dir)?.fingerprint();
            let scored = rsnext_core::wot::trust_map(&me, &store.cert_edges());
            Ok(json!({"trust": scored.into_iter().map(|(who, v)| json!({"fingerprint": who, "score": (v * 1000.0).round() / 1000.0})).collect::<Vec<_>>()}))
        }
        "node.quit" => {
            println!("[rpc] node.quit requested");
            std::process::exit(0);
        }
        other => Err(anyhow!("unknown method {other:?}")),
    }
}

/// Ask a running node to do something. Err = could not talk to the control socket at all
/// (no daemon); Ok carries the reply, whose `ok:false` means the *action* failed.
pub fn request(dir: &str, method: &str, params: &str) -> Result<Value> {
    use std::io::Write;
    let path = socket_path(dir)?;
    let mut s = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| anyhow!("connect {}: {e}", path.display()))?;
    let parsed: Value = if params.trim().is_empty() { json!({}) } else { serde_json::from_str(params)? };
    s.write_all(json!({"id": 1, "method": method, "params": parsed}).to_string().as_bytes())?;
    s.write_all(b"\n")?;
    s.flush()?;
    let mut line = String::new();
    {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(&s);
        if reader.read_line(&mut line)? == 0 {
            return Err(anyhow!("control socket closed without a response"));
        }
    }
    Ok(serde_json::from_str(line.trim())?)
}

/// Blocking subscriber used by `rsnext-node events <dir>`: prints one event per line until the
/// node goes away or the user interrupts.
pub fn subscribe(dir: &str) -> Result<()> {
    use std::io::{BufRead, Write};
    let path = socket_path(dir)?;
    let stream = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| anyhow!("connect {}: {e} (is `net` running?)", path.display()))?;
    let mut w = &stream;
    w.write_all(json!({"id": 1, "method": "events.subscribe"}).to_string().as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    let reader = std::io::BufReader::new(&stream);
    for line in reader.lines() {
        println!("{}", line?);
    }
    Ok(())
}

/// One-shot client used by the CLI: `rsnext-node rpc <dir> <method> [json-params]`
pub fn call_one_shot(dir: &str, method: &str, params: &str) -> Result<()> {
    use std::io::{Read, Write};
    let path = socket_path(dir)?;
    let mut s = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| anyhow!("connect {}: {e} (is `net` running?)", path.display()))?;
    let parsed: Value = if params.trim().is_empty() { json!({}) } else { serde_json::from_str(params)? };
    let req = json!({"id": 1, "method": method, "params": parsed}).to_string();
    s.write_all(req.as_bytes())?;
    s.write_all(b"\n")?;
    s.flush()?;
    // Read exactly ONE response line. `read_to_string`/`read_to_end` would hang forever: the
    // server keeps the connection open for further requests (line-delimited session, not one-shot),
    // so EOF only arrives when the daemon exits.
    let mut line = String::new();
    {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(&s);
        if reader.read_line(&mut line)? == 0 {
            return Err(anyhow!("control socket closed without a response"));
        }
    }
    let v: Value = serde_json::from_str(line.trim())?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    if v["ok"].as_bool() == Some(false) {
        std::process::exit(2);
    }
    Ok(())
}
