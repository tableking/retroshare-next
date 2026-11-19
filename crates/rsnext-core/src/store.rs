//! SQLite-backed local store: messages, forum posts (merkle-syncable), files index, peers.
//! One DB per node data-dir. rusqlite bundled (compiles its own sqlite3.c).
//!
//! Design notes (M2):
//! - Errors are `anyhow::Result` so the transport layer can `?` them directly.
//! - The connection lives behind a `Mutex`: `rusqlite::Connection` is `Send` but not `Sync`, so a
//!   bare `Store` cannot be captured by `tokio::spawn` across `.await`. Wrapping it makes
//!   `Store: Send + Sync`, so the daemon owns ONE `Arc<Store>` shared by every connection task.
//!   Every method holds the lock only for the SQL call, never across an await point.
//! - **Post identity is `(author, seq)`, not a bare local `seq`.** A globally-incremented local
//!   integer collides across peers (both nodes have seq=1), and `INSERT OR IGNORE` then silently
//!   drops the peer's post — that is how the first M2 sync run lost 'bob post one'. Per-author
//!   sequences make the log append-only *and* merge-idempotent, which is what the merkle root
//!   comparison relies on: order leaves by (author, seq) and every replica computes the same root.
//! - `peers` also carries a last-known `addr`, so a node coming back online can redial everyone it
//!   ever bound to (`sync-all`) without re-scanning invites.
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use crate::wot::Cert;
use std::sync::{Mutex, MutexGuard};

/// (author, channel, seq): seq is a per-author counter WITHIN a channel, so the channel must be
/// part of the key or two channels of the same author collide on seq 1.
const POSTS_SCHEMA: &str =
    "CREATE TABLE posts(author TEXT, channel TEXT NOT NULL DEFAULT 'general', seq INTEGER, body TEXT, ts INTEGER, PRIMARY KEY(author, channel, seq));";

/// Marker used to detect a table that still has the pre-channel primary key.
const POSTS_PK_OK: &str = "PRIMARY KEY(author, channel, seq)";

pub struct Store {
    db: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let db = Connection::open(path).with_context(|| format!("open {path}"))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT, peer TEXT, text TEXT, ts INTEGER);
             CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, size INTEGER, sha256 TEXT, dir TEXT);
             CREATE TABLE IF NOT EXISTS peers(fingerprint TEXT PRIMARY KEY, endpoint_id TEXT, pair TEXT, addr TEXT, bound_ts INTEGER);
             CREATE TABLE IF NOT EXISTS certs(subject_fp TEXT, issuer_fp TEXT, issuer_ed TEXT, subject_ed TEXT, subject_x25519 TEXT, ts INTEGER, sig TEXT, PRIMARY KEY(subject_fp, issuer_fp));
             CREATE TABLE IF NOT EXISTS channels(name TEXT PRIMARY KEY, created_by TEXT, created_ts INTEGER, desc TEXT);
             CREATE TABLE IF NOT EXISTS subs(channel TEXT, reader_fp TEXT, last_seq INTEGER, updated_ts INTEGER, PRIMARY KEY(channel, reader_fp));
             CREATE TABLE IF NOT EXISTS forgotten(channel TEXT NOT NULL, author TEXT NOT NULL, seq INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(channel, author, seq));",
        )
        .context("schema")?;
        // 1) make sure the table exists, 2) add the column to legacy tables, 3) rebuild the key.
        // This order is load-bearing: ALTER TABLE needs the table, and the key rebuild needs the column.
        Self::ensure_posts_table(&db)?;
        Self::ensure_column(&db, "posts", "channel", "TEXT NOT NULL DEFAULT 'general'")?;
        Self::ensure_posts_key(&db)?;
        Self::ensure_column(&db, "subs", "last_rowid", "INTEGER NOT NULL DEFAULT 0")?;
        // demo/older data dirs predate these columns; upgrade them in place rather than resetting
        Self::ensure_column(&db, "peers", "addr", "TEXT")?;
        Self::ensure_column(&db, "files", "shared", "INTEGER NOT NULL DEFAULT 0")?;
        Self::ensure_column(&db, "files", "local_path", "TEXT")?;
        // the x25519 half of a peer identity comes from the invite payload; a certificate signs it
        Self::ensure_column(&db, "peers", "x25519", "TEXT")?;
        // legacy posts had no channel; they belong to the default one
        Self::ensure_column(&db, "posts", "channel", "TEXT NOT NULL DEFAULT 'general'")?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Add a column when an existing table lacks it (idempotent light-weight migration).
    fn ensure_column(db: &Connection, table: &str, col: &str, ty: &str) -> Result<()> {
        let mut st = db.prepare(&format!("PRAGMA table_info({table})"))?;
        let have: Vec<String> = st
            .query_map([], |r| r.get::<_, String>(1))?
            .filter_map(|x| x.ok())
            .collect();
        drop(st);
        if !have.iter().any(|c| c == col) {
            db.execute(&format!("ALTER TABLE {table} ADD COLUMN {col} {ty}"), [])
                .with_context(|| format!("add column {table}.{col}"))?;
        }
        Ok(())
    }

    fn table_sql(db: &Connection, name: &str) -> Option<String> {
        db.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", params![name], |r| r.get::<_, Option<String>>(0))
            .ok()
            .flatten()
    }

    /// Create the posts table when this is a brand new data dir.
    fn ensure_posts_table(db: &Connection) -> Result<()> {
        if Self::table_sql(db, "posts").is_none() {
            db.execute_batch(POSTS_SCHEMA).context("create posts")?;
        }
        Ok(())
    }

    /// Rebuild the primary key to include `channel` when it does not already.
    fn ensure_posts_key(db: &Connection) -> Result<()> {
        let Some(sql) = Self::table_sql(db, "posts") else { return Ok(()) };
        if sql.contains(POSTS_PK_OK) {
            return Ok(());
        }
        // legacy rows have no channel of their own; they all belong to 'general'. The old key was
        // (author, seq) so (author, channel, seq) cannot introduce new collisions.
        db.execute_batch(
            "BEGIN;
             ALTER TABLE posts RENAME TO posts_legacy;
             CREATE TABLE posts(author TEXT, channel TEXT NOT NULL DEFAULT 'general', seq INTEGER, body TEXT, ts INTEGER, PRIMARY KEY(author, channel, seq));
             INSERT OR IGNORE INTO posts(author, channel, seq, body, ts)
                 SELECT author, COALESCE(channel,'general'), seq, body, ts FROM posts_legacy;
             DROP TABLE posts_legacy;
             COMMIT;",
        )
        .context("migrate posts key to (author, channel, seq)")?;
        Ok(())
    }

    pub(crate) fn guard(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|_| anyhow!("store mutex poisoned"))
    }

    /// The lock, for callers that must touch the database and the index as one action.
    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        self.guard().expect("store mutex poisoned")
    }

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
    }

    // ---------- chat ----------
    pub fn add_message(&self, peer: &str, text: &str) -> Result<i64> {
        let db = self.guard()?;
        db.execute("INSERT INTO messages(peer,text,ts) VALUES (?1,?2,?3)", params![peer, text, Self::now()])?;
        Ok(db.last_insert_rowid())
    }
    pub fn messages(&self, limit: i64) -> Vec<(i64, String, String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT seq,peer,text,ts FROM messages ORDER BY seq DESC LIMIT ?1") else { return Vec::new() };
        let Ok(rows) = st.query_map(params![limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }

    // ---------- forum (append-only log) ----------
    /// append a forum post; seq is per-author (the merge key is (author, seq))
    pub fn add_post(&self, author: &str, body: &str) -> Result<i64> {
        self.add_post_to("general", author, body)
    }
    /// Append to a named channel. seq stays per-(author) so the merge key (author,seq) is unique
    /// inside a channel, and every replica orders leaves by (author, seq) within that channel.
    pub fn add_post_to(&self, channel: &str, author: &str, body: &str) -> Result<i64> {
        let db = self.guard()?;
        // Sequence numbers must never be reused, so the high-water mark is taken over live rows
        // AND tombstones. Allocating from live rows alone gave an erased post's number to the next
        // one, which made two different bodies share the merge identity (author, channel, seq):
        // receivers then ignored the new content as a duplicate, and replicas' roots diverged
        // silently instead of converging.
        let seq: i64 = db
            .query_row(
                "SELECT COALESCE(MAX(seq),0)+1 FROM (SELECT seq FROM posts WHERE author=?1 AND channel=?2 UNION ALL SELECT seq FROM forgotten WHERE author=?1 AND channel=?2)",
                params![author, channel], |r| r.get(0))
            .context("seq high-water mark")?;
        let ts = Self::now();
        db.execute("INSERT INTO posts(channel,author,seq,body,ts) VALUES (?1,?2,?3,?4,?5)", params![channel, author, seq, body, ts])?;
        let url = crate::deepsearch::post_url(channel, author, seq);
        crate::deepsearch::index_post(&db, &url, channel, body, ts)?;
        Ok(seq)
    }
    /// every post, in the order that defines the merkle leaves (replicas must agree on it)
    pub fn posts_all(&self) -> Vec<(i64, String, String, i64)> {
        self.posts_in("general")
    }
    /// every post of one channel, in the order that defines that channel's merkle leaves
    pub fn posts_in(&self, channel: &str) -> Vec<(i64, String, String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT seq,author,body,ts FROM posts WHERE channel=?1 ORDER BY author, seq") else { return Vec::new() };
        let Ok(rows) = st.query_map(params![channel], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
    /// (channel, seq, author, body, ts) for every channel we hold - what sync exchanges.
    pub fn posts_everywhere(&self) -> Vec<(String, i64, String, String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT channel,seq,author,body,ts FROM posts ORDER BY channel, author, seq") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
    pub fn insert_post_row(&self, seq: i64, author: &str, body: &str, ts: i64) -> Result<()> {
        self.insert_post_row_in("general", seq, author, body, ts)
    }
    pub fn insert_post_row_in(&self, channel: &str, seq: i64, author: &str, body: &str, ts: i64) -> Result<()> {
        self.ensure_forget()?;
        // A row we erased on purpose must not come back because a peer still holds it: without this
        // check `forget` would last exactly until the next sync.
        let tombstoned = self.guard().ok().and_then(|db| db
            .query_row("SELECT COUNT(*) FROM forgotten WHERE channel=?1 AND author=?2 AND seq=?3",
                params![channel, author, seq], |r| r.get::<_, i64>(0)).ok()).unwrap_or(0) > 0;
        if tombstoned {
            return Ok(());
        }
        let db = self.guard()?;
        let fresh = db.execute("INSERT OR IGNORE INTO posts(channel,author,seq,body,ts) VALUES (?1,?2,?3,?4,?5)", params![channel, author, seq, body, ts])?;
        if fresh == 1 {
            // replicated content is as searchable as local content, or the index silently encodes
            // "posts I wrote" instead of "the forum I have"
            let url = crate::deepsearch::post_url(channel, author, seq);
            crate::deepsearch::index_post(&db, &url, channel, body, ts)?;
        }
        Ok(())
    }
    pub fn post_count(&self) -> i64 {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COUNT(*) FROM posts", [], |r| r.get(0)).unwrap_or(0),
            Err(_) => 0,
        }
    }
    pub fn post_count_in(&self, channel: &str) -> i64 {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COUNT(*) FROM posts WHERE channel=?1", params![channel], |r| r.get(0)).unwrap_or(0),
            Err(_) => 0,
        }
    }
    /// posts in a channel inserted after a cursor. Two rejected designs, both seen as real bugs:
    ///  - `seq > last_seq`: seq is per-author, so author B's seq=1 reads as "seen" once A is at 5.
    ///  - `ts > bookmark`: second resolution hides a post made in the same second as the read.
    pub fn unread_after(&self, channel: &str, cursor: i64) -> i64 {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COUNT(*) FROM posts WHERE channel=?1 AND rowid>?2", params![channel, cursor], |r| r.get(0)).unwrap_or(0),
            Err(_) => 0,
        }
    }
    /// unread for a reader, taken from their own bookmark row
    pub fn unread_for(&self, channel: &str, reader: &str) -> i64 {
        let c = self.sub_cursor(channel, reader);
        self.unread_after(channel, c)
    }
    /// highest seq any author reached in a channel - used for unread counts
    pub fn max_seq_in(&self, channel: &str) -> i64 {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COALESCE(MAX(seq),0) FROM posts WHERE channel=?1", params![channel], |r| r.get(0)).unwrap_or(0),
            Err(_) => 0,
        }
    }

    // ---------- files ----------
    pub fn record_file(&self, name: &str, size: i64, sha: &str, dir: &str) -> Result<()> {
        let db = self.guard()?;
        // keep whatever shared/local_path row already exists (upsert, not replace)
        db.execute(
            "INSERT INTO files(name,size,sha256,dir) VALUES (?1,?2,?3,?4)
             ON CONFLICT(name) DO UPDATE SET size=excluded.size, sha256=excluded.sha256, dir=excluded.dir",
            params![name, size, sha, dir],
        )?;
        // deliberately NOT indexed: holding a file is not offering it. Search answers "what can a
        // friend get from me", so the index must follow the shared flag, not the row's existence.
        Ok(())
    }
    /// offer a local file to bound peers (shared=1) or revoke it; `local_path` is this host's path
    pub fn set_shared(&self, name: &str, size: i64, sha: &str, local_path: &str, shared: bool) -> Result<()> {
        let db = self.guard()?;
        db.execute(
            "INSERT INTO files(name,size,sha256,dir,shared,local_path) VALUES (?1,?2,?3,'share',?4,?5)
             ON CONFLICT(name) DO UPDATE SET shared=excluded.shared, local_path=excluded.local_path,
                                              size=excluded.size, sha256=excluded.sha256",
            params![name, size, sha, shared as i64, local_path],
        )?;
        if shared {
            crate::deepsearch::index_file(&db, name, sha, local_path)?;
        } else {
            // a hit we cannot serve is worse than no hit at all
            crate::deepsearch::purge_file(&db, name)?;
        }
        Ok(())
    }
    pub fn list_shared(&self) -> Vec<(String, i64, String, String)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT name,size,sha256,COALESCE(local_path,'') FROM files WHERE shared=1 ORDER BY name") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
    pub fn shared_by_name(&self, name: &str) -> Option<(i64, String, String)> {
        let db = self.guard().ok()?;
        db.query_row(
            "SELECT size,sha256,COALESCE(local_path,'') FROM files WHERE name=?1 AND shared=1",
            params![name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()
    }
    /// revoke an offer; returns false when no such row existed
    pub fn unshare(&self, name: &str) -> Result<bool> {
        let db = self.guard()?;
        let changed = db.execute("UPDATE files SET shared=0 WHERE name=?1", params![name])? > 0;
        if changed {
            // the offer and its index entry must go together: a search hit we cannot serve is
            // worse than no hit, and this path (unshare) is separate from set_shared(false)
            crate::deepsearch::purge_file(&db, name)?;
        }
        Ok(changed)
    }

    // ---------- peers (F2F bindings) ----------
    pub fn bind_peer(&self, fp: &str, endpoint_id: &str, pair: &str, addr: &str) -> Result<()> {
        let db = self.guard()?;
        db.execute(
            "INSERT INTO peers(fingerprint,endpoint_id,pair,addr,bound_ts) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(fingerprint) DO UPDATE SET endpoint_id=excluded.endpoint_id, pair=excluded.pair,
                                                    addr=excluded.addr, bound_ts=excluded.bound_ts",
            params![fp, endpoint_id, pair, addr, Self::now()],
        )?;
        Ok(())
    }
    /// refresh how to reach a peer (its port changes every time it comes up)
    pub fn set_peer_addr(&self, fp: &str, addr: &str) -> Result<()> {
        if addr.is_empty() {
            return Ok(()); // never erase a known-good address
        }
        let db = self.guard()?;
        db.execute("UPDATE peers SET addr=?2 WHERE fingerprint=?1", params![fp, addr])?;
        Ok(())
    }
    /// Same, keyed by iroh endpoint id. This is the authoritative way to learn an address,
    /// because the endpoint id is what both sides actually observe: the peer's fingerprint is
    /// only self-reported in a frame.
    pub fn set_peer_addr_by_endpoint(&self, endpoint_id: &str, addr: &str) -> Result<()> {
        if endpoint_id.is_empty() || addr.is_empty() {
            return Ok(());
        }
        let db = self.guard()?;
        db.execute("UPDATE peers SET addr=?2 WHERE endpoint_id=?1", params![endpoint_id, addr])?;
        Ok(())
    }
    pub fn peer_by_fp(&self, fp: &str) -> Option<(String, String)> {
        let db = self.guard().ok()?;
        db.query_row("SELECT endpoint_id,pair FROM peers WHERE fingerprint=?1", params![fp], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    }
    /// Last known address of a peer by iroh endpoint id (the key both sides agree on).
    pub fn peer_addr_by_endpoint(&self, endpoint_id: &str) -> Option<String> {
        let db = self.guard().ok()?;
        db.query_row("SELECT COALESCE(addr,'') FROM peers WHERE endpoint_id=?1", params![endpoint_id], |r| r.get::<_, String>(0))
            .ok()
            .filter(|a| !a.is_empty())
    }
    /// Is this fingerprint one of *our* bound friends? Gates the rendezvous answer so a node
    /// never becomes a free address oracle for whoever happens to connect.
    pub fn is_bound(&self, fp: &str) -> bool {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COUNT(*) FROM peers WHERE fingerprint=?1", params![fp], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0,
            Err(_) => false,
        }
    }
    /// Reverse lookup: which friend lives behind this iroh endpoint id?
    pub fn peer_by_eid(&self, endpoint_id: &str) -> Option<(String, String)> {
        let db = self.guard().ok()?;
        db.query_row("SELECT fingerprint,pair FROM peers WHERE endpoint_id=?1", params![endpoint_id], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    }

    // ---------- channels & subscriptions ----------
    pub fn create_channel(&self, name: &str, by: &str, desc: &str) -> Result<bool> {
        let db = self.guard()?;
        let ins = db.execute(
            "INSERT INTO channels(name,created_by,created_ts,desc) VALUES (?1,?2,?3,?4)",
            params![name, by, Self::now(), desc],
        )?;
        // every channel is readable/writable by default, so make sure the local subscription row exists
        db.execute(
            "INSERT OR IGNORE INTO subs(channel,reader_fp,last_seq,updated_ts) VALUES (?1,?2,0,?3)",
            params![name, by, Self::now()],
        )?;
        Ok(ins > 0)
    }
    /// Record a channel learned from a peer (does not touch our own subscription bookmarks).
    pub fn import_channel(&self, name: &str, by: &str, created_ts: i64, desc: &str) -> Result<()> {
        let db = self.guard()?;
        db.execute(
            "INSERT INTO channels(name,created_by,created_ts,desc) VALUES (?1,?2,?3,?4)
             ON CONFLICT(name) DO UPDATE SET desc=COALESCE(NULLIF(excluded.desc,''), channels.desc)",
            params![name, by, created_ts, desc],
        )?;
        Ok(())
    }
    pub fn channels(&self) -> Vec<(String, String, i64, String)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT name,created_by,created_ts,COALESCE(desc,'') FROM channels ORDER BY name") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
    /// Bookmark how far `reader` has read, returning the insertion cursor it pinned.
    /// `last_seq` is kept for display only - seq is per-author and cannot order a channel.
    pub fn mark_read(&self, channel: &str, reader: &str, last_seq: i64) -> Result<i64> {
        let db = self.guard()?;
        let cursor: i64 = db
            .query_row("SELECT COALESCE(MAX(rowid),0) FROM posts WHERE channel=?1", params![channel], |r| r.get(0))
            .unwrap_or(0);
        db.execute(
            "INSERT INTO subs(channel,reader_fp,last_seq,updated_ts,last_rowid) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(channel,reader_fp) DO UPDATE SET
                 last_seq=MAX(subs.last_seq,excluded.last_seq),
                 last_rowid=MAX(subs.last_rowid,excluded.last_rowid),
                 updated_ts=excluded.updated_ts",
            params![channel, reader, last_seq, Self::now(), cursor],
        )?;
        Ok(cursor)
    }
    /// the rowid this reader had caught up to (0 = never read)
    pub fn sub_cursor(&self, channel: &str, reader: &str) -> i64 {
        match self.guard() {
            Ok(db) => db.query_row("SELECT COALESCE(last_rowid,0) FROM subs WHERE channel=?1 AND reader_fp=?2", params![channel, reader], |r| r.get(0)).unwrap_or(0),
            Err(_) => 0,
        }
    }
    /// (channel, last read seq) for a reader.
    pub fn subs(&self, reader: &str) -> Vec<(String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT channel,last_seq FROM subs WHERE reader_fp=?1 ORDER BY channel") else { return Vec::new() };
        let Ok(rows) = st.query_map(params![reader], |r| Ok((r.get(0)?, r.get(1)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }

    // ---------- web of trust ----------
    pub fn put_cert(&self, c: &Cert) -> Result<()> {
        let db = self.guard()?;
        db.execute(
            "INSERT INTO certs(subject_fp,issuer_fp,issuer_ed,subject_ed,subject_x25519,ts,sig) VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(subject_fp,issuer_fp) DO UPDATE SET sig=excluded.sig, ts=excluded.ts",
            params![c.cert.subject_fp, c.issuer_fp, c.issuer_ed, c.cert.subject_ed, c.cert.subject_x25519, c.cert.ts, c.sig],
        )?;
        Ok(())
    }
    pub fn certs(&self) -> Vec<Cert> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT subject_fp,issuer_fp,issuer_ed,subject_ed,subject_x25519,ts,sig FROM certs ORDER BY issuer_fp, subject_fp") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| {
            Ok(Cert {
                cert: crate::wot::CertInfo {
                    subject_fp: r.get(0)?, subject_ed: r.get(3)?, subject_x25519: r.get(4)?, ts: r.get(5)?,
                },
                issuer_fp: r.get(1)?,
                issuer_ed: r.get(2)?,
                sig: r.get(6)?,
            })
        }) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
    /// Adjacency for trust scoring: every signature we hold, subject only.
    pub fn cert_edges(&self) -> Vec<crate::wot::Edge> {
        self.certs().into_iter().map(|c| crate::wot::Edge { issuer_fp: c.issuer_fp, subject_fp: c.cert.subject_fp }).collect()
    }
    pub fn set_peer_x25519(&self, fp: &str, x25519: &str) -> Result<()> {
        let db = self.guard()?;
        db.execute("UPDATE peers SET x25519=?2 WHERE fingerprint=?1", params![fp, x25519])?;
        Ok(())
    }
    /// (endpoint_id, pair, last_addr, x25519) for one friend.
    pub fn peer_full(&self, fp: &str) -> Option<(String, String, String, String)> {
        let db = self.guard().ok()?;
        db.query_row("SELECT endpoint_id,pair,COALESCE(addr,''),COALESCE(x25519,'') FROM peers WHERE fingerprint=?1", params![fp], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).ok()
    }
    pub fn peers(&self) -> Vec<(String, String, String, String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT fingerprint,endpoint_id,pair,COALESCE(addr,''),bound_ts FROM peers ORDER BY fingerprint") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }
}


/// Second impl block on purpose: appending cannot disturb the code above it, and a whole-library
/// content inventory is a different concern from per-file bookkeeping.
impl Store {
    /// Every file we hold complete, as (name, size, sha256, local_path). `local_path` is empty for
    /// files that arrived in our own `files/` directory.
    pub fn inventory(&self) -> Result<Vec<(String, i64, String, String)>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT name, size, sha256, COALESCE(local_path,'') FROM files \
             WHERE local_path IS NOT NULL OR dir = 'files'")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// How many file rows exist at all (offered or merely held).
    pub fn file_count(&self) -> i64 {
        let Ok(db) = self.guard() else { return 0 };
        db.query_row("SELECT COUNT(*) FROM files", [], |r| r.get::<_, i64>(0)).unwrap_or(0)
    }

    /// The offered subset - the right-hand side of the index-vs-truth invariant in search-status,
    /// because "searchable" means "I would hand it to a friend".
    pub fn shared_count(&self) -> i64 {
        let Ok(db) = self.guard() else { return 0 };
        db.query_row("SELECT COUNT(*) FROM files WHERE shared=1", [], |r| r.get::<_, i64>(0)).unwrap_or(0)
    }

    /// The hash we recorded for this exact name, if any. Lets a batch pull tell "already have it"
    /// from "this name holds different content".
    pub fn known_sha(&self, name: &str) -> Result<Option<String>> {
        let db = self.db.lock().unwrap();
        let row = rusqlite::OptionalExtension::optional(
            db.query_row("SELECT sha256 FROM files WHERE name = ?1 LIMIT 1", params![name],
                         |r| r.get::<_, String>(0)))?;
        Ok(row)
    }
}
/// RSS subscriptions, kept beside the posts they turn into so one database holds all local state.
/// The schema is created on demand rather than in the migration ladder: it is additive, and a
/// separate block cannot break the migrations above it.
impl Store {
    pub fn ensure_rss(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "CREATE TABLE IF NOT EXISTS rss_feeds(\
               name TEXT PRIMARY KEY, url TEXT NOT NULL, added INTEGER NOT NULL)",
            [],
        )?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS rss_seen(\
               feed TEXT NOT NULL, guid TEXT NOT NULL, PRIMARY KEY(feed, guid))",
            [],
        )?;
        Ok(())
    }

    /// Insert or re-point a subscription. Returns true when the name is new.
    pub fn add_feed(&self, name: &str, url: &str) -> Result<bool> {
        self.ensure_rss()?;
        let db = self.db.lock().unwrap();
        let existed: i64 = db
            .query_row("SELECT COUNT(*) FROM rss_feeds WHERE name=?1", params![name], |r| r.get(0))
            .unwrap_or(0);
        db.execute(
            "INSERT INTO rss_feeds(name,url,added) VALUES(?1,?2,?3) \
             ON CONFLICT(name) DO UPDATE SET url=excluded.url",
            params![name, url, Self::now()],
        )?;
        Ok(existed == 0)
    }

    pub fn feeds(&self) -> Vec<(String, String)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT name,url FROM rss_feeds ORDER BY name") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) else { return Vec::new() };
        rows.filter_map(|x| x.ok()).collect()
    }

    /// Record a guid; true when we had not seen it before. `INSERT OR IGNORE` plus the affected-row
    /// count is the whole atomicity argument - no read-then-write race between two pollers.
    pub fn note_guid(&self, feed: &str, guid: &str) -> Result<bool> {
        self.ensure_rss()?;
        let db = self.db.lock().unwrap();
        let n = db.execute("INSERT OR IGNORE INTO rss_seen(feed,guid) VALUES(?1,?2)", params![feed, guid])?;
        Ok(n == 1)
    }

    pub fn seen_count(&self, feed: &str) -> i64 {
        let Ok(db) = self.guard() else { return 0 };
        db.query_row("SELECT COUNT(*) FROM rss_seen WHERE feed=?1", params![feed], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
    }
}


/// LIKE-based search. Escaping matters: an unescaped `%` in the user's query would match
/// everything, and `_` would turn the query into a pattern - both look like "the index is broken".
impl Store {
    /// Escape LIKE metacharacters, then wrap in wildcards. Shared by both searches so they cannot
    /// drift apart; backslash is escaped first or it would double the escapes added afterwards.
    fn like_pattern(query: &str) -> String {
        let escaped = query.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        format!("%{escaped}%")
    }

    pub fn search_posts(&self, query: &str, channel: Option<&str>, limit: i64) -> Vec<(String, i64, String, String, i64)> {
        let like = Self::like_pattern(query);
        let Ok(db) = self.guard() else { return Vec::new() };
        // one statement per shape: adding a bind parameter for a filter that is absent would shift
        // every later ?N, which is exactly the kind of bug that reads back as "search finds nothing"
        let sql = match channel {
            Some(_) => "SELECT channel,seq,author,body,ts FROM posts \
                        WHERE body LIKE ?1 ESCAPE '\\' AND channel=?3 ORDER BY ts DESC LIMIT ?2",
            None => "SELECT channel,seq,author,body,ts FROM posts \
                     WHERE body LIKE ?1 ESCAPE '\\' ORDER BY ts DESC LIMIT ?2",
        };
        let mut out = Vec::new();
        if let Ok(mut st) = db.prepare(sql) {
            let rows = match channel {
                Some(ch) => st.query_map(rusqlite::params![&like, limit, ch], Self::row_post),
                None => st.query_map(rusqlite::params![&like, limit], Self::row_post),
            };
            if let Ok(rows) = rows {
                out = rows.flatten().collect();
            }
        }
        out
    }

    fn row_post(r: &rusqlite::Row) -> Result<(String, i64, String, String, i64), rusqlite::Error> {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    }

    pub fn search_files(&self, query: &str, shared_only: bool, limit: i64) -> Result<Vec<(String, i64, String)>> {
        let like = Self::like_pattern(query);
        let db = self.guard()?;
        // two complete statements rather than one assembled string: interpolating a clause into
        // SQL is how the ESCAPE literal got broken in the first place
        let sql = if shared_only {
            "SELECT name,size,COALESCE(sha256,'') FROM files \
             WHERE name LIKE ?1 ESCAPE '\\' AND shared=1 ORDER BY size DESC LIMIT ?2"
        } else {
            "SELECT name,size,COALESCE(sha256,'') FROM files \
             WHERE name LIKE ?1 ESCAPE '\\' ORDER BY size DESC LIMIT ?2"
        };
        let mut st = db.prepare(sql)?;
        let rows = st.query_map(rusqlite::params![&like, limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.flatten().collect())
    }
}

/// Ban list: refuse a fingerprint permanently, independently of whether it is already bonded.
impl Store {
    pub fn ensure_bans(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "CREATE TABLE IF NOT EXISTS bans(\
               fp TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL)",
            [],
        )?;
        Ok(())
    }

    /// true when the fingerprint was not already banned
    pub fn ban(&self, fp: &str, reason: &str) -> Result<bool> {
        self.ensure_bans()?;
        let db = self.db.lock().unwrap();
        let n = db.execute(
            "INSERT OR IGNORE INTO bans(fp,reason,ts) VALUES(?1,?2,?3)",
            params![fp, reason, Self::now()],
        )?;
        Ok(n == 1)
    }

    pub fn unban(&self, fp: &str) -> Result<bool> {
        self.ensure_bans()?;
        let db = self.db.lock().unwrap();
        Ok(db.execute("DELETE FROM bans WHERE fp=?1", params![fp])? > 0)
    }

    pub fn is_banned(&self, fp: &str) -> bool {
        let Ok(db) = self.guard() else { return false };
        db.query_row("SELECT COUNT(*) FROM bans WHERE fp=?1", params![fp], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Empty when the peer is not banned, so callers can print one string either way.
    pub fn ban_reason(&self, fp: &str) -> String {
        let Ok(db) = self.guard() else { return String::new() };
        db.query_row("SELECT reason FROM bans WHERE fp=?1", params![fp], |r| r.get::<_, String>(0))
            .unwrap_or_default()
    }

    pub fn bans(&self) -> Vec<(String, String, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT fp,reason,ts FROM bans ORDER BY ts DESC") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))) else { return Vec::new() };
        rows.flatten().collect()
    }
}

/// Circles: named sets of friends, used to restrict which channels a peer may receive.
impl Store {
    pub fn ensure_circles(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("CREATE TABLE IF NOT EXISTS circles(name TEXT PRIMARY KEY, created INTEGER NOT NULL)", [])?;
        db.execute("CREATE TABLE IF NOT EXISTS circle_members(name TEXT NOT NULL, fp TEXT NOT NULL, PRIMARY KEY(name, fp))", [])?;
        db.execute("CREATE TABLE IF NOT EXISTS channel_circles(channel TEXT PRIMARY KEY, circle TEXT NOT NULL)", [])?;
        Ok(())
    }

    pub fn create_circle(&self, name: &str) -> Result<bool> {
        self.ensure_circles()?;
        let db = self.db.lock().unwrap();
        Ok(db.execute("INSERT OR IGNORE INTO circles(name,created) VALUES(?1,?2)", params![name, Self::now()])? == 1)
    }

    pub fn circle_add(&self, name: &str, fp: &str) -> Result<bool> {
        self.ensure_circles()?;
        let db = self.db.lock().unwrap();
        if db.query_row("SELECT COUNT(*) FROM circles WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).unwrap_or(0) == 0 {
            return Err(anyhow!("no such circle: {name}"));
        }
        Ok(db.execute("INSERT OR IGNORE INTO circle_members(name,fp) VALUES(?1,?2)", params![name, fp])? == 1)
    }

    pub fn circle_remove(&self, name: &str, fp: &str) -> Result<bool> {
        self.ensure_circles()?;
        let db = self.db.lock().unwrap();
        Ok(db.execute("DELETE FROM circle_members WHERE name=?1 AND fp=?2", params![name, fp])? > 0)
    }

    pub fn circle_members(&self, name: &str) -> Vec<String> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT fp FROM circle_members WHERE name=?1 ORDER BY fp") else { return Vec::new() };
        let Ok(rows) = st.query_map(params![name], |r| r.get::<_, String>(0)) else { return Vec::new() };
        rows.flatten().collect()
    }

    // ---------- forgetting (local erasure + tombstones) ----------

    /// Rows we deliberately erased. Merge identity is `(author, channel, seq)`, so without this the
    /// next sync would restore every deleted post from the peer that still holds it.
    pub fn ensure_forget(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "CREATE TABLE IF NOT EXISTS forgotten(\
               channel TEXT NOT NULL, author TEXT NOT NULL, seq INTEGER NOT NULL, ts INTEGER NOT NULL,\
               PRIMARY KEY(channel, author, seq))",
            [],
        )?;
        Ok(())
    }

    pub fn is_forgotten(&self, channel: &str, author: &str, seq: i64) -> bool {
        let Ok(db) = self.guard() else { return false };
        db.query_row("SELECT COUNT(*) FROM forgotten WHERE channel=?1 AND author=?2 AND seq=?3",
            params![channel, author, seq], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Erase one channel's posts from this node. Returns how many rows were removed.
    /// The channel definition itself stays: an empty channel is a legitimate thing to keep, and
    /// dropping it would change another node's root for it without erasing anything.
    pub fn forget_channel(&self, channel: &str) -> Result<i64> {
        self.ensure_forget()?;
        let db = self.db.lock().unwrap();
        let rows: Vec<(i64, String, i64)> = {
            let mut st = db.prepare("SELECT seq,author,ts FROM posts WHERE channel=?1")?;
            let mapped = st.query_map(params![channel], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.flatten().collect()
        };
        for (seq, author, _ts) in &rows {
            db.execute("INSERT OR IGNORE INTO forgotten(channel,author,seq,ts) VALUES(?1,?2,?3,?4)",
                params![channel, author, seq, Self::now()])?;
            Store::purge_doc(&db, &crate::deepsearch::post_url(channel, author, *seq))?;
        }
        let n = db.execute("DELETE FROM posts WHERE channel=?1", params![channel])? as i64;
        Ok(n)
    }

    /// Erase everything received from or written by one author, across channels.
    pub fn forget_author(&self, author: &str) -> Result<i64> {
        self.ensure_forget()?;
        let db = self.db.lock().unwrap();
        let rows: Vec<(String, i64)> = {
            let mut st = db.prepare("SELECT channel,seq FROM posts WHERE author=?1")?;
            let mapped = st.query_map(params![author], |r| Ok((r.get(0)?, r.get(1)?)))?;
            mapped.flatten().collect()
        };
        for (chan, seq) in &rows {
            db.execute("INSERT OR IGNORE INTO forgotten(channel,author,seq,ts) VALUES(?1,?2,?3,?4)",
                params![chan, author, seq, Self::now()])?;
            Store::purge_doc(&db, &crate::deepsearch::post_url(chan, author, *seq))?;
        }
        let n = db.execute("DELETE FROM posts WHERE author=?1", params![author])? as i64;
        let msgs = db.execute("DELETE FROM messages WHERE peer=?1", params![author])? as i64;
        Ok(n + msgs)
    }

    pub fn forgotten(&self) -> Vec<(String, String, i64, i64)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT channel,author,seq,ts FROM forgotten ORDER BY ts DESC LIMIT 500") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))) else { return Vec::new() };
        rows.flatten().collect()
    }

    /// Circle names, ordered. A helper because its borrow ends at its own `return`: reading members
    /// inline would re-enter the same non-reentrant mutex and self-deadlock the process, which
    /// surfaces as a control-plane call that never answers.
    fn circle_names(&self) -> Vec<String> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT name FROM circles ORDER BY name") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) else { return Vec::new() };
        rows.flatten().collect()
    }

    pub fn circles(&self) -> Vec<(String, Vec<String>)> {
        self.circle_names().into_iter().map(|n| { let m = self.circle_members(&n); (n, m) }).collect()
    }

    /// Point a channel at a circle. A channel with no row here is public to every bound friend.
    pub fn restrict_channel(&self, channel: &str, circle: &str) -> Result<()> {
        self.ensure_circles()?;
        let db = self.db.lock().unwrap();
        if db.query_row("SELECT COUNT(*) FROM circles WHERE name=?1", params![circle], |r| r.get::<_, i64>(0)).unwrap_or(0) == 0 {
            return Err(anyhow!("no such circle: {circle}"));
        }
        db.execute(
            "INSERT INTO channel_circles(channel,circle) VALUES(?1,?2) ON CONFLICT(channel) DO UPDATE SET circle=excluded.circle",
            params![channel, circle],
        )?;
        Ok(())
    }

    pub fn unrestrict_channel(&self, channel: &str) -> Result<bool> {
        self.ensure_circles()?;
        let db = self.db.lock().unwrap();
        Ok(db.execute("DELETE FROM channel_circles WHERE channel=?1", params![channel])? > 0)
    }

    pub fn channel_circle(&self, channel: &str) -> Option<String> {
        let Ok(db) = self.guard() else { return None };
        db.query_row("SELECT circle FROM channel_circles WHERE channel=?1", params![channel], |r| r.get::<_, String>(0)).ok()
    }

    /// The single question the wire protocol asks per (channel, requesting peer).
    ///
    /// The owner is always allowed, so a node still syncs its own restricted channel with itself
    /// and its local view never depends on membership bookkeeping.
    pub fn may_send_channel(&self, channel: &str, peer_fp: &str, my_fp: &str) -> bool {
        match self.channel_circle(channel) {
            None => true,
            Some(circle) => peer_fp == my_fp || self.circle_members(&circle).iter().any(|m| m == peer_fp),
        }
    }

    pub fn restricted_channels(&self) -> Vec<(String, String)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT channel,circle FROM channel_circles ORDER BY channel") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) else { return Vec::new() };
        rows.flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rsnext-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("rsnext.db");
        (Store::open(&db.to_string_lossy()).unwrap(), dir)
    }

    #[test]
    fn roots_are_per_channel_so_one_channel_cannot_invalidate_another() {
        let (st, _d) = tmp_store("roots");
        st.add_post_to("general", "A", "gossip").unwrap();
        let general_only = crate_root(&st, "general");
        st.add_post_to("crypto", "A", "channel specific").unwrap();
        assert_eq!(crate_root(&st, "general"), general_only, "posting in another channel must not move the general root");
        assert_ne!(crate_root(&st, "crypto"), general_only, "the new channel has its own log");
        assert_eq!(st.posts_in("general").len(), 1);
        assert_eq!(st.posts_in("crypto").len(), 1);
    }

    #[test]
    fn one_author_can_post_in_two_channels() {
        // this is the case the old (author, seq) primary key made impossible: the same author's
        // first post in each channel is seq 1, which used to collide and error out
        let (st, _d) = tmp_store("cross-channel");
        st.add_post_to("general", "A", "hello").unwrap();
        st.add_post_to("crypto", "A", "also seq 1").unwrap();
        assert_eq!(st.posts_in("general").len(), 1);
        assert_eq!(st.posts_in("crypto").len(), 1);
        assert_eq!(st.posts_everywhere().len(), 2);
    }

    #[test]
    fn two_authors_with_the_same_seq_do_not_collide() {
        let (st, _d) = tmp_store("seq");
        st.add_post_to("tech", "A", "one").unwrap();
        st.add_post_to("tech", "B", "two").unwrap();
        // both are seq 1 for their own author; the merge key keeps both
        assert_eq!(st.posts_in("tech").len(), 2);
    }

    #[test]
    fn unread_counts_off_the_bookmark_not_a_cross_author_seq() {
        let (st, _d) = tmp_store("unread");
        st.add_post_to("tech", "AAAAAAAA", "a1").unwrap();
        st.add_post_to("tech", "AAAAAAAA", "a2").unwrap();
        st.add_post_to("tech", "BBBBBBBB", "b1").unwrap();
        // unread follows the local insertion cursor: never a per-author seq, never a
        // unix-seconds timestamp (a post landing in the same second as the read used to vanish)
        assert_eq!(st.unread_for("tech", "reader"), 3, "never read => everything unread");
        let cursor = st.mark_read("tech", "reader", 2).unwrap();
        assert!(cursor > 0, "mark_read returns the cursor it pinned");
        assert_eq!(st.unread_for("tech", "reader"), 0, "caught up => nothing unread");
        st.add_post_to("tech", "BBBBBBBB", "same-second arrival").unwrap();
        assert_eq!(st.unread_for("tech", "reader"), 1, "an arrival in the same second is still unread");
        // b1 carries seq 1 - a seq-based rule would have called it read once A reached 2
        let seqs: Vec<i64> = st.posts_in("tech").into_iter().map(|(seq, ..)| seq).collect();
        assert_eq!(seqs.iter().filter(|s| **s == 1).count(), 2, "two authors may both sit at seq 1");
    }

    #[test]
    fn channels_learned_from_a_peer_are_recorded_without_touching_our_bookmarks() {
        let (st, _d) = tmp_store("import");
        st.import_channel("music", "peer-x", 100, "songs").unwrap();
        st.import_channel("music", "peer-x", 100, "songs").unwrap(); // idempotent
        assert_eq!(st.channels().iter().filter(|c| c.0 == "music").count(), 1);
        assert!(st.subs("local-reader").is_empty(), "importing a channel must not fabricate a read position");
    }

    #[test]
    fn a_restricted_channel_is_only_sendable_to_its_circle() {
        let st = Store::open(":memory:").unwrap();
        // the default is open, so existing deployments keep their behaviour
        assert!(st.may_send_channel("general", "ANYONE", "ME"));
        st.create_circle("family").unwrap();
        st.circle_add("family", "BOB").unwrap();
        // must not self-deadlock: circles() takes the lock and then reads members
        let cs = st.circles();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].0, "family");
        assert_eq!(cs[0].1, vec!["BOB".to_string()]);
        st.restrict_channel("private", "family").unwrap();
        assert!(st.may_send_channel("private", "BOB", "ME"), "a member receives it");
        assert!(!st.may_send_channel("private", "CAROL", "ME"), "a bound friend outside the circle does not");
        assert!(st.may_send_channel("private", "ME", "ME"), "the owner always keeps full access");
        assert!(st.may_send_channel("general", "CAROL", "ME"), "unrestricted channels are unaffected");
        // removing a member takes effect immediately: membership, not history, decides
        st.circle_remove("family", "BOB").unwrap();
        assert!(!st.may_send_channel("private", "BOB", "ME"));
        // a second circle can be opened up again per channel
        st.unrestrict_channel("private").unwrap();
        assert!(st.may_send_channel("private", "CAROL", "ME"));
        // restricting to a circle that does not exist is refused rather than silently public
        assert!(st.restrict_channel("x", "nope").is_err());
    }

    #[test]
    fn forgetting_survives_the_next_sync() {
        let st = Store::open(":memory:").unwrap();
        st.add_post_to("crypto", "AAAA", "secret plans").unwrap();
        st.add_post_to("crypto", "BBBB", "other keeps").unwrap();
        assert_eq!(st.deep_doc_count("post"), 2, "index holds both before the erase");

        assert_eq!(st.forget_channel("crypto").unwrap(), 2);
        assert!(st.posts_in("crypto").is_empty(), "rows are gone locally");
        assert_eq!(st.deep_doc_count("post"), 0, "erased posts must leave the search index too");

        // the peer's copy arrives again on the next sync: this is exactly what the tombstone stops
        st.insert_post_row_in("crypto", 1, "AAAA", "secret plans", 100).unwrap();
        assert!(st.posts_in("crypto").is_empty(), "a forgotten row came back from a peer");

        // a different row of the same author, never forgotten, still merges normally
        st.insert_post_row_in("crypto", 3, "AAAA", "brand new", 200).unwrap();
        assert_eq!(st.posts_in("crypto").len(), 1, "tombstones must not block new content");
        assert_eq!(st.deep_doc_count("post"), 1, "new content is indexed again");

        // and per-author erasure reaches across channels
        st.add_post_to("general", "AAAA", "also private").unwrap();
        assert_eq!(st.forget_author("AAAA").unwrap(), 2);
        assert!(st.posts_in("general").is_empty() && st.posts_in("crypto").is_empty());
        assert_eq!(st.deep_doc_count("post"), 0);
    }

    #[test]
    fn an_erased_sequence_number_is_never_handed_out_again() {
        // the bug this pins: seq was allocated from live rows only, so after erasing (author,
        // channel, 1..2) the next post took seq 1 again - two different bodies then shared the
        // merge identity, receivers dropped the new one as a duplicate, and replicas' roots
        // diverged while every convergence test still passed
        let st = Store::open(":memory:").unwrap();
        assert_eq!(st.add_post_to("notes", "AAAA", "one").unwrap(), 1);
        assert_eq!(st.add_post_to("notes", "AAAA", "two").unwrap(), 2);
        st.forget_channel("notes").unwrap();
        assert_eq!(st.add_post_to("notes", "AAAA", "three").unwrap(), 3, "must not reuse 1");
        let rows = st.posts_in("notes");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 3, "the surviving row keeps a fresh number");
        // other authors keep their own counters, and the tombstone does not block them
        assert_eq!(st.add_post_to("notes", "BBBB", "b-one").unwrap(), 1);
        st.forget_channel("notes").unwrap();
        assert_eq!(st.add_post_to("notes", "BBBB", "b-two").unwrap(), 2);
    }

    fn crate_root(st: &Store, channel: &str) -> String {
        use crate::merkle::{leaf_hash, merkle_root};
        let leaves: Vec<[u8; 32]> = st.posts_in(channel).into_iter().map(|(seq, author, body, ts)| leaf_hash(seq, &author, &body, ts)).collect();
        hex::encode(merkle_root(&leaves))
    }
}