//! Deep search: a persistent inverted index over local content, shaped after upstream
//! `libretroshare/src/deep_search/` (one indexer per content kind, documents identified by a
//! `retroshare://` URL, results carrying a weight and a snippet).
//!
//! Two deliberate differences from upstream, both because we are not Xapian:
//!   * upstream fires `indexX()/removeXFromIndex()` signals from outside the database, because the
//!     index is a separate Xapian file. Here the index lives in the same SQLite database, so
//!     indexing happens *inside* the mutator under the same lock: a write path cannot forget to
//!     update the index, and there is no queue to drain (upstream's `StubbornWriteOpQueue` exists
//!     only to work around Xapian's single-writer database).
//!   * ranking is BM25 rather than Xapian's term-proximity model: no stemming, no phrase boosts,
//!     but it is explainable, testable, and needs no C++ dependency.

use crate::store::Store;
use anyhow::Result;
use rusqlite::{params, Connection};

/// Content kinds with an indexer. Adding a kind = adding a source query in `rebuild`.
pub const KIND_POST: &str = "post";
pub const KIND_FILE: &str = "file";

/// Document identity, mirroring upstream's `mUrl`: a search hit must be actionable without
/// re-deriving where it came from.
pub fn post_url(channel: &str, author: &str, seq: i64) -> String {
    format!("retroshare://post/{channel}/{author}/{seq}")
}
pub fn file_url(name: &str) -> String {
    format!("retroshare://file/{name}")
}

/// Schema in one place, so `ensure_deep` and the in-lock helpers cannot drift apart.
const DDL: &str = "CREATE TABLE IF NOT EXISTS ds_docs(
     url TEXT PRIMARY KEY, kind TEXT NOT NULL, channel TEXT, ts INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS ds_terms(
     term TEXT NOT NULL, url TEXT NOT NULL, tf INTEGER NOT NULL, PRIMARY KEY(term, url));
   CREATE INDEX IF NOT EXISTS ds_terms_url ON ds_terms(url);
   CREATE INDEX IF NOT EXISTS ds_docs_kind ON ds_docs(kind);";

/// Called from Store's mutators while they already hold the write lock. Creating tables on demand
/// is deliberate: an index that only exists after somebody remembers to call setup() is an index
/// that silently returns nothing.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(DDL)?;
    Ok(())
}

pub fn index_post(conn: &Connection, url: &str, channel: &str, text: &str, ts: i64) -> Result<()> {
    ensure_schema(conn)?;
    Store::index_doc(conn, &Doc { url, kind: KIND_POST, channel: Some(channel), text, ts })
}

pub fn index_file(conn: &Connection, name: &str, sha: &str, path: &str) -> Result<()> {
    ensure_schema(conn)?;
    let url = file_url(name);
    let text = format!("{name} {sha} {path}");
    Store::index_doc(conn, &Doc { url: &url, kind: KIND_FILE, channel: None, text: &text, ts: 0 })
}

pub fn purge_file(conn: &Connection, name: &str) -> Result<()> {
    ensure_schema(conn)?;
    Store::purge_doc(conn, &file_url(name))
}

pub struct Doc<'a> {
    pub url: &'a str,
    pub kind: &'a str,
    pub channel: Option<&'a str>,
    pub text: &'a str,
    pub ts: i64,
}

/// Lowercase alphanumeric tokens, length >= 3 (the same threshold upstream's Xapian setup ends up
/// with after stop-word filtering; short tokens make the postings lists huge for no recall gain).
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '_')) {
        let w = raw.trim_matches('\'').to_lowercase();
        if w.len() >= 3 {
            out.push(w);
        }
    }
    out
}

/// BM25 with k1=1.2, b=0.75. Split out as a pure function so the monotonicity properties that
/// matter (more occurrences -> better, more documents containing it -> worse) are testable.
pub fn bm25(tf: f64, df: f64, n_docs: f64, dl: f64, avgdl: f64) -> f64 {
    let (k1, b) = (1.2f64, 0.75f64);
    let df = df.max(1.0);
    let idf = ((n_docs - df + 0.5) / (df + 0.5) + 1.0).ln();
    let norm = k1 * (1.0 - b + b * (dl / avgdl.max(1.0)));
    idf * ((tf * (k1 + 1.0)) / (tf + norm))
}

impl Store {
    pub fn ensure_deep(&self) -> Result<()> {
        let db = self.conn();
        ensure_schema(&db)?;
        Ok(())
    }

    /// (Re)index one document, replacing any previous terms for it. Takes the connection so the
    /// caller can keep it inside the same write as the row itself.
    pub fn index_doc(conn: &Connection, doc: &Doc) -> Result<()> {
        let mut seen: Vec<(String, i64)> = Vec::new();
        for t in tokenize(doc.text) {
            match seen.iter_mut().find(|(k, _)| *k == t) {
                Some((_, c)) => *c += 1,
                None => seen.push((t, 1)),
            }
        }
        Self::purge_doc(conn, doc.url)?;
        conn.execute(
            "INSERT INTO ds_docs(url,kind,channel,ts) VALUES(?1,?2,?3,?4)",
            params![doc.url, doc.kind, doc.channel, doc.ts],
        )?;
        for (t, c) in &seen {
            conn.execute("INSERT OR REPLACE INTO ds_terms(term,url,tf) VALUES(?1,?2,?3)", params![t, doc.url, c])?;
        }
        Ok(())
    }

    pub fn purge_doc(conn: &Connection, url: &str) -> Result<()> {
        conn.execute("DELETE FROM ds_terms WHERE url=?1", params![url])?;
        conn.execute("DELETE FROM ds_docs WHERE url=?1", params![url])?;
        Ok(())
    }

    fn indexed_doc_count(db: &Connection, kind: Option<&str>) -> f64 {
        let r = match kind {
            Some(k) => db.query_row("SELECT COUNT(*) FROM ds_docs WHERE kind=?1", params![k], |r| r.get::<_, i64>(0)),
            None => db.query_row("SELECT COUNT(*) FROM ds_docs", [], |r| r.get::<_, i64>(0)),
        };
        r.unwrap_or(0) as f64
    }

    /// Query the index. Terms are AND-ed (a document must contain every token), which is what makes
    /// a wildcard-looking query harmless: `%` tokenises to nothing, so it matches nothing rather
    /// than everything.
    pub fn deep_search(&self, query: &str, channel: Option<&str>, max: i64) -> Result<Vec<(String, f64, String)>> {
        let terms = {
            let mut v = tokenize(query);
            v.sort();
            v.dedup();
            v
        };
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        // NOT self.ensure_deep(): that would take the same non-reentrant mutex a second time and
        // deadlock. The schema helper must work on the connection we already hold.
        let db = self.conn();
        ensure_schema(&db)?;
        let n = Self::indexed_doc_count(&db, None).max(1.0);
        let avgdl: f64 = db
            .query_row(
                "SELECT COALESCE(AVG(len),1) FROM (SELECT url, SUM(tf) AS len FROM ds_terms GROUP BY url)",
                [],
                |r| r.get::<_, f64>(0),
            )
            .unwrap_or(1.0);

        let mut scores: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut cand: Option<Vec<String>> = None;
        for t in &terms {
            let mut st = db.prepare("SELECT url, tf FROM ds_terms WHERE term=?1")?;
            let rows: Vec<(String, i64)> = st
                .query_map(params![t], |r| Ok((r.get(0)?, r.get(1)?)))?
                .flatten()
                .collect();
            let df = rows.len() as f64;
            let urls: Vec<String> = rows.iter().map(|(u, _)| u.clone()).collect();
            cand = Some(match cand {
                None => urls.clone(),
                Some(prev) => prev.into_iter().filter(|u| urls.contains(u)).collect(),
            });
            for (u, tf) in &rows {
                let dl: f64 = db
                    .query_row("SELECT COALESCE(SUM(tf),1) FROM ds_terms WHERE url=?1", params![u], |r| r.get::<_, f64>(0))
                    .unwrap_or(1.0);
                *scores.entry(u.clone()).or_insert(0.0) += bm25(*tf as f64, df, n, dl, avgdl);
            }
        }
        let kept = cand.unwrap_or_default();
        let mut hits: Vec<(String, f64, String)> = Vec::new();
        for u in kept {
            let Some(score) = scores.get(&u) else { continue };
            let (kind, chan): (String, Option<String>) =
                match db.query_row("SELECT kind, channel FROM ds_docs WHERE url=?1", params![&u], |r| Ok((r.get(0)?, r.get(1)?))) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            if let Some(want) = channel {
                if chan.as_deref() != Some(want) {
                    continue;
                }
            }
            let snippet = match kind.as_str() {
                KIND_FILE => u.rsplit('/').next().unwrap_or(&u).to_string(),
                _ => {
                    let body: String = db
                        .query_row(
                            "SELECT body FROM posts WHERE ?1 = 'retroshare://post/' || channel || '/' || author || '/' || seq",
                            params![&u],
                            |r| r.get(0),
                        )
                        .unwrap_or_default();
                    let flat: String = body.chars().take(90).collect();
                    flat
                }
            };
            hits.push((u, *score, snippet));
        }
        hits.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(&b.0)));
        hits.truncate(max.max(1) as usize);
        Ok(hits)
    }

    /// Rebuild from truth. Cheap enough to be the repair path when `deep_stats` disagrees.
    pub fn deep_rebuild(&self) -> Result<(i64, i64)> {
        self.ensure_deep()?;
        let db = self.conn();
        db.execute("DELETE FROM ds_terms", [])?;
        db.execute("DELETE FROM ds_docs", [])?;
        let mut posts = 0i64;
        let mut files = 0i64;
        {
            let mut st = db.prepare("SELECT channel,author,seq,body,ts FROM posts")?;
            let rows: Vec<(String, String, i64, String, i64)> = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .flatten()
                .collect();
            for (ch, author, seq, body, ts) in &rows {
                let url = post_url(ch, author, *seq);
                Self::index_doc(&db, &Doc { url: &url, kind: KIND_POST, channel: Some(ch), text: body, ts: *ts })?;
                posts += 1;
            }
        }
        {
            // WHERE shared=1: rebuild has to reproduce exactly what the incremental hooks hold,
            // otherwise rebuilding silently changes the searchable set
            let mut st = db.prepare(
                "SELECT name, COALESCE(sha256,''), COALESCE(local_path,'') FROM files WHERE shared=1")?;
            let rows: Vec<(String, String, String)> = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .flatten()
                .collect();
            for (name, sha, lp) in &rows {
                let text = format!("{name} {sha} {lp}");
                let url = file_url(name);
                Self::index_doc(&db, &Doc { url: &url, kind: KIND_FILE, channel: None, text: &text, ts: 0 })?;
                files += 1;
            }
        }
        Ok((posts, files))
    }

    /// (docs, terms) currently in the index - the invariant a gate asserts against truth.
    pub fn deep_stats(&self) -> (i64, i64) {
        let Ok(db) = self.guard() else { return (0, 0) };
        let d = db.query_row("SELECT COUNT(*) FROM ds_docs", [], |r| r.get::<_, i64>(0)).unwrap_or(0);
        let t = db.query_row("SELECT COUNT(*) FROM ds_terms", [], |r| r.get::<_, i64>(0)).unwrap_or(0);
        (d, t)
    }

    pub fn deep_doc_count(&self, kind: &str) -> i64 {
        Self::indexed_doc_count(&self.conn(), Some(kind)) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_drops_short_words_and_case() {
        let v = tokenize("RetroShare: the F2F io net");
        assert_eq!(
            v,
            vec!["retroshare".to_string(), "the".to_string(), "f2f".to_string(), "net".to_string()],
            "case folds, punctuation splits, length >= 3 keeps; no stop-word list (upstream gets that from Xapian, we do not pretend)");
    }

    #[test]
    fn bm25_is_monotonic_in_tf_and_inverse_in_df() {
        let a = bm25(1.0, 10.0, 100.0, 10.0, 10.0);
        let b = bm25(5.0, 10.0, 100.0, 10.0, 10.0);
        let common = bm25(1.0, 90.0, 100.0, 10.0, 10.0);
        assert!(b > a, "more occurrences must outrank fewer: {a} vs {b}");
        assert!(a > common, "a rarer term must outrank a ubiquitous one: {a} vs {common}");
    }

    #[test]
    fn search_ands_terms_and_ranks_by_weight() {
        let st = Store::open(":memory:").unwrap();
        DeepHarness::seed(&st, &[
                ("retroshare://post/crypto/A/1", "merkle tree sync for channels"),
                ("retroshare://post/crypto/A/2", "merkle tree merkle tree merkle"),
                ("retroshare://post/general/B/1", "unrelated gossip about weather"),
        ]);
        let one = st.deep_search("merkle", None, 10).unwrap();
        assert_eq!(one.len(), 2, "both merkle docs found");
        assert!(one[0].0.ends_with("/A/2"), "the document repeating the term ranks first: {:?}", one.iter().map(|h| (h.0.clone(), h.1)).collect::<Vec<_>>());

        // AND semantics: a document containing only one of the terms is not a hit
        let two = st.deep_search("merkle weather", None, 10).unwrap();
        assert!(two.is_empty(), "terms are intersected, not unioned: {two:?}");

        // channel scoping survives ranking
        let scoped = st.deep_search("merkle", Some("crypto"), 10).unwrap();
        assert_eq!(scoped.len(), 2);
        assert!(st.deep_search("merkle", Some("general"), 10).unwrap().is_empty());
    }

    #[test]
    fn wildcard_looking_queries_match_nothing() {
        // the LIKE version had to escape these; a tokeniser has no metacharacters at all, which is
        // why "% must not dump the corpus" is now structural rather than a bug we remember to fix
        let st = Store::open(":memory:").unwrap();
        DeepHarness::seed(&st, &[("retroshare://post/crypto/A/1", "alpha beta")]);
        // Two different properties, and only one of them is "must be empty":
        //   * a query with no words in it matches nothing (it can never dump the corpus)
        //   * a query that merely *looks* like a wildcard is handled as words: `%alpha%` contains
        //     the word alpha, so it matches exactly as `alpha` would. There is no wildcard
        //     semantics left to escape - which is the point of tokenising instead of LIKE.
        for q in ["%", "_", "%%", "' OR 1=1 --", "..."] {
            assert!(st.deep_search(q, None, 50).unwrap().is_empty(), "wordless query {q:?} leaked results");
        }
        assert_eq!(st.deep_search("%alpha%", None, 50).unwrap().len(), 1, "%alpha% behaves as alpha");
        assert_eq!(st.deep_search("alpha", None, 50).unwrap().len(), 1, "index itself works");
    }

    #[test]
    fn repurging_a_document_removes_its_terms() {
        let st = Store::open(":memory:").unwrap();
        DeepHarness::seed(&st, &[("retroshare://post/crypto/A/1", "ephemeral note")]);
        assert_eq!(st.deep_search("ephemeral", None, 10).unwrap().len(), 1);
        {
            let db = st.conn();
            ensure_schema(&db).unwrap();
            Store::purge_doc(&db, "retroshare://post/crypto/A/1").unwrap();
        }
        assert!(st.deep_search("ephemeral", None, 10).unwrap().is_empty(), "stale hit after removal");
        let (docs, terms) = st.deep_stats();
        assert_eq!(docs, 0, "doc row left behind: {docs}");
        assert_eq!(terms, 0, "postings left behind: {terms}");
    }

    /// Seeding goes through `insert_post_row_in` - the same entry point peer replication uses - so
    /// these tests fail if a production write path ever stops maintaining the index. Inserting
    /// rows by hand here would test the index in isolation and prove nothing about the hooks.
    struct DeepHarness;
    impl DeepHarness {
        fn seed(st: &Store, docs: &[(&str, &str)]) {
            for (url, text) in docs {
                let parts: Vec<&str> = url.split('/').collect();
                let ch = parts.get(3).copied().unwrap_or("general");
                let author = parts.get(4).copied().unwrap_or("A");
                let seq: i64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(1);
                st.insert_post_row_in(ch, seq, author, text, seq).unwrap();
            }
        }
    }
}
