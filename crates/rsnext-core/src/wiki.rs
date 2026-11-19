//! Collaborative wiki over the channel log (upstream: `libretroshare/src/retroshare/rswiki.h`).
//!
//! A page is a channel named `wiki/<slug>`; every save appends the full text as a revision post.
//! Nothing is overwritten, so replication is ordinary post merge and the per-channel merkle root
//! already proves convergence - a wiki needs no new sync mechanism, only a rule for "which
//! revision is current".
//!
//! That rule lives here as one pure function. Two replicas that disagree about it would disagree
//! about the page while agreeing about every byte stored, which is the worst kind of divergence,
//! so it is total and deterministic: newest `ts` wins, ties broken by `(author, seq)`.
//!
//! Resolution caveat, stated because users hit it: `ts` is whole seconds, so same-second saves
//! are routine. The tie-break is arbitrary but total, and nothing is lost - every revision
//! stays in `wiki_history`. What the gates assert is that all replicas pick the SAME current
//! revision; "my edit wins" is not something a one-second clock can promise.

use crate::store::Store;
use anyhow::{Result, anyhow};

pub const PREFIX: &str = "wiki/";

/// Page names are channel names, and channel names travel in the wire protocol as plain strings,
/// so keep them to a conservative alphabet rather than sanitising at every use site.
pub fn page_channel(page: &str) -> Result<String> {
    let p = page.trim();
    if p.is_empty() || p.len() > 64 {
        return Err(anyhow!("page name must be 1-64 bytes"));
    }
    if !p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(anyhow!("page name may use letters, digits, '-', '_', '.' (got {p:?})"));
    }
    Ok(format!("{PREFIX}{p}"))
}

pub fn is_wiki_channel(channel: &str) -> bool {
    channel.starts_with(PREFIX)
}

pub fn page_of(channel: &str) -> &str {
    channel.strip_prefix(PREFIX).unwrap_or(channel)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub seq: i64,
    pub author: String,
    pub body: String,
    pub ts: i64,
}

/// The current revision: highest ts, then author, then seq. The order is total, so two replicas
/// holding the same set of revisions pick the same winner regardless of arrival order - which is
/// what makes returning the element (not an index) the right shape.
pub fn resolve_current(revs: &[Revision]) -> Option<&Revision> {
    revs.iter()
        .max_by(|a, b| (a.ts, &a.author, a.seq).cmp(&(b.ts, &b.author, b.seq)))
}

impl Store {
    /// Create the page if it does not exist. Returns true when it is new.
    /// `create_channel` rejects a duplicate name as an error, which is right for an explicit
    /// `channel-create` but wrong here: opening a page you already have is not a failure.
    pub fn wiki_open(&self, page: &str, by: &str) -> Result<bool> {
        let ch = page_channel(page)?;
        if self.channels().into_iter().any(|(name, _, _, _)| name == ch) {
            return Ok(false);
        }
        self.create_channel(&ch, by, "wiki page")
    }

    pub fn wiki_save(&self, page: &str, author: &str, text: &str) -> Result<i64> {
        let ch = page_channel(page)?;
        if text.trim().is_empty() {
            return Err(anyhow!("refusing to save an empty page body"));
        }
        // register the page even when the first action was a save, or wiki_pages() would miss a
        // page that demonstrably has content
        self.wiki_open(page, author)?;
        self.add_post_to(&ch, author, text)
    }

    pub fn wiki_pages(&self) -> Vec<String> {
        self.channels()
            .into_iter()
            .map(|(name, _by, _ts, _desc)| name)
            .filter(|c| is_wiki_channel(c))
            .map(|c| page_of(c.as_str()).to_string())
            .collect()
    }

    pub fn wiki_history(&self, page: &str) -> Vec<Revision> {
        let ch = match page_channel(page) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        self.posts_in(&ch)
            .into_iter()
            .map(|(seq, author, body, ts)| Revision { seq, author, body, ts })
            .collect()
    }

    pub fn wiki_current(&self, page: &str) -> Option<Revision> {
        let revs = self.wiki_history(page);
        resolve_current(&revs).map(|r| Revision {
            seq: r.seq,
            author: r.author.clone(),
            body: r.body.clone(),
            ts: r.ts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(seq: i64, author: &str, body: &str, ts: i64) -> Revision {
        Revision { seq, author: author.into(), body: body.into(), ts }
    }

    #[test]
    fn page_names_are_channels_with_a_reserved_prefix() {
        assert_eq!(page_channel("Getting-Started").unwrap(), "wiki/Getting-Started");
        assert!(is_wiki_channel("wiki/x"));
        assert!(!is_wiki_channel("general"));
        assert_eq!(page_of("wiki/x"), "x");
        // the wire format is space-separated frames, and '/' would collide with channel names
        for bad in ["", "a b", "a/b", "a\nb", "日本", &"x".repeat(65)] {
            assert!(page_channel(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    fn winner(v: &[Revision]) -> Option<String> {
        resolve_current(v).map(|r| r.body.clone())
    }

    #[test]
    fn a_strictly_newer_save_wins_even_against_a_higher_author() {
        // what a wiki needs: writing later beats writing as a "larger" identity, otherwise a save
        // is invisible for a second with no indication to the user
        let v = vec![rev(1, "FFFF", "senior author", 200), rev(1, "AAAA", "late edit", 201)];
        assert_eq!(winner(&v).as_deref(), Some("late edit"));
        let r: Vec<Revision> = v.iter().rev().cloned().collect();
        assert_eq!(winner(&r), winner(&v), "input order must not matter");
    }

    #[test]
    fn newest_timestamp_is_current() {
        let v = vec![rev(1, "A", "first", 100), rev(2, "A", "second", 200), rev(1, "B", "third", 150)];
        assert_eq!(winner(&v).as_deref(), Some("second"));
    }

    #[test]
    fn ties_are_broken_by_content_not_by_arrival_order() {
        // two edits inside the same second is normal at one-second clock resolution. If the winner
        // depended on which row arrived first, two replicas would show different pages while
        // holding byte-identical logs and identical merkle roots - undetectable from the outside.
        let a = vec![rev(3, "AAAA", "mine", 200), rev(1, "BBBB", "theirs", 200)];
        let b = vec![rev(1, "BBBB", "theirs", 200), rev(3, "AAAA", "mine", 200)];
        assert_eq!(winner(&a), winner(&b), "arrival order must not decide");
        assert_eq!(winner(&a).as_deref(), Some("theirs"), "higher author fingerprint wins the tie");

        let c = vec![rev(1, "AAAA", "one", 200), rev(2, "AAAA", "two", 200)];
        let d = vec![rev(2, "AAAA", "two", 200), rev(1, "AAAA", "one", 200)];
        assert_eq!(winner(&c), winner(&d));
        assert_eq!(winner(&c).as_deref(), Some("two"), "same author, same second -> higher seq");

        // an empty page has no current revision rather than a panic
        assert!(resolve_current(&[]).is_none());
    }

    #[test]
    fn saving_appends_revisions_and_history_is_full() {
        let st = Store::open(":memory:").unwrap();
        assert!(st.wiki_open("Manual", "A").unwrap(), "first open creates the page");
        assert!(!st.wiki_open("Manual", "A").unwrap(), "second open is not a new page");
        st.wiki_save("Manual", "A", "v1").unwrap();
        st.wiki_save("Manual", "B", "v2").unwrap();
        assert_eq!(st.wiki_history("Manual").len(), 2, "saves never overwrite history");
        assert_eq!(st.wiki_current("Manual").unwrap().body, "v2");
        assert_eq!(st.wiki_pages(), vec!["Manual".to_string()]);
        assert!(st.wiki_save("Manual", "A", "   ").is_err(), "an empty body must not shadow the page");
        assert!(st.wiki_history("nope").is_empty());
        assert!(st.wiki_current("nope").is_none());
    }

    #[test]
    fn wiki_revisions_do_not_disturb_ordinary_channels() {
        let st = Store::open(":memory:").unwrap();
        st.create_channel("crypto", "A", "").unwrap();
        st.add_post_to("crypto", "A", "not a page").unwrap();
        st.wiki_open("Manual", "A").unwrap();
        st.wiki_save("Manual", "A", "page body").unwrap();
        // the wiki sits on top of channels, so a plain channel must not appear as a page
        assert_eq!(st.wiki_pages(), vec!["Manual".to_string()]);
        assert_eq!(st.posts_in("crypto").len(), 1);
        assert_eq!(st.posts_in("wiki/Manual").len(), 1);
    }
}
