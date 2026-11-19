//! Feed service: RSS 2.0 / Atom polling for the local node.
//!
//! Split out of `net` on purpose. A feed poll touches no peer and no connection - it is the local
//! node fetching from the clear web and turning unseen items into channel posts, which then ride
//! the ordinary replication path. Keeping it in the transport module made that boundary invisible.

use crate::dir_paths;
use crate::net::fp_self;
use anyhow::{anyhow, Result};
use rsnext_core::store::Store;

/// Fetch one feed document. Hard size cap: a poller runs unattended against hosts that may be
/// broken or hostile, and reading an unbounded response into memory is how it dies at 3am.
pub fn fetch_feed(url: &str) -> Result<String> {
    const MAX_FEED_BYTES: usize = 4 << 20;
    let resp = ureq::get(url).call().map_err(|e| anyhow!("fetch {url}: {e}"))?;
    let mut reader = resp.into_reader();
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16384];
    loop {
        let n = std::io::Read::read(&mut reader, &mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_FEED_BYTES {
            return Err(anyhow!("feed at {url} exceeds the {MAX_FEED_BYTES} byte cap; refusing to buffer it"));
        }
    }
    // feeds lie about encoding far more often than they honour it; lossy beats a hard failure
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Poll subscriptions: every unseen guid becomes a post in a channel named after the feed, which
/// means RSS inherits the merkle replication, unread counters and trust model for free.
pub fn rss_fetch(dir: &str, only: Option<&str>) -> Result<serde_json::Value> {
    let store = Store::open(&dir_paths(dir)?.join("rsnext.db").to_string_lossy())?;
    let me = fp_self(dir)?;
    let all = store.feeds();
    if let Some(want) = only {
        if !all.iter().any(|(n, _)| n == want) {
            return Err(anyhow!("no subscription named {want} (known: {})", all.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")));
        }
    }
    let mut out = Vec::new();
    let subs = all.len();
    for (name, url) in all {
        if let Some(want) = only {
            if want != name {
                continue;
            }
        }
        // a channel that does not exist yet must still exist even if the feed is empty, so the
        // subscription is visible in channel-list
        store.create_channel(&name, &me, &format!("RSS {url}")).ok();
        match fetch_feed(&url) {
            Err(e) => out.push(serde_json::json!({ "feed": name, "url": url, "error": format!("{e:#}") })),
            Ok(body) => {
                let items = rsnext_core::rss::parse_feed(&body);
                let parsed = items.len();
                let mut posted = 0usize;
                for it in &items {
                    if !store.note_guid(&name, &it.guid)? {
                        continue;
                    }
                    let text = if it.link.is_empty() { it.title.clone() } else { format!("{} — {}", it.title, it.link) };
                    store.add_post_to(&name, &me, &text)?;
                    posted += 1;
                }
                out.push(serde_json::json!({ "feed": name, "url": url, "items": parsed, "posted": posted }));
            }
        }
    }
    Ok(serde_json::json!({ "feeds": out, "subscriptions": subs }))
}
