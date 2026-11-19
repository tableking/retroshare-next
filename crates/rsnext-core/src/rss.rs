//! RSS 2.0 / Atom feed parsing - no XML dependency.
//!
//! Why hand-rolled: the crate we would need (a real XML reader) is not in the offline registry,
//! and feeds only need a handful of fields. This is a strict-subset scanner, not a general XML
//! parser: it finds `<item>` / `<entry>` blocks and reads scalar children of them. Anything that
//! is not that shape yields no item rather than a panic - a poller must survive the wild.

use hex;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedItem {
    /// stable identity: <guid>/<id>, else <link>, else a digest of title+date.
    /// The poller keys dedupe on this, so it must never fall back to a per-fetch counter.
    pub guid: String,
    pub title: String,
    pub link: String,
    pub when: String,
}

/// Replace the standard entities and numeric references. Single pass over `&`, otherwise
/// `&amp;lt;` would decode twice into `<`.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'&' {
            if let Some(end) = s[i..].find(';') {
                let ent = &s[i + 1..i + end];
                let decoded = match ent {
                    "amp" => Some("&".to_string()),
                    "lt" => Some("<".to_string()),
                    "gt" => Some(">".to_string()),
                    "quot" => Some("\"".to_string()),
                    "apos" => Some("'".to_string()),
                    "nbsp" => Some(" ".to_string()),
                    _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                        u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32).map(|c| c.to_string())
                    }
                    _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32).map(|c| c.to_string()),
                    _ => None,
                };
                if let Some(d) = decoded {
                    out.push_str(&d);
                    i += end + 1;
                    continue;
                }
            }
        }
        // decode_utf8 on a byte slice can split a multi-byte char; walk chars instead
        let c = s[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Drop CDATA wrappers and any remaining tags, then collapse runs of whitespace.
fn clean(s: &str) -> String {
    // unwrap CDATA losslessly: a title may mix plain text and CDATA sections
    let no_cdata = s.replace("<![CDATA[", "").replace("]]>", "");
    let mut out = String::with_capacity(no_cdata.len());
    let mut depth = 0usize;
    for c in no_cdata.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let flat: Vec<&str> = out.split_whitespace().collect();
    unescape(&flat.join(" "))
}

/// First scalar child of `block` named `tag` (self-closing tags are not interesting here).
fn field(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let mut at = 0usize;
    while let Some(rel) = block[at..].find(&open) {
        let start = at + rel + open.len();
        // the tag must end here: next char is '>' or whitespace (rejects <linker>, <title-ish>)
        let after = block[start..].chars().next().unwrap_or(' ');
        if after != '>' && !after.is_whitespace() {
            at = start;
            continue;
        }
        let gt = block[start..].find('>')? + start + 1;
        let close = format!("</{tag}>");
        let end = block[gt..].find(&close)? + gt;
        let v = clean(&block[gt..end]);
        if !v.is_empty() {
            return Some(v);
        }
        at = end;
    }
    None
}

fn blocks<'a>(hay: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(rel) = hay[at..].find(open) {
        let start = at + rel;
        let after = start + open.len();
        // require the tag boundary: "<item>" or "<item " but never "<itemized>"
        let ch = hay[after..].chars().next().unwrap_or(' ');
        if ch != '>' && !ch.is_whitespace() && ch != '/' {
            at = after;
            continue;
        }
        match hay[after..].find(close) {
            Some(rel2) => {
                let end = after + rel2;
                out.push(&hay[start..end]);
                at = end + close.len();
            }
            None => break,
        }
    }
    out
}

/// Parse a feed. RSS `<item>` blocks first, then Atom `<entry>`; a document with neither yields an
/// empty list (callers treat that as "not a feed I understand", never as "no new items").
pub fn parse_feed(xml: &str) -> Vec<FeedItem> {
    let mut items = Vec::new();
    for b in blocks(xml, "<item", "</item>") {
        items.push(build(b, "guid", "pubDate"));
    }
    if items.is_empty() {
        for b in blocks(xml, "<entry", "</entry>") {
            items.push(build(b, "id", "published"));
        }
    }
    items
}

fn build(block: &str, id_tag: &str, date_tag: &str) -> FeedItem {
    let title = field(block, "title").unwrap_or_default();
    let link = field(block, "link").unwrap_or_else(|| {
        // Atom carries the href as an attribute: <link rel="alternate" href="..."/>
        if let Some(rel) = block.find("<link") {
            let tail = &block[rel..];
            if let Some(h) = tail.find("href=\"") {
                let rest = &tail[h + 6..];
                if let Some(q) = rest.find('"') {
                    return clean(&rest[..q]);
                }
            }
        }
        String::new()
    });
    let when = field(block, date_tag)
        .or_else(|| field(block, "updated"))
        .or_else(|| field(block, "date"))
        .unwrap_or_default();
    let guid = field(block, id_tag)
        .or_else(|| field(block, "guid"))
        .or_else(|| field(block, "id"))
        .or_else(|| if link.is_empty() { None } else { Some(link.clone()) })
        .unwrap_or_else(|| {
            // no guid, no id, no link: derive a stable identity from the content itself so
            // re-polling the same document can never post it twice
            let d = Sha256::digest(format!("{title}\u{1}{when}").as_bytes());
            format!("digest:{}", &hex::encode(d)[..32])
        });
    FeedItem { guid, title, link, when }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_items_keep_order_and_identity() {
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel>
          <title>Dev log</title>
          <item><guid>urn:uuid:1</guid><title>first &amp; only</title><link>https://x.test/1</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
          <item><guid>urn:uuid:2</guid><title><![CDATA[second <b>post</b>]]></title><link>https://x.test/2</link></item>
        </channel></rss>"#;
        let v = parse_feed(xml);
        assert_eq!(v.len(), 2, "both items parsed: {v:?}");
        assert_eq!(v[0].guid, "urn:uuid:1");
        assert_eq!(v[0].title, "first & only", "entities must decode exactly once");
        assert_eq!(v[1].title, "second post", "CDATA unwrapped and inner tag stripped");
        assert_eq!(v[1].when, "", "absent pubDate is empty, not a guess");
    }

    #[test]
    fn atom_entries_use_id_and_href_link() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
          <entry><id>tag:x,2024:9</id><title>atom one</title><link rel="alternate" href="https://x.test/a"/><published>2024-02-02T00:00:00Z</published></entry>
        </feed>"#;
        let v = parse_feed(xml);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].guid, "tag:x,2024:9");
        assert_eq!(v[0].link, "https://x.test/a", "Atom link is an attribute, not text");
        assert_eq!(v[0].when, "2024-02-02T00:00:00Z");
    }

    #[test]
    fn guid_falls_back_to_link_then_digest() {
        let xml = "<rss><channel><item><title>t</title><link>https://x.test/noguid</link></item></channel></rss>";
        let v = parse_feed(xml);
        assert_eq!(v[0].guid, "https://x.test/noguid");
        // no guid and no link: still a stable identity derived from content, so a re-poll of the
        // same document cannot post it twice
        let xml2 = "<rss><channel><item><title>only a title</title></item></channel></rss>";
        let a = parse_feed(xml2);
        let b = parse_feed(xml2);
        assert!(a[0].guid.starts_with("digest:"));
        assert_eq!(a[0].guid, b[0].guid, "digest must be deterministic across fetches");
    }

    #[test]
    fn near_miss_tag_names_are_not_matched() {
        // a naive substring search would read <itemized> as an item and <titleish> as a title
        let xml = "<rss><channel><itemized>not an item</itemized><titleish>no</titleish><item><title>real</title><guid>g1</guid></item></channel></rss>";
        let v = parse_feed(xml);
        assert_eq!(v.len(), 1, "only the real item: {v:?}");
        assert_eq!(v[0].title, "real");
    }

    #[test]
    fn junk_yields_no_items_instead_of_a_panic() {
        assert!(parse_feed("").is_empty());
        assert!(parse_feed("<html><body>404 not found</body></html>").is_empty());
        assert!(parse_feed("<rss><channel><item><title>unclosed").is_empty());
        // unterminated entity and a stray ampersand must not crash the decoder
        assert_eq!(unescape("a & b &amp;c &#38; d &#x41;"), "a & b &c & d A");
    }
}
