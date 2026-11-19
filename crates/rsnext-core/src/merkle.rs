//! Merkle tree over ordered leaf hashes (forum posts, files index).
//! Same digest rule as our fingerprints: SHA-256, pairwise combine, odd node promotes.
//! Sync protocol: exchange root -> if differ, bisect by prefix roots -> fetch missing leaves.
use sha2::{Digest, Sha256};

pub fn leaf_hash(seq: i64, author: &str, body: &str, ts: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rsnext-post-v1");
    h.update(seq.to_le_bytes());
    h.update(author.as_bytes());
    h.update(body.as_bytes());
    h.update(ts.to_le_bytes());
    h.finalize().into()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Sha256::new();
        h.update(b"rsnext-empty");
        return h.finalize().into();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut h = Sha256::new();
                h.update(b"rsnext-node");
                h.update(level[i]);
                h.update(level[i + 1]);
                next.push(h.finalize().into());
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

/// Prefix roots for bisection: root of leaves[0..mid] for a given split index.
pub fn prefix_root(leaves: &[[u8; 32]], n: usize) -> [u8; 32] {
    merkle_root(&leaves[..n.min(leaves.len())])
}

/// Smallest index i where my leaves[i] digest diverges from theirs (given equal length prefix roots).
/// Returns min(len_mine, len_theirs) if prefixes agree up to the shorter length.
pub fn first_divergence(mine: &[[u8; 32]], theirs: &[[u8; 32]]) -> usize {
    let n = mine.len().min(theirs.len());
    let mut lo = 0usize;
    while lo < n {
        // binary search on prefix roots
        let mut l = lo;
        let mut r = n;
        while l < r {
            let mid = (l + r) / 2;
            if prefix_root(mine, mid + 1) == prefix_root(theirs, mid + 1) {
                l = mid + 1;
            } else {
                r = mid;
            }
        }
        return l; // first index that differs
    }
    n
}
