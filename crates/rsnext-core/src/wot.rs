//! Web of Trust (M3): Ed25519 certificates over peer identities, and a local trust score.
//!
//! RetroShare's original WoT was PGP certs pasted between friends. Same guarantee, minus the
//! ceremony: a node signs a friend's identity bundle, signatures replicate between friends, and
//! trust is computed *locally* from the graph rooted at my own signature (nothing is authoritative
//! until I signed it - which is exactly what "friend to friend" means).
//!
//! Canonical form is domain-separated and versioned so a signature can never be reinterpreted by
//! a future format change.
use crate::identity::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Version + domain separation prefix. Bump on any change to the byte layout.
pub const CERT_DOMAIN: &[u8] = b"rsnext-cert-v1\n";
/// One signature seen as "I vouch for this key".
pub const SELF_TRUST: f64 = 1.0;
/// Multiplier per hop past a direct friend (a FoF is worth less than a friend).
pub const HOP_DECAY: f64 = 0.7;
/// A chain longer than this is noise, not trust.
pub const MAX_HOPS: usize = 4;

/// The thing that gets signed: who a key belongs to, at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    /// Human fingerprint of the subject, e.g. `ABCD-1234-EF01-2345`.
    pub subject_fp: String,
    /// Subject's Ed25519 public key (hex) - also its iroh endpoint id.
    pub subject_ed: String,
    /// Subject's X25519 public key (hex) - used by the Noise channel.
    pub subject_x25519: String,
    /// Unix seconds when the signing node observed this identity.
    pub ts: i64,
}

impl CertInfo {
    pub fn from_identity(id: &Identity, ts: i64) -> Self {
        Self { subject_fp: id.fingerprint(), subject_ed: id.ed25519_public.clone(), subject_x25519: id.x25519_public.clone(), ts }
    }

    /// The exact bytes a signature covers. Keep this the single source of truth.
    pub fn message(&self) -> Vec<u8> {
        let mut v = CERT_DOMAIN.to_vec();
        v.extend_from_slice(self.subject_fp.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(self.subject_ed.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(self.subject_x25519.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(self.ts.to_string().as_bytes());
        v
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WotError {
    #[error("bad public key hex: {0}")]
    BadKey(String),
    #[error("signature is not valid for this certificate")]
    BadSignature,
}

/// Sign a subject's identity with `issuer`'s Ed25519 key.
pub fn sign_cert(issuer: &Identity, cert: &CertInfo) -> Result<String, WotError> {
    let sk = SigningKey::from_bytes(&issuer.ed25519_secret_bytes());
    Ok(hex::encode(sk.sign(&cert.message()).to_bytes()))
}

/// Verify a certificate against the *issuer's* public key (hex).
pub fn verify_cert(issuer_ed_hex: &str, cert: &CertInfo, sig_hex: &str) -> Result<(), WotError> {
    let pk = decode32(issuer_ed_hex).map_err(WotError::BadKey)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| WotError::BadKey(e.to_string()))?;
    let sigb = decode64(sig_hex).map_err(WotError::BadKey)?;
    let sig = Signature::from_bytes(&sigb);
    vk.verify(&cert.message(), &sig).map_err(|_| WotError::BadSignature)
}

/// One stored signature. `PK = (subject_fp, issuer_fp)` - several friends may sign the same peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cert {
    pub cert: CertInfo,
    pub issuer_fp: String,
    pub issuer_ed: String,
    pub sig: String,
}

/// Adjacency for the trust graph: `issuer -> subject` with the issuer's key.
#[derive(Debug, Clone)]
pub struct Edge {
    pub issuer_fp: String,
    pub subject_fp: String,
}

/// Trust in `target` as seen by `me`, from a set of verified signatures.
///
/// Path value = SELF_TRUST * HOP_DECAY^(hops-1); the best path wins. Signature validity is the
/// caller's job (`verify_cert`) - putting it here would let an unverified cert influence a score.
/// Returns `None` for a stranger with no chain to me: absence of evidence, not evidence of evil.
pub fn trust_score(me: &str, target: &str, edges: &[Edge]) -> Option<f64> {
    if me == target {
        return Some(SELF_TRUST);
    }
    // Layered Bellman-Ford: each round advances the frontier by EXACTLY one hop, so MAX_HOPS is a
    // real bound. Relaxing in place would let a single pass walk the entire chain and hand a score
    // to nodes far beyond the horizon (caught by trust_decays_with_hops_and_strangers_score_nothing).
    let mut best: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    best.insert(me.to_string(), SELF_TRUST);
    for _ in 0..MAX_HOPS {
        let mut next = best.clone();
        let mut changed = false;
        for e in edges {
            if let Some(&v) = best.get(&e.issuer_fp) {
                let nv = v * HOP_DECAY;
                if nv > best.get(&e.subject_fp).copied().unwrap_or(0.0) + f64::EPSILON
                    && nv > next.get(&e.subject_fp).copied().unwrap_or(0.0) + f64::EPSILON
                {
                    next.insert(e.subject_fp.clone(), nv);
                    changed = true;
                }
            }
        }
        best = next;
        if !changed {
            break;
        }
    }
    best.get(target).copied()
}

/// Full ranking of everyone reachable from `me`, most trusted first.
pub fn trust_map(me: &str, edges: &[Edge]) -> Vec<(String, f64)> {
    let mut nodes: Vec<String> = edges.iter().flat_map(|e| [e.issuer_fp.clone(), e.subject_fp.clone()]).collect();
    nodes.sort();
    nodes.dedup();
    let mut scored: Vec<(String, f64)> = nodes
        .into_iter()
        .filter(|n| n != me)
        .filter_map(|n| trust_score(me, &n, edges).map(|s| (n, s)))
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

fn decode32(hex_str: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(hex_str).map_err(|e| e.to_string())?;
    let v: [u8; 32] = b.try_into().map_err(|_| "expected 32 bytes".to_string())?;
    Ok(v)
}

fn decode64(hex_str: &str) -> Result<[u8; 64], String> {
    let b = hex::decode(hex_str).map_err(|e| e.to_string())?;
    let v: [u8; 64] = b.try_into().map_err(|_| "expected 64 bytes".to_string())?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> Identity {
        Identity::generate(name)
    }

    #[test]
    fn a_signature_verifies_against_the_issuers_key() {
        let (alice, bob) = (id("alice"), id("bob"));
        let cert = CertInfo::from_identity(&bob, 1700000000);
        let sig = sign_cert(&alice, &cert).unwrap();
        assert!(verify_cert(&alice.ed25519_public, &cert, &sig).is_ok());
    }

    #[test]
    fn tampering_with_any_signed_field_breaks_verification() {
        let (alice, bob) = (id("alice2"), id("bob2"));
        let cert = CertInfo::from_identity(&bob, 1700000000);
        let sig = sign_cert(&alice, &cert).unwrap();
        let mut later = cert.clone();
        later.ts += 1;
        assert!(verify_cert(&alice.ed25519_public, &later, &sig).is_err(), "timestamp is signed");
        let mut other_key = cert.clone();
        other_key.subject_ed = id("eve").ed25519_public;
        assert!(verify_cert(&alice.ed25519_public, &other_key, &sig).is_err(), "subject key is signed");
    }

    #[test]
    fn someone_elses_cannot_sign_for_alice() {
        let (alice, eve, bob) = (id("alice3"), id("eve3"), id("bob3"));
        let cert = CertInfo::from_identity(&bob, 1);
        let forged = sign_cert(&eve, &cert).unwrap();
        assert_eq!(verify_cert(&alice.ed25519_public, &cert, &forged), Err(WotError::BadSignature),
            "a cert claiming alice as issuer must not verify under alice's key");
    }

    #[test]
    fn trust_decays_with_hops_and_strangers_score_nothing() {
        let e = |i: &str, s: &str| Edge { issuer_fp: i.into(), subject_fp: s.into() };
        let edges = vec![e("me", "bob"), e("bob", "carol"), e("carol", "dave")];
        assert!((trust_score("me", "me", &edges).unwrap() - SELF_TRUST).abs() < 1e-12);
        assert!((trust_score("me", "bob", &edges).unwrap() - 0.7).abs() < 1e-9);
        assert!((trust_score("me", "carol", &edges).unwrap() - 0.49).abs() < 1e-9);
        // 4 hops is the last one we count
        let mut deep = edges.clone();
        deep.push(e("dave", "erin"));
        assert!(trust_score("me", "erin", &deep).is_some());
        deep.push(e("erin", "fred"));
        assert_eq!(trust_score("me", "fred", &deep), None, "beyond MAX_HOPS there is no evidence");
        assert_eq!(trust_score("me", "stranger", &edges), None, "no chain, no score");
    }

    #[test]
    fn the_best_path_wins_not_the_first() {
        let e = |i: &str, s: &str| Edge { issuer_fp: i.into(), subject_fp: s.into() };
        // carol is both a FoF of me and deep-signed by a stranger: the short path must win
        let edges = vec![e("me", "bob"), e("bob", "carol"), e("x", "y"), e("y", "z"), e("z", "carol")];
        assert!((trust_score("me", "carol", &edges).unwrap() - 0.49).abs() < 1e-9);
    }

    #[test]
    fn trust_map_is_sorted_most_trusted_first() {
        let e = |i: &str, s: &str| Edge { issuer_fp: i.into(), subject_fp: s.into() };
        let edges = vec![e("me", "bob"), e("bob", "carol"), e("me", "dan")];
        let m = trust_map("me", &edges);
        assert_eq!(m.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), vec!["bob", "dan", "carol"]);
    }
}
