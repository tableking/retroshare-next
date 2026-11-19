//! Node identity: Ed25519 long-term key + X25519 static key (for Noise_XX `s` pattern).
//! Replaces the old 300-line PGP certificate ceremony. Human-readable fingerprint =
//! first 8 bytes of SHA-256 over the public identity bundle, grouped like Bitcoin-style
//! so two friends can verbally compare 4x4 chars when scanning a QR is impossible.
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Identity {
    pub name: String,
    pub ed25519_secret: String, // hex
    pub ed25519_public: String, // hex
    pub x25519_secret: String,  // hex
    pub x25519_public: String,  // hex
}

impl Identity {
    pub fn generate(name: &str) -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let ss = StaticSecret::random_from_rng(OsRng);
        let vp = VerifyingKey::from(&sk);
        let xp = XPublic::from(&ss);
        Self {
            name: name.to_string(),
            ed25519_secret: hex::encode(sk.to_bytes()),
            ed25519_public: hex::encode(vp.to_bytes()),
            x25519_secret: hex::encode(ss.to_bytes()),
            x25519_public: hex::encode(xp.as_bytes()),
        }
    }

    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"rsnext-identity-v1");
        h.update(hex::decode(&self.ed25519_public).unwrap());
        h.update(hex::decode(&self.x25519_public).unwrap());
        let d = h.finalize();
        let raw = hex::encode(&d[..8]).to_uppercase();
        raw.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
    }

    /// Magic-link / QR payload (friend adds friend): id + pubs + a one-time pairing code.
    pub fn invite_payload(&self, pairing_code: &str, addr: &str) -> String {
        format!(
            "rsnext://v1?id={}&ed={}&x25519={}&pair={}&addr={}",
            self.fingerprint(), self.ed25519_public, self.x25519_public, pairing_code, addr
        )
    }

    pub fn x25519_secret_bytes(&self) -> [u8; 32] {
        hex::decode(&self.x25519_secret).unwrap().try_into().unwrap()
    }
    pub fn ed25519_secret_bytes(&self) -> [u8; 32] {
        hex::decode(&self.ed25519_secret).unwrap().try_into().unwrap()
    }
}
