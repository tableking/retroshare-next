//! Noise_XX over X25519 + ChaCha20Poly1305 + SHA-256 — canonical pattern:
//!   msg1 -> e                         msg2 <- e, ee, s, es           msg3 -> s, se
//! where s is the static PUBLIC key (never the secret), es=DH(e_i,s_r), se=DH(s_i,e_r).
//! Mutual static authentication; transcript binding; fresh session keys via split().
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use generic_array::{typenum::U12, GenericArray};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const PROTOCOL: &[u8] = b"Noise_XX_ChaCha20Poly1305_SHA256";

pub struct EphemeralPubHolder(pub [u8; 32]);

pub struct XxHandshake {
    h: [u8; 32],
    ck: [u8; 32],
    k: Option<[u8; 32]>,
    pub local_static: [u8; 32], // SECRET
    static_pub: [u8; 32],
    pub eph: [u8; 32],         // our ephemeral secret (initiator msg1 / responder msg2)
    re_i: Option<[u8; 32]>,    // initiator ephemeral pub (responder view)
    re_r: Option<[u8; 32]>,    // responder ephemeral pub (initiator view)
    pub remote_static: Option<[u8; 32]>, // peer static PUBLIC
}

fn hkdf_two(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut a = Vec::with_capacity(32 + ikm.len());
    a.extend_from_slice(ck);
    a.extend_from_slice(ikm);
    let t = Sha256::digest(&a);
    let k1: [u8; 32] = Sha256::digest(t.as_slice()).into();
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(t.as_slice());
    b.extend_from_slice(ck);
    let k2: [u8; 32] = Sha256::digest(&b).into();
    (k1, k2)
}

fn aead_seal(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key len");
    cipher.encrypt(GenericArray::<u8, U12>::from_slice(&[0u8; 12]), pt).expect("seal")
}

fn aead_open(key: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "key len".to_string())?;
    cipher.decrypt(GenericArray::<u8, U12>::from_slice(&[0u8; 12]), ct).map_err(|_| "aead tag mismatch".to_string())
}

impl XxHandshake {
    pub fn new(local_static: [u8; 32]) -> Self {
        let h: [u8; 32] = Sha256::digest(PROTOCOL).into();
        let static_pub: [u8; 32] = *PublicKey::from(&StaticSecret::from(local_static)).as_bytes();
        Self { h, ck: h, k: None, local_static, static_pub, eph: [0u8; 32], re_i: None, re_r: None, remote_static: None }
    }
    pub fn h(&self) -> [u8; 32] { self.h }
    fn gen_eph(&mut self) {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        self.eph = b;
    }
    fn mix_hash(&mut self, data: &[u8]) {
        let mut d = Sha256::new();
        d.update(self.h);
        d.update(data);
        self.h = d.finalize().into();
    }
    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf_two(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
    }
    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Vec<u8> {
        match self.k {
            None => { self.mix_hash(pt); pt.to_vec() }
            Some(key) => {
                let ct = aead_seal(&key, pt);
                self.mix_hash(&ct);
                ct
            }
        }
    }
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, String> {
        match self.k {
            None => { self.mix_hash(ct); Ok(ct.to_vec()) }
            Some(key) => {
                let pt = aead_open(&key, ct)?;
                self.mix_hash(ct);
                Ok(pt)
            }
        }
    }
    /// initiator msg1 -> e
    pub fn write_msg1(&mut self) -> Vec<u8> {
        self.gen_eph();
        let ep = PublicKey::from(&StaticSecret::from(self.eph));
        self.mix_hash(ep.as_bytes());
        ep.as_bytes().to_vec()
    }
    /// responder reads msg1 (stores initiator ephemeral pub)
    pub fn read_msg1(&mut self, m: &[u8]) -> Result<EphemeralPubHolder, String> {
        if m.len() != 32 { return Err("msg1 len".into()); }
        self.mix_hash(m);
        let mut b = [0u8; 32];
        b.copy_from_slice(m);
        self.re_i = Some(b);
        Ok(EphemeralPubHolder(b))
    }
    /// responder msg2 <- e, ee, s, es
    pub fn write_msg2(&mut self, re: &EphemeralPubHolder) -> Vec<u8> {
        self.gen_eph();
        let ss_e = StaticSecret::from(self.eph);
        let ep = PublicKey::from(&ss_e);
        self.mix_hash(ep.as_bytes());
        let ee = ss_e.diffie_hellman(&PublicKey::from(re.0)); // DH(e_r, e_i)
        self.mix_key(ee.as_bytes());
        let sp = self.static_pub;
        let enc_s = self.encrypt_and_hash(&sp); // send PUBLIC static
        let es = StaticSecret::from(self.local_static).diffie_hellman(&PublicKey::from(re.0)); // DH(s_r, e_i)
        self.mix_key(es.as_bytes());
        let mut msg = ep.as_bytes().to_vec();
        msg.extend_from_slice(&enc_s);
        msg
    }
    /// initiator reads msg2 -> learns peer static pub; returns remote static pub
    pub fn read_msg2(&mut self, m: &[u8]) -> Result<[u8; 32], String> {
        if m.len() != 80 { return Err("msg2 len".into()); }
        let mut ep = [0u8; 32];
        ep.copy_from_slice(&m[..32]);
        self.re_r = Some(ep);
        self.mix_hash(&ep);
        let ee = StaticSecret::from(self.eph).diffie_hellman(&PublicKey::from(ep)); // DH(e_i, e_r)
        self.mix_key(ee.as_bytes());
        let s = self.decrypt_and_hash(&m[32..80])?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&s);
        self.remote_static = Some(rs); // STATIC PUBLIC of peer
        let es = StaticSecret::from(self.eph).diffie_hellman(&PublicKey::from(rs)); // DH(e_i, s_r_pub)
        self.mix_key(es.as_bytes());
        Ok(rs)
    }
    /// initiator msg3 -> s, se ; returns (msg, (k, tempk, h))
    pub fn write_msg3(&mut self) -> (Vec<u8>, ([u8; 32], [u8; 32], [u8; 32])) {
        let sp = self.static_pub;
        let enc_s = self.encrypt_and_hash(&sp);
        let se = StaticSecret::from(self.local_static).diffie_hellman(&PublicKey::from(self.re_r.unwrap())); // DH(s_i, e_r)
        self.mix_key(se.as_bytes());
        let (k, tempk) = hkdf_two(&self.ck, &[]);
        (enc_s, (k, tempk, self.h))
    }
    /// responder reads msg3 -> learns peer static pub; returns transport material
    pub fn read_msg3(&mut self, m: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
        if m.len() != 48 { return Err("msg3 len".into()); }
        let s = self.decrypt_and_hash(m)?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&s);
        self.remote_static = Some(rs);
        let se = StaticSecret::from(self.eph).diffie_hellman(&PublicKey::from(rs)); // DH(e_r, s_i_pub)
        self.mix_key(se.as_bytes());
        let (k, tempk) = hkdf_two(&self.ck, &[]);
        Ok((k, tempk, self.h))
    }
}
