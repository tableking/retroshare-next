//! Transport channel after Noise_XX: two directional ChaCha20Poly1305 keys, 128-bit counters.
use chacha20poly1305::ChaCha20Poly1305;
use aead::{Aead, KeyInit};
use generic_array::{typenum::U12, GenericArray};

pub struct SymmChannel {
    key: [u8; 32],
    counter: u128,
}

impl SymmChannel {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }
    fn next_nonce(&mut self) -> [u8; 12] {
        let c = self.counter;
        self.counter += 1;
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&(c as u64).to_le_bytes()); // Noise spec: 4 zero bytes + 8-byte LE counter
        n
    }
    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "key len".to_string())?;
        cipher.encrypt(GenericArray::<u8, U12>::from_slice(&self.next_nonce()), pt).map_err(|_| "seal fail".into())
    }
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "key len".to_string())?;
        cipher.decrypt(GenericArray::<u8, U12>::from_slice(&self.next_nonce()), ct).map_err(|_| "replay or tamper".into())
    }
}

/// Given the (k, tempk) pair from a finished XX, return (send, recv) for one side.
pub fn transport_pair(k: [u8; 32], tempk: [u8; 32], initiator: bool) -> (SymmChannel, SymmChannel) {
    let (a, b) = (SymmChannel::new(k), SymmChannel::new(tempk));
    if initiator { (a, b) } else { (b, a) }
}
