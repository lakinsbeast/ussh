//! Packet sealing: ChaCha20-Poly1305 with a masked 12-byte header.
//!
//! Wire format: `header(12) || ciphertext+tag`. The header is the AEAD nonce
//! (`generation u32 || direction|seq u64`) XORed with a per-session mask, so
//! packets carry no fixed plaintext signature.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const HEADER_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const DIR_TO_CLIENT: u64 = 1 << 63;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("getrandom failed");
    b
}

pub fn random_u64() -> u64 {
    u64::from_le_bytes(random_bytes::<8>())
}

pub struct Keys {
    aead: ChaCha20Poly1305,
}

impl Keys {
    pub fn new(key: &[u8; 32]) -> Self {
        Keys { aead: ChaCha20Poly1305::new(&Key::from(*key)) }
    }

    pub fn seal(&self, mask: &[u8; 12], generation: u32, seq_dir: u64, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&generation.to_be_bytes());
        nonce[4..].copy_from_slice(&seq_dir.to_be_bytes());
        let ct = self.aead.encrypt(&Nonce::from(nonce), plain).expect("encrypt");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend(nonce.iter().zip(mask).map(|(n, m)| n ^ m));
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, hdr: &Header, wire: &[u8]) -> Option<Vec<u8>> {
        self.aead.decrypt(&Nonce::from(hdr.nonce), &wire[HEADER_LEN..]).ok()
    }
}

pub struct Header {
    pub generation: u32,
    pub seq_dir: u64,
    nonce: [u8; 12],
}

pub fn peek_header(mask: &[u8; 12], wire: &[u8]) -> Option<Header> {
    if wire.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    for i in 0..12 {
        nonce[i] = wire[i] ^ mask[i];
    }
    Some(Header {
        generation: u32::from_be_bytes(nonce[..4].try_into().unwrap()),
        seq_dir: u64::from_be_bytes(nonce[4..].try_into().unwrap()),
        nonce,
    })
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
