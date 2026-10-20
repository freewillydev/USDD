use sha2::{Digest, Sha256};

use crate::codec::CanonicalEncode;

pub type Hash32 = [u8; 32];

/// BIP340-style tagged SHA-256: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged_hash(tag: &str, message: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag.as_bytes()).into();
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(message);
    engine.finalize().into()
}

pub fn canonical_hash(tag: &str, value: &impl CanonicalEncode) -> Hash32 {
    tagged_hash(tag, &value.canonical_bytes())
}
