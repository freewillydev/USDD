//! Frozen encrypted-witness availability parameters.
//!
//! The cryptographic implementation lives outside protocol-core, but its exact
//! scheme identity and custodian registry are committed by the singleton's
//! frozen configuration. A key rotation therefore changes the configuration
//! hash instead of silently reinterpreting an existing availability root.

use crate::codec::{put_u32, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::ProtocolError;

pub const AVAILABILITY_RECOVERY_THRESHOLD: u8 = 3;
pub const AVAILABILITY_CUSTODIAN_COUNT: u8 = 5;
pub const MAX_AVAILABILITY_WITNESS_BYTES: u32 = 16 * 1024 * 1024;
/// Frozen output of the reviewed witness-availability v1 scheme transcript:
/// `ECXWIT1\0`, bundle version 1, threshold 3-of-5, 16 MiB plaintext limit,
/// XChaCha20-Poly1305, HKDF-SHA256, X25519, Ristretto255-Feldman, Ed25519,
/// and the exact bundle/header/payload/share/KDF/attestation/receipt/share-hash
/// domains, under tagged SHA256 domain `ECX/witness-availability-scheme/v1`.
///
/// Protocol-core deliberately stores the resulting dependency-neutral value
/// rather than depending on the cryptographic service crate. Proof-core has a
/// cross-crate regression requiring byte equality with that implementation's
/// independently derived `availability_scheme_hash()`.
pub const AVAILABILITY_SCHEME_HASH_V1: Hash32 = [
    0x8d, 0x24, 0x40, 0x42, 0x79, 0x39, 0xc9, 0x72, 0xfc, 0x0c, 0xba, 0x68, 0x41, 0xfb, 0x66, 0x1e,
    0x4c, 0x0a, 0x7d, 0x53, 0x0c, 0x84, 0x54, 0x3b, 0xd3, 0x90, 0x6a, 0xfb, 0x3c, 0x34, 0x80, 0x4e,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AvailabilityConfigV1 {
    pub version: u8,
    /// Commitment to the exact bundle codec, encryption, sharing, KDF, and
    /// attestation domains selected for this deployment.
    pub scheme_hash: Hash32,
    /// Commitment to the five ordered (index, X25519, Ed25519) public records.
    pub custodian_registry_hash: Hash32,
    pub recovery_threshold: u8,
    pub custodian_count: u8,
    pub maximum_witness_bytes: u32,
}

impl AvailabilityConfigV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.scheme_hash == [0; 32]
            || self.custodian_registry_hash == [0; 32]
            || self.recovery_threshold != AVAILABILITY_RECOVERY_THRESHOLD
            || self.custodian_count != AVAILABILITY_CUSTODIAN_COUNT
            || self.maximum_witness_bytes != MAX_AVAILABILITY_WITNESS_BYTES
        {
            return Err(ProtocolError::InvalidAvailabilityConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/availability-configuration/v1", self)
    }
}

impl CanonicalEncode for AvailabilityConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.scheme_hash);
        out.extend_from_slice(&self.custodian_registry_hash);
        put_u8(out, self.recovery_threshold);
        put_u8(out, self.custodian_count);
        put_u32(out, self.maximum_witness_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> AvailabilityConfigV1 {
        AvailabilityConfigV1 {
            version: AvailabilityConfigV1::VERSION,
            scheme_hash: [1; 32],
            custodian_registry_hash: [2; 32],
            recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
            custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
            maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
        }
    }

    #[test]
    fn exact_three_of_five_profile_is_frozen() {
        configuration().validate().unwrap();
        let mut changed = configuration();
        changed.recovery_threshold = 2;
        assert_eq!(
            changed.validate(),
            Err(ProtocolError::InvalidAvailabilityConfiguration)
        );
        let mut changed = configuration();
        changed.custodian_count = 6;
        assert_eq!(
            changed.validate(),
            Err(ProtocolError::InvalidAvailabilityConfiguration)
        );
    }
}
