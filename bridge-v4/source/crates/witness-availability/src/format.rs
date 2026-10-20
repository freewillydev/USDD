use std::convert::TryFrom;

use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{AvailabilityError, Result};

pub const BUNDLE_VERSION: u16 = 1;
pub const RECOVERY_THRESHOLD: usize = 3;
pub const CUSTODIAN_COUNT: usize = 5;
pub const MAX_WITNESS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BUNDLE_BYTES: usize = MAX_WITNESS_BYTES + 1_024;

pub(crate) const BUNDLE_MAGIC: [u8; 8] = *b"ECXWIT1\0";
pub(crate) const SHARE_MAGIC: [u8; 8] = *b"ECXSHR1\0";
pub(crate) const SHARE_PLAINTEXT_BYTES: usize = 44;
pub(crate) const SHARE_CIPHERTEXT_BYTES: usize = SHARE_PLAINTEXT_BYTES + 16;

const ROOT_DOMAIN: &[u8] = b"ECX/witness-bundle-root/v1";
const HEADER_DOMAIN: &[u8] = b"ECX/witness-bundle-header/v1";
pub(crate) const PAYLOAD_AAD_DOMAIN: &[u8] = b"ECX/witness-payload-aad/v1";
pub(crate) const SHARE_AAD_DOMAIN: &[u8] = b"ECX/witness-share-aad/v1";
pub(crate) const PAYLOAD_KDF_DOMAIN: &[u8] = b"ECX/witness-payload-key/v1";
pub(crate) const SHARE_KDF_DOMAIN: &[u8] = b"ECX/witness-share-key/v1";
pub(crate) const ATTEST_DOMAIN: &[u8] = b"ECX/witness-custodian-attestation/v1";
pub(crate) const CUSTODY_RECEIPT_DOMAIN: &[u8] = b"ECX/witness-custody-receipt/v1";
pub(crate) const SHARE_HASH_DOMAIN: &[u8] = b"ECX/witness-share-hash/v1";

/// Commitment to the exact ECX availability profile selected by
/// `AvailabilityConfigV1`. Deployment tooling pins this value alongside the
/// reviewed implementation revision.
pub fn availability_scheme_hash() -> [u8; 32] {
    let mut profile = Vec::new();
    profile.extend_from_slice(&BUNDLE_MAGIC);
    profile.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
    profile.push(RECOVERY_THRESHOLD as u8);
    profile.push(CUSTODIAN_COUNT as u8);
    profile.extend_from_slice(&(MAX_WITNESS_BYTES as u64).to_be_bytes());
    for identity in [
        b"XChaCha20-Poly1305".as_slice(),
        b"HKDF-SHA256".as_slice(),
        b"X25519".as_slice(),
        b"Ristretto255-Feldman".as_slice(),
        b"Ed25519".as_slice(),
        ROOT_DOMAIN,
        HEADER_DOMAIN,
        PAYLOAD_AAD_DOMAIN,
        SHARE_AAD_DOMAIN,
        PAYLOAD_KDF_DOMAIN,
        SHARE_KDF_DOMAIN,
        ATTEST_DOMAIN,
        CUSTODY_RECEIPT_DOMAIN,
        SHARE_HASH_DOMAIN,
    ] {
        profile.extend_from_slice(&(identity.len() as u32).to_be_bytes());
        profile.extend_from_slice(identity);
    }
    tagged_hash(b"ECX/witness-availability-scheme/v1", &profile)
}

/// Commit the exact canonical 1-through-5 X25519/Ed25519 registry.
pub fn custodian_registry_hash(custodians: &[CustodianPublic]) -> Result<[u8; 32]> {
    validate_custodian_registry(custodians)?;
    let mut bytes = Vec::with_capacity(CUSTODIAN_COUNT * 65);
    for custodian in custodians {
        bytes.push(custodian.index);
        bytes.extend_from_slice(&custodian.encryption_public_key);
        bytes.extend_from_slice(&custodian.attestation_public_key);
    }
    Ok(tagged_hash(b"ECX/witness-custodian-registry/v1", &bytes))
}

pub(crate) fn validate_custodian_registry(custodians: &[CustodianPublic]) -> Result<()> {
    if custodians.len() != CUSTODIAN_COUNT {
        return Err(AvailabilityError::Custodian("count must be exactly five"));
    }
    for (position, custodian) in custodians.iter().enumerate() {
        let expected_index = u8::try_from(position + 1).expect("five fits in u8");
        if custodian.index != expected_index {
            return Err(AvailabilityError::Custodian(
                "indices must be canonical 1 through 5",
            ));
        }
        if !x25519_public_is_contributory(custodian.encryption_public_key) {
            return Err(AvailabilityError::NonContributoryKey);
        }
        let verifying_key = VerifyingKey::from_bytes(&custodian.attestation_public_key)
            .map_err(|_| AvailabilityError::Custodian("invalid Ed25519 public key"))?;
        if verifying_key.is_weak() {
            return Err(AvailabilityError::Custodian("weak Ed25519 public key"));
        }
        for prior in &custodians[..position] {
            if prior.encryption_public_key == custodian.encryption_public_key {
                return Err(AvailabilityError::Custodian("duplicate X25519 public key"));
            }
            if prior.attestation_public_key == custodian.attestation_public_key {
                return Err(AvailabilityError::Custodian("duplicate Ed25519 public key"));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodianPublic {
    pub index: u8,
    pub encryption_public_key: [u8; 32],
    pub attestation_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodianEnvelope {
    pub public: CustodianPublic,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessBundle {
    pub context: [u8; 32],
    pub witness_len: u64,
    pub ephemeral_public_key: [u8; 32],
    pub commitments: [[u8; 32]; RECOVERY_THRESHOLD],
    pub custodians: Vec<CustodianEnvelope>,
    pub payload_nonce: [u8; 24],
    pub payload_ciphertext: Vec<u8>,
}

impl WitnessBundle {
    pub fn validate(&self) -> Result<()> {
        if self.context.ct_eq(&[0; 32]).into() {
            return Err(AvailabilityError::Canonical("zero application context"));
        }

        let witness_len =
            usize::try_from(self.witness_len).map_err(|_| AvailabilityError::WitnessSize {
                max: MAX_WITNESS_BYTES,
            })?;
        if witness_len == 0 || witness_len > MAX_WITNESS_BYTES {
            return Err(AvailabilityError::WitnessSize {
                max: MAX_WITNESS_BYTES,
            });
        }
        if self.payload_ciphertext.len() != witness_len + 16 {
            return Err(AvailabilityError::Canonical("payload ciphertext length"));
        }
        if self.custodians.len() != CUSTODIAN_COUNT {
            return Err(AvailabilityError::Custodian("count must be exactly five"));
        }

        if self.ephemeral_public_key.ct_eq(&[0; 32]).into()
            || !x25519_public_is_contributory(self.ephemeral_public_key)
        {
            return Err(AvailabilityError::NonContributoryKey);
        }

        let points = self.commitment_points()?;
        if points[0] == curve25519_dalek::ristretto::RistrettoPoint::identity() {
            return Err(AvailabilityError::Canonical("identity secret commitment"));
        }

        for (position, envelope) in self.custodians.iter().enumerate() {
            let expected_index = u8::try_from(position + 1).expect("five fits in u8");
            if envelope.public.index != expected_index {
                return Err(AvailabilityError::Custodian(
                    "indices must be canonical 1 through 5",
                ));
            }
            if envelope.ciphertext.len() != SHARE_CIPHERTEXT_BYTES {
                return Err(AvailabilityError::Canonical("share ciphertext length"));
            }
            if !x25519_public_is_contributory(envelope.public.encryption_public_key) {
                return Err(AvailabilityError::NonContributoryKey);
            }

            let verifying_key =
                VerifyingKey::from_bytes(&envelope.public.attestation_public_key)
                    .map_err(|_| AvailabilityError::Custodian("invalid Ed25519 public key"))?;
            if verifying_key.is_weak() {
                return Err(AvailabilityError::Custodian("weak Ed25519 public key"));
            }

            for prior in &self.custodians[..position] {
                if prior.public.encryption_public_key == envelope.public.encryption_public_key {
                    return Err(AvailabilityError::Custodian("duplicate X25519 public key"));
                }
                if prior.public.attestation_public_key == envelope.public.attestation_public_key {
                    return Err(AvailabilityError::Custodian("duplicate Ed25519 public key"));
                }
                if prior.nonce == envelope.nonce {
                    return Err(AvailabilityError::Canonical("duplicate share nonce"));
                }
            }
        }

        let encoded_len = self
            .header_bytes()
            .len()
            .checked_add(24 + 4)
            .and_then(|length| length.checked_add(self.payload_ciphertext.len()))
            .and_then(|length| {
                self.custodians.iter().try_fold(length, |total, custodian| {
                    total.checked_add(1 + 24 + 2 + custodian.ciphertext.len())
                })
            })
            .ok_or(AvailabilityError::TooLarge)?;
        if encoded_len > MAX_BUNDLE_BYTES {
            return Err(AvailabilityError::TooLarge);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_validated())
    }

    fn encode_validated(&self) -> Vec<u8> {
        let mut out = self.header_bytes();
        out.extend_from_slice(&self.payload_nonce);
        let payload_len = u32::try_from(self.payload_ciphertext.len())
            .expect("validated witness ciphertext fits u32");
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload_ciphertext);
        for custodian in &self.custodians {
            out.push(custodian.public.index);
            out.extend_from_slice(&custodian.nonce);
            let length = u16::try_from(custodian.ciphertext.len())
                .expect("share ciphertext length fits u16");
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&custodian.ciphertext);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(AvailabilityError::TooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != BUNDLE_MAGIC {
            return Err(AvailabilityError::Canonical("bundle magic/domain"));
        }
        if reader.u16()? != BUNDLE_VERSION {
            return Err(AvailabilityError::Canonical("bundle version"));
        }
        if usize::from(reader.u8()?) != RECOVERY_THRESHOLD {
            return Err(AvailabilityError::Canonical("threshold"));
        }
        if usize::from(reader.u8()?) != CUSTODIAN_COUNT {
            return Err(AvailabilityError::Canonical("custodian count"));
        }

        let context = reader.array::<32>()?;
        let witness_len = reader.u64()?;
        let ephemeral_public_key = reader.array::<32>()?;
        let mut commitments = [[0; 32]; RECOVERY_THRESHOLD];
        for commitment in &mut commitments {
            *commitment = reader.array::<32>()?;
        }

        let mut public = Vec::with_capacity(CUSTODIAN_COUNT);
        for _ in 0..CUSTODIAN_COUNT {
            public.push(CustodianPublic {
                index: reader.u8()?,
                encryption_public_key: reader.array::<32>()?,
                attestation_public_key: reader.array::<32>()?,
            });
        }

        let payload_nonce = reader.array::<24>()?;
        let payload_length = usize::try_from(reader.u32()?)
            .map_err(|_| AvailabilityError::Canonical("payload length"))?;
        if payload_length > MAX_WITNESS_BYTES + 16 {
            return Err(AvailabilityError::TooLarge);
        }
        let payload_ciphertext = reader.bytes(payload_length)?.to_vec();

        let mut custodians = Vec::with_capacity(CUSTODIAN_COUNT);
        for expected_public in public {
            let repeated_index = reader.u8()?;
            if repeated_index != expected_public.index {
                return Err(AvailabilityError::Canonical("envelope index"));
            }
            let nonce = reader.array::<24>()?;
            let ciphertext_length = usize::from(reader.u16()?);
            if ciphertext_length != SHARE_CIPHERTEXT_BYTES {
                return Err(AvailabilityError::Canonical("share ciphertext length"));
            }
            let ciphertext = reader.bytes(ciphertext_length)?.to_vec();
            custodians.push(CustodianEnvelope {
                public: expected_public,
                nonce,
                ciphertext,
            });
        }
        if !reader.is_empty() {
            return Err(AvailabilityError::Canonical("trailing bytes"));
        }

        let bundle = Self {
            context,
            witness_len,
            ephemeral_public_key,
            commitments,
            custodians,
            payload_nonce,
            payload_ciphertext,
        };
        bundle.validate()?;
        if bundle.encode_validated() != bytes {
            return Err(AvailabilityError::Canonical("non-canonical re-encoding"));
        }
        Ok(bundle)
    }

    pub fn root(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(tagged_hash(ROOT_DOMAIN, &self.encode_validated()))
    }

    pub fn header_hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(tagged_hash(HEADER_DOMAIN, &self.header_bytes()))
    }

    pub(crate) fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(505);
        out.extend_from_slice(&BUNDLE_MAGIC);
        out.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
        out.push(RECOVERY_THRESHOLD as u8);
        out.push(CUSTODIAN_COUNT as u8);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.witness_len.to_be_bytes());
        out.extend_from_slice(&self.ephemeral_public_key);
        for commitment in &self.commitments {
            out.extend_from_slice(commitment);
        }
        for custodian in &self.custodians {
            out.push(custodian.public.index);
            out.extend_from_slice(&custodian.public.encryption_public_key);
            out.extend_from_slice(&custodian.public.attestation_public_key);
        }
        out
    }

    pub(crate) fn commitment_points(
        &self,
    ) -> Result<[curve25519_dalek::ristretto::RistrettoPoint; RECOVERY_THRESHOLD]> {
        let mut points = [
            curve25519_dalek::ristretto::RistrettoPoint::identity(),
            curve25519_dalek::ristretto::RistrettoPoint::identity(),
            curve25519_dalek::ristretto::RistrettoPoint::identity(),
        ];
        for (position, encoded) in self.commitments.iter().enumerate() {
            points[position] = CompressedRistretto(*encoded)
                .decompress()
                .ok_or(AvailabilityError::Canonical("Ristretto commitment"))?;
        }
        Ok(points)
    }
}

pub(crate) fn tagged_hash(domain: &[u8], message: &[u8]) -> [u8; 32] {
    let tag = Sha256::digest(domain);
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update(tag);
    hash.update(message);
    hash.finalize().into()
}

pub(crate) fn payload_aad(bundle: &WitnessBundle, header_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAYLOAD_AAD_DOMAIN.len() + 32 + 24);
    aad.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&bundle.payload_nonce);
    aad
}

pub(crate) fn share_aad(
    bundle: &WitnessBundle,
    header_hash: &[u8; 32],
    custodian: &CustodianEnvelope,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARE_AAD_DOMAIN.len() + 32 + 1 + 24 + 64);
    aad.extend_from_slice(SHARE_AAD_DOMAIN);
    aad.extend_from_slice(header_hash);
    aad.push(custodian.public.index);
    aad.extend_from_slice(&custodian.nonce);
    aad.extend_from_slice(&custodian.public.encryption_public_key);
    aad.extend_from_slice(&custodian.public.attestation_public_key);
    aad.extend_from_slice(&bundle.ephemeral_public_key);
    aad
}

fn x25519_public_is_contributory(encoded: [u8; 32]) -> bool {
    if encoded.ct_eq(&[0; 32]).into() {
        return false;
    }
    let validation_secret = StaticSecret::from([0x42; 32]);
    let shared = validation_secret.diffie_hellman(&PublicKey::from(encoded));
    !bool::from(shared.as_bytes().ct_eq(&[0; 32]))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AvailabilityError::Canonical("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AvailabilityError::Canonical("truncated bundle"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| AvailabilityError::Canonical("array length"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_scheme_identity_is_frozen() {
        assert_eq!(
            availability_scheme_hash(),
            [
                0x8d, 0x24, 0x40, 0x42, 0x79, 0x39, 0xc9, 0x72, 0xfc, 0x0c, 0xba, 0x68, 0x41, 0xfb,
                0x66, 0x1e, 0x4c, 0x0a, 0x7d, 0x53, 0x0c, 0x84, 0x54, 0x3b, 0xd3, 0x90, 0x6a, 0xfb,
                0x3c, 0x34, 0x80, 0x4e,
            ]
        );
    }
}
