use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(feature = "producer")]
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
#[cfg(feature = "producer")]
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "producer")]
use crate::format::{CustodianEnvelope, SHARE_CIPHERTEXT_BYTES};
use crate::{
    error::{AvailabilityError, Result},
    format::{
        payload_aad, share_aad, tagged_hash, validate_custodian_registry, CustodianPublic,
        WitnessBundle, ATTEST_DOMAIN, BUNDLE_VERSION, CUSTODIAN_COUNT, CUSTODY_RECEIPT_DOMAIN,
        MAX_WITNESS_BYTES, PAYLOAD_KDF_DOMAIN, RECOVERY_THRESHOLD, SHARE_HASH_DOMAIN,
        SHARE_KDF_DOMAIN, SHARE_MAGIC, SHARE_PLAINTEXT_BYTES,
    },
};

#[cfg(feature = "producer")]
pub struct CustodianSecrets {
    index: u8,
    encryption_secret: StaticSecret,
    attestation_secret: SigningKey,
}

#[cfg(feature = "producer")]
impl CustodianSecrets {
    pub fn generate(index: u8) -> Result<Self> {
        validate_index(index)?;
        let mut rng = OsRng;
        let encryption_secret = StaticSecret::random_from_rng(OsRng);
        let attestation_secret = SigningKey::generate(&mut rng);
        Self::new(
            index,
            encryption_secret.to_bytes(),
            attestation_secret.to_bytes(),
        )
    }

    pub fn new(
        index: u8,
        encryption_secret: [u8; 32],
        attestation_secret: [u8; 32],
    ) -> Result<Self> {
        validate_index(index)?;
        if encryption_secret.ct_eq(&attestation_secret).into() {
            return Err(AvailabilityError::Custodian(
                "X25519 and Ed25519 secret material must be distinct",
            ));
        }
        let encryption_secret = StaticSecret::from(encryption_secret);
        let attestation_secret = SigningKey::from_bytes(&attestation_secret);
        let result = Self {
            index,
            encryption_secret,
            attestation_secret,
        };
        let public = result.public();
        if public.encryption_public_key.ct_eq(&[0; 32]).into() {
            return Err(AvailabilityError::NonContributoryKey);
        }
        if VerifyingKey::from_bytes(&public.attestation_public_key)
            .map_err(|_| AvailabilityError::Custodian("invalid Ed25519 key"))?
            .is_weak()
        {
            return Err(AvailabilityError::Custodian("weak Ed25519 key"));
        }
        Ok(result)
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn public(&self) -> CustodianPublic {
        CustodianPublic {
            index: self.index,
            encryption_public_key: PublicKey::from(&self.encryption_secret).to_bytes(),
            attestation_public_key: self.attestation_secret.verifying_key().to_bytes(),
        }
    }

    /// Returns key bytes solely for writing a protected provisioning file.
    pub fn provisioning_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.encryption_secret.to_bytes(),
            self.attestation_secret.to_bytes(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContribution {
    pub bundle_root: [u8; 32],
    pub custodian_index: u8,
    pub share: [u8; 32],
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

pub const RECOVERY_CONTRIBUTION_CANONICAL_LEN: usize = 1 + 32 + 32 + 64;

impl RecoveryContribution {
    /// Canonical private certificate leaf. This encoding contains the Shamir
    /// share and must remain inside the SP1 private witness; only
    /// [`recovery_certificate_root_v1`] may be projected into a public failure
    /// commitment after cryptographic verification.
    pub fn encode_canonical(&self) -> Result<[u8; RECOVERY_CONTRIBUTION_CANONICAL_LEN]> {
        validate_index(self.custodian_index)?;
        // A nonzero degree-two polynomial can legitimately evaluate to zero
        // at a custodian index; Feldman/signature verification, not an
        // ad-hoc nonzero rule, authenticates the share.
        if self.bundle_root == [0; 32] {
            return Err(AvailabilityError::Canonical("recovery contribution fields"));
        }
        let mut output = [0u8; RECOVERY_CONTRIBUTION_CANONICAL_LEN];
        output[0] = self.custodian_index;
        output[1..33].copy_from_slice(&self.bundle_root);
        output[33..65].copy_from_slice(&self.share);
        output[65..129].copy_from_slice(&self.signature);
        Ok(output)
    }
}

/// Root of exactly the three private contributions selected as the recovery
/// certificate. Verification remains a separate mandatory step: this helper
/// intentionally commits bytes and canonical order, not signature validity.
pub fn recovery_certificate_root_v1(contributions: &[RecoveryContribution]) -> Result<[u8; 32]> {
    if contributions.len() != RECOVERY_THRESHOLD {
        return Err(AvailabilityError::Threshold);
    }
    let mut bytes = Vec::with_capacity(RECOVERY_THRESHOLD * RECOVERY_CONTRIBUTION_CANONICAL_LEN);
    let mut previous_index = None;
    for contribution in contributions {
        if previous_index.is_some_and(|prior| contribution.custodian_index <= prior) {
            return Err(AvailabilityError::DuplicateCustodian);
        }
        previous_index = Some(contribution.custodian_index);
        bytes.extend_from_slice(&contribution.encode_canonical()?);
    }
    Ok(tagged_hash(b"ECX/witness-recovery-certificate/v1", &bytes))
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveredWitness(Vec<u8>);

impl RecoveredWitness {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Private values which make bundle encryption a verifiable proof relation.
///
/// This value is supplied only inside the zero-knowledge witness. It lets the
/// transition guest prove that the public bundle contains the exact expected
/// recovery payload and five correctly encrypted Shamir shares, without
/// exposing either the payload key or the ephemeral X25519 secret.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityEncryptionWitnessV1 {
    pub version: u8,
    pub polynomial_coefficients: [[u8; 32]; RECOVERY_THRESHOLD],
    pub ephemeral_secret_key: [u8; 32],
}

impl AvailabilityEncryptionWitnessV1 {
    pub const VERSION: u8 = 1;
}

impl std::fmt::Debug for AvailabilityEncryptionWitnessV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AvailabilityEncryptionWitnessV1")
            .field("version", &self.version)
            .field("polynomial_coefficients", &"[REDACTED]")
            .field("ephemeral_secret_key", &"[REDACTED]")
            .finish()
    }
}

/// A custodian's signed statement that it durably persisted this exact bundle
/// and successfully decrypted and Feldman-validated its assigned share.
///
/// The receipt reveals no share. The transition proof requires a threshold of
/// distinct receipts before it will accept the bundle root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyReceiptV1 {
    pub version: u8,
    pub bundle_root: [u8; 32],
    pub context: [u8; 32],
    pub witness_len: u64,
    pub custodian_index: u8,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl CustodyReceiptV1 {
    pub const VERSION: u8 = 1;

    /// Canonical, serde-independent wire encoding used when a receipt is
    /// embedded in the bond-inbox source annex. This does not change the V1
    /// availability scheme: the bond inbox freezes this codec as a separate
    /// identity and round-trips every byte before signature verification.
    pub fn encode_canonical(&self) -> Result<[u8; CUSTODY_RECEIPT_CANONICAL_LEN]> {
        if self.version != Self::VERSION
            || self.bundle_root == [0; 32]
            || self.context == [0; 32]
            || self.witness_len == 0
            || !(1..=CUSTODIAN_COUNT as u8).contains(&self.custodian_index)
        {
            return Err(AvailabilityError::Canonical("custody receipt fields"));
        }
        let mut output = [0u8; CUSTODY_RECEIPT_CANONICAL_LEN];
        output[0] = self.version;
        output[1..33].copy_from_slice(&self.bundle_root);
        output[33..65].copy_from_slice(&self.context);
        output[65..73].copy_from_slice(&self.witness_len.to_be_bytes());
        output[73] = self.custodian_index;
        output[74..138].copy_from_slice(&self.signature);
        Ok(output)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CUSTODY_RECEIPT_CANONICAL_LEN {
            return Err(AvailabilityError::Canonical("custody receipt length"));
        }
        let receipt = Self {
            version: bytes[0],
            bundle_root: bytes[1..33]
                .try_into()
                .map_err(|_| AvailabilityError::Canonical("custody receipt root"))?,
            context: bytes[33..65]
                .try_into()
                .map_err(|_| AvailabilityError::Canonical("custody receipt context"))?,
            witness_len: u64::from_be_bytes(
                bytes[65..73]
                    .try_into()
                    .map_err(|_| AvailabilityError::Canonical("custody receipt length"))?,
            ),
            custodian_index: bytes[73],
            signature: bytes[74..138]
                .try_into()
                .map_err(|_| AvailabilityError::Canonical("custody receipt signature"))?,
        };
        if receipt.encode_canonical()?.as_slice() != bytes {
            return Err(AvailabilityError::Canonical(
                "custody receipt non-canonical re-encoding",
            ));
        }
        Ok(receipt)
    }
}

pub const CUSTODY_RECEIPT_CANONICAL_LEN: usize = 138;

/// Separate frozen identity for the exact receipt bytes used by the V2 bond
/// inbox.  Keeping this outside `availability_scheme_hash()` preserves the
/// already-deployed V1 availability profile.
pub fn custody_receipt_codec_hash_v1() -> [u8; 32] {
    tagged_hash(
        b"ECX/witness-custody-receipt-codec/v1",
        b"version:u8|bundle_root:32|context:32|witness_len:u64be|custodian_index:u8(1..5)|ed25519_signature:64",
    )
}

mod signature_serde {
    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(signature)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("exactly 64 Ed25519 signature bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(65, &self));
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(feature = "producer")]
pub fn create_bundle(
    context: [u8; 32],
    witness: &[u8],
    custodians: &[CustodianPublic],
) -> Result<WitnessBundle> {
    create_bundle_with_encryption_witness(context, witness, custodians).map(|(bundle, _)| bundle)
}

/// Construct a bundle and retain the private opening needed by the transition
/// proof to verify all encryption, commitments, and plaintext semantics.
#[cfg(feature = "producer")]
pub fn create_bundle_with_encryption_witness(
    context: [u8; 32],
    witness: &[u8],
    custodians: &[CustodianPublic],
) -> Result<(WitnessBundle, AvailabilityEncryptionWitnessV1)> {
    if context.ct_eq(&[0; 32]).into() {
        return Err(AvailabilityError::Canonical("zero application context"));
    }
    if witness.is_empty() || witness.len() > MAX_WITNESS_BYTES {
        return Err(AvailabilityError::WitnessSize {
            max: MAX_WITNESS_BYTES,
        });
    }
    validate_custodian_registry(custodians)?;

    let mut rng = OsRng;
    let coefficients = Zeroizing::new([
        random_nonzero_scalar(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    let mut commitments = [[0; 32]; RECOVERY_THRESHOLD];
    for (output, coefficient) in commitments.iter_mut().zip(coefficients.iter()) {
        *output = (RISTRETTO_BASEPOINT_POINT * coefficient)
            .compress()
            .to_bytes();
    }

    let ephemeral_secret_bytes =
        canonical_x25519_secret(StaticSecret::random_from_rng(OsRng).to_bytes());
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let mut payload_nonce = [0; 24];
    rng.fill_bytes(&mut payload_nonce);

    let mut envelopes = Vec::with_capacity(CUSTODIAN_COUNT);
    let mut nonces = Vec::<[u8; 24]>::with_capacity(CUSTODIAN_COUNT);
    for public in custodians {
        let nonce = unique_nonce(&mut rng, &nonces);
        nonces.push(nonce);
        envelopes.push(CustodianEnvelope {
            public: *public,
            nonce,
            ciphertext: vec![0; SHARE_CIPHERTEXT_BYTES],
        });
    }

    let witness_len = u64::try_from(witness.len()).map_err(|_| AvailabilityError::WitnessSize {
        max: MAX_WITNESS_BYTES,
    })?;
    let mut bundle = WitnessBundle {
        context,
        witness_len,
        ephemeral_public_key,
        commitments,
        custodians: envelopes,
        payload_nonce,
        payload_ciphertext: vec![0; witness.len() + 16],
    };
    bundle.validate()?;
    let header_hash = bundle.header_hash()?;

    let payload_key = derive_payload_key(&coefficients[0], &header_hash, &context)?;
    let payload_nonce_value = XNonce::from(bundle.payload_nonce);
    bundle.payload_ciphertext = XChaCha20Poly1305::new_from_slice(payload_key.as_ref())
        .map_err(|_| AvailabilityError::Aead)?
        .encrypt(
            &payload_nonce_value,
            Payload {
                msg: witness,
                aad: &payload_aad(&bundle, &header_hash),
            },
        )
        .map_err(|_| AvailabilityError::Aead)?;

    for position in 0..CUSTODIAN_COUNT {
        let index = bundle.custodians[position].public.index;
        let share = evaluate_polynomial(&coefficients, index);
        let mut plaintext = Zeroizing::new(Vec::with_capacity(SHARE_PLAINTEXT_BYTES));
        plaintext.extend_from_slice(&SHARE_MAGIC);
        plaintext.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
        plaintext.push(index);
        plaintext.push(0);
        plaintext.extend_from_slice(&share.to_bytes());
        debug_assert_eq!(plaintext.len(), SHARE_PLAINTEXT_BYTES);

        let recipient = PublicKey::from(bundle.custodians[position].public.encryption_public_key);
        let shared = ephemeral_secret.diffie_hellman(&recipient);
        if shared.as_bytes().ct_eq(&[0; 32]).into() {
            return Err(AvailabilityError::NonContributoryKey);
        }
        let share_key = derive_share_key(
            shared.as_bytes(),
            &header_hash,
            index,
            &bundle.ephemeral_public_key,
            &bundle.custodians[position].public.encryption_public_key,
        )?;
        let aad = share_aad(&bundle, &header_hash, &bundle.custodians[position]);
        let share_nonce_value = XNonce::from(bundle.custodians[position].nonce);
        bundle.custodians[position].ciphertext =
            XChaCha20Poly1305::new_from_slice(share_key.as_ref())
                .map_err(|_| AvailabilityError::Aead)?
                .encrypt(
                    &share_nonce_value,
                    Payload {
                        msg: plaintext.as_slice(),
                        aad: &aad,
                    },
                )
                .map_err(|_| AvailabilityError::Aead)?;
    }

    bundle.validate()?;
    let encryption_witness = AvailabilityEncryptionWitnessV1 {
        version: AvailabilityEncryptionWitnessV1::VERSION,
        polynomial_coefficients: coefficients.each_ref().map(Scalar::to_bytes),
        ephemeral_secret_key: ephemeral_secret_bytes,
    };
    Ok((bundle, encryption_witness))
}

/// Verify the complete encrypted-bundle relation against an exact plaintext.
///
/// Structural bundle validation alone cannot distinguish valid-looking random
/// ciphertext from recoverable state. This verifier proves that the three
/// Feldman commitments open to the supplied polynomial, that every one of the
/// five encrypted envelopes contains its correct polynomial evaluation, and
/// that the payload AEAD decrypts to `expected_payload` byte-for-byte.
pub fn verify_bundle_encryption(
    bundle: &WitnessBundle,
    encryption_witness: &AvailabilityEncryptionWitnessV1,
    expected_payload: &[u8],
) -> Result<()> {
    bundle.validate()?;
    if encryption_witness.version != AvailabilityEncryptionWitnessV1::VERSION {
        return Err(AvailabilityError::Canonical(
            "availability encryption witness version",
        ));
    }
    if expected_payload.is_empty() || expected_payload.len() > MAX_WITNESS_BYTES {
        return Err(AvailabilityError::WitnessSize {
            max: MAX_WITNESS_BYTES,
        });
    }
    if bundle.witness_len
        != u64::try_from(expected_payload.len()).map_err(|_| AvailabilityError::WitnessSize {
            max: MAX_WITNESS_BYTES,
        })?
    {
        return Err(AvailabilityError::Canonical("recovery payload length"));
    }

    let mut coefficients = Zeroizing::new([Scalar::ZERO; RECOVERY_THRESHOLD]);
    for (output, encoded) in coefficients
        .iter_mut()
        .zip(encryption_witness.polynomial_coefficients)
    {
        *output = Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
            .ok_or(AvailabilityError::InvalidShare)?;
    }
    if coefficients[0] == Scalar::ZERO {
        return Err(AvailabilityError::InvalidShare);
    }
    for ((commitment, coefficient), encoded) in bundle
        .commitment_points()?
        .iter()
        .zip(coefficients.iter())
        .zip(bundle.commitments)
    {
        let expected = RISTRETTO_BASEPOINT_POINT * coefficient;
        if *commitment != expected || expected.compress().to_bytes() != encoded {
            return Err(AvailabilityError::InvalidShare);
        }
    }

    if canonical_x25519_secret(encryption_witness.ephemeral_secret_key)
        != encryption_witness.ephemeral_secret_key
    {
        return Err(AvailabilityError::Canonical(
            "non-canonical ephemeral X25519 secret",
        ));
    }
    let ephemeral_secret = StaticSecret::from(encryption_witness.ephemeral_secret_key);
    if PublicKey::from(&ephemeral_secret).to_bytes() != bundle.ephemeral_public_key {
        return Err(AvailabilityError::Canonical("ephemeral X25519 opening"));
    }
    let header_hash = bundle.header_hash()?;
    for envelope in &bundle.custodians {
        let recipient = PublicKey::from(envelope.public.encryption_public_key);
        let shared = ephemeral_secret.diffie_hellman(&recipient);
        if shared.as_bytes().ct_eq(&[0; 32]).into() {
            return Err(AvailabilityError::NonContributoryKey);
        }
        let share_key = derive_share_key(
            shared.as_bytes(),
            &header_hash,
            envelope.public.index,
            &bundle.ephemeral_public_key,
            &envelope.public.encryption_public_key,
        )?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(share_key.as_ref())
                .map_err(|_| AvailabilityError::Aead)?
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &share_aad(bundle, &header_hash, envelope),
                    },
                )
                .map_err(|_| AvailabilityError::Aead)?,
        );
        let expected_share = evaluate_polynomial(&coefficients, envelope.public.index).to_bytes();
        if parse_share_plaintext(&plaintext, envelope.public.index)? != expected_share {
            return Err(AvailabilityError::InvalidShare);
        }
    }

    let payload_key = derive_payload_key(&coefficients[0], &header_hash, &bundle.context)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(payload_key.as_ref())
            .map_err(|_| AvailabilityError::Aead)?
            .decrypt(
                &XNonce::from(bundle.payload_nonce),
                Payload {
                    msg: &bundle.payload_ciphertext,
                    aad: &payload_aad(bundle, &header_hash),
                },
            )
            .map_err(|_| AvailabilityError::Aead)?,
    );
    if plaintext.as_slice() != expected_payload {
        return Err(AvailabilityError::Canonical(
            "recovery payload does not match transition",
        ));
    }
    Ok(())
}

/// Verify a threshold of distinct post-persistence custody receipts.
///
/// This proves that at least three configured custodians signed the exact
/// bundle only after their service-side implementation had persisted it and
/// validated its encrypted share. It cannot prove future retention, so normal
/// monitoring and replication remain required.
pub fn verify_custody_receipts(
    bundle: &WitnessBundle,
    receipts: &[CustodyReceiptV1],
) -> Result<()> {
    bundle.validate()?;
    let registry = bundle
        .custodians
        .iter()
        .map(|envelope| envelope.public)
        .collect::<Vec<_>>();
    verify_custody_receipts_compact(
        bundle.root()?,
        bundle.context,
        bundle.witness_len,
        &registry,
        receipts,
    )
}

/// Verify custody for an already authenticated bundle root without carrying
/// its potentially 16 MiB ciphertext through a recursive parent witness.
/// The caller must bind `custodian_registry_hash(registry)` in its frozen
/// configuration and obtain the full bundle by `bundle_root` for recovery.
pub fn verify_custody_receipts_compact(
    bundle_root: [u8; 32],
    context: [u8; 32],
    witness_len: u64,
    registry: &[CustodianPublic],
    receipts: &[CustodyReceiptV1],
) -> Result<()> {
    validate_custodian_registry(registry)?;
    if bundle_root == [0; 32]
        || context == [0; 32]
        || witness_len == 0
        || witness_len > MAX_WITNESS_BYTES as u64
    {
        return Err(AvailabilityError::InvalidAttestation);
    }
    if !(RECOVERY_THRESHOLD..=CUSTODIAN_COUNT).contains(&receipts.len()) {
        return Err(AvailabilityError::Threshold);
    }
    let mut seen = [false; CUSTODIAN_COUNT];
    for receipt in receipts {
        if receipt.version != CustodyReceiptV1::VERSION
            || receipt.bundle_root != bundle_root
            || receipt.context != context
            || receipt.witness_len != witness_len
            || !(1..=CUSTODIAN_COUNT as u8).contains(&receipt.custodian_index)
        {
            return Err(AvailabilityError::InvalidAttestation);
        }
        let position = usize::from(receipt.custodian_index - 1);
        if seen[position] {
            return Err(AvailabilityError::DuplicateCustodian);
        }
        seen[position] = true;
        let public = &registry[position];
        if public.index != receipt.custodian_index {
            return Err(AvailabilityError::InvalidAttestation);
        }
        let verifying_key = VerifyingKey::from_bytes(&public.attestation_public_key)
            .map_err(|_| AvailabilityError::InvalidAttestation)?;
        let signature = Signature::from_bytes(&receipt.signature);
        verifying_key
            .verify_strict(&custody_receipt_message(receipt), &signature)
            .map_err(|_| AvailabilityError::InvalidAttestation)?;
    }
    Ok(())
}

#[cfg(feature = "producer")]
impl CustodianSecrets {
    fn decrypt_validated_share(&self, bundle: &WitnessBundle) -> Result<Zeroizing<[u8; 32]>> {
        bundle.validate()?;
        let position = usize::from(
            self.index
                .checked_sub(1)
                .ok_or(AvailabilityError::Custodian("index outside 1 through 5"))?,
        );
        let envelope = bundle
            .custodians
            .get(position)
            .ok_or(AvailabilityError::Custodian("index outside 1 through 5"))?;
        if envelope.public != self.public() {
            return Err(AvailabilityError::Custodian(
                "configured secrets do not match bundle identity",
            ));
        }

        let header_hash = bundle.header_hash()?;
        let sender = PublicKey::from(bundle.ephemeral_public_key);
        let shared = self.encryption_secret.diffie_hellman(&sender);
        if shared.as_bytes().ct_eq(&[0; 32]).into() {
            return Err(AvailabilityError::NonContributoryKey);
        }
        let share_key = derive_share_key(
            shared.as_bytes(),
            &header_hash,
            self.index,
            &bundle.ephemeral_public_key,
            &envelope.public.encryption_public_key,
        )?;
        let share_nonce_value = XNonce::from(envelope.nonce);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(share_key.as_ref())
                .map_err(|_| AvailabilityError::Aead)?
                .decrypt(
                    &share_nonce_value,
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &share_aad(bundle, &header_hash, envelope),
                    },
                )
                .map_err(|_| AvailabilityError::Aead)?,
        );
        let share = Zeroizing::new(parse_share_plaintext(&plaintext, self.index)?);
        verify_feldman_share(bundle, self.index, &share)?;
        Ok(share)
    }

    /// Sign a recovery contribution which intentionally reveals this
    /// custodian's share to an authorized recovery coordinator.
    pub fn attest(&self, bundle: &WitnessBundle) -> Result<RecoveryContribution> {
        let share = self.decrypt_validated_share(bundle)?;

        let bundle_root = bundle.root()?;
        let message = attestation_message(&bundle_root, &bundle.context, self.index, &share);
        let signature = self.attestation_secret.sign(&message).to_bytes();
        Ok(RecoveryContribution {
            bundle_root,
            custodian_index: self.index,
            share: *share,
            signature,
        })
    }

    /// Produce a non-revealing receipt after the caller has durably persisted
    /// the bundle. Share decryption and Feldman validation happen before the
    /// receipt is signed.
    pub fn custody_receipt(&self, bundle: &WitnessBundle) -> Result<CustodyReceiptV1> {
        let _validated_share = self.decrypt_validated_share(bundle)?;
        let mut receipt = CustodyReceiptV1 {
            version: CustodyReceiptV1::VERSION,
            bundle_root: bundle.root()?,
            context: bundle.context,
            witness_len: bundle.witness_len,
            custodian_index: self.index,
            signature: [0; 64],
        };
        receipt.signature = self
            .attestation_secret
            .sign(&custody_receipt_message(&receipt))
            .to_bytes();
        Ok(receipt)
    }
}

pub fn verify_recovery_certificate(
    bundle: &WitnessBundle,
    contributions: &[RecoveryContribution],
) -> Result<()> {
    bundle.validate()?;
    if !(RECOVERY_THRESHOLD..=CUSTODIAN_COUNT).contains(&contributions.len()) {
        return Err(AvailabilityError::Threshold);
    }
    let bundle_root = bundle.root()?;
    let mut seen = [false; CUSTODIAN_COUNT];

    for contribution in contributions {
        validate_index(contribution.custodian_index)?;
        let position = usize::from(contribution.custodian_index - 1);
        if seen[position] {
            return Err(AvailabilityError::DuplicateCustodian);
        }
        seen[position] = true;
        if !bool::from(contribution.bundle_root.ct_eq(&bundle_root)) {
            return Err(AvailabilityError::RootMismatch);
        }
        verify_feldman_share(bundle, contribution.custodian_index, &contribution.share)?;

        let public = &bundle.custodians[position].public;
        let verifying_key = VerifyingKey::from_bytes(&public.attestation_public_key)
            .map_err(|_| AvailabilityError::InvalidAttestation)?;
        let signature = Signature::from_bytes(&contribution.signature);
        let message = attestation_message(
            &bundle_root,
            &bundle.context,
            contribution.custodian_index,
            &contribution.share,
        );
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| AvailabilityError::InvalidAttestation)?;
    }
    Ok(())
}

pub fn recover_witness(
    bundle: &WitnessBundle,
    contributions: &[RecoveryContribution],
) -> Result<RecoveredWitness> {
    verify_recovery_certificate(bundle, contributions)?;

    // Recovery certificates have one frozen, non-malleable representation;
    // accepting four or five valid shares here would let a producer choose
    // multiple roots for the same recovered payload.
    recovery_certificate_root_v1(contributions)?;
    let selected = contributions;
    let mut shares = Zeroizing::new(Vec::with_capacity(RECOVERY_THRESHOLD));
    for contribution in selected {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(contribution.share))
            .ok_or(AvailabilityError::InvalidShare)?;
        shares.push((
            Scalar::from(u64::from(contribution.custodian_index)),
            scalar,
        ));
    }
    let mut secret = Zeroizing::new(Scalar::ZERO);
    for (position, (x_i, y_i)) in shares.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (other_position, (x_j, _)) in shares.iter().enumerate() {
            if position != other_position {
                numerator *= -*x_j;
                denominator *= *x_i - *x_j;
            }
        }
        *secret += *y_i * numerator * denominator.invert();
    }
    if *secret == Scalar::ZERO {
        return Err(AvailabilityError::InvalidShare);
    }

    let header_hash = bundle.header_hash()?;
    let payload_key = derive_payload_key(&secret, &header_hash, &bundle.context)?;
    let payload_nonce_value = XNonce::from(bundle.payload_nonce);
    let plaintext = XChaCha20Poly1305::new_from_slice(payload_key.as_ref())
        .map_err(|_| AvailabilityError::Aead)?
        .decrypt(
            &payload_nonce_value,
            Payload {
                msg: &bundle.payload_ciphertext,
                aad: &payload_aad(bundle, &header_hash),
            },
        )
        .map_err(|_| AvailabilityError::Aead)?;
    if plaintext.len()
        != usize::try_from(bundle.witness_len).map_err(|_| AvailabilityError::WitnessSize {
            max: MAX_WITNESS_BYTES,
        })?
    {
        return Err(AvailabilityError::Canonical("recovered witness length"));
    }
    Ok(RecoveredWitness(plaintext))
}

#[cfg(feature = "producer")]
fn random_nonzero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let scalar = Scalar::random(&mut *rng);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

fn canonical_x25519_secret(mut secret: [u8; 32]) -> [u8; 32] {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

#[cfg(feature = "producer")]
fn unique_nonce(rng: &mut OsRng, existing: &[[u8; 24]]) -> [u8; 24] {
    loop {
        let mut nonce = [0; 24];
        rng.fill_bytes(&mut nonce);
        if !existing.contains(&nonce) {
            return nonce;
        }
    }
}

fn evaluate_polynomial(coefficients: &[Scalar; RECOVERY_THRESHOLD], index: u8) -> Scalar {
    let x = Scalar::from(u64::from(index));
    coefficients[0] + coefficients[1] * x + coefficients[2] * x * x
}

fn verify_feldman_share(bundle: &WitnessBundle, index: u8, encoded: &[u8; 32]) -> Result<()> {
    validate_index(index)?;
    let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(*encoded))
        .ok_or(AvailabilityError::InvalidShare)?;
    let commitments = bundle.commitment_points()?;
    let x = Scalar::from(u64::from(index));
    let expected: RistrettoPoint = commitments[0] + commitments[1] * x + commitments[2] * x * x;
    let actual = RISTRETTO_BASEPOINT_POINT * share;
    if actual != expected {
        return Err(AvailabilityError::InvalidShare);
    }
    Ok(())
}

fn parse_share_plaintext(plaintext: &[u8], index: u8) -> Result<[u8; 32]> {
    if plaintext.len() != SHARE_PLAINTEXT_BYTES
        || plaintext[..8] != SHARE_MAGIC
        || plaintext[8..10] != BUNDLE_VERSION.to_be_bytes()
        || plaintext[10] != index
        || plaintext[11] != 0
    {
        return Err(AvailabilityError::InvalidShare);
    }
    plaintext[12..44]
        .try_into()
        .map_err(|_| AvailabilityError::InvalidShare)
}

fn derive_payload_key(
    secret: &Scalar,
    header_hash: &[u8; 32],
    context: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let input = Zeroizing::new(secret.to_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(header_hash), input.as_ref());
    let mut info = Vec::with_capacity(PAYLOAD_KDF_DOMAIN.len() + context.len());
    info.extend_from_slice(PAYLOAD_KDF_DOMAIN);
    info.extend_from_slice(context);
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| AvailabilityError::Aead)?;
    Ok(key)
}

fn derive_share_key(
    shared_secret: &[u8; 32],
    header_hash: &[u8; 32],
    index: u8,
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(header_hash), shared_secret);
    let mut info = Vec::with_capacity(SHARE_KDF_DOMAIN.len() + 65);
    info.extend_from_slice(SHARE_KDF_DOMAIN);
    info.push(index);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| AvailabilityError::Aead)?;
    Ok(key)
}

fn attestation_message(
    bundle_root: &[u8; 32],
    context: &[u8; 32],
    index: u8,
    share: &[u8; 32],
) -> [u8; 32] {
    let share_hash = tagged_hash(SHARE_HASH_DOMAIN, share);
    let mut message = Vec::with_capacity(32 + 32 + 1 + 32);
    message.extend_from_slice(bundle_root);
    message.extend_from_slice(context);
    message.push(index);
    message.extend_from_slice(&share_hash);
    tagged_hash(ATTEST_DOMAIN, &message)
}

fn custody_receipt_message(receipt: &CustodyReceiptV1) -> [u8; 32] {
    let mut message = Vec::with_capacity(1 + 32 + 32 + 8 + 1);
    message.push(receipt.version);
    message.extend_from_slice(&receipt.bundle_root);
    message.extend_from_slice(&receipt.context);
    message.extend_from_slice(&receipt.witness_len.to_be_bytes());
    message.push(receipt.custodian_index);
    tagged_hash(CUSTODY_RECEIPT_DOMAIN, &message)
}

fn validate_index(index: u8) -> Result<()> {
    if !(1..=CUSTODIAN_COUNT as u8).contains(&index) {
        return Err(AvailabilityError::Custodian(
            "index must be between 1 and 5",
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "producer"))]
mod tests {
    use super::*;
    use crate::format::MAX_BUNDLE_BYTES;

    fn fixture() -> (Vec<CustodianSecrets>, WitnessBundle) {
        let secrets: Vec<_> = (1..=5)
            .map(|i| CustodianSecrets::generate(i).unwrap())
            .collect();
        let public: Vec<_> = secrets.iter().map(CustodianSecrets::public).collect();
        let bundle = create_bundle([7; 32], b"confidential transition witness", &public).unwrap();
        (secrets, bundle)
    }

    #[test]
    fn every_three_of_five_subset_recovers() {
        let (secrets, bundle) = fixture();
        let all: Vec<_> = secrets
            .iter()
            .map(|key| key.attest(&bundle).unwrap())
            .collect();
        for a in 0..3 {
            for b in (a + 1)..4 {
                for c in (b + 1)..5 {
                    let recovered =
                        recover_witness(&bundle, &[all[a].clone(), all[b].clone(), all[c].clone()])
                            .unwrap();
                    assert_eq!(recovered.as_bytes(), b"confidential transition witness");
                }
            }
        }
    }

    #[test]
    fn encryption_opening_binds_every_share_and_exact_payload() {
        let secrets: Vec<_> = (1..=5)
            .map(|i| CustodianSecrets::generate(i).unwrap())
            .collect();
        let public: Vec<_> = secrets.iter().map(CustodianSecrets::public).collect();
        let payload = b"canonical availability-neutral transition";
        let (bundle, encryption_witness) =
            create_bundle_with_encryption_witness([8; 32], payload, &public).unwrap();
        verify_bundle_encryption(&bundle, &encryption_witness, payload).unwrap();

        assert!(matches!(
            verify_bundle_encryption(&bundle, &encryption_witness, b"different transition"),
            Err(AvailabilityError::Canonical("recovery payload length"))
        ));

        let mut wrong_coefficients = encryption_witness.clone();
        wrong_coefficients.polynomial_coefficients[1][0] ^= 1;
        assert!(verify_bundle_encryption(&bundle, &wrong_coefficients, payload).is_err());

        let mut wrong_ephemeral = encryption_witness.clone();
        wrong_ephemeral.ephemeral_secret_key[0] ^= 1;
        assert!(matches!(
            verify_bundle_encryption(&bundle, &wrong_ephemeral, payload),
            Err(AvailabilityError::Canonical(
                "non-canonical ephemeral X25519 secret"
            ))
        ));

        let mut tampered_share = bundle.clone();
        tampered_share.custodians[4].ciphertext[0] ^= 1;
        assert!(matches!(
            verify_bundle_encryption(&tampered_share, &encryption_witness, payload),
            Err(AvailabilityError::Aead)
        ));
    }

    #[test]
    fn same_length_garbage_payload_is_rejected() {
        let secrets: Vec<_> = (1..=5)
            .map(|i| CustodianSecrets::generate(i).unwrap())
            .collect();
        let public: Vec<_> = secrets.iter().map(CustodianSecrets::public).collect();
        let payload = b"expected private transition";
        let (bundle, encryption_witness) =
            create_bundle_with_encryption_witness([9; 32], payload, &public).unwrap();
        let garbage = vec![0x55; payload.len()];
        assert!(matches!(
            verify_bundle_encryption(&bundle, &encryption_witness, &garbage),
            Err(AvailabilityError::Canonical(
                "recovery payload does not match transition"
            ))
        ));
    }

    #[test]
    fn two_shares_are_not_a_certificate() {
        let (secrets, bundle) = fixture();
        let contributions: Vec<_> = secrets[..2]
            .iter()
            .map(|key| key.attest(&bundle).unwrap())
            .collect();
        assert!(matches!(
            recover_witness(&bundle, &contributions),
            Err(AvailabilityError::Threshold)
        ));
    }

    #[test]
    fn custody_receipts_require_three_distinct_persisting_custodians() {
        let (secrets, bundle) = fixture();
        let receipts = secrets[..3]
            .iter()
            .map(|custodian| custodian.custody_receipt(&bundle).unwrap())
            .collect::<Vec<_>>();
        verify_custody_receipts(&bundle, &receipts).unwrap();
        let registry = secrets
            .iter()
            .map(CustodianSecrets::public)
            .collect::<Vec<_>>();
        verify_custody_receipts_compact(
            bundle.root().unwrap(),
            bundle.context,
            bundle.witness_len,
            &registry,
            &receipts,
        )
        .unwrap();
        let mut wrong_root = bundle.root().unwrap();
        wrong_root[0] ^= 1;
        assert!(verify_custody_receipts_compact(
            wrong_root,
            bundle.context,
            bundle.witness_len,
            &registry,
            &receipts,
        )
        .is_err());
        assert!(matches!(
            verify_custody_receipts(&bundle, &receipts[..2]),
            Err(AvailabilityError::Threshold)
        ));

        let mut duplicate = receipts.clone();
        duplicate[2] = duplicate[0].clone();
        assert!(matches!(
            verify_custody_receipts(&bundle, &duplicate),
            Err(AvailabilityError::DuplicateCustodian)
        ));

        let mut wrong_context = receipts.clone();
        wrong_context[0].context[0] ^= 1;
        assert!(matches!(
            verify_custody_receipts(&bundle, &wrong_context),
            Err(AvailabilityError::InvalidAttestation)
        ));

        let mut transplanted = receipts;
        transplanted[0].signature = transplanted[1].signature;
        assert!(matches!(
            verify_custody_receipts(&bundle, &transplanted),
            Err(AvailabilityError::InvalidAttestation)
        ));
    }

    #[test]
    fn custody_receipt_canonical_codec_is_fixed_and_rejects_aliases() {
        let receipt = CustodyReceiptV1 {
            version: CustodyReceiptV1::VERSION,
            bundle_root: [1; 32],
            context: [2; 32],
            witness_len: 0x0102_0304_0506_0708,
            custodian_index: 3,
            signature: [4; 64],
        };
        let encoded = receipt.encode_canonical().unwrap();
        assert_eq!(encoded.len(), CUSTODY_RECEIPT_CANONICAL_LEN);
        assert_eq!(&encoded[65..73], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(
            CustodyReceiptV1::decode_canonical(&encoded).unwrap(),
            receipt
        );
        assert!(CustodyReceiptV1::decode_canonical(&encoded[..137]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(CustodyReceiptV1::decode_canonical(&trailing).is_err());
        let mut zero_root = encoded;
        zero_root[1..33].fill(0);
        assert!(CustodyReceiptV1::decode_canonical(&zero_root).is_err());
        assert_ne!(
            custody_receipt_codec_hash_v1(),
            crate::availability_scheme_hash()
        );
    }

    #[test]
    fn duplicate_custodian_is_rejected() {
        let (secrets, bundle) = fixture();
        let first = secrets[0].attest(&bundle).unwrap();
        assert!(matches!(
            verify_recovery_certificate(&bundle, &[first.clone(), first.clone(), first]),
            Err(AvailabilityError::DuplicateCustodian)
        ));
    }

    #[test]
    fn recovery_certificate_root_is_exact_private_three_share_transcript() {
        let (secrets, bundle) = fixture();
        let contributions = secrets[..3]
            .iter()
            .map(|secret| secret.attest(&bundle).unwrap())
            .collect::<Vec<_>>();
        verify_recovery_certificate(&bundle, &contributions).unwrap();
        let root = recovery_certificate_root_v1(&contributions).unwrap();
        assert_ne!(root, [0; 32]);
        assert_eq!(
            contributions[0].encode_canonical().unwrap().len(),
            RECOVERY_CONTRIBUTION_CANONICAL_LEN
        );

        let mut reordered = contributions.clone();
        reordered.swap(0, 1);
        assert!(matches!(
            recovery_certificate_root_v1(&reordered),
            Err(AvailabilityError::DuplicateCustodian)
        ));
        assert!(matches!(
            recovery_certificate_root_v1(&contributions[..2]),
            Err(AvailabilityError::Threshold)
        ));
        let mut changed = contributions;
        changed[0].signature[0] ^= 1;
        assert_ne!(recovery_certificate_root_v1(&changed).unwrap(), root);
        assert!(verify_recovery_certificate(&bundle, &changed).is_err());
    }

    #[test]
    fn wrong_encryption_key_cannot_attest() {
        let (secrets, bundle) = fixture();
        let (wrong_encryption, _) = CustodianSecrets::generate(1).unwrap().provisioning_bytes();
        let (_, signing) = secrets[0].provisioning_bytes();
        let wrong = CustodianSecrets::new(1, wrong_encryption, signing).unwrap();
        assert!(matches!(
            wrong.attest(&bundle),
            Err(AvailabilityError::Custodian(_))
        ));
    }

    #[test]
    fn encrypted_share_tamper_cannot_receive_attestation() {
        let (secrets, mut bundle) = fixture();
        bundle.custodians[0].ciphertext[0] ^= 1;
        assert!(matches!(
            secrets[0].attest(&bundle),
            Err(AvailabilityError::Aead)
        ));
    }

    #[test]
    fn payload_ciphertext_tamper_fails_decryption() {
        let (secrets, mut bundle) = fixture();
        let contributions: Vec<_> = secrets[..3]
            .iter()
            .map(|key| key.attest(&bundle).unwrap())
            .collect();
        bundle.payload_ciphertext[0] ^= 1;
        assert!(matches!(
            recover_witness(&bundle, &contributions),
            Err(AvailabilityError::RootMismatch)
        ));
    }

    #[test]
    fn malformed_share_fails_even_with_valid_custodian_signature() {
        let (secrets, bundle) = fixture();
        let mut contributions: Vec<_> = secrets[..3]
            .iter()
            .map(|key| key.attest(&bundle).unwrap())
            .collect();
        contributions[0].share[0] ^= 1;
        let message = attestation_message(
            &contributions[0].bundle_root,
            &bundle.context,
            1,
            &contributions[0].share,
        );
        contributions[0].signature = secrets[0].attestation_secret.sign(&message).to_bytes();
        assert!(matches!(
            verify_recovery_certificate(&bundle, &contributions),
            Err(AvailabilityError::InvalidShare)
        ));
    }

    #[test]
    fn signature_cannot_be_transplanted() {
        let (secrets, bundle) = fixture();
        let mut contributions: Vec<_> = secrets[..3]
            .iter()
            .map(|key| key.attest(&bundle).unwrap())
            .collect();
        contributions[0].signature = contributions[1].signature;
        assert!(matches!(
            verify_recovery_certificate(&bundle, &contributions),
            Err(AvailabilityError::InvalidAttestation)
        ));
    }

    #[test]
    fn canonical_round_trip_and_strict_domains() {
        let (_, bundle) = fixture();
        let encoded = bundle.encode().unwrap();
        assert_eq!(WitnessBundle::decode(&encoded).unwrap(), bundle);
        assert_eq!(
            encoded.len() - usize::try_from(bundle.witness_len).unwrap(),
            984
        );
        assert_eq!(MAX_BUNDLE_BYTES - MAX_WITNESS_BYTES, 1_024);
        assert!(encoded.len() <= MAX_BUNDLE_BYTES);

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(WitnessBundle::decode(&bad_magic).is_err());

        let mut bad_count = encoded.clone();
        bad_count[11] = 4;
        assert!(WitnessBundle::decode(&bad_count).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(WitnessBundle::decode(&trailing).is_err());
    }

    #[test]
    fn distinct_key_types_are_enforced() {
        assert!(matches!(
            CustodianSecrets::new(1, [9; 32], [9; 32]),
            Err(AvailabilityError::Custodian(_))
        ));
    }
}
