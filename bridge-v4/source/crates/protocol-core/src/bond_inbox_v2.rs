//! Header-authenticated confidential bond-action inbox for protocol V2.
//!
//! The public Elements marker deliberately contains no contribution, share,
//! redemption-payment, or confidential-opening value.  It commits to an
//! encrypted availability bundle and to a blinded, fixed-width action body.
//! The transition proof reconstructs that body, consumes only a contiguous
//! prefix, and deterministically rejects malformed inner actions without
//! allowing malformed data to halt the cursor.

use std::collections::BTreeSet;

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::availability::AvailabilityConfigV1;
use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::merkle::ordered_root;
use crate::order::Signature64;
use crate::transition_v2::{
    BondSubscriptionV2, InsuranceRecapitalizationContributionV2, RedemptionCancellationV2Action,
    RedemptionEnqueueV2, SignedBondSubscriptionV2, SignedInsuranceRecapitalizationContributionV2,
    SignedRedemptionCancellationV2, SignedRedemptionEnqueueV2,
};
use crate::types::XOnlyKey;
use crate::ProtocolError;

pub const BOND_INBOX_MARKER_MAGIC: [u8; 4] = *b"ECXB";
pub const BOND_INBOX_MARKER_VERSION: u8 = 1;
pub const BOND_INBOX_MARKER_LEN: usize = 4 + 1 + 1 + (13 * 32) + 4 + 8 + 4 + 1 + 64;
pub const MAX_BOND_INBOX_BUNDLE_BYTES_V2: u32 = 64 * 1024;
/// Maximum native witness serialization for one source transaction. V2 admits
/// exactly one marker and one canonical input-zero annex frame per source
/// transaction; the separate per-block rule permits up to eight transactions.
pub const MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2: u32 = 576 * 1024;
/// Maximum exact full source-transaction serialization admitted for one
/// transaction. The per-block aggregate uses the same bound independently of
/// the smaller witness-only aggregate.
pub const MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2: u32 = 768 * 1024;
/// The frozen V1 custody-receipt codec is exactly 138 bytes.
pub const MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2: usize = 138;
pub const BOND_INBOX_MIN_DISTINCT_CUSTODY_RECEIPTS_V2: usize = 3;
pub const BOND_INBOX_MAX_CUSTODIANS_V2: usize = 5;

/// Commitment to the complete canonical encrypted availability bundle stored
/// in the designated source-transaction annex. Both length and every
/// ciphertext byte are bound; an external locator is never a valid substitute.
pub fn bond_inbox_availability_bundle_root_v2(
    canonical_encrypted_bundle: &[u8],
) -> Result<Hash32, ProtocolError> {
    if canonical_encrypted_bundle.is_empty()
        || canonical_encrypted_bundle.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(4 + canonical_encrypted_bundle.len());
    put_u32(
        &mut bytes,
        u32::try_from(canonical_encrypted_bundle.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    );
    bytes.extend_from_slice(canonical_encrypted_bundle);
    Ok(tagged_hash(
        "ECX/bond-inbox-encrypted-availability-bundle/v2",
        &bytes,
    ))
}

/// Raw SHA-256 of the exact source transaction witness serialization. The
/// active-chain node also binds the resulting projection to `source_wtxid`.
pub fn bond_inbox_source_witness_sha256_v2(
    exact_source_witness: &[u8],
) -> Result<Hash32, ProtocolError> {
    if exact_source_witness.is_empty()
        || exact_source_witness.len() > MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2 as usize
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(Sha256::digest(exact_source_witness).into())
}

/// Public commitment to the exact serialized confidential staging TxOut. It
/// deliberately excludes source txid/wtxid to avoid a transaction self-cycle;
/// those locators are bound separately by [`BondInboxEntryV2`].
pub fn bond_inbox_staging_source_authorization_commitment_v2(
    exact_serialized_staging_txout: &[u8],
    staging_intent_id: Hash32,
    refund_script_sha256: Hash32,
    refund_not_before_parent_height: u64,
) -> Result<Hash32, ProtocolError> {
    if exact_serialized_staging_txout.is_empty()
        || exact_serialized_staging_txout.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        || staging_intent_id == [0; 32]
        || refund_script_sha256 == [0; 32]
        || refund_not_before_parent_height == 0
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(76 + exact_serialized_staging_txout.len());
    put_u32(
        &mut bytes,
        u32::try_from(exact_serialized_staging_txout.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    );
    bytes.extend_from_slice(exact_serialized_staging_txout);
    bytes.extend_from_slice(&staging_intent_id);
    bytes.extend_from_slice(&refund_script_sha256);
    put_u64(&mut bytes, refund_not_before_parent_height);
    Ok(tagged_hash(
        "ECX/bond-inbox-staging-source-authorization/v2",
        &bytes,
    ))
}

/// Canonical no-staging authorization for subscriptions, recap contributions,
/// and cancellations.  This domain is intentionally distinct from staging;
/// node/proof integrations must not accept arbitrary opaque bytes instead.
pub fn bond_inbox_no_staging_source_authorization_commitment_v2(
    chain_id: Hash32,
    configuration_hash: Hash32,
    signer: XOnlyKey,
    action_id: Hash32,
    marker_vout: u32,
) -> Result<Hash32, ProtocolError> {
    if chain_id == [0; 32]
        || configuration_hash == [0; 32]
        || action_id == [0; 32]
        || marker_vout == u32::MAX
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(132);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&configuration_hash);
    signer.encode_to(&mut bytes);
    bytes.extend_from_slice(&action_id);
    put_u32(&mut bytes, marker_vout);
    Ok(tagged_hash(
        "ECX/bond-inbox-no-staging-source-authorization/v2",
        &bytes,
    ))
}

/// Exact source-witness receipt bytes paired with their frozen registry slot.
/// Signature parsing and public-key verification are performed by the node
/// and proof integration for the frozen availability scheme.  This core type
/// supplies the one canonical digest/root/bitmap contract both must use.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxCustodyReceiptV2 {
    /// Zero-based position in the frozen five-custodian registry.
    pub custodian_index: u8,
    /// Complete canonical receipt bytes, including its signature.  Hashing a
    /// parsed subset would permit malleable source witnesses with the same
    /// public projection.
    pub exact_receipt_bytes: Vec<u8>,
}

/// V2 leaf-context binding for one exact V1 custody receipt. This is NOT the
/// Ed25519 message signed inside `CustodyReceiptV1`; node/proof integrations
/// must decode and verify that fixed 138-byte receipt under its V1 domain,
/// require its one-based index equals `custodian_index + 1`, and bind its
/// bundle root/context/length to the recovered `WitnessBundleV1` first.
pub fn bond_inbox_custody_receipt_binding_digest_v2(
    marker: &BondInboxMarkerV2,
    custodian_index: u8,
) -> Result<Hash32, ProtocolError> {
    marker.validate_syntax(MAX_BOND_INBOX_BUNDLE_BYTES_V2)?;
    if usize::from(custodian_index) >= BOND_INBOX_MAX_CUSTODIANS_V2 {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(32 * 6 + 5);
    bytes.extend_from_slice(&marker.availability_scheme_hash);
    bytes.extend_from_slice(&marker.availability_custodian_registry_hash);
    bytes.extend_from_slice(&marker.availability_context);
    bytes.extend_from_slice(&marker.availability_bundle_root);
    put_u32(&mut bytes, marker.availability_bundle_len);
    bytes.extend_from_slice(&marker.payload_commitment);
    bytes.extend_from_slice(&marker.source_authorization_commitment);
    put_u8(&mut bytes, custodian_index);
    Ok(tagged_hash(
        "ECX/bond-inbox-custody-receipt-binding/v2",
        &bytes,
    ))
}

/// Computes the exact ordered receipt root and bitmap committed in the public
/// marker. Receipts must be supplied in strictly increasing registry order;
/// this prevents node/prover disagreement over duplicate or permuted bytes.
pub fn canonical_bond_inbox_custody_receipts_v2(
    marker: &BondInboxMarkerV2,
    receipts: &[BondInboxCustodyReceiptV2],
) -> Result<(Hash32, u8), ProtocolError> {
    if receipts.len() < BOND_INBOX_MIN_DISTINCT_CUSTODY_RECEIPTS_V2
        || receipts.len() > BOND_INBOX_MAX_CUSTODIANS_V2
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut prior_index = None;
    let mut bitmap = 0u8;
    let mut leaves = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        if usize::from(receipt.custodian_index) >= BOND_INBOX_MAX_CUSTODIANS_V2
            || prior_index.is_some_and(|prior| receipt.custodian_index <= prior)
            || receipt.exact_receipt_bytes.len() != MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        prior_index = Some(receipt.custodian_index);
        bitmap |= 1u8 << receipt.custodian_index;
        let digest = bond_inbox_custody_receipt_binding_digest_v2(marker, receipt.custodian_index)?;
        let mut bytes = Vec::with_capacity(37 + receipt.exact_receipt_bytes.len());
        bytes.extend_from_slice(&digest);
        put_u32(
            &mut bytes,
            u32::try_from(receipt.exact_receipt_bytes.len())
                .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        );
        bytes.extend_from_slice(&receipt.exact_receipt_bytes);
        leaves.push(tagged_hash(
            "ECX/bond-inbox-exact-custody-receipt/v2",
            &bytes,
        ));
    }
    Ok((
        ordered_root("ECX/bond-inbox-custody-receipts/v2", &leaves),
        bitmap,
    ))
}

/// Recomputes the source-witness projections a node must authenticate before
/// appending an inbox entry. Callers additionally verify each receipt's
/// V1 signature against its indexed frozen custodian. The V2 binding digest is
/// leaf context only and must never be treated as the receipt's signed message.
pub fn verify_bond_inbox_source_witness_commitments_v2(
    marker: &BondInboxMarkerV2,
    availability: AvailabilityConfigV1,
    canonical_encrypted_bundle: &[u8],
    receipts: &[BondInboxCustodyReceiptV2],
) -> Result<(), ProtocolError> {
    marker.verify_availability_claim(availability, MAX_BOND_INBOX_BUNDLE_BYTES_V2)?;
    let (receipt_root, receipt_bitmap) =
        canonical_bond_inbox_custody_receipts_v2(marker, receipts)?;
    if marker.availability_bundle_len
        != u32::try_from(canonical_encrypted_bundle.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
        || marker.availability_bundle_root
            != bond_inbox_availability_bundle_root_v2(canonical_encrypted_bundle)?
        || marker.availability_receipt_root != receipt_root
        || marker.availability_receipt_bitmap != receipt_bitmap
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BondInboxActionKindV2 {
    Subscription = 0,
    RedemptionEnqueue = 1,
    RedemptionCancellation = 2,
    InsuranceRecapitalizationContribution = 3,
}

impl BondInboxActionKindV2 {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Subscription),
            1 => Ok(Self::RedemptionEnqueue),
            2 => Ok(Self::RedemptionCancellation),
            3 => Ok(Self::InsuranceRecapitalizationContribution),
            other => Err(ProtocolError::InvalidDiscriminant(other)),
        }
    }

    pub const fn canonical_signed_action_len(self) -> usize {
        match self {
            Self::Subscription => 281,
            Self::RedemptionEnqueue => 377,
            Self::RedemptionCancellation => 297,
            Self::InsuranceRecapitalizationContribution => 249,
        }
    }
}

impl CanonicalEncode for BondInboxActionKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

/// Amount-free public marker admitted by the Elements node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxMarkerV2 {
    pub version: u8,
    pub kind: BondInboxActionKindV2,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub signer: XOnlyKey,
    /// Hash of the complete signed private action.  This is not a stable
    /// business identifier and exposes no amount by itself.
    pub action_id: Hash32,
    /// Randomly salted staging identifier for redemption enqueue only. Other
    /// kinds encode zero so their amount-bearing business ids remain private.
    pub staging_intent_id: Hash32,
    /// Public, amount-free staging projection. Only enqueue actions use a
    /// staging output; all other action kinds encode the canonical sentinels.
    pub staging_vout: u32,
    pub refund_script_sha256: Hash32,
    pub refund_not_before_parent_height: u64,
    /// Blinded commitment to the recovered fixed-width signed action bytes.
    pub payload_commitment: Hash32,
    pub availability_scheme_hash: Hash32,
    pub availability_custodian_registry_hash: Hash32,
    /// Root and exact serialized length of the encrypted availability bundle.
    pub availability_bundle_root: Hash32,
    pub availability_context: Hash32,
    pub availability_receipt_root: Hash32,
    pub availability_bundle_len: u32,
    /// Bitmap computed by the node after checking exact signed receipts. Bits
    /// zero through four identify the frozen custodians; all other bits are
    /// forbidden, so its population count proves distinctness.
    pub availability_receipt_bitmap: u8,
    /// Commits the holder input/preauthorization without putting it in this
    /// public marker.  The transaction id itself is committed by the entry,
    /// because a transaction cannot commit its own txid without a hash cycle.
    pub source_authorization_commitment: Hash32,
    /// Separate BIP340 wrapper signature over every field above.
    pub signature: Signature64,
}

impl BondInboxMarkerV2 {
    pub const VERSION: u8 = BOND_INBOX_MARKER_VERSION;

    fn signing_digest(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(BOND_INBOX_MARKER_LEN - 4 - 64);
        put_u8(&mut bytes, self.version);
        self.kind.encode_to(&mut bytes);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        self.signer.encode_to(&mut bytes);
        bytes.extend_from_slice(&self.action_id);
        bytes.extend_from_slice(&self.staging_intent_id);
        put_u32(&mut bytes, self.staging_vout);
        bytes.extend_from_slice(&self.refund_script_sha256);
        put_u64(&mut bytes, self.refund_not_before_parent_height);
        bytes.extend_from_slice(&self.payload_commitment);
        bytes.extend_from_slice(&self.availability_scheme_hash);
        bytes.extend_from_slice(&self.availability_custodian_registry_hash);
        bytes.extend_from_slice(&self.availability_bundle_root);
        bytes.extend_from_slice(&self.availability_context);
        bytes.extend_from_slice(&self.availability_receipt_root);
        put_u32(&mut bytes, self.availability_bundle_len);
        put_u8(&mut bytes, self.availability_receipt_bitmap);
        bytes.extend_from_slice(&self.source_authorization_commitment);
        tagged_hash("ECX/bond-inbox-marker-signature/v2", &bytes)
    }

    pub fn expected_availability_context(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity((32 * 7) + 12);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.action_id);
        bytes.extend_from_slice(&self.staging_intent_id);
        put_u32(&mut bytes, self.staging_vout);
        bytes.extend_from_slice(&self.refund_script_sha256);
        put_u64(&mut bytes, self.refund_not_before_parent_height);
        bytes.extend_from_slice(&self.payload_commitment);
        bytes.extend_from_slice(&self.source_authorization_commitment);
        tagged_hash("ECX/bond-inbox-availability-context/v2", &bytes)
    }

    pub fn sign(mut self, key: &SecretKey) -> Result<Self, ProtocolError> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, key);
        let (derived, _) = XOnlyPublicKey::from_keypair(&keypair);
        if derived.serialize() != self.signer.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&self.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        self.signature = Signature64(*secp.sign_schnorr_no_aux_rand(&message, &keypair).as_ref());
        Ok(self)
    }

    /// Checks the fixed-width marker representation only. It deliberately does
    /// not check the wrapper signature, action context, or custody receipts;
    /// those failures must remain consumable deterministic rejections.
    pub fn validate_syntax(&self, maximum_bundle_len: u32) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.action_id == [0; 32]
            || self.payload_commitment == [0; 32]
            || self.availability_scheme_hash == [0; 32]
            || self.availability_custodian_registry_hash == [0; 32]
            || self.availability_bundle_root == [0; 32]
            || self.availability_receipt_root == [0; 32]
            || self.source_authorization_commitment == [0; 32]
            || self.availability_bundle_len == 0
            || self.availability_bundle_len > maximum_bundle_len
            || self.availability_context != self.expected_availability_context()
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let has_enqueue_staging = self.staging_vout != u32::MAX
            && self.staging_intent_id != [0; 32]
            && self.refund_script_sha256 != [0; 32]
            && self.refund_not_before_parent_height != 0;
        let has_no_staging = self.staging_vout == u32::MAX
            && self.staging_intent_id == [0; 32]
            && self.refund_script_sha256 == [0; 32]
            && self.refund_not_before_parent_height == 0;
        if match self.kind {
            BondInboxActionKindV2::RedemptionEnqueue => !has_enqueue_staging,
            _ => !has_no_staging,
        } {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }

    /// Checks the compact node projection of exact source-witness validation.
    /// Consensus derives the bundle root/length/context and receipt root/bitmap
    /// from bytes committed by the source wtxid, verifies each signature
    /// against the frozen registry, and rejects duplicate custodian indices.
    pub fn verify_availability_claim(
        &self,
        availability: AvailabilityConfigV1,
        maximum_bundle_len: u32,
    ) -> Result<(), ProtocolError> {
        availability.validate()?;
        self.validate_syntax(maximum_bundle_len)?;
        let valid_bitmap_mask = (1u8 << availability.custodian_count) - 1;
        if self.availability_scheme_hash != availability.scheme_hash
            || self.availability_custodian_registry_hash != availability.custodian_registry_hash
            || self.availability_receipt_bitmap & !valid_bitmap_mask != 0
            || self.availability_receipt_bitmap.count_ones()
                < u32::from(availability.recovery_threshold)
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }

    pub fn verify_wrapper_signature(&self) -> Result<(), ProtocolError> {
        let key = XOnlyPublicKey::from_slice(&self.signer.0)
            .map_err(|_| ProtocolError::InvalidBondInbox)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidBondInbox)?;
        let message = Message::from_digest_slice(&self.signing_digest())
            .map_err(|_| ProtocolError::InvalidBondInbox)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidBondInbox)
    }

    pub fn payload_bytes(&self, maximum_bundle_len: u32) -> Result<Vec<u8>, ProtocolError> {
        self.validate_syntax(maximum_bundle_len)?;
        let mut out = Vec::with_capacity(BOND_INBOX_MARKER_LEN);
        out.extend_from_slice(&BOND_INBOX_MARKER_MAGIC);
        self.encode_to(&mut out);
        debug_assert_eq!(out.len(), BOND_INBOX_MARKER_LEN);
        Ok(out)
    }

    pub fn decode_payload(payload: &[u8], maximum_bundle_len: u32) -> Result<Self, ProtocolError> {
        if payload.len() != BOND_INBOX_MARKER_LEN {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let mut decoder = Decoder::new(payload);
        if decoder.take::<4>()? != BOND_INBOX_MARKER_MAGIC {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let marker = Self {
            version: decoder.u8()?,
            kind: BondInboxActionKindV2::decode(decoder.u8()?)?,
            chain_id: decoder.take()?,
            configuration_hash: decoder.take()?,
            signer: XOnlyKey(decoder.take()?),
            action_id: decoder.take()?,
            staging_intent_id: decoder.take()?,
            staging_vout: decoder.u32()?,
            refund_script_sha256: decoder.take()?,
            refund_not_before_parent_height: decoder.u64()?,
            payload_commitment: decoder.take()?,
            availability_scheme_hash: decoder.take()?,
            availability_custodian_registry_hash: decoder.take()?,
            availability_bundle_root: decoder.take()?,
            availability_context: decoder.take()?,
            availability_receipt_root: decoder.take()?,
            availability_bundle_len: decoder.u32()?,
            availability_receipt_bitmap: decoder.u8()?,
            source_authorization_commitment: decoder.take()?,
            signature: Signature64(decoder.take()?),
        };
        decoder.finish()?;
        marker.validate_syntax(maximum_bundle_len)?;
        Ok(marker)
    }
}

impl CanonicalEncode for BondInboxMarkerV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.kind.encode_to(out);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.signer.encode_to(out);
        out.extend_from_slice(&self.action_id);
        out.extend_from_slice(&self.staging_intent_id);
        put_u32(out, self.staging_vout);
        out.extend_from_slice(&self.refund_script_sha256);
        put_u64(out, self.refund_not_before_parent_height);
        out.extend_from_slice(&self.payload_commitment);
        out.extend_from_slice(&self.availability_scheme_hash);
        out.extend_from_slice(&self.availability_custodian_registry_hash);
        out.extend_from_slice(&self.availability_bundle_root);
        out.extend_from_slice(&self.availability_context);
        out.extend_from_slice(&self.availability_receipt_root);
        put_u32(out, self.availability_bundle_len);
        put_u8(out, self.availability_receipt_bitmap);
        out.extend_from_slice(&self.source_authorization_commitment);
        self.signature.encode_to(out);
    }
}

/// Marker plus its active-branch source locator, appended by the node adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxEntryV2 {
    pub version: u8,
    pub index: u64,
    pub previous_root: Hash32,
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub source_block_hash: Hash32,
    pub source_txid: Hash32,
    pub source_wtxid: Hash32,
    /// Exact full witness transaction serialization length. Proof/node code
    /// authenticates the bytes against txid/wtxid; core uses this projection
    /// to enforce the frozen aggregate prover-input bound.
    pub source_transaction_len: u32,
    pub source_witness_sha256: Hash32,
    pub source_witness_len: u32,
    pub source_tx_index: u32,
    pub marker_vout: u32,
    pub marker: BondInboxMarkerV2,
}

impl BondInboxEntryV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(
        &self,
        availability: AvailabilityConfigV1,
        maximum_bundle_len: u32,
        refund_minimum_parent_blocks: u32,
    ) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.previous_root == [0; 32]
            || self.observed_sidechain_height == 0
            || self.observed_parent_height == 0
            || self.source_block_hash == [0; 32]
            || self.source_txid == [0; 32]
            || self.source_wtxid == [0; 32]
            || self.source_transaction_len == 0
            || self.source_transaction_len > MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2
            || self.source_witness_sha256 == [0; 32]
            || self.source_witness_len == 0
            || self.source_witness_len > MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2
            || self.source_witness_len > self.source_transaction_len
            || self.marker_vout == u32::MAX
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        self.marker
            .verify_availability_claim(availability, maximum_bundle_len)?;
        if self.marker.kind == BondInboxActionKindV2::RedemptionEnqueue
            && (self.marker.staging_vout == self.marker_vout
                || self
                    .observed_parent_height
                    .checked_add(u64::from(refund_minimum_parent_blocks))
                    .map_or(true, |minimum_refund_height| {
                        self.marker.refund_not_before_parent_height < minimum_refund_height
                    }))
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        if self.marker.kind != BondInboxActionKindV2::RedemptionEnqueue
            && self.marker.source_authorization_commitment
                != bond_inbox_no_staging_source_authorization_commitment_v2(
                    self.marker.chain_id,
                    self.marker.configuration_hash,
                    self.marker.signer,
                    self.marker.action_id,
                    self.marker_vout,
                )?
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }

    pub fn entry_hash(&self) -> Hash32 {
        canonical_hash("ECX/bond-inbox-entry/v2", self)
    }

    pub fn next_root(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.previous_root);
        put_u64(&mut bytes, self.index);
        bytes.extend_from_slice(&self.entry_hash());
        tagged_hash("ECX/bond-inbox-step/v2", &bytes)
    }

    pub fn deadline(&self, inclusion_blocks: u32) -> Result<u64, ProtocolError> {
        if inclusion_blocks == 0 {
            return Err(ProtocolError::InvalidBondInbox);
        }
        self.observed_parent_height
            .checked_add(u64::from(inclusion_blocks))
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

/// Verifies the exact serialized witness projection committed by an entry.
/// Wtxid verification itself belongs to the Elements transaction parser; this
/// helper prevents proof/node implementations from hashing different bytes.
pub fn verify_bond_inbox_entry_source_witness_v2(
    entry: &BondInboxEntryV2,
    exact_source_witness: &[u8],
) -> Result<(), ProtocolError> {
    if entry.source_witness_len
        != u32::try_from(exact_source_witness.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
        || entry.source_witness_sha256 != bond_inbox_source_witness_sha256_v2(exact_source_witness)?
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

impl CanonicalEncode for BondInboxEntryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.index);
        out.extend_from_slice(&self.previous_root);
        put_u64(out, self.observed_sidechain_height);
        put_u64(out, self.observed_parent_height);
        out.extend_from_slice(&self.source_block_hash);
        out.extend_from_slice(&self.source_txid);
        out.extend_from_slice(&self.source_wtxid);
        put_u32(out, self.source_transaction_len);
        out.extend_from_slice(&self.source_witness_sha256);
        put_u32(out, self.source_witness_len);
        put_u32(out, self.source_tx_index);
        put_u32(out, self.marker_vout);
        self.marker.encode_to(out);
    }
}

/// Canonical extraction order for two entries observed in one sidechain
/// block. V2 admits exactly one marker per source transaction, so transaction
/// indices increase strictly. The full transition verifier additionally
/// rejects a repeated txid or wtxid at a different index.
pub fn validate_bond_inbox_source_order_v2(
    previous: &BondInboxEntryV2,
    current: &BondInboxEntryV2,
) -> Result<(), ProtocolError> {
    if current.observed_sidechain_height != previous.observed_sidechain_height {
        return Ok(());
    }
    if current.source_block_hash != previous.source_block_hash
        || current.observed_parent_height != previous.observed_parent_height
        || current.source_tx_index <= previous.source_tx_index
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxStateV2 {
    pub head_root: Hash32,
    pub entry_count: u64,
    pub processed_root: Hash32,
    pub cursor: u64,
}

impl BondInboxStateV2 {
    pub fn genesis(
        domain: Hash32,
        chain_id: Hash32,
        configuration_hash: Hash32,
    ) -> Result<Self, ProtocolError> {
        if domain == [0; 32] || chain_id == [0; 32] || configuration_hash == [0; 32] {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(&domain);
        bytes.extend_from_slice(&chain_id);
        bytes.extend_from_slice(&configuration_hash);
        let root = tagged_hash("ECX/bond-inbox-genesis/v2", &bytes);
        Ok(Self {
            head_root: root,
            entry_count: 0,
            processed_root: root,
            cursor: 0,
        })
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.head_root == [0; 32]
            || self.processed_root == [0; 32]
            || self.cursor > self.entry_count
            || (self.cursor == self.entry_count && self.processed_root != self.head_root)
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }
}

impl CanonicalEncode for BondInboxStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_root);
        put_u64(out, self.entry_count);
        out.extend_from_slice(&self.processed_root);
        put_u64(out, self.cursor);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BondInboxUserActionV2 {
    Subscription(SignedBondSubscriptionV2),
    InsuranceRecapitalizationContribution(SignedInsuranceRecapitalizationContributionV2),
    RedemptionEnqueue(SignedRedemptionEnqueueV2),
    RedemptionCancellation(SignedRedemptionCancellationV2),
}

impl BondInboxUserActionV2 {
    pub fn kind(&self) -> BondInboxActionKindV2 {
        match self {
            Self::Subscription(_) => BondInboxActionKindV2::Subscription,
            Self::InsuranceRecapitalizationContribution(_) => {
                BondInboxActionKindV2::InsuranceRecapitalizationContribution
            }
            Self::RedemptionEnqueue(_) => BondInboxActionKindV2::RedemptionEnqueue,
            Self::RedemptionCancellation(_) => BondInboxActionKindV2::RedemptionCancellation,
        }
    }

    pub fn signer(&self) -> XOnlyKey {
        match self {
            Self::Subscription(value) => value.action.trader,
            Self::InsuranceRecapitalizationContribution(value) => value.action.contributor,
            Self::RedemptionEnqueue(value) => value.action.claimant,
            Self::RedemptionCancellation(value) => value.action.claimant,
        }
    }

    pub fn action_id(&self) -> Hash32 {
        match self {
            Self::Subscription(value) => value.action.action_id(),
            Self::InsuranceRecapitalizationContribution(value) => value.action.action_id(),
            Self::RedemptionEnqueue(value) => value.action.action_id(),
            Self::RedemptionCancellation(value) => value.action.action_id(),
        }
    }

    /// Public staging identifier. Only enqueue has a staging output. Other
    /// business identifiers remain private because small amounts could make
    /// an unsalted public hash dictionary-testable.
    pub fn staging_intent_id(&self) -> Hash32 {
        match self {
            Self::RedemptionEnqueue(value) => value.action.stable_intent_id(),
            Self::Subscription(_)
            | Self::InsuranceRecapitalizationContribution(_)
            | Self::RedemptionCancellation(_) => [0; 32],
        }
    }

    pub fn canonical_signed_bytes(&self) -> Vec<u8> {
        match self {
            Self::Subscription(value) => value.canonical_bytes(),
            Self::InsuranceRecapitalizationContribution(value) => value.canonical_bytes(),
            Self::RedemptionEnqueue(value) => value.canonical_bytes(),
            Self::RedemptionCancellation(value) => value.canonical_bytes(),
        }
    }

    pub fn settlement_witness_commitment(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(&self.action_id());
        match self {
            Self::Subscription(value) => {
                bytes.extend_from_slice(&value.action.usdd_output_opening_commitment);
                bytes.extend_from_slice(&value.action.bond_output_opening_commitment);
            }
            Self::InsuranceRecapitalizationContribution(value) => {
                bytes.extend_from_slice(&value.action.insurance_output_opening_commitment);
                bytes.extend_from_slice(&value.action.bond_output_opening_commitment);
            }
            Self::RedemptionEnqueue(value) => {
                bytes.extend_from_slice(&value.action.bond_input_opening_commitment);
                bytes.extend_from_slice(&value.action.queue_output_opening_commitment);
            }
            Self::RedemptionCancellation(value) => {
                bytes.extend_from_slice(&value.action.queue_input_opening_commitment);
                bytes.extend_from_slice(&value.action.bond_return_output_opening_commitment);
            }
        }
        tagged_hash("ECX/bond-inbox-settlement-witness/v2", &bytes)
    }

    fn verify(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Subscription(value) => value.verify(),
            Self::InsuranceRecapitalizationContribution(value) => value.verify(),
            Self::RedemptionEnqueue(value) => value.verify(),
            Self::RedemptionCancellation(value) => value.verify(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BondInboxRejectionV2 {
    MalformedOrInvalidAction,
    DuplicateOrReplayedAction,
    InvalidContext,
    InvalidNonce,
    InsufficientCollateral,
    InvalidSubscriptionQuote,
    CapitalModeRestriction,
    InvalidQueueRequest,
    InvalidRecapitalizationContribution,
}

/// Exact public disposition committed for every consumed inbox entry. Once an
/// entry reaches its frozen inclusion deadline, `ExpiredUnavailable` advances
/// the lane without private custodian shares. It is neither an accepted action
/// nor a malformed rejection and therefore consumes no account nonce and
/// creates no queue/reserve/supply mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BondInboxProcessedDispositionV2 {
    Accepted,
    Rejected(BondInboxRejectionV2),
    ExpiredUnavailable,
}

impl CanonicalEncode for BondInboxProcessedDispositionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Accepted => put_u8(out, 0),
            Self::Rejected(reason) => {
                put_u8(out, 1);
                reason.encode_to(out);
            }
            Self::ExpiredUnavailable => put_u8(out, 2),
        }
    }
}

impl CanonicalEncode for BondInboxRejectionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(
            out,
            match self {
                Self::MalformedOrInvalidAction => 0,
                Self::DuplicateOrReplayedAction => 1,
                Self::InvalidContext => 2,
                Self::InvalidNonce => 3,
                Self::InsufficientCollateral => 4,
                Self::InvalidSubscriptionQuote => 5,
                Self::CapitalModeRestriction => 6,
                Self::InvalidQueueRequest => 7,
                Self::InvalidRecapitalizationContribution => 8,
            },
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxProcessedOutcomeV2 {
    pub version: u8,
    pub entry_index: u64,
    pub entry_hash: Hash32,
    pub marker_kind: BondInboxActionKindV2,
    pub marker_action_id: Hash32,
    pub disposition: BondInboxProcessedDispositionV2,
}

impl BondInboxProcessedOutcomeV2 {
    pub const VERSION: u8 = 3;

    pub fn accepted(consumed: &BondInboxConsumedOutcomeV2) -> Self {
        Self {
            version: Self::VERSION,
            entry_index: consumed.entry_index,
            entry_hash: consumed.entry_hash,
            marker_kind: consumed.marker_kind,
            marker_action_id: consumed.marker_action_id,
            disposition: BondInboxProcessedDispositionV2::Accepted,
        }
    }

    pub fn rejected(
        consumed: &BondInboxConsumedOutcomeV2,
        rejection: BondInboxRejectionV2,
    ) -> Self {
        Self {
            version: Self::VERSION,
            entry_index: consumed.entry_index,
            entry_hash: consumed.entry_hash,
            marker_kind: consumed.marker_kind,
            marker_action_id: consumed.marker_action_id,
            disposition: BondInboxProcessedDispositionV2::Rejected(rejection),
        }
    }

    pub fn expired_unavailable(consumed: &BondInboxConsumedOutcomeV2) -> Self {
        Self {
            version: Self::VERSION,
            entry_index: consumed.entry_index,
            entry_hash: consumed.entry_hash,
            marker_kind: consumed.marker_kind,
            marker_action_id: consumed.marker_action_id,
            disposition: BondInboxProcessedDispositionV2::ExpiredUnavailable,
        }
    }

    pub fn outcome_hash(&self) -> Hash32 {
        canonical_hash(
            "ECX/bond-inbox-processed-outcome/v4-expired-unavailable-v2",
            self,
        )
    }
}

impl CanonicalEncode for BondInboxProcessedOutcomeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.entry_index);
        out.extend_from_slice(&self.entry_hash);
        self.marker_kind.encode_to(out);
        out.extend_from_slice(&self.marker_action_id);
        self.disposition.encode_to(out);
    }
}

pub fn bond_inbox_outcome_genesis_root_v2(
    domain: Hash32,
    chain_id: Hash32,
    configuration_hash: Hash32,
) -> Result<Hash32, ProtocolError> {
    if domain == [0; 32] || chain_id == [0; 32] || configuration_hash == [0; 32] {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&configuration_hash);
    Ok(tagged_hash(
        "ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2",
        &bytes,
    ))
}

pub fn bond_inbox_outcome_next_root_v2(
    previous_root: Hash32,
    outcome: &BondInboxProcessedOutcomeV2,
) -> Result<Hash32, ProtocolError> {
    if previous_root == [0; 32] || outcome.version != BondInboxProcessedOutcomeV2::VERSION {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&previous_root);
    put_u64(&mut bytes, outcome.entry_index);
    bytes.extend_from_slice(&outcome.outcome_hash());
    Ok(tagged_hash(
        "ECX/bond-inbox-outcomes-step/v4-expired-unavailable-v2",
        &bytes,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// This is a transient verification result, not persisted state. Keeping the
// authenticated action inline avoids heap-dependent control flow in the SP1
// guest and does not affect any public or canonical encoding.
#[allow(clippy::large_enum_variant)]
pub enum BondInboxConsumedDispositionV2 {
    Action(Result<BondInboxUserActionV2, BondInboxRejectionV2>),
    ExpiredUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxConsumedOutcomeV2 {
    pub entry_index: u64,
    pub entry_hash: Hash32,
    pub marker_kind: BondInboxActionKindV2,
    pub marker_action_id: Hash32,
    pub source_parent_height: u64,
    pub disposition: BondInboxConsumedDispositionV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxAvailablePayloadV2 {
    /// Prevents low-entropy confidential values from being brute-forced from
    /// the public commitment. Zero is a deterministic action rejection.
    pub commitment_blinding: Hash32,
    pub canonical_signed_action: Vec<u8>,
    /// Commitments derived by proof-core from the decrypted canonical bundle.
    /// The full private bytes remain outside protocol-core; the encryption
    /// verifier must prove that the exact admitted bundle decrypts to these
    /// values before calling the transition verifier.
    pub settlement_witness_commitment: Hash32,
    pub source_authorization_commitment: Hash32,
}

impl BondInboxAvailablePayloadV2 {
    pub fn commitment(
        kind: BondInboxActionKindV2,
        commitment_blinding: Hash32,
        canonical_signed_action: &[u8],
        settlement_witness_commitment: Hash32,
        source_authorization_commitment: Hash32,
    ) -> Hash32 {
        let mut bytes = Vec::with_capacity(97 + canonical_signed_action.len());
        bytes.extend_from_slice(&commitment_blinding);
        put_u8(&mut bytes, kind as u8);
        bytes.extend_from_slice(canonical_signed_action);
        bytes.extend_from_slice(&settlement_witness_commitment);
        bytes.extend_from_slice(&source_authorization_commitment);
        tagged_hash("ECX/bond-inbox-payload-commitment/v2", &bytes)
    }

    /// Decode the entire exact recovered payload envelope. `kind` comes from
    /// the authenticated public marker and fixes the only variable-width
    /// member. Short, long, and trailing encodings are all rejected.
    pub fn decode_canonical(
        kind: BondInboxActionKindV2,
        canonical_payload: &[u8],
    ) -> Result<Self, ProtocolError> {
        let signed_len = kind.canonical_signed_action_len();
        let expected_len = 32usize
            .checked_add(4)
            .and_then(|value| value.checked_add(signed_len))
            .and_then(|value| value.checked_add(64))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if canonical_payload.len() != expected_len {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let mut decoder = Decoder::new(canonical_payload);
        let commitment_blinding = decoder.take()?;
        if decoder.u32()? as usize != signed_len {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let canonical_signed_action = match kind {
            BondInboxActionKindV2::Subscription => decoder.take::<281>()?.to_vec(),
            BondInboxActionKindV2::RedemptionEnqueue => decoder.take::<377>()?.to_vec(),
            BondInboxActionKindV2::RedemptionCancellation => decoder.take::<297>()?.to_vec(),
            BondInboxActionKindV2::InsuranceRecapitalizationContribution => {
                decoder.take::<249>()?.to_vec()
            }
        };
        let settlement_witness_commitment = decoder.take()?;
        let source_authorization_commitment = decoder.take()?;
        decoder.finish()?;
        Ok(Self {
            commitment_blinding,
            canonical_signed_action,
            settlement_witness_commitment,
            source_authorization_commitment,
        })
    }

    /// Decode the exact fixed-width inner signed action selected by `kind`.
    /// This deliberately rejects short, long, and trailing encodings so
    /// proof-core can classify successful-AEAD but malformed plaintext without
    /// reimplementing the private action codec.
    pub fn decode_canonical_signed_action(
        kind: BondInboxActionKindV2,
        canonical_signed_action: &[u8],
    ) -> Result<BondInboxUserActionV2, ProtocolError> {
        if canonical_signed_action.len() != kind.canonical_signed_action_len() {
            return Err(ProtocolError::InvalidBondInbox);
        }
        decode_signed_action(kind, canonical_signed_action)
    }

    fn classify(
        &self,
        entry: &BondInboxEntryV2,
    ) -> Result<BondInboxConsumedOutcomeV2, ProtocolError> {
        if self.canonical_signed_action.len() > entry.marker.availability_bundle_len as usize
            || self.settlement_witness_commitment == [0; 32]
            || self.source_authorization_commitment != entry.marker.source_authorization_commitment
            || Self::commitment(
                entry.marker.kind,
                self.commitment_blinding,
                &self.canonical_signed_action,
                self.settlement_witness_commitment,
                self.source_authorization_commitment,
            ) != entry.marker.payload_commitment
        {
            // Proof-core must already have authenticated these as the exact
            // bytes recovered from the admitted encrypted bundle. A malicious
            // producer can encrypt a payload that does not match its marker;
            // that is a deterministic rejection, not a lane-wide halt.
            return Ok(malformed_consumed_outcome(entry));
        }

        let decoded = if self.commitment_blinding == [0; 32]
            || self.canonical_signed_action.len() != entry.marker.kind.canonical_signed_action_len()
        {
            Err(ProtocolError::InvalidBondInbox)
        } else {
            Self::decode_canonical_signed_action(entry.marker.kind, &self.canonical_signed_action)
        };
        let action = match decoded {
            Ok(action)
                if action.kind() == entry.marker.kind
                    && action.signer() == entry.marker.signer
                    && action.action_id() == entry.marker.action_id
                    && action.staging_intent_id() == entry.marker.staging_intent_id
                    && match &action {
                        BondInboxUserActionV2::RedemptionEnqueue(value) => {
                            value.action.refund_script_sha256 == entry.marker.refund_script_sha256
                                && value.action.refund_not_before_parent_height
                                    == entry.marker.refund_not_before_parent_height
                        }
                        _ => true,
                    }
                    && action.settlement_witness_commitment()
                        == self.settlement_witness_commitment
                    && entry.marker.verify_wrapper_signature().is_ok()
                    && action.verify().is_ok() =>
            {
                Ok(action)
            }
            _ => Err(BondInboxRejectionV2::MalformedOrInvalidAction),
        };
        Ok(BondInboxConsumedOutcomeV2 {
            entry_index: entry.index,
            entry_hash: entry.entry_hash(),
            marker_kind: entry.marker.kind,
            marker_action_id: entry.marker.action_id,
            source_parent_height: entry.observed_parent_height,
            disposition: BondInboxConsumedDispositionV2::Action(action),
        })
    }
}

impl CanonicalEncode for BondInboxAvailablePayloadV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.commitment_blinding);
        put_u32(
            out,
            u32::try_from(self.canonical_signed_action.len()).unwrap_or(u32::MAX),
        );
        out.extend_from_slice(&self.canonical_signed_action);
        out.extend_from_slice(&self.settlement_witness_commitment);
        out.extend_from_slice(&self.source_authorization_commitment);
    }
}

/// The reason exact threshold recovery could not yield a canonical plaintext
/// payload. Proof-core, not protocol-core, verifies the availability bundle,
/// custody receipts, threshold recovery contributions/certificate, and the
/// claimed failure before this value reaches [`BondInboxTransitionV2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BondInboxRecoveryFailureV2 {
    PayloadAead = 0,
    PlaintextLength = 1,
    PlaintextDecode = 2,
}

impl CanonicalEncode for BondInboxRecoveryFailureV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

/// Fixed digest used when AEAD authentication fails and therefore no
/// plaintext bytes exist to hash. It cannot be confused with a caller-chosen
/// zero or an omitted recovery transcript.
pub fn bond_inbox_aead_failure_plaintext_sentinel_v2() -> Hash32 {
    tagged_hash("ECX/bond-inbox-aead-failure-plaintext-sentinel/v2", &[])
}

/// Raw SHA-256 of exact recovered plaintext bytes. Successful AEAD recovery
/// can yield malformed or even empty plaintext, so empty input is permitted;
/// the surrounding failure kind distinguishes it from the AEAD sentinel.
pub fn bond_inbox_recovered_plaintext_sha256_v2(
    exact_recovered_plaintext: &[u8],
) -> Result<Hash32, ProtocolError> {
    if exact_recovered_plaintext.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(Sha256::digest(exact_recovered_plaintext).into())
}

/// Canonical binding for a proof-authenticated recovery or payload failure.
/// `entry_hash` commits the exact public source projection and outer encrypted
/// bundle commitment; `witness_bundle_root` is the root decoded from that
/// exact V1 bundle. Proof-core must independently verify the certificate and
/// failure before presenting this commitment to protocol-core.
pub fn bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2(
    entry_hash: Hash32,
    witness_bundle_root: Hash32,
    failure: BondInboxRecoveryFailureV2,
    recovered_plaintext_sha256: Hash32,
    recovery_certificate_root: Hash32,
) -> Result<Hash32, ProtocolError> {
    if entry_hash == [0; 32]
        || witness_bundle_root == [0; 32]
        || recovered_plaintext_sha256 == [0; 32]
        || recovery_certificate_root == [0; 32]
        || (failure == BondInboxRecoveryFailureV2::PayloadAead
            && recovered_plaintext_sha256 != bond_inbox_aead_failure_plaintext_sentinel_v2())
        || (failure != BondInboxRecoveryFailureV2::PayloadAead
            && recovered_plaintext_sha256 == bond_inbox_aead_failure_plaintext_sentinel_v2())
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(129);
    bytes.extend_from_slice(&entry_hash);
    bytes.extend_from_slice(&witness_bundle_root);
    failure.encode_to(&mut bytes);
    bytes.extend_from_slice(&recovered_plaintext_sha256);
    bytes.extend_from_slice(&recovery_certificate_root);
    Ok(tagged_hash(
        "ECX/bond-inbox-authenticated-recovery-or-payload-failure/v2",
        &bytes,
    ))
}

/// Proof-authenticated evidence that the exact admitted bundle was recovered
/// with a threshold certificate but did not produce a canonical payload.
///
/// The commitment is to the exact recovery certificate/contributions used by
/// proof-core. It is not itself a certificate, and callers must never accept
/// this variant without verifying recovery against the entry's exact bundle,
/// context, length, receipt set, and frozen availability registry. Once that
/// verification succeeds, failure is attributable to the admitted producer
/// and is consumed as a deterministic malformed-action rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxAuthenticatedRecoveryOrPayloadFailureV2 {
    pub failure: BondInboxRecoveryFailureV2,
    pub witness_bundle_root: Hash32,
    pub recovered_plaintext_sha256: Hash32,
    /// Commitment/root of exactly three private, strictly index-ordered,
    /// proof-verified V1 recovery contributions. The shares themselves never
    /// appear in the source transaction, marker, public values, or journal.
    pub recovery_certificate_root: Hash32,
    pub failure_commitment: Hash32,
}

impl CanonicalEncode for BondInboxAuthenticatedRecoveryOrPayloadFailureV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.failure.encode_to(out);
        out.extend_from_slice(&self.witness_bundle_root);
        out.extend_from_slice(&self.recovered_plaintext_sha256);
        out.extend_from_slice(&self.recovery_certificate_root);
        out.extend_from_slice(&self.failure_commitment);
    }
}

/// Exactly one proof-authenticated recovery result for each consumed prefix
/// entry. Source transaction, witness, encrypted bundle, receipt, or recovery
/// certificate substitution is a proof error. Producer-authored plaintext
/// failure or commitment mismatch is a deterministic rejection so it cannot
/// permanently halt the lane at the inclusion deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BondInboxConsumedEvidenceV2 {
    /// `source_entry_hash` is assigned by the proof after active-chain
    /// inclusion. It is not part of the producer-encrypted payload and may
    /// therefore safely bind a raced/reorged node-assigned entry index.
    Recovered {
        source_entry_hash: Hash32,
        payload: BondInboxAvailablePayloadV2,
    },
    AuthenticatedRecoveryOrPayloadFailure(BondInboxAuthenticatedRecoveryOrPayloadFailureV2),
    /// No private recovery material is required once the exact public entry
    /// reaches the frozen inclusion deadline. This closes exchange-side
    /// processing without claiming an enqueue refund occurred; its staging
    /// output remains independently locked until the later signed refund
    /// boundary.
    ExpiredUnavailable {
        source_entry_hash: Hash32,
    },
}

impl BondInboxConsumedEvidenceV2 {
    fn classify(
        &self,
        entry: &BondInboxEntryV2,
        parent_height: u64,
        inclusion_blocks: u32,
    ) -> Result<BondInboxConsumedOutcomeV2, ProtocolError> {
        let deadline_reached = parent_height >= entry.deadline(inclusion_blocks)?;
        match self {
            Self::Recovered {
                source_entry_hash,
                payload,
            } => {
                if *source_entry_hash != entry.entry_hash() || deadline_reached {
                    return Err(ProtocolError::InvalidBondInbox);
                }
                payload.classify(entry)
            }
            Self::AuthenticatedRecoveryOrPayloadFailure(failure) => {
                if deadline_reached
                    || failure.failure_commitment
                        != bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2(
                            entry.entry_hash(),
                            failure.witness_bundle_root,
                            failure.failure,
                            failure.recovered_plaintext_sha256,
                            failure.recovery_certificate_root,
                        )?
                {
                    return Err(ProtocolError::InvalidBondInbox);
                }
                Ok(malformed_consumed_outcome(entry))
            }
            Self::ExpiredUnavailable { source_entry_hash } => {
                if *source_entry_hash != entry.entry_hash() || !deadline_reached {
                    return Err(ProtocolError::InvalidBondInbox);
                }
                Ok(BondInboxConsumedOutcomeV2 {
                    entry_index: entry.index,
                    entry_hash: entry.entry_hash(),
                    marker_kind: entry.marker.kind,
                    marker_action_id: entry.marker.action_id,
                    source_parent_height: entry.observed_parent_height,
                    disposition: BondInboxConsumedDispositionV2::ExpiredUnavailable,
                })
            }
        }
    }
}

impl CanonicalEncode for BondInboxConsumedEvidenceV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Recovered {
                source_entry_hash,
                payload,
            } => {
                put_u8(out, 0);
                out.extend_from_slice(source_entry_hash);
                payload.encode_to(out);
            }
            Self::AuthenticatedRecoveryOrPayloadFailure(failure) => {
                put_u8(out, 1);
                failure.encode_to(out);
            }
            Self::ExpiredUnavailable { source_entry_hash } => {
                put_u8(out, 2);
                out.extend_from_slice(source_entry_hash);
            }
        }
    }
}

fn malformed_consumed_outcome(entry: &BondInboxEntryV2) -> BondInboxConsumedOutcomeV2 {
    BondInboxConsumedOutcomeV2 {
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        source_parent_height: entry.observed_parent_height,
        disposition: BondInboxConsumedDispositionV2::Action(Err(
            BondInboxRejectionV2::MalformedOrInvalidAction,
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxTransitionV2 {
    /// Complete suffix from the previous cursor through the new source head.
    pub pending_entries: Vec<BondInboxEntryV2>,
    /// Exactly one proof-authenticated recovery result for each consumed
    /// prefix entry. The outer proof must verify the crypto contract described
    /// on [`BondInboxConsumedEvidenceV2`] before invoking this state verifier.
    pub consumed_evidence: Vec<BondInboxConsumedEvidenceV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondInboxLimitsV2 {
    pub inbox_domain: Hash32,
    pub inclusion_blocks: u32,
    pub refund_minimum_parent_blocks: u32,
    pub maximum_bundle_bytes: u32,
    pub maximum_entries_per_sidechain_block: u32,
    pub maximum_unique_source_witness_bytes_per_sidechain_block: u32,
    pub maximum_unique_source_transaction_bytes_per_sidechain_block: u32,
    pub maximum_pending_entries_per_transition: u32,
    pub maximum_consumed_entries_per_transition: u32,
}

impl BondInboxLimitsV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.inbox_domain == [0; 32]
            || self.inclusion_blocks == 0
            || self.refund_minimum_parent_blocks < self.inclusion_blocks
            || self.maximum_bundle_bytes == 0
            || self.maximum_bundle_bytes > MAX_BOND_INBOX_BUNDLE_BYTES_V2
            || self.maximum_entries_per_sidechain_block == 0
            || self.maximum_unique_source_witness_bytes_per_sidechain_block == 0
            || self.maximum_unique_source_witness_bytes_per_sidechain_block
                > MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2
            || self.maximum_unique_source_transaction_bytes_per_sidechain_block == 0
            || self.maximum_unique_source_transaction_bytes_per_sidechain_block
                > MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2
            || self.maximum_pending_entries_per_transition == 0
            || self.maximum_consumed_entries_per_transition == 0
            || self.maximum_consumed_entries_per_transition
                < self.maximum_pending_entries_per_transition
            || self
                .maximum_entries_per_sidechain_block
                .checked_mul(self.inclusion_blocks)
                .map_or(true, |bound| {
                    bound > self.maximum_pending_entries_per_transition
                })
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }
}

impl BondInboxTransitionV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        chain_id: Hash32,
        configuration_hash: Hash32,
        previous: BondInboxStateV2,
        next: BondInboxStateV2,
        parent_height: u64,
        transition_sidechain_height: u64,
        availability: AvailabilityConfigV1,
        limits: BondInboxLimitsV2,
    ) -> Result<Vec<BondInboxConsumedOutcomeV2>, ProtocolError> {
        previous.validate()?;
        next.validate()?;
        availability.validate()?;
        limits.validate()?;
        if chain_id == [0; 32]
            || configuration_hash == [0; 32]
            || transition_sidechain_height == 0
            || next.entry_count < previous.entry_count
            || next.cursor < previous.cursor
            || self.consumed_evidence.len() > self.pending_entries.len()
            || self.pending_entries.len() > limits.maximum_pending_entries_per_transition as usize
            || self.consumed_evidence.len()
                > limits.maximum_consumed_entries_per_transition as usize
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        if previous.entry_count == 0
            && previous
                != BondInboxStateV2::genesis(limits.inbox_domain, chain_id, configuration_hash)?
        {
            return Err(ProtocolError::InvalidBondInbox);
        }

        let consumed_count = u64::try_from(self.consumed_evidence.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let consumed_end = previous
            .cursor
            .checked_add(consumed_count)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let mut root = previous.processed_root;
        let mut root_after_consumed = root;
        let mut index = previous.cursor;
        let mut observed_previous_head = previous.cursor == previous.entry_count;
        let mut last_sidechain_height = 0u64;
        let mut last_parent_height = 0u64;
        let mut entries_at_height = 0u32;
        let mut unique_source_witness_bytes_at_height = 0u32;
        let mut unique_source_transaction_bytes_at_height = 0u32;
        let mut source_txids_at_height = BTreeSet::new();
        let mut source_wtxids_at_height = BTreeSet::new();
        let mut previous_entry = None;
        let mut outcomes = Vec::with_capacity(self.consumed_evidence.len());

        for (offset, entry) in self.pending_entries.iter().enumerate() {
            entry.validate(
                availability,
                limits.maximum_bundle_bytes,
                limits.refund_minimum_parent_blocks,
            )?;
            if let Some(prior) = previous_entry {
                validate_bond_inbox_source_order_v2(prior, entry)?;
            }
            if entry.observed_sidechain_height != last_sidechain_height {
                entries_at_height = 0;
                unique_source_witness_bytes_at_height = 0;
                unique_source_transaction_bytes_at_height = 0;
                source_txids_at_height.clear();
                source_wtxids_at_height.clear();
            }
            entries_at_height = entries_at_height
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if !source_txids_at_height.insert(entry.source_txid)
                || !source_wtxids_at_height.insert(entry.source_wtxid)
            {
                return Err(ProtocolError::InvalidBondInbox);
            }
            unique_source_witness_bytes_at_height = unique_source_witness_bytes_at_height
                .checked_add(entry.source_witness_len)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            unique_source_transaction_bytes_at_height = unique_source_transaction_bytes_at_height
                .checked_add(entry.source_transaction_len)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if entry.marker.chain_id != chain_id
                || entry.marker.configuration_hash != configuration_hash
                // The proof-bearing singleton transaction cannot commit an
                // inbox source from its own block without a block/state hash
                // cycle. Only active-branch predecessor blocks are eligible.
                || entry.observed_sidechain_height >= transition_sidechain_height
                || entry.index != index
                || entry.previous_root != root
                || entries_at_height > limits.maximum_entries_per_sidechain_block
                || unique_source_witness_bytes_at_height
                    > limits.maximum_unique_source_witness_bytes_per_sidechain_block
                || unique_source_transaction_bytes_at_height
                    > limits.maximum_unique_source_transaction_bytes_per_sidechain_block
                || (last_sidechain_height != 0
                    && entry.observed_sidechain_height < last_sidechain_height)
                || (last_parent_height != 0
                    && entry.observed_parent_height < last_parent_height)
            {
                return Err(ProtocolError::InvalidBondInbox);
            }
            if let Some(evidence) = self.consumed_evidence.get(offset) {
                outcomes.push(evidence.classify(entry, parent_height, limits.inclusion_blocks)?);
            }
            root = entry.next_root();
            index = index
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            last_sidechain_height = entry.observed_sidechain_height;
            last_parent_height = entry.observed_parent_height;
            previous_entry = Some(entry);
            if index == consumed_end {
                root_after_consumed = root;
            }
            if index == previous.entry_count {
                if root != previous.head_root {
                    return Err(ProtocolError::InvalidBondInbox);
                }
                observed_previous_head = true;
            }
        }

        if !observed_previous_head
            || index != next.entry_count
            || root != next.head_root
            || next.cursor != consumed_end
            || next.processed_root != root_after_consumed
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        if self
            .pending_entries
            .get(self.consumed_evidence.len())
            .is_some_and(|entry| {
                entry
                    .deadline(limits.inclusion_blocks)
                    .map(|deadline| parent_height >= deadline)
                    .unwrap_or(true)
            })
        {
            return Err(ProtocolError::BondInboxDeadline);
        }
        Ok(outcomes)
    }
}

fn decode_signed_action(
    kind: BondInboxActionKindV2,
    bytes: &[u8],
) -> Result<BondInboxUserActionV2, ProtocolError> {
    match kind {
        BondInboxActionKindV2::Subscription => {
            let mut decoder = Decoder::new(bytes);
            let action = BondSubscriptionV2 {
                version: decoder.u8()?,
                chain_id: decoder.take()?,
                configuration_hash: decoder.take()?,
                trader: XOnlyKey(decoder.take()?),
                account_nonce: decoder.u64()?,
                contribution_usdd_atoms: decoder.u64()?,
                issued_share_atoms: decoder.u64()?,
                bond_recipient_script_sha256: decoder.take()?,
                usdd_output_opening_commitment: decoder.take()?,
                bond_output_opening_commitment: decoder.take()?,
            };
            let signature = Signature64(decoder.take()?);
            decoder.finish()?;
            Ok(BondInboxUserActionV2::Subscription(
                SignedBondSubscriptionV2 { action, signature },
            ))
        }
        BondInboxActionKindV2::RedemptionEnqueue => {
            let mut decoder = Decoder::new(bytes);
            let action = RedemptionEnqueueV2 {
                version: decoder.u8()?,
                chain_id: decoder.take()?,
                configuration_hash: decoder.take()?,
                claimant: XOnlyKey(decoder.take()?),
                account_nonce: decoder.u64()?,
                requested_share_atoms: decoder.u64()?,
                destination_script_hash: decoder.take()?,
                holder_script_sha256: decoder.take()?,
                intent_salt: decoder.take()?,
                refund_script_sha256: decoder.take()?,
                refund_not_before_parent_height: decoder.u64()?,
                bond_input_opening_commitment: decoder.take()?,
                queue_output_opening_commitment: decoder.take()?,
            };
            let signature = Signature64(decoder.take()?);
            decoder.finish()?;
            Ok(BondInboxUserActionV2::RedemptionEnqueue(
                SignedRedemptionEnqueueV2 { action, signature },
            ))
        }
        BondInboxActionKindV2::RedemptionCancellation => {
            let mut decoder = Decoder::new(bytes);
            let action = RedemptionCancellationV2Action {
                version: decoder.u8()?,
                chain_id: decoder.take()?,
                configuration_hash: decoder.take()?,
                claimant: XOnlyKey(decoder.take()?),
                sequence: decoder.u64()?,
                request_id: decoder.take()?,
                bond_recipient_script_sha256: decoder.take()?,
                queue_input_opening_commitment: decoder.take()?,
                bond_return_output_opening_commitment: decoder.take()?,
            };
            let signature = Signature64(decoder.take()?);
            decoder.finish()?;
            Ok(BondInboxUserActionV2::RedemptionCancellation(
                SignedRedemptionCancellationV2 { action, signature },
            ))
        }
        BondInboxActionKindV2::InsuranceRecapitalizationContribution => {
            let mut decoder = Decoder::new(bytes);
            let action = InsuranceRecapitalizationContributionV2 {
                version: decoder.u8()?,
                chain_id: decoder.take()?,
                configuration_hash: decoder.take()?,
                contributor: XOnlyKey(decoder.take()?),
                account_nonce: decoder.u64()?,
                contribution_usdd_atoms: decoder.u64()?,
                insurance_output_opening_commitment: decoder.take()?,
                issued_share_atoms: decoder.u64()?,
                bond_output_opening_commitment: decoder.take()?,
            };
            let signature = Signature64(decoder.take()?);
            decoder.finish()?;
            Ok(
                BondInboxUserActionV2::InsuranceRecapitalizationContribution(
                    SignedInsuranceRecapitalizationContributionV2 { action, signature },
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretKey {
        SecretKey::from_slice(&[7; 32]).unwrap()
    }

    fn signer() -> XOnlyKey {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret());
        XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
    }

    fn subscription() -> SignedBondSubscriptionV2 {
        SignedBondSubscriptionV2::sign(
            BondSubscriptionV2 {
                version: BondSubscriptionV2::VERSION,
                chain_id: [1; 32],
                configuration_hash: [2; 32],
                trader: signer(),
                account_nonce: 3,
                contribution_usdd_atoms: 4,
                issued_share_atoms: 4,
                bond_recipient_script_sha256: [5; 32],
                usdd_output_opening_commitment: [6; 32],
                bond_output_opening_commitment: [7; 32],
            },
            &secret(),
        )
        .unwrap()
    }

    fn enqueue() -> SignedRedemptionEnqueueV2 {
        SignedRedemptionEnqueueV2::sign(
            RedemptionEnqueueV2 {
                version: RedemptionEnqueueV2::VERSION,
                chain_id: [1; 32],
                configuration_hash: [2; 32],
                claimant: signer(),
                account_nonce: 3,
                requested_share_atoms: 4,
                destination_script_hash: [5; 32],
                holder_script_sha256: [6; 32],
                intent_salt: [7; 32],
                refund_script_sha256: [8; 32],
                refund_not_before_parent_height: 112,
                bond_input_opening_commitment: [9; 32],
                queue_output_opening_commitment: [10; 32],
            },
            &secret(),
        )
        .unwrap()
    }

    fn cancellation() -> SignedRedemptionCancellationV2 {
        SignedRedemptionCancellationV2::sign(
            RedemptionCancellationV2Action {
                version: RedemptionCancellationV2Action::VERSION,
                chain_id: [1; 32],
                configuration_hash: [2; 32],
                claimant: signer(),
                sequence: 3,
                request_id: [4; 32],
                bond_recipient_script_sha256: [5; 32],
                queue_input_opening_commitment: [6; 32],
                bond_return_output_opening_commitment: [7; 32],
            },
            &secret(),
        )
        .unwrap()
    }

    fn recapitalization() -> SignedInsuranceRecapitalizationContributionV2 {
        SignedInsuranceRecapitalizationContributionV2::sign(
            InsuranceRecapitalizationContributionV2 {
                version: InsuranceRecapitalizationContributionV2::VERSION,
                chain_id: [1; 32],
                configuration_hash: [2; 32],
                contributor: signer(),
                account_nonce: 3,
                contribution_usdd_atoms: 4,
                insurance_output_opening_commitment: [5; 32],
                issued_share_atoms: 0,
                bond_output_opening_commitment: [0; 32],
            },
            &secret(),
        )
        .unwrap()
    }

    #[test]
    fn every_private_signed_action_has_one_fixed_canonical_width() {
        assert_eq!(
            subscription().canonical_bytes().len(),
            BondInboxActionKindV2::Subscription.canonical_signed_action_len()
        );
        assert_eq!(
            enqueue().canonical_bytes().len(),
            BondInboxActionKindV2::RedemptionEnqueue.canonical_signed_action_len()
        );
        let cancellation = cancellation();
        assert_eq!(
            cancellation.canonical_bytes().len(),
            BondInboxActionKindV2::RedemptionCancellation.canonical_signed_action_len()
        );
        let recap = recapitalization();
        assert_eq!(
            recap.canonical_bytes().len(),
            BondInboxActionKindV2::InsuranceRecapitalizationContribution
                .canonical_signed_action_len()
        );
    }

    fn availability() -> AvailabilityConfigV1 {
        AvailabilityConfigV1 {
            version: AvailabilityConfigV1::VERSION,
            scheme_hash: [31; 32],
            custodian_registry_hash: [32; 32],
            recovery_threshold: crate::AVAILABILITY_RECOVERY_THRESHOLD,
            custodian_count: crate::AVAILABILITY_CUSTODIAN_COUNT,
            maximum_witness_bytes: crate::MAX_AVAILABILITY_WITNESS_BYTES,
        }
    }

    fn limits() -> BondInboxLimitsV2 {
        BondInboxLimitsV2 {
            inbox_domain: [3; 32],
            inclusion_blocks: 6,
            refund_minimum_parent_blocks: 12,
            maximum_bundle_bytes: MAX_BOND_INBOX_BUNDLE_BYTES_V2,
            maximum_entries_per_sidechain_block: 8,
            maximum_unique_source_witness_bytes_per_sidechain_block:
                MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2,
            maximum_unique_source_transaction_bytes_per_sidechain_block:
                MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
            maximum_pending_entries_per_transition: 64,
            maximum_consumed_entries_per_transition: 64,
        }
    }

    fn marker_for(action: BondInboxUserActionV2, blind: Hash32) -> BondInboxMarkerV2 {
        let bytes = action.canonical_signed_bytes();
        let settlement = action.settlement_witness_commitment();
        let (staging_vout, refund_script_sha256, refund_not_before_parent_height) = match &action {
            BondInboxUserActionV2::RedemptionEnqueue(value) => (
                2,
                value.action.refund_script_sha256,
                value.action.refund_not_before_parent_height,
            ),
            _ => (u32::MAX, [0; 32], 0),
        };
        let source_authorization_commitment = match &action {
            BondInboxUserActionV2::RedemptionEnqueue(_) => {
                bond_inbox_staging_source_authorization_commitment_v2(
                    &[0x51; 64],
                    action.staging_intent_id(),
                    refund_script_sha256,
                    refund_not_before_parent_height,
                )
                .unwrap()
            }
            _ => bond_inbox_no_staging_source_authorization_commitment_v2(
                [1; 32],
                [2; 32],
                action.signer(),
                action.action_id(),
                1,
            )
            .unwrap(),
        };
        let mut marker = BondInboxMarkerV2 {
            version: BondInboxMarkerV2::VERSION,
            kind: action.kind(),
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            signer: action.signer(),
            action_id: action.action_id(),
            staging_intent_id: action.staging_intent_id(),
            staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height,
            payload_commitment: BondInboxAvailablePayloadV2::commitment(
                action.kind(),
                blind,
                &bytes,
                settlement,
                source_authorization_commitment,
            ),
            availability_scheme_hash: availability().scheme_hash,
            availability_custodian_registry_hash: availability().custodian_registry_hash,
            availability_bundle_root: [8; 32],
            availability_context: [0; 32],
            availability_receipt_root: [9; 32],
            availability_bundle_len: 1_000,
            availability_receipt_bitmap: 0b0_0111,
            source_authorization_commitment,
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        marker.sign(&secret()).unwrap()
    }

    fn entry(
        index: u64,
        previous_root: Hash32,
        parent_height: u64,
        marker: BondInboxMarkerV2,
    ) -> BondInboxEntryV2 {
        BondInboxEntryV2 {
            version: BondInboxEntryV2::VERSION,
            index,
            previous_root,
            observed_sidechain_height: 20 + index,
            observed_parent_height: parent_height,
            source_block_hash: [11 + index as u8; 32],
            source_txid: [21 + index as u8; 32],
            source_wtxid: [31 + index as u8; 32],
            source_transaction_len: 3_000,
            source_witness_sha256: [41 + index as u8; 32],
            source_witness_len: 2_000,
            source_tx_index: index as u32,
            marker_vout: 1,
            marker,
        }
    }

    #[test]
    fn public_marker_roundtrips_and_contains_no_confidential_amount() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let bytes = marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        assert_eq!(bytes.len(), BOND_INBOX_MARKER_LEN);
        assert_eq!(
            BondInboxMarkerV2::decode_payload(&bytes, MAX_BOND_INBOX_BUNDLE_BYTES_V2).unwrap(),
            marker
        );
        assert!(!bytes
            .windows(8)
            .any(|window| window == 4u64.to_be_bytes().as_slice()));
        assert_eq!(marker.staging_intent_id, [0; 32]);
        assert_eq!(marker.staging_vout, u32::MAX);
    }

    #[test]
    fn enqueue_marker_uses_a_salted_amount_free_staging_intent() {
        let original = enqueue();
        let marker = marker_for(
            BondInboxUserActionV2::RedemptionEnqueue(original.clone()),
            [12; 32],
        );
        assert_ne!(marker.staging_intent_id, [0; 32]);
        assert_eq!(
            marker.refund_script_sha256,
            original.action.refund_script_sha256
        );
        let mut changed = original.action;
        changed.intent_salt[0] ^= 1;
        assert_ne!(changed.stable_intent_id(), marker.staging_intent_id);
        let bytes = marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        assert!(!bytes
            .windows(8)
            .any(|window| { window == changed.requested_share_atoms.to_be_bytes().as_slice() }));
    }

    #[test]
    fn contiguous_prefix_maps_valid_action_once() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let action_bytes = action.canonical_signed_bytes();
        let settlement = action.settlement_witness_commitment();
        let blind = [12; 32];
        let marker = marker_for(action.clone(), blind);
        let source_authorization_commitment = marker.source_authorization_commitment;
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload: BondInboxAvailablePayloadV2 {
                    commitment_blinding: blind,
                    canonical_signed_action: action_bytes,
                    settlement_witness_commitment: settlement,
                    source_authorization_commitment,
                },
            }],
        };
        let recovered = match &transition.consumed_evidence[0] {
            BondInboxConsumedEvidenceV2::Recovered { payload, .. } => payload,
            BondInboxConsumedEvidenceV2::AuthenticatedRecoveryOrPayloadFailure(_) => {
                unreachable!()
            }
            BondInboxConsumedEvidenceV2::ExpiredUnavailable { .. } => unreachable!(),
        };
        assert_eq!(
            BondInboxAvailablePayloadV2::decode_canonical(
                BondInboxActionKindV2::Subscription,
                &recovered.canonical_bytes(),
            )
            .unwrap(),
            *recovered
        );
        let mut trailing = recovered.canonical_bytes();
        trailing.push(0);
        assert_eq!(
            BondInboxAvailablePayloadV2::decode_canonical(
                BondInboxActionKindV2::Subscription,
                &trailing,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
        let outcomes = transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                limits(),
            )
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].disposition,
            BondInboxConsumedDispositionV2::Action(Ok(action))
        );
    }

    #[test]
    fn producer_payload_survives_node_assigned_index_race_and_reorg() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let payload = BondInboxAvailablePayloadV2 {
            commitment_blinding: [12; 32],
            canonical_signed_action: action.canonical_signed_bytes(),
            settlement_witness_commitment: action.settlement_witness_commitment(),
            source_authorization_commitment: marker_for(action.clone(), [12; 32])
                .source_authorization_commitment,
        };
        let encrypted_before_inclusion = payload.canonical_bytes();
        let genesis = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut raced = entry(
            7,
            genesis.head_root,
            100,
            marker_for(action.clone(), [12; 32]),
        );
        // The node-assigned index and active-branch locator are absent from
        // the wallet-authored encrypted payload.
        assert_eq!(payload.canonical_bytes(), encrypted_before_inclusion);
        let first_entry_hash = raced.entry_hash();
        raced.index = 9;
        raced.source_block_hash[0] ^= 1;
        raced.source_tx_index = 4;
        assert_eq!(payload.canonical_bytes(), encrypted_before_inclusion);
        assert_ne!(raced.entry_hash(), first_entry_hash);

        let decoded = BondInboxAvailablePayloadV2::decode_canonical(
            BondInboxActionKindV2::Subscription,
            &encrypted_before_inclusion,
        )
        .unwrap();
        assert_eq!(
            decoded.classify(&raced).unwrap().disposition,
            BondInboxConsumedDispositionV2::Action(Ok(action))
        );
        assert_eq!(
            BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: first_entry_hash,
                payload: decoded.clone(),
            }
            .classify(&raced, 101, limits().inclusion_blocks),
            Err(ProtocolError::InvalidBondInbox)
        );
        BondInboxConsumedEvidenceV2::Recovered {
            source_entry_hash: raced.entry_hash(),
            payload: decoded,
        }
        .classify(&raced, 101, limits().inclusion_blocks)
        .unwrap();
    }

    #[test]
    fn malformed_committed_payload_is_consumed_as_rejection() {
        let malformed = vec![0x55; 13];
        let blind = [12; 32];
        let valid_action = BondInboxUserActionV2::Subscription(subscription());
        let mut marker = marker_for(valid_action, blind);
        let source_authorization_commitment = marker.source_authorization_commitment;
        marker.payload_commitment = BondInboxAvailablePayloadV2::commitment(
            marker.kind,
            blind,
            &malformed,
            [13; 32],
            source_authorization_commitment,
        );
        marker.availability_context = marker.expected_availability_context();
        marker.signature = Signature64([0; 64]);
        marker = marker.sign(&secret()).unwrap();
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload: BondInboxAvailablePayloadV2 {
                    commitment_blinding: blind,
                    canonical_signed_action: malformed,
                    settlement_witness_commitment: [13; 32],
                    source_authorization_commitment,
                },
            }],
        };
        let outcomes = transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                limits(),
            )
            .unwrap();
        assert_eq!(
            outcomes[0].disposition,
            BondInboxConsumedDispositionV2::Action(Err(
                BondInboxRejectionV2::MalformedOrInvalidAction
            ))
        );
        assert_eq!(next.cursor, 1);
    }

    #[test]
    fn authenticated_recovered_commitment_mismatch_is_consumed_as_rejection() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let source_authorization_commitment = marker.source_authorization_commitment;
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload: BondInboxAvailablePayloadV2 {
                    commitment_blinding: [13; 32],
                    canonical_signed_action: vec![0; 13],
                    settlement_witness_commitment: [13; 32],
                    source_authorization_commitment,
                },
            }],
        };
        let outcomes = transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                limits(),
            )
            .unwrap();
        assert_eq!(
            outcomes[0].disposition,
            BondInboxConsumedDispositionV2::Action(Err(
                BondInboxRejectionV2::MalformedOrInvalidAction
            ))
        );
    }

    #[test]
    fn authenticated_random_ciphertext_recovery_failure_advances_cursor() {
        let action = BondInboxUserActionV2::RedemptionEnqueue(enqueue());
        let marker = marker_for(action, [12; 32]);
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let witness_bundle_root = [0x44; 32];
        let recovery_certificate_root = [0x55; 32];
        let recovered_plaintext_sha256 = bond_inbox_aead_failure_plaintext_sentinel_v2();
        let failure_commitment =
            bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2(
                entry.entry_hash(),
                witness_bundle_root,
                BondInboxRecoveryFailureV2::PayloadAead,
                recovered_plaintext_sha256,
                recovery_certificate_root,
            )
            .unwrap();
        let evidence = BondInboxAuthenticatedRecoveryOrPayloadFailureV2 {
            failure: BondInboxRecoveryFailureV2::PayloadAead,
            witness_bundle_root,
            recovered_plaintext_sha256,
            recovery_certificate_root,
            failure_commitment,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![
                BondInboxConsumedEvidenceV2::AuthenticatedRecoveryOrPayloadFailure(evidence),
            ],
        };
        let outcomes = transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                105,
                21,
                availability(),
                limits(),
            )
            .unwrap();
        assert_eq!(next.cursor, 1);
        assert_eq!(
            outcomes[0].disposition,
            BondInboxConsumedDispositionV2::Action(Err(
                BondInboxRejectionV2::MalformedOrInvalidAction
            ))
        );

        assert_eq!(
            transition.verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                106,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );

        let mut substituted = evidence;
        substituted.recovery_certificate_root[0] ^= 1;
        assert_eq!(
            BondInboxTransitionV2 {
                pending_entries: vec![entry],
                consumed_evidence: vec![
                    BondInboxConsumedEvidenceV2::AuthenticatedRecoveryOrPayloadFailure(
                        substituted,
                    ),
                ],
            }
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                105,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn expired_unavailable_is_exactly_bound_to_inclusion_deadline() {
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let actions = [
            BondInboxUserActionV2::Subscription(subscription()),
            BondInboxUserActionV2::RedemptionEnqueue(enqueue()),
            BondInboxUserActionV2::RedemptionCancellation(cancellation()),
            BondInboxUserActionV2::InsuranceRecapitalizationContribution(recapitalization()),
        ];

        for action in actions {
            let marker = marker_for(action.clone(), [12; 32]);
            let entry = entry(0, previous.head_root, 100, marker);
            let next = BondInboxStateV2 {
                head_root: entry.next_root(),
                entry_count: 1,
                processed_root: entry.next_root(),
                cursor: 1,
            };
            let expired = BondInboxConsumedEvidenceV2::ExpiredUnavailable {
                source_entry_hash: entry.entry_hash(),
            };
            let transition = |evidence| BondInboxTransitionV2 {
                pending_entries: vec![entry],
                consumed_evidence: vec![evidence],
            };
            let payload = BondInboxAvailablePayloadV2 {
                commitment_blinding: [12; 32],
                canonical_signed_action: action.canonical_signed_bytes(),
                settlement_witness_commitment: action.settlement_witness_commitment(),
                source_authorization_commitment: entry.marker.source_authorization_commitment,
            };
            let recovered = BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload,
            };

            // One block before the +6 inclusion deadline the action remains
            // recoverable and the public expiry path is forbidden.
            assert_eq!(
                transition(expired.clone()).verify(
                    [1; 32],
                    [2; 32],
                    previous,
                    next,
                    105,
                    21,
                    availability(),
                    limits(),
                ),
                Err(ProtocolError::InvalidBondInbox)
            );
            assert!(transition(recovered.clone())
                .verify(
                    [1; 32],
                    [2; 32],
                    previous,
                    next,
                    105,
                    21,
                    availability(),
                    limits(),
                )
                .is_ok());

            // At and after the deadline the deterministic public disposition
            // is required and recovery semantics can no longer be selected.
            for height in [106, 107] {
                let outcomes = transition(expired.clone())
                    .verify(
                        [1; 32],
                        [2; 32],
                        previous,
                        next,
                        height,
                        21,
                        availability(),
                        limits(),
                    )
                    .unwrap();
                assert_eq!(
                    outcomes[0].disposition,
                    BondInboxConsumedDispositionV2::ExpiredUnavailable
                );
                assert_eq!(
                    BondInboxProcessedOutcomeV2::expired_unavailable(&outcomes[0]).disposition,
                    BondInboxProcessedDispositionV2::ExpiredUnavailable
                );
            }
            assert_eq!(
                transition(recovered).verify(
                    [1; 32],
                    [2; 32],
                    previous,
                    next,
                    106,
                    21,
                    availability(),
                    limits(),
                ),
                Err(ProtocolError::InvalidBondInbox)
            );

            let mut substituted = expired;
            let BondInboxConsumedEvidenceV2::ExpiredUnavailable { source_entry_hash } =
                &mut substituted
            else {
                unreachable!()
            };
            source_entry_hash[0] ^= 1;
            assert_eq!(
                transition(substituted).verify(
                    [1; 32],
                    [2; 32],
                    previous,
                    next,
                    106,
                    21,
                    availability(),
                    limits(),
                ),
                Err(ProtocolError::InvalidBondInbox)
            );

            if entry.marker.kind == BondInboxActionKindV2::RedemptionEnqueue {
                assert_eq!(entry.marker.refund_not_before_parent_height, 112);
                assert_eq!(entry.deadline(limits().inclusion_blocks).unwrap(), 106);
            }
        }
    }

    #[test]
    fn substituted_recovery_evidence_source_is_a_hard_proof_error() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let source_authorization_commitment = marker.source_authorization_commitment;
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: [0x77; 32],
                payload: BondInboxAvailablePayloadV2 {
                    commitment_blinding: [12; 32],
                    canonical_signed_action: vec![],
                    settlement_witness_commitment: [13; 32],
                    source_authorization_commitment,
                },
            }],
        };
        assert_eq!(
            transition.verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn deadline_and_reorg_projection_fail_closed() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        let transition = BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![],
        };
        assert_eq!(
            transition.verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                106,
                21,
                availability(),
                limits()
            ),
            Err(ProtocolError::BondInboxDeadline)
        );
        let mut wrong_branch = next;
        wrong_branch.head_root[0] ^= 1;
        assert_eq!(
            transition.verify(
                [1; 32],
                [2; 32],
                previous,
                wrong_branch,
                101,
                21,
                availability(),
                limits()
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn marker_mutations_and_trailing_bytes_are_rejected() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let original = marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        for offset in 0..original.len() {
            let mut mutated = original.clone();
            mutated[offset] ^= 1;
            if let Ok(decoded) =
                BondInboxMarkerV2::decode_payload(&mutated, MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            {
                assert!(decoded.verify_wrapper_signature().is_err());
            }
        }
        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            BondInboxMarkerV2::decode_payload(&trailing, MAX_BOND_INBOX_BUNDLE_BYTES_V2),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn exact_bundle_and_ordered_receipts_are_fully_committed() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let mut marker = marker_for(action, [12; 32]);
        let bundle = vec![0x42; 1_000];
        marker.availability_bundle_root = bond_inbox_availability_bundle_root_v2(&bundle).unwrap();
        marker.availability_bundle_len = bundle.len() as u32;
        marker.availability_context = marker.expected_availability_context();
        let receipts = [
            BondInboxCustodyReceiptV2 {
                custodian_index: 0,
                exact_receipt_bytes: vec![0x51; 138],
            },
            BondInboxCustodyReceiptV2 {
                custodian_index: 2,
                exact_receipt_bytes: vec![0x52; 138],
            },
            BondInboxCustodyReceiptV2 {
                custodian_index: 4,
                exact_receipt_bytes: vec![0x53; 138],
            },
        ];
        let (receipt_root, bitmap) =
            canonical_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
        marker.availability_receipt_root = receipt_root;
        marker.availability_receipt_bitmap = bitmap;
        marker.signature = Signature64([0; 64]);
        marker = marker.sign(&secret()).unwrap();
        verify_bond_inbox_source_witness_commitments_v2(
            &marker,
            availability(),
            &bundle,
            &receipts,
        )
        .unwrap();

        let mut mutated_bundle = bundle.clone();
        mutated_bundle[500] ^= 1;
        assert_eq!(
            verify_bond_inbox_source_witness_commitments_v2(
                &marker,
                availability(),
                &mutated_bundle,
                &receipts,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
        let mut reordered = receipts.clone();
        reordered.swap(0, 1);
        assert_eq!(
            canonical_bond_inbox_custody_receipts_v2(&marker, &reordered),
            Err(ProtocolError::InvalidBondInbox)
        );
        let mut mutated_receipts = receipts.clone();
        mutated_receipts[1].exact_receipt_bytes[0] ^= 1;
        assert_ne!(
            canonical_bond_inbox_custody_receipts_v2(&marker, &mutated_receipts)
                .unwrap()
                .0,
            receipt_root
        );
        let mut wrong_width = receipts.clone();
        wrong_width[1].exact_receipt_bytes.pop();
        assert_eq!(
            canonical_bond_inbox_custody_receipts_v2(&marker, &wrong_width),
            Err(ProtocolError::InvalidBondInbox)
        );
        assert_eq!(
            canonical_bond_inbox_custody_receipts_v2(&marker, &receipts[..2]),
            Err(ProtocolError::InvalidBondInbox)
        );

        // The V2 leaf binding cannot masquerade as the Ed25519 message signed
        // by the embedded V1 receipt. The latter uses a one-based index and
        // only its own receipt fields under the frozen V1 domain.
        let binding = bond_inbox_custody_receipt_binding_digest_v2(&marker, 0).unwrap();
        let mut v1_message = Vec::with_capacity(74);
        v1_message.push(1);
        v1_message.extend_from_slice(&marker.availability_bundle_root);
        v1_message.extend_from_slice(&marker.availability_context);
        v1_message.extend_from_slice(&u64::from(marker.availability_bundle_len).to_be_bytes());
        v1_message.push(1);
        let v1_signed_message = tagged_hash("ECX/witness-custody-receipt/v1", &v1_message);
        assert_ne!(binding, v1_signed_message);
    }

    #[test]
    fn same_block_extraction_order_is_unique_and_canonical() {
        let marker = marker_for(
            BondInboxUserActionV2::Subscription(subscription()),
            [12; 32],
        );
        let genesis = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let first = entry(0, genesis.head_root, 100, marker);
        let mut second = entry(1, first.next_root(), 100, marker);
        second.observed_sidechain_height = first.observed_sidechain_height;
        second.source_block_hash = first.source_block_hash;
        validate_bond_inbox_source_order_v2(&first, &second).unwrap();

        let mut wrong_block = second;
        wrong_block.source_block_hash[0] ^= 1;
        assert_eq!(
            validate_bond_inbox_source_order_v2(&first, &wrong_block),
            Err(ProtocolError::InvalidBondInbox)
        );
        let mut lower_tx_index = second;
        lower_tx_index.source_tx_index = 0;
        lower_tx_index.marker_vout = 2;
        lower_tx_index.source_txid = first.source_txid;
        lower_tx_index.source_wtxid = first.source_wtxid;
        lower_tx_index.source_witness_sha256 = first.source_witness_sha256;
        lower_tx_index.source_witness_len = first.source_witness_len;
        assert_eq!(
            validate_bond_inbox_source_order_v2(&first, &lower_tx_index),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn same_block_source_cannot_enter_its_own_transition() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let marker = marker_for(action, [12; 32]);
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, previous.head_root, 100, marker);
        let next = BondInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        assert_eq!(
            BondInboxTransitionV2 {
                pending_entries: vec![entry],
                consumed_evidence: vec![],
            }
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                entry.observed_sidechain_height,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn frozen_inbox_domain_binds_the_empty_state_root() {
        let canonical = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut arbitrary = canonical;
        arbitrary.head_root[0] ^= 1;
        arbitrary.processed_root = arbitrary.head_root;
        assert_eq!(
            BondInboxTransitionV2 {
                pending_entries: vec![],
                consumed_evidence: vec![],
            }
            .verify(
                [1; 32],
                [2; 32],
                arbitrary,
                arbitrary,
                100,
                20,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn source_admission_flood_and_enqueue_refund_bounds_fail_closed() {
        let subscription_marker = marker_for(
            BondInboxUserActionV2::Subscription(subscription()),
            [12; 32],
        );
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut entries = Vec::new();
        let mut root = previous.head_root;
        for index in 0..9u64 {
            let mut item = entry(index, root, 100, subscription_marker);
            item.observed_sidechain_height = 20;
            item.source_block_hash = [11; 32];
            item.source_tx_index = index as u32;
            root = item.next_root();
            entries.push(item);
        }
        let next = BondInboxStateV2 {
            head_root: root,
            entry_count: 9,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        assert_eq!(
            BondInboxTransitionV2 {
                pending_entries: entries,
                consumed_evidence: vec![],
            }
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );

        let enqueue_marker = marker_for(
            BondInboxUserActionV2::RedemptionEnqueue(enqueue()),
            [13; 32],
        );
        let mut staged = entry(0, previous.head_root, 100, enqueue_marker);
        staged.marker.staging_vout = staged.marker_vout;
        assert_eq!(
            staged.validate(
                availability(),
                MAX_BOND_INBOX_BUNDLE_BYTES_V2,
                limits().refund_minimum_parent_blocks,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
        staged.marker.staging_vout = 2;
        staged.marker.refund_not_before_parent_height = 111;
        assert_eq!(
            staged.validate(
                availability(),
                MAX_BOND_INBOX_BUNDLE_BYTES_V2,
                limits().refund_minimum_parent_blocks,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    fn pending_block_transition(
        previous: BondInboxStateV2,
        entries: Vec<BondInboxEntryV2>,
    ) -> (BondInboxTransitionV2, BondInboxStateV2) {
        let last = *entries.last().unwrap();
        (
            BondInboxTransitionV2 {
                pending_entries: entries,
                consumed_evidence: vec![],
            },
            BondInboxStateV2 {
                head_root: last.next_root(),
                entry_count: last.index + 1,
                processed_root: previous.processed_root,
                cursor: previous.cursor,
            },
        )
    }

    #[test]
    fn same_block_source_transaction_cannot_supply_two_markers() {
        let marker = marker_for(
            BondInboxUserActionV2::RedemptionEnqueue(enqueue()),
            [12; 32],
        );
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut first = entry(0, previous.head_root, 100, marker);
        first.marker_vout = 0;
        let mut second = entry(1, first.next_root(), 100, marker);
        second.observed_sidechain_height = first.observed_sidechain_height;
        second.source_block_hash = first.source_block_hash;
        second.source_txid = first.source_txid;
        second.source_wtxid = first.source_wtxid;
        second.source_transaction_len = first.source_transaction_len;
        second.source_witness_sha256 = first.source_witness_sha256;
        second.source_witness_len = first.source_witness_len;
        second.source_tx_index = first.source_tx_index;
        second.marker_vout = 1;
        let (transition, next) = pending_block_transition(previous, vec![first, second]);
        let mut tight = limits();
        tight.maximum_unique_source_transaction_bytes_per_sidechain_block = 3_000;
        tight.maximum_unique_source_witness_bytes_per_sidechain_block = 2_000;
        assert_eq!(
            transition.verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                101,
                21,
                availability(),
                tight,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn distinct_source_transaction_and_witness_aggregates_are_bounded() {
        let marker = marker_for(
            BondInboxUserActionV2::Subscription(subscription()),
            [12; 32],
        );
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();

        let mut first = entry(0, previous.head_root, 100, marker);
        first.source_transaction_len = 400 * 1024;
        first.source_witness_len = 1_000;
        let mut second = entry(1, first.next_root(), 100, marker);
        second.observed_sidechain_height = first.observed_sidechain_height;
        second.source_block_hash = first.source_block_hash;
        second.source_transaction_len = 400 * 1024;
        second.source_witness_len = 1_000;
        let (transaction_flood, transaction_flood_next) =
            pending_block_transition(previous, vec![first, second]);
        assert_eq!(
            transaction_flood.verify(
                [1; 32],
                [2; 32],
                previous,
                transaction_flood_next,
                101,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );

        let mut first = entry(0, previous.head_root, 100, marker);
        first.source_transaction_len = 350 * 1024;
        first.source_witness_len = 300 * 1024;
        let mut second = entry(1, first.next_root(), 100, marker);
        second.observed_sidechain_height = first.observed_sidechain_height;
        second.source_block_hash = first.source_block_hash;
        second.source_transaction_len = 350 * 1024;
        second.source_witness_len = 300 * 1024;
        let (witness_flood, witness_flood_next) =
            pending_block_transition(previous, vec![first, second]);
        assert_eq!(
            witness_flood.verify(
                [1; 32],
                [2; 32],
                previous,
                witness_flood_next,
                101,
                21,
                availability(),
                limits(),
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn oversized_source_transaction_is_rejected_even_with_small_witness() {
        let marker = marker_for(
            BondInboxUserActionV2::Subscription(subscription()),
            [12; 32],
        );
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut oversized = entry(0, previous.head_root, 100, marker);
        oversized.source_transaction_len = MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2 + 1;
        oversized.source_witness_len = 128;
        assert_eq!(
            oversized.validate(
                availability(),
                MAX_BOND_INBOX_BUNDLE_BYTES_V2,
                limits().refund_minimum_parent_blocks,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn source_witness_sha256_binds_every_byte_and_is_bounded() {
        let witness = vec![0x31; 1_024];
        let digest = bond_inbox_source_witness_sha256_v2(&witness).unwrap();
        let marker = marker_for(
            BondInboxUserActionV2::Subscription(subscription()),
            [12; 32],
        );
        let genesis = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let mut projected = entry(0, genesis.head_root, 100, marker);
        projected.source_witness_len = witness.len() as u32;
        projected.source_witness_sha256 = digest;
        verify_bond_inbox_entry_source_witness_v2(&projected, &witness).unwrap();
        let mut mutated = witness;
        mutated[700] ^= 1;
        assert_ne!(
            bond_inbox_source_witness_sha256_v2(&mutated).unwrap(),
            digest
        );
        assert_eq!(
            verify_bond_inbox_entry_source_witness_v2(&projected, &mutated),
            Err(ProtocolError::InvalidBondInbox)
        );
        assert_eq!(
            bond_inbox_source_witness_sha256_v2(&[]),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn staging_authorization_binds_exact_txout_without_a_txid_cycle() {
        let txout = vec![0x22; 513];
        let intent = [3; 32];
        let refund_script = [4; 32];
        let commitment = bond_inbox_staging_source_authorization_commitment_v2(
            &txout,
            intent,
            refund_script,
            112,
        )
        .unwrap();
        let mut mutated = txout;
        mutated[200] ^= 1;
        assert_ne!(
            bond_inbox_staging_source_authorization_commitment_v2(
                &mutated,
                intent,
                refund_script,
                112,
            )
            .unwrap(),
            commitment
        );
        assert_ne!(
            bond_inbox_staging_source_authorization_commitment_v2(
                &mutated,
                [5; 32],
                refund_script,
                112,
            )
            .unwrap(),
            commitment
        );
        let no_staging = bond_inbox_no_staging_source_authorization_commitment_v2(
            [1; 32],
            [2; 32],
            signer(),
            [6; 32],
            1,
        )
        .unwrap();
        assert_ne!(no_staging, commitment);
    }

    #[test]
    fn non_enqueue_source_authorization_is_not_an_opaque_prover_choice() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let action_bytes = action.canonical_signed_bytes();
        let settlement = action.settlement_witness_commitment();
        let blind = [12; 32];
        let mut marker = marker_for(action, blind);
        marker.source_authorization_commitment = [0x77; 32];
        marker.payload_commitment = BondInboxAvailablePayloadV2::commitment(
            marker.kind,
            blind,
            &action_bytes,
            settlement,
            marker.source_authorization_commitment,
        );
        marker.availability_context = marker.expected_availability_context();
        marker.signature = Signature64([0; 64]);
        marker = marker.sign(&secret()).unwrap();
        let genesis = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let entry = entry(0, genesis.head_root, 100, marker);
        assert_eq!(
            entry.validate(
                availability(),
                MAX_BOND_INBOX_BUNDLE_BYTES_V2,
                limits().refund_minimum_parent_blocks,
            ),
            Err(ProtocolError::InvalidBondInbox)
        );
    }

    #[test]
    fn mixed_semantic_outcomes_advance_cursor_and_commit_exact_order() {
        let action = BondInboxUserActionV2::Subscription(subscription());
        let bytes = action.canonical_signed_bytes();
        let settlement = action.settlement_witness_commitment();
        let blind = [12; 32];
        let marker = marker_for(action, blind);
        let source_authorization_commitment = marker.source_authorization_commitment;
        let previous = BondInboxStateV2::genesis([3; 32], [1; 32], [2; 32]).unwrap();
        let first = entry(0, previous.head_root, 100, marker);
        let second = entry(1, first.next_root(), 101, marker);
        let next = BondInboxStateV2 {
            head_root: second.next_root(),
            entry_count: 2,
            processed_root: second.next_root(),
            cursor: 2,
        };
        let payload = || BondInboxAvailablePayloadV2 {
            commitment_blinding: blind,
            canonical_signed_action: bytes.clone(),
            settlement_witness_commitment: settlement,
            source_authorization_commitment,
        };
        let consumed = BondInboxTransitionV2 {
            pending_entries: vec![first, second],
            consumed_evidence: vec![
                BondInboxConsumedEvidenceV2::Recovered {
                    source_entry_hash: first.entry_hash(),
                    payload: payload(),
                },
                BondInboxConsumedEvidenceV2::Recovered {
                    source_entry_hash: second.entry_hash(),
                    payload: payload(),
                },
            ],
        }
        .verify(
            [1; 32],
            [2; 32],
            previous,
            next,
            102,
            22,
            availability(),
            limits(),
        )
        .unwrap();
        assert_eq!(next.cursor, 2);
        let outcomes = [
            BondInboxProcessedOutcomeV2::accepted(&consumed[0]),
            BondInboxProcessedOutcomeV2::rejected(
                &consumed[1],
                BondInboxRejectionV2::DuplicateOrReplayedAction,
            ),
        ];
        let genesis = bond_inbox_outcome_genesis_root_v2([3; 32], [1; 32], [2; 32]).unwrap();
        let ordered = outcomes
            .iter()
            .try_fold(genesis, |root, outcome| {
                bond_inbox_outcome_next_root_v2(root, outcome)
            })
            .unwrap();
        let reversed = outcomes
            .iter()
            .rev()
            .try_fold(genesis, |root, outcome| {
                bond_inbox_outcome_next_root_v2(root, outcome)
            })
            .unwrap();
        assert_ne!(ordered, reversed);
    }
}
