//! Fresh authenticated bond-inbox boundary for the incremental successor.
//!
//! V18 used `u64` entry and processed cursors.  This module deliberately does
//! not reinterpret those bytes.  It carries the successor's `u128` lifetime
//! counters, version-3 marker, and successor signed actions under new domains.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::availability::AvailabilityConfigV1;
use crate::bond_inbox_v2::{
    BondInboxActionKindV2, BondInboxCustodyReceiptV2, BondInboxLimitsV2,
    BondInboxProcessedDispositionV2, BondInboxRecoveryFailureV2, BondInboxRejectionV2,
    BOND_INBOX_MAX_CUSTODIANS_V2, BOND_INBOX_MIN_DISTINCT_CUSTODY_RECEIPTS_V2,
    MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2,
    MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2, MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2,
};
use crate::codec::{put_u128, put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::merkle::ordered_root;
use crate::successor_bond_action_v2::{
    SuccessorBondInboxAvailablePayloadV2, SuccessorBondInboxMarkerV2,
    SuccessorBondInboxUserActionV2,
};
use crate::types::XOnlyKey;
use crate::ProtocolError;

pub fn successor_bond_inbox_availability_bundle_root_v2(
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
        "ECX/successor-bond-inbox-encrypted-availability-bundle/v2-u128",
        &bytes,
    ))
}

pub fn successor_bond_inbox_staging_source_authorization_commitment_v2(
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
        "ECX/successor-bond-inbox-staging-source-authorization/v2-u128",
        &bytes,
    ))
}

pub fn successor_bond_inbox_no_staging_source_authorization_commitment_v2(
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
        "ECX/successor-bond-inbox-no-staging-source-authorization/v2-u128",
        &bytes,
    ))
}

pub fn successor_bond_inbox_custody_receipt_binding_digest_v2(
    marker: &SuccessorBondInboxMarkerV2,
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
        "ECX/successor-bond-inbox-custody-receipt-binding/v2-u128",
        &bytes,
    ))
}

pub fn canonical_successor_bond_inbox_custody_receipts_v2(
    marker: &SuccessorBondInboxMarkerV2,
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
        let digest = successor_bond_inbox_custody_receipt_binding_digest_v2(
            marker,
            receipt.custodian_index,
        )?;
        let mut bytes = Vec::with_capacity(37 + receipt.exact_receipt_bytes.len());
        bytes.extend_from_slice(&digest);
        put_u32(
            &mut bytes,
            u32::try_from(receipt.exact_receipt_bytes.len())
                .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        );
        bytes.extend_from_slice(&receipt.exact_receipt_bytes);
        leaves.push(tagged_hash(
            "ECX/successor-bond-inbox-exact-custody-receipt/v2-u128",
            &bytes,
        ));
    }
    Ok((
        ordered_root("ECX/successor-bond-inbox-custody-receipts/v2-u128", &leaves),
        bitmap,
    ))
}

pub fn verify_successor_bond_inbox_source_witness_commitments_v2(
    marker: &SuccessorBondInboxMarkerV2,
    availability: AvailabilityConfigV1,
    canonical_encrypted_bundle: &[u8],
    receipts: &[BondInboxCustodyReceiptV2],
) -> Result<(), ProtocolError> {
    marker.verify_availability_claim(availability, MAX_BOND_INBOX_BUNDLE_BYTES_V2)?;
    let (receipt_root, receipt_bitmap) =
        canonical_successor_bond_inbox_custody_receipts_v2(marker, receipts)?;
    if marker.availability_bundle_len
        != u32::try_from(canonical_encrypted_bundle.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
        || marker.availability_bundle_root
            != successor_bond_inbox_availability_bundle_root_v2(canonical_encrypted_bundle)?
        || marker.availability_receipt_root != receipt_root
        || marker.availability_receipt_bitmap != receipt_bitmap
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxEntryV2 {
    pub version: u8,
    pub index: u128,
    pub previous_root: Hash32,
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub source_block_hash: Hash32,
    pub source_txid: Hash32,
    pub source_wtxid: Hash32,
    pub source_transaction_len: u32,
    pub source_witness_sha256: Hash32,
    pub source_witness_len: u32,
    pub source_tx_index: u32,
    pub marker_vout: u32,
    pub marker: SuccessorBondInboxMarkerV2,
}

impl SuccessorBondInboxEntryV2 {
    pub const VERSION: u8 = 2;

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
        if self.marker.kind == BondInboxActionKindV2::RedemptionEnqueue {
            if self.marker.staging_vout == self.marker_vout
                || self
                    .observed_parent_height
                    .checked_add(u64::from(refund_minimum_parent_blocks))
                    .map_or(true, |height| {
                        self.marker.refund_not_before_parent_height < height
                    })
            {
                return Err(ProtocolError::InvalidBondInbox);
            }
        } else if self.marker.source_authorization_commitment
            != successor_bond_inbox_no_staging_source_authorization_commitment_v2(
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
        canonical_hash("ECX/successor-bond-inbox-entry/v2-u128", self)
    }

    pub fn next_root(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.previous_root);
        put_u128(&mut bytes, self.index);
        bytes.extend_from_slice(&self.entry_hash());
        tagged_hash("ECX/successor-bond-inbox-step/v2-u128", &bytes)
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

impl CanonicalEncode for SuccessorBondInboxEntryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u128(out, self.index);
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

pub fn verify_successor_bond_inbox_entry_source_witness_v2(
    entry: &SuccessorBondInboxEntryV2,
    exact_source_witness: &[u8],
) -> Result<(), ProtocolError> {
    let actual_sha256: Hash32 = Sha256::digest(exact_source_witness).into();
    if entry.source_witness_len
        != u32::try_from(exact_source_witness.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
        || entry.source_witness_sha256 != actual_sha256
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

pub fn validate_successor_bond_inbox_source_order_v2(
    previous: &SuccessorBondInboxEntryV2,
    current: &SuccessorBondInboxEntryV2,
) -> Result<(), ProtocolError> {
    if current.observed_sidechain_height == previous.observed_sidechain_height
        && (current.source_block_hash != previous.source_block_hash
            || current.observed_parent_height != previous.observed_parent_height
            || current.source_tx_index <= previous.source_tx_index)
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxStateV2 {
    pub head_root: Hash32,
    pub entry_count: u128,
    pub processed_root: Hash32,
    pub cursor: u128,
}

impl SuccessorBondInboxStateV2 {
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
        let root = tagged_hash("ECX/successor-bond-inbox-genesis/v2-u128", &bytes);
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

impl CanonicalEncode for SuccessorBondInboxStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_root);
        put_u128(out, self.entry_count);
        out.extend_from_slice(&self.processed_root);
        put_u128(out, self.cursor);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxProcessedOutcomeV2 {
    pub version: u8,
    pub entry_index: u128,
    pub entry_hash: Hash32,
    pub marker_kind: BondInboxActionKindV2,
    pub marker_action_id: Hash32,
    pub disposition: BondInboxProcessedDispositionV2,
}

impl SuccessorBondInboxProcessedOutcomeV2 {
    pub const VERSION: u8 = 4;

    pub fn accepted(consumed: &SuccessorBondInboxConsumedOutcomeV2) -> Self {
        Self::from_consumed(consumed, BondInboxProcessedDispositionV2::Accepted)
    }

    pub fn rejected(
        consumed: &SuccessorBondInboxConsumedOutcomeV2,
        rejection: BondInboxRejectionV2,
    ) -> Self {
        Self::from_consumed(
            consumed,
            BondInboxProcessedDispositionV2::Rejected(rejection),
        )
    }

    pub fn expired_unavailable(consumed: &SuccessorBondInboxConsumedOutcomeV2) -> Self {
        Self::from_consumed(
            consumed,
            BondInboxProcessedDispositionV2::ExpiredUnavailable,
        )
    }

    fn from_consumed(
        consumed: &SuccessorBondInboxConsumedOutcomeV2,
        disposition: BondInboxProcessedDispositionV2,
    ) -> Self {
        Self {
            version: Self::VERSION,
            entry_index: consumed.entry_index,
            entry_hash: consumed.entry_hash,
            marker_kind: consumed.marker_kind,
            marker_action_id: consumed.marker_action_id,
            disposition,
        }
    }

    pub fn outcome_hash(&self) -> Hash32 {
        canonical_hash("ECX/successor-bond-inbox-processed-outcome/v2-u128", self)
    }
}

impl CanonicalEncode for SuccessorBondInboxProcessedOutcomeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u128(out, self.entry_index);
        out.extend_from_slice(&self.entry_hash);
        self.marker_kind.encode_to(out);
        out.extend_from_slice(&self.marker_action_id);
        self.disposition.encode_to(out);
    }
}

pub fn successor_bond_inbox_outcome_genesis_root_v2(
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
        "ECX/successor-bond-inbox-outcomes-genesis/v2-u128",
        &bytes,
    ))
}

pub fn successor_bond_inbox_outcome_next_root_v2(
    previous_root: Hash32,
    outcome: &SuccessorBondInboxProcessedOutcomeV2,
) -> Result<Hash32, ProtocolError> {
    if previous_root == [0; 32] || outcome.version != SuccessorBondInboxProcessedOutcomeV2::VERSION
    {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&previous_root);
    put_u128(&mut bytes, outcome.entry_index);
    bytes.extend_from_slice(&outcome.outcome_hash());
    Ok(tagged_hash(
        "ECX/successor-bond-inbox-outcomes-step/v2-u128",
        &bytes,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
pub enum SuccessorBondInboxConsumedDispositionV2 {
    Action(Result<SuccessorBondInboxUserActionV2, BondInboxRejectionV2>),
    ExpiredUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxConsumedOutcomeV2 {
    pub entry_index: u128,
    pub entry_hash: Hash32,
    pub marker_kind: BondInboxActionKindV2,
    pub marker_action_id: Hash32,
    pub source_parent_height: u64,
    pub disposition: SuccessorBondInboxConsumedDispositionV2,
}

pub fn successor_bond_inbox_aead_failure_plaintext_sentinel_v2() -> Hash32 {
    tagged_hash(
        "ECX/successor-bond-inbox-aead-failure-plaintext-sentinel/v2-u128",
        &[],
    )
}

pub fn successor_bond_inbox_recovered_plaintext_sha256_v2(
    exact_recovered_plaintext: &[u8],
) -> Result<Hash32, ProtocolError> {
    if exact_recovered_plaintext.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize {
        return Err(ProtocolError::InvalidBondInbox);
    }
    Ok(Sha256::digest(exact_recovered_plaintext).into())
}

pub fn successor_bond_inbox_authenticated_failure_commitment_v2(
    entry_hash: Hash32,
    witness_bundle_root: Hash32,
    failure: BondInboxRecoveryFailureV2,
    recovered_plaintext_sha256: Hash32,
    recovery_certificate_root: Hash32,
) -> Result<Hash32, ProtocolError> {
    let sentinel = successor_bond_inbox_aead_failure_plaintext_sentinel_v2();
    if entry_hash == [0; 32]
        || witness_bundle_root == [0; 32]
        || recovered_plaintext_sha256 == [0; 32]
        || recovery_certificate_root == [0; 32]
        || (failure == BondInboxRecoveryFailureV2::PayloadAead
            && recovered_plaintext_sha256 != sentinel)
        || (failure != BondInboxRecoveryFailureV2::PayloadAead
            && recovered_plaintext_sha256 == sentinel)
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
        "ECX/successor-bond-inbox-authenticated-recovery-or-payload-failure/v2-u128",
        &bytes,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxAuthenticatedFailureV2 {
    pub failure: BondInboxRecoveryFailureV2,
    pub witness_bundle_root: Hash32,
    pub recovered_plaintext_sha256: Hash32,
    pub recovery_certificate_root: Hash32,
    pub failure_commitment: Hash32,
}

impl CanonicalEncode for SuccessorBondInboxAuthenticatedFailureV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.failure.encode_to(out);
        out.extend_from_slice(&self.witness_bundle_root);
        out.extend_from_slice(&self.recovered_plaintext_sha256);
        out.extend_from_slice(&self.recovery_certificate_root);
        out.extend_from_slice(&self.failure_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SuccessorBondInboxConsumedEvidenceV2 {
    Recovered {
        source_entry_hash: Hash32,
        payload: SuccessorBondInboxAvailablePayloadV2,
    },
    AuthenticatedRecoveryOrPayloadFailure(SuccessorBondInboxAuthenticatedFailureV2),
    ExpiredUnavailable {
        source_entry_hash: Hash32,
    },
}

impl SuccessorBondInboxConsumedEvidenceV2 {
    fn classify(
        &self,
        entry: &SuccessorBondInboxEntryV2,
        parent_height: u64,
        inclusion_blocks: u32,
    ) -> Result<SuccessorBondInboxConsumedOutcomeV2, ProtocolError> {
        let deadline_reached = parent_height >= entry.deadline(inclusion_blocks)?;
        match self {
            Self::Recovered {
                source_entry_hash,
                payload,
            } => {
                if *source_entry_hash != entry.entry_hash() || deadline_reached {
                    return Err(ProtocolError::InvalidBondInbox);
                }
                classify_payload(payload, entry)
            }
            Self::AuthenticatedRecoveryOrPayloadFailure(failure) => {
                if deadline_reached
                    || failure.failure_commitment
                        != successor_bond_inbox_authenticated_failure_commitment_v2(
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
                Ok(SuccessorBondInboxConsumedOutcomeV2 {
                    entry_index: entry.index,
                    entry_hash: entry.entry_hash(),
                    marker_kind: entry.marker.kind,
                    marker_action_id: entry.marker.action_id,
                    source_parent_height: entry.observed_parent_height,
                    disposition: SuccessorBondInboxConsumedDispositionV2::ExpiredUnavailable,
                })
            }
        }
    }
}

impl CanonicalEncode for SuccessorBondInboxConsumedEvidenceV2 {
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

fn classify_payload(
    payload: &SuccessorBondInboxAvailablePayloadV2,
    entry: &SuccessorBondInboxEntryV2,
) -> Result<SuccessorBondInboxConsumedOutcomeV2, ProtocolError> {
    if payload.canonical_signed_action.len() > entry.marker.availability_bundle_len as usize
        || payload.settlement_witness_commitment == [0; 32]
        || payload.source_authorization_commitment != entry.marker.source_authorization_commitment
        || SuccessorBondInboxAvailablePayloadV2::commitment(
            entry.marker.kind,
            payload.commitment_blinding,
            &payload.canonical_signed_action,
            payload.settlement_witness_commitment,
            payload.source_authorization_commitment,
        ) != entry.marker.payload_commitment
    {
        return Ok(malformed_consumed_outcome(entry));
    }
    let decoded = if payload.commitment_blinding == [0; 32] {
        Err(ProtocolError::InvalidBondInbox)
    } else {
        payload.decode_action(entry.marker.kind)
    };
    let action = match decoded {
        Ok(action)
            if action.kind() == entry.marker.kind
                && action.signer() == entry.marker.signer
                && action.action_id() == entry.marker.action_id
                && action.staging_intent_id() == entry.marker.staging_intent_id
                && match &action {
                    SuccessorBondInboxUserActionV2::RedemptionEnqueue(value) => {
                        value.action.refund_script_sha256 == entry.marker.refund_script_sha256
                            && value.action.refund_not_before_parent_height
                                == entry.marker.refund_not_before_parent_height
                    }
                    _ => true,
                }
                && action.settlement_witness_commitment()
                    == payload.settlement_witness_commitment
                && entry.marker.verify_wrapper_signature().is_ok()
                && action.verify().is_ok() =>
        {
            Ok(action)
        }
        _ => Err(BondInboxRejectionV2::MalformedOrInvalidAction),
    };
    Ok(SuccessorBondInboxConsumedOutcomeV2 {
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        source_parent_height: entry.observed_parent_height,
        disposition: SuccessorBondInboxConsumedDispositionV2::Action(action),
    })
}

fn malformed_consumed_outcome(
    entry: &SuccessorBondInboxEntryV2,
) -> SuccessorBondInboxConsumedOutcomeV2 {
    SuccessorBondInboxConsumedOutcomeV2 {
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        source_parent_height: entry.observed_parent_height,
        disposition: SuccessorBondInboxConsumedDispositionV2::Action(Err(
            BondInboxRejectionV2::MalformedOrInvalidAction,
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxTransitionV2 {
    pub pending_entries: Vec<SuccessorBondInboxEntryV2>,
    pub consumed_evidence: Vec<SuccessorBondInboxConsumedEvidenceV2>,
}

impl SuccessorBondInboxTransitionV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        chain_id: Hash32,
        configuration_hash: Hash32,
        previous: SuccessorBondInboxStateV2,
        next: SuccessorBondInboxStateV2,
        parent_height: u64,
        transition_sidechain_height: u64,
        availability: AvailabilityConfigV1,
        limits: BondInboxLimitsV2,
    ) -> Result<Vec<SuccessorBondInboxConsumedOutcomeV2>, ProtocolError> {
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
                != SuccessorBondInboxStateV2::genesis(
                    limits.inbox_domain,
                    chain_id,
                    configuration_hash,
                )?
        {
            return Err(ProtocolError::InvalidBondInbox);
        }

        let consumed_count = u128::try_from(self.consumed_evidence.len())
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
        let mut source_witness_bytes_at_height = 0u32;
        let mut source_transaction_bytes_at_height = 0u32;
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
                validate_successor_bond_inbox_source_order_v2(prior, entry)?;
            }
            if entry.observed_sidechain_height != last_sidechain_height {
                entries_at_height = 0;
                source_witness_bytes_at_height = 0;
                source_transaction_bytes_at_height = 0;
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
            source_witness_bytes_at_height = source_witness_bytes_at_height
                .checked_add(entry.source_witness_len)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            source_transaction_bytes_at_height = source_transaction_bytes_at_height
                .checked_add(entry.source_transaction_len)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if entry.marker.chain_id != chain_id
                || entry.marker.configuration_hash != configuration_hash
                || entry.observed_sidechain_height >= transition_sidechain_height
                || entry.index != index
                || entry.previous_root != root
                || entries_at_height > limits.maximum_entries_per_sidechain_block
                || source_witness_bytes_at_height
                    > limits.maximum_unique_source_witness_bytes_per_sidechain_block
                || source_transaction_bytes_at_height
                    > limits.maximum_unique_source_transaction_bytes_per_sidechain_block
                || (last_sidechain_height != 0
                    && entry.observed_sidechain_height < last_sidechain_height)
                || (last_parent_height != 0 && entry.observed_parent_height < last_parent_height)
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

#[cfg(test)]
mod tests {
    use secp256k1::SecretKey;

    use super::*;
    use crate::availability::{
        AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD,
        MAX_AVAILABILITY_WITNESS_BYTES,
    };
    use crate::bond_inbox_v2::BOND_INBOX_MARKER_LEN;
    use crate::order::Signature64;
    use crate::successor_bond_action_v2::{
        SuccessorBondSubscriptionV2, SuccessorSignedBondSubscriptionV2,
    };

    fn availability() -> AvailabilityConfigV1 {
        AvailabilityConfigV1 {
            version: AvailabilityConfigV1::VERSION,
            scheme_hash: [10; 32],
            custodian_registry_hash: [11; 32],
            recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
            custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
            maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
        }
    }

    fn action() -> SuccessorBondInboxUserActionV2 {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        let (trader, _) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        SuccessorBondInboxUserActionV2::Subscription(
            SuccessorSignedBondSubscriptionV2::sign(
                SuccessorBondSubscriptionV2 {
                    version: SuccessorBondSubscriptionV2::VERSION,
                    chain_id: [1; 32],
                    configuration_hash: [2; 32],
                    trader: XOnlyKey(trader.serialize()),
                    account_nonce: (1u128 << 96) + 3,
                    contribution_usdd_atoms: 10,
                    issued_share_atoms: 10,
                    bond_recipient_script_sha256: [3; 32],
                    usdd_output_opening_commitment: [4; 32],
                    bond_output_opening_commitment: [5; 32],
                },
                &secret,
            )
            .unwrap(),
        )
    }

    fn marker(
        action: &SuccessorBondInboxUserActionV2,
        marker_vout: u32,
    ) -> SuccessorBondInboxMarkerV2 {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let source_authorization_commitment =
            successor_bond_inbox_no_staging_source_authorization_commitment_v2(
                [1; 32],
                [2; 32],
                action.signer(),
                action.action_id(),
                marker_vout,
            )
            .unwrap();
        let payload = SuccessorBondInboxAvailablePayloadV2 {
            commitment_blinding: [8; 32],
            canonical_signed_action: action.canonical_signed_bytes(),
            settlement_witness_commitment: action.settlement_witness_commitment(),
            source_authorization_commitment,
        };
        let mut marker = SuccessorBondInboxMarkerV2 {
            version: SuccessorBondInboxMarkerV2::VERSION,
            kind: action.kind(),
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            signer: action.signer(),
            action_id: action.action_id(),
            staging_intent_id: [0; 32],
            staging_vout: u32::MAX,
            refund_script_sha256: [0; 32],
            refund_not_before_parent_height: 0,
            payload_commitment: SuccessorBondInboxAvailablePayloadV2::commitment(
                action.kind(),
                payload.commitment_blinding,
                &payload.canonical_signed_action,
                payload.settlement_witness_commitment,
                source_authorization_commitment,
            ),
            availability_scheme_hash: [10; 32],
            availability_custodian_registry_hash: [11; 32],
            availability_bundle_root: [12; 32],
            availability_context: [0; 32],
            availability_receipt_root: [13; 32],
            availability_bundle_len: 800,
            availability_receipt_bitmap: 0b00111,
            source_authorization_commitment,
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        marker.sign(&secret).unwrap()
    }

    fn entry(index: u128, previous_root: Hash32) -> SuccessorBondInboxEntryV2 {
        let action = action();
        SuccessorBondInboxEntryV2 {
            version: SuccessorBondInboxEntryV2::VERSION,
            index,
            previous_root,
            observed_sidechain_height: 9,
            observed_parent_height: 100,
            source_block_hash: [20; 32],
            source_txid: [21; 32],
            source_wtxid: [22; 32],
            source_transaction_len: 1_000,
            source_witness_sha256: [23; 32],
            source_witness_len: 900,
            source_tx_index: 1,
            marker_vout: 0,
            marker: marker(&action, 0),
        }
    }

    fn limits() -> BondInboxLimitsV2 {
        BondInboxLimitsV2 {
            inbox_domain: [30; 32],
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

    #[test]
    fn successor_inbox_preserves_high_u128_index_and_rejects_v18_width() {
        let high = (1u128 << 96) + 7;
        let entry = entry(high, [31; 32]);
        assert_eq!(entry.canonical_bytes().len(), BOND_INBOX_MARKER_LEN + 205);
        assert_eq!(&entry.canonical_bytes()[1..17], &high.to_be_bytes());
        assert_ne!(
            entry.entry_hash(),
            canonical_hash("ECX/bond-inbox-entry/v2", &entry)
        );
        let state = SuccessorBondInboxStateV2 {
            head_root: [1; 32],
            entry_count: high,
            processed_root: [2; 32],
            cursor: high - 1,
        };
        state.validate().unwrap();
        assert_eq!(state.canonical_bytes().len(), 96);
    }

    #[test]
    fn successor_inbox_transition_consumes_high_u128_expiry_exactly() {
        let high = (1u128 << 96) + 7;
        let pending = entry(high, [31; 32]);
        let previous = SuccessorBondInboxStateV2 {
            head_root: pending.previous_root,
            entry_count: high,
            processed_root: pending.previous_root,
            cursor: high,
        };
        let next = SuccessorBondInboxStateV2 {
            head_root: pending.next_root(),
            entry_count: high + 1,
            processed_root: pending.next_root(),
            cursor: high + 1,
        };
        let transition = SuccessorBondInboxTransitionV2 {
            pending_entries: vec![pending],
            consumed_evidence: vec![SuccessorBondInboxConsumedEvidenceV2::ExpiredUnavailable {
                source_entry_hash: pending.entry_hash(),
            }],
        };
        let outcomes = transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                106,
                10,
                availability(),
                limits(),
            )
            .unwrap();
        assert_eq!(outcomes[0].entry_index, high);
        assert_eq!(
            outcomes[0].disposition,
            SuccessorBondInboxConsumedDispositionV2::ExpiredUnavailable
        );
        assert!(transition
            .verify(
                [1; 32],
                [2; 32],
                previous,
                next,
                105,
                10,
                availability(),
                limits(),
            )
            .is_err());
    }
}
