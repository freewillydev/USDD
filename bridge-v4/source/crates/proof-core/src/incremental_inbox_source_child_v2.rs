//! Recursive child statement for authenticated bond-inbox source recovery.
//!
//! The child reuses the production source-transaction, custody-receipt,
//! threshold-recovery, payload-decoding, and inbox-state relation. It exposes
//! only roots and counters; recovered signed actions remain private.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    BondInboxActionKindV2, BondInboxLimitsV2, FrozenConfigurationV2, Hash32, ProtocolError,
    SuccessorBondInboxConsumedDispositionV2, SuccessorBondInboxConsumedEvidenceV2,
    SuccessorBondInboxConsumedOutcomeV2, SuccessorBondInboxStateV2, SuccessorBondInboxTransitionV2,
    MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
    MAX_TRANSITION_ACTIONS,
};
use ecx_truthcoin_proof::{
    sp1_deferred_proof_marker, ConsensusProofVerificationError, ConsensusProofVerifier,
    DenyAllConsensusProofs,
};
use ecx_witness_availability::{
    custodian_registry_hash, verify_custody_receipts_compact, CustodianPublic, CustodyReceiptV1,
    RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::proof_v2::{
    recover_successor_bond_inbox_entry_from_compact_evidence_v2,
    SuccessorBondInboxEntryRecoveryEvidenceV2,
};
use crate::{
    decode_incremental_source_transaction_child_projection_v2,
    incremental_staging_source_projection_root_v2, IncrementalCustodianPublicV2,
    IncrementalSourceTransactionChildErrorV2, ProofErrorV2,
    INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2,
};

pub const INCREMENTAL_INBOX_SOURCE_CHILD_VERSION_V2: u8 = 2;
pub const INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 2;
pub const INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (10 * 32) + (5 * 16) + (2 * 8);
pub const MAX_INCREMENTAL_INBOX_SOURCE_ENTRY_AUXILIARY_BYTES_V2: usize = 16 * 1024;
pub const INCREMENTAL_INBOX_SOURCE_COMPACT_REACHABLE_CEILING_V2: usize = (MAX_TRANSITION_ACTIONS
    as usize
    * (MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        + MAX_INCREMENTAL_INBOX_SOURCE_ENTRY_AUXILIARY_BYTES_V2))
    + (64 * 1024);
pub const MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2: usize = 8 * 1024 * 1024;
const _: () = assert!(
    INCREMENTAL_INBOX_SOURCE_COMPACT_REACHABLE_CEILING_V2
        < MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2
);
/// The successor source cap is per sidechain block while action expiry is measured
/// in parent heights. Sixty-four distinct sidechain blocks can therefore each
/// contribute one maximum-size still-processable source transaction at the
/// same parent height. The current raw-transaction child cannot prove a
/// universal 16 MiB recovery bound for that reachable case.
pub const SUCCESSOR_REACHABLE_INBOX_SOURCE_TRANSACTION_BYTES_V2: usize =
    MAX_TRANSITION_ACTIONS as usize * MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2 as usize;
const _: () = assert!(
    SUCCESSOR_REACHABLE_INBOX_SOURCE_TRANSACTION_BYTES_V2
        > MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSourceTransactionReceiptV2 {
    pub program_id: Hash32,
    pub public_values: Vec<u8>,
    pub proof_marker: Hash32,
    pub bundle_root: Hash32,
    pub bundle_context: Hash32,
    pub child_witness_len: u64,
    pub custody_receipts: Vec<CustodyReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalInboxSourceReceiptEvidenceV2 {
    pub source_wtxid: Hash32,
    pub source_receipt: IncrementalSourceTransactionReceiptV2,
    pub entry: SuccessorBondInboxEntryRecoveryEvidenceV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalInboxSourceChildInputV2 {
    pub version: u8,
    pub configuration: FrozenConfigurationV2,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub previous_state: SuccessorBondInboxStateV2,
    pub next_state: SuccessorBondInboxStateV2,
    pub parent_height: u64,
    pub transition_sidechain_height: u64,
    pub transition: SuccessorBondInboxTransitionV2,
    pub source_transaction_program_id: Hash32,
    pub source_transaction_custodians: Vec<IncrementalCustodianPublicV2>,
    pub source_evidence: Vec<IncrementalInboxSourceReceiptEvidenceV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalInboxSourceChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub previous_state_hash: Hash32,
    pub next_state_hash: Hash32,
    pub previous_head_root: Hash32,
    pub previous_processed_root: Hash32,
    pub next_head_root: Hash32,
    pub next_processed_root: Hash32,
    pub recovered_candidate_root: Hash32,
    pub staging_source_projection_root: Hash32,
    pub previous_entry_count: u128,
    pub previous_cursor: u128,
    pub next_entry_count: u128,
    pub next_cursor: u128,
    pub parent_height: u64,
    pub transition_sidechain_height: u64,
    pub consumed_count: u128,
}

impl IncrementalInboxSourceChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for value in [
            self.configuration_hash,
            self.chain_id,
            self.previous_state_hash,
            self.next_state_hash,
            self.previous_head_root,
            self.previous_processed_root,
            self.next_head_root,
            self.next_processed_root,
            self.recovered_candidate_root,
            self.staging_source_projection_root,
        ] {
            out.extend_from_slice(&value);
        }
        for value in [
            self.previous_entry_count,
            self.previous_cursor,
            self.next_entry_count,
            self.next_cursor,
            self.consumed_count,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.parent_height.to_be_bytes());
        out.extend_from_slice(&self.transition_sidechain_height.to_be_bytes());
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalInboxSourceChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub previous_state_hash: Hash32,
    pub next_state_hash: Hash32,
    pub next_head_root: Hash32,
    pub next_processed_root: Hash32,
    pub next_entry_count: u128,
    pub next_cursor: u128,
    pub recovered_candidate_root: Hash32,
    pub staging_source_projection_root: Hash32,
    pub parent_height: u64,
    pub transition_sidechain_height: u64,
}

pub fn decode_incremental_inbox_source_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalInboxSourceChildProjectionV2, IncrementalInboxSourceChildErrorV2> {
    if bytes.len() != INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalInboxSourceChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalInboxSourceChildErrorV2> {
        let start = 4 + (index * 32);
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalInboxSourceChildErrorV2::UnsupportedVersion)
    };
    let value = |index: usize| -> Result<u64, IncrementalInboxSourceChildErrorV2> {
        let start = 4 + (10 * 32) + (5 * 16) + (index * 8);
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalInboxSourceChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let wide = |index: usize| -> Result<u128, IncrementalInboxSourceChildErrorV2> {
        let start = 4 + (10 * 32) + (index * 16);
        Ok(u128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalInboxSourceChildErrorV2::UnsupportedVersion)?,
        ))
    };
    Ok(IncrementalInboxSourceChildProjectionV2 {
        configuration_hash: hash(0)?,
        chain_id: hash(1)?,
        previous_state_hash: hash(2)?,
        next_state_hash: hash(3)?,
        next_head_root: hash(6)?,
        next_processed_root: hash(7)?,
        next_entry_count: wide(2)?,
        next_cursor: wide(3)?,
        recovered_candidate_root: hash(8)?,
        staging_source_projection_root: hash(9)?,
        parent_height: value(0)?,
        transition_sidechain_height: value(1)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalInboxSourceChildErrorV2 {
    #[error("unsupported incremental inbox source child version")]
    UnsupportedVersion,
    #[error("invalid incremental inbox source child binding")]
    InvalidBinding,
    #[error("incremental inbox source child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental inbox source child input encoding failed")]
    InputEncoding,
    #[error("bond inbox source authentication rejected: {0}")]
    Source(#[from] ProofErrorV2),
    #[error("source transaction receipt projection rejected: {0}")]
    SourceProjection(#[from] IncrementalSourceTransactionChildErrorV2),
    #[error("source transaction recursive proof was rejected")]
    SourceProof,
    #[error("bond inbox state transition rejected: {0}")]
    Transition(#[from] ProtocolError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_source_transaction_bundle_context_v2(
    program_id: Hash32,
    public_values: &[u8],
    proof_marker: Hash32,
    registry_hash: Hash32,
) -> Result<Hash32, IncrementalInboxSourceChildErrorV2> {
    if program_id == [0; 32]
        || public_values.len() != INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || proof_marker != sp1_deferred_proof_marker(program_id, public_values)
        || registry_hash == [0; 32]
    {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let mut bytes = Vec::with_capacity(101 + public_values.len());
    bytes.push(INCREMENTAL_INBOX_SOURCE_CHILD_VERSION_V2);
    bytes.extend_from_slice(&program_id);
    bytes.extend_from_slice(&(public_values.len() as u32).to_be_bytes());
    bytes.extend_from_slice(public_values);
    bytes.extend_from_slice(&proof_marker);
    bytes.extend_from_slice(&registry_hash);
    Ok(tagged_hash(
        b"ECX/incremental-source-transaction-bundle-context/v2-u128-inbox",
        &bytes,
    ))
}

fn state_hash(state: SuccessorBondInboxStateV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-inbox-source-child-state/v2-u128-inbox",
        &state.canonical_bytes(),
    )
}

pub fn successor_recovered_candidate_root_v2(
    configuration_hash: Hash32,
    chain_id: Hash32,
    outcomes: &[SuccessorBondInboxConsumedOutcomeV2],
) -> Result<Hash32, IncrementalInboxSourceChildErrorV2> {
    if configuration_hash == [0; 32] || chain_id == [0; 32] {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let mut genesis = Vec::with_capacity(64);
    genesis.extend_from_slice(&configuration_hash);
    genesis.extend_from_slice(&chain_id);
    let mut root = tagged_hash(
        b"ECX/incremental-inbox-recovered-candidates-genesis/v2-u128-inbox",
        &genesis,
    );
    for outcome in outcomes {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&root);
        bytes.extend_from_slice(&outcome.entry_index.to_be_bytes());
        bytes.extend_from_slice(&outcome.entry_hash);
        bytes.push(outcome.marker_kind as u8);
        bytes.extend_from_slice(&outcome.marker_action_id);
        bytes.extend_from_slice(&outcome.source_parent_height.to_be_bytes());
        match &outcome.disposition {
            SuccessorBondInboxConsumedDispositionV2::Action(Ok(action)) => {
                bytes.push(0);
                let action_bytes = action.canonical_signed_bytes();
                bytes.extend_from_slice(
                    &u32::try_from(action_bytes.len())
                        .map_err(|_| IncrementalInboxSourceChildErrorV2::InvalidBinding)?
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(&action_bytes);
            }
            SuccessorBondInboxConsumedDispositionV2::Action(Err(rejection)) => {
                bytes.push(1);
                bytes.extend_from_slice(&rejection.canonical_bytes());
            }
            SuccessorBondInboxConsumedDispositionV2::ExpiredUnavailable => bytes.push(2),
        }
        root = tagged_hash(
            b"ECX/incremental-inbox-recovered-candidates-step/v2-u128-inbox",
            &bytes,
        );
    }
    Ok(root)
}

fn limits(configuration: &FrozenConfigurationV2) -> BondInboxLimitsV2 {
    BondInboxLimitsV2 {
        inbox_domain: configuration.bond_inbox_domain,
        inclusion_blocks: configuration.bond_inbox_inclusion_blocks,
        refund_minimum_parent_blocks: configuration.bond_inbox_refund_minimum_parent_blocks,
        maximum_bundle_bytes: configuration.bond_inbox_max_bundle_bytes,
        maximum_entries_per_sidechain_block: configuration
            .bond_inbox_max_entries_per_sidechain_block,
        maximum_unique_source_witness_bytes_per_sidechain_block: configuration
            .bond_inbox_max_unique_source_witness_bytes_per_sidechain_block,
        maximum_unique_source_transaction_bytes_per_sidechain_block: configuration
            .bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block,
        maximum_pending_entries_per_transition: configuration
            .bond_inbox_max_pending_entries_per_transition,
        maximum_consumed_entries_per_transition: configuration
            .bond_inbox_max_consumed_entries_per_transition,
    }
}

pub fn execute_incremental_inbox_source_child_v2(
    input: &IncrementalInboxSourceChildInputV2,
) -> Result<IncrementalInboxSourceChildPublicValuesV2, IncrementalInboxSourceChildErrorV2> {
    execute_incremental_inbox_source_child_v2_with_consensus_verifier(
        input,
        &DenyAllConsensusProofs,
    )
}

pub fn execute_incremental_inbox_source_child_v2_with_consensus_verifier<
    V: ConsensusProofVerifier,
>(
    input: &IncrementalInboxSourceChildInputV2,
    verifier: &V,
) -> Result<IncrementalInboxSourceChildPublicValuesV2, IncrementalInboxSourceChildErrorV2> {
    if input.version != INCREMENTAL_INBOX_SOURCE_CHILD_VERSION_V2 {
        return Err(IncrementalInboxSourceChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.chain_id == [0; 32]
        || input.configuration_hash != input.configuration.digest()
        || input.source_transaction_program_id == [0; 32]
        || input.parent_height == 0
        || input.transition_sidechain_height == 0
    {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalInboxSourceChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalInboxSourceChildErrorV2::InputTooLarge);
    }
    let consumed_count = input.transition.consumed_evidence.len();
    if input.transition.pending_entries.len() < consumed_count {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let required = input
        .transition
        .pending_entries
        .iter()
        .take(consumed_count)
        .zip(&input.transition.consumed_evidence)
        .filter(|(_, evidence)| {
            !matches!(
                evidence,
                SuccessorBondInboxConsumedEvidenceV2::ExpiredUnavailable { .. }
            )
        })
        .map(|(entry, evidence)| (entry.index, (entry, evidence)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let source_custodians = input
        .source_transaction_custodians
        .iter()
        .copied()
        .map(CustodianPublic::from)
        .collect::<Vec<_>>();
    if custodian_registry_hash(&source_custodians)
        .map_err(|_| IncrementalInboxSourceChildErrorV2::InvalidBinding)?
        != input
            .configuration
            .base
            .availability
            .custodian_registry_hash
    {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    if input.source_evidence.len() != required.len() {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let mut previous_wtxid = None;
    let mut seen_entries = std::collections::BTreeSet::new();
    let mut staging_source_public_values = Vec::new();
    for source in &input.source_evidence {
        if source.source_wtxid == [0; 32]
            || previous_wtxid.is_some_and(|prior| prior >= source.source_wtxid)
            || !seen_entries.insert(source.entry.entry_index)
            || source.source_receipt.program_id != input.source_transaction_program_id
            || source.source_receipt.public_values.len()
                != INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
            || source.source_receipt.proof_marker
                != sp1_deferred_proof_marker(
                    source.source_receipt.program_id,
                    &source.source_receipt.public_values,
                )
            || source.source_receipt.custody_receipts.len() != RECOVERY_THRESHOLD
        {
            return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
        }
        previous_wtxid = Some(source.source_wtxid);
        verifier
            .verify(
                source.source_receipt.program_id,
                &source.source_receipt.public_values,
                &source.source_receipt.proof_marker,
            )
            .map_err(|_: ConsensusProofVerificationError| {
                IncrementalInboxSourceChildErrorV2::SourceProof
            })?;
        let expected_bundle_context = incremental_source_transaction_bundle_context_v2(
            source.source_receipt.program_id,
            &source.source_receipt.public_values,
            source.source_receipt.proof_marker,
            input
                .configuration
                .base
                .availability
                .custodian_registry_hash,
        )?;
        if source.source_receipt.bundle_context != expected_bundle_context {
            return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
        }
        verify_custody_receipts_compact(
            source.source_receipt.bundle_root,
            source.source_receipt.bundle_context,
            source.source_receipt.child_witness_len,
            &source_custodians,
            &source.source_receipt.custody_receipts,
        )
        .map_err(|_| IncrementalInboxSourceChildErrorV2::InvalidBinding)?;
        let projection = decode_incremental_source_transaction_child_projection_v2(
            &source.source_receipt.public_values,
        )?;
        let (entry, expected_evidence) = required
            .get(&source.entry.entry_index)
            .ok_or(IncrementalInboxSourceChildErrorV2::InvalidBinding)?;
        if projection.configuration_hash != input.configuration_hash
            || projection.chain_id != input.chain_id
            || projection.entry_hash != entry.entry_hash()
            || projection.txid != entry.source_txid
            || projection.wtxid != entry.source_wtxid
            || projection.wtxid != source.source_wtxid
            || projection.exact_witness_sha256 != entry.source_witness_sha256
            || projection.availability_bundle_root != entry.marker.availability_bundle_root
            || projection.availability_receipt_root != entry.marker.availability_receipt_root
            || projection.source_transaction_len != entry.source_transaction_len
            || projection.availability_bundle_len != entry.marker.availability_bundle_len
            || projection.staging_present
                != (entry.marker.kind == BondInboxActionKindV2::RedemptionEnqueue)
            || (projection.staging_present && projection.staging_vout != entry.marker.staging_vout)
        {
            return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
        }
        if projection.staging_present {
            staging_source_public_values.push(source.source_receipt.public_values.clone());
        }
        let reconstructed = recover_successor_bond_inbox_entry_from_compact_evidence_v2(
            &input.configuration,
            entry,
            &source.entry,
        )?;
        if &reconstructed != *expected_evidence {
            return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
        }
    }
    if seen_entries.len() != required.len() {
        return Err(IncrementalInboxSourceChildErrorV2::InvalidBinding);
    }
    let outcomes = input.transition.verify(
        input.chain_id,
        input.configuration_hash,
        input.previous_state,
        input.next_state,
        input.parent_height,
        input.transition_sidechain_height,
        input.configuration.base.availability,
        limits(&input.configuration),
    )?;
    Ok(IncrementalInboxSourceChildPublicValuesV2 {
        configuration_hash: input.configuration_hash,
        chain_id: input.chain_id,
        previous_state_hash: state_hash(input.previous_state),
        next_state_hash: state_hash(input.next_state),
        previous_head_root: input.previous_state.head_root,
        previous_processed_root: input.previous_state.processed_root,
        next_head_root: input.next_state.head_root,
        next_processed_root: input.next_state.processed_root,
        recovered_candidate_root: successor_recovered_candidate_root_v2(
            input.configuration_hash,
            input.chain_id,
            &outcomes,
        )?,
        staging_source_projection_root: incremental_staging_source_projection_root_v2(
            &staging_source_public_values,
        )?,
        previous_entry_count: input.previous_state.entry_count,
        previous_cursor: input.previous_state.cursor,
        next_entry_count: input.next_state.entry_count,
        next_cursor: input.next_state.cursor,
        parent_height: input.parent_height,
        transition_sidechain_height: input.transition_sidechain_height,
        consumed_count: u128::try_from(outcomes.len())
            .map_err(|_| IncrementalInboxSourceChildErrorV2::InvalidBinding)?,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        BondInboxActionKindV2, BondInboxRejectionV2, SuccessorBondInboxConsumedDispositionV2,
        SuccessorBondInboxConsumedOutcomeV2,
    };

    use super::*;

    #[test]
    fn candidate_root_binds_order_source_and_disposition_without_disclosing_action() {
        let rejected = SuccessorBondInboxConsumedOutcomeV2 {
            entry_index: (1u128 << 80) + 7,
            entry_hash: [3; 32],
            marker_kind: BondInboxActionKindV2::Subscription,
            marker_action_id: [4; 32],
            source_parent_height: 90,
            disposition: SuccessorBondInboxConsumedDispositionV2::Action(Err(
                BondInboxRejectionV2::MalformedOrInvalidAction,
            )),
        };
        let expired = SuccessorBondInboxConsumedOutcomeV2 {
            entry_index: (1u128 << 80) + 8,
            entry_hash: [5; 32],
            marker_kind: BondInboxActionKindV2::RedemptionEnqueue,
            marker_action_id: [6; 32],
            source_parent_height: 91,
            disposition: SuccessorBondInboxConsumedDispositionV2::ExpiredUnavailable,
        };
        let root = successor_recovered_candidate_root_v2(
            [1; 32],
            [2; 32],
            &[rejected.clone(), expired.clone()],
        )
        .unwrap();
        assert_ne!(root, [0; 32]);
        assert_ne!(
            root,
            successor_recovered_candidate_root_v2([1; 32], [2; 32], &[expired, rejected.clone()],)
                .unwrap()
        );
        let mut mutated = rejected;
        mutated.source_parent_height += 1;
        assert_ne!(
            root,
            successor_recovered_candidate_root_v2([1; 32], [2; 32], &[mutated]).unwrap()
        );
    }

    #[test]
    fn inbox_source_public_values_layout_is_exact() {
        let values = IncrementalInboxSourceChildPublicValuesV2 {
            configuration_hash: [1; 32],
            chain_id: [2; 32],
            previous_state_hash: [3; 32],
            next_state_hash: [4; 32],
            previous_head_root: [5; 32],
            previous_processed_root: [6; 32],
            next_head_root: [7; 32],
            next_processed_root: [8; 32],
            recovered_candidate_root: [9; 32],
            staging_source_projection_root: [17; 32],
            previous_entry_count: 10,
            previous_cursor: 11,
            next_entry_count: 12,
            next_cursor: 13,
            parent_height: 14,
            transition_sidechain_height: 15,
            consumed_count: 16,
        };
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        );
        assert_eq!(&encoded[..4], &2u32.to_be_bytes());
        assert_eq!(encoded[4], 1);
        assert_eq!(
            &encoded[encoded.len() - 16..encoded.len() - 8],
            &14u64.to_be_bytes()
        );
        assert_eq!(&encoded[encoded.len() - 8..], &15u64.to_be_bytes());
        let projection = decode_incremental_inbox_source_child_projection_v2(&encoded).unwrap();
        assert_eq!(projection.configuration_hash, [1; 32]);
        assert_eq!(projection.chain_id, [2; 32]);
        assert_eq!(projection.previous_state_hash, [3; 32]);
        assert_eq!(projection.next_state_hash, [4; 32]);
        assert_eq!(projection.recovered_candidate_root, [9; 32]);
        assert_eq!(projection.staging_source_projection_root, [17; 32]);
        assert_eq!(projection.parent_height, 14);
        assert_eq!(projection.transition_sidechain_height, 15);
    }

    #[test]
    fn per_sidechain_block_source_cap_does_not_imply_parent_window_recovery_bound() {
        assert_eq!(
            SUCCESSOR_REACHABLE_INBOX_SOURCE_TRANSACTION_BYTES_V2,
            50_331_648
        );
    }
}
