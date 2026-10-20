//! Complete additive statement for the insurance-bond transition program.
//!
//! This module intentionally does not call the V1 proof entry point. V2 has a
//! different private state, unified two-asset settlement and three recursive
//! consensus receipts. Reusing only the protocol V2 verifier keeps the frozen
//! V1 guest and its public values byte-for-byte unchanged.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_elements_settlement::{
    logical_allocation_commitment_v2, verify_bond_inbox_source_transaction_v2,
    verify_confidential_deposit, verify_transition_settlement_v2, BondInputOpeningV2,
    BondInputRoleV2, BondOutputOpeningV2, BondOutputRoleV2, BondSettlementActionV2,
    CollateralInputOpeningV2, CollateralOutputOpeningV2, CollateralOutputRoleV2,
    ConfidentialDepositOpeningV1, FrozenBondAssetV2, LogicalAllocationKindV2, SettlementError,
    TransitionSettlementV2,
};
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    bond_action_root_v2, bond_inbox_aead_failure_plaintext_sentinel_v2,
    bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2,
    bond_inbox_recovered_plaintext_sha256_v2, central_matcher_receipt_batch_root,
    matcher_cancel_command_hash, matcher_order_command_hash, order_risk_root_v2,
    successor_bond_inbox_aead_failure_plaintext_sentinel_v2,
    successor_bond_inbox_authenticated_failure_commitment_v2,
    successor_bond_inbox_recovered_plaintext_sha256_v2, tagged_hash, transition_withdrawals,
    verify_bond_inbox_source_witness_commitments_v2, verify_central_matcher_receipt_chain,
    verify_matcher_execution_receipt_batch_v2,
    verify_successor_bond_inbox_source_witness_commitments_v2, verify_transition_v2,
    BondInboxAuthenticatedRecoveryOrPayloadFailureV2, BondInboxAvailablePayloadV2,
    BondInboxConsumedEvidenceV2, BondInboxCustodyReceiptV2, BondInboxProcessedDispositionV2,
    BondInboxRecoveryFailureV2, BondInboxRedemptionStagingRendererInputV2, BondPublicStateV2,
    CentralMatcherReceiptV1, FrozenConfigurationV2, Hash32, MatchedOrderPair, MatcherCommandKind,
    MatcherExecutionReceiptV2, MatcherExecutionRelationV2, OracleMode, OrderFlags, ProtocolError,
    RedemptionQueueEntryV2, SuccessorBondInboxAuthenticatedFailureV2,
    SuccessorBondInboxAvailablePayloadV2, SuccessorBondInboxConsumedEvidenceV2,
    SuccessorBondInboxEntryV2, TransitionJournalV2, TransitionWitness, TransitionWitnessV2,
    AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD, AVAILABILITY_SCHEME_HASH_V1,
    MAX_AVAILABILITY_WITNESS_BYTES, MAX_TRANSITION_ACTIONS,
};
use ecx_truthcoin_proof::{
    verify_authenticated_hybrid_quote, AuthenticationError, ConsensusProofVerifier,
    DenyAllConsensusProofs, ParentChainContextV1, TruthcoinConsensusProofV1,
};
use ecx_witness_availability::{
    availability_scheme_hash, custodian_registry_hash, custody_receipt_codec_hash_v1,
    recover_witness, recovery_certificate_root_v1, verify_bundle_encryption,
    verify_custody_receipts, verify_recovery_certificate, AvailabilityEncryptionWitnessV1,
    AvailabilityError, CustodianPublic, CustodyReceiptV1, RecoveryContribution, WitnessBundle,
    CUSTODIAN_COUNT, MAX_BUNDLE_BYTES, MAX_WITNESS_BYTES, RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    derive_authenticated_price_range_v2, derive_direct_native_truthcoin_price_range_v2,
    verify_authenticated_conversion_legs_v2, verify_funding_parent_chain_v2,
    ConversionLegConsensusProofV2, ConversionLegErrorV2, FundingParentChainErrorV2,
    FundingParentChainWitnessV2,
};

pub const PROOF_BINDING_VERSION_V2: u8 = 5;
pub const COVENANT_STATE_VERSION_V2: u32 = 4;
pub const AVAILABILITY_RECOVERY_PAYLOAD_VERSION_V2: u8 = 6;
pub const MAX_PROOF_INPUT_BYTES_V2: usize = 192 * 1024 * 1024;
pub const PUBLIC_VALUES_V5_LEN: usize = 850;
/// Partition the 16 MiB encrypted recovery envelope so the maximum valid bond
/// inbox table cannot crowd out the remainder of the transition witness.
pub const MAX_BOND_INBOX_RECOVERY_TABLE_BYTES_V2: usize = 5 * 1024 * 1024;
pub const MAX_NON_BOND_INBOX_RECOVERY_PAYLOAD_BYTES_V2: usize = 10 * 1024 * 1024;
const PUBLIC_VALUES_V5_VERSION: u32 = 5;

/// Guest-side encoder. `zkvm/interface::PublicValuesV5` is the intentionally
/// independent consensus-side encoder for the same frozen 850-byte V5 layout.
struct ProofPublicValuesV5 {
    transition_journal_domain_sha256: Hash32,
    configuration_hash: Hash32,
    current_state_hash: Hash32,
    next_state_hash: Hash32,
    transition_txid_consensus: Hash32,
    prior_exchange_header_root: Hash32,
    prior_parent_block_hash: Hash32,
    prior_parent_height: u64,
    prior_parent_mtp: u64,
    transition_journal_hash: Hash32,
    bond_asset_id: Hash32,
    bond_deployment_commitment: Hash32,
    bond_state_root: Hash32,
    redemption_queue_root: Hash32,
    funding_state_root: Hash32,
    conversion_legs_commitment: Hash32,
    insurance_reserve: u128,
    outstanding_share_atoms: u64,
    nav_per_whole_share_usdd_atoms: u128,
    full_bound_deficit: u128,
    target_reserve: u128,
    coverage_bps: u128,
    capital_mode: u8,
    authenticated_min_price: u64,
    authenticated_max_price: u64,
    funding_epoch: u64,
    funding_rate_ppm: i32,
    redemption_head: u64,
    redemption_tail: u64,
    queued_redemption_share_atoms: u64,
    oracle_certificate_hash: Hash32,
    oracle_valid_through_mtp: u64,
    oracle_mode: u8,
    next_encrypted_availability_root: Hash32,
    bond_inbox_head_root: Hash32,
    bond_inbox_entry_count: u64,
    bond_inbox_processed_root: Hash32,
    bond_inbox_cursor: u64,
    bond_inbox_outcome_root: Hash32,
    bond_inbox_outcome_count: u64,
    matcher_execution_receipt_batch_root: Hash32,
    previous_matcher_execution_sequence: u64,
    next_matcher_execution_sequence: u64,
}

impl ProofPublicValuesV5 {
    fn encode(&self) -> [u8; PUBLIC_VALUES_V5_LEN] {
        let mut output = [0u8; PUBLIC_VALUES_V5_LEN];
        let mut cursor = 0usize;
        macro_rules! put {
            ($bytes:expr) => {{
                let bytes = $bytes;
                let end = cursor + bytes.len();
                output[cursor..end].copy_from_slice(bytes);
                cursor = end;
            }};
        }
        put!(&self.transition_journal_domain_sha256);
        put!(&PUBLIC_VALUES_V5_VERSION.to_be_bytes());
        put!(&self.configuration_hash);
        put!(&self.current_state_hash);
        put!(&self.next_state_hash);
        put!(&self.transition_txid_consensus);
        put!(&self.prior_exchange_header_root);
        put!(&self.prior_parent_block_hash);
        put!(&self.prior_parent_height.to_be_bytes());
        put!(&self.prior_parent_mtp.to_be_bytes());
        put!(&self.transition_journal_hash);
        put!(&self.bond_asset_id);
        put!(&self.bond_deployment_commitment);
        put!(&self.bond_state_root);
        put!(&self.redemption_queue_root);
        put!(&self.funding_state_root);
        put!(&self.conversion_legs_commitment);
        put!(&self.insurance_reserve.to_be_bytes());
        put!(&self.outstanding_share_atoms.to_be_bytes());
        put!(&self.nav_per_whole_share_usdd_atoms.to_be_bytes());
        put!(&self.full_bound_deficit.to_be_bytes());
        put!(&self.target_reserve.to_be_bytes());
        put!(&self.coverage_bps.to_be_bytes());
        put!(&[self.capital_mode]);
        put!(&self.authenticated_min_price.to_be_bytes());
        put!(&self.authenticated_max_price.to_be_bytes());
        put!(&self.funding_epoch.to_be_bytes());
        put!(&self.funding_rate_ppm.to_be_bytes());
        put!(&self.redemption_head.to_be_bytes());
        put!(&self.redemption_tail.to_be_bytes());
        put!(&self.queued_redemption_share_atoms.to_be_bytes());
        put!(&self.oracle_certificate_hash);
        put!(&self.oracle_valid_through_mtp.to_be_bytes());
        put!(&[self.oracle_mode]);
        put!(&self.next_encrypted_availability_root);
        put!(&self.bond_inbox_head_root);
        put!(&self.bond_inbox_entry_count.to_be_bytes());
        put!(&self.bond_inbox_processed_root);
        put!(&self.bond_inbox_cursor.to_be_bytes());
        put!(&self.bond_inbox_outcome_root);
        put!(&self.bond_inbox_outcome_count.to_be_bytes());
        put!(&self.matcher_execution_receipt_batch_root);
        put!(&self.previous_matcher_execution_sequence.to_be_bytes());
        put!(&self.next_matcher_execution_sequence.to_be_bytes());
        debug_assert_eq!(cursor, PUBLIC_VALUES_V5_LEN);
        output
    }

    fn sha256(&self) -> Hash32 {
        sha256(&self.encode())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantPublicStateV2 {
    pub version: u32,
    pub sequence: u64,
    pub private_state_root: Hash32,
    pub encrypted_availability_root: Hash32,
    pub forced_action_inbox_root: Hash32,
    pub deposit_inbox_root: Hash32,
    pub configuration_hash: Hash32,
    pub bond_state_root: Hash32,
    pub funding_state_root: Hash32,
    pub active_order_risk_root: Hash32,
    pub position_risk_root: Hash32,
    pub bond_inbox_head_root: Hash32,
    pub bond_inbox_entry_count: u64,
    pub bond_inbox_processed_root: Hash32,
    pub bond_inbox_cursor: u64,
    pub bond_inbox_outcome_root: Hash32,
    pub bond_inbox_outcome_count: u64,
    pub matcher_execution_sequence: u64,
    pub last_transition_sidechain_height: u64,
}

impl CovenantPublicStateV2 {
    /// Derive pristine public state from the same canonical empty-state
    /// constructor used by the node-facing materializer. This does not prove
    /// deployment, authenticated time or transaction membership.
    pub fn derive_empty_genesis(
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        height: u64, parent_mtp: u64, mark: u64,
        order_receipts_root: Hash32, availability_root: Hash32,
    ) -> Result<Self, String> {
        if availability_root == [0;32] { return Err("zero genesis availability root".into()); }
        let state = ecx_protocol_core::genesis_v2::derive_empty_genesis_v2(
            configuration, height, parent_mtp, mark, order_receipts_root)?;
        Ok(Self {
            version: COVENANT_STATE_VERSION_V2, sequence: 0,
            private_state_root: state.state_root(), encrypted_availability_root: availability_root,
            forced_action_inbox_root: state.base.forced_inbox.head_root,
            deposit_inbox_root: state.base.deposit_inbox.head_root,
            configuration_hash: configuration.digest(),
            bond_state_root: bond_public_state_root_v2(&state.bond),
            funding_state_root: state.funding.root(),
            active_order_risk_root: state.active_order_risk_root,
            position_risk_root: state.position_risk_root,
            bond_inbox_head_root: state.bond_inbox.head_root, bond_inbox_entry_count: 0,
            bond_inbox_processed_root: state.bond_inbox.processed_root, bond_inbox_cursor: 0,
            bond_inbox_outcome_root: state.bond_inbox_outcome_root, bond_inbox_outcome_count: 0,
            matcher_execution_sequence: 0, last_transition_sidechain_height: height,
        })
    }

    /// V2 Simplicity state hash. V1's five records remain in their original
    /// order and the bond, funding, active-order-risk, and position-risk roots
    /// are appended without reinterpreting the V1 records.
    pub fn state_hash(&self, state_domain_sha256: Hash32) -> Hash32 {
        let mut preimage = Vec::with_capacity(32 + 4 + 8 + 12 * 32 + 5 * 8);
        preimage.extend_from_slice(&state_domain_sha256);
        preimage.extend_from_slice(&self.version.to_be_bytes());
        preimage.extend_from_slice(&self.sequence.to_be_bytes());
        preimage.extend_from_slice(&self.private_state_root);
        preimage.extend_from_slice(&self.encrypted_availability_root);
        preimage.extend_from_slice(&self.forced_action_inbox_root);
        preimage.extend_from_slice(&self.deposit_inbox_root);
        preimage.extend_from_slice(&self.configuration_hash);
        preimage.extend_from_slice(&self.bond_state_root);
        preimage.extend_from_slice(&self.funding_state_root);
        preimage.extend_from_slice(&self.active_order_risk_root);
        preimage.extend_from_slice(&self.position_risk_root);
        preimage.extend_from_slice(&self.bond_inbox_head_root);
        preimage.extend_from_slice(&self.bond_inbox_entry_count.to_be_bytes());
        preimage.extend_from_slice(&self.bond_inbox_processed_root);
        preimage.extend_from_slice(&self.bond_inbox_cursor.to_be_bytes());
        preimage.extend_from_slice(&self.bond_inbox_outcome_root);
        preimage.extend_from_slice(&self.bond_inbox_outcome_count.to_be_bytes());
        preimage.extend_from_slice(&self.matcher_execution_sequence.to_be_bytes());
        preimage.extend_from_slice(&self.last_transition_sidechain_height.to_be_bytes());
        sha256(&preimage)
    }

    fn validate(&self) -> Result<(), ProofErrorV2> {
        if self.version != COVENANT_STATE_VERSION_V2 {
            return Err(ProofErrorV2::UnsupportedVersion);
        }
        for (name, identity) in [
            ("private state root", self.private_state_root),
            ("availability root", self.encrypted_availability_root),
            ("forced inbox root", self.forced_action_inbox_root),
            ("deposit inbox root", self.deposit_inbox_root),
            ("configuration hash", self.configuration_hash),
            ("bond state root", self.bond_state_root),
            ("funding state root", self.funding_state_root),
            ("active order risk root", self.active_order_risk_root),
            ("position risk root", self.position_risk_root),
            ("bond inbox head root", self.bond_inbox_head_root),
            ("bond inbox processed root", self.bond_inbox_processed_root),
            ("bond inbox outcome root", self.bond_inbox_outcome_root),
        ] {
            if identity == [0; 32] {
                return Err(ProofErrorV2::ZeroIdentity(name));
            }
        }
        if self.bond_inbox_cursor > self.bond_inbox_entry_count
            || self.bond_inbox_outcome_count != self.bond_inbox_cursor
            || self.last_transition_sidechain_height == 0
        {
            return Err(ProofErrorV2::BindingMismatch(
                "explicit covenant inbox or execution state",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBindingV2 {
    pub version: u8,
    pub transition_txid_consensus: Hash32,
    pub prior_exchange_header_root: Hash32,
    pub prior_parent_block_hash: Hash32,
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub public_state_domain_sha256: Hash32,
    pub transition_journal_domain_sha256: Hash32,
    pub current: CovenantPublicStateV2,
    pub next: CovenantPublicStateV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputV2 {
    pub binding: ProofBindingV2,
    pub configuration: FrozenConfigurationV2,
    pub truthcoin_consensus_proof: TruthcoinConsensusProofV1,
    pub ecx_btc_conversion_proof: ConversionLegConsensusProofV2,
    pub usdd_usd_conversion_proof: ConversionLegConsensusProofV2,
    pub matcher_receipts: Vec<CentralMatcherReceiptV1>,
    /// Deduplicated exact active-chain source transactions and per-entry
    /// recovery evidence. Recovery contributions contain Shamir shares and
    /// remain private: they are excluded from the Elements source transaction
    /// and public values, but are included inside the encrypted transition
    /// recovery payload so a replacement prover can reconstruct the witness.
    pub bond_inbox_source_evidence: Vec<BondInboxSourceTransactionEvidenceV2>,
    pub funding_parent_chain: FundingParentChainWitnessV2,
    pub deposit_openings: Vec<ConfidentialDepositOpeningV1>,
    pub transition_settlement: TransitionSettlementV2,
    pub transition: TransitionWitnessV2,
    pub availability_bundle: Vec<u8>,
    pub availability_custody_receipts: Vec<CustodyReceiptV1>,
    pub availability_encryption_witness: AvailabilityEncryptionWitnessV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInboxSourceTransactionEvidenceV2 {
    pub source_wtxid: Hash32,
    pub source_transaction: Vec<u8>,
    pub entries: Vec<BondInboxEntryRecoveryEvidenceV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInboxEntryRecoveryEvidenceV2 {
    pub entry_index: u64,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub custody_receipts: Vec<BondInboxCustodyReceiptV2>,
    /// Exactly three, strictly increasing, signed V1 contributions. These
    /// bytes include private Shamir shares and must never leave ProofInputV2.
    pub recovery_contributions: Vec<RecoveryContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorBondInboxEntryRecoveryEvidenceV2 {
    pub entry_index: u128,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub custody_receipts: Vec<BondInboxCustodyReceiptV2>,
    pub recovery_contributions: Vec<RecoveryContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofResultV2 {
    pub transition_journal: TransitionJournalV2,
    pub public_values: Vec<u8>,
    pub public_values_sha256: Hash32,
}

/// Exact source-authenticated inputs needed by the funding/oracle child.
///
/// The mark and narrow liquidation band come from the recursively verified
/// Truthcoin statement. For a cross-asset deployment, the wide deficit
/// endpoints also require both recursively verified redemption/conversion
/// statements. For the exact native ECX/USDD profile they are the direct
/// Truthcoin scalar endpoints and both conversion envelopes are canonically
/// absent. None of these values is host-selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedFundingSourceV2 {
    pub truthcoin_public_values_hash: Hash32,
    pub oracle_certificate_hash: Hash32,
    pub oracle_mode: OracleMode,
    pub mark_price_atoms: u64,
    pub liquidation_low_atoms: u64,
    pub liquidation_high_atoms: u64,
    pub authenticated_min_price_atoms: u64,
    pub authenticated_max_price_atoms: u64,
    pub authenticated_price_range_commitment: Hash32,
    pub conversion_legs_commitment: Hash32,
    pub oracle_valid_through_mtp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofErrorV2 {
    #[error("unsupported V2 proof or covenant version")]
    UnsupportedVersion,
    #[error("zero deployment identity: {0}")]
    ZeroIdentity(&'static str),
    #[error("V2 proof binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("V2 transition rejected: {0}")]
    Transition(#[from] ProtocolError),
    #[error("Truthcoin source authentication rejected: {0}")]
    Truthcoin(#[from] AuthenticationError),
    #[error("conversion-leg authentication rejected: {0}")]
    Conversion(#[from] ConversionLegErrorV2),
    #[error("funding parent-chain authentication rejected: {0}")]
    FundingParentChain(#[from] FundingParentChainErrorV2),
    #[error("unified settlement rejected: {0}")]
    Settlement(#[from] SettlementError),
    #[error("encrypted V2 witness availability rejected: {0}")]
    Availability(String),
    #[error("V2 availability recovery payload encoding failed")]
    AvailabilityPayloadEncoding,
}

/// Fail-closed unless every source required by the frozen deployment profile
/// is linked by the caller. Cross-asset profiles consume three deferred
/// proofs; the native ECX/USDD profile consumes exactly the Truthcoin proof.
pub fn execute_proof_v2(input: &ProofInputV2) -> Result<ProofResultV2, ProofErrorV2> {
    execute_proof_v2_with_consensus_verifier(input, &DenyAllConsensusProofs)
}

pub fn execute_proof_v2_with_consensus_verifier<V: ConsensusProofVerifier>(
    input: &ProofInputV2,
    verifier: &V,
) -> Result<ProofResultV2, ProofErrorV2> {
    verify_proof_input_size_v2(input)?;
    validate_binding_and_configuration(input)?;
    verify_operation_bound(input)?;
    verify_availability_binding_v2(input)?;

    let parent = ParentChainContextV1 {
        block_hash: input.binding.prior_parent_block_hash,
        height: input.binding.prior_parent_height,
        median_time_past: input.binding.prior_parent_mtp,
    };
    let source = verify_authenticated_funding_source_v2(
        &input.configuration,
        parent,
        &input.truthcoin_consensus_proof,
        &input.ecx_btc_conversion_proof,
        &input.usdd_usd_conversion_proof,
        verifier,
    )?;
    verify_oracle_binding_v2(&input.transition.base, source)?;
    if input.transition.public.oracle_valid_through_mtp != source.oracle_valid_through_mtp {
        return Err(ProofErrorV2::BindingMismatch("oracle validity endpoint"));
    }
    if input.transition.public.authenticated_min_price.get() != source.authenticated_min_price_atoms
        || input.transition.public.authenticated_max_price.get()
            != source.authenticated_max_price_atoms
        || input.transition.public.authenticated_price_range_commitment
            != source.authenticated_price_range_commitment
    {
        return Err(ProofErrorV2::BindingMismatch(
            "authenticated full price range",
        ));
    }

    verify_matcher_binding_v2(input)?;
    verify_deposit_binding_v2(input)?;
    verify_bond_inbox_source_evidence_v2(input)?;
    verify_funding_parent_chain_v2(
        &input.funding_parent_chain,
        input.binding.prior_parent_block_hash,
        input.binding.prior_parent_height,
        input.binding.prior_parent_mtp,
        &input.transition.matcher_execution_receipts,
        input
            .configuration
            .matcher_execution_inclusion_parent_blocks,
    )?;
    verify_settlement_binding_v2(input)?;

    let journal = verify_transition_v2(&input.transition)?;
    verify_transition_binding_v2(input, &journal)?;

    let next_bond = input.transition.next_state.bond;
    let values = ProofPublicValuesV5 {
        transition_journal_domain_sha256: input.binding.transition_journal_domain_sha256,
        configuration_hash: input.binding.current.configuration_hash,
        current_state_hash: input
            .binding
            .current
            .state_hash(input.binding.public_state_domain_sha256),
        next_state_hash: input
            .binding
            .next
            .state_hash(input.binding.public_state_domain_sha256),
        transition_txid_consensus: input.binding.transition_txid_consensus,
        prior_exchange_header_root: input.binding.prior_exchange_header_root,
        prior_parent_block_hash: input.binding.prior_parent_block_hash,
        prior_parent_height: input.binding.prior_parent_height,
        prior_parent_mtp: input.binding.prior_parent_mtp,
        transition_journal_hash: journal.digest(),
        bond_asset_id: next_bond.bond_asset_id,
        bond_deployment_commitment: next_bond.deployment_commitment,
        bond_state_root: bond_public_state_root_v2(&next_bond),
        redemption_queue_root: journal.redemption_queue_root,
        funding_state_root: journal.funding_state_root,
        conversion_legs_commitment: source.conversion_legs_commitment,
        insurance_reserve: journal.insurance_reserve,
        outstanding_share_atoms: journal.outstanding_share_atoms,
        nav_per_whole_share_usdd_atoms: journal.nav_per_whole_share_usdd_atoms,
        full_bound_deficit: journal.full_bound_deficit,
        target_reserve: journal.target_reserve,
        coverage_bps: journal.coverage_bps,
        capital_mode: journal.capital_mode as u8,
        authenticated_min_price: journal.authenticated_min_price.get(),
        authenticated_max_price: journal.authenticated_max_price.get(),
        funding_epoch: journal.funding_epoch,
        funding_rate_ppm: input.transition.base.public.funding_rate_ppm,
        redemption_head: journal.redemption_head,
        redemption_tail: journal.redemption_tail,
        queued_redemption_share_atoms: journal.queued_redemption_share_atoms,
        oracle_certificate_hash: source.oracle_certificate_hash,
        oracle_valid_through_mtp: journal.oracle_valid_through_mtp,
        oracle_mode: input.transition.base.public.oracle_mode as u8,
        next_encrypted_availability_root: input.binding.next.encrypted_availability_root,
        bond_inbox_head_root: journal.bond_inbox_head_root,
        bond_inbox_entry_count: journal.bond_inbox_entry_count,
        bond_inbox_processed_root: journal.bond_inbox_processed_root,
        bond_inbox_cursor: journal.bond_inbox_cursor,
        bond_inbox_outcome_root: journal.bond_inbox_outcome_root,
        bond_inbox_outcome_count: journal.bond_inbox_outcome_count,
        matcher_execution_receipt_batch_root: journal.matcher_execution_receipt_batch_root,
        previous_matcher_execution_sequence: journal.previous_matcher_execution_sequence,
        next_matcher_execution_sequence: journal.next_matcher_execution_sequence,
    };
    let encoded = values.encode();
    debug_assert_eq!(encoded.len(), PUBLIC_VALUES_V5_LEN);
    Ok(ProofResultV2 {
        transition_journal: journal,
        public_values: encoded.to_vec(),
        public_values_sha256: values.sha256(),
    })
}

/// Verify every recursive source statement required by the frozen profile and
/// derive the exact mark, funding band, deficit endpoints, and freshness
/// endpoint used by V2.
/// Open the ECX successor's pinned oracle configuration before verifying its
/// recursive source. This does not authenticate the supplied parent or funding
/// cursor; the enclosing successor must establish those from prior state.
/// The oracle commitment currently names the exact FrozenConfigurationV2
/// encoding, not an independently selected subset of its oracle fields.
pub fn verify_ecx_authenticated_funding_source_v1<V: ConsensusProofVerifier>(
    bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin_consensus_proof: &TruthcoinConsensusProofV1,
    ecx_btc_conversion_proof: &ConversionLegConsensusProofV2,
    usdd_usd_conversion_proof: &ConversionLegConsensusProofV2,
    verifier: &V,
) -> Result<AuthenticatedFundingSourceV2, ProofErrorV2> {
    bindings.account_domain(economics)?;
    if bindings.oracle_configuration_hash != configuration.digest()
        || economics.chain_id != configuration.base.chain_id
        || economics.market != configuration.base.market
    {
        return Err(ProofErrorV2::BindingMismatch("ECX oracle configuration"));
    }
    verify_authenticated_funding_source_v2(
        configuration, parent, truthcoin_consensus_proof,
        ecx_btc_conversion_proof, usdd_usd_conversion_proof, verifier,
    )
}

pub fn verify_authenticated_funding_source_v2<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin_consensus_proof: &TruthcoinConsensusProofV1,
    ecx_btc_conversion_proof: &ConversionLegConsensusProofV2,
    usdd_usd_conversion_proof: &ConversionLegConsensusProofV2,
    verifier: &V,
) -> Result<AuthenticatedFundingSourceV2, ProofErrorV2> {
    configuration.validate()?;
    let authenticated_quote = verify_authenticated_hybrid_quote(
        &configuration.base.truthcoin_authentication,
        &configuration.base.oracle,
        truthcoin_consensus_proof,
        parent,
        verifier,
    )?;
    let oracle_valid_through_mtp = derive_oracle_valid_through_mtp_v2(
        parent.median_time_past,
        authenticated_quote.quote.oracle_mode,
        truthcoin_consensus_proof
            .public_values
            .anchor
            .finalized_at_mtp,
        truthcoin_consensus_proof
            .public_values
            .lmsr_snapshot
            .source_mtp,
        configuration.base.oracle.maximum_anchor_age_seconds,
        configuration.base.oracle.maximum_snapshot_age_seconds,
    )?;
    let scalar = &truthcoin_consensus_proof.public_values.lmsr_snapshot;
    let (minimum, maximum, range_commitment, price_source_commitment) =
        if configuration.base.uses_direct_native_truthcoin_price() {
            derive_direct_native_truthcoin_price_range_v2(
                configuration,
                authenticated_quote.source_public_values_hash,
                scalar.scalar_lower_bound.get(),
                scalar.scalar_upper_bound.get(),
                ecx_btc_conversion_proof,
                usdd_usd_conversion_proof,
            )?
        } else {
            let conversions = verify_authenticated_conversion_legs_v2(
                configuration,
                parent.block_hash,
                parent.height,
                parent.median_time_past,
                ecx_btc_conversion_proof,
                usdd_usd_conversion_proof,
                verifier,
            )?;
            let (minimum, maximum, range_commitment) = derive_authenticated_price_range_v2(
                configuration,
                scalar.scalar_lower_bound.get(),
                scalar.scalar_upper_bound.get(),
                conversions,
            )?;
            (
                minimum,
                maximum,
                range_commitment,
                conversions.combined_commitment,
            )
        };
    Ok(AuthenticatedFundingSourceV2 {
        truthcoin_public_values_hash: authenticated_quote.source_public_values_hash,
        oracle_certificate_hash: authenticated_quote.quote.certificate_hash(),
        oracle_mode: authenticated_quote.quote.oracle_mode,
        mark_price_atoms: authenticated_quote.quote.ecx_usdd_index.get(),
        liquidation_low_atoms: authenticated_quote.quote.ecx_usdd_low.get(),
        liquidation_high_atoms: authenticated_quote.quote.ecx_usdd_high.get(),
        authenticated_min_price_atoms: minimum,
        authenticated_max_price_atoms: maximum,
        authenticated_price_range_commitment: range_commitment,
        conversion_legs_commitment: price_source_commitment,
        oracle_valid_through_mtp,
    })
}

pub fn derive_oracle_valid_through_mtp_v2(
    parent_mtp: u64,
    mode: OracleMode,
    anchor_finalized_at_mtp: u64,
    snapshot_source_mtp: u64,
    maximum_anchor_age_seconds: u64,
    maximum_snapshot_age_seconds: u64,
) -> Result<u64, ProofErrorV2> {
    if mode != OracleMode::Normal {
        return Ok(parent_mtp);
    }
    let anchor_endpoint = anchor_finalized_at_mtp
        .checked_add(maximum_anchor_age_seconds)
        .ok_or(ProofErrorV2::BindingMismatch(
            "oracle validity endpoint overflow",
        ))?;
    let snapshot_endpoint = snapshot_source_mtp
        .checked_add(maximum_snapshot_age_seconds)
        .ok_or(ProofErrorV2::BindingMismatch(
            "oracle validity endpoint overflow",
        ))?;
    let valid_through = anchor_endpoint.min(snapshot_endpoint);
    if valid_through < parent_mtp {
        return Err(ProofErrorV2::BindingMismatch(
            "stale oracle validity endpoint",
        ));
    }
    Ok(valid_through)
}

/// Bound the complete canonical guest input before any statement logic runs.
/// This is deliberately distinct from the much smaller availability recovery
/// payload bound: source transactions, encrypted bundles, receipts and
/// recovery certificates are still private proof input even when they are
/// deduplicated from the recovery payload.
fn verify_proof_input_size_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let encoded_len = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialized_size(input)
        .map_err(|_| ProofErrorV2::AvailabilityPayloadEncoding)?;
    let maximum = u64::try_from(MAX_PROOF_INPUT_BYTES_V2)
        .map_err(|_| ProofErrorV2::BindingMismatch("proof input size"))?;
    if encoded_len == 0 || encoded_len > maximum {
        return Err(ProofErrorV2::BindingMismatch("proof input size"));
    }
    Ok(())
}

fn validate_binding_and_configuration(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let binding = &input.binding;
    if binding.version != PROOF_BINDING_VERSION_V2 {
        return Err(ProofErrorV2::UnsupportedVersion);
    }
    // V5 admits only fixed deferred-proof markers. Full compressed receipts
    // and verifying keys are consumed by SP1's deferred-proof stream and must
    // never inflate or leak through this recoverable private envelope.
    let recursive_marker_bytes = usize::try_from(input.configuration.recursive_proof_marker_bytes)
        .map_err(|_| ProofErrorV2::BindingMismatch("deferred proof marker length"))?;
    if recursive_marker_bytes != 32
        || input.truthcoin_consensus_proof.proof.len() != recursive_marker_bytes
        || input.ecx_btc_conversion_proof.proof.len() != recursive_marker_bytes
        || input.usdd_usd_conversion_proof.proof.len() != recursive_marker_bytes
    {
        return Err(ProofErrorV2::BindingMismatch(
            "deferred proof marker length",
        ));
    }
    binding.current.validate()?;
    binding.next.validate()?;
    for (name, value) in [
        ("transition txid", binding.transition_txid_consensus),
        ("prior exchange root", binding.prior_exchange_header_root),
        ("prior parent block hash", binding.prior_parent_block_hash),
        ("public state domain", binding.public_state_domain_sha256),
        (
            "transition journal domain",
            binding.transition_journal_domain_sha256,
        ),
    ] {
        if value == [0; 32] {
            return Err(ProofErrorV2::ZeroIdentity(name));
        }
    }
    if binding.prior_parent_height == 0 || binding.prior_parent_mtp == 0 {
        return Err(ProofErrorV2::BindingMismatch("parent chain context"));
    }
    if binding.current.configuration_hash != binding.next.configuration_hash {
        return Err(ProofErrorV2::BindingMismatch("configuration hash"));
    }
    input.configuration.validate()?;
    if input.transition.configuration != input.configuration
        || input.configuration.digest() != binding.current.configuration_hash
        || input.transition.public.configuration_hash != binding.current.configuration_hash
        || input.configuration.base.chain_id != input.transition.base.public.chain_id
        || input.configuration.base.market != input.transition.base.public.market
        || input.configuration.base.risk != input.transition.base.risk_params
        || input.configuration.base.matcher.forced_inclusion_blocks
            != input.transition.base.public.forced_inclusion_blocks
        || input.transition.public.parent_mtp != binding.prior_parent_mtp
        || input.transition.public.previous_state_root != binding.current.private_state_root
        || input.transition.public.next_state_root != binding.next.private_state_root
        || input.transition.public.base_public_digest != input.transition.base.public.digest()
        || input
            .transition
            .subscriptions
            .iter()
            .any(|signed| signed.action.configuration_hash != binding.current.configuration_hash)
        || input
            .transition
            .redemption_enqueues
            .iter()
            .any(|signed| signed.action.configuration_hash != binding.current.configuration_hash)
        || input
            .transition
            .redemption_cancellations
            .iter()
            .any(|signed| signed.action.configuration_hash != binding.current.configuration_hash)
        || input
            .transition
            .order_risk_commitments
            .iter()
            .chain(
                input
                    .transition
                    .previous_active_order_risk_commitments
                    .iter(),
            )
            .chain(input.transition.next_active_order_risk_commitments.iter())
            .any(|risk| risk.configuration_hash != binding.current.configuration_hash)
    {
        return Err(ProofErrorV2::BindingMismatch("frozen V2 configuration"));
    }
    Ok(())
}

fn verify_operation_bound(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let base = &input.transition.base;
    let forced = base.forced_inbox.consumed()?;
    let forced_action_count = forced
        .iter()
        .filter(|entry| match &entry.action {
            ecx_protocol_core::ForcedActionV1::ReduceOnlyIoc(order) => !base
                .fills
                .iter()
                .any(|pair| pair.taker_order.order_id() == order.order_id()),
            ecx_protocol_core::ForcedActionV1::Cancel(_)
            | ecx_protocol_core::ForcedActionV1::Withdraw(_) => true,
        })
        .count();
    let consumed_bond_inbox_entries = input.transition.bond_inbox.consumed_evidence.len();
    let accepted_bond_projection_count = input
        .transition
        .subscriptions
        .len()
        .checked_add(input.transition.recapitalization_contributions.len())
        .and_then(|n| n.checked_add(input.transition.redemption_enqueues.len()))
        .and_then(|n| n.checked_add(input.transition.redemption_cancellations.len()))
        .ok_or(ProofErrorV2::BindingMismatch("operation count"))?;
    // Rejected inbox entries are operations too. The accepted action vectors
    // and outcome transcript are only projections of this consumed prefix;
    // counting them again would both omit rejections and double-count accepts.
    if input.transition.bond_inbox_outcomes.len() != consumed_bond_inbox_entries
        || accepted_bond_projection_count > consumed_bond_inbox_entries
    {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox operation projection",
        ));
    }
    let count = base
        .deposits
        .len()
        .checked_add(base.withdrawals.len())
        .and_then(|n| n.checked_add(base.placements.len()))
        .and_then(|n| n.checked_add(base.cancellations.len()))
        .and_then(|n| n.checked_add(base.fills.len()))
        .and_then(|n| n.checked_add(base.liquidations.len()))
        .and_then(|n| n.checked_add(forced_action_count))
        .and_then(|n| n.checked_add(consumed_bond_inbox_entries))
        .and_then(|n| n.checked_add(input.transition.redemption_executions.len()))
        .ok_or(ProofErrorV2::BindingMismatch("operation count"))?;
    let configured = usize::try_from(input.configuration.base.maximum_transition_actions)
        .map_err(|_| ProofErrorV2::BindingMismatch("operation count"))?;
    let global = usize::try_from(MAX_TRANSITION_ACTIONS)
        .map_err(|_| ProofErrorV2::BindingMismatch("operation count"))?;
    if count > configured || count > global {
        return Err(ProofErrorV2::BindingMismatch("operation count"));
    }
    Ok(())
}

fn verify_transition_binding_v2(
    input: &ProofInputV2,
    journal: &TransitionJournalV2,
) -> Result<(), ProofErrorV2> {
    let binding = &input.binding;
    let previous = &input.transition.previous_state;
    let next = &input.transition.next_state;
    if journal.previous_sequence != binding.current.sequence
        || journal.next_sequence != binding.next.sequence
        || journal.previous_state_root != binding.current.private_state_root
        || journal.next_state_root != binding.next.private_state_root
        || journal.parent_mtp != binding.prior_parent_mtp
        || input.transition.base.public.parent_height != binding.prior_parent_height
        || binding.current.forced_action_inbox_root != previous.base.forced_inbox.head_root
        || binding.next.forced_action_inbox_root != next.base.forced_inbox.head_root
        || binding.current.deposit_inbox_root != previous.base.deposit_inbox.head_root
        || binding.next.deposit_inbox_root != next.base.deposit_inbox.head_root
        || binding.next.encrypted_availability_root
            != input.transition.base.public.encrypted_availability_root
        || binding.current.bond_state_root != bond_public_state_root_v2(&previous.bond)
        || binding.next.bond_state_root != bond_public_state_root_v2(&next.bond)
        || binding.current.funding_state_root != previous.funding.root()
        || binding.next.funding_state_root != next.funding.root()
        || binding.current.active_order_risk_root != previous.active_order_risk_root
        || binding.next.active_order_risk_root != next.active_order_risk_root
        || binding.current.position_risk_root != previous.position_risk_root
        || binding.next.position_risk_root != next.position_risk_root
        || binding.current.bond_inbox_head_root != previous.bond_inbox.head_root
        || binding.next.bond_inbox_head_root != next.bond_inbox.head_root
        || binding.current.bond_inbox_entry_count != previous.bond_inbox.entry_count
        || binding.next.bond_inbox_entry_count != next.bond_inbox.entry_count
        || binding.current.bond_inbox_processed_root != previous.bond_inbox.processed_root
        || binding.next.bond_inbox_processed_root != next.bond_inbox.processed_root
        || binding.current.bond_inbox_cursor != previous.bond_inbox.cursor
        || binding.next.bond_inbox_cursor != next.bond_inbox.cursor
        || binding.current.bond_inbox_outcome_root != previous.bond_inbox_outcome_root
        || binding.next.bond_inbox_outcome_root != next.bond_inbox_outcome_root
        || binding.current.bond_inbox_outcome_count != previous.bond_inbox_outcome_count
        || binding.next.bond_inbox_outcome_count != next.bond_inbox_outcome_count
        || binding.current.matcher_execution_sequence != previous.matcher_execution_sequence
        || binding.next.matcher_execution_sequence != next.matcher_execution_sequence
        || binding.current.last_transition_sidechain_height
            != previous.last_transition_sidechain_height
        || binding.next.last_transition_sidechain_height != next.last_transition_sidechain_height
        || input.transition.public.bond_action_root != bond_action_root_v2(&input.transition)
        || input.transition.public.order_risk_root
            != order_risk_root_v2(&input.transition.order_risk_commitments)
        || input.transition.public.funding_state_root != next.funding.root()
    {
        return Err(ProofErrorV2::BindingMismatch("V2 state or action linkage"));
    }
    Ok(())
}

fn verify_oracle_binding_v2(
    transition: &TransitionWitness,
    source: AuthenticatedFundingSourceV2,
) -> Result<(), ProofErrorV2> {
    if transition.public.oracle_certificate_hash != source.oracle_certificate_hash
        || transition.public.oracle_mode != source.oracle_mode
        || transition.public.mark_price.get() != source.mark_price_atoms
        || transition.public.liquidation_low.get() != source.liquidation_low_atoms
        || transition.public.liquidation_high.get() != source.liquidation_high_atoms
    {
        return Err(ProofErrorV2::BindingMismatch("hybrid oracle certificate"));
    }
    if source.oracle_mode != OracleMode::Normal && !transition.liquidations.is_empty() {
        return Err(ProofErrorV2::BindingMismatch(
            "liquidation outside normal oracle mode",
        ));
    }
    match source.oracle_mode {
        OracleMode::Normal => {}
        OracleMode::ReduceOnly | OracleMode::Disputed => {
            if transition.public.funding_rate_ppm != 0
                || transition.placements.iter().any(|placement| {
                    !placement
                        .order
                        .order
                        .flags
                        .contains(OrderFlags::REDUCE_ONLY)
                })
                || transition.fills.iter().any(|pair| {
                    !pair
                        .maker_order
                        .order
                        .flags
                        .contains(OrderFlags::REDUCE_ONLY)
                        || !pair
                            .taker_order
                            .order
                            .flags
                            .contains(OrderFlags::REDUCE_ONLY)
                })
            {
                return Err(ProofErrorV2::BindingMismatch("reduce-only oracle mode"));
            }
        }
        OracleMode::Halt => {
            if transition.public.funding_rate_ppm != 0
                || !transition.withdrawals.is_empty()
                || !transition.placements.is_empty()
                || !transition.fills.is_empty()
            {
                return Err(ProofErrorV2::BindingMismatch("halted oracle mode"));
            }
        }
    }
    Ok(())
}

fn verify_deposit_binding_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let events = input.transition.base.deposit_inbox.consumed()?;
    if events.len() != input.deposit_openings.len()
        || events.len() != input.transition.base.deposits.len()
    {
        return Err(ProofErrorV2::BindingMismatch("deposit opening coverage"));
    }
    for ((event, opening), expected) in events
        .iter()
        .zip(&input.deposit_openings)
        .zip(&input.transition.base.deposits)
    {
        let request = verify_confidential_deposit(
            event,
            opening,
            input.configuration.base.usdd_asset_id,
            input.configuration.base.collateral_vault_script_sha256,
        )?;
        if &request != expected {
            return Err(ProofErrorV2::BindingMismatch("deposit opening"));
        }
    }
    Ok(())
}

fn verify_bond_inbox_source_evidence_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    verify_bond_inbox_source_evidence_parts_v2(
        &input.configuration,
        &input.transition.bond_inbox,
        &input.bond_inbox_source_evidence,
    )
}

pub fn verify_bond_inbox_source_evidence_parts_v2(
    configuration: &FrozenConfigurationV2,
    bond_inbox: &ecx_protocol_core::BondInboxTransitionV2,
    source_evidence: &[BondInboxSourceTransactionEvidenceV2],
) -> Result<(), ProofErrorV2> {
    if configuration.bond_inbox_custody_receipt_codec_hash != custody_receipt_codec_hash_v1() {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox custody receipt codec",
        ));
    }
    let consumed_count = bond_inbox.consumed_evidence.len();
    let consumed_entries = bond_inbox
        .pending_entries
        .iter()
        .take(consumed_count)
        .zip(&bond_inbox.consumed_evidence)
        .filter(|(_, evidence)| {
            !matches!(
                evidence,
                BondInboxConsumedEvidenceV2::ExpiredUnavailable { .. }
            )
        })
        .map(|(entry, _)| (entry.index, entry))
        .collect::<BTreeMap<_, _>>();
    if bond_inbox.pending_entries.len() < consumed_count {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox consumed source coverage",
        ));
    }

    let mut seen_source_wtxids = BTreeSet::new();
    let mut seen_entry_indices = BTreeSet::new();
    let mut reconstructed = BTreeMap::new();
    let mut previous_source_wtxid = None;
    for source in source_evidence {
        if source.source_wtxid == [0; 32]
            || source.source_transaction.is_empty()
            || source.entries.is_empty()
            || !seen_source_wtxids.insert(source.source_wtxid)
            || previous_source_wtxid.is_some_and(|prior| source.source_wtxid <= prior)
        {
            return Err(ProofErrorV2::BindingMismatch(
                "bond inbox source evidence table",
            ));
        }
        previous_source_wtxid = Some(source.source_wtxid);
        let mut previous_entry_index = None;
        for evidence in &source.entries {
            if previous_entry_index.is_some_and(|prior| evidence.entry_index <= prior)
                || !seen_entry_indices.insert(evidence.entry_index)
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "duplicate bond inbox entry evidence",
                ));
            }
            previous_entry_index = Some(evidence.entry_index);
            let entry = consumed_entries.get(&evidence.entry_index).ok_or(
                ProofErrorV2::BindingMismatch("unused bond inbox entry evidence"),
            )?;
            if entry.source_wtxid != source.source_wtxid {
                return Err(ProofErrorV2::BindingMismatch(
                    "bond inbox source wtxid reference",
                ));
            }
            let exact_receipt_bytes = evidence
                .custody_receipts
                .iter()
                .map(|receipt| receipt.exact_receipt_bytes.clone())
                .collect::<Vec<_>>();
            let verified_source = verify_bond_inbox_source_transaction_v2(
                entry,
                &source.source_transaction,
                &evidence.canonical_encrypted_bundle,
                &evidence.custody_receipts,
                configuration,
            )?;
            if verified_source.wtxid != source.source_wtxid
                || verified_source.txid != entry.source_txid
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "bond inbox exact source transaction",
                ));
            }
            verify_bond_inbox_source_witness_commitments_v2(
                &entry.marker,
                configuration.base.availability,
                &evidence.canonical_encrypted_bundle,
                &evidence.custody_receipts,
            )?;

            let bundle = WitnessBundle::decode(&evidence.canonical_encrypted_bundle)
                .map_err(availability_error)?;
            if bundle.context != entry.marker.availability_context
                || bundle.encode().map_err(availability_error)?
                    != evidence.canonical_encrypted_bundle
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "bond inbox exact encrypted bundle",
                ));
            }
            let custodians = bundle
                .custodians
                .iter()
                .map(|envelope| envelope.public)
                .collect::<Vec<_>>();
            if custodian_registry_hash(&custodians).map_err(availability_error)?
                != configuration.base.availability.custodian_registry_hash
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "bond inbox custodian registry",
                ));
            }
            let bundle_root = bundle.root().map_err(availability_error)?;
            let mut receipts = Vec::with_capacity(evidence.custody_receipts.len());
            for (wrapper, exact_bytes) in evidence.custody_receipts.iter().zip(&exact_receipt_bytes)
            {
                let receipt =
                    CustodyReceiptV1::decode_canonical(exact_bytes).map_err(availability_error)?;
                if receipt
                    .encode_canonical()
                    .map_err(availability_error)?
                    .as_slice()
                    != exact_bytes
                    || receipt.custodian_index
                        != wrapper.custodian_index.checked_add(1).ok_or(
                            ProofErrorV2::BindingMismatch("bond inbox custody receipt index"),
                        )?
                    || receipt.bundle_root != bundle_root
                    || receipt.context != bundle.context
                    || receipt.witness_len != bundle.witness_len
                {
                    return Err(ProofErrorV2::BindingMismatch(
                        "bond inbox custody receipt binding",
                    ));
                }
                receipts.push(receipt);
            }
            verify_custody_receipts(&bundle, &receipts).map_err(availability_error)?;
            verify_recovery_certificate(&bundle, &evidence.recovery_contributions)
                .map_err(availability_error)?;
            let recovery_certificate_root =
                recovery_certificate_root_v1(&evidence.recovery_contributions)
                    .map_err(availability_error)?;

            let recovered_evidence =
                match recover_witness(&bundle, &evidence.recovery_contributions) {
                    Ok(recovered) => {
                        let plaintext = recovered.as_bytes();
                        match BondInboxAvailablePayloadV2::decode_canonical(
                            entry.marker.kind,
                            plaintext,
                        ) {
                            Ok(payload) => BondInboxConsumedEvidenceV2::Recovered {
                                source_entry_hash: entry.entry_hash(),
                                payload,
                            },
                            Err(_) => authenticated_bond_inbox_recovery_failure_v2(
                                entry.entry_hash(),
                                bundle_root,
                                BondInboxRecoveryFailureV2::PlaintextDecode,
                                bond_inbox_recovered_plaintext_sha256_v2(plaintext)?,
                                recovery_certificate_root,
                            )?,
                        }
                    }
                    Err(AvailabilityError::Aead) => authenticated_bond_inbox_recovery_failure_v2(
                        entry.entry_hash(),
                        bundle_root,
                        BondInboxRecoveryFailureV2::PayloadAead,
                        bond_inbox_aead_failure_plaintext_sentinel_v2(),
                        recovery_certificate_root,
                    )?,
                    Err(AvailabilityError::Canonical("recovered witness length")) => {
                        authenticated_bond_inbox_recovery_failure_v2(
                            entry.entry_hash(),
                            bundle_root,
                            BondInboxRecoveryFailureV2::PlaintextLength,
                            bond_inbox_recovered_plaintext_sha256_v2(&[])?,
                            recovery_certificate_root,
                        )?
                    }
                    Err(error) => return Err(availability_error(error)),
                };
            reconstructed.insert(evidence.entry_index, recovered_evidence);
        }
    }

    let required_source_count = consumed_entries.len();
    if seen_entry_indices.len() != required_source_count
        || reconstructed.len() != required_source_count
        || bond_inbox
            .consumed_evidence
            .iter()
            .zip(bond_inbox.pending_entries.iter().take(consumed_count))
            .filter(|(expected, _)| {
                !matches!(
                    expected,
                    BondInboxConsumedEvidenceV2::ExpiredUnavailable { .. }
                )
            })
            .any(|(expected, entry)| reconstructed.get(&entry.index) != Some(expected))
    {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox recovered evidence projection",
        ));
    }
    Ok(())
}

fn authenticated_bond_inbox_recovery_failure_v2(
    entry_hash: Hash32,
    witness_bundle_root: Hash32,
    failure: BondInboxRecoveryFailureV2,
    recovered_plaintext_sha256: Hash32,
    recovery_certificate_root: Hash32,
) -> Result<BondInboxConsumedEvidenceV2, ProofErrorV2> {
    let failure_commitment = bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2(
        entry_hash,
        witness_bundle_root,
        failure,
        recovered_plaintext_sha256,
        recovery_certificate_root,
    )?;
    Ok(
        BondInboxConsumedEvidenceV2::AuthenticatedRecoveryOrPayloadFailure(
            BondInboxAuthenticatedRecoveryOrPayloadFailureV2 {
                failure,
                witness_bundle_root,
                recovered_plaintext_sha256,
                recovery_certificate_root,
                failure_commitment,
            },
        ),
    )
}

/// Recover one entry after a sibling recursive source-transaction proof has
/// authenticated the exact txid/wtxid, annex, bundle and receipt projection.
/// This deliberately performs the custody, threshold-recovery, AEAD and
/// canonical action checks again inside the inbox aggregate child; a source
/// transaction receipt alone never authorizes an economic action.
// Retained solely for historical V18 decoding tests while recursive children
// migrate atomically to the successor-width inbox relation.
#[allow(dead_code)]
pub(crate) fn recover_bond_inbox_entry_from_compact_evidence_v2(
    configuration: &FrozenConfigurationV2,
    entry: &ecx_protocol_core::BondInboxEntryV2,
    evidence: &BondInboxEntryRecoveryEvidenceV2,
) -> Result<BondInboxConsumedEvidenceV2, ProofErrorV2> {
    verify_bond_inbox_source_witness_commitments_v2(
        &entry.marker,
        configuration.base.availability,
        &evidence.canonical_encrypted_bundle,
        &evidence.custody_receipts,
    )?;
    let bundle =
        WitnessBundle::decode(&evidence.canonical_encrypted_bundle).map_err(availability_error)?;
    if bundle.context != entry.marker.availability_context
        || bundle.encode().map_err(availability_error)? != evidence.canonical_encrypted_bundle
    {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox exact encrypted bundle",
        ));
    }
    let custodians = bundle
        .custodians
        .iter()
        .map(|envelope| envelope.public)
        .collect::<Vec<_>>();
    if custodian_registry_hash(&custodians).map_err(availability_error)?
        != configuration.base.availability.custodian_registry_hash
    {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox custodian registry",
        ));
    }
    let bundle_root = bundle.root().map_err(availability_error)?;
    let mut receipts = Vec::with_capacity(evidence.custody_receipts.len());
    for wrapper in &evidence.custody_receipts {
        let receipt = CustodyReceiptV1::decode_canonical(&wrapper.exact_receipt_bytes)
            .map_err(availability_error)?;
        if receipt
            .encode_canonical()
            .map_err(availability_error)?
            .as_slice()
            != wrapper.exact_receipt_bytes
            || receipt.custodian_index
                != wrapper
                    .custodian_index
                    .checked_add(1)
                    .ok_or(ProofErrorV2::BindingMismatch(
                        "bond inbox custody receipt index",
                    ))?
            || receipt.bundle_root != bundle_root
            || receipt.context != bundle.context
            || receipt.witness_len != bundle.witness_len
        {
            return Err(ProofErrorV2::BindingMismatch(
                "bond inbox custody receipt binding",
            ));
        }
        receipts.push(receipt);
    }
    verify_custody_receipts(&bundle, &receipts).map_err(availability_error)?;
    verify_recovery_certificate(&bundle, &evidence.recovery_contributions)
        .map_err(availability_error)?;
    let recovery_certificate_root = recovery_certificate_root_v1(&evidence.recovery_contributions)
        .map_err(availability_error)?;
    match recover_witness(&bundle, &evidence.recovery_contributions) {
        Ok(recovered) => {
            let plaintext = recovered.as_bytes();
            match BondInboxAvailablePayloadV2::decode_canonical(entry.marker.kind, plaintext) {
                Ok(payload) => Ok(BondInboxConsumedEvidenceV2::Recovered {
                    source_entry_hash: entry.entry_hash(),
                    payload,
                }),
                Err(_) => authenticated_bond_inbox_recovery_failure_v2(
                    entry.entry_hash(),
                    bundle_root,
                    BondInboxRecoveryFailureV2::PlaintextDecode,
                    bond_inbox_recovered_plaintext_sha256_v2(plaintext)?,
                    recovery_certificate_root,
                ),
            }
        }
        Err(AvailabilityError::Aead) => authenticated_bond_inbox_recovery_failure_v2(
            entry.entry_hash(),
            bundle_root,
            BondInboxRecoveryFailureV2::PayloadAead,
            bond_inbox_aead_failure_plaintext_sentinel_v2(),
            recovery_certificate_root,
        ),
        Err(AvailabilityError::Canonical("recovered witness length")) => {
            authenticated_bond_inbox_recovery_failure_v2(
                entry.entry_hash(),
                bundle_root,
                BondInboxRecoveryFailureV2::PlaintextLength,
                bond_inbox_recovered_plaintext_sha256_v2(&[])?,
                recovery_certificate_root,
            )
        }
        Err(error) => Err(availability_error(error)),
    }
}

fn authenticated_successor_bond_inbox_recovery_failure_v2(
    entry_hash: Hash32,
    witness_bundle_root: Hash32,
    failure: BondInboxRecoveryFailureV2,
    recovered_plaintext_sha256: Hash32,
    recovery_certificate_root: Hash32,
) -> Result<SuccessorBondInboxConsumedEvidenceV2, ProofErrorV2> {
    let failure_commitment = successor_bond_inbox_authenticated_failure_commitment_v2(
        entry_hash,
        witness_bundle_root,
        failure,
        recovered_plaintext_sha256,
        recovery_certificate_root,
    )?;
    Ok(
        SuccessorBondInboxConsumedEvidenceV2::AuthenticatedRecoveryOrPayloadFailure(
            SuccessorBondInboxAuthenticatedFailureV2 {
                failure,
                witness_bundle_root,
                recovered_plaintext_sha256,
                recovery_certificate_root,
                failure_commitment,
            },
        ),
    )
}

pub(crate) fn recover_successor_bond_inbox_entry_from_compact_evidence_v2(
    configuration: &FrozenConfigurationV2,
    entry: &SuccessorBondInboxEntryV2,
    evidence: &SuccessorBondInboxEntryRecoveryEvidenceV2,
) -> Result<SuccessorBondInboxConsumedEvidenceV2, ProofErrorV2> {
    if evidence.entry_index != entry.index {
        return Err(ProofErrorV2::BindingMismatch(
            "successor bond inbox entry index",
        ));
    }
    verify_successor_bond_inbox_source_witness_commitments_v2(
        &entry.marker,
        configuration.base.availability,
        &evidence.canonical_encrypted_bundle,
        &evidence.custody_receipts,
    )?;
    let bundle =
        WitnessBundle::decode(&evidence.canonical_encrypted_bundle).map_err(availability_error)?;
    if bundle.context != entry.marker.availability_context
        || bundle.encode().map_err(availability_error)? != evidence.canonical_encrypted_bundle
    {
        return Err(ProofErrorV2::BindingMismatch(
            "successor bond inbox exact encrypted bundle",
        ));
    }
    let custodians = bundle
        .custodians
        .iter()
        .map(|envelope| envelope.public)
        .collect::<Vec<_>>();
    if custodian_registry_hash(&custodians).map_err(availability_error)?
        != configuration.base.availability.custodian_registry_hash
    {
        return Err(ProofErrorV2::BindingMismatch(
            "successor bond inbox custodian registry",
        ));
    }
    let bundle_root = bundle.root().map_err(availability_error)?;
    let mut receipts = Vec::with_capacity(evidence.custody_receipts.len());
    for wrapper in &evidence.custody_receipts {
        let receipt = CustodyReceiptV1::decode_canonical(&wrapper.exact_receipt_bytes)
            .map_err(availability_error)?;
        if receipt
            .encode_canonical()
            .map_err(availability_error)?
            .as_slice()
            != wrapper.exact_receipt_bytes
            || receipt.custodian_index
                != wrapper
                    .custodian_index
                    .checked_add(1)
                    .ok_or(ProofErrorV2::BindingMismatch(
                        "successor bond inbox custody receipt index",
                    ))?
            || receipt.bundle_root != bundle_root
            || receipt.context != bundle.context
            || receipt.witness_len != bundle.witness_len
        {
            return Err(ProofErrorV2::BindingMismatch(
                "successor bond inbox custody receipt binding",
            ));
        }
        receipts.push(receipt);
    }
    verify_custody_receipts(&bundle, &receipts).map_err(availability_error)?;
    verify_recovery_certificate(&bundle, &evidence.recovery_contributions)
        .map_err(availability_error)?;
    let recovery_certificate_root = recovery_certificate_root_v1(&evidence.recovery_contributions)
        .map_err(availability_error)?;
    match recover_witness(&bundle, &evidence.recovery_contributions) {
        Ok(recovered) => {
            let plaintext = recovered.as_bytes();
            match SuccessorBondInboxAvailablePayloadV2::decode_canonical(
                entry.marker.kind,
                plaintext,
            ) {
                Ok(payload) => Ok(SuccessorBondInboxConsumedEvidenceV2::Recovered {
                    source_entry_hash: entry.entry_hash(),
                    payload,
                }),
                Err(_) => authenticated_successor_bond_inbox_recovery_failure_v2(
                    entry.entry_hash(),
                    bundle_root,
                    BondInboxRecoveryFailureV2::PlaintextDecode,
                    successor_bond_inbox_recovered_plaintext_sha256_v2(plaintext)?,
                    recovery_certificate_root,
                ),
            }
        }
        Err(AvailabilityError::Aead) => authenticated_successor_bond_inbox_recovery_failure_v2(
            entry.entry_hash(),
            bundle_root,
            BondInboxRecoveryFailureV2::PayloadAead,
            successor_bond_inbox_aead_failure_plaintext_sentinel_v2(),
            recovery_certificate_root,
        ),
        Err(AvailabilityError::Canonical("recovered witness length")) => {
            authenticated_successor_bond_inbox_recovery_failure_v2(
                entry.entry_hash(),
                bundle_root,
                BondInboxRecoveryFailureV2::PlaintextLength,
                successor_bond_inbox_recovered_plaintext_sha256_v2(&[])?,
                recovery_certificate_root,
            )
        }
        Err(error) => Err(availability_error(error)),
    }
}

type ExpectedMatcherCommand = (MatcherCommandKind, Hash32, Option<u64>);

fn verify_matcher_binding_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let transition = &input.transition.base;
    if central_matcher_receipt_batch_root(&input.matcher_receipts)
        != transition.public.matcher_receipt_batch_root
    {
        return Err(ProofErrorV2::BindingMismatch("matcher receipt batch root"));
    }
    let (next_sequence, next_hash) = verify_central_matcher_receipt_chain(
        &input.configuration.base.matcher,
        input.configuration.base.chain_id,
        transition.previous_state.matcher_sequence,
        transition.previous_state.matcher_receipt_hash,
        &input.matcher_receipts,
    )?;
    if next_sequence != transition.next_state.matcher_sequence
        || next_hash != transition.next_state.matcher_receipt_hash
        || input.matcher_receipts.iter().any(|receipt| {
            receipt.body.observed_sidechain_height > transition.public.sidechain_height
                || receipt.body.observed_parent_height > input.binding.prior_parent_height
                || receipt.body.observed_parent_mtp > input.binding.prior_parent_mtp
                || receipt.body.forced_inbox_cursor > transition.next_state.forced_inbox.cursor
        })
    {
        return Err(ProofErrorV2::BindingMismatch("matcher receipt chain"));
    }
    let mut expected = Vec::new();
    for placement in &transition.placements {
        expected.push((
            MatcherCommandKind::Place,
            matcher_order_command_hash(&placement.order),
            Some(placement.received_sequence),
        ));
    }
    for cancellation in &transition.cancellations {
        expected.push((
            MatcherCommandKind::Cancel,
            matcher_cancel_command_hash(cancellation),
            None,
        ));
    }
    let forced_ioc: BTreeSet<Hash32> = transition
        .forced_inbox
        .consumed()?
        .iter()
        .filter_map(|entry| match &entry.action {
            ecx_protocol_core::ForcedActionV1::ReduceOnlyIoc(order) => Some(order.order_id()),
            _ => None,
        })
        .collect();
    for pair in &transition.fills {
        let taker = pair.taker_order.order_id();
        if !forced_ioc.contains(&taker) {
            require_place_receipt_v2(
                &mut expected,
                matcher_order_command_hash(&pair.taker_order),
                pair.trade.sequence,
            )?;
        }
    }
    if expected.len() != input.matcher_receipts.len() {
        return Err(ProofErrorV2::BindingMismatch("matcher command coverage"));
    }
    let mut matched = vec![false; expected.len()];
    for receipt in &input.matcher_receipts {
        let found = expected.iter().enumerate().find_map(|(index, item)| {
            (!matched[index]
                && receipt.body.command_kind == item.0
                && receipt.body.command_hash == item.1
                && item
                    .2
                    .is_none_or(|sequence| sequence == receipt.body.global_sequence))
            .then_some(index)
        });
        let index = found.ok_or(ProofErrorV2::BindingMismatch("matcher command receipt"))?;
        matched[index] = true;
    }

    // Protocol-core verifies that every V2 receipt signs the exact fill, but
    // the proof must additionally bind it to the one authenticated V1 Place
    // receipt that admitted that taker command. This relation is deliberately
    // built in ordinary-fill order so the execution-receipt cursor cannot be
    // advanced by an omitted, duplicated, reordered or context-substituted
    // admission receipt. Forced IOCs are authenticated by their on-chain
    // inbox entry and therefore have no central-matcher execution receipt.
    verify_exact_matcher_execution_admissions_v2(
        &input.configuration.base.matcher,
        input.configuration.base.chain_id,
        input.binding.prior_parent_block_hash,
        input.transition.previous_state.matcher_execution_sequence,
        &transition.fills,
        &forced_ioc,
        &input.matcher_receipts,
        &input.transition.matcher_execution_receipts,
        input.transition.public.matcher_execution_receipt_batch_root,
        input.transition.public.next_matcher_execution_sequence,
    )?;
    if input.transition.public.next_matcher_execution_sequence
        != input.transition.next_state.matcher_execution_sequence
    {
        return Err(ProofErrorV2::BindingMismatch(
            "matcher execution admission projection",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_exact_matcher_execution_admissions_v2(
    matcher_configuration: &ecx_protocol_core::CentralMatcherConfigV1,
    chain_id: Hash32,
    expected_execution_parent_block_hash: Hash32,
    previous_execution_sequence: u64,
    fills: &[MatchedOrderPair],
    forced_ioc: &BTreeSet<Hash32>,
    matcher_receipts: &[CentralMatcherReceiptV1],
    execution_receipts: &[MatcherExecutionReceiptV2],
    expected_execution_root: Hash32,
    expected_next_execution_sequence: u64,
) -> Result<(), ProofErrorV2> {
    // Height and MTP are checked against the authenticated transition parent
    // by protocol-core. The parent hash is part of the outer proof binding,
    // so it must be checked here as well: a matcher signature cannot select a
    // different block at the same height/MTP and thereby manufacture an
    // execution context.
    if execution_receipts.iter().any(|receipt| {
        receipt.body.execution_parent.block_hash != expected_execution_parent_block_hash
    }) {
        return Err(ProofErrorV2::BindingMismatch(
            "matcher execution parent block hash",
        ));
    }
    let mut execution_relations = Vec::with_capacity(fills.len());
    for pair in fills {
        if forced_ioc.contains(&pair.taker_order.order_id()) {
            continue;
        }
        let command_hash = matcher_order_command_hash(&pair.taker_order);
        let mut candidates = matcher_receipts.iter().filter(|receipt| {
            receipt.body.command_kind == MatcherCommandKind::Place
                && receipt.body.command_hash == command_hash
                && receipt.body.global_sequence == pair.trade.sequence
        });
        let taker_admission = candidates
            .next()
            .ok_or(ProofErrorV2::BindingMismatch("taker admission receipt"))?;
        if candidates.next().is_some() {
            return Err(ProofErrorV2::BindingMismatch(
                "duplicate taker admission receipt",
            ));
        }
        execution_relations.push(MatcherExecutionRelationV2 {
            maker: &pair.maker_order,
            taker: &pair.taker_order,
            trade: &pair.trade,
            taker_admission,
        });
    }
    let (execution_root, next_execution_sequence) = verify_matcher_execution_receipt_batch_v2(
        matcher_configuration,
        chain_id,
        previous_execution_sequence,
        &execution_relations,
        execution_receipts,
    )?;
    if execution_root != expected_execution_root
        || next_execution_sequence != expected_next_execution_sequence
    {
        return Err(ProofErrorV2::BindingMismatch(
            "matcher execution admission projection",
        ));
    }
    Ok(())
}

fn require_place_receipt_v2(
    expected: &mut Vec<ExpectedMatcherCommand>,
    hash: Hash32,
    sequence: u64,
) -> Result<(), ProofErrorV2> {
    if let Some((_, _, required)) = expected
        .iter_mut()
        .find(|(kind, candidate, _)| *kind == MatcherCommandKind::Place && *candidate == hash)
    {
        match *required {
            Some(current) if current != sequence => {
                return Err(ProofErrorV2::BindingMismatch("taker receipt sequence"));
            }
            Some(_) => {}
            None => *required = Some(sequence),
        }
    } else {
        expected.push((MatcherCommandKind::Place, hash, Some(sequence)));
    }
    Ok(())
}

/// Commitment helpers are public so settlement producers cannot accidentally
/// use a host-native struct hash. Fixed-integer, big-endian bincode is part of
/// the V2 statement and includes the exact role metadata and blinding factors.
fn opening_commitment<T: Serialize>(
    domain: &'static str,
    value: &T,
) -> Result<Hash32, ProofErrorV2> {
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialize(value)
        .map_err(|_| ProofErrorV2::BindingMismatch("opening commitment encoding"))?;
    Ok(tagged_hash(domain, &bytes))
}

pub fn collateral_input_opening_commitment_v2(
    value: &CollateralInputOpeningV2,
) -> Result<Hash32, ProofErrorV2> {
    opening_commitment("ECX/v2-collateral-input-opening/v1", value)
}

pub fn collateral_output_opening_commitment_v2(
    value: &CollateralOutputOpeningV2,
) -> Result<Hash32, ProofErrorV2> {
    opening_commitment("ECX/v2-collateral-output-opening/v1", value)
}

pub fn bond_input_opening_commitment_v2(
    value: &BondInputOpeningV2,
) -> Result<Hash32, ProofErrorV2> {
    opening_commitment("ECX/v2-bond-input-opening/v1", value)
}

pub fn bond_output_opening_commitment_v2(
    value: &BondOutputOpeningV2,
) -> Result<Hash32, ProofErrorV2> {
    opening_commitment("ECX/v2-bond-output-opening/v1", value)
}

pub fn subscription_usdd_output_opening_commitment_v2(
    value: &CollateralOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id } => subscription_id,
        _ => return Err(ProofErrorV2::BindingMismatch("subscription USDD role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::SubscriptionInsuranceOutput,
        stable_id,
        configuration.base.usdd_asset_id,
        value.amount,
        configuration.insurance_reserve_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn subscription_bond_output_opening_commitment_v2(
    value: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let (stable_id, script) = match value.role {
        BondOutputRoleV2::Subscription {
            subscription_id,
            recipient_script_sha256,
        } => (subscription_id, recipient_script_sha256),
        _ => return Err(ProofErrorV2::BindingMismatch("subscription bond role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::SubscriptionBondOutput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn recapitalization_usdd_output_opening_commitment_v2(
    value: &CollateralOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        CollateralOutputRoleV2::InsuranceRecapitalizationContribution { contribution_id } => {
            contribution_id
        }
        _ => return Err(ProofErrorV2::BindingMismatch("recapitalization USDD role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::RecapitalizationInsuranceOutput,
        stable_id,
        configuration.base.usdd_asset_id,
        value.amount,
        configuration.insurance_reserve_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_enqueue_bond_input_opening_commitment_v2(
    value: &BondInputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let (stable_id, script) = match value.role {
        BondInputRoleV2::StagedRedemptionEnqueue {
            staging_intent_id,
            staging_script_sha256,
            ..
        } => (staging_intent_id, staging_script_sha256),
        _ => return Err(ProofErrorV2::BindingMismatch("enqueue staging input role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::EnqueueStagingBondInput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_enqueue_queue_output_opening_commitment_v2(
    value: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        BondOutputRoleV2::QueuedRedemptionEntry {
            staging_intent_id, ..
        } => staging_intent_id,
        _ => return Err(ProofErrorV2::BindingMismatch("enqueue queue output role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::EnqueueQueueBondOutput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        configuration.bond_redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_cancel_queue_input_opening_commitment_v2(
    value: &BondInputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        BondInputRoleV2::QueuedRedemption { redemption_id } => redemption_id,
        _ => {
            return Err(ProofErrorV2::BindingMismatch(
                "cancellation queue input role",
            ));
        }
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::CancellationQueueBondInput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        configuration.bond_redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_cancel_bond_return_opening_commitment_v2(
    value: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let (stable_id, script) = match value.role {
        BondOutputRoleV2::CancelledRedemptionReturn {
            cancellation_id,
            recipient_script_sha256,
            ..
        } => (cancellation_id, recipient_script_sha256),
        _ => return Err(ProofErrorV2::BindingMismatch("cancellation return role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::CancellationBondReturnOutput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_execute_queue_input_opening_commitment_v2(
    value: &BondInputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        BondInputRoleV2::QueuedRedemption { redemption_id } => redemption_id,
        _ => return Err(ProofErrorV2::BindingMismatch("execution queue input role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::ExecutionQueueBondInput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        configuration.bond_redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_execute_usdd_output_opening_commitment_v2(
    value: &CollateralOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let (stable_id, script) = match value.role {
        CollateralOutputRoleV2::BondRedemptionPayment {
            redemption_id,
            recipient_script_sha256,
        } => (redemption_id, recipient_script_sha256),
        _ => return Err(ProofErrorV2::BindingMismatch("execution payment role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::ExecutionUsddPaymentOutput,
        stable_id,
        configuration.base.usdd_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_execute_inventory_output_opening_commitment_v2(
    value: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        BondOutputRoleV2::RedemptionInventoryReturn { redemption_id } => redemption_id,
        _ => return Err(ProofErrorV2::BindingMismatch("execution inventory role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::ExecutionInventoryBondOutput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        configuration.bond_inventory_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

pub fn redemption_execute_queue_remainder_output_opening_commitment_v2(
    value: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<Hash32, ProofErrorV2> {
    let stable_id = match value.role {
        BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder { redemption_id, .. } => {
            redemption_id
        }
        _ => return Err(ProofErrorV2::BindingMismatch("execution remainder role")),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::ExecutionQueueRemainderOutput,
        stable_id,
        configuration.bond_asset_id,
        value.amount,
        configuration.bond_redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
    .map_err(ProofErrorV2::Settlement)
}

fn find_collateral_output(
    settlement: &TransitionSettlementV2,
    action_id: Hash32,
    predicate: impl Fn(&CollateralOutputRoleV2) -> bool,
) -> Result<&CollateralOutputOpeningV2, ProofErrorV2> {
    unique(
        settlement
            .collateral_outputs
            .iter()
            .filter(|opening| predicate(&opening.role)),
        action_id,
    )
}

fn find_bond_input(
    settlement: &TransitionSettlementV2,
    action_id: Hash32,
    predicate: impl Fn(&BondInputRoleV2) -> bool,
) -> Result<&BondInputOpeningV2, ProofErrorV2> {
    unique(
        settlement
            .bond_inputs
            .iter()
            .filter(|opening| predicate(&opening.role)),
        action_id,
    )
}

fn find_bond_output(
    settlement: &TransitionSettlementV2,
    action_id: Hash32,
    predicate: impl Fn(&BondOutputRoleV2) -> bool,
) -> Result<&BondOutputOpeningV2, ProofErrorV2> {
    unique(
        settlement
            .bond_outputs
            .iter()
            .filter(|opening| predicate(&opening.role)),
        action_id,
    )
}

fn unique<'a, T>(
    mut values: impl Iterator<Item = &'a T>,
    _action_id: Hash32,
) -> Result<&'a T, ProofErrorV2> {
    let value = values
        .next()
        .ok_or(ProofErrorV2::BindingMismatch("action settlement opening"))?;
    if values.next().is_some() {
        return Err(ProofErrorV2::BindingMismatch(
            "duplicate action settlement opening",
        ));
    }
    Ok(value)
}

fn prior_queue_by_id(
    transition: &TransitionWitnessV2,
) -> Result<BTreeMap<Hash32, RedemptionQueueEntryV2>, ProofErrorV2> {
    let mut entries = BTreeMap::new();
    for entry in &transition.previous_redemption_queue {
        if entries.insert(entry.request_id, *entry).is_some() {
            return Err(ProofErrorV2::BindingMismatch(
                "duplicate redemption request",
            ));
        }
    }
    Ok(entries)
}

fn require_signed_subscription_allocation(
    action: &ecx_protocol_core::BondSubscriptionV2,
    collateral: &CollateralOutputOpeningV2,
    bond: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<(), ProofErrorV2> {
    let id = action.subscription_id();
    let collateral_id = match collateral.role {
        CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id } => subscription_id,
        _ => {
            return Err(ProofErrorV2::BindingMismatch(
                "subscription collateral role",
            ));
        }
    };
    let (bond_id, recipient) = match bond.role {
        BondOutputRoleV2::Subscription {
            subscription_id,
            recipient_script_sha256,
        } => (subscription_id, recipient_script_sha256),
        _ => return Err(ProofErrorV2::BindingMismatch("subscription bond role")),
    };
    if collateral_id != id
        || bond_id != id
        || collateral.amount != action.contribution_usdd_atoms
        || bond.amount != action.issued_share_atoms
        || recipient != action.bond_recipient_script_sha256
        || subscription_usdd_output_opening_commitment_v2(collateral, configuration)?
            != action.usdd_output_opening_commitment
        || subscription_bond_output_opening_commitment_v2(bond, configuration)?
            != action.bond_output_opening_commitment
    {
        return Err(ProofErrorV2::BindingMismatch(
            "signed subscription allocation",
        ));
    }
    Ok(())
}

fn require_signed_enqueue_allocation(
    action: &ecx_protocol_core::RedemptionEnqueueV2,
    redemption_id: Hash32,
    source_entry: &ecx_protocol_core::BondInboxEntryV2,
    input: &BondInputOpeningV2,
    output: &BondOutputOpeningV2,
    configuration: &FrozenConfigurationV2,
) -> Result<(), ProofErrorV2> {
    let id = redemption_id;
    let claimant = action.claimant_commitment();
    if source_entry.marker.signer != action.claimant
        || source_entry.marker.chain_id != action.chain_id
        || source_entry.marker.configuration_hash != action.configuration_hash
        || source_entry.marker.staging_intent_id != action.stable_intent_id()
        || source_entry.marker.refund_script_sha256 != action.refund_script_sha256
        || source_entry.marker.refund_not_before_parent_height
            != action.refund_not_before_parent_height
    {
        return Err(ProofErrorV2::BindingMismatch(
            "enqueue marker renderer context",
        ));
    }
    let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
        chain_id: source_entry.marker.chain_id,
        configuration_hash: source_entry.marker.configuration_hash,
        marker_signer: source_entry.marker.signer,
        stable_intent_id: source_entry.marker.staging_intent_id,
        staging_vout: source_entry.marker.staging_vout,
        refund_script_sha256: source_entry.marker.refund_script_sha256,
        refund_not_before_parent_height: source_entry.marker.refund_not_before_parent_height,
    };
    let (input_id, staging_intent, input_claimant, staging_script, source_txid, source_vout) =
        match input.role {
            BondInputRoleV2::StagedRedemptionEnqueue {
                redemption_id,
                staging_intent_id,
                claimant,
                staging_script_sha256,
                source_txid,
                source_vout,
            } => (
                redemption_id,
                staging_intent_id,
                claimant,
                staging_script_sha256,
                source_txid,
                source_vout,
            ),
            _ => return Err(ProofErrorV2::BindingMismatch("enqueue bond input role")),
        };
    let (output_id, output_staging_intent, output_claimant, destination) = match output.role {
        BondOutputRoleV2::QueuedRedemptionEntry {
            redemption_id,
            staging_intent_id,
            claimant,
            destination_script_sha256,
        } => (
            redemption_id,
            staging_intent_id,
            claimant,
            destination_script_sha256,
        ),
        _ => return Err(ProofErrorV2::BindingMismatch("enqueue bond output role")),
    };
    if input_id != id
        || output_id != id
        || staging_intent != action.stable_intent_id()
        || output_staging_intent != action.stable_intent_id()
        || source_txid != source_entry.source_txid
        || source_vout != source_entry.marker.staging_vout
        || input.previous_vout != source_entry.marker.staging_vout
        || input.amount != action.requested_share_atoms
        || output.amount != action.requested_share_atoms
        || input_claimant != claimant
        || output_claimant != claimant
        || staging_script
            != ecx_elements_settlement::bond_inbox_redemption_staging_script_sha256_v2(
                configuration,
                renderer_input,
            )?
        || destination != action.destination_script_hash
        || redemption_enqueue_bond_input_opening_commitment_v2(input, configuration)?
            != action.bond_input_opening_commitment
        || redemption_enqueue_queue_output_opening_commitment_v2(output, configuration)?
            != action.queue_output_opening_commitment
    {
        return Err(ProofErrorV2::BindingMismatch(
            "signed redemption enqueue allocation",
        ));
    }
    Ok(())
}

fn verify_settlement_binding_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    let transition = &input.transition;
    let settlement = &input.transition_settlement;
    let mut queue_by_id = prior_queue_by_id(transition)?;
    let mut actions = Vec::new();

    for signed in &transition.subscriptions {
        let action = &signed.action;
        let id = action.subscription_id();
        let collateral = find_collateral_output(
            settlement,
            id,
            |role| matches!(role, CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id } if *subscription_id == id),
        )?;
        let bond = find_bond_output(
            settlement,
            id,
            |role| matches!(role, BondOutputRoleV2::Subscription { subscription_id, .. } if *subscription_id == id),
        )?;
        require_signed_subscription_allocation(action, collateral, bond, &input.configuration)?;
        actions.push(BondSettlementActionV2::Subscription {
            subscription_id: id,
            usdd_contribution_amount: action.contribution_usdd_atoms,
            bond_share_amount: action.issued_share_atoms,
            recipient_script_sha256: action.bond_recipient_script_sha256,
        });
    }
    for signed in &transition.recapitalization_contributions {
        let action = &signed.action;
        let id = action.contribution_id();
        let collateral = find_collateral_output(settlement, id, |role| {
            matches!(
                role,
                CollateralOutputRoleV2::InsuranceRecapitalizationContribution {
                    contribution_id
                } if *contribution_id == id
            )
        })?;
        if collateral.amount != action.contribution_usdd_atoms
            || recapitalization_usdd_output_opening_commitment_v2(collateral, &input.configuration)?
                != action.insurance_output_opening_commitment
            || action.issued_share_atoms != 0
            || action.bond_output_opening_commitment != [0; 32]
        {
            return Err(ProofErrorV2::BindingMismatch(
                "signed insurance recapitalization allocation",
            ));
        }
        actions.push(
            BondSettlementActionV2::InsuranceRecapitalizationContribution {
                contribution_id: id,
                usdd_contribution_amount: action.contribution_usdd_atoms,
            },
        );
    }

    // FIFO sequence is assigned by the authenticated consumed inbox order,
    // never by producer-selected settlement ordering. Rejections do not
    // advance the tail, so derive each accepted request from its exact entry.
    let consumed_count = transition.bond_inbox.consumed_evidence.len();
    let consumed_entries = transition
        .bond_inbox
        .pending_entries
        .iter()
        .take(consumed_count);
    let mut accepted_enqueues = transition.redemption_enqueues.iter();
    let mut assigned_sequence = transition.previous_state.bond.redemption_tail;
    let mut enqueue_assignments = Vec::new();
    for (entry, outcome) in consumed_entries.zip(&transition.bond_inbox_outcomes) {
        if outcome.entry_index != entry.index || outcome.entry_hash != entry.entry_hash() {
            return Err(ProofErrorV2::BindingMismatch(
                "bond inbox outcome source entry",
            ));
        }
        if outcome.disposition == BondInboxProcessedDispositionV2::Accepted
            && outcome.marker_kind == ecx_protocol_core::BondInboxActionKindV2::RedemptionEnqueue
        {
            let signed = accepted_enqueues
                .next()
                .ok_or(ProofErrorV2::BindingMismatch("accepted enqueue projection"))?;
            if signed.action.action_id() != outcome.marker_action_id {
                return Err(ProofErrorV2::BindingMismatch("accepted enqueue action"));
            }
            let queue_entry = signed.action.queue_entry(
                assigned_sequence,
                entry.entry_hash(),
                entry.observed_parent_height,
            )?;
            enqueue_assignments.push((signed, entry, queue_entry));
            assigned_sequence = assigned_sequence
                .checked_add(1)
                .ok_or(ProofErrorV2::BindingMismatch("redemption queue tail"))?;
        }
    }
    if accepted_enqueues.next().is_some()
        || assigned_sequence != transition.next_state.bond.redemption_tail
    {
        return Err(ProofErrorV2::BindingMismatch(
            "accepted enqueue FIFO projection",
        ));
    }

    for (signed, source_entry, queue_entry) in enqueue_assignments {
        let action = &signed.action;
        let id = queue_entry.request_id;
        let input_opening = find_bond_input(
            settlement,
            id,
            |role| matches!(role, BondInputRoleV2::StagedRedemptionEnqueue { redemption_id, .. } if *redemption_id == id),
        )?;
        let output_opening = find_bond_output(
            settlement,
            id,
            |role| matches!(role, BondOutputRoleV2::QueuedRedemptionEntry { redemption_id, .. } if *redemption_id == id),
        )?;
        let claimant = action.claimant_commitment();
        require_signed_enqueue_allocation(
            action,
            id,
            source_entry,
            input_opening,
            output_opening,
            &input.configuration,
        )?;
        if queue_by_id.insert(id, queue_entry).is_some() {
            return Err(ProofErrorV2::BindingMismatch(
                "duplicate redemption request",
            ));
        }
        actions.push(BondSettlementActionV2::EnqueueRedemption {
            redemption_id: id,
            staging_intent_id: action.stable_intent_id(),
            claimant,
            bond_share_amount: action.requested_share_atoms,
            staging_script_sha256:
                ecx_elements_settlement::bond_inbox_redemption_staging_script_sha256_v2(
                    &input.configuration,
                    BondInboxRedemptionStagingRendererInputV2 {
                        chain_id: source_entry.marker.chain_id,
                        configuration_hash: source_entry.marker.configuration_hash,
                        marker_signer: source_entry.marker.signer,
                        stable_intent_id: source_entry.marker.staging_intent_id,
                        staging_vout: source_entry.marker.staging_vout,
                        refund_script_sha256: source_entry.marker.refund_script_sha256,
                        refund_not_before_parent_height: source_entry
                            .marker
                            .refund_not_before_parent_height,
                    },
                )?,
            source_txid: source_entry.source_txid,
            source_vout: source_entry.marker.staging_vout,
            source_authorization_commitment: source_entry.marker.source_authorization_commitment,
            refund_script_sha256: action.refund_script_sha256,
            refund_not_before_parent_height: action.refund_not_before_parent_height,
            destination_script_sha256: action.destination_script_hash,
        });
    }
    for signed in &transition.redemption_cancellations {
        let action = &signed.action;
        let id = action.request_id;
        let entry = queue_by_id
            .get(&id)
            .copied()
            .ok_or(ProofErrorV2::BindingMismatch("cancellation queue entry"))?;
        let input_opening = find_bond_input(
            settlement,
            id,
            |role| matches!(role, BondInputRoleV2::QueuedRedemption { redemption_id } if *redemption_id == id),
        )?;
        let output_opening = find_bond_output(
            settlement,
            id,
            |role| matches!(role, BondOutputRoleV2::CancelledRedemptionReturn { redemption_id, .. } if *redemption_id == id),
        )?;
        let (output_claimant, recipient, cancellation_id) = match output_opening.role {
            BondOutputRoleV2::CancelledRedemptionReturn {
                claimant,
                recipient_script_sha256,
                cancellation_id,
                ..
            } => (claimant, recipient_script_sha256, cancellation_id),
            _ => unreachable!("filtered above"),
        };
        let expected_cancellation_id = action.cancellation_id();
        if input_opening.amount != entry.remaining_share_atoms
            || output_opening.amount != entry.remaining_share_atoms
            || output_claimant != entry.claimant_commitment
            || recipient != action.bond_recipient_script_sha256
            || cancellation_id != expected_cancellation_id
            || redemption_cancel_queue_input_opening_commitment_v2(
                input_opening,
                &input.configuration,
            )? != action.queue_input_opening_commitment
            || redemption_cancel_bond_return_opening_commitment_v2(
                output_opening,
                &input.configuration,
            )? != action.bond_return_output_opening_commitment
        {
            return Err(ProofErrorV2::BindingMismatch(
                "signed redemption cancellation allocation",
            ));
        }
        actions.push(BondSettlementActionV2::CancelRedemption {
            redemption_id: id,
            claimant: entry.claimant_commitment,
            bond_share_amount: entry.remaining_share_atoms,
            recipient_script_sha256: action.bond_recipient_script_sha256,
            cancellation_id,
        });
        queue_by_id.remove(&id);
    }
    for action in &transition.redemption_executions {
        let id = action.request_id;
        let entry = queue_by_id
            .get(&id)
            .copied()
            .ok_or(ProofErrorV2::BindingMismatch("execution queue entry"))?;
        let input_opening = find_bond_input(
            settlement,
            id,
            |role| matches!(role, BondInputRoleV2::QueuedRedemption { redemption_id } if *redemption_id == id),
        )?;
        let inventory = find_bond_output(
            settlement,
            id,
            |role| matches!(role, BondOutputRoleV2::RedemptionInventoryReturn { redemption_id } if *redemption_id == id),
        )?;
        let payment = find_collateral_output(
            settlement,
            id,
            |role| matches!(role, CollateralOutputRoleV2::BondRedemptionPayment { redemption_id, .. } if *redemption_id == id),
        )?;
        let paid = u64::try_from(action.paid_usdd_atoms)
            .map_err(|_| ProofErrorV2::BindingMismatch("redemption payment range"))?;
        let remainder = entry
            .remaining_share_atoms
            .checked_sub(action.redeemed_share_atoms)
            .ok_or(ProofErrorV2::BindingMismatch("redemption execution amount"))?;
        if remainder == 0 {
            let unexpected_remainder = settlement.bond_outputs.iter().any(|opening| {
                matches!(
                    opening.role,
                    BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
                        redemption_id,
                        ..
                    } if redemption_id == id
                )
            });
            if action.queue_remainder_output_opening_commitment != [0; 32] || unexpected_remainder {
                return Err(ProofErrorV2::BindingMismatch(
                    "full redemption remainder opening",
                ));
            }
        } else {
            let remainder_opening = find_bond_output(settlement, id, |role| {
                matches!(
                    role,
                    BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
                        redemption_id,
                        ..
                    } if *redemption_id == id
                )
            })?;
            let (claimant, destination) = match remainder_opening.role {
                BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
                    claimant,
                    destination_script_sha256,
                    ..
                } => (claimant, destination_script_sha256),
                _ => unreachable!("filtered above"),
            };
            if remainder_opening.amount != remainder
                || claimant != entry.claimant_commitment
                || destination != entry.destination_script_hash
                || redemption_execute_queue_remainder_output_opening_commitment_v2(
                    remainder_opening,
                    &input.configuration,
                )? != action.queue_remainder_output_opening_commitment
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "partial redemption remainder opening",
                ));
            }
        }
        let payment_destination = match payment.role {
            CollateralOutputRoleV2::BondRedemptionPayment {
                recipient_script_sha256,
                ..
            } => recipient_script_sha256,
            _ => unreachable!("filtered above"),
        };
        if input_opening.amount != entry.remaining_share_atoms
            || inventory.amount != action.redeemed_share_atoms
            || payment.amount != paid
            || payment_destination != entry.destination_script_hash
            || redemption_execute_queue_input_opening_commitment_v2(
                input_opening,
                &input.configuration,
            )? != action.queue_input_opening_commitment
            || redemption_execute_usdd_output_opening_commitment_v2(payment, &input.configuration)?
                != action.usdd_output_opening_commitment
            || redemption_execute_inventory_output_opening_commitment_v2(
                inventory,
                &input.configuration,
            )? != action.inventory_output_opening_commitment
        {
            return Err(ProofErrorV2::BindingMismatch(
                "redemption execution allocation",
            ));
        }
        actions.push(BondSettlementActionV2::ExecuteRedemption {
            redemption_id: id,
            claimant: entry.claimant_commitment,
            queued_share_amount: entry.remaining_share_atoms,
            redeemed_share_amount: action.redeemed_share_atoms,
            remainder_share_amount: remainder,
            usdd_payment_amount: paid,
            destination_script_sha256: entry.destination_script_hash,
        });
        if remainder == 0 {
            queue_by_id.remove(&id);
        } else if let Some(entry) = queue_by_id.get_mut(&id) {
            entry.remaining_share_atoms = remainder;
        }
    }

    let withdrawals = transition_withdrawals(&transition.base)?;
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: input.configuration.bond_asset_id,
        inventory_vault_script_sha256: input.configuration.bond_inventory_script_sha256,
        redemption_queue_script_sha256: input.configuration.bond_redemption_queue_script_sha256,
        reissuance_token_burn_script_sha256: input
            .configuration
            .destroyed_reissuance_token_script_sha256,
    };
    let verified = verify_transition_settlement_v2(
        settlement,
        &withdrawals,
        &actions,
        input.configuration.base.usdd_asset_id,
        input.configuration.base.collateral_vault_script_sha256,
        input.configuration.insurance_reserve_script_sha256,
        &frozen,
    )?;
    let next = transition.next_state.bond;
    let prior = transition.previous_state.bond;
    let next_inventory = verified
        .bond_inventory_change_total
        .checked_add(verified.redemption_inventory_return_total)
        .ok_or(ProofErrorV2::BindingMismatch("inventory amount"))?;
    if verified.transition_txid != input.binding.transition_txid_consensus
        || verified.combined_settlement_root != transition.base.public.collateral_settlement_root
        || verified.forced_processed_cursor != transition.next_state.base.forced_inbox.cursor
        || verified.deposit_processed_cursor != transition.next_state.base.deposit_inbox.cursor
        || u128::from(verified.insurance_reserve_input_total) != prior.insurance_reserve
        || u128::from(verified.insurance_reserve_output_total) != next.insurance_reserve
        || verified.bond_inventory_input_total != prior.inventory_share_atoms
        || next_inventory != next.inventory_share_atoms
    {
        return Err(ProofErrorV2::BindingMismatch("unified settlement"));
    }
    Ok(())
}

pub fn bond_public_state_root_v2(state: &BondPublicStateV2) -> Hash32 {
    tagged_hash("ECX/bond-public-state/v2", &state.canonical_bytes())
}

/// Non-circular public context for the encrypted V2 recovery bundle.
pub fn transition_availability_context_v2(transition: &TransitionWitnessV2) -> Hash32 {
    let base_context = crate::transition_availability_context(&transition.base.public);
    let mut neutral = transition.public.clone();
    neutral.next_state_root = [0; 32];
    neutral.base_public_digest = [0; 32];
    let mut preimage = Vec::with_capacity(32 + neutral.canonical_bytes().len());
    preimage.extend_from_slice(&base_context);
    preimage.extend_from_slice(&neutral.canonical_bytes());
    tagged_hash(
        "ECX/transition-availability-context/v4-recovery-shares-v2",
        &preimage,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityRecoveryPayloadV2 {
    pub version: u8,
    pub configuration_hash: Hash32,
    pub transition: TransitionWitnessV2,
    pub matcher_receipts: Vec<CentralMatcherReceiptV1>,
    pub truthcoin_consensus_proof: TruthcoinConsensusProofV1,
    pub ecx_btc_conversion_proof: ConversionLegConsensusProofV2,
    pub usdd_usd_conversion_proof: ConversionLegConsensusProofV2,
    pub deposit_openings: Vec<ConfidentialDepositOpeningV1>,
    pub transition_settlement: TransitionSettlementV2,
    pub bond_inbox_sources: Vec<BondInboxRecoverySourceReferenceV2>,
    pub funding_parent_chain: FundingParentChainWitnessV2,
}

/// Compact private recovery data for every consumed entry in one public,
/// content-addressed source transaction. The full transaction is intentionally
/// not duplicated here: a failover prover must fetch its canonical bytes by
/// `source_wtxid` from an archival Elements node and re-run exact source
/// admission. The encrypted bundle, exact receipt wrappers and recovery shares
/// are retained because the shares are not available from that public chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInboxRecoverySourceReferenceV2 {
    pub source_wtxid: Hash32,
    pub entries: Vec<BondInboxRecoveryEntryV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInboxRecoveryEntryV2 {
    pub entry_index: u64,
    pub source_entry_hash: Hash32,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub custody_receipts: Vec<BondInboxCustodyReceiptV2>,
    /// Exactly three signed private Shamir shares, encrypted as part of the
    /// main transition availability bundle and never projected publicly.
    pub recovery_contributions: Vec<RecoveryContribution>,
}

/// Encrypt every non-chain input needed to reconstruct the canonical V2
/// witness. Large public transaction bytes remain fetchable from an archival
/// node by their committed txids/wtxids; the payload retains the private bond
/// inbox recovery shares and the exact encrypted-bundle/receipt projection
/// needed to rebuild each source-evidence record. Full compressed SP1 receipts
/// and verifying keys are likewise public, content-addressed release artifacts;
/// their exact public values, program identities (in configuration), and
/// deferred-proof markers are included here so substitution is detectable.
pub fn canonical_availability_recovery_payload_v2(
    input: &ProofInputV2,
) -> Result<Vec<u8>, ProofErrorV2> {
    let mut neutral_transition = input.transition.clone();
    neutral_transition.base.public.batch_hash = [0; 32];
    neutral_transition.base.public.next_state_root = [0; 32];
    neutral_transition.base.public.encrypted_availability_root = [0; 32];
    neutral_transition.base.next_state.roots.order_receipts = [0; 32];
    // `TransitionWitnessV2` deliberately carries the base successor both in
    // `base.next_state` and in `next_state.base` so the additive state can be
    // checked for exact linkage. Neutralize both copies: the receipt root is
    // downstream of the encrypted bundle root and leaving this duplicate live
    // would make the canonical recovery payload require a hash fixed point.
    neutral_transition.next_state.base.roots.order_receipts = [0; 32];
    neutral_transition.public.next_state_root = [0; 32];
    neutral_transition.public.base_public_digest = [0; 32];

    let mut private_deposits = input.deposit_openings.clone();
    for opening in &mut private_deposits {
        opening.transaction.clear();
    }
    let mut private_settlement = input.transition_settlement.clone();
    private_settlement.transaction.clear();
    for opening in &mut private_settlement.collateral_inputs {
        opening.previous_transaction.clear();
    }
    for opening in &mut private_settlement.bond_inputs {
        opening.previous_transaction.clear();
    }
    let payload = AvailabilityRecoveryPayloadV2 {
        version: AVAILABILITY_RECOVERY_PAYLOAD_VERSION_V2,
        configuration_hash: input.configuration.digest(),
        transition: neutral_transition,
        matcher_receipts: input.matcher_receipts.clone(),
        truthcoin_consensus_proof: input.truthcoin_consensus_proof.clone(),
        ecx_btc_conversion_proof: input.ecx_btc_conversion_proof.clone(),
        usdd_usd_conversion_proof: input.usdd_usd_conversion_proof.clone(),
        deposit_openings: private_deposits,
        transition_settlement: private_settlement,
        bond_inbox_sources: bond_inbox_recovery_source_references_v2(input)?,
        funding_parent_chain: input.funding_parent_chain.clone(),
    };
    let encoded_bond_inbox_sources = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialize(&payload.bond_inbox_sources)
        .map_err(|_| ProofErrorV2::AvailabilityPayloadEncoding)?;
    if encoded_bond_inbox_sources.len() > MAX_BOND_INBOX_RECOVERY_TABLE_BYTES_V2 {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox recovery table size",
        ));
    }
    let mut without_bond_inbox_sources = payload.clone();
    without_bond_inbox_sources.bond_inbox_sources.clear();
    let encoded_without_bond_inbox = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialize(&without_bond_inbox_sources)
        .map_err(|_| ProofErrorV2::AvailabilityPayloadEncoding)?;
    if encoded_without_bond_inbox.len() > MAX_NON_BOND_INBOX_RECOVERY_PAYLOAD_BYTES_V2 {
        return Err(ProofErrorV2::BindingMismatch(
            "non-bond-inbox recovery payload size",
        ));
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialize(&payload)
        .map_err(|_| ProofErrorV2::AvailabilityPayloadEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_WITNESS_BYTES {
        return Err(ProofErrorV2::BindingMismatch(
            "availability recovery payload size",
        ));
    }
    Ok(encoded)
}

/// Decode the exact fixed-integer, big-endian recovery envelope. Trailing bytes
/// are rejected so a recovered witness has one canonical representation.
pub fn decode_availability_recovery_payload_v2(
    encoded: &[u8],
) -> Result<AvailabilityRecoveryPayloadV2, ProofErrorV2> {
    if encoded.is_empty() || encoded.len() > MAX_WITNESS_BYTES {
        return Err(ProofErrorV2::BindingMismatch(
            "availability recovery payload size",
        ));
    }
    let payload: AvailabilityRecoveryPayloadV2 = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .deserialize(encoded)
        .map_err(|_| ProofErrorV2::AvailabilityPayloadEncoding)?;
    if payload.version != AVAILABILITY_RECOVERY_PAYLOAD_VERSION_V2 {
        return Err(ProofErrorV2::UnsupportedVersion);
    }
    Ok(payload)
}

fn bond_inbox_recovery_source_references_v2(
    input: &ProofInputV2,
) -> Result<Vec<BondInboxRecoverySourceReferenceV2>, ProofErrorV2> {
    let consumed_count = input.transition.bond_inbox.consumed_evidence.len();
    let consumed_entries = input
        .transition
        .bond_inbox
        .pending_entries
        .iter()
        .take(consumed_count)
        .zip(&input.transition.bond_inbox.consumed_evidence)
        .filter(|(_, evidence)| {
            !matches!(
                evidence,
                BondInboxConsumedEvidenceV2::ExpiredUnavailable { .. }
            )
        })
        .map(|(entry, _)| (entry.index, entry))
        .collect::<BTreeMap<_, _>>();
    if input.transition.bond_inbox.pending_entries.len() < consumed_count {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox recovery source coverage",
        ));
    }
    let mut seen_indices = BTreeSet::new();
    let mut references = Vec::with_capacity(input.bond_inbox_source_evidence.len());
    for source in &input.bond_inbox_source_evidence {
        let mut entries = Vec::with_capacity(source.entries.len());
        for evidence in &source.entries {
            let entry = consumed_entries.get(&evidence.entry_index).ok_or(
                ProofErrorV2::BindingMismatch("unused bond inbox recovery source"),
            )?;
            if entry.source_wtxid != source.source_wtxid
                || !seen_indices.insert(evidence.entry_index)
            {
                return Err(ProofErrorV2::BindingMismatch(
                    "bond inbox recovery source reference",
                ));
            }
            entries.push(BondInboxRecoveryEntryV2 {
                entry_index: evidence.entry_index,
                source_entry_hash: entry.entry_hash(),
                canonical_encrypted_bundle: evidence.canonical_encrypted_bundle.clone(),
                custody_receipts: evidence.custody_receipts.clone(),
                recovery_contributions: evidence.recovery_contributions.clone(),
            });
        }
        references.push(BondInboxRecoverySourceReferenceV2 {
            source_wtxid: source.source_wtxid,
            entries,
        });
    }
    if seen_indices.len() != consumed_entries.len() {
        return Err(ProofErrorV2::BindingMismatch(
            "bond inbox recovery source coverage",
        ));
    }
    Ok(references)
}

fn verify_availability_binding_v2(input: &ProofInputV2) -> Result<(), ProofErrorV2> {
    if input.availability_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ProofErrorV2::BindingMismatch("availability bundle size"));
    }
    let bundle = WitnessBundle::decode(&input.availability_bundle).map_err(availability_error)?;
    let configured = &input.configuration.base.availability;
    if availability_scheme_hash() != AVAILABILITY_SCHEME_HASH_V1
        || configured.scheme_hash != AVAILABILITY_SCHEME_HASH_V1
        || usize::from(configured.recovery_threshold) != RECOVERY_THRESHOLD
        || usize::from(configured.custodian_count) != CUSTODIAN_COUNT
        || configured.recovery_threshold != AVAILABILITY_RECOVERY_THRESHOLD
        || configured.custodian_count != AVAILABILITY_CUSTODIAN_COUNT
        || configured.maximum_witness_bytes != MAX_AVAILABILITY_WITNESS_BYTES
        || usize::try_from(configured.maximum_witness_bytes)
            .map_err(|_| ProofErrorV2::BindingMismatch("availability maximum witness size"))?
            != MAX_WITNESS_BYTES
    {
        return Err(ProofErrorV2::BindingMismatch("availability scheme"));
    }
    let custodians: Vec<CustodianPublic> = bundle
        .custodians
        .iter()
        .map(|envelope| envelope.public)
        .collect();
    if custodian_registry_hash(&custodians).map_err(availability_error)?
        != configured.custodian_registry_hash
    {
        return Err(ProofErrorV2::BindingMismatch(
            "availability custodian registry",
        ));
    }
    if bundle.context != transition_availability_context_v2(&input.transition) {
        return Err(ProofErrorV2::BindingMismatch("availability context"));
    }
    let root = bundle.root().map_err(availability_error)?;
    if root != input.transition.base.public.encrypted_availability_root
        || root != input.binding.next.encrypted_availability_root
    {
        return Err(ProofErrorV2::BindingMismatch("availability bundle root"));
    }
    verify_custody_receipts(&bundle, &input.availability_custody_receipts)
        .map_err(availability_error)?;
    let payload = canonical_availability_recovery_payload_v2(input)?;
    if bundle.witness_len
        != u64::try_from(payload.len())
            .map_err(|_| ProofErrorV2::BindingMismatch("availability payload size"))?
    {
        return Err(ProofErrorV2::BindingMismatch("availability payload size"));
    }
    verify_bundle_encryption(&bundle, &input.availability_encryption_witness, &payload)
        .map_err(availability_error)?;
    Ok(())
}

fn availability_error(error: AvailabilityError) -> ProofErrorV2 {
    ProofErrorV2::Availability(error.to_string())
}

fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ecx_protocol_core::{
        matcher_execution_receipt_batch_root_v2, Amount, CentralMatcherConfigV1, LimitOrder,
        MatcherExecutionReceiptV2, MatcherReceiptBodyV1, Price, Quantity, Side, SignedLimitOrder,
        TimeInForce, TradeMatch, XOnlyKey, ECX_USDD_MARKET, PRICE_SCALE,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    #[test]
    fn dependency_neutral_availability_identity_matches_crypto_implementation() {
        assert_eq!(AVAILABILITY_SCHEME_HASH_V1, availability_scheme_hash());
    }

    fn matcher_test_key(secret: &SecretKey) -> XOnlyKey {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        XOnlyKey(public.serialize())
    }

    fn matcher_test_order(
        secret: &SecretKey,
        chain_id: Hash32,
        side: Side,
        nonce: u64,
    ) -> SignedLimitOrder {
        SignedLimitOrder::sign(
            LimitOrder {
                version: LimitOrder::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: matcher_test_key(secret),
                side,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(25).unwrap(),
                client_order_id: [nonce as u8; 16],
                max_fee_bps: 25,
                nonce,
                valid_from_height: 1,
                expires_at_height: 500,
            },
            secret,
        )
        .unwrap()
    }

    fn matcher_admission_fixture() -> (
        CentralMatcherConfigV1,
        SecretKey,
        MatchedOrderPair,
        CentralMatcherReceiptV1,
        MatcherExecutionReceiptV2,
    ) {
        let matcher_secret = SecretKey::from_slice(&[41; 32]).unwrap();
        let maker_secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let taker_secret = SecretKey::from_slice(&[43; 32]).unwrap();
        let chain_id = [44; 32];
        let configuration = CentralMatcherConfigV1 {
            version: CentralMatcherConfigV1::VERSION,
            key_epoch: 7,
            signer: matcher_test_key(&matcher_secret),
            genesis_sequence: 10,
            genesis_receipt_hash: [45; 32],
            forced_inclusion_blocks: 6,
        };
        let maker = matcher_test_order(&maker_secret, chain_id, Side::Sell, 1);
        let taker = matcher_test_order(&taker_secret, chain_id, Side::Buy, 2);
        let trade = TradeMatch {
            sequence: 11,
            maker_order_id: maker.order_id(),
            taker_order_id: taker.order_id(),
            maker: maker.order.trader,
            taker: taker.order.trader,
            maker_side: Side::Sell,
            price: maker.order.limit_price,
            quantity: Quantity::new(10).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(5),
        };
        let admission = CentralMatcherReceiptV1::sign(
            MatcherReceiptBodyV1 {
                version: MatcherReceiptBodyV1::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                matcher_config_hash: configuration.digest(),
                matcher_key_epoch: configuration.key_epoch,
                global_sequence: trade.sequence,
                previous_receipt_hash: configuration.genesis_receipt_hash,
                command_kind: MatcherCommandKind::Place,
                command_hash: matcher_order_command_hash(&taker),
                observed_sidechain_height: 100,
                observed_parent_height: 900,
                observed_parent_mtp: 1_700_000_000,
                forced_inbox_cursor: 0,
                availability_root: [46; 32],
            },
            &matcher_secret,
            &configuration,
        )
        .unwrap();
        let execution = MatcherExecutionReceiptV2::issue(
            &configuration,
            &matcher_secret,
            chain_id,
            &maker,
            &taker,
            &trade,
            18,
            &admission,
            [47; 32],
        )
        .unwrap();
        (
            configuration,
            matcher_secret,
            MatchedOrderPair {
                maker_order: maker,
                taker_order: taker,
                trade,
            },
            admission,
            execution,
        )
    }

    #[test]
    fn public_values_v5_length_is_exact() {
        const APPENDED_V5_BYTES: usize = 32 + 8 + 1 + 32 + 32 + 8 + 32 + 8 + 32 + 8 + 32 + 8 + 8;
        assert_eq!(APPENDED_V5_BYTES, 241);
        assert_eq!(PUBLIC_VALUES_V5_LEN, 609 + APPENDED_V5_BYTES);
    }

    #[test]
    fn public_values_v5_fixed_offsets_bind_new_consensus_projections() {
        let values = ProofPublicValuesV5 {
            transition_journal_domain_sha256: [0x01; 32],
            configuration_hash: [0x02; 32],
            current_state_hash: [0x03; 32],
            next_state_hash: [0x04; 32],
            transition_txid_consensus: [0x05; 32],
            prior_exchange_header_root: [0x06; 32],
            prior_parent_block_hash: [0x07; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [0x0a; 32],
            bond_asset_id: [0x0b; 32],
            bond_deployment_commitment: [0x0c; 32],
            bond_state_root: [0x0d; 32],
            redemption_queue_root: [0x0e; 32],
            funding_state_root: [0x0f; 32],
            conversion_legs_commitment: [0x10; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 22,
            authenticated_max_price: 23,
            funding_epoch: 24,
            funding_rate_ppm: -25,
            redemption_head: 26,
            redemption_tail: 27,
            queued_redemption_share_atoms: 28,
            oracle_certificate_hash: [0x11; 32],
            oracle_valid_through_mtp: 29,
            oracle_mode: 1,
            next_encrypted_availability_root: [0x12; 32],
            bond_inbox_head_root: [0x13; 32],
            bond_inbox_entry_count: 30,
            bond_inbox_processed_root: [0x14; 32],
            bond_inbox_cursor: 31,
            bond_inbox_outcome_root: [0x15; 32],
            bond_inbox_outcome_count: 32,
            matcher_execution_receipt_batch_root: [0x16; 32],
            previous_matcher_execution_sequence: 33,
            next_matcher_execution_sequence: 34,
        };
        let encoded = values.encode();
        assert_eq!(encoded.len(), PUBLIC_VALUES_V5_LEN);
        assert_eq!(&encoded[609..641], &[0x11; 32]);
        assert_eq!(&encoded[641..649], &29u64.to_be_bytes());
        assert_eq!(encoded[649], 1);
        assert_eq!(&encoded[650..682], &[0x12; 32]);
        assert_eq!(&encoded[682..714], &[0x13; 32]);
        assert_eq!(&encoded[714..722], &30u64.to_be_bytes());
        assert_eq!(&encoded[722..754], &[0x14; 32]);
        assert_eq!(&encoded[754..762], &31u64.to_be_bytes());
        assert_eq!(&encoded[762..794], &[0x15; 32]);
        assert_eq!(&encoded[794..802], &32u64.to_be_bytes());
        assert_eq!(&encoded[802..834], &[0x16; 32]);
        assert_eq!(&encoded[834..842], &33u64.to_be_bytes());
        assert_eq!(&encoded[842..850], &34u64.to_be_bytes());
        assert_ne!(values.sha256(), [0; 32]);
    }

    #[test]
    fn v2_state_hash_appends_and_binds_new_roots() {
        let state = CovenantPublicStateV2 {
            version: COVENANT_STATE_VERSION_V2,
            sequence: 1,
            private_state_root: [1; 32],
            encrypted_availability_root: [2; 32],
            forced_action_inbox_root: [3; 32],
            deposit_inbox_root: [4; 32],
            configuration_hash: [5; 32],
            bond_state_root: [6; 32],
            funding_state_root: [7; 32],
            active_order_risk_root: [9; 32],
            position_risk_root: [10; 32],
            bond_inbox_head_root: [11; 32],
            bond_inbox_entry_count: 12,
            bond_inbox_processed_root: [13; 32],
            bond_inbox_cursor: 4,
            bond_inbox_outcome_root: [14; 32],
            bond_inbox_outcome_count: 4,
            matcher_execution_sequence: 15,
            last_transition_sidechain_height: 16,
        };
        let expected = state.state_hash([8; 32]);
        let mut changed = state.clone();
        changed.bond_state_root[0] ^= 1;
        assert_ne!(changed.state_hash([8; 32]), expected);
        changed = state.clone();
        changed.funding_state_root[0] ^= 1;
        assert_ne!(changed.state_hash([8; 32]), expected);
        changed = state.clone();
        changed.active_order_risk_root[0] ^= 1;
        assert_ne!(changed.state_hash([8; 32]), expected);
        changed = state;
        changed.position_risk_root[0] ^= 1;
        assert_ne!(changed.state_hash([8; 32]), expected);
    }

    #[test]
    fn fail_closed_entrypoint_does_not_accept_unlinked_sources() {
        assert!(std::mem::size_of::<DenyAllConsensusProofs>() == 0);
    }

    #[test]
    fn logical_allocation_is_rebatchable_but_binds_every_economic_field() {
        let commitment = logical_allocation_commitment_v2(
            LogicalAllocationKindV2::SubscriptionInsuranceOutput,
            [1; 32],
            [2; 32],
            400,
            [3; 32],
            [4; 32],
            [5; 32],
        )
        .unwrap();
        // There is deliberately no transaction index or prior transaction in
        // the logical API, so alternate producer batching cannot alter it.
        assert_eq!(
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [2; 32],
                400,
                [3; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            commitment
        );
        for changed in [
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::RecapitalizationInsuranceOutput,
                [1; 32],
                [2; 32],
                400,
                [3; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [6; 32],
                [2; 32],
                400,
                [3; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [6; 32],
                400,
                [3; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [2; 32],
                401,
                [3; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [2; 32],
                400,
                [6; 32],
                [4; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [2; 32],
                400,
                [3; 32],
                [6; 32],
                [5; 32],
            )
            .unwrap(),
            logical_allocation_commitment_v2(
                LogicalAllocationKindV2::SubscriptionInsuranceOutput,
                [1; 32],
                [2; 32],
                400,
                [3; 32],
                [4; 32],
                [6; 32],
            )
            .unwrap(),
        ] {
            assert_ne!(changed, commitment);
        }
        assert!(logical_allocation_commitment_v2(
            LogicalAllocationKindV2::SubscriptionInsuranceOutput,
            [1; 32],
            [2; 32],
            400,
            [3; 32],
            [4; 32],
            [4; 32],
        )
        .is_err());
    }

    #[test]
    fn oracle_validity_endpoint_is_exact_stale_safe_and_mode_scoped() {
        assert_eq!(
            derive_oracle_valid_through_mtp_v2(1_100, OracleMode::Normal, 1_000, 1_090, 200, 30)
                .unwrap(),
            1_120
        );
        assert_eq!(
            derive_oracle_valid_through_mtp_v2(
                1_100,
                OracleMode::ReduceOnly,
                u64::MAX,
                u64::MAX,
                1,
                1
            )
            .unwrap(),
            1_100
        );
        assert!(derive_oracle_valid_through_mtp_v2(
            1_101,
            OracleMode::Normal,
            1_000,
            1_090,
            100,
            10
        )
        .is_err());
        assert!(
            derive_oracle_valid_through_mtp_v2(1, OracleMode::Normal, u64::MAX, 1, 1, 1).is_err()
        );
    }

    #[test]
    fn recovery_entry_codec_roundtrips_private_shares_and_rejects_trailing_bytes() {
        let source = BondInboxRecoverySourceReferenceV2 {
            source_wtxid: [1; 32],
            entries: vec![BondInboxRecoveryEntryV2 {
                entry_index: 7,
                source_entry_hash: [2; 32],
                canonical_encrypted_bundle: vec![3; 128],
                custody_receipts: (0..3)
                    .map(|custodian_index| BondInboxCustodyReceiptV2 {
                        custodian_index,
                        exact_receipt_bytes: vec![custodian_index; 138],
                    })
                    .collect(),
                recovery_contributions: (1..=3)
                    .map(|custodian_index| RecoveryContribution {
                        bundle_root: [4; 32],
                        custodian_index,
                        share: [custodian_index; 32],
                        signature: [custodian_index; 64],
                    })
                    .collect(),
            }],
        };
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(&source)
            .unwrap();
        let recovered: BondInboxRecoverySourceReferenceV2 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .reject_trailing_bytes()
            .deserialize(&bytes)
            .unwrap();
        assert_eq!(recovered, source);
        assert_eq!(
            recovered.entries[0].recovery_contributions[2].share,
            [3; 32]
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .reject_trailing_bytes()
            .deserialize::<BondInboxRecoverySourceReferenceV2>(&trailing)
            .is_err());
    }

    #[test]
    fn execution_receipt_is_bound_to_exact_admission_hash_and_observed_context() {
        let (configuration, matcher_secret, fill, admission, execution) =
            matcher_admission_fixture();
        let root = matcher_execution_receipt_batch_root_v2(std::slice::from_ref(&execution));
        verify_exact_matcher_execution_admissions_v2(
            &configuration,
            [44; 32],
            [47; 32],
            17,
            std::slice::from_ref(&fill),
            &BTreeSet::new(),
            std::slice::from_ref(&admission),
            std::slice::from_ref(&execution),
            root,
            18,
        )
        .unwrap();

        // A separately valid V1 receipt for the same command and sequence has
        // a different exact receipt hash and cannot be substituted.
        let mut alternate_body = admission.body.clone();
        alternate_body.availability_root[0] ^= 1;
        let alternate_hash =
            CentralMatcherReceiptV1::sign(alternate_body, &matcher_secret, &configuration).unwrap();
        assert!(verify_exact_matcher_execution_admissions_v2(
            &configuration,
            [44; 32],
            [47; 32],
            17,
            std::slice::from_ref(&fill),
            &BTreeSet::new(),
            std::slice::from_ref(&alternate_hash),
            std::slice::from_ref(&execution),
            root,
            18,
        )
        .is_err());

        // A validly signed admission carrying a different node-observed
        // sidechain/parent context also fails the exact verify_match relation.
        let mut alternate_context_body = admission.body.clone();
        alternate_context_body.observed_parent_mtp += 1;
        let alternate_context =
            CentralMatcherReceiptV1::sign(alternate_context_body, &matcher_secret, &configuration)
                .unwrap();
        assert!(verify_exact_matcher_execution_admissions_v2(
            &configuration,
            [44; 32],
            [47; 32],
            17,
            std::slice::from_ref(&fill),
            &BTreeSet::new(),
            std::slice::from_ref(&alternate_context),
            std::slice::from_ref(&execution),
            root,
            18,
        )
        .is_err());

        // Even a correctly signed execution receipt cannot be rebound to a
        // different authenticated transition parent hash.
        assert!(verify_exact_matcher_execution_admissions_v2(
            &configuration,
            [44; 32],
            [48; 32],
            17,
            std::slice::from_ref(&fill),
            &BTreeSet::new(),
            std::slice::from_ref(&admission),
            std::slice::from_ref(&execution),
            root,
            18,
        )
        .is_err());
    }

    #[test]
    fn worst_reachable_compact_bond_inbox_recovery_table_is_bounded() {
        // Sixty-four entries is the frozen per-transition maximum. This uses
        // the maximum encrypted bundle width for every entry, five exact 138-
        // byte custody receipts and exactly three private 129-byte recovery
        // contributions. Full source transactions are fetched by wtxid and do
        // not consume this encrypted recovery budget.
        let entries = (0..64u64)
            .map(|entry_index| BondInboxRecoveryEntryV2 {
                entry_index,
                source_entry_hash: [2; 32],
                canonical_encrypted_bundle: vec![3; 64 * 1024],
                custody_receipts: (0..5)
                    .map(|custodian_index| BondInboxCustodyReceiptV2 {
                        custodian_index,
                        exact_receipt_bytes: vec![custodian_index; 138],
                    })
                    .collect(),
                recovery_contributions: (1..=3)
                    .map(|custodian_index| RecoveryContribution {
                        bundle_root: [4; 32],
                        custodian_index,
                        share: [custodian_index; 32],
                        signature: [custodian_index; 64],
                    })
                    .collect(),
            })
            .collect();
        let table = vec![BondInboxRecoverySourceReferenceV2 {
            source_wtxid: [1; 32],
            entries,
        }];
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(&table)
            .unwrap();
        assert!(encoded.len() < MAX_BOND_INBOX_RECOVERY_TABLE_BYTES_V2);
        const {
            assert!(
                MAX_BOND_INBOX_RECOVERY_TABLE_BYTES_V2
                    + MAX_NON_BOND_INBOX_RECOVERY_PAYLOAD_BYTES_V2
                    < MAX_WITNESS_BYTES
            );
        }
    }
}
