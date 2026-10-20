//! Exact public-values boundary shared by the host tests and SP1 guest.
//!
//! The guest commits [`ProofResult::public_values`] verbatim. The Simplicity
//! covenant reconstructs SHA256 of those exact bytes. The verifier jet receives
//! that SHA256 digest, never a host-selected alternate digest algorithm.

#![forbid(unsafe_code)]

pub mod conversion_v2;
pub mod conversion_witness_v2;
pub mod ecx_execution_v1;
pub mod ecx_successor_state_v1;
pub mod ecx_match_input_v1;
pub mod ecx_withdrawal_input_v1;
pub mod ecx_cancellation_input_v1;
pub mod ecx_admission_input_v1;
pub mod ecx_liquidation_input_v1;
mod ecx_owned_vault_v1;
pub mod funding_parent_chain_v2;
pub mod incremental_account_action_child_v2;
pub mod incremental_activation_v2;
pub mod incremental_bond_action_child_v2;
pub mod incremental_deficit_child_v2;
pub mod incremental_deposit_source_child_v2;
pub mod incremental_economic_action_child_v2;
pub mod incremental_forced_action_child_v2;
pub mod incremental_funding_oracle_child_v2;
pub mod incremental_inbox_source_child_v2;
pub mod incremental_nullifier_child_v2;
pub mod incremental_order_child_v2;
pub mod incremental_previous_transaction_child_v2;
pub mod incremental_recovery_budget_v2;
pub mod incremental_recursive_availability_v2;
pub mod incremental_risk_child_v2;
pub mod incremental_settlement_child_v2;
pub mod incremental_source_transaction_child_v2;
pub mod incremental_successor_proof_v2;
pub mod incremental_trader_child_v2;
pub mod proof_v2;
pub mod usdd_checkpoint_authority_v3;
pub mod usdd_elements_source_v2;
pub mod usdd_usd_conversion_v2;
pub mod usdd_usd_ownerless_v3;

pub use conversion_v2::{
    derive_authenticated_price_range_v2, derive_direct_native_truthcoin_price_range_v2,
    verify_authenticated_conversion_legs_v2, AuthenticatedConversionLegsV2,
    ConversionLegConsensusProofV2, ConversionLegErrorV2, ConversionLegKindV2,
    ConversionLegPublicValuesV2, CONVERSION_LEG_PUBLIC_VALUES_LEN_V2,
    CONVERSION_LEG_PUBLIC_VALUES_VERSION_V2,
};
pub use conversion_witness_v2::{
    execute_ecx_btc_conversion_producer_v2, execute_usdd_usd_conversion_producer_v2,
    BitcoinAuthenticatedHistoryWitnessV2, ConfidentialOpeningRecordV2, ConversionProducerErrorV2,
    EcxBtcConversionProducerInputV2, ElementsAuthenticatedStateWitnessV2,
    EthereumAccountProofWitnessV2, EthereumFinalizedStateWitnessV2, EthereumStorageProofWitnessV2,
    UsddElementsCheckpointLaneWitnessV2, UsddUsdConversionProducerInputV2,
    CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2, MAX_CONVERSION_PRODUCER_INPUT_BYTES_V2,
};
pub use funding_parent_chain_v2::{
    bitcoin_header_hash_internal_v2, compose_funding_parent_chain_v2,
    reverse_bitcoin_hash_byte_order_v2, verify_funding_parent_chain_v2, BitcoinHeader80V2,
    FundingParentChainErrorV2, FundingParentChainWitnessV2, VerifiedFundingParentChainV2,
    FUNDING_PARENT_CHAIN_WITNESS_VERSION_V2, FUNDING_PARENT_MAX_HEADERS_V2,
    FUNDING_PARENT_MTP_WINDOW_V2, FUNDING_PARENT_PREHISTORY_V2,
};
pub use incremental_account_action_child_v2::*;
pub use incremental_activation_v2::*;
pub use incremental_bond_action_child_v2::*;
pub use incremental_deficit_child_v2::*;
pub use incremental_deposit_source_child_v2::*;
pub use incremental_economic_action_child_v2::*;
pub use incremental_forced_action_child_v2::*;
pub use incremental_funding_oracle_child_v2::*;
pub use incremental_inbox_source_child_v2::*;
pub use incremental_nullifier_child_v2::*;
pub use incremental_order_child_v2::*;
pub use incremental_previous_transaction_child_v2::*;
pub use incremental_recovery_budget_v2::*;
pub use incremental_recursive_availability_v2::*;
pub use incremental_risk_child_v2::*;
pub use incremental_settlement_child_v2::*;
pub use incremental_source_transaction_child_v2::*;
pub use incremental_successor_proof_v2::{
    execute_incremental_successor_proof_v2,
    execute_incremental_successor_proof_v2_with_consensus_verifier,
    IncrementalSuccessorProofBindingV2, IncrementalSuccessorProofErrorV2,
    IncrementalSuccessorProofInputV2, IncrementalSuccessorProofPublicValuesV2,
    IncrementalSuccessorProofResultV2, INCREMENTAL_SUCCESSOR_PROOF_BINDING_VERSION_V2,
    INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2, INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2,
    MAX_INCREMENTAL_SUCCESSOR_PROOF_INPUT_BYTES_V2,
};
pub use incremental_trader_child_v2::*;
pub use proof_v2::{
    bond_input_opening_commitment_v2, bond_output_opening_commitment_v2, bond_public_state_root_v2,
    canonical_availability_recovery_payload_v2, collateral_input_opening_commitment_v2,
    collateral_output_opening_commitment_v2, decode_availability_recovery_payload_v2,
    execute_proof_v2, execute_proof_v2_with_consensus_verifier,
    redemption_cancel_bond_return_opening_commitment_v2,
    redemption_cancel_queue_input_opening_commitment_v2,
    redemption_enqueue_bond_input_opening_commitment_v2,
    redemption_enqueue_queue_output_opening_commitment_v2,
    redemption_execute_inventory_output_opening_commitment_v2,
    redemption_execute_queue_input_opening_commitment_v2,
    redemption_execute_queue_remainder_output_opening_commitment_v2,
    redemption_execute_usdd_output_opening_commitment_v2,
    subscription_bond_output_opening_commitment_v2, subscription_usdd_output_opening_commitment_v2,
    transition_availability_context_v2, verify_authenticated_funding_source_v2,
    AuthenticatedFundingSourceV2, AvailabilityRecoveryPayloadV2, BondInboxEntryRecoveryEvidenceV2,
    BondInboxRecoveryEntryV2, BondInboxRecoverySourceReferenceV2,
    BondInboxSourceTransactionEvidenceV2, CovenantPublicStateV2, ProofBindingV2, ProofErrorV2,
    ProofInputV2, ProofResultV2, AVAILABILITY_RECOVERY_PAYLOAD_VERSION_V2,
    COVENANT_STATE_VERSION_V2, MAX_BOND_INBOX_RECOVERY_TABLE_BYTES_V2,
    MAX_NON_BOND_INBOX_RECOVERY_PAYLOAD_BYTES_V2, MAX_PROOF_INPUT_BYTES_V2,
    PROOF_BINDING_VERSION_V2, PUBLIC_VALUES_V5_LEN,
};
pub use usdd_elements_source_v2::*;
pub use usdd_usd_conversion_v2::{
    execute_usdd_usd_conversion_v2, usdd_finality_update_proof_commitment_v2,
    usdd_usd_source_state_root_v2, EthereumAccountProofV2, EthereumAccountRoleV2,
    EthereumStorageProofV2, EthereumStorageRoleV2, EthereumUsddStateWitnessV2,
    FrozenUsddUsdConfigurationV2, UsddElementsSourcePublicValuesV2, UsddElementsSourceReceiptV2,
    UsddElementsSourceVerifierV2, UsddEthereumSourcePublicValuesV2, UsddEthereumSourceReceiptV2,
    UsddUsdConversionErrorV2, UsddUsdConversionInputV2, UsddUsdEthereumVerifierV2,
    MAX_USDD_USD_CONVERSION_INPUT_BYTES_V2, USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2,
    USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2, USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2,
    USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2, USDD_USD_CONVERSION_INPUT_VERSION_V2,
    USDD_USD_FROZEN_CONFIGURATION_VERSION_V2,
};

use bincode::Options;
use ecx_elements_settlement::{
    verify_confidential_deposit, verify_transition_settlement, ConfidentialDepositOpeningV1,
    SettlementError, TransitionSettlementV1,
};
use ecx_protocol_core::{
    central_matcher_receipt_batch_root, matcher_cancel_command_hash, matcher_order_command_hash,
    tagged_hash, transition_withdrawals, verify_central_matcher_receipt_chain, verify_transition,
    CentralMatcherReceiptV1, FrozenConfigurationV1, Hash32, HybridOracleQuoteV1,
    MatcherCommandKind, OracleMode, OrderFlags, ProtocolError, TransitionJournal,
    TransitionPublicInputs, TransitionWitness, AVAILABILITY_CUSTODIAN_COUNT,
    AVAILABILITY_RECOVERY_THRESHOLD, MAX_AVAILABILITY_WITNESS_BYTES, MAX_TRANSITION_ACTIONS,
};
use ecx_truthcoin_proof::{
    verify_authenticated_hybrid_quote, AuthenticationError, ConsensusProofVerifier,
    DenyAllConsensusProofs, ParentChainContextV1, TruthcoinConsensusProofV1,
};
use ecx_witness_availability::{
    availability_scheme_hash, custodian_registry_hash, verify_bundle_encryption,
    verify_custody_receipts, AvailabilityEncryptionWitnessV1, AvailabilityError, CustodianPublic,
    CustodyReceiptV1, WitnessBundle, CUSTODIAN_COUNT, MAX_BUNDLE_BYTES, MAX_WITNESS_BYTES,
    RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROOF_BINDING_VERSION: u8 = 3;
pub const COVENANT_STATE_VERSION: u32 = 2;
pub const PUBLIC_VALUES_VERSION: u32 = 3;
pub const PUBLIC_VALUES_LEN: usize = 32 + 4 + (7 * 32) + (2 * 8);
pub const AVAILABILITY_RECOVERY_PAYLOAD_VERSION: u8 = 1;
/// Hard cap for the entire canonical `ProofInputV1` passed to the zkVM guest.
pub const MAX_PROOF_INPUT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantPublicStateV1 {
    pub version: u32,
    pub sequence: u64,
    /// The private exchange-state root emitted by `ecx-protocol-core`.
    pub private_state_root: Hash32,
    pub encrypted_availability_root: Hash32,
    pub forced_action_inbox_root: Hash32,
    pub deposit_inbox_root: Hash32,
    pub configuration_hash: Hash32,
}

impl CovenantPublicStateV1 {
    /// Mirrors `contracts/simplicity/common.simf::state_hash` exactly.
    pub fn state_hash(&self, state_domain_sha256: Hash32) -> Hash32 {
        let mut preimage = Vec::with_capacity(32 + 4 + 8 + 5 * 32);
        preimage.extend_from_slice(&state_domain_sha256);
        preimage.extend_from_slice(&self.version.to_be_bytes());
        preimage.extend_from_slice(&self.sequence.to_be_bytes());
        preimage.extend_from_slice(&self.private_state_root);
        preimage.extend_from_slice(&self.encrypted_availability_root);
        preimage.extend_from_slice(&self.forced_action_inbox_root);
        preimage.extend_from_slice(&self.deposit_inbox_root);
        preimage.extend_from_slice(&self.configuration_hash);
        sha256(&preimage)
    }

    fn validate(&self) -> Result<(), ProofError> {
        if self.version != COVENANT_STATE_VERSION {
            return Err(ProofError::UnsupportedVersion);
        }
        for (name, value) in [
            ("private state root", self.private_state_root),
            ("availability root", self.encrypted_availability_root),
            ("forced inbox root", self.forced_action_inbox_root),
            ("deposit inbox root", self.deposit_inbox_root),
            ("configuration hash", self.configuration_hash),
        ] {
            if value == [0; 32] {
                return Err(ProofError::ZeroIdentity(name));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBindingV1 {
    pub version: u8,
    /// Raw 32 bytes in the same consensus order returned by Simplicity's jet.
    pub transition_txid_consensus: Hash32,
    pub prior_exchange_header_root: Hash32,
    /// Exact Bitcoin block selected as the current prior-parent BMM context.
    pub prior_parent_block_hash: Hash32,
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    /// Frozen parameter bytes used as the first state-hash record.
    pub public_state_domain_sha256: Hash32,
    /// Frozen parameter bytes used as the first public-values record.
    pub transition_journal_domain_sha256: Hash32,
    pub current: CovenantPublicStateV1,
    pub next: CovenantPublicStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputV1 {
    pub binding: ProofBindingV1,
    /// Canonical bytes whose digest must equal the covenant configuration hash.
    pub configuration: FrozenConfigurationV1,
    /// Full-replay proof of the selected Truthcoin anchor and LMSR state under
    /// the source program/checkpoint frozen in `configuration`.
    pub truthcoin_consensus_proof: TruthcoinConsensusProofV1,
    pub matcher_receipts: Vec<CentralMatcherReceiptV1>,
    /// One exact confidential Elements opening per consumed deposit event.
    pub deposit_openings: Vec<ConfidentialDepositOpeningV1>,
    pub transition_settlement: TransitionSettlementV1,
    pub transition: TransitionWitness,
    /// Exact canonical `WitnessBundle::encode()` bytes committed by the next
    /// public state. Bytes are decoded and re-encoded inside the proof.
    pub availability_bundle: Vec<u8>,
    /// Threshold post-persistence receipts from distinct configured custodians.
    /// Receipt signatures reveal no Shamir share.
    pub availability_custody_receipts: Vec<CustodyReceiptV1>,
    /// Private opening which proves every encrypted share and the payload AEAD
    /// encode the availability-neutral recovery payload for this transition.
    pub availability_encryption_witness: AvailabilityEncryptionWitnessV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofResult {
    pub transition_journal: TransitionJournal,
    /// Exact SP1 public values. This is not itself a hash.
    pub public_values: Vec<u8>,
    /// Exact value passed to `verify_sp1_groth16_sha256` by Simplicity.
    pub public_values_sha256: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofError {
    #[error("unsupported proof or covenant version")]
    UnsupportedVersion,
    #[error("zero deployment identity: {0}")]
    ZeroIdentity(&'static str),
    #[error("proof binding does not match transition: {0}")]
    BindingMismatch(&'static str),
    #[error("private transition rejected: {0}")]
    Transition(#[from] ProtocolError),
    #[error("Truthcoin source authentication rejected: {0}")]
    Truthcoin(#[from] AuthenticationError),
    #[error("collateral settlement rejected: {0}")]
    Settlement(#[from] SettlementError),
    #[error("encrypted witness availability rejected: {0}")]
    Availability(String),
    #[error("availability recovery payload encoding failed")]
    AvailabilityPayloadEncoding,
}

/// Fail-closed production entrypoint.
///
/// A build that has not linked the deployment's frozen Truthcoin replay-proof
/// verifier cannot turn an RPC response or test fixture into an accepted price.
pub fn execute_proof(input: &ProofInputV1) -> Result<ProofResult, ProofError> {
    execute_proof_with_truthcoin_verifier(input, &DenyAllConsensusProofs)
}

/// Execute the complete statement with the verifier for the source proof
/// program frozen in [`FrozenConfigurationV1`].
pub fn execute_proof_with_truthcoin_verifier<V: ConsensusProofVerifier>(
    input: &ProofInputV1,
    truthcoin_verifier: &V,
) -> Result<ProofResult, ProofError> {
    let binding = &input.binding;
    if binding.version != PROOF_BINDING_VERSION {
        return Err(ProofError::UnsupportedVersion);
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
            return Err(ProofError::ZeroIdentity(name));
        }
    }
    if binding.prior_parent_height == 0 || binding.prior_parent_mtp == 0 {
        return Err(ProofError::BindingMismatch("parent chain context"));
    }
    if binding.current.configuration_hash != binding.next.configuration_hash {
        return Err(ProofError::BindingMismatch("configuration hash"));
    }

    input.configuration.validate()?;
    if input.configuration.digest() != binding.current.configuration_hash
        || input.configuration.chain_id != input.transition.public.chain_id
        || input.configuration.market != input.transition.public.market
        || input.configuration.risk != input.transition.risk_params
        || input.configuration.matcher.forced_inclusion_blocks
            != input.transition.public.forced_inclusion_blocks
    {
        return Err(ProofError::BindingMismatch("frozen configuration"));
    }

    verify_availability_binding(input)?;

    let operation_count = input
        .transition
        .deposits
        .len()
        .checked_add(input.transition.withdrawals.len())
        .and_then(|value| value.checked_add(input.transition.placements.len()))
        .and_then(|value| value.checked_add(input.transition.cancellations.len()))
        .and_then(|value| value.checked_add(input.transition.fills.len()))
        .and_then(|value| value.checked_add(input.transition.liquidations.len()))
        .and_then(|value| {
            usize::try_from(input.transition.forced_inbox.consumed_count)
                .ok()
                .and_then(|forced| value.checked_add(forced))
        })
        .ok_or(ProofError::BindingMismatch("operation count"))?;
    if operation_count
        > usize::try_from(MAX_TRANSITION_ACTIONS)
            .map_err(|_| ProofError::BindingMismatch("operation count"))?
        || operation_count
            > usize::try_from(input.configuration.maximum_transition_actions)
                .map_err(|_| ProofError::BindingMismatch("operation count"))?
    {
        return Err(ProofError::BindingMismatch("operation count"));
    }

    let authenticated_quote = verify_authenticated_hybrid_quote(
        &input.configuration.truthcoin_authentication,
        &input.configuration.oracle,
        &input.truthcoin_consensus_proof,
        ParentChainContextV1 {
            block_hash: binding.prior_parent_block_hash,
            height: binding.prior_parent_height,
            median_time_past: binding.prior_parent_mtp,
        },
        truthcoin_verifier,
    )?;
    verify_oracle_binding(&input.transition, &authenticated_quote.quote)?;

    verify_matcher_binding(input, binding)?;
    verify_deposit_binding(input)?;
    verify_settlement_binding(input, binding)?;

    let transition_journal = verify_transition(&input.transition)?;
    if binding.current.sequence != transition_journal.previous_sequence
        || binding.next.sequence != transition_journal.next_sequence
    {
        return Err(ProofError::BindingMismatch("state sequence"));
    }
    if binding.current.private_state_root != transition_journal.previous_state_root
        || binding.next.private_state_root != transition_journal.next_state_root
    {
        return Err(ProofError::BindingMismatch("private state root"));
    }
    if binding.prior_parent_height != transition_journal.parent_height
        || binding.current.forced_action_inbox_root
            != input.transition.previous_state.forced_inbox.head_root
        || binding.next.forced_action_inbox_root
            != input.transition.next_state.forced_inbox.head_root
        || binding.current.deposit_inbox_root
            != input.transition.previous_state.deposit_inbox.head_root
        || binding.next.deposit_inbox_root != input.transition.next_state.deposit_inbox.head_root
        || binding.next.encrypted_availability_root
            != transition_journal.encrypted_availability_root
    {
        return Err(ProofError::BindingMismatch(
            "parent, forced inbox, or availability root",
        ));
    }

    let private_batch_journal_hash = transition_journal.digest();
    let current_hash = binding
        .current
        .state_hash(binding.public_state_domain_sha256);
    let next_hash = binding.next.state_hash(binding.public_state_domain_sha256);

    // Exact mirror of `contracts/simplicity/common.simf::journal_hash`.
    let mut public_values = Vec::with_capacity(PUBLIC_VALUES_LEN);
    public_values.extend_from_slice(&binding.transition_journal_domain_sha256);
    public_values.extend_from_slice(&PUBLIC_VALUES_VERSION.to_be_bytes());
    public_values.extend_from_slice(&binding.current.configuration_hash);
    public_values.extend_from_slice(&current_hash);
    public_values.extend_from_slice(&next_hash);
    public_values.extend_from_slice(&binding.transition_txid_consensus);
    public_values.extend_from_slice(&binding.prior_exchange_header_root);
    public_values.extend_from_slice(&binding.prior_parent_block_hash);
    public_values.extend_from_slice(&binding.prior_parent_height.to_be_bytes());
    public_values.extend_from_slice(&binding.prior_parent_mtp.to_be_bytes());
    public_values.extend_from_slice(&private_batch_journal_hash);
    debug_assert_eq!(public_values.len(), PUBLIC_VALUES_LEN);

    let public_values_sha256 = sha256(&public_values);
    Ok(ProofResult {
        transition_journal,
        public_values,
        public_values_sha256,
    })
}

/// Derive the non-circular public context embedded in each witness bundle.
///
/// The batch hash, next private-state root, and availability root are set to
/// zero because each is downstream of the bundle root. Every other fixed-width
/// transition public input remains committed byte-for-byte.
pub fn transition_availability_context(public: &TransitionPublicInputs) -> Hash32 {
    let mut neutral = public.clone();
    neutral.batch_hash = [0; 32];
    neutral.next_state_root = [0; 32];
    neutral.encrypted_availability_root = [0; 32];
    tagged_hash(
        "ECX/transition-availability-context/v2",
        &neutral.encode_fixed(),
    )
}

#[derive(Serialize)]
struct AvailabilityRecoveryPayloadV1 {
    version: u8,
    configuration_hash: Hash32,
    transition: TransitionWitness,
    deposit_openings: Vec<ConfidentialDepositOpeningV1>,
    transition_settlement: TransitionSettlementV1,
}

/// Produce the exact plaintext that five availability envelopes must encrypt.
///
/// Availability-derived fields are neutralized before serialization, avoiding
/// a fixed-point dependency between plaintext, bundle root, batch hash, and the
/// next state root. Elements transaction bytes are public chain data and are
/// likewise omitted while their confidential openings remain recoverable.
pub fn canonical_availability_recovery_payload(
    configuration: &FrozenConfigurationV1,
    transition: &TransitionWitness,
    deposit_openings: &[ConfidentialDepositOpeningV1],
    transition_settlement: &TransitionSettlementV1,
) -> Result<Vec<u8>, ProofError> {
    let mut neutral_transition = transition.clone();
    neutral_transition.public.batch_hash = [0; 32];
    neutral_transition.public.next_state_root = [0; 32];
    neutral_transition.public.encrypted_availability_root = [0; 32];
    neutral_transition.next_state.roots.order_receipts = [0; 32];

    let mut private_deposit_openings = deposit_openings.to_vec();
    for opening in &mut private_deposit_openings {
        opening.transaction.clear();
    }
    let mut private_settlement = transition_settlement.clone();
    private_settlement.transaction.clear();
    for opening in &mut private_settlement.collateral_inputs {
        opening.previous_transaction.clear();
    }

    let payload = AvailabilityRecoveryPayloadV1 {
        version: AVAILABILITY_RECOVERY_PAYLOAD_VERSION,
        configuration_hash: configuration.digest(),
        transition: neutral_transition,
        deposit_openings: private_deposit_openings,
        transition_settlement: private_settlement,
    };
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .serialize(&payload)
        .map_err(|_| ProofError::AvailabilityPayloadEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_WITNESS_BYTES {
        return Err(ProofError::BindingMismatch(
            "availability recovery payload size",
        ));
    }
    Ok(encoded)
}

fn verify_availability_binding(input: &ProofInputV1) -> Result<(), ProofError> {
    if input.availability_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ProofError::BindingMismatch("availability bundle size"));
    }
    let bundle = WitnessBundle::decode(&input.availability_bundle).map_err(availability_error)?;
    let configured = &input.configuration.availability;
    if configured.scheme_hash != availability_scheme_hash()
        || usize::from(configured.recovery_threshold) != RECOVERY_THRESHOLD
        || usize::from(configured.custodian_count) != CUSTODIAN_COUNT
        || configured.recovery_threshold != AVAILABILITY_RECOVERY_THRESHOLD
        || configured.custodian_count != AVAILABILITY_CUSTODIAN_COUNT
        || configured.maximum_witness_bytes != MAX_AVAILABILITY_WITNESS_BYTES
        || usize::try_from(configured.maximum_witness_bytes)
            .map_err(|_| ProofError::BindingMismatch("availability maximum witness size"))?
            != MAX_WITNESS_BYTES
    {
        return Err(ProofError::BindingMismatch("availability scheme"));
    }
    let custodians: Vec<CustodianPublic> = bundle
        .custodians
        .iter()
        .map(|envelope| envelope.public)
        .collect();
    if custodian_registry_hash(&custodians).map_err(availability_error)?
        != configured.custodian_registry_hash
    {
        return Err(ProofError::BindingMismatch(
            "availability custodian registry",
        ));
    }
    if bundle.context != transition_availability_context(&input.transition.public) {
        return Err(ProofError::BindingMismatch("availability context"));
    }
    let root = bundle.root().map_err(availability_error)?;
    if root != input.transition.public.encrypted_availability_root
        || root != input.binding.next.encrypted_availability_root
    {
        return Err(ProofError::BindingMismatch("availability bundle root"));
    }
    verify_custody_receipts(&bundle, &input.availability_custody_receipts)
        .map_err(availability_error)?;
    let payload = canonical_availability_recovery_payload(
        &input.configuration,
        &input.transition,
        &input.deposit_openings,
        &input.transition_settlement,
    )?;
    if bundle.witness_len
        != u64::try_from(payload.len())
            .map_err(|_| ProofError::BindingMismatch("availability recovery payload size"))?
    {
        return Err(ProofError::BindingMismatch(
            "availability recovery payload size",
        ));
    }
    verify_bundle_encryption(&bundle, &input.availability_encryption_witness, &payload)
        .map_err(availability_error)?;
    Ok(())
}

fn availability_error(error: AvailabilityError) -> ProofError {
    ProofError::Availability(error.to_string())
}

fn verify_deposit_binding(input: &ProofInputV1) -> Result<(), ProofError> {
    let events = input.transition.deposit_inbox.consumed()?;
    if events.len() != input.deposit_openings.len()
        || events.len() != input.transition.deposits.len()
    {
        return Err(ProofError::BindingMismatch("deposit opening coverage"));
    }
    for ((event, opening), expected) in events
        .iter()
        .zip(&input.deposit_openings)
        .zip(&input.transition.deposits)
    {
        let request = verify_confidential_deposit(
            event,
            opening,
            input.configuration.usdd_asset_id,
            input.configuration.collateral_vault_script_sha256,
        )?;
        if &request != expected {
            return Err(ProofError::BindingMismatch("deposit opening"));
        }
    }
    Ok(())
}

fn verify_settlement_binding(
    input: &ProofInputV1,
    binding: &ProofBindingV1,
) -> Result<(), ProofError> {
    let withdrawals = transition_withdrawals(&input.transition)?;
    let settlement = verify_transition_settlement(
        &input.transition_settlement,
        &withdrawals,
        input.configuration.usdd_asset_id,
        input.configuration.collateral_vault_script_sha256,
    )?;
    if settlement.transition_txid != binding.transition_txid_consensus
        || settlement.settlement_root != input.transition.public.collateral_settlement_root
        || settlement.forced_processed_cursor != input.transition.next_state.forced_inbox.cursor
        || settlement.deposit_processed_cursor != input.transition.next_state.deposit_inbox.cursor
    {
        return Err(ProofError::BindingMismatch("collateral settlement"));
    }
    Ok(())
}

fn verify_oracle_binding(
    transition: &TransitionWitness,
    quote: &HybridOracleQuoteV1,
) -> Result<(), ProofError> {
    if transition.public.oracle_certificate_hash != quote.certificate_hash()
        || transition.public.oracle_mode != quote.oracle_mode
        || transition.public.mark_price != quote.ecx_usdd_index
        || transition.public.liquidation_low != quote.ecx_usdd_low
        || transition.public.liquidation_high != quote.ecx_usdd_high
    {
        return Err(ProofError::BindingMismatch("hybrid oracle certificate"));
    }
    if quote.oracle_mode != OracleMode::Normal && !transition.liquidations.is_empty() {
        return Err(ProofError::BindingMismatch(
            "liquidation outside normal oracle mode",
        ));
    }
    match quote.oracle_mode {
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
                return Err(ProofError::BindingMismatch("reduce-only oracle mode"));
            }
        }
        OracleMode::Halt => {
            if transition.public.funding_rate_ppm != 0
                || !transition.withdrawals.is_empty()
                || !transition.placements.is_empty()
                || !transition.fills.is_empty()
            {
                return Err(ProofError::BindingMismatch("halted oracle mode"));
            }
        }
    }
    Ok(())
}

fn verify_matcher_binding(
    input: &ProofInputV1,
    binding: &ProofBindingV1,
) -> Result<(), ProofError> {
    if central_matcher_receipt_batch_root(&input.matcher_receipts)
        != input.transition.public.matcher_receipt_batch_root
    {
        return Err(ProofError::BindingMismatch("matcher receipt batch root"));
    }
    let (next_sequence, next_receipt_hash) = verify_central_matcher_receipt_chain(
        &input.configuration.matcher,
        input.configuration.chain_id,
        input.transition.previous_state.matcher_sequence,
        input.transition.previous_state.matcher_receipt_hash,
        &input.matcher_receipts,
    )?;
    if next_sequence != input.transition.next_state.matcher_sequence
        || next_receipt_hash != input.transition.next_state.matcher_receipt_hash
        || input.matcher_receipts.iter().any(|receipt| {
            receipt.body.observed_sidechain_height > input.transition.public.sidechain_height
                || receipt.body.observed_parent_height > binding.prior_parent_height
                || receipt.body.observed_parent_mtp > binding.prior_parent_mtp
                || receipt.body.forced_inbox_cursor
                    > input.transition.next_state.forced_inbox.cursor
        })
    {
        return Err(ProofError::BindingMismatch("matcher receipt chain"));
    }

    let mut expected = Vec::new();
    for placement in &input.transition.placements {
        expected.push((
            MatcherCommandKind::Place,
            matcher_order_command_hash(&placement.order),
            Some(placement.received_sequence),
        ));
    }
    for cancellation in &input.transition.cancellations {
        expected.push((
            MatcherCommandKind::Cancel,
            matcher_cancel_command_hash(cancellation),
            None,
        ));
    }

    // A direct non-forced IOC/FOK taker can be represented only in `fills`; it
    // still needs exactly one ingress receipt. Its fill sequence is the
    // matcher's signed acceptance sequence. Forced IOC orders are committed by
    // the Elements inbox and deliberately do not depend on matcher admission.
    let forced_ioc_ids: std::collections::BTreeSet<Hash32> = input
        .transition
        .forced_inbox
        .consumed()?
        .iter()
        .filter_map(|entry| match &entry.action {
            ecx_protocol_core::ForcedActionV1::ReduceOnlyIoc(order) => Some(order.order_id()),
            _ => None,
        })
        .collect();
    for pair in &input.transition.fills {
        let taker_id = pair.taker_order.order_id();
        if !forced_ioc_ids.contains(&taker_id) {
            require_place_receipt(
                &mut expected,
                matcher_order_command_hash(&pair.taker_order),
                pair.trade.sequence,
            )?;
        }
    }

    if expected.len() != input.matcher_receipts.len() {
        return Err(ProofError::BindingMismatch("matcher command coverage"));
    }
    let mut matched = vec![false; expected.len()];
    for receipt in &input.matcher_receipts {
        let mut found = None;
        for (index, (kind, hash, required_sequence)) in expected.iter().enumerate() {
            if !matched[index] && matcher_receipt_covers(receipt, *kind, *hash, *required_sequence)
            {
                found = Some(index);
                break;
            }
        }
        let index = found.ok_or(ProofError::BindingMismatch("matcher command receipt"))?;
        matched[index] = true;
    }
    Ok(())
}

type ExpectedMatcherCommand = (MatcherCommandKind, Hash32, Option<u64>);

fn require_place_receipt(
    expected: &mut Vec<ExpectedMatcherCommand>,
    command_hash: Hash32,
    taker_sequence: u64,
) -> Result<(), ProofError> {
    if let Some((_, _, required_sequence)) = expected
        .iter_mut()
        .find(|(kind, hash, _)| *kind == MatcherCommandKind::Place && *hash == command_hash)
    {
        match *required_sequence {
            Some(sequence) if sequence != taker_sequence => {
                return Err(ProofError::BindingMismatch("taker receipt sequence"));
            }
            Some(_) => {}
            None => *required_sequence = Some(taker_sequence),
        }
    } else {
        expected.push((
            MatcherCommandKind::Place,
            command_hash,
            Some(taker_sequence),
        ));
    }
    Ok(())
}

fn matcher_receipt_covers(
    receipt: &CentralMatcherReceiptV1,
    expected_kind: MatcherCommandKind,
    expected_hash: Hash32,
    required_sequence: Option<u64>,
) -> bool {
    receipt.body.command_kind == expected_kind
        && receipt.body.command_hash == expected_hash
        && required_sequence.is_none_or(|sequence| sequence == receipt.body.global_sequence)
}

fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_protocol_core::{MatcherReceiptBodyV1, Signature64, ECX_USDD_MARKET};

    #[test]
    fn public_value_length_is_frozen() {
        assert_eq!(PUBLIC_VALUES_LEN, 276);
    }

    #[test]
    fn covenant_state_hash_binds_every_field() {
        let state = CovenantPublicStateV1 {
            version: COVENANT_STATE_VERSION,
            sequence: 7,
            private_state_root: [1; 32],
            encrypted_availability_root: [2; 32],
            forced_action_inbox_root: [3; 32],
            deposit_inbox_root: [4; 32],
            configuration_hash: [5; 32],
        };
        let expected = state.state_hash([5; 32]);
        let mut variants = Vec::new();
        let mut changed = state.clone();
        changed.sequence += 1;
        variants.push(changed);
        let mut changed = state.clone();
        changed.private_state_root[0] ^= 1;
        variants.push(changed);
        let mut changed = state.clone();
        changed.encrypted_availability_root[0] ^= 1;
        variants.push(changed);
        let mut changed = state.clone();
        changed.forced_action_inbox_root[0] ^= 1;
        variants.push(changed);
        let mut changed = state.clone();
        changed.deposit_inbox_root[0] ^= 1;
        variants.push(changed);
        let mut changed = state;
        changed.configuration_hash[0] ^= 1;
        variants.push(changed);
        for variant in variants {
            assert_ne!(variant.state_hash([5; 32]), expected);
        }
    }

    #[test]
    fn taker_fill_sequence_must_match_unique_place_receipt() {
        let command_hash = [41; 32];
        let mut expected = Vec::new();
        require_place_receipt(&mut expected, command_hash, 17).unwrap();
        require_place_receipt(&mut expected, command_hash, 17).unwrap();
        assert_eq!(expected.len(), 1, "multi-fill taker uses one receipt");
        assert!(matches!(
            require_place_receipt(&mut expected, command_hash, 18),
            Err(ProofError::BindingMismatch("taker receipt sequence"))
        ));

        let mut receipt = CentralMatcherReceiptV1 {
            body: MatcherReceiptBodyV1 {
                version: MatcherReceiptBodyV1::VERSION,
                chain_id: [1; 32],
                market: ECX_USDD_MARKET,
                matcher_config_hash: [2; 32],
                matcher_key_epoch: 0,
                global_sequence: 18,
                previous_receipt_hash: [3; 32],
                command_kind: MatcherCommandKind::Place,
                command_hash,
                observed_sidechain_height: 1,
                observed_parent_height: 1,
                observed_parent_mtp: 1,
                forced_inbox_cursor: 0,
                availability_root: [4; 32],
            },
            signature: Signature64([0; 64]),
        };
        assert!(!matcher_receipt_covers(
            &receipt,
            MatcherCommandKind::Place,
            command_hash,
            Some(17),
        ));
        receipt.body.global_sequence = 17;
        assert!(matcher_receipt_covers(
            &receipt,
            MatcherCommandKind::Place,
            command_hash,
            Some(17),
        ));
    }
}
