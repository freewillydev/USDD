//! Distinct Alpha checkpoint/transition receipt-chain adapter.
//!
//! This is NOT the ECX/BTC conversion relation. It authenticates the exact
//! reviewed checkpoint receipt, all sequential full-Alpha transition receipts,
//! and terminal executed-state preimage. No header-only or marker-only fallback
//! exists. A caller must provide a cryptographic recursive receipt verifier.
//!
//! The outer consumer must freeze the complete `AlphaRecursiveBindingV3` (or
//! its commitment). Caller-selected program IDs/checkpoints are not trust roots.
//! Keep the execution-source commitment independent of the reviewed checkpoint
//! hash: hashing a checkpoint into its own state's source commitment is circular.
//! Review binds the two in this explicit outer binding. Checkpoint authenticity,
//! source-event completeness and observation clocks remain source-workflow gates.

use bincode::Options;
use bitcoin::hashes::Hash as _;
use ecx_full_consensus_validator_v2::alpha_pow_v3::ALPHA_FORK_HEIGHT_V3;
use ecx_full_consensus_validator_v2::alpha_state_v3::{
    alpha_consensus_profile_commitment_v3, AlphaExecutedConsensusStateV3,
};
use ecx_full_consensus_validator_v2::checkpoint_alpha_v3::{
    decode_reviewed_alpha_checkpoint_input_v3, execute_reviewed_alpha_checkpoint_v3,
    ReviewedAlphaCheckpointPublicValuesV3, MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3,
    REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_BYTES_V3,
};
use ecx_full_consensus_validator_v2::recursive_alpha_v3::{
    decode_full_alpha_transition_public_values_v3, FullAlphaTransitionPublicValuesV3,
    FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3, MAX_FULL_ALPHA_TRANSITION_STEPS_V3,
};
use ecx_full_consensus_validator_v2::{median_time_past_v2, Hash32};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod conversion_parent_link_v3;
pub mod verified_child_observation_v5;
#[cfg(feature = "truthcoin-authority")]
pub mod truthcoin_authority_guest_v2;
pub mod native_bmm_anchor_v1;
pub mod native_child_commitment_v3;
pub mod native_withdrawal_accumulator_v3;
pub mod native_withdrawal_extraction_v3;
pub mod custody_burn_v2;
pub mod custody_redemption_statement_v2;
pub mod custody_history_wire_v2;
pub mod custody_execution_wire_v2;
pub mod custody_execution_v2;
pub mod custody_child_lineage_v2;
pub mod settlement_history_v5;
pub mod parent_finality_v3;
pub mod relay_bootstrap_v3;
pub mod parent_finality_wire_v3;
pub mod relay_continuation_v3;
pub mod relay_continuation_wire_v3;
pub mod relay_reorg_v3;
pub mod relay_reorg_wire_v3;
pub mod native_child_block_v3;
pub mod child_execution_state_v3;
pub mod child_custody_checkpoint_v3;
pub mod child_execution_state_v4;
pub mod ecx_environment_v4;
pub mod ecx_match_checkpoint_v1;
pub mod ecx_match_execution_v1;
pub mod native_bond_inbox_scan_v4;
pub mod capital_genesis_utxos_v4;
pub mod genesis_initialization_v2;
pub mod child_deployments_v3;
pub mod native_child_witness_v3;
pub mod native_transaction_checks_v3;
pub mod native_deposit_outputs_v3;
pub mod native_deposit_policy_v4;
pub mod native_creation_policy_v1;
pub mod effective_child_configuration_v1;
pub mod native_child_context_v3;
pub mod native_reward_v3;
pub mod native_header_signature_v3;
pub mod native_header_v3;
pub mod native_block_wire_v3;
#[cfg(test)]
mod native_lock_tests_v3;

pub const FULL_ALPHA_ADAPTER_INPUT_VERSION_V3: u8 = 0xa3;
pub const FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3: u8 = 0xa3;
pub const FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3: usize = 529;
pub const MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3: usize = 16 * 1024 * 1024;
pub const MAX_FULL_ALPHA_TRANSITION_RECEIPTS_V3: usize = 16_384;
pub const MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3: usize = 256;
const KOALA_BEAR_MODULUS: u32 = 0x7f00_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaRecursiveBindingV3 {
    pub source_configuration_commitment: Hash32,
    pub reviewed_checkpoint_input_commitment: Hash32,
    pub checkpoint_program_id: Hash32,
    pub transition_program_id: Hash32,
}

impl AlphaRecursiveBindingV3 {
    pub fn validate(&self) -> Result<(), FullAlphaAdapterErrorV3> {
        if self.source_configuration_commitment == [0; 32]
            || self.reviewed_checkpoint_input_commitment == [0; 32]
            || !alpha_sp1_program_id_is_canonical_v3(self.checkpoint_program_id)
            || !alpha_sp1_program_id_is_canonical_v3(self.transition_program_id)
            || self.checkpoint_program_id == self.transition_program_id
        {
            return Err(FullAlphaAdapterErrorV3::Binding);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, FullAlphaAdapterErrorV3> {
        self.validate()?;
        let mut bytes = vec![FULL_ALPHA_ADAPTER_INPUT_VERSION_V3];
        bytes.extend_from_slice(&alpha_consensus_profile_commitment_v3());
        for hash in [
            self.source_configuration_commitment,
            self.reviewed_checkpoint_input_commitment,
            self.checkpoint_program_id,
            self.transition_program_id,
        ] {
            bytes.extend_from_slice(&hash);
        }
        Ok(tagged_hash("ECX/full-alpha-recursive-binding/v3", &bytes))
    }
}

pub fn alpha_sp1_program_id_is_canonical_v3(program_id: Hash32) -> bool {
    program_id != [0; 32]
        && program_id.chunks_exact(4).all(|word| {
            u32::from_be_bytes(word.try_into().expect("four byte word")) < KOALA_BEAR_MODULUS
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaRecursiveReceiptBindingV3 {
    pub public_values: Vec<u8>,
    pub proof_marker: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullAlphaAdapterInputV3 {
    pub version: u8,
    pub binding: AlphaRecursiveBindingV3,
    /// Canonical reviewed Alpha checkpoint input, not a host state summary.
    pub checkpoint_input: Vec<u8>,
    pub checkpoint_receipt: AlphaRecursiveReceiptBindingV3,
    pub transition_receipts: Vec<AlphaRecursiveReceiptBindingV3>,
    pub terminal_selected_state: AlphaExecutedConsensusStateV3,
}

/// Full parent-consensus statement only: no redemption, child BMM edge,
/// deployment, conversion quote or ECX proof-readiness claim is made here.
/// Fixed bincode/fixint little-endian journal, explicitly version/profile bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullAlphaStatementV3 {
    pub version: u8,
    pub alpha_consensus_profile_commitment: Hash32,
    pub binding: AlphaRecursiveBindingV3,
    pub initial_selected_state_commitment: Hash32,
    pub initial_all_slots_state_commitment: Hash32,
    pub initial_frontier_commitment: Hash32,
    pub initial_event_stream_commitment: Hash32,
    pub initial_selected_height: u32,
    pub initial_event_sequence: u128,
    pub terminal_selected_state_commitment: Hash32,
    pub final_all_slots_state_commitment: Hash32,
    pub final_frontier_commitment: Hash32,
    pub final_event_stream_commitment: Hash32,
    pub terminal_selected_height: u32,
    pub final_event_sequence: u128,
    pub terminal_tip_hash_internal: Hash32,
    pub terminal_mtp: u64,
    pub terminal_chainwork_be: Hash32,
}

pub trait FullAlphaReceiptVerifierV3 {
    /// MUST cryptographically verify the exact program and public-value bytes.
    /// A marker equality check alone is not an implementation of this contract.
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullAlphaAdapterErrorV3 {
    #[error("unsupported full-Alpha adapter version")]
    UnsupportedVersion,
    #[error("full-Alpha adapter input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("reviewed checkpoint/program binding is invalid")]
    Binding,
    #[error("reviewed Alpha checkpoint preimage or receipt is invalid")]
    Checkpoint,
    #[error("full Alpha recursive transition chain is invalid")]
    TransitionChain,
    #[error("terminal Alpha executed state does not match recursive receipts")]
    TerminalState,
    #[error("full Alpha statement is invalid")]
    Statement,
    #[error("recursive receipt rejected")]
    Receipt,
}

pub fn encode_full_alpha_adapter_input_v3(
    input: &FullAlphaAdapterInputV3,
) -> Result<Vec<u8>, FullAlphaAdapterErrorV3> {
    validate_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullAlphaAdapterErrorV3::NonCanonicalInput)
}

pub fn decode_full_alpha_adapter_input_v3(
    bytes: &[u8],
) -> Result<FullAlphaAdapterInputV3, FullAlphaAdapterErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3 {
        return Err(FullAlphaAdapterErrorV3::NonCanonicalInput);
    }
    let input = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullAlphaAdapterErrorV3::NonCanonicalInput)?;
    if encode_full_alpha_adapter_input_v3(&input)? != bytes {
        return Err(FullAlphaAdapterErrorV3::NonCanonicalInput);
    }
    Ok(input)
}

pub fn encode_full_alpha_statement_v3(
    statement: &FullAlphaStatementV3,
) -> Result<Vec<u8>, FullAlphaAdapterErrorV3> {
    validate_statement(statement)?;
    let encoded = canonical_options()
        .serialize(statement)
        .map_err(|_| FullAlphaAdapterErrorV3::Statement)?;
    if encoded.len() != FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3 {
        return Err(FullAlphaAdapterErrorV3::Statement);
    }
    Ok(encoded)
}

pub fn decode_full_alpha_statement_v3(
    bytes: &[u8],
) -> Result<FullAlphaStatementV3, FullAlphaAdapterErrorV3> {
    if bytes.len() != FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3 {
        return Err(FullAlphaAdapterErrorV3::Statement);
    }
    let statement = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullAlphaAdapterErrorV3::Statement)?;
    if encode_full_alpha_statement_v3(&statement)? != bytes {
        return Err(FullAlphaAdapterErrorV3::Statement);
    }
    Ok(statement)
}

pub fn execute_full_alpha_adapter_v3<V: FullAlphaReceiptVerifierV3>(
    input: &FullAlphaAdapterInputV3,
    verifier: &V,
) -> Result<FullAlphaStatementV3, FullAlphaAdapterErrorV3> {
    validate_shape(input)?;
    let checkpoint = decode_reviewed_alpha_checkpoint_input_v3(&input.checkpoint_input)
        .map_err(|_| FullAlphaAdapterErrorV3::Checkpoint)?;
    let initial = execute_reviewed_alpha_checkpoint_v3(&checkpoint)
        .map_err(|_| FullAlphaAdapterErrorV3::Checkpoint)?;
    if initial.source_configuration_commitment != input.binding.source_configuration_commitment
        || initial.checkpoint_input_commitment != input.binding.reviewed_checkpoint_input_commitment
        || input.checkpoint_receipt.public_values != initial.canonical_bytes()
    {
        return Err(FullAlphaAdapterErrorV3::Checkpoint);
    }
    verifier.verify(
        input.binding.checkpoint_program_id,
        &input.checkpoint_receipt.public_values,
        &input.checkpoint_receipt.proof_marker,
    )?;
    let terminal = verify_alpha_transition_receipt_chain_v3(
        initial,
        input.binding,
        &input.transition_receipts,
        verifier,
    )?;
    let state = &input.terminal_selected_state;
    state
        .validate()
        .map_err(|_| FullAlphaAdapterErrorV3::TerminalState)?;
    if state.source_configuration_commitment != input.binding.source_configuration_commitment
        || terminal.successor_state_commitment
            != state
                .commitment()
                .map_err(|_| FullAlphaAdapterErrorV3::TerminalState)?
        || terminal.successor_height != state.tip.height
        || terminal.successor_tip_hash_internal != state.tip.block_hash.to_byte_array()
        || state.tip.discovery_sequence > terminal.final_discovery_sequence
        || state.deployment_state != checkpoint.selected_state.deployment_state
    {
        return Err(FullAlphaAdapterErrorV3::TerminalState);
    }
    let statement = FullAlphaStatementV3 {
        version: FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3,
        alpha_consensus_profile_commitment: alpha_consensus_profile_commitment_v3(),
        binding: input.binding,
        initial_selected_state_commitment: initial.selected_state_commitment,
        initial_all_slots_state_commitment: initial.all_slots_state_commitment,
        initial_frontier_commitment: initial.frontier_commitment,
        initial_event_stream_commitment: initial.event_stream_commitment,
        initial_selected_height: initial.selected_height,
        initial_event_sequence: initial.event_sequence,
        terminal_selected_state_commitment: terminal.successor_state_commitment,
        final_all_slots_state_commitment: state
            .bip300_state
            .commitment()
            .map_err(|_| FullAlphaAdapterErrorV3::TerminalState)?,
        final_frontier_commitment: terminal.successor_frontier_commitment,
        final_event_stream_commitment: terminal.successor_event_stream_commitment,
        terminal_selected_height: terminal.successor_height,
        final_event_sequence: terminal.final_discovery_sequence,
        terminal_tip_hash_internal: terminal.successor_tip_hash_internal,
        terminal_mtp: u64::from(
            median_time_past_v2(&state.pow_context.previous_11_times)
                .map_err(|_| FullAlphaAdapterErrorV3::TerminalState)?,
        ),
        terminal_chainwork_be: state.tip.chainwork_be,
    };
    encode_full_alpha_statement_v3(&statement)?;
    Ok(statement)
}

pub fn verify_alpha_transition_receipt_chain_v3<V: FullAlphaReceiptVerifierV3>(
    checkpoint: ReviewedAlphaCheckpointPublicValuesV3,
    binding: AlphaRecursiveBindingV3,
    receipts: &[AlphaRecursiveReceiptBindingV3],
    verifier: &V,
) -> Result<FullAlphaTransitionPublicValuesV3, FullAlphaAdapterErrorV3> {
    binding.validate()?;
    if receipts.is_empty()
        || receipts.len() > MAX_FULL_ALPHA_TRANSITION_RECEIPTS_V3
        || checkpoint.source_configuration_commitment != binding.source_configuration_commitment
        || checkpoint.checkpoint_input_commitment != binding.reviewed_checkpoint_input_commitment
    {
        return Err(FullAlphaAdapterErrorV3::TransitionChain);
    }
    let mut state = checkpoint.selected_state_commitment;
    let mut height = checkpoint.selected_height;
    let mut frontier = checkpoint.frontier_commitment;
    let mut event = checkpoint.event_stream_commitment;
    let mut sequence = checkpoint.event_sequence;
    let mut terminal = None;
    for receipt in receipts {
        let current = decode_full_alpha_transition_public_values_v3(&receipt.public_values)
            .map_err(|_| FullAlphaAdapterErrorV3::TransitionChain)?;
        if !receipt_marker_valid(receipt)
            || current.source_configuration_commitment != binding.source_configuration_commitment
            || current.predecessor_state_commitment != state
            || current.predecessor_height != height
            || current.predecessor_frontier_commitment != frontier
            || current.predecessor_event_stream_commitment != event
            || sequence.checked_add(1) != Some(current.first_discovery_sequence)
            || current.step_count as usize > MAX_FULL_ALPHA_TRANSITION_STEPS_V3
            || current.predecessor_height < ALPHA_FORK_HEIGHT_V3 - 1
            || current.successor_height < ALPHA_FORK_HEIGHT_V3 - 1
        {
            return Err(FullAlphaAdapterErrorV3::TransitionChain);
        }
        verifier.verify(
            binding.transition_program_id,
            &receipt.public_values,
            &receipt.proof_marker,
        )?;
        state = current.successor_state_commitment;
        height = current.successor_height;
        frontier = current.successor_frontier_commitment;
        event = current.successor_event_stream_commitment;
        sequence = current.final_discovery_sequence;
        terminal = Some(current);
    }
    terminal.ok_or(FullAlphaAdapterErrorV3::TransitionChain)
}

fn validate_shape(input: &FullAlphaAdapterInputV3) -> Result<(), FullAlphaAdapterErrorV3> {
    if input.version != FULL_ALPHA_ADAPTER_INPUT_VERSION_V3 {
        return Err(FullAlphaAdapterErrorV3::UnsupportedVersion);
    }
    input.binding.validate()?;
    if input.checkpoint_input.is_empty()
        || input.checkpoint_input.len() > MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3
        || !receipt_marker_valid(&input.checkpoint_receipt)
        || input.checkpoint_receipt.public_values.len()
            != REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_BYTES_V3
        || input.transition_receipts.is_empty()
        || input.transition_receipts.len() > MAX_FULL_ALPHA_TRANSITION_RECEIPTS_V3
        || input.transition_receipts.iter().any(|r| {
            !receipt_marker_valid(r)
                || r.public_values.len() != FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3
        })
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullAlphaAdapterErrorV3::NonCanonicalInput)?
            > MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3 as u64
    {
        return Err(FullAlphaAdapterErrorV3::NonCanonicalInput);
    }
    Ok(())
}

fn receipt_marker_valid(receipt: &AlphaRecursiveReceiptBindingV3) -> bool {
    !receipt.proof_marker.is_empty()
        && receipt.proof_marker.len() <= MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3
}

fn validate_statement(statement: &FullAlphaStatementV3) -> Result<(), FullAlphaAdapterErrorV3> {
    statement.binding.validate()?;
    if statement.version != FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3
        || statement.alpha_consensus_profile_commitment != alpha_consensus_profile_commitment_v3()
        || statement.initial_selected_height < ALPHA_FORK_HEIGHT_V3 - 1
        || statement.terminal_selected_height < ALPHA_FORK_HEIGHT_V3 - 1
        || statement.final_event_sequence <= statement.initial_event_sequence
        || statement.terminal_mtp == 0
        || [
            statement.initial_selected_state_commitment,
            statement.initial_all_slots_state_commitment,
            statement.initial_frontier_commitment,
            statement.initial_event_stream_commitment,
            statement.terminal_selected_state_commitment,
            statement.final_all_slots_state_commitment,
            statement.final_frontier_commitment,
            statement.final_event_stream_commitment,
            statement.terminal_tip_hash_internal,
            statement.terminal_chainwork_be,
        ]
        .contains(&[0; 32])
    {
        return Err(FullAlphaAdapterErrorV3::Statement);
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3 as u64)
}

fn tagged_hash(tag: &str, payload: &[u8]) -> Hash32 {
    let tag_hash = bitcoin::hashes::sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut preimage = Vec::with_capacity(64 + payload.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(payload);
    bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array()
}

#[cfg(test)]
mod tests;
pub mod native_claims_v3;
pub mod checkpoint_coin_import_v3;
pub mod native_conversion_accounting_v3;
pub mod conversion_composition_v3;
pub mod child_execution_policy_v3;
pub mod child_header_policy_v3;
pub mod child_execution_guest_v3;
pub mod child_execution_statement_v4;
pub mod child_execution_guest_v4;
pub mod child_custody_guest_v4;
pub mod child_custody_guest_v6;
pub mod child_custody_guest_v7;
pub mod native_conversion_source_v3;
pub mod native_redemption_deployment_v3;
pub mod native_checkpoint_lineage_v3;
pub mod ecx_deposit_membership_v1;
// Compile the actual host materializer only for interoperability tests.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../bond-action-client/src/bin/ecx-bond-v2-genesis-materialize.rs"]
mod genesis_materializer_test_bridge;
