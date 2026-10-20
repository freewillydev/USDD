//! Final recursive adapter from checkpoint/transition receipts to the exact
//! `FullBitcoinStatementV2` consumed by the ECX/BTC conversion guest.

use bincode::Options;
use bitcoin::hashes::Hash as _;
use ecx_conversion_foundation_v2::ecx_btc::{
    derive_full_bitcoin_statement_v2, ecx_btc_source_checkpoint_commitment_v2,
    encode_full_bitcoin_statement_v2, EcxBtcConversionWitnessV2, FullBitcoinStatementV2,
};
use ecx_full_consensus_validator_v2::checkpoint_bitcoin_v2::{
    decode_reviewed_bitcoin_checkpoint_input_v2, execute_reviewed_bitcoin_checkpoint_v2,
    ReviewedBitcoinCheckpointPublicValuesV2,
};
use ecx_full_consensus_validator_v2::median_time_past_v2;
use ecx_full_consensus_validator_v2::recursive_bitcoin_v2::{
    decode_full_bitcoin_transition_public_values_v2, FullBitcoinTransitionPublicValuesV2,
};
use ecx_full_consensus_validator_v2::state_frontier_v2::BitcoinExecutedConsensusStateV2;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Breaking unreleased wire revision: terminal state includes the authenticated
// Signet challenge. This requires a rebuilt program, not old receipt reuse.
pub const FULL_BITCOIN_ADAPTER_INPUT_VERSION_V2: u8 = 2;
pub const MAX_FULL_BITCOIN_ADAPTER_INPUT_BYTES_V2: usize = 160 * 1024 * 1024;
pub const MAX_FULL_BITCOIN_TRANSITION_RECEIPTS_V2: usize = 16_384;
pub const MAX_FULL_BITCOIN_RECEIPT_MARKER_BYTES_V2: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursiveReceiptBindingV2 {
    pub public_values: Vec<u8>,
    pub proof_marker: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinAdapterInputV2 {
    pub version: u8,
    /// Exact material also consumed by the outer conversion relation.
    pub conversion_witness: EcxBtcConversionWitnessV2,
    pub checkpoint_receipt: RecursiveReceiptBindingV2,
    pub transition_receipts: Vec<RecursiveReceiptBindingV2>,
    /// Complete terminal preimage whose commitment is exposed by the final
    /// transition receipt.
    pub terminal_selected_state: BitcoinExecutedConsensusStateV2,
}

pub trait FullBitcoinReceiptVerifierV2 {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullBitcoinAdapterErrorV2>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullBitcoinAdapterErrorV2 {
    #[error("unsupported full-Bitcoin adapter version")]
    UnsupportedVersion,
    #[error("full-Bitcoin adapter input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("reviewed checkpoint preimage, profile, or receipt is invalid")]
    Checkpoint,
    #[error("recursive transition receipt chain is invalid")]
    TransitionChain,
    #[error("terminal executed state does not match the receipt chain")]
    TerminalState,
    #[error("conversion foundation statement does not match full validation")]
    Statement,
    #[error("recursive receipt rejected")]
    Receipt,
}

pub fn encode_full_bitcoin_adapter_input_v2(
    input: &FullBitcoinAdapterInputV2,
) -> Result<Vec<u8>, FullBitcoinAdapterErrorV2> {
    validate_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullBitcoinAdapterErrorV2::NonCanonicalInput)
}

pub fn decode_full_bitcoin_adapter_input_v2(
    bytes: &[u8],
) -> Result<FullBitcoinAdapterInputV2, FullBitcoinAdapterErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_FULL_BITCOIN_ADAPTER_INPUT_BYTES_V2 {
        return Err(FullBitcoinAdapterErrorV2::NonCanonicalInput);
    }
    let input: FullBitcoinAdapterInputV2 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullBitcoinAdapterErrorV2::NonCanonicalInput)?;
    validate_shape(&input)?;
    if encode_full_bitcoin_adapter_input_v2(&input)? != bytes {
        return Err(FullBitcoinAdapterErrorV2::NonCanonicalInput);
    }
    Ok(input)
}

pub fn execute_full_bitcoin_adapter_v2<V: FullBitcoinReceiptVerifierV2>(
    input: &FullBitcoinAdapterInputV2,
    verifier: &V,
) -> Result<FullBitcoinStatementV2, FullBitcoinAdapterErrorV2> {
    validate_shape(input)?;
    let checkpoint = &input.conversion_witness.source_checkpoint;
    let source_checkpoint_commitment = ecx_btc_source_checkpoint_commitment_v2(checkpoint)
        .map_err(|_| FullBitcoinAdapterErrorV2::Checkpoint)?;
    let checkpoint_input = decode_reviewed_bitcoin_checkpoint_input_v2(
        &checkpoint.parent.complete_executed_checkpoint_preimage,
    )
    .map_err(|_| FullBitcoinAdapterErrorV2::Checkpoint)?;
    if checkpoint_input.source_configuration_commitment
        != checkpoint.bitcoin_consensus_configuration_commitment
    {
        return Err(FullBitcoinAdapterErrorV2::Checkpoint);
    }
    let checkpoint_values = execute_reviewed_bitcoin_checkpoint_v2(&checkpoint_input)
        .map_err(|_| FullBitcoinAdapterErrorV2::Checkpoint)?;
    let checkpoint_bytes = checkpoint_values.canonical_bytes();
    if input.checkpoint_receipt.public_values != checkpoint_bytes
        || input.checkpoint_receipt.proof_marker.is_empty()
    {
        return Err(FullBitcoinAdapterErrorV2::Checkpoint);
    }
    verifier.verify(
        checkpoint.full_bitcoin_checkpoint_program_id,
        &checkpoint_bytes,
        &input.checkpoint_receipt.proof_marker,
    )?;

    let terminal = verify_transition_receipt_chain_v2(
        checkpoint_values,
        checkpoint.bitcoin_consensus_configuration_commitment,
        checkpoint.full_bitcoin_transition_program_id,
        &input.transition_receipts,
        verifier,
    )?;
    input
        .terminal_selected_state
        .validate()
        .map_err(|_| FullBitcoinAdapterErrorV2::TerminalState)?;
    let terminal_state_commitment = input
        .terminal_selected_state
        .commitment()
        .map_err(|_| FullBitcoinAdapterErrorV2::TerminalState)?;
    if terminal.successor_state_commitment != terminal_state_commitment
        || terminal.successor_height != input.terminal_selected_state.tip.height
        || terminal.successor_tip_hash_internal
            != input.terminal_selected_state.tip.block_hash.to_byte_array()
    {
        return Err(FullBitcoinAdapterErrorV2::TerminalState);
    }

    let expected = derive_full_bitcoin_statement_v2(&input.conversion_witness)
        .map_err(|_| FullBitcoinAdapterErrorV2::Statement)?;
    let initial_all_slots_state_commitment = checkpoint_input
        .selected_state
        .bip300_state
        .commitment()
        .map_err(|_| FullBitcoinAdapterErrorV2::Checkpoint)?;
    let final_all_slots_state_commitment = input
        .terminal_selected_state
        .bip300_state
        .commitment()
        .map_err(|_| FullBitcoinAdapterErrorV2::TerminalState)?;
    let terminal_mtp = u64::from(
        median_time_past_v2(&input.terminal_selected_state.pow_context.previous_11_times)
            .map_err(|_| FullBitcoinAdapterErrorV2::TerminalState)?,
    );
    if expected.source_checkpoint_commitment != source_checkpoint_commitment
        || expected.initial_all_slots_state_commitment != initial_all_slots_state_commitment
        || expected.final_all_slots_state_commitment != final_all_slots_state_commitment
        || expected.final_executed_frontier_commitment != terminal.successor_frontier_commitment
        || expected.final_event_stream_commitment != terminal.successor_event_stream_commitment
        || expected.final_event_sequence != terminal.final_discovery_sequence
        || expected.parent_tip_hash_internal != terminal.successor_tip_hash_internal
        || expected.parent_tip_height != terminal.successor_height
        || expected.parent_tip_mtp != terminal_mtp
        || expected.cumulative_work_be != input.terminal_selected_state.tip.chainwork_be
        || !expected.contextual_consensus_valid
        || !expected.selected_by_best_work
        || !expected.all_bip300_messages_preserved
        || !expected.confirmation_semantics_valid
    {
        return Err(FullBitcoinAdapterErrorV2::Statement);
    }
    encode_full_bitcoin_statement_v2(&expected)
        .map_err(|_| FullBitcoinAdapterErrorV2::Statement)?;
    Ok(expected)
}

pub fn verify_transition_receipt_chain_v2<V: FullBitcoinReceiptVerifierV2>(
    checkpoint: ReviewedBitcoinCheckpointPublicValuesV2,
    source_configuration_commitment: [u8; 32],
    transition_program_id: [u8; 32],
    receipts: &[RecursiveReceiptBindingV2],
    verifier: &V,
) -> Result<FullBitcoinTransitionPublicValuesV2, FullBitcoinAdapterErrorV2> {
    if receipts.is_empty() || receipts.len() > MAX_FULL_BITCOIN_TRANSITION_RECEIPTS_V2 {
        return Err(FullBitcoinAdapterErrorV2::TransitionChain);
    }
    let mut previous = CheckpointOrTransitionV2::Checkpoint(checkpoint);
    for receipt in receipts {
        let current = decode_full_bitcoin_transition_public_values_v2(&receipt.public_values)
            .map_err(|_| FullBitcoinAdapterErrorV2::TransitionChain)?;
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > MAX_FULL_BITCOIN_RECEIPT_MARKER_BYTES_V2
            || current.source_configuration_commitment != source_configuration_commitment
            || !previous.connects_to(current)
        {
            return Err(FullBitcoinAdapterErrorV2::TransitionChain);
        }
        verifier.verify(
            transition_program_id,
            &receipt.public_values,
            &receipt.proof_marker,
        )?;
        previous = CheckpointOrTransitionV2::Transition(current);
    }
    match previous {
        CheckpointOrTransitionV2::Checkpoint(_) => Err(FullBitcoinAdapterErrorV2::TransitionChain),
        CheckpointOrTransitionV2::Transition(value) => Ok(value),
    }
}

#[derive(Clone, Copy)]
enum CheckpointOrTransitionV2 {
    Checkpoint(ReviewedBitcoinCheckpointPublicValuesV2),
    Transition(FullBitcoinTransitionPublicValuesV2),
}

impl CheckpointOrTransitionV2 {
    fn connects_to(self, next: FullBitcoinTransitionPublicValuesV2) -> bool {
        match self {
            Self::Checkpoint(previous) => {
                next.predecessor_state_commitment == previous.selected_state_commitment
                    && next.predecessor_height == previous.selected_height
                    && next.predecessor_frontier_commitment == previous.frontier_commitment
                    && next.predecessor_event_stream_commitment == previous.event_stream_commitment
                    && previous.event_sequence.checked_add(1) == Some(next.first_discovery_sequence)
            }
            Self::Transition(previous) => {
                next.predecessor_state_commitment == previous.successor_state_commitment
                    && next.predecessor_height == previous.successor_height
                    && next.predecessor_frontier_commitment
                        == previous.successor_frontier_commitment
                    && next.predecessor_event_stream_commitment
                        == previous.successor_event_stream_commitment
                    && previous.final_discovery_sequence.checked_add(1)
                        == Some(next.first_discovery_sequence)
            }
        }
    }
}

fn validate_shape(input: &FullBitcoinAdapterInputV2) -> Result<(), FullBitcoinAdapterErrorV2> {
    if input.version != FULL_BITCOIN_ADAPTER_INPUT_VERSION_V2 {
        return Err(FullBitcoinAdapterErrorV2::UnsupportedVersion);
    }
    if input.transition_receipts.is_empty()
        || input.transition_receipts.len() > MAX_FULL_BITCOIN_TRANSITION_RECEIPTS_V2
        || input.checkpoint_receipt.proof_marker.is_empty()
        || input.checkpoint_receipt.proof_marker.len() > MAX_FULL_BITCOIN_RECEIPT_MARKER_BYTES_V2
        || input.transition_receipts.iter().any(|receipt| {
            receipt.public_values.is_empty()
                || receipt.proof_marker.is_empty()
                || receipt.proof_marker.len() > MAX_FULL_BITCOIN_RECEIPT_MARKER_BYTES_V2
        })
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullBitcoinAdapterErrorV2::NonCanonicalInput)?
            > MAX_FULL_BITCOIN_ADAPTER_INPUT_BYTES_V2 as u64
    {
        return Err(FullBitcoinAdapterErrorV2::NonCanonicalInput);
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FULL_BITCOIN_ADAPTER_INPUT_BYTES_V2 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExactVerifier;

    impl FullBitcoinReceiptVerifierV2 for ExactVerifier {
        fn verify(
            &self,
            program_id: [u8; 32],
            _public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), FullBitcoinAdapterErrorV2> {
            if program_id == [9; 32] && proof_marker == [0xaa] {
                Ok(())
            } else {
                Err(FullBitcoinAdapterErrorV2::Receipt)
            }
        }
    }

    fn checkpoint() -> ReviewedBitcoinCheckpointPublicValuesV2 {
        ReviewedBitcoinCheckpointPublicValuesV2 {
            source_configuration_commitment: [1; 32],
            selected_state_commitment: [2; 32],
            frontier_commitment: [3; 32],
            event_stream_commitment: [4; 32],
            selected_height: 10,
            selected_tip_hash_internal: [5; 32],
            event_sequence: 20,
        }
    }

    fn transition() -> FullBitcoinTransitionPublicValuesV2 {
        FullBitcoinTransitionPublicValuesV2 {
            source_configuration_commitment: [1; 32],
            predecessor_state_commitment: [2; 32],
            predecessor_height: 10,
            predecessor_frontier_commitment: [3; 32],
            predecessor_event_stream_commitment: [4; 32],
            successor_state_commitment: [6; 32],
            successor_height: 11,
            successor_tip_hash_internal: [7; 32],
            successor_frontier_commitment: [8; 32],
            successor_event_stream_commitment: [10; 32],
            step_count: 1,
            first_discovery_sequence: 21,
            final_discovery_sequence: 21,
        }
    }

    #[test]
    fn receipt_chain_binds_every_checkpoint_endpoint_and_sequence() {
        let transition = transition();
        let receipt = RecursiveReceiptBindingV2 {
            public_values: transition.canonical_bytes().to_vec(),
            proof_marker: vec![0xaa],
        };
        assert_eq!(
            verify_transition_receipt_chain_v2(
                checkpoint(),
                [1; 32],
                [9; 32],
                std::slice::from_ref(&receipt),
                &ExactVerifier,
            )
            .unwrap(),
            transition
        );

        let mut wrong_checkpoint = checkpoint();
        wrong_checkpoint.event_stream_commitment[0] ^= 1;
        assert_eq!(
            verify_transition_receipt_chain_v2(
                wrong_checkpoint,
                [1; 32],
                [9; 32],
                std::slice::from_ref(&receipt),
                &ExactVerifier,
            ),
            Err(FullBitcoinAdapterErrorV2::TransitionChain)
        );
        let mut wrong_transition = transition;
        wrong_transition.first_discovery_sequence += 1;
        wrong_transition.final_discovery_sequence += 1;
        assert_eq!(
            verify_transition_receipt_chain_v2(
                checkpoint(),
                [1; 32],
                [9; 32],
                &[RecursiveReceiptBindingV2 {
                    public_values: wrong_transition.canonical_bytes().to_vec(),
                    proof_marker: vec![0xaa],
                }],
                &ExactVerifier,
            ),
            Err(FullBitcoinAdapterErrorV2::TransitionChain)
        );
        assert_eq!(
            verify_transition_receipt_chain_v2(checkpoint(), [1; 32], [9; 32], &[], &ExactVerifier,),
            Err(FullBitcoinAdapterErrorV2::TransitionChain)
        );
    }
}
