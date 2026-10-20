//! Reviewed checkpoint relation for bootstrapping recursive Bitcoin state.
//!
//! The receipt validates structure and exact commitments; trust comes from the
//! source configuration committing this exact preimage and checkpoint program
//! identity. This relation does not turn an operator-selected checkpoint into
//! a trustless genesis proof.

use crate::state_frontier_v2::{
    executed_frontier_root_commitment_v2, verify_executed_frontier_membership_v2,
    BitcoinExecutedConsensusStateV2, BitcoinExecutedFrontierNodeV2, BitcoinExecutedFrontierPathV2,
};
use crate::{tagged_hash, FullValidatorPrimitiveErrorV2, Hash32};
use bincode::Options;
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};

// Breaking unreleased wire revision: nested executed states now authenticate
// the mandatory Signet challenge field. Old checkpoint inputs are rejected.
pub const REVIEWED_BITCOIN_CHECKPOINT_INPUT_VERSION_V2: u8 = 2;
pub const REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const MAX_REVIEWED_BITCOIN_CHECKPOINT_INPUT_BYTES_V2: usize = 4 * 1024 * 1024;
pub const REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_BYTES_V2: usize = 181;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedBitcoinCheckpointInputV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub selected_state: BitcoinExecutedConsensusStateV2,
    pub frontier: BitcoinExecutedFrontierNodeV2,
    pub selected_membership_path: BitcoinExecutedFrontierPathV2,
    pub event_stream_commitment: Hash32,
    pub event_sequence: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewedBitcoinCheckpointPublicValuesV2 {
    pub source_configuration_commitment: Hash32,
    pub selected_state_commitment: Hash32,
    pub frontier_commitment: Hash32,
    pub event_stream_commitment: Hash32,
    pub selected_height: u32,
    pub selected_tip_hash_internal: Hash32,
    pub event_sequence: u128,
}

impl ReviewedBitcoinCheckpointPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_BYTES_V2] {
        let mut output = [0u8; REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_BYTES_V2];
        let mut cursor = 0usize;
        output[cursor] = REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_VERSION_V2;
        cursor += 1;
        for value in [
            self.source_configuration_commitment,
            self.selected_state_commitment,
            self.frontier_commitment,
            self.event_stream_commitment,
        ] {
            output[cursor..cursor + 32].copy_from_slice(&value);
            cursor += 32;
        }
        output[cursor..cursor + 4].copy_from_slice(&self.selected_height.to_be_bytes());
        cursor += 4;
        output[cursor..cursor + 32].copy_from_slice(&self.selected_tip_hash_internal);
        cursor += 32;
        output[cursor..cursor + 16].copy_from_slice(&self.event_sequence.to_be_bytes());
        cursor += 16;
        debug_assert_eq!(cursor, output.len());
        output
    }

    pub fn commitment(self) -> Hash32 {
        tagged_hash(
            "ECX/reviewed-bitcoin-checkpoint-public-values/v2",
            &self.canonical_bytes(),
        )
    }
}

pub fn encode_reviewed_bitcoin_checkpoint_input_v2(
    input: &ReviewedBitcoinCheckpointInputV2,
) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
    validate_input(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)
}

pub fn decode_reviewed_bitcoin_checkpoint_input_v2(
    bytes: &[u8],
) -> Result<ReviewedBitcoinCheckpointInputV2, FullValidatorPrimitiveErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_REVIEWED_BITCOIN_CHECKPOINT_INPUT_BYTES_V2 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let input: ReviewedBitcoinCheckpointInputV2 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    validate_input(&input)?;
    if encode_reviewed_bitcoin_checkpoint_input_v2(&input)? != bytes {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(input)
}

pub fn execute_reviewed_bitcoin_checkpoint_v2(
    input: &ReviewedBitcoinCheckpointInputV2,
) -> Result<ReviewedBitcoinCheckpointPublicValuesV2, FullValidatorPrimitiveErrorV2> {
    validate_input(input)?;
    let selected_tip = input.selected_state.frontier_tip()?;
    if input.frontier.best != Some(selected_tip)
        || input.frontier.maximum_discovery_sequence != Some(input.event_sequence)
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    verify_executed_frontier_membership_v2(
        input.frontier,
        selected_tip,
        &input.selected_membership_path,
    )?;
    Ok(ReviewedBitcoinCheckpointPublicValuesV2 {
        source_configuration_commitment: input.source_configuration_commitment,
        selected_state_commitment: input.selected_state.commitment()?,
        frontier_commitment: executed_frontier_root_commitment_v2(input.frontier)?,
        event_stream_commitment: input.event_stream_commitment,
        selected_height: input.selected_state.tip.height,
        selected_tip_hash_internal: input.selected_state.tip.block_hash.to_byte_array(),
        event_sequence: input.event_sequence,
    })
}

fn validate_input(
    input: &ReviewedBitcoinCheckpointInputV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if input.version != REVIEWED_BITCOIN_CHECKPOINT_INPUT_VERSION_V2
        || input.source_configuration_commitment == [0; 32]
        || input.event_stream_commitment == [0; 32]
        || input.selected_state.source_configuration_commitment
            != input.source_configuration_commitment
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?
            > MAX_REVIEWED_BITCOIN_CHECKPOINT_INPUT_BYTES_V2 as u64
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    input.selected_state.validate()
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_REVIEWED_BITCOIN_CHECKPOINT_INPUT_BYTES_V2 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_frontier_v2::tests::executed_state;
    use crate::state_frontier_v2::{
        apply_executed_frontier_mutation_v2, canonical_empty_executed_frontier_path_v2,
        canonical_empty_executed_frontier_root_v2, BitcoinExecutedFrontierMutationV2,
    };

    fn input() -> ReviewedBitcoinCheckpointInputV2 {
        let selected_state = executed_state();
        let path = canonical_empty_executed_frontier_path_v2();
        let frontier = apply_executed_frontier_mutation_v2(
            canonical_empty_executed_frontier_root_v2(),
            &BitcoinExecutedFrontierMutationV2 {
                candidate: selected_state.frontier_tip().unwrap(),
                insert: true,
                path: path.clone(),
            },
        )
        .unwrap();
        ReviewedBitcoinCheckpointInputV2 {
            version: REVIEWED_BITCOIN_CHECKPOINT_INPUT_VERSION_V2,
            source_configuration_commitment: selected_state.source_configuration_commitment,
            selected_state,
            frontier,
            selected_membership_path: path,
            event_stream_commitment: [7; 32],
            event_sequence: 0,
        }
    }

    #[test]
    fn canonical_checkpoint_binds_state_frontier_and_event_cursor() {
        let input = input();
        let encoded = encode_reviewed_bitcoin_checkpoint_input_v2(&input).unwrap();
        assert_eq!(
            decode_reviewed_bitcoin_checkpoint_input_v2(&encoded).unwrap(),
            input
        );
        let values = execute_reviewed_bitcoin_checkpoint_v2(&input).unwrap();
        let mut old_wire = encoded.clone();
        old_wire[0] = 1;
        assert_eq!(
            decode_reviewed_bitcoin_checkpoint_input_v2(&old_wire),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut old_state = input.clone();
        old_state.selected_state.version = 1;
        assert_eq!(
            encode_reviewed_bitcoin_checkpoint_input_v2(&old_state),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        assert_eq!(
            values.canonical_bytes().len(),
            REVIEWED_BITCOIN_CHECKPOINT_PUBLIC_VALUES_BYTES_V2
        );
        assert_eq!(values.selected_height, 0);
        let mut wrong = input.clone();
        wrong.event_sequence = 1;
        assert_eq!(
            execute_reviewed_bitcoin_checkpoint_v2(&wrong),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_reviewed_bitcoin_checkpoint_input_v2(&trailing),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
    }
}
