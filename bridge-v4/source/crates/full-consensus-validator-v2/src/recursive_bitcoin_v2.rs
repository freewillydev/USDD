//! Canonical bounded relation for recursively proving fully executed Bitcoin
//! state and best-work-frontier transitions.
//!
//! A caller must bind the predecessor commitments to a verified receipt or
//! reviewed genesis profile. Each discovered block authenticates its executed
//! parent in the current frontier, executes completely, receives the exact
//! next global discovery sequence, and is inserted before final selection.

use crate::elements_v2::FullBitcoinBlockEvidenceStepV2;
use crate::state_frontier_v2::{
    apply_executed_frontier_mutation_v2, execute_bitcoin_executed_successor_v2,
    executed_frontier_root_commitment_v2, verify_executed_frontier_membership_v2,
    BitcoinExecutedConsensusStateV2, BitcoinExecutedFrontierMutationV2,
    BitcoinExecutedFrontierNodeV2, BitcoinExecutedFrontierPathV2,
};
use crate::{tagged_hash, FullValidatorPrimitiveErrorV2, Hash32};
use bincode::Options;
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};

// Breaking unreleased wire revision for authenticated executed-state schema 2.
// Rebuild the guest and freeze its new identity; old receipts are not migrated.
pub const FULL_BITCOIN_TRANSITION_INPUT_VERSION_V2: u8 = 4;
pub const FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_VERSION_V2: u8 = 3;
pub const MAX_FULL_BITCOIN_TRANSITION_STEPS_V2: usize = 64;
pub const MAX_FULL_BITCOIN_TRANSITION_INPUT_BYTES_V2: usize = 16 * 1024 * 1024;
pub const FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_BYTES_V2: usize = 301;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinDiscoveredBlockV2 {
    pub parent: BitcoinExecutedConsensusStateV2,
    pub parent_membership_path: BitcoinExecutedFrontierPathV2,
    pub step: FullBitcoinBlockEvidenceStepV2,
    pub insertion_path: BitcoinExecutedFrontierPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinTransitionInputV2 {
    pub version: u8,
    pub predecessor_selected: BitcoinExecutedConsensusStateV2,
    pub predecessor_frontier: BitcoinExecutedFrontierNodeV2,
    pub predecessor_selected_membership_path: BitcoinExecutedFrontierPathV2,
    pub predecessor_event_stream_commitment: Hash32,
    /// Exact source-event order, including competing branches.
    pub discovered_blocks: Vec<FullBitcoinDiscoveredBlockV2>,
    pub successor_selected: BitcoinExecutedConsensusStateV2,
    pub successor_selected_membership_path: BitcoinExecutedFrontierPathV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullBitcoinTransitionPublicValuesV2 {
    pub source_configuration_commitment: Hash32,
    pub predecessor_state_commitment: Hash32,
    pub predecessor_height: u32,
    pub predecessor_frontier_commitment: Hash32,
    pub predecessor_event_stream_commitment: Hash32,
    pub successor_state_commitment: Hash32,
    pub successor_height: u32,
    pub successor_tip_hash_internal: Hash32,
    pub successor_frontier_commitment: Hash32,
    pub successor_event_stream_commitment: Hash32,
    pub step_count: u32,
    pub first_discovery_sequence: u128,
    pub final_discovery_sequence: u128,
}

impl FullBitcoinTransitionPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_BYTES_V2] {
        let mut output = [0u8; FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_BYTES_V2];
        let mut cursor = 0usize;
        output[cursor] = FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_VERSION_V2;
        cursor += 1;
        for value in [
            self.source_configuration_commitment,
            self.predecessor_state_commitment,
        ] {
            output[cursor..cursor + 32].copy_from_slice(&value);
            cursor += 32;
        }
        output[cursor..cursor + 4].copy_from_slice(&self.predecessor_height.to_be_bytes());
        cursor += 4;
        output[cursor..cursor + 32].copy_from_slice(&self.predecessor_frontier_commitment);
        cursor += 32;
        output[cursor..cursor + 32].copy_from_slice(&self.predecessor_event_stream_commitment);
        cursor += 32;
        output[cursor..cursor + 32].copy_from_slice(&self.successor_state_commitment);
        cursor += 32;
        output[cursor..cursor + 4].copy_from_slice(&self.successor_height.to_be_bytes());
        cursor += 4;
        output[cursor..cursor + 32].copy_from_slice(&self.successor_tip_hash_internal);
        cursor += 32;
        output[cursor..cursor + 32].copy_from_slice(&self.successor_frontier_commitment);
        cursor += 32;
        output[cursor..cursor + 32].copy_from_slice(&self.successor_event_stream_commitment);
        cursor += 32;
        output[cursor..cursor + 4].copy_from_slice(&self.step_count.to_be_bytes());
        cursor += 4;
        output[cursor..cursor + 16].copy_from_slice(&self.first_discovery_sequence.to_be_bytes());
        cursor += 16;
        output[cursor..cursor + 16].copy_from_slice(&self.final_discovery_sequence.to_be_bytes());
        cursor += 16;
        debug_assert_eq!(cursor, output.len());
        output
    }

    pub fn commitment(self) -> Hash32 {
        tagged_hash(
            "ECX/full-bitcoin-transition-public-values/v2",
            &self.canonical_bytes(),
        )
    }
}

pub fn decode_full_bitcoin_transition_public_values_v2(
    bytes: &[u8],
) -> Result<FullBitcoinTransitionPublicValuesV2, FullValidatorPrimitiveErrorV2> {
    if bytes.len() != FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_BYTES_V2
        || bytes[0] != FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_VERSION_V2
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let mut cursor = 1usize;
    let mut take = |length: usize| {
        let start = cursor;
        cursor += length;
        &bytes[start..cursor]
    };
    let source_configuration_commitment = take(32).try_into().unwrap();
    let predecessor_state_commitment = take(32).try_into().unwrap();
    let predecessor_height = u32::from_be_bytes(take(4).try_into().unwrap());
    let predecessor_frontier_commitment = take(32).try_into().unwrap();
    let predecessor_event_stream_commitment = take(32).try_into().unwrap();
    let successor_state_commitment = take(32).try_into().unwrap();
    let successor_height = u32::from_be_bytes(take(4).try_into().unwrap());
    let successor_tip_hash_internal = take(32).try_into().unwrap();
    let successor_frontier_commitment = take(32).try_into().unwrap();
    let successor_event_stream_commitment = take(32).try_into().unwrap();
    let step_count = u32::from_be_bytes(take(4).try_into().unwrap());
    let first_discovery_sequence = u128::from_be_bytes(take(16).try_into().unwrap());
    let final_discovery_sequence = u128::from_be_bytes(take(16).try_into().unwrap());
    debug_assert_eq!(cursor, bytes.len());
    let expected_final = first_discovery_sequence
        .checked_add(u128::from(
            step_count
                .checked_sub(1)
                .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?,
        ))
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let values = FullBitcoinTransitionPublicValuesV2 {
        source_configuration_commitment,
        predecessor_state_commitment,
        predecessor_height,
        predecessor_frontier_commitment,
        predecessor_event_stream_commitment,
        successor_state_commitment,
        successor_height,
        successor_tip_hash_internal,
        successor_frontier_commitment,
        successor_event_stream_commitment,
        step_count,
        first_discovery_sequence,
        final_discovery_sequence,
    };
    if source_configuration_commitment == [0; 32]
        || predecessor_state_commitment == [0; 32]
        || predecessor_frontier_commitment == [0; 32]
        || predecessor_event_stream_commitment == [0; 32]
        || successor_state_commitment == [0; 32]
        || successor_tip_hash_internal == [0; 32]
        || successor_frontier_commitment == [0; 32]
        || successor_event_stream_commitment == [0; 32]
        || final_discovery_sequence != expected_final
        || values.canonical_bytes() != bytes
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(values)
}

pub fn encode_full_bitcoin_transition_input_v2(
    input: &FullBitcoinTransitionInputV2,
) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
    validate_input_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)
}

pub fn decode_full_bitcoin_transition_input_v2(
    bytes: &[u8],
) -> Result<FullBitcoinTransitionInputV2, FullValidatorPrimitiveErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_FULL_BITCOIN_TRANSITION_INPUT_BYTES_V2 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let input: FullBitcoinTransitionInputV2 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    validate_input_shape(&input)?;
    if encode_full_bitcoin_transition_input_v2(&input)? != bytes {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(input)
}

pub fn execute_full_bitcoin_transition_v2(
    input: &FullBitcoinTransitionInputV2,
) -> Result<
    (
        BitcoinExecutedConsensusStateV2,
        FullBitcoinTransitionPublicValuesV2,
    ),
    FullValidatorPrimitiveErrorV2,
> {
    validate_input_shape(input)?;
    let predecessor_tip = input.predecessor_selected.frontier_tip()?;
    if input.predecessor_frontier.best != Some(predecessor_tip) {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    verify_executed_frontier_membership_v2(
        input.predecessor_frontier,
        predecessor_tip,
        &input.predecessor_selected_membership_path,
    )?;
    let predecessor_state_commitment = input.predecessor_selected.commitment()?;
    let predecessor_frontier_commitment =
        executed_frontier_root_commitment_v2(input.predecessor_frontier)?;
    let first_discovery_sequence = input
        .predecessor_frontier
        .maximum_discovery_sequence
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;

    let mut frontier = input.predecessor_frontier;
    let mut event_stream_commitment = input.predecessor_event_stream_commitment;
    for event in &input.discovered_blocks {
        let parent_tip = event.parent.frontier_tip()?;
        verify_executed_frontier_membership_v2(
            frontier,
            parent_tip,
            &event.parent_membership_path,
        )?;
        let sequence = frontier
            .maximum_discovery_sequence
            .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?
            .checked_add(1)
            .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
        let successor =
            execute_bitcoin_executed_successor_v2(&event.parent, &event.step, sequence)?;
        let mut event_preimage = Vec::with_capacity(112);
        event_preimage.extend_from_slice(&event_stream_commitment);
        event_preimage.extend_from_slice(&sequence.to_be_bytes());
        event_preimage.extend_from_slice(&event.parent.tip.block_hash.to_byte_array());
        event_preimage.extend_from_slice(&successor.tip.block_hash.to_byte_array());
        event_stream_commitment = tagged_hash(
            "ECX/full-bitcoin-discovered-block-event/v2",
            &event_preimage,
        );
        frontier = apply_executed_frontier_mutation_v2(
            frontier,
            &BitcoinExecutedFrontierMutationV2 {
                candidate: successor.frontier_tip()?,
                insert: true,
                path: event.insertion_path.clone(),
            },
        )?;
    }

    let successor_tip = input.successor_selected.frontier_tip()?;
    if frontier.best != Some(successor_tip) {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    verify_executed_frontier_membership_v2(
        frontier,
        successor_tip,
        &input.successor_selected_membership_path,
    )?;
    let step_count = u32::try_from(input.discovered_blocks.len())
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let final_discovery_sequence = frontier
        .maximum_discovery_sequence
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let public_values = FullBitcoinTransitionPublicValuesV2 {
        source_configuration_commitment: input.predecessor_selected.source_configuration_commitment,
        predecessor_state_commitment,
        predecessor_height: input.predecessor_selected.tip.height,
        predecessor_frontier_commitment,
        predecessor_event_stream_commitment: input.predecessor_event_stream_commitment,
        successor_state_commitment: input.successor_selected.commitment()?,
        successor_height: input.successor_selected.tip.height,
        successor_tip_hash_internal: input.successor_selected.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: executed_frontier_root_commitment_v2(frontier)?,
        successor_event_stream_commitment: event_stream_commitment,
        step_count,
        first_discovery_sequence,
        final_discovery_sequence,
    };
    Ok((input.successor_selected.clone(), public_values))
}

fn validate_input_shape(
    input: &FullBitcoinTransitionInputV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if input.version != FULL_BITCOIN_TRANSITION_INPUT_VERSION_V2
        || input.discovered_blocks.is_empty()
        || input.discovered_blocks.len() > MAX_FULL_BITCOIN_TRANSITION_STEPS_V2
        || input.predecessor_event_stream_commitment == [0; 32]
        || input.predecessor_selected.source_configuration_commitment
            != input.successor_selected.source_configuration_commitment
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?
            > MAX_FULL_BITCOIN_TRANSITION_INPUT_BYTES_V2 as u64
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    input.predecessor_selected.validate()?;
    input.successor_selected.validate()
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FULL_BITCOIN_TRANSITION_INPUT_BYTES_V2 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_frontier_v2::tests::{
        executed_state, mined_successor_step, two_leaf_frontier_fixture,
    };

    fn input() -> FullBitcoinTransitionInputV2 {
        let predecessor = executed_state();
        let step = mined_successor_step();
        let successor = execute_bitcoin_executed_successor_v2(&predecessor, &step, 1).unwrap();
        let (predecessor_frontier, predecessor_path, successor_path, _) = two_leaf_frontier_fixture(
            predecessor.frontier_tip().unwrap(),
            successor.frontier_tip().unwrap(),
        );
        FullBitcoinTransitionInputV2 {
            version: FULL_BITCOIN_TRANSITION_INPUT_VERSION_V2,
            predecessor_selected: predecessor.clone(),
            predecessor_frontier,
            predecessor_selected_membership_path: predecessor_path.clone(),
            predecessor_event_stream_commitment: [9; 32],
            discovered_blocks: vec![FullBitcoinDiscoveredBlockV2 {
                parent: predecessor,
                parent_membership_path: predecessor_path,
                step,
                insertion_path: successor_path.clone(),
            }],
            successor_selected: successor,
            successor_selected_membership_path: successor_path,
        }
    }

    #[test]
    fn public_values_encoding_is_fixed_and_every_field_is_bound() {
        let values = FullBitcoinTransitionPublicValuesV2 {
            source_configuration_commitment: [1; 32],
            predecessor_state_commitment: [2; 32],
            predecessor_height: 3,
            predecessor_frontier_commitment: [4; 32],
            predecessor_event_stream_commitment: [5; 32],
            successor_state_commitment: [6; 32],
            successor_height: 7,
            successor_tip_hash_internal: [8; 32],
            successor_frontier_commitment: [9; 32],
            successor_event_stream_commitment: [10; 32],
            step_count: 11,
            first_discovery_sequence: 12,
            final_discovery_sequence: 22,
        };
        assert_eq!(
            values.canonical_bytes().len(),
            FULL_BITCOIN_TRANSITION_PUBLIC_VALUES_BYTES_V2
        );
        assert_eq!(
            decode_full_bitcoin_transition_public_values_v2(&values.canonical_bytes()).unwrap(),
            values
        );
        let commitment = values.commitment();
        let mut changed = values;
        changed.successor_frontier_commitment[0] ^= 1;
        assert_ne!(changed.commitment(), commitment);
        let mut changed = values;
        changed.successor_state_commitment[0] ^= 1;
        assert_ne!(changed.commitment(), commitment);
        let mut changed = values;
        changed.successor_event_stream_commitment[0] ^= 1;
        assert_ne!(changed.commitment(), commitment);
        let mut invalid_interval = values.canonical_bytes();
        *invalid_interval.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_full_bitcoin_transition_public_values_v2(&invalid_interval),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
    }

    #[test]
    fn mined_event_updates_authenticated_frontier_and_selects_executed_best_leaf() {
        let input = input();
        let encoded = encode_full_bitcoin_transition_input_v2(&input).unwrap();
        let decoded = decode_full_bitcoin_transition_input_v2(&encoded).unwrap();
        assert_eq!(decoded, input);
        let mut old_wire = encoded.clone();
        old_wire[0] = 3;
        assert_eq!(
            decode_full_bitcoin_transition_input_v2(&old_wire),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut old_state = input.clone();
        old_state.predecessor_selected.version = 1;
        assert_eq!(
            encode_full_bitcoin_transition_input_v2(&old_state),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let (successor, public_values) = execute_full_bitcoin_transition_v2(&decoded).unwrap();
        assert_eq!(public_values.predecessor_height, 0);
        assert_eq!(public_values.successor_height, 1);
        assert_eq!(
            public_values.successor_state_commitment,
            successor.commitment().unwrap()
        );
        assert_eq!(public_values.step_count, 1);
        assert_eq!(public_values.first_discovery_sequence, 1);
        assert_eq!(public_values.final_discovery_sequence, 1);

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_full_bitcoin_transition_input_v2(&trailing),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut omitted = input;
        omitted.discovered_blocks.clear();
        assert_eq!(
            execute_full_bitcoin_transition_v2(&omitted),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut wrong_best = decoded;
        wrong_best.successor_selected = wrong_best.predecessor_selected.clone();
        assert_eq!(
            execute_full_bitcoin_transition_v2(&wrong_best),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
    }
}
