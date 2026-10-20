//! Reviewed post-fork Alpha checkpoint, distinct from the Bitcoin/Signet ABI.
//!
//! This relation checks structure, exact preimage commitment, selected frontier
//! membership and the event cursor. It does NOT authenticate history, clocks,
//! source-event completeness or an operator-selected UTXO root. A consumer must
//! independently review and freeze this exact input commitment AND the rebuilt
//! checkpoint program identity. A receipt is not a genesis-replay proof.

use crate::alpha_state_v3::{alpha_consensus_profile_commitment_v3, AlphaExecutedConsensusStateV3};
use crate::state_frontier_v2::{
    executed_frontier_root_commitment_v2, verify_executed_frontier_membership_v2,
    BitcoinExecutedFrontierNodeV2, BitcoinExecutedFrontierPathV2,
};
use crate::{tagged_hash, FullValidatorPrimitiveErrorV2, Hash32};
use bincode::Options;
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};

pub const REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3: u8 = 0xa3;
pub const REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_VERSION_V3: u8 = 0xa3;
pub const MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3: usize = 4 * 1024 * 1024;
pub const REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_BYTES_V3: usize = 277;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedAlphaCheckpointInputV3 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub selected_state: AlphaExecutedConsensusStateV3,
    pub frontier: BitcoinExecutedFrontierNodeV2,
    pub selected_membership_path: BitcoinExecutedFrontierPathV2,
    pub event_stream_commitment: Hash32,
    pub event_sequence: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewedAlphaCheckpointPublicValuesV3 {
    pub source_configuration_commitment: Hash32,
    pub checkpoint_input_commitment: Hash32,
    pub selected_state_commitment: Hash32,
    pub all_slots_state_commitment: Hash32,
    pub frontier_commitment: Hash32,
    pub event_stream_commitment: Hash32,
    pub selected_height: u32,
    pub selected_tip_hash_internal: Hash32,
    pub event_sequence: u128,
}

impl ReviewedAlphaCheckpointPublicValuesV3 {
    pub fn canonical_bytes(self) -> [u8; REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_BYTES_V3] {
        let mut bytes = [0; REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_BYTES_V3];
        bytes[0] = REVIEWED_ALPHA_CHECKPOINT_PUBLIC_VALUES_VERSION_V3;
        let mut cursor = 1;
        for hash in [
            alpha_consensus_profile_commitment_v3(),
            self.source_configuration_commitment,
            self.checkpoint_input_commitment,
            self.selected_state_commitment,
            self.all_slots_state_commitment,
            self.frontier_commitment,
            self.event_stream_commitment,
        ] {
            bytes[cursor..cursor + 32].copy_from_slice(&hash);
            cursor += 32;
        }
        bytes[cursor..cursor + 4].copy_from_slice(&self.selected_height.to_be_bytes());
        cursor += 4;
        bytes[cursor..cursor + 32].copy_from_slice(&self.selected_tip_hash_internal);
        cursor += 32;
        bytes[cursor..cursor + 16].copy_from_slice(&self.event_sequence.to_be_bytes());
        cursor += 16;
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    pub fn commitment(self) -> Hash32 {
        tagged_hash(
            "ECX/reviewed-alpha-checkpoint-public-values/v3",
            &self.canonical_bytes(),
        )
    }
}

pub fn encode_reviewed_alpha_checkpoint_input_v3(
    input: &ReviewedAlphaCheckpointInputV3,
) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
    validate_input(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)
}

pub fn decode_reviewed_alpha_checkpoint_input_v3(
    bytes: &[u8],
) -> Result<ReviewedAlphaCheckpointInputV3, FullValidatorPrimitiveErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let input = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    if encode_reviewed_alpha_checkpoint_input_v3(&input)? != bytes {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(input)
}

pub fn reviewed_alpha_checkpoint_input_commitment_v3(
    input: &ReviewedAlphaCheckpointInputV3,
) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
    Ok(tagged_hash(
        "ECX/reviewed-alpha-checkpoint-input/v3",
        &encode_reviewed_alpha_checkpoint_input_v3(input)?,
    ))
}

pub fn execute_reviewed_alpha_checkpoint_v3(
    input: &ReviewedAlphaCheckpointInputV3,
) -> Result<ReviewedAlphaCheckpointPublicValuesV3, FullValidatorPrimitiveErrorV2> {
    validate_input(input)?;
    let selected = input.selected_state.frontier_tip()?;
    if input.frontier.best != Some(selected)
        || input.frontier.maximum_discovery_sequence != Some(input.event_sequence)
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    verify_executed_frontier_membership_v2(
        input.frontier,
        selected,
        &input.selected_membership_path,
    )?;
    Ok(ReviewedAlphaCheckpointPublicValuesV3 {
        source_configuration_commitment: input.source_configuration_commitment,
        checkpoint_input_commitment: reviewed_alpha_checkpoint_input_commitment_v3(input)?,
        selected_state_commitment: input.selected_state.commitment()?,
        all_slots_state_commitment: input
            .selected_state
            .bip300_state
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?,
        frontier_commitment: executed_frontier_root_commitment_v2(input.frontier)?,
        event_stream_commitment: input.event_stream_commitment,
        selected_height: input.selected_state.tip.height,
        selected_tip_hash_internal: input.selected_state.tip.block_hash.to_byte_array(),
        event_sequence: input.event_sequence,
    })
}

fn validate_input(
    input: &ReviewedAlphaCheckpointInputV3,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if input.version != REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3
        || input.source_configuration_commitment == [0; 32]
        || input.event_stream_commitment == [0; 32]
        || input.selected_state.source_configuration_commitment
            != input.source_configuration_commitment
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?
            > MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3 as u64
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    input.selected_state.validate()
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_REVIEWED_ALPHA_CHECKPOINT_INPUT_BYTES_V3 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha_state_v3::tests::synthetic_state;
    use crate::state_frontier_v2::{
        apply_executed_frontier_mutation_v2, canonical_empty_executed_frontier_path_v2,
        canonical_empty_executed_frontier_root_v2, BitcoinExecutedFrontierMutationV2,
    };

    // Synthetic shape evidence only, never a reviewed live checkpoint.
    fn input() -> ReviewedAlphaCheckpointInputV3 {
        let selected_state = synthetic_state();
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
        ReviewedAlphaCheckpointInputV3 {
            version: REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3,
            source_configuration_commitment: selected_state.source_configuration_commitment,
            selected_state,
            frontier,
            selected_membership_path: path,
            event_stream_commitment: [7; 32],
            event_sequence: 0,
        }
    }

    #[test]
    fn alpha_checkpoint_binds_exact_preimage_profile_and_all_slot_state() {
        let input = input();
        let encoded = encode_reviewed_alpha_checkpoint_input_v3(&input).unwrap();
        assert_eq!(
            decode_reviewed_alpha_checkpoint_input_v3(&encoded).unwrap(),
            input
        );
        let values = execute_reviewed_alpha_checkpoint_v3(&input).unwrap();
        assert_eq!(values.canonical_bytes().len(), 277);
        assert_eq!(
            &values.canonical_bytes()[1..33],
            &alpha_consensus_profile_commitment_v3()
        );
        assert_eq!(
            values.checkpoint_input_commitment,
            reviewed_alpha_checkpoint_input_commitment_v3(&input).unwrap()
        );
        assert_eq!(
            values.all_slots_state_commitment,
            input.selected_state.bip300_state.commitment().unwrap()
        );
        let mut changed = input.clone();
        changed.event_stream_commitment[0] ^= 1;
        let different = execute_reviewed_alpha_checkpoint_v3(&changed).unwrap();
        assert_ne!(
            different.checkpoint_input_commitment,
            values.checkpoint_input_commitment
        );
        assert_ne!(different.commitment(), values.commitment());
    }

    #[test]
    fn alpha_checkpoint_rejects_cursor_source_frontier_and_state_substitutions() {
        let input = input();
        let mut changed = input.clone();
        changed.event_sequence += 1;
        assert!(execute_reviewed_alpha_checkpoint_v3(&changed).is_err());
        let mut changed = input.clone();
        changed.source_configuration_commitment[0] ^= 1;
        assert!(execute_reviewed_alpha_checkpoint_v3(&changed).is_err());
        let mut changed = input.clone();
        changed.frontier.best = None;
        assert!(execute_reviewed_alpha_checkpoint_v3(&changed).is_err());
        let mut changed = input.clone();
        changed.selected_membership_path.siblings[0].hash[0] ^= 1;
        assert!(execute_reviewed_alpha_checkpoint_v3(&changed).is_err());
        let mut changed = input;
        changed.selected_state.utxo_root.hash[0] ^= 1;
        assert!(execute_reviewed_alpha_checkpoint_v3(&changed).is_err());
    }

    #[test]
    fn alpha_checkpoint_has_no_legacy_or_signet_decoder_fallback() {
        let input = input();
        let mut signet = input.clone();
        signet.selected_state.deployment_state.network_genesis =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet).block_hash();
        assert!(execute_reviewed_alpha_checkpoint_v3(&signet).is_err());
        assert!(encode_reviewed_alpha_checkpoint_input_v3(&signet).is_err());
        let encoded = encode_reviewed_alpha_checkpoint_input_v3(&input).unwrap();
        assert!(
            crate::checkpoint_bitcoin_v2::decode_reviewed_bitcoin_checkpoint_input_v2(&encoded)
                .is_err()
        );
        let mut old = encoded.clone();
        old[0] = 2;
        assert!(decode_reviewed_alpha_checkpoint_input_v3(&old).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_reviewed_alpha_checkpoint_input_v3(&trailing).is_err());
        let mut json = serde_json::to_value(input).unwrap();
        json["selected_state"]["pow_context"]["network"] = serde_json::json!("signet");
        assert!(serde_json::from_value::<ReviewedAlphaCheckpointInputV3>(json).is_err());
    }
}
