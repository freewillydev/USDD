//! Canonical bounded relation for recursively proving checkpoint-relative Alpha
//! state and best-work-frontier transitions.
//!
//! A caller must bind the predecessor commitments to a verified receipt or
//! reviewed post-Taproot Alpha checkpoint. This staged relation does not
//! authenticate that checkpoint, a clock, or source-event completeness itself. Each discovered block authenticates its executed
//! parent in the current frontier, executes completely, receives the exact
//! next global discovery sequence, and is inserted before final selection.

use crate::alpha_state_v3::{
    alpha_consensus_profile_commitment_v3, execute_alpha_executed_successor_v3,
    AlphaBlockEvidenceStepV3, AlphaExecutedConsensusStateV3,
};
use crate::state_frontier_v2::{
    apply_executed_frontier_mutation_v2, executed_frontier_root_commitment_v2,
    verify_executed_frontier_membership_v2, BitcoinExecutedFrontierMutationV2,
    BitcoinExecutedFrontierNodeV2, BitcoinExecutedFrontierPathV2,
};
use crate::{tagged_hash, FullValidatorPrimitiveErrorV2, Hash32};
use bincode::Options;
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};

// Breaking unreleased wire revision for authenticated executed-state Alpha schema 3.
// Rebuild the guest and freeze its new identity; old receipts are not migrated.
pub const FULL_ALPHA_TRANSITION_INPUT_VERSION_V3: u8 = 0xa3;
/// Compact transport only. Public-state semantics remain V3; a new guest
/// identity must still be qualified before this transport can be proved.
pub const COMPACT_ALPHA_TRANSITION_INPUT_VERSION: u8 = 0xa4;
pub const FULL_ALPHA_TRANSITION_PUBLIC_VALUES_VERSION_V3: u8 = 0xa3;
pub const MAX_FULL_ALPHA_TRANSITION_STEPS_V3: usize = 64;
pub const MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3: usize = 16 * 1024 * 1024;
pub const FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3: usize = 333;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullAlphaDiscoveredBlockV3<S = AlphaBlockEvidenceStepV3> {
    pub parent: AlphaExecutedConsensusStateV3,
    pub parent_membership_path: BitcoinExecutedFrontierPathV2,
    pub step: S,
    pub insertion_path: BitcoinExecutedFrontierPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullAlphaTransitionInputV3<S = AlphaBlockEvidenceStepV3> {
    pub version: u8,
    pub predecessor_selected: AlphaExecutedConsensusStateV3,
    pub predecessor_frontier: BitcoinExecutedFrontierNodeV2,
    pub predecessor_selected_membership_path: BitcoinExecutedFrontierPathV2,
    pub predecessor_event_stream_commitment: Hash32,
    /// Exact source-event order, including competing branches.
    pub discovered_blocks: Vec<FullAlphaDiscoveredBlockV3<S>>,
    pub successor_selected: AlphaExecutedConsensusStateV3,
    pub successor_selected_membership_path: BitcoinExecutedFrontierPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactAlphaBlockEvidenceStep {
    #[serde(with = "bulk_bytes")]
    pub raw_block: Vec<u8>,
    pub authenticated_adjusted_time: u64,
    #[serde(with = "bulk_bytes")]
    pub utxo_frame: Vec<u8>,
}

// Bincode encodes both byte sequences and byte buffers as length + raw bytes.
// Bulk operations avoid millions of per-u8 serializer/visitor calls. Preserve
// JSON behavior and the outer bounded, byte-exact canonical reencoding gate.
mod bulk_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() { bytes.serialize(s) } else { s.serialize_bytes(bytes) }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() { return Vec::<u8>::deserialize(d); }
        struct Bytes;
        impl<'de> serde::de::Visitor<'de> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded byte buffer")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                if bytes.len() > super::MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 {
                    return Err(E::custom("byte buffer exceeds transition bound"));
                }
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                if bytes.len() > super::MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 {
                    return Err(E::custom("byte buffer exceeds transition bound"));
                }
                Ok(bytes)
            }
        }
        d.deserialize_byte_buf(Bytes)
    }
}

#[cfg(test)]
mod bulk_byte_tests {
    use super::*;
    #[test]
    fn compact_bulk_bytes_preserve_legacy_wire() {
        #[derive(Serialize, Deserialize)]
        struct Legacy { raw_block: Vec<u8>, authenticated_adjusted_time: u64, utxo_frame: Vec<u8> }
        for n in [0, 1, 255, 256, 65536] {
            let current = CompactAlphaBlockEvidenceStep {
                raw_block: (0..n).map(|i| i as u8).collect(),
                authenticated_adjusted_time: 12345,
                utxo_frame: vec![173; n],
            };
            let old = Legacy { raw_block: current.raw_block.clone(), authenticated_adjusted_time: 12345, utxo_frame: current.utxo_frame.clone() };
            let expected = canonical_options().serialize(&old).unwrap();
            assert_eq!(canonical_options().serialize(&current).unwrap(), expected);
            assert_eq!(canonical_options().deserialize::<CompactAlphaBlockEvidenceStep>(&expected).unwrap(), current);
            let mut extra = expected.clone(); extra.push(0);
            assert!(canonical_options().deserialize::<CompactAlphaBlockEvidenceStep>(&extra).is_err());
            if !expected.is_empty() { assert!(canonical_options().deserialize::<CompactAlphaBlockEvidenceStep>(&expected[..expected.len()-1]).is_err()); }
        }
        assert!(canonical_options().deserialize::<CompactAlphaBlockEvidenceStep>(&u64::MAX.to_le_bytes()).is_err());
    }
}

pub type CompactAlphaTransitionInput = FullAlphaTransitionInputV3<CompactAlphaBlockEvidenceStep>;

// Both transports use exactly the same frontier, event and selected-state
// relation. Only transaction witness consumption differs.
trait TransitionStep: Serialize {
    const VERSION: u8;
    fn raw_block(&self) -> &[u8];
    fn time(&self) -> u64;
    fn execute(&self, parent: &AlphaExecutedConsensusStateV3, sequence: u128)
        -> Result<AlphaExecutedConsensusStateV3, FullValidatorPrimitiveErrorV2>;
}

impl TransitionStep for AlphaBlockEvidenceStepV3 {
    const VERSION: u8 = FULL_ALPHA_TRANSITION_INPUT_VERSION_V3;
    fn raw_block(&self) -> &[u8] { &self.raw_block }
    fn time(&self) -> u64 { self.authenticated_adjusted_time }
    fn execute(&self, parent: &AlphaExecutedConsensusStateV3, sequence: u128)
        -> Result<AlphaExecutedConsensusStateV3, FullValidatorPrimitiveErrorV2> {
        execute_alpha_executed_successor_v3(parent, self, sequence)
    }
}

impl TransitionStep for CompactAlphaBlockEvidenceStep {
    const VERSION: u8 = COMPACT_ALPHA_TRANSITION_INPUT_VERSION;
    fn raw_block(&self) -> &[u8] { &self.raw_block }
    fn time(&self) -> u64 { self.authenticated_adjusted_time }
    fn execute(&self, parent: &AlphaExecutedConsensusStateV3, sequence: u128)
        -> Result<AlphaExecutedConsensusStateV3, FullValidatorPrimitiveErrorV2> {
        crate::alpha_state_v3::execute_alpha_compact_successor_with_effects_v3(
            parent, &self.raw_block, self.authenticated_adjusted_time, sequence, &self.utxo_frame,
        ).map(|(state, _)| state)
    }
}

pub fn encode_compact_alpha_transition_input(input: &CompactAlphaTransitionInput)
    -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
    validate_input_shape(input)?;
    canonical_options().serialize(input).map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)
}

pub fn decode_compact_alpha_transition_input(bytes: &[u8])
    -> Result<CompactAlphaTransitionInput, FullValidatorPrimitiveErrorV2> {
    if bytes.first() != Some(&COMPACT_ALPHA_TRANSITION_INPUT_VERSION)
        || bytes.len() > MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let input: CompactAlphaTransitionInput = canonical_options().deserialize(bytes)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    if encode_compact_alpha_transition_input(&input)? != bytes {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(input)
}

pub fn execute_compact_alpha_transition(input: &CompactAlphaTransitionInput)
    -> Result<(AlphaExecutedConsensusStateV3, FullAlphaTransitionPublicValuesV3), FullValidatorPrimitiveErrorV2> {
    execute_transition(input)
}

/// Exact version dispatch shared by native host and guest. No fallback parsing
/// or relabelling: both decoders retain their own canonical shape/size checks.
pub fn execute_encoded_alpha_transition(bytes: &[u8])
    -> Result<(AlphaExecutedConsensusStateV3, FullAlphaTransitionPublicValuesV3), FullValidatorPrimitiveErrorV2> {
    match bytes.first() {
        Some(&FULL_ALPHA_TRANSITION_INPUT_VERSION_V3) =>
            execute_full_alpha_transition_v3(&decode_full_alpha_transition_input_v3(bytes)?),
        Some(&COMPACT_ALPHA_TRANSITION_INPUT_VERSION) =>
            execute_compact_alpha_transition(&decode_compact_alpha_transition_input(bytes)?),
        _ => Err(FullValidatorPrimitiveErrorV2::ExecutedState),
    }
}

pub fn assemble_compact_alpha_transition(
    predecessor_selected: AlphaExecutedConsensusStateV3,
    predecessor_frontier: BitcoinExecutedFrontierNodeV2,
    predecessor_event_stream_commitment: Hash32,
    states: Vec<AlphaExecutedConsensusStateV3>,
    steps: Vec<CompactAlphaBlockEvidenceStep>,
) -> Result<CompactAlphaTransitionInput, FullValidatorPrimitiveErrorV2> {
    assemble_transition(predecessor_selected, predecessor_frontier,
        predecessor_event_stream_commitment, states, steps)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullAlphaTransitionPublicValuesV3 {
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

impl FullAlphaTransitionPublicValuesV3 {
    pub fn canonical_bytes(self) -> [u8; FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3] {
        let mut output = [0u8; FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3];
        let mut cursor = 0usize;
        output[cursor] = FULL_ALPHA_TRANSITION_PUBLIC_VALUES_VERSION_V3;
        cursor += 1;
        output[cursor..cursor + 32].copy_from_slice(&alpha_consensus_profile_commitment_v3());
        cursor += 32;
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
            "ECX/full-alpha-transition-public-values/v3",
            &self.canonical_bytes(),
        )
    }
}

pub fn decode_full_alpha_transition_public_values_v3(
    bytes: &[u8],
) -> Result<FullAlphaTransitionPublicValuesV3, FullValidatorPrimitiveErrorV2> {
    if bytes.len() != FULL_ALPHA_TRANSITION_PUBLIC_VALUES_BYTES_V3
        || bytes[0] != FULL_ALPHA_TRANSITION_PUBLIC_VALUES_VERSION_V3
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    if bytes[1..33] != alpha_consensus_profile_commitment_v3() {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let mut cursor = 33usize;
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
    let values = FullAlphaTransitionPublicValuesV3 {
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

pub fn encode_full_alpha_transition_input_v3(
    input: &FullAlphaTransitionInputV3,
) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
    validate_input_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)
}

/// Host construction from the complete predecessor frontier and ordered steps.
/// Observation authority is external: callers must bind the resulting input to
/// the sealed native journal. This executes consensus, but does not authenticate
/// supplied predecessor states or clocks on its own.
pub fn assemble_full_alpha_transition_v3(
    predecessor_selected: AlphaExecutedConsensusStateV3,
    predecessor_frontier: BitcoinExecutedFrontierNodeV2,
    predecessor_event_stream_commitment: Hash32,
    states: Vec<AlphaExecutedConsensusStateV3>,
    steps: Vec<AlphaBlockEvidenceStepV3>,
) -> Result<FullAlphaTransitionInputV3, FullValidatorPrimitiveErrorV2> {
    assemble_transition(predecessor_selected, predecessor_frontier,
        predecessor_event_stream_commitment, states, steps)
}

fn assemble_transition<S: TransitionStep>(
    predecessor_selected: AlphaExecutedConsensusStateV3,
    predecessor_frontier: BitcoinExecutedFrontierNodeV2,
    predecessor_event_stream_commitment: Hash32,
    mut states: Vec<AlphaExecutedConsensusStateV3>,
    steps: Vec<S>,
) -> Result<FullAlphaTransitionInputV3<S>, FullValidatorPrimitiveErrorV2> {
    use crate::state_frontier_v2::build_executed_frontier_path_v2;
    if steps.is_empty() || steps.len()>MAX_FULL_ALPHA_TRANSITION_STEPS_V3 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let tips = |states: &[AlphaExecutedConsensusStateV3]| states.iter()
        .map(AlphaExecutedConsensusStateV3::frontier_tip).collect::<Result<Vec<_>,_>>();
    let (mut frontier, predecessor_path)=build_executed_frontier_path_v2(&tips(&states)?,predecessor_selected.tip.block_hash)?;
    if frontier!=predecessor_frontier { return Err(FullValidatorPrimitiveErrorV2::RootMismatch); }
    verify_executed_frontier_membership_v2(frontier,predecessor_selected.frontier_tip()?,&predecessor_path)?;
    let mut discovered_blocks=Vec::with_capacity(steps.len());
    for step in steps {
        let block: bitcoin::Block=bitcoin::consensus::deserialize(step.raw_block())
            .map_err(|_|FullValidatorPrimitiveErrorV2::ExecutedState)?;
        let parent=states.iter().find(|s|s.tip.block_hash==block.header.prev_blockhash)
            .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?.clone();
        let (_,parent_membership_path)=build_executed_frontier_path_v2(&tips(&states)?,parent.tip.block_hash)?;
        let sequence=frontier.maximum_discovery_sequence.ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?
            .checked_add(1).ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
        let successor=step.execute(&parent,sequence)?;
        let (_,insertion_path)=build_executed_frontier_path_v2(&tips(&states)?,successor.tip.block_hash)?;
        frontier=apply_executed_frontier_mutation_v2(frontier,&BitcoinExecutedFrontierMutationV2{
            candidate:successor.frontier_tip()?,insert:true,path:insertion_path.clone()})?;
        discovered_blocks.push(FullAlphaDiscoveredBlockV3{parent,parent_membership_path,step,insertion_path});
        states.push(successor);
    }
    let best=frontier.best.ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let successor_selected=states.iter().find(|s|s.tip==best.tip)
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?.clone();
    let (_,successor_selected_membership_path)=build_executed_frontier_path_v2(&tips(&states)?,best.tip.block_hash)?;
    let input=FullAlphaTransitionInputV3{version:S::VERSION,
        predecessor_selected,predecessor_frontier,predecessor_selected_membership_path:predecessor_path,
        predecessor_event_stream_commitment,discovered_blocks,successor_selected,successor_selected_membership_path};
    execute_transition(&input)?;
    Ok(input)
}

pub fn decode_full_alpha_transition_input_v3(
    bytes: &[u8],
) -> Result<FullAlphaTransitionInputV3, FullValidatorPrimitiveErrorV2> {
    if bytes.first() != Some(&FULL_ALPHA_TRANSITION_INPUT_VERSION_V3)
        || bytes.len() > MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let input: FullAlphaTransitionInputV3 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    validate_input_shape(&input)?;
    if encode_full_alpha_transition_input_v3(&input)? != bytes {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    Ok(input)
}

pub fn execute_full_alpha_transition_v3(
    input: &FullAlphaTransitionInputV3,
) -> Result<
    (
        AlphaExecutedConsensusStateV3,
        FullAlphaTransitionPublicValuesV3,
    ),
    FullValidatorPrimitiveErrorV2,
> {
    execute_transition(input)
}

fn execute_transition<S: TransitionStep>(input: &FullAlphaTransitionInputV3<S>)
    -> Result<(AlphaExecutedConsensusStateV3, FullAlphaTransitionPublicValuesV3), FullValidatorPrimitiveErrorV2> {
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
        let successor = event.step.execute(&event.parent, sequence)?;
        let mut event_preimage = Vec::with_capacity(152);
        event_preimage.extend_from_slice(&alpha_consensus_profile_commitment_v3());
        event_preimage.extend_from_slice(&event_stream_commitment);
        event_preimage.extend_from_slice(&event.step.time().to_be_bytes());
        event_preimage.extend_from_slice(&sequence.to_be_bytes());
        event_preimage.extend_from_slice(&event.parent.tip.block_hash.to_byte_array());
        event_preimage.extend_from_slice(&successor.tip.block_hash.to_byte_array());
        event_stream_commitment =
            tagged_hash("ECX/full-alpha-discovered-block-event/v3", &event_preimage);
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
    let public_values = FullAlphaTransitionPublicValuesV3 {
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

fn validate_input_shape<S: TransitionStep>(
    input: &FullAlphaTransitionInputV3<S>,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if input.version != S::VERSION
        || input.discovered_blocks.is_empty()
        || input.discovered_blocks.len() > MAX_FULL_ALPHA_TRANSITION_STEPS_V3
        || input.predecessor_event_stream_commitment == [0; 32]
        || input.predecessor_selected.source_configuration_commitment
            != input.successor_selected.source_configuration_commitment
        || canonical_options()
            .serialized_size(input)
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?
            > MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 as u64
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    input.predecessor_selected.validate()?;
    input.successor_selected.validate()?;
    if input.successor_selected.deployment_state != input.predecessor_selected.deployment_state {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    for event in &input.discovered_blocks {
        event.parent.validate()?;
        if event.parent.source_configuration_commitment
            != input.predecessor_selected.source_configuration_commitment
            || event.parent.deployment_state != input.predecessor_selected.deployment_state
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3 as u64)
}

#[cfg(test)]
#[path = "recursive_alpha_v3_tests.rs"]
mod tests;
