//! Authenticated frontier for fully executed Bitcoin branch states.
//!
//! The older `BitcoinTipFrontierNodeV2` intentionally authenticates header
//! work only.  A full-consensus receipt must use this frontier (or an exact
//! reviewed successor) so the selected tip cannot be detached from its UTXO,
//! BIP300 and deployment-state execution commitment.

use crate::bip300_v2::{apply_bip300_block_v2, Bip300AllSlotStateV2};
use crate::elements_v2::{
    verify_full_bitcoin_block_step_v2, BitcoinConsensusExecutionParametersV2,
    FullBitcoinBlockEvidenceStepV2,
};
use crate::script_v2::{
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2,
    SCRIPT_VERIFY_DERSIG_V2, SCRIPT_VERIFY_NULLDUMMY_V2, SCRIPT_VERIFY_P2SH_V2,
    SCRIPT_VERIFY_TAPROOT_V2, SCRIPT_VERIFY_WITNESS_V2,
};
use crate::{
    derive_successor_tip_v2, tagged_hash, BitcoinChainTipV2, BitcoinPowContextV2,
    FullValidatorPrimitiveErrorV2, Hash32, SparseUtxoNodeV2, SPARSE_UTXO_DEPTH_V2,
};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

/// Breaking unreleased schema revision: Signet's challenge is part of the
/// authenticated state. Version-1 states/receipts must not be reinterpreted.
pub const BITCOIN_EXECUTED_CONSENSUS_STATE_VERSION_V2: u8 = 2;
pub const BITCOIN_TERMINAL_DEPLOYMENT_STATE_VERSION_V2: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum BitcoinDeploymentKindV2 {
    P2sh,
    Bip34,
    Bip66,
    Bip65,
    Csv,
    Segwit,
    Taproot,
}

impl BitcoinDeploymentKindV2 {
    fn code(self) -> u8 {
        match self {
            Self::P2sh => 0,
            Self::Bip34 => 1,
            Self::Bip66 => 2,
            Self::Bip65 => 3,
            Self::Csv => 4,
            Self::Segwit => 5,
            Self::Taproot => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinDeploymentActivationAnchorV2 {
    pub kind: BitcoinDeploymentKindV2,
    pub activation_height: u32,
    pub activation_block_hash: BlockHash,
}

/// Terminal post-Taproot deployment profile authenticated by a recursive
/// predecessor or genesis receipt. Activation anchors are network instance
/// data; no height or hash is compiled into the validation algorithm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinTerminalDeploymentStateV2 {
    pub version: u8,
    pub network_genesis: BlockHash,
    pub terminal_checkpoint_height: u32,
    pub terminal_checkpoint_hash: BlockHash,
    /// Exactly seven entries in `BitcoinDeploymentKindV2::code()` order.
    pub activation_anchors: Vec<BitcoinDeploymentActivationAnchorV2>,
}

impl BitcoinTerminalDeploymentStateV2 {
    pub fn validate(&self) -> Result<(), FullValidatorPrimitiveErrorV2> {
        if self.version != BITCOIN_TERMINAL_DEPLOYMENT_STATE_VERSION_V2
            || self.network_genesis == BlockHash::all_zeros()
            || self.terminal_checkpoint_hash == BlockHash::all_zeros()
            || self.activation_anchors.len() != 7
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
        for (expected, anchor) in self.activation_anchors.iter().enumerate() {
            if usize::from(anchor.kind.code()) != expected
                || anchor.activation_height > self.terminal_checkpoint_height
                || anchor.activation_block_hash == BlockHash::all_zeros()
            {
                return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
        self.validate()?;
        let mut output = Vec::with_capacity(329);
        output.push(self.version);
        output.extend_from_slice(&self.network_genesis.to_byte_array());
        output.extend_from_slice(&self.terminal_checkpoint_height.to_be_bytes());
        output.extend_from_slice(&self.terminal_checkpoint_hash.to_byte_array());
        output.push(7);
        for anchor in &self.activation_anchors {
            output.push(anchor.kind.code());
            output.extend_from_slice(&anchor.activation_height.to_be_bytes());
            output.extend_from_slice(&anchor.activation_block_hash.to_byte_array());
        }
        debug_assert_eq!(output.len(), 329);
        Ok(output)
    }

    pub fn commitment(&self) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
        Ok(tagged_hash(
            "ECX/full-bitcoin-terminal-deployment-state/v2",
            &self.canonical_bytes()?,
        ))
    }

    pub fn execution_parameters(
        &self,
    ) -> Result<BitcoinConsensusExecutionParametersV2, FullValidatorPrimitiveErrorV2> {
        self.validate()?;
        Ok(BitcoinConsensusExecutionParametersV2 {
            version: 1,
            bip34_active: true,
            bip68_active: true,
            active_script_flags: SCRIPT_VERIFY_P2SH_V2
                | SCRIPT_VERIFY_DERSIG_V2
                | SCRIPT_VERIFY_NULLDUMMY_V2
                | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2
                | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2
                | SCRIPT_VERIFY_WITNESS_V2
                | SCRIPT_VERIFY_TAPROOT_V2,
        })
    }
}

/// Complete state preimage committed by one executed-frontier leaf.
///
/// The typed terminal deployment state derives the only allowed post-Taproot
/// execution flags. Its historical activation anchors still require a
/// recursive predecessor/genesis proof; the witness cannot self-authenticate
/// them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinExecutedConsensusStateV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub tip: BitcoinChainTipV2,
    pub pow_context: BitcoinPowContextV2,
    pub utxo_root: SparseUtxoNodeV2,
    pub bip300_state: Bip300AllSlotStateV2,
    pub execution_parameters: BitcoinConsensusExecutionParametersV2,
    pub deployment_state: BitcoinTerminalDeploymentStateV2,
}

impl BitcoinExecutedConsensusStateV2 {
    pub fn validate(&self) -> Result<(), FullValidatorPrimitiveErrorV2> {
        if self.version != BITCOIN_EXECUTED_CONSENSUS_STATE_VERSION_V2
            || self.source_configuration_commitment == [0; 32]
            || self.tip.block_hash == BlockHash::all_zeros()
            || self.tip.chainwork_be == [0; 32]
            || self.utxo_root.hash == [0; 32]
            || self.pow_context.previous_height != self.tip.height
            || self.pow_context.previous_header.block_hash() != self.tip.block_hash
            || self.pow_context.previous_11_times.len() != 11
            || self.pow_context.previous_11_times.last()
                != Some(&self.pow_context.previous_header.time)
            || self.bip300_state.tip_hash != Some(self.tip.block_hash)
            || self.bip300_state.next_height
                != self
                    .tip
                    .height
                    .checked_add(1)
                    .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
        self.bip300_state
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
        self.execution_parameters
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
        if self.deployment_state.network_genesis != self.bip300_state.network_genesis
            || self.deployment_state.terminal_checkpoint_height > self.tip.height
            || self.deployment_state.execution_parameters()? != self.execution_parameters
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
        self.validate()?;
        let bip300_commitment = self
            .bip300_state
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
        let execution_commitment = self
            .execution_parameters
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
        let deployment_commitment = self.deployment_state.commitment()?;
        let mut output = Vec::with_capacity(517);
        output.push(self.version);
        output.extend_from_slice(&self.source_configuration_commitment);
        output.extend_from_slice(&self.tip.block_hash.to_byte_array());
        output.extend_from_slice(&self.tip.height.to_be_bytes());
        output.extend_from_slice(&self.tip.chainwork_be);
        output.extend_from_slice(&self.tip.discovery_sequence.to_be_bytes());
        output.extend_from_slice(&serialize(&self.pow_context.previous_header));
        for time in &self.pow_context.previous_11_times {
            output.extend_from_slice(&time.to_be_bytes());
        }
        output.extend_from_slice(&self.pow_context.retarget_epoch_start_time.to_be_bytes());
        output.extend_from_slice(&self.utxo_root.hash);
        output.extend_from_slice(&self.utxo_root.aggregate.count.to_be_bytes());
        output.extend_from_slice(&self.utxo_root.aggregate.value_atoms.to_be_bytes());
        output.extend_from_slice(&bip300_commitment);
        output.extend_from_slice(&execution_commitment);
        output.extend_from_slice(&deployment_commitment);
        Ok(output)
    }

    pub fn commitment(&self) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
        Ok(tagged_hash(
            "ECX/full-bitcoin-executed-consensus-state/v2",
            &self.canonical_bytes()?,
        ))
    }

    pub fn frontier_tip(
        &self,
    ) -> Result<BitcoinExecutedBranchTipV2, FullValidatorPrimitiveErrorV2> {
        Ok(BitcoinExecutedBranchTipV2 {
            tip: self.tip,
            executed_state_commitment: self.commitment()?,
        })
    }
}

/// Execute one fully validated successor block and derive the exact state
/// preimage committed by an executed-frontier leaf.
///
/// The caller must subsequently insert `result.frontier_tip()` using the
/// frontier's globally next discovery sequence and an authenticated path.
/// This separation prevents a block witness from choosing its own best-work
/// accumulator root.
pub fn execute_bitcoin_executed_successor_v2(
    parent: &BitcoinExecutedConsensusStateV2,
    step: &FullBitcoinBlockEvidenceStepV2,
    discovery_sequence: u128,
) -> Result<BitcoinExecutedConsensusStateV2, FullValidatorPrimitiveErrorV2> {
    parent.validate()?;
    // Header linkage alone does not authenticate the other contextual
    // consensus inputs. Bind every PoW/MTP/epoch field before interpreting the
    // witness under Alpha rules.
    if step.pow_context != parent.pow_context
        || discovery_sequence <= parent.tip.discovery_sequence
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let expected_height = parent
        .tip
        .height
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let (block, next_utxo_root) = verify_full_bitcoin_block_step_v2(
        step,
        parent.bip300_state.network_genesis,
        expected_height,
        parent.utxo_root,
        parent.execution_parameters,
    )
    .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let (next_bip300_state, _) = apply_bip300_block_v2(&parent.bip300_state, &block)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let next_tip = derive_successor_tip_v2(parent.tip, &block.header, discovery_sequence)?;
    let next_pow_context = derive_successor_pow_context(parent, block.header)?;
    let successor = BitcoinExecutedConsensusStateV2 {
        version: BITCOIN_EXECUTED_CONSENSUS_STATE_VERSION_V2,
        source_configuration_commitment: parent.source_configuration_commitment,
        tip: next_tip,
        pow_context: next_pow_context,
        utxo_root: next_utxo_root,
        bip300_state: next_bip300_state,
        execution_parameters: parent.execution_parameters,
        deployment_state: parent.deployment_state.clone(),
    };
    successor.validate()?;
    Ok(successor)
}

fn derive_successor_pow_context(
    parent: &BitcoinExecutedConsensusStateV2,
    header: bitcoin::block::Header,
) -> Result<BitcoinPowContextV2, FullValidatorPrimitiveErrorV2> {
    // Alpha's retarget interval, fixed rather than selected from a network.
    let interval = u64::from(crate::alpha_pow_v3::ALPHA_RETARGET_INTERVAL_V3);
    let mut previous_11_times = parent.pow_context.previous_11_times.clone();
    previous_11_times.remove(0);
    previous_11_times.push(header.time);
    let height = parent
        .tip
        .height
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let retarget_epoch_start_time = if u64::from(height).is_multiple_of(interval) {
        header.time
    } else {
        parent.pow_context.retarget_epoch_start_time
    };
    // Alpha has no min-difficulty exception, so there is no last-non-minimum
    // target to carry forward.
    Ok(BitcoinPowContextV2 {
        previous_height: height,
        previous_header: header,
        previous_11_times,
        retarget_epoch_start_time,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinExecutedBranchTipV2 {
    pub tip: BitcoinChainTipV2,
    /// Canonical tagged commitment to the complete executed state preimage.
    /// The recursive relation must define and validate that preimage; this
    /// accumulator never accepts a zero or witness-only summary commitment.
    pub executed_state_commitment: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinExecutedFrontierNodeV2 {
    pub hash: Hash32,
    pub count: u128,
    pub best: Option<BitcoinExecutedBranchTipV2>,
    pub maximum_discovery_sequence: Option<u128>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinExecutedFrontierPathV2 {
    /// Leaf-to-root siblings. Exactly 256 entries are canonical.
    pub siblings: Vec<BitcoinExecutedFrontierNodeV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinExecutedFrontierMutationV2 {
    pub candidate: BitcoinExecutedBranchTipV2,
    pub insert: bool,
    pub path: BitcoinExecutedFrontierPathV2,
}

fn validate_candidate(
    candidate: BitcoinExecutedBranchTipV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if candidate.tip.block_hash == BlockHash::all_zeros()
        || candidate.tip.chainwork_be == [0; 32]
        || candidate.executed_state_commitment == [0; 32]
    {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    }
    Ok(())
}

fn encode_candidate(candidate: BitcoinExecutedBranchTipV2, output: &mut Vec<u8>) {
    output.extend_from_slice(&candidate.tip.block_hash.to_byte_array());
    output.extend_from_slice(&candidate.tip.height.to_le_bytes());
    output.extend_from_slice(&candidate.tip.chainwork_be);
    output.extend_from_slice(&candidate.tip.discovery_sequence.to_le_bytes());
    output.extend_from_slice(&candidate.executed_state_commitment);
}

fn empty_leaf() -> BitcoinExecutedFrontierNodeV2 {
    BitcoinExecutedFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-executed-frontier-empty-leaf/v2", &[]),
        count: 0,
        best: None,
        maximum_discovery_sequence: None,
    }
}

fn present_leaf(candidate: BitcoinExecutedBranchTipV2) -> BitcoinExecutedFrontierNodeV2 {
    let mut payload = Vec::with_capacity(116);
    encode_candidate(candidate, &mut payload);
    BitcoinExecutedFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-executed-frontier-leaf/v2", &payload),
        count: 1,
        best: Some(candidate),
        maximum_discovery_sequence: Some(candidate.tip.discovery_sequence),
    }
}

fn better(
    left: BitcoinExecutedBranchTipV2,
    right: BitcoinExecutedBranchTipV2,
) -> BitcoinExecutedBranchTipV2 {
    if right.tip.chainwork_be > left.tip.chainwork_be
        || (right.tip.chainwork_be == left.tip.chainwork_be
            && (right.tip.discovery_sequence < left.tip.discovery_sequence
                || (right.tip.discovery_sequence == left.tip.discovery_sequence
                    && right.tip.block_hash.to_byte_array() < left.tip.block_hash.to_byte_array())))
    {
        right
    } else {
        left
    }
}

fn combine(
    left: BitcoinExecutedFrontierNodeV2,
    right: BitcoinExecutedFrontierNodeV2,
) -> Result<BitcoinExecutedFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    if (left.count == 0) != left.best.is_none()
        || (left.count == 0) != left.maximum_discovery_sequence.is_none()
        || (right.count == 0) != right.best.is_none()
        || (right.count == 0) != right.maximum_discovery_sequence.is_none()
    {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    }
    let count = left
        .count
        .checked_add(right.count)
        .ok_or(FullValidatorPrimitiveErrorV2::Chainwork)?;
    let best = match (left.best, right.best) {
        (Some(left), Some(right)) => Some(better(left, right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    let maximum_discovery_sequence = match (
        left.maximum_discovery_sequence,
        right.maximum_discovery_sequence,
    ) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    let mut payload = Vec::new();
    encode_node(left, &mut payload);
    encode_node(right, &mut payload);
    Ok(BitcoinExecutedFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-executed-frontier-node/v2", &payload),
        count,
        best,
        maximum_discovery_sequence,
    })
}

fn encode_node(node: BitcoinExecutedFrontierNodeV2, output: &mut Vec<u8>) {
    output.extend_from_slice(&node.hash);
    output.extend_from_slice(&node.count.to_le_bytes());
    if let Some(best) = node.best {
        output.push(1);
        encode_candidate(best, output);
    } else {
        output.push(0);
    }
    if let Some(sequence) = node.maximum_discovery_sequence {
        output.push(1);
        output.extend_from_slice(&sequence.to_le_bytes());
    } else {
        output.push(0);
    }
}

/// Receipt-chain commitment to an executed frontier root and all of its
/// best-work/discovery metadata.
pub fn executed_frontier_root_commitment_v2(
    node: BitcoinExecutedFrontierNodeV2,
) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
    if (node.count == 0) != node.best.is_none()
        || (node.count == 0) != node.maximum_discovery_sequence.is_none()
    {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    }
    if let Some(best) = node.best {
        validate_candidate(best)?;
    }
    let mut payload = Vec::new();
    encode_node(node, &mut payload);
    Ok(tagged_hash(
        "ECX/full-bitcoin-executed-frontier-root/v2",
        &payload,
    ))
}

pub fn canonical_empty_executed_frontier_root_v2() -> BitcoinExecutedFrontierNodeV2 {
    let mut node = empty_leaf();
    for _ in 0..SPARSE_UTXO_DEPTH_V2 {
        node = combine(node, node).expect("canonical empty executed frontier cannot overflow");
    }
    node
}

/// Canonical membership path for inserting the first executed branch state.
pub fn canonical_empty_executed_frontier_path_v2() -> BitcoinExecutedFrontierPathV2 {
    let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
    let mut node = empty_leaf();
    for _ in 0..SPARSE_UTXO_DEPTH_V2 {
        siblings.push(node);
        node = combine(node, node).expect("canonical empty executed frontier cannot overflow");
    }
    BitcoinExecutedFrontierPathV2 { siblings }
}

/// Host-side witness construction from a complete set of executed states.
/// Does not authenticate those states; callers must compare the resulting root
/// with their authenticated predecessor and execute every newly inserted state.
/// The query may be absent, in which case the path proves an empty insertion.
pub fn build_executed_frontier_path_v2(
    candidates: &[BitcoinExecutedBranchTipV2], query: BlockHash,
) -> Result<(BitcoinExecutedFrontierNodeV2, BitcoinExecutedFrontierPathV2), FullValidatorPrimitiveErrorV2> {
    let mut leaves = candidates.to_vec();
    for candidate in &leaves { validate_candidate(*candidate)?; }
    leaves.sort_by_key(|c| c.tip.block_hash.to_byte_array());
    if leaves.windows(2).any(|p| p[0].tip.block_hash == p[1].tip.block_hash) {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath);
    }
    let mut empty = vec![empty_leaf()];
    for depth in 0..256 { empty.push(combine(empty[depth], empty[depth])?); }
    fn subtree(leaves: &[BitcoinExecutedBranchTipV2], depth: usize,
        query: &[u8;32], empty: &[BitcoinExecutedFrontierNodeV2],
        path: &mut Vec<BitcoinExecutedFrontierNodeV2>, track: bool,
    ) -> Result<BitcoinExecutedFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
        if leaves.is_empty() {
            if track { path.extend_from_slice(&empty[..256-depth]); }
            return Ok(empty[256-depth]);
        }
        if depth == 256 { return Ok(present_leaf(leaves[0])); }
        let mask = 1 << (7-depth%8);
        let split = leaves.partition_point(|c| c.tip.block_hash.to_byte_array()[depth/8] & mask == 0);
        let right_query = query[depth/8] & mask != 0;
        let left = subtree(&leaves[..split], depth+1, query, empty, path, track && !right_query)?;
        let right = subtree(&leaves[split..], depth+1, query, empty, path, track && right_query)?;
        if track { path.push(if right_query {left} else {right}); }
        combine(left,right)
    }
    let mut siblings = Vec::with_capacity(256);
    let root = subtree(&leaves,0,&query.to_byte_array(),&empty,&mut siblings,true)?;
    Ok((root,BitcoinExecutedFrontierPathV2{siblings}))
}

fn root_from_path(
    candidate: BitcoinExecutedBranchTipV2,
    leaf: BitcoinExecutedFrontierNodeV2,
    path: &BitcoinExecutedFrontierPathV2,
) -> Result<BitcoinExecutedFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    validate_candidate(candidate)?;
    if path.siblings.len() != SPARSE_UTXO_DEPTH_V2 {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath);
    }
    let key = candidate.tip.block_hash.to_byte_array();
    let mut node = leaf;
    for (depth, sibling) in path.siblings.iter().enumerate() {
        let byte = key[31 - depth / 8];
        let bit = (byte >> (depth % 8)) & 1;
        node = if bit == 0 {
            combine(node, *sibling)?
        } else {
            combine(*sibling, node)?
        };
    }
    Ok(node)
}

pub fn apply_executed_frontier_mutation_v2(
    current_root: BitcoinExecutedFrontierNodeV2,
    mutation: &BitcoinExecutedFrontierMutationV2,
) -> Result<BitcoinExecutedFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    validate_candidate(mutation.candidate)?;
    let empty = empty_leaf();
    let present = present_leaf(mutation.candidate);
    let (old_leaf, new_leaf) = if mutation.insert {
        (empty, present)
    } else {
        (present, empty)
    };
    if root_from_path(mutation.candidate, old_leaf, &mutation.path)? != current_root {
        return Err(FullValidatorPrimitiveErrorV2::RootMismatch);
    }
    root_from_path(mutation.candidate, new_leaf, &mutation.path)
}

pub fn verify_executed_frontier_membership_v2(
    root: BitcoinExecutedFrontierNodeV2,
    candidate: BitcoinExecutedBranchTipV2,
    path: &BitcoinExecutedFrontierPathV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if root_from_path(candidate, present_leaf(candidate), path)? != root {
        return Err(FullValidatorPrimitiveErrorV2::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bip300_v2::{Bip300AllSlotStateV2, Bip300ConsensusParametersV2};
    use crate::{
        apply_bitcoin_block_utxos_v2, canonical_empty_utxo_leaf_v2, median_time_past_v2,
        sparse_utxo_parent_v2, BitcoinBlockSpendContextV2, BitcoinBlockUtxoWitnessV2,
        BitcoinPowContextV2, BitcoinTransactionUtxoWitnessV2, BitcoinUtxoLeafV2,
        SparseUtxoMutationV2, SparseUtxoPathV2,
    };
    use bitcoin::block;
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{
        absolute, transaction, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use std::collections::BTreeMap;

    fn candidate(state_byte: u8) -> BitcoinExecutedBranchTipV2 {
        BitcoinExecutedBranchTipV2 {
            tip: BitcoinChainTipV2 {
                block_hash: BlockHash::from_byte_array([9; 32]),
                height: 100,
                chainwork_be: [7; 32],
                discovery_sequence: 3,
            },
            executed_state_commitment: [state_byte; 32],
        }
    }

    #[test]
    fn constructed_frontier_paths_match_native_mutations() {
        let mut leaves = Vec::new();
        let mut root = canonical_empty_executed_frontier_root_v2();
        for index in 0..8u8 {
            let mut next = candidate(index+1);
            let mut key = [0;32]; key[0]=index*31; key[31]=index+1;
            next.tip.block_hash=BlockHash::from_byte_array(key);
            next.tip.discovery_sequence=u128::from(index);
            let (before,path)=build_executed_frontier_path_v2(&leaves,next.tip.block_hash).unwrap();
            assert_eq!(before,root);
            root=apply_executed_frontier_mutation_v2(root,&BitcoinExecutedFrontierMutationV2{candidate:next,insert:true,path}).unwrap();
            leaves.push(next);
            for leaf in &leaves {
                let (built,path)=build_executed_frontier_path_v2(&leaves,leaf.tip.block_hash).unwrap();
                assert_eq!(built,root);
                verify_executed_frontier_membership_v2(root,*leaf,&path).unwrap();
            }
        }
        leaves.push(leaves[0]);
        assert!(build_executed_frontier_path_v2(&leaves,leaves[0].tip.block_hash).is_err());
    }

    pub(crate) fn executed_state() -> BitcoinExecutedConsensusStateV2 {
        let genesis = genesis_block(Network::Regtest);
        let tip = BitcoinChainTipV2 {
            block_hash: genesis.block_hash(),
            height: 0,
            chainwork_be: genesis.header.target().to_work().to_be_bytes(),
            discovery_sequence: 0,
        };
        let deployment_state = BitcoinTerminalDeploymentStateV2 {
            version: BITCOIN_TERMINAL_DEPLOYMENT_STATE_VERSION_V2,
            network_genesis: genesis.block_hash(),
            terminal_checkpoint_height: 0,
            terminal_checkpoint_hash: genesis.block_hash(),
            activation_anchors: [
                BitcoinDeploymentKindV2::P2sh,
                BitcoinDeploymentKindV2::Bip34,
                BitcoinDeploymentKindV2::Bip66,
                BitcoinDeploymentKindV2::Bip65,
                BitcoinDeploymentKindV2::Csv,
                BitcoinDeploymentKindV2::Segwit,
                BitcoinDeploymentKindV2::Taproot,
            ]
            .into_iter()
            .map(|kind| BitcoinDeploymentActivationAnchorV2 {
                kind,
                activation_height: 0,
                activation_block_hash: genesis.block_hash(),
            })
            .collect(),
        };
        let execution_parameters = deployment_state.execution_parameters().unwrap();
        BitcoinExecutedConsensusStateV2 {
            version: BITCOIN_EXECUTED_CONSENSUS_STATE_VERSION_V2,
            source_configuration_commitment: [1; 32],
            tip,
            pow_context: BitcoinPowContextV2 {
                previous_height: 0,
                previous_header: genesis.header,
                previous_11_times: vec![genesis.header.time; 11],
                retarget_epoch_start_time: genesis.header.time,
            },
            utxo_root: empty_utxo_tree().0,
            bip300_state: Bip300AllSlotStateV2 {
                network_genesis: genesis.block_hash(),
                consensus_parameters: Bip300ConsensusParametersV2 {
                    proposal_max_age: 10,
                    proposal_activation_threshold: 5,
                    withdrawal_max_age: 10,
                    withdrawal_inclusion_threshold: 5,
                },
                next_height: 1,
                tip_hash: Some(genesis.block_hash()),
                proposals: BTreeMap::new(),
                active_slots: BTreeMap::new(),
                previous_effective_m4: BTreeMap::new(),
            },
            execution_parameters,
            deployment_state,
        }
    }

    fn empty_utxo_tree() -> (SparseUtxoNodeV2, SparseUtxoPathV2) {
        let mut node = canonical_empty_utxo_leaf_v2();
        let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
        for _ in 0..SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = sparse_utxo_parent_v2(node, node).unwrap();
        }
        (node, SparseUtxoPathV2 { siblings })
    }

    pub(crate) fn mined_successor_step() -> FullBitcoinBlockEvidenceStepV2 {
        let genesis = genesis_block(Network::Regtest);
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                // BIP34 permits OP_1 for height one; the trailing zero also
                // satisfies the independent 2-byte coinbase scriptSig floor.
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = coinbase.compute_txid();
        let mut header = block::Header {
            version: block::Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array(txid.to_byte_array()),
            time: genesis.header.time + 1,
            bits: genesis.header.bits,
            nonce: 0,
        };
        while header.validate_pow(header.target()).is_err() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        let block = Block {
            header,
            txdata: vec![coinbase.clone()],
        };
        let (_, path) = empty_utxo_tree();
        let outpoint = OutPoint { txid, vout: 0 };
        FullBitcoinBlockEvidenceStepV2 {
            raw_block: serialize(&block),
            pow_context: BitcoinPowContextV2 {
                previous_height: 0,
                previous_header: genesis.header,
                previous_11_times: vec![genesis.header.time; 11],
                retarget_epoch_start_time: genesis.header.time,
            },
            authenticated_adjusted_time: u64::from(header.time),
            utxo_witness: BitcoinBlockUtxoWitnessV2 {
                transactions: vec![BitcoinTransactionUtxoWitnessV2 {
                    spends: vec![],
                    creates: vec![SparseUtxoMutationV2 {
                        outpoint,
                        old_leaf: None,
                        new_leaf: Some(BitcoinUtxoLeafV2 {
                            outpoint,
                            output: coinbase.output[0].clone(),
                            creation_height: 1,
                            creation_parent_mtp: genesis.header.time,
                            coinbase: true,
                        }),
                        path,
                    }],
                }],
            },
        }
    }


    pub(crate) fn two_leaf_frontier_fixture(
        first: BitcoinExecutedBranchTipV2,
        second: BitcoinExecutedBranchTipV2,
    ) -> (
        BitcoinExecutedFrontierNodeV2,
        BitcoinExecutedFrontierPathV2,
        BitcoinExecutedFrontierPathV2,
        BitcoinExecutedFrontierNodeV2,
    ) {
        let first_path = canonical_empty_executed_frontier_path_v2();
        let first_root = apply_executed_frontier_mutation_v2(
            canonical_empty_executed_frontier_root_v2(),
            &BitcoinExecutedFrontierMutationV2 {
                candidate: first,
                insert: true,
                path: first_path.clone(),
            },
        )
        .unwrap();
        let first_key = first.tip.block_hash.to_byte_array();
        let second_key = second.tip.block_hash.to_byte_array();
        // Paths are folded leaf-to-root, so the two occupied subtrees join at
        // the highest differing key bit; all bits above it must be shared.
        let divergence = (0..SPARSE_UTXO_DEPTH_V2)
            .rev()
            .find(|depth| {
                let byte = 31 - depth / 8;
                ((first_key[byte] >> (depth % 8)) & 1) != ((second_key[byte] >> (depth % 8)) & 1)
            })
            .unwrap();
        let mut first_subtree = present_leaf(first);
        for (depth, empty) in first_path.siblings.iter().enumerate().take(divergence) {
            let byte = first_key[31 - depth / 8];
            first_subtree = if ((byte >> (depth % 8)) & 1) == 0 {
                combine(first_subtree, *empty).unwrap()
            } else {
                combine(*empty, first_subtree).unwrap()
            };
        }
        let mut second_path = canonical_empty_executed_frontier_path_v2();
        second_path.siblings[divergence] = first_subtree;
        let reconstructed = root_from_path(second, empty_leaf(), &second_path).unwrap();
        assert_eq!(
            reconstructed, first_root,
            "two-leaf fixture failed at divergence depth {divergence}"
        );
        let final_root = apply_executed_frontier_mutation_v2(
            first_root,
            &BitcoinExecutedFrontierMutationV2 {
                candidate: second,
                insert: true,
                path: second_path.clone(),
            },
        )
        .unwrap();
        (first_root, first_path, second_path, final_root)
    }

    #[test]
    fn executed_state_is_part_of_membership_and_round_trip() {
        let empty = canonical_empty_executed_frontier_root_v2();
        let path = canonical_empty_executed_frontier_path_v2();
        let value = candidate(1);
        let occupied = apply_executed_frontier_mutation_v2(
            empty,
            &BitcoinExecutedFrontierMutationV2 {
                candidate: value,
                insert: true,
                path: path.clone(),
            },
        )
        .unwrap();
        verify_executed_frontier_membership_v2(occupied, value, &path).unwrap();
        assert_eq!(occupied.best, Some(value));
        assert_eq!(
            verify_executed_frontier_membership_v2(occupied, candidate(2), &path),
            Err(FullValidatorPrimitiveErrorV2::RootMismatch)
        );
        assert_eq!(
            apply_executed_frontier_mutation_v2(
                occupied,
                &BitcoinExecutedFrontierMutationV2 {
                    candidate: value,
                    insert: false,
                    path,
                },
            )
            .unwrap(),
            empty
        );
    }

    #[test]
    fn zero_state_commitment_and_noncanonical_path_reject() {
        let empty = canonical_empty_executed_frontier_root_v2();
        let mut zero = candidate(0);
        zero.executed_state_commitment = [0; 32];
        assert_eq!(
            apply_executed_frontier_mutation_v2(
                empty,
                &BitcoinExecutedFrontierMutationV2 {
                    candidate: zero,
                    insert: true,
                    path: canonical_empty_executed_frontier_path_v2(),
                },
            ),
            Err(FullValidatorPrimitiveErrorV2::Chainwork)
        );
        let short = BitcoinExecutedFrontierPathV2 { siblings: vec![] };
        assert_eq!(
            apply_executed_frontier_mutation_v2(
                empty,
                &BitcoinExecutedFrontierMutationV2 {
                    candidate: candidate(1),
                    insert: true,
                    path: short,
                },
            ),
            Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)
        );
    }

    #[test]
    fn canonical_executed_state_binds_every_consensus_component() {
        let state = executed_state();
        state.validate().unwrap();
        // 405, down from the pre-Alpha 411. Removing the network selector
        // (1 byte), the min-difficulty carry `last_non_minimum_bits` (4), and
        // the Signet challenge discriminant (1) shortened the preimage by six
        // bytes. This is a deliberate recursive wire-format change: any guest
        // built against the old 411-byte layout must be rebuilt.
        assert_eq!(state.canonical_bytes().unwrap().len(), 405);
        let commitment = state.commitment().unwrap();
        assert_eq!(
            state.frontier_tip().unwrap().executed_state_commitment,
            commitment
        );

        let mut changed = state.clone();
        changed.utxo_root.hash[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = state.clone();
        changed.deployment_state.activation_anchors[6].activation_block_hash =
            BlockHash::from_byte_array([3; 32]);
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = state.clone();
        changed.source_configuration_commitment[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = state;
        changed.bip300_state.consensus_parameters.proposal_max_age += 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
    }



    #[test]
    fn successor_rejects_mtp_epoch_and_bits_context_substitution() {
        let parent = executed_state();
        let step = mined_successor_step();
        execute_bitcoin_executed_successor_v2(&parent, &step, 1).unwrap();
        let mut substitutions = Vec::new();
        let mut changed = step.clone();
        changed.pow_context.previous_11_times[0] -= 1;
        substitutions.push(("MTP history", changed));
        let mut changed = step;
        changed.pow_context.retarget_epoch_start_time += 1;
        substitutions.push(("retarget epoch", changed));
        for (label, changed) in substitutions {
            // These substitutions all pass block-local validation: the test
            // must specifically exercise binding to the authenticated parent.
            assert!(
                verify_full_bitcoin_block_step_v2(
                    &changed,
                    parent.bip300_state.network_genesis,
                    1,
                    parent.utxo_root,
                    parent.execution_parameters,
                )
                .is_ok(),
                "{label} must be a valid block-local context substitution"
            );
            assert_eq!(
                execute_bitcoin_executed_successor_v2(&parent, &changed, 1),
                Err(FullValidatorPrimitiveErrorV2::ExecutedState),
                "{label} must not replace authenticated context"
            );
        }
    }


    #[test]
    fn executed_state_rejects_cross_component_tip_substitution() {
        let mut state = executed_state();
        state.tip.height += 1;
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut state = executed_state();
        state.bip300_state.tip_hash = Some(BlockHash::from_byte_array([4; 32]));
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut state = executed_state();
        state.pow_context.previous_11_times.pop();
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut state = executed_state();
        state.deployment_state.activation_anchors.swap(0, 1);
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut state = executed_state();
        state.execution_parameters.active_script_flags ^= SCRIPT_VERIFY_TAPROOT_V2;
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
        let mut state = executed_state();
        state.deployment_state.terminal_checkpoint_height = 1;
        assert_eq!(
            state.validate(),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
    }

    #[test]
    fn complete_successor_execution_derives_every_committed_state_component() {
        let parent = executed_state();
        let step = mined_successor_step();
        let decoded: Block = bitcoin::consensus::deserialize(&step.raw_block).unwrap();
        let utxo_result = apply_bitcoin_block_utxos_v2(
            &decoded,
            BitcoinBlockSpendContextV2 {
                height: 1,
                previous_block_mtp: median_time_past_v2(&step.pow_context.previous_11_times)
                    .unwrap(),
                bip34_active: parent.execution_parameters.bip34_active,
                bip68_active: parent.execution_parameters.bip68_active,
            },
            parent.utxo_root,
            &step.utxo_witness,
            parent.execution_parameters.active_script_flags,
            &crate::FullBitcoinScriptVerifierV2,
        );
        assert!(
            utxo_result.is_ok(),
            "UTXO execution failed: {utxo_result:?}"
        );
        let block_result = verify_full_bitcoin_block_step_v2(
            &step,
            parent.bip300_state.network_genesis,
            1,
            parent.utxo_root,
            parent.execution_parameters,
        );
        assert!(
            block_result.is_ok(),
            "block execution failed: {block_result:?}"
        );
        let (block, _) = block_result.unwrap();
        let bip300_result = apply_bip300_block_v2(&parent.bip300_state, &block);
        assert!(
            bip300_result.is_ok(),
            "BIP300 replay failed: {bip300_result:?}"
        );
        let successor = execute_bitcoin_executed_successor_v2(&parent, &step, 1).unwrap();
        assert_eq!(successor.tip.height, 1);
        assert_eq!(successor.tip.discovery_sequence, 1);
        assert_eq!(
            successor.pow_context.previous_header.block_hash(),
            successor.tip.block_hash
        );
        assert_eq!(
            successor.bip300_state.tip_hash,
            Some(successor.tip.block_hash)
        );
        assert_eq!(successor.bip300_state.next_height, 2);
        assert_eq!(successor.utxo_root.aggregate.count, 1);
        assert_eq!(successor.utxo_root.aggregate.value_atoms, 50 * 100_000_000);
        assert_ne!(
            successor.commitment().unwrap(),
            parent.commitment().unwrap()
        );
        assert_eq!(
            execute_bitcoin_executed_successor_v2(&parent, &mined_successor_step(), 0),
            Err(FullValidatorPrimitiveErrorV2::ExecutedState)
        );
    }
}
