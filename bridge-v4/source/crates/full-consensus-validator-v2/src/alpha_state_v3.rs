//! Staged, checkpoint-relative Alpha executed state. Not a release identity.
//!
//! The authenticated starting checkpoint must be at/after 963647 with terminal
//! Bitcoin deployments. This is NOT genesis replay, checkpoint authentication,
//! source-event completeness, or approval to freeze a conversion guest. Native
//! Alpha differential qualification remains mandatory before production use.

use crate::alpha_pow_v3::{
    alpha_pow_profile_commitment_v3, verify_alpha_next_header_v3, AlphaHeaderContextV3,
    ALPHA_FORK_HEIGHT_V3,
};
use crate::bip300_v2::alpha_bip300_v3::{
    alpha_bip300_policy_commitment_v3, apply_alpha_bip300_block_v3, AlphaBip300AllSlotStateV3,
};
use crate::state_frontier_v2::{BitcoinExecutedBranchTipV2, BitcoinTerminalDeploymentStateV2};
use crate::{
    derive_successor_tip_v2, median_time_past_v2, tagged_hash,
    verify_bitcoin_block_foundation_v2, BitcoinBlockSpendContextV2, BitcoinBlockUtxoWitnessV2,
    BitcoinChainTipV2, BitcoinScriptVerifierV2, FullValidatorPrimitiveErrorV2, Hash32,
    SparseUtxoNodeV2, BITCOIN_MAX_BLOCK_WEIGHT_V2,
};
use bitcoin::hashes::Hash as _;
use bitcoin::{Block, BlockHash, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};

#[path = "alpha_repurpose_txids_v3.rs"]
mod repurpose;

pub const ALPHA_EXECUTED_STATE_VERSION_V3: u8 = 3;

/// Fixed Alpha finality exception, without modifying transaction bytes or BIP68.
pub fn apply_alpha_block_utxos_v3(
    block: &Block,
    context: BitcoinBlockSpendContextV2,
    initial_root: SparseUtxoNodeV2,
    witness: &BitcoinBlockUtxoWitnessV2,
    active_script_flags: u32,
    script_verifier: &AlphaScriptVerifierV3,
) -> Result<crate::BitcoinBlockUtxoResultV2, FullValidatorPrimitiveErrorV2> {
    crate::apply_block_utxos_with_alpha_policy(
        block, context, initial_root, witness, active_script_flags, script_verifier, true,
    )
}

pub fn alpha_terminal_execution_parameters_v3(
) -> crate::elements_v2::BitcoinConsensusExecutionParametersV2 {
    use crate::script_v2::*;
    crate::elements_v2::BitcoinConsensusExecutionParametersV2 {
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
    }
}

/// Frozen source exception set, not a caller-selected list or test bypass.
pub fn alpha_repurpose_txid_v3(txid: Txid) -> bool {
    repurpose::ALPHA_REPURPOSE_TXIDS_INTERNAL.contains(txid.as_byte_array())
}

pub fn alpha_repurpose_set_commitment_v3() -> Hash32 {
    let mut bytes = Vec::with_capacity(220 * 32);
    for txid in repurpose::ALPHA_REPURPOSE_TXIDS_INTERNAL {
        bytes.extend_from_slice(&txid);
    }
    tagged_hash("ECX/alpha-repurpose-transactions/v3", &bytes)
}

/// Binds the fixed PoW, live BIP300 (144 blocks, >72), script exceptions and
/// terminal execution profile. There is no witness-selectable rule parameter.
pub fn alpha_consensus_profile_commitment_v3() -> Hash32 {
    let mut bytes = vec![ALPHA_EXECUTED_STATE_VERSION_V3];
    bytes.extend_from_slice(&alpha_pow_profile_commitment_v3());
    bytes.extend_from_slice(&alpha_bip300_policy_commitment_v3());
    bytes.extend_from_slice(&alpha_repurpose_set_commitment_v3());
    bytes.extend_from_slice(
        &alpha_terminal_execution_parameters_v3()
            .commitment()
            .expect("fixed Alpha terminal parameters"),
    );
    bytes.extend_from_slice(b"checkpoint>=963647;terminal-deployments;OP_DRIVECHAIN=0xb4,len4,first,pushdc,exit;else-nop;repurpose=script-only");
    bytes.extend_from_slice(b";absolute-locktime-499999999=final;bip68-unchanged");
    bytes.extend_from_slice(&BITCOIN_MAX_BLOCK_WEIGHT_V2.to_be_bytes());
    tagged_hash("ECX/alpha-executed-consensus-profile/v3", &bytes)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AlphaScriptVerifierV3;

impl BitcoinScriptVerifierV2 for AlphaScriptVerifierV3 {
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
        active_script_flags: u32,
    ) -> Result<(), FullValidatorPrimitiveErrorV2> {
        if input_index >= transaction.input.len()
            || previous_outputs.len() != transaction.input.len()
        {
            return Err(FullValidatorPrimitiveErrorV2::ScriptConsensus);
        }
        // Native validation.cpp CheckInputScripts skips only script checks for
        // setRepurposeTx. UTXO membership, money, maturity and locks remain in
        // apply_bitcoin_block_utxos_v2 and cannot be skipped by this verifier.
        if alpha_repurpose_txid_v3(transaction.compute_txid()) {
            return Ok(());
        }
        crate::verify_bitcoin_script_input_with_dialect(
            transaction,
            input_index,
            previous_outputs,
            active_script_flags,
            true,
        )
    }
}

/// No Network, difficulty override, script flags, challenge or policy fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaBlockEvidenceStepV3 {
    pub raw_block: Vec<u8>,
    /// Must be authenticated by the enclosing observation/source workflow.
    /// Journal binding prevents substitution, not fabricated source clocks.
    pub authenticated_adjusted_time: u64,
    pub utxo_witness: BitcoinBlockUtxoWitnessV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaExecutedConsensusStateV3 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub tip: BitcoinChainTipV2,
    pub pow_context: AlphaHeaderContextV3,
    pub utxo_root: SparseUtxoNodeV2,
    pub bip300_state: AlphaBip300AllSlotStateV3,
    pub deployment_state: BitcoinTerminalDeploymentStateV2,
}

impl AlphaExecutedConsensusStateV3 {
    pub fn validate(&self) -> Result<(), FullValidatorPrimitiveErrorV2> {
        let genesis =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).block_hash();
        if self.version != ALPHA_EXECUTED_STATE_VERSION_V3
            || self.source_configuration_commitment == [0; 32]
            || self.tip.block_hash == BlockHash::all_zeros()
            || self.tip.chainwork_be == [0; 32]
            || self.utxo_root.hash == [0; 32]
            || self.tip.height < ALPHA_FORK_HEIGHT_V3 - 1
            || self.pow_context.previous_height != self.tip.height
            || self.pow_context.previous_header.block_hash() != self.tip.block_hash
            || self.bip300_state.as_state().tip_hash != Some(self.tip.block_hash)
            || self.bip300_state.as_state().next_height
                != self
                    .tip
                    .height
                    .checked_add(1)
                    .ok_or(FullValidatorPrimitiveErrorV2::ExecutedState)?
            || self.deployment_state.network_genesis != genesis
            || self.deployment_state.terminal_checkpoint_height < ALPHA_FORK_HEIGHT_V3 - 1
            || self.deployment_state.terminal_checkpoint_height > self.tip.height
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
        self.pow_context.commitment()?;
        self.bip300_state
            .commitment()
            .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
        if self.deployment_state.execution_parameters()? != alpha_terminal_execution_parameters_v3()
        {
            return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullValidatorPrimitiveErrorV2> {
        self.validate()?;
        let mut bytes = vec![self.version];
        bytes.extend_from_slice(&alpha_consensus_profile_commitment_v3());
        bytes.extend_from_slice(&self.source_configuration_commitment);
        bytes.extend_from_slice(self.tip.block_hash.as_byte_array());
        bytes.extend_from_slice(&self.tip.height.to_be_bytes());
        bytes.extend_from_slice(&self.tip.chainwork_be);
        bytes.extend_from_slice(&self.tip.discovery_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.pow_context.commitment()?);
        bytes.extend_from_slice(&self.utxo_root.hash);
        bytes.extend_from_slice(&self.utxo_root.aggregate.count.to_be_bytes());
        bytes.extend_from_slice(&self.utxo_root.aggregate.value_atoms.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .bip300_state
                .commitment()
                .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?,
        );
        bytes.extend_from_slice(&self.deployment_state.commitment()?);
        Ok(bytes)
    }

    pub fn commitment(&self) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
        Ok(tagged_hash(
            "ECX/alpha-executed-consensus-state/v3",
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

pub fn execute_alpha_executed_successor_v3(
    parent: &AlphaExecutedConsensusStateV3,
    step: &AlphaBlockEvidenceStepV3,
    discovery_sequence: u128,
) -> Result<AlphaExecutedConsensusStateV3, FullValidatorPrimitiveErrorV2> {
    execute_alpha_executed_successor_with_effects_v3(parent, step, discovery_sequence)
        .map(|(state, _)| state)
}

/// Return BIP300 effects only after the complete Alpha block execution passes.
/// These effects are checkpoint-relative: callers must still authenticate the
/// parent state and establish canonical-chain inclusion/finality. They are not
/// independently sufficient deposit receipts.
pub fn execute_alpha_executed_successor_with_effects_v3(
    parent: &AlphaExecutedConsensusStateV3,
    step: &AlphaBlockEvidenceStepV3,
    discovery_sequence: u128,
) -> Result<
    (AlphaExecutedConsensusStateV3, crate::bip300_v2::Bip300BlockEffectsV2),
    FullValidatorPrimitiveErrorV2,
> {
    execute_successor_with_witness(parent,&step.raw_block,step.authenticated_adjusted_time,
        discovery_sequence,SuccessorWitness::Expanded(&step.utxo_witness))
}

/// Compact transport uses the identical header, script, state and BIP300 gates.
pub fn execute_alpha_compact_successor_with_effects_v3(
    parent:&AlphaExecutedConsensusStateV3,raw_block:&[u8],authenticated_adjusted_time:u64,
    discovery_sequence:u128,frame:&[u8],
)->Result<(AlphaExecutedConsensusStateV3,crate::bip300_v2::Bip300BlockEffectsV2),FullValidatorPrimitiveErrorV2>{
    execute_successor_with_witness(parent,raw_block,authenticated_adjusted_time,discovery_sequence,SuccessorWitness::Compact(frame))
}

enum SuccessorWitness<'a>{Expanded(&'a BitcoinBlockUtxoWitnessV2),Compact(&'a [u8])}
fn execute_successor_with_witness(
    parent:&AlphaExecutedConsensusStateV3,raw_block:&[u8],authenticated_adjusted_time:u64,
    discovery_sequence:u128,witness:SuccessorWitness<'_>,
)->Result<(AlphaExecutedConsensusStateV3,crate::bip300_v2::Bip300BlockEffectsV2),FullValidatorPrimitiveErrorV2>{
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-start: alpha_header_block");
    parent.validate()?;
    if discovery_sequence <= parent.tip.discovery_sequence || authenticated_adjusted_time == 0
    {
        return Err(FullValidatorPrimitiveErrorV2::ExecutedState);
    }
    let block: Block = bitcoin::consensus::deserialize(raw_block)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let next_pow_context = verify_alpha_next_header_v3(
        &parent.pow_context,
        block.header,
        authenticated_adjusted_time,
    )?;
    verify_bitcoin_block_foundation_v2(
        raw_block,
        parent.tip.block_hash,
        block.header.target(),
        BITCOIN_MAX_BLOCK_WEIGHT_V2,
    )?;
    let parameters = parent.deployment_state.execution_parameters()?;
    let context=BitcoinBlockSpendContextV2 {
            height: next_pow_context.previous_height,
            previous_block_mtp: median_time_past_v2(&parent.pow_context.previous_11_times)?,
            bip34_active: parameters.bip34_active,
            bip68_active: parameters.bip68_active,
        };
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-end: alpha_header_block");
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-start: alpha_utxo_scripts");
    let result=match witness{
        SuccessorWitness::Expanded(w)=>apply_alpha_block_utxos_v3(&block,context,parent.utxo_root,w,parameters.active_script_flags,&AlphaScriptVerifierV3),
        SuccessorWitness::Compact(w)=>crate::compact_utxo_frame::verify_alpha(&block,context,parent.utxo_root,w,parameters.active_script_flags,&AlphaScriptVerifierV3),
    }?;
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-end: alpha_utxo_scripts");
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-start: alpha_bip300_state");
    let (bip300_state, effects) = apply_alpha_bip300_block_v3(&parent.bip300_state, &block)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ExecutedState)?;
    let next = AlphaExecutedConsensusStateV3 {
        version: ALPHA_EXECUTED_STATE_VERSION_V3,
        source_configuration_commitment: parent.source_configuration_commitment,
        tip: derive_successor_tip_v2(parent.tip, &block.header, discovery_sequence)?,
        pow_context: next_pow_context,
        utxo_root: result.next_root,
        bip300_state,
        deployment_state: parent.deployment_state.clone(),
    };
    next.validate()?;
    #[cfg(feature = "diagnostic-stages")]
    println!("cycle-tracker-report-end: alpha_bip300_state");
    Ok((next, effects))
}

#[cfg(test)]
#[path = "alpha_state_v3_tests.rs"]
pub(crate) mod tests;
