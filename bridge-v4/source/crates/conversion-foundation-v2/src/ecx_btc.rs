//! Composable, fail-closed ECX/BTC conversion-receipt relation.
//!
//! This module performs every check that is available in the provenance-pinned
//! Rust foundation: canonical witness decoding, a frozen checkpoint binding,
//! Alpha parent authorization, header linkage/difficulty/PoW/chainwork,
//! Bitcoin MTP, exact block/Merkle parsing, bounded slot-24 BIP300/BIP301
//! replay, BMM-to-Elements block binding, and basic Elements block continuity.
//!
//! The pinned foundation still does not implement full contextual Bitcoin
//! validation or full Elements/Simplicity/confidential-UTXO validation. Those
//! obligations are therefore represented as *mandatory recursive receipts*.
//! The conversion relation can emit public values only after a verifier has
//! accepted both exact receipt statements. There is no host-summary bypass.

use bincode::Options;
use elements::encode;
use elements::hashes::{sha256d, Hash};
use elements::{Block, TxMerkleNode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use usdd_bitcoin_bmm_ecx_v2::{
    apply_merkle_bound_elements_slot24_parent_block,
    apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact,
    verify_header_pow_against_caller_supplied_bits, verify_mtp_successor,
    BitcoinHeader, BlockHash, ContextualHeaderChainState, EffectiveSlot24M4,
    ElementsSlot24ReplayConfig, ElementsSlot24ReplayState, HeaderChainState, MinerBundleArtifact,
    PendingSlot24M6id, PendingSlot24Proposal, PowParameters, Slot24AccumulatorIdentity,
    Slot24ApprovedRoot, Slot24Ctip, Uint256,
};

pub type Hash32 = [u8; 32];

pub const ECX_BTC_CONVERSION_WITNESS_VERSION_V2: u8 = 3;
pub const ECX_BTC_CONVERSION_PUBLIC_VALUES_VERSION_V2: u8 = 2;
pub const ECX_BTC_CONVERSION_PUBLIC_VALUES_LEN_V2: usize = 275;
pub const ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2: u8 = 2;
pub const ECX_BTC_FULL_ELEMENTS_STATEMENT_VERSION_V2: u8 = 1;
/// Exact `FullAlphaStatementV3` journal length. Parsed by offset so this crate
/// does not import the adapter; the journal is not coerced into the Bitcoin
/// statement. Version byte `0xa3` is the adapter public-values version.
pub const FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3: u8 = 0xa3;
pub const FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3: usize = 529;
/// Parent-bound child conversion projection. Must stay identical to
/// `full-alpha-adapter-v3::conversion_composition_v3`.
pub const ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3: u8 = 0xa5;
pub const ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3: usize = 285;
pub const MAX_ECX_BTC_WITNESS_BYTES_V2: usize = 128 * 1024 * 1024;
pub const MAX_PARENT_BLOCKS_V2: usize = 8_192;
pub const MAX_ELEMENTS_BLOCKS_V2: usize = 8_192;
pub const MAX_PREDECESSOR_TRANSACTIONS_V2: usize = 65_536;
pub const MAX_CONFIDENTIAL_OPENINGS_V2: usize = 262_144;
pub const MAX_RECORD_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_CHECKPOINT_BYTES_V2: usize = 32 * 1024 * 1024;
pub const MAX_ELEMENTS_CONSENSUS_CONFIGURATION_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_RECURSIVE_PROOF_MARKER_BYTES_V2: usize = 256;
pub const BITCOIN_MTP_WINDOW: usize = 11;
pub const BASE_ASSET_ATOMS_PER_WHOLE: u128 = 100_000_000;
pub const KOALA_BEAR_MODULUS: u32 = 0x7f00_0001;
pub const OPENING_ROLE_SUPPLY_V2: u8 = 1;
pub const OPENING_ROLE_RESERVE_V2: u8 = 2;
pub const OPENING_ROLE_REDEMPTION_INVENTORY_V2: u8 = 3;
pub const OPENING_ROLE_BURN_V2: u8 = 4;
pub const OPENING_ROLE_FEE_V2: u8 = 5;
pub const OPENING_ROLE_IRRELEVANT_WITH_PROOF_V2: u8 = 6;

/// Deployment-frozen state from which both parent and Elements replay begin.
/// Its canonical tagged hash is exposed as `source_checkpoint_commitment`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxBtcSourceCheckpointV2 {
    pub version: u8,
    pub base_asset_id: Hash32,
    pub policy_asset_id: Hash32,
    pub quote_atoms_per_whole_base: u64,
    pub maximum_age_seconds: u64,
    pub required_parent_confirmations: u32,
    /// Immutable Bitcoin network/consensus profile commitment carried by every
    /// executed state. This is distinct from the outer checkpoint hash to
    /// avoid a self-referential hash cycle with the embedded state preimage.
    pub bitcoin_consensus_configuration_commitment: Hash32,
    /// Immutable Elements consensus/evaluator/checkpoint profile commitment.
    /// This is distinct from the outer checkpoint hash for the same reason.
    pub elements_consensus_configuration_commitment: Hash32,
    /// Canonical preimage of the Elements consensus/evaluator profile. The
    /// commitment is repeated explicitly so transition journals can carry a
    /// fixed-size network identity without embedding this bounded record.
    pub elements_consensus_configuration_preimage: Vec<u8>,
    pub full_bitcoin_checkpoint_program_id: Hash32,
    pub full_bitcoin_transition_program_id: Hash32,
    pub full_bitcoin_validator_program_id: Hash32,
    /// Distinct from the Bitcoin validator. The conversion recursively verifies
    /// the 529-byte Alpha parent journal under this program ID.
    pub full_alpha_validator_program_id: Hash32,
    /// Distinct from the Alpha parent validator. Recursively verifies the
    /// 285-byte parent-bound child conversion projection.
    pub full_alpha_child_validator_program_id: Hash32,
    pub full_elements_checkpoint_program_id: Hash32,
    pub full_elements_transition_program_id: Hash32,
    pub full_elements_validator_program_id: Hash32,
    pub parent: ParentHeaderCheckpointV2,
    pub bip300: ElementsSlot24CheckpointV2,
    pub elements: ElementsStateCheckpointV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentHeaderCheckpointV2 {
    pub header: Vec<u8>,
    pub height: u32,
    pub cumulative_work_be: Hash32,
    pub interval_start_time: u32,
    /// Exactly eleven linked headers ending at `header`. They are part of the
    /// frozen checkpoint preimage, not an untrusted timestamp summary.
    pub mtp_context_headers: Vec<Vec<u8>>,
    /// Canonical `BitcoinExecutedConsensusStateV2` preimage authenticated by
    /// the reviewed checkpoint receipt. A header-only checkpoint is not a
    /// full-validity trust root.
    pub complete_executed_checkpoint_preimage: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSlot24CheckpointV2 {
    pub processed_parent_height: u32,
    pub parent_tip_hash_internal: Hash32,
    pub active_proposal_hash: Option<Hash32>,
    pub required_activation: Option<RequiredActivationV2>,
    pub pending_proposals: Vec<PendingProposalV2>,
    pub ctip: Option<CtipV2>,
    /// Complete ordered M3/M4 vote state. Omitting an old proposal could make
    /// a later M6 appear unauthorized or hide a valid authorization.
    pub pending_m6ids: Vec<PendingM6V2>,
    /// Audit set carried by the source replay. It remains commitment-bound
    /// even though the source enforcer permits a paid M6id to be proposed
    /// again.
    pub successful_m6ids: Vec<Hash32>,
    pub previous_effective_m4: Option<EffectiveM4V2>,
    pub accumulator_identity: Option<AccumulatorIdentityV2>,
    pub approved_root: Option<ApprovedRootV2>,
    /// Canonical complete all-256-slot checkpoint/predecessor-receipt
    /// preimage. The inline adapter replays slot 24, while the mandatory full
    /// Bitcoin receipt authenticates this preimage and proves that no message
    /// or active sidechain slot was omitted.
    pub complete_all_slots_state_preimage: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredActivationV2 {
    pub parent_height: u32,
    pub parent_hash_internal: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingProposalV2 {
    pub proposal_hash: Hash32,
    pub proposal_height: u32,
    pub votes: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtipV2 {
    pub txid_internal: Hash32,
    pub vout: u32,
    pub value_satoshis: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingM6V2 {
    pub m6id: Hash32,
    pub proposal_height: u32,
    pub score: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EffectiveM4V2 {
    Upvote { m6id: Hash32 },
    Alarm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccumulatorIdentityV2 {
    pub bitcoin_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub usdd_asset: Hash32,
    pub vault_id: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRootV2 {
    pub claim_count: u64,
    pub claim_root: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsStateCheckpointV2 {
    pub height: u32,
    pub block_hash_internal: Hash32,
    pub block_time: u32,
    /// Exactly eleven authenticated Elements block times ending at
    /// `block_time`. The frozen checkpoint/full Elements receipt authenticates
    /// this context; the conversion relation derives later MTP from it.
    pub mtp_context_times: Vec<u32>,
    pub state_root: Hash32,
    pub utxo_root: Hash32,
    /// Complete authenticated snapshot bytes or a canonical predecessor
    /// receipt preimage. This record is frozen by the source checkpoint hash.
    pub complete_state_preimage: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxBtcCovenantDeploymentV2 {
    pub simplicity_program_bytes: Vec<u8>,
    pub deployment_transaction: Vec<u8>,
    pub redemption_inventory_outpoint: OutPointV2,
    pub reserve_outpoint: OutPointV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutPointV2 {
    pub txid_internal: Hash32,
    pub vout: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxBtcElementsMaterialV2 {
    /// Exact BMM-committed successor Elements blocks in chain order.
    pub blocks: Vec<Vec<u8>>,
    /// Exact predecessor transactions required to open/classify every spent
    /// output touched by the segment.
    pub predecessor_transactions: Vec<Vec<u8>>,
    /// Openings used by the full Elements recursive validator. Nonzero
    /// blinders are mandatory; an opening is never accepted as authentication
    /// without the full validator receipt.
    pub confidential_openings: Vec<EcxBtcConfidentialOpeningV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxBtcConfidentialOpeningV2 {
    pub outpoint: OutPointV2,
    pub asset_id: Hash32,
    pub amount: u64,
    pub asset_blinding_factor: Hash32,
    pub value_blinding_factor: Hash32,
    pub script_sha256: Hash32,
    /// Frozen classification selected by the full validator: 1 supply, 2
    /// reserve, 3 redemption inventory, 4 burn, 5 fee, or 6 irrelevant with
    /// proof. No other value is canonical.
    pub role: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursiveReceiptReferenceV2 {
    /// In SP1 this is the canonical deferred-proof marker; the compressed
    /// receipt itself travels in SP1's separate proof stream.
    pub proof_marker: Vec<u8>,
}

/// Authenticated output of the missing full contextual Bitcoin validator.
/// The conversion guest derives every field except the four validity flags,
/// then verifies a recursive proof over these exact bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinStatementV2 {
    pub version: u8,
    pub source_checkpoint_commitment: Hash32,
    pub exact_parent_branch_commitment: Hash32,
    pub parent_tip_hash_internal: Hash32,
    pub parent_tip_height: u32,
    pub parent_tip_mtp: u64,
    pub cumulative_work_be: Hash32,
    pub final_slot24_state_commitment: Hash32,
    /// Full-validator-only commitments. The source-local slot-24 adapter
    /// cannot derive these and must never substitute its partial state.
    pub initial_all_slots_state_commitment: Hash32,
    pub final_all_slots_state_commitment: Hash32,
    pub final_executed_frontier_commitment: Hash32,
    pub final_event_stream_commitment: Hash32,
    pub final_event_sequence: u128,
    pub contextual_consensus_valid: bool,
    pub selected_by_best_work: bool,
    pub all_bip300_messages_preserved: bool,
    pub confirmation_semantics_valid: bool,
}

/// Authenticated output of the missing full Elements validator. Its exact
/// state and economic totals become the conversion public values only after
/// the recursive receipt verifies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullElementsStatementV2 {
    pub version: u8,
    pub source_checkpoint_commitment: Hash32,
    pub covenant_commitment: Hash32,
    pub exact_material_commitment: Hash32,
    pub bmm_edge_commitment: Hash32,
    pub prior_state_root: Hash32,
    pub prior_utxo_root: Hash32,
    pub next_state_root: Hash32,
    pub next_utxo_root: Hash32,
    pub source_tip_hash_internal: Hash32,
    pub source_tip_height: u64,
    pub source_tip_mtp: u64,
    pub base_asset_id: Hash32,
    pub policy_asset_id: Hash32,
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub redemption_enabled: bool,
    pub complete_utxo_replay_valid: bool,
    pub confidential_openings_valid: bool,
    pub asset_conservation_valid: bool,
    pub simplicity_covenant_valid: bool,
    pub issuance_and_reissuance_valid: bool,
    pub pause_timelock_governance_valid: bool,
    pub all_outputs_classified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxBtcConversionWitnessV2 {
    pub version: u8,
    pub source_checkpoint: EcxBtcSourceCheckpointV2,
    pub covenant_deployment: EcxBtcCovenantDeploymentV2,
    pub parent_successor_blocks: Vec<Vec<u8>>,
    /// Optional canonical accumulator M6 artifact aligned one-for-one with
    /// parent successor blocks. `None` is required for blocks that do not
    /// consume one. Extra or wrong artifacts are rejected by slot-24 replay.
    pub parent_bip300_m6_artifacts: Vec<Option<Vec<u8>>>,
    pub elements_material: EcxBtcElementsMaterialV2,
    pub full_bitcoin_statement: FullBitcoinStatementV2,
    pub full_bitcoin_receipt: RecursiveReceiptReferenceV2,
    /// Canonical 529-byte `FullAlphaStatementV3` journal. Not a Bitcoin statement.
    pub full_alpha_statement: Vec<u8>,
    pub full_alpha_receipt: RecursiveReceiptReferenceV2,
    /// Canonical 285-byte parent-bound child conversion projection.
    pub alpha_child_conversion_projection: Vec<u8>,
    pub alpha_child_conversion_receipt: RecursiveReceiptReferenceV2,
    pub full_elements_statement: FullElementsStatementV2,
    pub full_elements_receipt: RecursiveReceiptReferenceV2,
}

/// Exact 275-byte ABI consumed by the outer V2 transition proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcxBtcConversionPublicValuesV2 {
    pub observed_parent_block_hash: Hash32,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub source_height: u64,
    pub source_mtp: u64,
    pub valid_until_mtp: u64,
    pub base_asset_id: Hash32,
    pub quote_unit_id: Hash32,
    pub redemption_covenant_commitment: Hash32,
    pub source_checkpoint_commitment: Hash32,
    pub source_state_root: Hash32,
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub redemption_enabled: bool,
}

impl EcxBtcConversionPublicValuesV2 {
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ECX_BTC_CONVERSION_PUBLIC_VALUES_LEN_V2);
        out.push(ECX_BTC_CONVERSION_PUBLIC_VALUES_VERSION_V2);
        out.push(0); // ConversionLegKindV2::EcxBtc
        out.extend_from_slice(&self.observed_parent_block_hash);
        out.extend_from_slice(&self.observed_parent_height.to_be_bytes());
        out.extend_from_slice(&self.observed_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.source_height.to_be_bytes());
        out.extend_from_slice(&self.source_mtp.to_be_bytes());
        out.extend_from_slice(&self.valid_until_mtp.to_be_bytes());
        out.extend_from_slice(&self.base_asset_id);
        out.extend_from_slice(&self.quote_unit_id);
        out.extend_from_slice(&self.redemption_covenant_commitment);
        out.extend_from_slice(&self.source_checkpoint_commitment);
        out.extend_from_slice(&self.source_state_root);
        out.extend_from_slice(&self.quote_atoms_per_whole_base.to_be_bytes());
        out.extend_from_slice(&self.outstanding_base_atoms.to_be_bytes());
        out.extend_from_slice(&self.redeemable_reserve_quote_atoms.to_be_bytes());
        out.push(u8::from(self.redemption_enabled));
        debug_assert_eq!(out.len(), ECX_BTC_CONVERSION_PUBLIC_VALUES_LEN_V2);
        out
    }
}

/// Production guest implementations must cryptographically verify the exact
/// recursive receipt. Tests may implement this trait, but no permissive
/// implementation is provided by this crate.
pub trait RecursiveReceiptVerifierV2 {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), RecursiveReceiptErrorV2>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("recursive receipt rejected")]
pub struct RecursiveReceiptErrorV2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum EcxBtcConversionErrorV2 {
    #[error("unsupported ECX/BTC witness or checkpoint version")]
    UnsupportedVersion,
    #[error("canonical witness codec rejected the input")]
    NonCanonicalWitness,
    #[error("witness exceeds a frozen resource bound")]
    ResourceLimit,
    #[error("frozen source checkpoint is malformed")]
    InvalidSourceCheckpoint,
    #[error("frozen redemption covenant deployment is malformed")]
    InvalidCovenantDeployment,
    #[error("Alpha parent checkpoint, header, PoW, MTP, chainwork, or block validation failed")]
    InvalidParentHistory,
    #[error("BIP300/BIP301 slot-24 replay or BMM inclusion failed")]
    InvalidBip300OrBmm,
    #[error("Elements block serialization, Merkle root, order, or BMM binding failed")]
    InvalidElementsHistory,
    #[error("full contextual Bitcoin recursive statement does not match derived state")]
    BitcoinStatementMismatch,
    #[error("full contextual Bitcoin recursive receipt was rejected")]
    BitcoinReceiptRejected,
    #[error("Alpha parent journal does not bind the derived parent history")]
    AlphaStatementMismatch,
    #[error("Alpha parent recursive receipt was rejected")]
    AlphaReceiptRejected,
    #[error("parent-bound child conversion projection does not bind parent history and child totals")]
    AlphaChildProjectionMismatch,
    #[error("parent-bound child conversion projection receipt was rejected")]
    AlphaChildReceiptRejected,
    #[error("full Elements recursive statement does not match exact material")]
    ElementsStatementMismatch,
    #[error("full Elements/Simplicity/confidential-state recursive receipt was rejected")]
    ElementsReceiptRejected,
    #[error(
        "source state is stale, unconfirmed, paused, under-reserved, or otherwise unredeemable"
    )]
    RedemptionUnavailable,
    #[error("conversion arithmetic overflow")]
    ArithmeticOverflow,
}

pub fn encode_ecx_btc_conversion_witness_v2(
    witness: &EcxBtcConversionWitnessV2,
) -> Result<Vec<u8>, EcxBtcConversionErrorV2> {
    validate_resource_bounds(witness)?;
    canonical_serialize(witness)
}

pub fn decode_ecx_btc_conversion_witness_v2(
    bytes: &[u8],
) -> Result<EcxBtcConversionWitnessV2, EcxBtcConversionErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_ECX_BTC_WITNESS_BYTES_V2 {
        return Err(EcxBtcConversionErrorV2::ResourceLimit);
    }
    let options = canonical_options();
    let witness: EcxBtcConversionWitnessV2 = options
        .deserialize(bytes)
        .map_err(|_| EcxBtcConversionErrorV2::NonCanonicalWitness)?;
    validate_resource_bounds(&witness)?;
    let reencoded = canonical_serialize(&witness)?;
    if reencoded != bytes {
        return Err(EcxBtcConversionErrorV2::NonCanonicalWitness);
    }
    Ok(witness)
}

/// Canonical statement bytes which the full Bitcoin subprogram must commit.
/// This is the exact byte string hashed by SP1 deferred verification.
pub fn encode_full_bitcoin_statement_v2(
    statement: &FullBitcoinStatementV2,
) -> Result<Vec<u8>, EcxBtcConversionErrorV2> {
    if statement.version != ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2
        || statement.initial_all_slots_state_commitment == [0; 32]
        || statement.final_all_slots_state_commitment == [0; 32]
        || statement.final_executed_frontier_commitment == [0; 32]
        || statement.final_event_stream_commitment == [0; 32]
    {
        return Err(EcxBtcConversionErrorV2::UnsupportedVersion);
    }
    canonical_serialize(statement)
}

/// Canonical statement bytes which the full Elements subprogram must commit.
/// This is the exact byte string hashed by SP1 deferred verification.
pub fn encode_full_elements_statement_v2(
    statement: &FullElementsStatementV2,
) -> Result<Vec<u8>, EcxBtcConversionErrorV2> {
    if statement.version != ECX_BTC_FULL_ELEMENTS_STATEMENT_VERSION_V2 {
        return Err(EcxBtcConversionErrorV2::UnsupportedVersion);
    }
    canonical_serialize(statement)
}

pub fn ecx_btc_source_checkpoint_commitment_v2(
    checkpoint: &EcxBtcSourceCheckpointV2,
) -> Result<Hash32, EcxBtcConversionErrorV2> {
    validate_checkpoint(checkpoint)?;
    Ok(tagged_hash(
        "ECX/ecx-btc-source-checkpoint/v2",
        &canonical_serialize(checkpoint)?,
    ))
}

pub fn elements_consensus_configuration_commitment_v2(preimage: &[u8]) -> Hash32 {
    tagged_hash("ECX/elements-consensus-configuration/v2", preimage)
}

pub fn ecx_btc_covenant_commitment_v2(
    covenant: &EcxBtcCovenantDeploymentV2,
) -> Result<Hash32, EcxBtcConversionErrorV2> {
    validate_covenant(covenant)?;
    Ok(tagged_hash(
        "ECX/ecx-btc-redemption-covenant/v2",
        &canonical_serialize(covenant)?,
    ))
}

/// Derive the exact full-Bitcoin statement expected by the conversion
/// relation without verifying its recursive receipt. This is the adapter
/// boundary for the full validator: all foundation-derived fields are
/// recomputed here, while the all-slot/frontier/event commitments remain
/// mandatory claims authenticated by that validator's receipt.
pub fn derive_full_bitcoin_statement_v2(
    witness: &EcxBtcConversionWitnessV2,
) -> Result<FullBitcoinStatementV2, EcxBtcConversionErrorV2> {
    validate_resource_bounds(witness)?;
    validate_checkpoint(&witness.source_checkpoint)?;
    encode_full_bitcoin_statement_v2(&witness.full_bitcoin_statement)?;
    let checkpoint_commitment =
        ecx_btc_source_checkpoint_commitment_v2(&witness.source_checkpoint)?;
    Ok(verify_parent_history(
        &witness.source_checkpoint,
        checkpoint_commitment,
        &witness.parent_successor_blocks,
        &witness.parent_bip300_m6_artifacts,
        &witness.elements_material.blocks,
        &witness.full_bitcoin_statement,
    )?
    .statement)
}

/// Tip fields extracted from a canonical 529-byte Alpha parent journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlphaParentJournalTipV3 {
    pub terminal_selected_height: u32,
    pub terminal_mtp: u64,
    pub terminal_tip_hash_internal: Hash32,
    pub terminal_chainwork_be: Hash32,
    pub final_all_slots_state_commitment: Hash32,
    pub final_frontier_commitment: Hash32,
    pub final_event_stream_commitment: Hash32,
    pub final_event_sequence: u128,
}

fn read_hash32(bytes: &[u8], offset: usize) -> Result<Hash32, EcxBtcConversionErrorV2> {
    bytes
        .get(offset..offset + 32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(EcxBtcConversionErrorV2::AlphaStatementMismatch)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, EcxBtcConversionErrorV2> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(EcxBtcConversionErrorV2::AlphaStatementMismatch)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, EcxBtcConversionErrorV2> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(EcxBtcConversionErrorV2::AlphaStatementMismatch)
}

fn read_u128_le(bytes: &[u8], offset: usize) -> Result<u128, EcxBtcConversionErrorV2> {
    bytes
        .get(offset..offset + 16)
        .and_then(|slice| slice.try_into().ok())
        .map(u128::from_le_bytes)
        .ok_or(EcxBtcConversionErrorV2::AlphaStatementMismatch)
}

/// Decode the Alpha parent journal by the frozen 529-byte layout. This is not
/// a `FullBitcoinStatementV2` and must not be rewritten into one.
pub fn decode_alpha_parent_journal_tip_v3(
    bytes: &[u8],
) -> Result<AlphaParentJournalTipV3, EcxBtcConversionErrorV2> {
    if bytes.len() != FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3
        || bytes.first().copied() != Some(FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3)
    {
        return Err(EcxBtcConversionErrorV2::AlphaStatementMismatch);
    }
    let tip = AlphaParentJournalTipV3 {
        final_all_slots_state_commitment: read_hash32(bytes, 341)?,
        final_frontier_commitment: read_hash32(bytes, 373)?,
        final_event_stream_commitment: read_hash32(bytes, 405)?,
        terminal_selected_height: read_u32_le(bytes, 437)?,
        final_event_sequence: read_u128_le(bytes, 441)?,
        terminal_tip_hash_internal: read_hash32(bytes, 457)?,
        terminal_mtp: read_u64_le(bytes, 489)?,
        terminal_chainwork_be: read_hash32(bytes, 497)?,
    };
    if tip.terminal_mtp == 0
        || tip.final_event_sequence == 0
        || [
            tip.terminal_tip_hash_internal,
            tip.terminal_chainwork_be,
            tip.final_all_slots_state_commitment,
            tip.final_frontier_commitment,
            tip.final_event_stream_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(EcxBtcConversionErrorV2::AlphaStatementMismatch);
    }
    Ok(tip)
}

fn require_alpha_parent_binds_derived_history(
    journal: &[u8],
    parent: &VerifiedParentHistoryV2,
) -> Result<AlphaParentJournalTipV3, EcxBtcConversionErrorV2> {
    let tip = decode_alpha_parent_journal_tip_v3(journal)?;
    if tip.terminal_tip_hash_internal != parent.tip_hash
        || tip.terminal_selected_height != parent.tip_height
        || tip.terminal_mtp != parent.tip_mtp
        || tip.terminal_chainwork_be != parent.statement.cumulative_work_be
        || tip.final_all_slots_state_commitment != parent.statement.final_all_slots_state_commitment
        || tip.final_frontier_commitment != parent.statement.final_executed_frontier_commitment
        || tip.final_event_stream_commitment != parent.statement.final_event_stream_commitment
        || tip.final_event_sequence != parent.statement.final_event_sequence
    {
        return Err(EcxBtcConversionErrorV2::AlphaStatementMismatch);
    }
    Ok(tip)
}

/// Parent-bound child conversion projection. Layout matches
/// `full-alpha-adapter-v3::conversion_composition_v3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlphaChildConversionProjectionV3 {
    pub parent_binding_commitment: Hash32,
    pub parent_block_hash_internal: Hash32,
    pub parent_predecessor_hash_internal: Hash32,
    pub m7_critical_hash_internal: Hash32,
    pub child_checkpoint_commitment: Hash32,
    pub base_asset_internal: Hash32,
    pub quote_asset_internal: Hash32,
    pub parent_height: u32,
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub required_reserve_quote_atoms: u128,
}

pub fn decode_alpha_child_conversion_projection_v3(
    bytes: &[u8],
) -> Result<AlphaChildConversionProjectionV3, EcxBtcConversionErrorV2> {
    if bytes.len() != ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3
        || bytes.first().copied() != Some(ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3)
    {
        return Err(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch);
    }
    let projection = AlphaChildConversionProjectionV3 {
        parent_binding_commitment: read_hash32(bytes, 1)?,
        parent_block_hash_internal: read_hash32(bytes, 33)?,
        parent_predecessor_hash_internal: read_hash32(bytes, 65)?,
        m7_critical_hash_internal: read_hash32(bytes, 97)?,
        child_checkpoint_commitment: read_hash32(bytes, 129)?,
        base_asset_internal: read_hash32(bytes, 161)?,
        quote_asset_internal: read_hash32(bytes, 193)?,
        parent_height: u32::from_be_bytes(
            bytes
                .get(225..229)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)?,
        ),
        quote_atoms_per_whole_base: u64::from_be_bytes(
            bytes
                .get(229..237)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)?,
        ),
        outstanding_base_atoms: u128::from_be_bytes(
            bytes
                .get(237..253)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)?,
        ),
        redeemable_reserve_quote_atoms: u128::from_be_bytes(
            bytes
                .get(253..269)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)?,
        ),
        required_reserve_quote_atoms: u128::from_be_bytes(
            bytes
                .get(269..285)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)?,
        ),
    };
    if projection.parent_height == 0
        || projection.quote_atoms_per_whole_base == 0
        || projection.outstanding_base_atoms == 0
        || projection.redeemable_reserve_quote_atoms == 0
        || projection.required_reserve_quote_atoms == 0
        || projection.base_asset_internal == projection.quote_asset_internal
        || [
            projection.parent_binding_commitment,
            projection.parent_block_hash_internal,
            projection.parent_predecessor_hash_internal,
            projection.m7_critical_hash_internal,
            projection.child_checkpoint_commitment,
            projection.base_asset_internal,
            projection.quote_asset_internal,
        ]
        .contains(&[0; 32])
    {
        return Err(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch);
    }
    Ok(projection)
}

fn require_alpha_child_projection_binds_parent_and_elements(
    bytes: &[u8],
    parent: &VerifiedParentHistoryV2,
    checkpoint: &EcxBtcSourceCheckpointV2,
    outstanding_base_atoms: u128,
    redeemable_reserve_quote_atoms: u128,
    required_reserve_quote_atoms: u128,
) -> Result<AlphaChildConversionProjectionV3, EcxBtcConversionErrorV2> {
    let projection = decode_alpha_child_conversion_projection_v3(bytes)?;
    if projection.parent_block_hash_internal != parent.tip_hash
        || projection.parent_height != parent.tip_height
        || projection.base_asset_internal != checkpoint.base_asset_id
        || projection.quote_asset_internal != checkpoint.policy_asset_id
        || projection.quote_atoms_per_whole_base != checkpoint.quote_atoms_per_whole_base
        || projection.outstanding_base_atoms != outstanding_base_atoms
        || projection.redeemable_reserve_quote_atoms != redeemable_reserve_quote_atoms
        || projection.required_reserve_quote_atoms != required_reserve_quote_atoms
    {
        return Err(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch);
    }
    Ok(projection)
}

pub fn execute_ecx_btc_conversion_v2<V: RecursiveReceiptVerifierV2>(
    witness: &EcxBtcConversionWitnessV2,
    verifier: &V,
) -> Result<EcxBtcConversionPublicValuesV2, EcxBtcConversionErrorV2> {
    validate_resource_bounds(witness)?;
    let checkpoint = &witness.source_checkpoint;
    validate_checkpoint(checkpoint)?;

    let source_checkpoint_commitment = ecx_btc_source_checkpoint_commitment_v2(checkpoint)?;
    let covenant_commitment = ecx_btc_covenant_commitment_v2(&witness.covenant_deployment)?;

    let parent = verify_parent_history(
        checkpoint,
        source_checkpoint_commitment,
        &witness.parent_successor_blocks,
        &witness.parent_bip300_m6_artifacts,
        &witness.elements_material.blocks,
        &witness.full_bitcoin_statement,
    )?;

    if witness.full_bitcoin_statement != parent.statement {
        return Err(EcxBtcConversionErrorV2::BitcoinStatementMismatch);
    }
    require_receipt_shape(&witness.full_bitcoin_receipt)?;
    let bitcoin_statement_bytes = encode_full_bitcoin_statement_v2(&parent.statement)?;
    verifier
        .verify(
            checkpoint.full_bitcoin_validator_program_id,
            &bitcoin_statement_bytes,
            &witness.full_bitcoin_receipt.proof_marker,
        )
        .map_err(|_| EcxBtcConversionErrorV2::BitcoinReceiptRejected)?;
    require_alpha_parent_binds_derived_history(&witness.full_alpha_statement, &parent)?;
    require_receipt_shape(&witness.full_alpha_receipt)?;
    verifier
        .verify(
            checkpoint.full_alpha_validator_program_id,
            &witness.full_alpha_statement,
            &witness.full_alpha_receipt.proof_marker,
        )
        .map_err(|_| EcxBtcConversionErrorV2::AlphaReceiptRejected)?;
    if !parent.statement.contextual_consensus_valid
        || !parent.statement.selected_by_best_work
        || !parent.statement.all_bip300_messages_preserved
        || !parent.statement.confirmation_semantics_valid
    {
        return Err(EcxBtcConversionErrorV2::BitcoinStatementMismatch);
    }

    let elements_derived = verify_elements_material(
        checkpoint,
        source_checkpoint_commitment,
        covenant_commitment,
        parent.bmm_edges.clone(),
        &witness.elements_material,
    )?;
    let expected_elements = FullElementsStatementV2 {
        version: ECX_BTC_FULL_ELEMENTS_STATEMENT_VERSION_V2,
        source_checkpoint_commitment,
        covenant_commitment,
        exact_material_commitment: elements_derived.material_commitment,
        bmm_edge_commitment: elements_derived.bmm_edge_commitment,
        prior_state_root: checkpoint.elements.state_root,
        prior_utxo_root: checkpoint.elements.utxo_root,
        next_state_root: witness.full_elements_statement.next_state_root,
        next_utxo_root: witness.full_elements_statement.next_utxo_root,
        source_tip_hash_internal: elements_derived.tip_hash,
        source_tip_height: elements_derived.tip_height,
        source_tip_mtp: elements_derived.tip_time,
        base_asset_id: checkpoint.base_asset_id,
        policy_asset_id: checkpoint.policy_asset_id,
        quote_atoms_per_whole_base: checkpoint.quote_atoms_per_whole_base,
        outstanding_base_atoms: witness.full_elements_statement.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: witness
            .full_elements_statement
            .redeemable_reserve_quote_atoms,
        redemption_enabled: witness.full_elements_statement.redemption_enabled,
        complete_utxo_replay_valid: witness.full_elements_statement.complete_utxo_replay_valid,
        confidential_openings_valid: witness.full_elements_statement.confidential_openings_valid,
        asset_conservation_valid: witness.full_elements_statement.asset_conservation_valid,
        simplicity_covenant_valid: witness.full_elements_statement.simplicity_covenant_valid,
        issuance_and_reissuance_valid: witness
            .full_elements_statement
            .issuance_and_reissuance_valid,
        pause_timelock_governance_valid: witness
            .full_elements_statement
            .pause_timelock_governance_valid,
        all_outputs_classified: witness.full_elements_statement.all_outputs_classified,
    };
    if witness.full_elements_statement != expected_elements
        || expected_elements.next_state_root == [0; 32]
        || expected_elements.next_utxo_root == [0; 32]
        || expected_elements.outstanding_base_atoms == 0
        || !expected_elements.complete_utxo_replay_valid
        || !expected_elements.confidential_openings_valid
        || !expected_elements.asset_conservation_valid
        || !expected_elements.simplicity_covenant_valid
        || !expected_elements.issuance_and_reissuance_valid
        || !expected_elements.pause_timelock_governance_valid
        || !expected_elements.all_outputs_classified
    {
        return Err(EcxBtcConversionErrorV2::ElementsStatementMismatch);
    }
    require_receipt_shape(&witness.full_elements_receipt)?;
    let elements_statement_bytes = encode_full_elements_statement_v2(&expected_elements)?;
    verifier
        .verify(
            checkpoint.full_elements_validator_program_id,
            &elements_statement_bytes,
            &witness.full_elements_receipt.proof_marker,
        )
        .map_err(|_| EcxBtcConversionErrorV2::ElementsReceiptRejected)?;

    let confirmations = parent
        .tip_height
        .checked_sub(parent.last_bmm_parent_height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(EcxBtcConversionErrorV2::InvalidBip300OrBmm)?;
    let valid_until_mtp = expected_elements
        .source_tip_mtp
        .checked_add(checkpoint.maximum_age_seconds)
        .ok_or(EcxBtcConversionErrorV2::ArithmeticOverflow)?;
    let required_reserve = ceil_div(
        expected_elements
            .outstanding_base_atoms
            .checked_mul(u128::from(checkpoint.quote_atoms_per_whole_base))
            .ok_or(EcxBtcConversionErrorV2::ArithmeticOverflow)?,
        BASE_ASSET_ATOMS_PER_WHOLE,
    )?;
    require_alpha_child_projection_binds_parent_and_elements(
        &witness.alpha_child_conversion_projection,
        &parent,
        checkpoint,
        expected_elements.outstanding_base_atoms,
        expected_elements.redeemable_reserve_quote_atoms,
        required_reserve,
    )?;
    require_receipt_shape(&witness.alpha_child_conversion_receipt)?;
    verifier
        .verify(
            checkpoint.full_alpha_child_validator_program_id,
            &witness.alpha_child_conversion_projection,
            &witness.alpha_child_conversion_receipt.proof_marker,
        )
        .map_err(|_| EcxBtcConversionErrorV2::AlphaChildReceiptRejected)?;
    if confirmations < checkpoint.required_parent_confirmations
        || expected_elements.source_tip_mtp > parent.tip_mtp
        || valid_until_mtp < parent.tip_mtp
        || !expected_elements.redemption_enabled
        || expected_elements.redeemable_reserve_quote_atoms < required_reserve
    {
        return Err(EcxBtcConversionErrorV2::RedemptionUnavailable);
    }

    Ok(EcxBtcConversionPublicValuesV2 {
        observed_parent_block_hash: parent.tip_hash,
        observed_parent_height: u64::from(parent.tip_height),
        observed_parent_mtp: parent.tip_mtp,
        source_height: expected_elements.source_tip_height,
        source_mtp: expected_elements.source_tip_mtp,
        valid_until_mtp,
        base_asset_id: checkpoint.base_asset_id,
        quote_unit_id: checkpoint.policy_asset_id,
        redemption_covenant_commitment: covenant_commitment,
        source_checkpoint_commitment,
        source_state_root: expected_elements.next_state_root,
        quote_atoms_per_whole_base: checkpoint.quote_atoms_per_whole_base,
        outstanding_base_atoms: expected_elements.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: expected_elements.redeemable_reserve_quote_atoms,
        redemption_enabled: true,
    })
}

struct VerifiedParentHistoryV2 {
    statement: FullBitcoinStatementV2,
    tip_hash: Hash32,
    tip_height: u32,
    tip_mtp: u64,
    last_bmm_parent_height: u32,
    bmm_edges: Vec<BmmEdgeBindingV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BmmEdgeBindingV2 {
    parent_block_hash_internal: Hash32,
    parent_height: u32,
    child_block_hash_internal: Hash32,
}

/// Alpha parent proof-of-work parameters.
///
/// Alpha is a Bitcoin fork sharing Bitcoin's genesis, retarget interval, target
/// timespan and spacing. It differs from LayerTwo Signet in exactly one header
/// parameter, the proof-of-work limit, and it has no Signet block-signature
/// challenge. Signet's limit is `0x00000377ae00...`; Alpha uses the Bitcoin
/// mainnet limit implied by compact bits `0x1d00ffff`.
///
/// There is deliberately no network discriminator and no caller-supplied
/// parameter set: a witness cannot turn this relation back into Signet,
/// regtest, or stock Bitcoin. These values must stay equal to
/// `ecx_full_consensus_validator_v2::alpha_pow_v3`.
pub const ALPHA_POW_LIMIT_BE_V3: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub const ALPHA_TARGET_TIMESPAN_V3: u32 = 14 * 24 * 60 * 60;
pub const ALPHA_TARGET_SPACING_V3: u32 = 10 * 60;

fn alpha_pow_parameters_v3() -> PowParameters {
    PowParameters {
        pow_limit: Uint256::from_be_bytes(ALPHA_POW_LIMIT_BE_V3),
        target_timespan: ALPHA_TARGET_TIMESPAN_V3,
        target_spacing: ALPHA_TARGET_SPACING_V3,
        allow_min_difficulty_blocks: false,
        no_retargeting: false,
    }
}

/// Advance the parent chain by one Alpha block.
///
/// This replaces `verify_layer_two_signet_mtp_successor`. It performs the same
/// median-time-past, header-linkage, difficulty and proof-of-work checks under
/// Alpha parameters, and deliberately omits the Signet block-signature
/// validation, which has no Alpha equivalent. Block structure and Merkle
/// binding for the same bytes are enforced immediately afterwards by the
/// merkle-bound slot-24 replay, so a malformed block cannot be accepted here
/// and skipped there.
fn alpha_header_slice(serialized_block: &[u8]) -> Result<&[u8], EcxBtcConversionErrorV2> {
    let header_bytes = serialized_block
        .get(..80)
        .ok_or(EcxBtcConversionErrorV2::InvalidParentHistory)?;
    BitcoinHeader::decode_exact(header_bytes)
        .map_err(|_| EcxBtcConversionErrorV2::InvalidParentHistory)?;
    Ok(header_bytes)
}

fn verify_alpha_mtp_successor(
    prior: &ContextualHeaderChainState,
    serialized_block: &[u8],
) -> Result<ContextualHeaderChainState, EcxBtcConversionErrorV2> {
    let header_bytes = alpha_header_slice(serialized_block)?;
    verify_mtp_successor(prior, header_bytes, alpha_pow_parameters_v3())
        .map_err(|_| EcxBtcConversionErrorV2::InvalidParentHistory)
}

fn verify_parent_history(
    checkpoint: &EcxBtcSourceCheckpointV2,
    checkpoint_commitment: Hash32,
    parent_blocks: &[Vec<u8>],
    m6_artifacts: &[Option<Vec<u8>>],
    elements_blocks: &[Vec<u8>],
    recursive_claim: &FullBitcoinStatementV2,
) -> Result<VerifiedParentHistoryV2, EcxBtcConversionErrorV2> {
    if parent_blocks.len() != m6_artifacts.len() {
        return Err(EcxBtcConversionErrorV2::InvalidBip300OrBmm);
    }
    let parent_checkpoint = &checkpoint.parent;
    let decoded_checkpoint = BitcoinHeader::decode_exact(&parent_checkpoint.header)
        .map_err(|_| EcxBtcConversionErrorV2::InvalidParentHistory)?;
    let verified_checkpoint = verify_header_pow_against_caller_supplied_bits(
        &parent_checkpoint.header,
        decoded_checkpoint.bits,
        alpha_pow_parameters_v3(),
    )
    .map_err(|_| EcxBtcConversionErrorV2::InvalidParentHistory)?;
    let header_state = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
        parent_checkpoint.height,
        verified_checkpoint,
        Uint256::from_be_bytes(parent_checkpoint.cumulative_work_be),
        parent_checkpoint.interval_start_time,
    )
    .map_err(|_| EcxBtcConversionErrorV2::InvalidParentHistory)?;
    let timestamps = checkpoint_context_times(parent_checkpoint)?;
    let mut contextual =
        ContextualHeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            header_state,
            &timestamps,
        )
        .map_err(|_| EcxBtcConversionErrorV2::InvalidSourceCheckpoint)?;
    let mut slot24 = slot24_state(checkpoint)?;
    let exact_branch = canonical_serialize(&(parent_blocks, m6_artifacts))?;
    let branch_commitment = tagged_hash("ECX/ecx-btc-parent-branch/v2", &exact_branch);
    let mut edges = Vec::new();
    let mut elements_index = 0usize;

    for (serialized, m6_artifact) in parent_blocks.iter().zip(m6_artifacts) {
        contextual = verify_alpha_mtp_successor(&contextual, serialized)?;

        let decoded_m6 = m6_artifact
            .as_deref()
            .map(MinerBundleArtifact::decode_artifact)
            .transpose()
            .map_err(|_| EcxBtcConversionErrorV2::InvalidBip300OrBmm)?;
        let effects = match decoded_m6.as_ref() {
            Some(artifact) => apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact(
                &mut slot24,
                serialized,
                artifact,
            ),
            None => apply_merkle_bound_elements_slot24_parent_block(&mut slot24, serialized),
        }
        .map_err(|_| EcxBtcConversionErrorV2::InvalidBip300OrBmm)?;
        if let Some(edge) = effects.bmm_edge {
            let child = elements_blocks
                .get(elements_index)
                .ok_or(EcxBtcConversionErrorV2::InvalidElementsHistory)?;
            let block: Block = decode_exact_elements(child)?;
            let child_hash = block.block_hash().to_byte_array();
            if edge.committed_child_hash.to_internal_bytes() != child_hash
                || edge.successor_height != contextual.header_chain.height
                || edge.successor_block_hash != contextual.header_chain.tip.hash
            {
                return Err(EcxBtcConversionErrorV2::InvalidBip300OrBmm);
            }
            edges.push(BmmEdgeBindingV2 {
                parent_block_hash_internal: edge.successor_block_hash.to_internal_bytes(),
                parent_height: edge.successor_height,
                child_block_hash_internal: child_hash,
            });
            elements_index = elements_index
                .checked_add(1)
                .ok_or(EcxBtcConversionErrorV2::ArithmeticOverflow)?;
        }
    }
    if elements_index != elements_blocks.len()
        || edges.is_empty()
        || !slot24.required_proposal_is_active()
    {
        return Err(EcxBtcConversionErrorV2::InvalidBip300OrBmm);
    }
    let tip_mtp = u64::from(contextual.median_time_past());
    let tip_hash = contextual.header_chain.tip.hash.to_internal_bytes();
    let final_slot24_state_commitment = slot24_commitment(&slot24)?;
    let statement = FullBitcoinStatementV2 {
        version: ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2,
        source_checkpoint_commitment: checkpoint_commitment,
        exact_parent_branch_commitment: branch_commitment,
        parent_tip_hash_internal: tip_hash,
        parent_tip_height: contextual.header_chain.height,
        parent_tip_mtp: tip_mtp,
        cumulative_work_be: contextual.header_chain.cumulative_work.to_be_bytes(),
        final_slot24_state_commitment,
        initial_all_slots_state_commitment: recursive_claim.initial_all_slots_state_commitment,
        final_all_slots_state_commitment: recursive_claim.final_all_slots_state_commitment,
        final_executed_frontier_commitment: recursive_claim.final_executed_frontier_commitment,
        final_event_stream_commitment: recursive_claim.final_event_stream_commitment,
        final_event_sequence: recursive_claim.final_event_sequence,
        // These are proved by the mandatory recursive full validator. The
        // inline foundation deliberately cannot manufacture them.
        contextual_consensus_valid: true,
        selected_by_best_work: true,
        all_bip300_messages_preserved: true,
        confirmation_semantics_valid: true,
    };
    Ok(VerifiedParentHistoryV2 {
        statement,
        tip_hash,
        tip_height: contextual.header_chain.height,
        tip_mtp,
        last_bmm_parent_height: edges
            .last()
            .ok_or(EcxBtcConversionErrorV2::InvalidBip300OrBmm)?
            .parent_height,
        bmm_edges: edges,
    })
}

struct VerifiedElementsMaterialV2 {
    material_commitment: Hash32,
    bmm_edge_commitment: Hash32,
    tip_hash: Hash32,
    tip_height: u64,
    tip_time: u64,
}

fn verify_elements_material(
    checkpoint: &EcxBtcSourceCheckpointV2,
    checkpoint_commitment: Hash32,
    covenant_commitment: Hash32,
    edges: Vec<BmmEdgeBindingV2>,
    material: &EcxBtcElementsMaterialV2,
) -> Result<VerifiedElementsMaterialV2, EcxBtcConversionErrorV2> {
    if material.blocks.len() != edges.len() {
        return Err(EcxBtcConversionErrorV2::InvalidElementsHistory);
    }
    let mut expected_previous = checkpoint.elements.block_hash_internal;
    let mut expected_height = checkpoint.elements.height;
    let mut mtp_context = checkpoint.elements.mtp_context_times.clone();
    let mut tip_hash = [0; 32];
    for (serialized, edge) in material.blocks.iter().zip(&edges) {
        let block: Block = decode_exact_elements(serialized)?;
        expected_height = expected_height
            .checked_add(1)
            .ok_or(EcxBtcConversionErrorV2::ArithmeticOverflow)?;
        let block_hash = block.block_hash().to_byte_array();
        if block_hash != edge.child_block_hash_internal
            || block.header.prev_blockhash.to_byte_array() != expected_previous
            || block.header.height != expected_height
            || block.header.time <= median_time_u32(&mtp_context)
            || !elements_merkle_root_valid(&block)
        {
            return Err(EcxBtcConversionErrorV2::InvalidElementsHistory);
        }
        expected_previous = block_hash;
        mtp_context.remove(0);
        mtp_context.push(block.header.time);
        tip_hash = block_hash;
    }
    validate_confidential_openings(&material.confidential_openings)?;
    let material_bytes = canonical_serialize(material)?;
    let mut material_binding = Vec::with_capacity(64 + material_bytes.len());
    material_binding.extend_from_slice(&checkpoint_commitment);
    material_binding.extend_from_slice(&covenant_commitment);
    material_binding.extend_from_slice(&material_bytes);
    let material_commitment = tagged_hash("ECX/ecx-btc-elements-material/v2", &material_binding);
    let edge_bytes = canonical_serialize(&edges)?;
    let bmm_edge_commitment = tagged_hash("ECX/ecx-btc-bmm-edges/v2", &edge_bytes);
    Ok(VerifiedElementsMaterialV2 {
        material_commitment,
        bmm_edge_commitment,
        tip_hash,
        tip_height: u64::from(expected_height),
        tip_time: u64::from(median_time_u32(&mtp_context)),
    })
}

fn validate_checkpoint(
    checkpoint: &EcxBtcSourceCheckpointV2,
) -> Result<(), EcxBtcConversionErrorV2> {
    let recursive_program_ids = [
        checkpoint.full_bitcoin_checkpoint_program_id,
        checkpoint.full_bitcoin_transition_program_id,
        checkpoint.full_bitcoin_validator_program_id,
        checkpoint.full_alpha_validator_program_id,
        checkpoint.full_alpha_child_validator_program_id,
        checkpoint.full_elements_checkpoint_program_id,
        checkpoint.full_elements_transition_program_id,
        checkpoint.full_elements_validator_program_id,
    ];
    let recursive_program_ids_valid = recursive_program_ids
        .iter()
        .all(|program_id| sp1_program_id_is_canonical(*program_id))
        && recursive_program_ids
            .iter()
            .enumerate()
            .all(|(index, program_id)| !recursive_program_ids[..index].contains(program_id));
    if checkpoint.version != ECX_BTC_CONVERSION_WITNESS_VERSION_V2
        || checkpoint.base_asset_id == [0; 32]
        || checkpoint.policy_asset_id == [0; 32]
        || checkpoint.base_asset_id == checkpoint.policy_asset_id
        || checkpoint.quote_atoms_per_whole_base == 0
        || checkpoint.maximum_age_seconds == 0
        || checkpoint.required_parent_confirmations == 0
        || checkpoint.bitcoin_consensus_configuration_commitment == [0; 32]
        || checkpoint.elements_consensus_configuration_commitment == [0; 32]
        || checkpoint.elements_consensus_configuration_preimage.is_empty()
        || checkpoint.elements_consensus_configuration_preimage.len()
            > MAX_ELEMENTS_CONSENSUS_CONFIGURATION_BYTES_V2
        || elements_consensus_configuration_commitment_v2(
            &checkpoint.elements_consensus_configuration_preimage,
        ) != checkpoint.elements_consensus_configuration_commitment
        || !recursive_program_ids_valid
        || checkpoint.parent.height == 0
        || checkpoint.parent.cumulative_work_be == [0; 32]
        || checkpoint.parent.interval_start_time == 0
        || checkpoint
            .parent
            .complete_executed_checkpoint_preimage
            .is_empty()
        || checkpoint
            .parent
            .complete_executed_checkpoint_preimage
            .len()
            > MAX_CHECKPOINT_BYTES_V2
        || checkpoint.bip300.processed_parent_height != checkpoint.parent.height
        || checkpoint
            .bip300
            .complete_all_slots_state_preimage
            .is_empty()
        || checkpoint.bip300.complete_all_slots_state_preimage.len() > MAX_CHECKPOINT_BYTES_V2
        || checkpoint.elements.height == 0
        || checkpoint.elements.block_hash_internal == [0; 32]
        || checkpoint.elements.block_time == 0
        || checkpoint.elements.mtp_context_times.len() != BITCOIN_MTP_WINDOW
        || checkpoint.elements.mtp_context_times.contains(&0)
        || checkpoint.elements.mtp_context_times.last().copied()
            != Some(checkpoint.elements.block_time)
        || checkpoint.elements.state_root == [0; 32]
        || checkpoint.elements.utxo_root == [0; 32]
        || checkpoint.elements.complete_state_preimage.is_empty()
        || checkpoint.elements.complete_state_preimage.len() > MAX_CHECKPOINT_BYTES_V2
    {
        return Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint);
    }
    Ok(())
}

fn validate_covenant(covenant: &EcxBtcCovenantDeploymentV2) -> Result<(), EcxBtcConversionErrorV2> {
    if covenant.simplicity_program_bytes.is_empty()
        || covenant.simplicity_program_bytes.len() > MAX_RECORD_BYTES_V2
        || covenant.deployment_transaction.is_empty()
        || covenant.deployment_transaction.len() > MAX_RECORD_BYTES_V2
        || covenant.redemption_inventory_outpoint.txid_internal == [0; 32]
        || covenant.reserve_outpoint.txid_internal == [0; 32]
        || covenant.redemption_inventory_outpoint == covenant.reserve_outpoint
    {
        return Err(EcxBtcConversionErrorV2::InvalidCovenantDeployment);
    }
    let transaction: elements::Transaction = encode::deserialize(&covenant.deployment_transaction)
        .map_err(|_| EcxBtcConversionErrorV2::InvalidCovenantDeployment)?;
    if encode::serialize(&transaction) != covenant.deployment_transaction {
        return Err(EcxBtcConversionErrorV2::InvalidCovenantDeployment);
    }
    Ok(())
}

fn validate_resource_bounds(
    witness: &EcxBtcConversionWitnessV2,
) -> Result<(), EcxBtcConversionErrorV2> {
    if witness.version != ECX_BTC_CONVERSION_WITNESS_VERSION_V2 {
        return Err(EcxBtcConversionErrorV2::UnsupportedVersion);
    }
    if witness.parent_successor_blocks.is_empty()
        || witness.parent_successor_blocks.len() > MAX_PARENT_BLOCKS_V2
        || witness.parent_bip300_m6_artifacts.len() != witness.parent_successor_blocks.len()
        || witness.elements_material.blocks.is_empty()
        || witness.elements_material.blocks.len() > MAX_ELEMENTS_BLOCKS_V2
        || witness.elements_material.predecessor_transactions.len()
            > MAX_PREDECESSOR_TRANSACTIONS_V2
        || witness.elements_material.confidential_openings.is_empty()
        || witness.elements_material.confidential_openings.len() > MAX_CONFIDENTIAL_OPENINGS_V2
        || records_invalid(&witness.parent_successor_blocks)
        || witness
            .parent_bip300_m6_artifacts
            .iter()
            .flatten()
            .any(|artifact| artifact.is_empty() || artifact.len() > MAX_RECORD_BYTES_V2)
        || records_invalid(&witness.elements_material.blocks)
        || records_invalid(&witness.elements_material.predecessor_transactions)
        || witness.full_alpha_statement.len() != FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3
        || witness.alpha_child_conversion_projection.len()
            != ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3
        || witness.source_checkpoint.parent.header.len() != 80
        || witness.source_checkpoint.parent.mtp_context_headers.len() != BITCOIN_MTP_WINDOW
        || witness.source_checkpoint.bip300.pending_m6ids.len() > MAX_PARENT_BLOCKS_V2
        || witness.source_checkpoint.bip300.successful_m6ids.len() > MAX_PARENT_BLOCKS_V2
        || witness
            .source_checkpoint
            .parent
            .mtp_context_headers
            .iter()
            .any(|header| header.len() != 80)
    {
        return Err(EcxBtcConversionErrorV2::ResourceLimit);
    }
    Ok(())
}

fn validate_confidential_openings(
    openings: &[EcxBtcConfidentialOpeningV2],
) -> Result<(), EcxBtcConversionErrorV2> {
    if openings.is_empty()
        || openings.iter().any(|opening| {
            opening.outpoint.txid_internal == [0; 32]
                || opening.asset_id == [0; 32]
                || opening.amount == 0
                || opening.asset_blinding_factor == [0; 32]
                || opening.value_blinding_factor == [0; 32]
                || opening.script_sha256 == [0; 32]
                || !(1..=6).contains(&opening.role)
        })
    {
        return Err(EcxBtcConversionErrorV2::ElementsStatementMismatch);
    }
    let mut opening_outpoints = openings
        .iter()
        .map(|opening| opening.outpoint)
        .collect::<Vec<_>>();
    opening_outpoints.sort_unstable();
    if opening_outpoints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EcxBtcConversionErrorV2::ElementsStatementMismatch);
    }
    Ok(())
}

fn records_invalid(records: &[Vec<u8>]) -> bool {
    records
        .iter()
        .any(|record| record.is_empty() || record.len() > MAX_RECORD_BYTES_V2)
}

fn median_time_u32(times: &[u32]) -> u32 {
    debug_assert_eq!(times.len(), BITCOIN_MTP_WINDOW);
    let mut ordered = times.to_vec();
    ordered.sort_unstable();
    ordered[ordered.len() / 2]
}

fn require_receipt_shape(
    receipt: &RecursiveReceiptReferenceV2,
) -> Result<(), EcxBtcConversionErrorV2> {
    if receipt.proof_marker.is_empty()
        || receipt.proof_marker.len() > MAX_RECURSIVE_PROOF_MARKER_BYTES_V2
    {
        return Err(EcxBtcConversionErrorV2::ResourceLimit);
    }
    Ok(())
}

fn checkpoint_context_times(
    checkpoint: &ParentHeaderCheckpointV2,
) -> Result<Vec<u32>, EcxBtcConversionErrorV2> {
    let mut previous = None;
    let mut timestamps = Vec::with_capacity(BITCOIN_MTP_WINDOW);
    for raw in &checkpoint.mtp_context_headers {
        let header = BitcoinHeader::decode_exact(raw)
            .map_err(|_| EcxBtcConversionErrorV2::InvalidSourceCheckpoint)?;
        if let Some(previous_hash) = previous {
            if header.previous_block != previous_hash {
                return Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint);
            }
        }
        previous = Some(header.block_hash());
        timestamps.push(header.time);
    }
    if checkpoint.mtp_context_headers.last() != Some(&checkpoint.header) {
        return Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint);
    }
    Ok(timestamps)
}

fn slot24_state(
    checkpoint: &EcxBtcSourceCheckpointV2,
) -> Result<ElementsSlot24ReplayState, EcxBtcConversionErrorV2> {
    let expected_parent_hash = BitcoinHeader::decode_exact(&checkpoint.parent.header)
        .map_err(|_| EcxBtcConversionErrorV2::InvalidSourceCheckpoint)?
        .block_hash()
        .to_internal_bytes();
    if checkpoint.bip300.parent_tip_hash_internal != expected_parent_hash {
        return Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint);
    }
    let pending_proposals = checkpoint
        .bip300
        .pending_proposals
        .iter()
        .map(|proposal| PendingSlot24Proposal {
            proposal_hash: proposal.proposal_hash,
            proposal_height: proposal.proposal_height,
            votes: proposal.votes,
        })
        .collect();
    let ctip = checkpoint.bip300.ctip.map(|ctip| Slot24Ctip {
        txid: BlockHash::from_internal_bytes(ctip.txid_internal),
        vout: ctip.vout,
        value_sat: ctip.value_satoshis,
    });
    let required_activation = checkpoint.bip300.required_activation.map(|activation| {
        (
            activation.parent_height,
            BlockHash::from_internal_bytes(activation.parent_hash_internal),
        )
    });
    let base_arguments = (
        ElementsSlot24ReplayConfig::elements_v1(),
        checkpoint.bip300.processed_parent_height,
        BlockHash::from_internal_bytes(checkpoint.bip300.parent_tip_hash_internal),
        checkpoint.bip300.active_proposal_hash,
        required_activation,
        pending_proposals,
        ctip,
    );
    match (
        checkpoint.bip300.accumulator_identity,
        checkpoint.bip300.approved_root,
    ) {
        (Some(identity), Some(root)) => {
            ElementsSlot24ReplayState::from_unverified_usdd_checkpoint_requires_manifest_binding(
                base_arguments.0,
                base_arguments.1,
                base_arguments.2,
                base_arguments.3,
                base_arguments.4,
                base_arguments.5,
                base_arguments.6,
                checkpoint
                    .bip300
                    .pending_m6ids
                    .iter()
                    .map(|pending| PendingSlot24M6id {
                        m6id: pending.m6id.into(),
                        proposal_height: pending.proposal_height,
                        score: pending.score,
                    })
                    .collect(),
                checkpoint
                    .bip300
                    .successful_m6ids
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect(),
                checkpoint
                    .bip300
                    .previous_effective_m4
                    .map(|effective| match effective {
                        EffectiveM4V2::Upvote { m6id } => {
                            EffectiveSlot24M4::Upvote { m6id: m6id.into() }
                        }
                        EffectiveM4V2::Alarm => EffectiveSlot24M4::Alarm,
                    }),
                Slot24AccumulatorIdentity {
                    bitcoin_genesis: identity.bitcoin_genesis.into(),
                    elements_genesis: identity.elements_genesis.into(),
                    usdd_asset: identity.usdd_asset.into(),
                    vault_id: identity.vault_id.into(),
                },
                Slot24ApprovedRoot {
                    claim_count: root.claim_count,
                    claim_root: root.claim_root.into(),
                },
            )
        }
        (None, None)
            if checkpoint.bip300.pending_m6ids.is_empty()
                && checkpoint.bip300.successful_m6ids.is_empty()
                && checkpoint.bip300.previous_effective_m4.is_none() =>
        {
            ElementsSlot24ReplayState::from_unverified_checkpoint_requires_manifest_binding(
                base_arguments.0,
                base_arguments.1,
                base_arguments.2,
                base_arguments.3,
                base_arguments.4,
                base_arguments.5,
                base_arguments.6,
            )
        }
        _ => return Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint),
    }
    .map_err(|_| EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
}

fn slot24_commitment(state: &ElementsSlot24ReplayState) -> Result<Hash32, EcxBtcConversionErrorV2> {
    let pending = state
        .pending_proposals()
        .map(|proposal| PendingProposalV2 {
            proposal_hash: proposal.proposal_hash,
            proposal_height: proposal.proposal_height,
            votes: proposal.votes,
        })
        .collect::<Vec<_>>();
    let encoded = canonical_serialize(&(
        state.next_height(),
        state.tip_hash().to_internal_bytes(),
        state.active_proposal_hash(),
        state
            .required_activation()
            .map(|(height, hash)| (height, hash.to_internal_bytes())),
        pending,
        state
            .ctip()
            .map(|ctip| (ctip.txid.to_internal_bytes(), ctip.vout, ctip.value_sat)),
        state
            .pending_m6ids()
            .map(|pending| {
                (
                    *pending.m6id.as_bytes(),
                    pending.proposal_height,
                    pending.score,
                )
            })
            .collect::<Vec<_>>(),
        state
            .successful_m6ids()
            .map(|m6id| *m6id.as_bytes())
            .collect::<Vec<_>>(),
        state
            .previous_effective_m4()
            .map(|effective| match effective {
                EffectiveSlot24M4::Upvote { m6id } => (1u8, *m6id.as_bytes()),
                EffectiveSlot24M4::Alarm => (2u8, [0; 32]),
            }),
        state.accumulator_identity().map(|identity| {
            (
                *identity.bitcoin_genesis.as_bytes(),
                *identity.elements_genesis.as_bytes(),
                *identity.usdd_asset.as_bytes(),
                *identity.vault_id.as_bytes(),
            )
        }),
        state
            .approved_root()
            .map(|root| (root.claim_count, *root.claim_root.as_bytes())),
    ))?;
    Ok(tagged_hash("ECX/ecx-btc-slot24-state/v2", &encoded))
}

fn decode_exact_elements(bytes: &[u8]) -> Result<Block, EcxBtcConversionErrorV2> {
    let block: Block =
        encode::deserialize(bytes).map_err(|_| EcxBtcConversionErrorV2::InvalidElementsHistory)?;
    if encode::serialize(&block) != bytes || block.txdata.is_empty() {
        return Err(EcxBtcConversionErrorV2::InvalidElementsHistory);
    }
    Ok(block)
}

fn elements_merkle_root_valid(block: &Block) -> bool {
    if block.txdata.is_empty() {
        return false;
    }
    let mut layer = block
        .txdata
        .iter()
        .map(|transaction| transaction.txid().to_byte_array())
        .collect::<Vec<_>>();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            if pair.len() == 2 && pair[0] == pair[1] {
                return false;
            }
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&pair[0]);
            preimage[32..].copy_from_slice(&right);
            next.push(sha256d::Hash::hash(&preimage).to_byte_array());
        }
        layer = next;
    }
    block.header.merkle_root == TxMerkleNode::from_byte_array(layer[0])
}

fn ceil_div(value: u128, divisor: u128) -> Result<u128, EcxBtcConversionErrorV2> {
    value
        .checked_add(divisor - 1)
        .map(|sum| sum / divisor)
        .ok_or(EcxBtcConversionErrorV2::ArithmeticOverflow)
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_ECX_BTC_WITNESS_BYTES_V2 as u64)
}

fn canonical_serialize<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, EcxBtcConversionErrorV2> {
    canonical_options()
        .serialize(value)
        .map_err(|_| EcxBtcConversionErrorV2::NonCanonicalWitness)
}

#[allow(dead_code)]
fn canonical_deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, EcxBtcConversionErrorV2> {
    canonical_options()
        .deserialize(bytes)
        .map_err(|_| EcxBtcConversionErrorV2::NonCanonicalWitness)
}

pub fn tagged_hash(tag: &str, message: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag.as_bytes()).into();
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(message);
    engine.finalize().into()
}

/// Exact marker used to bind an SP1 deferred receipt to its program and
/// public values. It is intentionally public so an offline exporter can check
/// witness/receipt-stream alignment. This hash is not a proof.
pub fn sp1_deferred_receipt_marker_v2(program_id: Hash32, public_values: &[u8]) -> Hash32 {
    let public_values_sha256: Hash32 = Sha256::digest(public_values).into();
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&program_id);
    preimage.extend_from_slice(&public_values_sha256);
    tagged_hash("ECX/truthcoin-sp1-deferred-proof/v1", &preimage)
}

pub fn sp1_program_id_is_canonical(program_id: Hash32) -> bool {
    program_id != [0; 32]
        && program_id
            .chunks_exact(4)
            .map(|word| u32::from_be_bytes(word.try_into().expect("four-byte word")))
            .all(|word| word < KOALA_BEAR_MODULUS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct DenyAll;

    impl RecursiveReceiptVerifierV2 for DenyAll {
        fn verify(
            &self,
            _program_id: Hash32,
            _public_values: &[u8],
            _proof_marker: &[u8],
        ) -> Result<(), RecursiveReceiptErrorV2> {
            Err(RecursiveReceiptErrorV2)
        }
    }

    fn alpha_journal_bytes(tip: AlphaParentJournalTipV3) -> Vec<u8> {
        let mut bytes = vec![0u8; FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3];
        bytes[0] = FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3;
        bytes[341..373].copy_from_slice(&tip.final_all_slots_state_commitment);
        bytes[373..405].copy_from_slice(&tip.final_frontier_commitment);
        bytes[405..437].copy_from_slice(&tip.final_event_stream_commitment);
        bytes[437..441].copy_from_slice(&tip.terminal_selected_height.to_le_bytes());
        bytes[441..457].copy_from_slice(&tip.final_event_sequence.to_le_bytes());
        bytes[457..489].copy_from_slice(&tip.terminal_tip_hash_internal);
        bytes[489..497].copy_from_slice(&tip.terminal_mtp.to_le_bytes());
        bytes[497..529].copy_from_slice(&tip.terminal_chainwork_be);
        bytes
    }

    #[test]
    fn alpha_parent_journal_binds_derived_tip_and_rejects_coercion() {
        let tip = AlphaParentJournalTipV3 {
            terminal_selected_height: 64,
            terminal_mtp: 1_700_000_000,
            terminal_tip_hash_internal: [0x11; 32],
            terminal_chainwork_be: [0x22; 32],
            final_all_slots_state_commitment: [0x33; 32],
            final_frontier_commitment: [0x44; 32],
            final_event_stream_commitment: [0x55; 32],
            final_event_sequence: 9,
        };
        let journal = alpha_journal_bytes(tip);
        assert_eq!(decode_alpha_parent_journal_tip_v3(&journal).unwrap(), tip);
        let mut wrong_version = journal.clone();
        wrong_version[0] = ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2;
        assert_eq!(
            decode_alpha_parent_journal_tip_v3(&wrong_version),
            Err(EcxBtcConversionErrorV2::AlphaStatementMismatch)
        );
        let mut short = journal.clone();
        short.pop();
        assert_eq!(
            decode_alpha_parent_journal_tip_v3(&short),
            Err(EcxBtcConversionErrorV2::AlphaStatementMismatch)
        );
    }

    fn child_projection_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3];
        bytes[0] = ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3;
        bytes[1..33].copy_from_slice(&[1; 32]);
        bytes[33..65].copy_from_slice(&[2; 32]);
        bytes[65..97].copy_from_slice(&[3; 32]);
        bytes[97..129].copy_from_slice(&[4; 32]);
        bytes[129..161].copy_from_slice(&[5; 32]);
        bytes[161..193].copy_from_slice(&[6; 32]);
        bytes[193..225].copy_from_slice(&[7; 32]);
        bytes[225..229].copy_from_slice(&64u32.to_be_bytes());
        bytes[229..237].copy_from_slice(&1u64.to_be_bytes());
        bytes[237..253].copy_from_slice(&100_000_001u128.to_be_bytes());
        bytes[253..269].copy_from_slice(&2u128.to_be_bytes());
        bytes[269..285].copy_from_slice(&2u128.to_be_bytes());
        bytes
    }

    #[test]
    fn ecx_btc_covenant_and_checkpoint_commitments_are_derived_from_the_relation() {
        let witness = structurally_bounded_witness();
        let covenant = ecx_btc_covenant_commitment_v2(&witness.covenant_deployment).unwrap();
        let checkpoint = ecx_btc_source_checkpoint_commitment_v2(&witness.source_checkpoint).unwrap();
        assert_ne!(covenant, [0; 32]);
        assert_ne!(checkpoint, [0; 32]);
        assert_ne!(covenant, checkpoint);
        let mut mutated = witness.covenant_deployment.clone();
        mutated.simplicity_program_bytes = vec![2];
        assert_ne!(
            ecx_btc_covenant_commitment_v2(&mutated).unwrap(),
            covenant
        );
    }

    #[test]
    fn child_projection_is_not_the_parent_journal_and_binds_totals() {
        let encoded = child_projection_bytes();
        let decoded = decode_alpha_child_conversion_projection_v3(&encoded).unwrap();
        assert_eq!(decoded.parent_height, 64);
        assert_eq!(decoded.outstanding_base_atoms, 100_000_001);
        assert_eq!(decoded.required_reserve_quote_atoms, 2);
        let mut as_parent = encoded.clone();
        as_parent[0] = FULL_ALPHA_ADAPTER_PUBLIC_VALUES_VERSION_V3;
        assert_eq!(
            decode_alpha_child_conversion_projection_v3(&as_parent),
            Err(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)
        );
        let mut empty_supply = encoded;
        empty_supply[237..253].copy_from_slice(&0u128.to_be_bytes());
        assert_eq!(
            decode_alpha_child_conversion_projection_v3(&empty_supply),
            Err(EcxBtcConversionErrorV2::AlphaChildProjectionMismatch)
        );
    }

    #[test]
    fn public_values_abi_is_exactly_the_outer_abi() {
        let values = EcxBtcConversionPublicValuesV2 {
            observed_parent_block_hash: [1; 32],
            observed_parent_height: 2,
            observed_parent_mtp: 3,
            source_height: 4,
            source_mtp: 5,
            valid_until_mtp: 6,
            base_asset_id: [7; 32],
            quote_unit_id: [8; 32],
            redemption_covenant_commitment: [9; 32],
            source_checkpoint_commitment: [10; 32],
            source_state_root: [11; 32],
            quote_atoms_per_whole_base: 12,
            outstanding_base_atoms: 13,
            redeemable_reserve_quote_atoms: 14,
            redemption_enabled: true,
        };
        let encoded = values.canonical_bytes();
        assert_eq!(encoded.len(), ECX_BTC_CONVERSION_PUBLIC_VALUES_LEN_V2);
        assert_eq!(&encoded[..2], &[2, 0]);
    }

    #[test]
    fn missing_recursive_receipts_have_no_permissive_verifier() {
        let error = DenyAll
            .verify([1; 32], b"statement", b"marker")
            .unwrap_err();
        assert_eq!(error, RecursiveReceiptErrorV2);
    }

    #[test]
    fn execute_ecx_btc_conversion_v2_does_not_succeed_without_receipts() {
        let witness = structurally_bounded_witness();
        assert!(
            execute_ecx_btc_conversion_v2(&witness, &DenyAll).is_err(),
            "the named conversion relation must not emit public values when recursive receipts are denied"
        );
    }

    struct MarkerOnly;

    impl RecursiveReceiptVerifierV2 for MarkerOnly {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), RecursiveReceiptErrorV2> {
            if proof_marker == sp1_deferred_receipt_marker_v2(program_id, public_values) {
                Ok(())
            } else {
                Err(RecursiveReceiptErrorV2)
            }
        }
    }

    #[test]
    fn named_relation_does_not_emit_public_values_from_structural_dummy_witness() {
        let witness = structurally_bounded_witness();
        let result = execute_ecx_btc_conversion_v2(&witness, &MarkerOnly);
        assert!(
            result.is_err(),
            "structural dummy witness must not be treated as a conversion identity source: {result:?}"
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes_and_wrong_version() {
        let mut witness = structurally_bounded_witness();
        let encoded = encode_ecx_btc_conversion_witness_v2(&witness).unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_ecx_btc_conversion_witness_v2(&trailing),
            Err(EcxBtcConversionErrorV2::NonCanonicalWitness)
        );
        witness.version = 1;
        assert_eq!(
            encode_ecx_btc_conversion_witness_v2(&witness),
            Err(EcxBtcConversionErrorV2::UnsupportedVersion)
        );
    }

    #[test]
    fn checkpoint_identity_and_recursive_roles_are_nonzero_and_distinct() {
        let mut witness = structurally_bounded_witness();
        witness.source_checkpoint.full_elements_validator_program_id =
            witness.source_checkpoint.full_bitcoin_validator_program_id;
        assert_eq!(
            execute_ecx_btc_conversion_v2(&witness, &DenyAll),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );
        let mut witness = structurally_bounded_witness();
        witness.source_checkpoint.full_bitcoin_transition_program_id =
            witness.source_checkpoint.full_bitcoin_checkpoint_program_id;
        assert_eq!(
            validate_checkpoint(&witness.source_checkpoint),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );
        let mut witness = structurally_bounded_witness();
        witness
            .source_checkpoint
            .parent
            .complete_executed_checkpoint_preimage
            .clear();
        assert_eq!(
            validate_checkpoint(&witness.source_checkpoint),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );
    }

    #[test]
    fn zero_confidential_blinders_are_rejected_before_a_receipt_can_help() {
        let mut witness = structurally_bounded_witness();
        witness.elements_material.confidential_openings[0].value_blinding_factor = [0; 32];
        assert_eq!(
            validate_confidential_openings(&witness.elements_material.confidential_openings),
            Err(EcxBtcConversionErrorV2::ElementsStatementMismatch)
        );
        witness.elements_material.confidential_openings[0].value_blinding_factor = [14; 32];
        witness.elements_material.confidential_openings[0].asset_blinding_factor = [0; 32];
        assert_eq!(
            validate_confidential_openings(&witness.elements_material.confidential_openings),
            Err(EcxBtcConversionErrorV2::ElementsStatementMismatch)
        );
    }

    #[test]
    fn duplicate_openings_and_unclassified_outputs_are_rejected() {
        let mut witness = structurally_bounded_witness();
        let duplicate = witness.elements_material.confidential_openings[0].clone();
        witness
            .elements_material
            .confidential_openings
            .push(duplicate);
        assert_eq!(
            validate_confidential_openings(&witness.elements_material.confidential_openings),
            Err(EcxBtcConversionErrorV2::ElementsStatementMismatch)
        );
        witness.elements_material.confidential_openings[0].role = 7;
        assert_eq!(
            validate_confidential_openings(&witness.elements_material.confidential_openings),
            Err(EcxBtcConversionErrorV2::ElementsStatementMismatch)
        );
        witness.elements_material.confidential_openings.pop();
        witness.elements_material.confidential_openings[0].role = 0;
        assert_eq!(
            validate_confidential_openings(&witness.elements_material.confidential_openings),
            Err(EcxBtcConversionErrorV2::ElementsStatementMismatch)
        );
    }

    #[test]
    fn deferred_marker_binds_program_and_statement_bytes() {
        let program = [3; 32];
        let marker = sp1_deferred_receipt_marker_v2(program, b"statement");
        assert_ne!(
            marker,
            sp1_deferred_receipt_marker_v2([4; 32], b"statement")
        );
        assert_ne!(marker, sp1_deferred_receipt_marker_v2(program, b"mutated"));
        assert!(sp1_program_id_is_canonical(program));
        let mut invalid = program;
        invalid[..4].copy_from_slice(&KOALA_BEAR_MODULUS.to_be_bytes());
        assert!(!sp1_program_id_is_canonical(invalid));
    }

    #[test]
    fn canonical_witness_encoding_is_deterministic() {
        let witness = structurally_bounded_witness();
        let first = encode_ecx_btc_conversion_witness_v2(&witness).unwrap();
        let second = encode_ecx_btc_conversion_witness_v2(&witness).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            decode_ecx_btc_conversion_witness_v2(&first).unwrap(),
            witness
        );
    }

    #[test]
    fn malformed_mtp_checkpoint_context_is_rejected() {
        let witness = structurally_bounded_witness();
        assert_eq!(
            checkpoint_context_times(&witness.source_checkpoint.parent),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );
    }

    #[test]
    fn elements_mtp_context_and_complete_bip300_state_are_mandatory() {
        let mut witness = structurally_bounded_witness();
        witness.source_checkpoint.elements.mtp_context_times.pop();
        assert_eq!(
            validate_checkpoint(&witness.source_checkpoint),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );

        witness.source_checkpoint.elements.mtp_context_times = vec![1; BITCOIN_MTP_WINDOW];
        witness
            .source_checkpoint
            .bip300
            .complete_all_slots_state_preimage
            .clear();
        assert_eq!(
            validate_checkpoint(&witness.source_checkpoint),
            Err(EcxBtcConversionErrorV2::InvalidSourceCheckpoint)
        );
    }

    #[test]
    fn m6_artifacts_are_exactly_aligned_with_parent_blocks() {
        let mut witness = structurally_bounded_witness();
        witness.parent_bip300_m6_artifacts.clear();
        assert_eq!(
            encode_ecx_btc_conversion_witness_v2(&witness),
            Err(EcxBtcConversionErrorV2::ResourceLimit)
        );

        witness.parent_bip300_m6_artifacts = vec![Some(vec![])];
        assert_eq!(
            encode_ecx_btc_conversion_witness_v2(&witness),
            Err(EcxBtcConversionErrorV2::ResourceLimit)
        );
    }

    #[test]
    fn m6_artifacts_change_the_exact_parent_branch_commitment() {
        let blocks = vec![vec![1, 2, 3]];
        let absent = canonical_serialize(&(&blocks, vec![None::<Vec<u8>>])).unwrap();
        let present = canonical_serialize(&(&blocks, vec![Some(vec![4])])).unwrap();
        assert_ne!(
            tagged_hash("ECX/ecx-btc-parent-branch/v2", &absent),
            tagged_hash("ECX/ecx-btc-parent-branch/v2", &present)
        );
    }

    #[test]
    fn frozen_checkpoint_and_covenant_commitments_bind_every_mutation() {
        let witness = structurally_bounded_witness();
        let checkpoint = ecx_btc_source_checkpoint_commitment_v2(&witness.source_checkpoint)
            .expect("structural checkpoint");
        let mut mutated_checkpoint = witness.source_checkpoint.clone();
        mutated_checkpoint.quote_atoms_per_whole_base += 1;
        assert_ne!(
            checkpoint,
            ecx_btc_source_checkpoint_commitment_v2(&mutated_checkpoint)
                .expect("mutated structural checkpoint")
        );

        let covenant = ecx_btc_covenant_commitment_v2(&witness.covenant_deployment)
            .expect("structural covenant");
        let mut mutated_covenant = witness.covenant_deployment.clone();
        mutated_covenant.reserve_outpoint.vout += 1;
        assert_ne!(
            covenant,
            ecx_btc_covenant_commitment_v2(&mutated_covenant).expect("mutated structural covenant")
        );
    }

    #[test]
    fn recursive_statement_codecs_reject_version_substitution() {
        let witness = structurally_bounded_witness();
        assert!(
            !encode_full_bitcoin_statement_v2(&witness.full_bitcoin_statement)
                .unwrap()
                .is_empty()
        );
        assert!(
            !encode_full_elements_statement_v2(&witness.full_elements_statement)
                .unwrap()
                .is_empty()
        );
        let mut bitcoin = witness.full_bitcoin_statement;
        bitcoin.version = ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2 + 1;
        assert_eq!(
            encode_full_bitcoin_statement_v2(&bitcoin),
            Err(EcxBtcConversionErrorV2::UnsupportedVersion)
        );
        let mut elements = witness.full_elements_statement;
        elements.version = 2;
        assert_eq!(
            encode_full_elements_statement_v2(&elements),
            Err(EcxBtcConversionErrorV2::UnsupportedVersion)
        );
    }

    #[test]
    fn reserve_rounds_up_instead_of_understating_liability() {
        assert_eq!(ceil_div(101, 100).unwrap(), 2);
        assert_eq!(ceil_div(100, 100).unwrap(), 1);
    }

    fn structurally_bounded_witness() -> EcxBtcConversionWitnessV2 {
        let header = vec![0; 80];
        let deployment_transaction = encode::serialize(&elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![],
        });
        let elements_configuration_preimage = vec![9, 1];
        EcxBtcConversionWitnessV2 {
            version: ECX_BTC_CONVERSION_WITNESS_VERSION_V2,
            source_checkpoint: EcxBtcSourceCheckpointV2 {
                version: ECX_BTC_CONVERSION_WITNESS_VERSION_V2,
                base_asset_id: [1; 32],
                policy_asset_id: [2; 32],
                quote_atoms_per_whole_base: 1,
                maximum_age_seconds: 1,
                required_parent_confirmations: 1,
                bitcoin_consensus_configuration_commitment: [2; 32],
                elements_consensus_configuration_commitment:
                    elements_consensus_configuration_commitment_v2(
                        &elements_configuration_preimage,
                    ),
                elements_consensus_configuration_preimage: elements_configuration_preimage,
                full_bitcoin_checkpoint_program_id: [3; 32],
                full_bitcoin_transition_program_id: [4; 32],
                full_bitcoin_validator_program_id: [5; 32],
                full_alpha_validator_program_id: [9; 32],
                full_alpha_child_validator_program_id: [10; 32],
                full_elements_checkpoint_program_id: [6; 32],
                full_elements_transition_program_id: [7; 32],
                full_elements_validator_program_id: [8; 32],
                parent: ParentHeaderCheckpointV2 {
                    header: header.clone(),
                    height: 1,
                    cumulative_work_be: [5; 32],
                    interval_start_time: 1,
                    mtp_context_headers: vec![header; BITCOIN_MTP_WINDOW],
                    complete_executed_checkpoint_preimage: vec![1],
                },
                bip300: ElementsSlot24CheckpointV2 {
                    processed_parent_height: 1,
                    parent_tip_hash_internal: [6; 32],
                    active_proposal_hash: None,
                    required_activation: None,
                    pending_proposals: vec![],
                    ctip: None,
                    pending_m6ids: vec![],
                    successful_m6ids: vec![],
                    previous_effective_m4: None,
                    accumulator_identity: None,
                    approved_root: None,
                    complete_all_slots_state_preimage: vec![1],
                },
                elements: ElementsStateCheckpointV2 {
                    height: 1,
                    block_hash_internal: [7; 32],
                    block_time: 1,
                    mtp_context_times: vec![1; BITCOIN_MTP_WINDOW],
                    state_root: [8; 32],
                    utxo_root: [9; 32],
                    complete_state_preimage: vec![1],
                },
            },
            covenant_deployment: EcxBtcCovenantDeploymentV2 {
                simplicity_program_bytes: vec![1],
                deployment_transaction,
                redemption_inventory_outpoint: OutPointV2 {
                    txid_internal: [10; 32],
                    vout: 0,
                },
                reserve_outpoint: OutPointV2 {
                    txid_internal: [11; 32],
                    vout: 0,
                },
            },
            parent_successor_blocks: vec![vec![1]],
            parent_bip300_m6_artifacts: vec![None],
            elements_material: EcxBtcElementsMaterialV2 {
                blocks: vec![vec![1]],
                predecessor_transactions: vec![],
                confidential_openings: vec![EcxBtcConfidentialOpeningV2 {
                    outpoint: OutPointV2 {
                        txid_internal: [12; 32],
                        vout: 0,
                    },
                    asset_id: [1; 32],
                    amount: 1,
                    asset_blinding_factor: [13; 32],
                    value_blinding_factor: [14; 32],
                    script_sha256: [15; 32],
                    role: 1,
                }],
            },
            full_bitcoin_statement: FullBitcoinStatementV2 {
                version: ECX_BTC_FULL_BITCOIN_STATEMENT_VERSION_V2,
                source_checkpoint_commitment: [1; 32],
                exact_parent_branch_commitment: [1; 32],
                parent_tip_hash_internal: [1; 32],
                parent_tip_height: 2,
                parent_tip_mtp: 1,
                cumulative_work_be: [1; 32],
                final_slot24_state_commitment: [1; 32],
                initial_all_slots_state_commitment: [2; 32],
                final_all_slots_state_commitment: [3; 32],
                final_executed_frontier_commitment: [4; 32],
                final_event_stream_commitment: [5; 32],
                final_event_sequence: 1,
                contextual_consensus_valid: true,
                selected_by_best_work: true,
                all_bip300_messages_preserved: true,
                confirmation_semantics_valid: true,
            },
            full_bitcoin_receipt: RecursiveReceiptReferenceV2 {
                proof_marker: vec![1],
            },
            full_alpha_statement: vec![0; FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3],
            full_alpha_receipt: RecursiveReceiptReferenceV2 {
                proof_marker: vec![1],
            },
            alpha_child_conversion_projection: vec![0; ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3],
            alpha_child_conversion_receipt: RecursiveReceiptReferenceV2 {
                proof_marker: vec![1],
            },
            full_elements_statement: FullElementsStatementV2 {
                version: 1,
                source_checkpoint_commitment: [1; 32],
                covenant_commitment: [1; 32],
                exact_material_commitment: [1; 32],
                bmm_edge_commitment: [1; 32],
                prior_state_root: [8; 32],
                prior_utxo_root: [9; 32],
                next_state_root: [16; 32],
                next_utxo_root: [17; 32],
                source_tip_hash_internal: [18; 32],
                source_tip_height: 2,
                source_tip_mtp: 1,
                base_asset_id: [1; 32],
                policy_asset_id: [2; 32],
                quote_atoms_per_whole_base: 1,
                outstanding_base_atoms: 1,
                redeemable_reserve_quote_atoms: 1,
                redemption_enabled: true,
                complete_utxo_replay_valid: true,
                confidential_openings_valid: true,
                asset_conservation_valid: true,
                simplicity_covenant_valid: true,
                issuance_and_reissuance_valid: true,
                pause_timelock_governance_valid: true,
                all_outputs_classified: true,
            },
            full_elements_receipt: RecursiveReceiptReferenceV2 {
                proof_marker: vec![1],
            },
        }
    }

    /// Alpha replaced LayerTwo Signet as the only parent chain. These are
    /// consensus-parameter guards: if the proof-of-work limit ever silently
    /// reverts to Signet's, the relation would accept a far weaker parent
    /// chain, so this must fail loudly rather than drift.
    #[test]
    fn alpha_pow_limit_is_derived_from_compact_bits_1d00ffff() {
        // 0x1d00ffff decodes as mantissa 0x00ffff scaled by 256^(0x1d - 3),
        // i.e. 0xFFFF << 208. Rebuild it independently of the constant.
        let mut expected = [0u8; 32];
        expected[4] = 0xFF;
        expected[5] = 0xFF;
        assert_eq!(ALPHA_POW_LIMIT_BE_V3, expected);
        assert_eq!(
            alpha_pow_parameters_v3().pow_limit,
            Uint256::from_be_bytes(expected)
        );
    }

    #[test]
    fn alpha_parameters_are_not_signet_parameters() {
        let alpha = alpha_pow_parameters_v3();
        let signet = PowParameters::LAYER_TWO_SIGNET;

        // The single intended divergence.
        assert_ne!(alpha.pow_limit, signet.pow_limit);
        // Signet's limit is numerically larger, i.e. easier. Alpha must be
        // the stricter of the two.
        assert!(alpha.pow_limit < signet.pow_limit);

        // Everything else is shared with Signet and with Bitcoin mainnet.
        assert_eq!(alpha.target_timespan, signet.target_timespan);
        assert_eq!(alpha.target_spacing, signet.target_spacing);
        assert!(!alpha.allow_min_difficulty_blocks);
        assert!(!alpha.no_retargeting);
    }

    #[test]
    fn alpha_parameters_match_the_validator_crate_profile() {
        // These mirror ecx_full_consensus_validator_v2::alpha_pow_v3. The two
        // definitions are compiled separately, so drift between them would
        // otherwise be invisible until a proof failed.
        assert_eq!(ALPHA_TARGET_TIMESPAN_V3, 14 * 24 * 60 * 60);
        assert_eq!(ALPHA_TARGET_SPACING_V3, 10 * 60);
        assert_eq!(
            alpha_pow_parameters_v3().target_timespan / alpha_pow_parameters_v3().target_spacing,
            2_016
        );
    }

    #[test]
    fn alpha_header_slice_rejects_blocks_too_short_to_carry_a_header() {
        // The witness fixture used elsewhere in these tests supplies a
        // one-byte parent block; the relation must reject it at the header
        // boundary rather than indexing past the end.
        for truncated in [vec![], vec![0u8; 1], vec![0u8; 79]] {
            assert!(matches!(
                alpha_header_slice(&truncated),
                Err(EcxBtcConversionErrorV2::InvalidParentHistory)
            ));
        }
    }

    #[test]
    fn alpha_header_slice_takes_exactly_the_first_80_bytes() {
        // A block header is 80 fixed-width bytes followed by transaction data.
        // Confirm the split takes the header and nothing after it.
        let header: Vec<u8> = (0u8..80).collect();
        let mut block = header.clone();
        block.extend_from_slice(&[0xAB; 137]);
        let taken = alpha_header_slice(&block).expect("valid 80-byte header prefix");
        assert_eq!(taken.len(), 80);
        assert_eq!(taken, &header[..]);
    }
}
