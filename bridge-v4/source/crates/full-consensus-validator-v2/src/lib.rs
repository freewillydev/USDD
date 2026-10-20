//! Isolated primitives for the missing recursive full-consensus validators.
//!
//! This crate is deliberately not a conversion guest or release identity.  It
//! becomes eligible for integration only after the complete relations in
//! `docs/FULL_CONSENSUS_VALIDATORS_V2.md` exist and pass differential tests.

pub mod alpha_pow_v3;
pub mod alpha_state_v3;
pub mod alpha_deposit_v3;
pub mod bip300_v2;
pub mod bmm_v2;
pub mod checkpoint_alpha_v3;
pub mod checkpoint_bitcoin_v2;
#[cfg(feature = "full-elements")]
pub mod checkpoint_elements_v2;
pub mod elements_v2;
pub mod alpha_simplicity_receipt_v3;
pub mod elements_wire_v2;
pub mod elements_sighash_v3;
#[cfg(feature = "full-elements")]
pub mod full_elements_v2;
#[cfg(feature = "full-elements")]
pub mod transition_elements_v2;
pub mod patched_elements_v2;
pub mod recursive_bitcoin_v2;
pub mod recursive_alpha_v3;
pub mod script_v2;
pub mod state_frontier_v2;
pub mod compact_utxo_paths;
pub mod compact_utxo_frame;
#[cfg(target_os = "zkvm")]
mod sha256_sp1_v6;

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{Block, BlockHash, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub type Hash32 = [u8; 32];

pub const SPARSE_UTXO_DEPTH_V2: usize = 256;
pub const MAX_UTXO_MUTATIONS_PER_SEGMENT_V2: usize = 131_072;
pub const BITCOIN_MAX_BLOCK_WEIGHT_V2: u64 = 4_000_000;
pub const BITCOIN_MAX_FUTURE_BLOCK_SECONDS_V2: u64 = 2 * 60 * 60;
pub const BITCOIN_COINBASE_MATURITY_V2: u32 = 100;
pub const BITCOIN_MAX_MONEY_ATOMS_V2: u64 = 21_000_000 * 100_000_000;
pub const MAX_HEADER_DISCOVERIES_PER_SEGMENT_V2: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Alpha parent header context.
///
/// There is deliberately no `network` field. Alpha is the only parent chain,
/// so a witness cannot select Signet, regtest, testnet, or stock Bitcoin, and
/// there is no min-difficulty test-chain exception to carry state for.
pub struct BitcoinPowContextV2 {
    pub previous_height: u32,
    pub previous_header: Header,
    /// Previous ten headers followed by `previous_header.time`. Exactly eleven
    /// values are required outside the genesis bootstrap relation.
    pub previous_11_times: Vec<u32>,
    pub retarget_epoch_start_time: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinBlockFoundationV2 {
    pub block_hash: BlockHash,
    pub header: Header,
    pub transaction_count: usize,
    pub weight: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinChainTipV2 {
    pub block_hash: BlockHash,
    pub height: u32,
    /// Bitcoin Core-compatible unsigned 256-bit chainwork, big endian.
    pub chainwork_be: Hash32,
    /// Authenticated first-observation order. Equal-work ties retain the
    /// earliest eligible incumbent, matching active-chain behavior.
    pub discovery_sequence: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinTipFrontierNodeV2 {
    pub hash: Hash32,
    pub count: u128,
    pub best: Option<BitcoinChainTipV2>,
    pub maximum_discovery_sequence: Option<u128>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinTipFrontierPathV2 {
    /// Leaf-to-root siblings. Exactly 256 entries are canonical.
    pub siblings: Vec<BitcoinTipFrontierNodeV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinTipFrontierMutationV2 {
    pub candidate: BitcoinChainTipV2,
    pub insert: bool,
    pub path: BitcoinTipFrontierPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedHeaderDiscoveryV2 {
    pub parent: BitcoinChainTipV2,
    pub parent_path: BitcoinTipFrontierPathV2,
    pub pow_context: BitcoinPowContextV2,
    pub header: Header,
    pub authenticated_adjusted_time: u64,
    pub successor_path: BitcoinTipFrontierPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinHeaderDiscoveryBatchV2 {
    pub version: u8,
    pub source_sequence_start: u128,
    pub discoveries: Vec<AuthenticatedHeaderDiscoveryV2>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoAggregateV2 {
    pub count: u128,
    pub value_atoms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SparseUtxoNodeV2 {
    pub hash: Hash32,
    pub aggregate: UtxoAggregateV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinUtxoLeafV2 {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub creation_height: u32,
    /// Median time past of the block immediately preceding the block that
    /// created this output. BIP68 time locks are measured from this value.
    pub creation_parent_mtp: u32,
    pub coinbase: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinBlockSpendContextV2 {
    pub height: u32,
    /// MTP of the candidate block's parent, as required by BIP113/BIP68.
    pub previous_block_mtp: u32,
    pub bip34_active: bool,
    pub bip68_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SparseUtxoPathV2 {
    /// Leaf-to-root siblings. Exactly 256 entries are canonical.
    pub siblings: Vec<SparseUtxoNodeV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SparseUtxoMutationV2 {
    pub outpoint: OutPoint,
    pub old_leaf: Option<BitcoinUtxoLeafV2>,
    pub new_leaf: Option<BitcoinUtxoLeafV2>,
    pub path: SparseUtxoPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinTransactionUtxoWitnessV2 {
    /// Exact input order. Empty only for coinbase.
    pub spends: Vec<SparseUtxoMutationV2>,
    /// Exact output order.
    pub creates: Vec<SparseUtxoMutationV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinBlockUtxoWitnessV2 {
    /// One entry per block transaction in exact order.
    pub transactions: Vec<BitcoinTransactionUtxoWitnessV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinBlockUtxoResultV2 {
    pub next_root: SparseUtxoNodeV2,
    pub total_fees_atoms: u128,
    pub allowed_subsidy_atoms: u64,
    pub claimed_coinbase_atoms: u128,
}

/// Mandatory consensus Script boundary. There is intentionally no permissive
/// implementation. `previous_outputs` contains every input's authenticated
/// prior output in transaction order, which is required for Taproot sighashes.
pub trait BitcoinScriptVerifierV2 {
    fn verify_input(
        &self,
        transaction: &bitcoin::Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
        active_script_flags: u32,
    ) -> Result<(), FullValidatorPrimitiveErrorV2>;
}

/// Concrete Bitcoin Script verifier used by the full block relation. Every
/// spend is evaluated against the authenticated previous-output vector; there
/// is no success stub or network RPC boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct FullBitcoinScriptVerifierV2;

impl BitcoinScriptVerifierV2 for FullBitcoinScriptVerifierV2 {
    fn verify_input(
        &self,
        transaction: &bitcoin::Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
        active_script_flags: u32,
    ) -> Result<(), FullValidatorPrimitiveErrorV2> {
        verify_bitcoin_script_input_with_dialect(transaction, input_index, previous_outputs, active_script_flags, false)
    }
}

pub(crate) fn verify_bitcoin_script_input_with_dialect(
    transaction: &bitcoin::Transaction,
    input_index: usize,
    previous_outputs: &[TxOut],
    active_script_flags: u32,
    alpha_drivechain: bool,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
        use script_v2::*;

        let input = transaction
            .input
            .get(input_index)
            .ok_or(FullValidatorPrimitiveErrorV2::ScriptConsensus)?;
        if active_script_flags & SCRIPT_VERIFY_SIGPUSHONLY_V2 != 0
            && !script_is_push_only_v2(input.script_sig.as_bytes())
                .map_err(|_| FullValidatorPrimitiveErrorV2::ScriptConsensus)?
        {
            return Err(FullValidatorPrimitiveErrorV2::ScriptConsensus);
        }
        let checker = LegacyEcdsaCheckerV2::new(
            transaction,
            input_index,
            active_script_flags
                & (SCRIPT_VERIFY_DERSIG_V2 | SCRIPT_VERIFY_LOW_S_V2 | SCRIPT_VERIFY_STRICTENC_V2)
                != 0,
            active_script_flags & SCRIPT_VERIFY_STRICTENC_V2 != 0,
            active_script_flags & SCRIPT_VERIFY_LOW_S_V2 != 0,
            active_script_flags & SCRIPT_VERIFY_CONST_SCRIPTCODE_V2 != 0,
        );
        verify_script_input_v2(
            transaction,
            input_index,
            previous_outputs,
            ScriptLockContextV2 {
                alpha_drivechain,
                transaction_version: transaction.version.0 as u32,
                transaction_lock_time: transaction.lock_time.to_consensus_u32(),
                input_sequence: input.sequence.to_consensus_u32(),
                check_lock_time_verify: active_script_flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2
                    != 0,
                check_sequence_verify: active_script_flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2
                    != 0,
                null_fail: active_script_flags & SCRIPT_VERIFY_NULLFAIL_V2 != 0,
                null_dummy: active_script_flags & SCRIPT_VERIFY_NULLDUMMY_V2 != 0,
                discourage_upgradable_nops: active_script_flags
                    & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS_V2
                    != 0,
                const_script_code: active_script_flags & SCRIPT_VERIFY_CONST_SCRIPTCODE_V2 != 0,
                witness_v0: false,
            },
            &checker,
            LegacyScriptFlagsV2 {
                require_minimal_push: active_script_flags & SCRIPT_VERIFY_MINIMALDATA_V2 != 0,
                require_minimal_if: active_script_flags & SCRIPT_VERIFY_MINIMALIF_V2 != 0,
                verify_p2sh: active_script_flags & SCRIPT_VERIFY_P2SH_V2 != 0,
                clean_stack: active_script_flags & SCRIPT_VERIFY_CLEANSTACK_V2 != 0,
                verify_witness: active_script_flags & SCRIPT_VERIFY_WITNESS_V2 != 0,
                verify_taproot: active_script_flags & SCRIPT_VERIFY_TAPROOT_V2 != 0,
                witness_pubkey_type: active_script_flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE_V2 != 0,
                discourage_upgradable_witness_program: active_script_flags
                    & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_V2
                    != 0,
                strict_der: active_script_flags
                    & (SCRIPT_VERIFY_DERSIG_V2
                        | SCRIPT_VERIFY_LOW_S_V2
                        | SCRIPT_VERIFY_STRICTENC_V2)
                    != 0,
                strict_encoding: active_script_flags & SCRIPT_VERIFY_STRICTENC_V2 != 0,
                low_s: active_script_flags & SCRIPT_VERIFY_LOW_S_V2 != 0,
            },
        )
        .map_err(|_| FullValidatorPrimitiveErrorV2::ScriptConsensus)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullValidatorPrimitiveErrorV2 {
    #[error("noncanonical sparse UTXO path")]
    NonCanonicalPath,
    #[error("UTXO leaf does not match its indexed outpoint")]
    OutpointMismatch,
    #[error("UTXO mutation must be exactly one insertion or deletion")]
    InvalidMutation,
    #[error("authenticated sparse root mismatch")]
    RootMismatch,
    #[error("UTXO aggregate overflow or underflow")]
    AggregateOverflow,
    #[error("too many UTXO mutations in one recursive segment")]
    ResourceLimit,
    #[error("noncanonical or trailing Bitcoin block bytes")]
    NonCanonicalBlock,
    #[error("Bitcoin block exceeds the active weight limit")]
    BlockWeight,
    #[error("Bitcoin header does not extend the authenticated tip")]
    HeaderLink,
    #[error("Bitcoin target or proof of work is invalid")]
    ProofOfWork,
    #[error("Bitcoin difficulty context or retarget result is invalid")]
    DifficultyContext,
    #[error("Bitcoin median-time-past or future-time rule failed")]
    HeaderTime,
    #[error("Bitcoin transaction Merkle or witness commitment is invalid")]
    BlockCommitment,
    #[error("Bitcoin block coinbase structure is invalid")]
    CoinbaseStructure,
    #[error("Bitcoin coinbase does not commit the active BIP34 height")]
    CoinbaseHeight,
    #[error("Bitcoin block contains a duplicate transaction ID")]
    DuplicateTransaction,
    #[error("Bitcoin transaction UTXO witness does not match the block")]
    TransactionWitness,
    #[error("Bitcoin input spends an immature coinbase")]
    CoinbaseMaturity,
    #[error("Bitcoin transaction absolute lock time is not final")]
    AbsoluteLockTime,
    #[error("Bitcoin transaction relative sequence locks are not satisfied")]
    RelativeLockTime,
    #[error("Bitcoin transaction value, fee, subsidy or money range is invalid")]
    MonetaryConsensus,
    #[error("Bitcoin consensus Script rejected an input")]
    ScriptConsensus,
    #[error("Bitcoin cumulative-work or competing-tip relation is invalid")]
    Chainwork,
    #[error("authenticated header discovery batch is malformed or mismatched")]
    HeaderDiscoveryBatch,
    #[error("executed branch consensus-state preimage is malformed or inconsistent")]
    ExecutedState,
}

fn tagged_hash(tag: &str, payload: &[u8]) -> Hash32 {
    let tag_hash = sha256_bytes(tag.as_bytes());
    let mut preimage = Vec::with_capacity(64 + payload.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(payload);
    sha256_bytes(&preimage)
}

pub fn sha256_bytes(payload: &[u8]) -> Hash32 {
    #[cfg(target_os = "zkvm")]
    { sha256_sp1_v6::hash(payload) }
    #[cfg(not(target_os = "zkvm"))]
    { sha256::Hash::hash(payload).to_byte_array() }
}

pub fn sparse_utxo_key_v2(outpoint: OutPoint) -> Hash32 {
    tagged_hash("ECX/full-bitcoin-utxo-key/v2", &serialize(&outpoint))
}

pub fn canonical_empty_utxo_leaf_v2() -> SparseUtxoNodeV2 {
    SparseUtxoNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-utxo-empty-leaf/v2", &[]),
        aggregate: UtxoAggregateV2::default(),
    }
}

pub fn bitcoin_utxo_leaf_node_v2(
    leaf: &BitcoinUtxoLeafV2,
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    let mut payload = serialize(&leaf.outpoint);
    payload.extend_from_slice(&serialize(&leaf.output));
    payload.extend_from_slice(&leaf.creation_height.to_be_bytes());
    payload.extend_from_slice(&leaf.creation_parent_mtp.to_be_bytes());
    payload.push(u8::from(leaf.coinbase));
    Ok(SparseUtxoNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-utxo-leaf/v2", &payload),
        aggregate: UtxoAggregateV2 {
            count: 1,
            value_atoms: u128::from(leaf.output.value.to_sat()),
        },
    })
}

// SHA256 of the fixed protocol tag; independently checked against the text in tests.
const UTXO_NODE_TAG_HASH: Hash32 = [
    0xe9, 0x09, 0x87, 0xe0, 0x75, 0x09, 0x30, 0x9c,
    0xd9, 0x1a, 0xf8, 0xd1, 0x6c, 0x1f, 0xc1, 0xc4,
    0x1e, 0xef, 0x43, 0xc3, 0x47, 0xad, 0x25, 0xc3,
    0x3b, 0x9c, 0x46, 0x38, 0x5a, 0xae, 0x3c, 0xdd,
];

pub fn sparse_utxo_parent_v2(
    left: SparseUtxoNodeV2,
    right: SparseUtxoNodeV2,
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    let aggregate = UtxoAggregateV2 {
        count: left
            .aggregate
            .count
            .checked_add(right.aggregate.count)
            .ok_or(FullValidatorPrimitiveErrorV2::AggregateOverflow)?,
        value_atoms: left
            .aggregate
            .value_atoms
            .checked_add(right.aggregate.value_atoms)
            .ok_or(FullValidatorPrimitiveErrorV2::AggregateOverflow)?,
    };
    // Exact legacy tagged-hash preimage, without two allocations or recomputing
    // the same tag for every tree fold. Aggregate overflow remains checked above.
    let mut preimage = [0u8; 160];
    preimage[..32].copy_from_slice(&UTXO_NODE_TAG_HASH);
    preimage[32..64].copy_from_slice(&UTXO_NODE_TAG_HASH);
    preimage[64..96].copy_from_slice(&left.hash);
    preimage[96..128].copy_from_slice(&right.hash);
    preimage[128..144].copy_from_slice(&aggregate.count.to_be_bytes());
    preimage[144..160].copy_from_slice(&aggregate.value_atoms.to_be_bytes());
    Ok(SparseUtxoNodeV2 {
        hash: sha256_bytes(&preimage),
        aggregate,
    })
}

fn key_bit_from_leaf_level(key: Hash32, leaf_level: usize) -> bool {
    let root_bit = SPARSE_UTXO_DEPTH_V2 - 1 - leaf_level;
    let byte = root_bit / 8;
    let bit_in_byte = 7 - (root_bit % 8);
    (key[byte] >> bit_in_byte) & 1 == 1
}

pub fn sparse_utxo_root_from_path_v2(
    outpoint: OutPoint,
    leaf: SparseUtxoNodeV2,
    path: &SparseUtxoPathV2,
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    if path.siblings.len() != SPARSE_UTXO_DEPTH_V2 {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath);
    }
    let key = sparse_utxo_key_v2(outpoint);
    path.siblings
        .iter()
        .copied()
        .enumerate()
        .try_fold(leaf, |current, (level, sibling)| {
            if key_bit_from_leaf_level(key, level) {
                sparse_utxo_parent_v2(sibling, current)
            } else {
                sparse_utxo_parent_v2(current, sibling)
            }
        })
}

pub fn apply_sparse_utxo_mutation_v2(
    current_root: SparseUtxoNodeV2,
    mutation: &SparseUtxoMutationV2,
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    apply_sparse_utxo_mutation_observed_v2(current_root, mutation, |_, _, _| {})
}

/// Observations are provisional until this function succeeds. Consumers must
/// not publish/cache them before both authenticated folds have completed.
pub(crate) fn apply_sparse_utxo_mutation_observed_v2(
    current_root: SparseUtxoNodeV2,
    mutation: &SparseUtxoMutationV2,
    mut observe: impl FnMut(bool, usize, SparseUtxoNodeV2),
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    let (old_node, new_node) = match (&mutation.old_leaf, &mutation.new_leaf) {
        (None, Some(new_leaf)) => {
            if new_leaf.outpoint != mutation.outpoint {
                return Err(FullValidatorPrimitiveErrorV2::OutpointMismatch);
            }
            (
                canonical_empty_utxo_leaf_v2(),
                bitcoin_utxo_leaf_node_v2(new_leaf)?,
            )
        }
        (Some(old_leaf), None) => {
            if old_leaf.outpoint != mutation.outpoint {
                return Err(FullValidatorPrimitiveErrorV2::OutpointMismatch);
            }
            (
                bitcoin_utxo_leaf_node_v2(old_leaf)?,
                canonical_empty_utxo_leaf_v2(),
            )
        }
        _ => return Err(FullValidatorPrimitiveErrorV2::InvalidMutation),
    };
    if mutation.path.siblings.len() != SPARSE_UTXO_DEPTH_V2 {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath);
    }
    let key = sparse_utxo_key_v2(mutation.outpoint);
    let mut fold = |is_new, mut node| {
        for (level, &sibling) in mutation.path.siblings.iter().enumerate() {
            observe(is_new, level, node);
            node = if key_bit_from_leaf_level(key, level) {
                sparse_utxo_parent_v2(sibling, node)?
            } else {
                sparse_utxo_parent_v2(node, sibling)?
            };
        }
        Ok::<_, FullValidatorPrimitiveErrorV2>(node)
    };
    if fold(false, old_node)? != current_root {
        return Err(FullValidatorPrimitiveErrorV2::RootMismatch);
    }
    fold(true, new_node)
}

pub fn apply_sparse_utxo_segment_v2(
    initial_root: SparseUtxoNodeV2,
    mutations: &[SparseUtxoMutationV2],
) -> Result<SparseUtxoNodeV2, FullValidatorPrimitiveErrorV2> {
    if mutations.len() > MAX_UTXO_MUTATIONS_PER_SEGMENT_V2 {
        return Err(FullValidatorPrimitiveErrorV2::ResourceLimit);
    }
    mutations.iter().try_fold(initial_root, |root, mutation| {
        apply_sparse_utxo_mutation_v2(root, mutation)
    })
}

/// Verify the context-independent block foundation plus the exact authenticated
/// predecessor and target selected by the recursive contextual state.
///
/// This intentionally does not claim transaction/script/UTXO validity, target
/// retarget derivation, BIP300 replay, MTP or
/// best-work selection. Those are separate mandatory kernels in the full
/// relation; callers must not emit `FullBitcoinStatementV2` from this result.
pub fn verify_bitcoin_block_foundation_v2(
    raw_block: &[u8],
    expected_previous_block: BlockHash,
    required_target: Target,
    maximum_weight: u64,
) -> Result<VerifiedBitcoinBlockFoundationV2, FullValidatorPrimitiveErrorV2> {
    let block: Block =
        deserialize(raw_block).map_err(|_| FullValidatorPrimitiveErrorV2::NonCanonicalBlock)?;
    if serialize(&block) != raw_block {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalBlock);
    }
    let weight = block.weight().to_wu();
    if maximum_weight == 0
        || maximum_weight > BITCOIN_MAX_BLOCK_WEIGHT_V2
        || weight > maximum_weight
    {
        return Err(FullValidatorPrimitiveErrorV2::BlockWeight);
    }
    if block.header.prev_blockhash != expected_previous_block {
        return Err(FullValidatorPrimitiveErrorV2::HeaderLink);
    }
    if !block.check_merkle_root() || !block.check_witness_commitment() {
        return Err(FullValidatorPrimitiveErrorV2::BlockCommitment);
    }
    let Some((coinbase, rest)) = block.txdata.split_first() else {
        return Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure);
    };
    if !coinbase.is_coinbase() || rest.iter().any(bitcoin::Transaction::is_coinbase) {
        return Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure);
    }
    let mut transaction_ids = HashSet::with_capacity(block.txdata.len());
    if block
        .txdata
        .iter()
        .any(|transaction| !transaction_ids.insert(transaction.compute_txid()))
    {
        return Err(FullValidatorPrimitiveErrorV2::DuplicateTransaction);
    }
    let block_hash = block
        .header
        .validate_pow(required_target)
        .map_err(|_| FullValidatorPrimitiveErrorV2::ProofOfWork)?;
    Ok(VerifiedBitcoinBlockFoundationV2 {
        block_hash,
        header: block.header,
        transaction_count: block.txdata.len(),
        weight,
    })
}

pub fn median_time_past_v2(times: &[u32]) -> Result<u32, FullValidatorPrimitiveErrorV2> {
    if times.len() != 11 {
        return Err(FullValidatorPrimitiveErrorV2::DifficultyContext);
    }
    let mut ordered = <[u32; 11]>::try_from(times)
        .map_err(|_| FullValidatorPrimitiveErrorV2::DifficultyContext)?;
    ordered.sort_unstable();
    Ok(ordered[5])
}





pub fn expected_next_target_v2(
    context: &BitcoinPowContextV2,
    next_time: u32,
) -> Result<CompactTarget, FullValidatorPrimitiveErrorV2> {
    if context.previous_11_times.len() != 11
        || context.previous_11_times[10] != context.previous_header.time
    {
        return Err(FullValidatorPrimitiveErrorV2::DifficultyContext);
    }
    // Alpha rules. Retargeting is always enabled and there is no
    // min-difficulty exception, so both of those Bitcoin test-chain branches
    // are gone rather than made unreachable. `next_time` is consequently
    // unused: it only ever fed the min-difficulty exception.
    let _ = next_time;
    let next_height = context
        .previous_height
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::DifficultyContext)?;
    if next_height == crate::alpha_pow_v3::ALPHA_FORK_HEIGHT_V3 {
        return Ok(CompactTarget::from_consensus(
            crate::alpha_pow_v3::ALPHA_POW_LIMIT_BITS_V3,
        ));
    }
    if next_height.is_multiple_of(crate::alpha_pow_v3::ALPHA_RETARGET_INTERVAL_V3) {
        let timespan = context
            .previous_header
            .time
            .saturating_sub(context.retarget_epoch_start_time);
        return Ok(CompactTarget::from_next_work_required(
            context.previous_header.bits,
            u64::from(timespan),
            bitcoin::consensus::Params::MAINNET,
        ));
    }
    Ok(context.previous_header.bits)
}

pub fn verify_next_header_context_v2(
    context: &BitcoinPowContextV2,
    next_header: Header,
    authenticated_adjusted_time: u64,
) -> Result<CompactTarget, FullValidatorPrimitiveErrorV2> {
    verify_next_header_context_inner_v2(context, next_header, authenticated_adjusted_time)
}

fn verify_next_header_context_inner_v2(
    context: &BitcoinPowContextV2,
    next_header: Header,
    authenticated_adjusted_time: u64,
) -> Result<CompactTarget, FullValidatorPrimitiveErrorV2> {
    if next_header.prev_blockhash != context.previous_header.block_hash() {
        return Err(FullValidatorPrimitiveErrorV2::HeaderLink);
    }
    let median = median_time_past_v2(&context.previous_11_times)?;
    let future_limit = authenticated_adjusted_time
        .checked_add(BITCOIN_MAX_FUTURE_BLOCK_SECONDS_V2)
        .ok_or(FullValidatorPrimitiveErrorV2::HeaderTime)?;
    if next_header.time <= median || u64::from(next_header.time) > future_limit {
        return Err(FullValidatorPrimitiveErrorV2::HeaderTime);
    }
    let expected = expected_next_target_v2(context, next_header.time)?;
    if next_header.bits != expected {
        return Err(FullValidatorPrimitiveErrorV2::ProofOfWork);
    }
    next_header
        .validate_pow(Target::from(expected))
        .map_err(|_| FullValidatorPrimitiveErrorV2::ProofOfWork)?;
    Ok(expected)
}


pub fn successor_chainwork_v2(previous_chainwork_be: Hash32, target: Target) -> Hash32 {
    let work = target.to_work().to_be_bytes();
    let mut result = previous_chainwork_be;
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = u16::from(result[index]) + u16::from(work[index]) + carry;
        result[index] = sum as u8;
        carry = sum >> 8;
    }
    // Bitcoin Core's arith_uint256 chainwork arithmetic is modulo 2^256.
    result
}

pub fn derive_successor_tip_v2(
    previous: BitcoinChainTipV2,
    header: &Header,
    discovery_sequence: u128,
) -> Result<BitcoinChainTipV2, FullValidatorPrimitiveErrorV2> {
    if header.prev_blockhash != previous.block_hash {
        return Err(FullValidatorPrimitiveErrorV2::HeaderLink);
    }
    Ok(BitcoinChainTipV2 {
        block_hash: header.block_hash(),
        height: previous
            .height
            .checked_add(1)
            .ok_or(FullValidatorPrimitiveErrorV2::Chainwork)?,
        chainwork_be: successor_chainwork_v2(previous.chainwork_be, header.target()),
        discovery_sequence,
    })
}

/// Selects the greatest-work header tip from an authenticated complete header
/// frontier. This does not establish block, transaction, UTXO, Script or
/// BIP300 validity and therefore must not set a full-validator
/// `selected_by_best_work` flag. The recursive release relation needs a
/// separate stateful frontier whose leaves commit those executed states.
pub fn select_best_bitcoin_tip_v2(
    authenticated_frontier: &[BitcoinChainTipV2],
) -> Result<BitcoinChainTipV2, FullValidatorPrimitiveErrorV2> {
    let Some(first) = authenticated_frontier.first().copied() else {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    };
    let mut hashes = HashSet::with_capacity(authenticated_frontier.len());
    let mut sequences = HashSet::with_capacity(authenticated_frontier.len());
    let mut best = first;
    for candidate in authenticated_frontier {
        if !hashes.insert(candidate.block_hash)
            || !sequences.insert(candidate.discovery_sequence)
            || candidate.block_hash == BlockHash::all_zeros()
        {
            return Err(FullValidatorPrimitiveErrorV2::Chainwork);
        }
        if candidate.chainwork_be > best.chainwork_be
            || (candidate.chainwork_be == best.chainwork_be
                && candidate.discovery_sequence < best.discovery_sequence)
        {
            best = *candidate;
        }
    }
    Ok(best)
}

fn better_tip_v2(left: BitcoinChainTipV2, right: BitcoinChainTipV2) -> BitcoinChainTipV2 {
    if right.chainwork_be > left.chainwork_be
        || (right.chainwork_be == left.chainwork_be
            && (right.discovery_sequence < left.discovery_sequence
                || (right.discovery_sequence == left.discovery_sequence
                    && right.block_hash.to_byte_array() < left.block_hash.to_byte_array())))
    {
        right
    } else {
        left
    }
}

fn encode_tip_v2(tip: BitcoinChainTipV2, output: &mut Vec<u8>) {
    output.extend_from_slice(&tip.block_hash.to_byte_array());
    output.extend_from_slice(&tip.height.to_le_bytes());
    output.extend_from_slice(&tip.chainwork_be);
    output.extend_from_slice(&tip.discovery_sequence.to_le_bytes());
}

fn canonical_empty_tip_leaf_v2() -> BitcoinTipFrontierNodeV2 {
    BitcoinTipFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-tip-empty-leaf/v2", &[]),
        count: 0,
        best: None,
        maximum_discovery_sequence: None,
    }
}

fn present_tip_leaf_v2(candidate: BitcoinChainTipV2) -> BitcoinTipFrontierNodeV2 {
    let mut payload = Vec::with_capacity(84);
    encode_tip_v2(candidate, &mut payload);
    BitcoinTipFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-tip-leaf/v2", &payload),
        count: 1,
        best: Some(candidate),
        maximum_discovery_sequence: Some(candidate.discovery_sequence),
    }
}

fn combine_tip_frontier_nodes_v2(
    left: BitcoinTipFrontierNodeV2,
    right: BitcoinTipFrontierNodeV2,
) -> Result<BitcoinTipFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
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
        (Some(left), Some(right)) => Some(better_tip_v2(left, right)),
        (Some(tip), None) | (None, Some(tip)) => Some(tip),
        (None, None) => None,
    };
    let maximum_discovery_sequence = match (
        left.maximum_discovery_sequence,
        right.maximum_discovery_sequence,
    ) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(sequence), None) | (None, Some(sequence)) => Some(sequence),
        (None, None) => None,
    };
    let mut payload = Vec::with_capacity(259);
    payload.extend_from_slice(&left.hash);
    payload.extend_from_slice(&left.count.to_le_bytes());
    if let Some(tip) = left.best {
        payload.push(1);
        encode_tip_v2(tip, &mut payload);
    } else {
        payload.push(0);
    }
    if let Some(sequence) = left.maximum_discovery_sequence {
        payload.push(1);
        payload.extend_from_slice(&sequence.to_le_bytes());
    } else {
        payload.push(0);
    }
    payload.extend_from_slice(&right.hash);
    payload.extend_from_slice(&right.count.to_le_bytes());
    if let Some(tip) = right.best {
        payload.push(1);
        encode_tip_v2(tip, &mut payload);
    } else {
        payload.push(0);
    }
    if let Some(sequence) = right.maximum_discovery_sequence {
        payload.push(1);
        payload.extend_from_slice(&sequence.to_le_bytes());
    } else {
        payload.push(0);
    }
    Ok(BitcoinTipFrontierNodeV2 {
        hash: tagged_hash("ECX/full-bitcoin-tip-node/v2", &payload),
        count,
        best,
        maximum_discovery_sequence,
    })
}

pub fn canonical_empty_tip_frontier_root_v2() -> BitcoinTipFrontierNodeV2 {
    let mut node = canonical_empty_tip_leaf_v2();
    for _ in 0..SPARSE_UTXO_DEPTH_V2 {
        node = combine_tip_frontier_nodes_v2(node, node)
            .expect("canonical empty tip frontier cannot overflow");
    }
    node
}

fn tip_frontier_root_from_path_v2(
    candidate: BitcoinChainTipV2,
    leaf: BitcoinTipFrontierNodeV2,
    path: &BitcoinTipFrontierPathV2,
) -> Result<BitcoinTipFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    if path.siblings.len() != SPARSE_UTXO_DEPTH_V2 {
        return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath);
    }
    let key = candidate.block_hash.to_byte_array();
    let mut node = leaf;
    for (depth, sibling) in path.siblings.iter().enumerate() {
        let byte = key[31 - depth / 8];
        let bit = (byte >> (depth % 8)) & 1;
        node = if bit == 0 {
            combine_tip_frontier_nodes_v2(node, *sibling)?
        } else {
            combine_tip_frontier_nodes_v2(*sibling, node)?
        };
    }
    Ok(node)
}

pub fn apply_tip_frontier_mutation_v2(
    current_root: BitcoinTipFrontierNodeV2,
    mutation: &BitcoinTipFrontierMutationV2,
) -> Result<BitcoinTipFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    if mutation.candidate.block_hash == BlockHash::all_zeros() {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    }
    let empty = canonical_empty_tip_leaf_v2();
    let present = present_tip_leaf_v2(mutation.candidate);
    let old_leaf = if mutation.insert { empty } else { present };
    let new_leaf = if mutation.insert { present } else { empty };
    let derived_old = tip_frontier_root_from_path_v2(mutation.candidate, old_leaf, &mutation.path)?;
    if derived_old != current_root {
        return Err(FullValidatorPrimitiveErrorV2::RootMismatch);
    }
    tip_frontier_root_from_path_v2(mutation.candidate, new_leaf, &mutation.path)
}

pub fn verify_tip_frontier_membership_v2(
    root: BitcoinTipFrontierNodeV2,
    candidate: BitcoinChainTipV2,
    path: &BitcoinTipFrontierPathV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    let derived = tip_frontier_root_from_path_v2(candidate, present_tip_leaf_v2(candidate), path)?;
    if derived != root {
        return Err(FullValidatorPrimitiveErrorV2::RootMismatch);
    }
    Ok(())
}

/// Extends an authenticated header branch and inserts the exact successor into
/// the persistent header frontier. Header contextual validity (target, MTP and
/// deployments) must be checked before this call. This API does not bind a
/// block body, UTXO state or BIP300 state and is not
/// an all-valid-block frontier.
pub fn apply_authenticated_header_discovery_v2(
    current_root: BitcoinTipFrontierNodeV2,
    parent: BitcoinChainTipV2,
    parent_path: &BitcoinTipFrontierPathV2,
    header: &Header,
    successor_path: BitcoinTipFrontierPathV2,
) -> Result<(BitcoinTipFrontierNodeV2, BitcoinChainTipV2), FullValidatorPrimitiveErrorV2> {
    verify_tip_frontier_membership_v2(current_root, parent, parent_path)?;
    let discovery_sequence = current_root
        .maximum_discovery_sequence
        .ok_or(FullValidatorPrimitiveErrorV2::Chainwork)?
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::Chainwork)?;
    let successor = derive_successor_tip_v2(parent, header, discovery_sequence)?;
    let next_root = apply_tip_frontier_mutation_v2(
        current_root,
        &BitcoinTipFrontierMutationV2 {
            candidate: successor,
            insert: true,
            path: successor_path,
        },
    )?;
    if next_root.best
        != Some(select_best_bitcoin_tip_v2(&[
            current_root
                .best
                .ok_or(FullValidatorPrimitiveErrorV2::Chainwork)?,
            successor,
        ])?)
    {
        return Err(FullValidatorPrimitiveErrorV2::Chainwork);
    }
    Ok((next_root, successor))
}

pub fn bitcoin_header_discovery_commitment_v2(batch: &BitcoinHeaderDiscoveryBatchV2) -> Hash32 {
    let mut payload = Vec::with_capacity(21 + batch.discoveries.len() * 80);
    payload.push(batch.version);
    payload.extend_from_slice(&batch.source_sequence_start.to_le_bytes());
    payload.extend_from_slice(&(batch.discoveries.len() as u32).to_le_bytes());
    for discovery in &batch.discoveries {
        payload.extend_from_slice(&serialize(&discovery.header));
    }
    tagged_hash("ECX/full-bitcoin-header-discovery-batch/v2", &payload)
}

pub fn apply_authenticated_header_discovery_batch_v2(
    mut current_root: BitcoinTipFrontierNodeV2,
    batch: &BitcoinHeaderDiscoveryBatchV2,
    expected_source_commitment: Hash32,
) -> Result<BitcoinTipFrontierNodeV2, FullValidatorPrimitiveErrorV2> {
    if batch.version != 1
        || batch.discoveries.is_empty()
        || batch.discoveries.len() > MAX_HEADER_DISCOVERIES_PER_SEGMENT_V2
        || bitcoin_header_discovery_commitment_v2(batch) != expected_source_commitment
    {
        return Err(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch);
    }
    let expected_start = current_root
        .maximum_discovery_sequence
        .ok_or(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch)?
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch)?;
    if batch.source_sequence_start != expected_start {
        return Err(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch);
    }
    for discovery in &batch.discoveries {
        if discovery.pow_context.previous_height != discovery.parent.height
            || discovery.pow_context.previous_header.block_hash() != discovery.parent.block_hash
        {
            return Err(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch);
        }
        verify_next_header_context_v2(
            &discovery.pow_context,
            discovery.header,
            discovery.authenticated_adjusted_time,
        )?;
        (current_root, _) = apply_authenticated_header_discovery_v2(
            current_root,
            discovery.parent,
            &discovery.parent_path,
            &discovery.header,
            discovery.successor_path.clone(),
        )?;
    }
    Ok(current_root)
}

pub fn bitcoin_block_subsidy_atoms_v2(height: u32) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        0
    } else {
        (50 * 100_000_000u64) >> halvings
    }
}

fn minimally_encoded_script_number_v2(value: u32) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut value = u64::from(value);
    let mut encoded = Vec::new();
    while value != 0 {
        encoded.push((value & 0xff) as u8);
        value >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

pub fn verify_bip34_coinbase_height_v2(
    coinbase: &bitcoin::Transaction,
    height: u32,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if !coinbase.is_coinbase() || coinbase.input.len() != 1 {
        return Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure);
    }
    let number = minimally_encoded_script_number_v2(height);
    let mut expected = Vec::with_capacity(number.len() + 1);
    match height {
        0 => expected.push(0x00),
        1..=16 => expected.push(0x50 + height as u8),
        _ => {
            expected.push(
                u8::try_from(number.len())
                    .map_err(|_| FullValidatorPrimitiveErrorV2::CoinbaseHeight)?,
            );
            expected.extend_from_slice(&number);
        }
    }
    if !coinbase.input[0]
        .script_sig
        .as_bytes()
        .starts_with(&expected)
    {
        return Err(FullValidatorPrimitiveErrorV2::CoinbaseHeight);
    }
    Ok(())
}

/// Enforces the block-acceptance lock-time rules, including the consensus
/// boundary differences from script-level CLTV/CSV helpers.
pub fn verify_bitcoin_transaction_locks_v2(
    transaction: &bitcoin::Transaction,
    spends: &[SparseUtxoMutationV2],
    context: BitcoinBlockSpendContextV2,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    verify_transaction_locks_with_alpha_policy(transaction, spends, context, false)
}

fn verify_transaction_locks_with_alpha_policy(
    transaction: &bitcoin::Transaction,
    spends: &[SparseUtxoMutationV2],
    context: BitcoinBlockSpendContextV2,
    alpha: bool,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    let lock_time = transaction.lock_time.to_consensus_u32();
    if lock_time != 0
        && !(alpha && lock_time == 499_999_999)
        && transaction
            .input
            .iter()
            .any(|input| !input.sequence.is_final())
    {
        const LOCKTIME_THRESHOLD: u32 = 500_000_000;
        let comparison = if lock_time < LOCKTIME_THRESHOLD {
            context.height
        } else {
            context.previous_block_mtp
        };
        // Bitcoin Core's IsFinalTx uses strict inequality here.
        if lock_time >= comparison {
            return Err(FullValidatorPrimitiveErrorV2::AbsoluteLockTime);
        }
    }

    if !context.bip68_active || transaction.version < bitcoin::transaction::Version::TWO {
        return Ok(());
    }
    if spends.len() != transaction.input.len() {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    for (input, mutation) in transaction.input.iter().zip(spends) {
        let sequence = input.sequence.to_consensus_u32();
        const DISABLE_FLAG: u32 = 1 << 31;
        const TYPE_FLAG: u32 = 1 << 22;
        const VALUE_MASK: u32 = 0x0000_ffff;
        if sequence & DISABLE_FLAG != 0 {
            continue;
        }
        let old_leaf = mutation
            .old_leaf
            .as_ref()
            .ok_or(FullValidatorPrimitiveErrorV2::TransactionWitness)?;
        let relative = sequence & VALUE_MASK;
        if sequence & TYPE_FLAG == 0 {
            let required_height = old_leaf
                .creation_height
                .checked_add(relative)
                .ok_or(FullValidatorPrimitiveErrorV2::RelativeLockTime)?;
            if context.height < required_height {
                return Err(FullValidatorPrimitiveErrorV2::RelativeLockTime);
            }
        } else {
            let relative_seconds = relative
                .checked_shl(9)
                .ok_or(FullValidatorPrimitiveErrorV2::RelativeLockTime)?;
            let required_mtp = old_leaf
                .creation_parent_mtp
                .checked_add(relative_seconds)
                .ok_or(FullValidatorPrimitiveErrorV2::RelativeLockTime)?;
            if context.previous_block_mtp < required_mtp {
                return Err(FullValidatorPrimitiveErrorV2::RelativeLockTime);
            }
        }
    }
    Ok(())
}

/// Mirrors Bitcoin Core's context-free `CheckTransaction` consensus gate.
///
/// This is deliberately separate from UTXO, lock-time and script validation so
/// external transaction corpora can exercise the exact structural boundary.
pub fn verify_bitcoin_transaction_structure_v2(
    transaction: &bitcoin::Transaction,
) -> Result<(), FullValidatorPrimitiveErrorV2> {
    if transaction.input.is_empty() || transaction.output.is_empty() {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
    if transaction.weight().to_wu() > MAX_BLOCK_WEIGHT {
        return Err(FullValidatorPrimitiveErrorV2::ResourceLimit);
    }

    let mut output_total = 0u64;
    for output in &transaction.output {
        let value = output.value.to_sat();
        if value > BITCOIN_MAX_MONEY_ATOMS_V2 {
            return Err(FullValidatorPrimitiveErrorV2::MonetaryConsensus);
        }
        output_total = output_total
            .checked_add(value)
            .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
        if output_total > BITCOIN_MAX_MONEY_ATOMS_V2 {
            return Err(FullValidatorPrimitiveErrorV2::MonetaryConsensus);
        }
    }

    let mut previous_outpoints = HashSet::with_capacity(transaction.input.len());
    if transaction
        .input
        .iter()
        .any(|input| !previous_outpoints.insert(input.previous_output))
    {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }

    if transaction.is_coinbase() {
        if !(2..=100).contains(&transaction.input[0].script_sig.len()) {
            return Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure);
        }
    } else if transaction
        .input
        .iter()
        .any(|input| input.previous_output.is_null())
    {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    Ok(())
}

pub fn apply_bitcoin_block_utxos_v2<V: BitcoinScriptVerifierV2>(
    block: &Block,
    context: BitcoinBlockSpendContextV2,
    initial_root: SparseUtxoNodeV2,
    witness: &BitcoinBlockUtxoWitnessV2,
    active_script_flags: u32,
    script_verifier: &V,
) -> Result<BitcoinBlockUtxoResultV2, FullValidatorPrimitiveErrorV2> {
    apply_block_utxos_with_alpha_policy(block, context, initial_root, witness, active_script_flags, script_verifier, false)
}

pub(crate) fn apply_block_utxos_with_alpha_policy<V: BitcoinScriptVerifierV2>(
    block: &Block,
    context: BitcoinBlockSpendContextV2,
    initial_root: SparseUtxoNodeV2,
    witness: &BitcoinBlockUtxoWitnessV2,
    active_script_flags: u32,
    script_verifier: &V,
    alpha: bool,
) -> Result<BitcoinBlockUtxoResultV2, FullValidatorPrimitiveErrorV2> {
    if witness.transactions.len() != block.txdata.len() {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    apply_block_utxos_from_transaction_stream(block, context, initial_root,
        witness.transactions.iter().map(Ok), active_script_flags, script_verifier, alpha)
}

pub(crate) trait TransactionWitnessSource {
    fn witness(&self) -> &BitcoinTransactionUtxoWitnessV2;
    fn authenticated_roots(&self) -> Option<(SparseUtxoNodeV2, SparseUtxoNodeV2)> { None }
}
impl TransactionWitnessSource for BitcoinTransactionUtxoWitnessV2 {
    fn witness(&self) -> &BitcoinTransactionUtxoWitnessV2 { self }
}
impl TransactionWitnessSource for &BitcoinTransactionUtxoWitnessV2 {
    fn witness(&self) -> &BitcoinTransactionUtxoWitnessV2 { self }
}

/// Shared execution loop for borrowed legacy witnesses and bounded, owned
/// transaction witnesses decoded by a compact producer. No consensus checks
/// are skipped: compact witnesses carry private decoder-authenticated Merkle
/// roots, while all transaction semantics remain checked here. A producer must bound a
/// single transaction's expansion; this interface does not supply that bound.
pub(crate) fn apply_block_utxos_from_transaction_stream<V, I, W>(
    block: &Block,
    context: BitcoinBlockSpendContextV2,
    initial_root: SparseUtxoNodeV2,
    witnesses: I,
    active_script_flags: u32,
    script_verifier: &V,
    alpha: bool,
) -> Result<BitcoinBlockUtxoResultV2, FullValidatorPrimitiveErrorV2>
where
    V: BitcoinScriptVerifierV2,
    I: IntoIterator<Item = Result<W, FullValidatorPrimitiveErrorV2>>,
    W: TransactionWitnessSource,
{
    if block.txdata.is_empty() {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    let mut witnesses = witnesses.into_iter();
    let mut root = initial_root;
    let mut total_fees = 0u128;
    let mut claimed_coinbase = None;

    for (transaction_index, transaction) in block.txdata.iter().enumerate() {
        let witness = witnesses.next()
            .ok_or(FullValidatorPrimitiveErrorV2::TransactionWitness)??;
        let authenticated_roots = witness.authenticated_roots();
        if authenticated_roots.is_some_and(|(before, _)| before != root) {
            return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
        }
        let transaction_witness = witness.witness();
        verify_bitcoin_transaction_structure_v2(transaction)?;
        let coinbase = transaction_index == 0;
        if coinbase {
            let script_length = transaction.input[0].script_sig.len();
            if !transaction.is_coinbase()
                || transaction.input.len() != 1
                || !(2..=100).contains(&script_length)
                || !transaction_witness.spends.is_empty()
            {
                return Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure);
            }
            // IsFinalTx also applies to coinbase. Relative locks do not:
            // coinbase has no previous output whose age could be checked.
            verify_transaction_locks_with_alpha_policy(
                transaction,
                &[],
                BitcoinBlockSpendContextV2 { bip68_active: false, ..context },
                alpha,
            )?;
            if context.bip34_active {
                verify_bip34_coinbase_height_v2(transaction, context.height)?;
            }
        } else if transaction.is_coinbase()
            || transaction.input.is_empty()
            || transaction.output.is_empty()
            || transaction_witness.spends.len() != transaction.input.len()
        {
            return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
        }
        if !coinbase {
            let mut previous_outpoints = HashSet::with_capacity(transaction.input.len());
            if transaction
                .input
                .iter()
                .any(|input| !previous_outpoints.insert(input.previous_output))
            {
                return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
            }
        }
        let spendable_output_count = transaction
            .output
            .iter()
            .filter(|output| !bitcoin_script_is_provably_unspendable_v2(&output.script_pubkey))
            .count();
        if transaction_witness.creates.len() != spendable_output_count {
            return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
        }

        let mut input_total = 0u128;
        let mut previous_outputs = Vec::with_capacity(transaction.input.len());
        if !coinbase {
            for (input, mutation) in transaction.input.iter().zip(&transaction_witness.spends) {
                let Some(old_leaf) = mutation.old_leaf.as_ref() else {
                    return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
                };
                if mutation.new_leaf.is_some()
                    || mutation.outpoint != input.previous_output
                    || old_leaf.outpoint != input.previous_output
                {
                    return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
                }
                if old_leaf.coinbase
                    && context.height
                        < old_leaf
                            .creation_height
                            .checked_add(BITCOIN_COINBASE_MATURITY_V2)
                            .ok_or(FullValidatorPrimitiveErrorV2::CoinbaseMaturity)?
                {
                    return Err(FullValidatorPrimitiveErrorV2::CoinbaseMaturity);
                }
                input_total = input_total
                    .checked_add(u128::from(old_leaf.output.value.to_sat()))
                    .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
                previous_outputs.push(old_leaf.output.clone());
            }
            verify_transaction_locks_with_alpha_policy(transaction, &transaction_witness.spends, context, alpha)?;
            for input_index in 0..transaction.input.len() {
                script_verifier
                    .verify_input(
                        transaction,
                        input_index,
                        &previous_outputs,
                        active_script_flags,
                    )
                    .map_err(|_| FullValidatorPrimitiveErrorV2::ScriptConsensus)?;
            }
            for mutation in &transaction_witness.spends {
                if authenticated_roots.is_none() {
                    root = apply_sparse_utxo_mutation_v2(root, mutation)?;
                }
            }
        }

        let transaction_id = transaction.compute_txid();
        let mut output_total = 0u128;
        let mut create_index = 0usize;
        for (output_index, output) in transaction.output.iter().enumerate() {
            let value = output.value.to_sat();
            if value > BITCOIN_MAX_MONEY_ATOMS_V2 {
                return Err(FullValidatorPrimitiveErrorV2::MonetaryConsensus);
            }
            output_total = output_total
                .checked_add(u128::from(value))
                .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
            if output_total > u128::from(BITCOIN_MAX_MONEY_ATOMS_V2) {
                return Err(FullValidatorPrimitiveErrorV2::MonetaryConsensus);
            }
            // Bitcoin Core's `AddCoins` deliberately omits provably
            // unspendable outputs from the UTXO set while still including
            // their values in transaction accounting.
            if bitcoin_script_is_provably_unspendable_v2(&output.script_pubkey) {
                continue;
            }
            let mutation = transaction_witness
                .creates
                .get(create_index)
                .ok_or(FullValidatorPrimitiveErrorV2::TransactionWitness)?;
            create_index = create_index
                .checked_add(1)
                .ok_or(FullValidatorPrimitiveErrorV2::ResourceLimit)?;
            let expected_outpoint = OutPoint {
                txid: transaction_id,
                vout: u32::try_from(output_index)
                    .map_err(|_| FullValidatorPrimitiveErrorV2::ResourceLimit)?,
            };
            let Some(new_leaf) = mutation.new_leaf.as_ref() else {
                return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
            };
            if mutation.old_leaf.is_some()
                || mutation.outpoint != expected_outpoint
                || new_leaf.outpoint != expected_outpoint
                || new_leaf.output != *output
                || new_leaf.creation_height != context.height
                || new_leaf.creation_parent_mtp != context.previous_block_mtp
                || new_leaf.coinbase != coinbase
            {
                return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
            }
            if authenticated_roots.is_none() {
                root = apply_sparse_utxo_mutation_v2(root, mutation)?;
            }
        }
        if create_index != transaction_witness.creates.len() {
            return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
        }
        if coinbase {
            claimed_coinbase = Some(output_total);
        } else {
            let fee = input_total
                .checked_sub(output_total)
                .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
            total_fees = total_fees
                .checked_add(fee)
                .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
        }
        if let Some((_, after)) = authenticated_roots {
            root = after;
        }
    }

    if witnesses.next().is_some() {
        return Err(FullValidatorPrimitiveErrorV2::TransactionWitness);
    }
    let allowed_subsidy = bitcoin_block_subsidy_atoms_v2(context.height);
    let claimed_coinbase =
        claimed_coinbase.ok_or(FullValidatorPrimitiveErrorV2::CoinbaseStructure)?;
    let maximum_coinbase = u128::from(allowed_subsidy)
        .checked_add(total_fees)
        .ok_or(FullValidatorPrimitiveErrorV2::MonetaryConsensus)?;
    if claimed_coinbase > maximum_coinbase {
        return Err(FullValidatorPrimitiveErrorV2::MonetaryConsensus);
    }
    Ok(BitcoinBlockUtxoResultV2 {
        next_root: root,
        total_fees_atoms: total_fees,
        allowed_subsidy_atoms: allowed_subsidy,
        claimed_coinbase_atoms: claimed_coinbase,
    })
}

/// Mirrors Bitcoin Core's `CScript::IsUnspendable`: scripts beginning with
/// `OP_RETURN`, and scripts larger than the maximum script size, are never
/// inserted into the UTXO set.
fn bitcoin_script_is_provably_unspendable_v2(script: &bitcoin::Script) -> bool {
    const OP_RETURN: u8 = 0x6a;
    const MAX_SCRIPT_SIZE: usize = 10_000;
    script.len() > MAX_SCRIPT_SIZE || script.as_bytes().first() == Some(&OP_RETURN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::{absolute, Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness};

    fn empty_tree() -> (SparseUtxoNodeV2, SparseUtxoPathV2) {
        let mut node = canonical_empty_utxo_leaf_v2();
        let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
        for _ in 0..SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = sparse_utxo_parent_v2(node, node).unwrap();
        }
        (node, SparseUtxoPathV2 { siblings })
    }

    fn empty_tip_tree() -> (BitcoinTipFrontierNodeV2, BitcoinTipFrontierPathV2) {
        let mut node = canonical_empty_tip_leaf_v2();
        let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
        for _ in 0..SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = combine_tip_frontier_nodes_v2(node, node).unwrap();
        }
        (node, BitcoinTipFrontierPathV2 { siblings })
    }

    fn insertion_path_against_single_tip(
        existing: BitcoinChainTipV2,
        inserted: BitcoinChainTipV2,
    ) -> BitcoinTipFrontierPathV2 {
        let mut empty_nodes = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
        let mut empty = canonical_empty_tip_leaf_v2();
        for _ in 0..SPARSE_UTXO_DEPTH_V2 {
            empty_nodes.push(empty);
            empty = combine_tip_frontier_nodes_v2(empty, empty).unwrap();
        }
        let existing_key = existing.block_hash.to_byte_array();
        let inserted_key = inserted.block_hash.to_byte_array();
        let divergence = (0..SPARSE_UTXO_DEPTH_V2)
            .rfind(|depth| {
                let existing_bit = (existing_key[31 - depth / 8] >> (depth % 8)) & 1;
                let inserted_bit = (inserted_key[31 - depth / 8] >> (depth % 8)) & 1;
                existing_bit != inserted_bit
            })
            .unwrap();
        let mut existing_subtree = present_tip_leaf_v2(existing);
        for (depth, empty_sibling) in empty_nodes.iter().enumerate().take(divergence) {
            let bit = (existing_key[31 - depth / 8] >> (depth % 8)) & 1;
            existing_subtree = if bit == 0 {
                combine_tip_frontier_nodes_v2(existing_subtree, *empty_sibling).unwrap()
            } else {
                combine_tip_frontier_nodes_v2(*empty_sibling, existing_subtree).unwrap()
            };
        }
        let mut siblings = empty_nodes;
        siblings[divergence] = existing_subtree;
        BitcoinTipFrontierPathV2 { siblings }
    }

    struct NoOrdinarySpends;

    impl BitcoinScriptVerifierV2 for NoOrdinarySpends {
        fn verify_input(
            &self,
            _transaction: &bitcoin::Transaction,
            _input_index: usize,
            _previous_outputs: &[TxOut],
            _active_script_flags: u32,
        ) -> Result<(), FullValidatorPrimitiveErrorV2> {
            Err(FullValidatorPrimitiveErrorV2::ScriptConsensus)
        }
    }



    fn witness_commitment_test_block(extra_solution: Option<&[u8]>) -> Block {
        let mut block = genesis_block(Network::Regtest);
        let mut commitment_data = vec![0xaa, 0x21, 0xa9, 0xed];
        commitment_data.extend_from_slice(&[0; 32]);
        let commitment_data = bitcoin::script::PushBytesBuf::try_from(commitment_data).unwrap();
        let mut builder = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(commitment_data);
        if let Some(solution) = extra_solution {
            let mut section = vec![0xec, 0xc7, 0xda, 0xa2];
            section.extend_from_slice(solution);
            builder = builder.push_slice(bitcoin::script::PushBytesBuf::try_from(section).unwrap());
        }
        block.txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: builder.into_script(),
        });
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn genesis_utxo_witness(block: &Block) -> BitcoinBlockUtxoWitnessV2 {
        let (_empty_root, path) = empty_tree();
        let transaction = &block.txdata[0];
        let txid = transaction.compute_txid();
        BitcoinBlockUtxoWitnessV2 {
            transactions: vec![BitcoinTransactionUtxoWitnessV2 {
                spends: vec![],
                creates: transaction
                    .output
                    .iter()
                    .enumerate()
                    .filter(|(_, output)| {
                        !bitcoin_script_is_provably_unspendable_v2(&output.script_pubkey)
                    })
                    .map(|(vout, output)| {
                        let outpoint = OutPoint {
                            txid,
                            vout: vout as u32,
                        };
                        SparseUtxoMutationV2 {
                            outpoint,
                            old_leaf: None,
                            new_leaf: Some(BitcoinUtxoLeafV2 {
                                outpoint,
                                output: output.clone(),
                                creation_height: 0,
                                creation_parent_mtp: 0,
                                coinbase: true,
                            }),
                            path: path.clone(),
                        }
                    })
                    .collect(),
            }],
        }
    }

    fn leaf() -> BitcoinUtxoLeafV2 {
        BitcoinUtxoLeafV2 {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 3,
            },
            output: TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            creation_height: 42,
            creation_parent_mtp: 1_700_000_000,
            coinbase: false,
        }
    }

    fn spending_transaction(sequence: Sequence, lock_time: u32) -> Transaction {
        let previous = leaf().outpoint;
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: previous,
                sequence,
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn spend_witness() -> Vec<SparseUtxoMutationV2> {
        let old_leaf = leaf();
        vec![SparseUtxoMutationV2 {
            outpoint: old_leaf.outpoint,
            old_leaf: Some(old_leaf),
            new_leaf: None,
            path: SparseUtxoPathV2 { siblings: vec![] },
        }]
    }

    #[test]
    fn alpha_absolute_sentinel_is_scoped_and_preserves_relative_locks() {
        let spends = spend_witness();
        let context = BitcoinBlockSpendContextV2 { height: 100, previous_block_mtp: 500_000_100, bip34_active: true, bip68_active: true };
        let tx = spending_transaction(Sequence::ENABLE_LOCKTIME_NO_RBF, 499_999_999);
        assert_eq!(verify_bitcoin_transaction_locks_v2(&tx, &spends, context), Err(FullValidatorPrimitiveErrorV2::AbsoluteLockTime));
        verify_transaction_locks_with_alpha_policy(&tx, &spends, context, true).unwrap();
        for lock in [499_999_998, 500_000_100] {
            let tx = spending_transaction(Sequence::ENABLE_LOCKTIME_NO_RBF, lock);
            assert_eq!(verify_transaction_locks_with_alpha_policy(&tx, &spends, context, true), Err(FullValidatorPrimitiveErrorV2::AbsoluteLockTime));
        }
        let relative = spending_transaction(Sequence(65_535), 499_999_999);
        assert!(verify_transaction_locks_with_alpha_policy(&relative, &spends, context, true).is_err());
    }

    #[test]
    fn absolute_and_bip68_lock_boundaries_are_consensus_exact() {
        let spends = spend_witness();
        let mut context = BitcoinBlockSpendContextV2 {
            height: 100,
            previous_block_mtp: 500_000_100,
            bip34_active: true,
            bip68_active: true,
        };

        let height_locked = spending_transaction(Sequence::ENABLE_LOCKTIME_NO_RBF, 100);
        assert_eq!(
            verify_bitcoin_transaction_locks_v2(&height_locked, &spends, context),
            Err(FullValidatorPrimitiveErrorV2::AbsoluteLockTime)
        );
        context.height = 101;
        verify_bitcoin_transaction_locks_v2(&height_locked, &spends, context).unwrap();

        let time_locked = spending_transaction(Sequence::ENABLE_LOCKTIME_NO_RBF, 500_000_100);
        assert_eq!(
            verify_bitcoin_transaction_locks_v2(&time_locked, &spends, context),
            Err(FullValidatorPrimitiveErrorV2::AbsoluteLockTime)
        );
        context.previous_block_mtp += 1;
        verify_bitcoin_transaction_locks_v2(&time_locked, &spends, context).unwrap();

        // Final sequences disable nLockTime regardless of its value.
        let disabled = spending_transaction(Sequence::MAX, 500_000_999);
        verify_bitcoin_transaction_locks_v2(&disabled, &spends, context).unwrap();

        let relative_height = spending_transaction(Sequence::from_height(5), 0);
        context.height = leaf().creation_height + 4;
        assert_eq!(
            verify_bitcoin_transaction_locks_v2(&relative_height, &spends, context),
            Err(FullValidatorPrimitiveErrorV2::RelativeLockTime)
        );
        context.height += 1;
        verify_bitcoin_transaction_locks_v2(&relative_height, &spends, context).unwrap();

        let relative_time = spending_transaction(Sequence::from_512_second_intervals(2), 0);
        context.previous_block_mtp = leaf().creation_parent_mtp + 2 * 512 - 1;
        assert_eq!(
            verify_bitcoin_transaction_locks_v2(&relative_time, &spends, context),
            Err(FullValidatorPrimitiveErrorV2::RelativeLockTime)
        );
        context.previous_block_mtp += 1;
        verify_bitcoin_transaction_locks_v2(&relative_time, &spends, context).unwrap();

        let mut pre_bip68 = relative_height;
        pre_bip68.version = Version::ONE;
        context.height = 0;
        verify_bitcoin_transaction_locks_v2(&pre_bip68, &spends, context).unwrap();
    }

    #[test]
    fn bip34_height_is_minimal_and_prefix_exact() {
        let mut coinbase = genesis_block(Network::Bitcoin).txdata[0].clone();
        let height = 227_931;
        let number = minimally_encoded_script_number_v2(height);
        let mut script = vec![number.len() as u8];
        script.extend_from_slice(&number);
        script.extend_from_slice(&[0xaa, 0xbb]);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(script.clone());
        verify_bip34_coinbase_height_v2(&coinbase, height).unwrap();

        let mut wrong = coinbase.clone();
        wrong.input[0].script_sig.as_mut_bytes()[1] ^= 1;
        assert_eq!(
            verify_bip34_coinbase_height_v2(&wrong, height),
            Err(FullValidatorPrimitiveErrorV2::CoinbaseHeight)
        );

        // A numerically equivalent non-minimal PUSHDATA encoding is not the
        // exact CScript height prefix required by BIP34.
        let mut non_minimal = coinbase.clone();
        let mut non_minimal_script = vec![0x4c, number.len() as u8];
        non_minimal_script.extend_from_slice(&number);
        non_minimal.input[0].script_sig = ScriptBuf::from_bytes(non_minimal_script);
        assert_eq!(
            verify_bip34_coinbase_height_v2(&non_minimal, height),
            Err(FullValidatorPrimitiveErrorV2::CoinbaseHeight)
        );

        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51, 0x00]);
        verify_bip34_coinbase_height_v2(&coinbase, 1).unwrap();
    }

    #[test]
    fn insertion_and_deletion_chain_exact_intermediate_roots() {
        let (empty_root, path) = empty_tree();
        let leaf = leaf();
        let insert = SparseUtxoMutationV2 {
            outpoint: leaf.outpoint,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path: path.clone(),
        };
        let occupied = apply_sparse_utxo_mutation_v2(empty_root, &insert).unwrap();
        assert_eq!(occupied.aggregate.count, 1);
        assert_eq!(occupied.aggregate.value_atoms, 50_000);
        let delete = SparseUtxoMutationV2 {
            outpoint: leaf.outpoint,
            old_leaf: Some(leaf.clone()),
            new_leaf: None,
            path: path.clone(),
        };
        let mut altered_time_provenance = delete.clone();
        altered_time_provenance
            .old_leaf
            .as_mut()
            .unwrap()
            .creation_parent_mtp += 1;
        assert_eq!(
            apply_sparse_utxo_mutation_v2(occupied, &altered_time_provenance),
            Err(FullValidatorPrimitiveErrorV2::RootMismatch)
        );
        assert_eq!(
            apply_sparse_utxo_mutation_v2(occupied, &delete),
            Ok(empty_root)
        );
    }

    #[test]
    fn wrong_root_outpoint_and_noncanonical_mutation_reject() {
        let (empty_root, path) = empty_tree();
        let leaf = leaf();
        let mut insert = SparseUtxoMutationV2 {
            outpoint: leaf.outpoint,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path,
        };
        let mut wrong = empty_root;
        wrong.hash[0] ^= 1;
        assert_eq!(
            apply_sparse_utxo_mutation_v2(wrong, &insert),
            Err(FullValidatorPrimitiveErrorV2::RootMismatch)
        );
        insert.outpoint.vout += 1;
        assert_eq!(
            apply_sparse_utxo_mutation_v2(empty_root, &insert),
            Err(FullValidatorPrimitiveErrorV2::OutpointMismatch)
        );
        insert.outpoint = leaf.outpoint;
        insert.old_leaf = Some(leaf);
        assert_eq!(
            apply_sparse_utxo_mutation_v2(empty_root, &insert),
            Err(FullValidatorPrimitiveErrorV2::InvalidMutation)
        );
    }

    #[test]
    fn fixed_parent_preimage_matches_legacy() {
        assert_eq!(UTXO_NODE_TAG_HASH, sha256::Hash::hash(b"ECX/full-bitcoin-utxo-node/v2").to_byte_array());
        for count in [0, 1, 255, 256, u64::MAX as u128, u128::MAX - 1] {
            for value in [0, 1, 256, u128::MAX - 1] {
                let left = SparseUtxoNodeV2 { hash: [0x53; 32], aggregate: UtxoAggregateV2 { count, value_atoms: value } };
                let right = SparseUtxoNodeV2 { hash: [0xa7; 32], aggregate: UtxoAggregateV2 { count: 1, value_atoms: 1 } };
                for (left, right) in [(left, right), (right, left)] {
                    let actual = sparse_utxo_parent_v2(left, right).unwrap();
                    let mut payload = left.hash.to_vec();
                    payload.extend(right.hash);
                    payload.extend((count + 1).to_be_bytes());
                    payload.extend((value + 1).to_be_bytes());
                    assert_eq!(actual.hash, tagged_hash("ECX/full-bitcoin-utxo-node/v2", &payload));
                    assert_eq!(actual.aggregate, UtxoAggregateV2 { count: count + 1, value_atoms: value + 1 });
                }
            }
        }
        let node = |count, value_atoms| SparseUtxoNodeV2 { hash: [0;32], aggregate: UtxoAggregateV2 { count, value_atoms } };
        for (left, right) in [(node(u128::MAX, 0), node(1, 0)), (node(0, u128::MAX), node(0, 1))] {
            assert_eq!(sparse_utxo_parent_v2(left, right), Err(FullValidatorPrimitiveErrorV2::AggregateOverflow));
        }
    }

    #[test]
    fn path_length_and_aggregate_overflow_reject() {
        let (_empty_root, mut path) = empty_tree();
        path.siblings.pop();
        assert_eq!(
            sparse_utxo_root_from_path_v2(OutPoint::null(), canonical_empty_utxo_leaf_v2(), &path,),
            Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)
        );
        let max = SparseUtxoNodeV2 {
            hash: [1; 32],
            aggregate: UtxoAggregateV2 {
                count: u128::MAX,
                value_atoms: u128::MAX,
            },
        };
        let one = SparseUtxoNodeV2 {
            hash: [2; 32],
            aggregate: UtxoAggregateV2 {
                count: 1,
                value_atoms: 1,
            },
        };
        assert_eq!(
            sparse_utxo_parent_v2(max, one),
            Err(FullValidatorPrimitiveErrorV2::AggregateOverflow)
        );
    }

    #[test]
    fn canonical_genesis_block_foundation_and_mutations() {
        let block = genesis_block(Network::Bitcoin);
        let raw = serialize(&block);
        let verified = verify_bitcoin_block_foundation_v2(
            &raw,
            block.header.prev_blockhash,
            block.header.target(),
            BITCOIN_MAX_BLOCK_WEIGHT_V2,
        )
        .unwrap();
        assert_eq!(verified.block_hash, block.block_hash());
        assert_eq!(verified.transaction_count, 1);

        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &trailing,
                block.header.prev_blockhash,
                block.header.target(),
                BITCOIN_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::NonCanonicalBlock)
        );
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &raw,
                BlockHash::from_byte_array([9; 32]),
                block.header.target(),
                BITCOIN_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::HeaderLink)
        );
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &raw,
                block.header.prev_blockhash,
                Target::ZERO,
                BITCOIN_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::ProofOfWork)
        );
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &raw,
                block.header.prev_blockhash,
                block.header.target(),
                1,
            ),
            Err(FullValidatorPrimitiveErrorV2::BlockWeight)
        );

        let mut wrong_merkle = block.clone();
        wrong_merkle.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &serialize(&wrong_merkle),
                wrong_merkle.header.prev_blockhash,
                wrong_merkle.header.target(),
                BITCOIN_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::BlockCommitment)
        );

        let mut duplicate_coinbase = block.clone();
        duplicate_coinbase
            .txdata
            .push(duplicate_coinbase.txdata[0].clone());
        duplicate_coinbase.header.merkle_root = duplicate_coinbase.compute_merkle_root().unwrap();
        assert_eq!(
            verify_bitcoin_block_foundation_v2(
                &serialize(&duplicate_coinbase),
                duplicate_coinbase.header.prev_blockhash,
                duplicate_coinbase.header.target(),
                BITCOIN_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::CoinbaseStructure)
        );
    }

    #[test]
    fn difficulty_mtp_and_future_time_context_is_exact() {
        let previous = genesis_block(Network::Regtest).header;
        let mut next = previous;
        next.prev_blockhash = previous.block_hash();
        next.time = previous.time + 1;
        let context = BitcoinPowContextV2 {
            previous_height: 0,
            previous_header: previous,
            previous_11_times: vec![previous.time; 11],
            retarget_epoch_start_time: previous.time,
        };
        assert_eq!(
            expected_next_target_v2(&context, next.time),
            Ok(previous.bits)
        );
        // The copied nonce does not solve the changed header, so contextual PoW
        // still fails after target/MTP/link derivation.
        assert_eq!(
            verify_next_header_context_v2(&context, next, u64::from(next.time)),
            Err(FullValidatorPrimitiveErrorV2::ProofOfWork)
        );

        let mut bad_mtp = next;
        bad_mtp.time = previous.time;
        assert_eq!(
            verify_next_header_context_v2(&context, bad_mtp, u64::from(previous.time) + 1),
            Err(FullValidatorPrimitiveErrorV2::HeaderTime)
        );
        let mut future = next;
        future.time = previous.time + BITCOIN_MAX_FUTURE_BLOCK_SECONDS_V2 as u32 + 1;
        assert_eq!(
            verify_next_header_context_v2(&context, future, u64::from(previous.time)),
            Err(FullValidatorPrimitiveErrorV2::HeaderTime)
        );

        let mut malformed = context.clone();
        malformed.previous_11_times.pop();
        assert_eq!(
            expected_next_target_v2(&malformed, next.time),
            Err(FullValidatorPrimitiveErrorV2::DifficultyContext)
        );
    }

    #[test]
    fn authenticated_header_batch_is_ordered_committed_and_contextual() {
        let previous = genesis_block(Network::Regtest).header;
        let parent = BitcoinChainTipV2 {
            block_hash: previous.block_hash(),
            height: 0,
            chainwork_be: previous.target().to_work().to_be_bytes(),
            discovery_sequence: 0,
        };
        let (empty_root, parent_path) = empty_tip_tree();
        let current_root = apply_tip_frontier_mutation_v2(
            empty_root,
            &BitcoinTipFrontierMutationV2 {
                candidate: parent,
                insert: true,
                path: parent_path.clone(),
            },
        )
        .unwrap();
        let context = BitcoinPowContextV2 {
            previous_height: 0,
            previous_header: previous,
            previous_11_times: vec![previous.time; 11],
            retarget_epoch_start_time: previous.time,
        };
        let mut header = previous;
        header.prev_blockhash = parent.block_hash;
        header.time += 1;
        header.nonce = 0;
        while header.validate_pow(header.target()).is_err() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        let successor = derive_successor_tip_v2(parent, &header, 1).unwrap();
        let batch = BitcoinHeaderDiscoveryBatchV2 {
            version: 1,
            source_sequence_start: 1,
            discoveries: vec![AuthenticatedHeaderDiscoveryV2 {
                parent,
                parent_path,
                pow_context: context,
                header,
                authenticated_adjusted_time: u64::from(header.time),
                successor_path: insertion_path_against_single_tip(parent, successor),
            }],
        };
        let commitment = bitcoin_header_discovery_commitment_v2(&batch);
        let next_root =
            apply_authenticated_header_discovery_batch_v2(current_root, &batch, commitment)
                .unwrap();
        assert_eq!(next_root.count, 2);
        assert_eq!(next_root.best, Some(successor));

        let mut wrong_commitment = commitment;
        wrong_commitment[0] ^= 1;
        assert_eq!(
            apply_authenticated_header_discovery_batch_v2(current_root, &batch, wrong_commitment,),
            Err(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch)
        );
        let mut wrong_start = batch;
        wrong_start.source_sequence_start = 2;
        let wrong_start_commitment = bitcoin_header_discovery_commitment_v2(&wrong_start);
        assert_eq!(
            apply_authenticated_header_discovery_batch_v2(
                current_root,
                &wrong_start,
                wrong_start_commitment,
            ),
            Err(FullValidatorPrimitiveErrorV2::HeaderDiscoveryBatch)
        );
    }


    #[test]
    fn chainwork_and_authenticated_frontier_selection_are_exact() {
        let genesis = genesis_block(Network::Bitcoin).header;
        assert_eq!(
            successor_chainwork_v2([0; 32], genesis.target()),
            genesis.target().to_work().to_be_bytes()
        );
        let mut wrapped = Target::MAX.to_work().to_be_bytes();
        for byte in wrapped.iter_mut().rev() {
            if *byte != 0 {
                *byte -= 1;
                break;
            }
            *byte = 0xff;
        }
        assert_eq!(successor_chainwork_v2([0xff; 32], Target::MAX), wrapped);

        let incumbent = BitcoinChainTipV2 {
            block_hash: BlockHash::from_byte_array([1; 32]),
            height: 10,
            chainwork_be: [3; 32],
            discovery_sequence: 7,
        };
        let equal_later = BitcoinChainTipV2 {
            block_hash: BlockHash::from_byte_array([2; 32]),
            discovery_sequence: 8,
            ..incumbent
        };
        let better = BitcoinChainTipV2 {
            block_hash: BlockHash::from_byte_array([3; 32]),
            height: 9,
            chainwork_be: [4; 32],
            discovery_sequence: 9,
        };
        assert_eq!(
            select_best_bitcoin_tip_v2(&[equal_later, incumbent]).unwrap(),
            incumbent
        );
        assert_eq!(
            select_best_bitcoin_tip_v2(&[incumbent, equal_later, better]).unwrap(),
            better
        );
        assert_eq!(
            select_best_bitcoin_tip_v2(&[incumbent, incumbent]),
            Err(FullValidatorPrimitiveErrorV2::Chainwork)
        );
        assert_eq!(
            select_best_bitcoin_tip_v2(&[]),
            Err(FullValidatorPrimitiveErrorV2::Chainwork)
        );

        let (empty_root, path) = empty_tip_tree();
        assert_eq!(empty_root, canonical_empty_tip_frontier_root_v2());
        let insertion = BitcoinTipFrontierMutationV2 {
            candidate: better,
            insert: true,
            path: path.clone(),
        };
        let occupied = apply_tip_frontier_mutation_v2(empty_root, &insertion).unwrap();
        assert_eq!(occupied.count, 1);
        assert_eq!(occupied.best, Some(better));
        let deletion = BitcoinTipFrontierMutationV2 {
            insert: false,
            ..insertion
        };
        assert_eq!(
            apply_tip_frontier_mutation_v2(occupied, &deletion).unwrap(),
            empty_root
        );
        let mut substituted = deletion;
        substituted.candidate.block_hash = BlockHash::from_byte_array([9; 32]);
        assert_eq!(
            apply_tip_frontier_mutation_v2(occupied, &substituted),
            Err(FullValidatorPrimitiveErrorV2::RootMismatch)
        );

        let parent = better;
        let mut successor_header = genesis;
        successor_header.prev_blockhash = parent.block_hash;
        while (successor_header.block_hash().to_byte_array()[31] & 1)
            == (parent.block_hash.to_byte_array()[31] & 1)
        {
            successor_header.nonce = successor_header.nonce.wrapping_add(1);
        }
        let successor = derive_successor_tip_v2(parent, &successor_header, 10).unwrap();
        let successor_path = insertion_path_against_single_tip(parent, successor);
        verify_tip_frontier_membership_v2(occupied, parent, &path).unwrap();
        apply_tip_frontier_mutation_v2(
            occupied,
            &BitcoinTipFrontierMutationV2 {
                candidate: successor,
                insert: true,
                path: successor_path.clone(),
            },
        )
        .unwrap();
        let (two_tip_root, discovered) = apply_authenticated_header_discovery_v2(
            occupied,
            parent,
            &path,
            &successor_header,
            successor_path,
        )
        .unwrap();
        assert_eq!(discovered, successor);
        assert_eq!(two_tip_root.count, 2);
        assert_eq!(two_tip_root.best, Some(successor));
        assert_eq!(two_tip_root.maximum_discovery_sequence, Some(10));
    }

    #[test]
    fn authenticated_compact_stream_preserves_semantics() {
        let block = genesis_block(Network::Bitcoin);
        let witness = genesis_utxo_witness(&block);
        let context = BitcoinBlockSpendContextV2 { height: 0, previous_block_mtp: 0,
            bip34_active: false, bip68_active: false };
        let (root, _) = empty_tree();
        let expanded = |w: &BitcoinBlockUtxoWitnessV2| apply_block_utxos_with_alpha_policy(
            &block, context, root, w, 0, &NoOrdinarySpends, true);
        let compact = |frame: &[u8]| compact_utxo_frame::verify_alpha(
            &block, context, root, frame, 0, &NoOrdinarySpends);
        let frame = compact_utxo_frame::encode(root, &witness).unwrap();
        assert!(expanded(&witness).is_ok());
        assert_eq!(compact(&frame), expanded(&witness));
        // These encode successfully with authentic Merkle transitions, but
        // violate transaction semantics. Authentication must not bypass them.
        for variant in 0..4 {
            let mut changed = witness.clone();
            let leaf = changed.transactions[0].creates[0].new_leaf.as_mut().unwrap();
            match variant {
                0 => leaf.creation_height += 1,
                1 => leaf.creation_parent_mtp += 1,
                2 => leaf.coinbase = false,
                _ => leaf.output.value = bitcoin::Amount::from_sat(1),
            }
            let encoded = compact_utxo_frame::encode(root, &changed).unwrap();
            assert!(expanded(&changed).is_err());
            assert_eq!(compact(&encoded), expanded(&changed));
        }
        let mut wrong_root = root;
        wrong_root.hash[0] ^= 1;
        assert!(compact_utxo_frame::verify_alpha(&block, context, wrong_root,
            &frame, 0, &NoOrdinarySpends).is_err());
        let mut trailing = frame.clone(); trailing.push(0);
        assert!(compact(&trailing).is_err());
        assert!(compact(&frame[..frame.len()-1]).is_err());
    }

    #[test]
    fn transaction_stream_preserves_execution_and_rejects_bad_framing() {
        let block = genesis_block(Network::Bitcoin);
        let witness = genesis_utxo_witness(&block);
        let context = BitcoinBlockSpendContextV2 { height: 0, previous_block_mtp: 0,
            bip34_active: false, bip68_active: false };
        let (root, _) = empty_tree();
        let expected = apply_bitcoin_block_utxos_v2(&block, context, root, &witness, 0, &NoOrdinarySpends);
        assert!(expected.is_ok());
        let run = |items: Vec<Result<BitcoinTransactionUtxoWitnessV2, FullValidatorPrimitiveErrorV2>>|
            apply_block_utxos_from_transaction_stream(&block, context, root, items, 0, &NoOrdinarySpends, false);
        assert_eq!(run(witness.transactions.iter().cloned().map(Ok).collect()), expected);
        assert!(run(vec![]).is_err());
        assert!(run(vec![Ok(witness.transactions[0].clone()), Ok(witness.transactions[0].clone())]).is_err());
        assert!(run(vec![Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)]).is_err());
        let mut changed = witness.transactions[0].clone();
        changed.creates[0].path.siblings.pop();
        assert!(run(vec![Ok(changed)]).is_err());
    }

    #[test]
    fn coinbase_absolute_finality_is_enforced_without_relative_locks() {
        let mut block = genesis_block(Network::Bitcoin);
        block.txdata[0].version = bitcoin::transaction::Version::TWO;
        block.txdata[0].input[0].sequence = bitcoin::Sequence::ZERO;
        let context = BitcoinBlockSpendContextV2 {
            height: 0, previous_block_mtp: 0, bip34_active: false, bip68_active: true,
        };
        for (lock, alpha, accepted) in [(1, false, false), (1, true, false),
            (499_999_999, false, false), (499_999_999, true, true), (0, true, true)] {
            block.txdata[0].lock_time = bitcoin::absolute::LockTime::from_consensus(lock);
            let witness = genesis_utxo_witness(&block);
            let (root, _) = empty_tree();
            let result = apply_block_utxos_with_alpha_policy(
                &block, context, root, &witness, 0, &NoOrdinarySpends, alpha,
            );
            if accepted {
                assert!(result.is_ok(), "lock={lock}, alpha={alpha}: {result:?}");
            } else {
                assert_eq!(result.unwrap_err(), FullValidatorPrimitiveErrorV2::AbsoluteLockTime);
            }
        }
    }

    #[test]
    fn genesis_utxo_application_binds_outputs_and_subsidy() {
        let block = genesis_block(Network::Bitcoin);
        let (empty_root, _) = empty_tree();
        let witness = genesis_utxo_witness(&block);
        let result = apply_bitcoin_block_utxos_v2(
            &block,
            BitcoinBlockSpendContextV2 {
                height: 0,
                previous_block_mtp: 0,
                bip34_active: false,
                bip68_active: false,
            },
            empty_root,
            &witness,
            0,
            &NoOrdinarySpends,
        )
        .unwrap();
        assert_eq!(result.next_root.aggregate.count, 1);
        assert_eq!(result.next_root.aggregate.value_atoms, 5_000_000_000);
        assert_eq!(result.allowed_subsidy_atoms, 5_000_000_000);
        assert_eq!(result.claimed_coinbase_atoms, 5_000_000_000);
        assert_eq!(result.total_fees_atoms, 0);

        let mut wrong = witness.clone();
        wrong.transactions[0].creates[0]
            .new_leaf
            .as_mut()
            .unwrap()
            .creation_height = 1;
        assert_eq!(
            apply_bitcoin_block_utxos_v2(
                &block,
                BitcoinBlockSpendContextV2 {
                    height: 0,
                    previous_block_mtp: 0,
                    bip34_active: false,
                    bip68_active: false,
                },
                empty_root,
                &wrong,
                0,
                &NoOrdinarySpends,
            ),
            Err(FullValidatorPrimitiveErrorV2::TransactionWitness)
        );
        assert_eq!(bitcoin_block_subsidy_atoms_v2(210_000), 2_500_000_000);
        assert_eq!(bitcoin_block_subsidy_atoms_v2(64 * 210_000), 0);
    }

    #[test]
    fn provably_unspendable_outputs_are_not_inserted_into_utxo_state() {
        let block = witness_commitment_test_block(None);
        let (empty_root, _) = empty_tree();
        let witness = genesis_utxo_witness(&block);
        assert_eq!(block.txdata[0].output.len(), 2);
        assert_eq!(witness.transactions[0].creates.len(), 1);

        let result = apply_bitcoin_block_utxos_v2(
            &block,
            BitcoinBlockSpendContextV2 {
                height: 0,
                previous_block_mtp: 0,
                bip34_active: false,
                bip68_active: false,
            },
            empty_root,
            &witness,
            0,
            &NoOrdinarySpends,
        )
        .unwrap();
        assert_eq!(result.next_root.aggregate.count, 1);
        assert_eq!(result.next_root.aggregate.value_atoms, 5_000_000_000);

        let mut incorrectly_included = witness;
        let output = block.txdata[0].output[1].clone();
        let outpoint = OutPoint {
            txid: block.txdata[0].compute_txid(),
            vout: 1,
        };
        incorrectly_included.transactions[0]
            .creates
            .push(SparseUtxoMutationV2 {
                outpoint,
                old_leaf: None,
                new_leaf: Some(BitcoinUtxoLeafV2 {
                    outpoint,
                    output,
                    creation_height: 0,
                    creation_parent_mtp: 0,
                    coinbase: true,
                }),
                path: empty_tree().1,
            });
        assert_eq!(
            apply_bitcoin_block_utxos_v2(
                &block,
                BitcoinBlockSpendContextV2 {
                    height: 0,
                    previous_block_mtp: 0,
                    bip34_active: false,
                    bip68_active: false,
                },
                empty_root,
                &incorrectly_included,
                0,
                &NoOrdinarySpends,
            ),
            Err(FullValidatorPrimitiveErrorV2::TransactionWitness)
        );
    }

    #[test]
    fn concrete_full_script_verifier_is_wired_and_fail_closed() {
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let valid_previous = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        };
        assert_eq!(
            FullBitcoinScriptVerifierV2.verify_input(
                &transaction,
                0,
                std::slice::from_ref(&valid_previous),
                0,
            ),
            Ok(())
        );
        let invalid_previous = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Builder::new().push_int(0).into_script(),
        };
        assert_eq!(
            FullBitcoinScriptVerifierV2.verify_input(
                &transaction,
                0,
                std::slice::from_ref(&invalid_previous),
                0,
            ),
            Err(FullValidatorPrimitiveErrorV2::ScriptConsensus)
        );

        let mut unexpected_witness = transaction.clone();
        unexpected_witness.input[0].witness.push([1]);
        assert_eq!(
            FullBitcoinScriptVerifierV2.verify_input(
                &unexpected_witness,
                0,
                std::slice::from_ref(&valid_previous),
                script_v2::SCRIPT_VERIFY_WITNESS_V2,
            ),
            Err(FullValidatorPrimitiveErrorV2::ScriptConsensus)
        );
    }
}
