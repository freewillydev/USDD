//! Pinned, fail-closed Truthcoin 0.17.0 replay boundary.
//!
//! This crate authenticates the transport-independent portion of the source
//! statement: mainnet Bitcoin proof of work from an epoch-aligned checkpoint,
//! exact M7 coinbase inclusion for BIP301 sidechain 13, Truthcoin Borsh header
//! and BLAKE3 body commitments, a single fail-closed sidechain ancestry, and
//! deterministic transcript roots. The complete upstream state transition is
//! deliberately represented by [`Truthcoin017StateMachine`]. The repository's
//! default implementation rejects every witness until the reviewed in-memory
//! port is linked and frozen into a replay-guest program ID.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{
    block::Header as BitcoinHeader,
    consensus::{deserialize, serialize, Params},
    hashes::{sha256d, Hash as BitcoinHash},
    opcodes::all::OP_RETURN,
    pow::CompactTarget,
    script::Instruction,
    Transaction,
};
use ecx_protocol_core::{
    Hash32, Price, TruthcoinAnchorStateV1, TruthcoinAnchorV1, TruthcoinLmsrSnapshotV1, PRICE_SCALE,
};
use ecx_truthcoin_proof::{
    is_standard_native_decision_id, native_decision_id_hash, native_lmsr_state_root,
    native_market_id_hash, pinned_truthcoin_chain_id, probability_to_ppb,
    source_public_values_bytes, upstream_binary_lmsr_probability, validate_source_public_values,
    ParentChainContextV1, TruthcoinMarketTemplateCommitmentV1, TruthcoinSourcePublicValuesV1,
    TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256, TRUTHCOIN_LMSR_MATH_COMMITMENT,
    TRUTHCOIN_SIDECHAIN_NUMBER, TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod voting_math;
pub mod authority;

pub const REPLAY_INPUT_VERSION: u8 = 1;
pub const REPLAY_OUTPUT_VERSION: u8 = 1;
pub const MAX_MAINCHAIN_HEADERS: usize = 16_384;
pub const MAX_MERKLE_BRANCH_NODES: usize = 32;
pub const MAX_COINBASE_TRANSACTION_BYTES: usize = 1_000_000;
pub const MAX_BITCOIN_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SIDECHAIN_BLOCKS: usize = 65_536;
pub const MAX_TRUTHCOIN_HEADER_BYTES: usize = 97;
pub const MAX_TRUTHCOIN_COINBASE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRUTHCOIN_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRUTHCOIN_TRANSACTIONS_PER_BLOCK: usize = 65_536;
pub const MAX_AUTHORIZATION_BYTES_PER_BLOCK: usize = 8 * 1024 * 1024;
pub const MAX_MARKET_TEMPLATE_TAGS: usize = 10;

/// Aggregate raw evidence admitted by either the native verifier or the guest.
/// Alpha's epoch-aligned 102-block authentication window can exceed 64 MiB
/// without any individual block or transaction approaching its own limit. The
/// 128 MiB ceiling admits that complete, deposit-aware window while remaining
/// deliberately below the guest's outer 256 MiB bincode limit so decoded
/// containers, replay state, and hashing scratch space retain headroom.
pub const MAX_REPLAY_EVIDENCE_BYTES: usize = 128 * 1024 * 1024;

/// Aggregate transaction count across the complete replay, independent of the
/// per-block transaction cap above.
pub const MAX_REPLAY_TRANSACTIONS: usize = 262_144;

/// The pinned state machine must return the complete exact-template candidate
/// set, but the boundary must not permit unbounded set construction or sorting.
pub const MAX_STATE_MACHINE_CANDIDATES: usize = 4_096;
pub const MAX_STATE_MACHINE_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
/// Pinned upstream 0.17 has 35 databases. ECX's rollback correction adds the
/// timestamp and exact market-transition undo tables, making this an
/// intentionally incompatible profile.
pub const TRUTHCOIN_STATE_DATABASE_COUNT: usize = 37;
pub const MAX_STATE_TABLE_ENTRIES: usize = 1_000_000;
pub const MAX_STATE_KEY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STATE_VALUE_BYTES: usize = 16 * 1024 * 1024;
const TRUTHCOIN_AUTHORIZATION_WIRE_BYTES: usize = 32 + 64;
/// Pinned upstream `sneed::UnitKey` codec is the single byte `0x69`.
const TRUTHCOIN_UNIT_KEY: [u8; 1] = [0x69];

/// Frozen IDs follow the pinned upstream `State::NUM_DBS` construction order:
/// reputation, Decisions, markets, voting, base state, then undo databases.
pub const TRUTHCOIN_STATE_DATABASE_NAMES: [&str; TRUTHCOIN_STATE_DATABASE_COUNT] = [
    "reputation",
    "period_decisions",
    "decision_state_histories",
    "period_pricing",
    "period_pricing_undo",
    "markets",
    "markets_by_state",
    "markets_by_expiry",
    "markets_by_decision",
    "share_accounts",
    "market_funds_utxos",
    "mempool_shares",
    "votes",
    "ballots",
    "decision_outcomes",
    "period_stats",
    "tip",
    "height",
    "mainchain_timestamp",
    "genesis_timestamp",
    "utxos",
    "utxos_by_address",
    "stxos",
    "pending_withdrawal_bundle",
    "latest_failed_withdrawal_bundle",
    "withdrawal_bundles",
    "deposit_blocks",
    "withdrawal_bundle_event_blocks",
    "state_version",
    "settlement_undo",
    "consensus_undo",
    "consolidation_undo",
    "market_transition_undo",
    "minting_undo",
    "reputation_transfer_undo",
    "skipped_tx_indices_undo",
    "mainchain_timestamp_undo",
];

/// Closed, construction-order identity of every database in the authenticated
/// patched Truthcoin state. Ported consensus modules use this type instead of
/// caller-provided numeric IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TruthcoinDatabaseId {
    Reputation = 0,
    PeriodDecisions = 1,
    DecisionStateHistories = 2,
    PeriodPricing = 3,
    PeriodPricingUndo = 4,
    Markets = 5,
    MarketsByState = 6,
    MarketsByExpiry = 7,
    MarketsByDecision = 8,
    ShareAccounts = 9,
    MarketFundsUtxos = 10,
    MempoolShares = 11,
    Votes = 12,
    Ballots = 13,
    DecisionOutcomes = 14,
    PeriodStats = 15,
    Tip = 16,
    Height = 17,
    MainchainTimestamp = 18,
    GenesisTimestamp = 19,
    Utxos = 20,
    UtxosByAddress = 21,
    Stxos = 22,
    PendingWithdrawalBundle = 23,
    LatestFailedWithdrawalBundle = 24,
    WithdrawalBundles = 25,
    DepositBlocks = 26,
    WithdrawalBundleEventBlocks = 27,
    StateVersion = 28,
    SettlementUndo = 29,
    ConsensusUndo = 30,
    ConsolidationUndo = 31,
    MarketTransitionUndo = 32,
    MintingUndo = 33,
    ReputationTransferUndo = 34,
    SkippedTxIndicesUndo = 35,
    MainchainTimestampUndo = 36,
}

impl TruthcoinDatabaseId {
    pub const ALL: [Self; TRUTHCOIN_STATE_DATABASE_COUNT] = [
        Self::Reputation,
        Self::PeriodDecisions,
        Self::DecisionStateHistories,
        Self::PeriodPricing,
        Self::PeriodPricingUndo,
        Self::Markets,
        Self::MarketsByState,
        Self::MarketsByExpiry,
        Self::MarketsByDecision,
        Self::ShareAccounts,
        Self::MarketFundsUtxos,
        Self::MempoolShares,
        Self::Votes,
        Self::Ballots,
        Self::DecisionOutcomes,
        Self::PeriodStats,
        Self::Tip,
        Self::Height,
        Self::MainchainTimestamp,
        Self::GenesisTimestamp,
        Self::Utxos,
        Self::UtxosByAddress,
        Self::Stxos,
        Self::PendingWithdrawalBundle,
        Self::LatestFailedWithdrawalBundle,
        Self::WithdrawalBundles,
        Self::DepositBlocks,
        Self::WithdrawalBundleEventBlocks,
        Self::StateVersion,
        Self::SettlementUndo,
        Self::ConsensusUndo,
        Self::ConsolidationUndo,
        Self::MarketTransitionUndo,
        Self::MintingUndo,
        Self::ReputationTransferUndo,
        Self::SkippedTxIndicesUndo,
        Self::MainchainTimestampUndo,
    ];

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        TRUTHCOIN_STATE_DATABASE_NAMES[usize::from(self.as_u8())]
    }
}

impl TryFrom<u8> for TruthcoinDatabaseId {
    type Error = ReplayError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .get(usize::from(value))
            .copied()
            .ok_or(ReplayError::InvalidStateDatabaseId)
    }
}
pub const BITCOIN_DIFFICULTY_INTERVAL: u64 = 2_016;
pub const BITCOIN_MTP_WINDOW: usize = 11;

/// The exact pinned upstream 0.17.0 state machine and fork-choice
/// implementation are linked for production proof execution. Release identity,
/// authenticated-witness, receipt-verification, and deployment gates remain
/// separate and fail closed.
pub const PRODUCTION_STATE_MACHINE_LINKED: bool = true;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainchainHeaderV1 {
    pub height: u64,
    /// Exact 80-byte Bitcoin consensus header.
    pub consensus_header: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseInclusionV1 {
    pub version: u8,
    pub height: u64,
    /// Exact Bitcoin consensus transaction bytes.
    pub coinbase_transaction: Vec<u8>,
    /// Siblings from the coinbase leaf (transaction index zero) to the root.
    ///
    /// Bitcoin's header does not commit an independently recoverable exact
    /// transaction count: odd-leaf duplication means the same Merkle root can
    /// describe more than one apparent width. Accordingly this proof makes no
    /// unauthenticated transaction-count claim. It authenticates only the
    /// consensus-required index-zero coinbase path.
    pub merkle_siblings: Vec<Hash32>,
}

impl CoinbaseInclusionV1 {
    pub const VERSION: u8 = 1;
}

/// Complete transaction sequence for one authenticated Bitcoin header.
///
/// Inclusion proofs alone cannot prove that a host omitted no BIP300 CTIP
/// transition. The replay therefore authenticates the exact ordered Bitcoin
/// transaction list by recomputing its Merkle root against the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainchainBlockTransactionsV1 {
    pub version: u8,
    pub height: u64,
    /// Exact canonical Bitcoin consensus transaction encodings, coinbase first.
    pub transactions: Vec<Vec<u8>>,
}

impl MainchainBlockTransactionsV1 {
    pub const VERSION: u8 = 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bip300CtipV1 {
    pub txid: Hash32,
    pub vout: u32,
    pub value_sats: u64,
    pub sequence_number: u64,
}

/// Frozen BIP300 validator state from which complete parent-block replay starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinBip300CheckpointStateV1 {
    pub version: u8,
    pub truthcoin_slot_active: bool,
    pub ctip: Option<Bip300CtipV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedTruthcoinDepositV1 {
    pub mainchain_height: u64,
    pub mainchain_block_hash: Hash32,
    pub txid: Hash32,
    pub vout: u32,
    pub address: [u8; 20],
    pub value_sats: u64,
    pub sequence_number: u64,
}

impl TruthcoinBip300CheckpointStateV1 {
    pub const VERSION: u8 = 1;

    pub fn digest(&self) -> Hash32 {
        let mut hasher = TaggedHasher::new("ECX/truthcoin-bip300-checkpoint-state/v1");
        hasher.bytes(&[self.version, u8::from(self.truthcoin_slot_active)]);
        match self.ctip {
            None => hasher.bytes(&[0]),
            Some(ctip) => {
                hasher.bytes(&[1]);
                hasher.bytes(&ctip.txid);
                hasher.u32(ctip.vout);
                hasher.u64(ctip.value_sats);
                hasher.u64(ctip.sequence_number);
            }
        }
        hasher.finalize()
    }
}

/// Exact split representation of a Truthcoin 0.17.0 `Body`.
///
/// The header commits only `BLAKE3(Borsh(coinbase))` and each transaction ID.
/// Authorization and actor-proof encodings are nevertheless transcript-bound
/// and must be decoded and checked by the linked state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinBodyV1 {
    pub coinbase_borsh: Vec<u8>,
    pub transactions_borsh: Vec<Vec<u8>>,
    pub authorizations_borsh: Vec<u8>,
    pub actor_proofs_borsh: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinBlockV1 {
    pub version: u8,
    pub height: u64,
    /// Mainchain block containing the first accepted M7 for this header.
    pub bmm_main_height: u64,
    /// Exact Borsh bytes of upstream `types::Header`.
    pub header_borsh: Vec<u8>,
    pub body: TruthcoinBodyV1,
}

impl TruthcoinBlockV1 {
    pub const VERSION: u8 = 1;

    pub fn block_hash(&self) -> Hash32 {
        *blake3::hash(&self.header_borsh).as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayInputV1 {
    pub version: u8,
    pub authentication: ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    pub parent: ParentChainContextV1,
    /// The full template is private input; its digest must equal the frozen
    /// authentication configuration.
    pub market_template: TruthcoinMarketTemplateCommitmentV1,
    /// BIP300 slot/CTIP state frozen by the authentication configuration.
    pub bip300_checkpoint_state: TruthcoinBip300CheckpointStateV1,
    /// Starts at the frozen checkpoint and ends at the exact ECX parent.
    pub mainchain_headers: Vec<MainchainHeaderV1>,
    /// Exact ten headers immediately before the checkpoint. The checkpoint's
    /// recursive prev-hash commitment authenticates this context, which is
    /// required to enforce Bitcoin MTP on the first post-checkpoint header.
    pub checkpoint_mtp_headers: Vec<Vec<u8>>,
    /// Exactly one coinbase inclusion for every mainchain header.
    pub coinbase_inclusions: Vec<CoinbaseInclusionV1>,
    /// Complete ordered Bitcoin transaction lists for every authenticated
    /// header. These make BIP300 deposit/withdrawal replay omission-resistant.
    pub mainchain_block_transactions: Vec<MainchainBlockTransactionsV1>,
    /// Exactly one body/header preimage for every distinct nonzero M7 accepted
    /// for sidechain 13, ordered by first commitment on the authenticated
    /// Bitcoin chain. Competing branches are retained as evidence; replay uses
    /// the pinned upstream shared-mainchain tip rule.
    pub sidechain_blocks: Vec<TruthcoinBlockV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCandidateV1 {
    pub native_decision_id: [u8; 3],
    pub template_hash: Hash32,
    pub finalized: bool,
    pub anchor: TruthcoinAnchorV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketCandidateV1 {
    pub native_decision_id: [u8; 3],
    pub native_market_id: [u8; 6],
    pub template_hash: Hash32,
    pub is_open: bool,
    pub market_creation_txid: Hash32,
    pub market_created_height: u64,
    pub market_first_eligible_height: u64,
    pub liquidity_base_sats: u64,
    pub beta_f64_bits: u64,
    pub shares: [i64; 2],
    pub selected_outcome_index: u32,
    pub probability_f64_bits: u64,
    pub snapshot: TruthcoinLmsrSnapshotV1,
}

/// Complete oracle-relevant view derived by the exact state machine. Candidate
/// vectors must contain every Decision and market matching the frozen template;
/// the boundary, rather than the host, performs the final deterministic choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineOutputV1 {
    pub version: u8,
    pub replayed_state_root: Hash32,
    pub anchors: Vec<AnchorCandidateV1>,
    pub markets: Vec<MarketCandidateV1>,
}

/// Canonical hand-off between two incremental replay proofs. `state_bytes` is
/// the exact pinned Truthcoin engine's deterministic checkpoint encoding; its
/// meaning is frozen by the replay program ID and it is never trusted without
/// rechecking this envelope and the recursive predecessor proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineCheckpointV1 {
    pub version: u8,
    #[serde(default)]
    pub trusted_start: Option<TrustedStateStartV1>,
    pub authentication_config_hash: Hash32,
    pub market_template_hash: Hash32,
    pub sidechain_tip_hash: Hash32,
    pub sidechain_tip_height: u64,
    pub replayed_state_root: Hash32,
    pub state_bytes: Vec<u8>,
}

/// Immutable bootstrap provenance. The enclosing proof must authenticate the
/// reviewed bootstrap commitment; this field is not permission to trust an
/// arbitrary state supplied by a prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedStateStartV1 {
    pub bootstrap_commitment: Hash32,
    pub sidechain_height: u32,
}

/// Reviewed native bootstrap, not a proof of pre-checkpoint history. The
/// expected commitment supplied to `import` MUST come from the frozen verifier
/// configuration or guest constant, never from the same untrusted witness.
/// The authentication digest is checked separately: including its program ID
/// in a pin compiled into that program would create a hash self-reference.
/// Parent canonicality, MTP and historical validator state are review inputs;
/// the coinbase inclusion and native clock are independently checked here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedNativeBootstrapV1 {
    pub version: u8,
    pub native_capture_sha256: Hash32,
    pub checkpoint: StateMachineCheckpointV1,
    pub parent: MainchainHeaderV1,
    pub inclusion: CoinbaseInclusionV1,
    pub parent_mtp: u64,
    pub bip300: TruthcoinBip300CheckpointStateV1,
}

impl ReviewedNativeBootstrapV1 {
    pub fn commitment(&self) -> Hash32 {
        let mut hash = TaggedHasher::new("ECX/truthcoin-reviewed-native-bootstrap/v2");
        hash.bytes(&[self.version]);
        hash.bytes(&self.native_capture_sha256);
        // Bind all native starting-state data, but not the final program's
        // authentication digest. `import` requires that digest independently.
        hash.bytes(&[self.checkpoint.version]);
        hash.bytes(&self.checkpoint.market_template_hash);
        hash.bytes(&self.checkpoint.sidechain_tip_hash);
        hash.u64(self.checkpoint.sidechain_tip_height);
        hash.bytes(&self.checkpoint.replayed_state_root);
        hash.length_prefixed(&self.checkpoint.state_bytes);
        hash.u64(self.parent.height);
        hash.length_prefixed(&self.parent.consensus_header);
        hash.bytes(&[self.inclusion.version]);
        hash.u64(self.inclusion.height);
        hash.length_prefixed(&self.inclusion.coinbase_transaction);
        hash.u64(self.inclusion.merkle_siblings.len() as u64);
        for sibling in &self.inclusion.merkle_siblings { hash.bytes(sibling); }
        hash.u64(self.parent_mtp);
        hash.bytes(&self.bip300.digest());
        hash.finalize()
    }

    pub fn import(&self, reviewed_commitment: Hash32, expected_authentication_hash: Hash32) -> Result<StateMachineCheckpointV1, ReplayError> {
        if reviewed_commitment == [0; 32]
            || expected_authentication_hash == [0; 32]
            || self.checkpoint.authentication_config_hash != expected_authentication_hash
            || self.commitment() != reviewed_commitment
            || self.version != 2
            || self.native_capture_sha256 == [0; 32]
            || self.checkpoint.version != 1
            || self.checkpoint.trusted_start.is_some()
            || self.bip300.version != TruthcoinBip300CheckpointStateV1::VERSION
            || !self.bip300.truthcoin_slot_active
            || self.parent_mtp == 0
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        self.checkpoint.validate()?;
        if verify_truthcoin_checkpoint_inclusion(&self.parent, &self.inclusion)?
            != Some(self.checkpoint.sidechain_tip_hash)
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        let header: BitcoinHeader = deserialize(&self.parent.consensus_header)
            .map_err(|_| ReplayError::InvalidIncrementalCheckpoint)?;
        let store = CanonicalStateStoreV1::import(&self.checkpoint.state_bytes)?;
        let clock = u64::from(header.time).to_le_bytes();
        if store.entries(TruthcoinDatabaseId::MainchainTimestamp.as_u8())?.len() != 1
            || store.get(TruthcoinDatabaseId::MainchainTimestamp.as_u8(), &TRUTHCOIN_UNIT_KEY)?
                != Some(clock.as_slice())
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        for id in [TruthcoinDatabaseId::MarketTransitionUndo, TruthcoinDatabaseId::MainchainTimestampUndo] {
            if store.entries(id.as_u8())?.len() != 0 {
                return Err(ReplayError::InvalidIncrementalCheckpoint);
            }
        }
        let mut checkpoint = self.checkpoint.clone();
        checkpoint.version = 2;
        checkpoint.trusted_start = Some(TrustedStateStartV1 {
            bootstrap_commitment: reviewed_commitment,
            sidechain_height: u32::try_from(checkpoint.sidechain_tip_height)
                .map_err(|_| ReplayError::InvalidIncrementalCheckpoint)?,
        });
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

impl StateMachineCheckpointV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ReplayError> {
        let snapshot = CanonicalStateSnapshotV1::decode(&self.state_bytes)?;
        let expected_version = if self.trusted_start.is_some() { 2 } else { Self::VERSION };
        if self.version != expected_version
            || self.trusted_start.as_ref().is_some_and(|start|
                start.bootstrap_commitment == [0; 32]
                || u64::from(start.sidechain_height) > self.sidechain_tip_height)
            || self.state_bytes.is_empty()
            || self.state_bytes.len() > MAX_STATE_MACHINE_CHECKPOINT_BYTES
            || [
                self.authentication_config_hash,
                self.market_template_hash,
                self.sidechain_tip_hash,
                self.replayed_state_root,
            ]
            .contains(&[0; 32])
            || snapshot.root()? != self.replayed_state_root
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        if let Some(start) = &self.trusted_start {
            let store = CanonicalStateStoreV1::import(&self.state_bytes)?;
            for (id, expected) in [
                (TruthcoinDatabaseId::Tip, self.sidechain_tip_hash.to_vec()),
                (TruthcoinDatabaseId::Height, u32::try_from(self.sidechain_tip_height)
                    .map_err(|_| ReplayError::InvalidIncrementalCheckpoint)?
                    .to_le_bytes().to_vec()),
            ] {
                if store.entries(id.as_u8())?.len() != 1
                    || store.get(id.as_u8(), &TRUTHCOIN_UNIT_KEY)? != Some(expected.as_slice())
                {
                    return Err(ReplayError::InvalidIncrementalCheckpoint);
                }
            }
            // These two tables were absent in the native bootstrap. Their
            // only permissible contents are verified successor history.
            for id in [TruthcoinDatabaseId::MarketTransitionUndo, TruthcoinDatabaseId::MainchainTimestampUndo] {
                for (key, _) in store.entries(id.as_u8())? {
                    let height = u32::from_le_bytes(key.try_into()
                        .map_err(|_| ReplayError::InvalidIncrementalCheckpoint)?);
                    if height <= start.sidechain_height || u64::from(height) > self.sidechain_tip_height {
                        return Err(ReplayError::InvalidIncrementalCheckpoint);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Hash32 {
        let mut hasher = TaggedHasher::new(if self.trusted_start.is_some() {
            "ECX/truthcoin-state-machine-checkpoint/v2"
        } else { "ECX/truthcoin-state-machine-checkpoint/v1" });
        hasher.bytes(&[self.version]);
        if let Some(start) = &self.trusted_start {
            hasher.bytes(&start.bootstrap_commitment);
            hasher.u32(start.sidechain_height);
        }
        hasher.bytes(&self.authentication_config_hash);
        hasher.bytes(&self.market_template_hash);
        hasher.bytes(&self.sidechain_tip_hash);
        hasher.u64(self.sidechain_tip_height);
        hasher.bytes(&self.replayed_state_root);
        hasher.length_prefixed(&self.state_bytes);
        hasher.finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStateEntryV1 {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStateTableV1 {
    pub database_id: u8,
    pub entries: Vec<CanonicalStateEntryV1>,
}

/// Complete deterministic encoding of all patched Truthcoin state databases.
/// Keys and values are the exact typed database codec bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStateSnapshotV1 {
    pub version: u8,
    pub tables: Vec<CanonicalStateTableV1>,
}

/// Deterministic mutable backend used by the guest-compatible Truthcoin port.
/// It deliberately exposes only ordered unique-table semantics, not LMDB page
/// layout, cursors tied to host lifetimes, or environment-dependent behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStateStoreV1 {
    snapshot: CanonicalStateSnapshotV1,
}

/// Typed view over one canonical Truthcoin database using the exact
/// `heed_types::SerdeBincode` codec selected by upstream 0.17.0. Reads require
/// decode-then-reencode equality because upstream bincode decoding permits
/// trailing bytes; accepting those bytes would give the guest more states than
/// the canonical node can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedCanonicalDatabaseV1<K, V> {
    database_id: u8,
    marker: std::marker::PhantomData<fn() -> (K, V)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TruthcoinFilledOutputV1 {
    address: [u8; 20],
    content: TruthcoinFilledContentV1,
    memo: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum TruthcoinFilledContentV1 {
    Bitcoin(u64),
    BitcoinWithdrawal(TruthcoinWithdrawalContentV1),
    MarketFunds {
        market_id: [u8; 6],
        amount: u64,
        is_fee: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TruthcoinWithdrawalContentV1 {
    value: u64,
    main_fee: u64,
    main_address: String,
}

impl<K, V> TypedCanonicalDatabaseV1<K, V>
where
    K: serde::Serialize + serde::de::DeserializeOwned,
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    pub const fn for_database(database_id: TruthcoinDatabaseId) -> Self {
        Self {
            database_id: database_id.as_u8(),
            marker: std::marker::PhantomData,
        }
    }

    pub fn new(database_id: u8) -> Result<Self, ReplayError> {
        if usize::from(database_id) >= TRUTHCOIN_STATE_DATABASE_COUNT {
            return Err(ReplayError::InvalidStateDatabaseId);
        }
        Ok(Self {
            database_id,
            marker: std::marker::PhantomData,
        })
    }

    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ReplayError> {
        bincode::serialize(value).map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)
    }

    fn decode_canonical<T>(bytes: &[u8]) -> Result<T, ReplayError>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let value: T =
            bincode::deserialize(bytes).map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?;
        if Self::encode(&value)? != bytes {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        Ok(value)
    }

    pub fn get(&self, store: &CanonicalStateStoreV1, key: &K) -> Result<Option<V>, ReplayError> {
        let key = Self::encode(key)?;
        store
            .get(self.database_id, &key)?
            .map(Self::decode_canonical)
            .transpose()
    }

    pub fn put(
        &self,
        store: &mut CanonicalStateStoreV1,
        key: &K,
        value: &V,
    ) -> Result<Option<V>, ReplayError> {
        let old = store.put(self.database_id, Self::encode(key)?, Self::encode(value)?)?;
        old.map(|bytes| Self::decode_canonical(&bytes)).transpose()
    }

    pub fn delete(
        &self,
        store: &mut CanonicalStateStoreV1,
        key: &K,
    ) -> Result<Option<V>, ReplayError> {
        let key = Self::encode(key)?;
        store
            .delete(self.database_id, &key)?
            .map(|bytes| Self::decode_canonical(&bytes))
            .transpose()
    }

    pub fn entries(&self, store: &CanonicalStateStoreV1) -> Result<Vec<(K, V)>, ReplayError> {
        store
            .entries(self.database_id)?
            .map(|(key, value)| Ok((Self::decode_canonical(key)?, Self::decode_canonical(value)?)))
            .collect()
    }
}

impl CanonicalStateStoreV1 {
    pub fn new() -> Self {
        Self {
            snapshot: CanonicalStateSnapshotV1::empty(),
        }
    }

    pub fn from_snapshot(snapshot: CanonicalStateSnapshotV1) -> Result<Self, ReplayError> {
        snapshot.validate()?;
        Ok(Self { snapshot })
    }

    pub fn import(bytes: &[u8]) -> Result<Self, ReplayError> {
        Self::from_snapshot(CanonicalStateSnapshotV1::decode(bytes)?)
    }

    pub fn snapshot(&self) -> &CanonicalStateSnapshotV1 {
        &self.snapshot
    }

    pub fn export(&self) -> Result<Vec<u8>, ReplayError> {
        self.snapshot.encode()
    }

    pub fn root(&self) -> Result<Hash32, ReplayError> {
        self.snapshot.root()
    }

    fn table(&self, database_id: u8) -> Result<&CanonicalStateTableV1, ReplayError> {
        self.snapshot
            .tables
            .get(usize::from(database_id))
            .filter(|table| table.database_id == database_id)
            .ok_or(ReplayError::InvalidStateDatabaseId)
    }

    fn table_mut(&mut self, database_id: u8) -> Result<&mut CanonicalStateTableV1, ReplayError> {
        self.snapshot
            .tables
            .get_mut(usize::from(database_id))
            .filter(|table| table.database_id == database_id)
            .ok_or(ReplayError::InvalidStateDatabaseId)
    }

    pub fn get(&self, database_id: u8, key: &[u8]) -> Result<Option<&[u8]>, ReplayError> {
        let table = self.table(database_id)?;
        match table
            .entries
            .binary_search_by(|entry| entry.key.as_slice().cmp(key))
        {
            Ok(index) => Ok(Some(&table.entries[index].value)),
            Err(_) => Ok(None),
        }
    }

    /// Insert or replace one exact typed-codec entry. Returns the old value.
    pub fn put(
        &mut self,
        database_id: u8,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ReplayError> {
        if key.len() > MAX_STATE_KEY_BYTES || value.len() > MAX_STATE_VALUE_BYTES {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        let original = self.snapshot.clone();
        let table = self.table_mut(database_id)?;
        let old = match table.entries.binary_search_by(|entry| entry.key.cmp(&key)) {
            Ok(index) => Some(std::mem::replace(&mut table.entries[index].value, value)),
            Err(index) => {
                table
                    .entries
                    .insert(index, CanonicalStateEntryV1 { key, value });
                None
            }
        };
        if self.snapshot.validate().is_err() {
            self.snapshot = original;
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        Ok(old)
    }

    pub fn delete(&mut self, database_id: u8, key: &[u8]) -> Result<Option<Vec<u8>>, ReplayError> {
        let table = self.table_mut(database_id)?;
        match table
            .entries
            .binary_search_by(|entry| entry.key.as_slice().cmp(key))
        {
            Ok(index) => Ok(Some(table.entries.remove(index).value)),
            Err(_) => Ok(None),
        }
    }

    pub fn entries(
        &self,
        database_id: u8,
    ) -> Result<impl ExactSizeIterator<Item = (&[u8], &[u8])>, ReplayError> {
        Ok(self
            .table(database_id)?
            .entries
            .iter()
            .map(|entry| (entry.key.as_slice(), entry.value.as_slice())))
    }

    /// Apply a complete block transition atomically. Any error discards every
    /// intermediate table mutation, matching one write transaction's consensus
    /// behavior without relying on an LMDB environment.
    pub fn transaction<T, F>(&mut self, apply: F) -> Result<T, ReplayError>
    where
        F: FnOnce(&mut Self) -> Result<T, ReplayError>,
    {
        let mut candidate = self.clone();
        let result = apply(&mut candidate)?;
        candidate.snapshot.validate()?;
        self.snapshot = candidate.snapshot;
        Ok(result)
    }
}

impl Default for CanonicalStateStoreV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalStateSnapshotV1 {
    pub const VERSION: u8 = 3;
    const MAGIC: [u8; 4] = *b"TCST";

    pub fn empty() -> Self {
        Self {
            version: Self::VERSION,
            tables: (0..TRUTHCOIN_STATE_DATABASE_COUNT)
                .map(|database_id| CanonicalStateTableV1 {
                    database_id: database_id as u8,
                    entries: Vec::new(),
                })
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.version != Self::VERSION || self.tables.len() != TRUTHCOIN_STATE_DATABASE_COUNT {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        let mut total_entries = 0_usize;
        let mut total_bytes = 0_usize;
        for (expected_id, table) in self.tables.iter().enumerate() {
            if usize::from(table.database_id) != expected_id
                || table.entries.len() > MAX_STATE_TABLE_ENTRIES
            {
                return Err(ReplayError::InvalidCanonicalStateSnapshot);
            }
            total_entries = total_entries
                .checked_add(table.entries.len())
                .ok_or(ReplayError::InvalidCanonicalStateSnapshot)?;
            if total_entries > MAX_STATE_TABLE_ENTRIES {
                return Err(ReplayError::InvalidCanonicalStateSnapshot);
            }
            let mut previous_key: Option<&[u8]> = None;
            for entry in &table.entries {
                if entry.key.len() > MAX_STATE_KEY_BYTES
                    || entry.value.len() > MAX_STATE_VALUE_BYTES
                    || previous_key.is_some_and(|previous| previous >= entry.key.as_slice())
                {
                    return Err(ReplayError::InvalidCanonicalStateSnapshot);
                }
                total_bytes = total_bytes
                    .checked_add(entry.key.len())
                    .and_then(|sum| sum.checked_add(entry.value.len()))
                    .ok_or(ReplayError::InvalidCanonicalStateSnapshot)?;
                if total_bytes > MAX_STATE_MACHINE_CHECKPOINT_BYTES {
                    return Err(ReplayError::InvalidCanonicalStateSnapshot);
                }
                previous_key = Some(&entry.key);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ReplayError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.push(self.version);
        out.push(TRUTHCOIN_STATE_DATABASE_COUNT as u8);
        for table in &self.tables {
            out.push(table.database_id);
            out.extend_from_slice(&(table.entries.len() as u64).to_be_bytes());
            for entry in &table.entries {
                out.extend_from_slice(&(entry.key.len() as u32).to_be_bytes());
                out.extend_from_slice(&entry.key);
                out.extend_from_slice(&(entry.value.len() as u32).to_be_bytes());
                out.extend_from_slice(&entry.value);
            }
        }
        if out.len() > MAX_STATE_MACHINE_CHECKPOINT_BYTES {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReplayError> {
        if bytes.len() > MAX_STATE_MACHINE_CHECKPOINT_BYTES {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        let mut decoder = StateSnapshotDecoder::new(bytes);
        if decoder.take(4)? != Self::MAGIC
            || decoder.u8()? != Self::VERSION
            || usize::from(decoder.u8()?) != TRUTHCOIN_STATE_DATABASE_COUNT
        {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        let mut tables = Vec::with_capacity(TRUTHCOIN_STATE_DATABASE_COUNT);
        let mut total_entries = 0_usize;
        for expected_id in 0..TRUTHCOIN_STATE_DATABASE_COUNT {
            let database_id = decoder.u8()?;
            let entry_count = usize::try_from(decoder.u64()?)
                .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?;
            total_entries = total_entries
                .checked_add(entry_count)
                .ok_or(ReplayError::InvalidCanonicalStateSnapshot)?;
            if usize::from(database_id) != expected_id
                || entry_count > MAX_STATE_TABLE_ENTRIES
                || total_entries > MAX_STATE_TABLE_ENTRIES
            {
                return Err(ReplayError::InvalidCanonicalStateSnapshot);
            }
            let mut entries = Vec::with_capacity(entry_count.min(4_096));
            for _ in 0..entry_count {
                let key_len = usize::try_from(decoder.u32()?)
                    .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?;
                if key_len > MAX_STATE_KEY_BYTES {
                    return Err(ReplayError::InvalidCanonicalStateSnapshot);
                }
                let key = decoder.take(key_len)?.to_vec();
                let value_len = usize::try_from(decoder.u32()?)
                    .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?;
                if value_len > MAX_STATE_VALUE_BYTES {
                    return Err(ReplayError::InvalidCanonicalStateSnapshot);
                }
                let value = decoder.take(value_len)?.to_vec();
                entries.push(CanonicalStateEntryV1 { key, value });
            }
            tables.push(CanonicalStateTableV1 {
                database_id,
                entries,
            });
        }
        if !decoder.is_finished() {
            return Err(ReplayError::InvalidCanonicalStateSnapshot);
        }
        let snapshot = Self {
            version: Self::VERSION,
            tables,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn root(&self) -> Result<Hash32, ReplayError> {
        let bytes = self.encode()?;
        let mut hasher = TaggedHasher::new("ECX/truthcoin-complete-state/v3");
        hasher.bytes(&bytes);
        Ok(hasher.finalize())
    }
}

struct StateSnapshotDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateSnapshotDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ReplayError::InvalidCanonicalStateSnapshot)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReplayError::InvalidCanonicalStateSnapshot)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ReplayError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ReplayError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?,
        ))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalStateMachineOutputV1 {
    pub version: u8,
    pub state: StateMachineOutputV1,
    pub successor_checkpoint: StateMachineCheckpointV1,
}

impl IncrementalStateMachineOutputV1 {
    pub const VERSION: u8 = 1;
}

/// Bitcoin-derived consensus context supplied to Truthcoin's state transition
/// for one accepted sidechain block.
///
/// Truthcoin 0.17.0's `connect_prevalidated` consumes the raw timestamp of the
/// Bitcoin block containing M7 for period transitions, claims, voting
/// consensus, genesis time, and market pricing. ECX separately uses Bitcoin
/// median-time-past for source-location semantics. Both values are therefore
/// named explicitly and derived only after authenticating the Bitcoin
/// header/M7 path; neither is accepted as host input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBlockContextV1 {
    pub sidechain_block_hash: Hash32,
    pub sidechain_height: u64,
    pub bmm_main_block_hash: Hash32,
    pub bmm_main_height: u64,
    pub bmm_main_timestamp: u64,
    pub bmm_main_mtp: u64,
}

impl StateMachineOutputV1 {
    pub const VERSION: u8 = 1;
}

/// Exact pinned Truthcoin 0.17.0 transition boundary.
///
/// Implementations must canonically Borsh-decode every raw body component,
/// verify UTXOs and authorizations, execute every transaction and rollback rule,
/// pass each context's `bmm_main_timestamp` (not MTP) into upstream's
/// `connect_prevalidated`-equivalent transition, derive a complete state root,
/// and return *all* exact-template candidates. Returning host-preselected
/// records or substituting host timestamps violates this contract.
/// Implementations must stop exact-template candidate extraction at
/// [`MAX_STATE_MACHINE_CANDIDATES`] before growing the returned vectors beyond
/// that bound.
pub trait Truthcoin017StateMachine {
    fn replay(
        &self,
        template: &TruthcoinMarketTemplateCommitmentV1,
        canonical_blocks: &[TruthcoinBlockV1],
        canonical_contexts: &[CanonicalBlockContextV1],
    ) -> Result<StateMachineOutputV1, ReplayError>;

    /// Resume from a recursively authenticated predecessor checkpoint and
    /// execute only the contiguous canonical suffix. Implementations must
    /// decode `prior.state_bytes` canonically and confirm that it produces
    /// `prior.replayed_state_root` before applying a block.
    fn replay_incremental(
        &self,
        _template: &TruthcoinMarketTemplateCommitmentV1,
        _prior: &StateMachineCheckpointV1,
        _canonical_delta_blocks: &[TruthcoinBlockV1],
        _canonical_delta_contexts: &[CanonicalBlockContextV1],
    ) -> Result<IncrementalStateMachineOutputV1, ReplayError> {
        Err(ReplayError::IncrementalStateMachineUnlinked)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnlinkedTruthcoin017StateMachine;

impl Truthcoin017StateMachine for UnlinkedTruthcoin017StateMachine {
    fn replay(
        &self,
        _template: &TruthcoinMarketTemplateCommitmentV1,
        _canonical_blocks: &[TruthcoinBlockV1],
        _canonical_contexts: &[CanonicalBlockContextV1],
    ) -> Result<StateMachineOutputV1, ReplayError> {
        Err(ReplayError::StateMachineUnlinked)
    }
}

/// Auditable in-memory port of the pinned Truthcoin transition engine. This is
/// usable by native differential tooling now; the production constant remains
/// false until its guest identity and release artifacts are independently
/// frozen.
#[derive(Debug, Clone)]
pub struct CanonicalTruthcoin017StateMachine {
    authentication: ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    bitcoin_tip_height: u64,
}

impl CanonicalTruthcoin017StateMachine {
    pub fn new(
        authentication: ecx_protocol_core::TruthcoinAuthenticationConfigV1,
        bitcoin_tip_height: u64,
    ) -> Result<Self, ReplayError> {
        if authentication.validate().is_err()
            || bitcoin_tip_height < authentication.bitcoin_checkpoint_height
        {
            return Err(ReplayError::InvalidConfiguration);
        }
        Ok(Self {
            authentication,
            bitcoin_tip_height,
        })
    }

    fn source_confirmations(
        &self,
        contexts: &[CanonicalBlockContextV1],
    ) -> Result<u32, ReplayError> {
        let source_height = contexts
            .last()
            .ok_or(ReplayError::EmptySidechain)?
            .bmm_main_height;
        let confirmations = self
            .bitcoin_tip_height
            .checked_sub(source_height)
            .and_then(|distance| distance.checked_add(1))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ReplayError::ConfirmationOverflow)?;
        if confirmations < self.authentication.minimum_bitcoin_confirmations {
            return Err(ReplayError::InsufficientConfirmations);
        }
        Ok(confirmations)
    }
}

impl Truthcoin017StateMachine for CanonicalTruthcoin017StateMachine {
    fn replay(
        &self,
        template: &TruthcoinMarketTemplateCommitmentV1,
        canonical_blocks: &[TruthcoinBlockV1],
        canonical_contexts: &[CanonicalBlockContextV1],
    ) -> Result<StateMachineOutputV1, ReplayError> {
        if canonical_blocks.len() != canonical_contexts.len() || canonical_blocks.is_empty() {
            return Err(ReplayError::InvalidStateMachineOutput);
        }
        let mut store = CanonicalStateStoreV1::new();
        for (block, context) in canonical_blocks.iter().zip(canonical_contexts) {
            apply_truthcoin_block_transition(&mut store, block, *context)?;
        }
        extract_truthcoin_oracle_candidates(
            &self.authentication,
            template,
            &store,
            canonical_blocks,
            canonical_contexts,
            self.source_confirmations(canonical_contexts)?,
        )
    }

    fn replay_incremental(
        &self,
        template: &TruthcoinMarketTemplateCommitmentV1,
        prior: &StateMachineCheckpointV1,
        canonical_delta_blocks: &[TruthcoinBlockV1],
        canonical_delta_contexts: &[CanonicalBlockContextV1],
    ) -> Result<IncrementalStateMachineOutputV1, ReplayError> {
        prior.validate()?;
        if prior.authentication_config_hash != self.authentication.digest()
            || prior.market_template_hash != template.digest()
            || canonical_delta_blocks.len() != canonical_delta_contexts.len()
            || canonical_delta_blocks.is_empty()
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        let mut store = CanonicalStateStoreV1::import(&prior.state_bytes)?;
        for (block, context) in canonical_delta_blocks.iter().zip(canonical_delta_contexts) {
            apply_truthcoin_block_transition(&mut store, block, *context)?;
        }
        let state = extract_truthcoin_oracle_candidates_with_floor(
            &self.authentication,
            template,
            &store,
            canonical_delta_blocks,
            canonical_delta_contexts,
            self.source_confirmations(canonical_delta_contexts)?,
            prior.trusted_start.as_ref().map(|start| start.sidechain_height),
        )?;
        let last = canonical_delta_blocks
            .last()
            .ok_or(ReplayError::InvalidIncrementalCheckpoint)?;
        let state_bytes = store.export()?;
        Ok(IncrementalStateMachineOutputV1 {
            version: IncrementalStateMachineOutputV1::VERSION,
            successor_checkpoint: StateMachineCheckpointV1 {
                version: prior.version,
                trusted_start: prior.trusted_start.clone(),
                authentication_config_hash: self.authentication.digest(),
                market_template_hash: template.digest(),
                sidechain_tip_hash: last.block_hash(),
                sidechain_tip_height: last.height,
                replayed_state_root: state.replayed_state_root,
                state_bytes,
            },
            state,
        })
    }
}

/// Validate checkpoint/delta linkage and invoke the pinned incremental engine.
/// Bitcoin/BMM authentication of `delta_blocks` and `delta_contexts` must be
/// performed by the enclosing replay proof before this function is called.
pub fn execute_incremental_state_transition<S: Truthcoin017StateMachine>(
    authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    template: &TruthcoinMarketTemplateCommitmentV1,
    prior: &StateMachineCheckpointV1,
    delta_blocks: &[TruthcoinBlockV1],
    delta_contexts: &[CanonicalBlockContextV1],
    state_machine: &S,
) -> Result<IncrementalStateMachineOutputV1, ReplayError> {
    authentication
        .validate()
        .map_err(|_| ReplayError::InvalidConfiguration)?;
    prior.validate()?;
    if prior.authentication_config_hash != authentication.digest()
        || prior.market_template_hash != template.digest()
        || delta_blocks.is_empty()
        || delta_blocks.len() > MAX_SIDECHAIN_BLOCKS
        || delta_blocks.len() != delta_contexts.len()
    {
        return Err(ReplayError::InvalidIncrementalCheckpoint);
    }
    validate_delta_resource_bounds(template, delta_blocks)?;

    let mut expected_previous = prior.sidechain_tip_hash;
    let mut expected_height = prior
        .sidechain_tip_height
        .checked_add(1)
        .ok_or(ReplayError::InvalidIncrementalCheckpoint)?;
    for (block, context) in delta_blocks.iter().zip(delta_contexts) {
        let (_, previous_side, _) = parse_truthcoin_header(&block.header_borsh)?;
        if previous_side != Some(expected_previous)
            || block.height != expected_height
            || context.sidechain_block_hash != block.block_hash()
            || context.sidechain_height != block.height
            || context.bmm_main_height != block.bmm_main_height
        {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
        expected_previous = block.block_hash();
        expected_height = expected_height
            .checked_add(1)
            .ok_or(ReplayError::InvalidIncrementalCheckpoint)?;
    }

    let output = state_machine.replay_incremental(template, prior, delta_blocks, delta_contexts)?;
    output.successor_checkpoint.validate()?;
    validate_state_machine_output_bounds(&output.state)?;
    let last = delta_blocks
        .last()
        .ok_or(ReplayError::InvalidIncrementalCheckpoint)?;
    if output.version != IncrementalStateMachineOutputV1::VERSION
        || output.state.version != StateMachineOutputV1::VERSION
        || output.state.replayed_state_root == [0; 32]
        || output.successor_checkpoint.authentication_config_hash
            != prior.authentication_config_hash
        || output.successor_checkpoint.version != prior.version
        || output.successor_checkpoint.trusted_start != prior.trusted_start
        || output.successor_checkpoint.market_template_hash != prior.market_template_hash
        || output.successor_checkpoint.sidechain_tip_hash != last.block_hash()
        || output.successor_checkpoint.sidechain_tip_height != last.height
        || output.successor_checkpoint.replayed_state_root != output.state.replayed_state_root
        || output.successor_checkpoint.commitment() == prior.commitment()
    {
        return Err(ReplayError::InvalidIncrementalStateMachineOutput);
    }
    Ok(output)
}

/// Apply the full replay witness budget to a recursively supplied suffix.
/// Recursive verification authenticates the predecessor checkpoint; it does
/// not make newly supplied block bodies free or exempt them from consensus
/// resource ceilings.
fn validate_delta_resource_bounds(
    template: &TruthcoinMarketTemplateCommitmentV1,
    blocks: &[TruthcoinBlockV1],
) -> Result<(), ReplayError> {
    let mut budget = ReplayResourceBudget::default();
    if template.decision_tags.len() > MAX_MARKET_TEMPLATE_TAGS {
        return Err(ReplayError::Bounds);
    }
    budget.charge_bytes(template.market_title_template.len())?;
    budget.charge_bytes(template.market_description_template.len())?;
    budget.charge_bytes(template.decision_header_template.len())?;
    budget.charge_bytes(template.decision_description_template.len())?;
    for tag in &template.decision_tags {
        budget.charge_bytes(tag.len())?;
    }
    for block in blocks {
        budget.charge_bytes(block.header_borsh.len())?;
        budget.charge_bytes(block.body.coinbase_borsh.len())?;
        budget.charge_bytes(block.body.authorizations_borsh.len())?;
        budget.charge_bytes(block.body.actor_proofs_borsh.len())?;
        budget.charge_transactions(block.body.transactions_borsh.len())?;
        for transaction in &block.body.transactions_borsh {
            budget.charge_bytes(transaction.len())?;
        }
        let authorization_bytes = block
            .body
            .authorizations_borsh
            .len()
            .checked_add(block.body.actor_proofs_borsh.len())
            .ok_or(ReplayError::Bounds)?;
        if block.version != TruthcoinBlockV1::VERSION
            || block.header_borsh.is_empty()
            || block.header_borsh.len() > MAX_TRUTHCOIN_HEADER_BYTES
            || block.body.coinbase_borsh.len() > MAX_TRUTHCOIN_COINBASE_BYTES
            || block.body.transactions_borsh.len() > MAX_TRUTHCOIN_TRANSACTIONS_PER_BLOCK
            || authorization_bytes > MAX_AUTHORIZATION_BYTES_PER_BLOCK
            || block.body.transactions_borsh.iter().any(|transaction| {
                transaction.is_empty() || transaction.len() > MAX_TRUTHCOIN_TRANSACTION_BYTES
            })
        {
            return Err(ReplayError::Bounds);
        }
        validate_truthcoin_authorization_envelopes(&block.body)?;
    }
    Ok(())
}

/// Cross-crate consensus bridge: the Elements singleton must publish the exact
/// checkpoint produced by the incremental replay, not merely a prover-selected
/// state with internally consistent roots.
pub fn verify_incremental_anchor_binding(
    authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    deployment: &ecx_protocol_core::TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
    anchor: &TruthcoinAnchorStateV1,
    checkpoint: &StateMachineCheckpointV1,
    update_public_values_hash: Hash32,
) -> Result<(), ReplayError> {
    anchor
        .validate()
        .map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
    checkpoint.validate()?;
    deployment
        .validate(policy_asset_id)
        .map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
    let anchor_configuration_hash = ecx_protocol_core::truthcoin_anchor_configuration_hash(
        authentication,
        deployment,
        policy_asset_id,
    );
    if update_public_values_hash == [0; 32]
        || checkpoint.authentication_config_hash != authentication.digest()
        || anchor.configuration_hash != anchor_configuration_hash
        || anchor.truthcoin_genesis_hash != authentication.genesis_sidechain_block_hash
        || anchor.truthcoin_tip_hash != checkpoint.sidechain_tip_hash
        || anchor.truthcoin_tip_height != checkpoint.sidechain_tip_height
        || anchor.complete_state_root != checkpoint.replayed_state_root
        || anchor.last_update_proof_commitment != update_public_values_hash
    {
        return Err(ReplayError::InvalidIncrementalAnchorBinding);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStructureV1 {
    pub canonical_chain_root: Hash32,
    pub replay_transcript_root: Hash32,
    pub bitcoin_tip_hash: Hash32,
    pub bitcoin_tip_height: u64,
    pub sidechain_tip_hash: Hash32,
    pub sidechain_tip_height: u64,
    pub sidechain_tip_mtp: u64,
    pub source_confirmations: u32,
    pub canonical_sidechain_blocks: Vec<TruthcoinBlockV1>,
    pub canonical_block_contexts: Vec<CanonicalBlockContextV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutputV1 {
    pub version: u8,
    pub public_values: TruthcoinSourcePublicValuesV1,
    pub public_values_bytes: Vec<u8>,
}

/// Verify the structural replay, execute the exact state machine, perform
/// deterministic candidate selection, and emit the source receipt's public
/// values. No caller-supplied public-values structure is accepted.
pub fn execute_replay_with_state_machine<S: Truthcoin017StateMachine>(
    input: &ReplayInputV1,
    state_machine: &S,
) -> Result<ReplayOutputV1, ReplayError> {
    let structure = verify_replay_structure(input)?;
    execute_replay_with_verified_structure(input, state_machine, &structure)
}

fn execute_replay_with_verified_structure<S: Truthcoin017StateMachine>(
    input: &ReplayInputV1,
    state_machine: &S,
    structure: &ReplayStructureV1,
) -> Result<ReplayOutputV1, ReplayError> {
    // Prefer deposit-aware canonical replay when the BIP300 checkpoint is active:
    // authenticate M5 deposits from the mainchain window and apply them between
    // sidechain transitions (required for production-period private chains).
    let deposits = verify_truthcoin_bip300_deposits(input)?;
    let state = if !deposits.is_empty() {
        let confirmations = {
            let source_height = structure
                .canonical_block_contexts
                .last()
                .ok_or(ReplayError::EmptySidechain)?
                .bmm_main_height;
            let confirmations = structure
                .bitcoin_tip_height
                .checked_sub(source_height)
                .and_then(|distance| distance.checked_add(1))
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(ReplayError::ConfirmationOverflow)?;
            if confirmations < input.authentication.minimum_bitcoin_confirmations {
                return Err(ReplayError::InsufficientConfirmations);
            }
            confirmations
        };
        let mut store = CanonicalStateStoreV1::new();
        let mut next_deposit = 0_usize;
        for (block, context) in structure
            .canonical_sidechain_blocks
            .iter()
            .zip(&structure.canonical_block_contexts)
        {
            // Native connect_tip_ connects the child before connect_two_way_peg_data.
            // Deposits reached in this batch become spendable by later children,
            // not by the child that first imports them.
            apply_truthcoin_block_transition(&mut store, block, *context)?;
            let first_deposit = next_deposit;
            while let Some(deposit) = deposits.get(next_deposit) {
                if deposit.mainchain_height > context.bmm_main_height {
                    break;
                }
                next_deposit += 1;
            }
            apply_authenticated_truthcoin_deposit_batch(&mut store,
                &deposits[first_deposit..next_deposit], context.sidechain_height)?;
        }
        extract_truthcoin_oracle_candidates(
            &input.authentication,
            &input.market_template,
            &store,
            &structure.canonical_sidechain_blocks,
            &structure.canonical_block_contexts,
            confirmations,
        )?
    } else {
        state_machine.replay(
            &input.market_template,
            &structure.canonical_sidechain_blocks,
            &structure.canonical_block_contexts,
        )?
    };
    finalize_replay_output(input, structure, &state)
}

fn finalize_replay_output(
    input: &ReplayInputV1,
    structure: &ReplayStructureV1,
    state: &StateMachineOutputV1,
) -> Result<ReplayOutputV1, ReplayError> {
    if state.version != StateMachineOutputV1::VERSION || state.replayed_state_root == [0; 32] {
        return Err(ReplayError::InvalidStateMachineOutput);
    }
    validate_state_machine_output_bounds(&state)?;
    validate_candidate_integrity(input, &state)?;
    let anchor = select_anchor(input, &state.anchors)?;
    let market = select_market(input, &state.markets)?;
    validate_source_location(input, &anchor.anchor)?;
    validate_source_location(input, &market.snapshot)?;

    let public_values = TruthcoinSourcePublicValuesV1 {
        version: TruthcoinSourcePublicValuesV1::VERSION,
        authentication_config_hash: input.authentication.digest(),
        source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
        consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
        sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
        observed_parent_block_hash: input.parent.block_hash,
        observed_parent_height: input.parent.height,
        observed_parent_mtp: input.parent.median_time_past,
        bitcoin_checkpoint_hash: input.authentication.bitcoin_checkpoint_hash,
        bitcoin_checkpoint_height: input.authentication.bitcoin_checkpoint_height,
        bitcoin_tip_hash: structure.bitcoin_tip_hash,
        bitcoin_tip_height: structure.bitcoin_tip_height,
        sidechain_genesis_hash: input.authentication.genesis_sidechain_block_hash,
        sidechain_tip_hash: structure.sidechain_tip_hash,
        sidechain_tip_height: structure.sidechain_tip_height,
        sidechain_tip_mtp: structure.sidechain_tip_mtp,
        source_confirmations: structure.source_confirmations,
        canonical_chain_root: structure.canonical_chain_root,
        replay_transcript_root: structure.replay_transcript_root,
        replayed_state_root: state.replayed_state_root,
        selection_rule_hash: input.authentication.selection_rule_hash,
        anchor_decision_id_native: anchor.native_decision_id,
        lmsr_decision_id_native: market.native_decision_id,
        lmsr_market_id_native: market.native_market_id,
        lmsr_market_creation_txid: market.market_creation_txid,
        lmsr_market_created_height: market.market_created_height,
        lmsr_market_first_eligible_height: market.market_first_eligible_height,
        lmsr_liquidity_base_sats: market.liquidity_base_sats,
        lmsr_beta_f64_bits: market.beta_f64_bits,
        lmsr_shares: market.shares,
        lmsr_selected_outcome_index: market.selected_outcome_index,
        lmsr_probability_f64_bits: market.probability_f64_bits,
        anchor: anchor.anchor,
        lmsr_snapshot: market.snapshot,
    };
    validate_source_public_values(&input.authentication, input.parent, &public_values)
        .map_err(|_| ReplayError::InvalidStateMachineOutput)?;
    let public_values_bytes = source_public_values_bytes(&public_values);
    Ok(ReplayOutputV1 {
        version: REPLAY_OUTPUT_VERSION,
        public_values,
        public_values_bytes,
    })
}

/// Production replay entrypoint used by the release guest.
///
/// The concrete canonical 37-table implementation is wired here rather than
/// selected by the guest. Human review is advisory and cannot select the
/// relation; frozen identities and authenticated inputs remain fail-closed
/// release requirements.
pub fn execute_production_replay(input: &ReplayInputV1) -> Result<ReplayOutputV1, ReplayError> {
    if !PRODUCTION_STATE_MACHINE_LINKED {
        return Err(ReplayError::StateMachineUnlinked);
    }
    let structure = verify_production_replay_structure(input)?;
    let state_machine = CanonicalTruthcoin017StateMachine::new(
        input.authentication.clone(),
        structure.bitcoin_tip_height,
    )?;
    execute_replay_with_verified_structure(input, &state_machine, &structure)
}

/// Replay the complete suffix from a reviewed native starting state. Both
/// expected hashes are verifier inputs, not values to copy from the witness.
/// This is not a recursive checkpoint API: every call supplies the full suffix
/// from `bootstrap.parent`, including deposits not yet consumed by a child.
pub fn execute_production_replay_from_bootstrap(
    input: &ReplayInputV1,
    bootstrap: &ReviewedNativeBootstrapV1,
    reviewed_commitment: Hash32,
    expected_authentication_hash: Hash32,
) -> Result<ReplayOutputV1, ReplayError> {
    replay_bootstrap_with(input, bootstrap, reviewed_commitment, expected_authentication_hash,
        |structure, _store, state, _headers| finalize_replay_output(input, structure, state))
}

// Both the legacy guest and authority guest use the SAME authenticated replay.
// The completion callback is private; it cannot substitute an external engine.
fn replay_bootstrap_with<T>(
    input: &ReplayInputV1,
    bootstrap: &ReviewedNativeBootstrapV1,
    reviewed_commitment: Hash32,
    expected_authentication_hash: Hash32,
    finish: impl FnOnce(&ReplayStructureV1, &CanonicalStateStoreV1,
        &StateMachineOutputV1, &[BitcoinHeader]) -> Result<T, ReplayError>,
) -> Result<T, ReplayError> {
    if !PRODUCTION_STATE_MACHINE_LINKED {
        return Err(ReplayError::StateMachineUnlinked);
    }
    validate_replay_configuration(input)?;
    let prior = bootstrap.import(reviewed_commitment, expected_authentication_hash)?;
    if input.authentication.digest() != expected_authentication_hash
        || prior.market_template_hash != input.market_template.digest()
        || input.mainchain_headers.first() != Some(&bootstrap.parent)
        || input.coinbase_inclusions.first() != Some(&bootstrap.inclusion)
        || input.bip300_checkpoint_state != bootstrap.bip300
    {
        return Err(ReplayError::InvalidIncrementalCheckpoint);
    }
    let (mtp_context, headers) = verify_mainchain_headers(input)?;
    if median_time_past(&mtp_context, &headers, 0)? != bootstrap.parent_mtp {
        return Err(ReplayError::InvalidIncrementalCheckpoint);
    }
    verify_mainchain_block_transactions(input, &headers)?;
    let commitments = verify_coinbase_inclusions(input, &headers)?;
    let set = verify_sidechain_set_from_start(
        input, &mtp_context, &headers, &commitments,
        Some((prior.sidechain_tip_hash, prior.sidechain_tip_height)),
    )?;
    let deposits = verify_truthcoin_bip300_transition(input)?.deposits;
    for tip_hash in ranked_sidechain_tips(&set) {
        let structure = replay_structure_for_tip(input, &headers, &commitments, &set, tip_hash)?;
        // Each fork starts from exactly the imported state. A failed branch
        // cannot leak partial mutations or consumed deposits into another.
        let store = CanonicalStateStoreV1::import(&prior.state_bytes)?;
        let Ok(store) = apply_branch_from_store(
            store, &structure.canonical_sidechain_blocks,
            &structure.canonical_block_contexts, &deposits,
        ) else { continue; };
        let state = extract_truthcoin_oracle_candidates_with_floor(
            &input.authentication, &input.market_template, &store,
            &structure.canonical_sidechain_blocks, &structure.canonical_block_contexts,
            structure.source_confirmations,
            prior.trusted_start.as_ref().map(|start| start.sidechain_height),
        )?;
        return finish(&structure, &store, &state, &headers);
    }
    Err(ReplayError::NoStateValidTruthcoinBranch)
}

/// Verify everything that can be established without interpreting Truthcoin
/// transactions. This is public for native differential-vector tooling; it is
/// not sufficient to authenticate an oracle price.
pub fn verify_replay_structure(input: &ReplayInputV1) -> Result<ReplayStructureV1, ReplayError> {
    validate_replay_configuration(input)?;
    let (mtp_context, headers) = verify_mainchain_headers(input)?;
    verify_mainchain_block_transactions(input, &headers)?;
    let commitments = verify_coinbase_inclusions(input, &headers)?;
    let set = verify_sidechain_set(input, &mtp_context, &headers, &commitments)?;
    let tip_hash = ranked_sidechain_tips(&set)
        .into_iter()
        .next()
        .ok_or(ReplayError::EmptySidechain)?;
    replay_structure_for_tip(input, &headers, &commitments, &set, tip_hash)
}

fn validate_replay_configuration(input: &ReplayInputV1) -> Result<(), ReplayError> {
    validate_input_bounds(input)?;
    if input.version != REPLAY_INPUT_VERSION
        || input.authentication.validate().is_err()
        || input.authentication.source_git_commit_sha1 != TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1
        || input.authentication.consensus_source_manifest_sha256
            != TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256
        || input.authentication.sidechain_number != TRUTHCOIN_SIDECHAIN_NUMBER
        || input.authentication.truthcoin_chain_id
            != pinned_truthcoin_chain_id(input.authentication.genesis_sidechain_block_hash)
        || input.authentication.lmsr_math_commitment != TRUTHCOIN_LMSR_MATH_COMMITMENT
        || input.bip300_checkpoint_state.version != TruthcoinBip300CheckpointStateV1::VERSION
        || input.bip300_checkpoint_state.digest()
            != input.authentication.bip300_checkpoint_state_hash
        || input.market_template.version != TruthcoinMarketTemplateCommitmentV1::VERSION
        || input.market_template.digest() != input.authentication.btc_usd_template_hash
    {
        return Err(ReplayError::InvalidConfiguration);
    }

    Ok(())
}

fn replay_structure_for_tip(
    input: &ReplayInputV1,
    headers: &[BitcoinHeader],
    commitments: &[Option<Hash32>],
    set: &VerifiedSidechainSet,
    tip_hash: Hash32,
) -> Result<ReplayStructureV1, ReplayError> {
    let (canonical_sidechain_blocks, canonical_block_contexts) =
        sidechain_branch_for_tip(input, set, tip_hash)?;
    let source_confirmations = sidechain_confirmations(input, set, tip_hash)?;
    let sidechain_tip_mtp = canonical_block_contexts
        .last()
        .ok_or(ReplayError::EmptySidechain)?
        .bmm_main_mtp;

    let tip = headers.last().ok_or(ReplayError::EmptyMainchain)?;
    let side_tip = canonical_sidechain_blocks
        .last()
        .ok_or(ReplayError::EmptySidechain)?;
    Ok(ReplayStructureV1 {
        canonical_chain_root: canonical_chain_root(input, &commitments),
        replay_transcript_root: replay_transcript_root(
            &canonical_sidechain_blocks,
            &canonical_block_contexts,
        ),
        bitcoin_tip_hash: tip.block_hash().to_byte_array(),
        bitcoin_tip_height: input.parent.height,
        sidechain_tip_hash: side_tip.block_hash(),
        sidechain_tip_height: side_tip.height,
        sidechain_tip_mtp,
        source_confirmations,
        canonical_sidechain_blocks,
        canonical_block_contexts,
    })
}

fn branch_transitions_are_valid(
    blocks: &[TruthcoinBlockV1],
    contexts: &[CanonicalBlockContextV1],
    deposits: &[AuthenticatedTruthcoinDepositV1],
) -> bool {
    apply_branch_from_store(CanonicalStateStoreV1::new(), blocks, contexts, deposits).is_ok()
}

fn apply_branch_from_store(
    mut store: CanonicalStateStoreV1,
    blocks: &[TruthcoinBlockV1],
    contexts: &[CanonicalBlockContextV1],
    deposits: &[AuthenticatedTruthcoinDepositV1],
) -> Result<CanonicalStateStoreV1, ReplayError> {
        if blocks.is_empty() || blocks.len() != contexts.len() {
            return Err(ReplayError::EmptySidechain);
        }
        let mut next_deposit = 0_usize;
        for (block, context) in blocks.iter().zip(contexts) {
            // Match native child-connect, then two-way-peg-connect ordering.
            apply_truthcoin_block_transition(&mut store, block, *context)?;
            let first_deposit = next_deposit;
            while let Some(deposit) = deposits.get(next_deposit) {
                if deposit.mainchain_height > context.bmm_main_height {
                    break;
                }
                next_deposit += 1;
            }
            apply_authenticated_truthcoin_deposit_batch(&mut store,
                &deposits[first_deposit..next_deposit], context.sidechain_height)?;
        }
        Ok(store)
}

/// Verify the authenticated replay and select the best BMM branch whose full
/// Truthcoin state transition is valid. This is the exact structural boundary
/// used by [`execute_production_replay`]; callers still need the latter to
/// derive and validate oracle candidates.
pub fn verify_production_replay_structure(
    input: &ReplayInputV1,
) -> Result<ReplayStructureV1, ReplayError> {
    // Run the complete public structural gate first, including bounds,
    // configuration, full Bitcoin transaction completeness, and M7 coverage.
    let _ = verify_replay_structure(input)?;
    let (mtp_context, headers) = verify_mainchain_headers(input)?;
    verify_mainchain_block_transactions(input, &headers)?;
    let commitments = verify_coinbase_inclusions(input, &headers)?;
    let set = verify_sidechain_set(input, &mtp_context, &headers, &commitments)?;
    let deposits = verify_truthcoin_bip300_deposits(input)?;
    for tip_hash in ranked_sidechain_tips(&set) {
        let structure = replay_structure_for_tip(input, &headers, &commitments, &set, tip_hash)?;
        if branch_transitions_are_valid(
            &structure.canonical_sidechain_blocks,
            &structure.canonical_block_contexts,
            &deposits,
        ) {
            return Ok(structure);
        }
    }
    Err(ReplayError::NoStateValidTruthcoinBranch)
}

fn validate_input_bounds(input: &ReplayInputV1) -> Result<(), ReplayError> {
    if input.mainchain_headers.is_empty()
        || input.mainchain_headers.len() > MAX_MAINCHAIN_HEADERS
        || input.mainchain_headers.len() != input.coinbase_inclusions.len()
        || input.mainchain_headers.len() != input.mainchain_block_transactions.len()
        || input.checkpoint_mtp_headers.len() != BITCOIN_MTP_WINDOW - 1
        || input.sidechain_blocks.is_empty()
        || input.sidechain_blocks.len() > MAX_SIDECHAIN_BLOCKS
        || input.market_template.decision_tags.len() > MAX_MARKET_TEMPLATE_TAGS
    {
        return Err(ReplayError::Bounds);
    }
    let mut budget = ReplayResourceBudget::default();
    budget.charge_bytes(input.market_template.market_title_template.len())?;
    budget.charge_bytes(input.market_template.market_description_template.len())?;
    budget.charge_bytes(input.market_template.decision_header_template.len())?;
    budget.charge_bytes(input.market_template.decision_description_template.len())?;
    for tag in &input.market_template.decision_tags {
        budget.charge_bytes(tag.len())?;
    }
    for header in &input.mainchain_headers {
        budget.charge_bytes(header.consensus_header.len())?;
    }
    for header in &input.checkpoint_mtp_headers {
        budget.charge_bytes(header.len())?;
    }

    if input
        .mainchain_headers
        .iter()
        .any(|header| header.consensus_header.len() != 80)
        || input
            .checkpoint_mtp_headers
            .iter()
            .any(|header| header.len() != 80)
    {
        return Err(ReplayError::Bounds);
    }
    for inclusion in &input.coinbase_inclusions {
        budget.charge_bytes(inclusion.coinbase_transaction.len())?;
        budget.charge_bytes(
            inclusion
                .merkle_siblings
                .len()
                .checked_mul(std::mem::size_of::<Hash32>())
                .ok_or(ReplayError::Bounds)?,
        )?;
        if inclusion.version != CoinbaseInclusionV1::VERSION
            || inclusion.coinbase_transaction.is_empty()
            || inclusion.coinbase_transaction.len() > MAX_COINBASE_TRANSACTION_BYTES
            || inclusion.merkle_siblings.len() > MAX_MERKLE_BRANCH_NODES
        {
            return Err(ReplayError::Bounds);
        }
    }
    for block in &input.mainchain_block_transactions {
        if block.version != MainchainBlockTransactionsV1::VERSION
            || block.transactions.is_empty()
            || block.transactions.len() > MAX_REPLAY_TRANSACTIONS
        {
            return Err(ReplayError::Bounds);
        }
        budget.charge_transactions(block.transactions.len())?;
        for transaction in &block.transactions {
            budget.charge_bytes(transaction.len())?;
            if transaction.is_empty() || transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
                return Err(ReplayError::Bounds);
            }
        }
    }
    for block in &input.sidechain_blocks {
        budget.charge_bytes(block.header_borsh.len())?;
        budget.charge_bytes(block.body.coinbase_borsh.len())?;
        budget.charge_bytes(block.body.authorizations_borsh.len())?;
        budget.charge_bytes(block.body.actor_proofs_borsh.len())?;
        budget.charge_transactions(block.body.transactions_borsh.len())?;
        for transaction in &block.body.transactions_borsh {
            budget.charge_bytes(transaction.len())?;
        }
        let authorization_bytes = block
            .body
            .authorizations_borsh
            .len()
            .checked_add(block.body.actor_proofs_borsh.len())
            .ok_or(ReplayError::Bounds)?;
        if block.version != TruthcoinBlockV1::VERSION
            || block.header_borsh.is_empty()
            || block.header_borsh.len() > MAX_TRUTHCOIN_HEADER_BYTES
            || block.body.coinbase_borsh.len() > MAX_TRUTHCOIN_COINBASE_BYTES
            || block.body.transactions_borsh.len() > MAX_TRUTHCOIN_TRANSACTIONS_PER_BLOCK
            || authorization_bytes > MAX_AUTHORIZATION_BYTES_PER_BLOCK
            || block
                .body
                .transactions_borsh
                .iter()
                .any(|tx| tx.is_empty() || tx.len() > MAX_TRUTHCOIN_TRANSACTION_BYTES)
        {
            return Err(ReplayError::Bounds);
        }
        validate_truthcoin_authorization_envelopes(&block.body)?;
    }
    Ok(())
}

/// Decode the two split Borsh vectors from upstream `Body` without trusting a
/// host-side object model. `Authorization` is exactly a 32-byte Ed25519 public
/// key followed by a 64-byte signature. `actor_proofs` contains exactly one
/// Borsh `Option<Authorization>` for every transaction. Signature semantics
/// remain the responsibility of the linked state machine, which also decodes
/// each transaction and checks the authorization count against its inputs.
struct TruthcoinWireCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> TruthcoinWireCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayError> {
        let value = self
            .remaining
            .get(..length)
            .ok_or(ReplayError::InvalidTruthcoinTransactionEncoding)?;
        self.remaining = &self.remaining[length..];
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayError> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<usize, ReplayError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
        usize::try_from(u32::from_le_bytes(bytes))
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)
    }

    fn string_value(&mut self) -> Result<String, ReplayError> {
        let length = self.u32_le()?;
        Ok(std::str::from_utf8(self.take(length)?)
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?
            .to_owned())
    }

    fn f64_value(&mut self) -> Result<f64, ReplayError> {
        let bits: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
        let value = f64::from_le_bytes(bits);
        if value.is_nan() {
            return Err(ReplayError::InvalidTruthcoinTransactionEncoding);
        }
        Ok(value)
    }

    fn optional_f64_value(&mut self) -> Result<Option<f64>, ReplayError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.f64_value()?)),
            _ => Err(ReplayError::InvalidTruthcoinTransactionEncoding),
        }
    }

    fn optional_u8_value(&mut self) -> Result<Option<u8>, ReplayError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u8()?)),
            _ => Err(ReplayError::InvalidTruthcoinTransactionEncoding),
        }
    }
}

fn decode_truthcoin_string_vec_value(
    cursor: &mut TruthcoinWireCursor<'_>,
) -> Result<Vec<String>, ReplayError> {
    let count = cursor.u32_le()?;
    let mut values = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        values.push(cursor.string_value()?);
    }
    Ok(values)
}

fn decode_truthcoin_optional_string(
    cursor: &mut TruthcoinWireCursor<'_>,
) -> Result<Option<String>, ReplayError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.string_value()?)),
        _ => Err(ReplayError::InvalidTruthcoinTransactionEncoding),
    }
}

fn decode_truthcoin_optional_string_vec(
    cursor: &mut TruthcoinWireCursor<'_>,
) -> Result<Option<Vec<String>>, ReplayError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_truthcoin_string_vec_value(cursor)?)),
        _ => Err(ReplayError::InvalidTruthcoinTransactionEncoding),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum DecodedTruthcoinDecisionTypeV1 {
    Binary,
    Scaled { min: f64, max: f64, increment: f64 },
    Category { options: Vec<String> },
}

#[derive(Debug, Clone, PartialEq)]
struct DecodedTruthcoinDecisionClaimEntryV1 {
    decision_id: [u8; 3],
    header: String,
    description: String,
    option_0_label: Option<String>,
    option_1_label: Option<String>,
    option_labels: Option<Vec<String>>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
struct DecodedTruthcoinDecisionClaimV1 {
    decision_type: DecodedTruthcoinDecisionTypeV1,
    decisions: Vec<DecodedTruthcoinDecisionClaimEntryV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodedTruthcoinDimensionSpecV1 {
    Single([u8; 3]),
    Categorical([u8; 3]),
}

#[derive(Debug, Clone, PartialEq)]
struct DecodedTruthcoinMarketCreationV1 {
    title: String,
    description: String,
    dimension_specs: Vec<DecodedTruthcoinDimensionSpecV1>,
    new_claims: Vec<DecodedTruthcoinDecisionClaimV1>,
    trading_fee: Option<f64>,
    tx_pow_hash_selector: Option<u8>,
    tx_pow_ordering: Option<u8>,
    tx_pow_difficulty: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedTruthcoinTradeV1 {
    market_id: [u8; 6],
    outcome_index: u32,
    shares: i64,
    trader: [u8; 20],
    limit_sats: u64,
    tx_pow_nonce: Option<u64>,
    prev_block_hash: Hash32,
}

fn decode_truthcoin_decision_claim(
    cursor: &mut TruthcoinWireCursor<'_>,
) -> Result<DecodedTruthcoinDecisionClaimV1, ReplayError> {
    let decision_type = match cursor.u8()? {
        0 => DecodedTruthcoinDecisionTypeV1::Binary,
        1 => {
            let min = cursor.f64_value()?;
            let max = cursor.f64_value()?;
            let increment = cursor.f64_value()?;
            DecodedTruthcoinDecisionTypeV1::Scaled {
                min,
                max,
                increment,
            }
        }
        2 => DecodedTruthcoinDecisionTypeV1::Category {
            options: decode_truthcoin_string_vec_value(cursor)?,
        },
        _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
    };
    let decision_count = cursor.u32_le()?;
    let mut decisions = Vec::with_capacity(decision_count.min(4_096));
    for _ in 0..decision_count {
        let decision_id = cursor
            .take(3)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
        let header = cursor.string_value()?;
        let description = cursor.string_value()?;
        let option_0_label = decode_truthcoin_optional_string(cursor)?;
        let option_1_label = decode_truthcoin_optional_string(cursor)?;
        let option_labels = decode_truthcoin_optional_string_vec(cursor)?;
        let tags = decode_truthcoin_optional_string_vec(cursor)?;
        decisions.push(DecodedTruthcoinDecisionClaimEntryV1 {
            decision_id,
            header,
            description,
            option_0_label,
            option_1_label,
            option_labels,
            tags,
        });
    }
    Ok(DecodedTruthcoinDecisionClaimV1 {
        decision_type,
        decisions,
    })
}

fn decode_truthcoin_transaction_data(
    cursor: &mut TruthcoinWireCursor<'_>,
) -> Result<DecodedTruthcoinTransactionDataV1, ReplayError> {
    let data = match cursor.u8()? {
        0 => DecodedTruthcoinTransactionDataV1::ClaimDecision(decode_truthcoin_decision_claim(
            cursor,
        )?),
        1 => {
            let title = cursor.string_value()?;
            let description = cursor.string_value()?;
            let dimension_count = cursor.u32_le()?;
            let mut dimension_specs = Vec::with_capacity(dimension_count.min(4_096));
            for _ in 0..dimension_count {
                let tag = cursor.u8()?;
                let decision_id = cursor
                    .take(3)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                dimension_specs.push(match tag {
                    0 => DecodedTruthcoinDimensionSpecV1::Single(decision_id),
                    1 => DecodedTruthcoinDimensionSpecV1::Categorical(decision_id),
                    _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
                });
            }
            let claim_count = cursor.u32_le()?;
            let mut new_claims = Vec::with_capacity(claim_count.min(4_096));
            for _ in 0..claim_count {
                new_claims.push(decode_truthcoin_decision_claim(cursor)?);
            }
            let trading_fee = cursor.optional_f64_value()?;
            let tx_pow_hash_selector = cursor.optional_u8_value()?;
            let tx_pow_ordering = cursor.optional_u8_value()?;
            let tx_pow_difficulty = cursor.optional_u8_value()?;
            DecodedTruthcoinTransactionDataV1::CreateMarket(DecodedTruthcoinMarketCreationV1 {
                title,
                description,
                dimension_specs,
                new_claims,
                trading_fee,
                tx_pow_hash_selector,
                tx_pow_ordering,
                tx_pow_difficulty,
            })
        }
        2 => {
            let market_id = cursor
                .take(6)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let outcome_index = u32::from_le_bytes(
                cursor
                    .take(4)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            let shares = i64::from_le_bytes(
                cursor
                    .take(8)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            let trader = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let limit_sats = u64::from_le_bytes(
                cursor
                    .take(8)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            let tx_pow_nonce = match cursor.u8()? {
                0 => None,
                1 => {
                    Some(u64::from_le_bytes(cursor.take(8)?.try_into().map_err(
                        |_| ReplayError::InvalidTruthcoinTransactionEncoding,
                    )?))
                }
                _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
            };
            let prev_block_hash = cursor
                .take(32)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            DecodedTruthcoinTransactionDataV1::Trade(DecodedTruthcoinTradeV1 {
                market_id,
                outcome_index,
                shares,
                trader,
                limit_sats,
                tx_pow_nonce,
                prev_block_hash,
            })
        }
        3 => {
            let voter = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let decision_id = cursor
                .take(3)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let vote_value = cursor.f64_value()?;
            let voting_period = u32::from_le_bytes(
                cursor
                    .take(4)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            DecodedTruthcoinTransactionDataV1::SubmitVote {
                voter,
                decision_id,
                vote_value,
                voting_period,
            }
        }
        4 => {
            let voter = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let vote_count = cursor.u32_le()?;
            let mut votes = Vec::with_capacity(vote_count.min(4_096));
            for _ in 0..vote_count {
                let decision_id = cursor
                    .take(3)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                let vote_value = cursor.f64_value()?;
                votes.push((decision_id, vote_value));
            }
            let voting_period = u32::from_le_bytes(
                cursor
                    .take(4)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            DecodedTruthcoinTransactionDataV1::SubmitBallot {
                voter,
                votes,
                voting_period,
            }
        }
        5 => {
            let sender = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let destination = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let amount = cursor.f64_value()?;
            DecodedTruthcoinTransactionDataV1::TransferReputation {
                sender,
                destination,
                amount,
            }
        }
        6 => {
            let market_id = cursor
                .take(6)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            let amount = u64::from_le_bytes(
                cursor
                    .take(8)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            );
            let market_author = cursor
                .take(20)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
            DecodedTruthcoinTransactionDataV1::AmplifyBeta {
                market_id,
                amount,
                market_author,
            }
        }
        _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
    };
    Ok(data)
}

#[derive(Debug, Clone, PartialEq)]
enum DecodedTruthcoinTransactionDataV1 {
    ClaimDecision(DecodedTruthcoinDecisionClaimV1),
    CreateMarket(DecodedTruthcoinMarketCreationV1),
    Trade(DecodedTruthcoinTradeV1),
    SubmitVote {
        voter: [u8; 20],
        decision_id: [u8; 3],
        vote_value: f64,
        voting_period: u32,
    },
    SubmitBallot {
        voter: [u8; 20],
        votes: Vec<([u8; 3], f64)>,
        voting_period: u32,
    },
    TransferReputation {
        sender: [u8; 20],
        destination: [u8; 20],
        amount: f64,
    },
    AmplifyBeta {
        market_id: [u8; 6],
        amount: u64,
        market_author: [u8; 20],
    },
}

#[derive(Debug, Clone, PartialEq)]
struct DecodedTruthcoinTransactionV1 {
    input_keys: Vec<[u8; 37]>,
    outputs: Vec<DecodedTruthcoinOutputV1>,
    data: Option<DecodedTruthcoinTransactionDataV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedTruthcoinOutputV1 {
    address: [u8; 20],
    content: DecodedTruthcoinOutputContentV1,
    memo: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedTruthcoinOutputContentV1 {
    Bitcoin(u64),
    Withdrawal {
        value: u64,
        main_fee: u64,
        main_address: String,
    },
    MarketFunds {
        market_id: [u8; 6],
        amount: u64,
        is_fee: bool,
    },
}

fn decode_truthcoin_transaction(
    bytes: &[u8],
) -> Result<DecodedTruthcoinTransactionV1, ReplayError> {
    let mut cursor = TruthcoinWireCursor::new(bytes);
    let input_count = cursor.u32_le()?;
    let mut input_keys = Vec::with_capacity(input_count.min(4_096));
    for _ in 0..input_count {
        let before = cursor.remaining;
        let variant = cursor.u8()?;
        match variant {
            // Regular, Coinbase, Deposit and Payout contain a 32-byte hash
            // followed by a u32 output index.
            0 | 1 | 2 | 4 => {
                cursor.take(32 + 4)?;
            }
            // MarketFunds contains MarketId([u8; 6]), height and bool.
            3 => {
                cursor.take(6 + 4)?;
                if !matches!(cursor.u8()?, 0 | 1) {
                    return Err(ReplayError::InvalidTruthcoinTransactionEncoding);
                }
            }
            _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
        }
        let encoded_len = before.len() - cursor.remaining.len();
        let mut key = [0_u8; 37];
        key[..encoded_len].copy_from_slice(&before[..encoded_len]);
        input_keys.push(key);
    }

    let output_count = cursor.u32_le()?;
    let mut outputs = Vec::with_capacity(output_count.min(4_096));
    for _ in 0..output_count {
        let address = cursor
            .take(20)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
        let content = match cursor.u8()? {
            0 => DecodedTruthcoinOutputContentV1::Bitcoin(u64::from_le_bytes(
                cursor
                    .take(8)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
            )),
            1 => {
                let value = u64::from_le_bytes(
                    cursor
                        .take(8)?
                        .try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
                );
                let main_fee = u64::from_le_bytes(
                    cursor
                        .take(8)?
                        .try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
                );
                let address_len = cursor.u32_le()?;
                let main_address = std::str::from_utf8(cursor.take(address_len)?)
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?
                    .to_owned();
                let parsed = main_address
                    .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                if parsed.assume_checked_ref().to_string() != main_address {
                    return Err(ReplayError::InvalidTruthcoinTransactionEncoding);
                }
                DecodedTruthcoinOutputContentV1::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                }
            }
            2 => {
                let market_id = cursor
                    .take(6)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                let amount = u64::from_le_bytes(
                    cursor
                        .take(8)?
                        .try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?,
                );
                let is_fee = match cursor.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
                };
                DecodedTruthcoinOutputContentV1::MarketFunds {
                    market_id,
                    amount,
                    is_fee,
                }
            }
            _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
        };
        let memo_len = cursor.u32_le()?;
        let memo = cursor.take(memo_len)?.to_vec();
        outputs.push(DecodedTruthcoinOutputV1 {
            address,
            content,
            memo,
        });
    }

    let transaction_memo_len = cursor.u32_le()?;
    cursor.take(transaction_memo_len)?;
    let data = match cursor.u8()? {
        0 => None,
        1 => Some(decode_truthcoin_transaction_data(&mut cursor)?),
        _ => return Err(ReplayError::InvalidTruthcoinTransactionEncoding),
    };
    if !cursor.remaining.is_empty() {
        return Err(ReplayError::InvalidTruthcoinTransactionEncoding);
    }
    Ok(DecodedTruthcoinTransactionV1 {
        input_keys,
        outputs,
        data,
    })
}

fn decode_truthcoin_transaction_prefix(bytes: &[u8]) -> Result<usize, ReplayError> {
    Ok(decode_truthcoin_transaction(bytes)?.input_keys.len())
}

fn decode_truthcoin_filled_output(bytes: &[u8]) -> Result<TruthcoinFilledOutputV1, ReplayError> {
    struct Cursor<'a>(&'a [u8]);
    impl<'a> Cursor<'a> {
        fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayError> {
            let value = self
                .0
                .get(..length)
                .ok_or(ReplayError::InvalidTruthcoinUtxoEncoding)?;
            self.0 = &self.0[length..];
            Ok(value)
        }
        fn u8(&mut self) -> Result<u8, ReplayError> {
            Ok(self.take(1)?[0])
        }
        fn u32(&mut self) -> Result<u32, ReplayError> {
            Ok(u32::from_le_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?,
            ))
        }
        fn u64(&mut self) -> Result<u64, ReplayError> {
            Ok(u64::from_le_bytes(
                self.take(8)?
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?,
            ))
        }
        fn vec(&mut self) -> Result<Vec<u8>, ReplayError> {
            let length = usize::try_from(self.u64()?)
                .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?;
            Ok(self.take(length)?.to_vec())
        }
    }

    let mut cursor = Cursor(bytes);
    let address = cursor
        .take(20)?
        .try_into()
        .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?;
    let content = match cursor.u32()? {
        0 => TruthcoinFilledContentV1::Bitcoin(cursor.u64()?),
        1 => {
            let value = cursor.u64()?;
            let main_fee = cursor.u64()?;
            let display_length = usize::try_from(cursor.u64()?)
                .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?;
            let main_address = std::str::from_utf8(cursor.take(display_length)?)
                .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?
                .to_owned();
            let parsed = main_address
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?;
            if parsed.assume_checked_ref().to_string() != main_address {
                return Err(ReplayError::InvalidTruthcoinUtxoEncoding);
            }
            TruthcoinFilledContentV1::BitcoinWithdrawal(TruthcoinWithdrawalContentV1 {
                value,
                main_fee,
                main_address,
            })
        }
        2 => {
            let market_id = cursor
                .take(6)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinUtxoEncoding)?;
            let amount = cursor.u64()?;
            let is_fee = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ReplayError::InvalidTruthcoinUtxoEncoding),
            };
            TruthcoinFilledContentV1::MarketFunds {
                market_id,
                amount,
                is_fee,
            }
        }
        _ => return Err(ReplayError::InvalidTruthcoinUtxoEncoding),
    };
    let memo = cursor.vec()?;
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinUtxoEncoding);
    }
    Ok(TruthcoinFilledOutputV1 {
        address,
        content,
        memo,
    })
}

/// Bind every flattened input authorization to the address of the exact UTXO
/// it spends in a canonical checkpoint. Signature validity and transaction
/// mapping are rechecked here so callers cannot accidentally use this as a
/// standalone ownership-only predicate.
pub fn validate_truthcoin_utxo_ownership(
    store: &CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
) -> Result<(), ReplayError> {
    validate_truthcoin_authorization_envelopes(body)?;
    let authorization_payload = body
        .authorizations_borsh
        .get(4..)
        .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?;
    let mut authorizations = authorization_payload.chunks_exact(TRUTHCOIN_AUTHORIZATION_WIRE_BYTES);
    for transaction_bytes in &body.transactions_borsh {
        let transaction = decode_truthcoin_transaction(transaction_bytes)?;
        for input_key in transaction.input_keys {
            let authorization = authorizations
                .next()
                .ok_or(ReplayError::InvalidTruthcoinAuthorization)?;
            let utxo_bytes = store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &input_key)?
                .ok_or(ReplayError::MissingTruthcoinUtxo)?;
            let utxo = decode_truthcoin_filled_output(utxo_bytes)?;
            let mut expected_address = [0_u8; 20];
            blake3::Hasher::new()
                .update(&authorization[..32])
                .finalize_xof()
                .fill(&mut expected_address);
            if utxo.address != expected_address {
                return Err(ReplayError::WrongTruthcoinAuthorizationAddress);
            }
        }
    }
    if authorizations.next().is_some() || !authorizations.remainder().is_empty() {
        return Err(ReplayError::InvalidTruthcoinAuthorization);
    }
    Ok(())
}

fn encode_truthcoin_filled_output(
    output: &DecodedTruthcoinOutputV1,
) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = output.address.to_vec();
    match &output.content {
        DecodedTruthcoinOutputContentV1::Bitcoin(amount) => {
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&amount.to_le_bytes());
        }
        DecodedTruthcoinOutputContentV1::Withdrawal {
            value,
            main_fee,
            main_address,
        } => {
            bytes.extend_from_slice(&1_u32.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&main_fee.to_le_bytes());
            bytes.extend_from_slice(&(main_address.len() as u64).to_le_bytes());
            bytes.extend_from_slice(main_address.as_bytes());
        }
        DecodedTruthcoinOutputContentV1::MarketFunds {
            market_id,
            amount,
            is_fee,
        } => {
            bytes.extend_from_slice(&2_u32.to_le_bytes());
            bytes.extend_from_slice(market_id);
            bytes.extend_from_slice(&amount.to_le_bytes());
            bytes.push(u8::from(*is_fee));
        }
    }
    bytes.extend_from_slice(&(output.memo.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&output.memo);
    Ok(bytes)
}

fn truthcoin_address_index_key(address: [u8; 20], outpoint_key: &[u8; 37]) -> Vec<u8> {
    let mut key = address.to_vec();
    key.extend_from_slice(&u32::from(outpoint_key[0]).to_le_bytes());
    let payload_len = match outpoint_key[0] {
        0 | 1 | 2 | 4 => 32 + 4,
        3 => 6 + 4 + 1,
        _ => 0,
    };
    // bitcoin::OutPoint's serde representation length-prefixes its Txid byte
    // string, unlike Truthcoin's native Regular/Coinbase hash wrappers.
    if outpoint_key[0] == 2 {
        key.extend_from_slice(&32_u64.to_le_bytes());
    }
    key.extend_from_slice(&outpoint_key[1..1 + payload_len]);
    key
}

/// Apply one already-authenticated BIP300 deposit event to the canonical
/// Truthcoin UTXO tables. The enclosing replay verifier is responsible for
/// authenticating the Bitcoin transaction, its block position, CTIP ancestry,
/// sidechain number, value delta, address encoding, and application order.
///
/// This narrow transition mirrors `two_way_peg_data::connect_2wpd_event` in
/// pinned Truthcoin 0.17.0. It is public so differential tooling can validate
/// deposit-aware replay without treating host-provided deposit data as proof.
pub fn apply_authenticated_truthcoin_deposit(
    store: &mut CanonicalStateStoreV1,
    bitcoin_txid: Hash32,
    vout: u32,
    address: [u8; 20],
    value_sats: u64,
) -> Result<(), ReplayError> {
    let mut outpoint_key = [0_u8; 37];
    outpoint_key[0] = 2;
    outpoint_key[1..33].copy_from_slice(&bitcoin_txid);
    outpoint_key[33..].copy_from_slice(&vout.to_le_bytes());
    let output = DecodedTruthcoinOutputV1 {
        address,
        content: DecodedTruthcoinOutputContentV1::Bitcoin(value_sats),
        memo: Vec::new(),
    };
    let output_value = encode_truthcoin_filled_output(&output)?;
    store.transaction(|candidate| {
        if candidate
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                outpoint_key.to_vec(),
                output_value,
            )?
            .is_some()
        {
            return Err(ReplayError::DuplicateTruthcoinUtxo);
        }
        let address_key = truthcoin_address_index_key(address, &outpoint_key);
        if candidate
            .put(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                address_key,
                Vec::new(),
            )?
            .is_some()
        {
            return Err(ReplayError::InvalidTruthcoinUtxoIndex);
        }
        Ok(())
    })
}

/// Apply a previously authenticated, ordered deposit batch after connecting
/// its child, atomically including the native deposit-history record.
/// Callers must authenticate the complete parent/CTIP lineage and select only
/// deposits reached by this child. This function does not authenticate inputs.
pub fn apply_authenticated_truthcoin_deposit_batch(
    store: &mut CanonicalStateStoreV1,
    deposits: &[AuthenticatedTruthcoinDepositV1],
    child_height: u64,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for deposit in deposits {
            apply_authenticated_truthcoin_deposit(candidate, deposit.txid,
                deposit.vout, deposit.address, deposit.value_sats)?;
        }
        record_truthcoin_deposit_batch(candidate, deposits, child_height)
    })
}

// Native connect_two_way_peg_data records one entry per nonempty batch, using
// the last deposit's parent hash and the newly connected child height. The
// batch index is distinct from the parent CTIP/deposit sequence number.
fn record_truthcoin_deposit_batch(
    store: &mut CanonicalStateStoreV1,
    deposits: &[AuthenticatedTruthcoinDepositV1],
    child_height: u64,
) -> Result<(), ReplayError> {
    let Some(last) = deposits.last() else { return Ok(()); };
    type Codec = TypedCanonicalDatabaseV1<u32, (bitcoin::BlockHash, u32)>;
    let database = TruthcoinDatabaseId::DepositBlocks.as_u8();
    // Match the native database's lexicographic key order, not CTIP order.
    let sequence = match store.entries(database)?.last() {
        None => 0,
        Some((key, _)) => Codec::decode_canonical::<u32>(key)?
            .checked_add(1).ok_or(ReplayError::InvalidCanonicalStateSnapshot)?,
    };
    let height = u32::try_from(child_height)
        .map_err(|_| ReplayError::InvalidCanonicalStateSnapshot)?;
    let value = (bitcoin::BlockHash::from_byte_array(last.mainchain_block_hash), height);
    store.put(database, Codec::encode(&sequence)?, Codec::encode(&value)?)?;
    Ok(())
}

fn truthcoin_regular_outpoint_key(txid: Hash32, vout: u32) -> [u8; 37] {
    let mut key = [0_u8; 37];
    key[0] = 0;
    key[1..33].copy_from_slice(&txid);
    key[33..37].copy_from_slice(&vout.to_le_bytes());
    key
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinBaseUtxoUndoV1 {
    spent: Vec<([u8; 37], Vec<u8>)>,
    created: Vec<[u8; 37]>,
}

#[derive(Debug, Clone, PartialEq)]
struct TruthcoinReputationTransferUndoEntryV1 {
    sender: [u8; 20],
    sender_pre_reputation: f64,
    receiver: [u8; 20],
    receiver_pre_reputation: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinReputationTransitionUndoV1 {
    height_key: [u8; 4],
    prior_undo_value: Option<Vec<u8>>,
}

struct TruthcoinBincodeCursor<'a>(&'a [u8]);

impl<'a> TruthcoinBincodeCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayError> {
        let value = self
            .0
            .get(..length)
            .ok_or(ReplayError::InvalidTruthcoinVotingState)?;
        self.0 = &self.0[length..];
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ReplayError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ReplayError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
        ))
    }

    fn f64(&mut self) -> Result<f64, ReplayError> {
        let value = f64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
        );
        if value.is_nan() {
            return Err(ReplayError::InvalidTruthcoinVotingState);
        }
        Ok(value)
    }

    fn length(&mut self) -> Result<usize, ReplayError> {
        usize::try_from(self.u64()?).map_err(|_| ReplayError::InvalidTruthcoinVotingState)
    }

    fn string(&mut self) -> Result<(), ReplayError> {
        self.string_value().map(|_| ())
    }

    fn string_value(&mut self) -> Result<String, ReplayError> {
        let length = self.length()?;
        Ok(std::str::from_utf8(self.take(length)?)
            .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?
            .to_owned())
    }

    fn option(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<(), ReplayError>,
    ) -> Result<(), ReplayError> {
        match self.u8()? {
            0 => Ok(()),
            1 => decode(self),
            _ => Err(ReplayError::InvalidTruthcoinVotingState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TruthcoinDecisionKindV1 {
    Binary,
    Scaled,
    Category(usize),
}

#[derive(Debug, Clone, PartialEq)]
struct TruthcoinStoredDecisionV1 {
    market_maker: [u8; 20],
    decision_type: DecodedTruthcoinDecisionTypeV1,
    header: String,
    description: String,
    option_0_label: Option<String>,
    option_1_label: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct TruthcoinStoredDecisionEntryV1 {
    decision_id: [u8; 3],
    decision: Option<TruthcoinStoredDecisionV1>,
    claiming_txid: Hash32,
}

fn decode_truthcoin_bincode_string_vec(
    cursor: &mut TruthcoinBincodeCursor<'_>,
) -> Result<Vec<String>, ReplayError> {
    let count = cursor.length()?;
    if count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let mut values = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        values.push(cursor.string_value()?);
    }
    Ok(values)
}

fn decode_truthcoin_bincode_optional_string(
    cursor: &mut TruthcoinBincodeCursor<'_>,
) -> Result<Option<String>, ReplayError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.string_value()?)),
        _ => Err(ReplayError::InvalidTruthcoinDecisionState),
    }
}

fn decode_truthcoin_stored_decision(
    cursor: &mut TruthcoinBincodeCursor<'_>,
) -> Result<TruthcoinStoredDecisionV1, ReplayError> {
    let market_maker = cursor
        .take(20)?
        .try_into()
        .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
    let decision_type = match cursor.u32()? {
        0 => DecodedTruthcoinDecisionTypeV1::Binary,
        1 => DecodedTruthcoinDecisionTypeV1::Scaled {
            min: cursor.f64()?,
            max: cursor.f64()?,
            increment: cursor.f64()?,
        },
        2 => DecodedTruthcoinDecisionTypeV1::Category {
            options: decode_truthcoin_bincode_string_vec(cursor)?,
        },
        _ => return Err(ReplayError::InvalidTruthcoinDecisionState),
    };
    Ok(TruthcoinStoredDecisionV1 {
        market_maker,
        decision_type,
        header: cursor.string_value()?,
        description: cursor.string_value()?,
        option_0_label: decode_truthcoin_bincode_optional_string(cursor)?,
        option_1_label: decode_truthcoin_bincode_optional_string(cursor)?,
        tags: decode_truthcoin_bincode_string_vec(cursor)?,
    })
}

fn decode_truthcoin_period_decisions(
    bytes: &[u8],
) -> Result<Vec<TruthcoinStoredDecisionEntryV1>, ReplayError> {
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let count = cursor.length()?;
    if count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let mut entries = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        let decision_id = cursor
            .take(3)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
        let decision = match cursor.u8()? {
            0 => None,
            1 => Some(decode_truthcoin_stored_decision(&mut cursor)?),
            _ => return Err(ReplayError::InvalidTruthcoinDecisionState),
        };
        let claiming_txid = cursor
            .take(32)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
        entries.push(TruthcoinStoredDecisionEntryV1 {
            decision_id,
            decision,
            claiming_txid,
        });
    }
    if !cursor.0.is_empty()
        || entries
            .windows(2)
            .any(|pair| pair[0].decision_id >= pair[1].decision_id)
    {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(entries)
}

fn put_bincode_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ReplayError> {
    bytes.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bincode_string_vec(bytes: &mut Vec<u8>, values: &[String]) -> Result<(), ReplayError> {
    bytes.extend_from_slice(
        &u64::try_from(values.len())
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?
            .to_le_bytes(),
    );
    for value in values {
        put_bincode_string(bytes, value)?;
    }
    Ok(())
}

fn put_bincode_optional_string(
    bytes: &mut Vec<u8>,
    value: &Option<String>,
) -> Result<(), ReplayError> {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_bincode_string(bytes, value)?;
        }
    }
    Ok(())
}

fn encode_truthcoin_period_decisions(
    entries: &[TruthcoinStoredDecisionEntryV1],
) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u64::try_from(entries.len())
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?
            .to_le_bytes(),
    );
    for entry in entries {
        bytes.extend_from_slice(&entry.decision_id);
        match &entry.decision {
            None => bytes.push(0),
            Some(decision) => {
                bytes.push(1);
                bytes.extend_from_slice(&decision.market_maker);
                match &decision.decision_type {
                    DecodedTruthcoinDecisionTypeV1::Binary => {
                        bytes.extend_from_slice(&0_u32.to_le_bytes())
                    }
                    DecodedTruthcoinDecisionTypeV1::Scaled {
                        min,
                        max,
                        increment,
                    } => {
                        bytes.extend_from_slice(&1_u32.to_le_bytes());
                        bytes.extend_from_slice(&min.to_le_bytes());
                        bytes.extend_from_slice(&max.to_le_bytes());
                        bytes.extend_from_slice(&increment.to_le_bytes());
                    }
                    DecodedTruthcoinDecisionTypeV1::Category { options } => {
                        bytes.extend_from_slice(&2_u32.to_le_bytes());
                        put_bincode_string_vec(&mut bytes, options)?;
                    }
                }
                put_bincode_string(&mut bytes, &decision.header)?;
                put_bincode_string(&mut bytes, &decision.description)?;
                put_bincode_optional_string(&mut bytes, &decision.option_0_label)?;
                put_bincode_optional_string(&mut bytes, &decision.option_1_label)?;
                put_bincode_string_vec(&mut bytes, &decision.tags)?;
            }
        }
        bytes.extend_from_slice(&entry.claiming_txid);
    }
    Ok(bytes)
}

fn truthcoin_decision_period(decision_id: [u8; 3]) -> u32 {
    u32::from(decision_id[0] & 0x7f) + 1
}

fn decode_truthcoin_decision_kind(
    store: &CanonicalStateStoreV1,
    decision_id: [u8; 3],
) -> Result<TruthcoinDecisionKindV1, ReplayError> {
    let period_key = u32::from(decision_id[0] & 0x7f).to_le_bytes();
    let bytes = store
        .get(TruthcoinDatabaseId::PeriodDecisions.as_u8(), &period_key)?
        .ok_or(ReplayError::InvalidTruthcoinVote)?;
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let count = cursor.length()?;
    if count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinVotingState);
    }
    let mut found = None;
    for _ in 0..count {
        let id: [u8; 3] = cursor
            .take(3)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
        let decision = match cursor.u8()? {
            0 => None,
            1 => {
                cursor.take(20)?;
                let kind = match cursor.u32()? {
                    0 => TruthcoinDecisionKindV1::Binary,
                    1 => {
                        cursor.f64()?;
                        cursor.f64()?;
                        cursor.f64()?;
                        TruthcoinDecisionKindV1::Scaled
                    }
                    2 => {
                        let options = cursor.length()?;
                        if !(2..=MAX_STATE_TABLE_ENTRIES).contains(&options) {
                            return Err(ReplayError::InvalidTruthcoinVotingState);
                        }
                        for _ in 0..options {
                            cursor.string()?;
                        }
                        TruthcoinDecisionKindV1::Category(options)
                    }
                    _ => return Err(ReplayError::InvalidTruthcoinVotingState),
                };
                cursor.string()?;
                cursor.string()?;
                cursor.option(|cursor| cursor.string())?;
                cursor.option(|cursor| cursor.string())?;
                let tags = cursor.length()?;
                if tags > MAX_MARKET_TEMPLATE_TAGS {
                    return Err(ReplayError::InvalidTruthcoinVotingState);
                }
                for _ in 0..tags {
                    cursor.string()?;
                }
                Some(kind)
            }
            _ => return Err(ReplayError::InvalidTruthcoinVotingState),
        };
        cursor.take(32)?;
        if id == decision_id {
            found = decision;
        }
    }
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinVotingState);
    }
    found.ok_or(ReplayError::InvalidTruthcoinVote)
}

fn truthcoin_decision_is_voting(
    store: &CanonicalStateStoreV1,
    decision_id: [u8; 3],
) -> Result<bool, ReplayError> {
    let bytes = store
        .get(
            TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
            &decision_id,
        )?
        .ok_or(ReplayError::InvalidTruthcoinVote)?;
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let count = cursor.length()?;
    if count == 0 || count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinVotingState);
    }
    let mut last_state = 0;
    for _ in 0..count {
        last_state = cursor.u32()?;
        if last_state > 4 {
            return Err(ReplayError::InvalidTruthcoinVotingState);
        }
        cursor.u32()?;
        cursor.option(|cursor| cursor.f64().map(|_| ()))?;
    }
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinVotingState);
    }
    Ok(last_state == 2)
}

fn truthcoin_actor_addresses(body: &TruthcoinBodyV1) -> Result<Vec<Option<[u8; 20]>>, ReplayError> {
    validate_truthcoin_authorization_envelopes(body)?;
    let mut cursor = TruthcoinWireCursor::new(&body.actor_proofs_borsh);
    let count = cursor.u32_le()?;
    if count != body.transactions_borsh.len() {
        return Err(ReplayError::InvalidTruthcoinBodyEncoding);
    }
    let mut actors = Vec::with_capacity(count);
    for _ in 0..count {
        match cursor.u8()? {
            0 => actors.push(None),
            1 => {
                let public_key = cursor.take(32)?;
                cursor.take(64)?;
                let mut address = [0_u8; 20];
                blake3::Hasher::new()
                    .update(public_key)
                    .finalize_xof()
                    .fill(&mut address);
                actors.push(Some(address));
            }
            _ => return Err(ReplayError::InvalidTruthcoinBodyEncoding),
        }
    }
    if !cursor.remaining.is_empty() {
        return Err(ReplayError::InvalidTruthcoinBodyEncoding);
    }
    Ok(actors)
}

fn truthcoin_vote_key(period: u32, voter: [u8; 20], decision_id: [u8; 3]) -> Vec<u8> {
    let mut key = period.to_le_bytes().to_vec();
    key.extend_from_slice(&voter);
    key.extend_from_slice(&decision_id);
    key
}

fn truthcoin_vote_value(
    kind: TruthcoinDecisionKindV1,
    wire_value: f64,
    timestamp: u64,
    height: u32,
) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();
    if wire_value == -1.0 {
        bytes.extend_from_slice(&3_u32.to_le_bytes());
    } else {
        match kind {
            TruthcoinDecisionKindV1::Category(options) => {
                if !wire_value.is_finite()
                    || wire_value < 0.0
                    || wire_value.fract() != 0.0
                    || wire_value > options as f64
                {
                    return Err(ReplayError::InvalidTruthcoinVote);
                }
                bytes.extend_from_slice(&2_u32.to_le_bytes());
                bytes.extend_from_slice(&(wire_value as u16).to_le_bytes());
            }
            TruthcoinDecisionKindV1::Binary | TruthcoinDecisionKindV1::Scaled => {
                if !wire_value.is_finite() || !(0.0..=1.0).contains(&wire_value) {
                    return Err(ReplayError::InvalidTruthcoinVote);
                }
                if wire_value == 0.0 || wire_value == 1.0 {
                    bytes.extend_from_slice(&0_u32.to_le_bytes());
                    bytes.push(u8::from(wire_value == 1.0));
                } else {
                    bytes.extend_from_slice(&1_u32.to_le_bytes());
                    bytes.extend_from_slice(&wire_value.to_le_bytes());
                }
            }
        }
    }
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinVotingTransitionUndoV1 {
    inserted: Vec<(Vec<u8>, Vec<u8>)>,
}

pub fn apply_truthcoin_voting_transitions(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinVotingTransitionUndoV1, ReplayError> {
    validate_truthcoin_utxo_ownership(store, body)?;
    let actors = truthcoin_actor_addresses(body)?;
    let timestamp_bytes = store
        .get(
            TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )?
        .ok_or(ReplayError::InvalidTruthcoinVotingState)?;
    let timestamp = u64::from_le_bytes(
        timestamp_bytes
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
    );
    let existing_vote_keys: BTreeSet<Vec<u8>> = store
        .entries(TruthcoinDatabaseId::Votes.as_u8())?
        .map(|(key, _)| key.to_vec())
        .collect();
    store.transaction(|candidate| {
        let mut inserted = Vec::new();
        for (transaction_bytes, actor) in body.transactions_borsh.iter().zip(actors) {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let votes = match transaction.data {
                Some(DecodedTruthcoinTransactionDataV1::SubmitVote {
                    voter,
                    decision_id,
                    vote_value,
                    voting_period,
                }) => {
                    vec![(voter, decision_id, vote_value, voting_period)]
                }
                Some(DecodedTruthcoinTransactionDataV1::SubmitBallot {
                    voter,
                    votes,
                    voting_period,
                }) => votes
                    .into_iter()
                    .map(|(decision_id, vote_value)| {
                        (voter, decision_id, vote_value, voting_period)
                    })
                    .collect(),
                _ => continue,
            };
            let mut voter_input_addresses = BTreeSet::new();
            for input_key in &transaction.input_keys {
                let output = candidate
                    .get(TruthcoinDatabaseId::Utxos.as_u8(), input_key)?
                    .ok_or(ReplayError::MissingTruthcoinUtxo)?;
                voter_input_addresses.insert(decode_truthcoin_filled_output(output)?.address);
            }
            let mut seen = BTreeSet::new();
            for (voter, decision_id, wire_value, declared_period) in votes {
                let period = truthcoin_decision_period(decision_id);
                let period_matches = declared_period == period;
                let voter_authorized =
                    voter_input_addresses.contains(&voter) || actor == Some(voter);
                let reputation_positive = get_truthcoin_reputation(candidate, &voter)? > 0.0;
                let decision_voting = truthcoin_decision_is_voting(candidate, decision_id)?;
                let vote_unique = seen.insert((voter, decision_id));
                if !period_matches
                    || !voter_authorized
                    || !reputation_positive
                    || !decision_voting
                    || !vote_unique
                {
                    return Err(ReplayError::InvalidTruthcoinVote);
                }
                let kind = decode_truthcoin_decision_kind(candidate, decision_id)?;
                let key = truthcoin_vote_key(period, voter, decision_id);
                if existing_vote_keys.contains(&key) {
                    return Err(ReplayError::InvalidTruthcoinVote);
                }
                let value = truthcoin_vote_value(kind, wire_value, timestamp, height)?;
                candidate.put(
                    TruthcoinDatabaseId::Votes.as_u8(),
                    key.clone(),
                    value.clone(),
                )?;
                if let Some((_, prior_value)) =
                    inserted.iter_mut().find(|(prior_key, _)| *prior_key == key)
                {
                    *prior_value = value;
                } else {
                    inserted.push((key, value));
                }
            }
        }
        Ok(TruthcoinVotingTransitionUndoV1 { inserted })
    })
}

pub fn revert_truthcoin_voting_transitions(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinVotingTransitionUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for (key, expected_value) in undo.inserted.iter().rev() {
            let actual = candidate
                .delete(TruthcoinDatabaseId::Votes.as_u8(), key)?
                .ok_or(ReplayError::InvalidTruthcoinVotingState)?;
            if actual != *expected_value {
                return Err(ReplayError::InvalidTruthcoinVotingState);
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TruthcoinExactTableChangeV1 {
    database: TruthcoinDatabaseId,
    key: Vec<u8>,
    prior: Option<Vec<u8>>,
    successor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinDecisionClaimUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

fn validate_truthcoin_decision_claim_payload(
    claim: &DecodedTruthcoinDecisionClaimV1,
) -> Result<(), ReplayError> {
    if claim.decisions.len() != 1 {
        return Err(ReplayError::InvalidTruthcoinDecisionClaim);
    }
    let entry = &claim.decisions[0];
    if entry.header.len() > 100
        || entry.description.len() > 2_000
        || entry.tags.as_ref().is_some_and(|tags| {
            tags.len() > MAX_MARKET_TEMPLATE_TAGS || tags.iter().any(|tag| tag.len() > 50)
        })
    {
        return Err(ReplayError::InvalidTruthcoinDecisionClaim);
    }
    match &claim.decision_type {
        DecodedTruthcoinDecisionTypeV1::Binary => {
            if entry.option_labels.is_some() {
                return Err(ReplayError::InvalidTruthcoinDecisionClaim);
            }
        }
        DecodedTruthcoinDecisionTypeV1::Scaled {
            min,
            max,
            increment,
        } => {
            let steps = (max - min) / increment;
            let tolerance = increment.abs().mul_add(1e-9, 0.0).max(1e-12);
            if entry.option_labels.is_some()
                || !min.is_finite()
                || !max.is_finite()
                || !increment.is_finite()
                || min >= max
                || *increment <= 0.0
                || ((max - min) - steps.round() * increment).abs() > tolerance
            {
                return Err(ReplayError::InvalidTruthcoinDecisionClaim);
            }
        }
        DecodedTruthcoinDecisionTypeV1::Category { options } => {
            if options.len() < 2 || entry.option_labels.as_ref() != Some(options) {
                return Err(ReplayError::InvalidTruthcoinDecisionClaim);
            }
        }
    }
    Ok(())
}

fn truthcoin_claims(
    data: Option<DecodedTruthcoinTransactionDataV1>,
) -> Vec<DecodedTruthcoinDecisionClaimV1> {
    match data {
        Some(DecodedTruthcoinTransactionDataV1::ClaimDecision(claim)) => vec![claim],
        Some(DecodedTruthcoinTransactionDataV1::CreateMarket(creation)) => creation.new_claims,
        _ => Vec::new(),
    }
}

fn truthcoin_period_pricing_increment_claimed(bytes: &[u8]) -> Result<Vec<u8>, ReplayError> {
    if bytes.len() != 52 {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let mut successor = bytes.to_vec();
    let claimed = u64::from_le_bytes(
        successor[24..32]
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
    )
    .checked_add(1)
    .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)?;
    successor[24..32].copy_from_slice(&claimed.to_le_bytes());
    Ok(successor)
}

fn truthcoin_filled_bitcoin_value(output: &TruthcoinFilledOutputV1) -> Result<u64, ReplayError> {
    match &output.content {
        TruthcoinFilledContentV1::Bitcoin(value) => Ok(*value),
        // Pinned upstream `WithdrawalContent::get_bitcoin_value` maps an
        // overflowing withdrawal value to Amount::MAX. The enclosing sum is
        // still checked, exactly like `Iterator::checked_sum` upstream.
        TruthcoinFilledContentV1::BitcoinWithdrawal(withdrawal) => Ok(withdrawal
            .value
            .checked_add(withdrawal.main_fee)
            .unwrap_or(u64::MAX)),
        TruthcoinFilledContentV1::MarketFunds { amount, .. } => Ok(*amount),
    }
}

fn truthcoin_output_bitcoin_value(output: &DecodedTruthcoinOutputV1) -> Result<u64, ReplayError> {
    match &output.content {
        DecodedTruthcoinOutputContentV1::Bitcoin(value) => Ok(*value),
        DecodedTruthcoinOutputContentV1::Withdrawal {
            value, main_fee, ..
        } => Ok(value.checked_add(*main_fee).unwrap_or(u64::MAX)),
        DecodedTruthcoinOutputContentV1::MarketFunds { amount, .. } => Ok(*amount),
    }
}

fn truthcoin_transaction_fee(
    store: &CanonicalStateStoreV1,
    transaction: &DecodedTruthcoinTransactionV1,
) -> Result<u64, ReplayError> {
    let input_value = transaction.input_keys.iter().try_fold(0_u64, |sum, key| {
        let output = decode_truthcoin_filled_output(
            store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                .ok_or(ReplayError::MissingTruthcoinUtxo)?,
        )?;
        sum.checked_add(truthcoin_filled_bitcoin_value(&output)?)
            .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)
    })?;
    let output_value = transaction.outputs.iter().try_fold(0_u64, |sum, output| {
        sum.checked_add(truthcoin_output_bitcoin_value(output)?)
            .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)
    })?;
    input_value
        .checked_sub(output_value)
        .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)
}

fn truthcoin_standard_listing_fee(
    pricing: TruthcoinPeriodPricingV1,
    decision_index: u32,
) -> Result<u64, ReplayError> {
    if decision_index >= 500 || u64::from(decision_index % 100) >= pricing.mints.saturating_mul(5) {
        return Err(ReplayError::InvalidTruthcoinDecisionClaim);
    }
    let numerator = [1_u64, 2, 4, 8, 16][decision_index as usize / 100];
    Ok(pricing.p_period.saturating_mul(numerator) / 4)
}

pub fn validate_truthcoin_decision_claims(
    store: &CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
) -> Result<(), ReplayError> {
    validate_truthcoin_utxo_ownership(store, body)?;
    let timestamp = match store.get(
        TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
        &TRUTHCOIN_UNIT_KEY,
    )? {
        Some(bytes) => u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
        ),
        None => 0,
    };
    let genesis = match store.get(
        TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
        &TRUTHCOIN_UNIT_KEY,
    )? {
        Some(bytes) => u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
        ),
        None => 0,
    };
    let current_period = truthcoin_current_period(timestamp, genesis)?;
    let mut claimed_ids = BTreeSet::new();
    for transaction_bytes in &body.transactions_borsh {
        let transaction = decode_truthcoin_transaction(transaction_bytes)?;
        let claims = truthcoin_claims(transaction.data.clone());
        if claims.is_empty() {
            continue;
        }
        if transaction.input_keys.is_empty() {
            return Err(ReplayError::InvalidTruthcoinDecisionClaim);
        }
        let transaction_fee = truthcoin_transaction_fee(store, &transaction)?;
        let mut required_listing_fee = 0_u64;
        for claim in &claims {
            validate_truthcoin_decision_claim_payload(claim)?;
            let entry = &claim.decisions[0];
            if !claimed_ids.insert(entry.decision_id) {
                return Err(ReplayError::InvalidTruthcoinDecisionClaim);
            }
            let period = u32::from(entry.decision_id[0] & 0x7f);
            if current_period > period.saturating_add(7)
                || period > current_period.saturating_add(TRUTHCOIN_FUTURE_PERIODS - 1)
            {
                return Err(ReplayError::InvalidTruthcoinDecisionClaim);
            }
            let period_key = period.to_le_bytes();
            if let Some(bytes) =
                store.get(TruthcoinDatabaseId::PeriodDecisions.as_u8(), &period_key)?
            {
                if decode_truthcoin_period_decisions(bytes)?
                    .iter()
                    .any(|existing| existing.decision_id == entry.decision_id)
                {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
            }
            if let Some(bytes) = store.get(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                &entry.decision_id,
            )? {
                let history = decode_truthcoin_state_history(bytes)?;
                if history.last().is_some_and(|state| state.0 == 2) {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
            }
            if entry.decision_id[0] & 0x80 != 0 {
                if period < current_period
                    || period > current_period.saturating_add(TRUTHCOIN_FUTURE_PERIODS - 1)
                {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
                let pricing = decode_truthcoin_period_pricing(
                    store
                        .get(TruthcoinDatabaseId::PeriodPricing.as_u8(), &period_key)?
                        .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)?,
                )?;
                let decision_index =
                    u32::from_be_bytes([0, 0, entry.decision_id[1], entry.decision_id[2]]);
                required_listing_fee = required_listing_fee
                    .checked_add(truthcoin_standard_listing_fee(pricing, decision_index)?)
                    .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)?;
            }
        }
        if transaction_fee < required_listing_fee {
            return Err(ReplayError::InvalidTruthcoinDecisionClaim);
        }
    }
    Ok(())
}

/// Apply the exact Decision-table mutations performed by standalone claims and
/// embedded market claims. Block-wide time/window/listing-fee validation is a
/// separate port slice and must run before this mutator in the linked engine.
pub fn apply_truthcoin_decision_claim_mutations(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinDecisionClaimUndoV1, ReplayError> {
    validate_truthcoin_decision_claims(store, body)?;
    apply_prevalidated_truthcoin_decision_claim_mutations(store, body, height)
}

// Only the full block connector may use this after validation against the
// pre-block state. Native prevalidation observes the previous stored clock,
// before connect transitions existing decisions to Voting.
fn apply_prevalidated_truthcoin_decision_claim_mutations(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinDecisionClaimUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let mut changes = Vec::new();
        let mut claimed_ids = BTreeSet::new();
        for transaction_bytes in &body.transactions_borsh {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let claims = truthcoin_claims(transaction.data);
            if claims.is_empty() {
                continue;
            }
            let first_input = transaction
                .input_keys
                .first()
                .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)?;
            let creator = decode_truthcoin_filled_output(
                candidate
                    .get(TruthcoinDatabaseId::Utxos.as_u8(), first_input)?
                    .ok_or(ReplayError::MissingTruthcoinUtxo)?,
            )?
            .address;
            let txid = *blake3::hash(transaction_bytes).as_bytes();
            for claim in claims {
                validate_truthcoin_decision_claim_payload(&claim)?;
                let entry = &claim.decisions[0];
                if !claimed_ids.insert(entry.decision_id) {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
                let period = u32::from(entry.decision_id[0] & 0x7f);
                let period_key = period.to_le_bytes().to_vec();
                let prior_period = candidate
                    .get(TruthcoinDatabaseId::PeriodDecisions.as_u8(), &period_key)?
                    .map(ToOwned::to_owned);
                let mut entries = prior_period
                    .as_deref()
                    .map(decode_truthcoin_period_decisions)
                    .transpose()?
                    .unwrap_or_default();
                if entries
                    .iter()
                    .any(|existing| existing.decision_id == entry.decision_id)
                {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
                entries.push(TruthcoinStoredDecisionEntryV1 {
                    decision_id: entry.decision_id,
                    decision: Some(TruthcoinStoredDecisionV1 {
                        market_maker: creator,
                        decision_type: claim.decision_type,
                        header: entry.header.clone(),
                        description: entry.description.clone(),
                        option_0_label: entry.option_0_label.clone(),
                        option_1_label: entry.option_1_label.clone(),
                        tags: entry.tags.clone().unwrap_or_default(),
                    }),
                    claiming_txid: txid,
                });
                entries.sort_by_key(|stored| stored.decision_id);
                let successor_period = encode_truthcoin_period_decisions(&entries)?;
                candidate.put(
                    TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                    period_key.clone(),
                    successor_period.clone(),
                )?;
                changes.push(TruthcoinExactTableChangeV1 {
                    database: TruthcoinDatabaseId::PeriodDecisions,
                    key: period_key.clone(),
                    prior: prior_period,
                    successor: successor_period,
                });

                let history_key = entry.decision_id.to_vec();
                let prior_history = candidate
                    .get(
                        TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                        &history_key,
                    )?
                    .map(ToOwned::to_owned);
                if prior_history.is_some() {
                    return Err(ReplayError::InvalidTruthcoinDecisionClaim);
                }
                let mut successor_history = 1_u64.to_le_bytes().to_vec();
                successor_history.extend_from_slice(&1_u32.to_le_bytes());
                successor_history.extend_from_slice(&height.to_le_bytes());
                successor_history.push(0);
                candidate.put(
                    TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                    history_key.clone(),
                    successor_history.clone(),
                )?;
                changes.push(TruthcoinExactTableChangeV1 {
                    database: TruthcoinDatabaseId::DecisionStateHistories,
                    key: history_key,
                    prior: None,
                    successor: successor_history,
                });

                if entry.decision_id[0] & 0x80 != 0 {
                    let prior_pricing = candidate
                        .get(TruthcoinDatabaseId::PeriodPricing.as_u8(), &period_key)?
                        .ok_or(ReplayError::InvalidTruthcoinDecisionClaim)?
                        .to_vec();
                    let successor_pricing =
                        truthcoin_period_pricing_increment_claimed(&prior_pricing)?;
                    candidate.put(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        period_key.clone(),
                        successor_pricing.clone(),
                    )?;
                    changes.push(TruthcoinExactTableChangeV1 {
                        database: TruthcoinDatabaseId::PeriodPricing,
                        key: period_key,
                        prior: Some(prior_pricing),
                        successor: successor_pricing,
                    });
                }
            }
        }
        Ok(TruthcoinDecisionClaimUndoV1 { changes })
    })
}

pub fn revert_truthcoin_decision_claim_mutations(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinDecisionClaimUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let actual = candidate
                .get(change.database.as_u8(), &change.key)?
                .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
            if actual != change.successor {
                return Err(ReplayError::InvalidTruthcoinDecisionState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinMarketCreationUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum TruthcoinMarketDimensionCodecV1 {
    Single([u8; 3]),
    Categorical([u8; 3]),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum TruthcoinMarketStateCodecV1 {
    Trading,
    Cancelled,
    Invalid,
    Settled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinMarketCodecV1 {
    id: [u8; 6],
    title: String,
    description: String,
    tags: Vec<String>,
    creator_address: [u8; 20],
    dimension_specs: Vec<TruthcoinMarketDimensionCodecV1>,
    decision_ids: Vec<[u8; 3]>,
    state_combos: Vec<Vec<usize>>,
    created_at_height: u32,
    expires_at_height: Option<u32>,
    tau_from_now: u8,
    storage_fee_sats: u64,
    market_state: TruthcoinMarketStateCodecV1,
    trading_fee: f64,
    liquidity_base_sats: u64,
    shares: Vec<i64>,
    final_prices: Vec<f64>,
    version: u64,
    last_updated_height: u32,
    total_volume_sats: u64,
    outcome_volumes_sats: Vec<u64>,
    tx_pow_hash_selector: u8,
    tx_pow_ordering: u8,
    tx_pow_difficulty: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct TruthcoinShareAccountCodecV1 {
    positions: BTreeMap<([u8; 6], u32), i64>,
    last_updated_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinMarketTransitionUndoCodecV1 {
    entries: Vec<TruthcoinMarketCodecV1>,
    share_accounts: Vec<([u8; 20], Option<TruthcoinShareAccountCodecV1>)>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum TruthcoinDecisionResolutionStatusCodecV1 {
    Pending,
    AwaitingResolution,
    Resolved,
    Defaulted,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TruthcoinDecisionResolutionCodecV1 {
    decision_id: [u8; 3],
    period_id: u32,
    status: TruthcoinDecisionResolutionStatusCodecV1,
    status_changed_at: u64,
    status_changed_height: u32,
    vote_count: u32,
    min_votes_required: u32,
    voting_deadline: u64,
    outcome_ready: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinDecisionOutcomeCodecV1 {
    decision_id: [u8; 3],
    period_id: u32,
    outcome_value: f64,
    min: f64,
    max: f64,
    confidence: f64,
    total_votes: u64,
    total_reputation_weight: f64,
    finalized_at: u64,
    block_height: u32,
    is_consensus: bool,
    resolution: TruthcoinDecisionResolutionCodecV1,
    categorical_winner: Option<Option<u16>>,
}

fn decode_truthcoin_decision_outcome(
    decision_id: [u8; 3],
    bytes: &[u8],
) -> Result<TruthcoinDecisionOutcomeCodecV1, ReplayError> {
    let outcome: TruthcoinDecisionOutcomeCodecV1 =
        bincode::deserialize(bytes).map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
    if bincode::serialize(&outcome).map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?
        != bytes
        || outcome.decision_id != decision_id
        || outcome.resolution.decision_id != decision_id
        || outcome.period_id != truthcoin_decision_period(decision_id)
        || outcome.resolution.period_id != outcome.period_id
        || !outcome.outcome_value.is_finite()
        || !outcome.min.is_finite()
        || !outcome.max.is_finite()
        || outcome.min > outcome.max
        || outcome.outcome_value < outcome.min
        || outcome.outcome_value > outcome.max
        || !outcome.confidence.is_finite()
        || !(0.0..=1.0).contains(&outcome.confidence)
        || !outcome.total_reputation_weight.is_finite()
        || outcome.total_reputation_weight < 0.0
        || outcome.finalized_at != 0
        || outcome.block_height != 0
        || !outcome.is_consensus
        || outcome.resolution.status != TruthcoinDecisionResolutionStatusCodecV1::Pending
        || outcome.resolution.status_changed_at != 0
        || outcome.resolution.status_changed_height != 0
        || !outcome.resolution.outcome_ready
    {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(outcome)
}

fn truthcoin_resolved_decision_outcome(
    store: &CanonicalStateStoreV1,
    decision_id: [u8; 3],
) -> Result<Option<TruthcoinDecisionOutcomeCodecV1>, ReplayError> {
    let history = decode_truthcoin_state_history(
        store
            .get(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                &decision_id,
            )?
            .ok_or(ReplayError::InvalidTruthcoinDecisionState)?,
    )?;
    let Some((3, _, Some(history_outcome))) = history.last().copied() else {
        return Ok(None);
    };
    if !history_outcome.is_finite() {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let outcome = decode_truthcoin_decision_outcome(
        decision_id,
        store
            .get(TruthcoinDatabaseId::DecisionOutcomes.as_u8(), &decision_id)?
            .ok_or(ReplayError::InvalidTruthcoinDecisionState)?,
    )?;
    if outcome.outcome_value != history_outcome {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(Some(outcome))
}

/// Return the consensus outcome only when the canonical outcome record and the
/// Decision state-history terminal transition agree exactly. `None` means the
/// Decision is not resolved yet; malformed or cross-height data is rejected.
pub fn truthcoin_resolved_decision_value(
    store: &CanonicalStateStoreV1,
    decision_id: [u8; 3],
) -> Result<Option<f64>, ReplayError> {
    Ok(truthcoin_resolved_decision_outcome(store, decision_id)?
        .map(|outcome| outcome.outcome_value))
}

/// Derive upstream's normalized terminal outcome prices from only committed
/// Decision outcomes and the canonical market/Decision records.
pub fn truthcoin_market_final_prices(
    store: &CanonicalStateStoreV1,
    market_id: [u8; 6],
) -> Result<Option<Vec<f64>>, ReplayError> {
    let market = decode_truthcoin_market(
        store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)?
            .ok_or(ReplayError::InvalidTruthcoinMarketState)?,
    )?;
    let mut axes = Vec::<Vec<f64>>::with_capacity(market.dimension_specs.len());
    for spec in &market.dimension_specs {
        let (decision_id, categorical) = match spec {
            TruthcoinMarketDimensionCodecV1::Single(id) => (*id, false),
            TruthcoinMarketDimensionCodecV1::Categorical(id) => (*id, true),
        };
        let Some(outcome) = truthcoin_resolved_decision_value(store, decision_id)? else {
            return Ok(None);
        };
        let decision = truthcoin_stored_decision(store, decision_id)?;
        let axis = if categorical {
            let DecodedTruthcoinDecisionTypeV1::Category { options } = decision.decision_type
            else {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            };
            let real_winner = if outcome == 0.5 || !outcome.is_finite() {
                None
            } else {
                let rounded = outcome.round();
                if (outcome - rounded).abs() > f64::EPSILON
                    || rounded < 0.0
                    || rounded >= options.len() as f64
                {
                    None
                } else {
                    Some(rounded as usize)
                }
            };
            match real_winner {
                Some(winner) => (0..options.len())
                    .map(|index| if index == winner { 1.0 } else { 0.0 })
                    .collect(),
                None => vec![1.0 / options.len() as f64; options.len()],
            }
        } else {
            match decision.decision_type {
                DecodedTruthcoinDecisionTypeV1::Scaled { .. } => vec![1.0 - outcome, outcome],
                DecodedTruthcoinDecisionTypeV1::Binary if outcome > 0.7 => vec![0.0, 1.0],
                DecodedTruthcoinDecisionTypeV1::Binary if outcome < 0.3 => vec![1.0, 0.0],
                DecodedTruthcoinDecisionTypeV1::Binary => vec![0.5, 0.5],
                DecodedTruthcoinDecisionTypeV1::Category { .. } => {
                    return Err(ReplayError::InvalidTruthcoinMarketState);
                }
            }
        };
        axes.push(axis);
    }
    let mut prices = Vec::new();
    'combinations: for combo in &market.state_combos {
        if combo.len() != axes.len() {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
        let mut joint = 1.0;
        for (dimension, state) in combo.iter().enumerate() {
            if matches!(
                market.dimension_specs[dimension],
                TruthcoinMarketDimensionCodecV1::Single(_)
            ) && *state >= 2
            {
                continue 'combinations;
            }
            joint *= *axes[dimension]
                .get(*state)
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
        }
        prices.push(joint);
    }
    if prices.len() != market.final_prices.len() {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    let sum: f64 = prices.iter().sum();
    if !sum.is_finite() || sum <= 0.0 {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    for price in &mut prices {
        *price /= sum;
    }
    Ok(Some(prices))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum TruthcoinFeeRoleCodecV1 {
    CorrectVoter,
    DecisionAuthor,
    MarketAuthor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinSharePayoutCodecV1 {
    market_id: [u8; 6],
    address: [u8; 20],
    outcome_index: u32,
    shares_redeemed: i64,
    final_price: f64,
    payout_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TruthcoinFeePayoutCodecV1 {
    address: [u8; 20],
    amount_sats: u64,
    fee_role: TruthcoinFeeRoleCodecV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TruthcoinCreatorRefundCodecV1 {
    address: [u8; 20],
    amount_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinMarketPayoutSummaryCodecV1 {
    market_id: [u8; 6],
    treasury_distributed: u64,
    total_fees_distributed: u64,
    shareholder_count: u32,
    payouts: Vec<TruthcoinSharePayoutCodecV1>,
    fee_payouts: Vec<TruthcoinFeePayoutCodecV1>,
    creator_refund: Option<TruthcoinCreatorRefundCodecV1>,
    block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinSettlementUndoEntryCodecV1 {
    pre_settlement_market: TruthcoinMarketCodecV1,
    payout_summary: TruthcoinMarketPayoutSummaryCodecV1,
    treasury_utxo: Option<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
    fee_utxo: Option<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
    pre_settlement_share_accounts: Vec<([u8; 20], TruthcoinShareAccountCodecV1)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinSettlementUndoCodecV1 {
    entries: Vec<TruthcoinSettlementUndoEntryCodecV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinVotingPeriodStatsCodecV1 {
    period_id: u32,
    total_voters: u64,
    total_votes: u64,
    total_decisions: u64,
    avg_participation_rate: f64,
    total_reputation_weight: f64,
    consensus_decisions: u64,
    calculated_at: u64,
    first_loading: Option<Vec<f64>>,
    certainty: Option<f64>,
    reputation_changes: Option<BTreeMap<[u8; 20], (f64, f64)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinConsensusUndoEntryCodecV1 {
    period_id: u32,
    decision_outcome_ids: Vec<[u8; 3]>,
    had_period_stats: bool,
    resolved_decision_ids: Vec<[u8; 3]>,
    pre_consensus_reputation: BTreeMap<[u8; 20], f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TruthcoinConsensusUndoCodecV1 {
    entries: Vec<TruthcoinConsensusUndoEntryCodecV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinNoVoteConsensusUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinVotedConsensusUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinMarketSettlementUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

fn truthcoin_allocate_proportionally<K: Clone>(
    participants: Vec<(K, f64)>,
    pool: u64,
) -> Result<Vec<(K, u64)>, ReplayError> {
    if participants.is_empty() || pool == 0 {
        return Ok(Vec::new());
    }
    let total_weight: f64 = participants.iter().map(|(_, weight)| *weight).sum();
    if !total_weight.is_finite() || total_weight <= 0.0 {
        return Ok(Vec::new());
    }
    let mut allocations = Vec::new();
    let mut fallback = None;
    let mut allocated = 0_u64;
    for (key, weight) in participants {
        if !weight.is_finite() || weight < 0.0 {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
        if weight < f64::EPSILON {
            continue;
        }
        if fallback
            .as_ref()
            .is_none_or(|(_, best): &(K, f64)| *best < weight)
        {
            fallback = Some((key.clone(), weight));
        }
        let raw = weight / total_weight * pool as f64;
        if !raw.is_finite() || raw < 0.0 || raw >= u64::MAX as f64 {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
        let amount = raw.round() as u64;
        if amount > 0 {
            allocated = allocated
                .checked_add(amount)
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            allocations.push((key, amount));
        }
    }
    match allocated.cmp(&pool) {
        std::cmp::Ordering::Less => {
            let remainder = pool - allocated;
            if let Some((index, _)) = allocations
                .iter()
                .enumerate()
                .max_by_key(|(_, (_, amount))| *amount)
            {
                allocations[index].1 += remainder;
            } else {
                allocations.push((
                    fallback.ok_or(ReplayError::InvalidTruthcoinMarketState)?.0,
                    remainder,
                ));
            }
        }
        std::cmp::Ordering::Greater => {
            let mut excess = allocated - pool;
            allocations.sort_by_key(|(_, amount)| *amount);
            for (_, amount) in &mut allocations {
                let take = (*amount).min(excess);
                *amount -= take;
                excess -= take;
                if excess == 0 {
                    break;
                }
            }
            if excess != 0 {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
        }
        std::cmp::Ordering::Equal => {}
    }
    if allocations.iter().map(|(_, amount)| *amount).sum::<u64>() != pool {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    Ok(allocations)
}

fn truthcoin_share_payout_outpoint(
    market_id: [u8; 6],
    address: [u8; 20],
    height: u32,
    sequence: u32,
) -> TruthcoinOutPointCodecV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SHARE_PAYOUT");
    hasher.update(&market_id);
    hasher.update(&address);
    hasher.update(&height.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    TruthcoinOutPointCodecV1::Payout {
        hash: *hasher.finalize().as_bytes(),
        vout: sequence,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TruthcoinStoredVoteValueV1 {
    Binary(bool),
    Scalar(f64),
    Categorical(u16),
    Abstain,
}

fn decode_truthcoin_stored_vote(bytes: &[u8]) -> Result<TruthcoinStoredVoteValueV1, ReplayError> {
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let value = match cursor.u32()? {
        0 => TruthcoinStoredVoteValueV1::Binary(match cursor.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ReplayError::InvalidTruthcoinVotingState),
        }),
        1 => TruthcoinStoredVoteValueV1::Scalar(cursor.f64()?),
        2 => TruthcoinStoredVoteValueV1::Categorical(u16::from_le_bytes(
            cursor
                .take(2)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
        )),
        3 => TruthcoinStoredVoteValueV1::Abstain,
        _ => return Err(ReplayError::InvalidTruthcoinVotingState),
    };
    cursor.take(8 + 4)?;
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinVotingState);
    }
    Ok(value)
}

fn truthcoin_vote_is_correct(
    vote: TruthcoinStoredVoteValueV1,
    outcome: f64,
    decision: &TruthcoinStoredDecisionV1,
) -> bool {
    match vote {
        TruthcoinStoredVoteValueV1::Abstain => false,
        TruthcoinStoredVoteValueV1::Binary(value) => f64::from(u8::from(value)) == outcome,
        TruthcoinStoredVoteValueV1::Scalar(value) => match decision.decision_type {
            DecodedTruthcoinDecisionTypeV1::Scaled { .. } => {
                ((value - outcome).abs() * 1_000_000.0).round() / 1_000_000.0 <= 0.05
            }
            _ => value == outcome,
        },
        TruthcoinStoredVoteValueV1::Categorical(index) => {
            if f64::from(index) == outcome {
                true
            } else {
                outcome == 0.5
                    && matches!(
                        &decision.decision_type,
                        DecodedTruthcoinDecisionTypeV1::Category { options }
                            if usize::from(index) == options.len()
                    )
            }
        }
    }
}

fn truthcoin_market_fee_payouts(
    store: &CanonicalStateStoreV1,
    market: &TruthcoinMarketCodecV1,
    outcomes: &BTreeMap<[u8; 3], f64>,
    fee_sats: u64,
) -> Result<Vec<TruthcoinFeePayoutCodecV1>, ReplayError> {
    if fee_sats == 0 {
        return Ok(Vec::new());
    }
    let split =
        truthcoin_allocate_proportionally(vec![(0_u8, 2.0), (1_u8, 1.0), (2_u8, 1.0)], fee_sats)?;
    let mut voter_pool = 0;
    let mut decision_author_pool = 0;
    let mut market_author_pool = 0;
    for (role, amount) in split {
        match role {
            0 => voter_pool = amount,
            1 => decision_author_pool = amount,
            2 => market_author_pool = amount,
            _ => unreachable!(),
        }
    }
    let mut payouts = Vec::new();
    if voter_pool > 0 {
        let per_decision = truthcoin_allocate_proportionally(
            market
                .decision_ids
                .iter()
                .copied()
                .map(|id| (id, 1.0))
                .collect(),
            voter_pool,
        )?;
        for (decision_id, sub_pool) in per_decision {
            let decision = truthcoin_stored_decision(store, decision_id)?;
            let outcome = *outcomes
                .get(&decision_id)
                .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
            let period = truthcoin_decision_period(decision_id);
            let mut voters = Vec::new();
            for (key, bytes) in store.entries(TruthcoinDatabaseId::Votes.as_u8())? {
                if key.len() != 27 || key[..4] != period.to_le_bytes() || key[24..27] != decision_id
                {
                    continue;
                }
                let address: [u8; 20] = key[4..24]
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
                if truthcoin_vote_is_correct(
                    decode_truthcoin_stored_vote(bytes)?,
                    outcome,
                    &decision,
                ) {
                    let reputation = get_truthcoin_reputation(store, &address)?;
                    if reputation > 0.0 {
                        voters.push((address, reputation));
                    }
                }
            }
            voters.sort_by_key(|(address, _)| *address);
            if voters.is_empty() {
                market_author_pool = market_author_pool
                    .checked_add(sub_pool)
                    .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            } else {
                for (address, amount) in truthcoin_allocate_proportionally(voters, sub_pool)? {
                    payouts.push(TruthcoinFeePayoutCodecV1 {
                        address,
                        amount_sats: amount,
                        fee_role: TruthcoinFeeRoleCodecV1::CorrectVoter,
                    });
                }
            }
        }
    }
    if decision_author_pool > 0 {
        let mut authors = BTreeSet::new();
        for decision_id in &market.decision_ids {
            authors.insert(truthcoin_stored_decision(store, *decision_id)?.market_maker);
        }
        for (address, amount) in truthcoin_allocate_proportionally(
            authors.into_iter().map(|address| (address, 1.0)).collect(),
            decision_author_pool,
        )? {
            payouts.push(TruthcoinFeePayoutCodecV1 {
                address,
                amount_sats: amount,
                fee_role: TruthcoinFeeRoleCodecV1::DecisionAuthor,
            });
        }
    }
    if market_author_pool > 0 {
        payouts.push(TruthcoinFeePayoutCodecV1 {
            address: market.creator_address,
            amount_sats: market_author_pool,
            fee_role: TruthcoinFeeRoleCodecV1::MarketAuthor,
        });
    }
    payouts.sort_by_key(|payout| {
        let role = match payout.fee_role {
            TruthcoinFeeRoleCodecV1::CorrectVoter => 0,
            TruthcoinFeeRoleCodecV1::DecisionAuthor => 1,
            TruthcoinFeeRoleCodecV1::MarketAuthor => 2,
        };
        (role, payout.address)
    });
    Ok(payouts)
}

fn delete_truthcoin_settlement_change(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    database: TruthcoinDatabaseId,
    key: &[u8],
) -> Result<Option<Vec<u8>>, ReplayError> {
    let prior = store.delete(database.as_u8(), key)?;
    if let Some(value) = &prior {
        changes.push(TruthcoinExactTableChangeV1 {
            database,
            key: key.to_vec(),
            prior: Some(value.clone()),
            successor: Vec::new(),
        });
    }
    Ok(prior)
}

/// Settle every Trading market whose Decisions have canonical, committed
/// consensus outcomes. This is a deterministic block-level transition and
/// accepts no externally supplied prices or payout amounts.
pub fn apply_truthcoin_resolved_market_settlements(
    store: &mut CanonicalStateStoreV1,
    height: u32,
) -> Result<TruthcoinMarketSettlementUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let trading_key = 0_u32.to_le_bytes().to_vec();
        let trading_ids = decode_market_id_index(
            candidate.get(TruthcoinDatabaseId::MarketsByState.as_u8(), &trading_key)?,
        )?;
        let mut changes = Vec::new();
        let mut native_entries = Vec::new();
        for market_id in trading_ids.clone() {
            let Some(final_prices) = truthcoin_market_final_prices(candidate, market_id)? else {
                continue;
            };
            let pre_market = decode_truthcoin_market(
                candidate
                    .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)?
                    .ok_or(ReplayError::InvalidTruthcoinMarketState)?,
            )?;
            if pre_market.market_state != TruthcoinMarketStateCodecV1::Trading {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            let mut outcomes = BTreeMap::new();
            for decision_id in &pre_market.decision_ids {
                outcomes.insert(
                    *decision_id,
                    truthcoin_resolved_decision_value(candidate, *decision_id)?
                        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?,
                );
            }

            let treasury_pointer_key = truthcoin_market_funds_pointer_key(market_id, false);
            let fee_pointer_key = truthcoin_market_funds_pointer_key(market_id, true);
            let treasury_pointer = candidate
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &treasury_pointer_key,
                )?
                .map(decode_truthcoin_outpoint)
                .transpose()?;
            let fee_pointer = candidate
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &fee_pointer_key,
                )?
                .map(decode_truthcoin_outpoint)
                .transpose()?;
            let treasury_utxo = treasury_pointer
                .map(|pointer| {
                    let key = truthcoin_outpoint_key(pointer)?;
                    let output = decode_truthcoin_filled_output(
                        candidate
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), &key)?
                            .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                    )?;
                    Ok::<_, ReplayError>((pointer, output))
                })
                .transpose()?;
            let fee_utxo = fee_pointer
                .map(|pointer| {
                    let key = truthcoin_outpoint_key(pointer)?;
                    let output = decode_truthcoin_filled_output(
                        candidate
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), &key)?
                            .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                    )?;
                    Ok::<_, ReplayError>((pointer, output))
                })
                .transpose()?;
            let treasury_sats = treasury_utxo
                .as_ref()
                .map(|(_, output)| match output.content {
                    TruthcoinFilledContentV1::MarketFunds {
                        market_id: id,
                        amount,
                        is_fee: false,
                    } if id == market_id => Ok(amount),
                    _ => Err(ReplayError::InvalidTruthcoinMarketState),
                })
                .transpose()?
                .unwrap_or(0);
            let fee_sats = fee_utxo
                .as_ref()
                .map(|(_, output)| match output.content {
                    TruthcoinFilledContentV1::MarketFunds {
                        market_id: id,
                        amount,
                        is_fee: true,
                    } if id == market_id => Ok(amount),
                    _ => Err(ReplayError::InvalidTruthcoinMarketState),
                })
                .transpose()?
                .unwrap_or(0);

            let mut payouts = Vec::new();
            let mut pre_accounts = Vec::new();
            for (address_bytes, account_bytes) in
                candidate.entries(TruthcoinDatabaseId::ShareAccounts.as_u8())?
            {
                let address: [u8; 20] = address_bytes
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
                let account = decode_truthcoin_share_account(account_bytes)?;
                let positions: Vec<_> = account
                    .positions
                    .iter()
                    .filter(|((id, _), _)| *id == market_id)
                    .map(|((_, outcome), shares)| (*outcome, *shares))
                    .collect();
                if positions.is_empty() {
                    continue;
                }
                pre_accounts.push((address, account));
                for (outcome_index, shares) in positions {
                    let price = *final_prices
                        .get(outcome_index as usize)
                        .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
                    let raw = (shares as f64 * price).max(0.0);
                    if !raw.is_finite() || raw >= u64::MAX as f64 {
                        return Err(ReplayError::InvalidTruthcoinMarketState);
                    }
                    payouts.push(TruthcoinSharePayoutCodecV1 {
                        market_id,
                        address,
                        outcome_index,
                        shares_redeemed: shares,
                        final_price: price,
                        payout_sats: raw.round() as u64,
                    });
                }
            }
            let mut redeemed = payouts
                .iter()
                .try_fold(0_u64, |sum, payout| sum.checked_add(payout.payout_sats))
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            if redeemed > treasury_sats {
                let mut excess = redeemed - treasury_sats;
                let mut order: Vec<usize> = (0..payouts.len()).collect();
                order.sort_by(|left, right| {
                    let fraction = |payout: &TruthcoinSharePayoutCodecV1| {
                        let raw = (payout.shares_redeemed as f64 * payout.final_price).max(0.0);
                        raw - raw.floor()
                    };
                    fraction(&payouts[*right])
                        .partial_cmp(&fraction(&payouts[*left]))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                for index in order {
                    if excess == 0 {
                        break;
                    }
                    let raw = (payouts[index].shares_redeemed as f64 * payouts[index].final_price)
                        .max(0.0);
                    if payouts[index].payout_sats > raw.floor() as u64 {
                        payouts[index].payout_sats -= 1;
                        excess -= 1;
                    }
                }
                redeemed = payouts
                    .iter()
                    .try_fold(0_u64, |sum, payout| sum.checked_add(payout.payout_sats))
                    .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            }
            let refund = treasury_sats
                .checked_sub(redeemed)
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            let creator_refund = (refund > 0).then_some(TruthcoinCreatorRefundCodecV1 {
                address: pre_market.creator_address,
                amount_sats: refund,
            });
            let fee_payouts =
                truthcoin_market_fee_payouts(candidate, &pre_market, &outcomes, fee_sats)?;
            let total_fees_distributed = fee_payouts
                .iter()
                .try_fold(0_u64, |sum, payout| sum.checked_add(payout.amount_sats))
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            if total_fees_distributed != fee_sats {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            let payout_summary = TruthcoinMarketPayoutSummaryCodecV1 {
                market_id,
                treasury_distributed: redeemed,
                total_fees_distributed,
                shareholder_count: u32::try_from(
                    payouts
                        .iter()
                        .filter(|payout| payout.payout_sats > 0)
                        .count(),
                )
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
                payouts: payouts.clone(),
                fee_payouts: fee_payouts.clone(),
                creator_refund: creator_refund.clone(),
                block_height: height,
            };

            let mut sequence = 0_u32;
            for payout in &payouts {
                if payout.payout_sats > 0 {
                    insert_truthcoin_consolidation_utxo(
                        candidate,
                        &mut changes,
                        truthcoin_share_payout_outpoint(
                            market_id,
                            payout.address,
                            height,
                            sequence,
                        ),
                        TruthcoinFilledOutputV1 {
                            address: payout.address,
                            content: TruthcoinFilledContentV1::Bitcoin(payout.payout_sats),
                            memo: Vec::new(),
                        },
                    )?;
                }
                sequence = sequence
                    .checked_add(1)
                    .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            }
            for payout in &fee_payouts {
                insert_truthcoin_consolidation_utxo(
                    candidate,
                    &mut changes,
                    truthcoin_share_payout_outpoint(market_id, payout.address, height, sequence),
                    TruthcoinFilledOutputV1 {
                        address: payout.address,
                        content: TruthcoinFilledContentV1::Bitcoin(payout.amount_sats),
                        memo: Vec::new(),
                    },
                )?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            }
            if let Some(refund) = &creator_refund {
                insert_truthcoin_consolidation_utxo(
                    candidate,
                    &mut changes,
                    truthcoin_share_payout_outpoint(market_id, refund.address, height, sequence),
                    TruthcoinFilledOutputV1 {
                        address: refund.address,
                        content: TruthcoinFilledContentV1::Bitcoin(refund.amount_sats),
                        memo: Vec::new(),
                    },
                )?;
            }

            for (address, mut account) in pre_accounts.iter().cloned() {
                account.positions.retain(|(id, _), _| *id != market_id);
                let prior = delete_truthcoin_settlement_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::ShareAccounts,
                    &address,
                )?;
                if prior.is_none() {
                    return Err(ReplayError::InvalidTruthcoinMarketState);
                }
                if !account.positions.is_empty() {
                    account.last_updated_height = height;
                    put_truthcoin_consolidation_change(
                        candidate,
                        &mut changes,
                        TruthcoinDatabaseId::ShareAccounts,
                        address.to_vec(),
                        bincode::serialize(&account)
                            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
                    )?;
                }
            }
            if let Some((pointer, _)) = &treasury_utxo {
                delete_truthcoin_consolidation_utxo(candidate, &mut changes, *pointer)?;
                delete_truthcoin_settlement_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketFundsUtxos,
                    &treasury_pointer_key,
                )?;
            }
            if let Some((pointer, _)) = &fee_utxo {
                delete_truthcoin_consolidation_utxo(candidate, &mut changes, *pointer)?;
                delete_truthcoin_settlement_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketFundsUtxos,
                    &fee_pointer_key,
                )?;
            }

            let mut settled_market = pre_market.clone();
            settled_market.final_prices = final_prices;
            settled_market.version = settled_market
                .version
                .checked_add(2)
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            settled_market.last_updated_height = height;
            settled_market.market_state = TruthcoinMarketStateCodecV1::Settled;
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::Markets,
                market_id.to_vec(),
                bincode::serialize(&settled_market)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
            )?;

            native_entries.push(TruthcoinSettlementUndoEntryCodecV1 {
                pre_settlement_market: pre_market,
                payout_summary,
                treasury_utxo,
                fee_utxo,
                pre_settlement_share_accounts: pre_accounts,
            });
        }

        if !native_entries.is_empty() {
            let settled: Vec<[u8; 6]> = native_entries
                .iter()
                .map(|entry| entry.pre_settlement_market.id)
                .collect();
            let remaining: Vec<_> = trading_ids
                .into_iter()
                .filter(|id| !settled.contains(id))
                .collect();
            delete_truthcoin_settlement_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MarketsByState,
                &trading_key,
            )?;
            if !remaining.is_empty() {
                put_truthcoin_consolidation_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketsByState,
                    trading_key,
                    encode_market_id_index(&remaining)?,
                )?;
            }
            let settled_key = 3_u32.to_le_bytes().to_vec();
            let mut settled_ids = decode_market_id_index(
                candidate.get(TruthcoinDatabaseId::MarketsByState.as_u8(), &settled_key)?,
            )?;
            settled_ids.extend(settled);
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MarketsByState,
                settled_key,
                encode_market_id_index(&settled_ids)?,
            )?;
            put_truthcoin_consolidation_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::SettlementUndo,
                height.to_le_bytes().to_vec(),
                bincode::serialize(&TruthcoinSettlementUndoCodecV1 {
                    entries: native_entries,
                })
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
            )?;
        }
        Ok(TruthcoinMarketSettlementUndoV1 { changes })
    })
}

pub fn revert_truthcoin_resolved_market_settlements(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinMarketSettlementUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate.get(change.database.as_u8(), &change.key)?;
            if change.successor.is_empty() && change.prior.is_some() {
                if current.is_some() {
                    return Err(ReplayError::InvalidTruthcoinMarketState);
                }
            } else if current != Some(change.successor.as_slice()) {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

/// Commit upstream's exact default-consensus branch for expired voting periods
/// that contain no votes. Voted periods are deliberately left untouched for
/// the weighted SVD implementation; this function never substitutes a simpler
/// calculation for them.
fn truthcoin_period_has_outcomes(
    store: &CanonicalStateStoreV1,
    period: u32,
) -> Result<bool, ReplayError> {
    // Native compute_consensus skips the entire period, including late-listed
    // decisions, when any decision in that period already has an outcome.
    for (key, bytes) in store.entries(TruthcoinDatabaseId::DecisionOutcomes.as_u8())? {
        let decision_id: [u8; 3] = key
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
        if truthcoin_decision_period(decision_id) == period {
            decode_truthcoin_decision_outcome(decision_id, bytes)?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn apply_truthcoin_no_vote_consensus(
    store: &mut CanonicalStateStoreV1,
    height: u32,
) -> Result<TruthcoinNoVoteConsensusUndoV1, ReplayError> {
    let timestamp = u64::from_le_bytes(
        store
            .get(
                TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                &TRUTHCOIN_UNIT_KEY,
            )?
            .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
    );
    let genesis = u64::from_le_bytes(
        store
            .get(
                TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                &TRUTHCOIN_UNIT_KEY,
            )?
            .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
    );
    let current_period = truthcoin_current_period(timestamp, genesis)?;
    store.transaction(|candidate| {
        let mut periods = BTreeMap::<u32, Vec<[u8; 3]>>::new();
        for (key, bytes) in
            candidate.entries(TruthcoinDatabaseId::DecisionStateHistories.as_u8())?
        {
            let decision_id: [u8; 3] = key
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
            let history = decode_truthcoin_state_history(bytes)?;
            if history.last().is_some_and(|entry| entry.0 == 2)
                && current_period > truthcoin_decision_period(decision_id)
            {
                periods
                    .entry(truthcoin_decision_period(decision_id))
                    .or_default()
                    .push(decision_id);
            }
        }
        let mut changes = Vec::new();
        let mut native_entries = Vec::new();
        let pre_consensus_reputation: BTreeMap<[u8; 20], f64> = candidate
            .entries(TruthcoinDatabaseId::Reputation.as_u8())?
            .map(|(key, value)| {
                Ok((
                    key.try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
                    decode_truthcoin_reputation(value)?,
                ))
            })
            .collect::<Result<_, ReplayError>>()?;

        for (period, mut decision_ids) in periods {
            decision_ids.sort();
            let has_votes = candidate
                .entries(TruthcoinDatabaseId::Votes.as_u8())?
                .any(|(key, _)| key.len() == 27 && key[..4] == period.to_le_bytes());
            if has_votes {
                continue;
            }
            if truthcoin_period_has_outcomes(candidate, period)? {
                continue;
            }
            let stats_key = period.to_le_bytes().to_vec();
            let had_period_stats = candidate
                .get(TruthcoinDatabaseId::PeriodStats.as_u8(), &stats_key)?
                .is_some();
            let stats = TruthcoinVotingPeriodStatsCodecV1 {
                period_id: period,
                total_voters: 0,
                total_votes: 0,
                total_decisions: 0,
                avg_participation_rate: 0.0,
                total_reputation_weight: 0.0,
                consensus_decisions: 0,
                calculated_at: 0,
                first_loading: None,
                certainty: Some(0.0),
                reputation_changes: None,
            };
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::PeriodStats,
                stats_key,
                bincode::serialize(&stats).map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
            )?;
            for decision_id in &decision_ids {
                let outcome = TruthcoinDecisionOutcomeCodecV1 {
                    decision_id: *decision_id,
                    period_id: period,
                    outcome_value: 0.5,
                    min: 0.0,
                    max: 1.0,
                    confidence: 0.0,
                    total_votes: 0,
                    total_reputation_weight: 0.0,
                    finalized_at: 0,
                    block_height: 0,
                    is_consensus: true,
                    resolution: TruthcoinDecisionResolutionCodecV1 {
                        decision_id: *decision_id,
                        period_id: period,
                        status: TruthcoinDecisionResolutionStatusCodecV1::Pending,
                        status_changed_at: 0,
                        status_changed_height: 0,
                        vote_count: 0,
                        min_votes_required: 0,
                        voting_deadline: 0,
                        outcome_ready: true,
                        reason: None,
                    },
                    categorical_winner: None,
                };
                put_truthcoin_consolidation_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::DecisionOutcomes,
                    decision_id.to_vec(),
                    bincode::serialize(&outcome)
                        .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
                )?;
                let mut history = decode_truthcoin_state_history(
                    candidate
                        .get(
                            TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                            decision_id,
                        )?
                        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?,
                )?;
                if history.last().is_none_or(|entry| entry.0 != 2) {
                    return Err(ReplayError::InvalidTruthcoinDecisionState);
                }
                history.push((3, height, Some(0.5)));
                put_exact_market_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::DecisionStateHistories,
                    decision_id.to_vec(),
                    encode_truthcoin_state_history(&history)?,
                )?;
            }
            native_entries.push(TruthcoinConsensusUndoEntryCodecV1 {
                period_id: period,
                decision_outcome_ids: decision_ids.clone(),
                had_period_stats,
                resolved_decision_ids: decision_ids,
                pre_consensus_reputation: pre_consensus_reputation.clone(),
            });
        }
        if !native_entries.is_empty() {
            put_truthcoin_consolidation_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::ConsensusUndo,
                height.to_le_bytes().to_vec(),
                bincode::serialize(&TruthcoinConsensusUndoCodecV1 {
                    entries: native_entries,
                })
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
            )?;
        }
        Ok(TruthcoinNoVoteConsensusUndoV1 { changes })
    })
}

pub fn revert_truthcoin_no_vote_consensus(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinNoVoteConsensusUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate.get(change.database.as_u8(), &change.key)?;
            if change.successor.is_empty() && change.prior.is_some() {
                if current.is_some() {
                    return Err(ReplayError::InvalidTruthcoinVotingState);
                }
            } else if current != Some(change.successor.as_slice()) {
                return Err(ReplayError::InvalidTruthcoinVotingState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

/// Commit expired voting periods using the pinned Truthcoin weighted-SVD
/// algorithm. Periods without votes remain the responsibility of
/// `apply_truthcoin_no_vote_consensus`, keeping both native branches explicit.
pub fn apply_truthcoin_voted_consensus(
    store: &mut CanonicalStateStoreV1,
    height: u32,
) -> Result<TruthcoinVotedConsensusUndoV1, ReplayError> {
    let timestamp = u64::from_le_bytes(
        store
            .get(
                TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                &TRUTHCOIN_UNIT_KEY,
            )?
            .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
    );
    let genesis = u64::from_le_bytes(
        store
            .get(
                TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                &TRUTHCOIN_UNIT_KEY,
            )?
            .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
    );
    let current_period = truthcoin_current_period(timestamp, genesis)?;
    store.transaction(|candidate| {
        let mut periods = BTreeMap::<u32, Vec<[u8; 3]>>::new();
        for (key, bytes) in
            candidate.entries(TruthcoinDatabaseId::DecisionStateHistories.as_u8())?
        {
            let decision_id: [u8; 3] = key
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
            let history = decode_truthcoin_state_history(bytes)?;
            if history.last().is_some_and(|entry| entry.0 == 2)
                && current_period > truthcoin_decision_period(decision_id)
            {
                periods
                    .entry(truthcoin_decision_period(decision_id))
                    .or_default()
                    .push(decision_id);
            }
        }
        if periods.is_empty() {
            return Ok(TruthcoinVotedConsensusUndoV1 {
                changes: Vec::new(),
            });
        }
        let mut active_reputation: BTreeMap<[u8; 20], f64> = candidate
            .entries(TruthcoinDatabaseId::Reputation.as_u8())?
            .map(|(key, value)| {
                Ok((
                    key.try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
                    decode_truthcoin_reputation(value)?,
                ))
            })
            .collect::<Result<_, ReplayError>>()?;
        let initial_total = active_reputation.values().sum::<f64>();
        if active_reputation.is_empty()
            || !initial_total.is_finite()
            || initial_total <= 0.0
            || (initial_total - 1.0).abs() > 1e-6
        {
            return Err(ReplayError::InvalidTruthcoinReputationState);
        }
        let all_vote_entries: Vec<_> = candidate
            .entries(TruthcoinDatabaseId::Votes.as_u8())?
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let mut changes = Vec::new();
        let mut native_entries = Vec::new();
        for (period, mut decisions) in periods {
            let pre_reputation = active_reputation.clone();
            let pre_total = pre_reputation.values().sum::<f64>();
            let voters: Vec<_> = pre_reputation.keys().copied().collect();
            decisions.sort();
            if truthcoin_period_has_outcomes(candidate, period)? {
                continue;
            }
            let mut votes = BTreeMap::new();
            let mut total_votes = 0_u64;
            for (key, value) in &all_vote_entries {
                if key.len() != 27 || key[..4] != period.to_le_bytes() {
                    continue;
                }
                let voter: [u8; 20] = key[4..24]
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
                let decision: [u8; 3] = key[24..27]
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
                if !pre_reputation.contains_key(&voter) || !decisions.contains(&decision) {
                    return Err(ReplayError::InvalidTruthcoinVotingState);
                }
                total_votes = total_votes
                    .checked_add(1)
                    .ok_or(ReplayError::InvalidTruthcoinVotingState)?;
                let numeric = match decode_truthcoin_stored_vote(value)? {
                    TruthcoinStoredVoteValueV1::Binary(value) => Some(f64::from(u8::from(value))),
                    TruthcoinStoredVoteValueV1::Scalar(value) => Some(value),
                    TruthcoinStoredVoteValueV1::Categorical(value) => Some(f64::from(value)),
                    TruthcoinStoredVoteValueV1::Abstain => None,
                };
                if let Some(numeric) = numeric {
                    if !numeric.is_finite() {
                        return Err(ReplayError::InvalidTruthcoinVotingState);
                    }
                    votes.insert((voter, decision), numeric);
                }
            }
            if total_votes == 0 {
                continue;
            }
            let mut scaled = BTreeSet::new();
            let mut categorical = BTreeMap::new();
            for decision_id in &decisions {
                match truthcoin_stored_decision(candidate, *decision_id)?.decision_type {
                    DecodedTruthcoinDecisionTypeV1::Binary => {}
                    DecodedTruthcoinDecisionTypeV1::Scaled { .. } => {
                        scaled.insert(*decision_id);
                    }
                    DecodedTruthcoinDecisionTypeV1::Category { options } => {
                        categorical.insert(
                            *decision_id,
                            u16::try_from(options.len())
                                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
                        );
                    }
                }
            }
            let result = voting_math::calculate(
                &voters,
                &decisions,
                &votes,
                &pre_reputation,
                &scaled,
                &categorical,
            )
            .map_err(|()| ReplayError::InvalidTruthcoinVotingState)?;
            let post_total = result.reputations.values().sum::<f64>();
            if !post_total.is_finite() || (post_total - pre_total).abs() > 1e-9 {
                return Err(ReplayError::InvalidTruthcoinReputationState);
            }
            let mut post_reputation = result.reputations;
            let residual = 1.0 - post_reputation.values().sum::<f64>();
            if residual != 0.0 {
                let address = post_reputation
                    .iter()
                    .max_by(|left, right| {
                        left.1
                            .partial_cmp(right.1)
                            .unwrap_or(core::cmp::Ordering::Equal)
                            .then_with(|| left.0.cmp(right.0))
                    })
                    .map(|(address, _)| *address)
                    .ok_or(ReplayError::InvalidTruthcoinReputationState)?;
                *post_reputation
                    .get_mut(&address)
                    .ok_or(ReplayError::InvalidTruthcoinReputationState)? += residual;
            }
            let stats_key = period.to_le_bytes().to_vec();
            let had_period_stats = candidate
                .get(TruthcoinDatabaseId::PeriodStats.as_u8(), &stats_key)?
                .is_some();
            let mut stats =
                match candidate.get(TruthcoinDatabaseId::PeriodStats.as_u8(), &stats_key)? {
                    Some(bytes) => bincode::deserialize::<TruthcoinVotingPeriodStatsCodecV1>(bytes)
                        .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
                    None => TruthcoinVotingPeriodStatsCodecV1 {
                        period_id: period,
                        total_voters: 0,
                        total_votes: 0,
                        total_decisions: 0,
                        avg_participation_rate: 0.0,
                        total_reputation_weight: 0.0,
                        consensus_decisions: 0,
                        calculated_at: 0,
                        first_loading: None,
                        certainty: None,
                        reputation_changes: None,
                    },
                };
            if stats.period_id != period {
                return Err(ReplayError::InvalidTruthcoinVotingState);
            }
            stats.first_loading = Some(result.first_loading);
            stats.certainty = Some(result.certainty);
            stats.reputation_changes = Some(
                post_reputation
                    .iter()
                    .map(|(address, new)| (*address, (pre_reputation[address], *new)))
                    .collect(),
            );
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::PeriodStats,
                stats_key,
                bincode::serialize(&stats).map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
            )?;
            for decision_id in &decisions {
                let value = result.outcomes[decision_id].unwrap_or(0.5);
                let outcome = TruthcoinDecisionOutcomeCodecV1 {
                    decision_id: *decision_id,
                    period_id: period,
                    outcome_value: value,
                    min: 0.0,
                    max: 1.0,
                    confidence: 1.0,
                    total_votes,
                    total_reputation_weight: pre_total,
                    finalized_at: 0,
                    block_height: 0,
                    is_consensus: true,
                    resolution: TruthcoinDecisionResolutionCodecV1 {
                        decision_id: *decision_id,
                        period_id: period,
                        status: TruthcoinDecisionResolutionStatusCodecV1::Pending,
                        status_changed_at: 0,
                        status_changed_height: 0,
                        vote_count: 0,
                        min_votes_required: 1,
                        voting_deadline: 0,
                        outcome_ready: true,
                        reason: None,
                    },
                    categorical_winner: categorical
                        .contains_key(decision_id)
                        .then(|| result.categorical_winners[decision_id]),
                };
                put_truthcoin_consolidation_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::DecisionOutcomes,
                    decision_id.to_vec(),
                    bincode::serialize(&outcome)
                        .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
                )?;
                let mut history = decode_truthcoin_state_history(
                    candidate
                        .get(
                            TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                            decision_id,
                        )?
                        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?,
                )?;
                if history.last().is_none_or(|entry| entry.0 != 2) {
                    return Err(ReplayError::InvalidTruthcoinDecisionState);
                }
                history.push((3, height, Some(value)));
                put_exact_market_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::DecisionStateHistories,
                    decision_id.to_vec(),
                    encode_truthcoin_state_history(&history)?,
                )?;
            }
            for (address, value) in &post_reputation {
                put_exact_market_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::Reputation,
                    address.to_vec(),
                    bincode::serialize(value)
                        .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
                )?;
            }
            native_entries.push(TruthcoinConsensusUndoEntryCodecV1 {
                period_id: period,
                decision_outcome_ids: decisions.clone(),
                had_period_stats,
                resolved_decision_ids: decisions,
                pre_consensus_reputation: pre_reputation.clone(),
            });
            active_reputation = post_reputation;
        }
        if !native_entries.is_empty() {
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::ConsensusUndo,
                height.to_le_bytes().to_vec(),
                bincode::serialize(&TruthcoinConsensusUndoCodecV1 {
                    entries: native_entries,
                })
                .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
            )?;
        }
        Ok(TruthcoinVotedConsensusUndoV1 { changes })
    })
}

pub fn revert_truthcoin_voted_consensus(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinVotedConsensusUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate.get(change.database.as_u8(), &change.key)?;
            if change.successor.is_empty() && change.prior.is_some() {
                if current.is_some() {
                    return Err(ReplayError::InvalidTruthcoinVotingState);
                }
            } else if current != Some(change.successor.as_slice()) {
                return Err(ReplayError::InvalidTruthcoinVotingState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

fn decode_truthcoin_market(bytes: &[u8]) -> Result<TruthcoinMarketCodecV1, ReplayError> {
    let market: TruthcoinMarketCodecV1 =
        bincode::deserialize(bytes).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
    let canonical =
        bincode::serialize(&market).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
    if canonical != bytes
        || market.id == [0; 6]
        || market.shares.len() < 2
        || market.shares.len() > 256
        || market.shares.len() != market.final_prices.len()
        || market.shares.len() != market.outcome_volumes_sats.len()
        || !market.trading_fee.is_finite()
        || !(0.0..=1.0).contains(&market.trading_fee)
    {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    Ok(market)
}

fn truthcoin_lmsr_cost(shares: &[i64], beta: f64) -> Result<f64, ReplayError> {
    if !(1e-6..1e12).contains(&beta) || shares.is_empty() || shares.iter().any(|share| *share < 0) {
        return Err(ReplayError::InvalidTruthcoinTrade);
    }
    let max_share = *shares
        .iter()
        .max()
        .ok_or(ReplayError::InvalidTruthcoinTrade)? as f64;
    let sum_exp = shares.iter().try_fold(0.0, |sum, share| {
        let value = libm::exp((*share as f64 - max_share) / beta);
        if value.is_finite() {
            Ok(sum + value)
        } else {
            Err(ReplayError::InvalidTruthcoinTrade)
        }
    })?;
    let cost = beta * (libm::log(sum_exp) + max_share / beta);
    if cost.is_finite() {
        Ok(cost)
    } else {
        Err(ReplayError::InvalidTruthcoinTrade)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruthcoinTradeQuoteV1 {
    pub base_sats: u64,
    pub trading_fee_sats: u64,
    pub trader_value_sats: u64,
}

pub fn quote_truthcoin_trade(
    market_bytes: &[u8],
    outcome_index: u32,
    share_delta: i64,
) -> Result<TruthcoinTradeQuoteV1, ReplayError> {
    let market = decode_truthcoin_market(market_bytes)?;
    let index = usize::try_from(outcome_index).map_err(|_| ReplayError::InvalidTruthcoinTrade)?;
    if share_delta == 0 || index >= market.shares.len() || market.liquidity_base_sats == 0 {
        return Err(ReplayError::InvalidTruthcoinTrade);
    }
    let mut successor = market.shares.clone();
    successor[index] = successor[index]
        .checked_add(share_delta)
        .ok_or(ReplayError::InvalidTruthcoinTrade)?;
    if successor[index] < 0 {
        return Err(ReplayError::InvalidTruthcoinTrade);
    }
    let beta = market.liquidity_base_sats as f64 / libm::log(market.shares.len() as f64);
    let raw = if share_delta > 0 {
        truthcoin_lmsr_cost(&successor, beta)? - truthcoin_lmsr_cost(&market.shares, beta)?
    } else {
        truthcoin_lmsr_cost(&market.shares, beta)? - truthcoin_lmsr_cost(&successor, beta)?
    };
    if !raw.is_finite() || !(0.0..18_446_744_073_709_551_616.0).contains(&raw) {
        return Err(ReplayError::InvalidTruthcoinTrade);
    }
    let base_sats = if share_delta > 0 {
        raw.ceil() as u64
    } else {
        raw.floor() as u64
    };
    let calculated_fee = (raw * market.trading_fee).round();
    if !calculated_fee.is_finite() || !(0.0..18_446_744_073_709_551_616.0).contains(&calculated_fee)
    {
        return Err(ReplayError::InvalidTruthcoinTrade);
    }
    let trading_fee_sats = (calculated_fee as u64).max(1_000);
    let trader_value_sats = if share_delta > 0 {
        base_sats.checked_add(trading_fee_sats)
    } else {
        base_sats.checked_sub(trading_fee_sats)
    }
    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
    Ok(TruthcoinTradeQuoteV1 {
        base_sats,
        trading_fee_sats,
        trader_value_sats,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinTradeMarketUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
    settlements: Vec<TruthcoinPendingTradeSettlementV1>,
    skipped_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TruthcoinPendingTradeSettlementV1 {
    market_id: [u8; 6],
    trader: [u8; 20],
    input_value_sats: u64,
    base_sats: u64,
    fee_sats: u64,
    trader_value_sats: u64,
    txid: [u8; 32],
    is_buy: bool,
}

fn decode_truthcoin_share_account(
    bytes: &[u8],
) -> Result<TruthcoinShareAccountCodecV1, ReplayError> {
    let account: TruthcoinShareAccountCodecV1 =
        bincode::deserialize(bytes).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
    if bincode::serialize(&account).map_err(|_| ReplayError::InvalidTruthcoinMarketState)? != bytes
        || account.positions.values().any(|shares| *shares <= 0)
    {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    Ok(account)
}

fn apply_truthcoin_trade_market_transitions_inner(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
    authenticate: bool,
) -> Result<TruthcoinTradeMarketUndoV1, ReplayError> {
    if authenticate {
        validate_truthcoin_utxo_ownership(store, body)?;
    }
    let actors = if authenticate {
        truthcoin_actor_addresses(body)?
    } else {
        vec![None; body.transactions_borsh.len()]
    };
    store.transaction(|candidate| {
        let mut markets = BTreeMap::<[u8; 6], TruthcoinMarketCodecV1>::new();
        let mut prior_markets = BTreeMap::<[u8; 6], TruthcoinMarketCodecV1>::new();
        let mut accounts = BTreeMap::<[u8; 20], TruthcoinShareAccountCodecV1>::new();
        let mut prior_accounts = BTreeMap::<[u8; 20], Option<TruthcoinShareAccountCodecV1>>::new();
        let mut settlements = Vec::new();
        let mut skipped_indices = Vec::new();
        let mut traded_markets = BTreeSet::new();

        for (transaction_index, (transaction_bytes, actor)) in
            body.transactions_borsh.iter().zip(actors).enumerate()
        {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            if let Some(DecodedTruthcoinTransactionDataV1::AmplifyBeta {
                market_id,
                amount,
                market_author,
            }) = transaction.data.clone()
            {
                if amount == 0 || !transaction.outputs.is_empty() {
                    return Err(ReplayError::InvalidTruthcoinTrade);
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = markets.entry(market_id)
                {
                    let market = decode_truthcoin_market(
                        candidate
                            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)?
                            .ok_or(ReplayError::InvalidTruthcoinTrade)?,
                    )?;
                    prior_markets.insert(market_id, market.clone());
                    entry.insert(market);
                }
                let market = markets
                    .get_mut(&market_id)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                if market.market_state != TruthcoinMarketStateCodecV1::Trading
                    || market.creator_address != market_author
                {
                    return Err(ReplayError::InvalidTruthcoinTrade);
                }
                let mut author_input = false;
                let mut input_value = 0_u64;
                for key in &transaction.input_keys {
                    let output = decode_truthcoin_filled_output(
                        candidate
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                            .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                    )?;
                    author_input |= output.address == market_author;
                    input_value = input_value
                        .checked_add(truthcoin_filled_bitcoin_value(&output)?)
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                }
                if (!author_input && actor != Some(market_author))
                    || input_value
                        < amount
                            .checked_add(1_000)
                            .ok_or(ReplayError::InvalidTruthcoinTrade)?
                {
                    return Err(ReplayError::InvalidTruthcoinTrade);
                }
                market.liquidity_base_sats = market
                    .liquidity_base_sats
                    .checked_add(amount)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                settlements.push(TruthcoinPendingTradeSettlementV1 {
                    market_id,
                    trader: market_author,
                    input_value_sats: input_value,
                    base_sats: amount,
                    fee_sats: 0,
                    trader_value_sats: amount,
                    txid: *blake3::hash(transaction_bytes).as_bytes(),
                    is_buy: true,
                });
                continue;
            }
            let Some(DecodedTruthcoinTransactionDataV1::Trade(trade)) = transaction.data else {
                continue;
            };
            if !transaction.outputs.is_empty() || trade.shares == 0 {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let market_snapshot = match markets.get(&trade.market_id) {
                Some(market) => market.clone(),
                None => decode_truthcoin_market(
                    candidate
                        .get(TruthcoinDatabaseId::Markets.as_u8(), &trade.market_id)?
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?,
                )?,
            };
            let prior_account = candidate
                .get(TruthcoinDatabaseId::ShareAccounts.as_u8(), &trade.trader)?
                .map(decode_truthcoin_share_account)
                .transpose()?;
            let account_snapshot = accounts
                .get(&trade.trader)
                .cloned()
                .unwrap_or_else(|| prior_account.clone().unwrap_or_default());
            let market = &market_snapshot;
            if market.market_state != TruthcoinMarketStateCodecV1::Trading
                || market.tx_pow_difficulty != 0
                || trade.tx_pow_nonce.is_some()
            {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let quote = quote_truthcoin_trade(
                &bincode::serialize(market)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
                trade.outcome_index,
                trade.shares,
            )?;
            let input_value = transaction.input_keys.iter().try_fold(0_u64, |sum, key| {
                let output = decode_truthcoin_filled_output(
                    candidate
                        .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                        .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                )?;
                sum.checked_add(truthcoin_filled_bitcoin_value(&output)?)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)
            })?;
            let position_key = (trade.market_id, trade.outcome_index);
            let prior_position = account_snapshot
                .positions
                .get(&position_key)
                .copied()
                .unwrap_or(0);
            if trade.shares > 0 {
                let limit_with_miner = quote
                    .trader_value_sats
                    .checked_add(1_000)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                if trade.limit_sats == 0 || input_value < trade.limit_sats {
                    return Err(ReplayError::InvalidTruthcoinTrade);
                }
                if limit_with_miner > trade.limit_sats {
                    skipped_indices.push(transaction_index);
                    continue;
                }
            } else {
                let trader_owns_input =
                    transaction.input_keys.iter().try_fold(false, |owns, key| {
                        let output = decode_truthcoin_filled_output(
                            candidate
                                .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                                .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                        )?;
                        Ok::<_, ReplayError>(owns || output.address == trade.trader)
                    })?;
                if (!trader_owns_input && actor != Some(trade.trader))
                    || input_value < 1_000
                    || prior_position < trade.shares.saturating_abs()
                {
                    return Err(ReplayError::InvalidTruthcoinTrade);
                }
                if quote.trader_value_sats < trade.limit_sats {
                    skipped_indices.push(transaction_index);
                    continue;
                }
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                markets.entry(trade.market_id)
            {
                prior_markets.insert(trade.market_id, market_snapshot.clone());
                entry.insert(market_snapshot);
            }
            if let std::collections::btree_map::Entry::Vacant(entry) = accounts.entry(trade.trader)
            {
                prior_accounts.insert(trade.trader, prior_account);
                entry.insert(account_snapshot);
            }
            let market = markets
                .get_mut(&trade.market_id)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            let account = accounts
                .get_mut(&trade.trader)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            traded_markets.insert(trade.market_id);
            let successor_position = prior_position
                .checked_add(trade.shares)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            if successor_position < 0 {
                return Err(ReplayError::InvalidTruthcoinTrade);
            } else if successor_position == 0 {
                account.positions.remove(&position_key);
            } else {
                account.positions.insert(position_key, successor_position);
            }
            account.last_updated_height = height;
            let index = usize::try_from(trade.outcome_index)
                .map_err(|_| ReplayError::InvalidTruthcoinTrade)?;
            market.shares[index] = market.shares[index]
                .checked_add(trade.shares)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            market.total_volume_sats = market
                .total_volume_sats
                .saturating_add(quote.trader_value_sats);
            market.outcome_volumes_sats[index] =
                market.outcome_volumes_sats[index].saturating_add(quote.trader_value_sats);
            settlements.push(TruthcoinPendingTradeSettlementV1 {
                market_id: trade.market_id,
                trader: trade.trader,
                input_value_sats: input_value,
                base_sats: quote.base_sats,
                fee_sats: quote.trading_fee_sats,
                trader_value_sats: quote.trader_value_sats,
                txid: *blake3::hash(transaction_bytes).as_bytes(),
                is_buy: trade.shares > 0,
            });
        }

        if markets.is_empty() {
            return Ok(TruthcoinTradeMarketUndoV1 {
                changes: Vec::new(),
                settlements,
                skipped_indices,
            });
        }
        let market_undo = TruthcoinMarketTransitionUndoCodecV1 {
            entries: prior_markets.values().cloned().collect(),
            share_accounts: prior_accounts
                .iter()
                .map(|(address, account)| (*address, account.clone()))
                .collect(),
        };
        let mut changes = Vec::new();
        put_exact_market_change(
            candidate,
            &mut changes,
            TruthcoinDatabaseId::MarketTransitionUndo,
            height.to_le_bytes().to_vec(),
            bincode::serialize(&market_undo)
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
        )?;
        for (market_id, mut market) in markets {
            if traded_markets.contains(&market_id) {
                market.version = market
                    .version
                    .checked_add(1)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                market.last_updated_height = height;
            }
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::Markets,
                market_id.to_vec(),
                bincode::serialize(&market)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
            )?;
        }
        for (address, account) in accounts {
            if account.positions.is_empty() {
                let prior =
                    candidate.delete(TruthcoinDatabaseId::ShareAccounts.as_u8(), &address)?;
                let successor = Vec::new();
                changes.push(TruthcoinExactTableChangeV1 {
                    database: TruthcoinDatabaseId::ShareAccounts,
                    key: address.to_vec(),
                    prior,
                    successor,
                });
            } else {
                put_exact_market_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::ShareAccounts,
                    address.to_vec(),
                    bincode::serialize(&account)
                        .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
                )?;
            }
        }
        Ok(TruthcoinTradeMarketUndoV1 {
            changes,
            settlements,
            skipped_indices,
        })
    })
}

pub fn apply_truthcoin_trade_market_transitions(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinTradeMarketUndoV1, ReplayError> {
    apply_truthcoin_trade_market_transitions_inner(store, body, height, true)
}

pub fn revert_truthcoin_trade_market_transitions(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinTradeMarketUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate.get(change.database.as_u8(), &change.key)?;
            if change.successor.is_empty() && change.prior.is_some() {
                if current.is_some() {
                    return Err(ReplayError::InvalidTruthcoinMarketState);
                }
            } else if current != Some(change.successor.as_slice()) {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum TruthcoinOutPointCodecV1 {
    Regular {
        txid: [u8; 32],
        vout: u32,
    },
    Coinbase {
        merkle_root: [u8; 32],
        vout: u32,
    },
    Deposit(bitcoin::OutPoint),
    MarketFunds {
        market_id: [u8; 6],
        block_height: u32,
        is_fee: bool,
    },
    Payout {
        hash: [u8; 32],
        vout: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TruthcoinConsolidationUndoEntryCodecV1 {
    market_id: [u8; 6],
    old_treasury_utxos: Vec<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
    old_fee_utxos: Vec<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
    old_treasury_pointer: Option<TruthcoinOutPointCodecV1>,
    old_fee_pointer: Option<TruthcoinOutPointCodecV1>,
    new_treasury_utxo: Option<TruthcoinOutPointCodecV1>,
    new_fee_utxo: Option<TruthcoinOutPointCodecV1>,
    sell_payout_utxos: Vec<TruthcoinOutPointCodecV1>,
    buy_change_utxos: Vec<TruthcoinOutPointCodecV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TruthcoinConsolidationUndoCodecV1 {
    entries: Vec<TruthcoinConsolidationUndoEntryCodecV1>,
    sell_input_change_utxos: Vec<TruthcoinOutPointCodecV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinTradeConsolidationUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

fn truthcoin_outpoint_key(outpoint: TruthcoinOutPointCodecV1) -> Result<[u8; 37], ReplayError> {
    let mut key = [0_u8; 37];
    match outpoint {
        TruthcoinOutPointCodecV1::Regular { txid, vout } => {
            key[0] = 0;
            key[1..33].copy_from_slice(&txid);
            key[33..].copy_from_slice(&vout.to_le_bytes());
        }
        TruthcoinOutPointCodecV1::Coinbase { merkle_root, vout } => {
            key[0] = 1;
            key[1..33].copy_from_slice(&merkle_root);
            key[33..].copy_from_slice(&vout.to_le_bytes());
        }
        TruthcoinOutPointCodecV1::Deposit(outpoint) => {
            use bitcoin::hashes::Hash as _;
            key[0] = 2;
            key[1..33].copy_from_slice(&outpoint.txid.to_byte_array());
            key[33..].copy_from_slice(&outpoint.vout.to_le_bytes());
        }
        TruthcoinOutPointCodecV1::MarketFunds {
            market_id,
            block_height,
            is_fee,
        } => {
            key[0] = 3;
            key[1..7].copy_from_slice(&market_id);
            key[7..11].copy_from_slice(&block_height.to_le_bytes());
            key[11] = u8::from(is_fee);
        }
        TruthcoinOutPointCodecV1::Payout { hash, vout } => {
            key[0] = 4;
            key[1..33].copy_from_slice(&hash);
            key[33..].copy_from_slice(&vout.to_le_bytes());
        }
    }
    Ok(key)
}

fn decode_truthcoin_outpoint(bytes: &[u8]) -> Result<TruthcoinOutPointCodecV1, ReplayError> {
    let outpoint: TruthcoinOutPointCodecV1 =
        bincode::deserialize(bytes).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
    if bincode::serialize(&outpoint).map_err(|_| ReplayError::InvalidTruthcoinMarketState)? != bytes
    {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    Ok(outpoint)
}

fn truthcoin_market_funds_pointer_key(market_id: [u8; 6], is_fee: bool) -> Vec<u8> {
    let mut key = market_id.to_vec();
    key.push(u8::from(is_fee));
    key
}

fn truthcoin_market_address(domain: &[u8], market_id: [u8; 6]) -> [u8; 20] {
    let mut address = [0_u8; 20];
    address.copy_from_slice(&blake3::hash(&[domain, &market_id].concat()).as_bytes()[..20]);
    address
}

fn truthcoin_synthetic_payout_outpoint(
    domain: &[u8],
    market_id: Option<[u8; 6]>,
    trader: [u8; 20],
    txid: [u8; 32],
) -> TruthcoinOutPointCodecV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    if let Some(market_id) = market_id {
        hasher.update(&market_id);
    }
    hasher.update(&trader);
    hasher.update(&txid);
    TruthcoinOutPointCodecV1::Payout {
        hash: *hasher.finalize().as_bytes(),
        vout: 0,
    }
}

fn put_truthcoin_consolidation_change(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    database: TruthcoinDatabaseId,
    key: Vec<u8>,
    successor: Vec<u8>,
) -> Result<(), ReplayError> {
    let prior = store.put(database.as_u8(), key.clone(), successor.clone())?;
    if prior.is_some() {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    changes.push(TruthcoinExactTableChangeV1 {
        database,
        key,
        prior,
        successor,
    });
    Ok(())
}

fn insert_truthcoin_consolidation_utxo(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    outpoint: TruthcoinOutPointCodecV1,
    output: TruthcoinFilledOutputV1,
) -> Result<(), ReplayError> {
    let key = truthcoin_outpoint_key(outpoint)?;
    let value =
        bincode::serialize(&output).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
    put_truthcoin_consolidation_change(
        store,
        changes,
        TruthcoinDatabaseId::Utxos,
        key.to_vec(),
        value,
    )?;
    put_truthcoin_consolidation_change(
        store,
        changes,
        TruthcoinDatabaseId::UtxosByAddress,
        truthcoin_address_index_key(output.address, &key),
        Vec::new(),
    )
}

fn delete_truthcoin_consolidation_utxo(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    outpoint: TruthcoinOutPointCodecV1,
) -> Result<TruthcoinFilledOutputV1, ReplayError> {
    let key = truthcoin_outpoint_key(outpoint)?;
    let prior = store
        .delete(TruthcoinDatabaseId::Utxos.as_u8(), &key)?
        .ok_or(ReplayError::MissingTruthcoinUtxo)?;
    let output = decode_truthcoin_filled_output(&prior)?;
    changes.push(TruthcoinExactTableChangeV1 {
        database: TruthcoinDatabaseId::Utxos,
        key: key.to_vec(),
        prior: Some(prior),
        successor: Vec::new(),
    });
    let index_key = truthcoin_address_index_key(output.address, &key);
    let index = store
        .delete(TruthcoinDatabaseId::UtxosByAddress.as_u8(), &index_key)?
        .ok_or(ReplayError::InvalidTruthcoinUtxoIndex)?;
    changes.push(TruthcoinExactTableChangeV1 {
        database: TruthcoinDatabaseId::UtxosByAddress,
        key: index_key,
        prior: Some(index),
        successor: Vec::new(),
    });
    Ok(output)
}

/// Apply upstream Truthcoin's C3 treasury/author-fee consolidation after the
/// regular transaction inputs have been moved to STXOs. The settlement list is
/// derived by the already validated market transition and cannot be supplied by
/// an unauthenticated caller.
pub fn apply_truthcoin_trade_consolidation(
    store: &mut CanonicalStateStoreV1,
    trade_undo: &TruthcoinTradeMarketUndoV1,
    height: u32,
) -> Result<TruthcoinTradeConsolidationUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let mut changes = Vec::new();
        let mut native_entries = Vec::new();
        let mut by_market = BTreeMap::<[u8; 6], Vec<TruthcoinPendingTradeSettlementV1>>::new();
        for settlement in &trade_undo.settlements {
            by_market
                .entry(settlement.market_id)
                .or_default()
                .push(*settlement);
        }

        for (market_id, settlements) in by_market {
            let treasury_pointer_key = truthcoin_market_funds_pointer_key(market_id, false);
            let fee_pointer_key = truthcoin_market_funds_pointer_key(market_id, true);
            let old_treasury_pointer = candidate
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &treasury_pointer_key,
                )?
                .map(decode_truthcoin_outpoint)
                .transpose()?;
            let old_fee_pointer = candidate
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &fee_pointer_key,
                )?
                .map(decode_truthcoin_outpoint)
                .transpose()?;
            let mut old_treasury_utxos = Vec::new();
            let mut old_fee_utxos = Vec::new();
            let mut treasury_total = 0_u64;
            let mut fee_total = 0_u64;
            if let Some(pointer) = old_treasury_pointer {
                let output = delete_truthcoin_consolidation_utxo(candidate, &mut changes, pointer)?;
                treasury_total = truthcoin_filled_bitcoin_value(&output)?;
                old_treasury_utxos.push((pointer, output));
            }
            if let Some(pointer) = old_fee_pointer {
                let output = delete_truthcoin_consolidation_utxo(candidate, &mut changes, pointer)?;
                fee_total = truthcoin_filled_bitcoin_value(&output)?;
                old_fee_utxos.push((pointer, output));
            }

            let mut sell_payout_utxos = Vec::new();
            let mut buy_change_utxos = Vec::new();
            let mut sell_gross = 0_u64;
            for settlement in &settlements {
                fee_total = fee_total
                    .checked_add(settlement.fee_sats)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                if settlement.is_buy {
                    treasury_total = treasury_total
                        .checked_add(settlement.base_sats)
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                    let change = settlement
                        .input_value_sats
                        .checked_sub(1_000)
                        .and_then(|value| value.checked_sub(settlement.base_sats))
                        .and_then(|value| value.checked_sub(settlement.fee_sats))
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                    if change > 0 {
                        let outpoint = truthcoin_synthetic_payout_outpoint(
                            b"BUY_CHANGE",
                            Some(market_id),
                            settlement.trader,
                            settlement.txid,
                        );
                        insert_truthcoin_consolidation_utxo(
                            candidate,
                            &mut changes,
                            outpoint,
                            TruthcoinFilledOutputV1 {
                                address: settlement.trader,
                                content: TruthcoinFilledContentV1::Bitcoin(change),
                                memo: Vec::new(),
                            },
                        )?;
                        buy_change_utxos.push(outpoint);
                    }
                } else {
                    sell_gross = sell_gross
                        .checked_add(settlement.base_sats)
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                    let outpoint = truthcoin_synthetic_payout_outpoint(
                        b"SELL_PAYOUT",
                        Some(market_id),
                        settlement.trader,
                        settlement.txid,
                    );
                    insert_truthcoin_consolidation_utxo(
                        candidate,
                        &mut changes,
                        outpoint,
                        TruthcoinFilledOutputV1 {
                            address: settlement.trader,
                            content: TruthcoinFilledContentV1::Bitcoin(
                                settlement.trader_value_sats,
                            ),
                            memo: Vec::new(),
                        },
                    )?;
                    sell_payout_utxos.push(outpoint);
                }
            }
            treasury_total = treasury_total
                .checked_sub(sell_gross)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;

            let prior_treasury_pointer = candidate.delete(
                TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                &treasury_pointer_key,
            )?;
            if let Some(prior) = prior_treasury_pointer {
                changes.push(TruthcoinExactTableChangeV1 {
                    database: TruthcoinDatabaseId::MarketFundsUtxos,
                    key: treasury_pointer_key.clone(),
                    prior: Some(prior),
                    successor: Vec::new(),
                });
            }
            let new_treasury_utxo = if treasury_total > 0 {
                let outpoint = TruthcoinOutPointCodecV1::MarketFunds {
                    market_id,
                    block_height: height,
                    is_fee: false,
                };
                insert_truthcoin_consolidation_utxo(
                    candidate,
                    &mut changes,
                    outpoint,
                    TruthcoinFilledOutputV1 {
                        address: truthcoin_market_address(b"MARKET_TREASURY_ADDRESS", market_id),
                        content: TruthcoinFilledContentV1::MarketFunds {
                            market_id,
                            amount: treasury_total,
                            is_fee: false,
                        },
                        memo: Vec::new(),
                    },
                )?;
                let encoded = bincode::serialize(&outpoint)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
                put_truthcoin_consolidation_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketFundsUtxos,
                    treasury_pointer_key,
                    encoded,
                )?;
                Some(outpoint)
            } else {
                None
            };

            let prior_fee_pointer = candidate.delete(
                TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                &fee_pointer_key,
            )?;
            if let Some(prior) = prior_fee_pointer {
                changes.push(TruthcoinExactTableChangeV1 {
                    database: TruthcoinDatabaseId::MarketFundsUtxos,
                    key: fee_pointer_key.clone(),
                    prior: Some(prior),
                    successor: Vec::new(),
                });
            }
            let new_fee_utxo = if fee_total > 0 {
                let outpoint = TruthcoinOutPointCodecV1::MarketFunds {
                    market_id,
                    block_height: height,
                    is_fee: true,
                };
                insert_truthcoin_consolidation_utxo(
                    candidate,
                    &mut changes,
                    outpoint,
                    TruthcoinFilledOutputV1 {
                        address: truthcoin_market_address(b"MARKET_AUTHOR_FEE_ADDRESS", market_id),
                        content: TruthcoinFilledContentV1::MarketFunds {
                            market_id,
                            amount: fee_total,
                            is_fee: true,
                        },
                        memo: Vec::new(),
                    },
                )?;
                let encoded = bincode::serialize(&outpoint)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
                put_truthcoin_consolidation_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketFundsUtxos,
                    fee_pointer_key,
                    encoded,
                )?;
                Some(outpoint)
            } else {
                None
            };

            native_entries.push(TruthcoinConsolidationUndoEntryCodecV1 {
                market_id,
                old_treasury_utxos,
                old_fee_utxos,
                old_treasury_pointer,
                old_fee_pointer,
                new_treasury_utxo,
                new_fee_utxo,
                sell_payout_utxos,
                buy_change_utxos,
            });
        }

        let mut sell_input_change_utxos = Vec::new();
        for settlement in &trade_undo.settlements {
            if !settlement.is_buy {
                let change = settlement
                    .input_value_sats
                    .checked_sub(1_000)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
                if change > 0 {
                    let outpoint = truthcoin_synthetic_payout_outpoint(
                        b"SELL_INPUT_CHANGE",
                        None,
                        settlement.trader,
                        settlement.txid,
                    );
                    insert_truthcoin_consolidation_utxo(
                        candidate,
                        &mut changes,
                        outpoint,
                        TruthcoinFilledOutputV1 {
                            address: settlement.trader,
                            content: TruthcoinFilledContentV1::Bitcoin(change),
                            memo: Vec::new(),
                        },
                    )?;
                    sell_input_change_utxos.push(outpoint);
                }
            }
        }

        if !native_entries.is_empty() || !sell_input_change_utxos.is_empty() {
            let native_undo = TruthcoinConsolidationUndoCodecV1 {
                entries: native_entries,
                sell_input_change_utxos,
            };
            put_truthcoin_consolidation_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::ConsolidationUndo,
                height.to_le_bytes().to_vec(),
                bincode::serialize(&native_undo)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
            )?;
        }
        Ok(TruthcoinTradeConsolidationUndoV1 { changes })
    })
}

pub fn revert_truthcoin_trade_consolidation(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinTradeConsolidationUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate.get(change.database.as_u8(), &change.key)?;
            if change.successor.is_empty() && change.prior.is_some() {
                if current.is_some() {
                    return Err(ReplayError::InvalidTruthcoinMarketState);
                }
            } else if current != Some(change.successor.as_slice()) {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinCompleteTradeUndoV1 {
    market: TruthcoinTradeMarketUndoV1,
    base_utxo: TruthcoinBaseUtxoUndoV1,
    consolidation: TruthcoinTradeConsolidationUndoV1,
    height_key: Vec<u8>,
    prior_skipped_indices: Option<Vec<u8>>,
}

/// Execute the complete upstream trade path as one authenticated state
/// transaction. This is the only safe public composition for production block
/// replay: market/share mutations, regular input spending and C3 consolidation
/// either all commit or all disappear.
pub fn apply_truthcoin_complete_trade_transition(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinCompleteTradeUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let market = apply_truthcoin_trade_market_transitions_inner(candidate, body, height, true)?;
        let skipped_indices: BTreeSet<_> = market.skipped_indices.iter().copied().collect();
        let base_utxo =
            apply_truthcoin_base_utxo_transition_inner(candidate, body, false, &skipped_indices)?;
        let consolidation = apply_truthcoin_trade_consolidation(candidate, &market, height)?;
        let height_key = height.to_le_bytes().to_vec();
        let prior_skipped_indices = candidate
            .get(
                TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                &height_key,
            )?
            .map(ToOwned::to_owned);
        if !market.skipped_indices.is_empty() {
            if prior_skipped_indices.is_some() {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let indices: Vec<u32> = market
                .skipped_indices
                .iter()
                .map(|index| u32::try_from(*index).map_err(|_| ReplayError::InvalidTruthcoinTrade))
                .collect::<Result<_, _>>()?;
            candidate.put(
                TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                height_key.clone(),
                bincode::serialize(&indices).map_err(|_| ReplayError::InvalidTruthcoinTrade)?,
            )?;
        }
        Ok(TruthcoinCompleteTradeUndoV1 {
            market,
            base_utxo,
            consolidation,
            height_key,
            prior_skipped_indices,
        })
    })
}

pub fn revert_truthcoin_complete_trade_transition(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinCompleteTradeUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        match &undo.prior_skipped_indices {
            Some(prior) => {
                candidate.put(
                    TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                    undo.height_key.clone(),
                    prior.clone(),
                )?;
            }
            None => {
                candidate.delete(
                    TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                    &undo.height_key,
                )?;
            }
        }
        revert_truthcoin_trade_consolidation(candidate, &undo.consolidation)?;
        revert_truthcoin_base_utxo_transition(candidate, &undo.base_utxo)?;
        revert_truthcoin_trade_market_transitions(candidate, &undo.market)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinAmplifyBetaUndoV1 {
    market: TruthcoinTradeMarketUndoV1,
    base_utxo: TruthcoinBaseUtxoUndoV1,
    consolidation: TruthcoinTradeConsolidationUndoV1,
}

fn apply_truthcoin_amplify_beta_market_inner(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinTradeMarketUndoV1, ReplayError> {
    validate_truthcoin_utxo_ownership(store, body)?;
    let actors = truthcoin_actor_addresses(body)?;
    store.transaction(|candidate| {
        let mut prior_markets = BTreeMap::<[u8; 6], TruthcoinMarketCodecV1>::new();
        let mut additions = BTreeMap::<[u8; 6], u64>::new();
        let mut settlements = Vec::new();
        for (transaction_bytes, actor) in body.transactions_borsh.iter().zip(actors) {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let Some(DecodedTruthcoinTransactionDataV1::AmplifyBeta {
                market_id,
                amount,
                market_author,
            }) = transaction.data
            else {
                return Err(ReplayError::InvalidTruthcoinTrade);
            };
            if amount == 0 || !transaction.outputs.is_empty() {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let market = match prior_markets.entry(market_id) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(decode_truthcoin_market(
                        candidate
                            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)?
                            .ok_or(ReplayError::InvalidTruthcoinTrade)?,
                    )?)
                }
            };
            if market.market_state != TruthcoinMarketStateCodecV1::Trading
                || market.creator_address != market_author
            {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let mut author_input = false;
            let mut input_value = 0_u64;
            for key in &transaction.input_keys {
                let output = decode_truthcoin_filled_output(
                    candidate
                        .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                        .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                )?;
                author_input |= output.address == market_author;
                input_value = input_value
                    .checked_add(truthcoin_filled_bitcoin_value(&output)?)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            }
            if (!author_input && actor != Some(market_author))
                || input_value
                    < amount
                        .checked_add(1_000)
                        .ok_or(ReplayError::InvalidTruthcoinTrade)?
            {
                return Err(ReplayError::InvalidTruthcoinTrade);
            }
            let total = additions.entry(market_id).or_default();
            *total = total
                .checked_add(amount)
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            settlements.push(TruthcoinPendingTradeSettlementV1 {
                market_id,
                trader: market_author,
                input_value_sats: input_value,
                base_sats: amount,
                fee_sats: 0,
                trader_value_sats: amount,
                txid: *blake3::hash(transaction_bytes).as_bytes(),
                is_buy: true,
            });
        }
        if settlements.is_empty() {
            return Err(ReplayError::InvalidTruthcoinTrade);
        }
        let native_undo = TruthcoinMarketTransitionUndoCodecV1 {
            entries: prior_markets.values().cloned().collect(),
            share_accounts: Vec::new(),
        };
        let mut changes = Vec::new();
        put_exact_market_change(
            candidate,
            &mut changes,
            TruthcoinDatabaseId::MarketTransitionUndo,
            height.to_le_bytes().to_vec(),
            bincode::serialize(&native_undo)
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
        )?;
        for (market_id, mut market) in prior_markets {
            market.liquidity_base_sats = market
                .liquidity_base_sats
                .checked_add(additions[&market_id])
                .ok_or(ReplayError::InvalidTruthcoinTrade)?;
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::Markets,
                market_id.to_vec(),
                bincode::serialize(&market)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
            )?;
        }
        Ok(TruthcoinTradeMarketUndoV1 {
            changes,
            settlements,
            skipped_indices: Vec::new(),
        })
    })
}

/// Execute a block body consisting exclusively of `AmplifyBeta`
/// transactions. The author-funded input, liquidity mutation, regular UTXO
/// spend, treasury consolidation, miner fee, and deterministic change output
/// commit atomically.
pub fn apply_truthcoin_amplify_beta_transition(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinAmplifyBetaUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let market = apply_truthcoin_amplify_beta_market_inner(candidate, body, height)?;
        let base_utxo =
            apply_truthcoin_base_utxo_transition_inner(candidate, body, false, &BTreeSet::new())?;
        let consolidation = apply_truthcoin_trade_consolidation(candidate, &market, height)?;
        Ok(TruthcoinAmplifyBetaUndoV1 {
            market,
            base_utxo,
            consolidation,
        })
    })
}

pub fn revert_truthcoin_amplify_beta_transition(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinAmplifyBetaUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        revert_truthcoin_trade_consolidation(candidate, &undo.consolidation)?;
        revert_truthcoin_base_utxo_transition(candidate, &undo.base_utxo)?;
        revert_truthcoin_trade_market_transitions(candidate, &undo.market)?;
        Ok(())
    })
}

fn truthcoin_market_decision_id(spec: DecodedTruthcoinDimensionSpecV1) -> [u8; 3] {
    match spec {
        DecodedTruthcoinDimensionSpecV1::Single(id)
        | DecodedTruthcoinDimensionSpecV1::Categorical(id) => id,
    }
}

fn truthcoin_stored_decision(
    store: &CanonicalStateStoreV1,
    decision_id: [u8; 3],
) -> Result<TruthcoinStoredDecisionV1, ReplayError> {
    let period_key = u32::from(decision_id[0] & 0x7f).to_le_bytes();
    let entries = decode_truthcoin_period_decisions(
        store
            .get(TruthcoinDatabaseId::PeriodDecisions.as_u8(), &period_key)?
            .ok_or(ReplayError::InvalidTruthcoinMarketState)?,
    )?;
    entries
        .into_iter()
        .find(|entry| entry.decision_id == decision_id)
        .and_then(|entry| entry.decision)
        .ok_or(ReplayError::InvalidTruthcoinMarketCreation)
}

fn truthcoin_market_id(
    creation: &DecodedTruthcoinMarketCreationV1,
    creator: [u8; 20],
) -> Result<[u8; 6], ReplayError> {
    let mut borsh = Vec::new();
    for value in [&creation.title, &creation.description] {
        borsh.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| ReplayError::InvalidTruthcoinMarketCreation)?
                .to_le_bytes(),
        );
        borsh.extend_from_slice(value.as_bytes());
    }
    borsh.extend_from_slice(&creator);
    borsh.extend_from_slice(
        &u32::try_from(creation.dimension_specs.len())
            .map_err(|_| ReplayError::InvalidTruthcoinMarketCreation)?
            .to_le_bytes(),
    );
    for spec in &creation.dimension_specs {
        match spec {
            DecodedTruthcoinDimensionSpecV1::Single(id) => {
                borsh.push(0);
                borsh.extend_from_slice(id);
            }
            DecodedTruthcoinDimensionSpecV1::Categorical(id) => {
                borsh.push(1);
                borsh.extend_from_slice(id);
            }
        }
    }
    blake3::hash(&borsh).as_bytes()[..6]
        .try_into()
        .map_err(|_| ReplayError::InvalidTruthcoinMarketCreation)
}

fn put_bincode_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), ReplayError> {
    bytes.extend_from_slice(
        &u64::try_from(len)
            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?
            .to_le_bytes(),
    );
    Ok(())
}

fn decode_market_id_index(bytes: Option<&[u8]>) -> Result<Vec<[u8; 6]>, ReplayError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let count = cursor.length()?;
    if count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    let mut ids = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        ids.push(
            cursor
                .take(6)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
        );
    }
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    Ok(ids)
}

fn encode_market_id_index(ids: &[[u8; 6]]) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();
    put_bincode_len(&mut bytes, ids.len())?;
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Ok(bytes)
}

fn cartesian_truthcoin_states(dimensions: &[usize]) -> Result<Vec<Vec<usize>>, ReplayError> {
    let mut result = vec![Vec::new()];
    for &size in dimensions {
        let capacity = result
            .len()
            .checked_mul(size)
            .ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
        if capacity > 64 {
            return Err(ReplayError::InvalidTruthcoinMarketCreation);
        }
        let mut successor = Vec::with_capacity(capacity);
        for combo in result {
            for value in 0..size {
                let mut next = combo.clone();
                next.push(value);
                successor.push(next);
            }
        }
        result = successor;
    }
    Ok(result)
}

fn encode_truthcoin_market(
    creation: &DecodedTruthcoinMarketCreationV1,
    creator: [u8; 20],
    market_id: [u8; 6],
    height: u32,
    liquidity_base_sats: u64,
    decisions: &[(DecodedTruthcoinDimensionSpecV1, TruthcoinStoredDecisionV1)],
) -> Result<Vec<u8>, ReplayError> {
    let mut dimension_sizes = Vec::with_capacity(decisions.len());
    let mut tradeable_sizes = Vec::with_capacity(decisions.len());
    let mut tags = BTreeSet::new();
    for (spec, decision) in decisions {
        for tag in &decision.tags {
            tags.insert(tag.clone());
        }
        match (spec, &decision.decision_type) {
            (DecodedTruthcoinDimensionSpecV1::Single(_), _) => {
                dimension_sizes.push(3);
                tradeable_sizes.push(2);
            }
            (
                DecodedTruthcoinDimensionSpecV1::Categorical(_),
                DecodedTruthcoinDecisionTypeV1::Category { options },
            ) if options.len() >= 2 => {
                dimension_sizes.push(options.len());
                tradeable_sizes.push(options.len());
            }
            _ => return Err(ReplayError::InvalidTruthcoinMarketCreation),
        }
    }
    let outcomes = tradeable_sizes
        .iter()
        .try_fold(1_usize, |value, size| value.checked_mul(*size))
        .ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
    if outcomes == 0 || outcomes > 64 {
        return Err(ReplayError::InvalidTruthcoinMarketCreation);
    }
    let state_combos = cartesian_truthcoin_states(&dimension_sizes)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&market_id);
    put_bincode_string(&mut bytes, &creation.title)?;
    put_bincode_string(&mut bytes, &creation.description)?;
    put_bincode_len(&mut bytes, tags.len())?;
    for tag in tags {
        put_bincode_string(&mut bytes, &tag)?;
    }
    bytes.extend_from_slice(&creator);
    put_bincode_len(&mut bytes, creation.dimension_specs.len())?;
    for spec in &creation.dimension_specs {
        match spec {
            DecodedTruthcoinDimensionSpecV1::Single(id) => {
                bytes.extend_from_slice(&0_u32.to_le_bytes());
                bytes.extend_from_slice(id);
            }
            DecodedTruthcoinDimensionSpecV1::Categorical(id) => {
                bytes.extend_from_slice(&1_u32.to_le_bytes());
                bytes.extend_from_slice(id);
            }
        }
    }
    put_bincode_len(&mut bytes, decisions.len())?;
    for (spec, _) in decisions {
        bytes.extend_from_slice(&truthcoin_market_decision_id(*spec));
    }
    put_bincode_len(&mut bytes, state_combos.len())?;
    for combo in state_combos {
        put_bincode_len(&mut bytes, combo.len())?;
        for state in combo {
            bytes.extend_from_slice(
                &u64::try_from(state)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?
                    .to_le_bytes(),
            );
        }
    }
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.push(0); // expires_at_height: None
    bytes.push(5); // tau_from_now
    bytes.extend_from_slice(&(1_000_u64 + (outcomes as u64).pow(2)).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // MarketState::Trading serde variant
    bytes.extend_from_slice(&creation.trading_fee.unwrap_or(0.005).to_le_bytes());
    bytes.extend_from_slice(&liquidity_base_sats.to_le_bytes());
    put_bincode_len(&mut bytes, outcomes)?;
    bytes.resize(bytes.len() + outcomes * 8, 0); // shares: i64 zeros
    put_bincode_len(&mut bytes, outcomes)?;
    bytes.resize(bytes.len() + outcomes * 8, 0); // final_prices: f64 zeros
    bytes.extend_from_slice(&0_u64.to_le_bytes()); // version
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes()); // total volume
    put_bincode_len(&mut bytes, outcomes)?;
    bytes.resize(bytes.len() + outcomes * 8, 0); // outcome volumes
    bytes.push(creation.tx_pow_hash_selector.unwrap_or(0));
    bytes.push(creation.tx_pow_ordering.unwrap_or(0));
    bytes.push(creation.tx_pow_difficulty.unwrap_or(0));
    Ok(bytes)
}

fn put_exact_market_change(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    database: TruthcoinDatabaseId,
    key: Vec<u8>,
    successor: Vec<u8>,
) -> Result<(), ReplayError> {
    let prior = store.put(database.as_u8(), key.clone(), successor.clone())?;
    changes.push(TruthcoinExactTableChangeV1 {
        database,
        key,
        prior,
        successor,
    });
    Ok(())
}

pub fn apply_truthcoin_market_creations(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinMarketCreationUndoV1, ReplayError> {
    validate_truthcoin_utxo_ownership(store, body)?;
    store.transaction(|candidate| {
        let mut changes = Vec::new();
        for transaction_bytes in &body.transactions_borsh {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let Some(DecodedTruthcoinTransactionDataV1::CreateMarket(creation)) = transaction.data
            else {
                continue;
            };
            if creation.title.is_empty()
                || creation.dimension_specs.is_empty()
                || creation
                    .trading_fee
                    .is_some_and(|fee| !fee.is_finite() || !(0.0..=1.0).contains(&fee))
                || creation.tx_pow_difficulty.unwrap_or(0) > 32
                || (creation.tx_pow_difficulty.unwrap_or(0) > 0
                    && creation.tx_pow_hash_selector.unwrap_or(0) == 0)
            {
                return Err(ReplayError::InvalidTruthcoinMarketCreation);
            }
            let input = transaction
                .input_keys
                .first()
                .ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
            let creator = decode_truthcoin_filled_output(
                candidate
                    .get(TruthcoinDatabaseId::Utxos.as_u8(), input)?
                    .ok_or(ReplayError::MissingTruthcoinUtxo)?,
            )?
            .address;
            let market_id = truthcoin_market_id(&creation, creator)?;
            if candidate
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)?
                .is_some()
            {
                return Err(ReplayError::InvalidTruthcoinMarketCreation);
            }
            let mut seen = BTreeSet::new();
            let mut decisions = Vec::with_capacity(creation.dimension_specs.len());
            for spec in &creation.dimension_specs {
                let id = truthcoin_market_decision_id(*spec);
                if !seen.insert(id) {
                    return Err(ReplayError::InvalidTruthcoinMarketCreation);
                }
                decisions.push((*spec, truthcoin_stored_decision(candidate, id)?));
            }
            let mut treasury = None;
            let txid = *blake3::hash(transaction_bytes).as_bytes();
            for (vout, output) in transaction.outputs.iter().enumerate() {
                if let DecodedTruthcoinOutputContentV1::MarketFunds {
                    market_id: id,
                    amount,
                    is_fee: false,
                } = &output.content
                {
                    if *id == market_id && *amount > 0 {
                        treasury = Some((
                            *amount,
                            u32::try_from(vout)
                                .map_err(|_| ReplayError::InvalidTruthcoinMarketCreation)?,
                        ));
                        break;
                    }
                }
            }
            let (liquidity, vout) = treasury.ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
            let market = encode_truthcoin_market(
                &creation, creator, market_id, height, liquidity, &decisions,
            )?;
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::Markets,
                market_id.to_vec(),
                market,
            )?;

            let state_key = 0_u32.to_le_bytes().to_vec();
            let mut state_ids = decode_market_id_index(
                candidate.get(TruthcoinDatabaseId::MarketsByState.as_u8(), &state_key)?,
            )?;
            state_ids.push(market_id);
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MarketsByState,
                state_key,
                encode_market_id_index(&state_ids)?,
            )?;
            for (spec, _) in &decisions {
                let id = truthcoin_market_decision_id(*spec);
                let mut ids = decode_market_id_index(
                    candidate.get(TruthcoinDatabaseId::MarketsByDecision.as_u8(), &id)?,
                )?;
                ids.push(market_id);
                put_exact_market_change(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::MarketsByDecision,
                    id.to_vec(),
                    encode_market_id_index(&ids)?,
                )?;
            }
            let mut funds_key = market_id.to_vec();
            funds_key.push(0); // bincode false
            let mut outpoint = 0_u32.to_le_bytes().to_vec(); // OutPoint::Regular
            outpoint.extend_from_slice(&txid);
            outpoint.extend_from_slice(&vout.to_le_bytes());
            put_exact_market_change(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MarketFundsUtxos,
                funds_key,
                outpoint,
            )?;
        }
        Ok(TruthcoinMarketCreationUndoV1 { changes })
    })
}

pub fn revert_truthcoin_market_creations(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinMarketCreationUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let current = candidate
                .get(change.database.as_u8(), &change.key)?
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
            if current != change.successor {
                return Err(ReplayError::InvalidTruthcoinMarketState);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

const TRUTHCOIN_FUTURE_PERIODS: u32 = 20;
const TRUTHCOIN_GENESIS_P_PERIOD_SATS: u64 = 10_000;
#[cfg(not(feature = "truthcoin-alpha-one-day-period"))]
const TRUTHCOIN_PERIOD_SECONDS: u64 = 7_862_400;
#[cfg(feature = "truthcoin-alpha-one-day-period")]
const TRUTHCOIN_PERIOD_SECONDS: u64 = 86_400;
const TRUTHCOIN_REPRICE_INTERVAL_BLOCKS: u32 = 2_620;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TruthcoinPeriodPricingV1 {
    p_period: u64,
    p_floor: u64,
    mints: u64,
    claimed: u64,
    last_reprice_block: u32,
    window_open_claimed: u64,
    window_open_mints: u64,
}

fn decode_truthcoin_period_pricing(bytes: &[u8]) -> Result<TruthcoinPeriodPricingV1, ReplayError> {
    if bytes.len() != 52 {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let pricing = TruthcoinPeriodPricingV1 {
        p_period: cursor.u64()?,
        p_floor: cursor.u64()?,
        mints: cursor.u64()?,
        claimed: cursor.u64()?,
        last_reprice_block: cursor.u32()?,
        window_open_claimed: cursor.u64()?,
        window_open_mints: cursor.u64()?,
    };
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(pricing)
}

fn encode_truthcoin_period_pricing(pricing: TruthcoinPeriodPricingV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(&pricing.p_period.to_le_bytes());
    bytes.extend_from_slice(&pricing.p_floor.to_le_bytes());
    bytes.extend_from_slice(&pricing.mints.to_le_bytes());
    bytes.extend_from_slice(&pricing.claimed.to_le_bytes());
    bytes.extend_from_slice(&pricing.last_reprice_block.to_le_bytes());
    bytes.extend_from_slice(&pricing.window_open_claimed.to_le_bytes());
    bytes.extend_from_slice(&pricing.window_open_mints.to_le_bytes());
    bytes
}

fn truthcoin_current_period(timestamp: u64, genesis_timestamp: u64) -> Result<u32, ReplayError> {
    if genesis_timestamp == 0 || timestamp < genesis_timestamp {
        return Ok(0);
    }
    u32::try_from((timestamp - genesis_timestamp) / TRUTHCOIN_PERIOD_SECONDS + 1)
        .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)
}

fn truthcoin_reprice(p_old: u64, sales: u64, available_at_open: u64) -> u64 {
    if available_at_open == 0 {
        return p_old;
    }
    if sales == 0 {
        return p_old / 2;
    }
    if sales == available_at_open {
        return p_old.saturating_mul(2);
    }
    if sales.saturating_mul(2) == available_at_open {
        return p_old;
    }
    let q32 = 1_i128 << 32;
    let exponent = (i128::from(sales) * 2 * q32 / i128::from(available_at_open)) - q32;
    let integer = exponent.div_euclid(q32);
    let fraction = exponent.rem_euclid(q32) as u128;
    let q62 = 1_u128 << 62;
    let x = ((fraction << 30) * 0x_2C5C_85FD_F473_DE6B_u128) >> 62;
    let mut term = q62;
    let mut sum = q62;
    for divisor in 1_u128..12 {
        term = ((term * x) >> 62) / divisor;
        sum += term;
    }
    let mut factor = sum >> 30;
    if integer >= 0 {
        if integer >= 64 {
            factor = u128::MAX;
        } else {
            factor <<= integer as u32;
        }
    } else {
        let shift = (-integer) as u32;
        factor = if shift >= 64 { 0 } else { factor >> shift };
    }
    ((u128::from(p_old) * factor) >> 32) as u64
}

fn truthcoin_apply_reprice(pricing: &mut TruthcoinPeriodPricingV1, height: u32) {
    if pricing.last_reprice_block == height {
        return;
    }
    let sales = pricing.claimed.saturating_sub(pricing.window_open_claimed);
    let available = pricing
        .window_open_mints
        .saturating_mul(25)
        .saturating_sub(pricing.window_open_claimed);
    pricing.p_period = truthcoin_reprice(pricing.p_period, sales, available).max(pricing.p_floor);
    pricing.last_reprice_block = height;
    pricing.window_open_claimed = pricing.claimed;
    pricing.window_open_mints = pricing.mints;
}

fn encode_truthcoin_pricing_snapshot(entries: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = u64::try_from(entries.len())
        .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?
        .to_le_bytes()
        .to_vec();
    for (period, pricing) in entries {
        decode_truthcoin_period_pricing(pricing)?;
        bytes.extend_from_slice(&period.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(pricing);
    }
    Ok(bytes)
}

fn decode_truthcoin_state_history(
    bytes: &[u8],
) -> Result<Vec<(u32, u32, Option<f64>)>, ReplayError> {
    let mut cursor = TruthcoinBincodeCursor(bytes);
    let count = cursor.length()?;
    if count > MAX_STATE_TABLE_ENTRIES {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let mut history = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        let state = cursor.u32()?;
        if state > 4 {
            return Err(ReplayError::InvalidTruthcoinDecisionState);
        }
        let height = cursor.u32()?;
        let outcome = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.f64()?),
            _ => return Err(ReplayError::InvalidTruthcoinDecisionState),
        };
        history.push((state, height, outcome));
    }
    if !cursor.0.is_empty() {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(history)
}

fn encode_truthcoin_state_history(
    history: &[(u32, u32, Option<f64>)],
) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = u64::try_from(history.len())
        .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?
        .to_le_bytes()
        .to_vec();
    for (state, height, outcome) in history {
        bytes.extend_from_slice(&state.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        match outcome {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinDecisionFrameUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinBlockIdentityUndoV1 {
    changes: Vec<TruthcoinExactTableChangeV1>,
}

/// Advance the two chain-identity tables written last by upstream
/// `apply_block`. The header bytes are the authenticated Borsh header, so the
/// new tip is derived rather than supplied by the host.
pub fn apply_truthcoin_block_identity(
    store: &mut CanonicalStateStoreV1,
    height: u32,
    header_borsh: &[u8],
) -> Result<TruthcoinBlockIdentityUndoV1, ReplayError> {
    let (_, previous_side, _) = parse_truthcoin_header(header_borsh)?;
    store.transaction(|candidate| {
        let prior_tip = candidate
            .get(TruthcoinDatabaseId::Tip.as_u8(), &TRUTHCOIN_UNIT_KEY)?
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)
            })
            .transpose()?;
        let prior_height = candidate
            .get(TruthcoinDatabaseId::Height.as_u8(), &TRUTHCOIN_UNIT_KEY)?
            .map(|bytes| {
                Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    ReplayError::InvalidTruthcoinHeaderEncoding
                })?))
            })
            .transpose()?;
        if height == 0 {
            if prior_tip.is_some() || prior_height.is_some() || previous_side.is_some() {
                return Err(ReplayError::InvalidTruthcoinHeaderEncoding);
            }
        } else if prior_tip != previous_side
            || prior_height.and_then(|value| value.checked_add(1)) != Some(height)
        {
            return Err(ReplayError::InvalidTruthcoinHeaderEncoding);
        }
        let mut changes = Vec::new();
        truthcoin_record_put(
            candidate,
            &mut changes,
            TruthcoinDatabaseId::Tip,
            TRUTHCOIN_UNIT_KEY.to_vec(),
            blake3::hash(header_borsh).as_bytes().to_vec(),
        )?;
        truthcoin_record_put(
            candidate,
            &mut changes,
            TruthcoinDatabaseId::Height,
            TRUTHCOIN_UNIT_KEY.to_vec(),
            height.to_le_bytes().to_vec(),
        )?;
        Ok(TruthcoinBlockIdentityUndoV1 { changes })
    })
}

pub fn revert_truthcoin_block_identity(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinBlockIdentityUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            if candidate.get(change.database.as_u8(), &change.key)?
                != Some(change.successor.as_slice())
            {
                return Err(ReplayError::InvalidTruthcoinHeaderEncoding);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinBlockTransitionUndoV1 {
    prior_checkpoint: Vec<u8>,
    successor_root: Hash32,
}

fn preinitialize_truthcoin_block_frame(
    store: &mut CanonicalStateStoreV1,
    height: u32,
    timestamp: u64,
) -> Result<(), ReplayError> {
    let height_key = height.to_le_bytes();
    if store
        .get(
            TruthcoinDatabaseId::MainchainTimestampUndo.as_u8(),
            &height_key,
        )?
        .is_some()
    {
        return Err(ReplayError::InvalidTruthcoinDecisionFrame);
    }
    let prior = store.get(
        TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
        &TRUTHCOIN_UNIT_KEY,
    )?;
    let undo = match prior {
        None => vec![0],
        Some(bytes) if bytes.len() == 8 => {
            let mut undo = vec![1];
            undo.extend_from_slice(bytes);
            undo
        }
        Some(_) => return Err(ReplayError::InvalidTruthcoinDecisionFrame),
    };
    store.put(
        TruthcoinDatabaseId::MainchainTimestampUndo.as_u8(),
        height_key.to_vec(),
        undo,
    )?;
    store.put(
        TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
        TRUTHCOIN_UNIT_KEY.to_vec(),
        timestamp.to_le_bytes().to_vec(),
    )?;
    if height == 0 {
        if store
            .put(
                TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                timestamp.to_le_bytes().to_vec(),
            )?
            .is_some()
        {
            return Err(ReplayError::InvalidTruthcoinDecisionFrame);
        }
    } else if store
        .get(
            TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )?
        .is_none()
    {
        return Err(ReplayError::InvalidTruthcoinDecisionFrame);
    }

    let pricing_entries: Vec<(u32, Vec<u8>)> = store
        .entries(TruthcoinDatabaseId::PeriodPricing.as_u8())?
        .map(|(key, value)| {
            let period = u32::from_le_bytes(
                key.try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
            );
            Ok((period, value.to_vec()))
        })
        .collect::<Result<_, ReplayError>>()?;
    if store
        .put(
            TruthcoinDatabaseId::PeriodPricingUndo.as_u8(),
            height_key.to_vec(),
            encode_truthcoin_pricing_snapshot(&pricing_entries)?,
        )?
        .is_some()
    {
        return Err(ReplayError::InvalidTruthcoinDecisionFrame);
    }

    let period_keys: Vec<u32> = store
        .entries(TruthcoinDatabaseId::PeriodDecisions.as_u8())?
        .map(|(key, _)| {
            Ok(u32::from_le_bytes(
                key.try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
            ))
        })
        .collect::<Result<_, ReplayError>>()?;
    let previous_highest = period_keys.iter().copied().max().unwrap_or(0);
    if store
        .put(
            TruthcoinDatabaseId::MintingUndo.as_u8(),
            height_key.to_vec(),
            previous_highest.to_le_bytes().to_vec(),
        )?
        .is_some()
    {
        return Err(ReplayError::InvalidTruthcoinDecisionFrame);
    }

    let genesis_timestamp = store
        .get(
            TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )?
        .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?;
    let genesis_timestamp = u64::from_le_bytes(
        genesis_timestamp
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
    );
    let current_period = truthcoin_current_period(timestamp, genesis_timestamp)?;
    let histories: Vec<(Vec<u8>, Vec<u8>)> = store
        .entries(TruthcoinDatabaseId::DecisionStateHistories.as_u8())?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    for (key, value) in histories {
        let decision_id: [u8; 3] = key
            .as_slice()
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
        let mut history = decode_truthcoin_state_history(&value)?;
        if history.last().is_some_and(|entry| entry.0 == 1)
            && current_period > u32::from(decision_id[0] & 0x7f)
        {
            history.push((2, height, None));
            store.put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                key,
                encode_truthcoin_state_history(&history)?,
            )?;
        }
    }
    Ok(())
}

fn decode_truthcoin_coinbase(
    body: &TruthcoinBodyV1,
) -> Result<DecodedTruthcoinTransactionV1, ReplayError> {
    // A Truthcoin Body coinbase is Borsh(Vec<Output>), not a Transaction.
    // Wrap it in a canonical zero-input, empty-memo, data=None transaction so
    // it is decoded by the exact same output codec as ordinary transactions.
    let mut encoded = 0_u32.to_le_bytes().to_vec();
    encoded.extend_from_slice(&body.coinbase_borsh);
    encoded.extend_from_slice(&0_u32.to_le_bytes());
    encoded.push(0);
    decode_truthcoin_transaction(&encoded)
}

fn validate_truthcoin_block_fees(
    store: &CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    skipped_indices: &BTreeSet<usize>,
) -> Result<(), ReplayError> {
    const TRADE_MINER_FEE_SATS: u64 = 1_000;

    let coinbase = decode_truthcoin_coinbase(body)?;
    let coinbase_value = coinbase.outputs.iter().try_fold(0_u64, |sum, output| {
        if matches!(
            output.content,
            DecodedTruthcoinOutputContentV1::MarketFunds { .. }
        ) {
            return Err(ReplayError::InvalidTruthcoinCoinbase);
        }
        sum.checked_add(truthcoin_output_bitcoin_value(output)?)
            .ok_or(ReplayError::InvalidTruthcoinBlockFees)
    })?;

    let mut total_fees = 0_u64;
    for (index, transaction_bytes) in body.transactions_borsh.iter().enumerate() {
        // Upstream soft-skipped trades neither spend their inputs nor pay the
        // fixed trade miner fee. Counting that fee would admit the exact
        // invalid Alpha BMM candidates that this replay must reject.
        if skipped_indices.contains(&index) {
            continue;
        }
        let transaction = decode_truthcoin_transaction(transaction_bytes)?;
        let fee = if matches!(
            transaction.data,
            Some(DecodedTruthcoinTransactionDataV1::Trade(_))
                | Some(DecodedTruthcoinTransactionDataV1::AmplifyBeta { .. })
        ) {
            TRADE_MINER_FEE_SATS
        } else {
            let input_value = transaction.input_keys.iter().try_fold(0_u64, |sum, key| {
                let output = decode_truthcoin_filled_output(
                    store
                        .get(TruthcoinDatabaseId::Utxos.as_u8(), key)?
                        .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                )?;
                sum.checked_add(truthcoin_filled_bitcoin_value(&output)?)
                    .ok_or(ReplayError::InvalidTruthcoinBlockFees)
            })?;
            let output_value = transaction.outputs.iter().try_fold(0_u64, |sum, output| {
                sum.checked_add(truthcoin_output_bitcoin_value(output)?)
                    .ok_or(ReplayError::InvalidTruthcoinBlockFees)
            })?;
            input_value
                .checked_sub(output_value)
                .ok_or(ReplayError::InvalidTruthcoinBlockFees)?
        };
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(ReplayError::InvalidTruthcoinBlockFees)?;
    }
    if coinbase_value > total_fees {
        return Err(ReplayError::InvalidTruthcoinBlockFees);
    }
    Ok(())
}

/// Execute one authenticated, valid-transaction Truthcoin block against the
/// canonical 37-table checkpoint. Every specialized transition and every
/// native undo table commits under one outer transaction. Authenticated trades
/// that fail their buy/sell price limit are soft-skipped exactly as upstream;
/// every other malformed transaction fails the entire candidate block.
pub fn apply_truthcoin_block_transition(
    store: &mut CanonicalStateStoreV1,
    block: &TruthcoinBlockV1,
    context: CanonicalBlockContextV1,
) -> Result<TruthcoinBlockTransitionUndoV1, ReplayError> {
    if block.version != TruthcoinBlockV1::VERSION
        || block.height != context.sidechain_height
        || block.block_hash() != context.sidechain_block_hash
        || block.bmm_main_height != context.bmm_main_height
        || block.height > u64::from(u32::MAX)
    {
        return Err(ReplayError::InvalidTruthcoinHeaderEncoding);
    }
    let (merkle_root, _, _) = parse_truthcoin_header(&block.header_borsh)?;
    if merkle_root != truthcoin_body_merkle_root(&block.body) {
        return Err(ReplayError::InvalidTruthcoinMerkleRoot);
    }
    validate_truthcoin_authorization_envelopes(&block.body)?;
    validate_truthcoin_utxo_ownership(store, &block.body)?;
    // Match native BlockValidator::prevalidate: claim eligibility and fees
    // use pre-block clock/pricing/history, not the incoming BMM timestamp.
    validate_truthcoin_decision_claims(store, &block.body)?;
    let height =
        u32::try_from(block.height).map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)?;
    let prior_checkpoint = store.export()?;
    store.transaction(|candidate| {
        preinitialize_truthcoin_block_frame(candidate, height, context.bmm_main_timestamp)?;
        if height == 0 {
            // Pinned Truthcoin 0.17.0 `connect_prevalidated` assigns the first
            // genesis coinbase recipient the initial voting reputation.
            // Coinbase is Borsh(Vec<Output>), so decode it through the same
            // canonical transaction wrapper used by the base UTXO transition.
            let mut encoded = 0_u32.to_le_bytes().to_vec();
            encoded.extend_from_slice(&block.body.coinbase_borsh);
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.push(0);
            let coinbase = decode_truthcoin_transaction(&encoded)?;
            if let Some(first_coinbase) = coinbase.outputs.first() {
                set_truthcoin_reputation(candidate, first_coinbase.address, 1.0)?;
            }
        }
        let mut created_markets = BTreeSet::new();
        let mut updated_markets = BTreeSet::new();
        for transaction_bytes in &block.body.transactions_borsh {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            match transaction.data {
                Some(DecodedTruthcoinTransactionDataV1::CreateMarket(creation)) => {
                    let first_input = transaction
                        .input_keys
                        .first()
                        .ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
                    let creator = decode_truthcoin_filled_output(
                        candidate
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), first_input)?
                            .ok_or(ReplayError::MissingTruthcoinUtxo)?,
                    )?
                    .address;
                    created_markets.insert(truthcoin_market_id(&creation, creator)?);
                }
                Some(DecodedTruthcoinTransactionDataV1::Trade(trade)) => {
                    updated_markets.insert(trade.market_id);
                }
                Some(DecodedTruthcoinTransactionDataV1::AmplifyBeta { market_id, .. }) => {
                    updated_markets.insert(market_id);
                }
                _ => {}
            }
        }
        if created_markets
            .iter()
            .any(|market_id| updated_markets.contains(market_id))
        {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }

        apply_prevalidated_truthcoin_decision_claim_mutations(candidate, &block.body, height)?;
        apply_truthcoin_market_creations(candidate, &block.body, height)?;
        apply_truthcoin_reputation_transitions(candidate, &block.body, height)?;
        apply_truthcoin_voting_transitions(candidate, &block.body, height)?;
        let market =
            apply_truthcoin_trade_market_transitions_inner(candidate, &block.body, height, true)?;
        let skipped_indices: BTreeSet<_> = market.skipped_indices.iter().copied().collect();
        validate_truthcoin_block_fees(candidate, &block.body, &skipped_indices)?;
        apply_truthcoin_base_utxo_transition_inner(
            candidate,
            &block.body,
            false,
            &skipped_indices,
        )?;
        apply_truthcoin_trade_consolidation(candidate, &market, height)?;
        apply_truthcoin_decision_block_frame(candidate, height, context.bmm_main_timestamp)?;

        apply_truthcoin_no_vote_consensus(candidate, height)?;
        let consensus_key = height.to_le_bytes();
        let no_vote_undo = candidate
            .get(TruthcoinDatabaseId::ConsensusUndo.as_u8(), &consensus_key)?
            .map(ToOwned::to_owned);
        apply_truthcoin_voted_consensus(candidate, height)?;
        let voted_undo = candidate
            .get(TruthcoinDatabaseId::ConsensusUndo.as_u8(), &consensus_key)?
            .map(ToOwned::to_owned);
        if let (Some(no_vote), Some(voted)) = (&no_vote_undo, &voted_undo) {
            if no_vote != voted {
                let mut combined: TruthcoinConsensusUndoCodecV1 = bincode::deserialize(no_vote)
                    .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
                let voted: TruthcoinConsensusUndoCodecV1 = bincode::deserialize(voted)
                    .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?;
                combined.entries.extend(voted.entries);
                combined.entries.sort_by_key(|entry| entry.period_id);
                if combined
                    .entries
                    .windows(2)
                    .any(|pair| pair[0].period_id == pair[1].period_id)
                {
                    return Err(ReplayError::InvalidTruthcoinVotingState);
                }
                candidate.put(
                    TruthcoinDatabaseId::ConsensusUndo.as_u8(),
                    consensus_key.to_vec(),
                    bincode::serialize(&combined)
                        .map_err(|_| ReplayError::InvalidTruthcoinVotingState)?,
                )?;
            }
        }
        apply_truthcoin_resolved_market_settlements(candidate, height)?;
        if !market.skipped_indices.is_empty() {
            let indices: Vec<u32> = market
                .skipped_indices
                .iter()
                .map(|index| u32::try_from(*index).map_err(|_| ReplayError::InvalidTruthcoinTrade))
                .collect::<Result<_, ReplayError>>()?;
            candidate.put(
                TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                height.to_le_bytes().to_vec(),
                bincode::serialize(&indices).map_err(|_| ReplayError::InvalidTruthcoinTrade)?,
            )?;
        }
        apply_truthcoin_block_identity(candidate, height, &block.header_borsh)?;
        Ok(())
    })?;
    Ok(TruthcoinBlockTransitionUndoV1 {
        prior_checkpoint,
        successor_root: store.root()?,
    })
}

pub fn revert_truthcoin_block_transition(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinBlockTransitionUndoV1,
) -> Result<(), ReplayError> {
    if store.root()? != undo.successor_root {
        return Err(ReplayError::InvalidCanonicalStateSnapshot);
    }
    let parent = CanonicalStateStoreV1::import(&undo.prior_checkpoint)?;
    *store = parent;
    Ok(())
}

fn truthcoin_record_put(
    store: &mut CanonicalStateStoreV1,
    changes: &mut Vec<TruthcoinExactTableChangeV1>,
    database: TruthcoinDatabaseId,
    key: Vec<u8>,
    successor: Vec<u8>,
) -> Result<(), ReplayError> {
    let prior = store.get(database.as_u8(), &key)?.map(ToOwned::to_owned);
    store.put(database.as_u8(), key.clone(), successor.clone())?;
    changes.push(TruthcoinExactTableChangeV1 {
        database,
        key,
        prior,
        successor,
    });
    Ok(())
}

pub fn apply_truthcoin_decision_block_frame(
    store: &mut CanonicalStateStoreV1,
    height: u32,
    mainchain_timestamp: u64,
) -> Result<TruthcoinDecisionFrameUndoV1, ReplayError> {
    store.transaction(|candidate| {
        let mut changes = Vec::new();
        let height_key = height.to_le_bytes().to_vec();
        let frame_preinitialized = candidate.get(
            TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )? == Some(mainchain_timestamp.to_le_bytes().as_slice())
            && candidate
                .get(
                    TruthcoinDatabaseId::MainchainTimestampUndo.as_u8(),
                    &height_key,
                )?
                .is_some()
            && candidate
                .get(TruthcoinDatabaseId::PeriodPricingUndo.as_u8(), &height_key)?
                .is_some()
            && candidate
                .get(TruthcoinDatabaseId::MintingUndo.as_u8(), &height_key)?
                .is_some();
        let genesis_timestamp = if frame_preinitialized {
            let bytes = candidate
                .get(
                    TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                    &TRUTHCOIN_UNIT_KEY,
                )?
                .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?;
            u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
            )
        } else {
            let prior_timestamp = candidate
                .get(
                    TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                    &TRUTHCOIN_UNIT_KEY,
                )?
                .map(ToOwned::to_owned);
            let timestamp_undo = match &prior_timestamp {
                None => vec![0],
                Some(bytes) if bytes.len() == 8 => {
                    let mut value = vec![1];
                    value.extend_from_slice(bytes);
                    value
                }
                Some(_) => return Err(ReplayError::InvalidTruthcoinDecisionFrame),
            };
            truthcoin_record_put(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MainchainTimestampUndo,
                height_key.clone(),
                timestamp_undo,
            )?;
            truthcoin_record_put(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MainchainTimestamp,
                TRUTHCOIN_UNIT_KEY.to_vec(),
                mainchain_timestamp.to_le_bytes().to_vec(),
            )?;
            if height == 0 {
                truthcoin_record_put(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::GenesisTimestamp,
                    TRUTHCOIN_UNIT_KEY.to_vec(),
                    mainchain_timestamp.to_le_bytes().to_vec(),
                )?;
                mainchain_timestamp
            } else {
                let bytes = candidate
                    .get(
                        TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                        &TRUTHCOIN_UNIT_KEY,
                    )?
                    .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?;
                u64::from_le_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinDecisionFrame)?,
                )
            }
        };

        if !frame_preinitialized {
            let pricing_entries: Vec<(u32, Vec<u8>)> = candidate
                .entries(TruthcoinDatabaseId::PeriodPricing.as_u8())?
                .map(|(key, value)| {
                    let period = u32::from_le_bytes(
                        key.try_into()
                            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
                    );
                    Ok((period, value.to_vec()))
                })
                .collect::<Result<_, ReplayError>>()?;
            truthcoin_record_put(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::PeriodPricingUndo,
                height_key.clone(),
                encode_truthcoin_pricing_snapshot(&pricing_entries)?,
            )?;
        }

        let period_keys: Vec<u32> = candidate
            .entries(TruthcoinDatabaseId::PeriodDecisions.as_u8())?
            .map(|(key, _)| {
                Ok(u32::from_le_bytes(
                    key.try_into()
                        .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
                ))
            })
            .collect::<Result<_, ReplayError>>()?;
        let previous_highest = period_keys.iter().copied().max().unwrap_or(0);
        if !frame_preinitialized {
            truthcoin_record_put(
                candidate,
                &mut changes,
                TruthcoinDatabaseId::MintingUndo,
                height_key,
                previous_highest.to_le_bytes().to_vec(),
            )?;
        }

        let current_period = truthcoin_current_period(mainchain_timestamp, genesis_timestamp)?;
        if !frame_preinitialized {
            let histories: Vec<(Vec<u8>, Vec<u8>)> = candidate
                .entries(TruthcoinDatabaseId::DecisionStateHistories.as_u8())?
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .collect();
            for (key, value) in histories {
                let decision_id: [u8; 3] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?;
                let mut history = decode_truthcoin_state_history(&value)?;
                if history.last().is_some_and(|entry| entry.0 == 1)
                    && current_period > u32::from(decision_id[0] & 0x7f)
                {
                    history.push((2, height, None));
                    truthcoin_record_put(
                        candidate,
                        &mut changes,
                        TruthcoinDatabaseId::DecisionStateHistories,
                        key,
                        encode_truthcoin_state_history(&history)?,
                    )?;
                }
            }
        }

        let target = current_period
            .checked_add(TRUTHCOIN_FUTURE_PERIODS - 1)
            .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?;
        let empty_set = 0_u64.to_le_bytes().to_vec();
        let highest_existing = period_keys.iter().copied().max().unwrap_or(0);
        if highest_existing < target {
            for period in (highest_existing + 1)..=target {
                truthcoin_record_put(
                    candidate,
                    &mut changes,
                    TruthcoinDatabaseId::PeriodDecisions,
                    period.to_le_bytes().to_vec(),
                    empty_set.clone(),
                )?;
            }
        }

        if height == 0 {
            for period in current_period..=target {
                if candidate
                    .get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &period.to_le_bytes(),
                    )?
                    .is_none()
                {
                    let offset = period - current_period;
                    let mints = u64::from(TRUTHCOIN_FUTURE_PERIODS - offset);
                    let pricing = TruthcoinPeriodPricingV1 {
                        p_period: TRUTHCOIN_GENESIS_P_PERIOD_SATS,
                        p_floor: TRUTHCOIN_GENESIS_P_PERIOD_SATS / 16,
                        mints,
                        claimed: 0,
                        last_reprice_block: height,
                        window_open_claimed: 0,
                        window_open_mints: mints,
                    };
                    truthcoin_record_put(
                        candidate,
                        &mut changes,
                        TruthcoinDatabaseId::PeriodPricing,
                        period.to_le_bytes().to_vec(),
                        encode_truthcoin_period_pricing(pricing),
                    )?;
                }
            }
        } else {
            let previous_current = previous_highest
                .saturating_add(1)
                .saturating_sub(TRUTHCOIN_FUTURE_PERIODS);
            if current_period < previous_current {
                return Err(ReplayError::InvalidTruthcoinDecisionFrame);
            }
            if current_period > previous_current {
                for new_period in (previous_highest + 1)..=target {
                    let mut active_prices = Vec::new();
                    for period in
                        (current_period + 1)..=(current_period + TRUTHCOIN_FUTURE_PERIODS - 1)
                    {
                        if let Some(bytes) = candidate.get(
                            TruthcoinDatabaseId::PeriodPricing.as_u8(),
                            &period.to_le_bytes(),
                        )? {
                            active_prices.push(decode_truthcoin_period_pricing(bytes)?.p_period);
                        }
                    }
                    let seed = if active_prices.is_empty() {
                        TRUTHCOIN_GENESIS_P_PERIOD_SATS
                    } else {
                        (active_prices
                            .iter()
                            .map(|value| u128::from(*value))
                            .sum::<u128>()
                            / active_prices.len() as u128) as u64
                    };
                    let pricing = TruthcoinPeriodPricingV1 {
                        p_period: seed,
                        p_floor: seed / 16,
                        mints: 1,
                        claimed: 0,
                        last_reprice_block: height,
                        window_open_claimed: 0,
                        window_open_mints: 1,
                    };
                    truthcoin_record_put(
                        candidate,
                        &mut changes,
                        TruthcoinDatabaseId::PeriodPricing,
                        new_period.to_le_bytes().to_vec(),
                        encode_truthcoin_period_pricing(pricing),
                    )?;
                }
                let surviving_end = previous_highest.min(target);
                for period in current_period..=surviving_end {
                    if let Some(bytes) = candidate.get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &period.to_le_bytes(),
                    )? {
                        let mut pricing = decode_truthcoin_period_pricing(bytes)?;
                        pricing.mints = pricing
                            .mints
                            .saturating_add(u64::from(current_period - previous_current));
                        truthcoin_apply_reprice(&mut pricing, height);
                        truthcoin_record_put(
                            candidate,
                            &mut changes,
                            TruthcoinDatabaseId::PeriodPricing,
                            period.to_le_bytes().to_vec(),
                            encode_truthcoin_period_pricing(pricing),
                        )?;
                    }
                }
            } else {
                let mut due = false;
                for period in current_period..=target {
                    if let Some(bytes) = candidate.get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &period.to_le_bytes(),
                    )? {
                        let pricing = decode_truthcoin_period_pricing(bytes)?;
                        due |= height.saturating_sub(pricing.last_reprice_block)
                            >= TRUTHCOIN_REPRICE_INTERVAL_BLOCKS;
                    }
                }
                if due {
                    for period in current_period..=target {
                        if let Some(bytes) = candidate.get(
                            TruthcoinDatabaseId::PeriodPricing.as_u8(),
                            &period.to_le_bytes(),
                        )? {
                            let mut pricing = decode_truthcoin_period_pricing(bytes)?;
                            truthcoin_apply_reprice(&mut pricing, height);
                            truthcoin_record_put(
                                candidate,
                                &mut changes,
                                TruthcoinDatabaseId::PeriodPricing,
                                period.to_le_bytes().to_vec(),
                                encode_truthcoin_period_pricing(pricing),
                            )?;
                        }
                    }
                }
            }
        }
        truthcoin_record_put(
            candidate,
            &mut changes,
            TruthcoinDatabaseId::MainchainTimestamp,
            TRUTHCOIN_UNIT_KEY.to_vec(),
            mainchain_timestamp.to_le_bytes().to_vec(),
        )?;
        Ok(TruthcoinDecisionFrameUndoV1 { changes })
    })
}

pub fn revert_truthcoin_decision_block_frame(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinDecisionFrameUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for change in undo.changes.iter().rev() {
            let actual = candidate
                .get(change.database.as_u8(), &change.key)?
                .ok_or(ReplayError::InvalidTruthcoinDecisionFrame)?;
            if actual != change.successor {
                return Err(ReplayError::InvalidTruthcoinDecisionFrame);
            }
            match &change.prior {
                Some(prior) => {
                    candidate.put(change.database.as_u8(), change.key.clone(), prior.clone())?;
                }
                None => {
                    candidate.delete(change.database.as_u8(), &change.key)?;
                }
            }
        }
        Ok(())
    })
}

fn decode_truthcoin_reputation(bytes: &[u8]) -> Result<f64, ReplayError> {
    let value = f64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
    );
    if !value.is_finite() || value <= 0.0 {
        return Err(ReplayError::InvalidTruthcoinReputationState);
    }
    Ok(value)
}

fn get_truthcoin_reputation(
    store: &CanonicalStateStoreV1,
    address: &[u8; 20],
) -> Result<f64, ReplayError> {
    store
        .get(TruthcoinDatabaseId::Reputation.as_u8(), address)?
        .map(decode_truthcoin_reputation)
        .transpose()
        .map(|value| value.unwrap_or(0.0))
}

fn set_truthcoin_reputation(
    store: &mut CanonicalStateStoreV1,
    address: [u8; 20],
    value: f64,
) -> Result<(), ReplayError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ReplayError::InvalidTruthcoinReputationState);
    }
    if value <= 0.0 {
        store.delete(TruthcoinDatabaseId::Reputation.as_u8(), &address)?;
    } else {
        store.put(
            TruthcoinDatabaseId::Reputation.as_u8(),
            address.to_vec(),
            value.to_le_bytes().to_vec(),
        )?;
    }
    Ok(())
}

fn decode_truthcoin_reputation_undo(
    bytes: &[u8],
) -> Result<Vec<TruthcoinReputationTransferUndoEntryV1>, ReplayError> {
    let mut cursor = TruthcoinWireCursor::new(bytes);
    let count = usize::try_from(u64::from_le_bytes(
        cursor
            .take(8)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
    ))
    .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?;
    if count > MAX_TRUTHCOIN_TRANSACTIONS_PER_BLOCK {
        return Err(ReplayError::InvalidTruthcoinReputationState);
    }
    let mut entries = Vec::with_capacity(count.min(4_096));
    for _ in 0..count {
        let sender = cursor
            .take(20)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?;
        let sender_pre_reputation = f64::from_le_bytes(
            cursor
                .take(8)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
        );
        let receiver = cursor
            .take(20)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?;
        let receiver_pre_reputation = f64::from_le_bytes(
            cursor
                .take(8)?
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinReputationState)?,
        );
        if !sender_pre_reputation.is_finite()
            || sender_pre_reputation < 0.0
            || !receiver_pre_reputation.is_finite()
            || receiver_pre_reputation < 0.0
        {
            return Err(ReplayError::InvalidTruthcoinReputationState);
        }
        entries.push(TruthcoinReputationTransferUndoEntryV1 {
            sender,
            sender_pre_reputation,
            receiver,
            receiver_pre_reputation,
        });
    }
    if !cursor.remaining.is_empty() {
        return Err(ReplayError::InvalidTruthcoinReputationState);
    }
    Ok(entries)
}

fn encode_truthcoin_reputation_undo(
    entries: &[TruthcoinReputationTransferUndoEntryV1],
) -> Result<Vec<u8>, ReplayError> {
    let count =
        u64::try_from(entries.len()).map_err(|_| ReplayError::InvalidTruthcoinReputationState)?;
    let mut bytes = Vec::with_capacity(8 + entries.len() * 56);
    bytes.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.sender);
        bytes.extend_from_slice(&entry.sender_pre_reputation.to_le_bytes());
        bytes.extend_from_slice(&entry.receiver);
        bytes.extend_from_slice(&entry.receiver_pre_reputation.to_le_bytes());
    }
    Ok(bytes)
}

/// Apply pinned Truthcoin reputation transfers and their exact per-height
/// bincode undo record. This runs before the base UTXO mutation, as upstream
/// validates sender identity against the filled inputs first.
pub fn apply_truthcoin_reputation_transitions(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    height: u32,
) -> Result<TruthcoinReputationTransitionUndoV1, ReplayError> {
    validate_truthcoin_utxo_ownership(store, body)?;
    let height_key = height.to_le_bytes();
    store.transaction(|candidate| {
        let prior_undo_value = candidate
            .get(
                TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                &height_key,
            )?
            .map(ToOwned::to_owned);
        let mut entries = prior_undo_value
            .as_deref()
            .map(decode_truthcoin_reputation_undo)
            .transpose()?
            .unwrap_or_default();
        for transaction_bytes in &body.transactions_borsh {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let Some(DecodedTruthcoinTransactionDataV1::TransferReputation {
                sender,
                destination,
                amount,
            }) = transaction.data
            else {
                continue;
            };
            if !amount.is_finite()
                || amount <= 0.0
                || amount != ((amount * 10_000_000_000.0).round() / 10_000_000_000.0)
                || sender == destination
            {
                return Err(ReplayError::InvalidTruthcoinReputationTransfer);
            }
            let mut sender_input = false;
            for input_key in &transaction.input_keys {
                let output = candidate
                    .get(TruthcoinDatabaseId::Utxos.as_u8(), input_key)?
                    .ok_or(ReplayError::MissingTruthcoinUtxo)?;
                if decode_truthcoin_filled_output(output)?.address == sender {
                    sender_input = true;
                }
            }
            if !sender_input {
                return Err(ReplayError::InvalidTruthcoinReputationTransfer);
            }
            let sender_rep = get_truthcoin_reputation(candidate, &sender)?;
            let receiver_rep = get_truthcoin_reputation(candidate, &destination)?;
            if sender_rep < amount
                || !((sender_rep - amount).is_finite() && (receiver_rep + amount).is_finite())
            {
                return Err(ReplayError::InvalidTruthcoinReputationTransfer);
            }
            entries.push(TruthcoinReputationTransferUndoEntryV1 {
                sender,
                sender_pre_reputation: sender_rep,
                receiver: destination,
                receiver_pre_reputation: receiver_rep,
            });
            set_truthcoin_reputation(candidate, sender, sender_rep - amount)?;
            set_truthcoin_reputation(candidate, destination, receiver_rep + amount)?;
        }
        if entries.is_empty() {
            if prior_undo_value.is_some() {
                return Err(ReplayError::InvalidTruthcoinReputationState);
            }
        } else {
            candidate.put(
                TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                height_key.to_vec(),
                encode_truthcoin_reputation_undo(&entries)?,
            )?;
        }
        Ok(TruthcoinReputationTransitionUndoV1 {
            height_key,
            prior_undo_value,
        })
    })
}

pub fn revert_truthcoin_reputation_transitions(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinReputationTransitionUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        let current = candidate
            .get(
                TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                &undo.height_key,
            )?
            .ok_or(ReplayError::InvalidTruthcoinReputationState)?
            .to_vec();
        let current_entries = decode_truthcoin_reputation_undo(&current)?;
        let prior_len = undo
            .prior_undo_value
            .as_deref()
            .map(decode_truthcoin_reputation_undo)
            .transpose()?
            .map_or(0, |entries| entries.len());
        if current_entries.len() <= prior_len {
            return Err(ReplayError::InvalidTruthcoinReputationState);
        }
        for entry in current_entries[prior_len..].iter().rev() {
            set_truthcoin_reputation(candidate, entry.sender, entry.sender_pre_reputation)?;
            set_truthcoin_reputation(candidate, entry.receiver, entry.receiver_pre_reputation)?;
        }
        match &undo.prior_undo_value {
            Some(value) => {
                candidate.put(
                    TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                    undo.height_key.to_vec(),
                    value.clone(),
                )?;
            }
            None => {
                candidate.delete(
                    TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                    &undo.height_key,
                )?;
            }
        }
        Ok(())
    })
}

/// Apply upstream's regular UTXO/STXO base transition atomically. Specialized
/// Decision, market, vote and reputation tables are deliberately handled by
/// later port slices; this function cannot be mistaken for a complete block
/// transition.
fn apply_truthcoin_base_utxo_transition_inner(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
    authenticate: bool,
    excluded_indices: &BTreeSet<usize>,
) -> Result<TruthcoinBaseUtxoUndoV1, ReplayError> {
    if authenticate {
        validate_truthcoin_utxo_ownership(store, body)?;
    }
    store.transaction(|candidate| {
        let mut undo = TruthcoinBaseUtxoUndoV1 {
            spent: Vec::new(),
            created: Vec::new(),
        };
        if !body.coinbase_borsh.is_empty() {
            // A Body coinbase is Borsh(Vec<Output>), not a Transaction. Reuse
            // the exact Output decoder by wrapping it in an otherwise empty
            // canonical transaction encoding.
            let mut encoded = 0_u32.to_le_bytes().to_vec();
            encoded.extend_from_slice(&body.coinbase_borsh);
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.push(0);
            let coinbase = decode_truthcoin_transaction(&encoded)?;
            let merkle_root = truthcoin_body_merkle_root(body);
            for (vout, output) in coinbase.outputs.iter().enumerate() {
                let vout = u32::try_from(vout)
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                let mut output_key = [0_u8; 37];
                output_key[0] = 1;
                output_key[1..33].copy_from_slice(&merkle_root);
                output_key[33..].copy_from_slice(&vout.to_le_bytes());
                let output_value = encode_truthcoin_filled_output(output)?;
                if candidate
                    .put(
                        TruthcoinDatabaseId::Utxos.as_u8(),
                        output_key.to_vec(),
                        output_value,
                    )?
                    .is_some()
                {
                    return Err(ReplayError::DuplicateTruthcoinUtxo);
                }
                let address_key = truthcoin_address_index_key(output.address, &output_key);
                if candidate
                    .put(
                        TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                        address_key,
                        Vec::new(),
                    )?
                    .is_some()
                {
                    return Err(ReplayError::InvalidTruthcoinUtxoIndex);
                }
                undo.created.push(output_key);
            }
        }
        for (transaction_index, transaction_bytes) in body.transactions_borsh.iter().enumerate() {
            if excluded_indices.contains(&transaction_index) {
                continue;
            }
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            let txid = *blake3::hash(transaction_bytes).as_bytes();
            for (vin, input_key) in transaction.input_keys.iter().enumerate() {
                let spent = candidate
                    .delete(TruthcoinDatabaseId::Utxos.as_u8(), input_key)?
                    .ok_or(ReplayError::MissingTruthcoinUtxo)?;
                let spent_output = decode_truthcoin_filled_output(&spent)?;
                let address_key = truthcoin_address_index_key(spent_output.address, input_key);
                if candidate
                    .delete(TruthcoinDatabaseId::UtxosByAddress.as_u8(), &address_key)?
                    .is_none()
                {
                    return Err(ReplayError::InvalidTruthcoinUtxoIndex);
                }
                let mut stxo = spent.clone();
                stxo.extend_from_slice(&0_u32.to_le_bytes());
                stxo.extend_from_slice(&txid);
                stxo.extend_from_slice(
                    &u32::try_from(vin)
                        .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?
                        .to_le_bytes(),
                );
                if candidate
                    .put(TruthcoinDatabaseId::Stxos.as_u8(), input_key.to_vec(), stxo)?
                    .is_some()
                {
                    return Err(ReplayError::DuplicateTruthcoinStxo);
                }
                undo.spent.push((*input_key, spent));
            }
            for (vout, output) in transaction.outputs.iter().enumerate() {
                let vout = u32::try_from(vout)
                    .map_err(|_| ReplayError::InvalidTruthcoinTransactionEncoding)?;
                let output_key = truthcoin_regular_outpoint_key(txid, vout);
                let output_value = encode_truthcoin_filled_output(output)?;
                if candidate
                    .put(
                        TruthcoinDatabaseId::Utxos.as_u8(),
                        output_key.to_vec(),
                        output_value,
                    )?
                    .is_some()
                {
                    return Err(ReplayError::DuplicateTruthcoinUtxo);
                }
                let address_key = truthcoin_address_index_key(output.address, &output_key);
                if candidate
                    .put(
                        TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                        address_key,
                        Vec::new(),
                    )?
                    .is_some()
                {
                    return Err(ReplayError::InvalidTruthcoinUtxoIndex);
                }
                undo.created.push(output_key);
            }
        }
        Ok(undo)
    })
}

pub fn apply_truthcoin_base_utxo_transition(
    store: &mut CanonicalStateStoreV1,
    body: &TruthcoinBodyV1,
) -> Result<TruthcoinBaseUtxoUndoV1, ReplayError> {
    apply_truthcoin_base_utxo_transition_inner(store, body, true, &BTreeSet::new())
}

pub fn revert_truthcoin_base_utxo_transition(
    store: &mut CanonicalStateStoreV1,
    undo: &TruthcoinBaseUtxoUndoV1,
) -> Result<(), ReplayError> {
    store.transaction(|candidate| {
        for output_key in undo.created.iter().rev() {
            let output = candidate
                .delete(TruthcoinDatabaseId::Utxos.as_u8(), output_key)?
                .ok_or(ReplayError::MissingTruthcoinUtxo)?;
            let output = decode_truthcoin_filled_output(&output)?;
            let address_key = truthcoin_address_index_key(output.address, output_key);
            if candidate
                .delete(TruthcoinDatabaseId::UtxosByAddress.as_u8(), &address_key)?
                .is_none()
            {
                return Err(ReplayError::InvalidTruthcoinUtxoIndex);
            }
        }
        for (input_key, spent) in undo.spent.iter().rev() {
            if candidate
                .delete(TruthcoinDatabaseId::Stxos.as_u8(), input_key)?
                .is_none()
            {
                return Err(ReplayError::MissingTruthcoinStxo);
            }
            if candidate
                .put(
                    TruthcoinDatabaseId::Utxos.as_u8(),
                    input_key.to_vec(),
                    spent.clone(),
                )?
                .is_some()
            {
                return Err(ReplayError::DuplicateTruthcoinUtxo);
            }
            let output = decode_truthcoin_filled_output(spent)?;
            let address_key = truthcoin_address_index_key(output.address, input_key);
            if candidate
                .put(
                    TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                    address_key,
                    Vec::new(),
                )?
                .is_some()
            {
                return Err(ReplayError::InvalidTruthcoinUtxoIndex);
            }
        }
        Ok(())
    })
}

fn validate_truthcoin_authorization_envelopes(body: &TruthcoinBodyV1) -> Result<(), ReplayError> {
    fn decode_authorization(
        bytes: &[u8],
    ) -> Result<(ed25519_dalek::VerifyingKey, ed25519_dalek::Signature), ReplayError> {
        let key_bytes: [u8; 32] = bytes
            .get(..32)
            .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinBodyEncoding)?;
        let signature_bytes: [u8; 64] = bytes
            .get(32..TRUTHCOIN_AUTHORIZATION_WIRE_BYTES)
            .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinBodyEncoding)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ReplayError::InvalidTruthcoinAuthorization)?;
        Ok((key, ed25519_dalek::Signature::from_bytes(&signature_bytes)))
    }

    fn take_u32_le(bytes: &[u8]) -> Result<(usize, &[u8]), ReplayError> {
        let prefix: [u8; 4] = bytes
            .get(..4)
            .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinBodyEncoding)?;
        Ok((
            usize::try_from(u32::from_le_bytes(prefix))
                .map_err(|_| ReplayError::InvalidTruthcoinBodyEncoding)?,
            &bytes[4..],
        ))
    }

    let (authorization_count, authorization_payload) = take_u32_le(&body.authorizations_borsh)?;
    let expected_authorization_bytes = authorization_count
        .checked_mul(TRUTHCOIN_AUTHORIZATION_WIRE_BYTES)
        .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?;
    if authorization_payload.len() != expected_authorization_bytes {
        return Err(ReplayError::InvalidTruthcoinBodyEncoding);
    }
    let mut expected_authorizations = 0_usize;
    let mut input_counts = Vec::with_capacity(body.transactions_borsh.len());
    for transaction in &body.transactions_borsh {
        let input_count = decode_truthcoin_transaction_prefix(transaction)?;
        expected_authorizations = expected_authorizations
            .checked_add(input_count)
            .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?;
        input_counts.push(input_count);
    }
    if authorization_count != expected_authorizations {
        return Err(ReplayError::InvalidTruthcoinAuthorization);
    }
    let mut authorization_chunks =
        authorization_payload.chunks_exact(TRUTHCOIN_AUTHORIZATION_WIRE_BYTES);
    for (transaction, input_count) in body.transactions_borsh.iter().zip(input_counts) {
        let mut message = Vec::with_capacity(transaction.len() + 1);
        message.push(0); // upstream `Dst::Transaction`
        message.extend_from_slice(transaction);
        for _ in 0..input_count {
            let authorization = authorization_chunks
                .next()
                .ok_or(ReplayError::InvalidTruthcoinAuthorization)?;
            let (key, signature) = decode_authorization(authorization)?;
            key.verify_strict(&message, &signature)
                .map_err(|_| ReplayError::InvalidTruthcoinAuthorization)?;
        }
    }
    if authorization_chunks.next().is_some() || !authorization_chunks.remainder().is_empty() {
        return Err(ReplayError::InvalidTruthcoinAuthorization);
    }

    let (actor_count, mut actor_payload) = take_u32_le(&body.actor_proofs_borsh)?;
    if actor_count != body.transactions_borsh.len() {
        return Err(ReplayError::InvalidTruthcoinBodyEncoding);
    }
    for transaction in &body.transactions_borsh {
        let (tag, rest) = actor_payload
            .split_first()
            .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?;
        actor_payload = rest;
        match tag {
            0 => {}
            1 => {
                let authorization = actor_payload
                    .get(..TRUTHCOIN_AUTHORIZATION_WIRE_BYTES)
                    .ok_or(ReplayError::InvalidTruthcoinBodyEncoding)?;
                let (key, signature) = decode_authorization(authorization)?;
                let mut message = Vec::with_capacity(transaction.len() + 1);
                message.push(0); // upstream `Dst::Transaction`
                message.extend_from_slice(transaction);
                key.verify_strict(&message, &signature)
                    .map_err(|_| ReplayError::InvalidTruthcoinAuthorization)?;
                actor_payload = &actor_payload[TRUTHCOIN_AUTHORIZATION_WIRE_BYTES..];
            }
            _ => return Err(ReplayError::InvalidTruthcoinBodyEncoding),
        }
    }
    if !actor_payload.is_empty() {
        return Err(ReplayError::InvalidTruthcoinBodyEncoding);
    }
    Ok(())
}

#[derive(Debug, Default)]
struct ReplayResourceBudget {
    evidence_bytes: usize,
    transactions: usize,
}

impl ReplayResourceBudget {
    fn charge_bytes(&mut self, amount: usize) -> Result<(), ReplayError> {
        self.evidence_bytes = self
            .evidence_bytes
            .checked_add(amount)
            .ok_or(ReplayError::Bounds)?;
        if self.evidence_bytes > MAX_REPLAY_EVIDENCE_BYTES {
            return Err(ReplayError::Bounds);
        }
        Ok(())
    }

    fn charge_transactions(&mut self, amount: usize) -> Result<(), ReplayError> {
        self.transactions = self
            .transactions
            .checked_add(amount)
            .ok_or(ReplayError::Bounds)?;
        if self.transactions > MAX_REPLAY_TRANSACTIONS {
            return Err(ReplayError::Bounds);
        }
        Ok(())
    }
}

fn validate_state_machine_output_bounds(state: &StateMachineOutputV1) -> Result<(), ReplayError> {
    let candidates = state
        .anchors
        .len()
        .checked_add(state.markets.len())
        .ok_or(ReplayError::CandidateBounds)?;
    if candidates > MAX_STATE_MACHINE_CANDIDATES {
        return Err(ReplayError::CandidateBounds);
    }
    Ok(())
}

fn verify_mainchain_headers(
    input: &ReplayInputV1,
) -> Result<(Vec<BitcoinHeader>, Vec<BitcoinHeader>), ReplayError> {
    let first = input
        .mainchain_headers
        .first()
        .ok_or(ReplayError::EmptyMainchain)?;
    // The exact checkpoint hash and height are frozen in the authentication
    // configuration. A mid-epoch checkpoint is therefore an explicit trust
    // anchor, not caller-selected work. It is safe to extend until the first
    // difficulty boundary; crossing that boundary still requires the complete
    // prior 2,016-header adjustment context below and fails closed otherwise.
    if first.height != input.authentication.bitcoin_checkpoint_height {
        return Err(ReplayError::CheckpointNotEpochAligned);
    }
    let expected_len = input
        .parent
        .height
        .checked_sub(first.height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(ReplayError::MainchainHeightMismatch)?;
    if expected_len != input.mainchain_headers.len() {
        return Err(ReplayError::MainchainHeightMismatch);
    }

    let checkpoint: BitcoinHeader = deserialize(&first.consensus_header)
        .map_err(|_| ReplayError::InvalidBitcoinHeaderEncoding)?;
    let mtp_context = decode_checkpoint_mtp_context(input, checkpoint)?;
    let mut decoded: Vec<BitcoinHeader> = Vec::with_capacity(input.mainchain_headers.len());
    for (index, encoded) in input.mainchain_headers.iter().enumerate() {
        let expected_height = first
            .height
            .checked_add(index as u64)
            .ok_or(ReplayError::MainchainHeightMismatch)?;
        if encoded.height != expected_height {
            return Err(ReplayError::MainchainHeightMismatch);
        }
        let header: BitcoinHeader = deserialize(&encoded.consensus_header)
            .map_err(|_| ReplayError::InvalidBitcoinHeaderEncoding)?;
        if serialize(&header) != encoded.consensus_header {
            return Err(ReplayError::InvalidBitcoinHeaderEncoding);
        }
        if index == 0 {
            if header.block_hash().to_byte_array() != input.authentication.bitcoin_checkpoint_hash {
                return Err(ReplayError::WrongCheckpoint);
            }
            header
                .validate_pow(header.target())
                .map_err(|_| ReplayError::InvalidProofOfWork)?;
        } else {
            let previous = decoded[index - 1];
            if header.prev_blockhash != previous.block_hash() {
                return Err(ReplayError::InvalidMainchainAncestry);
            }
            let required_bits = if expected_height % BITCOIN_DIFFICULTY_INTERVAL == 0 {
                let epoch_start_index = index
                    .checked_sub(BITCOIN_DIFFICULTY_INTERVAL as usize)
                    .ok_or(ReplayError::MissingDifficultyContext)?;
                CompactTarget::from_header_difficulty_adjustment(
                    decoded[epoch_start_index],
                    previous,
                    Params::MAINNET,
                )
            } else {
                previous.bits
            };
            header
                .validate_pow(required_bits.into())
                .map_err(|_| ReplayError::InvalidProofOfWork)?;
            let mut prior_times = mtp_context
                .iter()
                .chain(decoded.iter())
                .rev()
                .take(BITCOIN_MTP_WINDOW)
                .map(|prior| u64::from(prior.time))
                .collect::<Vec<_>>();
            if prior_times.len() != BITCOIN_MTP_WINDOW {
                return Err(ReplayError::MissingMedianTimeContext);
            }
            prior_times.sort_unstable();
            if u64::from(header.time) <= prior_times[BITCOIN_MTP_WINDOW / 2] {
                return Err(ReplayError::InvalidBitcoinTimestamp);
            }
        }
        decoded.push(header);
    }
    let tip = decoded.last().ok_or(ReplayError::EmptyMainchain)?;
    if tip.block_hash().to_byte_array() != input.parent.block_hash
        || median_time_past(&mtp_context, &decoded, decoded.len() - 1)?
            != input.parent.median_time_past
    {
        return Err(ReplayError::WrongParentContext);
    }
    Ok((mtp_context, decoded))
}

fn decode_checkpoint_mtp_context(
    input: &ReplayInputV1,
    checkpoint: BitcoinHeader,
) -> Result<Vec<BitcoinHeader>, ReplayError> {
    let mut context: Vec<BitcoinHeader> = Vec::with_capacity(BITCOIN_MTP_WINDOW - 1);
    for encoded in &input.checkpoint_mtp_headers {
        let header: BitcoinHeader =
            deserialize(encoded).map_err(|_| ReplayError::InvalidBitcoinHeaderEncoding)?;
        if serialize(&header) != *encoded {
            return Err(ReplayError::InvalidBitcoinHeaderEncoding);
        }
        if let Some(previous) = context.last() {
            if header.prev_blockhash != previous.block_hash() {
                return Err(ReplayError::InvalidCheckpointMtpContext);
            }
        }
        context.push(header);
    }
    if context
        .last()
        .map(BitcoinHeader::block_hash)
        .ok_or(ReplayError::InvalidCheckpointMtpContext)?
        != checkpoint.prev_blockhash
    {
        return Err(ReplayError::InvalidCheckpointMtpContext);
    }
    Ok(context)
}

fn verify_mainchain_block_transactions(
    input: &ReplayInputV1,
    headers: &[BitcoinHeader],
) -> Result<(), ReplayError> {
    for (((declared_header, header), block), inclusion) in input
        .mainchain_headers
        .iter()
        .zip(headers)
        .zip(&input.mainchain_block_transactions)
        .zip(&input.coinbase_inclusions)
    {
        if block.version != MainchainBlockTransactionsV1::VERSION
            || block.height != declared_header.height
            || block.transactions.is_empty()
            || block.transactions[0] != inclusion.coinbase_transaction
        {
            return Err(ReplayError::InvalidBitcoinBlockTransactions);
        }
        let mut txids = Vec::with_capacity(block.transactions.len());
        for (index, bytes) in block.transactions.iter().enumerate() {
            let transaction: Transaction =
                deserialize(bytes).map_err(|_| ReplayError::InvalidBitcoinBlockTransactions)?;
            if serialize(&transaction) != *bytes || transaction.is_coinbase() != (index == 0) {
                return Err(ReplayError::InvalidBitcoinBlockTransactions);
            }
            txids.push(transaction.compute_txid().to_raw_hash());
        }
        while txids.len() > 1 {
            if txids.len() & 1 == 1 {
                let last = *txids
                    .last()
                    .ok_or(ReplayError::InvalidBitcoinBlockTransactions)?;
                txids.push(last);
            }
            let mut next = Vec::with_capacity(txids.len() / 2);
            for pair in txids.chunks_exact(2) {
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(pair[0].as_byte_array());
                bytes[32..].copy_from_slice(pair[1].as_byte_array());
                next.push(sha256d::Hash::hash(&bytes));
            }
            txids = next;
        }
        if txids.first() != Some(&header.merkle_root.to_raw_hash()) {
            return Err(ReplayError::InvalidBitcoinBlockTransactions);
        }
    }
    Ok(())
}

fn truthcoin_drivechain_vout(transaction: &Transaction) -> Result<Option<(u32, u64)>, ReplayError> {
    let mut found = None;
    for (index, output) in transaction.output.iter().enumerate() {
        if output.script_pubkey.as_bytes() != [0xb4, 0x01, TRUTHCOIN_SIDECHAIN_NUMBER, 0x51] {
            continue;
        }
        let vout = u32::try_from(index).map_err(|_| ReplayError::InvalidBip300CtipTransition)?;
        if found.replace((vout, output.value.to_sat())).is_some() {
            return Err(ReplayError::InvalidBip300CtipTransition);
        }
    }
    Ok(found)
}

fn parse_truthcoin_deposit_address(bytes: &[u8]) -> Result<[u8; 20], ReplayError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::InvalidBip300DepositAddress)?;
    let payload = if let Some(suffixed) = text.strip_prefix("s13_") {
        let (base58, checksum) = suffixed
            .split_once('_')
            .ok_or(ReplayError::InvalidBip300DepositAddress)?;
        let prefix = format!("s13_{base58}_");
        let digest = Sha256::digest(prefix.as_bytes());
        if checksum != format!("{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2]) {
            return Err(ReplayError::InvalidBip300DepositAddress);
        }
        base58
    } else {
        text
    };
    bitcoin::base58::decode(payload)
        .map_err(|_| ReplayError::InvalidBip300DepositAddress)?
        .try_into()
        .map_err(|_| ReplayError::InvalidBip300DepositAddress)
}

fn transaction_op_return_address(
    transaction: &Transaction,
    ctip_vout: u32,
) -> Result<[u8; 20], ReplayError> {
    let output = transaction
        .output
        .get(usize::try_from(ctip_vout).map_err(|_| ReplayError::InvalidBip300DepositAddress)? + 1)
        .ok_or(ReplayError::InvalidBip300DepositAddress)?;
    let mut instructions = output.script_pubkey.instructions();
    if !matches!(instructions.next(), Some(Ok(Instruction::Op(OP_RETURN)))) {
        return Err(ReplayError::InvalidBip300DepositAddress);
    }
    let Some(Ok(Instruction::PushBytes(address))) = instructions.next() else {
        return Err(ReplayError::InvalidBip300DepositAddress);
    };
    if instructions.next().is_some() {
        return Err(ReplayError::InvalidBip300DepositAddress);
    }
    parse_truthcoin_deposit_address(address.as_bytes())
}

/// Authenticate the complete BIP300 CTIP lineage and derive every Truthcoin
/// M5 deposit after the frozen checkpoint. M6 transitions fail closed until
/// their full Truthcoin withdrawal-state effects are linked into the guest.
pub fn verify_truthcoin_bip300_deposits(
    input: &ReplayInputV1,
) -> Result<Vec<AuthenticatedTruthcoinDepositV1>, ReplayError> {
    Ok(verify_truthcoin_bip300_transition(input)?.deposits)
}

/// Derived state, not an independently authenticated continuation checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthcoinBip300TransitionV1 {
    pub final_ctip: Option<Bip300CtipV1>,
    pub deposits: Vec<AuthenticatedTruthcoinDepositV1>,
}

/// Derive deposits and the resulting CTIP using the existing lineage checks.
/// The caller must separately authenticate complete parent transaction lists,
/// headers and checkpoint bindings. M6 and unlinked activation remain rejected.
pub fn verify_truthcoin_bip300_transition(
    input: &ReplayInputV1,
) -> Result<TruthcoinBip300TransitionV1, ReplayError> {
    if input.bip300_checkpoint_state.version != TruthcoinBip300CheckpointStateV1::VERSION
        || input.bip300_checkpoint_state.digest()
            != input.authentication.bip300_checkpoint_state_hash
    {
        return Err(ReplayError::InvalidBip300CheckpointState);
    }
    let mut ctip = input.bip300_checkpoint_state.ctip;
    let mut deposits = Vec::new();
    for (block_index, (declared, block)) in input
        .mainchain_headers
        .iter()
        .zip(&input.mainchain_block_transactions)
        .enumerate()
    {
        // The frozen state is the post-checkpoint validator state.
        if block_index == 0 {
            continue;
        }
        for transaction_bytes in block.transactions.iter().skip(1) {
            let transaction: Transaction = deserialize(transaction_bytes)
                .map_err(|_| ReplayError::InvalidBitcoinBlockTransactions)?;
            let new_ctip = truthcoin_drivechain_vout(&transaction)?;
            let spends_prior = ctip.is_some_and(|prior| {
                transaction.input.iter().any(|input| {
                    input.previous_output.txid.to_byte_array() == prior.txid
                        && input.previous_output.vout == prior.vout
                })
            });
            if new_ctip.is_none() {
                if spends_prior {
                    return Err(ReplayError::InvalidBip300CtipTransition);
                }
                continue;
            }
            if !input.bip300_checkpoint_state.truthcoin_slot_active {
                return Err(ReplayError::Bip300ActivationReplayUnlinked);
            }
            if ctip.is_some() != spends_prior {
                return Err(ReplayError::InvalidBip300CtipTransition);
            }
            let (vout, new_value) = new_ctip.ok_or(ReplayError::InvalidBip300CtipTransition)?;
            let old_value = ctip.map_or(0, |prior| prior.value_sats);
            if new_value == old_value {
                return Err(ReplayError::InvalidBip300CtipTransition);
            }
            if new_value < old_value {
                return Err(ReplayError::Bip300WithdrawalReplayUnlinked);
            }
            let txid = transaction.compute_txid().to_byte_array();
            let sequence_number = ctip.map_or(0, |prior| prior.sequence_number.saturating_add(1));
            deposits.push(AuthenticatedTruthcoinDepositV1 {
                mainchain_height: declared.height,
                mainchain_block_hash: deserialize::<BitcoinHeader>(&declared.consensus_header)
                    .map_err(|_| ReplayError::InvalidBitcoinHeaderEncoding)?
                    .block_hash()
                    .to_byte_array(),
                txid,
                vout,
                address: transaction_op_return_address(&transaction, vout)?,
                value_sats: new_value - old_value,
                sequence_number,
            });
            ctip = Some(Bip300CtipV1 {
                txid,
                vout,
                value_sats: new_value,
                sequence_number,
            });
        }
    }
    Ok(TruthcoinBip300TransitionV1 {
        final_ctip: ctip,
        deposits,
    })
}

fn verify_coinbase_inclusions(
    input: &ReplayInputV1,
    headers: &[BitcoinHeader],
) -> Result<Vec<Option<Hash32>>, ReplayError> {
    let mut commitments = Vec::with_capacity(headers.len());
    for ((announced_header, inclusion), header) in input
        .mainchain_headers
        .iter()
        .zip(&input.coinbase_inclusions)
        .zip(headers)
    {
        if inclusion.height != announced_header.height {
            return Err(ReplayError::CoinbaseHeightMismatch);
        }
        let coinbase: Transaction = deserialize(&inclusion.coinbase_transaction)
            .map_err(|_| ReplayError::InvalidCoinbaseEncoding)?;
        if serialize(&coinbase) != inclusion.coinbase_transaction || !coinbase.is_coinbase() {
            return Err(ReplayError::InvalidCoinbaseEncoding);
        }
        verify_coinbase_merkle_branch(&coinbase, inclusion, header)?;
        commitments.push(extract_truthcoin_m7(&coinbase)?);
    }
    Ok(commitments)
}

/// Verify slot-13 M7 inclusion under an already authenticated parent header.
/// This does not establish header canonicality, PoW, CTIP state or finality.
pub fn verify_truthcoin_checkpoint_inclusion(
    announced: &MainchainHeaderV1,
    inclusion: &CoinbaseInclusionV1,
) -> Result<Option<Hash32>, ReplayError> {
    if inclusion.version != 1 || inclusion.height != announced.height {
        return Err(ReplayError::CoinbaseHeightMismatch);
    }
    let header: BitcoinHeader = deserialize(&announced.consensus_header)
        .map_err(|_| ReplayError::InvalidCoinbaseEncoding)?;
    let coinbase: Transaction = deserialize(&inclusion.coinbase_transaction)
        .map_err(|_| ReplayError::InvalidCoinbaseEncoding)?;
    if serialize(&coinbase) != inclusion.coinbase_transaction || !coinbase.is_coinbase() {
        return Err(ReplayError::InvalidCoinbaseEncoding);
    }
    verify_coinbase_merkle_branch(&coinbase, inclusion, &header)?;
    extract_truthcoin_m7(&coinbase)
}

fn verify_coinbase_merkle_branch(
    coinbase: &Transaction,
    inclusion: &CoinbaseInclusionV1,
    header: &BitcoinHeader,
) -> Result<(), ReplayError> {
    let mut current = coinbase.compute_txid().to_raw_hash();
    for sibling_bytes in &inclusion.merkle_siblings {
        let sibling = sha256d::Hash::from_byte_array(*sibling_bytes);
        // The unique coinbase is transaction index zero, hence its node is the
        // left child at every level of its authenticated path.
        let mut pair = [0_u8; 64];
        pair[..32].copy_from_slice(current.as_byte_array());
        pair[32..].copy_from_slice(sibling.as_byte_array());
        current = sha256d::Hash::hash(&pair);
    }
    if current != header.merkle_root.to_raw_hash() {
        return Err(ReplayError::InvalidCoinbaseMerkleProof);
    }
    Ok(())
}

fn extract_truthcoin_m7(coinbase: &Transaction) -> Result<Option<Hash32>, ReplayError> {
    let mut commitment = None;
    for output in &coinbase.output {
        let mut instructions = output.script_pubkey.instructions();
        let Some(Ok(Instruction::Op(opcode))) = instructions.next() else {
            continue;
        };
        if opcode != OP_RETURN {
            continue;
        }
        let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
            continue;
        };
        if instructions.next().is_some() {
            continue;
        }
        let data = data.as_bytes();
        if data.len() != 37 || data[..4] != [0xd1, 0x61, 0x73, 0x68] {
            continue;
        }
        if data[4] != TRUTHCOIN_SIDECHAIN_NUMBER {
            continue;
        }
        let value: Hash32 = data[5..].try_into().map_err(|_| ReplayError::InvalidM7)?;
        if value == [0; 32] || commitment.replace(value).is_some() {
            return Err(ReplayError::DuplicateOrZeroM7);
        }
    }
    Ok(commitment)
}

type VerifiedSidechainRecord = (usize, usize, Option<Hash32>, u64, CanonicalBlockContextV1);

struct VerifiedSidechainSet {
    records: BTreeMap<Hash32, VerifiedSidechainRecord>,
    encounter_order: Vec<Hash32>,
    trusted_start: Option<(Hash32, u64)>,
}

fn verify_sidechain_set(
    input: &ReplayInputV1,
    mtp_context: &[BitcoinHeader],
    headers: &[BitcoinHeader],
    commitments: &[Option<Hash32>],
) -> Result<VerifiedSidechainSet, ReplayError> {
    verify_sidechain_set_from_start(input, mtp_context, headers, commitments, None)
}

/// `trusted_start` must come from an independently pinned, imported checkpoint,
/// never from a witness-selected tip. The first parent header authenticates its
/// M7; only descendants are eligible for the suffix's branch selection.
fn verify_sidechain_set_from_start(
    input: &ReplayInputV1,
    mtp_context: &[BitcoinHeader],
    headers: &[BitcoinHeader],
    commitments: &[Option<Hash32>],
    trusted_start: Option<(Hash32, u64)>,
) -> Result<VerifiedSidechainSet, ReplayError> {
    if let Some((hash, _)) = trusted_start {
        if hash == [0; 32] || commitments.first().copied().flatten() != Some(hash) {
            return Err(ReplayError::InvalidIncrementalCheckpoint);
        }
    }
    let checkpoint_height = input.authentication.bitcoin_checkpoint_height;
    let mut next_block = 0_usize;
    let mut records = BTreeMap::<Hash32, VerifiedSidechainRecord>::new();
    let mut encounter_order = Vec::<Hash32>::new();

    for (header_index, commitment) in commitments.iter().enumerate() {
        let Some(commitment) = commitment else {
            continue;
        };
        if trusted_start.is_some_and(|(hash, _)| hash == *commitment) {
            // The checkpoint's body/state was authenticated by its pin. A
            // repeated M7 for that same immutable block is not a new transition.
            continue;
        }
        if records.contains_key(commitment) {
            // On one Bitcoin lineage a repeated commitment cannot be another
            // successful verification: the immutable side header binds the
            // predecessor of its original verifying main block. It is therefore
            // irrelevant to upstream's verified-BMM set.
            continue;
        }
        let block = input
            .sidechain_blocks
            .get(next_block)
            .ok_or(ReplayError::MissingCommittedSidechainBlock)?;
        if block.block_hash() != *commitment {
            return Err(ReplayError::MissingCommittedSidechainBlock);
        }
        let block_index = next_block;
        next_block += 1;
        let (merkle_root, previous_side, previous_main) =
            parse_truthcoin_header(&block.header_borsh)?;
        if merkle_root != truthcoin_body_merkle_root(&block.body) {
            return Err(ReplayError::InvalidTruthcoinMerkleRoot);
        }
        let main_height = checkpoint_height
            .checked_add(header_index as u64)
            .ok_or(ReplayError::MainchainHeightMismatch)?;
        if block.bmm_main_height != main_height {
            return Err(ReplayError::InvalidBmmParentBinding);
        }
        if previous_main != headers[header_index].prev_blockhash.to_byte_array() {
            // M7 commits a candidate, not a successful BMM verification. The
            // complete immutable candidate is still mandatory in the witness,
            // but upstream ignores it when its claimed main parent differs
            // from the Bitcoin block immediately preceding this commitment.
            continue;
        }
        let valid_ancestry = match previous_side {
            None => {
                trusted_start.is_none()
                    && block.height == 0
                    && *commitment == input.authentication.genesis_sidechain_block_hash
            }
            Some(previous) => trusted_start.is_some_and(|(hash, height)| {
                previous == hash && height.checked_add(1) == Some(block.height)
            }) || records.get(&previous).is_some_and(|record| {
                record
                    .3
                    .checked_add(1)
                    .is_some_and(|height| block.height == height)
            }),
        };
        if !valid_ancestry {
            // As above, this is a fully supplied but unsuccessful candidate.
            // Retaining it in sidechain_blocks prevents an omission attack;
            // excluding it from records matches upstream's verified set.
            continue;
        }
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: *commitment,
            sidechain_height: block.height,
            bmm_main_block_hash: headers[header_index].block_hash().to_byte_array(),
            bmm_main_height: main_height,
            bmm_main_timestamp: u64::from(headers[header_index].time),
            bmm_main_mtp: median_time_past(mtp_context, headers, header_index)?,
        };
        records.insert(
            *commitment,
            (
                header_index,
                block_index,
                previous_side,
                block.height,
                context,
            ),
        );
        encounter_order.push(*commitment);
    }
    if next_block != input.sidechain_blocks.len() || records.is_empty() {
        return Err(ReplayError::UncommittedSidechainBlock);
    }
    Ok(VerifiedSidechainSet {
        records,
        encounter_order,
        trusted_start,
    })
}

fn ranked_sidechain_tips(set: &VerifiedSidechainSet) -> Vec<Hash32> {
    let mut tips = set.encounter_order.clone();
    // Upstream Archive::better_tip prefers greater sidechain height, then at
    // equal height the lower-work (earlier) best BMM verification. Exact ties
    // retain encounter order.
    tips.sort_by(|left, right| {
        let left_record = &set.records[left];
        let right_record = &set.records[right];
        right_record
            .3
            .cmp(&left_record.3)
            .then_with(|| left_record.0.cmp(&right_record.0))
            .then_with(|| left_record.1.cmp(&right_record.1))
    });
    tips
}

fn sidechain_branch_for_tip(
    input: &ReplayInputV1,
    set: &VerifiedSidechainSet,
    tip_hash: Hash32,
) -> Result<(Vec<TruthcoinBlockV1>, Vec<CanonicalBlockContextV1>), ReplayError> {
    if !set.records.contains_key(&tip_hash) {
        return Err(ReplayError::TruthcoinForkOrInvalidAncestry);
    }

    let mut canonical_hashes = Vec::new();
    let mut cursor = Some(tip_hash);
    while let Some(hash) = cursor {
        if set.trusted_start.is_some_and(|(start, _)| hash == start) {
            break;
        }
        let (_, _, parent, _, _) = set
            .records
            .get(&hash)
            .ok_or(ReplayError::TruthcoinForkOrInvalidAncestry)?;
        canonical_hashes.push(hash);
        cursor = *parent;
    }
    canonical_hashes.reverse();
    let valid_start = match set.trusted_start {
        Some((hash, _)) => cursor == Some(hash),
        None => canonical_hashes.first().copied()
            == Some(input.authentication.genesis_sidechain_block_hash),
    };
    if !valid_start {
        return Err(ReplayError::TruthcoinForkOrInvalidAncestry);
    }
    let mut canonical_blocks = Vec::with_capacity(canonical_hashes.len());
    let mut canonical_contexts = Vec::with_capacity(canonical_hashes.len());
    for hash in canonical_hashes {
        let block_index = set
            .records
            .get(&hash)
            .map(|record| record.1)
            .ok_or(ReplayError::TruthcoinForkOrInvalidAncestry)?;
        canonical_blocks.push(input.sidechain_blocks[block_index].clone());
        canonical_contexts.push(set.records[&hash].4);
    }
    Ok((canonical_blocks, canonical_contexts))
}

fn sidechain_confirmations(
    input: &ReplayInputV1,
    set: &VerifiedSidechainSet,
    tip_hash: Hash32,
) -> Result<u32, ReplayError> {
    let sidechain_tip_main_height = set
        .records
        .get(&tip_hash)
        .ok_or(ReplayError::TruthcoinForkOrInvalidAncestry)?
        .4
        .bmm_main_height;
    let confirmations = input
        .parent
        .height
        .checked_sub(sidechain_tip_main_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ReplayError::ConfirmationOverflow)?;
    if confirmations < input.authentication.minimum_bitcoin_confirmations {
        return Err(ReplayError::InsufficientConfirmations);
    }
    Ok(confirmations)
}

fn verify_sidechain(
    input: &ReplayInputV1,
    mtp_context: &[BitcoinHeader],
    headers: &[BitcoinHeader],
    commitments: &[Option<Hash32>],
) -> Result<(Vec<TruthcoinBlockV1>, Vec<CanonicalBlockContextV1>, u32), ReplayError> {
    let set = verify_sidechain_set(input, mtp_context, headers, commitments)?;
    let tip_hash = ranked_sidechain_tips(&set)
        .into_iter()
        .next()
        .ok_or(ReplayError::EmptySidechain)?;
    let (blocks, contexts) = sidechain_branch_for_tip(input, &set, tip_hash)?;
    let confirmations = sidechain_confirmations(input, &set, tip_hash)?;
    Ok((blocks, contexts, confirmations))
}

fn parse_truthcoin_header(bytes: &[u8]) -> Result<(Hash32, Option<Hash32>, Hash32), ReplayError> {
    if bytes.len() < 65 {
        return Err(ReplayError::InvalidTruthcoinHeaderEncoding);
    }
    let merkle_root = bytes[..32]
        .try_into()
        .map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)?;
    match bytes[32] {
        0 if bytes.len() == 65 => Ok((
            merkle_root,
            None,
            bytes[33..65]
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)?,
        )),
        1 if bytes.len() == 97 => Ok((
            merkle_root,
            Some(
                bytes[33..65]
                    .try_into()
                    .map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)?,
            ),
            bytes[65..97]
                .try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinHeaderEncoding)?,
        )),
        _ => Err(ReplayError::InvalidTruthcoinHeaderEncoding),
    }
}

fn truthcoin_body_merkle_root(body: &TruthcoinBodyV1) -> Hash32 {
    let mut leaves = Vec::with_capacity(body.transactions_borsh.len() + 1);
    leaves.push(*blake3::hash(&body.coinbase_borsh).as_bytes());
    leaves.extend(
        body.transactions_borsh
            .iter()
            .map(|transaction| *blake3::hash(transaction).as_bytes()),
    );
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut combined = [0_u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(right);
            next.push(*blake3::hash(&combined).as_bytes());
        }
        leaves = next;
    }
    leaves[0]
}

fn render_truthcoin_template(value: &str, period: u32) -> String {
    value.replace("{period}", &period.to_string())
}

fn truthcoin_slot_id(
    chain_id: Hash32,
    branch_id: Hash32,
    template_hash: Hash32,
    epoch: u64,
    genesis_timestamp: u64,
) -> Result<Hash32, ReplayError> {
    let start = epoch
        .checked_mul(TRUTHCOIN_PERIOD_SECONDS)
        .and_then(|offset| genesis_timestamp.checked_add(offset))
        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
    let end = start
        .checked_add(TRUTHCOIN_PERIOD_SECONDS)
        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
    let mut hasher = TaggedHasher::new("ECX/truthcoin-slot/v1");
    hasher.bytes(&chain_id);
    hasher.bytes(&branch_id);
    hasher.bytes(&template_hash);
    hasher.u64(epoch);
    hasher.u64(start);
    hasher.u64(end);
    Ok(hasher.finalize())
}

fn truthcoin_scaled_price(value: f64) -> Result<Price, ReplayError> {
    let scaled = value * PRICE_SCALE as f64;
    if !value.is_finite()
        || value <= 0.0
        || !scaled.is_finite()
        || scaled < 1.0
        || scaled > u64::MAX as f64
    {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Price::new(scaled.round() as u64).map_err(|_| ReplayError::InvalidTruthcoinDecisionState)
}

/// Convert Truthcoin's consensus-internal scalar outcome back to the decision's
/// real value. Native Truthcoin normalizes scalar votes and outcomes to `[0, 1]`
/// and stores `DecisionOutcome::{min,max}` as exactly `0.0` and `1.0`; the
/// decision record retains the user-facing scalar bounds.
fn truthcoin_denormalized_scalar_outcome(
    decision_type: &DecodedTruthcoinDecisionTypeV1,
    outcome: &TruthcoinDecisionOutcomeCodecV1,
) -> Result<f64, ReplayError> {
    let DecodedTruthcoinDecisionTypeV1::Scaled { min, max, .. } = decision_type else {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    };
    if outcome.min.to_bits() != 0.0_f64.to_bits()
        || outcome.max.to_bits() != 1.0_f64.to_bits()
        || !outcome.outcome_value.is_finite()
        || !(0.0..=1.0).contains(&outcome.outcome_value)
        || !min.is_finite()
        || !max.is_finite()
        || min >= max
    {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    let value = outcome.outcome_value * (max - min) + min;
    if !value.is_finite() || value < *min || value > *max {
        return Err(ReplayError::InvalidTruthcoinDecisionState);
    }
    Ok(value)
}

fn truthcoin_market_creation_txids(
    store: &CanonicalStateStoreV1,
    blocks: &[TruthcoinBlockV1],
) -> Result<BTreeMap<[u8; 6], Hash32>, ReplayError> {
    let mut block_result = BTreeMap::new();
    for block in blocks {
        for transaction_bytes in &block.body.transactions_borsh {
            let transaction = decode_truthcoin_transaction(transaction_bytes)?;
            if !matches!(
                transaction.data,
                Some(DecodedTruthcoinTransactionDataV1::CreateMarket(_))
            ) {
                continue;
            }
            let mut market_ids = transaction.outputs.iter().filter_map(|output| {
                if let DecodedTruthcoinOutputContentV1::MarketFunds {
                    market_id,
                    is_fee: false,
                    ..
                } = &output.content
                {
                    Some(*market_id)
                } else {
                    None
                }
            });
            let market_id = market_ids
                .next()
                .ok_or(ReplayError::InvalidTruthcoinMarketCreation)?;
            if market_ids.any(|candidate| candidate != market_id)
                || block_result
                    .insert(market_id, *blake3::hash(transaction_bytes).as_bytes())
                    .is_some()
            {
                return Err(ReplayError::InvalidTruthcoinMarketCreation);
            }
        }
    }
    let mut state_result = BTreeMap::new();
    for (_, value) in store.entries(TruthcoinDatabaseId::ConsolidationUndo.as_u8())? {
        let undo: TruthcoinConsolidationUndoCodecV1 =
            bincode::deserialize(value).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        if bincode::serialize(&undo).map_err(|_| ReplayError::InvalidTruthcoinMarketState)? != value
        {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
        for entry in undo.entries {
            if state_result.contains_key(&entry.market_id) {
                continue;
            }
            if let Some(TruthcoinOutPointCodecV1::Regular { txid, .. }) = entry.old_treasury_pointer
            {
                state_result.insert(entry.market_id, txid);
            }
        }
    }
    for (key, _) in store.entries(TruthcoinDatabaseId::Markets.as_u8())? {
        let market_id: [u8; 6] = key
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        if state_result.contains_key(&market_id) {
            continue;
        }
        let pointer_key = truthcoin_market_funds_pointer_key(market_id, false);
        if let Some(pointer) =
            store.get(TruthcoinDatabaseId::MarketFundsUtxos.as_u8(), &pointer_key)?
        {
            if let TruthcoinOutPointCodecV1::Regular { txid, .. } =
                decode_truthcoin_outpoint(pointer)?
            {
                state_result.insert(market_id, txid);
            }
        }
    }
    for (market_id, txid) in block_result {
        if state_result
            .insert(market_id, txid)
            .is_some_and(|state_txid| state_txid != txid)
        {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
    }
    Ok(state_result)
}

type TruthcoinMarketSampleV1 = (u32, u64, [i64; 2]);

fn truthcoin_market_samples(
    store: &CanonicalStateStoreV1,
    market: &TruthcoinMarketCodecV1,
    minimum_liquidity_sats: u64,
) -> Result<(u64, Vec<TruthcoinMarketSampleV1>), ReplayError> {
    truthcoin_market_samples_after_checkpoint(store, market, minimum_liquidity_sats, None)
}

// A trusted state snapshot is not evidence of observations before its height.
// The floor must ultimately come from the authenticated bootstrap commitment,
// never from an uncommitted caller-selected witness value.
fn truthcoin_market_samples_after_checkpoint(
    store: &CanonicalStateStoreV1,
    market: &TruthcoinMarketCodecV1,
    minimum_liquidity_sats: u64,
    trusted_floor: Option<u32>,
) -> Result<(u64, Vec<TruthcoinMarketSampleV1>), ReplayError> {
    if market.shares.len() != 2 {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }
    let mut updates = Vec::<(u32, TruthcoinMarketCodecV1)>::new();
    for (key, value) in store.entries(TruthcoinDatabaseId::MarketTransitionUndo.as_u8())? {
        let height = u32::from_le_bytes(
            key.try_into()
                .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
        );
        let undo: TruthcoinMarketTransitionUndoCodecV1 =
            bincode::deserialize(value).map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        if bincode::serialize(&undo).map_err(|_| ReplayError::InvalidTruthcoinMarketState)? != value
        {
            return Err(ReplayError::InvalidTruthcoinMarketState);
        }
        if let Some(prior) = undo.entries.into_iter().find(|entry| entry.id == market.id) {
            updates.push((height, prior));
        }
    }
    updates.sort_by_key(|(height, _)| *height);
    if updates.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ReplayError::InvalidTruthcoinMarketState);
    }

    let mut first_eligible = if updates
        .first()
        .map_or(market.liquidity_base_sats, |(_, prior)| {
            prior.liquidity_base_sats
        })
        >= minimum_liquidity_sats
    {
        u64::from(market.created_at_height)
    } else {
        u64::MAX
    };
    let mut samples = Vec::new();
    for index in 0..updates.len() {
        let (height, prior) = &updates[index];
        let post = updates.get(index + 1).map_or(market, |(_, next)| next);
        if prior.liquidity_base_sats < minimum_liquidity_sats
            && post.liquidity_base_sats >= minimum_liquidity_sats
        {
            first_eligible = first_eligible.min(u64::from(*height));
        }
        let shares: [i64; 2] = post
            .shares
            .as_slice()
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        if post.liquidity_base_sats >= minimum_liquidity_sats
            && samples.last().is_none_or(|sample: &(u32, u64, [i64; 2])| {
                sample.1 != post.liquidity_base_sats || sample.2 != shares
            })
        {
            samples.push((*height, post.liquidity_base_sats, shares));
        }
    }
    if updates.is_empty() && market.liquidity_base_sats >= minimum_liquidity_sats
        && trusted_floor.is_none_or(|floor| market.created_at_height > floor)
    {
        samples.push((
            market.created_at_height,
            market.liquidity_base_sats,
            [market.shares[0], market.shares[1]],
        ));
    }
    if samples.is_empty() && trusted_floor.is_none() {
        samples.push((
            market.last_updated_height,
            market.liquidity_base_sats,
            [market.shares[0], market.shares[1]],
        ));
    }
    if let Some(floor) = trusted_floor {
        samples.retain(|sample| sample.0 > floor);
        // Eligibility cannot be backdated from the snapshot's current state.
        first_eligible = samples.first().map_or(u64::MAX, |sample| u64::from(sample.0));
    }
    Ok((first_eligible, samples))
}

/// Derive every exact-template BTC/USD Decision and live LMSR market directly
/// from the canonical Truthcoin checkpoint. The keeper contributes no price,
/// candidate ID, eligibility height, or source location.
pub fn extract_truthcoin_oracle_candidates(
    authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    template: &TruthcoinMarketTemplateCommitmentV1,
    store: &CanonicalStateStoreV1,
    canonical_blocks: &[TruthcoinBlockV1],
    canonical_contexts: &[CanonicalBlockContextV1],
    source_confirmations: u32,
) -> Result<StateMachineOutputV1, ReplayError> {
    extract_truthcoin_oracle_candidates_with_floor(authentication, template, store,
        canonical_blocks, canonical_contexts, source_confirmations, None)
}

// Kept private until the enclosing bootstrap authenticates and carries the
// floor across every successor checkpoint. Ordinary full replay has no floor.
fn extract_truthcoin_oracle_candidates_with_floor(
    authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
    template: &TruthcoinMarketTemplateCommitmentV1,
    store: &CanonicalStateStoreV1,
    canonical_blocks: &[TruthcoinBlockV1],
    canonical_contexts: &[CanonicalBlockContextV1],
    source_confirmations: u32,
    trusted_floor: Option<u32>,
) -> Result<StateMachineOutputV1, ReplayError> {
    if template.version != TruthcoinMarketTemplateCommitmentV1::VERSION
        || authentication.validate().is_err()
        || template.digest() != authentication.btc_usd_template_hash
        || canonical_blocks.len() != canonical_contexts.len()
        || canonical_blocks.is_empty()
        || canonical_blocks
            .iter()
            .zip(canonical_contexts)
            .any(|(block, context)| {
                block.block_hash() != context.sidechain_block_hash
                    || block.height != context.sidechain_height
                    || block.bmm_main_height != context.bmm_main_height
            })
    {
        return Err(ReplayError::InvalidStateMachineOutput);
    }
    let source = *canonical_contexts
        .last()
        .ok_or(ReplayError::InvalidStateMachineOutput)?;
    let state_tip = store
        .get(TruthcoinDatabaseId::Tip.as_u8(), &TRUTHCOIN_UNIT_KEY)?
        .ok_or(ReplayError::InvalidStateMachineOutput)?;
    let state_height = store
        .get(TruthcoinDatabaseId::Height.as_u8(), &TRUTHCOIN_UNIT_KEY)?
        .ok_or(ReplayError::InvalidStateMachineOutput)?;
    let state_timestamp = store
        .get(
            TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )?
        .ok_or(ReplayError::InvalidStateMachineOutput)?;
    if state_tip != source.sidechain_block_hash
        || u64::from(u32::from_le_bytes(
            state_height
                .try_into()
                .map_err(|_| ReplayError::InvalidStateMachineOutput)?,
        )) != source.sidechain_height
        || u64::from_le_bytes(
            state_timestamp
                .try_into()
                .map_err(|_| ReplayError::InvalidStateMachineOutput)?,
        ) != source.bmm_main_timestamp
    {
        return Err(ReplayError::InvalidStateMachineOutput);
    }
    let state_root = store.root()?;
    let genesis_timestamp_bytes = store
        .get(
            TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
            &TRUTHCOIN_UNIT_KEY,
        )?
        .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
    let genesis_timestamp = u64::from_le_bytes(
        genesis_timestamp_bytes
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinDecisionState)?,
    );
    let template_hash = template.digest();
    let creation_txids = truthcoin_market_creation_txids(store, canonical_blocks)?;
    let mut matching_decisions = BTreeMap::<[u8; 3], TruthcoinStoredDecisionV1>::new();
    for (_, bytes) in store.entries(TruthcoinDatabaseId::PeriodDecisions.as_u8())? {
        for entry in decode_truthcoin_period_decisions(bytes)? {
            let Some(decision) = entry.decision else {
                continue;
            };
            let period = u32::from(entry.decision_id[0] & 0x7f);
            let exact_scalar = matches!(
                &decision.decision_type,
                DecodedTruthcoinDecisionTypeV1::Scaled { min, max, increment }
                    if min.to_bits() == template.scalar_min_f64_bits
                        && max.to_bits() == template.scalar_max_f64_bits
                        && increment.to_bits() == template.scalar_increment_f64_bits
            );
            if is_standard_native_decision_id(entry.decision_id)
                && exact_scalar
                && decision.header
                    == render_truthcoin_template(&template.decision_header_template, period)
                && decision.description
                    == render_truthcoin_template(&template.decision_description_template, period)
                && decision.tags == template.decision_tags
                && decision.option_0_label.is_none()
                && decision.option_1_label.is_none()
            {
                matching_decisions.insert(entry.decision_id, decision);
            }
        }
    }

    let mut anchors = Vec::new();
    for (decision_id, decision) in &matching_decisions {
        let Some(outcome) = truthcoin_resolved_decision_outcome(store, *decision_id)? else {
            continue;
        };
        if !matches!(
            &decision.decision_type,
            DecodedTruthcoinDecisionTypeV1::Scaled { .. }
        ) {
            continue;
        }
        let denormalized_outcome =
            truthcoin_denormalized_scalar_outcome(&decision.decision_type, &outcome)?;
        let epoch = native_decision_period_index(*decision_id);
        let observation_end_mtp = epoch
            .checked_add(1)
            .and_then(|period| period.checked_mul(TRUTHCOIN_PERIOD_SECONDS))
            .and_then(|offset| genesis_timestamp.checked_add(offset))
            .ok_or(ReplayError::InvalidTruthcoinDecisionState)?;
        anchors.push(AnchorCandidateV1 {
            native_decision_id: *decision_id,
            template_hash,
            finalized: true,
            anchor: TruthcoinAnchorV1 {
                version: TruthcoinAnchorV1::VERSION,
                truthcoin_chain_id: authentication.truthcoin_chain_id,
                branch_id: authentication.truthcoin_branch_id,
                template_hash,
                epoch,
                decision_id: native_decision_id_hash(
                    authentication.truthcoin_chain_id,
                    *decision_id,
                ),
                slot_id: truthcoin_slot_id(
                    authentication.truthcoin_chain_id,
                    authentication.truthcoin_branch_id,
                    template_hash,
                    epoch,
                    genesis_timestamp,
                )?,
                source_block_hash: source.sidechain_block_hash,
                source_state_root: state_root,
                source_height: source.sidechain_height,
                source_mtp: source.bmm_main_mtp,
                source_confirmations,
                observation_end_mtp,
                finalized_at_mtp: observation_end_mtp,
                btc_usd_price: truthcoin_scaled_price(denormalized_outcome)?,
            },
        });
    }

    let mut markets = Vec::new();
    let mut matching_market_records =
        Vec::<([u8; 6], Vec<u8>, TruthcoinMarketCodecV1, [u8; 3])>::new();
    let expected_market_tags = template
        .decision_tags
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_market_tags = expected_market_tags.into_iter().collect::<Vec<_>>();
    for (key, bytes) in store.entries(TruthcoinDatabaseId::Markets.as_u8())? {
        let market_id: [u8; 6] = key
            .try_into()
            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        let market = decode_truthcoin_market(bytes)?;
        let [decision_id] = market.decision_ids.as_slice() else {
            continue;
        };
        let decision_id = *decision_id;
        if !matching_decisions.contains_key(&decision_id) {
            continue;
        }
        let period = u32::from(decision_id[0] & 0x7f);
        let exact_dimension = market.dimension_specs.as_slice()
            == [TruthcoinMarketDimensionCodecV1::Single(decision_id)];
        let exact_fee = market.trading_fee.to_bits()
            == (f64::from(template.trading_fee_ppm) / 1_000_000.0).to_bits();
        if market.id != market_id
            || market.title != render_truthcoin_template(&template.market_title_template, period)
            || market.description
                != render_truthcoin_template(&template.market_description_template, period)
            || market.tags != expected_market_tags
            || !exact_dimension
            || !exact_fee
            || market.tx_pow_hash_selector != template.tx_pow_hash_selector
            || market.tx_pow_ordering != template.tx_pow_ordering
            || market.tx_pow_difficulty != template.tx_pow_difficulty
            || market.shares.len() != 2
        {
            continue;
        }
        matching_market_records.push((market_id, bytes.to_vec(), market, decision_id));
    }
    let mut registry_hasher = TaggedHasher::new("ECX/truthcoin-market-registry/v1");
    registry_hasher.bytes(&state_root);
    registry_hasher.u32(
        u32::try_from(matching_market_records.len()).map_err(|_| ReplayError::CandidateBounds)?,
    );
    for (market_id, bytes, _, _) in &matching_market_records {
        registry_hasher.bytes(market_id);
        registry_hasher.bytes(&Sha256::digest(bytes));
    }
    let registry_root = registry_hasher.finalize();

    for (market_id, _bytes, market, decision_id) in matching_market_records {
        let decision = matching_decisions
            .get(&decision_id)
            .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
        let DecodedTruthcoinDecisionTypeV1::Scaled { min, max, .. } = &decision.decision_type
        else {
            continue;
        };
        let (first_eligible, samples) = match trusted_floor {
            None => truthcoin_market_samples(store, &market, template.minimum_liquidity_sats)?,
            Some(floor) => truthcoin_market_samples_after_checkpoint(
                store, &market, template.minimum_liquidity_sats, Some(floor),
            )?,
        };
        if samples.is_empty() {
            // Preserve the market in the registry, but do not offer it as an
            // oracle candidate without any verified post-checkpoint samples.
            continue;
        }
        let beta = market.liquidity_base_sats as f64 / libm::log(2.0);
        let shares = [market.shares[0], market.shares[1]];
        let probability = upstream_binary_lmsr_probability(shares, beta)
            .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?;
        let mut sample_hasher = TaggedHasher::new("ECX/truthcoin-lmsr-sample-window/v1");
        sample_hasher.bytes(&market_id);
        sample_hasher.u32(samples.len() as u32);
        for (height, liquidity, sample_shares) in &samples {
            sample_hasher.u32(*height);
            sample_hasher.u64(*liquidity);
            sample_hasher.bytes(&sample_shares[0].to_le_bytes());
            sample_hasher.bytes(&sample_shares[1].to_le_bytes());
        }
        let sample_window_root = sample_hasher.finalize();
        let mut selection_hasher = TaggedHasher::new("ECX/truthcoin-market-selection/v1");
        selection_hasher.bytes(&registry_root);
        selection_hasher.bytes(&market_id);
        selection_hasher.u64(first_eligible);
        let epoch = native_decision_period_index(decision_id);
        let epoch_start_mtp = epoch
            .checked_mul(TRUTHCOIN_PERIOD_SECONDS)
            .and_then(|offset| genesis_timestamp.checked_add(offset))
            .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
        let resolves_at_mtp = epoch_start_mtp
            .checked_add(TRUTHCOIN_PERIOD_SECONDS)
            .ok_or(ReplayError::InvalidTruthcoinMarketState)?;
        markets.push(MarketCandidateV1 {
            native_decision_id: decision_id,
            native_market_id: market_id,
            template_hash,
            is_open: market.market_state == TruthcoinMarketStateCodecV1::Trading,
            market_creation_txid: *creation_txids
                .get(&market_id)
                .ok_or(ReplayError::InvalidTruthcoinMarketState)?,
            market_created_height: u64::from(market.created_at_height),
            market_first_eligible_height: first_eligible,
            liquidity_base_sats: market.liquidity_base_sats,
            beta_f64_bits: beta.to_bits(),
            shares,
            selected_outcome_index: 1,
            probability_f64_bits: probability.to_bits(),
            snapshot: TruthcoinLmsrSnapshotV1 {
                version: TruthcoinLmsrSnapshotV1::VERSION,
                truthcoin_chain_id: authentication.truthcoin_chain_id,
                branch_id: authentication.truthcoin_branch_id,
                template_hash,
                epoch,
                decision_id: native_decision_id_hash(
                    authentication.truthcoin_chain_id,
                    decision_id,
                ),
                market_id: native_market_id_hash(authentication.truthcoin_chain_id, market_id),
                slot_id: truthcoin_slot_id(
                    authentication.truthcoin_chain_id,
                    authentication.truthcoin_branch_id,
                    template_hash,
                    epoch,
                    genesis_timestamp,
                )?,
                registry_root,
                selection_proof_root: selection_hasher.finalize(),
                source_block_hash: source.sidechain_block_hash,
                source_state_root: state_root,
                source_height: source.sidechain_height,
                source_mtp: source.bmm_main_mtp,
                source_confirmations,
                epoch_start_mtp,
                resolves_at_mtp,
                scalar_lower_bound: truthcoin_scaled_price(*min)?,
                scalar_upper_bound: truthcoin_scaled_price(*max)?,
                lmsr_b: beta.floor() as u64,
                yes_probability_ppb: probability_to_ppb(probability)
                    .map_err(|_| ReplayError::InvalidTruthcoinMarketState)?,
                sample_window_root,
                sample_count: u32::try_from(samples.len())
                    .map_err(|_| ReplayError::CandidateBounds)?,
                lmsr_state_root: native_lmsr_state_root(
                    market_id,
                    market.liquidity_base_sats,
                    beta.to_bits(),
                    shares,
                ),
                saturated: false,
            },
        });
    }
    let state = StateMachineOutputV1 {
        version: StateMachineOutputV1::VERSION,
        replayed_state_root: state_root,
        anchors,
        markets,
    };
    validate_state_machine_output_bounds(&state)?;
    Ok(state)
}

fn validate_candidate_integrity(
    input: &ReplayInputV1,
    state: &StateMachineOutputV1,
) -> Result<(), ReplayError> {
    let unique_anchor_ids = state
        .anchors
        .iter()
        .try_fold(BTreeSet::new(), |mut ids, candidate| {
            ids.insert(candidate.native_decision_id).then_some(ids)
        })
        .is_some();
    let unique_market_ids = state
        .markets
        .iter()
        .try_fold(BTreeSet::new(), |mut ids, candidate| {
            ids.insert(candidate.native_market_id).then_some(ids)
        })
        .is_some();
    if !unique_anchor_ids || !unique_market_ids {
        return Err(ReplayError::DuplicateCandidate);
    }

    for candidate in &state.anchors {
        if candidate.anchor.version != TruthcoinAnchorV1::VERSION
            || candidate.anchor.truthcoin_chain_id != input.authentication.truthcoin_chain_id
            || candidate.anchor.branch_id != input.authentication.truthcoin_branch_id
            || candidate.anchor.template_hash != candidate.template_hash
            || candidate.anchor.epoch != native_decision_period_index(candidate.native_decision_id)
            || candidate.anchor.decision_id
                != native_decision_id_hash(
                    input.authentication.truthcoin_chain_id,
                    candidate.native_decision_id,
                )
        {
            return Err(ReplayError::InvalidStateMachineOutput);
        }
    }
    for candidate in &state.markets {
        if candidate.snapshot.version != TruthcoinLmsrSnapshotV1::VERSION
            || candidate.snapshot.truthcoin_chain_id != input.authentication.truthcoin_chain_id
            || candidate.snapshot.branch_id != input.authentication.truthcoin_branch_id
            || candidate.snapshot.template_hash != candidate.template_hash
            || candidate.snapshot.epoch
                != native_decision_period_index(candidate.native_decision_id)
            || candidate.snapshot.decision_id
                != native_decision_id_hash(
                    input.authentication.truthcoin_chain_id,
                    candidate.native_decision_id,
                )
            || candidate.snapshot.market_id
                != native_market_id_hash(
                    input.authentication.truthcoin_chain_id,
                    candidate.native_market_id,
                )
        {
            return Err(ReplayError::InvalidStateMachineOutput);
        }
    }
    Ok(())
}

fn select_anchor(
    input: &ReplayInputV1,
    anchors: &[AnchorCandidateV1],
) -> Result<AnchorCandidateV1, ReplayError> {
    anchors
        .iter()
        .filter(|candidate| {
            candidate.finalized
                && candidate.template_hash == input.authentication.btc_usd_template_hash
                && is_standard_native_decision_id(candidate.native_decision_id)
                && candidate.anchor.finalized_at_mtp <= input.parent.median_time_past
        })
        .min_by(|left, right| {
            right
                .anchor
                .observation_end_mtp
                .cmp(&left.anchor.observation_end_mtp)
                .then_with(|| left.native_decision_id.cmp(&right.native_decision_id))
        })
        .cloned()
        .ok_or(ReplayError::NoEligibleAnchor)
}

fn native_decision_period_index(native_id: [u8; 3]) -> u64 {
    u64::from(native_id[0] & 0x7f)
}

fn select_market(
    input: &ReplayInputV1,
    markets: &[MarketCandidateV1],
) -> Result<MarketCandidateV1, ReplayError> {
    markets
        .iter()
        .filter(|candidate| {
            candidate.is_open
                && candidate.template_hash == input.authentication.btc_usd_template_hash
                && is_standard_native_decision_id(candidate.native_decision_id)
                && candidate.liquidity_base_sats >= input.market_template.minimum_liquidity_sats
                && candidate.market_created_height <= candidate.market_first_eligible_height
                && candidate.market_first_eligible_height <= candidate.snapshot.source_height
                && candidate.selected_outcome_index == 1
                && candidate.snapshot.resolves_at_mtp > input.parent.median_time_past
        })
        .min_by(|left, right| {
            left.snapshot
                .resolves_at_mtp
                .cmp(&right.snapshot.resolves_at_mtp)
                .then_with(|| {
                    left.market_first_eligible_height
                        .cmp(&right.market_first_eligible_height)
                })
                .then_with(|| left.native_market_id.cmp(&right.native_market_id))
        })
        .cloned()
        .ok_or(ReplayError::NoEligibleMarket)
}

trait SourceLocation {
    fn source_block_hash(&self) -> Hash32;
    fn source_height(&self) -> u64;
    fn source_mtp(&self) -> u64;
    fn source_confirmations(&self) -> u32;
}

impl SourceLocation for TruthcoinAnchorV1 {
    fn source_block_hash(&self) -> Hash32 {
        self.source_block_hash
    }
    fn source_height(&self) -> u64 {
        self.source_height
    }
    fn source_mtp(&self) -> u64 {
        self.source_mtp
    }
    fn source_confirmations(&self) -> u32 {
        self.source_confirmations
    }
}

impl SourceLocation for TruthcoinLmsrSnapshotV1 {
    fn source_block_hash(&self) -> Hash32 {
        self.source_block_hash
    }
    fn source_height(&self) -> u64 {
        self.source_height
    }
    fn source_mtp(&self) -> u64 {
        self.source_mtp
    }
    fn source_confirmations(&self) -> u32 {
        self.source_confirmations
    }
}

fn validate_source_location<T: SourceLocation>(
    input: &ReplayInputV1,
    record: &T,
) -> Result<(), ReplayError> {
    let block = input
        .sidechain_blocks
        .iter()
        .find(|block| block.block_hash() == record.source_block_hash())
        .ok_or(ReplayError::InvalidSourceLocation)?;
    let index = block
        .bmm_main_height
        .checked_sub(input.authentication.bitcoin_checkpoint_height)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(ReplayError::InvalidSourceLocation)?;
    let headers = input
        .mainchain_headers
        .iter()
        .map(|header| {
            deserialize::<BitcoinHeader>(&header.consensus_header)
                .map_err(|_| ReplayError::InvalidBitcoinHeaderEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoint = *headers.first().ok_or(ReplayError::InvalidSourceLocation)?;
    let mtp_context = decode_checkpoint_mtp_context(input, checkpoint)?;
    let confirmations = input
        .parent
        .height
        .checked_sub(block.bmm_main_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ReplayError::InvalidSourceLocation)?;
    if block.height != record.source_height()
        || median_time_past(&mtp_context, &headers, index)? != record.source_mtp()
        || confirmations != record.source_confirmations()
    {
        return Err(ReplayError::InvalidSourceLocation);
    }
    Ok(())
}

fn median_time_past(
    context: &[BitcoinHeader],
    headers: &[BitcoinHeader],
    index: usize,
) -> Result<u64, ReplayError> {
    if context.len() != BITCOIN_MTP_WINDOW - 1 || index >= headers.len() {
        return Err(ReplayError::MissingMedianTimeContext);
    }
    let mut times = context
        .iter()
        .chain(headers[..=index].iter())
        .rev()
        .take(BITCOIN_MTP_WINDOW)
        .map(|header| u64::from(header.time))
        .collect::<Vec<_>>();
    if times.len() != BITCOIN_MTP_WINDOW {
        return Err(ReplayError::MissingMedianTimeContext);
    }
    times.sort_unstable();
    Ok(times[BITCOIN_MTP_WINDOW / 2])
}

fn canonical_chain_root(input: &ReplayInputV1, commitments: &[Option<Hash32>]) -> Hash32 {
    let mut hasher = TaggedHasher::new("ECX/truthcoin-canonical-chain/v1");
    hasher.u32(input.checkpoint_mtp_headers.len() as u32);
    for header in &input.checkpoint_mtp_headers {
        hasher.bytes(header);
    }
    hasher.u32(input.mainchain_headers.len() as u32);
    for ((header, inclusion), commitment) in input
        .mainchain_headers
        .iter()
        .zip(&input.coinbase_inclusions)
        .zip(commitments)
    {
        hasher.u64(header.height);
        hasher.bytes(&header.consensus_header);
        hasher.bytes(&Sha256::digest(&inclusion.coinbase_transaction));
        match commitment {
            Some(value) => {
                hasher.bytes(&[1]);
                hasher.bytes(value);
            }
            None => hasher.bytes(&[0]),
        }
    }
    hasher.u32(input.sidechain_blocks.len() as u32);
    for block in &input.sidechain_blocks {
        hasher.u64(block.height);
        hasher.u64(block.bmm_main_height);
        hasher.bytes(&block.block_hash());
    }
    hasher.finalize()
}

fn replay_transcript_root(
    blocks: &[TruthcoinBlockV1],
    contexts: &[CanonicalBlockContextV1],
) -> Hash32 {
    debug_assert_eq!(blocks.len(), contexts.len());
    let mut hasher = TaggedHasher::new("ECX/truthcoin-replay-transcript/v2");
    hasher.u32(blocks.len() as u32);
    for (block, context) in blocks.iter().zip(contexts) {
        hasher.u64(block.height);
        hasher.u64(block.bmm_main_height);
        hasher.length_prefixed(&block.header_borsh);
        hasher.length_prefixed(&block.body.coinbase_borsh);
        hasher.u32(block.body.transactions_borsh.len() as u32);
        for transaction in &block.body.transactions_borsh {
            hasher.length_prefixed(transaction);
        }
        hasher.length_prefixed(&block.body.authorizations_borsh);
        hasher.length_prefixed(&block.body.actor_proofs_borsh);
        hasher.bytes(&context.sidechain_block_hash);
        hasher.u64(context.sidechain_height);
        hasher.bytes(&context.bmm_main_block_hash);
        hasher.u64(context.bmm_main_height);
        hasher.u64(context.bmm_main_timestamp);
        hasher.u64(context.bmm_main_mtp);
    }
    hasher.finalize()
}

struct TaggedHasher(Sha256);

impl TaggedHasher {
    fn new(tag: &str) -> Self {
        let tag_hash: Hash32 = Sha256::digest(tag.as_bytes()).into();
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        Self(hasher)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn length_prefixed(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes(value);
    }

    fn finalize(self) -> Hash32 {
        self.0.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayError {
    #[error("replay input exceeds a frozen bound")]
    Bounds,
    #[error("invalid replay authentication or market-template configuration")]
    InvalidConfiguration,
    #[error("mainchain header list is empty")]
    EmptyMainchain,
    #[error("Truthcoin sidechain block list is empty")]
    EmptySidechain,
    #[error("Bitcoin checkpoint must be the first header bound by the authentication config")]
    CheckpointNotEpochAligned,
    #[error("Bitcoin header range does not exactly reach the parent height")]
    MainchainHeightMismatch,
    #[error("Bitcoin header is not exact canonical consensus encoding")]
    InvalidBitcoinHeaderEncoding,
    #[error("Bitcoin checkpoint hash mismatch")]
    WrongCheckpoint,
    #[error("missing Bitcoin difficulty-adjustment context")]
    MissingDifficultyContext,
    #[error("Bitcoin proof of work or required target is invalid")]
    InvalidProofOfWork,
    #[error("Bitcoin headers are not a contiguous chain")]
    InvalidMainchainAncestry,
    #[error("checkpoint MTP headers are not the exact ten authenticated predecessors")]
    InvalidCheckpointMtpContext,
    #[error("Bitcoin header timestamp does not exceed the prior median time")]
    InvalidBitcoinTimestamp,
    #[error("Bitcoin tip hash/height/MTP does not equal the ECX parent context")]
    WrongParentContext,
    #[error("coinbase evidence height mismatch")]
    CoinbaseHeightMismatch,
    #[error("invalid or noncanonical Bitcoin coinbase transaction")]
    InvalidCoinbaseEncoding,
    #[error(
        "Bitcoin block transaction list is incomplete, noncanonical, or has the wrong Merkle root"
    )]
    InvalidBitcoinBlockTransactions,
    #[error("frozen BIP300 checkpoint state does not match its authentication commitment")]
    InvalidBip300CheckpointState,
    #[error("BIP300 sidechain activation occurred after the checkpoint but activation replay is unlinked")]
    Bip300ActivationReplayUnlinked,
    #[error("BIP300 CTIP ancestry, value, or replacement output is invalid")]
    InvalidBip300CtipTransition,
    #[error("BIP300 M5 deposit address is missing or noncanonical")]
    InvalidBip300DepositAddress,
    #[error("BIP300 M6 withdrawal effects are not linked into Truthcoin replay")]
    Bip300WithdrawalReplayUnlinked,
    #[error("coinbase transaction is not committed by the Bitcoin header")]
    InvalidCoinbaseMerkleProof,
    #[error("invalid BIP301 M7 message")]
    InvalidM7,
    #[error("duplicate or zero M7 commitment for Truthcoin in one coinbase")]
    DuplicateOrZeroM7,
    #[error("a committed Truthcoin header/body preimage is missing")]
    MissingCommittedSidechainBlock,
    #[error("Truthcoin Borsh header is noncanonical")]
    InvalidTruthcoinHeaderEncoding,
    #[error("Truthcoin body does not match its BLAKE3 Merkle root")]
    InvalidTruthcoinMerkleRoot,
    #[error("Truthcoin authorization or actor-proof body is not exact canonical Borsh")]
    InvalidTruthcoinBodyEncoding,
    #[error("Truthcoin authorization key or actor-proof signature is invalid")]
    InvalidTruthcoinAuthorization,
    #[error("Truthcoin transaction input vector is not exact pinned Borsh")]
    InvalidTruthcoinTransactionEncoding,
    #[error("Truthcoin UTXO value is not exact canonical upstream bincode")]
    InvalidTruthcoinUtxoEncoding,
    #[error("Truthcoin transaction spends an unknown UTXO")]
    MissingTruthcoinUtxo,
    #[error("Truthcoin input authorization does not own its spent UTXO")]
    WrongTruthcoinAuthorizationAddress,
    #[error("Truthcoin UTXO address index is missing or inconsistent")]
    InvalidTruthcoinUtxoIndex,
    #[error("Truthcoin transition would overwrite an existing UTXO")]
    DuplicateTruthcoinUtxo,
    #[error("Truthcoin transition would overwrite an existing STXO")]
    DuplicateTruthcoinStxo,
    #[error("Truthcoin coinbase contains an output type forbidden by pinned consensus")]
    InvalidTruthcoinCoinbase,
    #[error("Truthcoin block coinbase exceeds the fees paid by non-skipped transactions")]
    InvalidTruthcoinBlockFees,
    #[error("Truthcoin rollback cannot find its spent-output record")]
    MissingTruthcoinStxo,
    #[error("Truthcoin reputation table or undo record is malformed")]
    InvalidTruthcoinReputationState,
    #[error("Truthcoin reputation transfer violates pinned consensus rules")]
    InvalidTruthcoinReputationTransfer,
    #[error("Truthcoin Decision or vote table bytes are malformed")]
    InvalidTruthcoinVotingState,
    #[error("Truthcoin vote or ballot violates pinned consensus rules")]
    InvalidTruthcoinVote,
    #[error("Truthcoin Decision table bytes are malformed")]
    InvalidTruthcoinDecisionState,
    #[error("Truthcoin Decision claim violates pinned consensus rules")]
    InvalidTruthcoinDecisionClaim,
    #[error("Truthcoin Decision period/pricing block frame is malformed")]
    InvalidTruthcoinDecisionFrame,
    #[error("Truthcoin market table or index bytes are malformed")]
    InvalidTruthcoinMarketState,
    #[error("Truthcoin market creation violates pinned consensus rules")]
    InvalidTruthcoinMarketCreation,
    #[error("Truthcoin LMSR trade violates pinned consensus rules")]
    InvalidTruthcoinTrade,
    #[error("Truthcoin header prev_main_hash is not the M7 block's parent")]
    InvalidBmmParentBinding,
    #[error(
        "Truthcoin fork encountered; this boundary fails closed until exact fork choice is ported"
    )]
    TruthcoinForkOrInvalidAncestry,
    #[error("no Truthcoin branch committed by the authenticated Bitcoin chain has valid state transitions")]
    NoStateValidTruthcoinBranch,
    #[error("sidechain evidence is not committed by the authenticated Bitcoin chain")]
    UncommittedSidechainBlock,
    #[error("eleven Bitcoin headers are required to derive MTP")]
    MissingMedianTimeContext,
    #[error("source confirmation count overflow")]
    ConfirmationOverflow,
    #[error("Truthcoin tip has insufficient Bitcoin confirmations")]
    InsufficientConfirmations,
    #[error("the exact pinned Truthcoin 0.17.0 state machine is not linked")]
    StateMachineUnlinked,
    #[error("the exact pinned Truthcoin 0.17.0 incremental state machine is not linked")]
    IncrementalStateMachineUnlinked,
    #[error("invalid or unlinked incremental Truthcoin replay checkpoint")]
    InvalidIncrementalCheckpoint,
    #[error("the incremental Truthcoin state machine returned an invalid successor")]
    InvalidIncrementalStateMachineOutput,
    #[error("incremental replay checkpoint does not match the Elements anchor state")]
    InvalidIncrementalAnchorBinding,
    #[error("invalid canonical Truthcoin state snapshot")]
    InvalidCanonicalStateSnapshot,
    #[error("unknown canonical Truthcoin state database ID")]
    InvalidStateDatabaseId,
    #[error("the linked state machine returned malformed or inconsistent data")]
    InvalidStateMachineOutput,
    #[error("no finalized canonical BTC/USD anchor exists")]
    NoEligibleAnchor,
    #[error("no open canonical BTC/USD LMSR market exists")]
    NoEligibleMarket,
    #[error("state-machine candidate output contains duplicate native IDs")]
    DuplicateCandidate,
    #[error("state-machine candidate output exceeds the frozen aggregate bound")]
    CandidateBounds,
    #[error("selected record is not located at its replayed sidechain block")]
    InvalidSourceLocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    // External captured-state evidence; never a production schema migration.
    #[test]
    #[ignore = "requires pinned native and replay capture paths"]
    fn captured_settlement_undo_matches_legacy_projection() {
        #[derive(Serialize, Deserialize)]
        struct LegacyEntry {
            pre_settlement_market: TruthcoinMarketCodecV1,
            payout_summary: TruthcoinMarketPayoutSummaryCodecV1,
            treasury_utxo: Option<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
            fee_utxo: Option<(TruthcoinOutPointCodecV1, TruthcoinFilledOutputV1)>,
        }
        #[derive(Serialize, Deserialize)]
        struct LegacyUndo { entries: Vec<LegacyEntry> }
        fn pinned(name: &str, expected: &str) -> Vec<u8> {
            use sha2::{Digest, Sha256};
            let bytes = std::fs::read(std::env::var(name).expect(name)).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&bytes)), expected);
            bytes
        }
        let native: serde_json::Value = serde_json::from_slice(&pinned(
            "ALPHA_NATIVE_CAPTURE",
            "8007a2549506161a58bc9d9994ec270d7da45f42632e768e185d5197e17e4d31",
        )).unwrap();
        let replay = CanonicalStateStoreV1::import(&pinned(
            "ALPHA_REPLAY_CAPTURE",
            "c30be5aee0a280f4840e72cf706db54baf96aea53b40011791769f0d45b39c15",
        )).unwrap();
        let table = native["tables"].as_array().unwrap().iter()
            .find(|t| t["name"] == "settlement_undo").unwrap();
        for (height, count) in [(14u32, 4usize), (15, 1)] {
            let key = height.to_le_bytes();
            let entry = table["entries"].as_array().unwrap().iter()
                .find(|e| e["key_hex"] == hex::encode(key)).unwrap();
            let old_bytes = hex::decode(entry["value_hex"].as_str().unwrap()).unwrap();
            let old: LegacyUndo = bincode::deserialize(&old_bytes).unwrap();
            assert_eq!(bincode::serialize(&old).unwrap(), old_bytes);
            let (_, new_bytes) = replay.entries(TruthcoinDatabaseId::SettlementUndo as u8)
                .unwrap().find(|(k, _)| *k == key).unwrap();
            let new: TruthcoinSettlementUndoCodecV1 = bincode::deserialize(new_bytes).unwrap();
            assert_eq!(bincode::serialize(&new).unwrap(), new_bytes);
            assert_eq!(new.entries.len(), count);
            assert_eq!(new_bytes.len(), old_bytes.len() + 8 * count);
            let mut projection = LegacyUndo { entries: new.entries.into_iter().map(|e| {
                assert!(e.pre_settlement_share_accounts.is_empty());
                LegacyEntry {
                    pre_settlement_market: e.pre_settlement_market,
                    payout_summary: e.payout_summary,
                    treasury_utxo: e.treasury_utxo,
                    fee_utxo: e.fee_utxo,
                }
            }).collect() };
            assert_eq!(bincode::serialize(&projection).unwrap(), old_bytes);
            projection.entries[0].payout_summary.block_height ^= 1;
            assert_ne!(bincode::serialize(&projection).unwrap(), old_bytes);
            println!("height {height}: {count} entries, exact legacy projection PASS; recovery vectors empty");
        }
    }

    #[cfg(not(feature = "truthcoin-alpha-one-day-period"))]
    #[test]
    fn default_replay_profile_keeps_quarterly_periods() {
        assert_eq!(TRUTHCOIN_PERIOD_SECONDS, 7_862_400);
    }

    #[cfg(feature = "truthcoin-alpha-one-day-period")]
    #[test]
    fn alpha_replay_profile_uses_upstream_one_day_periods() {
        assert_eq!(TRUTHCOIN_PERIOD_SECONDS, 86_400);
    }
    use bitcoin::{
        absolute, script::PushBytesBuf, transaction, Amount, BlockHash, OutPoint, ScriptBuf,
        Sequence, TxIn, TxMerkleNode, TxOut, Witness,
    };
    use ecx_protocol_core::types::{Price, PRICE_SCALE};
    use ecx_truthcoin_proof::{
        native_lmsr_state_root, probability_to_ppb, upstream_binary_lmsr_probability,
        TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
    };

    const CHECKPOINT_HEIGHT: u64 = BITCOIN_DIFFICULTY_INTERVAL;
    const CONTEXT_START_TIME: u32 = 10_000;
    const EASY_BITS: u32 = 0x207f_ffff;

    #[test]
    fn complete_standard_market_block_matches_patched_native_checkpoint_and_query() {
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-standard-market-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            "ab455a84b4d104cb13dac113f30fda65c7d8d71c56cf1772e4f731ec098a2f7c"
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: bytes("coinbase_borsh_hex"),
                transactions_borsh: vec![bytes("transaction_borsh_hex")],
                authorizations_borsh: bytes("authorizations_borsh_hex"),
                actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );

        let query = &vector["native_query"];
        let market_id = hex::decode(query["market_id"].as_str().unwrap()).unwrap();
        let market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            u64::from(market.created_at_height),
            query["created_at_height"]
        );
        assert_eq!(
            u64::from(market.last_updated_height),
            query["last_updated_height"]
        );
        assert_eq!(market.liquidity_base_sats, query["liquidity_base_sats"]);
        assert_eq!(market.shares, vec![0, 0]);
        assert_eq!(market.tx_pow_hash_selector, 0);
        assert_eq!(market.tx_pow_ordering, 0);
        assert_eq!(market.tx_pow_difficulty, 0);
        assert_eq!(market.trading_fee.to_bits(), query["trading_fee_bits"]);
        assert_eq!(
            (market.liquidity_base_sats as f64 / libm::log(2.0)).to_bits(),
            query["beta_bits"]
        );
        assert_eq!(
            hex::encode(blake3::hash(&block.body.transactions_borsh[0]).as_bytes()),
            query["creation_txid"].as_str().unwrap()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                    &TRUTHCOIN_UNIT_KEY,
                )
                .unwrap()
                .unwrap(),
            timestamp.to_le_bytes()
        );

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);
    }

    #[test]
    fn complete_standard_buy_matches_patched_native_and_conserves_value() {
        const VECTOR: &[u8] = include_bytes!("../test-vectors/patched-native-standard-buy-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            "f44456b628346258fecfb6100246613f171a69e98206e6f9f69187e7976195d0"
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let transaction_bytes = bytes("transaction_borsh_hex");
        let transaction = decode_truthcoin_transaction(&transaction_bytes).unwrap();
        let DecodedTruthcoinTransactionDataV1::Trade(trade) = transaction.data.as_ref().unwrap()
        else {
            panic!("native vector must contain one trade")
        };
        assert_eq!(trade.shares, 25_000);
        assert_eq!(trade.outcome_index, 0);
        assert_eq!(
            hex::encode(blake3::hash(&transaction_bytes).as_bytes()),
            vector["transaction_id"].as_str().unwrap()
        );

        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let market_id: [u8; 6] = hex::decode(vector["market_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: bytes("coinbase_borsh_hex"),
                transactions_borsh: vec![transaction_bytes],
                authorizations_borsh: bytes("authorizations_borsh_hex"),
                actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let total_utxo_value = |store: &CanonicalStateStoreV1| {
            store
                .entries(TruthcoinDatabaseId::Utxos.as_u8())
                .unwrap()
                .try_fold(0_u64, |sum, (_, value)| {
                    sum.checked_add(truthcoin_filled_bitcoin_value(
                        &decode_truthcoin_filled_output(value)?,
                    )?)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)
                })
                .unwrap()
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let parent_total = total_utxo_value(&store);
        let prior_market_bytes = store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
            .unwrap()
            .unwrap()
            .to_vec();
        let prior_market = decode_truthcoin_market(&prior_market_bytes).unwrap();
        assert_eq!(
            quote_truthcoin_trade(&prior_market_bytes, 0, 25_000).unwrap(),
            TruthcoinTradeQuoteV1 {
                base_sats: 12_506,
                trading_fee_sats: 1_000,
                trader_value_sats: 13_506,
            }
        );

        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );
        let successor_market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(successor_market.shares, vec![25_000, 0]);
        assert_eq!(successor_market.version, prior_market.version + 1);
        assert_eq!(successor_market.last_updated_height, 2);
        let account = decode_truthcoin_share_account(
            store
                .get(TruthcoinDatabaseId::ShareAccounts.as_u8(), &trade.trader)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(account.positions.get(&(market_id, 0)), Some(&25_000));
        assert_eq!(account.last_updated_height, 2);
        for input_key in &transaction.input_keys {
            assert!(store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), input_key)
                .unwrap()
                .is_none());
            assert!(store
                .get(TruthcoinDatabaseId::Stxos.as_u8(), input_key)
                .unwrap()
                .is_some());
        }
        assert_eq!(
            total_utxo_value(&store),
            parent_total - vector["expected_miner_fee_sats"].as_u64().unwrap()
        );

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);
    }

    #[test]
    fn complete_standard_sell_matches_patched_native_and_conserves_value() {
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-standard-sell-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            "af7c308da82c9d5b57e17374dc3570eec57abf2d05e91821001b479c03f3b87d"
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let transaction_bytes = bytes("transaction_borsh_hex");
        let transaction = decode_truthcoin_transaction(&transaction_bytes).unwrap();
        let DecodedTruthcoinTransactionDataV1::Trade(trade) = transaction.data.as_ref().unwrap()
        else {
            panic!("native vector must contain one trade")
        };
        assert_eq!(trade.shares, -12_500);
        assert_eq!(trade.outcome_index, 0);
        assert_eq!(
            hex::encode(blake3::hash(&transaction_bytes).as_bytes()),
            vector["transaction_id"].as_str().unwrap()
        );

        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let market_id: [u8; 6] = hex::decode(vector["market_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: bytes("coinbase_borsh_hex"),
                transactions_borsh: vec![transaction_bytes],
                authorizations_borsh: bytes("authorizations_borsh_hex"),
                actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let total_utxo_value = |store: &CanonicalStateStoreV1| {
            store
                .entries(TruthcoinDatabaseId::Utxos.as_u8())
                .unwrap()
                .try_fold(0_u64, |sum, (_, value)| {
                    sum.checked_add(truthcoin_filled_bitcoin_value(
                        &decode_truthcoin_filled_output(value)?,
                    )?)
                    .ok_or(ReplayError::InvalidTruthcoinTrade)
                })
                .unwrap()
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let parent_total = total_utxo_value(&store);
        let prior_market_bytes = store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
            .unwrap()
            .unwrap()
            .to_vec();
        let prior_market = decode_truthcoin_market(&prior_market_bytes).unwrap();
        assert_eq!(prior_market.shares, vec![25_000, 0]);
        assert_eq!(
            quote_truthcoin_trade(&prior_market_bytes, 0, -12_500).unwrap(),
            TruthcoinTradeQuoteV1 {
                base_sats: 6_254,
                trading_fee_sats: 1_000,
                trader_value_sats: 5_254,
            }
        );

        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );
        let successor_market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(successor_market.shares, vec![12_500, 0]);
        assert_eq!(successor_market.version, prior_market.version + 1);
        assert_eq!(successor_market.last_updated_height, 3);
        let account = decode_truthcoin_share_account(
            store
                .get(TruthcoinDatabaseId::ShareAccounts.as_u8(), &trade.trader)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(account.positions.get(&(market_id, 0)), Some(&12_500));
        assert_eq!(account.last_updated_height, 3);
        for input_key in &transaction.input_keys {
            assert!(store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), input_key)
                .unwrap()
                .is_none());
            assert!(store
                .get(TruthcoinDatabaseId::Stxos.as_u8(), input_key)
                .unwrap()
                .is_some());
        }
        assert_eq!(
            total_utxo_value(&store),
            parent_total - vector["expected_miner_fee_sats"].as_u64().unwrap()
        );

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);
    }

    #[test]
    fn standard_market_buy_sell_history_composes_and_reorgs_exactly() {
        let vectors = [
            serde_json::from_slice::<serde_json::Value>(include_bytes!(
                "../test-vectors/patched-native-standard-market-v1.json"
            ))
            .unwrap(),
            serde_json::from_slice::<serde_json::Value>(include_bytes!(
                "../test-vectors/patched-native-standard-buy-v1.json"
            ))
            .unwrap(),
            serde_json::from_slice::<serde_json::Value>(include_bytes!(
                "../test-vectors/patched-native-standard-sell-v1.json"
            ))
            .unwrap(),
        ];
        let mut blocks = Vec::new();
        let mut contexts = Vec::new();
        for vector in &vectors {
            let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
            let height = vector["height"].as_u64().unwrap();
            let timestamp = vector["timestamp"].as_u64().unwrap();
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height,
                bmm_main_height: height,
                header_borsh: bytes("header_borsh_hex"),
                body: TruthcoinBodyV1 {
                    coinbase_borsh: bytes("coinbase_borsh_hex"),
                    transactions_borsh: vec![bytes("transaction_borsh_hex")],
                    authorizations_borsh: bytes("authorizations_borsh_hex"),
                    actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
                },
            };
            contexts.push(CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            });
            blocks.push(block);
        }

        let initial = hex::decode(vectors[0]["parent_checkpoint_hex"].as_str().unwrap()).unwrap();
        let mut store = CanonicalStateStoreV1::import(&initial).unwrap();
        let mut undos = Vec::new();
        for index in 0..blocks.len() {
            let embedded_parent =
                hex::decode(vectors[index]["parent_checkpoint_hex"].as_str().unwrap()).unwrap();
            assert_eq!(store.export().unwrap(), embedded_parent);
            undos.push(
                apply_truthcoin_block_transition(&mut store, &blocks[index], contexts[index])
                    .unwrap(),
            );
            assert_eq!(
                hex::encode(Sha256::digest(store.export().unwrap())),
                vectors[index]["native_successor_sha256"].as_str().unwrap()
            );

            if index == 0 {
                let before_skipped_buy = store.export().unwrap();
                assert!(
                    apply_truthcoin_block_transition(&mut store, &blocks[2], contexts[2]).is_err()
                );
                assert_eq!(store.export().unwrap(), before_skipped_buy);
            }
        }
        let final_successor = store.export().unwrap();

        for undo in undos.iter().rev() {
            revert_truthcoin_block_transition(&mut store, undo).unwrap();
        }
        assert_eq!(store.export().unwrap(), initial);
        for (block, context) in blocks.iter().zip(contexts) {
            apply_truthcoin_block_transition(&mut store, block, context).unwrap();
        }
        assert_eq!(store.export().unwrap(), final_successor);
    }

    #[test]
    fn complete_voted_settlement_block_matches_patched_native_checkpoint() {
        #[cfg(not(feature = "truthcoin-alpha-one-day-period"))]
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-voted-settlement-v1.json");
        #[cfg(feature = "truthcoin-alpha-one-day-period")]
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-alpha-voted-settlement-v1.json");
        let expected_digest = if cfg!(feature = "truthcoin-alpha-one-day-period") {
            "1bd982d431d8c1f2054c73f1ee88abb669dc47e9dad6a61d2d55121b80874030"
        } else {
            "018afc82788fa9c3f764b79f97d5d45c51aa3a7e1e4f8c1731ddfd1e6abb03b7"
        };
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            expected_digest
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: 0_u32.to_le_bytes().to_vec(),
                transactions_borsh: Vec::new(),
                authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
                actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );

        let market_id = hex::decode(vector["market_id"].as_str().unwrap()).unwrap();
        let market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(market.market_state, TruthcoinMarketStateCodecV1::Settled);
        assert_eq!(market.final_prices.len(), market.shares.len());
        assert!(market.final_prices.iter().all(|price| price.is_finite()));
        assert!(store
            .get(
                TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                &[market_id.as_slice(), &[0]].concat(),
            )
            .unwrap()
            .is_none());
        assert!(store
            .get(
                TruthcoinDatabaseId::SettlementUndo.as_u8(),
                &u32::try_from(height).unwrap().to_le_bytes(),
            )
            .unwrap()
            .is_some());
        assert!(store
            .get(
                TruthcoinDatabaseId::ConsensusUndo.as_u8(),
                &u32::try_from(height).unwrap().to_le_bytes(),
            )
            .unwrap()
            .is_some());

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);
    }

    #[test]
    fn complete_native_fork_lifecycle_switches_and_replays_exact_branches() {
        #[cfg(not(feature = "truthcoin-alpha-one-day-period"))]
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-fork-lifecycle-v1.json");
        #[cfg(feature = "truthcoin-alpha-one-day-period")]
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-alpha-fork-lifecycle-v1.json");
        let expected_digest = if cfg!(feature = "truthcoin-alpha-one-day-period") {
            "e18fed32a9e255086f0e91b5a77c625d7d6f34ee2ae366dc508f80bad14ad940"
        } else {
            "273716d88a9ca862a80a15fd838561647866a06032ac7d1a05fb12a834ae2d17"
        };
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            expected_digest
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let parent = hex::decode(vector["parent_checkpoint_hex"].as_str().unwrap()).unwrap();
        let mut successor_hashes = Vec::new();

        for branch_name in ["a", "b"] {
            let branch = &vector["branches"][branch_name];
            let mut store = CanonicalStateStoreV1::import(&parent).unwrap();
            let mut blocks = Vec::new();
            let mut contexts = Vec::new();
            let mut undos = Vec::new();
            for encoded in branch["blocks"].as_array().unwrap() {
                let height = encoded["height"].as_u64().unwrap();
                let timestamp = encoded["timestamp"].as_u64().unwrap();
                let block = TruthcoinBlockV1 {
                    version: TruthcoinBlockV1::VERSION,
                    height,
                    bmm_main_height: height,
                    header_borsh: hex::decode(encoded["header_borsh_hex"].as_str().unwrap())
                        .unwrap(),
                    body: TruthcoinBodyV1 {
                        coinbase_borsh: hex::decode(
                            encoded["coinbase_borsh_hex"].as_str().unwrap(),
                        )
                        .unwrap(),
                        transactions_borsh: Vec::new(),
                        authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
                        actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
                    },
                };
                let context = CanonicalBlockContextV1 {
                    sidechain_block_hash: block.block_hash(),
                    sidechain_height: height,
                    bmm_main_block_hash: [1; 32],
                    bmm_main_height: height,
                    bmm_main_timestamp: timestamp,
                    bmm_main_mtp: timestamp,
                };
                undos.push(apply_truthcoin_block_transition(&mut store, &block, context).unwrap());
                blocks.push(block);
                contexts.push(context);
            }
            let successor = store.export().unwrap();
            let successor_hash = hex::encode(Sha256::digest(&successor));
            assert_eq!(
                successor_hash,
                branch["native_successor_sha256"].as_str().unwrap()
            );
            successor_hashes.push(successor_hash);

            for undo in undos.iter().rev() {
                revert_truthcoin_block_transition(&mut store, undo).unwrap();
            }
            assert_eq!(store.export().unwrap(), parent);
            for (block, context) in blocks.iter().zip(contexts) {
                apply_truthcoin_block_transition(&mut store, block, context).unwrap();
            }
            assert_eq!(store.export().unwrap(), successor);
        }
        assert_ne!(successor_hashes[0], successor_hashes[1]);
    }

    #[test]
    fn complete_native_slippage_skip_commits_index_without_spending_or_trading() {
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-slippage-skip-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            "4c0fdafbebfe4102b798a371cd4df14ce36a3104986cf2563a35443695c8c303"
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let transaction_bytes = bytes("transaction_borsh_hex");
        let transaction = decode_truthcoin_transaction(&transaction_bytes).unwrap();
        let input_key = transaction.input_keys[0];
        let market_id = hex::decode(vector["market_id"].as_str().unwrap()).unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: bytes("coinbase_borsh_hex"),
                transactions_borsh: vec![transaction_bytes],
                authorizations_borsh: bytes("authorizations_borsh_hex"),
                actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let prior_input = store
            .get(TruthcoinDatabaseId::Utxos.as_u8(), &input_key)
            .unwrap()
            .unwrap()
            .to_vec();
        let prior_market = store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
            .unwrap()
            .unwrap()
            .to_vec();

        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &input_key)
                .unwrap(),
            Some(prior_input.as_slice())
        );
        assert!(store
            .get(TruthcoinDatabaseId::Stxos.as_u8(), &input_key)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap(),
            Some(prior_market.as_slice())
        );
        let height_key = u32::try_from(height).unwrap().to_le_bytes();
        let skipped: Vec<u32> = bincode::deserialize(
            store
                .get(
                    TruthcoinDatabaseId::SkippedTxIndicesUndo.as_u8(),
                    &height_key,
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            skipped,
            vec![vector["skipped_index"].as_u64().unwrap() as u32]
        );

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);

        // A skipped trade pays no fixed miner fee. The live Alpha candidates
        // that first carried the ECX/USDD market claimed a 1,000-sat coinbase
        // anyway; pinned upstream rejects those blocks as NotEnoughFees.
        let mut excessive_coinbase = block.clone();
        let mut coinbase_borsh = 1_u32.to_le_bytes().to_vec();
        coinbase_borsh.extend_from_slice(&[0x42; 20]);
        coinbase_borsh.push(0); // Bitcoin output content
        coinbase_borsh.extend_from_slice(&1_000_u64.to_le_bytes());
        coinbase_borsh.extend_from_slice(&0_u32.to_le_bytes()); // empty output memo
        excessive_coinbase.body.coinbase_borsh = coinbase_borsh;
        excessive_coinbase.header_borsh[..32]
            .copy_from_slice(&truthcoin_body_merkle_root(&excessive_coinbase.body));
        let excessive_context = CanonicalBlockContextV1 {
            sidechain_block_hash: excessive_coinbase.block_hash(),
            ..context
        };
        let mut rejected = CanonicalStateStoreV1::import(&parent).unwrap();
        let rejected_parent = rejected.export().unwrap();
        assert_eq!(
            apply_truthcoin_block_transition(&mut rejected, &excessive_coinbase, excessive_context,),
            Err(ReplayError::InvalidTruthcoinBlockFees)
        );
        assert_eq!(rejected.export().unwrap(), rejected_parent);
    }

    #[test]
    fn complete_native_mixed_amplify_then_trade_is_atomic_and_ordered() {
        const VECTOR: &[u8] =
            include_bytes!("../test-vectors/patched-native-mixed-amplify-trade-v1.json");
        assert_eq!(
            hex::encode(Sha256::digest(VECTOR)),
            "4469c7421e0c4baa954cd10713067e41670c0fd7527feec6f15350e190c49f92"
        );
        let vector: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector["source_git_commit"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1)
        );
        assert_eq!(
            vector["source_patch_manifest_sha256"].as_str().unwrap(),
            hex::encode(TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256)
        );
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let transaction_bytes: Vec<Vec<u8>> = vector["transactions_borsh_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| hex::decode(value.as_str().unwrap()).unwrap())
            .collect();
        let input_keys: Vec<[u8; 37]> = transaction_bytes
            .iter()
            .map(|bytes| decode_truthcoin_transaction(bytes).unwrap().input_keys[0])
            .collect();
        assert_ne!(input_keys[0], input_keys[1]);
        let height = vector["height"].as_u64().unwrap();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let market_id = hex::decode(vector["market_id"].as_str().unwrap()).unwrap();
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height,
            bmm_main_height: height,
            header_borsh: bytes("header_borsh_hex"),
            body: TruthcoinBodyV1 {
                coinbase_borsh: bytes("coinbase_borsh_hex"),
                transactions_borsh: transaction_bytes,
                authorizations_borsh: bytes("authorizations_borsh_hex"),
                actor_proofs_borsh: bytes("actor_proofs_borsh_hex"),
            },
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: height,
            bmm_main_block_hash: [1; 32],
            bmm_main_height: height,
            bmm_main_timestamp: timestamp,
            bmm_main_mtp: timestamp,
        };
        let mut store = CanonicalStateStoreV1::import(&bytes("parent_checkpoint_hex")).unwrap();
        let parent = store.export().unwrap();
        let prior_market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        let successor = store.export().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&successor)),
            vector["native_successor_sha256"].as_str().unwrap()
        );
        let market = decode_truthcoin_market(
            store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            market.liquidity_base_sats,
            vector["expected_liquidity_base_sats"].as_u64().unwrap()
        );
        assert_eq!(market.shares, vec![25_000, 0]);
        assert_eq!(market.version, prior_market.version + 1);
        assert_eq!(market.last_updated_height, u32::try_from(height).unwrap());
        for input_key in &input_keys {
            assert!(store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), input_key)
                .unwrap()
                .is_none());
            assert!(store
                .get(TruthcoinDatabaseId::Stxos.as_u8(), input_key)
                .unwrap()
                .is_some());
        }

        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(store.export().unwrap(), successor);
    }

    #[derive(Debug, Clone)]
    struct Fixture {
        input: ReplayInputV1,
        state: StateMachineOutputV1,
        contexts: Vec<CanonicalBlockContextV1>,
    }

    #[derive(Debug, Clone)]
    struct DeterministicStateMachine {
        output: StateMachineOutputV1,
        expected_contexts: Vec<CanonicalBlockContextV1>,
    }

    impl Truthcoin017StateMachine for DeterministicStateMachine {
        fn replay(
            &self,
            _template: &TruthcoinMarketTemplateCommitmentV1,
            canonical_blocks: &[TruthcoinBlockV1],
            canonical_contexts: &[CanonicalBlockContextV1],
        ) -> Result<StateMachineOutputV1, ReplayError> {
            if canonical_contexts != self.expected_contexts
                || canonical_blocks.len() != canonical_contexts.len()
                || canonical_blocks
                    .iter()
                    .zip(canonical_contexts)
                    .any(|(block, context)| {
                        block.block_hash() != context.sidechain_block_hash
                            || block.height != context.sidechain_height
                            || block.bmm_main_height != context.bmm_main_height
                    })
            {
                return Err(ReplayError::InvalidStateMachineOutput);
            }
            Ok(self.output.clone())
        }
    }

    #[test]
    fn truthcoin_header_and_body_commitment_match_upstream_codec() {
        let body = TruthcoinBodyV1 {
            coinbase_borsh: vec![1, 2, 3],
            transactions_borsh: vec![vec![4, 5], vec![6]],
            authorizations_borsh: vec![7],
            actor_proofs_borsh: vec![8],
        };
        let root = truthcoin_body_merkle_root(&body);
        let mut genesis = root.to_vec();
        genesis.push(0);
        genesis.extend_from_slice(&[9; 32]);
        assert_eq!(
            parse_truthcoin_header(&genesis).unwrap(),
            (root, None, [9; 32])
        );

        let hash = *blake3::hash(&genesis).as_bytes();
        let mut child = root.to_vec();
        child.push(1);
        child.extend_from_slice(&hash);
        child.extend_from_slice(&[10; 32]);
        assert_eq!(
            parse_truthcoin_header(&child).unwrap(),
            (root, Some(hash), [10; 32])
        );
        child.push(0);
        assert_eq!(
            parse_truthcoin_header(&child),
            Err(ReplayError::InvalidTruthcoinHeaderEncoding)
        );
    }

    #[test]
    fn genesis_first_coinbase_recipient_receives_pinned_initial_reputation() {
        let recipient = [0xa9; 20];
        let body = truthcoin_body(0xa9);
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 0,
            bmm_main_height: 2_022,
            header_borsh: truthcoin_header(&body, None, [0x31; 32]),
            body,
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: 0,
            bmm_main_block_hash: [0x32; 32],
            bmm_main_height: 2_022,
            bmm_main_timestamp: 1_801_874_000,
            bmm_main_mtp: 1_801_873_000,
        };
        let mut store = CanonicalStateStoreV1::new();
        let prior = store.export().unwrap();
        let undo = apply_truthcoin_block_transition(&mut store, &block, context).unwrap();
        assert_eq!(get_truthcoin_reputation(&store, &recipient).unwrap(), 1.0);
        revert_truthcoin_block_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), prior);
    }

    #[test]
    fn exact_m7_parser_rejects_duplicate_truthcoin_accepts() {
        let commitment = [0x42; 32];
        let script = m7_script(commitment);
        let transaction = coinbase_with_outputs(CHECKPOINT_HEIGHT, vec![script.clone()]);
        assert_eq!(
            extract_truthcoin_m7(&transaction).unwrap(),
            Some(commitment)
        );
        let duplicate = coinbase_with_outputs(CHECKPOINT_HEIGHT, vec![script.clone(), script]);
        assert_eq!(
            extract_truthcoin_m7(&duplicate),
            Err(ReplayError::DuplicateOrZeroM7)
        );
    }

    #[test]
    fn coinbase_merkle_branch_authenticates_index_zero_without_a_false_count_claim() {
        let coinbase = coinbase_with_outputs(CHECKPOINT_HEIGHT, Vec::new());
        let sibling = sha256d::Hash::hash(b"second transaction");
        let mut pair = [0_u8; 64];
        pair[..32].copy_from_slice(coinbase.compute_txid().to_raw_hash().as_byte_array());
        pair[32..].copy_from_slice(sibling.as_byte_array());
        let merkle_root = sha256d::Hash::hash(&pair);
        let header = BitcoinHeader {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array(merkle_root.to_byte_array()),
            time: 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let inclusion = CoinbaseInclusionV1 {
            version: 1,
            height: 0,
            coinbase_transaction: serialize(&coinbase),
            merkle_siblings: vec![sibling.to_byte_array()],
        };
        assert!(verify_coinbase_merkle_branch(&coinbase, &inclusion, &header).is_ok());

        let mut wrong_sibling = inclusion.clone();
        wrong_sibling.merkle_siblings[0][0] ^= 1;
        assert_eq!(
            verify_coinbase_merkle_branch(&coinbase, &wrong_sibling, &header),
            Err(ReplayError::InvalidCoinbaseMerkleProof)
        );
        let mut redundant_level = inclusion;
        redundant_level
            .merkle_siblings
            .push(merkle_root.to_byte_array());
        assert_eq!(
            verify_coinbase_merkle_branch(&coinbase, &redundant_level, &header),
            Err(ReplayError::InvalidCoinbaseMerkleProof)
        );
    }

    #[test]
    fn complete_bitcoin_transaction_lists_are_merkle_bound_and_omission_resistant() {
        let fixture = fixture();
        assert!(verify_replay_structure(&fixture.input).is_ok());

        let mut missing = fixture.input.clone();
        missing.mainchain_block_transactions[0].transactions.clear();
        assert_eq!(verify_replay_structure(&missing), Err(ReplayError::Bounds));

        let mut substituted = fixture.input.clone();
        substituted.mainchain_block_transactions[0].transactions[0][0] ^= 1;
        assert_eq!(
            verify_replay_structure(&substituted),
            Err(ReplayError::InvalidBitcoinBlockTransactions)
        );

        let mut wrong_height = fixture.input;
        wrong_height.mainchain_block_transactions[0].height += 1;
        assert_eq!(
            verify_replay_structure(&wrong_height),
            Err(ReplayError::InvalidBitcoinBlockTransactions)
        );
    }

    fn shift_declared_replay_heights(input: &mut ReplayInputV1, checkpoint_height: u64) {
        let delta =
            checkpoint_height as i128 - input.authentication.bitcoin_checkpoint_height as i128;
        let shifted = |height: u64| -> u64 { u64::try_from(height as i128 + delta).unwrap() };
        input.authentication.bitcoin_checkpoint_height = checkpoint_height;
        input.parent.height = shifted(input.parent.height);
        for header in &mut input.mainchain_headers {
            header.height = shifted(header.height);
        }
        for inclusion in &mut input.coinbase_inclusions {
            inclusion.height = shifted(inclusion.height);
        }
        for block in &mut input.mainchain_block_transactions {
            block.height = shifted(block.height);
        }
        for block in &mut input.sidechain_blocks {
            block.bmm_main_height = shifted(block.bmm_main_height);
        }
    }

    #[test]
    fn pinned_mid_epoch_checkpoint_is_accepted_before_adjustment() {
        let mut input = fixture().input;
        shift_declared_replay_heights(&mut input, CHECKPOINT_HEIGHT + 17);
        assert!(verify_replay_structure(&input).is_ok());
    }

    #[test]
    fn pinned_mid_epoch_checkpoint_cannot_cross_unproven_adjustment() {
        let mut input = fixture().input;
        shift_declared_replay_heights(&mut input, 2 * BITCOIN_DIFFICULTY_INTERVAL - 1);
        assert_eq!(
            verify_replay_structure(&input),
            Err(ReplayError::MissingDifficultyContext)
        );
    }

    #[test]
    fn trusted_start_branch_verification_preserves_bmm_coverage() {
        let mut input = fixture().input;
        let start = input.sidechain_blocks.remove(0);
        let (mtp, headers) = verify_mainchain_headers(&input).unwrap();
        let commitments = verify_coinbase_inclusions(&input, &headers).unwrap();
        let boundary = Some((start.block_hash(), start.height));
        let set = verify_sidechain_set_from_start(
            &input, &mtp, &headers, &commitments, boundary,
        ).unwrap();
        let tip = ranked_sidechain_tips(&set)[0];
        let (blocks, contexts) = sidechain_branch_for_tip(&input, &set, tip).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_hash(), input.sidechain_blocks[0].block_hash());
        assert_eq!(contexts[0].sidechain_height, start.height + 1);
        // The same suffix cannot authenticate itself as a genesis replay.
        assert!(verify_sidechain_set(&input, &mtp, &headers, &commitments).is_err());
        assert!(verify_sidechain_set_from_start(
            &input, &mtp, &headers, &commitments, Some(([0x99; 32], 0)),
        ).is_err());
        assert!(verify_sidechain_set_from_start(
            &input, &mtp, &headers, &commitments, Some((start.block_hash(), 7)),
        ).is_err());
        let mut omitted = input.clone();
        omitted.sidechain_blocks.clear();
        assert!(verify_sidechain_set_from_start(
            &omitted, &mtp, &headers, &commitments, boundary,
        ).is_err());
        let mut extra = input.clone();
        extra.sidechain_blocks.push(start);
        assert!(verify_sidechain_set_from_start(
            &extra, &mtp, &headers, &commitments, boundary,
        ).is_err());
    }

    #[test]
    fn native_happy_path_authenticates_bitcoin_bmm_bodies_and_timestamps() {
        let fixture = fixture();
        let structure = verify_replay_structure(&fixture.input).unwrap();
        assert_eq!(structure.bitcoin_tip_hash, fixture.input.parent.block_hash);
        assert_eq!(structure.bitcoin_tip_height, CHECKPOINT_HEIGHT + 3);
        assert_eq!(structure.sidechain_tip_height, 1);
        assert_eq!(structure.source_confirmations, 3);
        assert_ne!(structure.canonical_chain_root, [0; 32]);
        assert_ne!(structure.replay_transcript_root, [0; 32]);
        assert_eq!(structure.canonical_block_contexts, fixture.contexts);
        assert_eq!(
            structure.canonical_block_contexts[1].bmm_main_timestamp,
            u64::from(CONTEXT_START_TIME + 11)
        );
        assert_eq!(
            structure.canonical_block_contexts[1].bmm_main_mtp,
            u64::from(CONTEXT_START_TIME + 6)
        );

        let output = execute_replay_with_state_machine(
            &fixture.input,
            &DeterministicStateMachine {
                output: fixture.state,
                expected_contexts: fixture.contexts,
            },
        )
        .unwrap();
        assert_eq!(output.public_values.anchor_decision_id_native, [0x81, 0, 1]);
        assert_eq!(
            output.public_values.lmsr_market_id_native,
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            output.public_values.replay_transcript_root,
            structure.replay_transcript_root
        );
    }

    #[test]
    fn parent_hash_and_mtp_are_exact() {
        let fixture = fixture();
        let mut wrong_hash = fixture.input.clone();
        wrong_hash.parent.block_hash[0] ^= 1;
        assert_eq!(
            verify_replay_structure(&wrong_hash),
            Err(ReplayError::WrongParentContext)
        );

        let mut wrong_mtp = fixture.input;
        wrong_mtp.parent.median_time_past += 1;
        assert_eq!(
            verify_replay_structure(&wrong_mtp),
            Err(ReplayError::WrongParentContext)
        );
    }

    #[test]
    fn missing_and_duplicate_m7_or_body_fail_closed() {
        let fixture = fixture();

        let mut missing_m7 = fixture.input.clone();
        replace_coinbase_and_remine(
            &mut missing_m7,
            1,
            coinbase_with_outputs(CHECKPOINT_HEIGHT + 1, Vec::new()),
        );
        assert_eq!(
            verify_replay_structure(&missing_m7),
            Err(ReplayError::UncommittedSidechainBlock)
        );

        let mut duplicate_m7 = fixture.input.clone();
        let script = m7_script([0x42; 32]);
        replace_coinbase_and_remine(
            &mut duplicate_m7,
            2,
            coinbase_with_outputs(CHECKPOINT_HEIGHT + 2, vec![script.clone(), script]),
        );
        assert_eq!(
            verify_replay_structure(&duplicate_m7),
            Err(ReplayError::DuplicateOrZeroM7)
        );

        let mut missing_body = fixture.input.clone();
        missing_body.sidechain_blocks.pop();
        assert_eq!(
            verify_replay_structure(&missing_body),
            Err(ReplayError::MissingCommittedSidechainBlock)
        );

        let mut duplicate_body = fixture.input;
        duplicate_body
            .sidechain_blocks
            .push(duplicate_body.sidechain_blocks[1].clone());
        assert_eq!(
            verify_replay_structure(&duplicate_body),
            Err(ReplayError::UncommittedSidechainBlock)
        );
    }

    #[test]
    fn body_root_is_authenticated_and_complete_failed_bmm_candidates_are_ignored() {
        let fixture = fixture();

        let mut wrong_body = fixture.input.clone();
        wrong_body.sidechain_blocks[1]
            .body
            .coinbase_borsh
            .push(0xff);
        assert_eq!(
            verify_replay_structure(&wrong_body),
            Err(ReplayError::InvalidTruthcoinMerkleRoot)
        );

        let mut wrong_prev_main = fixture.input.clone();
        wrong_prev_main.sidechain_blocks[1].header_borsh[65] ^= 1;
        recommit_sidechain_block(&mut wrong_prev_main, 1);
        let ignored_wrong_parent = verify_replay_structure(&wrong_prev_main).unwrap();
        assert_eq!(ignored_wrong_parent.sidechain_tip_height, 0);

        let mut wrong_side_ancestry = fixture.input;
        wrong_side_ancestry.sidechain_blocks[1].header_borsh[33] ^= 1;
        recommit_sidechain_block(&mut wrong_side_ancestry, 1);
        let ignored_wrong_ancestry = verify_replay_structure(&wrong_side_ancestry).unwrap();
        assert_eq!(ignored_wrong_ancestry.sidechain_tip_height, 0);
    }

    #[test]
    fn shared_bitcoin_lineage_fork_choice_matches_pinned_upstream_rule() {
        let mut input = fixture().input;
        let genesis = input.sidechain_blocks[0].clone();
        let original_child = input.sidechain_blocks[1].clone();
        let header_one: BitcoinHeader =
            deserialize(&input.mainchain_headers[1].consensus_header).unwrap();
        let fork_body = truthcoin_body(0x30);
        let fork_child = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 1,
            bmm_main_height: CHECKPOINT_HEIGHT + 2,
            header_borsh: truthcoin_header(
                &fork_body,
                Some(genesis.block_hash()),
                header_one.block_hash().to_byte_array(),
            ),
            body: fork_body,
        };
        replace_coinbase_and_remine(
            &mut input,
            2,
            coinbase_with_outputs(
                CHECKPOINT_HEIGHT + 2,
                vec![m7_script(fork_child.block_hash())],
            ),
        );
        input.sidechain_blocks.push(fork_child.clone());

        // Equal-height competitors on one Bitcoin lineage prefer the block
        // whose best BMM verification has lower work (the earlier block).
        let equal_height = verify_replay_structure(&input).unwrap();
        assert_eq!(
            equal_height
                .canonical_sidechain_blocks
                .iter()
                .map(TruthcoinBlockV1::block_hash)
                .collect::<Vec<_>>(),
            vec![genesis.block_hash(), original_child.block_hash()]
        );

        // A higher sidechain branch wins even though its BMM verification is
        // later on the same authenticated Bitcoin lineage.
        let header_two: BitcoinHeader =
            deserialize(&input.mainchain_headers[2].consensus_header).unwrap();
        let grandchild_body = truthcoin_body(0x40);
        let grandchild = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 2,
            bmm_main_height: CHECKPOINT_HEIGHT + 3,
            header_borsh: truthcoin_header(
                &grandchild_body,
                Some(fork_child.block_hash()),
                header_two.block_hash().to_byte_array(),
            ),
            body: grandchild_body,
        };
        replace_coinbase_and_remine(
            &mut input,
            3,
            coinbase_with_outputs(
                CHECKPOINT_HEIGHT + 3,
                vec![m7_script(grandchild.block_hash())],
            ),
        );
        input.sidechain_blocks.push(grandchild.clone());
        input.authentication.minimum_bitcoin_confirmations = 1;
        let higher_branch = verify_replay_structure(&input).unwrap();
        assert_eq!(
            higher_branch
                .canonical_sidechain_blocks
                .iter()
                .map(TruthcoinBlockV1::block_hash)
                .collect::<Vec<_>>(),
            vec![
                genesis.block_hash(),
                fork_child.block_hash(),
                grandchild.block_hash()
            ]
        );
        assert_eq!(higher_branch.source_confirmations, 1);
    }

    #[test]
    fn production_fork_choice_skips_higher_branch_with_invalid_block_fees() {
        let mut input = fixture().input;
        let genesis = input.sidechain_blocks[0].clone();
        let canonical_child = input.sidechain_blocks[1].clone();
        let header_one: BitcoinHeader =
            deserialize(&input.mainchain_headers[1].consensus_header).unwrap();

        let mut invalid_body = truthcoin_body(0x30);
        // The synthetic body has no fee-paying transaction, so changing its
        // coinbase from zero to one satoshi makes the transition invalid while
        // preserving a completely authenticated BMM candidate.
        invalid_body.coinbase_borsh[25..33].copy_from_slice(&1_u64.to_le_bytes());
        let invalid_child = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 1,
            bmm_main_height: CHECKPOINT_HEIGHT + 2,
            header_borsh: truthcoin_header(
                &invalid_body,
                Some(genesis.block_hash()),
                header_one.block_hash().to_byte_array(),
            ),
            body: invalid_body,
        };
        replace_coinbase_and_remine(
            &mut input,
            2,
            coinbase_with_outputs(
                CHECKPOINT_HEIGHT + 2,
                vec![m7_script(invalid_child.block_hash())],
            ),
        );
        input.sidechain_blocks.push(invalid_child.clone());

        let header_two: BitcoinHeader =
            deserialize(&input.mainchain_headers[2].consensus_header).unwrap();
        let grandchild_body = truthcoin_body(0x40);
        let invalid_grandchild = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 2,
            bmm_main_height: CHECKPOINT_HEIGHT + 3,
            header_borsh: truthcoin_header(
                &grandchild_body,
                Some(invalid_child.block_hash()),
                header_two.block_hash().to_byte_array(),
            ),
            body: grandchild_body,
        };
        replace_coinbase_and_remine(
            &mut input,
            3,
            coinbase_with_outputs(
                CHECKPOINT_HEIGHT + 3,
                vec![m7_script(invalid_grandchild.block_hash())],
            ),
        );
        input.sidechain_blocks.push(invalid_grandchild.clone());
        input.authentication.minimum_bitcoin_confirmations = 1;

        let structural = verify_replay_structure(&input).unwrap();
        assert_eq!(
            structural.sidechain_tip_hash,
            invalid_grandchild.block_hash()
        );
        let production = verify_production_replay_structure(&input).unwrap();
        assert_eq!(production.sidechain_tip_hash, canonical_child.block_hash());
        assert_eq!(production.sidechain_tip_height, 1);
    }

    #[test]
    fn confirmation_floor_is_enforced() {
        let mut input = fixture().input;
        input.authentication.minimum_bitcoin_confirmations = 4;
        assert_eq!(
            verify_replay_structure(&input),
            Err(ReplayError::InsufficientConfirmations)
        );
    }

    #[test]
    fn raw_bmm_timestamp_and_mtp_are_distinct_and_transcript_bound() {
        let fixture = fixture();
        let original = verify_replay_structure(&fixture.input).unwrap();
        let mut changed = fixture.input;
        remine_from(&mut changed, 1, Some((1, CONTEXT_START_TIME + 12)));
        let changed = verify_replay_structure(&changed).unwrap();

        assert_ne!(
            original.canonical_block_contexts[1].bmm_main_timestamp,
            changed.canonical_block_contexts[1].bmm_main_timestamp
        );
        assert_eq!(
            original.canonical_block_contexts[1].bmm_main_mtp,
            changed.canonical_block_contexts[1].bmm_main_mtp
        );
        assert_ne!(
            original.replay_transcript_root,
            changed.replay_transcript_root
        );
    }

    #[test]
    fn candidate_selection_is_order_independent_and_cross_bound() {
        let fixture = fixture();
        let machine = DeterministicStateMachine {
            output: fixture.state.clone(),
            expected_contexts: fixture.contexts.clone(),
        };
        let selected = execute_replay_with_state_machine(&fixture.input, &machine).unwrap();

        let mut reversed_state = fixture.state.clone();
        reversed_state.anchors.reverse();
        reversed_state.markets.reverse();
        let reordered = execute_replay_with_state_machine(
            &fixture.input,
            &DeterministicStateMachine {
                output: reversed_state,
                expected_contexts: fixture.contexts.clone(),
            },
        )
        .unwrap();
        assert_eq!(selected.public_values_bytes, reordered.public_values_bytes);

        let mut duplicate = fixture.state.clone();
        duplicate.anchors.push(duplicate.anchors[0].clone());
        assert_eq!(
            execute_replay_with_state_machine(
                &fixture.input,
                &DeterministicStateMachine {
                    output: duplicate,
                    expected_contexts: fixture.contexts.clone(),
                }
            ),
            Err(ReplayError::DuplicateCandidate)
        );

        let mut wrong_native_period = fixture.state.clone();
        wrong_native_period.markets[0].snapshot.epoch += 1;
        assert_eq!(
            execute_replay_with_state_machine(
                &fixture.input,
                &DeterministicStateMachine {
                    output: wrong_native_period,
                    expected_contexts: fixture.contexts.clone(),
                }
            ),
            Err(ReplayError::InvalidStateMachineOutput)
        );

        let mut mismatched = fixture.state;
        mismatched.anchors[1].anchor.template_hash[0] ^= 1;
        assert_eq!(
            execute_replay_with_state_machine(
                &fixture.input,
                &DeterministicStateMachine {
                    output: mismatched,
                    expected_contexts: fixture.contexts,
                }
            ),
            Err(ReplayError::InvalidStateMachineOutput)
        );
    }

    #[test]
    fn state_machine_context_cannot_be_substituted_by_replay_input() {
        let fixture = fixture();
        let mut substituted = fixture.contexts;
        substituted[1].bmm_main_timestamp += 1;
        assert_eq!(
            execute_replay_with_state_machine(
                &fixture.input,
                &DeterministicStateMachine {
                    output: fixture.state,
                    expected_contexts: substituted,
                }
            ),
            Err(ReplayError::InvalidStateMachineOutput)
        );
    }

    #[test]
    fn unlinked_state_machine_is_an_absolute_gate() {
        assert_eq!(
            UnlinkedTruthcoin017StateMachine.replay(
                &TruthcoinMarketTemplateCommitmentV1 {
                    version: 1,
                    market_title_template: String::new(),
                    market_description_template: String::new(),
                    decision_header_template: String::new(),
                    decision_description_template: String::new(),
                    decision_tags: Vec::new(),
                    scalar_min_f64_bits: 0,
                    scalar_max_f64_bits: 0,
                    scalar_increment_f64_bits: 0,
                    minimum_liquidity_sats: 0,
                    trading_fee_ppm: 0,
                    tx_pow_hash_selector: 0,
                    tx_pow_ordering: 0,
                    tx_pow_difficulty: 0,
                },
                &[],
                &[]
            ),
            Err(ReplayError::StateMachineUnlinked)
        );
    }

    #[test]
    fn production_entrypoint_uses_linked_machine_and_still_fails_closed() {
        let fixture = fixture();
        assert_eq!(
            execute_production_replay(&fixture.input),
            Err(ReplayError::NoEligibleAnchor)
        );
    }

    #[test]
    fn aggregate_resource_budgets_are_exact_and_overflow_safe() {
        let mut bytes = ReplayResourceBudget::default();
        bytes.charge_bytes(MAX_REPLAY_EVIDENCE_BYTES).unwrap();
        assert_eq!(bytes.charge_bytes(1), Err(ReplayError::Bounds));

        let mut transactions = ReplayResourceBudget::default();
        transactions
            .charge_transactions(MAX_REPLAY_TRANSACTIONS)
            .unwrap();
        assert_eq!(
            transactions.charge_transactions(1),
            Err(ReplayError::Bounds)
        );

        let mut overflow = ReplayResourceBudget {
            evidence_bytes: usize::MAX,
            transactions: usize::MAX,
        };
        assert_eq!(overflow.charge_bytes(1), Err(ReplayError::Bounds));
        assert_eq!(overflow.charge_transactions(1), Err(ReplayError::Bounds));

        let mut excessive_tags = fixture().input;
        excessive_tags.market_template.decision_tags =
            vec![String::new(); MAX_MARKET_TEMPLATE_TAGS + 1];
        assert_eq!(
            verify_replay_structure(&excessive_tags),
            Err(ReplayError::Bounds)
        );
    }

    #[test]
    fn block_body_resource_limits_reject_oversized_consensus_witnesses() {
        let mut oversized_authorizations = fixture().input;
        let body = &mut oversized_authorizations.sidechain_blocks[0].body;
        body.authorizations_borsh = vec![0; MAX_AUTHORIZATION_BYTES_PER_BLOCK];
        body.actor_proofs_borsh = vec![0];
        assert_eq!(
            verify_replay_structure(&oversized_authorizations),
            Err(ReplayError::Bounds)
        );

        let mut oversized_transaction = fixture().input;
        oversized_transaction.sidechain_blocks[0]
            .body
            .transactions_borsh = vec![vec![0; MAX_TRUTHCOIN_TRANSACTION_BYTES + 1]];
        assert_eq!(
            verify_replay_structure(&oversized_transaction),
            Err(ReplayError::Bounds)
        );

        let mut excessive_transactions = fixture().input;
        excessive_transactions.sidechain_blocks[0]
            .body
            .transactions_borsh = vec![vec![0]; MAX_TRUTHCOIN_TRANSACTIONS_PER_BLOCK + 1];
        assert_eq!(
            verify_replay_structure(&excessive_transactions),
            Err(ReplayError::Bounds)
        );
    }

    #[test]
    fn split_authorization_envelopes_require_exact_upstream_borsh_shape() {
        let canonical = truthcoin_body(7);
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&canonical),
            Ok(())
        );

        let mut truncated_authorization = canonical.clone();
        truncated_authorization.authorizations_borsh = vec![1, 0, 0, 0];
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&truncated_authorization),
            Err(ReplayError::InvalidTruthcoinBodyEncoding)
        );

        let mut trailing_authorization = canonical.clone();
        trailing_authorization.authorizations_borsh.push(0);
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&trailing_authorization),
            Err(ReplayError::InvalidTruthcoinBodyEncoding)
        );

        let mut wrong_actor_count = canonical.clone();
        wrong_actor_count.actor_proofs_borsh = vec![0, 0, 0, 0];
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&wrong_actor_count),
            Err(ReplayError::InvalidTruthcoinBodyEncoding)
        );

        let mut invalid_option_tag = canonical;
        invalid_option_tag.actor_proofs_borsh[4] = 2;
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&invalid_option_tag),
            Err(ReplayError::InvalidTruthcoinBodyEncoding)
        );

        let mut unknown_outpoint = truthcoin_body(8);
        unknown_outpoint.transactions_borsh = vec![vec![1, 0, 0, 0, 5]];
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&unknown_outpoint),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );

        let mut noncanonical_market_funds_bool = truthcoin_body(9);
        noncanonical_market_funds_bool.transactions_borsh =
            vec![vec![1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]];
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&noncanonical_market_funds_bool),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );
    }

    #[test]
    fn sponsored_actor_proof_wire_matches_pinned_truthcoin_017() {
        // Emitted by patched upstream 0.17 from the native sponsored-ballot
        // lifecycle fixture. This freezes the real Borsh vector/option layout,
        // including one input authorization and one present actor proof.
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: vec![hex::decode(concat!(
                "01000000020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "0a0a0a0a0a0a0a0000000001000000aff5bcf424b85d1401490c652fe8659b",
                "644c8bfc0098801e000000000000000000000000000104bc6e2e8c9248d09392",
                "89a04aba58d763733c597201000000000000333333333333e33f01000000"
            ))
            .unwrap()],
            authorizations_borsh: hex::decode(concat!(
                "01000000b604e9ef41560aa10d8b4ea994ce7e9e8848784cc2e8be5f26ba665d",
                "acf7ddd8ab3e695ac22852ea663db9d550e654ca85951e12907ae1d8f9c6750",
                "02dbd1f91c3ec9b51210b90c7a9d2f90411a78959e7be626a92ca6fe920730b",
                "ee98c14c03"
            ))
            .unwrap(),
            actor_proofs_borsh: hex::decode(concat!(
                "010000000143f9e02c3d175fd6b0117127ff5fe780943a8a47e4aaeb61ea937d",
                "bb248cf6f8b6631ad63a5516bb0273e2cabe2df175cb55833d6636a8a6b9eb3",
                "97ed3e9dcb286af7605ea0e6507ca0a12ce9cc4fd0fc9714f81acd7c8103ca2",
                "978e09015a00"
            ))
            .unwrap(),
        };
        assert_eq!(validate_truthcoin_authorization_envelopes(&body), Ok(()));

        let input_key = hex::decode(
            "020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000",
        )
        .unwrap();
        let sponsor_utxo = hex::decode(
            "aff5bcf424b85d1401490c652fe8659b644c8bfc0000000080841e00000000000000000000000000",
        )
        .unwrap();
        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                input_key.clone(),
                sponsor_utxo.clone(),
            )
            .unwrap();
        assert_eq!(validate_truthcoin_utxo_ownership(&store, &body), Ok(()));

        let input_key_array: [u8; 37] = input_key.clone().try_into().unwrap();
        let sponsor_address: [u8; 20] = sponsor_utxo[..20].try_into().unwrap();
        store
            .put(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                truthcoin_address_index_key(sponsor_address, &input_key_array),
                Vec::new(),
            )
            .unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_base_utxo_transition(&mut store, &body).unwrap();
        let connected = store.export().unwrap();
        assert_ne!(connected, parent);
        assert!(store
            .get(TruthcoinDatabaseId::Utxos.as_u8(), &input_key_array)
            .unwrap()
            .is_none());
        assert!(store
            .get(TruthcoinDatabaseId::Stxos.as_u8(), &input_key_array)
            .unwrap()
            .is_some());
        let native_output_index_key = hex::decode(concat!(
            "aff5bcf424b85d1401490c652fe8659b644c8bfc0000000077ba0c45f5fccdfb",
            "9fe2f5dab744785b0c7a2d4cdaa71ac458a652e1b989fb5100000000"
        ))
        .unwrap();
        let native_output_key = hex::decode(
            "0077ba0c45f5fccdfb9fe2f5dab744785b0c7a2d4cdaa71ac458a652e1b989fb5100000000",
        )
        .unwrap();
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &native_output_key)
                .unwrap()
                .unwrap(),
            hex::decode(
                "aff5bcf424b85d1401490c652fe8659b644c8bfc0000000098801e00000000000000000000000000"
            )
            .unwrap()
        );
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Stxos.as_u8(), &input_key_array)
                .unwrap()
                .unwrap(),
            hex::decode(concat!(
                "aff5bcf424b85d1401490c652fe8659b644c8bfc0000000080841e0000000000",
                "00000000000000000000000077ba0c45f5fccdfb9fe2f5dab744785b0c7a2d4",
                "cdaa71ac458a652e1b989fb5100000000"
            ))
            .unwrap()
        );
        assert!(store
            .get(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                &native_output_index_key
            )
            .unwrap()
            .is_some());
        let mut corrupt_rollback = store.clone();
        corrupt_rollback
            .delete(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                &native_output_index_key,
            )
            .unwrap();
        let before_bad_rollback = corrupt_rollback.export().unwrap();
        assert_eq!(
            revert_truthcoin_base_utxo_transition(&mut corrupt_rollback, &undo),
            Err(ReplayError::InvalidTruthcoinUtxoIndex)
        );
        assert_eq!(corrupt_rollback.export().unwrap(), before_bad_rollback);
        revert_truthcoin_base_utxo_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        let replay_undo = apply_truthcoin_base_utxo_transition(&mut store, &body).unwrap();
        assert_eq!(store.export().unwrap(), connected);
        revert_truthcoin_base_utxo_transition(&mut store, &replay_undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);

        let mut missing_index_store = CanonicalStateStoreV1::new();
        missing_index_store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                input_key.clone(),
                sponsor_utxo.clone(),
            )
            .unwrap();
        let before_missing_index = missing_index_store.export().unwrap();
        assert_eq!(
            apply_truthcoin_base_utxo_transition(&mut missing_index_store, &body),
            Err(ReplayError::InvalidTruthcoinUtxoIndex)
        );
        assert_eq!(missing_index_store.export().unwrap(), before_missing_index);

        let empty_store = CanonicalStateStoreV1::new();
        assert_eq!(
            validate_truthcoin_utxo_ownership(&empty_store, &body),
            Err(ReplayError::MissingTruthcoinUtxo)
        );

        let mut wrong_owner_store = CanonicalStateStoreV1::new();
        let mut wrong_owner_utxo = sponsor_utxo.clone();
        wrong_owner_utxo[0] ^= 1;
        wrong_owner_store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                input_key.clone(),
                wrong_owner_utxo,
            )
            .unwrap();
        assert_eq!(
            validate_truthcoin_utxo_ownership(&wrong_owner_store, &body),
            Err(ReplayError::WrongTruthcoinAuthorizationAddress)
        );

        let mut aliased_utxo_store = CanonicalStateStoreV1::new();
        let mut aliased_utxo = sponsor_utxo;
        aliased_utxo.push(0);
        aliased_utxo_store
            .put(TruthcoinDatabaseId::Utxos.as_u8(), input_key, aliased_utxo)
            .unwrap();
        assert_eq!(
            validate_truthcoin_utxo_ownership(&aliased_utxo_store, &body),
            Err(ReplayError::InvalidTruthcoinUtxoEncoding)
        );

        let mut bad_input_signature = body.clone();
        let last = bad_input_signature.authorizations_borsh.len() - 1;
        bad_input_signature.authorizations_borsh[last] ^= 1;
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&bad_input_signature),
            Err(ReplayError::InvalidTruthcoinAuthorization)
        );

        let mut missing_input_signature = body.clone();
        missing_input_signature.authorizations_borsh = vec![0, 0, 0, 0];
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&missing_input_signature),
            Err(ReplayError::InvalidTruthcoinAuthorization)
        );

        let mut bad_actor_signature = body;
        let last = bad_actor_signature.actor_proofs_borsh.len() - 1;
        bad_actor_signature.actor_proofs_borsh[last] ^= 1;
        assert_eq!(
            validate_truthcoin_authorization_envelopes(&bad_actor_signature),
            Err(ReplayError::InvalidTruthcoinAuthorization)
        );
    }

    #[test]
    fn sponsored_ballot_vote_table_matches_pinned_bincode_and_rolls_back() {
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: vec![hex::decode(concat!(
                "01000000020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "0a0a0a0a0a0a0a0000000001000000aff5bcf424b85d1401490c652fe8659b",
                "644c8bfc0098801e000000000000000000000000000104bc6e2e8c9248d09392",
                "89a04aba58d763733c597201000000000000333333333333e33f01000000"
            ))
            .unwrap()],
            authorizations_borsh: hex::decode(concat!(
                "01000000b604e9ef41560aa10d8b4ea994ce7e9e8848784cc2e8be5f26ba665d",
                "acf7ddd8ab3e695ac22852ea663db9d550e654ca85951e12907ae1d8f9c6750",
                "02dbd1f91c3ec9b51210b90c7a9d2f90411a78959e7be626a92ca6fe920730b",
                "ee98c14c03"
            ))
            .unwrap(),
            actor_proofs_borsh: hex::decode(concat!(
                "010000000143f9e02c3d175fd6b0117127ff5fe780943a8a47e4aaeb61ea937d",
                "bb248cf6f8b6631ad63a5516bb0273e2cabe2df175cb55833d6636a8a6b9eb3",
                "97ed3e9dcb286af7605ea0e6507ca0a12ce9cc4fd0fc9714f81acd7c8103ca2",
                "978e09015a00"
            ))
            .unwrap(),
        };
        let sponsor_input = hex::decode(
            "020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000",
        )
        .unwrap();
        let sponsor_utxo = hex::decode(
            "aff5bcf424b85d1401490c652fe8659b644c8bfc0000000080841e00000000000000000000000000",
        )
        .unwrap();
        let voter: [u8; 20] = hex::decode("bc6e2e8c9248d0939289a04aba58d763733c5972")
            .unwrap()
            .try_into()
            .unwrap();
        let decision_id = [0_u8; 3];

        let mut decision_set = 1_u64.to_le_bytes().to_vec();
        decision_set.extend_from_slice(&decision_id);
        decision_set.push(1); // Some(Decision)
        decision_set.extend_from_slice(&[0x55; 20]);
        decision_set.extend_from_slice(&0_u32.to_le_bytes()); // Binary
        decision_set.extend_from_slice(&3_u64.to_le_bytes());
        decision_set.extend_from_slice(b"BTC");
        decision_set.extend_from_slice(&3_u64.to_le_bytes());
        decision_set.extend_from_slice(b"USD");
        decision_set.push(0); // option_0_label
        decision_set.push(0); // option_1_label
        decision_set.extend_from_slice(&0_u64.to_le_bytes()); // tags
        decision_set.extend_from_slice(&[0x66; 32]);

        let mut voting_history = 1_u64.to_le_bytes().to_vec();
        voting_history.extend_from_slice(&2_u32.to_le_bytes()); // Voting
        voting_history.extend_from_slice(&4_u32.to_le_bytes());
        voting_history.push(0); // no outcome

        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                sponsor_input,
                sponsor_utxo,
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::Reputation.as_u8(),
                voter.to_vec(),
                1.0_f64.to_le_bytes().to_vec(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                0_u32.to_le_bytes().to_vec(),
                decision_set,
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                voting_history,
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                1_250_u64.to_le_bytes().to_vec(),
            )
            .unwrap();

        let parent = store.export().unwrap();
        assert_eq!(truthcoin_actor_addresses(&body).unwrap(), vec![Some(voter)]);
        assert_eq!(get_truthcoin_reputation(&store, &voter).unwrap(), 1.0);
        assert_eq!(
            decode_truthcoin_decision_kind(&store, decision_id).unwrap(),
            TruthcoinDecisionKindV1::Binary
        );
        assert!(truthcoin_decision_is_voting(&store, decision_id).unwrap());
        let undo = apply_truthcoin_voting_transitions(&mut store, &body, 3).unwrap();
        let key = truthcoin_vote_key(1, voter, decision_id);
        let mut expected = 1_u32.to_le_bytes().to_vec(); // Scalar
        expected.extend_from_slice(&0.6_f64.to_le_bytes());
        expected.extend_from_slice(&1_250_u64.to_le_bytes());
        expected.extend_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            hex::encode(&key),
            "01000000bc6e2e8c9248d0939289a04aba58d763733c5972000000"
        );
        assert_eq!(
            hex::encode(&expected),
            "01000000333333333333e33fe20400000000000003000000"
        );
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Votes.as_u8(), &key)
                .unwrap()
                .unwrap(),
            expected
        );
        let connected = store.export().unwrap();
        revert_truthcoin_voting_transitions(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        let replay_undo = apply_truthcoin_voting_transitions(&mut store, &body, 3).unwrap();
        assert_eq!(store.export().unwrap(), connected);

        let mut corrupt = store.clone();
        corrupt
            .put(TruthcoinDatabaseId::Votes.as_u8(), key, vec![0; 17])
            .unwrap();
        let before = corrupt.export().unwrap();
        assert_eq!(
            revert_truthcoin_voting_transitions(&mut corrupt, &replay_undo),
            Err(ReplayError::InvalidTruthcoinVotingState)
        );
        assert_eq!(corrupt.export().unwrap(), before);
    }

    #[test]
    fn embedded_market_decision_claim_matches_patched_native_tables() {
        let transaction = hex::decode(concat!(
            "010000000209090909090909090909090909090909090909090909090909090909",
            "09090909000000000200000004c32b9c70501b17c0fd75998cc61c05313f79d5",
            "029c0720f05bcd809698000000000000000000004b89f74befb4d2d2a78b1b5d",
            "68447ac25a21df2c00ac8e98000000000000000000000000000101140000004543",
            "58204254432f55534420706572696f6420302700000043616e6f6e6963616c2042",
            "54432f55534420666f72656361737420666f7220706572696f6420300100000000",
            "0000000100000001000000000088c3400000000080840e41000000000000f03f",
            "010000000000001a0000004254432f5553442061742063616e6f6e6963616c2063",
            "6c6f7365260000004543582063616e6f6e6963616c205472757468636f696e2042",
            "54432f555344207363616c617200000001020000000d0000006563782d6f726163",
            "6c652d7631070000006274632d757364017b14ae47e17a843f010001000100"
        ))
        .unwrap();
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: vec![transaction],
            authorizations_borsh: hex::decode(concat!(
                "0100000043f9e02c3d175fd6b0117127ff5fe780943a8a47e4aaeb61ea937dbb",
                "248cf6f8dc16ec05fcd8ea7e696cdfffe037943eb4d8b539d637f480f582cd16",
                "5b73727949a2f05ef9a0be026d8523146391d99493cfd885286d8d18ee8618eb",
                "73c98e06"
            ))
            .unwrap(),
            actor_proofs_borsh: vec![1, 0, 0, 0, 0],
        };
        let input_key = hex::decode(concat!(
            "020909090909090909090909090909090909090909090909090909090909090909",
            "00000000"
        ))
        .unwrap();
        let creator = hex::decode("bc6e2e8c9248d0939289a04aba58d763733c5972").unwrap();
        let mut input_value = creator.clone();
        input_value.extend_from_slice(&0_u32.to_le_bytes());
        input_value.extend_from_slice(&20_000_000_u64.to_le_bytes());
        input_value.extend_from_slice(&0_u64.to_le_bytes());
        let mut store = CanonicalStateStoreV1::new();
        store
            .put(TruthcoinDatabaseId::Utxos.as_u8(), input_key, input_value)
            .unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_decision_claim_mutations(&mut store, &body, 1).unwrap();
        assert_eq!(
            hex::encode(
                store
                    .get(
                        TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                        &0_u32.to_le_bytes()
                    )
                    .unwrap()
                    .unwrap()
            ),
            concat!(
                "010000000000000000000001bc6e2e8c9248d0939289a04aba58d763733c5972",
                "01000000000000000088c3400000000080840e41000000000000f03f1a000000",
                "000000004254432f5553442061742063616e6f6e6963616c20636c6f7365260000",
                "00000000004543582063616e6f6e6963616c205472757468636f696e204254432f55",
                "5344207363616c6172000002000000000000000d000000000000006563782d6f72",
                "61636c652d763107000000000000006274632d7573649f974f800a4a71a7d98e",
                "04e6cd1922b516210acbb5a7a98c6b6339a15fddca94"
            )
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                    &[0, 0, 0]
                )
                .unwrap()
                .unwrap(),
            hex::decode("0100000000000000010000000100000000").unwrap()
        );
        let decision_connected = store.export().unwrap();
        let market_undo = apply_truthcoin_market_creations(&mut store, &body, 1).unwrap();
        let market_id = hex::decode("9c0720f05bcd").unwrap();
        let market_bytes = store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
            .unwrap()
            .unwrap();
        assert_eq!(market_bytes.len(), 356);
        assert_eq!(
            hex::encode(Sha256::digest(market_bytes)),
            "5f906f52d9d698780f566ba6da272621d3923fd74e224b9242d76b2a3912675d"
        );
        let market = decode_truthcoin_market(market_bytes).unwrap();
        assert_eq!(market.id, [0x9c, 0x07, 0x20, 0xf0, 0x5b, 0xcd]);
        assert_eq!(market.shares, vec![0, 0]);
        assert_eq!(market.liquidity_base_sats, 10_000_000);
        assert_eq!(bincode::serialize(&market).unwrap(), market_bytes);
        let mut resolved_store = store.clone();
        resolved_store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                vec![0, 0, 0],
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None), (3, 7, Some(1.0))])
                    .unwrap(),
            )
            .unwrap();
        let resolved_outcome = TruthcoinDecisionOutcomeCodecV1 {
            decision_id: [0, 0, 0],
            period_id: 1,
            outcome_value: 1.0,
            min: 0.0,
            max: 1.0,
            confidence: 1.0,
            total_votes: 1,
            total_reputation_weight: 1.0,
            finalized_at: 0,
            block_height: 0,
            is_consensus: true,
            resolution: TruthcoinDecisionResolutionCodecV1 {
                decision_id: [0, 0, 0],
                period_id: 1,
                status: TruthcoinDecisionResolutionStatusCodecV1::Pending,
                status_changed_at: 0,
                status_changed_height: 0,
                vote_count: 1,
                min_votes_required: 1,
                voting_deadline: 1_000,
                outcome_ready: true,
                reason: None,
            },
            categorical_winner: None,
        };
        resolved_store
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                vec![0, 0, 0],
                bincode::serialize(&resolved_outcome).unwrap(),
            )
            .unwrap();
        assert_eq!(
            truthcoin_market_final_prices(&resolved_store, [0x9c, 0x07, 0x20, 0xf0, 0x5b, 0xcd],)
                .unwrap(),
            Some(vec![0.0, 1.0])
        );
        assert_eq!(
            quote_truthcoin_trade(market_bytes, 0, 100_000).unwrap(),
            TruthcoinTradeQuoteV1 {
                base_sats: 50_087,
                trading_fee_sats: 1_000,
                trader_value_sats: 51_087,
            }
        );
        let mut bought_market = market.clone();
        bought_market.shares[0] = 100_000;
        let bought_market_bytes = bincode::serialize(&bought_market).unwrap();
        assert_eq!(
            quote_truthcoin_trade(&bought_market_bytes, 0, -50_000).unwrap(),
            TruthcoinTradeQuoteV1 {
                base_sats: 25_064,
                trading_fee_sats: 1_000,
                trader_value_sats: 24_064,
            }
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MarketsByState.as_u8(),
                    &0_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            hex::decode("01000000000000009c0720f05bcd").unwrap()
        );
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::MarketsByDecision.as_u8(), &[0, 0, 0])
                .unwrap()
                .unwrap(),
            hex::decode("01000000000000009c0720f05bcd").unwrap()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &hex::decode("9c0720f05bcd00").unwrap()
                )
                .unwrap()
                .unwrap(),
            hex::decode(concat!(
                "000000009f974f800a4a71a7d98e04e6cd1922b516210acbb5a7a98c6b6339",
                "a15fddca9400000000"
            ))
            .unwrap()
        );
        let market_connected = store.export().unwrap();
        assert_eq!(
            apply_truthcoin_market_creations(&mut store, &body, 2),
            Err(ReplayError::InvalidTruthcoinMarketCreation)
        );
        assert_eq!(store.export().unwrap(), market_connected);

        // Candidate extraction reads the canonical tables and original block
        // bytes; it does not accept IDs, prices, or eligibility from a host.
        let mut candidate_store = store.clone();
        candidate_store
            .put(
                TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                1_000_u64.to_le_bytes().to_vec(),
            )
            .unwrap();
        let standard_decision_id = [0x80, 0, 0];
        let mut decision_entries = decode_truthcoin_period_decisions(
            candidate_store
                .get(
                    TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                    &0_u32.to_le_bytes(),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        decision_entries[0].decision_id = standard_decision_id;
        candidate_store
            .put(
                TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                0_u32.to_le_bytes().to_vec(),
                encode_truthcoin_period_decisions(&decision_entries).unwrap(),
            )
            .unwrap();
        candidate_store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                standard_decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None)]).unwrap(),
            )
            .unwrap();
        let mut candidate_market = market.clone();
        // Missing native history must not turn snapshot shares into an old
        // observation, even when last_updated_height appears recent.
        let empty_history = CanonicalStateStoreV1::import(
            &CanonicalStateSnapshotV1::empty().encode().unwrap(),
        ).unwrap();
        let mut snapshot_market = market.clone();
        snapshot_market.created_at_height = 2;
        snapshot_market.last_updated_height = 13;
        assert_eq!(
            truthcoin_market_samples_after_checkpoint(&empty_history, &snapshot_market, 0, Some(13)).unwrap(),
            (u64::MAX, vec![]),
        );
        snapshot_market.created_at_height = 14;
        snapshot_market.last_updated_height = 14;
        let (eligible, fresh_samples) = truthcoin_market_samples_after_checkpoint(
            &empty_history, &snapshot_market, 0, Some(13),
        ).unwrap();
        assert_eq!(eligible, 14);
        assert_eq!(fresh_samples.len(), 1);
        assert_eq!(fresh_samples[0].0, 14);
        candidate_market.decision_ids = vec![standard_decision_id];
        candidate_market.dimension_specs = vec![TruthcoinMarketDimensionCodecV1::Single(
            standard_decision_id,
        )];
        candidate_market.shares = vec![0, 1_000];
        candidate_store
            .put(
                TruthcoinDatabaseId::Markets.as_u8(),
                market_id.clone(),
                bincode::serialize(&candidate_market).unwrap(),
            )
            .unwrap();
        let stored_decision = decision_entries[0].decision.as_ref().unwrap();
        let DecodedTruthcoinDecisionTypeV1::Scaled {
            min,
            max,
            increment,
        } = stored_decision.decision_type
        else {
            panic!("fixture decision must be scaled")
        };
        let template = TruthcoinMarketTemplateCommitmentV1 {
            version: TruthcoinMarketTemplateCommitmentV1::VERSION,
            market_title_template: "ECX BTC/USD period {period}".into(),
            market_description_template: "Canonical BTC/USD forecast for period {period}".into(),
            decision_header_template: "BTC/USD at canonical close".into(),
            decision_description_template: "ECX canonical Truthcoin BTC/USD scalar".into(),
            decision_tags: vec!["ecx-oracle-v1".into(), "btc-usd".into()],
            scalar_min_f64_bits: min.to_bits(),
            scalar_max_f64_bits: max.to_bits(),
            scalar_increment_f64_bits: increment.to_bits(),
            minimum_liquidity_sats: 10_000_000,
            trading_fee_ppm: (candidate_market.trading_fee * 1_000_000.0) as u32,
            tx_pow_hash_selector: candidate_market.tx_pow_hash_selector,
            tx_pow_ordering: candidate_market.tx_pow_ordering,
            tx_pow_difficulty: candidate_market.tx_pow_difficulty,
        };
        let mut authentication = fixture().input.authentication;
        authentication.btc_usd_template_hash = template.digest();
        let source_block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 1,
            bmm_main_height: 2,
            header_borsh: vec![0x43],
            body: body.clone(),
        };
        let source_context = CanonicalBlockContextV1 {
            sidechain_block_hash: source_block.block_hash(),
            sidechain_height: 1,
            bmm_main_block_hash: [0x42; 32],
            bmm_main_height: 2,
            bmm_main_timestamp: 2_000,
            bmm_main_mtp: 1_900,
        };
        candidate_store
            .put(
                TruthcoinDatabaseId::Tip.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                source_context.sidechain_block_hash.to_vec(),
            )
            .unwrap();
        candidate_store
            .put(
                TruthcoinDatabaseId::Height.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                1_u32.to_le_bytes().to_vec(),
            )
            .unwrap();
        candidate_store
            .put(
                TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                source_context.bmm_main_timestamp.to_le_bytes().to_vec(),
            )
            .unwrap();
        let candidates = extract_truthcoin_oracle_candidates(
            &authentication,
            &template,
            &candidate_store,
            std::slice::from_ref(&source_block),
            &[source_context],
            6,
        )
        .unwrap();
        assert!(candidates.anchors.is_empty());
        assert_eq!(candidates.markets.len(), 1);
        let extracted = &candidates.markets[0];
        assert_eq!(extracted.native_decision_id, standard_decision_id);
        assert_eq!(extracted.native_market_id.as_slice(), market_id.as_slice());
        assert_eq!(extracted.market_created_height, 1);
        assert_eq!(extracted.market_first_eligible_height, 1);
        assert_eq!(extracted.snapshot.sample_count, 1);
        assert_eq!(
            extracted.snapshot.source_block_hash,
            source_context.sidechain_block_hash
        );
        assert_eq!(extracted.snapshot.source_confirmations, 6);
        assert_eq!(
            extracted.market_creation_txid,
            *blake3::hash(&body.transactions_borsh[0]).as_bytes()
        );
        assert_eq!(
            extracted.probability_f64_bits,
            upstream_binary_lmsr_probability([0, 1_000], 10_000_000_f64 / libm::log(2.0),)
                .unwrap()
                .to_bits()
        );
        let mut resolved_candidate_store = candidate_store.clone();
        resolved_candidate_store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                standard_decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None), (3, 7, Some(0.25))])
                    .unwrap(),
            )
            .unwrap();
        let anchor_outcome = TruthcoinDecisionOutcomeCodecV1 {
            decision_id: standard_decision_id,
            period_id: 1,
            outcome_value: 0.25,
            min: 0.0,
            max: 1.0,
            confidence: 1.0,
            total_votes: 1,
            total_reputation_weight: 1.0,
            finalized_at: 0,
            block_height: 0,
            is_consensus: true,
            resolution: TruthcoinDecisionResolutionCodecV1 {
                decision_id: standard_decision_id,
                period_id: 1,
                status: TruthcoinDecisionResolutionStatusCodecV1::Pending,
                status_changed_at: 0,
                status_changed_height: 0,
                vote_count: 1,
                min_votes_required: 1,
                voting_deadline: 1_000,
                outcome_ready: true,
                reason: None,
            },
            categorical_winner: None,
        };
        assert_eq!(
            truthcoin_denormalized_scalar_outcome(&stored_decision.decision_type, &anchor_outcome,)
                .unwrap(),
            70_000.0
        );
        let mut boundary_outcome = anchor_outcome.clone();
        boundary_outcome.outcome_value = 0.0;
        assert_eq!(
            truthcoin_denormalized_scalar_outcome(
                &stored_decision.decision_type,
                &boundary_outcome,
            )
            .unwrap(),
            min
        );
        boundary_outcome.outcome_value = 1.0;
        assert_eq!(
            truthcoin_denormalized_scalar_outcome(
                &stored_decision.decision_type,
                &boundary_outcome,
            )
            .unwrap(),
            max
        );
        for invalid in [f64::NAN, f64::INFINITY, -f64::EPSILON, 1.0 + f64::EPSILON] {
            boundary_outcome.outcome_value = invalid;
            assert_eq!(
                truthcoin_denormalized_scalar_outcome(
                    &stored_decision.decision_type,
                    &boundary_outcome,
                ),
                Err(ReplayError::InvalidTruthcoinDecisionState)
            );
        }
        boundary_outcome.outcome_value = 0.25;
        boundary_outcome.min = -0.0;
        assert_eq!(
            truthcoin_denormalized_scalar_outcome(
                &stored_decision.decision_type,
                &boundary_outcome,
            ),
            Err(ReplayError::InvalidTruthcoinDecisionState)
        );
        resolved_candidate_store
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                standard_decision_id.to_vec(),
                bincode::serialize(&anchor_outcome).unwrap(),
            )
            .unwrap();
        let mut settled_candidate_market = candidate_market;
        settled_candidate_market.market_state = TruthcoinMarketStateCodecV1::Settled;
        resolved_candidate_store
            .put(
                TruthcoinDatabaseId::Markets.as_u8(),
                market_id.clone(),
                bincode::serialize(&settled_candidate_market).unwrap(),
            )
            .unwrap();
        let resolved_candidates = extract_truthcoin_oracle_candidates(
            &authentication,
            &template,
            &resolved_candidate_store,
            &[source_block],
            &[source_context],
            6,
        )
        .unwrap();
        assert_eq!(resolved_candidates.anchors.len(), 1);
        assert_eq!(resolved_candidates.markets.len(), 1);
        assert!(!resolved_candidates.markets[0].is_open);
        let anchor = &resolved_candidates.anchors[0].anchor;
        assert_eq!(anchor.btc_usd_price.get(), 70_000 * PRICE_SCALE);
        assert_eq!(anchor.observation_end_mtp, 1_000 + TRUTHCOIN_PERIOD_SECONDS);
        assert_eq!(anchor.finalized_at_mtp, anchor.observation_end_mtp);
        assert_eq!(
            anchor.source_state_root,
            resolved_candidate_store.root().unwrap()
        );

        let mut trade_store = store.clone();
        let treasury_pointer = decode_truthcoin_outpoint(
            trade_store
                .get(
                    TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                    &hex::decode("9c0720f05bcd00").unwrap(),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let treasury_key = truthcoin_outpoint_key(treasury_pointer).unwrap();
        let creation_transaction =
            decode_truthcoin_transaction(&body.transactions_borsh[0]).unwrap();
        let treasury_output = &creation_transaction.outputs[0];
        trade_store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                treasury_key.to_vec(),
                encode_truthcoin_filled_output(treasury_output).unwrap(),
            )
            .unwrap();
        trade_store
            .put(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                truthcoin_address_index_key(treasury_output.address, &treasury_key),
                Vec::new(),
            )
            .unwrap();
        let buy_input_key = hex::decode(concat!(
            "009f974f800a4a71a7d98e04e6cd1922b516210acbb5a7a98c6b6339a15fddca94",
            "01000000"
        ))
        .unwrap();
        let buy_input_value = hex::decode(concat!(
            "4b89f74befb4d2d2a78b1b5d68447ac25a21df2c00000000ac8e980000000000",
            "0000000000000000"
        ))
        .unwrap();
        trade_store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                buy_input_key.clone(),
                buy_input_value.clone(),
            )
            .unwrap();
        let buy_input_key_array: [u8; 37] = buy_input_key.clone().try_into().unwrap();
        let buy_input = decode_truthcoin_filled_output(&buy_input_value).unwrap();
        trade_store
            .put(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                truthcoin_address_index_key(buy_input.address, &buy_input_key_array),
                Vec::new(),
            )
            .unwrap();
        let buy_body = TruthcoinBodyV1 {
            coinbase_borsh: vec![],
            transactions_borsh: vec![hex::decode(concat!(
                "01000000009f974f800a4a71a7d98e04e6cd1922b516210acbb5a7a98c6b6339",
                "a15fddca9401000000000000000000000001029c0720f05bcd00000000a0860100",
                "000000004b89f74befb4d2d2a78b1b5d68447ac25a21df2ca08601000000000000",
                "20603dcccc492cf9bbb497d1fc4d263f50fb9d776ae43541c301a59f90b7ed47"
            ))
            .unwrap()],
            authorizations_borsh: vec![],
            actor_proofs_borsh: vec![],
        };
        let trade_parent = trade_store.export().unwrap();
        let trade_undo =
            apply_truthcoin_trade_market_transitions_inner(&mut trade_store, &buy_body, 2, false)
                .unwrap();
        let successor_market = trade_store
            .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
            .unwrap()
            .unwrap();
        let mut keyed_market = market_id.clone();
        keyed_market.extend_from_slice(successor_market);
        assert_eq!(
            hex::encode(Sha256::digest(&keyed_market)),
            "33a38053990deb42301057fc7c06f3dbd26e7f36296d6bfe06f18c88631de52b"
        );
        let trader = hex::decode("4b89f74befb4d2d2a78b1b5d68447ac25a21df2c").unwrap();
        let account = trade_store
            .get(TruthcoinDatabaseId::ShareAccounts.as_u8(), &trader)
            .unwrap()
            .unwrap();
        let mut keyed_account = trader;
        keyed_account.extend_from_slice(account);
        assert_eq!(
            hex::encode(Sha256::digest(&keyed_account)),
            "818733853d6b4db49e1d95950e5bbbd2f23d5d751e0a1b4d92933c878ed0485d"
        );
        let undo_key = 2_u32.to_le_bytes();
        let undo_value = trade_store
            .get(TruthcoinDatabaseId::MarketTransitionUndo.as_u8(), &undo_key)
            .unwrap()
            .unwrap();
        let mut keyed_undo = undo_key.to_vec();
        keyed_undo.extend_from_slice(undo_value);
        assert_eq!(undo_value.len(), 393);
        assert_eq!(
            hex::encode(Sha256::digest(&keyed_undo)),
            "5e0de849220c346b70df3d75c4d09621a544a3d83ac0431b12ae2e108dca21dc"
        );

        let hash_table = |state: &CanonicalStateStoreV1, database: TruthcoinDatabaseId| {
            let mut bytes = Vec::new();
            for (key, value) in state.entries(database.as_u8()).unwrap() {
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(value);
            }
            hex::encode(Sha256::digest(bytes))
        };
        let base_undo = apply_truthcoin_base_utxo_transition_inner(
            &mut trade_store,
            &buy_body,
            false,
            &BTreeSet::new(),
        )
        .unwrap();
        let consolidation_undo =
            apply_truthcoin_trade_consolidation(&mut trade_store, &trade_undo, 2).unwrap();
        assert_eq!(
            hash_table(&trade_store, TruthcoinDatabaseId::MarketFundsUtxos),
            "9fe6cf3a835fc938e5a781ce8512bc7c46d6340506a4f642f8abebbe680c24c2"
        );
        assert_eq!(
            hash_table(&trade_store, TruthcoinDatabaseId::ConsolidationUndo),
            "0ac573b312dda5dfd168f664c273989e757b3aae1dd64913bc1d1192bcfae8fd"
        );
        let treasury_key = truthcoin_outpoint_key(TruthcoinOutPointCodecV1::MarketFunds {
            market_id: market_id.clone().try_into().unwrap(),
            block_height: 2,
            is_fee: false,
        })
        .unwrap();
        let treasury = decode_truthcoin_filled_output(
            trade_store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &treasury_key)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            truthcoin_filled_bitcoin_value(&treasury).unwrap(),
            10_050_087
        );
        let fee_key = truthcoin_outpoint_key(TruthcoinOutPointCodecV1::MarketFunds {
            market_id: market_id.clone().try_into().unwrap(),
            block_height: 2,
            is_fee: true,
        })
        .unwrap();
        let fee = decode_truthcoin_filled_output(
            trade_store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &fee_key)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(truthcoin_filled_bitcoin_value(&fee).unwrap(), 1_000);
        let buy_connected = trade_store.export().unwrap();
        let sell_body = TruthcoinBodyV1 {
            coinbase_borsh: vec![],
            transactions_borsh: vec![hex::decode(concat!(
                "0100000004a408f67cfe35d6bde4f299f2fd0dd58315ae09f4aa5a0319aada1",
                "2461340296400000000000000000000000001029c0720f05bcd00000000b03cff",
                "ffffffffff4b89f74befb4d2d2a78b1b5d68447ac25a21df2c00000000000000",
                "0000bbd1a6c6e9a62b4dec053cc8313c564e4ede55f6ebaa69314fb79332f60a",
                "e1c6"
            ))
            .unwrap()],
            authorizations_borsh: vec![],
            actor_proofs_borsh: vec![],
        };
        let sell_trade_undo =
            apply_truthcoin_trade_market_transitions_inner(&mut trade_store, &sell_body, 3, false)
                .unwrap();
        let sell_base_undo = apply_truthcoin_base_utxo_transition_inner(
            &mut trade_store,
            &sell_body,
            false,
            &BTreeSet::new(),
        )
        .unwrap();
        let sell_consolidation_undo =
            apply_truthcoin_trade_consolidation(&mut trade_store, &sell_trade_undo, 3).unwrap();
        assert_eq!(
            hash_table(&trade_store, TruthcoinDatabaseId::Markets),
            "62300e55161568479da9e4700a8d31d834c5437819486221577b8ab079eef7fb"
        );
        assert_eq!(
            hash_table(&trade_store, TruthcoinDatabaseId::ShareAccounts),
            "94b17d7056631822af4df8973385b514c125d3d6800e79356f1e5cedd8a24e05"
        );
        assert_eq!(
            hash_table(&trade_store, TruthcoinDatabaseId::MarketTransitionUndo),
            "3329161c0d148c4ffc6d20a3d5f11e8f7464100a6797268de62ee00a676d132a"
        );
        let market_id_array: [u8; 6] = market_id.clone().try_into().unwrap();
        let sell_treasury_key = truthcoin_outpoint_key(TruthcoinOutPointCodecV1::MarketFunds {
            market_id: market_id_array,
            block_height: 3,
            is_fee: false,
        })
        .unwrap();
        assert_eq!(
            truthcoin_filled_bitcoin_value(
                &decode_truthcoin_filled_output(
                    trade_store
                        .get(TruthcoinDatabaseId::Utxos.as_u8(), &sell_treasury_key)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            10_025_023
        );
        let sell_fee_key = truthcoin_outpoint_key(TruthcoinOutPointCodecV1::MarketFunds {
            market_id: market_id_array,
            block_height: 3,
            is_fee: true,
        })
        .unwrap();
        assert_eq!(
            truthcoin_filled_bitcoin_value(
                &decode_truthcoin_filled_output(
                    trade_store
                        .get(TruthcoinDatabaseId::Utxos.as_u8(), &sell_fee_key)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            2_000
        );
        let trader_array: [u8; 20] = hex::decode("4b89f74befb4d2d2a78b1b5d68447ac25a21df2c")
            .unwrap()
            .try_into()
            .unwrap();
        let sell_txid = *blake3::hash(&sell_body.transactions_borsh[0]).as_bytes();
        for (domain, market, expected) in [
            (b"SELL_PAYOUT".as_slice(), Some(market_id_array), 24_064_u64),
            (b"SELL_INPUT_CHANGE".as_slice(), None, 9_944_909_u64),
        ] {
            let key = truthcoin_outpoint_key(truthcoin_synthetic_payout_outpoint(
                domain,
                market,
                trader_array,
                sell_txid,
            ))
            .unwrap();
            assert_eq!(
                truthcoin_filled_bitcoin_value(
                    &decode_truthcoin_filled_output(
                        trade_store
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), &key)
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                expected
            );
        }

        let prior_decision_history = trade_store
            .get(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                &[0, 0, 0],
            )
            .unwrap()
            .unwrap()
            .to_vec();
        trade_store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                vec![0, 0, 0],
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None), (3, 8, Some(0.0))])
                    .unwrap(),
            )
            .unwrap();
        let mut settlement_outcome = resolved_outcome;
        settlement_outcome.outcome_value = 0.0;
        trade_store
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                vec![0, 0, 0],
                bincode::serialize(&settlement_outcome).unwrap(),
            )
            .unwrap();
        let voter_reputation_before = trade_store
            .get(TruthcoinDatabaseId::Reputation.as_u8(), &trader_array)
            .unwrap()
            .map(ToOwned::to_owned);
        set_truthcoin_reputation(&mut trade_store, trader_array, 2.0).unwrap();
        let settlement_vote_key = truthcoin_vote_key(1, trader_array, [0, 0, 0]);
        trade_store
            .put(
                TruthcoinDatabaseId::Votes.as_u8(),
                settlement_vote_key.clone(),
                truthcoin_vote_value(TruthcoinDecisionKindV1::Binary, 0.0, 1_001, 8).unwrap(),
            )
            .unwrap();
        let settlement_parent = trade_store.export().unwrap();
        let settlement_undo =
            apply_truthcoin_resolved_market_settlements(&mut trade_store, 8).unwrap();
        let settled_market = decode_truthcoin_market(
            trade_store
                .get(TruthcoinDatabaseId::Markets.as_u8(), &market_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            settled_market.market_state,
            TruthcoinMarketStateCodecV1::Settled
        );
        assert_eq!(settled_market.final_prices, vec![1.0, 0.0]);
        assert_eq!(settled_market.version, 4);
        assert!(trade_store
            .get(TruthcoinDatabaseId::ShareAccounts.as_u8(), &trader_array)
            .unwrap()
            .is_none());
        assert!(trade_store
            .get(
                TruthcoinDatabaseId::MarketFundsUtxos.as_u8(),
                &truthcoin_market_funds_pointer_key(market_id_array, false),
            )
            .unwrap()
            .is_none());
        for (sequence, address, expected) in [
            (0, trader_array, 50_000_u64),
            (1, trader_array, 1_000),
            (2, settled_market.creator_address, 500),
            (3, settled_market.creator_address, 500),
            (4, settled_market.creator_address, 9_975_023),
        ] {
            let key = truthcoin_outpoint_key(truthcoin_share_payout_outpoint(
                market_id_array,
                address,
                8,
                sequence,
            ))
            .unwrap();
            assert_eq!(
                truthcoin_filled_bitcoin_value(
                    &decode_truthcoin_filled_output(
                        trade_store
                            .get(TruthcoinDatabaseId::Utxos.as_u8(), &key)
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                expected
            );
        }
        let mut corrupt_settlement_rollback = trade_store.clone();
        corrupt_settlement_rollback
            .put(
                TruthcoinDatabaseId::Markets.as_u8(),
                market_id.clone(),
                vec![0],
            )
            .unwrap();
        let corrupt_settlement_before = corrupt_settlement_rollback.export().unwrap();
        assert_eq!(
            revert_truthcoin_resolved_market_settlements(
                &mut corrupt_settlement_rollback,
                &settlement_undo,
            ),
            Err(ReplayError::InvalidTruthcoinMarketState)
        );
        assert_eq!(
            corrupt_settlement_rollback.export().unwrap(),
            corrupt_settlement_before
        );
        revert_truthcoin_resolved_market_settlements(&mut trade_store, &settlement_undo).unwrap();
        assert_eq!(trade_store.export().unwrap(), settlement_parent);
        trade_store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                vec![0, 0, 0],
                prior_decision_history,
            )
            .unwrap();
        trade_store
            .delete(TruthcoinDatabaseId::DecisionOutcomes.as_u8(), &[0, 0, 0])
            .unwrap();
        trade_store
            .delete(TruthcoinDatabaseId::Votes.as_u8(), &settlement_vote_key)
            .unwrap();
        match voter_reputation_before {
            Some(value) => {
                trade_store
                    .put(
                        TruthcoinDatabaseId::Reputation.as_u8(),
                        trader_array.to_vec(),
                        value,
                    )
                    .unwrap();
            }
            None => {
                trade_store
                    .delete(TruthcoinDatabaseId::Reputation.as_u8(), &trader_array)
                    .unwrap();
            }
        }
        revert_truthcoin_trade_consolidation(&mut trade_store, &sell_consolidation_undo).unwrap();
        revert_truthcoin_base_utxo_transition(&mut trade_store, &sell_base_undo).unwrap();
        revert_truthcoin_trade_market_transitions(&mut trade_store, &sell_trade_undo).unwrap();
        assert_eq!(trade_store.export().unwrap(), buy_connected);

        let mut corrupt_consolidation_rollback = trade_store.clone();
        corrupt_consolidation_rollback
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                fee_key.to_vec(),
                vec![0],
            )
            .unwrap();
        let corrupt_rollback_before = corrupt_consolidation_rollback.export().unwrap();
        assert_eq!(
            revert_truthcoin_trade_consolidation(
                &mut corrupt_consolidation_rollback,
                &consolidation_undo,
            ),
            Err(ReplayError::InvalidTruthcoinMarketState)
        );
        assert_eq!(
            corrupt_consolidation_rollback.export().unwrap(),
            corrupt_rollback_before
        );

        let mut underfunded_sell = trade_store.clone();
        let underfunded_trade_undo = apply_truthcoin_trade_market_transitions_inner(
            &mut underfunded_sell,
            &sell_body,
            3,
            false,
        )
        .unwrap();
        apply_truthcoin_base_utxo_transition_inner(
            &mut underfunded_sell,
            &sell_body,
            false,
            &BTreeSet::new(),
        )
        .unwrap();
        let mut underfunded_treasury = decode_truthcoin_filled_output(
            underfunded_sell
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &treasury_key)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let TruthcoinFilledContentV1::MarketFunds { amount, .. } =
            &mut underfunded_treasury.content
        else {
            panic!("expected treasury output")
        };
        *amount = 1;
        underfunded_sell
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                treasury_key.to_vec(),
                bincode::serialize(&underfunded_treasury).unwrap(),
            )
            .unwrap();
        let underfunded_before = underfunded_sell.export().unwrap();
        assert_eq!(
            apply_truthcoin_trade_consolidation(&mut underfunded_sell, &underfunded_trade_undo, 3,),
            Err(ReplayError::InvalidTruthcoinTrade)
        );
        assert_eq!(underfunded_sell.export().unwrap(), underfunded_before);
        revert_truthcoin_trade_consolidation(&mut trade_store, &consolidation_undo).unwrap();
        revert_truthcoin_base_utxo_transition(&mut trade_store, &base_undo).unwrap();

        let mut corrupt_trade = trade_store.clone();
        corrupt_trade
            .put(
                TruthcoinDatabaseId::Markets.as_u8(),
                market_id.clone(),
                vec![0],
            )
            .unwrap();
        let corrupt_trade_before = corrupt_trade.export().unwrap();
        assert_eq!(
            revert_truthcoin_trade_market_transitions(&mut corrupt_trade, &trade_undo),
            Err(ReplayError::InvalidTruthcoinMarketState)
        );
        assert_eq!(corrupt_trade.export().unwrap(), corrupt_trade_before);

        revert_truthcoin_trade_market_transitions(&mut trade_store, &trade_undo).unwrap();
        assert_eq!(trade_store.export().unwrap(), trade_parent);

        revert_truthcoin_market_creations(&mut store, &market_undo).unwrap();
        assert_eq!(store.export().unwrap(), decision_connected);
        let replay_market_undo = apply_truthcoin_market_creations(&mut store, &body, 1).unwrap();
        assert_eq!(store.export().unwrap(), market_connected);

        let mut corrupt_market = store.clone();
        corrupt_market
            .put(
                TruthcoinDatabaseId::Markets.as_u8(),
                market_id.clone(),
                vec![0],
            )
            .unwrap();
        let corrupt_market_before = corrupt_market.export().unwrap();
        assert_eq!(
            revert_truthcoin_market_creations(&mut corrupt_market, &replay_market_undo),
            Err(ReplayError::InvalidTruthcoinMarketState)
        );
        assert_eq!(corrupt_market.export().unwrap(), corrupt_market_before);

        revert_truthcoin_market_creations(&mut store, &replay_market_undo).unwrap();
        assert_eq!(store.export().unwrap(), decision_connected);

        revert_truthcoin_decision_claim_mutations(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        let replay_undo = apply_truthcoin_decision_claim_mutations(&mut store, &body, 1).unwrap();
        assert_eq!(store.export().unwrap(), decision_connected);

        let mut corrupt = store.clone();
        corrupt
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                vec![0, 0, 0],
                vec![0],
            )
            .unwrap();
        let before = corrupt.export().unwrap();
        assert_eq!(
            revert_truthcoin_decision_claim_mutations(&mut corrupt, &replay_undo),
            Err(ReplayError::InvalidTruthcoinDecisionState)
        );
        assert_eq!(corrupt.export().unwrap(), before);
    }

    #[test]
    fn native_buy_trade_payload_and_quote_are_exact() {
        let transaction_bytes = hex::decode(concat!(
            "01000000009f974f800a4a71a7d98e04e6cd1922b516210acbb5a7a98c6b6339",
            "a15fddca9401000000000000000000000001029c0720f05bcd00000000a0860100",
            "000000004b89f74befb4d2d2a78b1b5d68447ac25a21df2ca08601000000000000",
            "20603dcccc492cf9bbb497d1fc4d263f50fb9d776ae43541c301a59f90b7ed47"
        ))
        .unwrap();
        let transaction = decode_truthcoin_transaction(&transaction_bytes).unwrap();
        assert_eq!(transaction.input_keys.len(), 1);
        assert!(transaction.outputs.is_empty());
        let Some(DecodedTruthcoinTransactionDataV1::Trade(trade)) = transaction.data else {
            panic!("expected native trade payload")
        };
        assert_eq!(trade.market_id, [0x9c, 0x07, 0x20, 0xf0, 0x5b, 0xcd]);
        assert_eq!(trade.outcome_index, 0);
        assert_eq!(trade.shares, 100_000);
        let expected_trader: [u8; 20] = hex::decode("4b89f74befb4d2d2a78b1b5d68447ac25a21df2c")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(trade.trader, expected_trader);
        assert_eq!(trade.limit_sats, 100_000);
        assert_eq!(trade.tx_pow_nonce, None);
        let expected_parent: [u8; 32] =
            hex::decode("20603dcccc492cf9bbb497d1fc4d263f50fb9d776ae43541c301a59f90b7ed47")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(trade.prev_block_hash, expected_parent);
        assert_eq!(
            hex::encode(blake3::hash(&transaction_bytes).as_bytes()),
            "0577a52a204c317fdc77b900566943d659b4df54a2d5487495fead94a3966157"
        );
    }

    #[test]
    fn native_sell_trade_payload_is_exact() {
        let transaction_bytes = hex::decode(concat!(
            "0100000004a408f67cfe35d6bde4f299f2fd0dd58315ae09f4aa5a0319aada1",
            "2461340296400000000000000000000000001029c0720f05bcd00000000b03cff",
            "ffffffffff4b89f74befb4d2d2a78b1b5d68447ac25a21df2c00000000000000",
            "0000bbd1a6c6e9a62b4dec053cc8313c564e4ede55f6ebaa69314fb79332f60a",
            "e1c6"
        ))
        .unwrap();
        let transaction = decode_truthcoin_transaction(&transaction_bytes).unwrap();
        let Some(DecodedTruthcoinTransactionDataV1::Trade(trade)) = transaction.data else {
            panic!("expected native trade payload")
        };
        assert_eq!(trade.market_id, [0x9c, 0x07, 0x20, 0xf0, 0x5b, 0xcd]);
        assert_eq!(trade.outcome_index, 0);
        assert_eq!(trade.shares, -50_000);
        assert_eq!(trade.limit_sats, 0);
        assert_eq!(trade.tx_pow_nonce, None);
        assert_eq!(
            hex::encode(blake3::hash(&transaction_bytes).as_bytes()),
            "b8627f7fb98119e9c3b61a7bd132fca8bdafc87e1b43352dcb3ce39a21f8a82e"
        );
    }

    #[test]
    fn resolved_decision_outcome_is_bound_to_exact_history() {
        let decision_id = [0, 0, 0];
        let resolution = TruthcoinDecisionResolutionCodecV1 {
            decision_id,
            period_id: 1,
            status: TruthcoinDecisionResolutionStatusCodecV1::Pending,
            status_changed_at: 0,
            status_changed_height: 0,
            vote_count: 3,
            min_votes_required: 1,
            voting_deadline: 1_000,
            outcome_ready: true,
            reason: None,
        };
        let outcome = TruthcoinDecisionOutcomeCodecV1 {
            decision_id,
            period_id: 1,
            outcome_value: 1.0,
            min: 0.0,
            max: 1.0,
            confidence: 0.99,
            total_votes: 3,
            total_reputation_weight: 10.0,
            finalized_at: 0,
            block_height: 0,
            is_consensus: true,
            resolution,
            categorical_winner: None,
        };
        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None), (3, 7, Some(1.0))])
                    .unwrap(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                decision_id.to_vec(),
                bincode::serialize(&outcome).unwrap(),
            )
            .unwrap();
        assert_eq!(
            truthcoin_resolved_decision_outcome(&store, decision_id)
                .unwrap()
                .unwrap(),
            outcome
        );

        let mut mismatched_history = store.clone();
        mismatched_history
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None), (3, 7, Some(0.0))])
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            truthcoin_resolved_decision_outcome(&mismatched_history, decision_id),
            Err(ReplayError::InvalidTruthcoinDecisionState)
        );

        let mut non_consensus = outcome;
        non_consensus.is_consensus = false;
        let bytes = bincode::serialize(&non_consensus).unwrap();
        assert_eq!(
            decode_truthcoin_decision_outcome(decision_id, &bytes),
            Err(ReplayError::InvalidTruthcoinDecisionState)
        );
    }

    #[test]
    fn no_vote_consensus_is_exact_atomic_and_never_handles_voted_periods() {
        let decision_id = [0, 0, 0];
        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::GenesisTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                1_000_u64.to_le_bytes().to_vec(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                (1_000 + 3 * TRUTHCOIN_PERIOD_SECONDS)
                    .to_le_bytes()
                    .to_vec(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None)]).unwrap(),
            )
            .unwrap();
        set_truthcoin_reputation(&mut store, [7; 20], 10.0).unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_no_vote_consensus(&mut store, 10).unwrap();
        assert_eq!(
            decode_truthcoin_state_history(
                store
                    .get(
                        TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                        &decision_id,
                    )
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
            vec![(1, 1, None), (2, 2, None), (3, 10, Some(0.5))]
        );
        assert_eq!(
            truthcoin_resolved_decision_value(&store, decision_id).unwrap(),
            Some(0.5)
        );
        let outcome = decode_truthcoin_decision_outcome(
            decision_id,
            store
                .get(TruthcoinDatabaseId::DecisionOutcomes.as_u8(), &decision_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.block_height, 0);
        assert_eq!(outcome.finalized_at, 0);
        assert_eq!(
            outcome.resolution.status,
            TruthcoinDecisionResolutionStatusCodecV1::Pending
        );
        assert!(outcome.resolution.outcome_ready);
        let stats: TruthcoinVotingPeriodStatsCodecV1 = bincode::deserialize(
            store
                .get(
                    TruthcoinDatabaseId::PeriodStats.as_u8(),
                    &1_u32.to_le_bytes(),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(stats.certainty, Some(0.0));
        assert_eq!(stats.calculated_at, 0);

        // A later decision in this already-resolved period must remain Voting.
        // Checking only the pending decision set would resolve it incorrectly.
        let mut late = store.clone();
        late.put(
            TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
            vec![0, 0, 1],
            encode_truthcoin_state_history(&[(1, 11, None), (2, 12, None)]).unwrap(),
        ).unwrap();
        let late_before = late.export().unwrap();
        assert!(apply_truthcoin_no_vote_consensus(&mut late, 13).unwrap().changes.is_empty());
        assert_eq!(late.export().unwrap(), late_before);
        let mut late_voted = late.clone();
        set_truthcoin_reputation(&mut late_voted, [7; 20], 1.0).unwrap();
        late_voted.put(
            TruthcoinDatabaseId::Votes.as_u8(),
            truthcoin_vote_key(1, [7; 20], [0, 0, 1]),
            truthcoin_vote_value(TruthcoinDecisionKindV1::Binary, 1.0, 2_000, 12).unwrap(),
        ).unwrap();
        let late_voted_before = late_voted.export().unwrap();
        apply_truthcoin_voted_consensus(&mut late_voted, 13).unwrap();
        assert_eq!(late_voted.export().unwrap(), late_voted_before);

        let mut corrupt = store.clone();
        corrupt
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                decision_id.to_vec(),
                vec![0],
            )
            .unwrap();
        let corrupt_before = corrupt.export().unwrap();
        assert_eq!(
            revert_truthcoin_no_vote_consensus(&mut corrupt, &undo),
            Err(ReplayError::InvalidTruthcoinVotingState)
        );
        assert_eq!(corrupt.export().unwrap(), corrupt_before);
        revert_truthcoin_no_vote_consensus(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);

        let voter = [8; 20];
        store
            .put(
                TruthcoinDatabaseId::Votes.as_u8(),
                truthcoin_vote_key(1, voter, decision_id),
                truthcoin_vote_value(TruthcoinDecisionKindV1::Binary, 1.0, 2_000, 3).unwrap(),
            )
            .unwrap();
        let voted_parent = store.export().unwrap();
        let voted_undo = apply_truthcoin_no_vote_consensus(&mut store, 10).unwrap();
        assert_eq!(store.export().unwrap(), voted_parent);
        assert!(voted_undo.changes.is_empty());
    }

    #[test]
    fn voted_consensus_updates_outcome_reputation_and_disconnects_atomically() {
        let decision_id = [0, 0, 0];
        let voters = [[7; 20], [8; 20], [9; 20]];
        let mut store = CanonicalStateStoreV1::new();
        for (database, timestamp) in [
            (TruthcoinDatabaseId::GenesisTimestamp, 1_000_u64),
            (
                TruthcoinDatabaseId::MainchainTimestamp,
                1_000 + 3 * TRUTHCOIN_PERIOD_SECONDS,
            ),
        ] {
            store
                .put(
                    database.as_u8(),
                    TRUTHCOIN_UNIT_KEY.to_vec(),
                    timestamp.to_le_bytes().to_vec(),
                )
                .unwrap();
        }
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                encode_truthcoin_state_history(&[(1, 1, None), (2, 2, None)]).unwrap(),
            )
            .unwrap();
        let decision = TruthcoinStoredDecisionV1 {
            market_maker: [6; 20],
            decision_type: DecodedTruthcoinDecisionTypeV1::Binary,
            header: "BTC/USD".into(),
            description: "binary fixture".into(),
            option_0_label: None,
            option_1_label: None,
            tags: Vec::new(),
        };
        store
            .put(
                TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                0_u32.to_le_bytes().to_vec(),
                encode_truthcoin_period_decisions(&[TruthcoinStoredDecisionEntryV1 {
                    decision_id,
                    decision: Some(decision),
                    claiming_txid: [5; 32],
                }])
                .unwrap(),
            )
            .unwrap();
        for (voter, reputation, vote) in [
            (voters[0], 0.2, 1.0),
            (voters[1], 0.3, 1.0),
            (voters[2], 0.5, 0.0),
        ] {
            set_truthcoin_reputation(&mut store, voter, reputation).unwrap();
            store
                .put(
                    TruthcoinDatabaseId::Votes.as_u8(),
                    truthcoin_vote_key(1, voter, decision_id),
                    truthcoin_vote_value(TruthcoinDecisionKindV1::Binary, vote, 2_000, 3).unwrap(),
                )
                .unwrap();
        }
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_voted_consensus(&mut store, 10).unwrap();
        assert!(!undo.changes.is_empty());
        let outcome = decode_truthcoin_decision_outcome(
            decision_id,
            store
                .get(TruthcoinDatabaseId::DecisionOutcomes.as_u8(), &decision_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.outcome_value, 1.0);
        assert_eq!(outcome.total_votes, 3);
        assert_eq!(outcome.total_reputation_weight, 1.0);
        assert_eq!(outcome.resolution.min_votes_required, 1);
        let reputation_total: f64 = store
            .entries(TruthcoinDatabaseId::Reputation.as_u8())
            .unwrap()
            .map(|(_, bytes)| decode_truthcoin_reputation(bytes).unwrap())
            .sum();
        assert_eq!(reputation_total, 1.0);

        let mut corrupt = store.clone();
        corrupt
            .put(
                TruthcoinDatabaseId::DecisionOutcomes.as_u8(),
                decision_id.to_vec(),
                vec![0],
            )
            .unwrap();
        let corrupt_before = corrupt.export().unwrap();
        assert_eq!(
            revert_truthcoin_voted_consensus(&mut corrupt, &undo),
            Err(ReplayError::InvalidTruthcoinVotingState)
        );
        assert_eq!(corrupt.export().unwrap(), corrupt_before);
        revert_truthcoin_voted_consensus(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
    }

    #[test]
    fn block_identity_derives_tip_and_rolls_back_atomically() {
        let prior_tip = [0x31; 32];
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: Vec::new(),
            authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
            actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
        };
        let header = truthcoin_header(&body, Some(prior_tip), [0x41; 32]);
        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::Tip.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                prior_tip.to_vec(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::Height.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                3_u32.to_le_bytes().to_vec(),
            )
            .unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_block_identity(&mut store, 4, &header).unwrap();
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Tip.as_u8(), &TRUTHCOIN_UNIT_KEY)
                .unwrap(),
            Some(blake3::hash(&header).as_bytes().as_slice())
        );
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Height.as_u8(), &TRUTHCOIN_UNIT_KEY)
                .unwrap(),
            Some(4_u32.to_le_bytes().as_slice())
        );
        let mut corrupt = store.clone();
        corrupt
            .put(
                TruthcoinDatabaseId::Tip.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                [0xff; 32].to_vec(),
            )
            .unwrap();
        let corrupt_before = corrupt.export().unwrap();
        assert_eq!(
            revert_truthcoin_block_identity(&mut corrupt, &undo),
            Err(ReplayError::InvalidTruthcoinHeaderEncoding)
        );
        assert_eq!(corrupt.export().unwrap(), corrupt_before);
        revert_truthcoin_block_identity(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
    }

    #[test]
    fn genesis_decision_frame_matches_patched_native_period_tables() {
        let mut store = CanonicalStateStoreV1::new();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        assert_eq!(
            store
                .entries(TruthcoinDatabaseId::PeriodDecisions.as_u8())
                .unwrap()
                .len(),
            20
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                    &1_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            0_u64.to_le_bytes()
        );
        assert_eq!(
            hex::encode(
                store
                    .get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &1_u32.to_le_bytes()
                    )
                    .unwrap()
                    .unwrap()
            ),
            "10270000000000007102000000000000140000000000000000000000000000000000000000000000000000001400000000000000"
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::PeriodPricingUndo.as_u8(),
                    &0_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            0_u64.to_le_bytes()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MintingUndo.as_u8(),
                    &0_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            0_u32.to_le_bytes()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MainchainTimestampUndo.as_u8(),
                    &0_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            [0]
        );
        for database in [
            TruthcoinDatabaseId::GenesisTimestamp,
            TruthcoinDatabaseId::MainchainTimestamp,
        ] {
            assert_eq!(
                store
                    .get(database.as_u8(), &TRUTHCOIN_UNIT_KEY)
                    .unwrap()
                    .unwrap(),
                1_000_u64.to_le_bytes()
            );
        }
        let connected = store.export().unwrap();
        revert_truthcoin_decision_block_frame(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        assert_eq!(store.export().unwrap(), connected);
    }

    #[test]
    fn ordinary_decision_frame_matches_native_snapshot_undo() {
        let mut store = CanonicalStateStoreV1::new();
        apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_decision_block_frame(&mut store, 1, 1_100).unwrap();
        let pricing_undo = store
            .get(
                TruthcoinDatabaseId::PeriodPricingUndo.as_u8(),
                &1_u32.to_le_bytes(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(pricing_undo)),
            "8cf250e85baa7a514b81f2a192af9a64bfcbc36db071bf1a52a23a4a1e5d36ac"
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MintingUndo.as_u8(),
                    &1_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            20_u32.to_le_bytes()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MainchainTimestampUndo.as_u8(),
                    &1_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            hex::decode("01e803000000000000").unwrap()
        );
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::MainchainTimestamp.as_u8(),
                    &TRUTHCOIN_UNIT_KEY
                )
                .unwrap()
                .unwrap(),
            1_100_u64.to_le_bytes()
        );
        let connected = store.export().unwrap();
        revert_truthcoin_decision_block_frame(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_decision_block_frame(&mut store, 1, 1_100).unwrap();
        assert_eq!(store.export().unwrap(), connected);
    }

    #[test]
    fn period_transition_mints_reprices_and_activates_claims_exactly() {
        let mut store = CanonicalStateStoreV1::new();
        apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        let decision_id = [1, 0, 0];
        let mut claimed = 1_u64.to_le_bytes().to_vec();
        claimed.extend_from_slice(&1_u32.to_le_bytes());
        claimed.extend_from_slice(&0_u32.to_le_bytes());
        claimed.push(0);
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                decision_id.to_vec(),
                claimed,
            )
            .unwrap();
        let parent = store.export().unwrap();
        let undo =
            apply_truthcoin_decision_block_frame(&mut store, 1, 1_000 + TRUTHCOIN_PERIOD_SECONDS)
                .unwrap();
        assert_eq!(
            decode_truthcoin_state_history(
                store
                    .get(
                        TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                        &decision_id
                    )
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            vec![(1, 0, None), (2, 1, None)]
        );
        assert_eq!(
            decode_truthcoin_period_pricing(
                store
                    .get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &2_u32.to_le_bytes()
                    )
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            TruthcoinPeriodPricingV1 {
                p_period: 5_000,
                p_floor: 625,
                mints: 20,
                claimed: 0,
                last_reprice_block: 1,
                window_open_claimed: 0,
                window_open_mints: 20,
            }
        );
        assert_eq!(
            decode_truthcoin_period_pricing(
                store
                    .get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &21_u32.to_le_bytes()
                    )
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            TruthcoinPeriodPricingV1 {
                p_period: 10_000,
                p_floor: 625,
                mints: 1,
                claimed: 0,
                last_reprice_block: 1,
                window_open_claimed: 0,
                window_open_mints: 1,
            }
        );
        assert!(store
            .get(
                TruthcoinDatabaseId::PeriodDecisions.as_u8(),
                &21_u32.to_le_bytes()
            )
            .unwrap()
            .is_some());
        let connected = store.export().unwrap();
        revert_truthcoin_decision_block_frame(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_decision_block_frame(&mut store, 1, 1_000 + TRUTHCOIN_PERIOD_SECONDS)
            .unwrap();
        assert_eq!(store.export().unwrap(), connected);
    }

    #[test]
    fn transaction_block_frame_snapshots_and_activates_only_parent_state() {
        let mut store = CanonicalStateStoreV1::new();
        apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        let parent_decision_id = [0, 0, 0];
        let same_block_decision_id = [0, 0, 1];
        let claimed = encode_truthcoin_state_history(&[(1, 0, None)]).unwrap();
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                parent_decision_id.to_vec(),
                claimed.clone(),
            )
            .unwrap();

        let height = 1;
        let timestamp = 1_000 + TRUTHCOIN_PERIOD_SECONDS;
        let expected_pricing_snapshot = encode_truthcoin_pricing_snapshot(
            &store
                .entries(TruthcoinDatabaseId::PeriodPricing.as_u8())
                .unwrap()
                .map(|(key, value)| (u32::from_le_bytes(key.try_into().unwrap()), value.to_vec()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        preinitialize_truthcoin_block_frame(&mut store, height, timestamp).unwrap();
        assert_eq!(
            decode_truthcoin_state_history(
                store
                    .get(
                        TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                        &parent_decision_id,
                    )
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
            vec![(1, 0, None), (2, 1, None)]
        );

        // Model transaction execution after the native pre-block frame: a
        // newly claimed Decision and changed pricing must not be folded back
        // into the parent-state activation or undo snapshot.
        store
            .put(
                TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                same_block_decision_id.to_vec(),
                claimed,
            )
            .unwrap();
        let mut changed_pricing = decode_truthcoin_period_pricing(
            store
                .get(
                    TruthcoinDatabaseId::PeriodPricing.as_u8(),
                    &1_u32.to_le_bytes(),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        changed_pricing.claimed += 1;
        store
            .put(
                TruthcoinDatabaseId::PeriodPricing.as_u8(),
                1_u32.to_le_bytes().to_vec(),
                encode_truthcoin_period_pricing(changed_pricing),
            )
            .unwrap();
        apply_truthcoin_decision_block_frame(&mut store, height, timestamp).unwrap();

        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::PeriodPricingUndo.as_u8(),
                    &height.to_le_bytes(),
                )
                .unwrap()
                .unwrap(),
            expected_pricing_snapshot
        );
        assert_eq!(
            decode_truthcoin_state_history(
                store
                    .get(
                        TruthcoinDatabaseId::DecisionStateHistories.as_u8(),
                        &same_block_decision_id,
                    )
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
            vec![(1, 0, None)]
        );
    }

    #[test]
    fn multi_epoch_frames_disconnect_and_replay_byte_identically() {
        let genesis_timestamp = 1_000;
        let mut store = CanonicalStateStoreV1::new();
        let mut checkpoints = vec![store.export().unwrap()];
        let mut undos = Vec::new();
        for height in 0..=4_u32 {
            let timestamp =
                genesis_timestamp + u64::from(height).saturating_mul(TRUTHCOIN_PERIOD_SECONDS);
            undos
                .push(apply_truthcoin_decision_block_frame(&mut store, height, timestamp).unwrap());
            checkpoints.push(store.export().unwrap());
        }

        for height in (0..=4_usize).rev() {
            revert_truthcoin_decision_block_frame(&mut store, &undos[height]).unwrap();
            assert_eq!(store.export().unwrap(), checkpoints[height]);
        }
        for height in 0..=4_u32 {
            let timestamp =
                genesis_timestamp + u64::from(height).saturating_mul(TRUTHCOIN_PERIOD_SECONDS);
            apply_truthcoin_decision_block_frame(&mut store, height, timestamp).unwrap();
            assert_eq!(store.export().unwrap(), checkpoints[height as usize + 1]);
        }
    }

    #[test]
    fn standard_decision_listing_fee_is_consensus_enforced() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut owner = [0_u8; 20];
        blake3::Hasher::new()
            .update(verifying_key.as_bytes())
            .finalize_xof()
            .fill(&mut owner);
        let input_key: [u8; 37] = {
            let mut key = [0_u8; 37];
            key[0] = 2;
            key[1..33].copy_from_slice(&[0x71; 32]);
            key
        };
        let make_body = |output_amount: u64| {
            let mut transaction = 1_u32.to_le_bytes().to_vec();
            transaction.extend_from_slice(&input_key);
            transaction.extend_from_slice(&1_u32.to_le_bytes());
            transaction.extend_from_slice(&owner);
            transaction.push(0);
            transaction.extend_from_slice(&output_amount.to_le_bytes());
            transaction.extend_from_slice(&0_u32.to_le_bytes());
            transaction.extend_from_slice(&0_u32.to_le_bytes());
            transaction.push(1);
            transaction.push(0); // ClaimDecision
            transaction.push(0); // Binary
            transaction.extend_from_slice(&1_u32.to_le_bytes());
            transaction.extend_from_slice(&[0x81, 0, 0]); // standard period 1, slot 0
            transaction.extend_from_slice(&3_u32.to_le_bytes());
            transaction.extend_from_slice(b"BTC");
            transaction.extend_from_slice(&3_u32.to_le_bytes());
            transaction.extend_from_slice(b"USD");
            transaction.extend_from_slice(&[0, 0, 0, 0]);
            let mut message = vec![0];
            message.extend_from_slice(&transaction);
            let mut authorizations = 1_u32.to_le_bytes().to_vec();
            authorizations.extend_from_slice(verifying_key.as_bytes());
            authorizations.extend_from_slice(&signing_key.sign(&message).to_bytes());
            TruthcoinBodyV1 {
                coinbase_borsh: 0_u32.to_le_bytes().to_vec(),
                transactions_borsh: vec![transaction],
                authorizations_borsh: authorizations,
                actor_proofs_borsh: vec![1, 0, 0, 0, 0],
            }
        };

        let mut store = CanonicalStateStoreV1::new();
        apply_truthcoin_decision_block_frame(&mut store, 0, 1_000).unwrap();
        let mut input_value = owner.to_vec();
        input_value.extend_from_slice(&0_u32.to_le_bytes());
        input_value.extend_from_slice(&10_000_u64.to_le_bytes());
        input_value.extend_from_slice(&0_u64.to_le_bytes());
        store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                input_key.to_vec(),
                input_value,
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::UtxosByAddress.as_u8(),
                truthcoin_address_index_key(owner, &input_key),
                Vec::new(),
            )
            .unwrap();
        let accepted = make_body(7_500);
        assert_eq!(
            validate_truthcoin_decision_claims(&store, &accepted),
            Ok(())
        );
        let undo = apply_truthcoin_decision_claim_mutations(&mut store, &accepted, 1).unwrap();
        assert_eq!(
            decode_truthcoin_period_pricing(
                store
                    .get(
                        TruthcoinDatabaseId::PeriodPricing.as_u8(),
                        &1_u32.to_le_bytes()
                    )
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .claimed,
            1
        );
        revert_truthcoin_decision_claim_mutations(&mut store, &undo).unwrap();

        let underpaid = make_body(7_501);
        let before = store.export().unwrap();
        assert_eq!(
            apply_truthcoin_decision_claim_mutations(&mut store, &underpaid, 1),
            Err(ReplayError::InvalidTruthcoinDecisionClaim)
        );
        assert_eq!(store.export().unwrap(), before);

        // Exercise the production block boundary as well as the specialized
        // mutation. The valid control must connect, while the one-satoshi
        // underpayment must roll back the preinitialized timestamp and every
        // other table mutation atomically.
        let prior_tip = [0x72; 32];
        store
            .put(
                TruthcoinDatabaseId::Tip.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                prior_tip.to_vec(),
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::Height.as_u8(),
                TRUTHCOIN_UNIT_KEY.to_vec(),
                0_u32.to_le_bytes().to_vec(),
            )
            .unwrap();
        let execute = |state: &mut CanonicalStateStoreV1, body: TruthcoinBodyV1| {
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: 1,
                bmm_main_height: 1,
                header_borsh: truthcoin_header(&body, Some(prior_tip), [0x73; 32]),
                body,
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: 1,
                bmm_main_block_hash: [0x74; 32],
                bmm_main_height: 1,
                bmm_main_timestamp: 1_100,
                bmm_main_mtp: 1_100,
            };
            apply_truthcoin_block_transition(state, &block, context)
        };
        let mut valid_control = store.clone();
        execute(&mut valid_control, accepted.clone()).unwrap();
        // A parent-clock jump must not retroactively invalidate a claim
        // prevalidated under the stored clock (native prevalidate/connect).
        let mut clock_jump = store.clone();
        let jump_block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 1,
            bmm_main_height: 1,
            header_borsh: truthcoin_header(&accepted, Some(prior_tip), [0x73; 32]),
            body: accepted.clone(),
        };
        let jump_context = CanonicalBlockContextV1 {
            sidechain_block_hash: jump_block.block_hash(),
            sidechain_height: 1,
            bmm_main_block_hash: [0x74; 32],
            bmm_main_height: 1,
            bmm_main_timestamp: 1_000 + 2 * TRUTHCOIN_PERIOD_SECONDS,
            bmm_main_mtp: 1_000 + 2 * TRUTHCOIN_PERIOD_SECONDS,
        };
        apply_truthcoin_block_transition(&mut clock_jump, &jump_block, jump_context).unwrap();
        assert_ne!(valid_control.export().unwrap(), store.export().unwrap());
        let connected = valid_control.export().unwrap();
        let connected_tip: [u8; 32] = valid_control
            .get(TruthcoinDatabaseId::Tip.as_u8(), &TRUTHCOIN_UNIT_KEY)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();
        let replay_block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 2,
            bmm_main_height: 2,
            header_borsh: truthcoin_header(&accepted, Some(connected_tip), [0x75; 32]),
            body: accepted.clone(),
        };
        let replay_context = CanonicalBlockContextV1 {
            sidechain_block_hash: replay_block.block_hash(),
            sidechain_height: 2,
            bmm_main_block_hash: [0x76; 32],
            bmm_main_height: 2,
            bmm_main_timestamp: 1_101,
            bmm_main_mtp: 1_101,
        };
        assert_eq!(
            apply_truthcoin_block_transition(&mut valid_control, &replay_block, replay_context),
            Err(ReplayError::MissingTruthcoinUtxo)
        );
        assert_eq!(valid_control.export().unwrap(), connected);

        let parent = store.export().unwrap();
        assert_eq!(
            execute(&mut store, underpaid),
            Err(ReplayError::InvalidTruthcoinDecisionClaim)
        );
        assert_eq!(store.export().unwrap(), parent);

        let mut bad_signature = accepted.clone();
        bad_signature.authorizations_borsh[36] ^= 1;
        let mut missing_authorization = accepted.clone();
        missing_authorization.authorizations_borsh = 0_u32.to_le_bytes().to_vec();
        let mut surplus_authorization = accepted;
        let authorization = surplus_authorization.authorizations_borsh[4..].to_vec();
        surplus_authorization.authorizations_borsh = 2_u32.to_le_bytes().to_vec();
        surplus_authorization
            .authorizations_borsh
            .extend_from_slice(&authorization);
        surplus_authorization
            .authorizations_borsh
            .extend_from_slice(&authorization);
        for malformed in [bad_signature, missing_authorization, surplus_authorization] {
            assert_eq!(
                execute(&mut store, malformed),
                Err(ReplayError::InvalidTruthcoinAuthorization)
            );
            assert_eq!(store.export().unwrap(), parent);
        }
    }

    #[test]
    fn output_wire_layouts_match_pinned_truthcoin_017() {
        // Exact regular transactions emitted by patched upstream 0.17 for its
        // Bitcoin, withdrawal and MarketFunds output variants.
        let vectors = [
            "00000000010000000101010101010101010101010101010101010101002a00000000000000000000000000000000",
            concat!(
                "000000000100000001010101010101010101010101010101010101010164000000",
                "0000000002000000000000003e0000007462317175776376677335636c73777066",
                "78686d376e79666a6d616579736e3675733079766a6465786e39796a6b76336b37",
                "7a6a6870327337687a386137000000000000000000"
            ),
            "00000000010000000101010101010101010101010101010101010101020303030303034d0000000000000001000000000000000000",
        ];
        for vector in vectors {
            assert_eq!(
                decode_truthcoin_transaction_prefix(&hex::decode(vector).unwrap()),
                Ok(0)
            );
        }

        let mut invalid_output_variant = hex::decode(vectors[0]).unwrap();
        invalid_output_variant[28] = 3;
        assert_eq!(
            decode_truthcoin_transaction_prefix(&invalid_output_variant),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );

        let mut invalid_market_funds_bool = hex::decode(vectors[2]).unwrap();
        invalid_market_funds_bool[43] = 2;
        assert_eq!(
            decode_truthcoin_transaction_prefix(&invalid_market_funds_bool),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );

        let mut trailing_regular = hex::decode(vectors[0]).unwrap();
        trailing_regular.push(0);
        assert_eq!(
            decode_truthcoin_transaction_prefix(&trailing_regular),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );
    }

    #[test]
    fn filled_output_bincode_matches_all_pinned_truthcoin_017_variants() {
        let vectors = [
            "0101010101010101010101010101010101010101000000002a0000000000000002000000000000000203",
            concat!(
                "0101010101010101010101010101010101010101010000006400000000000000",
                "02000000000000003e000000000000007462317175776376677335636c73777066",
                "78686d376e79666a6d616579736e3675733079766a6465786e39796a6b76336b37",
                "7a6a6870327337687a386137010000000000000004"
            ),
            "0101010101010101010101010101010101010101020000000303030303034d00000000000000010300000000000000050607",
        ];
        for vector in vectors {
            let bytes = hex::decode(vector).unwrap();
            let output = decode_truthcoin_filled_output(&bytes).unwrap();
            assert_eq!(output.address, [1; 20]);
        }
    }

    #[test]
    fn canonical_withdrawal_state_connect_disconnect_matches_patched_upstream() {
        let transaction = hex::decode(concat!(
            "000000000100000001010101010101010101010101010101010101010164000000",
            "0000000002000000000000003e0000007462317175776376677335636c73777066",
            "78686d376e79666a6d616579736e3675733079766a6465786e39796a6b76336b37",
            "7a6a6870327337687a386137000000000000000000"
        ))
        .unwrap();
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: vec![transaction.clone()],
            authorizations_borsh: vec![0, 0, 0, 0],
            actor_proofs_borsh: vec![1, 0, 0, 0, 0],
        };
        let mut store = CanonicalStateStoreV1::new();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_base_utxo_transition(&mut store, &body).unwrap();
        let connected = store.export().unwrap();
        let output_key = truthcoin_regular_outpoint_key(*blake3::hash(&transaction).as_bytes(), 0);
        assert_eq!(
            store
                .get(TruthcoinDatabaseId::Utxos.as_u8(), &output_key)
                .unwrap()
                .unwrap(),
            hex::decode(concat!(
                "0101010101010101010101010101010101010101010000006400000000000000",
                "02000000000000003e000000000000007462317175776376677335636c73777066",
                "78686d376e79666a6d616579736e3675733079766a6465786e39796a6b76336b37",
                "7a6a6870327337687a3861370000000000000000"
            ))
            .unwrap()
        );
        revert_truthcoin_base_utxo_transition(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        apply_truthcoin_base_utxo_transition(&mut store, &body).unwrap();
        assert_eq!(store.export().unwrap(), connected);
    }

    #[test]
    fn transaction_data_layouts_match_all_pinned_truthcoin_017_variants() {
        let vectors = [
            "00000000000000000000000001000001000000000000070000004254432f55534405000000707269636500000001020000000300000062746303000000757364",
            "0000000000000000000000000101070000004254432f5553440c0000007072696365206d61726b6574010000000000000000000000017b14ae47e17a843f010001010102",
            "000000000000000000000000010202020202020201000000fdffffffffffffff040404040404040404040404040404040404040405000000000000000106000000000000000707070707070707070707070707070707070707070707070707070707070707",
            "00000000000000000000000001030808080808080808080808080808080808080808000000000000000000d03f09000000",
            "00000000000000000000000001040a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a01000000000000000000000000e83f0b000000",
            "00000000000000000000000001050c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d000000000000e03f",
            "00000000000000000000000001060e0e0e0e0e0e0f000000000000001010101010101010101010101010101010101010",
        ];
        for vector in vectors {
            assert_eq!(
                decode_truthcoin_transaction_prefix(&hex::decode(vector).unwrap()),
                Ok(0)
            );
        }

        let mut unknown_data_variant = hex::decode(vectors[6]).unwrap();
        unknown_data_variant[13] = 7;
        assert_eq!(
            decode_truthcoin_transaction_prefix(&unknown_data_variant),
            Err(ReplayError::InvalidTruthcoinTransactionEncoding)
        );
    }

    #[test]
    fn reputation_transfer_connect_disconnect_replay_is_exact_and_atomic() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut sender = [0_u8; 20];
        blake3::Hasher::new()
            .update(verifying_key.as_bytes())
            .finalize_xof()
            .fill(&mut sender);
        let destination = [0x42; 20];
        let mut transaction = Vec::new();
        transaction.extend_from_slice(&1_u32.to_le_bytes());
        transaction.push(2); // Deposit(bitcoin::OutPoint)
        transaction.extend_from_slice(&[0x19; 32]);
        transaction.extend_from_slice(&0_u32.to_le_bytes());
        transaction.extend_from_slice(&0_u32.to_le_bytes()); // outputs
        transaction.extend_from_slice(&0_u32.to_le_bytes()); // memo
        transaction.push(1); // Some(TransactionData)
        transaction.push(5); // TransferReputation
        transaction.extend_from_slice(&sender);
        transaction.extend_from_slice(&destination);
        transaction.extend_from_slice(&0.4_f64.to_le_bytes());

        let mut message = vec![0];
        message.extend_from_slice(&transaction);
        let signature = signing_key.sign(&message);
        let mut authorizations_borsh = 1_u32.to_le_bytes().to_vec();
        authorizations_borsh.extend_from_slice(verifying_key.as_bytes());
        authorizations_borsh.extend_from_slice(&signature.to_bytes());
        let body = TruthcoinBodyV1 {
            coinbase_borsh: Vec::new(),
            transactions_borsh: vec![transaction],
            authorizations_borsh,
            actor_proofs_borsh: vec![1, 0, 0, 0, 0],
        };
        let input_key: [u8; 37] = {
            let mut key = [0_u8; 37];
            key[0] = 2;
            key[1..33].copy_from_slice(&[0x19; 32]);
            key
        };
        let mut input_value = sender.to_vec();
        input_value.extend_from_slice(&0_u32.to_le_bytes());
        input_value.extend_from_slice(&50_000_u64.to_le_bytes());
        input_value.extend_from_slice(&0_u64.to_le_bytes());

        let mut store = CanonicalStateStoreV1::new();
        store
            .put(
                TruthcoinDatabaseId::Utxos.as_u8(),
                input_key.to_vec(),
                input_value,
            )
            .unwrap();
        store
            .put(
                TruthcoinDatabaseId::Reputation.as_u8(),
                sender.to_vec(),
                1.0_f64.to_le_bytes().to_vec(),
            )
            .unwrap();
        let parent = store.export().unwrap();
        let undo = apply_truthcoin_reputation_transitions(&mut store, &body, 9).unwrap();
        assert_eq!(get_truthcoin_reputation(&store, &sender).unwrap(), 0.6);
        assert_eq!(get_truthcoin_reputation(&store, &destination).unwrap(), 0.4);
        let mut expected_undo = 1_u64.to_le_bytes().to_vec();
        expected_undo.extend_from_slice(&sender);
        expected_undo.extend_from_slice(&1.0_f64.to_le_bytes());
        expected_undo.extend_from_slice(&destination);
        expected_undo.extend_from_slice(&0.0_f64.to_le_bytes());
        assert_eq!(
            store
                .get(
                    TruthcoinDatabaseId::ReputationTransferUndo.as_u8(),
                    &9_u32.to_le_bytes()
                )
                .unwrap()
                .unwrap(),
            expected_undo
        );
        let connected = store.export().unwrap();
        revert_truthcoin_reputation_transitions(&mut store, &undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);
        let replay_undo = apply_truthcoin_reputation_transitions(&mut store, &body, 9).unwrap();
        assert_eq!(store.export().unwrap(), connected);
        revert_truthcoin_reputation_transitions(&mut store, &replay_undo).unwrap();
        assert_eq!(store.export().unwrap(), parent);

        let mut invalid = store.clone();
        invalid
            .put(
                TruthcoinDatabaseId::Reputation.as_u8(),
                sender.to_vec(),
                0.1_f64.to_le_bytes().to_vec(),
            )
            .unwrap();
        let before = invalid.export().unwrap();
        assert_eq!(
            apply_truthcoin_reputation_transitions(&mut invalid, &body, 9),
            Err(ReplayError::InvalidTruthcoinReputationTransfer)
        );
        assert_eq!(invalid.export().unwrap(), before);
    }

    #[test]
    fn state_machine_candidates_have_one_combined_ceiling() {
        let fixture = fixture();
        let anchor = fixture.state.anchors[0].clone();
        let market = fixture.state.markets[0].clone();
        let mut state = StateMachineOutputV1 {
            version: StateMachineOutputV1::VERSION,
            replayed_state_root: [1; 32],
            anchors: vec![anchor; MAX_STATE_MACHINE_CANDIDATES],
            markets: Vec::new(),
        };
        assert_eq!(validate_state_machine_output_bounds(&state), Ok(()));
        state.markets.push(market);
        assert_eq!(
            validate_state_machine_output_bounds(&state),
            Err(ReplayError::CandidateBounds)
        );
    }

    #[test]
    fn bip300_transition_preserves_checkpoint_and_wrapper_results() {
        let mut input = fixture().input;
        for ctip in [None, Some(Bip300CtipV1 {
            txid: [7; 32], vout: 2, value_sats: 1234, sequence_number: 9,
        })] {
            input.bip300_checkpoint_state.ctip = ctip;
            input.authentication.bip300_checkpoint_state_hash = input.bip300_checkpoint_state.digest();
            let result = verify_truthcoin_bip300_transition(&input).unwrap();
            assert_eq!(result.final_ctip, ctip);
            assert!(result.deposits.is_empty());
            assert_eq!(verify_truthcoin_bip300_deposits(&input).unwrap(), result.deposits);
        }
        input.authentication.bip300_checkpoint_state_hash = [0; 32];
        assert_eq!(verify_truthcoin_bip300_transition(&input), Err(ReplayError::InvalidBip300CheckpointState));
        assert_eq!(verify_truthcoin_bip300_deposits(&input), Err(ReplayError::InvalidBip300CheckpointState));
    }

    // Synthetic source values for authority mapping unit tests only. This does
    // not make a production AuthorityReplayOutput or qualify a real replay.
    pub(super) fn authority_mapping_fixture() -> (ReplayInputV1, ReplayOutputV1) {
        let f = fixture();
        let structure = verify_replay_structure(&f.input).unwrap();
        let output = finalize_replay_output(&f.input, &structure, &f.state).unwrap();
        (f.input, output)
    }

    fn fixture() -> Fixture {
        let market_template = TruthcoinMarketTemplateCommitmentV1 {
            version: TruthcoinMarketTemplateCommitmentV1::VERSION,
            market_title_template: "BTC/USD {period}".to_owned(),
            market_description_template: "Bitcoin price in USD".to_owned(),
            decision_header_template: "BTC/USD".to_owned(),
            decision_description_template: "Final scalar price".to_owned(),
            decision_tags: vec!["btc".to_owned(), "usd".to_owned()],
            scalar_min_f64_bits: 40_000_f64.to_bits(),
            scalar_max_f64_bits: 80_000_f64.to_bits(),
            scalar_increment_f64_bits: 1_f64.to_bits(),
            minimum_liquidity_sats: 10_000,
            trading_fee_ppm: 1_000,
            tx_pow_hash_selector: 0,
            tx_pow_ordering: 0,
            tx_pow_difficulty: 1,
        };

        let mut checkpoint_context = Vec::with_capacity(BITCOIN_MTP_WINDOW - 1);
        let mut previous = BlockHash::all_zeros();
        for index in 0..BITCOIN_MTP_WINDOW - 1 {
            let header = mine_easy_header(
                previous,
                TxMerkleNode::from_byte_array([index as u8 + 1; 32]),
                CONTEXT_START_TIME + index as u32,
            );
            previous = header.block_hash();
            checkpoint_context.push(header);
        }

        let genesis_body = truthcoin_body(0x10);
        let genesis_header = truthcoin_header(&genesis_body, None, previous.to_byte_array());
        let genesis = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 0,
            bmm_main_height: CHECKPOINT_HEIGHT,
            header_borsh: genesis_header,
            body: genesis_body,
        };
        let checkpoint_coinbase =
            coinbase_with_outputs(CHECKPOINT_HEIGHT, vec![m7_script(genesis.block_hash())]);
        let checkpoint = mine_easy_header(
            previous,
            checkpoint_coinbase.compute_txid().into(),
            CONTEXT_START_TIME + 10,
        );

        let child_body = truthcoin_body(0x20);
        let child_header = truthcoin_header(
            &child_body,
            Some(genesis.block_hash()),
            checkpoint.block_hash().to_byte_array(),
        );
        let child = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 1,
            bmm_main_height: CHECKPOINT_HEIGHT + 1,
            header_borsh: child_header,
            body: child_body,
        };
        let child_coinbase =
            coinbase_with_outputs(CHECKPOINT_HEIGHT + 1, vec![m7_script(child.block_hash())]);
        let header_one = mine_easy_header(
            checkpoint.block_hash(),
            child_coinbase.compute_txid().into(),
            CONTEXT_START_TIME + 11,
        );
        let coinbase_two = coinbase_with_outputs(CHECKPOINT_HEIGHT + 2, Vec::new());
        let header_two = mine_easy_header(
            header_one.block_hash(),
            coinbase_two.compute_txid().into(),
            CONTEXT_START_TIME + 12,
        );
        let coinbase_three = coinbase_with_outputs(CHECKPOINT_HEIGHT + 3, Vec::new());
        let header_three = mine_easy_header(
            header_two.block_hash(),
            coinbase_three.compute_txid().into(),
            CONTEXT_START_TIME + 13,
        );

        let bitcoin_headers = vec![checkpoint, header_one, header_two, header_three];
        let parent_mtp = median_time_past(&checkpoint_context, &bitcoin_headers, 3).unwrap();
        let genesis_hash = genesis.block_hash();
        let authentication = ecx_protocol_core::TruthcoinAuthenticationConfigV1 {
            version: ecx_protocol_core::TruthcoinAuthenticationConfigV1::VERSION,
            source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
            consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
            source_patch_manifest_sha256:
                ecx_truthcoin_proof::TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
            sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
            bitcoin_checkpoint_hash: checkpoint.block_hash().to_byte_array(),
            bitcoin_checkpoint_height: CHECKPOINT_HEIGHT,
            bip300_checkpoint_state_hash: TruthcoinBip300CheckpointStateV1 {
                version: TruthcoinBip300CheckpointStateV1::VERSION,
                truthcoin_slot_active: true,
                ctip: None,
            }
            .digest(),
            genesis_sidechain_block_hash: genesis_hash,
            truthcoin_chain_id: pinned_truthcoin_chain_id(genesis_hash),
            truthcoin_branch_id: [0x44; 32],
            btc_usd_template_hash: market_template.digest(),
            lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
            source_proof_program_id: [0x55; 32],
            selection_rule_hash: [0x66; 32],
            minimum_bitcoin_confirmations: 3,
            maximum_proof_bytes: 1_024,
        };
        let input = ReplayInputV1 {
            version: REPLAY_INPUT_VERSION,
            authentication,
            parent: ParentChainContextV1 {
                block_hash: header_three.block_hash().to_byte_array(),
                height: CHECKPOINT_HEIGHT + 3,
                median_time_past: parent_mtp,
            },
            market_template,
            bip300_checkpoint_state: TruthcoinBip300CheckpointStateV1 {
                version: TruthcoinBip300CheckpointStateV1::VERSION,
                truthcoin_slot_active: true,
                ctip: None,
            },
            mainchain_headers: bitcoin_headers
                .iter()
                .enumerate()
                .map(|(index, header)| MainchainHeaderV1 {
                    height: CHECKPOINT_HEIGHT + index as u64,
                    consensus_header: serialize(header),
                })
                .collect(),
            checkpoint_mtp_headers: checkpoint_context.iter().map(serialize).collect(),
            coinbase_inclusions: vec![
                coinbase_inclusion(CHECKPOINT_HEIGHT, &checkpoint_coinbase),
                coinbase_inclusion(CHECKPOINT_HEIGHT + 1, &child_coinbase),
                coinbase_inclusion(CHECKPOINT_HEIGHT + 2, &coinbase_two),
                coinbase_inclusion(CHECKPOINT_HEIGHT + 3, &coinbase_three),
            ],
            mainchain_block_transactions: vec![
                MainchainBlockTransactionsV1 {
                    version: MainchainBlockTransactionsV1::VERSION,
                    height: CHECKPOINT_HEIGHT,
                    transactions: vec![serialize(&checkpoint_coinbase)],
                },
                MainchainBlockTransactionsV1 {
                    version: MainchainBlockTransactionsV1::VERSION,
                    height: CHECKPOINT_HEIGHT + 1,
                    transactions: vec![serialize(&child_coinbase)],
                },
                MainchainBlockTransactionsV1 {
                    version: MainchainBlockTransactionsV1::VERSION,
                    height: CHECKPOINT_HEIGHT + 2,
                    transactions: vec![serialize(&coinbase_two)],
                },
                MainchainBlockTransactionsV1 {
                    version: MainchainBlockTransactionsV1::VERSION,
                    height: CHECKPOINT_HEIGHT + 3,
                    transactions: vec![serialize(&coinbase_three)],
                },
            ],
            sidechain_blocks: vec![genesis, child],
        };
        let structure = verify_replay_structure(&input).unwrap();
        let state = state_machine_output(&input, &structure.canonical_block_contexts);
        Fixture {
            input,
            state,
            contexts: structure.canonical_block_contexts,
        }
    }

    fn state_machine_output(
        input: &ReplayInputV1,
        contexts: &[CanonicalBlockContextV1],
    ) -> StateMachineOutputV1 {
        let source = contexts[1];
        let source_confirmations =
            u32::try_from(input.parent.height - source.bmm_main_height + 1).unwrap();
        let anchor_id = [0x81, 0, 1];
        let market_decision_id = [0x82, 0, 1];
        let market_id = [1, 2, 3, 4, 5, 6];
        let liquidity = 10_000;
        let beta = liquidity as f64 / libm::log(2.0);
        let shares = [0, 100];
        let probability = upstream_binary_lmsr_probability(shares, beta).unwrap();

        let primary_anchor = AnchorCandidateV1 {
            native_decision_id: anchor_id,
            template_hash: input.authentication.btc_usd_template_hash,
            finalized: true,
            anchor: TruthcoinAnchorV1 {
                version: TruthcoinAnchorV1::VERSION,
                truthcoin_chain_id: input.authentication.truthcoin_chain_id,
                branch_id: input.authentication.truthcoin_branch_id,
                template_hash: input.authentication.btc_usd_template_hash,
                epoch: 1,
                decision_id: native_decision_id_hash(
                    input.authentication.truthcoin_chain_id,
                    anchor_id,
                ),
                slot_id: [0x70; 32],
                source_block_hash: source.sidechain_block_hash,
                source_state_root: [0x71; 32],
                source_height: source.sidechain_height,
                source_mtp: source.bmm_main_mtp,
                source_confirmations,
                observation_end_mtp: source.bmm_main_mtp - 2,
                finalized_at_mtp: source.bmm_main_mtp,
                btc_usd_price: Price::new(60_000 * PRICE_SCALE).unwrap(),
            },
        };
        let mut alternate_anchor = primary_anchor.clone();
        alternate_anchor.native_decision_id = [0x81, 0, 2];
        alternate_anchor.anchor.decision_id = native_decision_id_hash(
            input.authentication.truthcoin_chain_id,
            alternate_anchor.native_decision_id,
        );

        let primary_market = MarketCandidateV1 {
            native_decision_id: market_decision_id,
            native_market_id: market_id,
            template_hash: input.authentication.btc_usd_template_hash,
            is_open: true,
            market_creation_txid: [0x80; 32],
            market_created_height: 0,
            market_first_eligible_height: 1,
            liquidity_base_sats: liquidity,
            beta_f64_bits: beta.to_bits(),
            shares,
            selected_outcome_index: 1,
            probability_f64_bits: probability.to_bits(),
            snapshot: TruthcoinLmsrSnapshotV1 {
                version: TruthcoinLmsrSnapshotV1::VERSION,
                truthcoin_chain_id: input.authentication.truthcoin_chain_id,
                branch_id: input.authentication.truthcoin_branch_id,
                template_hash: input.authentication.btc_usd_template_hash,
                epoch: 2,
                decision_id: native_decision_id_hash(
                    input.authentication.truthcoin_chain_id,
                    market_decision_id,
                ),
                market_id: native_market_id_hash(
                    input.authentication.truthcoin_chain_id,
                    market_id,
                ),
                slot_id: [0x81; 32],
                registry_root: [0x82; 32],
                selection_proof_root: [0x83; 32],
                source_block_hash: source.sidechain_block_hash,
                source_state_root: [0x84; 32],
                source_height: source.sidechain_height,
                source_mtp: source.bmm_main_mtp,
                source_confirmations,
                epoch_start_mtp: source.bmm_main_mtp,
                resolves_at_mtp: input.parent.median_time_past + 1_000,
                scalar_lower_bound: Price::new(50_000 * PRICE_SCALE).unwrap(),
                scalar_upper_bound: Price::new(70_000 * PRICE_SCALE).unwrap(),
                lmsr_b: beta.floor() as u64,
                yes_probability_ppb: probability_to_ppb(probability).unwrap(),
                sample_window_root: [0x85; 32],
                sample_count: 3,
                lmsr_state_root: native_lmsr_state_root(
                    market_id,
                    liquidity,
                    beta.to_bits(),
                    shares,
                ),
                saturated: false,
            },
        };
        let mut alternate_market = primary_market.clone();
        alternate_market.native_decision_id = [0x82, 0, 2];
        alternate_market.native_market_id = [2, 2, 3, 4, 5, 6];
        alternate_market.market_creation_txid = [0x90; 32];
        alternate_market.snapshot.decision_id = native_decision_id_hash(
            input.authentication.truthcoin_chain_id,
            alternate_market.native_decision_id,
        );
        alternate_market.snapshot.market_id = native_market_id_hash(
            input.authentication.truthcoin_chain_id,
            alternate_market.native_market_id,
        );
        alternate_market.snapshot.lmsr_state_root = native_lmsr_state_root(
            alternate_market.native_market_id,
            liquidity,
            beta.to_bits(),
            shares,
        );

        StateMachineOutputV1 {
            version: StateMachineOutputV1::VERSION,
            replayed_state_root: [0xa0; 32],
            // Put the lexicographically preferred candidates last to prove the
            // host/state-machine iteration order cannot control selection.
            anchors: vec![alternate_anchor, primary_anchor],
            markets: vec![alternate_market, primary_market],
        }
    }

    fn truthcoin_body(seed: u8) -> TruthcoinBodyV1 {
        let mut coinbase_borsh = 1_u32.to_le_bytes().to_vec();
        coinbase_borsh.extend_from_slice(&[seed; 20]);
        coinbase_borsh.push(0);
        // Synthetic fixtures have no fee-paying transactions, so their
        // coinbase output must be zero-valued under the pinned block-fee rule.
        coinbase_borsh.extend_from_slice(&0_u64.to_le_bytes());
        coinbase_borsh.extend_from_slice(&0_u32.to_le_bytes());
        TruthcoinBodyV1 {
            coinbase_borsh,
            // Canonical empty regular transaction: zero inputs, zero outputs,
            // empty memo and `None` transaction data.
            transactions_borsh: vec![vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            // Canonical Borsh `Vec<Authorization>` with zero entries.
            authorizations_borsh: vec![0, 0, 0, 0],
            // Canonical Borsh `Vec<Option<Authorization>>` with one `None`.
            actor_proofs_borsh: vec![1, 0, 0, 0, 0],
        }
    }

    #[derive(Debug, Clone)]
    struct DeterministicIncrementalStateMachine {
        output: IncrementalStateMachineOutputV1,
    }

    impl Truthcoin017StateMachine for DeterministicIncrementalStateMachine {
        fn replay(
            &self,
            _template: &TruthcoinMarketTemplateCommitmentV1,
            _canonical_blocks: &[TruthcoinBlockV1],
            _canonical_contexts: &[CanonicalBlockContextV1],
        ) -> Result<StateMachineOutputV1, ReplayError> {
            Err(ReplayError::StateMachineUnlinked)
        }

        fn replay_incremental(
            &self,
            _template: &TruthcoinMarketTemplateCommitmentV1,
            _prior: &StateMachineCheckpointV1,
            _canonical_delta_blocks: &[TruthcoinBlockV1],
            _canonical_delta_contexts: &[CanonicalBlockContextV1],
        ) -> Result<IncrementalStateMachineOutputV1, ReplayError> {
            Ok(self.output.clone())
        }
    }

    #[test]
    fn incremental_checkpoint_requires_exact_contiguous_successor() {
        let fixture = fixture();
        let prior_tip = [0xb0; 32];
        let prior_snapshot = canonical_snapshot(1);
        let prior = StateMachineCheckpointV1 {
            version: StateMachineCheckpointV1::VERSION,
            trusted_start: None,
            authentication_config_hash: fixture.input.authentication.digest(),
            market_template_hash: fixture.input.market_template.digest(),
            sidechain_tip_hash: prior_tip,
            sidechain_tip_height: 20,
            replayed_state_root: prior_snapshot.root().unwrap(),
            state_bytes: prior_snapshot.encode().unwrap(),
        };
        let body = truthcoin_body(0xb2);
        let block = TruthcoinBlockV1 {
            version: TruthcoinBlockV1::VERSION,
            height: 21,
            bmm_main_height: 3_000,
            header_borsh: truthcoin_header(&body, Some(prior_tip), [0xb3; 32]),
            body,
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: block.height,
            bmm_main_block_hash: [0xb4; 32],
            bmm_main_height: block.bmm_main_height,
            bmm_main_timestamp: 20_000,
            bmm_main_mtp: 19_000,
        };
        let mut state = fixture.state;
        let successor_snapshot = canonical_snapshot(2);
        state.replayed_state_root = successor_snapshot.root().unwrap();
        let output = IncrementalStateMachineOutputV1 {
            version: IncrementalStateMachineOutputV1::VERSION,
            successor_checkpoint: StateMachineCheckpointV1 {
                version: StateMachineCheckpointV1::VERSION,
                trusted_start: None,
                authentication_config_hash: prior.authentication_config_hash,
                market_template_hash: prior.market_template_hash,
                sidechain_tip_hash: block.block_hash(),
                sidechain_tip_height: block.height,
                replayed_state_root: state.replayed_state_root,
                state_bytes: successor_snapshot.encode().unwrap(),
            },
            state,
        };
        let machine = DeterministicIncrementalStateMachine { output };
        execute_incremental_state_transition(
            &fixture.input.authentication,
            &fixture.input.market_template,
            &prior,
            std::slice::from_ref(&block),
            std::slice::from_ref(&context),
            &machine,
        )
        .unwrap();

        let mut oversized_block = block.clone();
        let mut trusted_prior = prior.clone();
        trusted_prior.version = 2;
        trusted_prior.trusted_start = Some(TrustedStateStartV1 {
            bootstrap_commitment: [0x81; 32],
            sidechain_height: 13,
        });
        let bind_identity = |checkpoint: &mut StateMachineCheckpointV1| {
            let mut store = CanonicalStateStoreV1::import(&checkpoint.state_bytes).unwrap();
            store.put(TruthcoinDatabaseId::Tip.as_u8(), TRUTHCOIN_UNIT_KEY.to_vec(),
                checkpoint.sidechain_tip_hash.to_vec()).unwrap();
            store.put(TruthcoinDatabaseId::Height.as_u8(), TRUTHCOIN_UNIT_KEY.to_vec(),
                (checkpoint.sidechain_tip_height as u32).to_le_bytes().to_vec()).unwrap();
            checkpoint.state_bytes = store.export().unwrap();
            checkpoint.replayed_state_root = store.root().unwrap();
        };
        bind_identity(&mut trusted_prior);
        trusted_prior.validate().unwrap();
        let mut wrong_tip = trusted_prior.clone();
        wrong_tip.sidechain_tip_hash = [0x90; 32];
        assert!(wrong_tip.validate().is_err());
        let mut wrong_height = trusted_prior.clone();
        wrong_height.sidechain_tip_height += 1;
        assert!(wrong_height.validate().is_err());
        for id in [TruthcoinDatabaseId::MarketTransitionUndo, TruthcoinDatabaseId::MainchainTimestampUndo] {
            let mut invented_history = trusted_prior.clone();
            let mut store = CanonicalStateStoreV1::import(&invented_history.state_bytes).unwrap();
            store.put(id.as_u8(), 13_u32.to_le_bytes().to_vec(), vec![0]).unwrap();
            invented_history.state_bytes = store.export().unwrap();
            invented_history.replayed_state_root = store.root().unwrap();
            assert!(invented_history.validate().is_err());
        }
        assert_ne!(trusted_prior.commitment(), prior.commitment());
        let mut trusted_machine = DeterministicIncrementalStateMachine {
            output: machine.output.clone(),
        };
        trusted_machine.output.successor_checkpoint.version = 2;
        trusted_machine.output.successor_checkpoint.trusted_start = trusted_prior.trusted_start.clone();
        bind_identity(&mut trusted_machine.output.successor_checkpoint);
        trusted_machine.output.state.replayed_state_root = trusted_machine.output.successor_checkpoint.replayed_state_root;
        execute_incremental_state_transition(
            &fixture.input.authentication, &fixture.input.market_template,
            &trusted_prior, std::slice::from_ref(&block), std::slice::from_ref(&context),
            &trusted_machine,
        ).unwrap();
        for replacement in [None, Some(TrustedStateStartV1 {
            bootstrap_commitment: [0x81; 32], sidechain_height: 12,
        }), Some(TrustedStateStartV1 {
            bootstrap_commitment: [0x82; 32], sidechain_height: 13,
        })] {
            trusted_machine.output.successor_checkpoint.version = if replacement.is_some() { 2 } else { 1 };
            trusted_machine.output.successor_checkpoint.trusted_start = replacement;
            assert!(execute_incremental_state_transition(
                &fixture.input.authentication, &fixture.input.market_template,
                &trusted_prior, std::slice::from_ref(&block), std::slice::from_ref(&context),
                &trusted_machine,
            ).is_err());
        }
        trusted_prior.trusted_start.as_mut().unwrap().sidechain_height = 21;
        assert!(trusted_prior.validate().is_err());
        oversized_block.body.transactions_borsh =
            vec![vec![0; MAX_TRUTHCOIN_TRANSACTION_BYTES + 1]];
        assert_eq!(
            execute_incremental_state_transition(
                &fixture.input.authentication,
                &fixture.input.market_template,
                &prior,
                &[oversized_block],
                std::slice::from_ref(&context),
                &machine,
            ),
            Err(ReplayError::Bounds)
        );

        let mut oversized_template = fixture.input.market_template.clone();
        oversized_template.market_title_template = "x".repeat(MAX_REPLAY_EVIDENCE_BYTES + 1);
        assert_eq!(
            validate_delta_resource_bounds(&oversized_template, std::slice::from_ref(&block)),
            Err(ReplayError::Bounds)
        );
        let proof_hash = [0xb6; 32];
        let deployment = test_anchor_deployment();
        let policy_asset_id = [0xbe; 32];
        let anchor = anchor_for_checkpoint(
            &fixture.input.authentication,
            &deployment,
            policy_asset_id,
            &machine.output.successor_checkpoint,
            proof_hash,
        );
        verify_incremental_anchor_binding(
            &fixture.input.authentication,
            &deployment,
            policy_asset_id,
            &anchor,
            &machine.output.successor_checkpoint,
            proof_hash,
        )
        .unwrap();
        let mut substituted = anchor;
        substituted.complete_state_root = [0xb7; 32];
        assert_eq!(
            verify_incremental_anchor_binding(
                &fixture.input.authentication,
                &deployment,
                policy_asset_id,
                &substituted,
                &machine.output.successor_checkpoint,
                proof_hash,
            ),
            Err(ReplayError::InvalidIncrementalAnchorBinding)
        );

        let mut wrong_block = block;
        wrong_block.height += 1;
        assert_eq!(
            execute_incremental_state_transition(
                &fixture.input.authentication,
                &fixture.input.market_template,
                &prior,
                &[wrong_block],
                &[context],
                &machine,
            ),
            Err(ReplayError::InvalidIncrementalCheckpoint)
        );
    }

    #[test]
    fn incremental_unlinked_engine_fails_closed() {
        let fixture = fixture();
        let prior_tip = [0xc0; 32];
        let prior_snapshot = canonical_snapshot(3);
        let prior = StateMachineCheckpointV1 {
            version: StateMachineCheckpointV1::VERSION,
            trusted_start: None,
            authentication_config_hash: fixture.input.authentication.digest(),
            market_template_hash: fixture.input.market_template.digest(),
            sidechain_tip_hash: prior_tip,
            sidechain_tip_height: 2,
            replayed_state_root: prior_snapshot.root().unwrap(),
            state_bytes: prior_snapshot.encode().unwrap(),
        };
        let body = truthcoin_body(0xc2);
        let block = TruthcoinBlockV1 {
            version: 1,
            height: 3,
            bmm_main_height: 4_000,
            header_borsh: truthcoin_header(&body, Some(prior_tip), [0xc3; 32]),
            body,
        };
        let context = CanonicalBlockContextV1 {
            sidechain_block_hash: block.block_hash(),
            sidechain_height: block.height,
            bmm_main_block_hash: [0xc4; 32],
            bmm_main_height: block.bmm_main_height,
            bmm_main_timestamp: 30_000,
            bmm_main_mtp: 29_000,
        };
        assert_eq!(
            execute_incremental_state_transition(
                &fixture.input.authentication,
                &fixture.input.market_template,
                &prior,
                &[block],
                &[context],
                &UnlinkedTruthcoin017StateMachine,
            ),
            Err(ReplayError::IncrementalStateMachineUnlinked)
        );
    }

    #[test]
    fn canonical_state_machine_full_and_segmented_replay_are_identical() {
        let fixture = fixture();
        let structure = verify_replay_structure(&fixture.input).unwrap();
        let machine = CanonicalTruthcoin017StateMachine::new(
            fixture.input.authentication.clone(),
            fixture.input.parent.height,
        )
        .unwrap();
        let full = machine
            .replay(
                &fixture.input.market_template,
                &structure.canonical_sidechain_blocks,
                &structure.canonical_block_contexts,
            )
            .unwrap();
        assert!(full.anchors.is_empty());
        assert!(full.markets.is_empty());

        let mut genesis_store = CanonicalStateStoreV1::new();
        apply_truthcoin_block_transition(
            &mut genesis_store,
            &structure.canonical_sidechain_blocks[0],
            structure.canonical_block_contexts[0],
        )
        .unwrap();
        let prior = StateMachineCheckpointV1 {
            version: StateMachineCheckpointV1::VERSION,
            trusted_start: None,
            authentication_config_hash: fixture.input.authentication.digest(),
            market_template_hash: fixture.input.market_template.digest(),
            sidechain_tip_hash: structure.canonical_sidechain_blocks[0].block_hash(),
            sidechain_tip_height: 0,
            replayed_state_root: genesis_store.root().unwrap(),
            state_bytes: genesis_store.export().unwrap(),
        };
        let incremental = execute_incremental_state_transition(
            &fixture.input.authentication,
            &fixture.input.market_template,
            &prior,
            &structure.canonical_sidechain_blocks[1..],
            &structure.canonical_block_contexts[1..],
            &machine,
        )
        .unwrap();
        assert_eq!(incremental.state, full);

        let mut expected_store = CanonicalStateStoreV1::new();
        for (block, context) in structure
            .canonical_sidechain_blocks
            .iter()
            .zip(&structure.canonical_block_contexts)
        {
            apply_truthcoin_block_transition(&mut expected_store, block, *context).unwrap();
        }
        assert_eq!(
            incremental.successor_checkpoint.state_bytes,
            expected_store.export().unwrap()
        );
        assert_eq!(
            incremental.successor_checkpoint.replayed_state_root,
            expected_store.root().unwrap()
        );
    }

    fn anchor_for_checkpoint(
        authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
        deployment: &ecx_protocol_core::TruthcoinAnchorDeploymentV1,
        policy_asset_id: Hash32,
        checkpoint: &StateMachineCheckpointV1,
        proof_hash: Hash32,
    ) -> TruthcoinAnchorStateV1 {
        TruthcoinAnchorStateV1 {
            version: TruthcoinAnchorStateV1::VERSION,
            configuration_hash: ecx_protocol_core::truthcoin_anchor_configuration_hash(
                authentication,
                deployment,
                policy_asset_id,
            ),
            sequence: 1,
            bitcoin_checkpoint_hash: [0xd0; 32],
            bitcoin_checkpoint_height: 5_000,
            bitcoin_checkpoint_mtp: 30_000,
            bitcoin_checkpoint_chainwork: [0xd1; 32],
            truthcoin_genesis_hash: authentication.genesis_sidechain_block_hash,
            truthcoin_tip_hash: checkpoint.sidechain_tip_hash,
            truthcoin_tip_height: checkpoint.sidechain_tip_height,
            truthcoin_tip_parent_bitcoin_hash: [0xd2; 32],
            canonical_path_root: [0xd3; 32],
            replay_transcript_root: [0xd4; 32],
            complete_state_root: checkpoint.replayed_state_root,
            decision_registry_root: [0xd5; 32],
            market_registry_root: [0xd6; 32],
            lmsr_state_root: [0xd7; 32],
            sample_window_root: [0xd8; 32],
            selected_anchor_commitment: [0xd9; 32],
            selected_fast_market_commitment: [0xda; 32],
            oracle_certificate_commitment: [0xdb; 32],
            last_update_elements_height: 100,
            source_data_available_through_height: 5_000,
            cumulative_update_root: [0xdc; 32],
            last_update_proof_commitment: proof_hash,
        }
    }

    fn test_anchor_deployment() -> ecx_protocol_core::TruthcoinAnchorDeploymentV1 {
        ecx_protocol_core::TruthcoinAnchorDeploymentV1 {
            version: ecx_protocol_core::TruthcoinAnchorDeploymentV1::VERSION,
            authority_asset_id: [0xbd; 32],
            authority_amount: 1,
            script_tree_configuration_hash: [0xbc; 32],
        }
    }

    #[test]
    fn deposit_history_records_batches_not_individual_ctip_sequences() {
        let mut store = CanonicalStateStoreV1::new();
        let first = AuthenticatedTruthcoinDepositV1 {
            mainchain_height: 100, mainchain_block_hash: [0x11; 32],
            txid: [0x12; 32], vout: 0, address: [0x13; 20], value_sats: 10,
            sequence_number: 900,
        };
        let second = AuthenticatedTruthcoinDepositV1 {
            mainchain_height: 101, mainchain_block_hash: [0x21; 32],
            sequence_number: 901, ..first
        };
        record_truthcoin_deposit_batch(&mut store, &[first, second], 17).unwrap();
        let mut expected = 32u64.to_le_bytes().to_vec();
        expected.extend_from_slice(&[0x21; 32]);
        expected.extend_from_slice(&17u32.to_le_bytes());
        let database = TruthcoinDatabaseId::DepositBlocks.as_u8();
        assert_eq!(store.get(database, &0u32.to_le_bytes()).unwrap(), Some(expected.as_slice()));
        assert_eq!(store.entries(database).unwrap().len(), 1);
        let before = store.export().unwrap();
        record_truthcoin_deposit_batch(&mut store, &[], 18).unwrap();
        assert_eq!(store.export().unwrap(), before);
        record_truthcoin_deposit_batch(&mut store, &[second], 19).unwrap();
        expected[40..].copy_from_slice(&19u32.to_le_bytes());
        assert_eq!(store.get(database, &1u32.to_le_bytes()).unwrap(), Some(expected.as_slice()));
        assert_eq!(store.entries(database).unwrap().len(), 2);
        // A duplicate later in a batch must roll back its earlier deposits
        // and must not create a history entry for a partially applied batch.
        let before = store.export().unwrap();
        assert_eq!(apply_authenticated_truthcoin_deposit_batch(&mut store,
            &[first, first], 20), Err(ReplayError::DuplicateTruthcoinUtxo));
        assert_eq!(store.export().unwrap(), before);
    }

    #[test]
    fn imported_branch_applies_only_deposits_reached_by_child() {
        let fixture = fixture();
        let structure = verify_replay_structure(&fixture.input).unwrap();
        let mut prior = CanonicalStateStoreV1::new();
        apply_truthcoin_block_transition(&mut prior,
            &structure.canonical_sidechain_blocks[0], structure.canonical_block_contexts[0]).unwrap();
        let prior_bytes = prior.export().unwrap();
        let child = &structure.canonical_sidechain_blocks[1..];
        let contexts = &structure.canonical_block_contexts[1..];
        let deposit = AuthenticatedTruthcoinDepositV1 {
            mainchain_height: contexts[0].bmm_main_height,
            mainchain_block_hash: contexts[0].bmm_main_block_hash,
            txid: [0xa1; 32], vout: 0, address: [0xa2; 20], value_sats: 200_000_000,
            sequence_number: 3,
        };
        let mut future = deposit;
        future.txid = [0xa3; 32];
        future.mainchain_height += 1;
        let actual = apply_branch_from_store(prior, child, contexts, &[deposit, future]).unwrap();
        let mut expected = CanonicalStateStoreV1::import(&prior_bytes).unwrap();
        apply_truthcoin_block_transition(&mut expected, &child[0], contexts[0]).unwrap();
        apply_authenticated_truthcoin_deposit(&mut expected, deposit.txid,
            deposit.vout, deposit.address, deposit.value_sats).unwrap();
        // Independently spell the native bincode (BlockHash, u32) encoding.
        let mut record = 32u64.to_le_bytes().to_vec();
        record.extend_from_slice(&deposit.mainchain_block_hash);
        record.extend_from_slice(&(contexts[0].sidechain_height as u32).to_le_bytes());
        expected.put(TruthcoinDatabaseId::DepositBlocks.as_u8(),
            0u32.to_le_bytes().to_vec(), record).unwrap();
        assert_eq!(actual.export().unwrap(), expected.export().unwrap());
        // Supplying only a later deposit leaves this child state unchanged.
        let baseline = apply_branch_from_store(CanonicalStateStoreV1::import(&prior_bytes).unwrap(),
            child, contexts, &[]).unwrap();
        let later = apply_branch_from_store(CanonicalStateStoreV1::import(&prior_bytes).unwrap(),
            child, contexts, &[future]).unwrap();
        assert_eq!(baseline.export().unwrap(), later.export().unwrap());
        assert_ne!(actual.root().unwrap(), baseline.root().unwrap());
    }

    #[test]
    fn bootstrap_production_route_replays_then_requires_real_oracle_candidates() {
        let fixture = fixture();
        let mut input = fixture.input;
        let structure = verify_replay_structure(&input).unwrap();
        let genesis = input.sidechain_blocks.remove(0);
        let mut store = CanonicalStateStoreV1::new();
        apply_truthcoin_block_transition(&mut store, &genesis, structure.canonical_block_contexts[0]).unwrap();
        let mut snapshot = CanonicalStateSnapshotV1::decode(&store.export().unwrap()).unwrap();
        for table in &mut snapshot.tables {
            if [TruthcoinDatabaseId::MarketTransitionUndo.as_u8(),
                TruthcoinDatabaseId::MainchainTimestampUndo.as_u8()].contains(&table.database_id) {
                table.entries.clear();
            }
        }
        let bootstrap = ReviewedNativeBootstrapV1 {
            version: 2, native_capture_sha256: [7; 32],
            checkpoint: StateMachineCheckpointV1 {
                version: 1, trusted_start: None,
                authentication_config_hash: input.authentication.digest(),
                market_template_hash: input.market_template.digest(),
                sidechain_tip_hash: genesis.block_hash(), sidechain_tip_height: 0,
                replayed_state_root: snapshot.root().unwrap(), state_bytes: snapshot.encode().unwrap(),
            },
            parent: input.mainchain_headers[0].clone(),
            inclusion: input.coinbase_inclusions[0].clone(),
            parent_mtp: structure.canonical_block_contexts[0].bmm_main_mtp,
            bip300: input.bip300_checkpoint_state.clone(),
        };
        let pin = bootstrap.commitment();
        let auth = input.authentication.digest();
        // Native transition succeeds, but empty fixture markets must never
        // turn a reviewed checkpoint into a fabricated price observation.
        assert_eq!(execute_production_replay_from_bootstrap(&input, &bootstrap, pin, auth),
            Err(ReplayError::NoEligibleAnchor));
        // The authority wrapper cannot turn the same incomplete replay into
        // a successful state object, even with a nonzero trusted work input.
        let trust = authority::AuthorityReplayTrustV1 {
            reviewed_bootstrap_commitment: pin, authentication_hash: auth,
            checkpoint_chainwork: [1; 32],
        };
        assert!(matches!(authority::execute_authority_replay_from_bootstrap(
            &input, &bootstrap, trust), Err(ReplayError::NoEligibleAnchor)));
        assert!(authority::execute_authority_replay_from_bootstrap(
            &input, &bootstrap, authority::AuthorityReplayTrustV1 {
                checkpoint_chainwork: [0; 32], ..trust
            }).is_err());
        assert!(execute_production_replay_from_bootstrap(&input, &bootstrap, [0; 32], auth).is_err());
        assert!(execute_production_replay_from_bootstrap(&input, &bootstrap, pin, [1; 32]).is_err());
        let mut altered = input.clone();
        altered.mainchain_block_transactions[1].transactions.clear();
        assert!(execute_production_replay_from_bootstrap(&altered, &bootstrap, pin, auth).is_err());
        assert!(authority::execute_authority_replay_from_bootstrap(
            &altered, &bootstrap, trust).is_err());
        let mut wrong_mtp = bootstrap.clone();
        wrong_mtp.parent_mtp += 1;
        assert_eq!(execute_production_replay_from_bootstrap(&input, &wrong_mtp, wrong_mtp.commitment(), auth),
            Err(ReplayError::InvalidIncrementalCheckpoint));
    }

    #[test]
    fn reviewed_native_bootstrap_requires_exact_pin_and_native_bindings() {
        let input = fixture().input;
        let parent = input.mainchain_headers[1].clone();
        let inclusion = input.coinbase_inclusions[1].clone();
        let tip = verify_truthcoin_checkpoint_inclusion(&parent, &inclusion).unwrap().unwrap();
        let header: BitcoinHeader = deserialize(&parent.consensus_header).unwrap();
        let mut store = CanonicalStateStoreV1::import(&CanonicalStateSnapshotV1::empty().encode().unwrap()).unwrap();
        for (id, value) in [
            (TruthcoinDatabaseId::Tip, tip.to_vec()),
            (TruthcoinDatabaseId::Height, 13u32.to_le_bytes().to_vec()),
            (TruthcoinDatabaseId::MainchainTimestamp, u64::from(header.time).to_le_bytes().to_vec()),
        ] {
            store.put(id.as_u8(), TRUTHCOIN_UNIT_KEY.to_vec(), value).unwrap();
        }
        let envelope = ReviewedNativeBootstrapV1 {
            version: 2, native_capture_sha256: [7; 32],
            checkpoint: StateMachineCheckpointV1 {
                version: 1, trusted_start: None,
                authentication_config_hash: input.authentication.digest(),
                market_template_hash: input.market_template.digest(),
                sidechain_tip_hash: tip, sidechain_tip_height: 13,
                replayed_state_root: store.root().unwrap(), state_bytes: store.export().unwrap(),
            },
            parent, inclusion, parent_mtp: u64::from(header.time),
            bip300: input.bip300_checkpoint_state,
        };
        let pin = envelope.commitment();
        let auth = envelope.checkpoint.authentication_config_hash;
        let imported = envelope.import(pin, auth).unwrap();
        assert_eq!(imported.version, 2);
        assert_eq!(imported.trusted_start.unwrap().bootstrap_commitment, pin);
        assert!(envelope.import([0; 32], auth).is_err());
        assert!(envelope.import(pin, [0; 32]).is_err());
        let mut rebound = envelope.clone();
        rebound.checkpoint.authentication_config_hash = [9; 32];
        assert_eq!(rebound.commitment(), pin);
        assert!(rebound.import(pin, auth).is_err());
        assert!(rebound.import(pin, [9; 32]).is_ok());
        for field in 0..6 {
            let mut altered = envelope.clone();
            match field {
                0 => altered.native_capture_sha256[0] ^= 1,
                1 => altered.parent_mtp += 1,
                2 => altered.bip300.ctip = Some(Bip300CtipV1 { txid: [8; 32], vout: 0, value_sats: 1, sequence_number: 1 }),
                3 => altered.checkpoint.authentication_config_hash[0] ^= 1,
                4 => altered.checkpoint.market_template_hash[0] ^= 1,
                _ => altered.parent.height += 1,
            }
            assert!(altered.import(pin, auth).is_err());
        }
        // Even a separately pinned malformed envelope cannot invent native
        // clock state or pre-bootstrap history.
        for id in [TruthcoinDatabaseId::MainchainTimestamp, TruthcoinDatabaseId::MarketTransitionUndo] {
            let mut altered = envelope.clone();
            let mut store = CanonicalStateStoreV1::import(&altered.checkpoint.state_bytes).unwrap();
            store.put(id.as_u8(), TRUTHCOIN_UNIT_KEY.to_vec(), vec![0; 8]).unwrap();
            altered.checkpoint.state_bytes = store.export().unwrap();
            altered.checkpoint.replayed_state_root = store.root().unwrap();
            assert!(altered.import(altered.commitment(), auth).is_err());
        }
    }

    fn canonical_snapshot(seed: u8) -> CanonicalStateSnapshotV1 {
        let mut snapshot = CanonicalStateSnapshotV1::empty();
        snapshot.tables[usize::from(seed % TRUTHCOIN_STATE_DATABASE_COUNT as u8)]
            .entries
            .push(CanonicalStateEntryV1 {
                key: vec![seed],
                value: vec![seed.wrapping_add(1)],
            });
        snapshot
    }

    #[test]
    fn canonical_state_snapshot_roundtrips_all_patched_tables() {
        let snapshot = canonical_snapshot(7);
        let encoded = snapshot.encode().unwrap();
        assert_eq!(
            CanonicalStateSnapshotV1::decode(&encoded).unwrap(),
            snapshot
        );
        assert_ne!(snapshot.root().unwrap(), [0; 32]);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            CanonicalStateSnapshotV1::decode(&trailing),
            Err(ReplayError::InvalidCanonicalStateSnapshot)
        );
    }

    #[test]
    fn canonical_state_snapshot_rejects_reordered_duplicate_and_missing_tables() {
        let mut reordered = CanonicalStateSnapshotV1::empty();
        reordered.tables.swap(0, 1);
        assert_eq!(
            reordered.encode(),
            Err(ReplayError::InvalidCanonicalStateSnapshot)
        );

        let mut duplicate_key = CanonicalStateSnapshotV1::empty();
        duplicate_key.tables[0].entries = vec![
            CanonicalStateEntryV1 {
                key: vec![1],
                value: vec![1],
            },
            CanonicalStateEntryV1 {
                key: vec![1],
                value: vec![2],
            },
        ];
        assert_eq!(
            duplicate_key.encode(),
            Err(ReplayError::InvalidCanonicalStateSnapshot)
        );

        let mut missing = CanonicalStateSnapshotV1::empty();
        missing.tables.pop();
        assert_eq!(
            missing.encode(),
            Err(ReplayError::InvalidCanonicalStateSnapshot)
        );
    }

    #[test]
    fn canonical_state_snapshot_preserves_unit_codec_values() {
        let mut store = CanonicalStateStoreV1::new();
        store.put(21, vec![1, 2, 3], Vec::new()).unwrap();
        let encoded = store.export().unwrap();
        let decoded = CanonicalStateStoreV1::import(&encoded).unwrap();
        assert_eq!(decoded.get(21, &[1, 2, 3]).unwrap(), Some(&[][..]));
        assert_eq!(decoded.export().unwrap(), encoded);
    }

    #[test]
    fn canonical_store_is_insertion_order_independent_and_table_isolated() {
        let mut forward = CanonicalStateStoreV1::new();
        forward.put(0, vec![1], vec![11]).unwrap();
        forward.put(0, vec![2], vec![12]).unwrap();
        forward.put(1, vec![1], vec![21]).unwrap();

        let mut reverse = CanonicalStateStoreV1::new();
        reverse.put(1, vec![1], vec![21]).unwrap();
        reverse.put(0, vec![2], vec![12]).unwrap();
        reverse.put(0, vec![1], vec![11]).unwrap();

        assert_eq!(forward.export().unwrap(), reverse.export().unwrap());
        assert_eq!(forward.root().unwrap(), reverse.root().unwrap());
        assert_eq!(forward.get(0, &[1]).unwrap(), Some(&[11][..]));
        assert_eq!(forward.get(1, &[1]).unwrap(), Some(&[21][..]));
        assert_eq!(forward.get(2, &[1]).unwrap(), None);
        assert_eq!(
            forward
                .entries(0)
                .unwrap()
                .map(|(key, _)| key.to_vec())
                .collect::<Vec<_>>(),
            vec![vec![1], vec![2]]
        );
        assert_eq!(
            forward.get(TRUTHCOIN_STATE_DATABASE_COUNT as u8, &[]),
            Err(ReplayError::InvalidStateDatabaseId)
        );
    }

    #[test]
    fn canonical_store_transactions_commit_or_rollback_all_tables() {
        let mut store = CanonicalStateStoreV1::new();
        store.put(16, Vec::new(), vec![1]).unwrap();
        let before = store.export().unwrap();

        let failure = store.transaction(|candidate| {
            candidate.put(16, Vec::new(), vec![2])?;
            candidate.put(20, vec![3], vec![4])?;
            Err::<(), _>(ReplayError::InvalidStateMachineOutput)
        });
        assert_eq!(failure, Err(ReplayError::InvalidStateMachineOutput));
        assert_eq!(store.export().unwrap(), before);

        store
            .transaction(|candidate| {
                assert_eq!(candidate.put(16, Vec::new(), vec![2])?, Some(vec![1]));
                candidate.put(20, vec![3], vec![4])?;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.get(16, &[]).unwrap(), Some(&[2][..]));
        assert_eq!(store.delete(20, &[3]).unwrap(), Some(vec![4]));
        assert_eq!(store.delete(20, &[3]).unwrap(), None);

        let restored = CanonicalStateStoreV1::import(&store.export().unwrap()).unwrap();
        assert_eq!(restored, store);
    }

    #[test]
    fn typed_canonical_database_matches_upstream_bincode_and_rejects_aliases() {
        let database = TypedCanonicalDatabaseV1::<u32, u64>::for_database(
            TruthcoinDatabaseId::DecisionStateHistories,
        );
        let mut store = CanonicalStateStoreV1::new();
        assert_eq!(database.put(&mut store, &7, &42).unwrap(), None);
        assert_eq!(database.get(&store, &7).unwrap(), Some(42));
        assert_eq!(database.entries(&store).unwrap(), vec![(7, 42)]);

        // heed_types::SerdeBincode uses bincode 1.3's fixed-width,
        // little-endian convenience functions.
        assert_eq!(
            store.get(2, &[7, 0, 0, 0]).unwrap(),
            Some(&[42, 0, 0, 0, 0, 0, 0, 0][..])
        );

        // Upstream's decoder accepts trailing bytes. The deterministic guest
        // view deliberately rejects that noncanonical alias by requiring an
        // exact decode/re-encode round trip.
        store
            .put(2, vec![8, 0, 0, 0], vec![43, 0, 0, 0, 0, 0, 0, 0, 0xff])
            .unwrap();
        assert_eq!(
            database.get(&store, &8),
            Err(ReplayError::InvalidCanonicalStateSnapshot)
        );
        assert_eq!(
            TypedCanonicalDatabaseV1::<u32, u64>::new(TRUTHCOIN_STATE_DATABASE_COUNT as u8),
            Err(ReplayError::InvalidStateDatabaseId)
        );
    }

    #[test]
    fn database_enum_is_bijective_with_frozen_construction_order() {
        assert_eq!(
            TruthcoinDatabaseId::ALL.len(),
            TRUTHCOIN_STATE_DATABASE_COUNT
        );
        for (expected, database) in TruthcoinDatabaseId::ALL.iter().copied().enumerate() {
            assert_eq!(usize::from(database.as_u8()), expected);
            assert_eq!(database.name(), TRUTHCOIN_STATE_DATABASE_NAMES[expected]);
            assert_eq!(TruthcoinDatabaseId::try_from(expected as u8), Ok(database));
        }
        assert_eq!(
            TruthcoinDatabaseId::try_from(TRUTHCOIN_STATE_DATABASE_COUNT as u8),
            Err(ReplayError::InvalidStateDatabaseId)
        );
    }

    fn truthcoin_header(
        body: &TruthcoinBodyV1,
        previous_side: Option<Hash32>,
        previous_main: Hash32,
    ) -> Vec<u8> {
        let mut header = truthcoin_body_merkle_root(body).to_vec();
        match previous_side {
            Some(previous) => {
                header.push(1);
                header.extend_from_slice(&previous);
            }
            None => header.push(0),
        }
        header.extend_from_slice(&previous_main);
        header
    }

    fn m7_script(commitment: Hash32) -> ScriptBuf {
        let mut data = vec![0xd1, 0x61, 0x73, 0x68, TRUTHCOIN_SIDECHAIN_NUMBER];
        data.extend_from_slice(&commitment);
        let push = PushBytesBuf::try_from(data).expect("37-byte payload is a valid push");
        ScriptBuf::new_op_return(push)
    }

    fn coinbase_inclusion(height: u64, coinbase: &Transaction) -> CoinbaseInclusionV1 {
        CoinbaseInclusionV1 {
            version: CoinbaseInclusionV1::VERSION,
            height,
            coinbase_transaction: serialize(coinbase),
            merkle_siblings: Vec::new(),
        }
    }

    fn mine_easy_header(
        prev_blockhash: BlockHash,
        merkle_root: TxMerkleNode,
        time: u32,
    ) -> BitcoinHeader {
        let mut header = BitcoinHeader {
            version: bitcoin::block::Version::ONE,
            prev_blockhash,
            merkle_root,
            time,
            bits: CompactTarget::from_consensus(EASY_BITS),
            nonce: 0,
        };
        loop {
            if header.validate_pow(header.target()).is_ok() {
                return header;
            }
            header.nonce = header.nonce.checked_add(1).expect("easy test target mines");
        }
    }

    fn replace_coinbase_and_remine(input: &mut ReplayInputV1, index: usize, coinbase: Transaction) {
        let encoded = serialize(&coinbase);
        input.coinbase_inclusions[index].coinbase_transaction = encoded.clone();
        input.coinbase_inclusions[index].merkle_siblings.clear();
        input.mainchain_block_transactions[index].transactions = vec![encoded];
        remine_from(input, index, None);
    }

    fn recommit_sidechain_block(input: &mut ReplayInputV1, sidechain_index: usize) {
        let block = &input.sidechain_blocks[sidechain_index];
        let main_index =
            usize::try_from(block.bmm_main_height - input.authentication.bitcoin_checkpoint_height)
                .unwrap();
        let coinbase =
            coinbase_with_outputs(block.bmm_main_height, vec![m7_script(block.block_hash())]);
        replace_coinbase_and_remine(input, main_index, coinbase);
    }

    fn remine_from(input: &mut ReplayInputV1, start: usize, time_override: Option<(usize, u32)>) {
        assert!(
            start > 0,
            "fixture mutations keep the frozen checkpoint intact"
        );
        let old_headers = input
            .mainchain_headers
            .iter()
            .map(|header| deserialize::<BitcoinHeader>(&header.consensus_header).unwrap())
            .collect::<Vec<_>>();
        for (index, old_header) in old_headers.iter().enumerate().skip(start) {
            let previous: BitcoinHeader =
                deserialize(&input.mainchain_headers[index - 1].consensus_header).unwrap();
            let coinbase: Transaction =
                deserialize(&input.coinbase_inclusions[index].coinbase_transaction).unwrap();
            let time = time_override
                .filter(|(override_index, _)| *override_index == index)
                .map_or(old_header.time, |(_, value)| value);
            let header =
                mine_easy_header(previous.block_hash(), coinbase.compute_txid().into(), time);
            input.mainchain_headers[index].consensus_header = serialize(&header);
        }
        let headers = input
            .mainchain_headers
            .iter()
            .map(|header| deserialize::<BitcoinHeader>(&header.consensus_header).unwrap())
            .collect::<Vec<_>>();
        let context = input
            .checkpoint_mtp_headers
            .iter()
            .map(|header| deserialize::<BitcoinHeader>(header).unwrap())
            .collect::<Vec<_>>();
        input.parent.block_hash = headers.last().unwrap().block_hash().to_byte_array();
        input.parent.median_time_past =
            median_time_past(&context, &headers, headers.len() - 1).unwrap();
    }

    fn coinbase_with_outputs(height: u64, mut scripts: Vec<ScriptBuf>) -> Transaction {
        if scripts.is_empty() {
            scripts.push(ScriptBuf::new());
        }
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::builder()
                    .push_int(i64::try_from(height).unwrap())
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: scripts
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::ZERO,
                    script_pubkey,
                })
                .collect(),
        }
    }
}
