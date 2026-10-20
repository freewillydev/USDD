//! Source-pinned authentication boundary for the Truthcoin/LMSR oracle.
//!
//! Truthcoin 0.17.0 commits transactions in its BMM-authenticated block
//! headers, but it does not commit a state root or expose state proofs. An RPC
//! response is therefore not evidence of a Decision, market, or LMSR state.
//! This crate accepts those records only as public values of a cryptographic
//! proof whose program is frozen by [`TruthcoinAuthenticationConfigV1`].
//!
//! The proof program is required to replay the exact upstream consensus source
//! pinned below. The default verifier is [`DenyAllConsensusProofs`], so merely
//! constructing internally consistent structs never authenticates a price.

#![forbid(unsafe_code)]

use ecx_protocol_core::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
pub use ecx_protocol_core::TruthcoinAuthenticationConfigV1;
use ecx_protocol_core::{
    derive_hybrid_quote, tagged_hash, Hash32, HybridOracleConfigV1, HybridOracleQuoteV1,
    ProtocolError, TruthcoinAnchorV1, TruthcoinLmsrSnapshotV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Upstream repository: `LayerTwo-Labs/truthcoin-dc`.
pub const TRUTHCOIN_SOURCE_REPOSITORY: &str = "https://github.com/LayerTwo-Labs/truthcoin-dc";

/// Upstream 0.17.0 commit (`ca8fb2e27fef261ba03941d152cfe3ca7581b8b2`).
pub const TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1: [u8; 20] = [
    0xca, 0x8f, 0xb2, 0xe2, 0x7f, 0xef, 0x26, 0x1b, 0xa0, 0x39, 0x41, 0xd1, 0x52, 0xcf, 0xe3, 0xca,
    0x75, 0x81, 0xb8, 0xb2,
];

/// SHA-256 manifest of the pinned `Cargo.lock`, archive/authorization code,
/// and all Rust files below `lib/{math,state,types,validation}`.
///
/// The manifest codec is, for each lexicographically sorted path:
/// `u32_be(path_len) || path || u64_be(file_len) || file_bytes`.
pub const TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256: Hash32 = [
    0xb5, 0xb6, 0x21, 0x7e, 0xbd, 0x02, 0x6d, 0xf9, 0xdd, 0x72, 0x07, 0x0f, 0x45, 0x28, 0xa9, 0xfc,
    0xfd, 0x65, 0x2a, 0x08, 0x95, 0x67, 0xe5, 0x38, 0x8f, 0x01, 0xcf, 0xb0, 0x3a, 0x62, 0xdd, 0x49,
];

/// SHA-256 of the ordered ECX consensus patch manifest applied to the pinned
/// upstream source. Revisions one and two restore timestamp, Decision-claim, market
/// transition, and settlement rollback, selects the production cadence, and
/// defines the finite signed-transaction encoding for explicit abstention and
/// commits canonical network-aware withdrawal destinations. Revision two also
/// restores exact pre-trade share-account metadata on disconnect.
pub const TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256: Hash32 = [
    0xa3, 0x5d, 0x11, 0x7f, 0x9f, 0x66, 0xd0, 0x5c, 0xae, 0xb5, 0xc6, 0x26, 0xf0, 0x2a, 0xab, 0x92,
    0x71, 0xdc, 0x07, 0xfc, 0x10, 0xdc, 0x87, 0x7d, 0xaa, 0xdc, 0x55, 0x29, 0x92, 0xed, 0x9d, 0x21,
];

/// Manifest commitment for upstream `lmsr.rs`, `safe_math.rs`, and
/// `trading.rs`, using the same path/length/file codec as the full manifest.
pub const TRUTHCOIN_LMSR_MATH_COMMITMENT: Hash32 = [
    0x32, 0x41, 0x0c, 0x3f, 0x24, 0xf0, 0xdf, 0xf6, 0xc5, 0x58, 0x6b, 0x2e, 0x8f, 0x80, 0x1b, 0x6d,
    0x6d, 0x9d, 0xfb, 0x01, 0xb2, 0x6e, 0xf6, 0x3d, 0x91, 0x69, 0xaa, 0xe3, 0x73, 0xcb, 0x19, 0xf7,
];

/// Truthcoin's upstream BIP300 sidechain number.
pub const TRUTHCOIN_SIDECHAIN_NUMBER: u8 = 13;
pub const MAX_PROOF_BYTES_HARD_LIMIT: u32 = ecx_protocol_core::MAX_TRUTHCOIN_PROOF_BYTES;
/// Fixed canonical length of [`TruthcoinSourcePublicValuesV1`].
pub const TRUTHCOIN_SOURCE_PUBLIC_VALUES_V1_LEN: usize = 1_269;

/// Period-independent canonical scalar-price market template shared by the
/// keeper and source proof. The `btc_usd` field and hash-domain names are
/// retained as frozen V1 ABI labels; a direct-native deployment identifies
/// ECX/USDD through its template contents and exact 1:1 conversion profile.
/// Operational transaction fees and listing-fee caps are intentionally
/// excluded because they do not change source eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinMarketTemplateCommitmentV1 {
    pub version: u8,
    pub market_title_template: String,
    pub market_description_template: String,
    pub decision_header_template: String,
    pub decision_description_template: String,
    pub decision_tags: Vec<String>,
    pub scalar_min_f64_bits: u64,
    pub scalar_max_f64_bits: u64,
    pub scalar_increment_f64_bits: u64,
    pub minimum_liquidity_sats: u64,
    pub trading_fee_ppm: u32,
    pub tx_pow_hash_selector: u8,
    pub tx_pow_ordering: u8,
    pub tx_pow_difficulty: u8,
}

impl TruthcoinMarketTemplateCommitmentV1 {
    pub const VERSION: u8 = 1;

    pub fn digest(&self) -> Hash32 {
        tagged_hash("ECX/truthcoin-btc-usd-template/v1", &self.canonical_bytes())
    }
}

impl CanonicalEncode for TruthcoinMarketTemplateCommitmentV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_string(out, &self.market_title_template);
        put_string(out, &self.market_description_template);
        put_string(out, &self.decision_header_template);
        put_string(out, &self.decision_description_template);
        put_u32(
            out,
            u32::try_from(self.decision_tags.len()).expect("tag count fits u32"),
        );
        for tag in &self.decision_tags {
            put_string(out, tag);
        }
        put_u64(out, self.scalar_min_f64_bits);
        put_u64(out, self.scalar_max_f64_bits);
        put_u64(out, self.scalar_increment_f64_bits);
        put_u64(out, self.minimum_liquidity_sats);
        put_u32(out, self.trading_fee_ppm);
        put_u8(out, self.tx_pow_hash_selector);
        put_u8(out, self.tx_pow_ordering);
        put_u8(out, self.tx_pow_difficulty);
    }
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_u64(
        out,
        u64::try_from(value.len()).expect("string length fits u64"),
    );
    out.extend_from_slice(value.as_bytes());
}

pub fn pinned_truthcoin_chain_id(genesis_sidechain_block_hash: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(20 + 32 + 32 + 1 + 32);
    bytes.extend_from_slice(&TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1);
    bytes.extend_from_slice(&TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256);
    bytes.extend_from_slice(&TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256);
    bytes.push(TRUTHCOIN_SIDECHAIN_NUMBER);
    bytes.extend_from_slice(&genesis_sidechain_block_hash);
    tagged_hash("ECX/truthcoin-chain-id/v2", &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentChainContextV1 {
    pub block_hash: Hash32,
    pub height: u64,
    pub median_time_past: u64,
}

/// Exact public output required from the pinned full-replay proof program.
///
/// The program, rather than the proof packager, must derive every field after
/// replaying a chain whose headers and bodies satisfy upstream Truthcoin
/// consensus and whose sidechain blocks are accepted by a validated Bitcoin
/// BMM chain. The roots make the replay, canonical selection, and state used for
/// the two compact protocol-core records independently auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinSourcePublicValuesV1 {
    pub version: u8,
    pub authentication_config_hash: Hash32,
    pub source_git_commit_sha1: [u8; 20],
    pub consensus_source_manifest_sha256: Hash32,
    pub sidechain_number: u8,
    pub observed_parent_block_hash: Hash32,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub bitcoin_checkpoint_hash: Hash32,
    pub bitcoin_checkpoint_height: u64,
    pub bitcoin_tip_hash: Hash32,
    pub bitcoin_tip_height: u64,
    pub sidechain_genesis_hash: Hash32,
    pub sidechain_tip_hash: Hash32,
    pub sidechain_tip_height: u64,
    pub sidechain_tip_mtp: u64,
    pub source_confirmations: u32,
    /// Commitment to the canonical Bitcoin/BMM and Truthcoin header path.
    pub canonical_chain_root: Hash32,
    /// Commitment to every decoded block/body consumed by exact replay.
    pub replay_transcript_root: Hash32,
    /// Commitment emitted by the pinned replay program over its complete state.
    pub replayed_state_root: Hash32,
    pub selection_rule_hash: Hash32,
    /// Native source IDs and exact source state used to bridge Truthcoin's
    /// 3-byte DecisionId / 6-byte MarketId / `f64` LMSR into ECX fixed-width
    /// records. A single scaled Decision has two tradeable outcomes; index 1 is
    /// the upper-bound/YES leg.
    pub anchor_decision_id_native: [u8; 3],
    pub lmsr_decision_id_native: [u8; 3],
    pub lmsr_market_id_native: [u8; 6],
    pub lmsr_market_creation_txid: Hash32,
    pub lmsr_market_created_height: u64,
    /// First replayed height at which every static predicate and the minimum
    /// liquidity predicate were simultaneously true.
    pub lmsr_market_first_eligible_height: u64,
    pub lmsr_liquidity_base_sats: u64,
    pub lmsr_beta_f64_bits: u64,
    pub lmsr_shares: [i64; 2],
    pub lmsr_selected_outcome_index: u32,
    pub lmsr_probability_f64_bits: u64,
    pub anchor: TruthcoinAnchorV1,
    pub lmsr_snapshot: TruthcoinLmsrSnapshotV1,
}

impl TruthcoinSourcePublicValuesV1 {
    pub const VERSION: u8 = 1;

    pub fn digest(&self) -> Hash32 {
        tagged_hash(
            "ECX/truthcoin-source-public-values/v1",
            &self.canonical_bytes(),
        )
    }

    fn validate_against(
        &self,
        config: &TruthcoinAuthenticationConfigV1,
        parent: ParentChainContextV1,
    ) -> Result<(), AuthenticationError> {
        if self.version != Self::VERSION {
            return Err(AuthenticationError::UnsupportedVersion);
        }
        if self.authentication_config_hash != config.digest()
            || self.source_git_commit_sha1 != config.source_git_commit_sha1
            || self.consensus_source_manifest_sha256 != config.consensus_source_manifest_sha256
            || self.sidechain_number != config.sidechain_number
            || self.bitcoin_checkpoint_hash != config.bitcoin_checkpoint_hash
            || self.bitcoin_checkpoint_height != config.bitcoin_checkpoint_height
            || self.sidechain_genesis_hash != config.genesis_sidechain_block_hash
            || self.selection_rule_hash != config.selection_rule_hash
        {
            return Err(AuthenticationError::PublicValuesMismatch);
        }
        if self.observed_parent_block_hash != parent.block_hash
            || self.observed_parent_height != parent.height
            || self.observed_parent_mtp != parent.median_time_past
            || self.bitcoin_tip_hash != parent.block_hash
            || self.bitcoin_tip_height != parent.height
            || self.sidechain_tip_mtp > parent.median_time_past
            || self.bitcoin_tip_height < self.bitcoin_checkpoint_height
            || self.anchor.source_height > self.sidechain_tip_height
            || self.lmsr_snapshot.source_height > self.sidechain_tip_height
            || self.source_confirmations < config.minimum_bitcoin_confirmations
            || self.anchor.source_confirmations < config.minimum_bitcoin_confirmations
            || self.lmsr_snapshot.source_confirmations < config.minimum_bitcoin_confirmations
        {
            return Err(AuthenticationError::InvalidFinality);
        }
        if [
            self.bitcoin_checkpoint_hash,
            self.bitcoin_tip_hash,
            self.sidechain_genesis_hash,
            self.sidechain_tip_hash,
            self.canonical_chain_root,
            self.replay_transcript_root,
            self.replayed_state_root,
        ]
        .contains(&[0; 32])
        {
            return Err(AuthenticationError::PublicValuesMismatch);
        }
        if !is_standard_native_decision_id(self.anchor_decision_id_native)
            || !is_standard_native_decision_id(self.lmsr_decision_id_native)
            || self.lmsr_market_creation_txid == [0; 32]
            || self.lmsr_market_created_height > self.lmsr_market_first_eligible_height
            || self.lmsr_market_first_eligible_height > self.lmsr_snapshot.source_height
            || self.anchor.decision_id
                != native_decision_id_hash(
                    config.truthcoin_chain_id,
                    self.anchor_decision_id_native,
                )
            || self.lmsr_snapshot.decision_id
                != native_decision_id_hash(config.truthcoin_chain_id, self.lmsr_decision_id_native)
            || self.lmsr_snapshot.market_id
                != native_market_id_hash(config.truthcoin_chain_id, self.lmsr_market_id_native)
        {
            return Err(AuthenticationError::InvalidNativeState);
        }
        self.validate_lmsr_state()?;
        Ok(())
    }

    fn validate_lmsr_state(&self) -> Result<(), AuthenticationError> {
        if self.lmsr_liquidity_base_sats == 0
            || self.lmsr_selected_outcome_index != 1
            || self.lmsr_shares.iter().any(|shares| *shares < 0)
        {
            return Err(AuthenticationError::InvalidNativeState);
        }
        let expected_beta =
            self.lmsr_liquidity_base_sats as f64 / libm::log(self.lmsr_shares.len() as f64);
        let beta = f64::from_bits(self.lmsr_beta_f64_bits);
        if !beta.is_finite()
            || beta <= 0.0
            || beta.to_bits() != expected_beta.to_bits()
            || self.lmsr_snapshot.lmsr_b != expected_beta.floor() as u64
        {
            return Err(AuthenticationError::InvalidNativeState);
        }
        let expected_probability = upstream_binary_lmsr_probability(self.lmsr_shares, beta)?;
        if expected_probability.to_bits() != self.lmsr_probability_f64_bits
            || self.lmsr_snapshot.yes_probability_ppb != probability_to_ppb(expected_probability)?
            || self.lmsr_snapshot.lmsr_state_root
                != native_lmsr_state_root(
                    self.lmsr_market_id_native,
                    self.lmsr_liquidity_base_sats,
                    self.lmsr_beta_f64_bits,
                    self.lmsr_shares,
                )
        {
            return Err(AuthenticationError::InvalidNativeState);
        }
        Ok(())
    }
}

impl CanonicalEncode for TruthcoinSourcePublicValuesV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.authentication_config_hash);
        out.extend_from_slice(&self.source_git_commit_sha1);
        out.extend_from_slice(&self.consensus_source_manifest_sha256);
        put_u8(out, self.sidechain_number);
        out.extend_from_slice(&self.observed_parent_block_hash);
        put_u64(out, self.observed_parent_height);
        put_u64(out, self.observed_parent_mtp);
        out.extend_from_slice(&self.bitcoin_checkpoint_hash);
        put_u64(out, self.bitcoin_checkpoint_height);
        out.extend_from_slice(&self.bitcoin_tip_hash);
        put_u64(out, self.bitcoin_tip_height);
        out.extend_from_slice(&self.sidechain_genesis_hash);
        out.extend_from_slice(&self.sidechain_tip_hash);
        put_u64(out, self.sidechain_tip_height);
        put_u64(out, self.sidechain_tip_mtp);
        put_u32(out, self.source_confirmations);
        out.extend_from_slice(&self.canonical_chain_root);
        out.extend_from_slice(&self.replay_transcript_root);
        out.extend_from_slice(&self.replayed_state_root);
        out.extend_from_slice(&self.selection_rule_hash);
        out.extend_from_slice(&self.anchor_decision_id_native);
        out.extend_from_slice(&self.lmsr_decision_id_native);
        out.extend_from_slice(&self.lmsr_market_id_native);
        out.extend_from_slice(&self.lmsr_market_creation_txid);
        put_u64(out, self.lmsr_market_created_height);
        put_u64(out, self.lmsr_market_first_eligible_height);
        put_u64(out, self.lmsr_liquidity_base_sats);
        put_u64(out, self.lmsr_beta_f64_bits);
        out.extend_from_slice(&self.lmsr_shares[0].to_be_bytes());
        out.extend_from_slice(&self.lmsr_shares[1].to_be_bytes());
        put_u32(out, self.lmsr_selected_outcome_index);
        put_u64(out, self.lmsr_probability_f64_bits);
        self.anchor.encode_to(out);
        self.lmsr_snapshot.encode_to(out);
    }
}

/// Cryptographic proof plus the exact public values it authenticates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinConsensusProofV1 {
    pub version: u8,
    pub public_values: TruthcoinSourcePublicValuesV1,
    pub proof: Vec<u8>,
}

impl TruthcoinConsensusProofV1 {
    pub const VERSION: u8 = 1;

    pub fn proof_hash(&self) -> Hash32 {
        tagged_hash("ECX/truthcoin-consensus-proof/v1", &self.proof)
    }
}

/// Canonical marker carried in [`TruthcoinConsensusProofV1::proof`] when the
/// actual compressed SP1 receipt is supplied through SP1's deferred-proof
/// stream. The marker removes an otherwise unconstrained opaque byte string
/// from the outer proof witness; it is not itself a cryptographic proof.
pub fn sp1_deferred_proof_marker(program_id: Hash32, public_values: &[u8]) -> Hash32 {
    let public_values_sha256: Hash32 = Sha256::digest(public_values).into();
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&program_id);
    preimage.extend_from_slice(&public_values_sha256);
    tagged_hash("ECX/truthcoin-sp1-deferred-proof/v1", &preimage)
}

/// A verifier for the frozen Truthcoin full-replay proof program.
///
/// Production implementations must verify a cryptographic receipt for exactly
/// `program_id` and exactly `public_values`; signatures from an RPC server or
/// keeper do not implement this interface's security contract. An SP1 guest
/// implementation consumes the real receipt through the deferred-proof stream
/// and requires `proof` to equal [`sp1_deferred_proof_marker`].
pub trait ConsensusProofVerifier {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof: &[u8],
    ) -> Result<(), ConsensusProofVerificationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("cryptographic Truthcoin consensus proof was rejected")]
pub struct ConsensusProofVerificationError;

/// Safe default for builds that do not link the selected recursive verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllConsensusProofs;

impl ConsensusProofVerifier for DenyAllConsensusProofs {
    fn verify(
        &self,
        _program_id: Hash32,
        _public_values: &[u8],
        _proof: &[u8],
    ) -> Result<(), ConsensusProofVerificationError> {
        Err(ConsensusProofVerificationError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedTruthcoinQuoteV1 {
    pub source_public_values_hash: Hash32,
    pub consensus_proof_hash: Hash32,
    pub quote: HybridOracleQuoteV1,
}

/// Authenticate the Truthcoin source first, then run protocol-core's bounded
/// hybrid-oracle arithmetic over the proof-derived records.
pub fn verify_authenticated_hybrid_quote<V: ConsensusProofVerifier>(
    authentication: &TruthcoinAuthenticationConfigV1,
    oracle: &HybridOracleConfigV1,
    source_proof: &TruthcoinConsensusProofV1,
    parent: ParentChainContextV1,
    verifier: &V,
) -> Result<AuthenticatedTruthcoinQuoteV1, AuthenticationError> {
    validate_authentication_config(authentication)?;
    if source_proof.version != TruthcoinConsensusProofV1::VERSION {
        return Err(AuthenticationError::UnsupportedVersion);
    }
    if source_proof.proof.is_empty()
        || source_proof.proof.len()
            > usize::try_from(authentication.maximum_proof_bytes)
                .map_err(|_| AuthenticationError::InvalidConfiguration)?
    {
        return Err(AuthenticationError::InvalidProofSize);
    }
    source_proof
        .public_values
        .validate_against(authentication, parent)?;

    if oracle.truthcoin_chain_id != authentication.truthcoin_chain_id
        || oracle.truthcoin_branch_id != authentication.truthcoin_branch_id
        || oracle.btc_usd_template_hash != authentication.btc_usd_template_hash
        || oracle.lmsr_math_commitment != authentication.lmsr_math_commitment
    {
        return Err(AuthenticationError::OracleConfigurationMismatch);
    }

    let public_values = source_proof.public_values.canonical_bytes();
    verifier
        .verify(
            authentication.source_proof_program_id,
            &public_values,
            &source_proof.proof,
        )
        .map_err(|_| AuthenticationError::InvalidConsensusProof)?;

    let quote = derive_hybrid_quote(
        oracle,
        &source_proof.public_values.anchor,
        &source_proof.public_values.lmsr_snapshot,
        parent.median_time_past,
    )
    .map_err(AuthenticationError::InvalidSourceRecord)?;

    Ok(AuthenticatedTruthcoinQuoteV1 {
        source_public_values_hash: source_proof.public_values.digest(),
        consensus_proof_hash: source_proof.proof_hash(),
        quote,
    })
}

fn validate_authentication_config(
    authentication: &TruthcoinAuthenticationConfigV1,
) -> Result<(), AuthenticationError> {
    if authentication.version != TruthcoinAuthenticationConfigV1::VERSION {
        return Err(AuthenticationError::UnsupportedVersion);
    }
    authentication
        .validate()
        .map_err(|_| AuthenticationError::InvalidConfiguration)?;
    if authentication.source_git_commit_sha1 != TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1
        || authentication.consensus_source_manifest_sha256
            != TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256
        || authentication.source_patch_manifest_sha256 != TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256
        || authentication.sidechain_number != TRUTHCOIN_SIDECHAIN_NUMBER
        || authentication.truthcoin_chain_id
            != pinned_truthcoin_chain_id(authentication.genesis_sidechain_block_hash)
        || authentication.lmsr_math_commitment != TRUTHCOIN_LMSR_MATH_COMMITMENT
    {
        return Err(AuthenticationError::UnpinnedSource);
    }
    Ok(())
}

pub fn native_decision_id_hash(chain_id: Hash32, native_id: [u8; 3]) -> Hash32 {
    let mut bytes = Vec::with_capacity(35);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&native_id);
    tagged_hash("ECX/truthcoin-native-decision-id/v1", &bytes)
}

/// Truthcoin 0.17.0 stores `is_standard` in the high bit of its three-byte
/// DecisionId. The canonical BTC/USD selection profile only admits standard
/// slots allocated by production period pricing.
pub const fn is_standard_native_decision_id(native_id: [u8; 3]) -> bool {
    native_id[0] & 0x80 != 0
}

pub fn native_market_id_hash(chain_id: Hash32, native_id: [u8; 6]) -> Hash32 {
    let mut bytes = Vec::with_capacity(38);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&native_id);
    tagged_hash("ECX/truthcoin-native-market-id/v1", &bytes)
}

pub fn native_lmsr_state_root(
    native_market_id: [u8; 6],
    liquidity_base_sats: u64,
    beta_f64_bits: u64,
    shares: [i64; 2],
) -> Hash32 {
    let mut bytes = Vec::with_capacity(38);
    bytes.extend_from_slice(&native_market_id);
    bytes.extend_from_slice(&liquidity_base_sats.to_be_bytes());
    bytes.extend_from_slice(&beta_f64_bits.to_be_bytes());
    bytes.extend_from_slice(&shares[0].to_be_bytes());
    bytes.extend_from_slice(&shares[1].to_be_bytes());
    tagged_hash("ECX/truthcoin-native-lmsr-state/v1", &bytes)
}

/// Exact binary specialization of upstream 0.17.0's shifted softmax.
pub fn upstream_binary_lmsr_probability(
    shares: [i64; 2],
    beta: f64,
) -> Result<f64, AuthenticationError> {
    if !beta.is_finite() || beta <= 1e-6 || beta >= 1e12 {
        return Err(AuthenticationError::InvalidNativeState);
    }
    let max_share = shares[0].max(shares[1]) as f64;
    let left = libm::exp((shares[0] as f64 - max_share) / beta);
    let right = libm::exp((shares[1] as f64 - max_share) / beta);
    let sum = left + right;
    let probability = right / sum;
    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
        return Err(AuthenticationError::InvalidNativeState);
    }
    Ok(probability)
}

pub fn probability_to_ppb(probability: f64) -> Result<u32, AuthenticationError> {
    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
        return Err(AuthenticationError::InvalidNativeState);
    }
    let rounded = (probability * 1_000_000_000.0).round();
    if !(0.0..=1_000_000_000.0).contains(&rounded) {
        return Err(AuthenticationError::InvalidNativeState);
    }
    Ok(rounded as u32)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthenticationError {
    #[error("unsupported Truthcoin proof/configuration version")]
    UnsupportedVersion,
    #[error("Truthcoin source is not the reviewed pinned source")]
    UnpinnedSource,
    #[error("invalid Truthcoin authentication configuration")]
    InvalidConfiguration,
    #[error("Truthcoin proof public values do not match the frozen configuration")]
    PublicValuesMismatch,
    #[error("hybrid oracle configuration is not bound to the authenticated source")]
    OracleConfigurationMismatch,
    #[error("native Truthcoin IDs or LMSR state do not match the pinned source codec")]
    InvalidNativeState,
    #[error("Truthcoin proof does not establish required Bitcoin/BMM finality")]
    InvalidFinality,
    #[error("Truthcoin proof size is empty or outside its frozen bound")]
    InvalidProofSize,
    #[error("Truthcoin consensus proof rejected")]
    InvalidConsensusProof,
    #[error("proof-authenticated Truthcoin record failed oracle validation: {0}")]
    InvalidSourceRecord(ProtocolError),
}

/// SHA-256 digest used by receipt-verifier integrations that take a digest
/// rather than raw public values.
pub fn public_values_sha256(public_values: &TruthcoinSourcePublicValuesV1) -> Hash32 {
    Sha256::digest(public_values.canonical_bytes()).into()
}

/// Exact bytes committed as the Truthcoin replay program's SP1 public values.
pub fn source_public_values_bytes(public_values: &TruthcoinSourcePublicValuesV1) -> Vec<u8> {
    public_values.canonical_bytes()
}

/// Validate replay-program public values before they are placed in a receipt.
///
/// This exposes the same source pin, fixed-width bridge, and parent/finality
/// checks used by [`verify_authenticated_hybrid_quote`] without pretending a
/// receipt already exists. It is intended for the pinned replay guest, which
/// has just derived these values by executing the source consensus rules.
pub fn validate_source_public_values(
    authentication: &TruthcoinAuthenticationConfigV1,
    parent: ParentChainContextV1,
    public_values: &TruthcoinSourcePublicValuesV1,
) -> Result<(), AuthenticationError> {
    validate_authentication_config(authentication)?;
    public_values.validate_against(authentication, parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_protocol_core::types::{Price, PRICE_SCALE};

    #[derive(Debug, Clone, Copy)]
    struct TestDigestVerifier;

    impl TestDigestVerifier {
        fn proof(program_id: Hash32, public_values: &[u8]) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(32 + public_values.len());
            bytes.extend_from_slice(&program_id);
            bytes.extend_from_slice(public_values);
            Sha256::digest(bytes).to_vec()
        }
    }

    impl ConsensusProofVerifier for TestDigestVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof: &[u8],
        ) -> Result<(), ConsensusProofVerificationError> {
            if proof == Self::proof(program_id, public_values) {
                Ok(())
            } else {
                Err(ConsensusProofVerificationError)
            }
        }
    }

    fn oracle_config() -> HybridOracleConfigV1 {
        let genesis = [20; 32];
        HybridOracleConfigV1 {
            version: 1,
            truthcoin_chain_id: pinned_truthcoin_chain_id(genesis),
            truthcoin_branch_id: [2; 32],
            btc_usd_template_hash: [3; 32],
            lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
            schedule_origin_mtp: 1_000,
            epoch_length_seconds: 100,
            minimum_source_confirmations: 6,
            maximum_anchor_age_seconds: 1_000,
            maximum_snapshot_age_seconds: 30,
            minimum_lmsr_b: 1_000,
            minimum_sample_count: 3,
            base_lmsr_weight_ppm: 0,
            maximum_lmsr_weight_ppm: 1_000_000,
            initial_anchor_band_bps: 100,
            maximum_anchor_band_bps: 2_000,
            risk_haircut_bps: 100,
            boundary_guard_ppb: 10_000,
            maximum_unanchored_deviation_bps: 5_000,
            ecx_satoshis_per_coin: 1_000,
            usdd_usd_price_units: PRICE_SCALE,
        }
    }

    fn authentication_config() -> TruthcoinAuthenticationConfigV1 {
        let genesis_sidechain_block_hash = [20; 32];
        TruthcoinAuthenticationConfigV1 {
            version: TruthcoinAuthenticationConfigV1::VERSION,
            source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
            consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
            source_patch_manifest_sha256: TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
            sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
            bitcoin_checkpoint_hash: [30; 32],
            bitcoin_checkpoint_height: 100,
            bip300_checkpoint_state_hash: [29; 32],
            genesis_sidechain_block_hash,
            truthcoin_chain_id: pinned_truthcoin_chain_id(genesis_sidechain_block_hash),
            truthcoin_branch_id: [2; 32],
            btc_usd_template_hash: [3; 32],
            lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
            source_proof_program_id: [21; 32],
            selection_rule_hash: [22; 32],
            minimum_bitcoin_confirmations: 6,
            maximum_proof_bytes: 1_024,
        }
    }

    fn source_records() -> (TruthcoinAnchorV1, TruthcoinLmsrSnapshotV1) {
        let oracle = oracle_config();
        let anchor_decision_id_native = [0x80, 0, 1];
        let lmsr_decision_id_native = [0x81, 0, 1];
        let lmsr_market_id_native = [1, 2, 3, 4, 5, 6];
        let liquidity_base_sats = 10_000;
        let beta = liquidity_base_sats as f64 / libm::log(2.0);
        let shares = [0, 15_849];
        let probability = upstream_binary_lmsr_probability(shares, beta).unwrap();
        let anchor = TruthcoinAnchorV1 {
            version: 1,
            truthcoin_chain_id: oracle.truthcoin_chain_id,
            branch_id: [2; 32],
            template_hash: [3; 32],
            epoch: 0,
            decision_id: native_decision_id_hash(
                oracle.truthcoin_chain_id,
                anchor_decision_id_native,
            ),
            slot_id: oracle.canonical_slot_id(0).unwrap(),
            source_block_hash: [6; 32],
            source_state_root: [7; 32],
            source_height: 10,
            source_mtp: 1_095,
            source_confirmations: 6,
            observation_end_mtp: 1_100,
            finalized_at_mtp: 1_100,
            btc_usd_price: Price::new(60_000 * PRICE_SCALE).unwrap(),
        };
        let snapshot = TruthcoinLmsrSnapshotV1 {
            version: 1,
            truthcoin_chain_id: oracle.truthcoin_chain_id,
            branch_id: [2; 32],
            template_hash: [3; 32],
            epoch: 1,
            decision_id: native_decision_id_hash(
                oracle.truthcoin_chain_id,
                lmsr_decision_id_native,
            ),
            market_id: native_market_id_hash(oracle.truthcoin_chain_id, lmsr_market_id_native),
            slot_id: oracle.canonical_slot_id(1).unwrap(),
            registry_root: [10; 32],
            selection_proof_root: [11; 32],
            source_block_hash: [12; 32],
            source_state_root: [13; 32],
            source_height: 20,
            source_mtp: 1_140,
            source_confirmations: 6,
            epoch_start_mtp: 1_100,
            resolves_at_mtp: 1_200,
            scalar_lower_bound: Price::new(50_000 * PRICE_SCALE).unwrap(),
            scalar_upper_bound: Price::new(70_000 * PRICE_SCALE).unwrap(),
            lmsr_b: beta.floor() as u64,
            yes_probability_ppb: probability_to_ppb(probability).unwrap(),
            sample_window_root: [14; 32],
            sample_count: 5,
            lmsr_state_root: native_lmsr_state_root(
                lmsr_market_id_native,
                liquidity_base_sats,
                beta.to_bits(),
                shares,
            ),
            saturated: false,
        };
        (anchor, snapshot)
    }

    fn source_proof() -> TruthcoinConsensusProofV1 {
        let auth = authentication_config();
        let (anchor, lmsr_snapshot) = source_records();
        let lmsr_liquidity_base_sats = 10_000;
        let lmsr_beta = lmsr_liquidity_base_sats as f64 / libm::log(2.0);
        let lmsr_shares = [0, 15_849];
        let lmsr_probability = upstream_binary_lmsr_probability(lmsr_shares, lmsr_beta).unwrap();
        let public_values = TruthcoinSourcePublicValuesV1 {
            version: 1,
            authentication_config_hash: auth.digest(),
            source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
            consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
            sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
            observed_parent_block_hash: [31; 32],
            observed_parent_height: 120,
            observed_parent_mtp: 1_150,
            bitcoin_checkpoint_hash: auth.bitcoin_checkpoint_hash,
            bitcoin_checkpoint_height: auth.bitcoin_checkpoint_height,
            bitcoin_tip_hash: [31; 32],
            bitcoin_tip_height: 120,
            sidechain_genesis_hash: auth.genesis_sidechain_block_hash,
            sidechain_tip_hash: [32; 32],
            sidechain_tip_height: 20,
            sidechain_tip_mtp: 1_140,
            source_confirmations: 6,
            canonical_chain_root: [33; 32],
            replay_transcript_root: [34; 32],
            replayed_state_root: [35; 32],
            selection_rule_hash: auth.selection_rule_hash,
            anchor_decision_id_native: [0x80, 0, 1],
            lmsr_decision_id_native: [0x81, 0, 1],
            lmsr_market_id_native: [1, 2, 3, 4, 5, 6],
            lmsr_market_creation_txid: [36; 32],
            lmsr_market_created_height: 15,
            lmsr_market_first_eligible_height: 15,
            lmsr_liquidity_base_sats,
            lmsr_beta_f64_bits: lmsr_beta.to_bits(),
            lmsr_shares,
            lmsr_selected_outcome_index: 1,
            lmsr_probability_f64_bits: lmsr_probability.to_bits(),
            anchor,
            lmsr_snapshot,
        };
        let proof = TestDigestVerifier::proof(
            auth.source_proof_program_id,
            &public_values.canonical_bytes(),
        );
        TruthcoinConsensusProofV1 {
            version: 1,
            public_values,
            proof,
        }
    }

    fn parent_context() -> ParentChainContextV1 {
        ParentChainContextV1 {
            block_hash: [31; 32],
            height: 120,
            median_time_past: 1_150,
        }
    }

    #[test]
    fn canonical_market_template_commitment_vector_is_frozen() {
        let template = TruthcoinMarketTemplateCommitmentV1 {
            version: 1,
            market_title_template: "ECX BTC/USD period {period}".into(),
            market_description_template: "Canonical BTC/USD forecast for Truthcoin period {period}"
                .into(),
            decision_header_template: "BTC/USD at Truthcoin period {period} close".into(),
            decision_description_template:
                "Canonical scaled BTC/USD decision for Truthcoin period {period}".into(),
            decision_tags: vec!["ecx-oracle-v1".into(), "btc-usd".into()],
            scalar_min_f64_bits: 10_000.0f64.to_bits(),
            scalar_max_f64_bits: 250_000.0f64.to_bits(),
            scalar_increment_f64_bits: 1.0f64.to_bits(),
            minimum_liquidity_sats: 10_000_000,
            trading_fee_ppm: 10_000,
            tx_pow_hash_selector: 0,
            tx_pow_ordering: 0,
            tx_pow_difficulty: 0,
        };
        assert_eq!(
            template.digest(),
            [
                0xc5, 0xea, 0x2f, 0xf4, 0x11, 0xfc, 0xf7, 0x14, 0x15, 0xc9, 0xc8, 0x17, 0x83, 0x50,
                0x47, 0x9b, 0x14, 0x66, 0xa6, 0xa3, 0xfe, 0x30, 0x69, 0x47, 0xce, 0xa4, 0x6b, 0x4f,
                0x70, 0x78, 0x5e, 0xfa,
            ]
        );
    }

    #[test]
    fn authenticated_quote_requires_proof_over_exact_public_values() {
        let result = verify_authenticated_hybrid_quote(
            &authentication_config(),
            &oracle_config(),
            &source_proof(),
            parent_context(),
            &TestDigestVerifier,
        )
        .unwrap();
        assert_eq!(result.quote.btc_usd_anchor.get(), 60_000 * PRICE_SCALE);
        assert_eq!(
            result.source_public_values_hash,
            source_proof().public_values.digest()
        );
    }

    #[test]
    fn rpc_style_struct_mutation_invalidates_proof() {
        let mut proof = source_proof();
        proof.public_values.lmsr_snapshot.yes_probability_ppb = 900_000_000;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidNativeState)
        );
    }

    #[test]
    fn native_lmsr_recomputation_rejects_a_reproved_forgery() {
        let mut proof = source_proof();
        proof.public_values.lmsr_shares[1] += 1;
        proof.proof = TestDigestVerifier::proof(
            authentication_config().source_proof_program_id,
            &proof.public_values.canonical_bytes(),
        );
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidNativeState)
        );

        let mut proof = source_proof();
        proof.public_values.anchor_decision_id_native[0] &= 0x7f;
        proof.proof = TestDigestVerifier::proof(
            authentication_config().source_proof_program_id,
            &proof.public_values.canonical_bytes(),
        );
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidNativeState)
        );
    }

    #[test]
    fn tampered_receipt_and_wrong_source_are_rejected() {
        let mut proof = source_proof();
        proof.proof[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidConsensusProof)
        );

        let mut proof = source_proof();
        proof.public_values.canonical_chain_root[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidConsensusProof)
        );

        let mut auth = authentication_config();
        auth.source_git_commit_sha1[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &auth,
                &oracle_config(),
                &source_proof(),
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::UnpinnedSource)
        );

        let mut auth = authentication_config();
        auth.source_patch_manifest_sha256[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &auth,
                &oracle_config(),
                &source_proof(),
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::UnpinnedSource)
        );

        let mut auth = authentication_config();
        auth.bitcoin_checkpoint_hash[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &auth,
                &oracle_config(),
                &source_proof(),
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::PublicValuesMismatch)
        );
    }

    #[test]
    fn finality_and_parent_time_are_not_packager_selected() {
        let mut proof = source_proof();
        proof.public_values.source_confirmations = 5;
        proof.proof = TestDigestVerifier::proof(
            authentication_config().source_proof_program_id,
            &proof.public_values.canonical_bytes(),
        );
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &proof,
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidFinality)
        );

        let mut wrong_parent = parent_context();
        wrong_parent.median_time_past += 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &source_proof(),
                wrong_parent,
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidFinality)
        );

        let mut wrong_parent = parent_context();
        wrong_parent.block_hash[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &source_proof(),
                wrong_parent,
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidFinality)
        );

        let mut wrong_parent = parent_context();
        wrong_parent.height += 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &source_proof(),
                wrong_parent,
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::InvalidFinality)
        );
    }

    #[test]
    fn oracle_configuration_is_bound_to_authenticated_source() {
        let mut oracle = oracle_config();
        oracle.truthcoin_branch_id[0] ^= 1;
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle,
                &source_proof(),
                parent_context(),
                &TestDigestVerifier,
            ),
            Err(AuthenticationError::OracleConfigurationMismatch)
        );
    }

    #[test]
    fn deny_all_is_the_safe_unlinked_default() {
        assert_eq!(
            verify_authenticated_hybrid_quote(
                &authentication_config(),
                &oracle_config(),
                &source_proof(),
                parent_context(),
                &DenyAllConsensusProofs,
            ),
            Err(AuthenticationError::InvalidConsensusProof)
        );
    }

    #[test]
    fn deferred_proof_marker_binds_program_and_exact_public_values() {
        let program_id = authentication_config().source_proof_program_id;
        let values = source_proof().public_values.canonical_bytes();
        let marker = sp1_deferred_proof_marker(program_id, &values);
        assert_ne!(marker, [0; 32]);

        let mut other_program = program_id;
        other_program[0] ^= 1;
        assert_ne!(marker, sp1_deferred_proof_marker(other_program, &values));
        let mut other_values = values;
        other_values[0] ^= 1;
        assert_ne!(marker, sp1_deferred_proof_marker(program_id, &other_values));
    }

    #[test]
    fn source_public_values_length_is_frozen() {
        assert_eq!(
            source_public_values_bytes(&source_proof().public_values).len(),
            TRUTHCOIN_SOURCE_PUBLIC_VALUES_V1_LEN
        );
    }
}
