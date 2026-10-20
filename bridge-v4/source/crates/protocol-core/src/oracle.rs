//! Deterministic Truthcoin-anchor/LMSR oracle arithmetic.
//!
//! This module verifies the canonical market identity and derives a bounded
//! ECX/USDD quote from authenticated Truthcoin state. It deliberately does not
//! implement a Truthcoin light client. A production guest must authenticate
//! `source_*` and registry proofs before calling [`derive_hybrid_quote`].

use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::types::Price;
use crate::ProtocolError;

pub const PPM_DENOMINATOR: u64 = 1_000_000;
pub const PPB_DENOMINATOR: u64 = 1_000_000_000;
pub const BPS_DENOMINATOR: u64 = 10_000;
pub const MAX_TRUTHCOIN_PROOF_BYTES: u32 = 16 * 1024 * 1024;

/// Frozen trust roots for authenticating the Truthcoin source chain.
///
/// Source-specific validation (the reviewed repository/manifest and derived
/// chain ID) is performed by `ecx-truthcoin-proof`; protocol-core owns this
/// fixed-width record so the complete trust root is part of
/// `FrozenConfigurationV1` without introducing a crate dependency cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinAuthenticationConfigV1 {
    pub version: u8,
    /// Reviewed upstream source revision, raw SHA-1 bytes.
    pub source_git_commit_sha1: [u8; 20],
    pub consensus_source_manifest_sha256: Hash32,
    /// Ordered manifest of consensus patches applied on top of the reviewed
    /// upstream revision. The all-zero "no patch" identity is forbidden.
    pub source_patch_manifest_sha256: Hash32,
    pub sidechain_number: u8,
    /// Frozen Bitcoin trust root in the same 32-byte consensus order used by
    /// `ProofBindingV1::prior_parent_block_hash` and the source proof.
    pub bitcoin_checkpoint_hash: Hash32,
    pub bitcoin_checkpoint_height: u64,
    /// Frozen digest of the BIP300 validator state at the Bitcoin checkpoint,
    /// including sidechain-slot activation and the exact Truthcoin CTIP.
    pub bip300_checkpoint_state_hash: Hash32,
    /// BMM-authenticated genesis block of the selected Truthcoin deployment.
    pub genesis_sidechain_block_hash: Hash32,
    /// Adapter namespace for this exact source/genesis pair.
    pub truthcoin_chain_id: Hash32,
    /// Frozen application profile. Truthcoin 0.17.0 has no native 32-byte
    /// Branch identifier.
    pub truthcoin_branch_id: Hash32,
    pub btc_usd_template_hash: Hash32,
    pub lmsr_math_commitment: Hash32,
    /// Cryptographic program that performs exact canonical-chain replay.
    pub source_proof_program_id: Hash32,
    /// Frozen canonical BTC/USD Decision/market selection algorithm.
    pub selection_rule_hash: Hash32,
    pub minimum_bitcoin_confirmations: u32,
    pub maximum_proof_bytes: u32,
}

impl TruthcoinAuthenticationConfigV1 {
    pub const VERSION: u8 = 3;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.source_git_commit_sha1 == [0; 20]
            || self.sidechain_number == 0
            || self.bitcoin_checkpoint_height == 0
            || self.minimum_bitcoin_confirmations == 0
            || self.maximum_proof_bytes == 0
            || self.maximum_proof_bytes > MAX_TRUTHCOIN_PROOF_BYTES
            || [
                self.consensus_source_manifest_sha256,
                self.source_patch_manifest_sha256,
                self.bitcoin_checkpoint_hash,
                self.bip300_checkpoint_state_hash,
                self.genesis_sidechain_block_hash,
                self.truthcoin_chain_id,
                self.truthcoin_branch_id,
                self.btc_usd_template_hash,
                self.lmsr_math_commitment,
                self.source_proof_program_id,
                self.selection_rule_hash,
            ]
            .contains(&[0; 32])
        {
            return Err(ProtocolError::InvalidOracleConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        tagged_hash(
            "ECX/truthcoin-authentication-config/v3",
            &self.canonical_bytes(),
        )
    }
}

impl CanonicalEncode for TruthcoinAuthenticationConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.source_git_commit_sha1);
        out.extend_from_slice(&self.consensus_source_manifest_sha256);
        out.extend_from_slice(&self.source_patch_manifest_sha256);
        put_u8(out, self.sidechain_number);
        out.extend_from_slice(&self.bitcoin_checkpoint_hash);
        put_u64(out, self.bitcoin_checkpoint_height);
        out.extend_from_slice(&self.bip300_checkpoint_state_hash);
        out.extend_from_slice(&self.genesis_sidechain_block_hash);
        out.extend_from_slice(&self.truthcoin_chain_id);
        out.extend_from_slice(&self.truthcoin_branch_id);
        out.extend_from_slice(&self.btc_usd_template_hash);
        out.extend_from_slice(&self.lmsr_math_commitment);
        out.extend_from_slice(&self.source_proof_program_id);
        out.extend_from_slice(&self.selection_rule_hash);
        put_u32(out, self.minimum_bitcoin_confirmations);
        put_u32(out, self.maximum_proof_bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum OracleMode {
    Normal = 0,
    ReduceOnly = 1,
    Disputed = 2,
    Halt = 3,
}

impl OracleMode {
    pub fn allows_new_risk(self) -> bool {
        matches!(self, Self::Normal)
    }
}

impl CanonicalEncode for OracleMode {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridOracleConfigV1 {
    pub version: u8,
    pub truthcoin_chain_id: Hash32,
    pub truthcoin_branch_id: Hash32,
    pub btc_usd_template_hash: Hash32,
    /// Commits to the fixed-point LMSR-to-probability algorithm used by Truthcoin.
    pub lmsr_math_commitment: Hash32,
    pub schedule_origin_mtp: u64,
    pub epoch_length_seconds: u64,
    pub minimum_source_confirmations: u32,
    pub maximum_anchor_age_seconds: u64,
    pub maximum_snapshot_age_seconds: u64,
    pub minimum_lmsr_b: u64,
    pub minimum_sample_count: u32,
    pub base_lmsr_weight_ppm: u32,
    pub maximum_lmsr_weight_ppm: u32,
    pub initial_anchor_band_bps: u32,
    pub maximum_anchor_band_bps: u32,
    pub risk_haircut_bps: u32,
    pub boundary_guard_ppb: u32,
    pub maximum_unanchored_deviation_bps: u32,
    /// Fixed ECX/BTC conversion. Set only when this peg is enforced elsewhere.
    pub ecx_satoshis_per_coin: u64,
    /// USD per USDD in 1e8 units. A non-fixed USDD needs its own proven oracle leg.
    pub usdd_usd_price_units: u64,
}

impl HybridOracleConfigV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if [
            self.truthcoin_chain_id,
            self.truthcoin_branch_id,
            self.btc_usd_template_hash,
            self.lmsr_math_commitment,
        ]
        .contains(&[0; 32])
        {
            return Err(ProtocolError::InvalidOracleConfiguration);
        }
        if self.epoch_length_seconds == 0
            || self.minimum_source_confirmations == 0
            || self.maximum_anchor_age_seconds == 0
            || self.maximum_snapshot_age_seconds == 0
            || self.minimum_lmsr_b == 0
            || self.minimum_sample_count == 0
            || self.base_lmsr_weight_ppm > self.maximum_lmsr_weight_ppm
            || u64::from(self.maximum_lmsr_weight_ppm) > PPM_DENOMINATOR
            || self.initial_anchor_band_bps > self.maximum_anchor_band_bps
            || u64::from(self.maximum_anchor_band_bps) >= BPS_DENOMINATOR
            || u64::from(self.risk_haircut_bps) >= BPS_DENOMINATOR
            || u64::from(self.boundary_guard_ppb) * 2 >= PPB_DENOMINATOR
            || self.maximum_unanchored_deviation_bps == 0
            || u64::from(self.maximum_unanchored_deviation_bps) > BPS_DENOMINATOR
            || self.ecx_satoshis_per_coin == 0
            || self.usdd_usd_price_units == 0
        {
            return Err(ProtocolError::InvalidOracleConfiguration);
        }
        Ok(())
    }

    pub fn epoch_start(&self, epoch: u64) -> Result<u64, ProtocolError> {
        self.schedule_origin_mtp
            .checked_add(
                epoch
                    .checked_mul(self.epoch_length_seconds)
                    .ok_or(ProtocolError::ArithmeticOverflow)?,
            )
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn epoch_end(&self, epoch: u64) -> Result<u64, ProtocolError> {
        self.epoch_start(epoch)?
            .checked_add(self.epoch_length_seconds)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn canonical_slot_id(&self, epoch: u64) -> Result<Hash32, ProtocolError> {
        let mut bytes = Vec::with_capacity(32 * 3 + 24);
        bytes.extend_from_slice(&self.truthcoin_chain_id);
        bytes.extend_from_slice(&self.truthcoin_branch_id);
        bytes.extend_from_slice(&self.btc_usd_template_hash);
        put_u64(&mut bytes, epoch);
        put_u64(&mut bytes, self.epoch_start(epoch)?);
        put_u64(&mut bytes, self.epoch_end(epoch)?);
        Ok(tagged_hash("ECX/truthcoin-slot/v1", &bytes))
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/hybrid-oracle-config/v1", self)
    }
}

impl CanonicalEncode for HybridOracleConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.truthcoin_chain_id);
        out.extend_from_slice(&self.truthcoin_branch_id);
        out.extend_from_slice(&self.btc_usd_template_hash);
        out.extend_from_slice(&self.lmsr_math_commitment);
        put_u64(out, self.schedule_origin_mtp);
        put_u64(out, self.epoch_length_seconds);
        put_u32(out, self.minimum_source_confirmations);
        put_u64(out, self.maximum_anchor_age_seconds);
        put_u64(out, self.maximum_snapshot_age_seconds);
        put_u64(out, self.minimum_lmsr_b);
        put_u32(out, self.minimum_sample_count);
        put_u32(out, self.base_lmsr_weight_ppm);
        put_u32(out, self.maximum_lmsr_weight_ppm);
        put_u32(out, self.initial_anchor_band_bps);
        put_u32(out, self.maximum_anchor_band_bps);
        put_u32(out, self.risk_haircut_bps);
        put_u32(out, self.boundary_guard_ppb);
        put_u32(out, self.maximum_unanchored_deviation_bps);
        put_u64(out, self.ecx_satoshis_per_coin);
        put_u64(out, self.usdd_usd_price_units);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinAnchorV1 {
    pub version: u8,
    pub truthcoin_chain_id: Hash32,
    pub branch_id: Hash32,
    pub template_hash: Hash32,
    pub epoch: u64,
    pub decision_id: Hash32,
    pub slot_id: Hash32,
    pub source_block_hash: Hash32,
    pub source_state_root: Hash32,
    pub source_height: u64,
    pub source_mtp: u64,
    pub source_confirmations: u32,
    pub observation_end_mtp: u64,
    pub finalized_at_mtp: u64,
    /// Final BTC/USD scalar result in 1e8 units.
    pub btc_usd_price: Price,
}

impl TruthcoinAnchorV1 {
    pub const VERSION: u8 = 1;

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/truthcoin-anchor/v1", self)
    }
}

impl CanonicalEncode for TruthcoinAnchorV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.truthcoin_chain_id);
        out.extend_from_slice(&self.branch_id);
        out.extend_from_slice(&self.template_hash);
        put_u64(out, self.epoch);
        out.extend_from_slice(&self.decision_id);
        out.extend_from_slice(&self.slot_id);
        out.extend_from_slice(&self.source_block_hash);
        out.extend_from_slice(&self.source_state_root);
        put_u64(out, self.source_height);
        put_u64(out, self.source_mtp);
        put_u32(out, self.source_confirmations);
        put_u64(out, self.observation_end_mtp);
        put_u64(out, self.finalized_at_mtp);
        self.btc_usd_price.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinLmsrSnapshotV1 {
    pub version: u8,
    pub truthcoin_chain_id: Hash32,
    pub branch_id: Hash32,
    pub template_hash: Hash32,
    pub epoch: u64,
    pub decision_id: Hash32,
    pub market_id: Hash32,
    pub slot_id: Hash32,
    /// Authenticated registry root and non-inclusion/uniqueness proof commitment.
    pub registry_root: Hash32,
    pub selection_proof_root: Hash32,
    pub source_block_hash: Hash32,
    pub source_state_root: Hash32,
    pub source_height: u64,
    pub source_mtp: u64,
    pub source_confirmations: u32,
    pub epoch_start_mtp: u64,
    pub resolves_at_mtp: u64,
    pub scalar_lower_bound: Price,
    pub scalar_upper_bound: Price,
    pub lmsr_b: u64,
    /// Canonical LMSR YES probability produced by the proven Truthcoin state.
    pub yes_probability_ppb: u32,
    pub sample_window_root: Hash32,
    pub sample_count: u32,
    pub lmsr_state_root: Hash32,
    pub saturated: bool,
}

impl TruthcoinLmsrSnapshotV1 {
    pub const VERSION: u8 = 1;

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/truthcoin-lmsr-snapshot/v1", self)
    }
}

impl CanonicalEncode for TruthcoinLmsrSnapshotV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.truthcoin_chain_id);
        out.extend_from_slice(&self.branch_id);
        out.extend_from_slice(&self.template_hash);
        put_u64(out, self.epoch);
        out.extend_from_slice(&self.decision_id);
        out.extend_from_slice(&self.market_id);
        out.extend_from_slice(&self.slot_id);
        out.extend_from_slice(&self.registry_root);
        out.extend_from_slice(&self.selection_proof_root);
        out.extend_from_slice(&self.source_block_hash);
        out.extend_from_slice(&self.source_state_root);
        put_u64(out, self.source_height);
        put_u64(out, self.source_mtp);
        put_u32(out, self.source_confirmations);
        put_u64(out, self.epoch_start_mtp);
        put_u64(out, self.resolves_at_mtp);
        self.scalar_lower_bound.encode_to(out);
        self.scalar_upper_bound.encode_to(out);
        put_u64(out, self.lmsr_b);
        put_u32(out, self.yes_probability_ppb);
        out.extend_from_slice(&self.sample_window_root);
        put_u32(out, self.sample_count);
        out.extend_from_slice(&self.lmsr_state_root);
        put_u8(out, u8::from(self.saturated));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridOracleQuoteV1 {
    pub version: u8,
    pub round: u64,
    pub observed_parent_mtp: u64,
    pub anchor_hash: Hash32,
    pub lmsr_snapshot_hash: Hash32,
    pub source_proofs_root: Hash32,
    pub btc_usd_anchor: Price,
    pub btc_usd_fast: Price,
    pub btc_usd_index: Price,
    pub ecx_usdd_index: Price,
    pub ecx_usdd_low: Price,
    pub ecx_usdd_high: Price,
    pub lmsr_weight_ppm: u32,
    pub oracle_mode: OracleMode,
}

impl HybridOracleQuoteV1 {
    pub const VERSION: u8 = 1;

    pub fn certificate_hash(&self) -> Hash32 {
        canonical_hash("ECX/hybrid-oracle-certificate/v1", self)
    }
}

impl CanonicalEncode for HybridOracleQuoteV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.round);
        put_u64(out, self.observed_parent_mtp);
        out.extend_from_slice(&self.anchor_hash);
        out.extend_from_slice(&self.lmsr_snapshot_hash);
        out.extend_from_slice(&self.source_proofs_root);
        self.btc_usd_anchor.encode_to(out);
        self.btc_usd_fast.encode_to(out);
        self.btc_usd_index.encode_to(out);
        self.ecx_usdd_index.encode_to(out);
        self.ecx_usdd_low.encode_to(out);
        self.ecx_usdd_high.encode_to(out);
        put_u32(out, self.lmsr_weight_ppm);
        self.oracle_mode.encode_to(out);
    }
}

/// Converts a bounded scalar LMSR probability into its implied price.
pub fn lmsr_scalar_implied_price(
    lower: Price,
    upper: Price,
    yes_probability_ppb: u32,
) -> Result<Price, ProtocolError> {
    if upper <= lower || u64::from(yes_probability_ppb) > PPB_DENOMINATOR {
        return Err(ProtocolError::InvalidOracleSnapshot);
    }
    let spread = u128::from(upper.get() - lower.get());
    let offset = spread
        .checked_mul(u128::from(yes_probability_ppb))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(PPB_DENOMINATOR);
    let value = u128::from(lower.get())
        .checked_add(offset)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    Price::new(u64::try_from(value).map_err(|_| ProtocolError::ArithmeticOverflow)?)
}

/// Converts BTC/USD into USDD per ECX using frozen conversion legs.
pub fn derive_ecx_usdd_price(
    btc_usd: Price,
    ecx_satoshis_per_coin: u64,
    usdd_usd: Price,
) -> Result<Price, ProtocolError> {
    if ecx_satoshis_per_coin == 0 {
        return Err(ProtocolError::InvalidOracleConfiguration);
    }
    let value = u128::from(btc_usd.get())
        .checked_mul(u128::from(ecx_satoshis_per_coin))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(usdd_usd.get());
    Price::new(u64::try_from(value).map_err(|_| ProtocolError::ArithmeticOverflow)?)
}

/// Derives a continuous, bounded index between finalized Truthcoin Decisions.
///
/// The separate market-creation server is not consulted here. The snapshot must
/// occupy the deterministic slot implied by the frozen template and schedule.
pub fn derive_hybrid_quote(
    config: &HybridOracleConfigV1,
    anchor: &TruthcoinAnchorV1,
    snapshot: &TruthcoinLmsrSnapshotV1,
    parent_mtp: u64,
) -> Result<HybridOracleQuoteV1, ProtocolError> {
    config.validate()?;
    validate_sources(config, anchor, snapshot, parent_mtp)?;

    let btc_fast = lmsr_scalar_implied_price(
        snapshot.scalar_lower_bound,
        snapshot.scalar_upper_bound,
        snapshot.yes_probability_ppb,
    )?;
    let elapsed = parent_mtp
        .saturating_sub(snapshot.epoch_start_mtp)
        .min(config.epoch_length_seconds);
    let progress_ppm = u128::from(elapsed)
        .checked_mul(u128::from(PPM_DENOMINATOR))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(config.epoch_length_seconds);
    let weight_range = u128::from(
        config
            .maximum_lmsr_weight_ppm
            .saturating_sub(config.base_lmsr_weight_ppm),
    );
    let weight = u128::from(config.base_lmsr_weight_ppm)
        + weight_range * progress_ppm / u128::from(PPM_DENOMINATOR);
    let weight_u32 = u32::try_from(weight).map_err(|_| ProtocolError::ArithmeticOverflow)?;

    let band_range = u128::from(
        config
            .maximum_anchor_band_bps
            .saturating_sub(config.initial_anchor_band_bps),
    );
    let band = u128::from(config.initial_anchor_band_bps)
        + band_range * progress_ppm / u128::from(PPM_DENOMINATOR);
    let band_u32 = u32::try_from(band).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let (anchor_floor, anchor_ceiling) = price_band(anchor.btc_usd_price, band_u32)?;
    let bounded_fast = btc_fast
        .get()
        .clamp(anchor_floor.get(), anchor_ceiling.get());
    let anchor_value = i128::from(anchor.btc_usd_price.get());
    let delta = i128::from(bounded_fast) - anchor_value;
    let weighted_delta = delta
        .checked_mul(i128::from(weight_u32))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / i128::from(PPM_DENOMINATOR);
    let index_value = anchor_value
        .checked_add(weighted_delta)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let btc_index =
        Price::new(u64::try_from(index_value).map_err(|_| ProtocolError::ArithmeticOverflow)?)?;

    let usdd_usd = Price::new(config.usdd_usd_price_units)?;
    let ecx_index = derive_ecx_usdd_price(btc_index, config.ecx_satoshis_per_coin, usdd_usd)?;
    let ecx_anchor =
        derive_ecx_usdd_price(anchor.btc_usd_price, config.ecx_satoshis_per_coin, usdd_usd)?;
    let ecx_fast = derive_ecx_usdd_price(btc_fast, config.ecx_satoshis_per_coin, usdd_usd)?;
    let low_base = Price::new(ecx_anchor.get().min(ecx_fast.get()).min(ecx_index.get()))?;
    let high_base = Price::new(ecx_anchor.get().max(ecx_fast.get()).max(ecx_index.get()))?;
    let (low_haircut, _) = price_band(low_base, config.risk_haircut_bps)?;
    let (_, high_haircut) = price_band(high_base, config.risk_haircut_bps)?;

    let anchor_age = parent_mtp.saturating_sub(anchor.finalized_at_mtp);
    let snapshot_age = parent_mtp.saturating_sub(snapshot.source_mtp);
    let deviation = deviation_bps(anchor.btc_usd_price, btc_fast)?;
    let probability = u64::from(snapshot.yes_probability_ppb);
    let guard = u64::from(config.boundary_guard_ppb);
    let oracle_mode = if anchor_age > config.maximum_anchor_age_seconds {
        OracleMode::Halt
    } else if deviation > u64::from(config.maximum_unanchored_deviation_bps) {
        OracleMode::Disputed
    } else if snapshot_age > config.maximum_snapshot_age_seconds
        || snapshot.saturated
        || probability <= guard
        || probability >= PPB_DENOMINATOR.saturating_sub(guard)
    {
        OracleMode::ReduceOnly
    } else {
        OracleMode::Normal
    };

    let mut proof_bytes = Vec::with_capacity(32 * 5);
    proof_bytes.extend_from_slice(&snapshot.registry_root);
    proof_bytes.extend_from_slice(&snapshot.selection_proof_root);
    proof_bytes.extend_from_slice(&snapshot.source_state_root);
    proof_bytes.extend_from_slice(&snapshot.sample_window_root);
    proof_bytes.extend_from_slice(&snapshot.lmsr_state_root);

    Ok(HybridOracleQuoteV1 {
        version: HybridOracleQuoteV1::VERSION,
        round: snapshot.epoch,
        observed_parent_mtp: parent_mtp,
        anchor_hash: anchor.digest(),
        lmsr_snapshot_hash: snapshot.digest(),
        source_proofs_root: tagged_hash("ECX/truthcoin-source-proofs/v1", &proof_bytes),
        btc_usd_anchor: anchor.btc_usd_price,
        btc_usd_fast: btc_fast,
        btc_usd_index: btc_index,
        ecx_usdd_index: ecx_index,
        ecx_usdd_low: low_haircut,
        ecx_usdd_high: high_haircut,
        lmsr_weight_ppm: weight_u32,
        oracle_mode,
    })
}

fn validate_sources(
    config: &HybridOracleConfigV1,
    anchor: &TruthcoinAnchorV1,
    snapshot: &TruthcoinLmsrSnapshotV1,
    parent_mtp: u64,
) -> Result<(), ProtocolError> {
    if anchor.version != TruthcoinAnchorV1::VERSION
        || snapshot.version != TruthcoinLmsrSnapshotV1::VERSION
    {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if anchor.truthcoin_chain_id != config.truthcoin_chain_id
        || snapshot.truthcoin_chain_id != config.truthcoin_chain_id
        || anchor.branch_id != config.truthcoin_branch_id
        || snapshot.branch_id != config.truthcoin_branch_id
        || anchor.template_hash != config.btc_usd_template_hash
        || snapshot.template_hash != config.btc_usd_template_hash
    {
        return Err(ProtocolError::InvalidOracleSource);
    }
    if snapshot.epoch
        != anchor
            .epoch
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?
        || anchor.slot_id != config.canonical_slot_id(anchor.epoch)?
        || snapshot.slot_id != config.canonical_slot_id(snapshot.epoch)?
        || snapshot.epoch_start_mtp != config.epoch_start(snapshot.epoch)?
        || snapshot.resolves_at_mtp != config.epoch_end(snapshot.epoch)?
        || anchor.observation_end_mtp != snapshot.epoch_start_mtp
    {
        return Err(ProtocolError::InvalidOracleSchedule);
    }
    if [
        anchor.decision_id,
        anchor.source_block_hash,
        anchor.source_state_root,
        snapshot.decision_id,
        snapshot.market_id,
        snapshot.registry_root,
        snapshot.selection_proof_root,
        snapshot.source_block_hash,
        snapshot.source_state_root,
        snapshot.sample_window_root,
        snapshot.lmsr_state_root,
    ]
    .contains(&[0; 32])
    {
        return Err(ProtocolError::InvalidOracleSource);
    }
    if anchor.source_confirmations < config.minimum_source_confirmations
        || snapshot.source_confirmations < config.minimum_source_confirmations
        || anchor.source_mtp > parent_mtp
        || snapshot.source_mtp > parent_mtp
        || anchor.finalized_at_mtp > parent_mtp
        || snapshot.epoch_start_mtp > parent_mtp
        || snapshot.lmsr_b < config.minimum_lmsr_b
        || snapshot.sample_count < config.minimum_sample_count
        || snapshot.scalar_upper_bound <= snapshot.scalar_lower_bound
        || u64::from(snapshot.yes_probability_ppb) > PPB_DENOMINATOR
    {
        return Err(ProtocolError::InvalidOracleSnapshot);
    }
    Ok(())
}

fn price_band(price: Price, bps: u32) -> Result<(Price, Price), ProtocolError> {
    if u64::from(bps) >= BPS_DENOMINATOR {
        return Err(ProtocolError::InvalidOracleConfiguration);
    }
    let value = u128::from(price.get());
    let low = value
        .checked_mul(u128::from(BPS_DENOMINATOR - u64::from(bps)))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(BPS_DENOMINATOR);
    let high = value
        .checked_mul(u128::from(BPS_DENOMINATOR + u64::from(bps)))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(BPS_DENOMINATOR);
    Ok((
        Price::new(u64::try_from(low).map_err(|_| ProtocolError::ArithmeticOverflow)?)?,
        Price::new(u64::try_from(high).map_err(|_| ProtocolError::ArithmeticOverflow)?)?,
    ))
}

fn deviation_bps(anchor: Price, observed: Price) -> Result<u64, ProtocolError> {
    let delta = anchor.get().abs_diff(observed.get());
    let value = u128::from(delta)
        .checked_mul(u128::from(BPS_DENOMINATOR))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(anchor.get());
    u64::try_from(value).map_err(|_| ProtocolError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PRICE_SCALE;

    fn config() -> HybridOracleConfigV1 {
        HybridOracleConfigV1 {
            version: 1,
            truthcoin_chain_id: [1; 32],
            truthcoin_branch_id: [2; 32],
            btc_usd_template_hash: [3; 32],
            lmsr_math_commitment: [4; 32],
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

    #[test]
    fn configuration_rejects_unanchored_deviation_above_one_hundred_percent() {
        let mut config = config();
        config.maximum_unanchored_deviation_bps = 10_001;
        assert_eq!(
            config.validate(),
            Err(ProtocolError::InvalidOracleConfiguration)
        );
    }

    #[test]
    fn configuration_rejects_a_full_one_hundred_percent_anchor_band() {
        let mut config = config();
        config.maximum_anchor_band_bps = 10_000;
        assert_eq!(
            config.validate(),
            Err(ProtocolError::InvalidOracleConfiguration)
        );
    }

    fn sources() -> (TruthcoinAnchorV1, TruthcoinLmsrSnapshotV1) {
        let config = config();
        let anchor = TruthcoinAnchorV1 {
            version: 1,
            truthcoin_chain_id: [1; 32],
            branch_id: [2; 32],
            template_hash: [3; 32],
            epoch: 0,
            decision_id: [5; 32],
            slot_id: config.canonical_slot_id(0).unwrap(),
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
            truthcoin_chain_id: [1; 32],
            branch_id: [2; 32],
            template_hash: [3; 32],
            epoch: 1,
            decision_id: [8; 32],
            market_id: [9; 32],
            slot_id: config.canonical_slot_id(1).unwrap(),
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
            lmsr_b: 10_000,
            yes_probability_ppb: 750_000_000,
            sample_window_root: [14; 32],
            sample_count: 5,
            lmsr_state_root: [15; 32],
            saturated: false,
        };
        (anchor, snapshot)
    }

    #[test]
    fn scalar_lmsr_interpolation_is_exact() {
        let lower = Price::new(50 * PRICE_SCALE).unwrap();
        let upper = Price::new(70 * PRICE_SCALE).unwrap();
        assert_eq!(lmsr_scalar_implied_price(lower, upper, 0).unwrap(), lower);
        assert_eq!(
            lmsr_scalar_implied_price(lower, upper, 500_000_000)
                .unwrap()
                .get(),
            60 * PRICE_SCALE
        );
        assert_eq!(
            lmsr_scalar_implied_price(lower, upper, 1_000_000_000).unwrap(),
            upper
        );
    }

    #[test]
    fn bridge_starts_at_anchor_and_moves_toward_lmsr() {
        let config = config();
        let (anchor, mut snapshot) = sources();
        snapshot.source_mtp = 1_100;
        let start = derive_hybrid_quote(&config, &anchor, &snapshot, 1_100).unwrap();
        assert_eq!(start.btc_usd_index, anchor.btc_usd_price);
        snapshot.source_mtp = 1_150;
        let midpoint = derive_hybrid_quote(&config, &anchor, &snapshot, 1_150).unwrap();
        assert!(midpoint.btc_usd_index > anchor.btc_usd_price);
        assert!(midpoint.btc_usd_index < midpoint.btc_usd_fast);
        assert_eq!(midpoint.oracle_mode, OracleMode::Normal);
    }

    #[test]
    fn spoofed_fast_market_slot_is_rejected() {
        let config = config();
        let (anchor, mut snapshot) = sources();
        snapshot.slot_id = [99; 32];
        assert_eq!(
            derive_hybrid_quote(&config, &anchor, &snapshot, 1_150),
            Err(ProtocolError::InvalidOracleSchedule)
        );
    }

    #[test]
    fn stale_or_boundary_snapshot_disables_new_risk() {
        let config = config();
        let (anchor, mut snapshot) = sources();
        snapshot.source_mtp = 1_110;
        let stale = derive_hybrid_quote(&config, &anchor, &snapshot, 1_150).unwrap();
        assert_eq!(stale.oracle_mode, OracleMode::ReduceOnly);
        snapshot.source_mtp = 1_150;
        snapshot.yes_probability_ppb = 1;
        let boundary = derive_hybrid_quote(&config, &anchor, &snapshot, 1_150).unwrap();
        assert_eq!(boundary.oracle_mode, OracleMode::ReduceOnly);
    }

    #[test]
    fn btc_conversion_has_expected_scale() {
        let price = derive_ecx_usdd_price(
            Price::new(60_000 * PRICE_SCALE).unwrap(),
            1_000,
            Price::new(PRICE_SCALE).unwrap(),
        )
        .unwrap();
        assert_eq!(price.get(), 60_000_000); // 0.6 USDD per ECX.
    }
}
