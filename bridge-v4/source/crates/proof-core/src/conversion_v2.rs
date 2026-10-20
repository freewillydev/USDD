//! Recursive authentication boundary for the two non-Truthcoin price legs.
//!
//! The v1 oracle contains convenient ECX/BTC and USDD/USD constants. V2 may
//! use them only after two independently pinned proof programs attest that the
//! corresponding redemption covenants are live, current, and fully backed.

use ecx_protocol_core::{tagged_hash, FrozenConfigurationV2, Hash32, PRICE_SCALE};
use ecx_truthcoin_proof::{ConsensusProofVerificationError, ConsensusProofVerifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONVERSION_LEG_PUBLIC_VALUES_VERSION_V2: u8 = 2;
pub const CONVERSION_LEG_PUBLIC_VALUES_LEN_V2: usize = 275;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConversionLegKindV2 {
    EcxBtc = 0,
    UsddUsd = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionLegPublicValuesV2 {
    pub version: u8,
    pub kind: ConversionLegKindV2,
    pub observed_parent_block_hash: Hash32,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub source_height: u64,
    pub source_mtp: u64,
    pub valid_until_mtp: u64,
    pub base_asset_id: Hash32,
    /// BTC uses the Elements policy asset. USD uses the frozen finalized-USDD
    /// light-client configuration identity rather than an unauthenticated
    /// ticker string.
    pub quote_unit_id: Hash32,
    pub redemption_covenant_commitment: Hash32,
    /// Immutable checkpoint/configuration commitment frozen by the outer ECX
    /// deployment. This is separate from the rolling current source root.
    pub source_checkpoint_commitment: Hash32,
    pub source_state_root: Hash32,
    /// Quote atoms redeemable for one whole (1e8 atoms) base asset.
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub redemption_enabled: bool,
}

impl ConversionLegPublicValuesV2 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONVERSION_LEG_PUBLIC_VALUES_LEN_V2);
        out.push(self.version);
        out.push(self.kind as u8);
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
        debug_assert_eq!(out.len(), CONVERSION_LEG_PUBLIC_VALUES_LEN_V2);
        out
    }

    pub fn digest(&self) -> Hash32 {
        tagged_hash(
            "ECX/conversion-leg-public-values/v2",
            &self.canonical_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionLegConsensusProofV2 {
    pub public_values: ConversionLegPublicValuesV2,
    pub proof: Vec<u8>,
}

impl ConversionLegConsensusProofV2 {
    /// Unique empty envelope used when the deployment's native ECX/USDD lane
    /// authenticates the price directly with Truthcoin. Requiring this exact
    /// value prevents ignored private fields from becoming witness malleability
    /// or a hidden source of unbounded data.
    pub fn canonical_absent(kind: ConversionLegKindV2) -> Self {
        Self {
            public_values: ConversionLegPublicValuesV2 {
                version: 0,
                kind,
                observed_parent_block_hash: [0; 32],
                observed_parent_height: 0,
                observed_parent_mtp: 0,
                source_height: 0,
                source_mtp: 0,
                valid_until_mtp: 0,
                base_asset_id: [0; 32],
                quote_unit_id: [0; 32],
                redemption_covenant_commitment: [0; 32],
                source_checkpoint_commitment: [0; 32],
                source_state_root: [0; 32],
                quote_atoms_per_whole_base: 0,
                outstanding_base_atoms: 0,
                redeemable_reserve_quote_atoms: 0,
                redemption_enabled: false,
            },
            proof: Vec::new(),
        }
    }

    pub fn is_canonical_absent(&self, kind: ConversionLegKindV2) -> bool {
        self == &Self::canonical_absent(kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedConversionLegsV2 {
    pub ecx_satoshis_per_coin: u64,
    pub usdd_usd_price_units: u64,
    pub ecx_btc_public_values_hash: Hash32,
    pub usdd_usd_public_values_hash: Hash32,
    pub combined_commitment: Hash32,
}

/// Bind a direct ECX/USDD Truthcoin scalar range for a native ECX Elements
/// deployment. The fixed public ABI retains the historical
/// `conversion_legs_commitment` slot, but its domain-separated value commits
/// to the direct source identity instead of pretending that unused conversion
/// receipts were verified.
#[allow(clippy::too_many_arguments)]
pub fn derive_direct_native_truthcoin_price_range_v2(
    configuration: &FrozenConfigurationV2,
    truthcoin_public_values_hash: Hash32,
    truthcoin_scalar_lower_bound: u64,
    truthcoin_scalar_upper_bound: u64,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
) -> Result<(u64, u64, Hash32, Hash32), ConversionLegErrorV2> {
    if !configuration.base.uses_direct_native_truthcoin_price()
        || truthcoin_public_values_hash == [0; 32]
        || truthcoin_scalar_lower_bound == 0
        || truthcoin_scalar_upper_bound <= truthcoin_scalar_lower_bound
        || !ecx_btc.is_canonical_absent(ConversionLegKindV2::EcxBtc)
        || !usdd_usd.is_canonical_absent(ConversionLegKindV2::UsddUsd)
    {
        return Err(ConversionLegErrorV2::PublicValuesMismatch);
    }

    let mut source = Vec::with_capacity(32 * 6);
    source.extend_from_slice(&configuration.base.chain_id);
    source.extend_from_slice(&configuration.base.ecx_asset_id);
    source.extend_from_slice(&configuration.base.usdd_asset_id);
    source.extend_from_slice(&configuration.base.oracle.btc_usd_template_hash);
    source.extend_from_slice(
        &configuration
            .base
            .truthcoin_authentication
            .selection_rule_hash,
    );
    source.extend_from_slice(&truthcoin_public_values_hash);
    let price_source_commitment =
        tagged_hash("ECX/direct-native-truthcoin-price-source/v2", &source);

    let mut range = Vec::with_capacity(48);
    range.extend_from_slice(&price_source_commitment);
    range.extend_from_slice(&truthcoin_scalar_lower_bound.to_be_bytes());
    range.extend_from_slice(&truthcoin_scalar_upper_bound.to_be_bytes());
    let range_commitment = tagged_hash("ECX/authenticated-direct-native-price-range/v2", &range);
    Ok((
        truthcoin_scalar_lower_bound,
        truthcoin_scalar_upper_bound,
        range_commitment,
        price_source_commitment,
    ))
}

pub fn derive_authenticated_price_range_v2(
    configuration: &FrozenConfigurationV2,
    truthcoin_scalar_lower_bound: u64,
    truthcoin_scalar_upper_bound: u64,
    conversions: AuthenticatedConversionLegsV2,
) -> Result<(u64, u64, Hash32), ConversionLegErrorV2> {
    if truthcoin_scalar_lower_bound == 0
        || truthcoin_scalar_upper_bound <= truthcoin_scalar_lower_bound
        || conversions.ecx_satoshis_per_coin == 0
        || conversions.usdd_usd_price_units == 0
        || conversions.ecx_satoshis_per_coin != configuration.base.oracle.ecx_satoshis_per_coin
        || conversions.usdd_usd_price_units != configuration.base.oracle.usdd_usd_price_units
    {
        return Err(ConversionLegErrorV2::PublicValuesMismatch);
    }
    // Flooring the lower endpoint is conservative for long-side loss. The
    // upper endpoint must instead round up: flooring both sides could omit
    // one ECX/USDD atom from the authenticated range and understate the
    // short-side worst deficit used by the 125% coverage gate.
    let minimum = convert_scalar_endpoint_v2(
        truthcoin_scalar_lower_bound,
        conversions.ecx_satoshis_per_coin,
        conversions.usdd_usd_price_units,
        false,
    )?;
    let maximum = convert_scalar_endpoint_v2(
        truthcoin_scalar_upper_bound,
        conversions.ecx_satoshis_per_coin,
        conversions.usdd_usd_price_units,
        true,
    )?;
    if minimum == 0 || maximum <= minimum {
        return Err(ConversionLegErrorV2::PublicValuesMismatch);
    }
    let mut commitment = Vec::with_capacity(48);
    commitment.extend_from_slice(&conversions.combined_commitment);
    commitment.extend_from_slice(&minimum.to_be_bytes());
    commitment.extend_from_slice(&maximum.to_be_bytes());
    Ok((
        minimum,
        maximum,
        tagged_hash("ECX/authenticated-price-range/v2", &commitment),
    ))
}

fn convert_scalar_endpoint_v2(
    btc_usd: u64,
    ecx_satoshis_per_coin: u64,
    usdd_usd_price_units: u64,
    round_up: bool,
) -> Result<u64, ConversionLegErrorV2> {
    if usdd_usd_price_units == 0 {
        return Err(ConversionLegErrorV2::PublicValuesMismatch);
    }
    let numerator = u128::from(btc_usd)
        .checked_mul(u128::from(ecx_satoshis_per_coin))
        .ok_or(ConversionLegErrorV2::ArithmeticOverflow)?;
    let denominator = u128::from(usdd_usd_price_units);
    let quotient = numerator / denominator;
    let value = if round_up && numerator % denominator != 0 {
        quotient
            .checked_add(1)
            .ok_or(ConversionLegErrorV2::ArithmeticOverflow)?
    } else {
        quotient
    };
    u64::try_from(value).map_err(|_| ConversionLegErrorV2::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConversionLegErrorV2 {
    #[error("unsupported conversion-leg proof version")]
    UnsupportedVersion,
    #[error("conversion-leg proof is missing, oversized, stale, or malformed")]
    InvalidProofEnvelope,
    #[error("conversion-leg public values do not match the frozen deployment")]
    PublicValuesMismatch,
    #[error("conversion redemption is disabled or under-reserved")]
    RedemptionUnavailable,
    #[error("pinned conversion-leg consensus proof was rejected")]
    InvalidConsensusProof,
    #[error("conversion arithmetic overflow")]
    ArithmeticOverflow,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_conversion_legs_v2<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    prior_parent_block_hash: Hash32,
    prior_parent_height: u64,
    prior_parent_mtp: u64,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
) -> Result<AuthenticatedConversionLegsV2, ConversionLegErrorV2> {
    configuration
        .validate()
        .map_err(|_| ConversionLegErrorV2::PublicValuesMismatch)?;
    verify_one(
        configuration,
        prior_parent_block_hash,
        prior_parent_height,
        prior_parent_mtp,
        ecx_btc,
        ConversionLegKindV2::EcxBtc,
        configuration.ecx_btc_conversion_program_id,
        configuration.base.ecx_asset_id,
        configuration.base.policy_asset_id,
        configuration.base.oracle.ecx_satoshis_per_coin,
        configuration.ecx_btc_redemption_covenant_commitment,
        configuration.ecx_btc_source_checkpoint_commitment,
        verifier,
    )?;
    verify_one(
        configuration,
        prior_parent_block_hash,
        prior_parent_height,
        prior_parent_mtp,
        usdd_usd,
        ConversionLegKindV2::UsddUsd,
        configuration.usdd_usd_conversion_program_id,
        configuration.base.usdd_asset_id,
        configuration
            .base
            .usdd_checkpoint
            .ethereum_light_client_configuration_hash,
        configuration.base.oracle.usdd_usd_price_units,
        configuration.usdd_usd_redemption_covenant_commitment,
        configuration.usdd_usd_source_checkpoint_commitment,
        verifier,
    )?;

    let ecx_hash = ecx_btc.public_values.digest();
    let usdd_hash = usdd_usd.public_values.digest();
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&ecx_hash);
    combined[32..].copy_from_slice(&usdd_hash);
    Ok(AuthenticatedConversionLegsV2 {
        ecx_satoshis_per_coin: ecx_btc.public_values.quote_atoms_per_whole_base,
        usdd_usd_price_units: usdd_usd.public_values.quote_atoms_per_whole_base,
        ecx_btc_public_values_hash: ecx_hash,
        usdd_usd_public_values_hash: usdd_hash,
        combined_commitment: tagged_hash("ECX/authenticated-conversion-legs/v2", &combined),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_one<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
    proof: &ConversionLegConsensusProofV2,
    kind: ConversionLegKindV2,
    program_id: Hash32,
    base_asset_id: Hash32,
    quote_unit_id: Hash32,
    expected_quote_atoms: u64,
    expected_redemption_covenant: Hash32,
    expected_source_checkpoint: Hash32,
    verifier: &V,
) -> Result<(), ConversionLegErrorV2> {
    let public = &proof.public_values;
    if public.version != CONVERSION_LEG_PUBLIC_VALUES_VERSION_V2 {
        return Err(ConversionLegErrorV2::UnsupportedVersion);
    }
    // The actual compressed SP1 receipt and verifier key are supplied by the
    // deferred-proof stream. The recursive envelope carries exactly its
    // 32-byte domain-separated marker, never an opaque receipt blob that
    // could defeat the outer 16 MiB recovery bound.
    if proof.proof.len()
        != usize::try_from(configuration.recursive_proof_marker_bytes)
            .map_err(|_| ConversionLegErrorV2::InvalidProofEnvelope)?
        || proof.proof.len()
            > usize::try_from(configuration.maximum_conversion_proof_bytes)
                .map_err(|_| ConversionLegErrorV2::InvalidProofEnvelope)?
        || parent_height == 0
        || parent_mtp == 0
    {
        return Err(ConversionLegErrorV2::InvalidProofEnvelope);
    }
    if public.kind != kind
        || public.observed_parent_block_hash != parent_hash
        || public.observed_parent_height != parent_height
        || public.observed_parent_mtp != parent_mtp
        || !source_clock_is_current(
            public.source_height,
            public.source_mtp,
            public.valid_until_mtp,
            parent_mtp,
            configuration.maximum_conversion_age_seconds,
        )
        || public.base_asset_id != base_asset_id
        || public.quote_unit_id != quote_unit_id
        || public.quote_atoms_per_whole_base != expected_quote_atoms
        || public.redemption_covenant_commitment != expected_redemption_covenant
        || public.source_checkpoint_commitment != expected_source_checkpoint
        || public.source_state_root == [0; 32]
        || public.outstanding_base_atoms == 0
    {
        return Err(ConversionLegErrorV2::PublicValuesMismatch);
    }
    let required_reserve = ceil_div(
        public
            .outstanding_base_atoms
            .checked_mul(u128::from(public.quote_atoms_per_whole_base))
            .ok_or(ConversionLegErrorV2::ArithmeticOverflow)?,
        u128::from(PRICE_SCALE),
    )?;
    if !public.redemption_enabled || public.redeemable_reserve_quote_atoms < required_reserve {
        return Err(ConversionLegErrorV2::RedemptionUnavailable);
    }
    verifier
        .verify(program_id, &public.canonical_bytes(), &proof.proof)
        .map_err(|_: ConsensusProofVerificationError| ConversionLegErrorV2::InvalidConsensusProof)
}

/// Source heights are chain-local and deliberately not compared with Bitcoin
/// parent height. Freshness crosses chains only through authenticated time and
/// the recursive receipt's binding to the selected parent context.
fn source_clock_is_current(
    source_height: u64,
    source_mtp: u64,
    valid_until_mtp: u64,
    parent_mtp: u64,
    maximum_age_seconds: u64,
) -> bool {
    source_height != 0
        && source_mtp <= parent_mtp
        && valid_until_mtp >= parent_mtp
        && parent_mtp.saturating_sub(source_mtp) <= maximum_age_seconds
}

fn ceil_div(value: u128, denominator: u128) -> Result<u128, ConversionLegErrorV2> {
    value
        .checked_add(denominator - 1)
        .ok_or(ConversionLegErrorV2::ArithmeticOverflow)
        .map(|sum| sum / denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_truthcoin_proof::{
        sp1_deferred_proof_marker, ConsensusProofVerificationError, DenyAllConsensusProofs,
    };

    #[derive(Debug)]
    struct MarkerVerifier;

    impl ConsensusProofVerifier for MarkerVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof: &[u8],
        ) -> Result<(), ConsensusProofVerificationError> {
            if program_id == [0; 32]
                || proof != tagged_hash("ECX/test-conversion-proof/v2", public_values)
            {
                return Err(ConsensusProofVerificationError);
            }
            Ok(())
        }
    }

    #[test]
    fn canonical_length_is_fixed() {
        let public = ConversionLegPublicValuesV2 {
            version: 2,
            kind: ConversionLegKindV2::EcxBtc,
            observed_parent_block_hash: [1; 32],
            observed_parent_height: 10,
            observed_parent_mtp: 20,
            source_height: 9,
            source_mtp: 19,
            valid_until_mtp: 30,
            base_asset_id: [2; 32],
            quote_unit_id: [3; 32],
            redemption_covenant_commitment: [4; 32],
            source_checkpoint_commitment: [6; 32],
            source_state_root: [5; 32],
            quote_atoms_per_whole_base: 1_000,
            outstanding_base_atoms: u128::from(PRICE_SCALE),
            redeemable_reserve_quote_atoms: 1_000,
            redemption_enabled: true,
        };
        assert_eq!(
            public.canonical_bytes().len(),
            CONVERSION_LEG_PUBLIC_VALUES_LEN_V2
        );
        assert_ne!(public.digest(), [0; 32]);
    }

    #[test]
    fn direct_native_absence_envelope_is_unique_and_mutation_safe() {
        let ecx = ConversionLegConsensusProofV2::canonical_absent(ConversionLegKindV2::EcxBtc);
        let usdd = ConversionLegConsensusProofV2::canonical_absent(ConversionLegKindV2::UsddUsd);
        assert!(ecx.is_canonical_absent(ConversionLegKindV2::EcxBtc));
        assert!(!ecx.is_canonical_absent(ConversionLegKindV2::UsddUsd));
        assert!(usdd.is_canonical_absent(ConversionLegKindV2::UsddUsd));

        let mut mutated_public_value = ecx.clone();
        mutated_public_value.public_values.source_height = 1;
        assert!(!mutated_public_value.is_canonical_absent(ConversionLegKindV2::EcxBtc));

        let mut mutated_proof = ecx;
        mutated_proof.proof.push(0);
        assert!(!mutated_proof.is_canonical_absent(ConversionLegKindV2::EcxBtc));
    }

    #[test]
    fn verifier_type_is_objectively_fail_closed() {
        let error = MarkerVerifier
            .verify([1; 32], b"values", b"not-the-marker")
            .unwrap_err();
        assert_eq!(error, ConsensusProofVerificationError);
    }

    #[test]
    fn deferred_marker_is_not_a_standalone_conversion_proof() {
        let program_id = [7; 32];
        let public_values = [8; CONVERSION_LEG_PUBLIC_VALUES_LEN_V2];
        let marker = sp1_deferred_proof_marker(program_id, &public_values);
        assert!(DenyAllConsensusProofs
            .verify(program_id, &public_values, &marker)
            .is_err());
    }

    #[test]
    fn ethereum_height_is_not_compared_to_bitcoin_height() {
        // An execution block number in the tens of millions is normal while
        // the observed Bitcoin parent height is below one million. Only the
        // authenticated timestamps are comparable across these chains.
        let bitcoin_parent_height = 900_000u64;
        let ethereum_source_height = 25_000_000u64;
        assert!(ethereum_source_height > bitcoin_parent_height);
        assert!(source_clock_is_current(
            ethereum_source_height,
            1_800_000_000,
            1_800_000_600,
            1_800_000_300,
            600,
        ));
    }

    #[test]
    fn authenticated_range_floors_lower_but_ceils_non_divisible_upper_endpoint() {
        assert_eq!(convert_scalar_endpoint_v2(10, 2, 3, false), Ok(6));
        assert_eq!(convert_scalar_endpoint_v2(11, 2, 3, true), Ok(8));
        assert_eq!(convert_scalar_endpoint_v2(12, 2, 3, true), Ok(8));
    }

    #[test]
    fn authenticated_range_endpoint_rejects_unrepresentable_u64_result() {
        assert_eq!(
            convert_scalar_endpoint_v2(u64::MAX, u64::MAX, 1, true),
            Err(ConversionLegErrorV2::ArithmeticOverflow)
        );
    }
}
