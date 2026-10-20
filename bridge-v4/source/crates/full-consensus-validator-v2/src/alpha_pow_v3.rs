//! Staged ECX Alpha parent-header primitives, not a full-consensus relation.
//!
//! Alpha shares Bitcoin's genesis and most header rules, but resets the target
//! at height 963648. Selecting `bitcoin::Network::Bitcoin` does not select Alpha.
//! This module deliberately has no witness-selected network or PoW parameters.
//!
//! Before a recursive guest may use these primitives, its reviewed checkpoint
//! and executed-state commitment must authenticate this profile, the exact
//! context below, chainwork, UTXOs, deployments and all-slot BIP300 state.
//! Headers alone do not establish Alpha transaction/BIP300 consensus. In
//! particular this module is NOT wired into the existing Signet conversion
//! guest and must not be used to mark an Alpha activation profile proof-ready.
//!
//! Source rules: ecash-bitcoin-alphanet `src/kernel/chainparams.cpp` CMainParams,
//! `src/pow.cpp` GetNextWorkRequired/CalculateNextWorkRequired, and
//! `src/validation.cpp` ContextualCheckBlockHeader. See the accompanying dated
//! source/runtime evidence before using these staged rules in a release.

use crate::{median_time_past_v2, tagged_hash, FullValidatorPrimitiveErrorV2, Hash32};
use bitcoin::block::Header;
use bitcoin::consensus::{encode::serialize, Params};
use bitcoin::hashes::Hash as _;
use bitcoin::pow::{CompactTarget, Target};
use serde::{Deserialize, Serialize};

pub const ALPHA_POW_PROFILE_VERSION_V3: u8 = 1;
pub const ALPHA_FORK_HEIGHT_V3: u32 = 963_648;
pub const ALPHA_RETARGET_INTERVAL_V3: u32 = 2_016;
pub const ALPHA_TARGET_TIMESPAN_V3: u32 = 14 * 24 * 60 * 60;
pub const ALPHA_TARGET_SPACING_V3: u32 = 10 * 60;
pub const ALPHA_MAX_FUTURE_SECONDS_V3: u64 = 2 * 60 * 60;
pub const ALPHA_POW_LIMIT_BITS_V3: u32 = 0x1d00ffff;

/// Exact mutable context. There is intentionally no `Network` discriminator:
/// callers cannot turn this relation into Signet, regtest, or stock Bitcoin.
/// This data still REQUIRES an authenticated checkpoint/predecessor receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaHeaderContextV3 {
    pub previous_height: u32,
    pub previous_header: Header,
    /// Ordered oldest to newest, ending in previous_header.time.
    pub previous_11_times: Vec<u32>,
    pub retarget_epoch_start_time: u32,
}

/// A domain-separated commitment to fixed header rules, not a complete Alpha
/// consensus configuration or a reviewed source-checkpoint commitment.
pub fn alpha_pow_profile_commitment_v3() -> Hash32 {
    let mut bytes = vec![ALPHA_POW_PROFILE_VERSION_V3];
    bytes.extend_from_slice(
        &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin)
            .block_hash()
            .to_byte_array(),
    );
    bytes.extend_from_slice(&ALPHA_FORK_HEIGHT_V3.to_be_bytes());
    bytes.extend_from_slice(&ALPHA_RETARGET_INTERVAL_V3.to_be_bytes());
    bytes.extend_from_slice(&ALPHA_TARGET_TIMESPAN_V3.to_be_bytes());
    bytes.extend_from_slice(&ALPHA_TARGET_SPACING_V3.to_be_bytes());
    bytes.extend_from_slice(&ALPHA_POW_LIMIT_BITS_V3.to_be_bytes());
    bytes.extend_from_slice(&ALPHA_MAX_FUTURE_SECONDS_V3.to_be_bytes());
    // BIP34, BIP66, BIP65 version-enforcement heights, respectively.
    for height in [227_931u32, 363_725, 388_381] {
        bytes.extend_from_slice(&height.to_be_bytes());
    }
    // No Signet challenge, no min-difficulty exception, retargeting enabled.
    bytes.extend_from_slice(&[0, 0, 1]);
    tagged_hash("ECX/alpha-parent-header-profile/v3", &bytes)
}

impl AlphaHeaderContextV3 {
    fn validate(&self) -> Result<(), FullValidatorPrimitiveErrorV2> {
        let target = self.previous_header.target();
        if self.previous_height < 10
            || self.previous_11_times.len() != 11
            || self.previous_11_times.last() != Some(&self.previous_header.time)
            || self.previous_11_times.contains(&0)
            || self.retarget_epoch_start_time == 0
            || target == Target::ZERO
            || target > Target::MAX_ATTAINABLE_MAINNET
            || target.to_compact_lossy() != self.previous_header.bits
            || (self
                .previous_height
                .is_multiple_of(ALPHA_RETARGET_INTERVAL_V3)
                && self.retarget_epoch_start_time != self.previous_header.time)
        {
            return Err(FullValidatorPrimitiveErrorV2::DifficultyContext);
        }
        Ok(())
    }

    /// This binds every field and the fixed Alpha header profile. It is not a
    /// replacement for verifying the receipt that authenticates this context.
    pub fn commitment(&self) -> Result<Hash32, FullValidatorPrimitiveErrorV2> {
        self.validate()?;
        let mut bytes = alpha_pow_profile_commitment_v3().to_vec();
        bytes.extend_from_slice(&self.previous_height.to_be_bytes());
        bytes.extend_from_slice(&serialize(&self.previous_header));
        for time in &self.previous_11_times {
            bytes.extend_from_slice(&time.to_be_bytes());
        }
        bytes.extend_from_slice(&self.retarget_epoch_start_time.to_be_bytes());
        Ok(tagged_hash("ECX/alpha-parent-header-context/v3", &bytes))
    }
}

pub fn expected_alpha_next_target_v3(
    context: &AlphaHeaderContextV3,
) -> Result<CompactTarget, FullValidatorPrimitiveErrorV2> {
    context.validate()?;
    let height = context
        .previous_height
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::DifficultyContext)?;
    if height == ALPHA_FORK_HEIGHT_V3 {
        return Ok(CompactTarget::from_consensus(ALPHA_POW_LIMIT_BITS_V3));
    }
    if !height.is_multiple_of(ALPHA_RETARGET_INTERVAL_V3) {
        return Ok(context.previous_header.bits);
    }
    // Source-equivalent clamp to [timespan/4, timespan*4]. A negative Core
    // signed delta is also clamped to timespan/4 by this implementation.
    Ok(CompactTarget::from_next_work_required(
        context.previous_header.bits,
        u64::from(
            context
                .previous_header
                .time
                .saturating_sub(context.retarget_epoch_start_time),
        ),
        Params::MAINNET,
    ))
}

/// Validate the next header's link, contextual target (including the fork
/// reset), PoW, MTP, authenticated future-time bound and version floor.
/// Does not verify block bodies, BIP300, UTXOs or the context's provenance.
///
/// `authenticated_time` must come from the enclosing relation's independently
/// authenticated observation clock. Alpha Core uses its node wall clock here,
/// not MTP or the candidate header time. This primitive cannot authenticate the
/// argument and `AlphaHeaderContextV3::commitment` does not bind it. Choosing the
/// candidate time itself would make the future-time check vacuous; callers must
/// not treat doing so as evidence of equivalence to a live node's time checks.
pub fn verify_alpha_next_header_v3(
    context: &AlphaHeaderContextV3,
    header: Header,
    authenticated_time: u64,
) -> Result<AlphaHeaderContextV3, FullValidatorPrimitiveErrorV2> {
    let expected = expected_alpha_next_target_v3(context)?;
    if header.prev_blockhash != context.previous_header.block_hash() {
        return Err(FullValidatorPrimitiveErrorV2::HeaderLink);
    }
    let future_limit = authenticated_time
        .checked_add(ALPHA_MAX_FUTURE_SECONDS_V3)
        .ok_or(FullValidatorPrimitiveErrorV2::HeaderTime)?;
    if header.time <= median_time_past_v2(&context.previous_11_times)?
        || u64::from(header.time) > future_limit
    {
        return Err(FullValidatorPrimitiveErrorV2::HeaderTime);
    }
    let height = context
        .previous_height
        .checked_add(1)
        .ok_or(FullValidatorPrimitiveErrorV2::DifficultyContext)?;
    let version = header.version.to_consensus();
    if (height >= 227_931 && version < 2)
        || (height >= 363_725 && version < 3)
        || (height >= 388_381 && version < 4)
        || header.bits != expected
    {
        return Err(FullValidatorPrimitiveErrorV2::ProofOfWork);
    }
    header
        .validate_pow(Target::from(expected))
        .map_err(|_| FullValidatorPrimitiveErrorV2::ProofOfWork)?;
    let mut times = context.previous_11_times.clone();
    times.remove(0);
    times.push(header.time);
    Ok(AlphaHeaderContextV3 {
        previous_height: height,
        previous_header: header,
        previous_11_times: times,
        retarget_epoch_start_time: if height.is_multiple_of(ALPHA_RETARGET_INTERVAL_V3) {
            header.time
        } else {
            context.retarget_epoch_start_time
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic contexts exercise arithmetic only; these are NOT authenticated
    // Alpha checkpoints or successful live-chain replay evidence.
    fn context(height: u32, bits: u32, timespan: u32) -> AlphaHeaderContextV3 {
        let mut header =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        header.bits = CompactTarget::from_consensus(bits);
        header.time = 1_700_000_000;
        AlphaHeaderContextV3 {
            previous_height: height,
            previous_header: header,
            previous_11_times: (header.time - 10..=header.time).collect(),
            retarget_epoch_start_time: header.time - timespan,
        }
    }

    #[test]
    fn activation_reset_is_not_stock_bitcoin_retarget() {
        let ctx = context(
            ALPHA_FORK_HEIGHT_V3 - 1,
            0x1701e2a0,
            ALPHA_TARGET_TIMESPAN_V3,
        );
        assert_eq!(
            expected_alpha_next_target_v3(&ctx).unwrap().to_consensus(),
            ALPHA_POW_LIMIT_BITS_V3
        );
        let ordinary = CompactTarget::from_next_work_required(
            ctx.previous_header.bits,
            u64::from(ALPHA_TARGET_TIMESPAN_V3),
            Params::MAINNET,
        );
        assert_ne!(ordinary.to_consensus(), ALPHA_POW_LIMIT_BITS_V3);
    }

    #[test]
    fn ordinary_blocks_inherit_target_without_min_difficulty_exception() {
        let ctx = context(ALPHA_FORK_HEIGHT_V3 + 1, 0x1b0404cb, 1);
        assert_eq!(
            expected_alpha_next_target_v3(&ctx).unwrap(),
            ctx.previous_header.bits
        );
    }

    #[test]
    fn arithmetic_parameters_equal_the_committed_alpha_profile() {
        let params = Params::MAINNET;
        assert_eq!(
            params.pow_target_timespan,
            u64::from(ALPHA_TARGET_TIMESPAN_V3)
        );
        assert_eq!(
            params.pow_target_spacing,
            u64::from(ALPHA_TARGET_SPACING_V3)
        );
        assert_eq!(
            params.difficulty_adjustment_interval(),
            u64::from(ALPHA_RETARGET_INTERVAL_V3)
        );
        assert!(!params.allow_min_difficulty_blocks);
        assert!(!params.no_pow_retargeting);
        assert_eq!(
            params.max_attainable_target,
            Target::from(CompactTarget::from_consensus(ALPHA_POW_LIMIT_BITS_V3))
        );
    }

    #[test]
    fn ordinary_retarget_matches_independent_integer_vectors() {
        // Literal expectations computed independently with exact BigInt
        // expand(bits) * clamp(seconds, 302400, 4838400) / 1209600,
        // followed by the 0x1d00ffff cap and canonical compact encoding.
        // Do not derive these expectations using the implementation under test.
        let height = ALPHA_FORK_HEIGHT_V3 + ALPHA_RETARGET_INTERVAL_V3 - 1;
        for (bits, seconds, expected) in [
            (0x1b0404cb, 1_209_600, 0x1b0404cb),
            (0x1b0404cb, 604_800, 0x1b020265),
            (0x1b0404cb, 2_419_200, 0x1b080996),
            (0x1b0404cb, 1, 0x1b010132),
            (0x1b0404cb, 0, 0x1b010132),
            (0x1b0404cb, 9_999_999, 0x1b10132c),
            (0x1c7fffff, 4_838_400, 0x1d00ffff),
        ] {
            assert_eq!(
                expected_alpha_next_target_v3(&context(height, bits, seconds))
                    .unwrap()
                    .to_consensus(),
                expected,
                "bits={bits:08x}, seconds={seconds}"
            );
        }
    }

    #[test]
    fn ordinary_retarget_clamps_timespan_and_caps_at_pow_limit() {
        let height = ALPHA_FORK_HEIGHT_V3 + ALPHA_RETARGET_INTERVAL_V3 - 1;
        let bits = 0x1b0404cb;
        let lower =
            expected_alpha_next_target_v3(&context(height, bits, ALPHA_TARGET_TIMESPAN_V3 / 4))
                .unwrap();
        assert_eq!(
            expected_alpha_next_target_v3(&context(height, bits, 0)).unwrap(),
            lower
        );
        assert_eq!(
            expected_alpha_next_target_v3(&context(height, bits, 1)).unwrap(),
            lower
        );
        let mut negative_delta = context(height, bits, 1);
        negative_delta.retarget_epoch_start_time = negative_delta.previous_header.time + 1;
        assert_eq!(
            expected_alpha_next_target_v3(&negative_delta).unwrap(),
            lower
        );
        let upper =
            expected_alpha_next_target_v3(&context(height, bits, ALPHA_TARGET_TIMESPAN_V3 * 4))
                .unwrap();
        assert_eq!(
            expected_alpha_next_target_v3(&context(height, bits, ALPHA_TARGET_TIMESPAN_V3 * 8))
                .unwrap(),
            upper
        );
        assert_eq!(
            expected_alpha_next_target_v3(&context(
                height,
                ALPHA_POW_LIMIT_BITS_V3,
                ALPHA_TARGET_TIMESPAN_V3 * 4
            ))
            .unwrap()
            .to_consensus(),
            ALPHA_POW_LIMIT_BITS_V3
        );
    }

    #[test]
    fn invalid_context_never_selects_a_target() {
        let valid = context(
            ALPHA_FORK_HEIGHT_V3 - 1,
            0x1701e2a0,
            ALPHA_TARGET_TIMESPAN_V3,
        );
        let mutations: Vec<Box<dyn Fn(&mut AlphaHeaderContextV3)>> = vec![
            Box::new(|c| c.previous_height = u32::MAX),
            Box::new(|c| c.previous_height = 9),
            Box::new(|c| {
                c.previous_11_times.pop();
            }),
            Box::new(|c| c.previous_11_times[10] += 1),
            Box::new(|c| c.previous_11_times[0] = 0),
            Box::new(|c| c.retarget_epoch_start_time = 0),
            Box::new(|c| c.previous_header.bits = CompactTarget::from_consensus(0)),
            Box::new(|c| c.previous_header.bits = CompactTarget::from_consensus(0x207fffff)),
            Box::new(|c| c.previous_height = ALPHA_FORK_HEIGHT_V3),
        ];
        for mutate in mutations {
            let mut bad = valid.clone();
            mutate(&mut bad);
            assert!(expected_alpha_next_target_v3(&bad).is_err());
        }
    }

    #[test]
    fn context_commitment_binds_all_mutable_fields() {
        let valid = context(
            ALPHA_FORK_HEIGHT_V3 - 1,
            0x1701e2a0,
            ALPHA_TARGET_TIMESPAN_V3,
        );
        let original = valid.commitment().unwrap();
        let mutations: Vec<Box<dyn Fn(&mut AlphaHeaderContextV3)>> = vec![
            Box::new(|c| c.previous_height -= 1),
            Box::new(|c| c.previous_header.nonce ^= 1),
            Box::new(|c| c.previous_11_times[0] -= 1),
            Box::new(|c| c.retarget_epoch_start_time -= 1),
        ];
        for mutate in mutations {
            let mut other = valid.clone();
            mutate(&mut other);
            assert_ne!(original, other.commitment().unwrap());
        }
    }
}
