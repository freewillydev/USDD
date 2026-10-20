//! Fixed live-Alpha BIP300 policy, separate from the uniform v2 relation.
//!
//! Audited reference: `bip300301-enforcer-alphanet-no-txindex` at
//! `86543d13b32865ae629dbc8a373824e2c5aabb51`, `lib/types.rs` FORKNET/alphanet
//! and `lib/validator/task/mod.rs` M2 activation/failure, M6 expiry/inclusion,
//! and preactivation handling. These values match the dated live GetChainInfo
//! observation; that observation alone is NOT reproducible binary provenance.
//!
//! This ports the policy distinction only. It reuses v2 message/transaction
//! parsing, which still requires complete differential qualification against
//! the enforcer. It does not establish full block validity, checkpoint
//! authenticity, best-chain selection, or activation/proof readiness. The
//! recursive frontier/journals and conversion guest must explicitly bind this
//! v3 commitment before this policy can become a production proof relation.

use super::{
    apply_bip300_block_with_policy, Bip300AllSlotStateV2, Bip300BlockEffectsV2,
    Bip300ConsensusParametersV2, Bip300ReplayErrorV2, ReplayPolicy, BIP300_MAX_COINBASE_OUTPUTS_V2,
};
use bitcoin::hashes::Hash as _;
use bitcoin::{Block, BlockHash, Network};
use serde::{Deserialize, Serialize};

// Unreleased policy revision 2 also binds the native one-M8-per-slot rule.
// Revision 1 commitments/receipts are not compatible with this relation.
pub const ALPHA_BIP300_POLICY_VERSION_V3: u8 = 2;
pub const ALPHA_BIP300_ACTIVATION_HEIGHT_V3: u32 = 963_648;
pub const ALPHA_USED_PROPOSAL_MAX_AGE_V3: u32 = 144;
pub const ALPHA_USED_PROPOSAL_THRESHOLD_V3: u16 = 72;
pub const ALPHA_UNUSED_PROPOSAL_MAX_AGE_V3: u32 = 36;
pub const ALPHA_UNUSED_PROPOSAL_THRESHOLD_V3: u16 = 30;
pub const ALPHA_WITHDRAWAL_MAX_AGE_V3: u32 = 144;
pub const ALPHA_WITHDRAWAL_THRESHOLD_V3: u16 = 72;

// At most one coinbase's output bound per age, plus both age zero and the
// candidate block before its expiry pass. These bounds must cover the LONGER
// Alpha windows rather than inherit v2's short-window multiplier of 12.
pub const ALPHA_MAX_PENDING_PROPOSALS_V3: usize =
    BIP300_MAX_COINBASE_OUTPUTS_V2 * (ALPHA_USED_PROPOSAL_MAX_AGE_V3 as usize + 2);
pub const ALPHA_MAX_PENDING_M6IDS_V3: usize =
    BIP300_MAX_COINBASE_OUTPUTS_V2 * (ALPHA_WITHDRAWAL_MAX_AGE_V3 as usize + 2);

/// Storage compatibility only: used-slot/withdrawal values in the inner v2
/// state. Unused-slot policy is never inferred from these uniform fields.
const ALPHA_INNER_PARAMETERS_V3: Bip300ConsensusParametersV2 = Bip300ConsensusParametersV2 {
    proposal_max_age: ALPHA_USED_PROPOSAL_MAX_AGE_V3,
    proposal_activation_threshold: ALPHA_USED_PROPOSAL_THRESHOLD_V3,
    withdrawal_max_age: ALPHA_WITHDRAWAL_MAX_AGE_V3,
    withdrawal_inclusion_threshold: ALPHA_WITHDRAWAL_THRESHOLD_V3,
};

fn alpha_genesis() -> BlockHash {
    bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).block_hash()
}

/// Bind all policy components, including the used/unused distinction,
/// activation height, strict/inclusive comparisons and transient item bounds.
/// The rule semantics are fixed program text, not witness-supplied flags.
pub fn alpha_bip300_policy_commitment_v3() -> [u8; 32] {
    let mut bytes = vec![ALPHA_BIP300_POLICY_VERSION_V3];
    bytes.extend_from_slice(alpha_genesis().as_byte_array());
    bytes.extend_from_slice(&ALPHA_BIP300_ACTIVATION_HEIGHT_V3.to_be_bytes());
    for (age, threshold) in [
        (
            ALPHA_USED_PROPOSAL_MAX_AGE_V3,
            ALPHA_USED_PROPOSAL_THRESHOLD_V3,
        ),
        (
            ALPHA_UNUSED_PROPOSAL_MAX_AGE_V3,
            ALPHA_UNUSED_PROPOSAL_THRESHOLD_V3,
        ),
        (ALPHA_WITHDRAWAL_MAX_AGE_V3, ALPHA_WITHDRAWAL_THRESHOLD_V3),
    ] {
        bytes.extend_from_slice(&age.to_be_bytes());
        bytes.extend_from_slice(&threshold.to_be_bytes());
    }
    bytes.extend_from_slice(&(BIP300_MAX_COINBASE_OUTPUTS_V2 as u64).to_be_bytes());
    bytes.extend_from_slice(&(ALPHA_MAX_PENDING_PROPOSALS_V3 as u64).to_be_bytes());
    bytes.extend_from_slice(&(ALPHA_MAX_PENDING_M6IDS_V3 as u64).to_be_bytes());
    bytes.extend_from_slice(b"m2:ancestor-only,strict-votes,inclusive-age,current-active-slot;proposal-expiry:age>max-or-(age>max-fails-and-fails>=max-fails);m6:strict-score,inclusive-age;preactivation:ignore;m8:one-valid-request-per-slot-per-block");
    crate::tagged_hash("ECX/alpha-bip300-policy/v3", &bytes)
}

/// The private inner state is serializable for witnesses, but all entry points
/// validate its fixed Alpha bindings. There is no selectable network, policy,
/// activation height, or unused-slot parameter field in this API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaBip300AllSlotStateV3 {
    state: Bip300AllSlotStateV2,
}

impl AlphaBip300AllSlotStateV3 {
    pub fn before_genesis() -> Self {
        Self {
            state: Bip300AllSlotStateV2::before_genesis(alpha_genesis(), ALPHA_INNER_PARAMETERS_V3)
                .expect("fixed nonzero genesis and valid Alpha parameters"),
        }
    }

    /// Shape/binding validation only. The enclosing proof must independently
    /// verify the receipt/checkpoint authenticating every imported state field.
    /// Calling this constructor does not authenticate caller-supplied history.
    pub fn from_authenticated_state(
        state: Bip300AllSlotStateV2,
    ) -> Result<Self, Bip300ReplayErrorV2> {
        let result = Self { state };
        result.validate()?;
        Ok(result)
    }

    /// Read-only legacy-shaped storage, not a v2-policy proof statement.
    pub fn as_state(&self) -> &Bip300AllSlotStateV2 {
        &self.state
    }

    pub fn validate(&self) -> Result<(), Bip300ReplayErrorV2> {
        self.state.validate_with_policy(ReplayPolicy::AlphaV3)
    }

    /// Distinct domain and fixed policy bind all mutable state plus the
    /// otherwise absent unused-slot and activation rules. A generic v2 state
    /// commitment is NOT interchangeable with this commitment.
    pub fn commitment(&self) -> Result<[u8; 32], Bip300ReplayErrorV2> {
        let mut bytes = alpha_bip300_policy_commitment_v3().to_vec();
        bytes.extend_from_slice(&self.state.commitment_with_policy(ReplayPolicy::AlphaV3)?);
        Ok(crate::tagged_hash(
            "ECX/alpha-bip300-all-slot-state/v3",
            &bytes,
        ))
    }
}

pub(super) fn validate_fixed_alpha_state(
    state: &Bip300AllSlotStateV2,
) -> Result<(), Bip300ReplayErrorV2> {
    if state.network_genesis != alpha_genesis()
        || state.consensus_parameters != ALPHA_INNER_PARAMETERS_V3
    {
        return Err(Bip300ReplayErrorV2::InvalidConsensusParameters);
    }
    if (state.next_height <= ALPHA_BIP300_ACTIVATION_HEIGHT_V3
        && (!state.proposals.is_empty()
            || !state.active_slots.is_empty()
            || !state.previous_effective_m4.is_empty()))
        || state
            .proposals
            .values()
            .any(|proposal| proposal.proposal_height < ALPHA_BIP300_ACTIVATION_HEIGHT_V3)
        || state.active_slots.values().any(|active| {
            active.activation_height < ALPHA_BIP300_ACTIVATION_HEIGHT_V3
                || active
                    .pending_m6ids
                    .iter()
                    .any(|pending| pending.proposal_height < ALPHA_BIP300_ACTIVATION_HEIGHT_V3)
        })
    {
        return Err(Bip300ReplayErrorV2::MalformedState);
    }
    Ok(())
}

/// Apply fixed Alpha policy to an independently fully verified parent block.
/// Before activation, only the parent position advances: all BIP300/301
/// messages and treasury transitions are ignored, matching the enforcer.
/// Caller input is untouched on every failure; only a complete block commits.
pub fn apply_alpha_bip300_block_v3(
    state: &AlphaBip300AllSlotStateV3,
    block: &Block,
) -> Result<(AlphaBip300AllSlotStateV3, Bip300BlockEffectsV2), Bip300ReplayErrorV2> {
    let (next, effects) =
        apply_bip300_block_with_policy(&state.state, block, ReplayPolicy::AlphaV3)?;
    Ok((AlphaBip300AllSlotStateV3 { state: next }, effects))
}

#[cfg(test)]
#[path = "alpha_bip300_v3_tests.rs"]
mod tests;
