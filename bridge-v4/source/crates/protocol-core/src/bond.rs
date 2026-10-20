//! Version-two proof-enforced insurance-bond primitives.
//!
//! This module is intentionally independent of the version-one exchange state
//! and transition verifier.  Integrating it into a successor transition must
//! bind [`BondPublicStateV2`] into the v2 state commitment and authenticate the
//! confidential openings used by subscriptions and redemptions.
//!
//! Amounts in this module are non-negative atomic units.  USDD and bond shares
//! both use eight decimal places.  Individual redemption queue entries belong
//! in the private transition witness; only the queue root, cursors, and
//! aggregate queued shares are public.

use crate::codec::{put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::Hash32;
use crate::ProtocolError;

/// Bond protocol version. Version one remains untouched.
pub const BOND_PROTOCOL_VERSION_V2: u8 = 2;
/// Bond shares use the same eight-decimal atomic scale as USDD.
pub const BOND_SHARE_DECIMALS: u8 = 8;
pub const BOND_SHARE_SCALE: u64 = 100_000_000;
pub const BOND_FIXED_SUPPLY_WHOLE: u64 = 21_000_000;
/// Exactly 21,000,000 shares, expressed in eight-decimal atomic units.
pub const BOND_FIXED_SUPPLY_ATOMS: u64 = BOND_FIXED_SUPPLY_WHOLE * BOND_SHARE_SCALE;
/// A queued redemption remains loss-bearing for this many parent blocks.
pub const BOND_REDEMPTION_DELAY_PARENT_BLOCKS: u64 = 1_008;
pub const BOND_FULL_COVERAGE_BPS: u32 = 10_000;
pub const BOND_TARGET_COVERAGE_BPS: u32 = 12_500;

const BPS_DENOMINATOR: u128 = 10_000;

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn decode_u128(decoder: &mut Decoder<'_>) -> Result<u128, ProtocolError> {
    Ok(u128::from_be_bytes(decoder.take()?))
}

/// Exact `floor(value * multiplier / divisor)` without requiring a 256-bit
/// intermediate. The returned remainder is relative to `divisor`.
fn mul_u128_u64_div_rem(
    value: u128,
    multiplier: u64,
    divisor: u128,
) -> Result<(u128, u128), ProtocolError> {
    if divisor == 0 {
        return Err(ProtocolError::DivisionByZero);
    }

    fn add_remainders(left: u128, right: u128, divisor: u128) -> (u128, u128) {
        debug_assert!(left < divisor && right < divisor);
        if left >= divisor - right {
            (left - (divisor - right), 1)
        } else {
            (left + right, 0)
        }
    }

    let value_quotient = value / divisor;
    let value_remainder = value % divisor;
    let mut quotient = 0u128;
    let mut remainder = 0u128;
    for bit in (0..u64::BITS).rev() {
        let (doubled_remainder, carry) = add_remainders(remainder, remainder, divisor);
        remainder = doubled_remainder;
        quotient = quotient
            .checked_mul(2)
            .and_then(|result| result.checked_add(carry))
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        if (multiplier >> bit) & 1 == 1 {
            let (sum_remainder, carry) = add_remainders(remainder, value_remainder, divisor);
            remainder = sum_remainder;
            quotient = quotient
                .checked_add(value_quotient)
                .and_then(|result| result.checked_add(carry))
                .ok_or(ProtocolError::ArithmeticOverflow)?;
        }
    }
    Ok((quotient, remainder))
}

/// Trading permissions implied by authenticated insurance coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CapitalModeV2 {
    /// Insurance is at least 125% of the full-bound deficit.
    Normal = 0,
    /// Insurance covers the deficit but not the 125% target.
    ReduceOnly = 1,
    /// Insurance does not cover the deficit; only recapitalization is valid.
    RecapitalizationOnly = 2,
}

impl TryFrom<u8> for CapitalModeV2 {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::ReduceOnly),
            2 => Ok(Self::RecapitalizationOnly),
            other => Err(ProtocolError::InvalidDiscriminant(other)),
        }
    }
}

impl CanonicalEncode for CapitalModeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

/// Public capital state committed by the v2 exchange state.
///
/// `deployment_commitment` must bind the Elements issuance transaction, the
/// fixed supply, destruction of the reissuance token, and the immutable
/// inventory covenant. This type deliberately does not pretend that a non-zero
/// commitment proves those facts; the settlement verifier must authenticate
/// them when deploying v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondPublicStateV2 {
    pub version: u8,
    pub bond_asset_id: Hash32,
    pub deployment_commitment: Hash32,
    pub inventory_covenant_hash: Hash32,
    pub insurance_reserve: u128,
    pub issued_share_atoms: u64,
    pub outstanding_share_atoms: u64,
    pub inventory_share_atoms: u64,
    pub full_bound_deficit: u128,
    pub target_reserve: u128,
    /// Retained only to make the v2 invariant explicit. It must always be zero.
    pub legacy_fee_pool: u128,
    pub redemption_queue_root: Hash32,
    /// Sequence of the current FIFO head. Equal to `redemption_tail` if empty.
    pub redemption_head: u64,
    /// Next sequence that may be appended.
    pub redemption_tail: u64,
    pub queued_redemption_share_atoms: u64,
    pub capital_mode: CapitalModeV2,
}

impl BondPublicStateV2 {
    pub const ENCODED_LEN: usize = 242;

    pub fn validate(self) -> Result<Self, ProtocolError> {
        let conserved_supply = self
            .outstanding_share_atoms
            .checked_add(self.inventory_share_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let expected_target = target_reserve_125(self.full_bound_deficit)?;
        let expected_mode = capital_mode_for(self.insurance_reserve, self.full_bound_deficit)?;
        let empty_queue = self.redemption_head == self.redemption_tail;

        if self.version != BOND_PROTOCOL_VERSION_V2
            || self.bond_asset_id == [0; 32]
            || self.deployment_commitment == [0; 32]
            || self.inventory_covenant_hash == [0; 32]
            || self.redemption_queue_root == [0; 32]
            || self.issued_share_atoms != BOND_FIXED_SUPPLY_ATOMS
            || conserved_supply != self.issued_share_atoms
            || self.queued_redemption_share_atoms > self.outstanding_share_atoms
            || self.redemption_head > self.redemption_tail
            || empty_queue != (self.queued_redemption_share_atoms == 0)
            || self.insurance_reserve > i128::MAX as u128
            || self.full_bound_deficit > i128::MAX as u128
            || self.target_reserve != expected_target
            || self.target_reserve > i128::MAX as u128
            || self.legacy_fee_pool != 0
            || self.capital_mode != expected_mode
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let state = Self {
            version: decoder.u8()?,
            bond_asset_id: decoder.take()?,
            deployment_commitment: decoder.take()?,
            inventory_covenant_hash: decoder.take()?,
            insurance_reserve: decode_u128(&mut decoder)?,
            issued_share_atoms: decoder.u64()?,
            outstanding_share_atoms: decoder.u64()?,
            inventory_share_atoms: decoder.u64()?,
            full_bound_deficit: decode_u128(&mut decoder)?,
            target_reserve: decode_u128(&mut decoder)?,
            legacy_fee_pool: decode_u128(&mut decoder)?,
            redemption_queue_root: decoder.take()?,
            redemption_head: decoder.u64()?,
            redemption_tail: decoder.u64()?,
            queued_redemption_share_atoms: decoder.u64()?,
            capital_mode: CapitalModeV2::try_from(decoder.u8()?)?,
        };
        decoder.finish()?;
        state.validate()
    }
}

impl CanonicalEncode for BondPublicStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.bond_asset_id);
        out.extend_from_slice(&self.deployment_commitment);
        out.extend_from_slice(&self.inventory_covenant_hash);
        put_u128(out, self.insurance_reserve);
        put_u64(out, self.issued_share_atoms);
        put_u64(out, self.outstanding_share_atoms);
        put_u64(out, self.inventory_share_atoms);
        put_u128(out, self.full_bound_deficit);
        put_u128(out, self.target_reserve);
        put_u128(out, self.legacy_fee_pool);
        out.extend_from_slice(&self.redemption_queue_root);
        put_u64(out, self.redemption_head);
        put_u64(out, self.redemption_tail);
        put_u64(out, self.queued_redemption_share_atoms);
        self.capital_mode.encode_to(out);
    }
}

/// Private-witness representation of one confidential FIFO redemption.
///
/// Neither share amount is published directly. The v2 proof opens this entry
/// against `BondPublicStateV2::redemption_queue_root` and updates the aggregate
/// queued amount without revealing the claimant or destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RedemptionQueueEntryV2 {
    pub version: u8,
    pub sequence: u64,
    pub request_id: Hash32,
    pub claimant_commitment: Hash32,
    pub destination_script_hash: Hash32,
    pub requested_share_atoms: u64,
    pub remaining_share_atoms: u64,
    pub enqueued_parent_height: u64,
    pub unlock_parent_height: u64,
}

impl RedemptionQueueEntryV2 {
    pub const ENCODED_LEN: usize = 137;

    pub fn new(
        sequence: u64,
        request_id: Hash32,
        claimant_commitment: Hash32,
        destination_script_hash: Hash32,
        requested_share_atoms: u64,
        enqueued_parent_height: u64,
    ) -> Result<Self, ProtocolError> {
        let unlock_parent_height = enqueued_parent_height
            .checked_add(BOND_REDEMPTION_DELAY_PARENT_BLOCKS)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Self {
            version: BOND_PROTOCOL_VERSION_V2,
            sequence,
            request_id,
            claimant_commitment,
            destination_script_hash,
            requested_share_atoms,
            remaining_share_atoms: requested_share_atoms,
            enqueued_parent_height,
            unlock_parent_height,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, ProtocolError> {
        let expected_unlock = self
            .enqueued_parent_height
            .checked_add(BOND_REDEMPTION_DELAY_PARENT_BLOCKS)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if self.version != BOND_PROTOCOL_VERSION_V2
            || self.request_id == [0; 32]
            || self.claimant_commitment == [0; 32]
            || self.destination_script_hash == [0; 32]
            || self.requested_share_atoms == 0
            || self.remaining_share_atoms == 0
            || self.remaining_share_atoms > self.requested_share_atoms
            || self.unlock_parent_height != expected_unlock
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(self)
    }

    pub fn is_unlocked(self, parent_height: u64) -> bool {
        parent_height >= self.unlock_parent_height
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let entry = Self {
            version: decoder.u8()?,
            sequence: decoder.u64()?,
            request_id: decoder.take()?,
            claimant_commitment: decoder.take()?,
            destination_script_hash: decoder.take()?,
            requested_share_atoms: decoder.u64()?,
            remaining_share_atoms: decoder.u64()?,
            enqueued_parent_height: decoder.u64()?,
            unlock_parent_height: decoder.u64()?,
        };
        decoder.finish()?;
        entry.validate()
    }
}

impl CanonicalEncode for RedemptionQueueEntryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.claimant_commitment);
        out.extend_from_slice(&self.destination_script_hash);
        put_u64(out, self.requested_share_atoms);
        put_u64(out, self.remaining_share_atoms);
        put_u64(out, self.enqueued_parent_height);
        put_u64(out, self.unlock_parent_height);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionOutcomeV2 {
    pub contributed_usdd_atoms: u128,
    pub issued_share_atoms: u64,
    pub insurance_reserve_after: u128,
    pub outstanding_share_atoms_after: u64,
    pub inventory_share_atoms_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionOutcomeV2 {
    pub sequence: u64,
    pub redeemed_share_atoms: u64,
    pub paid_usdd_atoms: u128,
    pub remaining_entry_share_atoms: u64,
    pub insurance_reserve_after: u128,
    pub outstanding_share_atoms_after: u64,
    pub inventory_share_atoms_after: u64,
    pub queued_redemption_share_atoms_after: u64,
    pub redemption_head_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionCancellationV2 {
    pub sequence: u64,
    pub released_share_atoms: u64,
    pub queued_redemption_share_atoms_after: u64,
    pub redemption_head_after: u64,
}

/// Sum the magnitude of all negative account equities at one price endpoint.
/// The caller must include fees and the worst pending funding debit in each
/// supplied equity before calling this helper.
pub fn negative_equity_deficit(equities: &[i128]) -> Result<u128, ProtocolError> {
    equities.iter().try_fold(0u128, |total, equity| {
        let deficit = if *equity < 0 {
            equity.unsigned_abs()
        } else {
            0
        };
        total
            .checked_add(deficit)
            .ok_or(ProtocolError::ArithmeticOverflow)
    })
}

/// Worst total negative equity over the authenticated minimum and maximum
/// oracle endpoints. Per-account maxima are deliberately not mixed across
/// endpoints.
pub fn full_range_deficit(
    minimum_price_equities: &[i128],
    maximum_price_equities: &[i128],
) -> Result<u128, ProtocolError> {
    if minimum_price_equities.len() != maximum_price_equities.len() {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    let at_minimum = negative_equity_deficit(minimum_price_equities)?;
    let at_maximum = negative_equity_deficit(maximum_price_equities)?;
    Ok(at_minimum.max(at_maximum))
}

/// `ceil(deficit * 125%)` using checked integer arithmetic.
pub fn target_reserve_125(deficit: u128) -> Result<u128, ProtocolError> {
    let (floor, remainder) = mul_u128_u64_div_rem(
        deficit,
        u64::from(BOND_TARGET_COVERAGE_BPS),
        BPS_DENOMINATOR,
    )?;
    if remainder == 0 {
        Ok(floor)
    } else {
        floor
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

pub fn capital_mode_for(
    insurance_reserve: u128,
    deficit: u128,
) -> Result<CapitalModeV2, ProtocolError> {
    let target = target_reserve_125(deficit)?;
    Ok(if insurance_reserve >= target {
        CapitalModeV2::Normal
    } else if insurance_reserve >= deficit {
        CapitalModeV2::ReduceOnly
    } else {
        CapitalModeV2::RecapitalizationOnly
    })
}

/// Aggregate reserve coverage in basis points, rounded down. A zero-deficit
/// portfolio has no denominator; it is represented by the finite 125% target
/// sentinel so every authenticated public value remains interoperable with
/// exact-integer clients (including JavaScript) while expressing that the
/// coverage target is satisfied.
pub fn coverage_bps(insurance_reserve: u128, deficit: u128) -> Result<u128, ProtocolError> {
    if deficit == 0 {
        return Ok(u128::from(BOND_TARGET_COVERAGE_BPS));
    }
    Ok(mul_u128_u64_div_rem(
        insurance_reserve,
        u64::from(BOND_FULL_COVERAGE_BPS),
        deficit,
    )?
    .0)
}

/// Execution-time NAV in USDD atoms per one whole bond share, rounded down.
pub fn nav_per_whole_share_usdd_atoms(
    insurance_reserve: u128,
    outstanding_share_atoms: u64,
) -> Result<u128, ProtocolError> {
    if outstanding_share_atoms == 0 {
        return Err(ProtocolError::DivisionByZero);
    }
    insurance_reserve
        .checked_mul(u128::from(BOND_SHARE_SCALE))
        .ok_or(ProtocolError::ArithmeticOverflow)
        .map(|value| value / u128::from(outstanding_share_atoms))
}

/// Shares received for a USDD subscription, rounded in favor of the fund.
///
/// The first subscription is one atomic bond share per atomic USDD unit, even
/// if trading revenue accrued before any shares became outstanding. Later
/// subscriptions use `floor(contribution * outstanding / reserve)`. A wiped
/// fund with non-zero outstanding shares has zero NAV and requires a separately
/// specified recovery transition; this function fails closed instead of
/// assigning arbitrary shares.
pub fn subscription_share_atoms(
    contribution_usdd_atoms: u128,
    insurance_reserve: u128,
    outstanding_share_atoms: u64,
) -> Result<u64, ProtocolError> {
    if contribution_usdd_atoms == 0 {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    let shares = if outstanding_share_atoms == 0 {
        contribution_usdd_atoms
    } else {
        if insurance_reserve == 0 {
            return Err(ProtocolError::DivisionByZero);
        }
        mul_u128_u64_div_rem(
            contribution_usdd_atoms,
            outstanding_share_atoms,
            insurance_reserve,
        )?
        .0
    };
    if shares == 0 {
        return Err(ProtocolError::InsufficientCollateral);
    }
    u64::try_from(shares).map_err(|_| ProtocolError::ArithmeticOverflow)
}

pub fn apply_subscription(
    state: BondPublicStateV2,
    contribution_usdd_atoms: u128,
) -> Result<SubscriptionOutcomeV2, ProtocolError> {
    state.validate()?;
    let issued = subscription_share_atoms(
        contribution_usdd_atoms,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    if issued > state.inventory_share_atoms {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(SubscriptionOutcomeV2 {
        contributed_usdd_atoms: contribution_usdd_atoms,
        issued_share_atoms: issued,
        insurance_reserve_after: state
            .insurance_reserve
            .checked_add(contribution_usdd_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        outstanding_share_atoms_after: state
            .outstanding_share_atoms
            .checked_add(issued)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        inventory_share_atoms_after: state.inventory_share_atoms - issued,
    })
}

/// Execution-time USDD value of bond shares, rounded down so a redemption can
/// never withdraw more than its pro-rata NAV.
pub fn redemption_usdd_atoms(
    share_atoms: u64,
    insurance_reserve: u128,
    outstanding_share_atoms: u64,
) -> Result<u128, ProtocolError> {
    if share_atoms == 0 || outstanding_share_atoms == 0 {
        return Err(ProtocolError::DivisionByZero);
    }
    if share_atoms > outstanding_share_atoms {
        return Err(ProtocolError::ConservationViolation);
    }
    mul_u128_u64_div_rem(
        insurance_reserve,
        share_atoms,
        u128::from(outstanding_share_atoms),
    )
    .map(|(quotient, _)| quotient)
}

/// Largest share amount whose floor-rounded NAV payment does not exceed
/// `maximum_payment_usdd_atoms`.
pub fn maximum_redeemable_share_atoms(
    maximum_payment_usdd_atoms: u128,
    insurance_reserve: u128,
    outstanding_share_atoms: u64,
) -> Result<u64, ProtocolError> {
    if outstanding_share_atoms == 0 {
        return Err(ProtocolError::DivisionByZero);
    }
    if insurance_reserve == 0 || maximum_payment_usdd_atoms >= insurance_reserve {
        return Ok(outstanding_share_atoms);
    }

    // Binary search is deterministic and avoids overflowing a cross-product.
    let mut low = 0u64;
    let mut high = outstanding_share_atoms;
    while low < high {
        let midpoint = low + (high - low) / 2 + (high - low) % 2;
        let payment = redemption_usdd_atoms(midpoint, insurance_reserve, outstanding_share_atoms)?;
        if payment <= maximum_payment_usdd_atoms {
            low = midpoint;
        } else {
            high = midpoint - 1;
        }
    }
    Ok(low)
}

/// Plan execution of the current FIFO head while preserving 125% coverage.
///
/// `Ok(None)` is a normal fail-closed outcome: the entry is valid and mature,
/// but no positive-NAV share amount can safely redeem. The caller must update
/// the authenticated queue root with the partial remainder or remove the head
/// only after verifying the returned arithmetic inside the proof.
pub fn plan_fifo_redemption(
    state: BondPublicStateV2,
    entry: RedemptionQueueEntryV2,
    parent_height: u64,
) -> Result<Option<RedemptionOutcomeV2>, ProtocolError> {
    state.validate()?;
    entry.validate()?;
    if entry.sequence != state.redemption_head
        || entry.remaining_share_atoms > state.queued_redemption_share_atoms
        || !entry.is_unlocked(parent_height)
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    if state.insurance_reserve <= state.target_reserve {
        return Ok(None);
    }

    // Elements explicit/confidential value openings and the settlement action
    // encode one output amount as u64. A larger u128 reserve must therefore
    // make deterministic partial progress, never plan an unrepresentable
    // payment that later settlement code can only reject or truncate.
    let payment_capacity =
        (state.insurance_reserve - state.target_reserve).min(u128::from(u64::MAX));
    let safe_shares = maximum_redeemable_share_atoms(
        payment_capacity,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    let redeemed = entry.remaining_share_atoms.min(safe_shares);
    if redeemed == 0 {
        return Ok(None);
    }
    let paid = redemption_usdd_atoms(
        redeemed,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    // Do not destroy a claimant's shares in exchange for a zero-value output.
    if paid == 0 {
        return Ok(None);
    }

    let reserve_after = state.insurance_reserve - paid;
    if reserve_after < state.target_reserve {
        return Err(ProtocolError::InsufficientCollateral);
    }
    let remaining = entry.remaining_share_atoms - redeemed;
    let head_after = if remaining == 0 {
        state
            .redemption_head
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?
    } else {
        state.redemption_head
    };
    Ok(Some(RedemptionOutcomeV2 {
        sequence: entry.sequence,
        redeemed_share_atoms: redeemed,
        paid_usdd_atoms: paid,
        remaining_entry_share_atoms: remaining,
        insurance_reserve_after: reserve_after,
        outstanding_share_atoms_after: state.outstanding_share_atoms - redeemed,
        inventory_share_atoms_after: state
            .inventory_share_atoms
            .checked_add(redeemed)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        queued_redemption_share_atoms_after: state.queued_redemption_share_atoms - redeemed,
        redemption_head_after: head_after,
    }))
}

/// Arithmetic for a valid signed cancellation of the unexecuted remainder.
/// Signature and queue-membership verification belong to the v2 transition.
pub fn plan_redemption_cancellation(
    state: BondPublicStateV2,
    entry: RedemptionQueueEntryV2,
) -> Result<RedemptionCancellationV2, ProtocolError> {
    state.validate()?;
    entry.validate()?;
    if entry.sequence < state.redemption_head
        || entry.sequence >= state.redemption_tail
        || entry.remaining_share_atoms > state.queued_redemption_share_atoms
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    let head_after = if entry.sequence == state.redemption_head {
        state
            .redemption_head
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?
    } else {
        state.redemption_head
    };
    Ok(RedemptionCancellationV2 {
        sequence: entry.sequence,
        released_share_atoms: entry.remaining_share_atoms,
        queued_redemption_share_atoms_after: state.queued_redemption_share_atoms
            - entry.remaining_share_atoms,
        redemption_head_after: head_after,
    })
}

/// All protocol revenue is credited directly to insurance; there is no
/// treasury or operations split in v2.
pub fn credit_insurance_revenue(
    insurance_reserve: u128,
    trading_fees: u128,
    liquidation_penalties: u128,
) -> Result<u128, ProtocolError> {
    insurance_reserve
        .checked_add(trading_fees)
        .and_then(|value| value.checked_add(liquidation_penalties))
        .ok_or(ProtocolError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(reserve: u128, outstanding: u64, deficit: u128, queued: u64) -> BondPublicStateV2 {
        let queue_nonempty = queued != 0;
        BondPublicStateV2 {
            version: BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: [1; 32],
            deployment_commitment: [2; 32],
            inventory_covenant_hash: [3; 32],
            insurance_reserve: reserve,
            issued_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            outstanding_share_atoms: outstanding,
            inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS - outstanding,
            full_bound_deficit: deficit,
            target_reserve: target_reserve_125(deficit).unwrap(),
            legacy_fee_pool: 0,
            redemption_queue_root: [4; 32],
            redemption_head: 7,
            redemption_tail: if queue_nonempty { 8 } else { 7 },
            queued_redemption_share_atoms: queued,
            capital_mode: capital_mode_for(reserve, deficit).unwrap(),
        }
    }

    fn entry(shares: u64) -> RedemptionQueueEntryV2 {
        RedemptionQueueEntryV2::new(7, [5; 32], [6; 32], [7; 32], shares, 100).unwrap()
    }

    #[test]
    fn supply_constants_are_exact() {
        assert_eq!(BOND_SHARE_SCALE, 100_000_000);
        assert_eq!(BOND_FIXED_SUPPLY_ATOMS, 2_100_000_000_000_000);
        assert_eq!(BOND_REDEMPTION_DELAY_PARENT_BLOCKS, 1_008);
    }

    #[test]
    fn checked_mul_div_matches_direct_arithmetic_for_small_values() {
        for value in 0u128..50 {
            for multiplier in 0u64..50 {
                for divisor in 1u128..50 {
                    let product = value * u128::from(multiplier);
                    assert_eq!(
                        mul_u128_u64_div_rem(value, multiplier, divisor).unwrap(),
                        (product / divisor, product % divisor)
                    );
                }
            }
        }
    }

    #[test]
    fn public_state_round_trips_canonical_encoding() {
        let original = state(1_250, 100, 800, 25).validate().unwrap();
        let bytes = original.canonical_bytes();
        assert_eq!(bytes.len(), BondPublicStateV2::ENCODED_LEN);
        assert_eq!(BondPublicStateV2::decode(&bytes).unwrap(), original);
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            BondPublicStateV2::decode(&trailing),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn public_state_rejects_supply_creation_and_fee_pool() {
        let mut invalid_supply = state(1_250, 100, 800, 0);
        invalid_supply.inventory_share_atoms += 1;
        assert_eq!(
            invalid_supply.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );

        let mut fee_diversion = state(1_250, 100, 800, 0);
        fee_diversion.legacy_fee_pool = 1;
        assert_eq!(
            fee_diversion.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn public_state_rejects_false_capital_mode_and_queue_aggregate() {
        let mut false_mode = state(999, 100, 800, 0);
        assert_eq!(false_mode.capital_mode, CapitalModeV2::ReduceOnly);
        false_mode.capital_mode = CapitalModeV2::Normal;
        assert_eq!(
            false_mode.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );

        let mut empty_with_shares = state(1_250, 100, 800, 1);
        empty_with_shares.redemption_tail = empty_with_shares.redemption_head;
        assert_eq!(
            empty_with_shares.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn queue_entry_round_trips_and_enforces_exact_delay() {
        let original = entry(25);
        let bytes = original.canonical_bytes();
        assert_eq!(bytes.len(), RedemptionQueueEntryV2::ENCODED_LEN);
        assert_eq!(RedemptionQueueEntryV2::decode(&bytes).unwrap(), original);
        assert!(!original.is_unlocked(1_107));
        assert!(original.is_unlocked(1_108));

        let mut early = original;
        early.unlock_parent_height -= 1;
        assert_eq!(early.validate(), Err(ProtocolError::NonCanonicalEncoding));
    }

    #[test]
    fn deficit_is_totaled_per_endpoint_before_taking_maximum() {
        let minimum = [-100, 40, -20];
        let maximum = [10, -90, -5];
        assert_eq!(negative_equity_deficit(&minimum).unwrap(), 120);
        assert_eq!(negative_equity_deficit(&maximum).unwrap(), 95);
        assert_eq!(full_range_deficit(&minimum, &maximum).unwrap(), 120);
        assert_eq!(negative_equity_deficit(&[i128::MIN]).unwrap(), 1u128 << 127);
        assert_eq!(
            full_range_deficit(&minimum, &maximum[..2]),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn target_rounds_up_and_modes_follow_coverage_boundaries() {
        assert_eq!(target_reserve_125(0).unwrap(), 0);
        assert_eq!(target_reserve_125(1).unwrap(), 2);
        assert_eq!(target_reserve_125(800).unwrap(), 1_000);
        assert_eq!(capital_mode_for(1_000, 800).unwrap(), CapitalModeV2::Normal);
        assert_eq!(
            capital_mode_for(999, 800).unwrap(),
            CapitalModeV2::ReduceOnly
        );
        assert_eq!(
            capital_mode_for(799, 800).unwrap(),
            CapitalModeV2::RecapitalizationOnly
        );
        let maximum_deficit = i128::MAX as u128;
        let expected = (maximum_deficit / 4) * 5 + 4;
        assert_eq!(target_reserve_125(maximum_deficit).unwrap(), expected);
        assert_eq!(coverage_bps(1_000, 800).unwrap(), 12_500);
        assert_eq!(coverage_bps(999, 800).unwrap(), 12_487);
        assert_eq!(coverage_bps(1, 0).unwrap(), 12_500);
    }

    #[test]
    fn first_and_later_subscriptions_use_floor_nav_math() {
        assert_eq!(subscription_share_atoms(25, 0, 0).unwrap(), 25);
        // Fee and liquidation revenue belongs to the bond even when it arrives
        // before the first subscriber. The frozen first-subscription price is
        // still one share atom per contributed USDD atom.
        assert_eq!(subscription_share_atoms(25, 400, 0).unwrap(), 25);
        assert_eq!(subscription_share_atoms(10, 30, 100).unwrap(), 33);
        assert_eq!(nav_per_whole_share_usdd_atoms(30, 100).unwrap(), 30_000_000);
        assert_eq!(
            subscription_share_atoms(1, 1_000, 1),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            subscription_share_atoms(10, 0, 100),
            Err(ProtocolError::DivisionByZero)
        );
        assert_eq!(
            subscription_share_atoms(
                i128::MAX as u128,
                i128::MAX as u128,
                BOND_FIXED_SUPPLY_ATOMS,
            )
            .unwrap(),
            BOND_FIXED_SUPPLY_ATOMS
        );
    }

    #[test]
    fn applying_subscription_conserves_fixed_supply() {
        let outcome = apply_subscription(state(0, 0, 1_000, 0), 500).unwrap();
        assert_eq!(outcome.issued_share_atoms, 500);
        assert_eq!(outcome.insurance_reserve_after, 500);
        assert_eq!(outcome.outstanding_share_atoms_after, 500);
        assert_eq!(
            outcome.outstanding_share_atoms_after + outcome.inventory_share_atoms_after,
            BOND_FIXED_SUPPLY_ATOMS
        );

        let after_pre_subscription_revenue = apply_subscription(state(400, 0, 0, 0), 25).unwrap();
        assert_eq!(after_pre_subscription_revenue.issued_share_atoms, 25);
        assert_eq!(after_pre_subscription_revenue.insurance_reserve_after, 425);
    }

    #[test]
    fn redemptions_round_down_and_inverse_bound_is_exact() {
        assert_eq!(redemption_usdd_atoms(1, 10, 6).unwrap(), 1);
        assert_eq!(redemption_usdd_atoms(3, 10, 6).unwrap(), 5);
        for payment_limit in 0..10 {
            let shares = maximum_redeemable_share_atoms(payment_limit, 10, 6).unwrap();
            let paid = if shares == 0 {
                0
            } else {
                redemption_usdd_atoms(shares, 10, 6).unwrap()
            };
            assert!(paid <= payment_limit);
            if shares < 6 {
                assert!(redemption_usdd_atoms(shares + 1, 10, 6).unwrap() > payment_limit);
            }
        }
        assert_eq!(
            redemption_usdd_atoms(
                BOND_FIXED_SUPPLY_ATOMS,
                i128::MAX as u128,
                BOND_FIXED_SUPPLY_ATOMS,
            )
            .unwrap(),
            i128::MAX as u128
        );
    }

    #[test]
    fn fifo_redemption_partially_executes_to_exact_target() {
        let outcome = plan_fifo_redemption(state(1_000, 100, 720, 50), entry(50), 1_108)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.redeemed_share_atoms, 10);
        assert_eq!(outcome.paid_usdd_atoms, 100);
        assert_eq!(outcome.remaining_entry_share_atoms, 40);
        assert_eq!(outcome.insurance_reserve_after, 900);
        assert_eq!(outcome.outstanding_share_atoms_after, 90);
        assert_eq!(outcome.queued_redemption_share_atoms_after, 40);
        assert_eq!(outcome.redemption_head_after, 7);
        assert_eq!(
            outcome.outstanding_share_atoms_after + outcome.inventory_share_atoms_after,
            BOND_FIXED_SUPPLY_ATOMS
        );
    }

    #[test]
    fn fifo_redemption_can_fully_remove_the_head() {
        let outcome = plan_fifo_redemption(state(1_250, 100, 0, 100), entry(100), 1_108)
            .unwrap()
            .unwrap();
        assert_eq!(outcome.redeemed_share_atoms, 100);
        assert_eq!(outcome.paid_usdd_atoms, 1_250);
        assert_eq!(outcome.remaining_entry_share_atoms, 0);
        assert_eq!(outcome.insurance_reserve_after, 0);
        assert_eq!(outcome.outstanding_share_atoms_after, 0);
        assert_eq!(outcome.redemption_head_after, 8);
    }

    #[test]
    fn fifo_large_reserve_makes_u64_representable_partial_progress() {
        let reserve = u128::from(u64::MAX) + 1_000;
        let outcome = plan_fifo_redemption(state(reserve, 100, 0, 100), entry(100), 1_108)
            .unwrap()
            .unwrap();
        assert!(outcome.redeemed_share_atoms > 0);
        assert!(outcome.redeemed_share_atoms < 100);
        assert!(outcome.paid_usdd_atoms <= u128::from(u64::MAX));
        assert_eq!(
            outcome.remaining_entry_share_atoms,
            100 - outcome.redeemed_share_atoms
        );
        assert_eq!(
            outcome.insurance_reserve_after,
            reserve - outcome.paid_usdd_atoms
        );
    }

    #[test]
    fn fifo_is_mature_head_only_and_fails_closed_at_target() {
        assert_eq!(
            plan_fifo_redemption(state(1_000, 100, 800, 10), entry(10), 1_107),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        let mut non_head = entry(10);
        non_head.sequence = 8;
        assert_eq!(
            plan_fifo_redemption(state(1_000, 100, 800, 10), non_head, 1_108),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        assert_eq!(
            plan_fifo_redemption(state(1_000, 100, 800, 10), entry(10), 1_108).unwrap(),
            None
        );
    }

    #[test]
    fn signed_cancellation_releases_only_unexecuted_remainder() {
        let mut partially_filled = entry(50);
        partially_filled.remaining_share_atoms = 40;
        let cancellation =
            plan_redemption_cancellation(state(1_000, 100, 720, 40), partially_filled).unwrap();
        assert_eq!(cancellation.released_share_atoms, 40);
        assert_eq!(cancellation.queued_redemption_share_atoms_after, 0);
        assert_eq!(cancellation.redemption_head_after, 8);
    }

    #[test]
    fn all_revenue_accrues_to_insurance() {
        assert_eq!(credit_insurance_revenue(1_000, 5, 25).unwrap(), 1_030);
        assert_eq!(
            credit_insurance_revenue(u128::MAX, 1, 0),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }
}
