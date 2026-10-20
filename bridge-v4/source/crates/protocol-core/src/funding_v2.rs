//! Deterministic eight-hour funding accumulator for the V2 transition.
//!
//! Every observation is derived inside the transition proof from authenticated
//! oracle marks and verified fills. There is no host-selected rate. Funding is
//! settled at most once for each completed parent-MTP epoch.

use crate::codec::{put_i32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::types::{Price, Quantity, PRICE_SCALE};
use crate::ProtocolError;

pub const FUNDING_EPOCH_SECONDS: u64 = 8 * 60 * 60;
pub const FUNDING_BUCKET_SECONDS: u64 = 60 * 60;
pub const FUNDING_BUCKET_COUNT: usize = 8;
pub const FUNDING_RATE_DENOMINATOR_PPM: i128 = 1_000_000;
pub const FUNDING_RATE_CAP_PPM: i32 = 10_000;
/// One whole USDD expressed in the protocol's eight-decimal quote atoms.
pub const MINIMUM_FUNDING_VOLUME_QUOTE_UNITS: u128 = PRICE_SCALE as u128;

/// Minimal observation accepted by the deterministic funding accumulator.
///
/// Callers construct these only from executions already verified by the
/// transition rules. Keeping order ids, counterparties, fees, and synthetic
/// sequence numbers out of this type makes it explicit that funding depends
/// solely on executed price and quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FundingObservationV2 {
    pub price: Price,
    pub quantity: Quantity,
}

impl FundingObservationV2 {
    pub fn new(price: Price, quantity: Quantity) -> Result<Self, ProtocolError> {
        Price::new(price.get())?;
        Quantity::new(quantity.get())?;
        Ok(Self { price, quantity })
    }
}

/// An execution whose funding bucket is fixed by proof-verified consensus time.
///
/// This accumulator accepts an explicit parent MTP, but the V2 transition
/// relation sets it to the current authenticated prior-parent MTP for every
/// ordinary and permissionless fill. A matcher-signed receipt authenticates
/// the exact match; its claimed execution context never selects the economic
/// timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimestampedFundingObservationV2 {
    pub price: Price,
    pub quantity: Quantity,
    pub execution_parent_mtp: u64,
}

impl TimestampedFundingObservationV2 {
    pub fn new(
        price: Price,
        quantity: Quantity,
        execution_parent_mtp: u64,
    ) -> Result<Self, ProtocolError> {
        FundingObservationV2::new(price, quantity)?;
        if execution_parent_mtp == 0 {
            return Err(ProtocolError::InvalidFundingState);
        }
        Ok(Self {
            price,
            quantity,
            execution_parent_mtp,
        })
    }
}

impl CanonicalEncode for TimestampedFundingObservationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.price.encode_to(out);
        self.quantity.encode_to(out);
        put_u64(out, self.execution_parent_mtp);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FundingBucketV2 {
    pub epoch: u64,
    pub index: u8,
    /// Quote notional is used only for the frozen minimum-volume threshold.
    pub trade_quote_volume: u128,
    /// Executed base quantity is the denominator of conventional VWAP.
    pub trade_base_quantity: u128,
    /// Sum of executed price atoms multiplied by base quantity.
    pub trade_price_volume: u128,
    pub oracle_price_seconds: u128,
    pub oracle_seconds: u64,
    /// A proof-consumed execution belonged to this hour but its causally prior
    /// authenticated band was unavailable or expired. The trade still settles,
    /// but this flag makes the complete epoch's funding rate zero.
    pub sampling_invalid: bool,
}

impl FundingBucketV2 {
    pub const EMPTY_EPOCH: u64 = u64::MAX;

    pub const fn empty(index: u8) -> Self {
        Self {
            epoch: Self::EMPTY_EPOCH,
            index,
            trade_quote_volume: 0,
            trade_base_quantity: 0,
            trade_price_volume: 0,
            oracle_price_seconds: 0,
            oracle_seconds: 0,
            sampling_invalid: false,
        }
    }

    fn reset(&mut self, epoch: u64, index: u8) {
        *self = Self {
            epoch,
            index,
            ..Self::empty(index)
        };
    }
}

impl CanonicalEncode for FundingBucketV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.epoch);
        put_u8(out, self.index);
        out.extend_from_slice(&self.trade_quote_volume.to_be_bytes());
        out.extend_from_slice(&self.trade_base_quantity.to_be_bytes());
        out.extend_from_slice(&self.trade_price_volume.to_be_bytes());
        out.extend_from_slice(&self.oracle_price_seconds.to_be_bytes());
        put_u64(out, self.oracle_seconds);
        put_u8(out, u8::from(self.sampling_invalid));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FundingStateV2 {
    pub version: u8,
    pub last_parent_mtp: u64,
    /// Last authenticated oracle mark. It prices only the interval following
    /// its observation, preventing a newly supplied mark from rewriting the
    /// preceding hourly TWAP.
    pub last_oracle_mark: Price,
    /// Causally prior authenticated clamp for executions until the next state
    /// transition. A later quote never retroactively reprices that interval.
    pub last_oracle_low: Price,
    pub last_oracle_high: Price,
    /// Last parent MTP through which the carried quote is sampling-eligible.
    /// An endpoint at or below `last_parent_mtp` safely provides no forward
    /// oracle coverage.
    pub last_oracle_valid_through_mtp: u64,
    /// `u64::MAX` means no epoch has settled yet.
    pub last_settled_epoch: u64,
    pub last_rate_ppm: i32,
    pub epoch_start_open_interest_notional: u128,
    pub buckets: [FundingBucketV2; FUNDING_BUCKET_COUNT],
}

impl FundingStateV2 {
    pub const VERSION: u8 = 2;

    pub fn genesis(
        parent_mtp: u64,
        oracle_mark: Price,
        open_interest_notional: u128,
    ) -> Result<Self, ProtocolError> {
        // Compatibility constructor is deliberately fail-closed: without an
        // authenticated band/freshness endpoint it grants no forward sampling
        // coverage. Production genesis must call `genesis_with_band`.
        Self::genesis_with_band(
            parent_mtp,
            oracle_mark,
            oracle_mark,
            oracle_mark,
            parent_mtp,
            open_interest_notional,
        )
    }

    pub fn genesis_with_band(
        parent_mtp: u64,
        oracle_mark: Price,
        oracle_low: Price,
        oracle_high: Price,
        oracle_valid_through_mtp: u64,
        open_interest_notional: u128,
    ) -> Result<Self, ProtocolError> {
        if parent_mtp == 0 {
            return Err(ProtocolError::InvalidFundingState);
        }
        let state = Self {
            version: Self::VERSION,
            last_parent_mtp: parent_mtp,
            last_oracle_mark: oracle_mark,
            last_oracle_low: oracle_low,
            last_oracle_high: oracle_high,
            last_oracle_valid_through_mtp: oracle_valid_through_mtp,
            last_settled_epoch: u64::MAX,
            last_rate_ppm: 0,
            epoch_start_open_interest_notional: open_interest_notional,
            buckets: core::array::from_fn(|index| FundingBucketV2::empty(index as u8)),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let active_epoch = self.last_parent_mtp / FUNDING_EPOCH_SECONDS;
        if self.version != Self::VERSION
            || self.last_parent_mtp == 0
            || self.last_oracle_valid_through_mtp == 0
            || self.last_oracle_low > self.last_oracle_mark
            || self.last_oracle_mark > self.last_oracle_high
            || (self.last_settled_epoch != u64::MAX && self.last_settled_epoch >= active_epoch)
        {
            return Err(ProtocolError::InvalidFundingState);
        }
        for (index, bucket) in self.buckets.iter().enumerate() {
            let has_data = bucket.trade_quote_volume != 0
                || bucket.trade_base_quantity != 0
                || bucket.trade_price_volume != 0
                || bucket.oracle_price_seconds != 0
                || bucket.oracle_seconds != 0
                || bucket.sampling_invalid;
            let expected_quote_volume = if bucket.trade_price_volume == 0 {
                0
            } else {
                ceil_div(bucket.trade_price_volume, u128::from(PRICE_SCALE))?
            };
            if usize::from(bucket.index) != index
                || bucket.index as usize >= FUNDING_BUCKET_COUNT
                || (bucket.epoch == FundingBucketV2::EMPTY_EPOCH && has_data)
                || (bucket.epoch != FundingBucketV2::EMPTY_EPOCH && bucket.epoch != active_epoch)
                || bucket.trade_quote_volume != expected_quote_volume
                || (bucket.trade_base_quantity == 0) != (bucket.trade_price_volume == 0)
                || (bucket.oracle_seconds == 0 && bucket.oracle_price_seconds != 0)
                || bucket.oracle_seconds > FUNDING_BUCKET_SECONDS
            {
                return Err(ProtocolError::InvalidFundingState);
            }
        }
        if self.last_rate_ppm.unsigned_abs() > FUNDING_RATE_CAP_PPM as u32 {
            return Err(ProtocolError::InvalidFundingState);
        }
        Ok(())
    }

    pub fn root(&self) -> Hash32 {
        canonical_hash("ECX/funding-state/v2", self)
    }
}

impl CanonicalEncode for FundingStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.last_parent_mtp);
        self.last_oracle_mark.encode_to(out);
        self.last_oracle_low.encode_to(out);
        self.last_oracle_high.encode_to(out);
        put_u64(out, self.last_oracle_valid_through_mtp);
        put_u64(out, self.last_settled_epoch);
        put_i32(out, self.last_rate_ppm);
        out.extend_from_slice(&self.epoch_start_open_interest_notional.to_be_bytes());
        for bucket in &self.buckets {
            bucket.encode_to(out);
        }
    }
}

/// Advances the authenticated accumulator and returns the one funding rate
/// settled by this transition, or zero when no epoch completed or the frozen
/// sample/volume requirements were not met.
pub fn advance_funding_v2(
    previous: &FundingStateV2,
    parent_mtp: u64,
    mark: Price,
    low: Price,
    high: Price,
    observations: &[FundingObservationV2],
    open_interest_notional_before_fills: u128,
) -> Result<(FundingStateV2, i32), ProtocolError> {
    let timestamped = observations
        .iter()
        .map(|observation| TimestampedFundingObservationV2 {
            price: observation.price,
            quantity: observation.quantity,
            execution_parent_mtp: parent_mtp,
        })
        .collect::<Vec<_>>();
    advance_funding_timestamped_v2(
        previous,
        parent_mtp,
        mark,
        low,
        high,
        // The compatibility path cannot prove a forward freshness endpoint.
        // It therefore carries the quote with zero forward sampling coverage.
        parent_mtp,
        &timestamped,
        open_interest_notional_before_fills,
    )
}

/// Advance funding while assigning each execution to its authenticated hour.
///
/// The state retains all eight buckets for the active epoch, so an execution
/// may arrive after its hour only while the transition remains in that same
/// epoch. A transition that crosses an epoch boundary accepts observations only
/// in the new active epoch: funding is applied to all prior positions before
/// every current fill, so admitting an old-epoch fill during that transition
/// would settle the wrong position inventory. Such a matcher execution must be
/// finalized by a pre-boundary transition or it is never chain-final.
#[allow(clippy::too_many_arguments)]
pub fn advance_funding_timestamped_v2(
    previous: &FundingStateV2,
    parent_mtp: u64,
    mark: Price,
    low: Price,
    high: Price,
    oracle_valid_through_mtp: u64,
    observations: &[TimestampedFundingObservationV2],
    open_interest_notional_before_fills: u128,
) -> Result<(FundingStateV2, i32), ProtocolError> {
    previous.validate()?;
    if parent_mtp < previous.last_parent_mtp
        || low > mark
        || mark > high
        || oracle_valid_through_mtp < parent_mtp
    {
        return Err(ProtocolError::InvalidFundingState);
    }

    let previous_epoch = previous.last_parent_mtp / FUNDING_EPOCH_SECONDS;
    let next_epoch = parent_mtp / FUNDING_EPOCH_SECONDS;
    let mut next = previous.clone();
    let mut settled_rate = 0;

    for observation in observations {
        TimestampedFundingObservationV2::new(
            observation.price,
            observation.quantity,
            observation.execution_parent_mtp,
        )?;
        let observation_epoch = observation.execution_parent_mtp / FUNDING_EPOCH_SECONDS;
        let allowed_epoch = if next_epoch == previous_epoch {
            observation_epoch == previous_epoch
        } else {
            observation_epoch == next_epoch
        };
        if observation.execution_parent_mtp < previous.last_parent_mtp
            || observation.execution_parent_mtp > parent_mtp
            || (previous.last_settled_epoch != u64::MAX
                && observation_epoch <= previous.last_settled_epoch)
            || !allowed_epoch
        {
            return Err(ProtocolError::InvalidFundingState);
        }
    }

    if next_epoch > previous_epoch {
        let first_boundary = previous_epoch
            .checked_add(1)
            .and_then(|epoch| epoch.checked_mul(FUNDING_EPOCH_SECONDS))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        // Complete the old epoch solely from committed buckets before deriving
        // its rate. All current observations are in the new active epoch.
        accumulate_oracle_time(
            &mut next,
            previous.last_parent_mtp,
            first_boundary,
            previous.last_oracle_mark,
            previous.last_oracle_valid_through_mtp,
        )?;
        if previous.last_settled_epoch == u64::MAX || previous_epoch > previous.last_settled_epoch {
            // Always settle the immediately preceding active epoch exactly
            // once. A later transition gap makes every intervening epoch zero,
            // but cannot erase an already complete sample from this epoch.
            settled_rate = derive_epoch_rate(&next, previous_epoch)?;
            next.last_settled_epoch = next_epoch - 1;
            next.last_rate_ppm = settled_rate;
        }
        // The completed epoch has been deterministically derived. It must not
        // remain encoded alongside the new active epoch: reset all ring slots
        // before accumulating new-epoch oracle time and executions.
        next.buckets = core::array::from_fn(|index| FundingBucketV2::empty(index as u8));
        next.epoch_start_open_interest_notional = open_interest_notional_before_fills;
        let active_epoch_start = next_epoch
            .checked_mul(FUNDING_EPOCH_SECONDS)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        accumulate_oracle_time(
            &mut next,
            active_epoch_start,
            parent_mtp,
            previous.last_oracle_mark,
            previous.last_oracle_valid_through_mtp,
        )?;
        for observation in observations.iter().filter(|observation| {
            observation.execution_parent_mtp / FUNDING_EPOCH_SECONDS == next_epoch
        }) {
            accumulate_trade_observation(&mut next, previous, *observation)?;
        }
    } else {
        accumulate_oracle_time(
            &mut next,
            previous.last_parent_mtp,
            parent_mtp,
            previous.last_oracle_mark,
            previous.last_oracle_valid_through_mtp,
        )?;
        for observation in observations {
            accumulate_trade_observation(&mut next, previous, *observation)?;
        }
    }

    next.last_parent_mtp = parent_mtp;
    next.last_oracle_mark = mark;
    next.last_oracle_low = low;
    next.last_oracle_high = high;
    next.last_oracle_valid_through_mtp = oracle_valid_through_mtp;
    next.validate()?;
    Ok((next, settled_rate))
}

fn accumulate_trade_observation(
    state: &mut FundingStateV2,
    previous: &FundingStateV2,
    observation: TimestampedFundingObservationV2,
) -> Result<(), ProtocolError> {
    let epoch = observation.execution_parent_mtp / FUNDING_EPOCH_SECONDS;
    let bucket_index =
        ((observation.execution_parent_mtp % FUNDING_EPOCH_SECONDS) / FUNDING_BUCKET_SECONDS) as u8;
    let bucket = bucket_for(state, epoch, bucket_index);
    if observation.execution_parent_mtp > previous.last_oracle_valid_through_mtp {
        bucket.sampling_invalid = true;
        return Ok(());
    }
    let clamped = observation.price.get().clamp(
        previous.last_oracle_low.get(),
        previous.last_oracle_high.get(),
    );
    let price_volume = u128::from(clamped)
        .checked_mul(u128::from(observation.quantity.get()))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    bucket.trade_base_quantity = bucket
        .trade_base_quantity
        .checked_add(u128::from(observation.quantity.get()))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    bucket.trade_price_volume = bucket
        .trade_price_volume
        .checked_add(price_volume)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    // This public-state diagnostic is rounded only after bucket aggregation.
    // The consensus minimum-volume gate below compares the exact epoch-wide
    // price-volume numerator and is therefore invariant under fill splitting.
    bucket.trade_quote_volume = ceil_div(bucket.trade_price_volume, u128::from(PRICE_SCALE))?;
    Ok(())
}

fn accumulate_oracle_time(
    state: &mut FundingStateV2,
    mut cursor: u64,
    end: u64,
    mark: Price,
    valid_through_mtp: u64,
) -> Result<(), ProtocolError> {
    let end = end.min(valid_through_mtp);
    while cursor < end {
        let epoch = cursor / FUNDING_EPOCH_SECONDS;
        let within_epoch = cursor % FUNDING_EPOCH_SECONDS;
        let index = (within_epoch / FUNDING_BUCKET_SECONDS) as u8;
        let next_boundary = cursor
            .checked_add(FUNDING_BUCKET_SECONDS - (within_epoch % FUNDING_BUCKET_SECONDS))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let segment_end = end.min(next_boundary);
        let seconds = segment_end - cursor;
        let bucket = bucket_for(state, epoch, index);
        bucket.oracle_seconds = bucket
            .oracle_seconds
            .checked_add(seconds)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        bucket.oracle_price_seconds = bucket
            .oracle_price_seconds
            .checked_add(
                u128::from(mark.get())
                    .checked_mul(u128::from(seconds))
                    .ok_or(ProtocolError::ArithmeticOverflow)?,
            )
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        cursor = segment_end;
    }
    Ok(())
}

fn bucket_for(state: &mut FundingStateV2, epoch: u64, index: u8) -> &mut FundingBucketV2 {
    let bucket = &mut state.buckets[usize::from(index)];
    if bucket.epoch != epoch {
        bucket.reset(epoch, index);
    }
    bucket
}

fn derive_epoch_rate(state: &FundingStateV2, epoch: u64) -> Result<i32, ProtocolError> {
    let mut trade_base_quantity = 0u128;
    let mut trade_price_volume = 0u128;
    let mut oracle_seconds = 0u128;
    let mut oracle_price_seconds = 0u128;
    for (index, bucket) in state.buckets.iter().enumerate() {
        if bucket.epoch != epoch
            || usize::from(bucket.index) != index
            || bucket.sampling_invalid
            || bucket.trade_quote_volume == 0
            || bucket.trade_base_quantity == 0
            || bucket.oracle_seconds != FUNDING_BUCKET_SECONDS
        {
            return Ok(0);
        }
        trade_price_volume = trade_price_volume
            .checked_add(bucket.trade_price_volume)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        trade_base_quantity = trade_base_quantity
            .checked_add(bucket.trade_base_quantity)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        oracle_seconds = oracle_seconds
            .checked_add(u128::from(bucket.oracle_seconds))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        oracle_price_seconds = oracle_price_seconds
            .checked_add(bucket.oracle_price_seconds)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    let minimum_volume = MINIMUM_FUNDING_VOLUME_QUOTE_UNITS
        .max(ceil_div(state.epoch_start_open_interest_notional, 100)?);
    let minimum_price_volume = minimum_volume
        .checked_mul(u128::from(PRICE_SCALE))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if trade_price_volume < minimum_price_volume || oracle_seconds == 0 {
        return Ok(0);
    }
    let trade_vwap = trade_price_volume / trade_base_quantity;
    let oracle_twap = oracle_price_seconds / oracle_seconds;
    if oracle_twap == 0 {
        return Err(ProtocolError::InvalidFundingState);
    }
    let signed_delta = i128::try_from(trade_vwap)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?
        .checked_sub(i128::try_from(oracle_twap).map_err(|_| ProtocolError::ArithmeticOverflow)?)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let rate = signed_delta
        .checked_mul(FUNDING_RATE_DENOMINATOR_PPM)
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / i128::try_from(oracle_twap).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let capped = rate.clamp(
        -i128::from(FUNDING_RATE_CAP_PPM),
        i128::from(FUNDING_RATE_CAP_PPM),
    );
    i32::try_from(capped).map_err(|_| ProtocolError::ArithmeticOverflow)
}

fn ceil_div(value: u128, divisor: u128) -> Result<u128, ProtocolError> {
    if divisor == 0 {
        return Err(ProtocolError::DivisionByZero);
    }
    let quotient = value / divisor;
    quotient
        .checked_add(u128::from(value % divisor != 0))
        .ok_or(ProtocolError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(value: u64) -> Price {
        Price::new(value * PRICE_SCALE).unwrap()
    }

    fn fill(_sequence: u64, value: u64) -> FundingObservationV2 {
        FundingObservationV2 {
            price: price(value),
            quantity: Quantity::new(PRICE_SCALE).unwrap(),
        }
    }

    fn timestamped_fill(mtp: u64, value: u64) -> TimestampedFundingObservationV2 {
        TimestampedFundingObservationV2::new(price(value), Quantity::new(PRICE_SCALE).unwrap(), mtp)
            .unwrap()
    }

    fn funding_genesis(
        parent_mtp: u64,
        mark: Price,
        open_interest_notional: u128,
    ) -> Result<FundingStateV2, ProtocolError> {
        FundingStateV2::genesis_with_band(
            parent_mtp,
            mark,
            price(90),
            price(110),
            parent_mtp + 5 * FUNDING_EPOCH_SECONDS,
            open_interest_notional,
        )
    }

    fn advance_authenticated_test(
        previous: &FundingStateV2,
        parent_mtp: u64,
        mark: Price,
        low: Price,
        high: Price,
        observations: &[FundingObservationV2],
        open_interest_notional_before_fills: u128,
    ) -> Result<(FundingStateV2, i32), ProtocolError> {
        let timestamped = observations
            .iter()
            .map(|observation| TimestampedFundingObservationV2 {
                price: observation.price,
                quantity: observation.quantity,
                execution_parent_mtp: parent_mtp,
            })
            .collect::<Vec<_>>();
        advance_funding_timestamped_v2(
            previous,
            parent_mtp,
            mark,
            low,
            high,
            parent_mtp + 5 * FUNDING_EPOCH_SECONDS,
            &timestamped,
            open_interest_notional_before_fills,
        )
    }

    #[test]
    fn eight_hour_premium_is_deterministic_and_capped() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut state = funding_genesis(start, price(100), 100).unwrap();
        for hour in 1..=8 {
            let end = start + hour * FUNDING_BUCKET_SECONDS - 1;
            let (advanced, rate) = advance_authenticated_test(
                &state,
                end,
                price(100),
                price(90),
                price(110),
                &[fill(hour, 101)],
                100,
            )
            .unwrap();
            assert_eq!(rate, 0);
            state = advanced;
        }
        let (settled, rate) = advance_authenticated_test(
            &state,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            100,
        )
        .unwrap();
        assert_eq!(rate, FUNDING_RATE_CAP_PPM);
        assert_eq!(settled.last_settled_epoch, 1);
    }

    #[test]
    fn current_fills_cannot_change_the_funding_index_used_to_execute_them() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut previous = funding_genesis(start, price(100), 100).unwrap();
        for hour in 1..=8 {
            (previous, _) = advance_authenticated_test(
                &previous, start + hour * FUNDING_BUCKET_SECONDS - 1,
                price(100), price(90), price(110), &[fill(hour, 101)], 100,
            ).unwrap();
        }
        // Includes same-epoch, exact rollover, later-in-epoch and skipped-epoch
        // contexts. Current executions must affect buckets, never their rate.
        for mtp in [previous.last_parent_mtp, 2 * start, 2 * start + 60, 4 * start] {
            let (without, rate) = advance_authenticated_test(
                &previous, mtp, price(100), price(90), price(110), &[], 100,
            ).unwrap();
            for execution_price in [90, 100, 110] {
                let (with, observed_rate) = advance_authenticated_test(
                    &previous, mtp, price(100), price(90), price(110),
                    &[fill(1, execution_price)], 100,
                ).unwrap();
                assert_eq!(observed_rate, rate);
                assert_eq!(with.last_settled_epoch, without.last_settled_epoch);
                assert_ne!(with.root(), without.root());
                assert_eq!(
                    crate::advance_exact_funding_index_v2(123, price(100).get(), observed_rate).unwrap(),
                    crate::advance_exact_funding_index_v2(123, price(100).get(), rate).unwrap(),
                );
            }
            assert_eq!(rate, if mtp < 2 * start { 0 } else { FUNDING_RATE_CAP_PPM });
        }
    }

    #[test]
    fn missing_hour_or_volume_settles_zero() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut state = funding_genesis(start, price(100), 1_000_000).unwrap();
        let (advanced, _) = advance_authenticated_test(
            &state,
            start + FUNDING_BUCKET_SECONDS,
            price(100),
            price(90),
            price(110),
            &[fill(1, 101)],
            1_000_000,
        )
        .unwrap();
        state = advanced;
        let (_, rate) = advance_authenticated_test(
            &state,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            1_000_000,
        )
        .unwrap();
        assert_eq!(rate, 0);
    }

    #[test]
    fn partial_hourly_oracle_coverage_settles_zero() {
        let epoch_start = FUNDING_EPOCH_SECONDS;
        // Starting one second after the boundary leaves the first hourly TWAP
        // bucket incomplete. Eight trade buckets alone must not turn that
        // partial oracle history into a nonzero funding rate.
        let mut state = funding_genesis(epoch_start + 1, price(100), 0).unwrap();
        for hour in 1..=8 {
            (state, _) = advance_authenticated_test(
                &state,
                epoch_start + hour * FUNDING_BUCKET_SECONDS - 1,
                price(100),
                price(90),
                price(110),
                &[fill(hour, 101)],
                0,
            )
            .unwrap();
        }
        let (_, rate) = advance_authenticated_test(
            &state,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            0,
        )
        .unwrap();
        assert_eq!(rate, 0);
    }

    #[test]
    fn trade_price_is_clamped_to_authenticated_band() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = FundingStateV2::genesis_with_band(
            start,
            price(100),
            price(95),
            price(105),
            start + FUNDING_EPOCH_SECONDS,
            0,
        )
        .unwrap();
        let (next, _) = advance_authenticated_test(
            &state,
            start + 1,
            price(100),
            price(99),
            price(101),
            &[fill(1, 1_000)],
            0,
        )
        .unwrap();
        assert_eq!(
            next.buckets[0].trade_price_volume,
            u128::from(price(105).get()) * u128::from(PRICE_SCALE)
        );
    }

    #[test]
    fn execution_vwap_is_weighted_by_base_quantity_not_quote_notional() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut state = funding_genesis(start, price(100), 0).unwrap();
        let observations = [
            FundingObservationV2 {
                price: price(100),
                quantity: Quantity::new(9 * PRICE_SCALE).unwrap(),
            },
            FundingObservationV2 {
                price: price(101),
                quantity: Quantity::new(PRICE_SCALE).unwrap(),
            },
        ];
        for hour in 1..=8 {
            (state, _) = advance_authenticated_test(
                &state,
                start + hour * FUNDING_BUCKET_SECONDS - 1,
                price(100),
                price(90),
                price(110),
                &observations,
                0,
            )
            .unwrap();
        }
        let (_, rate) = advance_authenticated_test(
            &state,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            0,
        )
        .unwrap();
        // (9 * 100 + 1 * 101) / 10 = 100.1, hence 1,000 ppm.
        // Quote-notional weighting would incorrectly produce 1,009 ppm.
        assert_eq!(rate, 1_000);
    }

    #[test]
    fn duplicate_mtp_accumulates_without_settling_twice() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        let (next, rate) =
            advance_authenticated_test(&state, start, price(100), price(90), price(110), &[], 0)
                .unwrap();
        assert_eq!(rate, 0);
        assert_eq!(next.last_settled_epoch, u64::MAX);
    }

    #[test]
    fn canonical_state_rejects_settled_active_epoch_foreign_buckets_and_rounded_volume_mutation() {
        let start = FUNDING_EPOCH_SECONDS;
        let genesis = funding_genesis(start, price(100), 0).unwrap();
        genesis.validate().unwrap();

        let mut settled_active_epoch = genesis.clone();
        settled_active_epoch.last_settled_epoch = start / FUNDING_EPOCH_SECONDS;
        assert_eq!(
            settled_active_epoch.validate(),
            Err(ProtocolError::InvalidFundingState)
        );

        let (active, _) = advance_funding_timestamped_v2(
            &genesis,
            start + 1,
            price(100),
            price(90),
            price(110),
            start + FUNDING_EPOCH_SECONDS,
            &[timestamped_fill(start + 1, 101)],
            0,
        )
        .unwrap();
        active.validate().unwrap();

        let mut foreign_bucket = active.clone();
        foreign_bucket.buckets[0].epoch += 1;
        assert_eq!(
            foreign_bucket.validate(),
            Err(ProtocolError::InvalidFundingState)
        );

        let mut rounded_volume = active;
        rounded_volume.buckets[0].trade_quote_volume += 1;
        assert_eq!(
            rounded_volume.validate(),
            Err(ProtocolError::InvalidFundingState)
        );
    }

    #[test]
    fn new_mark_cannot_reprice_the_elapsed_oracle_interval() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        let (next, _) = advance_authenticated_test(
            &state,
            start + FUNDING_BUCKET_SECONDS,
            price(200),
            price(90),
            price(210),
            &[],
            0,
        )
        .unwrap();
        assert_eq!(
            next.buckets[0].oracle_price_seconds,
            u128::from(price(100).get()) * u128::from(FUNDING_BUCKET_SECONDS)
        );
        assert_eq!(next.last_oracle_mark, price(200));
    }

    #[test]
    fn incomplete_prior_epoch_before_multi_epoch_gap_settles_zero_and_cannot_be_replayed() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 100).unwrap();
        let (next, rate) = advance_authenticated_test(
            &state,
            start + 3 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            100,
        )
        .unwrap();
        assert_eq!(rate, 0);
        assert_eq!(next.last_settled_epoch, 3);
        let (same_epoch, rate) = advance_authenticated_test(
            &next,
            next.last_parent_mtp,
            price(100),
            price(90),
            price(110),
            &[],
            100,
        )
        .unwrap();
        assert_eq!(rate, 0);
        assert_eq!(same_epoch.last_settled_epoch, 3);
    }

    #[test]
    fn complete_prior_epoch_survives_multi_epoch_gap() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut state = funding_genesis(start, price(100), 100).unwrap();
        for hour in 1..=8 {
            (state, _) = advance_authenticated_test(
                &state,
                start + hour * FUNDING_BUCKET_SECONDS - 1,
                price(100),
                price(90),
                price(110),
                &[fill(hour, 101)],
                100,
            )
            .unwrap();
        }
        let (next, rate) = advance_authenticated_test(
            &state,
            start + 3 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            &[],
            100,
        )
        .unwrap();
        assert_eq!(rate, FUNDING_RATE_CAP_PPM);
        assert_eq!(next.last_settled_epoch, 3);
        next.validate().unwrap();
        assert!(next
            .buckets
            .iter()
            .all(|bucket| { bucket.epoch == FundingBucketV2::EMPTY_EPOCH || bucket.epoch == 4 }));
    }

    #[test]
    fn minimum_volume_is_invariant_under_adversarial_dust_splitting() {
        let start = FUNDING_EPOCH_SECONDS;
        let mark = Price::new(1).unwrap();
        let high = Price::new(2).unwrap();
        let state = FundingStateV2::genesis_with_band(
            start,
            mark,
            mark,
            high,
            start + 4 * FUNDING_EPOCH_SECONDS,
            0,
        )
        .unwrap();
        let minimum_numerator = MINIMUM_FUNDING_VOLUME_QUOTE_UNITS * u128::from(PRICE_SCALE);
        let total_quantity = u64::try_from((minimum_numerator - 2) / 2).unwrap();
        let base_per_bucket = total_quantity / FUNDING_BUCKET_COUNT as u64;
        let remainder = total_quantity % FUNDING_BUCKET_COUNT as u64;
        let mut split = Vec::new();
        let mut old_per_fill_ceiling = 0u128;
        for bucket in 0..FUNDING_BUCKET_COUNT {
            let quantity = base_per_bucket + u64::from((bucket as u64) < remainder);
            let first = quantity / 2;
            let second = quantity - first;
            let mtp = start + bucket as u64 * FUNDING_BUCKET_SECONDS + 1;
            for part in [first, second] {
                split.push(
                    TimestampedFundingObservationV2::new(high, Quantity::new(part).unwrap(), mtp)
                        .unwrap(),
                );
                old_per_fill_ceiling += ceil_div(
                    u128::from(high.get()) * u128::from(part),
                    u128::from(PRICE_SCALE),
                )
                .unwrap();
            }
        }
        // The former per-fill rounding rule would falsely clear the one-USDD
        // gate even though the exact aggregate numerator is below it.
        assert!(old_per_fill_ceiling >= MINIMUM_FUNDING_VOLUME_QUOTE_UNITS);
        let unsplit = split
            .chunks_exact(2)
            .map(|parts| {
                TimestampedFundingObservationV2::new(
                    high,
                    Quantity::new(parts[0].quantity.get() + parts[1].quantity.get()).unwrap(),
                    parts[0].execution_parent_mtp,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let settle = |observations: &[TimestampedFundingObservationV2]| {
            // Executions from the closing epoch must be finalized before its
            // boundary. The subsequent empty transition settles the carried
            // buckets; it cannot admit an old-epoch fill.
            let (carried, _) = advance_funding_timestamped_v2(
                &state,
                2 * FUNDING_EPOCH_SECONDS - 1,
                mark,
                mark,
                high,
                start + 4 * FUNDING_EPOCH_SECONDS,
                observations,
                0,
            )?;
            advance_funding_timestamped_v2(
                &carried,
                2 * FUNDING_EPOCH_SECONDS,
                mark,
                mark,
                high,
                start + 4 * FUNDING_EPOCH_SECONDS,
                &[],
                0,
            )
        };
        let (_, below_rate) = settle(&split).unwrap();
        let (_, unsplit_below_rate) = settle(&unsplit).unwrap();
        assert_eq!(below_rate, 0);
        assert_eq!(below_rate, unsplit_below_rate);

        split[0].quantity = Quantity::new(split[0].quantity.get() + 1).unwrap();
        let mut unsplit_at_threshold = unsplit;
        unsplit_at_threshold[0].quantity =
            Quantity::new(unsplit_at_threshold[0].quantity.get() + 1).unwrap();
        let (_, at_threshold_rate) = settle(&split).unwrap();
        let (_, unsplit_at_threshold_rate) = settle(&unsplit_at_threshold).unwrap();
        assert_eq!(at_threshold_rate, FUNDING_RATE_CAP_PPM);
        assert_eq!(at_threshold_rate, unsplit_at_threshold_rate);
    }

    #[test]
    fn delayed_execution_stays_in_its_authenticated_hour() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        let execution_mtp = start + FUNDING_BUCKET_SECONDS + 17;
        let (next, _) = advance_funding_timestamped_v2(
            &state,
            start + 4 * FUNDING_BUCKET_SECONDS,
            price(100),
            price(90),
            price(110),
            start + 5 * FUNDING_EPOCH_SECONDS,
            &[timestamped_fill(execution_mtp, 101)],
            0,
        )
        .unwrap();
        assert_eq!(next.buckets[1].trade_base_quantity, u128::from(PRICE_SCALE));
        assert_eq!(next.buckets[3].trade_base_quantity, 0);
    }

    #[test]
    fn epoch_roll_rejects_old_receipt_but_accepts_exact_boundary() {
        let start = FUNDING_EPOCH_SECONDS;
        let mut state = funding_genesis(start, price(100), 0).unwrap();
        for hour in 0..7 {
            (state, _) = advance_funding_timestamped_v2(
                &state,
                start + (hour + 1) * FUNDING_BUCKET_SECONDS,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(
                    start + hour * FUNDING_BUCKET_SECONDS + 1,
                    101,
                )],
                0,
            )
            .unwrap();
        }
        assert_eq!(
            advance_funding_timestamped_v2(
                &state,
                2 * FUNDING_EPOCH_SECONDS,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(
                    start + 7 * FUNDING_BUCKET_SECONDS + 1,
                    101,
                )],
                0,
            ),
            Err(ProtocolError::InvalidFundingState)
        );
        let boundary = 2 * FUNDING_EPOCH_SECONDS;
        let (settled, rate) = advance_funding_timestamped_v2(
            &state,
            boundary,
            price(100),
            price(90),
            price(110),
            start + 5 * FUNDING_EPOCH_SECONDS,
            &[timestamped_fill(boundary, 101)],
            0,
        )
        .unwrap();
        assert_eq!(rate, 0);
        assert_eq!(settled.last_settled_epoch, 1);
        assert_eq!(settled.buckets[0].epoch, 2);
        assert_eq!(
            settled.buckets[0].trade_base_quantity,
            u128::from(PRICE_SCALE)
        );
    }

    #[test]
    fn settled_epoch_receipt_is_rejected_instead_of_relocated() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        let (settled, _) = advance_funding_timestamped_v2(
            &state,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            start + 5 * FUNDING_EPOCH_SECONDS,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(settled.last_settled_epoch, 1);
        assert_eq!(
            advance_funding_timestamped_v2(
                &settled,
                2 * FUNDING_EPOCH_SECONDS + 1,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(start + 1, 101)],
                0,
            ),
            Err(ProtocolError::InvalidFundingState)
        );
    }

    #[test]
    fn future_and_skipped_epoch_receipts_fail_closed() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        assert_eq!(
            advance_funding_timestamped_v2(
                &state,
                start + FUNDING_BUCKET_SECONDS,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(start + FUNDING_BUCKET_SECONDS + 1, 101)],
                0,
            ),
            Err(ProtocolError::InvalidFundingState)
        );
        assert_eq!(
            advance_funding_timestamped_v2(
                &state,
                start + 3 * FUNDING_EPOCH_SECONDS,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(start + FUNDING_EPOCH_SECONDS + 1, 101)],
                0,
            ),
            Err(ProtocolError::InvalidFundingState)
        );
    }

    #[test]
    fn quote_expiry_mid_hour_cannot_look_like_complete_twap_coverage() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = FundingStateV2::genesis_with_band(
            start,
            price(100),
            price(90),
            price(110),
            start + FUNDING_BUCKET_SECONDS / 2,
            0,
        )
        .unwrap();
        let (next, _) = advance_funding_timestamped_v2(
            &state,
            start + FUNDING_BUCKET_SECONDS,
            price(100),
            price(90),
            price(110),
            start + 2 * FUNDING_EPOCH_SECONDS,
            &[timestamped_fill(start + 1, 101)],
            0,
        )
        .unwrap();
        assert_eq!(next.buckets[0].oracle_seconds, FUNDING_BUCKET_SECONDS / 2);
        assert!(!next.buckets[0].sampling_invalid);
    }

    #[test]
    fn eight_hour_stale_carry_settles_zero_even_with_one_fill_per_hour() {
        let start = FUNDING_EPOCH_SECONDS;
        let state =
            FundingStateV2::genesis_with_band(start, price(100), price(90), price(110), start, 0)
                .unwrap();
        let observations = (0..FUNDING_BUCKET_COUNT)
            .map(|hour| {
                timestamped_fill(
                    start + u64::try_from(hour).unwrap() * FUNDING_BUCKET_SECONDS + 1,
                    101,
                )
            })
            .collect::<Vec<_>>();
        let (carried, _) = advance_funding_timestamped_v2(
            &state,
            2 * FUNDING_EPOCH_SECONDS - 1,
            price(100),
            price(90),
            price(110),
            3 * FUNDING_EPOCH_SECONDS,
            &observations,
            0,
        )
        .unwrap();
        let (next, rate) = advance_funding_timestamped_v2(
            &carried,
            2 * FUNDING_EPOCH_SECONDS,
            price(100),
            price(90),
            price(110),
            3 * FUNDING_EPOCH_SECONDS,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(rate, 0);
        assert_eq!(next.last_settled_epoch, 1);
    }

    #[test]
    fn execution_in_expired_interval_invalidates_sampling_without_repricing() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = FundingStateV2::genesis_with_band(
            start,
            price(100),
            price(95),
            price(105),
            start + 10,
            0,
        )
        .unwrap();
        let (next, _) = advance_funding_timestamped_v2(
            &state,
            start + 20,
            price(100),
            price(1),
            price(1_000),
            start + FUNDING_EPOCH_SECONDS,
            &[timestamped_fill(start + 11, 999)],
            0,
        )
        .unwrap();
        assert!(next.buckets[0].sampling_invalid);
        assert_eq!(next.buckets[0].trade_base_quantity, 0);
        assert_eq!(next.buckets[0].trade_price_volume, 0);
    }

    #[test]
    fn receipt_from_before_previous_transition_is_rejected() {
        let start = FUNDING_EPOCH_SECONDS;
        let state = funding_genesis(start, price(100), 0).unwrap();
        let (state, _) = advance_funding_timestamped_v2(
            &state,
            start + FUNDING_BUCKET_SECONDS,
            price(100),
            price(90),
            price(110),
            start + 5 * FUNDING_EPOCH_SECONDS,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(
            advance_funding_timestamped_v2(
                &state,
                start + 2 * FUNDING_BUCKET_SECONDS,
                price(100),
                price(90),
                price(110),
                start + 5 * FUNDING_EPOCH_SECONDS,
                &[timestamped_fill(start + 1, 101)],
                0,
            ),
            Err(ProtocolError::InvalidFundingState)
        );
    }
}
