use crate::codec::{put_i32, put_u32, CanonicalEncode};
use crate::order::Side;
use crate::types::{Amount, Position, Price, Quantity, PRICE_SCALE};
use crate::ProtocolError;

pub const BPS_DENOMINATOR: u128 = 10_000;
pub const FUNDING_RATE_DENOMINATOR: i128 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskParams {
    pub initial_margin_bps: u32,
    pub maintenance_margin_bps: u32,
    pub liquidation_fee_bps: u32,
    /// A negative maker rate is a rebate.
    pub maker_fee_bps: i32,
    pub taker_fee_bps: u32,
    pub max_abs_funding_rate_ppm: u32,
    /// Maximum aggregate long quantity after any transition. Conservation
    /// makes aggregate short quantity identical.
    pub maximum_open_interest_lots: u64,
    /// Maximum aggregate liquidation execution notional admitted in one
    /// transition, denominated in protocol quote units.
    pub maximum_liquidation_notional_quote_units: u64,
    /// Version-one production policy is fail-closed insolvency: bad debt must
    /// be paid by the insurance fund and may not be assigned to traders.
    pub socialized_loss_enabled: bool,
}

impl RiskParams {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.initial_margin_bps == 0
            || self.initial_margin_bps > 10_000
            || self.maintenance_margin_bps == 0
            || self.maintenance_margin_bps >= self.initial_margin_bps
            || self.liquidation_fee_bps > self.maintenance_margin_bps
            || self.maker_fee_bps.unsigned_abs() > 10_000
            || self.taker_fee_bps > 10_000
            || self.max_abs_funding_rate_ppm > 1_000_000
            || self.maximum_open_interest_lots == 0
            || self.maximum_open_interest_lots > i64::MAX as u64
            || self.maximum_liquidation_notional_quote_units == 0
            || self.maximum_liquidation_notional_quote_units > i64::MAX as u64
            || self.socialized_loss_enabled
        {
            Err(ProtocolError::InvalidRate)
        } else {
            Ok(self)
        }
    }
}

impl Default for RiskParams {
    fn default() -> Self {
        Self {
            initial_margin_bps: 1_000,
            maintenance_margin_bps: 600,
            liquidation_fee_bps: 100,
            maker_fee_bps: 0,
            taker_fee_bps: 5,
            max_abs_funding_rate_ppm: 10_000,
            maximum_open_interest_lots: 100_000_000_000_000,
            maximum_liquidation_notional_quote_units: 1_000_000_000_000_000,
            socialized_loss_enabled: false,
        }
    }
}

impl CanonicalEncode for RiskParams {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u32(out, self.initial_margin_bps);
        put_u32(out, self.maintenance_margin_bps);
        put_u32(out, self.liquidation_fee_bps);
        put_i32(out, self.maker_fee_bps);
        put_u32(out, self.taker_fee_bps);
        put_u32(out, self.max_abs_funding_rate_ppm);
        crate::codec::put_u64(out, self.maximum_open_interest_lots);
        crate::codec::put_u64(out, self.maximum_liquidation_notional_quote_units);
        crate::codec::put_u8(out, u8::from(self.socialized_loss_enabled));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarginKind {
    Initial,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FillOutcome {
    pub position: Position,
    pub realized_pnl: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidationResult {
    pub closed_position: Position,
    pub realized_pnl: Amount,
    pub penalty_to_insurance: Amount,
    pub remaining_collateral: Amount,
    pub bad_debt: Amount,
}

fn ceil_div(value: u128, divisor: u128) -> Result<u128, ProtocolError> {
    if divisor == 0 {
        return Err(ProtocolError::DivisionByZero);
    }
    value
        .checked_add(divisor - 1)
        .ok_or(ProtocolError::ArithmeticOverflow)
        .map(|sum| sum / divisor)
}

pub fn notional(price: Price, quantity: u64) -> Result<Amount, ProtocolError> {
    let product = u128::from(price.get())
        .checked_mul(u128::from(quantity))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let quote = ceil_div(product, u128::from(PRICE_SCALE))?;
    let quote = i128::try_from(quote).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    Ok(Amount(quote))
}

pub fn required_margin(
    position: &Position,
    mark_price: Price,
    kind: MarginKind,
    params: RiskParams,
) -> Result<Amount, ProtocolError> {
    params.validate()?;
    let rate = match kind {
        MarginKind::Initial => params.initial_margin_bps,
        MarginKind::Maintenance => params.maintenance_margin_bps,
    };
    let notional = u128::try_from(notional(mark_price, position.size.unsigned_abs())?.0)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let margin = ceil_div(
        notional
            .checked_mul(u128::from(rate))
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        BPS_DENOMINATOR,
    )?;
    Ok(Amount(
        i128::try_from(margin).map_err(|_| ProtocolError::ArithmeticOverflow)?,
    ))
}

/// Returns the collateral delta. Positive funding means longs pay shorts.
pub fn funding_payment(
    position: &Position,
    mark_price: Price,
    funding_rate_ppm: i32,
    params: RiskParams,
) -> Result<Amount, ProtocolError> {
    params.validate()?;
    if funding_rate_ppm.unsigned_abs() > params.max_abs_funding_rate_ppm {
        return Err(ProtocolError::InvalidRate);
    }
    let product = i128::from(position.size)
        .checked_mul(i128::from(mark_price.get()))
        .and_then(|value| value.checked_mul(i128::from(funding_rate_ppm)))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let denominator = i128::from(PRICE_SCALE)
        .checked_mul(FUNDING_RATE_DENOMINATOR)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    Ok(Amount(-(product / denominator)))
}

pub fn unrealized_pnl(position: &Position, mark_price: Price) -> Result<Amount, ProtocolError> {
    position.validate()?;
    if position.size == 0 {
        return Ok(Amount(0));
    }
    let price_delta = i128::from(mark_price.get())
        .checked_sub(i128::from(position.entry_price))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let pnl = i128::from(position.size)
        .checked_mul(price_delta)
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / i128::from(PRICE_SCALE);
    Ok(Amount(pnl))
}

pub fn equity(
    collateral: Amount,
    position: &Position,
    mark_price: Price,
) -> Result<Amount, ProtocolError> {
    collateral.checked_add(unrealized_pnl(position, mark_price)?)
}

pub fn is_liquidatable(
    collateral: Amount,
    position: &Position,
    mark_price: Price,
    params: RiskParams,
) -> Result<bool, ProtocolError> {
    let maintenance = required_margin(position, mark_price, MarginKind::Maintenance, params)?;
    Ok(equity(collateral, position, mark_price)?.0 < maintenance.0)
}

pub fn trading_fee(
    price: Price,
    quantity: Quantity,
    fee_bps: i32,
) -> Result<Amount, ProtocolError> {
    if fee_bps.unsigned_abs() > 10_000 {
        return Err(ProtocolError::InvalidRate);
    }
    let base = notional(price, quantity.get())?.0;
    let magnitude = ceil_div(
        u128::try_from(base)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
            .checked_mul(u128::from(fee_bps.unsigned_abs()))
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        BPS_DENOMINATOR,
    )?;
    let signed = i128::try_from(magnitude).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    Ok(Amount(if fee_bps < 0 { -signed } else { signed }))
}

pub fn apply_fill(
    position: Position,
    side: Side,
    quantity: Quantity,
    fill_price: Price,
) -> Result<FillOutcome, ProtocolError> {
    position.validate()?;
    let delta_abs = quantity.get();
    let delta = i64::try_from(delta_abs)
        .map_err(|_| ProtocolError::InvalidQuantity)?
        .checked_mul(side.sign())
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let new_size = position
        .size
        .checked_add(delta)
        .ok_or(ProtocolError::ArithmeticOverflow)?;

    if position.size == 0 {
        return Ok(FillOutcome {
            position: Position {
                size: new_size,
                entry_price: fill_price.get(),
                last_funding_index: position.last_funding_index,
            },
            realized_pnl: Amount(0),
        });
    }

    if position.size.signum() == delta.signum() {
        let old_weight = u128::from(position.size.unsigned_abs())
            .checked_mul(u128::from(position.entry_price))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let new_weight = u128::from(delta_abs)
            .checked_mul(u128::from(fill_price.get()))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let total_weight = old_weight
            .checked_add(new_weight)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let entry_price = total_weight / u128::from(new_size.unsigned_abs());
        return Ok(FillOutcome {
            position: Position {
                size: new_size,
                entry_price: u64::try_from(entry_price)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                last_funding_index: position.last_funding_index,
            },
            realized_pnl: Amount(0),
        });
    }

    let closing_quantity = position.size.unsigned_abs().min(delta_abs);
    let price_delta = if position.size > 0 {
        i128::from(fill_price.get()) - i128::from(position.entry_price)
    } else {
        i128::from(position.entry_price) - i128::from(fill_price.get())
    };
    let realized_pnl = price_delta
        .checked_mul(i128::from(closing_quantity))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / i128::from(PRICE_SCALE);
    let entry_price = if new_size == 0 {
        0
    } else if new_size.signum() == position.size.signum() {
        position.entry_price
    } else {
        fill_price.get()
    };
    Ok(FillOutcome {
        position: Position {
            size: new_size,
            entry_price,
            last_funding_index: position.last_funding_index,
        },
        realized_pnl: Amount(realized_pnl),
    })
}

pub fn liquidation(
    collateral: Amount,
    position: Position,
    mark_price: Price,
    params: RiskParams,
) -> Result<LiquidationResult, ProtocolError> {
    if !is_liquidatable(collateral, &position, mark_price, params)? {
        return Err(ProtocolError::NotLiquidatable);
    }
    let realized_pnl = unrealized_pnl(&position, mark_price)?;
    let equity = collateral.checked_add(realized_pnl)?;
    let desired_penalty = trading_fee(
        mark_price,
        Quantity::new(position.size.unsigned_abs())?,
        i32::try_from(params.liquidation_fee_bps).map_err(|_| ProtocolError::InvalidRate)?,
    )?;
    let available = equity.0.max(0);
    let penalty = desired_penalty.0.min(available);
    let remaining = available - penalty;
    let bad_debt = (-equity.0).max(0);
    Ok(LiquidationResult {
        closed_position: Position::FLAT,
        realized_pnl,
        penalty_to_insurance: Amount(penalty),
        remaining_collateral: Amount(remaining),
        bad_debt: Amount(bad_debt),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(value: u64) -> Price {
        Price::new(value * PRICE_SCALE).unwrap()
    }

    #[test]
    fn weighted_entry_and_crossing_realize_pnl() {
        let opened =
            apply_fill(Position::FLAT, Side::Buy, Quantity::new(2).unwrap(), p(100)).unwrap();
        let added = apply_fill(
            opened.position,
            Side::Buy,
            Quantity::new(2).unwrap(),
            p(120),
        )
        .unwrap();
        assert_eq!(added.position.entry_price, 110 * PRICE_SCALE);
        let crossed = apply_fill(
            added.position,
            Side::Sell,
            Quantity::new(5).unwrap(),
            p(130),
        )
        .unwrap();
        assert_eq!(crossed.realized_pnl, Amount(80));
        assert_eq!(crossed.position.size, -1);
        assert_eq!(crossed.position.entry_price, 130 * PRICE_SCALE);
    }

    #[test]
    fn funding_is_zero_sum_for_equal_long_and_short() {
        let params = RiskParams::default();
        let long = Position {
            size: 10,
            entry_price: p(100).get(),
            last_funding_index: 0,
        };
        let short = Position { size: -10, ..long };
        let long_payment = funding_payment(&long, p(100), 1_000, params).unwrap();
        let short_payment = funding_payment(&short, p(100), 1_000, params).unwrap();
        assert_eq!(long_payment.0 + short_payment.0, 0);
        assert!(long_payment.0 < 0);
    }

    #[test]
    fn margin_and_liquidation_threshold_use_integer_math() {
        let params = RiskParams::default();
        let position = Position {
            size: 10,
            entry_price: p(100).get(),
            last_funding_index: 0,
        };
        assert_eq!(
            required_margin(&position, p(100), MarginKind::Initial, params).unwrap(),
            Amount(100)
        );
        assert!(!is_liquidatable(Amount(100), &position, p(100), params).unwrap());
        assert!(is_liquidatable(Amount(20), &position, p(95), params).unwrap());
        let result = liquidation(Amount(20), position, p(95), params).unwrap();
        assert_eq!(result.closed_position, Position::FLAT);
        assert!(result.bad_debt.0 > 0);
    }

    #[test]
    fn fees_round_up_and_rebates_are_negative() {
        let quantity = Quantity::new(1).unwrap();
        assert_eq!(trading_fee(p(1), quantity, 1).unwrap(), Amount(1));
        assert_eq!(trading_fee(p(1), quantity, -1).unwrap(), Amount(-1));
    }

    #[test]
    fn zero_maintenance_margin_is_not_a_valid_frozen_risk_profile() {
        let params = RiskParams {
            maintenance_margin_bps: 0,
            ..RiskParams::default()
        };
        assert_eq!(params.validate(), Err(ProtocolError::InvalidRate));
    }

    #[test]
    fn open_interest_cap_must_be_finite_and_positive() {
        let zero = RiskParams {
            maximum_open_interest_lots: 0,
            ..RiskParams::default()
        };
        assert_eq!(zero.validate(), Err(ProtocolError::InvalidRate));
        let oversized = RiskParams {
            maximum_open_interest_lots: i64::MAX as u64 + 1,
            ..RiskParams::default()
        };
        assert_eq!(oversized.validate(), Err(ProtocolError::InvalidRate));
    }

    #[test]
    fn liquidation_batch_cap_must_be_finite_and_positive() {
        let zero = RiskParams {
            maximum_liquidation_notional_quote_units: 0,
            ..RiskParams::default()
        };
        assert_eq!(zero.validate(), Err(ProtocolError::InvalidRate));
        let oversized = RiskParams {
            maximum_liquidation_notional_quote_units: i64::MAX as u64 + 1,
            ..RiskParams::default()
        };
        assert_eq!(oversized.validate(), Err(ProtocolError::InvalidRate));
    }

    #[test]
    fn socialized_loss_is_not_a_valid_version_one_policy() {
        let params = RiskParams {
            socialized_loss_enabled: true,
            ..RiskParams::default()
        };
        assert_eq!(params.validate(), Err(ProtocolError::InvalidRate));
    }
}
