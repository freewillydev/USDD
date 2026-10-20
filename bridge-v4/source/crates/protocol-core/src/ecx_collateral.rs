//! ECX collateral valuation primitives. These do not enable a deposit lane.
//!
//! Physical ECX and signed USDD accounting cash must remain separate. Callers
//! must authenticate the asset and oracle observation through the committed
//! transition policy before using these calculations for admission. A valuation
//! is not USDD issuance, a conversion receipt, or withdrawable USDD backing.

use crate::incremental_state_v2::{
    trader_equity_numerator_v2, IncrementalAccountingBoundsV2, Int256V2, TraderLeafV2,
    EXACT_ACCOUNTING_DENOMINATOR_V2, FUNDING_INDEX_DENOMINATOR_V2,
};
use crate::types::{Amount, Price, PRICE_SCALE};
use crate::ProtocolError;

/// Native ECX atoms held for a trader, not signed USDD cash atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcxCollateralAtoms(pub u64);

/// Mark an ECX-denominated account plus the existing linear position, without
/// inserting marked ECX into the USDD cash ledger. `ecx_cash_numerator` is a
/// signed account claim at `ecx_cash_scale` units per native ECX atom (not a
/// physical vault balance). Scale must be frozen by the consuming configuration.
/// The result is exact quote equity at denominator
/// `EXACT_ACCOUNTING_DENOMINATOR_V2 * ecx_cash_scale`.
///
/// This supports both whole atoms and fixed sub-atom accounts; it does not pick
/// a rounding policy. Callers must include all settled fractional claims in the
/// account value and authenticate mark/funding. Existing USDD conservation and
/// risk-index aggregates cannot be reused for this different collateral slope.
pub fn ecx_trader_equity_numerator(
    position: &TraderLeafV2,
    ecx_cash_numerator: Int256V2,
    ecx_cash_scale: u64,
    mark_price: Price,
    global_funding_index_numerator: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Int256V2, ProtocolError> {
    ecx_cash_numerator.validate()?;
    if ecx_cash_scale == 0
        || position.collateral_atoms != 0
        || position.cash_residual_numerator != 0
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    let maximum = Int256V2::from_u128(bounds.maximum_abs_trader_collateral_atoms)
        .checked_mul_u64(ecx_cash_scale)?;
    if ecx_cash_numerator.magnitude() > maximum.magnitude() {
        return Err(ProtocolError::InvalidBondState);
    }
    // This validates the position, bounds, mark and funding, and supplies exact
    // unrealized P&L plus pending funding, with quote cash forced to zero above.
    let position_equity = trader_equity_numerator_v2(
        position, mark_price.get(), global_funding_index_numerator, bounds,
    )?;
    ecx_cash_numerator
        .checked_mul_u64(mark_price.get())?
        .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
        .checked_add(position_equity.checked_mul_u64(ecx_cash_scale)?)
}

/// Pointwise maintenance check at an authenticated mark. Retains the existing
/// nested outward rounding of required margin while equity stays exact.
/// For an oracle interval the ECX risk engine must consider collateral exposure
/// as well as position direction; a short is NOT necessarily worst at its high
/// endpoint. This function alone is not interval admission or liquidation
/// authorization, and it does not mutate balances.
pub fn is_ecx_trader_liquidatable(
    position: &TraderLeafV2,
    ecx_cash_numerator: Int256V2,
    ecx_cash_scale: u64,
    mark_price: Price,
    global_funding_index_numerator: i128,
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<bool, ProtocolError> {
    if position.position_size_atoms == 0
        || maintenance_margin_bps == 0
        || maintenance_margin_bps >= 10_000
    {
        return Err(ProtocolError::InvalidRate);
    }
    let equity = ecx_trader_equity_numerator(
        position, ecx_cash_numerator, ecx_cash_scale, mark_price,
        global_funding_index_numerator, bounds,
    )?;
    let notional = (u128::from(mark_price.get())
        * u128::from(position.position_size_atoms.unsigned_abs()))
        .checked_add(u128::from(PRICE_SCALE - 1))
        .ok_or(ProtocolError::ArithmeticOverflow)? / u128::from(PRICE_SCALE);
    let required_atoms = notional.checked_mul(u128::from(maintenance_margin_bps))
        .and_then(|n| n.checked_add(9_999))
        .ok_or(ProtocolError::ArithmeticOverflow)? / 10_000;
    let required = Int256V2::from_u128(required_atoms)
        .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
        .checked_mul_u64(ecx_cash_scale)?;
    Ok(equity < required)
}

/// Exact conversion of the existing linear contract's quote numerator into ECX.
/// The signed fractional ECX claim is `remainder_numerator / denominator`.
/// It is NOT quote cash and must not be repriced at a later oracle price or
/// discarded when an account closes. A ledger must conserve opposing residuals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcxSettlementConversion {
    pub whole_ecx_atoms: Int256V2,
    pub remainder_numerator: Int256V2,
    pub denominator: u128,
}

/// Atomic result for two opposing linear P&L claims. Residuals must be
/// committed alongside balances; they are not spendable whole atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcxPnlSettlement {
    pub first_balance: EcxCollateralAtoms,
    pub second_balance: EcxCollateralAtoms,
    pub first_residual: Int256V2,
    pub second_residual: Int256V2,
    pub residual_denominator: u128,
}

/// A staged position update and its payment against the ECX clearing balance.
/// Commit all fields together, including the clearing account's opposite
/// fractional claim. This does not match two traders' realized profits: those
/// can differ when their entry prices differ. Authorization, margin and durable
/// residual accumulation belong to the consuming versioned account transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxPositionSettlement {
    pub position: TraderLeafV2,
    pub payment: EcxPnlSettlement,
}

/// Calculate a trade and pay its realized P&L/funding without mutating any
/// input. In particular an insolvent clearing account or trader cannot leave
/// behind an advanced position or funding checkpoint.
pub fn stage_ecx_trade(
    position: &TraderLeafV2,
    trader_balance: EcxCollateralAtoms,
    clearing_balance: EcxCollateralAtoms,
    position_delta_atoms: i64,
    fill_price: Price,
    settlement_price: Price,
    global_funding_index_numerator: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxPositionSettlement, ProtocolError> {
    let mut next = position.clone();
    let liability = next.apply_trade_for_ecx_settlement(position_delta_atoms,
        fill_price.get(), global_funding_index_numerator, bounds)?;
    let payment = settle_opposing_ecx_pnl(trader_balance, clearing_balance,
        liability, settlement_price)?;
    Ok(EcxPositionSettlement { position: next, payment })
}

/// Funding-only equivalent of `stage_ecx_trade`, with the same all-or-nothing
/// result. An unchanged funding index pays zero on a previously committed leaf.
pub fn stage_ecx_funding(
    position: &TraderLeafV2,
    trader_balance: EcxCollateralAtoms,
    clearing_balance: EcxCollateralAtoms,
    settlement_price: Price,
    global_funding_index_numerator: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxPositionSettlement, ProtocolError> {
    let mut next = position.clone();
    let liability = next.settle_lazy_funding_for_ecx(global_funding_index_numerator, bounds)?;
    let payment = settle_opposing_ecx_pnl(trader_balance, clearing_balance,
        liability, settlement_price)?;
    Ok(EcxPositionSettlement { position: next, payment })
}

/// Settle the first account's signed quote P&L against its counterparty.
/// The caller must authenticate the price and exact opposing P&L, and persist
/// both balances AND both residuals atomically. This does not authorize trades.
pub fn settle_opposing_ecx_pnl(
    first: EcxCollateralAtoms,
    second: EcxCollateralAtoms,
    first_quote_pnl: Int256V2,
    settlement_price: Price,
) -> Result<EcxPnlSettlement, ProtocolError> {
    let conversion = quote_numerator_to_ecx(first_quote_pnl, settlement_price)?;
    let signed_atoms = conversion.whole_ecx_atoms.try_to_i128()?;
    let atoms = u64::try_from(signed_atoms.unsigned_abs())
        .map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let (first_balance, second_balance) = if signed_atoms < 0 {
        settle_ecx_transfer(first, second, atoms)?
    } else {
        let (second, first) = settle_ecx_transfer(second, first, atoms)?;
        (first, second)
    };
    Ok(EcxPnlSettlement {
        first_balance,
        second_balance,
        first_residual: conversion.remainder_numerator,
        second_residual: conversion.remainder_numerator.checked_neg()?,
        residual_denominator: conversion.denominator,
    })
}

/// Convert a numerator at the existing exact quote denominator
/// `PRICE_SCALE * FUNDING_INDEX_DENOMINATOR_V2`. The caller supplies a price
/// already authenticated by the transition. No early quote-atom rounding occurs.
/// This preserves the linear base-quantity payoff; it is not an inverse contract.
pub fn quote_numerator_to_ecx(
    quote_numerator: Int256V2,
    settlement_price: Price,
) -> Result<EcxSettlementConversion, ProtocolError> {
    quote_numerator.validate()?;
    Price::new(settlement_price.get())?;
    let denominator = u128::from(settlement_price.get()) * u128::from(FUNDING_INDEX_DENOMINATOR_V2);
    // Sequential positive-divisor truncation gives the same integer quotient
    // as division by their product, without restricting prices to u64 / 1e6.
    let (scaled, _) = quote_numerator.div_rem_u64_toward_zero(FUNDING_INDEX_DENOMINATOR_V2)?;
    let (whole_ecx_atoms, _) = scaled.div_rem_u64_toward_zero(settlement_price.get())?;
    let remainder_numerator =
        quote_numerator.checked_sub(whole_ecx_atoms.checked_mul_u128(denominator)?)?;
    Ok(EcxSettlementConversion {
        whole_ecx_atoms,
        remainder_numerator,
        denominator,
    })
}

/// Settle an already-authorized, whole-atom ECX liability between two balances.
/// Returns both new balances or neither: callers must commit the pair atomically.
/// This is not a payoff calculator, oracle check, or liquidation authorization.
pub fn settle_ecx_transfer(
    payer: EcxCollateralAtoms,
    recipient: EcxCollateralAtoms,
    atoms: u64,
) -> Result<(EcxCollateralAtoms, EcxCollateralAtoms), ProtocolError> {
    let next_payer = payer.checked_withdraw(atoms)?;
    let next_recipient = recipient.checked_deposit(atoms)?;
    Ok((next_payer, next_recipient))
}

impl EcxCollateralAtoms {
    /// Gross USDD valuation, rounded down so fractional atoms never increase
    /// collateral credit. Risk discounts, if any, belong to committed policy.
    pub fn quote_value(self, ecx_price: Price) -> Result<Amount, ProtocolError> {
        // Price is validated again because optional serde can construct Price.
        Price::new(ecx_price.get())?;
        let value = u128::from(self.0) * u128::from(ecx_price.get()) / u128::from(PRICE_SCALE);
        Ok(Amount(
            i128::try_from(value).map_err(|_| ProtocolError::ArithmeticOverflow)?,
        ))
    }

    /// Withdraw physical ECX only. The transition must additionally enforce
    /// post-withdrawal margin, authorization, and exact vault conservation.
    pub fn checked_withdraw(self, atoms: u64) -> Result<Self, ProtocolError> {
        self.0
            .checked_sub(atoms)
            .map(Self)
            .ok_or(ProtocolError::InsufficientCollateral)
    }

    pub fn checked_deposit(self, atoms: u64) -> Result<Self, ProtocolError> {
        self.0
            .checked_add(atoms)
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opposing_pnl_settlement_preserves_direction_and_fraction() {
        let denominator = 3 * FUNDING_INDEX_DENOMINATOR_V2;
        for sign in [-1i128, 1] {
            let result = settle_opposing_ecx_pnl(
                EcxCollateralAtoms(10), EcxCollateralAtoms(10),
                Int256V2::from_i128(sign * (2 * i128::from(denominator) + 1)),
                Price::new(3).unwrap(),
            ).unwrap();
            assert_eq!(result.first_balance.0, (10 + sign * 2) as u64);
            assert_eq!(result.second_balance.0, (10 - sign * 2) as u64);
            assert_eq!(result.first_residual, Int256V2::from_i128(sign));
            assert_eq!(result.second_residual, Int256V2::from_i128(-sign));
            assert_eq!(result.residual_denominator, u128::from(denominator));
        }
        assert_eq!(settle_opposing_ecx_pnl(
            EcxCollateralAtoms(0), EcxCollateralAtoms(0),
            Int256V2::from_i128(i128::from(denominator)), Price::new(3).unwrap(),
        ), Err(ProtocolError::InsufficientCollateral));
    }

    #[test]
    fn linear_close_converts_quote_profit_to_physical_ecx() {
        // One base ECX, entry 30, exit 60: 30 quote units = 0.5 ECX.
        let numerator = Int256V2::from_i128(
            i128::from(PRICE_SCALE)
                * i128::from(30 * PRICE_SCALE)
                * i128::from(FUNDING_INDEX_DENOMINATOR_V2),
        );
        let converted =
            quote_numerator_to_ecx(numerator, Price::new(60 * PRICE_SCALE).unwrap()).unwrap();
        assert_eq!(converted.whole_ecx_atoms, Int256V2::from_i128(50_000_000));
        assert_eq!(converted.remainder_numerator, Int256V2::ZERO);
        let (short, long) = settle_ecx_transfer(
            EcxCollateralAtoms(PRICE_SCALE),
            EcxCollateralAtoms(PRICE_SCALE),
            u64::try_from(converted.whole_ecx_atoms.try_to_i128().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!((short.0, long.0), (50_000_000, 150_000_000));
        assert_eq!(short.checked_withdraw(short.0).unwrap().0, 0);
        assert_eq!(long.checked_withdraw(long.0).unwrap().0, 0);
    }

    #[test]
    fn conversion_retains_exact_opposing_fractional_claims() {
        for price in [1, 3, PRICE_SCALE, u64::MAX] {
            for value in [0, 1, -1, 9_999_999, -9_999_999, i128::MAX, i128::MIN] {
                let n = Int256V2::from_i128(value);
                let a = quote_numerator_to_ecx(n, Price::new(price).unwrap()).unwrap();
                let b =
                    quote_numerator_to_ecx(n.checked_neg().unwrap(), Price::new(price).unwrap())
                        .unwrap();
                assert_eq!(
                    a.whole_ecx_atoms.checked_add(b.whole_ecx_atoms).unwrap(),
                    Int256V2::ZERO
                );
                assert_eq!(
                    a.remainder_numerator
                        .checked_add(b.remainder_numerator)
                        .unwrap(),
                    Int256V2::ZERO
                );
                assert_eq!(
                    a.whole_ecx_atoms
                        .checked_mul_u128(a.denominator)
                        .unwrap()
                        .checked_add(a.remainder_numerator)
                        .unwrap(),
                    n
                );
                assert!(
                    a.remainder_numerator.magnitude()
                        < Int256V2::from_u128(a.denominator).magnitude()
                );
            }
        }
    }

    #[test]
    fn settlement_moves_physical_ecx_without_creating_quote_cash() {
        let payer = EcxCollateralAtoms(100);
        let recipient = EcxCollateralAtoms(20);
        let (a, b) = settle_ecx_transfer(payer, recipient, 30).unwrap();
        assert_eq!((a, b), (EcxCollateralAtoms(70), EcxCollateralAtoms(50)));
        assert_eq!(u128::from(a.0) + u128::from(b.0), 120);
        assert_eq!(settle_ecx_transfer(a, b, 0).unwrap(), (a, b));
        assert_eq!(settle_ecx_transfer(b, a, 30).unwrap(), (recipient, payer));
    }

    #[test]
    fn failed_settlement_cannot_return_a_partially_debited_balance() {
        assert_eq!(
            settle_ecx_transfer(EcxCollateralAtoms(1), EcxCollateralAtoms(0), 2),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            settle_ecx_transfer(EcxCollateralAtoms(1), EcxCollateralAtoms(u64::MAX), 1),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }

    #[test]
    fn ecx_remains_ecx_as_its_quote_value_changes() {
        let balance = EcxCollateralAtoms(PRICE_SCALE);
        assert_eq!(
            balance
                .quote_value(Price::new(30 * PRICE_SCALE).unwrap())
                .unwrap(),
            Amount(30 * i128::from(PRICE_SCALE))
        );
        assert_eq!(
            balance
                .quote_value(Price::new(15 * PRICE_SCALE).unwrap())
                .unwrap(),
            Amount(15 * i128::from(PRICE_SCALE))
        );
        assert_eq!(
            balance.checked_withdraw(PRICE_SCALE).unwrap(),
            EcxCollateralAtoms(0)
        );
    }

    #[test]
    fn valuation_rounds_down_and_accepts_full_width_inputs() {
        assert_eq!(
            EcxCollateralAtoms(1)
                .quote_value(Price::new(PRICE_SCALE - 1).unwrap())
                .unwrap(),
            Amount(0)
        );
        let expected = u128::from(u64::MAX) * u128::from(u64::MAX) / u128::from(PRICE_SCALE);
        assert_eq!(
            EcxCollateralAtoms(u64::MAX)
                .quote_value(Price::new(u64::MAX).unwrap())
                .unwrap()
                .0,
            i128::try_from(expected).unwrap()
        );
    }

    #[test]
    fn physical_balance_rejects_overdraw_and_overflow() {
        assert_eq!(
            EcxCollateralAtoms(1).checked_withdraw(2),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            EcxCollateralAtoms(u64::MAX).checked_deposit(1),
            Err(ProtocolError::ArithmeticOverflow)
        );
        assert_eq!(
            EcxCollateralAtoms(7)
                .checked_deposit(4)
                .unwrap()
                .checked_withdraw(4)
                .unwrap(),
            EcxCollateralAtoms(7)
        );
    }
}
