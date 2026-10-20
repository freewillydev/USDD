//! Deterministic portfolio stress harness for the mock-USDD ECX prototype.
//!
//! This is not a second risk engine. It drives the same margin and liquidation
//! functions consumed by protocol transitions and keeps a conserved mock-asset
//! ledger around them so insurance exhaustion is observable.

#![forbid(unsafe_code)]

use ecx_protocol_core::{
    equity, is_liquidatable, liquidation, required_margin, Amount, MarginKind, Position, Price,
    ProtocolError, RiskParams, PRICE_SCALE,
};
use serde::{Deserialize, Serialize};

/// Private-network-only asset identity used by the runnable prototype.
///
/// ASCII prefix: `ECX-MOCK-USDD-V1`. It is deliberately not a production asset
/// ID and deployment validation must never substitute it for a reviewed issuance.
pub const MOCK_USDD_ASSET_ID: [u8; 32] = [
    0x45, 0x43, 0x58, 0x2d, 0x4d, 0x4f, 0x43, 0x4b, 0x2d, 0x55, 0x53, 0x44, 0x44, 0x2d, 0x56, 0x31,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StressConfig {
    pub scenario: String,
    pub seed: u64,
    pub accounts: u32,
    /// Whole USDD per ECX before conversion to the protocol's 1e8 price scale.
    pub initial_price_usdd: u64,
    /// Price levels relative to the initial price, in basis points.
    pub price_path_bps: Vec<u32>,
    /// Adverse liquidation band around each mark, in basis points.
    pub liquidation_band_bps: u32,
    pub initial_insurance_usdd: i128,
    pub maker_liquidity_usdd: i128,
    pub risk: RiskParams,
}

impl StressConfig {
    pub fn orderly(seed: u64, accounts: u32) -> Self {
        Self {
            scenario: "orderly-volatility".to_owned(),
            seed,
            accounts,
            initial_price_usdd: 100,
            price_path_bps: vec![10_000, 9_700, 9_300, 9_000, 10_500, 11_000],
            liquidation_band_bps: 200,
            initial_insurance_usdd: i128::from(accounts) * 50,
            maker_liquidity_usdd: i128::from(accounts) * 2_000,
            risk: RiskParams::default(),
        }
    }

    pub fn crash(seed: u64, accounts: u32) -> Self {
        Self {
            scenario: "gap-crash".to_owned(),
            price_path_bps: vec![10_000, 8_500, 6_500, 4_000],
            liquidation_band_bps: 500,
            initial_insurance_usdd: i128::from(accounts) * 10,
            ..Self::orderly(seed, accounts)
        }
    }

    pub fn short_squeeze(seed: u64, accounts: u32) -> Self {
        Self {
            scenario: "short-squeeze".to_owned(),
            price_path_bps: vec![10_000, 11_500, 14_000, 18_000],
            liquidation_band_bps: 500,
            initial_insurance_usdd: i128::from(accounts) * 10,
            ..Self::orderly(seed, accounts)
        }
    }

    pub fn whipsaw(seed: u64, accounts: u32) -> Self {
        Self {
            scenario: "crash-and-squeeze".to_owned(),
            price_path_bps: vec![10_000, 8_000, 6_000, 12_000, 16_000],
            liquidation_band_bps: 400,
            initial_insurance_usdd: i128::from(accounts) * 25,
            ..Self::orderly(seed, accounts)
        }
    }

    pub fn validate(&self) -> Result<(), StressError> {
        self.risk.validate()?;
        if self.accounts < 2
            || self.initial_price_usdd == 0
            || self.price_path_bps.is_empty()
            || self.price_path_bps.contains(&0)
            || self.liquidation_band_bps >= 10_000
            || self.initial_insurance_usdd < 0
            || self.maker_liquidity_usdd <= 0
        {
            return Err(StressError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepReport {
    pub price_level_bps: u32,
    pub mark_price_usdd: u64,
    pub liquidations: u32,
    pub long_liquidations: u32,
    pub short_liquidations: u32,
    pub penalty_to_insurance_usdd: i128,
    pub bad_debt_usdd: i128,
    pub uncovered_bad_debt_usdd: i128,
    pub insurance_after_usdd: i128,
    pub active_accounts_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StressReport {
    pub scenario: String,
    pub seed: u64,
    pub mock_usdd_asset_id_hex: String,
    pub accounts: u32,
    pub initial_margin_bps: u32,
    pub maintenance_margin_bps: u32,
    pub liquidation_fee_bps: u32,
    pub minted_mock_usdd: i128,
    pub initially_admitted_accounts: u32,
    pub total_liquidations: u32,
    pub total_long_liquidations: u32,
    pub total_short_liquidations: u32,
    pub total_penalties_usdd: i128,
    pub total_bad_debt_usdd: i128,
    pub uncovered_bad_debt_usdd: i128,
    pub final_insurance_usdd: i128,
    pub final_maker_liquidity_usdd: i128,
    pub returned_collateral_usdd: i128,
    pub active_collateral_usdd: i128,
    pub ledger_assets_after_usdd: i128,
    pub ledger_conserved: bool,
    pub solvent: bool,
    pub steps: Vec<StepReport>,
}

#[derive(Debug, Clone)]
struct Account {
    collateral: Amount,
    position: Position,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StressError {
    InvalidConfiguration,
    Protocol(ProtocolError),
    Arithmetic,
    LedgerInvariant,
}

impl std::fmt::Display for StressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "mock-USDD stress error: {self:?}")
    }
}

impl std::error::Error for StressError {}

impl From<ProtocolError> for StressError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

pub fn run_stress(config: &StressConfig) -> Result<StressReport, StressError> {
    config.validate()?;
    let initial_price = scaled_price(config.initial_price_usdd, 10_000)?;
    let mut rng = Lcg::new(config.seed);
    let mut accounts = Vec::with_capacity(config.accounts as usize);
    let mut account_collateral = 0_i128;

    for index in 0..config.accounts {
        let magnitude = 10_u64
            .checked_add(rng.next_u64() % 991)
            .ok_or(StressError::Arithmetic)?;
        let signed_size = i64::try_from(magnitude).map_err(|_| StressError::Arithmetic)?
            * if index % 2 == 0 { 1 } else { -1 };
        let position = Position {
            size: signed_size,
            entry_price: initial_price.get(),
            last_funding_index: 0,
        };
        let initial_margin =
            required_margin(&position, initial_price, MarginKind::Initial, config.risk)?;
        // Between 105% and 180% of required initial margin. Every generated
        // account is admitted by the real margin function, while leverage is
        // varied enough to create cascades under the shock paths.
        let buffer_bps = 10_500_i128 + i128::from(rng.next_u64() % 7_501);
        let collateral = initial_margin
            .0
            .checked_mul(buffer_bps)
            .and_then(|value| value.checked_add(9_999))
            .map(|value| value / 10_000)
            .ok_or(StressError::Arithmetic)?;
        if equity(Amount(collateral), &position, initial_price)?.0 < initial_margin.0 {
            return Err(StressError::LedgerInvariant);
        }
        account_collateral = account_collateral
            .checked_add(collateral)
            .ok_or(StressError::Arithmetic)?;
        accounts.push(Account {
            collateral: Amount(collateral),
            position,
        });
    }

    let minted = account_collateral
        .checked_add(config.initial_insurance_usdd)
        .and_then(|value| value.checked_add(config.maker_liquidity_usdd))
        .ok_or(StressError::Arithmetic)?;
    let mut insurance = config.initial_insurance_usdd;
    let mut maker_liquidity = config.maker_liquidity_usdd;
    let mut returned_collateral = 0_i128;
    let mut uncovered_total = 0_i128;
    let mut total_penalties = 0_i128;
    let mut total_bad_debt = 0_i128;
    let mut total_liquidations = 0_u32;
    let mut total_longs = 0_u32;
    let mut total_shorts = 0_u32;
    let mut steps = Vec::with_capacity(config.price_path_bps.len());

    for level in &config.price_path_bps {
        let mark = scaled_price(config.initial_price_usdd, *level)?;
        let mut step = StepReport {
            price_level_bps: *level,
            mark_price_usdd: mark.get() / PRICE_SCALE,
            liquidations: 0,
            long_liquidations: 0,
            short_liquidations: 0,
            penalty_to_insurance_usdd: 0,
            bad_debt_usdd: 0,
            uncovered_bad_debt_usdd: 0,
            insurance_after_usdd: insurance,
            active_accounts_after: 0,
        };

        for account in &mut accounts {
            if account.position.size == 0 {
                continue;
            }
            let long = account.position.size > 0;
            let adverse_level = if long {
                u64::from(10_000 - config.liquidation_band_bps)
            } else {
                u64::from(10_000 + config.liquidation_band_bps)
            };
            let adverse_units = u128::from(mark.get())
                .checked_mul(u128::from(adverse_level))
                .map(|value| value / 10_000)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(StressError::Arithmetic)?;
            let adverse = Price::new(adverse_units)?;
            if !is_liquidatable(account.collateral, &account.position, adverse, config.risk)? {
                continue;
            }

            let result = liquidation(account.collateral, account.position, adverse, config.risk)?;
            let covered_bad_debt = result.bad_debt.0.min(insurance);
            let uncovered = result
                .bad_debt
                .0
                .checked_sub(covered_bad_debt)
                .ok_or(StressError::Arithmetic)?;
            insurance = insurance
                .checked_add(result.penalty_to_insurance.0)
                .and_then(|value| value.checked_sub(covered_bad_debt))
                .ok_or(StressError::Arithmetic)?;

            // Counterparty PnL is the negative of target PnL, except that an
            // uncovered deficit is not magically minted into the mock ledger.
            let counterparty_delta = result
                .realized_pnl
                .0
                .checked_neg()
                .and_then(|value| value.checked_sub(uncovered))
                .ok_or(StressError::Arithmetic)?;
            maker_liquidity = maker_liquidity
                .checked_add(counterparty_delta)
                .ok_or(StressError::Arithmetic)?;
            if maker_liquidity < 0 || insurance < 0 {
                return Err(StressError::LedgerInvariant);
            }

            returned_collateral = returned_collateral
                .checked_add(result.remaining_collateral.0)
                .ok_or(StressError::Arithmetic)?;
            total_penalties = total_penalties
                .checked_add(result.penalty_to_insurance.0)
                .ok_or(StressError::Arithmetic)?;
            total_bad_debt = total_bad_debt
                .checked_add(result.bad_debt.0)
                .ok_or(StressError::Arithmetic)?;
            uncovered_total = uncovered_total
                .checked_add(uncovered)
                .ok_or(StressError::Arithmetic)?;

            account.collateral = Amount(0);
            account.position = result.closed_position;
            step.liquidations += 1;
            total_liquidations += 1;
            if long {
                step.long_liquidations += 1;
                total_longs += 1;
            } else {
                step.short_liquidations += 1;
                total_shorts += 1;
            }
            step.penalty_to_insurance_usdd += result.penalty_to_insurance.0;
            step.bad_debt_usdd += result.bad_debt.0;
            step.uncovered_bad_debt_usdd += uncovered;
        }

        step.insurance_after_usdd = insurance;
        step.active_accounts_after = accounts
            .iter()
            .filter(|account| account.position.size != 0)
            .count()
            .try_into()
            .map_err(|_| StressError::Arithmetic)?;
        steps.push(step);
    }

    let active_collateral = accounts.iter().try_fold(0_i128, |total, account| {
        total
            .checked_add(account.collateral.0)
            .ok_or(StressError::Arithmetic)
    })?;
    let ledger_assets_after = active_collateral
        .checked_add(returned_collateral)
        .and_then(|value| value.checked_add(insurance))
        .and_then(|value| value.checked_add(maker_liquidity))
        .ok_or(StressError::Arithmetic)?;
    if ledger_assets_after != minted {
        return Err(StressError::LedgerInvariant);
    }

    Ok(StressReport {
        scenario: config.scenario.clone(),
        seed: config.seed,
        mock_usdd_asset_id_hex: hex_asset_id(),
        accounts: config.accounts,
        initial_margin_bps: config.risk.initial_margin_bps,
        maintenance_margin_bps: config.risk.maintenance_margin_bps,
        liquidation_fee_bps: config.risk.liquidation_fee_bps,
        minted_mock_usdd: minted,
        initially_admitted_accounts: config.accounts,
        total_liquidations,
        total_long_liquidations: total_longs,
        total_short_liquidations: total_shorts,
        total_penalties_usdd: total_penalties,
        total_bad_debt_usdd: total_bad_debt,
        uncovered_bad_debt_usdd: uncovered_total,
        final_insurance_usdd: insurance,
        final_maker_liquidity_usdd: maker_liquidity,
        returned_collateral_usdd: returned_collateral,
        active_collateral_usdd: active_collateral,
        ledger_assets_after_usdd: ledger_assets_after,
        ledger_conserved: true,
        solvent: uncovered_total == 0,
        steps,
    })
}

pub fn run_standard_suite(seed: u64, accounts: u32) -> Result<Vec<StressReport>, StressError> {
    [
        StressConfig::orderly(seed, accounts),
        StressConfig::crash(seed ^ 0x0043_5241_5348, accounts),
        StressConfig::short_squeeze(seed ^ 0x0053_5155_4545_5a45, accounts),
        StressConfig::whipsaw(seed ^ 0x0057_4849_5053_4157, accounts),
    ]
    .iter()
    .map(run_stress)
    .collect()
}

fn scaled_price(initial_price_usdd: u64, level_bps: u32) -> Result<Price, StressError> {
    let value = u128::from(initial_price_usdd)
        .checked_mul(u128::from(PRICE_SCALE))
        .and_then(|value| value.checked_mul(u128::from(level_bps)))
        .map(|value| value / 10_000)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(StressError::Arithmetic)?;
    Price::new(value).map_err(StressError::from)
}

fn hex_asset_id() -> String {
    MOCK_USDD_ASSET_ID
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_asset_is_explicit_and_never_zero() {
        assert_ne!(MOCK_USDD_ASSET_ID, [0; 32]);
        assert!(hex_asset_id().starts_with("4543582d4d4f434b2d555344442d5631"));
    }

    #[test]
    fn deterministic_orderly_run_is_solvent_and_conserved() {
        let config = StressConfig::orderly(7, 2_000);
        let first = run_stress(&config).unwrap();
        let second = run_stress(&config).unwrap();
        assert_eq!(first, second);
        assert!(first.ledger_conserved);
        assert!(first.solvent);
        assert!(first.total_liquidations > 0);
        assert_eq!(first.minted_mock_usdd, first.ledger_assets_after_usdd);
    }

    #[test]
    fn gap_crash_detects_uncovered_bad_debt() {
        let report = run_stress(&StressConfig::crash(9, 2_000)).unwrap();
        assert!(report.total_long_liquidations > 0);
        assert!(report.total_bad_debt_usdd > 0);
        assert!(report.uncovered_bad_debt_usdd > 0);
        assert!(!report.solvent);
        assert!(report.ledger_conserved);
    }

    #[test]
    fn short_squeeze_exercises_short_liquidations() {
        let report = run_stress(&StressConfig::short_squeeze(11, 2_000)).unwrap();
        assert!(report.total_short_liquidations > 0);
        assert!(report.ledger_conserved);
    }

    #[test]
    fn randomized_portfolios_preserve_the_mock_asset_ledger() {
        for seed in 0..64 {
            for report in run_standard_suite(seed, 250).unwrap() {
                assert!(report.ledger_conserved, "seed={seed} {}", report.scenario);
                assert_eq!(report.minted_mock_usdd, report.ledger_assets_after_usdd);
                assert!(report.initially_admitted_accounts == report.accounts);
                assert!(report.final_insurance_usdd >= 0);
                assert!(report.final_maker_liquidity_usdd >= 0);
            }
        }
    }

    #[test]
    fn risk_engine_rejects_one_unit_below_initial_margin_for_new_risk() {
        let params = RiskParams::default();
        let mark = scaled_price(100, 10_000).unwrap();
        let position = Position {
            size: 100,
            entry_price: mark.get(),
            last_funding_index: 0,
        };
        let required = required_margin(&position, mark, MarginKind::Initial, params).unwrap();
        assert_eq!(equity(required, &position, mark).unwrap(), required);
        assert!(equity(Amount(required.0 - 1), &position, mark).unwrap().0 < required.0);
    }
}
