//! Versioned ECX cash state for the ECX-settled linear contract.
//!
//! Outstanding fractions keep their original settlement denominator, including
//! across restart and later price changes. They are signed ECX claims, NOT USDD
//! and NOT spendable physical atoms. Entries may accumulate beyond one atom;
//! redemption/netting and fractional solvency must be implemented before live
//! withdrawals. This module deliberately neither rounds claims away nor grants
//! them to insurance. Outer transitions must bind account identity, network,
//! configuration, oracle, authorization, margin and actual vault conservation.

use crate::codec::{CanonicalEncode, Decoder};
use crate::ecx_collateral::{settle_ecx_transfer, EcxCollateralAtoms};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::incremental_state_v2::{
    IncrementalAccountingBoundsV2, Int256V2, TraderLeafV2, EXACT_ACCOUNTING_DENOMINATOR_V2,
    FUNDING_INDEX_DENOMINATOR_V2,
};
use crate::types::{MarketId, Price, PRICE_SCALE};
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxCashAccountV1 {
    balance: EcxCollateralAtoms,
    // Sorted unique denominators; zero claims are omitted. Numerators are not
    // reduced/repriced: all settlements at the same price share one entry.
    claims: Vec<(u128, Int256V2)>,
}

/// A pointwise result, not authority to liquidate or withdraw. Inconclusive
/// requires finer/exact evaluation; it must never be treated as sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcxMarginStatusV1 {
    Sufficient,
    Insufficient,
    Inconclusive,
}

/// Domain for an ECX account leaf. Asset and configuration must come from the
/// authenticated exchange configuration, never from an untrusted deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EcxAccountDomainV1 {
    pub chain_id: Hash32,
    pub market: MarketId,
    pub configuration_hash: Hash32,
    pub collateral_asset: Hash32,
}

/// Commit position, owner/nonce and complete ECX cash together. This is a new
/// leaf domain, not a replacement interpretation of the USDD trader leaf.
/// Membership, signatures and successor admission remain outer requirements.
pub fn ecx_account_commitment(
    domain: EcxAccountDomainV1,
    position: &TraderLeafV2,
    cash: &EcxCashAccountV1,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Hash32, ProtocolError> {
    domain.market.validate()?;
    if domain.chain_id == [0; 32]
        || domain.configuration_hash == [0; 32]
        || domain.collateral_asset == [0; 32]
        || position.collateral_atoms != 0
        || position.cash_residual_numerator != 0
    {
        return Err(ProtocolError::InvalidBondState);
    }
    position.validate(bounds)?;
    cash.validate()?;
    if u128::from(cash.balance.0) > bounds.maximum_abs_trader_collateral_atoms {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(&domain.chain_id);
    domain.market.encode_to(&mut bytes);
    bytes.extend_from_slice(&domain.configuration_hash);
    bytes.extend_from_slice(&domain.collateral_asset);
    position.encode_to(&mut bytes);
    cash.encode_to(&mut bytes);
    Ok(tagged_hash("ECX/ecx-position-cash-leaf/v1", &bytes))
}

/// Canonical empty subtree of the new, undeployed ECX account tree. Height
/// zero is an absent leaf; height 256 is the completely empty account tree.
/// Opaque membership siblings alone do not establish ledger completeness.
pub fn ecx_empty_account_subtree_v1(height: u16) -> Result<Hash32, ProtocolError> {
    if height > 256 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut node = tagged_hash("ECX/ecx-account-empty-leaf/v1", &[1]);
    for level in 1..=height {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&level.to_be_bytes());
        bytes.extend_from_slice(&node);
        bytes.extend_from_slice(&node);
        node = tagged_hash("ECX/ecx-account-tree-node/v1", &bytes);
    }
    Ok(node)
}

/// Open the complete account ledger, not merely selected membership paths,
/// and compare its exact cash total with the enclosing transaction's vault.
/// The caller must authenticate `expected_root`, ECX asset and `vault_atoms`.
/// No solvency, withdrawal authorization or transaction inclusion is implied.
pub fn verify_ecx_complete_ledger_v1(
    expected_root: Hash32,
    domain: EcxAccountDomainV1,
    bounds: IncrementalAccountingBoundsV2,
    accounts: &[(&TraderLeafV2, &EcxCashAccountV1)],
    vault_atoms: u64,
) -> Result<(), ProtocolError> {
    let mut leaves = Vec::with_capacity(accounts.len());
    let mut cash = Vec::with_capacity(accounts.len());
    for &(position, balance) in accounts {
        leaves.push((position.key(), ecx_account_commitment(domain, position, balance, bounds)?));
        cash.push(balance.clone());
    }
    leaves.sort_unstable_by_key(|entry| entry.0);
    if leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    // Compute each empty height once. Rebuilding it for every absent branch
    // made sparse-ledger verification unnecessarily quadratic in tree depth.
    // Keep the public single-height derivation independent for comparison.
    let mut empty = Vec::with_capacity(257);
    empty.push(tagged_hash("ECX/ecx-account-empty-leaf/v1", &[1]));
    for height in 1u16..=256 {
        let previous = empty[usize::from(height - 1)];
        let mut bytes = [0u8; 67];
        bytes[0] = 1;
        bytes[1..3].copy_from_slice(&height.to_be_bytes());
        bytes[3..35].copy_from_slice(&previous);
        bytes[35..].copy_from_slice(&previous);
        empty.push(tagged_hash("ECX/ecx-account-tree-node/v1", &bytes));
    }
    fn root(entries: &[(Hash32, Hash32)], depth: usize, empty: &[Hash32]) -> Result<Hash32, ProtocolError> {
        if entries.is_empty() {
            return Ok(empty[256 - depth]);
        }
        if depth == 256 { return Ok(entries[0].1); }
        let split = entries.partition_point(|entry| entry.0[depth / 8] & (1 << (7 - depth % 8)) == 0);
        let left = root(&entries[..split], depth + 1, empty)?;
        let right = root(&entries[split..], depth + 1, empty)?;
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((256 - depth) as u16).to_be_bytes());
        bytes.extend_from_slice(&left);
        bytes.extend_from_slice(&right);
        Ok(tagged_hash("ECX/ecx-account-tree-node/v1", &bytes))
    }
    if root(&leaves, 0, &empty)? != expected_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    verify_ecx_cash_conservation(&cash, vault_atoms)
}

/// Derive a present ECX account's sparse root from exactly 256 bottom-up
/// siblings. The owner key selects the path, most-significant bit at the root.
/// This tree has no USDD accounting aggregates. Vault conservation must be
/// established separately, not inferred from this membership hash.
pub fn ecx_account_root(
    domain: EcxAccountDomainV1,
    position: &TraderLeafV2,
    cash: &EcxCashAccountV1,
    bounds: IncrementalAccountingBoundsV2,
    siblings: &[Hash32],
) -> Result<Hash32, ProtocolError> {
    if siblings.len() != 256 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut node = ecx_account_commitment(domain, position, cash, bounds)?;
    let key = position.key();
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = 255 - height;
        let right = (key[bit / 8] >> (7 - bit % 8)) & 1 != 0;
        let mut bytes = Vec::with_capacity(67);
        bytes.push(1);
        bytes.extend_from_slice(&((height + 1) as u16).to_be_bytes());
        let (left, right) = if right {
            (sibling, &node)
        } else {
            (&node, sibling)
        };
        bytes.extend_from_slice(left);
        bytes.extend_from_slice(right);
        node = tagged_hash("ECX/ecx-account-tree-node/v1", &bytes);
    }
    Ok(node)
}

/// Verify membership in the supplied trusted source root and replace that same
/// owner's leaf. Does not authorize the economic mutation, increment a nonce,
/// or admit a new account. A successor must check those rules and commit all
/// linked trader/clearing updates atomically. Sequential updates require paths
/// against each intermediate root; stale paths are not reusable.
pub fn replace_ecx_account_leaf(
    source_root: Hash32,
    domain: EcxAccountDomainV1,
    old_position: &TraderLeafV2,
    old_cash: &EcxCashAccountV1,
    new_position: &TraderLeafV2,
    new_cash: &EcxCashAccountV1,
    bounds: IncrementalAccountingBoundsV2,
    siblings: &[Hash32],
) -> Result<Hash32, ProtocolError> {
    if old_position.key() != new_position.key()
        || ecx_account_root(domain, old_position, old_cash, bounds, siblings)? != source_root
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    ecx_account_root(domain, new_position, new_cash, bounds, siblings)
}

/// Credit an existing account under the committed ECX economic domain.
/// The enclosing deposit verifier MUST authenticate the recipient and exact
/// amount, consume a unique deposit outpoint, and increase physical backing
/// by the same amount. This helper is not standalone deposit authorization.
pub fn stage_ecx_account_top_up_v1(
    source_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    account: EcxAccountOpeningV1<'_>,
    atoms: u64,
) -> Result<(Hash32, EcxCashAccountV1), ProtocolError> {
    let domain = economics.account_domain()?;
    let next = account.cash.checked_top_up(atoms)?;
    let root = replace_ecx_account_leaf(
        source_root, domain, account.position, account.cash,
        account.position, &next, economics.bounds, account.siblings,
    )?;
    Ok((root, next))
}

impl EcxCashAccountV1 {
    /// Stage a whole-atom debit while preserving every fractional claim and
    /// requiring sufficient post-debit margin across the authenticated band.
    /// This is NOT withdrawal authorization: the outer transition must bind
    /// oracle/funding/configuration, signature/nonce, outstanding orders and
    /// the exact recipient output and reduction in physical vault backing.
    pub fn checked_margin_withdrawal(
        &self, atoms: u64, position: &TraderLeafV2, scale: u64,
        low: Price, high: Price, funding: i128, margin_bps: u32,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        self.validate()?;
        let mut next = self.clone();
        next.balance = next.balance.checked_withdraw(atoms)?;
        next.validate()?;
        if next.margin_over_interval(position, scale, low, high, funding,
            margin_bps, bounds)? != EcxMarginStatusV1::Sufficient {
            return Err(ProtocolError::InsufficientCollateral);
        }
        Ok(next)
    }

    /// Check post-debit margin with a nonnegative quote fee reserve. The
    /// hypothetical ECX liability uses the authenticated LOW settlement price,
    /// bounding fees paid anywhere in [low, high]. Never persist that liability:
    /// actual executions charge their exact fee only when they occur.
    /// This does not reserve position exposure from outstanding orders. The
    /// enclosing transition must check that separately and refresh the risk
    /// decision when the authenticated settlement-price interval changes.
    pub fn checked_fee_reserved_withdrawal(
        &self, atoms: u64, position: &TraderLeafV2, scale: u64,
        low: Price, high: Price, funding: i128, margin_bps: u32,
        bounds: IncrementalAccountingBoundsV2, quote_reserve: crate::types::Amount,
    ) -> Result<Self, ProtocolError> {
        if quote_reserve.0 < 0 { return Err(ProtocolError::InvalidBondState); }
        let next = self.checked_margin_withdrawal(
            atoms, position, scale, low, high, funding, margin_bps, bounds,
        )?;
        let mut projected = next.clone();
        let liability = Int256V2::from_i128(quote_reserve.0)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?.checked_neg()?;
        projected.add_claim(
            u128::from(low.get()) * u128::from(FUNDING_INDEX_DENOMINATOR_V2),
            liability,
        )?;
        if projected.margin_over_interval(position, scale, low, high, funding,
            margin_bps, bounds)? != EcxMarginStatusV1::Sufficient {
            return Err(ProtocolError::InsufficientCollateral);
        }
        Ok(next)
    }

    /// Stage a native-ECX top-up without erasing existing fractional claims.
    /// This arithmetic operation does not authenticate or consume a deposit.
    pub fn checked_top_up(&self, atoms: u64) -> Result<Self, ProtocolError> {
        self.validate()?;
        let mut next = self.clone();
        next.balance = next.balance.checked_deposit(atoms)?;
        next.validate()?;
        Ok(next)
    }
    /// The caller must establish provenance for the deposited native ECX.
    pub fn from_funded_balance(balance: EcxCollateralAtoms) -> Self {
        Self {
            balance,
            claims: Vec::new(),
        }
    }

    pub fn balance(&self) -> EcxCollateralAtoms {
        self.balance
    }

    pub fn outstanding_claims(&self) -> &[(u128, Int256V2)] {
        &self.claims
    }

    /// Exact minimum whole-atom credit that makes this cash account
    /// nonnegative. This is cash only, NOT open-position solvency or insurance
    /// authorization. Different denominators are netted without changing the
    /// persisted claims. Arbitrary-width intermediates avoid introducing a
    /// new rejection merely because the common denominator exceeds 256 bits.
    /// Enclosing transports must retain their authenticated input-size bounds.
    pub fn minimum_cash_cover_atoms(&self) -> Result<u64, ProtocolError> {
        use num_bigint::{BigUint, Sign};
        let (numerator, denominator) = self.exact_cash_fraction()?;
        if numerator.sign() != Sign::Minus {
            return Ok(0);
        }
        let whole = (numerator.magnitude() + &denominator - BigUint::from(1u8))
            / denominator;
        let digits = whole.to_u64_digits();
        match digits.as_slice() {
            [] => Ok(0),
            [atoms] => Ok(*atoms),
            _ => Err(ProtocolError::ArithmeticOverflow),
        }
    }

    // Shared exact projection; never replaces the stored denominator buckets.
    fn exact_cash_fraction(&self) -> Result<(num_bigint::BigInt, num_bigint::BigUint), ProtocolError> {
        use num_bigint::{BigInt, BigUint, Sign};
        self.validate()?;
        let mut numerator = BigInt::from(self.balance.0);
        let mut denominator = BigUint::from(1u8);
        for &(d, n) in &self.claims {
            let d = BigUint::from(d);
            let (mut gcd, mut remainder) = (denominator.clone(), d.clone());
            while remainder != BigUint::from(0u8) {
                let next = &gcd % &remainder;
                gcd = remainder;
                remainder = next;
            }
            let factor = &d / &gcd;
            let signed = BigInt::from_bytes_be(
                if n.is_negative() { Sign::Minus } else { Sign::Plus },
                &n.magnitude().to_be_bytes(),
            );
            numerator = numerator * BigInt::from(factor.clone())
                + signed * BigInt::from(&denominator / &gcd);
            denominator *= factor;
        }
        Ok((numerator, denominator))
    }

    /// Inclusive fixed-scale valuation bounds over ALL stored claims. This is
    /// a risk projection only: it does not round or replace account claims.
    /// A lower bound can establish sufficient collateral, never insolvency;
    /// an upper bound can establish insufficient collateral, never sufficiency.
    /// If a threshold lies between them, the consumer needs finer/exact
    /// evaluation rather than authorizing liquidation or withdrawal by rounding.
    pub fn valuation_bounds(&self, scale: u64) -> Result<(Int256V2, Int256V2), ProtocolError> {
        self.validate()?;
        if scale == 0 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let whole = Int256V2::from_u128(u128::from(self.balance.0)).checked_mul_u64(scale)?;
        let (mut lower, mut upper) = (whole, whole);
        for &(denominator, numerator) in &self.claims {
            let scaled = numerator.checked_mul_u64(scale)?;
            let price = u64::try_from(denominator / u128::from(FUNDING_INDEX_DENOMINATOR_V2))
                .map_err(|_| ProtocolError::ArithmeticOverflow)?;
            let (partial, r1) = scaled.div_rem_u64_toward_zero(FUNDING_INDEX_DENOMINATOR_V2)?;
            let (quotient, r2) = partial.div_rem_u64_toward_zero(price)?;
            lower = lower.checked_add(quotient)?;
            upper = upper.checked_add(quotient)?;
            if r1 != 0 || r2 != 0 {
                if numerator.is_negative() {
                    lower = lower.checked_sub(Int256V2::from_i128(1))?;
                } else {
                    upper = upper.checked_add(Int256V2::from_i128(1))?;
                }
            }
        }
        Ok((lower, upper))
    }

    /// Mark the complete cash state and linear position. Both results have the
    /// equity denominator documented by `ecx_trader_equity_numerator`.
    /// Caller must authenticate the mark, funding, bounds and account identity.
    pub fn equity_bounds(
        &self,
        position: &TraderLeafV2,
        scale: u64,
        mark: Price,
        funding: i128,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(Int256V2, Int256V2), ProtocolError> {
        let (lower, upper) = self.valuation_bounds(scale)?;
        let value = |cash| {
            crate::ecx_collateral::ecx_trader_equity_numerator(
                position, cash, scale, mark, funding, bounds,
            )
        };
        Ok((value(lower)?, value(upper)?))
    }

    /// Compare complete ECX equity against outward-rounded quote margin.
    /// The caller selects an authenticated initial/maintenance rate and mark.
    /// Straddling valuation bounds are resolved with exact rational arithmetic;
    /// equality is sufficient. A successful point check is never inconclusive.
    /// This is not an interval-risk check: ECX collateral can reverse the
    /// adverse endpoint relative to the USDD position-direction rule.
    pub fn margin_at_mark(
        &self,
        position: &TraderLeafV2,
        scale: u64,
        mark: Price,
        funding: i128,
        margin_bps: u32,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<EcxMarginStatusV1, ProtocolError> {
        if margin_bps == 0 || margin_bps > 10_000 {
            return Err(ProtocolError::InvalidRate);
        }
        let (lower, upper) = self.equity_bounds(position, scale, mark, funding, bounds)?;
        let notional = (u128::from(mark.get())
            * u128::from(position.position_size_atoms.unsigned_abs()))
        .checked_add(u128::from(PRICE_SCALE - 1))
        .ok_or(ProtocolError::ArithmeticOverflow)?
            / u128::from(PRICE_SCALE);
        let required_atoms = notional
            .checked_mul(u128::from(margin_bps))
            .and_then(|n| n.checked_add(9_999))
            .ok_or(ProtocolError::ArithmeticOverflow)?
            / 10_000;
        let required = Int256V2::from_u128(required_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_mul_u64(scale)?;
        Ok(if lower >= required {
            EcxMarginStatusV1::Sufficient
        } else if upper < required {
            EcxMarginStatusV1::Insufficient
        } else {
            // Fixed-scale bounds straddle the threshold. Compare exact
            // rationals rather than treating a lower bound as insolvency.
            use num_bigint::{BigInt, Sign};
            let (cash, denominator) = self.exact_cash_fraction()?;
            let position_equity = crate::incremental_state_v2::trader_equity_numerator_v2(
                position, mark.get(), funding, bounds)?;
            let position_equity = BigInt::from_bytes_be(
                if position_equity.is_negative() { Sign::Minus } else { Sign::Plus },
                &position_equity.magnitude().to_be_bytes());
            let denominator = BigInt::from(denominator);
            let equity = cash * BigInt::from(mark.get()) * BigInt::from(FUNDING_INDEX_DENOMINATOR_V2)
                + position_equity * &denominator;
            let required = BigInt::from(required_atoms)
                * BigInt::from(EXACT_ACCOUNTING_DENOMINATOR_V2) * denominator;
            if equity >= required { EcxMarginStatusV1::Sufficient }
            else { EcxMarginStatusV1::Insufficient }
        })
    }

    /// Sufficient proves margin throughout the closed integer-price interval.
    /// Equity minus unrounded margin is affine in price, including ECX cash
    /// exposure. The two nested ceilings add less than two quote atoms; bounding
    /// that error at both endpoints covers interior rounding jumps too.
    /// Inconclusive is not failure of solvency and requires tighter evaluation.
    pub fn margin_over_interval(
        &self,
        position: &TraderLeafV2,
        scale: u64,
        low: Price,
        high: Price,
        funding: i128,
        margin_bps: u32,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<EcxMarginStatusV1, ProtocolError> {
        if low > high {
            return Err(ProtocolError::InvalidBondState);
        }
        let first = self.margin_at_mark(position, scale, low, funding, margin_bps, bounds)?;
        let last = self.margin_at_mark(position, scale, high, funding, margin_bps, bounds)?;
        if first == EcxMarginStatusV1::Insufficient || last == EcxMarginStatusV1::Insufficient {
            return Ok(EcxMarginStatusV1::Insufficient);
        }
        if low == high {
            return Ok(first);
        }
        if position.position_size_atoms == 0 {
            return Ok(if first == EcxMarginStatusV1::Sufficient && last == first {
                first
            } else {
                EcxMarginStatusV1::Inconclusive
            });
        }
        let rounding = Int256V2::from_u128(2)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_mul_u64(scale)?;
        for mark in [low, high] {
            let (lower, _) = self.equity_bounds(position, scale, mark, funding, bounds)?;
            let ideal =
                Int256V2::from_u128(u128::from(position.position_size_atoms.unsigned_abs()))
                    .checked_mul_u64(mark.get())?
                    .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
                    .checked_mul_u64(scale)?
                    .checked_mul_u64(u64::from(margin_bps))?;
            let (mut required, remainder) = ideal.div_rem_u64_toward_zero(10_000)?;
            if remainder != 0 {
                required = required.checked_add(Int256V2::from_u128(1))?;
            }
            if lower < required.checked_add(rounding)? {
                return Ok(EcxMarginStatusV1::Inconclusive);
            }
        }
        Ok(EcxMarginStatusV1::Sufficient)
    }

    /// Prove a strict maintenance deficit at EVERY price in the closed band.
    /// Unlike `margin_over_interval`, one failing endpoint is not sufficient.
    /// For a non-singleton band, exact equity minus unrounded maintenance is
    /// affine in price. Strictly negative endpoints prove negativity throughout;
    /// outward rounding can only increase required margin. False means NOT
    /// PROVEN, not healthy: narrow rounding-only deficits may need refinement.
    /// This is arithmetic only, not oracle authentication or spend authority.
    pub fn proves_deficit_over_interval(
        &self, position: &TraderLeafV2, scale: u64, low: Price, high: Price,
        funding: i128, margin_bps: u32, bounds: IncrementalAccountingBoundsV2,
    ) -> Result<bool, ProtocolError> {
        if low > high || position.position_size_atoms == 0 {
            return Err(ProtocolError::InvalidBondState);
        }
        let first = self.margin_at_mark(position, scale, low, funding, margin_bps, bounds)?;
        let last = self.margin_at_mark(position, scale, high, funding, margin_bps, bounds)?;
        if first != EcxMarginStatusV1::Insufficient || last != EcxMarginStatusV1::Insufficient {
            return Ok(false);
        }
        if low == high { return Ok(true); }
        use num_bigint::{BigInt, Sign};
        let (cash, denominator) = self.exact_cash_fraction()?;
        let denominator = BigInt::from(denominator);
        for mark in [low, high] {
            let value = crate::incremental_state_v2::trader_equity_numerator_v2(
                position, mark.get(), funding, bounds)?;
            let value = BigInt::from_bytes_be(
                if value.is_negative() { Sign::Minus } else { Sign::Plus },
                &value.magnitude().to_be_bytes());
            let equity = &cash * BigInt::from(mark.get())
                * BigInt::from(FUNDING_INDEX_DENOMINATOR_V2) + value * &denominator;
            // Cross multiply both positive denominators; no fractional claim
            // or threshold is rounded and no account bytes are changed.
            let ideal = BigInt::from(position.position_size_atoms.unsigned_abs())
                * BigInt::from(mark.get()) * BigInt::from(margin_bps)
                * BigInt::from(EXACT_ACCOUNTING_DENOMINATOR_V2) * &denominator;
            if equity * BigInt::from(PRICE_SCALE) * BigInt::from(10_000u64) >= ideal {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        u32::try_from(self.claims.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let mut previous = 0;
        for &(denominator, numerator) in &self.claims {
            let scale = u128::from(FUNDING_INDEX_DENOMINATOR_V2);
            if denominator <= previous
                || denominator % scale != 0
                || denominator / scale > u128::from(u64::MAX)
                || numerator == Int256V2::ZERO
            {
                return Err(ProtocolError::NonCanonicalEncoding);
            }
            numerator.validate()?;
            previous = denominator;
        }
        Ok(())
    }

    fn add_claim(&mut self, denominator: u128, numerator: Int256V2) -> Result<(), ProtocolError> {
        if numerator == Int256V2::ZERO {
            return Ok(());
        }
        match self
            .claims
            .binary_search_by_key(&denominator, |entry| entry.0)
        {
            Ok(index) => {
                let sum = self.claims[index].1.checked_add(numerator)?;
                if sum == Int256V2::ZERO {
                    self.claims.remove(index);
                } else {
                    self.claims[index].1 = sum;
                }
            }
            Err(index) => self.claims.insert(index, (denominator, numerator)),
        }
        self.validate()
    }

    pub fn commitment(&self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash("ECX/ecx-cash-account/v1", self))
    }

    /// Reject noncanonical ordering, zero entries, negative zero, unsupported
    /// denominators, truncation and trailing bytes. No allocation from a count
    /// is performed until its exact required byte length is checked.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != 1 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let balance = EcxCollateralAtoms(decoder.u64()?);
        let count =
            usize::try_from(decoder.u32()?).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let length = count
            .checked_mul(49)
            .and_then(|n| n.checked_add(13))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if bytes.len() != length {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut claims = Vec::with_capacity(count);
        for _ in 0..count {
            let denominator = u128::from_be_bytes(decoder.take()?);
            let negative = match decoder.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ProtocolError::NonCanonicalEncoding),
            };
            let numerator = Int256V2::from_sign_and_magnitude(negative, decoder.take()?)?;
            claims.push((denominator, numerator));
        }
        decoder.finish()?;
        let account = Self { balance, claims };
        account.validate()?;
        Ok(account)
    }
}

impl CanonicalEncode for EcxCashAccountV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        // All constructors/updates validate the private representation.
        out.push(1);
        out.extend_from_slice(&self.balance.0.to_be_bytes());
        out.extend_from_slice(&(self.claims.len() as u32).to_be_bytes());
        for (denominator, numerator) in &self.claims {
            out.extend_from_slice(&denominator.to_be_bytes());
            numerator.encode_to(out);
        }
    }
}

/// Maximum quote debit across arbitrary positive-integer partial fills under
/// the existing per-fill, outward-rounded fee schedule. The caller must bind
/// the execution-price ceiling, remaining quantity and permitted fee role.
/// This is a reservation bound, never an actual charge or an ECX amount.
///
/// Splitting into one-atom fills attains the bound at the ceiling: nested
/// ceiling is subadditive, so any coarser partition costs no more. Rebates
/// reserve zero and cannot be used as collateral before they are received.
pub fn ecx_partial_fill_fee_reserve_quote_v1(
    execution_price_ceiling: Price,
    remaining: crate::types::Quantity,
    fee_bps: i32,
    signed_max_fee_bps: u32,
) -> Result<crate::types::Amount, ProtocolError> {
    if fee_bps.unsigned_abs() > 10_000
        || (fee_bps > 0 && fee_bps as u32 > signed_max_fee_bps)
    { return Err(ProtocolError::InvalidRate); }
    if fee_bps <= 0 { return Ok(crate::types::Amount(0)); }
    let one = crate::risk::trading_fee(execution_price_ceiling,
        crate::types::Quantity::new(1)?, fee_bps)?;
    Ok(crate::types::Amount(one.0.checked_mul(i128::from(remaining.get()))
        .ok_or(ProtocolError::ArithmeticOverflow)?))
}

/// Apply the existing quote-fee schedule, then convert its signed charge to
/// ECX at the settlement mark without rounding away fractional ECX claims.
/// Positive rates debit the trader; negative maker rates are funded rebates.
/// The caller must authenticate the rate, signed cap, mark and recipient and
/// atomically commit both states. This alone is not a matched execution.
pub fn settle_ecx_execution_fee(
    trader: &EcxCashAccountV1,
    recipient: &EcxCashAccountV1,
    execution_price: Price,
    quantity: crate::types::Quantity,
    fee_bps: i32,
    signed_max_fee_bps: u32,
    settlement_price: Price,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1), ProtocolError> {
    if fee_bps > 0 && fee_bps as u32 > signed_max_fee_bps {
        return Err(ProtocolError::InvalidRate);
    }
    let quote_fee = crate::risk::trading_fee(execution_price, quantity, fee_bps)?;
    let exact = Int256V2::from_i128(quote_fee.0)
        .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
        .checked_neg()?;
    settle_account_pnl(trader, recipient, exact, settlement_price)
}

/// Atomic fee-only update following an execution. Recipient's path must open
/// the intermediate root after updating the trader. Both positions/nonces are
/// preserved. Caller must pin recipient identity and bind the fill/rate to the
/// verified execution; this primitive is not standalone spending authority.
pub fn stage_ecx_account_fee(
    source_root: Hash32,
    domain: EcxAccountDomainV1,
    trader: EcxAccountOpeningV1<'_>,
    configured_recipient: crate::types::XOnlyKey,
    recipient: EcxAccountOpeningV1<'_>,
    execution_price: Price,
    quantity: crate::types::Quantity,
    fee_bps: i32,
    signed_max_fee_bps: u32,
    settlement_price: Price,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(Hash32, EcxCashAccountV1, EcxCashAccountV1), ProtocolError> {
    if recipient.position.trader != configured_recipient
        || trader.position.trader == configured_recipient
        || recipient.position.position_size_atoms != 0
        || recipient.position.signed_cost_basis_numerator != Int256V2::ZERO
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let (paid, received) = settle_ecx_execution_fee(
        trader.cash, recipient.cash, execution_price, quantity,
        fee_bps, signed_max_fee_bps, settlement_price,
    )?;
    let intermediate = replace_ecx_account_leaf(
        source_root, domain, trader.position, trader.cash,
        trader.position, &paid, bounds, trader.siblings,
    )?;
    let root = replace_ecx_account_leaf(
        intermediate, domain, recipient.position, recipient.cash,
        recipient.position, &received, bounds, recipient.siblings,
    )?;
    Ok((root, paid, received))
}

/// Return both complete cash states or neither. The consuming transaction must
/// atomically commit both, and prevent aliasing the same account as both roles.
pub fn settle_account_pnl(
    first: &EcxCashAccountV1,
    second: &EcxCashAccountV1,
    quote_pnl: Int256V2,
    price: Price,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1), ProtocolError> {
    first.validate()?;
    second.validate()?;
    Price::new(price.get())?;
    quote_pnl.validate()?;
    let denominator = u128::from(price.get()) * u128::from(FUNDING_INDEX_DENOMINATOR_V2);
    let mut a = first.clone();
    let mut b = second.clone();
    // Retain the entire new liability before payment: checking its whole
    // portion first would reject solvent offsets against existing claims.
    a.add_claim(denominator, quote_pnl)?;
    b.add_claim(denominator, quote_pnl.checked_neg()?)?;
    pay_matured_claims(&a, &b)
}

/// Stage realized cash loss and its minimum whole-atom insurance cover before
/// paying matured claims. All three inputs remain unchanged on every failure.
/// Fractions remain in their original trader/clearing buckets; insurance pays
/// physical atoms, never receives an unrecorded write-off or synthetic credit.
///
/// NOT liquidation authorization: the caller must establish a fully closed
/// eligible target, authenticated fill/funding/fees and distinct configured
/// trader/clearing/insurance identities, then commit all roots atomically.
/// Open-position risk, orders and permissionless liquidation admission remain
/// outer checks. Insurance cannot spend receivables as physical backing or
/// become cash-insolvent. No unrelated trader is debited.
pub fn settle_account_pnl_with_insurance(
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    insurance: &EcxCashAccountV1,
    quote_pnl: Int256V2,
    price: Price,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1, EcxCashAccountV1, u64), ProtocolError> {
    trader.validate()?;
    clearing.validate()?;
    insurance.validate()?;
    Price::new(price.get())?;
    quote_pnl.validate()?;
    let denominator = u128::from(price.get()) * u128::from(FUNDING_INDEX_DENOMINATOR_V2);
    let (mut next_trader, mut next_clearing, mut next_insurance) =
        (trader.clone(), clearing.clone(), insurance.clone());
    next_trader.add_claim(denominator, quote_pnl)?;
    next_clearing.add_claim(denominator, quote_pnl.checked_neg()?)?;
    let cover = next_trader.minimum_cash_cover_atoms()?;
    (next_insurance.balance, next_trader.balance) =
        settle_ecx_transfer(next_insurance.balance, next_trader.balance, cover)?;
    if next_insurance.minimum_cash_cover_atoms()? != 0 {
        return Err(ProtocolError::InsufficientCollateral);
    }
    let (next_trader, next_clearing) = pay_matured_claims(&next_trader, &next_clearing)?;
    Ok((next_trader, next_clearing, next_insurance, cover))
}

/// Pay the whole-atom portions of one trader's existing claims against its
/// authenticated clearing account. Opposing bucket payments are netted before
/// checking balances. Clearing may aggregate other traders: only the matching
/// liability adjustment is applied, never independent rounding of its buckets.
///
/// This preserves each original denominator and subatom remainder. It does not
/// net subatom fractions across different denominators, establish solvency, or
/// authorize withdrawals. The outer transition must authenticate the account
/// pair and commit both returned states atomically.
pub fn pay_matured_claims(
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1), ProtocolError> {
    let (mut a, mut b, net) = stage_matured_claims(trader, clearing)?;
    let amount = u64::try_from(net.try_to_i128()?.unsigned_abs())
        .map_err(|_| ProtocolError::ArithmeticOverflow)?;
    if net.is_negative() {
        (a.balance, b.balance) = settle_ecx_transfer(a.balance, b.balance, amount)?;
    } else {
        (b.balance, a.balance) = settle_ecx_transfer(b.balance, a.balance, amount)?;
    }
    Ok((a, b))
}

// Separate exact claim retirement from physical payment so a joined operation
// can validate final net balances without requiring fictitious intermediate
// liquidity. Positive net means the clearing account owes the first account.
fn stage_matured_claims(
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1, Int256V2), ProtocolError> {
    trader.validate()?;
    clearing.validate()?;
    let mut a = trader.clone();
    let mut b = clearing.clone();
    let mut net = Int256V2::ZERO;
    for &(denominator, numerator) in &trader.claims {
        let price = u64::try_from(denominator / u128::from(FUNDING_INDEX_DENOMINATOR_V2))
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let (scaled, _) = numerator.div_rem_u64_toward_zero(FUNDING_INDEX_DENOMINATOR_V2)?;
        let (whole, _) = scaled.div_rem_u64_toward_zero(price)?;
        let paid = whole.checked_mul_u128(denominator)?;
        a.add_claim(denominator, paid.checked_neg()?)?;
        b.add_claim(denominator, paid)?;
        net = net.checked_add(whole)?;
    }
    Ok((a, b, net))
}

/// Fee-inclusive cash leg of a full liquidation. The penalty credits insurance,
/// while all original-denominator cash claims settle through configured clearing.
/// Retire trader and insurance whole claims and pay cover in one atomic net
/// operation: a fee receivable alone is never counted as physical insurance.
/// `quote_penalty` is nonnegative and uses the same exact scale as `quote_pnl`.
/// This does NOT authorize liquidation or authenticate any account/price/rate.
pub fn settle_account_liquidation_cash(
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    insurance: &EcxCashAccountV1,
    quote_pnl: Int256V2,
    quote_penalty: Int256V2,
    price: Price,
) -> Result<(EcxCashAccountV1, EcxCashAccountV1, EcxCashAccountV1, u64), ProtocolError> {
    let (a, b, reserve, cover, _) = settle_liquidation_batch_cash(
        trader, clearing, insurance, quote_pnl, quote_penalty, price, &[])?;
    Ok((a, b, reserve, cover))
}

/// Atomic liquidation cash composition including maker P&L and signed fees.
/// Each maker tuple is (cash, exact quote P&L, exact quote fee, settlement price).
/// Positive fees credit insurance; negative fees are rebates. All whole-atom
/// payments are netted before liquidity checks, preserving original fractions.
/// The caller MUST authenticate distinct account identities, fill derivations,
/// configured rates and prices; this cash primitive provides no authorization.
pub fn settle_liquidation_batch_cash(
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    insurance: &EcxCashAccountV1,
    quote_pnl: Int256V2,
    quote_penalty: Int256V2,
    price: Price,
    makers: &[(&EcxCashAccountV1, Int256V2, Int256V2, Price)],
) -> Result<(EcxCashAccountV1, EcxCashAccountV1, EcxCashAccountV1, u64,
    Vec<EcxCashAccountV1>), ProtocolError> {
    trader.validate()?;
    clearing.validate()?;
    insurance.validate()?;
    quote_pnl.validate()?;
    quote_penalty.validate()?;
    Price::new(price.get())?;
    if quote_penalty.is_negative() {
        return Err(ProtocolError::InvalidRate);
    }
    let denominator = u128::from(price.get()) * u128::from(FUNDING_INDEX_DENOMINATOR_V2);
    let (mut a, mut b, mut reserve) = (trader.clone(), clearing.clone(), insurance.clone());
    a.add_claim(denominator, quote_pnl.checked_sub(quote_penalty)?)?;
    b.add_claim(denominator, quote_pnl.checked_neg()?)?;
    reserve.add_claim(denominator, quote_penalty)?;
    let mut staged_makers = Vec::with_capacity(makers.len());
    let mut maker_payments = Int256V2::ZERO;
    for &(cash, pnl, fee, settlement_price) in makers {
        cash.validate()?;
        pnl.validate()?;
        fee.validate()?;
        Price::new(settlement_price.get())?;
        let denominator = u128::from(settlement_price.get())
            * u128::from(FUNDING_INDEX_DENOMINATOR_V2);
        let mut maker = cash.clone();
        maker.add_claim(denominator, pnl.checked_sub(fee)?)?;
        b.add_claim(denominator, pnl.checked_neg()?)?;
        reserve.add_claim(denominator, fee)?;
        let (maker, next_clearing, payment) = stage_matured_claims(&maker, &b)?;
        b = next_clearing;
        maker_payments = maker_payments.checked_add(payment)?;
        staged_makers.push((maker, payment));
    }
    let cover = a.minimum_cash_cover_atoms()?;
    let (mut a, b, trader_payment) = stage_matured_claims(&a, &b)?;
    let (mut reserve, mut b, reserve_payment) = stage_matured_claims(&reserve, &b)?;
    let final_balance = |old: EcxCollateralAtoms, delta: Int256V2| {
        let value = Int256V2::from_u128(u128::from(old.0)).checked_add(delta)?;
        if value.is_negative() { return Err(ProtocolError::InsufficientCollateral); }
        let atoms = u64::try_from(value.try_to_i128()?)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        Ok(EcxCollateralAtoms(atoms))
    };
    let cover_exact = Int256V2::from_u128(u128::from(cover));
    a.balance = final_balance(a.balance, trader_payment.checked_add(cover_exact)?)?;
    reserve.balance = final_balance(reserve.balance, reserve_payment.checked_sub(cover_exact)?)?;
    b.balance = final_balance(b.balance, trader_payment.checked_add(reserve_payment)?
        .checked_add(maker_payments)?.checked_neg()?)?;
    let mut next_makers = Vec::with_capacity(staged_makers.len());
    for (mut maker, payment) in staged_makers {
        maker.balance = final_balance(maker.balance, payment)?;
        if maker.minimum_cash_cover_atoms()? != 0 {
            return Err(ProtocolError::InsufficientCollateral);
        }
        next_makers.push(maker);
    }
    if a.minimum_cash_cover_atoms()? != 0 || reserve.minimum_cash_cover_atoms()? != 0 {
        return Err(ProtocolError::InsufficientCollateral);
    }
    Ok((a, b, reserve, cover, next_makers))
}

/// Check the complete ECX cash ledger against physical vault atoms, without
/// converting ECX into USDD or counting fractional receivables as backing.
/// Include every trader, clearing and insurance account exactly once. The
/// caller must authenticate that complete set and the vault asset/amount.
/// This is conservation, not an account-solvency or withdrawal authorization.
/// Original-denominator liabilities must cancel bucket by bucket: settlement
/// never reprices them, even if different buckets happen to have equal value.
pub fn verify_ecx_cash_conservation(
    accounts: &[EcxCashAccountV1],
    vault_atoms: u64,
) -> Result<(), ProtocolError> {
    let mut atoms = 0u128;
    let mut claims = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
    for account in accounts {
        account.validate()?;
        atoms = atoms
            .checked_add(u128::from(account.balance.0))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        for &(denominator, numerator) in &account.claims {
            claims.add_claim(denominator, numerator)?;
        }
    }
    if atoms != u128::from(vault_atoms) || !claims.claims.is_empty() {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxAccountPositionSettlementV1 {
    pub position: TraderLeafV2,
    pub trader_cash: EcxCashAccountV1,
    pub clearing_cash: EcxCashAccountV1,
}

pub fn stage_account_trade(
    position: &TraderLeafV2,
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    delta: i64,
    fill_price: Price,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxAccountPositionSettlementV1, ProtocolError> {
    Price::new(fill_price.get())?;
    let mut next = position.clone();
    let liability =
        next.apply_trade_for_ecx_settlement(delta, fill_price.get(), funding, bounds)?;
    let (trader_cash, clearing_cash) =
        settle_account_pnl(trader, clearing, liability, settlement_price)?;
    Ok(EcxAccountPositionSettlementV1 {
        position: next,
        trader_cash,
        clearing_cash,
    })
}

/// Full-position close with exact P&L and lazy funding derived by the existing
/// position engine. This is staging, NOT liquidation authorization: the outer
/// transition must authenticate eligibility, prices, account identities, fees,
/// counterparty/order priority and commit all resulting roots atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxInsuredCloseV1 {
    pub settlement: EcxAccountPositionSettlementV1,
    pub insurance_cash: EcxCashAccountV1,
    pub insurance_cover_atoms: u64,
}

pub fn stage_account_insured_close(
    position: &TraderLeafV2,
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    insurance: &EcxCashAccountV1,
    fill_price: Price,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxInsuredCloseV1, ProtocolError> {
    stage_account_insured_close_with_penalty(position, trader, clearing, insurance,
        fill_price, settlement_price, funding, 0, bounds)
}

/// Derive the full-close penalty with the existing quote fee schedule. The
/// caller must pin `penalty_bps` to configuration, not to liquidator input.
/// Maker fills, maker fees, eligibility and atomic root updates remain required.
pub fn stage_account_insured_close_with_penalty(
    position: &TraderLeafV2,
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    insurance: &EcxCashAccountV1,
    fill_price: Price,
    settlement_price: Price,
    funding: i128,
    penalty_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxInsuredCloseV1, ProtocolError> {
    if penalty_bps > 10_000 { return Err(ProtocolError::InvalidRate); }
    if position.position_size_atoms == 0 {
        return Err(ProtocolError::InvalidQuantity);
    }
    let delta = position.position_size_atoms.checked_neg()
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let mut next = position.clone();
    let liability = next.apply_trade_for_ecx_settlement(delta, fill_price.get(), funding, bounds)?;
    if next.position_size_atoms != 0 || next.signed_cost_basis_numerator != Int256V2::ZERO {
        return Err(ProtocolError::InvalidStateSequence);
    }
    let fee = crate::risk::trading_fee(fill_price,
        crate::types::Quantity::new(position.position_size_atoms.unsigned_abs())?,
        penalty_bps as i32)?;
    let penalty = Int256V2::from_i128(fee.0).checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    let (trader_cash, clearing_cash, insurance_cash, insurance_cover_atoms) =
        settle_account_liquidation_cash(trader, clearing, insurance, liability, penalty, settlement_price)?;
    Ok(EcxInsuredCloseV1 {
        settlement: EcxAccountPositionSettlementV1 { position: next, trader_cash, clearing_cash },
        insurance_cash,
        insurance_cover_atoms,
    })
}

pub fn stage_account_funding(
    position: &TraderLeafV2,
    trader: &EcxCashAccountV1,
    clearing: &EcxCashAccountV1,
    price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxAccountPositionSettlementV1, ProtocolError> {
    let mut next = position.clone();
    let liability = next.settle_lazy_funding_for_ecx(funding, bounds)?;
    let (trader_cash, clearing_cash) = settle_account_pnl(trader, clearing, liability, price)?;
    Ok(EcxAccountPositionSettlementV1 {
        position: next,
        trader_cash,
        clearing_cash,
    })
}

/// An authenticated leaf opening. For a paired update, the clearing path must
/// open the intermediate root AFTER the trader update, not the source root.
pub struct EcxAccountOpeningV1<'a> {
    pub position: &'a TraderLeafV2,
    pub cash: &'a EcxCashAccountV1,
    pub siblings: &'a [Hash32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxTreeTradeResultV1 {
    pub root: Hash32,
    pub settlement: EcxAccountPositionSettlementV1,
}

/// Derive a trade's ECX payment and both tree updates, returning only the final
/// root. Failure of either opening/payment returns no partial transition.
/// The caller must authenticate source root, configured clearing identity,
/// prices/funding and order authorization, enforce nonce and risk rules, and
/// include the opposing position fill. This is not standalone trade admission.
pub fn stage_ecx_tree_trade(
    source_root: Hash32,
    domain: EcxAccountDomainV1,
    configured_clearing: crate::types::XOnlyKey,
    trader: EcxAccountOpeningV1<'_>,
    clearing: EcxAccountOpeningV1<'_>,
    delta: i64,
    fill_price: Price,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxTreeTradeResultV1, ProtocolError> {
    if clearing.position.trader != configured_clearing
        || trader.position.key() == clearing.position.key()
        || clearing.position.position_size_atoms != 0
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let settlement = stage_account_trade(
        trader.position,
        trader.cash,
        clearing.cash,
        delta,
        fill_price,
        settlement_price,
        funding,
        bounds,
    )?;
    let intermediate = replace_ecx_account_leaf(
        source_root,
        domain,
        trader.position,
        trader.cash,
        &settlement.position,
        &settlement.trader_cash,
        bounds,
        trader.siblings,
    )?;
    let root = replace_ecx_account_leaf(
        intermediate,
        domain,
        clearing.position,
        clearing.cash,
        clearing.position,
        &settlement.clearing_cash,
        bounds,
        clearing.siblings,
    )?;
    Ok(EcxTreeTradeResultV1 { root, settlement })
}

#[cfg(test)]
mod tests {
    /// Small-state reference for outstanding-order risk. Enumerate fill
    /// prefixes with the REAL realized-P&L/ECX conversion, not a net-position
    /// proxy. Finite test prices do not prove a production interval bound.
    #[test]
    fn outstanding_order_prefix_reference_preserves_cash_and_exposes_netting_risk() {
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let position = TraderLeafV2 {
            version: TraderLeafV2::VERSION, trader: crate::types::XOnlyKey([7;32]),
            account_nonce: 0, collateral_atoms: 0, cash_residual_numerator: 0,
            position_size_atoms: 0, signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0, selected_initial_margin_bps: 1000,
            order_generation: 0, salt: [4;32],
        };
        let start = EcxAccountPositionSettlementV1 {
            position, trader_cash: EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000)),
            clearing_cash: EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000_000)),
        };
        let original = start.clone();
        #[derive(Default)]
        struct Coverage { prefixes: usize, unsafe_prefixes: usize, flat_losses: usize, reductions: usize }
        fn visit(state: &EcxAccountPositionSettlementV1, remaining: [u8;2], reduce_sell: bool,
            bounds: IncrementalAccountingBoundsV2, vault: u64, coverage: &mut Coverage) {
            for side in 0..2 {
                for units in 1..=remaining[side] {
                    let delta = i64::from(units) * 50_000_000 * if side == 0 { 1 } else { -1 };
                    // Reduce-only eligibility depends on this prefix, not the
                    // initial flat account. A preceding buy can enable it.
                    if side == 1 && reduce_sell
                        && (state.position.position_size_atoms <= 0
                            || delta.unsigned_abs() > state.position.position_size_atoms as u64) {
                        continue;
                    }
                    for fill in [3_000_000_000, 30_000_000_000] {
                        for settlement in [3_000_000_000, 30_000_000_000] {
                            coverage.prefixes += 1;
                            let next = match stage_account_trade(&state.position, &state.trader_cash,
                                &state.clearing_cash, delta, Price::new(fill).unwrap(),
                                Price::new(settlement).unwrap(), 0, bounds) {
                                Ok(next) => next,
                                Err(ProtocolError::InsufficientCollateral) => {
                                    coverage.unsafe_prefixes += 1;
                                    if state.position.position_size_atoms + delta == 0 { coverage.flat_losses += 1; }
                                    continue;
                                }
                                Err(error) => panic!("unexpected reference execution failure: {error:?}"),
                            };
                            verify_ecx_cash_conservation(&[next.trader_cash.clone(), next.clearing_cash.clone()],
                                vault).unwrap();
                            if side == 1 && reduce_sell { coverage.reductions += 1; }
                            for mark in [3_000_000_000, 16_500_000_000, 30_000_000_000] {
                                if next.trader_cash.margin_at_mark(&next.position, 1_000_000,
                                    Price::new(mark).unwrap(), 0, 1000, bounds).unwrap()
                                    != EcxMarginStatusV1::Sufficient {
                                    coverage.unsafe_prefixes += 1;
                                    if next.position.position_size_atoms == 0 { coverage.flat_losses += 1; }
                                }
                            }
                            let mut rest = remaining;
                            rest[side] -= units;
                            visit(&next, rest, reduce_sell, bounds, vault, coverage);
                        }
                    }
                }
            }
        }
        // Initial flat position passes without an order-risk reserve, even
        // though equal outstanding buy/sell quantities can exhaust collateral.
        assert_eq!(start.trader_cash.margin_at_mark(&start.position, 1_000_000,
            Price::new(3_000_000_000).unwrap(), 0, 1000, bounds).unwrap(), EcxMarginStatusV1::Sufficient);
        for reduce_sell in [false, true] {
            let mut coverage = Coverage::default();
            visit(&start, [2,2], reduce_sell, bounds, 100_100_000_000, &mut coverage);
            assert!(coverage.prefixes > 100);
            assert!(coverage.unsafe_prefixes > 0);
            assert!(coverage.flat_losses > 0, "zero final quantity must not erase realized losses");
            if reduce_sell { assert!(coverage.reductions > 0); }
        }
        // Fund the production arithmetic bound, then run exactly the same
        // actual-settlement prefix exploration. No unsafe prefix is allowed;
        // neither endpoint settlement ordering nor net-flat losses are omitted.
        let reserve = crate::ecx_order_index_v1::ecx_order_prefix_reserve_bound_v1(
            &start.position, bounds, Price::new(3_000_000_000).unwrap(),
            Price::new(30_000_000_000).unwrap(), 0, 1000,
            &[(crate::order::Side::Buy, 100_000_000, 30_000_000_000),
              (crate::order::Side::Sell, 100_000_000, 3_000_000_000)],
            crate::types::Amount(0)).unwrap();
        assert!(reserve > Int256V2::from_u128(u128::from(start.trader_cash.balance().0)));
        let atoms = u64::try_from(reserve.try_to_i128().unwrap()).unwrap();
        let mut reserved = start.clone();
        reserved.trader_cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(atoms));
        for reduce_sell in [false, true] {
            let mut coverage = Coverage::default();
            visit(&reserved, [2,2], reduce_sell, bounds, 100_000_000_000 + atoms, &mut coverage);
            assert!(coverage.prefixes > 100);
            assert_eq!(coverage.unsafe_prefixes, 0, "reserved prefixes must retain margin");
            if reduce_sell { assert!(coverage.reductions > 0); }
        }
        // Identical quantities and fill prices, different authenticated ECX
        // settlement prices: the final flat position alone cannot distinguish
        // solvent from insolvent. These are hypothetical reference fills, not
        // an assertion that an under-margined live fill should be admitted.
        let opened = stage_account_trade(&start.position, &start.trader_cash, &start.clearing_cash,
            100_000_000, Price::new(30_000_000_000).unwrap(),
            Price::new(30_000_000_000).unwrap(), 0, bounds).unwrap();
        for settlement in [3_000_000_000, 30_000_000_000] {
            let closed = stage_account_trade(&opened.position, &opened.trader_cash,
                &opened.clearing_cash, -100_000_000, Price::new(3_000_000_000).unwrap(),
                Price::new(settlement).unwrap(), 0, bounds);
            if settlement == 3_000_000_000 {
                assert_eq!(closed, Err(ProtocolError::InsufficientCollateral));
                continue;
            }
            let closed = closed.unwrap();
            assert_eq!(closed.position.position_size_atoms, 0);
            assert_eq!(closed.trader_cash.margin_at_mark(&closed.position, 1_000_000,
                Price::new(3_000_000_000).unwrap(), 0, 1000, bounds).unwrap(), EcxMarginStatusV1::Sufficient);
        }
        assert_eq!(start, original, "risk exploration must never charge hypothetical losses");
    }

    #[test]
    fn atomic_fills_settle_funding_once_and_preserve_exact_cash() {
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let flat = TraderLeafV2 {
            version: TraderLeafV2::VERSION, trader: crate::types::XOnlyKey([7;32]),
            account_nonce: 0, collateral_atoms: 0, cash_residual_numerator: 0,
            position_size_atoms: 0, signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0, selected_initial_margin_bps: 1000,
            order_generation: 0, salt: [4;32],
        };
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000));
        for quantity in [-7, -1, 1, 7] {
            for funding in [-1_000_001, -1, 0, 1, 1_000_001] {
                for settlement in [3_000_000_001, 16_500_000_001, 30_000_000_001] {
                    let price = Price::new(settlement).unwrap();
                    let opened = stage_account_trade(&flat, &cash, &cash, quantity,
                        Price::new(30_000_000_001).unwrap(), price, 0, bounds).unwrap();
                    // Closing one atom tests fractional P&L and funding, not
                    // merely whole-position/whole-ECX arithmetic.
                    let delta = if quantity > 0 { -1 } else { 1 };
                    let combined = stage_account_trade(&opened.position, &opened.trader_cash,
                        &opened.clearing_cash, delta, Price::new(3_000_000_001).unwrap(),
                        price, funding, bounds).unwrap();
                    let funded = stage_account_funding(&opened.position, &opened.trader_cash,
                        &opened.clearing_cash, price, funding, bounds).unwrap();
                    let separate = stage_account_trade(&funded.position, &funded.trader_cash,
                        &funded.clearing_cash, delta, Price::new(3_000_000_001).unwrap(),
                        price, funding, bounds).unwrap();
                    assert_eq!(combined, separate, "funding must not be charged twice");
                    verify_ecx_cash_conservation(&[combined.trader_cash.clone(),
                        combined.clearing_cash.clone()], 200_000_000).unwrap();
                    let repeated = stage_account_funding(&combined.position, &combined.trader_cash,
                        &combined.clearing_cash, price, funding, bounds).unwrap();
                    assert_eq!(repeated, combined, "unchanged funding is idempotent");
                    assert_eq!(EcxCashAccountV1::from_bytes(&combined.trader_cash.canonical_bytes())
                        .unwrap(), combined.trader_cash);
                }
            }
        }
    }

    #[test]
    fn order_reserve_covers_atomic_prefixes_funding_and_execution_fees() {
        use crate::ecx_order_index_v1::ecx_order_prefix_reserve_bound_v1;
        use crate::order::Side;
        use crate::types::{Amount, Quantity};
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let flat = TraderLeafV2 {
            version: TraderLeafV2::VERSION, trader: crate::types::XOnlyKey([7;32]),
            account_nonce: 0, collateral_atoms: 0, cash_residual_numerator: 0,
            position_size_atoms: 0, signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0, selected_initial_margin_bps: 1000,
            order_generation: 0, salt: [4;32],
        };
        fn visit(state: &EcxAccountPositionSettlementV1, insurance: &EcxCashAccountV1,
            remaining: [u8;2], low: Price, high: Price, funding: i128,
            bounds: IncrementalAccountingBoundsV2, vault: u64, count: &mut usize) {
            for side in 0..2 {
                for quantity in 1..=remaining[side] {
                    for fill in [low, high] {
                        for settlement in [low, high] {
                            let delta = i64::from(quantity) * if side == 0 { 1 } else { -1 };
                            let mut next = stage_account_trade(&state.position, &state.trader_cash,
                                &state.clearing_cash, delta, fill, settlement, funding, bounds).unwrap();
                            let (paid, recipient) = settle_ecx_execution_fee(&next.trader_cash,
                                insurance, fill, Quantity::new(u64::from(quantity)).unwrap(),
                                if side == 0 { 5 } else { 2 }, 5, settlement).unwrap();
                            next.trader_cash = paid;
                            verify_ecx_cash_conservation(&[next.trader_cash.clone(),
                                next.clearing_cash.clone(), recipient.clone()], vault).unwrap();
                            for mark in [low, Price::new((low.get() + high.get()) / 2).unwrap(), high] {
                                assert_eq!(next.trader_cash.margin_at_mark(&next.position,
                                    1_000_000_000, mark, funding, 1000, bounds).unwrap(),
                                    EcxMarginStatusV1::Sufficient,
                                    "bound must cover atomic fee/funding prefix");
                            }
                            *count += 1;
                            let mut rest = remaining;
                            rest[side] -= quantity;
                            visit(&next, &recipient, rest, low, high, funding, bounds, vault, count);
                        }
                    }
                }
            }
        }
        let source_cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(1_000_000));
        for initial in [-3, 3] {
            for funding in [-1_000_001, 1_000_001] {
                for low in [3_000_000_001, 30_000_000_001] {
                    let low = Price::new(low).unwrap();
                    let high = Price::new(30_000_000_001).unwrap();
                    let opened = stage_account_trade(&flat, &source_cash, &source_cash,
                        initial, high, high, 0, bounds).unwrap();
                    let fee = ecx_partial_fill_fee_reserve_quote_v1(high,
                        Quantity::new(3).unwrap(), 5, 5).unwrap();
                    let reserve = ecx_order_prefix_reserve_bound_v1(&opened.position, bounds,
                        low, high, funding, 1000,
                        &[(Side::Buy, 2, high.get()), (Side::Sell, 1, low.get())], fee).unwrap();
                    let atoms = u64::try_from(reserve.try_to_i128().unwrap()).unwrap();
                    let start = EcxAccountPositionSettlementV1 {
                        position: opened.position,
                        trader_cash: EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(atoms)),
                        clearing_cash: source_cash.clone(),
                    };
                    let snapshot = start.clone();
                    let mut count = 0;
                    visit(&start, &source_cash, [2,1], low, high, funding, bounds,
                        atoms + 2_000_000, &mut count);
                    assert!(count > 100);
                    assert_eq!(start, snapshot);
                    assert!(ecx_order_prefix_reserve_bound_v1(&start.position, bounds,
                        high, Price::new(1).unwrap(), funding, 1000, &[], Amount(0)).is_err());
                    assert!(ecx_order_prefix_reserve_bound_v1(&start.position, bounds,
                        low, high, funding, 1000, &[], Amount(-1)).is_err());
                }
            }
        }
    }

    #[test]
    fn partial_fill_fee_reservation_covers_every_partition() {
        use super::ecx_partial_fill_fee_reserve_quote_v1;
        use crate::{risk::trading_fee, types::{Price, Quantity}};
        for price in [1, 99_999_999, 100_000_000, 100_000_001, 3_000_000_000] {
            let price = Price::new(price).unwrap();
            for rate in [1, 5, 999, 10_000] {
                for quantity in 1..=10u64 {
                    let reserve = ecx_partial_fill_fee_reserve_quote_v1(price,
                        Quantity::new(quantity).unwrap(), rate, 10_000).unwrap().0;
                    let mut maximum = 0;
                    // Every composition into positive integer fills, not just
                    // equal-sized partitions or a single full-size execution.
                    for cuts in 0..(1u64 << (quantity - 1)) {
                        let mut fill = 1;
                        let mut total = 0;
                        for boundary in 0..quantity {
                            if boundary == quantity - 1 || cuts & (1 << boundary) != 0 {
                                total += trading_fee(price, Quantity::new(fill).unwrap(), rate).unwrap().0;
                                fill = 1;
                            } else { fill += 1; }
                        }
                        assert!(total <= reserve);
                        maximum = maximum.max(total);
                    }
                    assert_eq!(maximum, reserve);
                }
            }
        }
        let price = Price::new(100_000_000).unwrap();
        let quantity = Quantity::new(10).unwrap();
        assert_eq!(trading_fee(price, quantity, 5).unwrap().0, 1);
        assert_eq!(ecx_partial_fill_fee_reserve_quote_v1(price, quantity, 5, 5).unwrap().0, 10);
        for rate in [-10_000, -5, 0] {
            assert_eq!(ecx_partial_fill_fee_reserve_quote_v1(price, quantity, rate, 0).unwrap().0, 0);
        }
        for (rate, cap) in [(5, 4), (10_001, 10_001), (-10_001, 0)] {
            assert!(ecx_partial_fill_fee_reserve_quote_v1(price, quantity, rate, cap).is_err());
        }
    }
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn native_top_up_preserves_fractional_claims_and_is_atomic() {
        let mut account = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(11));
        account.add_claim(3_000_000, Int256V2::from_i128(-1)).unwrap();
        let original = account.clone();
        let funded = account.checked_top_up(7).unwrap();
        assert_eq!(funded.balance(), EcxCollateralAtoms(18));
        assert_eq!(funded.outstanding_claims(), original.outstanding_claims());
        assert_eq!(account.checked_top_up(0).unwrap(), original);
        assert!(account.checked_top_up(u64::MAX).is_err());
        assert_eq!(account, original);
    }

    #[test]
    fn margin_distinguishes_exact_boundary_from_fractional_uncertainty() {
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let mut p = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: crate::types::XOnlyKey([7; 32]),
            account_nonce: 0,
            collateral_atoms: 0,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1000,
            order_generation: 0,
            salt: [4; 32],
        };
        let mark = Price::new(3_000_000_000).unwrap();
        let mut fractional = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        fractional
            .add_claim(3_000_000, Int256V2::from_i128(-1))
            .unwrap();
        let funded_fractional = fractional.checked_top_up(2).unwrap();
        let retained = funded_fractional.checked_margin_withdrawal(
            1, &p, 3_000_000, mark, mark, 0, 1000, bounds).unwrap();
        assert_eq!(retained.balance().0, 1);
        assert_eq!(retained.outstanding_claims(), funded_fractional.outstanding_claims());
        // A flat position with a fractional debt cannot empty its whole atoms.
        // Exact fallback rejects fractional debt even at low precision.
        for scale in [1, 3_000_000] {
            assert!(funded_fractional.checked_margin_withdrawal(
                2, &p, scale, mark, mark, 0, 1000, bounds).is_err());
        }
        assert_eq!(funded_fractional.balance().0, 2);
        assert_eq!(
            fractional
                .margin_at_mark(&p, 1, mark, 0, 1000, bounds)
                .unwrap(),
            EcxMarginStatusV1::Insufficient
        );
        assert_eq!(
            fractional
                .margin_at_mark(&p, 3_000_000, mark, 0, 1000, bounds)
                .unwrap(),
            EcxMarginStatusV1::Insufficient
        );
        // One ECX position at entry: ten percent margin is exactly 0.1 ECX.
        p.apply_trade_for_ecx_settlement(100_000_000, mark.get(), 0, bounds)
            .unwrap();
        let withdrawable = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10_000_001));
        assert_eq!(withdrawable.checked_margin_withdrawal(
            1, &p, 1, mark, mark, 0, 1000, bounds).unwrap().balance().0, 10_000_000);
        assert!(withdrawable.checked_margin_withdrawal(
            2, &p, 1, mark, mark, 0, 1000, bounds).is_err());
        assert!(withdrawable.checked_margin_withdrawal(
            u64::MAX, &p, 1, mark, mark, 0, 1000, bounds).is_err());
        assert_eq!(withdrawable.balance().0, 10_000_001);
        for (balance, expected) in [
            (9_999_999, EcxMarginStatusV1::Insufficient),
            (10_000_000, EcxMarginStatusV1::Sufficient),
            (10_000_001, EcxMarginStatusV1::Sufficient),
        ] {
            let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(balance));
            assert_eq!(
                cash.margin_at_mark(&p, 1, mark, 0, 1000, bounds).unwrap(),
                expected
            );
            assert!(cash.margin_at_mark(&p, 0, mark, 0, 1000, bounds).is_err());
            assert!(cash.margin_at_mark(&p, 1, mark, 0, 0, bounds).is_err());
            assert!(cash.margin_at_mark(&p, 1, mark, 0, 10_001, bounds).is_err());
        }
        // At entry, both directions need exactly 10,000,000 ECX atoms.
        // Two original denominator buckets sum to (5*a + 3*b)/15,000,000;
        // independently compare that signed numerator against zero.
        for size in [-100_000_000i64, 100_000_000] {
            let mut position = p.clone();
            position.position_size_atoms = 0;
            position.signed_cost_basis_numerator = Int256V2::ZERO;
            position.apply_trade_for_ecx_settlement(size, mark.get(), 0, bounds).unwrap();
            for a in -3i128..=3 {
                for b in -5i128..=5 {
                    let mut cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10_000_000));
                    cash.add_claim(3_000_000, Int256V2::from_i128(a)).unwrap();
                    cash.add_claim(5_000_000, Int256V2::from_i128(b)).unwrap();
                    let original = cash.clone();
                    let expected = if 5*a + 3*b >= 0 {
                        EcxMarginStatusV1::Sufficient
                    } else { EcxMarginStatusV1::Insufficient };
                    for scale in [1, 3_000_000, 15_000_000] {
                        assert_eq!(cash.margin_at_mark(&position, scale, mark, 0, 1000, bounds).unwrap(), expected);
                        for funding in [-1, 0, 1] {
                            let low = Price::new(mark.get() - 2).unwrap();
                            let high = Price::new(mark.get() + 2).unwrap();
                            let proven = cash.proves_deficit_over_interval(&position,
                                scale, low, high, funding, 1000, bounds).unwrap();
                            if proven {
                                for price in low.get()..=high.get() {
                                    assert_eq!(cash.margin_at_mark(&position, scale,
                                        Price::new(price).unwrap(), funding, 1000, bounds).unwrap(),
                                        EcxMarginStatusV1::Insufficient);
                                }
                            }
                        }
                    }
                    assert_eq!(cash, original);
                }
            }
        }
        // Exhaustively check every integer mark in each small test interval.
        // This covers long/short collateral slopes and interior ceiling jumps.
        let mut proven_deficits = 0;
        let mut mixed_bands = 0;
        for size in [-100_000_001i64, 100_000_001] {
            let mut position = p.clone();
            position.position_size_atoms = 0;
            position.signed_cost_basis_numerator = Int256V2::ZERO;
            position
                .apply_trade_for_ecx_settlement(size, 100, 0, bounds)
                .unwrap();
            for balance in [0, 10_000_000, 100_000_000, 200_000_000] {
                let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(balance));
                for rate in [1, 1000, 9999, 10_000] {
                    let result = cash
                        .margin_over_interval(
                            &position,
                            1,
                            Price::new(80).unwrap(),
                            Price::new(120).unwrap(),
                            0,
                            rate,
                            bounds,
                        )
                        .unwrap();
                    let mut all_safe = true;
                    let mut all_unsafe = true;
                    for price in 80..=120 {
                        let sufficient = cash
                            .margin_at_mark(
                                &position,
                                1,
                                Price::new(price).unwrap(),
                                0,
                                rate,
                                bounds,
                            )
                            .unwrap()
                            == EcxMarginStatusV1::Sufficient;
                        all_safe &= sufficient;
                        all_unsafe &= !sufficient;
                        assert_eq!(cash.proves_deficit_over_interval(&position, 1,
                            Price::new(price).unwrap(), Price::new(price).unwrap(),
                            0, rate, bounds).unwrap(), !sufficient);
                    }
                    let proves = cash.proves_deficit_over_interval(&position, 1,
                        Price::new(80).unwrap(), Price::new(120).unwrap(),
                        0, rate, bounds).unwrap();
                    if proves { assert!(all_unsafe); proven_deficits += 1; }
                    if !all_safe && !all_unsafe { assert!(!proves); mixed_bands += 1; }
                    if result == EcxMarginStatusV1::Sufficient {
                        assert!(all_safe);
                    }
                    if result == EcxMarginStatusV1::Insufficient {
                        assert!(!all_safe);
                    }
                }
            }
        }
        assert!(proven_deficits > 0);
        assert!(mixed_bands > 0);
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10_000_000));
        // Existing position margin alone exhausts this account. A positive
        // fee reserve must prevent withdrawal even if it rounds below one ECX
        // atom; reservation must not persist as an actual cash charge.
        let check = |cash: &EcxCashAccountV1, fee| cash.checked_fee_reserved_withdrawal(
            0, &p, 1_000_000, mark, mark, 0, 1000, bounds, crate::types::Amount(fee));
        assert_eq!(check(&cash, 0).unwrap(), cash);
        assert!(check(&cash, 1).is_err());
        assert!(check(&cash, -1).is_err());
        let funded = cash.checked_top_up(100_000_000).unwrap();
        assert_eq!(check(&funded, 1).unwrap(), funded);
        // For every settlement price in a small interval, the low-price
        // projection bounds the actual exact ECX fee debit.
        for settlement in 80..=120 {
            let mut actual = funded.clone();
            let mut projected = funded.clone();
            let liability = Int256V2::from_i128(-1)
                .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2).unwrap();
            actual.add_claim(u128::from(settlement as u64) * u128::from(FUNDING_INDEX_DENOMINATOR_V2), liability).unwrap();
            projected.add_claim(80 * u128::from(FUNDING_INDEX_DENOMINATOR_V2), liability).unwrap();
            assert!(projected.valuation_bounds(1_000_000).unwrap().0
                <= actual.valuation_bounds(1_000_000).unwrap().0);
        }
        assert_eq!(
            cash.margin_over_interval(&p, 1, mark, mark, 0, 1000, bounds)
                .unwrap(),
            EcxMarginStatusV1::Sufficient
        );
        assert!(cash
            .margin_over_interval(&p, 1, mark, Price::new(1).unwrap(), 0, 1000, bounds)
            .is_err());
    }

    #[test]
    fn execution_fees_preserve_ecx_fractions_and_fund_rebates() {
        let funded = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000));
        let price = Price::new(3_000_000_000).unwrap();
        let quantity = crate::types::Quantity::new(100_000_000).unwrap();
        let (trader, recipient) = settle_ecx_execution_fee(
            &funded, &funded, price, quantity, 5, 5, price,
        ).unwrap();
        assert_eq!(trader.balance(), EcxCollateralAtoms(99_950_000));
        assert_eq!(recipient.balance(), EcxCollateralAtoms(100_050_000));
        verify_ecx_cash_conservation(&[trader.clone(), recipient.clone()], 200_000_000).unwrap();
        let reversed = settle_ecx_execution_fee(
            &trader, &recipient, price, quantity, -5, 0, price,
        ).unwrap();
        assert_eq!(reversed, (funded.clone(), funded.clone()));
        assert!(settle_ecx_execution_fee(&funded, &funded, price, quantity, 5, 4, price).is_err());
        assert!(settle_ecx_execution_fee(&funded, &funded, price, quantity, -10_001, 0, price).is_err());
        let empty = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        assert!(settle_ecx_execution_fee(&funded, &empty, price, quantity, -5, 0, price).is_err());
        // Existing quote-fee rounding charges one quote atom; conversion is
        // exactly 1/30 ECX atom, retained rather than forgiven or rounded up.
        let tiny = crate::types::Quantity::new(1).unwrap();
        let (a, b) = settle_ecx_execution_fee(&funded, &funded, price, tiny, 5, 5, price).unwrap();
        assert_eq!(a.balance(), funded.balance());
        assert_eq!(a.claims.len(), 1);
        assert_eq!(a.claims[0], (3_000_000_000_000_000, Int256V2::from_i128(-100_000_000_000_000)));
        verify_ecx_cash_conservation(&[a.clone(), b.clone()], 200_000_000).unwrap();
        assert_eq!(settle_ecx_execution_fee(&a, &b, price, tiny, -5, 0, price).unwrap(), (funded.clone(), funded));
    }

    #[test]
    fn complete_ecx_cash_ledger_conserves_backing_after_settlement_and_restart() {
        let initial = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100));
        let (mut a, mut clearing) = (initial.clone(), initial.clone());
        let mut b = initial;
        for (amount, price) in [(8_000_001, 3), (-11_000_002, 7), (1, 11)] {
            (a, clearing) = settle_account_pnl(
                &a,
                &clearing,
                Int256V2::from_i128(amount),
                Price::new(price).unwrap(),
            )
            .unwrap();
            (b, clearing) = settle_account_pnl(
                &b,
                &clearing,
                Int256V2::from_i128(-amount / 2),
                Price::new(price).unwrap(),
            )
            .unwrap();
            let ledger: Vec<_> = [&a, &b, &clearing]
                .iter()
                .map(|account| EcxCashAccountV1::from_bytes(&account.canonical_bytes()).unwrap())
                .collect();
            verify_ecx_cash_conservation(&ledger, 300).unwrap();
            assert!(verify_ecx_cash_conservation(&ledger, 299).is_err());
            assert!(verify_ecx_cash_conservation(&ledger, 301).is_err());
            assert!(verify_ecx_cash_conservation(&ledger[..2], 200).is_err());
        }
    }

    #[test]
    fn ecx_backing_rejects_unmatched_or_repriced_claims() {
        let mut a = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        a.add_claim(3_000_000, Int256V2::from_i128(1)).unwrap();
        assert!(verify_ecx_cash_conservation(&[a.clone()], 0).is_err());
        let mut b = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        // Equal rational value is not permission to replace the original bucket.
        b.add_claim(6_000_000, Int256V2::from_i128(-2)).unwrap();
        assert!(verify_ecx_cash_conservation(&[a.clone(), b], 0).is_err());
        let mut opposite = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        opposite
            .add_claim(3_000_000, Int256V2::from_i128(-1))
            .unwrap();
        verify_ecx_cash_conservation(&[a, opposite], 0).unwrap();
        let maximum = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(u64::MAX));
        assert!(verify_ecx_cash_conservation(&[maximum.clone(), maximum], u64::MAX).is_err());
    }

    #[test]
    fn valuation_bounds_enclose_exact_mixed_price_claims_without_mutation() {
        for first in -12..=12 {
            for second in -12..=12 {
                let mut account = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(2));
                account
                    .add_claim(3_000_000, Int256V2::from_i128(first * 1_000_000))
                    .unwrap();
                account
                    .add_claim(7_000_000, Int256V2::from_i128(second * 1_000_000))
                    .unwrap();
                let before = account.canonical_bytes();
                for scale in [1u64, 21, 1_000_000] {
                    let (lo, hi) = account.valuation_bounds(scale).unwrap();
                    let exact = BigInt::from(42 + first * 7 + second * 3) * BigInt::from(scale);
                    assert!(BigInt::from(lo.try_to_i128().unwrap()) * 21 <= exact);
                    assert!(BigInt::from(hi.try_to_i128().unwrap()) * 21 >= exact);
                    if scale == 21 {
                        assert_eq!(lo, hi);
                    }
                }
                assert_eq!(account.canonical_bytes(), before);
                assert!(account.valuation_bounds(0).is_err());
            }
        }
    }

    #[test]
    fn new_loss_offsets_old_claim_before_checking_empty_cash() {
        let mut trader = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let mut clearing = trader.clone();
        trader
            .add_claim(3_000_000, Int256V2::from_i128(8_000_000))
            .unwrap();
        clearing
            .add_claim(3_000_000, Int256V2::from_i128(-8_000_000))
            .unwrap();
        // Neither account can pay two atoms separately, but the old receivable
        // and new loss cancel exactly. Payment order must not reject this.
        let (a, b) = settle_account_pnl(
            &trader,
            &clearing,
            Int256V2::from_i128(-8_000_000),
            Price::new(3).unwrap(),
        )
        .unwrap();
        assert_eq!(
            a,
            EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0))
        );
        assert_eq!(a, b);
        assert_eq!(trader.claims.len(), 1);
        assert_eq!(clearing.claims.len(), 1);
    }

    #[test]
    fn matured_claims_pay_ecx_preserve_remainders_and_do_not_round_clearing() {
        let mut trader = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let mut clearing = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10));
        trader
            .add_claim(3_000_000, Int256V2::from_i128(8_000_000))
            .unwrap();
        // Includes liabilities to other traders; must not be normalized alone.
        clearing
            .add_claim(3_000_000, Int256V2::from_i128(-20_000_000))
            .unwrap();
        let (a, b) = pay_matured_claims(&trader, &clearing).unwrap();
        assert_eq!(a.balance.0, 2);
        assert_eq!(b.balance.0, 8);
        assert_eq!(a.claims, vec![(3_000_000, Int256V2::from_i128(2_000_000))]);
        assert_eq!(
            b.claims,
            vec![(3_000_000, Int256V2::from_i128(-14_000_000))]
        );
        assert_eq!(pay_matured_claims(&a, &b).unwrap(), (a.clone(), b.clone()));
        assert_eq!(
            EcxCashAccountV1::from_bytes(&a.canonical_bytes()).unwrap(),
            a
        );
    }

    #[test]
    fn matured_opposing_buckets_net_before_payment_and_failure_is_atomic() {
        let mut trader = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let clearing = trader.clone();
        trader
            .add_claim(3_000_000, Int256V2::from_i128(-8_000_000))
            .unwrap();
        trader
            .add_claim(7_000_000, Int256V2::from_i128(15_000_000))
            .unwrap();
        let (a, b) = pay_matured_claims(&trader, &clearing).unwrap();
        assert_eq!((a.balance.0, b.balance.0), (0, 0));
        assert_eq!(
            a.claims,
            vec![
                (3_000_000, Int256V2::from_i128(-2_000_000)),
                (7_000_000, Int256V2::from_i128(1_000_000))
            ]
        );
        let before = (trader.clone(), clearing.clone());
        trader
            .add_claim(7_000_000, Int256V2::from_i128(7_000_000))
            .unwrap();
        let failed_before = trader.clone();
        assert_eq!(
            pay_matured_claims(&trader, &clearing),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(trader, failed_before);
        assert_eq!(clearing, before.1);
    }

    #[test]
    fn successive_prices_and_restart_preserve_exact_cash_and_opposing_claims() {
        let initial = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100));
        let (mut a, mut b) = (initial.clone(), initial);
        let scale = i128::from(FUNDING_INDEX_DENOMINATOR_V2);
        let common = BigInt::from(21 * scale);
        let mut expected = BigInt::from(100) * &common;
        for (price, n) in [(3u64, 8 * scale), (7, -9 * scale), (3, 8 * scale), (7, 1)] {
            let before = a.commitment().unwrap();
            (a, b) = settle_account_pnl(&a, &b, Int256V2::from_i128(n), Price::new(price).unwrap())
                .unwrap();
            expected += BigInt::from(n) * (&common / BigInt::from(i128::from(price) * scale));
            let exact = |account: &EcxCashAccountV1| {
                account.claims.iter().fold(
                    BigInt::from(account.balance.0) * &common,
                    |sum, (d, n)| {
                        sum + BigInt::from(n.try_to_i128().unwrap()) * (&common / BigInt::from(*d))
                    },
                )
            };
            assert_eq!(exact(&a), expected);
            assert_eq!(exact(&a) + exact(&b), BigInt::from(200) * &common);
            assert_ne!(a.commitment().unwrap(), before);
            let restored = EcxCashAccountV1::from_bytes(&a.canonical_bytes()).unwrap();
            assert_eq!(restored, a);
            assert_eq!(restored.commitment().unwrap(), a.commitment().unwrap());
            a = restored;
            b = EcxCashAccountV1::from_bytes(&b.canonical_bytes()).unwrap();
        }
        // Matured atoms have been paid; exact smaller claims remain owed.
        assert!(a
            .claims
            .iter()
            .all(|(d, n)| n.magnitude() < Int256V2::from_u128(*d).magnitude()));
    }

    #[test]
    fn cancellations_have_one_encoding_and_invalid_encodings_reject() {
        let initial = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10));
        let price = Price::new(3).unwrap();
        let (a, b) = settle_account_pnl(&initial, &initial, Int256V2::from_i128(1), price).unwrap();
        let bytes = a.canonical_bytes();
        assert_eq!(bytes.len(), 62);
        assert_eq!(&bytes[..13], &[1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 1]);
        let (a, b) = settle_account_pnl(&a, &b, Int256V2::from_i128(-1), price).unwrap();
        assert_eq!(a, initial);
        assert_eq!(b, initial);
        for index in [0usize, 12, 29] {
            let mut altered = bytes.clone();
            altered[index] = 255;
            assert!(EcxCashAccountV1::from_bytes(&altered).is_err());
        }
        let mut zero = bytes.clone();
        zero[30..].fill(0);
        assert!(EcxCashAccountV1::from_bytes(&zero).is_err());
        let mut duplicate = bytes.clone();
        duplicate[12] = 2;
        duplicate.extend_from_slice(&bytes[13..]);
        assert!(EcxCashAccountV1::from_bytes(&duplicate).is_err());
        for length in 0..bytes.len() {
            assert!(EcxCashAccountV1::from_bytes(&bytes[..length]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(EcxCashAccountV1::from_bytes(&trailing).is_err());
    }

    #[test]
    fn exact_insurance_cover_nets_denominators_and_rounds_only_final_deficit() {
        for balance in 0..=3u64 {
            for first in -12..=12i128 {
                for second in -12..=12i128 {
                    let mut cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(balance));
                    cash.add_claim(3_000_000, Int256V2::from_i128(first * 1_000_000)).unwrap();
                    cash.add_claim(7_000_000, Int256V2::from_i128(second * 1_000_000)).unwrap();
                    let numerator = i128::from(balance) * 21 + first * 7 + second * 3;
                    let expected = if numerator < 0 { ((-numerator + 20) / 21) as u64 } else { 0 };
                    let before = cash.clone();
                    assert_eq!(cash.minimum_cash_cover_atoms().unwrap(), expected);
                    assert_eq!(cash, before);
                    assert_eq!(cash.checked_top_up(expected).unwrap().minimum_cash_cover_atoms().unwrap(), 0);
                    if expected != 0 {
                        assert_eq!(cash.checked_top_up(expected - 1).unwrap().minimum_cash_cover_atoms().unwrap(), 1);
                    }
                }
            }
        }
        // The LCM exceeds 256 bits, but the exact total remains tiny. Do not
        // reject or round each bucket up to a separate atom of insurance.
        let mut cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        for p in [1009u128, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
                  1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
                  1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
                  1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223] {
            cash.add_claim(p * 1_000_000, Int256V2::from_i128(-(p as i128))).unwrap();
        }
        assert_eq!(cash.minimum_cash_cover_atoms().unwrap(), 1);
        let mut oversized = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        oversized.add_claim(1_000_000,
            Int256V2::from_u128((u128::from(u64::MAX) + 1) * 1_000_000).checked_neg().unwrap()).unwrap();
        assert_eq!(oversized.minimum_cash_cover_atoms(), Err(ProtocolError::ArithmeticOverflow));
    }

    #[test]
    fn insured_close_derives_full_position_loss_and_funding() {
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let flat = TraderLeafV2 {
            version: TraderLeafV2::VERSION, trader: crate::types::XOnlyKey([7;32]),
            account_nonce: 0, collateral_atoms: 0, cash_residual_numerator: 0,
            position_size_atoms: 0, signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0, selected_initial_margin_bps: 1000,
            order_generation: 0, salt: [4;32],
        };
        let empty = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let reserve = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10_000_000));
        for size in [-1_000_000, 1_000_000] {
            let mut opened = flat.clone();
            assert_eq!(opened.apply_trade_for_ecx_settlement(size, 30, 0, bounds).unwrap(), Int256V2::ZERO);
            for funding in [-2, 0, 2] {
                let fill = Price::new(if size > 0 { 20 } else { 40 }).unwrap();
                let price = Price::new(3).unwrap();
                let original = opened.clone();
                let mut expected_position = opened.clone();
                let quote = expected_position.apply_trade_for_ecx_settlement(-size, fill.get(), funding, bounds).unwrap();
                // Independent linear-contract reference: full close realizes
                // quantity * price change, scaled to exact quote units, less
                // signed quantity * accrued funding. Do not only compare two
                // invocations of the same engine.
                let reference_quote = i128::from(size)
                    * (i128::from(fill.get()) - 30)
                    * i128::from(FUNDING_INDEX_DENOMINATOR_V2)
                    - i128::from(size) * funding;
                assert_eq!(quote, Int256V2::from_i128(reference_quote));
                let expected = settle_account_pnl_with_insurance(&empty, &empty, &reserve, quote, price).unwrap();
                let actual = stage_account_insured_close(&opened, &empty, &empty, &reserve, fill, price, funding, bounds).unwrap();
                assert_eq!(actual.settlement.position, expected_position);
                assert_eq!((actual.settlement.trader_cash.clone(), actual.settlement.clearing_cash.clone(),
                    actual.insurance_cash.clone(), actual.insurance_cover_atoms), expected);
                assert!(actual.insurance_cover_atoms > 0);
                let denominator = i128::from(price.get()) * i128::from(FUNDING_INDEX_DENOMINATOR_V2);
                assert_eq!(actual.insurance_cover_atoms,
                    u64::try_from((-reference_quote + denominator - 1) / denominator).unwrap());
                for penalty_bps in [1u32, 100, 10_000] {
                    let notional = (u128::from(fill.get()) * u128::from(size.unsigned_abs())
                        + u128::from(PRICE_SCALE) - 1) / u128::from(PRICE_SCALE);
                    let fee = (notional * u128::from(penalty_bps) + 9_999) / 10_000;
                    let exact_fee = i128::try_from(fee).unwrap() * i128::from(EXACT_ACCOUNTING_DENOMINATOR_V2);
                    let charged = stage_account_insured_close_with_penalty(&opened, &empty, &empty,
                        &reserve, fill, price, funding, penalty_bps, bounds).unwrap();
                    assert_eq!(charged.settlement.position, expected_position);
                    assert_eq!(charged.insurance_cover_atoms,
                        u64::try_from((-reference_quote + exact_fee + denominator - 1) / denominator).unwrap());
                    assert_eq!(charged.insurance_cash.balance().0,
                        10_000_000 + u64::try_from(exact_fee / denominator).unwrap() - charged.insurance_cover_atoms);
                    verify_ecx_cash_conservation(&[charged.settlement.trader_cash,
                        charged.settlement.clearing_cash, charged.insurance_cash], 10_000_000).unwrap();
                }
                assert_eq!(stage_account_insured_close(&actual.settlement.position,
                    &actual.settlement.trader_cash, &actual.settlement.clearing_cash,
                    &actual.insurance_cash, fill, price, funding, bounds), Err(ProtocolError::InvalidQuantity));
                verify_ecx_cash_conservation(&[actual.settlement.trader_cash, actual.settlement.clearing_cash,
                    actual.insurance_cash], 10_000_000).unwrap();
                assert_eq!(stage_account_insured_close(&opened, &empty, &empty, &empty, fill, price, funding, bounds),
                    Err(ProtocolError::InsufficientCollateral));
                assert_eq!(opened, original);
            }
        }
        assert_eq!(stage_account_insured_close(&flat, &empty, &empty, &reserve,
            Price::new(30).unwrap(), Price::new(30).unwrap(), 0, bounds), Err(ProtocolError::InvalidQuantity));
    }

    #[test]
    fn insurance_settlement_covers_exact_loss_and_rejects_underfunding_atomically() {
        let trader = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(2));
        let clearing = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let insurance = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(3));
        let price = Price::new(3).unwrap();
        let loss = Int256V2::from_i128(-10_000_000);
        let originals = (trader.clone(), clearing.clone(), insurance.clone());
        let (after, cleared, reserve, cover) =
            settle_account_pnl_with_insurance(&trader, &clearing, &insurance, loss, price).unwrap();
        assert_eq!(cover, 2);
        assert_eq!((after.balance().0, cleared.balance().0, reserve.balance().0), (1, 3, 1));
        assert_eq!(after.outstanding_claims(), &[(3_000_000, Int256V2::from_i128(-1_000_000))]);
        assert_eq!(after.minimum_cash_cover_atoms().unwrap(), 0);
        verify_ecx_cash_conservation(&[after.clone(), cleared.clone(), reserve.clone()], 5).unwrap();
        assert_eq!(settle_account_pnl_with_insurance(&after, &cleared, &reserve, Int256V2::ZERO, price).unwrap(),
                   (after, cleared, reserve, 0));
        assert_eq!((trader.clone(), clearing.clone(), insurance.clone()), originals);
        for balance in [0, 1] {
            let poor = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(balance));
            let snapshot = (trader.clone(), clearing.clone(), poor.clone());
            assert_eq!(settle_account_pnl_with_insurance(&trader, &clearing, &poor, loss, price),
                       Err(ProtocolError::InsufficientCollateral));
            assert_eq!((trader.clone(), clearing.clone(), poor), snapshot);
        }
        // A physical balance is not wholly available if insurance itself owes
        // a retained fraction. Do not cover the target by bankrupting reserve.
        let mut encumbered = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(2));
        encumbered.add_claim(7_000_000, Int256V2::from_i128(-1)).unwrap();
        let snapshot = encumbered.clone();
        assert_eq!(settle_account_pnl_with_insurance(&trader, &clearing, &encumbered, loss, price),
                   Err(ProtocolError::InsufficientCollateral));
        assert_eq!(encumbered, snapshot);
    }

    #[test]
    fn liquidation_penalty_and_cover_settle_atomically_through_clearing() {
        let price = Price::new(1).unwrap();
        // Independent integer cash-flow reference, including profits, fees
        // exceeding initial reserve, and insufficient net insurance.
        for cash in 0u64..=3 {
            for insurance in 0u64..=3 {
                for pnl in -4i128..=4 {
                    for fee in 0i128..=3 {
                        let a = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(cash));
                        let b = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(4));
                        let reserve = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(insurance));
                        let original = (a.clone(), b.clone(), reserve.clone());
                        let cover = (fee - pnl - i128::from(cash)).max(0);
                        let remaining = i128::from(insurance) + fee - cover;
                        let result = settle_account_liquidation_cash(&a, &b, &reserve,
                            Int256V2::from_i128(pnl * 1_000_000),
                            Int256V2::from_i128(fee * 1_000_000), price);
                        if remaining < 0 {
                            assert_eq!(result, Err(ProtocolError::InsufficientCollateral));
                        } else {
                            let (next, clearing, insurance_after, paid_cover) = result.unwrap();
                            assert_eq!(paid_cover, cover as u64);
                            assert_eq!(next.balance().0, (i128::from(cash) + pnl - fee + cover) as u64);
                            assert_eq!(clearing.balance().0, (4 - pnl) as u64);
                            assert_eq!(insurance_after.balance().0, remaining as u64);
                            verify_ecx_cash_conservation(&[next, clearing, insurance_after], cash + 4 + insurance).unwrap();
                        }
                        assert_eq!((a, b, reserve), original);
                    }
                }
            }
        }
        let empty = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let reserve = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(4));
        let (a, b, r, cover) = settle_account_liquidation_cash(&empty, &empty, &reserve,
            Int256V2::from_i128(-10_000_000), Int256V2::from_i128(1_000_000), Price::new(3).unwrap()).unwrap();
        assert_eq!(cover, 4);
        assert_eq!((a.balance().0, b.balance().0, r.balance().0), (1, 3, 0));
        assert_eq!(a.outstanding_claims(), &[(3_000_000, Int256V2::from_i128(-2_000_000))]);
        assert_eq!(r.outstanding_claims(), &[(3_000_000, Int256V2::from_i128(1_000_000))]);
        verify_ecx_cash_conservation(&[a, b, r], 4).unwrap();
        // An unpaid fractional fee cannot finance physical cover.
        let one = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(1));
        assert_eq!(settle_account_liquidation_cash(&empty, &empty, &one,
            Int256V2::from_i128(-3_000_000), Int256V2::from_i128(1_000_000), Price::new(3).unwrap()),
            Err(ProtocolError::InsufficientCollateral));
        assert_eq!(settle_account_liquidation_cash(&empty, &empty, &reserve,
            Int256V2::ZERO, Int256V2::from_i128(-1), price), Err(ProtocolError::InvalidRate));
    }

    #[test]
    fn successful_whole_atom_settlement_does_not_erase_a_subatom_deficit() {
        let trader = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let clearing = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let (after, counterparty) = settle_account_pnl(
            &trader,
            &clearing,
            Int256V2::from_i128(-1),
            Price::new(3).unwrap(),
        )
        .unwrap();
        // No whole atom is payable, but a fully closed liquidation must still
        // account for this exact debt. Settlement success is not solvency.
        assert_eq!(after.balance(), EcxCollateralAtoms(0));
        assert_eq!(after.outstanding_claims(), &[(3_000_000, Int256V2::from_i128(-1))]);
        let (lower, upper) = after.valuation_bounds(3_000_000).unwrap();
        assert_eq!(lower, Int256V2::from_i128(-1));
        assert_eq!(upper, lower);
        verify_ecx_cash_conservation(&[after.clone(), counterparty.clone()], 0).unwrap();
        assert_eq!(pay_matured_claims(&after, &counterparty).unwrap(), (after, counterparty));
    }

    #[test]
    fn liquidation_makers_net_without_intermediate_clearing_liquidity() {
        let zero = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let funded = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(2));
        let price = Price::new(1).unwrap();
        let exact = |n: i128| Int256V2::from_i128(n * 1_000_000);
        // Maker loss finances target profit in the same atomic transition.
        // Clearing starts and ends empty; no artificial pre-funding is needed.
        let run = |maker: &EcxCashAccountV1, fee| settle_liquidation_batch_cash(
            &zero, &zero, &zero, exact(2), exact(0), price,
            &[(maker, exact(-2), exact(fee), price)]);
        let (target, clearing, reserve, cover, makers) = run(&funded, 0).unwrap();
        assert_eq!(target.balance().0, 2);
        assert_eq!(makers[0].balance().0, 0);
        assert_eq!(cover, 0);
        verify_ecx_cash_conservation(&[target, clearing, reserve, makers[0].clone()], 2).unwrap();
        // Neither an insolvent maker nor its unpaid fee can finance the batch.
        assert_eq!(run(&zero, 0), Err(ProtocolError::InsufficientCollateral));
        assert_eq!(run(&funded, 1), Err(ProtocolError::InsufficientCollateral));
        assert_eq!(zero.balance().0, 0);
        assert_eq!(funded.balance().0, 2);
    }

    #[test]
    fn overflow_or_insufficient_whole_cash_cannot_partially_update_accounts() {
        let mut a = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10));
        let mut max = [255; 32];
        max[0] = 127;
        a.add_claim(
            3_000_000,
            Int256V2::from_sign_and_magnitude(false, max).unwrap(),
        )
        .unwrap();
        let b = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10));
        let before = (a.clone(), b.clone());
        assert_eq!(
            settle_account_pnl(&a, &b, Int256V2::from_i128(1), Price::new(3).unwrap()),
            Err(ProtocolError::ArithmeticOverflow)
        );
        assert_eq!((a.clone(), b.clone()), before);
        let a = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(10));
        let before = (a.clone(), b.clone());
        assert_eq!(
            settle_account_pnl(
                &a,
                &b,
                Int256V2::from_i128(-33_000_000),
                Price::new(3).unwrap()
            ),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!((a, b), before);
    }
}
