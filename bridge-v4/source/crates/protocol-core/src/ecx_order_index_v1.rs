//! ECX-only remaining-order commitments, including admission sequence.
//! The enclosing successor must enforce price/time selection and risk.
use crate::ecx_cash_account_v1::{
    replace_ecx_account_leaf, EcxAccountDomainV1, EcxAccountOpeningV1,
};
use crate::ecx_order_v1::{
    stage_ecx_matched_accounts, EcxAdmittedOrderV2, EcxMatchedAccountUpdateV1, SignedEcxOrderV1,
};
use crate::hash::{tagged_hash, Hash32};
use crate::incremental_state_v2::{IncrementalAccountingBoundsV2, TraderLeafV2};
use crate::types::{Price, XOnlyKey};
use crate::ProtocolError;

/// Authenticate the complete competing book and account ledger before selecting
/// the best resting maker. Eligibility never depends on the requested fill size:
/// a smaller better order must be filled first, not skipped for a large fill.
/// Margin failures still reject the match; they do not authorize bypassing it.
pub fn verify_ecx_best_maker_v1(
    accounts_root: Hash32,
    orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    accounts: &[(&TraderLeafV2, &crate::ecx_cash_account_v1::EcxCashAccountV1)],
    vault_atoms: u64,
    orders: &[&EcxAdmittedOrderV2],
    maker: &EcxAdmittedOrderV2,
    taker: &EcxAdmittedOrderV2,
    height: u64,
) -> Result<(), ProtocolError> {
    use crate::order::{OrderFlags, Side, TimeInForce};
    let domain = economics.account_domain()?;
    crate::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        accounts_root, domain, economics.bounds, accounts, vault_atoms)?;
    verify_ecx_complete_order_book_v1(orders_root, domain, orders)?;
    let selected = maker.priority(domain)?;
    taker.commitment(domain)?;
    if !orders.contains(&maker) || !orders.contains(&taker)
        || maker.received_sequence >= taker.received_sequence
    {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    let mut best: Option<crate::incremental_state_v2::OrderPriorityV2> = None;
    for record in orders {
        let order = &record.signed.order;
        let trader = accounts.iter().find(|(p, _)| p.trader == order.trader)
            .ok_or(ProtocolError::InvalidMerkleProof)?.0;
        if record.generation > trader.order_generation || order.nonce >= trader.account_nonce {
            return Err(ProtocolError::InvalidBondState);
        }
        if record.generation != trader.order_generation || !order.is_live_at(height)
            || order.time_in_force != TimeInForce::GoodTilHeight
            || record.received_sequence >= taker.received_sequence
            || order.trader == taker.signed.order.trader
            || order.trader == economics.insurance_account
            || order.side == taker.signed.order.side
            || i64::from(economics.risk.maker_fee_bps) > i64::from(order.max_fee_bps)
        { continue; }
        if order.flags.contains(OrderFlags::REDUCE_ONLY)
            && (trader.position_size_atoms == 0
                || trader.position_size_atoms.signum() == order.side.sign())
        { continue; }
        let crosses = match taker.signed.order.side {
            Side::Buy => order.limit_price <= taker.signed.order.limit_price,
            Side::Sell => order.limit_price >= taker.signed.order.limit_price,
        };
        if !crosses { continue; }
        let candidate = record.priority(domain)?;
        if best.map(|head| candidate.compare_priority(head)).transpose()?
            .is_none_or(|ordering| ordering.is_lt())
        { best = Some(candidate); }
    }
    if best != Some(selected) { return Err(ProtocolError::PriceTimePriorityViolation); }
    Ok(())
}

/// ECX-domain liquidation head selection. Authenticate the complete current
/// ledger/book and target, then apply the existing one-sided liquidation band.
/// Returns the adverse band endpoint for risk checks, NOT the execution price.
/// This does not establish target deficit, fill solvency or successor roots.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_best_liquidation_maker_v1(
    accounts_root: Hash32,
    orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    accounts: &[(&TraderLeafV2, &crate::ecx_cash_account_v1::EcxCashAccountV1)],
    vault_atoms: u64,
    orders: &[&EcxAdmittedOrderV2],
    maker: &EcxAdmittedOrderV2,
    target: &TraderLeafV2,
    height: u64,
    liquidation_low: Price,
    liquidation_high: Price,
) -> Result<Price, ProtocolError> {
    let domain = economics.account_domain()?;
    crate::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        accounts_root, domain, economics.bounds, accounts, vault_atoms)?;
    verify_ecx_complete_order_book_v1(orders_root, domain, orders)?;
    let positions: Vec<_> = accounts.iter().map(|(position, _)| *position).collect();
    verify_liquidation_head(economics, &positions, orders, maker, target,
        height, liquidation_low, liquidation_high)
}

/// Private because these positions and records must come from authenticated
/// initial roots or the shared staging engine, never arbitrary witness state.
#[allow(clippy::too_many_arguments)]
fn verify_liquidation_head(
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    positions: &[&TraderLeafV2], orders: &[&EcxAdmittedOrderV2],
    maker: &EcxAdmittedOrderV2, target: &TraderLeafV2,
    height: u64, liquidation_low: Price, liquidation_high: Price,
) -> Result<Price, ProtocolError> {
    use crate::order::{OrderFlags, Side, TimeInForce};
    let domain = economics.account_domain()?;
    if !positions.contains(&target)
        || target.position_size_atoms == 0
        || target.trader == economics.insurance_account
        || target.trader == economics.clearing_account
        || liquidation_low.get() == 0 || liquidation_high < liquidation_low
    { return Err(ProtocolError::InvalidBondState); }
    let side = if target.position_size_atoms > 0 { Side::Buy } else { Side::Sell };
    let mut best: Option<crate::incremental_state_v2::OrderPriorityV2> = None;
    for record in orders {
        let order = &record.signed.order;
        let trader = positions.iter().find(|p| p.trader == order.trader)
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if record.generation > trader.order_generation || order.nonce >= trader.account_nonce {
            return Err(ProtocolError::InvalidBondState);
        }
        if record.generation != trader.order_generation || !order.is_live_at(height)
            || order.time_in_force != TimeInForce::GoodTilHeight
            || order.trader == target.trader || order.trader == economics.insurance_account
            || order.trader == economics.clearing_account
            || order.side != side
            || i64::from(economics.risk.maker_fee_bps) > i64::from(order.max_fee_bps)
        { continue; }
        if order.flags.contains(OrderFlags::REDUCE_ONLY)
            && (trader.position_size_atoms == 0
                || trader.position_size_atoms.signum() == order.side.sign())
        { continue; }
        let candidate = record.priority(domain)?;
        if best.map(|head| candidate.compare_priority(head)).transpose()?
            .is_none_or(|ordering| ordering.is_lt())
        { best = Some(candidate); }
    }
    let within_band = match side {
        Side::Buy => maker.signed.order.limit_price >= liquidation_low,
        Side::Sell => maker.signed.order.limit_price <= liquidation_high,
    };
    if !orders.contains(&maker) || best != Some(maker.priority(domain)?) || !within_band {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    Ok(if side == Side::Buy { liquidation_low } else { liquidation_high })
}

/// Authenticate the initial complete ledger/book, then check priority before
/// every derived fill. Untouched orders remain competitors; filled orders are
/// removed and partial orders retain priority. Positions, including reduce-only
/// eligibility, advance with each fill without intermediate cash settlement.
/// Deficit and authenticated oracle/funding context remain enclosing checks.
#[allow(clippy::too_many_arguments)]
pub fn stage_ecx_priority_liquidation_batch_v1(
    accounts_root: Hash32, orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    accounts: &[(&TraderLeafV2, &crate::ecx_cash_account_v1::EcxCashAccountV1)],
    vault_atoms: u64, source_orders: &[&EcxAdmittedOrderV2],
    target: &TraderLeafV2,
    makers: &[(&TraderLeafV2, &crate::ecx_cash_account_v1::EcxCashAccountV1)],
    orders: &[&EcxAdmittedOrderV2], fills: &[(Hash32, u64)],
    height: u64, settlement_price: Price, low: Price, high: Price, funding: i128,
) -> Result<crate::ecx_order_v1::EcxLiquidationBatchV1, ProtocolError> {
    let domain = economics.account_domain()?;
    crate::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        accounts_root, domain, economics.bounds, accounts, vault_atoms)?;
    verify_ecx_complete_order_book_v1(orders_root, domain, source_orders)?;
    if !accounts.iter().any(|(p, _)| *p == target)
        || makers.iter().any(|account| !accounts.contains(account))
        || orders.iter().any(|order| !source_orders.contains(order))
    { return Err(ProtocolError::InvalidMerkleProof); }
    let account = |key| accounts.iter().find(|(p, _)| p.trader == key)
        .copied().ok_or(ProtocolError::InvalidMerkleProof);
    let (_, target_cash) = account(target.trader)?;
    let (clearing, clearing_cash) = account(economics.clearing_account)?;
    let (insurance, insurance_cash) = account(economics.insurance_account)?;
    if clearing.position_size_atoms != 0 || insurance.position_size_atoms != 0 {
        return Err(ProtocolError::InvalidBondState);
    }
    crate::ecx_order_v1::stage_ecx_liquidation_batch_checked_v1(economics,
        target, target_cash, makers, orders, fills, clearing_cash, insurance_cash,
        height, settlement_price, funding, |maker, current_target, current_makers, remaining| {
            let positions: Vec<_> = accounts.iter().map(|(p, _)| {
                if p.trader == current_target.trader { current_target }
                else { current_makers.iter().find(|next| next.trader == p.trader).unwrap_or(p) }
            }).collect();
            let mut book = Vec::with_capacity(source_orders.len());
            for &original in source_orders {
                let id = original.signed.order_id()?;
                let current = match remaining.iter().find(|(key, _)| *key == id) {
                    Some((_, order)) => order.as_ref(),
                    None => Some(original),
                };
                if let Some(order) = current { book.push(order); }
            }
            verify_liquidation_head(economics, &positions, &book, maker,
                current_target, height, low, high).map(|_| ())
        })
}

pub fn order_leaf(
    domain: EcxAccountDomainV1,
    key: Hash32,
    order: Option<&EcxAdmittedOrderV2>,
) -> Result<Hash32, ProtocolError> {
    match order {
        None => Ok(tagged_hash("ECX/ecx-order-index-empty/v1", &[])),
        Some(order) => {
            if order.signed.order_id()? != key {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            let mut bytes = vec![1];
            bytes.extend_from_slice(&key);
            bytes.extend_from_slice(&order.commitment(domain)?);
            Ok(tagged_hash("ECX/ecx-order-index-leaf/v1", &bytes))
        }
    }
}

/// Exactly 256 bottom-up siblings; key bits are traversed MSB-first from root.
pub fn order_root(
    domain: EcxAccountDomainV1,
    key: Hash32,
    order: Option<&EcxAdmittedOrderV2>,
    siblings: &[Hash32],
) -> Result<Hash32, ProtocolError> {
    if siblings.len() != 256 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut current = order_leaf(domain, key, order)?;
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = 255 - height;
        let right = key[bit / 8] & (1 << (7 - bit % 8)) != 0;
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((height + 1) as u16).to_be_bytes());
        let (left, right) = if right {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        bytes.extend_from_slice(&left);
        bytes.extend_from_slice(&right);
        current = tagged_hash("ECX/ecx-order-index-node/v1", &bytes);
    }
    Ok(current)
}

/// Authenticate a complete book before aggregate risk/priority evaluation.
/// Membership paths alone cannot prove no outstanding order was omitted.
/// The expected root must come from committed state; this does not itself
/// enforce admission, expiry, account generations or reservation economics.
pub fn verify_ecx_complete_order_book_v1(
    expected_root: Hash32,
    domain: EcxAccountDomainV1,
    orders: &[&EcxAdmittedOrderV2],
) -> Result<(), ProtocolError> {
    let mut leaves = Vec::with_capacity(orders.len());
    for order in orders {
        let key = order.signed.order_id()?;
        leaves.push((key, order_leaf(domain, key, Some(order))?));
    }
    leaves.sort_unstable_by_key(|entry| entry.0);
    if leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    fn node(height: usize, left: Hash32, right: Hash32) -> Hash32 {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(height as u16).to_be_bytes());
        bytes.extend_from_slice(&left);
        bytes.extend_from_slice(&right);
        tagged_hash("ECX/ecx-order-index-node/v1", &bytes)
    }
    let mut empty = vec![tagged_hash("ECX/ecx-order-index-empty/v1", &[])];
    for height in 1..=256 {
        empty.push(node(height, empty[height - 1], empty[height - 1]));
    }
    fn root(entries: &[(Hash32, Hash32)], depth: usize, empty: &[Hash32]) -> Hash32 {
        if entries.is_empty() { return empty[256 - depth]; }
        if depth == 256 { return entries[0].1; }
        let split = entries.partition_point(|entry| entry.0[depth / 8] & (1 << (7 - depth % 8)) == 0);
        node(256 - depth, root(&entries[..split], depth + 1, empty),
            root(&entries[split..], depth + 1, empty))
    }
    if root(&leaves, 0, &empty) != expected_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxIndexedAdmissionV1 {
    pub accounts_root: Hash32,
    pub orders_root: Hash32,
    pub position: TraderLeafV2,
    pub order: EcxAdmittedOrderV2,
}

/// Authenticate the complete book before selecting a trader's outstanding
/// exposure. Callers must supply the committed root and authenticated account.
/// Future-valid orders remain reserved; expired and generation-cancelled orders
/// cannot execute. This establishes which remainders need risk evaluation,
/// not how much collateral they require and not withdrawal authorization.
pub fn ecx_outstanding_orders_v1<'a>(
    expected_root: Hash32,
    domain: EcxAccountDomainV1,
    orders: &[&'a EcxAdmittedOrderV2],
    trader: &TraderLeafV2,
    height: u64,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<&'a EcxAdmittedOrderV2>, ProtocolError> {
    trader.validate(bounds)?;
    verify_ecx_complete_order_book_v1(expected_root, domain, orders)?;
    let mut outstanding = Vec::new();
    for record in orders {
        let order = &record.signed.order;
        if order.trader != trader.trader { continue; }
        // Admission consumed the nonce. Never turn inconsistent authenticated
        // state into a smaller reservation by silently dropping the record.
        if order.nonce >= trader.account_nonce || record.generation > trader.order_generation {
            return Err(ProtocolError::InvalidBondState);
        }
        if record.generation == trader.order_generation && height <= order.expires_at_height {
            outstanding.push(*record);
        }
    }
    Ok(outstanding)
}

/// Quote-denominated fee reserve across the complete authenticated book.
/// This is NOT position margin or withdrawal authorization. Economics must be
/// pinned by the enclosing state. The sell-taker ceiling is the accounting
/// maximum enforced by apply_trade_for_ecx_settlement, not the oracle mark.
pub fn ecx_outstanding_fee_reserve_quote_v1(
    expected_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    orders: &[&EcxAdmittedOrderV2],
    trader: &TraderLeafV2,
    height: u64,
) -> Result<crate::types::Amount, ProtocolError> {
    use crate::ecx_cash_account_v1::ecx_partial_fill_fee_reserve_quote_v1;
    use crate::order::{OrderFlags, Side, TimeInForce};
    use crate::types::{Amount, Quantity};
    let domain = economics.account_domain()?;
    let records = ecx_outstanding_orders_v1(
        expected_root, domain, orders, trader, height, economics.bounds,
    )?;
    let mut total = 0i128;
    for record in records {
        let order = &record.signed.order;
        let reserve = |price: u64, rate: i32| -> Result<i128, ProtocolError> {
            // An unaffordable signed fee cap forbids this execution role;
            // negative maker rebates never become spendable collateral.
            if rate <= 0 || rate as u32 > order.max_fee_bps { return Ok(0); }
            Ok(ecx_partial_fill_fee_reserve_quote_v1(
                Price::new(price)?, Quantity::new(record.remaining)?,
                rate, order.max_fee_bps,
            )?.0)
        };
        let maker = if order.time_in_force == TimeInForce::GoodTilHeight
            && order.limit_price.get() <= economics.bounds.maximum_price_atoms {
            reserve(order.limit_price.get(), economics.risk.maker_fee_bps)?
        } else { 0 };
        // A sell whose minimum price exceeds the accounting ceiling cannot
        // execute as either role. Reserving its taker fee would unnecessarily
        // lock cash until cancellation, despite every such fill being invalid.
        let taker = if !order.flags.contains(OrderFlags::POST_ONLY)
            && (order.side == Side::Buy
                || order.limit_price.get() <= economics.bounds.maximum_price_atoms) {
            let ceiling = match order.side {
                Side::Buy => order.limit_price.get().min(economics.bounds.maximum_price_atoms),
                Side::Sell => economics.bounds.maximum_price_atoms,
            };
            reserve(ceiling, economics.risk.taker_fee_bps as i32)?
        } else { 0 };
        total = total.checked_add(maker.max(taker))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    Ok(Amount(total))
}

/// Conservative physical ECX required for any prefix of the authenticated
/// outstanding book at a FIXED funding index and settlement/mark interval.
/// This projection does not move cash, grant withdrawal authority, guarantee
/// clearing liquidity, or replace actual fill checks. Recompute on every
/// account/book/context change. Positive claims and hypothetical gains are
/// deliberately not relied on as immediately spendable physical collateral.
pub fn ecx_outstanding_order_reserve_atoms_v1(
    expected_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    orders: &[&EcxAdmittedOrderV2],
    trader: &TraderLeafV2,
    cash: &crate::ecx_cash_account_v1::EcxCashAccountV1,
    height: u64,
    low: Price,
    high: Price,
    funding: i128,
) -> Result<crate::incremental_state_v2::Int256V2, ProtocolError> {
    use crate::incremental_state_v2::{Int256V2, FUNDING_INDEX_DENOMINATOR_V2};
    use crate::order::{OrderFlags, Side, TimeInForce};
    let domain = economics.account_domain()?;
    crate::ecx_cash_account_v1::ecx_account_commitment(domain, trader, cash, economics.bounds)?;
    let records = ecx_outstanding_orders_v1(expected_root, domain, orders, trader, height, economics.bounds)?;
    let mut exposures = Vec::with_capacity(records.len());
    for record in records {
        let order = &record.signed.order;
        // Only adverse entry prices are needed: maximum for buys, minimum for
        // sells. Include reduce-only orders in full: eligibility can change.
        let mut entry = None;
        let eligible = |rate: i32| rate <= 0 || rate as u32 <= order.max_fee_bps;
        if order.time_in_force == TimeInForce::GoodTilHeight
            && order.limit_price.get() <= economics.bounds.maximum_price_atoms
            && eligible(economics.risk.maker_fee_bps) {
            entry = Some(order.limit_price.get());
        }
        if !order.flags.contains(OrderFlags::POST_ONLY)
            && eligible(economics.risk.taker_fee_bps as i32) {
            match order.side {
                Side::Buy => entry = Some(order.limit_price.get().min(economics.bounds.maximum_price_atoms)),
                Side::Sell if order.limit_price.get() <= economics.bounds.maximum_price_atoms =>
                    entry = Some(order.limit_price.get()),
                Side::Sell => {},
            }
        }
        if let Some(price) = entry { exposures.push((order.side, record.remaining, price)); }
    }
    let fees = ecx_outstanding_fee_reserve_quote_v1(expected_root, economics, orders, trader, height)?;
    let mut required = ecx_order_prefix_reserve_bound_v1(trader, economics.bounds,
        low, high, funding, trader.selected_initial_margin_bps.max(economics.risk.initial_margin_bps),
        &exposures, fees)?;
    // Existing negative buckets can mature during a later settlement. Reserve
    // each exactly rounded upward; never erase them or credit uncollected
    // positive fractions. Sequential ceilings equal ceil(n / (scale * price)).
    for &(denominator, numerator) in cash.outstanding_claims() {
        if numerator.is_negative() {
            let price = u64::try_from(denominator / u128::from(FUNDING_INDEX_DENOMINATOR_V2))
                .map_err(|_| ProtocolError::ArithmeticOverflow)?;
            required = required.checked_add(numerator.checked_neg()?
                .ceil_div_u64(FUNDING_INDEX_DENOMINATOR_V2)?.ceil_div_u64(price)?)?;
        }
    }
    debug_assert!(required >= Int256V2::ZERO);
    Ok(required)
}

/// Arithmetic kernel, not an authenticated book interface. Each tuple is
/// (side, remaining quantity, adverse executable entry price). The public
/// wrapper above derives these from the complete signed book.
///
/// Let L=min(mark low, all sell minima), H=max(mark high, all buy maxima).
/// A long's loss potential is max(0, basis-q*L*F); a short's is
/// max(0, |q|*H*F-|basis|). Closing at an eligible price consumes at least its
/// negative realized P&L from this potential; opening adds at most the entry's
/// positive potential. Proportional cost allocation truncates toward zero,
/// but q*L*F and q*H*F are integral, so this inequality also holds for atomic
/// partial closes. Thus initial plus all opening potentials bounds cumulative
/// negative realized P&L AND remaining negative unrealized P&L at every prefix.
/// Convert that loss, current funding debt, fees and maximal rounded margin at
/// LOW, without assuming profits settle first. Peak quantity includes either
/// side independently; the node's existing position bound caps valid prefixes.
pub(crate) fn ecx_order_prefix_reserve_bound_v1(
    trader: &TraderLeafV2,
    bounds: IncrementalAccountingBoundsV2,
    low: Price,
    high: Price,
    funding: i128,
    margin_bps: u32,
    exposures: &[(crate::order::Side, u64, u64)],
    fees: crate::types::Amount,
) -> Result<crate::incremental_state_v2::Int256V2, ProtocolError> {
    use crate::incremental_state_v2::{Int256V2, EXACT_ACCOUNTING_DENOMINATOR_V2, FUNDING_INDEX_DENOMINATOR_V2};
    use crate::order::Side;
    use crate::types::PRICE_SCALE;
    bounds.validate()?;
    trader.validate(bounds)?;
    if low > high || high.get() > bounds.maximum_price_atoms || margin_bps == 0
        || margin_bps > 10_000 || fees.0 < 0 {
        return Err(ProtocolError::InvalidBondState);
    }
    let (mut minimum_exit, mut maximum_exit) = (low.get(), high.get());
    let (mut buys, mut sells) = (0i128, 0i128);
    for &(side, quantity, entry) in exposures {
        if quantity == 0 || entry == 0 || entry > bounds.maximum_price_atoms {
            return Err(ProtocolError::InvalidBondState);
        }
        match side {
            Side::Buy => {
                buys = buys.checked_add(i128::from(quantity)).ok_or(ProtocolError::ArithmeticOverflow)?;
                maximum_exit = maximum_exit.max(entry);
            },
            Side::Sell => {
                sells = sells.checked_add(i128::from(quantity)).ok_or(ProtocolError::ArithmeticOverflow)?;
                minimum_exit = minimum_exit.min(entry);
            },
        }
    }
    let q = trader.position_size_atoms;
    let cost = trader.signed_cost_basis_numerator;
    let notional = |quantity: u64, price: u64| Int256V2::from_u128(u128::from(quantity))
        .checked_mul_u64(price)?.checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2);
    let mut loss = if q >= 0 {
        cost.checked_sub(notional(q.unsigned_abs(), minimum_exit)?)?
    } else {
        notional(q.unsigned_abs(), maximum_exit)?.checked_add(cost)?
    }.max(Int256V2::ZERO);
    for &(side, quantity, entry) in exposures {
        let spread = match side {
            Side::Buy => entry.saturating_sub(minimum_exit),
            Side::Sell => maximum_exit.saturating_sub(entry),
        };
        loss = loss.checked_add(notional(quantity, spread)?)?;
    }
    let funding_debt = Int256V2::from_i128(funding)
        .checked_sub(Int256V2::from_i128(trader.last_funding_index_numerator))?
        .checked_mul_i128(i128::from(q))?.max(Int256V2::ZERO);
    let peak = i128::from(q).checked_add(buys).ok_or(ProtocolError::ArithmeticOverflow)?
        .unsigned_abs().max(i128::from(q).checked_sub(sells)
            .ok_or(ProtocolError::ArithmeticOverflow)?.unsigned_abs())
        .min(u128::from(bounds.maximum_abs_position_atoms));
    let margin = Int256V2::from_u128(peak).checked_mul_u64(high.get())?
        .ceil_div_u64(PRICE_SCALE)?.checked_mul_u64(u64::from(margin_bps))?
        .ceil_div_u64(10_000)?;
    loss.checked_add(funding_debt)?
        .checked_add(margin.checked_add(Int256V2::from_i128(fees.0))?
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?)?
        .ceil_div_u64(FUNDING_INDEX_DENOMINATOR_V2)?.ceil_div_u64(low.get())
}

/// Atomically consume the signed nonce and insert an absence-proven order.
/// Cash is unchanged. Configured reserve identities cannot admit orders.
/// The enclosing successor must authenticate both source
/// roots and enforce its priority and authenticated context rules. Complete
/// source-book authentication and resulting aggregate collateral are mandatory.
pub fn stage_ecx_indexed_admission(
    accounts_root: Hash32,
    orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    signed: SignedEcxOrderV1,
    account: EcxAccountOpeningV1<'_>,
    absence_siblings: &[Hash32],
    height: u64,
    source_orders: &[&EcxAdmittedOrderV2],
    low: Price,
    high: Price,
    funding: i128,
    received_sequence: u128,
) -> Result<EcxIndexedAdmissionV1, ProtocolError> {
    let domain = economics.account_domain()?;
    let bounds = economics.bounds;
    if received_sequence == 0
        || source_orders.iter().any(|order| order.received_sequence >= received_sequence)
        || account.position.trader == economics.clearing_account
        || account.position.trader == economics.insurance_account
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let key = signed.order_id()?;
    if order_root(domain, key, None, absence_siblings)? != orders_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    // Check the old nonce before consuming the new one. Otherwise a forged
    // source record could appear admitted merely because this nonce advanced.
    ecx_outstanding_orders_v1(orders_root, domain, source_orders,
        account.position, height, bounds)?;
    let (order, position) =
        EcxAdmittedOrderV2::admit(signed, domain, account.position, height, bounds,
            received_sequence)?;
    let accounts_root = replace_ecx_account_leaf(
        accounts_root,
        domain,
        account.position,
        account.cash,
        &position,
        account.cash,
        bounds,
        account.siblings,
    )?;
    let orders_root = order_root(domain, key, Some(&order), absence_siblings)?;
    let mut resulting_orders = source_orders.to_vec();
    resulting_orders.push(&order);
    let reserve = ecx_outstanding_order_reserve_atoms_v1(
        orders_root, economics, &resulting_orders, &position, account.cash,
        height, low, high, funding,
    )?;
    if crate::incremental_state_v2::Int256V2::from_u128(
        u128::from(account.cash.balance().0)) < reserve {
        return Err(ProtocolError::InsufficientCollateral);
    }
    Ok(EcxIndexedAdmissionV1 {
        accounts_root,
        orders_root,
        position,
        order,
    })
}

fn replace_order(
    root: Hash32,
    domain: EcxAccountDomainV1,
    old: &EcxAdmittedOrderV2,
    new: Option<&EcxAdmittedOrderV2>,
    siblings: &[Hash32],
) -> Result<Hash32, ProtocolError> {
    let key = old.signed.order_id()?;
    if order_root(domain, key, Some(old), siblings)? != root {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    order_root(domain, key, new, siblings)
}

pub struct EcxIndexedOrderOpeningV1<'a> {
    pub order: &'a EcxAdmittedOrderV2,
    pub account: EcxAccountOpeningV1<'a>,
    pub order_siblings: &'a [Hash32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxIndexedMatchV1 {
    pub orders_root: Hash32,
    pub accounts: EcxMatchedAccountUpdateV1,
    pub insurance_cash: Option<crate::ecx_cash_account_v1::EcxCashAccountV1>,
}

/// One staged liquidation fill, with all four account updates committed.
/// This is an internal composition primitive, not liquidation authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxIndexedLiquidationFillV1 {
    pub accounts_root: Hash32,
    pub orders_root: Hash32,
    pub fill: crate::ecx_order_v1::EcxLiquidationFillV1,
    pub target_cash: crate::ecx_cash_account_v1::EcxCashAccountV1,
    pub maker_cash: crate::ecx_cash_account_v1::EcxCashAccountV1,
    pub clearing_cash: crate::ecx_cash_account_v1::EcxCashAccountV1,
    pub insurance_cash: crate::ecx_cash_account_v1::EcxCashAccountV1,
    pub insurance_cover_atoms: u64,
}

/// Derive the signed fill and its fees, settle ECX, then replace account paths
/// in target/maker/clearing/insurance order and the maker order path. Every
/// account path opens the root AFTER preceding replacements. Nothing mutates
/// on failure. Outer execution must authenticate deficit, priority, prices and
/// funding, enforce remaining-order risk, and finalize target order invalidation.
/// A multi-maker batch must net all liabilities together rather than chaining
/// this single-fill cash operation through artificial intermediate liquidity.
#[allow(clippy::too_many_arguments)]
pub fn stage_ecx_indexed_liquidation_fill_v1(
    accounts_root: Hash32, orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    target: EcxAccountOpeningV1<'_>, maker: EcxIndexedOrderOpeningV1<'_>,
    clearing: EcxAccountOpeningV1<'_>, insurance: EcxAccountOpeningV1<'_>,
    height: u64, quantity: u64, settlement_price: Price, funding: i128,
) -> Result<EcxIndexedLiquidationFillV1, ProtocolError> {
    let domain = economics.account_domain()?;
    if clearing.position.trader != economics.clearing_account
        || insurance.position.trader != economics.insurance_account
        || clearing.position.position_size_atoms != 0
        || insurance.position.position_size_atoms != 0
    { return Err(ProtocolError::InvalidBondState); }
    let fill = crate::ecx_order_v1::stage_ecx_liquidation_fill_v1(
        economics, maker.order, maker.account.position, target.position,
        height, quantity, funding)?;
    let (target_cash, clearing_cash, insurance_cash, insurance_cover_atoms, mut makers) =
        crate::ecx_cash_account_v1::settle_liquidation_batch_cash(
            target.cash, clearing.cash, insurance.cash,
            fill.target_quote_pnl, fill.target_quote_penalty, settlement_price,
            &[(maker.account.cash, fill.maker_quote_pnl, fill.maker_quote_fee, settlement_price)])?;
    let maker_cash = makers.pop().ok_or(ProtocolError::InvalidBondState)?;
    let clearing_position = clearing.position;
    let insurance_position = insurance.position;
    let mut root = accounts_root;
    for (opening, position, cash) in [
        (target, &fill.target_position, &target_cash),
        (maker.account, &fill.maker_position, &maker_cash),
        (clearing, clearing_position, &clearing_cash),
        (insurance, insurance_position, &insurance_cash),
    ] {
        root = replace_ecx_account_leaf(root, domain, opening.position, opening.cash,
            position, cash, economics.bounds, opening.siblings)?;
    }
    let orders_root = replace_order(orders_root, domain, maker.order,
        fill.maker_order.as_ref(), maker.order_siblings)?;
    Ok(EcxIndexedLiquidationFillV1 { accounts_root: root, orders_root, fill,
        target_cash, maker_cash, clearing_cash, insurance_cash, insurance_cover_atoms })
}

/// Stage one netted batch and commit all cash, position and order changes.
/// Account paths are sequential: target, unique makers, clearing, insurance.
/// Order paths likewise open successive roots in the supplied order list.
/// Finalization occurs once, in the target replacement, before maker updates.
/// The caller must still establish authenticated deficit, oracle
/// bounds and funding. No mutable state is exposed on any failure.
#[allow(clippy::too_many_arguments)]
pub fn stage_ecx_indexed_liquidation_batch_v1(
    accounts_root: Hash32, orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    accounts: &[(&TraderLeafV2, &crate::ecx_cash_account_v1::EcxCashAccountV1)],
    vault_atoms: u64,
    target: EcxAccountOpeningV1<'_>, makers: &[EcxAccountOpeningV1<'_>],
    clearing: EcxAccountOpeningV1<'_>, insurance: EcxAccountOpeningV1<'_>,
    orders: &[(&EcxAdmittedOrderV2, &[Hash32])], source_orders: &[&EcxAdmittedOrderV2],
    fills: &[(Hash32, u64)], height: u64, settlement_price: Price,
    low: Price, high: Price, funding: i128,
) -> Result<(Hash32, Hash32, crate::ecx_order_v1::EcxLiquidationBatchV1), ProtocolError> {
    let domain = economics.account_domain()?;
    if clearing.position.trader != economics.clearing_account
        || insurance.position.trader != economics.insurance_account
        || clearing.position.position_size_atoms != 0
        || insurance.position.position_size_atoms != 0 {
        return Err(ProtocolError::InvalidBondState);
    }
    let maker_accounts: Vec<_> = makers.iter().map(|a| (a.position, a.cash)).collect();
    let records: Vec<_> = orders.iter().map(|(order, _)| *order).collect();
    let mut batch = stage_ecx_priority_liquidation_batch_v1(accounts_root,
        orders_root, economics, accounts, vault_atoms, source_orders,
        target.position, &maker_accounts, &records, fills, height,
        settlement_price, low, high, funding)?;
    batch.target_position.account_nonce = batch.target_position.account_nonce.checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    batch.target_position.order_generation = batch.target_position.order_generation.checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let mut root = replace_ecx_account_leaf(accounts_root, domain, target.position,
        target.cash, &batch.target_position, &batch.target_cash, economics.bounds, target.siblings)?;
    for (opening, (position, cash)) in makers.iter().zip(&batch.makers) {
        root = replace_ecx_account_leaf(root, domain, opening.position, opening.cash,
            position, cash, economics.bounds, opening.siblings)?;
    }
    for (opening, cash) in [(&clearing, &batch.clearing_cash), (&insurance, &batch.insurance_cash)] {
        root = replace_ecx_account_leaf(root, domain, opening.position, opening.cash,
            opening.position, cash, economics.bounds, opening.siblings)?;
    }
    let mut book_root = orders_root;
    for ((order, path), (id, remaining)) in orders.iter().zip(&batch.orders) {
        if order.signed.order_id()? != *id { return Err(ProtocolError::InvalidBondState); }
        book_root = replace_order(book_root, domain, order, remaining.as_ref(), path)?;
    }
    verify_ecx_post_liquidation_reserve_v1(orders_root, book_root, source_orders,
        economics, &batch, height, low, high, funding)?;
    Ok((root, book_root, batch))
}

/// Finalize one already-authorized liquidation batch after all fills and cash
/// netting. Invalidate the target's prior orders and signed account operations
/// exactly once. The opening authenticates the post-fill account root; cash and
/// position economics are preserved. This is not liquidation authorization and
/// must not be called once per maker. Historical order leaves need not be erased:
/// matching and reserve selection reject their old account generation.
pub fn finalize_ecx_liquidation_target_v1(
    accounts_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    target: EcxAccountOpeningV1<'_>,
) -> Result<(Hash32, TraderLeafV2), ProtocolError> {
    let domain = economics.account_domain()?;
    if target.position.trader == economics.clearing_account
        || target.position.trader == economics.insurance_account
    { return Err(ProtocolError::InvalidBondState); }
    let mut position = target.position.clone();
    position.account_nonce = position.account_nonce.checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    position.order_generation = position.order_generation.checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let root = replace_ecx_account_leaf(accounts_root, domain, target.position,
        target.cash, &position, target.cash, economics.bounds, target.siblings)?;
    Ok((root, position))
}

/// Check remaining-order collateral against an already staged, fee-paid match.
/// Derive the successor book from authenticated source records and the actual
/// staged remainders, rather than trusting a caller's abbreviated successor book.
/// This does not authenticate account roots or execute the match: the enclosing
/// relation must first stage the actual match and fees, then require this check.
pub fn verify_ecx_post_match_reserve_v1(
    source_root: Hash32,
    source_orders: &[&EcxAdmittedOrderV2],
    maker_id: Hash32,
    taker_id: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    result: &EcxIndexedMatchV1,
    height: u64,
    low: Price,
    high: Price,
    funding: i128,
) -> Result<(), ProtocolError> {
    let domain = economics.account_domain()?;
    verify_ecx_complete_order_book_v1(source_root, domain, source_orders)?;
    if maker_id == taker_id {
        return Err(ProtocolError::InvalidBondState);
    }
    let trade = &result.accounts.trade;
    let mut found = [false; 2];
    let mut remaining = Vec::with_capacity(source_orders.len());
    for order in source_orders {
        let id = order.signed.order_id()?;
        let replacement = if id == maker_id {
            found[0] = true;
            trade.maker_order.as_ref()
        } else if id == taker_id {
            found[1] = true;
            trade.taker_order.as_ref()
        } else {
            Some(*order)
        };
        if let Some(replacement) = replacement {
            if replacement.signed.order_id()? != id {
                return Err(ProtocolError::InvalidBondState);
            }
            remaining.push(replacement);
        }
    }
    if found != [true; 2] {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    // Authenticate even an empty resulting book. This also rejects unrelated
    // deletions, substitutions and wrong remaining quantities.
    verify_ecx_complete_order_book_v1(result.orders_root, domain, &remaining)?;
    for (position, cash) in [(&trade.maker_position, &trade.maker_cash),
        (&trade.taker_position, &trade.taker_cash)] {
        let reserve = ecx_outstanding_order_reserve_atoms_v1(
            result.orders_root, economics, &remaining, position, cash,
            height, low, high, funding,
        )?;
        if crate::incremental_state_v2::Int256V2::from_u128(cash.balance().0 as u128) < reserve {
            return Err(ProtocolError::InsufficientCollateral);
        }
    }
    Ok(())
}

/// Check the actual batch's remaining maker exposure against its settled cash.
/// Authenticate both complete books; unrelated orders cannot disappear. This
/// consumes a derived batch, not an untrusted substitute for fill execution.
/// Target finalization, deficit/context authorization and account roots remain
/// responsibilities of the enclosing atomic liquidation relation.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_post_liquidation_reserve_v1(
    source_root: Hash32, successor_root: Hash32,
    source_orders: &[&EcxAdmittedOrderV2],
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    batch: &crate::ecx_order_v1::EcxLiquidationBatchV1,
    height: u64, low: Price, high: Price, funding: i128,
) -> Result<(), ProtocolError> {
    let domain = economics.account_domain()?;
    verify_ecx_complete_order_book_v1(source_root, domain, source_orders)?;
    let mut seen = vec![false; batch.orders.len()];
    let mut remaining = Vec::with_capacity(source_orders.len());
    for record in source_orders {
        let id = record.signed.order_id()?;
        let mut replacement = Some(*record);
        for (i, (key, order)) in batch.orders.iter().enumerate() {
            if *key == id {
                if seen[i] || seen.iter().enumerate().any(|(j, used)|
                    *used && batch.orders[j].0 == id) {
                    return Err(ProtocolError::InvalidBondState);
                }
                seen[i] = true;
                if let Some(order) = order {
                    if order.signed != record.signed || order.generation != record.generation
                        || order.received_sequence != record.received_sequence
                        || order.remaining > record.remaining {
                        return Err(ProtocolError::InvalidBondState);
                    }
                }
                replacement = order.as_ref();
            }
        }
        if let Some(order) = replacement { remaining.push(order); }
    }
    if seen.contains(&false) { return Err(ProtocolError::InvalidMerkleProof); }
    verify_ecx_complete_order_book_v1(successor_root, domain, &remaining)?;
    for (position, cash) in &batch.makers {
        let reserve = ecx_outstanding_order_reserve_atoms_v1(successor_root,
            economics, &remaining, position, cash, height, low, high, funding)?;
        if crate::incremental_state_v2::Int256V2::from_u128(cash.balance().0 as u128) < reserve {
            return Err(ProtocolError::InsufficientCollateral);
        }
    }
    Ok(())
}

/// Paths open successive roots AFTER P&L settlement: maker, insurance,
/// taker, insurance. The second insurance balance is derived, not supplied.
pub struct EcxMatchFeeWitnessV1<'a> {
    pub insurance: EcxAccountOpeningV1<'a>,
    pub maker_siblings: &'a [Hash32],
    pub taker_siblings: &'a [Hash32],
    pub final_insurance_siblings: &'a [Hash32],
}

/// Values must be bound by the enclosing authenticated configuration/context.
pub struct EcxMatchRiskV1 {
    pub low: Price,
    pub high: Price,
    pub cash_scale: u64,
    pub initial_margin_floor_bps: u32,
}

/// Observed context, not evidence of parent inclusion or an oracle proof.
/// Both proof children must bind these exact values to verified source data.
#[derive(Debug, Clone, Copy)]
pub struct EcxExecutionContextV1 {
    pub parent_hash: Hash32,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub match_sequence: u128,
}

/// Stage the real signed fill and commit its inputs AND resulting roots.
/// Derive the signing domain, clearing identity and risk/bounds from the opened
/// economic configuration; existing signatures and leaves pin its digest.
/// This is a shared execution relation, not a matcher signature or proof.
/// Parent authentication, sequence continuity and priority remain the
/// responsibility of the enclosing successor; callers cannot authorize a fill
/// merely by constructing this context or decoding a returned commitment.
pub fn stage_ecx_committed_match(
    accounts_root: Hash32,
    orders_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    maker: EcxIndexedOrderOpeningV1<'_>,
    taker: EcxIndexedOrderOpeningV1<'_>,
    clearing: EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    settlement_price: Price,
    funding: i128,
    low: Price,
    high: Price,
    context: EcxExecutionContextV1,
    fees: Option<EcxMatchFeeWitnessV1<'_>>,
    source_orders: &[&EcxAdmittedOrderV2],
) -> Result<(EcxIndexedMatchV1, Hash32), ProtocolError> {
    use crate::codec::CanonicalEncode;
    let domain = economics.account_domain()?;
    let configured_clearing = economics.clearing_account;
    let bounds = economics.bounds;
    let maker_id = maker.order.signed.order_id()?;
    let taker_id = taker.order.signed.order_id()?;
    // Validate against source nonces, before the match advances accounts.
    for account in [&maker.account, &taker.account] {
        ecx_outstanding_orders_v1(orders_root, domain, source_orders,
            account.position, height, bounds)?;
    }
    let maker_cap = maker.order.signed.order.max_fee_bps;
    let taker_cap = taker.order.signed.order.max_fee_bps;
    let execution_price = maker.order.signed.order.limit_price;
    if maker.account.position.trader == economics.insurance_account
        || taker.account.position.trader == economics.insurance_account
        || (fees.is_none()
            && (economics.risk.maker_fee_bps != 0 || economics.risk.taker_fee_bps != 0))
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let risk = EcxMatchRiskV1 {
        low,
        high,
        cash_scale: economics.cash_valuation_scale,
        initial_margin_floor_bps: economics.risk.initial_margin_bps,
    };
    if context.parent_hash == [0; 32]
        || context.parent_height == 0
        || context.parent_mtp == 0
        || context.match_sequence == 0
        || height == 0
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(&domain.chain_id);
    domain.market.encode_to(&mut bytes);
    bytes.extend_from_slice(&domain.configuration_hash);
    bytes.extend_from_slice(&domain.collateral_asset);
    bytes.extend_from_slice(&accounts_root);
    bytes.extend_from_slice(&orders_root);
    // Admitted commitments bind signed order IDs, remaining quantity and
    // generation. Their validation checks the actual ECX signatures.
    bytes.extend_from_slice(&maker.order.commitment(domain)?);
    bytes.extend_from_slice(&taker.order.commitment(domain)?);
    bytes.extend_from_slice(&configured_clearing.0);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&quantity.to_be_bytes());
    settlement_price.encode_to(&mut bytes);
    bytes.extend_from_slice(&funding.to_be_bytes());
    risk.low.encode_to(&mut bytes);
    risk.high.encode_to(&mut bytes);
    bytes.extend_from_slice(&risk.cash_scale.to_be_bytes());
    bytes.extend_from_slice(&risk.initial_margin_floor_bps.to_be_bytes());
    bounds.encode_to(&mut bytes);
    bytes.extend_from_slice(&context.parent_hash);
    bytes.extend_from_slice(&context.parent_height.to_be_bytes());
    bytes.extend_from_slice(&context.parent_mtp.to_be_bytes());
    bytes.extend_from_slice(&context.match_sequence.to_be_bytes());
    let mut result = stage_ecx_risk_checked_match(
        accounts_root,
        orders_root,
        domain,
        maker,
        taker,
        configured_clearing,
        clearing,
        height,
        quantity,
        settlement_price,
        funding,
        risk,
        bounds,
    )?;
    if let Some(fees) = fees {
        use crate::ecx_cash_account_v1::{stage_ecx_account_fee, EcxMarginStatusV1};
        let trade = &mut result.accounts.trade;
        let insurance_position = fees.insurance.position;
        let (root, maker_cash, insurance_cash) = stage_ecx_account_fee(
            result.accounts.root, domain,
            EcxAccountOpeningV1 { position: &trade.maker_position,
                cash: &trade.maker_cash, siblings: fees.maker_siblings },
            economics.insurance_account, fees.insurance,
            execution_price, crate::types::Quantity::new(quantity)?,
            economics.risk.maker_fee_bps, maker_cap, settlement_price, bounds,
        )?;
        let (root, taker_cash, insurance_cash) = stage_ecx_account_fee(
            root, domain,
            EcxAccountOpeningV1 { position: &trade.taker_position,
                cash: &trade.taker_cash, siblings: fees.taker_siblings },
            economics.insurance_account,
            EcxAccountOpeningV1 { position: insurance_position,
                cash: &insurance_cash, siblings: fees.final_insurance_siblings },
            execution_price, crate::types::Quantity::new(quantity)?,
            economics.risk.taker_fee_bps as i32, taker_cap, settlement_price, bounds,
        )?;
        for (position, cash) in [(&trade.maker_position, &maker_cash),
            (&trade.taker_position, &taker_cash)] {
            if cash.margin_over_interval(position, economics.cash_valuation_scale,
                low, high, funding,
                position.selected_initial_margin_bps.max(economics.risk.initial_margin_bps),
                bounds)? != EcxMarginStatusV1::Sufficient {
                return Err(ProtocolError::InsufficientCollateral);
            }
        }
        trade.maker_cash = maker_cash;
        trade.taker_cash = taker_cash;
        result.accounts.root = root;
        result.insurance_cash = Some(insurance_cash);
    }
    verify_ecx_post_match_reserve_v1(orders_root, source_orders, maker_id,
        taker_id, economics, &result, height, low, high, funding)?;
    bytes.extend_from_slice(&result.accounts.root);
    bytes.extend_from_slice(&result.orders_root);
    Ok((result, tagged_hash("ECX/ecx-execution-relation/v1", &bytes)))
}

/// Risk-gated composition. Unlike the staging primitive, this returns no roots
/// unless both resulting accounts meet initial margin throughout the interval.
/// It does not yet enforce book priority, outstanding-order exposure or fees.
pub fn stage_ecx_risk_checked_match(
    accounts_root: Hash32,
    orders_root: Hash32,
    domain: EcxAccountDomainV1,
    maker: EcxIndexedOrderOpeningV1<'_>,
    taker: EcxIndexedOrderOpeningV1<'_>,
    configured_clearing: XOnlyKey,
    clearing: EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    settlement_price: Price,
    funding: i128,
    risk: EcxMatchRiskV1,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxIndexedMatchV1, ProtocolError> {
    if risk.initial_margin_floor_bps == 0
        || risk.initial_margin_floor_bps > 10_000
        || settlement_price < risk.low
        || settlement_price > risk.high
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let staged = stage_ecx_indexed_match(
        accounts_root,
        orders_root,
        domain,
        maker,
        taker,
        configured_clearing,
        clearing,
        height,
        quantity,
        settlement_price,
        funding,
        bounds,
    )?;
    let trade = &staged.accounts.trade;
    for (position, cash) in [
        (&trade.maker_position, &trade.maker_cash),
        (&trade.taker_position, &trade.taker_cash),
    ] {
        if cash.margin_over_interval(
            position,
            risk.cash_scale,
            risk.low,
            risk.high,
            funding,
            position
                .selected_initial_margin_bps
                .max(risk.initial_margin_floor_bps),
            bounds,
        )? != crate::ecx_cash_account_v1::EcxMarginStatusV1::Sufficient
        {
            return Err(ProtocolError::InsufficientCollateral);
        }
    }
    Ok(staged)
}

/// Both order replacements and all three account replacements succeed or no
/// result is returned. Taker's order path opens the root after maker removal
/// or partial fill. Account paths likewise open successive account roots.
/// The source roots/configuration/context must be authenticated externally;
/// this does not implement priority, risk, execution fees or vault backing.
pub fn stage_ecx_indexed_match(
    accounts_root: Hash32,
    orders_root: Hash32,
    domain: EcxAccountDomainV1,
    maker: EcxIndexedOrderOpeningV1<'_>,
    taker: EcxIndexedOrderOpeningV1<'_>,
    configured_clearing: XOnlyKey,
    clearing: EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxIndexedMatchV1, ProtocolError> {
    let accounts = stage_ecx_matched_accounts(
        accounts_root,
        domain,
        maker.order,
        taker.order,
        maker.account,
        taker.account,
        configured_clearing,
        clearing,
        height,
        quantity,
        settlement_price,
        funding,
        bounds,
    )?;
    let intermediate = replace_order(
        orders_root,
        domain,
        maker.order,
        accounts.trade.maker_order.as_ref(),
        maker.order_siblings,
    )?;
    let orders_root = replace_order(
        intermediate,
        domain,
        taker.order,
        accounts.trade.taker_order.as_ref(),
        taker.order_siblings,
    )?;
    Ok(EcxIndexedMatchV1 {
        orders_root,
        accounts,
        insurance_cash: None,
    })
}

#[cfg(test)]
mod reservation_tests {
    #[test]
    fn proportional_cost_rounding_preserves_loss_potential() {
        // Exhaust small integral cost numerators, including bases that are
        // not divisible by position size. This checks the induction step,
        // not only an endpoint sample of whole-position executions.
        for q in 1i128..=8 {
            for basis in 0..=q * 20 {
                for closing in 1..=q {
                    let allocated = basis * closing / q;
                    let rest = basis - allocated;
                    for threshold in 1..=20 {
                        for exit in 1..=20 {
                            if exit >= threshold {
                                let before = (basis - q * threshold).max(0);
                                let paid = (allocated - closing * exit).max(0);
                                let after = (rest - (q - closing) * threshold).max(0);
                                assert!(paid + after <= before,
                                    "long q={q} basis={basis} closing={closing} threshold={threshold} exit={exit}");
                            }
                            if exit <= threshold {
                                let before = (q * threshold - basis).max(0);
                                let paid = (closing * exit - allocated).max(0);
                                let after = ((q - closing) * threshold - rest).max(0);
                                assert!(paid + after <= before,
                                    "short q={q} basis={basis} closing={closing} threshold={threshold} exit={exit}");
                            }
                        }
                    }
                }
            }
        }
    }
}
