//! Explicit authorization for ECX collateral and settlement. Legacy quote-cash
//! order signatures are not valid here. Admission still needs authenticated
//! order-index state, remaining quantity, nonce/generation, risk and context.
use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::CanonicalEncode;
use crate::ecx_cash_account_v1::{
    replace_ecx_account_leaf, stage_account_trade, EcxAccountDomainV1, EcxAccountOpeningV1,
    EcxCashAccountV1,
};
use crate::hash::{tagged_hash, Hash32};
use crate::incremental_state_v2::{IncrementalAccountingBoundsV2, TraderLeafV2};
use crate::order::{OrderFlags, Side, Signature64, TimeInForce};
use crate::successor_action_v2::SuccessorLimitOrderV2;
use crate::types::{Price, XOnlyKey};
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedEcxOrderV1 {
    pub domain: EcxAccountDomainV1,
    pub order: SuccessorLimitOrderV2,
    pub signature: Signature64,
}

fn digest(
    domain: EcxAccountDomainV1,
    order: &SuccessorLimitOrderV2,
) -> Result<Hash32, ProtocolError> {
    order.validate()?;
    if domain.chain_id == [0; 32]
        || domain.configuration_hash == [0; 32]
        || domain.collateral_asset == [0; 32]
        || order.chain_id != domain.chain_id
        || order.market != domain.market
    {
        return Err(ProtocolError::IncompatibleOrders);
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(&domain.configuration_hash);
    bytes.extend_from_slice(&domain.collateral_asset);
    // The canonical order includes chain, market, owner and all order terms.
    order.encode_to(&mut bytes);
    Ok(tagged_hash("ECX/ecx-settled-linear-order/v1", &bytes))
}

impl SignedEcxOrderV1 {
    pub fn sign(
        domain: EcxAccountDomainV1,
        order: SuccessorLimitOrderV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        let message = Message::from_digest_slice(&digest(domain, &order)?)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let secp = Secp256k1::new();
        let pair = Keypair::from_secret_key(&secp, key);
        if XOnlyPublicKey::from_keypair(&pair).0.serialize() != order.trader.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let signature = Signature64(*secp.sign_schnorr_no_aux_rand(&message, &pair).as_ref());
        Ok(Self {
            domain,
            order,
            signature,
        })
    }

    /// `expected` must come from the authenticated exchange configuration,
    /// not the submitted order. This verifies consent, not fill admissibility.
    pub fn verify(&self, expected: EcxAccountDomainV1) -> Result<(), ProtocolError> {
        if self.domain != expected {
            return Err(ProtocolError::IncompatibleOrders);
        }
        let message = Message::from_digest_slice(&digest(self.domain, &self.order)?)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let key = XOnlyPublicKey::from_slice(&self.order.trader.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn order_id(&self) -> Result<Hash32, ProtocolError> {
        digest(self.domain, &self.order)
    }

    /// Stage admission once against the current authenticated account. The
    /// caller must commit this nonce update atomically with order insertion or
    /// immediate execution, and must enforce risk/fee/matcher policy. Partial
    /// fills use the admitted remaining-quantity record, not re-admission.
    pub fn admit(
        &self,
        expected: EcxAccountDomainV1,
        trader: &TraderLeafV2,
        height: u64,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<TraderLeafV2, ProtocolError> {
        self.verify(expected)?;
        trader.validate(bounds)?;
        if trader.trader != self.order.trader
            || trader.account_nonce != self.order.nonce
            || trader.collateral_atoms != 0
            || trader.cash_residual_numerator != 0
        {
            return Err(ProtocolError::InvalidBondState);
        }
        if !self.order.is_live_at(height) {
            return Err(ProtocolError::OrderNotLive);
        }
        let mut next = trader.clone();
        next.account_nonce = next
            .account_nonce
            .checked_add(1)
            .ok_or(ProtocolError::InvalidBondState)?;
        next.validate(bounds)?;
        Ok(next)
    }
}

/// State carried after nonce-consuming admission. Its commitment must be
/// authenticated by the order index; a caller-supplied record is not evidence
/// that admission occurred or that previous fills have been consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EcxAdmittedOrderV2 {
    pub signed: SignedEcxOrderV1,
    pub remaining: u64,
    pub generation: u128,
    /// Allocated from the authenticated matcher cursor by admission, never
    /// from a trader timestamp. Partial fills preserve this value.
    pub received_sequence: u128,
}

impl EcxAdmittedOrderV2 {
    pub fn admit(
        signed: SignedEcxOrderV1,
        domain: EcxAccountDomainV1,
        trader: &TraderLeafV2,
        height: u64,
        bounds: IncrementalAccountingBoundsV2,
        received_sequence: u128,
    ) -> Result<(Self, TraderLeafV2), ProtocolError> {
        if received_sequence == 0 {
            return Err(ProtocolError::InvalidBondState);
        }
        let next = signed.admit(domain, trader, height, bounds)?;
        let record = Self {
            remaining: signed.order.quantity.get(),
            generation: trader.order_generation,
            received_sequence,
            signed,
        };
        Ok((record, next))
    }

    pub fn commitment(&self, domain: EcxAccountDomainV1) -> Result<Hash32, ProtocolError> {
        self.signed.verify(domain)?;
        if self.received_sequence == 0 {
            return Err(ProtocolError::InvalidBondState);
        }
        if self.remaining == 0 || self.remaining > self.signed.order.quantity.get() {
            return Err(ProtocolError::ExcessFill);
        }
        let mut bytes = vec![2];
        bytes.extend_from_slice(&self.signed.order_id()?);
        bytes.extend_from_slice(&self.remaining.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.received_sequence.to_be_bytes());
        Ok(tagged_hash("ECX/ecx-admitted-order/v2", &bytes))
    }

    /// Use the common price/time ordering with the ECX-domain order identity.
    /// This validates the record, not its membership or current eligibility.
    pub fn priority(&self, domain: EcxAccountDomainV1) -> Result<crate::incremental_state_v2::OrderPriorityV2, ProtocolError> {
        self.commitment(domain)?;
        Ok(crate::incremental_state_v2::OrderPriorityV2 {
            side: self.signed.order.side,
            limit_price_atoms: self.signed.order.limit_price.get(),
            received_sequence: self.received_sequence,
            order_id: self.signed.order_id()?,
        })
    }

    /// Stage one fill; `None` removes the order (full fill or IOC remainder).
    /// The signed position delta and updated record must be committed with
    /// BOTH traders' settlement atomically. This does not authenticate index
    /// membership, maker priority, fee payment or margin/oracle context.
    pub fn fill(
        &self,
        domain: EcxAccountDomainV1,
        trader: &TraderLeafV2,
        height: u64,
        quantity: u64,
        price: Price,
        is_maker: bool,
        fee_bps: u32,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(Option<Self>, i64), ProtocolError> {
        self.commitment(domain)?;
        trader.validate(bounds)?;
        let order = &self.signed.order;
        if trader.trader != order.trader
            || trader.order_generation != self.generation
            || trader.account_nonce <= order.nonce
            || trader.collateral_atoms != 0
            || trader.cash_residual_numerator != 0
            || fee_bps > order.max_fee_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
        if !order.is_live_at(height) {
            return Err(ProtocolError::OrderNotLive);
        }
        if quantity == 0 || quantity > self.remaining {
            return Err(ProtocolError::ExcessFill);
        }
        Price::new(price.get())?;
        if (is_maker
            && (order.time_in_force != TimeInForce::GoodTilHeight || price != order.limit_price))
            || (!is_maker && order.flags.contains(OrderFlags::POST_ONLY))
            || match order.side {
                Side::Buy => price > order.limit_price,
                Side::Sell => price < order.limit_price,
            }
        {
            return Err(ProtocolError::IncompatibleOrders);
        }
        let size = i64::try_from(quantity).map_err(|_| ProtocolError::ExcessFill)?;
        let delta = size * order.side.sign();
        if order.flags.contains(OrderFlags::REDUCE_ONLY)
            && (trader.position_size_atoms == 0
                || trader.position_size_atoms.signum() == delta.signum()
                || quantity > trader.position_size_atoms.unsigned_abs())
        {
            return Err(ProtocolError::ExcessFill);
        }
        let mut next = self.clone();
        next.remaining -= quantity;
        Ok((
            if next.remaining == 0 || order.time_in_force == TimeInForce::ImmediateOrCancel {
                None
            } else {
                Some(next)
            },
            delta,
        ))
    }
}

/// Derived position changes and exact liabilities for one liquidation fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxLiquidationFillV1 {
    pub maker_order: Option<EcxAdmittedOrderV2>,
    pub maker_position: TraderLeafV2,
    pub target_position: TraderLeafV2,
    pub maker_quote_pnl: crate::incremental_state_v2::Int256V2,
    pub target_quote_pnl: crate::incremental_state_v2::Int256V2,
    pub maker_quote_fee: crate::incremental_state_v2::Int256V2,
    pub target_quote_penalty: crate::incremental_state_v2::Int256V2,
}

/// Derive a liquidation fill from a signed resting order and configuration.
/// No synthetic target order/signature is needed for permissionless liquidation.
/// Caller must establish deficit, priority, oracle/funding authentication and
/// atomically settle the returned exact liabilities with all successor roots.
#[allow(clippy::too_many_arguments)]
pub fn stage_ecx_liquidation_fill_v1(
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    maker: &EcxAdmittedOrderV2,
    maker_position: &TraderLeafV2,
    target: &TraderLeafV2,
    height: u64,
    quantity: u64,
    funding: i128,
) -> Result<EcxLiquidationFillV1, ProtocolError> {
    use crate::incremental_state_v2::{Int256V2, EXACT_ACCOUNTING_DENOMINATOR_V2};
    let domain = economics.account_domain()?;
    if maker_position.trader == target.trader
        || [maker_position.trader, target.trader].iter().any(|key|
            *key == economics.clearing_account || *key == economics.insurance_account)
        || target.position_size_atoms == 0
        || quantity > target.position_size_atoms.unsigned_abs()
        || maker.signed.order.side.sign() != target.position_size_atoms.signum()
    { return Err(ProtocolError::IncompatibleOrders); }
    let price = maker.signed.order.limit_price;
    let (maker_order, delta) = maker.fill(domain, maker_position, height, quantity,
        price, true, economics.risk.maker_fee_bps.max(0) as u32, economics.bounds)?;
    let mut maker_next = maker_position.clone();
    let mut target_next = target.clone();
    let maker_quote_pnl = maker_next.apply_trade_for_ecx_settlement(
        delta, price.get(), funding, economics.bounds)?;
    let target_quote_pnl = target_next.apply_trade_for_ecx_settlement(
        delta.checked_neg().ok_or(ProtocolError::ArithmeticOverflow)?,
        price.get(), funding, economics.bounds)?;
    let fee = |rate| -> Result<Int256V2, ProtocolError> {
        let value = crate::risk::trading_fee(price, crate::types::Quantity::new(quantity)?, rate)?;
        Int256V2::from_i128(value.0).checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)
    };
    Ok(EcxLiquidationFillV1 {
        maker_order, maker_position: maker_next, target_position: target_next,
        maker_quote_pnl, target_quote_pnl,
        maker_quote_fee: fee(economics.risk.maker_fee_bps)?,
        target_quote_penalty: fee(economics.risk.liquidation_fee_bps as i32)?,
    })
}

/// Economic result of a liquidation fill sequence. Maker rows retain input
/// order, but each identity is settled once even when it owns several orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxLiquidationBatchV1 {
    pub target_position: TraderLeafV2,
    pub target_cash: EcxCashAccountV1,
    pub makers: Vec<(TraderLeafV2, EcxCashAccountV1)>,
    pub orders: Vec<(Hash32, Option<EcxAdmittedOrderV2>)>,
    pub clearing_cash: EcxCashAccountV1,
    pub insurance_cash: EcxCashAccountV1,
    pub insurance_cover_atoms: u64,
}

/// Derive all signed maker fills before settling any cash. Prices are the signed
/// order limits; one authenticated settlement price/funding context applies to
/// this batch. Repeated maker identities aggregate exact liabilities, and repeat
/// fills of an order consume its actual remainder. Caller must authenticate all
/// records, deficit, priority and context, check successor risk and commit roots
/// with target finalization once. This function provides no authorization.
#[allow(clippy::too_many_arguments)]
pub fn stage_ecx_liquidation_batch_v1(
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    target: &TraderLeafV2, target_cash: &EcxCashAccountV1,
    makers: &[(&TraderLeafV2, &EcxCashAccountV1)],
    orders: &[&EcxAdmittedOrderV2], fills: &[(Hash32, u64)],
    clearing_cash: &EcxCashAccountV1, insurance_cash: &EcxCashAccountV1,
    height: u64, settlement_price: Price, funding: i128,
) -> Result<EcxLiquidationBatchV1, ProtocolError> {
    stage_ecx_liquidation_batch_checked_v1(economics, target, target_cash, makers,
        orders, fills, clearing_cash, insurance_cash, height, settlement_price,
        funding, |_, _, _, _| Ok(()))
}

/// Shared staging engine. The enclosing authenticated-book relation checks each
/// selected order against the current derived positions/remainders before the
/// fill executes. Cash is still netted only once, after the complete sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_ecx_liquidation_batch_checked_v1(
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    target: &TraderLeafV2, target_cash: &EcxCashAccountV1,
    makers: &[(&TraderLeafV2, &EcxCashAccountV1)],
    orders: &[&EcxAdmittedOrderV2], fills: &[(Hash32, u64)],
    clearing_cash: &EcxCashAccountV1, insurance_cash: &EcxCashAccountV1,
    height: u64, settlement_price: Price, funding: i128,
    mut before_fill: impl FnMut(&EcxAdmittedOrderV2, &TraderLeafV2, &[TraderLeafV2],
        &[(Hash32, Option<EcxAdmittedOrderV2>)]) -> Result<(), ProtocolError>,
) -> Result<EcxLiquidationBatchV1, ProtocolError> {
    use crate::incremental_state_v2::Int256V2;
    let domain = economics.account_domain()?;
    if fills.is_empty() || makers.is_empty() || orders.is_empty() {
        return Err(ProtocolError::IncompatibleOrders);
    }
    let mut positions = Vec::with_capacity(makers.len());
    for &(position, _) in makers {
        position.validate(economics.bounds)?;
        if positions.iter().any(|p: &TraderLeafV2| p.trader == position.trader) {
            return Err(ProtocolError::IncompatibleOrders);
        }
        positions.push(position.clone());
    }
    let mut remaining = Vec::with_capacity(orders.len());
    for &order in orders {
        order.commitment(domain)?;
        let id = order.signed.order_id()?;
        if remaining.iter().any(|(key, _)| *key == id) {
            return Err(ProtocolError::IncompatibleOrders);
        }
        remaining.push((id, Some(order.clone())));
    }
    let mut maker_pnl = vec![Int256V2::ZERO; makers.len()];
    let mut maker_fee = vec![Int256V2::ZERO; makers.len()];
    let mut used_makers = vec![false; makers.len()];
    let mut used_orders = vec![false; orders.len()];
    let mut next_target = target.clone();
    let mut target_pnl = Int256V2::ZERO;
    let mut penalty = Int256V2::ZERO;
    for &(id, quantity) in fills {
        let order_index = remaining.iter().position(|(key, _)| *key == id)
            .ok_or(ProtocolError::IncompatibleOrders)?;
        let order = remaining[order_index].1.as_ref()
            .ok_or(ProtocolError::IncompatibleOrders)?;
        let maker_index = positions.iter().position(|p| p.trader == order.signed.order.trader)
            .ok_or(ProtocolError::IncompatibleOrders)?;
        before_fill(order, &next_target, &positions, &remaining)?;
        let result = stage_ecx_liquidation_fill_v1(economics, order,
            &positions[maker_index], &next_target, height, quantity, funding)?;
        maker_pnl[maker_index] = maker_pnl[maker_index].checked_add(result.maker_quote_pnl)?;
        maker_fee[maker_index] = maker_fee[maker_index].checked_add(result.maker_quote_fee)?;
        target_pnl = target_pnl.checked_add(result.target_quote_pnl)?;
        penalty = penalty.checked_add(result.target_quote_penalty)?;
        positions[maker_index] = result.maker_position;
        next_target = result.target_position;
        remaining[order_index].1 = result.maker_order;
        used_makers[maker_index] = true;
        used_orders[order_index] = true;
    }
    if used_makers.contains(&false) || used_orders.contains(&false) {
        return Err(ProtocolError::IncompatibleOrders);
    }
    let liabilities: Vec<_> = makers.iter().enumerate().map(|(i, (_, cash))|
        (*cash, maker_pnl[i], maker_fee[i], settlement_price)).collect();
    let (target_cash, clearing_cash, insurance_cash, insurance_cover_atoms, cash) =
        crate::ecx_cash_account_v1::settle_liquidation_batch_cash(target_cash,
            clearing_cash, insurance_cash, target_pnl, penalty, settlement_price, &liabilities)?;
    Ok(EcxLiquidationBatchV1 { target_position: next_target, target_cash,
        makers: positions.into_iter().zip(cash).collect(), orders: remaining,
        clearing_cash, insurance_cash, insurance_cover_atoms })
}

/// A staged matched trade, never a partially applied maker execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxMatchedTradeV1 {
    pub maker_order: Option<EcxAdmittedOrderV2>,
    pub taker_order: Option<EcxAdmittedOrderV2>,
    pub maker_position: TraderLeafV2,
    pub taker_position: TraderLeafV2,
    pub maker_cash: EcxCashAccountV1,
    pub taker_cash: EcxCashAccountV1,
    pub clearing_cash: EcxCashAccountV1,
}

/// Compose both signed fills and their linear ECX settlement. Inputs must be
/// authenticated by the caller, including the configured clearing identity.
/// This stages zero execution fees only; nonzero fee settlement, priority,
/// margin, oracle authentication and atomic root replacement remain external.
/// Clearing is evaluated maker-first and must fund that intermediate state.
pub fn stage_ecx_match(
    domain: EcxAccountDomainV1,
    maker: &EcxAdmittedOrderV2,
    taker: &EcxAdmittedOrderV2,
    maker_position: &TraderLeafV2,
    taker_position: &TraderLeafV2,
    maker_cash: &EcxCashAccountV1,
    taker_cash: &EcxCashAccountV1,
    clearing_key: XOnlyKey,
    clearing_cash: &EcxCashAccountV1,
    height: u64,
    quantity: u64,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxMatchedTradeV1, ProtocolError> {
    if maker_position.trader == taker_position.trader
        || maker_position.trader == clearing_key
        || taker_position.trader == clearing_key
        || maker.signed.order.side == taker.signed.order.side
    {
        return Err(ProtocolError::IncompatibleOrders);
    }
    let price = maker.signed.order.limit_price;
    let (maker_order, maker_delta) = maker.fill(
        domain,
        maker_position,
        height,
        quantity,
        price,
        true,
        0,
        bounds,
    )?;
    let (taker_order, taker_delta) = taker.fill(
        domain,
        taker_position,
        height,
        quantity,
        price,
        false,
        0,
        bounds,
    )?;
    if maker_delta.checked_add(taker_delta) != Some(0) {
        return Err(ProtocolError::IncompatibleOrders);
    }
    let first = stage_account_trade(
        maker_position,
        maker_cash,
        clearing_cash,
        maker_delta,
        price,
        settlement_price,
        funding,
        bounds,
    )?;
    let second = stage_account_trade(
        taker_position,
        taker_cash,
        &first.clearing_cash,
        taker_delta,
        price,
        settlement_price,
        funding,
        bounds,
    )?;
    Ok(EcxMatchedTradeV1 {
        maker_order,
        taker_order,
        maker_position: first.position,
        taker_position: second.position,
        maker_cash: first.trader_cash,
        taker_cash: second.trader_cash,
        clearing_cash: second.clearing_cash,
    })
}

/// Account-root result only: order-index replacements must be committed in
/// the same outer successor. Returning this is not permission to reuse orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxMatchedAccountUpdateV1 {
    pub root: Hash32,
    pub trade: EcxMatchedTradeV1,
}

/// Membership paths open successive roots: maker at source, taker after
/// maker, clearing after both traders. No intermediate root escapes on error.
/// The outer successor must authenticate configuration, order membership,
/// context and risk and commit the returned order remainders with this root.
pub fn stage_ecx_matched_accounts(
    source_root: Hash32,
    domain: EcxAccountDomainV1,
    maker_order: &EcxAdmittedOrderV2,
    taker_order: &EcxAdmittedOrderV2,
    maker: EcxAccountOpeningV1<'_>,
    taker: EcxAccountOpeningV1<'_>,
    configured_clearing: XOnlyKey,
    clearing: EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    settlement_price: Price,
    funding: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<EcxMatchedAccountUpdateV1, ProtocolError> {
    if clearing.position.trader != configured_clearing || clearing.position.position_size_atoms != 0
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let trade = stage_ecx_match(
        domain,
        maker_order,
        taker_order,
        maker.position,
        taker.position,
        maker.cash,
        taker.cash,
        configured_clearing,
        clearing.cash,
        height,
        quantity,
        settlement_price,
        funding,
        bounds,
    )?;
    let first = replace_ecx_account_leaf(
        source_root,
        domain,
        maker.position,
        maker.cash,
        &trade.maker_position,
        &trade.maker_cash,
        bounds,
        maker.siblings,
    )?;
    let second = replace_ecx_account_leaf(
        first,
        domain,
        taker.position,
        taker.cash,
        &trade.taker_position,
        &trade.taker_cash,
        bounds,
        taker.siblings,
    )?;
    let root = replace_ecx_account_leaf(
        second,
        domain,
        clearing.position,
        clearing.cash,
        clearing.position,
        &trade.clearing_cash,
        bounds,
        clearing.siblings,
    )?;
    Ok(EcxMatchedAccountUpdateV1 { root, trade })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::{OrderFlags, Side, TimeInForce};
    use crate::successor_action_v2::SuccessorSignedLimitOrderV2;
    use crate::types::{Price, Quantity, XOnlyKey, ECX_USDD_MARKET};

    // Independent sparse tree construction. Opaque other subtrees are not
    // claimed to establish complete vault backing.
    fn tree(
        entries: &[(Hash32, Hash32)],
        depth: usize,
        target: Hash32,
        path: &mut Vec<Hash32>,
    ) -> Hash32 {
        tree_tag(entries, depth, target, path, "ECX/ecx-account-tree-node/v1")
    }

    fn tree_tag(
        entries: &[(Hash32, Hash32)],
        depth: usize,
        target: Hash32,
        path: &mut Vec<Hash32>,
        tag: &str,
    ) -> Hash32 {
        if entries.is_empty() {
            if tag == "ECX/ecx-order-index-node/v1" {
                let mut empty = tagged_hash("ECX/ecx-order-index-empty/v1", &[]);
                for height in 1..=(256 - depth) {
                    let mut bytes = vec![1];
                    bytes.extend_from_slice(&(height as u16).to_be_bytes());
                    bytes.extend_from_slice(&empty);
                    bytes.extend_from_slice(&empty);
                    empty = tagged_hash(tag, &bytes);
                }
                return empty;
            }
            return [42; 32];
        }
        if depth == 256 {
            return entries[0].1;
        }
        let right_bit = |key: Hash32| key[depth / 8] & (1 << (7 - depth % 8)) != 0;
        let (left, right): (Vec<_>, Vec<_>) = entries
            .iter()
            .copied()
            .partition(|(key, _)| !right_bit(*key));
        let mut ignored = Vec::new();
        let (l, r) = if right_bit(target) {
            (
                tree_tag(&left, depth + 1, target, &mut ignored, tag),
                tree_tag(&right, depth + 1, target, path, tag),
            )
        } else {
            (
                tree_tag(&left, depth + 1, target, path, tag),
                tree_tag(&right, depth + 1, target, &mut ignored, tag),
            )
        };
        path.push(if right_bit(target) { l } else { r });
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((256 - depth) as u16).to_be_bytes());
        bytes.extend_from_slice(&l);
        bytes.extend_from_slice(&r);
        tagged_hash(tag, &bytes)
    }

    #[test]
    fn matched_round_trip_pays_ecx_and_rejects_insolvent_second_leg() {
        use crate::ecx_cash_account_v1::verify_ecx_cash_conservation;
        use crate::ecx_collateral::EcxCollateralAtoms;
        use crate::incremental_state_v2::Int256V2;
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let keys = [
            SecretKey::from_slice(&[7; 32]).unwrap(),
            SecretKey::from_slice(&[8; 32]).unwrap(),
        ];
        let clearing_pair = Keypair::from_secret_key(
            &Secp256k1::new(), &SecretKey::from_slice(&[9; 32]).unwrap(),
        );
        let clearing_key = XOnlyKey(clearing_pair.x_only_public_key().0.serialize());
        let economics = crate::ecx_configuration_v1::EcxConfigurationV1 {
            chain_id: [1; 32], market: ECX_USDD_MARKET, collateral_asset: [3; 32],
            clearing_account: clearing_key, cash_valuation_scale: 1_000_000,
            insurance_account: XOnlyKey(Keypair::from_secret_key(
                &Secp256k1::new(), &SecretKey::from_slice(&[10; 32]).unwrap(),
            ).x_only_public_key().0.serialize()),
            // This fixture isolates zero-fee P&L/root behavior explicitly.
            risk: crate::risk::RiskParams { taker_fee_bps: 0,
                ..crate::risk::RiskParams::default() }, bounds,
        };
        let domain = economics.account_domain().unwrap();
        let position = |key: &SecretKey| TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey(
                XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), key))
                    .0
                    .serialize(),
            ),
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
        let admit = |p: &TraderLeafV2, key: &SecretKey, side, price| {
            EcxAdmittedOrderV2::admit(
                SignedEcxOrderV1::sign(
                    domain,
                    SuccessorLimitOrderV2 {
                        version: 2,
                        chain_id: domain.chain_id,
                        market: domain.market,
                        trader: p.trader,
                        side,
                        time_in_force: TimeInForce::GoodTilHeight,
                        flags: OrderFlags::from_bits(0).unwrap(),
                        limit_price: Price::new(price).unwrap(),
                        quantity: Quantity::new(100_000_000).unwrap(),
                        client_order_id: [0; 16],
                        max_fee_bps: 0,
                        nonce: p.account_nonce,
                        valid_from_height: 0,
                        expires_at_height: 100,
                    },
                    key,
                )
                .unwrap(),
                domain,
                p,
                1,
                bounds, 1,
            )
            .unwrap()
        };
        let (buy, long) = admit(&position(&keys[0]), &keys[0], Side::Buy, 3_000_000_000);
        let (sell, short) = admit(&position(&keys[1]), &keys[1], Side::Sell, 3_000_000_000);
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000));
        // Admission commits the consumed nonce and inserted order together.
        // Independently build both trees, including an explicit empty leaf.
        {
            use crate::ecx_cash_account_v1::ecx_account_commitment;
            use crate::ecx_order_index_v1::{order_leaf, stage_ecx_indexed_admission};
            let old = position(&keys[0]);
            let mut account_path = Vec::new();
            let account_root = tree(
                &[(
                    old.key(),
                    ecx_account_commitment(domain, &old, &cash, bounds).unwrap(),
                )],
                0,
                old.key(),
                &mut account_path,
            );
            let key = buy.signed.order_id().unwrap();
            let tag = "ECX/ecx-order-index-node/v1";
            let mut absence = Vec::new();
            let empty_root = tree_tag(
                &[(key, order_leaf(domain, key, None).unwrap())],
                0,
                key,
                &mut absence,
                tag,
            );
            let insert = |ar, or, p: &TraderLeafV2, ap: &[Hash32], op: &[Hash32]| {
                stage_ecx_indexed_admission(
                    ar,
                    or,
                    economics,
                    buy.signed.clone(),
                    EcxAccountOpeningV1 {
                        position: p,
                        cash: &cash,
                        siblings: ap,
                    },
                    op,
                    1,
                    &[], Price::new(3_000_000_000).unwrap(),
                    Price::new(3_000_000_000).unwrap(), 0, 1,
                )
            };
            let result = insert(account_root, empty_root, &old, &account_path, &absence).unwrap();
            assert_eq!(result.position, long);
            assert_eq!(result.order, buy);
            let mark = Price::new(3_000_000_000).unwrap();
            let needed = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1(
                result.orders_root, economics, &[&result.order], &result.position,
                &cash, 1, mark, mark, 0).unwrap().try_to_i128().unwrap();
            let needed = u64::try_from(needed).unwrap();
            assert!(needed > 0);
            for (atoms, accepted) in [(needed - 1, false), (needed, true)] {
                let funded = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(atoms));
                let mut funded_path = Vec::new();
                let funded_root = tree(&[(old.key(),
                    ecx_account_commitment(domain, &old, &funded, bounds).unwrap())],
                    0, old.key(), &mut funded_path);
                let staged = stage_ecx_indexed_admission(
                    funded_root, empty_root, economics, buy.signed.clone(),
                    EcxAccountOpeningV1 { position: &old, cash: &funded, siblings: &funded_path },
                    &absence, 1, &[], mark, mark, 0, 1);
                if accepted {
                    let admitted = staged.unwrap();
                    assert_eq!(admitted.orders_root, result.orders_root);
                    let cancel = crate::ecx_cancel_v1::SignedEcxCancelV1::sign(domain,
                        crate::successor_action_v2::SuccessorCancelOrderV2 {
                            version: 2, chain_id: domain.chain_id, market: domain.market,
                            trader: admitted.position.trader, order_id: key,
                            nonce: admitted.position.account_nonce, valid_from_height: 1, expires_at_height: 3,
                        }, &keys[0]).unwrap();
                    let cancelled = crate::ecx_cancel_v1::stage_ecx_cancel_v1(
                        admitted.accounts_root, admitted.orders_root, economics, &cancel,
                        EcxAccountOpeningV1 { position: &admitted.position, cash: &funded, siblings: &funded_path },
                        &admitted.order, &absence, 1).unwrap();
                    assert_eq!(cancelled.orders_root, empty_root);
                    let check_cancel = |signed: &crate::ecx_cancel_v1::SignedEcxCancelV1,
                        account_root, book_root, height| {
                        crate::ecx_cancel_v1::stage_ecx_cancel_v1(account_root, book_root,
                            economics, signed, EcxAccountOpeningV1 {
                                position: &admitted.position, cash: &funded, siblings: &funded_path,
                            }, &admitted.order, &absence, height)
                    };
                    // Inclusive validity endpoints; no execution outside them.
                    assert_eq!(check_cancel(&cancel, admitted.accounts_root, admitted.orders_root, 3).unwrap(), cancelled);
                    for height in [0, 4] {
                        assert_eq!(check_cancel(&cancel, admitted.accounts_root, admitted.orders_root, height),
                            Err(ProtocolError::OrderNotLive));
                    }
                    let mut wrong = cancel.clone(); wrong.signature.0[0] ^= 1;
                    assert!(check_cancel(&wrong, admitted.accounts_root, admitted.orders_root, 1).is_err());
                    for field in 0..3 {
                        let mut wrong = cancel.clone();
                        match field {
                            0 => wrong.domain.chain_id[0] ^= 1,
                            1 => wrong.domain.configuration_hash[0] ^= 1,
                            _ => wrong.domain.collateral_asset[0] ^= 1,
                        }
                        assert!(check_cancel(&wrong, admitted.accounts_root, admitted.orders_root, 1).is_err());
                    }
                    // Even correctly signed commands cannot cancel a different
                    // order or skip the authenticated account nonce.
                    for field in 0..2 {
                        let mut request = cancel.cancel.clone();
                        if field == 0 { request.order_id[0] ^= 1; }
                        else { request.nonce += 1; }
                        let wrong = crate::ecx_cancel_v1::SignedEcxCancelV1::sign(domain, request, &keys[0]).unwrap();
                        assert!(check_cancel(&wrong, admitted.accounts_root, admitted.orders_root, 1).is_err());
                    }
                    let mut wrong_accounts = admitted.accounts_root; wrong_accounts[0] ^= 1;
                    let mut wrong_book = admitted.orders_root; wrong_book[0] ^= 1;
                    assert!(check_cancel(&cancel, wrong_accounts, admitted.orders_root, 1).is_err());
                    assert!(check_cancel(&cancel, admitted.accounts_root, wrong_book, 1).is_err());
                    let mut expected_position = admitted.position.clone();
                    expected_position.account_nonce += 1;
                    assert_eq!(cancelled.position, expected_position);
                    let reserve_after = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1(
                        cancelled.orders_root, economics, &[], &cancelled.position, &funded,
                        1, mark, mark, 0).unwrap().try_to_i128().unwrap();
                    assert_eq!(reserve_after, 0);
                    let withdrawal = |root, p: &TraderLeafV2, book_root, records: &[&EcxAdmittedOrderV2]| {
                        let signed = crate::ecx_withdrawal_v1::SignedEcxWithdrawalV1::sign(domain,
                            crate::successor_action_v2::SuccessorWithdrawalRequestV2 {
                                version: 2, chain_id: domain.chain_id, trader: p.trader, nonce: p.account_nonce,
                                amount: atoms, destination_script_hash: [73;32], requested_height: 1, not_before_height: 1,
                            }, &keys[0]).unwrap();
                        crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(root, economics, &signed,
                            EcxAccountOpeningV1 { position: p, cash: &funded, siblings: &funded_path },
                            1, mark, mark, 0, crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: book_root, records })
                    };
                    assert_eq!(withdrawal(admitted.accounts_root, &admitted.position,
                        admitted.orders_root, &[&admitted.order]), Err(ProtocolError::InsufficientCollateral));
                    let withdrawn = withdrawal(cancelled.accounts_root, &cancelled.position,
                        cancelled.orders_root, &[]).unwrap();
                    assert_eq!(withdrawn.cash.balance().0, 0);
                    assert_eq!(withdrawn.position.account_nonce, admitted.position.account_nonce + 2);
                    // Cancellation cannot be replayed at the resulting nonce/root.
                    assert!(crate::ecx_cancel_v1::stage_ecx_cancel_v1(cancelled.accounts_root,
                        cancelled.orders_root, economics, &cancel,
                        EcxAccountOpeningV1 { position: &cancelled.position, cash: &funded, siblings: &funded_path },
                        &admitted.order, &absence, 1).is_err());
                } else {
                    assert_eq!(staged, Err(ProtocolError::InsufficientCollateral));
                }
                assert_eq!(old.account_nonce, 0);
                assert_eq!(funded.balance().0, atoms);
                assert!(funded.outstanding_claims().is_empty());
            }
            assert_eq!(
                result.accounts_root,
                tree(
                    &[(
                        old.key(),
                        ecx_account_commitment(domain, &long, &cash, bounds).unwrap()
                    )],
                    0,
                    old.key(),
                    &mut Vec::new()
                )
            );
            assert_eq!(
                result.orders_root,
                tree_tag(
                    &[(key, order_leaf(domain, key, Some(&buy)).unwrap())],
                    0,
                    key,
                    &mut Vec::new(),
                    tag
                )
            );
            // Duplicate insertion fails even with the original account opening.
            assert!(insert(
                account_root,
                result.orders_root,
                &old,
                &account_path,
                &absence
            )
            .is_err());
            // Consumed nonce cannot be reused even if the order was removed.
            assert!(insert(
                result.accounts_root,
                empty_root,
                &long,
                &account_path,
                &absence
            )
            .is_err());
            assert!(insert(
                result.accounts_root,
                empty_root,
                &old,
                &account_path,
                &absence
            )
            .is_err());
            assert!(insert(
                account_root,
                empty_root,
                &old,
                &account_path[..255],
                &absence
            )
            .is_err());
            assert!(insert(
                account_root,
                empty_root,
                &old,
                &account_path,
                &absence[..255]
            )
            .is_err());
            let mut altered = absence.clone();
            altered[0][0] ^= 1;
            assert!(insert(account_root, empty_root, &old, &account_path, &altered).is_err());
            assert_eq!(old.account_nonce, 0);
            // Valid signatures, valid account and absence openings are not
            // authority for protocol reserve accounts to trade.
            for secret_byte in [9, 10] {
                let key = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
                let reserve = position(&key);
                let mut order = buy.signed.order.clone();
                order.trader = reserve.trader;
                let signed = SignedEcxOrderV1::sign(domain, order, &key).unwrap();
                signed.verify(domain).unwrap();
                let mut ap = Vec::new();
                let ar = tree(&[(reserve.key(),
                    ecx_account_commitment(domain, &reserve, &cash, bounds).unwrap())],
                    0, reserve.key(), &mut ap);
                let id = signed.order_id().unwrap();
                let mut op = Vec::new();
                let or = tree_tag(&[(id, order_leaf(domain, id, None).unwrap())],
                    0, id, &mut op, tag);
                // Lower-level signature/nonce admission is otherwise valid.
                assert!(EcxAdmittedOrderV2::admit(signed.clone(), domain,
                    &reserve, 1, bounds, 1).is_ok());
                assert_eq!(stage_ecx_indexed_admission(ar, or, economics, signed,
                    EcxAccountOpeningV1 { position: &reserve, cash: &cash, siblings: &ap },
                    &op, 1, &[], Price::new(3_000_000_000).unwrap(),
                    Price::new(3_000_000_000).unwrap(), 0, 1), Err(ProtocolError::InvalidBondState));
                assert_eq!(reserve.account_nonce, 0);
            }
        }
        let opened = stage_ecx_match(
            domain,
            &buy,
            &sell,
            &long,
            &short,
            &cash,
            &cash,
            clearing_key,
            &cash,
            1,
            100_000_000,
            Price::new(3_000_000_000).unwrap(),
            0,
            bounds,
        )
        .unwrap();
        let (sell, long) = admit(&opened.maker_position, &keys[0], Side::Sell, 6_000_000_000);
        let (buy, short) = admit(&opened.taker_position, &keys[1], Side::Buy, 6_000_000_000);
        let close = |short_cash: &EcxCashAccountV1| {
            stage_ecx_match(
                domain,
                &sell,
                &buy,
                &long,
                &short,
                &opened.maker_cash,
                short_cash,
                clearing_key,
                &opened.clearing_cash,
                2,
                100_000_000,
                Price::new(6_000_000_000).unwrap(),
                0,
                bounds,
            )
        };
        let closed = close(&opened.taker_cash).unwrap();
        use crate::ecx_cash_account_v1::ecx_account_commitment;
        let mut clearing_position = position(&SecretKey::from_slice(&[9; 32]).unwrap());
        clearing_position.trader = clearing_key;
        let leaf = |p: &TraderLeafV2, c: &EcxCashAccountV1| {
            (
                p.trader.0,
                ecx_account_commitment(domain, p, c, bounds).unwrap(),
            )
        };
        let mut leaves = vec![
            leaf(&long, &opened.maker_cash),
            leaf(&short, &opened.taker_cash),
            leaf(&clearing_position, &opened.clearing_cash),
        ];
        let mut maker_path = Vec::new();
        let source_root = tree(&leaves, 0, long.trader.0, &mut maker_path);
        let mut stale_taker_path = Vec::new();
        tree(&leaves, 0, short.trader.0, &mut stale_taker_path);
        leaves[0] = leaf(&closed.maker_position, &closed.maker_cash);
        let mut taker_path = Vec::new();
        tree(&leaves, 0, short.trader.0, &mut taker_path);
        leaves[1] = leaf(&closed.taker_position, &closed.taker_cash);
        let mut clearing_path = Vec::new();
        tree(&leaves, 0, clearing_key.0, &mut clearing_path);
        leaves[2] = leaf(&clearing_position, &closed.clearing_cash);
        let expected_root = tree(&leaves, 0, clearing_key.0, &mut Vec::new());
        let update = |taker_path: &[Hash32]| {
            stage_ecx_matched_accounts(
                source_root,
                domain,
                &sell,
                &buy,
                EcxAccountOpeningV1 {
                    position: &long,
                    cash: &opened.maker_cash,
                    siblings: &maker_path,
                },
                EcxAccountOpeningV1 {
                    position: &short,
                    cash: &opened.taker_cash,
                    siblings: taker_path,
                },
                clearing_key,
                EcxAccountOpeningV1 {
                    position: &clearing_position,
                    cash: &opened.clearing_cash,
                    siblings: &clearing_path,
                },
                2,
                100_000_000,
                Price::new(6_000_000_000).unwrap(),
                0,
                bounds,
            )
        };
        let committed = update(&taker_path).unwrap();
        assert_eq!(committed.root, expected_root);
        assert_eq!(committed.trade, closed);
        assert!(update(&stale_taker_path).is_err());
        use crate::ecx_order_index_v1::{
            order_leaf, stage_ecx_risk_checked_match, stage_ecx_committed_match,
            EcxExecutionContextV1, EcxIndexedOrderOpeningV1, EcxMatchRiskV1,
        };
        let maker_id = sell.signed.order_id().unwrap();
        let taker_id = buy.signed.order_id().unwrap();
        let tag = "ECX/ecx-order-index-node/v1";
        let mut order_leaves = vec![
            (maker_id, order_leaf(domain, maker_id, Some(&sell)).unwrap()),
            (taker_id, order_leaf(domain, taker_id, Some(&buy)).unwrap()),
        ];
        let mut maker_order_path = Vec::new();
        let orders_root = tree_tag(&order_leaves, 0, maker_id, &mut maker_order_path, tag);
        // Reservation selection authenticates the ENTIRE book before filtering
        // by owner. Omitting another trader is still an invalid root opening.
        use crate::ecx_order_index_v1::ecx_outstanding_orders_v1;
        let outstanding = |book: &[&EcxAdmittedOrderV2], owner: &TraderLeafV2, height| {
            ecx_outstanding_orders_v1(orders_root, domain, book, owner, height, bounds)
                .map(|records| records.iter().map(|r| r.signed.order_id().unwrap()).collect::<Vec<_>>())
        };
        assert_eq!(outstanding(&[&sell, &buy], &long, 2).unwrap(), vec![maker_id]);
        // Selection never drops an unexpired record merely because the
        // consuming clock precedes its signed valid-from height.
        assert_eq!(outstanding(&[&sell, &buy], &long, 0).unwrap(), vec![maker_id]);
        assert_eq!(outstanding(&[&buy, &sell], &long, 2).unwrap(), vec![maker_id]);
        assert!(outstanding(&[&sell], &long, 2).is_err());
        assert!(outstanding(&[&sell, &sell, &buy], &long, 2).is_err());
        let mut altered = sell.clone(); altered.remaining -= 1;
        assert!(outstanding(&[&altered, &buy], &long, 2).is_err());
        assert_eq!(outstanding(&[&sell, &buy], &long, sell.signed.order.expires_at_height)
            .unwrap(), vec![maker_id]);
        assert!(outstanding(&[&sell, &buy], &long, sell.signed.order.expires_at_height + 1)
            .unwrap().is_empty());
        let mut cancelled = long.clone(); cancelled.order_generation += 1;
        assert!(outstanding(&[&sell, &buy], &cancelled, 2).unwrap().is_empty());
        let mut unadmitted = long.clone(); unadmitted.account_nonce = sell.signed.order.nonce;
        assert!(outstanding(&[&sell, &buy], &unadmitted, 2).is_err());
        let mut stale_order_path = Vec::new();
        // Compose signed whole-book authentication with role-aware fees.
        let ordinary_limit = sell.signed.order.limit_price.get();
        for (side, post_only, cap, limit, expected_price, expected_rate) in [
            (Side::Sell, false, 5, ordinary_limit, bounds.maximum_price_atoms, 5),
            (Side::Buy, false, 5, ordinary_limit, ordinary_limit, 5),
            (Side::Sell, true, 5, ordinary_limit, ordinary_limit, 2),
            (Side::Sell, false, 2, ordinary_limit, ordinary_limit, 2),
            (Side::Sell, false, 0, ordinary_limit, ordinary_limit, 0),
            // Boundary is inclusive. Above it a sell cannot fill, whereas
            // a non-post-only buy can still take at a lower admissible price.
            (Side::Sell, false, 5, bounds.maximum_price_atoms, bounds.maximum_price_atoms, 5),
            (Side::Sell, false, 5, bounds.maximum_price_atoms + 1, ordinary_limit, 0),
            (Side::Buy, false, 5, bounds.maximum_price_atoms + 1, bounds.maximum_price_atoms, 5),
            (Side::Buy, true, 5, bounds.maximum_price_atoms + 1, ordinary_limit, 0),
        ] {
            let mut configured = economics;
            configured.risk.maker_fee_bps = 2;
            configured.risk.taker_fee_bps = 5;
            let fee_domain = configured.account_domain().unwrap();
            let mut payload = sell.signed.order.clone();
            payload.side = side;
            payload.limit_price = Price::new(limit).unwrap();
            payload.max_fee_bps = cap;
            payload.flags = if post_only { OrderFlags::POST_ONLY } else { OrderFlags::from_bits(0).unwrap() };
            let record = EcxAdmittedOrderV2 {
                signed: SignedEcxOrderV1::sign(fee_domain, payload, &keys[0]).unwrap(),
                remaining: sell.remaining, generation: sell.generation,
                received_sequence: sell.received_sequence,
            };
            let key = record.signed.order_id().unwrap();
            let root = tree_tag(&[(key, order_leaf(fee_domain, key, Some(&record)).unwrap())],
                0, key, &mut Vec::new(), tag);
            let reserve = crate::ecx_order_index_v1::ecx_outstanding_fee_reserve_quote_v1;
            let expected = crate::ecx_cash_account_v1::ecx_partial_fill_fee_reserve_quote_v1(
                Price::new(expected_price).unwrap(), Quantity::new(record.remaining).unwrap(),
                expected_rate, cap).unwrap();
            assert_eq!(reserve(root, configured, &[&record], &long, 2).unwrap(), expected);
            assert!(reserve(root, configured, &[], &long, 2).is_err());
            assert_eq!(reserve(root, configured, &[&record], &cancelled, 2).unwrap().0, 0);
            let backing = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(1_000_000_000_000));
            let snapshot = backing.clone();
            let aggregate = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1;
            let mark = Price::new(6_000_000_000).unwrap();
            let required = aggregate(root, configured, &[&record], &long, &backing, 2,
                mark, mark, 0).unwrap();
            assert!(required >= Int256V2::ZERO);
            assert!(aggregate(root, configured, &[], &long, &backing, 2, mark, mark, 0).is_err());
            assert!(aggregate(root, configured, &[&record, &record], &long, &backing, 2,
                mark, mark, 0).is_err());
            let released = aggregate(root, configured, &[&record], &cancelled, &backing, 2,
                mark, mark, 0).unwrap();
            assert!(released <= required);
            assert_eq!(backing, snapshot, "risk reservation must never change cash");
            let (debt, credit) = crate::ecx_cash_account_v1::settle_account_pnl(
                &backing, &backing, Int256V2::from_i128(-1), mark).unwrap();
            assert_eq!(aggregate(root, configured, &[&record], &long, &debt, 2,
                mark, mark, 0).unwrap(), required.checked_add(Int256V2::from_i128(1)).unwrap());
            assert_eq!(aggregate(root, configured, &[&record], &long, &credit, 2,
                mark, mark, 0).unwrap(), required, "uncollected positive fractions are not physical cash");
            let path = vec![[42; 32]; 256];
            let account_root = crate::ecx_cash_account_v1::ecx_account_root(
                fee_domain, &long, &backing, bounds, &path).unwrap();
            let withdrawal = crate::ecx_withdrawal_v1::SignedEcxWithdrawalV1::sign(
                fee_domain, crate::successor_action_v2::SuccessorWithdrawalRequestV2 {
                    version: 2, chain_id: fee_domain.chain_id, trader: long.trader,
                    nonce: long.account_nonce, amount: 1, destination_script_hash: [71; 32],
                    requested_height: 2, not_before_height: 2,
                }, &keys[0]).unwrap();
            let stage = |book| crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                account_root, configured, &withdrawal,
                EcxAccountOpeningV1 { position: &long, cash: &backing, siblings: &path },
                2, Price::new(6_000_000_000).unwrap(), Price::new(6_000_000_000).unwrap(), 0,
                crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root, records: book });
            let complete_book = [&record];
            let updated = stage(&complete_book).unwrap();
            assert_eq!(updated.cash.balance().0, backing.balance().0 - 1);
            assert_eq!(updated.cash.outstanding_claims(), backing.outstanding_claims());
            assert!(stage(&[]).is_err());
            // The signed one-atom withdrawal cannot consume reserved cash.
            // Open the actual bounded account, rather than substituting a
            // balance underneath an unrelated account root.
            if required > Int256V2::ZERO {
                let reserve_atoms = u64::try_from(required.try_to_i128().unwrap()).unwrap();
                let bounded = crate::ecx_cash_account_v1::EcxCashAccountV1::from_funded_balance(
                    crate::ecx_collateral::EcxCollateralAtoms(reserve_atoms));
                let bounded_root = crate::ecx_cash_account_v1::ecx_account_root(
                    fee_domain, &long, &bounded, bounds, &path).unwrap();
                assert_eq!(crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                    bounded_root, configured, &withdrawal,
                    EcxAccountOpeningV1 { position: &long, cash: &bounded, siblings: &path },
                    2, mark, mark, 0,
                    crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root, records: &complete_book }),
                    Err(ProtocolError::InsufficientCollateral));
                assert_eq!(bounded.balance().0, reserve_atoms);
                assert!(bounded.outstanding_claims().is_empty());
            }
            // A valid signature and matching book root are insufficient if
            // admission has not consumed the order nonce in the source account.
            // Withdrawal's own nonce increment must not accidentally admit it.
            let mut unadmitted = record.clone();
            let mut unsigned = unadmitted.signed.order.clone();
            unsigned.nonce = long.account_nonce;
            unadmitted.signed = SignedEcxOrderV1::sign(fee_domain, unsigned, &keys[0]).unwrap();
            let unadmitted_key = unadmitted.signed.order_id().unwrap();
            let unadmitted_root = tree_tag(&[(unadmitted_key,
                order_leaf(fee_domain, unadmitted_key, Some(&unadmitted)).unwrap())],
                0, unadmitted_key, &mut Vec::new(), tag);
            assert!(crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                account_root, configured, &withdrawal,
                EcxAccountOpeningV1 { position: &long, cash: &backing, siblings: &path },
                2, Price::new(6_000_000_000).unwrap(), Price::new(6_000_000_000).unwrap(), 0,
                crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                    root: unadmitted_root, records: &[&unadmitted] }).is_err());
        }
        tree_tag(&order_leaves, 0, taker_id, &mut stale_order_path, tag);
        order_leaves[0].1 = order_leaf(domain, maker_id, None).unwrap();
        let mut taker_order_path = Vec::new();
        tree_tag(&order_leaves, 0, taker_id, &mut taker_order_path, tag);
        order_leaves[1].1 = order_leaf(domain, taker_id, None).unwrap();
        let expected_orders_root = tree_tag(&order_leaves, 0, taker_id, &mut Vec::new(), tag);
        let context = EcxExecutionContextV1 {
            parent_hash: [31; 32], parent_height: 10, parent_mtp: 1234,
            match_sequence: 2,
        };
        let indexed_context = |root, second_path: &[Hash32], context, economics| {
            stage_ecx_committed_match(
                source_root,
                root,
                economics,
                EcxIndexedOrderOpeningV1 {
                    order: &sell,
                    account: EcxAccountOpeningV1 {
                        position: &long,
                        cash: &opened.maker_cash,
                        siblings: &maker_path,
                    },
                    order_siblings: &maker_order_path,
                },
                EcxIndexedOrderOpeningV1 {
                    order: &buy,
                    account: EcxAccountOpeningV1 {
                        position: &short,
                        cash: &opened.taker_cash,
                        siblings: &taker_path,
                    },
                    order_siblings: second_path,
                },
                EcxAccountOpeningV1 {
                    position: &clearing_position,
                    cash: &opened.clearing_cash,
                    siblings: &clearing_path,
                },
                2,
                100_000_000,
                Price::new(6_000_000_000).unwrap(),
                0,
                Price::new(3_000_000_000).unwrap(),
                Price::new(6_000_000_000).unwrap(),
                context,
                None,
                &[&sell, &buy],
            )
        };
        let (staged, digest) = indexed_context(orders_root, &taker_order_path, context, economics).unwrap();
        assert_eq!(staged.accounts, committed);
        // Joined partial fill: current-position margin alone permits the
        // smaller account, but its remaining orders still require collateral.
        // Rebuild all sequential paths from the actual half-fill, not the
        // full-fill paths used above.
        for (atoms, enough) in [(100_000_000, false), (1_000_000_000, true)] {
            let funded = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(atoms));
            let half = stage_ecx_match(domain, &sell, &buy, &long, &short,
                &funded, &funded, clearing_key, &opened.clearing_cash,
                2, 50_000_000, Price::new(6_000_000_000).unwrap(), 0, bounds).unwrap();
            let mut accounts = vec![leaf(&long, &funded), leaf(&short, &funded),
                leaf(&clearing_position, &opened.clearing_cash)];
            let mut mp = Vec::new();
            let root = tree(&accounts, 0, long.key(), &mut mp);
            accounts[0] = leaf(&half.maker_position, &half.maker_cash);
            let mut tp = Vec::new();
            tree(&accounts, 0, short.key(), &mut tp);
            accounts[1] = leaf(&half.taker_position, &half.taker_cash);
            let mut cp = Vec::new();
            tree(&accounts, 0, clearing_key.0, &mut cp);
            let mut book = vec![(maker_id, order_leaf(domain, maker_id, Some(&sell)).unwrap()),
                (taker_id, order_leaf(domain, taker_id, Some(&buy)).unwrap())];
            let mut mop = Vec::new();
            assert_eq!(tree_tag(&book, 0, maker_id, &mut mop, tag), orders_root);
            book[0].1 = order_leaf(domain, maker_id, half.maker_order.as_ref()).unwrap();
            let mut top = Vec::new();
            tree_tag(&book, 0, taker_id, &mut top, tag);
            let openings = || (
                EcxIndexedOrderOpeningV1 { order: &sell, order_siblings: &mop,
                    account: EcxAccountOpeningV1 { position: &long, cash: &funded, siblings: &mp } },
                EcxIndexedOrderOpeningV1 { order: &buy, order_siblings: &top,
                    account: EcxAccountOpeningV1 { position: &short, cash: &funded, siblings: &tp } },
                EcxAccountOpeningV1 { position: &clearing_position,
                    cash: &opened.clearing_cash, siblings: &cp });
            let low = Price::new(3_000_000_000).unwrap();
            let high = Price::new(6_000_000_000).unwrap();
            let (m, t, c) = openings();
            stage_ecx_risk_checked_match(root, orders_root, domain, m, t,
                clearing_key, c, 2, 50_000_000, high, 0,
                EcxMatchRiskV1 { low, high, cash_scale: economics.cash_valuation_scale,
                    initial_margin_floor_bps: economics.risk.initial_margin_bps }, bounds).unwrap();
            let (m, t, c) = openings();
            let checked = stage_ecx_committed_match(root, orders_root, economics,
                m, t, c, 2, 50_000_000, high, 0, low, high, context, None, &[&sell, &buy]);
            if enough {
                let matched = checked.unwrap().0;
                let trade = &matched.accounts.trade;
                assert_eq!(trade, &half);
                let remaining = [trade.maker_order.as_ref().unwrap(), trade.taker_order.as_ref().unwrap()];
                assert_eq!(remaining[0].remaining, 50_000_000);
                assert_eq!(remaining[1].remaining, 50_000_000);
                // Spend only the recomputed unreserved balance after the real
                // half-fill; source nonce and the remaining book stay bound.
                let reserve = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1(
                    matched.orders_root, economics, &remaining, &trade.maker_position,
                    &trade.maker_cash, 2, low, high, 0).unwrap().try_to_i128().unwrap();
                let reserve = u64::try_from(reserve).unwrap();
                let available = trade.maker_cash.balance().0.checked_sub(reserve).unwrap();
                assert!(available > 0);
                let final_accounts = vec![leaf(&trade.maker_position, &trade.maker_cash),
                    leaf(&trade.taker_position, &trade.taker_cash),
                    leaf(&clearing_position, &trade.clearing_cash)];
                let mut withdrawal_path = Vec::new();
                assert_eq!(tree(&final_accounts, 0, trade.maker_position.key(),
                    &mut withdrawal_path), matched.accounts.root);
                let key = keys.iter().find(|key| position(key).trader == trade.maker_position.trader).unwrap();
                let mut cancel_path = Vec::new();
                let remaining_leaves = remaining.iter().map(|record| {
                    let id = record.signed.order_id().unwrap();
                    (id, order_leaf(domain, id, Some(record)).unwrap())
                }).collect::<Vec<_>>();
                assert_eq!(tree_tag(&remaining_leaves, 0, maker_id, &mut cancel_path, tag), matched.orders_root);
                let cancel = crate::ecx_cancel_v1::SignedEcxCancelV1::sign(domain,
                    crate::successor_action_v2::SuccessorCancelOrderV2 {
                        version: 2, chain_id: domain.chain_id, market: domain.market,
                        trader: trade.maker_position.trader, order_id: maker_id,
                        nonce: trade.maker_position.account_nonce, valid_from_height: 2, expires_at_height: 3,
                    }, key).unwrap();
                let cancelled = crate::ecx_cancel_v1::stage_ecx_cancel_v1(
                    matched.accounts.root, matched.orders_root, economics, &cancel,
                    EcxAccountOpeningV1 { position: &trade.maker_position, cash: &trade.maker_cash,
                        siblings: &withdrawal_path }, remaining[0], &cancel_path, 2).unwrap();
                let mut expected = trade.maker_position.clone();
                expected.account_nonce += 1;
                assert_eq!(cancelled.position, expected);
                let released_reserve = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1(
                    cancelled.orders_root, economics, &remaining[1..], &cancelled.position,
                    &trade.maker_cash, 2, low, high, 0).unwrap().try_to_i128().unwrap();
                // Cancelling a reducing order need not lower the reserve:
                // the existing position can still dominate required margin.
                assert!(released_reserve <= i128::from(reserve));
                assert!(crate::ecx_order_index_v1::ecx_outstanding_orders_v1(
                    cancelled.orders_root, domain, &remaining[1..], &cancelled.position,
                    2, bounds).unwrap().is_empty());
                let mut legacy = cancel.clone();
                legacy.signature = crate::successor_action_v2::SuccessorSignedCancelOrderV2::sign(
                    cancel.cancel.clone(), key).unwrap().signature;
                assert!(legacy.verify(domain).is_err());
                for (amount, accepted) in [(available, true), (available + 1, false)] {
                    let signed = crate::ecx_withdrawal_v1::SignedEcxWithdrawalV1::sign(domain,
                        crate::successor_action_v2::SuccessorWithdrawalRequestV2 {
                            version: 2, chain_id: domain.chain_id, trader: trade.maker_position.trader,
                            nonce: trade.maker_position.account_nonce, amount,
                            destination_script_hash: [71; 32], requested_height: 2, not_before_height: 2,
                        }, key).unwrap();
                    let result = crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                        matched.accounts.root, economics, &signed,
                        EcxAccountOpeningV1 { position: &trade.maker_position, cash: &trade.maker_cash,
                            siblings: &withdrawal_path }, 2, low, high, 0,
                        crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                            root: matched.orders_root, records: &remaining });
                    if accepted {
                        let updated = result.unwrap();
                        assert_eq!(updated.cash.balance().0, reserve);
                        assert_eq!(updated.position.account_nonce, trade.maker_position.account_nonce + 1);
                    } else {
                        assert_eq!(result, Err(ProtocolError::InsufficientCollateral));
                    }
                    // A caller cannot release reservation by asserting a new
                    // generation without changing the authenticated account.
                    let mut forged = trade.maker_position.clone();
                    forged.order_generation += 1;
                    assert!(crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                        matched.accounts.root, economics, &signed,
                        EcxAccountOpeningV1 { position: &forged, cash: &trade.maker_cash,
                            siblings: &withdrawal_path }, 2, low, high, 0,
                        crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                            root: matched.orders_root, records: &remaining }).is_err());
                    // Nor can even the owner omit the remaining order while
                    // retaining the authenticated book root and valid consent.
                    assert!(crate::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
                        matched.accounts.root, economics, &signed,
                        EcxAccountOpeningV1 { position: &trade.maker_position, cash: &trade.maker_cash,
                            siblings: &withdrawal_path }, 2, low, high, 0,
                        crate::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                            root: matched.orders_root, records: &remaining[1..] }).is_err());
                }
            } else {
                assert_eq!(checked, Err(ProtocolError::InsufficientCollateral));
            }
            assert_eq!(funded.balance().0, atoms);
        }
        let check_remaining = |book: &[&EcxAdmittedOrderV2], result: &crate::ecx_order_index_v1::EcxIndexedMatchV1| {
            crate::ecx_order_index_v1::verify_ecx_post_match_reserve_v1(
                orders_root, book, maker_id, taker_id, economics, result, 2,
                Price::new(3_000_000_000).unwrap(),
                Price::new(6_000_000_000).unwrap(), 0)
        };
        check_remaining(&[&sell, &buy], &staged).unwrap();
        assert!(check_remaining(&[&sell], &staged).is_err());
        assert!(check_remaining(&[&sell, &buy, &buy], &staged).is_err());
        let mut wrong_book = staged.clone();
        wrong_book.orders_root = orders_root;
        assert!(check_remaining(&[&sell, &buy], &wrong_book).is_err());
        let mut wrong_remainder = staged.clone();
        wrong_remainder.accounts.trade.maker_order = Some(sell.clone());
        assert!(check_remaining(&[&sell, &buy], &wrong_remainder).is_err());
        for changed in [
            EcxExecutionContextV1 { parent_hash: [32; 32], ..context },
            EcxExecutionContextV1 { parent_height: 11, ..context },
            EcxExecutionContextV1 { parent_mtp: 1235, ..context },
            EcxExecutionContextV1 { match_sequence: 3, ..context },
        ] {
            let (same, other) = indexed_context(orders_root, &taker_order_path, changed, economics).unwrap();
            assert_eq!(same, staged);
            assert_ne!(other, digest);
        }
        for invalid in [
            EcxExecutionContextV1 { parent_hash: [0; 32], ..context },
            EcxExecutionContextV1 { parent_height: 0, ..context },
            EcxExecutionContextV1 { parent_mtp: 0, ..context },
            EcxExecutionContextV1 { match_sequence: 0, ..context },
        ] {
            assert!(indexed_context(orders_root, &taker_order_path, invalid, economics).is_err());
        }
        let indexed = |root, path: &[Hash32]| {
            indexed_context(root, path, context, economics).map(|(result, _)| result)
        };
        for changed in [
            crate::ecx_configuration_v1::EcxConfigurationV1 {
                cash_valuation_scale: 1, ..economics
            },
            crate::ecx_configuration_v1::EcxConfigurationV1 {
                clearing_account: long.trader, ..economics
            },
            crate::ecx_configuration_v1::EcxConfigurationV1 {
                risk: crate::risk::RiskParams { initial_margin_bps: 900, ..economics.risk },
                ..economics
            },
            crate::ecx_configuration_v1::EcxConfigurationV1 {
                bounds: IncrementalAccountingBoundsV2 {
                    maximum_price_atoms: bounds.maximum_price_atoms + 1, ..bounds
                }, ..economics
            },
        ] {
            assert!(indexed_context(orders_root, &taker_order_path, context, changed).is_err());
        }
        let result = indexed(orders_root, &taker_order_path).unwrap();
        assert_eq!(result.orders_root, expected_orders_root);
        assert_eq!(result.accounts, committed);
        assert!(indexed(orders_root, &stale_order_path).is_err());
        assert!(indexed(result.orders_root, &taker_order_path).is_err());
        assert!(indexed(orders_root, &taker_order_path[..255]).is_err());
        // Partial fills must pass economic checks, not merely membership checks.
        let partial = stage_ecx_match(
            domain,
            &sell,
            &buy,
            &long,
            &short,
            &opened.maker_cash,
            &opened.taker_cash,
            clearing_key,
            &opened.clearing_cash,
            2,
            50_000_000,
            Price::new(6_000_000_000).unwrap(),
            0,
            bounds,
        )
        .unwrap();
        let mut partial_leaves = vec![
            leaf(&partial.maker_position, &partial.maker_cash),
            leaf(&short, &opened.taker_cash),
            leaf(&clearing_position, &opened.clearing_cash),
        ];
        let mut partial_taker_path = Vec::new();
        tree(&partial_leaves, 0, short.trader.0, &mut partial_taker_path);
        partial_leaves[1] = leaf(&partial.taker_position, &partial.taker_cash);
        let mut partial_clearing_path = Vec::new();
        tree(
            &partial_leaves,
            0,
            clearing_key.0,
            &mut partial_clearing_path,
        );
        partial_leaves[2] = leaf(&clearing_position, &partial.clearing_cash);
        let partial_root = tree(&partial_leaves, 0, clearing_key.0, &mut Vec::new());
        let mut partial_orders = vec![
            (
                maker_id,
                order_leaf(domain, maker_id, partial.maker_order.as_ref()).unwrap(),
            ),
            (taker_id, order_leaf(domain, taker_id, Some(&buy)).unwrap()),
        ];
        let mut partial_order_path = Vec::new();
        tree_tag(&partial_orders, 0, taker_id, &mut partial_order_path, tag);
        partial_orders[1].1 = order_leaf(domain, taker_id, partial.taker_order.as_ref()).unwrap();
        let partial_orders_root = tree_tag(&partial_orders, 0, taker_id, &mut Vec::new(), tag);
        let checked_partial = |low| {
            stage_ecx_risk_checked_match(
                source_root,
                orders_root,
                domain,
                EcxIndexedOrderOpeningV1 {
                    order: &sell,
                    account: EcxAccountOpeningV1 {
                        position: &long,
                        cash: &opened.maker_cash,
                        siblings: &maker_path,
                    },
                    order_siblings: &maker_order_path,
                },
                EcxIndexedOrderOpeningV1 {
                    order: &buy,
                    account: EcxAccountOpeningV1 {
                        position: &short,
                        cash: &opened.taker_cash,
                        siblings: &partial_taker_path,
                    },
                    order_siblings: &partial_order_path,
                },
                clearing_key,
                EcxAccountOpeningV1 {
                    position: &clearing_position,
                    cash: &opened.clearing_cash,
                    siblings: &partial_clearing_path,
                },
                2,
                50_000_000,
                Price::new(6_000_000_000).unwrap(),
                0,
                EcxMatchRiskV1 {
                    low: Price::new(low).unwrap(),
                    high: Price::new(6_000_000_000).unwrap(),
                    cash_scale: 1_000_000,
                    initial_margin_floor_bps: 1000,
                },
                bounds,
            )
        };
        let accepted = checked_partial(3_000_000_000).unwrap();
        assert_eq!(accepted.accounts.root, partial_root);
        assert_eq!(accepted.orders_root, partial_orders_root);
        assert_eq!(accepted.accounts.trade, partial);
        assert_eq!(partial.maker_position.position_size_atoms, 50_000_000);
        assert_eq!(partial.taker_position.position_size_atoms, -50_000_000);
        assert_eq!(partial.maker_position.account_nonce, long.account_nonce);
        assert_eq!(partial.taker_position.account_nonce, short.account_nonce);
        assert_eq!(partial.maker_order.as_ref().unwrap().remaining, 50_000_000);
        assert_eq!(partial.taker_order.as_ref().unwrap().remaining, 50_000_000);
        assert_eq!(
            partial.maker_cash.balance(),
            EcxCollateralAtoms(125_000_000)
        );
        assert_eq!(partial.taker_cash.balance(), EcxCollateralAtoms(75_000_000));
        // Same authenticated leaves and paths: only the risk interval changes.
        assert_eq!(
            checked_partial(100_000_000),
            Err(ProtocolError::InsufficientCollateral)
        );
        verify_ecx_cash_conservation(
            &[
                partial.maker_cash,
                partial.taker_cash,
                partial.clearing_cash,
            ],
            300_000_000,
        )
        .unwrap();
        assert_eq!(closed.maker_position.position_size_atoms, 0);
        assert_eq!(closed.taker_position.position_size_atoms, 0);
        assert_eq!(closed.maker_cash.balance(), EcxCollateralAtoms(150_000_000));
        assert_eq!(closed.taker_cash.balance(), EcxCollateralAtoms(50_000_000));
        assert_eq!(closed.clearing_cash, cash);
        // Fee updates must commit the payer and recipient together, using
        // paths for the successive roots, not two paths for the old root.
        let fee_price = Price::new(6_000_000_000).unwrap();
        let fee_quantity = Quantity::new(100_000_000).unwrap();
        let (paid, received) = crate::ecx_cash_account_v1::settle_ecx_execution_fee(
            &closed.taker_cash, &closed.clearing_cash, fee_price, fee_quantity,
            5, 5, fee_price,
        ).unwrap();
        let mut fee_leaves = vec![
            leaf(&closed.maker_position, &closed.maker_cash),
            leaf(&closed.taker_position, &closed.taker_cash),
            leaf(&clearing_position, &closed.clearing_cash),
        ];
        let mut payer_path = Vec::new();
        let fee_source = tree(&fee_leaves, 0, short.trader.0, &mut payer_path);
        let mut stale_recipient = Vec::new();
        tree(&fee_leaves, 0, clearing_key.0, &mut stale_recipient);
        fee_leaves[1] = leaf(&closed.taker_position, &paid);
        let mut recipient_path = Vec::new();
        tree(&fee_leaves, 0, clearing_key.0, &mut recipient_path);
        fee_leaves[2] = leaf(&clearing_position, &received);
        let expected_fee_root = tree(&fee_leaves, 0, clearing_key.0, &mut Vec::new());
        let charge = |root, recipient_key, path: &[Hash32]| {
            crate::ecx_cash_account_v1::stage_ecx_account_fee(
                root, domain,
                EcxAccountOpeningV1 { position: &closed.taker_position,
                    cash: &closed.taker_cash, siblings: &payer_path },
                recipient_key,
                EcxAccountOpeningV1 { position: &clearing_position,
                    cash: &closed.clearing_cash, siblings: path },
                fee_price, fee_quantity, 5, 5, fee_price, bounds,
            )
        };
        assert_eq!(charge(fee_source, clearing_key, &recipient_path).unwrap(),
            (expected_fee_root, paid.clone(), received.clone()));
        assert!(charge(fee_source, clearing_key, &stale_recipient).is_err());
        assert!(charge(expected_fee_root, clearing_key, &recipient_path).is_err());
        assert!(charge(fee_source, short.trader, &recipient_path).is_err());
        assert_eq!(paid.balance(), EcxCollateralAtoms(49_950_000));
        verify_ecx_cash_conservation(&[closed.maker_cash.clone(), paid, received], 300_000_000).unwrap();
        // Full signed close with configured nonzero fees and a fourth,
        // distinct insurance leaf. Derive every successive path independently.
        {
            use crate::ecx_order_index_v1::EcxMatchFeeWitnessV1;
            for maker_rate in [0, 2, -2] {
            let economics = crate::ecx_configuration_v1::EcxConfigurationV1 {
                risk: crate::risk::RiskParams { maker_fee_bps: maker_rate,
                    ..crate::risk::RiskParams::default() }, ..economics
            };
            let domain = economics.account_domain().unwrap();
            let resign = |admitted: &EcxAdmittedOrderV2, key: &SecretKey| {
                let mut order = admitted.signed.order.clone();
                order.max_fee_bps = 5;
                EcxAdmittedOrderV2 { signed: SignedEcxOrderV1::sign(domain, order, key).unwrap(),
                    ..admitted.clone() }
            };
            let sell = resign(&sell, &keys[0]);
            let buy = resign(&buy, &keys[1]);
            let insurance = position(&SecretKey::from_slice(&[10; 32]).unwrap());
            let leaf = |p: &TraderLeafV2, c: &EcxCashAccountV1| {
                (p.key(), ecx_account_commitment(domain, p, c, bounds).unwrap())
            };
            let mut leaves = vec![leaf(&long, &opened.maker_cash),
                leaf(&short, &opened.taker_cash),
                leaf(&clearing_position, &opened.clearing_cash), leaf(&insurance, &cash)];
            let mut mp = Vec::new();
            let source = tree(&leaves, 0, long.key(), &mut mp);
            leaves[0] = leaf(&closed.maker_position, &closed.maker_cash);
            let mut tp = Vec::new();
            tree(&leaves, 0, short.key(), &mut tp);
            leaves[1] = leaf(&closed.taker_position, &closed.taker_cash);
            let mut cp = Vec::new();
            tree(&leaves, 0, clearing_key.0, &mut cp);
            leaves[2] = leaf(&clearing_position, &closed.clearing_cash);
            let mut mfp = Vec::new();
            tree(&leaves, 0, long.key(), &mut mfp);
            let (maker_paid, intermediate_insurance) =
                crate::ecx_cash_account_v1::settle_ecx_execution_fee(
                    &closed.maker_cash, &cash, fee_price, fee_quantity,
                    maker_rate, 5, fee_price,
                ).unwrap();
            leaves[0] = leaf(&closed.maker_position, &maker_paid);
            let mut ip = Vec::new();
            tree(&leaves, 0, insurance.key(), &mut ip);
            leaves[3] = leaf(&insurance, &intermediate_insurance);
            let mut tfp = Vec::new();
            tree(&leaves, 0, short.key(), &mut tfp);
            let (paid, received) = crate::ecx_cash_account_v1::settle_ecx_execution_fee(
                &closed.taker_cash, &intermediate_insurance,
                fee_price, fee_quantity, 5, 5, fee_price,
            ).unwrap();
            leaves[1] = leaf(&closed.taker_position, &paid);
            let mut ifp = Vec::new();
            tree(&leaves, 0, insurance.key(), &mut ifp);
            leaves[3] = leaf(&insurance, &received);
            let expected = tree(&leaves, 0, insurance.key(), &mut Vec::new());
            let mid = sell.signed.order_id().unwrap();
            let tid = buy.signed.order_id().unwrap();
            let mut ol = vec![(mid, order_leaf(domain, mid, Some(&sell)).unwrap()),
                (tid, order_leaf(domain, tid, Some(&buy)).unwrap())];
            let mut mop = Vec::new();
            let oroot = tree_tag(&ol, 0, mid, &mut mop, tag);
            ol[0].1 = order_leaf(domain, mid, None).unwrap();
            let mut top = Vec::new();
            tree_tag(&ol, 0, tid, &mut top, tag);
            ol[1].1 = order_leaf(domain, tid, None).unwrap();
            let expected_orders = tree_tag(&ol, 0, tid, &mut Vec::new(), tag);
            let run = |root, include_fees, final_path: &[Hash32]| {
                stage_ecx_committed_match(root, oroot, economics,
                    EcxIndexedOrderOpeningV1 { order: &sell,
                        account: EcxAccountOpeningV1 { position: &long,
                            cash: &opened.maker_cash, siblings: &mp }, order_siblings: &mop },
                    EcxIndexedOrderOpeningV1 { order: &buy,
                        account: EcxAccountOpeningV1 { position: &short,
                            cash: &opened.taker_cash, siblings: &tp }, order_siblings: &top },
                    EcxAccountOpeningV1 { position: &clearing_position,
                        cash: &opened.clearing_cash, siblings: &cp },
                    2, 100_000_000, fee_price, 0, fee_price, fee_price, context,
                    if include_fees { Some(EcxMatchFeeWitnessV1 {
                        insurance: EcxAccountOpeningV1 { position: &insurance,
                            cash: &cash, siblings: &ip }, maker_siblings: &mfp,
                        taker_siblings: &tfp, final_insurance_siblings: final_path,
                    }) } else { None }, &[&sell, &buy])
            };
            let (result, execution_hash) = run(source, true, &ifp).unwrap();
            // Use the fee-paid result, not the preliminary trade balances.
            crate::ecx_order_index_v1::verify_ecx_post_match_reserve_v1(
                oroot, &[&sell, &buy], mid, tid, economics, &result,
                2, fee_price, fee_price, 0).unwrap();
            // The receipt is over this actual signed, fee-bearing execution,
            // not a legacy matcher order hash or an uncomputed public value.
            let matcher_key = SecretKey::from_slice(&[11; 32]).unwrap();
            let matcher = crate::successor_matcher_v2::SuccessorCentralMatcherConfigV2 {
                version: 2, key_epoch: 3,
                signer: XOnlyKey(Keypair::from_secret_key(&Secp256k1::new(),
                    &matcher_key).x_only_public_key().0.serialize()),
                genesis_sequence: 1, genesis_receipt_hash: [19; 32],
                forced_inclusion_blocks: 1,
            };
            let bindings = crate::ecx_configuration_v1::EcxSuccessorBindingsV1 {
                economic_configuration_hash: economics.digest().unwrap(),
                matcher_configuration_hash: matcher.digest(),
                // Structural fixture IDs, not qualified proof programs.
                oracle_configuration_hash: [20; 32], funding_oracle_program_id: [21; 32],
                account_execution_program_id: [22; 32], vault_policy_hash: [23; 32],
            };
            let receipt = crate::ecx_matcher_v1::EcxMatcherExecutionReceiptV1::sign(
                economics, &matcher, context.match_sequence,
                matcher.genesis_receipt_hash, execution_hash, &matcher_key,
            ).unwrap();
            let verify = |r: &crate::ecx_matcher_v1::EcxMatcherExecutionReceiptV1,
                seq, prev, execution| r.verify(bindings, economics, &matcher, seq, prev, execution);
            assert_eq!(verify(&receipt, 1, [19; 32], (2, execution_hash)).unwrap(), receipt.digest());
            assert!(verify(&receipt, 2, receipt.digest(), (2, execution_hash)).is_err());
            assert!(verify(&receipt, 1, [18; 32], (2, execution_hash)).is_err());
            assert!(verify(&receipt, 1, [19; 32], (3, execution_hash)).is_err());
            assert!(verify(&receipt, 1, [19; 32], (2, [18; 32])).is_err());
            let mut altered = receipt.clone();
            altered.signature.0[0] ^= 1;
            assert!(verify(&altered, 1, [19; 32], (2, execution_hash)).is_err());
            let mut wrong_policy = bindings;
            wrong_policy.matcher_configuration_hash[0] ^= 1;
            assert!(receipt.verify(wrong_policy, economics, &matcher, 1,
                [19; 32], (2, execution_hash)).is_err());
            let authorize = |root, cursor, receipt: &crate::ecx_matcher_v1::EcxMatcherExecutionReceiptV1,
                quantity, include_fees| {
                crate::ecx_matcher_v1::stage_ecx_matcher_authorized_match(
                    root, oroot, bindings, economics, &matcher, cursor, receipt,
                    EcxIndexedOrderOpeningV1 { order: &sell,
                        account: EcxAccountOpeningV1 { position: &long,
                            cash: &opened.maker_cash, siblings: &mp }, order_siblings: &mop },
                    EcxIndexedOrderOpeningV1 { order: &buy,
                        account: EcxAccountOpeningV1 { position: &short,
                            cash: &opened.taker_cash, siblings: &tp }, order_siblings: &top },
                    EcxAccountOpeningV1 { position: &clearing_position,
                        cash: &opened.clearing_cash, siblings: &cp },
                    2, quantity, fee_price, 0, fee_price, fee_price, context,
                    if include_fees { Some(EcxMatchFeeWitnessV1 {
                        insurance: EcxAccountOpeningV1 { position: &insurance,
                            cash: &cash, siblings: &ip }, maker_siblings: &mfp,
                        taker_siblings: &tfp, final_insurance_siblings: &ifp,
                    }) } else { None }, &[&sell, &buy])
            };
            assert_eq!(authorize(source, (1, [19; 32]), &receipt, 100_000_000, true).unwrap(),
                (result.clone(), receipt.digest()));
            assert!(authorize(source, (1, [19; 32]), &altered, 100_000_000, true).is_err());
            assert!(authorize(source, (2, receipt.digest()), &receipt, 100_000_000, true).is_err());
            assert!(authorize(expected, (1, [19; 32]), &receipt, 100_000_000, true).is_err());
            assert!(authorize(source, (1, [19; 32]), &receipt, 50_000_000, true).is_err());
            assert!(authorize(source, (1, [19; 32]), &receipt, 100_000_000, false).is_err());
            assert_eq!(result.accounts.root, expected);
            assert_eq!(result.orders_root, expected_orders);
            assert_eq!(result.accounts.trade.taker_cash, paid);
            assert_eq!(result.accounts.trade.maker_cash, maker_paid);
            assert_eq!(maker_paid.balance().0 as i128,
                150_000_000 - i128::from(maker_rate) * 10_000);
            assert_eq!(received.balance().0 as i128,
                100_050_000 + i128::from(maker_rate) * 10_000);
            assert_eq!(result.insurance_cash, Some(received.clone()));
            assert_eq!(result.accounts.trade.clearing_cash, closed.clearing_cash);
            assert_eq!(run(source, false, &ifp), Err(ProtocolError::InvalidBondState));
            assert!(run(source, true, &ip).is_err());
            assert!(run(expected, true, &ifp).is_err());
            verify_ecx_cash_conservation(&[result.accounts.trade.maker_cash,
                result.accounts.trade.taker_cash, result.accounts.trade.clearing_cash,
                received], 400_000_000).unwrap();
            }
        }
        verify_ecx_cash_conservation(
            &[closed.maker_cash, closed.taker_cash, closed.clearing_cash],
            300_000_000,
        )
        .unwrap();
        let empty = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        assert!(close(&empty).is_err());
        assert_eq!(opened.maker_cash, cash);
        assert_eq!(opened.clearing_cash, cash);
        assert_eq!(sell.remaining, 100_000_000);
        assert_eq!(long.position_size_atoms, 100_000_000);
    }

    #[test]
    fn ecx_consent_rejects_legacy_signatures_and_substituted_settlement_domains() {
        let key = SecretKey::from_slice(&[7; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &key);
        let domain = EcxAccountDomainV1 {
            chain_id: [1; 32],
            market: ECX_USDD_MARKET,
            configuration_hash: [2; 32],
            collateral_asset: [3; 32],
        };
        let order = SuccessorLimitOrderV2 {
            version: 2,
            chain_id: domain.chain_id,
            market: domain.market,
            trader: XOnlyKey(XOnlyPublicKey::from_keypair(&pair).0.serialize()),
            side: Side::Buy,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::from_bits(0).unwrap(),
            limit_price: Price::new(30).unwrap(),
            quantity: Quantity::new(1).unwrap(),
            client_order_id: [0; 16],
            max_fee_bps: 10,
            nonce: (1u128 << 96) + 1,
            valid_from_height: 0,
            expires_at_height: 100,
        };
        let signed = SignedEcxOrderV1::sign(domain, order.clone(), &key).unwrap();
        signed.verify(domain).unwrap();
        let bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        };
        let trader = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: order.trader,
            account_nonce: order.nonce,
            collateral_atoms: 0,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: crate::incremental_state_v2::Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1000,
            order_generation: 0,
            salt: [4; 32],
        };
        let next = signed.admit(domain, &trader, 100, bounds).unwrap();
        let mut expected = trader.clone();
        expected.account_nonce += 1;
        assert_eq!(next, expected);
        // Both signatures, order remainders and position changes compose in
        // one result. A failure on the second leg leaves all inputs intact.
        let other_key = SecretKey::from_slice(&[8; 32]).unwrap();
        let other_pair = Keypair::from_secret_key(&Secp256k1::new(), &other_key);
        let mut sell = order.clone();
        sell.trader = XOnlyKey(XOnlyPublicKey::from_keypair(&other_pair).0.serialize());
        sell.side = Side::Sell;
        let mut seller = trader.clone();
        seller.trader = sell.trader;
        let (buy_record, buyer) =
            EcxAdmittedOrderV2::admit(signed.clone(), domain, &trader, 100, bounds, 1).unwrap();
        let (sell_record, seller) = EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(domain, sell, &other_key).unwrap(),
            domain,
            &seller,
            100,
            bounds, 1,
        )
        .unwrap();
        let cash =
            EcxCashAccountV1::from_funded_balance(crate::ecx_collateral::EcxCollateralAtoms(100));
        let run_match = |sell_record: &EcxAdmittedOrderV2, clearing_key| {
            stage_ecx_match(
                domain,
                &buy_record,
                sell_record,
                &buyer,
                &seller,
                &cash,
                &cash,
                clearing_key,
                &cash,
                100,
                1,
                Price::new(30).unwrap(),
                0,
                bounds,
            )
        };
        let matched = run_match(&sell_record, XOnlyKey([9; 32])).unwrap();
        assert!(matched.maker_order.is_none() && matched.taker_order.is_none());
        assert_eq!(matched.maker_position.position_size_atoms, 1);
        assert_eq!(matched.taker_position.position_size_atoms, -1);
        assert_eq!(matched.maker_cash, cash);
        assert_eq!(matched.taker_cash, cash);
        assert_eq!(matched.clearing_cash, cash);
        assert!(run_match(&sell_record, buyer.trader).is_err());
        let mut invalid_sell = sell_record.clone();
        invalid_sell.remaining = 0;
        assert!(run_match(&invalid_sell, XOnlyKey([9; 32])).is_err());
        assert_eq!(buy_record.remaining, 1);
        assert_eq!(buyer.position_size_atoms, 0);
        assert_eq!(seller.position_size_atoms, 0);
        let mut partial_order = order.clone();
        partial_order.quantity = Quantity::new(3).unwrap();
        let (record, admitted) = EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(domain, partial_order.clone(), &key).unwrap(),
            domain,
            &trader,
            100,
            bounds, 1,
        )
        .unwrap();
        let original = record.commitment(domain).unwrap();
        let mut altered_priority = record.clone();
        altered_priority.received_sequence += 1;
        assert_ne!(original, altered_priority.commitment(domain).unwrap());
        assert!(record.priority(domain).unwrap().compare_priority(
            altered_priority.priority(domain).unwrap()).unwrap().is_lt());
        assert_eq!(record.priority(domain).unwrap().order_id, record.signed.order_id().unwrap());
        altered_priority.received_sequence = 0;
        assert!(altered_priority.commitment(domain).is_err());
        assert!(altered_priority.priority(domain).is_err());
        let (partial, delta) = record
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds,
            )
            .unwrap();
        assert_eq!(delta, 1);
        let partial = partial.unwrap();
        assert_eq!(partial.remaining, 2);
        assert_eq!(partial.received_sequence, record.received_sequence);
        assert_eq!(partial.priority(domain).unwrap(), record.priority(domain).unwrap());
        assert_ne!(original, partial.commitment(domain).unwrap());
        assert!(partial
            .fill(
                domain,
                &admitted,
                100,
                3,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &admitted,
                100,
                0,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &admitted,
                101,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &trader,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        let mut cancelled = admitted.clone();
        cancelled.order_generation += 1;
        assert!(partial
            .fill(
                domain,
                &cancelled,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(31).unwrap(),
                false,
                10,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                11,
                bounds
            )
            .is_err());
        assert!(partial
            .fill(
                domain,
                &admitted,
                100,
                2,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .unwrap()
            .0
            .is_none());
        partial_order.time_in_force = TimeInForce::ImmediateOrCancel;
        let (ioc, _) = EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(domain, partial_order.clone(), &key).unwrap(),
            domain,
            &trader,
            100,
            bounds, 1,
        )
        .unwrap();
        assert!(ioc
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert!(ioc
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(29).unwrap(),
                false,
                10,
                bounds
            )
            .unwrap()
            .0
            .is_none());
        partial_order.time_in_force = TimeInForce::GoodTilHeight;
        partial_order.flags = OrderFlags::POST_ONLY;
        let (post, _) = EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(domain, partial_order.clone(), &key).unwrap(),
            domain,
            &trader,
            100,
            bounds, 1,
        )
        .unwrap();
        assert!(post
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(30).unwrap(),
                false,
                10,
                bounds
            )
            .is_err());
        partial_order.flags = OrderFlags::REDUCE_ONLY;
        let (reduce, _) = EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(domain, partial_order, &key).unwrap(),
            domain,
            &trader,
            100,
            bounds, 1,
        )
        .unwrap();
        assert!(reduce
            .fill(
                domain,
                &admitted,
                100,
                1,
                Price::new(30).unwrap(),
                true,
                10,
                bounds
            )
            .is_err());
        assert_eq!(record.remaining, 3);
        assert!(signed.admit(domain, &next, 100, bounds).is_err());
        assert!(signed.admit(domain, &trader, 101, bounds).is_err());
        let mut wrong = trader.clone();
        wrong.collateral_atoms = 1;
        assert!(signed.admit(domain, &wrong, 100, bounds).is_err());
        wrong = trader.clone();
        wrong.trader.0[0] ^= 1;
        assert!(signed.admit(domain, &wrong, 100, bounds).is_err());
        let mut exhausted_order = order.clone();
        exhausted_order.nonce = u128::MAX;
        let exhausted = SignedEcxOrderV1::sign(domain, exhausted_order, &key).unwrap();
        wrong = trader.clone();
        wrong.account_nonce = u128::MAX;
        assert!(exhausted.admit(domain, &wrong, 100, bounds).is_err());
        let legacy = SuccessorSignedLimitOrderV2::sign(order, &key).unwrap();
        assert_ne!(signed.order_id().unwrap(), legacy.order_id());
        let mut changed = signed.clone();
        changed.signature = legacy.signature;
        assert!(changed.verify(domain).is_err());
        for field in 0..3 {
            let mut changed = signed.clone();
            match field {
                0 => changed.domain.configuration_hash[0] ^= 1,
                1 => changed.domain.collateral_asset[0] ^= 1,
                _ => {
                    changed.domain.chain_id[0] ^= 1;
                    changed.order.chain_id = changed.domain.chain_id;
                }
            }
            assert!(changed.verify(domain).is_err());
            assert!(changed.verify(changed.domain).is_err());
        }
        let mut changed = signed.clone();
        changed.order.quantity = Quantity::new(2).unwrap();
        assert!(changed.verify(domain).is_err());
        let mut changed = signed.clone();
        changed.order.nonce ^= 1u128 << 96;
        assert!(changed.verify(domain).is_err());
        let mut empty = domain;
        empty.configuration_hash = [0; 32];
        assert!(SignedEcxOrderV1::sign(empty, signed.order, &key).is_err());
    }
}
