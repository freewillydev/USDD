//! Proof-shaped, lifetime-safe successor matcher runtime.
//!
//! This is deliberately separate from the V1 engine and journal. It retains
//! the exact signed successor order, risk selection, private order-index salt,
//! trader generation, admission receipt and full-`u128` priority required by
//! the incremental proof. Admission is staged before the journal is written;
//! after the journal fsync the in-memory swap is infallible, and restart
//! rebuilds the book by streaming the verified journal.

use std::collections::{BTreeMap, VecDeque};

use anyhow::{Context, Result, bail};
use ecx_protocol_core::{
    Hash32, IncrementalOrderContextV2, OrderFlags, OrderId, OrderIndexLeafV2,
    OrderRiskCommitmentV2, Quantity, RiskParams, Side, Signature64,
    SuccessorCentralMatcherConfigV2, SuccessorCentralMatcherReceiptV2,
    SuccessorMatcherCommandKindV2, SuccessorMatcherExecutionReceiptV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorTradeMatchV2, TimeInForce,
    XOnlyKey, successor_matcher_cancel_command_hash_v2, successor_matcher_order_command_hash_v2,
    trading_fee,
};

use crate::{
    SuccessorCentralMatcherSignerV2, SuccessorMatcherConsensusContextV2,
    SuccessorMatcherJournalCommandV2, SuccessorMatcherJournalEntryV2, SuccessorMatcherJournalV2,
};

pub const SUCCESSOR_MATCHER_PLACE_RECOVERY_LEN_V2: usize = 1 + 32 + 32 + 32 + 4 + 64 + 16 + 32 + 32;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherPlaceRecoveryV2 {
    pub risk: OrderRiskCommitmentV2,
    pub trader_order_generation: u128,
    pub salt: Hash32,
    /// Exact authenticated parent block used by execution receipts. It lives
    /// in the admission availability preimage so it cannot be rewritten after
    /// the taker receipt is signed.
    pub parent_block_hash: Hash32,
}

impl SuccessorMatcherPlaceRecoveryV2 {
    pub const VERSION: u8 = 1;

    pub fn encode_fixed(&self) -> Result<[u8; SUCCESSOR_MATCHER_PLACE_RECOVERY_LEN_V2]> {
        if self.salt == [0; 32] || self.parent_block_hash == [0; 32] {
            bail!("successor matcher recovery salt and parent block hash must be nonzero");
        }
        let mut out = [0u8; SUCCESSOR_MATCHER_PLACE_RECOVERY_LEN_V2];
        let mut offset = 0;
        out[offset] = Self::VERSION;
        offset += 1;
        out[offset..offset + 32].copy_from_slice(&self.risk.configuration_hash);
        offset += 32;
        out[offset..offset + 32].copy_from_slice(&self.risk.order_id);
        offset += 32;
        out[offset..offset + 32].copy_from_slice(&self.risk.trader.0);
        offset += 32;
        out[offset..offset + 4]
            .copy_from_slice(&self.risk.selected_initial_margin_bps.to_be_bytes());
        offset += 4;
        out[offset..offset + 64].copy_from_slice(&self.risk.signature.0);
        offset += 64;
        out[offset..offset + 16].copy_from_slice(&self.trader_order_generation.to_be_bytes());
        offset += 16;
        out[offset..offset + 32].copy_from_slice(&self.salt);
        offset += 32;
        out[offset..].copy_from_slice(&self.parent_block_hash);
        Ok(out)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SUCCESSOR_MATCHER_PLACE_RECOVERY_LEN_V2 || bytes[0] != Self::VERSION {
            bail!("successor matcher place recovery has the wrong length or version");
        }
        let mut offset = 1;
        let take32 = |offset: &mut usize| -> Hash32 {
            let value = bytes[*offset..*offset + 32]
                .try_into()
                .expect("fixed bounds");
            *offset += 32;
            value
        };
        let configuration_hash = take32(&mut offset);
        let order_id = take32(&mut offset);
        let trader = XOnlyKey(take32(&mut offset));
        let selected_initial_margin_bps =
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed bounds"));
        offset += 4;
        let signature = Signature64(bytes[offset..offset + 64].try_into().expect("fixed bounds"));
        offset += 64;
        let trader_order_generation =
            u128::from_be_bytes(bytes[offset..offset + 16].try_into().expect("fixed bounds"));
        offset += 16;
        let salt = take32(&mut offset);
        let parent_block_hash = take32(&mut offset);
        let value = Self {
            risk: OrderRiskCommitmentV2 {
                version: OrderRiskCommitmentV2::VERSION,
                configuration_hash,
                order_id,
                trader,
                selected_initial_margin_bps,
                signature,
            },
            trader_order_generation,
            salt,
            parent_block_hash,
        };
        if value.salt == [0; 32] || value.parent_block_hash == [0; 32] {
            bail!("successor matcher recovery salt and parent block hash must be nonzero");
        }
        Ok(value)
    }

    fn validate_for(
        &self,
        order: &SuccessorSignedLimitOrderV2,
        context: IncrementalOrderContextV2,
    ) -> Result<()> {
        self.risk
            .verify(context.risk_params)
            .context("invalid successor order risk commitment")?;
        if self.risk.configuration_hash != context.configuration_hash
            || self.risk.order_id != order.order_id()
            || self.risk.trader != order.order.trader
            || self.salt == [0; 32]
            || self.parent_block_hash == [0; 32]
        {
            bail!("successor matcher recovery does not match the signed order or context");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessorMatcherRuntimeConfigV2 {
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub market: ecx_protocol_core::MarketId,
    pub risk_params: RiskParams,
    pub maximum_live_orders: usize,
}

impl SuccessorMatcherRuntimeConfigV2 {
    pub fn validate(&self) -> Result<()> {
        if self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.maximum_live_orders == 0
            || self.maximum_live_orders > 64
        {
            bail!("invalid successor matcher runtime configuration");
        }
        self.market.validate().context("invalid successor market")?;
        self.risk_params
            .validate()
            .context("invalid successor risk parameters")?;
        Ok(())
    }

    fn order_context(&self, sidechain_height: u64) -> IncrementalOrderContextV2 {
        IncrementalOrderContextV2 {
            chain_id: self.chain_id,
            market: self.market,
            configuration_hash: self.configuration_hash,
            risk_params: self.risk_params,
            sidechain_height,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RestingSuccessorOrderV2 {
    leaf: OrderIndexLeafV2,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherFillV2 {
    pub maker: SuccessorSignedLimitOrderV2,
    pub trade: SuccessorTradeMatchV2,
    pub execution_receipt: SuccessorMatcherExecutionReceiptV2,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherPlaceOutcomeV2 {
    pub admission_receipt: SuccessorCentralMatcherReceiptV2,
    pub fills: Vec<SuccessorMatcherFillV2>,
    pub remaining_quantity_atoms: u64,
    pub resting: bool,
    pub self_trade_prevented: bool,
    pub pruned_order_ids: Vec<OrderId>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherCancelOutcomeV2 {
    pub admission_receipt: SuccessorCentralMatcherReceiptV2,
    pub cancelled_order: Option<OrderIndexLeafV2>,
    pub pruned_order_ids: Vec<OrderId>,
}

#[derive(Clone, Debug)]
struct StagedSuccessorMutationV2<T> {
    next_book: SuccessorMatcherOrderBookV2,
    outcome: T,
}

#[derive(Clone, Debug)]
pub struct SuccessorMatcherOrderBookV2 {
    config: SuccessorMatcherRuntimeConfigV2,
    sidechain_height: u64,
    match_sequence: u128,
    last_nonce: BTreeMap<XOnlyKey, u128>,
    orders: BTreeMap<OrderId, RestingSuccessorOrderV2>,
    bids: BTreeMap<u64, VecDeque<OrderId>>,
    asks: BTreeMap<u64, VecDeque<OrderId>>,
}

impl SuccessorMatcherOrderBookV2 {
    pub fn new(config: SuccessorMatcherRuntimeConfigV2, sidechain_height: u64) -> Result<Self> {
        config.validate()?;
        if sidechain_height == 0 {
            bail!("successor matcher sidechain height must be nonzero");
        }
        Ok(Self {
            config,
            sidechain_height,
            match_sequence: 0,
            last_nonce: BTreeMap::new(),
            orders: BTreeMap::new(),
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
        })
    }

    pub fn sidechain_height(&self) -> u64 {
        self.sidechain_height
    }

    pub fn config(&self) -> &SuccessorMatcherRuntimeConfigV2 {
        &self.config
    }

    pub fn match_sequence(&self) -> u128 {
        self.match_sequence
    }

    pub fn live_order_count(&self) -> usize {
        self.orders.len()
    }

    pub fn remaining_quantity(&self, order_id: OrderId) -> Option<u64> {
        self.orders
            .get(&order_id)
            .map(|order| order.leaf.remaining_quantity_atoms)
    }

    fn stage_place(
        &self,
        signer: &SuccessorCentralMatcherSignerV2,
        matcher_config: &SuccessorCentralMatcherConfigV2,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
        admission: &SuccessorCentralMatcherReceiptV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<StagedSuccessorMutationV2<SuccessorMatcherPlaceOutcomeV2>> {
        let mut next = self.clone();
        let pruned_order_ids = next.advance_height(consensus.sidechain_height)?;
        next.validate_place(matcher_config, order, recovery, admission, consensus)?;
        let trader = order.order.trader;
        if next
            .last_nonce
            .get(&trader)
            .is_some_and(|nonce| *nonce >= order.order.nonce)
        {
            bail!("successor matcher order nonce is not strictly increasing");
        }
        if next.orders.contains_key(&order.order_id()) {
            bail!("successor matcher order id is already live");
        }
        if order.order.max_fee_bps < next.config.risk_params.taker_fee_bps
            || order.order.max_fee_bps < next.config.risk_params.maker_fee_bps.unsigned_abs()
        {
            bail!("successor matcher order fee ceiling is below the frozen schedule");
        }
        if order.order.flags.contains(OrderFlags::POST_ONLY) && next.crosses_best(order) {
            bail!("successor post-only order would cross the authenticated best maker");
        }

        let mut remaining = order.order.quantity.get();
        let mut fills = Vec::new();
        let mut self_trade_prevented = false;
        while remaining > 0 {
            let Some(maker_id) = next.best_crossing_maker(order) else {
                break;
            };
            let maker = next
                .orders
                .get(&maker_id)
                .cloned()
                .context("successor matcher priority index references a missing order")?;
            if maker.leaf.signed_order.order.trader == trader {
                self_trade_prevented = true;
                break;
            }
            let fill_quantity = remaining.min(maker.leaf.remaining_quantity_atoms);
            next.match_sequence = next
                .match_sequence
                .checked_add(1)
                .context("successor matcher execution sequence overflow")?;
            if next.match_sequence == u128::MAX {
                bail!("successor matcher execution sequence exhausted");
            }
            let price = maker.leaf.signed_order.order.limit_price;
            let quantity =
                Quantity::new(fill_quantity).context("invalid successor fill quantity")?;
            let trade = SuccessorTradeMatchV2 {
                sequence: admission.body.global_sequence,
                maker_order_id: maker_id,
                taker_order_id: order.order_id(),
                maker: maker.leaf.signed_order.order.trader,
                taker: trader,
                maker_side: maker.leaf.signed_order.order.side,
                price,
                quantity,
                maker_fee: trading_fee(price, quantity, next.config.risk_params.maker_fee_bps)?,
                taker_fee: trading_fee(
                    price,
                    quantity,
                    i32::try_from(next.config.risk_params.taker_fee_bps)
                        .context("successor taker fee does not fit i32")?,
                )?,
            };
            trade
                .validate_orders(&maker.leaf.signed_order, order, consensus.sidechain_height)
                .context("generated successor trade is invalid")?;
            let execution_receipt = signer.issue_execution(
                &maker.leaf.signed_order,
                order,
                &trade,
                next.match_sequence,
                admission,
                recovery.parent_block_hash,
            )?;
            remaining -= fill_quantity;
            if fill_quantity == maker.leaf.remaining_quantity_atoms {
                next.remove_order(maker_id)?;
            } else {
                next.orders
                    .get_mut(&maker_id)
                    .context("successor maker disappeared during partial fill")?
                    .leaf
                    .remaining_quantity_atoms -= fill_quantity;
            }
            fills.push(SuccessorMatcherFillV2 {
                maker: maker.leaf.signed_order,
                trade,
                execution_receipt,
            });
        }

        let resting = remaining > 0
            && order.order.time_in_force == TimeInForce::GoodTilHeight
            && !self_trade_prevented;
        if resting {
            if next.orders.len() >= next.config.maximum_live_orders {
                bail!("successor matcher live-order capacity is exhausted");
            }
            let leaf = OrderIndexLeafV2 {
                version: OrderIndexLeafV2::VERSION,
                signed_order: order.clone(),
                risk: recovery.risk.clone(),
                remaining_quantity_atoms: remaining,
                received_sequence: admission.body.global_sequence,
                admission_receipt_hash: admission.receipt_hash(),
                trader_order_generation: recovery.trader_order_generation,
                salt: recovery.salt,
            };
            leaf.validate(next.config.order_context(consensus.sidechain_height))
                .context("successor resting-order leaf is invalid")?;
            next.insert_order(leaf)?;
        }
        next.last_nonce.insert(trader, order.order.nonce);
        Ok(StagedSuccessorMutationV2 {
            next_book: next,
            outcome: SuccessorMatcherPlaceOutcomeV2 {
                admission_receipt: admission.clone(),
                fills,
                remaining_quantity_atoms: remaining,
                resting,
                self_trade_prevented,
                pruned_order_ids,
            },
        })
    }

    fn stage_cancel(
        &self,
        matcher_config: &SuccessorCentralMatcherConfigV2,
        cancel: &SuccessorSignedCancelOrderV2,
        admission: &SuccessorCentralMatcherReceiptV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<StagedSuccessorMutationV2<SuccessorMatcherCancelOutcomeV2>> {
        let mut next = self.clone();
        let pruned_order_ids = next.advance_height(consensus.sidechain_height)?;
        next.validate_cancel(matcher_config, cancel, admission, consensus)?;
        let trader = cancel.cancel.trader;
        if next
            .last_nonce
            .get(&trader)
            .is_some_and(|nonce| *nonce >= cancel.cancel.nonce)
        {
            bail!("successor matcher cancellation nonce is not strictly increasing");
        }
        let cancelled_order = match next.orders.get(&cancel.cancel.order_id) {
            Some(order) if order.leaf.signed_order.order.trader != trader => {
                bail!("successor cancellation signer does not own the order")
            }
            Some(order) => {
                let leaf = order.leaf.clone();
                next.remove_order(cancel.cancel.order_id)?;
                Some(leaf)
            }
            None => None,
        };
        next.last_nonce.insert(trader, cancel.cancel.nonce);
        Ok(StagedSuccessorMutationV2 {
            next_book: next,
            outcome: SuccessorMatcherCancelOutcomeV2 {
                admission_receipt: admission.clone(),
                cancelled_order,
                pruned_order_ids,
            },
        })
    }

    fn validate_place(
        &self,
        matcher_config: &SuccessorCentralMatcherConfigV2,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
        admission: &SuccessorCentralMatcherReceiptV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<()> {
        order.verify().context("invalid successor signed order")?;
        recovery.validate_for(order, self.config.order_context(consensus.sidechain_height))?;
        admission
            .verify(matcher_config)
            .context("invalid successor admission receipt")?;
        if consensus.sidechain_height == 0
            || consensus.parent_height == 0
            || consensus.parent_mtp == 0
            || order.order.chain_id != self.config.chain_id
            || order.order.market != self.config.market
            || !order.order.is_live_at(consensus.sidechain_height)
            || admission.body.chain_id != self.config.chain_id
            || admission.body.command_kind != SuccessorMatcherCommandKindV2::Place
            || admission.body.command_hash != successor_matcher_order_command_hash_v2(order)
            || admission.body.observed_sidechain_height != consensus.sidechain_height
            || admission.body.observed_parent_height != consensus.parent_height
            || admission.body.observed_parent_mtp != consensus.parent_mtp
            || admission.body.forced_inbox_cursor != consensus.forced_inbox_cursor
        {
            bail!("successor order/admission/context binding is invalid");
        }
        Ok(())
    }

    fn validate_cancel(
        &self,
        matcher_config: &SuccessorCentralMatcherConfigV2,
        cancel: &SuccessorSignedCancelOrderV2,
        admission: &SuccessorCentralMatcherReceiptV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<()> {
        cancel
            .verify()
            .context("invalid successor signed cancellation")?;
        admission
            .verify(matcher_config)
            .context("invalid successor cancellation receipt")?;
        if cancel.cancel.chain_id != self.config.chain_id
            || cancel.cancel.market != self.config.market
            || !cancel.cancel.is_live_at(consensus.sidechain_height)
            || admission.body.chain_id != self.config.chain_id
            || admission.body.command_kind != SuccessorMatcherCommandKindV2::Cancel
            || admission.body.command_hash != successor_matcher_cancel_command_hash_v2(cancel)
            || admission.body.observed_sidechain_height != consensus.sidechain_height
            || admission.body.observed_parent_height != consensus.parent_height
            || admission.body.observed_parent_mtp != consensus.parent_mtp
            || admission.body.forced_inbox_cursor != consensus.forced_inbox_cursor
        {
            bail!("successor cancellation/admission/context binding is invalid");
        }
        Ok(())
    }

    fn advance_height(&mut self, height: u64) -> Result<Vec<OrderId>> {
        if height == 0 || height < self.sidechain_height {
            bail!("successor matcher sidechain height regressed");
        }
        self.sidechain_height = height;
        let expired = self
            .orders
            .iter()
            .filter_map(|(id, order)| {
                (order.leaf.signed_order.order.expires_at_height < height).then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in &expired {
            self.remove_order(*id)?;
        }
        Ok(expired)
    }

    fn crosses_best(&self, taker: &SuccessorSignedLimitOrderV2) -> bool {
        self.best_crossing_maker(taker).is_some()
    }

    fn best_crossing_maker(&self, taker: &SuccessorSignedLimitOrderV2) -> Option<OrderId> {
        match taker.order.side {
            Side::Buy => self.asks.iter().find_map(|(price, queue)| {
                (*price <= taker.order.limit_price.get())
                    .then(|| queue.front().copied())
                    .flatten()
            }),
            Side::Sell => self.bids.iter().rev().find_map(|(price, queue)| {
                (*price >= taker.order.limit_price.get())
                    .then(|| queue.front().copied())
                    .flatten()
            }),
        }
    }

    fn insert_order(&mut self, leaf: OrderIndexLeafV2) -> Result<()> {
        let order_id = leaf.order_id();
        let price = leaf.signed_order.order.limit_price.get();
        let side = leaf.signed_order.order.side;
        if self
            .orders
            .insert(order_id, RestingSuccessorOrderV2 { leaf })
            .is_some()
        {
            bail!("successor matcher inserted a duplicate order id");
        }
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        levels.entry(price).or_default().push_back(order_id);
        Ok(())
    }

    fn remove_order(&mut self, order_id: OrderId) -> Result<()> {
        let order = self
            .orders
            .remove(&order_id)
            .context("successor matcher order index is inconsistent")?;
        let price = order.leaf.signed_order.order.limit_price.get();
        let levels = match order.leaf.signed_order.order.side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let queue = levels
            .get_mut(&price)
            .context("successor matcher price level is missing")?;
        queue.retain(|candidate| *candidate != order_id);
        if queue.is_empty() {
            levels.remove(&price);
        }
        Ok(())
    }
}

pub struct SuccessorMatcherRuntimeV2 {
    signer: SuccessorCentralMatcherSignerV2,
    journal: SuccessorMatcherJournalV2,
    book: SuccessorMatcherOrderBookV2,
    activation_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessorMatcherProofEntryV2 {
    Place {
        order: SuccessorSignedLimitOrderV2,
        recovery: Box<SuccessorMatcherPlaceRecoveryV2>,
        outcome: Box<SuccessorMatcherPlaceOutcomeV2>,
    },
    Cancel {
        cancel: SuccessorSignedCancelOrderV2,
        outcome: Box<SuccessorMatcherCancelOutcomeV2>,
    },
}

impl SuccessorMatcherProofEntryV2 {
    pub fn admission_receipt(&self) -> &SuccessorCentralMatcherReceiptV2 {
        match self {
            Self::Place { outcome, .. } => &outcome.admission_receipt,
            Self::Cancel { outcome, .. } => &outcome.admission_receipt,
        }
    }
}

impl SuccessorMatcherRuntimeV2 {
    pub fn open(
        signer: SuccessorCentralMatcherSignerV2,
        journal: SuccessorMatcherJournalV2,
        book_config: SuccessorMatcherRuntimeConfigV2,
        activation_height: u64,
    ) -> Result<Self> {
        if signer.config() != journal.config()
            || signer.chain_id() != journal.chain_id()
            || journal.chain_id() != book_config.chain_id
        {
            bail!("successor runtime signer, journal and book identities differ");
        }
        let mut book = SuccessorMatcherOrderBookV2::new(book_config, activation_height)?;
        journal.replay_entries(|entry| {
            book = replay_entry(&book, &signer, signer.config(), entry)?;
            Ok(())
        })?;
        Ok(Self {
            signer,
            journal,
            book,
            activation_height,
        })
    }

    pub fn book(&self) -> &SuccessorMatcherOrderBookV2 {
        &self.book
    }

    pub fn journal(&self) -> &SuccessorMatcherJournalV2 {
        &self.journal
    }

    pub fn matcher_config(&self) -> &SuccessorCentralMatcherConfigV2 {
        self.signer.config()
    }

    pub fn chain_id(&self) -> Hash32 {
        self.signer.chain_id()
    }

    pub fn place(
        &mut self,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<SuccessorMatcherPlaceOutcomeV2> {
        let recovery_bytes = recovery.encode_fixed()?;
        let prepared =
            self.journal
                .prepare_place(&self.signer, order, &recovery_bytes, consensus)?;
        let staged = self.book.stage_place(
            &self.signer,
            self.signer.config(),
            order,
            recovery,
            prepared.receipt(),
            consensus,
        )?;
        self.journal.commit_prepared(prepared)?;
        self.book = staged.next_book;
        Ok(staged.outcome)
    }

    pub fn cancel(
        &mut self,
        cancel: &SuccessorSignedCancelOrderV2,
        consensus: SuccessorMatcherConsensusContextV2,
    ) -> Result<SuccessorMatcherCancelOutcomeV2> {
        let prepared = self
            .journal
            .prepare_cancel(&self.signer, cancel, &[], consensus)?;
        let staged =
            self.book
                .stage_cancel(self.signer.config(), cancel, prepared.receipt(), consensus)?;
        self.journal.commit_prepared(prepared)?;
        self.book = staged.next_book;
        Ok(staged.outcome)
    }

    /// Reconstruct a bounded, proof-complete suffix from the independently
    /// verified append-only journal. Fills and execution receipts are
    /// regenerated by the same deterministic matcher relation used at live
    /// admission, so a producer can restart without trusting an ephemeral HTTP
    /// response or a second private fill database.
    pub fn proof_entries_after(
        &self,
        previous_admission_sequence: u128,
        limit: usize,
    ) -> Result<Vec<SuccessorMatcherProofEntryV2>> {
        if limit == 0 || limit > 4_096 {
            bail!("successor proof entry limit is outside 1..=4096");
        }
        let head = self.journal.head();
        if previous_admission_sequence < self.matcher_config().genesis_sequence
            || previous_admission_sequence > head.sequence
        {
            bail!("successor proof cursor is outside the durable receipt chain");
        }
        let first_sequence = previous_admission_sequence
            .checked_add(1)
            .context("successor proof cursor overflow")?;
        let mut book =
            SuccessorMatcherOrderBookV2::new(self.book.config().clone(), self.activation_height)?;
        let mut entries = Vec::new();
        self.journal.replay_entries(|entry| {
            let sequence = entry.receipt.body.global_sequence;
            let proof_entry = match entry.command {
                SuccessorMatcherJournalCommandV2::Place(order) => {
                    let recovery =
                        SuccessorMatcherPlaceRecoveryV2::decode_fixed(&entry.recoverable_context)?;
                    let staged = book.stage_place(
                        &self.signer,
                        self.matcher_config(),
                        &order,
                        &recovery,
                        &entry.receipt,
                        entry.consensus_context,
                    )?;
                    book = staged.next_book;
                    SuccessorMatcherProofEntryV2::Place {
                        order,
                        recovery: Box::new(recovery),
                        outcome: Box::new(staged.outcome),
                    }
                }
                SuccessorMatcherJournalCommandV2::Cancel(cancel) => {
                    if !entry.recoverable_context.is_empty() {
                        bail!("successor cancellation recovery context is not empty");
                    }
                    let staged = book.stage_cancel(
                        self.matcher_config(),
                        &cancel,
                        &entry.receipt,
                        entry.consensus_context,
                    )?;
                    book = staged.next_book;
                    SuccessorMatcherProofEntryV2::Cancel {
                        cancel,
                        outcome: Box::new(staged.outcome),
                    }
                }
            };
            if sequence >= first_sequence && entries.len() < limit {
                if entries.is_empty() && sequence != first_sequence {
                    bail!("successor journal omitted the requested proof cursor successor");
                }
                entries.push(proof_entry);
            }
            Ok(())
        })?;
        if previous_admission_sequence < head.sequence && entries.is_empty() {
            bail!("successor proof suffix is missing from the durable journal");
        }
        Ok(entries)
    }
}

fn replay_entry(
    book: &SuccessorMatcherOrderBookV2,
    signer: &SuccessorCentralMatcherSignerV2,
    matcher_config: &SuccessorCentralMatcherConfigV2,
    entry: SuccessorMatcherJournalEntryV2,
) -> Result<SuccessorMatcherOrderBookV2> {
    match entry.command {
        SuccessorMatcherJournalCommandV2::Place(order) => {
            let recovery =
                SuccessorMatcherPlaceRecoveryV2::decode_fixed(&entry.recoverable_context)?;
            Ok(book
                .stage_place(
                    signer,
                    matcher_config,
                    &order,
                    &recovery,
                    &entry.receipt,
                    entry.consensus_context,
                )?
                .next_book)
        }
        SuccessorMatcherJournalCommandV2::Cancel(cancel) => {
            if !entry.recoverable_context.is_empty() {
                bail!("successor cancellation journal context must be empty");
            }
            Ok(book
                .stage_cancel(
                    matcher_config,
                    &cancel,
                    &entry.receipt,
                    entry.consensus_context,
                )?
                .next_book)
        }
    }
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        ECX_USDD_MARKET, OrderFlags, Price, SuccessorLimitOrderV2,
        SuccessorMatcherExecutionRelationV2, verify_successor_matcher_execution_receipt_batch_v2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use tempfile::tempdir;

    use super::*;

    fn identity(byte: u8) -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn fixture() -> (
        SuccessorCentralMatcherSignerV2,
        SuccessorCentralMatcherConfigV2,
        SuccessorMatcherRuntimeConfigV2,
        Hash32,
    ) {
        let (secret, signer_key) = identity(61);
        let chain_id = [7; 32];
        let matcher = SuccessorCentralMatcherConfigV2 {
            version: SuccessorCentralMatcherConfigV2::VERSION,
            key_epoch: 9,
            signer: signer_key,
            genesis_sequence: (1u128 << 96) + 10,
            genesis_receipt_hash: [8; 32],
            forced_inclusion_blocks: 6,
        };
        let signer =
            SuccessorCentralMatcherSignerV2::new(matcher.clone(), secret, chain_id).unwrap();
        let runtime = SuccessorMatcherRuntimeConfigV2 {
            chain_id,
            configuration_hash: [3; 32],
            market: ECX_USDD_MARKET,
            risk_params: RiskParams::default(),
            maximum_live_orders: 64,
        };
        (signer, matcher, runtime, chain_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_order(
        secret: &SecretKey,
        trader: XOnlyKey,
        chain_id: Hash32,
        side: Side,
        price: u64,
        quantity: u64,
        nonce: u128,
        client: u8,
        flags: OrderFlags,
    ) -> SuccessorSignedLimitOrderV2 {
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader,
                side,
                time_in_force: TimeInForce::GoodTilHeight,
                flags,
                limit_price: Price::new(price).unwrap(),
                quantity: Quantity::new(quantity).unwrap(),
                client_order_id: [client; 16],
                max_fee_bps: 5,
                nonce,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            secret,
        )
        .unwrap()
    }

    fn recovery(
        order: &SuccessorSignedLimitOrderV2,
        secret: &SecretKey,
        configuration_hash: Hash32,
        byte: u8,
    ) -> SuccessorMatcherPlaceRecoveryV2 {
        SuccessorMatcherPlaceRecoveryV2 {
            risk: OrderRiskCommitmentV2::sign(
                configuration_hash,
                order.order_id(),
                order.order.trader,
                1_000,
                secret,
            )
            .unwrap(),
            trader_order_generation: (1u128 << 100) + u128::from(byte),
            salt: [byte; 32],
            parent_block_hash: [byte.wrapping_add(20); 32],
        }
    }

    fn consensus(height: u64) -> SuccessorMatcherConsensusContextV2 {
        SuccessorMatcherConsensusContextV2 {
            sidechain_height: height,
            parent_height: 900_000 + height,
            parent_mtp: 1_800_000_000 + height,
            forced_inbox_cursor: (1u128 << 112) + u128::from(height),
        }
    }

    #[test]
    fn successor_runtime_matches_high_u128_orders_and_replays_byte_exact_book() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("runtime.matcher");
        let (signer, matcher_config, runtime_config, chain_id) = fixture();
        let (maker_secret, maker_key) = identity(62);
        let (taker_secret, taker_key) = identity(63);
        let maker = signed_order(
            &maker_secret,
            maker_key,
            chain_id,
            Side::Sell,
            100_000_000,
            5,
            (1u128 << 104) + 1,
            1,
            OrderFlags::NONE,
        );
        let taker = signed_order(
            &taker_secret,
            taker_key,
            chain_id,
            Side::Buy,
            110_000_000,
            3,
            (1u128 << 104) + 2,
            2,
            OrderFlags::NONE,
        );
        let maker_recovery = recovery(&maker, &maker_secret, runtime_config.configuration_hash, 11);
        let taker_recovery = recovery(&taker, &taker_secret, runtime_config.configuration_hash, 12);
        let final_head;
        {
            let journal =
                SuccessorMatcherJournalV2::open(&path, matcher_config.clone(), chain_id).unwrap();
            let mut runtime =
                SuccessorMatcherRuntimeV2::open(signer.clone(), journal, runtime_config.clone(), 1)
                    .unwrap();
            let maker_outcome = runtime
                .place(&maker, &maker_recovery, consensus(10))
                .unwrap();
            assert!(maker_outcome.resting);
            assert!(maker_outcome.fills.is_empty());

            let taker_outcome = runtime
                .place(&taker, &taker_recovery, consensus(10))
                .unwrap();
            assert_eq!(taker_outcome.fills.len(), 1);
            assert!(!taker_outcome.resting);
            assert_eq!(taker_outcome.remaining_quantity_atoms, 0);
            assert_eq!(runtime.book().remaining_quantity(maker.order_id()), Some(2));
            assert_eq!(runtime.book().match_sequence(), 1);
            assert_eq!(runtime.journal().record_count(), 2);

            let fill = &taker_outcome.fills[0];
            let relation = SuccessorMatcherExecutionRelationV2 {
                maker: &fill.maker,
                taker: &taker,
                trade: &fill.trade,
                taker_admission: &taker_outcome.admission_receipt,
            };
            let (_, next_match) = verify_successor_matcher_execution_receipt_batch_v2(
                &matcher_config,
                chain_id,
                0,
                &[relation],
                std::slice::from_ref(&fill.execution_receipt),
            )
            .unwrap();
            assert_eq!(next_match, 1);
            final_head = runtime.journal().head();
        }

        let reopened_journal =
            SuccessorMatcherJournalV2::open(&path, matcher_config, chain_id).unwrap();
        let reopened =
            SuccessorMatcherRuntimeV2::open(signer, reopened_journal, runtime_config, 1).unwrap();
        assert_eq!(reopened.journal().head(), final_head);
        assert_eq!(reopened.journal().record_count(), 2);
        assert_eq!(
            reopened.book().remaining_quantity(maker.order_id()),
            Some(2)
        );
        assert_eq!(reopened.book().match_sequence(), 1);
    }

    #[test]
    fn successor_runtime_rejects_precommit_failure_without_consuming_receipt() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("atomic.matcher");
        let (signer, matcher_config, runtime_config, chain_id) = fixture();
        let (maker_secret, maker_key) = identity(64);
        let (taker_secret, taker_key) = identity(65);
        let maker = signed_order(
            &maker_secret,
            maker_key,
            chain_id,
            Side::Sell,
            100_000_000,
            2,
            (1u128 << 104) + 1,
            1,
            OrderFlags::NONE,
        );
        let post_only = signed_order(
            &taker_secret,
            taker_key,
            chain_id,
            Side::Buy,
            100_000_000,
            1,
            (1u128 << 104) + 2,
            2,
            OrderFlags::POST_ONLY,
        );
        let journal = SuccessorMatcherJournalV2::open(&path, matcher_config, chain_id).unwrap();
        let mut runtime =
            SuccessorMatcherRuntimeV2::open(signer, journal, runtime_config.clone(), 1).unwrap();
        runtime
            .place(
                &maker,
                &recovery(&maker, &maker_secret, runtime_config.configuration_hash, 13),
                consensus(10),
            )
            .unwrap();
        let head = runtime.journal().head();
        let records = runtime.journal().record_count();
        assert!(
            runtime
                .place(
                    &post_only,
                    &recovery(
                        &post_only,
                        &taker_secret,
                        runtime_config.configuration_hash,
                        14,
                    ),
                    consensus(10),
                )
                .is_err()
        );
        assert_eq!(runtime.journal().head(), head);
        assert_eq!(runtime.journal().record_count(), records);
        assert_eq!(runtime.book().live_order_count(), 1);
    }

    #[test]
    fn successor_runtime_rejects_mismatched_journal_chain_before_replay() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("wrong-chain.matcher");
        let (signer, matcher_config, runtime_config, chain_id) = fixture();
        let mut wrong_chain = chain_id;
        wrong_chain[0] ^= 1;
        let journal = SuccessorMatcherJournalV2::open(&path, matcher_config, wrong_chain).unwrap();
        assert!(SuccessorMatcherRuntimeV2::open(signer, journal, runtime_config, 1).is_err());
    }

    #[test]
    fn successor_runtime_cancellation_is_owner_bound_and_replays_absent() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("cancel.matcher");
        let (signer, matcher_config, runtime_config, chain_id) = fixture();
        let (owner_secret, owner_key) = identity(66);
        let (other_secret, other_key) = identity(67);
        let maker = signed_order(
            &owner_secret,
            owner_key,
            chain_id,
            Side::Sell,
            100_000_000,
            2,
            (1u128 << 104) + 1,
            1,
            OrderFlags::NONE,
        );
        let journal =
            SuccessorMatcherJournalV2::open(&path, matcher_config.clone(), chain_id).unwrap();
        let mut runtime =
            SuccessorMatcherRuntimeV2::open(signer.clone(), journal, runtime_config.clone(), 1)
                .unwrap();
        runtime
            .place(
                &maker,
                &recovery(&maker, &owner_secret, runtime_config.configuration_hash, 15),
                consensus(10),
            )
            .unwrap();

        let unauthorized = SuccessorSignedCancelOrderV2::sign(
            ecx_protocol_core::SuccessorCancelOrderV2 {
                version: ecx_protocol_core::SuccessorCancelOrderV2::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: other_key,
                order_id: maker.order_id(),
                nonce: (1u128 << 104) + 2,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            &other_secret,
        )
        .unwrap();
        let head = runtime.journal().head();
        assert!(runtime.cancel(&unauthorized, consensus(10)).is_err());
        assert_eq!(runtime.journal().head(), head);
        assert_eq!(runtime.book().remaining_quantity(maker.order_id()), Some(2));

        let authorized = SuccessorSignedCancelOrderV2::sign(
            ecx_protocol_core::SuccessorCancelOrderV2 {
                version: ecx_protocol_core::SuccessorCancelOrderV2::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: owner_key,
                order_id: maker.order_id(),
                nonce: (1u128 << 104) + 2,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            &owner_secret,
        )
        .unwrap();
        let outcome = runtime.cancel(&authorized, consensus(10)).unwrap();
        assert!(outcome.cancelled_order.is_some());
        assert_eq!(runtime.book().remaining_quantity(maker.order_id()), None);
        assert_eq!(runtime.journal().record_count(), 2);
        drop(runtime);

        let journal = SuccessorMatcherJournalV2::open(&path, matcher_config, chain_id).unwrap();
        let reopened = SuccessorMatcherRuntimeV2::open(signer, journal, runtime_config, 1).unwrap();
        assert_eq!(reopened.book().remaining_quantity(maker.order_id()), None);
        assert_eq!(reopened.journal().record_count(), 2);
    }
}
