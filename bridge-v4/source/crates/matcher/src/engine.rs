use std::collections::{BTreeMap, HashMap, VecDeque};

use ecx_protocol_core::{
    CancelOrder, ECX_USDD_MARKET, LimitOrder, OrderFlags, OrderRiskCommitmentV2, Price, Quantity,
    RiskParams, Signature64, SignedCancelOrder, SignedLimitOrder, TradeMatch, XOnlyKey,
    matcher_cancel_command_hash, trading_fee,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    AccountView, CancelOrderOutcome, CancelOrderRequest, EngineCommand, MARKET, MarketEvent,
    Mutation, OrderBookSnapshot, OrderStatus, PositionView, PriceLevel, RestingOrderView, Side,
    StagedMatcherExecutionV2, SubmitOrderOutcome, SubmitOrderRequest, SubmitOrderRequestV2,
    TimeInForce, Trade,
};

const DEMO_ORDER_ID_DOMAIN: &[u8] = b"ECX/DEMO-ORDER-ID/V1";
const TRADE_ID_DOMAIN: &[u8] = b"ECX/TRADE-ID/V1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub demo_mode: bool,
    pub chain_height: u64,
    pub max_price_ticks: u64,
    pub max_quantity_lots: u64,
    pub recent_trade_limit: usize,
    pub max_open_orders: usize,
    pub max_open_orders_per_trader: usize,
    pub max_commands_per_height: u64,
    pub max_commands_per_trader_per_height: u64,
    pub max_traders: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            demo_mode: false,
            chain_height: 0,
            // Eight-decimal protocol units: 10,000 USDD and 10,000 ECX.
            max_price_ticks: 1_000_000_000_000,
            max_quantity_lots: 1_000_000_000_000,
            recent_trade_limit: 500,
            max_open_orders: 100_000,
            max_open_orders_per_trader: 1_000,
            max_commands_per_height: 50_000,
            max_commands_per_trader_per_height: 500,
            max_traders: 100_000,
        }
    }
}

impl EngineConfig {
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.max_price_ticks == 0
            || self.max_quantity_lots == 0
            || self.recent_trade_limit == 0
            || self.max_open_orders == 0
            || self.max_open_orders_per_trader == 0
            || self.max_open_orders_per_trader > self.max_open_orders
            || self.max_commands_per_height == 0
            || self.max_commands_per_trader_per_height == 0
            || self.max_commands_per_trader_per_height > self.max_commands_per_height
            || self.max_traders == 0
        {
            return Err(EngineError::InvalidJournal(
                "invalid matcher engine limits".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EngineError {
    #[error("this matcher only accepts {MARKET}")]
    WrongMarket,
    #[error("price and quantity must both be greater than zero")]
    ZeroValue,
    #[error("price or quantity exceeds the configured risk bound")]
    RiskBound,
    #[error("client_order_id must contain 1 to 96 printable characters")]
    InvalidClientOrderId,
    #[error("client_cancel_id must contain 1 to 96 printable characters")]
    InvalidClientCancelId,
    #[error("order is not yet live at matcher chain height {0}")]
    NotYetLive(u64),
    #[error("order expired at matcher chain height {0}")]
    Expired(u64),
    #[error("invalid trader key, chain id, or BIP340 signature")]
    InvalidSignature,
    #[error("demo signatures are disabled")]
    DemoDisabled,
    #[error("nonce must be strictly greater than the trader's last accepted nonce")]
    NonceReplay,
    #[error("idempotency key was reused with different order content")]
    IdempotencyConflict,
    #[error("post-only order would immediately trade")]
    PostOnlyWouldCross,
    #[error("fill-or-kill order cannot fill completely at the limit price")]
    FillOrKillUnavailable,
    #[error("reduce-only order would not strictly reduce the current position")]
    ReduceOnlyViolation,
    #[error("initial margin must be one of 10000, 5000, 3334, 2000, or 1000 basis points")]
    InvalidInitialMargin,
    #[error("missing or invalid v2 order risk commitment")]
    InvalidRiskCommitment,
    #[error("order not found")]
    OrderNotFound,
    #[error("only the trader that placed an order may cancel it")]
    NotOrderOwner,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("matcher admission quota is exhausted at the current sidechain height")]
    AdmissionQuota,
    #[error("invalid journal command: {0}")]
    InvalidJournal(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestingOrder {
    order_id: String,
    request: SubmitOrderRequest,
    original_quantity_lots: u64,
    remaining_quantity_lots: u64,
    created_sequence: u64,
}

impl RestingOrder {
    fn view(&self) -> RestingOrderView {
        RestingOrderView {
            order_id: self.order_id.clone(),
            client_order_id: self.request.client_order_id.clone(),
            trader: self.request.trader.clone(),
            side: self.request.side,
            price_ticks: self.request.limit_price_ticks,
            original_quantity_lots: self.original_quantity_lots,
            remaining_quantity_lots: self.remaining_quantity_lots,
            reduce_only: self.request.reduce_only,
            created_sequence: self.created_sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cached<T> {
    request_hash: [u8; 32],
    outcome: T,
    matcher_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    config: EngineConfig,
    sequence: u64,
    bids: BTreeMap<u64, VecDeque<String>>,
    asks: BTreeMap<u64, VecDeque<String>>,
    orders: HashMap<String, RestingOrder>,
    last_nonce: HashMap<String, u64>,
    submit_cache: HashMap<(String, String), Cached<SubmitOrderOutcome>>,
    cancel_cache: HashMap<(String, String), Cached<CancelOrderOutcome>>,
    positions: HashMap<String, PositionView>,
    recent_trades: VecDeque<Trade>,
    open_orders_by_trader: HashMap<String, usize>,
    quota_height: u64,
    commands_at_height: u64,
    commands_by_trader_at_height: HashMap<String, u64>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let quota_height = config.chain_height;
        Self {
            config,
            sequence: 0,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
            last_nonce: HashMap::new(),
            submit_cache: HashMap::new(),
            cancel_cache: HashMap::new(),
            positions: HashMap::new(),
            recent_trades: VecDeque::new(),
            open_orders_by_trader: HashMap::new(),
            quota_height,
            commands_at_height: 0,
            commands_by_trader_at_height: HashMap::new(),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn chain_height(&self) -> u64 {
        self.config.chain_height
    }

    pub(crate) fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Advance to a node-authenticated active-chain height and remove orders
    /// that can no longer be matched. Regressions fail closed: replaying an
    /// alternate chain requires a fresh process/state reconciliation instead
    /// of silently resurrecting already removed FIFO entries.
    pub fn advance_chain_height(&mut self, height: u64) -> Result<(), EngineError> {
        if height == 0 || height < self.config.chain_height {
            return Err(EngineError::InvalidJournal(
                "sidechain height is zero or regressed".into(),
            ));
        }
        self.config.chain_height = height;
        if height > self.quota_height {
            self.quota_height = height;
            self.commands_at_height = 0;
            self.commands_by_trader_at_height.clear();
        }
        let expired: Vec<(String, Side, u64)> = self
            .orders
            .values()
            .filter(|order| order.request.expires_at_height < height)
            .map(|order| {
                (
                    order.order_id.clone(),
                    order.request.side,
                    order.request.limit_price_ticks,
                )
            })
            .collect();
        for (order_id, side, price) in expired {
            if let Some(order) = self.orders.get(&order_id) {
                decrement_count(&mut self.open_orders_by_trader, &order.request.trader)?;
            }
            self.remove_from_level(side, price, &order_id);
            self.orders.remove(&order_id);
        }
        Ok(())
    }

    pub fn demo_mode(&self) -> bool {
        self.config.demo_mode
    }

    pub fn submit(
        &mut self,
        request: SubmitOrderRequest,
        received_at_ms: u64,
    ) -> Result<Mutation<SubmitOrderOutcome>, EngineError> {
        self.submit_inner(request, received_at_ms, true, None, None, false)
    }

    /// Applies a newly accepted command using its central matcher receipt
    /// sequence as the price-time priority sequence.
    pub fn submit_sequenced(
        &mut self,
        request: SubmitOrderRequest,
        received_at_ms: u64,
        matcher_sequence: u64,
    ) -> Result<Mutation<SubmitOrderOutcome>, EngineError> {
        if matcher_sequence == 0 {
            return Err(EngineError::InvalidJournal(
                "matcher sequence must be nonzero".into(),
            ));
        }
        self.submit_inner(
            request,
            received_at_ms,
            true,
            Some(matcher_sequence),
            None,
            false,
        )
    }

    pub fn submit_sequenced_v2(
        &mut self,
        request: SubmitOrderRequestV2,
        received_at_ms: u64,
        matcher_sequence: u64,
    ) -> Result<Mutation<SubmitOrderOutcome>, EngineError> {
        if matcher_sequence == 0 {
            return Err(EngineError::InvalidJournal(
                "matcher sequence must be nonzero".into(),
            ));
        }
        let request_hash = serialized_hash(&request)?;
        self.submit_inner(
            request.order,
            received_at_ms,
            true,
            Some(matcher_sequence),
            Some(request_hash),
            true,
        )
    }

    pub fn cancel(
        &mut self,
        order_id: &str,
        request: CancelOrderRequest,
        received_at_ms: u64,
    ) -> Result<Mutation<CancelOrderOutcome>, EngineError> {
        self.cancel_inner(order_id, request, received_at_ms, true, None)
    }

    pub fn cancel_sequenced(
        &mut self,
        order_id: &str,
        request: CancelOrderRequest,
        received_at_ms: u64,
        matcher_sequence: u64,
    ) -> Result<Mutation<CancelOrderOutcome>, EngineError> {
        if matcher_sequence == 0 {
            return Err(EngineError::InvalidJournal(
                "matcher sequence must be nonzero".into(),
            ));
        }
        self.cancel_inner(
            order_id,
            request,
            received_at_ms,
            true,
            Some(matcher_sequence),
        )
    }

    /// Applies a previously durable command. Authentication and current-height
    /// checks were performed before the command entered the journal.
    pub fn replay_sequenced(
        &mut self,
        command: EngineCommand,
        matcher_sequence: u64,
    ) -> Result<Vec<MarketEvent>, EngineError> {
        Ok(self
            .replay_sequenced_with_executions(command, matcher_sequence)?
            .0)
    }

    pub(crate) fn replay_sequenced_with_executions(
        &mut self,
        command: EngineCommand,
        matcher_sequence: u64,
    ) -> Result<(Vec<MarketEvent>, Vec<StagedMatcherExecutionV2>), EngineError> {
        if matcher_sequence == 0 {
            return Err(EngineError::InvalidJournal(
                "matcher sequence must be nonzero".into(),
            ));
        }
        match command {
            EngineCommand::Submit {
                request,
                received_at_ms,
            } => {
                let mutation = self.submit_inner(
                    request,
                    received_at_ms,
                    false,
                    Some(matcher_sequence),
                    None,
                    false,
                )?;
                Ok((mutation.events, mutation.executions_v2))
            }
            EngineCommand::SubmitV2 {
                request,
                received_at_ms,
            } => {
                let request_hash = serialized_hash(&request)?;
                let mutation = self.submit_inner(
                    request.order,
                    received_at_ms,
                    false,
                    Some(matcher_sequence),
                    Some(request_hash),
                    true,
                )?;
                Ok((mutation.events, mutation.executions_v2))
            }
            EngineCommand::Cancel {
                order_id,
                request,
                received_at_ms,
            } => {
                let mutation = self.cancel_inner(
                    &order_id,
                    request,
                    received_at_ms,
                    false,
                    Some(matcher_sequence),
                )?;
                Ok((mutation.events, mutation.executions_v2))
            }
        }
    }

    fn submit_inner(
        &mut self,
        request: SubmitOrderRequest,
        received_at_ms: u64,
        authenticate: bool,
        matcher_sequence: Option<u64>,
        request_hash_override: Option<[u8; 32]>,
        capture_v2_executions: bool,
    ) -> Result<Mutation<SubmitOrderOutcome>, EngineError> {
        let cache_key = (request.trader.clone(), request.client_order_id.clone());
        let request_hash = request_hash_override.unwrap_or(serialized_hash(&request)?);
        if let Some(cached) = self.submit_cache.get(&cache_key) {
            if cached.request_hash != request_hash {
                return Err(EngineError::IdempotencyConflict);
            }
            let mut outcome = cached.outcome.clone();
            outcome.duplicate = true;
            return Ok(Mutation {
                outcome,
                events: Vec::new(),
                executions_v2: Vec::new(),
            });
        }

        self.validate_order(&request, authenticate)?;
        self.consume_admission(&request.trader, request.time_in_force == TimeInForce::Gtc)?;
        if request.post_only && self.would_cross(request.side, request.limit_price_ticks) {
            return Err(EngineError::PostOnlyWouldCross);
        }
        if request.time_in_force == TimeInForce::Fok
            && self.available_to_fill(&request) < request.quantity_lots
        {
            return Err(EngineError::FillOrKillUnavailable);
        }
        if request.reduce_only && !self.strictly_reduces(&request) {
            return Err(EngineError::ReduceOnlyViolation);
        }

        self.last_nonce
            .insert(request.trader.clone(), request.nonce);
        let order_id = order_id(&request)?;
        let original_quantity_lots = request.quantity_lots;
        let mut remaining_quantity_lots = original_quantity_lots;
        let mut trades = Vec::new();
        let mut executions_v2 = Vec::new();
        let mut self_trade_prevented = false;
        self.bump_sequence()?;
        let accepted_sequence = matcher_sequence.unwrap_or(self.sequence);

        while remaining_quantity_lots > 0 {
            let Some((maker_price, maker_order_id)) = self.best_match(&request) else {
                break;
            };
            let maker = self.orders.get(&maker_order_id).cloned().ok_or_else(|| {
                EngineError::InvalidJournal("book references missing order".into())
            })?;
            if maker.request.trader == request.trader {
                self_trade_prevented = true;
                break;
            }

            let fill_quantity = remaining_quantity_lots.min(maker.remaining_quantity_lots);
            if capture_v2_executions {
                executions_v2.push(staged_execution_v2(
                    &maker.request,
                    &request,
                    accepted_sequence,
                    maker_price,
                    fill_quantity,
                    self.config.chain_height,
                )?);
            }
            remaining_quantity_lots -= fill_quantity;
            let maker_remaining = maker
                .remaining_quantity_lots
                .checked_sub(fill_quantity)
                .ok_or(EngineError::ArithmeticOverflow)?;
            if maker_remaining == 0 {
                decrement_count(&mut self.open_orders_by_trader, &maker.request.trader)?;
                self.remove_filled_head(maker.request.side, maker_price, &maker_order_id)?;
                self.orders.remove(&maker_order_id);
            } else {
                self.orders
                    .get_mut(&maker_order_id)
                    .ok_or_else(|| {
                        EngineError::InvalidJournal("maker disappeared while filling".into())
                    })?
                    .remaining_quantity_lots = maker_remaining;
            }

            self.bump_sequence()?;
            let (buyer, seller) = match request.side {
                Side::Buy => (request.trader.clone(), maker.request.trader.clone()),
                Side::Sell => (maker.request.trader.clone(), request.trader.clone()),
            };
            let trade = Trade {
                trade_id: trade_id(
                    self.sequence,
                    &maker_order_id,
                    &order_id,
                    maker_price,
                    fill_quantity,
                ),
                sequence: self.sequence,
                maker_order_id,
                taker_order_id: order_id.clone(),
                buyer: buyer.clone(),
                seller: seller.clone(),
                price_ticks: maker_price,
                quantity_lots: fill_quantity,
                executed_at_ms: received_at_ms,
            };
            self.apply_position_fill(
                &buyer,
                i64::try_from(fill_quantity).map_err(|_| EngineError::ArithmeticOverflow)?,
                maker_price,
            )?;
            self.apply_position_fill(&seller, -(fill_quantity as i64), maker_price)?;
            self.recent_trades.push_front(trade.clone());
            self.recent_trades.truncate(self.config.recent_trade_limit);
            trades.push(trade);
        }

        let may_rest = request.time_in_force == TimeInForce::Gtc && !self_trade_prevented;
        if remaining_quantity_lots > 0 && may_rest {
            let resting = RestingOrder {
                order_id: order_id.clone(),
                request: request.clone(),
                original_quantity_lots,
                remaining_quantity_lots,
                created_sequence: accepted_sequence,
            };
            self.book_mut(request.side)
                .entry(request.limit_price_ticks)
                .or_default()
                .push_back(order_id.clone());
            self.orders.insert(order_id.clone(), resting);
            *self
                .open_orders_by_trader
                .entry(request.trader.clone())
                .or_default() += 1;
        }

        let status = if remaining_quantity_lots == 0 {
            OrderStatus::Filled
        } else if !trades.is_empty() {
            OrderStatus::PartiallyFilled
        } else if may_rest {
            OrderStatus::Resting
        } else {
            OrderStatus::Cancelled
        };
        let outcome = SubmitOrderOutcome {
            order_id,
            sequence: self.sequence,
            status,
            original_quantity_lots,
            remaining_quantity_lots,
            trades: trades.clone(),
            self_trade_prevented,
            duplicate: false,
        };
        self.submit_cache.insert(
            cache_key,
            Cached {
                request_hash,
                outcome: outcome.clone(),
                matcher_sequence: accepted_sequence,
            },
        );

        let mut events = trades
            .into_iter()
            .map(MarketEvent::Trade)
            .collect::<Vec<_>>();
        events.push(MarketEvent::Order(outcome.clone()));
        events.push(MarketEvent::Book(self.orderbook(40)));
        Ok(Mutation {
            outcome,
            events,
            executions_v2,
        })
    }

    fn cancel_inner(
        &mut self,
        order_id: &str,
        request: CancelOrderRequest,
        _received_at_ms: u64,
        authenticate: bool,
        matcher_sequence: Option<u64>,
    ) -> Result<Mutation<CancelOrderOutcome>, EngineError> {
        validate_client_cancel_id(&request.client_cancel_id)?;
        let (cache_key, request_hash) = if is_demo_trader(&request.trader) {
            (
                (request.trader.clone(), request.client_cancel_id.clone()),
                serialized_hash(&(order_id, &request))?,
            )
        } else {
            // The transport-level client_cancel_id is not part of the v1
            // consensus signature. Key production retries by the exact signed
            // cancel instead, so changing an unsigned correlation label cannot
            // defeat recovery of an already durable receipt.
            let signed = protocol_signed_cancel(order_id, &request)?;
            let command_hash = matcher_cancel_command_hash(&signed);
            (
                (request.trader.clone(), hex::encode(command_hash)),
                command_hash,
            )
        };
        if let Some(cached) = self.cancel_cache.get(&cache_key) {
            if cached.request_hash != request_hash {
                return Err(EngineError::IdempotencyConflict);
            }
            let mut outcome = cached.outcome.clone();
            outcome.duplicate = true;
            return Ok(Mutation {
                outcome,
                events: Vec::new(),
                executions_v2: Vec::new(),
            });
        }

        let resting = self
            .orders
            .get(order_id)
            .cloned()
            .ok_or(EngineError::OrderNotFound)?;
        if resting.request.trader != request.trader {
            return Err(EngineError::NotOrderOwner);
        }
        if authenticate {
            self.validate_cancel(order_id, &request)?;
        } else {
            self.validate_nonce(&request.trader, request.nonce)?;
        }
        self.consume_admission(&request.trader, false)?;

        self.last_nonce
            .insert(request.trader.clone(), request.nonce);
        self.remove_from_level(
            resting.request.side,
            resting.request.limit_price_ticks,
            order_id,
        );
        self.orders.remove(order_id);
        decrement_count(&mut self.open_orders_by_trader, &request.trader)?;
        self.bump_sequence()?;
        let outcome = CancelOrderOutcome {
            order_id: order_id.to_owned(),
            sequence: self.sequence,
            status: OrderStatus::Cancelled,
            cancelled_quantity_lots: resting.remaining_quantity_lots,
            duplicate: false,
        };
        self.cancel_cache.insert(
            cache_key,
            Cached {
                request_hash,
                outcome: outcome.clone(),
                matcher_sequence: matcher_sequence.unwrap_or(self.sequence),
            },
        );
        let events = vec![
            MarketEvent::Cancel(outcome.clone()),
            MarketEvent::Book(self.orderbook(40)),
        ];
        Ok(Mutation {
            outcome,
            events,
            executions_v2: Vec::new(),
        })
    }

    fn validate_order(
        &self,
        request: &SubmitOrderRequest,
        authenticate: bool,
    ) -> Result<(), EngineError> {
        if request.market != MARKET {
            return Err(EngineError::WrongMarket);
        }
        if request.limit_price_ticks == 0 || request.quantity_lots == 0 {
            return Err(EngineError::ZeroValue);
        }
        if request.limit_price_ticks > self.config.max_price_ticks
            || request.quantity_lots > self.config.max_quantity_lots
            || request.quantity_lots > i64::MAX as u64
        {
            return Err(EngineError::RiskBound);
        }
        if request.client_order_id.is_empty()
            || request.client_order_id.len() > 96
            || !request.client_order_id.chars().all(|c| !c.is_control())
        {
            return Err(EngineError::InvalidClientOrderId);
        }
        if authenticate {
            if request.valid_from_height > self.config.chain_height {
                return Err(EngineError::NotYetLive(self.config.chain_height));
            }
            if request.expires_at_height < self.config.chain_height
                || request.expires_at_height < request.valid_from_height
            {
                return Err(EngineError::Expired(self.config.chain_height));
            }
            self.verify_order_signature(request)?;
        }
        self.validate_nonce(&request.trader, request.nonce)
    }

    fn validate_cancel(
        &self,
        order_id: &str,
        request: &CancelOrderRequest,
    ) -> Result<(), EngineError> {
        self.validate_nonce(&request.trader, request.nonce)?;
        if is_demo_trader(&request.trader) {
            if self.config.demo_mode && request.signature.is_empty() {
                return Ok(());
            }
            return Err(EngineError::DemoDisabled);
        }
        if request.market != MARKET {
            return Err(EngineError::WrongMarket);
        }
        let signed = protocol_signed_cancel(order_id, request)?;
        if !signed.cancel.is_live_at(self.config.chain_height) {
            return Err(EngineError::Expired(self.config.chain_height));
        }
        signed.verify().map_err(|_| EngineError::InvalidSignature)
    }

    fn verify_order_signature(&self, request: &SubmitOrderRequest) -> Result<(), EngineError> {
        if is_demo_trader(&request.trader) {
            if self.config.demo_mode && request.signature.is_empty() {
                return Ok(());
            }
            return Err(EngineError::DemoDisabled);
        }
        protocol_signed_order(request)?
            .verify()
            .map_err(|_| EngineError::InvalidSignature)
    }

    fn validate_nonce(&self, trader: &str, nonce: u64) -> Result<(), EngineError> {
        if self
            .last_nonce
            .get(trader)
            .is_some_and(|last| nonce <= *last)
        {
            Err(EngineError::NonceReplay)
        } else {
            Ok(())
        }
    }

    fn consume_admission(&mut self, trader: &str, may_open: bool) -> Result<(), EngineError> {
        if self.config.max_open_orders == 0
            || self.config.max_open_orders_per_trader == 0
            || self.config.max_commands_per_height == 0
            || self.config.max_commands_per_trader_per_height == 0
            || self.quota_height != self.config.chain_height
        {
            return Err(EngineError::InvalidJournal(
                "matcher admission configuration or height is invalid".into(),
            ));
        }
        let trader_commands = self
            .commands_by_trader_at_height
            .get(trader)
            .copied()
            .unwrap_or(0);
        let new_trader = !self.last_nonce.contains_key(trader);
        if self.commands_at_height >= self.config.max_commands_per_height
            || trader_commands >= self.config.max_commands_per_trader_per_height
            || (may_open
                && (self.orders.len() >= self.config.max_open_orders
                    || self.open_orders_by_trader.get(trader).copied().unwrap_or(0)
                        >= self.config.max_open_orders_per_trader))
            || (new_trader && self.last_nonce.len() >= self.config.max_traders)
        {
            return Err(EngineError::AdmissionQuota);
        }
        self.commands_at_height = self
            .commands_at_height
            .checked_add(1)
            .ok_or(EngineError::ArithmeticOverflow)?;
        self.commands_by_trader_at_height.insert(
            trader.to_owned(),
            trader_commands
                .checked_add(1)
                .ok_or(EngineError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub(crate) fn compact_idempotency(&mut self, minimum_matcher_sequence: u64) {
        self.submit_cache
            .retain(|_, value| value.matcher_sequence >= minimum_matcher_sequence);
        self.cancel_cache
            .retain(|_, value| value.matcher_sequence >= minimum_matcher_sequence);
    }

    pub(crate) fn validate_restored(&self, expected: &EngineConfig) -> Result<(), EngineError> {
        let mut expected_policy = expected.clone();
        expected_policy.chain_height = self.config.chain_height;
        if self.config != expected_policy || self.quota_height != self.config.chain_height {
            return Err(EngineError::InvalidJournal(
                "matcher snapshot engine configuration differs".into(),
            ));
        }
        if self.orders.len() > self.config.max_open_orders
            || self.last_nonce.len() > self.config.max_traders
            || self.commands_at_height > self.config.max_commands_per_height
            || self
                .commands_by_trader_at_height
                .values()
                .any(|count| *count > self.config.max_commands_per_trader_per_height)
        {
            return Err(EngineError::InvalidJournal(
                "matcher snapshot exceeds configured limits".into(),
            ));
        }
        let mut seen = HashMap::<String, usize>::new();
        for (side, book) in [(Side::Buy, &self.bids), (Side::Sell, &self.asks)] {
            for (price, queue) in book {
                if queue.is_empty() {
                    return Err(EngineError::InvalidJournal(
                        "matcher snapshot contains an empty price level".into(),
                    ));
                }
                for order_id in queue {
                    let order = self.orders.get(order_id).ok_or_else(|| {
                        EngineError::InvalidJournal(
                            "matcher snapshot book references a missing order".into(),
                        )
                    })?;
                    if order.request.side != side || order.request.limit_price_ticks != *price {
                        return Err(EngineError::InvalidJournal(
                            "matcher snapshot order is in the wrong price queue".into(),
                        ));
                    }
                    *seen.entry(order_id.clone()).or_default() += 1;
                }
            }
        }
        if seen.len() != self.orders.len() || seen.values().any(|count| *count != 1) {
            return Err(EngineError::InvalidJournal(
                "matcher snapshot order index is not bijective".into(),
            ));
        }
        let mut counts = HashMap::new();
        for order in self.orders.values() {
            *counts.entry(order.request.trader.clone()).or_default() += 1;
        }
        if counts != self.open_orders_by_trader
            || counts
                .values()
                .any(|count| *count > self.config.max_open_orders_per_trader)
        {
            return Err(EngineError::InvalidJournal(
                "matcher snapshot open-order counts disagree".into(),
            ));
        }
        Ok(())
    }

    fn would_cross(&self, side: Side, limit_price: u64) -> bool {
        match side {
            Side::Buy => self
                .asks
                .first_key_value()
                .is_some_and(|(ask, _)| *ask <= limit_price),
            Side::Sell => self
                .bids
                .last_key_value()
                .is_some_and(|(bid, _)| *bid >= limit_price),
        }
    }

    fn available_to_fill(&self, request: &SubmitOrderRequest) -> u64 {
        let accumulate = |levels: &mut dyn Iterator<Item = (&u64, &VecDeque<String>)>| {
            let mut available = 0u64;
            for (_, queue) in levels {
                for order_id in queue {
                    let Some(order) = self.orders.get(order_id) else {
                        // A malformed book must never make FOK preflight optimistic.
                        return available;
                    };
                    if order.request.trader == request.trader {
                        // Matching stops at this exact FIFO position under the
                        // cancel-taker STP rule, so deeper liquidity is unreachable.
                        return available;
                    }
                    available = available.saturating_add(order.remaining_quantity_lots);
                    if available >= request.quantity_lots {
                        return available;
                    }
                }
            }
            available
        };

        match request.side {
            Side::Buy => accumulate(&mut self.asks.range(..=request.limit_price_ticks)),
            Side::Sell => accumulate(&mut self.bids.range(request.limit_price_ticks..).rev()),
        }
    }

    fn strictly_reduces(&self, request: &SubmitOrderRequest) -> bool {
        let net = self
            .positions
            .get(&request.trader)
            .map_or(0, |position| position.net_quantity_lots);
        match (net.signum(), request.side) {
            (1, Side::Sell) => request.quantity_lots <= net.unsigned_abs(),
            (-1, Side::Buy) => request.quantity_lots <= net.unsigned_abs(),
            _ => false,
        }
    }

    fn best_match(&self, taker: &SubmitOrderRequest) -> Option<(u64, String)> {
        let (price, queue) = match taker.side {
            Side::Buy => self.asks.first_key_value()?,
            Side::Sell => self.bids.last_key_value()?,
        };
        let crosses = match taker.side {
            Side::Buy => *price <= taker.limit_price_ticks,
            Side::Sell => *price >= taker.limit_price_ticks,
        };
        crosses.then(|| (*price, queue.front().expect("non-empty book level").clone()))
    }

    fn remove_filled_head(
        &mut self,
        maker_side: Side,
        price: u64,
        expected_id: &str,
    ) -> Result<(), EngineError> {
        let book = self.book_mut(maker_side);
        let queue = book
            .get_mut(&price)
            .ok_or_else(|| EngineError::InvalidJournal("missing maker price level".into()))?;
        if queue.front().map(String::as_str) != Some(expected_id) {
            return Err(EngineError::InvalidJournal(
                "price-time queue head changed unexpectedly".into(),
            ));
        }
        queue.pop_front();
        if queue.is_empty() {
            book.remove(&price);
        }
        Ok(())
    }

    fn remove_from_level(&mut self, side: Side, price: u64, order_id: &str) {
        let book = self.book_mut(side);
        if let Some(queue) = book.get_mut(&price) {
            queue.retain(|id| id != order_id);
            if queue.is_empty() {
                book.remove(&price);
            }
        }
    }

    fn book_mut(&mut self, side: Side) -> &mut BTreeMap<u64, VecDeque<String>> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn apply_position_fill(
        &mut self,
        trader: &str,
        signed_quantity: i64,
        price: u64,
    ) -> Result<(), EngineError> {
        let position = self
            .positions
            .entry(trader.to_owned())
            .or_insert_with(|| PositionView {
                market: MARKET.to_owned(),
                ..PositionView::default()
            });
        let old_net = position.net_quantity_lots;
        if old_net == 0 || old_net.signum() == signed_quantity.signum() {
            let old_notional = (position.average_entry_price_ticks as i128)
                .checked_mul(old_net.unsigned_abs() as i128)
                .ok_or(EngineError::ArithmeticOverflow)?;
            let added_notional = (price as i128)
                .checked_mul(signed_quantity.unsigned_abs() as i128)
                .ok_or(EngineError::ArithmeticOverflow)?;
            let new_net = old_net
                .checked_add(signed_quantity)
                .ok_or(EngineError::ArithmeticOverflow)?;
            let total_quantity = new_net.unsigned_abs();
            position.net_quantity_lots = new_net;
            position.average_entry_price_ticks =
                u64::try_from((old_notional + added_notional) / total_quantity as i128)
                    .map_err(|_| EngineError::ArithmeticOverflow)?;
            return Ok(());
        }

        let closed_quantity = old_net.unsigned_abs().min(signed_quantity.unsigned_abs());
        let pnl_per_lot = if old_net > 0 {
            price as i128 - position.average_entry_price_ticks as i128
        } else {
            position.average_entry_price_ticks as i128 - price as i128
        };
        let realized = pnl_per_lot
            .checked_mul(closed_quantity as i128)
            .ok_or(EngineError::ArithmeticOverflow)?
            / i128::from(ecx_protocol_core::PRICE_SCALE);
        position.realized_pnl_quote_units =
            i64::try_from(position.realized_pnl_quote_units as i128 + realized)
                .map_err(|_| EngineError::ArithmeticOverflow)?;
        let new_net = old_net
            .checked_add(signed_quantity)
            .ok_or(EngineError::ArithmeticOverflow)?;
        position.net_quantity_lots = new_net;
        if new_net == 0 {
            position.average_entry_price_ticks = 0;
        } else if new_net.signum() == signed_quantity.signum() {
            // The fill crossed through flat, so the residual opens at this fill price.
            position.average_entry_price_ticks = price;
        }
        Ok(())
    }

    fn bump_sequence(&mut self) -> Result<(), EngineError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(EngineError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn orderbook(&self, depth: usize) -> OrderBookSnapshot {
        let aggregate = |book: &BTreeMap<u64, VecDeque<String>>, descending: bool| {
            let mut levels = book
                .iter()
                .filter_map(|(price, queue)| {
                    let quantity = queue
                        .iter()
                        .filter_map(|id| self.orders.get(id))
                        .fold(0u64, |sum, order| {
                            sum.saturating_add(order.remaining_quantity_lots)
                        });
                    (quantity > 0).then_some(PriceLevel {
                        price_ticks: *price,
                        quantity_lots: quantity,
                        order_count: queue.len(),
                    })
                })
                .collect::<Vec<_>>();
            if descending {
                levels.reverse();
            }
            levels.truncate(depth);
            levels
        };
        OrderBookSnapshot {
            market: MARKET.to_owned(),
            sequence: self.sequence,
            bids: aggregate(&self.bids, true),
            asks: aggregate(&self.asks, false),
        }
    }

    pub fn recent_trades(&self, limit: usize) -> Vec<Trade> {
        self.recent_trades.iter().take(limit).cloned().collect()
    }

    /// Operational admission modes may only be enabled after establishing
    /// that every already-resting order obeys the new restriction.
    pub(crate) fn has_non_reduce_only_open_orders(&self) -> bool {
        self.orders.values().any(|order| !order.request.reduce_only)
    }

    pub(crate) fn has_open_orders(&self) -> bool {
        !self.orders.is_empty()
    }

    pub fn account(&self, trader: &str) -> AccountView {
        let mut open_orders = self
            .orders
            .values()
            .filter(|order| order.request.trader == trader)
            .map(RestingOrder::view)
            .collect::<Vec<_>>();
        open_orders.sort_by_key(|order| order.created_sequence);
        let recent_trades = self
            .recent_trades
            .iter()
            .filter(|trade| trade.buyer == trader || trade.seller == trader)
            .take(100)
            .cloned()
            .collect();
        AccountView {
            trader: trader.to_owned(),
            provisional: true,
            position: self
                .positions
                .get(trader)
                .cloned()
                .unwrap_or_else(|| PositionView {
                    market: MARKET.to_owned(),
                    ..PositionView::default()
                }),
            open_orders,
            recent_trades,
        }
    }
}

fn staged_execution_v2(
    maker_request: &SubmitOrderRequest,
    taker_request: &SubmitOrderRequest,
    admission_sequence: u64,
    price_ticks: u64,
    quantity_lots: u64,
    sidechain_height: u64,
) -> Result<StagedMatcherExecutionV2, EngineError> {
    let maker = protocol_signed_order(maker_request)?;
    let taker = protocol_signed_order(taker_request)?;
    let price = Price::new(price_ticks).map_err(|_| EngineError::RiskBound)?;
    let quantity = Quantity::new(quantity_lots).map_err(|_| EngineError::RiskBound)?;
    let risk = RiskParams::default();
    if risk.maker_fee_bps.unsigned_abs() > maker.order.max_fee_bps
        || risk.taker_fee_bps > taker.order.max_fee_bps
    {
        return Err(EngineError::InvalidRiskCommitment);
    }
    let trade = TradeMatch {
        sequence: admission_sequence,
        maker_order_id: maker.order_id(),
        taker_order_id: taker.order_id(),
        maker: maker.order.trader,
        taker: taker.order.trader,
        maker_side: maker.order.side,
        price,
        quantity,
        maker_fee: trading_fee(price, quantity, risk.maker_fee_bps)
            .map_err(|error| EngineError::InvalidJournal(error.to_string()))?,
        taker_fee: trading_fee(
            price,
            quantity,
            i32::try_from(risk.taker_fee_bps).map_err(|_| EngineError::ArithmeticOverflow)?,
        )
        .map_err(|error| EngineError::InvalidJournal(error.to_string()))?,
    };
    trade
        .validate_orders(&maker, &taker, sidechain_height)
        .map_err(|error| EngineError::InvalidJournal(error.to_string()))?;
    Ok(StagedMatcherExecutionV2 {
        maker,
        taker,
        trade,
    })
}

/// Builds the exact consensus-shaped order accepted by the transition verifier.
/// No independent matcher signing schema is permitted on the production path.
pub fn protocol_limit_order(request: &SubmitOrderRequest) -> Result<LimitOrder, EngineError> {
    if request.market != MARKET {
        return Err(EngineError::WrongMarket);
    }
    let chain_id = decode_array::<32>(&request.chain_id)?;
    let trader = XOnlyKey(decode_array::<32>(&request.trader)?);
    let mut flags = 0u8;
    if request.reduce_only {
        flags |= OrderFlags::REDUCE_ONLY.bits();
    }
    if request.post_only {
        flags |= OrderFlags::POST_ONLY.bits();
    }
    let order = LimitOrder {
        version: LimitOrder::VERSION,
        chain_id,
        market: ECX_USDD_MARKET,
        trader,
        side: match request.side {
            Side::Buy => ecx_protocol_core::Side::Buy,
            Side::Sell => ecx_protocol_core::Side::Sell,
        },
        time_in_force: match request.time_in_force {
            TimeInForce::Gtc => ecx_protocol_core::TimeInForce::GoodTilHeight,
            TimeInForce::Ioc => ecx_protocol_core::TimeInForce::ImmediateOrCancel,
            TimeInForce::Fok => ecx_protocol_core::TimeInForce::FillOrKill,
        },
        flags: OrderFlags::from_bits(flags).ok_or(EngineError::InvalidSignature)?,
        limit_price: Price::new(request.limit_price_ticks).map_err(|_| EngineError::RiskBound)?,
        quantity: Quantity::new(request.quantity_lots).map_err(|_| EngineError::RiskBound)?,
        client_order_id: decode_array::<16>(&request.client_order_id)?,
        max_fee_bps: request.max_fee_bps,
        nonce: request.nonce,
        valid_from_height: request.valid_from_height,
        expires_at_height: request.expires_at_height,
    };
    order
        .validate()
        .map_err(|_| EngineError::InvalidSignature)?;
    Ok(order)
}

pub fn protocol_signed_order(
    request: &SubmitOrderRequest,
) -> Result<SignedLimitOrder, EngineError> {
    let signature = Signature64(decode_array::<64>(&request.signature)?);
    Ok(SignedLimitOrder {
        order: protocol_limit_order(request)?,
        signature,
    })
}

/// Reconstructs and verifies the exact proof-consumed v2 collateral
/// commitment from the transport request. Both signatures must refer to the
/// same canonical order ID and trader.
pub fn protocol_order_risk_commitment(
    request: &SubmitOrderRequestV2,
) -> Result<OrderRiskCommitmentV2, EngineError> {
    ecx_protocol_core::validate_selected_margin_bps(
        request.initial_margin_bps,
        RiskParams::default(),
    )
    .map_err(|_| EngineError::InvalidInitialMargin)?;
    let signed_order = protocol_signed_order(&request.order)?;
    signed_order
        .verify()
        .map_err(|_| EngineError::InvalidSignature)?;
    let commitment = OrderRiskCommitmentV2 {
        version: OrderRiskCommitmentV2::VERSION,
        configuration_hash: decode_array::<32>(&request.configuration_hash)
            .map_err(|_| EngineError::InvalidRiskCommitment)?,
        order_id: signed_order.order_id(),
        trader: signed_order.order.trader,
        selected_initial_margin_bps: request.initial_margin_bps,
        signature: Signature64(
            decode_array::<64>(&request.risk_commitment_signature)
                .map_err(|_| EngineError::InvalidRiskCommitment)?,
        ),
    };
    commitment
        .verify(RiskParams::default())
        .map_err(|_| EngineError::InvalidRiskCommitment)?;
    Ok(commitment)
}

pub fn protocol_signed_cancel(
    order_id: &str,
    request: &CancelOrderRequest,
) -> Result<SignedCancelOrder, EngineError> {
    if request.market != MARKET {
        return Err(EngineError::WrongMarket);
    }
    let cancel = CancelOrder {
        version: CancelOrder::VERSION,
        chain_id: decode_array::<32>(&request.chain_id)?,
        market: ECX_USDD_MARKET,
        trader: XOnlyKey(decode_array::<32>(&request.trader)?),
        order_id: decode_array::<32>(order_id)?,
        nonce: request.nonce,
        valid_from_height: request.valid_from_height,
        expires_at_height: request.expires_at_height,
    };
    cancel
        .validate()
        .map_err(|_| EngineError::InvalidSignature)?;
    Ok(SignedCancelOrder {
        cancel,
        signature: Signature64(decode_array::<64>(&request.signature)?),
    })
}

fn order_id(request: &SubmitOrderRequest) -> Result<String, EngineError> {
    if !is_demo_trader(&request.trader) {
        return Ok(hex::encode(protocol_signed_order(request)?.order_id()));
    }
    let mut hasher = Sha256::new();
    hasher.update(DEMO_ORDER_ID_DOMAIN);
    hasher.update(serialized_hash(request)?);
    Ok(hex::encode(hasher.finalize()))
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], EngineError> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EngineError::InvalidSignature);
    }
    let bytes = hex::decode(value).map_err(|_| EngineError::InvalidSignature)?;
    bytes.try_into().map_err(|_| EngineError::InvalidSignature)
}

fn validate_client_cancel_id(value: &str) -> Result<(), EngineError> {
    if value.is_empty()
        || value.len() > 96
        || !value.chars().all(|character| !character.is_control())
    {
        return Err(EngineError::InvalidClientCancelId);
    }
    Ok(())
}

fn trade_id(
    sequence: u64,
    maker_order_id: &str,
    taker_order_id: &str,
    price: u64,
    quantity: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TRADE_ID_DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(maker_order_id.as_bytes());
    hasher.update(taker_order_id.as_bytes());
    hasher.update(price.to_be_bytes());
    hasher.update(quantity.to_be_bytes());
    hex::encode(hasher.finalize())
}

fn decrement_count(counts: &mut HashMap<String, usize>, trader: &str) -> Result<(), EngineError> {
    let count = counts
        .get_mut(trader)
        .ok_or_else(|| EngineError::InvalidJournal("missing open-order trader count".into()))?;
    *count = count
        .checked_sub(1)
        .ok_or_else(|| EngineError::InvalidJournal("open-order trader count underflow".into()))?;
    if *count == 0 {
        counts.remove(trader);
    }
    Ok(())
}

fn serialized_hash<T: serde::Serialize>(value: &T) -> Result<[u8; 32], EngineError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EngineError::InvalidJournal(error.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

fn is_demo_trader(trader: &str) -> bool {
    trader.starts_with("demo-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        })
    }

    fn order(
        trader: &str,
        client_id: &str,
        side: Side,
        price: u64,
        quantity: u64,
        nonce: u64,
    ) -> SubmitOrderRequest {
        SubmitOrderRequest {
            client_order_id: client_id.into(),
            chain_id: "demo-chain".into(),
            trader: trader.into(),
            market: MARKET.into(),
            side,
            limit_price_ticks: price,
            quantity_lots: quantity,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce,
            valid_from_height: 0,
            expires_at_height: 1_000,
            signature: String::new(),
        }
    }

    #[test]
    fn price_time_priority_and_maker_price_are_deterministic() {
        let mut engine = engine();
        engine
            .submit(order("demo-maker-a", "a", Side::Sell, 101, 4, 1), 1)
            .unwrap();
        engine
            .submit(order("demo-maker-b", "b", Side::Sell, 101, 4, 1), 2)
            .unwrap();
        engine
            .submit(order("demo-maker-c", "c", Side::Sell, 102, 4, 1), 3)
            .unwrap();
        let result = engine
            .submit(order("demo-taker", "take", Side::Buy, 102, 10, 1), 4)
            .unwrap();

        assert_eq!(result.outcome.trades.len(), 3);
        assert_eq!(result.outcome.trades[0].seller, "demo-maker-a");
        assert_eq!(result.outcome.trades[1].seller, "demo-maker-b");
        assert_eq!(result.outcome.trades[2].seller, "demo-maker-c");
        assert_eq!(result.outcome.trades[0].price_ticks, 101);
        assert_eq!(result.outcome.trades[2].price_ticks, 102);
        assert_eq!(result.outcome.trades[2].quantity_lots, 2);
        assert_eq!(engine.orderbook(10).asks[0].quantity_lots, 2);
    }

    #[test]
    fn v1_order_wire_shape_has_no_v2_risk_fields() {
        let request = order("demo-default", "default", Side::Buy, 100, 1, 1);
        let encoded = serde_json::to_value(&request).unwrap();
        assert!(encoded.get("initial_margin_bps").is_none());
        assert!(encoded.get("risk_commitment_signature").is_none());

        let mut invalid = encoded;
        invalid["initial_margin_bps"] = serde_json::json!(1_000);
        assert!(serde_json::from_value::<SubmitOrderRequest>(invalid).is_err());
    }

    #[test]
    fn idempotent_retry_does_not_trade_twice() {
        let mut engine = engine();
        engine
            .submit(order("demo-maker", "maker", Side::Sell, 100, 5, 1), 1)
            .unwrap();
        let request = order("demo-taker", "stable-key", Side::Buy, 100, 5, 1);
        let first = engine.submit(request.clone(), 2).unwrap();
        let retry = engine.submit(request, 3).unwrap();
        assert_eq!(first.outcome.order_id, retry.outcome.order_id);
        assert!(retry.outcome.duplicate);
        assert!(retry.events.is_empty());
        assert_eq!(engine.recent_trades(10).len(), 1);
    }

    #[test]
    fn post_only_and_fok_preflight_do_not_mutate_book() {
        let mut engine = engine();
        engine
            .submit(order("demo-maker", "maker", Side::Sell, 100, 3, 1), 1)
            .unwrap();
        let before = engine.orderbook(10);

        let mut post_only = order("demo-post", "post", Side::Buy, 100, 1, 1);
        post_only.post_only = true;
        assert_eq!(
            engine.submit(post_only, 2).unwrap_err(),
            EngineError::PostOnlyWouldCross
        );
        let mut fok = order("demo-fok", "fok", Side::Buy, 100, 4, 1);
        fok.time_in_force = TimeInForce::Fok;
        assert_eq!(
            engine.submit(fok, 3).unwrap_err(),
            EngineError::FillOrKillUnavailable
        );
        assert_eq!(engine.orderbook(10), before);
    }

    #[test]
    fn cancel_requires_owner_and_preserves_fifo_for_survivors() {
        let mut engine = engine();
        let first = engine
            .submit(order("demo-a", "a", Side::Buy, 99, 2, 1), 1)
            .unwrap();
        engine
            .submit(order("demo-b", "b", Side::Buy, 99, 3, 1), 2)
            .unwrap();
        assert_eq!(
            engine
                .cancel(
                    &first.outcome.order_id,
                    CancelOrderRequest {
                        chain_id: "demo-chain".into(),
                        trader: "demo-b".into(),
                        market: MARKET.into(),
                        client_cancel_id: "wrong".into(),
                        nonce: 2,
                        valid_from_height: 0,
                        expires_at_height: 1_000,
                        signature: String::new(),
                    },
                    3,
                )
                .unwrap_err(),
            EngineError::NotOrderOwner
        );
        engine
            .cancel(
                &first.outcome.order_id,
                CancelOrderRequest {
                    chain_id: "demo-chain".into(),
                    trader: "demo-a".into(),
                    market: MARKET.into(),
                    client_cancel_id: "cancel-a".into(),
                    nonce: 2,
                    valid_from_height: 0,
                    expires_at_height: 1_000,
                    signature: String::new(),
                },
                4,
            )
            .unwrap();
        assert_eq!(engine.orderbook(10).bids[0].quantity_lots, 3);
    }

    #[test]
    fn realized_pnl_tracks_close_and_flip() {
        let mut engine = engine();
        let scale = ecx_protocol_core::PRICE_SCALE;
        engine
            .submit(
                order("demo-short", "s1", Side::Sell, 100 * scale, 10 * scale, 1),
                1,
            )
            .unwrap();
        engine
            .submit(
                order("demo-trader", "b1", Side::Buy, 100 * scale, 10 * scale, 1),
                2,
            )
            .unwrap();
        engine
            .submit(
                order("demo-buyer", "b2", Side::Buy, 110 * scale, 14 * scale, 1),
                3,
            )
            .unwrap();
        engine
            .submit(
                order("demo-trader", "s2", Side::Sell, 110 * scale, 14 * scale, 2),
                4,
            )
            .unwrap();
        let position = engine.account("demo-trader").position;
        assert_eq!(position.net_quantity_lots, -((4 * scale) as i64));
        assert_eq!(position.average_entry_price_ticks, 110 * scale);
        assert_eq!(position.realized_pnl_quote_units, (100 * scale) as i64);
    }

    #[test]
    fn self_trade_is_prevented_without_reordering_the_book() {
        let mut engine = engine();
        engine
            .submit(order("demo-a", "sell", Side::Sell, 100, 2, 1), 1)
            .unwrap();
        let result = engine
            .submit(order("demo-a", "buy", Side::Buy, 100, 2, 2), 2)
            .unwrap();
        assert!(result.outcome.self_trade_prevented);
        assert_eq!(result.outcome.status, OrderStatus::Cancelled);
        assert_eq!(engine.orderbook(10).asks[0].quantity_lots, 2);
    }

    #[test]
    fn fok_rejects_atomically_when_own_order_blocks_deeper_liquidity() {
        let mut engine = engine();
        engine
            .submit(order("demo-maker-a", "a", Side::Sell, 100, 2, 1), 1)
            .unwrap();
        engine
            .submit(order("demo-taker", "self", Side::Sell, 100, 1, 1), 2)
            .unwrap();
        engine
            .submit(order("demo-maker-b", "b", Side::Sell, 100, 3, 1), 3)
            .unwrap();

        let before_book = engine.orderbook(10);
        let before_taker = engine.account("demo-taker");
        let before_maker_a = engine.account("demo-maker-a");
        let before_maker_b = engine.account("demo-maker-b");
        let before_trades = engine.recent_trades(10);
        let before_sequence = engine.sequence();
        let mut fok = order("demo-taker", "fok", Side::Buy, 100, 4, 2);
        fok.time_in_force = TimeInForce::Fok;

        assert_eq!(
            engine.submit(fok, 4).unwrap_err(),
            EngineError::FillOrKillUnavailable
        );
        assert_eq!(engine.sequence(), before_sequence);
        assert_eq!(engine.orderbook(10), before_book);
        assert_eq!(engine.recent_trades(10), before_trades);
        assert_eq!(engine.account("demo-taker"), before_taker);
        assert_eq!(engine.account("demo-maker-a"), before_maker_a);
        assert_eq!(engine.account("demo-maker-b"), before_maker_b);
    }

    #[test]
    fn production_path_uses_protocol_core_signature_and_order_id() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

        let secret = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (trader, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut order = SubmitOrderRequest {
            client_order_id: hex::encode([8u8; 16]),
            chain_id: hex::encode([9u8; 32]),
            trader: hex::encode(trader.serialize()),
            market: MARKET.into(),
            side: Side::Buy,
            limit_price_ticks: 2 * ecx_protocol_core::PRICE_SCALE,
            quantity_lots: ecx_protocol_core::PRICE_SCALE,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce: 7,
            valid_from_height: 90,
            expires_at_height: 110,
            signature: String::new(),
        };
        let signed =
            SignedLimitOrder::sign(protocol_limit_order(&order).unwrap(), &secret).unwrap();
        order.signature = hex::encode(signed.signature.0);

        let outcome = engine().submit(order, 1).unwrap().outcome;
        assert_eq!(outcome.order_id, hex::encode(signed.order_id()));
        assert_eq!(outcome.status, OrderStatus::Resting);
    }

    #[test]
    fn v2_risk_commitment_rejects_missing_mutated_wrong_trader_and_wrong_margin() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

        let secret = SecretKey::from_slice(&[52u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (trader, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut order = SubmitOrderRequest {
            client_order_id: hex::encode([0x52; 16]),
            chain_id: hex::encode([9u8; 32]),
            trader: hex::encode(trader.serialize()),
            market: MARKET.into(),
            side: Side::Buy,
            limit_price_ticks: 2 * ecx_protocol_core::PRICE_SCALE,
            quantity_lots: ecx_protocol_core::PRICE_SCALE,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce: 7,
            valid_from_height: 90,
            expires_at_height: 110,
            signature: String::new(),
        };
        let signed_order =
            SignedLimitOrder::sign(protocol_limit_order(&order).unwrap(), &secret).unwrap();
        order.signature = hex::encode(signed_order.signature.0);
        let mut request = SubmitOrderRequestV2 {
            order,
            configuration_hash: hex::encode([54; 32]),
            initial_margin_bps: 5_000,
            risk_commitment_signature: String::new(),
        };
        let risk = OrderRiskCommitmentV2::sign(
            [54; 32],
            signed_order.order_id(),
            signed_order.order.trader,
            request.initial_margin_bps,
            &secret,
        )
        .unwrap();
        request.risk_commitment_signature = hex::encode(risk.signature.0);
        protocol_order_risk_commitment(&request).unwrap();

        let mut missing = request.clone();
        missing.risk_commitment_signature.clear();
        assert_eq!(
            protocol_order_risk_commitment(&missing).unwrap_err(),
            EngineError::InvalidRiskCommitment
        );

        let mut wrong_margin = request.clone();
        wrong_margin.initial_margin_bps = 3_334;
        assert_eq!(
            protocol_order_risk_commitment(&wrong_margin).unwrap_err(),
            EngineError::InvalidRiskCommitment
        );
        let mut invalid_margin = request.clone();
        invalid_margin.initial_margin_bps = 999;
        assert_eq!(
            protocol_order_risk_commitment(&invalid_margin).unwrap_err(),
            EngineError::InvalidInitialMargin
        );

        let wrong_secret = SecretKey::from_slice(&[53u8; 32]).unwrap();
        let wrong_keypair = Keypair::from_secret_key(&Secp256k1::new(), &wrong_secret);
        let (wrong_trader, _) = XOnlyPublicKey::from_keypair(&wrong_keypair);
        let wrong_risk = OrderRiskCommitmentV2::sign(
            [54; 32],
            signed_order.order_id(),
            XOnlyKey(wrong_trader.serialize()),
            request.initial_margin_bps,
            &wrong_secret,
        )
        .unwrap();
        let mut wrong_trader_request = request.clone();
        wrong_trader_request.risk_commitment_signature = hex::encode(wrong_risk.signature.0);
        assert_eq!(
            protocol_order_risk_commitment(&wrong_trader_request).unwrap_err(),
            EngineError::InvalidRiskCommitment
        );

        let mut mutated_order = request.clone();
        mutated_order.order.limit_price_ticks += 1;
        let resigned =
            SignedLimitOrder::sign(protocol_limit_order(&mutated_order.order).unwrap(), &secret)
                .unwrap();
        mutated_order.order.signature = hex::encode(resigned.signature.0);
        assert_eq!(
            protocol_order_risk_commitment(&mutated_order).unwrap_err(),
            EngineError::InvalidRiskCommitment
        );
    }

    #[test]
    fn production_cancel_uses_protocol_core_signed_cancel() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

        let secret = SecretKey::from_slice(&[43u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (trader_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let trader = hex::encode(trader_key.serialize());
        let chain_id = [9u8; 32];
        let mut request = SubmitOrderRequest {
            client_order_id: hex::encode([7u8; 16]),
            chain_id: hex::encode(chain_id),
            trader: trader.clone(),
            market: MARKET.into(),
            side: Side::Buy,
            limit_price_ticks: 2 * ecx_protocol_core::PRICE_SCALE,
            quantity_lots: ecx_protocol_core::PRICE_SCALE,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce: 7,
            valid_from_height: 90,
            expires_at_height: 110,
            signature: String::new(),
        };
        let signed_order =
            SignedLimitOrder::sign(protocol_limit_order(&request).unwrap(), &secret).unwrap();
        request.signature = hex::encode(signed_order.signature.0);
        let mut production_engine = engine();
        let order_id = production_engine
            .submit(request, 1)
            .unwrap()
            .outcome
            .order_id;

        let cancel = CancelOrder {
            version: CancelOrder::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            trader: XOnlyKey(trader_key.serialize()),
            order_id: signed_order.order_id(),
            nonce: 8,
            valid_from_height: 100,
            expires_at_height: 110,
        };
        let signed_cancel = SignedCancelOrder::sign(cancel, &secret).unwrap();
        let mut cancel_request = CancelOrderRequest {
            chain_id: hex::encode(chain_id),
            trader,
            market: MARKET.into(),
            client_cancel_id: "cancel-retry-key".into(),
            nonce: 8,
            valid_from_height: 100,
            expires_at_height: 110,
            signature: hex::encode(signed_cancel.signature.0),
        };
        let outcome = production_engine
            .cancel(&order_id, cancel_request.clone(), 2)
            .unwrap()
            .outcome;
        assert_eq!(outcome.status, OrderStatus::Cancelled);
        assert!(production_engine.orderbook(10).bids.is_empty());

        // client_cancel_id is an unsigned transport correlation label in v1.
        // Retrying the exact signed cancel with another label still recovers
        // the cached result and cannot consume the nonce twice.
        cancel_request.client_cancel_id = "replacement-correlation-label".into();
        let retry = production_engine
            .cancel(&order_id, cancel_request, 3)
            .unwrap()
            .outcome;
        assert!(retry.duplicate);
        assert_eq!(retry.order_id, order_id);
    }

    #[test]
    fn production_rejects_noncanonical_hex_aliases_before_nonce_or_book_mutation() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

        let secret = SecretKey::from_slice(&[44u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (trader, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut request = SubmitOrderRequest {
            client_order_id: hex::encode([0xabu8; 16]),
            chain_id: hex::encode([9u8; 32]),
            trader: hex::encode(trader.serialize()),
            market: MARKET.into(),
            side: Side::Buy,
            limit_price_ticks: ecx_protocol_core::PRICE_SCALE,
            quantity_lots: ecx_protocol_core::PRICE_SCALE,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce: 1,
            valid_from_height: 90,
            expires_at_height: 110,
            signature: String::new(),
        };
        let signed =
            SignedLimitOrder::sign(protocol_limit_order(&request).unwrap(), &secret).unwrap();
        request.signature = hex::encode(signed.signature.0);
        request.trader.make_ascii_uppercase();

        let mut production_engine = engine();
        assert_eq!(
            production_engine.submit(request, 1).unwrap_err(),
            EngineError::InvalidSignature
        );
        assert_eq!(production_engine.sequence(), 0);
        assert!(production_engine.orderbook(10).bids.is_empty());
    }

    #[test]
    fn admission_quotas_are_deterministic_and_idempotent_retries_are_free() {
        let mut matcher = Engine::new(EngineConfig {
            demo_mode: true,
            chain_height: 100,
            max_open_orders: 2,
            max_open_orders_per_trader: 1,
            max_commands_per_height: 2,
            max_commands_per_trader_per_height: 1,
            ..EngineConfig::default()
        });
        let first = order("demo-a", "one", Side::Buy, 90, 1, 1);
        let accepted = matcher.submit(first.clone(), 1).unwrap().outcome;
        assert!(!accepted.duplicate);
        let retry = matcher.submit(first, 2).unwrap().outcome;
        assert!(retry.duplicate);

        assert_eq!(
            matcher
                .submit(order("demo-a", "two", Side::Buy, 89, 1, 2), 3)
                .unwrap_err(),
            EngineError::AdmissionQuota
        );
        matcher
            .submit(order("demo-b", "one", Side::Sell, 110, 1, 1), 4)
            .unwrap();
        assert_eq!(
            matcher
                .submit(order("demo-c", "one", Side::Sell, 111, 1, 1), 5)
                .unwrap_err(),
            EngineError::AdmissionQuota
        );

        matcher.advance_chain_height(101).unwrap();
        let mut next_height = order("demo-c", "next", Side::Sell, 111, 1, 1);
        next_height.time_in_force = TimeInForce::Ioc;
        matcher.submit(next_height, 6).unwrap();
    }

    #[test]
    fn invalid_admission_limits_fail_validation() {
        let invalid = EngineConfig {
            max_open_orders: 1,
            max_open_orders_per_trader: 2,
            ..EngineConfig::default()
        };
        assert!(invalid.validate().is_err());
    }
}
