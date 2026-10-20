use ecx_protocol_core::{
    CentralMatcherReceiptV1, MatcherExecutionReceiptV2, SignedLimitOrder, TradeMatch,
};
use serde::{Deserialize, Serialize};

pub const MARKET: &str = "ECX-USDD-PERP";
pub const PRICE_DECIMALS: u32 = 8;
pub const QUANTITY_DECIMALS: u32 = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    #[default]
    Gtc,
    Ioc,
    Fok,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitOrderRequest {
    /// Wallet-supplied stable key. Production orders use exactly 16 bytes as
    /// lowercase hex; demo orders may use a human-readable value.
    pub client_order_id: String,
    /// 32-byte chain identifier as lowercase hex in production.
    pub chain_id: String,
    /// BIP340 x-only public key as lowercase hex in production.
    pub trader: String,
    #[serde(default = "default_market")]
    pub market: String,
    pub side: Side,
    pub limit_price_ticks: u64,
    pub quantity_lots: u64,
    #[serde(default)]
    pub time_in_force: TimeInForce,
    #[serde(default)]
    pub post_only: bool,
    #[serde(default)]
    pub reduce_only: bool,
    #[serde(default = "default_max_fee_bps")]
    pub max_fee_bps: u32,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    /// BIP340 signature over the protocol core's canonical `LimitOrder` digest,
    /// encoded as 64-byte lowercase hex.
    #[serde(default)]
    pub signature: String,
}

/// Additive v2 transport and journal envelope. Keeping these fields outside
/// `SubmitOrderRequest` preserves the v1 wire schema and bincode snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitOrderRequestV2 {
    pub order: SubmitOrderRequest,
    /// Frozen singleton configuration signed by the leverage commitment.
    pub configuration_hash: String,
    pub initial_margin_bps: u32,
    /// BIP340 signature from the proof-consumed `OrderRiskCommitmentV2`.
    pub risk_commitment_signature: String,
}

fn default_market() -> String {
    MARKET.to_owned()
}

fn default_max_fee_bps() -> u32 {
    25
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOrderRequest {
    pub chain_id: String,
    pub trader: String,
    #[serde(default = "default_market")]
    pub market: String,
    pub client_cancel_id: String,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    #[serde(default)]
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Resting,
    PartiallyFilled,
    Filled,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Trade {
    pub trade_id: String,
    pub sequence: u64,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub buyer: String,
    pub seller: String,
    pub price_ticks: u64,
    pub quantity_lots: u64,
    pub executed_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitOrderOutcome {
    pub order_id: String,
    pub sequence: u64,
    pub status: OrderStatus,
    pub original_quantity_lots: u64,
    pub remaining_quantity_lots: u64,
    pub trades: Vec<Trade>,
    pub self_trade_prevented: bool,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelOrderOutcome {
    pub order_id: String,
    pub sequence: u64,
    pub status: OrderStatus,
    pub cancelled_quantity_lots: u64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencedSubmitOrderOutcome {
    #[serde(flatten)]
    pub outcome: SubmitOrderOutcome,
    pub matcher_receipt: CentralMatcherReceiptV1,
}

/// Additive V2 response returned only to the submitting authenticated order.
/// Execution receipts are deliberately absent from every V1 and public-market
/// payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencedSubmitOrderOutcomeV2 {
    #[serde(flatten)]
    pub outcome: SubmitOrderOutcome,
    pub matcher_receipt: CentralMatcherReceiptV1,
    pub execution_receipts: Vec<MatcherExecutionReceiptV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencedCancelOrderOutcome {
    #[serde(flatten)]
    pub outcome: CancelOrderOutcome,
    pub matcher_receipt: CentralMatcherReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestingOrderView {
    pub order_id: String,
    pub client_order_id: String,
    pub trader: String,
    pub side: Side,
    pub price_ticks: u64,
    pub original_quantity_lots: u64,
    pub remaining_quantity_lots: u64,
    pub reduce_only: bool,
    pub created_sequence: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapitalMode {
    Normal,
    ReduceOnly,
    #[default]
    Recovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleModeV2 {
    Normal,
    ReduceOnly,
    Disputed,
    Halt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleSnapshotV2 {
    pub certificate_hash: [u8; 32],
    pub valid_through_parent_mtp: u64,
    pub mode: OracleModeV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BondInboxSnapshotV2 {
    pub head_root: [u8; 32],
    pub entry_count: u64,
    pub processed_root: [u8; 32],
    pub processed_cursor: u64,
    pub outcome_root: [u8; 32],
    pub outcome_count: u64,
    pub node_verified_source_head_root: [u8; 32],
    pub node_verified_source_entry_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherExecutionSnapshotV2 {
    pub receipt_batch_root: [u8; 32],
    pub previous_sequence: u64,
    pub sequence: u64,
}

impl CapitalMode {
    pub fn permits(self, reduce_only: bool) -> bool {
        match self {
            Self::Normal => true,
            Self::ReduceOnly => reduce_only,
            Self::Recovery => false,
        }
    }
}

/// Public values authenticated by the patched Elements node and bound to its
/// exchange-state root. Missing v2 data is deliberately not represented by a
/// synthetic healthy snapshot; admission treats it as recovery mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalSnapshotV2 {
    pub version: u8,
    pub exchange_state_root: [u8; 32],
    /// Frozen v2 configuration whose hash is signed by every bond action.
    pub configuration_hash: [u8; 32],
    /// Exact fixed-supply confidential Elements asset.
    pub bond_asset_id: [u8; 32],
    /// Verified issuance/inventory/reissuance-token deployment envelope.
    pub bond_deployment_commitment: [u8; 32],
    /// SP1 transition-v2 program identity authenticated by node consensus.
    pub transition_program_id: [u8; 32],
    /// Frozen Simplicity transition covenant CMR authenticated by the node.
    pub transition_cmr: [u8; 32],
    pub covenant_state_hash: [u8; 32],
    pub bond_state_root: [u8; 32],
    pub funding_state_root: [u8; 32],
    pub insurance_reserve_quote_units: u128,
    pub outstanding_bond_units: u64,
    pub nav_quote_units_per_bond: u128,
    pub deficit_quote_units: u128,
    pub target_reserve_quote_units: u128,
    pub coverage_bps: u128,
    pub mode: CapitalMode,
    pub minimum_authenticated_price: u64,
    pub maximum_authenticated_price: u64,
    pub funding_epoch: u64,
    pub funding_rate_ppm: i32,
    pub redemption_queue_root: [u8; 32],
    pub redemption_head: u64,
    pub redemption_tail: u64,
    pub queued_redemption_bond_units: u64,
    pub oracle: OracleSnapshotV2,
    pub encrypted_availability_root: [u8; 32],
    pub bond_inbox: BondInboxSnapshotV2,
    pub matcher_execution: MatcherExecutionSnapshotV2,
    pub last_transition_sidechain_height: u64,
    pub legacy_fee_pool_quote_units: u128,
}

impl CapitalSnapshotV2 {
    pub const VERSION: u8 = 3;
    pub const NORMAL_COVERAGE_BPS: u128 = 12_500;
    pub const MINIMUM_COVERAGE_BPS: u128 = 10_000;

    pub fn derived_coverage_bps(&self) -> anyhow::Result<u128> {
        ecx_protocol_core::coverage_bps(
            self.insurance_reserve_quote_units,
            self.deficit_quote_units,
        )
        .map_err(|error| anyhow::anyhow!("invalid v2 capital coverage: {error}"))
    }

    pub fn derived_mode(&self) -> anyhow::Result<CapitalMode> {
        ecx_protocol_core::capital_mode_for(
            self.insurance_reserve_quote_units,
            self.deficit_quote_units,
        )
        .map(|mode| match mode {
            ecx_protocol_core::CapitalModeV2::Normal => CapitalMode::Normal,
            ecx_protocol_core::CapitalModeV2::ReduceOnly => CapitalMode::ReduceOnly,
            ecx_protocol_core::CapitalModeV2::RecapitalizationOnly => CapitalMode::Recovery,
        })
        .map_err(|error| anyhow::anyhow!("invalid v2 capital mode: {error}"))
    }

    /// Admission combines proven capital and oracle modes. A disputed or
    /// reduce-only oracle can never upgrade an economically stricter mode;
    /// halt always disables matching.
    pub fn admission_mode(&self) -> CapitalMode {
        match self.oracle.mode {
            OracleModeV2::Normal => self.mode,
            OracleModeV2::ReduceOnly | OracleModeV2::Disputed => match self.mode {
                CapitalMode::Recovery => CapitalMode::Recovery,
                CapitalMode::Normal | CapitalMode::ReduceOnly => CapitalMode::ReduceOnly,
            },
            OracleModeV2::Halt => CapitalMode::Recovery,
        }
    }

    pub fn validate_for_exchange_root(&self, exchange_state_root: [u8; 32]) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == Self::VERSION
                && self.exchange_state_root == exchange_state_root
                && self.exchange_state_root != [0; 32]
                && self.configuration_hash != [0; 32]
                && self.bond_asset_id != [0; 32]
                && self.bond_deployment_commitment != [0; 32]
                && self.transition_program_id != [0; 32]
                && self.transition_cmr != [0; 32]
                && self.covenant_state_hash != [0; 32]
                && self.bond_state_root != [0; 32]
                && self.funding_state_root != [0; 32]
                && self.redemption_queue_root != [0; 32]
                && self.oracle.certificate_hash != [0; 32]
                && self.oracle.valid_through_parent_mtp != 0
                && self.encrypted_availability_root != [0; 32]
                && self.bond_inbox.head_root != [0; 32]
                && self.bond_inbox.processed_root != [0; 32]
                && self.bond_inbox.outcome_root != [0; 32]
                && self.bond_inbox.node_verified_source_head_root != [0; 32]
                && self.matcher_execution.receipt_batch_root != [0; 32]
                && self.minimum_authenticated_price != 0
                && self.minimum_authenticated_price <= self.maximum_authenticated_price
                && self.funding_rate_ppm.unsigned_abs()
                    <= ecx_protocol_core::RiskParams::default().max_abs_funding_rate_ppm
                && self.last_transition_sidechain_height != 0
                && self.redemption_head <= self.redemption_tail
                && ((self.redemption_head == self.redemption_tail)
                    == (self.queued_redemption_bond_units == 0))
                && self.queued_redemption_bond_units <= self.outstanding_bond_units
                && self.outstanding_bond_units <= ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS,
            "capital snapshot is not bound to the authenticated v2 exchange state"
        );
        anyhow::ensure!(
            self.legacy_fee_pool_quote_units == 0,
            "v2 capital snapshot has a nonzero legacy fee pool"
        );
        anyhow::ensure!(
            self.bond_inbox.processed_cursor <= self.bond_inbox.entry_count
                && self.bond_inbox.outcome_count == self.bond_inbox.processed_cursor
                && self.bond_inbox.node_verified_source_entry_count >= self.bond_inbox.entry_count
                && (self.bond_inbox.node_verified_source_entry_count
                    != self.bond_inbox.entry_count
                    || self.bond_inbox.node_verified_source_head_root == self.bond_inbox.head_root),
            "v2 bond inbox projection is inconsistent"
        );
        anyhow::ensure!(
            self.matcher_execution.previous_sequence <= self.matcher_execution.sequence,
            "v2 matcher execution projection is inconsistent"
        );
        anyhow::ensure!(
            self.coverage_bps == self.derived_coverage_bps()?
                && self.mode == self.derived_mode()?,
            "v2 capital snapshot coverage or mode is inconsistent"
        );
        let expected_target = ecx_protocol_core::target_reserve_125(self.deficit_quote_units)
            .map_err(|error| anyhow::anyhow!("invalid v2 target reserve: {error}"))?;
        anyhow::ensure!(
            self.target_reserve_quote_units == expected_target,
            "v2 capital snapshot target reserve is inconsistent"
        );
        let expected_nav = if self.outstanding_bond_units == 0 {
            0
        } else {
            ecx_protocol_core::nav_per_whole_share_usdd_atoms(
                self.insurance_reserve_quote_units,
                self.outstanding_bond_units,
            )
            .map_err(|error| anyhow::anyhow!("invalid v2 bond NAV: {error}"))?
        };
        anyhow::ensure!(
            self.nav_quote_units_per_bond == expected_nav,
            "v2 capital snapshot NAV is inconsistent"
        );
        Ok(())
    }
}

#[cfg(test)]
mod capital_tests {
    use super::*;

    fn snapshot(
        reserve: u128,
        deficit: u128,
        coverage: u128,
        mode: CapitalMode,
    ) -> CapitalSnapshotV2 {
        CapitalSnapshotV2 {
            version: CapitalSnapshotV2::VERSION,
            exchange_state_root: [7; 32],
            configuration_hash: [8; 32],
            bond_asset_id: [9; 32],
            bond_deployment_commitment: [10; 32],
            transition_program_id: [11; 32],
            transition_cmr: [12; 32],
            covenant_state_hash: [14; 32],
            bond_state_root: [15; 32],
            funding_state_root: [16; 32],
            insurance_reserve_quote_units: reserve,
            outstanding_bond_units: 100,
            nav_quote_units_per_bond: reserve * u128::from(ecx_protocol_core::BOND_SHARE_SCALE)
                / 100,
            deficit_quote_units: deficit,
            target_reserve_quote_units: ecx_protocol_core::target_reserve_125(deficit).unwrap(),
            coverage_bps: coverage,
            mode,
            minimum_authenticated_price: 1,
            maximum_authenticated_price: 10,
            funding_epoch: 3,
            funding_rate_ppm: 0,
            redemption_queue_root: [13; 32],
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_bond_units: 0,
            oracle: OracleSnapshotV2 {
                certificate_hash: [17; 32],
                valid_through_parent_mtp: 1_000,
                mode: OracleModeV2::Normal,
            },
            encrypted_availability_root: [18; 32],
            bond_inbox: BondInboxSnapshotV2 {
                head_root: [19; 32],
                entry_count: 0,
                processed_root: [20; 32],
                processed_cursor: 0,
                outcome_root: [21; 32],
                outcome_count: 0,
                node_verified_source_head_root: [19; 32],
                node_verified_source_entry_count: 0,
            },
            matcher_execution: MatcherExecutionSnapshotV2 {
                receipt_batch_root: [22; 32],
                previous_sequence: 0,
                sequence: 0,
            },
            last_transition_sidechain_height: 1,
            legacy_fee_pool_quote_units: 0,
        }
    }

    #[test]
    fn derives_and_validates_fail_closed_capital_modes() {
        for (reserve, coverage, mode) in [
            (125, 12_500, CapitalMode::Normal),
            (110, 11_000, CapitalMode::ReduceOnly),
            (99, 9_900, CapitalMode::Recovery),
        ] {
            let capital = snapshot(reserve, 100, coverage, mode);
            capital.validate_for_exchange_root([7; 32]).unwrap();
            assert_eq!(capital.derived_coverage_bps().unwrap(), coverage);
            assert_eq!(mode.permits(true), mode != CapitalMode::Recovery);
            assert_eq!(mode.permits(false), mode == CapitalMode::Normal);
        }
        let inconsistent = snapshot(99, 100, 12_500, CapitalMode::Normal);
        assert!(inconsistent.validate_for_exchange_root([7; 32]).is_err());
        let mut fee_pool = snapshot(125, 100, 12_500, CapitalMode::Normal);
        fee_pool.legacy_fee_pool_quote_units = 1;
        assert!(fee_pool.validate_for_exchange_root([7; 32]).is_err());

        let mut wrong_nav = snapshot(125, 100, 12_500, CapitalMode::Normal);
        wrong_nav.nav_quote_units_per_bond -= 1;
        assert!(wrong_nav.validate_for_exchange_root([7; 32]).is_err());

        let mut unbound_queue = snapshot(125, 100, 12_500, CapitalMode::Normal);
        unbound_queue.redemption_tail = 1;
        assert!(unbound_queue.validate_for_exchange_root([7; 32]).is_err());

        let mut overcommitted_queue = snapshot(125, 100, 12_500, CapitalMode::Normal);
        overcommitted_queue.redemption_tail = 1;
        overcommitted_queue.queued_redemption_bond_units = 101;
        assert!(
            overcommitted_queue
                .validate_for_exchange_root([7; 32])
                .is_err()
        );

        let rounded_target = snapshot(2, 1, 20_000, CapitalMode::Normal);
        assert_eq!(rounded_target.target_reserve_quote_units, 2);
        rounded_target.validate_for_exchange_root([7; 32]).unwrap();
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PriceLevel {
    pub price_ticks: u64,
    pub quantity_lots: u64,
    pub order_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderBookSnapshot {
    pub market: String,
    pub sequence: u64,
    pub bids: Vec<PriceLevel>,
    pub asks: Vec<PriceLevel>,
}

/// Public market depth deliberately omits quantities and order counts. Exact
/// order data belongs to the private transition witness and authenticated
/// owner views, not an unauthenticated market-data endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicPriceLevel {
    pub price_ticks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicOrderBookSnapshot {
    pub market: String,
    pub sequence: u64,
    pub bids: Vec<PublicPriceLevel>,
    pub asks: Vec<PublicPriceLevel>,
}

impl From<OrderBookSnapshot> for PublicOrderBookSnapshot {
    fn from(value: OrderBookSnapshot) -> Self {
        Self {
            market: value.market,
            sequence: value.sequence,
            bids: value
                .bids
                .into_iter()
                .map(|level| PublicPriceLevel {
                    price_ticks: level.price_ticks,
                })
                .collect(),
            asks: value
                .asks
                .into_iter()
                .map(|level| PublicPriceLevel {
                    price_ticks: level.price_ticks,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicTrade {
    pub sequence: u64,
    pub price_ticks: u64,
    pub executed_at_ms: u64,
}

impl From<Trade> for PublicTrade {
    fn from(value: Trade) -> Self {
        Self {
            sequence: value.sequence,
            price_ticks: value.price_ticks,
            executed_at_ms: value.executed_at_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum PublicMarketEvent {
    Trade(PublicTrade),
    Book(PublicOrderBookSnapshot),
    Changed { sequence: u64 },
}

impl From<MarketEvent> for PublicMarketEvent {
    fn from(value: MarketEvent) -> Self {
        match value {
            MarketEvent::Trade(trade) => Self::Trade(trade.into()),
            MarketEvent::Book(book) => Self::Book(book.into()),
            MarketEvent::Order(order) => Self::Changed {
                sequence: order.sequence,
            },
            MarketEvent::Cancel(cancel) => Self::Changed {
                sequence: cancel.sequence,
            },
        }
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[test]
    fn public_market_payloads_exclude_private_order_and_fill_fields() {
        let trade = Trade {
            trade_id: "secret-trade".into(),
            sequence: 7,
            maker_order_id: "secret-maker".into(),
            taker_order_id: "secret-taker".into(),
            buyer: "secret-buyer".into(),
            seller: "secret-seller".into(),
            price_ticks: 250_000_000,
            quantity_lots: 900_000_000,
            executed_at_ms: 123,
        };
        let encoded = serde_json::to_string(&PublicTrade::from(trade)).unwrap();
        for forbidden in ["trade_id", "order_id", "buyer", "seller", "quantity"] {
            assert!(
                !encoded.contains(forbidden),
                "public trade leaked {forbidden}"
            );
        }
        let book = OrderBookSnapshot {
            market: MARKET.into(),
            sequence: 8,
            bids: vec![PriceLevel {
                price_ticks: 1,
                quantity_lots: 2,
                order_count: 3,
            }],
            asks: vec![],
        };
        let encoded = serde_json::to_string(&PublicOrderBookSnapshot::from(book)).unwrap();
        assert!(!encoded.contains("quantity"));
        assert!(!encoded.contains("order_count"));
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PositionView {
    pub market: String,
    pub net_quantity_lots: i64,
    pub average_entry_price_ticks: u64,
    /// Signed realized PnL in USDD base units (eight decimals).
    pub realized_pnl_quote_units: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountView {
    pub trader: String,
    /// Matcher-derived and not final until included in a verified state transition.
    pub provisional: bool,
    pub position: PositionView,
    pub open_orders: Vec<RestingOrderView>,
    pub recent_trades: Vec<Trade>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum MarketEvent {
    Trade(Trade),
    Book(OrderBookSnapshot),
    Order(SubmitOrderOutcome),
    Cancel(CancelOrderOutcome),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EngineCommand {
    Submit {
        request: SubmitOrderRequest,
        received_at_ms: u64,
    },
    Cancel {
        order_id: String,
        request: CancelOrderRequest,
        received_at_ms: u64,
    },
    SubmitV2 {
        request: SubmitOrderRequestV2,
        received_at_ms: u64,
    },
}

#[derive(Clone, Debug)]
pub struct Mutation<T> {
    pub outcome: T,
    pub events: Vec<MarketEvent>,
    /// Exact private proof-side matches derived while applying the staged
    /// mutation. This field is never serialized into public API responses.
    pub(crate) executions_v2: Vec<StagedMatcherExecutionV2>,
}

#[derive(Clone, Debug)]
pub(crate) struct StagedMatcherExecutionV2 {
    pub maker: SignedLimitOrder,
    pub taker: SignedLimitOrder,
    pub trade: TradeMatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthView {
    pub status: String,
    pub market: String,
    pub mode: String,
    pub chain_height: u64,
    pub sequence: u64,
    pub privacy: String,
    pub matcher_mode: String,
    pub matcher_signer: String,
    pub chain_id: String,
    pub matcher_sequence: u64,
    pub matcher_receipt_hash: String,
    #[serde(default)]
    pub capital_controls_v2: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capital_mode: Option<CapitalMode>,
    #[serde(default)]
    pub capital_authenticated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatcherReceiptView {
    pub receipt_hash: String,
    pub receipt: CentralMatcherReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptBatchViewV2 {
    pub previous_sequence: u64,
    pub next_sequence: u64,
    pub durable_head_sequence: u64,
    pub durable_history_hash: String,
    pub execution_receipts: Vec<MatcherExecutionReceiptV2>,
    pub taker_admission_receipts: Vec<CentralMatcherReceiptV1>,
}
