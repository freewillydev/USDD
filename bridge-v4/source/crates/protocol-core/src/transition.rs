use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use crate::codec::{put_i32, put_u32, put_u64, put_u8, CanonicalEncode};
use crate::deposit_inbox::{DepositEventV1, DepositInboxTransitionV1};
use crate::forced::{
    ForcedActionEntryV1, ForcedActionV1, ForcedInboxTransitionV1,
    MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1, MAX_COMBINED_SAME_DEADLINE_APPENDS_V1,
    MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1,
};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::incremental_state_v2::Int256V2;
use crate::merkle::ordered_root;
use crate::oracle::OracleMode;
use crate::order::{
    LimitOrder, OrderFlags, OrderId, Side, SignedCancelOrder, SignedLimitOrder, TimeInForce,
    TradeMatch,
};
use crate::queue::{DepositRequest, SignedWithdrawalRequest};
use crate::risk::{
    apply_fill, equity, funding_payment, is_liquidatable, notional, required_margin, trading_fee,
    MarginKind, RiskParams,
};
use crate::risk_v2::{
    creates_directional_risk, required_margin_bps_v2, validate_selected_margin_bps,
};
use crate::state::{AccountLeaf, ExchangeState, OpenOrderLeaf, PositionLeaf, StateRoots};
use crate::types::{Amount, MarketId, Price, Quantity, XOnlyKey, ECX_USDD_MARKET, PRICE_SCALE};
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatchedOrderPair {
    pub maker_order: SignedLimitOrder,
    pub taker_order: SignedLimitOrder,
    pub trade: TradeMatch,
}

/// Permissionless liquidation against the best eligible resting maker. The
/// target does not sign a new order; the proof establishes maintenance-margin
/// breach at the adverse authenticated oracle bound.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LiquidationMatchV1 {
    pub target: XOnlyKey,
    pub maker_order: SignedLimitOrder,
    pub quantity: Quantity,
}

impl LiquidationMatchV1 {
    pub fn liquidation_id(&self) -> Hash32 {
        canonical_hash("ECX/liquidation-match/v1", self)
    }
}

impl CanonicalEncode for LiquidationMatchV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.target.encode_to(out);
        self.maker_order.encode_to(out);
        self.quantity.encode_to(out);
    }
}

impl CanonicalEncode for MatchedOrderPair {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.maker_order.encode_to(out);
        self.taker_order.encode_to(out);
        self.trade.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderPlacement {
    pub order: SignedLimitOrder,
    pub received_sequence: u64,
    pub salt: Hash32,
}

impl OrderPlacement {
    pub fn placement_id(&self) -> Hash32 {
        canonical_hash("ECX/order-placement/v1", self)
    }
}

impl CanonicalEncode for OrderPlacement {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.order.encode_to(out);
        put_u64(out, self.received_sequence);
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionPublicInputs {
    pub protocol_version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub sidechain_height: u64,
    /// Parent-chain height of the BMM-approved child block carrying this step.
    pub parent_height: u64,
    /// Frozen matcher escape deadline copied into the proof journal.
    pub forced_inclusion_blocks: u32,
    pub previous_state_root: Hash32,
    pub previous_sequence: u64,
    pub next_state_root: Hash32,
    pub next_sequence: u64,
    pub batch_hash: Hash32,
    pub deposit_batch_root: Hash32,
    /// Node-derived deposit locators consumed by this transition.
    pub deposit_event_batch_root: Hash32,
    pub withdrawal_batch_root: Hash32,
    /// Exact confidential vault inputs/change and withdrawal-output binding.
    pub collateral_settlement_root: Hash32,
    pub liquidation_batch_root: Hash32,
    /// The already-existing withdrawal commitment `W_h` from the node.
    pub existing_withdrawal_commitment: Hash32,
    /// Hybrid Truthcoin/LMSR certificate committed by this state step.
    pub oracle_certificate_hash: Hash32,
    pub oracle_mode: OracleMode,
    /// Root of the central matcher's signed sequencing receipts consumed by this batch.
    pub matcher_receipt_batch_root: Hash32,
    /// Ordered root of the on-chain forced actions consumed by this step.
    pub forced_action_batch_root: Hash32,
    /// Set when an overdue inbox head forces a matcher-independent batch.
    pub escape_only: bool,
    /// Root of the encrypted, recoverable witness availability certificate.
    pub encrypted_availability_root: Hash32,
    pub mark_price: Price,
    /// Adverse oracle bounds used only for maintenance and liquidation tests.
    pub liquidation_low: Price,
    pub liquidation_high: Price,
    pub funding_rate_ppm: i32,
    pub risk_params_hash: Hash32,
}

impl TransitionPublicInputs {
    pub const VERSION: u8 = 4;

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/transition-public-inputs/v4", self)
    }

    pub fn encode_fixed(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

impl CanonicalEncode for TransitionPublicInputs {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.protocol_version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        put_u64(out, self.sidechain_height);
        put_u64(out, self.parent_height);
        put_u32(out, self.forced_inclusion_blocks);
        out.extend_from_slice(&self.previous_state_root);
        put_u64(out, self.previous_sequence);
        out.extend_from_slice(&self.next_state_root);
        put_u64(out, self.next_sequence);
        out.extend_from_slice(&self.batch_hash);
        out.extend_from_slice(&self.deposit_batch_root);
        out.extend_from_slice(&self.deposit_event_batch_root);
        out.extend_from_slice(&self.withdrawal_batch_root);
        out.extend_from_slice(&self.collateral_settlement_root);
        out.extend_from_slice(&self.liquidation_batch_root);
        out.extend_from_slice(&self.existing_withdrawal_commitment);
        out.extend_from_slice(&self.oracle_certificate_hash);
        self.oracle_mode.encode_to(out);
        out.extend_from_slice(&self.matcher_receipt_batch_root);
        out.extend_from_slice(&self.forced_action_batch_root);
        put_u8(out, u8::from(self.escape_only));
        out.extend_from_slice(&self.encrypted_availability_root);
        self.mark_price.encode_to(out);
        self.liquidation_low.encode_to(out);
        self.liquidation_high.encode_to(out);
        put_i32(out, self.funding_rate_ppm);
        out.extend_from_slice(&self.risk_params_hash);
    }
}

/// Private witness consumed by the deterministic transition verifier.
///
/// A production prover keeps this value off chain and publishes only the
/// [`TransitionJournal`] plus the zk proof. Account/position salts may rotate in
/// `next_*`; their semantic fields must match the verified transition exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionWitness {
    pub public: TransitionPublicInputs,
    pub risk_params: RiskParams,
    pub previous_state: ExchangeState,
    pub next_state: ExchangeState,
    pub previous_accounts: Vec<AccountLeaf>,
    pub next_accounts: Vec<AccountLeaf>,
    pub previous_positions: Vec<PositionLeaf>,
    pub next_positions: Vec<PositionLeaf>,
    pub previous_open_orders: Vec<OpenOrderLeaf>,
    pub next_open_orders: Vec<OpenOrderLeaf>,
    pub previous_deposit_nullifiers: Vec<Hash32>,
    pub previous_withdrawal_nullifiers: Vec<Hash32>,
    pub deposit_inbox: DepositInboxTransitionV1,
    /// Complete unconsumed on-chain inbox suffix and the prefix consumed now.
    pub forced_inbox: ForcedInboxTransitionV1,
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<SignedWithdrawalRequest>,
    pub placements: Vec<OrderPlacement>,
    pub cancellations: Vec<SignedCancelOrder>,
    pub fills: Vec<MatchedOrderPair>,
    pub liquidations: Vec<LiquidationMatchV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionJournal {
    pub protocol_version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub forced_inclusion_blocks: u32,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_sequence: u64,
    pub next_sequence: u64,
    pub batch_hash: Hash32,
    pub deposit_batch_root: Hash32,
    pub deposit_event_batch_root: Hash32,
    pub withdrawal_batch_root: Hash32,
    pub collateral_settlement_root: Hash32,
    pub liquidation_batch_root: Hash32,
    pub existing_withdrawal_commitment: Hash32,
    pub oracle_certificate_hash: Hash32,
    pub oracle_mode: OracleMode,
    pub matcher_receipt_batch_root: Hash32,
    pub forced_action_batch_root: Hash32,
    pub escape_only: bool,
    pub encrypted_availability_root: Hash32,
    pub mark_price: Price,
    pub liquidation_low: Price,
    pub liquidation_high: Price,
    pub funding_rate_ppm: i32,
    pub risk_params_hash: Hash32,
}

impl TransitionJournal {
    pub const VERSION: u8 = 4;

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/transition-journal/v4", self)
    }

    pub fn encode_fixed(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

impl CanonicalEncode for TransitionJournal {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.protocol_version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        put_u64(out, self.sidechain_height);
        put_u64(out, self.parent_height);
        put_u32(out, self.forced_inclusion_blocks);
        out.extend_from_slice(&self.previous_state_root);
        out.extend_from_slice(&self.next_state_root);
        put_u64(out, self.previous_sequence);
        put_u64(out, self.next_sequence);
        out.extend_from_slice(&self.batch_hash);
        out.extend_from_slice(&self.deposit_batch_root);
        out.extend_from_slice(&self.deposit_event_batch_root);
        out.extend_from_slice(&self.withdrawal_batch_root);
        out.extend_from_slice(&self.collateral_settlement_root);
        out.extend_from_slice(&self.liquidation_batch_root);
        out.extend_from_slice(&self.existing_withdrawal_commitment);
        out.extend_from_slice(&self.oracle_certificate_hash);
        self.oracle_mode.encode_to(out);
        out.extend_from_slice(&self.matcher_receipt_batch_root);
        out.extend_from_slice(&self.forced_action_batch_root);
        put_u8(out, u8::from(self.escape_only));
        out.extend_from_slice(&self.encrypted_availability_root);
        self.mark_price.encode_to(out);
        self.liquidation_low.encode_to(out);
        self.liquidation_high.encode_to(out);
        put_i32(out, self.funding_rate_ppm);
        out.extend_from_slice(&self.risk_params_hash);
    }
}

pub fn risk_params_hash(params: RiskParams) -> Hash32 {
    canonical_hash("ECX/risk-params/v1", &params)
}

pub fn deposit_batch_root(deposits: &[DepositRequest]) -> Hash32 {
    let ids: Vec<Hash32> = deposits.iter().map(DepositRequest::request_id).collect();
    ordered_root("ECX/deposit-batch/v1", &ids)
}

pub fn deposit_event_batch_root(entries: &[DepositEventV1]) -> Hash32 {
    let ids: Vec<Hash32> = entries.iter().map(DepositEventV1::event_hash).collect();
    ordered_root("ECX/deposit-event-batch/v1", &ids)
}

pub fn withdrawal_batch_root(withdrawals: &[SignedWithdrawalRequest]) -> Hash32 {
    let ids: Vec<Hash32> = withdrawals
        .iter()
        .map(|request| request.request.request_id())
        .collect();
    ordered_root("ECX/withdrawal-batch/v1", &ids)
}

pub fn fill_batch_root(fills: &[MatchedOrderPair]) -> Hash32 {
    let ids: Vec<Hash32> = fills.iter().map(|pair| pair.trade.match_id()).collect();
    ordered_root("ECX/fill-batch/v1", &ids)
}

pub fn placement_batch_root(placements: &[OrderPlacement]) -> Hash32 {
    let ids: Vec<Hash32> = placements
        .iter()
        .map(OrderPlacement::placement_id)
        .collect();
    ordered_root("ECX/placement-batch/v1", &ids)
}

pub fn cancellation_batch_root(cancellations: &[SignedCancelOrder]) -> Hash32 {
    let ids: Vec<Hash32> = cancellations
        .iter()
        .map(|cancel| cancel.cancel.cancel_id())
        .collect();
    ordered_root("ECX/cancellation-batch/v1", &ids)
}

pub fn forced_action_batch_root(entries: &[ForcedActionEntryV1]) -> Hash32 {
    let ids: Vec<Hash32> = entries
        .iter()
        .map(ForcedActionEntryV1::entry_hash)
        .collect();
    ordered_root("ECX/forced-action-batch/v1", &ids)
}

pub fn liquidation_batch_root(liquidations: &[LiquidationMatchV1]) -> Hash32 {
    let ids: Vec<Hash32> = liquidations
        .iter()
        .map(LiquidationMatchV1::liquidation_id)
        .collect();
    ordered_root("ECX/liquidation-batch/v1", &ids)
}

pub fn transition_batch_hash(
    deposits: &[DepositRequest],
    withdrawals: &[SignedWithdrawalRequest],
    placements: &[OrderPlacement],
    cancellations: &[SignedCancelOrder],
    fills: &[MatchedOrderPair],
    liquidations: &[LiquidationMatchV1],
) -> Hash32 {
    let mut bytes = [0u8; 192];
    bytes[..32].copy_from_slice(&deposit_batch_root(deposits));
    bytes[32..64].copy_from_slice(&withdrawal_batch_root(withdrawals));
    bytes[64..96].copy_from_slice(&placement_batch_root(placements));
    bytes[96..128].copy_from_slice(&cancellation_batch_root(cancellations));
    bytes[128..160].copy_from_slice(&fill_batch_root(fills));
    bytes[160..].copy_from_slice(&liquidation_batch_root(liquidations));
    tagged_hash("ECX/transition-batch/v2", &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionEnvelopeV4 {
    pub operation_batch_hash: Hash32,
    pub deposit_event_batch_root: Hash32,
    pub oracle_certificate_hash: Hash32,
    pub oracle_mode: OracleMode,
    pub matcher_receipt_batch_root: Hash32,
    pub collateral_settlement_root: Hash32,
    pub forced_action_batch_root: Hash32,
    pub escape_only: bool,
    pub encrypted_availability_root: Hash32,
}

impl CanonicalEncode for TransitionEnvelopeV4 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.operation_batch_hash);
        out.extend_from_slice(&self.deposit_event_batch_root);
        out.extend_from_slice(&self.oracle_certificate_hash);
        self.oracle_mode.encode_to(out);
        out.extend_from_slice(&self.matcher_receipt_batch_root);
        out.extend_from_slice(&self.collateral_settlement_root);
        out.extend_from_slice(&self.forced_action_batch_root);
        put_u8(out, u8::from(self.escape_only));
        out.extend_from_slice(&self.encrypted_availability_root);
    }
}

/// Commits source authentication and sequencer receipts without changing any
/// existing Elements header field. This envelope is folded into the private
/// exchange root and therefore into the appended header state root.
pub fn transition_envelope_hash(envelope: &TransitionEnvelopeV4) -> Hash32 {
    canonical_hash("ECX/transition-envelope/v4", envelope)
}

pub fn next_order_receipts_root(previous: Hash32, batch_hash: Hash32) -> Hash32 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&previous);
    bytes[32..].copy_from_slice(&batch_hash);
    tagged_hash("ECX/order-receipts-step/v1", &bytes)
}

/// Verifies a complete private state transition and emits only public journal data.
pub fn verify_transition(witness: &TransitionWitness) -> Result<TransitionJournal, ProtocolError> {
    verify_transition_with_fee_policy(
        witness,
        FeePolicy::LegacyPool,
        &V2ExternalEffects::default(),
    )
}

/// V2-compatible transition verification. It preserves V1 ordering, margin,
/// liquidation, and inbox semantics, but routes all trading fees into the
/// loss-bearing insurance reserve, requires the legacy fee pool to stay empty,
/// and replaces V1's independently truncated conservation sum with an exact
/// common-denominator transition-delta invariant.
///
/// This is deliberately a separate entry point so existing V1 proof programs
/// and public values retain their exact semantics and identity.
pub fn verify_transition_fees_to_insurance(
    witness: &TransitionWitness,
) -> Result<TransitionJournal, ProtocolError> {
    verify_transition_with_fee_policy(witness, FeePolicy::Insurance, &V2ExternalEffects::default())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeePolicy {
    LegacyPool,
    Insurance,
}

/// Already-authenticated external capital effects supplied exclusively by the
/// V2 verifier. Keeping this crate-private prevents callers from bypassing the
/// signed bond-action and queue checks in `transition_v2`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct V2ExternalEffects {
    /// Applied after all base transition actions, in exact accepted bond-inbox
    /// order. A zero amount consumes the signed account nonce for a successful
    /// redemption enqueue without moving collateral.
    pub account_debits: Vec<(XOnlyKey, u64, Amount)>,
    /// Subscription contributions less execution-time redemption payments.
    pub insurance_delta: Amount,
    /// Execution-time redemption payments leaving the confidential vault.
    pub withdrawal_delta: Amount,
    /// Authenticated order-level initial-margin selections keyed by canonical
    /// order id. `None` retains the exact V1 margin semantics.
    pub selected_margin_bps: Option<BTreeMap<OrderId, u32>>,
    /// V2's carried per-position selection at the start of this transition.
    /// It is used only when exposure grows or changes direction, so an order
    /// cannot silently lower the collateral requirement of an existing
    /// stricter position. `None` retains exact V1 behavior.
    pub starting_position_margin_bps: Option<BTreeMap<[u8; 32], u32>>,
}

pub(crate) fn verify_transition_v2_base(
    witness: &TransitionWitness,
    effects: &V2ExternalEffects,
) -> Result<TransitionJournal, ProtocolError> {
    verify_transition_with_fee_policy(witness, FeePolicy::Insurance, effects)
}

/// Replays every ordinary V1/base action and returns the account map at the
/// exact boundary before V2 bond-inbox account effects. This is intentionally
/// derived from the authenticated predecessor and base actions rather than by
/// reversing a producer-claimed accepted bond set; otherwise a stale nonce
/// could become valid through circular reconstruction.
pub(crate) fn v2_accounts_before_external(
    witness: &TransitionWitness,
    selected_margin_bps: BTreeMap<OrderId, u32>,
    starting_position_margin_bps: BTreeMap<[u8; 32], u32>,
) -> Result<BTreeMap<[u8; 32], AccountLeaf>, ProtocolError> {
    let external = V2ExternalEffects {
        selected_margin_bps: Some(selected_margin_bps),
        starting_position_margin_bps: Some(starting_position_margin_bps),
        ..V2ExternalEffects::default()
    };
    verify_private_evolution(witness, FeePolicy::Insurance, &external, true)?
        .ok_or(ProtocolError::InvalidBondState)
}

fn verify_transition_with_fee_policy(
    witness: &TransitionWitness,
    fee_policy: FeePolicy,
    external: &V2ExternalEffects,
) -> Result<TransitionJournal, ProtocolError> {
    let public = &witness.public;
    if public.protocol_version != TransitionPublicInputs::VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    witness.risk_params.validate()?;
    if public.risk_params_hash != risk_params_hash(witness.risk_params) {
        return Err(ProtocolError::RiskParamsMismatch);
    }
    witness.previous_state.validate()?;
    witness.next_state.validate()?;
    validate_public_state_linkage(witness)?;
    validate_source_inboxes(witness)?;
    validate_batches(witness)?;

    let effective_withdrawals = transition_withdrawals(witness)?;

    let next_deposit_nullifiers = extend_nullifiers(
        &witness.previous_deposit_nullifiers,
        witness.deposits.iter().map(DepositRequest::request_id),
    )?;
    let next_withdrawal_nullifiers = extend_nullifiers(
        &witness.previous_withdrawal_nullifiers,
        effective_withdrawals
            .iter()
            .map(|request| request.request.request_id()),
    )?;

    let previous_roots = StateRoots::from_private_state(
        &witness.previous_accounts,
        &witness.previous_positions,
        &witness.previous_open_orders,
        &witness.previous_deposit_nullifiers,
        &witness.previous_withdrawal_nullifiers,
        witness.previous_state.roots.order_receipts,
    )?;
    if previous_roots != witness.previous_state.roots {
        return Err(ProtocolError::StateRootMismatch);
    }
    let expected_receipts = next_order_receipts_root(
        witness.previous_state.roots.order_receipts,
        public.batch_hash,
    );
    let next_roots = StateRoots::from_private_state(
        &witness.next_accounts,
        &witness.next_positions,
        &witness.next_open_orders,
        &next_deposit_nullifiers,
        &next_withdrawal_nullifiers,
        expected_receipts,
    )?;
    if next_roots != witness.next_state.roots {
        return Err(ProtocolError::StateRootMismatch);
    }

    verify_private_evolution(witness, fee_policy, external, false)?;

    Ok(TransitionJournal {
        protocol_version: TransitionJournal::VERSION,
        chain_id: public.chain_id,
        market: public.market,
        sidechain_height: public.sidechain_height,
        parent_height: public.parent_height,
        forced_inclusion_blocks: public.forced_inclusion_blocks,
        previous_state_root: public.previous_state_root,
        next_state_root: public.next_state_root,
        previous_sequence: public.previous_sequence,
        next_sequence: public.next_sequence,
        batch_hash: public.batch_hash,
        deposit_batch_root: public.deposit_batch_root,
        deposit_event_batch_root: public.deposit_event_batch_root,
        withdrawal_batch_root: public.withdrawal_batch_root,
        collateral_settlement_root: public.collateral_settlement_root,
        liquidation_batch_root: public.liquidation_batch_root,
        existing_withdrawal_commitment: public.existing_withdrawal_commitment,
        oracle_certificate_hash: public.oracle_certificate_hash,
        oracle_mode: public.oracle_mode,
        matcher_receipt_batch_root: public.matcher_receipt_batch_root,
        forced_action_batch_root: public.forced_action_batch_root,
        escape_only: public.escape_only,
        encrypted_availability_root: public.encrypted_availability_root,
        mark_price: public.mark_price,
        liquidation_low: public.liquidation_low,
        liquidation_high: public.liquidation_high,
        funding_rate_ppm: public.funding_rate_ppm,
        risk_params_hash: public.risk_params_hash,
    })
}

fn validate_public_state_linkage(witness: &TransitionWitness) -> Result<(), ProtocolError> {
    let public = &witness.public;
    let previous = &witness.previous_state;
    let next = &witness.next_state;
    if public.chain_id != previous.chain_id || public.chain_id != next.chain_id {
        return Err(ProtocolError::TransitionMismatch("chain id"));
    }
    if public.market != ECX_USDD_MARKET
        || public.market != previous.market
        || public.market != next.market
    {
        return Err(ProtocolError::InvalidMarket);
    }
    if public.previous_state_root != previous.state_root()
        || public.next_state_root != next.state_root()
    {
        return Err(ProtocolError::StateRootMismatch);
    }
    if public.previous_sequence != previous.sequence
        || public.next_sequence != next.sequence
        || next.sequence
            != previous
                .sequence
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?
    {
        return Err(ProtocolError::InvalidStateSequence);
    }
    if public.parent_height == 0
        || next.last_processed_height != public.sidechain_height
        || previous.last_processed_height >= public.sidechain_height
    {
        return Err(ProtocolError::TransitionMismatch("sidechain height"));
    }
    if next.mark_price != public.mark_price
        || public.liquidation_low > public.mark_price
        || public.mark_price > public.liquidation_high
    {
        return Err(ProtocolError::TransitionMismatch("mark price"));
    }
    if next.matcher_sequence < previous.matcher_sequence
        || (next.matcher_sequence == previous.matcher_sequence
            && next.matcher_receipt_hash != previous.matcher_receipt_hash)
    {
        return Err(ProtocolError::TransitionMismatch("matcher receipt state"));
    }
    let expected_funding_index = previous
        .funding_index
        .checked_add(i128::from(public.funding_rate_ppm))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if next.funding_index != expected_funding_index {
        return Err(ProtocolError::TransitionMismatch("funding index"));
    }
    Ok(())
}

fn validate_source_inboxes(witness: &TransitionWitness) -> Result<(), ProtocolError> {
    const FORCED_INCLUSION_BLOCKS: u32 = 6;
    if witness.public.forced_inclusion_blocks != FORCED_INCLUSION_BLOCKS
        || witness
            .forced_inbox
            .pending_entries
            .len()
            .saturating_add(witness.deposit_inbox.pending_entries.len())
            > MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1
    {
        return Err(ProtocolError::InvalidForcedInbox);
    }
    let combined_unconsumed = witness
        .next_state
        .forced_inbox
        .entry_count
        .checked_sub(witness.next_state.forced_inbox.cursor)
        .and_then(|value| {
            witness
                .next_state
                .deposit_inbox
                .entry_count
                .checked_sub(witness.next_state.deposit_inbox.cursor)
                .and_then(|deposit| value.checked_add(deposit))
        })
        .ok_or(ProtocolError::InvalidForcedInbox)?;
    if combined_unconsumed > MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1 {
        return Err(ProtocolError::InvalidForcedInbox);
    }
    for parent_height in witness
        .forced_inbox
        .pending_entries
        .iter()
        .filter(|entry| entry.index >= witness.previous_state.forced_inbox.entry_count)
        .map(|entry| entry.enqueued_parent_height)
        .chain(
            witness
                .deposit_inbox
                .pending_entries
                .iter()
                .filter(|entry| entry.index >= witness.previous_state.deposit_inbox.entry_count)
                .map(|entry| entry.observed_parent_height),
        )
    {
        let same_deadline = witness
            .forced_inbox
            .pending_entries
            .iter()
            .filter(|entry| {
                entry.index >= witness.previous_state.forced_inbox.entry_count
                    && entry.enqueued_parent_height == parent_height
            })
            .count()
            + witness
                .deposit_inbox
                .pending_entries
                .iter()
                .filter(|entry| {
                    entry.index >= witness.previous_state.deposit_inbox.entry_count
                        && entry.observed_parent_height == parent_height
                })
                .count();
        if same_deadline > MAX_COMBINED_SAME_DEADLINE_APPENDS_V1 {
            return Err(ProtocolError::InvalidForcedInbox);
        }
    }
    let forced_outcome = witness.forced_inbox.verify(
        witness.public.chain_id,
        witness.previous_state.forced_inbox,
        witness.next_state.forced_inbox,
        witness.public.parent_height,
        witness.public.forced_inclusion_blocks,
    )?;
    let forced = witness.forced_inbox.consumed()?;
    let deposit_overdue = witness.deposit_inbox.verify(
        witness.public.chain_id,
        witness.previous_state.deposit_inbox,
        witness.next_state.deposit_inbox,
        witness.public.parent_height,
        witness.public.forced_inclusion_blocks,
    )?;
    let deposit_events = witness.deposit_inbox.consumed()?;
    if forced_action_batch_root(forced) != witness.public.forced_action_batch_root
        || deposit_event_batch_root(deposit_events) != witness.public.deposit_event_batch_root
        || witness.public.escape_only != (forced_outcome.had_overdue_action || deposit_overdue)
        || witness.public.encrypted_availability_root == [0; 32]
    {
        return Err(ProtocolError::InvalidForcedInbox);
    }

    if deposit_events.len() != witness.deposits.len() {
        return Err(ProtocolError::InvalidDepositInbox);
    }
    for (event, deposit) in deposit_events.iter().zip(&witness.deposits) {
        if event.chain_id != deposit.chain_id
            || event.source_txid != deposit.deposit_txid
            || event.deposit_vout != deposit.deposit_vout
            || event.trader != deposit.trader
            || event.observed_sidechain_height != deposit.observed_height
        {
            return Err(ProtocolError::InvalidDepositInbox);
        }
    }

    if witness.public.escape_only
        && (!witness.withdrawals.is_empty()
            || !witness.placements.is_empty()
            || !witness.cancellations.is_empty()
            || !witness.liquidations.is_empty())
    {
        return Err(ProtocolError::ForcedActionDeadline);
    }

    let forced_iocs: BTreeSet<Hash32> = forced
        .iter()
        .filter_map(|entry| match &entry.action {
            ForcedActionV1::ReduceOnlyIoc(order) => Some(order.order_id()),
            _ => None,
        })
        .collect();
    if witness.public.escape_only
        && witness
            .fills
            .iter()
            .any(|pair| !forced_iocs.contains(&pair.taker_order.order_id()))
    {
        return Err(ProtocolError::InvalidForcedAction);
    }
    Ok(())
}

fn validate_batches(witness: &TransitionWitness) -> Result<(), ProtocolError> {
    let deposit_root = deposit_batch_root(&witness.deposits);
    if deposit_root != witness.public.deposit_batch_root {
        return Err(ProtocolError::DepositRootMismatch);
    }
    let withdrawals = transition_withdrawals(witness)?;
    let withdrawal_root = withdrawal_batch_root(&withdrawals);
    if withdrawal_root != witness.public.withdrawal_batch_root {
        return Err(ProtocolError::WithdrawalRootMismatch);
    }
    let operation_batch_hash = transition_batch_hash(
        &witness.deposits,
        &withdrawals,
        &witness.placements,
        &witness.cancellations,
        &witness.fills,
        &witness.liquidations,
    );
    if witness.public.oracle_certificate_hash == [0; 32]
        || liquidation_batch_root(&witness.liquidations) != witness.public.liquidation_batch_root
        || (!witness.liquidations.is_empty() && witness.public.oracle_mode != OracleMode::Normal)
        || transition_envelope_hash(&TransitionEnvelopeV4 {
            operation_batch_hash,
            deposit_event_batch_root: witness.public.deposit_event_batch_root,
            oracle_certificate_hash: witness.public.oracle_certificate_hash,
            oracle_mode: witness.public.oracle_mode,
            matcher_receipt_batch_root: witness.public.matcher_receipt_batch_root,
            collateral_settlement_root: witness.public.collateral_settlement_root,
            forced_action_batch_root: witness.public.forced_action_batch_root,
            escape_only: witness.public.escape_only,
            encrypted_availability_root: witness.public.encrypted_availability_root,
        }) != witness.public.batch_hash
    {
        return Err(ProtocolError::BatchHashMismatch);
    }
    Ok(())
}

pub fn transition_withdrawals(
    witness: &TransitionWitness,
) -> Result<Vec<SignedWithdrawalRequest>, ProtocolError> {
    let mut withdrawals = witness.withdrawals.clone();
    for entry in witness.forced_inbox.consumed()? {
        if let ForcedActionV1::Withdraw(request) = &entry.action {
            withdrawals.push(request.clone());
        }
    }
    Ok(withdrawals)
}

fn extend_nullifiers(
    previous: &[Hash32],
    additions: impl IntoIterator<Item = Hash32>,
) -> Result<Vec<Hash32>, ProtocolError> {
    let mut seen: BTreeSet<Hash32> = previous.iter().copied().collect();
    if seen.len() != previous.len() {
        return Err(ProtocolError::DuplicateRequest);
    }
    let mut next = previous.to_vec();
    for id in additions {
        if !seen.insert(id) {
            return Err(ProtocolError::DuplicateRequest);
        }
        next.push(id);
    }
    Ok(next)
}

fn verify_private_evolution(
    witness: &TransitionWitness,
    fee_policy: FeePolicy,
    external: &V2ExternalEffects,
    stop_before_external: bool,
) -> Result<Option<BTreeMap<[u8; 32], AccountLeaf>>, ProtocolError> {
    let mut accounts = account_map(&witness.previous_accounts)?;
    let mut positions = position_map(&witness.previous_positions)?;
    let mut open_orders = open_order_map(&witness.previous_open_orders)?;
    let initial_sizes: BTreeMap<[u8; 32], u64> = positions
        .iter()
        .map(|(trader, position)| (*trader, position.position.size.unsigned_abs()))
        .collect();
    let initial_positions: BTreeMap<[u8; 32], crate::types::Position> = positions
        .iter()
        .map(|(trader, position)| (*trader, position.position))
        .collect();
    let mut v2_increased_margin_bps = BTreeMap::<[u8; 32], u32>::new();
    let mut v2_position_margin_bps = external
        .starting_position_margin_bps
        .clone()
        .unwrap_or_default();
    let mut forced_iocs: BTreeMap<OrderId, SignedLimitOrder> = BTreeMap::new();
    let mut withdrawal_total = Amount(0);

    let mut deposit_total = Amount(0);
    for deposit in &witness.deposits {
        deposit.validate()?;
        if deposit.chain_id != witness.public.chain_id
            || deposit.observed_height > witness.public.sidechain_height
        {
            return Err(ProtocolError::TransitionMismatch("deposit context"));
        }
        let account = accounts
            .get_mut(&deposit.trader.0)
            .ok_or(ProtocolError::TransitionMismatch("deposit account"))?;
        let amount = Amount(i128::from(deposit.amount));
        account.collateral = account.collateral.checked_add(amount)?;
        deposit_total = deposit_total.checked_add(amount)?;
    }

    let mut funding_sum = Amount(0);
    for (trader, position_leaf) in &mut positions {
        let account = accounts
            .get_mut(trader)
            .ok_or(ProtocolError::TransitionMismatch("position account"))?;
        let payment = funding_payment(
            &position_leaf.position,
            witness.public.mark_price,
            witness.public.funding_rate_ppm,
            witness.risk_params,
        )?;
        account.collateral = account.collateral.checked_add(payment)?;
        funding_sum = funding_sum.checked_add(payment)?;
        position_leaf.position.last_funding_index = witness.next_state.funding_index;
    }

    // Expiry is deterministic and does not consume an account nonce.
    open_orders.retain(|_, order| order.expires_at_height >= witness.public.sidechain_height);

    // Forced actions consume account nonces in their authenticated on-chain
    // order. They never require a matcher receipt and remain processable after
    // their original validity window, provided they were live when enqueued.
    for entry in witness.forced_inbox.consumed()? {
        if entry.enqueued_sidechain_height > witness.public.sidechain_height {
            return Err(ProtocolError::InvalidForcedAction);
        }
        match &entry.action {
            ForcedActionV1::Cancel(signed) => {
                let cancel = &signed.cancel;
                if cancel.chain_id != witness.public.chain_id
                    || cancel.market != witness.public.market
                    || !cancel.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction);
                }
                consume_account_nonce(&mut accounts, cancel.trader, cancel.nonce)?;
                if let Some(resting) = open_orders.get(&cancel.order_id) {
                    if resting.trader != cancel.trader {
                        return Err(ProtocolError::TransitionMismatch("forced cancel owner"));
                    }
                    open_orders.remove(&cancel.order_id);
                }
            }
            ForcedActionV1::ReduceOnlyIoc(signed) => {
                let order = &signed.order;
                if order.chain_id != witness.public.chain_id
                    || order.market != witness.public.market
                    || !order.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction);
                }
                consume_account_nonce(&mut accounts, order.trader, order.nonce)?;
                if forced_iocs
                    .insert(signed.order_id(), signed.clone())
                    .is_some()
                {
                    return Err(ProtocolError::DuplicateRequest);
                }
            }
            ForcedActionV1::Withdraw(signed) => {
                let withdrawal = &signed.request;
                if withdrawal.chain_id != witness.public.chain_id
                    || withdrawal.not_before_height > witness.public.sidechain_height
                {
                    return Err(ProtocolError::TransitionMismatch(
                        "forced withdrawal context",
                    ));
                }
                consume_account_nonce(&mut accounts, withdrawal.trader, withdrawal.nonce)?;
                let account = accounts.get_mut(&withdrawal.trader.0).ok_or(
                    ProtocolError::TransitionMismatch("forced withdrawal account"),
                )?;
                let amount = Amount(i128::from(withdrawal.amount));
                account.collateral = account.collateral.checked_sub(amount)?;
                withdrawal_total = withdrawal_total.checked_add(amount)?;
            }
        }
    }

    for signed in &witness.cancellations {
        signed.verify()?;
        let cancel = &signed.cancel;
        if cancel.chain_id != witness.public.chain_id
            || cancel.market != witness.public.market
            || !cancel.is_live_at(witness.public.sidechain_height)
        {
            return Err(ProtocolError::TransitionMismatch("cancel context"));
        }
        let resting = open_orders
            .get(&cancel.order_id)
            .ok_or(ProtocolError::TransitionMismatch("cancel order"))?;
        if resting.trader != cancel.trader {
            return Err(ProtocolError::TransitionMismatch("cancel owner"));
        }
        consume_account_nonce(&mut accounts, cancel.trader, cancel.nonce)?;
        open_orders.remove(&cancel.order_id);
    }

    for placement in &witness.placements {
        placement.order.verify()?;
        let order = &placement.order.order;
        if placement.salt == [0; 32] {
            return Err(ProtocolError::ZeroSalt);
        }
        if order.chain_id != witness.public.chain_id
            || order.market != witness.public.market
            || !order.is_live_at(witness.public.sidechain_height)
            || order.time_in_force != TimeInForce::GoodTilHeight
        {
            return Err(ProtocolError::TransitionMismatch("placement context"));
        }
        consume_account_nonce(&mut accounts, order.trader, order.nonce)?;
        let leaf = OpenOrderLeaf {
            version: OpenOrderLeaf::VERSION,
            order_id: placement.order.order_id(),
            trader: order.trader,
            market: order.market,
            side: order.side,
            limit_price: order.limit_price,
            remaining_quantity: order.quantity,
            received_sequence: placement.received_sequence,
            expires_at_height: order.expires_at_height,
            salt: placement.salt,
        };
        leaf.validate()?;
        if open_orders.insert(leaf.order_id, leaf).is_some() {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    ensure_unique_receipt_sequences(&open_orders)?;

    // Only taker orders are newly accepted by fills. Makers must already be in
    // the committed book (including a placement earlier in this batch).
    let mut taker_states: BTreeMap<OrderId, (LimitOrder, u64, u64)> = BTreeMap::new();
    let mut fee_total = Amount(0);
    let mut previous_trade: Option<(u64, OrderId)> = None;
    for pair in &witness.fills {
        if previous_trade.is_some_and(|(sequence, taker)| {
            pair.trade.sequence < sequence
                || (pair.trade.sequence == sequence && pair.taker_order.order_id() != taker)
        }) {
            return Err(ProtocolError::InvalidTradeSequence);
        }
        previous_trade = Some((pair.trade.sequence, pair.taker_order.order_id()));
        if pair.trade.maker == pair.trade.taker {
            return Err(ProtocolError::IncompatibleOrders);
        }
        pair.trade.validate_orders(
            &pair.maker_order,
            &pair.taker_order,
            witness.public.sidechain_height,
        )?;
        let expected_maker_fee = trading_fee(
            pair.trade.price,
            pair.trade.quantity,
            witness.risk_params.maker_fee_bps,
        )?;
        let expected_taker_fee = trading_fee(
            pair.trade.price,
            pair.trade.quantity,
            i32::try_from(witness.risk_params.taker_fee_bps)
                .map_err(|_| ProtocolError::InvalidRate)?,
        )?;
        if pair.trade.maker_fee != expected_maker_fee || pair.trade.taker_fee != expected_taker_fee
        {
            return Err(ProtocolError::TransitionMismatch("trade fee"));
        }
        if witness.risk_params.maker_fee_bps.unsigned_abs() > pair.maker_order.order.max_fee_bps
            || witness.risk_params.taker_fee_bps > pair.taker_order.order.max_fee_bps
        {
            return Err(ProtocolError::InvalidRate);
        }
        if pair.taker_order.order.flags.contains(OrderFlags::POST_ONLY) {
            return Err(ProtocolError::IncompatibleOrders);
        }

        let best = best_maker(
            &open_orders,
            &pair.taker_order.order,
            witness.public.sidechain_height,
            pair.trade.sequence,
        )
        .ok_or(ProtocolError::PriceTimePriorityViolation)?;
        if best != pair.maker_order.order_id() {
            return Err(ProtocolError::PriceTimePriorityViolation);
        }
        let maker_leaf = open_orders
            .get(&best)
            .cloned()
            .ok_or(ProtocolError::PriceTimePriorityViolation)?;
        validate_maker_leaf(&maker_leaf, &pair.maker_order)?;
        let maker_remaining = maker_leaf
            .remaining_quantity
            .get()
            .checked_sub(pair.trade.quantity.get())
            .ok_or(ProtocolError::ExcessFill)?;
        if maker_remaining == 0 {
            open_orders.remove(&best);
        } else {
            open_orders
                .get_mut(&best)
                .expect("maker exists")
                .remaining_quantity = Quantity::new(maker_remaining)?;
        }
        apply_trader_fill_with_policy(
            &pair.maker_order,
            pair.trade.maker_fill(),
            &mut accounts,
            &mut positions,
            witness.public.mark_price,
            witness.risk_params,
            external.selected_margin_bps.as_ref(),
            &mut v2_position_margin_bps,
            &mut v2_increased_margin_bps,
        )?;

        let taker_id = pair.taker_order.order_id();
        if open_orders.contains_key(&taker_id) {
            return Err(ProtocolError::IncompatibleOrders);
        }
        match taker_states.entry(taker_id) {
            Entry::Vacant(entry) => {
                if let Some(forced) = forced_iocs.get(&taker_id) {
                    if forced != &pair.taker_order {
                        return Err(ProtocolError::InvalidForcedAction);
                    }
                } else {
                    consume_account_nonce(
                        &mut accounts,
                        pair.taker_order.order.trader,
                        pair.taker_order.order.nonce,
                    )?;
                }
                entry.insert((
                    pair.taker_order.order.clone(),
                    pair.taker_order.order.quantity.get(),
                    pair.trade.sequence,
                ));
            }
            Entry::Occupied(entry) => {
                if entry.get().0 != pair.taker_order.order || entry.get().2 != pair.trade.sequence {
                    return Err(ProtocolError::IncompatibleOrders);
                }
            }
        }
        let taker_state = taker_states.get_mut(&taker_id).expect("inserted above");
        taker_state.1 = taker_state
            .1
            .checked_sub(pair.trade.quantity.get())
            .ok_or(ProtocolError::ExcessFill)?;
        apply_trader_fill_with_policy(
            &pair.taker_order,
            pair.trade.taker_fill(),
            &mut accounts,
            &mut positions,
            witness.public.mark_price,
            witness.risk_params,
            external.selected_margin_bps.as_ref(),
            &mut v2_position_margin_bps,
            &mut v2_increased_margin_bps,
        )?;
        fee_total = fee_total
            .checked_add(pair.trade.maker_fee)?
            .checked_add(pair.trade.taker_fee)?;
    }
    for (order_id, (order, remaining, received_sequence)) in taker_states {
        match order.time_in_force {
            TimeInForce::FillOrKill if remaining != 0 => return Err(ProtocolError::ExcessFill),
            TimeInForce::GoodTilHeight if remaining != 0 => {
                let resting = OpenOrderLeaf {
                    version: OpenOrderLeaf::VERSION,
                    order_id,
                    trader: order.trader,
                    market: order.market,
                    side: order.side,
                    limit_price: order.limit_price,
                    remaining_quantity: Quantity::new(remaining)?,
                    received_sequence,
                    expires_at_height: order.expires_at_height,
                    // The proof compares semantic fields; the committed next leaf
                    // supplies a fresh non-zero salt.
                    salt: [1; 32],
                };
                if open_orders.insert(order_id, resting).is_some() {
                    return Err(ProtocolError::DuplicateMerkleKey);
                }
            }
            _ => {}
        }
    }
    ensure_unique_receipt_sequences(&open_orders)?;

    // Liquidations are permissionless proof inputs, not matcher-issued taker
    // orders. Each one must reduce a position that fails maintenance at the
    // adverse authenticated oracle bound and execute against the best eligible
    // resting price. The target's resting orders are cancelled deterministically
    // on its first liquidation so they cannot recreate risk after the rescue.
    let mut liquidation_insurance_delta = Amount(0);
    let mut liquidation_notional_total = 0u128;
    let mut liquidated_targets = BTreeSet::new();
    let mut liquidation_ids = BTreeSet::new();
    for liquidation in &witness.liquidations {
        if !liquidation_ids.insert(liquidation.liquidation_id()) {
            return Err(ProtocolError::DuplicateRequest);
        }
        if liquidation.target == liquidation.maker_order.order.trader {
            return Err(ProtocolError::IncompatibleOrders);
        }

        let target_position = positions
            .get(&liquidation.target.0)
            .ok_or(ProtocolError::TransitionMismatch(
                "liquidation target position",
            ))?
            .position;
        let target_collateral = accounts
            .get(&liquidation.target.0)
            .ok_or(ProtocolError::TransitionMismatch(
                "liquidation target account",
            ))?
            .collateral;
        if target_position.size == 0 {
            return Err(ProtocolError::NotLiquidatable);
        }
        let adverse_price = if target_position.size > 0 {
            witness.public.liquidation_low
        } else {
            witness.public.liquidation_high
        };
        if !is_liquidatable(
            target_collateral,
            &target_position,
            adverse_price,
            witness.risk_params,
        )? {
            return Err(ProtocolError::NotLiquidatable);
        }
        if liquidation.quantity.get() > target_position.size.unsigned_abs() {
            return Err(ProtocolError::ExcessFill);
        }

        if liquidated_targets.insert(liquidation.target.0) {
            open_orders.retain(|_, order| order.trader != liquidation.target);
        }

        let liquidation_side = if target_position.size > 0 {
            Side::Sell
        } else {
            Side::Buy
        };
        let maker = &liquidation.maker_order;
        maker.verify()?;
        if maker.order.chain_id != witness.public.chain_id
            || maker.order.market != witness.public.market
            || maker.order.side != liquidation_side.opposite()
            || !maker.order.is_live_at(witness.public.sidechain_height)
            || witness.risk_params.maker_fee_bps.unsigned_abs() > maker.order.max_fee_bps
        {
            return Err(ProtocolError::IncompatibleOrders);
        }

        let best = best_liquidation_maker(
            &open_orders,
            liquidation_side,
            witness.public.liquidation_low,
            witness.public.liquidation_high,
            witness.public.sidechain_height,
        )
        .ok_or(ProtocolError::PriceTimePriorityViolation)?;
        if best != maker.order_id() {
            return Err(ProtocolError::PriceTimePriorityViolation);
        }
        liquidation_notional_total = accumulate_liquidation_notional(
            liquidation_notional_total,
            maker.order.limit_price,
            liquidation.quantity,
            witness.risk_params.maximum_liquidation_notional_quote_units,
        )?;
        let maker_leaf = open_orders
            .get(&best)
            .cloned()
            .ok_or(ProtocolError::PriceTimePriorityViolation)?;
        validate_maker_leaf(&maker_leaf, maker)?;
        let maker_remaining = maker_leaf
            .remaining_quantity
            .get()
            .checked_sub(liquidation.quantity.get())
            .ok_or(ProtocolError::ExcessFill)?;
        if maker_remaining == 0 {
            open_orders.remove(&best);
        } else {
            open_orders
                .get_mut(&best)
                .expect("maker exists")
                .remaining_quantity = Quantity::new(maker_remaining)?;
        }

        let maker_fee = trading_fee(
            maker.order.limit_price,
            liquidation.quantity,
            witness.risk_params.maker_fee_bps,
        )?;
        apply_trader_fill_with_policy(
            maker,
            crate::order::Fill {
                match_id: liquidation.liquidation_id(),
                trader: maker.order.trader,
                side: maker.order.side,
                price: maker.order.limit_price,
                quantity: liquidation.quantity,
                fee: maker_fee,
            },
            &mut accounts,
            &mut positions,
            witness.public.mark_price,
            witness.risk_params,
            external.selected_margin_bps.as_ref(),
            &mut v2_position_margin_bps,
            &mut v2_increased_margin_bps,
        )?;
        fee_total = fee_total.checked_add(maker_fee)?;

        let target_outcome = apply_fill(
            target_position,
            liquidation_side,
            liquidation.quantity,
            maker.order.limit_price,
        )?;
        if target_outcome.position.size.unsigned_abs() >= target_position.size.unsigned_abs()
            || (target_outcome.position.size != 0
                && target_outcome.position.size.signum() != target_position.size.signum())
        {
            return Err(ProtocolError::ReduceOnlyViolation);
        }
        positions
            .get_mut(&liquidation.target.0)
            .expect("target position exists")
            .position = target_outcome.position;
        let target_account = accounts
            .get_mut(&liquidation.target.0)
            .expect("target account exists");
        target_account.collateral = target_account
            .collateral
            .checked_add(target_outcome.realized_pnl)?;
        target_account.cumulative_realized_pnl = target_account
            .cumulative_realized_pnl
            .checked_add(target_outcome.realized_pnl)?;

        let desired_penalty = trading_fee(
            maker.order.limit_price,
            liquidation.quantity,
            i32::try_from(witness.risk_params.liquidation_fee_bps)
                .map_err(|_| ProtocolError::InvalidRate)?,
        )?;
        let penalty = Amount(desired_penalty.0.min(target_account.collateral.0.max(0)));
        target_account.collateral = target_account.collateral.checked_sub(penalty)?;
        let bad_debt = Amount((-target_account.collateral.0).max(0));
        if bad_debt.0 != 0 {
            target_account.collateral = target_account.collateral.checked_add(bad_debt)?;
        }
        liquidation_insurance_delta = liquidation_insurance_delta
            .checked_add(penalty)?
            .checked_sub(bad_debt)?;
        let projected_insurance = witness
            .previous_state
            .insurance_fund
            .checked_sub(funding_sum)?
            .checked_add(liquidation_insurance_delta)?;
        if projected_insurance.0 < 0 {
            return Err(ProtocolError::InsufficientCollateral);
        }
    }
    ensure_unique_receipt_sequences(&open_orders)?;

    for signed in &witness.withdrawals {
        signed.verify()?;
        let withdrawal = &signed.request;
        if withdrawal.chain_id != witness.public.chain_id
            || withdrawal.not_before_height > witness.public.sidechain_height
        {
            return Err(ProtocolError::TransitionMismatch("withdrawal context"));
        }
        let account = accounts
            .get_mut(&withdrawal.trader.0)
            .ok_or(ProtocolError::TransitionMismatch("withdrawal account"))?;
        if account.account_nonce != withdrawal.nonce {
            return Err(ProtocolError::InvalidNonce);
        }
        account.account_nonce = account
            .account_nonce
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let amount = Amount(i128::from(withdrawal.amount));
        account.collateral = account.collateral.checked_sub(amount)?;
        withdrawal_total = withdrawal_total.checked_add(amount)?;
    }

    if stop_before_external {
        return Ok(Some(accounts));
    }

    if fee_policy != FeePolicy::Insurance
        && (!external.account_debits.is_empty()
            || external.insurance_delta != Amount(0)
            || external.withdrawal_delta != Amount(0)
            || external.selected_margin_bps.is_some()
            || external.starting_position_margin_bps.is_some())
    {
        return Err(ProtocolError::InvalidBondState);
    }
    if external.withdrawal_delta.0 < 0 {
        return Err(ProtocolError::InvalidBondState);
    }
    for (trader, nonce, amount) in &external.account_debits {
        if amount.0 < 0 {
            return Err(ProtocolError::InvalidBondState);
        }
        let account = accounts
            .get_mut(&trader.0)
            .ok_or(ProtocolError::TransitionMismatch(
                "bond subscription account",
            ))?;
        if account.account_nonce != *nonce {
            return Err(ProtocolError::InvalidNonce);
        }
        account.account_nonce = account
            .account_nonce
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        account.collateral = account.collateral.checked_sub(*amount)?;
    }
    withdrawal_total = withdrawal_total.checked_add(external.withdrawal_delta)?;

    let expected_total_deposits = witness
        .previous_state
        .total_deposits
        .checked_add(deposit_total)?;
    let expected_total_withdrawals = witness
        .previous_state
        .total_withdrawals
        .checked_add(withdrawal_total)?;
    let liquidation_adjusted_insurance = witness
        .previous_state
        .insurance_fund
        .checked_sub(funding_sum)?
        .checked_add(liquidation_insurance_delta)?;
    let (expected_fee_pool, expected_insurance) = match fee_policy {
        FeePolicy::LegacyPool => (
            witness.previous_state.fee_pool.checked_add(fee_total)?,
            liquidation_adjusted_insurance,
        ),
        FeePolicy::Insurance => {
            if witness.previous_state.fee_pool != Amount(0) {
                return Err(ProtocolError::ConservationViolation);
            }
            (
                Amount(0),
                liquidation_adjusted_insurance
                    .checked_add(fee_total)?
                    .checked_add(external.insurance_delta)?,
            )
        }
    };
    if witness.next_state.total_deposits != expected_total_deposits
        || witness.next_state.total_withdrawals != expected_total_withdrawals
        || witness.next_state.fee_pool != expected_fee_pool
        || witness.next_state.insurance_fund != expected_insurance
    {
        return Err(ProtocolError::ConservationViolation);
    }

    let next_accounts = account_map(&witness.next_accounts)?;
    let next_positions = position_map(&witness.next_positions)?;
    let next_open_orders = open_order_map(&witness.next_open_orders)?;
    compare_account_semantics(&accounts, &next_accounts)?;
    compare_position_semantics(&positions, &next_positions)?;
    compare_open_order_semantics(&open_orders, &next_open_orders)?;
    validate_open_interest(&positions, witness.risk_params.maximum_open_interest_lots)?;
    match fee_policy {
        FeePolicy::LegacyPool => {
            validate_global_collateral_conservation(&accounts, &positions, &witness.next_state)?
        }
        FeePolicy::Insurance => validate_global_collateral_conservation_v2_exact_delta(
            &account_map(&witness.previous_accounts)?,
            &position_map(&witness.previous_positions)?,
            &witness.previous_state,
            &accounts,
            &positions,
            &witness.next_state,
        )?,
    }

    for (trader, next_position) in &positions {
        if next_position.position.size == 0 {
            continue;
        }
        let old_abs = initial_sizes.get(trader).copied().unwrap_or(0);
        let initial_position = initial_positions
            .get(trader)
            .copied()
            .unwrap_or(crate::types::Position::FLAT);
        let margin_kind = if external.selected_margin_bps.is_some()
            && creates_directional_risk(initial_position, next_position.position)
            || external.selected_margin_bps.is_none()
                && next_position.position.size.unsigned_abs() > old_abs
        {
            MarginKind::Initial
        } else {
            MarginKind::Maintenance
        };
        let account = accounts
            .get(trader)
            .ok_or(ProtocolError::TransitionMismatch("margin account"))?;
        let required = if let Some(margin_bps) = v2_increased_margin_bps.get(trader) {
            required_margin_bps_v2(
                &next_position.position,
                witness.public.mark_price,
                *margin_bps,
            )?
        } else {
            required_margin(
                &next_position.position,
                witness.public.mark_price,
                margin_kind,
                witness.risk_params,
            )?
        };
        if equity(
            account.collateral,
            &next_position.position,
            witness.public.mark_price,
        )?
        .0 < required.0
        {
            return Err(ProtocolError::InsufficientCollateral);
        }

        if liquidated_targets.contains(trader) {
            let adverse_price = if next_position.position.size > 0 {
                witness.public.liquidation_low
            } else {
                witness.public.liquidation_high
            };
            let maintenance = required_margin(
                &next_position.position,
                adverse_price,
                MarginKind::Maintenance,
                witness.risk_params,
            )?;
            if equity(account.collateral, &next_position.position, adverse_price)?.0 < maintenance.0
            {
                return Err(ProtocolError::InsufficientCollateral);
            }
        }
    }

    Ok(None)
}

fn validate_global_collateral_conservation(
    accounts: &BTreeMap<[u8; 32], AccountLeaf>,
    positions: &BTreeMap<[u8; 32], PositionLeaf>,
    state: &ExchangeState,
) -> Result<(), ProtocolError> {
    let mut equity_total = Amount(0);
    for account in accounts.values() {
        equity_total = equity_total.checked_add(account.collateral)?;
    }
    for position in positions.values() {
        let unrealized = equity(Amount(0), &position.position, state.mark_price)?;
        equity_total = equity_total.checked_add(unrealized)?;
    }
    let controlled = equity_total
        .checked_add(state.insurance_fund)?
        .checked_add(state.fee_pool)?;
    let issued = state.total_deposits.checked_sub(state.total_withdrawals)?;
    if controlled != issued {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(())
}

/// Preserve the exact V2 controlled-value residual across a transition.
///
/// V1 historically truncates every position's unrealized PnL before summing
/// it. That can change the integer total on a price-only transition even when
/// aggregate position size is zero. V2 instead lifts every term to the common
/// `PRICE_SCALE` numerator and compares the exact residual relative to issued
/// collateral before and after the transition. Recomputing the prior residual
/// from the authenticated full-state witness preserves already-reachable V2
/// states without inventing a fractional balance, while any transition that
/// destroys or creates rounding dust fails closed.
fn validate_global_collateral_conservation_v2_exact_delta(
    previous_accounts: &BTreeMap<[u8; 32], AccountLeaf>,
    previous_positions: &BTreeMap<[u8; 32], PositionLeaf>,
    previous_state: &ExchangeState,
    next_accounts: &BTreeMap<[u8; 32], AccountLeaf>,
    next_positions: &BTreeMap<[u8; 32], PositionLeaf>,
    next_state: &ExchangeState,
) -> Result<(), ProtocolError> {
    let previous_residual = controlled_value_residual_numerator_v2(
        previous_accounts,
        previous_positions,
        previous_state,
    )?;
    let next_residual =
        controlled_value_residual_numerator_v2(next_accounts, next_positions, next_state)?;
    if previous_residual != next_residual {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(())
}

fn controlled_value_residual_numerator_v2(
    accounts: &BTreeMap<[u8; 32], AccountLeaf>,
    positions: &BTreeMap<[u8; 32], PositionLeaf>,
    state: &ExchangeState,
) -> Result<Int256V2, ProtocolError> {
    let mut controlled = Int256V2::ZERO;
    for account in accounts.values() {
        controlled = controlled
            .checked_add(Int256V2::from_i128(account.collateral.0).checked_mul_u64(PRICE_SCALE)?)?;
    }
    for position in positions.values() {
        let price_delta = i128::from(state.mark_price.get())
            .checked_sub(i128::from(position.position.entry_price))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        controlled = controlled.checked_add(Int256V2::checked_product_i64_i128(
            position.position.size,
            price_delta,
        )?)?;
    }
    controlled = controlled
        .checked_add(Int256V2::from_i128(state.insurance_fund.0).checked_mul_u64(PRICE_SCALE)?)?;
    controlled = controlled
        .checked_add(Int256V2::from_i128(state.fee_pool.0).checked_mul_u64(PRICE_SCALE)?)?;
    let issued = state.total_deposits.checked_sub(state.total_withdrawals)?;
    controlled.checked_sub(Int256V2::from_i128(issued.0).checked_mul_u64(PRICE_SCALE)?)
}

fn account_map(accounts: &[AccountLeaf]) -> Result<BTreeMap<[u8; 32], AccountLeaf>, ProtocolError> {
    let mut map = BTreeMap::new();
    for account in accounts {
        account.validate()?;
        if map.insert(account.trader.0, account.clone()).is_some() {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    Ok(map)
}

fn position_map(
    positions: &[PositionLeaf],
) -> Result<BTreeMap<[u8; 32], PositionLeaf>, ProtocolError> {
    let mut map = BTreeMap::new();
    for position in positions {
        position.validate()?;
        if map.insert(position.trader.0, position.clone()).is_some() {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    Ok(map)
}

fn open_order_map(
    orders: &[OpenOrderLeaf],
) -> Result<BTreeMap<OrderId, OpenOrderLeaf>, ProtocolError> {
    let mut map = BTreeMap::new();
    for order in orders {
        order.validate()?;
        if map.insert(order.order_id, order.clone()).is_some() {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    ensure_unique_receipt_sequences(&map)?;
    Ok(map)
}

fn ensure_unique_receipt_sequences(
    orders: &BTreeMap<OrderId, OpenOrderLeaf>,
) -> Result<(), ProtocolError> {
    let mut sequences = BTreeSet::new();
    if orders
        .values()
        .any(|order| !sequences.insert(order.received_sequence))
    {
        Err(ProtocolError::PriceTimePriorityViolation)
    } else {
        Ok(())
    }
}

fn consume_account_nonce(
    accounts: &mut BTreeMap<[u8; 32], AccountLeaf>,
    trader: crate::types::XOnlyKey,
    nonce: u64,
) -> Result<(), ProtocolError> {
    let account = accounts
        .get_mut(&trader.0)
        .ok_or(ProtocolError::TransitionMismatch("order account"))?;
    if account.account_nonce != nonce {
        return Err(ProtocolError::InvalidNonce);
    }
    account.account_nonce = account
        .account_nonce
        .checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    Ok(())
}

fn validate_maker_leaf(
    leaf: &OpenOrderLeaf,
    signed_order: &SignedLimitOrder,
) -> Result<(), ProtocolError> {
    let order = &signed_order.order;
    if leaf.order_id != signed_order.order_id()
        || leaf.trader != order.trader
        || leaf.market != order.market
        || leaf.side != order.side
        || leaf.limit_price != order.limit_price
        || leaf.remaining_quantity.get() > order.quantity.get()
        || leaf.expires_at_height != order.expires_at_height
        || order.time_in_force != TimeInForce::GoodTilHeight
    {
        return Err(ProtocolError::TransitionMismatch("maker book leaf"));
    }
    Ok(())
}

fn best_maker(
    orders: &BTreeMap<OrderId, OpenOrderLeaf>,
    taker: &LimitOrder,
    height: u64,
    taker_sequence: u64,
) -> Option<OrderId> {
    let mut best: Option<&OpenOrderLeaf> = None;
    for candidate in orders.values() {
        if candidate.side == taker.side
            || candidate.expires_at_height < height
            || candidate.received_sequence >= taker_sequence
        {
            continue;
        }
        let crosses = match taker.side {
            Side::Buy => candidate.limit_price <= taker.limit_price,
            Side::Sell => candidate.limit_price >= taker.limit_price,
        };
        if !crosses {
            continue;
        }
        let is_better = match best {
            None => true,
            Some(current) => match taker.side {
                Side::Buy => {
                    candidate.limit_price < current.limit_price
                        || (candidate.limit_price == current.limit_price
                            && (candidate.received_sequence < current.received_sequence
                                || (candidate.received_sequence == current.received_sequence
                                    && candidate.order_id < current.order_id)))
                }
                Side::Sell => {
                    candidate.limit_price > current.limit_price
                        || (candidate.limit_price == current.limit_price
                            && (candidate.received_sequence < current.received_sequence
                                || (candidate.received_sequence == current.received_sequence
                                    && candidate.order_id < current.order_id)))
                }
            },
        };
        if is_better {
            best = Some(candidate);
        }
    }
    best.map(|order| order.order_id)
}

/// Selects the price-time best maker for a liquidation. A long target sells
/// only at or above the authenticated low bound; a short target buys only at
/// or below the authenticated high bound. Better-than-bound execution remains
/// valid and is selected before receipt time.
fn best_liquidation_maker(
    orders: &BTreeMap<OrderId, OpenOrderLeaf>,
    liquidation_side: Side,
    low: Price,
    high: Price,
    height: u64,
) -> Option<OrderId> {
    let mut best: Option<&OpenOrderLeaf> = None;
    for candidate in orders.values() {
        if candidate.side == liquidation_side || candidate.expires_at_height < height {
            continue;
        }
        let within_bound = match liquidation_side {
            Side::Sell => candidate.side == Side::Buy && candidate.limit_price >= low,
            Side::Buy => candidate.side == Side::Sell && candidate.limit_price <= high,
        };
        if !within_bound {
            continue;
        }
        let is_better = match best {
            None => true,
            Some(current) => {
                let better_price = match liquidation_side {
                    Side::Sell => candidate.limit_price > current.limit_price,
                    Side::Buy => candidate.limit_price < current.limit_price,
                };
                better_price
                    || (candidate.limit_price == current.limit_price
                        && (candidate.received_sequence < current.received_sequence
                            || (candidate.received_sequence == current.received_sequence
                                && candidate.order_id < current.order_id)))
            }
        };
        if is_better {
            best = Some(candidate);
        }
    }
    best.map(|order| order.order_id)
}

fn apply_trader_fill(
    signed_order: &SignedLimitOrder,
    fill: crate::order::Fill,
    accounts: &mut BTreeMap<[u8; 32], AccountLeaf>,
    positions: &mut BTreeMap<[u8; 32], PositionLeaf>,
) -> Result<(), ProtocolError> {
    let account = accounts
        .get_mut(&signed_order.order.trader.0)
        .ok_or(ProtocolError::TransitionMismatch("order account"))?;
    let position = positions
        .get_mut(&signed_order.order.trader.0)
        .ok_or(ProtocolError::TransitionMismatch("order position"))?;
    let old_size = position.position.size;
    let outcome = apply_fill(position.position, fill.side, fill.quantity, fill.price)?;
    if signed_order.order.flags.contains(OrderFlags::REDUCE_ONLY)
        && (old_size == 0
            || outcome.position.size.unsigned_abs() >= old_size.unsigned_abs()
            || (outcome.position.size != 0 && outcome.position.size.signum() != old_size.signum()))
    {
        return Err(ProtocolError::ReduceOnlyViolation);
    }
    position.position = outcome.position;
    account.collateral = account
        .collateral
        .checked_add(outcome.realized_pnl)?
        .checked_sub(fill.fee)?;
    account.cumulative_realized_pnl = account
        .cumulative_realized_pnl
        .checked_add(outcome.realized_pnl)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_trader_fill_with_policy(
    signed_order: &SignedLimitOrder,
    fill: crate::order::Fill,
    accounts: &mut BTreeMap<[u8; 32], AccountLeaf>,
    positions: &mut BTreeMap<[u8; 32], PositionLeaf>,
    mark_price: Price,
    risk_params: RiskParams,
    selected_margin_bps: Option<&BTreeMap<OrderId, u32>>,
    position_margin_bps: &mut BTreeMap<[u8; 32], u32>,
    increased_margin_bps: &mut BTreeMap<[u8; 32], u32>,
) -> Result<(), ProtocolError> {
    let old_position = positions
        .get(&signed_order.order.trader.0)
        .ok_or(ProtocolError::TransitionMismatch("order position"))?
        .position;
    apply_trader_fill(signed_order, fill, accounts, positions)?;
    let Some(selections) = selected_margin_bps else {
        return Ok(());
    };
    let selected =
        *selections
            .get(&signed_order.order_id())
            .ok_or(ProtocolError::TransitionMismatch(
                "missing signed order margin",
            ))?;
    validate_selected_margin_bps(selected, risk_params)?;
    let next_position = positions
        .get(&signed_order.order.trader.0)
        .ok_or(ProtocolError::TransitionMismatch("order position"))?
        .position;
    if next_position.size != 0 {
        let increases_risk = creates_directional_risk(old_position, next_position);
        let required = if increases_risk {
            let carried = position_margin_bps
                .get(&signed_order.order.trader.0)
                .copied()
                .unwrap_or(risk_params.initial_margin_bps);
            let effective = carried.max(selected);
            increased_margin_bps
                .entry(signed_order.order.trader.0)
                .and_modify(|current| *current = (*current).max(effective))
                .or_insert(effective);
            position_margin_bps.insert(signed_order.order.trader.0, effective);
            required_margin_bps_v2(&next_position, mark_price, effective)?
        } else {
            required_margin(
                &next_position,
                mark_price,
                MarginKind::Maintenance,
                risk_params,
            )?
        };
        let account = accounts
            .get(&signed_order.order.trader.0)
            .ok_or(ProtocolError::TransitionMismatch("order account"))?;
        if equity(account.collateral, &next_position, mark_price)?.0 < required.0 {
            return Err(ProtocolError::InsufficientCollateral);
        }
    } else {
        position_margin_bps.insert(signed_order.order.trader.0, risk_params.initial_margin_bps);
    }
    Ok(())
}

fn compare_open_order_semantics(
    actual: &BTreeMap<OrderId, OpenOrderLeaf>,
    expected: &BTreeMap<OrderId, OpenOrderLeaf>,
) -> Result<(), ProtocolError> {
    if actual.len() != expected.len() {
        return Err(ProtocolError::TransitionMismatch("open order set"));
    }
    for (order_id, actual) in actual {
        let expected = expected
            .get(order_id)
            .ok_or(ProtocolError::TransitionMismatch("open order set"))?;
        if actual.version != expected.version
            || actual.order_id != expected.order_id
            || actual.trader != expected.trader
            || actual.market != expected.market
            || actual.side != expected.side
            || actual.limit_price != expected.limit_price
            || actual.remaining_quantity != expected.remaining_quantity
            || actual.received_sequence != expected.received_sequence
            || actual.expires_at_height != expected.expires_at_height
        {
            return Err(ProtocolError::TransitionMismatch("open order semantics"));
        }
    }
    Ok(())
}

fn compare_account_semantics(
    actual: &BTreeMap<[u8; 32], AccountLeaf>,
    expected: &BTreeMap<[u8; 32], AccountLeaf>,
) -> Result<(), ProtocolError> {
    if actual.len() != expected.len() {
        return Err(ProtocolError::TransitionMismatch("account set"));
    }
    for (key, actual) in actual {
        let expected = expected
            .get(key)
            .ok_or(ProtocolError::TransitionMismatch("account set"))?;
        if actual.version != expected.version
            || actual.trader != expected.trader
            || actual.account_nonce != expected.account_nonce
            || actual.collateral != expected.collateral
            || actual.cumulative_realized_pnl != expected.cumulative_realized_pnl
        {
            return Err(ProtocolError::TransitionMismatch("account semantics"));
        }
    }
    Ok(())
}

fn compare_position_semantics(
    actual: &BTreeMap<[u8; 32], PositionLeaf>,
    expected: &BTreeMap<[u8; 32], PositionLeaf>,
) -> Result<(), ProtocolError> {
    if actual.len() != expected.len() {
        return Err(ProtocolError::TransitionMismatch("position set"));
    }
    for (key, actual) in actual {
        let expected = expected
            .get(key)
            .ok_or(ProtocolError::TransitionMismatch("position set"))?;
        if actual.version != expected.version
            || actual.trader != expected.trader
            || actual.market != expected.market
            || actual.position != expected.position
            || actual.isolated_margin != expected.isolated_margin
        {
            return Err(ProtocolError::TransitionMismatch("position semantics"));
        }
    }
    Ok(())
}

fn validate_open_interest(
    positions: &BTreeMap<[u8; 32], PositionLeaf>,
    maximum_open_interest_lots: u64,
) -> Result<(), ProtocolError> {
    let (net, longs) = positions
        .values()
        .try_fold((0i128, 0u128), |(net, longs), position| {
            let size = position.position.size;
            Ok::<_, ProtocolError>((
                net.checked_add(i128::from(size))
                    .ok_or(ProtocolError::ArithmeticOverflow)?,
                if size > 0 {
                    longs
                        .checked_add(u128::from(size.unsigned_abs()))
                        .ok_or(ProtocolError::ArithmeticOverflow)?
                } else {
                    longs
                },
            ))
        })?;
    if net != 0 {
        return Err(ProtocolError::ConservationViolation);
    }
    if longs > u128::from(maximum_open_interest_lots) {
        return Err(ProtocolError::TransitionMismatch("open-interest cap"));
    }
    Ok(())
}

fn accumulate_liquidation_notional(
    current: u128,
    price: Price,
    quantity: Quantity,
    maximum: u64,
) -> Result<u128, ProtocolError> {
    let added = u128::try_from(notional(price, quantity.get())?.0)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let total = current
        .checked_add(added)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if total > u128::from(maximum) {
        return Err(ProtocolError::TransitionMismatch(
            "liquidation-notional cap",
        ));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::empty_hash;
    use crate::order::{OrderFlags, Side, TimeInForce};
    use crate::types::{Position, XOnlyKey, PRICE_SCALE};
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    const TEST_TRADER_XONLY: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn account(collateral: i128, salt: u8) -> AccountLeaf {
        AccountLeaf {
            version: 1,
            trader: XOnlyKey(TEST_TRADER_XONLY),
            account_nonce: 0,
            collateral: Amount(collateral),
            cumulative_realized_pnl: Amount(0),
            salt: [salt; 32],
        }
    }

    fn position(salt: u8) -> PositionLeaf {
        PositionLeaf {
            version: 1,
            trader: XOnlyKey(TEST_TRADER_XONLY),
            market: ECX_USDD_MARKET,
            position: Position::FLAT,
            isolated_margin: Amount(0),
            salt: [salt; 32],
        }
    }

    fn deposit_witness() -> TransitionWitness {
        let chain_id = [9; 32];
        let previous_accounts = vec![account(1_000, 1)];
        let previous_positions = vec![position(1)];
        let next_accounts = vec![account(1_100, 2)];
        let next_positions = vec![position(2)];
        let deposits = vec![DepositRequest {
            version: 1,
            chain_id,
            deposit_txid: [3; 32],
            deposit_vout: 0,
            usdd_asset_id: [4; 32],
            trader: XOnlyKey(TEST_TRADER_XONLY),
            amount: 100,
            observed_height: 11,
        }];
        let withdrawals = vec![];
        let placements = vec![];
        let cancellations = vec![];
        let fills = vec![];
        let liquidations = vec![];
        let oracle_certificate_hash = [17; 32];
        let matcher_receipt_batch_root =
            crate::matcher_receipt::central_matcher_receipt_batch_root(&[]);
        let forced_action_batch_root = forced_action_batch_root(&[]);
        let encrypted_availability_root = [19; 32];
        let deposit_previous =
            crate::deposit_inbox::DepositInboxStateV1::genesis([21; 32], chain_id).unwrap();
        let deposit_event = DepositEventV1 {
            version: DepositEventV1::VERSION,
            chain_id,
            index: 0,
            previous_root: deposit_previous.head_root,
            observed_sidechain_height: 11,
            observed_parent_height: 115,
            source_txid: deposits[0].deposit_txid,
            deposit_vout: deposits[0].deposit_vout,
            marker_vout: 1,
            output_sha256: [22; 32],
            trader: deposits[0].trader,
        };
        let deposit_next = crate::deposit_inbox::DepositInboxStateV1 {
            head_root: deposit_event.next_root(),
            entry_count: 1,
            processed_root: deposit_event.next_root(),
            cursor: 1,
        };
        let deposit_event_batch_root = deposit_event_batch_root(&[deposit_event]);
        let collateral_settlement_root = [23; 32];
        let liquidation_batch_root = liquidation_batch_root(&liquidations);
        let batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
            operation_batch_hash: transition_batch_hash(
                &deposits,
                &withdrawals,
                &placements,
                &cancellations,
                &fills,
                &liquidations,
            ),
            deposit_event_batch_root,
            oracle_certificate_hash,
            oracle_mode: OracleMode::Normal,
            matcher_receipt_batch_root,
            collateral_settlement_root,
            forced_action_batch_root,
            escape_only: false,
            encrypted_availability_root,
        });
        let forced_inbox = crate::forced::ForcedInboxStateV1::genesis([20; 32], chain_id).unwrap();
        let previous_receipts = empty_hash();
        let previous_roots = StateRoots::from_private_state(
            &previous_accounts,
            &previous_positions,
            &[],
            &[],
            &[],
            previous_receipts,
        )
        .unwrap();
        let next_roots = StateRoots::from_private_state(
            &next_accounts,
            &next_positions,
            &[],
            &[deposits[0].request_id()],
            &[],
            next_order_receipts_root(previous_receipts, batch_hash),
        )
        .unwrap();
        let previous_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            sequence: 7,
            last_processed_height: 10,
            mark_price: Price::new(PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(1_000),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox: deposit_previous,
            roots: previous_roots,
        };
        let next_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            sequence: 8,
            last_processed_height: 12,
            mark_price: Price::new(PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(1_100),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox: deposit_next,
            roots: next_roots,
        };
        let params = RiskParams::default();
        TransitionWitness {
            public: TransitionPublicInputs {
                protocol_version: TransitionPublicInputs::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                sidechain_height: 12,
                parent_height: 120,
                forced_inclusion_blocks: 6,
                previous_state_root: previous_state.state_root(),
                previous_sequence: 7,
                next_state_root: next_state.state_root(),
                next_sequence: 8,
                batch_hash,
                deposit_batch_root: deposit_batch_root(&deposits),
                deposit_event_batch_root,
                withdrawal_batch_root: withdrawal_batch_root(&withdrawals),
                collateral_settlement_root,
                liquidation_batch_root,
                existing_withdrawal_commitment: [6; 32],
                oracle_certificate_hash,
                oracle_mode: OracleMode::Normal,
                matcher_receipt_batch_root,
                forced_action_batch_root,
                escape_only: false,
                encrypted_availability_root,
                mark_price: Price::new(PRICE_SCALE).unwrap(),
                liquidation_low: Price::new(PRICE_SCALE).unwrap(),
                liquidation_high: Price::new(PRICE_SCALE).unwrap(),
                funding_rate_ppm: 0,
                risk_params_hash: risk_params_hash(params),
            },
            risk_params: params,
            previous_state,
            next_state,
            previous_accounts,
            next_accounts,
            previous_positions,
            next_positions,
            previous_open_orders: vec![],
            next_open_orders: vec![],
            previous_deposit_nullifiers: vec![],
            previous_withdrawal_nullifiers: vec![],
            deposit_inbox: DepositInboxTransitionV1 {
                pending_entries: vec![deposit_event],
                consumed_count: 1,
            },
            forced_inbox: ForcedInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposits,
            withdrawals,
            placements,
            cancellations,
            fills,
            liquidations,
        }
    }

    #[test]
    fn verifies_private_deposit_and_emits_fixed_journal() {
        let witness = deposit_witness();
        let journal = verify_transition(&witness).unwrap();
        assert_eq!(journal.next_state_root, witness.next_state.state_root());
        assert_eq!(journal.existing_withdrawal_commitment, [6; 32]);
        assert_eq!(journal.encode_fixed().len(), 563);
    }

    #[test]
    fn rotated_salts_are_allowed_but_semantic_forgery_is_not() {
        let witness = deposit_witness();
        verify_transition(&witness).unwrap();

        let mut forged = witness;
        forged.next_accounts[0].collateral = Amount(1_101);
        forged.next_state.roots = StateRoots::from_private_state(
            &forged.next_accounts,
            &forged.next_positions,
            &forged.next_open_orders,
            &[forged.deposits[0].request_id()],
            &[],
            next_order_receipts_root(
                forged.previous_state.roots.order_receipts,
                forged.public.batch_hash,
            ),
        )
        .unwrap();
        forged.public.next_state_root = forged.next_state.state_root();
        assert!(matches!(
            verify_transition(&forged),
            Err(ProtocolError::TransitionMismatch("account semantics"))
        ));
    }

    #[test]
    fn duplicate_deposit_is_rejected_across_batches() {
        let mut witness = deposit_witness();
        witness.previous_deposit_nullifiers = vec![witness.deposits[0].request_id()];
        assert_eq!(
            verify_transition(&witness),
            Err(ProtocolError::DuplicateRequest)
        );
    }

    #[test]
    fn source_inbox_liveness_profile_is_consensus_bounded() {
        let mut wrong_window = deposit_witness();
        wrong_window.public.forced_inclusion_blocks = 7;
        assert_eq!(
            validate_source_inboxes(&wrong_window),
            Err(ProtocolError::InvalidForcedInbox)
        );

        let mut oversized_witness = deposit_witness();
        let event = oversized_witness.deposit_inbox.pending_entries[0];
        oversized_witness
            .deposit_inbox
            .pending_entries
            .resize(449, event);
        assert_eq!(
            validate_source_inboxes(&oversized_witness),
            Err(ProtocolError::InvalidForcedInbox)
        );

        let mut unbounded_backlog = deposit_witness();
        unbounded_backlog.next_state.forced_inbox.entry_count = 65;
        assert_eq!(
            validate_source_inboxes(&unbounded_backlog),
            Err(ProtocolError::InvalidForcedInbox)
        );
    }

    fn signing_identity(byte: u8) -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn signed_order(
        secret: &SecretKey,
        trader: XOnlyKey,
        side: Side,
        price: u64,
        quantity: u64,
        nonce: u64,
        time_in_force: TimeInForce,
    ) -> SignedLimitOrder {
        SignedLimitOrder::sign(
            LimitOrder {
                version: 1,
                chain_id: [9; 32],
                market: ECX_USDD_MARKET,
                trader,
                side,
                time_in_force,
                flags: OrderFlags::NONE,
                limit_price: Price::new(price).unwrap(),
                quantity: Quantity::new(quantity).unwrap(),
                client_order_id: [nonce as u8 + 1; 16],
                max_fee_bps: 20,
                nonce,
                valid_from_height: 1,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    #[test]
    fn persistent_book_fill_preserves_maker_nonce_and_remaining_quantity() {
        let (maker_secret, maker_key) = signing_identity(11);
        let (taker_secret, taker_key) = signing_identity(12);
        let maker_order = signed_order(
            &maker_secret,
            maker_key,
            Side::Sell,
            100 * PRICE_SCALE,
            5,
            0,
            TimeInForce::GoodTilHeight,
        );
        let taker_order = signed_order(
            &taker_secret,
            taker_key,
            Side::Buy,
            100 * PRICE_SCALE,
            2,
            0,
            TimeInForce::ImmediateOrCancel,
        );
        let params = RiskParams::default();
        let maker_fee = trading_fee(
            maker_order.order.limit_price,
            Quantity::new(2).unwrap(),
            params.maker_fee_bps,
        )
        .unwrap();
        let taker_fee = trading_fee(
            maker_order.order.limit_price,
            Quantity::new(2).unwrap(),
            params.taker_fee_bps as i32,
        )
        .unwrap();
        let trade = TradeMatch {
            sequence: 20,
            maker_order_id: maker_order.order_id(),
            taker_order_id: taker_order.order_id(),
            maker: maker_key,
            taker: taker_key,
            maker_side: Side::Sell,
            price: maker_order.order.limit_price,
            quantity: Quantity::new(2).unwrap(),
            maker_fee,
            taker_fee,
        };
        let fills = vec![MatchedOrderPair {
            maker_order: maker_order.clone(),
            taker_order,
            trade,
        }];
        let previous_accounts = vec![
            AccountLeaf {
                version: 1,
                trader: maker_key,
                account_nonce: 1,
                collateral: Amount(1_000),
                cumulative_realized_pnl: Amount(0),
                salt: [1; 32],
            },
            AccountLeaf {
                version: 1,
                trader: taker_key,
                account_nonce: 0,
                collateral: Amount(1_000),
                cumulative_realized_pnl: Amount(0),
                salt: [2; 32],
            },
        ];
        let next_accounts = vec![
            AccountLeaf {
                salt: [3; 32],
                ..previous_accounts[0].clone()
            },
            AccountLeaf {
                account_nonce: 1,
                collateral: Amount(1_000 - taker_fee.0),
                salt: [4; 32],
                ..previous_accounts[1].clone()
            },
        ];
        let previous_positions = vec![
            PositionLeaf {
                version: 1,
                trader: maker_key,
                market: ECX_USDD_MARKET,
                position: Position::FLAT,
                isolated_margin: Amount(0),
                salt: [5; 32],
            },
            PositionLeaf {
                version: 1,
                trader: taker_key,
                market: ECX_USDD_MARKET,
                position: Position::FLAT,
                isolated_margin: Amount(0),
                salt: [6; 32],
            },
        ];
        let next_positions = vec![
            PositionLeaf {
                position: Position {
                    size: -2,
                    entry_price: 100 * PRICE_SCALE,
                    last_funding_index: 0,
                },
                salt: [7; 32],
                ..previous_positions[0].clone()
            },
            PositionLeaf {
                position: Position {
                    size: 2,
                    entry_price: 100 * PRICE_SCALE,
                    last_funding_index: 0,
                },
                salt: [8; 32],
                ..previous_positions[1].clone()
            },
        ];
        let previous_open_orders = vec![OpenOrderLeaf {
            version: 1,
            order_id: maker_order.order_id(),
            trader: maker_key,
            market: ECX_USDD_MARKET,
            side: Side::Sell,
            limit_price: maker_order.order.limit_price,
            remaining_quantity: Quantity::new(5).unwrap(),
            received_sequence: 10,
            expires_at_height: 100,
            salt: [9; 32],
        }];
        let next_open_orders = vec![OpenOrderLeaf {
            remaining_quantity: Quantity::new(3).unwrap(),
            salt: [10; 32],
            ..previous_open_orders[0].clone()
        }];
        let deposits = vec![];
        let withdrawals = vec![];
        let placements = vec![];
        let cancellations = vec![];
        let liquidations = vec![];
        let oracle_certificate_hash = [17; 32];
        let matcher_receipt_batch_root =
            crate::matcher_receipt::central_matcher_receipt_batch_root(&[]);
        let forced_action_batch_root = forced_action_batch_root(&[]);
        let encrypted_availability_root = [19; 32];
        let deposit_event_batch_root = deposit_event_batch_root(&[]);
        let collateral_settlement_root = [23; 32];
        let liquidation_batch_root = liquidation_batch_root(&liquidations);
        let batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
            operation_batch_hash: transition_batch_hash(
                &deposits,
                &withdrawals,
                &placements,
                &cancellations,
                &fills,
                &liquidations,
            ),
            deposit_event_batch_root,
            oracle_certificate_hash,
            oracle_mode: OracleMode::Normal,
            matcher_receipt_batch_root,
            collateral_settlement_root,
            forced_action_batch_root,
            escape_only: false,
            encrypted_availability_root,
        });
        let forced_inbox = crate::forced::ForcedInboxStateV1::genesis([20; 32], [9; 32]).unwrap();
        let deposit_inbox =
            crate::deposit_inbox::DepositInboxStateV1::genesis([21; 32], [9; 32]).unwrap();
        let previous_receipts = empty_hash();
        let previous_roots = StateRoots::from_private_state(
            &previous_accounts,
            &previous_positions,
            &previous_open_orders,
            &[],
            &[],
            previous_receipts,
        )
        .unwrap();
        let next_roots = StateRoots::from_private_state(
            &next_accounts,
            &next_positions,
            &next_open_orders,
            &[],
            &[],
            next_order_receipts_root(previous_receipts, batch_hash),
        )
        .unwrap();
        let previous_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id: [9; 32],
            market: ECX_USDD_MARKET,
            sequence: 1,
            last_processed_height: 9,
            mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(2_000),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox,
            roots: previous_roots,
        };
        let next_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id: [9; 32],
            market: ECX_USDD_MARKET,
            sequence: 2,
            last_processed_height: 10,
            mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(2_000),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(maker_fee.0 + taker_fee.0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox,
            roots: next_roots,
        };
        let witness = TransitionWitness {
            public: TransitionPublicInputs {
                protocol_version: TransitionPublicInputs::VERSION,
                chain_id: [9; 32],
                market: ECX_USDD_MARKET,
                sidechain_height: 10,
                parent_height: 100,
                forced_inclusion_blocks: 6,
                previous_state_root: previous_state.state_root(),
                previous_sequence: 1,
                next_state_root: next_state.state_root(),
                next_sequence: 2,
                batch_hash,
                deposit_batch_root: deposit_batch_root(&deposits),
                deposit_event_batch_root,
                withdrawal_batch_root: withdrawal_batch_root(&withdrawals),
                collateral_settlement_root,
                liquidation_batch_root,
                existing_withdrawal_commitment: [4; 32],
                oracle_certificate_hash,
                oracle_mode: OracleMode::Normal,
                matcher_receipt_batch_root,
                forced_action_batch_root,
                escape_only: false,
                encrypted_availability_root,
                mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
                liquidation_low: Price::new(99 * PRICE_SCALE).unwrap(),
                liquidation_high: Price::new(101 * PRICE_SCALE).unwrap(),
                funding_rate_ppm: 0,
                risk_params_hash: risk_params_hash(params),
            },
            risk_params: params,
            previous_state,
            next_state,
            previous_accounts,
            next_accounts,
            previous_positions,
            next_positions,
            previous_open_orders,
            next_open_orders,
            previous_deposit_nullifiers: vec![],
            previous_withdrawal_nullifiers: vec![],
            deposit_inbox: DepositInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            forced_inbox: ForcedInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposits,
            withdrawals,
            placements,
            cancellations,
            fills,
            liquidations,
        };
        verify_transition(&witness).unwrap();
        assert_eq!(witness.next_accounts[0].account_nonce, 1);
        assert_eq!(witness.next_open_orders[0].remaining_quantity.get(), 3);
    }

    fn liquidation_witness() -> TransitionWitness {
        let chain_id = [9; 32];
        let (target_secret, target_key) = signing_identity(31);
        let (maker_secret, maker_key) = signing_identity(32);
        let _ = target_secret;
        let maker_order = signed_order(
            &maker_secret,
            maker_key,
            Side::Buy,
            90 * PRICE_SCALE,
            10,
            0,
            TimeInForce::GoodTilHeight,
        );
        let liquidation = LiquidationMatchV1 {
            target: target_key,
            maker_order: maker_order.clone(),
            quantity: Quantity::new(10).unwrap(),
        };
        let liquidations = vec![liquidation];
        let previous_accounts = vec![
            AccountLeaf {
                version: AccountLeaf::VERSION,
                trader: target_key,
                account_nonce: 0,
                collateral: Amount(20),
                cumulative_realized_pnl: Amount(0),
                salt: [41; 32],
            },
            AccountLeaf {
                version: AccountLeaf::VERSION,
                trader: maker_key,
                account_nonce: 1,
                collateral: Amount(1_980),
                cumulative_realized_pnl: Amount(0),
                salt: [42; 32],
            },
        ];
        let next_accounts = vec![
            AccountLeaf {
                collateral: Amount(0),
                cumulative_realized_pnl: Amount(-100),
                salt: [43; 32],
                ..previous_accounts[0].clone()
            },
            AccountLeaf {
                collateral: Amount(2_080),
                cumulative_realized_pnl: Amount(100),
                salt: [44; 32],
                ..previous_accounts[1].clone()
            },
        ];
        let previous_positions = vec![
            PositionLeaf {
                version: PositionLeaf::VERSION,
                trader: target_key,
                market: ECX_USDD_MARKET,
                position: Position {
                    size: 10,
                    entry_price: 100 * PRICE_SCALE,
                    last_funding_index: 0,
                },
                isolated_margin: Amount(0),
                salt: [45; 32],
            },
            PositionLeaf {
                version: PositionLeaf::VERSION,
                trader: maker_key,
                market: ECX_USDD_MARKET,
                position: Position {
                    size: -10,
                    entry_price: 100 * PRICE_SCALE,
                    last_funding_index: 0,
                },
                isolated_margin: Amount(0),
                salt: [46; 32],
            },
        ];
        let next_positions = vec![
            PositionLeaf {
                position: Position::FLAT,
                salt: [47; 32],
                ..previous_positions[0].clone()
            },
            PositionLeaf {
                position: Position::FLAT,
                salt: [48; 32],
                ..previous_positions[1].clone()
            },
        ];
        let previous_open_orders = vec![OpenOrderLeaf {
            version: OpenOrderLeaf::VERSION,
            order_id: maker_order.order_id(),
            trader: maker_key,
            market: ECX_USDD_MARKET,
            side: Side::Buy,
            limit_price: maker_order.order.limit_price,
            remaining_quantity: Quantity::new(10).unwrap(),
            received_sequence: 1,
            expires_at_height: 100,
            salt: [49; 32],
        }];
        let next_open_orders = vec![];
        let deposits = vec![];
        let withdrawals = vec![];
        let placements = vec![];
        let cancellations = vec![];
        let fills = vec![];
        let oracle_certificate_hash = [17; 32];
        let matcher_receipt_batch_root =
            crate::matcher_receipt::central_matcher_receipt_batch_root(&[]);
        let forced_action_batch_root = forced_action_batch_root(&[]);
        let encrypted_availability_root = [19; 32];
        let deposit_event_batch_root = deposit_event_batch_root(&[]);
        let collateral_settlement_root = [23; 32];
        let liquidation_batch_root = liquidation_batch_root(&liquidations);
        let batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
            operation_batch_hash: transition_batch_hash(
                &deposits,
                &withdrawals,
                &placements,
                &cancellations,
                &fills,
                &liquidations,
            ),
            deposit_event_batch_root,
            oracle_certificate_hash,
            oracle_mode: OracleMode::Normal,
            matcher_receipt_batch_root,
            collateral_settlement_root,
            forced_action_batch_root,
            escape_only: false,
            encrypted_availability_root,
        });
        let forced_inbox = crate::forced::ForcedInboxStateV1::genesis([20; 32], chain_id).unwrap();
        let deposit_inbox =
            crate::deposit_inbox::DepositInboxStateV1::genesis([21; 32], chain_id).unwrap();
        let previous_receipts = empty_hash();
        let previous_roots = StateRoots::from_private_state(
            &previous_accounts,
            &previous_positions,
            &previous_open_orders,
            &[],
            &[],
            previous_receipts,
        )
        .unwrap();
        let next_roots = StateRoots::from_private_state(
            &next_accounts,
            &next_positions,
            &next_open_orders,
            &[],
            &[],
            next_order_receipts_root(previous_receipts, batch_hash),
        )
        .unwrap();
        let params = RiskParams::default();
        let previous_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            sequence: 1,
            last_processed_height: 9,
            mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(2_100),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(100),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox,
            roots: previous_roots,
        };
        let next_state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            sequence: 2,
            last_processed_height: 10,
            mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(2_100),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(20),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [18; 32],
            forced_inbox,
            deposit_inbox,
            roots: next_roots,
        };
        TransitionWitness {
            public: TransitionPublicInputs {
                protocol_version: TransitionPublicInputs::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                sidechain_height: 10,
                parent_height: 100,
                forced_inclusion_blocks: 6,
                previous_state_root: previous_state.state_root(),
                previous_sequence: 1,
                next_state_root: next_state.state_root(),
                next_sequence: 2,
                batch_hash,
                deposit_batch_root: deposit_batch_root(&deposits),
                deposit_event_batch_root,
                withdrawal_batch_root: withdrawal_batch_root(&withdrawals),
                collateral_settlement_root,
                liquidation_batch_root,
                existing_withdrawal_commitment: [4; 32],
                oracle_certificate_hash,
                oracle_mode: OracleMode::Normal,
                matcher_receipt_batch_root,
                forced_action_batch_root,
                escape_only: false,
                encrypted_availability_root,
                mark_price: Price::new(100 * PRICE_SCALE).unwrap(),
                liquidation_low: Price::new(90 * PRICE_SCALE).unwrap(),
                liquidation_high: Price::new(110 * PRICE_SCALE).unwrap(),
                funding_rate_ppm: 0,
                risk_params_hash: risk_params_hash(params),
            },
            risk_params: params,
            previous_state,
            next_state,
            previous_accounts,
            next_accounts,
            previous_positions,
            next_positions,
            previous_open_orders,
            next_open_orders,
            previous_deposit_nullifiers: vec![],
            previous_withdrawal_nullifiers: vec![],
            deposit_inbox: DepositInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            forced_inbox: ForcedInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposits,
            withdrawals,
            placements,
            cancellations,
            fills,
            liquidations,
        }
    }

    #[test]
    fn liquidation_uses_adverse_bound_and_insurance_for_bad_debt() {
        let witness = liquidation_witness();
        verify_transition(&witness).unwrap();
        assert_eq!(witness.next_accounts[0].collateral, Amount(0));
        assert_eq!(witness.next_state.insurance_fund, Amount(20));
        assert!(witness
            .next_positions
            .iter()
            .all(|leaf| leaf.position.size == 0));
    }

    #[test]
    fn non_liquidatable_target_is_rejected() {
        let mut witness = liquidation_witness();
        witness.previous_accounts[0].collateral = Amount(200);
        witness.previous_state.roots = StateRoots::from_private_state(
            &witness.previous_accounts,
            &witness.previous_positions,
            &witness.previous_open_orders,
            &[],
            &[],
            witness.previous_state.roots.order_receipts,
        )
        .unwrap();
        witness.public.previous_state_root = witness.previous_state.state_root();
        assert_eq!(
            verify_transition(&witness),
            Err(ProtocolError::NotLiquidatable)
        );
    }

    #[test]
    fn complete_liquidation_transition_rejects_batch_above_frozen_notional_cap() {
        let mut witness = liquidation_witness();
        witness.risk_params.maximum_liquidation_notional_quote_units = 1;
        witness.public.risk_params_hash = risk_params_hash(witness.risk_params);
        assert_eq!(
            verify_transition(&witness),
            Err(ProtocolError::TransitionMismatch(
                "liquidation-notional cap"
            ))
        );
    }

    #[test]
    fn liquidation_fails_closed_before_socializing_uninsured_bad_debt() {
        let mut witness = liquidation_witness();
        witness.previous_state.insurance_fund = Amount(79);
        witness.public.previous_state_root = witness.previous_state.state_root();
        assert_eq!(
            verify_transition(&witness),
            Err(ProtocolError::InsufficientCollateral)
        );
    }

    #[test]
    fn liquidation_rejects_a_worse_maker_or_price_outside_bound() {
        let mut worse = liquidation_witness();
        let (better_secret, better_key) = signing_identity(33);
        let better = signed_order(
            &better_secret,
            better_key,
            Side::Buy,
            91 * PRICE_SCALE,
            10,
            0,
            TimeInForce::GoodTilHeight,
        );
        worse.previous_open_orders.push(OpenOrderLeaf {
            version: OpenOrderLeaf::VERSION,
            order_id: better.order_id(),
            trader: better_key,
            market: ECX_USDD_MARKET,
            side: Side::Buy,
            limit_price: better.order.limit_price,
            remaining_quantity: Quantity::new(10).unwrap(),
            received_sequence: 2,
            expires_at_height: 100,
            salt: [50; 32],
        });
        worse.previous_state.roots = StateRoots::from_private_state(
            &worse.previous_accounts,
            &worse.previous_positions,
            &worse.previous_open_orders,
            &[],
            &[],
            worse.previous_state.roots.order_receipts,
        )
        .unwrap();
        worse.public.previous_state_root = worse.previous_state.state_root();
        assert_eq!(
            verify_transition(&worse),
            Err(ProtocolError::PriceTimePriorityViolation)
        );

        let mut outside = liquidation_witness();
        outside.public.liquidation_low = Price::new(91 * PRICE_SCALE).unwrap();
        assert_eq!(
            verify_transition(&outside),
            Err(ProtocolError::PriceTimePriorityViolation)
        );
    }

    #[test]
    fn liquidation_without_authenticated_maker_liquidity_halts_safely() {
        let mut witness = liquidation_witness();
        witness.previous_open_orders.clear();
        witness.previous_state.roots = StateRoots::from_private_state(
            &witness.previous_accounts,
            &witness.previous_positions,
            &witness.previous_open_orders,
            &[],
            &[],
            witness.previous_state.roots.order_receipts,
        )
        .unwrap();
        witness.public.previous_state_root = witness.previous_state.state_root();

        assert_eq!(
            verify_transition(&witness),
            Err(ProtocolError::PriceTimePriorityViolation)
        );
        assert_eq!(witness.previous_state.insurance_fund, Amount(100));
        assert_eq!(witness.previous_accounts[0].collateral, Amount(20));
    }

    #[test]
    fn best_maker_uses_price_before_time_then_order_id() {
        let (_, taker_key) = signing_identity(21);
        let taker = LimitOrder {
            version: 1,
            chain_id: [9; 32],
            market: ECX_USDD_MARKET,
            trader: taker_key,
            side: Side::Buy,
            time_in_force: TimeInForce::ImmediateOrCancel,
            flags: OrderFlags::NONE,
            limit_price: Price::new(110 * PRICE_SCALE).unwrap(),
            quantity: Quantity::new(1).unwrap(),
            client_order_id: [1; 16],
            max_fee_bps: 20,
            nonce: 0,
            valid_from_height: 1,
            expires_at_height: 100,
        };
        let leaf = |id: u8, price: u64, sequence: u64| OpenOrderLeaf {
            version: 1,
            order_id: [id; 32],
            trader: XOnlyKey([id; 32]),
            market: ECX_USDD_MARKET,
            side: Side::Sell,
            limit_price: Price::new(price * PRICE_SCALE).unwrap(),
            remaining_quantity: Quantity::new(1).unwrap(),
            received_sequence: sequence,
            expires_at_height: 100,
            salt: [id; 32],
        };
        let orders = open_order_map(&[leaf(1, 105, 1), leaf(2, 104, 9), leaf(3, 104, 3)]).unwrap();
        assert_eq!(best_maker(&orders, &taker, 10, 20), Some([3; 32]));
    }

    #[test]
    fn open_interest_is_consensus_capped_after_conservation() {
        let mut long = position(1);
        long.position = Position {
            size: 11,
            entry_price: PRICE_SCALE,
            last_funding_index: 0,
        };
        let mut short = position(2);
        short.position = Position {
            size: -11,
            entry_price: PRICE_SCALE,
            last_funding_index: 0,
        };
        let positions = BTreeMap::from([([1; 32], long), ([2; 32], short)]);
        assert_eq!(
            validate_open_interest(&positions, 10),
            Err(ProtocolError::TransitionMismatch("open-interest cap"))
        );
        assert_eq!(validate_open_interest(&positions, 11), Ok(()));
    }

    #[test]
    fn legacy_per_position_pnl_rounding_can_reject_a_price_only_state() {
        // Equal and opposite positions have zero net mark exposure.  At 0.90
        // USDD both independently truncated PnLs sum to zero; at 1.20 USDD the
        // long rounds to +1 atom while the short rounds to zero.  No asset or
        // position changed, yet the legacy integer-equity sum changes.  V1 is
        // intentionally preserved; the incremental successor carries exact
        // cost and fractional cash instead of reusing this invariant.
        let accounts = BTreeMap::from([
            (
                [1; 32],
                AccountLeaf {
                    trader: XOnlyKey(TEST_TRADER_XONLY),
                    collateral: Amount(100),
                    salt: [0xa1; 32],
                    ..account(100, 0xa1)
                },
            ),
            (
                [2; 32],
                AccountLeaf {
                    trader: XOnlyKey(TEST_TRADER_XONLY),
                    collateral: Amount(100),
                    salt: [0xa2; 32],
                    ..account(100, 0xa2)
                },
            ),
        ]);
        let positions = BTreeMap::from([
            (
                [1; 32],
                PositionLeaf {
                    position: Position {
                        size: 3,
                        entry_price: 80_000_000,
                        last_funding_index: 0,
                    },
                    salt: [0xb1; 32],
                    ..position(0xb1)
                },
            ),
            (
                [2; 32],
                PositionLeaf {
                    position: Position {
                        size: -3,
                        entry_price: 90_000_000,
                        last_funding_index: 0,
                    },
                    salt: [0xb2; 32],
                    ..position(0xb2)
                },
            ),
        ]);
        let mut state = deposit_witness().next_state;
        state.total_deposits = Amount(200);
        state.total_withdrawals = Amount(0);
        state.insurance_fund = Amount(0);
        state.fee_pool = Amount(0);
        state.mark_price = Price::new(90_000_000).unwrap();
        assert!(validate_global_collateral_conservation(&accounts, &positions, &state).is_ok());

        let previous_state = state.clone();
        state.mark_price = Price::new(120_000_000).unwrap();
        assert_eq!(
            validate_global_collateral_conservation(&accounts, &positions, &state),
            Err(ProtocolError::ConservationViolation)
        );

        // V2 compares the exact common-denominator residual across the
        // transition. The net position is flat, so a price-only update cannot
        // manufacture a conservation failure even though the legacy integer
        // sum changes.
        assert_eq!(
            validate_global_collateral_conservation_v2_exact_delta(
                &accounts,
                &positions,
                &previous_state,
                &accounts,
                &positions,
                &state,
            ),
            Ok(())
        );

        // A real change in exact exposure is not hidden by the residual rule.
        let mut altered_positions = positions.clone();
        altered_positions.get_mut(&[2; 32]).unwrap().position.size = -2;
        assert_eq!(
            validate_global_collateral_conservation_v2_exact_delta(
                &accounts,
                &positions,
                &previous_state,
                &accounts,
                &altered_positions,
                &state,
            ),
            Err(ProtocolError::ConservationViolation)
        );
    }

    #[test]
    fn aggregate_liquidation_notional_is_consensus_capped() {
        let price = Price::new(2 * PRICE_SCALE).unwrap();
        let quantity = Quantity::new(3).unwrap();
        assert_eq!(
            accumulate_liquidation_notional(0, price, quantity, 6),
            Ok(6)
        );
        assert_eq!(
            accumulate_liquidation_notional(6, price, quantity, 11),
            Err(ProtocolError::TransitionMismatch(
                "liquidation-notional cap"
            ))
        );
    }

    #[test]
    fn v2_rejects_intermediate_underwater_reduction_before_later_rescue_fill() {
        let trader = XOnlyKey(TEST_TRADER_XONLY);
        let signed = SignedLimitOrder {
            order: LimitOrder {
                version: LimitOrder::VERSION,
                chain_id: [9; 32],
                market: ECX_USDD_MARKET,
                trader,
                side: Side::Sell,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::REDUCE_ONLY,
                limit_price: Price::new(90 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(5 * PRICE_SCALE).unwrap(),
                client_order_id: [44; 16],
                max_fee_bps: 10,
                nonce: 0,
                valid_from_height: 1,
                expires_at_height: 100,
            },
            signature: crate::order::Signature64([0; 64]),
        };
        let mut accounts = BTreeMap::from([(trader.0, account(i128::from(70 * PRICE_SCALE), 1))]);
        let mut open_position = position(1);
        open_position.position = Position {
            size: i64::try_from(10 * PRICE_SCALE).unwrap(),
            entry_price: 100 * PRICE_SCALE,
            last_funding_index: 0,
        };
        let mut positions = BTreeMap::from([(trader.0, open_position)]);
        let selected = BTreeMap::from([(signed.order_id(), 1_000)]);
        let mut position_margins = BTreeMap::from([(trader.0, 1_000)]);
        let mut increased = BTreeMap::new();
        let result = apply_trader_fill_with_policy(
            &signed,
            crate::order::Fill {
                match_id: [45; 32],
                trader,
                side: Side::Sell,
                price: Price::new(90 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(5 * PRICE_SCALE).unwrap(),
                fee: Amount(0),
            },
            &mut accounts,
            &mut positions,
            Price::new(100 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
            Some(&selected),
            &mut position_margins,
            &mut increased,
        );
        // The remaining five-lot position has only 20 USDD equity versus a
        // 30 USDD maintenance requirement. A later closing fill could make it
        // flat, but consensus must reject at this intermediate boundary.
        assert_eq!(result, Err(ProtocolError::InsufficientCollateral));
    }

    #[test]
    fn v2_position_keeps_stricter_carried_margin_when_a_looser_order_adds_risk() {
        let trader = XOnlyKey(TEST_TRADER_XONLY);
        let signed = SignedLimitOrder {
            order: LimitOrder {
                version: LimitOrder::VERSION,
                chain_id: [9; 32],
                market: ECX_USDD_MARKET,
                trader,
                side: Side::Buy,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::from_bits(0).unwrap(),
                limit_price: Price::new(100 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(PRICE_SCALE).unwrap(),
                client_order_id: [46; 16],
                max_fee_bps: 10,
                nonce: 0,
                valid_from_height: 1,
                expires_at_height: 100,
            },
            signature: crate::order::Signature64([0; 64]),
        };
        let mut accounts = BTreeMap::from([(trader.0, account(i128::from(50 * PRICE_SCALE), 1))]);
        let mut open_position = position(1);
        open_position.position = Position {
            size: i64::try_from(PRICE_SCALE).unwrap(),
            entry_price: 100 * PRICE_SCALE,
            last_funding_index: 0,
        };
        let mut positions = BTreeMap::from([(trader.0, open_position)]);
        // The new order asks for the proof floor (10x), but the existing
        // position is committed at 1x. Increasing it must retain the stricter
        // carried requirement instead of silently weakening the position.
        let selected = BTreeMap::from([(signed.order_id(), 1_000)]);
        let mut position_margins = BTreeMap::from([(trader.0, 10_000)]);
        let mut increased = BTreeMap::new();
        let result = apply_trader_fill_with_policy(
            &signed,
            crate::order::Fill {
                match_id: [47; 32],
                trader,
                side: Side::Buy,
                price: Price::new(100 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(PRICE_SCALE).unwrap(),
                fee: Amount(0),
            },
            &mut accounts,
            &mut positions,
            Price::new(100 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
            Some(&selected),
            &mut position_margins,
            &mut increased,
        );
        assert_eq!(result, Err(ProtocolError::InsufficientCollateral));
    }
}
