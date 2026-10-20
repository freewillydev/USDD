//! Consensus-shaped primitives for the ECX/USDD perpetual exchange.
//!
//! All hashes and state transitions in this crate are deterministic and use
//! fixed-width canonical encodings. The crate deliberately contains no network,
//! database, wall-clock, floating-point, random-number, or order-book scheduling
//! logic. That makes [`verify_transition`] suitable for reuse by a zkVM guest.

#![forbid(unsafe_code)]

pub mod availability;
pub mod bond;
pub mod bond_inbox_v2;
pub mod codec;
pub mod configuration;
pub mod configuration_v2;
pub mod deposit_inbox;
pub mod ecx_collateral;
pub mod ecx_cash_account_v1;
pub mod ecx_order_v1;
pub mod ecx_withdrawal_v1;
pub mod ecx_cancel_v1;
pub mod ecx_order_index_v1;
pub mod ecx_matcher_v1;
pub mod ecx_configuration_v1;
pub mod error;
pub mod execution_receipt_v2;
pub mod forced;
pub mod funding_v2;
pub mod hash;
pub mod incremental_activation_v2;
pub mod incremental_risk_extrema_v2;
pub mod incremental_state_v2;
pub mod incremental_successor_v2;
#[cfg(feature = "trader-archive")]
pub mod incremental_trader_archive_v2;
pub mod matcher_receipt;
pub mod merkle;
pub mod oracle;
pub mod order;
pub mod prediction_market;
pub mod queue;
pub mod risk;
pub mod risk_v2;
pub mod state;
pub mod state_v2;
pub mod successor_action_v2;
pub mod successor_bond_action_v2;
pub mod successor_bond_inbox_v2;
pub mod successor_bond_state_v2;
pub mod successor_forced_inbox_v2;
pub mod successor_matcher_v2;
pub mod transition;
pub mod transition_v2;
pub mod truthcoin_anchor;
pub mod truthcoin_authority_policy;
pub mod truthcoin_authority_journal;
pub mod types;
pub mod usdd_checkpoint;
pub mod withdrawal_anchor;

pub use availability::{
    AvailabilityConfigV1, AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD,
    AVAILABILITY_SCHEME_HASH_V1, MAX_AVAILABILITY_WITNESS_BYTES,
};
pub use bond::{
    apply_subscription, capital_mode_for, coverage_bps, credit_insurance_revenue,
    full_range_deficit, maximum_redeemable_share_atoms, nav_per_whole_share_usdd_atoms,
    negative_equity_deficit, plan_fifo_redemption, plan_redemption_cancellation,
    redemption_usdd_atoms, subscription_share_atoms, target_reserve_125, BondPublicStateV2,
    CapitalModeV2, RedemptionCancellationV2, RedemptionOutcomeV2, RedemptionQueueEntryV2,
    SubscriptionOutcomeV2, BOND_FIXED_SUPPLY_ATOMS, BOND_PROTOCOL_VERSION_V2,
    BOND_REDEMPTION_DELAY_PARENT_BLOCKS, BOND_SHARE_DECIMALS, BOND_SHARE_SCALE,
    BOND_TARGET_COVERAGE_BPS,
};
pub use bond_inbox_v2::{
    bond_inbox_aead_failure_plaintext_sentinel_v2,
    bond_inbox_authenticated_recovery_or_payload_failure_commitment_v2,
    bond_inbox_availability_bundle_root_v2, bond_inbox_custody_receipt_binding_digest_v2,
    bond_inbox_no_staging_source_authorization_commitment_v2, bond_inbox_outcome_genesis_root_v2,
    bond_inbox_outcome_next_root_v2, bond_inbox_recovered_plaintext_sha256_v2,
    bond_inbox_source_witness_sha256_v2, bond_inbox_staging_source_authorization_commitment_v2,
    canonical_bond_inbox_custody_receipts_v2, validate_bond_inbox_source_order_v2,
    verify_bond_inbox_entry_source_witness_v2, verify_bond_inbox_source_witness_commitments_v2,
    BondInboxActionKindV2, BondInboxAuthenticatedRecoveryOrPayloadFailureV2,
    BondInboxAvailablePayloadV2, BondInboxConsumedDispositionV2, BondInboxConsumedEvidenceV2,
    BondInboxConsumedOutcomeV2, BondInboxCustodyReceiptV2, BondInboxEntryV2, BondInboxLimitsV2,
    BondInboxMarkerV2, BondInboxProcessedDispositionV2, BondInboxProcessedOutcomeV2,
    BondInboxRecoveryFailureV2, BondInboxRejectionV2, BondInboxStateV2, BondInboxTransitionV2,
    BondInboxUserActionV2, BOND_INBOX_MARKER_LEN, BOND_INBOX_MARKER_MAGIC,
    BOND_INBOX_MARKER_VERSION, BOND_INBOX_MAX_CUSTODIANS_V2,
    BOND_INBOX_MIN_DISTINCT_CUSTODY_RECEIPTS_V2, MAX_BOND_INBOX_BUNDLE_BYTES_V2,
    MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2, MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
    MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2,
};
pub use configuration::{FrozenConfigurationV1, MAX_TRANSITION_ACTIONS};
pub use configuration_v2::{
    bond_inbox_redemption_staging_descriptor_commitment_v2,
    bond_inbox_redemption_staging_hidden_node_v2, BondInboxRedemptionStagingRendererInputV2,
    FrozenConfigurationV2, BOND_INBOX_INCLUSION_BLOCKS_V2,
    BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
    BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
    BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
    BOND_INBOX_REDEMPTION_STAGING_TREE_SHAPE_VERSION_V2,
    BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2, BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2,
    FORCED_INCLUSION_BLOCKS_V2, MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
    MAX_CONVERSION_LEG_PROOF_BYTES_V2, RECURSIVE_PROOF_MARKER_BYTES_V2,
};
pub use deposit_inbox::{
    DepositEventV1, DepositInboxStateV1, DepositInboxTransitionV1, DepositMarkerV1,
    DEPOSIT_MARKER_LEN, DEPOSIT_MARKER_MAGIC, DEPOSIT_MARKER_VERSION,
};
pub use error::ProtocolError;
pub use execution_receipt_v2::{
    matcher_execution_receipt_batch_root_v2, verify_matcher_execution_batch_v2,
    verify_matcher_execution_receipt_batch_v2, MatcherExecutionParentV2,
    MatcherExecutionReceiptBodyV2, MatcherExecutionReceiptV2, MatcherExecutionRelationV2,
    MatcherExecutionV2,
};
pub use forced::{
    ForcedActionEntryV1, ForcedActionV1, ForcedInboxOutcome, ForcedInboxStateV1,
    ForcedInboxTransitionV1, FORCED_ACTION_PAYLOAD_MAGIC, FORCED_ACTION_PAYLOAD_VERSION,
    MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1, MAX_COMBINED_SAME_DEADLINE_APPENDS_V1,
    MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1,
};
pub use funding_v2::{
    advance_funding_timestamped_v2, advance_funding_v2, FundingBucketV2, FundingObservationV2,
    FundingStateV2, TimestampedFundingObservationV2, FUNDING_BUCKET_COUNT, FUNDING_BUCKET_SECONDS,
    FUNDING_EPOCH_SECONDS, FUNDING_RATE_CAP_PPM,
};
pub use hash::{tagged_hash, Hash32};
pub use incremental_activation_v2::*;
pub use incremental_risk_extrema_v2::*;
pub use incremental_state_v2::*;
pub use incremental_successor_v2::*;
#[cfg(feature = "trader-archive")]
pub use incremental_trader_archive_v2::*;
pub use matcher_receipt::{
    central_matcher_receipt_batch_root, matcher_cancel_command_hash, matcher_order_command_hash,
    verify_central_matcher_receipt_chain, CentralMatcherConfigV1, CentralMatcherReceiptV1,
    MatcherCommandKind, MatcherReceiptBodyV1, MAX_FORCED_INCLUSION_BLOCKS,
};
pub use merkle::{KeyedCommitment, MerkleProof, MerkleTree};
pub use oracle::{
    derive_ecx_usdd_price, derive_hybrid_quote, lmsr_scalar_implied_price, HybridOracleConfigV1,
    HybridOracleQuoteV1, OracleMode, TruthcoinAnchorV1, TruthcoinAuthenticationConfigV1,
    TruthcoinLmsrSnapshotV1, MAX_TRUTHCOIN_PROOF_BYTES,
};
pub use order::{
    CancelOrder, Fill, LimitOrder, OrderFlags, OrderId, Side, Signature64, SignedCancelOrder,
    SignedLimitOrder, TimeInForce, TradeMatch,
};
pub use prediction_market::{
    apply_prediction_market_order_v1, execute_prediction_market_proof_v1,
    prediction_market_account_root_v1, BinaryOutcomeV1, PredictionMarketAccountV1,
    PredictionMarketConfigV1, PredictionMarketOrderV1, PredictionMarketProofInputV1,
    PredictionMarketPublicValuesV1, PredictionMarketSideV1, PredictionMarketStateV1,
    PredictionMarketTransitionV1, SignedPredictionMarketOrderV1,
    PREDICTION_MARKET_PUBLIC_VALUES_BYTES_V1, PREDICTION_MARKET_PUBLIC_VALUES_VERSION_V1,
    PREDICTION_MARKET_VERSION_V1, PROBABILITY_SCALE_PPB,
};
pub use queue::{DepositRequest, SignedWithdrawalRequest, WithdrawalRequest};
pub use risk::{
    apply_fill, equity, funding_payment, is_liquidatable, liquidation, required_margin,
    trading_fee, unrealized_pnl, FillOutcome, LiquidationResult, MarginKind, RiskParams,
};
pub use risk_v2::{
    creates_directional_risk, required_margin_bps_v2, validate_selected_margin_bps,
    OrderRiskCommitmentV2, ALLOWED_INITIAL_MARGIN_BPS_V2,
};
pub use state::{
    AccountLeaf, ExchangeState, OpenOrderLeaf, PositionLeaf, StateCommitment, StateRoots,
};
pub use state_v2::{ExchangeStateV2, PositionRiskLeafV2, StateCommitmentV2};
pub use successor_action_v2::{
    successor_withdrawal_batch_root_v2, SuccessorCancelOrderV2, SuccessorLimitOrderV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorSignedWithdrawalRequestV2,
    SuccessorTradeMatchV2, SuccessorWithdrawalRequestV2, SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2,
    SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2, SUCCESSOR_SIGNED_CANCEL_ORDER_ENCODED_LEN_V2,
    SUCCESSOR_SIGNED_LIMIT_ORDER_ENCODED_LEN_V2,
    SUCCESSOR_SIGNED_WITHDRAWAL_REQUEST_ENCODED_LEN_V2, SUCCESSOR_TRADE_MATCH_ENCODED_LEN_V2,
    SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2,
};
pub use successor_bond_action_v2::*;
pub use successor_bond_inbox_v2::*;
pub use successor_bond_state_v2::*;
pub use successor_forced_inbox_v2::{
    successor_forced_action_batch_root_v2, successor_forced_inbox_state_hash_v2,
    SuccessorForcedActionEntryV2, SuccessorForcedActionV2, SuccessorForcedInboxStateV2,
    SuccessorForcedInboxTransitionV2, SUCCESSOR_FORCED_ACTION_PAYLOAD_VERSION_V2,
};
pub use successor_matcher_v2::{
    successor_central_matcher_receipt_batch_root_v2, successor_matcher_cancel_command_hash_v2,
    successor_matcher_execution_receipt_batch_root_v2, successor_matcher_order_command_hash_v2,
    verify_successor_central_matcher_receipt_chain_v2,
    verify_successor_matcher_execution_receipt_batch_v2, SuccessorCentralMatcherConfigV2,
    SuccessorCentralMatcherReceiptV2, SuccessorMatcherCommandKindV2,
    SuccessorMatcherExecutionParentV2, SuccessorMatcherExecutionReceiptBodyV2,
    SuccessorMatcherExecutionReceiptV2, SuccessorMatcherExecutionRelationV2,
    SuccessorMatcherReceiptBodyV2,
};
pub use transition::{
    cancellation_batch_root, deposit_batch_root, deposit_event_batch_root, fill_batch_root,
    forced_action_batch_root, liquidation_batch_root, next_order_receipts_root,
    placement_batch_root, risk_params_hash, transition_batch_hash, transition_envelope_hash,
    transition_withdrawals, verify_transition, verify_transition_fees_to_insurance,
    withdrawal_batch_root, LiquidationMatchV1, MatchedOrderPair, OrderPlacement,
    TransitionEnvelopeV4, TransitionJournal, TransitionPublicInputs, TransitionWitness,
};
pub use transition_v2::{
    active_order_risk_root_v2, bond_action_root_v2, order_risk_root_v2, position_risk_root_v2,
    redemption_queue_has_capacity_v2, redemption_queue_root_v2, verify_transition_v2,
    BondSubscriptionV2, InsuranceRecapitalizationContributionV2, RedemptionCancellationV2Action,
    RedemptionEnqueueV2, RedemptionExecutionV2, SignedBondSubscriptionV2,
    SignedInsuranceRecapitalizationContributionV2, SignedRedemptionCancellationV2,
    SignedRedemptionEnqueueV2, TransitionJournalV2, TransitionPublicInputsV2, TransitionWitnessV2,
    TRANSITION_PROTOCOL_VERSION_V2,
};
pub use truthcoin_anchor::{
    truthcoin_anchor_configuration_hash, truthcoin_anchor_history_root,
    verify_truthcoin_anchor_successor, AnchorOutpointV1, TruthcoinAnchorDeploymentV1,
    TruthcoinAnchorStateV1, TruthcoinAnchorUpdateV1,
};
pub use types::{
    Amount, MarketId, Position, Price, Quantity, XOnlyKey, ECX_USDD_MARKET, PRICE_SCALE,
};
pub use usdd_checkpoint::{
    usdd_checkpoint_authority_configuration_hash, verify_usdd_checkpoint_successor,
    UsddCheckpointConfigV1, UsddCheckpointUpdateV1, UsddEthereumCheckpointV1,
    USDD_MAX_CHECKPOINT_AGE_SECONDS,
};
pub use withdrawal_anchor::{
    verify_child_withdrawal_state_commitment, AuthenticatedChildCheckpointV1,
    WithdrawalStateAnchorV1, BMM_SLOT, PXST_MARKER_LEN, PXST_MARKER_MAGIC,
};
pub mod genesis_v2;
