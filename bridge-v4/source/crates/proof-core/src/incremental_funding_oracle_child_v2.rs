//! Recursive child statement for authenticated oracle inputs and funding.
//!
//! Unlike PublicValuesV5, this statement publishes the exact recursively
//! authenticated mark used in the funding-index delta. It also verifies the
//! complete deterministic `FundingStateV2` accumulator step. A host-supplied
//! mark, range, rate, or funding root therefore cannot cross this boundary.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    advance_exact_funding_index_v2, advance_funding_timestamped_v2, FrozenConfigurationV2,
    FundingStateV2, Hash32, IncrementalSuccessorConfigurationV2, MarketId, OracleMode, OrderFlags,
    Price, ProtocolError, SuccessorCentralMatcherConfigV2, SuccessorCentralMatcherReceiptV2,
    SuccessorMatcherExecutionReceiptV2, SuccessorMatcherExecutionRelationV2,
    SuccessorSignedLimitOrderV2, SuccessorTradeMatchV2, TimeInForce,
    TimestampedFundingObservationV2, XOnlyKey, MAX_TRANSITION_ACTIONS,
};
use ecx_truthcoin_proof::{
    ConsensusProofVerifier, DenyAllConsensusProofs, ParentChainContextV1, TruthcoinConsensusProofV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::funding_parent_chain_v2::verify_successor_funding_parent_chain_v2;
use crate::{
    incremental_successor_forced_reduce_only_ioc_root_v2, verify_authenticated_funding_source_v2,
    ConversionLegConsensusProofV2, FundingParentChainErrorV2, FundingParentChainWitnessV2,
    ProofErrorV2,
};

pub const INCREMENTAL_FUNDING_ORACLE_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 5;
pub const INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (13 * 32) + (12 * 8) + (4 * 16) + 4 + 1;
const MAX_FUNDING_CONFIGURATION_BINCODE_BYTES_V2: usize = 4 * 1024;
const MAX_FUNDING_TRUTHCOIN_PROOF_BINCODE_BYTES_V2: usize = 4 * 1024;
const MAX_FUNDING_CONVERSION_PROOF_BINCODE_BYTES_V2: usize = 1024;
const MAX_FUNDING_STATE_BINCODE_BYTES_V2: usize = 2 * 1024;
const MAX_FUNDING_ORDINARY_EXECUTION_BINCODE_BYTES_V2: usize = 4 * 1024;
const MAX_FUNDING_SIGNED_ORDER_BINCODE_BYTES_V2: usize = 1024;
const MAX_FUNDING_FORCED_EXECUTION_BINCODE_BYTES_V2: usize = 3 * 1024;
const MAX_FUNDING_EXECUTION_RECEIPT_BINCODE_BYTES_V2: usize = 2 * 1024;
const MAX_FUNDING_PARENT_CHAIN_BINCODE_BYTES_V2: usize = 2 * 1024;
const MAX_FUNDING_LIQUIDATION_BINCODE_BYTES_V2: usize = 256;
const MAX_FUNDING_FIXED_WRAPPER_BYTES_V2: usize = 4 * 1024;
pub const INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2: usize =
    MAX_FUNDING_FIXED_WRAPPER_BYTES_V2
        + MAX_FUNDING_CONFIGURATION_BINCODE_BYTES_V2
        + MAX_FUNDING_TRUTHCOIN_PROOF_BINCODE_BYTES_V2
        + (2 * MAX_FUNDING_CONVERSION_PROOF_BINCODE_BYTES_V2)
        + (2 * MAX_FUNDING_STATE_BINCODE_BYTES_V2)
        + (MAX_TRANSITION_ACTIONS as usize * MAX_FUNDING_ORDINARY_EXECUTION_BINCODE_BYTES_V2)
        + (MAX_TRANSITION_ACTIONS as usize * MAX_FUNDING_SIGNED_ORDER_BINCODE_BYTES_V2)
        + (MAX_TRANSITION_ACTIONS as usize * MAX_FUNDING_FORCED_EXECUTION_BINCODE_BYTES_V2)
        + (MAX_TRANSITION_ACTIONS as usize * MAX_FUNDING_EXECUTION_RECEIPT_BINCODE_BYTES_V2)
        + MAX_FUNDING_PARENT_CHAIN_BINCODE_BYTES_V2
        + (MAX_TRANSITION_ACTIONS as usize * MAX_FUNDING_LIQUIDATION_BINCODE_BYTES_V2);
pub const MAX_INCREMENTAL_FUNDING_ORACLE_CHILD_INPUT_BYTES_V2: usize = 700 * 1024;
const _: () = assert!(
    INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_FUNDING_ORACLE_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalFundingOrdinaryExecutionV2 {
    pub maker: SuccessorSignedLimitOrderV2,
    pub taker: SuccessorSignedLimitOrderV2,
    pub trade: SuccessorTradeMatchV2,
    pub taker_admission: SuccessorCentralMatcherReceiptV2,
}

pub const INCREMENTAL_FORCED_IOC_TAKER_SEQUENCE_V2: u128 = u128::MAX;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalForcedIocExecutionV2 {
    pub maker: SuccessorSignedLimitOrderV2,
    pub taker: SuccessorSignedLimitOrderV2,
    pub trade: SuccessorTradeMatchV2,
}

impl CanonicalEncode for IncrementalForcedIocExecutionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.maker.encode_to(out);
        self.taker.encode_to(out);
        self.trade.encode_to(out);
    }
}

pub fn incremental_forced_ioc_execution_root_v2(
    executions: &[IncrementalForcedIocExecutionV2],
) -> Result<Hash32, ProtocolError> {
    let count = u16::try_from(executions.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    for execution in executions {
        execution.encode_to(&mut bytes);
    }
    Ok(tagged_hash(
        b"ECX/incremental-forced-ioc-executions/v1",
        &bytes,
    ))
}

pub fn validate_incremental_forced_ioc_batch_v2(
    chain_id: Hash32,
    market: MarketId,
    sidechain_height: u64,
    iocs: &[SuccessorSignedLimitOrderV2],
    executions: &[IncrementalForcedIocExecutionV2],
) -> Result<(Hash32, Hash32), ProtocolError> {
    if iocs.len() > MAX_TRANSITION_ACTIONS as usize
        || executions.len() > MAX_TRANSITION_ACTIONS as usize
    {
        return Err(ProtocolError::InvalidForcedAction);
    }
    let mut positions = BTreeMap::new();
    for (index, ioc) in iocs.iter().enumerate() {
        ioc.verify()?;
        if ioc.order.chain_id != chain_id
            || ioc.order.market != market
            || ioc.order.time_in_force != TimeInForce::ImmediateOrCancel
            || !ioc.order.flags.contains(OrderFlags::REDUCE_ONLY)
            || ioc.order.flags.contains(OrderFlags::POST_ONLY)
            || positions.insert(ioc.order_id(), index).is_some()
        {
            return Err(ProtocolError::InvalidForcedAction);
        }
    }
    let mut filled = BTreeMap::<Hash32, u64>::new();
    let mut last_position = None;
    let mut distinct_trades = BTreeSet::new();
    for execution in executions {
        execution
            .trade
            .validate_orders(&execution.maker, &execution.taker, sidechain_height)?;
        let order_id = execution.taker.order_id();
        let position = *positions
            .get(&order_id)
            .ok_or(ProtocolError::InvalidForcedAction)?;
        if execution.taker != iocs[position]
            || execution.trade.sequence != INCREMENTAL_FORCED_IOC_TAKER_SEQUENCE_V2
            || last_position.is_some_and(|previous| previous > position)
            || !distinct_trades.insert(execution.trade.match_id())
        {
            return Err(ProtocolError::InvalidForcedAction);
        }
        last_position = Some(position);
        let total = filled
            .entry(order_id)
            .or_default()
            .checked_add(execution.trade.quantity.get())
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if total > execution.taker.order.quantity.get() {
            return Err(ProtocolError::ExcessFill);
        }
        *filled.get_mut(&order_id).expect("entry inserted") = total;
    }
    Ok((
        incremental_successor_forced_reduce_only_ioc_root_v2(iocs),
        incremental_forced_ioc_execution_root_v2(executions)?,
    ))
}

impl CanonicalEncode for IncrementalFundingOrdinaryExecutionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.maker.encode_to(out);
        self.taker.encode_to(out);
        self.trade.encode_to(out);
        self.taker_admission.encode_to(out);
    }
}

pub fn incremental_ordinary_execution_root_v2(
    executions: &[IncrementalFundingOrdinaryExecutionV2],
) -> Result<Hash32, IncrementalFundingOracleChildErrorV2> {
    let count = u16::try_from(executions.len())
        .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    for execution in executions {
        execution.encode_to(&mut bytes);
    }
    Ok(tagged_hash(
        b"ECX/incremental-ordinary-executions/v1",
        &bytes,
    ))
}

/// Permissionless liquidation observation cross-bound to the order child.
/// Its target and maker identity prevent an ordinary fill from being relabelled
/// as a liquidation solely to manipulate funding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalLiquidationObservationV2 {
    pub target: XOnlyKey,
    pub maker_order_id: Hash32,
    pub price_atoms: u64,
    pub quantity_atoms: u64,
}

impl CanonicalEncode for IncrementalLiquidationObservationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.target.encode_to(out);
        out.extend_from_slice(&self.maker_order_id);
        out.extend_from_slice(&self.price_atoms.to_be_bytes());
        out.extend_from_slice(&self.quantity_atoms.to_be_bytes());
    }
}

pub fn incremental_liquidation_observation_root_v2(
    observations: &[IncrementalLiquidationObservationV2],
) -> Result<Hash32, IncrementalFundingOracleChildErrorV2> {
    let count = u16::try_from(observations.len())
        .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    for observation in observations {
        if observation.maker_order_id == [0; 32]
            || observation.price_atoms == 0
            || observation.quantity_atoms == 0
        {
            return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
        }
        observation.encode_to(&mut bytes);
    }
    Ok(tagged_hash(
        b"ECX/incremental-liquidation-observations/v1",
        &bytes,
    ))
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn validate_observation_counts_v2(
    ordinary_execution_count: usize,
    execution_receipt_count: usize,
    forced_ioc_count: usize,
    forced_ioc_execution_count: usize,
    liquidation_count: usize,
) -> Result<(), IncrementalFundingOracleChildErrorV2> {
    let maximum = MAX_TRANSITION_ACTIONS as usize;
    if ordinary_execution_count > maximum
        || execution_receipt_count > maximum
        || forced_ioc_count > maximum
        || forced_ioc_execution_count > maximum
        || liquidation_count > maximum
        || ordinary_execution_count
            .checked_add(forced_ioc_execution_count)
            .and_then(|count| count.checked_add(liquidation_count))
            .is_none_or(|count| count > maximum)
    {
        return Err(IncrementalFundingOracleChildErrorV2::InputTooLarge);
    }
    Ok(())
}

fn fixed_bincode_size_v2<T: Serialize>(
    value: &T,
) -> Result<usize, IncrementalFundingOracleChildErrorV2> {
    usize::try_from(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialized_size(value)
            .map_err(|_| IncrementalFundingOracleChildErrorV2::InputEncoding)?,
    )
    .map_err(|_| IncrementalFundingOracleChildErrorV2::InputTooLarge)
}

fn require_component_size_v2<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<(), IncrementalFundingOracleChildErrorV2> {
    if fixed_bincode_size_v2(value)? > maximum {
        return Err(IncrementalFundingOracleChildErrorV2::InputTooLarge);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalFundingOracleChildInputV2 {
    pub version: u8,
    pub successor_configuration: IncrementalSuccessorConfigurationV2,
    pub successor_matcher_configuration: SuccessorCentralMatcherConfigV2,
    pub configuration: FrozenConfigurationV2,
    pub parent: ParentChainContextV1,
    pub truthcoin_consensus_proof: TruthcoinConsensusProofV1,
    pub ecx_btc_conversion_proof: ConversionLegConsensusProofV2,
    pub usdd_usd_conversion_proof: ConversionLegConsensusProofV2,
    pub previous_funding: FundingStateV2,
    pub next_funding: FundingStateV2,
    pub previous_match_sequence: u128,
    pub next_match_sequence: u128,
    pub ordinary_executions: Vec<IncrementalFundingOrdinaryExecutionV2>,
    pub forced_iocs: Vec<SuccessorSignedLimitOrderV2>,
    pub forced_ioc_executions: Vec<IncrementalForcedIocExecutionV2>,
    pub execution_receipts: Vec<SuccessorMatcherExecutionReceiptV2>,
    pub funding_parent_chain: FundingParentChainWitnessV2,
    pub liquidation_observations: Vec<IncrementalLiquidationObservationV2>,
    pub open_interest_notional_before_fills: u128,
    pub previous_global_funding_index_numerator: i128,
    pub next_global_funding_index_numerator: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalFundingOracleChildPublicValuesV2 {
    pub successor_configuration_hash: Hash32,
    pub v18_configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub parent_block_hash: Hash32,
    pub truthcoin_public_values_hash: Hash32,
    pub conversion_legs_commitment: Hash32,
    pub previous_funding_root: Hash32,
    pub next_funding_root: Hash32,
    pub matcher_execution_receipt_batch_root: Hash32,
    pub ordinary_execution_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub mark_price_atoms: u64,
    pub liquidation_low_atoms: u64,
    pub liquidation_high_atoms: u64,
    pub authenticated_min_price_atoms: u64,
    pub authenticated_max_price_atoms: u64,
    pub oracle_valid_through_mtp: u64,
    pub observation_count: u64,
    pub previous_match_sequence: u128,
    pub next_match_sequence: u128,
    pub liquidation_observation_count: u64,
    pub forced_ioc_count: u64,
    pub forced_ioc_execution_count: u64,
    pub previous_global_funding_index_numerator: i128,
    pub next_global_funding_index_numerator: i128,
    pub funding_rate_ppm: i32,
    pub oracle_mode: OracleMode,
}

impl IncrementalFundingOracleChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for value in [
            self.successor_configuration_hash,
            self.v18_configuration_hash,
            self.chain_id,
            self.parent_block_hash,
            self.truthcoin_public_values_hash,
            self.conversion_legs_commitment,
            self.previous_funding_root,
            self.next_funding_root,
            self.matcher_execution_receipt_batch_root,
            self.ordinary_execution_root,
            self.forced_ioc_root,
            self.forced_ioc_execution_root,
            self.liquidation_observation_root,
        ] {
            out.extend_from_slice(&value);
        }
        for value in [
            self.parent_height,
            self.parent_mtp,
            self.mark_price_atoms,
            self.liquidation_low_atoms,
            self.liquidation_high_atoms,
            self.authenticated_min_price_atoms,
            self.authenticated_max_price_atoms,
            self.oracle_valid_through_mtp,
            self.observation_count,
            self.liquidation_observation_count,
            self.forced_ioc_count,
            self.forced_ioc_execution_count,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.previous_match_sequence.to_be_bytes());
        out.extend_from_slice(&self.next_match_sequence.to_be_bytes());
        out.extend_from_slice(&self.previous_global_funding_index_numerator.to_be_bytes());
        out.extend_from_slice(&self.next_global_funding_index_numerator.to_be_bytes());
        out.extend_from_slice(&self.funding_rate_ppm.to_be_bytes());
        out.push(self.oracle_mode as u8);
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalFundingOracleChildProjectionV2 {
    pub successor_configuration_hash: Hash32,
    pub v18_configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub parent_block_hash: Hash32,
    pub truthcoin_public_values_hash: Hash32,
    pub previous_funding_root: Hash32,
    pub next_funding_root: Hash32,
    pub matcher_execution_receipt_batch_root: Hash32,
    pub ordinary_execution_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub mark_price_atoms: u64,
    pub authenticated_min_price_atoms: u64,
    pub authenticated_max_price_atoms: u64,
    pub oracle_valid_through_mtp: u64,
    pub previous_match_sequence: u128,
    pub next_match_sequence: u128,
    pub liquidation_observation_count: u64,
    pub forced_ioc_count: u64,
    pub forced_ioc_execution_count: u64,
    pub previous_global_funding_index_numerator: i128,
    pub next_global_funding_index_numerator: i128,
    pub funding_rate_ppm: i32,
    pub oracle_mode: OracleMode,
}

pub fn decode_incremental_funding_oracle_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalFundingOracleChildProjectionV2, IncrementalFundingOracleChildErrorV2> {
    if bytes.len() != INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalFundingOracleChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalFundingOracleChildErrorV2> {
        let start = 4 + (index * 32);
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalFundingOracleChildErrorV2::UnsupportedVersion)
    };
    let value = |index: usize| -> Result<u64, IncrementalFundingOracleChildErrorV2> {
        let start = 4 + (13 * 32) + (index * 8);
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalFundingOracleChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let signed = |index: usize| -> Result<i128, IncrementalFundingOracleChildErrorV2> {
        let start = 4 + (13 * 32) + (12 * 8) + (index * 16);
        Ok(i128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalFundingOracleChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let unsigned = |index: usize| -> Result<u128, IncrementalFundingOracleChildErrorV2> {
        let start = 4 + (13 * 32) + (12 * 8) + (index * 16);
        Ok(u128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalFundingOracleChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let rate_start = 4 + (13 * 32) + (12 * 8) + (4 * 16);
    Ok(IncrementalFundingOracleChildProjectionV2 {
        successor_configuration_hash: hash(0)?,
        v18_configuration_hash: hash(1)?,
        chain_id: hash(2)?,
        parent_block_hash: hash(3)?,
        truthcoin_public_values_hash: hash(4)?,
        previous_funding_root: hash(6)?,
        next_funding_root: hash(7)?,
        matcher_execution_receipt_batch_root: hash(8)?,
        ordinary_execution_root: hash(9)?,
        forced_ioc_root: hash(10)?,
        forced_ioc_execution_root: hash(11)?,
        liquidation_observation_root: hash(12)?,
        parent_height: value(0)?,
        parent_mtp: value(1)?,
        mark_price_atoms: value(2)?,
        authenticated_min_price_atoms: value(5)?,
        authenticated_max_price_atoms: value(6)?,
        oracle_valid_through_mtp: value(7)?,
        previous_match_sequence: unsigned(0)?,
        next_match_sequence: unsigned(1)?,
        liquidation_observation_count: value(9)?,
        forced_ioc_count: value(10)?,
        forced_ioc_execution_count: value(11)?,
        previous_global_funding_index_numerator: signed(2)?,
        next_global_funding_index_numerator: signed(3)?,
        funding_rate_ppm: i32::from_be_bytes(
            bytes[rate_start..rate_start + 4]
                .try_into()
                .map_err(|_| IncrementalFundingOracleChildErrorV2::UnsupportedVersion)?,
        ),
        oracle_mode: match bytes[rate_start + 4] {
            0 => OracleMode::Normal,
            1 => OracleMode::ReduceOnly,
            2 => OracleMode::Disputed,
            3 => OracleMode::Halt,
            _ => return Err(IncrementalFundingOracleChildErrorV2::UnsupportedVersion),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalFundingOracleChildErrorV2 {
    #[error("unsupported incremental funding/oracle child version")]
    UnsupportedVersion,
    #[error("invalid incremental funding/oracle child binding")]
    InvalidBinding,
    #[error("incremental funding/oracle child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental funding/oracle child input encoding failed")]
    InputEncoding,
    #[error("funding/oracle recursive source authentication rejected: {0}")]
    Source(#[from] ProofErrorV2),
    #[error("funding accumulator rejected: {0}")]
    Funding(#[from] ProtocolError),
    #[error("funding parent-chain authentication rejected: {0}")]
    FundingParentChain(#[from] FundingParentChainErrorV2),
}

pub fn execute_incremental_funding_oracle_child_v2(
    input: &IncrementalFundingOracleChildInputV2,
) -> Result<IncrementalFundingOracleChildPublicValuesV2, IncrementalFundingOracleChildErrorV2> {
    execute_incremental_funding_oracle_child_v2_with_consensus_verifier(
        input,
        &DenyAllConsensusProofs,
    )
}

pub fn execute_incremental_funding_oracle_child_v2_with_consensus_verifier<
    V: ConsensusProofVerifier,
>(
    input: &IncrementalFundingOracleChildInputV2,
    verifier: &V,
) -> Result<IncrementalFundingOracleChildPublicValuesV2, IncrementalFundingOracleChildErrorV2> {
    if input.version != INCREMENTAL_FUNDING_ORACLE_CHILD_VERSION_V2 {
        return Err(IncrementalFundingOracleChildErrorV2::UnsupportedVersion);
    }
    input.successor_configuration.validate()?;
    input.successor_matcher_configuration.validate()?;
    input.configuration.validate()?;
    if input
        .successor_configuration
        .successor_matcher_configuration_hash
        != input.successor_matcher_configuration.digest()
        || input.successor_configuration.chain_id != input.configuration.base.chain_id
        || input.successor_configuration.market != input.configuration.base.market
        || input.parent.block_hash == [0; 32]
        || input.parent.height == 0
        || input.parent.median_time_past == 0
    {
        return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
    }
    validate_observation_counts_v2(
        input.ordinary_executions.len(),
        input.execution_receipts.len(),
        input.forced_iocs.len(),
        input.forced_ioc_executions.len(),
        input.liquidation_observations.len(),
    )?;
    let marker_bytes = usize::try_from(input.configuration.recursive_proof_marker_bytes)
        .map_err(|_| IncrementalFundingOracleChildErrorV2::InputTooLarge)?;
    if marker_bytes != 32
        || input.truthcoin_consensus_proof.proof.len() != marker_bytes
        || input.ecx_btc_conversion_proof.proof.len() != marker_bytes
        || input.usdd_usd_conversion_proof.proof.len() != marker_bytes
    {
        return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
    }
    require_component_size_v2(
        &input.configuration,
        MAX_FUNDING_CONFIGURATION_BINCODE_BYTES_V2,
    )?;
    require_component_size_v2(
        &input.truthcoin_consensus_proof,
        MAX_FUNDING_TRUTHCOIN_PROOF_BINCODE_BYTES_V2,
    )?;
    for proof in [
        &input.ecx_btc_conversion_proof,
        &input.usdd_usd_conversion_proof,
    ] {
        require_component_size_v2(proof, MAX_FUNDING_CONVERSION_PROOF_BINCODE_BYTES_V2)?;
    }
    for state in [&input.previous_funding, &input.next_funding] {
        require_component_size_v2(state, MAX_FUNDING_STATE_BINCODE_BYTES_V2)?;
    }
    for execution in &input.ordinary_executions {
        require_component_size_v2(execution, MAX_FUNDING_ORDINARY_EXECUTION_BINCODE_BYTES_V2)?;
    }
    for order in &input.forced_iocs {
        require_component_size_v2(order, MAX_FUNDING_SIGNED_ORDER_BINCODE_BYTES_V2)?;
    }
    for execution in &input.forced_ioc_executions {
        require_component_size_v2(execution, MAX_FUNDING_FORCED_EXECUTION_BINCODE_BYTES_V2)?;
    }
    for receipt in &input.execution_receipts {
        require_component_size_v2(receipt, MAX_FUNDING_EXECUTION_RECEIPT_BINCODE_BYTES_V2)?;
    }
    require_component_size_v2(
        &input.funding_parent_chain,
        MAX_FUNDING_PARENT_CHAIN_BINCODE_BYTES_V2,
    )?;
    for liquidation in &input.liquidation_observations {
        require_component_size_v2(liquidation, MAX_FUNDING_LIQUIDATION_BINCODE_BYTES_V2)?;
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalFundingOracleChildErrorV2::InputEncoding)?;
    if encoded.len() > INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2 {
        return Err(IncrementalFundingOracleChildErrorV2::InputTooLarge);
    }
    let source = verify_authenticated_funding_source_v2(
        &input.configuration,
        input.parent,
        &input.truthcoin_consensus_proof,
        &input.ecx_btc_conversion_proof,
        &input.usdd_usd_conversion_proof,
        verifier,
    )?;
    let relations = input
        .ordinary_executions
        .iter()
        .map(|execution| SuccessorMatcherExecutionRelationV2 {
            maker: &execution.maker,
            taker: &execution.taker,
            trade: &execution.trade,
            taker_admission: &execution.taker_admission,
        })
        .collect::<Vec<_>>();
    let (matcher_execution_receipt_batch_root, next_match_sequence) =
        ecx_protocol_core::verify_successor_matcher_execution_receipt_batch_v2(
            &input.successor_matcher_configuration,
            input.configuration.base.chain_id,
            input.previous_match_sequence,
            &relations,
            &input.execution_receipts,
        )?;
    if next_match_sequence != input.next_match_sequence {
        return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
    }
    let ordinary_execution_root =
        incremental_ordinary_execution_root_v2(&input.ordinary_executions)?;
    let (forced_ioc_root, forced_ioc_execution_root) = validate_incremental_forced_ioc_batch_v2(
        input.configuration.base.chain_id,
        input.configuration.base.market,
        input.parent.height,
        &input.forced_iocs,
        &input.forced_ioc_executions,
    )?;
    verify_successor_funding_parent_chain_v2(
        &input.funding_parent_chain,
        input.parent.block_hash,
        input.parent.height,
        input.parent.median_time_past,
        &input.execution_receipts,
        input
            .configuration
            .matcher_execution_inclusion_parent_blocks,
    )?;
    let mut observations = input
        .ordinary_executions
        .iter()
        .map(|execution| {
            TimestampedFundingObservationV2::new(
                execution.trade.price,
                execution.trade.quantity,
                input.parent.median_time_past,
            )
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    for execution in &input.forced_ioc_executions {
        observations.push(TimestampedFundingObservationV2::new(
            execution.trade.price,
            execution.trade.quantity,
            input.parent.median_time_past,
        )?);
    }
    let liquidation_observation_root =
        incremental_liquidation_observation_root_v2(&input.liquidation_observations)?;
    for liquidation in &input.liquidation_observations {
        observations.push(TimestampedFundingObservationV2::new(
            Price::new(liquidation.price_atoms)?,
            ecx_protocol_core::Quantity::new(liquidation.quantity_atoms)?,
            input.parent.median_time_past,
        )?);
    }
    let (next_funding, funding_rate_ppm) = advance_funding_timestamped_v2(
        &input.previous_funding,
        input.parent.median_time_past,
        Price::new(source.mark_price_atoms)?,
        Price::new(source.liquidation_low_atoms)?,
        Price::new(source.liquidation_high_atoms)?,
        source.oracle_valid_through_mtp,
        &observations,
        input.open_interest_notional_before_fills,
    )?;
    if next_funding != input.next_funding
        || input.previous_funding.last_parent_mtp > input.parent.median_time_past
    {
        return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
    }
    let expected_index = advance_exact_funding_index_v2(
        input.previous_global_funding_index_numerator,
        source.mark_price_atoms,
        funding_rate_ppm,
    )?;
    if input.next_global_funding_index_numerator != expected_index {
        return Err(IncrementalFundingOracleChildErrorV2::InvalidBinding);
    }
    Ok(IncrementalFundingOracleChildPublicValuesV2 {
        successor_configuration_hash: input.successor_configuration.digest()?,
        v18_configuration_hash: input.configuration.digest(),
        chain_id: input.configuration.base.chain_id,
        parent_block_hash: input.parent.block_hash,
        truthcoin_public_values_hash: source.truthcoin_public_values_hash,
        conversion_legs_commitment: source.conversion_legs_commitment,
        previous_funding_root: input.previous_funding.root(),
        next_funding_root: input.next_funding.root(),
        matcher_execution_receipt_batch_root,
        ordinary_execution_root,
        forced_ioc_root,
        forced_ioc_execution_root,
        liquidation_observation_root,
        parent_height: input.parent.height,
        parent_mtp: input.parent.median_time_past,
        mark_price_atoms: source.mark_price_atoms,
        liquidation_low_atoms: source.liquidation_low_atoms,
        liquidation_high_atoms: source.liquidation_high_atoms,
        authenticated_min_price_atoms: source.authenticated_min_price_atoms,
        authenticated_max_price_atoms: source.authenticated_max_price_atoms,
        oracle_valid_through_mtp: source.oracle_valid_through_mtp,
        observation_count: u64::try_from(observations.len())
            .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?,
        previous_match_sequence: input.previous_match_sequence,
        next_match_sequence: input.next_match_sequence,
        liquidation_observation_count: u64::try_from(input.liquidation_observations.len())
            .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?,
        forced_ioc_count: u64::try_from(input.forced_iocs.len())
            .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?,
        forced_ioc_execution_count: u64::try_from(input.forced_ioc_executions.len())
            .map_err(|_| IncrementalFundingOracleChildErrorV2::InvalidBinding)?,
        previous_global_funding_index_numerator: input.previous_global_funding_index_numerator,
        next_global_funding_index_numerator: input.next_global_funding_index_numerator,
        funding_rate_ppm,
        oracle_mode: source.oracle_mode,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        Amount, Quantity, Side, SuccessorLimitOrderV2, SuccessorSignedLimitOrderV2,
        SuccessorTradeMatchV2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;

    fn signed_order(secret_byte: u8, side: Side, forced_ioc: bool) -> SuccessorSignedLimitOrderV2 {
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: [0x11; 32],
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader: XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize()),
                side,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                time_in_force: if forced_ioc {
                    TimeInForce::ImmediateOrCancel
                } else {
                    TimeInForce::GoodTilHeight
                },
                flags: if forced_ioc {
                    OrderFlags::REDUCE_ONLY
                } else {
                    OrderFlags::NONE
                },
                client_order_id: [secret_byte; 16],
                max_fee_bps: 100,
                nonce: (1u128 << 96) + u128::from(secret_byte),
                valid_from_height: 0,
                expires_at_height: 100,
            },
            &secret,
        )
        .unwrap()
    }

    #[test]
    fn funding_oracle_projection_rejects_truncation_and_preserves_signed_index() {
        let values = IncrementalFundingOracleChildPublicValuesV2 {
            successor_configuration_hash: [1; 32],
            v18_configuration_hash: [2; 32],
            chain_id: [3; 32],
            parent_block_hash: [4; 32],
            truthcoin_public_values_hash: [5; 32],
            conversion_legs_commitment: [6; 32],
            previous_funding_root: [7; 32],
            next_funding_root: [8; 32],
            matcher_execution_receipt_batch_root: [9; 32],
            ordinary_execution_root: [11; 32],
            forced_ioc_root: [12; 32],
            forced_ioc_execution_root: [13; 32],
            liquidation_observation_root: [10; 32],
            parent_height: 9,
            parent_mtp: 10,
            mark_price_atoms: 11,
            liquidation_low_atoms: 12,
            liquidation_high_atoms: 13,
            authenticated_min_price_atoms: 14,
            authenticated_max_price_atoms: 15,
            oracle_valid_through_mtp: 16,
            observation_count: 17,
            previous_match_sequence: 18,
            next_match_sequence: 19,
            liquidation_observation_count: 2,
            forced_ioc_count: 3,
            forced_ioc_execution_count: 4,
            previous_global_funding_index_numerator: -20,
            next_global_funding_index_numerator: 21,
            funding_rate_ppm: -22,
            oracle_mode: OracleMode::Normal,
        };
        let encoded = values.encode();
        let projection = decode_incremental_funding_oracle_child_projection_v2(&encoded).unwrap();
        assert_eq!(projection.mark_price_atoms, 11);
        assert_eq!(projection.previous_match_sequence, 18);
        assert_eq!(projection.next_match_sequence, 19);
        assert_eq!(projection.forced_ioc_count, 3);
        assert_eq!(projection.forced_ioc_execution_count, 4);
        assert_eq!(projection.previous_global_funding_index_numerator, -20);
        assert_eq!(projection.funding_rate_ppm, -22);
        assert!(decode_incremental_funding_oracle_child_projection_v2(
            &encoded[..encoded.len() - 1]
        )
        .is_err());
    }

    #[test]
    fn matcher_receipts_and_funding_observations_are_transition_bounded() {
        assert!(validate_observation_counts_v2(64, 64, 0, 0, 0).is_ok());
        assert!(validate_observation_counts_v2(16, 16, 16, 16, 32).is_ok());
        assert_eq!(
            validate_observation_counts_v2(65, 65, 0, 0, 0).unwrap_err(),
            IncrementalFundingOracleChildErrorV2::InputTooLarge
        );
        assert_eq!(
            validate_observation_counts_v2(33, 33, 0, 1, 31).unwrap_err(),
            IncrementalFundingOracleChildErrorV2::InputTooLarge
        );
    }

    #[test]
    fn funding_oracle_child_has_enforced_structural_encoding_ceiling() {
        assert_eq!(
            INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2,
            692_224
        );
        let order = signed_order(7, Side::Sell, false);
        assert!(
            fixed_bincode_size_v2(&order).unwrap() <= MAX_FUNDING_SIGNED_ORDER_BINCODE_BYTES_V2
        );
        let liquidation = IncrementalLiquidationObservationV2 {
            target: order.order.trader,
            maker_order_id: order.order_id(),
            price_atoms: u64::MAX,
            quantity_atoms: u64::MAX,
        };
        assert!(
            fixed_bincode_size_v2(&liquidation).unwrap()
                <= MAX_FUNDING_LIQUIDATION_BINCODE_BYTES_V2
        );
    }

    #[test]
    fn forced_ioc_batch_binds_signed_actions_exact_fills_and_zero_fill_expiry() {
        let maker = signed_order(7, Side::Sell, false);
        let taker = signed_order(8, Side::Buy, true);
        let execution = IncrementalForcedIocExecutionV2 {
            trade: SuccessorTradeMatchV2 {
                sequence: INCREMENTAL_FORCED_IOC_TAKER_SEQUENCE_V2,
                maker_order_id: maker.order_id(),
                taker_order_id: taker.order_id(),
                maker: maker.order.trader,
                taker: taker.order.trader,
                maker_side: Side::Sell,
                price: maker.order.limit_price,
                quantity: Quantity::new(10).unwrap(),
                maker_fee: Amount(0),
                taker_fee: Amount(1),
            },
            maker,
            taker: taker.clone(),
        };
        let roots = validate_incremental_forced_ioc_batch_v2(
            [0x11; 32],
            ecx_protocol_core::ECX_USDD_MARKET,
            7,
            std::slice::from_ref(&taker),
            std::slice::from_ref(&execution),
        )
        .unwrap();
        assert_eq!(
            roots.0,
            incremental_successor_forced_reduce_only_ioc_root_v2(std::slice::from_ref(&taker))
        );
        assert_eq!(
            roots.1,
            incremental_forced_ioc_execution_root_v2(std::slice::from_ref(&execution)).unwrap()
        );

        let mut wrong_sequence = execution;
        wrong_sequence.trade.sequence = 0;
        assert!(validate_incremental_forced_ioc_batch_v2(
            [0x11; 32],
            ecx_protocol_core::ECX_USDD_MARKET,
            7,
            std::slice::from_ref(&taker),
            &[wrong_sequence],
        )
        .is_err());

        assert!(validate_incremental_forced_ioc_batch_v2(
            [0x11; 32],
            ecx_protocol_core::ECX_USDD_MARKET,
            101,
            &[taker],
            &[],
        )
        .is_ok());
    }
}
