//! Recursive child statement for the authenticated price-time order index.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    is_incremental_trader_liquidatable_v2, verify_best_liquidation_maker_v2,
    verify_no_crossing_maker_v2, verify_order_operation_trader_projection_parts_v2,
    ChainedOrderIndexTranscriptV2, Hash32, IncrementalSuccessorConfigurationV2,
    OrderIndexOperationKindV2, OrderIndexRootV2, ProtocolError, SparseMerkleSumRootV2,
    SparseStateDomainV2, SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2,
    TraderStateBatchLeafUpdateV2, TraderStateReadBatchProofV2, XOnlyKey,
    MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2, MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    incremental_liquidation_observation_root_v2, incremental_ordinary_execution_root_v2,
    incremental_successor_forced_cancel_root_v2, incremental_trader_root_projection_v2,
    incremental_trader_update_leaf_projection_v2, validate_incremental_forced_ioc_batch_v2,
    IncrementalForcedIocExecutionV2, IncrementalFundingOrdinaryExecutionV2,
    IncrementalLiquidationObservationV2,
};

pub const INCREMENTAL_ORDER_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 6;
pub const INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (12 * 32) + 14;
/// The order child may need both the immediate-root order transcript and a
/// populated read-only trader frontier in the same transition. Reserve one
/// additional MiB for 64 typed openings/classifications and fixed framing.
pub const INCREMENTAL_ORDER_CHILD_REACHABLE_ENCODING_CEILING_V2: usize =
    MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2
        + MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2
        + (1024 * 1024);
pub const MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2: usize = 12 * 1024 * 1024;
const _: () = assert!(
    INCREMENTAL_ORDER_CHILD_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalOrderLiquidationV2 {
    /// Index of the exact PartialFill/RemoveFilled action in the immediate-root
    /// transcript. Prunes before this index are therefore authenticated.
    pub action_index: u16,
    pub target: XOnlyKey,
    pub quantity_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalOrderOrdinaryFillV2 {
    pub action_index: u16,
    pub execution: IncrementalFundingOrdinaryExecutionV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalForcedCancellationV2 {
    pub action_index: u16,
    pub cancellation: SuccessorSignedCancelOrderV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalOrderForcedIocFillV2 {
    pub action_index: u16,
    pub execution: IncrementalForcedIocExecutionV2,
}

/// Exact immediate-root boundary at which one forced IOC is complete. The
/// boundary is a count, so a zero-fill IOC may stop at the input root while a
/// filled IOC stops after its final authenticated maker action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalOrderForcedIocStopV2 {
    pub ioc_index: u16,
    pub stop_action_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalOrderChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub sidechain_height: u64,
    pub trader_updates: Vec<TraderStateBatchLeafUpdateV2>,
    pub previous_trader_root: SparseMerkleSumRootV2,
    pub previous_order_root: OrderIndexRootV2,
    pub next_order_root: OrderIndexRootV2,
    pub transcript: Option<ChainedOrderIndexTranscriptV2>,
    pub trader_reads: Option<TraderStateReadBatchProofV2>,
    pub liquidation_low_atoms: u64,
    pub liquidation_high_atoms: u64,
    pub global_funding_index_numerator: i128,
    pub ordinary_fills: Vec<IncrementalOrderOrdinaryFillV2>,
    pub liquidations: Vec<IncrementalOrderLiquidationV2>,
    pub forced_cancellations: Vec<IncrementalForcedCancellationV2>,
    pub forced_iocs: Vec<SuccessorSignedLimitOrderV2>,
    pub forced_ioc_fills: Vec<IncrementalOrderForcedIocFillV2>,
    pub forced_ioc_stops: Vec<IncrementalOrderForcedIocStopV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalOrderChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub previous_trader_root_projection: Hash32,
    pub previous_order_root_projection: Hash32,
    pub next_order_root_projection: Hash32,
    pub operation_transcript_root: Hash32,
    pub ordinary_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    pub forced_cancel_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub forced_ioc_completion_root: Hash32,
    pub operation_count: u16,
    pub insertion_count: u16,
    pub prune_count: u16,
    pub liquidation_count: u16,
    pub forced_cancel_count: u16,
    pub forced_ioc_count: u16,
    pub forced_ioc_execution_count: u16,
}

impl IncrementalOrderChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.trader_update_leaf_projection_root,
            self.previous_trader_root_projection,
            self.previous_order_root_projection,
            self.next_order_root_projection,
            self.operation_transcript_root,
            self.ordinary_execution_root,
            self.liquidation_observation_root,
            self.forced_cancel_root,
            self.forced_ioc_root,
            self.forced_ioc_execution_root,
            self.forced_ioc_completion_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.operation_count.to_be_bytes());
        out.extend_from_slice(&self.insertion_count.to_be_bytes());
        out.extend_from_slice(&self.prune_count.to_be_bytes());
        out.extend_from_slice(&self.liquidation_count.to_be_bytes());
        out.extend_from_slice(&self.forced_cancel_count.to_be_bytes());
        out.extend_from_slice(&self.forced_ioc_count.to_be_bytes());
        out.extend_from_slice(&self.forced_ioc_execution_count.to_be_bytes());
        debug_assert_eq!(out.len(), INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalOrderChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub previous_trader_root_projection: Hash32,
    pub previous_order_root_projection: Hash32,
    pub next_order_root_projection: Hash32,
    pub ordinary_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    pub forced_cancel_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub forced_ioc_completion_root: Hash32,
    pub operation_count: u16,
    pub insertion_count: u16,
    pub prune_count: u16,
    pub liquidation_count: u16,
    pub forced_cancel_count: u16,
    pub forced_ioc_count: u16,
    pub forced_ioc_execution_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalOrderChildErrorV2 {
    #[error("unsupported incremental order child version")]
    UnsupportedVersion,
    #[error("incremental order child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental order child input encoding failed")]
    InputEncoding,
    #[error("incremental order transition rejected: {0}")]
    Transition(#[from] ProtocolError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn order_root_after_action_count(
    action_count: u16,
    total_actions: u16,
    initial_root: OrderIndexRootV2,
    final_root: OrderIndexRootV2,
    predecessor_roots: &[OrderIndexRootV2],
) -> Result<OrderIndexRootV2, ProtocolError> {
    if action_count > total_actions {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    if action_count == 0 {
        return Ok(initial_root);
    }
    if action_count == total_actions {
        return Ok(final_root);
    }
    predecessor_roots
        .get(usize::from(action_count))
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)
}

fn apply_position_delta(
    position: i64,
    side: ecx_protocol_core::Side,
    quantity_atoms: u64,
) -> Result<i64, ProtocolError> {
    let delta = i128::from(side.sign())
        .checked_mul(i128::from(quantity_atoms))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    i64::try_from(
        i128::from(position)
            .checked_add(delta)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
    )
    .map_err(|_| ProtocolError::ArithmeticOverflow)
}

pub fn incremental_order_root_projection_v2(root: OrderIndexRootV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-order-root-projection/v1",
        &root.canonical_bytes(),
    )
}

pub fn decode_incremental_order_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalOrderChildProjectionV2, IncrementalOrderChildErrorV2> {
    if bytes.len() != INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalOrderChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalOrderChildErrorV2> {
        bytes[4 + (index * 32)..4 + ((index + 1) * 32)]
            .try_into()
            .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)
    };
    Ok(IncrementalOrderChildProjectionV2 {
        configuration_hash: hash(0)?,
        trader_update_leaf_projection_root: hash(1)?,
        previous_trader_root_projection: hash(2)?,
        previous_order_root_projection: hash(3)?,
        next_order_root_projection: hash(4)?,
        ordinary_execution_root: hash(6)?,
        liquidation_observation_root: hash(7)?,
        forced_cancel_root: hash(8)?,
        forced_ioc_root: hash(9)?,
        forced_ioc_execution_root: hash(10)?,
        forced_ioc_completion_root: hash(11)?,
        operation_count: u16::from_be_bytes(
            bytes[4 + (12 * 32)..4 + (12 * 32) + 2]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        insertion_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 2..4 + (12 * 32) + 4]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        prune_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 4..4 + (12 * 32) + 6]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        liquidation_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 6..4 + (12 * 32) + 8]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        forced_cancel_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 8..4 + (12 * 32) + 10]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        forced_ioc_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 10..4 + (12 * 32) + 12]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
        forced_ioc_execution_count: u16::from_be_bytes(
            bytes[4 + (12 * 32) + 12..]
                .try_into()
                .map_err(|_| IncrementalOrderChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

pub fn execute_incremental_order_child_v2(
    input: &IncrementalOrderChildInputV2,
) -> Result<IncrementalOrderChildPublicValuesV2, IncrementalOrderChildErrorV2> {
    if input.version != INCREMENTAL_ORDER_CHILD_VERSION_V2 {
        return Err(IncrementalOrderChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.previous_trader_root.domain != SparseStateDomainV2::Trader {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalOrderChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalOrderChildErrorV2::InputTooLarge);
    }
    let bounds = input.configuration.accounting_bounds;
    input.previous_trader_root.aggregate.validate(bounds)?;
    input.previous_order_root.aggregate.validate()?;
    input.next_order_root.aggregate.validate()?;
    let maximum_live_orders = u128::from(input.configuration.maximum_order_operations);
    if input.previous_order_root.aggregate.leaf_count > maximum_live_orders
        || input.next_order_root.aggregate.leaf_count > maximum_live_orders
    {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let context = input.configuration.order_context(input.sidechain_height);
    let (verified, predecessor_roots, count, transcript_bytes) = match &input.transcript {
        None => {
            if input.trader_reads.is_some()
                || !input.ordinary_fills.is_empty()
                || !input.liquidations.is_empty()
                || !input.forced_cancellations.is_empty()
                || !input.forced_ioc_fills.is_empty()
            {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            (input.previous_order_root, Vec::new(), 0, Vec::new())
        }
        Some(transcript) => {
            if transcript.actions.len() > usize::from(input.configuration.maximum_order_operations)
            {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            let operations = transcript
                .actions
                .iter()
                .map(|action| action.operation.clone())
                .collect::<Vec<_>>();
            verify_order_operation_trader_projection_parts_v2(
                &operations,
                &input.trader_updates,
                input.trader_reads.as_ref(),
                input.previous_trader_root,
                context,
                bounds,
            )?;
            let (next_root, predecessor_roots) = transcript.verify_with_predecessor_roots(
                input.previous_order_root,
                context,
                bounds,
            )?;
            (
                next_root,
                predecessor_roots,
                u16::try_from(transcript.actions.len())
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                transcript.canonical_bytes_checked(context, bounds)?,
            )
        }
    };
    if verified != input.next_order_root {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let transcript = input.transcript.as_ref();
    let mut classified_operation_indices = BTreeSet::new();
    let mut ordinary_executions = Vec::with_capacity(input.ordinary_fills.len());
    let mut previous_action_index = None;
    for ordinary in &input.ordinary_fills {
        if previous_action_index.is_some_and(|value| value >= ordinary.action_index)
            || !classified_operation_indices.insert(ordinary.action_index)
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        previous_action_index = Some(ordinary.action_index);
        let action = transcript
            .and_then(|value| value.actions.get(usize::from(ordinary.action_index)))
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let maker_leaf = action
            .operation
            .old_leaf
            .as_ref()
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        ordinary.execution.trade.validate_orders(
            &ordinary.execution.maker,
            &ordinary.execution.taker,
            input.sidechain_height,
        )?;
        if !matches!(
            action.operation.kind,
            OrderIndexOperationKindV2::PartialFill | OrderIndexOperationKindV2::RemoveFilled
        ) || action.operation.filled_quantity_atoms != ordinary.execution.trade.quantity.get()
            || maker_leaf.order_id() != ordinary.execution.maker.order_id()
            || maker_leaf.order_id() != ordinary.execution.trade.maker_order_id
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        ordinary_executions.push(ordinary.execution.clone());
    }
    let ordinary_execution_root = incremental_ordinary_execution_root_v2(&ordinary_executions)
        .map_err(|_| ProtocolError::InvalidMerkleProof)?;
    let forced_ioc_executions = input
        .forced_ioc_fills
        .iter()
        .map(|fill| fill.execution.clone())
        .collect::<Vec<_>>();
    let (forced_ioc_root, forced_ioc_execution_root) = validate_incremental_forced_ioc_batch_v2(
        input.configuration.chain_id,
        input.configuration.market,
        input.sidechain_height,
        &input.forced_iocs,
        &forced_ioc_executions,
    )?;
    if input.forced_ioc_stops.len() != input.forced_iocs.len()
        || (!input.forced_iocs.is_empty()
            && (!input.ordinary_fills.is_empty() || !input.liquidations.is_empty()))
        || (input.forced_iocs.is_empty() && !input.forced_ioc_stops.is_empty())
    {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let ioc_positions = input
        .forced_iocs
        .iter()
        .enumerate()
        .map(|(index, ioc)| (ioc.order_id(), index))
        .collect::<BTreeMap<_, _>>();
    let mut forced_fill_by_action = BTreeMap::new();
    let mut filled_by_ioc = vec![0u64; input.forced_iocs.len()];
    let mut previous_action_index = None;
    for forced in &input.forced_ioc_fills {
        if previous_action_index.is_some_and(|value| value >= forced.action_index)
            || !classified_operation_indices.insert(forced.action_index)
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        previous_action_index = Some(forced.action_index);
        let action = transcript
            .and_then(|value| value.actions.get(usize::from(forced.action_index)))
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let maker_leaf = action
            .operation
            .old_leaf
            .as_ref()
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let taker_leaf = input
            .trader_updates
            .iter()
            .find(|update| update.trader == forced.execution.taker.order.trader)
            .and_then(|update| update.old_leaf.as_ref())
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let taker_side = forced.execution.trade.maker_side.opposite();
        let ioc_position = *ioc_positions
            .get(&forced.execution.taker.order_id())
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if !matches!(
            action.operation.kind,
            OrderIndexOperationKindV2::PartialFill | OrderIndexOperationKindV2::RemoveFilled
        ) || action.operation.filled_quantity_atoms != forced.execution.trade.quantity.get()
            || maker_leaf.order_id() != forced.execution.maker.order_id()
            || maker_leaf.order_id() != forced.execution.trade.maker_order_id
            || taker_leaf.position_size_atoms == 0
            || taker_side.sign() == taker_leaf.position_size_atoms.signum()
            || forced.execution.trade.quantity.get() > taker_leaf.position_size_atoms.unsigned_abs()
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        if forced_fill_by_action
            .insert(forced.action_index, (ioc_position, &forced.execution))
            .is_some()
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        filled_by_ioc[ioc_position] = filled_by_ioc[ioc_position]
            .checked_add(forced.execution.trade.quantity.get())
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }

    // Replay the exact forced-fill action order and authenticate one stopping
    // root for every IOC.  A stop is valid only after all of that IOC's fills,
    // before any later IOC fill, and when the request is filled, has no
    // remaining reduce-only capacity, is expired, or the committed opposite
    // head no longer crosses.
    let mut positions = BTreeMap::<[u8; 32], i64>::new();
    for ioc in &input.forced_iocs {
        let opening = input
            .trader_updates
            .iter()
            .find(|update| update.trader == ioc.order.trader)
            .and_then(|update| update.old_leaf.as_ref().or(update.new_leaf.as_ref()))
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        positions.insert(ioc.order.trader.0, opening.position_size_atoms);
    }
    for fill in &input.forced_ioc_fills {
        for trader in [fill.execution.trade.maker, fill.execution.trade.taker] {
            if let std::collections::btree_map::Entry::Vacant(entry) = positions.entry(trader.0) {
                let opening = input
                    .trader_updates
                    .iter()
                    .find(|update| update.trader == trader)
                    .and_then(|update| update.old_leaf.as_ref().or(update.new_leaf.as_ref()))
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                entry.insert(opening.position_size_atoms);
            }
        }
    }
    let actions = transcript.map_or(&[][..], |value| value.actions.as_slice());
    let mut replayed_actions = 0u16;
    let mut previous_stop = 0u16;
    let mut completion_bytes = Vec::new();
    completion_bytes.extend_from_slice(
        &u16::try_from(input.forced_ioc_stops.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    for (expected_ioc_index, stop) in input.forced_ioc_stops.iter().enumerate() {
        let expected_ioc_index =
            u16::try_from(expected_ioc_index).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        if stop.ioc_index != expected_ioc_index
            || stop.stop_action_count < previous_stop
            || stop.stop_action_count > count
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        for action_index in previous_stop..stop.stop_action_count {
            let action = actions
                .get(usize::from(action_index))
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            if matches!(
                action.operation.kind,
                OrderIndexOperationKindV2::PartialFill | OrderIndexOperationKindV2::RemoveFilled
            ) && forced_fill_by_action
                .get(&action_index)
                .is_none_or(|(ioc_index, _)| *ioc_index != usize::from(expected_ioc_index))
            {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            if let Some((_, execution)) = forced_fill_by_action.get(&action_index) {
                let quantity = execution.trade.quantity.get();
                let maker = execution.trade.maker.0;
                let taker = execution.trade.taker.0;
                let maker_position = *positions
                    .get(&maker)
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                let taker_position = *positions
                    .get(&taker)
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                let taker_side = execution.trade.maker_side.opposite();
                if taker_position == 0
                    || taker_side.sign() == taker_position.signum()
                    || quantity > taker_position.unsigned_abs()
                {
                    return Err(ProtocolError::InvalidMerkleProof.into());
                }
                positions.insert(
                    maker,
                    apply_position_delta(maker_position, execution.trade.maker_side, quantity)?,
                );
                positions.insert(
                    taker,
                    apply_position_delta(taker_position, taker_side, quantity)?,
                );
            }
            replayed_actions = replayed_actions
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
        }
        if replayed_actions != stop.stop_action_count
            || forced_fill_by_action
                .iter()
                .any(|(action_index, (ioc_index, _))| {
                    *ioc_index == usize::from(expected_ioc_index)
                        && (*action_index < previous_stop
                            || *action_index >= stop.stop_action_count)
                })
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let stopping_root = order_root_after_action_count(
            stop.stop_action_count,
            count,
            input.previous_order_root,
            verified,
            &predecessor_roots,
        )?;
        let ioc = &input.forced_iocs[usize::from(expected_ioc_index)];
        let current_position = *positions
            .get(&ioc.order.trader.0)
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let filled = filled_by_ioc[usize::from(expected_ioc_index)];
        let no_reduce_only_capacity =
            current_position == 0 || ioc.order.side.sign() == current_position.signum();
        let expired = !ioc.order.is_live_at(input.sidechain_height);
        if filled != ioc.order.quantity.get()
            && !no_reduce_only_capacity
            && !expired
            && verify_no_crossing_maker_v2(
                stopping_root,
                ioc.order.side,
                ioc.order.limit_price.get(),
            )
            .is_err()
        {
            return Err(ProtocolError::PriceTimePriorityViolation.into());
        }
        completion_bytes.extend_from_slice(&ioc.order_id());
        completion_bytes.extend_from_slice(&stop.stop_action_count.to_be_bytes());
        completion_bytes.extend_from_slice(&filled.to_be_bytes());
        completion_bytes.extend_from_slice(&incremental_order_root_projection_v2(stopping_root));
        previous_stop = stop.stop_action_count;
    }
    if forced_fill_by_action
        .keys()
        .any(|action_index| *action_index >= previous_stop)
    {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let forced_ioc_completion_root = tagged_hash(
        b"ECX/incremental-forced-ioc-completions/v1",
        &completion_bytes,
    );
    let mut observations = Vec::with_capacity(input.liquidations.len());
    let mut previous_action_index = None;
    for liquidation in &input.liquidations {
        if liquidation.quantity_atoms == 0
            || previous_action_index.is_some_and(|value| value >= liquidation.action_index)
            || !classified_operation_indices.insert(liquidation.action_index)
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        previous_action_index = Some(liquidation.action_index);
        let action = transcript
            .and_then(|value| value.actions.get(usize::from(liquidation.action_index)))
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if !matches!(
            action.operation.kind,
            OrderIndexOperationKindV2::PartialFill | OrderIndexOperationKindV2::RemoveFilled
        ) || action.operation.filled_quantity_atoms != liquidation.quantity_atoms
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let maker = action
            .operation
            .old_leaf
            .as_ref()
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let target = input
            .trader_updates
            .iter()
            .find(|update| update.trader == liquidation.target)
            .and_then(|update| update.old_leaf.as_ref())
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if target.position_size_atoms == 0
            || target.trader == maker.signed_order.order.trader
            || liquidation.quantity_atoms > target.position_size_atoms.unsigned_abs()
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let predecessor_root = predecessor_roots
            .get(usize::from(liquidation.action_index))
            .copied()
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let adverse_price = verify_best_liquidation_maker_v2(
            predecessor_root,
            maker,
            context,
            target.position_size_atoms,
            input.liquidation_low_atoms,
            input.liquidation_high_atoms,
        )?;
        if !is_incremental_trader_liquidatable_v2(
            target,
            adverse_price,
            input.global_funding_index_numerator,
            input.configuration.risk_params.maintenance_margin_bps,
            input.configuration.accounting_bounds,
        )? {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        observations.push(IncrementalLiquidationObservationV2 {
            target: liquidation.target,
            maker_order_id: maker.order_id(),
            price_atoms: maker.signed_order.order.limit_price.get(),
            quantity_atoms: liquidation.quantity_atoms,
        });
    }
    let mut forced_cancel_values = Vec::with_capacity(input.forced_cancellations.len());
    let mut previous_action_index = None;
    for forced in &input.forced_cancellations {
        forced.cancellation.verify()?;
        let cancel = &forced.cancellation.cancel;
        if previous_action_index.is_some_and(|value| value >= forced.action_index)
            || !classified_operation_indices.insert(forced.action_index)
            || cancel.chain_id != input.configuration.chain_id
            || cancel.market != input.configuration.market
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        previous_action_index = Some(forced.action_index);
        let action = transcript
            .and_then(|value| value.actions.get(usize::from(forced.action_index)))
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if action.operation.order_id != cancel.order_id
            || action.operation.trader_leaf.trader != cancel.trader
            || !matches!(
                action.operation.kind,
                OrderIndexOperationKindV2::RemoveCancelled
                    | OrderIndexOperationKindV2::ConfirmAbsentCancelled
            )
            || (action.operation.kind == OrderIndexOperationKindV2::RemoveCancelled
                && action.operation.old_leaf.as_ref().is_none_or(|leaf| {
                    leaf.order_id() != cancel.order_id
                        || leaf.signed_order.order.trader != cancel.trader
                }))
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        forced_cancel_values.push(forced.cancellation.clone());
    }
    if transcript.is_some_and(|value| {
        value
            .actions
            .iter()
            .enumerate()
            .filter(|(_, action)| {
                matches!(
                    action.operation.kind,
                    OrderIndexOperationKindV2::PartialFill
                        | OrderIndexOperationKindV2::RemoveFilled
                        | OrderIndexOperationKindV2::RemoveCancelled
                        | OrderIndexOperationKindV2::ConfirmAbsentCancelled
                )
            })
            .any(|(index, _)| {
                u16::try_from(index)
                    .ok()
                    .is_none_or(|index| !classified_operation_indices.contains(&index))
            })
    }) {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let liquidation_observation_root = incremental_liquidation_observation_root_v2(&observations)
        .map_err(|_| ProtocolError::InvalidMerkleProof)?;
    let forced_cancel_root = incremental_successor_forced_cancel_root_v2(&forced_cancel_values);
    Ok(IncrementalOrderChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        trader_update_leaf_projection_root: incremental_trader_update_leaf_projection_v2(
            &input.trader_updates,
        )?,
        previous_trader_root_projection: incremental_trader_root_projection_v2(
            input.previous_trader_root,
        ),
        previous_order_root_projection: incremental_order_root_projection_v2(
            input.previous_order_root,
        ),
        next_order_root_projection: incremental_order_root_projection_v2(input.next_order_root),
        operation_transcript_root: tagged_hash(
            b"ECX/incremental-order-operation-transcript/v1",
            &transcript_bytes,
        ),
        ordinary_execution_root,
        liquidation_observation_root,
        forced_cancel_root,
        forced_ioc_root,
        forced_ioc_execution_root,
        forced_ioc_completion_root,
        operation_count: count,
        insertion_count: u16::try_from(transcript.map_or(0, |value| {
            value
                .actions
                .iter()
                .filter(|action| action.operation.kind == OrderIndexOperationKindV2::Insert)
                .count()
        }))
        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        prune_count: u16::try_from(transcript.map_or(0, |value| {
            value
                .actions
                .iter()
                .filter(|action| action.operation.kind == OrderIndexOperationKindV2::RemovePruned)
                .count()
        }))
        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        liquidation_count: u16::try_from(observations.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        forced_cancel_count: u16::try_from(forced_cancel_values.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        forced_ioc_count: u16::try_from(input.forced_iocs.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        forced_ioc_execution_count: u16::try_from(forced_ioc_executions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        canonical_empty_order_index_root_v2, canonical_empty_sparse_root_v2,
        ChainedOrderIndexActionV2, IncrementalAccountingBoundsV2, Int256V2, OrderFlags,
        OrderIndexFrontierItemV2, OrderIndexLeafV2, OrderIndexOperationV2, OrderRiskCommitmentV2,
        Price, Quantity, RiskParams, Side, SparseStateDomainV2, SuccessorCancelOrderV2,
        SuccessorLimitOrderV2, SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2,
        SuccessorTradeMatchV2, TimeInForce, TraderLeafV2, ECX_USDD_MARKET,
        INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;

    #[test]
    fn order_child_cap_composes_transcript_and_trader_read_frontier() {
        assert_eq!(
            INCREMENTAL_ORDER_CHILD_REACHABLE_ENCODING_CEILING_V2,
            11 * 1024 * 1024
        );
        assert_eq!(MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2, 12 * 1024 * 1024);
    }

    fn configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [0x11; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [0x22; 32],
            successor_matcher_configuration_hash: [0x23; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 1_000_000,
                maximum_total_controlled_atoms: 10_000_000,
                maximum_abs_position_atoms: 1_000_000,
                maximum_open_interest_atoms: 10_000_000,
                maximum_price_atoms: 1_000_000_000,
            },
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        }
    }

    fn trader_key(secret: &SecretKey) -> XOnlyKey {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
    }

    fn trader_leaf(secret: &SecretKey, position: i64, collateral: i128) -> TraderLeafV2 {
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: trader_key(secret),
            account_nonce: 0,
            collateral_atoms: collateral,
            cash_residual_numerator: 0,
            position_size_atoms: position,
            signed_cost_basis_numerator: if position == 0 {
                Int256V2::ZERO
            } else {
                Int256V2::from_u128(
                    u128::from(position.unsigned_abs()) * 100_000_000u128 * 1_000_000u128,
                )
            },
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [secret.secret_bytes()[0]; 32],
        }
    }

    fn maker_order(
        configuration: IncrementalSuccessorConfigurationV2,
        secret: &SecretKey,
    ) -> OrderIndexLeafV2 {
        let trader = trader_key(secret);
        let order = SuccessorLimitOrderV2 {
            version: SuccessorLimitOrderV2::VERSION,
            chain_id: configuration.chain_id,
            market: configuration.market,
            trader,
            side: Side::Buy,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::REDUCE_ONLY,
            limit_price: Price::new(95_000_000).unwrap(),
            quantity: Quantity::new(10).unwrap(),
            client_order_id: [0x44; 16],
            max_fee_bps: 5,
            nonce: (1u128 << 96) + 1,
            valid_from_height: 0,
            expires_at_height: 100,
        };
        let signed_order = SuccessorSignedLimitOrderV2::sign(order, secret).unwrap();
        OrderIndexLeafV2 {
            version: OrderIndexLeafV2::VERSION,
            risk: OrderRiskCommitmentV2::sign(
                configuration.order_configuration_hash,
                signed_order.order_id(),
                trader,
                1_000,
                secret,
            )
            .unwrap(),
            signed_order,
            remaining_quantity_atoms: 10,
            received_sequence: 1,
            admission_receipt_hash: [0x45; 32],
            trader_order_generation: 0,
            salt: [0x46; 32],
        }
    }

    fn forced_ioc(
        configuration: IncrementalSuccessorConfigurationV2,
        secret: &SecretKey,
    ) -> SuccessorSignedLimitOrderV2 {
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: configuration.chain_id,
                market: configuration.market,
                trader: trader_key(secret),
                side: Side::Sell,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::REDUCE_ONLY,
                limit_price: Price::new(90_000_000).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                client_order_id: [0x54; 16],
                max_fee_bps: 5,
                nonce: 1u128 << 96,
                valid_from_height: 0,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    #[test]
    fn order_child_binds_trader_projection_and_rejects_root_substitution() {
        let order = canonical_empty_order_index_root_v2();
        let input = IncrementalOrderChildInputV2 {
            version: INCREMENTAL_ORDER_CHILD_VERSION_V2,
            configuration: configuration(),
            sidechain_height: 1,
            trader_updates: vec![],
            previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            previous_order_root: order,
            next_order_root: order,
            transcript: None,
            trader_reads: None,
            liquidation_low_atoms: 90_000_000,
            liquidation_high_atoms: 110_000_000,
            global_funding_index_numerator: 0,
            ordinary_fills: vec![],
            liquidations: vec![],
            forced_cancellations: vec![],
            forced_iocs: vec![],
            forced_ioc_fills: vec![],
            forced_ioc_stops: vec![],
        };
        let values = execute_incremental_order_child_v2(&input).unwrap();
        assert_eq!(values.operation_count, 0);
        assert_eq!(
            values.encode().len(),
            INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let mut substituted = input;
        substituted.next_order_root.hash[0] ^= 1;
        assert!(execute_incremental_order_child_v2(&substituted).is_err());
    }

    #[test]
    fn liquidation_projection_requires_exact_head_target_and_adverse_solvency() {
        let configuration = configuration();
        let maker_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let target_secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let maker = maker_order(configuration, &maker_secret);
        let maker_trader = trader_leaf(&maker_secret, 0, 100);
        let target = trader_leaf(&target_secret, 100, 0);
        let mut target_next = target.clone();
        target_next.salt = [0x77; 32];
        target_next.position_size_atoms = 90;
        target_next.signed_cost_basis_numerator =
            Int256V2::from_u128(90u128 * 100_000_000u128 * 1_000_000u128);
        let insert = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::Insert,
            order_id: maker.order_id(),
            old_leaf: None,
            new_leaf: Some(maker.clone()),
            trader_leaf: maker_trader.clone(),
            filled_quantity_atoms: 0,
        };
        let remove = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::RemoveFilled,
            order_id: maker.order_id(),
            old_leaf: Some(maker.clone()),
            new_leaf: None,
            trader_leaf: maker_trader.clone(),
            filled_quantity_atoms: 10,
        };
        let empty_path = vec![OrderIndexFrontierItemV2::CanonicalEmpty; 256];
        let transcript = ChainedOrderIndexTranscriptV2 {
            actions: vec![
                ChainedOrderIndexActionV2 {
                    operation: insert,
                    siblings_leaf_to_root: empty_path.clone(),
                },
                ChainedOrderIndexActionV2 {
                    operation: remove,
                    siblings_leaf_to_root: empty_path,
                },
            ],
        };
        let empty_order = canonical_empty_order_index_root_v2();
        let base = IncrementalOrderChildInputV2 {
            version: INCREMENTAL_ORDER_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            trader_updates: vec![
                TraderStateBatchLeafUpdateV2 {
                    trader: maker_trader.trader,
                    old_leaf: None,
                    new_leaf: Some(maker_trader),
                },
                TraderStateBatchLeafUpdateV2 {
                    trader: target.trader,
                    old_leaf: Some(target.clone()),
                    new_leaf: Some(target_next),
                },
            ],
            previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            previous_order_root: empty_order,
            next_order_root: empty_order,
            transcript: Some(transcript),
            trader_reads: None,
            liquidation_low_atoms: 90_000_000,
            liquidation_high_atoms: 110_000_000,
            global_funding_index_numerator: 0,
            ordinary_fills: vec![],
            liquidations: vec![IncrementalOrderLiquidationV2 {
                action_index: 1,
                target: target.trader,
                quantity_atoms: 10,
            }],
            forced_cancellations: vec![],
            forced_iocs: vec![],
            forced_ioc_fills: vec![],
            forced_ioc_stops: vec![],
        };
        assert!(is_incremental_trader_liquidatable_v2(
            &target,
            90_000_000,
            0,
            base.configuration.risk_params.maintenance_margin_bps,
            base.configuration.accounting_bounds,
        )
        .unwrap());
        base.transcript
            .as_ref()
            .unwrap()
            .verify(
                base.previous_order_root,
                base.configuration.order_context(base.sidechain_height),
                base.configuration.accounting_bounds,
            )
            .unwrap();
        let values = execute_incremental_order_child_v2(&base).unwrap();
        assert_eq!(values.operation_count, 2);
        assert_eq!(values.liquidation_count, 1);

        let mut unclassified_fill = base.clone();
        unclassified_fill.liquidations.clear();
        assert!(execute_incremental_order_child_v2(&unclassified_fill).is_err());

        let mut wrong_target = base.clone();
        wrong_target.liquidations[0].target = trader_key(&maker_secret);
        assert!(execute_incremental_order_child_v2(&wrong_target).is_err());
        let mut wrong_quantity = base.clone();
        wrong_quantity.liquidations[0].quantity_atoms = 9;
        assert!(execute_incremental_order_child_v2(&wrong_quantity).is_err());
        let mut outside_band = base;
        outside_band.liquidation_low_atoms = 96_000_000;
        assert!(execute_incremental_order_child_v2(&outside_band).is_err());
    }

    #[test]
    fn forced_cancel_authenticates_absent_order_and_exact_signed_action() {
        let configuration = configuration();
        let secret = SecretKey::from_slice(&[5; 32]).unwrap();
        let trader = trader_leaf(&secret, 0, 100);
        let cancellation = SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
                chain_id: configuration.chain_id,
                market: configuration.market,
                trader: trader.trader,
                order_id: [0x71; 32],
                nonce: 1u128 << 96,
                valid_from_height: 1,
                expires_at_height: 20,
            },
            &secret,
        )
        .unwrap();
        let operation = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::ConfirmAbsentCancelled,
            order_id: cancellation.cancel.order_id,
            old_leaf: None,
            new_leaf: None,
            trader_leaf: trader.clone(),
            filled_quantity_atoms: 0,
        };
        let empty_order = canonical_empty_order_index_root_v2();
        let mut next_trader = trader.clone();
        next_trader.account_nonce += 1;
        next_trader.salt = [0x72; 32];
        let input = IncrementalOrderChildInputV2 {
            version: INCREMENTAL_ORDER_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 10,
            trader_updates: vec![TraderStateBatchLeafUpdateV2 {
                trader: trader.trader,
                old_leaf: Some(trader),
                new_leaf: Some(next_trader),
            }],
            previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            previous_order_root: empty_order,
            next_order_root: empty_order,
            transcript: Some(ChainedOrderIndexTranscriptV2 {
                actions: vec![ChainedOrderIndexActionV2 {
                    operation,
                    siblings_leaf_to_root: vec![OrderIndexFrontierItemV2::CanonicalEmpty; 256],
                }],
            }),
            trader_reads: None,
            liquidation_low_atoms: 90_000_000,
            liquidation_high_atoms: 110_000_000,
            global_funding_index_numerator: 0,
            ordinary_fills: vec![],
            liquidations: vec![],
            forced_cancellations: vec![IncrementalForcedCancellationV2 {
                action_index: 0,
                cancellation: cancellation.clone(),
            }],
            forced_iocs: vec![],
            forced_ioc_fills: vec![],
            forced_ioc_stops: vec![],
        };
        let values = execute_incremental_order_child_v2(&input).unwrap();
        assert_eq!(values.forced_cancel_count, 1);
        assert_eq!(
            values.forced_cancel_root,
            incremental_successor_forced_cancel_root_v2(&[cancellation])
        );
        assert_eq!(
            values.previous_order_root_projection,
            values.next_order_root_projection
        );

        let mut substituted = input;
        substituted.forced_cancellations[0]
            .cancellation
            .cancel
            .order_id[0] ^= 1;
        assert!(execute_incremental_order_child_v2(&substituted).is_err());
    }

    #[test]
    fn forced_ioc_fill_binds_signed_taker_exact_maker_removal_and_reduce_only_position() {
        let configuration = configuration();
        let maker_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let taker_secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let maker = maker_order(configuration, &maker_secret);
        let maker_trader = trader_leaf(&maker_secret, 0, 100);
        let taker = forced_ioc(configuration, &taker_secret);
        let taker_old = trader_leaf(&taker_secret, 100, 100);
        let mut taker_next = taker_old.clone();
        taker_next.position_size_atoms = 90;
        taker_next.signed_cost_basis_numerator =
            Int256V2::from_u128(90u128 * 100_000_000u128 * 1_000_000u128);
        taker_next.salt = [0x57; 32];
        let insert = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::Insert,
            order_id: maker.order_id(),
            old_leaf: None,
            new_leaf: Some(maker.clone()),
            trader_leaf: maker_trader.clone(),
            filled_quantity_atoms: 0,
        };
        let remove = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::RemoveFilled,
            order_id: maker.order_id(),
            old_leaf: Some(maker.clone()),
            new_leaf: None,
            trader_leaf: maker_trader.clone(),
            filled_quantity_atoms: 10,
        };
        let empty_path = vec![OrderIndexFrontierItemV2::CanonicalEmpty; 256];
        let empty_order = canonical_empty_order_index_root_v2();
        let insert_action = ChainedOrderIndexActionV2 {
            operation: insert.clone(),
            siblings_leaf_to_root: empty_path.clone(),
        };
        let remove_action = ChainedOrderIndexActionV2 {
            operation: remove,
            siblings_leaf_to_root: empty_path,
        };
        let crossing_root = ChainedOrderIndexTranscriptV2 {
            actions: vec![insert_action.clone()],
        }
        .verify(
            empty_order,
            configuration.order_context(1),
            configuration.accounting_bounds,
        )
        .unwrap();
        let execution = IncrementalForcedIocExecutionV2 {
            maker: maker.signed_order.clone(),
            taker: taker.clone(),
            trade: SuccessorTradeMatchV2 {
                sequence: crate::INCREMENTAL_FORCED_IOC_TAKER_SEQUENCE_V2,
                maker_order_id: maker.order_id(),
                taker_order_id: taker.order_id(),
                maker: maker.signed_order.order.trader,
                taker: taker.order.trader,
                maker_side: Side::Buy,
                price: maker.signed_order.order.limit_price,
                quantity: Quantity::new(10).unwrap(),
                maker_fee: ecx_protocol_core::Amount(0),
                taker_fee: ecx_protocol_core::Amount(1),
            },
        };
        let input = IncrementalOrderChildInputV2 {
            version: INCREMENTAL_ORDER_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            trader_updates: vec![
                TraderStateBatchLeafUpdateV2 {
                    trader: maker_trader.trader,
                    old_leaf: None,
                    new_leaf: Some(maker_trader),
                },
                TraderStateBatchLeafUpdateV2 {
                    trader: taker_old.trader,
                    old_leaf: Some(taker_old),
                    new_leaf: Some(taker_next),
                },
            ],
            previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            previous_order_root: empty_order,
            next_order_root: empty_order,
            transcript: Some(ChainedOrderIndexTranscriptV2 {
                actions: vec![insert_action, remove_action],
            }),
            trader_reads: None,
            liquidation_low_atoms: 90_000_000,
            liquidation_high_atoms: 110_000_000,
            global_funding_index_numerator: 0,
            ordinary_fills: vec![],
            liquidations: vec![],
            forced_cancellations: vec![],
            forced_iocs: vec![taker],
            forced_ioc_fills: vec![IncrementalOrderForcedIocFillV2 {
                action_index: 1,
                execution,
            }],
            forced_ioc_stops: vec![IncrementalOrderForcedIocStopV2 {
                ioc_index: 0,
                stop_action_count: 2,
            }],
        };
        let values = execute_incremental_order_child_v2(&input).unwrap();
        assert_eq!(values.forced_ioc_count, 1);
        assert_eq!(values.forced_ioc_execution_count, 1);

        let mut stopped_before_fill = input.clone();
        stopped_before_fill.forced_ioc_stops[0].stop_action_count = 1;
        assert!(execute_incremental_order_child_v2(&stopped_before_fill).is_err());

        let mut hidden_crossing_liquidity = input.clone();
        hidden_crossing_liquidity
            .transcript
            .as_mut()
            .unwrap()
            .actions
            .truncate(1);
        hidden_crossing_liquidity.next_order_root = crossing_root;
        hidden_crossing_liquidity.forced_ioc_fills.clear();
        hidden_crossing_liquidity.forced_ioc_stops[0].stop_action_count = 1;
        assert!(matches!(
            execute_incremental_order_child_v2(&hidden_crossing_liquidity),
            Err(IncrementalOrderChildErrorV2::Transition(
                ProtocolError::PriceTimePriorityViolation
            ))
        ));

        let mut over_capacity = input.clone();
        let mut oversized_root = crossing_root;
        oversized_root.aggregate.leaf_count = 65;
        over_capacity.previous_order_root = oversized_root;
        over_capacity.next_order_root = oversized_root;
        over_capacity.transcript = None;
        over_capacity.ordinary_fills.clear();
        over_capacity.liquidations.clear();
        over_capacity.forced_cancellations.clear();
        over_capacity.forced_iocs.clear();
        over_capacity.forced_ioc_fills.clear();
        over_capacity.forced_ioc_stops.clear();
        assert!(matches!(
            execute_incremental_order_child_v2(&over_capacity),
            Err(IncrementalOrderChildErrorV2::Transition(
                ProtocolError::InvalidBondState
            ))
        ));

        let mut wrong_position = input.clone();
        let taker = wrong_position.forced_iocs[0].order.trader;
        wrong_position
            .trader_updates
            .iter_mut()
            .find(|update| update.trader == taker)
            .unwrap()
            .old_leaf
            .as_mut()
            .unwrap()
            .position_size_atoms = -100;
        assert!(execute_incremental_order_child_v2(&wrong_position).is_err());

        let mut wrong_action = input;
        wrong_action.forced_iocs[0].signature.0[0] ^= 1;
        assert!(execute_incremental_order_child_v2(&wrong_action).is_err());
    }
}
