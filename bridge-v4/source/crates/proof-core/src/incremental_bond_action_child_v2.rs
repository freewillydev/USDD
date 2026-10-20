//! Recursive child statement composing authenticated bond-inbox actions with
//! exact trader mutations, FIFO bond state, and confidential settlement roles.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_elements_settlement::{
    bond_inbox_redemption_staging_script_sha256_v2, bond_settlement_action_root_v2,
    BondSettlementActionV2, SettlementError,
};
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    apply_incremental_trader_economic_mutation_v2, apply_successor_subscription_v2,
    capital_mode_for, incremental_successor_bond_state_root_v2, plan_successor_fifo_redemption_v2,
    plan_successor_redemption_cancellation_v2, redemption_queue_has_capacity_v2,
    successor_bond_inbox_outcome_next_root_v2, successor_redemption_queue_root_v2,
    target_reserve_125, BondInboxRedemptionStagingRendererInputV2, BondInboxRejectionV2,
    CapitalModeV2, FrozenConfigurationV2, Hash32, IncrementalAccountingBoundsV2,
    IncrementalTraderEconomicMutationV2, IncrementalTraderMutationChainV2,
    IncrementalTraderMutationKindV2, Int256V2, ProtocolError, SparseMerkleSumRootV2,
    SparseStateDomainV2, SuccessorBondInboxConsumedDispositionV2,
    SuccessorBondInboxConsumedOutcomeV2, SuccessorBondInboxEntryV2,
    SuccessorBondInboxProcessedOutcomeV2, SuccessorBondInboxUserActionV2,
    SuccessorBondPublicStateV2, SuccessorRedemptionExecutionV2, SuccessorRedemptionQueueEntryV2,
    TraderLeafV2, TraderStateReadBatchProofV2, BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2,
    EXACT_ACCOUNTING_DENOMINATOR_V2, MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    incremental_trader_economic_mutation_root_v2, incremental_trader_root_projection_v2,
    successor_recovered_candidate_root_v2, IncrementalInboxSourceChildErrorV2,
};

pub const INCREMENTAL_BOND_ACTION_CHILD_VERSION_V2: u8 = 2;
pub const INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 6;
pub const INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (13 * 32) + SuccessorBondPublicStateV2::ENCODED_LEN + (4 * 8) + (6 * 16) + 2;
pub const MAX_INCREMENTAL_BOND_QUEUE_ENTRY_ENCODING_BYTES_V2: usize = 160;
pub const INCREMENTAL_BOND_ACTION_AUXILIARY_ENCODING_BYTES_V2: usize = 2 * 1024 * 1024;
pub const INCREMENTAL_BOND_ACTION_REACHABLE_ENCODING_CEILING_V2: usize =
    MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2
        + (2 * BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2 as usize
            * MAX_INCREMENTAL_BOND_QUEUE_ENTRY_ENCODING_BYTES_V2)
        + INCREMENTAL_BOND_ACTION_AUXILIARY_ENCODING_BYTES_V2;
pub const MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2: usize = 12 * 1024 * 1024;
const _: () = assert!(
    SuccessorRedemptionQueueEntryV2::ENCODED_LEN
        <= MAX_INCREMENTAL_BOND_QUEUE_ENTRY_ENCODING_BYTES_V2
);
const _: () = assert!(
    INCREMENTAL_BOND_ACTION_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalBondReadOnlyActionEventV2 {
    pub event_id: Hash32,
    pub trader: [u8; 32],
    pub leaf: TraderLeafV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalBondActionChildInputV2 {
    pub version: u8,
    pub configuration: FrozenConfigurationV2,
    pub chain_id: Hash32,
    pub accounting_bounds: IncrementalAccountingBoundsV2,
    pub previous_bond: SuccessorBondPublicStateV2,
    pub next_bond: SuccessorBondPublicStateV2,
    pub previous_queue: Vec<SuccessorRedemptionQueueEntryV2>,
    pub next_queue: Vec<SuccessorRedemptionQueueEntryV2>,
    pub parent_height: u64,
    /// Reserve after trade fees, funding and liquidation but before inbox bond
    /// actions. The outer composition must derive this value from those action
    /// classes; it is not inferred from the predecessor reserve.
    pub insurance_reserve_before_bond_actions: u128,
    pub consumed_outcomes: Vec<SuccessorBondInboxConsumedOutcomeV2>,
    /// Exact source entries corresponding one-for-one to consumed outcomes.
    /// They are cross-bound by the recovered-candidate root produced by the
    /// independently authenticated inbox/source child.
    pub consumed_entries: Vec<SuccessorBondInboxEntryV2>,
    pub previous_outcome_root: Hash32,
    pub previous_outcome_count: u128,
    pub next_outcome_root: Hash32,
    pub next_outcome_count: u128,
    pub redemption_executions: Vec<SuccessorRedemptionExecutionV2>,
    pub settlement_actions: Vec<BondSettlementActionV2>,
    pub trader_mutation_chains: Vec<IncrementalTraderMutationChainV2>,
    /// Authenticated predecessor trader state used only for invalid-nonce
    /// outcomes which do not mutate the trader tree. Context/duplicate
    /// rejection and cancellation do not require or permit a trader opening.
    pub previous_trader_root: SparseMerkleSumRootV2,
    pub trader_reads: Option<TraderStateReadBatchProofV2>,
    pub read_only_action_events: Vec<IncrementalBondReadOnlyActionEventV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalBondActionChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub previous_bond_root: Hash32,
    pub next_bond_root: Hash32,
    pub previous_queue_root: Hash32,
    pub next_queue_root: Hash32,
    pub recovered_candidate_root: Hash32,
    pub processed_outcome_root: Hash32,
    pub settlement_action_root: Hash32,
    pub trader_economic_mutation_root: Hash32,
    pub previous_trader_root_projection: Hash32,
    pub previous_outcome_root: Hash32,
    pub next_outcome_root: Hash32,
    /// Exact validated successor bond-state opening. Publishing only its root
    /// is insufficient for a node to authenticate reserve, supply, NAV and
    /// FIFO projections without stale host-side state.
    pub next_bond: SuccessorBondPublicStateV2,
    pub parent_height: u64,
    pub consumed_count: u64,
    pub accepted_action_count: u64,
    pub redemption_execution_count: u64,
    pub previous_outcome_count: u128,
    pub next_outcome_count: u128,
    pub insurance_reserve_before_bond_actions: u128,
    pub insurance_reserve_after: u128,
    pub queued_redemption_share_atoms_after: u128,
    pub full_bound_deficit_after: u128,
    pub authorized_mutation_count: u16,
}

impl IncrementalBondActionChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for value in [
            self.configuration_hash,
            self.chain_id,
            self.previous_bond_root,
            self.next_bond_root,
            self.previous_queue_root,
            self.next_queue_root,
            self.recovered_candidate_root,
            self.processed_outcome_root,
            self.settlement_action_root,
            self.trader_economic_mutation_root,
            self.previous_trader_root_projection,
            self.previous_outcome_root,
            self.next_outcome_root,
        ] {
            out.extend_from_slice(&value);
        }
        self.next_bond.encode_to(&mut out);
        for value in [
            self.parent_height,
            self.consumed_count,
            self.accepted_action_count,
            self.redemption_execution_count,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.previous_outcome_count,
            self.next_outcome_count,
            self.insurance_reserve_before_bond_actions,
            self.insurance_reserve_after,
            self.queued_redemption_share_atoms_after,
            self.full_bound_deficit_after,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.authorized_mutation_count.to_be_bytes());
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalBondActionChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub previous_bond_root: Hash32,
    pub next_bond_root: Hash32,
    pub recovered_candidate_root: Hash32,
    pub processed_outcome_root: Hash32,
    pub settlement_action_root: Hash32,
    pub trader_economic_mutation_root: Hash32,
    pub previous_trader_root_projection: Hash32,
    pub previous_outcome_root: Hash32,
    pub next_outcome_root: Hash32,
    pub next_bond: SuccessorBondPublicStateV2,
    pub parent_height: u64,
    pub accepted_action_count: u64,
    pub previous_outcome_count: u128,
    pub next_outcome_count: u128,
    pub insurance_reserve_before_bond_actions: u128,
    pub full_bound_deficit_after: u128,
    pub authorized_mutation_count: u16,
}

pub fn decode_incremental_bond_action_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalBondActionChildProjectionV2, IncrementalBondActionChildErrorV2> {
    if bytes.len() != INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalBondActionChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalBondActionChildErrorV2> {
        let start = 4 + (index * 32);
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalBondActionChildErrorV2::UnsupportedVersion)
    };
    let bond_start = 4 + (13 * 32);
    let next_bond = SuccessorBondPublicStateV2::decode(
        &bytes[bond_start..bond_start + SuccessorBondPublicStateV2::ENCODED_LEN],
    )?;
    let u64_at = |index: usize| -> Result<u64, IncrementalBondActionChildErrorV2> {
        let start = bond_start + SuccessorBondPublicStateV2::ENCODED_LEN + (index * 8);
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalBondActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let u128_at = |index: usize| -> Result<u128, IncrementalBondActionChildErrorV2> {
        let start = bond_start + SuccessorBondPublicStateV2::ENCODED_LEN + (4 * 8) + (index * 16);
        Ok(u128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalBondActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let projection = IncrementalBondActionChildProjectionV2 {
        configuration_hash: hash(0)?,
        chain_id: hash(1)?,
        previous_bond_root: hash(2)?,
        next_bond_root: hash(3)?,
        recovered_candidate_root: hash(6)?,
        processed_outcome_root: hash(7)?,
        settlement_action_root: hash(8)?,
        trader_economic_mutation_root: hash(9)?,
        previous_trader_root_projection: hash(10)?,
        previous_outcome_root: hash(11)?,
        next_outcome_root: hash(12)?,
        next_bond,
        parent_height: u64_at(0)?,
        accepted_action_count: u64_at(2)?,
        previous_outcome_count: u128_at(0)?,
        next_outcome_count: u128_at(1)?,
        insurance_reserve_before_bond_actions: u128_at(2)?,
        full_bound_deficit_after: u128_at(5)?,
        authorized_mutation_count: u16::from_be_bytes(
            bytes[INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 2..]
                .try_into()
                .map_err(|_| IncrementalBondActionChildErrorV2::UnsupportedVersion)?,
        ),
    };
    if incremental_successor_bond_state_root_v2(projection.next_bond) != projection.next_bond_root
        || projection.next_bond.insurance_reserve != u128_at(3)?
        || u128::from(projection.next_bond.queued_redemption_share_atoms) != u128_at(4)?
        || projection.next_bond.full_bound_deficit != projection.full_bound_deficit_after
    {
        return Err(IncrementalBondActionChildErrorV2::Protocol(
            ProtocolError::InvalidBondState,
        ));
    }
    Ok(projection)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalBondActionChildErrorV2 {
    #[error("unsupported incremental bond action child version")]
    UnsupportedVersion,
    #[error("incremental bond action child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental bond action child input encoding failed")]
    InputEncoding,
    #[error("incremental bond action composition rejected: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("incremental bond action settlement rendering rejected: {0}")]
    Settlement(#[from] SettlementError),
    #[error("incremental inbox candidate binding rejected: {0}")]
    Inbox(#[from] IncrementalInboxSourceChildErrorV2),
}

#[derive(Clone)]
struct MutationOpening {
    trader: [u8; 32],
    before: TraderLeafV2,
    mutation: IncrementalTraderEconomicMutationV2,
    chain_index: usize,
    mutation_index: usize,
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_bond_trader_mutation_event_id_v2(
    entry_hash: Hash32,
    signed_action_id: Hash32,
) -> Result<Hash32, ProtocolError> {
    if entry_hash == [0; 32] || signed_action_id == [0; 32] {
        return Err(ProtocolError::InvalidBondInbox);
    }
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&entry_hash);
    bytes.extend_from_slice(&signed_action_id);
    Ok(tagged_hash(
        b"ECX/incremental-bond-trader-mutation-event/v2-u128-actions",
        &bytes,
    ))
}

fn validate_queue(
    state: SuccessorBondPublicStateV2,
    queue: &[SuccessorRedemptionQueueEntryV2],
    maximum_entries: u32,
) -> Result<(), ProtocolError> {
    if queue.len() > maximum_entries as usize
        || state.redemption_queue_root != successor_redemption_queue_root_v2(queue)?
        || state.queued_redemption_share_atoms
            != queue.iter().try_fold(0u64, |total, entry| {
                entry.validate()?;
                total
                    .checked_add(entry.remaining_share_atoms)
                    .ok_or(ProtocolError::ArithmeticOverflow)
            })?
        || state.redemption_head
            != queue
                .first()
                .map(|entry| entry.sequence)
                .unwrap_or(state.redemption_tail)
        || queue
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        || queue
            .last()
            .is_some_and(|entry| entry.sequence >= state.redemption_tail)
    {
        return Err(ProtocolError::InvalidBondState);
    }
    Ok(())
}

fn refresh_bond_derived(state: &mut SuccessorBondPublicStateV2) -> Result<(), ProtocolError> {
    state.target_reserve = target_reserve_125(state.full_bound_deficit)?;
    state.capital_mode = capital_mode_for(state.insurance_reserve, state.full_bound_deficit)?;
    Ok(())
}

fn expected_cash_delta(amount: u64) -> Result<Int256V2, ProtocolError> {
    let numerator = i128::from(amount)
        .checked_mul(i128::from(EXACT_ACCOUNTING_DENOMINATOR_V2))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    Ok(Int256V2::from_i128(-numerator))
}

fn mutation_is_exact(
    opening: &MutationOpening,
    signer: [u8; 32],
    kind: IncrementalTraderMutationKindV2,
    action_id: Hash32,
    debit: u64,
    nonce_increment: u128,
) -> Result<(), ProtocolError> {
    let mutation = &opening.mutation;
    if opening.trader != signer
        || mutation.kind != kind
        || mutation.action_id != action_id
        || mutation.exact_cash_delta_numerator != expected_cash_delta(debit)?
        || mutation.position_size_delta_atoms != 0
        || mutation.signed_cost_basis_delta_numerator != Int256V2::ZERO
        || mutation.funding_checkpoint_after.is_some()
        || mutation.account_nonce_increment != nonce_increment
        || mutation.order_generation_increment != 0
        || mutation.selected_initial_margin_bps_after.is_some()
    {
        return Err(ProtocolError::InvalidBondState);
    }
    Ok(())
}

fn account_can_debit(
    opening: &MutationOpening,
    nonce: u128,
    amount: u64,
    bounds: IncrementalAccountingBoundsV2,
) -> bool {
    if opening.before.account_nonce != nonce {
        return false;
    }
    let Ok(remaining) = opening
        .before
        .exact_cash_numerator(bounds)
        .and_then(|cash| cash.checked_add(expected_cash_delta(amount)?))
    else {
        return false;
    };
    !remaining.is_negative()
}

fn rejection_consumes_nonce(reason: BondInboxRejectionV2) -> bool {
    matches!(
        reason,
        BondInboxRejectionV2::InsufficientCollateral
            | BondInboxRejectionV2::InvalidSubscriptionQuote
            | BondInboxRejectionV2::CapitalModeRestriction
            | BondInboxRejectionV2::InvalidQueueRequest
            | BondInboxRejectionV2::InvalidRecapitalizationContribution
    )
}

fn processed_outcome_root(outcomes: &[SuccessorBondInboxProcessedOutcomeV2]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(outcomes.len() as u32).to_be_bytes());
    for outcome in outcomes {
        bytes.extend_from_slice(&outcome.outcome_hash());
    }
    tagged_hash(
        b"ECX/incremental-bond-processed-outcomes/v2-u128-inbox",
        &bytes,
    )
}

/// Execute the exact economic/action composition. Source authenticity and the
/// confidential transaction are proved by sibling children; equality of the
/// candidate, settlement-action and mutation roots makes those statements one
/// atomic successor relation.
pub fn execute_incremental_bond_action_child_v2(
    input: &IncrementalBondActionChildInputV2,
) -> Result<IncrementalBondActionChildPublicValuesV2, IncrementalBondActionChildErrorV2> {
    if input.version != INCREMENTAL_BOND_ACTION_CHILD_VERSION_V2 {
        return Err(IncrementalBondActionChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    input.accounting_bounds.validate()?;
    if input.chain_id == [0; 32] || input.parent_height == 0 {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalBondActionChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalBondActionChildErrorV2::InputTooLarge);
    }
    let maximum_actions = usize::try_from(
        input
            .configuration
            .bond_inbox_max_consumed_entries_per_transition,
    )
    .map_err(|_| IncrementalBondActionChildErrorV2::InputTooLarge)?;
    if input.consumed_outcomes.len() > maximum_actions
        || input.consumed_entries.len() > maximum_actions
        || input.redemption_executions.len() > maximum_actions
        || input.settlement_actions.len() > maximum_actions
        || input.trader_mutation_chains.len() > maximum_actions
        || input.read_only_action_events.len() > maximum_actions
    {
        return Err(IncrementalBondActionChildErrorV2::InputTooLarge);
    }
    input.previous_bond.validate()?;
    input.next_bond.validate()?;
    validate_queue(
        input.previous_bond,
        &input.previous_queue,
        input.configuration.bond_redemption_max_queue_entries,
    )?;
    validate_queue(
        input.next_bond,
        &input.next_queue,
        input.configuration.bond_redemption_max_queue_entries,
    )?;
    if input.consumed_entries.len() != input.consumed_outcomes.len() {
        return Err(ProtocolError::InvalidBondInbox.into());
    }
    for (entry, outcome) in input.consumed_entries.iter().zip(&input.consumed_outcomes) {
        if entry.index != outcome.entry_index
            || entry.entry_hash() != outcome.entry_hash
            || entry.marker.kind != outcome.marker_kind
            || entry.marker.action_id != outcome.marker_action_id
            || entry.observed_parent_height != outcome.source_parent_height
        {
            return Err(ProtocolError::InvalidBondInbox.into());
        }
    }

    let mutation_root = incremental_trader_economic_mutation_root_v2(
        &input.trader_mutation_chains,
        input.accounting_bounds,
    )?;
    if input.previous_trader_root.domain != SparseStateDomainV2::Trader {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    match &input.trader_reads {
        Some(reads) => reads.verify(input.previous_trader_root, input.accounting_bounds)?,
        None if !input.read_only_action_events.is_empty() => {
            return Err(ProtocolError::InvalidMerkleProof.into())
        }
        None => {}
    }
    let mut authenticated_read_leaves = BTreeMap::new();
    if let Some(reads) = &input.trader_reads {
        for leaf in &reads.leaves {
            authenticated_read_leaves.insert(leaf.trader.0, leaf.clone());
        }
    }
    let mut read_events = BTreeMap::new();
    for event in &input.read_only_action_events {
        if event.event_id == [0; 32]
            || event.trader != event.leaf.trader.0
            || authenticated_read_leaves.get(&event.trader) != Some(&event.leaf)
            || read_events.insert(event.event_id, event.clone()).is_some()
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
    }
    let mut mutations = BTreeMap::new();
    for (chain_index, chain) in input.trader_mutation_chains.iter().enumerate() {
        let mut current = chain.old_leaf.clone();
        for (mutation_index, mutation) in chain.mutations.iter().enumerate() {
            if matches!(
                mutation.kind,
                IncrementalTraderMutationKindV2::BondSubscription
                    | IncrementalTraderMutationKindV2::BondRecapitalization
                    | IncrementalTraderMutationKindV2::BondRedemptionEnqueue
                    | IncrementalTraderMutationKindV2::BondRedemptionCancellation
                    | IncrementalTraderMutationKindV2::BondActionRejection
            ) && mutations
                .insert(
                    mutation.action_id,
                    MutationOpening {
                        trader: chain.trader.0,
                        before: current.clone(),
                        mutation: mutation.clone(),
                        chain_index,
                        mutation_index,
                    },
                )
                .is_some()
            {
                return Err(ProtocolError::InvalidBondState.into());
            }
            current = apply_incremental_trader_economic_mutation_v2(
                &current,
                mutation,
                input.accounting_bounds,
            )?;
        }
    }
    let authorized_mutation_count =
        u16::try_from(mutations.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;

    let mut state = input.previous_bond;
    state.insurance_reserve = input.insurance_reserve_before_bond_actions;
    state.full_bound_deficit = input.next_bond.full_bound_deficit;
    refresh_bond_derived(&mut state)?;
    state.validate()?;
    let mut queue = input.previous_queue.clone();
    let mut seen_actions = BTreeSet::new();
    let mut last_position = BTreeMap::<usize, usize>::new();
    let mut processed = Vec::with_capacity(input.consumed_outcomes.len());
    let mut settlement_actions = Vec::new();
    let mut accepted_count = 0u64;

    for (entry, consumed) in input.consumed_entries.iter().zip(&input.consumed_outcomes) {
        match &consumed.disposition {
            SuccessorBondInboxConsumedDispositionV2::ExpiredUnavailable => {
                processed.push(SuccessorBondInboxProcessedOutcomeV2::expired_unavailable(
                    consumed,
                ));
                continue;
            }
            SuccessorBondInboxConsumedDispositionV2::Action(Err(reason)) => {
                processed.push(SuccessorBondInboxProcessedOutcomeV2::rejected(
                    consumed, *reason,
                ));
                continue;
            }
            SuccessorBondInboxConsumedDispositionV2::Action(Ok(_)) => {}
        }
        let SuccessorBondInboxConsumedDispositionV2::Action(Ok(action)) = &consumed.disposition
        else {
            unreachable!();
        };
        let action_id = action.action_id();
        let mutation_event_id =
            incremental_bond_trader_mutation_event_id_v2(consumed.entry_hash, action_id)?;
        let opening = mutations.remove(&mutation_event_id);
        if let Some(opening) = &opening {
            if last_position
                .insert(opening.chain_index, opening.mutation_index)
                .is_some_and(|previous| previous >= opening.mutation_index)
            {
                return Err(ProtocolError::InvalidBondState.into());
            }
        }
        let read_event = read_events.remove(&mutation_event_id);
        let duplicate = !seen_actions.insert(action_id);
        let mut rejection = None;
        let mut accepted_kind = None;
        let mut accepted_debit = 0u64;

        match action {
            SuccessorBondInboxUserActionV2::Subscription(signed) => {
                signed.verify()?;
                let value = &signed.action;
                if value.chain_id != input.chain_id
                    || value.configuration_hash != input.configuration.digest()
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if duplicate {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else {
                    let account = opening
                        .as_ref()
                        .map(|item| &item.before)
                        .or_else(|| read_event.as_ref().map(|item| &item.leaf))
                        .ok_or(ProtocolError::InvalidBondState)?;
                    if account.trader.0 != value.trader.0
                        || account.account_nonce != value.account_nonce
                    {
                        rejection = Some(BondInboxRejectionV2::InvalidNonce);
                    } else {
                        let opening = opening.as_ref().ok_or(ProtocolError::InvalidBondState)?;
                        if !account_can_debit(
                            opening,
                            value.account_nonce,
                            value.contribution_usdd_atoms,
                            input.accounting_bounds,
                        ) {
                            rejection = Some(BondInboxRejectionV2::InsufficientCollateral);
                        } else {
                            match apply_successor_subscription_v2(
                                state,
                                u128::from(value.contribution_usdd_atoms),
                            ) {
                                Ok(result)
                                    if result.issued_share_atoms == value.issued_share_atoms =>
                                {
                                    state.insurance_reserve = result.insurance_reserve_after;
                                    state.outstanding_share_atoms =
                                        result.outstanding_share_atoms_after;
                                    state.inventory_share_atoms =
                                        result.inventory_share_atoms_after;
                                    refresh_bond_derived(&mut state)?;
                                    accepted_kind =
                                        Some(IncrementalTraderMutationKindV2::BondSubscription);
                                    accepted_debit = value.contribution_usdd_atoms;
                                    settlement_actions.push(BondSettlementActionV2::Subscription {
                                        subscription_id: value.subscription_id(),
                                        usdd_contribution_amount: value.contribution_usdd_atoms,
                                        bond_share_amount: value.issued_share_atoms,
                                        recipient_script_sha256: value.bond_recipient_script_sha256,
                                    });
                                }
                                Ok(_) => {
                                    rejection = Some(BondInboxRejectionV2::InvalidSubscriptionQuote)
                                }
                                Err(ProtocolError::InsufficientCollateral) => {
                                    rejection = Some(BondInboxRejectionV2::InsufficientCollateral)
                                }
                                Err(_) => {
                                    rejection = Some(BondInboxRejectionV2::InvalidSubscriptionQuote)
                                }
                            }
                        }
                    }
                }
            }
            SuccessorBondInboxUserActionV2::InsuranceRecapitalizationContribution(signed) => {
                signed.verify()?;
                let value = &signed.action;
                if value.chain_id != input.chain_id
                    || value.configuration_hash != input.configuration.digest()
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if duplicate {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else {
                    let account = opening
                        .as_ref()
                        .map(|item| &item.before)
                        .or_else(|| read_event.as_ref().map(|item| &item.leaf))
                        .ok_or(ProtocolError::InvalidBondState)?;
                    if account.trader.0 != value.contributor.0
                        || account.account_nonce != value.account_nonce
                    {
                        rejection = Some(BondInboxRejectionV2::InvalidNonce);
                    } else {
                        let opening = opening.as_ref().ok_or(ProtocolError::InvalidBondState)?;
                        if !account_can_debit(
                            opening,
                            value.account_nonce,
                            value.contribution_usdd_atoms,
                            input.accounting_bounds,
                        ) {
                            rejection = Some(BondInboxRejectionV2::InsufficientCollateral);
                        } else if let Some(after) = state
                            .insurance_reserve
                            .checked_add(u128::from(value.contribution_usdd_atoms))
                        {
                            state.insurance_reserve = after;
                            refresh_bond_derived(&mut state)?;
                            accepted_kind =
                                Some(IncrementalTraderMutationKindV2::BondRecapitalization);
                            accepted_debit = value.contribution_usdd_atoms;
                            settlement_actions.push(
                                BondSettlementActionV2::InsuranceRecapitalizationContribution {
                                    contribution_id: value.contribution_id(),
                                    usdd_contribution_amount: value.contribution_usdd_atoms,
                                },
                            );
                        } else {
                            rejection =
                                Some(BondInboxRejectionV2::InvalidRecapitalizationContribution);
                        }
                    }
                }
            }
            SuccessorBondInboxUserActionV2::RedemptionEnqueue(signed) => {
                signed.verify()?;
                let value = &signed.action;
                if value.chain_id != input.chain_id
                    || value.configuration_hash != input.configuration.digest()
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if duplicate {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else {
                    let account = opening
                        .as_ref()
                        .map(|item| &item.before)
                        .or_else(|| read_event.as_ref().map(|item| &item.leaf))
                        .ok_or(ProtocolError::InvalidBondState)?;
                    if account.trader.0 != value.claimant.0
                        || account.account_nonce != value.account_nonce
                    {
                        rejection = Some(BondInboxRejectionV2::InvalidNonce);
                    } else {
                        opening.as_ref().ok_or(ProtocolError::InvalidBondState)?;
                        if state.capital_mode != CapitalModeV2::Normal {
                            rejection = Some(BondInboxRejectionV2::CapitalModeRestriction);
                        } else if !redemption_queue_has_capacity_v2(
                            queue.len(),
                            input.configuration.bond_redemption_max_queue_entries,
                        ) || state.redemption_tail == u128::MAX
                            || consumed
                                .source_parent_height
                                .checked_add(u64::from(
                                    input.configuration.bond_inbox_refund_minimum_parent_blocks,
                                ))
                                .is_none_or(|minimum| {
                                    value.refund_not_before_parent_height < minimum
                                })
                        {
                            rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                        } else {
                            let queued = value.queue_entry(
                                state.redemption_tail,
                                consumed.entry_hash,
                                consumed.source_parent_height,
                            )?;
                            let queued_after = state
                                .queued_redemption_share_atoms
                                .checked_add(queued.remaining_share_atoms)
                                .ok_or(ProtocolError::ArithmeticOverflow)?;
                            if queued_after > state.outstanding_share_atoms
                                || queue
                                    .iter()
                                    .any(|item| item.request_id == queued.request_id)
                            {
                                rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                            } else {
                                state.redemption_tail = state
                                    .redemption_tail
                                    .checked_add(1)
                                    .ok_or(ProtocolError::ArithmeticOverflow)?;
                                state.queued_redemption_share_atoms = queued_after;
                                queue.push(queued);
                                accepted_kind =
                                    Some(IncrementalTraderMutationKindV2::BondRedemptionEnqueue);
                                let renderer = BondInboxRedemptionStagingRendererInputV2 {
                                    chain_id: input.chain_id,
                                    configuration_hash: input.configuration.digest(),
                                    marker_signer: entry.marker.signer,
                                    stable_intent_id: entry.marker.staging_intent_id,
                                    staging_vout: entry.marker.staging_vout,
                                    refund_script_sha256: entry.marker.refund_script_sha256,
                                    refund_not_before_parent_height: entry
                                        .marker
                                        .refund_not_before_parent_height,
                                };
                                settlement_actions.push(
                                    BondSettlementActionV2::EnqueueRedemption {
                                        redemption_id: queued.request_id,
                                        staging_intent_id: value.stable_intent_id(),
                                        claimant: value.claimant.0,
                                        bond_share_amount: value.requested_share_atoms,
                                        staging_script_sha256:
                                            bond_inbox_redemption_staging_script_sha256_v2(
                                                &input.configuration,
                                                renderer,
                                            )?,
                                        source_txid: entry.source_txid,
                                        source_vout: entry.marker.staging_vout,
                                        source_authorization_commitment: entry
                                            .marker
                                            .source_authorization_commitment,
                                        refund_script_sha256: value.refund_script_sha256,
                                        refund_not_before_parent_height: value
                                            .refund_not_before_parent_height,
                                        destination_script_sha256: value.destination_script_hash,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            SuccessorBondInboxUserActionV2::RedemptionCancellation(signed) => {
                signed.verify()?;
                let value = &signed.action;
                if value.chain_id != input.chain_id
                    || value.configuration_hash != input.configuration.digest()
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if duplicate {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else if state.capital_mode == CapitalModeV2::RecapitalizationOnly {
                    rejection = Some(BondInboxRejectionV2::CapitalModeRestriction);
                } else if let Some(index) = queue.iter().position(|item| {
                    item.sequence == value.sequence && item.request_id == value.request_id
                }) {
                    let queued = queue[index];
                    if queued.claimant_commitment
                        != tagged_hash(b"ECX/bond-claimant/v2", &value.claimant.0)
                    {
                        rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                    } else {
                        let result = plan_successor_redemption_cancellation_v2(state, queued)?;
                        state.queued_redemption_share_atoms =
                            result.queued_redemption_share_atoms_after;
                        queue.remove(index);
                        state.redemption_head = queue
                            .first()
                            .map(|item| item.sequence)
                            .unwrap_or(state.redemption_tail);
                        accepted_kind =
                            Some(IncrementalTraderMutationKindV2::BondRedemptionCancellation);
                        settlement_actions.push(BondSettlementActionV2::CancelRedemption {
                            redemption_id: queued.request_id,
                            claimant: value.claimant.0,
                            bond_share_amount: queued.remaining_share_atoms,
                            recipient_script_sha256: value.bond_recipient_script_sha256,
                            cancellation_id: value.cancellation_id(),
                        });
                    }
                } else {
                    rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                }
            }
        }

        if let Some(reason) = rejection {
            let cancellation = matches!(
                action,
                SuccessorBondInboxUserActionV2::RedemptionCancellation(_)
            );
            if cancellation
                || matches!(
                    reason,
                    BondInboxRejectionV2::InvalidContext
                        | BondInboxRejectionV2::DuplicateOrReplayedAction
                )
            {
                if opening.is_some() || read_event.is_some() {
                    return Err(ProtocolError::InvalidBondState.into());
                }
            } else if reason == BondInboxRejectionV2::InvalidNonce {
                match (&opening, &read_event) {
                    (Some(opening), None) => mutation_is_exact(
                        opening,
                        action.signer().0,
                        IncrementalTraderMutationKindV2::BondActionRejection,
                        mutation_event_id,
                        0,
                        0,
                    )?,
                    (None, Some(event))
                        if event.event_id == mutation_event_id
                            && event.trader == action.signer().0 => {}
                    _ => return Err(ProtocolError::InvalidBondState.into()),
                }
            } else {
                if read_event.is_some() || !rejection_consumes_nonce(reason) {
                    return Err(ProtocolError::InvalidBondState.into());
                }
                mutation_is_exact(
                    opening.as_ref().ok_or(ProtocolError::InvalidBondState)?,
                    action.signer().0,
                    IncrementalTraderMutationKindV2::BondActionRejection,
                    mutation_event_id,
                    0,
                    1,
                )?;
            }
            if action.kind() == ecx_protocol_core::BondInboxActionKindV2::RedemptionEnqueue
                && !matches!(
                    reason,
                    BondInboxRejectionV2::InvalidContext
                        | BondInboxRejectionV2::InvalidNonce
                        | BondInboxRejectionV2::DuplicateOrReplayedAction
                )
            {
                let SuccessorBondInboxUserActionV2::RedemptionEnqueue(signed) = action else {
                    unreachable!();
                };
                let value = &signed.action;
                let renderer = BondInboxRedemptionStagingRendererInputV2 {
                    chain_id: input.chain_id,
                    configuration_hash: input.configuration.digest(),
                    marker_signer: entry.marker.signer,
                    stable_intent_id: entry.marker.staging_intent_id,
                    staging_vout: entry.marker.staging_vout,
                    refund_script_sha256: entry.marker.refund_script_sha256,
                    refund_not_before_parent_height: entry.marker.refund_not_before_parent_height,
                };
                settlement_actions.push(BondSettlementActionV2::RefundRejectedEnqueue {
                    staging_intent_id: value.stable_intent_id(),
                    claimant: value.claimant.0,
                    bond_share_amount: value.requested_share_atoms,
                    staging_script_sha256: bond_inbox_redemption_staging_script_sha256_v2(
                        &input.configuration,
                        renderer,
                    )?,
                    source_txid: entry.source_txid,
                    source_vout: entry.marker.staging_vout,
                    source_authorization_commitment: entry.marker.source_authorization_commitment,
                    refund_script_sha256: value.refund_script_sha256,
                    refund_not_before_parent_height: value.refund_not_before_parent_height,
                });
            }
            processed.push(SuccessorBondInboxProcessedOutcomeV2::rejected(
                consumed, reason,
            ));
        } else {
            if matches!(
                action,
                SuccessorBondInboxUserActionV2::RedemptionCancellation(_)
            ) {
                if opening.is_some() || read_event.is_some() || accepted_kind.is_none() {
                    return Err(ProtocolError::InvalidBondState.into());
                }
            } else {
                if read_event.is_some() {
                    return Err(ProtocolError::InvalidBondState.into());
                }
                mutation_is_exact(
                    opening.as_ref().ok_or(ProtocolError::InvalidBondState)?,
                    action.signer().0,
                    accepted_kind.ok_or(ProtocolError::InvalidBondState)?,
                    mutation_event_id,
                    accepted_debit,
                    1,
                )?;
            }
            accepted_count = accepted_count
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            processed.push(SuccessorBondInboxProcessedOutcomeV2::accepted(consumed));
        }
    }

    if !mutations.is_empty() || !read_events.is_empty() {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let used_read_traders = input
        .read_only_action_events
        .iter()
        .map(|event| event.trader)
        .collect::<BTreeSet<_>>();
    if used_read_traders != authenticated_read_leaves.keys().copied().collect() {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let mut chained_outcome_root = input.previous_outcome_root;
    for outcome in &processed {
        chained_outcome_root =
            successor_bond_inbox_outcome_next_root_v2(chained_outcome_root, outcome)?;
    }
    let derived_outcome_count = input
        .previous_outcome_count
        .checked_add(
            u128::try_from(processed.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?,
        )
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if input.previous_outcome_root == [0; 32]
        || chained_outcome_root != input.next_outcome_root
        || derived_outcome_count != input.next_outcome_count
    {
        return Err(ProtocolError::InvalidBondInbox.into());
    }

    for execution in &input.redemption_executions {
        execution.validate()?;
        if state.capital_mode != CapitalModeV2::Normal {
            return Err(ProtocolError::InvalidBondState.into());
        }
        let queued = *queue.first().ok_or(ProtocolError::InvalidBondState)?;
        if execution.sequence != queued.sequence || execution.request_id != queued.request_id {
            return Err(ProtocolError::InvalidBondState.into());
        }
        let result = plan_successor_fifo_redemption_v2(state, queued, input.parent_height)?
            .ok_or(ProtocolError::InsufficientCollateral)?;
        if execution.redeemed_share_atoms != result.redeemed_share_atoms
            || execution.paid_usdd_atoms != result.paid_usdd_atoms
            || (result.remaining_entry_share_atoms == 0)
                != (execution.queue_remainder_output_opening_commitment == [0; 32])
        {
            return Err(ProtocolError::InvalidBondState.into());
        }
        settlement_actions.push(BondSettlementActionV2::ExecuteRedemption {
            redemption_id: queued.request_id,
            claimant: queued.claimant_commitment,
            queued_share_amount: queued.remaining_share_atoms,
            redeemed_share_amount: result.redeemed_share_atoms,
            remainder_share_amount: result.remaining_entry_share_atoms,
            usdd_payment_amount: u64::try_from(result.paid_usdd_atoms)
                .map_err(|_| ProtocolError::ArithmeticOverflow)?,
            destination_script_sha256: queued.destination_script_hash,
        });
        state.insurance_reserve = result.insurance_reserve_after;
        state.outstanding_share_atoms = result.outstanding_share_atoms_after;
        state.inventory_share_atoms = result.inventory_share_atoms_after;
        state.queued_redemption_share_atoms = result.queued_redemption_share_atoms_after;
        if result.remaining_entry_share_atoms == 0 {
            queue.remove(0);
        } else {
            queue[0].remaining_share_atoms = result.remaining_entry_share_atoms;
        }
        state.redemption_head = queue
            .first()
            .map(|item| item.sequence)
            .unwrap_or(state.redemption_tail);
        refresh_bond_derived(&mut state)?;
    }

    state.redemption_queue_root = successor_redemption_queue_root_v2(&queue)?;
    if state != input.next_bond
        || queue != input.next_queue
        || settlement_actions != input.settlement_actions
    {
        return Err(ProtocolError::InvalidBondState.into());
    }

    Ok(IncrementalBondActionChildPublicValuesV2 {
        configuration_hash: input.configuration.digest(),
        chain_id: input.chain_id,
        previous_bond_root: incremental_successor_bond_state_root_v2(input.previous_bond),
        next_bond_root: incremental_successor_bond_state_root_v2(input.next_bond),
        previous_queue_root: successor_redemption_queue_root_v2(&input.previous_queue)?,
        next_queue_root: successor_redemption_queue_root_v2(&input.next_queue)?,
        recovered_candidate_root: successor_recovered_candidate_root_v2(
            input.configuration.digest(),
            input.chain_id,
            &input.consumed_outcomes,
        )?,
        processed_outcome_root: processed_outcome_root(&processed),
        settlement_action_root: bond_settlement_action_root_v2(&settlement_actions),
        trader_economic_mutation_root: mutation_root,
        previous_trader_root_projection: incremental_trader_root_projection_v2(
            input.previous_trader_root,
        ),
        previous_outcome_root: input.previous_outcome_root,
        next_outcome_root: input.next_outcome_root,
        next_bond: input.next_bond,
        parent_height: input.parent_height,
        consumed_count: u64::try_from(input.consumed_outcomes.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        accepted_action_count: accepted_count,
        redemption_execution_count: u64::try_from(input.redemption_executions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        previous_outcome_count: input.previous_outcome_count,
        next_outcome_count: input.next_outcome_count,
        insurance_reserve_before_bond_actions: input.insurance_reserve_before_bond_actions,
        insurance_reserve_after: input.next_bond.insurance_reserve,
        queued_redemption_share_atoms_after: u128::from(
            input.next_bond.queued_redemption_share_atoms,
        ),
        full_bound_deficit_after: input.next_bond.full_bound_deficit,
        authorized_mutation_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_action_child_cap_composes_full_queues_and_trader_reads() {
        assert_eq!(SuccessorRedemptionQueueEntryV2::ENCODED_LEN, 145);
        assert_eq!(
            INCREMENTAL_BOND_ACTION_REACHABLE_ENCODING_CEILING_V2,
            9_699_328
        );
        assert_eq!(
            MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2,
            12 * 1024 * 1024
        );
    }

    #[test]
    fn bond_action_public_values_and_event_ids_are_exact_and_domain_separate() {
        let next_bond = SuccessorBondPublicStateV2 {
            version: ecx_protocol_core::SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: [22; 32],
            deployment_commitment: [23; 32],
            inventory_covenant_hash: [24; 32],
            insurance_reserve: 16,
            issued_share_atoms: ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS,
            outstanding_share_atoms: 100,
            inventory_share_atoms: ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS - 100,
            full_bound_deficit: 18,
            target_reserve: target_reserve_125(18).unwrap(),
            legacy_fee_pool: 0,
            redemption_queue_root: [25; 32],
            redemption_head: 1,
            redemption_tail: 2,
            queued_redemption_share_atoms: 17,
            capital_mode: capital_mode_for(16, 18).unwrap(),
        };
        let values = IncrementalBondActionChildPublicValuesV2 {
            configuration_hash: [1; 32],
            chain_id: [2; 32],
            previous_bond_root: [3; 32],
            next_bond_root: incremental_successor_bond_state_root_v2(next_bond),
            previous_queue_root: [5; 32],
            next_queue_root: [6; 32],
            recovered_candidate_root: [7; 32],
            processed_outcome_root: [8; 32],
            settlement_action_root: [9; 32],
            trader_economic_mutation_root: [10; 32],
            previous_trader_root_projection: [19; 32],
            previous_outcome_root: [20; 32],
            next_outcome_root: [21; 32],
            next_bond,
            parent_height: 11,
            consumed_count: 12,
            accepted_action_count: 13,
            redemption_execution_count: 14,
            previous_outcome_count: (1u128 << 96) + 22,
            next_outcome_count: (1u128 << 96) + 23,
            insurance_reserve_before_bond_actions: 15,
            insurance_reserve_after: 16,
            queued_redemption_share_atoms_after: 17,
            full_bound_deficit_after: 18,
            authorized_mutation_count: 1,
        };
        let bytes = values.encode();
        assert_eq!(
            bytes.len(),
            INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let decoded = decode_incremental_bond_action_child_projection_v2(&bytes).unwrap();
        assert_eq!(decoded.previous_bond_root, [3; 32]);
        assert_eq!(decoded.settlement_action_root, [9; 32]);
        assert_eq!(decoded.trader_economic_mutation_root, [10; 32]);
        assert_eq!(decoded.insurance_reserve_before_bond_actions, 15);
        assert_eq!(decoded.previous_outcome_count, (1u128 << 96) + 22);
        assert_eq!(decoded.next_outcome_count, (1u128 << 96) + 23);
        assert_eq!(decoded.next_bond.outstanding_share_atoms, 100);
        assert_eq!(decoded.next_bond.queued_redemption_share_atoms, 17);
        assert!(decode_incremental_bond_action_child_projection_v2(
            &bytes[..INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 1]
        )
        .is_err());

        let first = incremental_bond_trader_mutation_event_id_v2([1; 32], [2; 32]).unwrap();
        assert_ne!(
            first,
            incremental_bond_trader_mutation_event_id_v2([3; 32], [2; 32]).unwrap()
        );
        assert_ne!(
            first,
            incremental_bond_trader_mutation_event_id_v2([1; 32], [3; 32]).unwrap()
        );
        assert!(incremental_bond_trader_mutation_event_id_v2([0; 32], [2; 32]).is_err());
    }
}
