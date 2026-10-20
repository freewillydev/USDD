//! Recursive child authorizing deposits and withdrawals against exact trader,
//! deposit-inbox, nullifier-key, and confidential-settlement projections.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_protocol_core::{
    apply_incremental_trader_economic_mutation_v2, deposit_batch_root,
    incremental_deposit_inbox_state_hash_v2, successor_forced_action_batch_root_v2,
    successor_withdrawal_batch_root_v2, DepositInboxStateV1, DepositInboxTransitionV1,
    DepositRequest, Hash32, IncrementalSuccessorConfigurationV2,
    IncrementalTraderEconomicMutationV2, IncrementalTraderMutationChainV2,
    IncrementalTraderMutationKindV2, Int256V2, NullifierKindV2, ProtocolError,
    SuccessorForcedActionEntryV2, SuccessorForcedActionV2, SuccessorSignedWithdrawalRequestV2,
    TraderLeafV2, EXACT_ACCOUNTING_DENOMINATOR_V2, MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1,
};
use ecx_truthcoin_proof::{
    sp1_deferred_proof_marker, ConsensusProofVerificationError, ConsensusProofVerifier,
    DenyAllConsensusProofs,
};
use ecx_witness_availability::{
    custodian_registry_hash, verify_custody_receipts_compact, CustodianPublic, CustodyReceiptV1,
    RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    decode_incremental_deposit_source_projection_v2, incremental_nullifier_key_root_v2,
    incremental_trader_economic_mutation_root_v2, incremental_trader_insertion_root_v2,
    IncrementalCustodianPublicV2, IncrementalDepositSourceProjectionV2,
    IncrementalSettlementChildConfigurationV2, IncrementalTraderInsertionV2,
};

pub const INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 6;
pub const INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (14 * 32) + (8 * 8) + 4;
pub const MAX_INCREMENTAL_ACCOUNT_ACTION_CHILD_INPUT_BYTES_V2: usize = 1024 * 1024;
/// Exact fixed-int bincode length of the conservative structural maximum built
/// by `account_action_child_has_exact_structural_encoding_ceiling`: every
/// relation-bounded vector is simultaneously full and every per-chain optional
/// field uses its largest encoding. Several maxima are mutually unreachable,
/// so this is a safe upper bound for every valid account-action witness.
pub const INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2: usize = 961_332;
pub const DEPOSIT_INCLUSION_BLOCKS_INCREMENTAL_V2: u32 = 6;
const _: () = assert!(
    INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_ACCOUNT_ACTION_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalAccountActionConfigurationV2 {
    pub successor: IncrementalSuccessorConfigurationV2,
    pub settlement: IncrementalSettlementChildConfigurationV2,
    pub deposit_source_program_id: Hash32,
    pub deposit_source_custodian_registry_hash: Hash32,
}

impl IncrementalAccountActionConfigurationV2 {
    pub fn validate(self) -> Result<(), IncrementalAccountActionChildErrorV2> {
        self.successor.validate()?;
        self.settlement
            .validate()
            .map_err(|_| IncrementalAccountActionChildErrorV2::InvalidConfiguration)?;
        if self.deposit_source_program_id == [0; 32]
            || self.deposit_source_custodian_registry_hash == [0; 32]
            || self.deposit_source_program_id == self.deposit_source_custodian_registry_hash
        {
            return Err(IncrementalAccountActionChildErrorV2::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalAuthenticatedDepositReceiptV2 {
    pub program_id: Hash32,
    pub public_values: Vec<u8>,
    pub proof_marker: Hash32,
    pub bundle_root: Hash32,
    pub bundle_context: Hash32,
    pub child_witness_len: u64,
    pub custody_receipts: Vec<CustodyReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalAccountActionChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalAccountActionConfigurationV2,
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub previous_deposit_inbox: DepositInboxStateV1,
    pub next_deposit_inbox: DepositInboxStateV1,
    pub deposit_inbox_transition: DepositInboxTransitionV1,
    pub deposit_source_custodians: Vec<IncrementalCustodianPublicV2>,
    pub deposit_receipts: Vec<IncrementalAuthenticatedDepositReceiptV2>,
    /// Exact consumed entries authenticated by the separately proved forced
    /// inbox child. All action kinds consume account nonces in this order.
    pub forced_actions: Vec<SuccessorForcedActionEntryV2>,
    pub withdrawals: Vec<SuccessorSignedWithdrawalRequestV2>,
    pub trader_mutation_chains: Vec<IncrementalTraderMutationChainV2>,
    /// First-deposit account creations, ordered strictly by trader key.
    pub trader_insertions: Vec<IncrementalTraderInsertionV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalAccountActionChildPublicValuesV2 {
    pub successor_configuration_hash: Hash32,
    pub settlement_configuration_hash: Hash32,
    pub previous_deposit_inbox_state_hash: Hash32,
    pub next_deposit_inbox_state_hash: Hash32,
    pub previous_deposit_inbox_head_root: Hash32,
    pub next_deposit_inbox_head_root: Hash32,
    pub deposit_batch_root: Hash32,
    pub forced_action_batch_root: Hash32,
    pub forced_withdrawal_root: Hash32,
    pub withdrawal_batch_root: Hash32,
    pub trader_economic_mutation_root: Hash32,
    pub trader_insertion_root: Hash32,
    pub deposit_nullifier_key_root: Hash32,
    pub withdrawal_nullifier_key_root: Hash32,
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub previous_deposit_cursor: u64,
    pub next_deposit_cursor: u64,
    pub deposit_count: u64,
    pub withdrawal_count: u64,
    pub deposit_total: u64,
    pub withdrawal_total: u64,
    pub authorized_mutation_count: u16,
    pub trader_insertion_count: u16,
}

impl IncrementalAccountActionChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for hash in [
            self.successor_configuration_hash,
            self.settlement_configuration_hash,
            self.previous_deposit_inbox_state_hash,
            self.next_deposit_inbox_state_hash,
            self.previous_deposit_inbox_head_root,
            self.next_deposit_inbox_head_root,
            self.deposit_batch_root,
            self.forced_action_batch_root,
            self.forced_withdrawal_root,
            self.withdrawal_batch_root,
            self.trader_economic_mutation_root,
            self.trader_insertion_root,
            self.deposit_nullifier_key_root,
            self.withdrawal_nullifier_key_root,
        ] {
            out.extend_from_slice(&hash);
        }
        for value in [
            self.sidechain_height,
            self.parent_height,
            self.previous_deposit_cursor,
            self.next_deposit_cursor,
            self.deposit_count,
            self.withdrawal_count,
            self.deposit_total,
            self.withdrawal_total,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.authorized_mutation_count.to_be_bytes());
        out.extend_from_slice(&self.trader_insertion_count.to_be_bytes());
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

pub type IncrementalAccountActionChildProjectionV2 = IncrementalAccountActionChildPublicValuesV2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalAccountActionChildErrorV2 {
    #[error("invalid incremental account-action configuration")]
    InvalidConfiguration,
    #[error("unsupported incremental account-action version")]
    UnsupportedVersion,
    #[error("incremental account-action input exceeds its recoverable cap")]
    InputTooLarge,
    #[error("incremental account-action input encoding failed")]
    InputEncoding,
    #[error("invalid recursive deposit proof or availability")]
    InvalidDepositProof,
    #[error("account action rejected: {0}")]
    Protocol(#[from] ProtocolError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_deposit_source_bundle_context_v2(
    program_id: Hash32,
    public_values: &[u8],
    proof_marker: Hash32,
    registry_hash: Hash32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(96 + public_values.len());
    bytes.extend_from_slice(&program_id);
    bytes.extend_from_slice(&Sha256::digest(public_values));
    bytes.extend_from_slice(&proof_marker);
    bytes.extend_from_slice(&registry_hash);
    tagged_hash(b"ECX/incremental-deposit-source-bundle-context/v1", &bytes)
}

pub fn decode_incremental_account_action_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalAccountActionChildProjectionV2, IncrementalAccountActionChildErrorV2> {
    if bytes.len() != INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalAccountActionChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalAccountActionChildErrorV2> {
        let start = 4 + index * 32;
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalAccountActionChildErrorV2::UnsupportedVersion)
    };
    let u64_at = |index: usize| -> Result<u64, IncrementalAccountActionChildErrorV2> {
        let start = 4 + 14 * 32 + index * 8;
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalAccountActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    Ok(IncrementalAccountActionChildProjectionV2 {
        successor_configuration_hash: hash(0)?,
        settlement_configuration_hash: hash(1)?,
        previous_deposit_inbox_state_hash: hash(2)?,
        next_deposit_inbox_state_hash: hash(3)?,
        previous_deposit_inbox_head_root: hash(4)?,
        next_deposit_inbox_head_root: hash(5)?,
        deposit_batch_root: hash(6)?,
        forced_action_batch_root: hash(7)?,
        forced_withdrawal_root: hash(8)?,
        withdrawal_batch_root: hash(9)?,
        trader_economic_mutation_root: hash(10)?,
        trader_insertion_root: hash(11)?,
        deposit_nullifier_key_root: hash(12)?,
        withdrawal_nullifier_key_root: hash(13)?,
        sidechain_height: u64_at(0)?,
        parent_height: u64_at(1)?,
        previous_deposit_cursor: u64_at(2)?,
        next_deposit_cursor: u64_at(3)?,
        deposit_count: u64_at(4)?,
        withdrawal_count: u64_at(5)?,
        deposit_total: u64_at(6)?,
        withdrawal_total: u64_at(7)?,
        authorized_mutation_count: u16::from_be_bytes(
            bytes[INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 4
                ..INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 2]
                .try_into()
                .map_err(|_| IncrementalAccountActionChildErrorV2::UnsupportedVersion)?,
        ),
        trader_insertion_count: u16::from_be_bytes(
            bytes[INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 2..]
                .try_into()
                .map_err(|_| IncrementalAccountActionChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

fn verify_first_deposit_insertion(
    insertion: &IncrementalTraderInsertionV2,
    deposit: &DepositRequest,
    bounds: ecx_protocol_core::IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    insertion.leaf.validate(bounds)?;
    if insertion.deposit_request_id != deposit.request_id()
        || insertion.leaf.trader != deposit.trader
        || insertion.leaf.account_nonce != 0
        || insertion.leaf.collateral_atoms != i128::from(deposit.amount)
        || insertion.leaf.cash_residual_numerator != 0
        || insertion.leaf.position_size_atoms != 0
        || insertion.leaf.signed_cost_basis_numerator != Int256V2::ZERO
        || insertion.leaf.last_funding_index_numerator != 0
        || insertion.leaf.selected_initial_margin_bps != 10_000
        || insertion.leaf.order_generation != 0
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

#[derive(Clone)]
struct MutationOpening {
    before: TraderLeafV2,
    mutation: IncrementalTraderEconomicMutationV2,
    ordinal: usize,
}

fn require_later_account_action(
    last: &mut BTreeMap<[u8; 32], usize>,
    trader: [u8; 32],
    opening: &MutationOpening,
) -> Result<(), ProtocolError> {
    if last
        .insert(trader, opening.ordinal)
        .is_some_and(|previous| previous >= opening.ordinal)
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

fn exact_cash_delta(amount: u64, negative: bool) -> Result<Int256V2, ProtocolError> {
    let value = Int256V2::from_u128(
        u128::from(amount)
            .checked_mul(u128::from(EXACT_ACCOUNTING_DENOMINATOR_V2))
            .ok_or(ProtocolError::ArithmeticOverflow)?,
    );
    if negative {
        value.checked_neg()
    } else {
        Ok(value)
    }
}

fn verify_account_mutation(
    opening: &MutationOpening,
    kind: IncrementalTraderMutationKindV2,
    action_id: Hash32,
    amount: u64,
    expected_nonce: Option<u128>,
    configuration: IncrementalSuccessorConfigurationV2,
) -> Result<(), ProtocolError> {
    let mutation = &opening.mutation;
    let consumes_nonce = matches!(
        kind,
        IncrementalTraderMutationKindV2::Withdrawal
            | IncrementalTraderMutationKindV2::ForcedCancellation
            | IncrementalTraderMutationKindV2::ForcedReduceOnlyIoc
    );
    let withdraws_cash = kind == IncrementalTraderMutationKindV2::Withdrawal;
    if mutation.kind != kind
        || mutation.action_id != action_id
        || mutation.position_size_delta_atoms != 0
        || mutation.signed_cost_basis_delta_numerator != Int256V2::ZERO
        || mutation.funding_checkpoint_after.is_some()
        || mutation.order_generation_increment != 0
        || mutation.selected_initial_margin_bps_after.is_some()
        || mutation.exact_cash_delta_numerator != exact_cash_delta(amount, withdraws_cash)?
        || mutation.account_nonce_increment != u128::from(consumes_nonce)
        || expected_nonce.is_some_and(|nonce| opening.before.account_nonce != nonce)
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    apply_incremental_trader_economic_mutation_v2(
        &opening.before,
        mutation,
        configuration.accounting_bounds,
    )?;
    Ok(())
}

pub fn execute_incremental_account_action_child_v2(
    input: &IncrementalAccountActionChildInputV2,
) -> Result<IncrementalAccountActionChildPublicValuesV2, IncrementalAccountActionChildErrorV2> {
    execute_incremental_account_action_child_v2_with_consensus_verifier(
        input,
        &DenyAllConsensusProofs,
    )
}

pub fn execute_incremental_account_action_child_v2_with_consensus_verifier<
    V: ConsensusProofVerifier,
>(
    input: &IncrementalAccountActionChildInputV2,
    verifier: &V,
) -> Result<IncrementalAccountActionChildPublicValuesV2, IncrementalAccountActionChildErrorV2> {
    if input.version != INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2 {
        return Err(IncrementalAccountActionChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalAccountActionChildErrorV2::InputEncoding)?;
    let maximum = usize::from(input.configuration.successor.maximum_trader_updates);
    if encoded.len() > MAX_INCREMENTAL_ACCOUNT_ACTION_CHILD_INPUT_BYTES_V2
        || input.deposit_receipts.len() > maximum
        || input.forced_actions.len() > MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1
        || input.withdrawals.len() > maximum
        || input.trader_mutation_chains.len() > maximum
        || input.trader_insertions.len() > maximum
    {
        return Err(IncrementalAccountActionChildErrorV2::InputTooLarge);
    }
    input.deposit_inbox_transition.verify(
        input.configuration.successor.chain_id,
        input.previous_deposit_inbox,
        input.next_deposit_inbox,
        input.parent_height,
        DEPOSIT_INCLUSION_BLOCKS_INCREMENTAL_V2,
    )?;
    let consumed_count = input.deposit_inbox_transition.consumed()?.len();
    let events = &input.deposit_inbox_transition.pending_entries;
    if events.len() != input.deposit_receipts.len() {
        return Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof);
    }
    let custodians = input
        .deposit_source_custodians
        .iter()
        .copied()
        .map(CustodianPublic::from)
        .collect::<Vec<_>>();
    if custodians.len() != 5
        || custodian_registry_hash(&custodians)
            .map_err(|_| IncrementalAccountActionChildErrorV2::InvalidDepositProof)?
            != input.configuration.deposit_source_custodian_registry_hash
    {
        return Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof);
    }
    let mut deposits = Vec::with_capacity(events.len());
    for (event_offset, (event, receipt)) in events.iter().zip(&input.deposit_receipts).enumerate() {
        if receipt.program_id != input.configuration.deposit_source_program_id
            || receipt.proof_marker
                != sp1_deferred_proof_marker(receipt.program_id, &receipt.public_values)
            || receipt.custody_receipts.len() != RECOVERY_THRESHOLD
            || receipt.bundle_context
                != incremental_deposit_source_bundle_context_v2(
                    receipt.program_id,
                    &receipt.public_values,
                    receipt.proof_marker,
                    input.configuration.deposit_source_custodian_registry_hash,
                )
        {
            return Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof);
        }
        verifier
            .verify(
                receipt.program_id,
                &receipt.public_values,
                &receipt.proof_marker,
            )
            .map_err(|_: ConsensusProofVerificationError| {
                IncrementalAccountActionChildErrorV2::InvalidDepositProof
            })?;
        verify_custody_receipts_compact(
            receipt.bundle_root,
            receipt.bundle_context,
            receipt.child_witness_len,
            &custodians,
            &receipt.custody_receipts,
        )
        .map_err(|_| IncrementalAccountActionChildErrorV2::InvalidDepositProof)?;
        let projection: IncrementalDepositSourceProjectionV2 =
            decode_incremental_deposit_source_projection_v2(&receipt.public_values)
                .map_err(|_| IncrementalAccountActionChildErrorV2::InvalidDepositProof)?;
        if projection.event_hash != event.event_hash()
            || projection.chain_id != event.chain_id
            || projection.source_txid != event.source_txid
            || projection.output_sha256 != event.output_sha256
            || projection.trader != event.trader.0
            || projection.deposit_vout != event.deposit_vout
            || projection.observed_sidechain_height != event.observed_sidechain_height
            || projection.observed_parent_height != event.observed_parent_height
            || projection.event_index != event.index
            || projection.usdd_asset_id != input.configuration.settlement.usdd_asset_id
            || projection.vault_script_sha256
                != input
                    .configuration
                    .settlement
                    .collateral_vault_script_sha256
            || projection.observed_sidechain_height > input.sidechain_height
            || projection.observed_parent_height > input.parent_height
        {
            return Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof);
        }
        let deposit = DepositRequest {
            version: DepositRequest::VERSION,
            chain_id: projection.chain_id,
            deposit_txid: projection.source_txid,
            deposit_vout: projection.deposit_vout,
            usdd_asset_id: projection.usdd_asset_id,
            trader: event.trader,
            amount: projection.amount,
            observed_height: projection.observed_sidechain_height,
        };
        deposit.validate()?;
        if deposit.request_id() != projection.request_id {
            return Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof);
        }
        if event_offset < consumed_count {
            deposits.push(deposit);
        }
    }

    let mut forced_withdrawals = Vec::new();
    for entry in &input.forced_actions {
        entry.validate()?;
        if entry.chain_id != input.configuration.successor.chain_id
            || entry.enqueued_sidechain_height > input.sidechain_height
        {
            return Err(ProtocolError::InvalidForcedAction.into());
        }
        match &entry.action {
            SuccessorForcedActionV2::Cancel(value) => {
                if value.cancel.market != input.configuration.successor.market
                    || !value.cancel.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction.into());
                }
            }
            SuccessorForcedActionV2::ReduceOnlyIoc(value) => {
                if value.order.market != input.configuration.successor.market
                    || !value.order.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction.into());
                }
            }
            SuccessorForcedActionV2::Withdraw(value) => {
                if value.request.not_before_height > input.sidechain_height {
                    return Err(
                        ProtocolError::TransitionMismatch("forced withdrawal context").into(),
                    );
                }
                forced_withdrawals.push(value.clone());
            }
        }
    }
    for withdrawal in &input.withdrawals {
        withdrawal.verify()?;
        if withdrawal.request.chain_id != input.configuration.successor.chain_id
            || withdrawal.request.not_before_height > input.sidechain_height
        {
            return Err(ProtocolError::TransitionMismatch("withdrawal context").into());
        }
    }

    let mutation_root = incremental_trader_economic_mutation_root_v2(
        &input.trader_mutation_chains,
        input.configuration.successor.accounting_bounds,
    )?;
    let insertion_root = incremental_trader_insertion_root_v2(
        &input.trader_insertions,
        input.configuration.successor.accounting_bounds,
    )?;
    let mut insertions_by_request = BTreeMap::new();
    let mut insertion_traders = BTreeSet::new();
    for insertion in &input.trader_insertions {
        if insertions_by_request
            .insert(insertion.deposit_request_id, insertion)
            .is_some()
            || !insertion_traders.insert(insertion.leaf.trader.0)
        {
            return Err(ProtocolError::DuplicateRequest.into());
        }
    }
    let mut openings = BTreeMap::new();
    for chain in &input.trader_mutation_chains {
        if insertion_traders.contains(&chain.trader.0) {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let mut current = chain.old_leaf.clone();
        for (ordinal, mutation) in chain.mutations.iter().enumerate() {
            if matches!(
                mutation.kind,
                IncrementalTraderMutationKindV2::Deposit
                    | IncrementalTraderMutationKindV2::Withdrawal
                    | IncrementalTraderMutationKindV2::ForcedCancellation
                    | IncrementalTraderMutationKindV2::ForcedReduceOnlyIoc
            ) && openings
                .insert(
                    mutation.action_id,
                    MutationOpening {
                        before: current.clone(),
                        mutation: mutation.clone(),
                        ordinal,
                    },
                )
                .is_some()
            {
                return Err(ProtocolError::DuplicateRequest.into());
            }
            current = apply_incremental_trader_economic_mutation_v2(
                &current,
                mutation,
                input.configuration.successor.accounting_bounds,
            )?;
        }
    }
    let authorized_mutation_count =
        u16::try_from(openings.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let mut used = BTreeSet::new();
    let mut used_insertions = BTreeSet::new();
    let mut last_account_action = BTreeMap::new();
    let mut deposit_total = 0u64;
    for deposit in &deposits {
        let id = deposit.request_id();
        if let Some(opening) = openings.get(&id) {
            if !used.insert(id) || opening.before.trader != deposit.trader {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            require_later_account_action(
                &mut last_account_action,
                opening.before.trader.0,
                opening,
            )?;
            verify_account_mutation(
                opening,
                IncrementalTraderMutationKindV2::Deposit,
                id,
                deposit.amount,
                None,
                input.configuration.successor,
            )?;
        } else {
            let insertion = insertions_by_request
                .get(&id)
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            if !used_insertions.insert(id) {
                return Err(ProtocolError::DuplicateRequest.into());
            }
            verify_first_deposit_insertion(
                insertion,
                deposit,
                input.configuration.successor.accounting_bounds,
            )?;
        }
        deposit_total = deposit_total
            .checked_add(deposit.amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    let mut withdrawal_total = 0u64;
    for entry in &input.forced_actions {
        let (id, trader, nonce, kind, amount) = match &entry.action {
            SuccessorForcedActionV2::Cancel(value) => (
                value.cancel.cancel_id(),
                value.cancel.trader,
                value.cancel.nonce,
                IncrementalTraderMutationKindV2::ForcedCancellation,
                0,
            ),
            SuccessorForcedActionV2::ReduceOnlyIoc(value) => (
                value.order_id(),
                value.order.trader,
                value.order.nonce,
                IncrementalTraderMutationKindV2::ForcedReduceOnlyIoc,
                0,
            ),
            SuccessorForcedActionV2::Withdraw(value) => (
                value.request.request_id(),
                value.request.trader,
                value.request.nonce,
                IncrementalTraderMutationKindV2::Withdrawal,
                value.request.amount,
            ),
        };
        let opening = openings.get(&id).ok_or(ProtocolError::InvalidMerkleProof)?;
        if !used.insert(id) || opening.before.trader != trader {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        require_later_account_action(&mut last_account_action, opening.before.trader.0, opening)?;
        verify_account_mutation(
            opening,
            kind,
            id,
            amount,
            Some(nonce),
            input.configuration.successor,
        )?;
        withdrawal_total = withdrawal_total
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    for withdrawal in &input.withdrawals {
        let id = withdrawal.request.request_id();
        let opening = openings.get(&id).ok_or(ProtocolError::InvalidMerkleProof)?;
        if !used.insert(id) || opening.before.trader != withdrawal.request.trader {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        require_later_account_action(&mut last_account_action, opening.before.trader.0, opening)?;
        verify_account_mutation(
            opening,
            IncrementalTraderMutationKindV2::Withdrawal,
            id,
            withdrawal.request.amount,
            Some(withdrawal.request.nonce),
            input.configuration.successor,
        )?;
        withdrawal_total = withdrawal_total
            .checked_add(withdrawal.request.amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    if used.len() != openings.len() || used_insertions.len() != insertions_by_request.len() {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let mut settlement_withdrawals = input.withdrawals.clone();
    settlement_withdrawals.extend(forced_withdrawals.iter().cloned());
    Ok(IncrementalAccountActionChildPublicValuesV2 {
        successor_configuration_hash: input.configuration.successor.digest()?,
        settlement_configuration_hash: input
            .configuration
            .settlement
            .digest()
            .map_err(|_| IncrementalAccountActionChildErrorV2::InvalidConfiguration)?,
        previous_deposit_inbox_state_hash: incremental_deposit_inbox_state_hash_v2(
            input.previous_deposit_inbox,
        ),
        next_deposit_inbox_state_hash: incremental_deposit_inbox_state_hash_v2(
            input.next_deposit_inbox,
        ),
        previous_deposit_inbox_head_root: input.previous_deposit_inbox.head_root,
        next_deposit_inbox_head_root: input.next_deposit_inbox.head_root,
        deposit_batch_root: deposit_batch_root(&deposits),
        forced_action_batch_root: successor_forced_action_batch_root_v2(&input.forced_actions),
        forced_withdrawal_root: successor_withdrawal_batch_root_v2(&forced_withdrawals),
        withdrawal_batch_root: successor_withdrawal_batch_root_v2(&settlement_withdrawals),
        trader_economic_mutation_root: mutation_root,
        trader_insertion_root: insertion_root,
        deposit_nullifier_key_root: incremental_nullifier_key_root_v2(
            NullifierKindV2::Deposit,
            deposits.iter().map(DepositRequest::request_id),
        )?,
        withdrawal_nullifier_key_root: incremental_nullifier_key_root_v2(
            NullifierKindV2::Withdrawal,
            input
                .forced_actions
                .iter()
                .filter_map(|entry| match &entry.action {
                    SuccessorForcedActionV2::Withdraw(value) => Some(value),
                    SuccessorForcedActionV2::Cancel(_)
                    | SuccessorForcedActionV2::ReduceOnlyIoc(_) => None,
                })
                .chain(&input.withdrawals)
                .map(|withdrawal| withdrawal.request.request_id()),
        )?,
        sidechain_height: input.sidechain_height,
        parent_height: input.parent_height,
        previous_deposit_cursor: input.previous_deposit_inbox.cursor,
        next_deposit_cursor: input.next_deposit_inbox.cursor,
        deposit_count: u64::try_from(deposits.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        withdrawal_count: u64::try_from(settlement_withdrawals.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        deposit_total,
        withdrawal_total,
        authorized_mutation_count,
        trader_insertion_count: u16::try_from(input.trader_insertions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use ecx_elements_settlement::FrozenBondAssetV2;
    use ecx_protocol_core::{
        IncrementalAccountingBoundsV2, OrderFlags, Price, Quantity, RiskParams, Side,
        SuccessorCancelOrderV2, SuccessorLimitOrderV2, SuccessorSignedCancelOrderV2,
        SuccessorSignedLimitOrderV2, SuccessorWithdrawalRequestV2, TimeInForce, XOnlyKey,
        ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
    };
    use ecx_witness_availability::{create_bundle, CustodianSecrets};
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;

    struct MarkerVerifier;

    impl ConsensusProofVerifier for MarkerVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof: &[u8],
        ) -> Result<(), ConsensusProofVerificationError> {
            if proof == sp1_deferred_proof_marker(program_id, public_values) {
                Ok(())
            } else {
                Err(ConsensusProofVerificationError)
            }
        }
    }

    fn configuration() -> (
        IncrementalAccountActionConfigurationV2,
        Vec<IncrementalCustodianPublicV2>,
        Vec<CustodianSecrets>,
    ) {
        let successor = IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [0x11; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [0x12; 32],
            successor_matcher_configuration_hash: [0x13; 32],
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
        };
        let settlement = IncrementalSettlementChildConfigurationV2 {
            version: crate::INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2,
            usdd_asset_id: [1; 32],
            collateral_vault_script_sha256: [2; 32],
            insurance_reserve_script_sha256: [3; 32],
            frozen_bond_asset: FrozenBondAssetV2 {
                version: FrozenBondAssetV2::VERSION,
                asset_id: [4; 32],
                inventory_vault_script_sha256: [5; 32],
                redemption_queue_script_sha256: [6; 32],
                reissuance_token_burn_script_sha256: [7; 32],
            },
            previous_transaction_program_id: [8; 32],
            previous_transaction_custodian_registry_hash: [9; 32],
        };
        let secrets = (1..=5)
            .map(|index| CustodianSecrets::generate(index).unwrap())
            .collect::<Vec<_>>();
        let public = secrets
            .iter()
            .map(CustodianSecrets::public)
            .collect::<Vec<_>>();
        let registry_hash = custodian_registry_hash(&public).unwrap();
        let compact = public
            .into_iter()
            .map(|value| IncrementalCustodianPublicV2 {
                index: value.index,
                encryption_public_key: value.encryption_public_key,
                attestation_public_key: value.attestation_public_key,
            })
            .collect();
        (
            IncrementalAccountActionConfigurationV2 {
                successor,
                settlement,
                deposit_source_program_id: [10; 32],
                deposit_source_custodian_registry_hash: registry_hash,
            },
            compact,
            secrets,
        )
    }

    #[test]
    fn account_action_public_values_layout_is_exact() {
        let values = IncrementalAccountActionChildPublicValuesV2 {
            successor_configuration_hash: [1; 32],
            settlement_configuration_hash: [2; 32],
            previous_deposit_inbox_state_hash: [3; 32],
            next_deposit_inbox_state_hash: [4; 32],
            previous_deposit_inbox_head_root: [5; 32],
            next_deposit_inbox_head_root: [6; 32],
            deposit_batch_root: [7; 32],
            forced_action_batch_root: [20; 32],
            forced_withdrawal_root: [19; 32],
            withdrawal_batch_root: [8; 32],
            trader_economic_mutation_root: [9; 32],
            trader_insertion_root: [12; 32],
            deposit_nullifier_key_root: [10; 32],
            withdrawal_nullifier_key_root: [11; 32],
            sidechain_height: 10,
            parent_height: 11,
            previous_deposit_cursor: 12,
            next_deposit_cursor: 13,
            deposit_count: 14,
            withdrawal_count: 15,
            deposit_total: 16,
            withdrawal_total: 17,
            authorized_mutation_count: 18,
            trader_insertion_count: 19,
        };
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        assert_eq!(
            decode_incremental_account_action_projection_v2(&encoded).unwrap(),
            values
        );
        assert!(
            decode_incremental_account_action_projection_v2(&encoded[..encoded.len() - 1]).is_err()
        );
    }

    #[test]
    fn first_deposit_insertion_requires_exact_initial_account() {
        let (configuration, _, _) = configuration();
        let keypair =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[6; 32]).unwrap());
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let deposit = DepositRequest {
            version: DepositRequest::VERSION,
            chain_id: configuration.successor.chain_id,
            deposit_txid: [0x31; 32],
            deposit_vout: 2,
            usdd_asset_id: configuration.settlement.usdd_asset_id,
            trader,
            amount: 250,
            observed_height: 4,
        };
        let insertion = IncrementalTraderInsertionV2 {
            deposit_request_id: deposit.request_id(),
            leaf: TraderLeafV2 {
                version: TraderLeafV2::VERSION,
                trader,
                account_nonce: 0,
                collateral_atoms: 250,
                cash_residual_numerator: 0,
                position_size_atoms: 0,
                signed_cost_basis_numerator: Int256V2::ZERO,
                last_funding_index_numerator: 0,
                selected_initial_margin_bps: 10_000,
                order_generation: 0,
                salt: [0x32; 32],
            },
        };
        verify_first_deposit_insertion(
            &insertion,
            &deposit,
            configuration.successor.accounting_bounds,
        )
        .unwrap();

        let mut wrong_nonce = insertion.clone();
        wrong_nonce.leaf.account_nonce = 1;
        assert!(verify_first_deposit_insertion(
            &wrong_nonce,
            &deposit,
            configuration.successor.accounting_bounds,
        )
        .is_err());
        let mut wrong_collateral = insertion.clone();
        wrong_collateral.leaf.collateral_atoms -= 1;
        assert!(verify_first_deposit_insertion(
            &wrong_collateral,
            &deposit,
            configuration.successor.accounting_bounds,
        )
        .is_err());
        let mut wrong_request = insertion;
        wrong_request.deposit_request_id[0] ^= 1;
        assert!(verify_first_deposit_insertion(
            &wrong_request,
            &deposit,
            configuration.successor.accounting_bounds,
        )
        .is_err());
    }

    #[test]
    fn authenticated_first_deposit_executes_without_prior_account() {
        let (configuration, custodians, secrets) = configuration();
        let previous = DepositInboxStateV1::genesis(
            configuration.successor.digest().unwrap(),
            configuration.successor.chain_id,
        )
        .unwrap();
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[10; 32]).unwrap(),
        );
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let event = ecx_protocol_core::DepositEventV1 {
            version: 1,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: previous.head_root,
            observed_sidechain_height: 2,
            observed_parent_height: 3,
            source_txid: [0x81; 32],
            deposit_vout: 1,
            marker_vout: 2,
            output_sha256: [0x82; 32],
            trader,
        };
        let deposit = DepositRequest {
            version: DepositRequest::VERSION,
            chain_id: event.chain_id,
            deposit_txid: event.source_txid,
            deposit_vout: event.deposit_vout,
            usdd_asset_id: configuration.settlement.usdd_asset_id,
            trader,
            amount: 250,
            observed_height: event.observed_sidechain_height,
        };
        let public_values = crate::IncrementalDepositSourceChildPublicValuesV2 {
            chain_id: event.chain_id,
            event_hash: event.event_hash(),
            request_id: deposit.request_id(),
            source_txid: event.source_txid,
            output_sha256: event.output_sha256,
            trader: trader.0,
            usdd_asset_id: configuration.settlement.usdd_asset_id,
            vault_script_sha256: configuration.settlement.collateral_vault_script_sha256,
            deposit_vout: event.deposit_vout,
            amount: deposit.amount,
            observed_sidechain_height: event.observed_sidechain_height,
            observed_parent_height: event.observed_parent_height,
            event_index: event.index,
        }
        .encode();
        let proof_marker =
            sp1_deferred_proof_marker(configuration.deposit_source_program_id, &public_values);
        let bundle_context = incremental_deposit_source_bundle_context_v2(
            configuration.deposit_source_program_id,
            &public_values,
            proof_marker,
            configuration.deposit_source_custodian_registry_hash,
        );
        let public_custodians = secrets
            .iter()
            .map(CustodianSecrets::public)
            .collect::<Vec<_>>();
        let bundle = create_bundle(
            bundle_context,
            b"first-deposit-child-witness",
            &public_custodians,
        )
        .unwrap();
        let receipt = IncrementalAuthenticatedDepositReceiptV2 {
            program_id: configuration.deposit_source_program_id,
            public_values,
            proof_marker,
            bundle_root: bundle.root().unwrap(),
            bundle_context,
            child_witness_len: bundle.witness_len,
            custody_receipts: secrets[..RECOVERY_THRESHOLD]
                .iter()
                .map(|secret| secret.custody_receipt(&bundle).unwrap())
                .collect(),
        };
        let next = DepositInboxStateV1 {
            head_root: event.next_root(),
            entry_count: 1,
            processed_root: event.next_root(),
            cursor: 1,
        };
        let insertion = IncrementalTraderInsertionV2 {
            deposit_request_id: deposit.request_id(),
            leaf: TraderLeafV2 {
                version: TraderLeafV2::VERSION,
                trader,
                account_nonce: 0,
                collateral_atoms: i128::from(deposit.amount),
                cash_residual_numerator: 0,
                position_size_atoms: 0,
                signed_cost_basis_numerator: Int256V2::ZERO,
                last_funding_index_numerator: 0,
                selected_initial_margin_bps: 10_000,
                order_generation: 0,
                salt: [0x83; 32],
            },
        };
        let input = IncrementalAccountActionChildInputV2 {
            version: INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 4,
            parent_height: 4,
            previous_deposit_inbox: previous,
            next_deposit_inbox: next,
            deposit_inbox_transition: DepositInboxTransitionV1 {
                pending_entries: vec![event],
                consumed_count: 1,
            },
            deposit_source_custodians: custodians,
            deposit_receipts: vec![receipt],
            forced_actions: vec![],
            withdrawals: vec![],
            trader_mutation_chains: vec![],
            trader_insertions: vec![insertion],
        };
        let values = execute_incremental_account_action_child_v2_with_consensus_verifier(
            &input,
            &MarkerVerifier,
        )
        .unwrap();
        assert_eq!(values.deposit_count, 1);
        assert_eq!(values.deposit_total, 250);
        assert_eq!(values.authorized_mutation_count, 0);
        assert_eq!(values.trader_insertion_count, 1);

        let mut wrong_amount = input;
        wrong_amount.trader_insertions[0].leaf.collateral_atoms = 249;
        assert!(
            execute_incremental_account_action_child_v2_with_consensus_verifier(
                &wrong_amount,
                &MarkerVerifier,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_account_relation_binds_deposit_inbox_and_rejects_cursor_substitution() {
        let (configuration, custodians, _) = configuration();
        let state = DepositInboxStateV1::genesis(
            configuration.successor.digest().unwrap(),
            configuration.successor.chain_id,
        )
        .unwrap();
        let input = IncrementalAccountActionChildInputV2 {
            version: INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            parent_height: 1,
            previous_deposit_inbox: state,
            next_deposit_inbox: state,
            deposit_inbox_transition: DepositInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposit_source_custodians: custodians,
            deposit_receipts: vec![],
            forced_actions: vec![],
            withdrawals: vec![],
            trader_mutation_chains: vec![],
            trader_insertions: vec![],
        };
        let values = execute_incremental_account_action_child_v2(&input).unwrap();
        assert_eq!(
            values.previous_deposit_inbox_state_hash,
            values.next_deposit_inbox_state_hash
        );
        assert_eq!(values.deposit_count, 0);
        assert_eq!(values.withdrawal_count, 0);
        assert_eq!(values.authorized_mutation_count, 0);

        let mut unauthenticated_pending = input.clone();
        let event = ecx_protocol_core::DepositEventV1 {
            version: 1,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: state.head_root,
            observed_sidechain_height: 1,
            observed_parent_height: 1,
            source_txid: [0x47; 32],
            deposit_vout: 0,
            marker_vout: 1,
            output_sha256: [0x48; 32],
            trader: XOnlyKey(
                XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(
                    &Secp256k1::new(),
                    &SecretKey::from_slice(&[6; 32]).unwrap(),
                ))
                .0
                .serialize(),
            ),
        };
        unauthenticated_pending.next_deposit_inbox = DepositInboxStateV1 {
            head_root: event.next_root(),
            entry_count: 1,
            processed_root: state.processed_root,
            cursor: 0,
        };
        unauthenticated_pending
            .deposit_inbox_transition
            .pending_entries = vec![event];
        assert_eq!(
            execute_incremental_account_action_child_v2(&unauthenticated_pending),
            Err(IncrementalAccountActionChildErrorV2::InvalidDepositProof)
        );

        let mut substituted = input;
        substituted.next_deposit_inbox.cursor = 1;
        assert!(execute_incremental_account_action_child_v2(&substituted).is_err());
    }

    #[test]
    fn signed_withdrawal_authorizes_exact_cash_nonce_and_nullifier_only() {
        let (configuration, custodians, _) = configuration();
        let state = DepositInboxStateV1::genesis(
            configuration.successor.digest().unwrap(),
            configuration.successor.chain_id,
        )
        .unwrap();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let request = SuccessorWithdrawalRequestV2 {
            version: SuccessorWithdrawalRequestV2::VERSION,
            chain_id: configuration.successor.chain_id,
            trader,
            nonce: (1u128 << 96) + 3,
            amount: 25,
            destination_script_hash: [0x44; 32],
            requested_height: 1,
            not_before_height: 1,
        };
        let signed = SuccessorSignedWithdrawalRequestV2::sign(request, &secret).unwrap();
        let old_leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: (1u128 << 96) + 3,
            collateral_atoms: 100,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [0x45; 32],
        };
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::Withdrawal,
            action_id: signed.request.request_id(),
            exact_cash_delta_numerator: Int256V2::from_u128(
                u128::from(signed.request.amount) * u128::from(EXACT_ACCOUNTING_DENOMINATOR_V2),
            )
            .checked_neg()
            .unwrap(),
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: None,
            account_nonce_increment: 1,
            order_generation_increment: 0,
            selected_initial_margin_bps_after: None,
        };
        let mut expected_new_leaf = apply_incremental_trader_economic_mutation_v2(
            &old_leaf,
            &mutation,
            configuration.successor.accounting_bounds,
        )
        .unwrap();
        expected_new_leaf.salt = [0x46; 32];
        let chain = IncrementalTraderMutationChainV2 {
            trader,
            old_leaf,
            mutations: vec![mutation],
            final_salt: expected_new_leaf.salt,
            expected_new_leaf,
        };
        let input = IncrementalAccountActionChildInputV2 {
            version: INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            parent_height: 1,
            previous_deposit_inbox: state,
            next_deposit_inbox: state,
            deposit_inbox_transition: DepositInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposit_source_custodians: custodians,
            deposit_receipts: vec![],
            forced_actions: vec![],
            withdrawals: vec![signed.clone()],
            trader_mutation_chains: vec![chain],
            trader_insertions: vec![],
        };
        let values = execute_incremental_account_action_child_v2(&input).unwrap();
        assert_eq!(values.withdrawal_count, 1);
        assert_eq!(values.withdrawal_total, 25);
        assert_eq!(values.authorized_mutation_count, 1);

        let mut forced = input.clone();
        forced.withdrawals.clear();
        forced.forced_actions = vec![SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: [0x47; 32],
            enqueued_sidechain_height: 1,
            enqueued_parent_height: 1,
            source_txid: [0x48; 32],
            source_vout: 0,
            action: SuccessorForcedActionV2::Withdraw(signed.clone()),
        }];
        let forced_values = execute_incremental_account_action_child_v2(&forced).unwrap();
        assert_eq!(
            forced_values.forced_withdrawal_root,
            successor_withdrawal_batch_root_v2(&[signed])
        );
        assert_eq!(
            forced_values.withdrawal_batch_root,
            values.withdrawal_batch_root
        );

        let mut wrong_nonce_delta = input;
        wrong_nonce_delta.trader_mutation_chains[0].mutations[0].account_nonce_increment = 0;
        assert!(execute_incremental_account_action_child_v2(&wrong_nonce_delta).is_err());
    }

    #[test]
    fn forced_cancel_and_ioc_consume_nonces_in_exact_inbox_order() {
        let (configuration, custodians, _) = configuration();
        let state = DepositInboxStateV1::genesis(
            configuration.successor.digest().unwrap(),
            configuration.successor.chain_id,
        )
        .unwrap();
        let secret = SecretKey::from_slice(&[8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let cancel = SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
                chain_id: configuration.successor.chain_id,
                market: configuration.successor.market,
                trader,
                order_id: [0x51; 32],
                nonce: (1u128 << 96) + 5,
                valid_from_height: 1,
                expires_at_height: 20,
            },
            &secret,
        )
        .unwrap();
        let ioc = SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: configuration.successor.chain_id,
                market: configuration.successor.market,
                trader,
                side: Side::Sell,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::REDUCE_ONLY,
                limit_price: Price::new(100).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                client_order_id: [0x52; 16],
                max_fee_bps: 5,
                nonce: (1u128 << 96) + 6,
                valid_from_height: 1,
                expires_at_height: 20,
            },
            &secret,
        )
        .unwrap();
        let old_leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: (1u128 << 96) + 5,
            collateral_atoms: 100,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [0x53; 32],
        };
        let mutations = vec![
            IncrementalTraderEconomicMutationV2 {
                kind: IncrementalTraderMutationKindV2::ForcedCancellation,
                action_id: cancel.cancel.cancel_id(),
                exact_cash_delta_numerator: Int256V2::ZERO,
                position_size_delta_atoms: 0,
                signed_cost_basis_delta_numerator: Int256V2::ZERO,
                funding_checkpoint_after: None,
                account_nonce_increment: 1,
                order_generation_increment: 0,
                selected_initial_margin_bps_after: None,
            },
            IncrementalTraderEconomicMutationV2 {
                kind: IncrementalTraderMutationKindV2::ForcedReduceOnlyIoc,
                action_id: ioc.order_id(),
                exact_cash_delta_numerator: Int256V2::ZERO,
                position_size_delta_atoms: 0,
                signed_cost_basis_delta_numerator: Int256V2::ZERO,
                funding_checkpoint_after: None,
                account_nonce_increment: 1,
                order_generation_increment: 0,
                selected_initial_margin_bps_after: None,
            },
        ];
        let mut expected_new_leaf = old_leaf.clone();
        for mutation in &mutations {
            expected_new_leaf = apply_incremental_trader_economic_mutation_v2(
                &expected_new_leaf,
                mutation,
                configuration.successor.accounting_bounds,
            )
            .unwrap();
        }
        expected_new_leaf.salt = [0x54; 32];
        let chain = IncrementalTraderMutationChainV2 {
            trader,
            old_leaf,
            mutations,
            final_salt: expected_new_leaf.salt,
            expected_new_leaf,
        };
        let first = SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: [0x55; 32],
            enqueued_sidechain_height: 2,
            enqueued_parent_height: 2,
            source_txid: [0x56; 32],
            source_vout: 0,
            action: SuccessorForcedActionV2::Cancel(cancel),
        };
        let second = SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id: configuration.successor.chain_id,
            index: 1,
            previous_root: first.next_root(),
            enqueued_sidechain_height: 3,
            enqueued_parent_height: 3,
            source_txid: [0x57; 32],
            source_vout: 0,
            action: SuccessorForcedActionV2::ReduceOnlyIoc(ioc),
        };
        let input = IncrementalAccountActionChildInputV2 {
            version: INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 10,
            parent_height: 10,
            previous_deposit_inbox: state,
            next_deposit_inbox: state,
            deposit_inbox_transition: DepositInboxTransitionV1 {
                pending_entries: vec![],
                consumed_count: 0,
            },
            deposit_source_custodians: custodians,
            deposit_receipts: vec![],
            forced_actions: vec![first, second],
            withdrawals: vec![],
            trader_mutation_chains: vec![chain],
            trader_insertions: vec![],
        };
        let values = execute_incremental_account_action_child_v2(&input).unwrap();
        assert_eq!(values.authorized_mutation_count, 2);
        assert_eq!(values.withdrawal_count, 0);
        assert_eq!(values.withdrawal_total, 0);
        assert_eq!(
            values.forced_action_batch_root,
            successor_forced_action_batch_root_v2(&input.forced_actions)
        );

        let mut reordered = input;
        reordered.forced_actions.swap(0, 1);
        assert!(execute_incremental_account_action_child_v2(&reordered).is_err());
    }

    #[test]
    fn account_action_child_has_exact_structural_encoding_ceiling() {
        let (configuration, custodians, _) = configuration();
        let state = DepositInboxStateV1::genesis(
            configuration.successor.digest().unwrap(),
            configuration.successor.chain_id,
        )
        .unwrap();
        let secret = SecretKey::from_slice(&[11; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let event = ecx_protocol_core::DepositEventV1 {
            version: 1,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: [0x91; 32],
            observed_sidechain_height: 1,
            observed_parent_height: 1,
            source_txid: [0x92; 32],
            deposit_vout: 0,
            marker_vout: 1,
            output_sha256: [0x93; 32],
            trader,
        };
        let receipt = IncrementalAuthenticatedDepositReceiptV2 {
            program_id: configuration.deposit_source_program_id,
            public_values: vec![0; crate::INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2],
            proof_marker: [0x94; 32],
            bundle_root: [0x95; 32],
            bundle_context: [0x96; 32],
            child_witness_len: 1,
            custody_receipts: (1..=RECOVERY_THRESHOLD)
                .map(|index| CustodyReceiptV1 {
                    version: CustodyReceiptV1::VERSION,
                    bundle_root: [0x95; 32],
                    context: [0x96; 32],
                    witness_len: 1,
                    custodian_index: u8::try_from(index).unwrap(),
                    signature: [0x97; 64],
                })
                .collect(),
        };
        let withdrawal = SuccessorSignedWithdrawalRequestV2::sign(
            SuccessorWithdrawalRequestV2 {
                version: SuccessorWithdrawalRequestV2::VERSION,
                chain_id: configuration.successor.chain_id,
                trader,
                nonce: 1u128 << 96,
                amount: 1,
                destination_script_hash: [0x98; 32],
                requested_height: 1,
                not_before_height: 1,
            },
            &secret,
        )
        .unwrap();
        let ioc = SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: configuration.successor.chain_id,
                market: configuration.successor.market,
                trader,
                side: Side::Sell,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::REDUCE_ONLY,
                limit_price: Price::new(1).unwrap(),
                quantity: Quantity::new(1).unwrap(),
                client_order_id: [0x99; 16],
                max_fee_bps: 5,
                nonce: 1u128 << 96,
                valid_from_height: 1,
                expires_at_height: u64::MAX,
            },
            &secret,
        )
        .unwrap();
        let cancel = SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
                chain_id: configuration.successor.chain_id,
                market: configuration.successor.market,
                trader,
                order_id: [0x9a; 32],
                nonce: 1u128 << 96,
                valid_from_height: 1,
                expires_at_height: u64::MAX,
            },
            &secret,
        )
        .unwrap();
        let forced_ioc_action = SuccessorForcedActionV2::ReduceOnlyIoc(ioc);
        let option_len = |action: &SuccessorForcedActionV2| {
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(action)
                .unwrap()
                .len()
        };
        assert!(
            option_len(&forced_ioc_action) >= option_len(&SuccessorForcedActionV2::Cancel(cancel))
        );
        assert!(
            option_len(&forced_ioc_action)
                >= option_len(&SuccessorForcedActionV2::Withdraw(withdrawal.clone()))
        );
        let forced = SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: [0x9a; 32],
            enqueued_sidechain_height: 1,
            enqueued_parent_height: 1,
            source_txid: [0x9b; 32],
            source_vout: 0,
            action: forced_ioc_action,
        };
        let leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: 0,
            collateral_atoms: 1,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 10_000,
            order_generation: 0,
            salt: [0x9c; 32],
        };
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::ForcedReduceOnlyIoc,
            action_id: [0x9d; 32],
            exact_cash_delta_numerator: Int256V2::ZERO,
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: Some(i128::MAX),
            account_nonce_increment: 1,
            order_generation_increment: 1,
            selected_initial_margin_bps_after: Some(10_000),
        };
        let chain = IncrementalTraderMutationChainV2 {
            trader,
            old_leaf: leaf.clone(),
            mutations: vec![mutation; crate::MAX_INCREMENTAL_TRADER_MUTATIONS_PER_CHAIN_V2],
            final_salt: [0x9e; 32],
            expected_new_leaf: leaf.clone(),
        };
        let insertion = IncrementalTraderInsertionV2 {
            deposit_request_id: [0x9f; 32],
            leaf,
        };
        let maximum = usize::from(configuration.successor.maximum_trader_updates);
        let input = IncrementalAccountActionChildInputV2 {
            version: INCREMENTAL_ACCOUNT_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            parent_height: 1,
            previous_deposit_inbox: state,
            next_deposit_inbox: state,
            deposit_inbox_transition: DepositInboxTransitionV1 {
                pending_entries: vec![event; maximum],
                consumed_count: u32::try_from(maximum).unwrap(),
            },
            deposit_source_custodians: custodians,
            deposit_receipts: vec![receipt; maximum],
            forced_actions: vec![forced; MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1],
            withdrawals: vec![withdrawal; maximum],
            trader_mutation_chains: vec![chain; maximum],
            trader_insertions: vec![insertion; maximum],
        };
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialize(&input)
            .unwrap();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2
        );
    }
}
