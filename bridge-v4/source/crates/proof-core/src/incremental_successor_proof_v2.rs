//! Fresh proof boundary for the exact incremental successor slice.
//!
//! This is intentionally not `ProofInputV2`, PublicValuesV5, or an activation
//! artifact. It gives the future successor guest an exact binding and public
//! values format while the remaining source/settlement/risk/global-bound proof
//! classes are still composed.

use bincode::Options;
use ecx_protocol_core::{
    capital_mode_for, coverage_bps, nav_per_whole_share_usdd_atoms, target_reserve_125,
    CapitalModeV2, Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2,
    IncrementalSuccessorResultV2, OracleMode, ProtocolError, FUNDING_EPOCH_SECONDS,
};
use ecx_truthcoin_proof::{ConsensusProofVerifier, DenyAllConsensusProofs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    decode_incremental_account_action_projection_v2,
    decode_incremental_bond_action_child_projection_v2,
    decode_incremental_deficit_child_projection_v2,
    decode_incremental_economic_action_child_projection_v2,
    decode_incremental_forced_action_projection_v2,
    decode_incremental_funding_oracle_child_projection_v2,
    decode_incremental_inbox_source_child_projection_v2,
    decode_incremental_nullifier_child_projection_v2, decode_incremental_order_child_projection_v2,
    decode_incremental_risk_child_projection_v2, decode_incremental_settlement_child_projection_v2,
    decode_incremental_trader_child_projection_v2, incremental_deficit_root_projection_v2,
    incremental_nullifier_root_projection_v2, incremental_order_root_projection_v2,
    incremental_risk_root_projection_v2, incremental_trader_root_projection_v2,
    verify_incremental_child_availability_v2, IncrementalChildAvailabilityErrorV2,
    IncrementalChildAvailabilityV2, IncrementalChildClassV2, IncrementalCustodianPublicV2,
};

pub const INCREMENTAL_SUCCESSOR_PROOF_BINDING_VERSION_V2: u8 = 16;
pub const INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2: u32 = 23;
pub const INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2: usize =
    4 + (40 * 32) + (12 * 8) + (15 * 16) + 7;
/// Runtime denial-of-service cap only. This is deliberately not the unproven
/// 16 MiB availability-recovery bound or a production-readiness assertion.
pub const MAX_INCREMENTAL_SUCCESSOR_PROOF_INPUT_BYTES_V2: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSuccessorProofBindingV2 {
    pub version: u8,
    pub transition_txid_consensus: Hash32,
    pub prior_exchange_header_root: Hash32,
    pub prior_parent_block_hash: Hash32,
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub expected_configuration_hash: Hash32,
    pub expected_v18_configuration_hash: Hash32,
    pub expected_settlement_configuration_hash: Hash32,
    pub expected_chain_id: Hash32,
    pub expected_custodian_registry_hash: Hash32,
    pub expected_previous_state_root: Hash32,
    pub expected_next_state_root: Hash32,
    pub expected_previous_inbox_state_hash: Hash32,
    pub expected_next_inbox_state_hash: Hash32,
    pub expected_previous_deposit_inbox_head_root: Hash32,
    pub expected_next_deposit_inbox_head_root: Hash32,
    pub expected_previous_forced_inbox_head_root: Hash32,
    pub expected_next_forced_inbox_head_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSuccessorProofInputV2 {
    pub binding: IncrementalSuccessorProofBindingV2,
    pub configuration: IncrementalSuccessorConfigurationV2,
    /// Only the authenticated public predecessor/successor records remain in
    /// the outer input. All state mutation paths live exclusively in their
    /// recursively verified child witnesses.
    pub previous_state: IncrementalPublicStateV2,
    pub next_state: IncrementalPublicStateV2,
    pub child_availability: Vec<IncrementalChildAvailabilityV2>,
    pub custodian_registry: Vec<IncrementalCustodianPublicV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSuccessorProofPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub transition_txid_consensus: Hash32,
    pub prior_exchange_header_root: Hash32,
    pub prior_parent_block_hash: Hash32,
    pub risk_extrema_root: Hash32,
    pub child_availability_root: Hash32,
    pub custodian_registry_hash: Hash32,
    pub settlement_action_root: Hash32,
    pub combined_settlement_root: Hash32,
    pub settlement_configuration_hash: Hash32,
    pub v18_configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub bond_asset_id: Hash32,
    pub bond_deployment_commitment: Hash32,
    pub bond_inventory_covenant_hash: Hash32,
    pub bond_state_root: Hash32,
    pub funding_state_root: Hash32,
    pub redemption_queue_root: Hash32,
    pub oracle_certificate_hash: Hash32,
    pub matcher_execution_receipt_batch_root: Hash32,
    pub next_bond_inbox_head_root: Hash32,
    pub next_bond_inbox_processed_root: Hash32,
    pub next_bond_inbox_outcome_root: Hash32,
    pub previous_inbox_state_hash: Hash32,
    pub next_inbox_state_hash: Hash32,
    pub recovered_inbox_candidate_root: Hash32,
    pub trader_update_transcript_root: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub trader_economic_mutation_root: Hash32,
    /// Domain-separated commitment to every action-class root used by the
    /// outer composition. This is not a replacement for the exact equality
    /// checks below; it makes their ordered composition public and prevents a
    /// consumer from treating any individually authenticated action root as
    /// optional metadata.
    pub action_composition_root: Hash32,
    pub previous_deposit_inbox_state_hash: Hash32,
    pub next_deposit_inbox_state_hash: Hash32,
    pub previous_deposit_inbox_head_root: Hash32,
    pub next_deposit_inbox_head_root: Hash32,
    pub previous_forced_inbox_state_hash: Hash32,
    pub next_forced_inbox_state_hash: Hash32,
    pub previous_forced_inbox_head_root: Hash32,
    pub next_forced_inbox_head_root: Hash32,
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub sidechain_height: u64,
    pub mark_price_atoms: u64,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
    pub issued_share_atoms: u64,
    pub outstanding_share_atoms: u64,
    pub inventory_share_atoms: u64,
    pub queued_redemption_share_atoms: u64,
    pub funding_epoch: u64,
    pub oracle_valid_through_parent_mtp: u64,
    pub global_funding_index_numerator: i128,
    pub lower_deficit_atoms: u128,
    pub upper_deficit_atoms: u128,
    pub full_range_deficit_atoms: u128,
    pub target_reserve_atoms: u128,
    pub insurance_reserve_atoms: u128,
    pub controlled_usdd_atoms: u128,
    pub matcher_sequence: u128,
    pub nav_per_whole_share_usdd_atoms: u128,
    pub coverage_bps: u128,
    pub redemption_head: u128,
    pub redemption_tail: u128,
    pub bond_inbox_entry_count: u128,
    pub bond_inbox_processed_cursor: u128,
    pub bond_inbox_outcome_count: u128,
    pub funding_rate_ppm: i32,
    pub capital_mode: CapitalModeV2,
    pub oracle_mode: OracleMode,
    pub operationally_safe: bool,
}

impl IncrementalSuccessorProofPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.previous_state_root,
            self.next_state_root,
            self.transition_txid_consensus,
            self.prior_exchange_header_root,
            self.prior_parent_block_hash,
            self.risk_extrema_root,
            self.child_availability_root,
            self.custodian_registry_hash,
            self.settlement_action_root,
            self.combined_settlement_root,
            self.settlement_configuration_hash,
            self.v18_configuration_hash,
            self.chain_id,
            self.bond_asset_id,
            self.bond_deployment_commitment,
            self.bond_inventory_covenant_hash,
            self.bond_state_root,
            self.funding_state_root,
            self.redemption_queue_root,
            self.oracle_certificate_hash,
            self.matcher_execution_receipt_batch_root,
            self.next_bond_inbox_head_root,
            self.next_bond_inbox_processed_root,
            self.next_bond_inbox_outcome_root,
            self.previous_inbox_state_hash,
            self.next_inbox_state_hash,
            self.recovered_inbox_candidate_root,
            self.trader_update_transcript_root,
            self.trader_update_leaf_projection_root,
            self.trader_economic_mutation_root,
            self.action_composition_root,
            self.previous_deposit_inbox_state_hash,
            self.next_deposit_inbox_state_hash,
            self.previous_deposit_inbox_head_root,
            self.next_deposit_inbox_head_root,
            self.previous_forced_inbox_state_hash,
            self.next_forced_inbox_state_hash,
            self.previous_forced_inbox_head_root,
            self.next_forced_inbox_head_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.prior_parent_height.to_be_bytes());
        out.extend_from_slice(&self.prior_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.sidechain_height.to_be_bytes());
        out.extend_from_slice(&self.mark_price_atoms.to_be_bytes());
        out.extend_from_slice(&self.price_lower_atoms.to_be_bytes());
        out.extend_from_slice(&self.price_upper_atoms.to_be_bytes());
        out.extend_from_slice(&self.issued_share_atoms.to_be_bytes());
        out.extend_from_slice(&self.outstanding_share_atoms.to_be_bytes());
        out.extend_from_slice(&self.inventory_share_atoms.to_be_bytes());
        out.extend_from_slice(&self.queued_redemption_share_atoms.to_be_bytes());
        out.extend_from_slice(&self.funding_epoch.to_be_bytes());
        out.extend_from_slice(&self.oracle_valid_through_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.global_funding_index_numerator.to_be_bytes());
        for value in [
            self.lower_deficit_atoms,
            self.upper_deficit_atoms,
            self.full_range_deficit_atoms,
            self.target_reserve_atoms,
            self.insurance_reserve_atoms,
            self.controlled_usdd_atoms,
            self.matcher_sequence,
            self.nav_per_whole_share_usdd_atoms,
            self.coverage_bps,
            self.redemption_head,
            self.redemption_tail,
            self.bond_inbox_entry_count,
            self.bond_inbox_processed_cursor,
            self.bond_inbox_outcome_count,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.funding_rate_ppm.to_be_bytes());
        out.push(self.capital_mode as u8);
        out.push(self.oracle_mode as u8);
        out.push(u8::from(self.operationally_safe));
        debug_assert_eq!(out.len(), INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalSuccessorProofResultV2 {
    pub relation: IncrementalSuccessorResultV2,
    pub public_values: Vec<u8>,
    pub public_values_sha256: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalSuccessorProofErrorV2 {
    #[error("unsupported incremental successor proof binding")]
    UnsupportedVersion,
    #[error("zero incremental successor binding identity: {0}")]
    ZeroIdentity(&'static str),
    #[error("incremental successor binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("incremental successor input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental successor relation rejected: {0}")]
    Relation(#[from] ProtocolError),
    #[error("incremental successor recursive availability rejected: {0}")]
    ChildAvailability(#[from] IncrementalChildAvailabilityErrorV2),
    #[error("incremental successor input encoding failed")]
    InputEncoding,
}

fn canonical_input_bytes_v2(
    input: &IncrementalSuccessorProofInputV2,
) -> Result<Vec<u8>, IncrementalSuccessorProofErrorV2> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalSuccessorProofErrorV2::InputEncoding)
}

fn sha256(bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn incremental_action_composition_root_v2(
    recovered_candidate_root: Hash32,
    processed_outcome_root: Hash32,
    settlement_action_root: Hash32,
    economic_action_root: Hash32,
    deposit_batch_root: Hash32,
    forced_action_batch_root: Hash32,
    forced_withdrawal_root: Hash32,
    withdrawal_batch_root: Hash32,
    forced_cancel_root: Hash32,
    forced_ioc_root: Hash32,
    ordinary_execution_root: Hash32,
    forced_ioc_execution_root: Hash32,
    liquidation_observation_root: Hash32,
    trader_economic_mutation_root: Hash32,
    combined_settlement_root: Hash32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(15 * 32);
    for root in [
        recovered_candidate_root,
        processed_outcome_root,
        settlement_action_root,
        economic_action_root,
        deposit_batch_root,
        forced_action_batch_root,
        forced_withdrawal_root,
        withdrawal_batch_root,
        forced_cancel_root,
        forced_ioc_root,
        ordinary_execution_root,
        forced_ioc_execution_root,
        liquidation_observation_root,
        trader_economic_mutation_root,
        combined_settlement_root,
    ] {
        bytes.extend_from_slice(&root);
    }
    tagged_hash(b"ECX/incremental-action-composition/v1", &bytes)
}

pub fn execute_incremental_successor_proof_v2(
    input: &IncrementalSuccessorProofInputV2,
) -> Result<IncrementalSuccessorProofResultV2, IncrementalSuccessorProofErrorV2> {
    execute_incremental_successor_proof_v2_with_consensus_verifier(input, &DenyAllConsensusProofs)
}

pub fn execute_incremental_successor_proof_v2_with_consensus_verifier<V: ConsensusProofVerifier>(
    input: &IncrementalSuccessorProofInputV2,
    verifier: &V,
) -> Result<IncrementalSuccessorProofResultV2, IncrementalSuccessorProofErrorV2> {
    if input.binding.version != INCREMENTAL_SUCCESSOR_PROOF_BINDING_VERSION_V2 {
        return Err(IncrementalSuccessorProofErrorV2::UnsupportedVersion);
    }
    for (name, value) in [
        ("transition txid", input.binding.transition_txid_consensus),
        (
            "prior exchange header root",
            input.binding.prior_exchange_header_root,
        ),
        ("prior parent block", input.binding.prior_parent_block_hash),
        ("configuration", input.binding.expected_configuration_hash),
        (
            "V18 configuration",
            input.binding.expected_v18_configuration_hash,
        ),
        (
            "settlement configuration",
            input.binding.expected_settlement_configuration_hash,
        ),
        ("chain", input.binding.expected_chain_id),
        (
            "custodian registry",
            input.binding.expected_custodian_registry_hash,
        ),
        ("previous state", input.binding.expected_previous_state_root),
        ("next state", input.binding.expected_next_state_root),
        (
            "previous inbox state",
            input.binding.expected_previous_inbox_state_hash,
        ),
        (
            "next inbox state",
            input.binding.expected_next_inbox_state_hash,
        ),
        (
            "previous deposit inbox head",
            input.binding.expected_previous_deposit_inbox_head_root,
        ),
        (
            "next deposit inbox head",
            input.binding.expected_next_deposit_inbox_head_root,
        ),
        (
            "previous forced inbox head",
            input.binding.expected_previous_forced_inbox_head_root,
        ),
        (
            "next forced inbox head",
            input.binding.expected_next_forced_inbox_head_root,
        ),
    ] {
        if value == [0; 32] {
            return Err(IncrementalSuccessorProofErrorV2::ZeroIdentity(name));
        }
    }
    if input.binding.prior_parent_height == 0 || input.binding.prior_parent_mtp == 0 {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "prior parent context",
        ));
    }
    let encoded = canonical_input_bytes_v2(input)?;
    if encoded.len() > MAX_INCREMENTAL_SUCCESSOR_PROOF_INPUT_BYTES_V2 {
        return Err(IncrementalSuccessorProofErrorV2::InputTooLarge);
    }
    let configuration_hash = input.configuration.digest()?;
    if configuration_hash != input.binding.expected_configuration_hash {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "configuration hash",
        ));
    }
    input.previous_state.validate(input.configuration)?;
    input.next_state.validate(input.configuration)?;
    // The node permits blocks that carry the singleton forward unchanged.
    // A later proof consequently binds the actual authenticated block height,
    // which must advance strictly but may skip carry-forward blocks.
    if input.next_state.sidechain_height <= input.previous_state.sidechain_height
        || input.next_state.parent_median_time_past < input.previous_state.parent_median_time_past
        || input.next_state.matcher_sequence < input.previous_state.matcher_sequence
    {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let child_availability_root = verify_incremental_child_availability_v2(
        &input.child_availability,
        &input.custodian_registry,
        input.binding.expected_custodian_registry_hash,
        verifier,
    )?;
    let trader_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Trader)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "trader child",
        ))?;
    let trader = decode_incremental_trader_child_projection_v2(&trader_descriptor.public_values)
        .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("trader child"))?;
    if trader.configuration_hash != configuration_hash
        || trader.previous_root_projection
            != incremental_trader_root_projection_v2(input.previous_state.trader_root)
        || trader.next_root_projection
            != incremental_trader_root_projection_v2(input.next_state.trader_root)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "trader child roots",
        ));
    }
    let deficit_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Deficit)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "deficit child",
        ))?;
    let deficit = decode_incremental_deficit_child_projection_v2(&deficit_descriptor.public_values)
        .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("deficit child"))?;
    if deficit.configuration_hash != configuration_hash
        || deficit.trader_update_leaf_projection_root != trader.update_leaf_projection_root
        || deficit.next_trader_root_projection
            != incremental_trader_root_projection_v2(input.next_state.trader_root)
        || deficit.previous_long_root_projection
            != incremental_deficit_root_projection_v2(input.previous_state.long_deficit_root)
        || deficit.previous_short_root_projection
            != incremental_deficit_root_projection_v2(input.previous_state.short_deficit_root)
        || deficit.next_long_root_projection
            != incremental_deficit_root_projection_v2(input.next_state.long_deficit_root)
        || deficit.next_short_root_projection
            != incremental_deficit_root_projection_v2(input.next_state.short_deficit_root)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "deficit child roots, trader updates, or endpoints",
        ));
    }
    let risk_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Risk)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "risk child",
        ))?;
    let risk = decode_incremental_risk_child_projection_v2(&risk_descriptor.public_values)
        .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("risk child"))?;
    if risk.configuration_hash != configuration_hash
        || risk.trader_update_leaf_projection_root != trader.update_leaf_projection_root
        || risk.previous_root_projection
            != incremental_risk_root_projection_v2(input.previous_state.risk_extrema_root)
        || risk.next_root_projection
            != incremental_risk_root_projection_v2(input.next_state.risk_extrema_root)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "risk child roots, trader updates, or operational result",
        ));
    }
    let nullifier_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Nullifiers)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "nullifier child",
        ))?;
    let nullifiers =
        decode_incremental_nullifier_child_projection_v2(&nullifier_descriptor.public_values)
            .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("nullifier child"))?;
    if nullifiers.configuration_hash != configuration_hash
        || nullifiers.previous_deposit_root_projection
            != incremental_nullifier_root_projection_v2(input.previous_state.deposit_nullifier_root)
        || nullifiers.next_deposit_root_projection
            != incremental_nullifier_root_projection_v2(input.next_state.deposit_nullifier_root)
        || nullifiers.previous_withdrawal_root_projection
            != incremental_nullifier_root_projection_v2(
                input.previous_state.withdrawal_nullifier_root,
            )
        || nullifiers.next_withdrawal_root_projection
            != incremental_nullifier_root_projection_v2(input.next_state.withdrawal_nullifier_root)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "nullifier child roots",
        ));
    }
    let order_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Order)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "order child",
        ))?;
    let order = decode_incremental_order_child_projection_v2(&order_descriptor.public_values)
        .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("order child"))?;
    if order.configuration_hash != configuration_hash
        || order.trader_update_leaf_projection_root != trader.update_leaf_projection_root
        || order.previous_trader_root_projection
            != incremental_trader_root_projection_v2(input.previous_state.trader_root)
        || order.previous_order_root_projection
            != incremental_order_root_projection_v2(input.previous_state.order_root)
        || order.next_order_root_projection
            != incremental_order_root_projection_v2(input.next_state.order_root)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "order child roots or trader updates",
        ));
    }
    let funding_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::FundingOracle)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "funding/oracle child",
        ))?;
    let funding =
        decode_incremental_funding_oracle_child_projection_v2(&funding_descriptor.public_values)
            .map_err(|_| {
                IncrementalSuccessorProofErrorV2::BindingMismatch("funding/oracle child")
            })?;
    if funding.successor_configuration_hash != configuration_hash
        || funding.v18_configuration_hash != input.binding.expected_v18_configuration_hash
        || funding.chain_id != input.binding.expected_chain_id
        || funding.parent_block_hash != input.binding.prior_parent_block_hash
        || funding.parent_height != input.binding.prior_parent_height
        || funding.parent_mtp != input.binding.prior_parent_mtp
        || funding.previous_funding_root != input.previous_state.funding_state_root
        || funding.next_funding_root != input.next_state.funding_state_root
        || funding.mark_price_atoms != input.next_state.mark_price_atoms
        || funding.authenticated_min_price_atoms != input.next_state.price_lower_atoms
        || funding.authenticated_max_price_atoms != input.next_state.price_upper_atoms
        || funding.previous_global_funding_index_numerator
            != input.previous_state.global_funding_index_numerator
        || funding.next_global_funding_index_numerator
            != input.next_state.global_funding_index_numerator
        || funding.previous_match_sequence != input.previous_state.matcher_sequence
        || funding.next_match_sequence != input.next_state.matcher_sequence
        || funding.liquidation_observation_root != order.liquidation_observation_root
        || funding.liquidation_observation_count != u64::from(order.liquidation_count)
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "funding/oracle source, roots, or index",
        ));
    }
    let settlement_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::Settlement)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "settlement child",
        ))?;
    let settlement =
        decode_incremental_settlement_child_projection_v2(&settlement_descriptor.public_values)
            .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("settlement child"))?;
    let next_controlled = u128::from(settlement.collateral_vault_change_total)
        .checked_add(u128::from(settlement.insurance_reserve_output_total))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if settlement.configuration_hash != input.binding.expected_settlement_configuration_hash
        || settlement.transition_txid != input.binding.transition_txid_consensus
        || next_controlled != input.next_state.controlled_usdd_atoms
        || u128::from(settlement.insurance_reserve_input_total)
            != input.previous_state.insurance_reserve_atoms
        || u128::from(settlement.insurance_reserve_output_total)
            != input.next_state.insurance_reserve_atoms
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "settlement transaction or reserve flow",
        ));
    }
    let inbox_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::InboxSource)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "inbox source child",
        ))?;
    let inbox =
        decode_incremental_inbox_source_child_projection_v2(&inbox_descriptor.public_values)
            .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("inbox source child"))?;
    if inbox.configuration_hash != input.binding.expected_v18_configuration_hash
        || inbox.chain_id != input.binding.expected_chain_id
        || inbox.previous_state_hash != input.binding.expected_previous_inbox_state_hash
        || inbox.next_state_hash != input.binding.expected_next_inbox_state_hash
        || inbox.previous_state_hash != input.previous_state.bond_inbox_state_hash
        || inbox.next_state_hash != input.next_state.bond_inbox_state_hash
        || inbox.parent_height != input.binding.prior_parent_height
        || inbox.transition_sidechain_height != input.next_state.sidechain_height
        || inbox.staging_source_projection_root != settlement.staging_source_projection_root
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "inbox source state or context",
        ));
    }
    let bond_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::BondActions)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "bond action child",
        ))?;
    let bond =
        decode_incremental_bond_action_child_projection_v2(&bond_descriptor.public_values)
            .map_err(|_| IncrementalSuccessorProofErrorV2::BindingMismatch("bond action child"))?;
    let economic_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::EconomicActions)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "economic action child",
        ))?;
    let economic =
        decode_incremental_economic_action_child_projection_v2(&economic_descriptor.public_values)
            .map_err(|_| {
                IncrementalSuccessorProofErrorV2::BindingMismatch("economic action child")
            })?;
    let reserve_after_matcher_economics = economic
        .previous_insurance_reserve_atoms
        .checked_add(economic.protocol_fee_atoms)
        .and_then(|value| value.checked_sub(economic.liquidation_loss_atoms))
        .ok_or(ProtocolError::InvalidBondState)?;
    let account_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::AccountActions)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "account action child",
        ))?;
    let account =
        decode_incremental_account_action_projection_v2(&account_descriptor.public_values)
            .map_err(|_| {
                IncrementalSuccessorProofErrorV2::BindingMismatch("account action child")
            })?;
    let forced_descriptor = input
        .child_availability
        .iter()
        .find(|descriptor| descriptor.class == IncrementalChildClassV2::ForcedActions)
        .ok_or(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "forced action child",
        ))?;
    let forced = decode_incremental_forced_action_projection_v2(&forced_descriptor.public_values)
        .map_err(|_| {
        IncrementalSuccessorProofErrorV2::BindingMismatch("forced action child")
    })?;
    let reserve_after_actions = bond
        .insurance_reserve_before_bond_actions
        .checked_add(u128::from(settlement.subscription_contribution_total))
        .and_then(|value| {
            value.checked_add(u128::from(settlement.recapitalization_contribution_total))
        })
        .and_then(|value| value.checked_sub(u128::from(settlement.redemption_payment_total)))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let authorized_mutation_count = u32::from(bond.authorized_mutation_count)
        .checked_add(u32::from(economic.authorized_mutation_count))
        .and_then(|count| count.checked_add(u32::from(account.authorized_mutation_count)))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let expected_collateral_inputs = input
        .previous_state
        .controlled_usdd_atoms
        .checked_add(u128::from(account.deposit_total))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let expected_collateral_outputs = input
        .next_state
        .controlled_usdd_atoms
        .checked_add(u128::from(account.withdrawal_total))
        .and_then(|value| value.checked_add(u128::from(settlement.redemption_payment_total)))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let previous_forced_pending = forced
        .previous_entry_count
        .checked_sub(forced.previous_cursor)
        .ok_or(ProtocolError::InvalidForcedInbox)?;
    let forced_order_lane_active = previous_forced_pending != 0
        || forced.consumed_count != 0
        || order.forced_ioc_count != 0
        || order.forced_cancel_count != 0;
    let forced_order_operation_count = order
        .forced_cancel_count
        .checked_add(order.forced_ioc_execution_count)
        .and_then(|value| value.checked_add(order.prune_count))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if bond.configuration_hash != inbox.configuration_hash
        || bond.chain_id != inbox.chain_id
        || bond.previous_bond_root != input.previous_state.bond_state_root
        || bond.next_bond_root != input.next_state.bond_state_root
        || bond.recovered_candidate_root != inbox.recovered_candidate_root
        || bond.settlement_action_root != settlement.action_root
        || bond.trader_economic_mutation_root != trader.economic_mutation_root
        || bond.previous_trader_root_projection != trader.previous_root_projection
        || bond.previous_outcome_root != input.previous_state.bond_inbox_outcome_root
        || bond.next_outcome_root != input.next_state.bond_inbox_outcome_root
        || bond.previous_outcome_count != input.previous_state.bond_inbox_outcome_count
        || bond.next_outcome_count != input.next_state.bond_inbox_outcome_count
        || bond.parent_height != input.binding.prior_parent_height
        || economic.configuration_hash != configuration_hash
        || economic.trader_economic_mutation_root != trader.economic_mutation_root
        || economic.trader_economic_mutation_root != bond.trader_economic_mutation_root
        || economic.ordinary_execution_root != order.ordinary_execution_root
        || economic.ordinary_execution_root != funding.ordinary_execution_root
        || economic.forced_ioc_root != forced.forced_reduce_only_ioc_root
        || economic.forced_ioc_root != order.forced_ioc_root
        || economic.forced_ioc_root != funding.forced_ioc_root
        || economic.forced_ioc_execution_root != order.forced_ioc_execution_root
        || economic.forced_ioc_execution_root != funding.forced_ioc_execution_root
        || economic.forced_ioc_count != u64::from(order.forced_ioc_count)
        || economic.forced_ioc_count != funding.forced_ioc_count
        || economic.forced_ioc_execution_count != u64::from(order.forced_ioc_execution_count)
        || economic.forced_ioc_execution_count != funding.forced_ioc_execution_count
        || economic.liquidation_observation_root != order.liquidation_observation_root
        || economic.liquidation_observation_root != funding.liquidation_observation_root
        || economic.global_funding_index_numerator
            != input.next_state.global_funding_index_numerator
        || economic.previous_insurance_reserve_atoms != input.previous_state.insurance_reserve_atoms
        || reserve_after_matcher_economics != economic.insurance_reserve_before_bond_actions_atoms
        || economic.insurance_reserve_before_bond_actions_atoms
            != bond.insurance_reserve_before_bond_actions
        || account.successor_configuration_hash != configuration_hash
        || account.settlement_configuration_hash
            != input.binding.expected_settlement_configuration_hash
        || account.previous_deposit_inbox_state_hash
            != input.previous_state.deposit_inbox_state_hash
        || account.next_deposit_inbox_state_hash != input.next_state.deposit_inbox_state_hash
        || account.previous_deposit_inbox_head_root
            != input.binding.expected_previous_deposit_inbox_head_root
        || account.next_deposit_inbox_head_root
            != input.binding.expected_next_deposit_inbox_head_root
        || account.sidechain_height != input.next_state.sidechain_height
        || account.parent_height != input.binding.prior_parent_height
        || account.trader_economic_mutation_root != trader.economic_mutation_root
        || account.trader_insertion_root != trader.insertion_root
        || account.trader_insertion_count != trader.insertion_count
        || account.deposit_nullifier_key_root != nullifiers.deposit_nullifier_key_root
        || account.withdrawal_nullifier_key_root != nullifiers.withdrawal_nullifier_key_root
        || account.deposit_count != u64::from(nullifiers.deposit_update_count)
        || account.withdrawal_count != u64::from(nullifiers.withdrawal_update_count)
        || account.withdrawal_batch_root != settlement.withdrawal_root
        || account.deposit_batch_root != settlement.deposit_batch_root
        || forced.successor_configuration_hash != configuration_hash
        || forced.v18_configuration_hash != input.binding.expected_v18_configuration_hash
        || forced.previous_state_hash != input.previous_state.forced_inbox_state_hash
        || forced.next_state_hash != input.next_state.forced_inbox_state_hash
        || forced.previous_head_root != input.binding.expected_previous_forced_inbox_head_root
        || forced.next_head_root != input.binding.expected_next_forced_inbox_head_root
        || forced.current_parent_height != input.binding.prior_parent_height
        || forced.consumed_entry_batch_root != account.forced_action_batch_root
        || forced.forced_withdrawal_root != account.forced_withdrawal_root
        || forced.forced_cancel_root != order.forced_cancel_root
        || forced.next_cursor != settlement.forced_processed_cursor
        || forced.previous_cursor > forced.previous_entry_count
        || forced.next_cursor > forced.next_entry_count
        || forced.next_cursor < forced.previous_cursor
        || forced.next_entry_count < forced.previous_entry_count
        || account.next_deposit_cursor != settlement.deposit_processed_cursor
        || account.withdrawal_total != settlement.withdrawal_total
        || u128::from(settlement.collateral_input_total) != expected_collateral_inputs
        || u128::from(settlement.collateral_output_total) != expected_collateral_outputs
        || authorized_mutation_count != u32::from(trader.economic_mutation_count)
        || reserve_after_actions != input.next_state.insurance_reserve_atoms
        || forced.escape_only != forced.had_overdue_action
        || (forced_order_lane_active
            && (order.insertion_count != 0
                || economic.ordinary_execution_count != 0
                || economic.liquidation_count != 0
                || order.operation_count != forced_order_operation_count))
        || (forced.escape_only
            && (economic.ordinary_execution_count != 0
                || economic.liquidation_count != 0
                || bond.accepted_action_count != 0
                || order.operation_count != forced_order_operation_count))
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "bond action composition",
        ));
    }
    let full_range_deficit_atoms = deficit.lower_deficit_atoms.max(deficit.upper_deficit_atoms);
    let target_reserve_atoms = target_reserve_125(full_range_deficit_atoms)?;
    let relation = IncrementalSuccessorResultV2 {
        previous_state_root: input.previous_state.state_root(input.configuration)?,
        next_state_root: input.next_state.state_root(input.configuration)?,
        lower_deficit_atoms: deficit.lower_deficit_atoms,
        upper_deficit_atoms: deficit.upper_deficit_atoms,
        full_range_deficit_atoms,
        target_reserve_atoms,
        capital_mode: capital_mode_for(
            input.next_state.insurance_reserve_atoms,
            full_range_deficit_atoms,
        )?,
        operationally_safe: risk.operationally_safe,
    };
    if bond.full_bound_deficit_after != relation.full_range_deficit_atoms {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "bond action deficit projection",
        ));
    }
    let action_composition_root = incremental_action_composition_root_v2(
        inbox.recovered_candidate_root,
        bond.processed_outcome_root,
        settlement.action_root,
        economic.economic_action_root,
        account.deposit_batch_root,
        account.forced_action_batch_root,
        account.forced_withdrawal_root,
        account.withdrawal_batch_root,
        forced.forced_cancel_root,
        forced.forced_reduce_only_ioc_root,
        order.ordinary_execution_root,
        order.forced_ioc_execution_root,
        order.liquidation_observation_root,
        trader.economic_mutation_root,
        settlement.combined_settlement_root,
    );
    if relation.previous_state_root != input.binding.expected_previous_state_root
        || relation.next_state_root != input.binding.expected_next_state_root
        || input.next_state.parent_median_time_past != input.binding.prior_parent_mtp
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "state or parent context",
        ));
    }
    if bond.next_bond.insurance_reserve != input.next_state.insurance_reserve_atoms
        || bond.next_bond.full_bound_deficit != relation.full_range_deficit_atoms
        || bond.next_bond.target_reserve != relation.target_reserve_atoms
        || bond.next_bond.capital_mode != relation.capital_mode
        || inbox.next_cursor > inbox.next_entry_count
    {
        return Err(IncrementalSuccessorProofErrorV2::BindingMismatch(
            "public bond capital or inbox projection",
        ));
    }
    let nav_per_whole_share_usdd_atoms = if bond.next_bond.outstanding_share_atoms == 0 {
        0
    } else {
        nav_per_whole_share_usdd_atoms(
            bond.next_bond.insurance_reserve,
            bond.next_bond.outstanding_share_atoms,
        )?
    };
    let coverage_bps = coverage_bps(
        bond.next_bond.insurance_reserve,
        bond.next_bond.full_bound_deficit,
    )?;
    let values = IncrementalSuccessorProofPublicValuesV2 {
        configuration_hash,
        previous_state_root: relation.previous_state_root,
        next_state_root: relation.next_state_root,
        transition_txid_consensus: input.binding.transition_txid_consensus,
        prior_exchange_header_root: input.binding.prior_exchange_header_root,
        prior_parent_block_hash: input.binding.prior_parent_block_hash,
        risk_extrema_root: input.next_state.risk_extrema_root.hash,
        child_availability_root,
        custodian_registry_hash: input.binding.expected_custodian_registry_hash,
        settlement_action_root: settlement.action_root,
        combined_settlement_root: settlement.combined_settlement_root,
        settlement_configuration_hash: settlement.configuration_hash,
        v18_configuration_hash: inbox.configuration_hash,
        chain_id: inbox.chain_id,
        bond_asset_id: bond.next_bond.bond_asset_id,
        bond_deployment_commitment: bond.next_bond.deployment_commitment,
        bond_inventory_covenant_hash: bond.next_bond.inventory_covenant_hash,
        bond_state_root: bond.next_bond_root,
        funding_state_root: funding.next_funding_root,
        redemption_queue_root: bond.next_bond.redemption_queue_root,
        oracle_certificate_hash: funding.truthcoin_public_values_hash,
        matcher_execution_receipt_batch_root: funding.matcher_execution_receipt_batch_root,
        next_bond_inbox_head_root: inbox.next_head_root,
        next_bond_inbox_processed_root: inbox.next_processed_root,
        next_bond_inbox_outcome_root: bond.next_outcome_root,
        previous_inbox_state_hash: inbox.previous_state_hash,
        next_inbox_state_hash: inbox.next_state_hash,
        recovered_inbox_candidate_root: inbox.recovered_candidate_root,
        trader_update_transcript_root: trader.update_transcript_root,
        trader_update_leaf_projection_root: trader.update_leaf_projection_root,
        trader_economic_mutation_root: trader.economic_mutation_root,
        action_composition_root,
        previous_deposit_inbox_state_hash: account.previous_deposit_inbox_state_hash,
        next_deposit_inbox_state_hash: account.next_deposit_inbox_state_hash,
        previous_deposit_inbox_head_root: account.previous_deposit_inbox_head_root,
        next_deposit_inbox_head_root: account.next_deposit_inbox_head_root,
        previous_forced_inbox_state_hash: forced.previous_state_hash,
        next_forced_inbox_state_hash: forced.next_state_hash,
        previous_forced_inbox_head_root: forced.previous_head_root,
        next_forced_inbox_head_root: forced.next_head_root,
        prior_parent_height: input.binding.prior_parent_height,
        prior_parent_mtp: input.binding.prior_parent_mtp,
        sidechain_height: input.next_state.sidechain_height,
        mark_price_atoms: input.next_state.mark_price_atoms,
        price_lower_atoms: input.next_state.price_lower_atoms,
        price_upper_atoms: input.next_state.price_upper_atoms,
        issued_share_atoms: bond.next_bond.issued_share_atoms,
        outstanding_share_atoms: bond.next_bond.outstanding_share_atoms,
        inventory_share_atoms: bond.next_bond.inventory_share_atoms,
        queued_redemption_share_atoms: bond.next_bond.queued_redemption_share_atoms,
        funding_epoch: input.binding.prior_parent_mtp / FUNDING_EPOCH_SECONDS,
        oracle_valid_through_parent_mtp: funding.oracle_valid_through_mtp,
        global_funding_index_numerator: input.next_state.global_funding_index_numerator,
        lower_deficit_atoms: relation.lower_deficit_atoms,
        upper_deficit_atoms: relation.upper_deficit_atoms,
        full_range_deficit_atoms: relation.full_range_deficit_atoms,
        target_reserve_atoms: relation.target_reserve_atoms,
        insurance_reserve_atoms: input.next_state.insurance_reserve_atoms,
        controlled_usdd_atoms: input.next_state.controlled_usdd_atoms,
        matcher_sequence: input.next_state.matcher_sequence,
        nav_per_whole_share_usdd_atoms,
        coverage_bps,
        redemption_head: bond.next_bond.redemption_head,
        redemption_tail: bond.next_bond.redemption_tail,
        bond_inbox_entry_count: inbox.next_entry_count,
        bond_inbox_processed_cursor: inbox.next_cursor,
        bond_inbox_outcome_count: bond.next_outcome_count,
        funding_rate_ppm: funding.funding_rate_ppm,
        capital_mode: relation.capital_mode,
        oracle_mode: funding.oracle_mode,
        operationally_safe: relation.operationally_safe,
    };
    let public_values = values.encode();
    Ok(IncrementalSuccessorProofResultV2 {
        relation,
        public_values_sha256: sha256(&public_values),
        public_values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incremental_recursive_availability_v2::tests::{
        fixture_with_child_public_values, MarkerVerifier,
    };
    use crate::{
        incremental_liquidation_observation_root_v2, incremental_successor_forced_cancel_root_v2,
        incremental_successor_forced_reduce_only_ioc_root_v2,
    };
    use crate::{
        IncrementalAccountActionChildPublicValuesV2, IncrementalBondActionChildPublicValuesV2,
        IncrementalDeficitChildPublicValuesV2, IncrementalEconomicActionChildPublicValuesV2,
        IncrementalForcedActionChildPublicValuesV2, IncrementalFundingOracleChildPublicValuesV2,
        IncrementalInboxSourceChildPublicValuesV2, IncrementalNullifierChildPublicValuesV2,
        IncrementalOrderChildPublicValuesV2, IncrementalRiskChildPublicValuesV2,
        IncrementalSettlementChildPublicValuesV2, IncrementalTraderChildPublicValuesV2,
    };
    use ecx_protocol_core::{
        incremental_successor_bond_state_root_v2, successor_forced_action_batch_root_v2,
        successor_withdrawal_batch_root_v2, IncrementalAccountingBoundsV2,
        IncrementalPublicStateV2, RiskParams, SuccessorBondPublicStateV2,
        SuccessorForcedInboxStateV2, BOND_FIXED_SUPPLY_ATOMS, ECX_USDD_MARKET,
        INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2, SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
    };

    fn proof_input_with_liquidation_roots(
        order_liquidation_root: Hash32,
        funding_liquidation_root: Hash32,
        collateral_vault_input_total: u64,
        collateral_vault_change_total: u64,
        trader_mutation_count: u16,
    ) -> IncrementalSuccessorProofInputV2 {
        let configuration = IncrementalSuccessorConfigurationV2 {
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
        };
        let previous = IncrementalPublicStateV2::canonical_empty(
            configuration,
            10,
            1_000,
            100_000_000,
            90_000_000,
            110_000_000,
        )
        .unwrap();
        let deposit_inbox = ecx_protocol_core::DepositInboxStateV1::genesis(
            configuration.digest().unwrap(),
            configuration.chain_id,
        )
        .unwrap();
        let forced_inbox =
            SuccessorForcedInboxStateV2::genesis([0x75; 32], configuration.chain_id).unwrap();
        let mut next = previous;
        next.sidechain_height += 1;
        next.parent_median_time_past += 1;
        let mut previous = previous;
        previous.bond_inbox_state_hash = [0x52; 32];
        previous.bond_inbox_outcome_root = [0x73; 32];
        previous.bond_inbox_outcome_count = 0;
        next.bond_inbox_state_hash = [0x53; 32];
        next.bond_inbox_outcome_root = [0x74; 32];
        next.bond_inbox_outcome_count = 0;
        previous.forced_inbox_state_hash =
            ecx_protocol_core::incremental_forced_inbox_state_hash_v2(forced_inbox);
        next.forced_inbox_state_hash = previous.forced_inbox_state_hash;
        let next_bond = SuccessorBondPublicStateV2 {
            version: SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: [0x76; 32],
            deployment_commitment: [0x77; 32],
            inventory_covenant_hash: [0x78; 32],
            insurance_reserve: 0,
            issued_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            outstanding_share_atoms: 0,
            inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            full_bound_deficit: 0,
            target_reserve: 0,
            legacy_fee_pool: 0,
            redemption_queue_root: [0x79; 32],
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_share_atoms: 0,
            capital_mode: CapitalModeV2::Normal,
        };
        let next_bond_root = incremental_successor_bond_state_root_v2(next_bond);
        previous.bond_state_root = next_bond_root;
        next.bond_state_root = next_bond_root;
        let settlement_public_values = IncrementalSettlementChildPublicValuesV2 {
            configuration_hash: [0x40; 32],
            transition_txid: [0x31; 32],
            action_root: [0x41; 32],
            withdrawal_root: [0x42; 32],
            deposit_batch_root: ecx_protocol_core::deposit_batch_root(&[]),
            staging_source_projection_root: [0x59; 32],
            previous_transaction_projection_root: [0x5a; 32],
            collateral_settlement_root: [0x43; 32],
            bond_settlement_root: [0x44; 32],
            combined_settlement_root: [0x45; 32],
            forced_processed_cursor: 0,
            deposit_processed_cursor: 0,
            collateral_input_total: 0,
            collateral_output_total: 0,
            collateral_vault_input_total,
            insurance_reserve_input_total: 0,
            collateral_vault_change_total,
            insurance_reserve_output_total: 0,
            subscription_contribution_total: 0,
            recapitalization_contribution_total: 0,
            redemption_payment_total: 0,
            withdrawal_total: 0,
            bond_input_total: 0,
            bond_output_total: 0,
            bond_inventory_input_total: 0,
            bond_inventory_change_total: 0,
            bond_subscription_total: 0,
            queued_redemption_input_total: 0,
            redemption_remainder_total: 0,
            redemption_inventory_return_total: 0,
            rejected_enqueue_refund_total: 0,
        }
        .encode();
        let inbox_source_public_values = IncrementalInboxSourceChildPublicValuesV2 {
            configuration_hash: [0x50; 32],
            chain_id: [0x51; 32],
            previous_state_hash: [0x52; 32],
            next_state_hash: [0x53; 32],
            previous_head_root: [0x54; 32],
            previous_processed_root: [0x55; 32],
            next_head_root: [0x56; 32],
            next_processed_root: [0x57; 32],
            recovered_candidate_root: [0x58; 32],
            staging_source_projection_root: [0x59; 32],
            previous_entry_count: 0,
            previous_cursor: 0,
            next_entry_count: 0,
            next_cursor: 0,
            parent_height: 99,
            transition_sidechain_height: next.sidechain_height,
            consumed_count: 0,
        }
        .encode();
        let trader_public_values = IncrementalTraderChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            previous_root_projection: incremental_trader_root_projection_v2(previous.trader_root),
            next_root_projection: incremental_trader_root_projection_v2(next.trader_root),
            previous_merkle_root: previous.trader_root.hash,
            next_merkle_root: next.trader_root.hash,
            update_transcript_root: [0x60; 32],
            update_leaf_projection_root: [0x61; 32],
            economic_mutation_root: [0x6a; 32],
            insertion_root: crate::incremental_trader_insertion_root_v2(
                &[],
                configuration.accounting_bounds,
            )
            .unwrap(),
            update_count: 0,
            economic_mutation_count: trader_mutation_count,
            insertion_count: 0,
        }
        .encode();
        let deficit_public_values = IncrementalDeficitChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            trader_update_leaf_projection_root: [0x61; 32],
            next_trader_root_projection: incremental_trader_root_projection_v2(next.trader_root),
            previous_long_root_projection: incremental_deficit_root_projection_v2(
                previous.long_deficit_root,
            ),
            previous_short_root_projection: incremental_deficit_root_projection_v2(
                previous.short_deficit_root,
            ),
            next_long_root_projection: incremental_deficit_root_projection_v2(
                next.long_deficit_root,
            ),
            next_short_root_projection: incremental_deficit_root_projection_v2(
                next.short_deficit_root,
            ),
            long_update_transcript_root: [0x62; 32],
            short_update_transcript_root: [0x63; 32],
            lower_deficit_atoms: 0,
            upper_deficit_atoms: 0,
            trader_update_count: 0,
        }
        .encode();
        let risk_public_values = IncrementalRiskChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            trader_update_leaf_projection_root: [0x61; 32],
            previous_root_projection: incremental_risk_root_projection_v2(
                previous.risk_extrema_root,
            ),
            next_root_projection: incremental_risk_root_projection_v2(next.risk_extrema_root),
            update_transcript_root: [0x64; 32],
            trader_update_count: 0,
            operationally_safe: true,
        }
        .encode();
        let nullifier_public_values = IncrementalNullifierChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            previous_deposit_root_projection: incremental_nullifier_root_projection_v2(
                previous.deposit_nullifier_root,
            ),
            next_deposit_root_projection: incremental_nullifier_root_projection_v2(
                next.deposit_nullifier_root,
            ),
            previous_withdrawal_root_projection: incremental_nullifier_root_projection_v2(
                previous.withdrawal_nullifier_root,
            ),
            next_withdrawal_root_projection: incremental_nullifier_root_projection_v2(
                next.withdrawal_nullifier_root,
            ),
            deposit_update_transcript_root: [0x65; 32],
            withdrawal_update_transcript_root: [0x66; 32],
            deposit_nullifier_key_root: crate::incremental_nullifier_key_root_v2(
                ecx_protocol_core::NullifierKindV2::Deposit,
                [],
            )
            .unwrap(),
            withdrawal_nullifier_key_root: crate::incremental_nullifier_key_root_v2(
                ecx_protocol_core::NullifierKindV2::Withdrawal,
                [],
            )
            .unwrap(),
            deposit_update_count: 0,
            withdrawal_update_count: 0,
        }
        .encode();
        let empty_deposit_key_root = crate::incremental_nullifier_key_root_v2(
            ecx_protocol_core::NullifierKindV2::Deposit,
            [],
        )
        .unwrap();
        let empty_withdrawal_key_root = crate::incremental_nullifier_key_root_v2(
            ecx_protocol_core::NullifierKindV2::Withdrawal,
            [],
        )
        .unwrap();
        let order_public_values = IncrementalOrderChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            trader_update_leaf_projection_root: [0x61; 32],
            previous_trader_root_projection: incremental_trader_root_projection_v2(
                previous.trader_root,
            ),
            previous_order_root_projection: incremental_order_root_projection_v2(
                previous.order_root,
            ),
            next_order_root_projection: incremental_order_root_projection_v2(next.order_root),
            operation_transcript_root: [0x67; 32],
            ordinary_execution_root: [0x6b; 32],
            liquidation_observation_root: order_liquidation_root,
            forced_cancel_root: incremental_successor_forced_cancel_root_v2(&[]),
            forced_ioc_root: incremental_successor_forced_reduce_only_ioc_root_v2(&[]),
            forced_ioc_execution_root: crate::incremental_forced_ioc_execution_root_v2(&[])
                .unwrap(),
            forced_ioc_completion_root: [0x6c; 32],
            operation_count: 0,
            insertion_count: 0,
            prune_count: 0,
            liquidation_count: 0,
            forced_cancel_count: 0,
            forced_ioc_count: 0,
            forced_ioc_execution_count: 0,
        }
        .encode();
        let funding_oracle_public_values = IncrementalFundingOracleChildPublicValuesV2 {
            successor_configuration_hash: configuration.digest().unwrap(),
            v18_configuration_hash: [0x50; 32],
            chain_id: [0x51; 32],
            parent_block_hash: [0x33; 32],
            truthcoin_public_values_hash: [0x68; 32],
            conversion_legs_commitment: [0x69; 32],
            previous_funding_root: previous.funding_state_root,
            next_funding_root: next.funding_state_root,
            matcher_execution_receipt_batch_root: [0x6a; 32],
            ordinary_execution_root: [0x6b; 32],
            forced_ioc_root: incremental_successor_forced_reduce_only_ioc_root_v2(&[]),
            forced_ioc_execution_root: crate::incremental_forced_ioc_execution_root_v2(&[])
                .unwrap(),
            liquidation_observation_root: funding_liquidation_root,
            parent_height: 99,
            parent_mtp: next.parent_median_time_past,
            mark_price_atoms: next.mark_price_atoms,
            liquidation_low_atoms: next.mark_price_atoms,
            liquidation_high_atoms: next.mark_price_atoms,
            authenticated_min_price_atoms: next.price_lower_atoms,
            authenticated_max_price_atoms: next.price_upper_atoms,
            oracle_valid_through_mtp: next.parent_median_time_past,
            observation_count: 0,
            liquidation_observation_count: 0,
            forced_ioc_count: 0,
            forced_ioc_execution_count: 0,
            previous_match_sequence: 0,
            next_match_sequence: 0,
            previous_global_funding_index_numerator: previous.global_funding_index_numerator,
            next_global_funding_index_numerator: next.global_funding_index_numerator,
            funding_rate_ppm: 0,
            oracle_mode: ecx_protocol_core::OracleMode::Normal,
        }
        .encode();
        let bond_action_public_values = IncrementalBondActionChildPublicValuesV2 {
            configuration_hash: [0x50; 32],
            chain_id: [0x51; 32],
            previous_bond_root: previous.bond_state_root,
            next_bond_root: next.bond_state_root,
            previous_queue_root: [0x70; 32],
            next_queue_root: [0x71; 32],
            recovered_candidate_root: [0x58; 32],
            processed_outcome_root: [0x72; 32],
            settlement_action_root: [0x41; 32],
            trader_economic_mutation_root: [0x6a; 32],
            previous_trader_root_projection: incremental_trader_root_projection_v2(
                previous.trader_root,
            ),
            previous_outcome_root: previous.bond_inbox_outcome_root,
            next_outcome_root: next.bond_inbox_outcome_root,
            next_bond,
            parent_height: 99,
            consumed_count: 0,
            accepted_action_count: 0,
            redemption_execution_count: 0,
            previous_outcome_count: previous.bond_inbox_outcome_count,
            next_outcome_count: next.bond_inbox_outcome_count,
            insurance_reserve_before_bond_actions: next.insurance_reserve_atoms,
            insurance_reserve_after: next.insurance_reserve_atoms,
            queued_redemption_share_atoms_after: 0,
            full_bound_deficit_after: 0,
            authorized_mutation_count: 0,
        }
        .encode();
        let economic_action_public_values = IncrementalEconomicActionChildPublicValuesV2 {
            configuration_hash: configuration.digest().unwrap(),
            trader_economic_mutation_root: [0x6a; 32],
            ordinary_execution_root: [0x6b; 32],
            forced_ioc_root: incremental_successor_forced_reduce_only_ioc_root_v2(&[]),
            forced_ioc_execution_root: crate::incremental_forced_ioc_execution_root_v2(&[])
                .unwrap(),
            liquidation_observation_root: order_liquidation_root,
            economic_action_root: [0x6c; 32],
            ordinary_execution_count: 0,
            forced_ioc_count: 0,
            forced_ioc_execution_count: 0,
            liquidation_count: 0,
            funding_normalization_count: 0,
            global_funding_index_numerator: next.global_funding_index_numerator,
            previous_insurance_reserve_atoms: previous.insurance_reserve_atoms,
            protocol_fee_atoms: 0,
            liquidation_loss_atoms: 0,
            insurance_reserve_before_bond_actions_atoms: next.insurance_reserve_atoms,
            authorized_mutation_count: 0,
        }
        .encode();
        let account_action_public_values = IncrementalAccountActionChildPublicValuesV2 {
            successor_configuration_hash: configuration.digest().unwrap(),
            settlement_configuration_hash: [0x40; 32],
            previous_deposit_inbox_state_hash: previous.deposit_inbox_state_hash,
            next_deposit_inbox_state_hash: next.deposit_inbox_state_hash,
            previous_deposit_inbox_head_root: deposit_inbox.head_root,
            next_deposit_inbox_head_root: deposit_inbox.head_root,
            deposit_batch_root: ecx_protocol_core::deposit_batch_root(&[]),
            forced_action_batch_root: successor_forced_action_batch_root_v2(&[]),
            forced_withdrawal_root: successor_withdrawal_batch_root_v2(&[]),
            withdrawal_batch_root: [0x42; 32],
            trader_economic_mutation_root: [0x6a; 32],
            trader_insertion_root: crate::incremental_trader_insertion_root_v2(
                &[],
                configuration.accounting_bounds,
            )
            .unwrap(),
            deposit_nullifier_key_root: empty_deposit_key_root,
            withdrawal_nullifier_key_root: empty_withdrawal_key_root,
            sidechain_height: next.sidechain_height,
            parent_height: 99,
            previous_deposit_cursor: 0,
            next_deposit_cursor: 0,
            deposit_count: 0,
            withdrawal_count: 0,
            deposit_total: 0,
            withdrawal_total: 0,
            authorized_mutation_count: 0,
            trader_insertion_count: 0,
        }
        .encode();
        let forced_action_public_values = IncrementalForcedActionChildPublicValuesV2 {
            successor_configuration_hash: configuration.digest().unwrap(),
            v18_configuration_hash: [0x50; 32],
            previous_state_hash: previous.forced_inbox_state_hash,
            next_state_hash: next.forced_inbox_state_hash,
            previous_head_root: forced_inbox.head_root,
            next_head_root: forced_inbox.head_root,
            consumed_entry_batch_root: successor_forced_action_batch_root_v2(&[]),
            forced_withdrawal_root: successor_withdrawal_batch_root_v2(&[]),
            forced_cancel_root: incremental_successor_forced_cancel_root_v2(&[]),
            forced_reduce_only_ioc_root: incremental_successor_forced_reduce_only_ioc_root_v2(&[]),
            previous_cursor: 0,
            next_cursor: 0,
            previous_entry_count: 0,
            next_entry_count: 0,
            consumed_count: 0,
            pending_count: 0,
            current_parent_height: 99,
            had_overdue_action: false,
            escape_only: false,
        }
        .encode();
        let (child_availability, custodian_registry, registry_hash) =
            fixture_with_child_public_values(
                Some(settlement_public_values),
                Some(inbox_source_public_values),
                Some(trader_public_values),
                Some(deficit_public_values),
                Some(risk_public_values),
                Some(nullifier_public_values),
                Some(order_public_values),
                Some(funding_oracle_public_values),
                Some(bond_action_public_values),
                Some(economic_action_public_values),
                Some(account_action_public_values),
                Some(forced_action_public_values),
            );
        IncrementalSuccessorProofInputV2 {
            binding: IncrementalSuccessorProofBindingV2 {
                version: INCREMENTAL_SUCCESSOR_PROOF_BINDING_VERSION_V2,
                transition_txid_consensus: [0x31; 32],
                prior_exchange_header_root: [0x32; 32],
                prior_parent_block_hash: [0x33; 32],
                prior_parent_height: 99,
                prior_parent_mtp: next.parent_median_time_past,
                expected_configuration_hash: configuration.digest().unwrap(),
                expected_v18_configuration_hash: [0x50; 32],
                expected_settlement_configuration_hash: [0x40; 32],
                expected_chain_id: [0x51; 32],
                expected_custodian_registry_hash: registry_hash,
                expected_previous_state_root: previous.state_root(configuration).unwrap(),
                expected_next_state_root: next.state_root(configuration).unwrap(),
                expected_previous_inbox_state_hash: [0x52; 32],
                expected_next_inbox_state_hash: [0x53; 32],
                expected_previous_deposit_inbox_head_root: deposit_inbox.head_root,
                expected_next_deposit_inbox_head_root: deposit_inbox.head_root,
                expected_previous_forced_inbox_head_root: forced_inbox.head_root,
                expected_next_forced_inbox_head_root: forced_inbox.head_root,
            },
            configuration,
            previous_state: previous,
            next_state: next,
            child_availability,
            custodian_registry,
        }
    }

    fn proof_input() -> IncrementalSuccessorProofInputV2 {
        let empty = incremental_liquidation_observation_root_v2(&[]).unwrap();
        proof_input_with_liquidation_roots(empty, empty, 0, 0, 0)
    }

    fn replace_child_public_values(
        input: &mut IncrementalSuccessorProofInputV2,
        class: IncrementalChildClassV2,
        replacement: Vec<u8>,
    ) {
        let value = |candidate| {
            if candidate == class {
                replacement.clone()
            } else {
                input
                    .child_availability
                    .iter()
                    .find(|descriptor| descriptor.class == candidate)
                    .unwrap()
                    .public_values
                    .clone()
            }
        };
        let (children, registry, registry_hash) = fixture_with_child_public_values(
            Some(value(IncrementalChildClassV2::Settlement)),
            Some(value(IncrementalChildClassV2::InboxSource)),
            Some(value(IncrementalChildClassV2::Trader)),
            Some(value(IncrementalChildClassV2::Deficit)),
            Some(value(IncrementalChildClassV2::Risk)),
            Some(value(IncrementalChildClassV2::Nullifiers)),
            Some(value(IncrementalChildClassV2::Order)),
            Some(value(IncrementalChildClassV2::FundingOracle)),
            Some(value(IncrementalChildClassV2::BondActions)),
            Some(value(IncrementalChildClassV2::EconomicActions)),
            Some(value(IncrementalChildClassV2::AccountActions)),
            Some(value(IncrementalChildClassV2::ForcedActions)),
        );
        input.child_availability = children;
        input.custodian_registry = registry;
        input.binding.expected_custodian_registry_hash = registry_hash;
    }

    #[test]
    fn incremental_public_values_layout_is_exact_and_domain_separate() {
        let values = IncrementalSuccessorProofPublicValuesV2 {
            configuration_hash: [1; 32],
            previous_state_root: [2; 32],
            next_state_root: [3; 32],
            transition_txid_consensus: [4; 32],
            prior_exchange_header_root: [5; 32],
            prior_parent_block_hash: [6; 32],
            risk_extrema_root: [7; 32],
            child_availability_root: [8; 32],
            custodian_registry_hash: [9; 32],
            settlement_action_root: [10; 32],
            combined_settlement_root: [11; 32],
            settlement_configuration_hash: [12; 32],
            v18_configuration_hash: [13; 32],
            chain_id: [14; 32],
            bond_asset_id: [30; 32],
            bond_deployment_commitment: [31; 32],
            bond_inventory_covenant_hash: [32; 32],
            bond_state_root: [33; 32],
            funding_state_root: [34; 32],
            redemption_queue_root: [35; 32],
            oracle_certificate_hash: [36; 32],
            matcher_execution_receipt_batch_root: [37; 32],
            next_bond_inbox_head_root: [38; 32],
            next_bond_inbox_processed_root: [39; 32],
            next_bond_inbox_outcome_root: [40; 32],
            previous_inbox_state_hash: [15; 32],
            next_inbox_state_hash: [16; 32],
            recovered_inbox_candidate_root: [17; 32],
            trader_update_transcript_root: [18; 32],
            trader_update_leaf_projection_root: [19; 32],
            trader_economic_mutation_root: [20; 32],
            action_composition_root: [29; 32],
            previous_deposit_inbox_state_hash: [21; 32],
            next_deposit_inbox_state_hash: [22; 32],
            previous_deposit_inbox_head_root: [23; 32],
            next_deposit_inbox_head_root: [24; 32],
            previous_forced_inbox_state_hash: [25; 32],
            next_forced_inbox_state_hash: [26; 32],
            previous_forced_inbox_head_root: [27; 32],
            next_forced_inbox_head_root: [28; 32],
            prior_parent_height: 7,
            prior_parent_mtp: 8,
            sidechain_height: 9,
            mark_price_atoms: 10,
            price_lower_atoms: 9,
            price_upper_atoms: 11,
            issued_share_atoms: 20,
            outstanding_share_atoms: 21,
            inventory_share_atoms: 22,
            queued_redemption_share_atoms: 23,
            funding_epoch: 24,
            oracle_valid_through_parent_mtp: 25,
            global_funding_index_numerator: -12,
            lower_deficit_atoms: 13,
            upper_deficit_atoms: 14,
            full_range_deficit_atoms: 15,
            target_reserve_atoms: 16,
            insurance_reserve_atoms: 17,
            controlled_usdd_atoms: 18,
            matcher_sequence: 19,
            nav_per_whole_share_usdd_atoms: 20,
            coverage_bps: 21,
            redemption_head: 22,
            redemption_tail: 23,
            bond_inbox_entry_count: 24,
            bond_inbox_processed_cursor: 25,
            bond_inbox_outcome_count: 26,
            funding_rate_ppm: -27,
            capital_mode: CapitalModeV2::ReduceOnly,
            oracle_mode: OracleMode::Normal,
            operationally_safe: false,
        };
        let encoded = values.encode();
        assert_eq!(encoded.len(), INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2);
        assert_eq!(
            &encoded[..4],
            &INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
        );
        assert_eq!(encoded[4], 1);
        assert_eq!(encoded[encoded.len() - 3], CapitalModeV2::ReduceOnly as u8);
        assert_eq!(encoded[encoded.len() - 2], OracleMode::Normal as u8);
        assert_eq!(encoded[encoded.len() - 1], 0);
        assert_ne!(
            INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2,
            super::super::PUBLIC_VALUES_V5_LEN
        );
    }

    #[test]
    fn outer_successor_input_contains_only_public_states_and_child_descriptors() {
        let input = proof_input();
        let bytes = canonical_input_bytes_v2(&input).unwrap();
        assert!(bytes.len() < 64 * 1024);
        assert_eq!(input.child_availability.len(), 12);
    }

    #[test]
    fn action_composition_root_binds_every_slot_order_omission_and_duplication() {
        let roots = core::array::from_fn::<_, 15, _>(|index| [index as u8 + 1; 32]);
        let compose = |items: [Hash32; 15]| {
            incremental_action_composition_root_v2(
                items[0], items[1], items[2], items[3], items[4], items[5], items[6], items[7],
                items[8], items[9], items[10], items[11], items[12], items[13], items[14],
            )
        };
        let expected = compose(roots);
        for index in 0..roots.len() {
            let mut omitted = roots;
            omitted[index] = [0; 32];
            assert_ne!(compose(omitted), expected, "omitted root slot {index}");

            let mut substituted = roots;
            substituted[index][0] ^= 0x80;
            assert_ne!(
                compose(substituted),
                expected,
                "substituted root slot {index}"
            );
        }
        let mut reordered = roots;
        reordered.swap(0, 1);
        assert_ne!(compose(reordered), expected);
        let mut duplicated = roots;
        duplicated[1] = duplicated[0];
        assert_ne!(compose(duplicated), expected);
    }

    #[test]
    fn successor_proof_binding_executes_and_rejects_identity_substitution() {
        let input = proof_input();
        assert!(execute_incremental_successor_proof_v2(&input).is_err());
        let result =
            execute_incremental_successor_proof_v2_with_consensus_verifier(&input, &MarkerVerifier)
                .unwrap();
        assert_eq!(
            result.public_values.len(),
            INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2
        );
        assert_eq!(result.public_values_sha256, sha256(&result.public_values));
        let expected_composition = incremental_action_composition_root_v2(
            [0x58; 32],
            [0x72; 32],
            [0x41; 32],
            [0x6c; 32],
            ecx_protocol_core::deposit_batch_root(&[]),
            successor_forced_action_batch_root_v2(&[]),
            successor_withdrawal_batch_root_v2(&[]),
            [0x42; 32],
            incremental_successor_forced_cancel_root_v2(&[]),
            incremental_successor_forced_reduce_only_ioc_root_v2(&[]),
            [0x6b; 32],
            crate::incremental_forced_ioc_execution_root_v2(&[]).unwrap(),
            incremental_liquidation_observation_root_v2(&[]).unwrap(),
            [0x6a; 32],
            [0x45; 32],
        );
        let composition_offset = 4 + (31 * 32);
        assert_eq!(
            &result.public_values[composition_offset..composition_offset + 32],
            &expected_composition
        );

        let mut wrong_inbox_state = input.clone();
        wrong_inbox_state.binding.expected_next_inbox_state_hash[0] ^= 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_inbox_state,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut wrong_transition_txid = input.clone();
        wrong_transition_txid.binding.transition_txid_consensus[0] ^= 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_transition_txid,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut wrong_forced_head = input.clone();
        wrong_forced_head
            .binding
            .expected_next_forced_inbox_head_root[0] ^= 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_forced_head,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut wrong_settlement_configuration = input.clone();
        wrong_settlement_configuration
            .binding
            .expected_settlement_configuration_hash[0] ^= 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_settlement_configuration,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut wrong_next = input.clone();
        wrong_next.binding.expected_next_state_root[0] ^= 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_next,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        // Exact fractional cash is committed by the trader root and validated
        // against physically controlled USDD before any child projection is
        // trusted. Mutating one numerator unit without a corresponding valid
        // root is rejected as non-canonical state; the protocol-core
        // conservation tests separately pin the exact numerator comparison.
        let mut fractional_value_creation = input.clone();
        fractional_value_creation
            .next_state
            .trader_root
            .aggregate
            .fractional_cash_numerator = ecx_protocol_core::Int256V2::from_i128(1);
        fractional_value_creation
            .next_state
            .trader_root
            .aggregate
            .gross_fractional_cash_numerator = ecx_protocol_core::Uint256V2::from_u64(1);
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &fractional_value_creation,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::Relation(
                ProtocolError::InvalidBondState
            ))
        ));

        let mut wrong_parent = input;
        wrong_parent.binding.prior_parent_mtp += 1;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_parent,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let empty = incremental_liquidation_observation_root_v2(&[]).unwrap();
        let mismatched_liquidation = proof_input_with_liquidation_roots(empty, [0x7a; 32], 0, 0, 0);
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &mismatched_liquidation,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        // A trader transcript containing a deposit/withdrawal (or any other)
        // mutation that no recursive action child authorized must fail closed.
        let uncovered_account_mutation = proof_input_with_liquidation_roots(empty, empty, 0, 0, 1);
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &uncovered_account_mutation,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut wrong_insertion_binding = proof_input();
        let child_values = |class| {
            wrong_insertion_binding
                .child_availability
                .iter()
                .find(|descriptor| descriptor.class == class)
                .unwrap()
                .public_values
                .clone()
        };
        let mut account = decode_incremental_account_action_projection_v2(&child_values(
            IncrementalChildClassV2::AccountActions,
        ))
        .unwrap();
        account.trader_insertion_root[0] ^= 1;
        let (children, registry, registry_hash) = fixture_with_child_public_values(
            Some(child_values(IncrementalChildClassV2::Settlement)),
            Some(child_values(IncrementalChildClassV2::InboxSource)),
            Some(child_values(IncrementalChildClassV2::Trader)),
            Some(child_values(IncrementalChildClassV2::Deficit)),
            Some(child_values(IncrementalChildClassV2::Risk)),
            Some(child_values(IncrementalChildClassV2::Nullifiers)),
            Some(child_values(IncrementalChildClassV2::Order)),
            Some(child_values(IncrementalChildClassV2::FundingOracle)),
            Some(child_values(IncrementalChildClassV2::BondActions)),
            Some(child_values(IncrementalChildClassV2::EconomicActions)),
            Some(account.encode()),
            Some(child_values(IncrementalChildClassV2::ForcedActions)),
        );
        wrong_insertion_binding.child_availability = children;
        wrong_insertion_binding.custodian_registry = registry;
        wrong_insertion_binding
            .binding
            .expected_custodian_registry_hash = registry_hash;
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &wrong_insertion_binding,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));
    }

    #[test]
    fn escape_only_rejects_ordinary_order_liquidation_and_bond_actions() {
        let mut escape = proof_input();
        let mut forced = escape
            .child_availability
            .iter()
            .find(|descriptor| descriptor.class == IncrementalChildClassV2::ForcedActions)
            .unwrap()
            .public_values
            .clone();
        let last = forced.len() - 1;
        forced[last - 1] = 1;
        forced[last] = 1;
        replace_child_public_values(&mut escape, IncrementalChildClassV2::ForcedActions, forced);
        execute_incremental_successor_proof_v2_with_consensus_verifier(&escape, &MarkerVerifier)
            .unwrap();

        let mut ordinary = escape.clone();
        let mut economic = ordinary
            .child_availability
            .iter()
            .find(|descriptor| descriptor.class == IncrementalChildClassV2::EconomicActions)
            .unwrap()
            .public_values
            .clone();
        let ordinary_count_offset = 4 + (7 * 32);
        economic[ordinary_count_offset..ordinary_count_offset + 8]
            .copy_from_slice(&1u64.to_be_bytes());
        replace_child_public_values(
            &mut ordinary,
            IncrementalChildClassV2::EconomicActions,
            economic,
        );
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &ordinary,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut placement = escape.clone();
        let mut order = placement
            .child_availability
            .iter()
            .find(|descriptor| descriptor.class == IncrementalChildClassV2::Order)
            .unwrap()
            .public_values
            .clone();
        let operation_count_offset = 4 + (12 * 32);
        order[operation_count_offset..operation_count_offset + 2]
            .copy_from_slice(&1u16.to_be_bytes());
        replace_child_public_values(&mut placement, IncrementalChildClassV2::Order, order);
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &placement,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));

        let mut bond_action = escape;
        let mut bond = bond_action
            .child_availability
            .iter()
            .find(|descriptor| descriptor.class == IncrementalChildClassV2::BondActions)
            .unwrap()
            .public_values
            .clone();
        let accepted_count_offset = 4 + (13 * 32) + (2 * 8);
        bond[accepted_count_offset..accepted_count_offset + 8].copy_from_slice(&1u64.to_be_bytes());
        replace_child_public_values(&mut bond_action, IncrementalChildClassV2::BondActions, bond);
        assert!(matches!(
            execute_incremental_successor_proof_v2_with_consensus_verifier(
                &bond_action,
                &MarkerVerifier,
            ),
            Err(IncrementalSuccessorProofErrorV2::BindingMismatch(_))
        ));
    }
}
