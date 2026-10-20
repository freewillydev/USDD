//! Composable exact-accounting successor relation for the incremental V2 state.
//!
//! This module deliberately has a fresh domain and does not reinterpret the
//! finite [`crate::TransitionWitnessV2`] relation.  It connects the isolated
//! authenticated-state primitives into one state-root transition, but it is
//! not yet the complete production guest: settlement/inbox/receipt composition,
//! liquidation-band reads and the global 16 MiB
//! recovery bound remain explicit release gates.

use crate::bond::{capital_mode_for, target_reserve_125, CapitalModeV2};
use crate::codec::{put_i128, put_u128, put_u16, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::incremental_risk_extrema_v2::{
    canonical_empty_risk_extrema_root_v2, verify_trader_risk_extrema_batch_v2,
    RiskExtremaBatchProofV2, RiskExtremaRootV2,
};
use crate::incremental_state_v2::{
    advance_exact_funding_index_v2, canonical_empty_deficit_index_root_v2,
    canonical_empty_nullifier_root_v2, canonical_empty_order_index_root_v2,
    canonical_empty_sparse_root_v2, operational_risk_coordinates_v2, portfolio_deficit_atoms_v2,
    price_funding_q_numerator_v2, verify_balanced_trader_root_v2, verify_controlled_value_v2,
    verify_order_operation_trader_projection_v2, verify_sparse_nullifier_updates_v2,
    verify_trader_deficit_index_batches_v2, ChainedOrderIndexTranscriptV2,
    DeficitIndexBatchProofV2, DeficitIndexRangeProofV2, DeficitIndexRootV2, DeficitSideV2,
    IncrementalAccountingBoundsV2, IncrementalOrderContextV2, Int256V2, NullifierKindV2,
    OrderIndexRootV2, SparseMerkleSumRootV2, SparseNullifierRootV2, SparseNullifierUpdateV2,
    SparseStateDomainV2, TraderStateBatchProofV2, TraderStateReadBatchProofV2,
    EXACT_ACCOUNTING_DENOMINATOR_V2, MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2,
    MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2, MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2,
};
use crate::risk::RiskParams;
use crate::types::{MarketId, Price};
use crate::ProtocolError;

pub const INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2: u8 = 2;
pub const INCREMENTAL_SUCCESSOR_STATE_VERSION_V2: u8 = 8;
pub const INCREMENTAL_SUCCESSOR_WITNESS_VERSION_V2: u8 = 8;

pub fn incremental_empty_bond_state_root_v2(configuration_hash: Hash32) -> Hash32 {
    tagged_hash("ECX/incremental-bond-state/empty/v1", &configuration_hash)
}

pub fn incremental_bond_state_root_v2(state: crate::BondPublicStateV2) -> Hash32 {
    canonical_hash("ECX/incremental-bond-state/v1", &state)
}

pub fn incremental_successor_bond_state_root_v2(
    state: crate::SuccessorBondPublicStateV2,
) -> Hash32 {
    canonical_hash("ECX/incremental-bond-state/v2-u128-queue", &state)
}

pub fn incremental_deposit_inbox_state_hash_v2(state: crate::DepositInboxStateV1) -> Hash32 {
    canonical_hash("ECX/incremental-deposit-inbox-state/v1", &state)
}

pub fn incremental_forced_inbox_state_hash_v2(state: crate::SuccessorForcedInboxStateV2) -> Hash32 {
    canonical_hash("ECX/incremental-forced-inbox-state/v2-u128", &state)
}

/// Frozen inputs for the fresh incremental successor identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalSuccessorConfigurationV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    /// Hash of the economic configuration signed by orders and actions.
    pub order_configuration_hash: Hash32,
    /// Hash of the lifetime-safe matcher configuration that signs successor
    /// admission and execution receipts. It is distinct from the V1 matcher
    /// configuration embedded in the finite V18 relation.
    pub successor_matcher_configuration_hash: Hash32,
    pub risk_params: RiskParams,
    pub accounting_bounds: IncrementalAccountingBoundsV2,
    pub maximum_trader_updates: u16,
    pub maximum_order_operations: u16,
    pub maximum_nullifier_updates_per_kind: u16,
}

impl IncrementalSuccessorConfigurationV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.version != INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2
            || self.chain_id == [0; 32]
            || self.order_configuration_hash == [0; 32]
            || self.successor_matcher_configuration_hash == [0; 32]
            || self.successor_matcher_configuration_hash == self.order_configuration_hash
            || self.risk_params != RiskParams::default()
            || self.maximum_trader_updates == 0
            || usize::from(self.maximum_trader_updates) > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
            || self.maximum_order_operations == 0
            || usize::from(self.maximum_order_operations) > MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2
            || self.maximum_nullifier_updates_per_kind == 0
            || usize::from(self.maximum_nullifier_updates_per_kind)
                > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        {
            return Err(ProtocolError::InvalidBondState);
        }
        self.market.validate()?;
        self.risk_params.validate()?;
        self.accounting_bounds.validate()
    }

    pub fn digest(self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash(
            "ECX/incremental-successor-configuration/v2-u128-matcher",
            &self,
        ))
    }

    pub fn order_context(self, sidechain_height: u64) -> IncrementalOrderContextV2 {
        IncrementalOrderContextV2 {
            chain_id: self.chain_id,
            market: self.market,
            configuration_hash: self.order_configuration_hash,
            risk_params: self.risk_params,
            sidechain_height,
        }
    }
}

impl CanonicalEncode for IncrementalSuccessorConfigurationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.order_configuration_hash);
        out.extend_from_slice(&self.successor_matcher_configuration_hash);
        self.risk_params.encode_to(out);
        self.accounting_bounds.encode_to(out);
        put_u16(out, self.maximum_trader_updates);
        put_u16(out, self.maximum_order_operations);
        put_u16(out, self.maximum_nullifier_updates_per_kind);
    }
}

/// Public authenticated state consumed and produced by the successor relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalPublicStateV2 {
    pub version: u8,
    pub successor_configuration_hash: Hash32,
    pub sidechain_height: u64,
    pub parent_median_time_past: u64,
    pub mark_price_atoms: u64,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
    pub global_funding_index_numerator: i128,
    pub controlled_usdd_atoms: u128,
    pub insurance_reserve_atoms: u128,
    /// Root of the proof-enforced bond supply, reserve, and FIFO state. The
    /// action-composition child must authenticate every change to this root.
    pub bond_state_root: Hash32,
    /// Root of the complete deterministic eight-hour funding accumulator.
    /// The dedicated funding/oracle child authenticates its transition.
    pub funding_state_root: Hash32,
    /// Exact successor-width bond-inbox state and processed-outcome accumulator carried
    /// across recursive successors. Without these fields a valid child proof
    /// could be replayed against an unrelated inbox history.
    pub bond_inbox_state_hash: Hash32,
    pub bond_inbox_outcome_root: Hash32,
    pub bond_inbox_outcome_count: u128,
    /// Authenticated V1 deposit-inbox head/cursor carried into the fresh
    /// successor identity. The account-action child opens and advances it.
    pub deposit_inbox_state_hash: Hash32,
    /// Authenticated V1 forced-action inbox. A dedicated recursive child opens
    /// this hash and proves the complete pending suffix and consumed prefix.
    pub forced_inbox_state_hash: Hash32,
    pub trader_root: SparseMerkleSumRootV2,
    pub order_root: OrderIndexRootV2,
    pub deposit_nullifier_root: SparseNullifierRootV2,
    pub withdrawal_nullifier_root: SparseNullifierRootV2,
    pub long_deficit_root: DeficitIndexRootV2,
    pub short_deficit_root: DeficitIndexRootV2,
    pub risk_extrema_root: RiskExtremaRootV2,
    pub matcher_sequence: u128,
}

impl IncrementalPublicStateV2 {
    pub fn canonical_empty(
        configuration: IncrementalSuccessorConfigurationV2,
        sidechain_height: u64,
        parent_median_time_past: u64,
        mark_price_atoms: u64,
        price_lower_atoms: u64,
        price_upper_atoms: u64,
    ) -> Result<Self, ProtocolError> {
        configuration.validate()?;
        let state = Self {
            version: INCREMENTAL_SUCCESSOR_STATE_VERSION_V2,
            successor_configuration_hash: configuration.digest()?,
            sidechain_height,
            parent_median_time_past,
            mark_price_atoms,
            price_lower_atoms,
            price_upper_atoms,
            global_funding_index_numerator: 0,
            controlled_usdd_atoms: 0,
            insurance_reserve_atoms: 0,
            bond_state_root: incremental_empty_bond_state_root_v2(configuration.digest()?),
            funding_state_root: crate::FundingStateV2::genesis_with_band(
                parent_median_time_past,
                Price::new(mark_price_atoms)?,
                Price::new(price_lower_atoms)?,
                Price::new(price_upper_atoms)?,
                parent_median_time_past,
                0,
            )?
            .root(),
            bond_inbox_state_hash: tagged_hash(
                "ECX/incremental-bond-inbox-state/empty/v2-u128",
                &configuration.digest()?,
            ),
            bond_inbox_outcome_root: tagged_hash(
                "ECX/incremental-bond-inbox-outcomes/empty/v2-u128",
                &configuration.digest()?,
            ),
            bond_inbox_outcome_count: 0,
            deposit_inbox_state_hash: incremental_deposit_inbox_state_hash_v2(
                crate::DepositInboxStateV1::genesis(
                    configuration.digest()?,
                    configuration.chain_id,
                )?,
            ),
            forced_inbox_state_hash: incremental_forced_inbox_state_hash_v2(
                crate::SuccessorForcedInboxStateV2::genesis(
                    configuration.digest()?,
                    configuration.chain_id,
                )?,
            ),
            trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            order_root: canonical_empty_order_index_root_v2(),
            deposit_nullifier_root: canonical_empty_nullifier_root_v2(NullifierKindV2::Deposit),
            withdrawal_nullifier_root: canonical_empty_nullifier_root_v2(
                NullifierKindV2::Withdrawal,
            ),
            long_deficit_root: canonical_empty_deficit_index_root_v2(DeficitSideV2::Long)?,
            short_deficit_root: canonical_empty_deficit_index_root_v2(DeficitSideV2::Short)?,
            risk_extrema_root: canonical_empty_risk_extrema_root_v2()?,
            matcher_sequence: 0,
        };
        state.validate(configuration)?;
        Ok(state)
    }

    pub fn validate(
        self,
        configuration: IncrementalSuccessorConfigurationV2,
    ) -> Result<(), ProtocolError> {
        configuration.validate()?;
        if self.version != INCREMENTAL_SUCCESSOR_STATE_VERSION_V2
            || self.successor_configuration_hash != configuration.digest()?
            || self.sidechain_height == 0
            || self.parent_median_time_past == 0
            || self.mark_price_atoms == 0
            || self.price_lower_atoms == 0
            || self.price_lower_atoms > self.mark_price_atoms
            || self.mark_price_atoms > self.price_upper_atoms
            || self.price_upper_atoms > configuration.accounting_bounds.maximum_price_atoms
            || self.controlled_usdd_atoms
                > configuration
                    .accounting_bounds
                    .maximum_total_controlled_atoms
            || self.insurance_reserve_atoms > self.controlled_usdd_atoms
            || self.bond_state_root == [0; 32]
            || self.funding_state_root == [0; 32]
            || self.bond_inbox_state_hash == [0; 32]
            || self.bond_inbox_outcome_root == [0; 32]
            || self.deposit_inbox_state_hash == [0; 32]
            || self.forced_inbox_state_hash == [0; 32]
            || self.trader_root.domain != SparseStateDomainV2::Trader
            || self.deposit_nullifier_root.kind != NullifierKindV2::Deposit
            || self.withdrawal_nullifier_root.kind != NullifierKindV2::Withdrawal
            || self.long_deficit_root.side != DeficitSideV2::Long
            || self.short_deficit_root.side != DeficitSideV2::Short
        {
            return Err(ProtocolError::InvalidBondState);
        }
        verify_balanced_trader_root_v2(self.trader_root, configuration.accounting_bounds)?;
        self.order_root.aggregate.validate()?;
        // A forced IOC has to be completely resolved in one transition.  The
        // immediate-root transcript spends one operation per stale-head prune
        // or maker fill, so admitting more live leaves than the frozen
        // operation budget would make the six-block escape promise
        // unreachable for a valid worst-case book.
        if self.order_root.aggregate.leaf_count > u128::from(configuration.maximum_order_operations)
        {
            return Err(ProtocolError::InvalidBondState);
        }
        self.deposit_nullifier_root.validate()?;
        self.withdrawal_nullifier_root.validate()?;
        self.long_deficit_root
            .validate(configuration.accounting_bounds)?;
        self.short_deficit_root
            .validate(configuration.accounting_bounds)?;
        self.risk_extrema_root.validate()?;
        if self.risk_extrema_root.aggregate.leaf_count != 0
            && self.risk_extrema_root.aggregate.maintenance_margin_bps
                != configuration.risk_params.maintenance_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let expected = Int256V2::from_u128(self.controlled_usdd_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
        verify_controlled_value_v2(
            self.trader_root,
            self.mark_price_atoms,
            self.global_funding_index_numerator,
            self.insurance_reserve_atoms,
            expected,
            configuration.accounting_bounds,
        )
    }

    pub fn state_root(
        self,
        configuration: IncrementalSuccessorConfigurationV2,
    ) -> Result<Hash32, ProtocolError> {
        self.validate(configuration)?;
        Ok(canonical_hash(
            "ECX/incremental-public-state/v8-u128-bond-inbox",
            &self,
        ))
    }
}

impl CanonicalEncode for IncrementalPublicStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.successor_configuration_hash);
        put_u64(out, self.sidechain_height);
        put_u64(out, self.parent_median_time_past);
        put_u64(out, self.mark_price_atoms);
        put_u64(out, self.price_lower_atoms);
        put_u64(out, self.price_upper_atoms);
        put_i128(out, self.global_funding_index_numerator);
        out.extend_from_slice(&self.controlled_usdd_atoms.to_be_bytes());
        out.extend_from_slice(&self.insurance_reserve_atoms.to_be_bytes());
        out.extend_from_slice(&self.bond_state_root);
        out.extend_from_slice(&self.funding_state_root);
        out.extend_from_slice(&self.bond_inbox_state_hash);
        out.extend_from_slice(&self.bond_inbox_outcome_root);
        put_u128(out, self.bond_inbox_outcome_count);
        out.extend_from_slice(&self.deposit_inbox_state_hash);
        out.extend_from_slice(&self.forced_inbox_state_hash);
        self.trader_root.encode_to(out);
        self.order_root.encode_to(out);
        self.deposit_nullifier_root.encode_to(out);
        self.withdrawal_nullifier_root.encode_to(out);
        self.long_deficit_root.encode_to(out);
        self.short_deficit_root.encode_to(out);
        self.risk_extrema_root.encode_to(out);
        out.extend_from_slice(&self.matcher_sequence.to_be_bytes());
    }
}

/// Complete next-state deficit query at the two authenticated price endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalDeficitEndpointProofsV2 {
    pub lower_long: DeficitIndexRangeProofV2,
    pub lower_short: DeficitIndexRangeProofV2,
    pub upper_long: DeficitIndexRangeProofV2,
    pub upper_short: DeficitIndexRangeProofV2,
}

impl CanonicalEncode for IncrementalDeficitEndpointProofsV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.lower_long.encode_to(out);
        self.lower_short.encode_to(out);
        self.upper_long.encode_to(out);
        self.upper_short.encode_to(out);
    }
}

/// Exact arithmetic step for one settled eight-hour funding epoch. The future
/// source composition must authenticate both fields against the funding
/// observations; this root relation prevents an arbitrary index jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalFundingSettlementV2 {
    pub mark_price_atoms: u64,
    pub funding_rate_ppm: i32,
}

impl CanonicalEncode for IncrementalFundingSettlementV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.mark_price_atoms);
        out.extend_from_slice(&self.funding_rate_ppm.to_be_bytes());
    }
}

/// One atomic authenticated-state successor witness.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalSuccessorWitnessV2 {
    pub version: u8,
    pub previous_state: IncrementalPublicStateV2,
    pub next_state: IncrementalPublicStateV2,
    pub funding_settlement: Option<IncrementalFundingSettlementV2>,
    pub trader_updates: Option<TraderStateBatchProofV2>,
    pub long_deficit_updates: Option<DeficitIndexBatchProofV2>,
    pub short_deficit_updates: Option<DeficitIndexBatchProofV2>,
    pub risk_extrema_updates: Option<RiskExtremaBatchProofV2>,
    pub order_transcript: Option<ChainedOrderIndexTranscriptV2>,
    pub trader_reads: Option<TraderStateReadBatchProofV2>,
    pub deposit_nullifier_updates: Vec<SparseNullifierUpdateV2>,
    pub withdrawal_nullifier_updates: Vec<SparseNullifierUpdateV2>,
    pub next_deficit_endpoints: IncrementalDeficitEndpointProofsV2,
}

fn encode_option<T: CanonicalEncode>(out: &mut Vec<u8>, value: &Option<T>) {
    match value {
        None => put_u8(out, 0),
        Some(value) => {
            put_u8(out, 1);
            value.encode_to(out);
        }
    }
}

impl CanonicalEncode for IncrementalSuccessorWitnessV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.previous_state.encode_to(out);
        self.next_state.encode_to(out);
        encode_option(out, &self.funding_settlement);
        encode_option(out, &self.trader_updates);
        encode_option(out, &self.long_deficit_updates);
        encode_option(out, &self.short_deficit_updates);
        encode_option(out, &self.risk_extrema_updates);
        encode_option(out, &self.order_transcript);
        encode_option(out, &self.trader_reads);
        put_u16(
            out,
            u16::try_from(self.deposit_nullifier_updates.len()).unwrap_or(u16::MAX),
        );
        for update in &self.deposit_nullifier_updates {
            update.encode_to(out);
        }
        put_u16(
            out,
            u16::try_from(self.withdrawal_nullifier_updates.len()).unwrap_or(u16::MAX),
        );
        for update in &self.withdrawal_nullifier_updates {
            update.encode_to(out);
        }
        self.next_deficit_endpoints.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalSuccessorResultV2 {
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub lower_deficit_atoms: u128,
    pub upper_deficit_atoms: u128,
    pub full_range_deficit_atoms: u128,
    pub target_reserve_atoms: u128,
    pub capital_mode: CapitalModeV2,
    /// Authenticated adverse-band maintenance result. A future complete action
    /// composition must use this value in its action-class admission policy.
    pub operationally_safe: bool,
}

fn verify_endpoint_deficit_v2(
    state: IncrementalPublicStateV2,
    price_atoms: u64,
    long_proof: &DeficitIndexRangeProofV2,
    short_proof: &DeficitIndexRangeProofV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<u128, ProtocolError> {
    let q =
        price_funding_q_numerator_v2(price_atoms, state.global_funding_index_numerator, bounds)?;
    if long_proof.q_numerator != q || short_proof.q_numerator != q {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let long = long_proof.verify(state.long_deficit_root, bounds)?;
    let short = short_proof.verify(state.short_deficit_root, bounds)?;
    portfolio_deficit_atoms_v2(
        long,
        short,
        state
            .trader_root
            .aggregate
            .flat_negative_exact_cash_numerator,
        q,
        bounds,
    )?
    .try_to_u128()
}

/// Verify the connected exact-accounting successor slice.
pub fn verify_incremental_successor_v2(
    configuration: IncrementalSuccessorConfigurationV2,
    witness: &IncrementalSuccessorWitnessV2,
) -> Result<IncrementalSuccessorResultV2, ProtocolError> {
    configuration.validate()?;
    if witness.version != INCREMENTAL_SUCCESSOR_WITNESS_VERSION_V2
        || witness.next_state.sidechain_height
            != witness
                .previous_state
                .sidechain_height
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?
        || witness.next_state.parent_median_time_past
            < witness.previous_state.parent_median_time_past
        || witness.next_state.matcher_sequence < witness.previous_state.matcher_sequence
    {
        return Err(ProtocolError::InvalidBondState);
    }
    witness.previous_state.validate(configuration)?;

    let expected_funding_index = match witness.funding_settlement {
        None => witness.previous_state.global_funding_index_numerator,
        Some(settlement) => advance_exact_funding_index_v2(
            witness.previous_state.global_funding_index_numerator,
            settlement.mark_price_atoms,
            settlement.funding_rate_ppm,
        )?,
    };
    if witness.next_state.global_funding_index_numerator != expected_funding_index {
        return Err(ProtocolError::InvalidBondState);
    }

    let bounds = configuration.accounting_bounds;
    let (trader_root, trader_updates) = match &witness.trader_updates {
        Some(proof) => (
            proof.verify(
                witness.previous_state.trader_root,
                bounds,
                usize::from(configuration.maximum_trader_updates),
            )?,
            proof.updates.as_slice(),
        ),
        None => (witness.previous_state.trader_root, &[][..]),
    };
    if trader_root != witness.next_state.trader_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }

    let (long_root, short_root) = if trader_updates.is_empty() {
        if witness.long_deficit_updates.is_some() || witness.short_deficit_updates.is_some() {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        (
            witness.previous_state.long_deficit_root,
            witness.previous_state.short_deficit_root,
        )
    } else {
        verify_trader_deficit_index_batches_v2(
            trader_updates,
            witness.previous_state.long_deficit_root,
            witness.previous_state.short_deficit_root,
            witness.long_deficit_updates.as_ref(),
            witness.short_deficit_updates.as_ref(),
            bounds,
            MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2,
        )?
    };
    if long_root != witness.next_state.long_deficit_root
        || short_root != witness.next_state.short_deficit_root
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }

    let risk_extrema_root = verify_trader_risk_extrema_batch_v2(
        trader_updates,
        witness.previous_state.risk_extrema_root,
        witness.risk_extrema_updates.as_ref(),
        configuration.risk_params.maintenance_margin_bps,
        bounds,
    )?;
    if risk_extrema_root != witness.next_state.risk_extrema_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }

    let order_context = configuration.order_context(witness.next_state.sidechain_height);
    let order_root = match &witness.order_transcript {
        None => {
            if witness.trader_reads.is_some() {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            witness.previous_state.order_root
        }
        Some(transcript) => {
            if transcript.actions.len() > usize::from(configuration.maximum_order_operations) {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            let trader_batch = witness
                .trader_updates
                .as_ref()
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            let operations = transcript
                .actions
                .iter()
                .map(|action| action.operation.clone())
                .collect::<Vec<_>>();
            verify_order_operation_trader_projection_v2(
                &operations,
                trader_batch,
                witness.trader_reads.as_ref(),
                witness.previous_state.trader_root,
                order_context,
                bounds,
            )?;
            transcript.verify(witness.previous_state.order_root, order_context, bounds)?
        }
    };
    if order_root != witness.next_state.order_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }

    let deposit_root = verify_sparse_nullifier_updates_v2(
        witness.previous_state.deposit_nullifier_root,
        &witness.deposit_nullifier_updates,
        usize::from(configuration.maximum_nullifier_updates_per_kind),
    )?;
    let withdrawal_root = verify_sparse_nullifier_updates_v2(
        witness.previous_state.withdrawal_nullifier_root,
        &witness.withdrawal_nullifier_updates,
        usize::from(configuration.maximum_nullifier_updates_per_kind),
    )?;
    if deposit_root != witness.next_state.deposit_nullifier_root
        || withdrawal_root != witness.next_state.withdrawal_nullifier_root
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    if (witness.next_state.controlled_usdd_atoms > witness.previous_state.controlled_usdd_atoms
        && witness.deposit_nullifier_updates.is_empty())
        || (witness.next_state.controlled_usdd_atoms < witness.previous_state.controlled_usdd_atoms
            && witness.withdrawal_nullifier_updates.is_empty())
    {
        // Exact amounts are bound by the future unified-settlement composition,
        // but the root-only slice must already reject a value delta with no
        // corresponding authenticated nullifier class.
        return Err(ProtocolError::ConservationViolation);
    }

    witness.next_state.validate(configuration)?;
    let lower = verify_endpoint_deficit_v2(
        witness.next_state,
        witness.next_state.price_lower_atoms,
        &witness.next_deficit_endpoints.lower_long,
        &witness.next_deficit_endpoints.lower_short,
        bounds,
    )?;
    let upper = verify_endpoint_deficit_v2(
        witness.next_state,
        witness.next_state.price_upper_atoms,
        &witness.next_deficit_endpoints.upper_long,
        &witness.next_deficit_endpoints.upper_short,
        bounds,
    )?;
    let full = lower.max(upper);
    let target = target_reserve_125(full)?;
    let operationally_safe = if witness.next_state.risk_extrema_root.aggregate.leaf_count == 0 {
        true
    } else {
        let (long_x, short_x) = operational_risk_coordinates_v2(
            witness.next_state.price_lower_atoms,
            witness.next_state.price_upper_atoms,
            witness.next_state.global_funding_index_numerator,
            configuration.risk_params.maintenance_margin_bps,
            bounds,
        )?;
        witness
            .next_state
            .risk_extrema_root
            .aggregate
            .all_positions_operationally_safe(long_x, short_x)?
    };
    Ok(IncrementalSuccessorResultV2 {
        previous_state_root: witness.previous_state.state_root(configuration)?,
        next_state_root: witness.next_state.state_root(configuration)?,
        lower_deficit_atoms: lower,
        upper_deficit_atoms: upper,
        full_range_deficit_atoms: full,
        target_reserve_atoms: target,
        capital_mode: capital_mode_for(witness.next_state.insurance_reserve_atoms, full)?,
        operationally_safe,
    })
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use crate::incremental_state_v2::{
        DeficitIndexRangeProofV2, TraderLeafV2, TraderStateBatchLeafUpdateV2, Uint256V2,
    };
    use crate::types::{MarketId, XOnlyKey, ECX_USDD_MARKET};

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

    fn trader_key() -> XOnlyKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (key, _) = XOnlyPublicKey::from_keypair(&keypair);
        XOnlyKey(key.serialize())
    }

    #[test]
    fn successor_configuration_freezes_exact_v2_economics() {
        let exact = configuration();
        exact.validate().unwrap();
        let mut maker_rebate = exact;
        maker_rebate.risk_params.maker_fee_bps = -1;
        assert_eq!(
            maker_rebate.validate(),
            Err(ProtocolError::InvalidBondState)
        );
        let mut liquidation_penalty = exact;
        liquidation_penalty.risk_params.liquidation_fee_bps = 99;
        assert_eq!(
            liquidation_penalty.validate(),
            Err(ProtocolError::InvalidBondState)
        );
    }

    fn flat_trader(collateral_atoms: i128) -> TraderLeafV2 {
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: trader_key(),
            account_nonce: 1,
            collateral_atoms,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 10_000,
            order_generation: 0,
            salt: [0x33; 32],
        }
    }

    fn empty_endpoint_proofs(
        state: IncrementalPublicStateV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> IncrementalDeficitEndpointProofsV2 {
        let lower = price_funding_q_numerator_v2(
            state.price_lower_atoms,
            state.global_funding_index_numerator,
            bounds,
        )
        .unwrap();
        let upper = price_funding_q_numerator_v2(
            state.price_upper_atoms,
            state.global_funding_index_numerator,
            bounds,
        )
        .unwrap();
        IncrementalDeficitEndpointProofsV2 {
            lower_long: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Long,
                lower,
                bounds,
            )
            .unwrap(),
            lower_short: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Short,
                lower,
                bounds,
            )
            .unwrap(),
            upper_long: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Long,
                upper,
                bounds,
            )
            .unwrap(),
            upper_short: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Short,
                upper,
                bounds,
            )
            .unwrap(),
        }
    }

    fn insertion_witness() -> (
        IncrementalSuccessorConfigurationV2,
        IncrementalSuccessorWitnessV2,
    ) {
        let configuration = configuration();
        let previous = IncrementalPublicStateV2::canonical_empty(
            configuration,
            10,
            1_000,
            100_000_000,
            90_000_000,
            110_000_000,
        )
        .unwrap();
        let trader_updates = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader: trader_key(),
                old_leaf: None,
                new_leaf: Some(flat_trader(100)),
            }],
            configuration.accounting_bounds,
        )
        .unwrap();
        let trader_root = trader_updates
            .verify(previous.trader_root, configuration.accounting_bounds, 64)
            .unwrap();
        let deposit = SparseNullifierUpdateV2 {
            kind: NullifierKindV2::Deposit,
            nullifier: [0x44; 32],
            path: crate::incremental_state_v2::canonical_empty_nullifier_path_v2(
                NullifierKindV2::Deposit,
            ),
        };
        let deposit_root = verify_sparse_nullifier_updates_v2(
            previous.deposit_nullifier_root,
            core::slice::from_ref(&deposit),
            64,
        )
        .unwrap();
        let mut next = previous;
        next.sidechain_height += 1;
        next.parent_median_time_past += 1;
        next.controlled_usdd_atoms = 100;
        next.trader_root = trader_root;
        next.deposit_nullifier_root = deposit_root;
        next.matcher_sequence = 1;
        next.validate(configuration).unwrap();
        let endpoints = empty_endpoint_proofs(next, configuration.accounting_bounds);
        (
            configuration,
            IncrementalSuccessorWitnessV2 {
                version: INCREMENTAL_SUCCESSOR_WITNESS_VERSION_V2,
                previous_state: previous,
                next_state: next,
                funding_settlement: None,
                trader_updates: Some(trader_updates),
                long_deficit_updates: None,
                short_deficit_updates: None,
                risk_extrema_updates: None,
                order_transcript: None,
                trader_reads: None,
                deposit_nullifier_updates: vec![deposit],
                withdrawal_nullifier_updates: vec![],
                next_deficit_endpoints: endpoints,
            },
        )
    }

    #[test]
    fn exact_successor_atomically_chains_roots_and_conservation() {
        let (configuration, witness) = insertion_witness();
        let result = verify_incremental_successor_v2(configuration, &witness).unwrap();
        assert_ne!(result.previous_state_root, result.next_state_root);
        assert_eq!(result.full_range_deficit_atoms, 0);
        assert_eq!(result.target_reserve_atoms, 0);
        assert_eq!(result.capital_mode, CapitalModeV2::Normal);
        assert!(result.operationally_safe);
        assert!(!witness.canonical_bytes().is_empty());
    }

    #[test]
    fn successor_rejects_root_conservation_and_endpoint_substitution() {
        let (configuration, witness) = insertion_witness();

        let mut root_substitution = witness.clone();
        root_substitution.next_state.trader_root.hash[0] ^= 1;
        assert!(verify_incremental_successor_v2(configuration, &root_substitution).is_err());

        let mut risk_substitution = witness.clone();
        risk_substitution.next_state.risk_extrema_root.hash[0] ^= 1;
        assert!(verify_incremental_successor_v2(configuration, &risk_substitution).is_err());

        let mut conservation = witness.clone();
        conservation.next_state.controlled_usdd_atoms += 1;
        assert_eq!(
            verify_incremental_successor_v2(configuration, &conservation),
            Err(ProtocolError::ConservationViolation)
        );

        let mut endpoint = witness.clone();
        endpoint.next_deficit_endpoints.lower_long.q_numerator = Int256V2::from_u128(1);
        assert!(verify_incremental_successor_v2(configuration, &endpoint).is_err());

        let mut nullifier = witness.clone();
        nullifier.deposit_nullifier_updates.clear();
        assert!(verify_incremental_successor_v2(configuration, &nullifier).is_err());
    }

    #[test]
    fn funding_index_requires_exact_settlement_and_endpoint_rebinding() {
        let (configuration, witness) = insertion_witness();

        let mut arbitrary_jump = witness.clone();
        arbitrary_jump.next_state.global_funding_index_numerator = 1;
        assert_eq!(
            verify_incremental_successor_v2(configuration, &arbitrary_jump),
            Err(ProtocolError::InvalidBondState)
        );

        let mut settled = witness;
        let settlement = IncrementalFundingSettlementV2 {
            mark_price_atoms: 100_000_000,
            funding_rate_ppm: 1_000,
        };
        settled.funding_settlement = Some(settlement);
        settled.next_state.global_funding_index_numerator = advance_exact_funding_index_v2(
            0,
            settlement.mark_price_atoms,
            settlement.funding_rate_ppm,
        )
        .unwrap();
        settled.next_deficit_endpoints =
            empty_endpoint_proofs(settled.next_state, configuration.accounting_bounds);
        verify_incremental_successor_v2(configuration, &settled).unwrap();

        let mut wrong_rate = settled;
        wrong_rate
            .funding_settlement
            .as_mut()
            .unwrap()
            .funding_rate_ppm += 1;
        assert!(verify_incremental_successor_v2(configuration, &wrong_rate).is_err());
    }

    #[test]
    fn configuration_and_state_domains_are_fresh_and_canonical() {
        let configuration = configuration();
        assert_eq!(
            configuration.digest().unwrap(),
            configuration.digest().unwrap()
        );
        let previous = IncrementalPublicStateV2::canonical_empty(
            configuration,
            1,
            1,
            100_000_000,
            90_000_000,
            110_000_000,
        )
        .unwrap();
        assert_ne!(previous.state_root(configuration).unwrap(), [0; 32]);
        let mut wrong = configuration;
        wrong.market = MarketId([0; 16]);
        assert!(wrong.validate().is_err());
        assert!(Uint256V2::from_u128(1).try_to_u128().is_ok());
    }
}
