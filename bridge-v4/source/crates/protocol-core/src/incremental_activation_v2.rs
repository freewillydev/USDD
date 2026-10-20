//! One-shot activation boundary for the exact-accounting incremental successor.
//!
//! The finite V18 relation cannot be migrated by silently reinterpreting its
//! integer account/position leaves: it does not retain the fractional cash and
//! exact cost-basis information required by the successor.  This module
//! therefore defines the only source-local migration that is currently sound:
//! an authenticated, economically pristine V18 state is replaced by a fresh
//! incremental state before any user funds, positions, orders, nullifiers, or
//! inbox entries exist.  Historical migration remains a separate program.

use crate::bond::{BondPublicStateV2, BOND_FIXED_SUPPLY_ATOMS};
use crate::codec::{put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::incremental_successor_v2::{
    incremental_successor_bond_state_root_v2, IncrementalPublicStateV2,
    IncrementalSuccessorConfigurationV2, INCREMENTAL_SUCCESSOR_STATE_VERSION_V2,
};
use crate::merkle::empty_hash;
use crate::state::StateRoots;
use crate::state_v2::ExchangeStateV2;
use crate::successor_bond_state_v2::{
    successor_redemption_queue_root_v2, SuccessorBondPublicStateV2,
    SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
};
use crate::transition_v2::{
    active_order_risk_root_v2, position_risk_root_v2, redemption_queue_root_v2,
};
use crate::{Amount, ProtocolError};

pub const INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2: u8 = 1;

/// Frozen identities for the one-shot empty-state activation program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalEmptyActivationConfigurationV2 {
    pub version: u8,
    /// Exact finite V18 configuration accepted by the predecessor singleton.
    pub finite_v18_configuration_hash: Hash32,
    /// Fresh exact-accounting successor configuration.
    pub successor: IncrementalSuccessorConfigurationV2,
}

impl IncrementalEmptyActivationConfigurationV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        self.successor.validate()?;
        let successor_hash = self.successor.digest()?;
        if self.version != INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2
            || self.finite_v18_configuration_hash == [0; 32]
            || self.finite_v18_configuration_hash == successor_hash
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn digest(self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash(
            "ECX/incremental-empty-activation-configuration/v1",
            &self,
        ))
    }
}

impl CanonicalEncode for IncrementalEmptyActivationConfigurationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.finite_v18_configuration_hash);
        self.successor.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalEmptyActivationWitnessV2 {
    pub version: u8,
    pub finite_v18_state: ExchangeStateV2,
    pub successor_bond_state: SuccessorBondPublicStateV2,
    /// Exact first state authorized by the fresh successor singleton.
    pub successor_state: IncrementalPublicStateV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalEmptyActivationResultV2 {
    pub activation_configuration_hash: Hash32,
    pub finite_v18_state_root: Hash32,
    pub successor_state_root: Hash32,
}

fn empty_v18_roots() -> Result<StateRoots, ProtocolError> {
    StateRoots::from_private_state(&[], &[], &[], &[], &[], empty_hash())
}

fn require_pristine_v18_state(state: &ExchangeStateV2) -> Result<(), ProtocolError> {
    state.validate()?;
    let base = &state.base;
    let bond = state.bond;
    let empty_roots = empty_v18_roots()?;
    if base.total_deposits != Amount(0)
        || base.total_withdrawals != Amount(0)
        || base.insurance_fund != Amount(0)
        || base.fee_pool != Amount(0)
        || base.funding_index != 0
        || base.matcher_sequence != 0
        || state.matcher_execution_sequence != 0
        || base.roots.accounts != empty_roots.accounts
        || base.roots.positions != empty_roots.positions
        || base.roots.open_orders != empty_roots.open_orders
        || base.roots.deposit_nullifiers != empty_roots.deposit_nullifiers
        || base.roots.withdrawal_nullifiers != empty_roots.withdrawal_nullifiers
        || base.forced_inbox.entry_count != 0
        || base.forced_inbox.cursor != 0
        || base.deposit_inbox.entry_count != 0
        || base.deposit_inbox.cursor != 0
        || state.bond_inbox.entry_count != 0
        || state.bond_inbox.cursor != 0
        || state.bond_inbox_outcome_count != 0
        || state.active_order_risk_root != active_order_risk_root_v2(&[])?
        || state.position_risk_root != position_risk_root_v2(&[])?
        || bond.insurance_reserve != 0
        || bond.outstanding_share_atoms != 0
        || bond.inventory_share_atoms != BOND_FIXED_SUPPLY_ATOMS
        || bond.full_bound_deficit != 0
        || bond.target_reserve != 0
        || bond.redemption_head != 0
        || bond.redemption_tail != 0
        || bond.queued_redemption_share_atoms != 0
        || bond.redemption_queue_root != redemption_queue_root_v2(&[])
    {
        return Err(ProtocolError::InvalidBondState);
    }

    let expected_funding = crate::FundingStateV2::genesis_with_band(
        state.funding.last_parent_mtp,
        state.funding.last_oracle_mark,
        state.funding.last_oracle_low,
        state.funding.last_oracle_high,
        state.funding.last_oracle_valid_through_mtp,
        0,
    )?;
    if state.funding != expected_funding {
        return Err(ProtocolError::InvalidFundingState);
    }
    Ok(())
}

fn successor_bond_from_pristine_v18(
    state: BondPublicStateV2,
) -> Result<SuccessorBondPublicStateV2, ProtocolError> {
    state.validate()?;
    let successor = SuccessorBondPublicStateV2 {
        version: SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
        bond_asset_id: state.bond_asset_id,
        deployment_commitment: state.deployment_commitment,
        inventory_covenant_hash: state.inventory_covenant_hash,
        insurance_reserve: state.insurance_reserve,
        issued_share_atoms: state.issued_share_atoms,
        outstanding_share_atoms: state.outstanding_share_atoms,
        inventory_share_atoms: state.inventory_share_atoms,
        full_bound_deficit: state.full_bound_deficit,
        target_reserve: state.target_reserve,
        legacy_fee_pool: state.legacy_fee_pool,
        redemption_queue_root: successor_redemption_queue_root_v2(&[])?,
        redemption_head: u128::from(state.redemption_head),
        redemption_tail: u128::from(state.redemption_tail),
        queued_redemption_share_atoms: state.queued_redemption_share_atoms,
        capital_mode: state.capital_mode,
    };
    successor.validate()
}

/// Verify an exact one-shot activation before any economically relevant V18
/// history exists.  This deliberately rejects a merely empty order book if
/// deposits, nullifiers, positions, bond holders, or pending inbox work exist.
pub fn verify_incremental_empty_activation_v2(
    configuration: IncrementalEmptyActivationConfigurationV2,
    witness: &IncrementalEmptyActivationWitnessV2,
) -> Result<IncrementalEmptyActivationResultV2, ProtocolError> {
    configuration.validate()?;
    if witness.version != INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    require_pristine_v18_state(&witness.finite_v18_state)?;
    if witness.finite_v18_state.base.chain_id != configuration.successor.chain_id
        || witness.finite_v18_state.base.market != configuration.successor.market
        || witness.successor_bond_state
            != successor_bond_from_pristine_v18(witness.finite_v18_state.bond)?
    {
        return Err(ProtocolError::InvalidBondState);
    }

    let mut expected = IncrementalPublicStateV2::canonical_empty(
        configuration.successor,
        witness.successor_state.sidechain_height,
        witness.successor_state.parent_median_time_past,
        witness.successor_state.mark_price_atoms,
        witness.successor_state.price_lower_atoms,
        witness.successor_state.price_upper_atoms,
    )?;
    // Elements permits blocks which carry the singleton forward unchanged.
    // Therefore this is an authenticated chain height, not a transition
    // sequence number: activation must be later than the finite predecessor,
    // but it need not be in the immediately following block.
    if witness.successor_state.version != INCREMENTAL_SUCCESSOR_STATE_VERSION_V2
        || witness.successor_state.sidechain_height
            <= witness.finite_v18_state.last_transition_sidechain_height
        || witness.successor_state.parent_median_time_past
            < witness.finite_v18_state.funding.last_parent_mtp
    {
        return Err(ProtocolError::InvalidBondState);
    }
    expected.bond_state_root =
        incremental_successor_bond_state_root_v2(witness.successor_bond_state);
    if witness.successor_state != expected {
        return Err(ProtocolError::InvalidBondState);
    }
    witness.successor_state.validate(configuration.successor)?;

    Ok(IncrementalEmptyActivationResultV2 {
        activation_configuration_hash: configuration.digest()?,
        finite_v18_state_root: witness.finite_v18_state.state_root(),
        successor_state_root: witness
            .successor_state
            .state_root(configuration.successor)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond::{CapitalModeV2, BOND_PROTOCOL_VERSION_V2};
    use crate::deposit_inbox::DepositInboxStateV1;
    use crate::forced::ForcedInboxStateV1;
    use crate::funding_v2::FundingStateV2;
    use crate::incremental_state_v2::IncrementalAccountingBoundsV2;
    use crate::risk::RiskParams;
    use crate::state::ExchangeState;
    use crate::types::{Price, ECX_USDD_MARKET};
    use crate::{BondInboxStateV2, Hash32};

    const CHAIN_ID: Hash32 = [0x11; 32];
    const FINITE_CONFIGURATION_HASH: Hash32 = [0x22; 32];

    fn successor_configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: crate::INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: CHAIN_ID,
            market: ECX_USDD_MARKET,
            order_configuration_hash: [0x33; 32],
            successor_matcher_configuration_hash: [0x44; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 10_000_000,
                maximum_total_controlled_atoms: 21_000_000 * 100_000_000,
                maximum_abs_position_atoms: 10_000_000,
                maximum_open_interest_atoms: 20_000_000,
                maximum_price_atoms: 1_000_000_000,
            },
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        }
    }

    fn finite_bond() -> BondPublicStateV2 {
        BondPublicStateV2 {
            version: BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: [0x51; 32],
            deployment_commitment: [0x52; 32],
            inventory_covenant_hash: [0x53; 32],
            insurance_reserve: 0,
            issued_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            outstanding_share_atoms: 0,
            inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            full_bound_deficit: 0,
            target_reserve: 0,
            legacy_fee_pool: 0,
            redemption_queue_root: redemption_queue_root_v2(&[]),
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_share_atoms: 0,
            capital_mode: CapitalModeV2::Normal,
        }
    }

    fn finite_state() -> ExchangeStateV2 {
        let funding = FundingStateV2::genesis_with_band(
            1_000,
            Price::new(100_000_000).unwrap(),
            Price::new(90_000_000).unwrap(),
            Price::new(110_000_000).unwrap(),
            1_000,
            0,
        )
        .unwrap();
        let state = ExchangeStateV2 {
            version: ExchangeStateV2::VERSION,
            base: ExchangeState {
                protocol_version: ExchangeState::VERSION,
                chain_id: CHAIN_ID,
                market: ECX_USDD_MARKET,
                sequence: 7,
                last_processed_height: 10,
                mark_price: Price::new(100_000_000).unwrap(),
                funding_index: 0,
                total_deposits: Amount(0),
                total_withdrawals: Amount(0),
                insurance_fund: Amount(0),
                fee_pool: Amount(0),
                matcher_sequence: 0,
                matcher_receipt_hash: [0x61; 32],
                forced_inbox: ForcedInboxStateV1::genesis([0x62; 32], CHAIN_ID).unwrap(),
                deposit_inbox: DepositInboxStateV1::genesis([0x63; 32], CHAIN_ID).unwrap(),
                roots: empty_v18_roots().unwrap(),
            },
            bond: finite_bond(),
            funding,
            matcher_execution_sequence: 0,
            last_transition_sidechain_height: 10,
            bond_inbox: BondInboxStateV2::genesis([0x64; 32], CHAIN_ID, FINITE_CONFIGURATION_HASH)
                .unwrap(),
            bond_inbox_outcome_root: [0x65; 32],
            bond_inbox_outcome_count: 0,
            active_order_risk_root: active_order_risk_root_v2(&[]).unwrap(),
            position_risk_root: position_risk_root_v2(&[]).unwrap(),
        };
        state.validate().unwrap();
        state
    }

    fn fixture() -> (
        IncrementalEmptyActivationConfigurationV2,
        IncrementalEmptyActivationWitnessV2,
    ) {
        let configuration = IncrementalEmptyActivationConfigurationV2 {
            version: INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2,
            finite_v18_configuration_hash: FINITE_CONFIGURATION_HASH,
            successor: successor_configuration(),
        };
        let finite = finite_state();
        let successor_bond = successor_bond_from_pristine_v18(finite.bond).unwrap();
        let mut successor = IncrementalPublicStateV2::canonical_empty(
            configuration.successor,
            11,
            1_001,
            100_000_000,
            90_000_000,
            110_000_000,
        )
        .unwrap();
        successor.bond_state_root = incremental_successor_bond_state_root_v2(successor_bond);
        successor.validate(configuration.successor).unwrap();
        (
            configuration,
            IncrementalEmptyActivationWitnessV2 {
                version: INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2,
                finite_v18_state: finite,
                successor_bond_state: successor_bond,
                successor_state: successor,
            },
        )
    }

    #[test]
    fn empty_activation_supports_thirty_usdd_initial_mark_without_conversion_receipts() {
        let (mut configuration, mut witness) = fixture();
        // User-selected initialization, not a market observation. Retain only
        // the representation bound instead of a discretionary 10-USDD ceiling.
        configuration.successor.accounting_bounds.maximum_price_atoms = u64::MAX;
        let mark = 3_000_000_000;
        witness.successor_state = IncrementalPublicStateV2::canonical_empty(
            configuration.successor,11,1_001,mark,mark,mark).unwrap();
        witness.successor_state.bond_state_root =
            incremental_successor_bond_state_root_v2(witness.successor_bond_state);
        let result = verify_incremental_empty_activation_v2(configuration,&witness).unwrap();
        assert_eq!(witness.successor_state.controlled_usdd_atoms,0);
        assert_eq!(result.successor_state_root,
            witness.successor_state.state_root(configuration.successor).unwrap());
        // This activation witness contains pristine state, not funded conversion
        // evidence; it must still reject even one atom of prior deposits.
        witness.finite_v18_state.base.total_deposits = Amount(1);
        assert!(verify_incremental_empty_activation_v2(configuration,&witness).is_err());
    }

    #[test]
    fn pristine_v18_state_activates_exact_accounting_successor_once() {
        let (configuration, witness) = fixture();
        let result = verify_incremental_empty_activation_v2(configuration, &witness).unwrap();
        assert_eq!(
            result.activation_configuration_hash,
            configuration.digest().unwrap()
        );
        assert_eq!(
            result.finite_v18_state_root,
            witness.finite_v18_state.state_root()
        );
        assert_eq!(
            result.successor_state_root,
            witness
                .successor_state
                .state_root(configuration.successor)
                .unwrap()
        );

        // The receipt accumulator has a configuration-frozen genesis root;
        // it is not one of the five private keyed sets whose emptiness is
        // represented by the generic Merkle empty root.
        let mut configured_receipt_root = witness.clone();
        configured_receipt_root
            .finite_v18_state
            .base
            .roots
            .order_receipts = [0x66; 32];
        verify_incremental_empty_activation_v2(configuration, &configured_receipt_root).unwrap();
    }

    #[test]
    fn activation_accepts_authenticated_carry_forward_height_gaps() {
        let (configuration, mut witness) = fixture();
        witness.successor_state.sidechain_height = 14;
        let result = verify_incremental_empty_activation_v2(configuration, &witness).unwrap();
        assert_eq!(
            result.successor_state_root,
            witness
                .successor_state
                .state_root(configuration.successor)
                .unwrap()
        );
    }

    #[test]
    fn activation_rejects_any_history_pending_work_or_successor_substitution() {
        let (configuration, witness) = fixture();

        let mut deposited = witness.clone();
        deposited.finite_v18_state.base.total_deposits = Amount(1);
        assert!(verify_incremental_empty_activation_v2(configuration, &deposited).is_err());

        let mut nullifier_history = witness.clone();
        nullifier_history
            .finite_v18_state
            .base
            .roots
            .deposit_nullifiers[0] ^= 1;
        assert!(verify_incremental_empty_activation_v2(configuration, &nullifier_history).is_err());

        let mut pending = witness.clone();
        pending.finite_v18_state.bond_inbox.entry_count = 1;
        assert!(verify_incremental_empty_activation_v2(configuration, &pending).is_err());

        let mut holder = witness.clone();
        holder.finite_v18_state.bond.outstanding_share_atoms = 1;
        holder.finite_v18_state.bond.inventory_share_atoms -= 1;
        assert!(verify_incremental_empty_activation_v2(configuration, &holder).is_err());

        let mut wrong_bond = witness.clone();
        wrong_bond.successor_bond_state.bond_asset_id[0] ^= 1;
        assert!(verify_incremental_empty_activation_v2(configuration, &wrong_bond).is_err());

        let mut wrong_root = witness.clone();
        wrong_root.successor_state.order_root.hash[0] ^= 1;
        assert!(verify_incremental_empty_activation_v2(configuration, &wrong_root).is_err());

        let mut wrong_height = witness.clone();
        wrong_height.successor_state.sidechain_height = 10;
        assert!(verify_incremental_empty_activation_v2(configuration, &wrong_height).is_err());

        let mut wrong_chain = configuration;
        wrong_chain.successor.chain_id[0] ^= 1;
        assert!(verify_incremental_empty_activation_v2(wrong_chain, &witness).is_err());
    }
}
