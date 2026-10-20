//! Fail-closed private snapshot composer for successor trader-state grants.
//!
//! The composer does not fetch or invent exchange state. A proof producer
//! supplies the exact public-state preimage, one opened trader leaf, and the
//! canonical shared-frontier membership path. This module verifies that the
//! preimage reconstructs the authenticated root and that the typed opening is
//! a member before producing the exact snapshot consumed by the grant service.

use anyhow::{Context, Result, bail};
use ecx_protocol_core::{
    Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2,
    SparseMerkleSumFrontierItemV2, TraderLeafV2, TraderStateReadBatchProofV2,
};
use serde::{Deserialize, Serialize};

use crate::SuccessorTraderStateSnapshotV2;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderStateComposeInputV2 {
    pub version: u8,
    pub expected_exchange_state_root: Hash32,
    pub state: IncrementalPublicStateV2,
    pub trader_leaf: TraderLeafV2,
    pub frontier: Vec<SparseMerkleSumFrontierItemV2>,
}

impl SuccessorTraderStateComposeInputV2 {
    pub const VERSION: u8 = 1;
}

pub fn compose_successor_trader_state_snapshot(
    configuration: IncrementalSuccessorConfigurationV2,
    input: SuccessorTraderStateComposeInputV2,
) -> Result<SuccessorTraderStateSnapshotV2> {
    configuration
        .validate()
        .context("invalid incremental-successor configuration")?;
    if input.version != SuccessorTraderStateComposeInputV2::VERSION
        || input.expected_exchange_state_root == [0; 32]
    {
        bail!("invalid successor trader-state composition input");
    }
    input
        .state
        .validate(configuration)
        .context("invalid incremental public-state preimage")?;
    let exchange_state_root = input
        .state
        .state_root(configuration)
        .context("deriving incremental public-state root")?;
    if exchange_state_root != input.expected_exchange_state_root {
        bail!("incremental public-state preimage does not match the expected exchange root");
    }

    let trader = input.trader_leaf.trader;
    let trader_read = TraderStateReadBatchProofV2 {
        leaves: vec![input.trader_leaf],
        frontier: input.frontier,
    };
    trader_read
        .verify(input.state.trader_root, configuration.accounting_bounds)
        .context("invalid authenticated trader-state opening")?;

    Ok(SuccessorTraderStateSnapshotV2 {
        version: SuccessorTraderStateSnapshotV2::VERSION,
        exchange_state_root,
        trader,
        state: input.state,
        trader_read,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        BOND_FIXED_SUPPLY_ATOMS, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        IncrementalAccountingBoundsV2, Int256V2, RiskParams, TraderStateBatchLeafUpdateV2,
        TraderStateBatchProofV2, XOnlyKey,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;

    fn configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [7; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [3; 32],
            successor_matcher_configuration_hash: [4; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
                maximum_total_controlled_atoms: u128::from(BOND_FIXED_SUPPLY_ATOMS),
                maximum_abs_position_atoms: 10_000_000_000,
                maximum_open_interest_atoms: 20_000_000_000,
                maximum_price_atoms: 10_000_000_000,
            },
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        }
    }

    fn fixture() -> (
        IncrementalSuccessorConfigurationV2,
        SuccessorTraderStateComposeInputV2,
    ) {
        let configuration = configuration();
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        let trader = XOnlyKey(public.serialize());
        let leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: 9,
            collateral_atoms: 0,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 11,
            salt: [0x31; 32],
        };
        let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader,
                old_leaf: None,
                new_leaf: Some(leaf.clone()),
            }],
            configuration.accounting_bounds,
        )
        .unwrap();
        let mut state =
            IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
        state.trader_root = insertion
            .verify(state.trader_root, configuration.accounting_bounds, 1)
            .unwrap();
        let expected_exchange_state_root = state.state_root(configuration).unwrap();
        (
            configuration,
            SuccessorTraderStateComposeInputV2 {
                version: SuccessorTraderStateComposeInputV2::VERSION,
                expected_exchange_state_root,
                state,
                trader_leaf: leaf,
                frontier: insertion.frontier,
            },
        )
    }

    #[test]
    fn successor_snapshot_composer_requires_exact_state_and_typed_opening() {
        let (configuration, input) = fixture();
        let snapshot = compose_successor_trader_state_snapshot(configuration, input.clone())
            .expect("valid authenticated opening composes");
        assert_eq!(
            snapshot.exchange_state_root,
            input.expected_exchange_state_root
        );
        assert_eq!(snapshot.trader, input.trader_leaf.trader);
        snapshot
            .trader_read
            .verify(snapshot.state.trader_root, configuration.accounting_bounds)
            .unwrap();

        let mut wrong_root = input.clone();
        wrong_root.expected_exchange_state_root[0] ^= 1;
        assert!(compose_successor_trader_state_snapshot(configuration, wrong_root).is_err());

        let mut wrong_leaf = input.clone();
        wrong_leaf.trader_leaf.salt[0] ^= 1;
        assert!(compose_successor_trader_state_snapshot(configuration, wrong_leaf).is_err());

        let mut wrong_frontier = input.clone();
        wrong_frontier.frontier.pop();
        assert!(compose_successor_trader_state_snapshot(configuration, wrong_frontier).is_err());

        let mut wrong_state = input;
        wrong_state.state.sidechain_height += 1;
        assert!(compose_successor_trader_state_snapshot(configuration, wrong_state).is_err());
    }
}
