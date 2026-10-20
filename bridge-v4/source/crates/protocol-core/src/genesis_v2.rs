//! Canonical pristine finite genesis shared by materializers and proof consumers.
//! Derivation is not evidence of deployment, UTXO inclusion or authenticated time.
use crate::{
    active_order_risk_root_v2, bond_inbox_outcome_genesis_root_v2, position_risk_root_v2,
    redemption_queue_root_v2, Amount, BondInboxStateV2, BondPublicStateV2, CapitalModeV2,
    DepositInboxStateV1, ExchangeState, ExchangeStateV2, ForcedInboxStateV1, FrozenConfigurationV2,
    FundingStateV2, Hash32, Price, StateRoots, BOND_FIXED_SUPPLY_ATOMS, BOND_PROTOCOL_VERSION_V2,
};

pub fn derive_empty_genesis_v2(
    configuration: &FrozenConfigurationV2,
    state_creation_sidechain_height: u64,
    prior_parent_mtp: u64,
    genesis_mark_price_atoms: u64,
    order_receipts_root: Hash32,
) -> Result<ExchangeStateV2, String> {
    configuration.validate().map_err(|e| format!("configuration rejected: {e}"))?;
    if state_creation_sidechain_height == 0 || prior_parent_mtp == 0
        || genesis_mark_price_atoms == 0 || order_receipts_root == [0; 32] {
        return Err("genesis height, time, mark and order root must be nonzero".to_owned());
    }
    let configuration_hash = configuration.digest();
    let chain_id = configuration.base.chain_id;
    let forced_inbox =
        ForcedInboxStateV1::genesis(configuration.base.forced_action_domain, chain_id)
            .map_err(|error| format!("cannot derive forced inbox genesis: {error}"))?;
    let deposit_inbox =
        DepositInboxStateV1::genesis(configuration.base.deposit_inbox_domain, chain_id)
            .map_err(|error| format!("cannot derive deposit inbox genesis: {error}"))?;
    let bond_inbox = BondInboxStateV2::genesis(
        configuration.bond_inbox_domain,
        chain_id,
        configuration_hash,
    )
    .map_err(|error| format!("cannot derive bond inbox genesis: {error}"))?;
    let bond_inbox_outcome_root = bond_inbox_outcome_genesis_root_v2(
        configuration.bond_inbox_domain,
        chain_id,
        configuration_hash,
    )
    .map_err(|error| format!("cannot derive bond inbox outcome genesis: {error}"))?;
    let active_order_risk_root = active_order_risk_root_v2(&[])
        .map_err(|error| format!("cannot derive active-order-risk genesis: {error}"))?;
    let position_risk_root = position_risk_root_v2(&[])
        .map_err(|error| format!("cannot derive position-risk genesis: {error}"))?;

    let bond = BondPublicStateV2 {
        version: BOND_PROTOCOL_VERSION_V2,
        bond_asset_id: configuration.bond_asset_id,
        deployment_commitment: configuration.bond_deployment_commitment,
        inventory_covenant_hash: configuration.bond_inventory_script_sha256,
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
    .validate()
    .map_err(|error| format!("cannot derive bond genesis: {error}"))?;
    let mark = Price::new(genesis_mark_price_atoms)
        .map_err(|error| format!("invalid genesis mark price: {error}"))?;
    let funding = FundingStateV2::genesis_with_band(
        prior_parent_mtp,
        mark,
        mark,
        mark,
        prior_parent_mtp,
        0,
    )
    .map_err(|error| format!("cannot derive funding genesis: {error}"))?;
    let roots = StateRoots::from_private_state(&[], &[], &[], &[], &[], order_receipts_root)
        .map_err(|error| format!("cannot derive private-state roots: {error}"))?;
    let finite_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id,
            market: configuration.base.market,
            sequence: 0,
            last_processed_height: state_creation_sidechain_height,
            mark_price: mark,
            funding_index: 0,
            total_deposits: Amount(0),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(0),
            matcher_sequence: configuration.base.matcher.genesis_sequence,
            matcher_receipt_hash: configuration.base.matcher.genesis_receipt_hash,
            forced_inbox,
            deposit_inbox,
            roots,
        },
        bond,
        funding,
        matcher_execution_sequence: 0,
        last_transition_sidechain_height: state_creation_sidechain_height,
        bond_inbox,
        bond_inbox_outcome_root,
        bond_inbox_outcome_count: 0,
        active_order_risk_root,
        position_risk_root,
    };
    finite_state
        .validate()
        .map_err(|error| format!("finite genesis state rejected: {error}"))?;

    Ok(finite_state)
}
