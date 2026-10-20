//! Recursive child composing signed fills, permissionless liquidations, and
//! lazy-funding normalization with the exact trader mutation transcript.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    apply_incremental_trader_economic_mutation_v2, trading_fee, Hash32,
    IncrementalSuccessorConfigurationV2, IncrementalTraderEconomicMutationV2,
    IncrementalTraderMutationChainV2, IncrementalTraderMutationKindV2, Int256V2, ProtocolError,
    Side, SuccessorSignedLimitOrderV2, TraderLeafV2, XOnlyKey, EXACT_ACCOUNTING_DENOMINATOR_V2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    incremental_liquidation_observation_root_v2, incremental_ordinary_execution_root_v2,
    incremental_trader_economic_mutation_root_v2, validate_incremental_forced_ioc_batch_v2,
    IncrementalForcedIocExecutionV2, IncrementalFundingOrdinaryExecutionV2,
    IncrementalLiquidationObservationV2,
};

pub const INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 4;
pub const INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (7 * 32) + (5 * 8) + (5 * 16) + 2;
pub const MAX_INCREMENTAL_ECONOMIC_ACTION_CHILD_INPUT_BYTES_V2: usize = 8 * 1024 * 1024;
pub const MAX_INCREMENTAL_ECONOMIC_MUTATIONS_V2: usize = 3 * 64;
pub const MAX_INCREMENTAL_ECONOMIC_CONFIGURATION_BYTES_V2: usize = 1_024;
pub const MAX_INCREMENTAL_ECONOMIC_ORDINARY_EXECUTION_BYTES_V2: usize = 2_048;
pub const MAX_INCREMENTAL_ECONOMIC_FORCED_IOC_BYTES_V2: usize = 1_024;
pub const MAX_INCREMENTAL_ECONOMIC_LIQUIDATION_BYTES_V2: usize = 1_024;
pub const MAX_INCREMENTAL_FUNDING_NORMALIZATION_BYTES_V2: usize = 64;
pub const MAX_INCREMENTAL_TRADER_MUTATION_BYTES_V2: usize = 256;
pub const MAX_INCREMENTAL_TRADER_MUTATION_CHAIN_FIXED_BYTES_V2: usize = 1_024;
pub const INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2: usize =
    MAX_INCREMENTAL_ECONOMIC_CONFIGURATION_BYTES_V2
        + 1_024
        + (64 * MAX_INCREMENTAL_ECONOMIC_ORDINARY_EXECUTION_BYTES_V2)
        + (64 * MAX_INCREMENTAL_ECONOMIC_FORCED_IOC_BYTES_V2)
        + (64 * MAX_INCREMENTAL_FUNDING_NORMALIZATION_BYTES_V2)
        + (64 * MAX_INCREMENTAL_TRADER_MUTATION_CHAIN_FIXED_BYTES_V2)
        + (MAX_INCREMENTAL_ECONOMIC_MUTATIONS_V2 * MAX_INCREMENTAL_TRADER_MUTATION_BYTES_V2);
const _: () = assert!(
    INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_ECONOMIC_ACTION_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalEconomicLiquidationV2 {
    pub target: XOnlyKey,
    pub maker: SuccessorSignedLimitOrderV2,
    pub quantity_atoms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalFundingNormalizationV2 {
    pub trader: XOnlyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalEconomicActionChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub sidechain_height: u64,
    pub global_funding_index_numerator: i128,
    pub previous_insurance_reserve_atoms: u128,
    pub insurance_reserve_before_bond_actions_atoms: u128,
    pub ordinary_executions: Vec<IncrementalFundingOrdinaryExecutionV2>,
    pub forced_iocs: Vec<SuccessorSignedLimitOrderV2>,
    pub forced_ioc_executions: Vec<IncrementalForcedIocExecutionV2>,
    pub liquidations: Vec<IncrementalEconomicLiquidationV2>,
    pub funding_normalizations: Vec<IncrementalFundingNormalizationV2>,
    pub trader_mutation_chains: Vec<IncrementalTraderMutationChainV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalEconomicActionChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub trader_economic_mutation_root: Hash32,
    pub ordinary_execution_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    pub economic_action_root: Hash32,
    pub ordinary_execution_count: u64,
    pub forced_ioc_count: u64,
    pub forced_ioc_execution_count: u64,
    pub liquidation_count: u64,
    pub funding_normalization_count: u64,
    pub global_funding_index_numerator: i128,
    pub previous_insurance_reserve_atoms: u128,
    /// Gross maker/taker fees and liquidation penalties collected by this
    /// transition. These atoms are credited to the insurance reserve.
    pub protocol_fee_atoms: u128,
    /// Exact whole-atom cover applied to fully closed insolvent traders. These
    /// atoms are debited from the insurance reserve and credited to the
    /// affected trader leaf before the next root is committed.
    pub liquidation_loss_atoms: u128,
    pub insurance_reserve_before_bond_actions_atoms: u128,
    pub authorized_mutation_count: u16,
}

impl IncrementalEconomicActionChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for hash in [
            self.configuration_hash,
            self.trader_economic_mutation_root,
            self.ordinary_execution_root,
            self.forced_ioc_root,
            self.forced_ioc_execution_root,
            self.liquidation_observation_root,
            self.economic_action_root,
        ] {
            out.extend_from_slice(&hash);
        }
        for count in [
            self.ordinary_execution_count,
            self.forced_ioc_count,
            self.forced_ioc_execution_count,
            self.liquidation_count,
            self.funding_normalization_count,
        ] {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(&self.global_funding_index_numerator.to_be_bytes());
        out.extend_from_slice(&self.previous_insurance_reserve_atoms.to_be_bytes());
        out.extend_from_slice(&self.protocol_fee_atoms.to_be_bytes());
        out.extend_from_slice(&self.liquidation_loss_atoms.to_be_bytes());
        out.extend_from_slice(
            &self
                .insurance_reserve_before_bond_actions_atoms
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.authorized_mutation_count.to_be_bytes());
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalEconomicActionChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub trader_economic_mutation_root: Hash32,
    pub ordinary_execution_root: Hash32,
    pub forced_ioc_root: Hash32,
    pub forced_ioc_execution_root: Hash32,
    pub liquidation_observation_root: Hash32,
    /// Ordered role-action commitment. The outer successor includes this in
    /// its action-composition root rather than silently discarding a field
    /// authenticated by the recursive child receipt.
    pub economic_action_root: Hash32,
    pub ordinary_execution_count: u64,
    pub forced_ioc_count: u64,
    pub forced_ioc_execution_count: u64,
    pub liquidation_count: u64,
    pub global_funding_index_numerator: i128,
    pub previous_insurance_reserve_atoms: u128,
    pub protocol_fee_atoms: u128,
    pub liquidation_loss_atoms: u128,
    pub insurance_reserve_before_bond_actions_atoms: u128,
    pub authorized_mutation_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalEconomicActionChildErrorV2 {
    #[error("unsupported incremental economic-action child version")]
    UnsupportedVersion,
    #[error("incremental economic-action child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental economic-action child input encoding failed")]
    InputEncoding,
    #[error("incremental economic-action composition rejected: {0}")]
    Protocol(#[from] ProtocolError),
}

#[derive(Clone)]
struct MutationOpening {
    before: TraderLeafV2,
    mutation: IncrementalTraderEconomicMutationV2,
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn role_action_id(tag: &[u8], body: &[u8], trader: XOnlyKey) -> Hash32 {
    let mut bytes = Vec::with_capacity(body.len() + 32);
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&trader.0);
    tagged_hash(tag, &bytes)
}

fn cash_atoms_numerator(atoms: i128) -> Result<Int256V2, ProtocolError> {
    let magnitude = atoms
        .checked_mul(i128::from(EXACT_ACCOUNTING_DENOMINATOR_V2))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    Ok(Int256V2::from_i128(magnitude))
}

// Fixture-independent relation helper keeps every economic coordinate explicit
// at its call site, which is easier to audit than a second host-shaped record.
#[allow(clippy::too_many_arguments)]
fn derive_after_trade(
    before: &TraderLeafV2,
    side: Side,
    price_atoms: u64,
    quantity_atoms: u64,
    cash_charge_atoms: i128,
    insurance_credit_atoms: u128,
    funding_index: i128,
    configuration: &IncrementalSuccessorConfigurationV2,
) -> Result<TraderLeafV2, ProtocolError> {
    let signed_quantity = i64::try_from(quantity_atoms)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?
        .checked_mul(side.sign())
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let mut expected = before.clone();
    expected.apply_trade_exact(
        signed_quantity,
        price_atoms,
        funding_index,
        configuration.accounting_bounds,
    )?;
    expected.apply_exact_cash_delta_numerator(
        cash_atoms_numerator(cash_charge_atoms)?.checked_neg()?,
        configuration.accounting_bounds,
    )?;
    if insurance_credit_atoms != 0 {
        let credit = i128::try_from(insurance_credit_atoms)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        expected.apply_exact_cash_delta_numerator(
            cash_atoms_numerator(credit)?,
            configuration.accounting_bounds,
        )?;
    }
    Ok(expected)
}

/// Whole reserve atoms required to clear a fully closed trader's exact
/// negative cash. The outward ceiling is mandatory because reserve outputs are
/// whole atoms while trader cash retains a sub-atom exact numerator.
fn flat_liquidation_loss_atoms(
    trader: &TraderLeafV2,
    configuration: &IncrementalSuccessorConfigurationV2,
) -> Result<u128, ProtocolError> {
    if trader.position_size_atoms != 0 {
        return Ok(0);
    }
    let exact_cash = trader.exact_cash_numerator(configuration.accounting_bounds)?;
    if !exact_cash.is_negative() {
        return Ok(0);
    }
    let (whole, remainder) = exact_cash
        .magnitude()
        .div_rem_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    let whole = if remainder == 0 {
        whole
    } else {
        whole.checked_add(ecx_protocol_core::Uint256V2::from_u64(1))?
    };
    whole.try_to_u128()
}

fn expected_after_trade(
    opening: &MutationOpening,
    kind: IncrementalTraderMutationKindV2,
    action_id: Hash32,
    side: Side,
    price_atoms: u64,
    quantity_atoms: u64,
    cash_charge_atoms: i128,
    insurance_credit_atoms: u128,
    funding_index: i128,
    configuration: &IncrementalSuccessorConfigurationV2,
) -> Result<TraderLeafV2, ProtocolError> {
    let mutation = &opening.mutation;
    if mutation.kind != kind
        || mutation.action_id != action_id
        || mutation.account_nonce_increment != 0
        || mutation.order_generation_increment != 0
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut expected = derive_after_trade(
        &opening.before,
        side,
        price_atoms,
        quantity_atoms,
        cash_charge_atoms,
        insurance_credit_atoms,
        funding_index,
        configuration,
    )?;
    let actual = apply_incremental_trader_economic_mutation_v2(
        &opening.before,
        mutation,
        configuration.accounting_bounds,
    )?;
    // Margin selection is authorized by the order/risk children. This child
    // composes every economic field while permitting that separately proved
    // projection to update the selected margin in the same mutation.
    expected.selected_initial_margin_bps = actual.selected_initial_margin_bps;
    if actual != expected {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(expected)
}

pub fn decode_incremental_economic_action_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalEconomicActionChildProjectionV2, IncrementalEconomicActionChildErrorV2> {
    if bytes.len() != INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalEconomicActionChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalEconomicActionChildErrorV2> {
        let start = 4 + index * 32;
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalEconomicActionChildErrorV2::UnsupportedVersion)
    };
    let i128_at = |index: usize| -> Result<i128, IncrementalEconomicActionChildErrorV2> {
        let start = 4 + (7 * 32) + (5 * 8) + index * 16;
        Ok(i128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalEconomicActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let u64_at = |index: usize| -> Result<u64, IncrementalEconomicActionChildErrorV2> {
        let start = 4 + (7 * 32) + index * 8;
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalEconomicActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let u128_at = |index: usize| -> Result<u128, IncrementalEconomicActionChildErrorV2> {
        let start = 4 + (7 * 32) + (5 * 8) + index * 16;
        Ok(u128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalEconomicActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    Ok(IncrementalEconomicActionChildProjectionV2 {
        configuration_hash: hash(0)?,
        trader_economic_mutation_root: hash(1)?,
        ordinary_execution_root: hash(2)?,
        forced_ioc_root: hash(3)?,
        forced_ioc_execution_root: hash(4)?,
        liquidation_observation_root: hash(5)?,
        economic_action_root: hash(6)?,
        ordinary_execution_count: u64_at(0)?,
        forced_ioc_count: u64_at(1)?,
        forced_ioc_execution_count: u64_at(2)?,
        liquidation_count: u64_at(3)?,
        global_funding_index_numerator: i128_at(0)?,
        previous_insurance_reserve_atoms: u128_at(1)?,
        protocol_fee_atoms: u128_at(2)?,
        liquidation_loss_atoms: u128_at(3)?,
        insurance_reserve_before_bond_actions_atoms: u128_at(4)?,
        authorized_mutation_count: u16::from_be_bytes(
            bytes[INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 2..]
                .try_into()
                .map_err(|_| IncrementalEconomicActionChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use ecx_protocol_core::{
        Amount, IncrementalAccountingBoundsV2, OrderFlags, Price, Quantity, RiskParams,
        Signature64, SuccessorCentralMatcherReceiptV2, SuccessorLimitOrderV2,
        SuccessorMatcherCommandKindV2, SuccessorMatcherReceiptBodyV2, SuccessorSignedLimitOrderV2,
        SuccessorTradeMatchV2, TimeInForce, TraderLeafV2,
        INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;

    fn fixed_size<T: Serialize>(value: &T) -> usize {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(value)
            .unwrap()
            .len()
    }

    fn configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [0x11; 32],
            market: ecx_protocol_core::ECX_USDD_MARKET,
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

    fn leaf() -> TraderLeafV2 {
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey([2; 32]),
            account_nonce: 0,
            collateral_atoms: 1_000,
            cash_residual_numerator: 0,
            position_size_atoms: 10,
            signed_cost_basis_numerator: Int256V2::from_i128(
                10 * 100 * i128::from(ecx_protocol_core::FUNDING_INDEX_DENOMINATOR_V2),
            ),
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [3; 32],
        }
    }

    fn signed_order(secret: &SecretKey, side: Side, nonce: u64) -> SuccessorSignedLimitOrderV2 {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: [0x11; 32],
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader,
                side,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                client_order_id: [u8::try_from(nonce).unwrap(); 16],
                max_fee_bps: 100,
                nonce: (1u128 << 96) + u128::from(nonce),
                valid_from_height: 0,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    fn signed_forced_ioc(
        secret: &SecretKey,
        side: Side,
        nonce: u64,
    ) -> SuccessorSignedLimitOrderV2 {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: [0x11; 32],
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader,
                side,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::REDUCE_ONLY,
                client_order_id: [u8::try_from(nonce).unwrap(); 16],
                max_fee_bps: 100,
                nonce: (1u128 << 96) + u128::from(nonce),
                valid_from_height: 0,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    fn flat_leaf(trader: XOnlyKey, salt: Hash32) -> TraderLeafV2 {
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: 0,
            collateral_atoms: 1_000,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt,
        }
    }

    fn trade_chain(
        old: TraderLeafV2,
        action_id: Hash32,
        side: Side,
        fee: i128,
        final_salt: Hash32,
        configuration: IncrementalSuccessorConfigurationV2,
        kind: IncrementalTraderMutationKindV2,
    ) -> IncrementalTraderMutationChainV2 {
        let mut next = old.clone();
        next.apply_trade_exact(
            side.sign() * 10,
            100_000_000,
            0,
            configuration.accounting_bounds,
        )
        .unwrap();
        next.apply_exact_cash_delta_numerator(
            cash_atoms_numerator(fee).unwrap().checked_neg().unwrap(),
            configuration.accounting_bounds,
        )
        .unwrap();
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind,
            action_id,
            exact_cash_delta_numerator: next
                .exact_cash_numerator(configuration.accounting_bounds)
                .unwrap()
                .checked_sub(
                    old.exact_cash_numerator(configuration.accounting_bounds)
                        .unwrap(),
                )
                .unwrap(),
            position_size_delta_atoms: next.position_size_atoms - old.position_size_atoms,
            signed_cost_basis_delta_numerator: next
                .signed_cost_basis_numerator
                .checked_sub(old.signed_cost_basis_numerator)
                .unwrap(),
            funding_checkpoint_after: Some(next.last_funding_index_numerator),
            account_nonce_increment: 0,
            order_generation_increment: 0,
            selected_initial_margin_bps_after: None,
        };
        next.salt = final_salt;
        IncrementalTraderMutationChainV2 {
            trader: old.trader,
            old_leaf: old,
            mutations: vec![mutation],
            final_salt,
            expected_new_leaf: next,
        }
    }

    #[test]
    fn empty_relation_binds_reserve_and_public_layout() {
        let input = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration: configuration(),
            sidechain_height: 7,
            global_funding_index_numerator: 0,
            previous_insurance_reserve_atoms: 9,
            insurance_reserve_before_bond_actions_atoms: 9,
            ordinary_executions: vec![],
            forced_iocs: vec![],
            forced_ioc_executions: vec![],
            liquidations: vec![],
            funding_normalizations: vec![],
            trader_mutation_chains: vec![],
        };
        let values = execute_incremental_economic_action_child_v2(&input).unwrap();
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let projection = decode_incremental_economic_action_child_projection_v2(&encoded).unwrap();
        assert_eq!(projection.previous_insurance_reserve_atoms, 9);
        assert_eq!(projection.economic_action_root, values.economic_action_root);
        let mut wrong = input;
        wrong.insurance_reserve_before_bond_actions_atoms = 10;
        assert!(execute_incremental_economic_action_child_v2(&wrong).is_err());
    }

    #[test]
    fn funding_normalization_is_exact_and_tamper_rejects() {
        let configuration = configuration();
        let old = leaf();
        let funding_index = 5_000i128;
        let mut expected = old.clone();
        expected
            .settle_lazy_funding(funding_index, configuration.accounting_bounds)
            .unwrap();
        let action_id = role_action_id(
            b"ECX/incremental-funding-normalization/v1",
            &funding_index.to_be_bytes(),
            old.trader,
        );
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::FundingSettlement,
            action_id,
            exact_cash_delta_numerator: expected
                .exact_cash_numerator(configuration.accounting_bounds)
                .unwrap()
                .checked_sub(
                    old.exact_cash_numerator(configuration.accounting_bounds)
                        .unwrap(),
                )
                .unwrap(),
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: Some(funding_index),
            account_nonce_increment: 0,
            order_generation_increment: 0,
            selected_initial_margin_bps_after: None,
        };
        expected.salt = [4; 32];
        let chain = IncrementalTraderMutationChainV2 {
            trader: old.trader,
            old_leaf: old,
            mutations: vec![mutation],
            final_salt: [4; 32],
            expected_new_leaf: expected,
        };
        let input = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 7,
            global_funding_index_numerator: funding_index,
            previous_insurance_reserve_atoms: 9,
            insurance_reserve_before_bond_actions_atoms: 9,
            ordinary_executions: vec![],
            forced_iocs: vec![],
            forced_ioc_executions: vec![],
            liquidations: vec![],
            funding_normalizations: vec![IncrementalFundingNormalizationV2 {
                trader: XOnlyKey([2; 32]),
            }],
            trader_mutation_chains: vec![chain],
        };
        assert!(execute_incremental_economic_action_child_v2(&input).is_ok());
        let mut tampered = input;
        tampered.global_funding_index_numerator += 1;
        assert!(execute_incremental_economic_action_child_v2(&tampered).is_err());
    }

    #[test]
    fn signed_ordinary_fill_derives_both_trader_mutations_and_fee_reserve() {
        let configuration = configuration();
        let maker = signed_order(&SecretKey::from_slice(&[7; 32]).unwrap(), Side::Sell, 1);
        let taker = signed_order(&SecretKey::from_slice(&[8; 32]).unwrap(), Side::Buy, 2);
        let trade = SuccessorTradeMatchV2 {
            sequence: (1u128 << 96) + 1,
            maker_order_id: maker.order_id(),
            taker_order_id: taker.order_id(),
            maker: maker.order.trader,
            taker: taker.order.trader,
            maker_side: Side::Sell,
            price: maker.order.limit_price,
            quantity: Quantity::new(10).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(1),
        };
        let execution = IncrementalFundingOrdinaryExecutionV2 {
            maker,
            taker,
            trade,
            taker_admission: SuccessorCentralMatcherReceiptV2 {
                body: SuccessorMatcherReceiptBodyV2 {
                    version: SuccessorMatcherReceiptBodyV2::VERSION,
                    chain_id: [0x11; 32],
                    market: ecx_protocol_core::ECX_USDD_MARKET,
                    matcher_config_hash: [9; 32],
                    matcher_key_epoch: 1,
                    global_sequence: (1u128 << 96) + 1,
                    previous_receipt_hash: [8; 32],
                    command_kind: SuccessorMatcherCommandKindV2::Place,
                    command_hash: [7; 32],
                    observed_sidechain_height: 1,
                    observed_parent_height: 1,
                    observed_parent_mtp: 1,
                    forced_inbox_cursor: 1u128 << 96,
                    availability_root: [6; 32],
                },
                signature: Signature64([5; 64]),
            },
        };
        let body = execution.canonical_bytes();
        let maker_id = role_action_id(
            b"ECX/incremental-ordinary-fill-role/v1",
            &body,
            execution.trade.maker,
        );
        let taker_id = role_action_id(
            b"ECX/incremental-ordinary-fill-role/v1",
            &body,
            execution.trade.taker,
        );
        let mut chains = vec![
            trade_chain(
                flat_leaf(execution.trade.maker, [3; 32]),
                maker_id,
                Side::Sell,
                0,
                [4; 32],
                configuration,
                IncrementalTraderMutationKindV2::OrdinaryFill,
            ),
            trade_chain(
                flat_leaf(execution.trade.taker, [5; 32]),
                taker_id,
                Side::Buy,
                1,
                [6; 32],
                configuration,
                IncrementalTraderMutationKindV2::OrdinaryFill,
            ),
        ];
        chains.sort_by_key(|chain| chain.trader.0);
        let input = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 7,
            global_funding_index_numerator: 0,
            previous_insurance_reserve_atoms: 9,
            insurance_reserve_before_bond_actions_atoms: 10,
            ordinary_executions: vec![execution],
            forced_iocs: vec![],
            forced_ioc_executions: vec![],
            liquidations: vec![],
            funding_normalizations: vec![],
            trader_mutation_chains: chains,
        };
        let values = execute_incremental_economic_action_child_v2(&input).unwrap();
        assert_eq!(values.protocol_fee_atoms, 1);
        assert_eq!(values.liquidation_loss_atoms, 0);
        let mut wrong_fee = input.clone();
        wrong_fee.ordinary_executions[0].trade.taker_fee = Amount(2);
        assert!(execute_incremental_economic_action_child_v2(&wrong_fee).is_err());
        let mut missing_mutation = input;
        missing_mutation.trader_mutation_chains.pop();
        assert!(execute_incremental_economic_action_child_v2(&missing_mutation).is_err());
    }

    #[test]
    fn liquidation_fees_credit_and_exact_bad_debt_debits_the_reserve() {
        let configuration = configuration();
        let target_secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let target_keypair = Keypair::from_secret_key(&Secp256k1::new(), &target_secret);
        let target = XOnlyKey(XOnlyPublicKey::from_keypair(&target_keypair).0.serialize());
        let maker = signed_order(&SecretKey::from_slice(&[7; 32]).unwrap(), Side::Buy, 3);
        let liquidation = IncrementalEconomicLiquidationV2 {
            target,
            maker: maker.clone(),
            quantity_atoms: 10,
        };
        let observation = IncrementalLiquidationObservationV2 {
            target,
            maker_order_id: maker.order_id(),
            price_atoms: maker.order.limit_price.get(),
            quantity_atoms: liquidation.quantity_atoms,
        };
        let body = observation.canonical_bytes();
        let target_id =
            role_action_id(b"ECX/incremental-liquidation-target-role/v1", &body, target);
        let maker_id = role_action_id(
            b"ECX/incremental-liquidation-maker-role/v1",
            &body,
            maker.order.trader,
        );
        let mut target_old = flat_leaf(target, [0x31; 32]);
        target_old.collateral_atoms = 0;
        target_old.position_size_atoms = 10;
        target_old.signed_cost_basis_numerator = Int256V2::from_i128(
            10 * 200_000_000 * i128::from(ecx_protocol_core::FUNDING_INDEX_DENOMINATOR_V2),
        );
        let quantity = Quantity::new(liquidation.quantity_atoms).unwrap();
        let penalty = trading_fee(
            maker.order.limit_price,
            quantity,
            i32::try_from(configuration.risk_params.liquidation_fee_bps).unwrap(),
        )
        .unwrap()
        .0;
        let provisional = derive_after_trade(
            &target_old,
            Side::Sell,
            maker.order.limit_price.get(),
            liquidation.quantity_atoms,
            penalty,
            0,
            0,
            &configuration,
        )
        .unwrap();
        let loss = flat_liquidation_loss_atoms(&provisional, &configuration).unwrap();
        assert_eq!(penalty, 1);
        assert_eq!(loss, 11);

        let mut chains = vec![
            trade_chain(
                target_old.clone(),
                target_id,
                Side::Sell,
                penalty - i128::try_from(loss).unwrap(),
                [0x32; 32],
                configuration,
                IncrementalTraderMutationKindV2::Liquidation,
            ),
            trade_chain(
                flat_leaf(maker.order.trader, [0x41; 32]),
                maker_id,
                Side::Buy,
                0,
                [0x42; 32],
                configuration,
                IncrementalTraderMutationKindV2::Liquidation,
            ),
        ];
        chains.sort_by_key(|chain| chain.trader.0);
        let reserve_before = 20u128;
        let reserve_after = reserve_before
            .checked_add(u128::try_from(penalty).unwrap())
            .unwrap()
            .checked_sub(loss)
            .unwrap();
        let input = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 7,
            global_funding_index_numerator: 0,
            previous_insurance_reserve_atoms: reserve_before,
            insurance_reserve_before_bond_actions_atoms: reserve_after,
            ordinary_executions: vec![],
            forced_iocs: vec![],
            forced_ioc_executions: vec![],
            liquidations: vec![liquidation],
            funding_normalizations: vec![],
            trader_mutation_chains: chains,
        };
        let values = execute_incremental_economic_action_child_v2(&input).unwrap();
        assert_eq!(values.protocol_fee_atoms, 1);
        assert_eq!(values.liquidation_loss_atoms, 11);
        assert_eq!(values.insurance_reserve_before_bond_actions_atoms, 10);
        let projection =
            decode_incremental_economic_action_child_projection_v2(&values.encode()).unwrap();
        assert_eq!(projection.protocol_fee_atoms, 1);
        assert_eq!(projection.liquidation_loss_atoms, 11);

        let mut uncovered = input.clone();
        let target_chain = uncovered
            .trader_mutation_chains
            .iter_mut()
            .find(|chain| chain.trader == target)
            .unwrap();
        *target_chain = trade_chain(
            target_old,
            target_id,
            Side::Sell,
            penalty,
            [0x32; 32],
            configuration,
            IncrementalTraderMutationKindV2::Liquidation,
        );
        assert!(execute_incremental_economic_action_child_v2(&uncovered).is_err());

        let mut underfunded = input;
        underfunded.previous_insurance_reserve_atoms = 9;
        underfunded.insurance_reserve_before_bond_actions_atoms = 0;
        assert!(execute_incremental_economic_action_child_v2(&underfunded).is_err());
    }

    #[test]
    fn forced_reduce_only_ioc_fill_binds_signed_action_economics_and_cannot_grow_risk() {
        let configuration = configuration();
        let maker = signed_order(&SecretKey::from_slice(&[7; 32]).unwrap(), Side::Sell, 1);
        let taker = signed_forced_ioc(&SecretKey::from_slice(&[8; 32]).unwrap(), Side::Buy, 2);
        let execution = IncrementalForcedIocExecutionV2 {
            trade: SuccessorTradeMatchV2 {
                sequence: crate::INCREMENTAL_FORCED_IOC_TAKER_SEQUENCE_V2,
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
        let body = execution.canonical_bytes();
        let maker_id = role_action_id(
            b"ECX/incremental-forced-ioc-fill-role/v1",
            &body,
            execution.trade.maker,
        );
        let taker_id = role_action_id(
            b"ECX/incremental-forced-ioc-fill-role/v1",
            &body,
            execution.trade.taker,
        );
        let mut taker_old = flat_leaf(execution.trade.taker, [5; 32]);
        taker_old.position_size_atoms = -10;
        taker_old.signed_cost_basis_numerator = Int256V2::from_i128(
            -10 * 100_000_000 * i128::from(ecx_protocol_core::FUNDING_INDEX_DENOMINATOR_V2),
        );
        let mut chains = vec![
            trade_chain(
                flat_leaf(execution.trade.maker, [3; 32]),
                maker_id,
                Side::Sell,
                0,
                [4; 32],
                configuration,
                IncrementalTraderMutationKindV2::ForcedReduceOnlyIocFill,
            ),
            trade_chain(
                taker_old,
                taker_id,
                Side::Buy,
                1,
                [6; 32],
                configuration,
                IncrementalTraderMutationKindV2::ForcedReduceOnlyIocFill,
            ),
        ];
        chains.sort_by_key(|chain| chain.trader.0);
        let input = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 7,
            global_funding_index_numerator: 0,
            previous_insurance_reserve_atoms: 9,
            insurance_reserve_before_bond_actions_atoms: 10,
            ordinary_executions: vec![],
            forced_iocs: vec![taker],
            forced_ioc_executions: vec![execution],
            liquidations: vec![],
            funding_normalizations: vec![],
            trader_mutation_chains: chains,
        };
        let values = execute_incremental_economic_action_child_v2(&input).unwrap();
        assert_eq!(values.forced_ioc_count, 1);
        assert_eq!(values.forced_ioc_execution_count, 1);

        let mut wrong_position = input.clone();
        let taker_chain = wrong_position
            .trader_mutation_chains
            .iter_mut()
            .find(|chain| chain.trader == wrong_position.forced_iocs[0].order.trader)
            .unwrap();
        taker_chain.old_leaf.position_size_atoms = 10;
        assert!(execute_incremental_economic_action_child_v2(&wrong_position).is_err());

        let mut substituted_action = input;
        substituted_action.forced_iocs[0].signature.0[0] ^= 1;
        assert!(execute_incremental_economic_action_child_v2(&substituted_action).is_err());
    }

    #[test]
    fn economic_action_child_has_exact_reachable_encoding_ceiling() {
        let configuration = configuration();
        let maker = signed_order(&SecretKey::from_slice(&[7; 32]).unwrap(), Side::Sell, 1);
        let taker = signed_order(&SecretKey::from_slice(&[8; 32]).unwrap(), Side::Buy, 2);
        let execution = IncrementalFundingOrdinaryExecutionV2 {
            maker: maker.clone(),
            taker,
            trade: SuccessorTradeMatchV2 {
                sequence: u128::MAX,
                maker_order_id: [1; 32],
                taker_order_id: [2; 32],
                maker: maker.order.trader,
                taker: XOnlyKey([3; 32]),
                maker_side: Side::Sell,
                price: Price::new(u64::MAX).unwrap(),
                quantity: Quantity::new(i64::MAX as u64).unwrap(),
                maker_fee: Amount(i128::MAX),
                taker_fee: Amount(i128::MAX),
            },
            taker_admission: SuccessorCentralMatcherReceiptV2 {
                body: SuccessorMatcherReceiptBodyV2 {
                    version: SuccessorMatcherReceiptBodyV2::VERSION,
                    chain_id: [4; 32],
                    market: ecx_protocol_core::ECX_USDD_MARKET,
                    matcher_config_hash: [5; 32],
                    matcher_key_epoch: u64::MAX,
                    global_sequence: u128::MAX,
                    previous_receipt_hash: [6; 32],
                    command_kind: SuccessorMatcherCommandKindV2::Place,
                    command_hash: [7; 32],
                    observed_sidechain_height: u64::MAX,
                    observed_parent_height: u64::MAX,
                    observed_parent_mtp: u64::MAX,
                    forced_inbox_cursor: u128::MAX,
                    availability_root: [8; 32],
                },
                signature: Signature64([9; 64]),
            },
        };
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::OrdinaryFill,
            action_id: [10; 32],
            exact_cash_delta_numerator: Int256V2::from_i128(i128::MAX),
            position_size_delta_atoms: i64::MAX,
            signed_cost_basis_delta_numerator: Int256V2::from_i128(i128::MAX),
            funding_checkpoint_after: Some(i128::MAX),
            account_nonce_increment: u128::MAX,
            order_generation_increment: u128::MAX,
            selected_initial_margin_bps_after: Some(u32::MAX),
        };
        let chain = IncrementalTraderMutationChainV2 {
            trader: XOnlyKey([11; 32]),
            old_leaf: leaf(),
            mutations: vec![mutation.clone(); 64],
            final_salt: [12; 32],
            expected_new_leaf: leaf(),
        };
        assert!(fixed_size(&configuration) <= MAX_INCREMENTAL_ECONOMIC_CONFIGURATION_BYTES_V2);
        assert!(fixed_size(&execution) <= MAX_INCREMENTAL_ECONOMIC_ORDINARY_EXECUTION_BYTES_V2);
        assert!(
            fixed_size(&IncrementalEconomicLiquidationV2 {
                target: XOnlyKey([13; 32]),
                maker,
                quantity_atoms: u64::MAX,
            }) <= MAX_INCREMENTAL_ECONOMIC_LIQUIDATION_BYTES_V2
        );
        assert!(
            fixed_size(&IncrementalFundingNormalizationV2 {
                trader: XOnlyKey([14; 32]),
            }) <= MAX_INCREMENTAL_FUNDING_NORMALIZATION_BYTES_V2
        );
        assert!(fixed_size(&mutation) <= MAX_INCREMENTAL_TRADER_MUTATION_BYTES_V2);
        assert!(
            fixed_size(&chain) - (64 * fixed_size(&mutation))
                <= MAX_INCREMENTAL_TRADER_MUTATION_CHAIN_FIXED_BYTES_V2
        );
        assert_eq!(
            INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2,
            317_440
        );

        let oversized = IncrementalEconomicActionChildInputV2 {
            version: INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2,
            configuration,
            sidechain_height: 1,
            global_funding_index_numerator: 0,
            previous_insurance_reserve_atoms: 0,
            insurance_reserve_before_bond_actions_atoms: 0,
            ordinary_executions: vec![],
            forced_iocs: vec![],
            forced_ioc_executions: vec![],
            liquidations: vec![],
            funding_normalizations: vec![],
            trader_mutation_chains: vec![chain],
        };
        assert_eq!(
            execute_incremental_economic_action_child_v2(&oversized),
            Err(IncrementalEconomicActionChildErrorV2::InputTooLarge)
        );
    }
}

pub fn execute_incremental_economic_action_child_v2(
    input: &IncrementalEconomicActionChildInputV2,
) -> Result<IncrementalEconomicActionChildPublicValuesV2, IncrementalEconomicActionChildErrorV2> {
    if input.version != INCREMENTAL_ECONOMIC_ACTION_CHILD_VERSION_V2 {
        return Err(IncrementalEconomicActionChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    let maximum_trader_updates = usize::from(input.configuration.maximum_trader_updates);
    let maximum_order_operations = usize::from(input.configuration.maximum_order_operations);
    let order_action_count = input
        .ordinary_executions
        .len()
        .checked_add(input.forced_ioc_executions.len())
        .and_then(|count| count.checked_add(input.liquidations.len()))
        .ok_or(IncrementalEconomicActionChildErrorV2::InputTooLarge)?;
    let mutation_count = input
        .trader_mutation_chains
        .iter()
        .try_fold(0usize, |count, chain| {
            count.checked_add(chain.mutations.len())
        })
        .ok_or(IncrementalEconomicActionChildErrorV2::InputTooLarge)?;
    let maximum_reachable_mutations = order_action_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(input.funding_normalizations.len()))
        .ok_or(IncrementalEconomicActionChildErrorV2::InputTooLarge)?;
    if input.trader_mutation_chains.len() > maximum_trader_updates
        || input.funding_normalizations.len() > maximum_trader_updates
        || order_action_count > maximum_order_operations
        || mutation_count > maximum_reachable_mutations
        || mutation_count > MAX_INCREMENTAL_ECONOMIC_MUTATIONS_V2
        || input
            .trader_mutation_chains
            .iter()
            .any(|chain| chain.mutations.len() > 64)
    {
        return Err(IncrementalEconomicActionChildErrorV2::InputTooLarge);
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalEconomicActionChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_ECONOMIC_ACTION_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalEconomicActionChildErrorV2::InputTooLarge);
    }
    let mutation_root = incremental_trader_economic_mutation_root_v2(
        &input.trader_mutation_chains,
        input.configuration.accounting_bounds,
    )?;
    let mut openings = BTreeMap::new();
    for chain in &input.trader_mutation_chains {
        let mut current = chain.old_leaf.clone();
        for mutation in &chain.mutations {
            if matches!(
                mutation.kind,
                IncrementalTraderMutationKindV2::OrdinaryFill
                    | IncrementalTraderMutationKindV2::ForcedReduceOnlyIocFill
                    | IncrementalTraderMutationKindV2::Liquidation
                    | IncrementalTraderMutationKindV2::FundingSettlement
            ) && openings
                .insert(
                    mutation.action_id,
                    MutationOpening {
                        before: current.clone(),
                        mutation: mutation.clone(),
                    },
                )
                .is_some()
            {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            current = apply_incremental_trader_economic_mutation_v2(
                &current,
                mutation,
                input.configuration.accounting_bounds,
            )?;
        }
    }

    let mut used = BTreeSet::new();
    let mut action_bytes = Vec::new();
    let mut protocol_fee_atoms = 0u128;
    let mut liquidation_loss_atoms = 0u128;
    for execution in &input.ordinary_executions {
        execution.trade.validate_orders(
            &execution.maker,
            &execution.taker,
            input.sidechain_height,
        )?;
        let maker_fee = trading_fee(
            execution.trade.price,
            execution.trade.quantity,
            input.configuration.risk_params.maker_fee_bps,
        )?;
        let taker_fee = trading_fee(
            execution.trade.price,
            execution.trade.quantity,
            i32::try_from(input.configuration.risk_params.taker_fee_bps)
                .map_err(|_| ProtocolError::InvalidRate)?,
        )?;
        if execution.trade.maker_fee != maker_fee || execution.trade.taker_fee != taker_fee {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let body = execution.canonical_bytes();
        for (trader, side, fee) in [
            (
                execution.trade.maker,
                execution.trade.maker_side,
                maker_fee.0,
            ),
            (
                execution.trade.taker,
                execution.trade.maker_side.opposite(),
                taker_fee.0,
            ),
        ] {
            let action_id = role_action_id(b"ECX/incremental-ordinary-fill-role/v1", &body, trader);
            let opening = openings
                .get(&action_id)
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            if !used.insert(action_id) || opening.before.trader != trader {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            expected_after_trade(
                opening,
                IncrementalTraderMutationKindV2::OrdinaryFill,
                action_id,
                side,
                execution.trade.price.get(),
                execution.trade.quantity.get(),
                fee,
                0,
                input.global_funding_index_numerator,
                &input.configuration,
            )?;
            protocol_fee_atoms = protocol_fee_atoms
                .checked_add(u128::try_from(fee).map_err(|_| ProtocolError::InvalidRate)?)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            action_bytes.extend_from_slice(&action_id);
        }
    }

    let (forced_ioc_root, forced_ioc_execution_root) = validate_incremental_forced_ioc_batch_v2(
        input.configuration.chain_id,
        input.configuration.market,
        input.sidechain_height,
        &input.forced_iocs,
        &input.forced_ioc_executions,
    )?;
    for execution in &input.forced_ioc_executions {
        let maker_fee = trading_fee(
            execution.trade.price,
            execution.trade.quantity,
            input.configuration.risk_params.maker_fee_bps,
        )?;
        let taker_fee = trading_fee(
            execution.trade.price,
            execution.trade.quantity,
            i32::try_from(input.configuration.risk_params.taker_fee_bps)
                .map_err(|_| ProtocolError::InvalidRate)?,
        )?;
        if execution.trade.maker_fee != maker_fee || execution.trade.taker_fee != taker_fee {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let body = execution.canonical_bytes();
        for (trader, side, fee, reduce_only_taker) in [
            (
                execution.trade.maker,
                execution.trade.maker_side,
                maker_fee.0,
                false,
            ),
            (
                execution.trade.taker,
                execution.trade.maker_side.opposite(),
                taker_fee.0,
                true,
            ),
        ] {
            let action_id =
                role_action_id(b"ECX/incremental-forced-ioc-fill-role/v1", &body, trader);
            let opening = openings
                .get(&action_id)
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            if !used.insert(action_id) || opening.before.trader != trader {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            if reduce_only_taker
                && (opening.before.position_size_atoms == 0
                    || side.sign() == opening.before.position_size_atoms.signum()
                    || execution.trade.quantity.get()
                        > opening.before.position_size_atoms.unsigned_abs())
            {
                return Err(ProtocolError::InvalidMerkleProof.into());
            }
            expected_after_trade(
                opening,
                IncrementalTraderMutationKindV2::ForcedReduceOnlyIocFill,
                action_id,
                side,
                execution.trade.price.get(),
                execution.trade.quantity.get(),
                fee,
                0,
                input.global_funding_index_numerator,
                &input.configuration,
            )?;
            protocol_fee_atoms = protocol_fee_atoms
                .checked_add(u128::try_from(fee).map_err(|_| ProtocolError::InvalidRate)?)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            action_bytes.extend_from_slice(&action_id);
        }
    }

    let mut observations = Vec::with_capacity(input.liquidations.len());
    for liquidation in &input.liquidations {
        liquidation.maker.verify()?;
        if liquidation.quantity_atoms == 0
            || !liquidation.maker.order.is_live_at(input.sidechain_height)
        {
            return Err(ProtocolError::InvalidQuantity.into());
        }
        let target_opening = openings
            .values()
            .find(|opening| {
                opening.before.trader == liquidation.target
                    && opening.mutation.kind == IncrementalTraderMutationKindV2::Liquidation
                    && !used.contains(&opening.mutation.action_id)
            })
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let target_side = if target_opening.before.position_size_atoms > 0 {
            Side::Sell
        } else if target_opening.before.position_size_atoms < 0 {
            Side::Buy
        } else {
            return Err(ProtocolError::InvalidMerkleProof.into());
        };
        if liquidation.maker.order.side != target_side.opposite()
            || liquidation.quantity_atoms > target_opening.before.position_size_atoms.unsigned_abs()
        {
            return Err(ProtocolError::InvalidQuantity.into());
        }
        let observation = IncrementalLiquidationObservationV2 {
            target: liquidation.target,
            maker_order_id: liquidation.maker.order_id(),
            price_atoms: liquidation.maker.order.limit_price.get(),
            quantity_atoms: liquidation.quantity_atoms,
        };
        let body = observation.canonical_bytes();
        let target_id = role_action_id(
            b"ECX/incremental-liquidation-target-role/v1",
            &body,
            liquidation.target,
        );
        let maker_id = role_action_id(
            b"ECX/incremental-liquidation-maker-role/v1",
            &body,
            liquidation.maker.order.trader,
        );
        let target_opening = openings
            .get(&target_id)
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let maker_opening = openings
            .get(&maker_id)
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if !used.insert(target_id)
            || !used.insert(maker_id)
            || target_opening.before.trader != liquidation.target
            || maker_opening.before.trader != liquidation.maker.order.trader
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let quantity = ecx_protocol_core::Quantity::new(liquidation.quantity_atoms)?;
        let maker_fee = trading_fee(
            liquidation.maker.order.limit_price,
            quantity,
            input.configuration.risk_params.maker_fee_bps,
        )?;
        let penalty = trading_fee(
            liquidation.maker.order.limit_price,
            quantity,
            i32::try_from(input.configuration.risk_params.liquidation_fee_bps)
                .map_err(|_| ProtocolError::InvalidRate)?,
        )?;
        let provisional_target = derive_after_trade(
            &target_opening.before,
            target_side,
            liquidation.maker.order.limit_price.get(),
            liquidation.quantity_atoms,
            penalty.0,
            0,
            input.global_funding_index_numerator,
            &input.configuration,
        )?;
        let liquidation_loss =
            flat_liquidation_loss_atoms(&provisional_target, &input.configuration)?;
        let covered_target = expected_after_trade(
            target_opening,
            IncrementalTraderMutationKindV2::Liquidation,
            target_id,
            target_side,
            liquidation.maker.order.limit_price.get(),
            liquidation.quantity_atoms,
            penalty.0,
            liquidation_loss,
            input.global_funding_index_numerator,
            &input.configuration,
        )?;
        // A full close must not leave negative exact cash after insurance has
        // been debited. Partial liquidations retain their open-position risk
        // and are represented by the authenticated deficit indices instead.
        if covered_target.position_size_atoms == 0
            && covered_target
                .exact_cash_numerator(input.configuration.accounting_bounds)?
                .is_negative()
        {
            return Err(ProtocolError::InvalidBondState.into());
        }
        expected_after_trade(
            maker_opening,
            IncrementalTraderMutationKindV2::Liquidation,
            maker_id,
            target_side.opposite(),
            liquidation.maker.order.limit_price.get(),
            liquidation.quantity_atoms,
            maker_fee.0,
            0,
            input.global_funding_index_numerator,
            &input.configuration,
        )?;
        protocol_fee_atoms = protocol_fee_atoms
            .checked_add(u128::try_from(penalty.0).map_err(|_| ProtocolError::InvalidRate)?)
            .and_then(|value| value.checked_add(u128::try_from(maker_fee.0).ok()?))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        liquidation_loss_atoms = liquidation_loss_atoms
            .checked_add(liquidation_loss)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        action_bytes.extend_from_slice(&target_id);
        action_bytes.extend_from_slice(&maker_id);
        observations.push(observation);
    }

    for normalization in &input.funding_normalizations {
        let action_id = role_action_id(
            b"ECX/incremental-funding-normalization/v1",
            &input.global_funding_index_numerator.to_be_bytes(),
            normalization.trader,
        );
        let opening = openings
            .get(&action_id)
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if !used.insert(action_id)
            || opening.before.trader != normalization.trader
            || opening.mutation.kind != IncrementalTraderMutationKindV2::FundingSettlement
            || opening.mutation.account_nonce_increment != 0
            || opening.mutation.order_generation_increment != 0
            || opening.mutation.selected_initial_margin_bps_after.is_some()
        {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        let mut expected = opening.before.clone();
        expected.settle_lazy_funding(
            input.global_funding_index_numerator,
            input.configuration.accounting_bounds,
        )?;
        let actual = apply_incremental_trader_economic_mutation_v2(
            &opening.before,
            &opening.mutation,
            input.configuration.accounting_bounds,
        )?;
        if actual != expected {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        action_bytes.extend_from_slice(&action_id);
    }
    if openings.keys().any(|action_id| !used.contains(action_id)) {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let expected_reserve = input
        .previous_insurance_reserve_atoms
        .checked_add(protocol_fee_atoms)
        .and_then(|value| value.checked_sub(liquidation_loss_atoms))
        .ok_or(ProtocolError::InvalidBondState)?;
    if expected_reserve != input.insurance_reserve_before_bond_actions_atoms {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let ordinary_execution_root =
        incremental_ordinary_execution_root_v2(&input.ordinary_executions)
            .map_err(|_| ProtocolError::InvalidMerkleProof)?;
    let liquidation_observation_root = incremental_liquidation_observation_root_v2(&observations)
        .map_err(|_| ProtocolError::InvalidMerkleProof)?;
    Ok(IncrementalEconomicActionChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        trader_economic_mutation_root: mutation_root,
        ordinary_execution_root,
        forced_ioc_root,
        forced_ioc_execution_root,
        liquidation_observation_root,
        economic_action_root: tagged_hash(b"ECX/incremental-economic-actions/v1", &action_bytes),
        ordinary_execution_count: u64::try_from(input.ordinary_executions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        forced_ioc_count: u64::try_from(input.forced_iocs.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        forced_ioc_execution_count: u64::try_from(input.forced_ioc_executions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        liquidation_count: u64::try_from(input.liquidations.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        funding_normalization_count: u64::try_from(input.funding_normalizations.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        global_funding_index_numerator: input.global_funding_index_numerator,
        previous_insurance_reserve_atoms: input.previous_insurance_reserve_atoms,
        protocol_fee_atoms,
        liquidation_loss_atoms,
        insurance_reserve_before_bond_actions_atoms: input
            .insurance_reserve_before_bond_actions_atoms,
        authorized_mutation_count: u16::try_from(used.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}
