//! Recursive child statement for the typed incremental risk-extrema tree.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    operational_risk_coordinates_v2, verify_trader_risk_extrema_batch_v2, Hash32,
    IncrementalSuccessorConfigurationV2, ProtocolError, RiskExtremaBatchProofV2, RiskExtremaRootV2,
    TraderStateBatchLeafUpdateV2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::incremental_trader_update_leaf_projection_v2;

pub const INCREMENTAL_RISK_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (5 * 32) + 2 + 1;
pub const MAX_INCREMENTAL_RISK_CHILD_INPUT_BYTES_V2: usize = 5 * 1024 * 1024;
pub const MAX_INCREMENTAL_RISK_PROOF_BINCODE_BYTES_V2: usize =
    ecx_protocol_core::MAX_RISK_EXTREMA_BATCH_BYTES_V2 + (64 * 1024);
pub const MAX_INCREMENTAL_RISK_TRADER_UPDATE_BYTES_V2: usize = 2_048;
pub const INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2: usize =
    MAX_INCREMENTAL_RISK_PROOF_BINCODE_BYTES_V2
        + (64 * MAX_INCREMENTAL_RISK_TRADER_UPDATE_BYTES_V2)
        + 1_024
        + 4_096;
const _: () = assert!(
    INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_RISK_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalRiskChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub trader_updates: Vec<TraderStateBatchLeafUpdateV2>,
    pub previous_root: RiskExtremaRootV2,
    pub next_root: RiskExtremaRootV2,
    pub updates: Option<RiskExtremaBatchProofV2>,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
    pub global_funding_index_numerator: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalRiskChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub previous_root_projection: Hash32,
    pub next_root_projection: Hash32,
    pub update_transcript_root: Hash32,
    pub trader_update_count: u16,
    pub operationally_safe: bool,
}

impl IncrementalRiskChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.trader_update_leaf_projection_root,
            self.previous_root_projection,
            self.next_root_projection,
            self.update_transcript_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.trader_update_count.to_be_bytes());
        out.push(u8::from(self.operationally_safe));
        debug_assert_eq!(out.len(), INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalRiskChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub previous_root_projection: Hash32,
    pub next_root_projection: Hash32,
    pub operationally_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalRiskChildErrorV2 {
    #[error("unsupported incremental risk child version")]
    UnsupportedVersion,
    #[error("incremental risk child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental risk child input encoding failed")]
    InputEncoding,
    #[error("incremental risk transition rejected: {0}")]
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

pub fn incremental_risk_root_projection_v2(root: RiskExtremaRootV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-risk-root-projection/v1",
        &root.canonical_bytes(),
    )
}

pub fn decode_incremental_risk_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalRiskChildProjectionV2, IncrementalRiskChildErrorV2> {
    if bytes.len() != INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
        || bytes[bytes.len() - 1] > 1
    {
        return Err(IncrementalRiskChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalRiskChildErrorV2> {
        bytes[4 + (index * 32)..4 + ((index + 1) * 32)]
            .try_into()
            .map_err(|_| IncrementalRiskChildErrorV2::UnsupportedVersion)
    };
    Ok(IncrementalRiskChildProjectionV2 {
        configuration_hash: hash(0)?,
        trader_update_leaf_projection_root: hash(1)?,
        previous_root_projection: hash(2)?,
        next_root_projection: hash(3)?,
        operationally_safe: bytes[bytes.len() - 1] == 1,
    })
}

pub fn execute_incremental_risk_child_v2(
    input: &IncrementalRiskChildInputV2,
) -> Result<IncrementalRiskChildPublicValuesV2, IncrementalRiskChildErrorV2> {
    if input.version != INCREMENTAL_RISK_CHILD_VERSION_V2 {
        return Err(IncrementalRiskChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.price_lower_atoms == 0 || input.price_lower_atoms > input.price_upper_atoms {
        return Err(ProtocolError::InvalidBondState.into());
    }
    if input.trader_updates.len() > usize::from(input.configuration.maximum_trader_updates) {
        return Err(IncrementalRiskChildErrorV2::InputTooLarge);
    }
    if let Some(proof) = &input.updates {
        proof.canonical_bytes_checked(input.configuration.accounting_bounds)?;
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalRiskChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_RISK_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalRiskChildErrorV2::InputTooLarge);
    }
    let bounds = input.configuration.accounting_bounds;
    let verified = verify_trader_risk_extrema_batch_v2(
        &input.trader_updates,
        input.previous_root,
        input.updates.as_ref(),
        input.configuration.risk_params.maintenance_margin_bps,
        bounds,
    )?;
    if verified != input.next_root {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let operationally_safe = if input.next_root.aggregate.leaf_count == 0 {
        true
    } else {
        let (long_x, short_x) = operational_risk_coordinates_v2(
            input.price_lower_atoms,
            input.price_upper_atoms,
            input.global_funding_index_numerator,
            input.configuration.risk_params.maintenance_margin_bps,
            bounds,
        )?;
        input
            .next_root
            .aggregate
            .all_positions_operationally_safe(long_x, short_x)?
    };
    let mut update_bytes = Vec::new();
    match &input.updates {
        None => update_bytes.push(0),
        Some(proof) => {
            update_bytes.push(1);
            proof.encode_to(&mut update_bytes);
        }
    }
    Ok(IncrementalRiskChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        trader_update_leaf_projection_root: incremental_trader_update_leaf_projection_v2(
            &input.trader_updates,
        )?,
        previous_root_projection: incremental_risk_root_projection_v2(input.previous_root),
        next_root_projection: incremental_risk_root_projection_v2(input.next_root),
        update_transcript_root: tagged_hash(
            b"ECX/incremental-risk-update-transcript/v1",
            &update_bytes,
        ),
        trader_update_count: u16::try_from(input.trader_updates.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        operationally_safe,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        canonical_empty_risk_extrema_root_v2, IncrementalAccountingBoundsV2, Int256V2,
        RiskExtremaAggregateV2, RiskExtremaBatchProofV2, RiskExtremaFrontierItemV2,
        RiskExtremaMutationKindV2, RiskExtremaMutationV2, RiskExtremaNodeV2, RiskParams,
        TraderLeafV2, XOnlyKey, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2,
    };

    use super::*;

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

    #[test]
    fn risk_child_binds_trader_projection_root_and_operational_result() {
        let root = canonical_empty_risk_extrema_root_v2().unwrap();
        let input = IncrementalRiskChildInputV2 {
            version: INCREMENTAL_RISK_CHILD_VERSION_V2,
            configuration: configuration(),
            trader_updates: vec![],
            previous_root: root,
            next_root: root,
            updates: None,
            price_lower_atoms: 90,
            price_upper_atoms: 110,
            global_funding_index_numerator: 0,
        };
        let values = execute_incremental_risk_child_v2(&input).unwrap();
        assert!(values.operationally_safe);
        let projection = decode_incremental_risk_child_projection_v2(&values.encode()).unwrap();
        assert_eq!(projection.next_root_projection, values.next_root_projection);

        let mut wrong = input;
        wrong.next_root.hash[0] ^= 1;
        assert!(execute_incremental_risk_child_v2(&wrong).is_err());
    }

    #[test]
    fn risk_child_wrapper_has_exact_reachable_encoding_ceiling() {
        let leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey([3; 32]),
            account_nonce: u128::MAX,
            collateral_atoms: i128::MAX,
            cash_residual_numerator: i64::MAX,
            position_size_atoms: i64::MAX,
            signed_cost_basis_numerator: Int256V2::from_i128(i128::MAX),
            last_funding_index_numerator: i128::MAX,
            selected_initial_margin_bps: u32::MAX,
            order_generation: u128::MAX,
            salt: [4; 32],
        };
        let aggregate = RiskExtremaAggregateV2 {
            leaf_count: u128::MAX,
            maximum_long_cut_x_numerator: Some(Int256V2::from_i128(i128::MAX)),
            minimum_short_cut_x_numerator: Some(Int256V2::from_i128(i128::MIN)),
            minimum_selected_initial_margin_bps: u32::MAX,
            maximum_selected_initial_margin_bps: u32::MAX,
            maintenance_margin_bps: u32::MAX,
        };
        let proof = RiskExtremaBatchProofV2 {
            maintenance_margin_bps: u32::MAX,
            mutations: vec![
                RiskExtremaMutationV2 {
                    kind: RiskExtremaMutationKindV2::Insert,
                    trader_leaf: leaf.clone(),
                };
                128
            ],
            frontier: vec![
                RiskExtremaFrontierItemV2::Occupied(RiskExtremaNodeV2 {
                    hash: [5; 32],
                    aggregate,
                });
                MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2
            ],
        };
        let trader_update = TraderStateBatchLeafUpdateV2 {
            trader: leaf.trader,
            old_leaf: Some(leaf.clone()),
            new_leaf: Some(leaf),
        };
        let fixed_size = |value: &RiskExtremaBatchProofV2| {
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(value)
                .unwrap()
                .len()
        };
        assert!(fixed_size(&proof) <= MAX_INCREMENTAL_RISK_PROOF_BINCODE_BYTES_V2);
        assert!(
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(&trader_update)
                .unwrap()
                .len()
                <= MAX_INCREMENTAL_RISK_TRADER_UPDATE_BYTES_V2
        );
        assert_eq!(
            INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2,
            4_396_032
        );
    }
}
