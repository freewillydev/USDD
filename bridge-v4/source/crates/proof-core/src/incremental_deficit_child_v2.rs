//! Recursive child statement for incremental deficit-index updates and queries.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    portfolio_deficit_atoms_v2, price_funding_q_numerator_v2, verify_deficit_index_range_pair_v2,
    verify_trader_deficit_index_batches_v2, DeficitIndexBatchProofV2, DeficitIndexRangeProofV2,
    DeficitIndexRootV2, Hash32, IncrementalSuccessorConfigurationV2, ProtocolError,
    SparseMerkleSumRootV2, SparseStateDomainV2, TraderStateBatchLeafUpdateV2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{incremental_trader_root_projection_v2, incremental_trader_update_leaf_projection_v2};

pub const INCREMENTAL_DEFICIT_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (9 * 32) + (2 * 16) + 2;
pub const INCREMENTAL_DEFICIT_CHILD_REACHABLE_ENCODING_CEILING_V2: usize = 13_548_554;
pub const MAX_INCREMENTAL_DEFICIT_CHILD_INPUT_BYTES_V2: usize = 13 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalDeficitChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub trader_updates: Vec<TraderStateBatchLeafUpdateV2>,
    pub next_trader_root: SparseMerkleSumRootV2,
    pub previous_long_root: DeficitIndexRootV2,
    pub previous_short_root: DeficitIndexRootV2,
    pub next_long_root: DeficitIndexRootV2,
    pub next_short_root: DeficitIndexRootV2,
    pub long_updates: Option<DeficitIndexBatchProofV2>,
    pub short_updates: Option<DeficitIndexBatchProofV2>,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
    pub global_funding_index_numerator: i128,
    pub lower_long: DeficitIndexRangeProofV2,
    pub lower_short: DeficitIndexRangeProofV2,
    pub upper_long: DeficitIndexRangeProofV2,
    pub upper_short: DeficitIndexRangeProofV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalDeficitChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub next_trader_root_projection: Hash32,
    pub previous_long_root_projection: Hash32,
    pub previous_short_root_projection: Hash32,
    pub next_long_root_projection: Hash32,
    pub next_short_root_projection: Hash32,
    pub long_update_transcript_root: Hash32,
    pub short_update_transcript_root: Hash32,
    pub lower_deficit_atoms: u128,
    pub upper_deficit_atoms: u128,
    pub trader_update_count: u16,
}

impl IncrementalDeficitChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.trader_update_leaf_projection_root,
            self.next_trader_root_projection,
            self.previous_long_root_projection,
            self.previous_short_root_projection,
            self.next_long_root_projection,
            self.next_short_root_projection,
            self.long_update_transcript_root,
            self.short_update_transcript_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.lower_deficit_atoms.to_be_bytes());
        out.extend_from_slice(&self.upper_deficit_atoms.to_be_bytes());
        out.extend_from_slice(&self.trader_update_count.to_be_bytes());
        debug_assert_eq!(out.len(), INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalDeficitChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub trader_update_leaf_projection_root: Hash32,
    pub next_trader_root_projection: Hash32,
    pub previous_long_root_projection: Hash32,
    pub previous_short_root_projection: Hash32,
    pub next_long_root_projection: Hash32,
    pub next_short_root_projection: Hash32,
    pub lower_deficit_atoms: u128,
    pub upper_deficit_atoms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalDeficitChildErrorV2 {
    #[error("unsupported incremental deficit child version")]
    UnsupportedVersion,
    #[error("incremental deficit child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental deficit child input encoding failed")]
    InputEncoding,
    #[error("incremental deficit transition rejected: {0}")]
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

pub fn incremental_deficit_root_projection_v2(root: DeficitIndexRootV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-deficit-root-projection/v1",
        &root.canonical_bytes(),
    )
}

fn update_transcript_root(side_tag: &[u8], proof: Option<&DeficitIndexBatchProofV2>) -> Hash32 {
    let mut bytes = Vec::new();
    match proof {
        None => bytes.push(0),
        Some(proof) => {
            bytes.push(1);
            proof.encode_to(&mut bytes);
        }
    }
    tagged_hash(side_tag, &bytes)
}

pub fn decode_incremental_deficit_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalDeficitChildProjectionV2, IncrementalDeficitChildErrorV2> {
    if bytes.len() != INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalDeficitChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalDeficitChildErrorV2> {
        bytes[4 + (index * 32)..4 + ((index + 1) * 32)]
            .try_into()
            .map_err(|_| IncrementalDeficitChildErrorV2::UnsupportedVersion)
    };
    let numbers = 4 + (9 * 32);
    Ok(IncrementalDeficitChildProjectionV2 {
        configuration_hash: hash(0)?,
        trader_update_leaf_projection_root: hash(1)?,
        next_trader_root_projection: hash(2)?,
        previous_long_root_projection: hash(3)?,
        previous_short_root_projection: hash(4)?,
        next_long_root_projection: hash(5)?,
        next_short_root_projection: hash(6)?,
        lower_deficit_atoms: u128::from_be_bytes(
            bytes[numbers..numbers + 16]
                .try_into()
                .map_err(|_| IncrementalDeficitChildErrorV2::UnsupportedVersion)?,
        ),
        upper_deficit_atoms: u128::from_be_bytes(
            bytes[numbers + 16..numbers + 32]
                .try_into()
                .map_err(|_| IncrementalDeficitChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

pub fn execute_incremental_deficit_child_v2(
    input: &IncrementalDeficitChildInputV2,
) -> Result<IncrementalDeficitChildPublicValuesV2, IncrementalDeficitChildErrorV2> {
    if input.version != INCREMENTAL_DEFICIT_CHILD_VERSION_V2 {
        return Err(IncrementalDeficitChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.next_trader_root.domain != SparseStateDomainV2::Trader
        || input.price_lower_atoms == 0
        || input.price_lower_atoms > input.price_upper_atoms
    {
        return Err(ProtocolError::InvalidBondState.into());
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalDeficitChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_DEFICIT_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalDeficitChildErrorV2::InputTooLarge);
    }
    let bounds = input.configuration.accounting_bounds;
    input.next_trader_root.aggregate.validate(bounds)?;
    let (next_long, next_short) = if input.trader_updates.is_empty() {
        if input.long_updates.is_some() || input.short_updates.is_some() {
            return Err(ProtocolError::InvalidMerkleProof.into());
        }
        (input.previous_long_root, input.previous_short_root)
    } else {
        verify_trader_deficit_index_batches_v2(
            &input.trader_updates,
            input.previous_long_root,
            input.previous_short_root,
            input.long_updates.as_ref(),
            input.short_updates.as_ref(),
            bounds,
            usize::from(input.configuration.maximum_trader_updates) * 2,
        )?
    };
    if next_long != input.next_long_root || next_short != input.next_short_root {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let long_ranges = verify_deficit_index_range_pair_v2(
        input.next_long_root,
        &input.lower_long,
        &input.upper_long,
        bounds,
    )?;
    let short_ranges = verify_deficit_index_range_pair_v2(
        input.next_short_root,
        &input.lower_short,
        &input.upper_short,
        bounds,
    )?;
    let endpoint = |price,
                    long,
                    short,
                    long_proof: &DeficitIndexRangeProofV2,
                    short_proof: &DeficitIndexRangeProofV2| {
        let q = price_funding_q_numerator_v2(price, input.global_funding_index_numerator, bounds)?;
        if long_proof.q_numerator != q || short_proof.q_numerator != q {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        portfolio_deficit_atoms_v2(
            long,
            short,
            input
                .next_trader_root
                .aggregate
                .flat_negative_exact_cash_numerator,
            q,
            bounds,
        )?
        .try_to_u128()
    };
    let lower_deficit_atoms = endpoint(
        input.price_lower_atoms,
        long_ranges[0],
        short_ranges[0],
        &input.lower_long,
        &input.lower_short,
    )?;
    let upper_deficit_atoms = endpoint(
        input.price_upper_atoms,
        long_ranges[1],
        short_ranges[1],
        &input.upper_long,
        &input.upper_short,
    )?;
    Ok(IncrementalDeficitChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        trader_update_leaf_projection_root: incremental_trader_update_leaf_projection_v2(
            &input.trader_updates,
        )?,
        next_trader_root_projection: incremental_trader_root_projection_v2(input.next_trader_root),
        previous_long_root_projection: incremental_deficit_root_projection_v2(
            input.previous_long_root,
        ),
        previous_short_root_projection: incremental_deficit_root_projection_v2(
            input.previous_short_root,
        ),
        next_long_root_projection: incremental_deficit_root_projection_v2(input.next_long_root),
        next_short_root_projection: incremental_deficit_root_projection_v2(input.next_short_root),
        long_update_transcript_root: update_transcript_root(
            b"ECX/incremental-long-deficit-update-transcript/v1",
            input.long_updates.as_ref(),
        ),
        short_update_transcript_root: update_transcript_root(
            b"ECX/incremental-short-deficit-update-transcript/v1",
            input.short_updates.as_ref(),
        ),
        lower_deficit_atoms,
        upper_deficit_atoms,
        trader_update_count: u16::try_from(input.trader_updates.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use bincode::Options;
    use ecx_protocol_core::{
        canonical_empty_deficit_index_root_v2, canonical_empty_sparse_root_v2,
        DeficitIndexBatchMutationV2, DeficitIndexMutationKindV2, DeficitIndexNodeV2,
        DeficitIndexPathItemV2, DeficitRangeAggregateV2, DeficitSideV2,
        IncrementalAccountingBoundsV2, Int256V2, RiskParams, TraderLeafV2, XOnlyKey,
        ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2, MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

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

    fn input() -> IncrementalDeficitChildInputV2 {
        let configuration = configuration();
        let bounds = configuration.accounting_bounds;
        let trader = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let long = canonical_empty_deficit_index_root_v2(DeficitSideV2::Long).unwrap();
        let short = canonical_empty_deficit_index_root_v2(DeficitSideV2::Short).unwrap();
        let lower_q = price_funding_q_numerator_v2(90, 0, bounds).unwrap();
        let upper_q = price_funding_q_numerator_v2(110, 0, bounds).unwrap();
        IncrementalDeficitChildInputV2 {
            version: INCREMENTAL_DEFICIT_CHILD_VERSION_V2,
            configuration,
            trader_updates: vec![],
            next_trader_root: trader,
            previous_long_root: long,
            previous_short_root: short,
            next_long_root: long,
            next_short_root: short,
            long_updates: None,
            short_updates: None,
            price_lower_atoms: 90,
            price_upper_atoms: 110,
            global_funding_index_numerator: 0,
            lower_long: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Long,
                lower_q,
                bounds,
            )
            .unwrap(),
            lower_short: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Short,
                lower_q,
                bounds,
            )
            .unwrap(),
            upper_long: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Long,
                upper_q,
                bounds,
            )
            .unwrap(),
            upper_short: DeficitIndexRangeProofV2::for_canonical_empty_root(
                DeficitSideV2::Short,
                upper_q,
                bounds,
            )
            .unwrap(),
        }
    }

    #[test]
    fn deficit_child_has_exact_structural_encoding_ceiling() {
        let mut input = input();
        let keypair =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: u128::MAX,
            collateral_atoms: i128::MAX,
            cash_residual_numerator: i64::MAX,
            position_size_atoms: i64::MAX,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: i128::MAX,
            selected_initial_margin_bps: u32::MAX,
            order_generation: u128::MAX,
            salt: [0xff; 32],
        };
        input.trader_updates = vec![
            TraderStateBatchLeafUpdateV2 {
                trader,
                old_leaf: Some(leaf.clone()),
                new_leaf: Some(leaf.clone()),
            };
            64
        ];
        let occupied = DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
            hash: [0xff; 32],
            aggregate: DeficitRangeAggregateV2::ZERO,
        });
        let proof = |side| DeficitIndexBatchProofV2 {
            side,
            mutations: vec![
                DeficitIndexBatchMutationV2 {
                    kind: DeficitIndexMutationKindV2::Insert,
                    trader_leaf: leaf.clone(),
                };
                MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2
            ],
            frontier: vec![occupied; MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2],
        };
        input.long_updates = Some(proof(DeficitSideV2::Long));
        input.short_updates = Some(proof(DeficitSideV2::Short));
        for range in [
            &mut input.lower_long,
            &mut input.lower_short,
            &mut input.upper_long,
            &mut input.upper_short,
        ] {
            range.siblings_root_to_leaf = vec![occupied; ecx_protocol_core::DEFICIT_INDEX_DEPTH_V2];
        }
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialize(&input)
            .unwrap();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_DEFICIT_CHILD_REACHABLE_ENCODING_CEILING_V2
        );
        assert!(encoded.len() <= MAX_INCREMENTAL_DEFICIT_CHILD_INPUT_BYTES_V2);
    }

    #[test]
    fn deficit_child_binds_trader_projection_roots_and_endpoint_queries() {
        let input = input();
        let values = execute_incremental_deficit_child_v2(&input).unwrap();
        assert_eq!(values.lower_deficit_atoms, 0);
        assert_eq!(values.upper_deficit_atoms, 0);
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let projection = decode_incremental_deficit_child_projection_v2(&encoded).unwrap();
        assert_eq!(
            projection.trader_update_leaf_projection_root,
            incremental_trader_update_leaf_projection_v2(&[]).unwrap()
        );

        let mut wrong_query = input.clone();
        wrong_query.lower_long.q_numerator =
            price_funding_q_numerator_v2(91, 0, wrong_query.configuration.accounting_bounds)
                .unwrap();
        assert!(execute_incremental_deficit_child_v2(&wrong_query).is_err());

        let mut wrong_root = input;
        wrong_root.next_long_root.hash[0] ^= 1;
        assert!(execute_incremental_deficit_child_v2(&wrong_root).is_err());
    }
}
