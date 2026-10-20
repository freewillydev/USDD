//! Recursive child statement for the typed incremental trader tree.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    verify_incremental_trader_mutation_chain_v2, Hash32, IncrementalSuccessorConfigurationV2,
    IncrementalTraderMutationChainV2, ProtocolError, SparseMerkleSumRootV2, SparseStateDomainV2,
    TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const INCREMENTAL_TRADER_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 5;
pub const INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (9 * 32) + (3 * 2);
pub const MAX_INCREMENTAL_TRADER_MUTATIONS_PER_CHAIN_V2: usize = 64;
pub const INCREMENTAL_TRADER_CHILD_REACHABLE_ENCODING_CEILING_V2: usize = 6_598_112;
pub const MAX_INCREMENTAL_TRADER_CHILD_INPUT_BYTES_V2: usize = 7 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalTraderChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub previous_root: SparseMerkleSumRootV2,
    pub next_root: SparseMerkleSumRootV2,
    pub updates: Option<TraderStateBatchProofV2>,
    pub mutation_chains: Vec<IncrementalTraderMutationChainV2>,
    pub insertions: Vec<IncrementalTraderInsertionV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalTraderInsertionV2 {
    pub deposit_request_id: Hash32,
    pub leaf: ecx_protocol_core::TraderLeafV2,
}

pub fn incremental_trader_insertion_root_v2(
    insertions: &[IncrementalTraderInsertionV2],
    bounds: ecx_protocol_core::IncrementalAccountingBoundsV2,
) -> Result<Hash32, ProtocolError> {
    let count = u16::try_from(insertions.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut previous = None;
    for insertion in insertions {
        insertion.leaf.validate(bounds)?;
        if insertion.deposit_request_id == [0; 32]
            || previous.is_some_and(|trader| trader >= insertion.leaf.trader.0)
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        previous = Some(insertion.leaf.trader.0);
        bytes.extend_from_slice(&insertion.deposit_request_id);
        insertion.leaf.encode_to(&mut bytes);
    }
    Ok(tagged_hash(b"ECX/incremental-trader-insertions/v1", &bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalTraderChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub previous_root_projection: Hash32,
    pub next_root_projection: Hash32,
    pub previous_merkle_root: Hash32,
    pub next_merkle_root: Hash32,
    pub update_transcript_root: Hash32,
    pub update_leaf_projection_root: Hash32,
    pub economic_mutation_root: Hash32,
    pub insertion_root: Hash32,
    pub update_count: u16,
    pub economic_mutation_count: u16,
    pub insertion_count: u16,
}

impl IncrementalTraderChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.previous_root_projection,
            self.next_root_projection,
            self.previous_merkle_root,
            self.next_merkle_root,
            self.update_transcript_root,
            self.update_leaf_projection_root,
            self.economic_mutation_root,
            self.insertion_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.update_count.to_be_bytes());
        out.extend_from_slice(&self.economic_mutation_count.to_be_bytes());
        out.extend_from_slice(&self.insertion_count.to_be_bytes());
        debug_assert_eq!(out.len(), INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalTraderChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub previous_root_projection: Hash32,
    pub next_root_projection: Hash32,
    pub update_transcript_root: Hash32,
    pub update_leaf_projection_root: Hash32,
    pub economic_mutation_root: Hash32,
    pub insertion_root: Hash32,
    pub update_count: u16,
    pub economic_mutation_count: u16,
    pub insertion_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalTraderChildErrorV2 {
    #[error("unsupported incremental trader child version")]
    UnsupportedVersion,
    #[error("incremental trader child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental trader child input encoding failed")]
    InputEncoding,
    #[error("incremental trader transition rejected: {0}")]
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

pub fn incremental_trader_root_projection_v2(root: SparseMerkleSumRootV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-trader-root-projection/v1",
        &root.canonical_bytes(),
    )
}

/// Commits only the ordered, typed old/new trader openings. Deficit and risk
/// children can reproduce this root without embedding the trader frontier.
pub fn incremental_trader_update_leaf_projection_v2(
    updates: &[TraderStateBatchLeafUpdateV2],
) -> Result<Hash32, ProtocolError> {
    let count = u16::try_from(updates.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    for update in updates {
        update.encode_to(&mut bytes);
    }
    Ok(tagged_hash(
        b"ECX/incremental-trader-update-leaves/v1",
        &bytes,
    ))
}

/// Commits the complete ordered list of per-trader economic mutation chains.
/// Each chain root is independently derived from its opened old/new leaves and
/// exact ordered mutations before it enters this aggregate root.
pub fn incremental_trader_economic_mutation_root_v2(
    chains: &[IncrementalTraderMutationChainV2],
    bounds: ecx_protocol_core::IncrementalAccountingBoundsV2,
) -> Result<Hash32, ProtocolError> {
    let count = u16::try_from(chains.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let mut bytes = Vec::with_capacity(2 + (chains.len() * 32));
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut previous_trader = None;
    for chain in chains {
        if previous_trader.is_some_and(|previous| previous >= chain.trader.0) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        previous_trader = Some(chain.trader.0);
        bytes.extend_from_slice(&verify_incremental_trader_mutation_chain_v2(
            chain,
            bounds,
            MAX_INCREMENTAL_TRADER_MUTATIONS_PER_CHAIN_V2,
        )?);
    }
    Ok(tagged_hash(
        b"ECX/incremental-trader-economic-mutations/v1",
        &bytes,
    ))
}

pub fn decode_incremental_trader_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalTraderChildProjectionV2, IncrementalTraderChildErrorV2> {
    if bytes.len() != INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalTraderChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalTraderChildErrorV2> {
        let start = 4 + (index * 32);
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalTraderChildErrorV2::UnsupportedVersion)
    };
    Ok(IncrementalTraderChildProjectionV2 {
        configuration_hash: hash(0)?,
        previous_root_projection: hash(1)?,
        next_root_projection: hash(2)?,
        update_transcript_root: hash(5)?,
        update_leaf_projection_root: hash(6)?,
        economic_mutation_root: hash(7)?,
        insertion_root: hash(8)?,
        update_count: u16::from_be_bytes(
            bytes[4 + (9 * 32)..4 + (9 * 32) + 2]
                .try_into()
                .map_err(|_| IncrementalTraderChildErrorV2::UnsupportedVersion)?,
        ),
        economic_mutation_count: u16::from_be_bytes(
            bytes[4 + (9 * 32) + 2..4 + (9 * 32) + 4]
                .try_into()
                .map_err(|_| IncrementalTraderChildErrorV2::UnsupportedVersion)?,
        ),
        insertion_count: u16::from_be_bytes(
            bytes[4 + (9 * 32) + 4..]
                .try_into()
                .map_err(|_| IncrementalTraderChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

pub fn execute_incremental_trader_child_v2(
    input: &IncrementalTraderChildInputV2,
) -> Result<IncrementalTraderChildPublicValuesV2, IncrementalTraderChildErrorV2> {
    if input.version != INCREMENTAL_TRADER_CHILD_VERSION_V2 {
        return Err(IncrementalTraderChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.previous_root.domain != SparseStateDomainV2::Trader
        || input.next_root.domain != SparseStateDomainV2::Trader
    {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalTraderChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_TRADER_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalTraderChildErrorV2::InputTooLarge);
    }
    let bounds = input.configuration.accounting_bounds;
    let insertion_root = incremental_trader_insertion_root_v2(&input.insertions, bounds)?;
    let insertions = input
        .insertions
        .iter()
        .map(|insertion| (insertion.leaf.trader.0, insertion))
        .collect::<std::collections::BTreeMap<_, _>>();
    if insertions.len() != input.insertions.len() {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let (verified_next, update_count, update_bytes, update_leaf_projection_root) =
        match &input.updates {
            Some(proof) => {
                if proof.updates.len()
                    != input
                        .mutation_chains
                        .len()
                        .checked_add(input.insertions.len())
                        .ok_or(ProtocolError::ArithmeticOverflow)?
                {
                    return Err(ProtocolError::InvalidMerkleProof.into());
                }
                let chains = input
                    .mutation_chains
                    .iter()
                    .map(|chain| (chain.trader.0, chain))
                    .collect::<std::collections::BTreeMap<_, _>>();
                if chains.len() != input.mutation_chains.len()
                    || chains.keys().any(|trader| insertions.contains_key(trader))
                {
                    return Err(ProtocolError::InvalidMerkleProof.into());
                }
                for update in &proof.updates {
                    match (update.old_leaf.as_ref(), update.new_leaf.as_ref()) {
                        (None, Some(next)) => {
                            let insertion = insertions
                                .get(&update.trader.0)
                                .ok_or(ProtocolError::InvalidMerkleProof)?;
                            if next != &insertion.leaf || update.trader != insertion.leaf.trader {
                                return Err(ProtocolError::InvalidMerkleProof.into());
                            }
                        }
                        (Some(previous), Some(next)) => {
                            let chain = chains
                                .get(&update.trader.0)
                                .ok_or(ProtocolError::InvalidMerkleProof)?;
                            if update.trader != chain.trader
                                || previous != &chain.old_leaf
                                || next != &chain.expected_new_leaf
                            {
                                return Err(ProtocolError::InvalidMerkleProof.into());
                            }
                        }
                        _ => return Err(ProtocolError::InvalidMerkleProof.into()),
                    }
                }
                (
                    proof.verify(
                        input.previous_root,
                        bounds,
                        usize::from(input.configuration.maximum_trader_updates),
                    )?,
                    u16::try_from(proof.updates.len())
                        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                    proof.canonical_bytes_checked(bounds)?,
                    incremental_trader_update_leaf_projection_v2(&proof.updates)?,
                )
            }
            None => {
                if !input.mutation_chains.is_empty() || !input.insertions.is_empty() {
                    return Err(ProtocolError::InvalidMerkleProof.into());
                }
                (
                    input.previous_root,
                    0,
                    Vec::new(),
                    incremental_trader_update_leaf_projection_v2(&[])?,
                )
            }
        };
    if verified_next != input.next_root {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    Ok(IncrementalTraderChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        previous_root_projection: incremental_trader_root_projection_v2(input.previous_root),
        next_root_projection: incremental_trader_root_projection_v2(input.next_root),
        previous_merkle_root: input.previous_root.hash,
        next_merkle_root: input.next_root.hash,
        update_transcript_root: tagged_hash(
            b"ECX/incremental-trader-update-transcript/v1",
            &update_bytes,
        ),
        update_leaf_projection_root,
        economic_mutation_root: incremental_trader_economic_mutation_root_v2(
            &input.mutation_chains,
            bounds,
        )?,
        insertion_root,
        update_count,
        economic_mutation_count: u16::try_from(
            input
                .mutation_chains
                .iter()
                .try_fold(0usize, |count, chain| {
                    count.checked_add(chain.mutations.len())
                })
                .ok_or(ProtocolError::ArithmeticOverflow)?,
        )
        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        insertion_count: u16::try_from(input.insertions.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use bincode::Options;
    use ecx_protocol_core::{
        canonical_empty_sparse_root_v2, IncrementalAccountingBoundsV2,
        IncrementalTraderEconomicMutationV2, IncrementalTraderMutationChainV2,
        IncrementalTraderMutationKindV2, Int256V2, RiskParams, SparseMerkleSumFrontierItemV2,
        SparseMerkleSumNodeV2, TraderAggregateV2, TraderLeafV2, TraderStateBatchLeafUpdateV2,
        XOnlyKey, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
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

    #[test]
    fn trader_child_has_exact_reachable_structural_encoding_ceiling() {
        let secp = Secp256k1::new();
        let trader = |byte: u8| {
            let keypair =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap());
            XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
        };
        let leaf = |trader: XOnlyKey, salt: u8| TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: u128::MAX,
            collateral_atoms: i128::MAX,
            cash_residual_numerator: i64::MAX,
            position_size_atoms: i64::MAX,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: i128::MAX,
            selected_initial_margin_bps: 10_000,
            order_generation: u128::MAX,
            salt: [salt; 32],
        };
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::ForcedReduceOnlyIocFill,
            action_id: [0xff; 32],
            exact_cash_delta_numerator: Int256V2::ZERO,
            position_size_delta_atoms: i64::MAX,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: Some(i128::MAX),
            account_nonce_increment: u128::MAX,
            order_generation_increment: u128::MAX,
            selected_initial_margin_bps_after: Some(u32::MAX),
        };
        let mut updates = Vec::with_capacity(64);
        let mut mutation_chains = Vec::with_capacity(64);
        for index in 1u8..=64 {
            let key = trader(index);
            let old_leaf = leaf(key, index);
            let mut next_leaf = old_leaf.clone();
            next_leaf.salt = [index.wrapping_add(64); 32];
            updates.push(TraderStateBatchLeafUpdateV2 {
                trader: key,
                old_leaf: Some(old_leaf.clone()),
                new_leaf: Some(next_leaf.clone()),
            });
            mutation_chains.push(IncrementalTraderMutationChainV2 {
                trader: key,
                old_leaf,
                mutations: vec![mutation.clone(); MAX_INCREMENTAL_TRADER_MUTATIONS_PER_CHAIN_V2],
                final_salt: [index.wrapping_add(64); 32],
                expected_new_leaf: next_leaf,
            });
        }
        updates.sort_by_key(|update| update.trader.0);
        mutation_chains.sort_by_key(|chain| chain.trader.0);
        let occupied = SparseMerkleSumFrontierItemV2::Occupied(SparseMerkleSumNodeV2 {
            hash: [0xff; 32],
            aggregate: TraderAggregateV2::ZERO,
        });
        let proof = TraderStateBatchProofV2 {
            updates,
            frontier: vec![occupied; 16_000],
        };
        let root = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let input = IncrementalTraderChildInputV2 {
            version: INCREMENTAL_TRADER_CHILD_VERSION_V2,
            configuration: configuration(),
            previous_root: root,
            next_root: root,
            updates: Some(proof),
            mutation_chains,
            insertions: Vec::new(),
        };
        let maximum_chain_bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&input.mutation_chains[0])
            .unwrap()
            .len();
        let maximum_insertion_bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&IncrementalTraderInsertionV2 {
                deposit_request_id: [0xff; 32],
                leaf: input.mutation_chains[0].expected_new_leaf.clone(),
            })
            .unwrap()
            .len();
        assert!(maximum_chain_bytes > maximum_insertion_bytes);
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialize(&input)
            .unwrap();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_TRADER_CHILD_REACHABLE_ENCODING_CEILING_V2
        );
        assert!(encoded.len() <= MAX_INCREMENTAL_TRADER_CHILD_INPUT_BYTES_V2);
    }

    #[test]
    fn trader_child_binds_complete_root_projection_and_rejects_substitution() {
        let root = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let trader = XOnlyKey(public_key.serialize());
        let old_leaf = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader,
            account_nonce: 0,
            collateral_atoms: 100,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 10_000,
            order_generation: 0,
            salt: [0x33; 32],
        };
        let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader,
                old_leaf: None,
                new_leaf: Some(old_leaf.clone()),
            }],
            configuration().accounting_bounds,
        )
        .unwrap();
        let previous = insertion
            .verify(root, configuration().accounting_bounds, 64)
            .unwrap();
        let mut new_leaf = old_leaf.clone();
        new_leaf.account_nonce = 1;
        new_leaf.collateral_atoms = 105;
        new_leaf.salt = [0x44; 32];
        let proof = TraderStateBatchProofV2 {
            updates: vec![TraderStateBatchLeafUpdateV2 {
                trader,
                old_leaf: Some(old_leaf.clone()),
                new_leaf: Some(new_leaf.clone()),
            }],
            frontier: insertion.frontier,
        };
        let next = proof
            .verify(previous, configuration().accounting_bounds, 64)
            .unwrap();
        let mutation_chain = IncrementalTraderMutationChainV2 {
            trader,
            old_leaf,
            mutations: vec![IncrementalTraderEconomicMutationV2 {
                kind: IncrementalTraderMutationKindV2::Deposit,
                action_id: [0x55; 32],
                exact_cash_delta_numerator: Int256V2::from_i128(
                    5 * i128::from(ecx_protocol_core::EXACT_ACCOUNTING_DENOMINATOR_V2),
                ),
                position_size_delta_atoms: 0,
                signed_cost_basis_delta_numerator: Int256V2::ZERO,
                funding_checkpoint_after: None,
                account_nonce_increment: 1,
                order_generation_increment: 0,
                selected_initial_margin_bps_after: None,
            }],
            final_salt: [0x44; 32],
            expected_new_leaf: new_leaf,
        };
        let input = IncrementalTraderChildInputV2 {
            version: INCREMENTAL_TRADER_CHILD_VERSION_V2,
            configuration: configuration(),
            previous_root: previous,
            next_root: next,
            updates: Some(proof),
            mutation_chains: vec![mutation_chain],
            insertions: vec![],
        };
        let values = execute_incremental_trader_child_v2(&input).unwrap();
        assert_ne!(values.previous_root_projection, values.next_root_projection);
        assert_eq!(values.update_count, 1);
        let encoded = values.encode();
        assert_eq!(encoded.len(), INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2);
        let projection = decode_incremental_trader_child_projection_v2(&encoded).unwrap();
        assert_eq!(
            projection.configuration_hash,
            configuration().digest().unwrap()
        );
        assert_eq!(
            projection.previous_root_projection,
            values.previous_root_projection
        );
        assert_eq!(
            projection.update_transcript_root,
            values.update_transcript_root
        );
        assert_eq!(
            projection.update_leaf_projection_root,
            incremental_trader_update_leaf_projection_v2(&input.updates.as_ref().unwrap().updates)
                .unwrap()
        );
        assert_eq!(
            projection.economic_mutation_root,
            incremental_trader_economic_mutation_root_v2(
                &input.mutation_chains,
                configuration().accounting_bounds,
            )
            .unwrap()
        );
        assert_eq!(projection.update_count, 1);

        let mut omitted = input.clone();
        omitted.mutation_chains.clear();
        assert!(execute_incremental_trader_child_v2(&omitted).is_err());

        let mut forged = input.clone();
        forged.mutation_chains[0].mutations[0].account_nonce_increment = 0;
        assert!(execute_incremental_trader_child_v2(&forged).is_err());

        let mut substituted = input;
        substituted.next_root.hash[0] ^= 1;
        assert!(execute_incremental_trader_child_v2(&substituted).is_err());
    }

    #[test]
    fn first_deposit_insertion_is_typed_and_rejects_substitution() {
        let configuration = configuration();
        let previous = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let keypair =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[9; 32]).unwrap());
        let trader = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let leaf = TraderLeafV2 {
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
            salt: [0x71; 32],
        };
        let proof = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader,
                old_leaf: None,
                new_leaf: Some(leaf.clone()),
            }],
            configuration.accounting_bounds,
        )
        .unwrap();
        let next = proof
            .verify(previous, configuration.accounting_bounds, 64)
            .unwrap();
        let input = IncrementalTraderChildInputV2 {
            version: INCREMENTAL_TRADER_CHILD_VERSION_V2,
            configuration,
            previous_root: previous,
            next_root: next,
            updates: Some(proof),
            mutation_chains: vec![],
            insertions: vec![IncrementalTraderInsertionV2 {
                deposit_request_id: [0x72; 32],
                leaf,
            }],
        };
        let values = execute_incremental_trader_child_v2(&input).unwrap();
        assert_eq!(values.update_count, 1);
        assert_eq!(values.economic_mutation_count, 0);
        assert_eq!(values.insertion_count, 1);

        let mut wrong_request = input.clone();
        wrong_request.insertions[0].deposit_request_id = [0x73; 32];
        assert_ne!(
            execute_incremental_trader_child_v2(&wrong_request)
                .unwrap()
                .insertion_root,
            values.insertion_root
        );

        let mut wrong_leaf = input;
        wrong_leaf.insertions[0].leaf.account_nonce = 1;
        assert!(execute_incremental_trader_child_v2(&wrong_leaf).is_err());
    }
}
