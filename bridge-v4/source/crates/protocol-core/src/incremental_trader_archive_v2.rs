//! Private proof-producer archive for the incremental trader sparse tree.
//!
//! This is not a consensus state or a replacement for the authenticated root.
//! It stores only occupied nodes and opened trader leaves, applies only typed
//! batches already verified against that root, and can reconstruct the exact
//! shared-frontier membership proof used by the successor grant service. There
//! is no finite trader-count cap; archive size is operational storage, not a
//! zkVM witness.

use std::collections::{BTreeMap, BTreeSet};

use crate::incremental_state_v2::{
    canonical_empty_sparse_nodes_v2, parent_hash_v2, present_leaf_hash_v2,
};
use crate::{
    Hash32, IncrementalAccountingBoundsV2, ProtocolError, SparseMerkleSumFrontierItemV2,
    SparseMerkleSumNodeV2, SparseMerkleSumRootV2, SparseStateDomainV2, TraderLeafV2,
    TraderStateBatchProofV2, TraderStateReadBatchProofV2, XOnlyKey, SPARSE_MERKLE_SUM_DEPTH_V2,
};

pub const INCREMENTAL_TRADER_ARCHIVE_VERSION_V2: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalTraderNodeLocatorV2 {
    /// Root is depth zero; a leaf is depth 256.
    pub depth: u16,
    /// Big-endian path prefix. Bits after `depth` must be zero.
    pub prefix: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalTraderNodeRecordV2 {
    pub locator: IncrementalTraderNodeLocatorV2,
    pub node: SparseMerkleSumNodeV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalTraderStateArchiveV2 {
    version: u8,
    root: SparseMerkleSumRootV2,
    leaves: Vec<TraderLeafV2>,
    occupied_nodes: Vec<IncrementalTraderNodeRecordV2>,
}

impl IncrementalTraderStateArchiveV2 {
    pub fn canonical_empty(bounds: IncrementalAccountingBoundsV2) -> Result<Self, ProtocolError> {
        bounds.validate()?;
        Self::from_sorted_leaves(Vec::new(), bounds)
    }

    pub fn root(&self) -> SparseMerkleSumRootV2 {
        self.root
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn validate(&self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        if self.version != INCREMENTAL_TRADER_ARCHIVE_VERSION_V2
            || self.root.domain != SparseStateDomainV2::Trader
            || self
                .leaves
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
            || self
                .occupied_nodes
                .windows(2)
                .any(|pair| pair[0].locator >= pair[1].locator)
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for leaf in &self.leaves {
            leaf.validate(bounds)?;
        }
        for record in &self.occupied_nodes {
            validate_locator(record.locator)?;
            record.node.aggregate.validate(bounds)?;
        }
        let rebuilt = Self::from_sorted_leaves(self.leaves.clone(), bounds)?;
        if rebuilt.root != self.root || rebuilt.occupied_nodes != self.occupied_nodes {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(())
    }

    pub fn apply_verified_batch(
        &mut self,
        batch: &TraderStateBatchProofV2,
        bounds: IncrementalAccountingBoundsV2,
        maximum_updates: usize,
    ) -> Result<(), ProtocolError> {
        self.validate(bounds)?;
        let expected = batch.verify(self.root, bounds, maximum_updates)?;
        let mut leaves: BTreeMap<Hash32, TraderLeafV2> = self
            .leaves
            .iter()
            .cloned()
            .map(|leaf| (leaf.key(), leaf))
            .collect();
        for update in &batch.updates {
            if update.old_leaf.as_ref() != leaves.get(&update.trader.0) {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            match &update.new_leaf {
                Some(leaf) => {
                    if leaf.trader != update.trader {
                        return Err(ProtocolError::InvalidMerkleProof);
                    }
                    leaves.insert(update.trader.0, leaf.clone());
                }
                None => {
                    leaves.remove(&update.trader.0);
                }
            }
        }
        let next = Self::from_sorted_leaves(leaves.into_values().collect(), bounds)?;
        if next.root != expected {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        *self = next;
        Ok(())
    }

    pub fn trader_read_proof(
        &self,
        trader: XOnlyKey,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<TraderStateReadBatchProofV2, ProtocolError> {
        self.validate(bounds)?;
        let leaf = self
            .leaves
            .binary_search_by_key(&trader.0, TraderLeafV2::key)
            .ok()
            .and_then(|index| self.leaves.get(index))
            .cloned()
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        let nodes: BTreeMap<IncrementalTraderNodeLocatorV2, SparseMerkleSumNodeV2> = self
            .occupied_nodes
            .iter()
            .map(|record| (record.locator, record.node))
            .collect();
        let mut frontier = Vec::with_capacity(SPARSE_MERKLE_SUM_DEPTH_V2);
        let mut stack = vec![IncrementalTraderNodeLocatorV2 {
            depth: 0,
            prefix: [0; 32],
        }];
        while let Some(locator) = stack.pop() {
            let depth = usize::from(locator.depth);
            if !prefix_contains(locator, trader.0)? {
                frontier.push(match nodes.get(&locator).copied() {
                    Some(node) => SparseMerkleSumFrontierItemV2::Occupied(node),
                    None => SparseMerkleSumFrontierItemV2::CanonicalEmpty,
                });
                continue;
            }
            if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
                continue;
            }
            // LIFO preserves the verifier's canonical left-first DFS.
            stack.push(child_locator(locator, true)?);
            stack.push(child_locator(locator, false)?);
        }
        let proof = TraderStateReadBatchProofV2 {
            leaves: vec![leaf],
            frontier,
        };
        proof.verify(self.root, bounds)?;
        Ok(proof)
    }

    fn from_sorted_leaves(
        leaves: Vec<TraderLeafV2>,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        bounds.validate()?;
        if leaves.windows(2).any(|pair| pair[0].key() >= pair[1].key()) {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
        let empty = canonical_empty_sparse_nodes_v2(SparseStateDomainV2::Trader)?;
        let mut nodes = BTreeMap::new();
        for leaf in &leaves {
            let sparse = leaf.sparse_leaf(bounds)?;
            nodes.insert(
                IncrementalTraderNodeLocatorV2 {
                    depth: u16::try_from(SPARSE_MERKLE_SUM_DEPTH_V2)
                        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                    prefix: leaf.key(),
                },
                SparseMerkleSumNodeV2 {
                    hash: present_leaf_hash_v2(SparseStateDomainV2::Trader, leaf.key(), sparse),
                    aggregate: sparse.aggregate,
                },
            );
        }

        for depth in (0..SPARSE_MERKLE_SUM_DEPTH_V2).rev() {
            let child_depth =
                u16::try_from(depth + 1).map_err(|_| ProtocolError::ArithmeticOverflow)?;
            let parent_depth =
                u16::try_from(depth).map_err(|_| ProtocolError::ArithmeticOverflow)?;
            let parents: BTreeSet<Hash32> = nodes
                .keys()
                .filter(|locator| locator.depth == child_depth)
                .map(|locator| canonical_prefix(locator.prefix, depth))
                .collect();
            for prefix in parents {
                let parent = IncrementalTraderNodeLocatorV2 {
                    depth: parent_depth,
                    prefix,
                };
                let left_locator = child_locator(parent, false)?;
                let right_locator = child_locator(parent, true)?;
                let subtree_height = SPARSE_MERKLE_SUM_DEPTH_V2 - (depth + 1);
                let left = nodes
                    .get(&left_locator)
                    .copied()
                    .unwrap_or(empty[subtree_height]);
                let right = nodes
                    .get(&right_locator)
                    .copied()
                    .unwrap_or(empty[subtree_height]);
                let aggregate = left.aggregate.checked_add(right.aggregate)?;
                let node = SparseMerkleSumNodeV2 {
                    hash: parent_hash_v2(
                        SparseStateDomainV2::Trader,
                        u16::try_from(SPARSE_MERKLE_SUM_DEPTH_V2 - depth)
                            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                        left,
                        right,
                        aggregate,
                    ),
                    aggregate,
                };
                let expected_empty = empty[SPARSE_MERKLE_SUM_DEPTH_V2 - depth];
                if node != expected_empty {
                    nodes.insert(parent, node);
                }
            }
        }
        let root_node = nodes
            .get(&IncrementalTraderNodeLocatorV2 {
                depth: 0,
                prefix: [0; 32],
            })
            .copied()
            .unwrap_or(empty[SPARSE_MERKLE_SUM_DEPTH_V2]);
        let root = SparseMerkleSumRootV2::from_node(SparseStateDomainV2::Trader, root_node);
        root.aggregate.validate(bounds)?;
        Ok(Self {
            version: INCREMENTAL_TRADER_ARCHIVE_VERSION_V2,
            root,
            leaves,
            occupied_nodes: nodes
                .into_iter()
                .map(|(locator, node)| IncrementalTraderNodeRecordV2 { locator, node })
                .collect(),
        })
    }
}

fn validate_locator(locator: IncrementalTraderNodeLocatorV2) -> Result<(), ProtocolError> {
    let depth = usize::from(locator.depth);
    if depth > SPARSE_MERKLE_SUM_DEPTH_V2
        || canonical_prefix(locator.prefix, depth) != locator.prefix
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

fn canonical_prefix(mut key: Hash32, depth: usize) -> Hash32 {
    if depth >= SPARSE_MERKLE_SUM_DEPTH_V2 {
        return key;
    }
    let complete_bytes = depth / 8;
    let remainder = depth % 8;
    if remainder != 0 {
        key[complete_bytes] &= 0xff << (8 - remainder);
    }
    let zero_from = complete_bytes + usize::from(remainder != 0);
    key[zero_from..].fill(0);
    key
}

fn child_locator(
    parent: IncrementalTraderNodeLocatorV2,
    right: bool,
) -> Result<IncrementalTraderNodeLocatorV2, ProtocolError> {
    validate_locator(parent)?;
    let depth = usize::from(parent.depth);
    if depth >= SPARSE_MERKLE_SUM_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut prefix = parent.prefix;
    if right {
        prefix[depth / 8] |= 1 << (7 - (depth % 8));
    }
    Ok(IncrementalTraderNodeLocatorV2 {
        depth: parent
            .depth
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        prefix,
    })
}

fn prefix_contains(
    locator: IncrementalTraderNodeLocatorV2,
    key: Hash32,
) -> Result<bool, ProtocolError> {
    validate_locator(locator)?;
    Ok(canonical_prefix(key, usize::from(locator.depth)) == locator.prefix)
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::{
        Int256V2, TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2, BOND_FIXED_SUPPLY_ATOMS,
        MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2,
    };

    use super::*;

    fn bounds() -> IncrementalAccountingBoundsV2 {
        IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: u128::from(BOND_FIXED_SUPPLY_ATOMS),
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 20_000_000_000,
            maximum_price_atoms: 10_000_000_000,
        }
    }

    fn leaf(secret_byte: u8, collateral_atoms: i128) -> TraderLeafV2 {
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey(public.serialize()),
            account_nonce: u128::from(secret_byte),
            collateral_atoms,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: u128::from(secret_byte),
            salt: [secret_byte.wrapping_add(1); 32],
        }
    }

    fn batch_for_archive(
        archive: &IncrementalTraderStateArchiveV2,
        updates: Vec<TraderStateBatchLeafUpdateV2>,
    ) -> TraderStateBatchProofV2 {
        let mut sorted = updates;
        sorted.sort_by_key(|update| update.trader.0);
        let mut frontier = Vec::new();
        // The test starts from an empty archive or uses one-key typed reads to
        // recover the exact occupied siblings for each single update.
        if archive.leaf_count() == 0 {
            return TraderStateBatchProofV2::for_canonical_empty_root(sorted, bounds()).unwrap();
        }
        assert_eq!(sorted.len(), 1);
        let read = archive
            .trader_read_proof(sorted[0].trader, bounds())
            .unwrap();
        frontier.append(&mut read.frontier.clone());
        TraderStateBatchProofV2 {
            updates: sorted,
            frontier,
        }
    }

    #[test]
    fn trader_archive_applies_verified_batches_and_emits_exact_reads() {
        let mut archive = IncrementalTraderStateArchiveV2::canonical_empty(bounds()).unwrap();
        let left = leaf(42, 5);
        let right = leaf(43, -5);
        let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
            {
                let mut updates = vec![
                    TraderStateBatchLeafUpdateV2 {
                        trader: left.trader,
                        old_leaf: None,
                        new_leaf: Some(left.clone()),
                    },
                    TraderStateBatchLeafUpdateV2 {
                        trader: right.trader,
                        old_leaf: None,
                        new_leaf: Some(right.clone()),
                    },
                ];
                updates.sort_by_key(|update| update.trader.0);
                updates
            },
            bounds(),
        )
        .unwrap();
        archive
            .apply_verified_batch(
                &insertion,
                bounds(),
                MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2,
            )
            .unwrap();
        assert_eq!(archive.leaf_count(), 2);
        for trader in [left.trader, right.trader] {
            archive
                .trader_read_proof(trader, bounds())
                .unwrap()
                .verify(archive.root(), bounds())
                .unwrap();
        }
        let mut damaged = archive.clone();
        damaged.occupied_nodes[0].node.hash[0] ^= 1;
        assert!(damaged.validate(bounds()).is_err());
        let absent = leaf(44, 0);
        assert!(archive.trader_read_proof(absent.trader, bounds()).is_err());

        let mut next_left = left.clone();
        next_left.account_nonce += 1;
        let update = batch_for_archive(
            &archive,
            vec![TraderStateBatchLeafUpdateV2 {
                trader: left.trader,
                old_leaf: Some(left.clone()),
                new_leaf: Some(next_left.clone()),
            }],
        );
        archive.apply_verified_batch(&update, bounds(), 1).unwrap();
        assert_eq!(
            archive
                .trader_read_proof(left.trader, bounds())
                .unwrap()
                .leaves[0],
            next_left
        );

        let before_rejected_batch = archive.clone();
        let mut substituted = update;
        substituted.updates[0].old_leaf = Some(right);
        assert!(archive
            .apply_verified_batch(&substituted, bounds(), 1)
            .is_err());
        assert_eq!(archive, before_rejected_batch);
        archive.validate(bounds()).unwrap();

        #[cfg(feature = "serde")]
        {
            let encoded = serde_json::to_vec(&archive).unwrap();
            let decoded: IncrementalTraderStateArchiveV2 =
                serde_json::from_slice(&encoded).unwrap();
            decoded.validate(bounds()).unwrap();
            assert_eq!(decoded, archive);
        }
    }
}
