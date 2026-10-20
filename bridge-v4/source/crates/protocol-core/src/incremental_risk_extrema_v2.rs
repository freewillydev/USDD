//! Authenticated shared-prefix risk-extrema projection for incremental traders.

use std::collections::BTreeSet;

use crate::codec::{put_u16, put_u32, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::incremental_state_v2::{
    IncrementalAccountingBoundsV2, PositionRiskExtremaV2, RiskExtremaAggregateV2,
    TraderStateBatchLeafUpdateV2, MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2,
    SPARSE_MERKLE_SUM_DEPTH_V2,
};
use crate::{ProtocolError, TraderLeafV2};

pub const RISK_EXTREMA_TREE_VERSION_V2: u8 = 1;
pub const MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2: usize = 16_000;
pub const MAX_RISK_EXTREMA_BATCH_BYTES_V2: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskExtremaNodeV2 {
    pub hash: Hash32,
    pub aggregate: RiskExtremaAggregateV2,
}

impl CanonicalEncode for RiskExtremaNodeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskExtremaRootV2 {
    pub hash: Hash32,
    pub aggregate: RiskExtremaAggregateV2,
}

impl CanonicalEncode for RiskExtremaRootV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, RISK_EXTREMA_TREE_VERSION_V2);
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RiskExtremaFrontierItemV2 {
    CanonicalEmpty,
    Occupied(RiskExtremaNodeV2),
}

impl CanonicalEncode for RiskExtremaFrontierItemV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::CanonicalEmpty => put_u8(out, 0),
            Self::Occupied(node) => {
                put_u8(out, 1);
                node.encode_to(out);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RiskExtremaMutationKindV2 {
    Remove = 0,
    Insert = 1,
}

impl CanonicalEncode for RiskExtremaMutationKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskExtremaMutationV2 {
    pub kind: RiskExtremaMutationKindV2,
    pub trader_leaf: TraderLeafV2,
}

impl CanonicalEncode for RiskExtremaMutationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        self.trader_leaf.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskExtremaBatchProofV2 {
    pub maintenance_margin_bps: u32,
    pub mutations: Vec<RiskExtremaMutationV2>,
    pub frontier: Vec<RiskExtremaFrontierItemV2>,
}

impl CanonicalEncode for RiskExtremaBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, RISK_EXTREMA_TREE_VERSION_V2);
        put_u32(out, self.maintenance_margin_bps);
        put_u16(out, u16::try_from(self.mutations.len()).unwrap_or(u16::MAX));
        for mutation in &self.mutations {
            mutation.encode_to(out);
        }
        put_u16(out, u16::try_from(self.frontier.len()).unwrap_or(u16::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerivedRiskMutationV2 {
    kind: RiskExtremaMutationKindV2,
    leaf: PositionRiskExtremaV2,
    key: Hash32,
}

#[derive(Debug, Clone, Copy)]
struct RiskParentPreimageV2 {
    height: u16,
    left: RiskExtremaNodeV2,
    right: RiskExtremaNodeV2,
    aggregate: RiskExtremaAggregateV2,
}

impl CanonicalEncode for RiskParentPreimageV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.height.to_be_bytes());
        self.left.encode_to(out);
        self.right.encode_to(out);
        self.aggregate.encode_to(out);
    }
}

fn risk_leaf_node_v2(leaf: PositionRiskExtremaV2) -> Result<RiskExtremaNodeV2, ProtocolError> {
    leaf.validate()?;
    let aggregate = RiskExtremaAggregateV2::from_leaf(leaf)?;
    Ok(RiskExtremaNodeV2 {
        hash: canonical_hash("ECX/incremental-risk-extrema-leaf/v1", &leaf),
        aggregate,
    })
}

fn risk_parent_node_v2(
    height: u16,
    left: RiskExtremaNodeV2,
    right: RiskExtremaNodeV2,
) -> Result<RiskExtremaNodeV2, ProtocolError> {
    let aggregate = left.aggregate.checked_add(right.aggregate)?;
    Ok(RiskExtremaNodeV2 {
        hash: canonical_hash(
            "ECX/incremental-risk-extrema-node/v1",
            &RiskParentPreimageV2 {
                height,
                left,
                right,
                aggregate,
            },
        ),
        aggregate,
    })
}

fn empty_risk_nodes_v2() -> Result<Vec<RiskExtremaNodeV2>, ProtocolError> {
    let mut nodes = Vec::with_capacity(SPARSE_MERKLE_SUM_DEPTH_V2 + 1);
    nodes.push(RiskExtremaNodeV2 {
        hash: tagged_hash(
            "ECX/incremental-risk-extrema-empty-leaf/v1",
            &[RISK_EXTREMA_TREE_VERSION_V2],
        ),
        aggregate: RiskExtremaAggregateV2::ZERO,
    });
    for height in 1..=SPARSE_MERKLE_SUM_DEPTH_V2 {
        let child = nodes[height - 1];
        nodes.push(risk_parent_node_v2(
            u16::try_from(height).map_err(|_| ProtocolError::ArithmeticOverflow)?,
            child,
            child,
        )?);
    }
    Ok(nodes)
}

pub fn canonical_empty_risk_extrema_root_v2() -> Result<RiskExtremaRootV2, ProtocolError> {
    let node = empty_risk_nodes_v2()?[SPARSE_MERKLE_SUM_DEPTH_V2];
    Ok(RiskExtremaRootV2 {
        hash: node.hash,
        aggregate: node.aggregate,
    })
}

impl RiskExtremaRootV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        self.aggregate.validate()?;
        let empty = canonical_empty_risk_extrema_root_v2()?;
        if (self.aggregate == RiskExtremaAggregateV2::ZERO && self.hash != empty.hash)
            || (self.aggregate != RiskExtremaAggregateV2::ZERO
                && (self.hash == [0; 32] || self.hash == empty.hash))
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(())
    }
}

fn key_bit(key: &Hash32, depth: usize) -> Result<bool, ProtocolError> {
    if depth >= SPARSE_MERKLE_SUM_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(((key[depth / 8] >> (7 - depth % 8)) & 1) != 0)
}

fn derive_mutations(
    mutations: &[RiskExtremaMutationV2],
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<DerivedRiskMutationV2>, ProtocolError> {
    if mutations.is_empty()
        || mutations.len() > 2 * MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || maintenance_margin_bps == 0
        || maintenance_margin_bps >= 10_000
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let derived = mutations
        .iter()
        .map(|mutation| {
            let leaf = PositionRiskExtremaV2::from_trader(
                &mutation.trader_leaf,
                maintenance_margin_bps,
                bounds,
            )?
            .ok_or(ProtocolError::InvalidMerkleProof)?;
            Ok(DerivedRiskMutationV2 {
                kind: mutation.kind,
                leaf,
                key: leaf.trader.0,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    for pair in derived.windows(2) {
        if pair[0].key > pair[1].key
            || (pair[0].key == pair[1].key
                && (pair[0].kind != RiskExtremaMutationKindV2::Remove
                    || pair[1].kind != RiskExtremaMutationKindV2::Insert
                    || pair[0].leaf == pair[1].leaf))
        {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    Ok(derived)
}

fn split_at_depth(mutations: &[DerivedRiskMutationV2], depth: usize) -> usize {
    mutations.partition_point(|mutation| !key_bit(&mutation.key, depth).unwrap_or(true))
}

fn frontier_slots(mutations: &[DerivedRiskMutationV2]) -> Result<usize, ProtocolError> {
    let mut stack = vec![(0usize, 0usize, mutations.len())];
    let mut slots = 0usize;
    while let Some((depth, lo, hi)) = stack.pop() {
        if lo == hi {
            slots = slots
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if slots > MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2 {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        } else if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
            if hi - lo > 2 {
                return Err(ProtocolError::DuplicateMerkleKey);
            }
        } else {
            let split = lo + split_at_depth(&mutations[lo..hi], depth);
            stack.push((depth + 1, split, hi));
            stack.push((depth + 1, lo, split));
        }
    }
    Ok(slots)
}

fn frontier_node(
    item: RiskExtremaFrontierItemV2,
    subtree_height: usize,
    empties: &[RiskExtremaNodeV2],
) -> Result<RiskExtremaNodeV2, ProtocolError> {
    let empty = empties
        .get(subtree_height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)?;
    match item {
        RiskExtremaFrontierItemV2::CanonicalEmpty => Ok(empty),
        RiskExtremaFrontierItemV2::Occupied(node) => {
            node.aggregate.validate()?;
            if node.aggregate == RiskExtremaAggregateV2::ZERO
                || node.hash == [0; 32]
                || node.hash == empty.hash
                || (subtree_height < 128 && node.aggregate.leaf_count > (1u128 << subtree_height))
            {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            Ok(node)
        }
    }
}

fn leaf_pair(
    mutations: &[DerivedRiskMutationV2],
    empty: RiskExtremaNodeV2,
) -> Result<(RiskExtremaNodeV2, RiskExtremaNodeV2), ProtocolError> {
    match mutations {
        [mutation] => {
            let present = risk_leaf_node_v2(mutation.leaf)?;
            Ok(match mutation.kind {
                RiskExtremaMutationKindV2::Remove => (present, empty),
                RiskExtremaMutationKindV2::Insert => (empty, present),
            })
        }
        [remove, insert]
            if remove.key == insert.key
                && remove.kind == RiskExtremaMutationKindV2::Remove
                && insert.kind == RiskExtremaMutationKindV2::Insert
                && remove.leaf != insert.leaf =>
        {
            Ok((
                risk_leaf_node_v2(remove.leaf)?,
                risk_leaf_node_v2(insert.leaf)?,
            ))
        }
        _ => Err(ProtocolError::InvalidMerkleProof),
    }
}

fn compute_batch(
    mutations: &[DerivedRiskMutationV2],
    frontier: &[RiskExtremaFrontierItemV2],
) -> Result<(RiskExtremaNodeV2, RiskExtremaNodeV2), ProtocolError> {
    #[derive(Clone, Copy)]
    enum Frame {
        Visit { depth: usize, lo: usize, hi: usize },
        Combine { depth: usize },
    }
    let empties = empty_risk_nodes_v2()?;
    let mut stack = vec![Frame::Visit {
        depth: 0,
        lo: 0,
        hi: mutations.len(),
    }];
    let mut results = Vec::new();
    let mut cursor = 0usize;
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Visit { depth, lo, hi } if lo == hi => {
                let item = *frontier.get(cursor).ok_or(ProtocolError::UnexpectedEnd)?;
                cursor += 1;
                let node = frontier_node(item, SPARSE_MERKLE_SUM_DEPTH_V2 - depth, &empties)?;
                results.push((node, node));
            }
            Frame::Visit { depth, lo, hi } if depth == SPARSE_MERKLE_SUM_DEPTH_V2 => {
                results.push(leaf_pair(&mutations[lo..hi], empties[0])?);
            }
            Frame::Visit { depth, lo, hi } => {
                let split = lo + split_at_depth(&mutations[lo..hi], depth);
                stack.push(Frame::Combine { depth });
                stack.push(Frame::Visit {
                    depth: depth + 1,
                    lo: split,
                    hi,
                });
                stack.push(Frame::Visit {
                    depth: depth + 1,
                    lo,
                    hi: split,
                });
            }
            Frame::Combine { depth } => {
                let (old_right, new_right) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let (old_left, new_left) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let height = u16::try_from(SPARSE_MERKLE_SUM_DEPTH_V2 - depth)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?;
                results.push((
                    risk_parent_node_v2(height, old_left, old_right)?,
                    risk_parent_node_v2(height, new_left, new_right)?,
                ));
            }
        }
    }
    if cursor != frontier.len() || results.len() != 1 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    results.pop().ok_or(ProtocolError::InvalidMerkleProof)
}

impl RiskExtremaBatchProofV2 {
    pub fn for_canonical_empty_root(
        maintenance_margin_bps: u32,
        mutations: Vec<RiskExtremaMutationV2>,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        let derived = derive_mutations(&mutations, maintenance_margin_bps, bounds)?;
        if derived
            .iter()
            .any(|mutation| mutation.kind != RiskExtremaMutationKindV2::Insert)
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let proof = Self {
            maintenance_margin_bps,
            mutations,
            frontier: vec![RiskExtremaFrontierItemV2::CanonicalEmpty; frontier_slots(&derived)?],
        };
        proof.canonical_bytes_checked(bounds)?;
        Ok(proof)
    }

    pub fn canonical_bytes_checked(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        let derived = derive_mutations(&self.mutations, self.maintenance_margin_bps, bounds)?;
        if self.frontier.len() != frontier_slots(&derived)?
            || self.frontier.len() > MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for item in &self.frontier {
            if let RiskExtremaFrontierItemV2::Occupied(node) = item {
                node.aggregate.validate()?;
            }
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_RISK_EXTREMA_BATCH_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    fn verify_internal(
        &self,
        old_root: RiskExtremaRootV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<RiskExtremaRootV2, ProtocolError> {
        old_root.validate()?;
        self.canonical_bytes_checked(bounds)?;
        let derived = derive_mutations(&self.mutations, self.maintenance_margin_bps, bounds)?;
        let (old, next) = compute_batch(&derived, &self.frontier)?;
        if old.hash != old_root.hash || old.aggregate != old_root.aggregate {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(RiskExtremaRootV2 {
            hash: next.hash,
            aggregate: next.aggregate,
        })
    }
}

fn expected_projection(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<RiskExtremaMutationV2>, ProtocolError> {
    if trader_updates.is_empty()
        || trader_updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut traders = BTreeSet::new();
    let mut expected = Vec::new();
    for update in trader_updates {
        if !traders.insert(update.trader.0) {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
        for (kind, leaf) in [
            (RiskExtremaMutationKindV2::Remove, update.old_leaf.as_ref()),
            (RiskExtremaMutationKindV2::Insert, update.new_leaf.as_ref()),
        ] {
            if leaf.is_some_and(|leaf| leaf.position_size_atoms != 0) {
                expected.push(RiskExtremaMutationV2 {
                    kind,
                    trader_leaf: leaf.cloned().ok_or(ProtocolError::InvalidMerkleProof)?,
                });
            }
        }
    }
    expected.sort_by(|left, right| {
        left.trader_leaf
            .trader
            .0
            .cmp(&right.trader_leaf.trader.0)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    // Derivation validates every projected leaf and replacement pair. A batch
    // containing only flat trader leaves has no risk-tree mutation.
    if !expected.is_empty() {
        derive_mutations(&expected, maintenance_margin_bps, bounds)?;
    }
    Ok(expected)
}

/// Bind the complete risk projection to the exact typed trader replacements.
pub fn verify_trader_risk_extrema_batch_v2(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    old_root: RiskExtremaRootV2,
    proof: Option<&RiskExtremaBatchProofV2>,
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<RiskExtremaRootV2, ProtocolError> {
    old_root.validate()?;
    if trader_updates.is_empty() {
        return if proof.is_none() {
            Ok(old_root)
        } else {
            Err(ProtocolError::InvalidMerkleProof)
        };
    }
    let expected = expected_projection(trader_updates, maintenance_margin_bps, bounds)?;
    if expected.is_empty() {
        return if proof.is_none() {
            Ok(old_root)
        } else {
            Err(ProtocolError::InvalidMerkleProof)
        };
    }
    let proof = proof.ok_or(ProtocolError::InvalidMerkleProof)?;
    if proof.maintenance_margin_bps != maintenance_margin_bps || proof.mutations != expected {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    proof.verify_internal(old_root, bounds)
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use crate::{Int256V2, XOnlyKey};

    fn bounds() -> IncrementalAccountingBoundsV2 {
        IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 1_000_000_000,
            maximum_total_controlled_atoms: 10_000_000_000,
            maximum_abs_position_atoms: 1_000_000,
            maximum_open_interest_atoms: 10_000_000,
            maximum_price_atoms: 1_000_000_000,
        }
    }

    fn trader(secret_byte: u8, size: i64) -> TraderLeafV2 {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (key, _) = XOnlyPublicKey::from_keypair(&keypair);
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey(key.serialize()),
            account_nonce: 1,
            collateral_atoms: 100_000_000,
            cash_residual_numerator: 0,
            position_size_atoms: size,
            signed_cost_basis_numerator: Int256V2::from_i128(i128::from(size))
                .checked_mul_u64(100_000_000)
                .unwrap()
                .checked_mul_u64(1_000_000)
                .unwrap(),
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [secret_byte; 32],
        }
    }

    #[test]
    fn typed_risk_frontier_is_trader_linked_and_operationally_queryable() {
        let long = trader(3, 10);
        let short = trader(4, -10);
        let mut updates = vec![
            TraderStateBatchLeafUpdateV2 {
                trader: long.trader,
                old_leaf: None,
                new_leaf: Some(long.clone()),
            },
            TraderStateBatchLeafUpdateV2 {
                trader: short.trader,
                old_leaf: None,
                new_leaf: Some(short.clone()),
            },
        ];
        updates.sort_by_key(|update| update.trader.0);
        let expected = expected_projection(&updates, 600, bounds()).unwrap();
        let proof =
            RiskExtremaBatchProofV2::for_canonical_empty_root(600, expected, bounds()).unwrap();
        let next = verify_trader_risk_extrema_batch_v2(
            &updates,
            canonical_empty_risk_extrema_root_v2().unwrap(),
            Some(&proof),
            600,
            bounds(),
        )
        .unwrap();
        assert_eq!(next.aggregate.leaf_count, 2);
        let (long_x, short_x) =
            crate::operational_risk_coordinates_v2(90_000_000, 110_000_000, 0, 600, bounds())
                .unwrap();
        assert!(next
            .aggregate
            .all_positions_operationally_safe(long_x, short_x)
            .unwrap());

        let mut substituted = proof;
        substituted.mutations[0].trader_leaf.collateral_atoms += 1;
        assert!(verify_trader_risk_extrema_batch_v2(
            &updates,
            canonical_empty_risk_extrema_root_v2().unwrap(),
            Some(&substituted),
            600,
            bounds(),
        )
        .is_err());
    }

    #[test]
    fn empty_and_flat_updates_cannot_invent_a_risk_root() {
        let empty = canonical_empty_risk_extrema_root_v2().unwrap();
        assert_eq!(
            verify_trader_risk_extrema_batch_v2(&[], empty, None, 600, bounds()).unwrap(),
            empty
        );
        assert!(verify_trader_risk_extrema_batch_v2(
            &[],
            empty,
            Some(&RiskExtremaBatchProofV2 {
                maintenance_margin_bps: 600,
                mutations: vec![],
                frontier: vec![],
            }),
            600,
            bounds(),
        )
        .is_err());
    }

    #[test]
    fn risk_frontier_wire_is_bounded_and_nonrecursive() {
        let leaf = trader(5, 1);
        let updates = vec![TraderStateBatchLeafUpdateV2 {
            trader: leaf.trader,
            old_leaf: None,
            new_leaf: Some(leaf),
        }];
        let proof = RiskExtremaBatchProofV2::for_canonical_empty_root(
            600,
            expected_projection(&updates, 600, bounds()).unwrap(),
            bounds(),
        )
        .unwrap();
        assert!(
            proof.canonical_bytes_checked(bounds()).unwrap().len()
                < MAX_RISK_EXTREMA_BATCH_BYTES_V2
        );
        assert!(proof.frontier.len() <= MAX_RISK_EXTREMA_FRONTIER_ITEMS_V2);
        assert!(crate::MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2 > u128::from(u64::MAX));
    }
}
