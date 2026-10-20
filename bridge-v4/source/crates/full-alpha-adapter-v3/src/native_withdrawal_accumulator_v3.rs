//! Exact native depth-64 withdrawal accumulator and BIP301 preimage codec.
//! Leaves must come from independently validated complete child transactions.
//! This module does not authenticate caller-supplied leaves or checkpoints.
use bitcoin::hashes::{sha256, Hash};
use ecx_full_consensus_validator_v2::Hash32;

fn hash(bytes: &[u8]) -> Hash32 { sha256::Hash::hash(bytes).to_byte_array() }
fn node(left: Hash32, right: Hash32) -> Hash32 {
    let mut bytes = [0; 65];
    bytes[0] = 1;
    bytes[1..33].copy_from_slice(&left);
    bytes[33..].copy_from_slice(&right);
    hash(&bytes)
}
fn empty_roots() -> [Hash32; 65] {
    let mut roots = [[0; 32]; 65];
    roots[0] = hash(&[0]);
    for i in 0..64 { roots[i + 1] = node(roots[i], roots[i]); }
    roots
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "WithdrawalAccumulatorWire", try_from = "WithdrawalAccumulatorWire")]
pub struct WithdrawalAccumulator {
    pub count: u64,
    pub root: Hash32,
    pub frontier: [Hash32; 64],
}

// Witness transport only; the consensus commitment remains unchanged. Serde
// does not support this array length directly. Reject other lengths and invalid
// frontiers on input rather than padding/truncating an untrusted vector.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawalAccumulatorWire {
    count: u64,
    root: Hash32,
    frontier: Vec<Hash32>,
}
impl From<WithdrawalAccumulator> for WithdrawalAccumulatorWire {
    fn from(value: WithdrawalAccumulator) -> Self {
        Self { count: value.count, root: value.root, frontier: value.frontier.to_vec() }
    }
}
impl TryFrom<WithdrawalAccumulatorWire> for WithdrawalAccumulator {
    type Error = &'static str;
    fn try_from(value: WithdrawalAccumulatorWire) -> Result<Self, Self::Error> {
        let accumulator = Self { count: value.count, root: value.root,
            frontier: value.frontier.try_into().map_err(|_| "withdrawal frontier length")? };
        if !accumulator.is_sane() { return Err("withdrawal frontier/root mismatch"); }
        Ok(accumulator)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccumulatorError { Malformed, Overflow, NullIdentity }

/// Verify membership in an independently authenticated native accumulator.
/// Siblings are leaf-to-root; indices use the global withdrawal sequence.
/// This does not establish custody authorization or parent approval.
pub fn verify_withdrawal_membership(
    leaf: Hash32, index: u64, count: u64, root: Hash32, siblings: &[Hash32],
) -> Result<(), AccumulatorError> {
    if index >= count || siblings.len() != 64 {
        return Err(AccumulatorError::Malformed);
    }
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if (index >> level) & 1 == 0 {
            node(current, *sibling)
        } else {
            node(*sibling, current)
        };
    }
    if current != root { return Err(AccumulatorError::Malformed); }
    Ok(())
}

impl WithdrawalAccumulator {
    pub fn empty() -> Self {
        Self { count: 0, root: empty_roots()[64], frontier: [[0; 32]; 64] }
    }
    pub fn is_sane(&self) -> bool {
        let empty = empty_roots();
        let mut root = empty[0];
        for level in 0..64 {
            root = if (self.count >> level) & 1 != 0 {
                node(self.frontier[level], root)
            } else {
                if self.frontier[level] != [0; 32] { return false; }
                node(root, empty[level])
            };
        }
        root == self.root
    }
    pub fn append(&mut self, leaf: Hash32) -> Result<(), AccumulatorError> {
        if !self.is_sane() { return Err(AccumulatorError::Malformed); }
        if self.count == u64::MAX { return Err(AccumulatorError::Overflow); }
        let mut occupied = self.count;
        let mut current = leaf;
        let mut level = 0;
        while occupied & 1 != 0 {
            current = node(self.frontier[level], current);
            self.frontier[level] = [0; 32];
            occupied >>= 1;
            level += 1;
        }
        self.frontier[level] = current;
        self.count += 1;
        let empty = empty_roots();
        let mut root = empty[0];
        for level in 0..64 {
            root = if (self.count >> level) & 1 != 0 {
                node(self.frontier[level], root)
            } else { node(root, empty[level]) };
        }
        self.root = root;
        Ok(())
    }
}

/// Hash arguments/result are internal uint256 byte order. Accumulator roots
/// remain raw SHA-256 digest bytes. Native checkpoint hashing is SINGLE SHA256,
/// not Bitcoin's double hash or a tagged hash.
pub fn critical_hash_internal(
    genesis_internal: Hash32, slot: u8, child_internal: Hash32,
    previous: &WithdrawalAccumulator, next: &WithdrawalAccumulator,
) -> Result<Hash32, AccumulatorError> {
    if genesis_internal == [0; 32] || child_internal == [0; 32] {
        return Err(AccumulatorError::NullIdentity);
    }
    if !previous.is_sane() || !next.is_sane() || next.count < previous.count
        || (next.count == previous.count) != (next.root == previous.root) {
        return Err(AccumulatorError::Malformed);
    }
    let mut bytes = b"Elements/USDD/BIP301-checkpoint/v1".to_vec();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(genesis_internal.iter().rev());
    bytes.push(slot);
    bytes.extend(child_internal.iter().rev());
    bytes.extend_from_slice(&previous.count.to_be_bytes());
    bytes.extend_from_slice(&previous.root);
    bytes.extend_from_slice(&next.count.to_be_bytes());
    bytes.extend_from_slice(&next.root);
    let mut digest = hash(&bytes);
    digest.reverse();
    if digest == [0; 32] { return Err(AccumulatorError::NullIdentity); }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Hash32 {
        core::array::from_fn(|i| u8::from_str_radix(&s[i*2..i*2+2], 16).unwrap())
    }
    fn internal(s: &str) -> Hash32 { let mut h = hex(s); h.reverse(); h }
    #[test]
    fn native_cpp_two_claim_critical_hash_vector() {
        let previous = WithdrawalAccumulator::empty();
        let mut next = previous.clone();
        next.append(hex("8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f")).unwrap();
        next.append(hex("411d36323ee653bda6c17167e4321e2437ae288a42e7786bed84832ba7baa7ec")).unwrap();
        assert!(next.is_sane());
        let genesis = internal("3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6");
        let child = internal("f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2");
        let result = critical_hash_internal(genesis, 24, child, &previous, &next).unwrap();
        assert_eq!(result, internal("6b9c9c485cce8a07a5d6d78c81b5566f269f5df03fa38cd29d5c3de7cb985161"));
        assert_ne!(result, critical_hash_internal(genesis, 25, child, &previous, &next).unwrap());
        assert_ne!(result, critical_hash_internal(child, 24, genesis, &previous, &next).unwrap());
    }
    #[test]
    fn malformed_states_and_regression_rejected_without_mutation() {
        let empty = WithdrawalAccumulator::empty();
        let mut bad = empty.clone(); bad.frontier[0] = [7; 32];
        let saved = bad.clone();
        assert_eq!(bad.append([1; 32]), Err(AccumulatorError::Malformed));
        assert_eq!(bad, saved);
        assert_eq!(critical_hash_internal([1; 32],24,[2;32],&empty,&bad), Err(AccumulatorError::Malformed));
        let mut next = empty.clone(); next.append([3;32]).unwrap();
        assert_eq!(critical_hash_internal([1;32],24,[2;32],&next,&empty), Err(AccumulatorError::Malformed));
        assert!(critical_hash_internal([1;32],24,[2;32],&next,&next).is_ok());
        assert_eq!(critical_hash_internal([0;32],24,[2;32],&next,&next), Err(AccumulatorError::NullIdentity));
    }
    #[test]
    fn frontier_carries_match_independent_padded_tree() {
        let empty = empty_roots();
        let mut state = WithdrawalAccumulator::empty();
        let mut leaves = Vec::new();
        for i in 0..65u8 {
            let leaf = hash(&[i]); leaves.push(leaf); state.append(leaf).unwrap();
            let mut layer = leaves.clone();
            for level in 0..64 {
                if layer.len() % 2 != 0 { layer.push(empty[level]); }
                layer = layer.chunks_exact(2).map(|p| node(p[0], p[1])).collect();
            }
            assert_eq!(layer, vec![state.root]);
            assert!(state.is_sane());
        }
    }

    #[test]
    fn membership_checks_global_index_depth_and_claim() {
        let empty = empty_roots();
        let leaves: Vec<_> = (0..5u8).map(|i| hash(&[i])).collect();
        let mut state = WithdrawalAccumulator::empty();
        for leaf in &leaves { state.append(*leaf).unwrap(); }
        for index in 0..leaves.len() {
            let mut layer = leaves.clone();
            let mut cursor = index;
            let mut path = Vec::new();
            for level in 0..64 {
                if layer.len() % 2 != 0 { layer.push(empty[level]); }
                path.push(layer[cursor ^ 1]);
                layer = layer.chunks_exact(2).map(|p| node(p[0], p[1])).collect();
                cursor >>= 1;
            }
            assert_eq!(verify_withdrawal_membership(leaves[index], index as u64, state.count, state.root, &path), Ok(()));
            assert!(verify_withdrawal_membership(hash(b"wrong"), index as u64, state.count, state.root, &path).is_err());
            assert!(verify_withdrawal_membership(leaves[index], index as u64, state.count, state.root, &path[..63]).is_err());
            assert!(verify_withdrawal_membership(leaves[index], index as u64, index as u64, state.root, &path).is_err());
            assert!(verify_withdrawal_membership(leaves[index], (index as u64) ^ 1, state.count, state.root, &path).is_err());
            path[63][0] ^= 1;
            assert!(verify_withdrawal_membership(leaves[index], index as u64, state.count, state.root, &path).is_err());
        }
    }
}
