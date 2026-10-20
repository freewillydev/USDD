use crate::codec::{put_u64, CanonicalEncode};
use crate::hash::{tagged_hash, Hash32};
use crate::ProtocolError;

const EMPTY_TAG: &str = "ECX/merkle-empty/v1";
const LEAF_TAG: &str = "ECX/merkle-leaf/v1";
const NODE_TAG: &str = "ECX/merkle-node/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyedCommitment {
    pub key: Hash32,
    pub commitment: Hash32,
}

impl KeyedCommitment {
    pub fn leaf_hash(&self) -> Hash32 {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.key);
        bytes[32..].copy_from_slice(&self.commitment);
        tagged_hash(LEAF_TAG, &bytes)
    }
}

impl CanonicalEncode for KeyedCommitment {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<KeyedCommitment>,
    layers: Vec<Vec<Hash32>>,
}

impl MerkleTree {
    pub fn from_keyed(mut leaves: Vec<KeyedCommitment>) -> Result<Self, ProtocolError> {
        leaves.sort_by_key(|leaf| leaf.key);
        if leaves.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(ProtocolError::DuplicateMerkleKey);
        }

        if leaves.is_empty() {
            return Ok(Self {
                leaves,
                layers: vec![vec![empty_hash()]],
            });
        }

        let width = leaves.len().next_power_of_two();
        let mut bottom: Vec<Hash32> = leaves.iter().map(KeyedCommitment::leaf_hash).collect();
        bottom.resize(width, empty_hash());
        let mut layers = vec![bottom];
        while layers.last().expect("one layer").len() > 1 {
            let previous = layers.last().expect("one layer");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for pair in previous.chunks_exact(2) {
                next.push(node_hash(pair[0], pair[1]));
            }
            layers.push(next);
        }
        Ok(Self { leaves, layers })
    }

    pub fn root(&self) -> Hash32 {
        self.layers.last().expect("tree always has a root")[0]
    }

    pub fn leaves(&self) -> &[KeyedCommitment] {
        &self.leaves
    }

    pub fn proof(&self, key: Hash32) -> Result<MerkleProof, ProtocolError> {
        let mut index = self
            .leaves
            .binary_search_by_key(&key, |leaf| leaf.key)
            .map_err(|_| ProtocolError::InvalidMerkleProof)?;
        let original_index = index;
        let mut siblings = Vec::with_capacity(self.layers.len().saturating_sub(1));
        for layer in self.layers.iter().take(self.layers.len().saturating_sub(1)) {
            siblings.push(layer[index ^ 1]);
            index /= 2;
        }
        Ok(MerkleProof {
            index: original_index as u64,
            leaf_count: self.leaves.len() as u64,
            siblings,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleProof {
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Hash32>,
}

impl MerkleProof {
    pub fn verify(&self, leaf: KeyedCommitment, root: Hash32) -> bool {
        if self.leaf_count == 0 || self.index >= self.leaf_count {
            return false;
        }
        let expected_width = match usize::try_from(self.leaf_count) {
            Ok(count) => count.next_power_of_two(),
            Err(_) => return false,
        };
        if self.siblings.len() != expected_width.trailing_zeros() as usize {
            return false;
        }
        let mut hash = leaf.leaf_hash();
        let mut index = self.index as usize;
        for sibling in &self.siblings {
            hash = if index & 1 == 0 {
                node_hash(hash, *sibling)
            } else {
                node_hash(*sibling, hash)
            };
            index /= 2;
        }
        hash == root
    }
}

pub fn empty_hash() -> Hash32 {
    tagged_hash(EMPTY_TAG, &[])
}

pub fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    tagged_hash(NODE_TAG, &bytes)
}

/// Commits to an ordered list without depending on map iteration order.
pub fn ordered_root(tag: &str, values: &[Hash32]) -> Hash32 {
    if values.is_empty() {
        return tagged_hash(&format!("{tag}/empty"), &[]);
    }
    let mut leaves = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let mut bytes = Vec::with_capacity(40);
        put_u64(&mut bytes, index as u64);
        bytes.extend_from_slice(value);
        leaves.push(tagged_hash(&format!("{tag}/leaf"), &bytes));
    }
    let width = leaves.len().next_power_of_two();
    leaves.resize(width, tagged_hash(&format!("{tag}/pad"), &[]));
    while leaves.len() > 1 {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| {
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(&pair[0]);
                bytes[32..].copy_from_slice(&pair[1]);
                tagged_hash(&format!("{tag}/node"), &bytes)
            })
            .collect();
    }
    leaves[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_root_is_insertion_order_independent() {
        let a = KeyedCommitment {
            key: [1; 32],
            commitment: [9; 32],
        };
        let b = KeyedCommitment {
            key: [2; 32],
            commitment: [8; 32],
        };
        let first = MerkleTree::from_keyed(vec![a, b]).unwrap();
        let second = MerkleTree::from_keyed(vec![b, a]).unwrap();
        assert_eq!(first.root(), second.root());
        assert!(first.proof(a.key).unwrap().verify(a, first.root()));
        assert!(first.proof(b.key).unwrap().verify(b, first.root()));
    }

    #[test]
    fn proof_rejects_mutated_leaf_and_shape() {
        let leaf = KeyedCommitment {
            key: [3; 32],
            commitment: [4; 32],
        };
        let tree = MerkleTree::from_keyed(vec![leaf]).unwrap();
        let proof = tree.proof(leaf.key).unwrap();
        let mut altered = leaf;
        altered.commitment[0] ^= 1;
        assert!(!proof.verify(altered, tree.root()));
        let mut malformed = proof;
        malformed.siblings.push([0; 32]);
        assert!(!malformed.verify(leaf, tree.root()));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let leaf = KeyedCommitment {
            key: [1; 32],
            commitment: [2; 32],
        };
        assert_eq!(
            MerkleTree::from_keyed(vec![leaf, leaf]),
            Err(ProtocolError::DuplicateMerkleKey)
        );
    }
}
