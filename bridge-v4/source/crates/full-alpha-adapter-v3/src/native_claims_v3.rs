//! Sparse spent-peg-in set. Paths are leaf-first, exactly 256 siblings.
//! Root authentication belongs to the enclosing child checkpoint.
use ecx_full_consensus_validator_v2::Hash32;
use elements::hashes::Hash as _;

fn branch(left: Hash32, right: Hash32) -> Hash32 {
    let mut bytes = [0;64];
    bytes[..32].copy_from_slice(&left); bytes[32..].copy_from_slice(&right);
    crate::tagged_hash("ECX/alpha-native-claim-branch/v3", &bytes)
}
fn leaf(claimed: bool) -> Hash32 {
    crate::tagged_hash("ECX/alpha-native-claim-leaf/v3", &[u8::from(claimed)])
}
pub fn empty_root() -> Hash32 {
    let mut root = leaf(false);
    for _ in 0..256 { root = branch(root,root); }
    root
}
/// Native GetPeginSpentKey is (prevout.hash, prevout), not a witness hash.
pub fn claim_key(outpoint: elements::OutPoint) -> Hash32 {
    let mut bytes = [0;68];
    bytes[..32].copy_from_slice(&outpoint.txid.to_byte_array());
    bytes[32..64].copy_from_slice(&outpoint.txid.to_byte_array());
    bytes[64..].copy_from_slice(&outpoint.vout.to_le_bytes());
    crate::tagged_hash("ECX/alpha-native-claim-key/v3", &bytes)
}
fn ascend(key: Hash32, siblings: &[Hash32], mut node: Hash32) -> Hash32 {
    for (level,sibling) in siblings.iter().enumerate() {
        let bit = 255 - level;
        node = if (key[bit/8] >> (7-bit%8)) & 1 == 0 {
            branch(node,*sibling)
        } else { branch(*sibling,node) };
    }
    node
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError { Path, AlreadyClaimedOrWrongRoot }

/// Derive a checkpoint root from exact native (claim domain, outpoint) keys.
/// Alpha's drivechain domain repeats the transaction ID. Other Elements
/// peg-in domains must not be silently projected into this set.
pub fn root_from_native_claims(claims: &[[u8; 68]]) -> Result<Hash32, &'static str> {
    let mut keys = Vec::with_capacity(claims.len());
    for claim in claims {
        if claim[..32] != claim[32..64] { return Err("unsupported claim domain"); }
        keys.push(crate::tagged_hash("ECX/alpha-native-claim-key/v3", claim));
    }
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) { return Err("duplicate claim"); }
    let mut empty = vec![leaf(false)];
    for height in 0..256 { empty.push(branch(empty[height], empty[height])); }
    fn subtree(keys: &[Hash32], depth: usize, empty: &[Hash32]) -> Hash32 {
        if keys.is_empty() { return empty[256 - depth]; }
        if depth == 256 { return leaf(true); }
        let split = keys.partition_point(|key| key[depth / 8] & (1 << (7 - depth % 8)) == 0);
        branch(subtree(&keys[..split], depth + 1, empty),
               subtree(&keys[split..], depth + 1, empty))
    }
    Ok(subtree(&keys, 0, &empty))
}
/// Authenticate an absent leaf and return the inserted root without mutating
/// caller state. Reusing an absence path after insertion fails.
pub fn insert(root: Hash32, outpoint: elements::OutPoint, siblings: &[Hash32])
    -> Result<Hash32,ClaimError> {
    if siblings.len()!=256 { return Err(ClaimError::Path); }
    let key=claim_key(outpoint);
    if ascend(key,siblings,leaf(false))!=root {
        return Err(ClaimError::AlreadyClaimedOrWrongRoot);
    }
    Ok(ascend(key,siblings,leaf(true)))
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn native_snapshot_root_matches_transition_insertion() {
        let outpoint = elements::OutPoint::new(elements::Txid::from_byte_array([4; 32]), 2);
        let mut raw = [4u8; 68];
        raw[64..].copy_from_slice(&2u32.to_le_bytes());
        let mut siblings = Vec::new();
        let mut node = leaf(false);
        for _ in 0..256 { siblings.push(node); node = branch(node, node); }
        assert_eq!(root_from_native_claims(&[]).unwrap(), empty_root());
        let expected = insert(empty_root(), outpoint, &siblings).unwrap();
        assert_eq!(root_from_native_claims(&[raw]).unwrap(), expected);
        assert!(root_from_native_claims(&[raw, raw]).is_err());
        let mut wrong_domain = raw; wrong_domain[0] ^= 1;
        assert!(root_from_native_claims(&[wrong_domain]).is_err());
        let mut other = raw; other[64..].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(root_from_native_claims(&[raw, other]), root_from_native_claims(&[other, raw]));
        assert_ne!(root_from_native_claims(&[raw, other]).unwrap(), expected);
    }
    #[test] fn insertion_rejects_repeated_claim_and_mutated_paths() {
        let mut siblings=Vec::new(); let mut node=leaf(false);
        for _ in 0..256 { siblings.push(node); node=branch(node,node); }
        assert_eq!(node,empty_root());
        let outpoint=elements::OutPoint::new(elements::Txid::from_byte_array([4;32]),2);
        let next=insert(node,outpoint,&siblings).unwrap();
        assert_ne!(next,node);
        assert_eq!(insert(next,outpoint,&siblings),Err(ClaimError::AlreadyClaimedOrWrongRoot));
        assert_eq!(insert(node,outpoint,&siblings[..255]),Err(ClaimError::Path));
        for level in [0,127,255] {
            let mut changed=siblings.clone(); changed[level][0]^=1;
            assert!(insert(node,outpoint,&changed).is_err());
        }
        let other=elements::OutPoint::new(outpoint.txid,3);
        assert_ne!(claim_key(other),claim_key(outpoint));
        assert_ne!(insert(node,other,&siblings).unwrap(),next);
    }
}
