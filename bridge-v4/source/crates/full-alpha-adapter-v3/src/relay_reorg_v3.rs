//! Authenticate the shared ancestor of the stored and successor selected tips.
//! A relay may retain previously authenticated membership at/below this height;
//! entries above it need invalidation, and new membership still requires proof.
use bitcoin::{block::Header, hashes::Hash};
use crate::{FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3, FullAlphaStatementV3,
    execute_full_alpha_adapter_v3,
    relay_continuation_v3::{AlphaRelayCursorV3, authenticate_relay_continuation_v3},
    parent_finality_v3::MAX_PARENT_MEMBERSHIP_HEADERS_V3};

#[derive(Debug, PartialEq, Eq)]
pub enum RelayReorgErrorV3 { Authentication, Shape, Ancestry }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAncestorV3 { pub height: u32, pub hash_internal: [u8;32] }

pub fn authenticate_relay_reorg_v3<V: FullAlphaReceiptVerifierV3>(
    accepted_input: &FullAlphaAdapterInputV3, successor_input: &FullAlphaAdapterInputV3,
    accepted_headers: &[Header], successor_headers: &[Header], verifier: &V,
) -> Result<(AlphaRelayCursorV3, FullAlphaStatementV3, SharedAncestorV3), RelayReorgErrorV3> {
    let accepted = execute_full_alpha_adapter_v3(accepted_input, verifier)
        .map_err(|_| RelayReorgErrorV3::Authentication)?;
    let cursor = AlphaRelayCursorV3::terminal(&accepted);
    let successor = authenticate_relay_continuation_v3(successor_input, &cursor, verifier)
        .map_err(|_| RelayReorgErrorV3::Authentication)?;
    let shared = shared_ancestor(accepted.terminal_selected_height, accepted.terminal_tip_hash_internal,
        accepted_headers, successor.terminal_selected_height, successor.terminal_tip_hash_internal,
        successor_headers)?;
    Ok((cursor, successor, shared))
}

fn anchored_start(height: u32, tip: [u8;32], headers: &[Header]) -> Result<u32, RelayReorgErrorV3> {
    if headers.is_empty() || headers.len() > MAX_PARENT_MEMBERSHIP_HEADERS_V3 {
        return Err(RelayReorgErrorV3::Shape);
    }
    let start = height.checked_sub((headers.len()-1) as u32).ok_or(RelayReorgErrorV3::Shape)?;
    if headers.last().unwrap().block_hash().to_byte_array() != tip
        || headers.windows(2).any(|p| p[1].prev_blockhash != p[0].block_hash()) {
        return Err(RelayReorgErrorV3::Ancestry);
    }
    Ok(start)
}
fn shared_ancestor(old_height: u32, old_tip: [u8;32], old: &[Header],
    new_height: u32, new_tip: [u8;32], new: &[Header]) -> Result<SharedAncestorV3, RelayReorgErrorV3> {
    let start = anchored_start(old_height, old_tip, old)?;
    if anchored_start(new_height, new_tip, new)? != start || old[0] != new[0] {
        return Err(RelayReorgErrorV3::Ancestry);
    }
    let common = old.iter().zip(new).take_while(|(a,b)| a == b).count();
    Ok(SharedAncestorV3 {height: start + (common-1) as u32,
        hash_internal: old[common-1].block_hash().to_byte_array()})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn extend(headers: &mut Vec<Header>, nonce: u32) {
        let mut h = *headers.last().unwrap(); h.prev_blockhash = h.block_hash();
        h.time += 600; h.nonce = nonce; headers.push(h);
    }
    #[test]
    fn shared_prefix_retains_ancestors_and_rejects_unanchored_paths() {
        // Structural hash-chain fixture, not mined headers or live receipts.
        let mut old = vec![bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header];
        for n in 1..6 { extend(&mut old,n); }
        let mut new = old[..3].to_vec();
        for n in 10..15 { extend(&mut new,n); }
        let check = |a: &[Header], b: &[Header]| shared_ancestor(5,old[5].block_hash().to_byte_array(),a,
            7,new[7].block_hash().to_byte_array(),b);
        assert_eq!(check(&old,&new).unwrap(),SharedAncestorV3 {height:2,hash_internal:old[2].block_hash().to_byte_array()});
        assert_eq!(check(&old[1..],&new[1..]).unwrap().height,2);
        assert!(check(&old[1..],&new).is_err());
        assert!(check(&[],&new).is_err());
        for n in 0..new.len() { let mut changed=new.clone();changed[n].nonce^=1;assert!(check(&old,&changed).is_err()); }
        let mut extension=old.clone();extend(&mut extension,20);
        assert_eq!(shared_ancestor(5,old[5].block_hash().to_byte_array(),&old,
            6,extension[6].block_hash().to_byte_array(),&extension).unwrap().height,5);
        assert_eq!(shared_ancestor(5,old[5].block_hash().to_byte_array(),&old,
            5,old[5].block_hash().to_byte_array(),&old).unwrap().height,5);
    }
}
