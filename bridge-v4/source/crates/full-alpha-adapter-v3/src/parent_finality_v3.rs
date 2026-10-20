//! Exact ancestor tuple derived from a recursively authenticated selected tip.
//! This is membership relative to that tip, NOT an on-chain freshness oracle.
//! The consumer must pin the recursive binding and authenticate the currently
//! accepted terminal state/frontier before treating this as canonical finality.
use bitcoin::{block::Header, hashes::Hash};
use crate::{execute_full_alpha_adapter_v3, FullAlphaAdapterInputV3,
    FullAlphaReceiptVerifierV3, FullAlphaStatementV3,
    conversion_parent_link_v3::CustodyParentTupleV2};

pub const MAX_PARENT_MEMBERSHIP_HEADERS_V3: usize = 30_011;
#[derive(Debug,PartialEq,Eq)]
pub enum ParentFinalityErrorV3 { Receipt, Shape, Ancestry, Depth, Work }

/// Headers are oldest first: the ten predecessors of the requested ancestor
/// (or all predecessors back to genesis), the ancestor, then through the tip.
/// No caller-provided ancestor MTP or work is accepted.
pub fn authenticate_parent_ancestor_v3<V:FullAlphaReceiptVerifierV3>(
    input:&FullAlphaAdapterInputV3, headers:&[Header], ancestor_height:u32,
    minimum_descendants:u32, verifier:&V,
) -> Result<(FullAlphaStatementV3,CustodyParentTupleV2),ParentFinalityErrorV3> {
    if headers.is_empty() || headers.len()>MAX_PARENT_MEMBERSHIP_HEADERS_V3 {
        return Err(ParentFinalityErrorV3::Shape);
    }
    let statement=execute_full_alpha_adapter_v3(input,verifier)
        .map_err(|_|ParentFinalityErrorV3::Receipt)?;
    let tuple=derive_ancestor(&statement,headers,ancestor_height,minimum_descendants)?;
    Ok((statement,tuple))
}

fn derive_ancestor(s:&FullAlphaStatementV3, headers:&[Header], height:u32, depth:u32)
    ->Result<CustodyParentTupleV2,ParentFinalityErrorV3> {
    if depth==0 || s.terminal_selected_height.checked_sub(height)
        .filter(|d|*d>=depth).is_none() { return Err(ParentFinalityErrorV3::Depth); }
    let preceding=height.min(10) as usize;
    let descendants=(s.terminal_selected_height-height) as usize;
    let expected=preceding.checked_add(1).and_then(|n|n.checked_add(descendants))
        .ok_or(ParentFinalityErrorV3::Shape)?;
    if headers.len()!=expected || expected>MAX_PARENT_MEMBERSHIP_HEADERS_V3 {
        return Err(ParentFinalityErrorV3::Shape);
    }
    if headers.last().ok_or(ParentFinalityErrorV3::Shape)?.block_hash().to_byte_array()
        !=s.terminal_tip_hash_internal {return Err(ParentFinalityErrorV3::Ancestry);}
    for pair in headers.windows(2) {
        if pair[1].prev_blockhash!=pair[0].block_hash() {
            return Err(ParentFinalityErrorV3::Ancestry);
        }
    }
    let mut work=s.terminal_chainwork_be;
    // Consensus chainwork uses unsigned modulo-2^256 arithmetic, so inverse
    // accumulation uses the same wrapping subtraction (not host integers).
    for header in &headers[preceding+1..] {
        let subtract=header.target().to_work().to_be_bytes();
        let mut borrow=0i16;
        for i in (0..32).rev() {
            let value=work[i] as i16-subtract[i] as i16-borrow;
            work[i]=value as u8; borrow=if value<0 {1} else {0};
        }
    }
    if work==[0;32] {return Err(ParentFinalityErrorV3::Work);}
    let mut times:Vec<u32>=headers[..=preceding].iter().map(|h|h.time).collect();
    times.sort_unstable();
    let mut hash=headers[preceding].block_hash().to_byte_array(); hash.reverse();
    Ok(CustodyParentTupleV2 {block_hash_display:hash,height,
        median_time_past:times[times.len()/2],chainwork_be:work})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlphaRecursiveBindingV3;
    #[test]
    fn exact_ancestor_opening_and_substitutions() {
        // Codec/ancestry fixture only: the public entry point additionally
        // requires full checkpoint/transition cryptographic receipts.
        let mut headers=vec![bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header];
        for n in 1..15 {let mut h=*headers.last().unwrap();h.prev_blockhash=h.block_hash();
            h.time+=600;h.nonce=n;headers.push(h);}
        let mut total=[0;32];
        for h in &headers {total=ecx_full_consensus_validator_v2::successor_chainwork_v2(total,h.target());}
        let binding=AlphaRecursiveBindingV3 {source_configuration_commitment:[1;32],
            reviewed_checkpoint_input_commitment:[2;32],checkpoint_program_id:[3;32],transition_program_id:[4;32]};
        let s=FullAlphaStatementV3 {version:0xa3,alpha_consensus_profile_commitment:[1;32],binding,
            initial_selected_state_commitment:[1;32],initial_all_slots_state_commitment:[1;32],
            initial_frontier_commitment:[1;32],initial_event_stream_commitment:[1;32],
            initial_selected_height:0,initial_event_sequence:0,terminal_selected_state_commitment:[1;32],
            final_all_slots_state_commitment:[1;32],final_frontier_commitment:[1;32],
            final_event_stream_commitment:[1;32],terminal_selected_height:14,final_event_sequence:14,
            terminal_tip_hash_internal:headers[14].block_hash().to_byte_array(),terminal_mtp:0,
            terminal_chainwork_be:total};
        let tuple=derive_ancestor(&s,&headers,10,4).unwrap();
        assert_eq!(tuple.height,10); assert_eq!(tuple.median_time_past,headers[5].time);
        let mut expected=[0;32];for h in &headers[..11] {
            expected=ecx_full_consensus_validator_v2::successor_chainwork_v2(expected,h.target());}
        assert_eq!(tuple.chainwork_be,expected);
        let mut hash=headers[10].block_hash().to_byte_array();hash.reverse();
        assert_eq!(tuple.block_hash_display,hash);
        for i in 0..headers.len() {let mut bad=headers.clone();bad[i].time+=1;
            assert_eq!(derive_ancestor(&s,&bad,10,4),Err(ParentFinalityErrorV3::Ancestry));}
        assert_eq!(derive_ancestor(&s,&headers,10,5),Err(ParentFinalityErrorV3::Depth));
        assert_eq!(derive_ancestor(&s,&headers,10,0),Err(ParentFinalityErrorV3::Depth));
        assert_eq!(derive_ancestor(&s,&headers[1..],10,4),Err(ParentFinalityErrorV3::Shape));
    }
}
