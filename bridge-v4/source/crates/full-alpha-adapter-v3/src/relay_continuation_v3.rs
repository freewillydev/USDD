//! Authenticated continuation from an already accepted relay cursor.
//! The external relay must pin the cursor commitment; supplying one is not
//! authorization. This relation does not prove completeness of unseen events.
use crate::{execute_full_alpha_adapter_v3, FullAlphaAdapterInputV3,
    FullAlphaReceiptVerifierV3, FullAlphaStatementV3, AlphaRecursiveBindingV3};
use ecx_full_consensus_validator_v2::recursive_alpha_v3::decode_full_alpha_transition_public_values_v3;
use serde::{Serialize, Deserialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaRelayCursorV3 {
    pub binding: AlphaRecursiveBindingV3,
    pub selected_state: [u8;32],
    pub frontier: [u8;32],
    pub event_stream: [u8;32],
    pub selected_height: u32,
    pub event_sequence: u128,
}
#[derive(Debug, PartialEq, Eq)]
pub enum RelayContinuationErrorV3 { Receipt, Cursor, NoContinuation }
impl AlphaRelayCursorV3 {
    pub fn commitment(&self) -> Result<[u8;32], RelayContinuationErrorV3> {
        let binding = self.binding.commitment().map_err(|_|RelayContinuationErrorV3::Cursor)?;
        if [self.selected_state,self.frontier,self.event_stream].contains(&[0;32]) {
            return Err(RelayContinuationErrorV3::Cursor);
        }
        let mut bytes = vec![0xc4];
        for value in [binding,self.selected_state,self.frontier,self.event_stream] { bytes.extend(value); }
        bytes.extend(self.selected_height.to_be_bytes());
        bytes.extend(self.event_sequence.to_be_bytes());
        Ok(crate::tagged_hash("ECX/alpha-relay-cursor/v3", &bytes))
    }
    pub fn terminal(s: &FullAlphaStatementV3) -> Self {
        Self {binding:s.binding, selected_state:s.terminal_selected_state_commitment,
            frontier:s.final_frontier_commitment, event_stream:s.final_event_stream_commitment,
            selected_height:s.terminal_selected_height, event_sequence:s.final_event_sequence}
    }
}
pub fn authenticate_relay_continuation_v3<V:FullAlphaReceiptVerifierV3>(
    input:&FullAlphaAdapterInputV3, accepted:&AlphaRelayCursorV3, verifier:&V,
) -> Result<FullAlphaStatementV3,RelayContinuationErrorV3> {
    accepted.commitment()?;
    let s=execute_full_alpha_adapter_v3(input,verifier)
        .map_err(|_|RelayContinuationErrorV3::Receipt)?;
    if accepted.binding != s.binding || accepted.event_sequence >= s.final_event_sequence {
        return Err(RelayContinuationErrorV3::NoContinuation);
    }
    let initial=AlphaRelayCursorV3 {binding:s.binding,
        selected_state:s.initial_selected_state_commitment, frontier:s.initial_frontier_commitment,
        event_stream:s.initial_event_stream_commitment, selected_height:s.initial_selected_height,
        event_sequence:s.initial_event_sequence};
    if *accepted == initial {return Ok(s);}
    // Every receipt below was authenticated above, with complete ordered-chain
    // continuity. Match all cursor fields, not merely height or selected tip.
    for receipt in &input.transition_receipts {
        let t=decode_full_alpha_transition_public_values_v3(&receipt.public_values)
            .map_err(|_|RelayContinuationErrorV3::Receipt)?;
        let cursor=AlphaRelayCursorV3 {binding:s.binding, selected_state:t.successor_state_commitment,
            frontier:t.successor_frontier_commitment, event_stream:t.successor_event_stream_commitment,
            selected_height:t.successor_height, event_sequence:t.final_discovery_sequence};
        if cursor == *accepted {return Ok(s);}
    }
    Err(RelayContinuationErrorV3::NoContinuation)
}
