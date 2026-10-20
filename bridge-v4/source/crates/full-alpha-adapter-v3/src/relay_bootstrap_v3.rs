//! Derive relay constructor checkpoint values from an authenticated Alpha chain.
//! The expected binding must come from an independently reviewed release, not
//! be copied from untrusted witness input. This does not establish freshness,
//! event-source completeness or release approval.
use bitcoin::hashes::{sha256, Hash as _};
use crate::{AlphaRecursiveBindingV3, FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3,
    execute_full_alpha_adapter_v3, encode_full_alpha_statement_v3};
use crate::relay_continuation_v3::AlphaRelayCursorV3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlphaRelayBootstrapV3 {
    pub binding_sha256: [u8;32],
    pub cursor: [u8;32],
    pub journal_sha256: [u8;32],
    pub height: u32,
    pub public_values: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayBootstrapErrorV3 { Binding, Authentication, Encoding }

pub fn authenticate_relay_bootstrap_v3<V: FullAlphaReceiptVerifierV3>(
    input: &FullAlphaAdapterInputV3,
    expected_binding: &AlphaRecursiveBindingV3,
    verifier: &V,
) -> Result<AlphaRelayBootstrapV3,RelayBootstrapErrorV3> {
    expected_binding.commitment().map_err(|_|RelayBootstrapErrorV3::Binding)?;
    if input.binding != *expected_binding { return Err(RelayBootstrapErrorV3::Binding); }
    let statement=execute_full_alpha_adapter_v3(input,verifier)
        .map_err(|_|RelayBootstrapErrorV3::Authentication)?;
    let values=encode_full_alpha_statement_v3(&statement)
        .map_err(|_|RelayBootstrapErrorV3::Encoding)?;
    let cursor=AlphaRelayCursorV3::terminal(&statement).commitment()
        .map_err(|_|RelayBootstrapErrorV3::Encoding)?;
    // Solidity sha256(abi.encode(profile,source,checkpoint,checkpointProgram,
    // transitionProgram)): five consecutive bytes32 values, no version byte.
    let binding_sha256=sha256::Hash::hash(&values[1..161]).to_byte_array();
    Ok(AlphaRelayBootstrapV3 { binding_sha256,cursor,
        journal_sha256:sha256::Hash::hash(&values).to_byte_array(),
        height:statement.terminal_selected_height,public_values:values })
}
