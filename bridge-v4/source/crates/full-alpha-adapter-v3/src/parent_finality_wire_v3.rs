//! Canonical transport for ancestor membership relative to an authenticated tip.
//! Consumers must still authenticate that tip against their current relay state.
use bincode::Options;
use bitcoin::block::Header;
use serde::{Deserialize, Serialize};
use crate::{FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3,
    encode_full_alpha_adapter_input_v3, encode_full_alpha_statement_v3,
    parent_finality_v3::{authenticate_parent_ancestor_v3, ParentFinalityErrorV3,
        MAX_PARENT_MEMBERSHIP_HEADERS_V3}};

pub const PARENT_FINALITY_WIRE_VERSION_V3: u8 = 0xc3;
pub const MAX_PARENT_FINALITY_WIRE_BYTES_V3: usize = 24 * 1024 * 1024;
pub const PARENT_FINALITY_PUBLIC_VALUES_BYTES_V3: usize = 606;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentFinalityWitnessV3 {
    pub version: u8,
    pub parent: FullAlphaAdapterInputV3,
    pub headers: Vec<Header>,
    pub ancestor_height: u32,
    pub minimum_descendants: u32,
}
fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_PARENT_FINALITY_WIRE_BYTES_V3 as u64).reject_trailing_bytes()
}
pub fn encode_parent_finality_v3(input: &ParentFinalityWitnessV3)
    -> Result<Vec<u8>, ParentFinalityErrorV3> {
    if input.version != PARENT_FINALITY_WIRE_VERSION_V3 || input.minimum_descendants == 0
        || input.headers.is_empty() || input.headers.len() > MAX_PARENT_MEMBERSHIP_HEADERS_V3
        || encode_full_alpha_adapter_input_v3(&input.parent).is_err() {
        return Err(ParentFinalityErrorV3::Shape);
    }
    let bytes = options().serialize(input).map_err(|_| ParentFinalityErrorV3::Shape)?;
    if bytes.len() > MAX_PARENT_FINALITY_WIRE_BYTES_V3 { return Err(ParentFinalityErrorV3::Shape); }
    Ok(bytes)
}
pub fn decode_parent_finality_v3(bytes: &[u8])
    -> Result<ParentFinalityWitnessV3, ParentFinalityErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_PARENT_FINALITY_WIRE_BYTES_V3 {
        return Err(ParentFinalityErrorV3::Shape);
    }
    let input = options().deserialize(bytes).map_err(|_| ParentFinalityErrorV3::Shape)?;
    if encode_parent_finality_v3(&input)? != bytes { return Err(ParentFinalityErrorV3::Shape); }
    Ok(input)
}
/// Version byte, exact existing 529-byte Alpha journal, depth (BE u32), then
/// ancestor display hash, height (BE u32), MTP (BE u32), chainwork (BE u256).
/// No caller-supplied tuple or journal can bypass recursive authentication.
pub fn execute_parent_finality_v3<V: FullAlphaReceiptVerifierV3>(
    input: &ParentFinalityWitnessV3, verifier: &V,
) -> Result<Vec<u8>, ParentFinalityErrorV3> {
    encode_parent_finality_v3(input)?;
    let (statement, tuple) = authenticate_parent_ancestor_v3(&input.parent, &input.headers,
        input.ancestor_height, input.minimum_descendants, verifier)?;
    let mut bytes = vec![PARENT_FINALITY_WIRE_VERSION_V3];
    bytes.extend(encode_full_alpha_statement_v3(&statement).map_err(|_| ParentFinalityErrorV3::Shape)?);
    bytes.extend(input.minimum_descendants.to_be_bytes());
    bytes.extend(tuple.block_hash_display);
    bytes.extend(tuple.height.to_be_bytes());
    bytes.extend(tuple.median_time_past.to_be_bytes());
    bytes.extend(tuple.chainwork_be);
    if bytes.len() != PARENT_FINALITY_PUBLIC_VALUES_BYTES_V3 { return Err(ParentFinalityErrorV3::Shape); }
    Ok(bytes)
}
