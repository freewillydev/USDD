//! Versioned reorg transport. Consumers must pin the accepted cursor and verifier.
use bincode::Options;
use bitcoin::block::Header;
use serde::{Deserialize, Serialize};
use crate::{FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3,
    encode_full_alpha_adapter_input_v3, encode_full_alpha_statement_v3,
    relay_continuation_v3::AlphaRelayCursorV3,
    relay_reorg_v3::authenticate_relay_reorg_v3,
    parent_finality_v3::MAX_PARENT_MEMBERSHIP_HEADERS_V3};

pub const RELAY_REORG_WIRE_VERSION_V3: u8 = 0xc5;
pub const MAX_RELAY_REORG_WIRE_BYTES_V3: usize = 40 * 1024 * 1024;
pub const RELAY_REORG_PUBLIC_VALUES_BYTES_V3: usize = 630;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayReorgWitnessV3 {
    pub version: u8,
    pub accepted: FullAlphaAdapterInputV3,
    pub successor: FullAlphaAdapterInputV3,
    pub accepted_headers: Vec<Header>,
    pub successor_headers: Vec<Header>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum RelayReorgWireErrorV3 { Shape, Authentication }
fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_RELAY_REORG_WIRE_BYTES_V3 as u64).reject_trailing_bytes()
}
pub fn encode_relay_reorg_v3(input: &RelayReorgWitnessV3) -> Result<Vec<u8>, RelayReorgWireErrorV3> {
    use RelayReorgWireErrorV3::Shape;
    if input.version != RELAY_REORG_WIRE_VERSION_V3
        || [&input.accepted_headers, &input.successor_headers].iter()
            .any(|h| h.is_empty() || h.len() > MAX_PARENT_MEMBERSHIP_HEADERS_V3)
        || encode_full_alpha_adapter_input_v3(&input.accepted).is_err()
        || encode_full_alpha_adapter_input_v3(&input.successor).is_err() { return Err(Shape); }
    let bytes = options().serialize(input).map_err(|_| Shape)?;
    if bytes.len() > MAX_RELAY_REORG_WIRE_BYTES_V3 { return Err(Shape); }
    Ok(bytes)
}
pub fn decode_relay_reorg_v3(bytes: &[u8]) -> Result<RelayReorgWitnessV3, RelayReorgWireErrorV3> {
    use RelayReorgWireErrorV3::Shape;
    if bytes.is_empty() || bytes.len() > MAX_RELAY_REORG_WIRE_BYTES_V3 { return Err(Shape); }
    let input = options().deserialize(bytes).map_err(|_| Shape)?;
    if encode_relay_reorg_v3(&input)? != bytes { return Err(Shape); }
    Ok(input)
}
/// 0xc5, accepted cursor, successor cursor, exact 529-byte successor Alpha
/// journal, shared-ancestor height (BE u32), shared-ancestor internal hash.
pub fn execute_relay_reorg_v3<V: FullAlphaReceiptVerifierV3>(input: &RelayReorgWitnessV3, verifier: &V)
    -> Result<Vec<u8>, RelayReorgWireErrorV3> {
    use RelayReorgWireErrorV3::{Shape, Authentication};
    encode_relay_reorg_v3(input)?;
    let (accepted, successor, shared) = authenticate_relay_reorg_v3(&input.accepted,
        &input.successor, &input.accepted_headers, &input.successor_headers, verifier)
        .map_err(|_| Authentication)?;
    let mut bytes = vec![RELAY_REORG_WIRE_VERSION_V3];
    bytes.extend(accepted.commitment().map_err(|_| Shape)?);
    bytes.extend(AlphaRelayCursorV3::terminal(&successor).commitment().map_err(|_| Shape)?);
    bytes.extend(encode_full_alpha_statement_v3(&successor).map_err(|_| Shape)?);
    bytes.extend(shared.height.to_be_bytes());
    bytes.extend(shared.hash_internal);
    if bytes.len() != RELAY_REORG_PUBLIC_VALUES_BYTES_V3 { return Err(Shape); }
    Ok(bytes)
}
