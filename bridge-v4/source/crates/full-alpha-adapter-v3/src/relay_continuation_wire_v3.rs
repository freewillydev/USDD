//! Canonical recursive continuation transport. The consumer must compare the
//! accepted commitment with its own stored cursor before updating that cursor.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3,
    encode_full_alpha_adapter_input_v3, encode_full_alpha_statement_v3,
    relay_continuation_v3::{AlphaRelayCursorV3, authenticate_relay_continuation_v3}};

pub const RELAY_CONTINUATION_WIRE_VERSION_V3: u8 = 0xc4;
pub const MAX_RELAY_CONTINUATION_WIRE_BYTES_V3: usize = 17 * 1024 * 1024;
pub const RELAY_CONTINUATION_PUBLIC_VALUES_BYTES_V3: usize = 594;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayContinuationWitnessV3 {
    pub version: u8,
    pub parent: FullAlphaAdapterInputV3,
    pub accepted: AlphaRelayCursorV3,
}
#[derive(Debug, PartialEq, Eq)]
pub enum RelayContinuationWireErrorV3 { Shape, Authentication }
fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_RELAY_CONTINUATION_WIRE_BYTES_V3 as u64).reject_trailing_bytes()
}
pub fn encode_relay_continuation_v3(input: &RelayContinuationWitnessV3)
    -> Result<Vec<u8>, RelayContinuationWireErrorV3> {
    use RelayContinuationWireErrorV3::Shape;
    if input.version != RELAY_CONTINUATION_WIRE_VERSION_V3
        || input.accepted.commitment().is_err()
        || encode_full_alpha_adapter_input_v3(&input.parent).is_err() { return Err(Shape); }
    let bytes = options().serialize(input).map_err(|_| Shape)?;
    if bytes.len() > MAX_RELAY_CONTINUATION_WIRE_BYTES_V3 { return Err(Shape); }
    Ok(bytes)
}
pub fn decode_relay_continuation_v3(bytes: &[u8])
    -> Result<RelayContinuationWitnessV3, RelayContinuationWireErrorV3> {
    use RelayContinuationWireErrorV3::Shape;
    if bytes.is_empty() || bytes.len() > MAX_RELAY_CONTINUATION_WIRE_BYTES_V3 { return Err(Shape); }
    let input = options().deserialize(bytes).map_err(|_| Shape)?;
    if encode_relay_continuation_v3(&input)? != bytes { return Err(Shape); }
    Ok(input)
}
/// Version, accepted cursor commitment, successor cursor commitment, then the
/// byte-exact 529-byte Alpha journal. All commitments come from verified inputs.
pub fn execute_relay_continuation_v3<V: FullAlphaReceiptVerifierV3>(
    input: &RelayContinuationWitnessV3, verifier: &V,
) -> Result<Vec<u8>, RelayContinuationWireErrorV3> {
    use RelayContinuationWireErrorV3::{Shape, Authentication};
    encode_relay_continuation_v3(input)?;
    let statement = authenticate_relay_continuation_v3(&input.parent, &input.accepted, verifier)
        .map_err(|_| Authentication)?;
    let mut bytes = vec![RELAY_CONTINUATION_WIRE_VERSION_V3];
    bytes.extend(input.accepted.commitment().map_err(|_| Shape)?);
    bytes.extend(AlphaRelayCursorV3::terminal(&statement).commitment().map_err(|_| Shape)?);
    bytes.extend(encode_full_alpha_statement_v3(&statement).map_err(|_| Shape)?);
    if bytes.len() != RELAY_CONTINUATION_PUBLIC_VALUES_BYTES_V3 { return Err(Shape); }
    Ok(bytes)
}
