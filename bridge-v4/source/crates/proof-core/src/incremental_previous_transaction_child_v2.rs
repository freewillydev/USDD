//! Independently recoverable projection of selected predecessor outputs.

use bincode::Options;
use ecx_elements_settlement::{
    verify_previous_transaction_output_openings_v2, PreviousTransactionOutputOpeningV2,
    SettlementError, MAX_ELEMENTS_TRANSACTION_BYTES,
};
use ecx_protocol_core::Hash32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INCREMENTAL_PREVIOUS_TRANSACTION_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2: usize = 4 + 32 + 32 + 4 + 4;
pub const INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2: usize =
    4 + 32 + 8 + 32 + 32 + 32;
pub const MAX_INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUTS_V2: usize = 10_000;
pub const MAX_INCREMENTAL_PREVIOUS_TRANSACTION_CHILD_INPUT_BYTES_V2: usize = 2 * 1024 * 1024;
pub const MAX_INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_BYTES_V2: usize =
    INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
        + MAX_INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUTS_V2
            * INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2;
const _: () =
    assert!(MAX_INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_BYTES_V2 < 2 * 1024 * 1024);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalPreviousTransactionChildInputV2 {
    pub version: u8,
    pub previous_transaction: Vec<u8>,
    pub openings: Vec<PreviousTransactionOutputOpeningV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalPreviousTransactionOutputProjectionV2 {
    pub previous_vout: u32,
    pub expected_asset_id: Hash32,
    pub amount: u64,
    pub script_sha256: Hash32,
    pub txout_sha256: Hash32,
    pub txout_witness_sha256: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalPreviousTransactionProjectionV2 {
    pub txid: Hash32,
    pub wtxid: Hash32,
    pub transaction_len: u32,
    pub outputs: Vec<IncrementalPreviousTransactionOutputProjectionV2>,
}

impl IncrementalPreviousTransactionProjectionV2 {
    pub fn encode(&self) -> Result<Vec<u8>, IncrementalPreviousTransactionChildErrorV2> {
        if self.txid == [0; 32]
            || self.wtxid == [0; 32]
            || self.transaction_len == 0
            || usize::try_from(self.transaction_len).unwrap_or(usize::MAX)
                > MAX_ELEMENTS_TRANSACTION_BYTES
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUTS_V2
        {
            return Err(IncrementalPreviousTransactionChildErrorV2::InvalidProjection);
        }
        let mut out = Vec::with_capacity(
            INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
                + self.outputs.len() * INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2,
        );
        out.extend_from_slice(
            &INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.wtxid);
        out.extend_from_slice(&self.transaction_len.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.outputs.len())
                .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?
                .to_be_bytes(),
        );
        let mut previous_vout = None;
        for output in &self.outputs {
            if output.expected_asset_id == [0; 32]
                || output.amount == 0
                || output.script_sha256 == [0; 32]
                || output.txout_sha256 == [0; 32]
                || output.txout_witness_sha256 == [0; 32]
                || previous_vout.is_some_and(|prior| prior >= output.previous_vout)
            {
                return Err(IncrementalPreviousTransactionChildErrorV2::InvalidProjection);
            }
            previous_vout = Some(output.previous_vout);
            out.extend_from_slice(&output.previous_vout.to_be_bytes());
            out.extend_from_slice(&output.expected_asset_id);
            out.extend_from_slice(&output.amount.to_be_bytes());
            out.extend_from_slice(&output.script_sha256);
            out.extend_from_slice(&output.txout_sha256);
            out.extend_from_slice(&output.txout_witness_sha256);
        }
        Ok(out)
    }
}

pub fn decode_incremental_previous_transaction_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalPreviousTransactionProjectionV2, IncrementalPreviousTransactionChildErrorV2>
{
    if bytes.len() < INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
        || bytes[..4] != INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalPreviousTransactionChildErrorV2::InvalidProjection);
    }
    let txid = bytes[4..36]
        .try_into()
        .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?;
    let wtxid = bytes[36..68]
        .try_into()
        .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?;
    let transaction_len = u32::from_be_bytes(
        bytes[68..72]
            .try_into()
            .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?,
    );
    let count =
        usize::try_from(u32::from_be_bytes(bytes[72..76].try_into().map_err(
            |_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection,
        )?))
        .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?;
    let expected_len = INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
        .checked_add(
            count
                .checked_mul(INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2)
                .ok_or(IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?,
        )
        .ok_or(IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?;
    if count == 0
        || count > MAX_INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUTS_V2
        || bytes.len() != expected_len
        || txid == [0; 32]
        || wtxid == [0; 32]
        || transaction_len == 0
        || usize::try_from(transaction_len).unwrap_or(usize::MAX) > MAX_ELEMENTS_TRANSACTION_BYTES
    {
        return Err(IncrementalPreviousTransactionChildErrorV2::InvalidProjection);
    }
    let mut outputs = Vec::with_capacity(count);
    for index in 0..count {
        let start = INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
            + index * INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2;
        let hash = |offset: usize| -> Result<Hash32, IncrementalPreviousTransactionChildErrorV2> {
            bytes[start + offset..start + offset + 32]
                .try_into()
                .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)
        };
        outputs.push(IncrementalPreviousTransactionOutputProjectionV2 {
            previous_vout: u32::from_be_bytes(
                bytes[start..start + 4]
                    .try_into()
                    .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?,
            ),
            expected_asset_id: hash(4)?,
            amount: u64::from_be_bytes(
                bytes[start + 36..start + 44]
                    .try_into()
                    .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InvalidProjection)?,
            ),
            script_sha256: hash(44)?,
            txout_sha256: hash(76)?,
            txout_witness_sha256: hash(108)?,
        });
    }
    let projection = IncrementalPreviousTransactionProjectionV2 {
        txid,
        wtxid,
        transaction_len,
        outputs,
    };
    if projection.encode()? != bytes {
        return Err(IncrementalPreviousTransactionChildErrorV2::InvalidProjection);
    }
    Ok(projection)
}

pub fn execute_incremental_previous_transaction_child_v2(
    input: &IncrementalPreviousTransactionChildInputV2,
) -> Result<Vec<u8>, IncrementalPreviousTransactionChildErrorV2> {
    if input.version != INCREMENTAL_PREVIOUS_TRANSACTION_CHILD_VERSION_V2 {
        return Err(IncrementalPreviousTransactionChildErrorV2::UnsupportedVersion);
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalPreviousTransactionChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_PREVIOUS_TRANSACTION_CHILD_INPUT_BYTES_V2
        || input.openings.len() > MAX_INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUTS_V2
    {
        return Err(IncrementalPreviousTransactionChildErrorV2::InputTooLarge);
    }
    let verified = verify_previous_transaction_output_openings_v2(
        &input.previous_transaction,
        &input.openings,
    )?;
    IncrementalPreviousTransactionProjectionV2 {
        txid: verified.txid,
        wtxid: verified.wtxid,
        transaction_len: verified.transaction_len,
        outputs: verified
            .outputs
            .into_iter()
            .map(|output| IncrementalPreviousTransactionOutputProjectionV2 {
                previous_vout: output.previous_vout,
                expected_asset_id: output.expected_asset_id,
                amount: output.amount,
                script_sha256: output.script_sha256,
                txout_sha256: output.txout_sha256,
                txout_witness_sha256: output.txout_witness_sha256,
            })
            .collect(),
    }
    .encode()
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalPreviousTransactionChildErrorV2 {
    #[error("unsupported predecessor-transaction child version")]
    UnsupportedVersion,
    #[error("predecessor-transaction child input exceeds its cap")]
    InputTooLarge,
    #[error("predecessor-transaction child input encoding failed")]
    InputEncoding,
    #[error("invalid predecessor-transaction projection")]
    InvalidProjection,
    #[error("predecessor transaction rejected: {0}")]
    Settlement(#[from] SettlementError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_codec_is_canonical_variable_and_bounded() {
        let projection = IncrementalPreviousTransactionProjectionV2 {
            txid: [1; 32],
            wtxid: [2; 32],
            transaction_len: 100,
            outputs: vec![IncrementalPreviousTransactionOutputProjectionV2 {
                previous_vout: 3,
                expected_asset_id: [4; 32],
                amount: 5,
                script_sha256: [6; 32],
                txout_sha256: [7; 32],
                txout_witness_sha256: [8; 32],
            }],
        };
        let encoded = projection.encode().unwrap();
        // Producers must reject exactly the invalid headers rejected by the
        // decoder; encoding successfully must not produce an unusable receipt.
        for invalid in [
            IncrementalPreviousTransactionProjectionV2 { txid: [0; 32], ..projection.clone() },
            IncrementalPreviousTransactionProjectionV2 { wtxid: [0; 32], ..projection.clone() },
            IncrementalPreviousTransactionProjectionV2 { transaction_len: 0, ..projection.clone() },
            IncrementalPreviousTransactionProjectionV2 {
                transaction_len: u32::try_from(MAX_ELEMENTS_TRANSACTION_BYTES).unwrap() + 1,
                ..projection.clone()
            },
        ] {
            assert!(invalid.encode().is_err());
        }
        assert_eq!(encoded.len(), 216);
        assert_eq!(
            decode_incremental_previous_transaction_projection_v2(&encoded).unwrap(),
            projection
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_incremental_previous_transaction_projection_v2(&trailing).is_err());
        assert_eq!(
            MAX_INCREMENTAL_PREVIOUS_TRANSACTION_PUBLIC_VALUES_BYTES_V2,
            1_400_076
        );
    }
}
