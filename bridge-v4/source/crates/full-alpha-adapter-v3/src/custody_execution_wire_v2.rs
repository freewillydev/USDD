//! Bounded candidate input transport, not authentication of its policy.
//! A proving wrapper must independently constrain the supplied policy and
//! authenticate canonical parent membership before authorizing redemption.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{AlphaRecursiveReceiptBindingV3,
    child_execution_guest_v3::AlphaChildExecutionInputV3,
    custody_execution_v2::CustodyExecutionPolicyV2,
    custody_history_wire_v2::{CustodyHistoryWitnessV2,encode_custody_history_v2}};

pub const CUSTODY_EXECUTION_WIRE_VERSION_V2:u8 = 0xb3;
pub const MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2:usize = 256 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionWitnessV2 {
    pub version:u8,
    pub policy:CustodyExecutionPolicyV2,
    pub child:AlphaChildExecutionInputV3,
    pub history:CustodyHistoryWitnessV2,
    pub lineage_receipts:Vec<AlphaRecursiveReceiptBindingV3>,
    pub transaction_index:u32,
    pub output_index:u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CustodyExecutionWireErrorV2;

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 as u64).reject_trailing_bytes()
}
pub fn encode_custody_execution_v2(input:&CustodyExecutionWitnessV2)
    -> Result<Vec<u8>,CustodyExecutionWireErrorV2> {
    if input.version != CUSTODY_EXECUTION_WIRE_VERSION_V2 || input.lineage_receipts.len() > 8192
        || input.policy.commitment().is_err()
        || input.lineage_receipts.iter().any(|r| r.public_values.len()!=407
            || r.proof_marker.is_empty() || r.proof_marker.len()>crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3)
        || encode_custody_history_v2(&input.history).is_err() {
        return Err(CustodyExecutionWireErrorV2);
    }
    let bytes=options().serialize(input).map_err(|_|CustodyExecutionWireErrorV2)?;
    if bytes.len()>MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 {return Err(CustodyExecutionWireErrorV2);}
    Ok(bytes)
}
pub fn decode_custody_execution_v2(bytes:&[u8])
    -> Result<CustodyExecutionWitnessV2,CustodyExecutionWireErrorV2> {
    if bytes.is_empty() || bytes.len()>MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 {
        return Err(CustodyExecutionWireErrorV2);
    }
    let input=options().deserialize(bytes).map_err(|_|CustodyExecutionWireErrorV2)?;
    if encode_custody_execution_v2(&input)? != bytes {return Err(CustodyExecutionWireErrorV2);}
    Ok(input)
}

/// Distinct transport for the V5 checkpoint and per-block evaluator bindings.
/// The outer envelope uses big-endian fixed integers, including nested fields;
/// it is not a concatenation of the standalone child's little-endian codec.
pub const CUSTODY_EXECUTION_WIRE_VERSION_V5: u8 = 0xb5;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionWitnessV5 {
    pub version: u8,
    pub policy: crate::custody_execution_v2::CustodyExecutionPolicyV5,
    pub child: crate::child_execution_guest_v4::AlphaChildExecutionInputV5,
    pub history: CustodyHistoryWitnessV2,
    pub lineage_receipts: Vec<crate::custody_child_lineage_v2::CustodyChildLineageReceiptV5>,
    pub transaction_index: u32,
    pub output_index: u32,
}

pub fn encode_custody_execution_v5(input: &CustodyExecutionWitnessV5)
    -> Result<Vec<u8>, CustodyExecutionWireErrorV2> {
    use crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5;
    if input.version != CUSTODY_EXECUTION_WIRE_VERSION_V5
        || input.lineage_receipts.len() > 8192
        || input.policy.commitment().is_err()
        || crate::child_execution_guest_v4::encode_alpha_child_execution_input_v5(&input.child).is_err()
        || encode_custody_history_v2(&input.history).is_err()
        || input.lineage_receipts.iter().any(|r| r.environment == [0;32]
            || AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&r.receipt.public_values).is_err()
            || r.receipt.proof_marker.is_empty()
            || r.receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3) {
        return Err(CustodyExecutionWireErrorV2);
    }
    let bytes = options().serialize(input).map_err(|_| CustodyExecutionWireErrorV2)?;
    if bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    Ok(bytes)
}

pub fn decode_custody_execution_v5(bytes: &[u8])
    -> Result<CustodyExecutionWitnessV5, CustodyExecutionWireErrorV2> {
    if bytes.first() != Some(&CUSTODY_EXECUTION_WIRE_VERSION_V5)
        || bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 {
        return Err(CustodyExecutionWireErrorV2);
    }
    let input = options().deserialize(bytes).map_err(|_| CustodyExecutionWireErrorV2)?;
    if encode_custody_execution_v5(&input)? != bytes { return Err(CustodyExecutionWireErrorV2); }
    Ok(input)
}


/// Distinct transport for the owned accounting checkpoint and per-block evaluator bindings.
/// The outer envelope uses big-endian fixed integers, including nested fields;
/// it is not a concatenation of the standalone child's little-endian codec.
pub const CUSTODY_ACCOUNTING_WIRE_VERSION_V4: u8 = 0xb6;

pub const CUSTODY_ACCOUNTING_WIRE_VERSION_V6: u8 = 0xb7;
pub const CUSTODY_ACCOUNTING_WIRE_VERSION_V7: u8 = 0xb8;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingWitnessV7 {
    pub version: u8,
    pub policy: crate::custody_execution_v2::CustodyAccountingExecutionPolicyV7,
    pub child: crate::child_custody_guest_v7::CustodyExecutionInputV7,
    pub history: CustodyHistoryWitnessV2,
    pub lineage_receipts: Vec<crate::custody_child_lineage_v2::CustodyAccountingLineageReceiptV6>,
    pub transaction_index: u32,
    pub output_index: u32,
}
pub fn encode_custody_accounting_v7(input: &CustodyAccountingWitnessV7)
    -> Result<Vec<u8>, CustodyExecutionWireErrorV2> {
    if input.version != CUSTODY_ACCOUNTING_WIRE_VERSION_V7
        || input.lineage_receipts.len() > 8192 || input.policy.commitment().is_err()
        || crate::child_custody_guest_v7::encode_custody_execution_input_v7(&input.child).is_err()
        || encode_custody_history_v2(&input.history).is_err()
        || input.lineage_receipts.iter().any(|r| [r.environment,r.projection_predecessor].contains(&[0;32])
            || crate::child_custody_guest_v7::CustodyExecutionPublicValuesV7::from_canonical_bytes(
                &r.receipt.public_values).is_err()
            || r.receipt.proof_marker.is_empty()
            || r.receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3) {
        return Err(CustodyExecutionWireErrorV2);
    }
    let bytes = options().serialize(input).map_err(|_| CustodyExecutionWireErrorV2)?;
    if bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    Ok(bytes)
}
pub fn decode_custody_accounting_v7(bytes: &[u8])
    -> Result<CustodyAccountingWitnessV7, CustodyExecutionWireErrorV2> {
    if bytes.first() != Some(&CUSTODY_ACCOUNTING_WIRE_VERSION_V7)
        || bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    let input = options().deserialize(bytes).map_err(|_| CustodyExecutionWireErrorV2)?;
    if encode_custody_accounting_v7(&input)? != bytes { return Err(CustodyExecutionWireErrorV2); }
    Ok(input)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingWitnessV6 {
    pub version: u8,
    pub policy: crate::custody_execution_v2::CustodyAccountingExecutionPolicyV6,
    pub child: crate::child_custody_guest_v6::CustodyExecutionInputV6,
    pub history: CustodyHistoryWitnessV2,
    pub lineage_receipts: Vec<crate::custody_child_lineage_v2::CustodyAccountingLineageReceiptV6>,
    pub transaction_index: u32,
    pub output_index: u32,
}
pub fn encode_custody_accounting_v6(input: &CustodyAccountingWitnessV6)
    -> Result<Vec<u8>, CustodyExecutionWireErrorV2> {
    if input.version != CUSTODY_ACCOUNTING_WIRE_VERSION_V6
        || input.lineage_receipts.len() > 8192 || input.policy.commitment().is_err()
        || crate::child_custody_guest_v6::encode_custody_execution_input_v6(&input.child).is_err()
        || encode_custody_history_v2(&input.history).is_err()
        || input.lineage_receipts.iter().any(|r| [r.environment,r.projection_predecessor].contains(&[0;32])
            || crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6::from_canonical_bytes(
                &r.receipt.public_values).is_err()
            || r.receipt.proof_marker.is_empty()
            || r.receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3) {
        return Err(CustodyExecutionWireErrorV2);
    }
    let bytes = options().serialize(input).map_err(|_| CustodyExecutionWireErrorV2)?;
    if bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    Ok(bytes)
}
pub fn decode_custody_accounting_v6(bytes: &[u8])
    -> Result<CustodyAccountingWitnessV6, CustodyExecutionWireErrorV2> {
    if bytes.first() != Some(&CUSTODY_ACCOUNTING_WIRE_VERSION_V6)
        || bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    let input = options().deserialize(bytes).map_err(|_| CustodyExecutionWireErrorV2)?;
    if encode_custody_accounting_v6(&input)? != bytes { return Err(CustodyExecutionWireErrorV2); }
    Ok(input)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingWitnessV4 {
    pub version: u8,
    pub policy: crate::custody_execution_v2::CustodyAccountingExecutionPolicyV4,
    pub child: crate::child_custody_guest_v4::CustodyExecutionInputV4,
    pub history: CustodyHistoryWitnessV2,
    pub lineage_receipts: Vec<crate::custody_child_lineage_v2::CustodyChildLineageReceiptV5>,
    pub transaction_index: u32,
    pub output_index: u32,
}

pub fn encode_custody_accounting_v4(input: &CustodyAccountingWitnessV4)
    -> Result<Vec<u8>, CustodyExecutionWireErrorV2> {
    use crate::child_custody_guest_v4::CustodyExecutionPublicValuesV4;
    if input.version != CUSTODY_ACCOUNTING_WIRE_VERSION_V4
        || input.lineage_receipts.len() > 8192
        || input.policy.commitment().is_err()
        || crate::child_custody_guest_v4::encode_custody_execution_input_v4(&input.child).is_err()
        || encode_custody_history_v2(&input.history).is_err()
        || input.lineage_receipts.iter().any(|r| r.environment == [0;32]
            || CustodyExecutionPublicValuesV4::from_canonical_bytes(&r.receipt.public_values).is_err()
            || r.receipt.proof_marker.is_empty()
            || r.receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3) {
        return Err(CustodyExecutionWireErrorV2);
    }
    let bytes = options().serialize(input).map_err(|_| CustodyExecutionWireErrorV2)?;
    if bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 { return Err(CustodyExecutionWireErrorV2); }
    Ok(bytes)
}

pub fn decode_custody_accounting_v4(bytes: &[u8])
    -> Result<CustodyAccountingWitnessV4, CustodyExecutionWireErrorV2> {
    if bytes.first() != Some(&CUSTODY_ACCOUNTING_WIRE_VERSION_V4)
        || bytes.len() > MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2 {
        return Err(CustodyExecutionWireErrorV2);
    }
    let input = options().deserialize(bytes).map_err(|_| CustodyExecutionWireErrorV2)?;
    if encode_custody_accounting_v4(&input)? != bytes { return Err(CustodyExecutionWireErrorV2); }
    Ok(input)
}

#[cfg(test)]
mod v5_tests {
    use super::*;
    #[test]
    fn rejects_empty_legacy_and_truncated_envelopes() {
        for bytes in [&[][..], &[CUSTODY_EXECUTION_WIRE_VERSION_V2][..],
            &[CUSTODY_EXECUTION_WIRE_VERSION_V5][..], &[0xb5, 0xff, 0xff][..]] {
            assert!(decode_custody_execution_v5(bytes).is_err());
        }
    }
}
