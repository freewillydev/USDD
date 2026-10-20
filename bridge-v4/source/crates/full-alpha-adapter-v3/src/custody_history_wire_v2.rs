//! Owned, canonical transport for the parent history following a custody burn.
//! This is witness data, not a source of deployment or finality-policy defaults.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3;

// New wire version: old proofs cannot silently acquire early-exit semantics.
pub const CUSTODY_HISTORY_VERSION_V2: u8 = 0xb3;
pub const MAX_CUSTODY_HISTORY_BYTES_V2: usize = 128 * 1024 * 1024;
pub const MAX_CUSTODY_HISTORY_STEPS_V2: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyHistoryWitnessV2 {
    pub version: u8,
    pub steps: Vec<AlphaConversionParentLinkInputV3>,
    pub approval_index: u32,
    pub approval_transaction: bitcoin::Txid,
    /// Blinded bundle preimage for six-ack Ethereum approval. None retains
    /// the stronger, actually mined M6 path for historical witnesses.
    pub approval_bundle: Option<crate::conversion_parent_link_v3::CustodyAckBundleV3>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CustodyHistoryWireErrorV2;

impl CustodyHistoryWitnessV2 {
    fn check_shape(&self) -> Result<(), CustodyHistoryWireErrorV2> {
        use bitcoin::hashes::Hash;
        if self.version != CUSTODY_HISTORY_VERSION_V2
            || self.steps.len() > MAX_CUSTODY_HISTORY_STEPS_V2
            || self.approval_index as usize >= self.steps.len()
            || self.approval_transaction == bitcoin::Txid::all_zeros() {
            return Err(CustodyHistoryWireErrorV2);
        }
        if self.approval_bundle.as_ref().is_some_and(|bundle|
            bundle.compute_txid() != self.approval_transaction) {
            return Err(CustodyHistoryWireErrorV2);
        }
        Ok(())
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_CUSTODY_HISTORY_BYTES_V2 as u64).reject_trailing_bytes()
}

pub fn encode_custody_history_v2(input: &CustodyHistoryWitnessV2)
    -> Result<Vec<u8>, CustodyHistoryWireErrorV2> {
    input.check_shape()?;
    let bytes = options().serialize(input).map_err(|_|CustodyHistoryWireErrorV2)?;
    if bytes.len() > MAX_CUSTODY_HISTORY_BYTES_V2 { return Err(CustodyHistoryWireErrorV2); }
    Ok(bytes)
}

pub fn decode_custody_history_v2(bytes: &[u8])
    -> Result<CustodyHistoryWitnessV2, CustodyHistoryWireErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_CUSTODY_HISTORY_BYTES_V2 {
        return Err(CustodyHistoryWireErrorV2);
    }
    let input: CustodyHistoryWitnessV2 = options().deserialize(bytes)
        .map_err(|_|CustodyHistoryWireErrorV2)?;
    if encode_custody_history_v2(&input)? != bytes { return Err(CustodyHistoryWireErrorV2); }
    Ok(input)
}
