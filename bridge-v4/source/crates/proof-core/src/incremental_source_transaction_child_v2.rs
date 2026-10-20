//! Per-transaction recursive child for successor bond-inbox source parsing.
//!
//! One source transaction is independently recoverable and proved here. The
//! inbox aggregate child can then carry only this fixed projection plus the
//! encrypted bundle/recovery shares, avoiding a 64-transaction raw-byte
//! witness that can exceed the 16 MiB availability limit.

use bincode::Options;
use ecx_elements_settlement::{verify_successor_bond_inbox_source_transaction_v2, SettlementError};
use ecx_protocol_core::{
    BondInboxCustodyReceiptV2, FrozenConfigurationV2, Hash32, SuccessorBondInboxEntryV2,
    MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const INCREMENTAL_SOURCE_TRANSACTION_CHILD_VERSION_V2: u8 = 2;
pub const INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 2;
pub const INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (11 * 32) + (3 * 4) + 1;
pub const MAX_INCREMENTAL_SOURCE_TRANSACTION_CHILD_INPUT_BYTES_V2: usize = 1024 * 1024;
/// One exact source transaction, one duplicate encrypted bundle used by the
/// recovery verifier, five fixed custody wrappers, configuration/entry, and
/// conservative fixed framing remain below one MiB.
pub const INCREMENTAL_SOURCE_TRANSACTION_CHILD_REACHABLE_CEILING_V2: usize =
    MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2 as usize
        + MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        + (64 * 1024);
const _: () = assert!(
    INCREMENTAL_SOURCE_TRANSACTION_CHILD_REACHABLE_CEILING_V2
        < MAX_INCREMENTAL_SOURCE_TRANSACTION_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSourceTransactionChildInputV2 {
    pub version: u8,
    pub configuration: FrozenConfigurationV2,
    pub entry: SuccessorBondInboxEntryV2,
    pub source_transaction: Vec<u8>,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub custody_receipts: Vec<BondInboxCustodyReceiptV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSourceTransactionChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub entry_hash: Hash32,
    pub txid: Hash32,
    pub wtxid: Hash32,
    pub exact_witness_sha256: Hash32,
    pub availability_bundle_root: Hash32,
    pub availability_receipt_root: Hash32,
    pub staging_txout_sha256: Hash32,
    pub staging_txout_witness_sha256: Hash32,
    pub staging_script_sha256: Hash32,
    pub source_transaction_len: u32,
    pub availability_bundle_len: u32,
    pub staging_vout: u32,
    pub staging_present: bool,
}

impl IncrementalSourceTransactionChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for value in [
            self.configuration_hash,
            self.chain_id,
            self.entry_hash,
            self.txid,
            self.wtxid,
            self.exact_witness_sha256,
            self.availability_bundle_root,
            self.availability_receipt_root,
            self.staging_txout_sha256,
            self.staging_txout_witness_sha256,
            self.staging_script_sha256,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.source_transaction_len.to_be_bytes());
        out.extend_from_slice(&self.availability_bundle_len.to_be_bytes());
        out.extend_from_slice(&self.staging_vout.to_be_bytes());
        out.push(u8::from(self.staging_present));
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSourceTransactionChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub chain_id: Hash32,
    pub entry_hash: Hash32,
    pub txid: Hash32,
    pub wtxid: Hash32,
    pub exact_witness_sha256: Hash32,
    pub availability_bundle_root: Hash32,
    pub availability_receipt_root: Hash32,
    pub staging_txout_sha256: Hash32,
    pub staging_txout_witness_sha256: Hash32,
    pub staging_script_sha256: Hash32,
    pub source_transaction_len: u32,
    pub availability_bundle_len: u32,
    pub staging_vout: u32,
    pub staging_present: bool,
}

pub fn decode_incremental_source_transaction_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalSourceTransactionChildProjectionV2, IncrementalSourceTransactionChildErrorV2>
{
    if bytes.len() != INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalSourceTransactionChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalSourceTransactionChildErrorV2> {
        let start = 4 + (index * 32);
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalSourceTransactionChildErrorV2::UnsupportedVersion)
    };
    let number = |index: usize| -> Result<u32, IncrementalSourceTransactionChildErrorV2> {
        let start = 4 + (11 * 32) + (index * 4);
        Ok(u32::from_be_bytes(
            bytes[start..start + 4]
                .try_into()
                .map_err(|_| IncrementalSourceTransactionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let staging_present = match bytes[bytes.len() - 1] {
        0 => false,
        1 => true,
        _ => return Err(IncrementalSourceTransactionChildErrorV2::InvalidProjection),
    };
    let projection = IncrementalSourceTransactionChildProjectionV2 {
        configuration_hash: hash(0)?,
        chain_id: hash(1)?,
        entry_hash: hash(2)?,
        txid: hash(3)?,
        wtxid: hash(4)?,
        exact_witness_sha256: hash(5)?,
        availability_bundle_root: hash(6)?,
        availability_receipt_root: hash(7)?,
        staging_txout_sha256: hash(8)?,
        staging_txout_witness_sha256: hash(9)?,
        staging_script_sha256: hash(10)?,
        source_transaction_len: number(0)?,
        availability_bundle_len: number(1)?,
        staging_vout: number(2)?,
        staging_present,
    };
    if projection.staging_present
        != (projection.staging_vout != u32::MAX
            && projection.staging_txout_sha256 != [0; 32]
            && projection.staging_txout_witness_sha256 != [0; 32]
            && projection.staging_script_sha256 != [0; 32])
        || (!projection.staging_present
            && (projection.staging_vout != u32::MAX
                || projection.staging_txout_sha256 != [0; 32]
                || projection.staging_txout_witness_sha256 != [0; 32]
                || projection.staging_script_sha256 != [0; 32]))
    {
        return Err(IncrementalSourceTransactionChildErrorV2::InvalidProjection);
    }
    Ok(projection)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalSourceTransactionChildErrorV2 {
    #[error("unsupported incremental source-transaction child version")]
    UnsupportedVersion,
    #[error("incremental source-transaction child input exceeds its recovery cap")]
    InputTooLarge,
    #[error("incremental source-transaction child input encoding failed")]
    InputEncoding,
    #[error("invalid incremental source-transaction projection")]
    InvalidProjection,
    #[error("source transaction rejected: {0}")]
    Settlement(#[from] SettlementError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_staging_source_projection_root_v2(
    public_values: &[Vec<u8>],
) -> Result<Hash32, IncrementalSourceTransactionChildErrorV2> {
    let mut bytes = Vec::with_capacity(4 + public_values.len() * (32 + 32));
    bytes.extend_from_slice(
        &u32::try_from(public_values.len())
            .map_err(|_| IncrementalSourceTransactionChildErrorV2::InvalidProjection)?
            .to_be_bytes(),
    );
    let mut previous_wtxid = None;
    for values in public_values {
        let projection = decode_incremental_source_transaction_child_projection_v2(values)?;
        if !projection.staging_present
            || previous_wtxid.is_some_and(|prior| prior >= projection.wtxid)
        {
            return Err(IncrementalSourceTransactionChildErrorV2::InvalidProjection);
        }
        previous_wtxid = Some(projection.wtxid);
        bytes.extend_from_slice(&projection.wtxid);
        bytes.extend_from_slice(&Sha256::digest(values));
    }
    Ok(tagged_hash(
        b"ECX/incremental-staging-source-projection-root/v2-u128-inbox",
        &bytes,
    ))
}

pub fn execute_incremental_source_transaction_child_v2(
    input: &IncrementalSourceTransactionChildInputV2,
) -> Result<IncrementalSourceTransactionChildPublicValuesV2, IncrementalSourceTransactionChildErrorV2>
{
    if input.version != INCREMENTAL_SOURCE_TRANSACTION_CHILD_VERSION_V2 {
        return Err(IncrementalSourceTransactionChildErrorV2::UnsupportedVersion);
    }
    input
        .configuration
        .validate()
        .map_err(SettlementError::Protocol)?;
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalSourceTransactionChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_SOURCE_TRANSACTION_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalSourceTransactionChildErrorV2::InputTooLarge);
    }
    let verified = verify_successor_bond_inbox_source_transaction_v2(
        &input.entry,
        &input.source_transaction,
        &input.canonical_encrypted_bundle,
        &input.custody_receipts,
        &input.configuration,
    )?;
    let staging_present = verified.staging_vout.is_some();
    let values = IncrementalSourceTransactionChildPublicValuesV2 {
        configuration_hash: input.configuration.digest(),
        chain_id: input.configuration.base.chain_id,
        entry_hash: input.entry.entry_hash(),
        txid: verified.txid,
        wtxid: verified.wtxid,
        exact_witness_sha256: verified.exact_witness_sha256,
        availability_bundle_root: input.entry.marker.availability_bundle_root,
        availability_receipt_root: input.entry.marker.availability_receipt_root,
        staging_txout_sha256: verified.staging_txout_sha256.unwrap_or([0; 32]),
        staging_txout_witness_sha256: verified.staging_txout_witness_sha256.unwrap_or([0; 32]),
        staging_script_sha256: verified.staging_script_sha256.unwrap_or([0; 32]),
        source_transaction_len: input.entry.source_transaction_len,
        availability_bundle_len: input.entry.marker.availability_bundle_len,
        staging_vout: verified.staging_vout.unwrap_or(u32::MAX),
        staging_present,
    };
    decode_incremental_source_transaction_child_projection_v2(&values.encode())?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_transaction_projection_is_fixed_and_canonical() {
        let values = IncrementalSourceTransactionChildPublicValuesV2 {
            configuration_hash: [1; 32],
            chain_id: [2; 32],
            entry_hash: [3; 32],
            txid: [4; 32],
            wtxid: [5; 32],
            exact_witness_sha256: [6; 32],
            availability_bundle_root: [7; 32],
            availability_receipt_root: [8; 32],
            staging_txout_sha256: [9; 32],
            staging_txout_witness_sha256: [10; 32],
            staging_script_sha256: [11; 32],
            source_transaction_len: 11,
            availability_bundle_len: 12,
            staging_vout: 13,
            staging_present: true,
        };
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let decoded = decode_incremental_source_transaction_child_projection_v2(&encoded).unwrap();
        assert_eq!(decoded.entry_hash, [3; 32]);
        assert_eq!(decoded.staging_vout, 13);

        let mut noncanonical = encoded;
        *noncanonical.last_mut().unwrap() = 2;
        assert!(decode_incremental_source_transaction_child_projection_v2(&noncanonical).is_err());
    }

    #[test]
    fn one_source_transaction_is_recoverable_below_one_mib() {
        assert_eq!(
            INCREMENTAL_SOURCE_TRANSACTION_CHILD_REACHABLE_CEILING_V2,
            917_504
        );
        assert_eq!(
            MAX_INCREMENTAL_SOURCE_TRANSACTION_CHILD_INPUT_BYTES_V2,
            1_048_576
        );
    }
}
