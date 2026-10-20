//! Recursive child authenticating one Elements deposit source transaction.
//!
//! The account-action child consumes only this fixed projection. Keeping the
//! raw transaction in its own recoverable child prevents 64 individually valid
//! deposit transactions from overflowing the parent's 16 MiB envelope.

use bincode::Options;
use ecx_elements_settlement::{
    verify_confidential_deposit, ConfidentialDepositOpeningV1, SettlementError,
    MAX_ELEMENTS_TRANSACTION_BYTES,
};
use ecx_protocol_core::{DepositEventV1, Hash32};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INCREMENTAL_DEPOSIT_SOURCE_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (8 * 32) + 4 + (4 * 8);
pub const MAX_INCREMENTAL_DEPOSIT_SOURCE_CHILD_INPUT_BYTES_V2: usize =
    MAX_ELEMENTS_TRANSACTION_BYTES + 2 * 1024;
pub const INCREMENTAL_DEPOSIT_SOURCE_CHILD_REACHABLE_CEILING_V2: usize =
    MAX_ELEMENTS_TRANSACTION_BYTES + 1_024;
const _: () = assert!(
    INCREMENTAL_DEPOSIT_SOURCE_CHILD_REACHABLE_CEILING_V2
        < MAX_INCREMENTAL_DEPOSIT_SOURCE_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalDepositSourceChildInputV2 {
    pub version: u8,
    pub event: DepositEventV1,
    pub opening: ConfidentialDepositOpeningV1,
    pub expected_usdd_asset_id: Hash32,
    pub expected_vault_script_sha256: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalDepositSourceChildPublicValuesV2 {
    pub chain_id: Hash32,
    pub event_hash: Hash32,
    pub request_id: Hash32,
    pub source_txid: Hash32,
    pub output_sha256: Hash32,
    pub trader: Hash32,
    pub usdd_asset_id: Hash32,
    pub vault_script_sha256: Hash32,
    pub deposit_vout: u32,
    pub amount: u64,
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub event_index: u64,
}

impl IncrementalDepositSourceChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for hash in [
            self.chain_id,
            self.event_hash,
            self.request_id,
            self.source_txid,
            self.output_sha256,
            self.trader,
            self.usdd_asset_id,
            self.vault_script_sha256,
        ] {
            out.extend_from_slice(&hash);
        }
        out.extend_from_slice(&self.deposit_vout.to_be_bytes());
        for value in [
            self.amount,
            self.observed_sidechain_height,
            self.observed_parent_height,
            self.event_index,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

pub type IncrementalDepositSourceProjectionV2 = IncrementalDepositSourceChildPublicValuesV2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalDepositSourceChildErrorV2 {
    #[error("unsupported incremental deposit-source child version")]
    UnsupportedVersion,
    #[error("incremental deposit-source input exceeds its recoverable cap")]
    InputTooLarge,
    #[error("incremental deposit-source input encoding failed")]
    InputEncoding,
    #[error("confidential deposit rejected: {0}")]
    Deposit(#[from] SettlementError),
}

pub fn decode_incremental_deposit_source_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalDepositSourceProjectionV2, IncrementalDepositSourceChildErrorV2> {
    if bytes.len() != INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalDepositSourceChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalDepositSourceChildErrorV2> {
        let start = 4 + index * 32;
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalDepositSourceChildErrorV2::UnsupportedVersion)
    };
    let u64_at = |index: usize| -> Result<u64, IncrementalDepositSourceChildErrorV2> {
        let start = 4 + 8 * 32 + 4 + index * 8;
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalDepositSourceChildErrorV2::UnsupportedVersion)?,
        ))
    };
    Ok(IncrementalDepositSourceProjectionV2 {
        chain_id: hash(0)?,
        event_hash: hash(1)?,
        request_id: hash(2)?,
        source_txid: hash(3)?,
        output_sha256: hash(4)?,
        trader: hash(5)?,
        usdd_asset_id: hash(6)?,
        vault_script_sha256: hash(7)?,
        deposit_vout: u32::from_be_bytes(
            bytes[4 + 8 * 32..4 + 8 * 32 + 4]
                .try_into()
                .map_err(|_| IncrementalDepositSourceChildErrorV2::UnsupportedVersion)?,
        ),
        amount: u64_at(0)?,
        observed_sidechain_height: u64_at(1)?,
        observed_parent_height: u64_at(2)?,
        event_index: u64_at(3)?,
    })
}

pub fn execute_incremental_deposit_source_child_v2(
    input: &IncrementalDepositSourceChildInputV2,
) -> Result<IncrementalDepositSourceChildPublicValuesV2, IncrementalDepositSourceChildErrorV2> {
    if input.version != INCREMENTAL_DEPOSIT_SOURCE_CHILD_VERSION_V2 {
        return Err(IncrementalDepositSourceChildErrorV2::UnsupportedVersion);
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalDepositSourceChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_DEPOSIT_SOURCE_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalDepositSourceChildErrorV2::InputTooLarge);
    }
    let request = verify_confidential_deposit(
        &input.event,
        &input.opening,
        input.expected_usdd_asset_id,
        input.expected_vault_script_sha256,
    )?;
    Ok(IncrementalDepositSourceChildPublicValuesV2 {
        chain_id: request.chain_id,
        event_hash: input.event.event_hash(),
        request_id: request.request_id(),
        source_txid: request.deposit_txid,
        output_sha256: input.event.output_sha256,
        trader: request.trader.0,
        usdd_asset_id: request.usdd_asset_id,
        vault_script_sha256: input.expected_vault_script_sha256,
        deposit_vout: request.deposit_vout,
        amount: request.amount,
        observed_sidechain_height: request.observed_height,
        observed_parent_height: input.event.observed_parent_height,
        event_index: input.event.index,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{DepositInboxStateV1, DepositMarkerV1, XOnlyKey};
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::encode;
    use elements::hashes::Hash;
    use elements::opcodes;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{AssetId, LockTime, Script, Transaction, TxOut, TxOutSecrets};
    use rand::thread_rng;
    use sha2::{Digest, Sha256};

    use super::*;

    const TRADER: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[test]
    fn deposit_source_projection_codec_is_exact_and_bounded() {
        let values = IncrementalDepositSourceChildPublicValuesV2 {
            chain_id: [1; 32],
            event_hash: [2; 32],
            request_id: [3; 32],
            source_txid: [4; 32],
            output_sha256: [5; 32],
            trader: [6; 32],
            usdd_asset_id: [7; 32],
            vault_script_sha256: [8; 32],
            deposit_vout: 9,
            amount: 10,
            observed_sidechain_height: 11,
            observed_parent_height: 12,
            event_index: 13,
        };
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_DEPOSIT_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        );
        assert_eq!(
            decode_incremental_deposit_source_projection_v2(&encoded).unwrap(),
            values
        );
        assert!(
            decode_incremental_deposit_source_projection_v2(&encoded[..encoded.len() - 1]).is_err()
        );
        assert_eq!(
            INCREMENTAL_DEPOSIT_SOURCE_CHILD_REACHABLE_CEILING_V2,
            401_024
        );
    }

    #[test]
    fn confidential_source_executes_and_opening_mutation_rejects() {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let chain_id = [1; 32];
        let trader = XOnlyKey(TRADER);
        let asset_id = AssetId::from_byte_array([3; 32]);
        let vault_script = Script::from(vec![0x51, 0x20, 7, 7, 7, 7]);
        let abf = AssetBlindingFactor::from_slice(&[4; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[5; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            vault_script.clone(),
            receiver_public,
            ephemeral_secret,
            TxOutSecrets::new(asset_id, abf, 100, vbf),
            &[TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::zero(),
                100,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap();
        let marker = DepositMarkerV1 {
            chain_id,
            deposit_vout: 0,
            trader,
        };
        let payload = marker.payload_bytes().unwrap();
        let mut marker_bytes = vec![opcodes::all::OP_RETURN.into_u8(), payload.len() as u8];
        marker_bytes.extend_from_slice(&payload);
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                output.clone(),
                TxOut {
                    asset: Asset::Explicit(AssetId::from_byte_array([9; 32])),
                    value: Value::Explicit(0),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(marker_bytes),
                    witness: Default::default(),
                },
            ],
        };
        let inbox = DepositInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let event = DepositEventV1 {
            version: 1,
            chain_id,
            index: 0,
            previous_root: inbox.head_root,
            observed_sidechain_height: 10,
            observed_parent_height: 100,
            source_txid: transaction.txid().to_byte_array(),
            deposit_vout: 0,
            marker_vout: 1,
            output_sha256: ecx_elements_settlement::output_sha256(&output),
            trader,
        };
        let input = IncrementalDepositSourceChildInputV2 {
            version: INCREMENTAL_DEPOSIT_SOURCE_CHILD_VERSION_V2,
            event,
            opening: ConfidentialDepositOpeningV1 {
                version: 1,
                transaction: encode::serialize(&transaction),
                amount: 100,
                asset_blinding_factor: [4; 32],
                value_blinding_factor: [5; 32],
            },
            expected_usdd_asset_id: asset_id.into_inner().to_byte_array(),
            expected_vault_script_sha256: Sha256::digest(vault_script.as_bytes()).into(),
        };
        let values = execute_incremental_deposit_source_child_v2(&input).unwrap();
        assert_eq!(values.amount, 100);
        assert_eq!(values.trader, TRADER);

        let mut wrong_opening = input;
        wrong_opening.opening.amount = 101;
        assert!(execute_incremental_deposit_source_child_v2(&wrong_opening).is_err());
    }
}
