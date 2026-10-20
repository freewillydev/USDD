//! Recursive child statement for deposit and withdrawal nullifier trees.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    verify_sparse_nullifier_updates_v2, Hash32, IncrementalSuccessorConfigurationV2,
    NullifierKindV2, ProtocolError, SparseNullifierRootV2, SparseNullifierUpdateV2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const INCREMENTAL_NULLIFIER_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 2;
pub const INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (9 * 32) + 4;
pub const MAX_INCREMENTAL_NULLIFIER_CHILD_INPUT_BYTES_V2: usize = 2 * 1024 * 1024;
/// Exact fixed-int bincode length with both nullifier classes simultaneously
/// carrying the frozen maximum of 64 complete depth-256 paths.
pub const INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2: usize = 1_579_457;
const _: () = assert!(
    INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_NULLIFIER_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalNullifierChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSuccessorConfigurationV2,
    pub previous_deposit_root: SparseNullifierRootV2,
    pub next_deposit_root: SparseNullifierRootV2,
    pub previous_withdrawal_root: SparseNullifierRootV2,
    pub next_withdrawal_root: SparseNullifierRootV2,
    pub deposit_updates: Vec<SparseNullifierUpdateV2>,
    pub withdrawal_updates: Vec<SparseNullifierUpdateV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalNullifierChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub previous_deposit_root_projection: Hash32,
    pub next_deposit_root_projection: Hash32,
    pub previous_withdrawal_root_projection: Hash32,
    pub next_withdrawal_root_projection: Hash32,
    pub deposit_update_transcript_root: Hash32,
    pub withdrawal_update_transcript_root: Hash32,
    pub deposit_nullifier_key_root: Hash32,
    pub withdrawal_nullifier_key_root: Hash32,
    pub deposit_update_count: u16,
    pub withdrawal_update_count: u16,
}

impl IncrementalNullifierChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.previous_deposit_root_projection,
            self.next_deposit_root_projection,
            self.previous_withdrawal_root_projection,
            self.next_withdrawal_root_projection,
            self.deposit_update_transcript_root,
            self.withdrawal_update_transcript_root,
            self.deposit_nullifier_key_root,
            self.withdrawal_nullifier_key_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.deposit_update_count.to_be_bytes());
        out.extend_from_slice(&self.withdrawal_update_count.to_be_bytes());
        debug_assert_eq!(out.len(), INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalNullifierChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub previous_deposit_root_projection: Hash32,
    pub next_deposit_root_projection: Hash32,
    pub previous_withdrawal_root_projection: Hash32,
    pub next_withdrawal_root_projection: Hash32,
    pub deposit_nullifier_key_root: Hash32,
    pub withdrawal_nullifier_key_root: Hash32,
    pub deposit_update_count: u16,
    pub withdrawal_update_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalNullifierChildErrorV2 {
    #[error("unsupported incremental nullifier child version")]
    UnsupportedVersion,
    #[error("incremental nullifier child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental nullifier child input encoding failed")]
    InputEncoding,
    #[error("incremental nullifier transition rejected: {0}")]
    Transition(#[from] ProtocolError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_nullifier_root_projection_v2(root: SparseNullifierRootV2) -> Hash32 {
    tagged_hash(
        b"ECX/incremental-nullifier-root-projection/v1",
        &root.canonical_bytes(),
    )
}

fn update_root(tag: &[u8], updates: &[SparseNullifierUpdateV2]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u16::try_from(updates.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for update in updates {
        update.encode_to(&mut bytes);
    }
    tagged_hash(tag, &bytes)
}

pub fn incremental_nullifier_key_root_v2(
    kind: NullifierKindV2,
    keys: impl IntoIterator<Item = Hash32>,
) -> Result<Hash32, ProtocolError> {
    let keys = keys.into_iter().collect::<Vec<_>>();
    let mut bytes = Vec::with_capacity(3 + keys.len() * 32);
    bytes.push(kind.code());
    bytes.extend_from_slice(
        &u16::try_from(keys.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    let mut seen = std::collections::BTreeSet::new();
    for key in keys {
        if key == [0; 32] || !seen.insert(key) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        bytes.extend_from_slice(&key);
    }
    Ok(tagged_hash(b"ECX/incremental-nullifier-keys/v1", &bytes))
}

pub fn decode_incremental_nullifier_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalNullifierChildProjectionV2, IncrementalNullifierChildErrorV2> {
    if bytes.len() != INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalNullifierChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalNullifierChildErrorV2> {
        bytes[4 + (index * 32)..4 + ((index + 1) * 32)]
            .try_into()
            .map_err(|_| IncrementalNullifierChildErrorV2::UnsupportedVersion)
    };
    Ok(IncrementalNullifierChildProjectionV2 {
        configuration_hash: hash(0)?,
        previous_deposit_root_projection: hash(1)?,
        next_deposit_root_projection: hash(2)?,
        previous_withdrawal_root_projection: hash(3)?,
        next_withdrawal_root_projection: hash(4)?,
        deposit_nullifier_key_root: hash(7)?,
        withdrawal_nullifier_key_root: hash(8)?,
        deposit_update_count: u16::from_be_bytes(
            bytes[4 + (9 * 32)..4 + (9 * 32) + 2]
                .try_into()
                .map_err(|_| IncrementalNullifierChildErrorV2::UnsupportedVersion)?,
        ),
        withdrawal_update_count: u16::from_be_bytes(
            bytes[4 + (9 * 32) + 2..]
                .try_into()
                .map_err(|_| IncrementalNullifierChildErrorV2::UnsupportedVersion)?,
        ),
    })
}

pub fn execute_incremental_nullifier_child_v2(
    input: &IncrementalNullifierChildInputV2,
) -> Result<IncrementalNullifierChildPublicValuesV2, IncrementalNullifierChildErrorV2> {
    if input.version != INCREMENTAL_NULLIFIER_CHILD_VERSION_V2 {
        return Err(IncrementalNullifierChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    if input.previous_deposit_root.kind != NullifierKindV2::Deposit
        || input.next_deposit_root.kind != NullifierKindV2::Deposit
        || input.previous_withdrawal_root.kind != NullifierKindV2::Withdrawal
        || input.next_withdrawal_root.kind != NullifierKindV2::Withdrawal
    {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalNullifierChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_NULLIFIER_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalNullifierChildErrorV2::InputTooLarge);
    }
    let maximum = usize::from(input.configuration.maximum_nullifier_updates_per_kind);
    let deposit = verify_sparse_nullifier_updates_v2(
        input.previous_deposit_root,
        &input.deposit_updates,
        maximum,
    )?;
    let withdrawal = verify_sparse_nullifier_updates_v2(
        input.previous_withdrawal_root,
        &input.withdrawal_updates,
        maximum,
    )?;
    if deposit != input.next_deposit_root || withdrawal != input.next_withdrawal_root {
        return Err(ProtocolError::InvalidMerkleProof.into());
    }
    Ok(IncrementalNullifierChildPublicValuesV2 {
        configuration_hash: input.configuration.digest()?,
        previous_deposit_root_projection: incremental_nullifier_root_projection_v2(
            input.previous_deposit_root,
        ),
        next_deposit_root_projection: incremental_nullifier_root_projection_v2(
            input.next_deposit_root,
        ),
        previous_withdrawal_root_projection: incremental_nullifier_root_projection_v2(
            input.previous_withdrawal_root,
        ),
        next_withdrawal_root_projection: incremental_nullifier_root_projection_v2(
            input.next_withdrawal_root,
        ),
        deposit_update_transcript_root: update_root(
            b"ECX/incremental-deposit-nullifier-updates/v1",
            &input.deposit_updates,
        ),
        withdrawal_update_transcript_root: update_root(
            b"ECX/incremental-withdrawal-nullifier-updates/v1",
            &input.withdrawal_updates,
        ),
        deposit_nullifier_key_root: incremental_nullifier_key_root_v2(
            NullifierKindV2::Deposit,
            input.deposit_updates.iter().map(|update| update.nullifier),
        )?,
        withdrawal_nullifier_key_root: incremental_nullifier_key_root_v2(
            NullifierKindV2::Withdrawal,
            input
                .withdrawal_updates
                .iter()
                .map(|update| update.nullifier),
        )?,
        deposit_update_count: u16::try_from(input.deposit_updates.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        withdrawal_update_count: u16::try_from(input.withdrawal_updates.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        canonical_empty_nullifier_path_v2, canonical_empty_nullifier_root_v2,
        IncrementalAccountingBoundsV2, RiskParams, SparseNullifierUpdateV2, ECX_USDD_MARKET,
        INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
    };

    use super::*;

    fn configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [0x11; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [0x22; 32],
            successor_matcher_configuration_hash: [0x23; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 1_000_000,
                maximum_total_controlled_atoms: 10_000_000,
                maximum_abs_position_atoms: 1_000_000,
                maximum_open_interest_atoms: 10_000_000,
                maximum_price_atoms: 1_000_000_000,
            },
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        }
    }

    #[test]
    fn nullifier_child_binds_both_kinds_and_rejects_replay_or_substitution() {
        let deposit = canonical_empty_nullifier_root_v2(NullifierKindV2::Deposit);
        let withdrawal = canonical_empty_nullifier_root_v2(NullifierKindV2::Withdrawal);
        let update = SparseNullifierUpdateV2 {
            kind: NullifierKindV2::Deposit,
            nullifier: [0x33; 32],
            path: canonical_empty_nullifier_path_v2(NullifierKindV2::Deposit),
        };
        let next_deposit =
            verify_sparse_nullifier_updates_v2(deposit, std::slice::from_ref(&update), 64).unwrap();
        let input = IncrementalNullifierChildInputV2 {
            version: INCREMENTAL_NULLIFIER_CHILD_VERSION_V2,
            configuration: configuration(),
            previous_deposit_root: deposit,
            next_deposit_root: next_deposit,
            previous_withdrawal_root: withdrawal,
            next_withdrawal_root: withdrawal,
            deposit_updates: vec![update],
            withdrawal_updates: vec![],
        };
        let values = execute_incremental_nullifier_child_v2(&input).unwrap();
        assert_eq!(values.deposit_update_count, 1);
        assert_eq!(values.withdrawal_update_count, 0);
        assert_eq!(
            values.encode().len(),
            INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2
        );

        let mut substituted = input.clone();
        substituted.next_deposit_root.hash[0] ^= 1;
        assert!(execute_incremental_nullifier_child_v2(&substituted).is_err());
        let mut replayed = input;
        replayed
            .deposit_updates
            .push(replayed.deposit_updates[0].clone());
        assert!(execute_incremental_nullifier_child_v2(&replayed).is_err());
    }

    #[test]
    fn nullifier_child_has_exact_two_tree_encoding_ceiling() {
        let configuration = configuration();
        let maximum = usize::from(configuration.maximum_nullifier_updates_per_kind);
        let deposit = canonical_empty_nullifier_root_v2(NullifierKindV2::Deposit);
        let withdrawal = canonical_empty_nullifier_root_v2(NullifierKindV2::Withdrawal);
        let deposit_update = SparseNullifierUpdateV2 {
            kind: NullifierKindV2::Deposit,
            nullifier: [0x41; 32],
            path: canonical_empty_nullifier_path_v2(NullifierKindV2::Deposit),
        };
        let withdrawal_update = SparseNullifierUpdateV2 {
            kind: NullifierKindV2::Withdrawal,
            nullifier: [0x42; 32],
            path: canonical_empty_nullifier_path_v2(NullifierKindV2::Withdrawal),
        };
        let input = IncrementalNullifierChildInputV2 {
            version: INCREMENTAL_NULLIFIER_CHILD_VERSION_V2,
            configuration,
            previous_deposit_root: deposit,
            next_deposit_root: deposit,
            previous_withdrawal_root: withdrawal,
            next_withdrawal_root: withdrawal,
            deposit_updates: vec![deposit_update; maximum],
            withdrawal_updates: vec![withdrawal_update; maximum],
        };
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialize(&input)
            .unwrap();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2
        );
    }
}
