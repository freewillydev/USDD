//! Canonical execution-root preimage for future authenticated child checkpoints.
//! Hashing this preimage is NOT authentication, history replay, or qualification.
//! Consumers must bind its commitment in a reviewed checkpoint or verified receipt.
use ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2;
use ecx_full_consensus_validator_v2::Hash32;
use crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator;
use crate::native_header_v3::NativeHeader;
use elements::hashes::Hash as _;

/// Explicit checkpoint preimage. This is not inferred from a node's claimed tip.
/// Configuration and history commitments require separately verified preimages.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildExecutionCheckpointV3 {
    pub genesis_internal: Hash32,
    pub configuration_commitment: Hash32,
    pub tip_internal: Hash32,
    pub height: u32,
    pub history_commitment: Hash32,
    pub roots: ElementsTransactionStateRootsV2,
    pub spent_claims_root: Hash32,
    pub withdrawals: WithdrawalAccumulator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError { Identity, Height, Accumulator, FrozenCommitment, History }

/// Exact contiguous native header history, oldest first. Includes wire signatures
/// and all Alpha extension fields; it is not the lossy upstream header encoding.
/// Linkage and commitment do not establish historical consensus validity.
pub fn child_history_commitment(headers: &[NativeHeader]) -> Result<Hash32, CheckpointError> {
    let count = u32::try_from(headers.len()).map_err(|_| CheckpointError::History)?;
    if count == 0 { return Err(CheckpointError::History); }
    let mut bytes = vec![3];
    bytes.extend_from_slice(&count.to_be_bytes());
    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            let previous = &headers[index - 1];
            if previous.base.height.checked_add(1) != Some(header.base.height)
                || previous.hash_internal().map_err(|_| CheckpointError::History)?
                    != header.base.prev_blockhash.to_byte_array() {
                return Err(CheckpointError::History);
            }
        }
        let wire = header.encode(false, true).map_err(|_| CheckpointError::History)?;
        let length = u32::try_from(wire.len()).map_err(|_| CheckpointError::History)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&wire);
    }
    Ok(super::tagged_hash("ECX/alpha-child-execution-history/v3", &bytes))
}

impl ChildExecutionCheckpointV3 {
    /// Check the committed history preimage and derive the exact MTP suffix.
    /// Longer history can supply epoch selection; its required epoch coverage is
    /// checked separately by native parameter selection. The checkpoint itself
    /// must still be authenticated against an independently frozen commitment.
    pub fn checked_mtp_history(&self, headers: &[NativeHeader]) -> Result<Vec<NativeHeader>, CheckpointError> {
        let needed = self.height.checked_add(1).ok_or(CheckpointError::Height)?.min(11) as usize;
        let tip = headers.last().ok_or(CheckpointError::History)?;
        if headers.len() < needed || tip.base.height != self.height
            || tip.hash_internal().map_err(|_| CheckpointError::History)? != self.tip_internal
            || child_history_commitment(headers)? != self.history_commitment {
            return Err(CheckpointError::History);
        }
        if headers[0].base.height == 0
            && headers[0].hash_internal().map_err(|_| CheckpointError::History)? != self.genesis_internal {
            return Err(CheckpointError::History);
        }
        Ok(headers[headers.len() - needed..].to_vec())
    }
    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        if [self.genesis_internal, self.configuration_commitment, self.tip_internal,
            self.history_commitment, self.spent_claims_root].contains(&[0; 32]) {
            return Err(CheckpointError::Identity);
        }
        if self.height == u32::MAX || (self.height == 0 && self.tip_internal != self.genesis_internal) {
            return Err(CheckpointError::Height);
        }
        if !self.withdrawals.is_sane() { return Err(CheckpointError::Accumulator); }
        let mut bytes = Vec::with_capacity(2350);
        bytes.push(3);
        for hash in [self.genesis_internal, self.configuration_commitment, self.tip_internal,
            self.history_commitment] { bytes.extend_from_slice(&hash); }
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&execution_roots_bytes(&self.roots));
        bytes.extend_from_slice(&self.spent_claims_root);
        bytes.extend_from_slice(&self.withdrawals.count.to_be_bytes());
        bytes.extend_from_slice(&self.withdrawals.root);
        for hash in self.withdrawals.frontier { bytes.extend_from_slice(&hash); }
        Ok(super::tagged_hash("ECX/alpha-child-execution-checkpoint/v3", &bytes))
    }

    /// Only equality against an independently frozen checkpoint, not evidence
    /// that the frozen value was reviewed or produced by a qualified program.
    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0; 32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
}

/// Fixed version, raw internal-order hashes, unsigned 128-bit big-endian totals.
/// Includes every aggregate: committing only the root hashes is insufficient for
/// callers that subsequently use the separately supplied aggregate values.
pub fn execution_roots_bytes(roots: &ElementsTransactionStateRootsV2) -> [u8; 129] {
    let mut bytes = [0; 129];
    bytes[0] = 3;
    bytes[1..33].copy_from_slice(&roots.utxo_root.hash);
    bytes[33..49].copy_from_slice(&roots.utxo_root.aggregate.count.to_be_bytes());
    bytes[49..81].copy_from_slice(&roots.economic_root.hash);
    bytes[81..97].copy_from_slice(&roots.economic_root.aggregate.count.to_be_bytes());
    bytes[97..113].copy_from_slice(&roots.economic_root.aggregate.outstanding_base_atoms.to_be_bytes());
    bytes[113..129].copy_from_slice(&roots.economic_root.aggregate.redeemable_reserve_quote_atoms.to_be_bytes());
    bytes
}

pub fn execution_roots_commitment(roots: &ElementsTransactionStateRootsV2) -> Hash32 {
    super::tagged_hash("ECX/alpha-child-execution-roots/v3", &execution_roots_bytes(roots))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_full_consensus_validator_v2::elements_v2::*;

    fn fixture() -> ElementsTransactionStateRootsV2 {
        ElementsTransactionStateRootsV2 {
            utxo_root: ElementsSparseUtxoNodeV2 {
                hash: [1; 32], aggregate: ElementsUtxoAggregateV2 { count: 2 },
            },
            economic_root: ElementsSparseEconomicNodeV2 {
                hash: [3; 32], aggregate: ElementsEconomicAggregateV2 {
                    count: 4, outstanding_base_atoms: 5, redeemable_reserve_quote_atoms: u128::MAX,
                },
            },
        }
    }

    #[test]
    fn exact_layout_and_every_field_are_committed() {
        let roots = fixture();
        let bytes = execution_roots_bytes(&roots);
        assert_eq!(bytes[0], 3);
        assert_eq!(&bytes[1..33], &[1; 32]);
        assert_eq!(&bytes[33..49], &2u128.to_be_bytes());
        assert_eq!(&bytes[49..81], &[3; 32]);
        assert_eq!(&bytes[81..97], &4u128.to_be_bytes());
        assert_eq!(&bytes[97..113], &5u128.to_be_bytes());
        assert_eq!(&bytes[113..129], &[255; 16]);
        for field in 0..6 {
            let mut changed = roots;
            match field {
                0 => changed.utxo_root.hash[0] ^= 1,
                1 => changed.utxo_root.aggregate.count += 1,
                2 => changed.economic_root.hash[0] ^= 1,
                3 => changed.economic_root.aggregate.count += 1,
                4 => changed.economic_root.aggregate.outstanding_base_atoms += 1,
                _ => changed.economic_root.aggregate.redeemable_reserve_quote_atoms -= 1,
            }
            assert_ne!(execution_roots_commitment(&roots), execution_roots_commitment(&changed));
        }
    }

    #[test]
    fn frozen_checkpoint_rejects_state_and_identity_substitution() {
        let checkpoint = ChildExecutionCheckpointV3 {
            genesis_internal: [1; 32], configuration_commitment: [2; 32],
            tip_internal: [3; 32], height: 7, history_commitment: [4; 32],
            roots: fixture(), withdrawals: WithdrawalAccumulator::empty(),
            spent_claims_root: crate::native_claims_v3::empty_root(),
        };
        let frozen = checkpoint.commitment().unwrap();
        // Guest transport preserves the exact committed state, including every
        // withdrawal frontier entry. Decoding does not authenticate the root.
        let wire = bincode::serialize(&checkpoint).unwrap();
        let decoded: ChildExecutionCheckpointV3 = bincode::deserialize(&wire).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.commitment().unwrap(), frozen);
        let mut populated = checkpoint.clone();
        for index in 0..65u8 { populated.withdrawals.append([index;32]).unwrap(); }
        let wire = bincode::serialize(&populated).unwrap();
        let decoded: ChildExecutionCheckpointV3 = bincode::deserialize(&wire).unwrap();
        assert_eq!(decoded, populated);
        assert_eq!(decoded.commitment(), populated.commitment());
        let mut invalid = populated.clone(); invalid.withdrawals.root[0] ^= 1;
        assert!(bincode::deserialize::<ChildExecutionCheckpointV3>(
            &bincode::serialize(&invalid).unwrap()).is_err());
        assert_eq!(checkpoint.require_frozen(frozen), Ok(()));
        assert_eq!(checkpoint.require_frozen([0; 32]), Err(CheckpointError::FrozenCommitment));
        for field in 0..13 {
            let mut changed = checkpoint.clone();
            match field {
                0 => changed.genesis_internal[0] ^= 1,
                1 => changed.configuration_commitment[0] ^= 1,
                2 => changed.tip_internal[0] ^= 1,
                3 => changed.height += 1,
                4 => changed.history_commitment[0] ^= 1,
                5 => changed.roots.utxo_root.hash[0] ^= 1,
                6 => changed.roots.utxo_root.aggregate.count += 1,
                7 => changed.roots.economic_root.hash[0] ^= 1,
                8 => changed.roots.economic_root.aggregate.count += 1,
                9 => changed.roots.economic_root.aggregate.outstanding_base_atoms += 1,
                10 => changed.roots.economic_root.aggregate.redeemable_reserve_quote_atoms -= 1,
                11 => changed.withdrawals.append([9; 32]).unwrap(),
                _ => changed.spent_claims_root[0] ^= 1,
            }
            assert_eq!(changed.require_frozen(frozen), Err(CheckpointError::FrozenCommitment));
        }
        let mut malformed = checkpoint.clone();
        malformed.withdrawals.frontier[0] = [8; 32];
        assert_eq!(malformed.commitment(), Err(CheckpointError::Accumulator));
        malformed = checkpoint.clone();
        malformed.height = 0;
        assert_eq!(malformed.commitment(), Err(CheckpointError::Height));
        malformed.tip_internal = malformed.genesis_internal;
        assert!(malformed.commitment().is_ok());
        malformed.configuration_commitment = [0; 32];
        assert_eq!(malformed.commitment(), Err(CheckpointError::Identity));
    }

    #[test]
    fn committed_history_binds_native_preimages_and_derives_mtp_suffix() {
        use elements::{BlockHeader, BlockExtData, BlockHash, TxMerkleNode, Script};
        let mut headers = Vec::new();
        let mut previous = BlockHash::all_zeros();
        for height in 0..13 {
            let header = NativeHeader::from_standard(BlockHeader {
                version: 2, prev_blockhash: previous, merkle_root: TxMerkleNode::all_zeros(),
                time: height + 1, height,
                ext: BlockExtData::Proof { challenge: Script::from(vec![0x51]), solution: Script::new() },
            });
            previous = BlockHash::from_byte_array(header.hash_internal().unwrap());
            headers.push(header);
        }
        let checkpoint = ChildExecutionCheckpointV3 {
            genesis_internal: headers[0].hash_internal().unwrap(), configuration_commitment: [2;32],
            tip_internal: previous.to_byte_array(), height: 12,
            history_commitment: child_history_commitment(&headers).unwrap(),
            roots: fixture(), withdrawals: WithdrawalAccumulator::empty(),
            spent_claims_root: crate::native_claims_v3::empty_root(),
        };
        let mtp = checkpoint.checked_mtp_history(&headers).unwrap();
        assert_eq!(mtp.len(), 11);
        assert_eq!(mtp[0].base.height, 2);
        assert!(checkpoint.checked_mtp_history(&headers[1..]).is_err());
        let mut changed = headers.clone();
        changed[4].base.time += 1;
        assert!(checkpoint.checked_mtp_history(&changed).is_err());
        let mut changed = headers.clone();
        if let BlockExtData::Proof { solution, .. } = &mut changed[4].base.ext {
            *solution = Script::from(vec![0x51]);
        }
        // Signature changes preserve block hashes, but not the exact history.
        assert_eq!(changed[4].hash_internal().unwrap(), headers[4].hash_internal().unwrap());
        assert!(checkpoint.checked_mtp_history(&changed).is_err());
        assert!(child_history_commitment(&[]).is_err());
    }
}
