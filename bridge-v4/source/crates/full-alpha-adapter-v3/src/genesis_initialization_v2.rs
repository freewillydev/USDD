//! Reviewed ancestor initialization, distinct from fresh activation time.
//! The frozen record is a trust input: a child header does not authenticate
//! historical parent MTP. Its digest must be pinned independently by the release.
use crate::{child_execution_state_v3::ChildExecutionCheckpointV3,
    native_header_v3::NativeHeader};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisInitializationV2 {
    pub version: u8,
    pub child_genesis: [u8; 32],
    pub height: u32,
    /// Raw internal-order child block hash, not display-order hex.
    pub block_internal: [u8; 32],
    pub parent_mtp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializationError { Record, FrozenRecord, Checkpoint, History, Order }

/// Only produced after checking both independent commitments and the ancestor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedGenesisInitialization {
    height: u32,
    parent_mtp: u64,
}
impl CheckedGenesisInitialization {
    pub fn height(self) -> u64 { u64::from(self.height) }
    pub fn parent_mtp(self) -> u64 { self.parent_mtp }
}

impl GenesisInitializationV2 {
    pub fn commitment(&self) -> Result<[u8; 32], InitializationError> {
        if self.version != 2 || self.height == 0 || self.parent_mtp == 0
            || self.parent_mtp > u64::from(u32::MAX)
            || self.child_genesis == [0; 32] || self.block_internal == [0; 32] {
            return Err(InitializationError::Record);
        }
        let mut bytes = vec![self.version];
        bytes.extend_from_slice(&self.child_genesis);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.block_internal);
        bytes.extend_from_slice(&self.parent_mtp.to_be_bytes());
        Ok(crate::tagged_hash("ECX/alpha-genesis-initialization/v2", &bytes))
    }

    /// `frozen_record` and `frozen_checkpoint` must originate outside the witness.
    /// The caller still verifies the activation execution, state-coin membership,
    /// current authenticated parent context and complete deployment relation.
    pub fn authenticate(
        &self, frozen_record: [u8; 32], checkpoint: &ChildExecutionCheckpointV3,
        frozen_checkpoint: [u8; 32], history: &[NativeHeader],
        state_creation_height: u32, activation_parent_mtp: u64,
    ) -> Result<CheckedGenesisInitialization, InitializationError> {
        if frozen_record == [0; 32] || self.commitment()? != frozen_record {
            return Err(InitializationError::FrozenRecord);
        }
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| InitializationError::Checkpoint)?;
        if checkpoint.genesis_internal != self.child_genesis {
            return Err(InitializationError::Checkpoint);
        }
        if self.height >= state_creation_height || state_creation_height > checkpoint.height
            || activation_parent_mtp == 0 || self.parent_mtp > activation_parent_mtp {
            return Err(InitializationError::Order);
        }
        checkpoint.checked_mtp_history(history).map_err(|_| InitializationError::History)?;
        self.checked_ancestor(history)
    }

    /// Selected public-custody lane: authenticate the full custody checkpoint,
    /// never manufacture a legacy economic checkpoint from its roots.
    pub fn authenticate_custody(
        &self, frozen_record: [u8; 32],
        checkpoint: &crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
        frozen_checkpoint: [u8; 32], history: &[NativeHeader],
        state_creation_height: u32, activation_parent_mtp: u64,
    ) -> Result<CheckedGenesisInitialization, InitializationError> {
        if frozen_record == [0; 32] || self.commitment()? != frozen_record {
            return Err(InitializationError::FrozenRecord);
        }
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| InitializationError::Checkpoint)?;
        let execution = &checkpoint.execution;
        if execution.genesis_internal != self.child_genesis || checkpoint.capital.is_some() {
            return Err(InitializationError::Checkpoint);
        }
        if self.height >= state_creation_height || state_creation_height > execution.height
            || activation_parent_mtp == 0 || self.parent_mtp > activation_parent_mtp {
            return Err(InitializationError::Order);
        }
        execution.checked_mtp_history(history).map_err(|_| InitializationError::History)?;
        self.checked_ancestor(history)
    }

    fn checked_ancestor(&self, history: &[NativeHeader])
        -> Result<CheckedGenesisInitialization, InitializationError> {
        // Histories may be suffixes. Never treat a height as an array index.
        let ancestor = history.iter().find(|h| h.base.height == self.height)
            .ok_or(InitializationError::History)?;
        if ancestor.hash_internal().map_err(|_| InitializationError::History)? != self.block_internal {
            return Err(InitializationError::History);
        }
        Ok(CheckedGenesisInitialization { height: self.height, parent_mtp: self.parent_mtp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn materializer_shared_initialization_digest_vector() {
        let record = GenesisInitializationV2 {
            version: 2, child_genesis: [1;32], height: 39,
            block_internal: [2;32], parent_mtp: 1_700_000_000,
        };
        let expected = "6665079f802e65cd66b1047b36bf906a95fe025e0eb6763561156a022a2a3d9c";
        let actual: String = record.commitment().unwrap().iter()
            .map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, expected);
    }
    use elements::{hashes::Hash, BlockHeader, BlockExtData, BlockHash, TxMerkleNode, Script};
    use crate::child_execution_state_v3::child_history_commitment;
    use ecx_full_consensus_validator_v2::elements_v2::{ElementsTransactionStateRootsV2,
        ElementsSparseUtxoNodeV2, ElementsUtxoAggregateV2, ElementsSparseEconomicNodeV2,
        ElementsEconomicAggregateV2};

    #[test]
    fn reviewed_initializer_is_stable_and_rejects_substitutions() {
        let mut history = Vec::new();
        let mut previous = BlockHash::all_zeros();
        for height in 0..14 {
            let header = NativeHeader::from_standard(BlockHeader {
                version: 2, prev_blockhash: previous, merkle_root: TxMerkleNode::all_zeros(),
                time: height + 1, height,
                ext: BlockExtData::Proof { challenge: Script::from(vec![0x51]), solution: Script::new() },
            });
            previous = BlockHash::from_byte_array(header.hash_internal().unwrap());
            history.push(header);
        }
        let mut checkpoint = ChildExecutionCheckpointV3 {
            genesis_internal: history[0].hash_internal().unwrap(), configuration_commitment: [2; 32],
            tip_internal: previous.to_byte_array(), height: 13,
            history_commitment: child_history_commitment(&history).unwrap(),
            roots: ElementsTransactionStateRootsV2 {
                utxo_root: ElementsSparseUtxoNodeV2 {
                    hash: [1; 32], aggregate: ElementsUtxoAggregateV2 { count: 0 },
                },
                economic_root: ElementsSparseEconomicNodeV2 {
                    hash: [2; 32], aggregate: ElementsEconomicAggregateV2 {
                        count: 0, outstanding_base_atoms: 0, redeemable_reserve_quote_atoms: 0,
                    },
                },
            },
            spent_claims_root: [3; 32],
            withdrawals: crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty(),
        };
        let record = GenesisInitializationV2 { version: 2, child_genesis: checkpoint.genesis_internal,
            height: 2, block_internal: history[2].hash_internal().unwrap(), parent_mtp: 100 };
        let frozen = record.commitment().unwrap();
        let cp = checkpoint.commitment().unwrap();
        let first = record.authenticate(frozen, &checkpoint, cp, &history, 12, 110).unwrap();
        assert_eq!(first.height(), 2);
        assert_eq!(first.parent_mtp(), 100);
        use crate::child_custody_checkpoint_v3::{ChildCustodyCheckpointV3, ChildCustodyExecutionCheckpointV4};
        use ecx_full_consensus_validator_v2::elements_v2::{ElementsCustodyClassificationV3,
            ElementsTransactionCustodyRootsV3, ElementsSparseCustodyNodeV3};
        let custody = ChildCustodyExecutionCheckpointV4 {
            execution: ChildCustodyCheckpointV3 {
                genesis_internal: checkpoint.genesis_internal,
                configuration_commitment: checkpoint.configuration_commitment,
                tip_internal: checkpoint.tip_internal, height: checkpoint.height,
                history_commitment: checkpoint.history_commitment,
                spent_claims_root: checkpoint.spent_claims_root,
                withdrawals: checkpoint.withdrawals.clone(),
                classification: ElementsCustodyClassificationV3 { native_pegged_asset_id: [6; 32], custody_asset_id: [7; 32] },
                roots: ElementsTransactionCustodyRootsV3 {
                    utxo_root: checkpoint.roots.utxo_root,
                    custody_root: ElementsSparseCustodyNodeV3 { hash: [8; 32], count: 0, custody_supply_atoms: 0 },
                },
            // Structural test endpoint only; no parent receipt is claimed here.
            }, capital: None, bmm_endpoint: Some(vec![1; 80]),
        };
        let custody_hash = custody.commitment().unwrap();
        assert_eq!(record.authenticate_custody(frozen, &custody, custody_hash, &history, 12, 110), Ok(first));
        assert_eq!(record.authenticate_custody(frozen, &custody, custody_hash, &history, 13, 120), Ok(first));
        assert_eq!(record.authenticate_custody(frozen, &custody, cp, &history, 12, 110), Err(InitializationError::Checkpoint));
        assert_eq!(record.authenticate_custody(frozen, &custody, custody_hash, &history[3..], 12, 110), Err(InitializationError::History));
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &history, 13, 120), Ok(first));
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &history, 2, 110), Err(InitializationError::Order));
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &history, 14, 110), Err(InitializationError::Order));
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &history, 12, 99), Err(InitializationError::Order));
        let mut changed = record.clone(); changed.parent_mtp += 1;
        assert_eq!(changed.authenticate(frozen, &checkpoint, cp, &history, 12, 110), Err(InitializationError::FrozenRecord));
        changed = record.clone(); changed.block_internal = [9; 32];
        assert_eq!(changed.authenticate(changed.commitment().unwrap(), &checkpoint, cp, &history, 12, 110), Err(InitializationError::History));
        changed = record.clone(); changed.child_genesis = [9; 32];
        assert_eq!(changed.authenticate(changed.commitment().unwrap(), &checkpoint, cp, &history, 12, 110), Err(InitializationError::Checkpoint));
        let mut tampered = history.clone();
        if let BlockExtData::Proof { solution, .. } = &mut tampered[2].base.ext { *solution = Script::from(vec![0x51]); }
        assert_eq!(tampered[2].hash_internal().unwrap(), history[2].hash_internal().unwrap());
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &tampered, 12, 110), Err(InitializationError::History));
        // A committed suffix with enough MTP coverage still cannot omit the anchor.
        checkpoint.history_commitment = child_history_commitment(&history[3..]).unwrap();
        assert_eq!(record.authenticate(frozen, &checkpoint, checkpoint.commitment().unwrap(), &history[3..], 12, 110), Err(InitializationError::History));
        assert_eq!(record.authenticate(frozen, &checkpoint, cp, &history[3..], 12, 110), Err(InitializationError::Checkpoint));
        changed = record.clone(); changed.version = 1;
        assert_eq!(changed.commitment(), Err(InitializationError::Record));
    }
}
