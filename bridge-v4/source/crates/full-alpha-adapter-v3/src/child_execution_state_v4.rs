//! Explicitly versioned checkpoint extension for native capital projection.
//! Commitment only: producers must verify genesis/transitions and scan all
//! source transactions. Neither serialization nor hashing authenticates state.
use crate::child_execution_state_v3::{ChildExecutionCheckpointV3, CheckpointError};
use ecx_full_consensus_validator_v2::Hash32;

/// Evaluator-relevant projection, not the full native capital snapshot.
/// Counts remain u128 for incremental consensus; the native execution ABI's
/// narrower u64 conversion must be checked separately, never truncated.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalProjectionV4 {
    pub proof_profile: u8,
    pub exchange_state_root: Hash32,
    pub configuration_hash: Hash32,
    pub asset_id: Hash32,
    pub deployment_commitment: Hash32,
    pub transition_program_id: Hash32,
    pub transition_cmr: Hash32,
    pub covenant_state_hash: Hash32,
    pub covenant_inbox_root: Hash32,
    pub covenant_inbox_count: u128,
    pub node_inbox_root: Hash32,
    pub node_inbox_count: u128,
}

impl CapitalProjectionV4 {
    /// Append the complete block's admitted finite inbox sources after its
    /// genesis/transition projection has been verified. This preserves the
    /// covenant's settled head: native execution uses the independently
    /// appended node head on the following block.
    ///
    /// The caller must authenticate the block, heights and this initial
    /// projection through consensus. This method performs source admission,
    /// not ordinary input validation or genesis/transition proof verification.
    /// Incremental projections require their own wide-count source codec.
    pub fn append_finite_block_sources(
        &self,
        transactions: &[elements::Transaction],
        sidechain_height: u64,
        parent_height: u64,
        block_hash: Hash32,
        configuration: &ecx_protocol_core::configuration_v2::FrozenConfigurationV2,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<Self, crate::native_bond_inbox_scan_v4::ScanError> {
        use crate::native_bond_inbox_scan_v4::{EntryContext, ScanError, verify_finite_block_sources};
        self.commitment().map_err(|_| ScanError::Context)?;
        if self.proof_profile != 0 || self.configuration_hash != configuration.digest()
            || sidechain_height == 0 || parent_height == 0 || block_hash == [0; 32] {
            return Err(ScanError::Context);
        }
        let context = EntryContext {
            count: u64::try_from(self.node_inbox_count).map_err(|_| ScanError::Limit)?,
            previous_root: self.node_inbox_root,
            sidechain_height, parent_height, block_hash,
        };
        let entries = verify_finite_block_sources(transactions, &context, configuration, registry)?;
        let mut next = self.clone();
        if let Some(last) = entries.last() {
            next.node_inbox_count = u128::from(last.index.checked_add(1).ok_or(ScanError::Limit)?);
            next.node_inbox_root = last.next_root();
        }
        next.commitment().map_err(|_| ScanError::Context)?;
        Ok(next)
    }

    /// Successor counterpart of finite admission, preserving the full lifetime
    /// counter and the separately settled covenant head.
    /// `successor_configuration_hash` must come from the authenticated frozen
    /// successor identity. Markers still bind the base economic configuration,
    /// whereas the capital snapshot binds the distinct successor configuration.
    pub fn append_successor_block_sources(
        &self, transactions: &[elements::Transaction], sidechain_height: u64,
        parent_height: u64, block_hash: Hash32,
        configuration: &ecx_protocol_core::configuration_v2::FrozenConfigurationV2,
        successor_configuration_hash: Hash32,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<Self, crate::native_bond_inbox_scan_v4::ScanError> {
        use crate::native_bond_inbox_scan_v4::{SuccessorEntryContext, ScanError, verify_successor_block_sources};
        self.commitment().map_err(|_| ScanError::Context)?;
        if self.proof_profile != 1 || successor_configuration_hash == [0; 32]
            || successor_configuration_hash == configuration.digest()
            || self.configuration_hash != successor_configuration_hash {
            return Err(ScanError::Context);
        }
        let context = SuccessorEntryContext { count: self.node_inbox_count,
            previous_root: self.node_inbox_root, sidechain_height, parent_height, block_hash };
        let entries = verify_successor_block_sources(transactions, &context, configuration, registry)?;
        let mut next = self.clone();
        if let Some(last) = entries.last() {
            next.node_inbox_count = last.index.checked_add(1).ok_or(ScanError::Limit)?;
            next.node_inbox_root = last.next_root();
        }
        next.commitment().map_err(|_| ScanError::Context)?;
        Ok(next)
    }

    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        let hashes = [self.exchange_state_root, self.configuration_hash,
            self.asset_id, self.deployment_commitment, self.transition_program_id,
            self.transition_cmr, self.covenant_state_hash, self.covenant_inbox_root,
            self.node_inbox_root];
        if self.proof_profile > 1 || hashes.contains(&[0; 32])
            || self.node_inbox_count < self.covenant_inbox_count
            || (self.node_inbox_count == self.covenant_inbox_count
                && self.node_inbox_root != self.covenant_inbox_root)
            || (self.proof_profile == 0 && self.node_inbox_count > u64::MAX as u128) {
            return Err(CheckpointError::Identity);
        }
        let mut bytes = vec![4, self.proof_profile];
        for hash in hashes { bytes.extend_from_slice(&hash); }
        bytes.extend_from_slice(&self.covenant_inbox_count.to_be_bytes());
        bytes.extend_from_slice(&self.node_inbox_count.to_be_bytes());
        Ok(crate::tagged_hash("ECX/alpha-child-capital-projection/v4", &bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildExecutionCheckpointV4 {
    pub execution: ChildExecutionCheckpointV3,
    pub capital: Option<CapitalProjectionV4>,
}

impl ChildExecutionCheckpointV4 {
    /// Expected commitment must be independently frozen or receipt-authenticated.
    /// This binds the projection to the same prior header used by execution;
    /// it does not replace verification of the projection-producing transition.
    pub fn checked_header(
        &self, expected: Hash32, header: &crate::native_header_v3::NativeHeader,
    ) -> Result<Option<crate::native_header_v3::PriorExchangeContext>, CheckpointError> {
        self.require_frozen(expected)?;
        let context = header.prior_exchange_context(
            self.execution.tip_internal, self.execution.height,
        ).map_err(|_| CheckpointError::History)?;
        if let Some(capital) = &self.capital {
            if header.base.version & crate::native_header_v3::EXCHANGE == 0
                || header.exchange != capital.exchange_state_root {
                return Err(CheckpointError::Identity);
            }
        }
        Ok(context)
    }

    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        let mut bytes = vec![4];
        bytes.extend_from_slice(&self.execution.commitment()?);
        bytes.push(u8::from(self.capital.is_some()));
        bytes.extend_from_slice(&match &self.capital {
            Some(capital) => capital.commitment()?, None => [0; 32],
        });
        Ok(crate::tagged_hash("ECX/alpha-child-execution-checkpoint/v4", &bytes))
    }

    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0; 32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
}

/// Explicit extension; V4 commitments cannot authenticate a BMM anchor.
/// A decoded value is only a preimage. Its commitment must be frozen or verified
/// by the preceding recursive receipt before using its endpoint in execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildExecutionCheckpointV5 {
    pub state: ChildExecutionCheckpointV4,
    /// Native display hash || BE u64 height || BE u64 MTP || BE chainwork.
    /// Absent only for the genesis checkpoint in this authenticated Alpha lane.
    pub bmm_endpoint: Option<Vec<u8>>,
}

impl ChildExecutionCheckpointV5 {
    /// Open the anchor only under a separately authenticated full checkpoint.
    pub fn evaluator_anchor_commitment(&self, frozen: Hash32)
        -> Result<Hash32, CheckpointError> {
        self.require_frozen(frozen)?;
        ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::alpha_prior_anchor_commitment_v4(
            self.bmm_endpoint.as_deref()).map_err(|_| CheckpointError::Identity)
    }

    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        let mut bytes = vec![5];
        bytes.extend_from_slice(&self.state.commitment()?);
        match &self.bmm_endpoint {
            None if self.state.execution.height == 0 => bytes.push(0),
            Some(endpoint) if self.state.execution.height > 0
                && endpoint.len() == 80
                && endpoint[..32] != [0; 32] && endpoint[48..] != [0; 32] => {
                bytes.push(1);
                bytes.extend_from_slice(endpoint);
            }
            _ => return Err(CheckpointError::Identity),
        }
        Ok(crate::tagged_hash("ECX/alpha-child-execution-checkpoint/v5", &bytes))
    }

    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0; 32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }

    /// Join an independently verified capital projection with this exact
    /// executed child's authenticated P endpoint. Does not authenticate the
    /// capital projection itself; the enclosing relation must still do that.
    pub fn join_executed_parent<P: crate::FullAlphaReceiptVerifierV3>(
        state: ChildExecutionCheckpointV4,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        parent: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
        frozen_parent_binding: Hash32,
        verifier: &P,
    ) -> Result<Self, CheckpointError> {
        if executed.child().next_checkpoint() != Some(&state.execution) {
            return Err(CheckpointError::Identity);
        }
        let (statement, endpoint) =
            crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
                parent, frozen_parent_binding, verifier)
                .map_err(|_| CheckpointError::Identity)?;
        if &statement != executed.parent() {
            return Err(CheckpointError::Identity);
        }
        state.checked_header(state.commitment()?, &executed.child().foundation().native_header)?;
        let result = Self { state, bmm_endpoint: Some(endpoint.to_vec()) };
        result.commitment()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::hashes::Hash as _;
    fn projection() -> CapitalProjectionV4 {
        CapitalProjectionV4 { proof_profile: 0, exchange_state_root: [1;32],
            configuration_hash: [2;32], asset_id: [3;32], deployment_commitment: [4;32],
            transition_program_id: [5;32], transition_cmr: [6;32], covenant_state_hash: [7;32],
            covenant_inbox_root: [8;32], covenant_inbox_count: 2,
            node_inbox_root: [9;32], node_inbox_count: 3 }
    }
    #[test]
    fn checkpoint_header_rejects_projection_and_header_substitution() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        use crate::native_header_v3::*;
        let mut header = NativeHeader::from_standard(elements::BlockHeader {
            version: EXCHANGE | FORCED | DEPOSIT | CURSORS,
            prev_blockhash: elements::BlockHash::from_byte_array([1;32]),
            merkle_root: elements::TxMerkleNode::from_byte_array([2;32]),
            time: 100, height: 7, ext: elements::BlockExtData::Proof {
                challenge: elements::Script::from(vec![0x51]), solution: elements::Script::new(),
            },
        });
        header.exchange = [1;32]; header.forced = [2;32]; header.deposit = [3;32];
        let checkpoint = ChildExecutionCheckpointV4 {
            execution: ChildExecutionCheckpointV3 {
                genesis_internal: [4;32], configuration_commitment: [5;32],
                tip_internal: header.hash_internal().unwrap(), height: 7,
                history_commitment: [6;32], spent_claims_root: [7;32],
                withdrawals: crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty(),
                roots: ElementsTransactionStateRootsV2 {
                    utxo_root: ElementsSparseUtxoNodeV2 { hash: [8;32], aggregate: ElementsUtxoAggregateV2 { count: 0 } },
                    economic_root: ElementsSparseEconomicNodeV2 { hash: [9;32], aggregate: ElementsEconomicAggregateV2 {
                        count: 0, outstanding_base_atoms: 0, redeemable_reserve_quote_atoms: 0,
                    } },
                },
            }, capital: Some(projection()),
        };
        let frozen = checkpoint.commitment().unwrap();
        let mut endpoint = vec![1; 80];
        endpoint[32..40].copy_from_slice(&10u64.to_be_bytes());
        endpoint[40..48].copy_from_slice(&100u64.to_be_bytes());
        let anchored = ChildExecutionCheckpointV5 {
            state: checkpoint.clone(), bmm_endpoint: Some(endpoint),
        };
        let anchored_hash = anchored.commitment().unwrap();
        assert_eq!(anchored.evaluator_anchor_commitment(anchored_hash).unwrap(),
            crate::tagged_hash("ECX/alpha-native-evaluator-prior-anchor/v3",
                anchored.bmm_endpoint.as_ref().unwrap()));
        assert!(anchored.evaluator_anchor_commitment(frozen).is_err());
        assert_ne!(anchored_hash, frozen);
        assert!(anchored.require_frozen(frozen).is_err());
        assert!(anchored.require_frozen(anchored_hash).is_ok());
        for index in 0..80 {
            let mut changed = anchored.clone();
            changed.bmm_endpoint.as_mut().unwrap()[index] ^= 1;
            assert!(changed.require_frozen(anchored_hash).is_err());
        }
        let mut changed = anchored.clone();
        changed.bmm_endpoint.as_mut().unwrap().push(0);
        assert!(changed.commitment().is_err());
        changed.bmm_endpoint = None;
        assert!(changed.commitment().is_err());
        changed.state.execution.height = 0;
        changed.state.execution.tip_internal = changed.state.execution.genesis_internal;
        assert!(changed.commitment().is_ok());
        assert_ne!(changed.evaluator_anchor_commitment(changed.commitment().unwrap()).unwrap(),
            anchored.evaluator_anchor_commitment(anchored_hash).unwrap());
        changed.bmm_endpoint = anchored.bmm_endpoint.clone();
        assert!(changed.commitment().is_err());
        assert!(checkpoint.checked_header(frozen, &header).unwrap().is_some());
        assert!(checkpoint.checked_header(checkpoint.execution.commitment().unwrap(), &header).is_err());
        let mut changed = checkpoint.clone();
        changed.capital.as_mut().unwrap().exchange_state_root = [10;32];
        assert!(changed.checked_header(frozen, &header).is_err());
        assert!(changed.checked_header(changed.commitment().unwrap(), &header).is_err());
        header.deposit_cursor += 1;
        assert!(checkpoint.checked_header(frozen, &header).is_err());
    }

    #[test]
    fn distinct_settled_and_appended_heads_and_wide_counts() {
        let p = projection(); let original = p.commitment().unwrap();
        let mut changed = p.clone(); changed.node_inbox_root[0] ^= 1;
        assert_ne!(original, changed.commitment().unwrap());
        changed = p.clone(); changed.covenant_inbox_count = 3;
        assert!(changed.commitment().is_err());
        changed = p.clone(); changed.node_inbox_count = 1;
        assert!(changed.commitment().is_err());
        changed = p.clone(); changed.node_inbox_count = u64::MAX as u128 + 1;
        assert!(changed.commitment().is_err());
        changed.proof_profile = 1;
        assert!(changed.commitment().is_ok());
        changed.proof_profile = 2;
        assert!(changed.commitment().is_err());
    }
}
