//! ECX continuity preimage, not authentication or a legacy USDD projection.
use crate::{Hash32, child_execution_state_v3::{ChildExecutionCheckpointV3, CheckpointError}};

/// Parent-anchored transport. V1's native/match projection alone cannot carry
/// the endpoint needed by the next block's authenticated evaluator.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxMatchCheckpointV2 {
    pub state: EcxMatchCheckpointV1,
    pub bmm_endpoint: Option<Vec<u8>>,
}

impl EcxMatchCheckpointV2 {
    /// Deterministic native-only projection of an authenticated ECX checkpoint.
    /// The enclosing ECX receipt carries exchange state/outpoint separately;
    /// never copy a legacy USDD capital projection into the next ECX block.
    /// `expected` must be frozen or verified from the preceding ECXNJ1 receipt.
    pub fn native_projection(&self, expected: Hash32)
        -> Result<crate::child_execution_state_v4::ChildExecutionCheckpointV5, CheckpointError> {
        self.require_frozen(expected)?;
        let checkpoint = crate::child_execution_state_v4::ChildExecutionCheckpointV5 {
            state: crate::child_execution_state_v4::ChildExecutionCheckpointV4 {
                execution: self.state.execution.clone(), capital: None,
            }, bmm_endpoint: self.bmm_endpoint.clone(),
        };
        checkpoint.commitment()?;
        Ok(checkpoint)
    }

    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        let mut bytes = vec![2];
        bytes.extend_from_slice(&self.state.commitment()?);
        match &self.bmm_endpoint {
            None if self.state.execution.height == 0 => bytes.push(0),
            Some(endpoint) if self.state.execution.height > 0 && endpoint.len() == 80
                && endpoint[..32] != [0;32] && endpoint[48..] != [0;32] => {
                bytes.push(1);
                bytes.extend_from_slice(endpoint);
            }
            _ => return Err(CheckpointError::Identity),
        }
        Ok(crate::tagged_hash("ECX/native-match-checkpoint/v2", &bytes))
    }

    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxMatchCheckpointV1 {
    pub execution: ChildExecutionCheckpointV3,
    pub exchange_state_root: Hash32,
    pub bindings_hash: Hash32,
    pub vault_outpoint: elements::OutPoint,
}

impl EcxMatchCheckpointV1 {
    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        if self.exchange_state_root == [0;32] || self.bindings_hash == [0;32]
            || self.vault_outpoint.is_null() { return Err(CheckpointError::Identity); }
        let mut bytes = vec![1];
        bytes.extend_from_slice(&self.execution.commitment()?);
        bytes.extend_from_slice(&self.exchange_state_root);
        bytes.extend_from_slice(&self.bindings_hash);
        // Consensus outpoint bytes, not display-order txid or native memory.
        bytes.extend(elements::encode::serialize(&self.vault_outpoint));
        Ok(crate::tagged_hash("ECX/native-match-checkpoint/v1", &bytes))
    }

    /// Expected must be independently frozen or prior-receipt authenticated.
    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
}
