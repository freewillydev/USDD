//! Frozen execution-policy component, not the full consensus configuration.
//! Header policy, deposit rules and concrete engine qualification remain
//! separate mandatory bindings in the enclosing source relation.
use ecx_full_consensus_validator_v2::{Hash32, elements_v2::ElementsEconomicClassificationV2};
use crate::{child_deployments_v3::ChildDeploymentConfigurationV3,
    child_execution_state_v3::ChildExecutionCheckpointV3, native_reward_v3::RewardParameters};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildExecutionPolicyV3 {
    pub genesis_internal: Hash32,
    pub consensus_configuration_commitment: Hash32,
    pub deployments: ChildDeploymentConfigurationV3,
    pub reward: RewardParameters,
    pub classification: ElementsEconomicClassificationV2,
    pub header_policy_commitment: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionPolicyErrorV3 { Parameters, FrozenCommitment, Checkpoint }

/// Custody-specific policy component. No inventory/reserve scripts or local
/// USDD-to-ECX conversion roles. Deposit and program bindings remain mandatory
/// in the enclosing source configuration, as does header-policy verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCustodyExecutionPolicyV3 {
    pub creation: crate::native_creation_policy_v1::NativeCreationPolicyV1,
    pub genesis_internal: Hash32,
    pub consensus_configuration_commitment: Hash32,
    pub deployments: ChildDeploymentConfigurationV3,
    pub reward: RewardParameters,
    pub classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3,
    pub header_policy_commitment: Hash32,
}

impl ChildCustodyExecutionPolicyV3 {
    pub fn commitment(&self)->Result<Hash32,ExecutionPolicyErrorV3> {
        let classification=self.classification.commitment().map_err(|_|ExecutionPolicyErrorV3::Parameters)?;
        let deployments=self.deployments.commitment().map_err(|_|ExecutionPolicyErrorV3::Parameters)?;
        let subsidy=self.reward.subsidy_asset.into_inner().to_byte_array();
        let identities=[self.genesis_internal,self.consensus_configuration_commitment,
            subsidy,classification,self.header_policy_commitment,deployments];
        if identities.contains(&[0;32]) || self.reward.halving_interval==0
            || self.reward.genesis_subsidy>2_100_000_000_000_000 {
            return Err(ExecutionPolicyErrorV3::Parameters);
        }
        let mut bytes=vec![3];
        for identity in identities { bytes.extend_from_slice(&identity); }
        bytes.extend_from_slice(&self.reward.genesis_subsidy.to_be_bytes());
        bytes.extend_from_slice(&self.reward.halving_interval.to_be_bytes());
        // V4 domain prevents reuse of pre-creation-policy frozen commitments.
        bytes[0] = 4;
        bytes.extend_from_slice(&self.creation.commitment());
        Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-policy/v4",&bytes))
    }
    pub fn require_frozen(&self,expected:Hash32,
        checkpoint:&crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    )->Result<(),ExecutionPolicyErrorV3> {
        if expected==[0;32] || self.commitment()?!=expected {
            return Err(ExecutionPolicyErrorV3::FrozenCommitment);
        }
        if self.genesis_internal!=checkpoint.genesis_internal
            || self.consensus_configuration_commitment!=checkpoint.configuration_commitment
            || self.classification!=checkpoint.classification {
            return Err(ExecutionPolicyErrorV3::Checkpoint);
        }
        Ok(())
    }
}

/// Explicit reissuance is a new frozen policy, never an extension silently
/// decoded under the historical V3 wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCustodyExecutionPolicyV4 {
    pub base: ChildCustodyExecutionPolicyV3,
    pub explicit_reissuance_height: Option<u32>,
}

impl ChildCustodyExecutionPolicyV4 {
    pub fn creation(&self) -> crate::native_creation_policy_v1::NativeCreationPolicyV2 {
        crate::native_creation_policy_v1::NativeCreationPolicyV2 {
            creation: self.base.creation,
            explicit_reissuance_height: self.explicit_reissuance_height,
        }
    }

    pub fn commitment(&self) -> Result<Hash32, ExecutionPolicyErrorV3> {
        let mut bytes = vec![5];
        bytes.extend_from_slice(&self.base.commitment()?);
        bytes.extend_from_slice(&self.creation().commitment()
            .map_err(|_| ExecutionPolicyErrorV3::Parameters)?);
        Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-policy/v5", &bytes))
    }

    pub fn require_frozen(&self, expected: Hash32,
        checkpoint: &crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    ) -> Result<(), ExecutionPolicyErrorV3> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(ExecutionPolicyErrorV3::FrozenCommitment);
        }
        self.base.require_frozen(self.base.commitment()?, checkpoint)
    }
}

impl ChildExecutionPolicyV3 {
    pub fn commitment(&self) -> Result<Hash32, ExecutionPolicyErrorV3> {
        let c = self.classification;
        let subsidy = self.reward.subsidy_asset.into_inner().to_byte_array();
        let identities = [self.genesis_internal,self.consensus_configuration_commitment,
            subsidy,c.base_asset_id,c.policy_asset_id,c.redemption_inventory_script_sha256,
            c.reserve_script_sha256,self.header_policy_commitment];
        if identities.contains(&[0;32]) || c.base_asset_id == c.policy_asset_id
            || c.redemption_inventory_script_sha256 == c.reserve_script_sha256
            || self.reward.halving_interval == 0
            || self.reward.genesis_subsidy > 2_100_000_000_000_000 {
            return Err(ExecutionPolicyErrorV3::Parameters);
        }
        let deployment = self.deployments.commitment().map_err(|_|ExecutionPolicyErrorV3::Parameters)?;
        let mut bytes = vec![3];
        for identity in identities { bytes.extend_from_slice(&identity); }
        bytes.extend_from_slice(&deployment);
        bytes.extend_from_slice(&self.reward.genesis_subsidy.to_be_bytes());
        bytes.extend_from_slice(&self.reward.halving_interval.to_be_bytes());
        Ok(crate::tagged_hash("ECX/alpha-child-execution-policy/v3",&bytes))
    }

    /// `expected` is a separate, independently frozen source-profile binding.
    /// The consensus hash is cross-bound, not derived from this partial policy.
    pub fn require_frozen(&self, expected: Hash32, checkpoint: &ChildExecutionCheckpointV3)
        -> Result<(),ExecutionPolicyErrorV3> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(ExecutionPolicyErrorV3::FrozenCommitment);
        }
        if self.genesis_internal != checkpoint.genesis_internal
            || self.consensus_configuration_commitment != checkpoint.configuration_commitment {
            return Err(ExecutionPolicyErrorV3::Checkpoint);
        }
        Ok(())
    }
}
