//! Header configuration component. Its commitment must be part of the frozen
//! execution policy; checkpoint authentication remains an enclosing obligation.
use crate::{native_child_context_v3::{NativeDynafedBootstrap,select_native_dynafed_parameters},
    child_execution_state_v3::ChildExecutionCheckpointV3,
    child_deployments_v3::{ChildDeploymentConfigurationV3,DeploymentStateV3},
    native_header_v3::NativeHeader};
use ecx_full_consensus_validator_v2::{Hash32,elements_v2::ElementsHeaderConsensusContextV2};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildHeaderPolicyV3 {
    pub bootstrap: NativeDynafedBootstrap,
    pub epoch_length: u32,
}

impl ChildHeaderPolicyV3 {
    /// Custody counterpart; caller must authenticate the checkpoint and clock.
    pub fn derive_custody_context(&self,expected:Hash32,
        checkpoint:&crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
        history:&[NativeHeader],deployments:ChildDeploymentConfigurationV3,
        observation_time:u64)->Result<ElementsHeaderConsensusContextV2,&'static str> {
        let mtp=checkpoint.checked_mtp_history(history).map_err(|_|"header history")?;
        self.derive_checked_context(expected,history,deployments,observation_time,
            checkpoint.height.checked_add(1).ok_or("header height")?,
            checkpoint.genesis_internal,checkpoint.history_commitment,checkpoint.tip_internal,&mtp)
    }
    /// Construct guest header context from committed history and policy rather
    /// than accepting witness-selected signing parameters. Observation time
    /// still requires authentication by the enclosing source relation.
    pub fn derive_context(&self, expected: Hash32, checkpoint: &ChildExecutionCheckpointV3,
        history: &[NativeHeader], deployments: ChildDeploymentConfigurationV3,
        observation_time: u64) -> Result<ElementsHeaderConsensusContextV2, &'static str> {
        let mtp = checkpoint.checked_mtp_history(history).map_err(|_|"header history")?;
        let height = checkpoint.height.checked_add(1).ok_or("header height")?;
        self.derive_checked_context(expected,history,deployments,observation_time,height,
            checkpoint.genesis_internal,checkpoint.history_commitment,checkpoint.tip_internal,&mtp)
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_checked_context(&self,expected:Hash32,history:&[NativeHeader],
        deployments:ChildDeploymentConfigurationV3,observation_time:u64,height:u32,
        genesis:Hash32,history_commitment:Hash32,tip:Hash32,mtp:&[NativeHeader],
    )->Result<ElementsHeaderConsensusContextV2,&'static str> {
        use elements::hashes::Hash;
        if expected==[0;32] || self.commitment()?!=expected { return Err("header policy binding"); }
        let active = deployments.dynafed.state_after_history(history, genesis,
            history_commitment).map_err(|_|"header deployment")? == DeploymentStateV3::Active;
        let (current, full) = if active {
            let age = height % self.epoch_length;
            let count = if age == 0 { self.epoch_length } else { age } as usize;
            let start = history.len().checked_sub(count).ok_or("header epoch history")?;
            let derived = select_native_dynafed_parameters(&history[start..], self.epoch_length,
                height, deployments.dynafed.start == -1, &self.bootstrap)
                .map_err(|_|"header epoch parameters")?;
            (Some(derived.expected_current), Some(derived.expected_full_current))
        } else { (None, None) };
        Ok(ElementsHeaderConsensusContextV2 {
            previous_block_hash: elements::BlockHash::from_byte_array(tip),
            next_height: height,
            previous_11_times: mtp.iter().map(|header|header.base.time).collect(),
            authenticated_adjusted_time: observation_time,
            expected_current_dynafed_params: current,
            expected_full_current_dynafed_params: full,
            legacy_signblock_challenge: self.bootstrap.legacy_challenge.clone(),
            legacy_signblock_witness_limit: self.bootstrap.maximum_signature_size,
        })
    }

    pub fn commitment(&self) -> Result<Hash32, &'static str> {
        if self.epoch_length == 0 { return Err("zero header epoch"); }
        // Consensus serialization is length-delimited, including extension items.
        let mut bytes = vec![3];
        bytes.extend_from_slice(&self.epoch_length.to_be_bytes());
        bytes.extend(elements::encode::serialize(&self.bootstrap.legacy_challenge));
        bytes.extend_from_slice(&self.bootstrap.maximum_signature_size.to_be_bytes());
        bytes.extend(elements::encode::serialize(&self.bootstrap.fedpeg_script));
        bytes.push(u8::from(self.bootstrap.start_p2wsh));
        bytes.extend(elements::encode::serialize(&self.bootstrap.first_extension_space));
        Ok(crate::tagged_hash("ECX/alpha-child-header-policy/v3",&bytes))
    }

    pub fn check_context(&self, expected:Hash32, checkpoint:&ChildExecutionCheckpointV3,
        history:&[NativeHeader], deployments:ChildDeploymentConfigurationV3,
        context:&ElementsHeaderConsensusContextV2) -> Result<(), &'static str> {
        use elements::hashes::Hash;
        if expected == [0;32] || self.commitment()? != expected {return Err("header policy binding");}
        let mtp = checkpoint.checked_mtp_history(history).map_err(|_|"header history")?;
        if context.previous_11_times != mtp.iter().map(|header|header.base.time).collect::<Vec<_>>() {
            return Err("header median time history");
        }
        let height = checkpoint.height.checked_add(1).ok_or("header height")?;
        if context.next_height != height
            || context.previous_block_hash.to_byte_array() != checkpoint.tip_internal {
            return Err("header predecessor");
        }
        let active = deployments.dynafed.state_after_history(history,checkpoint.genesis_internal,
            checkpoint.history_commitment).map_err(|_|"header deployment")? == DeploymentStateV3::Active;
        if !active {
            if context.expected_current_dynafed_params.is_some()
                || context.expected_full_current_dynafed_params.is_some()
                || context.legacy_signblock_challenge != self.bootstrap.legacy_challenge
                || context.legacy_signblock_witness_limit != self.bootstrap.maximum_signature_size {
                return Err("legacy header policy");
            }
        } else {
            let age = height % self.epoch_length;
            let count = if age == 0 {self.epoch_length} else {age} as usize;
            let start = history.len().checked_sub(count).ok_or("header epoch history")?;
            let derived = select_native_dynafed_parameters(&history[start..],self.epoch_length,height,
                deployments.dynafed.start == -1,&self.bootstrap).map_err(|_|"header epoch parameters")?;
            if context.expected_current_dynafed_params.as_ref() != Some(&derived.expected_current)
                || context.expected_full_current_dynafed_params.as_ref() != Some(&derived.expected_full_current) {
                return Err("dynafed header policy");
            }
        }
        Ok(())
    }
}
