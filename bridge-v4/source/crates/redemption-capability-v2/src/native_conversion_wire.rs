//! Owned native final-conversion transport. Decoding is not authentication.
//! The caller must independently pin the whole policy commitment at execution.
use super::*;
use super::native_alpha::{NativeRedemptionPolicyV3,NativeRedemptionEvidenceV3};
use ecx_full_alpha_adapter_v3::{AlphaRecursiveReceiptBindingV3,FullAlphaStatementV3,
    FullAlphaReceiptVerifierV3,child_execution_state_v3::ChildExecutionCheckpointV3,
    native_conversion_accounting_v3::ConversionAccountingBindingV3,
    native_conversion_source_v3::{NativeConversionSourceBindingV3,NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3},
    native_checkpoint_lineage_v3::{NativeCheckpointLineageStepV3,MAX_NATIVE_CHECKPOINT_LINEAGE_STEPS_V3}};

pub const NATIVE_CONVERSION_INPUT_VERSION_V3:u8=0xa8;
pub const MAX_NATIVE_CONVERSION_INPUT_BYTES_V3:usize=128*1024*1024;

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConversionPolicyInputV3 {
    pub source_program:[u8;32],
    pub source_commitment:[u8;32],
    pub covenant_commitment:[u8;32],
    pub source:NativeConversionSourceBindingV3,
    pub public_pool:public_pool::FrozenPublicPoolProgramV3,
    pub deployment_checkpoint:[u8;32],
    pub checkpoint_lineage:Vec<NativeConversionSourceBindingV3>,
}
impl NativeConversionPolicyInputV3 {
    pub fn as_policy(&self)->NativeRedemptionPolicyV3<'_> {
        NativeRedemptionPolicyV3 {source_program:self.source_program,source_commitment:self.source_commitment,
            covenant_commitment:self.covenant_commitment,source:&self.source,public_pool:&self.public_pool,
            deployment_checkpoint:self.deployment_checkpoint,checkpoint_lineage:&self.checkpoint_lineage}
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConversionStepInputV3 {
    pub receipt:AlphaRecursiveReceiptBindingV3,
    pub observation:FullAlphaStatementV3,
    pub successor:ChildExecutionCheckpointV3,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConversionInputV3 {
    pub version:u8,
    pub policy:NativeConversionPolicyInputV3,
    pub current:NativeConversionStepInputV3,
    pub accounting:ConversionAccountingBindingV3,
    pub deployment:EcxBtcCovenantDeploymentV2,
    pub deployment_checkpoint:ChildExecutionCheckpointV3,
    pub checkpoint_lineage:Vec<NativeConversionStepInputV3>,
    pub lineage_blocks:Vec<Vec<u8>>,
    pub initial_inventory:AuthenticatedEconomicLeafV2,
    pub initial_reserve:AuthenticatedEconomicLeafV2,
    pub inventory:AuthenticatedEconomicLeafV2,
    pub reserve:AuthenticatedEconomicLeafV2,
    pub holder_base_input:ElementsEconomicLeafWireV2,
    pub probe_transaction:Vec<u8>,
    pub probe_outputs:Vec<ElementsEconomicLeafWireV2>,
    pub simplicity_receipts:Vec<ElementsSimplicityReceiptBindingV2>,
}
impl NativeConversionInputV3 {
    fn check_shape(&self)->Result<(),RedemptionCapabilityErrorV2> {
        use RedemptionCapabilityErrorV2::NonCanonicalInput;
        if self.version!=NATIVE_CONVERSION_INPUT_VERSION_V3
            || self.checkpoint_lineage.len()>MAX_NATIVE_CHECKPOINT_LINEAGE_STEPS_V3
            || self.checkpoint_lineage.len()!=self.policy.checkpoint_lineage.len()
            || self.lineage_blocks.len()!=self.checkpoint_lineage.len()+1
            || self.lineage_blocks.iter().any(|b|b.is_empty() || b.len()>ecx_full_alpha_adapter_v3::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES)
            || self.probe_transaction.is_empty() || !(2..=3).contains(&self.probe_outputs.len())
            || self.simplicity_receipts.len()!=2
            || self.deployment.simplicity_program_bytes.is_empty() {
            return Err(NonCanonicalInput);
        }
        for step in self.checkpoint_lineage.iter().chain(std::iter::once(&self.current)) {
            if step.receipt.public_values.len()!=NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3
                || step.receipt.proof_marker.is_empty()
                || step.receipt.proof_marker.len()>ecx_full_alpha_adapter_v3::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 {
                return Err(NonCanonicalInput);
            }
        }
        self.policy.as_policy().commitment()?;
        if wire_options().serialized_size(self).map_err(|_|NonCanonicalInput)? > MAX_NATIVE_CONVERSION_INPUT_BYTES_V3 as u64 {
            return Err(NonCanonicalInput);
        }
        Ok(())
    }
}
fn wire_options()->impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
        .with_limit(MAX_NATIVE_CONVERSION_INPUT_BYTES_V3 as u64).reject_trailing_bytes()
}
pub fn encode_native_conversion_input_v3(input:&NativeConversionInputV3)->Result<Vec<u8>,RedemptionCapabilityErrorV2> {
    input.check_shape()?;
    wire_options().serialize(input).map_err(|_|RedemptionCapabilityErrorV2::NonCanonicalInput)
}
pub fn decode_native_conversion_input_v3(bytes:&[u8])->Result<NativeConversionInputV3,RedemptionCapabilityErrorV2> {
    use RedemptionCapabilityErrorV2::NonCanonicalInput;
    if bytes.first()!=Some(&NATIVE_CONVERSION_INPUT_VERSION_V3) || bytes.len()>MAX_NATIVE_CONVERSION_INPUT_BYTES_V3 {
        return Err(NonCanonicalInput);
    }
    let input:NativeConversionInputV3=wire_options().deserialize(bytes).map_err(|_|NonCanonicalInput)?;
    if encode_native_conversion_input_v3(&input)?!=bytes {return Err(NonCanonicalInput);}
    Ok(input)
}
pub fn execute_native_conversion_input_v3(expected_policy:[u8;32],input:&NativeConversionInputV3,
    source_verifier:&impl FullAlphaReceiptVerifierV3,simplicity_verifier:&impl ElementsSimplicityReceiptVerifierV2,
) -> Result<ecx_conversion_foundation_v2::ecx_btc::EcxBtcConversionPublicValuesV2,RedemptionCapabilityErrorV2> {
    input.check_shape()?;
    let steps:Vec<_>=input.checkpoint_lineage.iter().map(|s|NativeCheckpointLineageStepV3 {
        receipt:&s.receipt,observation:&s.observation,successor:&s.successor}).collect();
    let evidence=NativeRedemptionEvidenceV3 {
        source_receipt:&input.current.receipt,observation:&input.current.observation,successor:&input.current.successor,
        accounting:&input.accounting,deployment:&input.deployment,deployment_checkpoint:&input.deployment_checkpoint,
        checkpoint_lineage:&steps,lineage_blocks:&input.lineage_blocks,
        initial_inventory:&input.initial_inventory,initial_reserve:&input.initial_reserve,
        inventory:&input.inventory,reserve:&input.reserve,
        probe:RedemptionProbeV3 {public_values:&input.current.receipt.public_values,
            simplicity_program_bytes:&input.deployment.simplicity_program_bytes,holder_base_input:&input.holder_base_input,
            probe_transaction:&input.probe_transaction,probe_outputs:&input.probe_outputs,simplicity_receipts:&input.simplicity_receipts},
    };
    super::native_alpha::execute_native_conversion_v3(expected_policy,&input.policy.as_policy(),&evidence,
        source_verifier,simplicity_verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_transport_rejects_wrong_versions_and_truncation() {
        for bytes in [vec![],vec![2],vec![0xa7],vec![0xa8],vec![0xa8;64]] {
            assert!(decode_native_conversion_input_v3(&bytes).is_err());
        }
    }
}
