//! Full-anchor custody with separately committed explicit-reissuance policy.
//! V6 is only a transport projection; neither its journal nor its source hash
//! can stand in for this relation.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{Hash32, FullAlphaReceiptVerifierV3};
use crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV5;
use crate::child_custody_guest_v6::{CustodyExecutionInputV6,
    encode_custody_execution_input_v6, execute_full_anchor_projection};
use crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4;
use crate::child_execution_guest_v3::{AlphaChildExecutionErrorV3 as E,
    AlphaChildExecutionPublicValuesV3, ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3};
use crate::child_execution_guest_v4::{AlphaChildExecutionErrorV4 as Error,
    MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4};

pub const CUSTODY_EXECUTION_VERSION_V7: u8 = 0xaf;

pub fn source_binding_v7(anchor_binding: Hash32, policy: Hash32) -> Result<Hash32,E> {
    if [anchor_binding, policy].contains(&[0;32]) { return Err(E::Binding); }
    let mut bytes = vec![CUSTODY_EXECUTION_VERSION_V7];
    bytes.extend_from_slice(&anchor_binding);
    bytes.extend_from_slice(&policy);
    Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-binding/v7", &bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionInputV7 {
    pub version: u8,
    pub anchor: CustodyExecutionInputV6,
    pub policy: ChildCustodyExecutionPolicyV4,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64)
}

impl CustodyExecutionInputV7 {
    pub fn source_binding(&self) -> Result<Hash32,E> {
        let inner = &self.anchor.execution;
        if self.policy.base != inner.policy { return Err(E::Binding); }
        self.policy.require_frozen(inner.binding.roots.execution.execution_policy,
            &inner.checkpoint.execution).map_err(|_| E::Binding)?;
        crate::effective_child_configuration_v1::EffectiveChildConfigurationV2::from_policies(
            &self.policy, &inner.header_policy, &inner.deposit_policy,
        ).map_err(|_| E::Binding)?
            .require_bound(inner.policy.consensus_configuration_commitment)
            .map_err(|_| E::Binding)?;
        source_binding_v7(self.anchor.source_binding()?,
            self.policy.commitment().map_err(|_| E::Binding)?)
    }

    fn check_shape(&self) -> Result<(),E> {
        if self.version != CUSTODY_EXECUTION_VERSION_V7
            || options().serialized_size(self).map_err(|_| E::Input)?
                > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64 { return Err(E::Input); }
        encode_custody_execution_input_v6(&self.anchor)?;
        self.source_binding()?;
        Ok(())
    }
}

pub fn encode_custody_execution_input_v7(input: &CustodyExecutionInputV7) -> Result<Vec<u8>,E> {
    input.check_shape()?;
    options().serialize(input).map_err(|_| E::Input)
}

pub fn decode_custody_execution_input_v7(bytes: &[u8]) -> Result<CustodyExecutionInputV7,E> {
    if bytes.first() != Some(&CUSTODY_EXECUTION_VERSION_V7)
        || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 { return Err(E::Input); }
    let input = options().deserialize(bytes).map_err(|_| E::Input)?;
    if encode_custody_execution_input_v7(&input)? != bytes { return Err(E::Input); }
    Ok(input)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyExecutionPublicValuesV7(pub AlphaChildExecutionPublicValuesV3);
impl CustodyExecutionPublicValuesV7 {
    pub fn canonical_bytes(self) -> [u8;ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] {
        let mut bytes = self.0.canonical_bytes(); bytes[0] = CUSTODY_EXECUTION_VERSION_V7; bytes
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self,E> {
        if bytes.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || bytes[0] != CUSTODY_EXECUTION_VERSION_V7 { return Err(E::Input); }
        let mut layout = bytes.to_vec();
        layout[0] = crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_VERSION_V3;
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&layout).map(Self)
    }
}

pub struct CustodyExecutionOutputV7 {
    projection: crate::child_custody_guest_v4::CustodyExecutionOutputV4,
    checkpoint: ChildCustodyExecutionCheckpointV5,
    public_values: CustodyExecutionPublicValuesV7,
}
impl CustodyExecutionOutputV7 {
    pub fn checked(&self) -> &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3 {
        self.projection.checked()
    }
    pub fn checkpoint(&self) -> &ChildCustodyExecutionCheckpointV5 { &self.checkpoint }
    pub fn public_values(&self) -> CustodyExecutionPublicValuesV7 { self.public_values }
}

pub fn execute_owned_custody_v7<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &CustodyExecutionInputV7, parent_verifier: &P, simplicity: &S,
) -> Result<CustodyExecutionOutputV7,Error> {
    input.check_shape()?;
    let (projection, checkpoint) = execute_full_anchor_projection(
        &input.anchor, parent_verifier, simplicity, Some(&input.policy))?;
    let mut statement = projection.public_values().0;
    statement.source_binding = input.source_binding()?;
    statement.predecessor_checkpoint = input.anchor.checkpoint.commitment().map_err(|_| E::Binding)?;
    statement.next_checkpoint = checkpoint.commitment().map_err(|_| E::Binding)?;
    let public_values = CustodyExecutionPublicValuesV7(statement);
    CustodyExecutionPublicValuesV7::from_canonical_bytes(&public_values.canonical_bytes())?;
    Ok(CustodyExecutionOutputV7 { projection, checkpoint, public_values })
}

#[cfg(test)]
#[path = "child_custody_guest_v7_reissuance_tests.rs"]
mod reissuance_tests;

#[cfg(test)]
#[path = "child_custody_guest_v7_accounting_tests.rs"]
mod accounting_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Synthetic Alpha execution with transcript-authenticated parent receipts.
    // This is not a live checkpoint or recursive-proof qualification.
    pub(crate) fn qualify_transport<S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(original: &CustodyExecutionInputV6,
        statement: AlphaChildExecutionPublicValuesV3,
        domain: &crate::custody_redemption_statement_v2::RedemptionDomainV2, simplicity: &S) {
        let mut input = CustodyExecutionInputV7 {
            version: CUSTODY_EXECUTION_VERSION_V7, anchor: original.clone(),
            policy: ChildCustodyExecutionPolicyV4 {
                base: original.execution.policy.clone(), explicit_reissuance_height: None,
            },
        };
        assert!(encode_custody_execution_input_v7(&input).is_err());
        let hash = crate::effective_child_configuration_v1::EffectiveChildConfigurationV2::from_policies(
            &input.policy, &input.anchor.execution.header_policy,
            &input.anchor.execution.deposit_policy).unwrap().commitment();
        input.policy.base.consensus_configuration_commitment = hash;
        input.anchor.execution.policy = input.policy.base.clone();
        input.anchor.execution.checkpoint.execution.configuration_commitment = hash;
        input.anchor.execution.binding.roots.execution.execution_policy = input.policy.commitment().unwrap();
        input.anchor.execution.binding.roots.execution.predecessor_checkpoint =
            input.anchor.execution.checkpoint.commitment().unwrap();
        input.anchor.checkpoint.projection = input.anchor.execution.checkpoint.clone();
        input.anchor.execution.parent.binding.child_consensus_configuration_commitment = hash;
        input.anchor.execution.binding.roots.execution.parent_binding =
            input.anchor.execution.parent.binding.commitment().unwrap();
        let history = crate::native_header_v3::NativeHeader::decode(
            input.anchor.execution.history.last().unwrap(), true).unwrap();
        let mut environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            &input.anchor.execution.environment).unwrap();
        environment.bind_custody_checkpoint_projection(&input.anchor.execution.checkpoint,
            input.anchor.execution.checkpoint.commitment().unwrap(), &history).unwrap();
        input.anchor.execution.environment = environment.encode().unwrap();
        input.anchor.execution.binding.roots.environment = environment.commitment().unwrap();
        let bytes = encode_custody_execution_input_v7(&input).unwrap();
        assert_eq!(decode_custody_execution_input_v7(&bytes).unwrap(), input);
        let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
            [&input.anchor.execution.parent;4]);
        let output = execute_owned_custody_v7(&input, &verifier, simplicity).unwrap();
        verifier.assert_consumed();
        assert_eq!(output.public_values().0.source_binding, input.source_binding().unwrap());
        assert_eq!(output.public_values().0.predecessor_checkpoint, input.anchor.checkpoint.commitment().unwrap());
        assert_eq!(output.public_values().0.next_checkpoint, output.checkpoint().commitment().unwrap());
        assert_eq!(output.public_values().0.child_height, statement.child_height);
        assert_eq!(output.public_values().0.child_hash_internal, statement.child_hash_internal);
        super::accounting_tests::qualify_accounting(&input, &output, domain, simplicity);
        use crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v7;
        let extracted = extract_owned_accounting_checkpoint_v7(
            domain, crate::custody_burn_v2::tests::fixture_verifier_address(), domain.custody_id, &output, 1, 0).unwrap();
        assert_eq!(extracted.checkpoint(), output.checkpoint().commitment().unwrap());
        assert_ne!(extracted.checkpoint(), output.checkpoint().projection.commitment().unwrap());
        // Extraction must retain the frozen domain and select an actual checked burn.
        assert!(extract_owned_accounting_checkpoint_v7(
            domain, [18;20], domain.custody_id, &output, 1, 0).is_err());
        let mut wrong_custody = domain.custody_id; wrong_custody[0] ^= 1;
        assert!(extract_owned_accounting_checkpoint_v7(
            domain, crate::custody_burn_v2::tests::fixture_verifier_address(), wrong_custody, &output, 1, 0).is_err());
        assert!(extract_owned_accounting_checkpoint_v7(
            domain, crate::custody_burn_v2::tests::fixture_verifier_address(), domain.custody_id, &output, usize::MAX, 0).is_err());
        assert!(extract_owned_accounting_checkpoint_v7(
            domain, crate::custody_burn_v2::tests::fixture_verifier_address(), domain.custody_id, &output, 1, u32::MAX).is_err());
        super::reissuance_tests::qualify_reissuance(&input, simplicity);
        for field in 0..3 {
            let mut substituted = input.clone();
            match field {
                0 => substituted.policy.explicit_reissuance_height = Some(1),
                1 => substituted.anchor.execution.binding.roots.execution.execution_policy[0] ^= 1,
                _ => substituted.anchor.execution.policy.consensus_configuration_commitment[0] ^= 1,
            }
            let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([]);
            assert!(execute_owned_custody_v7(&substituted, &verifier, simplicity).is_err());
            verifier.assert_consumed();
        }
        assert!(crate::child_custody_guest_v6::decode_custody_execution_input_v6(&bytes).is_err());
        assert!(decode_custody_execution_input_v7(
            &encode_custody_execution_input_v6(original).unwrap()).is_err());
        let mut extra = bytes.clone(); extra.push(0);
        assert!(decode_custody_execution_input_v7(&extra).is_err());
        assert!(decode_custody_execution_input_v7(&bytes[..bytes.len()-1]).is_err());
        let mut changed = input.clone(); changed.policy.explicit_reissuance_height = Some(1);
        assert!(encode_custody_execution_input_v7(&changed).is_err());
        let mut changed = input.clone(); changed.anchor.ancestry.push(vec![0;79]);
        assert!(encode_custody_execution_input_v7(&changed).is_err());
        assert_ne!(input.source_binding().unwrap(), input.anchor.source_binding().unwrap());
        let public = CustodyExecutionPublicValuesV7(statement);
        assert_eq!(CustodyExecutionPublicValuesV7::from_canonical_bytes(&public.canonical_bytes()).unwrap(), public);
        assert!(crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6::from_canonical_bytes(
            &public.canonical_bytes()).is_err());
        assert!(CustodyExecutionPublicValuesV7::from_canonical_bytes(
            &crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6(statement).canonical_bytes()).is_err());
        assert!(source_binding_v7([0;32], [1;32]).is_err());
        assert!(source_binding_v7([1;32], [0;32]).is_err());
        assert_ne!(source_binding_v7([1;32], [2;32]).unwrap(), source_binding_v7([1;32], [3;32]).unwrap());
    }
}
