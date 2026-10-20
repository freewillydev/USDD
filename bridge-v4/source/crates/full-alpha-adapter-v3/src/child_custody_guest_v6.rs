//! Full-anchor custody relation. Legacy execution is an internal projection,
//! never a substitute for this relation's frozen checkpoint or source binding.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{Hash32, FullAlphaReceiptVerifierV3};
use crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV5;
use crate::child_custody_guest_v4::{CustodyExecutionInputV4, CustodyExecutionOutputV4,
    execute_owned_custody_projection, encode_custody_execution_input_v4};
use crate::child_execution_guest_v3::{AlphaChildExecutionErrorV3 as E,
    AlphaChildExecutionPublicValuesV3, ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3};
use crate::child_execution_guest_v4::{AlphaChildExecutionErrorV4 as Error,
    MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4};
use crate::native_bmm_anchor_v1::NativeBmmAnchorV1;

pub const CUSTODY_EXECUTION_VERSION_V6: u8 = 0xae;

/// Shared with the lineage consumer; the execution proof authenticates the
/// projection opening, while the lineage independently pins all other roots.
pub fn source_binding_v6(projection_binding: Hash32, predecessor: Hash32) -> Result<Hash32,E> {
    if [projection_binding, predecessor].contains(&[0;32]) { return Err(E::Binding); }
    let mut bytes = vec![CUSTODY_EXECUTION_VERSION_V6];
    bytes.extend_from_slice(&projection_binding);
    bytes.extend_from_slice(&predecessor);
    Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-binding/v6", &bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionInputV6 {
    pub version: u8,
    pub checkpoint: ChildCustodyExecutionCheckpointV5,
    /// Exact 80-byte headers, excluding prior Q and including current P.
    /// The complete transport is bounded before any parent authentication.
    pub ancestry: Vec<Vec<u8>>,
    pub execution: CustodyExecutionInputV4,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64)
}

impl CustodyExecutionInputV6 {
    pub fn source_binding(&self) -> Result<Hash32,E> {
        let predecessor = self.checkpoint.commitment().map_err(|_| E::Binding)?;
        if self.checkpoint.projection != self.execution.checkpoint
            || self.execution.checkpoint.commitment().map_err(|_| E::Binding)?
                != self.execution.binding.roots.execution.predecessor_checkpoint {
            return Err(E::Binding);
        }
        source_binding_v6(self.execution.binding.commitment()?, predecessor)
    }

    fn check_shape(&self) -> Result<(),E> {
        if self.version != CUSTODY_EXECUTION_VERSION_V6
            || self.ancestry.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 / 80
            || self.ancestry.iter().any(|h| h.len() != 80)
            || options().serialized_size(self).map_err(|_| E::Input)?
                > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64 { return Err(E::Input); }
        self.source_binding()?;
        encode_custody_execution_input_v4(&self.execution)?;
        Ok(())
    }
}

pub fn encode_custody_execution_input_v6(input: &CustodyExecutionInputV6) -> Result<Vec<u8>,E> {
    input.check_shape()?;
    options().serialize(input).map_err(|_| E::Input)
}

pub fn decode_custody_execution_input_v6(bytes: &[u8]) -> Result<CustodyExecutionInputV6,E> {
    if bytes.first() != Some(&CUSTODY_EXECUTION_VERSION_V6)
        || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 { return Err(E::Input); }
    let input = options().deserialize(bytes).map_err(|_| E::Input)?;
    if encode_custody_execution_input_v6(&input)? != bytes { return Err(E::Input); }
    Ok(input)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyExecutionPublicValuesV6(pub AlphaChildExecutionPublicValuesV3);
impl CustodyExecutionPublicValuesV6 {
    pub fn canonical_bytes(self) -> [u8;ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] {
        let mut bytes = self.0.canonical_bytes(); bytes[0] = CUSTODY_EXECUTION_VERSION_V6; bytes
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self,E> {
        if bytes.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || bytes[0] != CUSTODY_EXECUTION_VERSION_V6 { return Err(E::Input); }
        let mut layout = bytes.to_vec();
        layout[0] = crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_VERSION_V3;
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&layout).map(Self)
    }
}

pub struct CustodyExecutionOutputV6 {
    projection: CustodyExecutionOutputV4,
    checkpoint: ChildCustodyExecutionCheckpointV5,
    public_values: CustodyExecutionPublicValuesV6,
}
impl CustodyExecutionOutputV6 {
    pub fn checked(&self) -> &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3 {
        self.projection.checked()
    }
    pub fn checkpoint(&self) -> &ChildCustodyExecutionCheckpointV5 { &self.checkpoint }
    pub fn public_values(&self) -> CustodyExecutionPublicValuesV6 { self.public_values }
}

/// The caller must pin the V6 source binding/guest independently. A legacy
/// receipt is not accepted: current P/Q is authenticated and sequence checked
/// before transaction execution, including blocks without evaluator inputs.
pub fn execute_owned_custody_v6<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &CustodyExecutionInputV6, parent_verifier: &P, simplicity: &S,
) -> Result<CustodyExecutionOutputV6,Error> {
    let (projection, checkpoint) = execute_full_anchor_projection(input, parent_verifier, simplicity, None)?;
    let mut statement = projection.public_values().0;
    statement.source_binding = input.source_binding()?;
    statement.predecessor_checkpoint = input.checkpoint.commitment().map_err(|_| E::Binding)?;
    statement.next_checkpoint = checkpoint.commitment().map_err(|_| E::Binding)?;
    let public_values = CustodyExecutionPublicValuesV6(statement);
    CustodyExecutionPublicValuesV6::from_canonical_bytes(&public_values.canonical_bytes())?;
    Ok(CustodyExecutionOutputV6 { projection, checkpoint, public_values })
}

/// Shared anchor authentication, not a public legacy receipt constructor.
pub(crate) fn execute_full_anchor_projection<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &CustodyExecutionInputV6, parent_verifier: &P, simplicity: &S,
    policy: Option<&crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4>,
) -> Result<(CustodyExecutionOutputV4, ChildCustodyExecutionCheckpointV5),Error> {
    input.check_shape()?;
    let frozen = input.checkpoint.commitment().map_err(|_| E::Binding)?;
    let inner = &input.execution;
    let (parent, anchor) = NativeBmmAnchorV1::authenticate(&inner.parent,
        inner.binding.roots.execution.parent_binding, parent_verifier).map_err(|_| E::Binding)?;
    let headers = input.ancestry.iter().map(|h| h.as_slice().try_into().map_err(|_| E::Input))
        .collect::<Result<Vec<[u8;80]>,E>>()?;
    input.checkpoint.require_next_anchor(frozen, &anchor, &headers).map_err(|_| E::Binding)?;
    let projection = execute_owned_custody_projection(inner, parent_verifier, simplicity, policy)?;
    if projection.checked().parent() != &parent { return Err(E::Binding.into()); }
    let checkpoint = ChildCustodyExecutionCheckpointV5 {
        projection: projection.checkpoint().clone(),
        full_anchor: Some(anchor.canonical_bytes().to_vec()),
    };
    Ok((projection, checkpoint))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::conversion_parent_link_v3::tests::TranscriptVerifier;

    // Called by the existing successful owned Alpha-shaped fixture. Its parent
    // receipts and initial checkpoint are synthetic, not a live qualification.
    pub(crate) fn qualify_anchor_wrapper<S:
        ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
        original: &CustodyExecutionInputV4,
        domain: &crate::custody_redemption_statement_v2::RedemptionDomainV2, simplicity: &S,
    ) {
        // The new internal projection must reject a historical effective
        // configuration, even when all other owned inputs are well formed.
        // These failures must happen before a recursive receipt is consumed.
        let mut policy = crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4 {
            base: original.policy.clone(), explicit_reissuance_height: None,
        };
        let untouched = TranscriptVerifier::for_inputs([]);
        assert!(crate::child_custody_guest_v4::execute_owned_custody_projection(
            original, &untouched, simplicity, Some(&policy)).is_err());
        untouched.assert_consumed();
        policy.base.consensus_configuration_commitment[0] ^= 1;
        let untouched = TranscriptVerifier::for_inputs([]);
        assert!(crate::child_custody_guest_v4::execute_owned_custody_projection(
            original, &untouched, simplicity, Some(&policy)).is_err());
        untouched.assert_consumed();
        let (_, current) = NativeBmmAnchorV1::authenticate(&original.parent,
            original.binding.roots.execution.parent_binding,
            &TranscriptVerifier::for_input(&original.parent)).unwrap();
        let wire = current.canonical_bytes();
        let mut prior = wire;
        // Construct a synthetic prior anchor whose Q is exactly current P.
        prior[33..65].copy_from_slice(&wire[1..33]);
        prior[97..129].copy_from_slice(&wire[65..97]);
        prior[133..137].copy_from_slice(&wire[129..133]);
        let p_height = u32::from_be_bytes(wire[129..133].try_into().unwrap());
        prior[129..133].copy_from_slice(&p_height.checked_sub(1).unwrap().to_be_bytes());
        prior[1..33].fill(42);
        for byte in prior[65..97].iter_mut().rev() {
            let (next, borrow) = byte.overflowing_sub(1); *byte = next;
            if !borrow { break; }
        }
        let prior = NativeBmmAnchorV1::from_canonical_bytes(&prior).unwrap();
        assert!(current.follows_with_ancestry(&prior, &[]));
        let rebind = |anchor: &NativeBmmAnchorV1| {
            let mut execution = original.clone();
            execution.checkpoint.bmm_endpoint = Some(anchor.parent_endpoint().to_vec());
            let frozen = execution.checkpoint.commitment().unwrap();
            execution.binding.roots.execution.predecessor_checkpoint = frozen;
            let history = crate::native_header_v3::NativeHeader::decode(
                execution.history.last().unwrap(), true).unwrap();
            let mut environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
                &execution.environment).unwrap();
            environment.bind_custody_checkpoint_projection(&execution.checkpoint, frozen, &history).unwrap();
            execution.environment = environment.encode().unwrap();
            execution.binding.roots.environment = environment.commitment().unwrap();
            CustodyExecutionInputV6 {
                version: CUSTODY_EXECUTION_VERSION_V6,
                checkpoint: ChildCustodyExecutionCheckpointV5 {
                    projection: execution.checkpoint.clone(), full_anchor: Some(anchor.canonical_bytes().to_vec()),
                }, ancestry: vec![], execution,
            }
        };
        let input = rebind(&prior);
        let bytes = encode_custody_execution_input_v6(&input).unwrap();
        assert_eq!(decode_custody_execution_input_v6(&bytes).unwrap(), input);
        assert!(crate::child_custody_guest_v4::decode_custody_execution_input_v4(&bytes).is_err());
        assert!(decode_custody_execution_input_v6(
            &encode_custody_execution_input_v4(&input.execution).unwrap()).is_err());
        let mut changed = bytes.clone(); changed.push(0);
        assert!(decode_custody_execution_input_v6(&changed).is_err());
        assert!(decode_custody_execution_input_v6(&bytes[..bytes.len()-1]).is_err());
        let verifier = TranscriptVerifier::for_inputs([&input.execution.parent;4]);
        let output = execute_owned_custody_v6(&input, &verifier, simplicity).unwrap();
        verifier.assert_consumed();
        assert_eq!(output.checkpoint.full_anchor, Some(current.canonical_bytes().to_vec()));
        qualify_accounting(&input, &output, domain, simplicity);
        let statement = output.public_values();
        crate::child_custody_guest_v7::tests::qualify_transport(&input, statement.0, domain, simplicity);
        assert_eq!(statement.0.predecessor_checkpoint, input.checkpoint.commitment().unwrap());
        assert_eq!(statement.0.next_checkpoint, output.checkpoint.commitment().unwrap());
        assert_eq!(statement.0.source_binding, input.source_binding().unwrap());
        assert_ne!(statement.0.source_binding, input.execution.binding.commitment().unwrap());
        assert_eq!(CustodyExecutionPublicValuesV6::from_canonical_bytes(&statement.canonical_bytes()).unwrap(), statement);
        assert!(crate::child_custody_guest_v4::CustodyExecutionPublicValuesV4::from_canonical_bytes(
            &statement.canonical_bytes()).is_err());
        // With no evaluator receipts, a fully re-committed reused anchor must
        // reject after parent authentication, before legacy transaction execution.
        let reused = rebind(&current);
        let verifier = TranscriptVerifier::for_input(&reused.execution.parent);
        assert!(matches!(execute_owned_custody_v6(&reused, &verifier, simplicity),
            Err(Error::Execution(E::Binding))));
        verifier.assert_consumed();
        let mut substituted = input.clone();
        substituted.checkpoint.full_anchor = Some(current.canonical_bytes().to_vec());
        assert!(encode_custody_execution_input_v6(&substituted).is_err());
        let mut malformed = input.clone(); malformed.ancestry.push(vec![0;79]);
        assert!(encode_custody_execution_input_v6(&malformed).is_err());
        let mut extra = input.clone(); extra.ancestry.push(vec![0;80]);
        let verifier = TranscriptVerifier::for_input(&extra.execution.parent);
        assert!(matches!(execute_owned_custody_v6(&extra, &verifier, simplicity),
            Err(Error::Execution(E::Binding))));
        verifier.assert_consumed();
    }

    fn qualify_accounting<S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
        input: &CustodyExecutionInputV6, output: &CustodyExecutionOutputV6,
        domain: &crate::custody_redemption_statement_v2::RedemptionDomainV2, simplicity: &S,
    ) {
        use crate::custody_child_lineage_v2::*;
        use crate::custody_execution_v2::*;
        use crate::custody_execution_wire_v2::*;
        let extracted = crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v6(
            domain,crate::custody_burn_v2::tests::fixture_verifier_address(),domain.custody_id,output,1,0).unwrap();
        assert_eq!(extracted.checkpoint(), output.checkpoint().commitment().unwrap());
        assert_ne!(extracted.checkpoint(), output.checkpoint().projection.commitment().unwrap());
        let inner = &input.execution;
        let roots = &inner.binding.roots;
        let lineage = CustodyAccountingLineagePolicyV4 {
            genesis_initialization: inner.binding.genesis_initialization,
            roots: CustodyChildLineagePolicyV5 {
                execution: CustodyChildLineagePolicyV2 {
                    execution_program:[42;32], initial_checkpoint:input.checkpoint.commitment().unwrap(),
                    initial_height:input.checkpoint.projection.execution.height,
                    parent_binding:roots.execution.parent_binding, execution_policy:roots.execution.execution_policy,
                    simplicity_program:roots.execution.simplicity_evaluator_program_id,
                    deposit_configuration:roots.execution.deposit_configuration,
                }, evaluator_source_closure:roots.evaluator_source_closure,
                genesis_bindings:roots.genesis_bindings, successor:roots.successor,
            },
        };
        assert_eq!(custody_accounting_binding_v6(&lineage,input.checkpoint.commitment().unwrap(),
            inner.checkpoint.commitment().unwrap(),roots.environment).unwrap(),input.source_binding().unwrap());
        // Exact-byte TEST receipt verifier, not a production cryptographic verifier.
        struct Exact { bytes: Vec<u8>, calls: std::cell::Cell<u32> }
        impl FullAlphaReceiptVerifierV3 for Exact {
            fn verify(&self, id: Hash32, values: &[u8], marker: &[u8]) -> Result<(),crate::FullAlphaAdapterErrorV3> {
                if id != [42;32] || values != self.bytes || marker != [1] {
                    return Err(crate::FullAlphaAdapterErrorV3::Receipt);
                }
                self.calls.set(self.calls.get()+1); Ok(())
            }
        }
        let receipt = CustodyAccountingLineageReceiptV6 {
            projection_predecessor:inner.checkpoint.commitment().unwrap(), environment:roots.environment,
            receipt:crate::AlphaRecursiveReceiptBindingV3 {
                public_values:output.public_values().canonical_bytes().to_vec(), proof_marker:vec![1],
            },
        };
        let exact = Exact {bytes:receipt.receipt.public_values.clone(),calls:std::cell::Cell::new(0)};
        let terminal = output.checkpoint().commitment().unwrap();
        let height = output.checkpoint().projection.execution.height;
        verify_custody_accounting_lineage_v6(&lineage,&[receipt.clone()],terminal,height,&exact).unwrap();
        assert_eq!(exact.calls.get(),1);
        for field in 0..4 {
            let mut bad = receipt.clone();
            match field {
                0 => bad.projection_predecessor[0] ^= 1,
                1 => bad.environment[0] ^= 1,
                2 => bad.receipt.public_values[0] = crate::child_custody_guest_v4::CUSTODY_EXECUTION_VERSION_V4,
                _ => bad.receipt.proof_marker[0] ^= 1,
            }
            assert!(verify_custody_accounting_lineage_v6(&lineage,&[bad],terminal,height,&exact).is_err());
        }
        assert!(verify_custody_accounting_lineage_v6(&lineage,&[],terminal,height,&exact).is_err());
        // Full history composition once; both carry modes already exercise
        // extraction and nonempty lineage above.
        if roots.successor.is_some() { return; }
        let mut steps = Vec::new();
        let approval = crate::conversion_parent_link_v3::tests::approve_checkpoint_after_fixture(
            inner.parent.clone(),domain.custody_id,extracted.checkpoint(),|s| steps.push(s.clone()));
        let approval_index = steps.len()-1;
        let approval_transaction = approval.approval().transaction_id;
        let confirmed = crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2::new(approval);
        let history = crate::custody_history_wire_v2::CustodyHistoryWitnessV2 {
            version:crate::custody_history_wire_v2::CUSTODY_HISTORY_VERSION_V2,
            steps,approval_index:approval_index as u32,approval_transaction,approval_bundle:None,
        };
        let policy = CustodyAccountingExecutionPolicyV6 {roots:CustodyAccountingExecutionPolicyV4 {
            domain:domain.clone(),verifier_address:crate::custody_burn_v2::tests::fixture_verifier_address(),child_execution_binding:input.source_binding().unwrap(),
            lineage,observation_time:inner.observation_time,destination_state:confirmed.state(),
            destination_anchor:confirmed.anchor(),minimum_confirmations:1,
        }};
        assert_ne!(policy.commitment().unwrap(),policy.roots.commitment().unwrap());
        assert_ne!(policy.release_commitment().unwrap(),policy.roots.release_commitment().unwrap());
        let witness = CustodyAccountingWitnessV6 {
            version:CUSTODY_ACCOUNTING_WIRE_VERSION_V6,policy:policy.clone(),child:input.clone(),
            history:history.clone(),lineage_receipts:vec![],transaction_index:1,output_index:0,
        };
        let wire = encode_custody_accounting_v6(&witness).unwrap();
        let decoded = decode_custody_accounting_v6(&wire).unwrap();
        assert_eq!(encode_custody_accounting_v6(&decoded).unwrap(),wire);
        assert!(decode_custody_accounting_v4(&wire).is_err());
        let mut bad = wire.clone();bad.push(0);
        assert!(decode_custody_accounting_v6(&bad).is_err());
        bad = wire.clone();bad[0] = CUSTODY_ACCOUNTING_WIRE_VERSION_V4;
        assert!(decode_custody_accounting_v6(&bad).is_err());
        assert!(decode_custody_accounting_v6(&wire[..wire.len()-1]).is_err());
        let verifier = TranscriptVerifier::for_inputs([&inner.parent;4].into_iter()
            .chain(history.steps.iter()).chain(std::iter::once(&history.steps[approval_index])));
        let composed = execute_custody_accounting_v6(&decoded.policy,&decoded.child,&decoded.history,
            &decoded.lineage_receipts,1,0,&verifier,simplicity).unwrap();
        verifier.assert_consumed();
        let verifier = TranscriptVerifier::for_inputs(history.steps.iter()
            .chain(std::iter::once(&history.steps[approval_index])));
        let (cursor,confirmed) = extracted.finish_history(&history.steps,approval_index,approval_transaction,&verifier).unwrap();
        verifier.assert_consumed();
        let statement = cursor.checked_statement(domain,crate::custody_burn_v2::tests::fixture_verifier_address(),&confirmed,policy.roots.destination_state,
            policy.roots.destination_anchor,1).unwrap();
        assert_eq!(&composed.canonical_bytes()[32..],&statement);
        assert_eq!(&composed.extended_bytes_v3()[..32],&policy.release_commitment().unwrap());
    }
}
