//! Native Alpha block commitment foundation, NOT complete child consensus.
//! Validates the complete serialized transaction-list commitment and derives
//! withdrawal state. Header authorization, UTXO/script/issuance/deposit rules,
//! time/frontier rules and authenticated predecessor state are still required.
use bitcoin::hashes::Hash;
use elements::{Block, BlockHash, Transaction};
use ecx_full_consensus_validator_v2::{Hash32, elements_v2::elements_transaction_merkle_root_v2};
use super::native_child_commitment_v3::extract_parent_hash;
use super::native_withdrawal_accumulator_v3::{WithdrawalAccumulator, critical_hash_internal};
use super::native_withdrawal_extraction_v3::{WithdrawalClaim, apply_withdrawals};
use super::native_child_witness_v3::verify_witness_commitment;

pub const ALPHA_MAX_BLOCK_WEIGHT: usize = 6_000_000;
pub const ALPHA_MAX_BLOCK_BYTES: usize = 6_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFoundationError { Encoding, Block, Transaction, Witness, Parent, Withdrawal, Critical, Context }

#[derive(Debug)]
pub enum ParentBoundChildError {
    Binding,
    Policy(super::child_execution_policy_v3::ExecutionPolicyErrorV3),
    Parent(super::conversion_parent_link_v3::AlphaConversionLinkErrorV3),
    Child(ChildFoundationError),
    State(ChildStateError),
}

/// Locally checked composition, constructible only by the parent/child path.
/// This is not a cryptographic receipt and retains the configured verifiers'
/// trust assumptions. Finality, freshness and redemption remain outer checks.
pub struct ParentBoundCheckedChildState {
    parent: super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3,
    child: CheckedChildState,
    ecx_context: Option<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3>,
    pub(crate) ecx_checkpoint: Option<Hash32>,
}

impl ParentBoundCheckedChildState {
    pub(crate) fn ecx_context(&self) -> Option<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3> { self.ecx_context }
    pub fn parent(&self) -> &super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3 {
        &self.parent
    }

    pub fn child(&self) -> &CheckedChildState { &self.child }

    /// Project accounting only after the parent and child have been checked
    /// together. The expected accounting hash is an independent profile input.
    pub fn conversion_accounting(
        &self,
        binding: &super::native_conversion_accounting_v3::ConversionAccountingBindingV3,
        frozen_accounting_binding: Hash32,
    ) -> Result<super::native_conversion_accounting_v3::ConversionAccountingV3,
        super::native_conversion_accounting_v3::ConversionAccountingErrorV3> {
        self.child.conversion_accounting(binding, frozen_accounting_binding)
    }
}

fn require_parent_checkpoint_binding(
    binding: &super::conversion_parent_link_v3::AlphaConversionLinkBindingV3,
    checkpoint: &super::child_execution_state_v3::ChildExecutionCheckpointV3,
) -> Result<(), ParentBoundChildError> {
    if binding.child_genesis_hash_internal != checkpoint.genesis_internal
        || binding.child_consensus_configuration_commitment != checkpoint.configuration_commitment
        || binding.child_checkpoint_hash_internal != checkpoint.tip_internal
        || binding.child_checkpoint_height != checkpoint.height {
        return Err(ParentBoundChildError::Binding);
    }
    Ok(())
}

/// Compose parent authentication with checkpoint-relative child execution.
/// Frozen parent, checkpoint and policy commitments are independent consumer
/// trust roots. This does not
/// qualify the configured engines or supply missing full-configuration bindings;
/// it is not yet a complete conversion, custody or finality proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_parent_bound_checkpoint_child_state<
    P: crate::FullAlphaReceiptVerifierV3,
    V: ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_execution_state_v3::ChildExecutionCheckpointV3,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    policy: &super::child_execution_policy_v3::ChildExecutionPolicyV3,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    witnesses: &[ChildTransactionStateWitness],
    input_verifier: &V,
    deposit_verifier: Option<&dyn ecx_full_consensus_validator_v2::elements_v2::DrivechainDepositReceiptVerifierV2>,
    native_deposits: Option<&NativeBlockDepositsV3<'_>>,
    // Must be derived from the reviewed configuration, independently of witnesses.
    expected_deposit_configuration: Option<Hash32>,
) -> Result<ParentBoundCheckedChildState, ParentBoundChildError> {
    if frozen_parent_binding == [0;32] || parent.binding.commitment()
        .map_err(|_|ParentBoundChildError::Binding)? != frozen_parent_binding {
        return Err(ParentBoundChildError::Binding);
    }
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    policy.require_frozen(frozen_policy,checkpoint).map_err(ParentBoundChildError::Policy)?;
    header_policy.check_context(policy.header_policy_commitment,checkpoint,history,
        policy.deployments,authorization).map_err(|_|ParentBoundChildError::Binding)?;
    let derived_authorization = header_policy.derive_context(policy.header_policy_commitment,
        checkpoint, history, policy.deployments, observation_time)
        .map_err(|_|ParentBoundChildError::Binding)?;
    if authorization != &derived_authorization {
        return Err(ParentBoundChildError::Binding);
    }
    require_parent_checkpoint_binding(&parent.binding,checkpoint)?;
    require_deposit_configuration_binding(native_deposits.map(|d|d.frozen_deposit_configuration),
        expected_deposit_configuration)?;
    let verified = super::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(
        parent,parent_verifier).map_err(ParentBoundChildError::Parent)?;
    if let Some(deposits) = native_deposits {
        let anchor_state = parent.terminal_parent_predecessor.commitment()
            .map_err(|_|ParentBoundChildError::Binding)?;
        if deposits.frozen_parent_binding != frozen_parent_binding
            || deposits.entries.iter().flatten().any(|(kernel,_)|
                kernel.deposit.parent_state_commitment() != anchor_state) {
            return Err(ParentBoundChildError::Binding);
        }
    }
    let child = verify_checkpoint_child_state(raw,checkpoint,frozen_checkpoint,history,
        verified.parent_predecessor_hash_internal,verified.m7_critical_hash_internal,
        policy.deployments,policy.deployments.commitment().map_err(|_|ParentBoundChildError::Binding)?,
        observation_time,&derived_authorization,&super::native_header_signature_v3::NativeHeaderScriptVerifier,
        policy.reward,witnesses,policy.classification,input_verifier,deposit_verifier,native_deposits)
        .map_err(ParentBoundChildError::State)?;
    Ok(ParentBoundCheckedChildState { parent: verified, child, ecx_context: None, ecx_checkpoint: None })
}

fn require_deposit_configuration_binding(actual: Option<Hash32>, expected: Option<Hash32>)
    -> Result<(), ParentBoundChildError> {
    match (actual,expected) {
        (None,None) => Ok(()),
        (Some(a),Some(e)) if e != [0;32] && a == e => Ok(()),
        _ => Err(ParentBoundChildError::Binding),
    }
}

/// Parent-authenticated custody result; not a recursive receipt or finality claim.
pub struct ParentBoundCheckedCustodyStateV3 {
    parent: super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3,
    child: CheckedChildCustodyStateV3,
    pub(crate) ecx_context: Option<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3>,
    pub(crate) ecx_checkpoint: Option<Hash32>,
}
impl ParentBoundCheckedCustodyStateV3 {
    pub fn parent(&self)->&super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3 { &self.parent }
    pub fn child(&self)->&CheckedChildCustodyStateV3 { &self.child }
}

/// Frozen custody-policy composition. Clock freshness, complete program/annex
/// and issuance qualification remain outer obligations. Deposit configuration
/// and parent anchor binding are enforced even for blocks without peg-ins.
#[allow(clippy::too_many_arguments)]
pub fn verify_parent_bound_checkpoint_custody_state_v3<
    P:crate::FullAlphaReceiptVerifierV3,
    V:ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3>(
    parent:&super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding:Hash32,parent_verifier:&P,
    raw:&[u8],checkpoint:&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    frozen_checkpoint:Hash32,history:&[super::native_header_v3::NativeHeader],
    policy:&super::child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    frozen_policy:Hash32,observation_time:u64,
    header_policy:&super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses:&[ChildTransactionCustodyWitnessV3],input_verifier:&V,
    deposits:&NativeBlockDepositsV3<'_>,expected_deposit_configuration:Hash32,
)->Result<ParentBoundCheckedCustodyStateV3,ParentBoundChildError> {
    policy.require_frozen(frozen_policy,checkpoint).map_err(ParentBoundChildError::Policy)?;
    verify_parent_bound_checkpoint_custody_state_with_rules(parent,frozen_parent_binding,
        parent_verifier,raw,checkpoint,frozen_checkpoint,history,policy,observation_time,
        header_policy,witnesses,input_verifier,deposits,expected_deposit_configuration,
        ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3::Legacy)
}

/// Versioned entrypoint: the independently frozen policy and predecessor
/// checkpoint determine activation, never a transaction witness or a clock.
#[allow(clippy::too_many_arguments)]
pub fn verify_parent_bound_checkpoint_custody_state_v4<
    P:crate::FullAlphaReceiptVerifierV3,
    V:ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3>(
    parent:&super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding:Hash32,parent_verifier:&P,
    raw:&[u8],checkpoint:&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    frozen_checkpoint:Hash32,history:&[super::native_header_v3::NativeHeader],
    policy:&super::child_execution_policy_v3::ChildCustodyExecutionPolicyV4,
    frozen_policy:Hash32,observation_time:u64,
    header_policy:&super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses:&[ChildTransactionCustodyWitnessV3],input_verifier:&V,
    deposits:&NativeBlockDepositsV3<'_>,expected_deposit_configuration:Hash32,
)->Result<ParentBoundCheckedCustodyStateV3,ParentBoundChildError> {
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    policy.require_frozen(frozen_policy,checkpoint).map_err(ParentBoundChildError::Policy)?;
    let height=checkpoint.height.checked_add(1).ok_or(ParentBoundChildError::Binding)?;
    let reissuance=policy.creation().reissuance_rules(height).map_err(|_|
        ParentBoundChildError::Policy(super::child_execution_policy_v3::ExecutionPolicyErrorV3::Parameters))?;
    verify_parent_bound_checkpoint_custody_state_with_rules(parent,frozen_parent_binding,
        parent_verifier,raw,checkpoint,frozen_checkpoint,history,&policy.base,observation_time,
        header_policy,witnesses,input_verifier,deposits,expected_deposit_configuration,reissuance)
}

#[allow(clippy::too_many_arguments)]
fn verify_parent_bound_checkpoint_custody_state_with_rules<
    P:crate::FullAlphaReceiptVerifierV3,
    V:ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3>(
    parent:&super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding:Hash32,parent_verifier:&P,
    raw:&[u8],checkpoint:&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    frozen_checkpoint:Hash32,history:&[super::native_header_v3::NativeHeader],
    policy:&super::child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    observation_time:u64,
    header_policy:&super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses:&[ChildTransactionCustodyWitnessV3],input_verifier:&V,
    deposits:&NativeBlockDepositsV3<'_>,expected_deposit_configuration:Hash32,
    reissuance:ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3,
)->Result<ParentBoundCheckedCustodyStateV3,ParentBoundChildError> {
    if frozen_parent_binding==[0;32] || parent.binding.commitment()
        .map_err(|_|ParentBoundChildError::Binding)?!=frozen_parent_binding {
        return Err(ParentBoundChildError::Binding);
    }
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    let binding=&parent.binding;
    if binding.child_genesis_hash_internal!=checkpoint.genesis_internal
        || binding.child_consensus_configuration_commitment!=checkpoint.configuration_commitment
        || binding.child_checkpoint_hash_internal!=checkpoint.tip_internal
        || binding.child_checkpoint_height!=checkpoint.height {
        return Err(ParentBoundChildError::Binding);
    }
    require_deposit_configuration_binding(Some(deposits.frozen_deposit_configuration),Some(expected_deposit_configuration))?;
    let anchor=parent.terminal_parent_predecessor.commitment().map_err(|_|ParentBoundChildError::Binding)?;
    if deposits.frozen_parent_binding!=frozen_parent_binding
        || deposits.entries.iter().flatten().any(|(kernel,_)|kernel.deposit.parent_state_commitment()!=anchor) {
        return Err(ParentBoundChildError::Binding);
    }
    let authorization=header_policy.derive_custody_context(policy.header_policy_commitment,
        checkpoint,history,policy.deployments,observation_time).map_err(|_|ParentBoundChildError::Binding)?;
    let verified=super::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(parent,parent_verifier)
        .map_err(ParentBoundChildError::Parent)?;
    let child=verify_checkpoint_child_custody_state_with_rules(raw,checkpoint,frozen_checkpoint,history,
        verified.parent_predecessor_hash_internal,verified.m7_critical_hash_internal,
        policy.deployments,policy.deployments.commitment().map_err(|_|ParentBoundChildError::Binding)?,
        observation_time,&authorization,&super::native_header_signature_v3::NativeHeaderScriptVerifier,
        policy.reward,witnesses,input_verifier,deposits,reissuance).map_err(ParentBoundChildError::State)?;
    // Validate every creation, including coinbase and native deposits, before
    // returning an accepted state. Execution above is pure: rejected roots are
    // never published. Historical input commitments remain independently checked.
    let height = checkpoint.height.checked_add(1).ok_or(ParentBoundChildError::Binding)?;
    if child.foundation.block.txdata.iter().any(|tx| !policy.creation.permits(height, tx)) {
        return Err(ParentBoundChildError::Policy(
            super::child_execution_policy_v3::ExecutionPolicyErrorV3::Parameters));
    }
    Ok(ParentBoundCheckedCustodyStateV3 {parent:verified,child,ecx_context:None,ecx_checkpoint:None})
}

/// Concrete custody execution with transaction-specific evaluator receipts.
/// Capital validation and the enclosing recursive guest remain required.
#[allow(clippy::too_many_arguments)]
pub fn execute_parent_bound_custody_with_ecx_v4<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    prior_header: &super::native_header_v3::NativeHeader,
    policy: &super::child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionCustodyWitnessV3],
    environment: &super::ecx_environment_v4::EcxExecutionEnvironmentV1,
    frozen_environment: Hash32, frozen_source_closure: Hash32,
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S, deposits: &NativeBlockDepositsV3<'_>,
    expected_deposit_configuration: Hash32,
) -> Result<(ParentBoundCheckedCustodyStateV3, super::ecx_environment_v4::CheckedAlphaCustodyExecutionContextV4), ParentBoundChildError> {
    policy.require_frozen(frozen_policy,&checkpoint.execution).map_err(ParentBoundChildError::Policy)?;
    execute_parent_bound_custody_with_ecx_rules(parent,frozen_parent_binding,parent_verifier,raw,checkpoint,frozen_checkpoint,history,
        prior_header,policy,observation_time,header_policy,witnesses,environment,
        frozen_environment,frozen_source_closure,frozen_evaluator_program_id,
        simplicity_receipts,simplicity_verifier,deposits,expected_deposit_configuration,ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3::Legacy)
}

/// Explicit reissuance variant; shares the same concrete script/receipt executor.
#[allow(clippy::too_many_arguments)]
pub fn execute_parent_bound_custody_with_ecx_v5<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    prior_header: &super::native_header_v3::NativeHeader,
    policy: &super::child_execution_policy_v3::ChildCustodyExecutionPolicyV4,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionCustodyWitnessV3],
    environment: &super::ecx_environment_v4::EcxExecutionEnvironmentV1,
    frozen_environment: Hash32, frozen_source_closure: Hash32,
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S, deposits: &NativeBlockDepositsV3<'_>,
    expected_deposit_configuration: Hash32,
) -> Result<(ParentBoundCheckedCustodyStateV3, super::ecx_environment_v4::CheckedAlphaCustodyExecutionContextV4), ParentBoundChildError> {
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    policy.require_frozen(frozen_policy,&checkpoint.execution).map_err(ParentBoundChildError::Policy)?;
    let height=checkpoint.execution.height.checked_add(1).ok_or(ParentBoundChildError::Binding)?;
    let reissuance=policy.creation().reissuance_rules(height).map_err(|_|
        ParentBoundChildError::Policy(super::child_execution_policy_v3::ExecutionPolicyErrorV3::Parameters))?;
    execute_parent_bound_custody_with_ecx_rules(parent,frozen_parent_binding,parent_verifier,raw,checkpoint,frozen_checkpoint,history,
        prior_header,&policy.base,observation_time,header_policy,witnesses,environment,
        frozen_environment,frozen_source_closure,frozen_evaluator_program_id,
        simplicity_receipts,simplicity_verifier,deposits,expected_deposit_configuration,reissuance)
}

// Only the checked policy wrappers above select execution rules.
#[allow(clippy::too_many_arguments)]
fn execute_parent_bound_custody_with_ecx_rules<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    prior_header: &super::native_header_v3::NativeHeader,
    policy: &super::child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionCustodyWitnessV3],
    environment: &super::ecx_environment_v4::EcxExecutionEnvironmentV1,
    frozen_environment: Hash32, frozen_source_closure: Hash32,
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S, deposits: &NativeBlockDepositsV3<'_>,
    expected_deposit_configuration: Hash32,
    reissuance: ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3,
) -> Result<(ParentBoundCheckedCustodyStateV3, super::ecx_environment_v4::CheckedAlphaCustodyExecutionContextV4), ParentBoundChildError> {
    use ecx_full_consensus_validator_v2::{elements_v2::{
        FullElementsInputVerifierV2, FullElementsInputVerifierWithSimplicityV2,
        MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2},
        alpha_simplicity_receipt_v3::AlphaSimplicityReceiptExecutorV4};
    if frozen_source_closure == [0;32]
        || !crate::alpha_sp1_program_id_is_canonical_v3(frozen_evaluator_program_id)
        || simplicity_receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2 {
        return Err(ParentBoundChildError::Binding);
    }
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    let mut identity = frozen_checkpoint.to_vec();
    identity.extend_from_slice(&frozen_source_closure);
    let composition = crate::tagged_hash("ECX/alpha-custody-evaluator-composition/v4", &identity);
    let context = super::ecx_environment_v4::CheckedAlphaCustodyExecutionContextV4::authenticate(
        environment, frozen_environment, composition, checkpoint, frozen_checkpoint,
        prior_header, parent, frozen_parent_binding, parent_verifier)
        .map_err(|_| ParentBoundChildError::Binding)?;
    let scope = context.evaluator_scope(frozen_checkpoint, frozen_source_closure)
        .map_err(|_| ParentBoundChildError::Binding)?;
    let execution = &checkpoint.execution;
    let frozen_execution = execution.commitment()
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    let (candidate, _) = super::native_header_v3::NativeHeader::decode_prefix(raw, true)
        .map_err(|_| ParentBoundChildError::Child(ChildFoundationError::Encoding))?;
    let rules = policy.deployments.checked_custody_candidate_rules(
        policy.deployments.commitment().map_err(|_| ParentBoundChildError::Binding)?,
        execution, frozen_execution, history, &candidate)
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Deployment(e)))?;
    let simplicity = AlphaSimplicityReceiptExecutorV4::new(frozen_evaluator_program_id,
        scope, simplicity_receipts, simplicity_verifier)
        .map_err(|_| ParentBoundChildError::State(ChildStateError::Authorization))?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(execution.genesis_internal), rules.base_input_rules()),
        simplicity: &simplicity,
    };
    let mut result = verify_parent_bound_checkpoint_custody_state_with_rules(parent, frozen_parent_binding,
        parent_verifier, raw, execution, frozen_execution, history, policy,
        observation_time, header_policy, witnesses, &input_verifier, deposits, expected_deposit_configuration,reissuance)?;
    simplicity.require_all_receipts_consumed()
        .map_err(|_| ParentBoundChildError::State(ChildStateError::Authorization))?;
    result.ecx_context = Some(context.context());
    result.ecx_checkpoint = Some(frozen_checkpoint);
    Ok((result, context))
}

/// Concrete receipt-backed input dispatch for the Alpha relation. All frozen
/// values, including the evaluator ID, must come from an independently bound
/// source profile. This helper does not qualify that profile or the evaluator.
#[allow(clippy::too_many_arguments)]
pub fn execute_parent_bound_child_with_simplicity_v3<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_execution_state_v3::ChildExecutionCheckpointV3,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    policy: &super::child_execution_policy_v3::ChildExecutionPolicyV3,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionStateWitness],
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S,
    native_deposits: Option<&NativeBlockDepositsV3<'_>>,
    expected_deposit_configuration: Option<Hash32>,
) -> Result<ParentBoundCheckedChildState, ParentBoundChildError> {
    use ecx_full_consensus_validator_v2::elements_v2::{
        FullElementsInputVerifierV2, FullElementsInputVerifierWithSimplicityV2,
        ProofCarryingElementsSimplicityExecutorV2};
    if !crate::alpha_sp1_program_id_is_canonical_v3(frozen_evaluator_program_id) {
        return Err(ParentBoundChildError::Binding);
    }
    policy.require_frozen(frozen_policy, checkpoint).map_err(ParentBoundChildError::Policy)?;
    let (candidate, _) = super::native_header_v3::NativeHeader::decode_prefix(raw, true)
        .map_err(|_|ParentBoundChildError::Child(ChildFoundationError::Encoding))?;
    let rules = policy.deployments.checked_candidate_rules(
        policy.deployments.commitment().map_err(|_|ParentBoundChildError::Binding)?,
        checkpoint, frozen_checkpoint, history, &candidate)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Deployment(e)))?;
    let authorization = header_policy.derive_context(policy.header_policy_commitment,
        checkpoint, history, policy.deployments, observation_time)
        .map_err(|_|ParentBoundChildError::Binding)?;
    let simplicity = ProofCarryingElementsSimplicityExecutorV2::new(
        frozen_evaluator_program_id, simplicity_receipts, simplicity_verifier)
        .map_err(|_|ParentBoundChildError::State(ChildStateError::Authorization))?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(checkpoint.genesis_internal), rules.base_input_rules()),
        simplicity: &simplicity,
    };
    let result = verify_parent_bound_checkpoint_child_state(parent, frozen_parent_binding,
        parent_verifier, raw, checkpoint, frozen_checkpoint, history, policy, frozen_policy,
        observation_time, header_policy, &authorization, witnesses, &input_verifier,
        None, native_deposits, expected_deposit_configuration)?;
    simplicity.require_all_receipts_consumed()
        .map_err(|_|ParentBoundChildError::State(ChildStateError::Authorization))?;
    Ok(result)
}

/// Native ECX receipt dispatch. The environment is independently frozen and
/// rederived against the authenticated parent and V4 predecessor checkpoint.
/// No a7/transaction-only receipt fallback is permitted. This verifies the
/// transaction-state transition, NOT the missing capital-state transition:
/// callers must verify and attach the successor capital projection separately.
#[allow(clippy::too_many_arguments)]
pub fn execute_parent_bound_child_with_ecx_v4<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_execution_state_v4::ChildExecutionCheckpointV4,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    prior_header: &super::native_header_v3::NativeHeader,
    policy: &super::child_execution_policy_v3::ChildExecutionPolicyV3,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionStateWitness],
    environment: &super::ecx_environment_v4::EcxExecutionEnvironmentV1,
    frozen_environment: Hash32, frozen_evaluator_binding: Hash32,
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S,
    native_deposits: Option<&NativeBlockDepositsV3<'_>>,
    expected_deposit_configuration: Option<Hash32>,
) -> Result<ParentBoundCheckedChildState, ParentBoundChildError> {
    use ecx_full_consensus_validator_v2::{elements_v2::{
        FullElementsInputVerifierV2, FullElementsInputVerifierWithSimplicityV2,
        MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2},
        alpha_simplicity_receipt_v3::AlphaSimplicityReceiptExecutorV3};
    if !crate::alpha_sp1_program_id_is_canonical_v3(frozen_evaluator_program_id)
        || simplicity_receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2 {
        return Err(ParentBoundChildError::Binding);
    }
    let context = super::ecx_environment_v4::CheckedAlphaExecutionContextV4::authenticate(
        environment, frozen_environment, frozen_evaluator_binding, checkpoint,
        frozen_checkpoint, prior_header, parent, frozen_parent_binding, parent_verifier)
        .map_err(|_| ParentBoundChildError::Binding)?;
    // The V3 execution commitment is a projection of the verified V4 preimage,
    // not a separately witness-selected trust root.
    let execution = &checkpoint.execution;
    let frozen_execution = execution.commitment()
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    policy.require_frozen(frozen_policy, execution).map_err(ParentBoundChildError::Policy)?;
    let (candidate, _) = super::native_header_v3::NativeHeader::decode_prefix(raw, true)
        .map_err(|_|ParentBoundChildError::Child(ChildFoundationError::Encoding))?;
    let rules = policy.deployments.checked_candidate_rules(
        policy.deployments.commitment().map_err(|_|ParentBoundChildError::Binding)?,
        execution, frozen_execution, history, &candidate)
        .map_err(|e|ParentBoundChildError::State(ChildStateError::Deployment(e)))?;
    let authorization = header_policy.derive_context(policy.header_policy_commitment,
        execution, history, policy.deployments, observation_time)
        .map_err(|_|ParentBoundChildError::Binding)?;
    // Native ECX environment fields are block-wide predecessor/configuration
    // values. Transaction/input-specific data is committed by each a8 journal.
    let contexts = vec![context.context(); simplicity_receipts.len()];
    let simplicity = AlphaSimplicityReceiptExecutorV3::new(frozen_evaluator_program_id,
        &contexts, simplicity_receipts, simplicity_verifier)
        .map_err(|_|ParentBoundChildError::State(ChildStateError::Authorization))?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(execution.genesis_internal), rules.base_input_rules()),
        simplicity: &simplicity,
    };
    let mut result = verify_parent_bound_checkpoint_child_state(parent, frozen_parent_binding,
        parent_verifier, raw, execution, frozen_execution, history, policy, frozen_policy,
        observation_time, header_policy, &authorization, witnesses, &input_verifier,
        None, native_deposits, expected_deposit_configuration)?;
    simplicity.require_all_receipts_consumed()
        .map_err(|_|ParentBoundChildError::State(ChildStateError::Authorization))?;
    result.ecx_context = Some(context.context());
    result.ecx_checkpoint = Some(frozen_checkpoint);
    Ok(result)
}

/// V5 checkpoint execution with transaction-specific native evaluator bindings.
/// The returned checked context is for capital composition, not a per-input
/// receipt context. The enclosing recursive statement must bind the full V5
/// predecessor and verify/attach the successor capital and BMM checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn execute_parent_bound_child_with_ecx_v5<
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    frozen_parent_binding: Hash32, parent_verifier: &P,
    raw: &[u8], checkpoint: &super::child_execution_state_v4::ChildExecutionCheckpointV5,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    prior_header: &super::native_header_v3::NativeHeader,
    policy: &super::child_execution_policy_v3::ChildExecutionPolicyV3,
    frozen_policy: Hash32, observation_time: u64,
    header_policy: &super::child_header_policy_v3::ChildHeaderPolicyV3,
    witnesses: &[ChildTransactionStateWitness],
    environment: &super::ecx_environment_v4::EcxExecutionEnvironmentV1,
    frozen_environment: Hash32, frozen_source_closure: Hash32,
    frozen_evaluator_program_id: Hash32,
    simplicity_receipts: &[ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2],
    simplicity_verifier: &S,
    native_deposits: Option<&NativeBlockDepositsV3<'_>>,
    expected_deposit_configuration: Option<Hash32>,
) -> Result<(ParentBoundCheckedChildState, super::ecx_environment_v4::CheckedAlphaExecutionContextV4), ParentBoundChildError> {
    use ecx_full_consensus_validator_v2::{elements_v2::{
        FullElementsInputVerifierV2, FullElementsInputVerifierWithSimplicityV2,
        MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2},
        alpha_simplicity_receipt_v3::AlphaSimplicityReceiptExecutorV4};
    if frozen_source_closure == [0; 32]
        || !crate::alpha_sp1_program_id_is_canonical_v3(frozen_evaluator_program_id)
        || simplicity_receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2 {
        return Err(ParentBoundChildError::Binding);
    }
    checkpoint.require_frozen(frozen_checkpoint)
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    let frozen_state = checkpoint.state.commitment()
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    // Internal block-composition identity. Never passed to a receipt verifier:
    // each invocation derives its actual evaluator binding through the scope.
    let mut identity = frozen_checkpoint.to_vec();
    identity.extend_from_slice(&frozen_source_closure);
    let composition = crate::tagged_hash("ECX/alpha-child-evaluator-composition/v5", &identity);
    let context = super::ecx_environment_v4::CheckedAlphaExecutionContextV4::authenticate(
        environment, frozen_environment, composition, &checkpoint.state,
        frozen_state, prior_header, parent, frozen_parent_binding, parent_verifier)
        .map_err(|_| ParentBoundChildError::Binding)?;
    let scope = context.evaluator_scope(checkpoint, frozen_checkpoint, frozen_source_closure)
        .map_err(|_| ParentBoundChildError::Binding)?;
    let execution = &checkpoint.state.execution;
    let frozen_execution = execution.commitment()
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Checkpoint(e)))?;
    policy.require_frozen(frozen_policy, execution).map_err(ParentBoundChildError::Policy)?;
    let (candidate, _) = super::native_header_v3::NativeHeader::decode_prefix(raw, true)
        .map_err(|_| ParentBoundChildError::Child(ChildFoundationError::Encoding))?;
    let rules = policy.deployments.checked_candidate_rules(
        policy.deployments.commitment().map_err(|_| ParentBoundChildError::Binding)?,
        execution, frozen_execution, history, &candidate)
        .map_err(|e| ParentBoundChildError::State(ChildStateError::Deployment(e)))?;
    let authorization = header_policy.derive_context(policy.header_policy_commitment,
        execution, history, policy.deployments, observation_time)
        .map_err(|_| ParentBoundChildError::Binding)?;
    let simplicity = AlphaSimplicityReceiptExecutorV4::new(frozen_evaluator_program_id,
        scope, simplicity_receipts, simplicity_verifier)
        .map_err(|_| ParentBoundChildError::State(ChildStateError::Authorization))?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(execution.genesis_internal), rules.base_input_rules()),
        simplicity: &simplicity,
    };
    let mut result = verify_parent_bound_checkpoint_child_state(parent, frozen_parent_binding,
        parent_verifier, raw, execution, frozen_execution, history, policy, frozen_policy,
        observation_time, header_policy, &authorization, witnesses, &input_verifier,
        None, native_deposits, expected_deposit_configuration)?;
    simplicity.require_all_receipts_consumed()
        .map_err(|_| ParentBoundChildError::State(ChildStateError::Authorization))?;
    result.ecx_context = Some(context.context());
    result.ecx_checkpoint = Some(frozen_state);
    Ok((result, context))
}

/// Join the verified Alpha parent relation to the native child commitment
/// preimage. The expected binding commitment is a frozen consumer trust root,
/// not a value to copy from untrusted input. This proves neither complete child
/// consensus nor custody: predecessor state and contextual execution are still
/// checked by the enclosing child-state relation.
#[allow(clippy::too_many_arguments)]
pub fn verify_parent_bound_child_commitments<V: crate::FullAlphaReceiptVerifierV3>(
    parent:&super::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    expected_binding_commitment:Hash32, parent_verifier:&V,
    raw:&[u8], previous_child:BlockHash, height:u32,
    previous_accumulator:&WithdrawalAccumulator, segwit_active:bool,
) -> Result<(super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3,
    ChildCommitmentFoundation),ParentBoundChildError> {
    if expected_binding_commitment==[0;32] || parent.binding.commitment()
        .map_err(|_|ParentBoundChildError::Binding)?!=expected_binding_commitment {
        return Err(ParentBoundChildError::Binding);
    }
    let verified=super::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(parent,parent_verifier)
        .map_err(ParentBoundChildError::Parent)?;
    let child=verify_native_child_commitments(raw,parent.binding.child_genesis_hash_internal,
        previous_child,height,verified.parent_predecessor_hash_internal,verified.m7_critical_hash_internal,
        previous_accumulator,segwit_active).map_err(ParentBoundChildError::Child)?;
    Ok((verified,child))
}

pub struct ChildCommitmentFoundation {
    /// Authoritative header. `block.header` is only an upstream transaction/
    /// context view and MUST NOT supply hashes for native extended headers.
    pub native_header: super::native_header_v3::NativeHeader,
    pub block: Block,
    pub withdrawals: Vec<WithdrawalClaim>,
    pub next_accumulator: WithdrawalAccumulator,
}

#[path = "child_transaction_witness_wire_v3.rs"]
pub(crate) mod transaction_witness_wire;

/// Untrusted execution input. Decoding this value does not authenticate its
/// roots, openings, kernel, or signatures; the complete block executor must.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildTransactionStateWitness {
    #[serde(with = "transaction_witness_wire::utxo")]
    pub utxo: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionUtxoWitnessV2,
    #[serde(with = "transaction_witness_wire::economic")]
    pub economic: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionEconomicWitnessV2,
    pub kernel: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionKernelWitnessV2,
}

/// Canonical bounded wire decoding for a transaction's execution witness.
/// The caller supplies its enclosing guest's byte budget. Native deposit
/// authentication is deliberately not encoded as a trusted result here.
pub fn decode_child_transaction_witness_v3(
    bytes: &[u8], maximum_bytes: u64,
) -> Result<ChildTransactionStateWitness, bincode::Error> {
    use bincode::Options;
    if bytes.len() as u64 > maximum_bytes {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    let options = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(maximum_bytes).reject_trailing_bytes();
    let witness: ChildTransactionStateWitness = options.deserialize(bytes)?;
    if options.serialize(&witness)? != bytes {
        return Err(Box::new(bincode::ErrorKind::Custom(
            "noncanonical child transaction witness".into())));
    }
    Ok(witness)
}

#[cfg(test)]
mod transaction_witness_wire_tests {
    use super::*;
    use bincode::Options;
    use ecx_full_consensus_validator_v2::elements_v2::*;

    #[test]
    fn canonical_witness_preserves_kernel_and_enforces_byte_boundary() {
        for kernel in [ElementsTransactionKernelWitnessV2::Coinbase,
            ElementsTransactionKernelWitnessV2::Ordinary,
            ElementsTransactionKernelWitnessV2::Issuance,
            ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit] {
            let witness = ChildTransactionStateWitness {
                utxo: ElementsTransactionUtxoWitnessV2 { spends: vec![], creates: vec![] },
                economic: ElementsTransactionEconomicWitnessV2 { spends: vec![], creates: vec![] },
                kernel,
            };
            let bytes = bincode::DefaultOptions::new().with_fixint_encoding()
                .serialize(&witness).unwrap();
            assert_eq!(decode_child_transaction_witness_v3(&bytes, bytes.len() as u64).unwrap(), witness);
            assert!(decode_child_transaction_witness_v3(&bytes, bytes.len() as u64 - 1).is_err());
            let mut trailing = bytes.clone(); trailing.push(0);
            assert!(decode_child_transaction_witness_v3(&trailing, trailing.len() as u64).is_err());
            for end in 0..bytes.len() {
                assert!(decode_child_transaction_witness_v3(&bytes[..end], bytes.len() as u64).is_err());
            }
        }
        // A hostile vector length must not bypass the decoder's byte budget.
        assert!(decode_child_transaction_witness_v3(&u64::MAX.to_le_bytes(), 8).is_err());
    }
}

/// Native deposit evidence indexed by transaction position. Configuration must
/// be independently frozen. Each deposit must be authenticated through the
/// child's exact parent anchor, including every intervening confirmation block.
pub struct NativeBlockDepositsV3<'a> {
    pub entries: &'a [Option<(super::native_deposit_outputs_v3::NativeDepositKernelV3<'a>, Vec<Hash32>)>],
    pub frozen_parent_binding: Hash32,
    /// Independent consumer trust root, not a hash chosen by the witness.
    pub frozen_deposit_configuration: Hash32,
    pub minimum_depth: u32,
    /// None retains scalar V3 semantics. Scheduled V5 callers bind the V4 policy.
    pub scheduled_policy: Option<&'a super::native_deposit_policy_v4::AlphaDepositPolicyV4>,
}

/// A custody execution witness is deliberately a separate type from the old
/// inventory/reserve economic witness. Transport and checkpoint binding are
/// obligations of the enclosing versioned guest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildTransactionCustodyWitnessV3 {
    #[serde(with = "transaction_witness_wire::utxo")]
    pub utxo: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionUtxoWitnessV2,
    #[serde(with = "transaction_witness_wire::custody")]
    pub custody: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyWitnessV3,
    pub kernel: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionKernelWitnessV2,
}

/// Bounded canonical transport only; execution authenticates the decoded witness.
pub fn decode_child_transaction_custody_witness_v3(
    bytes: &[u8], maximum_bytes: u64,
) -> Result<ChildTransactionCustodyWitnessV3, bincode::Error> {
    use bincode::Options;
    if bytes.len() as u64 > maximum_bytes {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    let options = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(maximum_bytes).reject_trailing_bytes();
    let witness: ChildTransactionCustodyWitnessV3 = options.deserialize(bytes)?;
    if options.serialize(&witness)? != bytes {
        return Err(Box::new(bincode::ErrorKind::Custom(
            "noncanonical child custody witness".into())));
    }
    Ok(witness)
}

/// Locally checked custody state, not an authenticated parent/child receipt.
pub struct CheckedChildCustodyStateV3 {
    foundation: ChildCommitmentFoundation,
    roots: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3,
    spent_claims_root: Hash32,
    next_checkpoint: Option<super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3>,
}

impl CheckedChildCustodyStateV3 {
    /// Burn extraction from checkpoint-bound execution only. Asset and genesis
    /// are derived, not supplied. Custody/vault/scale must still be frozen by the
    /// redemption domain; M6 finality and Ethereum release are separate checks.
    pub fn custody_burn_v2(&self,transaction_index:usize,vout:u32,
        custody_id:Hash32,vault_address:[u8;20],atoms_per_micro:u64,
    )->Result<crate::custody_burn_v2::CustodyBurnV2,crate::custody_burn_v2::CommittedBurnError> {
        use crate::custody_burn_v2::{CommittedBurnError,extract_custody_burn_v2};
        let checkpoint=self.next_checkpoint.as_ref().ok_or(CommittedBurnError::Checkpoint)?;
        if transaction_index==0 { return Err(CommittedBurnError::TransactionIndex); }
        let tx=self.foundation.block.txdata.get(transaction_index).ok_or(CommittedBurnError::TransactionIndex)?;
        let mut asset=checkpoint.classification.custody_asset_id;asset.reverse();
        let mut genesis=checkpoint.genesis_internal;genesis.reverse();
        extract_custody_burn_v2(tx,vout,genesis,asset,custody_id,vault_address,atoms_per_micro)
            .map_err(CommittedBurnError::Burn)
    }
    pub fn next_checkpoint(&self) -> Option<&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3> {
        self.next_checkpoint.as_ref()
    }
    pub fn roots(&self) -> ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3 { self.roots }
    pub fn spent_claims_root(&self) -> Hash32 { self.spent_claims_root }
    pub fn foundation(&self) -> &ChildCommitmentFoundation { &self.foundation }
}

/// The native asset argument must come from the enclosing frozen policy, not
/// the deposit witness. Shared by the legacy and custody execution paths.
fn require_native_deposit_binding(
    deposits: &NativeBlockDepositsV3<'_>,
    kernel: &super::native_deposit_outputs_v3::NativeDepositKernelV3<'_>,
    genesis_internal: Hash32, expected_parent: Hash32, height: u32,
    native_asset: Hash32,
) -> Result<(), ChildStateError> {
    let required_depth = match deposits.scheduled_policy {
        None => deposits.minimum_depth.max(1),
        Some(policy) => {
            if policy.child_genesis_internal != genesis_internal
                || policy.parent_genesis_internal != kernel.parent_genesis_internal
                || policy.historical.minimum_depth != deposits.minimum_depth
                || policy.commitment() != Some(deposits.frozen_deposit_configuration) {
                return Err(ChildStateError::DepositBinding);
            }
            policy.required_depth(height.checked_sub(1).ok_or(ChildStateError::DepositBinding)?)
                .ok_or(ChildStateError::DepositBinding)?
        }
    };
    if kernel.deposit.binding_commitment()!=deposits.frozen_parent_binding
        || kernel.deposit.confirmed_anchor()!=expected_parent
        || kernel.deposit.confirmations()<required_depth
        || super::native_deposit_outputs_v3::deposit_configuration_commitment_v3(
            kernel.pegged_asset,kernel.parent_genesis_internal,kernel.address_params,
            deposits.minimum_depth) != match deposits.scheduled_policy {
                None => Some(deposits.frozen_deposit_configuration),
                Some(policy) => policy.historical.commitment().ok(),
            }
        || kernel.pegged_asset.into_inner().to_byte_array()!=native_asset {
        return Err(ChildStateError::DepositBinding);
    }
    Ok(())
}

/// Result of the complete local state-check pipeline. Fields are private so a
/// caller cannot substitute transactions after checking execution. This is NOT
/// an authenticated receipt: its trust still depends on the supplied history,
/// deployment parameters and concrete verifier implementations.
pub struct CheckedChildState {
    foundation: ChildCommitmentFoundation,
    roots: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2,
    // Captured before each transaction, including native deposits. Never
    // reconstructed from the final root after the source coins were spent.
    transaction_pre_utxo_roots: Vec<ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoNodeV2>,
    genesis_internal: Hash32,
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
    next_checkpoint: Option<super::child_execution_state_v3::ChildExecutionCheckpointV3>,
    spent_claims_root: Option<Hash32>,
}

impl CheckedChildState {
    pub(crate) fn transaction_pre_utxo_root(&self, index: usize)
        -> Option<ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoNodeV2> {
        self.transaction_pre_utxo_roots.get(index).copied()
    }

    /// Derive conversion accounting from executed state, never from separately
    /// supplied witness totals. The expected accounting commitment must come
    /// from the frozen conversion configuration. This does not prove redemption
    /// availability, parent finality, or qualify the execution engines.
    pub fn conversion_accounting(
        &self,
        binding: &super::native_conversion_accounting_v3::ConversionAccountingBindingV3,
        frozen_accounting_binding: Hash32,
    ) -> Result<super::native_conversion_accounting_v3::ConversionAccountingV3,
        super::native_conversion_accounting_v3::ConversionAccountingErrorV3> {
        use super::native_conversion_accounting_v3::{derive_accounting, ConversionAccountingErrorV3};
        binding.require_frozen(frozen_accounting_binding)?;
        if self.classification != binding.classification
            || self.genesis_internal != binding.child_genesis_internal {
            return Err(ConversionAccountingErrorV3::Configuration);
        }
        let checkpoint = self.next_checkpoint.as_ref()
            .ok_or(ConversionAccountingErrorV3::Checkpoint)?;
        if checkpoint.configuration_commitment != binding.child_configuration_commitment
            || checkpoint.genesis_internal != binding.child_genesis_internal {
            return Err(ConversionAccountingErrorV3::Configuration);
        }
        derive_accounting(checkpoint, binding.classification, binding.quote_atoms_per_whole_base)
    }

    pub fn roots(&self) -> ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2 {
        self.roots
    }

    pub fn foundation(&self) -> &ChildCommitmentFoundation { &self.foundation }

    /// Present only when execution used the frozen-checkpoint entry point.
    /// This derived preimage is not itself a recursive receipt or qualification.
    pub fn next_checkpoint(&self) -> Option<&super::child_execution_state_v3::ChildExecutionCheckpointV3> {
        self.next_checkpoint.as_ref()
    }

    /// Extract only from transactions that passed this state's sequential
    /// execution pipeline. Asset/custody/vault/scale must come from the frozen
    /// deployment, not from the claim. The requested asset must be the same
    /// base asset whose supply was accounted during execution. M6 approval and
    /// finality remain separate.
    pub fn custody_burn_v2(&self, transaction_index: usize, vout: u32,
        asset_display: Hash32, custody_id: Hash32, vault_address: [u8;20],
        atoms_per_micro: u64,
    ) -> Result<crate::custody_burn_v2::CustodyBurnV2, crate::custody_burn_v2::CommittedBurnError> {
        use crate::custody_burn_v2::{extract_custody_burn_v2, CommittedBurnError};
        if transaction_index == 0 { return Err(CommittedBurnError::TransactionIndex); }
        let tx = self.foundation.block.txdata.get(transaction_index)
            .ok_or(CommittedBurnError::TransactionIndex)?;
        let mut accounted_asset_display = self.classification.base_asset_id;
        accounted_asset_display.reverse();
        if asset_display != accounted_asset_display {
            return Err(CommittedBurnError::AssetBinding);
        }
        let mut genesis_display = self.genesis_internal; genesis_display.reverse();
        extract_custody_burn_v2(tx,vout,genesis_display,asset_display,custody_id,
            vault_address,atoms_per_micro).map_err(CommittedBurnError::Burn)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildStateError {
    Checkpoint(super::child_execution_state_v3::CheckpointError),
    Deployment(super::child_deployments_v3::DeploymentErrorV3),
    Foundation(ChildFoundationError),
    Authorization,
    InputVerifierBinding,
    Reward(super::native_reward_v3::RewardError),
    WitnessCount,
    Claims(super::native_claims_v3::ClaimError),
    NativeDeposit(super::native_deposit_outputs_v3::NativeDepositStateErrorV3),
    DepositBinding,
    Transaction { index: usize, error: ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2 },
}

/// Execute from an independently frozen checkpoint, deriving predecessor roots,
/// height, accumulator and MTP history instead of accepting separate overrides.
/// Derive contextual activation flags from committed deployments and the actual
/// candidate. The complete configuration must still bind this deployment
/// component; parent replay, clock and concrete verifier qualification remain
/// required. The actual input dispatcher's genesis and base script selections
/// must match the checkpoint and derived rules; this is not engine qualification.
#[allow(clippy::too_many_arguments)]
pub fn verify_checkpoint_child_state<V: ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw: &[u8], checkpoint: &super::child_execution_state_v3::ChildExecutionCheckpointV3,
    frozen_checkpoint: Hash32, history: &[super::native_header_v3::NativeHeader],
    expected_parent: Hash32, expected_critical: Hash32,
    deployments: super::child_deployments_v3::ChildDeploymentConfigurationV3,
    frozen_deployments: Hash32, observation_time: u64,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier: &A, reward_parameters: super::native_reward_v3::RewardParameters,
    witnesses: &[ChildTransactionStateWitness],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn ecx_full_consensus_validator_v2::elements_v2::DrivechainDepositReceiptVerifierV2>,
    native_deposits: Option<&NativeBlockDepositsV3<'_>>,
) -> Result<CheckedChildState, ChildStateError> {
    checkpoint.require_frozen(frozen_checkpoint).map_err(ChildStateError::Checkpoint)?;
    let previous_headers = checkpoint.checked_mtp_history(history).map_err(ChildStateError::Checkpoint)?;
    let (candidate, _) = super::native_header_v3::NativeHeader::decode_prefix(raw, true)
        .map_err(|_|ChildStateError::Foundation(ChildFoundationError::Encoding))?;
    let rules = deployments.checked_candidate_rules(frozen_deployments,checkpoint,frozen_checkpoint,
        history,&candidate).map_err(ChildStateError::Deployment)?;
    if input_verifier.execution_binding() !=
        (BlockHash::from_byte_array(checkpoint.genesis_internal), rules.base_input_rules()) {
        return Err(ChildStateError::InputVerifierBinding);
    }
    let buried = deployments.buried.at_height(candidate.base.height)
        .map_err(|_|ChildStateError::Deployment(super::child_deployments_v3::DeploymentErrorV3::History))?;
    let context = super::native_child_context_v3::ChildContext {
        previous_headers, observation_time, csv_active:buried.csv,
        height_in_coinbase_active:buried.height_in_coinbase,
    };
    let height = checkpoint.height.checked_add(1).ok_or(ChildStateError::Checkpoint(
        super::child_execution_state_v3::CheckpointError::Height))?;
    let mut checked = verify_native_child_state(raw, checkpoint.genesis_internal,
        BlockHash::from_byte_array(checkpoint.tip_internal), height, expected_parent,
        expected_critical, &checkpoint.withdrawals, buried.segwit, &context,
        authorization, header_verifier, checkpoint.roots, reward_parameters,
        witnesses, classification, input_verifier, deposit_verifier,
        native_deposits.map(|deposits|(deposits,checkpoint.spent_claims_root)))?;
    // Peg-ins must use the native path with authenticated claim absence;
    // the legacy transaction path cannot advance the checkpoint claim set.
    if checked.spent_claims_root.is_none() && checked.foundation.block.txdata.iter().any(|tx| tx.input.iter().any(|input| input.is_pegin)) {
        return Err(ChildStateError::Claims(super::native_claims_v3::ClaimError::Path));
    }
    let mut next_history = history.to_vec();
    next_history.push(checked.foundation.native_header.clone());
    let next = super::child_execution_state_v3::ChildExecutionCheckpointV3 {
        genesis_internal: checkpoint.genesis_internal,
        configuration_commitment: checkpoint.configuration_commitment,
        tip_internal: checked.foundation.native_header.hash_internal()
            .map_err(|_|ChildStateError::Checkpoint(super::child_execution_state_v3::CheckpointError::History))?,
        height,
        history_commitment: super::child_execution_state_v3::child_history_commitment(&next_history)
            .map_err(ChildStateError::Checkpoint)?,
        roots: checked.roots,
        spent_claims_root: checked.spent_claims_root.unwrap_or(checkpoint.spent_claims_root),
        withdrawals: checked.foundation.next_accumulator.clone(),
    };
    next.commitment().map_err(ChildStateError::Checkpoint)?;
    checked.next_checkpoint = Some(next);
    Ok(checked)
}

/// Compose exact block commitments, contextual rules and sequential UTXO/economic
/// transitions. Returns no partial state on failure. This is NOT a qualified
/// child receipt: authenticated predecessor/deployment state, concrete header
/// and native script/deposit verifier qualification, reward configuration,
/// issuance and annex consensus obligations still belong to the final producer.
#[allow(clippy::too_many_arguments)]
pub fn verify_native_child_state<V: ecx_full_consensus_validator_v2::elements_v2::ElementsInputVerifierV2,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw: &[u8], genesis_internal: Hash32, previous_child: BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &WithdrawalAccumulator, segwit_active: bool,
    context: &super::native_child_context_v3::ChildContext,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier: &A,
    initial: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2,
    reward_parameters: super::native_reward_v3::RewardParameters,
    witnesses: &[ChildTransactionStateWitness],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn ecx_full_consensus_validator_v2::elements_v2::DrivechainDepositReceiptVerifierV2>,
    native_deposits: Option<(&NativeBlockDepositsV3<'_>,Hash32)>,
) -> Result<CheckedChildState, ChildStateError> {
    let foundation = verify_native_child_contextual_commitments(raw,genesis_internal,
        previous_child,height,expected_parent,expected_critical,previous_accumulator,
        segwit_active,context).map_err(ChildStateError::Foundation)?;
    let times: Vec<_> = context.previous_headers.iter().map(|h| h.base.time).collect();
    if authorization.previous_block_hash != previous_child
        || authorization.next_height != height
        || authorization.previous_11_times != times
        || authorization.authenticated_adjusted_time != context.observation_time {
        return Err(ChildStateError::Authorization);
    }
    header_verifier.authorize(&foundation.native_header,authorization)
        .map_err(|_| ChildStateError::Authorization)?;
    super::native_reward_v3::verify_reward(&foundation.block.txdata,height,reward_parameters)
        .map_err(ChildStateError::Reward)?;
    if witnesses.len() != foundation.block.txdata.len() { return Err(ChildStateError::WitnessCount); }
    let (spend,policy) = super::native_child_context_v3::derive_spend_rules(&foundation.block,context)
        .map_err(|_| ChildStateError::Foundation(ChildFoundationError::Context))?;
    let mut roots = initial;
    let mut transaction_pre_utxo_roots = Vec::with_capacity(witnesses.len());
    let mut claims=native_deposits.map(|(_,root)|root);
    if let Some((deposits,root))=native_deposits {
        if root==[0;32] || deposits.frozen_parent_binding==[0;32]
            || deposits.frozen_deposit_configuration==[0;32]
            || deposits.entries.len()!=witnesses.len() {
            return Err(ChildStateError::DepositBinding);
        }
    }
    for (index,(tx,witness)) in foundation.block.txdata.iter().zip(witnesses).enumerate() {
        transaction_pre_utxo_roots.push(roots.utxo_root);
        if let Some((deposits,_))=native_deposits {
            if let Some((kernel,path))=&deposits.entries[index] {
                if !matches!(witness.kernel,ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit)
                {
                    return Err(ChildStateError::DepositBinding);
                }
                require_native_deposit_binding(deposits,kernel,genesis_internal,
                    expected_parent,height,classification.base_asset_id)?;
                let (next_roots,next_claims)=super::native_deposit_outputs_v3::apply_native_deposit_and_claim_v3(
                    tx,spend,roots,claims.ok_or(ChildStateError::DepositBinding)?,path,
                    &witness.utxo,&witness.economic,classification,input_verifier,kernel,policy)
                    .map_err(ChildStateError::NativeDeposit)?;
                roots=next_roots;claims=Some(next_claims);
                continue;
            }
            if tx.input.iter().any(|input|input.is_pegin) {
                return Err(ChildStateError::DepositBinding);
            }
        }
        roots = ecx_full_consensus_validator_v2::elements_v2::apply_elements_transaction_state_native_v3(
            tx,spend,roots.utxo_root,roots.economic_root,&witness.utxo,&witness.economic,
            classification,&witness.kernel,input_verifier,deposit_verifier,policy)
            .map_err(|error| ChildStateError::Transaction {index,error})?;
    }
    Ok(CheckedChildState { foundation, roots, transaction_pre_utxo_roots, genesis_internal, classification, next_checkpoint: None, spent_claims_root:claims })
}

/// Custody counterpart of local child execution. Parent receipts, predecessor
/// roots and classification must be authenticated by the enclosing guest.
/// Native deposits are mandatory indexed evidence; legacy receipts cannot be
/// substituted. This does not itself qualify issuance or the final guest.
#[allow(clippy::too_many_arguments)]
pub fn verify_native_child_custody_state_v3<
    V: ecx_full_consensus_validator_v2::elements_v2::ElementsInputVerifierV2,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw: &[u8], genesis_internal: Hash32, previous_child: BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &WithdrawalAccumulator, segwit_active: bool,
    context: &super::native_child_context_v3::ChildContext,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier: &A,
    initial: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3,
    reward_parameters: super::native_reward_v3::RewardParameters,
    witnesses: &[ChildTransactionCustodyWitnessV3],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3,
    input_verifier: &V, deposits: &NativeBlockDepositsV3<'_>, claims_root: Hash32,
) -> Result<CheckedChildCustodyStateV3, ChildStateError> {
    verify_native_child_custody_state_with_rules(raw, genesis_internal, previous_child,
        height, expected_parent, expected_critical, previous_accumulator, segwit_active,
        context, authorization, header_verifier, initial, reward_parameters, witnesses,
        classification, input_verifier, deposits, claims_root,
        ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3::Legacy)
}

// Only enclosing checked policy entrypoints may choose this rule. It is not
// carried in per-transaction witnesses. Historical public entrypoints use Legacy.
#[allow(clippy::too_many_arguments)]
fn verify_native_child_custody_state_with_rules<
    V: ecx_full_consensus_validator_v2::elements_v2::ElementsInputVerifierV2,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw: &[u8], genesis_internal: Hash32, previous_child: BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &WithdrawalAccumulator, segwit_active: bool,
    context: &super::native_child_context_v3::ChildContext,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier: &A,
    initial: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3,
    reward_parameters: super::native_reward_v3::RewardParameters,
    witnesses: &[ChildTransactionCustodyWitnessV3],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3,
    input_verifier: &V, deposits: &NativeBlockDepositsV3<'_>, claims_root: Hash32,
    reissuance: ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3,
) -> Result<CheckedChildCustodyStateV3, ChildStateError> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    classification.commitment().map_err(|_|ChildStateError::DepositBinding)?;
    if claims_root==[0;32] || deposits.frozen_parent_binding==[0;32]
        || deposits.frozen_deposit_configuration==[0;32]
        || deposits.entries.len()!=witnesses.len() {
        return Err(ChildStateError::DepositBinding);
    }
    let foundation = verify_native_child_contextual_commitments(raw,genesis_internal,
        previous_child,height,expected_parent,expected_critical,previous_accumulator,
        segwit_active,context).map_err(ChildStateError::Foundation)?;
    let times: Vec<_> = context.previous_headers.iter().map(|h|h.base.time).collect();
    if authorization.previous_block_hash != previous_child
        || authorization.next_height != height || authorization.previous_11_times != times
        || authorization.authenticated_adjusted_time != context.observation_time {
        return Err(ChildStateError::Authorization);
    }
    header_verifier.authorize(&foundation.native_header,authorization)
        .map_err(|_|ChildStateError::Authorization)?;
    super::native_reward_v3::verify_reward(&foundation.block.txdata,height,reward_parameters)
        .map_err(ChildStateError::Reward)?;
    if witnesses.len()!=foundation.block.txdata.len() { return Err(ChildStateError::WitnessCount); }
    let (spend,policy) = super::native_child_context_v3::derive_spend_rules(&foundation.block,context)
        .map_err(|_|ChildStateError::Foundation(ChildFoundationError::Context))?;
    let mut roots = initial;
    let mut claims = claims_root;
    for (index,(tx,witness)) in foundation.block.txdata.iter().zip(witnesses).enumerate() {
        if let Some((kernel,path)) = &deposits.entries[index] {
            if !matches!(witness.kernel,ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit) {
                return Err(ChildStateError::DepositBinding);
            }
            require_native_deposit_binding(deposits,kernel,genesis_internal,expected_parent,
                height,classification.native_pegged_asset_id)?;
            (roots,claims) = super::native_deposit_outputs_v3::apply_native_deposit_and_custody_claim_v3(
                tx,spend,roots,claims,path,&witness.utxo,&witness.custody,classification,
                input_verifier,kernel,policy).map_err(ChildStateError::NativeDeposit)?;
        } else {
            if tx.input.iter().any(|input|input.is_pegin)
                || matches!(witness.kernel,ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit) {
                return Err(ChildStateError::DepositBinding);
            }
            roots = apply_elements_transaction_custody_native_v4(tx,spend,roots,&witness.utxo,
                &witness.custody,classification,&witness.kernel,input_verifier,None,policy,reissuance)
                .map_err(|error|ChildStateError::Transaction {index,error})?;
        }
    }
    Ok(CheckedChildCustodyStateV3 {foundation,roots,spent_claims_root:claims,next_checkpoint:None})
}

/// Execute from an independently authenticated custody checkpoint. This binds
/// predecessor state, both assets, deployment history and the input dispatcher;
/// parent receipts, complete execution-policy binding and engine qualification
/// remain obligations of the enclosing guest. No caller-supplied successor.
#[allow(clippy::too_many_arguments)]
pub fn verify_checkpoint_child_custody_state_v3<
    V: ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw:&[u8], checkpoint:&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    frozen_checkpoint:Hash32, history:&[super::native_header_v3::NativeHeader],
    expected_parent:Hash32, expected_critical:Hash32,
    deployments:super::child_deployments_v3::ChildDeploymentConfigurationV3,
    frozen_deployments:Hash32, observation_time:u64,
    authorization:&ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier:&A, reward_parameters:super::native_reward_v3::RewardParameters,
    witnesses:&[ChildTransactionCustodyWitnessV3], input_verifier:&V,
    deposits:&NativeBlockDepositsV3<'_>,
) -> Result<CheckedChildCustodyStateV3,ChildStateError> {
    verify_checkpoint_child_custody_state_with_rules(raw,checkpoint,frozen_checkpoint,history,
        expected_parent,expected_critical,deployments,frozen_deployments,observation_time,
        authorization,header_verifier,reward_parameters,witnesses,input_verifier,deposits,
        ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3::Legacy)
}

// Private rule routing: only authenticated policy entrypoints may select the
// new semantics. Historical checkpoint callers continue to select Legacy.
#[allow(clippy::too_many_arguments)]
fn verify_checkpoint_child_custody_state_with_rules<
    V: ecx_full_consensus_validator_v2::elements_v2::BoundElementsInputVerifierV3,
    A: super::native_header_signature_v3::NativeHeaderAuthorization>(
    raw:&[u8], checkpoint:&super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
    frozen_checkpoint:Hash32, history:&[super::native_header_v3::NativeHeader],
    expected_parent:Hash32, expected_critical:Hash32,
    deployments:super::child_deployments_v3::ChildDeploymentConfigurationV3,
    frozen_deployments:Hash32, observation_time:u64,
    authorization:&ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    header_verifier:&A, reward_parameters:super::native_reward_v3::RewardParameters,
    witnesses:&[ChildTransactionCustodyWitnessV3], input_verifier:&V,
    deposits:&NativeBlockDepositsV3<'_>,
    reissuance:ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3,
) -> Result<CheckedChildCustodyStateV3,ChildStateError> {
    checkpoint.require_frozen(frozen_checkpoint).map_err(ChildStateError::Checkpoint)?;
    let previous_headers=checkpoint.checked_mtp_history(history).map_err(ChildStateError::Checkpoint)?;
    let (candidate,_)=super::native_header_v3::NativeHeader::decode_prefix(raw,true)
        .map_err(|_|ChildStateError::Foundation(ChildFoundationError::Encoding))?;
    let rules=deployments.checked_custody_candidate_rules(frozen_deployments,checkpoint,
        frozen_checkpoint,history,&candidate).map_err(ChildStateError::Deployment)?;
    if input_verifier.execution_binding()!=
        (BlockHash::from_byte_array(checkpoint.genesis_internal),rules.base_input_rules()) {
        return Err(ChildStateError::InputVerifierBinding);
    }
    let height=checkpoint.height.checked_add(1).ok_or(ChildStateError::Checkpoint(
        super::child_execution_state_v3::CheckpointError::Height))?;
    let buried=deployments.buried.at_height(height).map_err(|_|ChildStateError::Deployment(
        super::child_deployments_v3::DeploymentErrorV3::History))?;
    let context=super::native_child_context_v3::ChildContext {previous_headers,observation_time,
        csv_active:buried.csv,height_in_coinbase_active:buried.height_in_coinbase};
    let mut checked=verify_native_child_custody_state_with_rules(raw,checkpoint.genesis_internal,
        BlockHash::from_byte_array(checkpoint.tip_internal),height,expected_parent,expected_critical,
        &checkpoint.withdrawals,buried.segwit,&context,authorization,header_verifier,
        checkpoint.roots,reward_parameters,witnesses,checkpoint.classification,input_verifier,
        deposits,checkpoint.spent_claims_root,reissuance)?;
    let mut next_history=history.to_vec();
    next_history.push(checked.foundation.native_header.clone());
    let next=super::child_custody_checkpoint_v3::ChildCustodyCheckpointV3 {
        genesis_internal:checkpoint.genesis_internal,
        configuration_commitment:checkpoint.configuration_commitment,
        classification:checkpoint.classification,
        tip_internal:checked.foundation.native_header.hash_internal().map_err(|_|ChildStateError::Checkpoint(
            super::child_execution_state_v3::CheckpointError::History))?,
        height,history_commitment:super::child_execution_state_v3::child_history_commitment(&next_history)
            .map_err(ChildStateError::Checkpoint)?,
        roots:checked.roots,spent_claims_root:checked.spent_claims_root,
        withdrawals:checked.foundation.next_accumulator.clone(),
    };
    next.commitment().map_err(ChildStateError::Checkpoint)?;
    checked.next_checkpoint=Some(next);
    Ok(checked)
}

/// Composes commitments with native history/time/finality/height checks.
/// Still NOT full consensus: authorization, UTXO rules and authentication of
/// the context and parent receipt remain obligations of the final producer.
pub fn verify_native_child_contextual_commitments(
    raw: &[u8], genesis_internal: Hash32, previous_child: BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &WithdrawalAccumulator, segwit_active: bool,
    context: &super::native_child_context_v3::ChildContext,
) -> Result<ChildCommitmentFoundation, ChildFoundationError> {
    let foundation = verify_native_child_commitments(raw,genesis_internal,previous_child,height,
        expected_parent,expected_critical,previous_accumulator,segwit_active)?;
    super::native_child_context_v3::verify_child_context(&foundation.block,context)
        .map_err(|_| ChildFoundationError::Context)?;
    Ok(foundation)
}

/// Expected parent and critical hashes must come from a verified Alpha parent
/// receipt with a frozen binding. Passing caller guesses authenticates nothing.
/// Likewise segwit_active must be derived from authenticated deployment history.
pub fn verify_native_child_commitments(
    raw: &[u8], genesis_internal: Hash32, previous_child: BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &WithdrawalAccumulator,
    segwit_active: bool,
) -> Result<ChildCommitmentFoundation, ChildFoundationError> {
    if raw.is_empty() || raw.len() > ALPHA_MAX_BLOCK_BYTES { return Err(ChildFoundationError::Encoding); }
    let native = super::native_block_wire_v3::NativeBlock::decode(raw)
        .map_err(|_| ChildFoundationError::Encoding)?;
    native.check_alpha_bmm_lane().map_err(|_| ChildFoundationError::Block)?;
    let weight = native.weight().map_err(|_| ChildFoundationError::Block)?;
    let native_hash = native.header.hash_internal().map_err(|_| ChildFoundationError::Block)?;
    let block = Block { header: native.header.base.clone(), txdata: native.transactions };
    if block.header.prev_blockhash != previous_child || block.header.height != height
        || weight > ALPHA_MAX_BLOCK_WEIGHT || block.txdata.is_empty()
        || !block.txdata[0].is_coinbase() || block.txdata.iter().skip(1).any(Transaction::is_coinbase)
        || elements_transaction_merkle_root_v2(&block.txdata).map_err(|_| ChildFoundationError::Block)? != block.header.merkle_root {
        return Err(ChildFoundationError::Block);
    }
    let mut ids = std::collections::HashSet::new();
    if block.txdata.iter().any(|tx| !ids.insert(tx.txid())) { return Err(ChildFoundationError::Block); }
    verify_witness_commitment(&block, segwit_active).map_err(|_| ChildFoundationError::Witness)?;
    super::native_transaction_checks_v3::check_block_transactions(&block.txdata)
        .map_err(|_| ChildFoundationError::Transaction)?;
    let parent = extract_parent_hash(block.txdata[0].output.iter().map(|o| o.script_pubkey.as_bytes()))
        .map_err(|_| ChildFoundationError::Parent)?;
    if parent != expected_parent || expected_parent == [0;32] { return Err(ChildFoundationError::Parent); }
    let (next_accumulator, withdrawals) = apply_withdrawals(&block.txdata, genesis_internal, previous_accumulator)
        .map_err(|_| ChildFoundationError::Withdrawal)?;
    let critical = critical_hash_internal(genesis_internal,24,native_hash,previous_accumulator,&next_accumulator)
        .map_err(|_| ChildFoundationError::Critical)?;
    if critical != expected_critical { return Err(ChildFoundationError::Critical); }
    Ok(ChildCommitmentFoundation { native_header: native.header, block, withdrawals, next_accumulator })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deposit_witness_cannot_choose_its_configuration_trust_root() {
        assert!(require_deposit_configuration_binding(None,None).is_ok());
        assert!(require_deposit_configuration_binding(Some([1;32]),Some([1;32])).is_ok());
        for (actual,expected) in [(Some([1;32]),None),(None,Some([1;32])),
            (Some([1;32]),Some([2;32])),(Some([0;32]),Some([0;32]))] {
            assert!(require_deposit_configuration_binding(actual,expected).is_err());
        }
    }
    #[test]
    fn parent_binding_requires_exact_child_checkpoint_identity() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        let checkpoint = super::super::child_execution_state_v3::ChildExecutionCheckpointV3 {
            genesis_internal:[1;32],configuration_commitment:[2;32],tip_internal:[3;32],
            height:6,history_commitment:[4;32],withdrawals:WithdrawalAccumulator::empty(),
            spent_claims_root: crate::native_claims_v3::empty_root(),
            roots:ElementsTransactionStateRootsV2 {
                utxo_root:ElementsSparseUtxoNodeV2 {hash:[5;32],aggregate:Default::default()},
                economic_root:ElementsSparseEconomicNodeV2 {hash:[6;32],aggregate:Default::default()},
            },
        };
        let binding = super::super::conversion_parent_link_v3::AlphaConversionLinkBindingV3 {
            parent:crate::AlphaRecursiveBindingV3 {source_configuration_commitment:[7;32],
                reviewed_checkpoint_input_commitment:[8;32],checkpoint_program_id:[2;32],transition_program_id:[3;32]},
            child_consensus_configuration_commitment:checkpoint.configuration_commitment,
            child_genesis_hash_internal:checkpoint.genesis_internal,
            child_checkpoint_hash_internal:checkpoint.tip_internal,
            child_checkpoint_height:checkpoint.height,
            slot24_proposal_hash:[9;32],slot24_activation_height:1,
        };
        require_parent_checkpoint_binding(&binding,&checkpoint).unwrap();
        for field in 0..4 {
            let mut changed = binding;
            match field {
                0 => changed.child_genesis_hash_internal[0] ^= 1,
                1 => changed.child_consensus_configuration_commitment[0] ^= 1,
                2 => changed.child_checkpoint_hash_internal[0] ^= 1,
                _ => changed.child_checkpoint_height += 1,
            }
            assert!(matches!(require_parent_checkpoint_binding(&changed,&checkpoint),Err(ParentBoundChildError::Binding)));
        }
    }
    use elements::{Script, TxIn, TxOut, LockTime, BlockHeader, BlockExtData};
    fn fixture() -> (Block, Hash32) {
        let mut script = vec![0x6a,37]; script.extend_from_slice(b"ELMTP"); script.extend_from_slice(&[2;32]);
        let coinbase = Transaction { version:2, lock_time:LockTime::ZERO,input:vec![TxIn {script_sig:Script::from(vec![1,7]), ..TxIn::default()}],output:vec![TxOut { script_pubkey: Script::from(script), ..TxOut::default() }] };
        let merkle_root = elements_transaction_merkle_root_v2(&[coinbase.clone()]).unwrap();
        let block = Block { header: BlockHeader { version:1, prev_blockhash:BlockHash::from_byte_array([3;32]),merkle_root,time:100,height:7,ext:BlockExtData::Proof {challenge:Script::new(),solution:Script::new()} },txdata:vec![coinbase] };
        let empty = WithdrawalAccumulator::empty();
        let critical = critical_hash_internal([1;32],24,block.block_hash().to_byte_array(),&empty,&empty).unwrap();
        (block, critical)
    }
    fn check(raw: &[u8], critical: Hash32) -> Result<ChildCommitmentFoundation,ChildFoundationError> {
        verify_native_child_commitments(raw,[1;32],BlockHash::from_byte_array([3;32]),7,[2;32],critical,&WithdrawalAccumulator::empty(),true)
    }
    #[test]
    fn full_list_and_parent_commitment_bound() {
        let (block,critical) = fixture(); let raw = elements::encode::serialize(&block);
        assert!(check(&raw,critical).is_ok());
        assert!(matches!(check(&raw,[7;32]),Err(ChildFoundationError::Critical)));
        let mut trailing = raw; trailing.push(0);
        assert!(matches!(check(&trailing,critical),Err(ChildFoundationError::Encoding)));
        let mut changed = block.clone(); changed.txdata[0].output[0].script_pubkey = Script::new();
        assert!(matches!(check(&elements::encode::serialize(&changed),critical),Err(ChildFoundationError::Block)));
        changed.header.merkle_root = elements_transaction_merkle_root_v2(&changed.txdata).unwrap();
        assert!(matches!(check(&elements::encode::serialize(&changed),critical),Err(ChildFoundationError::Parent)));
    }
    #[test]
    fn v2_burn_is_selected_from_committed_native_block() {
        use crate::custody_burn_v2::{verify_committed_custody_burn_v2, CommittedBurnError};
        let (mut block, _) = fixture();
        let (mut burn_tx, _) = crate::native_withdrawal_extraction_v3::tests::fixture();
        let mut input = TxIn::default(); input.previous_output.vout = 0;
        burn_tx.input.push(input);
        for output in &mut burn_tx.output {
            let mut script = output.script_pubkey.as_bytes().to_vec();
            script[6] = 2; output.script_pubkey = Script::from(script);
        }
        let custody = burn_tx.output[0].script_pubkey.as_bytes()[7..39].try_into().unwrap();
        let elements::confidential::Asset::Explicit(asset) = burn_tx.output[0].asset else { panic!() };
        let mut asset = asset.into_inner().to_byte_array(); asset.reverse();
        block.txdata.push(burn_tx.clone());
        block.header.merkle_root = elements_transaction_merkle_root_v2(&block.txdata).unwrap();
        let empty = WithdrawalAccumulator::empty();
        let critical = critical_hash_internal([1;32],24,block.block_hash().to_byte_array(),&empty,&empty).unwrap();
        let verify = |b: &Block, index| verify_committed_custody_burn_v2(
            &elements::encode::serialize(b),[1;32],block.header.prev_blockhash,7,[2;32],
            critical,&empty,true,index,0,asset,custody,[9;20],100);
        let burn = verify(&block,1).unwrap();
        let mut expected_txid = burn_tx.txid().to_byte_array(); expected_txid.reverse();
        assert_eq!(burn.txid_display,expected_txid);
        assert_eq!(burn.amount_micro,777000);
        for index in [0,2,usize::MAX] {
            assert!(matches!(verify(&block,index),Err(CommittedBurnError::TransactionIndex)));
        }
        // Substitution fails both with a stale Merkle root and with a rebuilt
        // root whose header is no longer bound by the expected critical hash.
        let mut changed = block.clone(); changed.txdata[1].lock_time = LockTime::from_consensus(1);
        assert!(matches!(verify(&changed,1),Err(CommittedBurnError::Child(_))));
        changed.header.merkle_root = elements_transaction_merkle_root_v2(&changed.txdata).unwrap();
        assert!(matches!(verify(&changed,1),Err(CommittedBurnError::Child(ChildFoundationError::Critical))));
    }
    #[test]
    fn native_extensions_are_bound_and_historical_bmm_is_rejected() {
        use super::super::native_header_v3::{NativeHeader, EXCHANGE, FORCED, DEPOSIT, CURSORS, BMM};
        use super::super::native_block_wire_v3::NativeBlock;
        let (block, _) = fixture();
        let mut header = NativeHeader::from_standard(block.header);
        header.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
        header.withdrawal = [4;32];
        header.exchange = [5;32];
        header.forced = [6;32];
        header.deposit = [7;32];
        header.parent_height = 19;
        header.forced_cursor = 20;
        header.deposit_cursor = 21;
        header.oldest_backlog_height = 22;
        let native = NativeBlock { header, transactions: block.txdata, bmm_proof: vec![] };
        let empty = WithdrawalAccumulator::empty();
        let critical = critical_hash_internal([1;32],24,native.header.hash_internal().unwrap(),&empty,&empty).unwrap();
        let accepted = check(&native.encode().unwrap(), critical).unwrap();
        assert_eq!(accepted.native_header.encode(false,true).unwrap(), native.header.encode(false,true).unwrap());
        assert_ne!(accepted.native_header.hash_internal().unwrap(), accepted.block.block_hash().to_byte_array());
        // Every serialized extension must affect the parent-bound commitment.
        for index in 0..8 {
            let mut changed = native.clone();
            match index {
                0 => changed.header.withdrawal[0] ^= 1,
                1 => changed.header.exchange[0] ^= 1,
                2 => changed.header.forced[0] ^= 1,
                3 => changed.header.deposit[0] ^= 1,
                4 => changed.header.parent_height += 1,
                5 => changed.header.forced_cursor += 1,
                6 => changed.header.deposit_cursor += 1,
                _ => changed.header.oldest_backlog_height += 1,
            }
            assert!(matches!(check(&changed.encode().unwrap(),critical),Err(ChildFoundationError::Critical)));
        }
        let mut historical = native;
        historical.header.base.version |= BMM;
        assert!(matches!(check(&historical.encode().unwrap(),critical),Err(ChildFoundationError::Block)));
    }
    #[test]
    fn predecessor_height_and_coinbase_shape_rejected() {
        let (mut block,critical) = fixture(); block.header.height += 1;
        assert!(matches!(check(&elements::encode::serialize(&block),critical),Err(ChildFoundationError::Block)));
        block.header.height -= 1; block.txdata.push(block.txdata[0].clone());
        block.header.merkle_root = elements_transaction_merkle_root_v2(&block.txdata).unwrap();
        assert!(matches!(check(&elements::encode::serialize(&block),critical),Err(ChildFoundationError::Block)));
    }
    #[test]
    fn contextual_composition_checks_history_after_commitments() {
        let (mut block,_) = fixture();
        let subsidy_asset = elements::AssetId::from_slice(&[9;32]).unwrap();
        block.txdata[0].output[0].asset = elements::confidential::Asset::Explicit(subsidy_asset);
        block.txdata[0].output[0].value = elements::confidential::Value::Explicit(0);
        block.header.merkle_root = elements_transaction_merkle_root_v2(&block.txdata).unwrap();
        let mut headers = Vec::<BlockHeader>::new();
        for height in 0..7 {
            let mut header = block.header.clone(); header.height = height; header.time = 10+height;
            header.prev_blockhash = headers.last().map(|h| h.block_hash()).unwrap_or(BlockHash::all_zeros());
            headers.push(header);
        }
        block.header.prev_blockhash = headers.last().unwrap().block_hash();
        let empty = WithdrawalAccumulator::empty();
        let critical = critical_hash_internal([1;32],24,block.block_hash().to_byte_array(),&empty,&empty).unwrap();
        let mut context = super::super::native_child_context_v3::ChildContext {
            previous_headers:headers.into_iter().map(super::super::native_header_v3::NativeHeader::from_standard).collect(), observation_time:100,csv_active:true,height_in_coinbase_active:false
        };
        let run = |ctx: &super::super::native_child_context_v3::ChildContext| {
            verify_native_child_contextual_commitments(&elements::encode::serialize(&block),[1;32],
                block.header.prev_blockhash,7,[2;32],critical,&empty,true,ctx)
        };
        assert!(run(&context).is_ok());
        // The fixture has only an unspendable coinbase commitment, so no
        // script verifier may be invoked and neither state tree may change.
        use ecx_full_consensus_validator_v2::elements_v2::*;
        struct NoScriptCalls;
        impl ElementsInputVerifierV2 for NoScriptCalls {
            fn verify_input(&self, _: &Transaction, _: usize, _: &[TxOut]) -> Result<(),ElementsStateErrorV2> {
                panic!("coinbase must not invoke script authorization")
            }
        }
        let initial = ElementsTransactionStateRootsV2 {
            utxo_root: ElementsSparseUtxoNodeV2 {hash:[17;32],aggregate:Default::default()},
            economic_root: ElementsSparseEconomicNodeV2 {hash:[18;32],aggregate:Default::default()},
        };
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id:[9;32],policy_asset_id:[10;32],
            redemption_inventory_script_sha256:[11;32],reserve_script_sha256:[12;32],
        };
        // Test-only verifier exercises required invocation/rejection, not real signatures.
        struct HeaderVerifier(bool);
        impl super::super::native_header_signature_v3::NativeHeaderAuthorization for HeaderVerifier {
            fn authorize(&self,_:&super::super::native_header_v3::NativeHeader,_:&ElementsHeaderConsensusContextV2)->Result<(),ElementsStateErrorV2> {
                if self.0 {Ok(())} else {Err(ElementsStateErrorV2::HeaderConsensus)}
            }
        }
        let authorization = ElementsHeaderConsensusContextV2 {
            previous_block_hash:block.header.prev_blockhash,next_height:7,
            previous_11_times:context.previous_headers.iter().map(|h| h.base.time).collect(),
            authenticated_adjusted_time:context.observation_time,
            expected_current_dynafed_params:None,expected_full_current_dynafed_params:None,
            legacy_signblock_challenge:Script::new(),legacy_signblock_witness_limit:100,
        };
        let state_run = |witnesses: &[ChildTransactionStateWitness],auth:&ElementsHeaderConsensusContextV2,accept| verify_native_child_state(
            &elements::encode::serialize(&block),[1;32],block.header.prev_blockhash,
            7,[2;32],critical,&empty,true,&context,auth,&HeaderVerifier(accept),initial,
            super::super::native_reward_v3::RewardParameters {subsidy_asset,genesis_subsidy:0,halving_interval:210_000},
            witnesses,classification,&NoScriptCalls,None,None);
        assert!(matches!(state_run(&[],&authorization,true),Err(ChildStateError::WitnessCount)));
        assert!(matches!(state_run(&[],&authorization,false),Err(ChildStateError::Authorization)));
        let mut inconsistent=authorization.clone(); inconsistent.authenticated_adjusted_time+=1;
        assert!(matches!(state_run(&[],&inconsistent,true),Err(ChildStateError::Authorization)));
        inconsistent=authorization.clone(); inconsistent.previous_11_times[0]+=1;
        assert!(matches!(state_run(&[],&inconsistent,true),Err(ChildStateError::Authorization)));
        inconsistent=authorization.clone(); inconsistent.next_height+=1;
        assert!(matches!(state_run(&[],&inconsistent,true),Err(ChildStateError::Authorization)));
        inconsistent=authorization.clone(); inconsistent.previous_block_hash=BlockHash::from_byte_array([99;32]);
        assert!(matches!(state_run(&[],&inconsistent,true),Err(ChildStateError::Authorization)));
        let witness = ChildTransactionStateWitness {
            utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
            economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
            kernel:ElementsTransactionKernelWitnessV2::Coinbase,
        };
        let checked = state_run(&[witness],&authorization,true).unwrap();
        assert_eq!(checked.roots(),initial);
        assert_eq!(checked.transaction_pre_utxo_root(0), Some(initial.utxo_root));
        assert_eq!(checked.transaction_pre_utxo_root(1), None);
        assert_eq!(checked.transaction_pre_utxo_root(usize::MAX), None);
        assert_eq!(checked.foundation().block.txdata,block.txdata);
        // Local execution alone cannot yield conversion accounting: the
        // checkpoint-relative entry point must first bind the state history.
        use crate::native_conversion_accounting_v3::ConversionAccountingErrorV3;
        let accounting_binding = crate::native_conversion_accounting_v3::ConversionAccountingBindingV3 {
            child_genesis_internal: [1;32], child_configuration_commitment: [2;32],
            classification, quote_atoms_per_whole_base: 1,
        };
        let frozen_accounting = accounting_binding.commitment().unwrap();
        assert_eq!(checked.conversion_accounting(&accounting_binding,frozen_accounting),
            Err(ConversionAccountingErrorV3::Checkpoint));
        // Every classification identity is part of the accounting boundary.
        // Reject substitution before attempting to project checkpoint totals.
        for field in 0..4 {
            let mut substituted = classification;
            match field {
                0 => substituted.base_asset_id = [99;32],
                1 => substituted.policy_asset_id = [99;32],
                2 => substituted.redemption_inventory_script_sha256 = [99;32],
                _ => substituted.reserve_script_sha256 = [99;32],
            }
            let substituted = crate::native_conversion_accounting_v3::ConversionAccountingBindingV3 {
                classification: substituted, ..accounting_binding
            };
            assert_eq!(checked.conversion_accounting(&substituted,frozen_accounting),
                Err(ConversionAccountingErrorV3::Configuration));
        }
        for index in [0,1,usize::MAX] {
            assert!(matches!(checked.custody_burn_v2(index,0,[1;32],[2;32],[3;20],100),
                Err(crate::custody_burn_v2::CommittedBurnError::TransactionIndex)));
        }
        // Exercise the same state composition with actual ECDSA authorization,
        // not the invocation-only checker above. This remains synthetic history.
        {
            use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[19;32]).unwrap();
            let mut challenge = vec![33];
            challenge.extend_from_slice(&PublicKey::from_secret_key(&secp,&secret).serialize());
            challenge.push(0xac);
            let challenge = Script::from(challenge);
            let mut signed = block.clone();
            signed.header.ext = BlockExtData::Proof {challenge:challenge.clone(),solution:Script::new()};
            let signature = secp.sign_ecdsa(&Message::from_digest(signed.block_hash().to_byte_array()),&secret)
                .serialize_der().to_vec();
            let mut solution = vec![signature.len() as u8]; solution.extend_from_slice(&signature);
            signed.header.ext = BlockExtData::Proof {challenge:challenge.clone(),solution:Script::from(solution)};
            let mut auth = authorization.clone(); auth.legacy_signblock_challenge = challenge;
            use super::super::{native_block_wire_v3::NativeBlock,native_header_v3::NativeHeader};
            let concrete_run = |candidate: &NativeBlock, binding: &ElementsHeaderConsensusContextV2| {
                // Rebind the parent commitment for mutation cases to ensure
                // rejection comes from authorization, not a stale block hash.
                let critical = critical_hash_internal([1;32],24,candidate.header.hash_internal().unwrap(),&empty,&empty).unwrap();
                verify_native_child_state(&candidate.encode().unwrap(),[1;32],
                    candidate.header.base.prev_blockhash,7,[2;32],critical,&empty,true,&context,
                    binding,&super::super::native_header_signature_v3::NativeHeaderScriptVerifier,
                    initial,super::super::native_reward_v3::RewardParameters {
                        subsidy_asset,genesis_subsidy:0,halving_interval:210_000},
                    &[ChildTransactionStateWitness {
                        utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                        economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
                        kernel:ElementsTransactionKernelWitnessV2::Coinbase,
                    }],classification,&NoScriptCalls,None,None)
            };
            let mut signed = NativeBlock {header:NativeHeader::from_standard(signed.header),transactions:signed.txdata,bmm_proof:vec![]};
            assert_eq!(concrete_run(&signed,&auth).unwrap().roots(),initial);
            signed.header.base.version |= super::super::native_header_v3::EXCHANGE;
            signed.header.exchange = [42;32];
            assert!(matches!(concrete_run(&signed,&auth),Err(ChildStateError::Authorization)));
            let signature = secp.sign_ecdsa(&Message::from_digest(signed.header.hash_internal().unwrap()),&secret).serialize_der();
            let mut bytes = vec![signature.len() as u8]; bytes.extend_from_slice(&signature);
            if let BlockExtData::Proof {solution,..} = &mut signed.header.base.ext { *solution=Script::from(bytes); }
            assert_eq!(concrete_run(&signed,&auth).unwrap().roots(),initial);
            let mut changed = signed.clone(); changed.header.exchange[0] ^= 1;
            assert!(matches!(concrete_run(&changed,&auth),Err(ChildStateError::Authorization)));
            let mut changed = signed.clone(); changed.header.base.time += 1;
            assert!(matches!(concrete_run(&changed,&auth),Err(ChildStateError::Authorization)));
            let mut wrong_challenge = auth.clone(); wrong_challenge.legacy_signblock_challenge = Script::from(vec![0x51]);
            assert!(matches!(concrete_run(&signed,&wrong_challenge),Err(ChildStateError::Authorization)));
            if let BlockExtData::Proof {solution,..} = &mut changed.header.base.ext { *solution = Script::new(); }
            assert!(matches!(concrete_run(&changed,&auth),Err(ChildStateError::Authorization)));
        }
        // The old fixture encodes 7 as a numeric alias, not the exact OP_7 prefix.
        context.height_in_coinbase_active = true;
        assert!(matches!(run(&context),Err(ChildFoundationError::Context)));
        context.height_in_coinbase_active = false; context.previous_headers[0].base.time += 1;
        assert!(matches!(run(&context),Err(ChildFoundationError::Context)));
    }
}
