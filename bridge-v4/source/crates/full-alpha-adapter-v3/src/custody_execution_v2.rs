//! Composition of native child execution and ordered custody approval history.
//! The caller must authenticate the policy (including destination and clock).
//! A generic guest must expose its commitment alongside the statement; emitting
//! only the statement would let a witness choose execution trust roots.
use ecx_full_consensus_validator_v2::{Hash32,elements_v2::ElementsSimplicityReceiptVerifierV2};
use crate::{FullAlphaReceiptVerifierV3,
    AlphaRecursiveReceiptBindingV3,
    custody_child_lineage_v2::{CustodyChildLineagePolicyV2,verify_custody_child_lineage_v2},
    child_execution_guest_v3::{AlphaChildExecutionInputV3,execute_alpha_child_execution_v3},
    custody_history_wire_v2::CustodyHistoryWitnessV2,
    custody_redemption_statement_v2::{RedemptionDomainV2,extract_executed_custody_checkpoint_v2}};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionPolicyV2 {
    pub domain: RedemptionDomainV2,
    pub verifier_address: [u8;20],
    pub child_execution_binding: Hash32,
    pub lineage: CustodyChildLineagePolicyV2,
    pub observation_time: u64,
    pub destination_state: Hash32,
    pub destination_anchor: Hash32,
    pub minimum_confirmations: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CustodyExecutionErrorV2 { Policy, Lineage, Child, Burn, History, Statement }

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionPolicyV5 {
    pub domain: RedemptionDomainV2,
    pub verifier_address: [u8;20],
    pub child_execution_binding: Hash32,
    pub lineage: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV5,
    pub observation_time: u64,
    pub destination_state: Hash32,
    pub destination_anchor: Hash32,
    pub minimum_confirmations: u32,
}

impl CustodyExecutionPolicyV5 {
    pub fn release_commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if self.minimum_confirmations == 0 { return Err(CustodyExecutionErrorV2::Policy); }
        let mut bytes = vec![5];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_| CustodyExecutionErrorV2::Policy)?);
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-release/v5", &bytes))
    }
    pub fn commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if !self.domain.require_frozen_custody(self.verifier_address, self.domain.custody_id)
            || [self.child_execution_binding, self.destination_state, self.destination_anchor].contains(&[0;32])
            || self.minimum_confirmations == 0 || self.observation_time == 0 {
            return Err(CustodyExecutionErrorV2::Policy);
        }
        let mut bytes = vec![5];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_| CustodyExecutionErrorV2::Policy)?);
        for value in [self.domain.custody_id, self.child_execution_binding,
            self.destination_state, self.destination_anchor] { bytes.extend_from_slice(&value); }
        bytes.extend_from_slice(&self.observation_time.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-execution-policy/v5", &bytes))
    }
}

/// V5 composition retains the exact custody history, approval and confirmation
/// checks. A caller must independently pin its policy/release commitment.
pub fn execute_custody_v5<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy: &CustodyExecutionPolicyV5,
    child: &crate::child_execution_guest_v4::AlphaChildExecutionInputV5,
    history: &CustodyHistoryWitnessV2,
    lineage_receipts: &[crate::custody_child_lineage_v2::CustodyChildLineageReceiptV5],
    transaction_index: usize, output_index: u32,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    use CustodyExecutionErrorV2 as E;
    let policy_commitment = policy.commitment()?;
    if child.binding.commitment().map_err(|_| E::Policy)? != policy.child_execution_binding
        || child.execution.observation_time != policy.observation_time { return Err(E::Policy); }
    let predecessor = child.binding.execution.predecessor_checkpoint;
    let expected = policy.lineage.binding(predecessor, child.binding.environment)
        .commitment().map_err(|_| E::Policy)?;
    if expected != policy.child_execution_binding { return Err(E::Lineage); }
    crate::custody_child_lineage_v2::verify_custody_child_lineage_v5(&policy.lineage,
        lineage_receipts, predecessor, child.checkpoint.state.execution.height, parent_verifier)
        .map_err(|_| E::Lineage)?;
    crate::custody_history_wire_v2::encode_custody_history_v2(history).map_err(|_| E::History)?;
    let executed = crate::child_execution_guest_v4::execute_owned_alpha_child_execution_v5(
        child, parent_verifier, simplicity_verifier).map_err(|_| E::Child)?;
    let cursor = crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v5(
        &policy.domain, policy.verifier_address, policy.domain.custody_id, &executed,
        transaction_index, output_index).map_err(|_| E::Burn)?;
    let (cursor, confirmations) = cursor.finish_history_with_bundle(&history.steps, history.approval_index as usize,
        history.approval_transaction, history.approval_bundle.as_ref(), parent_verifier).map_err(|_| E::History)?;
    let statement = cursor.checked_statement(&policy.domain, policy.verifier_address, &confirmations,
        policy.destination_state, policy.destination_anchor, policy.minimum_confirmations)
        .map_err(|_| E::Statement)?;
    let destination = confirmations.destination_tuple(&history.steps.last().ok_or(E::History)?
        .parent.terminal_selected_state).map_err(|_| E::History)?;
    Ok(CustodyExecutionOutputV2 { policy_commitment, statement, destination,
        release_commitment: policy.release_commitment()?, observation_time: policy.observation_time })
}


#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingExecutionPolicyV4 {
    pub domain: RedemptionDomainV2,
    pub verifier_address: [u8;20],
    pub child_execution_binding: Hash32,
    pub lineage: crate::custody_child_lineage_v2::CustodyAccountingLineagePolicyV4,
    pub observation_time: u64,
    pub destination_state: Hash32,
    pub destination_anchor: Hash32,
    pub minimum_confirmations: u32,
}

impl CustodyAccountingExecutionPolicyV4 {
    pub fn release_commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if self.minimum_confirmations == 0 { return Err(CustodyExecutionErrorV2::Policy); }
        let mut bytes = vec![0xac];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_| CustodyExecutionErrorV2::Policy)?);
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-release/v4", &bytes))
    }
    pub fn commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if !self.domain.require_frozen_custody(self.verifier_address, self.domain.custody_id)
            || [self.child_execution_binding, self.destination_state, self.destination_anchor].contains(&[0;32])
            || self.minimum_confirmations == 0 || self.observation_time == 0 {
            return Err(CustodyExecutionErrorV2::Policy);
        }
        let mut bytes = vec![0xac];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_| CustodyExecutionErrorV2::Policy)?);
        for value in [self.domain.custody_id, self.child_execution_binding,
            self.destination_state, self.destination_anchor] { bytes.extend_from_slice(&value); }
        bytes.extend_from_slice(&self.observation_time.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-execution-policy/v4", &bytes))
    }
}

/// Owned accounting composition retains the exact custody history, approval and confirmation
/// checks. A caller must independently pin its policy/release commitment.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingExecutionPolicyV6 {
    pub roots: CustodyAccountingExecutionPolicyV4,
}
impl CustodyAccountingExecutionPolicyV6 {
    pub fn commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        let mut bytes = self.roots.commitment()?.to_vec();
        bytes.extend_from_slice(&crate::custody_child_lineage_v2::custody_accounting_lineage_commitment_v6(
            &self.roots.lineage).map_err(|_| CustodyExecutionErrorV2::Policy)?);
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-execution-policy/v6", &bytes))
    }
    pub fn release_commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if self.roots.minimum_confirmations == 0 { return Err(CustodyExecutionErrorV2::Policy); }
        let mut bytes = crate::custody_child_lineage_v2::custody_accounting_lineage_commitment_v6(
            &self.roots.lineage).map_err(|_| CustodyExecutionErrorV2::Policy)?.to_vec();
        bytes.extend_from_slice(&self.roots.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-release/v6", &bytes))
    }
}

/// V7 accounting binds the separately activated native creation policy.
/// Historical V6 release identities cannot authorize this relation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingExecutionPolicyV7 {
    pub roots: CustodyAccountingExecutionPolicyV4,
}
impl CustodyAccountingExecutionPolicyV7 {
    pub fn commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        let mut bytes = self.roots.commitment()?.to_vec();
        bytes.extend_from_slice(&crate::custody_child_lineage_v2::custody_accounting_lineage_commitment_v7(
            &self.roots.lineage).map_err(|_| CustodyExecutionErrorV2::Policy)?);
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-execution-policy/v7", &bytes))
    }
    pub fn release_commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if self.roots.minimum_confirmations == 0 { return Err(CustodyExecutionErrorV2::Policy); }
        let mut bytes = crate::custody_child_lineage_v2::custody_accounting_lineage_commitment_v7(
            &self.roots.lineage).map_err(|_| CustodyExecutionErrorV2::Policy)?.to_vec();
        bytes.extend_from_slice(&self.roots.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-release/v7", &bytes))
    }
}

pub fn execute_custody_accounting_v7<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy: &CustodyAccountingExecutionPolicyV7,
    child: &crate::child_custody_guest_v7::CustodyExecutionInputV7,
    history: &CustodyHistoryWitnessV2,
    lineage_receipts: &[crate::custody_child_lineage_v2::CustodyAccountingLineageReceiptV6],
    transaction_index: usize, output_index: u32,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    let parent = SuccessfulParentReceipts::new(parent_verifier, 8192, 8 * 1024 * 1024);
    execute_custody_accounting_v7_inner(policy, child, history, lineage_receipts,
        transaction_index, output_index, &parent, simplicity_verifier)
}

// Private, invocation-local cache. Exact bytes avoid relying on another hash
// assumption. Saturation only disables insertion; verification still occurs.
struct SuccessfulParentReceipts<'a, V> {
    verifier: &'a V,
    entries: std::cell::RefCell<std::collections::BTreeSet<(Hash32, Vec<u8>, Vec<u8>)>>,
    bytes: std::cell::Cell<usize>,
    max_entries: usize,
    max_bytes: usize,
}
impl<'a, V> SuccessfulParentReceipts<'a, V> {
    fn new(verifier: &'a V, max_entries: usize, max_bytes: usize) -> Self {
        Self { verifier, entries: Default::default(), bytes: Default::default(), max_entries, max_bytes }
    }
}
impl<V: FullAlphaReceiptVerifierV3> FullAlphaReceiptVerifierV3 for SuccessfulParentReceipts<'_, V> {
    fn verify(&self, id: Hash32, public: &[u8], marker: &[u8]) -> Result<(), crate::FullAlphaAdapterErrorV3> {
        let key = (id, public.to_vec(), marker.to_vec());
        if self.entries.borrow().contains(&key) { return Ok(()); }
        self.verifier.verify(id, public, marker)?;
        let size = 32usize.checked_add(public.len()).and_then(|n| n.checked_add(marker.len()));
        if let Some(total) = size.and_then(|n| self.bytes.get().checked_add(n)) {
            if total <= self.max_bytes && self.entries.borrow().len() < self.max_entries {
                self.entries.borrow_mut().insert(key);
                self.bytes.set(total);
            }
        }
        Ok(())
    }
}

pub(crate) fn execute_custody_accounting_v7_inner<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy: &CustodyAccountingExecutionPolicyV7,
    child: &crate::child_custody_guest_v7::CustodyExecutionInputV7,
    history: &CustodyHistoryWitnessV2,
    lineage_receipts: &[crate::custody_child_lineage_v2::CustodyAccountingLineageReceiptV6],
    transaction_index: usize, output_index: u32,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    use CustodyExecutionErrorV2 as E;
    let policy_commitment = policy.commitment()?;
    let roots = &policy.roots;
    let inner = &child.anchor.execution;
    if child.source_binding().map_err(|_| E::Policy)? != roots.child_execution_binding
        || inner.observation_time != roots.observation_time { return Err(E::Policy); }
    let predecessor = child.anchor.checkpoint.commitment().map_err(|_| E::Lineage)?;
    let expected = crate::custody_child_lineage_v2::custody_accounting_binding_v7(&roots.lineage,
        predecessor, inner.binding.roots.execution.predecessor_checkpoint,
        inner.binding.roots.environment).map_err(|_| E::Lineage)?;
    if expected != roots.child_execution_binding { return Err(E::Lineage); }
    crate::custody_child_lineage_v2::verify_custody_accounting_lineage_v7(&roots.lineage,
        lineage_receipts, predecessor, child.anchor.checkpoint.projection.execution.height, parent_verifier)
        .map_err(|_| E::Lineage)?;
    crate::custody_history_wire_v2::encode_custody_history_v2(history).map_err(|_| E::History)?;
    let executed = crate::child_custody_guest_v7::execute_owned_custody_v7(
        child, parent_verifier, simplicity_verifier).map_err(|_| E::Child)?;
    let cursor = crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v7(
        &roots.domain, roots.verifier_address, roots.domain.custody_id, &executed,
        transaction_index, output_index).map_err(|_| E::Burn)?;
    let (cursor, confirmations) = cursor.finish_history_with_bundle(&history.steps, history.approval_index as usize,
        history.approval_transaction, history.approval_bundle.as_ref(), parent_verifier).map_err(|_| E::History)?;
    let statement = cursor.checked_statement(&roots.domain, roots.verifier_address, &confirmations,
        roots.destination_state, roots.destination_anchor, roots.minimum_confirmations)
        .map_err(|_| E::Statement)?;
    let destination = confirmations.destination_tuple(&history.steps.last().ok_or(E::History)?
        .parent.terminal_selected_state).map_err(|_| E::History)?;
    // The Ethereum redemption verifier ages the finalized parent tuple, not
    // the earlier child execution clock (which remains checked above).
    let observation_time = u64::from(destination.median_time_past);
    Ok(CustodyExecutionOutputV2 { policy_commitment, statement, destination,
        release_commitment: policy.release_commitment()?, observation_time })
}

pub fn execute_custody_accounting_v6<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy: &CustodyAccountingExecutionPolicyV6,
    child: &crate::child_custody_guest_v6::CustodyExecutionInputV6,
    history: &CustodyHistoryWitnessV2,
    lineage_receipts: &[crate::custody_child_lineage_v2::CustodyAccountingLineageReceiptV6],
    transaction_index: usize, output_index: u32,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    use CustodyExecutionErrorV2 as E;
    let policy_commitment = policy.commitment()?;
    let roots = &policy.roots;
    let inner = &child.execution;
    if child.source_binding().map_err(|_| E::Policy)? != roots.child_execution_binding
        || inner.observation_time != roots.observation_time { return Err(E::Policy); }
    let predecessor = child.checkpoint.commitment().map_err(|_| E::Lineage)?;
    let expected = crate::custody_child_lineage_v2::custody_accounting_binding_v6(&roots.lineage,
        predecessor, inner.binding.roots.execution.predecessor_checkpoint,
        inner.binding.roots.environment).map_err(|_| E::Lineage)?;
    if expected != roots.child_execution_binding { return Err(E::Lineage); }
    crate::custody_child_lineage_v2::verify_custody_accounting_lineage_v6(&roots.lineage,
        lineage_receipts, predecessor, child.checkpoint.projection.execution.height, parent_verifier)
        .map_err(|_| E::Lineage)?;
    crate::custody_history_wire_v2::encode_custody_history_v2(history).map_err(|_| E::History)?;
    let executed = crate::child_custody_guest_v6::execute_owned_custody_v6(
        child, parent_verifier, simplicity_verifier).map_err(|_| E::Child)?;
    let cursor = crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v6(
        &roots.domain, roots.verifier_address, roots.domain.custody_id, &executed,
        transaction_index, output_index).map_err(|_| E::Burn)?;
    let (cursor, confirmations) = cursor.finish_history_with_bundle(&history.steps, history.approval_index as usize,
        history.approval_transaction, history.approval_bundle.as_ref(), parent_verifier).map_err(|_| E::History)?;
    let statement = cursor.checked_statement(&roots.domain, roots.verifier_address, &confirmations,
        roots.destination_state, roots.destination_anchor, roots.minimum_confirmations)
        .map_err(|_| E::Statement)?;
    let destination = confirmations.destination_tuple(&history.steps.last().ok_or(E::History)?
        .parent.terminal_selected_state).map_err(|_| E::History)?;
    Ok(CustodyExecutionOutputV2 { policy_commitment, statement, destination,
        release_commitment: policy.release_commitment()?, observation_time: roots.observation_time })
}

pub fn execute_custody_accounting_v4<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy: &CustodyAccountingExecutionPolicyV4,
    child: &crate::child_custody_guest_v4::CustodyExecutionInputV4,
    history: &CustodyHistoryWitnessV2,
    lineage_receipts: &[crate::custody_child_lineage_v2::CustodyChildLineageReceiptV5],
    transaction_index: usize, output_index: u32,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    use CustodyExecutionErrorV2 as E;
    let policy_commitment = policy.commitment()?;
    if child.binding.commitment().map_err(|_| E::Policy)? != policy.child_execution_binding
        || child.observation_time != policy.observation_time { return Err(E::Policy); }
    let predecessor = child.binding.roots.execution.predecessor_checkpoint;
    let expected = policy.lineage.binding(predecessor, child.binding.roots.environment)
        .commitment().map_err(|_| E::Policy)?;
    if expected != policy.child_execution_binding { return Err(E::Lineage); }
    crate::custody_child_lineage_v2::verify_custody_accounting_lineage_v4(&policy.lineage,
        lineage_receipts, predecessor, child.checkpoint.execution.height, parent_verifier)
        .map_err(|_| E::Lineage)?;
    crate::custody_history_wire_v2::encode_custody_history_v2(history).map_err(|_| E::History)?;
    let executed = crate::child_custody_guest_v4::execute_owned_custody_v4(
        child, parent_verifier, simplicity_verifier).map_err(|_| E::Child)?;
    let cursor = crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v4(
        &policy.domain, policy.verifier_address, policy.domain.custody_id, &executed,
        transaction_index, output_index).map_err(|_| E::Burn)?;
    let (cursor, confirmations) = cursor.finish_history_with_bundle(&history.steps, history.approval_index as usize,
        history.approval_transaction, history.approval_bundle.as_ref(), parent_verifier).map_err(|_| E::History)?;
    let statement = cursor.checked_statement(&policy.domain, policy.verifier_address, &confirmations,
        policy.destination_state, policy.destination_anchor, policy.minimum_confirmations)
        .map_err(|_| E::Statement)?;
    let destination = confirmations.destination_tuple(&history.steps.last().ok_or(E::History)?
        .parent.terminal_selected_state).map_err(|_| E::History)?;
    Ok(CustodyExecutionOutputV2 { policy_commitment, statement, destination,
        release_commitment: policy.release_commitment()?, observation_time: policy.observation_time })
}

impl CustodyExecutionPolicyV2 {
    /// Reusable release roots: excludes self-referential deployment identities
    /// and per-proof predecessor, destination and observation time.
    pub fn release_commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if self.minimum_confirmations == 0 { return Err(CustodyExecutionErrorV2::Policy); }
        let mut bytes = vec![3];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_|CustodyExecutionErrorV2::Policy)?);
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-release/v3",&bytes))
    }
    pub fn commitment(&self) -> Result<Hash32,CustodyExecutionErrorV2> {
        if !self.domain.require_frozen_custody(self.verifier_address,self.domain.custody_id)
            || [self.child_execution_binding,self.destination_state,self.destination_anchor].contains(&[0;32])
            || self.minimum_confirmations == 0 || self.observation_time == 0 {
            return Err(CustodyExecutionErrorV2::Policy);
        }
        // custody_id commits every domain field and the verifier address.
        let mut bytes = vec![2];
        bytes.extend_from_slice(&self.lineage.commitment().map_err(|_|CustodyExecutionErrorV2::Policy)?);
        for value in [self.domain.custody_id,self.child_execution_binding,
            self.destination_state,self.destination_anchor] { bytes.extend_from_slice(&value); }
        bytes.extend_from_slice(&self.observation_time.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&crate::conversion_parent_link_v3::ETH_CUSTODY_REQUIRED_ACKS_V3.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-execution-policy/v2",&bytes))
    }
}

pub struct CustodyExecutionOutputV2 {
    policy_commitment: Hash32,
    statement: Hash32,
    release_commitment: Hash32,
    destination: crate::conversion_parent_link_v3::CustodyParentTupleV2,
    observation_time: u64,
}
impl CustodyExecutionOutputV2 {
    /// Candidate extended verifier boundary. The verifier must pin release,
    /// match statement, authenticate the exact relay tuple and check clock.
    /// Merely verifying SP1 over these bytes is not a redemption authorization.
    pub fn extended_bytes_v3(&self) -> [u8;144] {
        let mut bytes=[0;144];
        bytes[..32].copy_from_slice(&self.release_commitment);
        bytes[32..64].copy_from_slice(&self.statement);
        bytes[64..96].copy_from_slice(&self.destination.block_hash_display);
        bytes[96..100].copy_from_slice(&self.destination.height.to_be_bytes());
        bytes[100..104].copy_from_slice(&self.destination.median_time_past.to_be_bytes());
        bytes[104..136].copy_from_slice(&self.destination.chainwork_be);
        bytes[136..].copy_from_slice(&self.observation_time.to_be_bytes());
        bytes
    }
    /// This 64-byte composition output is NOT the vault's 32-byte SP1 ABI.
    /// A policy-pinned wrapper is required before use by that verifier.
    pub fn canonical_bytes(&self) -> [u8;64] {
        let mut bytes = [0;64]; bytes[..32].copy_from_slice(&self.policy_commitment);
        bytes[32..].copy_from_slice(&self.statement); bytes
    }
}

pub fn execute_custody_v2<P:FullAlphaReceiptVerifierV3,S:ElementsSimplicityReceiptVerifierV2>(
    policy:&CustodyExecutionPolicyV2, child:&AlphaChildExecutionInputV3,
    history:&CustodyHistoryWitnessV2, lineage_receipts:&[AlphaRecursiveReceiptBindingV3],
    transaction_index:usize, output_index:u32,
    parent_verifier:&P, simplicity_verifier:&S,
) -> Result<CustodyExecutionOutputV2,CustodyExecutionErrorV2> {
    let policy_commitment = policy.commitment()?;
    if child.binding.commitment().map_err(|_|CustodyExecutionErrorV2::Policy)? != policy.child_execution_binding
        || child.observation_time != policy.observation_time {
        return Err(CustodyExecutionErrorV2::Policy);
    }
    let expected_binding = policy.lineage.binding(child.binding.predecessor_checkpoint)
        .commitment().map_err(|_|CustodyExecutionErrorV2::Policy)?;
    if expected_binding != policy.child_execution_binding {
        return Err(CustodyExecutionErrorV2::Lineage);
    }
    verify_custody_child_lineage_v2(&policy.lineage,lineage_receipts,
        child.binding.predecessor_checkpoint,child.checkpoint.height,parent_verifier)
        .map_err(|_|CustodyExecutionErrorV2::Lineage)?;
    // Direct callers receive the same shape checks as canonical wire callers.
    crate::custody_history_wire_v2::encode_custody_history_v2(history)
        .map_err(|_|CustodyExecutionErrorV2::History)?;
    let executed = execute_alpha_child_execution_v3(child,parent_verifier,simplicity_verifier)
        .map_err(|_|CustodyExecutionErrorV2::Child)?;
    let cursor = extract_executed_custody_checkpoint_v2(&policy.domain,policy.verifier_address,
        policy.domain.custody_id,executed.checked(),transaction_index,output_index)
        .map_err(|_|CustodyExecutionErrorV2::Burn)?;
    let (cursor,confirmations) = cursor.finish_history_with_bundle(&history.steps,history.approval_index as usize,
        history.approval_transaction,history.approval_bundle.as_ref(),parent_verifier).map_err(|_|CustodyExecutionErrorV2::History)?;
    let statement = cursor.checked_statement(&policy.domain,policy.verifier_address,&confirmations,
        policy.destination_state,policy.destination_anchor,policy.minimum_confirmations)
        .map_err(|_|CustodyExecutionErrorV2::Statement)?;
    let destination=confirmations.destination_tuple(&history.steps.last()
        .ok_or(CustodyExecutionErrorV2::History)?.parent.terminal_selected_state)
        .map_err(|_|CustodyExecutionErrorV2::History)?;
    Ok(CustodyExecutionOutputV2 {policy_commitment,statement,destination,
        release_commitment:policy.release_commitment()?,observation_time:policy.observation_time})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parent_receipt_reuse_is_exact_success_only_bounded_and_local() {
        struct Verifier { calls: std::cell::Cell<usize>, reject: std::cell::Cell<bool> }
        impl FullAlphaReceiptVerifierV3 for Verifier {
            fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(), crate::FullAlphaAdapterErrorV3> {
                self.calls.set(self.calls.get()+1);
                if self.reject.get() { Err(crate::FullAlphaAdapterErrorV3::Receipt) } else { Ok(()) }
            }
        }
        let verifier = Verifier { calls: Default::default(), reject: std::cell::Cell::new(true) };
        let cache = SuccessfulParentReceipts::new(&verifier, 2, 1024);
        assert!(cache.verify([1;32], b"journal", b"marker").is_err());
        verifier.reject.set(false);
        cache.verify([1;32], b"journal", b"marker").unwrap();
        cache.verify([1;32], b"journal", b"marker").unwrap();
        assert_eq!(verifier.calls.get(), 2);
        verifier.reject.set(true);
        for (id, public, marker) in [([2;32], b"journal".as_slice(), b"marker".as_slice()),
            ([1;32], b"changed".as_slice(), b"marker".as_slice()),
            ([1;32], b"journal".as_slice(), b"changed".as_slice())] {
            assert!(cache.verify(id, public, marker).is_err());
        }
        assert_eq!(verifier.calls.get(), 5);
        // A new execution cannot inherit an earlier successful assertion.
        assert!(SuccessfulParentReceipts::new(&verifier,2,1024)
            .verify([1;32], b"journal", b"marker").is_err());
        verifier.reject.set(false);
        for (entries, bytes) in [(0,1024), (2,0)] {
            let saturated = SuccessfulParentReceipts::new(&verifier,entries,bytes);
            let before = verifier.calls.get();
            saturated.verify([1;32], b"journal", b"marker").unwrap();
            saturated.verify([1;32], b"journal", b"marker").unwrap();
            assert_eq!(verifier.calls.get(),before+2);
            assert!(saturated.entries.borrow().is_empty());
        }
    }
    #[test]
    fn parent_reuse_preserves_interleaved_script_occurrences() {
        struct Verifier(std::cell::RefCell<Vec<&'static str>>);
        impl FullAlphaReceiptVerifierV3 for Verifier {
            fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(), crate::FullAlphaAdapterErrorV3> {
                self.0.borrow_mut().push("parent"); Ok(())
            }
        }
        impl ElementsSimplicityReceiptVerifierV2 for Verifier {
            fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(), ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                self.0.borrow_mut().push("script"); Ok(())
            }
        }
        let verifier = Verifier(Default::default());
        let parent = SuccessfulParentReceipts::new(&verifier, 2, 1024);
        parent.verify([1;32], b"journal", b"marker").unwrap();
        ElementsSimplicityReceiptVerifierV2::verify(&verifier,[1;32],b"journal",b"marker").unwrap();
        parent.verify([1;32], b"journal", b"marker").unwrap();
        ElementsSimplicityReceiptVerifierV2::verify(&verifier,[1;32],b"journal",b"marker").unwrap();
        parent.verify([2;32], b"journal", b"marker").unwrap();
        assert_eq!(*verifier.0.borrow(), vec!["parent","script","script","parent"]);
    }
    #[test]
    fn v5_policy_separates_release_and_per_proof_roots() {
        let old = fixture();
        let policy = CustodyExecutionPolicyV5 {
            domain: old.domain.clone(), verifier_address: old.verifier_address,
            child_execution_binding: old.child_execution_binding,
            lineage: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV5 {
                execution: old.lineage.clone(), evaluator_source_closure: [18;32],
                genesis_bindings: [19;32], successor: None,
            },
            observation_time: old.observation_time, destination_state: old.destination_state,
            destination_anchor: old.destination_anchor, minimum_confirmations: old.minimum_confirmations,
        };
        let commitment = policy.commitment().unwrap();
        let release = policy.release_commitment().unwrap();
        let accounting = CustodyAccountingExecutionPolicyV4 {
            domain: policy.domain.clone(), verifier_address: policy.verifier_address,
            child_execution_binding: policy.child_execution_binding,
            lineage: crate::custody_child_lineage_v2::CustodyAccountingLineagePolicyV4 {
                roots: policy.lineage.clone(),
                genesis_initialization: [44;32],
            },
            observation_time: policy.observation_time, destination_state: policy.destination_state,
            destination_anchor: policy.destination_anchor, minimum_confirmations: policy.minimum_confirmations,
        };
        let accounting_commitment = accounting.commitment().unwrap();
        let accounting_release = accounting.release_commitment().unwrap();
        assert_ne!(accounting_commitment, commitment);
        assert_ne!(accounting_release, release);
        for field in 0..7 {
            let mut changed = accounting.clone();
            match field {
                0 => changed.observation_time += 1,
                1 => changed.destination_state[0] ^= 1,
                2 => changed.destination_anchor[0] ^= 1,
                3 => changed.child_execution_binding[0] ^= 1,
                4 => changed.minimum_confirmations += 1,
                5 => changed.lineage.roots.evaluator_source_closure[0] ^= 1,
                _ => changed.lineage.roots.genesis_bindings[0] ^= 1,
            }
            assert_ne!(changed.commitment().unwrap(), accounting_commitment);
            assert_eq!(changed.release_commitment().unwrap() == accounting_release, field < 4);
        }
        let mut invalid = accounting.clone(); invalid.minimum_confirmations = 0;
        assert!(invalid.commitment().is_err()); assert!(invalid.release_commitment().is_err());
        let mut invalid = accounting.clone(); invalid.verifier_address[0] ^= 1;
        assert!(invalid.commitment().is_err());
        assert_ne!(commitment, old.commitment().unwrap());
        assert_ne!(release, old.release_commitment().unwrap());
        for field in 0..4 {
            let mut bad = policy.clone();
            match field {
                0 => bad.observation_time += 1,
                1 => bad.destination_state[0] ^= 1,
                2 => bad.destination_anchor[0] ^= 1,
                _ => bad.child_execution_binding[0] ^= 1,
            }
            assert_ne!(bad.commitment().unwrap(), commitment);
            assert_eq!(bad.release_commitment().unwrap(), release);
        }
        for field in 0..3 {
            let mut bad = policy.clone();
            match field {
                0 => bad.minimum_confirmations += 1,
                1 => bad.lineage.evaluator_source_closure[0] ^= 1,
                _ => bad.lineage.genesis_bindings[0] ^= 1,
            }
            assert_ne!(bad.commitment().unwrap(), commitment);
            assert_ne!(bad.release_commitment().unwrap(), release);
        }
        let mut bad = policy.clone(); bad.minimum_confirmations = 0;
        assert!(bad.commitment().is_err()); assert!(bad.release_commitment().is_err());
        let mut bad = policy.clone(); bad.verifier_address[0] ^= 1;
        assert!(bad.commitment().is_err());
    }
    fn fixture() -> CustodyExecutionPolicyV2 {
        let mut domain = RedemptionDomainV2 { chain_id:[1;32],vault:[2;20],custody_id:[0;32],
            vault_id:[3;32],protocol_id:[4;32],security_model_id:[5;32],verifier_program_id:[6;32],
            verifier_config_hash:[7;32],elements_genesis_display:[8;32],usdd_asset_display:[9;32] };
        domain.custody_id = domain.derive_custody_id([10;20]);
        CustodyExecutionPolicyV2 { domain,verifier_address:[10;20],child_execution_binding:[11;32],
            lineage:CustodyChildLineagePolicyV2 {execution_program:[2;32],initial_checkpoint:[14;32],
                initial_height:0,parent_binding:[15;32],execution_policy:[16;32],
                simplicity_program:[1;32],deposit_configuration:[17;32]},
            observation_time:123,destination_state:[12;32],destination_anchor:[13;32],minimum_confirmations:2 }
    }
    #[test]
    fn policy_commits_trust_roots_clock_and_destination() {
        let expected = fixture().commitment().unwrap();
        for field in 0..7 {
            let mut policy = fixture();
            match field {
                0 => policy.child_execution_binding[0] ^= 1,
                1 => policy.observation_time += 1,
                2 => policy.destination_state[0] ^= 1,
                3 => policy.destination_anchor[0] ^= 1,
                4 => policy.minimum_confirmations += 1,
                6 => policy.lineage.initial_checkpoint[0] ^= 1,
                _ => { policy.domain.usdd_asset_display[0] ^= 1;
                    policy.domain.custody_id = policy.domain.derive_custody_id(policy.verifier_address); }
            }
            assert_ne!(policy.commitment().unwrap(),expected);
        }
        let mut policy = fixture(); policy.minimum_confirmations = 0;
        assert_eq!(policy.commitment(),Err(CustodyExecutionErrorV2::Policy));
        let mut policy = fixture(); policy.domain.usdd_asset_display[0] ^= 1;
        assert_eq!(policy.commitment(),Err(CustodyExecutionErrorV2::Policy));
        let output = CustodyExecutionOutputV2 {policy_commitment:expected,statement:[99;32],
            release_commitment:fixture().release_commitment().unwrap(),observation_time:123,
            destination:crate::conversion_parent_link_v3::CustodyParentTupleV2 {
                block_hash_display:[19;32],height:100,median_time_past:120,chainwork_be:[20;32]}};
        assert_eq!(&output.canonical_bytes()[..32],&expected);
        assert_eq!(&output.canonical_bytes()[32..],&[99;32]);
        let extended=output.extended_bytes_v3();
        assert_eq!(&extended[..32],&fixture().release_commitment().unwrap());
        assert_eq!(&extended[32..64],&[99;32]);
        assert_eq!(&extended[64..96],&[19;32]);
        assert_eq!(&extended[96..100],&100u32.to_be_bytes());
        assert_eq!(&extended[100..104],&120u32.to_be_bytes());
        assert_eq!(&extended[104..136],&[20;32]);
        assert_eq!(&extended[136..],&123u64.to_be_bytes());
        let stable=fixture().release_commitment().unwrap();
        let mut dynamic=fixture(); dynamic.observation_time+=1; dynamic.destination_state[0]^=1;
        dynamic.child_execution_binding[0]^=1;
        assert_eq!(dynamic.release_commitment().unwrap(),stable);
        dynamic.minimum_confirmations+=1;
        assert_ne!(dynamic.release_commitment().unwrap(),stable);
    }
}
