//! Byte-exact USDDVaultV2 redemption journal encoding, NOT a proof verifier.
//! The enclosing guest must establish burn execution, M3/M4/M6 approval,
//! authenticated parent finality and frozen deployment identities before
//! committing this digest. Encoding caller claims alone authorizes nothing.
use bitcoin::hashes::{sha256, Hash};
use ecx_full_consensus_validator_v2::Hash32;
use crate::custody_burn_v2::CustodyBurnV2;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedemptionDomainV2 {
    /// Full uint256 big-endian Solidity chain id, not a truncated u64.
    pub chain_id: Hash32,
    pub vault: [u8; 20],
    /// Frozen vault REDEMPTION_CUSTODY_ID, independently of the claim's field.
    pub custody_id: Hash32,
    pub vault_id: Hash32,
    pub protocol_id: Hash32,
    pub security_model_id: Hash32,
    pub verifier_program_id: Hash32,
    pub verifier_config_hash: Hash32,
    pub elements_genesis_display: Hash32,
    pub usdd_asset_display: Hash32,
}

impl RedemptionDomainV2 {
    /// Check a domain against an independently frozen custody commitment.
    /// The commitment includes every deployment identity used below. Actual
    /// code/storage authentication is still the enclosing relation's job.
    pub fn require_frozen_custody(&self, verifier_address: [u8;20], frozen_custody: Hash32) -> bool {
        self.vault != [0;20] && verifier_address != [0;20]
            && ![self.chain_id,self.vault_id,self.protocol_id,self.security_model_id,
                self.verifier_program_id,self.verifier_config_hash,self.elements_genesis_display,
                self.usdd_asset_display,frozen_custody].contains(&[0;32])
            && self.custody_id == frozen_custody
            && self.derive_custody_id(verifier_address) == frozen_custody
    }
    /// Reproduce the vault constructor's custody identity. The verifier
    /// address and this domain must be authenticated deployment inputs; this
    /// derivation alone does not establish deployed code or verifier validity.
    pub fn derive_custody_id(&self, verifier_address: [u8;20]) -> Hash32 {
        let mut deployment = verifier_address.to_vec();
        for value in [self.security_model_id, self.verifier_program_id, self.verifier_config_hash] {
            deployment.extend_from_slice(&value);
        }
        let deployment = sha256::Hash::hash(&deployment).to_byte_array();
        // keccak256("USDD_UNIFIED_CUSTODY_ID_V2").
        let mut bytes = vec![0x64,0xd5,0x26,0xda,0xfb,0xc6,0xab,0xec,0x9f,0x35,0x0d,0x6c,0xe7,0x0a,0xc3,0xf4,
            0x80,0x9a,0x9e,0x70,0x1b,0x6e,0xd8,0x0e,0x11,0xef,0xa8,0xfd,0xee,0xe5,0x4f,0x41];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.vault);
        for value in [self.vault_id, self.protocol_id, self.elements_genesis_display, self.usdd_asset_display, deployment] {
            bytes.extend_from_slice(&value);
        }
        sha256::Hash::hash(&bytes).to_byte_array()
    }
}

#[derive(Debug)]
pub enum ExecutedCustodyBurnErrorV2 {
    Domain,
    MissingCheckpoint,
    Checkpoint,
    Genesis,
    Burn(crate::custody_burn_v2::CommittedBurnError),
}

/// Execution-bound intermediate, not a final redemption authorization. Private
/// fields prevent replacing the checkpoint independently of the executed burn.
pub struct ExecutedCustodyCheckpointV2 {
    burn: CustodyBurnV2,
    checkpoint: Hash32,
    parent_binding: Hash32,
    parent_state: Hash32,
    parent_anchor: Hash32,
}
impl ExecutedCustodyCheckpointV2 {
    /// Compose the ordered parent history around one approval. Each supplied
    /// record contributes only its authenticated terminal parent block; child
    /// claims on that transport are not used. Consumes the cursor so partial
    /// failure cannot leave the caller with a seemingly completed history.
    pub fn finish_history<V: crate::FullAlphaReceiptVerifierV3>(self,
        steps: &[crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3],
        approval_index: usize, approval_transaction: bitcoin::Txid, verifier: &V,
    ) -> Result<(Self, crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2),
        crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        self.finish_history_with_bundle(steps,approval_index,approval_transaction,None,verifier)
    }
    pub fn finish_history_with_bundle<V: crate::FullAlphaReceiptVerifierV3>(mut self,
        steps: &[crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3],
        approval_index: usize, approval_transaction: bitcoin::Txid,
        bundle: Option<&crate::conversion_parent_link_v3::CustodyAckBundleV3>, verifier: &V,
    ) -> Result<(Self, crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2),
        crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        use crate::conversion_parent_link_v3::{AlphaConversionLinkErrorV3,
            authenticate_custody_m6_v2,CustodyApprovalConfirmationsV2,
            extend_custody_approval_confirmation_v2};
        if steps.len() > crate::custody_history_wire_v2::MAX_CUSTODY_HISTORY_STEPS_V2 || approval_index >= steps.len() {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        for step in &steps[..=approval_index] {
            self.advance_parent(&step.binding,&step.parent,&step.terminal_parent_predecessor,
                &step.terminal_parent_block,verifier)?;
        }
        let step = &steps[approval_index];
        let approval = match bundle {
            Some(bundle) => {
                if bundle.compute_txid() != approval_transaction {
                    return Err(AlphaConversionLinkErrorV3::M6Approval);
                }
                crate::conversion_parent_link_v3::authenticate_custody_acks_v3(
                    &step.binding,self.parent_binding,&step.parent,&step.terminal_parent_predecessor,
                    &step.terminal_parent_block,bundle,verifier)?
            }
            None => authenticate_custody_m6_v2(&step.binding,self.parent_binding,
                &step.parent,&step.terminal_parent_predecessor,&step.terminal_parent_block,
                approval_transaction,verifier)?,
        };
        self.require_history_approval(&approval)?;
        let mut confirmations = CustodyApprovalConfirmationsV2::new(approval);
        for step in &steps[approval_index+1..] {
            confirmations = extend_custody_approval_confirmation_v2(&confirmations,
                &step.binding,&step.parent,&step.terminal_parent_predecessor,
                &step.terminal_parent_block,verifier)?;
        }
        Ok((self,confirmations))
    }
    pub fn burn(&self) -> &CustodyBurnV2 { &self.burn }
    pub fn checkpoint(&self) -> Hash32 { self.checkpoint }
    pub fn parent_state(&self) -> Hash32 { self.parent_state }
    pub fn parent_anchor(&self) -> Hash32 { self.parent_anchor }
    /// Advance only through consecutively authenticated parent blocks. The
    /// burn/checkpoint remain fixed while the history cursor advances.
    pub fn advance_parent<V: crate::FullAlphaReceiptVerifierV3>(&mut self,
        binding: &crate::conversion_parent_link_v3::AlphaConversionLinkBindingV3,
        parent: &crate::FullAlphaAdapterInputV3,
        predecessor: &ecx_full_consensus_validator_v2::alpha_state_v3::AlphaExecutedConsensusStateV3,
        raw_block: &[u8], verifier: &V,
    ) -> Result<(), crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        use crate::conversion_parent_link_v3::{AlphaConversionLinkErrorV3,authenticate_terminal_parent};
        if binding.commitment()? != self.parent_binding
            || predecessor.commitment().map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)? != self.parent_state
            || predecessor.tip.block_hash.to_byte_array() != self.parent_anchor {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        let (statement,_,_) = authenticate_terminal_parent(binding,parent,predecessor,raw_block,verifier)?;
        self.parent_state = statement.terminal_selected_state_commitment;
        self.parent_anchor = statement.terminal_tip_hash_internal;
        Ok(())
    }
    /// History endpoint plus commitment matching, still not post-approval
    /// finality or authenticated deployment/code qualification.
    pub fn require_history_approval(&self,
        approval: &crate::conversion_parent_link_v3::AuthenticatedCustodyM6V2,
    ) -> Result<(), crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        if self.parent_state != approval.parent_state_commitment()
            || self.parent_anchor != approval.approval().block_hash.to_byte_array() {
            return Err(crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3::ParentBranch);
        }
        self.require_approval(approval,self.parent_binding)
    }
    /// Combine burn-to-approval ancestry with the same approval's confirmed
    /// destination. The enclosing relation must independently authenticate the
    /// expected destination and freeze the minimum depth; witness-selected
    /// values do not establish finality or qualify deployment identities.
    pub fn require_confirmed_history(&self,
        confirmations: &crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2,
        expected_state: Hash32, expected_anchor: Hash32, minimum_confirmations: u32,
    ) -> Result<(), crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        self.require_history_approval(confirmations.approval())?;
        confirmations.require_destination(expected_state, expected_anchor, minimum_confirmations)
    }
    /// Build the candidate V2 journal only after the linked history checks.
    /// `parentReplayCheckpointCommitment` is the complete confirmed parent
    /// state commitment, not its block hash. M6 IDs use display byte order,
    /// as do burn transaction IDs in the Solidity claim. Deployment code and
    /// destination authentication remain the enclosing relation's obligations.
    pub fn checked_statement(&self, domain: &RedemptionDomainV2,
        verifier_address: [u8;20],
        confirmations: &crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2,
        expected_state: Hash32, expected_anchor: Hash32, minimum_confirmations: u32,
    ) -> Result<Hash32, crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        if !domain.require_frozen_custody(verifier_address, self.burn.custody_id) {
            return Err(crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3::M6Approval);
        }
        self.require_confirmed_history(confirmations, expected_state, expected_anchor, minimum_confirmations)?;
        let mut m6id = confirmations.approval().approval().m6id.to_byte_array();
        m6id.reverse();
        Ok(encode_redemption_statement_v2(domain, &self.burn, m6id,
            self.checkpoint, confirmations.state()))
    }
    /// Still requires independently authenticated ancestry and finality in
    /// the enclosing proof. The approval may be in a later parent block.
    pub fn require_approval(&self,
        approval: &crate::conversion_parent_link_v3::AuthenticatedCustodyM6V2,
        frozen_approval_parent_binding: Hash32,
    ) -> Result<(), crate::conversion_parent_link_v3::AlphaConversionLinkErrorV3> {
        approval.require_checkpoint_approval(frozen_approval_parent_binding,
            self.burn.custody_id, self.checkpoint)
    }
}

pub fn extract_executed_custody_checkpoint_v2(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    checked: &crate::native_child_block_v3::ParentBoundCheckedChildState,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let burn = extract_domain_bound_executed_burn_v2(domain, verifier_address,
        frozen_custody, checked, transaction_index, vout)?;
    let checkpoint = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?
        .commitment().map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    Ok(ExecutedCustodyCheckpointV2 { burn, checkpoint,
        parent_binding: checked.parent().binding_commitment,
        parent_state: checked.parent().parent_terminal_state_commitment,
        parent_anchor: checked.parent().parent_block_hash_internal })
}

/// Capital-aware extraction. The output is obtainable only through the V4
/// executor; callers cannot pair an executed burn with a chosen capital root.
/// The contract statement ABI remains V2, but its Elements checkpoint is the
/// complete V4 commitment. The enclosing custody guest must also authenticate
/// V4 ancestry and freeze the matching execution program and source policy.
/// This does not make a V3 lineage receipt compatible with V4.
pub fn extract_executed_custody_checkpoint_v4(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    executed: &crate::child_execution_guest_v4::AlphaChildExecutionOutputV4,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let checked = executed.checked();
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let checkpoint = executed.checkpoint();
    let commitment = checkpoint.commitment()
        .map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    let statement = executed.public_values().0;
    if &checkpoint.execution != projection
        || statement.next_checkpoint != commitment
        || statement.child_hash_internal != checkpoint.execution.tip_internal
        || statement.child_height != checkpoint.execution.height
        || statement.parent != *checked.parent() {
        return Err(ExecutedCustodyBurnErrorV2::Checkpoint);
    }
    let burn = extract_domain_bound_executed_burn_v2(domain, verifier_address,
        frozen_custody, checked, transaction_index, vout)?;
    Ok(ExecutedCustodyCheckpointV2 { burn, checkpoint: commitment,
        parent_binding: checked.parent().binding_commitment,
        parent_state: checked.parent().parent_terminal_state_commitment,
        parent_anchor: checked.parent().parent_block_hash_internal })
}

/// V5 extraction consumes only the composed executor's private result type.
/// Its checkpoint includes capital and the authenticated BMM endpoint. This
/// does not supply ancestry/finality or authorize accepting older receipts.
/// Custody-accounting owned relation. Never reinterpret its checkpoint as the
/// legacy economic checkpoint. Approval history and finality remain separate.
pub fn extract_owned_accounting_checkpoint_v4(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    executed: &crate::child_custody_guest_v4::CustodyExecutionOutputV4,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let checked = executed.checked();
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let checkpoint = executed.checkpoint();
    let commitment = checkpoint.commitment().map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    let statement = executed.public_values().0;
    if &checkpoint.execution != projection || statement.next_checkpoint != commitment
        || statement.child_hash_internal != projection.tip_internal
        || statement.child_height != projection.height || statement.parent != *checked.parent() {
        return Err(ExecutedCustodyBurnErrorV2::Checkpoint);
    }
    extract_accounting_burn(domain, verifier_address, frozen_custody, checked,
        commitment, transaction_index, vout)
}

pub fn extract_owned_accounting_checkpoint_v6(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    executed: &crate::child_custody_guest_v6::CustodyExecutionOutputV6,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let checked = executed.checked();
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let checkpoint = executed.checkpoint();
    let commitment = checkpoint.commitment().map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    let statement = executed.public_values().0;
    if &checkpoint.projection.execution != projection || statement.next_checkpoint != commitment
        || statement.child_hash_internal != projection.tip_internal
        || statement.child_height != projection.height || statement.parent != *checked.parent() {
        return Err(ExecutedCustodyBurnErrorV2::Checkpoint);
    }
    extract_accounting_burn(domain, verifier_address, frozen_custody, checked,
        commitment, transaction_index, vout)
}

/// Accepts only the opaque result of native V7 execution, never a supplied journal.
pub fn extract_owned_accounting_checkpoint_v7(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    executed: &crate::child_custody_guest_v7::CustodyExecutionOutputV7,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let checked = executed.checked();
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let checkpoint = executed.checkpoint();
    let commitment = checkpoint.commitment().map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    let statement = executed.public_values().0;
    if &checkpoint.projection.execution != projection || statement.next_checkpoint != commitment
        || statement.child_hash_internal != projection.tip_internal
        || statement.child_height != projection.height || statement.parent != *checked.parent() {
        return Err(ExecutedCustodyBurnErrorV2::Checkpoint);
    }
    extract_accounting_burn(domain, verifier_address, frozen_custody, checked,
        commitment, transaction_index, vout)
}

fn extract_accounting_burn(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    checked: &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3,
    commitment: Hash32, transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    if !domain.require_frozen_custody(verifier_address, frozen_custody) {
        return Err(ExecutedCustodyBurnErrorV2::Domain);
    }
    let mut genesis = projection.genesis_internal; genesis.reverse();
    if genesis != domain.elements_genesis_display { return Err(ExecutedCustodyBurnErrorV2::Genesis); }
    let mut asset = projection.classification.custody_asset_id; asset.reverse();
    if asset != domain.usdd_asset_display {
        return Err(ExecutedCustodyBurnErrorV2::Burn(crate::custody_burn_v2::CommittedBurnError::AssetBinding));
    }
    let burn = checked.child().custody_burn_v2(transaction_index, vout, frozen_custody,
        domain.vault, 100).map_err(ExecutedCustodyBurnErrorV2::Burn)?;
    Ok(ExecutedCustodyCheckpointV2 { burn, checkpoint: commitment,
        parent_binding: checked.parent().binding_commitment,
        parent_state: checked.parent().parent_terminal_state_commitment,
        parent_anchor: checked.parent().parent_block_hash_internal })
}

pub fn extract_executed_custody_checkpoint_v5(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    executed: &crate::child_execution_guest_v4::AlphaChildExecutionOutputV5,
    transaction_index: usize, vout: u32,
) -> Result<ExecutedCustodyCheckpointV2, ExecutedCustodyBurnErrorV2> {
    let checked = executed.checked();
    let projection = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let checkpoint = executed.checkpoint();
    let commitment = checkpoint.commitment()
        .map_err(|_| ExecutedCustodyBurnErrorV2::Checkpoint)?;
    let statement = executed.public_values().0;
    if &checkpoint.state.execution != projection
        || statement.next_checkpoint != commitment
        || statement.child_hash_internal != checkpoint.state.execution.tip_internal
        || statement.child_height != checkpoint.state.execution.height
        || statement.parent != *checked.parent() {
        return Err(ExecutedCustodyBurnErrorV2::Checkpoint);
    }
    let burn = extract_domain_bound_executed_burn_v2(domain, verifier_address,
        frozen_custody, checked, transaction_index, vout)?;
    Ok(ExecutedCustodyCheckpointV2 { burn, checkpoint: commitment,
        parent_binding: checked.parent().binding_commitment,
        parent_state: checked.parent().parent_terminal_state_commitment,
        parent_anchor: checked.parent().parent_block_hash_internal })
}

/// Bind extraction to locally verified parent/child execution and a frozen
/// constructor-domain commitment. The fixed 100 atoms per reserve microtoken
/// implements the selected 8-decimal USDD / 6-decimal test-dollar 1:1 units.
/// This is NOT an M6 approval, ancestry/finality check or redemption proof.
pub fn extract_domain_bound_executed_burn_v2(
    domain: &RedemptionDomainV2, verifier_address: [u8;20], frozen_custody: Hash32,
    checked: &crate::native_child_block_v3::ParentBoundCheckedChildState,
    transaction_index: usize, vout: u32,
) -> Result<CustodyBurnV2, ExecutedCustodyBurnErrorV2> {
    if !domain.require_frozen_custody(verifier_address, frozen_custody) {
        return Err(ExecutedCustodyBurnErrorV2::Domain);
    }
    let checkpoint = checked.child().next_checkpoint()
        .ok_or(ExecutedCustodyBurnErrorV2::MissingCheckpoint)?;
    let mut genesis = checkpoint.genesis_internal;
    genesis.reverse();
    if genesis != domain.elements_genesis_display { return Err(ExecutedCustodyBurnErrorV2::Genesis); }
    checked.child().custody_burn_v2(transaction_index,vout,domain.usdd_asset_display,
        frozen_custody,domain.vault,100).map_err(ExecutedCustodyBurnErrorV2::Burn)
}

/// Match USDDVaultV2.redemptionStatement's three abi.encodePacked hashes.
/// Hash values and transaction ids are supplied in the contract's byte order.
/// `burn` must come from the authenticated execution, not a claim decoder.
/// Approval/checkpoint arguments still require verification by the caller.
pub fn encode_redemption_statement_v2(
    domain: &RedemptionDomainV2, burn: &CustodyBurnV2,
    approved_m6: Hash32, elements_checkpoint: Hash32, parent_checkpoint: Hash32,
) -> Hash32 {
    let mut identity = Vec::with_capacity(96);
    for value in [domain.security_model_id, domain.verifier_program_id, domain.verifier_config_hash] {
        identity.extend_from_slice(&value);
    }
    let identity = sha256::Hash::hash(&identity).to_byte_array();
    let mut claim = Vec::with_capacity(292);
    claim.extend_from_slice(&2u32.to_be_bytes());
    for value in [burn.custody_id, domain.elements_genesis_display,
        domain.usdd_asset_display, burn.txid_display] { claim.extend_from_slice(&value); }
    claim.extend_from_slice(&burn.vout.to_be_bytes());
    claim.extend_from_slice(&burn.burn_id);
    claim.extend_from_slice(&burn.amount_micro.to_be_bytes());
    claim.extend_from_slice(&burn.recipient);
    for value in [approved_m6, elements_checkpoint, parent_checkpoint] { claim.extend_from_slice(&value); }
    let claim = sha256::Hash::hash(&claim).to_byte_array();
    // keccak256("USDD_STRONG_REDEMPTION_STATEMENT_V2").
    let mut statement = vec![0x6f,0xdc,0x93,0x4f,0x6d,0x8d,0xe1,0x6a,0x32,0x4a,0x85,0x81,0x57,0x3c,0x66,0xc8,
        0x2b,0xb8,0x74,0x7c,0x6f,0xad,0x40,0x7e,0xac,0x79,0xb6,0xd6,0x23,0x91,0x5a,0xf1];
    statement.extend_from_slice(&2u32.to_be_bytes());
    statement.extend_from_slice(&domain.chain_id);
    statement.extend_from_slice(&domain.vault);
    for value in [domain.custody_id, domain.vault_id, domain.protocol_id, identity, claim] {
        statement.extend_from_slice(&value);
    }
    sha256::Hash::hash(&statement).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn solidity_packed_layout_and_recipient_binding() {
        let mut domain = RedemptionDomainV2 { chain_id: [1;32], vault: [2;20], custody_id: [11;32], vault_id: [3;32],
            protocol_id: [4;32], security_model_id: [5;32], verifier_program_id: [6;32],
            verifier_config_hash: [7;32], elements_genesis_display: [8;32], usdd_asset_display: [9;32] };
        let mut burn = CustodyBurnV2 { txid_display: [10;32], vout: 0x01020304, custody_id: [11;32],
            recipient: [12;20], amount_micro: 0x0102030405060708, burn_id: [13;32] };
        let custody = domain.derive_custody_id([17;20]);
        assert_eq!(custody, [0x78,0xde,0x88,0x79,0x98,0x79,0xcd,0x2e,0x8d,0x19,0x76,0x8a,0x61,0xd9,0x8f,0xae,
            0x56,0xae,0xb0,0xcb,0xb3,0x06,0x09,0xe7,0x21,0x34,0x03,0xcc,0xd2,0x0e,0x80,0xe6]);
        assert_ne!(custody, domain.derive_custody_id([18;20]));
        for i in 0..9 {
            let mut changed = domain.clone();
            let field: &mut [u8] = match i {
                0 => &mut changed.chain_id, 1 => &mut changed.vault,
                2 => &mut changed.vault_id, 3 => &mut changed.protocol_id,
                4 => &mut changed.elements_genesis_display, 5 => &mut changed.usdd_asset_display,
                6 => &mut changed.security_model_id, 7 => &mut changed.verifier_program_id,
                _ => &mut changed.verifier_config_hash,
            };
            field[0] ^= 1;
            assert_ne!(custody, changed.derive_custody_id([17;20]));
        }
        let mut claim_selected = domain.clone();
        claim_selected.custody_id = [99;32];
        assert_eq!(custody, claim_selected.derive_custody_id([17;20]));
        assert!(!claim_selected.require_frozen_custody([17;20],custody));
        claim_selected.custody_id = custody;
        assert!(claim_selected.require_frozen_custody([17;20],custody));
        assert!(!claim_selected.require_frozen_custody([18;20],custody));
        assert!(!claim_selected.require_frozen_custody([17;20],[0;32]));
        claim_selected.elements_genesis_display[0] ^= 1;
        assert!(!claim_selected.require_frozen_custody([17;20],custody));
        let digest = encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [16;32]);
        // Independent packed-byte fixture is recorded in the integration audit.
        assert_eq!(digest, [0x92,0x6d,0x64,0x66,0x6c,0x7e,0xba,0x5f,0x59,0x07,0x9e,0x14,0xe0,0x3b,0x03,0x48,
            0x67,0x5a,0xd1,0xa1,0x10,0x92,0xd1,0x0d,0x42,0x5c,0x36,0x45,0x10,0x34,0x5f,0x04]);
        burn.recipient[0] ^= 1;
        assert_ne!(digest, encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [16;32]));
        burn.recipient[0] ^= 1;
        assert_ne!(digest, encode_redemption_statement_v2(&domain, &burn, [17;32], [15;32], [16;32]));
        assert_ne!(digest, encode_redemption_statement_v2(&domain, &burn, [14;32], [17;32], [16;32]));
        assert_ne!(digest, encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [17;32]));
        // A claim cannot replace the contract's immutable custody domain.
        domain.custody_id[0] ^= 1;
        let changed_domain = encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [16;32]);
        assert_ne!(digest, changed_domain);
        domain.custody_id[0] ^= 1;
        burn.custody_id[0] ^= 1;
        assert_ne!(changed_domain, encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [16;32]));
        burn.custody_id[0] ^= 1;
        domain.chain_id = [0;32];
        domain.chain_id[24..].copy_from_slice(&11155111u64.to_be_bytes());
        // Same exact inputs are checked against compiled Solidity in qualify.mjs.
        assert_eq!(encode_redemption_statement_v2(&domain, &burn, [14;32], [15;32], [16;32]),
            [0x3a,0xb7,0xed,0x82,0xe7,0x6b,0x68,0x4b,0x6f,0x11,0x27,0xba,0x93,0xf7,0x7b,0x4a,
             0x3d,0xd5,0xcd,0xa4,0x34,0x72,0x72,0xd7,0xbb,0x4b,0xf7,0xee,0x73,0x34,0x1e,0x51]);
    }
}
