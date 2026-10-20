//! Reusable checkpoint ancestry from a frozen initial child checkpoint.
//! This authenticates execution ancestry, NOT canonical parent finality or
//! observation-time freshness. Those remain separate enclosing requirements.
use crate::{AlphaRecursiveReceiptBindingV3,FullAlphaReceiptVerifierV3,
    child_execution_guest_v3::{AlphaChildExecutionBindingV3,AlphaChildExecutionPublicValuesV3}};

#[cfg(test)]
mod v5_tests {
    use super::*;
    struct Exact { program: [u8;32], journals: Vec<Vec<u8>> }
    impl FullAlphaReceiptVerifierV3 for Exact {
        fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
            -> Result<(),crate::FullAlphaAdapterErrorV3> {
            if program == self.program && marker == [1] && self.journals.iter().any(|j| j == journal) {
                Ok(())
            } else { Err(crate::FullAlphaAdapterErrorV3::Receipt) }
        }
    }
    #[test]
    fn v5_lineage_authenticates_changing_environments_and_all_roots() {
        let policy = CustodyChildLineagePolicyV5 {
            execution: CustodyChildLineagePolicyV2 { execution_program: [1;32], initial_checkpoint: [2;32],
                initial_height: 0, parent_binding: [3;32], execution_policy: [4;32],
                simplicity_program: [5;32], deposit_configuration: [6;32] },
            evaluator_source_closure: [7;32], genesis_bindings: [8;32], successor: None,
        };
        let mut entries = Vec::new();
        let mut checkpoint = policy.execution.initial_checkpoint;
        for height in 1..=2 {
            let environment = [height as u8 + 10;32];
            let statement = crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5(
                AlphaChildExecutionPublicValuesV3 {
                    source_binding: policy.binding(checkpoint, environment).commitment().unwrap(),
                    predecessor_checkpoint: checkpoint, next_checkpoint: [height as u8 + 20;32],
                    child_hash_internal: [9;32], child_height: height, observation_time: 100,
                    parent: crate::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3 {
                        binding_commitment: policy.execution.parent_binding, parent_statement_commitment: [6;32],
                        parent_predecessor_state_commitment: [7;32], parent_terminal_state_commitment: [8;32],
                        parent_block_hash_internal: [9;32], parent_height: 100,
                        parent_predecessor_hash_internal: [10;32], m7_critical_hash_internal: [11;32], m7_coinbase_vout: 1,
                    },
                });
            checkpoint = statement.0.next_checkpoint;
            entries.push(CustodyChildLineageReceiptV5 { environment,
                receipt: AlphaRecursiveReceiptBindingV3 { public_values: statement.canonical_bytes().to_vec(), proof_marker: vec![1] } });
        }
        let verifier = Exact { program: policy.execution.execution_program,
            journals: entries.iter().map(|e| e.receipt.public_values.clone()).collect() };
        let check = |p: &CustodyChildLineagePolicyV5, e: &[CustodyChildLineageReceiptV5]| {
            verify_custody_child_lineage_v5(p, e, checkpoint, 2, &verifier)
        };
        assert!(check(&policy, &entries).is_ok());
        let custody = CustodyAccountingLineagePolicyV4 { roots: policy.clone(), genesis_initialization: [44;32] };
        assert_ne!(custody.commitment().unwrap(), policy.commitment().unwrap());
        let mut accounting = entries.clone();
        for entry in &mut accounting {
            let mut statement = crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&entry.receipt.public_values).unwrap().0;
            statement.source_binding = custody.binding(statement.predecessor_checkpoint,entry.environment).commitment().unwrap();
            entry.receipt.public_values = crate::child_custody_guest_v4::CustodyExecutionPublicValuesV4(statement).canonical_bytes().to_vec();
        }
        let exact = Exact { program: policy.execution.execution_program,
            journals: accounting.iter().map(|e| e.receipt.public_values.clone()).collect() };
        assert!(verify_custody_accounting_lineage_v4(&custody,&accounting,checkpoint,2,&exact).is_ok());
        // Synthetic receipts isolate lineage binding, not recursive proof validity.
        let v7: Vec<_> = accounting.iter().map(|entry| {
            let mut statement = crate::child_custody_guest_v4::CustodyExecutionPublicValuesV4::
                from_canonical_bytes(&entry.receipt.public_values).unwrap().0;
            let projection_predecessor = statement.predecessor_checkpoint;
            statement.source_binding = custody_accounting_binding_v7(&custody,
                statement.predecessor_checkpoint, projection_predecessor, entry.environment).unwrap();
            CustodyAccountingLineageReceiptV6 { projection_predecessor, environment: entry.environment,
                receipt: AlphaRecursiveReceiptBindingV3 {
                    public_values: crate::child_custody_guest_v7::CustodyExecutionPublicValuesV7(statement)
                        .canonical_bytes().to_vec(), proof_marker: vec![1] } }
        }).collect();
        let v7_exact = Exact { program: policy.execution.execution_program,
            journals: v7.iter().map(|e| e.receipt.public_values.clone()).collect() };
        assert_ne!(custody_accounting_lineage_commitment_v7(&custody).unwrap(),
            custody_accounting_lineage_commitment_v6(&custody).unwrap());
        assert!(verify_custody_accounting_lineage_v7(&custody,&v7,checkpoint,2,&v7_exact).is_ok());
        assert!(verify_custody_accounting_lineage_v6(&custody,&v7,checkpoint,2,&v7_exact).is_err());
        for mutation in 0..6 {
            let mut bad = v7.clone();
            match mutation {
                0 => bad[0].receipt.public_values[0] = crate::child_custody_guest_v6::CUSTODY_EXECUTION_VERSION_V6,
                1 => bad[0].projection_predecessor[0] ^= 1,
                2 => bad[0].environment[0] ^= 1,
                3 => bad[0].receipt.proof_marker.clear(),
                4 => bad.reverse(),
                _ => bad[0].receipt.proof_marker = vec![2],
            }
            assert!(verify_custody_accounting_lineage_v7(&custody,&bad,checkpoint,2,&v7_exact).is_err());
        }
        let mut wrong_policy = custody.clone();
        wrong_policy.roots.execution.execution_policy[0] ^= 1;
        assert!(verify_custody_accounting_lineage_v7(&wrong_policy,&v7,checkpoint,2,&v7_exact).is_err());
        let mut substituted=custody.clone(); substituted.genesis_initialization[0]^=1;
        assert_ne!(substituted.commitment().unwrap(),custody.commitment().unwrap());
        assert!(verify_custody_accounting_lineage_v4(&substituted,&accounting,checkpoint,2,&exact).is_err());
        let mut old_accounting=accounting.clone(); old_accounting[0].receipt.public_values[0]=0xac;
        assert!(verify_custody_accounting_lineage_v4(&custody,&old_accounting,checkpoint,2,&exact).is_err());
        assert!(verify_custody_accounting_lineage_v4(&custody,&entries,checkpoint,2,&verifier).is_err());
        assert!(verify_custody_child_lineage_v5(&policy,&accounting,checkpoint,2,&exact).is_err());
        for field in 0..4 {
            let mut bad = accounting.clone();
            match field {
                0 => bad[0].environment[0] ^= 1,
                1 => bad[0].receipt.proof_marker.clear(),
                2 => bad.reverse(),
                _ => bad[0].receipt.public_values[0] = 0xab,
            }
            assert!(verify_custody_accounting_lineage_v4(&custody,&bad,checkpoint,2,&exact).is_err());
        }
        // Synthetic receipt verifier isolates the historical block-opening
        // relation; this is not an SP1 execution fixture.
        {
            use elements::{hashes::Hash as _, BlockHeader, BlockHash, TxMerkleNode,
                BlockExtData, Script, Transaction, TxIn, TxOut, LockTime};
            use crate::settlement_history_v5::open_historical_transaction_v5;
            let transactions = vec![Transaction { version: 2, lock_time: LockTime::ZERO,
                input: vec![TxIn::default()], output: vec![TxOut::default()] }];
            let mut block = crate::native_block_wire_v3::NativeBlock {
                header: crate::native_header_v3::NativeHeader {
                    base: BlockHeader { version: 1, prev_blockhash: BlockHash::all_zeros(),
                        merkle_root: TxMerkleNode::all_zeros(), time: 1, height: 2,
                        ext: BlockExtData::Proof { challenge: Script::new(), solution: Script::new() } },
                    withdrawal: [0;32], bmm_proof: [0;32], exchange: [0;32], forced: [0;32],
                    deposit: [0;32], parent_height: 0, forced_cursor: 0, deposit_cursor: 0,
                    oldest_backlog_height: 0,
                }, transactions, bmm_proof: vec![],
            };
            block.header.base.merkle_root = ecx_full_consensus_validator_v2::elements_v2::
                elements_transaction_merkle_root_v2(&block.transactions).unwrap();
            let mut history = entries.clone();
            let mut statement = crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5::
                from_canonical_bytes(&history[1].receipt.public_values).unwrap();
            statement.0.child_hash_internal = block.header.hash_internal().unwrap();
            history[1].receipt.public_values = statement.canonical_bytes().to_vec();
            let exact = Exact { program: policy.execution.execution_program,
                journals: history.iter().map(|e| e.receipt.public_values.clone()).collect() };
            let raw = block.encode().unwrap();
            let opened = open_historical_transaction_v5(&policy, &history, checkpoint, 2,
                1, &raw, 0, &exact).unwrap();
            assert_eq!(opened.canonical_bytes(), elements::encode::serialize(&block.transactions[0]));
            assert_eq!(opened.txid_internal(), block.transactions[0].txid().to_byte_array());
            assert!(open_historical_transaction_v5(&policy, &history, checkpoint, 2,
                0, &raw, 0, &exact).is_err());
            assert!(open_historical_transaction_v5(&policy, &history, checkpoint, 2,
                1, &raw, 1, &exact).is_err());
            assert!(open_historical_transaction_v5(&policy, &history, [99;32], 2,
                1, &raw, 0, &exact).is_err());
            let mut bad = history.clone(); bad[1].receipt.proof_marker = vec![2];
            assert!(open_historical_transaction_v5(&policy, &bad, checkpoint, 2,
                1, &raw, 0, &exact).is_err());
            block.transactions[0].output[0].script_pubkey = Script::from(vec![0x51]);
            assert!(open_historical_transaction_v5(&policy, &history, checkpoint, 2,
                1, &block.encode().unwrap(), 0, &exact).is_err());
            block.transactions[0].output[0].script_pubkey = Script::new();
            block.transactions[0].input[0].witness.script_witness = vec![vec![0;32]];
            assert!(open_historical_transaction_v5(&policy, &history, checkpoint, 2,
                1, &block.encode().unwrap(), 0, &exact).is_err());
        }
        for field in 0..9 {
            let mut bad = policy.clone();
            match field {
                0 => bad.evaluator_source_closure[0] ^= 1,
                1 => bad.genesis_bindings[0] ^= 1,
                2 => bad.execution.execution_program = [2;32],
                3 => bad.execution.parent_binding[0] ^= 1,
                4 => bad.execution.execution_policy[0] ^= 1,
                5 => bad.execution.simplicity_program = [6;32],
                6 => bad.execution.deposit_configuration[0] ^= 1,
                7 => bad.execution.initial_checkpoint[0] ^= 1,
                _ => bad.successor = Some(crate::child_execution_statement_v4::SuccessorIdentityV4 {
                    configuration_hash: [1;32], program_id: [2;32], transition_cmr: [3;32] }),
            }
            assert_ne!(bad.commitment().unwrap(), policy.commitment().unwrap());
            assert!(check(&bad, &entries).is_err());
        }
        let mut bad = entries.clone(); bad[1].environment[0] ^= 1;
        assert!(check(&policy, &bad).is_err());
        let mut bad = entries.clone(); bad[0].receipt.proof_marker = vec![2];
        assert_eq!(check(&policy, &bad), Err(CustodyChildLineageErrorV2::Receipt));
        let mut bad = entries.clone(); bad.reverse();
        assert!(check(&policy, &bad).is_err());
        for version in [0xaa, crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_VERSION_V3] {
            let mut bad = entries.clone(); bad[0].receipt.public_values[0] = version;
            assert!(check(&policy, &bad).is_err());
        }
        assert!(verify_custody_child_lineage_v5(&policy, &entries, checkpoint, 3, &verifier).is_err());
        assert!(verify_custody_child_lineage_v5(&policy, &[], policy.execution.initial_checkpoint, 0, &verifier).is_ok());
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyChildLineagePolicyV2 {
    pub execution_program: [u8;32],
    pub initial_checkpoint: [u8;32],
    pub initial_height: u32,
    pub parent_binding: [u8;32],
    pub execution_policy: [u8;32],
    pub simplicity_program: [u8;32],
    pub deposit_configuration: [u8;32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum CustodyChildLineageErrorV2 { Policy, Shape, Binding, Receipt, Continuity }

/// V5 release roots. Environment changes per block and is authenticated by
/// the pinned execution guest; it must not be frozen to one block's context.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyChildLineagePolicyV5 {
    pub execution: CustodyChildLineagePolicyV2,
    pub evaluator_source_closure: [u8;32],
    pub genesis_bindings: [u8;32],
    pub successor: Option<crate::child_execution_statement_v4::SuccessorIdentityV4>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyChildLineageReceiptV5 {
    pub environment: [u8;32],
    pub receipt: AlphaRecursiveReceiptBindingV3,
}

/// Custody-accounting lineage is a distinct relation, not a V5 receipt alias.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingLineagePolicyV4 {
    pub roots: CustodyChildLineagePolicyV5,
    pub genesis_initialization: [u8;32],
}
impl CustodyAccountingLineagePolicyV4 {
    pub fn commitment(&self) -> Result<[u8;32],CustodyChildLineageErrorV2> {
        if self.genesis_initialization == [0;32] { return Err(CustodyChildLineageErrorV2::Policy); }
        let mut bytes = self.roots.commitment()?.to_vec();
        bytes.extend_from_slice(&self.genesis_initialization);
        Ok(crate::tagged_hash("USDD/alpha-custody-accounting-lineage/v5", &bytes))
    }
    pub(crate) fn binding(&self, predecessor: [u8;32], environment: [u8;32])
        -> crate::child_custody_guest_v4::CustodyExecutionBindingV4 {
        crate::child_custody_guest_v4::CustodyExecutionBindingV4 {
            roots: self.roots.binding(predecessor, environment),
            genesis_initialization: self.genesis_initialization,
        }
    }
}

/// Authenticates ancestry only; destination finality and freshness remain
/// mandatory obligations of the enclosing redemption composition.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAccountingLineageReceiptV6 {
    pub projection_predecessor: [u8;32],
    pub environment: [u8;32],
    pub receipt: AlphaRecursiveReceiptBindingV3,
}

/// Roots retain their named layout, but initial_checkpoint is a V5 full-anchor
/// commitment and execution_program MUST be the independently frozen V6 guest.
pub fn custody_accounting_lineage_commitment_v6(policy: &CustodyAccountingLineagePolicyV4)
    -> Result<[u8;32],CustodyChildLineageErrorV2> {
    Ok(crate::tagged_hash("USDD/alpha-custody-accounting-lineage/v6", &policy.commitment()?))
}

pub fn custody_accounting_binding_v6(policy: &CustodyAccountingLineagePolicyV4,
    predecessor: [u8;32], projection: [u8;32], environment: [u8;32])
    -> Result<[u8;32],CustodyChildLineageErrorV2> {
    let inner = policy.binding(projection, environment).commitment()
        .map_err(|_| CustodyChildLineageErrorV2::Binding)?;
    crate::child_custody_guest_v6::source_binding_v6(inner, predecessor)
        .map_err(|_| CustodyChildLineageErrorV2::Binding)
}

pub fn verify_custody_accounting_lineage_v6(policy: &CustodyAccountingLineagePolicyV4,
    receipts: &[CustodyAccountingLineageReceiptV6], terminal: [u8;32], terminal_height: u32,
    verifier: &impl FullAlphaReceiptVerifierV3) -> Result<(),CustodyChildLineageErrorV2> {
    use CustodyChildLineageErrorV2::*;
    custody_accounting_lineage_commitment_v6(policy)?;
    if receipts.len() > 8192 || terminal == [0;32] { return Err(Shape); }
    let roots = &policy.roots.execution;
    let mut checkpoint = roots.initial_checkpoint;
    let mut height = roots.initial_height;
    for entry in receipts {
        let receipt = &entry.receipt;
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 { return Err(Shape); }
        let statement = crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6::from_canonical_bytes(
            &receipt.public_values).map_err(|_| Binding)?.0;
        let expected = custody_accounting_binding_v6(policy, checkpoint,
            entry.projection_predecessor, entry.environment)?;
        if statement.source_binding != expected || statement.predecessor_checkpoint != checkpoint
            || statement.parent.binding_commitment != roots.parent_binding { return Err(Binding); }
        height = height.checked_add(1).ok_or(Continuity)?;
        if statement.child_height != height { return Err(Continuity); }
        verifier.verify(roots.execution_program, &receipt.public_values, &receipt.proof_marker)
            .map_err(|_| Receipt)?;
        checkpoint = statement.next_checkpoint;
    }
    if checkpoint != terminal || height != terminal_height { return Err(Continuity); }
    Ok(())
}

/// V7 retains the full-anchor checkpoint layout but authenticates the separately
/// frozen reissuance policy. A V6 receipt is never a V7 ancestry proof.
pub fn custody_accounting_lineage_commitment_v7(policy: &CustodyAccountingLineagePolicyV4)
    -> Result<[u8;32],CustodyChildLineageErrorV2> {
    Ok(crate::tagged_hash("USDD/alpha-custody-accounting-lineage/v7", &policy.commitment()?))
}

pub fn custody_accounting_binding_v7(policy: &CustodyAccountingLineagePolicyV4,
    predecessor: [u8;32], projection: [u8;32], environment: [u8;32])
    -> Result<[u8;32],CustodyChildLineageErrorV2> {
    let anchor = custody_accounting_binding_v6(policy, predecessor, projection, environment)?;
    crate::child_custody_guest_v7::source_binding_v7(anchor, policy.roots.execution.execution_policy)
        .map_err(|_| CustodyChildLineageErrorV2::Binding)
}

pub fn verify_custody_accounting_lineage_v7(policy: &CustodyAccountingLineagePolicyV4,
    receipts: &[CustodyAccountingLineageReceiptV6], terminal: [u8;32], terminal_height: u32,
    verifier: &impl FullAlphaReceiptVerifierV3) -> Result<(),CustodyChildLineageErrorV2> {
    use CustodyChildLineageErrorV2::*;
    custody_accounting_lineage_commitment_v7(policy)?;
    if receipts.len() > 8192 || terminal == [0;32] { return Err(Shape); }
    let roots = &policy.roots.execution;
    let mut checkpoint = roots.initial_checkpoint;
    let mut height = roots.initial_height;
    for entry in receipts {
        let receipt = &entry.receipt;
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 { return Err(Shape); }
        let statement = crate::child_custody_guest_v7::CustodyExecutionPublicValuesV7::from_canonical_bytes(
            &receipt.public_values).map_err(|_| Binding)?.0;
        let expected = custody_accounting_binding_v7(policy, checkpoint,
            entry.projection_predecessor, entry.environment)?;
        if statement.source_binding != expected || statement.predecessor_checkpoint != checkpoint
            || statement.parent.binding_commitment != roots.parent_binding { return Err(Binding); }
        height = height.checked_add(1).ok_or(Continuity)?;
        if statement.child_height != height { return Err(Continuity); }
        verifier.verify(roots.execution_program, &receipt.public_values, &receipt.proof_marker)
            .map_err(|_| Receipt)?;
        checkpoint = statement.next_checkpoint;
    }
    if checkpoint != terminal || height != terminal_height { return Err(Continuity); }
    Ok(())
}

pub fn verify_custody_accounting_lineage_v4(policy: &CustodyAccountingLineagePolicyV4,
    receipts: &[CustodyChildLineageReceiptV5], terminal: [u8;32], terminal_height: u32,
    verifier: &impl FullAlphaReceiptVerifierV3) -> Result<(),CustodyChildLineageErrorV2> {
    use CustodyChildLineageErrorV2::*;
    policy.commitment()?;
    if receipts.len() > 8192 || terminal == [0;32] { return Err(Shape); }
    let execution = &policy.roots.execution;
    let mut checkpoint = execution.initial_checkpoint;
    let mut height = execution.initial_height;
    for entry in receipts {
        let receipt = &entry.receipt;
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 { return Err(Shape); }
        let statement = crate::child_custody_guest_v4::CustodyExecutionPublicValuesV4::from_canonical_bytes(
            &receipt.public_values).map_err(|_| Binding)?.0;
        let expected = policy.binding(checkpoint, entry.environment).commitment().map_err(|_| Policy)?;
        if statement.source_binding != expected || statement.predecessor_checkpoint != checkpoint
            || statement.parent.binding_commitment != execution.parent_binding { return Err(Binding); }
        height = height.checked_add(1).ok_or(Continuity)?;
        if statement.child_height != height { return Err(Continuity); }
        verifier.verify(execution.execution_program, &receipt.public_values, &receipt.proof_marker)
            .map_err(|_| Receipt)?;
        checkpoint = statement.next_checkpoint;
    }
    if checkpoint != terminal || height != terminal_height { return Err(Continuity); }
    Ok(())
}

impl CustodyChildLineagePolicyV5 {
    pub fn commitment(&self) -> Result<[u8;32],CustodyChildLineageErrorV2> {
        let execution = self.execution.commitment()?;
        if [self.evaluator_source_closure, self.genesis_bindings].contains(&[0;32]) {
            return Err(CustodyChildLineageErrorV2::Policy);
        }
        let mut bytes = vec![5];
        for value in [execution, self.evaluator_source_closure, self.genesis_bindings] {
            bytes.extend_from_slice(&value);
        }
        bytes.push(u8::from(self.successor.is_some()));
        if let Some(successor) = self.successor {
            successor.validate().map_err(|_| CustodyChildLineageErrorV2::Policy)?;
            for value in [successor.configuration_hash, successor.program_id, successor.transition_cmr] {
                bytes.extend_from_slice(&value);
            }
        }
        Ok(crate::tagged_hash("USDD/alpha-custody-child-lineage/v5", &bytes))
    }

    pub(crate) fn binding(&self, predecessor: [u8;32], environment: [u8;32])
        -> crate::child_execution_statement_v4::AlphaChildExecutionBindingV5 {
        crate::child_execution_statement_v4::AlphaChildExecutionBindingV5 {
            execution: self.execution.binding(predecessor), environment,
            evaluator_source_closure: self.evaluator_source_closure,
            genesis_bindings: self.genesis_bindings, successor: self.successor,
        }
    }
}

/// Each environment opening is bound to that receipt's source commitment.
/// Receipt verification, not a host-supplied hash alone, authenticates its
/// derivation from the predecessor and parent context. Finality is separate.
pub fn verify_custody_child_lineage_v5(policy: &CustodyChildLineagePolicyV5,
    receipts: &[CustodyChildLineageReceiptV5], terminal: [u8;32], terminal_height: u32,
    verifier: &impl FullAlphaReceiptVerifierV3) -> Result<(),CustodyChildLineageErrorV2> {
    use CustodyChildLineageErrorV2::*;
    policy.commitment()?;
    if receipts.len() > 8192 || terminal == [0;32] { return Err(Shape); }
    let mut checkpoint = policy.execution.initial_checkpoint;
    let mut height = policy.execution.initial_height;
    for entry in receipts {
        let receipt = &entry.receipt;
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 { return Err(Shape); }
        let statement = crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5::from_canonical_bytes(
            &receipt.public_values).map_err(|_| Binding)?.0;
        let expected = policy.binding(checkpoint, entry.environment).commitment().map_err(|_| Policy)?;
        if statement.source_binding != expected || statement.predecessor_checkpoint != checkpoint
            || statement.parent.binding_commitment != policy.execution.parent_binding { return Err(Binding); }
        height = height.checked_add(1).ok_or(Continuity)?;
        if statement.child_height != height { return Err(Continuity); }
        verifier.verify(policy.execution.execution_program, &receipt.public_values, &receipt.proof_marker)
            .map_err(|_| Receipt)?;
        checkpoint = statement.next_checkpoint;
    }
    if checkpoint != terminal || height != terminal_height { return Err(Continuity); }
    Ok(())
}

impl CustodyChildLineagePolicyV2 {
    pub fn commitment(&self) -> Result<[u8;32],CustodyChildLineageErrorV2> {
        if !crate::alpha_sp1_program_id_is_canonical_v3(self.execution_program)
            || self.initial_checkpoint == [0;32] || self.initial_height == u32::MAX {
            return Err(CustodyChildLineageErrorV2::Policy);
        }
        self.binding(self.initial_checkpoint).commitment().map_err(|_|CustodyChildLineageErrorV2::Policy)?;
        let mut bytes = vec![2];
        for hash in [self.execution_program,self.initial_checkpoint,self.parent_binding,
            self.execution_policy,self.simplicity_program,self.deposit_configuration] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&self.initial_height.to_be_bytes());
        Ok(crate::tagged_hash("USDD/alpha-custody-child-lineage/v2",&bytes))
    }
    pub(crate) fn binding(&self, predecessor_checkpoint:[u8;32]) -> AlphaChildExecutionBindingV3 {
        AlphaChildExecutionBindingV3 {parent_binding:self.parent_binding,predecessor_checkpoint,
            execution_policy:self.execution_policy,simplicity_evaluator_program_id:self.simplicity_program,
            deposit_configuration:self.deposit_configuration}
    }
}

/// Policy is an independently trusted release input. Only predecessor changes
/// per receipt; the witness cannot supply a replacement execution policy.
pub fn verify_custody_child_lineage_v2(policy:&CustodyChildLineagePolicyV2,
    receipts:&[AlphaRecursiveReceiptBindingV3], terminal:[u8;32],terminal_height:u32,
    verifier:&impl FullAlphaReceiptVerifierV3) -> Result<(),CustodyChildLineageErrorV2> {
    use CustodyChildLineageErrorV2::*;
    policy.commitment()?;
    if receipts.len()>8192 || terminal == [0;32] { return Err(Shape); }
    let mut checkpoint=policy.initial_checkpoint;
    let mut height=policy.initial_height;
    for receipt in receipts {
        if receipt.proof_marker.is_empty()
            || receipt.proof_marker.len()>crate::MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 { return Err(Shape); }
        let statement=AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&receipt.public_values)
            .map_err(|_|Binding)?;
        let expected=policy.binding(checkpoint).commitment().map_err(|_|Policy)?;
        if statement.source_binding != expected || statement.predecessor_checkpoint != checkpoint
            || statement.parent.binding_commitment != policy.parent_binding { return Err(Binding); }
        height=height.checked_add(1).ok_or(Continuity)?;
        if statement.child_height != height { return Err(Continuity); }
        verifier.verify(policy.execution_program,&receipt.public_values,&receipt.proof_marker)
            .map_err(|_|Receipt)?;
        checkpoint=statement.next_checkpoint;
    }
    if checkpoint != terminal || height != terminal_height { return Err(Continuity); }
    Ok(())
}
