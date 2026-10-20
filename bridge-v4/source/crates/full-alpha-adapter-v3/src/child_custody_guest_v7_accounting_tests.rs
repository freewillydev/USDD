use super::*;
use crate::conversion_parent_link_v3::tests::TranscriptVerifier;

// Observe only successfully checked callbacks; retain duplicates and shared order.
// This records fixture requirements, never supplies or qualifies real proofs.
struct ReceiptTrace<'a, P, S> {
    parent: &'a P,
    simplicity: &'a S,
    calls: std::cell::RefCell<Vec<serde_json::Value>>,
}
impl<P, S> ReceiptTrace<'_, P, S> {
    fn record(&self, kind: &str, id: Hash32, values: &[u8], marker: &[u8]) {
        use bitcoin::hashes::{sha256, Hash};
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut calls = self.calls.borrow_mut();
        let index = calls.len();
        calls.push(serde_json::json!({
            "index":index,"kind":kind,"program_id":hex(&id),
            "public_values_length":values.len(),"public_values":hex(values),
            "public_values_sha256":sha256::Hash::hash(values).to_string(),
            "fixture_marker":hex(marker)
        }));
    }
}
impl<P: FullAlphaReceiptVerifierV3, S> FullAlphaReceiptVerifierV3 for ReceiptTrace<'_, P, S> {
    fn verify(&self, id: Hash32, values: &[u8], marker: &[u8]) -> Result<(), crate::FullAlphaAdapterErrorV3> {
        self.parent.verify(id, values, marker)?;
        self.record("parent_or_lineage", id, values, marker);
        Ok(())
    }
}
impl<P, S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>
    ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for ReceiptTrace<'_, P, S> {
    fn verify(&self, id: Hash32, values: &[u8], marker: &[u8]) -> Result<(), ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
        self.simplicity.verify(id, values, marker)?;
        self.record("simplicity", id, values, marker);
        Ok(())
    }
}

    pub(crate) fn qualify_accounting<S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
        input: &CustodyExecutionInputV7, output: &CustodyExecutionOutputV7,
        domain: &crate::custody_redemption_statement_v2::RedemptionDomainV2, simplicity: &S,
    ) {
        use crate::custody_child_lineage_v2::*;
        use crate::custody_execution_v2::*;
        use crate::custody_execution_wire_v2::*;
        let extracted = crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v7(
            domain,crate::custody_burn_v2::tests::fixture_verifier_address(),domain.custody_id,output,1,0).unwrap();
        assert_eq!(extracted.checkpoint(), output.checkpoint().commitment().unwrap());
        assert_ne!(extracted.checkpoint(), output.checkpoint().projection.commitment().unwrap());
        let inner = &input.anchor.execution;
        let roots = &inner.binding.roots;
        let lineage = CustodyAccountingLineagePolicyV4 {
            genesis_initialization: inner.binding.genesis_initialization,
            roots: CustodyChildLineagePolicyV5 {
                execution: CustodyChildLineagePolicyV2 {
                    execution_program:[42;32], initial_checkpoint:input.anchor.checkpoint.commitment().unwrap(),
                    initial_height:input.anchor.checkpoint.projection.execution.height,
                    parent_binding:roots.execution.parent_binding, execution_policy:roots.execution.execution_policy,
                    simplicity_program:roots.execution.simplicity_evaluator_program_id,
                    deposit_configuration:roots.execution.deposit_configuration,
                }, evaluator_source_closure:roots.evaluator_source_closure,
                genesis_bindings:roots.genesis_bindings, successor:roots.successor,
            },
        };
        assert_eq!(custody_accounting_binding_v7(&lineage,input.anchor.checkpoint.commitment().unwrap(),
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
        verify_custody_accounting_lineage_v7(&lineage,&[receipt.clone()],terminal,height,&exact).unwrap();
        assert_eq!(exact.calls.get(),1);
        for field in 0..4 {
            let mut bad = receipt.clone();
            match field {
                0 => bad.projection_predecessor[0] ^= 1,
                1 => bad.environment[0] ^= 1,
                2 => bad.receipt.public_values[0] = crate::child_custody_guest_v4::CUSTODY_EXECUTION_VERSION_V4,
                _ => bad.receipt.proof_marker[0] ^= 1,
            }
            assert!(verify_custody_accounting_lineage_v7(&lineage,&[bad],terminal,height,&exact).is_err());
        }
        assert!(verify_custody_accounting_lineage_v7(&lineage,&[],terminal,height,&exact).is_err());
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
        let policy = CustodyAccountingExecutionPolicyV7 {roots:CustodyAccountingExecutionPolicyV4 {
            domain:domain.clone(),verifier_address:crate::custody_burn_v2::tests::fixture_verifier_address(),child_execution_binding:input.source_binding().unwrap(),
            lineage,observation_time:inner.observation_time,destination_state:confirmed.state(),
            destination_anchor:confirmed.anchor(),minimum_confirmations:1,
        }};
        assert_ne!(policy.commitment().unwrap(),policy.roots.commitment().unwrap());
        assert_ne!(policy.release_commitment().unwrap(),policy.roots.release_commitment().unwrap());
        let legacy = CustodyAccountingExecutionPolicyV6 { roots: policy.roots.clone() };
        assert_ne!(policy.commitment().unwrap(), legacy.commitment().unwrap());
        assert_ne!(policy.release_commitment().unwrap(), legacy.release_commitment().unwrap());
        let witness = CustodyAccountingWitnessV7 {
            version:CUSTODY_ACCOUNTING_WIRE_VERSION_V7,policy:policy.clone(),child:input.clone(),
            history:history.clone(),lineage_receipts:vec![],transaction_index:1,output_index:0,
        };
        let wire = encode_custody_accounting_v7(&witness).unwrap();
        let decoded = decode_custody_accounting_v7(&wire).unwrap();
        assert_eq!(encode_custody_accounting_v7(&decoded).unwrap(),wire);
        assert!(decode_custody_accounting_v4(&wire).is_err());
        assert!(decode_custody_accounting_v6(&wire).is_err());
        let mut relabelled = wire.clone(); relabelled[0] = CUSTODY_ACCOUNTING_WIRE_VERSION_V6;
        assert!(decode_custody_accounting_v6(&relabelled).is_err());
        let mut old_receipt = witness.clone();
        let mut receipt = receipt.clone();
        receipt.receipt.public_values[0] = crate::child_custody_guest_v6::CUSTODY_EXECUTION_VERSION_V6;
        old_receipt.lineage_receipts.push(receipt);
        assert!(encode_custody_accounting_v7(&old_receipt).is_err());
        let mut bad = wire.clone();bad.push(0);
        assert!(decode_custody_accounting_v7(&bad).is_err());
        bad = wire.clone();bad[0] = CUSTODY_ACCOUNTING_WIRE_VERSION_V4;
        assert!(decode_custody_accounting_v7(&bad).is_err());
        assert!(decode_custody_accounting_v7(&wire[..wire.len()-1]).is_err());
        let verifier = TranscriptVerifier::for_inputs([&inner.parent;4].into_iter()
            .chain(history.steps.iter()).chain(std::iter::once(&history.steps[approval_index]))).first_occurrences();
        let trace = ReceiptTrace { parent: &verifier, simplicity, calls: Default::default() };
        let composed = execute_custody_accounting_v7(&decoded.policy,&decoded.child,&decoded.history,
            &decoded.lineage_receipts,1,0,&trace,&trace).unwrap();
        verifier.assert_consumed();
        assert!(!trace.calls.borrow().is_empty());
        let uncached = TranscriptVerifier::for_inputs([&inner.parent;4].into_iter()
            .chain(history.steps.iter()).chain(std::iter::once(&history.steps[approval_index])));
        let original = execute_custody_accounting_v7_inner(&decoded.policy,&decoded.child,&decoded.history,
            &decoded.lineage_receipts,1,0,&uncached,simplicity).unwrap();
        uncached.assert_consumed();
        assert_eq!(composed.extended_bytes_v3(), original.extended_bytes_v3());
        // Current V7 accounting guest also accepts the six-ack path, with the
        // same executed burn and supply checks and without any mined M6.
        {
            use bitcoin::hashes::Hash;
            use crate::conversion_parent_link_v3::{CustodyAckBundleV3,custody_checkpoint_approval_commitment_v2};
            let bundle = CustodyAckBundleV3 {transaction_version:2,lock_time:0,fee_sat:1000,
                checkpoint_commitment:custody_checkpoint_approval_commitment_v2(domain.custody_id,extracted.checkpoint()).unwrap()};
            let mut early = decoded.clone();
            let index = early.history.steps.iter().position(|step|
                step.parent.terminal_selected_state.bip300_state.as_state().active_slots[&24]
                    .pending_m6ids.iter().any(|p| p.m6id == bundle.compute_txid() && p.score == 7)).unwrap();
            early.history.steps.truncate(index+1);
            early.history.approval_index = index as u32;
            early.history.approval_transaction = bundle.compute_txid();
            early.history.approval_bundle = Some(bundle);
            let tip = &early.history.steps[index].parent.terminal_selected_state;
            early.policy.roots.destination_state = tip.commitment().unwrap();
            early.policy.roots.destination_anchor = tip.tip.block_hash.to_byte_array();
            let early = decode_custody_accounting_v7(&encode_custody_accounting_v7(&early).unwrap()).unwrap();
            let verifier = TranscriptVerifier::for_inputs([&inner.parent;4].into_iter()
                .chain(early.history.steps.iter()).chain(std::iter::once(&early.history.steps[index]))).first_occurrences();
            let result = execute_custody_accounting_v7(&early.policy,&early.child,&early.history,
                &early.lineage_receipts,1,0,&verifier,simplicity).unwrap();
            verifier.assert_consumed();
            assert_eq!(&result.extended_bytes_v3()[..32],&early.policy.release_commitment().unwrap());
            assert_ne!(result.extended_bytes_v3(),composed.extended_bytes_v3());
        }
        // Earlier steps populate the receipt cache, but altered terminal block
        // context must still fail even when its receipt bytes are unchanged.
        let mut altered_history = decoded.history.clone();
        altered_history.steps.last_mut().unwrap().terminal_parent_block[0] ^= 1;
        let context_verifier = TranscriptVerifier::for_inputs([&inner.parent;4].into_iter()
            .chain(history.steps.iter()).chain(std::iter::once(&history.steps[approval_index]))).first_occurrences();
        assert!(execute_custody_accounting_v7(&decoded.policy,&decoded.child,&altered_history,
            &decoded.lineage_receipts,1,0,&context_verifier,simplicity).is_err());
        if std::env::var_os("USDD_EXPORT_RECEIPT_REQUIREMENTS").is_some() {
            println!("USDD_ACCOUNTING_V7_RECEIPT_REQUIREMENTS={}", serde_json::json!({
                "qualification":"synthetic fixture requirements; not cryptographic proof evidence",
                "lineage_receipts":decoded.lineage_receipts.len(),
                "calls":*trace.calls.borrow()
            }));
        }
        let verifier = TranscriptVerifier::for_inputs(history.steps.iter()
            .chain(std::iter::once(&history.steps[approval_index])));
        let (cursor,confirmed) = extracted.finish_history(&history.steps,approval_index,approval_transaction,&verifier).unwrap();
        verifier.assert_consumed();
        let statement = cursor.checked_statement(domain,crate::custody_burn_v2::tests::fixture_verifier_address(),&confirmed,policy.roots.destination_state,
            policy.roots.destination_anchor,1).unwrap();
        assert_eq!(&composed.canonical_bytes()[32..],&statement);
        assert_eq!(&composed.extended_bytes_v3()[..32],&policy.release_commitment().unwrap());
        // SP1AlphaRedemptionProofVerifierV3 requires observation == the
        // authenticated destination MTP, not the earlier child observation.
        let public = composed.extended_bytes_v3();
        let destination_mtp = u32::from_be_bytes(public[100..104].try_into().unwrap());
        let observation = u64::from_be_bytes(public[136..144].try_into().unwrap());
        assert_eq!(observation, u64::from(destination_mtp));
        if std::env::var_os("USDD_EXPORT_ACCOUNTING_JOURNAL").is_some() {
            println!("USDD_ACCOUNTING_V7_JOURNAL={}", public.iter()
                .map(|byte| format!("{byte:02x}")).collect::<String>());
            // Export the executed burn and checked history, not a replacement
            // synthetic claim. The deployment join must bind this domain before
            // transaction construction; consumers must never relabel it later.
            use bitcoin::hashes::Hash;
            let burn = cursor.burn();
            let mut m6 = confirmed.approval().approval().m6id.to_byte_array();
            m6.reverse();
            let hex = |bytes: &[u8]| bytes.iter()
                .map(|byte| format!("{byte:02x}")).collect::<String>();
            println!("USDD_ACCOUNTING_V7_CLAIM={}", serde_json::json!({
                "qualification": "native fixture; synthetic recursive receipts",
                "domain": domain,
                "verifier_address": crate::custody_burn_v2::tests::fixture_verifier_address().to_vec(),
                "burn_txid": hex(&burn.txid_display),
                "burn_vout": burn.vout,
                "burn_id": hex(&burn.burn_id),
                "amount_micro": burn.amount_micro,
                "recipient": hex(&burn.recipient),
                "approved_m6_id": hex(&m6),
                "elements_checkpoint": hex(&cursor.checkpoint()),
                "parent_checkpoint": hex(&confirmed.state()),
                "statement": hex(&statement),
                "journal": hex(&public)
            }));
        }
    }
