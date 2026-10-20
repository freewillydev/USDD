//! ECX deposits and withdrawals against the native Alpha pre-spend UTXO tree. The caller must
//! authenticate this root from consensus and separately validate transaction
//! spending, script execution and maturity. Membership is not spend authority.
use ecx_full_consensus_validator_v2::elements_v2::{
    elements_sparse_utxo_root_from_path_v2, elements_utxo_leaf_node_v2,
    ElementsSparseUtxoNodeV2, ElementsSparseUtxoPathV2, ElementsUtxoLeafV2,
};
use ecx_proof_core::{ecx_execution_v1::EcxTradingVaultWitnessV1, proof_v2::ProofErrorV2};
use ecx_protocol_core::{ecx_cash_account_v1::{EcxAccountOpeningV1, EcxCashAccountV1},
    ecx_configuration_v1::EcxConfigurationV1, hash::Hash32,
    ecx_withdrawal_v1::{SignedEcxWithdrawalV1, EcxWithdrawalAccountUpdateV1}, Price};

#[derive(Clone, Copy)]
pub struct EcxCoinMembershipV1<'a> {
    pub leaf: &'a ElementsUtxoLeafV2,
    pub path: &'a ElementsSparseUtxoPathV2,
}

/// Consume an ECX match receipt against an actually executed vault spend.
/// The enclosing transition must authenticate `expected_state`, `prior` and
/// `expected_outpoint`; witness-selected pins are not predecessor authority.
/// This preserves the match's local oracle context, and establishes neither
/// context advancement nor finality. The returned outpoint is derived from
/// the executed transaction, never embedded in its own proving input.
/// Later transactions may spend that output: this is an inclusion projection,
/// not an assertion that it remains unspent at the block tip. An outer consumer
/// must also enforce the selected covenant and authenticate its state pins.
pub fn verify_executed_ecx_match_v1<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
    executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
    transaction_index: usize,
    expected_state: Hash32,
    prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    economics: EcxConfigurationV1,
    journal_bytes: &[u8], proof: &[u8], verifier: &V,
    vault: &EcxTradingVaultWitnessV1<'_>, membership: EcxCoinMembershipV1<'_>,
) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
    elements::OutPoint), ProofErrorV2> {
    let child = executed.child();
    let invalid = || ProofErrorV2::BindingMismatch("ECX match executed vault");
    if child.next_checkpoint().is_none()
        || vault.source_outpoint != expected_outpoint
        || child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction)
    { return Err(invalid()); }
    let root = child.transaction_pre_utxo_root(transaction_index).ok_or_else(invalid)?;
    check_coin(root, membership, expected_outpoint, vault.source_transaction)?;
    let journal = ecx_proof_core::ecx_match_input_v1::EcxMatchJournalV1::verify_receipt(
        journal_bytes, proof, verifier, expected_state, prior, expected_outpoint, bindings)?;
    if vault.source_script_sha256 != prior.vault_script_sha256
        || vault.successor_script_sha256 != journal.next_state.vault_script_sha256
    { return Err(invalid()); }
    let (before, after) = ecx_proof_core::ecx_execution_v1::ecx_trading_vault_outputs_v1(
        expected_outpoint, vault.source_transaction, vault.successor_transaction,
        vault.successor_vout)?;
    prior.verify_vault(expected_state, bindings, economics, vault.prior_accounts, before)?;
    journal.next_state.verify_vault(journal.next_state.digest()?, bindings, economics,
        vault.successor_accounts, after)?;
    let outpoint = elements::OutPoint {
        txid: vault.successor_transaction.txid(), vout: vault.successor_vout,
    };
    Ok((journal.next_state, outpoint))
}

/// Verify against the exact transaction and pre-spend root retained by the
/// checkpoint-relative parent/child executor. There is no caller-selected
/// UTXO root. This inherits the executor's configured verifier/trust roots;
/// it is not a cryptographic receipt or a finality check. The enclosing ECX
/// transition must still authenticate the prior account root and script policy.
pub fn verify_executed_ecx_top_up_v1(
    executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
    transaction_index: usize,
    prior_accounts_root: Hash32, recipient: Hash32, economics: EcxConfigurationV1,
    account: EcxAccountOpeningV1<'_>, vault: &EcxTradingVaultWitnessV1<'_>,
    vault_membership: EcxCoinMembershipV1<'_>,
    deposit_outpoint: elements::OutPoint, deposit_transaction: &elements::Transaction,
    deposit_membership: EcxCoinMembershipV1<'_>, atoms: u64,
) -> Result<(Hash32, EcxCashAccountV1), ProofErrorV2> {
    let child = executed.child();
    let error = || ProofErrorV2::BindingMismatch("ECX deposit executed transaction");
    if child.next_checkpoint().is_none()
        || child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction)
    { return Err(error()); }
    let root = child.transaction_pre_utxo_root(transaction_index).ok_or_else(error)?;
    verify_ecx_top_up_with_membership_v1(root, prior_accounts_root, recipient, economics,
        account, vault, vault_membership, deposit_outpoint, deposit_transaction,
        deposit_membership, atoms)
}

/// Join withdrawal accounting to the executed transaction, its pre-spend coin
/// tree and its checked child height. Prior account/script policy and oracle
/// price/funding inputs must still be authenticated by the enclosing transition.
/// This inherits the executor's verifier/trust assumptions, not finality.
pub fn verify_executed_ecx_withdrawal_v1(
    executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
    transaction_index: usize,
    prior_accounts_root: Hash32, economics: EcxConfigurationV1,
    signed: &SignedEcxWithdrawalV1, account: EcxAccountOpeningV1<'_>,
    low: Price, high: Price, funding: i128,
    vault: &EcxTradingVaultWitnessV1<'_>, membership: EcxCoinMembershipV1<'_>,
    recipient_vout: u32,
    orders: ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1<'_>,
) -> Result<EcxWithdrawalAccountUpdateV1, ProofErrorV2> {
    let child = executed.child();
    let error = || ProofErrorV2::BindingMismatch("ECX withdrawal executed transaction");
    let checkpoint = child.next_checkpoint().ok_or_else(error)?;
    if child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction) {
        return Err(error());
    }
    let root = child.transaction_pre_utxo_root(transaction_index).ok_or_else(error)?;
    verify_ecx_withdrawal_with_membership_v1(root, prior_accounts_root, economics,
        signed, account, u64::from(checkpoint.height), low, high, funding,
        vault, membership, recipient_vout, orders)
}

/// Membership alone is not spend authority. The caller must authenticate the
/// root and execution height and validate scripts, maturity and context.
pub fn verify_ecx_withdrawal_with_membership_v1(
    expected_utxo_root: ElementsSparseUtxoNodeV2,
    prior_accounts_root: Hash32, economics: EcxConfigurationV1,
    signed: &SignedEcxWithdrawalV1, account: EcxAccountOpeningV1<'_>,
    height: u64, low: Price, high: Price, funding: i128,
    vault: &EcxTradingVaultWitnessV1<'_>, membership: EcxCoinMembershipV1<'_>,
    recipient_vout: u32,
    orders: ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1<'_>,
) -> Result<EcxWithdrawalAccountUpdateV1, ProofErrorV2> {
    check_coin(expected_utxo_root, membership, vault.source_outpoint, vault.source_transaction)?;
    ecx_proof_core::ecx_execution_v1::verify_ecx_account_withdrawal_v1(
        prior_accounts_root, economics, signed, account, height, low, high,
        funding, vault, recipient_vout, orders)
}

pub(crate) fn check_coin(root: ElementsSparseUtxoNodeV2, proof: EcxCoinMembershipV1<'_>,
    outpoint: elements::OutPoint, transaction: &elements::Transaction,
) -> Result<(), ProofErrorV2> {
    let error = || ProofErrorV2::BindingMismatch("ECX source UTXO membership");
    if root.hash == [0; 32] || root.aggregate.count == 0
        || outpoint.is_null() || transaction.txid() != outpoint.txid
        || proof.leaf.outpoint != outpoint
        || transaction.output.get(outpoint.vout as usize) != Some(&proof.leaf.output)
    { return Err(error()); }
    let actual = elements_sparse_utxo_root_from_path_v2(outpoint,
        elements_utxo_leaf_node_v2(proof.leaf), proof.path).map_err(|_| error())?;
    if actual != root { return Err(error()); }
    Ok(())
}

/// Both coins must coexist at the same authenticated pre-spend root. The
/// lower relation enforces distinct coins, exact marker, consumption, credit
/// and before/after ledger backing. No witness-selected successor root is used.
pub fn verify_ecx_top_up_with_membership_v1(
    expected_utxo_root: ElementsSparseUtxoNodeV2,
    prior_accounts_root: Hash32, recipient: Hash32, economics: EcxConfigurationV1,
    account: EcxAccountOpeningV1<'_>, vault: &EcxTradingVaultWitnessV1<'_>,
    vault_membership: EcxCoinMembershipV1<'_>,
    deposit_outpoint: elements::OutPoint, deposit_transaction: &elements::Transaction,
    deposit_membership: EcxCoinMembershipV1<'_>, atoms: u64,
) -> Result<(Hash32, EcxCashAccountV1), ProofErrorV2> {
    check_coin(expected_utxo_root, vault_membership, vault.source_outpoint,
        vault.source_transaction)?;
    check_coin(expected_utxo_root, deposit_membership, deposit_outpoint, deposit_transaction)?;
    ecx_proof_core::ecx_execution_v1::verify_ecx_account_top_up_v1(
        prior_accounts_root, recipient, economics, account, vault,
        deposit_outpoint, deposit_transaction, atoms)
}

#[cfg(test)]
#[path = "../../proof-core/tests/support/oracle_context.rs"]
mod oracle_context;
#[cfg(test)]
#[path = "../../proof-core/tests/support/ecx_oracle_match.rs"]
mod oracle_lifecycle;
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use elements::hashes::Hash;
    use ecx_full_consensus_validator_v2::elements_v2::{
        canonical_empty_elements_utxo_leaf_v2, elements_sparse_utxo_parent_v2,
    };
    #[test]
    fn two_coin_deposit_composes_membership_credit_and_backing() {
        exercise(None);
    }

    pub(crate) struct NativeMatchInput {
        pub execution: crate::child_execution_guest_v3::AlphaChildExecutionInputV3,
        pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
        pub checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
        pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
        pub environment: crate::ecx_environment_v4::EcxExecutionEnvironmentV1,
    }
    pub(crate) struct NativeMatchResume {
        pub checkpoint: crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2,
        pub history: Vec<Vec<u8>>,
        pub coin: ElementsUtxoLeafV2,
    }
    type NativeBuilder<'a> = &'a dyn Fn(&elements::Transaction, &elements::Transaction,
        &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1, Option<&NativeMatchResume>,
        Option<&dyn Fn(&ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1)
            -> ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1>)
        -> (crate::native_child_block_v3::ParentBoundCheckedChildState,
            crate::ecx_environment_v4::CheckedAlphaExecutionContextV4,
            crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1, NativeMatchInput);

    pub(crate) fn exercise_native_match(builder: NativeBuilder<'_>) {
        exercise(Some(builder));
        exercise_owned_withdrawal(builder);
        exercise_owned_admission(builder);
        exercise_native_liquidation(builder);
    }

    fn exercise_native_liquidation(build: NativeBuilder<'_>) {
        use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
        use ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1;
        use ecx_truthcoin_proof::ParentChainContextV1;
        use super::oracle_context::{seed, context_with_anchor, TestDigestVerifier};
        let (configuration, truthcoin, ecx_btc, usdd_usd) = seed();
        let seed_parent = ParentChainContextV1 {
            block_hash: truthcoin.public_values.observed_parent_block_hash,
            height: truthcoin.public_values.observed_parent_height,
            median_time_past: truthcoin.public_values.observed_parent_mtp,
        };
        let predecessor = |state: &EcxSuccessorStateV1| {
            let mut state = state.clone();
            state.sidechain_height = 16;
            state.parent_hash = [19;32]; state.parent_height = 1; state.parent_mtp = 1;
            state
        };
        let mut discovered = None;
        super::oracle_lifecycle::exercise_with_liquidation(&configuration, seed_parent,
            &truthcoin, &ecx_btc, &usdd_usd, &TestDigestVerifier, &mut |input| {
                let prior = predecessor(input.prior);
                let identity = |state: &EcxSuccessorStateV1| state.clone();
                let (_, context, _, _) = build(input.vault.source_transaction,
                    input.vault.successor_transaction, &prior, None, Some(&identity));
                let prepared = context.prepare_ecx_match_state(&prior, input.bindings).unwrap();
                discovered = Some(ParentChainContextV1 { block_hash: prepared.parent_hash,
                    height: prepared.parent_height, median_time_past: prepared.parent_mtp });
            });
        let parent = discovered.unwrap();
        let oracle = context_with_anchor(&configuration, &truthcoin, &ecx_btc, &usdd_usd,
            parent.block_hash, parent.height, parent.median_time_past, None);
        let mut count = 0;
        super::oracle_lifecycle::exercise_with_liquidation(&configuration, parent,
            &oracle.truthcoin, &oracle.ecx_btc, &oracle.usdd_usd, &TestDigestVerifier,
            &mut |input| {
                let prior = predecessor(input.prior);
                let transition = |prepared: &EcxSuccessorStateV1| {
                    assert_eq!(prepared, input.prior);
                    input.next.clone()
                };
                let (executed, context, checkpoint, native) = build(input.vault.source_transaction,
                    input.vault.successor_transaction, &prior, None, Some(&transition));
                let witness = &native.execution.witnesses[1].utxo;
                let spent = witness.spends[0].old_leaf.as_ref().unwrap();
                let created = witness.creates[0].new_leaf.as_ref().unwrap();
                fn opening<'a>(a: &EcxAccountOpeningV1<'a>) -> EcxAccountOpeningV1<'a> {
                    EcxAccountOpeningV1 { position: a.position, cash: a.cash, siblings: a.siblings }
                }
                let attempt = |index, pin, state: &EcxSuccessorStateV1,
                    successor: &ElementsUtxoLeafV2| {
                    context.advance_ecx_liquidation_checkpoint(&executed, index, &checkpoint,
                        pin, state, input.bindings, input.economics, &configuration,
                        &oracle.truthcoin, &oracle.ecx_btc, &oracle.usdd_usd,
                        &TestDigestVerifier, input.funding, opening(&input.target), input.makers,
                        opening(&input.clearing), opening(&input.insurance), input.orders,
                        input.source_orders, input.fills, input.vault,
                        EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                        EcxCoinMembershipV1 { leaf: successor, path: &witness.creates[0].path })
                };
                let pin = checkpoint.commitment().unwrap();
                let result = attempt(1, pin, &prior, created).unwrap();
                let owned_attempt = |candidate: &ecx_proof_core::ecx_liquidation_input_v1::EcxLiquidationInputV1| {
                    context.advance_ecx_owned_liquidation(&executed, 1, &checkpoint, pin, &prior,
                        candidate, EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                        EcxCoinMembershipV1 { leaf: created, path: &witness.creates[0].path },
                        &TestDigestVerifier)
                };
                assert_eq!(owned_attempt(input.owned).unwrap(), result);
                let mut wrong_owned = input.owned.clone();
                wrong_owned.state_bytes = prior.encode().unwrap();
                assert!(owned_attempt(&wrong_owned).is_err());
                let mut wrong_owned = input.owned.clone();
                wrong_owned.expected_state = prior.digest().unwrap();
                assert!(owned_attempt(&wrong_owned).is_err());
                assert_eq!(&result.0, input.next);
                assert_eq!(result.2.exchange_state_root, input.next.digest().unwrap());
                assert_eq!(result.2.vault_outpoint, created.outpoint);
                assert_eq!(result.2.execution, executed.child().next_checkpoint().unwrap().clone());
                assert!(attempt(0, pin, &prior, created).is_err());
                assert!(attempt(2, pin, &prior, created).is_err());
                assert!(attempt(1, [0;32], &prior, created).is_err());
                let mut wrong = prior.clone(); wrong.accounts_root[0] ^= 1;
                assert!(attempt(1, pin, &wrong, created).is_err());
                let mut wrong = created.clone(); wrong.outpoint.vout += 1;
                assert!(attempt(1, pin, &prior, &wrong).is_err());
                use crate::ecx_match_execution_v1::{OwnedEcxNativeLiquidationV1,
                    OwnedEcxLiquidationContinuationV1, OwnedEcxContinuationActionV1,
                    EcxNativeMatchPublicValuesV1};
                use super::oracle_context::TestDigestVerifier;
                struct DenySimplicity;
                impl ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for DenySimplicity {
                    fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(),
                        ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                        Err(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::AuthorizationConsensus)
                    }
                }
                let full = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                    state: checkpoint.clone(), bmm_endpoint: native.checkpoint.bmm_endpoint.clone(),
                };
                let pin = full.commitment().unwrap();
                let binding_pin = native.binding.commitment().unwrap();
                let input = OwnedEcxNativeLiquidationV1 {
                    execution: native.execution.clone(), binding: native.binding.clone(),
                    native_checkpoint: native.checkpoint.clone(), deposit_policy: native.deposit_policy.clone(),
                    environment: native.environment.encode().unwrap(), native_binding_pin: binding_pin,
                    checkpoint_pin: pin, checkpoint: full, transaction_index: 1,
                    state_bytes: prior.encode().unwrap(), liquidation: input.owned.clone(),
                    coin: spent.clone(), path: witness.spends[0].path.clone(),
                    successor_coin: created.clone(), successor_path: witness.creates[0].path.clone(),
                };
                let parent = &native.execution.parent;
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let outer = input.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(outer.public_values().state, result.0);
                assert_eq!(outer.checkpoint().state, result.2);
                let source_public = EcxNativeMatchPublicValuesV1 {
                    native_binding: binding_pin, predecessor_checkpoint: pin,
                    successor_checkpoint: pin, state: prior.clone(),
                };
                let program = [15;32];
                let journal = source_public.canonical_bytes().unwrap().to_vec();
                let mut transcript = program.to_vec(); transcript.extend_from_slice(&journal);
                let envelope = OwnedEcxLiquidationContinuationV1 {
                    input, continuation_program: [16;32], recursive: false,
                    initialization_binding: native.binding.clone(),
                    initialization_parent: native.execution.parent.binding,
                    initialization_environment: native.environment.encode().unwrap(),
                    predecessor_program: program, predecessor_binding: binding_pin,
                    predecessor_checkpoint: pin, predecessor_journal: journal,
                    predecessor_proof: <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec(),
                };
                let bytes = envelope.encode().unwrap();
                assert_eq!(OwnedEcxLiquidationContinuationV1::decode(&bytes).unwrap().encode().unwrap(), bytes);
                let action = OwnedEcxContinuationActionV1::decode(&bytes).unwrap();
                assert!(matches!(&action, OwnedEcxContinuationActionV1::Liquidation(_)));
                assert_eq!(action.continuation_program(), envelope.continuation_program);
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let joined = action.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(joined.len(), 546);
                assert_eq!(&joined[..6], b"ECXNC2");
                assert_eq!(&joined[134..], outer.journal());
                assert_eq!(&joined[102..134], &envelope.continuation_program);
                for length in [0, 5, bytes.len()-1] {
                    assert!(OwnedEcxContinuationActionV1::decode(&bytes[..length]).is_err());
                }
                let mut extra = bytes.clone(); extra.push(0);
                assert!(OwnedEcxContinuationActionV1::decode(&extra).is_err());
                for mutation in 0..6 {
                    let mut bad = envelope.clone();
                    match mutation {
                        0 => bad.predecessor_proof[0] ^= 1,
                        1 => bad.continuation_program = program,
                        2 => bad.input.state_bytes[0] ^= 1,
                        3 => bad.input.checkpoint_pin[0] ^= 1,
                        4 => bad.input.transaction_index = 0,
                        _ => bad.input.liquidation.expected_state[0] ^= 1,
                    }
                    let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                    assert!(bad.execute(&verifier, &DenySimplicity, &TestDigestVerifier).is_err(), "mutation {mutation}");
                }
                count += 1;
            });
        assert_eq!(count, 2);
    }

    fn exercise_owned_admission(build: NativeBuilder<'_>) {
        use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
        use ecx_truthcoin_proof::ParentChainContextV1;
        use super::oracle_context::{seed, context_with_anchor, TestDigestVerifier};
        let (configuration, truthcoin, ecx_btc, usdd_usd) = seed();
        let seed_parent = ParentChainContextV1 {
            block_hash: truthcoin.public_values.observed_parent_block_hash,
            height: truthcoin.public_values.observed_parent_height,
            median_time_past: truthcoin.public_values.observed_parent_mtp,
        };
        let mut samples = Vec::new();
        super::oracle_lifecycle::exercise_with_admission(&configuration, seed_parent,
            &truthcoin, &ecx_btc, &usdd_usd, &TestDigestVerifier,
            &mut |input| samples.push(input.clone()));
        let sample = &samples[0];
        let source = elements::encode::deserialize(&sample.source_transaction_bytes).unwrap();
        let transaction = elements::encode::deserialize(&sample.successor_transaction_bytes).unwrap();
        let predecessor = |bytes: &[u8]| {
            let mut state = EcxSuccessorStateV1::decode(bytes).unwrap();
            state.sidechain_height = 16;
            state.parent_hash = [19;32]; state.parent_height = 1; state.parent_mtp = 1;
            state
        };
        let prior = predecessor(&sample.state_bytes);
        // Discover P's authenticated clock before generating signed inputs.
        // This probe does not verify an admission or promote synthetic receipts.
        let identity = |state: &EcxSuccessorStateV1| state.clone();
        let (_, context, _, _) = build(&source, &transaction, &prior, None, Some(&identity));
        let prepared = context.prepare_ecx_match_state(&prior, sample.bindings).unwrap();
        let parent = ParentChainContextV1 { block_hash: prepared.parent_hash,
            height: prepared.parent_height, median_time_past: prepared.parent_mtp };
        let oracle = context_with_anchor(&configuration, &truthcoin, &ecx_btc, &usdd_usd,
            parent.block_hash, parent.height, parent.median_time_past, None);
        let mut count = 0;
        super::oracle_lifecycle::exercise_with_admission(&configuration, parent,
            &oracle.truthcoin, &oracle.ecx_btc, &oracle.usdd_usd, &TestDigestVerifier,
            &mut |input| {
                let source = elements::encode::deserialize(&input.source_transaction_bytes).unwrap();
                let transaction = elements::encode::deserialize(&input.successor_transaction_bytes).unwrap();
                let prior = predecessor(&input.state_bytes);
                let transition = |prepared: &EcxSuccessorStateV1| {
                    assert_eq!(prepared.encode().unwrap(), input.state_bytes);
                    input.execute(&TestDigestVerifier).unwrap().0
                };
                let (executed, context, checkpoint, native) = build(&source, &transaction,
                    &prior, None, Some(&transition));
                let witness = &native.execution.witnesses[1].utxo;
                let spent = witness.spends[0].old_leaf.as_ref().unwrap();
                let vault = witness.creates[0].new_leaf.as_ref().unwrap();
                let attempt = |index, pin, candidate: &ecx_proof_core::ecx_admission_input_v1::EcxAdmissionInputV1| {
                    context.advance_ecx_owned_admission(&executed, index, &checkpoint,
                        pin, &prior, candidate,
                        EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                        EcxCoinMembershipV1 { leaf: vault, path: &witness.creates[0].path },
                        &TestDigestVerifier)
                };
                let pin = checkpoint.commitment().unwrap();
                let result = attempt(1, pin, input).unwrap();
                assert_eq!((result.0.clone(), result.1), input.execute(&TestDigestVerifier).unwrap());
                assert_eq!(result.2.exchange_state_root, result.0.digest().unwrap());
                assert_eq!(result.2.vault_outpoint, vault.outpoint);
                assert_eq!(result.2.execution, executed.child().next_checkpoint().unwrap().clone());
                assert!(attempt(0, pin, input).is_err());
                assert!(attempt(2, pin, input).is_err());
                assert!(attempt(1, [0;32], input).is_err());
                for mutation in 0..5 {
                    let mut wrong = input.clone();
                    match mutation {
                        0 => wrong.expected_state[0] ^= 1,
                        1 => wrong.successor_vout = 1,
                        2 => wrong.truthcoin.public_values.observed_parent_block_hash[0] ^= 1,
                        3 => wrong.receipt.signature.0[0] ^= 1,
                        _ => wrong.orders.clear(),
                    }
                    assert!(attempt(1, pin, &wrong).is_err(), "native admission mutation {mutation}");
                }
                use crate::ecx_match_execution_v1::{OwnedEcxNativeAdmissionV1,
                    OwnedEcxAdmissionContinuationV1, OwnedEcxContinuationActionV1,
                    EcxNativeMatchPublicValuesV1};
                use super::oracle_context::TestDigestVerifier;
                struct DenySimplicity;
                impl ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for DenySimplicity {
                    fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(),
                        ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                        Err(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::AuthorizationConsensus)
                    }
                }
                let full = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                    state: checkpoint.clone(), bmm_endpoint: native.checkpoint.bmm_endpoint.clone(),
                };
                let pin = full.commitment().unwrap();
                let binding_pin = native.binding.commitment().unwrap();
                let input = OwnedEcxNativeAdmissionV1 {
                    execution: native.execution.clone(), binding: native.binding.clone(),
                    native_checkpoint: native.checkpoint.clone(), deposit_policy: native.deposit_policy.clone(),
                    environment: native.environment.encode().unwrap(), native_binding_pin: binding_pin,
                    checkpoint_pin: pin, checkpoint: full, transaction_index: 1,
                    state_bytes: prior.encode().unwrap(), admission: input.clone(),
                    coin: spent.clone(), path: witness.spends[0].path.clone(),
                    successor_coin: vault.clone(), successor_path: witness.creates[0].path.clone(),
                };
                let parent = &native.execution.parent;
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let outer = input.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(outer.public_values().state, result.0);
                assert_eq!(outer.checkpoint().state, result.2);
                let source_public = EcxNativeMatchPublicValuesV1 {
                    native_binding: binding_pin, predecessor_checkpoint: pin,
                    successor_checkpoint: pin, state: prior.clone(),
                };
                let program = [15;32];
                let journal = source_public.canonical_bytes().unwrap().to_vec();
                let mut transcript = program.to_vec(); transcript.extend_from_slice(&journal);
                let envelope = OwnedEcxAdmissionContinuationV1 {
                    input, continuation_program: [16;32], recursive: false,
                    initialization_binding: native.binding.clone(),
                    initialization_parent: native.execution.parent.binding,
                    initialization_environment: native.environment.encode().unwrap(),
                    predecessor_program: program, predecessor_binding: binding_pin,
                    predecessor_checkpoint: pin, predecessor_journal: journal,
                    predecessor_proof: <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec(),
                };
                let bytes = envelope.encode().unwrap();
                assert_eq!(OwnedEcxAdmissionContinuationV1::decode(&bytes).unwrap().encode().unwrap(), bytes);
                let action = OwnedEcxContinuationActionV1::decode(&bytes).unwrap();
                assert!(matches!(&action, OwnedEcxContinuationActionV1::Admission(_)));
                assert_eq!(action.continuation_program(), envelope.continuation_program);
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let joined = action.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(joined.len(), 546);
                assert_eq!(&joined[..6], b"ECXNC2");
                assert_eq!(&joined[134..], outer.journal());
                assert_eq!(&joined[102..134], &envelope.continuation_program);
                for length in [0, 5, bytes.len()-1] {
                    assert!(OwnedEcxContinuationActionV1::decode(&bytes[..length]).is_err());
                }
                let mut extra = bytes.clone(); extra.push(0);
                assert!(OwnedEcxContinuationActionV1::decode(&extra).is_err());
                for mutation in 0..6 {
                    let mut bad = envelope.clone();
                    match mutation {
                        0 => bad.predecessor_proof[0] ^= 1,
                        1 => bad.continuation_program = program,
                        2 => bad.input.state_bytes[0] ^= 1,
                        3 => bad.input.checkpoint_pin[0] ^= 1,
                        4 => bad.input.transaction_index = 0,
                        _ => bad.input.admission.receipt.signature.0[0] ^= 1,
                    }
                    let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                    assert!(bad.execute(&verifier, &DenySimplicity, &TestDigestVerifier).is_err(), "mutation {mutation}");
                }
                count += 1;
            });
        assert_eq!(count, 2);
    }

    fn exercise_owned_withdrawal(build: NativeBuilder<'_>) {
        use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
        use ecx_truthcoin_proof::ParentChainContextV1;
        use super::oracle_context::{seed, context_with_anchor, TestDigestVerifier};
        let (configuration, truthcoin, ecx_btc, usdd_usd) = seed();
        let seed_parent = ParentChainContextV1 {
            block_hash: truthcoin.public_values.observed_parent_block_hash,
            height: truthcoin.public_values.observed_parent_height,
            median_time_past: truthcoin.public_values.observed_parent_mtp,
        };
        let mut samples = Vec::new();
        super::oracle_lifecycle::exercise_with_withdrawal(&configuration, seed_parent,
            &truthcoin, &ecx_btc, &usdd_usd, &TestDigestVerifier, 17,
            &mut |input| samples.push(input.clone()));
        let sample = &samples[0];
        let source = elements::encode::deserialize(&sample.source_transaction_bytes).unwrap();
        let transaction = elements::encode::deserialize(&sample.successor_transaction_bytes).unwrap();
        let mut prior = EcxSuccessorStateV1::decode(&sample.state_bytes).unwrap();
        prior.sidechain_height = 16;
        prior.parent_hash = [19;32]; prior.parent_height = 1; prior.parent_mtp = 1;
        // Probe only the native fixture's authenticated predecessor clock.
        // This probe makes no claim that its exchange transition was verified.
        let identity = |prepared: &EcxSuccessorStateV1| prepared.clone();
        let (_, context, _, _) = build(&source, &transaction, &prior, None, Some(&identity));
        let prepared = context.prepare_ecx_match_state(&prior, sample.bindings).unwrap();
        let parent = ParentChainContextV1 { block_hash: prepared.parent_hash,
            height: prepared.parent_height, median_time_past: prepared.parent_mtp };
        let oracle = context_with_anchor(&configuration, &truthcoin, &ecx_btc, &usdd_usd,
            parent.block_hash, parent.height, parent.median_time_past, None);
        let mut checked_count = 0;
        super::oracle_lifecycle::exercise_with_withdrawal(&configuration, parent,
            &oracle.truthcoin, &oracle.ecx_btc, &oracle.usdd_usd, &TestDigestVerifier, 17,
            &mut |input| {
                let source = elements::encode::deserialize(&input.source_transaction_bytes).unwrap();
                let transaction = elements::encode::deserialize(&input.successor_transaction_bytes).unwrap();
                let mut prior = EcxSuccessorStateV1::decode(&input.state_bytes).unwrap();
                prior.sidechain_height = 16;
                prior.parent_hash = [19;32]; prior.parent_height = 1; prior.parent_mtp = 1;
                let transition = |prepared: &EcxSuccessorStateV1| {
                    assert_eq!(prepared.encode().unwrap(), input.state_bytes);
                    input.execute(&TestDigestVerifier).unwrap().0
                };
                let (executed, context, checkpoint, native) = build(&source, &transaction,
                    &prior, None, Some(&transition));
                let witness = &native.execution.witnesses[1].utxo;
                let spent = witness.spends[0].old_leaf.as_ref().unwrap();
                let vault = witness.creates[0].new_leaf.as_ref().unwrap();
                let recipient = witness.creates[1].new_leaf.as_ref().unwrap();
                let (_, path, _) = crate::capital_genesis_utxos_v4::tests::pair_paths(vault, recipient);
                let attempt = |index, pin, candidate: &ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1| {
                    context.advance_ecx_owned_withdrawal(&executed, index, &checkpoint,
                        pin, &prior, candidate,
                        EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                        EcxCoinMembershipV1 { leaf: vault, path: &path }, &TestDigestVerifier)
                };
                let pin = checkpoint.commitment().unwrap();
                let mut wrong_pin = pin;
                wrong_pin[0] ^= 1;
                assert!(attempt(1, wrong_pin, input).is_err());
                assert!(attempt(0, pin, input).is_err());
                let mut substituted = input.clone();
                substituted.expected_state[0] ^= 1;
                assert!(attempt(1, pin, &substituted).is_err());
                let mut substituted = input.clone();
                substituted.truthcoin.public_values.observed_parent_block_hash[0] ^= 1;
                assert!(attempt(1, pin, &substituted).is_err());
                let result = context.advance_ecx_owned_withdrawal(&executed, 1, &checkpoint,
                    checkpoint.commitment().unwrap(), &prior, input,
                    EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                    EcxCoinMembershipV1 { leaf: vault, path: &path }, &TestDigestVerifier).unwrap();
                let expected = input.execute(&TestDigestVerifier).unwrap();
                assert_eq!((result.0, result.1), expected);
                assert_eq!(result.2.vault_outpoint, vault.outpoint);
                struct DenySimplicity;
                impl ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for DenySimplicity {
                    fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(),
                        ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                        Err(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::AuthorizationConsensus)
                    }
                }
                let continuity = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                    state: checkpoint.clone(), bmm_endpoint: native.checkpoint.bmm_endpoint.clone(),
                };
                let binding_pin = native.binding.commitment().unwrap();
                let full_pin = continuity.commitment().unwrap();
                let execute_outer = |binding_pin, full_pin, continuity: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2| {
                    let parent = &native.execution.parent;
                    let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                        [parent, parent, parent]);
                    let result = crate::ecx_match_execution_v1::execute_alpha_ecx_withdrawal_v1(
                        &native.execution, &native.binding, &native.checkpoint, &native.deposit_policy,
                        &native.environment, binding_pin, full_pin, continuity, &prior, 1, input,
                        EcxCoinMembershipV1 { leaf: spent, path: &witness.spends[0].path },
                        EcxCoinMembershipV1 { leaf: vault, path: &path },
                        &verifier, &DenySimplicity, &TestDigestVerifier);
                    if result.is_ok() { verifier.assert_consumed(); }
                    result
                };
                let outer = execute_outer(binding_pin, full_pin, &continuity).unwrap();
                use crate::ecx_match_execution_v1::OwnedEcxNativeWithdrawalV1;
                let owned = OwnedEcxNativeWithdrawalV1 {
                    execution: native.execution.clone(), binding: native.binding.clone(),
                    native_checkpoint: native.checkpoint.clone(), deposit_policy: native.deposit_policy.clone(),
                    environment: native.environment.encode().unwrap(), native_binding_pin: binding_pin,
                    checkpoint_pin: full_pin, checkpoint: continuity.clone(), transaction_index: 1,
                    state_bytes: prior.encode().unwrap(), withdrawal: input.clone(),
                    coin: spent.clone(), path: witness.spends[0].path.clone(),
                    successor_coin: vault.clone(), successor_path: path.clone(),
                };
                let bytes = owned.encode().unwrap();
                let decoded = OwnedEcxNativeWithdrawalV1::decode(&bytes).unwrap();
                assert_eq!(decoded.encode().unwrap(), bytes);
                assert_eq!(decoded.coin, owned.coin);
                assert_eq!(decoded.successor_coin, owned.successor_coin);
                let parent = &native.execution.parent;
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                    [parent, parent, parent]);
                let transported = decoded.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(transported.journal(), outer.journal());
                assert_eq!(transported.checkpoint(), outer.checkpoint());
                // Open the actual native result as a following withdrawal's
                // predecessor. This tests receipt linkage, not a second spend.
                let mut following = decoded.clone();
                following.checkpoint = outer.checkpoint().clone();
                following.checkpoint_pin = outer.public_values().successor_checkpoint;
                following.native_checkpoint = following.checkpoint.native_projection(following.checkpoint_pin).unwrap();
                following.state_bytes = outer.public_values().state.encode().unwrap();
                let program = [15;32];
                let mut transcript = program.to_vec();
                transcript.extend_from_slice(outer.journal());
                let receipt = <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec();
                let link = |candidate: &OwnedEcxNativeWithdrawalV1, selected_program, selected_binding, selected_checkpoint, proof: &[u8]| {
                    candidate.verify_predecessor_receipt(outer.journal(), proof, &TestDigestVerifier,
                        selected_program, selected_binding, selected_checkpoint)
                };
                link(&following, program, binding_pin, full_pin, &receipt).unwrap();
                // A withdrawal now carries its own continuation envelope;
                // no unrelated match input is needed to authenticate it.
                use crate::ecx_match_execution_v1::OwnedEcxWithdrawalContinuationV1;
                let initial = OwnedEcxWithdrawalContinuationV1 {
                    input: following.clone(), continuation_program: [16;32], recursive: false,
                    initialization_binding: native.binding.clone(),
                    initialization_parent: native.execution.parent.binding,
                    initialization_environment: native.environment.encode().unwrap(),
                    predecessor_program: program, predecessor_binding: binding_pin,
                    predecessor_checkpoint: full_pin,
                    predecessor_journal: outer.journal().to_vec(), predecessor_proof: receipt.clone(),
                };
                let encoded = initial.encode().unwrap();
                let initial = OwnedEcxWithdrawalContinuationV1::decode(&encoded).unwrap();
                assert_eq!(initial.encode().unwrap(), encoded);
                initial.verify_predecessor(&TestDigestVerifier).unwrap();
                // Execute the real withdrawal under a synthetic receipt opening
                // of its actual source state. Digest receipts are test-only;
                // native inclusion and withdrawal execution are not mocked.
                let mut executable = initial.clone();
                executable.input = decoded.clone();
                let source_public = crate::ecx_match_execution_v1::EcxNativeMatchPublicValuesV1 {
                    native_binding: binding_pin, predecessor_checkpoint: full_pin,
                    successor_checkpoint: full_pin, state: prior.clone(),
                };
                executable.predecessor_journal = source_public.canonical_bytes().unwrap().to_vec();
                let mut transcript = program.to_vec();
                transcript.extend_from_slice(&executable.predecessor_journal);
                executable.predecessor_proof = <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec();
                let parent_verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                    [parent, parent, parent]);
                use crate::ecx_match_execution_v1::OwnedEcxContinuationActionV1;
                let action_bytes = executable.encode().unwrap();
                let action = OwnedEcxContinuationActionV1::decode(&action_bytes).unwrap();
                assert!(matches!(&action, OwnedEcxContinuationActionV1::Withdrawal(_)));
                assert_eq!(action.continuation_program(), executable.continuation_program);
                for prefix in [b"ECXCI2", b"ECXWI2", b"ECXNW1", b"XXXXXX"] {
                    let mut wrong = action_bytes.clone(); wrong[..6].copy_from_slice(prefix);
                    assert!(OwnedEcxContinuationActionV1::decode(&wrong).is_err());
                }
                let mut trailing_action = action_bytes.clone(); trailing_action.push(0);
                assert!(OwnedEcxContinuationActionV1::decode(&trailing_action).is_err());
                assert!(OwnedEcxContinuationActionV1::decode(&[]).is_err());
                let joined = action.execute(&parent_verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                parent_verifier.assert_consumed();
                assert_eq!(joined.len(), 546);
                assert_eq!(&joined[..6], b"ECXNC2");
                assert_eq!(&joined[134..], outer.journal());
                assert_eq!(&joined[102..134], &executable.continuation_program);
                // A valid predecessor opening alone cannot authorize reusing
                // the already-executed transaction against its successor state.
                let parent_verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                    [parent, parent, parent]);
                assert!(initial.execute(&parent_verifier, &DenySimplicity, &TestDigestVerifier).is_err());
                assert!(crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1::decode(&encoded).is_err());
                assert!(OwnedEcxNativeWithdrawalV1::decode(&encoded).is_err());
                let mut extra = encoded.clone(); extra.push(0);
                assert!(OwnedEcxWithdrawalContinuationV1::decode(&extra).is_err());
                for length in [0, 5, encoded.len()-1] {
                    assert!(OwnedEcxWithdrawalContinuationV1::decode(&encoded[..length]).is_err());
                }
                // Synthetic recursive receipt around the real native result:
                // this qualifies opening/role checks, not SP1 execution.
                let mut recursive = initial.clone();
                recursive.recursive = true;
                recursive.predecessor_journal = b"ECXNC2".to_vec();
                recursive.predecessor_journal.extend_from_slice(&program);
                recursive.predecessor_journal.extend_from_slice(&binding_pin);
                recursive.predecessor_journal.extend_from_slice(&full_pin);
                recursive.predecessor_journal.extend_from_slice(&recursive.continuation_program);
                recursive.predecessor_journal.extend_from_slice(outer.journal());
                let mut transcript = recursive.continuation_program.to_vec();
                transcript.extend_from_slice(&recursive.predecessor_journal);
                recursive.predecessor_proof = <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec();
                recursive.verify_predecessor(&TestDigestVerifier).unwrap();
                for valid in [&initial, &recursive] {
                    let mut bad = valid.clone(); bad.input.state_bytes[0] ^= 1;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.input.checkpoint_pin[0] ^= 1;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.input.native_checkpoint = decoded.native_checkpoint.clone();
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.predecessor_binding[0] ^= 1;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.initialization_environment[0] ^= 1;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.continuation_program = program;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.predecessor_proof[0] ^= 1;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                    let mut bad = valid.clone(); bad.recursive = !bad.recursive;
                    assert!(bad.verify_predecessor(&TestDigestVerifier).is_err());
                }
                assert!(link(&decoded, program, binding_pin, full_pin, &receipt).is_err());
                assert!(link(&following, [14;32], binding_pin, full_pin, &receipt).is_err());
                assert!(link(&following, program, [1;32], full_pin, &receipt).is_err());
                assert!(link(&following, program, binding_pin, [1;32], &receipt).is_err());
                assert!(link(&following, program, binding_pin, full_pin, b"wrong-proof").is_err());
                let mut changed = following.clone(); changed.state_bytes[0] ^= 1;
                assert!(link(&changed, program, binding_pin, full_pin, &receipt).is_err());
                let mut changed = following.clone(); changed.checkpoint_pin[0] ^= 1;
                assert!(link(&changed, program, binding_pin, full_pin, &receipt).is_err());
                let mut changed = following.clone(); changed.native_checkpoint = decoded.native_checkpoint.clone();
                assert!(link(&changed, program, binding_pin, full_pin, &receipt).is_err());
                let mut trailing = bytes.clone(); trailing.push(0);
                assert!(OwnedEcxNativeWithdrawalV1::decode(&trailing).is_err());
                let mut wrong_role = bytes.clone(); wrong_role[..6].copy_from_slice(b"ECXNI1");
                assert!(OwnedEcxNativeWithdrawalV1::decode(&wrong_role).is_err());
                assert!(crate::ecx_match_execution_v1::OwnedEcxNativeMatchV1::decode(&bytes).is_err());
                assert!(OwnedEcxNativeWithdrawalV1::decode(&bytes[..bytes.len()-1]).is_err());
                assert_eq!(outer.public_values().state, expected.0);
                assert_eq!(outer.checkpoint().state, result.2);
                assert!(outer.checkpoint().bmm_endpoint.is_some());
                crate::ecx_match_execution_v1::EcxNativeMatchPublicValuesV1::decode(outer.journal())
                    .unwrap().check_opening(binding_pin, full_pin, outer.checkpoint()).unwrap();
                assert!(execute_outer([0;32], full_pin, &continuity).is_err());
                assert!(execute_outer(binding_pin, [0;32], &continuity).is_err());
                let mut changed = continuity.clone();
                changed.state.exchange_state_root[0] ^= 1;
                assert!(execute_outer(binding_pin, changed.commitment().unwrap(), &changed).is_err());
                let mut changed = continuity.clone();
                changed.state.vault_outpoint.vout += 1;
                assert!(execute_outer(binding_pin, changed.commitment().unwrap(), &changed).is_err());
                let mut wrong_next = outer.checkpoint().clone();
                wrong_next.bmm_endpoint.as_mut().unwrap()[0] ^= 1;
                assert!(outer.public_values().check_opening(binding_pin, full_pin, &wrong_next).is_err());
                checked_count += 1;
            });
        assert_eq!(checked_count, 2);
    }

    fn exercise(builder: Option<NativeBuilder<'_>>) {
        use ecx_protocol_core::{TraderLeafV2, IncrementalAccountingBoundsV2, XOnlyKey,
            incremental_state_v2::Int256V2, types::ECX_USDD_MARKET, risk::RiskParams,
            ecx_collateral::EcxCollateralAtoms,
            ecx_cash_account_v1::{ecx_account_root, ecx_empty_account_subtree_v1}};
        let key = |s: &str| XOnlyKey(hex::decode(s).unwrap().try_into().unwrap());
        let economics = EcxConfigurationV1 {
            chain_id: [1;32], market: ECX_USDD_MARKET, collateral_asset: [2;32],
            clearing_account: key("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            insurance_account: key("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            cash_valuation_scale: 1_000_000, risk: RiskParams::default(),
            bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 1_000_000,
                maximum_total_controlled_atoms: 10_000_000,
                maximum_abs_position_atoms: 1_000_000,
                maximum_open_interest_atoms: 10_000_000, maximum_price_atoms: 1_000_000_000,
            },
        };
        let domain = economics.account_domain().unwrap();
        let position = TraderLeafV2 {
            version: TraderLeafV2::VERSION, trader: key("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            account_nonce: 0, collateral_atoms: 0, cash_residual_numerator: 0,
            position_size_atoms: 0, signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0, selected_initial_margin_bps: 1000,
            order_generation: 0, salt: [4;32],
        };
        let before = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100));
        let after = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(107));
        let path: Vec<_> = (0..256).map(|h| ecx_empty_account_subtree_v1(h).unwrap()).collect();
        let root = |cash| ecx_account_root(domain, &position, cash, economics.bounds, &path).unwrap();
        {
            // Real owner signatures and authenticated account/book openings;
            // this qualifies the state operation, not a native covenant spend.
            use ecx_protocol_core::{ecx_order_v1::{SignedEcxOrderV1, EcxAdmittedOrderV2},
                ecx_cancel_v1::SignedEcxCancelV1,
                successor_action_v2::{SuccessorLimitOrderV2, SuccessorCancelOrderV2},
                order::{Side, TimeInForce, OrderFlags}, types::{Price, Quantity},
                ecx_configuration_v1::EcxSuccessorBindingsV1,
                ecx_order_index_v1::{order_leaf, order_root}, hash::tagged_hash};
            use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
            let mut secret = [0;32]; secret[31] = 3;
            let secret = bitcoin::secp256k1::SecretKey::from_slice(&secret).unwrap();
            let (order, admitted) = EcxAdmittedOrderV2::admit(SignedEcxOrderV1::sign(domain,
                SuccessorLimitOrderV2 {
                    version: 2, chain_id: domain.chain_id, market: domain.market,
                    trader: position.trader, side: Side::Buy,
                    time_in_force: TimeInForce::GoodTilHeight, flags: OrderFlags::from_bits(0).unwrap(),
                    limit_price: Price::new(100_000_000).unwrap(), quantity: Quantity::new(1).unwrap(),
                    client_order_id: [0;16], max_fee_bps: 100, nonce: 0,
                    valid_from_height: 0, expires_at_height: 100,
                }, &secret).unwrap(), domain, &position, 1, economics.bounds, 1).unwrap();
            let id = order.signed.order_id().unwrap();
            let mut empty = order_leaf(domain, id, None).unwrap();
            let mut book_path = Vec::new();
            for height in 1u16..=256 {
                book_path.push(empty);
                let mut bytes = vec![1]; bytes.extend_from_slice(&height.to_be_bytes());
                bytes.extend_from_slice(&empty); bytes.extend_from_slice(&empty);
                empty = tagged_hash("ECX/ecx-order-index-node/v1", &bytes);
            }
            let bindings = EcxSuccessorBindingsV1 {
                economic_configuration_hash: economics.digest().unwrap(),
                oracle_configuration_hash: [11;32], matcher_configuration_hash: [12;32],
                funding_oracle_program_id: [13;32], account_execution_program_id: [14;32],
                vault_policy_hash: [15;32],
            };
            let state = EcxSuccessorStateV1 {
                bindings_hash: bindings.digest().unwrap(),
                accounts_root: ecx_account_root(domain, &admitted, &before, economics.bounds, &path).unwrap(),
                orders_root: order_root(domain, id, Some(&order), &book_path).unwrap(),
                funding_root: [17;32], funding_index: -3, open_interest: 0,
                matcher_sequence: 4, matcher_receipt_hash: [18;32], sidechain_height: 1,
                parent_hash: [19;32], parent_height: 2, parent_mtp: 3,
                controlled_ecx_atoms: 100, vault_script_sha256: [20;32],
            };
            // Real owner + matcher signatures join indexed admission to the
            // committed cursor. This is a state relation, not native inclusion.
            {
                use ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1;
                use ecx_protocol_core::ecx_matcher_v1::EcxMatcherExecutionReceiptV1;
                use ecx_protocol_core::successor_matcher_v2::SuccessorCentralMatcherConfigV2;
                let matcher = SuccessorCentralMatcherConfigV2 {
                    version: 2, key_epoch: 1, signer: position.trader,
                    genesis_sequence: 4, genesis_receipt_hash: [18;32],
                    forced_inclusion_blocks: 1,
                };
                let mut bindings = bindings;
                bindings.matcher_configuration_hash = matcher.digest();
                let mut prior = state.clone();
                prior.bindings_hash = bindings.digest().unwrap();
                prior.accounts_root = ecx_account_root(domain, &position, &before, economics.bounds, &path).unwrap();
                prior.orders_root = empty;
                let opening = || EcxAccountOpeningV1 { position: &position, cash: &before, siblings: &path };
                let mark = Price::new(100_000_000).unwrap();
                let digest = prior.digest().unwrap();
                let (update, execution) = prior.order_admission_execution(digest, bindings, economics,
                    order.signed.clone(), opening(), &book_path, &[], mark, mark).unwrap();
                assert_eq!(update.order.received_sequence, 5);
                assert_eq!(update.position, admitted);
                assert_eq!(update.accounts_root, state.accounts_root);
                assert_ne!(update.orders_root, state.orders_root); // same order, different priority
                let receipt = EcxMatcherExecutionReceiptV1::sign(economics, &matcher, 5,
                    prior.matcher_receipt_hash, execution, &secret).unwrap();
                let execute = |source: &EcxSuccessorStateV1, expected, receipt: &EcxMatcherExecutionReceiptV1| {
                    source.admit_order(expected, bindings, economics, &matcher, receipt,
                        order.signed.clone(), opening(), &book_path, &[], mark, mark)
                };
                let next = execute(&prior, digest, &receipt).unwrap();
                let mut expected = prior.clone();
                expected.accounts_root = update.accounts_root;
                expected.orders_root = update.orders_root;
                expected.matcher_sequence = 5;
                expected.matcher_receipt_hash = receipt.digest();
                assert_eq!(next, expected);
                let mut bad_signature = receipt.clone();
                bad_signature.signature.0[0] ^= 1;
                assert!(execute(&prior, digest, &bad_signature).is_err());
                let mut bad_owner = order.signed.clone();
                bad_owner.signature.0[0] ^= 1;
                assert!(prior.admit_order(digest, bindings, economics, &matcher, &receipt,
                    bad_owner, opening(), &book_path, &[], mark, mark).is_err());
                assert!(execute(&prior, [0;32], &receipt).is_err());
                assert!(execute(&next, next.digest().unwrap(), &receipt).is_err());
                for (sequence, previous, hash) in [(6, [18;32], execution),
                    (5, [17;32], execution), (5, [18;32], [99;32])] {
                    let wrong = EcxMatcherExecutionReceiptV1::sign(economics, &matcher,
                        sequence, previous, hash, &secret).unwrap();
                    assert!(execute(&prior, digest, &wrong).is_err());
                }
                let (_, changed_bounds) = prior.order_admission_execution(digest, bindings, economics,
                    order.signed.clone(), opening(), &book_path, &[], mark,
                    Price::new(100_000_001).unwrap()).unwrap();
                assert_ne!(execution, changed_bounds);
                let mut overflow = prior.clone(); overflow.matcher_sequence = u128::MAX;
                assert!(execute(&overflow, overflow.digest().unwrap(), &receipt).is_err());
                assert_eq!(prior.digest().unwrap(), digest); // every rejection is atomic
            }
            // Authenticated target margin, not a liquidation or oracle proof.
            // At entry a 1,000-atom position requires 60 atoms at 600 bps.
            for size in [-1000i64, 1000] {
                let mut target = position.clone();
                let mark = Price::new(100_000_000).unwrap();
                target.apply_trade_for_ecx_settlement(size, mark.get(), 0, economics.bounds).unwrap();
                for balance in [59, 60, 61] {
                    use ecx_protocol_core::ecx_cash_account_v1::{EcxAccountOpeningV1, EcxMarginStatusV1};
                    let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(balance));
                    let opening = || EcxAccountOpeningV1 { position: &target, cash: &cash, siblings: &path };
                    let mut pinned = state.clone();
                    pinned.funding_index = 0;
                    pinned.accounts_root = ecx_account_root(domain, &target, &cash, economics.bounds, &path).unwrap();
                    let digest = pinned.digest().unwrap();
                    assert_eq!(pinned.liquidation_target_margin(digest, bindings, economics, opening(), mark).unwrap(),
                        if balance < 60 { EcxMarginStatusV1::Insufficient } else { EcxMarginStatusV1::Sufficient });
                    assert!(pinned.liquidation_target_margin([0;32], bindings, economics, opening(), mark).is_err());
                    let mut wrong = economics; wrong.risk.maintenance_margin_bps += 1;
                    assert!(pinned.liquidation_target_margin(digest, bindings, wrong, opening(), mark).is_err());
                    let mut substituted = target.clone(); substituted.account_nonce += 1;
                    assert!(pinned.liquidation_target_margin(digest, bindings, economics,
                        EcxAccountOpeningV1 { position: &substituted, cash: &cash, siblings: &path }, mark).is_err());
                    let altered = cash.checked_top_up(1).unwrap();
                    assert!(pinned.liquidation_target_margin(digest, bindings, economics,
                        EcxAccountOpeningV1 { position: &target, cash: &altered, siblings: &path }, mark).is_err());
                    if balance == 60 {
                        pinned.funding_index = if size > 0 { 1 } else { -1 };
                        assert!(pinned.liquidation_target_margin(digest, bindings, economics, opening(), mark).is_err());
                        assert_eq!(pinned.liquidation_target_margin(pinned.digest().unwrap(), bindings, economics,
                            opening(), mark).unwrap(), EcxMarginStatusV1::Insufficient);
                    }
                }
            }
            for role in [None, Some(economics.clearing_account), Some(economics.insurance_account)] {
                let mut forbidden = position.clone();
                if let Some(key) = role {
                    forbidden.trader = key;
                    forbidden.apply_trade_for_ecx_settlement(1000, 100_000_000, 0, economics.bounds).unwrap();
                }
                let mut pinned = state.clone();
                pinned.accounts_root = ecx_account_root(domain, &forbidden, &before, economics.bounds, &path).unwrap();
                assert!(pinned.liquidation_target_margin(pinned.digest().unwrap(), bindings, economics,
                    ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1 {
                        position: &forbidden, cash: &before, siblings: &path,
                    }, Price::new(100_000_000).unwrap()).is_err());
            }
            let signed = SignedEcxCancelV1::sign(domain, SuccessorCancelOrderV2 {
                version: 2, chain_id: domain.chain_id, market: domain.market,
                trader: admitted.trader, order_id: id, nonce: admitted.account_nonce,
                valid_from_height: 1, expires_at_height: 3,
            }, &secret).unwrap();
            let opening = || ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1 {
                position: &admitted, cash: &before, siblings: &path,
            };
            let next = state.cancel_order(state.digest().unwrap(), bindings, economics,
                &signed, opening(), &order, &book_path).unwrap();
            let mut cancelled = admitted.clone(); cancelled.account_nonce += 1;
            let mut expected = state.clone();
            expected.accounts_root = ecx_account_root(domain, &cancelled, &before, economics.bounds, &path).unwrap();
            expected.orders_root = empty;
            assert_ne!(next.accounts_root, state.accounts_root);
            assert_ne!(next.orders_root, state.orders_root);
            assert_eq!(next, expected); // Every non-root field is unchanged.
            let script = elements::Script::from(vec![0x51]); // Synthetic covenant only.
            let output = elements::TxOut {
                asset: elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array(domain.collateral_asset)),
                value: elements::confidential::Value::Explicit(100),
                nonce: elements::confidential::Nonce::Null, script_pubkey: script.clone(),
                witness: Default::default(),
            };
            let source = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
                input: vec![], output: vec![output.clone()] };
            let outpoint = elements::OutPoint::new(source.txid(), 0);
            let successor = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn { previous_output: outpoint, ..Default::default() }],
                output: vec![output] };
            let mut backed = state.clone();
            backed.vault_script_sha256 = elements::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array();
            let prior_ledger = [(&admitted, &before)];
            let next_ledger = [(&cancelled, &before)];
            let check = |tx: &elements::Transaction, ledger: &[(&TraderLeafV2, &EcxCashAccountV1)]| {
                ecx_proof_core::ecx_execution_v1::verify_ecx_cancellation_v1(
                    backed.digest().unwrap(), &backed, outpoint, bindings, economics,
                    &signed, opening(), &order, &book_path, &EcxTradingVaultWitnessV1 {
                        source_outpoint: outpoint, source_transaction: &source,
                        successor_transaction: tx, successor_vout: 0,
                        source_script_sha256: backed.vault_script_sha256,
                        successor_script_sha256: backed.vault_script_sha256,
                        prior_accounts: &prior_ledger, successor_accounts: ledger,
                    })
            };
            let mut expected_backed = next.clone();
            expected_backed.vault_script_sha256 = backed.vault_script_sha256;
            assert_eq!(check(&successor, &next_ledger).unwrap(), expected_backed);
            use ecx_proof_core::ecx_cancellation_input_v1::EcxCancellationInputV1;
            use ecx_protocol_core::codec::CanonicalEncode;
            let owned = EcxCancellationInputV1 {
                expected_state: backed.digest().unwrap(), state_bytes: backed.encode().unwrap(),
                bindings, economics, signed: signed.clone(),
                account: ecx_proof_core::ecx_match_input_v1::EcxOwnedAccountV1 {
                    position: admitted.clone(), cash_bytes: before.canonical_bytes(), siblings: path.clone(),
                },
                order: order.clone(), order_siblings: book_path.clone(),
                source_outpoint_bytes: elements::encode::serialize(&outpoint),
                source_transaction_bytes: elements::encode::serialize(&source),
                successor_transaction_bytes: elements::encode::serialize(&successor),
                successor_vout: 0, successor_script_sha256: backed.vault_script_sha256,
                prior_accounts: vec![(admitted.clone(), before.canonical_bytes())],
                successor_accounts: vec![(cancelled.clone(), before.canonical_bytes())],
            };
            let encoded = owned.encode().unwrap();
            let restored = EcxCancellationInputV1::decode(&encoded).unwrap();
            assert_eq!(restored.encode().unwrap(), encoded);
            assert_eq!(restored.execute().unwrap(), expected_backed);
            for bytes in [vec![], encoded[..encoded.len()-1].to_vec(),
                [encoded.as_slice(), &[0]].concat(),
                [b"ECXCA1".as_slice(), &encoded[6..]].concat(),
                [b"ECXWI1".as_slice(), &encoded[6..]].concat()] {
                assert!(EcxCancellationInputV1::decode(&bytes).is_err());
            }
            let mut corrupt = restored.clone(); corrupt.expected_state = [0;32];
            assert!(corrupt.execute().is_err());
            let mut corrupt = restored.clone(); corrupt.account.cash_bytes.push(0);
            assert!(corrupt.execute().is_err());
            let mut corrupt = restored.clone(); corrupt.order_siblings[0] = [99;32];
            assert!(corrupt.execute().is_err());
            let mut corrupt = restored.clone(); corrupt.successor_accounts = corrupt.prior_accounts.clone();
            assert!(corrupt.execute().is_err());
            assert!(check(&successor, &prior_ledger).is_err());
            let mut wrong = successor.clone(); wrong.output[0].value = elements::confidential::Value::Explicit(99);
            assert!(check(&wrong, &next_ledger).is_err());
            let mut wrong = successor.clone(); wrong.output[0].script_pubkey = elements::Script::from(vec![0x52]);
            assert!(check(&wrong, &next_ledger).is_err());
            let mut wrong = successor.clone(); wrong.output[0].asset = elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array([99;32]));
            assert!(check(&wrong, &next_ledger).is_err());
            let mut wrong = successor.clone(); wrong.input.push(wrong.input[0].clone());
            assert!(check(&wrong, &next_ledger).is_err());
            let mut wrong = successor.clone(); wrong.input.clear();
            assert!(check(&wrong, &next_ledger).is_err());
            assert!(state.cancel_order([0;32], bindings, economics, &signed, opening(), &order, &book_path).is_err());
            if let Some(build) = builder {
                let mut prior = backed.clone();
                prior.sidechain_height = 16;
                prior.parent_height = 1;
                prior.parent_mtp = 1;
                let mut request = signed.cancel.clone();
                request.expires_at_height = 100;
                let native_signed = SignedEcxCancelV1::sign(domain, request, &secret).unwrap();
                let transition = |prepared: &EcxSuccessorStateV1| {
                    prepared.cancel_order(prepared.digest().unwrap(), bindings, economics,
                        &native_signed, opening(), &order, &book_path).unwrap()
                };
                let (executed, context, continuity, native) = build(&source, &successor, &prior,
                    None, Some(&transition));
                let utxo = &native.execution.witnesses[1].utxo;
                let spent = utxo.spends[0].old_leaf.as_ref().unwrap();
                let created = utxo.creates[0].new_leaf.as_ref().unwrap();
                let vault = EcxTradingVaultWitnessV1 {
                    source_outpoint: outpoint, source_transaction: &source,
                    successor_transaction: &successor, successor_vout: 0,
                    source_script_sha256: prior.vault_script_sha256,
                    successor_script_sha256: prior.vault_script_sha256,
                    prior_accounts: &prior_ledger, successor_accounts: &next_ledger,
                };
                let verify = |index, prior: &EcxSuccessorStateV1, post_path: &ElementsSparseUtxoPathV2| {
                    context.verify_ecx_cancellation(&executed, index, prior, outpoint,
                        bindings, economics, &native_signed, opening(), &order, &book_path,
                        &vault, EcxCoinMembershipV1 { leaf: spent, path: &utxo.spends[0].path },
                        EcxCoinMembershipV1 { leaf: created, path: post_path })
                };
                let prepared = context.prepare_ecx_match_state(&prior, bindings).unwrap();
                assert_eq!(verify(1, &prior, &utxo.creates[0].path).unwrap(), transition(&prepared));
                assert!(verify(0, &prior, &utxo.creates[0].path).is_err());
                let mut wrong = prior.clone(); wrong.accounts_root[0] ^= 1;
                assert!(verify(1, &wrong, &utxo.creates[0].path).is_err());
                let mut wrong_path = utxo.creates[0].path.clone(); wrong_path.siblings[0].hash[0] ^= 1;
                assert!(verify(1, &prior, &wrong_path).is_err());
                let advance = |record: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1, pin| {
                    context.advance_ecx_cancellation_checkpoint(&executed, 1, record, pin,
                        &prior, bindings, economics, &native_signed, opening(), &order,
                        &book_path, &vault,
                        EcxCoinMembershipV1 { leaf: spent, path: &utxo.spends[0].path },
                        EcxCoinMembershipV1 { leaf: created, path: &utxo.creates[0].path })
                };
                let frozen = continuity.commitment().unwrap();
                let (state, next_checkpoint) = advance(&continuity, frozen).unwrap();
                assert_eq!(state, transition(&prepared));
                assert_eq!(next_checkpoint.execution, *executed.child().next_checkpoint().unwrap());
                assert_eq!(next_checkpoint.exchange_state_root, state.digest().unwrap());
                assert_eq!(next_checkpoint.bindings_hash, continuity.bindings_hash);
                assert_eq!(next_checkpoint.vault_outpoint, created.outpoint);
                let mut native_owned = restored.clone();
                native_owned.state_bytes = prepared.encode().unwrap();
                native_owned.expected_state = prepared.digest().unwrap();
                native_owned.signed = native_signed.clone();
                let transported = EcxCancellationInputV1::decode(&native_owned.encode().unwrap()).unwrap();
                let advance_owned = |input: &EcxCancellationInputV1| {
                    context.advance_ecx_owned_cancellation(&executed, 1, &continuity, frozen,
                        &prior, input,
                        EcxCoinMembershipV1 { leaf: spent, path: &utxo.spends[0].path },
                        EcxCoinMembershipV1 { leaf: created, path: &utxo.creates[0].path })
                };
                let (owned_state, owned_checkpoint) = advance_owned(&transported).unwrap();
                assert_eq!(owned_state, state);
                assert_eq!(owned_checkpoint, next_checkpoint);
                // Joined cancellation transport/receipt/native boundary. The
                // predecessor receipt is synthetic; native execution is real
                // under this fixture's OP_TRUE policy, not a production proof.
                use crate::ecx_match_execution_v1::{OwnedEcxNativeCancellationV1,
                    OwnedEcxCancellationContinuationV1, OwnedEcxContinuationActionV1,
                    EcxNativeMatchPublicValuesV1};
                use super::oracle_context::TestDigestVerifier;
                struct DenySimplicity;
                impl ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for DenySimplicity {
                    fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(),
                        ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                        Err(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::AuthorizationConsensus)
                    }
                }
                let full = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                    state: continuity.clone(), bmm_endpoint: native.checkpoint.bmm_endpoint.clone(),
                };
                let pin = full.commitment().unwrap();
                let binding_pin = native.binding.commitment().unwrap();
                let input = OwnedEcxNativeCancellationV1 {
                    execution: native.execution.clone(), binding: native.binding.clone(),
                    native_checkpoint: native.checkpoint.clone(), deposit_policy: native.deposit_policy.clone(),
                    environment: native.environment.encode().unwrap(), native_binding_pin: binding_pin,
                    checkpoint_pin: pin, checkpoint: full, transaction_index: 1,
                    state_bytes: prior.encode().unwrap(), cancellation: transported.clone(),
                    coin: spent.clone(), path: utxo.spends[0].path.clone(),
                    successor_coin: created.clone(), successor_path: utxo.creates[0].path.clone(),
                };
                let parent = &native.execution.parent;
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let outer = input.execute(&verifier, &DenySimplicity).unwrap();
                verifier.assert_consumed();
                assert_eq!(outer.public_values().state, state);
                assert_eq!(outer.checkpoint().state, next_checkpoint);
                let source_public = EcxNativeMatchPublicValuesV1 {
                    native_binding: binding_pin, predecessor_checkpoint: pin,
                    successor_checkpoint: pin, state: prior.clone(),
                };
                let program = [15;32];
                let journal = source_public.canonical_bytes().unwrap().to_vec();
                let mut transcript = program.to_vec(); transcript.extend_from_slice(&journal);
                let envelope = OwnedEcxCancellationContinuationV1 {
                    input, continuation_program: [16;32], recursive: false,
                    initialization_binding: native.binding.clone(),
                    initialization_parent: native.execution.parent.binding,
                    initialization_environment: native.environment.encode().unwrap(),
                    predecessor_program: program, predecessor_binding: binding_pin,
                    predecessor_checkpoint: pin, predecessor_journal: journal,
                    predecessor_proof: <sha2::Sha256 as sha2::Digest>::digest(&transcript).to_vec(),
                };
                let bytes = envelope.encode().unwrap();
                assert_eq!(OwnedEcxCancellationContinuationV1::decode(&bytes).unwrap().encode().unwrap(), bytes);
                let action = OwnedEcxContinuationActionV1::decode(&bytes).unwrap();
                assert!(matches!(&action, OwnedEcxContinuationActionV1::Cancellation(_)));
                assert_eq!(action.continuation_program(), envelope.continuation_program);
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                let joined = action.execute(&verifier, &DenySimplicity, &TestDigestVerifier).unwrap();
                verifier.assert_consumed();
                assert_eq!(joined.len(), 546);
                assert_eq!(&joined[..6], b"ECXNC2");
                assert_eq!(&joined[134..], outer.journal());
                assert_eq!(&joined[102..134], &envelope.continuation_program);
                for length in [0, 5, bytes.len()-1] {
                    assert!(OwnedEcxContinuationActionV1::decode(&bytes[..length]).is_err());
                }
                let mut extra = bytes.clone(); extra.push(0);
                assert!(OwnedEcxContinuationActionV1::decode(&extra).is_err());
                for mutation in 0..6 {
                    let mut bad = envelope.clone();
                    match mutation {
                        0 => bad.predecessor_proof[0] ^= 1,
                        1 => bad.continuation_program = program,
                        2 => bad.input.state_bytes[0] ^= 1,
                        3 => bad.input.checkpoint_pin[0] ^= 1,
                        4 => bad.input.transaction_index = 0,
                        _ => bad.input.cancellation.signed.cancel.nonce += 1,
                    }
                    let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([parent,parent,parent]);
                    assert!(bad.execute(&verifier, &DenySimplicity, &TestDigestVerifier).is_err(), "mutation {mutation}");
                }
                assert!(advance_owned(&restored).is_err()); // Unprepared clock.
                let mut wrong = transported.clone(); wrong.expected_state = prior.digest().unwrap();
                assert!(advance_owned(&wrong).is_err());
                let mut wrong = transported.clone(); wrong.state_bytes = prior.encode().unwrap();
                assert!(advance_owned(&wrong).is_err());
                let mut wrong = transported.clone();
                wrong.source_outpoint_bytes = elements::encode::serialize(&created.outpoint);
                assert!(advance_owned(&wrong).is_err());
                assert!(advance(&continuity, [0;32]).is_err());
                let mut substituted = continuity.clone(); substituted.exchange_state_root[0] ^= 1;
                assert!(advance(&substituted, substituted.commitment().unwrap()).is_err());
                let mut substituted = continuity.clone(); substituted.bindings_hash[0] ^= 1;
                assert!(advance(&substituted, substituted.commitment().unwrap()).is_err());
                let mut substituted = continuity.clone(); substituted.vault_outpoint.vout += 1;
                assert!(advance(&substituted, substituted.commitment().unwrap()).is_err());
                assert!(advance(&next_checkpoint, next_checkpoint.commitment().unwrap()).is_err());
            }
            let mut wrong_binding = bindings; wrong_binding.vault_policy_hash[0] ^= 1;
            assert!(state.cancel_order(state.digest().unwrap(), wrong_binding, economics,
                &signed, opening(), &order, &book_path).is_err());
            let mut wrong_economics = economics; wrong_economics.collateral_asset[0] ^= 1;
            assert!(state.cancel_order(state.digest().unwrap(), bindings, wrong_economics,
                &signed, opening(), &order, &book_path).is_err());
            assert!(next.cancel_order(next.digest().unwrap(), bindings, economics,
                &signed, opening(), &order, &book_path).is_err());
        }
        let script = elements::Script::from(vec![0x51]); // Synthetic policy only.
        let script_hash = elements::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array();
        let output = |amount| elements::TxOut {
            asset: elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array([2;32])),
            value: elements::confidential::Value::Explicit(amount), nonce: elements::confidential::Nonce::Null,
            script_pubkey: script.clone(), witness: Default::default(),
        };
        let mut marker = output(0);
        marker.script_pubkey = ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
            economics, position.key(), 1, 7).unwrap();
        let source = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![], output: vec![output(100), output(7), marker] };
        let coin = |vout| ElementsUtxoLeafV2 {
            outpoint: elements::OutPoint::new(source.txid(), vout), output: source.output[vout as usize].clone(),
            creation_height: 7, creation_parent_mtp: 100, coinbase: false,
            created_by_issuance: false, created_by_pegin: false,
        };
        let vault_coin = coin(0); let funding_coin = coin(1);
        let (utxo, vp, dp) = crate::capital_genesis_utxos_v4::tests::pair_paths(&vault_coin, &funding_coin);
        let successor = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: [vault_coin.outpoint, funding_coin.outpoint].into_iter().map(|previous_output|
                elements::TxIn { previous_output, ..Default::default() }).collect(), output: vec![output(107)] };
        let prior_ledger = [(&position, &before)]; let after_ledger = [(&position, &after)];
        if let Some(build) = builder {
            use ecx_proof_core::{ecx_successor_state_v1::EcxSuccessorStateV1,
                ecx_match_input_v1::{ConsensusProofVerifier, ConsensusProofVerificationError}};
            use ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1;
            let bindings = EcxSuccessorBindingsV1 {
                economic_configuration_hash: economics.digest().unwrap(),
                oracle_configuration_hash: [11;32], matcher_configuration_hash: [12;32],
                funding_oracle_program_id: [13;32], account_execution_program_id: [14;32],
                vault_policy_hash: [15;32],
            };
            let state = EcxSuccessorStateV1 {
                bindings_hash: bindings.digest().unwrap(), accounts_root: root(&before),
                orders_root: [16;32], funding_root: [17;32], funding_index: 0,
                open_interest: 0, matcher_sequence: 0, matcher_receipt_hash: [18;32],
                sidechain_height: 6, parent_hash: [19;32], parent_height: 1, parent_mtp: 1,
                controlled_ecx_atoms: 100, vault_script_sha256: script_hash,
            };
            let trade = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn { previous_output: vault_coin.outpoint, ..Default::default() }],
                output: vec![output(100)] };
            let (checked, context, continuity, native_input) = build(&source, &trade, &state, None, None);
            // Qualify the native split-output plumbing independently of the
            // withdrawal authorization relation. The synthetic header below
            // still models a match; this is not a withdrawal receipt.
            let mut split = trade.clone();
            split.output = vec![output(99), output(1)];
            let (split_checked, _, _, split_input) = build(&source, &split, &state, None, None);
            let creates = &split_input.execution.witnesses[1].utxo.creates;
            assert_eq!(creates.len(), 2);
            let vault = creates[0].new_leaf.as_ref().unwrap();
            let recipient = creates[1].new_leaf.as_ref().unwrap();
            let (split_root, vault_path, recipient_path) =
                crate::capital_genesis_utxos_v4::tests::pair_paths(vault, recipient);
            assert_eq!(split_checked.child().roots().utxo_root, split_root);
            for (coin, path) in [(vault, &vault_path), (recipient, &recipient_path)] {
                check_coin(split_root, EcxCoinMembershipV1 { leaf:coin, path },
                    coin.outpoint, &split).unwrap();
            }
            assert!(check_coin(split_root, EcxCoinMembershipV1 { leaf:vault,
                path:&creates[0].path }, vault.outpoint, &split).is_err());
            let prepared = context.prepare_ecx_match_state(&state, bindings).unwrap();
            let mut next = prepared.clone(); next.matcher_sequence = 1;
            let mut bytes = b"ECXMJ1".to_vec();
            bytes.extend_from_slice(&prepared.digest().unwrap());
            bytes.extend_from_slice(&elements::encode::serialize(&vault_coin.outpoint));
            bytes.extend_from_slice(&next.encode().unwrap());
            // Exact transcript only: this tests receipt consumption and native
            // inclusion, not an actual match guest execution or SP1 proof.
            struct Receipt<'a>(&'a [u8]);
            impl ConsensusProofVerifier for Receipt<'_> {
                fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                    -> Result<(), ConsensusProofVerificationError> {
                    if program == [14;32] && journal == self.0 && proof == b"match-fixture" {
                        Ok(())
                    } else { Err(ConsensusProofVerificationError) }
                }
            }
            let mut native_coin = vault_coin.clone();
            native_coin.creation_height = 6;
            native_coin.creation_parent_mtp = 13;
            let native_root = checked.child().transaction_pre_utxo_root(1).unwrap();
            let mut empty = canonical_empty_elements_utxo_leaf_v2();
            let mut siblings = Vec::new();
            for _ in 0..256 {
                siblings.push(empty); empty = elements_sparse_utxo_parent_v2(empty, empty).unwrap();
            }
            let native_path = ElementsSparseUtxoPathV2 { siblings };
            assert_eq!(elements_sparse_utxo_root_from_path_v2(vault_coin.outpoint,
                elements_utxo_leaf_node_v2(&native_coin), &native_path).unwrap(), native_root);
            let mut final_coin = native_coin.clone();
            final_coin.outpoint = elements::OutPoint::new(trade.txid(), 0);
            final_coin.output = trade.output[0].clone();
            final_coin.creation_height = checked.child().next_checkpoint().unwrap().height;
            final_coin.creation_parent_mtp = native_input.execution.witnesses[1].utxo.creates[0]
                .new_leaf.as_ref().unwrap().creation_parent_mtp;
            let verify_with_post = |index, tx: &elements::Transaction, journal: &[u8], proof: &[u8],
                path: &ElementsSparseUtxoPathV2, prior: &EcxSuccessorStateV1,
                post: EcxCoinMembershipV1<'_>| {
                let vault = EcxTradingVaultWitnessV1 {
                    source_outpoint: vault_coin.outpoint, source_transaction: &source,
                    successor_transaction: tx, successor_vout: 0,
                    source_script_sha256: script_hash, successor_script_sha256: script_hash,
                    prior_accounts: &prior_ledger, successor_accounts: &prior_ledger,
                };
                context.verify_ecx_match(&checked, index, prior, vault_coin.outpoint,
                    bindings, economics, journal, proof, &Receipt(&bytes), &vault,
                    EcxCoinMembershipV1 { leaf: &native_coin, path }, post)
            };
            let post = || EcxCoinMembershipV1 { leaf: &final_coin, path: &native_path };
            let verify = |index, tx: &elements::Transaction, journal: &[u8], proof: &[u8],
                path: &ElementsSparseUtxoPathV2, prior: &EcxSuccessorStateV1| {
                verify_with_post(index, tx, journal, proof, path, prior, post())
            };
            let pin = &state;
            assert_eq!(verify(1, &trade, &bytes, b"match-fixture", &native_path, pin).unwrap(),
                (next.clone(), elements::OutPoint::new(trade.txid(), 0)));
            // A valid receipt for a different result must not substitute for
            // the state committed by the authenticated block header.
            let mut other_next = next.clone(); other_next.matcher_sequence += 1;
            let mut other_journal = bytes[..74].to_vec();
            other_journal.extend_from_slice(&other_next.encode().unwrap());
            let witness = EcxTradingVaultWitnessV1 {
                source_outpoint: vault_coin.outpoint, source_transaction: &source,
                successor_transaction: &trade, successor_vout: 0,
                source_script_sha256: script_hash, successor_script_sha256: script_hash,
                prior_accounts: &prior_ledger, successor_accounts: &prior_ledger,
            };
            let membership = || EcxCoinMembershipV1 { leaf: &native_coin, path: &native_path };
            let frozen_continuity = continuity.commitment().unwrap();
            let full_checkpoint = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                state: continuity.clone(), bmm_endpoint: native_input.checkpoint.bmm_endpoint.clone(),
            };
            struct DenySimplicity;
            impl ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2 for DenySimplicity {
                fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(),
                    ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
                    Err(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::AuthorizationConsensus)
                }
            }
            let full_pin = full_checkpoint.commitment().unwrap();
            let execute_full = |checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2,
                checkpoint_pin, binding_pin, journal: &[u8]| {
                let parent = &native_input.execution.parent;
                let parent_verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                    [parent, parent, parent]); // Context, native execution, endpoint.
                let result = crate::ecx_match_execution_v1::execute_alpha_ecx_match_v1(
                    &native_input.execution, &native_input.binding, &native_input.checkpoint,
                    &native_input.deposit_policy, &native_input.environment, binding_pin, checkpoint_pin,
                    crate::ecx_match_execution_v1::EcxMatchExecutionWitnessV1 {
                        transaction_index: 1, checkpoint, prior: pin, bindings, economics,
                        journal, proof: b"match-fixture", vault: EcxTradingVaultWitnessV1 {
                            source_outpoint: vault_coin.outpoint, source_transaction: &source,
                            successor_transaction: &trade, successor_vout: 0,
                            source_script_sha256: script_hash, successor_script_sha256: script_hash,
                            prior_accounts: &prior_ledger, successor_accounts: &prior_ledger,
                        }, membership: membership(), successor_membership: post(),
                    }, &parent_verifier, &DenySimplicity, &Receipt(&bytes));
                if result.is_ok() { parent_verifier.assert_consumed(); }
                result
            };
            let binding_pin = native_input.binding.commitment().unwrap();
            let executed = execute_full(&full_checkpoint, full_pin, binding_pin, &bytes).unwrap();
            use crate::ecx_match_execution_v1::OwnedEcxNativeMatchV1;
            use ecx_protocol_core::codec::CanonicalEncode;
            let ledger: Vec<_> = prior_ledger.iter().map(|(position, cash)|
                ((*position).clone(), cash.canonical_bytes())).collect();
            let owned = OwnedEcxNativeMatchV1 {
                execution: native_input.execution.clone(), binding: native_input.binding.clone(),
                native_checkpoint: native_input.checkpoint.clone(),
                deposit_policy: native_input.deposit_policy.clone(),
                environment: native_input.environment.encode().unwrap(),
                native_binding_pin: binding_pin, checkpoint_pin: full_pin,
                checkpoint: full_checkpoint.clone(), transaction_index: 1,
                state_bytes: pin.encode().unwrap().to_vec(), bindings, economics,
                journal: bytes.to_vec(), proof: b"match-fixture".to_vec(),
                source_transaction: elements::encode::serialize(&source),
                successor_transaction: elements::encode::serialize(&trade), successor_vout: 0,
                successor_script_sha256: script_hash,
                prior_accounts: ledger.clone(), successor_accounts: ledger,
                coin: native_coin.clone(), path: native_path.clone(),
                successor_coin: post().leaf.clone(), successor_path: post().path.clone(),
            };
            let encoded = owned.encode().unwrap();
            let restored = OwnedEcxNativeMatchV1::decode(&encoded).unwrap();
            assert_eq!(restored.encode().unwrap(), encoded);
            let execute_owned = |input: &OwnedEcxNativeMatchV1| {
                let parent = &input.execution.parent;
                let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                    [parent, parent, parent]);
                let result = input.execute(&verifier, &DenySimplicity, &Receipt(&bytes));
                if result.is_ok() { verifier.assert_consumed(); }
                result
            };
            let transported = execute_owned(&restored).unwrap();
            assert_eq!(transported.journal(), executed.journal());
            assert_eq!(transported.checkpoint(), executed.checkpoint());
            // A self-consistently rebound legacy capital checkpoint is still
            // not the native projection authenticated by the ECX checkpoint.
            let mut mixed = restored.clone();
            mixed.native_checkpoint.state.capital = Some(crate::child_execution_state_v4::CapitalProjectionV4 {
                proof_profile: 1, exchange_state_root: state.digest().unwrap(),
                configuration_hash: [21;32], asset_id: [22;32], deployment_commitment: [23;32],
                transition_program_id: [24;32], transition_cmr: [25;32], covenant_state_hash: [26;32],
                covenant_inbox_root: [27;32], covenant_inbox_count: 0,
                node_inbox_root: [27;32], node_inbox_count: 0,
            });
            mixed.binding.execution.predecessor_checkpoint = mixed.native_checkpoint.commitment().unwrap();
            mixed.execution.binding = mixed.binding.execution;
            mixed.native_binding_pin = mixed.binding.commitment().unwrap();
            assert!(execute_owned(&mixed).is_err());
            for length in [0, 5, 6, encoded.len() - 1] {
                assert!(OwnedEcxNativeMatchV1::decode(&encoded[..length]).is_err());
            }
            let mut malformed = encoded.clone(); malformed.push(0);
            assert!(OwnedEcxNativeMatchV1::decode(&malformed).is_err());
            malformed = encoded.clone(); malformed[5] = b'2';
            assert!(OwnedEcxNativeMatchV1::decode(&malformed).is_err());
            let mut wrong = restored.clone(); wrong.prior_accounts[0].1.push(0);
            assert!(execute_owned(&wrong).is_err());
            wrong = restored.clone(); wrong.checkpoint_pin = [0;32];
            assert!(execute_owned(&wrong).is_err());
            wrong = restored; wrong.state_bytes.push(0);
            assert!(execute_owned(&wrong).is_err());
            let full_next = executed.checkpoint();
            let next_native = full_next.native_projection(executed.public_values().successor_checkpoint).unwrap();
            assert_eq!(next_native.state.execution, full_next.state.execution);
            assert_eq!(next_native.bmm_endpoint, full_next.bmm_endpoint);
            assert!(next_native.state.capital.is_none());
            assert!(full_next.native_projection(full_pin).is_err());
            assert!(full_next.native_projection([0;32]).is_err());
            assert_eq!(executed.public_values().state, next);
            let mut expected_journal = b"ECXNJ1".to_vec();
            expected_journal.extend_from_slice(&binding_pin);
            expected_journal.extend_from_slice(&full_pin);
            expected_journal.extend_from_slice(&full_next.commitment().unwrap());
            expected_journal.extend_from_slice(&next.encode().unwrap());
            assert_eq!(executed.journal().as_slice(), expected_journal.as_slice());
            use crate::ecx_match_execution_v1::EcxNativeMatchPublicValuesV1;
            let decoded = EcxNativeMatchPublicValuesV1::decode(executed.journal()).unwrap();
            assert_eq!(&decoded, executed.public_values());
            // Transcript fixture only, not actual SP1 verification.
            struct NativeReceipt<'a>(&'a [u8]);
            impl ConsensusProofVerifier for NativeReceipt<'_> {
                fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                    -> Result<(), ConsensusProofVerificationError> {
                    if program == [15;32] && journal == self.0 && proof == b"native-fixture" {
                        Ok(())
                    } else { Err(ConsensusProofVerificationError) }
                }
            }
            let native_receipt = NativeReceipt(executed.journal());
            // Open the actual result as the following input. This qualifies
            // receipt linkage only, not execution of a second native block.
            let mut following = owned.clone();
            following.checkpoint = full_next.clone();
            following.checkpoint_pin = decoded.successor_checkpoint;
            following.native_checkpoint = next_native.clone();
            following.state_bytes = decoded.state.encode().unwrap().to_vec();
            let link = |input: &OwnedEcxNativeMatchV1, program, proof: &[u8]| {
                input.verify_predecessor_receipt(executed.journal(), proof, &native_receipt,
                    program, binding_pin, full_pin)
            };
            link(&following, [15;32], b"native-fixture").unwrap();
            assert!(link(&owned, [15;32], b"native-fixture").is_err());
            assert!(link(&following, [14;32], b"native-fixture").is_err());
            assert!(link(&following, [15;32], b"wrong-proof").is_err());
            let mut substituted = following.clone(); substituted.state_bytes = owned.state_bytes.clone();
            assert!(link(&substituted, [15;32], b"native-fixture").is_err());
            let mut history = native_input.execution.history.clone();
            let (included_header, _) = crate::native_header_v3::NativeHeader::decode_prefix(
                &native_input.execution.raw_block, true).unwrap();
            history.push(included_header.encode(false,true).unwrap());
            let resume = NativeMatchResume { checkpoint: full_next.clone(), history, coin: final_coin.clone() };
            let mut second_trade = trade.clone();
            second_trade.input[0].previous_output = final_coin.outpoint;
            let (_, second_context, _, second_input) = build(&trade, &second_trade, &decoded.state, Some(&resume), None);
            let second_prepared = second_context.prepare_ecx_match_state(&decoded.state, bindings).unwrap();
            let mut second_state = second_prepared.clone();
            second_state.matcher_sequence += 1;
            let mut second_journal = b"ECXMJ1".to_vec();
            second_journal.extend_from_slice(&second_prepared.digest().unwrap());
            second_journal.extend_from_slice(&elements::encode::serialize(&final_coin.outpoint));
            second_journal.extend_from_slice(&second_state.encode().unwrap());
            let mut second = following.clone();
            second.execution = second_input.execution.clone();
            second.binding = second_input.binding.clone();
            second.native_binding_pin = second.binding.commitment().unwrap();
            second.native_checkpoint = second_input.checkpoint.clone();
            second.environment = second_input.environment.encode().unwrap();
            second.journal = second_journal.clone();
            second.source_transaction = elements::encode::serialize(&trade);
            second.successor_transaction = elements::encode::serialize(&second_trade);
            second.coin = final_coin.clone();
            second.successor_coin = second.execution.witnesses[1].utxo.creates[0].new_leaf.clone().unwrap();
            struct ChainReceipt<'a> { previous: &'a [u8], current: &'a [u8] }
            impl ConsensusProofVerifier for ChainReceipt<'_> {
                fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                    -> Result<(), ConsensusProofVerificationError> {
                    if (program == [15;32] && journal == self.previous && proof == b"native-fixture")
                        || (program == [14;32] && journal == self.current && proof == b"match-fixture") {
                        Ok(())
                    } else { Err(ConsensusProofVerificationError) }
                }
            }
            let second_parent = &second.execution.parent;
            let parent_verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                [second_parent, second_parent, second_parent]);
            let second_result = second.execute_after_receipt(executed.journal(), b"native-fixture",
                [15;32], binding_pin, full_pin, &parent_verifier, &DenySimplicity,
                &ChainReceipt { previous: executed.journal(), current: &second_journal }).unwrap();
            parent_verifier.assert_consumed();
            assert_eq!(second_result.public_values().predecessor_checkpoint, decoded.successor_checkpoint);
            assert_eq!(second_result.public_values().state, second_state);
            assert_eq!(second_result.checkpoint().state.execution.height, 18);
            assert_eq!(second_result.checkpoint().state.vault_outpoint, elements::OutPoint::new(second_trade.txid(), 0));
            let continuation = crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1 {
                input: second.clone(), continuation_program: [16;32], recursive: false,
                initialization_binding: owned.binding.clone(),
                initialization_parent: owned.execution.parent.binding,
                initialization_environment: owned.environment.clone(),
                predecessor_program: [15;32],
                predecessor_binding: binding_pin, predecessor_checkpoint: full_pin,
                predecessor_journal: executed.journal().to_vec(),
                predecessor_proof: b"native-fixture".to_vec(),
            };
            let transport = continuation.encode().unwrap();
            let continuation = crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1::decode(&transport).unwrap();
            assert!(OwnedEcxNativeMatchV1::decode(&transport).is_err());
            let mut trailing = transport.clone(); trailing.push(0);
            assert!(crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1::decode(&trailing).is_err());
            for length in [0, 5, transport.len()-1] {
                assert!(crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1::decode(&transport[..length]).is_err());
            }
            let parent_verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
                [second_parent, second_parent, second_parent]);
            let action = crate::ecx_match_execution_v1::OwnedEcxContinuationActionV1::decode(&transport).unwrap();
            assert!(matches!(&action, crate::ecx_match_execution_v1::OwnedEcxContinuationActionV1::Match(_)));
            assert_eq!(action.continuation_program(), continuation.continuation_program);
            let public = action.execute(&parent_verifier, &DenySimplicity,
                &ChainReceipt { previous: executed.journal(), current: &second_journal }).unwrap();
            parent_verifier.assert_consumed();
            assert_eq!(public.len(), 546);
            assert_eq!(&public[..6], b"ECXNC2");
            assert_eq!(&public[6..38], &[15;32]);
            assert_eq!(&public[38..70], &binding_pin);
            assert_eq!(&public[70..102], &full_pin);
            assert_eq!(&public[102..134], &[16;32]);
            assert_eq!(&public[134..], second_result.journal());
            assert!(EcxNativeMatchPublicValuesV1::decode(&public).is_err());
            struct ContinuationReceipt<'a>(&'a [u8]);
            impl ConsensusProofVerifier for ContinuationReceipt<'_> {
                fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                    -> Result<(), ConsensusProofVerificationError> {
                    if program == [16;32] && journal == self.0 && proof == b"native-fixture" {
                        Ok(())
                    } else { Err(ConsensusProofVerificationError) }
                }
            }
            let verify_continuation = |bytes: &[u8], program, previous_program, previous_binding,
                previous_checkpoint, proof: &[u8]| {
                crate::ecx_match_execution_v1::OwnedEcxNativeContinuationV1::verify_receipt(
                    bytes, proof, &ContinuationReceipt(&public), program, previous_program,
                    previous_binding, previous_checkpoint, second.native_binding_pin,
                    second.checkpoint_pin, second_result.checkpoint())
            };
            assert_eq!(verify_continuation(&public, [16;32], [15;32], binding_pin, full_pin,
                b"native-fixture").unwrap(), *second_result.public_values());
            assert!(verify_continuation(&public, [14;32], [15;32], binding_pin, full_pin, b"native-fixture").is_err());
            assert!(verify_continuation(&public, [16;32], [14;32], binding_pin, full_pin, b"native-fixture").is_err());
            assert!(verify_continuation(&public, [16;32], [15;32], [0;32], full_pin, b"native-fixture").is_err());
            assert!(verify_continuation(&public, [16;32], [15;32], binding_pin, [0;32], b"native-fixture").is_err());
            assert!(verify_continuation(&public, [16;32], [15;32], binding_pin, full_pin, b"wrong-proof").is_err());
            assert!(verify_continuation(second_result.journal(), [16;32], [15;32], binding_pin, full_pin, b"native-fixture").is_err());
            let mut changed_public = public.clone(); changed_public[102] ^= 1;
            assert!(verify_continuation(&changed_public, [16;32], [15;32], binding_pin, full_pin, b"native-fixture").is_err());
            let mut recursive = continuation.clone();
            recursive.recursive = true;
            recursive.predecessor_journal = public.clone();
            recursive.input.checkpoint = second_result.checkpoint().clone();
            recursive.input.checkpoint_pin = second_result.public_values().successor_checkpoint;
            recursive.input.native_checkpoint = recursive.input.checkpoint.native_projection(
                recursive.input.checkpoint_pin).unwrap();
            recursive.input.state_bytes = second_result.public_values().state.encode().unwrap().to_vec();
            recursive.verify_predecessor(&ContinuationReceipt(&public)).unwrap();
            let mut bad = recursive.clone();
            bad.initialization_environment[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone();
            let mut environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(&bad.input.environment).unwrap();
            environment.bond_identity = Some(crate::ecx_environment_v4::BondIdentity {
                configuration_hash: [19;32], asset_id: [19;32], deployment_commitment: [19;32],
                transition_cmr: [19;32], collateral_vault_script_sha256: [19;32],
                collateral_vault_cmr: [19;32], insurance_reserve_script_sha256: [19;32],
                insurance_reserve_cmr: [19;32],
            });
            bad.input.environment = environment.encode().unwrap();
            bad.input.binding.environment = environment.commitment().unwrap();
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone();
            bad.input.execution.parent.binding.parent.transition_program_id = [17;32];
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone();
            bad.initialization_parent.parent.reviewed_checkpoint_input_commitment[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.input.binding.execution.execution_policy[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.initialization_binding.genesis_bindings[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.predecessor_binding[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.predecessor_checkpoint[0] ^= 1;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.continuation_program = [17;32];
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.input.state_bytes = owned.state_bytes.clone();
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut bad = recursive.clone(); bad.recursive = false;
            assert!(bad.verify_predecessor(&ContinuationReceipt(&public)).is_err());
            let mut third_history = second.execution.history.clone();
            let (header, _) = crate::native_header_v3::NativeHeader::decode_prefix(
                &second.execution.raw_block, true).unwrap();
            third_history.push(header.encode(false,true).unwrap());
            let third_resume = NativeMatchResume { checkpoint: second_result.checkpoint().clone(),
                history: third_history, coin: second.successor_coin.clone() };
            let mut third_trade = second_trade.clone();
            third_trade.input[0].previous_output = second.successor_coin.outpoint;
            let (_, third_context, _, third_input) = build(&second_trade, &third_trade,
                &second_state, Some(&third_resume), None);
            let third_prepared = third_context.prepare_ecx_match_state(&second_state, bindings).unwrap();
            let mut third_state = third_prepared.clone(); third_state.matcher_sequence += 1;
            let mut journal = b"ECXMJ1".to_vec();
            journal.extend_from_slice(&third_prepared.digest().unwrap());
            journal.extend_from_slice(&elements::encode::serialize(&second.successor_coin.outpoint));
            journal.extend_from_slice(&third_state.encode().unwrap());
            recursive.input.execution = third_input.execution.clone();
            recursive.input.binding = third_input.binding.clone();
            recursive.input.native_binding_pin = third_input.binding.commitment().unwrap();
            recursive.input.environment = third_input.environment.encode().unwrap();
            recursive.input.journal = journal.clone();
            recursive.input.source_transaction = elements::encode::serialize(&second_trade);
            recursive.input.successor_transaction = elements::encode::serialize(&third_trade);
            recursive.input.coin = second.successor_coin.clone();
            recursive.input.successor_coin = third_input.execution.witnesses[1].utxo.creates[0].new_leaf.clone().unwrap();
            struct RecursiveReceipts<'a> { previous: &'a [u8], child: &'a [u8] }
            impl ConsensusProofVerifier for RecursiveReceipts<'_> {
                fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                    -> Result<(), ConsensusProofVerificationError> {
                    if (program == [16;32] && journal == self.previous && proof == b"native-fixture")
                        || (program == [14;32] && journal == self.child && proof == b"match-fixture") {
                        Ok(())
                    } else { Err(ConsensusProofVerificationError) }
                }
            }
            let p = &recursive.input.execution.parent;
            let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs([p,p,p]);
            let third_public = recursive.execute(&verifier, &DenySimplicity,
                &RecursiveReceipts { previous: &public, child: &journal }).unwrap();
            verifier.assert_consumed();
            assert_eq!(&third_public[..134], &public[..134]);
            let third_value = EcxNativeMatchPublicValuesV1::decode(&third_public[134..]).unwrap();
            assert_eq!(third_value.predecessor_checkpoint, second_result.public_values().successor_checkpoint);
            assert_eq!(third_value.state, third_state);
            assert_eq!(third_value.state.sidechain_height, 19);
            substituted = following.clone(); substituted.checkpoint_pin = full_pin;
            assert!(link(&substituted, [15;32], b"native-fixture").is_err());
            substituted = following.clone(); substituted.native_checkpoint = owned.native_checkpoint.clone();
            assert!(link(&substituted, [15;32], b"native-fixture").is_err());
            let consume = |program, proof: &[u8]| EcxNativeMatchPublicValuesV1::verify_receipt(
                executed.journal(), proof, &native_receipt, program, binding_pin, full_pin, full_next);
            assert_eq!(consume([15;32], b"native-fixture").unwrap(), decoded);
            assert!(consume([14;32], b"native-fixture").is_err()); // Wrong role.
            assert!(consume([0;32], b"native-fixture").is_err());
            assert!(consume([15;32], b"substituted").is_err());
            decoded.check_opening(binding_pin, full_pin, full_next).unwrap();
            assert!(decoded.check_opening([0;32], full_pin, full_next).is_err());
            assert!(decoded.check_opening(binding_pin, [0;32], full_next).is_err());
            assert!(decoded.check_opening(binding_pin, full_pin, &full_checkpoint).is_err());
            assert!(EcxNativeMatchPublicValuesV1::decode(&bytes).is_err()); // Child is not native outer.
            for length in [0, 6, 101, 411] {
                assert!(EcxNativeMatchPublicValuesV1::decode(&executed.journal()[..length]).is_err());
            }
            let mut extended = executed.journal().to_vec(); extended.push(0);
            assert!(EcxNativeMatchPublicValuesV1::decode(&extended).is_err());
            let mut wrong = *executed.journal(); wrong[5] = b'2';
            assert!(EcxNativeMatchPublicValuesV1::decode(&wrong).is_err());
            for range in [6..38, 38..70, 70..102, 108..140] {
                let mut wrong = *executed.journal(); wrong[range].fill(0);
                assert!(EcxNativeMatchPublicValuesV1::decode(&wrong).is_err());
            }
            let mut wrong = decoded.clone(); wrong.state.controlled_ecx_atoms += 1;
            assert!(wrong.check_opening(binding_pin, full_pin, full_next).is_err());
            let (_, expected_endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
                &native_input.execution.parent, native_input.binding.execution.parent_binding,
                &crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_input(&native_input.execution.parent)).unwrap();
            assert_eq!(full_next.bmm_endpoint.as_deref(), Some(expected_endpoint.as_slice()));
            assert_eq!(full_next.state.execution, *checked.child().next_checkpoint().unwrap());
            assert!(execute_full(&full_checkpoint, [0;32], binding_pin, &bytes).is_err());
            assert!(execute_full(&full_checkpoint, full_pin, [0;32], &bytes).is_err());
            let mut changed_anchor = full_checkpoint.clone();
            changed_anchor.bmm_endpoint.as_mut().unwrap()[0] ^= 1;
            assert!(execute_full(&changed_anchor, changed_anchor.commitment().unwrap(), binding_pin, &bytes).is_err());
            assert!(execute_full(&full_checkpoint, full_pin, binding_pin, &other_journal).is_err());
            // Structural transport tests only: these bytes are not a parent receipt.
            let anchored = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2 {
                state: continuity.clone(), bmm_endpoint: Some(vec![1;80]),
            };
            let anchor_pin = anchored.commitment().unwrap();
            anchored.require_frozen(anchor_pin).unwrap();
            assert_ne!(anchor_pin, frozen_continuity);
            assert!(anchored.require_frozen([0;32]).is_err());
            for index in [0, 32, 40, 48, 79] {
                let mut changed = anchored.clone();
                changed.bmm_endpoint.as_mut().unwrap()[index] ^= 1;
                assert!(changed.require_frozen(anchor_pin).is_err());
            }
            for endpoint in [None, Some(vec![1;79]), Some(vec![1;81]), Some(vec![0;80])] {
                let mut changed = anchored.clone(); changed.bmm_endpoint = endpoint;
                assert!(changed.commitment().is_err());
            }
            for range in [0..32, 48..80] {
                let mut changed = anchored.clone();
                changed.bmm_endpoint.as_mut().unwrap()[range].fill(0);
                assert!(changed.commitment().is_err());
            }
            let mut changed = anchored.clone(); changed.state.exchange_state_root[0] ^= 1;
            assert!(changed.require_frozen(anchor_pin).is_err());
            let advance = |record: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1, frozen| {
                context.advance_ecx_match_checkpoint(&checked, 1, record, frozen, pin,
                    bindings, economics, &bytes, b"match-fixture", &Receipt(&bytes),
                    &witness, membership(), post())
            };
            let (advanced, record) = advance(&continuity, frozen_continuity).unwrap();
            assert_eq!(advanced, next);
            assert_eq!(record.execution, *checked.child().next_checkpoint().unwrap());
            assert_eq!(record.exchange_state_root, next.digest().unwrap());
            assert_eq!(record.bindings_hash, continuity.bindings_hash);
            assert_eq!(record.vault_outpoint, elements::OutPoint::new(trade.txid(), 0));
            assert_ne!(record.commitment().unwrap(), frozen_continuity);
            assert!(advance(&record, record.commitment().unwrap()).is_err());
            assert!(advance(&continuity, [0;32]).is_err());
            let mut changed = continuity.clone(); changed.vault_outpoint.vout += 1;
            assert!(advance(&changed, frozen_continuity).is_err());
            assert!(advance(&changed, changed.commitment().unwrap()).is_err());
            let mut changed = continuity.clone(); changed.execution.height -= 1;
            assert!(advance(&changed, changed.commitment().unwrap()).is_err());
            let mut changed = continuity.clone(); changed.bindings_hash[0] ^= 1;
            assert!(advance(&changed, changed.commitment().unwrap()).is_err());
            let mut changed = continuity.clone(); changed.exchange_state_root[0] ^= 1;
            assert!(advance(&changed, changed.commitment().unwrap()).is_err());
            assert!(verify_executed_ecx_match_v1(&checked, 1, prepared.digest().unwrap(),
                &prepared, vault_coin.outpoint, bindings, economics, &other_journal,
                b"match-fixture", &Receipt(&other_journal), &witness, membership()).is_ok());
            assert!(context.verify_ecx_match(&checked, 1, pin, vault_coin.outpoint,
                bindings, economics, &other_journal, b"match-fixture",
                &Receipt(&other_journal), &witness, membership(), post()).is_err());
            assert!(verify_with_post(1, &trade, &bytes, b"match-fixture", &native_path,
                pin, membership()).is_err());
            let mut wrong_post = final_coin.clone(); wrong_post.creation_height -= 1;
            assert!(verify_with_post(1, &trade, &bytes, b"match-fixture", &native_path,
                pin, EcxCoinMembershipV1 { leaf: &wrong_post, path: &native_path }).is_err());
            let mut wrong_path = native_path.clone(); wrong_path.siblings[0].hash[0] ^= 1;
            assert!(verify_with_post(1, &trade, &bytes, b"match-fixture", &native_path,
                pin, EcxCoinMembershipV1 { leaf: &final_coin, path: &wrong_path }).is_err());
            for index in [0, 2, usize::MAX] {
                assert!(verify(index, &trade, &bytes, b"match-fixture", &native_path, pin).is_err());
            }
            assert!(verify(1, &trade, &bytes, b"wrong", &native_path, pin).is_err());
            assert!(verify(1, &trade, &bytes, b"match-fixture", &vp, pin).is_err());
            let mut wrong_state = state.clone(); wrong_state.accounts_root = [99;32];
            assert!(verify(1, &trade, &bytes, b"match-fixture", &native_path, &wrong_state).is_err());
            assert!(verify(1, &trade, &bytes, b"match-fixture", &native_path, &prepared).is_err());
            let mut altered = bytes.clone(); altered[100] ^= 1;
            assert!(verify(1, &trade, &altered, b"match-fixture", &native_path, pin).is_err());
            let mut altered = trade.clone(); altered.output[0] = output(99);
            assert!(verify(1, &altered, &bytes, b"match-fixture", &native_path, pin).is_err());
        }
        let check = |expected_root, tx: &elements::Transaction, deposit_path: &ElementsSparseUtxoPathV2| {
            let vault = EcxTradingVaultWitnessV1 {
                source_outpoint: vault_coin.outpoint, source_transaction: &source,
                successor_transaction: tx, successor_vout: 0,
                source_script_sha256: script_hash, successor_script_sha256: script_hash,
                prior_accounts: &prior_ledger, successor_accounts: &after_ledger,
            };
            verify_ecx_top_up_with_membership_v1(expected_root, root(&before), position.key(), economics,
                EcxAccountOpeningV1 { position: &position, cash: &before, siblings: &path }, &vault,
                EcxCoinMembershipV1 { leaf: &vault_coin, path: &vp }, funding_coin.outpoint, &source,
                EcxCoinMembershipV1 { leaf: &funding_coin, path: deposit_path }, 7)
        };
        assert_eq!(check(utxo, &successor, &dp).unwrap(), (root(&after), after.clone()));
        assert!(check(utxo, &successor, &vp).is_err());
        let spent = elements_sparse_utxo_root_from_path_v2(funding_coin.outpoint,
            canonical_empty_elements_utxo_leaf_v2(), &dp).unwrap();
        assert!(check(spent, &successor, &dp).is_err());
        let mut short_backing = successor.clone(); short_backing.output[0] = output(106);
        assert!(check(utxo, &short_backing, &dp).is_err());
        let mut missing_spend = successor.clone(); missing_spend.input.pop();
        assert!(check(utxo, &missing_spend, &dp).is_err());

        // Continue from the actual deposit successor: 107 backed atoms become
        // 106 plus the signed one-atom recipient output. Synthetic policy only.
        let withdrawal_coin = ElementsUtxoLeafV2 {
            outpoint: elements::OutPoint::new(successor.txid(), 0),
            output: successor.output[0].clone(), creation_height: 8,
            creation_parent_mtp: 101, coinbase: false,
            created_by_issuance: false, created_by_pegin: false,
        };
        let mut empty = canonical_empty_elements_utxo_leaf_v2();
        let mut siblings = Vec::new();
        for _ in 0..256 {
            siblings.push(empty);
            empty = elements_sparse_utxo_parent_v2(empty, empty).unwrap();
        }
        let coin_path = ElementsSparseUtxoPathV2 { siblings };
        let withdrawal_utxo = elements_sparse_utxo_root_from_path_v2(withdrawal_coin.outpoint,
            elements_utxo_leaf_node_v2(&withdrawal_coin), &coin_path).unwrap();
        let mut secret = [0;32]; secret[31] = 3;
        let signed = SignedEcxWithdrawalV1::sign(domain,
            ecx_protocol_core::successor_action_v2::SuccessorWithdrawalRequestV2 {
                version: 2, chain_id: domain.chain_id, trader: position.trader,
                nonce: 0, amount: 1, destination_script_hash: script_hash,
                requested_height: 8, not_before_height: 9,
            }, &bitcoin::secp256k1::SecretKey::from_slice(&secret).unwrap()).unwrap();
        let mut withdrawn_position = position.clone(); withdrawn_position.account_nonce = 1;
        let withdrawn_cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(106));
        let withdrawn_ledger = [(&withdrawn_position, &withdrawn_cash)];
        let withdrawal_tx = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn { previous_output: withdrawal_coin.outpoint, ..Default::default() }],
            output: vec![output(106), output(1)] };
        let mut empty_orders = ecx_protocol_core::hash::tagged_hash("ECX/ecx-order-index-empty/v1", &[]);
        for height in 1u16..=256 {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&height.to_be_bytes());
            bytes.extend_from_slice(&empty_orders);
            bytes.extend_from_slice(&empty_orders);
            empty_orders = ecx_protocol_core::hash::tagged_hash("ECX/ecx-order-index-node/v1", &bytes);
        }
        let withdraw = |utxo_root, tx: &elements::Transaction, height| {
            let vault = EcxTradingVaultWitnessV1 {
                source_outpoint: withdrawal_coin.outpoint, source_transaction: &successor,
                successor_transaction: tx, successor_vout: 0,
                source_script_sha256: script_hash, successor_script_sha256: script_hash,
                prior_accounts: &after_ledger, successor_accounts: &withdrawn_ledger,
            };
            verify_ecx_withdrawal_with_membership_v1(utxo_root, root(&after), economics,
                &signed, EcxAccountOpeningV1 { position: &position, cash: &after, siblings: &path },
                height, Price::new(30_000_000).unwrap(), Price::new(30_000_000).unwrap(), 0,
                &vault, EcxCoinMembershipV1 { leaf: &withdrawal_coin, path: &coin_path }, 1,
                ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: empty_orders, records: &[] })
        };
        let result = withdraw(withdrawal_utxo, &withdrawal_tx, 9).unwrap();
        assert_eq!(result.position, withdrawn_position);
        assert_eq!(result.cash, withdrawn_cash);
        assert_eq!(result.accounts_root, ecx_account_root(domain, &withdrawn_position,
            &withdrawn_cash, economics.bounds, &path).unwrap());
        if let Some(build) = builder {
            use ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1;
            use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
            let bindings = EcxSuccessorBindingsV1 {
                economic_configuration_hash: economics.digest().unwrap(),
                oracle_configuration_hash: [11;32], matcher_configuration_hash: [12;32],
                funding_oracle_program_id: [13;32], account_execution_program_id: [14;32],
                vault_policy_hash: [15;32],
            };
            let prior = EcxSuccessorStateV1 {
                bindings_hash: bindings.digest().unwrap(), accounts_root: root(&after),
                orders_root: empty_orders, funding_root: [17;32], funding_index: 0,
                open_interest: 0, matcher_sequence: 3, matcher_receipt_hash: [18;32],
                sidechain_height: 8, parent_hash: [19;32], parent_height: 1, parent_mtp: 1,
                controlled_ecx_atoms: 107, vault_script_sha256: script_hash,
            };
            let transition = |prepared: &EcxSuccessorStateV1| {
                let mut next = prepared.clone();
                next.accounts_root = result.accounts_root;
                next.controlled_ecx_atoms = 106;
                next
            };
            let (checked, context, _, input) = build(&successor, &withdrawal_tx,
                &prior, None, Some(&transition));
            let prepared = context.prepare_ecx_match_state(&prior, bindings).unwrap();
            let expected = transition(&prepared);
            assert_eq!(checked.child().foundation().native_header.exchange, expected.digest().unwrap());
            assert_eq!(expected.matcher_sequence, prior.matcher_sequence);
            assert_eq!(expected.matcher_receipt_hash, prior.matcher_receipt_hash);
            let spent = input.execution.witnesses[1].utxo.spends[0].old_leaf.as_ref().unwrap();
            let spent_path = &input.execution.witnesses[1].utxo.spends[0].path;
            let verify_native = |index, tx: &elements::Transaction, signature: &SignedEcxWithdrawalV1,
                supplied_root, membership_path: &ElementsSparseUtxoPathV2| {
                let vault = EcxTradingVaultWitnessV1 {
                    source_outpoint: withdrawal_coin.outpoint, source_transaction: &successor,
                    successor_transaction: tx, successor_vout: 0,
                    source_script_sha256: script_hash, successor_script_sha256: script_hash,
                    prior_accounts: &after_ledger, successor_accounts: &withdrawn_ledger,
                };
                verify_executed_ecx_withdrawal_v1(&checked,index,supplied_root,economics,signature,
                    EcxAccountOpeningV1 { position:&position,cash:&after,siblings:&path },
                    Price::new(30_000_000).unwrap(),Price::new(30_000_000).unwrap(),0,&vault,
                    EcxCoinMembershipV1 { leaf:spent,path:membership_path },1,
                    ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                        root:empty_orders,records:&[] })
            };
            assert_eq!(verify_native(1,&withdrawal_tx,&signed,prior.accounts_root,spent_path).unwrap(),result);
            for index in [0,2,usize::MAX] {
                assert!(verify_native(index,&withdrawal_tx,&signed,prior.accounts_root,spent_path).is_err());
            }
            assert!(verify_native(1,&withdrawal_tx,&signed,result.accounts_root,spent_path).is_err());
            let mut wrong_path = spent_path.clone(); wrong_path.siblings[0].hash[0] ^= 1;
            assert!(verify_native(1,&withdrawal_tx,&signed,prior.accounts_root,&wrong_path).is_err());
            let mut wrong_tx = withdrawal_tx.clone(); wrong_tx.output[1] = output(2);
            assert!(verify_native(1,&wrong_tx,&signed,prior.accounts_root,spent_path).is_err());
            let mut late_request = signed.request.clone();
            late_request.not_before_height = expected.sidechain_height + 1;
            let late = SignedEcxWithdrawalV1::sign(domain,late_request,
                &bitcoin::secp256k1::SecretKey::from_slice(&secret).unwrap()).unwrap();
            assert!(verify_native(1,&withdrawal_tx,&late,prior.accounts_root,spent_path).is_err());
            let creates = &input.execution.witnesses[1].utxo.creates;
            let final_vault = creates[0].new_leaf.as_ref().unwrap();
            let recipient = creates[1].new_leaf.as_ref().unwrap();
            let (root, vault_path, _) = crate::capital_genesis_utxos_v4::tests::pair_paths(final_vault,recipient);
            assert_eq!(root,checked.child().roots().utxo_root);
            check_coin(root,EcxCoinMembershipV1 { leaf:final_vault,path:&vault_path },
                final_vault.outpoint,&withdrawal_tx).unwrap();
            // Price/funding are synthetic here. The separate oracle wrapper
            // still needs this native fixture joined to authenticated inputs.
        }
        assert!(withdraw(empty, &withdrawal_tx, 9).is_err());
        assert!(withdraw(withdrawal_utxo, &withdrawal_tx, 8).is_err());
        let mut overpaid = withdrawal_tx.clone(); overpaid.output[1] = output(2);
        assert!(withdraw(withdrawal_utxo, &overpaid, 9).is_err());
        let mut unbacked = withdrawal_tx.clone(); unbacked.output[0] = output(107);
        assert!(withdraw(withdrawal_utxo, &unbacked, 9).is_err());
    }
    #[test]
    fn source_membership_binds_full_coin_and_rejects_spent_root() {
        let tx = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![], output: vec![elements::TxOut::default()] };
        let coin = ElementsUtxoLeafV2 {
            outpoint: elements::OutPoint::new(tx.txid(), 0), output: tx.output[0].clone(),
            creation_height: 7, creation_parent_mtp: 100, coinbase: false,
            created_by_issuance: false, created_by_pegin: false,
        };
        let mut empty = canonical_empty_elements_utxo_leaf_v2();
        let mut siblings = Vec::new();
        for _ in 0..256 { siblings.push(empty); empty = elements_sparse_utxo_parent_v2(empty, empty).unwrap(); }
        let path = ElementsSparseUtxoPathV2 { siblings };
        let root = elements_sparse_utxo_root_from_path_v2(coin.outpoint,
            elements_utxo_leaf_node_v2(&coin), &path).unwrap();
        let check = |r, c: &ElementsUtxoLeafV2, p: &ElementsSparseUtxoPathV2| check_coin(r,
            EcxCoinMembershipV1 { leaf: c, path: p }, coin.outpoint, &tx);
        check(root, &coin, &path).unwrap();
        assert!(check(empty, &coin, &path).is_err());
        for mutation in 0..5 {
            let mut bad = coin.clone();
            match mutation {
                0 => bad.creation_height += 1,
                1 => bad.creation_parent_mtp += 1,
                2 => bad.coinbase = true,
                3 => bad.output.script_pubkey = elements::Script::from(vec![0x51]),
                4 => bad.outpoint.txid = elements::Txid::from_byte_array([9; 32]),
                _ => unreachable!(),
            }
            assert!(check(root, &bad, &path).is_err());
        }
        let mut short = path.clone(); short.siblings.pop();
        assert!(check(root, &coin, &short).is_err());
        let mut wrong = root; wrong.aggregate.count += 1;
        assert!(check(wrong, &coin, &path).is_err());
    }
}
