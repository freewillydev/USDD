//! Context-bound Alpha evaluator receipt consumer. Not the legacy v1 or a7
//! journal. The enclosing child relation must derive each context from its
//! authenticated state; accepting witness-provided contexts is not sound.
use crate::{Hash32, sha256_bytes, elements_v2::*};
use std::cell::Cell;

pub const ALPHA_ECX_EXECUTION_JOURNAL_VERSION: u8 = 0xa8;

/// Shared native anchor codec. Presence is explicit: genesis absence is not an
/// all-zero fabricated endpoint. The caller must authenticate chain membership.
/// Present endpoints preserve the existing producer's commitment exactly.
pub fn alpha_prior_anchor_commitment_v4(endpoint: Option<&[u8]>)
    -> Result<Hash32, ElementsStateErrorV2> {
    let (domain, payload) = match endpoint {
        Some(bytes) if bytes.len() == 80
            && bytes[..32] != [0; 32] && bytes[48..] != [0; 32] =>
            (b"ECX/alpha-native-evaluator-prior-anchor/v3".as_slice(), bytes),
        None => (b"ECX/alpha-native-evaluator-prior-anchor-absent/v4".as_slice(), &[][..]),
        _ => return Err(ElementsStateErrorV2::AuthorizationConsensus),
    };
    let tag = sha256_bytes(domain);
    let mut bytes = Vec::with_capacity(64 + payload.len());
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(payload);
    Ok(sha256_bytes(&bytes))
}

/// Preserved structural codec shared by evaluator producers and child consumers.
/// This is not authentication: callers must derive the four context hashes from
/// checked state and costs from the actual input. The native closure is bound
/// separately by `alpha_native_evaluator_binding_v4`.
pub fn alpha_structural_evaluator_binding_v3(
    parent_binding: Hash32, child_genesis_internal: Hash32,
    prior_child_checkpoint: Hash32, prior_anchor_commitment: Hash32,
    minimum_cost: u64, budget: u64,
) -> Result<Hash32, ElementsStateErrorV2> {
    let hashes = [parent_binding, child_genesis_internal,
        prior_child_checkpoint, prior_anchor_commitment];
    if hashes.contains(&[0; 32]) || budget == 0 || minimum_cost > budget
        || budget > i64::MAX as u64 {
        return Err(ElementsStateErrorV2::AuthorizationConsensus);
    }
    // Historical recovered source identity is part of the existing v3 codec.
    const SOURCE: Hash32 = [
        0xcc,0xfc,0x3e,0x24,0x98,0x73,0x3f,0xb6,0x3f,0x73,0x51,0x6a,0x45,0xf0,0x49,0xf7,
        0xe6,0xeb,0x31,0xdc,0xc7,0x4b,0x6f,0x7d,0xad,0x5c,0x66,0xba,0x73,0x99,0x93,0x01,
    ];
    let tag = sha256_bytes(b"ECX/alpha-native-evaluator-binding/v3");
    let mut bytes = Vec::with_capacity(241);
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&tag);
    bytes.push(0xa7);
    for hash in hashes { bytes.extend_from_slice(&hash); }
    bytes.extend_from_slice(&SOURCE);
    bytes.extend_from_slice(&minimum_cost.to_be_bytes());
    bytes.extend_from_slice(&budget.to_be_bytes());
    Ok(sha256_bytes(&bytes))
}

/// Current Alpha parameterized-controller rule, not a caller-selected limit.
/// Native CheckSimplicity passes minimum cost zero and the consensus serialized
/// size of the *entire original* script witness plus VALIDATION_WEIGHT_OFFSET.
/// The parameterized controller profile does not grant the legacy SP1 credit.
/// This derives costs only; witness shape, script and annex validation remain
/// mandatory in the enclosing execution relation.
pub fn alpha_simplicity_cost_limits_v4(
    transaction: &elements::Transaction, input_index: usize,
) -> Result<(u64, u64), ElementsStateErrorV2> {
    fn compact_size_length(n: u64) -> u64 {
        match n { 0..=252 => 1, 253..=65535 => 3, 65536..=4294967295 => 5, _ => 9 }
    }
    let fail = || ElementsStateErrorV2::AuthorizationConsensus;
    let stack = &transaction.input.get(input_index).ok_or_else(fail)?.witness.script_witness;
    let count = u64::try_from(stack.len()).map_err(|_| fail())?;
    let mut budget = compact_size_length(count).checked_add(50).ok_or_else(fail)?;
    for item in stack {
        let length = u64::try_from(item.len()).map_err(|_| fail())?;
        budget = budget.checked_add(compact_size_length(length))
            .and_then(|value| value.checked_add(length)).ok_or_else(fail)?;
    }
    if budget > i64::MAX as u64 { return Err(fail()); }
    Ok((0, budget))
}

/// Shared native evaluator identity codec. Both inputs must be independently
/// pinned by the enclosing relation; hashing witness claims is not authority.
/// The structural binding includes parent/genesis/checkpoint/cost settings.
pub fn alpha_native_evaluator_binding_v4(
    structural_binding: Hash32, source_closure: Hash32,
) -> Result<Hash32, ElementsStateErrorV2> {
    if structural_binding == [0; 32] || source_closure == [0; 32] {
        return Err(ElementsStateErrorV2::AuthorizationConsensus);
    }
    let tag = sha256_bytes(b"ECX/alpha-ecx-native-evaluator-binding/v4");
    let mut bytes = Vec::with_capacity(129);
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&tag);
    bytes.push(ALPHA_ECX_EXECUTION_JOURNAL_VERSION);
    bytes.extend_from_slice(&structural_binding);
    bytes.extend_from_slice(&source_closure);
    Ok(sha256_bytes(&bytes))
}

/// Hashes of the independently authenticated evaluator binding, Alpha parent
/// public statement and canonical ECXENV1 environment, respectively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlphaExecutionContextV3 {
    pub evaluator_binding: Hash32,
    pub parent_statement: Hash32,
    pub ecx_environment: Hash32,
}

impl AlphaExecutionContextV3 {
    fn validate(self) -> Result<(), ElementsStateErrorV2> {
        if [self.evaluator_binding, self.parent_statement, self.ecx_environment]
            .contains(&[0; 32]) {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(())
    }
}

/// Shared producer/consumer codec. Includes the complete transaction, prevout,
/// genesis, program, witness and annex commitment from the existing input codec.
pub fn alpha_execution_journal_v3(
    input: &ElementsSimplicityExecutionV2<'_>,
    context: AlphaExecutionContextV3,
) -> Result<[u8; 33], ElementsStateErrorV2> {
    context.validate()?;
    let tx = elements_simplicity_execution_public_values_v2(input)?.canonical_bytes();
    let mut preimage = b"ECX/alpha-context-simplicity-execution/v3".to_vec();
    preimage.push(ALPHA_ECX_EXECUTION_JOURNAL_VERSION);
    preimage.extend_from_slice(&context.evaluator_binding);
    preimage.extend_from_slice(&context.parent_statement);
    preimage.extend_from_slice(&context.ecx_environment);
    preimage.extend_from_slice(&tx);
    let mut journal = [0; 33];
    journal[0] = ALPHA_ECX_EXECUTION_JOURNAL_VERSION;
    journal[1..].copy_from_slice(&sha256_bytes(&preimage));
    Ok(journal)
}

/// One independently derived context and one verified receipt per script call,
/// in transaction/input order. No legacy receipt fallback is provided.
pub struct AlphaSimplicityReceiptExecutorV3<'a, V> {
    program_id: Hash32,
    contexts: &'a [AlphaExecutionContextV3],
    receipts: &'a [ElementsSimplicityReceiptBindingV2],
    verifier: &'a V,
    next: Cell<usize>,
}

impl<'a, V> AlphaSimplicityReceiptExecutorV3<'a, V> {
    pub fn new(
        program_id: Hash32, contexts: &'a [AlphaExecutionContextV3],
        receipts: &'a [ElementsSimplicityReceiptBindingV2], verifier: &'a V,
    ) -> Result<Self, ElementsStateErrorV2> {
        if program_id == [0; 32] || contexts.len() != receipts.len()
            || receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2
            || receipts.iter().any(|r| r.public_values.len() != 33
                || r.public_values.first() != Some(&ALPHA_ECX_EXECUTION_JOURNAL_VERSION)
                || r.proof_marker.is_empty()
                || r.proof_marker.len() > MAX_ELEMENTS_SIMPLICITY_PROOF_MARKER_BYTES_V2) {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        for context in contexts { context.validate()?; }
        Ok(Self { program_id, contexts, receipts, verifier, next: Cell::new(0) })
    }

    pub fn require_all_receipts_consumed(&self) -> Result<(), ElementsStateErrorV2> {
        if self.next.get() != self.receipts.len() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(())
    }
}

impl<V: ElementsSimplicityReceiptVerifierV2> ElementsSimplicityExecutorV2
    for AlphaSimplicityReceiptExecutorV3<'_, V> {
    fn execute(&self, input: &ElementsSimplicityExecutionV2<'_>) -> Result<(), ElementsStateErrorV2> {
        let index = self.next.get();
        let receipt = self.receipts.get(index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        if receipt.public_values != alpha_execution_journal_v3(input, self.contexts[index])? {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        self.verifier.verify(self.program_id, &receipt.public_values, &receipt.proof_marker)?;
        self.next.set(index + 1);
        Ok(())
    }
}

/// Block-wide authenticated inputs, excluding the input-specific cost binding.
/// Construction alone grants no authority: the child must obtain these values
/// from its checked predecessor, parent relation and frozen program policy.
#[derive(Clone, Copy, Debug)]
pub struct AlphaEvaluatorScopeV4 {
    pub parent_binding: Hash32,
    pub child_genesis_internal: Hash32,
    pub prior_child_checkpoint: Hash32,
    pub prior_anchor_commitment: Hash32,
    pub source_closure: Hash32,
    pub parent_statement: Hash32,
    pub ecx_environment: Hash32,
}

impl AlphaEvaluatorScopeV4 {
    fn validate(&self) -> Result<(), ElementsStateErrorV2> {
        if [self.parent_binding, self.child_genesis_internal,
            self.prior_child_checkpoint, self.prior_anchor_commitment,
            self.source_closure, self.parent_statement, self.ecx_environment]
            .contains(&[0; 32]) {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(())
    }

    pub fn context_for_input(&self, input: &ElementsSimplicityExecutionV2<'_>)
        -> Result<AlphaExecutionContextV3, ElementsStateErrorV2> {
        use elements::hashes::Hash;
        self.validate()?;
        if input.genesis_hash.to_byte_array() != self.child_genesis_internal {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let (minimum_cost, budget) = alpha_simplicity_cost_limits_v4(
            input.transaction, input.input_index)?;
        let structural = alpha_structural_evaluator_binding_v3(
            self.parent_binding, self.child_genesis_internal,
            self.prior_child_checkpoint, self.prior_anchor_commitment,
            minimum_cost, budget)?;
        Ok(AlphaExecutionContextV3 {
            evaluator_binding: alpha_native_evaluator_binding_v4(structural, self.source_closure)?,
            parent_statement: self.parent_statement,
            ecx_environment: self.ecx_environment,
        })
    }
}

/// Derives the binding at each actual script invocation. Unlike the V3 array
/// adapter, this cannot repeat one caller-selected cost binding for a block.
/// Receipt ordering, exact journals and cryptographic verification are retained.
pub struct AlphaSimplicityReceiptExecutorV4<'a, V> {
    program_id: Hash32,
    scope: AlphaEvaluatorScopeV4,
    receipts: &'a [ElementsSimplicityReceiptBindingV2],
    verifier: &'a V,
    next: Cell<usize>,
}

impl<'a, V> AlphaSimplicityReceiptExecutorV4<'a, V> {
    pub fn new(program_id: Hash32, scope: AlphaEvaluatorScopeV4,
        receipts: &'a [ElementsSimplicityReceiptBindingV2], verifier: &'a V)
        -> Result<Self, ElementsStateErrorV2> {
        scope.validate()?;
        if program_id == [0; 32] || receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2
            || receipts.iter().any(|r| r.public_values.len() != 33
                || r.public_values.first() != Some(&ALPHA_ECX_EXECUTION_JOURNAL_VERSION)
                || r.proof_marker.is_empty()
                || r.proof_marker.len() > MAX_ELEMENTS_SIMPLICITY_PROOF_MARKER_BYTES_V2) {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(Self { program_id, scope, receipts, verifier, next: Cell::new(0) })
    }

    pub fn require_all_receipts_consumed(&self) -> Result<(), ElementsStateErrorV2> {
        if self.next.get() != self.receipts.len() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(())
    }
}

impl<V: ElementsSimplicityReceiptVerifierV2> ElementsSimplicityExecutorV2
    for AlphaSimplicityReceiptExecutorV4<'_, V> {
    fn execute(&self, input: &ElementsSimplicityExecutionV2<'_>) -> Result<(), ElementsStateErrorV2> {
        let index = self.next.get();
        let receipt = self.receipts.get(index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        let context = self.scope.context_for_input(input)?;
        if receipt.public_values != alpha_execution_journal_v3(input, context)? {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        self.verifier.verify(self.program_id, &receipt.public_values, &receipt.proof_marker)?;
        self.next.set(index + 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use elements::{BlockHash, Transaction, TxIn, TxOut, LockTime};
    struct Reject;

    #[test]
    fn anchor_presence_and_exact_native_encoding_are_distinct() {
        let endpoint = [1u8; 80];
        let present = alpha_prior_anchor_commitment_v4(Some(&endpoint)).unwrap();
        let absent = alpha_prior_anchor_commitment_v4(None).unwrap();
        assert_ne!(present, absent);
        assert_ne!(absent, [0; 32]);
        for length in [0, 32, 79, 81] {
            assert!(alpha_prior_anchor_commitment_v4(Some(&vec![1; length])).is_err());
        }
        for range in [0..32, 48..80] {
            let mut wrong = endpoint;
            wrong[range].fill(0);
            assert!(alpha_prior_anchor_commitment_v4(Some(&wrong)).is_err());
        }
        for index in 0..80 {
            let mut changed = endpoint;
            changed[index] ^= 1;
            assert_ne!(alpha_prior_anchor_commitment_v4(Some(&changed)).unwrap(), present);
        }
    }

    #[test]
    fn dynamic_receipts_derive_each_budget_and_do_not_advance_on_failure() {
        // Synthetic dispatch verifier only; this test does not generate a proof.
        struct Exact { calls: Cell<usize> }
        impl ElementsSimplicityReceiptVerifierV2 for Exact {
            fn verify(&self, id: Hash32, _: &[u8], marker: &[u8]) -> Result<(), ElementsStateErrorV2> {
                if id != [9;32] || marker != [7] {
                    return Err(ElementsStateErrorV2::AuthorizationConsensus);
                }
                self.calls.set(self.calls.get() + 1);
                Ok(())
            }
        }
        let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()], output: vec![] };
        tx.input[0].witness.script_witness = vec![vec![1;10]];
        tx.input[1].witness.script_witness = vec![vec![1;253]];
        let prevouts = [TxOut::default(), TxOut::default()];
        let mut input = ElementsSimplicityExecutionV2 { transaction: &tx, input_index: 0,
            previous_outputs: &prevouts, genesis_hash: BlockHash::from_byte_array([2;32]),
            committed_cmr: [8;32], program: &[1], witness: &[], annex: None };
        let scope = AlphaEvaluatorScopeV4 { parent_binding: [1;32], child_genesis_internal: [2;32],
            prior_child_checkpoint: [3;32], prior_anchor_commitment: [4;32],
            source_closure: [5;32], parent_statement: [6;32], ecx_environment: [7;32] };
        let first_context = scope.context_for_input(&input).unwrap();
        let first = alpha_execution_journal_v3(&input, first_context).unwrap();
        input.input_index = 1;
        let second_context = scope.context_for_input(&input).unwrap();
        assert_ne!(first_context.evaluator_binding, second_context.evaluator_binding);
        let second = alpha_execution_journal_v3(&input, second_context).unwrap();
        let receipts = [first, second].map(|j| ElementsSimplicityReceiptBindingV2 {
            public_values: j.to_vec(), proof_marker: vec![7] });
        let verifier = Exact { calls: Cell::new(0) };
        let executor = AlphaSimplicityReceiptExecutorV4::new([9;32], scope, &receipts, &verifier).unwrap();
        assert!(executor.execute(&input).is_err()); // Wrong order.
        assert_eq!(verifier.calls.get(), 0);
        input.input_index = 0;
        executor.execute(&input).unwrap();
        assert!(executor.require_all_receipts_consumed().is_err());
        input.input_index = 1;
        executor.execute(&input).unwrap();
        executor.require_all_receipts_consumed().unwrap();
        assert_eq!(verifier.calls.get(), 2);
        assert!(executor.execute(&input).is_err());

        let stale = [ElementsSimplicityReceiptBindingV2 {
            public_values: alpha_execution_journal_v3(&input, first_context).unwrap().to_vec(),
            proof_marker: vec![7] }];
        let stale_executor = AlphaSimplicityReceiptExecutorV4::new([9;32], scope, &stale, &verifier).unwrap();
        assert!(stale_executor.execute(&input).is_err());
        assert!(stale_executor.require_all_receipts_consumed().is_err());
        let second_only = [receipts[1].clone()];
        let reject = AlphaSimplicityReceiptExecutorV4::new([9;32], scope, &second_only, &Reject).unwrap();
        assert!(reject.execute(&input).is_err());
        assert!(reject.require_all_receipts_consumed().is_err());
        input.genesis_hash = BlockHash::from_byte_array([99;32]);
        assert!(scope.context_for_input(&input).is_err());
        input.genesis_hash = BlockHash::from_byte_array([2;32]);
        input.input_index = 2;
        assert!(scope.context_for_input(&input).is_err());
        for field in 0..7 {
            let mut missing = scope;
            match field { 0 => missing.parent_binding = [0;32],
                1 => missing.child_genesis_internal = [0;32],
                2 => missing.prior_child_checkpoint = [0;32],
                3 => missing.prior_anchor_commitment = [0;32],
                4 => missing.source_closure = [0;32],
                5 => missing.parent_statement = [0;32],
                _ => missing.ecx_environment = [0;32] }
            assert!(AlphaSimplicityReceiptExecutorV4::new([9;32], missing, &[], &Reject).is_err());
        }
    }

    #[test]
    fn alpha_costs_match_consensus_witness_serialization_without_legacy_credit() {
        let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()], output: vec![] };
        // Exercise both CompactSize item-count and byte-length boundaries.
        // These are codec vectors, not valid script execution fixtures.
        for stack in [vec![], vec![vec![]], vec![vec![1;252]],
            vec![vec![1;253]], vec![vec![2;65535]], vec![vec![2;65536]],
            vec![vec![];252], vec![vec![];253],
            vec![vec![1;4], vec![2;7], vec![3;32], vec![4;33], vec![0x50;10]]] {
            tx.input[0].witness.script_witness = stack;
            let expected = elements::encode::serialize(&tx.input[0].witness.script_witness).len() as u64 + 50;
            assert_eq!(alpha_simplicity_cost_limits_v4(&tx, 0).unwrap(), (0, expected));
        }
        let original = alpha_simplicity_cost_limits_v4(&tx, 0).unwrap();
        // Annex is included; pegin witness and output proofs are not part of
        // the native script-witness budget.
        tx.input[0].witness.pegin_witness = vec![vec![8;1000]];
        assert_eq!(alpha_simplicity_cost_limits_v4(&tx, 0).unwrap(), original);
        tx.input[0].witness.script_witness.pop();
        assert_eq!(alpha_simplicity_cost_limits_v4(&tx, 0).unwrap().1, original.1 - 11);
        assert!(alpha_simplicity_cost_limits_v4(&tx, 1).is_err());
        assert!(alpha_simplicity_cost_limits_v4(&tx, usize::MAX).is_err());
    }
    impl ElementsSimplicityReceiptVerifierV2 for Reject {
        fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(), ElementsStateErrorV2> {
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        }
    }
    #[test]
    fn binds_context_and_rejects_old_receipts_and_failed_proofs() {
        let tx = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()], output: vec![] };
        let prevouts = [TxOut::default()];
        let input = ElementsSimplicityExecutionV2 { transaction: &tx, input_index: 0,
            previous_outputs: &prevouts, genesis_hash: BlockHash::from_byte_array([1;32]),
            committed_cmr: [2;32], program: &[1], witness: &[], annex: None };
        let context = AlphaExecutionContextV3 { evaluator_binding: [3;32],
            parent_statement: [4;32], ecx_environment: [5;32] };
        let journal = alpha_execution_journal_v3(&input, context).unwrap();
        for field in 0..3 {
            let mut changed = context;
            match field { 0 => changed.evaluator_binding[0] ^= 1,
                1 => changed.parent_statement[0] ^= 1, _ => changed.ecx_environment[0] ^= 1 }
            assert_ne!(journal, alpha_execution_journal_v3(&input, changed).unwrap());
        }
        let contexts = [context];
        let receipts = [ElementsSimplicityReceiptBindingV2 { public_values: journal.to_vec(), proof_marker: vec![1] }];
        let executor = AlphaSimplicityReceiptExecutorV3::new([1;32], &contexts, &receipts, &Reject).unwrap();
        assert!(executor.execute(&input).is_err());
        assert!(executor.require_all_receipts_consumed().is_err());
        for old_version in [1, 0xa7] {
            let mut old = receipts.clone();
            old[0].public_values[0] = old_version;
            assert!(AlphaSimplicityReceiptExecutorV3::new([1;32], &contexts, &old, &Reject).is_err());
        }
        assert!(AlphaSimplicityReceiptExecutorV3::new([1;32], &[], &receipts, &Reject).is_err());
    }
}
