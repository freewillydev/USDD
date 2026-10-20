//! Synthetic composition/codec tests. Test transcripts below are NOT proofs;
//! their unmined parent blocks and invented state are never live evidence.
use super::*;
use crate::{
    child_deployments_v3::{
        BuriedDeploymentsV3, ChildDeploymentConfigurationV3, ElementsVersionbitsV3,
    },
    conversion_parent_link_v3::tests::{parent_for_child_checkpoint, TranscriptVerifier},
    native_block_wire_v3::NativeBlock,
    native_withdrawal_accumulator_v3::{critical_hash_internal, WithdrawalAccumulator},
    FullAlphaAdapterErrorV3,
};
use ecx_full_consensus_validator_v2::elements_v2::*;
use elements::{BlockExtData, BlockHeader, Script};
use std::cell::Cell;

pub(crate) struct ExactTranscript {
    expected: Vec<(Hash32, Vec<u8>, Vec<u8>)>,
    calls: Cell<usize>,
}
impl ExactTranscript {
    pub(crate) fn for_input(input: &NativeConversionSourceInputV3) -> Self {
        let mut expected = vec![];
        for adapter in [&input.parent.parent, &input.observation] {
            expected.push((
                adapter.binding.checkpoint_program_id,
                adapter.checkpoint_receipt.public_values.clone(),
                adapter.checkpoint_receipt.proof_marker.clone(),
            ));
            expected.extend(adapter.transition_receipts.iter().map(|r| {
                (
                    adapter.binding.transition_program_id,
                    r.public_values.clone(),
                    r.proof_marker.clone(),
                )
            }));
        }
        expected.push((
            input.binding.child_execution_program_id,
            input.child_receipt.public_values.clone(),
            input.child_receipt.proof_marker.clone(),
        ));
        Self {
            expected,
            calls: Cell::new(0),
        }
    }
}
impl FullAlphaReceiptVerifierV3 for ExactTranscript {
    fn verify(
        &self,
        id: Hash32,
        journal: &[u8],
        marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let index = self.calls.get();
        self.calls.set(index + 1);
        if self.expected.get(index) != Some(&(id, journal.to_vec(), marker.to_vec())) {
            return Err(FullAlphaAdapterErrorV3::Receipt);
        }
        Ok(())
    }
}

#[test]
fn v5_observation_executes_parent_relations_before_releasing_child_height() {
    use crate::verified_child_observation_v5::*;
    use crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5;
    let mut input = fixture();
    let child = AlphaChildExecutionPublicValuesV3::from_canonical_bytes(
        &input.child_receipt.public_values).unwrap();
    input.child_receipt.public_values = AlphaChildExecutionPublicValuesV5(child)
        .canonical_bytes().to_vec();
    let mut policy = FrozenChildObservationPolicyV5 {
        program_id: input.binding.child_execution_program_id,
        source_binding: child.source_binding,
        predecessor_checkpoint: child.predecessor_checkpoint,
        parent_binding_commitment: input.parent.binding.commitment().unwrap(),
        minimum_parent_confirmations: 1,
    };
    let run = |policy: &FrozenChildObservationPolicyV5, bytes: &[u8], headers: &[Vec<u8>]| {
        verify_child_at_parent_observation_v5(policy, &input.parent,
            &input.observation, headers, bytes, &input.child_receipt.proof_marker,
            &ExactTranscript::for_input(&input))
    };
    let result = run(&policy, &input.child_receipt.public_values,
        &input.parent_continuation).unwrap();
    assert_eq!(result.child().height(), child.child_height);
    assert_eq!(result.parent().terminal_mtp, child.observation_time);
    let mut changed = input.child_receipt.public_values.clone();
    changed[140] ^= 1;
    assert!(run(&policy, &changed, &input.parent_continuation).is_err());
    assert!(run(&policy, &input.child_receipt.public_values, &[vec![0;80]]).is_err());
    policy.parent_binding_commitment[0] ^= 1;
    assert!(run(&policy, &input.child_receipt.public_values, &input.parent_continuation).is_err());
}

fn fixture() -> NativeConversionSourceInputV3 {
    let mut history = Vec::<NativeHeader>::new();
    for height in 0..7 {
        history.push(NativeHeader::from_standard(BlockHeader {
            version: 1,
            prev_blockhash: elements::BlockHash::from_byte_array(
                history
                    .last()
                    .map(|h| h.hash_internal().unwrap())
                    .unwrap_or([0; 32]),
            ),
            merkle_root: elements::TxMerkleNode::from_byte_array([17; 32]),
            time: 100 + height,
            height,
            ext: BlockExtData::Proof {
                challenge: Script::new(),
                solution: Script::new(),
            },
        }));
    }
    let predecessor = ChildExecutionCheckpointV3 {
        genesis_internal: history[0].hash_internal().unwrap(),
        configuration_commitment: [11; 32],
        tip_internal: history.last().unwrap().hash_internal().unwrap(),
        height: 6,
        history_commitment: child_history_commitment(&history).unwrap(),
        spent_claims_root: crate::native_claims_v3::empty_root(),
        withdrawals: WithdrawalAccumulator::empty(),
        roots: ElementsTransactionStateRootsV2 {
            utxo_root: ElementsSparseUtxoNodeV2 {
                hash: [12; 32],
                aggregate: ElementsUtxoAggregateV2 { count: 2 },
            },
            economic_root: ElementsSparseEconomicNodeV2 {
                hash: [13; 32],
                aggregate: ElementsEconomicAggregateV2 {
                    count: 2,
                    outstanding_base_atoms: 100_000_001,
                    redeemable_reserve_quote_atoms: 2,
                },
            },
        },
    };
    let seed_parent = parent_for_child_checkpoint(&predecessor, [1; 32]);
    let mut script = vec![0x6a, 37];
    script.extend_from_slice(b"ELMTP");
    script.extend_from_slice(&seed_parent.expected_parent_hash_internal);
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            script_sig: Script::from(vec![1, 7]),
            ..Default::default()
        }],
        output: vec![elements::TxOut {
            script_pubkey: Script::from(script),
            ..Default::default()
        }],
    };
    let native = NativeBlock {
        header: NativeHeader::from_standard(BlockHeader {
            version: 1,
            prev_blockhash: elements::BlockHash::from_byte_array(predecessor.tip_internal),
            merkle_root: elements_transaction_merkle_root_v2(&[tx.clone()]).unwrap(),
            time: 107,
            height: 7,
            ext: BlockExtData::Proof {
                challenge: Script::new(),
                solution: Script::new(),
            },
        }),
        transactions: vec![tx],
        bmm_proof: vec![],
    };
    let critical = critical_hash_internal(
        predecessor.genesis_internal,
        24,
        native.header.hash_internal().unwrap(),
        &predecessor.withdrawals,
        &predecessor.withdrawals,
    )
    .unwrap();
    let parent = parent_for_child_checkpoint(&predecessor, critical);
    let native_parent =
        execute_alpha_conversion_parent_link_v3(&parent, &TranscriptVerifier::for_input(&parent))
            .unwrap();
    let observation = crate::execute_full_alpha_adapter_v3(
        &parent.parent,
        &TranscriptVerifier::for_input(&parent),
    )
    .unwrap();
    let classification = ElementsEconomicClassificationV2 {
        base_asset_id: [7; 32],
        policy_asset_id: [8; 32],
        redemption_inventory_script_sha256: [9; 32],
        reserve_script_sha256: [10; 32],
    };
    let versionbits = ElementsVersionbitsV3 {
        bit: 0,
        start: -2,
        timeout: i64::MAX,
        min_activation_height: 0,
        period: 10,
        threshold: 8,
    };
    let execution_policy = ChildExecutionPolicyV3 {
        genesis_internal: predecessor.genesis_internal,
        consensus_configuration_commitment: predecessor.configuration_commitment,
        deployments: ChildDeploymentConfigurationV3 {
            buried: BuriedDeploymentsV3 {
                height_in_coinbase: 0,
                strict_der: 0,
                cltv: 0,
                csv: 0,
                segwit: 0,
            },
            taproot: versionbits,
            dynafed: versionbits,
            simplicity: versionbits,
            bip16_exception_internal: [0; 32],
            usdd_sp1_annex: true,
        },
        reward: crate::native_reward_v3::RewardParameters {
            subsidy_asset: elements::AssetId::from_slice(&classification.base_asset_id).unwrap(),
            genesis_subsidy: 0,
            halving_interval: 210000,
        },
        classification,
        header_policy_commitment: [14; 32],
    };
    let deposit_configuration = AlphaDepositConfigurationV3 {
        pegged_asset_internal: classification.base_asset_id,
        minimum_depth: 1,
        p2pkh_prefix: 235,
        p2sh_prefix: 75,
        blinded_prefix: 4,
        bech_hrp: "ert".into(),
        blech_hrp: "el".into(),
    };
    let accounting = ConversionAccountingBindingV3 {
        child_genesis_internal: predecessor.genesis_internal,
        child_configuration_commitment: predecessor.configuration_commitment,
        classification,
        quote_atoms_per_whole_base: 1,
    };
    let binding = NativeConversionSourceBindingV3 {
        child_execution_program_id: [4; 32],
        parent: parent.binding,
        predecessor_checkpoint: predecessor.commitment().unwrap(),
        execution_policy: execution_policy.commitment().unwrap(),
        simplicity_evaluator_program_id: [1; 32],
        deposit_configuration: deposit_configuration.commitment().unwrap(),
        accounting_binding: accounting.commitment().unwrap(),
        clock_policy: NativeSourceClockPolicyV3::ParentObservationMtp,
        minimum_parent_confirmations: 1,
        maximum_child_age_seconds: 2_000_000_000,
    };
    let predecessor_history = history
        .iter()
        .map(|h| h.encode(false, true).unwrap())
        .collect();
    history.push(native.header.clone());
    let successor = ChildExecutionCheckpointV3 {
        height: 7,
        tip_internal: native.header.hash_internal().unwrap(),
        history_commitment: child_history_commitment(&history).unwrap(),
        ..predecessor.clone()
    };
    let child = AlphaChildExecutionPublicValuesV3 {
        source_binding: binding.child_binding().unwrap().commitment().unwrap(),
        predecessor_checkpoint: predecessor.commitment().unwrap(),
        next_checkpoint: successor.commitment().unwrap(),
        child_hash_internal: successor.tip_internal,
        child_height: 7,
        observation_time: observation.terminal_mtp,
        parent: native_parent,
    };
    NativeConversionSourceInputV3 {
        version: NATIVE_CONVERSION_SOURCE_VERSION_V3,
        binding,
        child_receipt: AlphaRecursiveReceiptBindingV3 {
            public_values: child.canonical_bytes().to_vec(),
            proof_marker: vec![0x7e],
        },
        observation: parent.parent.clone(),
        parent,
        parent_continuation: vec![],
        predecessor,
        successor,
        predecessor_history,
        raw_child_block: native.encode().unwrap(),
        execution_policy,
        deposit_configuration,
        accounting,
    }
}

fn run(
    input: &NativeConversionSourceInputV3,
) -> Result<NativeConversionSourcePublicValuesV3, NativeConversionSourceErrorV3> {
    execute_native_conversion_source_v3(
        input,
        input.binding.commitment()?,
        &ExactTranscript::for_input(input),
    )
}
fn update_child(
    input: &mut NativeConversionSourceInputV3,
    edit: impl FnOnce(&mut AlphaChildExecutionPublicValuesV3),
) {
    let mut child =
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&input.child_receipt.public_values)
            .unwrap();
    edit(&mut child);
    input.child_receipt.public_values = child.canonical_bytes().to_vec();
}

#[test]
fn native_source_binds_exact_execution_accounting_and_rounding() {
    let input = fixture();
    let transcript = ExactTranscript::for_input(&input);
    let output = execute_native_conversion_source_v3(
        &input,
        input.binding.commitment().unwrap(),
        &transcript,
    )
    .unwrap();
    assert_eq!(transcript.calls.get(), transcript.expected.len());
    assert_eq!(output.accounting.required_reserve_quote_atoms, 2);
    assert_eq!(output.accounting.outstanding_base_atoms, 100_000_001);
    assert_eq!(
        output.accounting.child_checkpoint_commitment,
        output.child.next_checkpoint
    );
    assert_eq!(output.child_mtp, 104);
    assert_eq!(output.parent_confirmations, 1);
    assert_eq!(output.child.observation_time, output.observation_mtp);
    assert_eq!(output.canonical_bytes().len(), 676);
    assert_eq!(
        NativeConversionSourcePublicValuesV3::from_canonical_bytes(&output.canonical_bytes())
            .unwrap(),
        output
    );
    assert!(output.require_frozen_source([0; 32]).is_err());
    let observation = crate::execute_full_alpha_adapter_v3(
        &input.observation, &TranscriptVerifier::for_input(&input.parent)).unwrap();
    let check = |observation: &FullAlphaStatementV3, successor: &ChildExecutionCheckpointV3,
        accounting: &ConversionAccountingBindingV3| output.require_conversion_preimages(
            &input.binding, input.binding.commitment().unwrap(), observation, successor, accounting);
    assert_eq!(check(&observation, &input.successor, &input.accounting), Ok(()));
    // Exact transport transcript is deliberately synthetic, not a live proof.
    let source_id = [11;32];
    let receipt = AlphaRecursiveReceiptBindingV3 {
        public_values: output.canonical_bytes().to_vec(), proof_marker: vec![42],
    };
    let verify = |receipt: &AlphaRecursiveReceiptBindingV3, id: Hash32| {
        let verifier = ExactTranscript { expected: vec![(source_id,
            output.canonical_bytes().to_vec(), vec![42])], calls: Cell::new(0) };
        verify_native_conversion_source_receipt_v3(receipt, id,
            input.binding.commitment().unwrap(), &input.binding, &observation,
            &input.successor, &input.accounting, &verifier)
    };
    assert_eq!(verify(&receipt, source_id), Ok(output));
    assert!(verify(&receipt, input.binding.child_execution_program_id).is_err());
    assert!(verify(&receipt, [0;32]).is_err());
    assert!(verify(&receipt, [12;32]).is_err());
    let mut wrong_proof = receipt.clone(); wrong_proof.proof_marker = vec![43];
    assert!(verify(&wrong_proof, source_id).is_err());
    let mut missing_proof = receipt.clone(); missing_proof.proof_marker.clear();
    assert!(verify(&missing_proof, source_id).is_err());
    let mut altered_observation = observation;
    altered_observation.terminal_tip_hash_internal = [99;32];
    assert!(check(&altered_observation, &input.successor, &input.accounting).is_err());
    let mut altered_checkpoint = input.successor.clone();
    altered_checkpoint.history_commitment = [99;32];
    assert!(check(&observation, &altered_checkpoint, &input.accounting).is_err());
    let mut altered_accounting = input.accounting;
    altered_accounting.quote_atoms_per_whole_base += 1;
    assert!(check(&observation, &input.successor, &altered_accounting).is_err());
    let encoded = encode_native_conversion_source_input_v3(&input).unwrap();
    assert_eq!(
        decode_native_conversion_source_input_v3(&encoded).unwrap(),
        input
    );
    assert!(decode_native_conversion_source_input_v3(&encoded[..encoded.len() - 1]).is_err());
    let mut extra = encoded;
    extra.push(0);
    assert!(decode_native_conversion_source_input_v3(&extra).is_err());
    assert!(execute_native_conversion_source_v3(
        &input,
        [99; 32],
        &ExactTranscript::for_input(&input)
    )
    .is_err());
}

#[test]
fn checkpoint_lineage_requires_exact_receipts_and_reviewed_endpoints() {
    use crate::native_checkpoint_lineage_v3::*;
    let input=fixture();
    let output=run(&input).unwrap();
    let observation=crate::execute_full_alpha_adapter_v3(&input.observation,
        &TranscriptVerifier::for_input(&input.parent)).unwrap();
    let receipt=AlphaRecursiveReceiptBindingV3 {
        public_values:output.canonical_bytes().to_vec(),proof_marker:vec![42],
    };
    let source_id=[11;32];
    let mut terminal=input.binding.clone();
    terminal.predecessor_checkpoint=output.child.next_checkpoint;
    let bindings=[input.binding.clone()];
    let check=|initial, terminal_hash, receipts: &[NativeCheckpointLineageStepV3<'_>],
        bindings: &[NativeConversionSourceBindingV3]| {
        let verifier=ExactTranscript { expected:vec![(source_id,
            receipt.public_values.clone(),receipt.proof_marker.clone())],calls:Cell::new(0) };
        verify_native_checkpoint_lineage_v3(source_id,initial,terminal_hash,bindings,
            receipts,&terminal,&input.accounting,&verifier)
    };
    let step=|receipt| NativeCheckpointLineageStepV3 {
        receipt,observation:&observation,successor:&input.successor,
    };
    let initial=input.binding.predecessor_checkpoint;
    let end=output.child.next_checkpoint;
    assert_eq!(check(initial,end,&[step(&receipt)],&bindings),Ok(()));
    assert_eq!(check(end,end,&[],&[]),Ok(()));
    assert_eq!(check(initial,end,&[],&[]),Err(NativeCheckpointLineageErrorV3::Continuity));
    assert_eq!(check(initial,end,&[],&bindings),Err(NativeCheckpointLineageErrorV3::Shape));
    assert_eq!(check([0;32],end,&[],&[]),Err(NativeCheckpointLineageErrorV3::Shape));
    assert_eq!(check([99;32],end,&[step(&receipt)],&bindings),Err(NativeCheckpointLineageErrorV3::Binding));
    let mut altered=receipt.clone(); altered.proof_marker.clear();
    assert_eq!(check(initial,end,&[step(&altered)],&bindings),Err(NativeCheckpointLineageErrorV3::Receipt));
    let mut altered=receipt.clone(); altered.public_values[440]^=1;
    assert_eq!(check(initial,end,&[step(&altered)],&bindings),Err(NativeCheckpointLineageErrorV3::Receipt));
    let mut altered=bindings.clone(); altered[0].deposit_configuration=[99;32];
    assert_eq!(check(initial,end,&[step(&receipt)],&altered),Err(NativeCheckpointLineageErrorV3::Binding));
}

#[test]
fn strict_child_parent_and_source_abis_reject_substitution_trailing_and_zero_fields() {
    let input = fixture();
    let wire = input.child_receipt.public_values.clone();
    let decoded = AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&wire).unwrap();
    assert_eq!(decoded.canonical_bytes().as_slice(), wire);
    assert_eq!(&wire[129..133], &7u32.to_be_bytes());
    assert_eq!(&wire[133..141], &decoded.observation_time.to_be_bytes());
    for length in 0..wire.len() {
        assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&wire[..length]).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&extra).is_err());
    for offset in [0, 141, 142, 143] {
        let mut changed = wire.clone();
        changed[offset] ^= 1;
        assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&changed).is_err());
    }
    for start in [1, 33, 65, 97, 175, 207, 239, 271, 303, 335, 367] {
        let mut changed = wire.clone();
        changed[start..start + 32].fill(0);
        assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&changed).is_err());
    }
    let output = run(&input).unwrap();
    let wire = output.canonical_bytes();
    for length in [0, 275, 285, 407, 675] {
        assert!(
            NativeConversionSourcePublicValuesV3::from_canonical_bytes(&wire[..length]).is_err()
        );
    }
    for offset in [0, 33, 660] {
        let mut changed = wire;
        changed[offset] ^= 1;
        assert!(NativeConversionSourcePublicValuesV3::from_canonical_bytes(&changed).is_err());
    }
}

#[test]
fn independent_binding_checkpoint_clock_parent_and_material_mutations_reject() {
    let input = fixture();
    for mutation in 0..24 {
        let mut changed = input.clone();
        match mutation {
            0 => changed.execution_policy.classification.base_asset_id = [99; 32],
            1 => changed.accounting.classification.reserve_script_sha256 = [99; 32],
            2 => changed.accounting.child_genesis_internal = [99; 32],
            3 => changed.deposit_configuration.minimum_depth += 1,
            4 => {
                changed
                    .predecessor
                    .roots
                    .economic_root
                    .aggregate
                    .outstanding_base_atoms += 1
            }
            5 => changed.successor.roots.utxo_root.hash = [99; 32],
            6 => changed.successor.spent_claims_root = [99; 32],
            7 => changed.successor.genesis_internal = [99; 32],
            8 => changed.successor.configuration_commitment = [99; 32],
            9 => changed.successor.withdrawals.append([99; 32]).unwrap(),
            10 => changed.predecessor_history[0][0] ^= 1,
            11 => changed.raw_child_block[0] ^= 1,
            12 => update_child(&mut changed, |c| c.observation_time += 1),
            13 => update_child(&mut changed, |c| c.source_binding = [99; 32]),
            14 => update_child(&mut changed, |c| {
                c.parent.parent_predecessor_hash_internal = c.parent.parent_block_hash_internal
            }),
            15 => update_child(&mut changed, |c| {
                c.parent.m7_critical_hash_internal = [99; 32]
            }),
            16 => update_child(&mut changed, |c| c.parent.m7_coinbase_vout += 1),
            17 => update_child(&mut changed, |c| {
                c.parent.parent_terminal_state_commitment = [99; 32]
            }),
            18 => changed.observation.binding.transition_program_id = [99; 32],
            19 => changed.binding.minimum_parent_confirmations = 2,
            20 => changed.binding.maximum_child_age_seconds = 1,
            21 => {
                changed.binding.child_execution_program_id =
                    changed.binding.simplicity_evaluator_program_id
            }
            22 => changed.parent_continuation.push(vec![0; 80]),
            _ => changed.parent.expected_parent_hash_internal = [99; 32],
        }
        assert!(run(&changed).is_err(), "mutation {mutation} accepted");
    }
    // Even a separately re-frozen accounting preimage cannot reinterpret the
    // execution's classification, nor may a new policy reinterpret old state.
    let mut changed = input.clone();
    changed.accounting.classification.reserve_script_sha256 = [99; 32];
    changed.binding.accounting_binding = changed.accounting.commitment().unwrap();
    assert_eq!(run(&changed), Err(NativeConversionSourceErrorV3::Binding));
    let mut changed = input.clone();
    changed
        .execution_policy
        .classification
        .reserve_script_sha256 = [99; 32];
    changed.binding.execution_policy = changed.execution_policy.commitment().unwrap();
    assert_eq!(run(&changed), Err(NativeConversionSourceErrorV3::Binding));
}

#[test]
fn exact_receipt_is_required_and_accounting_is_not_invented_from_balances() {
    let input = fixture();
    let verifier = ExactTranscript::for_input(&input);
    let mut changed = input.clone();
    changed.child_receipt.proof_marker.push(1);
    assert_eq!(
        execute_native_conversion_source_v3(
            &changed,
            changed.binding.commitment().unwrap(),
            &verifier
        ),
        Err(NativeConversionSourceErrorV3::ChildReceipt)
    );
    for (supply, reserve, expected) in [
        (0, 2, ConversionAccountingErrorV3::EmptySupply),
        (
            100_000_001,
            1,
            ConversionAccountingErrorV3::InsufficientReserve,
        ),
    ] {
        let mut changed = input.clone();
        changed
            .successor
            .roots
            .economic_root
            .aggregate
            .outstanding_base_atoms = supply;
        changed
            .successor
            .roots
            .economic_root
            .aggregate
            .redeemable_reserve_quote_atoms = reserve;
        let commitment = changed.successor.commitment().unwrap();
        update_child(&mut changed, |c| c.next_checkpoint = commitment);
        assert_eq!(
            run(&changed),
            Err(NativeConversionSourceErrorV3::Accounting(expected))
        );
    }
}

#[test]
fn finality_requires_q_ancestry_not_merely_matching_height() {
    let input = fixture();
    let parent =
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&input.child_receipt.public_values)
            .unwrap()
            .parent;
    let mut observed = crate::execute_full_alpha_adapter_v3(
        &input.observation,
        &TranscriptVerifier::for_input(&input.parent),
    )
    .unwrap();
    let mut header =
        bitcoin::consensus::deserialize::<bitcoin::Block>(&input.parent.terminal_parent_block)
            .unwrap()
            .header;
    header.prev_blockhash = bitcoin::BlockHash::from_byte_array(parent.parent_block_hash_internal);
    header.time += 1;
    observed.terminal_selected_height += 1;
    observed.terminal_tip_hash_internal = header.block_hash().to_byte_array();
    let headers = vec![bitcoin::consensus::serialize(&header)];
    assert_eq!(verify_continuation(&parent, &observed, &headers, 2), Ok(2));
    assert!(verify_continuation(&parent, &observed, &headers, 3).is_err());
    let mut wrong = headers.clone();
    wrong[0][4] ^= 1;
    assert!(verify_continuation(&parent, &observed, &wrong, 2).is_err());
    observed.terminal_tip_hash_internal = [99; 32];
    assert!(verify_continuation(&parent, &observed, &headers, 2).is_err());
}
