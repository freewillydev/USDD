//! Synthetic boundary tests: expected transcript matching is NOT a proof and
//! these deliberately unmined blocks are never advertised as live replay.
use super::*;
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use ecx_full_consensus_validator_v2::bip300_v2::alpha_bip300_v3::AlphaBip300AllSlotStateV3;
use ecx_full_consensus_validator_v2::bip300_v2::Bip300ActiveSlotV2;
use ecx_full_consensus_validator_v2::checkpoint_alpha_v3::{
    encode_reviewed_alpha_checkpoint_input_v3, ReviewedAlphaCheckpointInputV3,
    REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3,
};
use ecx_full_consensus_validator_v2::state_frontier_v2::{
    apply_executed_frontier_mutation_v2, canonical_empty_executed_frontier_path_v2,
    canonical_empty_executed_frontier_root_v2, BitcoinExecutedFrontierMutationV2,
};
use std::cell::Cell;

// Wire tag from bip300_v2::M7_TAG and native d1617368 coinbase commitment.
const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];

#[test]
fn custody_six_acks_do_not_require_m6_or_change_parent_rules() {
    let custody = [31;32];
    let checkpoint = [32;32];
    let bundle = CustodyAckBundleV3 {transaction_version:2,lock_time:0,fee_sat:1000,
        checkpoint_commitment:custody_checkpoint_approval_commitment_v2(custody,checkpoint).unwrap()};
    let mut history = Vec::new();
    let mined = approve_checkpoint_after_fixture(fixture(),custody,checkpoint,|s| history.push(s.clone()));
    assert_eq!(bundle.compute_txid(),mined.approval().m6id);
    let authenticate = |step: &AlphaConversionParentLinkInputV3, candidate: &CustodyAckBundleV3| {
        authenticate_custody_acks_v3(&step.binding,step.binding.commitment().unwrap(),&step.parent,
            &step.terminal_parent_predecessor,&step.terminal_parent_block,candidate,
            &TranscriptVerifier::for_input(step))
    };
    for acks in 0..=7 {
        // Deposit, then M3 with score 1, then one M4 per block.
        let step = &history[1+acks];
        assert_eq!(step.parent.terminal_selected_state.bip300_state.as_state()
            .active_slots[&24].pending_m6ids[0].score,1+acks as u16);
        assert_eq!(authenticate(step,&bundle).is_ok(),acks >= 6);
        let block: Block = deserialize(&step.terminal_parent_block).unwrap();
        assert_eq!(block.txdata.len(),1); // no withdrawal transaction is mined
    }
    let step = &history[7];
    let approval = authenticate(step,&bundle).unwrap();
    assert!(approval.approval().early_acks);
    approval.require_checkpoint_approval(step.binding.commitment().unwrap(),custody,checkpoint).unwrap();
    assert!(approval.require_checkpoint_approval(step.binding.commitment().unwrap(),[42;32],checkpoint).is_err());
    assert!(approval.require_checkpoint_approval(step.binding.commitment().unwrap(),custody,[42;32]).is_err());
    for field in 0..4 {
        let mut wrong = bundle.clone();
        match field {0 => wrong.fee_sat += 1,1 => wrong.lock_time += 1,
            2 => wrong.transaction_version += 1,_ => wrong.checkpoint_commitment[0] ^= 1}
        assert!(authenticate(step,&wrong).is_err());
    }
    let mut bad_receipt = step.clone();
    bad_receipt.parent.transition_receipts.last_mut().unwrap().proof_marker.push(99);
    assert!(authenticate_custody_acks_v3(&step.binding,step.binding.commitment().unwrap(),
        &bad_receipt.parent,&step.terminal_parent_predecessor,&step.terminal_parent_block,&bundle,
        &TranscriptVerifier::for_input(step)).is_err());
    // A reorg to a pre-six-ack state cannot satisfy the gate. Neither can an
    // expired bundle or a bundle moved to another slot, even at a high score.
    assert!(authenticate(&history[6],&bundle).is_err());
    let mut state = step.parent.terminal_selected_state.clone();
    let mut slots = state.bip300_state.as_state().clone();
    let slot = slots.active_slots.remove(&24).unwrap();
    slots.active_slots.insert(25,slot);
    slots.previous_effective_m4.clear();
    state.bip300_state = AlphaBip300AllSlotStateV3::from_authenticated_state(slots).unwrap();
    assert!(require_custody_ack_score(&state,bundle.compute_txid()).is_err());
    let confirmed = CustodyApprovalConfirmationsV2::new(approval);
    let extend = |next: &AlphaConversionParentLinkInputV3| extend_custody_approval_confirmation_v2(
        &confirmed,&next.binding,&next.parent,&next.terminal_parent_predecessor,
        &next.terminal_parent_block,&TranscriptVerifier::for_input(next));
    assert!(extend(&history[8]).is_ok());
    // Alarm lowers the score; later descendants must not inherit stale approval.
    let alarm = successor_with_messages_fixture(step,
        &[ScriptBuf::from_bytes(vec![0x6a,6,0xd7,0x7d,0x17,0x76,1,0xfe])],&[]);
    assert!(extend(&alarm).is_err());
    assert!(authenticate(history.last().unwrap(),&bundle).is_err()); // consumed M6 no longer pending
    let witness = crate::custody_history_wire_v2::CustodyHistoryWitnessV2 {
        version:crate::custody_history_wire_v2::CUSTODY_HISTORY_VERSION_V2,
        steps:history[..8].to_vec(),approval_index:7,approval_transaction:bundle.compute_txid(),
        approval_bundle:Some(bundle),
    };
    use crate::custody_history_wire_v2::{encode_custody_history_v2,decode_custody_history_v2};
    let bytes = encode_custody_history_v2(&witness).unwrap();
    assert_eq!(decode_custody_history_v2(&bytes).unwrap(),witness);
    let mut old = bytes.clone(); old[0] = 0xb2;
    assert!(decode_custody_history_v2(&old).is_err());
    let mut mismatch = witness; mismatch.approval_transaction = bitcoin::Txid::all_zeros();
    assert!(encode_custody_history_v2(&mismatch).is_err());
}

/// Synthetic discovery transcript with actual BIP300 successor replay. Not a
/// mined block or a cryptographic parent receipt; preserves the initial binding.
pub(crate) fn successor_fixture(input: &AlphaConversionParentLinkInputV3) -> AlphaConversionParentLinkInputV3 {
    successor_with_messages_fixture(input,&[],&[])
}

pub(crate) fn successor_with_messages_fixture(input: &AlphaConversionParentLinkInputV3,
    messages: &[ScriptBuf], transactions: &[Transaction]) -> AlphaConversionParentLinkInputV3 {
    let mut next = input.clone();
    next.terminal_parent_predecessor = input.parent.terminal_selected_state.clone();
    let mut block: Block = deserialize(&input.terminal_parent_block).unwrap();
    block.txdata.truncate(1);
    block.txdata[0].output = vec![TxOut {value:Amount::ZERO,script_pubkey:ScriptBuf::from_bytes(vec![0x51])}];
    block.txdata[0].output.extend(messages.iter().cloned().map(|script_pubkey| TxOut {value:Amount::ZERO,script_pubkey}));
    block.txdata.extend_from_slice(transactions);
    block.header.prev_blockhash = next.terminal_parent_predecessor.tip.block_hash;
    block.header.time += 600;
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let mut terminal = next.terminal_parent_predecessor.clone();
    terminal.tip.height += 1;
    terminal.tip.discovery_sequence += 1;
    for byte in terminal.tip.chainwork_be.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1); *byte = value;
        if !carry { break; }
    }
    terminal.tip.block_hash = block.block_hash();
    terminal.pow_context.previous_height += 1;
    terminal.pow_context.previous_header = block.header;
    terminal.pow_context.previous_11_times.remove(0);
    terminal.pow_context.previous_11_times.push(block.header.time);
    terminal.bip300_state = apply_alpha_bip300_block_v3(
        &next.terminal_parent_predecessor.bip300_state,&block).unwrap().0;
    let prior = decode_full_alpha_transition_public_values_v3(
        &input.parent.transition_receipts.last().unwrap().public_values).unwrap();
    let sequence = prior.final_discovery_sequence.checked_add(1).unwrap();
    let transition = FullAlphaTransitionPublicValuesV3 {
        predecessor_state_commitment: prior.successor_state_commitment,
        predecessor_height: prior.successor_height,
        predecessor_frontier_commitment: prior.successor_frontier_commitment,
        predecessor_event_stream_commitment: prior.successor_event_stream_commitment,
        successor_state_commitment: terminal.commitment().unwrap(),
        successor_height: terminal.tip.height,
        successor_tip_hash_internal: terminal.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: [34;32],successor_event_stream_commitment:[35;32],
        first_discovery_sequence:sequence,final_discovery_sequence:sequence,..prior
    };
    next.parent.transition_receipts.push(AlphaRecursiveReceiptBindingV3 {
        public_values:transition.canonical_bytes().to_vec(),proof_marker:vec![3] });
    next.parent.terminal_selected_state = terminal;
    next.terminal_parent_block = serialize(&block);
    next
}

pub(crate) struct TranscriptVerifier {
    expected: Vec<(Hash32, Vec<u8>, Vec<u8>)>,
    calls: Cell<usize>,
}

/// Exercise proposal/votes/approval after an existing burn anchor. Real BIP300
/// rules, but synthetic parent receipt transcripts and unmined transactions.
pub(crate) fn approve_checkpoint_after_fixture(mut input: AlphaConversionParentLinkInputV3,
    custody:Hash32, checkpoint:Hash32, mut visit:impl FnMut(&AlphaConversionParentLinkInputV3),
) -> AuthenticatedCustodyM6V2 {
    assert!(input.parent.terminal_selected_state.bip300_state.as_state().active_slots[&24].ctip.is_none());
    let deposit = Transaction { version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,
        input:vec![TxIn {previous_output:OutPoint {txid:bitcoin::Txid::from_byte_array([7;32]),vout:1},
            script_sig:ScriptBuf::new(),sequence:Sequence::MAX,witness:Witness::new()}],
        output:vec![TxOut {value:Amount::from_sat(10000),script_pubkey:ScriptBuf::from_bytes(vec![0xb4,1,24,0x51])},
            TxOut {value:Amount::ZERO,script_pubkey:ScriptBuf::from_bytes(vec![0x6a,1,0x61])}] };
    input = successor_with_messages_fixture(&input,&[],&[deposit.clone()]); visit(&input);
    let mut marker = b"\x6a\x27USDDM6\x02".to_vec();
    marker.extend_from_slice(&custody_checkpoint_approval_commitment_v2(custody,checkpoint).unwrap());
    let withdrawal = Transaction {version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,
        input:vec![TxIn {previous_output:OutPoint {txid:deposit.compute_txid(),vout:0},
            script_sig:ScriptBuf::new(),sequence:Sequence::MAX,witness:Witness::new()}],
        output:vec![TxOut {value:Amount::from_sat(9000),script_pubkey:ScriptBuf::from_bytes(vec![0xb4,1,24,0x51])},
            TxOut {value:Amount::ZERO,script_pubkey:ScriptBuf::from_bytes(marker.clone())}] };
    let mut blinded = vec![2,0,0,0,0,2];
    blinded.extend_from_slice(&0u64.to_le_bytes());blinded.extend_from_slice(&[10,0x6a,8]);
    blinded.extend_from_slice(&1000u64.to_be_bytes());blinded.extend_from_slice(&0u64.to_le_bytes());
    blinded.push(41);blinded.extend_from_slice(&marker);blinded.extend_from_slice(&[0;4]);
    let mut id_display = bitcoin::hashes::sha256d::Hash::hash(&blinded).to_byte_array();id_display.reverse();
    let mut proposal = vec![0x6a,37,0xd4,0x5a,0xa9,0x43,24];proposal.extend_from_slice(&id_display);
    input = successor_with_messages_fixture(&input,&[ScriptBuf::from_bytes(proposal)],&[]);visit(&input);
    let parameters = input.parent.terminal_selected_state.bip300_state.as_state().consensus_parameters;
    assert_eq!(input.parent.terminal_selected_state.bip300_state.as_state().active_slots[&24].pending_m6ids[0].score,1);
    for _ in 0..parameters.withdrawal_inclusion_threshold {
        input = successor_with_messages_fixture(&input,&[ScriptBuf::from_bytes(vec![0x6a,6,0xd7,0x7d,0x17,0x76,1,0])],&[]);
        visit(&input);
    }
    assert_eq!(input.parent.terminal_selected_state.bip300_state.as_state().consensus_parameters,parameters);
    input = successor_with_messages_fixture(&input,&[],&[withdrawal.clone()]);visit(&input);
    authenticate_custody_m6_v2(&input.binding,input.binding.commitment().unwrap(),&input.parent,
        &input.terminal_parent_predecessor,&input.terminal_parent_block,withdrawal.compute_txid(),
        &TranscriptVerifier::for_input(&input)).unwrap()
}
impl TranscriptVerifier {
    pub(crate) fn first_occurrences(mut self) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        self.expected.retain(|entry| seen.insert(entry.clone()));
        self
    }
    pub(crate) fn for_inputs<'a>(inputs: impl IntoIterator<Item = &'a AlphaConversionParentLinkInputV3>) -> Self {
        Self { expected: inputs.into_iter().flat_map(|input| Self::for_input(input).expected).collect(),
            calls: Cell::new(0) }
    }
    pub(crate) fn assert_consumed(&self) {
        assert_eq!(self.calls.get(), self.expected.len());
    }
    pub(crate) fn for_input(input: &AlphaConversionParentLinkInputV3) -> Self {
        let mut expected = vec![(
            input.parent.binding.checkpoint_program_id,
            input.parent.checkpoint_receipt.public_values.clone(),
            input.parent.checkpoint_receipt.proof_marker.clone(),
        )];
        expected.extend(input.parent.transition_receipts.iter().map(|r| {
            (
                input.parent.binding.transition_program_id,
                r.public_values.clone(),
                r.proof_marker.clone(),
            )
        }));
        Self {
            expected,
            calls: Cell::new(0),
        }
    }
}
impl FullAlphaReceiptVerifierV3 for TranscriptVerifier {
    fn verify(
        &self,
        program: Hash32,
        journal: &[u8],
        marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let index = self.calls.get();
        self.calls.set(index + 1);
        if self.expected.get(index) == Some(&(program, journal.to_vec(), marker.to_vec())) {
            Ok(())
        } else {
            Err(FullAlphaAdapterErrorV3::Receipt)
        }
    }
}

fn parent_adapter(
    predecessor: &AlphaExecutedConsensusStateV3,
    terminal: AlphaExecutedConsensusStateV3,
) -> FullAlphaAdapterInputV3 {
    let path = canonical_empty_executed_frontier_path_v2();
    let frontier = apply_executed_frontier_mutation_v2(
        canonical_empty_executed_frontier_root_v2(),
        &BitcoinExecutedFrontierMutationV2 {
            candidate: predecessor.frontier_tip().unwrap(),
            insert: true,
            path: path.clone(),
        },
    )
    .unwrap();
    let checkpoint = ReviewedAlphaCheckpointInputV3 {
        version: REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3,
        source_configuration_commitment: predecessor.source_configuration_commitment,
        selected_state: predecessor.clone(),
        frontier,
        selected_membership_path: path,
        event_stream_commitment: [31; 32],
        event_sequence: 0,
    };
    let values = execute_reviewed_alpha_checkpoint_v3(&checkpoint).unwrap();
    let transition = FullAlphaTransitionPublicValuesV3 {
        source_configuration_commitment: values.source_configuration_commitment,
        predecessor_state_commitment: values.selected_state_commitment,
        predecessor_height: values.selected_height,
        predecessor_frontier_commitment: values.frontier_commitment,
        predecessor_event_stream_commitment: values.event_stream_commitment,
        successor_state_commitment: terminal.commitment().unwrap(),
        successor_height: terminal.tip.height,
        successor_tip_hash_internal: terminal.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: [32; 32],
        successor_event_stream_commitment: [33; 32],
        step_count: 1,
        first_discovery_sequence: 1,
        final_discovery_sequence: 1,
    };
    FullAlphaAdapterInputV3 {
        version: FULL_ALPHA_ADAPTER_INPUT_VERSION_V3,
        binding: AlphaRecursiveBindingV3 {
            source_configuration_commitment: values.source_configuration_commitment,
            reviewed_checkpoint_input_commitment: values.checkpoint_input_commitment,
            checkpoint_program_id: [2; 32],
            transition_program_id: [3; 32],
        },
        checkpoint_input: encode_reviewed_alpha_checkpoint_input_v3(&checkpoint).unwrap(),
        checkpoint_receipt: AlphaRecursiveReceiptBindingV3 {
            public_values: values.canonical_bytes().to_vec(),
            proof_marker: vec![1],
        },
        transition_receipts: vec![AlphaRecursiveReceiptBindingV3 {
            public_values: transition.canonical_bytes().to_vec(),
            proof_marker: vec![2],
        }],
        terminal_selected_state: terminal,
    }
}

fn fixture() -> AlphaConversionParentLinkInputV3 {
    let mut predecessor = crate::tests::synthetic_state();
    predecessor.tip.height = ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 100;
    predecessor.pow_context.previous_height = predecessor.tip.height;
    let mut slots = predecessor.bip300_state.as_state().clone();
    slots.next_height = predecessor.tip.height + 1;
    slots.active_slots.insert(
        24,
        Bip300ActiveSlotV2 {
            proposal_hash: [42; 32],
            activation_height: ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
            ctip: None,
            next_treasury_sequence: 0,
            pending_m6ids: vec![],
        },
    );
    predecessor.bip300_state = AlphaBip300AllSlotStateV3::from_authenticated_state(slots).unwrap();
    // An opaque, non-palindromic M7 commitment; NOT a claimed child preimage.
    let critical: Hash32 = std::array::from_fn(|i| (i + 1) as u8);
    let mut critical_display = critical;
    critical_display.reverse();
    let mut payload = M7_TAG.to_vec();
    payload.push(24);
    payload.extend_from_slice(&critical_display);
    let mut script = vec![0x6a, 37];
    script.extend_from_slice(&payload);
    let coinbase = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    };
    let mut block = Block {
        header: predecessor.pow_context.previous_header,
        txdata: vec![coinbase],
    };
    block.header.prev_blockhash = predecessor.tip.block_hash;
    block.header.time += 600;
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let (slots, _) = apply_alpha_bip300_block_v3(&predecessor.bip300_state, &block).unwrap();
    let mut terminal = predecessor.clone();
    terminal.tip.height += 1;
    terminal.tip.block_hash = block.block_hash();
    terminal.tip.discovery_sequence = 1;
    terminal.tip.chainwork_be[31] += 1;
    terminal.pow_context.previous_height += 1;
    terminal.pow_context.previous_header = block.header;
    terminal.pow_context.previous_11_times.remove(0);
    terminal
        .pow_context
        .previous_11_times
        .push(block.header.time);
    terminal.bip300_state = slots;
    let parent = parent_adapter(&predecessor, terminal);
    AlphaConversionParentLinkInputV3 {
        version: ALPHA_CONVERSION_PARENT_LINK_VERSION_V3,
        purpose: AlphaConversionPurposeV3::ParentBmmLinkOnly,
        binding: AlphaConversionLinkBindingV3 {
            parent: parent.binding,
            child_consensus_configuration_commitment: [40; 32],
            child_genesis_hash_internal: [43; 32],
            child_checkpoint_hash_internal: [41; 32],
            child_checkpoint_height: 63,
            slot24_proposal_hash: [42; 32],
            slot24_activation_height: ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
        },
        parent,
        expected_parent_hash_internal: predecessor.tip.block_hash.to_byte_array(),
        expected_critical_hash_internal: critical,
        terminal_parent_predecessor: predecessor,
        terminal_parent_block: serialize(&block),
        candidate_child_block: vec![],
    }
}

fn run(
    input: &AlphaConversionParentLinkInputV3,
) -> Result<AlphaConversionParentLinkPublicValuesV3, AlphaConversionLinkErrorV3> {
    execute_alpha_conversion_parent_link_v3(input, &TranscriptVerifier::for_input(input))
}

#[test]
fn usdd_m6_approval_requires_real_replay_effect_without_m7() {
    use ecx_full_consensus_validator_v2::bip300_v2::{Bip300CtipV2, Bip300PendingM6idV2};
    let mut input = fixture();
    let (child_tx, child_genesis) = crate::native_withdrawal_extraction_v3::tests::fixture();
    let empty = crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty();
    let (child_state, claims) = crate::native_withdrawal_extraction_v3::apply_withdrawals(
        &[child_tx.clone()], child_genesis, &empty).unwrap();
    let mut child_display = child_genesis; child_display.reverse();
    let root = crate::native_withdrawal_extraction_v3::UsddRootTransitionV1 {
        parent_genesis_display: [1;32], elements_genesis_display: child_display,
        asset_display: claims[0].asset_display, vault: claims[0].vault, prior_count: 0,
        prior_root: empty.root, next_count: child_state.count, next_root: child_state.root,
    };
    let mut marker = b"\x6a\x27USDDM6\x01".to_vec(); marker.extend_from_slice(&root.commitment());
    let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([7;32]), vout: 0 };
    let tx = Transaction { version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(8999), script_pubkey: ScriptBuf::from_bytes(vec![0xb4,1,24,0x51]) },
            TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(marker) }] };
    // Independent exact non-witness blinded M6 serialization (fee 1000).
    let mut blinded = vec![2,0,0,0,0,2];
    blinded.extend_from_slice(&0u64.to_le_bytes()); blinded.extend_from_slice(&[10,0x6a,8]);
    blinded.extend_from_slice(&1000u64.to_be_bytes());
    blinded.extend_from_slice(&1u64.to_le_bytes()); blinded.push(41);
    blinded.extend_from_slice(tx.output[1].script_pubkey.as_bytes()); blinded.extend_from_slice(&[0;4]);
    let m6id = bitcoin::Txid::from_byte_array(bitcoin::hashes::sha256d::Hash::hash(&blinded).to_byte_array());
    let mut slots = input.terminal_parent_predecessor.bip300_state.as_state().clone();
    let height = slots.next_height;
    let slot = slots.active_slots.get_mut(&24).unwrap();
    slot.ctip = Some(Bip300CtipV2 {outpoint, value_sat:10000, sequence:0});
    slot.next_treasury_sequence = 1;
    slot.pending_m6ids.push(Bip300PendingM6idV2 {m6id, proposal_height:height-1, score:73});
    input.terminal_parent_predecessor.bip300_state = AlphaBip300AllSlotStateV3::from_authenticated_state(slots).unwrap();
    let mut block: Block = deserialize(&input.terminal_parent_block).unwrap();
    block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
    block.txdata.push(tx.clone()); refresh_parent(&mut input, block);
    let frozen = input.binding.commitment().unwrap();
    let call = |id, binding| authenticate_usdd_m6_v3(&input.binding, binding, &input.parent,
        &input.terminal_parent_predecessor, &input.terminal_parent_block, id, &TranscriptVerifier::for_input(&input));
    let result = call(tx.compute_txid(), frozen).unwrap();
    assert_eq!(result.marker(), root.commitment());
    assert_eq!(authenticate_custody_m6_v2(&input.binding, frozen, &input.parent,
        &input.terminal_parent_predecessor, &input.terminal_parent_block,
        tx.compute_txid(), &TranscriptVerifier::for_input(&input)), Err(AlphaConversionLinkErrorV3::M6Approval));
    assert_eq!(result.verify_root_preimage(&root), Ok(()));
    let mut path = vec![claims[1].leaf];
    let mut empty_leaf = bitcoin::hashes::sha256::Hash::hash(&[0]).to_byte_array();
    for _ in 0..63 {
        let mut preimage = vec![1]; preimage.extend_from_slice(&empty_leaf);
        preimage.extend_from_slice(&empty_leaf);
        empty_leaf = bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array();
        path.push(empty_leaf);
    }
    let check = |r: &crate::native_withdrawal_extraction_v3::UsddRootTransitionV1,
        first, output, asset, vault, branch: &[Hash32]| result.verify_introduced_claim(
            r, &child_tx, child_genesis, first, output, [1;32], asset, vault, branch);
    assert_eq!(check(&root, 0, 0, root.asset_display, root.vault, &path).unwrap(), claims[0]);
    assert!(check(&root, 1, 0, root.asset_display, root.vault, &path).is_err());
    assert!(check(&root, 0, 1, root.asset_display, root.vault, &path).is_err());
    assert!(check(&root, 0, 0, [9;32], root.vault, &path).is_err());
    assert!(check(&root, 0, 0, root.asset_display, [9;32], &path).is_err());
    assert!(check(&root, 0, 0, root.asset_display, root.vault, &path[..63]).is_err());
    let mut unapproved = root.clone(); unapproved.next_root[0] ^= 1;
    assert!(check(&unapproved, 0, 0, root.asset_display, root.vault, &path).is_err());
    // Matching M6 approval is not transferable to another identity or batch.
    for field in 0..8 {
        let mut bad = root.clone();
        match field {
            0 => bad.parent_genesis_display[0] ^= 1,
            1 => bad.elements_genesis_display[0] ^= 1,
            2 => bad.asset_display[0] ^= 1,
            3 => bad.vault[0] ^= 1,
            4 => bad.prior_count += 1,
            5 => bad.prior_root[0] ^= 1,
            6 => bad.next_count += 1,
            _ => bad.next_root[0] ^= 1,
        }
        assert_eq!(result.verify_root_preimage(&bad), Err(AlphaConversionLinkErrorV3::M6Approval));
    }
    assert_eq!(result.approval().m6id, m6id);
    assert_eq!(result.approval().transaction_id, tx.compute_txid());
    assert_eq!(result.binding_commitment(), frozen);
    assert_eq!(call(bitcoin::Txid::from_byte_array([9;32]), frozen), Err(AlphaConversionLinkErrorV3::M6Approval));
    assert_eq!(call(tx.compute_txid(), [0;32]), Err(AlphaConversionLinkErrorV3::Binding));
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::M7Link));
    let mut verifier = TranscriptVerifier::for_input(&input); verifier.expected[0].0 = [9;32];
    assert_eq!(authenticate_usdd_m6_v3(&input.binding, frozen, &input.parent, &input.terminal_parent_predecessor,
        &input.terminal_parent_block, tx.compute_txid(), &verifier), Err(AlphaConversionLinkErrorV3::Receipt));
}

#[test]
fn generic_parent_approval_can_commit_v2_without_relabeling_v1() {
    authenticated_checkpoint_approval_fixture([31;32],[32;32]);
}

/// Synthetic parent transcript only. Does not establish shared ancestry with
/// a caller's child fixture, finality, or a production recursive receipt.
pub(crate) fn authenticated_checkpoint_approval_fixture(custody_id: Hash32, checkpoint: Hash32)
    -> AuthenticatedCustodyM6V2 {
    // Feasibility regression only: synthetic receipt transcript and predecessor
    // with an already-voted bundle. Does not qualify V2 custody or finality.
    use ecx_full_consensus_validator_v2::bip300_v2::{Bip300CtipV2, Bip300PendingM6idV2};
    let mut input = fixture();
    let mut marker = b"\x6a\x27USDDM6\x02".to_vec();
    let approved = custody_checkpoint_approval_commitment_v2(custody_id,checkpoint).unwrap();
    marker.extend_from_slice(&approved);
    let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([7;32]), vout: 0 };
    let tx = Transaction { version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(9000), script_pubkey: ScriptBuf::from_bytes(vec![0xb4,1,24,0x51]) },
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(marker) }] };
    // Independent blinded serialization: fee 1000, zero-value V2 marker.
    let mut blinded = vec![2,0,0,0,0,2];
    blinded.extend_from_slice(&0u64.to_le_bytes()); blinded.extend_from_slice(&[10,0x6a,8]);
    blinded.extend_from_slice(&1000u64.to_be_bytes());
    blinded.extend_from_slice(&0u64.to_le_bytes()); blinded.push(41);
    blinded.extend_from_slice(tx.output[1].script_pubkey.as_bytes()); blinded.extend_from_slice(&[0;4]);
    let m6id = bitcoin::Txid::from_byte_array(bitcoin::hashes::sha256d::Hash::hash(&blinded).to_byte_array());
    let mut slots = input.terminal_parent_predecessor.bip300_state.as_state().clone();
    let height = slots.next_height;
    let threshold = slots.consensus_parameters.withdrawal_inclusion_threshold;
    let slot = slots.active_slots.get_mut(&24).unwrap();
    slot.ctip = Some(Bip300CtipV2 {outpoint, value_sat:10000, sequence:0});
    slot.next_treasury_sequence = 1;
    slot.pending_m6ids.push(Bip300PendingM6idV2 {m6id, proposal_height:height-1, score:threshold+1});
    input.terminal_parent_predecessor.bip300_state = AlphaBip300AllSlotStateV3::from_authenticated_state(slots).unwrap();
    let mut block: Block = deserialize(&input.terminal_parent_block).unwrap();
    block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
    block.txdata.push(tx.clone()); refresh_parent(&mut input, block);
    let verifier = TranscriptVerifier::for_input(&input);
    let (terminal_statement, _, effects) = authenticate_terminal_parent(&input.binding, &input.parent,
        &input.terminal_parent_predecessor, &input.terminal_parent_block, &verifier).unwrap();
    assert_eq!(effects.successful_m6s.len(),1);
    assert_eq!(effects.successful_m6s[0].m6id,m6id);
    assert_eq!(effects.successful_m6s[0].transaction_id,tx.compute_txid());
    assert_eq!(effects.successful_m6s[0].successor_ctip.value_sat,9000);
    let custody = authenticate_custody_m6_v2(&input.binding, input.binding.commitment().unwrap(),
        &input.parent, &input.terminal_parent_predecessor, &input.terminal_parent_block,
        tx.compute_txid(), &TranscriptVerifier::for_input(&input)).unwrap();
    assert_eq!(custody.commitment(),approved);
    assert_eq!(custody.parent_state_commitment(), terminal_statement.terminal_selected_state_commitment);
    assert_ne!(custody.parent_state_commitment(), input.terminal_parent_predecessor.commitment().unwrap());
    let parent_binding = input.binding.commitment().unwrap();
    custody.require_checkpoint_approval(parent_binding,custody_id,checkpoint).unwrap();
    let mut wrong_custody = custody_id; wrong_custody[0] ^= 1;
    let mut wrong_checkpoint = checkpoint; wrong_checkpoint[0] ^= 1;
    let mut wrong_binding = parent_binding; wrong_binding[0] ^= 1;
    assert!(custody.require_checkpoint_approval(parent_binding,wrong_custody,checkpoint).is_err());
    assert!(custody.require_checkpoint_approval(parent_binding,custody_id,wrong_checkpoint).is_err());
    assert!(custody.require_checkpoint_approval(wrong_binding,custody_id,checkpoint).is_err());
    assert!(custody.require_checkpoint_approval(parent_binding,[0;32],checkpoint).is_err());
    assert_eq!(custody.approval().m6id,m6id);
    assert_eq!(custody.binding_commitment(),input.binding.commitment().unwrap());
    let initial = CustodyApprovalConfirmationsV2::new(custody.clone());
    assert_eq!(initial.confirmations(),1);
    let mut next = input.clone();
    next.terminal_parent_predecessor = input.parent.terminal_selected_state.clone();
    let mut next_block: Block = deserialize(&input.terminal_parent_block).unwrap();
    next_block.txdata.truncate(1);
    next_block.header.prev_blockhash = next.terminal_parent_predecessor.tip.block_hash;
    next_block.header.time += 600;
    next_block.header.merkle_root = next_block.compute_merkle_root().unwrap();
    let mut terminal = next.terminal_parent_predecessor.clone();
    terminal.tip.height += 1;
    terminal.tip.discovery_sequence += 1;
    terminal.tip.chainwork_be[31] += 1;
    terminal.tip.block_hash = next_block.block_hash();
    terminal.pow_context.previous_height += 1;
    terminal.pow_context.previous_header = next_block.header;
    terminal.pow_context.previous_11_times.remove(0);
    terminal.pow_context.previous_11_times.push(next_block.header.time);
    terminal.bip300_state = apply_alpha_bip300_block_v3(
        &next.terminal_parent_predecessor.bip300_state,&next_block).unwrap().0;
    let prior = decode_full_alpha_transition_public_values_v3(
        &input.parent.transition_receipts.last().unwrap().public_values).unwrap();
    let transition = FullAlphaTransitionPublicValuesV3 {
        predecessor_state_commitment: prior.successor_state_commitment,
        predecessor_height: prior.successor_height,
        predecessor_frontier_commitment: prior.successor_frontier_commitment,
        predecessor_event_stream_commitment: prior.successor_event_stream_commitment,
        successor_state_commitment: terminal.commitment().unwrap(),
        successor_height: terminal.tip.height,
        successor_tip_hash_internal: terminal.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: [34;32], successor_event_stream_commitment: [35;32],
        first_discovery_sequence: 2, final_discovery_sequence: 2, ..prior
    };
    next.parent.transition_receipts.push(AlphaRecursiveReceiptBindingV3 {
        public_values: transition.canonical_bytes().to_vec(),proof_marker:vec![3] });
    next.parent.terminal_selected_state = terminal;
    next.terminal_parent_block = serialize(&next_block);
    let extend = |p: &CustodyApprovalConfirmationsV2| extend_custody_approval_confirmation_v2(
        p,&next.binding,&next.parent,&next.terminal_parent_predecessor,
        &next.terminal_parent_block,&TranscriptVerifier::for_input(&next));
    let confirmed = extend(&initial).unwrap();
    assert_eq!(confirmed.confirmations(),2);
    confirmed.require_destination(confirmed.state(),confirmed.anchor(),2).unwrap();
    confirmed.require_destination(confirmed.state(),confirmed.anchor(),1).unwrap();
    assert!(confirmed.require_destination(confirmed.state(),confirmed.anchor(),3).is_err());
    assert!(confirmed.require_destination(confirmed.state(),confirmed.anchor(),0).is_err());
    assert!(confirmed.require_destination([0;32],confirmed.anchor(),2).is_err());
    assert!(confirmed.require_destination(confirmed.state(),[0;32],2).is_err());
    assert!(confirmed.require_destination(initial.state(),confirmed.anchor(),2).is_err());
    assert!(confirmed.require_destination(confirmed.state(),initial.anchor(),2).is_err());
    assert_eq!(confirmed.approval(),&custody);
    assert_eq!(confirmed.anchor(),next_block.block_hash().to_byte_array());
    assert_eq!(confirmed.state(),next.parent.terminal_selected_state.commitment().unwrap());
    assert!(extend(&confirmed).is_err()); // duplicate block is not another confirmation
    let mut substituted = initial.clone(); substituted.state[0] ^= 1;
    assert!(extend(&substituted).is_err());
    let mut substituted = initial.clone(); substituted.anchor[0] ^= 1;
    assert!(extend(&substituted).is_err());
    let mut overflow = initial.clone(); overflow.confirmations = u32::MAX;
    assert!(extend(&overflow).is_err());
    assert_eq!(authenticate_custody_m6_v2(&input.binding, [0;32],
        &input.parent, &input.terminal_parent_predecessor, &input.terminal_parent_block,
        tx.compute_txid(), &TranscriptVerifier::for_input(&input)), Err(AlphaConversionLinkErrorV3::Binding));
    // Parent approval cannot make a V2 marker a V1 root authorization.
    assert_eq!(authenticate_usdd_m6_v3(&input.binding, input.binding.commitment().unwrap(),
        &input.parent, &input.terminal_parent_predecessor, &input.terminal_parent_block,
        tx.compute_txid(), &TranscriptVerifier::for_input(&input)), Err(AlphaConversionLinkErrorV3::M6Approval));
    // Mutating the marker changes the blinded bundle: the original votes do
    // not authorize it, even when a test transcript is reconstructed.
    let mut substituted: Block = deserialize(&input.terminal_parent_block).unwrap();
    let mut script = substituted.txdata[1].output[1].script_pubkey.as_bytes().to_vec();
    script[9] ^= 1;
    substituted.txdata[1].output[1].script_pubkey = ScriptBuf::from_bytes(script);
    // refresh_parent itself applies the real replay and must reject the
    // unmatched proposal, so inspect it directly rather than fabricating state.
    assert_eq!(apply_alpha_bip300_block_v3(&input.terminal_parent_predecessor.bip300_state, &substituted),
        Err(ecx_full_consensus_validator_v2::bip300_v2::Bip300ReplayErrorV2::M6MissingPendingBundle));
    custody
}

// Recompute only the synthetic test transcript after changing exact parent
// bytes. No live receipt is produced; a real verifier would require a new proof.
#[test]
fn alpha_deposit_binds_receipts_frozen_configuration_and_exact_outpoint() {
    // Transcript-only adapter test, NOT a real recursive proof or live deposit.
    let mut input = fixture();
    let tx = Transaction {
        version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([7;32]), vout: 1 },
            script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from_bytes(vec![0xb4,1,24,0x51]) },
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(vec![0x6a,1,0x61]) },
        ],
    };
    let outpoint = OutPoint { txid: tx.compute_txid(), vout: 0 };
    let mut block: Block = deserialize(&input.terminal_parent_block).unwrap();
    block.txdata.push(tx);
    refresh_parent(&mut input, block);
    let frozen = input.binding.commitment().unwrap();
    let verifier = TranscriptVerifier::for_input(&input);
    let call = |point, binding| authenticate_alpha_deposit_v3(
        &input.binding, binding, &input.parent, &input.terminal_parent_predecessor,
        &input.terminal_parent_block, point, &verifier,
    );
    let result = call(outpoint, frozen).unwrap();
    assert_eq!(result.deposit().prior_ctip, None);
    assert_eq!(result.deposit().value_sat, 1000);
    assert_eq!(result.binding_commitment(), frozen);
    assert_eq!(result.parent_state_commitment(), input.parent.terminal_selected_state.commitment().unwrap());
    assert_eq!(result.confirmations(), 1);
    assert_eq!(result.confirmed_anchor(), input.parent.terminal_selected_state.tip.block_hash.to_byte_array());
    // Extend the original receipt transcript, retaining its frozen checkpoint.
    let mut next = input.clone();
    next.terminal_parent_predecessor = input.parent.terminal_selected_state.clone();
    let mut block: Block = deserialize(&input.terminal_parent_block).unwrap();
    block.txdata.truncate(1);
    block.header.prev_blockhash = next.terminal_parent_predecessor.tip.block_hash;
    block.header.time += 600;
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let mut terminal = next.terminal_parent_predecessor.clone();
    terminal.tip.height += 1;
    terminal.tip.discovery_sequence += 1;
    terminal.tip.chainwork_be[31] += 1;
    terminal.tip.block_hash = block.block_hash();
    terminal.pow_context.previous_height += 1;
    terminal.pow_context.previous_header = block.header;
    terminal.pow_context.previous_11_times.remove(0);
    terminal.pow_context.previous_11_times.push(block.header.time);
    terminal.bip300_state = apply_alpha_bip300_block_v3(
        &next.terminal_parent_predecessor.bip300_state, &block).unwrap().0;
    let prior = decode_full_alpha_transition_public_values_v3(
        &input.parent.transition_receipts.last().unwrap().public_values).unwrap();
    let transition = FullAlphaTransitionPublicValuesV3 {
        predecessor_state_commitment: prior.successor_state_commitment,
        predecessor_height: prior.successor_height,
        predecessor_frontier_commitment: prior.successor_frontier_commitment,
        predecessor_event_stream_commitment: prior.successor_event_stream_commitment,
        successor_state_commitment: terminal.commitment().unwrap(),
        successor_height: terminal.tip.height,
        successor_tip_hash_internal: terminal.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: [34;32],
        successor_event_stream_commitment: [35;32],
        first_discovery_sequence: 2, final_discovery_sequence: 2,
        ..prior
    };
    next.parent.transition_receipts.push(AlphaRecursiveReceiptBindingV3 {
        public_values: transition.canonical_bytes().to_vec(), proof_marker: vec![3],
    });
    next.parent.terminal_selected_state = terminal;
    next.terminal_parent_block = serialize(&block);
    let extend = |deposit: &AuthenticatedAlphaDepositV3| extend_alpha_deposit_confirmation_v3(
        deposit, &next.binding, &next.parent, &next.terminal_parent_predecessor,
        &next.terminal_parent_block, &TranscriptVerifier::for_input(&next));
    let confirmed = extend(&result).unwrap();
    assert_eq!(confirmed.confirmations(), 2);
    assert_eq!(confirmed.confirmed_anchor(), block.block_hash().to_byte_array());
    assert_eq!(confirmed.deposit(), result.deposit());
    let owned_block = |i: &AlphaConversionParentLinkInputV3| AlphaDepositParentBlockWitnessV3 {
        parent: i.parent.clone(), predecessor: i.terminal_parent_predecessor.clone(),
        raw_block: i.terminal_parent_block.clone(),
    };
    let witness = AlphaDepositWitnessV3 { outpoint, inclusion: owned_block(&input),
        confirmations: vec![owned_block(&next)] };
    let bytes = bincode::serialize(&witness).unwrap();
    let decoded: AlphaDepositWitnessV3 = bincode::deserialize(&bytes).unwrap();
    assert_eq!(decoded, witness);
    let authenticate = |w: &AlphaDepositWitnessV3, anchor, state, depth| {
        let mut verifier = TranscriptVerifier::for_input(&input);
        verifier.expected.extend(TranscriptVerifier::for_input(&next).expected);
        w.authenticate(&input.binding, frozen, anchor, state, depth, &verifier)
    };
    assert_eq!(authenticate(&decoded, confirmed.confirmed_anchor(),
        confirmed.parent_state_commitment(), 2).unwrap(), confirmed);
    assert!(authenticate(&decoded, confirmed.confirmed_anchor(),
        confirmed.parent_state_commitment(), 3).is_err());
    assert!(authenticate(&decoded, [0;32], confirmed.parent_state_commitment(), 1).is_err());
    assert!(authenticate(&decoded, confirmed.confirmed_anchor(), [99;32], 1).is_err());
    let mut missing = decoded.clone(); missing.confirmations.clear();
    // Policy-to-parent-authentication integration, using synthetic receipt
    // transcripts only. This is NOT a live child-height or recursive-proof test.
    let policy = crate::native_deposit_policy_v4::tests::policy();
    let before_upgrade = policy.required_depth(62).unwrap();
    let at_upgrade = policy.required_depth(63).unwrap();
    assert!(authenticate(&missing, result.confirmed_anchor(),
        result.parent_state_commitment(), before_upgrade).is_err());
    assert_eq!(authenticate(&missing, result.confirmed_anchor(),
        result.parent_state_commitment(), at_upgrade).unwrap(), result);
    // One confirmation does not permit a different terminal anchor, state,
    // outpoint, or an absent authentication receipt.
    assert!(authenticate(&missing, confirmed.confirmed_anchor(),
        confirmed.parent_state_commitment(), at_upgrade).is_err());
    let mut unauthenticated = missing.clone();
    unauthenticated.inclusion.parent.checkpoint_receipt.proof_marker.clear();
    assert!(authenticate(&unauthenticated, result.confirmed_anchor(),
        result.parent_state_commitment(), at_upgrade).is_err());
    let mut substituted = missing.clone(); substituted.outpoint.vout = 1;
    assert!(authenticate(&substituted, result.confirmed_anchor(),
        result.parent_state_commitment(), at_upgrade).is_err());
    assert!(authenticate(&missing, confirmed.confirmed_anchor(),
        confirmed.parent_state_commitment(), 1).is_err());
    let mut duplicate = decoded.clone(); duplicate.confirmations.push(owned_block(&next));
    assert!(authenticate(&duplicate, confirmed.confirmed_anchor(),
        confirmed.parent_state_commitment(), 2).is_err());
    assert!(extend(&confirmed).is_err()); // cannot count the same block twice
    let mut wrong = result.clone(); wrong.parent_state_commitment = [99;32];
    assert!(extend(&wrong).is_err());
    let mut wrong = result.clone(); wrong.confirmed_anchor = [99;32];
    assert!(extend(&wrong).is_err());
    let mut wrong = result.clone(); wrong.binding_commitment = [99;32];
    assert!(extend(&wrong).is_err());
    assert!(call(outpoint, [0;32]).is_err());
    assert!(call(outpoint, [9;32]).is_err());
    assert!(call(OutPoint { vout: 1, ..outpoint }, frozen).is_err());
    let mut bad = input.parent.clone();
    bad.checkpoint_receipt.proof_marker.clear();
    assert!(authenticate_alpha_deposit_v3(
        &input.binding, frozen, &bad, &input.terminal_parent_predecessor,
        &input.terminal_parent_block, outpoint, &verifier,
    ).is_err());
}

pub(crate) fn refresh_parent(input: &mut AlphaConversionParentLinkInputV3, mut block: Block) {
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let predecessor = &input.terminal_parent_predecessor;
    let (slots, _) = apply_alpha_bip300_block_v3(&predecessor.bip300_state, &block).unwrap();
    let mut terminal = input.parent.terminal_selected_state.clone();
    terminal.tip.block_hash = block.block_hash();
    terminal.pow_context.previous_header = block.header;
    terminal.bip300_state = slots;
    input.parent = parent_adapter(predecessor, terminal);
    input.binding.parent = input.parent.binding;
    input.terminal_parent_block = serialize(&block);
}

// Test-only transcript builder; no real parent proof or mined block is supplied.
pub(crate) fn parent_for_child_checkpoint(
    checkpoint:&crate::child_execution_state_v3::ChildExecutionCheckpointV3,
    critical:Hash32,
) -> AlphaConversionParentLinkInputV3 {
    let mut input = fixture();
    input.binding.child_genesis_hash_internal = checkpoint.genesis_internal;
    input.binding.child_consensus_configuration_commitment = checkpoint.configuration_commitment;
    input.binding.child_checkpoint_hash_internal = checkpoint.tip_internal;
    input.binding.child_checkpoint_height = checkpoint.height;
    input.expected_critical_hash_internal = critical;
    let mut block:Block = deserialize(&input.terminal_parent_block).unwrap();
    let mut script = vec![0x6a,37]; script.extend_from_slice(&M7_TAG); script.push(24);
    let mut display = critical; display.reverse(); script.extend_from_slice(&display);
    block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(script);
    refresh_parent(&mut input,block);
    input
}

#[test]
fn verified_parent_is_joined_to_exact_native_child_preimage() {
    use crate::native_child_block_v3::{verify_parent_bound_child_commitments,ParentBoundChildError};
    use crate::native_withdrawal_accumulator_v3::{WithdrawalAccumulator,critical_hash_internal};
    let mut input=fixture();
    let mut script=vec![0x6a,37]; script.extend_from_slice(b"ELMTP");
    script.extend_from_slice(&input.expected_parent_hash_internal);
    let tx=elements::Transaction {version:2,lock_time:elements::LockTime::ZERO,
        input:vec![elements::TxIn {script_sig:elements::Script::from(vec![1,64]),..Default::default()}],
        output:vec![elements::TxOut {script_pubkey:elements::Script::from(script),..Default::default()}]};
    let previous=elements::BlockHash::from_byte_array(input.binding.child_checkpoint_hash_internal);
    let child=elements::Block {header:elements::BlockHeader {version:1,prev_blockhash:previous,
        merkle_root:ecx_full_consensus_validator_v2::elements_v2::elements_transaction_merkle_root_v2(&[tx.clone()]).unwrap(),
        time:100,height:64,ext:elements::BlockExtData::Proof {challenge:elements::Script::new(),solution:elements::Script::new()}},
        txdata:vec![tx]};
    let empty=WithdrawalAccumulator::empty();
    let critical=critical_hash_internal(input.binding.child_genesis_hash_internal,24,
        child.block_hash().to_byte_array(),&empty,&empty).unwrap();
    input.expected_critical_hash_internal=critical;
    let mut parent:Block=deserialize(&input.terminal_parent_block).unwrap();
    let mut m7=vec![0x6a,37]; m7.extend_from_slice(&M7_TAG); m7.push(24);
    m7.extend(critical.iter().rev());
    parent.txdata[0].output[0].script_pubkey=ScriptBuf::from_bytes(m7);
    refresh_parent(&mut input,parent);
    let binding=input.binding.commitment().unwrap();
    let raw=elements::encode::serialize(&child);
    let call=|bytes:&[u8],frozen|verify_parent_bound_child_commitments(&input,frozen,
        &TranscriptVerifier::for_input(&input),bytes,previous,64,&empty,true);
    assert!(call(&raw,binding).is_ok());
    assert!(matches!(call(&raw,[0;32]),Err(ParentBoundChildError::Binding)));
    let mut changed=child; changed.header.time+=1;
    assert!(matches!(call(&elements::encode::serialize(&changed),binding),Err(ParentBoundChildError::Child(_))));
    input.parent.transition_receipts[0].public_values[0]^=1;
    assert!(matches!(verify_parent_bound_child_commitments(&input,binding,
        &TranscriptVerifier::for_input(&input),&raw,previous,64,&empty,true),Err(ParentBoundChildError::Parent(_))));
}

#[test]
fn authenticated_endpoint_encodes_predecessor_not_mining_block() {
    let input = fixture();
    let frozen = input.binding.commitment().unwrap();
    let verifier = TranscriptVerifier::for_input(&input);
    let (statement, endpoint) =
        authenticate_alpha_bmm_endpoint_v4(&input, frozen, &verifier).unwrap();
    assert_eq!(verifier.calls.get(), 2);
    let predecessor = &input.terminal_parent_predecessor;
    let mut display_hash = predecessor.tip.block_hash.to_byte_array();
    display_hash.reverse();
    let mut times = predecessor.pow_context.previous_11_times.clone();
    times.sort_unstable();
    assert_eq!(&endpoint[..32], &display_hash);
    assert_eq!(&endpoint[32..40], &u64::from(predecessor.tip.height).to_be_bytes());
    assert_eq!(&endpoint[40..48], &u64::from(times[times.len() / 2]).to_be_bytes());
    assert_eq!(&endpoint[48..], &predecessor.tip.chainwork_be);
    assert_eq!(statement.parent_predecessor_hash_internal, predecessor.tip.block_hash.to_byte_array());
    assert_ne!(statement.parent_block_hash_internal, statement.parent_predecessor_hash_internal);
    assert_ne!(predecessor.tip.height, input.parent.terminal_selected_state.tip.height);

    for wrong_binding in [[0; 32], [5; 32]] {
        let verifier = TranscriptVerifier::for_input(&input);
        assert!(authenticate_alpha_bmm_endpoint_v4(&input, wrong_binding, &verifier).is_err());
        assert_eq!(verifier.calls.get(), 0);
    }
    let mut wrong = input.clone();
    wrong.terminal_parent_predecessor.tip.chainwork_be[31] ^= 1;
    assert!(authenticate_alpha_bmm_endpoint_v4(&wrong, frozen,
        &TranscriptVerifier::for_input(&input)).is_err());
    let mut wrong = input.clone();
    wrong.terminal_parent_predecessor.pow_context.previous_11_times[0] ^= 1;
    assert!(authenticate_alpha_bmm_endpoint_v4(&wrong, frozen,
        &TranscriptVerifier::for_input(&input)).is_err());
    let mut wrong = input.clone();
    wrong.parent.transition_receipts[0].public_values[0] ^= 1;
    assert!(authenticate_alpha_bmm_endpoint_v4(&wrong, frozen,
        &TranscriptVerifier::for_input(&input)).is_err());
}

#[test]
fn exact_alpha_parent_receipts_slot24_and_opaque_m7_are_bound() {
    let input = fixture();
    let verifier = TranscriptVerifier::for_input(&input);
    let values = execute_alpha_conversion_parent_link_v3(&input, &verifier).unwrap();
    assert_eq!(verifier.calls.get(), 2);
    assert_eq!(
        values.parent_block_hash_internal,
        input
            .parent
            .terminal_selected_state
            .tip
            .block_hash
            .to_byte_array()
    );
    assert_eq!(
        values.m7_critical_hash_internal,
        input.expected_critical_hash_internal
    );
    assert_eq!(
        values.parent_predecessor_hash_internal,
        input.expected_parent_hash_internal
    );
    assert_eq!(values.canonical_bytes().len(), 266);
    assert_eq!(&values.canonical_bytes()[..2], &[0xa4, 0]);
    assert_ne!(values.canonical_bytes().len(), 275); // legacy economic ABI
    assert_eq!(
        values.require_frozen_binding(input.binding.commitment().unwrap()),
        Ok(())
    );
    assert_eq!(
        values.require_frozen_binding([0; 32]),
        Err(AlphaConversionLinkErrorV3::Binding)
    );
    assert_eq!(
        values.require_frozen_binding([5; 32]),
        Err(AlphaConversionLinkErrorV3::Binding)
    );
    let bytes = encode_alpha_conversion_parent_link_input_v3(&input).unwrap();
    assert_eq!(
        decode_alpha_conversion_parent_link_input_v3(&bytes).unwrap(),
        input
    );
}

#[test]
fn neither_marker_only_nor_swapped_role_receipts_are_accepted() {
    let input = fixture();
    for index in 0..2 {
        let mut verifier = TranscriptVerifier::for_input(&input);
        verifier.expected[index].0 = [9; 32];
        assert_eq!(
            execute_alpha_conversion_parent_link_v3(&input, &verifier),
            Err(AlphaConversionLinkErrorV3::Receipt)
        );
    }
    let mut wrong = input.clone();
    std::mem::swap(
        &mut wrong.parent.binding.checkpoint_program_id,
        &mut wrong.parent.binding.transition_program_id,
    );
    wrong.binding.parent = wrong.parent.binding;
    assert_eq!(
        execute_alpha_conversion_parent_link_v3(&wrong, &TranscriptVerifier::for_input(&input)),
        Err(AlphaConversionLinkErrorV3::Receipt)
    );
}

#[test]
fn every_source_role_and_child_network_binding_changes_the_frozen_identity() {
    let input = fixture();
    let frozen = input.binding.commitment().unwrap();
    let mut cases = vec![];
    let mut b = input.binding;
    b.parent.source_configuration_commitment[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.parent.reviewed_checkpoint_input_commitment[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.parent.checkpoint_program_id = [4; 32];
    cases.push(b);
    let mut b = input.binding;
    b.parent.transition_program_id = [5; 32];
    cases.push(b);
    let mut b = input.binding;
    b.child_consensus_configuration_commitment[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.child_genesis_hash_internal[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.child_checkpoint_hash_internal[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.child_checkpoint_height += 1;
    cases.push(b);
    let mut b = input.binding;
    b.slot24_proposal_hash[0] ^= 1;
    cases.push(b);
    let mut b = input.binding;
    b.slot24_activation_height += 1;
    cases.push(b);
    for b in cases {
        assert_ne!(b.commitment().unwrap(), frozen);
    }
    let mut bad = input;
    bad.binding.parent.transition_program_id = [4; 32];
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::Binding));
}

#[test]
fn rejects_unbound_predecessor_and_slot_replacement() {
    let input = fixture();
    let mut bad = input.clone();
    bad.terminal_parent_predecessor.utxo_root.hash[0] ^= 1;
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::ParentBranch));
    let mut bad = input.clone();
    bad.binding.slot24_proposal_hash[0] ^= 1;
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::Slot24));
    let mut bad = input.clone();
    bad.binding.slot24_activation_height += 1;
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::Slot24));
}

#[test]
fn child_checkpoint_is_declared_binding_not_falsely_claimed_authenticated() {
    let input = fixture();
    let frozen = input.binding.commitment().unwrap();
    let mut changed = input;
    changed.binding.child_checkpoint_height += 1;
    changed.binding.child_checkpoint_hash_internal[0] ^= 1;
    // The parent half cannot authenticate this claim. Its changed identity
    // MUST be rejected by an outer consumer checking the reviewed binding.
    assert_eq!(
        run(&changed).unwrap().require_frozen_binding(frozen),
        Err(AlphaConversionLinkErrorV3::Binding)
    );
}

#[test]
fn rejects_receipt_valid_but_unsupported_terminal_frontier_shape() {
    let mut input = fixture();
    let mut last = decode_full_alpha_transition_public_values_v3(
        &input.parent.transition_receipts[0].public_values,
    )
    .unwrap();
    last.step_count = 2;
    last.final_discovery_sequence = 2;
    input.parent.transition_receipts[0].public_values = last.canonical_bytes().to_vec();
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::ParentBranch));
}

#[test]
fn parent_raw_block_mutations_are_rejected() {
    let input = fixture();
    let mut bad = input.clone();
    let mut parent: Block = deserialize(&bad.terminal_parent_block).unwrap();
    parent.txdata[0].output[0].value = Amount::from_sat(1);
    bad.terminal_parent_block = serialize(&parent);
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::ParentBlock));
    let mut bad = input.clone();
    bad.terminal_parent_block.push(0);
    assert_eq!(run(&bad), Err(AlphaConversionLinkErrorV3::ParentBlock));
}

#[test]
fn m7_display_byte_order_is_reversed_exactly_once() {
    let mut input = fixture();
    let critical = input.expected_critical_hash_internal;
    let mut display = critical;
    display.reverse();
    assert_ne!(critical, display); // non-palindromic fixture is essential
    let mut parent: Block = deserialize(&input.terminal_parent_block).unwrap();
    assert_eq!(
        &parent.txdata[0].output[0].script_pubkey.as_bytes()[7..],
        &display
    );
    assert!(run(&input).is_ok());
    let mut script = parent.txdata[0].output[0].script_pubkey.as_bytes().to_vec();
    script[7..].copy_from_slice(&critical); // internal bytes are not wire bytes
    parent.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(script);
    refresh_parent(&mut input, parent);
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::M7Link));
}

#[test]
fn parent_anchor_must_be_predecessor_not_mining_parent() {
    let original = fixture();
    let mining_parent = original
        .parent
        .terminal_selected_state
        .tip
        .block_hash
        .to_byte_array();
    assert_ne!(
        mining_parent,
        original
            .terminal_parent_predecessor
            .tip
            .block_hash
            .to_byte_array()
    );
    let mut input = original;
    input.expected_parent_hash_internal = mining_parent;
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::M7Link));
}

#[test]
fn any_child_bytes_are_rejected_without_decoding_or_transaction_indexing() {
    for bytes in [vec![0], vec![0xff; 8], b"ELMTP".to_vec()] {
        let mut input = fixture();
        input.candidate_child_block = bytes;
        let verifier = TranscriptVerifier::for_input(&input);
        assert_eq!(
            execute_alpha_conversion_parent_link_v3(&input, &verifier),
            Err(AlphaConversionLinkErrorV3::UnsupportedAlphaChildEconomicLane)
        );
        assert_eq!(verifier.calls.get(), 0);
    }
    // Parent-only operation has no child vector to index, even when empty.
    assert!(run(&fixture()).is_ok());
}

#[test]
fn full_economic_lane_is_always_rejected_even_with_matching_receipts() {
    for purpose in [
        AlphaConversionPurposeV3::EconomicConversion,
        AlphaConversionPurposeV3::NativeChildAndParentLink,
    ] {
        let mut input = fixture();
        input.purpose = purpose;
        let verifier = TranscriptVerifier::for_input(&input);
        assert_eq!(
            execute_alpha_conversion_parent_link_v3(&input, &verifier),
            Err(AlphaConversionLinkErrorV3::UnsupportedAlphaChildEconomicLane)
        );
        assert_eq!(verifier.calls.get(), 0);
        assert_eq!(
            encode_alpha_conversion_parent_link_input_v3(&input),
            Err(AlphaConversionLinkErrorV3::UnsupportedAlphaChildEconomicLane)
        );
    }
}

#[test]
fn rejects_legacy_abis_and_noncanonical_input() {
    let mut input = fixture();
    input.version = 2;
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::Input));
    input.version = 0xa3;
    assert_eq!(run(&input), Err(AlphaConversionLinkErrorV3::Input));
    let mut bytes = encode_alpha_conversion_parent_link_input_v3(&fixture()).unwrap();
    bytes.push(0);
    assert_eq!(
        decode_alpha_conversion_parent_link_input_v3(&bytes),
        Err(AlphaConversionLinkErrorV3::Input)
    );
    assert_eq!(
        decode_alpha_conversion_parent_link_input_v3(&[]),
        Err(AlphaConversionLinkErrorV3::Input)
    );
    assert_eq!(
        decode_alpha_conversion_parent_link_input_v3(&vec![
            0;
            MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3
                + 1
        ]),
        Err(AlphaConversionLinkErrorV3::Input)
    );
}
