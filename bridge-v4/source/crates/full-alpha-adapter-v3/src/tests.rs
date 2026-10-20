use super::*;
use bitcoin::{blockdata::constants::genesis_block, Network};
use ecx_full_consensus_validator_v2::alpha_pow_v3::AlphaHeaderContextV3;
use ecx_full_consensus_validator_v2::alpha_state_v3::ALPHA_EXECUTED_STATE_VERSION_V3;
use ecx_full_consensus_validator_v2::bip300_v2::alpha_bip300_v3::AlphaBip300AllSlotStateV3;
use ecx_full_consensus_validator_v2::checkpoint_alpha_v3::{
    encode_reviewed_alpha_checkpoint_input_v3, ReviewedAlphaCheckpointInputV3,
    REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3,
};
use ecx_full_consensus_validator_v2::state_frontier_v2::{
    apply_executed_frontier_mutation_v2, canonical_empty_executed_frontier_path_v2,
    canonical_empty_executed_frontier_root_v2, BitcoinDeploymentActivationAnchorV2,
    BitcoinDeploymentKindV2, BitcoinExecutedFrontierMutationV2, BitcoinTerminalDeploymentStateV2,
    BITCOIN_TERMINAL_DEPLOYMENT_STATE_VERSION_V2,
};
use ecx_full_consensus_validator_v2::{
    canonical_empty_utxo_leaf_v2, sparse_utxo_parent_v2, BitcoinChainTipV2, SPARSE_UTXO_DEPTH_V2,
};
use std::cell::RefCell;

/// Test-only cryptographic-verifier boundary model. It accepts only an exact
/// program/journal/marker transcript supplied by the test. It does not prove
/// these synthetic state transitions, and is never compiled into a guest or
/// exported as a production verification implementation.
struct TranscriptVerifier {
    expected: Vec<(Hash32, Vec<u8>, Vec<u8>)>,
    calls: RefCell<Vec<(Hash32, Vec<u8>, Vec<u8>)>>,
}

impl TranscriptVerifier {
    fn new(input: &FullAlphaAdapterInputV3) -> Self {
        let mut expected = vec![(
            input.binding.checkpoint_program_id,
            input.checkpoint_receipt.public_values.clone(),
            input.checkpoint_receipt.proof_marker.clone(),
        )];
        expected.extend(input.transition_receipts.iter().map(|r| {
            (
                input.binding.transition_program_id,
                r.public_values.clone(),
                r.proof_marker.clone(),
            )
        }));
        Self {
            expected,
            calls: RefCell::new(vec![]),
        }
    }
}

impl FullAlphaReceiptVerifierV3 for TranscriptVerifier {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let observed = (program_id, public_values.to_vec(), proof_marker.to_vec());
        self.calls.borrow_mut().push(observed.clone());
        if self.expected.contains(&observed) {
            Ok(())
        } else {
            Err(FullAlphaAdapterErrorV3::Receipt)
        }
    }
}

#[test]
fn parent_membership_wire_is_bounded_canonical_and_requires_receipts() {
    use crate::parent_finality_wire_v3::*;
    let witness = ParentFinalityWitnessV3 {
        version: PARENT_FINALITY_WIRE_VERSION_V3, parent: input(),
        headers: vec![genesis_block(Network::Bitcoin).header],
        ancestor_height: 0, minimum_descendants: 1,
    };
    let bytes = encode_parent_finality_v3(&witness).unwrap();
    assert_eq!(encode_parent_finality_v3(&decode_parent_finality_v3(&bytes).unwrap()).unwrap(), bytes);
    for end in [0, 1, bytes.len()-1] { assert!(decode_parent_finality_v3(&bytes[..end]).is_err()); }
    let mut bad = bytes.clone(); bad.push(0); assert!(decode_parent_finality_v3(&bad).is_err());
    let mut bad = bytes.clone(); bad[0] ^= 1; assert!(decode_parent_finality_v3(&bad).is_err());
    let mut bad = witness.clone(); bad.minimum_descendants = 0; assert!(encode_parent_finality_v3(&bad).is_err());
    let mut bad = witness.clone(); bad.headers.clear(); assert!(encode_parent_finality_v3(&bad).is_err());
    assert_eq!(execute_parent_finality_v3(&witness, &RejectEveryReceipt),
        Err(crate::parent_finality_v3::ParentFinalityErrorV3::Receipt));
}

struct RejectEveryReceipt;
#[test]
fn reorg_wire_is_canonical_and_requires_authentication() {
    use crate::relay_reorg_wire_v3::*;
    let parent = input();
    let headers = vec![genesis_block(Network::Bitcoin).header];
    let witness = RelayReorgWitnessV3 {version:0xc5, accepted:parent.clone(), successor:parent,
        accepted_headers:headers.clone(), successor_headers:headers};
    let bytes=encode_relay_reorg_v3(&witness).unwrap();
    let decoded=decode_relay_reorg_v3(&bytes).unwrap();
    assert_eq!(encode_relay_reorg_v3(&decoded).unwrap(),bytes);
    assert_eq!(execute_relay_reorg_v3(&decoded,&RejectEveryReceipt),Err(RelayReorgWireErrorV3::Authentication));
    for length in [0,1,bytes.len()-1] {assert!(decode_relay_reorg_v3(&bytes[..length]).is_err());}
    let mut extra=bytes.clone();extra.push(0);assert!(decode_relay_reorg_v3(&extra).is_err());
    let mut wrong=bytes;wrong[0]=0xc4;assert!(decode_relay_reorg_v3(&wrong).is_err());
    let mut empty=witness;empty.accepted_headers.clear();assert!(encode_relay_reorg_v3(&empty).is_err());
}
#[test]
fn reorg_relation_rejects_unverified_receipts_and_no_progress() {
    use crate::relay_reorg_v3::*;
    let parent = input();
    assert_eq!(authenticate_relay_reorg_v3(&parent,&parent,&[],&[],&RejectEveryReceipt),
        Err(RelayReorgErrorV3::Authentication));
    assert_eq!(authenticate_relay_reorg_v3(&parent,&parent,&[],&[],&TranscriptVerifier::new(&parent)),
        Err(RelayReorgErrorV3::Authentication));
}
#[test]
fn relay_continuation_wire_authenticates_both_cursors_and_exact_journal() {
    use crate::relay_continuation_v3::AlphaRelayCursorV3;
    use crate::relay_continuation_wire_v3::*;
    let parent = input();
    let verifier = TranscriptVerifier::new(&parent);
    let s = execute_full_alpha_adapter_v3(&parent, &verifier).unwrap();
    let accepted = AlphaRelayCursorV3 { binding: s.binding,
        selected_state: s.initial_selected_state_commitment,
        frontier: s.initial_frontier_commitment, event_stream: s.initial_event_stream_commitment,
        selected_height: s.initial_selected_height, event_sequence: s.initial_event_sequence };
    let witness = RelayContinuationWitnessV3 { version: 0xc4, parent, accepted };
    let encoded = encode_relay_continuation_v3(&witness).unwrap();
    let decoded = decode_relay_continuation_v3(&encoded).unwrap();
    assert_eq!(encode_relay_continuation_v3(&decoded).unwrap(), encoded);
    let journal = execute_relay_continuation_v3(&decoded, &verifier).unwrap();
    assert_eq!(journal.len(), 594);
    assert_eq!(journal[0], 0xc4);
    assert_eq!(&journal[1..33], &accepted.commitment().unwrap());
    assert_eq!(&journal[33..65], &AlphaRelayCursorV3::terminal(&s).commitment().unwrap());
    assert_eq!(&journal[65..], encode_full_alpha_statement_v3(&s).unwrap());
    assert_eq!(execute_relay_continuation_v3(&decoded, &RejectEveryReceipt),
        Err(RelayContinuationWireErrorV3::Authentication));
    for length in [0, 1, encoded.len()-1] {
        assert!(decode_relay_continuation_v3(&encoded[..length]).is_err());
    }
    let mut extra = encoded.clone(); extra.push(0);
    assert!(decode_relay_continuation_v3(&extra).is_err());
    let mut wrong = encoded; wrong[0] = 0xc3;
    assert!(decode_relay_continuation_v3(&wrong).is_err());
    let mut substituted = witness.clone(); substituted.accepted.frontier[0] ^= 1;
    assert!(execute_relay_continuation_v3(&substituted, &verifier).is_err());
    substituted.accepted = AlphaRelayCursorV3::terminal(&s);
    assert!(execute_relay_continuation_v3(&substituted, &verifier).is_err());
}
#[test]
fn relay_continuation_requires_exact_authenticated_prefix_and_progress() {
    use crate::relay_continuation_v3::*;
    let input=input(); let verifier=TranscriptVerifier::new(&input);
    let statement=execute_full_alpha_adapter_v3(&input,&verifier).unwrap();
    let initial=AlphaRelayCursorV3 {binding:statement.binding,
        selected_state:statement.initial_selected_state_commitment,
        frontier:statement.initial_frontier_commitment,event_stream:statement.initial_event_stream_commitment,
        selected_height:statement.initial_selected_height,event_sequence:statement.initial_event_sequence};
    assert_eq!(authenticate_relay_continuation_v3(&input,&initial,&verifier).unwrap(),statement);
    let first=decode_full_alpha_transition_public_values_v3(&input.transition_receipts[0].public_values).unwrap();
    let middle=AlphaRelayCursorV3 {binding:statement.binding,selected_state:first.successor_state_commitment,
        frontier:first.successor_frontier_commitment,event_stream:first.successor_event_stream_commitment,
        selected_height:first.successor_height,event_sequence:first.final_discovery_sequence};
    assert_eq!(authenticate_relay_continuation_v3(&input,&middle,&verifier).unwrap(),statement);
    assert!(authenticate_relay_continuation_v3(&input,&AlphaRelayCursorV3::terminal(&statement),&verifier).is_err());
    for index in 0..6 {
        let mut changed=middle;
        match index {0=>changed.selected_state[0]^=1,1=>changed.frontier[0]^=1,
            2=>changed.event_stream[0]^=1,3=>changed.selected_height+=1,
            4=>changed.event_sequence-=1,_=>changed.binding.source_configuration_commitment[0]^=1}
        assert_ne!(changed.commitment().unwrap(),middle.commitment().unwrap());
        assert!(authenticate_relay_continuation_v3(&input,&changed,&verifier).is_err());
    }
    assert_eq!(authenticate_relay_continuation_v3(&input,&middle,&RejectEveryReceipt),Err(RelayContinuationErrorV3::Receipt));
}
impl FullAlphaReceiptVerifierV3 for RejectEveryReceipt {
    fn verify(&self, _: Hash32, _: &[u8], _: &[u8]) -> Result<(), FullAlphaAdapterErrorV3> {
        Err(FullAlphaAdapterErrorV3::Receipt)
    }
}

// Entirely synthetic shape fixture. The genesis header at a post-fork height
// is deliberately NOT live replay evidence or an authenticated checkpoint.
pub(super) fn synthetic_state() -> AlphaExecutedConsensusStateV3 {
    let genesis = genesis_block(Network::Bitcoin);
    let height = ALPHA_FORK_HEIGHT_V3 - 1;
    let mut inner = AlphaBip300AllSlotStateV3::before_genesis()
        .as_state()
        .clone();
    inner.next_height = height + 1;
    inner.tip_hash = Some(genesis.block_hash());
    let mut utxo_root = canonical_empty_utxo_leaf_v2();
    for _ in 0..SPARSE_UTXO_DEPTH_V2 {
        utxo_root = sparse_utxo_parent_v2(utxo_root, utxo_root).unwrap();
    }
    AlphaExecutedConsensusStateV3 {
        version: ALPHA_EXECUTED_STATE_VERSION_V3,
        source_configuration_commitment: [1; 32],
        tip: BitcoinChainTipV2 {
            block_hash: genesis.block_hash(),
            height,
            chainwork_be: [1; 32],
            discovery_sequence: 0,
        },
        pow_context: AlphaHeaderContextV3 {
            previous_height: height,
            previous_header: genesis.header,
            previous_11_times: vec![genesis.header.time; 11],
            retarget_epoch_start_time: genesis.header.time - 1000,
        },
        utxo_root,
        bip300_state: AlphaBip300AllSlotStateV3::from_authenticated_state(inner).unwrap(),
        deployment_state: BitcoinTerminalDeploymentStateV2 {
            version: BITCOIN_TERMINAL_DEPLOYMENT_STATE_VERSION_V2,
            network_genesis: genesis.block_hash(),
            terminal_checkpoint_height: height,
            terminal_checkpoint_hash: genesis.block_hash(),
            activation_anchors: [
                BitcoinDeploymentKindV2::P2sh,
                BitcoinDeploymentKindV2::Bip34,
                BitcoinDeploymentKindV2::Bip66,
                BitcoinDeploymentKindV2::Bip65,
                BitcoinDeploymentKindV2::Csv,
                BitcoinDeploymentKindV2::Segwit,
                BitcoinDeploymentKindV2::Taproot,
            ]
            .into_iter()
            .map(|kind| BitcoinDeploymentActivationAnchorV2 {
                kind,
                activation_height: 0,
                activation_block_hash: genesis.block_hash(),
            })
            .collect(),
        },
    }
}

fn input() -> FullAlphaAdapterInputV3 {
    let state = synthetic_state();
    let path = canonical_empty_executed_frontier_path_v2();
    let frontier = apply_executed_frontier_mutation_v2(
        canonical_empty_executed_frontier_root_v2(),
        &BitcoinExecutedFrontierMutationV2 {
            candidate: state.frontier_tip().unwrap(),
            insert: true,
            path: path.clone(),
        },
    )
    .unwrap();
    let checkpoint = ReviewedAlphaCheckpointInputV3 {
        version: REVIEWED_ALPHA_CHECKPOINT_INPUT_VERSION_V3,
        source_configuration_commitment: state.source_configuration_commitment,
        selected_state: state.clone(),
        frontier,
        selected_membership_path: path,
        event_stream_commitment: [7; 32],
        event_sequence: 0,
    };
    let checkpoint_values = execute_reviewed_alpha_checkpoint_v3(&checkpoint).unwrap();
    let first = FullAlphaTransitionPublicValuesV3 {
        source_configuration_commitment: state.source_configuration_commitment,
        predecessor_state_commitment: checkpoint_values.selected_state_commitment,
        predecessor_height: state.tip.height,
        predecessor_frontier_commitment: checkpoint_values.frontier_commitment,
        predecessor_event_stream_commitment: checkpoint.event_stream_commitment,
        successor_state_commitment: [11; 32],
        successor_height: state.tip.height,
        successor_tip_hash_internal: [12; 32],
        successor_frontier_commitment: [13; 32],
        successor_event_stream_commitment: [14; 32],
        step_count: 2,
        first_discovery_sequence: 1,
        final_discovery_sequence: 2,
    };
    // Selection can remain at a prior best-work tip while newly discovered
    // competing branches advance the event cursor. Do not force tip sequence
    // or selected height to equal the final global discovery sequence.
    let second = FullAlphaTransitionPublicValuesV3 {
        source_configuration_commitment: first.source_configuration_commitment,
        predecessor_state_commitment: first.successor_state_commitment,
        predecessor_height: first.successor_height,
        predecessor_frontier_commitment: first.successor_frontier_commitment,
        predecessor_event_stream_commitment: first.successor_event_stream_commitment,
        successor_state_commitment: state.commitment().unwrap(),
        successor_height: state.tip.height,
        successor_tip_hash_internal: state.tip.block_hash.to_byte_array(),
        successor_frontier_commitment: [15; 32],
        successor_event_stream_commitment: [16; 32],
        step_count: 1,
        first_discovery_sequence: 3,
        final_discovery_sequence: 3,
    };
    FullAlphaAdapterInputV3 {
        version: FULL_ALPHA_ADAPTER_INPUT_VERSION_V3,
        binding: AlphaRecursiveBindingV3 {
            source_configuration_commitment: state.source_configuration_commitment,
            reviewed_checkpoint_input_commitment: checkpoint_values.checkpoint_input_commitment,
            checkpoint_program_id: [2; 32],
            transition_program_id: [3; 32],
        },
        checkpoint_input: encode_reviewed_alpha_checkpoint_input_v3(&checkpoint).unwrap(),
        checkpoint_receipt: AlphaRecursiveReceiptBindingV3 {
            public_values: checkpoint_values.canonical_bytes().to_vec(),
            proof_marker: vec![0xa0],
        },
        transition_receipts: vec![
            AlphaRecursiveReceiptBindingV3 {
                public_values: first.canonical_bytes().to_vec(),
                proof_marker: vec![0xa1],
            },
            AlphaRecursiveReceiptBindingV3 {
                public_values: second.canonical_bytes().to_vec(),
                proof_marker: vec![0xa2],
            },
        ],
        terminal_selected_state: state,
    }
}

#[test]
fn adapter_calls_every_receipt_and_binds_exact_alpha_state_statement() {
    let input = input();
    let verifier = TranscriptVerifier::new(&input);
    let statement = execute_full_alpha_adapter_v3(&input, &verifier).unwrap();
    assert_eq!(*verifier.calls.borrow(), verifier.expected);
    let encoded = encode_full_alpha_adapter_input_v3(&input).unwrap();
    assert_eq!(decode_full_alpha_adapter_input_v3(&encoded).unwrap(), input);
    let public = encode_full_alpha_statement_v3(&statement).unwrap();
    assert_eq!(public.len(), 529);
    assert_eq!(decode_full_alpha_statement_v3(&public).unwrap(), statement);
    assert_eq!(statement.binding, input.binding);
    assert_eq!(
        statement.final_all_slots_state_commitment,
        input
            .terminal_selected_state
            .bip300_state
            .commitment()
            .unwrap()
    );
    assert_ne!(
        statement.final_all_slots_state_commitment,
        input
            .terminal_selected_state
            .bip300_state
            .as_state()
            .commitment()
            .unwrap()
    );
    assert_eq!(
        statement.terminal_chainwork_be,
        input.terminal_selected_state.tip.chainwork_be
    );
    assert_eq!(statement.final_event_sequence, 3);
    assert_eq!(statement.terminal_selected_height, ALPHA_FORK_HEIGHT_V3 - 1);
    assert_eq!(input.terminal_selected_state.tip.discovery_sequence, 0);
}

#[test]
fn adapter_never_substitutes_marker_checks_for_recursive_verification() {
    let input = input();
    assert_eq!(
        execute_full_alpha_adapter_v3(&input, &RejectEveryReceipt),
        Err(FullAlphaAdapterErrorV3::Receipt)
    );
    for index in 0..3 {
        let mut verifier = TranscriptVerifier::new(&input);
        verifier.expected.remove(index);
        assert_eq!(
            execute_full_alpha_adapter_v3(&input, &verifier),
            Err(FullAlphaAdapterErrorV3::Receipt)
        );
        assert_eq!(verifier.calls.borrow().len(), index + 1);
    }
}

#[test]
fn adapter_rejects_invalid_or_substituted_program_and_checkpoint_bindings() {
    let original = input();
    for id in [[0; 32], [0xff; 32]] {
        for checkpoint in [true, false] {
            let mut changed = original.clone();
            if checkpoint {
                changed.binding.checkpoint_program_id = id;
            } else {
                changed.binding.transition_program_id = id;
            }
            assert_eq!(
                execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
                Err(FullAlphaAdapterErrorV3::Binding)
            );
        }
    }
    let mut modulus = [0; 32];
    modulus[..4].copy_from_slice(&KOALA_BEAR_MODULUS.to_be_bytes());
    assert!(!alpha_sp1_program_id_is_canonical_v3(modulus));
    modulus[..4].copy_from_slice(&(KOALA_BEAR_MODULUS - 1).to_be_bytes());
    assert!(alpha_sp1_program_id_is_canonical_v3(modulus));
    let mut changed = original.clone();
    changed.binding.transition_program_id = changed.binding.checkpoint_program_id;
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::Binding)
    );
    for checkpoint in [true, false] {
        let mut changed = original.clone();
        if checkpoint {
            changed.binding.checkpoint_program_id = [4; 32];
        } else {
            changed.binding.transition_program_id = [4; 32];
        }
        assert_ne!(
            changed.binding.commitment().unwrap(),
            original.binding.commitment().unwrap()
        );
        assert_eq!(
            execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&original)),
            Err(FullAlphaAdapterErrorV3::Receipt)
        );
    }
    let mut changed = original.clone();
    changed.binding.reviewed_checkpoint_input_commitment[0] ^= 1;
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::Checkpoint)
    );
    let mut changed = original;
    changed.binding.source_configuration_commitment[0] ^= 1;
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::Checkpoint)
    );
}

#[test]
fn adapter_rejects_every_transition_continuity_substitution_even_with_accepted_receipts() {
    let original = input();
    for index in 0..2 {
        for field in 0..7 {
            let mut changed = original.clone();
            let mut values = decode_full_alpha_transition_public_values_v3(
                &changed.transition_receipts[index].public_values,
            )
            .unwrap();
            match field {
                0 => values.source_configuration_commitment[0] ^= 1,
                1 => values.predecessor_state_commitment[0] ^= 1,
                2 => values.predecessor_height += 1,
                3 => values.predecessor_frontier_commitment[0] ^= 1,
                4 => values.predecessor_event_stream_commitment[0] ^= 1,
                5 => {
                    values.first_discovery_sequence += 1;
                    values.final_discovery_sequence += 1;
                }
                6 => {
                    values.step_count = 65;
                    values.final_discovery_sequence = values.first_discovery_sequence + 64;
                }
                _ => unreachable!(),
            }
            changed.transition_receipts[index].public_values = values.canonical_bytes().to_vec();
            // Accept the changed transcript at the verifier boundary so this
            // specifically tests adapter continuity, not signature failure.
            assert_eq!(
                execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
                Err(FullAlphaAdapterErrorV3::TransitionChain),
                "receipt {index}, field {field}"
            );
        }
    }
    let mut changed = original.clone();
    changed.transition_receipts.remove(0);
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::TransitionChain)
    );
    let mut changed = original.clone();
    changed.transition_receipts.swap(0, 1);
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::TransitionChain)
    );
    let mut changed = original.clone();
    changed
        .transition_receipts
        .push(changed.transition_receipts[1].clone());
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::TransitionChain)
    );
    let mut changed = original;
    changed.transition_receipts.clear();
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &RejectEveryReceipt),
        Err(FullAlphaAdapterErrorV3::NonCanonicalInput)
    );
}

#[test]
fn adapter_rejects_terminal_preimage_and_endpoint_substitutions() {
    let original = input();
    for field in 0..6 {
        let mut changed = original.clone();
        match field {
            0 => changed.terminal_selected_state.utxo_root.hash[0] ^= 1,
            1 => changed.terminal_selected_state.tip.chainwork_be[0] ^= 1,
            2 => {
                changed
                    .terminal_selected_state
                    .pow_context
                    .previous_11_times[0] -= 1
            }
            3 => {
                changed
                    .terminal_selected_state
                    .pow_context
                    .retarget_epoch_start_time += 1
            }
            4 => {
                changed
                    .terminal_selected_state
                    .source_configuration_commitment[0] ^= 1
            }
            5 => changed.terminal_selected_state.tip.discovery_sequence += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
            Err(FullAlphaAdapterErrorV3::TerminalState),
            "terminal field {field}"
        );
    }
    for field in 0..3 {
        let mut changed = original.clone();
        let mut values = decode_full_alpha_transition_public_values_v3(
            &changed.transition_receipts[1].public_values,
        )
        .unwrap();
        match field {
            0 => values.successor_state_commitment[0] ^= 1,
            1 => values.successor_height += 1,
            2 => values.successor_tip_hash_internal[0] ^= 1,
            _ => unreachable!(),
        }
        changed.transition_receipts[1].public_values = values.canonical_bytes().to_vec();
        assert_eq!(
            execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
            Err(FullAlphaAdapterErrorV3::TerminalState)
        );
    }
}

#[test]
fn adapter_rejects_signet_wrong_profile_and_noncanonical_wire() {
    let original = input();
    let mut signet = original.clone();
    signet
        .terminal_selected_state
        .deployment_state
        .network_genesis = genesis_block(Network::Signet).block_hash();
    assert_eq!(
        execute_full_alpha_adapter_v3(&signet, &TranscriptVerifier::new(&signet)),
        Err(FullAlphaAdapterErrorV3::TerminalState)
    );
    for field in 0..3 {
        let mut changed = original.clone();
        match field {
            0 => changed.transition_receipts[0].public_values[0] = 3,
            1 => changed.transition_receipts[0].public_values[1] ^= 1,
            2 => {
                changed.transition_receipts[0].public_values.drain(1..33);
            }
            _ => unreachable!(),
        }
        assert!(
            execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)).is_err()
        );
    }
    let mut changed = original.clone();
    changed.checkpoint_input[0] = 2;
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::Checkpoint)
    );
    let mut changed = original.clone();
    changed.checkpoint_receipt.public_values[1] ^= 1;
    assert_eq!(
        execute_full_alpha_adapter_v3(&changed, &TranscriptVerifier::new(&changed)),
        Err(FullAlphaAdapterErrorV3::Checkpoint)
    );
    let mut encoded = encode_full_alpha_adapter_input_v3(&original).unwrap();
    encoded.push(0);
    assert!(decode_full_alpha_adapter_input_v3(&encoded).is_err());
    encoded.pop();
    encoded[0] = 2;
    assert!(decode_full_alpha_adapter_input_v3(&encoded).is_err());
    let mut json = serde_json::to_value(original).unwrap();
    json["terminal_selected_state"]["pow_context"]["network"] = serde_json::json!("signet");
    assert!(serde_json::from_value::<FullAlphaAdapterInputV3>(json).is_err());
}

#[test]
fn alpha_statement_commits_all_bindings_and_rejects_relabelled_journals() {
    let input = input();
    let statement =
        execute_full_alpha_adapter_v3(&input, &TranscriptVerifier::new(&input)).unwrap();
    let encoded = encode_full_alpha_statement_v3(&statement).unwrap();
    for field in 0..7 {
        let mut changed = statement;
        match field {
            0 => changed.binding.reviewed_checkpoint_input_commitment[0] ^= 1,
            1 => changed.initial_all_slots_state_commitment[0] ^= 1,
            2 => changed.final_all_slots_state_commitment[0] ^= 1,
            3 => changed.final_frontier_commitment[0] ^= 1,
            4 => changed.final_event_stream_commitment[0] ^= 1,
            5 => changed.terminal_chainwork_be[0] ^= 1,
            6 => changed.terminal_mtp += 1,
            _ => unreachable!(),
        }
        assert_ne!(encode_full_alpha_statement_v3(&changed).unwrap(), encoded);
    }
    let mut changed = encoded.clone();
    changed[0] = 2;
    assert!(decode_full_alpha_statement_v3(&changed).is_err());
    let mut changed = encoded.clone();
    changed[1] ^= 1;
    assert!(decode_full_alpha_statement_v3(&changed).is_err());
    let mut changed = encoded;
    changed.push(0);
    assert!(decode_full_alpha_statement_v3(&changed).is_err());
}

#[test]
fn relay_bootstrap_requires_pinned_binding_and_authenticated_receipts() {
    use crate::relay_bootstrap_v3::{authenticate_relay_bootstrap_v3,RelayBootstrapErrorV3};
    use bitcoin::hashes::{sha256,Hash as _};
    let input=input();
    let verifier=TranscriptVerifier::new(&input);
    let bootstrap=authenticate_relay_bootstrap_v3(&input,&input.binding,&verifier).unwrap();
    let statement=execute_full_alpha_adapter_v3(&input,&verifier).unwrap();
    let bytes=encode_full_alpha_statement_v3(&statement).unwrap();
    assert_eq!(bootstrap.public_values,bytes);
    assert_eq!(bootstrap.public_values.len(),529);
    assert_eq!(bootstrap.height,statement.terminal_selected_height);
    assert_eq!(bootstrap.journal_sha256,sha256::Hash::hash(&bytes).to_byte_array());
    assert_eq!(bootstrap.binding_sha256,sha256::Hash::hash(&bytes[1..161]).to_byte_array());
    assert_eq!(bootstrap.cursor,crate::relay_continuation_v3::AlphaRelayCursorV3::terminal(&statement).commitment().unwrap());
    for field in 0..4 {
        let mut expected=input.binding;
        match field {
            0=>expected.source_configuration_commitment[0]^=1,
            1=>expected.reviewed_checkpoint_input_commitment[0]^=1,
            2=>expected.checkpoint_program_id[3]^=1,
            _=>expected.transition_program_id[3]^=1,
        }
        assert_eq!(authenticate_relay_bootstrap_v3(&input,&expected,&verifier),Err(RelayBootstrapErrorV3::Binding));
    }
    assert_eq!(authenticate_relay_bootstrap_v3(&input,&input.binding,&RejectEveryReceipt),
        Err(RelayBootstrapErrorV3::Authentication));
}
