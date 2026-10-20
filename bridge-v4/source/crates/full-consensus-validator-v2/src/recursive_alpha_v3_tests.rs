use super::*;
use crate::alpha_state_v3::tests::synthetic_state;
use crate::state_frontier_v2::{
    canonical_empty_executed_frontier_path_v2, canonical_empty_executed_frontier_root_v2,
};
use crate::BitcoinBlockUtxoWitnessV2;

fn values() -> FullAlphaTransitionPublicValuesV3 {
    FullAlphaTransitionPublicValuesV3 {
        source_configuration_commitment: [1; 32],
        predecessor_state_commitment: [2; 32],
        predecessor_height: 963647,
        predecessor_frontier_commitment: [4; 32],
        predecessor_event_stream_commitment: [5; 32],
        successor_state_commitment: [6; 32],
        successor_height: 963648,
        successor_tip_hash_internal: [8; 32],
        successor_frontier_commitment: [9; 32],
        successor_event_stream_commitment: [10; 32],
        step_count: 11,
        first_discovery_sequence: 12,
        final_discovery_sequence: 22,
    }
}

// Canonical-shape/membership fixture only. Its deliberately empty block MUST
// fail execution; it is not Alpha replay or an authenticated checkpoint.
fn shape_input() -> FullAlphaTransitionInputV3 {
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
    FullAlphaTransitionInputV3 {
        version: FULL_ALPHA_TRANSITION_INPUT_VERSION_V3,
        predecessor_selected: state.clone(),
        predecessor_frontier: frontier,
        predecessor_selected_membership_path: path.clone(),
        predecessor_event_stream_commitment: [9; 32],
        discovered_blocks: vec![FullAlphaDiscoveredBlockV3 {
            parent: state.clone(),
            parent_membership_path: path.clone(),
            step: AlphaBlockEvidenceStepV3 {
                raw_block: vec![],
                authenticated_adjusted_time: 1_800_000_000,
                utxo_witness: BitcoinBlockUtxoWitnessV2 {
                    transactions: vec![],
                },
            },
            insertion_path: path.clone(),
        }],
        successor_selected: state,
        successor_selected_membership_path: path,
    }
}

#[test]
fn compact_transport_is_separately_versioned_and_strict() {
    let old = shape_input();
    let legacy_bytes = encode_full_alpha_transition_input_v3(&old).unwrap();
    // Generic step representation must preserve the original wire bytes.
    assert_eq!(canonical_options().serialize(&old).unwrap(), legacy_bytes);
    let compact = FullAlphaTransitionInputV3 {
        version: COMPACT_ALPHA_TRANSITION_INPUT_VERSION,
        predecessor_selected: old.predecessor_selected,
        predecessor_frontier: old.predecessor_frontier,
        predecessor_selected_membership_path: old.predecessor_selected_membership_path,
        predecessor_event_stream_commitment: old.predecessor_event_stream_commitment,
        discovered_blocks: old.discovered_blocks.into_iter().map(|event| FullAlphaDiscoveredBlockV3 {
            parent: event.parent,
            parent_membership_path: event.parent_membership_path,
            step: CompactAlphaBlockEvidenceStep {
                raw_block: event.step.raw_block,
                authenticated_adjusted_time: event.step.authenticated_adjusted_time,
                utxo_frame: vec![],
            },
            insertion_path: event.insertion_path,
        }).collect(),
        successor_selected: old.successor_selected,
        successor_selected_membership_path: old.successor_selected_membership_path,
    };
    let bytes = encode_compact_alpha_transition_input(&compact).unwrap();
    assert_eq!(decode_compact_alpha_transition_input(&bytes).unwrap(), compact);
    assert!(decode_full_alpha_transition_input_v3(&bytes).is_err());
    assert!(decode_compact_alpha_transition_input(&legacy_bytes).is_err());
    assert!(execute_compact_alpha_transition(&compact).is_err()); // no valid block
    let mut trailing = bytes.clone(); trailing.push(0);
    assert!(decode_compact_alpha_transition_input(&trailing).is_err());
    for length in [0, 1, bytes.len()/2, bytes.len()-1] {
        assert!(decode_compact_alpha_transition_input(&bytes[..length]).is_err());
    }
    let mut bad = compact.clone(); bad.version = FULL_ALPHA_TRANSITION_INPUT_VERSION_V3;
    assert!(encode_compact_alpha_transition_input(&bad).is_err());
    let mut bad = compact.clone(); bad.discovered_blocks.clear();
    assert!(encode_compact_alpha_transition_input(&bad).is_err());
    let mut bad = compact;
    bad.discovered_blocks[0].step.utxo_frame = vec![0; MAX_FULL_ALPHA_TRANSITION_INPUT_BYTES_V3];
    assert!(encode_compact_alpha_transition_input(&bad).is_err());
}

#[test]
fn alpha_journal_is_fixed_profile_bound_and_cannot_decode_as_bitcoin() {
    let values = values();
    let bytes = values.canonical_bytes();
    assert_eq!(bytes.len(), 333);
    assert_eq!(bytes[0], 0xa3);
    assert_eq!(&bytes[1..33], &alpha_consensus_profile_commitment_v3());
    assert_eq!(
        decode_full_alpha_transition_public_values_v3(&bytes).unwrap(),
        values
    );
    assert!(
        crate::recursive_bitcoin_v2::decode_full_bitcoin_transition_public_values_v2(&bytes)
            .is_err()
    );
    // Relabelling a legacy-sized journal cannot create an Alpha journal.
    let mut legacy_sized = bytes.to_vec();
    legacy_sized.drain(1..33);
    assert!(decode_full_alpha_transition_public_values_v3(&legacy_sized).is_err());
    let commitment = values.commitment();
    for index in 1..33 {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(decode_full_alpha_transition_public_values_v3(&changed).is_err());
    }
    let mut changed = bytes;
    changed[0] = 3;
    assert!(decode_full_alpha_transition_public_values_v3(&changed).is_err());
    let mut changed = values;
    changed.successor_state_commitment[0] ^= 1;
    assert_ne!(changed.commitment(), commitment);
    let mut changed = values;
    changed.successor_frontier_commitment[0] ^= 1;
    assert_ne!(changed.commitment(), commitment);
    let mut changed = values;
    changed.successor_event_stream_commitment[0] ^= 1;
    assert_ne!(changed.commitment(), commitment);
    let mut changed = bytes;
    *changed.last_mut().unwrap() ^= 1;
    assert!(decode_full_alpha_transition_public_values_v3(&changed).is_err());
    let mut changed = values;
    changed.step_count = 0;
    assert!(decode_full_alpha_transition_public_values_v3(&changed.canonical_bytes()).is_err());
}

#[test]
#[ignore = "requires separately built ALPHA_TRANSITION_INSPECTOR executable"]
fn alpha_inspector_reads_canonical_bytes_without_claiming_execution() {
    // Opt-in integration test against the separately built host inspector.
    let inspector = std::env::var("ALPHA_TRANSITION_INSPECTOR")
        .expect("set ALPHA_TRANSITION_INSPECTOR to the built example executable");
    let mut input = shape_input();
    // Journal-compatible bytes, deliberately not a valid executable block.
    input.discovered_blocks[0].step.raw_block = vec![0; 81];
    let encoded = encode_full_alpha_transition_input_v3(&input).unwrap();
    let directory = std::env::temp_dir().join(format!("alpha-inspector-test-{}-{}",
        std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("shape-only.bin");
    std::fs::write(&path, &encoded).unwrap();
    let output = std::process::Command::new(&inspector).arg(&path).output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    use sha2::{Digest, Sha256};
    let sequence = input.predecessor_frontier.maximum_discovery_sequence.unwrap();
    let expected = serde_json::json!({
        "stage": "canonical-decoded-not-executed",
        "input_sha256": hex::encode(Sha256::digest(&encoded)),
        "predecessor_discovery_sequence": sequence.to_string(),
        "predecessor_state_commitment": hex::encode(input.predecessor_selected.commitment().unwrap()),
        "predecessor_frontier_commitment": hex::encode(executed_frontier_root_commitment_v2(input.predecessor_frontier).unwrap()),
        "source_configuration_commitment": hex::encode(input.predecessor_selected.source_configuration_commitment),
        "predecessor_event_stream_commitment": hex::encode(input.predecessor_event_stream_commitment),
        "steps": [{
            "raw_block": "00".repeat(81),
            "authenticated_adjusted_time": 1_800_000_000u64,
            "discovery_sequence": (sequence + 1).to_string(),
        }],
    });
    assert_eq!(actual, expected);
    assert!(execute_full_alpha_transition_v3(&input).is_err());
    if let Ok(harness) = std::env::var("ALPHA_BINDING_HARNESS") {
        let expectations = directory.join("test-only-expectations.json");
        std::fs::write(&expectations, serde_json::to_vec(&expected).unwrap()).unwrap();
        let result = std::process::Command::new("python3").arg(harness)
            .arg(&path).arg(&inspector).arg(&expectations).output().unwrap();
        assert!(result.status.success(), "{:?}", result.stderr);
        assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "real-inspector-binding-test-passed");
        std::fs::remove_file(expectations).unwrap();
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    for invalid in [trailing, vec![], { let mut wrong = encoded; wrong[0] = 4; wrong }] {
        std::fs::write(&path, invalid).unwrap();
        let output = std::process::Command::new(&inspector).arg(&path).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&directory).unwrap();
}

#[test]
fn alpha_input_is_canonical_but_shape_alone_never_establishes_execution() {
    let input = shape_input();
    let encoded = encode_full_alpha_transition_input_v3(&input).unwrap();
    assert_eq!(
        decode_full_alpha_transition_input_v3(&encoded).unwrap(),
        input
    );
    assert!(execute_full_alpha_transition_v3(&input).is_err());
    assert!(
        crate::recursive_bitcoin_v2::decode_full_bitcoin_transition_input_v2(&encoded).is_err()
    );
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(decode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = encoded;
    changed[0] = 4;
    assert!(decode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = input.clone();
    changed.discovered_blocks.clear();
    assert!(encode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = input;
    changed.predecessor_frontier.best = None;
    assert!(execute_full_alpha_transition_v3(&changed).is_err());
}

#[test]
fn alpha_every_branch_has_the_same_fixed_source_and_deployments() {
    let input = shape_input();
    let mut changed = input.clone();
    changed.discovered_blocks[0]
        .parent
        .source_configuration_commitment[0] ^= 1;
    assert!(encode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = input.clone();
    changed.successor_selected.source_configuration_commitment[0] ^= 1;
    assert!(encode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = input.clone();
    changed.discovered_blocks[0]
        .parent
        .deployment_state
        .terminal_checkpoint_hash = bitcoin::BlockHash::all_zeros();
    assert!(encode_full_alpha_transition_input_v3(&changed).is_err());
    let mut changed = serde_json::to_value(&input).unwrap();
    changed["discovered_blocks"][0]["step"]["network"] = serde_json::json!("signet");
    assert!(serde_json::from_value::<FullAlphaTransitionInputV3>(changed).is_err());
    let mut changed = serde_json::to_value(&input).unwrap();
    changed["discovered_blocks"][0]["step"]["withdrawal_max_age"] = serde_json::json!(10);
    assert!(serde_json::from_value::<FullAlphaTransitionInputV3>(changed).is_err());
}
