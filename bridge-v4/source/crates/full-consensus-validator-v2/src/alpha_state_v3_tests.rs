use super::*;
use crate::script_v2::*;
use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness};
use std::collections::HashSet;
use std::str::FromStr;

// Shape/commitment fixture only: deliberately synthetic and NOT a checkpoint
// claim, chain replay, or production evidence.
pub(crate) fn synthetic_state() -> AlphaExecutedConsensusStateV3 {
    let base = crate::state_frontier_v2::tests::executed_state();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
    let height = ALPHA_FORK_HEIGHT_V3 - 1;
    let mut inner = AlphaBip300AllSlotStateV3::before_genesis()
        .as_state()
        .clone();
    inner.next_height = height + 1;
    inner.tip_hash = Some(genesis.block_hash());
    let mut deployment = base.deployment_state;
    deployment.network_genesis = genesis.block_hash();
    deployment.terminal_checkpoint_height = height;
    deployment.terminal_checkpoint_hash = genesis.block_hash();
    for anchor in &mut deployment.activation_anchors {
        anchor.activation_block_hash = genesis.block_hash();
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
        utxo_root: base.utxo_root,
        bip300_state: AlphaBip300AllSlotStateV3::from_authenticated_state(inner).unwrap(),
        deployment_state: deployment,
    }
}

#[test]
fn alpha_native_repurpose_set_is_exact_unique_and_internal_endian() {
    assert_eq!(repurpose::ALPHA_REPURPOSE_TXIDS_INTERNAL.len(), 220);
    assert_eq!(
        repurpose::ALPHA_REPURPOSE_TXIDS_INTERNAL
            .into_iter()
            .collect::<HashSet<_>>()
            .len(),
        220
    );
    let txid =
        Txid::from_str("20fb9c22d2e4448ef6771024292eb12381e9b17f8a7808dd1e47f25dc92ee273").unwrap();
    assert!(alpha_repurpose_txid_v3(txid));
    let mut reversed = txid.to_byte_array();
    reversed.reverse();
    assert!(!alpha_repurpose_txid_v3(Txid::from_byte_array(reversed)));
    assert!(!alpha_repurpose_txid_v3(Txid::all_zeros()));
    // Independent hashlib calculation from the 220 native source txids.
    assert_eq!(
        hex::encode(alpha_repurpose_set_commitment_v3()),
        "18955e1a29342dd5da4caafc5dbcd575c8706c1be8430b851258cfb1e0a6f54c"
    );
    assert_eq!(
        hex::encode(alpha_consensus_profile_commitment_v3()),
        "46099ba39a9207f5fd93696d54dc6fb9c2ae07d60d338dd169ef47b72c843c23"
    );
    // The previous profile omitted Alpha's native absolute-locktime sentinel.
    assert_ne!(hex::encode(alpha_consensus_profile_commitment_v3()),
        "284873fab56eacbc78e65b358ae2bfe05081e452b6c8509f7733ae555b30e8e6");
    assert_ne!(
        hex::encode(alpha_consensus_profile_commitment_v3()),
        "e8f7f6095d8c5213daae7579588ddc1b0e151946c413378050d211a9a981e117"
    );
}

#[test]
fn alpha_four_byte_drivechain_exits_before_decoding_trailing_bytes() {
    let alpha = ScriptLockContextV2 {
        alpha_drivechain: true,
        ..Default::default()
    };
    for script in [
        [0xb4, 0x4e, 0xff, 0xff],
        [0xb4, 0x6a, 0x65, 0x66],
        [0xb4, 0, 0, 0],
    ] {
        assert_eq!(
            execute_script_with_locks_v2(&script, vec![], false, false, alpha).unwrap(),
            vec![vec![0xdc]]
        );
        assert!(
            execute_script_with_locks_v2(&script, vec![], false, false, Default::default())
                .map(|v| v != vec![vec![0xdc]])
                .unwrap_or(true)
        );
    }
    // Other lengths/positions never gain early success; Alpha's ordinary NOP
    // path, unlike Bitcoin's upgradeable NOP, ignores DISCOURAGE_NOPS.
    assert!(execute_script_with_locks_v2(&[0xb4, 0x6a], vec![], false, false, alpha).is_err());
    assert!(
        execute_script_with_locks_v2(&[0x61, 0xb4, 0x6a, 0x00], vec![], false, false, alpha)
            .is_err()
    );
    let discouraged = ScriptLockContextV2 {
        discourage_upgradable_nops: true,
        ..alpha
    };
    assert_eq!(
        execute_script_with_locks_v2(&[0xb4], vec![], false, false, discouraged).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert!(execute_script_with_locks_v2(
        &[0xb4],
        vec![],
        false,
        false,
        ScriptLockContextV2 {
            alpha_drivechain: false,
            ..discouraged
        }
    )
    .is_err());
    assert!(execute_script_with_locks_v2(
        &[0xb4, 0, 0, 0],
        vec![vec![]; 1000],
        false,
        false,
        alpha
    )
    .is_err());
}

fn spend(script_sig: Vec<u8>, witness: Witness) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![],
    }
}

#[test]
fn alpha_script_rule_is_fixed_and_legacy_bitcoin_is_unchanged() {
    let flags = alpha_terminal_execution_parameters_v3().active_script_flags;
    let output = TxOut {
        value: Amount::from_sat(100),
        script_pubkey: ScriptBuf::from_bytes(vec![0xb4, 0x4e, 0xff, 0xff]),
    };
    let tx = spend(vec![], Witness::new());
    assert!(!alpha_repurpose_txid_v3(tx.compute_txid()));
    assert!(AlphaScriptVerifierV3
        .verify_input(&tx, 0, &[output.clone()], flags)
        .is_ok());
    assert!(crate::FullBitcoinScriptVerifierV2
        .verify_input(&tx, 0, &[output.clone()], flags)
        .is_err());
    assert!(AlphaScriptVerifierV3
        .verify_input(
            &spend(vec![0x6a], Witness::new()),
            0,
            &[output.clone()],
            flags
        )
        .is_err());
    assert!(AlphaScriptVerifierV3
        .verify_input(
            &spend(vec![], Witness::from_slice(&[vec![1]])),
            0,
            &[output],
            flags
        )
        .is_err());
    // The native allowlist must not become a general invalid-script bypass.
    assert!(AlphaScriptVerifierV3
        .verify_input(
            &tx,
            0,
            &[TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a])
            }],
            flags
        )
        .is_err());
}

#[test]
fn alpha_p2sh_and_witness_v0_route_the_same_native_opcode() {
    let flags = alpha_terminal_execution_parameters_v3().active_script_flags;
    let script = ScriptBuf::from_bytes(vec![0xb4, 0x4e, 0xff, 0xff]);
    let p2sh = TxOut {
        value: Amount::from_sat(100),
        script_pubkey: script.to_p2sh(),
    };
    let tx = spend(vec![4, 0xb4, 0x4e, 0xff, 0xff], Witness::new());
    assert!(AlphaScriptVerifierV3
        .verify_input(&tx, 0, &[p2sh], flags)
        .is_ok());
    let p2wsh = TxOut {
        value: Amount::from_sat(100),
        script_pubkey: script.to_p2wsh(),
    };
    assert!(AlphaScriptVerifierV3
        .verify_input(
            &spend(vec![], Witness::from_slice(&[script.as_bytes()])),
            0,
            &[p2wsh.clone()],
            flags
        )
        .is_ok());
    assert!(AlphaScriptVerifierV3
        .verify_input(
            &spend(vec![], Witness::from_slice(&[vec![1], script.to_bytes()])),
            0,
            &[p2wsh],
            flags
        )
        .is_err());
}

#[test]
fn alpha_state_commits_every_context_and_rejects_other_network_rules() {
    let state = synthetic_state();
    state.validate().unwrap();
    let commitment = state.commitment().unwrap();
    let mut changed = state.clone();
    changed.pow_context.retarget_epoch_start_time += 1;
    assert_ne!(changed.commitment().unwrap(), commitment);
    let mut changed = state.clone();
    changed.utxo_root.aggregate.value_atoms += 1;
    assert_ne!(changed.commitment().unwrap(), commitment);
    let mut changed = state.clone();
    changed.source_configuration_commitment[0] ^= 1;
    assert_ne!(changed.commitment().unwrap(), commitment);
    let mut inner = state.bip300_state.as_state().clone();
    inner.consensus_parameters.withdrawal_max_age = 10;
    assert!(AlphaBip300AllSlotStateV3::from_authenticated_state(inner).is_err());
    let mut changed = state.clone();
    changed.deployment_state.network_genesis =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet).block_hash();
    assert!(changed.validate().is_err());
    let mut json = serde_json::to_value(&state).unwrap();
    json["pow_context"]["network"] = serde_json::json!("signet");
    assert!(serde_json::from_value::<AlphaExecutedConsensusStateV3>(json).is_err());
    let mut json = serde_json::to_value(&state).unwrap();
    json["execution_parameters"] = serde_json::json!({"active_script_flags": 0});
    assert!(serde_json::from_value::<AlphaExecutedConsensusStateV3>(json).is_err());
    assert_eq!(
        state
            .bip300_state
            .as_state()
            .consensus_parameters
            .withdrawal_max_age,
        144
    );
    assert_eq!(
        state
            .bip300_state
            .as_state()
            .consensus_parameters
            .withdrawal_inclusion_threshold,
        72
    );
}

#[test]
fn alpha_execution_does_not_accept_header_only_or_unauthenticated_rule_overrides() {
    let state = synthetic_state();
    let step = AlphaBlockEvidenceStepV3 {
        raw_block: vec![],
        authenticated_adjusted_time: 1_800_000_000,
        utxo_witness: BitcoinBlockUtxoWitnessV2 {
            transactions: vec![],
        },
    };
    assert!(execute_alpha_executed_successor_v3(&state, &step, 1).is_err());
    // The deposit-effects entry point must not leak effects for an invalid
    // block or bypass the existing complete-execution rejection path.
    assert_eq!(
        execute_alpha_executed_successor_with_effects_v3(&state, &step, 1)
            .map(|(next, _)| next),
        execute_alpha_executed_successor_v3(&state, &step, 1),
    );
    let mut json = serde_json::to_value(&step).unwrap();
    json["network"] = serde_json::json!("regtest");
    assert!(serde_json::from_value::<AlphaBlockEvidenceStepV3>(json).is_err());
}
