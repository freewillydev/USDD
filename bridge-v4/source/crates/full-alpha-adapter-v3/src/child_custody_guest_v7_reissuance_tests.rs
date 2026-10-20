//! Synthetic signed minting through the public V7 executor, not a live or
//! recursive-proof qualification. The authority token remains spendable.
use super::*;
use ecx_full_consensus_validator_v2::elements_v2::*;
use elements::{confidential::{Asset, Value, Nonce}, Script};

fn rebind(input: &mut CustodyExecutionInputV7) {
    let inner = &mut input.anchor.execution;
    let hash = crate::effective_child_configuration_v1::EffectiveChildConfigurationV2::from_policies(
        &input.policy, &inner.header_policy, &inner.deposit_policy).unwrap().commitment();
    input.policy.base.consensus_configuration_commitment = hash;
    inner.policy = input.policy.base;
    inner.checkpoint.execution.configuration_commitment = hash;
    inner.binding.roots.execution.execution_policy = input.policy.commitment().unwrap();
    inner.binding.roots.execution.predecessor_checkpoint = inner.checkpoint.commitment().unwrap();
    inner.parent.binding.child_consensus_configuration_commitment = hash;
    inner.binding.roots.execution.parent_binding = inner.parent.binding.commitment().unwrap();
    let history = crate::native_header_v3::NativeHeader::decode(inner.history.last().unwrap(), true).unwrap();
    let mut environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(&inner.environment).unwrap();
    environment.bind_custody_checkpoint_projection(&inner.checkpoint,
        inner.checkpoint.commitment().unwrap(), &history).unwrap();
    inner.environment = environment.encode().unwrap();
    inner.binding.roots.environment = environment.commitment().unwrap();
    input.anchor.checkpoint.projection = inner.checkpoint.clone();
}

pub(super) fn qualify_reissuance<S: ElementsSimplicityReceiptVerifierV2>(
    original: &CustodyExecutionInputV7, simplicity: &S,
) {
    let mut input = original.clone();
    let inner = &mut input.anchor.execution;
    let mut block = crate::native_block_wire_v3::NativeBlock::decode(&inner.raw_block).unwrap();
    let mut previous = inner.witnesses[1].utxo.spends[0].old_leaf.clone().unwrap();
    let mut txin = elements::TxIn { previous_output: previous.outpoint, ..Default::default() };
    txin.asset_issuance.asset_entropy = [21;32];
    let mut marker = [0;32]; marker[0] = 1;
    txin.asset_issuance.asset_blinding_nonce = elements::secp256k1_zkp::Tweak::from_slice(&marker).unwrap();
    txin.asset_issuance.amount = Value::Explicit(1_000);
    let (asset, token) = txin.issuance_ids();
    let output = |asset, amount| elements::TxOut {
        asset: Asset::Explicit(asset), value: Value::Explicit(amount), nonce: Nonce::Null,
        script_pubkey: previous.output.script_pubkey.clone(), witness: Default::default(),
    };
    let mut tx = elements::Transaction { version: 3, lock_time: elements::LockTime::ZERO,
        input: vec![txin], output: vec![output(asset, 1_000), output(token, 1)] };
    previous.output = output(token, 1);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[23;32]).unwrap();
    // Issuance legacy signing serializes the bare prevout in native Elements;
    // rust-elements' transaction-wire flags are not the native signing bytes.
    let digest = ecx_full_consensus_validator_v2::elements_sighash_v3::elements_ecdsa_sighash_v3(
        &tx, 0, previous.output.script_pubkey.as_bytes(), None, 1, false).unwrap();
    let mut sig = secp.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest(digest), &key)
        .serialize_der().to_vec();
    sig.push(elements::EcdsaSighashType::All.as_u32() as u8);
    let mut unlock = vec![sig.len() as u8]; unlock.extend(sig);
    tx.input[0].script_sig = Script::from(unlock);

    let class = ElementsCustodyClassificationV3 {
        native_pegged_asset_id: inner.policy.classification.native_pegged_asset_id,
        custody_asset_id: asset.into_inner().to_byte_array(),
    };
    let economic = |utxo: ElementsUtxoLeafV2| {
        let Asset::Explicit(asset) = utxo.output.asset else { panic!("explicit fixture") };
        let Value::Explicit(amount) = utxo.output.value else { panic!("explicit fixture") };
        let asset_id = asset.into_inner().to_byte_array();
        ElementsEconomicLeafV2 { utxo, asset_id, amount, asset_blinding_factor:[0;32],
            value_blinding_factor:[0;32], role: if asset_id == class.custody_asset_id {
                ElementsLiveEconomicRoleV2::OutstandingBase
            } else { ElementsLiveEconomicRoleV2::Irrelevant } }
    };
    let old = economic(previous.clone());
    inner.checkpoint.execution.classification = class;
    input.policy.base.classification = class;
    inner.checkpoint.execution.roots = crate::checkpoint_coin_import_v3::custody_execution_roots_v3(
        &[old.clone()], class).unwrap();
    let mut times: Vec<_> = inner.history.iter().map(|h|
        crate::native_header_v3::NativeHeader::decode(h, true).unwrap().base.time).collect();
    times.sort_unstable();
    let height = inner.checkpoint.execution.height.checked_add(1).unwrap();
    let coins: Vec<_> = tx.output.iter().enumerate().map(|(vout, output)| economic(ElementsUtxoLeafV2 {
        outpoint: elements::OutPoint::new(tx.txid(), vout as u32), output: output.clone(),
        creation_height: height, creation_parent_mtp: times[times.len()/2], coinbase: false,
        created_by_issuance: true, created_by_pegin: false,
    })).collect();
    let expected = crate::checkpoint_coin_import_v3::custody_execution_roots_v3(&coins, class).unwrap();
    assert_eq!(expected.custody_root.custody_supply_atoms, 1_000);
    assert_eq!(expected.custody_root.count, 2);

    let mut ue = canonical_empty_elements_utxo_leaf_v2();
    let mut ce = empty_elements_custody_leaf_v3();
    let mut up = Vec::new(); let mut cp = Vec::new();
    for _ in 0..256 {
        up.push(ue); cp.push(ce);
        ue = elements_sparse_utxo_parent_v2(ue, ue).unwrap();
        ce = elements_custody_parent_v3(ce, ce).unwrap();
    }
    let mut uw = ElementsTransactionUtxoWitnessV2 { spends: vec![ElementsSparseUtxoMutationV2 {
        outpoint: previous.outpoint, old_leaf: Some(previous), new_leaf: None,
        path: ElementsSparseUtxoPathV2 { siblings: up.clone() },
    }], creates: vec![] };
    let mut cw = ElementsTransactionCustodyWitnessV3 { spends: vec![ElementsSparseCustodyMutationV3 {
        outpoint: old.utxo.outpoint, old_leaf: Some(old), new_leaf: None, siblings: cp.clone(),
    }], creates: vec![] };
    let keys: Vec<_> = coins.iter().map(|coin| elements_sparse_utxo_key_v2(coin.utxo.outpoint)).collect();
    let bit = |key: &[u8;32], level: usize| (key[(255-level)/8] >> (level%8)) & 1;
    let split = (0..256).rev().find(|&level| bit(&keys[0], level) != bit(&keys[1], level)).unwrap();
    let mut second_up = up.clone(); let mut second_cp = cp.clone();
    let mut un = elements_utxo_leaf_node_v2(&coins[0].utxo);
    let mut cn = verify_elements_custody_leaf_v3(&coins[0], class).unwrap();
    for level in 0..split {
        (un, cn) = if bit(&keys[0], level) == 0 {
            (elements_sparse_utxo_parent_v2(un, up[level]).unwrap(), elements_custody_parent_v3(cn, cp[level]).unwrap())
        } else {
            (elements_sparse_utxo_parent_v2(up[level], un).unwrap(), elements_custody_parent_v3(cp[level], cn).unwrap())
        };
    }
    second_up[split] = un; second_cp[split] = cn;
    for (coin, (up, cp)) in coins.iter().zip([(up, cp), (second_up, second_cp)]) {
        uw.creates.push(ElementsSparseUtxoMutationV2 { outpoint: coin.utxo.outpoint, old_leaf: None,
            new_leaf: Some(coin.utxo.clone()), path: ElementsSparseUtxoPathV2 { siblings: up } });
        cw.creates.push(ElementsSparseCustodyMutationV3 { outpoint: coin.utxo.outpoint, old_leaf: None,
            new_leaf: Some(coin.clone()), siblings: cp });
    }
    inner.witnesses[1] = crate::native_child_block_v3::ChildTransactionCustodyWitnessV3 {
        utxo: uw, custody: cw, kernel: ElementsTransactionKernelWitnessV2::Issuance,
    };
    block.transactions[1] = tx;
    block.header.base.merkle_root = elements_transaction_merkle_root_v2(&block.transactions).unwrap();
    inner.raw_block = block.encode().unwrap();
    let empty = crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty();
    let critical = crate::native_withdrawal_accumulator_v3::critical_hash_internal(
        inner.checkpoint.execution.genesis_internal, 24, block.header.hash_internal().unwrap(), &empty, &empty).unwrap();
    inner.parent.expected_critical_hash_internal = critical;
    let mut parent: bitcoin::Block = bitcoin::consensus::deserialize(&inner.parent.terminal_parent_block).unwrap();
    let mut script = parent.txdata[0].output[0].script_pubkey.as_bytes().to_vec();
    assert_eq!(script.len(), 39);
    assert_eq!(script[6], 24);
    let mut display = critical; display.reverse(); script[7..].copy_from_slice(&display);
    parent.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(script);
    crate::conversion_parent_link_v3::tests::refresh_parent(&mut inner.parent, parent);

    for (activation, succeeds) in [(None, false), (Some(height+1), false),
        (Some(height), true), (Some(height-1), true)] {
        let mut candidate = input.clone();
        candidate.policy.explicit_reissuance_height = activation;
        rebind(&mut candidate);
        let verifier = crate::conversion_parent_link_v3::tests::TranscriptVerifier::for_inputs(
            std::iter::repeat_n(&candidate.anchor.execution.parent, if succeeds {4} else {3}));
        let result = execute_owned_custody_v7(&candidate, &verifier, simplicity);
        if succeeds {
            let output = result.unwrap_or_else(|error| panic!("activation {activation:?}: {error:?}"));
            verifier.assert_consumed();
            assert_eq!(output.checkpoint().projection.execution.roots, expected);
            assert_eq!(output.public_values().0.child_height, height);
            assert_eq!(output.public_values().0.source_binding, candidate.source_binding().unwrap());
        } else {
            let error = result.err().expect("legacy rule must reject explicit authority");
            assert!(format!("{error:?}").contains("ReissuanceAuthorization"), "{error:?}");
            verifier.assert_consumed();
        }
    }
}
