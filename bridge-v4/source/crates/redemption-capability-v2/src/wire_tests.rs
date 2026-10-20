//! Wire and authenticated-leaf regressions, not a complete covenant proof.
use super::*;
use ecx_conversion_foundation_v2::ecx_btc::OutPointV2;
use ecx_full_consensus_validator_v2::elements_v2::{
    canonical_empty_elements_economic_leaf_v2, canonical_empty_elements_utxo_leaf_v2,
    elements_sparse_economic_parent_v2, elements_sparse_utxo_parent_v2,
    ElementsEconomicClassificationV2, ElementsUtxoLeafV2, ELEMENTS_SPARSE_UTXO_DEPTH_V2,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::{PublicKey, RangeProof, SecretKey};
use elements::{AssetId, Script, TxOut, TxOutWitness, Txid};

struct MustNotVerify;
impl ElementsSimplicityReceiptVerifierV2 for MustNotVerify {
    fn verify(&self, _: [u8;32], _: &[u8], _: &[u8])
        -> Result<(), ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
        panic!("invalid probe reached recursive verification")
    }
}

#[test]
fn shared_probe_rejects_unbound_context_and_invalid_inventory_before_receipts() {
    let (input, classification) = fixture();
    let leaf = input.inventory.leaf.decode().unwrap();
    let probe = RedemptionProbeV3 {
        public_values: &input.public_values,
        simplicity_program_bytes: &input.covenant_deployment.simplicity_program_bytes,
        holder_base_input: &input.holder_base_input,
        probe_transaction: &input.probe_transaction,
        probe_outputs: &input.probe_outputs,
        simplicity_receipts: &input.simplicity_receipts,
    };
    let context = || RedemptionProbeContextV3 {
        classification, quote_atoms_per_whole_base: 100_000_000,
        simplicity_evaluator_program_id: [1;32], child_genesis: [2;32],
        outstanding_base_atoms: 100, source_tip_height: 11, source_tip_mtp: 22,
    };
    for mutation in 0..4 {
        let mut c = context();
        match mutation {
            0 => c.child_genesis = [0;32],
            1 => c.simplicity_evaluator_program_id = [0;32],
            2 => c.quote_atoms_per_whole_base = 0,
            _ => c.source_tip_mtp = 0,
        }
        assert_eq!(execute_redemption_probe_v3(&probe, &c, leaf.clone(), leaf.clone(),
            &MustNotVerify), Err(RedemptionCapabilityErrorV2::NonCanonicalInput));
    }
    // Fixture holds genuine confidential openings, but is neither a distinct
    // inventory/reserve pair nor proof of covenant spendability.
    assert_eq!(execute_redemption_probe_v3(&probe, &context(), leaf.clone(), leaf,
        &MustNotVerify), Err(RedemptionCapabilityErrorV2::Membership));
}

pub(super) fn fixture() -> (
    RedemptionCapabilityInputV2,
    ElementsEconomicClassificationV2,
) {
    let secp = Secp256k1::new();
    let abf = AssetBlindingFactor::from_slice(&[2; 32]).unwrap();
    let vbf = ValueBlindingFactor::from_slice(&[3; 32]).unwrap();
    let asset = Asset::new_confidential(&secp, AssetId::from_byte_array([9; 32]), abf);
    let generator = asset.commitment().unwrap();
    let value = Value::new_confidential(&secp, 100, generator, vbf);
    let secret = SecretKey::from_slice(&[4; 32]).unwrap();
    let script_pubkey = Script::from(vec![0x51]);
    let proof = RangeProof::new(
        &secp,
        1,
        value.commitment().unwrap(),
        100,
        vbf.into_inner(),
        b"redemption wire regression",
        script_pubkey.as_bytes(),
        secret,
        0,
        8,
        generator,
    )
    .unwrap();
    let outpoint = OutPoint {
        txid: Txid::from_byte_array(std::array::from_fn(|i| i as u8)),
        vout: 0x01020304,
    };
    let leaf = ElementsEconomicLeafV2 {
        utxo: ElementsUtxoLeafV2 {
            outpoint,
            output: TxOut {
                asset,
                value,
                nonce: Nonce::Confidential(PublicKey::from_secret_key(&secp, &secret)),
                script_pubkey,
                witness: TxOutWitness {
                    surjection_proof: None,
                    rangeproof: Some(Box::new(proof)),
                },
            },
            creation_height: 11,
            creation_parent_mtp: 22,
            coinbase: false,
            created_by_issuance: true,
            created_by_pegin: false,
        },
        asset_id: [9; 32],
        amount: 100,
        asset_blinding_factor: [2; 32],
        value_blinding_factor: [3; 32],
        role: ElementsLiveEconomicRoleV2::OutstandingBase,
    };
    let classification = ElementsEconomicClassificationV2 {
        base_asset_id: [9; 32],
        policy_asset_id: [8; 32],
        redemption_inventory_script_sha256: [7; 32],
        reserve_script_sha256: [6; 32],
    };
    let mut utxo_path = ElementsSparseUtxoPathV2 { siblings: vec![] };
    let mut economic_path = ElementsSparseEconomicPathV2 { siblings: vec![] };
    let mut empty_utxo = canonical_empty_elements_utxo_leaf_v2();
    let mut empty_economic = canonical_empty_elements_economic_leaf_v2();
    for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        utxo_path.siblings.push(empty_utxo);
        economic_path.siblings.push(empty_economic);
        empty_utxo = elements_sparse_utxo_parent_v2(empty_utxo, empty_utxo).unwrap();
        empty_economic =
            elements_sparse_economic_parent_v2(empty_economic, empty_economic).unwrap();
    }
    let terminal_utxo_root = elements_sparse_utxo_root_from_path_v2(
        outpoint,
        elements_utxo_leaf_node_v2(&leaf.utxo),
        &utxo_path,
    )
    .unwrap();
    let terminal_economic_root = elements_sparse_economic_root_from_path_v2(
        outpoint,
        verify_elements_economic_leaf_v2(&leaf, classification).unwrap(),
        &economic_path,
    )
    .unwrap();
    let evidence = AuthenticatedEconomicLeafV2::from_native(&leaf, utxo_path, economic_path);
    let deployment_outpoint = OutPointV2 {
        txid_internal: outpoint.txid.to_byte_array(),
        vout: outpoint.vout,
    };
    // This envelope deliberately does not pretend to contain a live deployment,
    // configuration, probe transaction, or recursive covenant receipts. Tests
    // below establish serialization and actual leaf membership/crypto only.
    let input = RedemptionCapabilityInputV2 {
        version: REDEMPTION_CAPABILITY_INPUT_VERSION_V2,
        public_values: vec![1],
        configuration_preimage: vec![1],
        covenant_deployment: EcxBtcCovenantDeploymentV2 {
            simplicity_program_bytes: vec![1],
            deployment_transaction: vec![1],
            redemption_inventory_outpoint: deployment_outpoint,
            reserve_outpoint: deployment_outpoint,
        },
        terminal_utxo_root,
        terminal_economic_root,
        inventory: evidence.clone(),
        reserve: evidence.clone(),
        holder_base_input: evidence.leaf.clone(),
        probe_transaction: vec![1],
        probe_outputs: vec![evidence.leaf; 3],
        simplicity_receipts: vec![
            ElementsSimplicityReceiptBindingV2 {
                public_values: vec![1],
                proof_marker: vec![1],
            };
            2
        ],
    };
    (input, classification)
}

#[test]
fn populated_redemption_wire_preserves_rangeproof_and_real_leaf_membership() {
    let (input, classification) = fixture();
    let bytes = encode_redemption_capability_input_v2(&input).unwrap();
    assert_eq!(bytes[0], 2);
    let decoded = decode_redemption_capability_input_v2(&bytes).unwrap();
    assert_eq!(decoded, input);
    let leaf = authenticate_leaf(
        &decoded.inventory,
        decoded.terminal_utxo_root,
        decoded.terminal_economic_root,
        classification,
    )
    .unwrap();
    assert!(!leaf.utxo.output.witness.is_empty());
    let lost: TxOut = elements::encode::deserialize(&decoded.inventory.leaf.utxo.output).unwrap();
    assert!(lost.witness.is_empty());
    for wire in [
        &decoded.inventory.leaf,
        &decoded.reserve.leaf,
        &decoded.holder_base_input,
    ]
    .into_iter()
    .chain(&decoded.probe_outputs)
    {
        assert_eq!(wire.decode().unwrap(), leaf);
        let encoded = options().serialize(wire).unwrap();
        assert_eq!(
            &encoded[..36],
            elements::encode::serialize(&leaf.utxo.outpoint)
        );
    }
}

#[test]
fn redemption_rejects_legacy_truncated_trailing_and_hostile_lengths() {
    let (input, _) = fixture();
    let bytes = encode_redemption_capability_input_v2(&input).unwrap();
    for version in [0, 1, 3, 255] {
        let mut changed = bytes.clone();
        changed[0] = version;
        assert!(decode_redemption_capability_input_v2(&changed).is_err());
        let mut changed = input.clone();
        changed.version = version;
        assert!(encode_redemption_capability_input_v2(&changed).is_err());
    }
    for end in [0, 1, 8, bytes.len() / 2, bytes.len() - 1] {
        assert!(decode_redemption_capability_input_v2(&bytes[..end]).is_err());
    }
    let mut hostile = bytes.clone();
    hostile[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode_redemption_capability_input_v2(&hostile).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_redemption_capability_input_v2(&trailing).is_err());
}

#[test]
fn redemption_rejects_missing_or_noncanonical_witness_in_every_leaf_position() {
    let (input, _) = fixture();
    for index in 0..6 {
        for bad in [vec![], vec![0], vec![0, 0, 0], vec![0xfd, 0, 0, 0]] {
            let mut changed = input.clone();
            let leaf = match index {
                0 => &mut changed.inventory.leaf,
                1 => &mut changed.reserve.leaf,
                2 => &mut changed.holder_base_input,
                _ => &mut changed.probe_outputs[index - 3],
            };
            leaf.utxo.output_witness = bad;
            assert!(encode_redemption_capability_input_v2(&changed).is_err());
            let raw = options().serialize(&changed).unwrap();
            assert!(decode_redemption_capability_input_v2(&raw).is_err());
        }
    }
    let mut changed = input;
    changed.probe_outputs[0].utxo.output.push(0);
    assert!(encode_redemption_capability_input_v2(&changed).is_err());
}

#[test]
fn redemption_membership_still_rejects_stripped_proof_opening_and_substitution() {
    let (input, classification) = fixture();
    let check = |evidence: &AuthenticatedEconomicLeafV2| {
        authenticate_leaf(
            evidence,
            input.terminal_utxo_root,
            input.terminal_economic_root,
            classification,
        )
    };
    assert!(check(&input.inventory).is_ok());
    let mut changed = input.inventory.clone();
    changed.leaf.utxo.output_witness = elements::encode::serialize(&TxOutWitness::default());
    assert!(check(&changed).is_err());
    changed = input.inventory.clone();
    changed.leaf.value_blinding_factor = [5; 32];
    assert!(check(&changed).is_err());
    changed = input.inventory.clone();
    changed.leaf.utxo.outpoint.vout ^= 1;
    assert!(check(&changed).is_err());
    changed = input.inventory.clone();
    changed.economic_path.siblings[0].hash[0] ^= 1;
    assert!(check(&changed).is_err());
    changed = input.inventory.clone();
    let mut output = changed.leaf.decode().unwrap().utxo.output;
    output.script_pubkey = Script::from(vec![0x52]);
    changed.leaf.utxo.output = elements::encode::serialize(&output);
    assert!(check(&changed).is_err());
}
