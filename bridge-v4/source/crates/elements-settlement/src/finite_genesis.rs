//! Deterministic finite-genesis script construction, not chain authentication.
use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TaprootBuilder};
use elements::Script;

/// Native ECX/header-state/v1 commitment. Transaction ids and genesis hashes
/// are internal byte order; the output index is little-endian. Output witnesses
/// are not part of CTxOut serialization (they are authenticated separately).
pub fn state_utxo_root(child_genesis: [u8;32], outpoint: elements::OutPoint,
    output: &elements::TxOut) -> [u8;32] {
    let output_hash = sha256::Hash::hash(&elements::encode::serialize(output));
    let tag = sha256::Hash::hash(b"ECX/header-state/v1");
    let mut preimage = Vec::with_capacity(164);
    preimage.extend_from_slice(tag.as_byte_array());
    preimage.extend_from_slice(tag.as_byte_array());
    preimage.extend_from_slice(&child_genesis);
    preimage.extend_from_slice(&outpoint.txid.to_byte_array());
    preimage.extend_from_slice(&outpoint.vout.to_le_bytes());
    preimage.extend_from_slice(output_hash.as_byte_array());
    sha256::Hash::hash(&preimage).to_byte_array()
}

pub struct FiniteGenesisScript {
    pub state_node: [u8; 32],
    pub merkle_root: [u8; 32],
    pub script: Script,
    pub transition_control: Vec<u8>,
    pub activation_control: Vec<u8>,
}

/// Build Branch(transition, Branch(activation, state)), preserving leaf version
/// 0xbe. Callers must derive the state hash and authenticate every frozen input.
pub fn derive_finite_genesis_script(
    state_hash: [u8; 32],
    state_node_domain: [u8; 32],
    transition_cmr: [u8; 32],
    activation_cmr: [u8; 32],
    internal_key: [u8; 32],
) -> Result<FiniteGenesisScript, String> {
    if [state_hash, state_node_domain, transition_cmr, activation_cmr, internal_key]
        .contains(&[0; 32]) || transition_cmr == activation_cmr {
        return Err("zero genesis binding or aliased program roles".into());
    }
    let state_node = sha256::Hash::hash(
        &[state_node_domain.as_slice(), state_hash.as_slice()].concat());
    let leaf_version = LeafVersion::from_u8(0xbe).map_err(|e| e.to_string())?;
    let transition_script = Script::from(transition_cmr.to_vec());
    let activation_script = Script::from(activation_cmr.to_vec());
    let internal_key = XOnlyPublicKey::from_slice(&internal_key).map_err(|e| e.to_string())?;
    let secp = Secp256k1::verification_only();
    let spend = TaprootBuilder::new()
        .add_leaf_with_ver(1, transition_script.clone(), leaf_version).map_err(|e| e.to_string())?
        .add_leaf_with_ver(2, activation_script.clone(), leaf_version).map_err(|e| e.to_string())?
        .add_hidden(2, state_node).map_err(|e| e.to_string())?
        .finalize(&secp, internal_key).map_err(|_| "cannot finalize genesis tree")?;
    let merkle_root = spend.merkle_root().ok_or("missing genesis merkle root")?;
    let transition_control = spend.control_block(&(transition_script.clone(), leaf_version))
        .ok_or("missing transition control")?;
    let activation_control = spend.control_block(&(activation_script.clone(), leaf_version))
        .ok_or("missing activation control")?;
    if !transition_control.verify_taproot_commitment(&secp, &spend.output_key(), &transition_script)
        || !activation_control.verify_taproot_commitment(&secp, &spend.output_key(), &activation_script) {
        return Err("genesis control commitment mismatch".into());
    }
    Ok(FiniteGenesisScript {
        state_node: state_node.to_byte_array(), merkle_root: merkle_root.to_byte_array(),
        script: Script::new_v1_p2tr(&secp, internal_key, Some(merkle_root)),
        transition_control: transition_control.serialize(),
        activation_control: activation_control.serialize(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_root_matches_native_serialization_layout() {
        let output = elements::TxOut {
            asset: elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array([9;32])),
            value: elements::confidential::Value::Explicit(1),
            script_pubkey: Script::from(vec![0x51]), ..Default::default()
        };
        let outpoint = elements::OutPoint::new(elements::Txid::from_byte_array([7;32]), 0x01020304);
        // Independent explicit-output encoding: asset, value, null nonce,
        // CompactSize script length and script. No transaction/witness framing.
        let mut output_bytes = vec![1]; output_bytes.extend_from_slice(&[9;32]);
        output_bytes.push(1); output_bytes.extend_from_slice(&1u64.to_be_bytes());
        output_bytes.extend_from_slice(&[0,1,0x51]);
        assert_eq!(elements::encode::serialize(&output), output_bytes);
        let tag = sha256::Hash::hash(b"ECX/header-state/v1").to_byte_array();
        let preimage = [tag.as_slice(),tag.as_slice(), &[8;32], &[7;32],
            &[4,3,2,1], sha256::Hash::hash(&output_bytes).as_byte_array()].concat();
        let expected = sha256::Hash::hash(&preimage).to_byte_array();
        assert_eq!(state_utxo_root([8;32], outpoint, &output), expected);
        assert_ne!(state_utxo_root([6;32], outpoint, &output), expected);
        assert_ne!(state_utxo_root([8;32], elements::OutPoint::new(outpoint.txid, 0), &output), expected);
    }
    #[test]
    fn topology_and_state_program_bindings_affect_the_script() {
        let key = XOnlyPublicKey::from_slice(&[
            0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,
            0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
        ]).unwrap().serialize(); // Synthetic test key, never a deployment input.
        let base = derive_finite_genesis_script([1;32],[2;32],[3;32],[4;32],key).unwrap();
        assert_eq!(base.transition_control.len(), 33 + 32);
        assert_eq!(base.activation_control.len(), 33 + 64);
        assert_eq!(base.script.len(), 34);
        for i in 0..4 {
            let mut inputs = [[1;32],[2;32],[3;32],[4;32]];
            inputs[i][0] ^= 0x80;
            let changed = derive_finite_genesis_script(inputs[0],inputs[1],inputs[2],inputs[3],key).unwrap();
            assert_ne!(base.script, changed.script);
        }
        assert!(derive_finite_genesis_script([0;32],[2;32],[3;32],[4;32],key).is_err());
        assert!(derive_finite_genesis_script([1;32],[2;32],[3;32],[3;32],key).is_err());
    }
}
