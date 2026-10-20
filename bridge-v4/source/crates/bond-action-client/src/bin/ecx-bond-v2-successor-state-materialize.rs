//! Materialize one incremental-successor singleton state tree.
//!
//! The consensus topology is exactly
//! `Branch(incremental_transition_leaf, SHA256(state_node_domain || state_root))`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TaprootBuilder};
use elements::Script;
use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    successor_state_root_hex: String,
    successor_state_node_domain_sha256_hex: String,
    incremental_successor_transition_cmr_hex: String,
    keyless_internal_key_hex: String,
    tapleaf_version: u8,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    successor_state_root_hex: String,
    successor_state_node_hex: String,
    incremental_successor_transition_cmr_hex: String,
    taproot_merkle_root_hex: String,
    state_script_hex: String,
    state_script_sha256_hex: String,
    transition_control_block_hex: String,
    output_key_hex: String,
    keyless_internal_key_hex: String,
    tapleaf_version: u8,
}

fn bytes32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))?;
    if value == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(value)
}

fn materialize(input: Input) -> Result<Output, String> {
    if input.tapleaf_version != 0xbe {
        return Err("successor singleton requires Simplicity tapleaf version 0xbe".to_owned());
    }
    let state_root = bytes32(&input.successor_state_root_hex, "successor state root")?;
    let state_domain = bytes32(
        &input.successor_state_node_domain_sha256_hex,
        "successor state-node domain",
    )?;
    let transition_cmr = bytes32(
        &input.incremental_successor_transition_cmr_hex,
        "incremental successor transition CMR",
    )?;
    let internal_key_bytes = bytes32(&input.keyless_internal_key_hex, "keyless internal key")?;
    if state_root == state_domain || state_root == transition_cmr || state_domain == transition_cmr
    {
        return Err("successor state identity fields must be distinct".to_owned());
    }
    let state_node = sha256::Hash::hash(
        [state_domain.as_slice(), state_root.as_slice()]
            .concat()
            .as_slice(),
    );
    let leaf_version = LeafVersion::from_u8(input.tapleaf_version)
        .map_err(|error| format!("invalid Simplicity leaf version: {error}"))?;
    let leaf = Script::from(transition_cmr.to_vec());
    let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes)
        .map_err(|error| format!("invalid keyless internal key: {error}"))?;
    let secp = Secp256k1::verification_only();
    let spend = TaprootBuilder::new()
        .add_leaf_with_ver(1, leaf.clone(), leaf_version)
        .map_err(|error| format!("cannot add successor transition leaf: {error}"))?
        .add_hidden(1, state_node)
        .map_err(|error| format!("cannot add successor state node: {error}"))?
        .finalize(&secp, internal_key)
        .map_err(|_| "cannot finalize successor singleton tree".to_owned())?;
    let merkle_root = spend
        .merkle_root()
        .ok_or_else(|| "successor singleton tree has no merkle root".to_owned())?;
    let control = spend
        .control_block(&(leaf.clone(), leaf_version))
        .ok_or_else(|| "successor transition control block is absent".to_owned())?;
    if !control.verify_taproot_commitment(&secp, &spend.output_key(), &leaf) {
        return Err("successor transition control block failed self-verification".to_owned());
    }
    let script = Script::new_v1_p2tr(&secp, internal_key, Some(merkle_root));
    Ok(Output {
        schema: "ECX_BOND_V2_SUCCESSOR_STATE_MATERIALIZATION_V1",
        successor_state_root_hex: hex::encode(state_root),
        successor_state_node_hex: hex::encode(state_node.to_byte_array()),
        incremental_successor_transition_cmr_hex: hex::encode(transition_cmr),
        taproot_merkle_root_hex: hex::encode(merkle_root.to_byte_array()),
        state_script_hex: hex::encode(script.as_bytes()),
        state_script_sha256_hex: hex::encode(sha256::Hash::hash(script.as_bytes()).to_byte_array()),
        transition_control_block_hex: hex::encode(control.serialize()),
        output_key_hex: hex::encode(spend.output_key().as_inner().serialize()),
        keyless_internal_key_hex: hex::encode(internal_key_bytes),
        tapleaf_version: input.tapleaf_version,
    })
}

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{} must be a nonempty regular file no larger than {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn run(input_path: &Path, output_path: &Path) -> Result<(), String> {
    let input: Input = serde_json::from_slice(&read_regular(input_path)?)
        .map_err(|error| format!("invalid successor-state input JSON: {error}"))?;
    let output = materialize(input)?;
    let mut encoded = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("cannot encode successor-state materialization: {error}"))?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| format!("cannot create-new {}: {error}", output_path.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output_path.display()))
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(input), Some(output), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!(
            "usage: ecx-bond-v2-successor-state-materialize <input.json> <create-new-output.json>"
        );
        std::process::exit(2);
    };
    if let Err(error) = run(&input, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_exact_depth_one_successor_tree() {
        let output = materialize(Input {
            successor_state_root_hex: "11".repeat(32),
            successor_state_node_domain_sha256_hex: "22".repeat(32),
            incremental_successor_transition_cmr_hex: "33".repeat(32),
            keyless_internal_key_hex:
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".to_owned(),
            tapleaf_version: 0xbe,
        })
        .unwrap();
        assert_eq!(output.state_script_hex.len(), 68);
        assert_eq!(output.transition_control_block_hex.len(), 130);
        assert_ne!(
            output.successor_state_node_hex,
            output.successor_state_root_hex
        );
    }
}
