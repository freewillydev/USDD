//! Materialize the fixed, stateless bond-v2 covenant leaves as Elements P2TR
//! scripts. Dynamic singleton and staging trees are intentionally handled by
//! their dedicated renderers.

use std::collections::{BTreeMap, BTreeSet};
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
    keyless_internal_key_hex: String,
    tapleaf_version: u8,
    programs: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct MaterializedCovenant {
    cmr_hex: String,
    script_hex: String,
    script_sha256_hex: String,
    control_block_hex: String,
    output_key_hex: String,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    keyless_internal_key_hex: String,
    tapleaf_version: u8,
    programs: BTreeMap<String, MaterializedCovenant>,
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

fn validate_role(role: &str) -> Result<(), String> {
    if role.is_empty()
        || role.len() > 64
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("invalid covenant role name: {role:?}"));
    }
    Ok(())
}

fn materialize(input: Input) -> Result<Output, String> {
    if input.programs.is_empty() || input.programs.len() > 32 {
        return Err("fixed covenant program set must contain 1..=32 entries".to_owned());
    }
    let internal_key_bytes = bytes32(&input.keyless_internal_key_hex, "keyless internal key")?;
    let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes)
        .map_err(|error| format!("invalid keyless internal key: {error}"))?;
    let leaf_version = LeafVersion::from_u8(input.tapleaf_version)
        .map_err(|error| format!("invalid Simplicity leaf version: {error}"))?;
    if input.tapleaf_version != 0xbe {
        return Err("fixed bond covenants require Simplicity tapleaf version 0xbe".to_owned());
    }
    let secp = Secp256k1::verification_only();
    let mut seen_cmrs = BTreeSet::new();
    let mut programs = BTreeMap::new();
    for (role, cmr_hex) in input.programs {
        validate_role(&role)?;
        let cmr = bytes32(&cmr_hex, &format!("{role} CMR"))?;
        if !seen_cmrs.insert(cmr) {
            return Err(format!("fixed covenant CMR is duplicated at role {role}"));
        }
        let leaf = Script::from(cmr.to_vec());
        let spend = TaprootBuilder::new()
            .add_leaf_with_ver(0, leaf.clone(), leaf_version)
            .map_err(|error| format!("cannot add {role} covenant leaf: {error}"))?
            .finalize(&secp, internal_key)
            .map_err(|_| format!("cannot finalize {role} covenant tree"))?;
        let control = spend
            .control_block(&(leaf.clone(), leaf_version))
            .ok_or_else(|| format!("{role} covenant control block is absent"))?;
        if !control.verify_taproot_commitment(&secp, &spend.output_key(), &leaf) {
            return Err(format!(
                "{role} covenant control block failed self-verification"
            ));
        }
        let script = Script::new_v1_p2tr(&secp, internal_key, spend.merkle_root());
        programs.insert(
            role,
            MaterializedCovenant {
                cmr_hex: hex::encode(cmr),
                script_hex: hex::encode(script.as_bytes()),
                script_sha256_hex: hex::encode(
                    sha256::Hash::hash(script.as_bytes()).to_byte_array(),
                ),
                control_block_hex: hex::encode(control.serialize()),
                output_key_hex: hex::encode(spend.output_key().as_inner().serialize()),
            },
        );
    }
    Ok(Output {
        schema: "ECX_BOND_V2_FIXED_COVENANTS_MATERIALIZATION_V1",
        keyless_internal_key_hex: hex::encode(internal_key_bytes),
        tapleaf_version: input.tapleaf_version,
        programs,
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
        .map_err(|error| format!("invalid fixed-covenant input JSON: {error}"))?;
    let output = materialize(input)?;
    let mut encoded = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("cannot encode fixed-covenant materialization: {error}"))?;
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
            "usage: ecx-bond-v2-fixed-covenants-materialize <input.json> <create-new-output.json>"
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

    const KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

    #[test]
    fn renders_distinct_self_authenticated_single_leaf_covenants() {
        let output = materialize(Input {
            keyless_internal_key_hex: KEY.to_owned(),
            tapleaf_version: 0xbe,
            programs: BTreeMap::from([
                ("collateral_vault".to_owned(), "11".repeat(32)),
                ("insurance_reserve".to_owned(), "22".repeat(32)),
            ]),
        })
        .unwrap();
        assert_eq!(output.programs.len(), 2);
        for covenant in output.programs.values() {
            assert_eq!(covenant.script_hex.len(), 68);
            assert_eq!(covenant.control_block_hex.len(), 66);
        }
        assert_ne!(
            output.programs["collateral_vault"].script_sha256_hex,
            output.programs["insurance_reserve"].script_sha256_hex
        );
    }

    #[test]
    fn rejects_wrong_leaf_version_and_duplicate_cmr() {
        let duplicate = BTreeMap::from([
            ("a".to_owned(), "11".repeat(32)),
            ("b".to_owned(), "11".repeat(32)),
        ]);
        assert!(materialize(Input {
            keyless_internal_key_hex: KEY.to_owned(),
            tapleaf_version: 0xbe,
            programs: duplicate,
        })
        .is_err());
        assert!(materialize(Input {
            keyless_internal_key_hex: KEY.to_owned(),
            tapleaf_version: 0xc0,
            programs: BTreeMap::from([("a".to_owned(), "11".repeat(32))]),
        })
        .is_err());
    }
}
