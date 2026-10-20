//! Create-new second-pass binding of an existing deployment plan to the exact
//! finite genesis singleton script while preserving the complete Tx1 identity.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ecx_bond_action_client::{
    rebind_frozen_bond_deployment_genesis_plan_v2, FrozenBondDeploymentGenesisPlanV2,
    FrozenBondDeploymentGenesisDocumentV2,
};
use elements::Script;

const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_PLAN_BYTES {
        return Err(format!(
            "input must be a nonempty regular file no larger than {MAX_PLAN_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn rebind_bytes(bytes: &[u8], genesis_script_hex: &str, public_document: bool) -> Result<Vec<u8>, String> {
    let script_bytes = hex::decode(genesis_script_hex)
        .map_err(|error| format!("invalid genesis state script hex: {error}"))?;
    let mut encoded = if public_document {
        let document: FrozenBondDeploymentGenesisDocumentV2 = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid public deployment document JSON: {error}"))?;
        let rebound = document.rebind_public_genesis_script(Script::from(script_bytes))
            .map_err(|error| format!("public genesis rebind rejected: {error}"))?;
        serde_json::to_vec_pretty(&rebound)
    } else {
        let plan: FrozenBondDeploymentGenesisPlanV2 = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid deployment plan JSON: {error}"))?;
        let rebound = rebind_frozen_bond_deployment_genesis_plan_v2(plan, Script::from(script_bytes))
            .map_err(|error| format!("genesis rebind rejected: {error}"))?;
        serde_json::to_vec_pretty(&rebound)
    }.map_err(|error| format!("cannot encode rebound input: {error}"))?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn run(input: &Path, genesis_script_hex: &str, output: &Path, public_document: bool) -> Result<(), String> {
    let encoded = rebind_bytes(&read_regular_file(input)?, genesis_script_hex, public_document)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))
}

fn usage() -> ! {
    eprintln!("usage: ecx-bond-v2-rebind-genesis-plan [--public-document] <input.json> <exact-genesis-state-script-hex> <create-new-output.json>");
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let first = arguments.next();
    let public_document = first.as_deref() == Some(std::ffi::OsStr::new("--public-document"));
    let input = if public_document { arguments.next() } else { first };
    let (Some(input), Some(script), Some(output), None) = (
        input,
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) else {
        usage();
    };
    let Some(script) = script.to_str() else {
        eprintln!("genesis state script hex must be valid UTF-8");
        std::process::exit(2);
    };
    if let Err(error) = run(&PathBuf::from(input), script, &PathBuf::from(output), public_document) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_inputs_fail_in_selected_mode_without_fallback() {
        assert!(rebind_bytes(b"{}", "00", true).unwrap_err().contains("public deployment document"));
        assert!(rebind_bytes(b"{}", "00", false).unwrap_err().contains("deployment plan"));
        assert!(rebind_bytes(b"{}", "not-hex", true).unwrap_err().contains("script hex"));
    }
}
