//! Read-only verifier for a physical deployment/configuration binding record.

use std::fs;
use std::path::{Path, PathBuf};

use ecx_bond_action_client::FrozenBondDeploymentConfigurationBindingDocumentV2;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "input must be a nonempty regular file no larger than {MAX_INPUT_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn run(path: &Path) -> Result<(), String> {
    let document: FrozenBondDeploymentConfigurationBindingDocumentV2 =
        serde_json::from_slice(&read_regular_file(path)?)
            .map_err(|error| format!("invalid deployment binding JSON: {error}"))?;
    document
        .verify()
        .map_err(|error| format!("deployment binding rejected: {error}"))
}

fn usage() -> ! {
    eprintln!("usage: ecx-bond-v2-verify-deployment-binding <bound-candidate.json>");
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(path) = arguments.next() else {
        usage();
    };
    if arguments.next().is_some() {
        usage();
    }
    if let Err(error) = run(&path) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
