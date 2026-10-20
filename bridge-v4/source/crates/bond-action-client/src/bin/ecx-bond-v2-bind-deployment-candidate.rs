//! Offline create-new V18 configuration binder for a physical candidate.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ecx_bond_action_client::{
    FrozenBondDeploymentConfigurationBindingDocumentV2, FrozenBondDeploymentGenesisDocumentV2,
};
use ecx_protocol_core::FrozenConfigurationV2;

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

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

fn run(candidate_path: &Path, configuration_path: &Path, output: &Path) -> Result<(), String> {
    let candidate: FrozenBondDeploymentGenesisDocumentV2 =
        serde_json::from_slice(&read_regular_file(candidate_path)?)
            .map_err(|error| format!("invalid physical candidate JSON: {error}"))?;
    let configuration: FrozenConfigurationV2 =
        serde_json::from_slice(&read_regular_file(configuration_path)?)
            .map_err(|error| format!("invalid FrozenConfigurationV2 JSON: {error}"))?;
    let bound = FrozenBondDeploymentConfigurationBindingDocumentV2::bind(candidate, configuration)
        .map_err(|error| format!("configuration binding rejected: {error}"))?;
    let mut bytes = serde_json::to_vec_pretty(&bound)
        .map_err(|error| format!("cannot encode bound candidate: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))?;
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: ecx-bond-v2-bind-deployment-candidate \
<candidate.json> <frozen-configuration-v2.json> <create-new-bound-output.json>"
    );
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(candidate) = arguments.next() else {
        usage();
    };
    let Some(configuration) = arguments.next() else {
        usage();
    };
    let Some(output) = arguments.next() else {
        usage();
    };
    if arguments.next().is_some() {
        usage();
    }
    if let Err(error) = run(&candidate, &configuration, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
