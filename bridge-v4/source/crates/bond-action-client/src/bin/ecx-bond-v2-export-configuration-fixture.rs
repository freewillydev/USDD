//! Create-new canonical-byte fixture for a validated V2 configuration JSON.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ecx_protocol_core::{codec::CanonicalEncode, FrozenConfigurationV2};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

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

fn run(configuration_path: &Path, output: &Path) -> Result<(), String> {
    let configuration: FrozenConfigurationV2 =
        serde_json::from_slice(&read_regular_file(configuration_path)?)
            .map_err(|error| format!("invalid FrozenConfigurationV2 JSON: {error}"))?;
    configuration
        .validate()
        .map_err(|error| format!("configuration rejected: {error}"))?;
    let canonical = configuration.canonical_bytes();
    let text = format!(
        "ECX_BOND_V2_CANDIDATE_CONFIGURATION_LEN={}\n\
ECX_BOND_V2_CANDIDATE_CONFIGURATION_DIGEST={}\n\
ECX_BOND_V2_CANDIDATE_CONFIGURATION_HEX={}\n",
        canonical.len(),
        hex::encode(configuration.digest()),
        hex::encode(canonical),
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))?;
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: ecx-bond-v2-export-configuration-fixture \
<frozen-configuration-v2.json> <create-new-fixture.txt>"
    );
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(configuration) = arguments.next() else {
        usage();
    };
    let Some(output) = arguments.next() else {
        usage();
    };
    if arguments.next().is_some() {
        usage();
    }
    if let Err(error) = run(&configuration, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
