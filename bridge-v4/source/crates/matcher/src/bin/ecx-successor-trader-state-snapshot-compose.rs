//! Compose one exact private trader-state snapshot for the successor grant service.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    SuccessorTraderStateComposeInputV2, compose_successor_trader_state_snapshot,
    successor_trader_snapshot_filename,
};
use ecx_protocol_core::IncrementalSuccessorConfigurationV2;
use serde::de::DeserializeOwned;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_COMPOSE_INPUT_BYTES: u64 = 12 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Compose a verified private incremental-successor trader-state snapshot")]
struct Args {
    #[arg(long)]
    successor_configuration_file: PathBuf,
    #[arg(long)]
    compose_input_file: PathBuf,
    #[arg(long)]
    output_directory: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let configuration: IncrementalSuccessorConfigurationV2 = read_json(
        &args.successor_configuration_file,
        MAX_CONFIGURATION_BYTES,
        false,
    )?;
    let input: SuccessorTraderStateComposeInputV2 =
        read_json(&args.compose_input_file, MAX_COMPOSE_INPUT_BYTES, true)?;
    let snapshot = compose_successor_trader_state_snapshot(configuration, input)?;
    validate_private_directory(&args.output_directory)?;
    let output = args
        .output_directory
        .join(successor_trader_snapshot_filename(
            snapshot.exchange_state_root,
            snapshot.trader,
        ));
    write_new_private_json(&output, &snapshot)?;
    println!(
        "wrote verified private successor trader-state snapshot {}",
        output.display()
    );
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path, maximum_bytes: u64, private: bool) -> Result<T> {
    serde_json::from_slice(&read_regular_file(path, maximum_bytes, private)?)
        .with_context(|| format!("decoding exact JSON from {}", path.display()))
}

fn read_regular_file(path: &Path, maximum_bytes: u64, private: bool) -> Result<Vec<u8>> {
    let before =
        std::fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if before.len() == 0 || before.len() > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            bail!("{} permissions are broader than 0600", path.display());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("inspect open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("{} changed while being opened", path.display());
        }
    }
    let capacity = usize::try_from(after.len()).context("file size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect output directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("output directory must be a regular non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("output directory permissions are broader than 0700");
        }
    }
    Ok(())
}

fn write_new_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding exact trader-state snapshot JSON")?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create new snapshot file {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
