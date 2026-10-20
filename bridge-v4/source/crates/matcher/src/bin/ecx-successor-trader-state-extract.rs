//! Maintain the private node-bound successor trader archive and emit grants snapshots.

use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ecx_matcher::{
    ElementsRpcClient, SuccessorTraderArchiveTransitionV2, V2IdentityPins,
    advance_successor_trader_archive, bootstrap_successor_trader_archive,
    read_successor_trader_archive_checkpoint, write_new_successor_trader_archive_checkpoint,
    write_new_successor_trader_snapshot,
};
use ecx_protocol_core::{
    Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2, XOnlyKey,
};
use serde::de::DeserializeOwned;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_PUBLIC_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRANSITION_BYTES: u64 = 12 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Maintain the node-bound incremental-successor trader archive")]
struct Args {
    #[arg(long, env = "ECX_SUCCESSOR_CONFIGURATION_FILE")]
    successor_configuration_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_ARCHIVE_DIRECTORY")]
    archive_directory: PathBuf,
    #[arg(long, env = "ECX_ELEMENTS_RPC_URL")]
    elements_rpc_url: String,
    #[arg(long, env = "ECX_ELEMENTS_RPC_USER")]
    elements_rpc_user: Option<String>,
    #[arg(long, env = "ECX_ELEMENTS_RPC_PASSWORD")]
    elements_rpc_password: Option<String>,
    #[arg(long, env = "ECX_V2_CONFIGURATION_HASH")]
    bond_action_configuration_hash: String,
    #[arg(long, env = "ECX_V2_BOND_ASSET_ID")]
    bond_asset_id: String,
    #[arg(long, env = "ECX_V2_BOND_DEPLOYMENT_COMMITMENT")]
    bond_deployment_commitment: String,
    #[arg(long, env = "ECX_SUCCESSOR_TRANSITION_PROGRAM_ID")]
    successor_transition_program_id: String,
    #[arg(long, env = "ECX_SUCCESSOR_TRANSITION_CMR")]
    successor_transition_cmr: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize an archive only when the accepted state has an empty trader tree.
    Bootstrap {
        #[arg(long)]
        public_state_file: PathBuf,
    },
    /// Apply one exact typed trader update to the immediately accepted successor.
    Advance {
        #[arg(long)]
        transition_file: PathBuf,
    },
    /// Emit one root-and-trader-named snapshot for the existing grant service.
    Snapshot {
        #[arg(long)]
        trader: String,
        #[arg(long)]
        output_directory: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let configuration: IncrementalSuccessorConfigurationV2 = read_json(
        &args.successor_configuration_file,
        MAX_CONFIGURATION_BYTES,
        false,
    )?;
    configuration
        .validate()
        .context("invalid incremental-successor configuration")?;
    validate_private_directory(&args.archive_directory)?;

    let node = ElementsRpcClient::new(
        &args.elements_rpc_url,
        args.elements_rpc_user,
        args.elements_rpc_password,
    )?
    .with_v2_identity_pins(V2IdentityPins {
        configuration_hash: decode_hash32(
            &args.bond_action_configuration_hash,
            "bond-action configuration",
        )?,
        bond_asset_id: decode_hash32(&args.bond_asset_id, "bond asset")?,
        bond_deployment_commitment: decode_hash32(
            &args.bond_deployment_commitment,
            "bond deployment commitment",
        )?,
        transition_program_id: decode_hash32(
            &args.successor_transition_program_id,
            "successor transition program",
        )?,
        transition_cmr: decode_hash32(&args.successor_transition_cmr, "successor CMR")?,
    })?;

    match args.command {
        Command::Bootstrap { public_state_file } => {
            let state: IncrementalPublicStateV2 =
                read_json(&public_state_file, MAX_PUBLIC_STATE_BYTES, true)?;
            let context = node
                .successor_consensus_context()
                .await
                .context("bootstrap requires an authenticated successor node context")?;
            let checkpoint = bootstrap_successor_trader_archive(configuration, context, state)?;
            let path = write_new_successor_trader_archive_checkpoint(
                &args.archive_directory,
                configuration,
                &checkpoint,
            )?;
            println!(
                "archive_bootstrapped=true sidechain_height={} exchange_state_root={} checkpoint={}",
                checkpoint.context.sidechain_height,
                hex::encode(checkpoint.context.exchange_state_root),
                path.display(),
            );
        }
        Command::Advance { transition_file } => {
            let transition: SuccessorTraderArchiveTransitionV2 =
                read_json(&transition_file, MAX_TRANSITION_BYTES, true)?;
            let previous = read_successor_trader_archive_checkpoint(
                &args.archive_directory,
                configuration,
                transition.previous_state.sidechain_height,
                transition.previous_sidechain_block_hash,
            )?;
            // This call checks that the retained predecessor remains on the
            // active chain and that the returned node snapshot is stable.
            let next_context = node
                .successor_consensus_context_after(&previous.context)
                .await
                .context("advance requires the retained checkpoint on the active chain")?;
            let checkpoint = advance_successor_trader_archive(
                configuration,
                &previous,
                next_context,
                transition,
            )?;
            let path = write_new_successor_trader_archive_checkpoint(
                &args.archive_directory,
                configuration,
                &checkpoint,
            )?;
            println!(
                "archive_advanced=true sidechain_height={} exchange_state_root={} checkpoint={}",
                checkpoint.context.sidechain_height,
                hex::encode(checkpoint.context.exchange_state_root),
                path.display(),
            );
        }
        Command::Snapshot {
            trader,
            output_directory,
        } => {
            validate_private_directory(&output_directory)?;
            let trader = XOnlyKey(decode_hash32(&trader, "trader x-only key")?);
            let context = node
                .successor_consensus_context()
                .await
                .context("snapshot requires an authenticated successor node context")?;
            let checkpoint = read_successor_trader_archive_checkpoint(
                &args.archive_directory,
                configuration,
                context.sidechain_height,
                context.sidechain_block_hash,
            )?;
            if checkpoint.context != context {
                bail!("retained checkpoint does not equal the current authenticated node context");
            }
            let snapshot = checkpoint.trader_snapshot(configuration, trader)?;
            let path =
                write_new_successor_trader_snapshot(&output_directory, configuration, &snapshot)?;
            println!(
                "snapshot_written=true sidechain_height={} exchange_state_root={} trader={} snapshot={}",
                context.sidechain_height,
                hex::encode(context.exchange_state_root),
                hex::encode(trader.0),
                path.display(),
            );
        }
    }
    Ok(())
}

fn decode_hash32(value: &str, name: &str) -> Result<Hash32> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be canonical lowercase 32-byte hex");
    }
    let decoded = hex::decode(value).with_context(|| format!("decoding {name}"))?;
    let hash: Hash32 = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly 32 bytes"))?;
    if hash == [0; 32] {
        bail!("{name} must be nonzero");
    }
    Ok(hash)
}

fn read_json<T: DeserializeOwned>(path: &Path, maximum_bytes: u64, private: bool) -> Result<T> {
    serde_json::from_slice(&read_regular_file(path, maximum_bytes, private)?)
        .with_context(|| format!("decoding exact JSON from {}", path.display()))
}

fn read_regular_file(path: &Path, maximum_bytes: u64, private: bool) -> Result<Vec<u8>> {
    let before =
        std::fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        bail!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        );
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
    let capacity = usize::try_from(after.len()).context("input size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("private directory must be a regular non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("private directory permissions are broader than 0700");
        }
    }
    Ok(())
}
