use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ecx_matcher::{EngineConfig, Journal};
use ecx_protocol_core::{CentralMatcherConfigV1, XOnlyKey};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Parser)]
#[command(
    name = "ecx-matcher-backup",
    about = "Offline verified ECX matcher backup and restore"
)]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Backup {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    Verify {
        #[arg(long)]
        backup: PathBuf,
    },
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        destination_journal: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryConfigV1 {
    version: u8,
    chain_id: String,
    matcher: MatcherIdentity,
    engine: EngineConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatcherIdentity {
    key_epoch: u64,
    signer_xonly_key: String,
    genesis_sequence: u64,
    genesis_receipt_hash: String,
    forced_inclusion_blocks: u32,
}

impl RecoveryConfigV1 {
    fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading recovery config {}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_CONFIG_BYTES
        {
            bail!("matcher recovery config must be a regular file no larger than 16 KiB");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("matcher recovery config must not grant group/other permissions");
            }
        }
        let bytes = fs::read(path)?;
        let value: Self =
            serde_json::from_slice(&bytes).context("decoding matcher recovery config")?;
        if value.version != 1 {
            bail!("unsupported matcher recovery config version");
        }
        value
            .engine
            .validate()
            .context("invalid matcher recovery engine policy")?;
        value
            .matcher_config()?
            .validate()
            .context("invalid matcher recovery signer identity")?;
        if value.chain_id()?.iter().all(|byte| *byte == 0) {
            bail!("matcher recovery chain id must be nonzero");
        }
        Ok(value)
    }

    fn chain_id(&self) -> Result<[u8; 32]> {
        decode_hex(&self.chain_id, "chain_id")
    }

    fn matcher_config(&self) -> Result<CentralMatcherConfigV1> {
        Ok(CentralMatcherConfigV1 {
            version: CentralMatcherConfigV1::VERSION,
            key_epoch: self.matcher.key_epoch,
            signer: XOnlyKey(decode_hex(
                &self.matcher.signer_xonly_key,
                "signer_xonly_key",
            )?),
            genesis_sequence: self.matcher.genesis_sequence,
            genesis_receipt_hash: decode_hex(
                &self.matcher.genesis_receipt_hash,
                "genesis_receipt_hash",
            )?,
            forced_inclusion_blocks: self.matcher.forced_inclusion_blocks,
        })
    }
}

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value != value.to_ascii_lowercase() {
        bail!("{field} must be canonical lowercase {}-byte hex", N);
    }
    let bytes = hex::decode(value).with_context(|| format!("decoding {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} has wrong length"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = RecoveryConfigV1::load(&cli.config)?;
    let chain_id = config.chain_id()?;
    let matcher = config.matcher_config()?;
    let manifest = match cli.command {
        Command::Backup {
            journal,
            destination,
        } => {
            let metadata = fs::symlink_metadata(&journal)
                .with_context(|| format!("reading source journal {}", journal.display()))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("source journal must already exist as a regular file");
            }
            let (mut journal, _) = Journal::open(&journal, config.engine, matcher, chain_id)
                .context("opening and replaying offline source journal")?;
            journal.backup_to(destination)?
        }
        Command::Verify { backup } => {
            let (journal, _, manifest) =
                Journal::open_backup(backup, config.engine, matcher, chain_id)?;
            drop(journal);
            manifest
        }
        Command::Restore {
            backup,
            destination_journal,
        } => {
            let (journal, _, manifest) = Journal::restore_backup_to(
                backup,
                destination_journal,
                config.engine,
                matcher,
                chain_id,
            )?;
            drop(journal);
            manifest
        }
    };
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
