//! Loopback-only authenticated trader-state grant service for the incremental successor.

use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    ElementsRpcClient, SuccessorTraderStateGrantServiceV2, V2IdentityPins,
    successor_trader_state_grant_router,
};
use ecx_protocol_core::{Hash32, IncrementalSuccessorConfigurationV2};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_SECRET_BYTES: u64 = 4_096;

#[derive(Debug, Parser)]
#[command(about = "Private node-bound incremental-successor trader-state grant service")]
struct Args {
    #[arg(
        long,
        env = "ECX_SUCCESSOR_TRADER_STATE_LISTEN",
        default_value = "127.0.0.1:8090"
    )]
    listen: SocketAddr,
    #[arg(long, env = "ECX_SUCCESSOR_CONFIGURATION_FILE")]
    successor_configuration_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_SNAPSHOT_DIRECTORY")]
    trader_snapshot_directory: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_STATE_AUTHORITY_SECRET_KEY_FILE")]
    authority_secret_key_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_STATE_AUTHORITY_PUBLIC_KEY")]
    authority_public_key: String,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_STATE_TOKEN_FILE")]
    bearer_token_file: PathBuf,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        bail!("trader-state grant service must bind loopback");
    }
    let configuration: IncrementalSuccessorConfigurationV2 =
        serde_json::from_slice(&read_regular_file(
            &args.successor_configuration_file,
            MAX_CONFIGURATION_BYTES,
            false,
        )?)
        .context("decoding exact incremental-successor configuration")?;
    configuration
        .validate()
        .context("invalid incremental-successor configuration")?;

    let secret_bytes = Zeroizing::new(read_regular_file(
        &args.authority_secret_key_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let secret_text = Zeroizing::new(
        std::str::from_utf8(&secret_bytes)
            .context("trader-state authority secret is not UTF-8")?
            .trim()
            .to_owned(),
    );
    let authority_secret = SecretKey::from_slice(&decode_hash32(
        &secret_text,
        "trader-state authority secret",
    )?)
    .context("invalid trader-state authority secret")?;
    let authority_keypair = Keypair::from_secret_key(&Secp256k1::new(), &authority_secret);
    let (derived_authority, _) = XOnlyPublicKey::from_keypair(&authority_keypair);
    let expected_authority = decode_hash32(
        &args.authority_public_key,
        "trader-state authority public key",
    )?;
    if derived_authority.serialize() != expected_authority {
        bail!("trader-state authority secret does not match the pinned public key");
    }

    let token_bytes = Zeroizing::new(read_regular_file(
        &args.bearer_token_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let token = Zeroizing::new(
        std::str::from_utf8(&token_bytes)
            .context("trader-state bearer token is not UTF-8")?
            .trim()
            .to_owned(),
    );
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
    let initial = node
        .successor_consensus_context()
        .await
        .context("trader-state service requires an authenticated successor node projection")?;
    if initial.successor_configuration_hash != configuration.digest()? {
        bail!("successor configuration preimage does not match the authenticated node digest");
    }
    let service = SuccessorTraderStateGrantServiceV2::new(
        configuration,
        args.trader_snapshot_directory,
        authority_secret,
        &token,
        node,
    )?;
    let listener = TcpListener::bind(args.listen).await?;
    axum::serve(listener, successor_trader_state_grant_router(service)).await?;
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
    let mut bytes = Vec::with_capacity(
        usize::try_from(after.len()).context("private file size does not fit memory")?,
    );
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}
