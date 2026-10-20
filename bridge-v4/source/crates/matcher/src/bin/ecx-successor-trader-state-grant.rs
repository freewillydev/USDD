//! One-shot private proof-state issuer for successor matcher grants.
//!
//! The issuer is deliberately a separate process from the matcher. It checks
//! the complete successor public-state preimage against the authenticated node
//! exchange root, verifies one typed trader membership opening, and only then
//! signs the tip/config/order-bound grant consumed by `/successor/v2/orders`.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    ElementsRpcClient, SuccessorMatcherPlaceRecoveryV2, SuccessorTraderStateGrantV2, V2IdentityPins,
};
use ecx_protocol_core::{
    Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2,
    SuccessorSignedLimitOrderV2, TraderStateReadBatchProofV2,
};
use secp256k1::SecretKey;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRADER_PROOF_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ORDER_BYTES: u64 = 64 * 1024;
const MAX_SECRET_BYTES: u64 = 4_096;

#[derive(Debug, Parser)]
#[command(about = "Issue one authenticated incremental-successor trader-state grant")]
struct Args {
    #[arg(long)]
    successor_configuration_file: PathBuf,
    #[arg(long)]
    successor_public_state_file: PathBuf,
    #[arg(long)]
    trader_read_proof_file: PathBuf,
    #[arg(long)]
    signed_order_file: PathBuf,
    #[arg(long)]
    matcher_recovery_file: PathBuf,
    #[arg(long)]
    authority_secret_key_file: PathBuf,
    #[arg(long)]
    output_grant_file: PathBuf,
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
    let configuration: IncrementalSuccessorConfigurationV2 = read_json(
        &args.successor_configuration_file,
        MAX_CONFIGURATION_BYTES,
        false,
    )?;
    let state: IncrementalPublicStateV2 =
        read_json(&args.successor_public_state_file, MAX_STATE_BYTES, true)?;
    let trader_read: TraderStateReadBatchProofV2 =
        read_json(&args.trader_read_proof_file, MAX_TRADER_PROOF_BYTES, true)?;
    let order: SuccessorSignedLimitOrderV2 =
        read_json(&args.signed_order_file, MAX_ORDER_BYTES, true)?;
    let recovery: SuccessorMatcherPlaceRecoveryV2 =
        read_json(&args.matcher_recovery_file, MAX_ORDER_BYTES, true)?;

    let authority_bytes = Zeroizing::new(read_regular_file(
        &args.authority_secret_key_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let authority_text = Zeroizing::new(
        std::str::from_utf8(&authority_bytes)
            .context("trader-state authority secret is not UTF-8")?
            .trim()
            .to_owned(),
    );
    let authority_secret = SecretKey::from_slice(&decode_hash32(
        &authority_text,
        "trader-state authority secret",
    )?)
    .context("invalid trader-state authority secret")?;

    let pins = V2IdentityPins {
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
    };
    let node = ElementsRpcClient::new(
        &args.elements_rpc_url,
        args.elements_rpc_user,
        args.elements_rpc_password,
    )?
    .with_v2_identity_pins(pins)?;
    let context = node
        .successor_consensus_context()
        .await
        .context("grant issuer requires an authenticated incremental-successor node context")?;
    let grant = SuccessorTraderStateGrantV2::issue_from_authenticated_trader_opening(
        configuration,
        &context,
        state,
        &trader_read,
        &order,
        &recovery,
        &authority_secret,
    )?;
    write_new_private_json(&args.output_grant_file, &grant)?;
    println!(
        "grant_issued=true sidechain_height={} exchange_state_root={} order_id={}",
        context.sidechain_height,
        hex::encode(context.exchange_state_root),
        hex::encode(order.order_id())
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

fn write_new_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding canonical trader-state grant JSON")?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create new grant file {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
