//! Dedicated private matcher for the lifetime-safe incremental successor.
//!
//! It is a separate process and journal from the frozen V1/finite-V18 matcher.
//! Startup requires the complete successor configuration preimage, exact node
//! identity pins, an authenticated `incremental-successor` node projection,
//! and protected matcher/proof-producer secrets.

use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    ElementsRpcClient, SuccessorApiStateV2, SuccessorCentralMatcherSignerV2,
    SuccessorMatcherJournalV2, SuccessorMatcherRuntimeConfigV2, SuccessorMatcherRuntimeV2,
    V2IdentityPins, successor_router,
};
use ecx_protocol_core::{
    Hash32, IncrementalSuccessorConfigurationV2, SuccessorCentralMatcherConfigV2, XOnlyKey,
};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_SECRET_BYTES: u64 = 4_096;

#[derive(Debug, Parser)]
#[command(about = "Private proof-shaped ECX incremental-successor matcher")]
struct Args {
    #[arg(
        long,
        env = "ECX_SUCCESSOR_MATCHER_LISTEN",
        default_value = "127.0.0.1:8089"
    )]
    listen: SocketAddr,
    #[arg(long, env = "ECX_SUCCESSOR_MATCHER_JOURNAL")]
    journal: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_CONFIGURATION_FILE")]
    successor_configuration_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_MATCHER_SECRET_KEY_FILE")]
    matcher_secret_key_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_PROOF_PRODUCER_TOKEN_FILE")]
    proof_producer_token_file: PathBuf,
    #[arg(long, env = "ECX_SUCCESSOR_TRADER_STATE_AUTHORITY_PUBLIC_KEY")]
    trader_state_authority_public_key: String,
    #[arg(long, env = "ECX_SUCCESSOR_ACTIVATION_HEIGHT")]
    activation_height: u64,
    #[arg(long, env = "ECX_SUCCESSOR_MATCHER_KEY_EPOCH")]
    matcher_key_epoch: u64,
    #[arg(long, env = "ECX_SUCCESSOR_MATCHER_GENESIS_SEQUENCE")]
    matcher_genesis_sequence: String,
    #[arg(long, env = "ECX_SUCCESSOR_MATCHER_GENESIS_RECEIPT_HASH")]
    matcher_genesis_receipt_hash: String,
    #[arg(long, env = "ECX_SUCCESSOR_MAX_LIVE_ORDERS", default_value_t = 64)]
    maximum_live_orders: usize,
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
        bail!(
            "successor matcher must bind loopback; terminate TLS/auth in a separate reviewed proxy"
        );
    }
    if args.activation_height == 0 {
        bail!("successor activation height must be nonzero");
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
        &args.matcher_secret_key_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let secret_text = Zeroizing::new(
        std::str::from_utf8(&secret_bytes)
            .context("matcher secret key is not UTF-8")?
            .trim()
            .to_owned(),
    );
    let secret_key = SecretKey::from_slice(&decode_hash32(&secret_text, "matcher secret key")?)
        .context("invalid successor matcher secret key")?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
    let (matcher_public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
    let matcher_config = SuccessorCentralMatcherConfigV2 {
        version: SuccessorCentralMatcherConfigV2::VERSION,
        key_epoch: args.matcher_key_epoch,
        signer: XOnlyKey(matcher_public_key.serialize()),
        genesis_sequence: args
            .matcher_genesis_sequence
            .parse()
            .context("matcher genesis sequence must be canonical u128 decimal")?,
        genesis_receipt_hash: decode_hash32(
            &args.matcher_genesis_receipt_hash,
            "matcher genesis receipt hash",
        )?,
        forced_inclusion_blocks: 6,
    };
    matcher_config
        .validate()
        .context("invalid successor matcher configuration")?;
    if matcher_config.digest() != configuration.successor_matcher_configuration_hash {
        bail!("matcher configuration does not match the frozen successor preimage");
    }
    let signer = SuccessorCentralMatcherSignerV2::new(
        matcher_config.clone(),
        secret_key,
        configuration.chain_id,
    )?;
    let journal =
        SuccessorMatcherJournalV2::open(&args.journal, matcher_config, configuration.chain_id)?;
    let runtime = SuccessorMatcherRuntimeV2::open(
        signer,
        journal,
        SuccessorMatcherRuntimeConfigV2 {
            chain_id: configuration.chain_id,
            configuration_hash: configuration.order_configuration_hash,
            market: configuration.market,
            risk_params: configuration.risk_params,
            maximum_live_orders: args.maximum_live_orders,
        },
        args.activation_height,
    )?;

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
    let initial_context = node
        .successor_consensus_context()
        .await
        .context("successor matcher requires an authenticated successor node projection")?;
    if configuration.digest()? != initial_context.successor_configuration_hash {
        bail!("successor configuration preimage does not match the authenticated node digest");
    }
    let token_bytes = Zeroizing::new(read_regular_file(
        &args.proof_producer_token_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let token = Zeroizing::new(
        std::str::from_utf8(&token_bytes)
            .context("proof-producer token is not UTF-8")?
            .trim()
            .to_owned(),
    );
    let trader_state_authority = XOnlyKey(decode_hash32(
        &args.trader_state_authority_public_key,
        "successor trader-state authority public key",
    )?);
    XOnlyPublicKey::from_slice(&trader_state_authority.0)
        .context("invalid successor trader-state authority public key")?;
    let state = SuccessorApiStateV2::new(
        runtime,
        node,
        initial_context,
        configuration,
        trader_state_authority,
        &token,
    )?;
    let listener = TcpListener::bind(args.listen).await?;
    axum::serve(listener, successor_router(state)).await?;
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
    let capacity = usize::try_from(after.len()).context("file size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}
