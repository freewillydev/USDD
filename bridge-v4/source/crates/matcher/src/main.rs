use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    AppState, CentralMatcherSigner, ElementsRpcClient, EngineConfig, Journal, V2IdentityPins,
    matcher_public_key, router,
};
use ecx_protocol_core::{CentralMatcherConfigV1, XOnlyKey, tagged_hash};
use secp256k1::SecretKey;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_MATCHER_KEY_FILE_BYTES: u64 = 4096;

#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct MatcherKeyDocument {
    version: u16,
    role: String,
    secret_key_hex: String,
    public_key_xonly: String,
}

#[derive(Parser)]
#[command(name = "ecx-matcher", about = "ECX/USDD signed CLOB matcher")]
struct Args {
    #[arg(long, env = "ECX_MATCHER_LISTEN", default_value = "127.0.0.1:8088")]
    listen: SocketAddr,
    /// Required for a non-loopback bind; terminate authenticated TLS before this listener.
    #[arg(
        long,
        env = "ECX_MATCHER_ALLOW_NON_LOOPBACK_BEHIND_TLS",
        default_value_t = false
    )]
    allow_non_loopback_behind_tls: bool,
    #[arg(long, env = "ECX_JOURNAL_PATH", default_value = "data/matcher.jsonl")]
    journal: PathBuf,
    /// Enables unsigned `demo-*` traders and permissive localhost CORS.
    #[arg(long, env = "ECX_DEMO_MODE", default_value_t = false)]
    demo: bool,
    /// Active Elements height used for order validity checks.
    #[arg(long, env = "ECX_CHAIN_HEIGHT", default_value_t = 0)]
    chain_height: u64,
    /// The only matcher sequencing key. Required outside demo mode.
    #[arg(long, env = "ECX_MATCHER_SECRET_KEY")]
    matcher_secret_key: Option<String>,
    /// Protected key document created by ecx-matcher-keygen. Preferred in production.
    #[arg(
        long,
        env = "ECX_MATCHER_SECRET_KEY_FILE",
        conflicts_with = "matcher_secret_key"
    )]
    matcher_secret_key_file: Option<PathBuf>,
    /// Frozen 32-byte sidechain identifier. Required outside demo mode.
    #[arg(long, env = "ECX_CHAIN_ID")]
    chain_id: Option<String>,
    #[arg(long, env = "ECX_MATCHER_KEY_EPOCH", default_value_t = 0)]
    matcher_key_epoch: u64,
    #[arg(long, env = "ECX_MATCHER_GENESIS_SEQUENCE", default_value_t = 0)]
    matcher_genesis_sequence: u64,
    #[arg(long, env = "ECX_MATCHER_GENESIS_RECEIPT_HASH")]
    matcher_genesis_receipt_hash: Option<String>,
    /// Height of the latest authenticated BMM parent-chain header.
    #[arg(long, env = "ECX_PARENT_HEIGHT", default_value_t = 0)]
    parent_height: u64,
    /// Median-time-past of the latest parent-chain header observed by the signer.
    #[arg(long, env = "ECX_PARENT_MTP", default_value_t = 0)]
    parent_mtp: u64,
    #[arg(long, env = "ECX_FORCED_INBOX_CURSOR", default_value_t = 0)]
    forced_inbox_cursor: u64,
    #[arg(long, env = "ECX_FORCED_INCLUSION_BLOCKS", default_value_t = 6)]
    forced_inclusion_blocks: u32,
    #[arg(long, env = "ECX_MAX_OPEN_ORDERS", default_value_t = 100_000)]
    max_open_orders: usize,
    #[arg(long, env = "ECX_MAX_OPEN_ORDERS_PER_TRADER", default_value_t = 1_000)]
    max_open_orders_per_trader: usize,
    #[arg(long, env = "ECX_MAX_COMMANDS_PER_HEIGHT", default_value_t = 50_000)]
    max_commands_per_height: u64,
    #[arg(
        long,
        env = "ECX_MAX_COMMANDS_PER_TRADER_PER_HEIGHT",
        default_value_t = 500
    )]
    max_commands_per_trader_per_height: u64,
    #[arg(long, env = "ECX_MAX_TRADERS", default_value_t = 100_000)]
    max_traders: usize,
    /// With no insurance fund, reject all new exposure and accept only
    /// strictly reduce-only orders. This does not alter the proof statement.
    #[arg(long, env = "ECX_ZERO_INSURANCE_MODE", default_value_t = false)]
    zero_insurance_mode: bool,
    /// Report authenticated v2 capital posture in matcher health/readiness.
    /// The additive `/v2/orders` route always enforces v2 capital admission.
    #[arg(long, env = "ECX_V2_CAPITAL_CONTROLS", default_value_t = false)]
    v2_capital_controls: bool,
    #[arg(
        long,
        env = "ECX_COMPACT_JOURNAL_BYTES",
        default_value_t = 64 * 1024 * 1024
    )]
    compact_journal_bytes: u64,
    #[arg(
        long,
        env = "ECX_RETAINED_IDEMPOTENCY_RECEIPTS",
        default_value_t = 100_000
    )]
    retained_idempotency_receipts: u64,
    /// Patched Elements JSON-RPC endpoint exposing getecxconsensuscontext.
    #[arg(long, env = "ECX_ELEMENTS_RPC_URL")]
    elements_rpc_url: Option<String>,
    #[arg(long, env = "ECX_ELEMENTS_RPC_USER")]
    elements_rpc_user: Option<String>,
    #[arg(long, env = "ECX_ELEMENTS_RPC_PASSWORD")]
    elements_rpc_password: Option<String>,
    /// Mandatory frozen singleton pins whenever v2 capital controls are on.
    #[arg(long, env = "ECX_V2_CONFIGURATION_HASH")]
    v2_configuration_hash: Option<String>,
    #[arg(long, env = "ECX_V2_BOND_ASSET_ID")]
    v2_bond_asset_id: Option<String>,
    #[arg(long, env = "ECX_V2_BOND_DEPLOYMENT_COMMITMENT")]
    v2_bond_deployment_commitment: Option<String>,
    #[arg(long, env = "ECX_V2_TRANSITION_PROGRAM_ID")]
    v2_transition_program_id: Option<String>,
    #[arg(long, env = "ECX_V2_TRANSITION_CMR")]
    v2_transition_cmr: Option<String>,
    /// Protected raw bearer token file for the private transition producer's
    /// V2 execution-receipt export route. Mandatory with V2 controls.
    #[arg(long, env = "ECX_PROOF_PRODUCER_TOKEN_FILE")]
    proof_producer_token_file: Option<PathBuf>,
    /// Explicitly unsafe escape hatch for hermetic tests with no node process.
    #[arg(
        long,
        env = "ECX_ALLOW_STATIC_CONTEXT_FOR_TESTS",
        default_value_t = false
    )]
    allow_static_context_for_tests: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    validate_matcher_bind(args.listen, args.allow_non_loopback_behind_tls)?;
    validate_static_context_escape(args.allow_static_context_for_tests, cfg!(debug_assertions))?;
    let secret_key = match (
        args.matcher_secret_key.as_deref(),
        args.matcher_secret_key_file.as_deref(),
    ) {
        (Some(encoded), None) => {
            SecretKey::from_slice(&decode_hex_array::<32>(encoded, "matcher key")?)
                .context("invalid central matcher secret key")?
        }
        (None, Some(path)) => load_matcher_key(path)?,
        (None, None) if args.demo => {
            SecretKey::from_slice(&[1; 32]).expect("fixed demo key is valid")
        }
        (None, None) => bail!(
            "ECX_MATCHER_SECRET_KEY_FILE (preferred) or ECX_MATCHER_SECRET_KEY is required outside demo mode"
        ),
        (Some(_), Some(_)) => {
            bail!("ECX_MATCHER_SECRET_KEY_FILE and ECX_MATCHER_SECRET_KEY are mutually exclusive")
        }
    };
    let chain_id = match args.chain_id.as_deref() {
        Some(encoded) => decode_hex_array::<32>(encoded, "chain id")?,
        None if args.demo => tagged_hash("ECX/demo-chain-id/v1", b"ECX-USDD-PERP"),
        None => bail!("ECX_CHAIN_ID is required outside demo mode"),
    };
    let has_node_rpc = args.elements_rpc_url.is_some();
    let static_parent_mtp = if args.parent_mtp == 0 && (args.demo || has_node_rpc) {
        1
    } else if args.parent_mtp == 0 {
        bail!("ECX_PARENT_MTP must be nonzero outside demo mode");
    } else {
        args.parent_mtp
    };
    let static_parent_height = if args.parent_height == 0 && (args.demo || has_node_rpc) {
        1
    } else if args.parent_height == 0 {
        bail!("ECX_PARENT_HEIGHT must be nonzero outside demo mode");
    } else {
        args.parent_height
    };
    let any_v2_identity_pin = [
        args.v2_configuration_hash.as_ref(),
        args.v2_bond_asset_id.as_ref(),
        args.v2_bond_deployment_commitment.as_ref(),
        args.v2_transition_program_id.as_ref(),
        args.v2_transition_cmr.as_ref(),
    ]
    .iter()
    .any(|value| value.is_some());
    let v2_pins = if args.v2_capital_controls {
        Some(v2_identity_pins(
            args.v2_configuration_hash.as_deref(),
            args.v2_bond_asset_id.as_deref(),
            args.v2_bond_deployment_commitment.as_deref(),
            args.v2_transition_program_id.as_deref(),
            args.v2_transition_cmr.as_deref(),
        )?)
    } else if any_v2_identity_pin {
        bail!("v2 identity pins require ECX_V2_CAPITAL_CONTROLS=true");
    } else {
        None
    };
    let proof_producer_token = match (
        args.v2_capital_controls,
        args.proof_producer_token_file.as_deref(),
    ) {
        (true, Some(path)) => Some(load_private_token(path)?),
        (true, None) => {
            bail!("ECX_PROOF_PRODUCER_TOKEN_FILE is required when V2 capital controls are enabled")
        }
        (false, Some(_)) => {
            bail!("ECX_PROOF_PRODUCER_TOKEN_FILE requires ECX_V2_CAPITAL_CONTROLS=true")
        }
        (false, None) => None,
    };
    let (node_rpc, node_context) = match args.elements_rpc_url.as_deref() {
        Some(endpoint) => {
            let mut client = ElementsRpcClient::new(
                endpoint,
                args.elements_rpc_user.clone(),
                args.elements_rpc_password.clone(),
            )?;
            if let Some(pins) = v2_pins {
                client = client.with_v2_identity_pins(pins)?;
            }
            let context = client
                .consensus_context()
                .await
                .context("matcher cannot start without authenticated Elements context")?;
            (Some(client), Some(context))
        }
        None if args.demo || args.allow_static_context_for_tests => (None, None),
        None => bail!("ECX_ELEMENTS_RPC_URL is required outside demo/test-static mode"),
    };
    let sidechain_height = node_context
        .as_ref()
        .map_or(args.chain_height.max(1), |context| context.sidechain_height);
    let parent_height = node_context
        .as_ref()
        .map_or(static_parent_height, |context| context.parent_height);
    let parent_mtp = node_context
        .as_ref()
        .map_or(static_parent_mtp, |context| context.parent_mtp);
    let forced_inbox_cursor = node_context
        .as_ref()
        .map_or(args.forced_inbox_cursor, |context| {
            context.forced_inbox_processed_cursor
        });

    let public_key = matcher_public_key(&secret_key);
    let genesis_receipt_hash = match args.matcher_genesis_receipt_hash.as_deref() {
        Some(encoded) => decode_hex_array::<32>(encoded, "matcher genesis receipt hash")?,
        None => {
            let mut origin = Vec::with_capacity(72);
            origin.extend_from_slice(&chain_id);
            origin.extend_from_slice(&public_key.serialize());
            origin.extend_from_slice(&args.matcher_key_epoch.to_be_bytes());
            tagged_hash("ECX/central-matcher-genesis/v1", &origin)
        }
    };
    let matcher_config = CentralMatcherConfigV1 {
        version: CentralMatcherConfigV1::VERSION,
        key_epoch: args.matcher_key_epoch,
        signer: XOnlyKey(public_key.serialize()),
        genesis_sequence: args.matcher_genesis_sequence,
        genesis_receipt_hash,
        forced_inclusion_blocks: args.forced_inclusion_blocks,
    };
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        secret_key,
        chain_id,
        sidechain_height,
        parent_height,
        parent_mtp,
        forced_inbox_cursor,
    )?;
    let config = EngineConfig {
        demo_mode: args.demo,
        chain_height: sidechain_height,
        max_open_orders: args.max_open_orders,
        max_open_orders_per_trader: args.max_open_orders_per_trader,
        max_commands_per_height: args.max_commands_per_height,
        max_commands_per_trader_per_height: args.max_commands_per_trader_per_height,
        max_traders: args.max_traders,
        ..EngineConfig::default()
    };
    let (journal, engine) = Journal::open(&args.journal, config, matcher_config, chain_id)?;
    info!(
        listen = %args.listen,
        journal = %journal.path().display(),
        demo = args.demo,
        chain_height = sidechain_height,
        matcher = %hex::encode(public_key.serialize()),
        "starting ECX matcher"
    );
    let listener = TcpListener::bind(args.listen).await?;
    let mut state = match (node_rpc, node_context) {
        (Some(client), Some(context)) => {
            AppState::new_with_node(engine, journal, signer, client, context).await?
        }
        (None, None) => AppState::new(engine, journal, signer)?,
        _ => bail!("incomplete Elements consensus context"),
    }
    .with_compaction(
        args.compact_journal_bytes,
        args.retained_idempotency_receipts,
    )?
    .with_zero_insurance_mode(args.zero_insurance_mode)
    .await?
    .with_v2_capital_controls(args.v2_capital_controls)
    .await?;
    if let Some(token) = proof_producer_token.as_deref() {
        state = state.with_proof_producer_token(token)?;
    }
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn load_private_token(path: &Path) -> Result<Zeroizing<String>> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected proof-producer token {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        bail!(
            "proof-producer token {} must be a regular non-symlink file",
            path.display()
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open protected proof-producer token {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect protected proof-producer token {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            bail!(
                "proof-producer token {} changed while being opened",
                path.display()
            );
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "proof-producer token {} permissions are too broad ({:04o})",
                path.display(),
                mode & 0o777
            );
        }
    }
    if metadata.len() > MAX_MATCHER_KEY_FILE_BYTES {
        bail!("proof-producer token {} exceeds 4096 bytes", path.display());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_MATCHER_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read protected proof-producer token {}", path.display()))?;
    if bytes.len() > MAX_MATCHER_KEY_FILE_BYTES as usize {
        bail!("proof-producer token {} exceeds 4096 bytes", path.display());
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    let token = String::from_utf8(std::mem::take(&mut *bytes))
        .context("proof-producer token must be valid UTF-8")?;
    if token.len() < 32 || token.chars().any(char::is_whitespace) {
        bail!("proof-producer token must contain at least 32 non-whitespace characters");
    }
    Ok(Zeroizing::new(token))
}

fn required_hash(value: Option<&str>, name: &str) -> Result<[u8; 32]> {
    value
        .map(|encoded| decode_hex_array::<32>(encoded, name))
        .transpose()?
        .filter(|value| *value != [0; 32])
        .with_context(|| format!("{name} is required and must be nonzero"))
}

fn v2_identity_pins(
    configuration_hash: Option<&str>,
    bond_asset_id: Option<&str>,
    bond_deployment_commitment: Option<&str>,
    transition_program_id: Option<&str>,
    transition_cmr: Option<&str>,
) -> Result<V2IdentityPins> {
    Ok(V2IdentityPins {
        configuration_hash: required_hash(configuration_hash, "ECX_V2_CONFIGURATION_HASH")?,
        bond_asset_id: required_hash(bond_asset_id, "ECX_V2_BOND_ASSET_ID")?,
        bond_deployment_commitment: required_hash(
            bond_deployment_commitment,
            "ECX_V2_BOND_DEPLOYMENT_COMMITMENT",
        )?,
        transition_program_id: required_hash(
            transition_program_id,
            "ECX_V2_TRANSITION_PROGRAM_ID",
        )?,
        transition_cmr: required_hash(transition_cmr, "ECX_V2_TRANSITION_CMR")?,
    })
}

fn decode_hex_array<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("decoding {name} as hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly {N} bytes"))
}

fn load_matcher_key(path: &Path) -> Result<SecretKey> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected matcher key {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        bail!(
            "matcher key {} must be a regular non-symlink file",
            path.display()
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open protected matcher key {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect protected matcher key {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("matcher key {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            bail!("matcher key {} changed while being opened", path.display());
        }
    }
    if metadata.len() > MAX_MATCHER_KEY_FILE_BYTES {
        bail!(
            "matcher key {} exceeds the {} byte limit",
            path.display(),
            MAX_MATCHER_KEY_FILE_BYTES
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "matcher key {} permissions are too broad ({:04o}); remove all group/other access",
                path.display(),
                mode & 0o777
            );
        }
    }

    let mut encoded = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_MATCHER_KEY_FILE_BYTES + 1)
        .read_to_end(&mut encoded)
        .with_context(|| format!("read protected matcher key {}", path.display()))?;
    if encoded.len() as u64 > MAX_MATCHER_KEY_FILE_BYTES {
        bail!(
            "matcher key {} exceeds the {} byte limit",
            path.display(),
            MAX_MATCHER_KEY_FILE_BYTES
        );
    }
    let document: MatcherKeyDocument = serde_json::from_slice(&encoded)
        .with_context(|| format!("parse protected matcher key {}", path.display()))?;
    if document.version != 1 {
        bail!("matcher key {} has unsupported version", path.display());
    }
    if document.role != "central_single_signer" {
        bail!("matcher key {} has an invalid role", path.display());
    }
    let secret = SecretKey::from_slice(&decode_hex_array::<32>(
        &document.secret_key_hex,
        "matcher key document secret",
    )?)
    .context("invalid central matcher secret key")?;
    let embedded_public = decode_hex_array::<32>(
        &document.public_key_xonly,
        "matcher key document public identity",
    )?;
    if matcher_public_key(&secret).serialize() != embedded_public {
        bail!(
            "matcher key {} public identity does not match its secret key",
            path.display()
        );
    }
    Ok(secret)
}

fn validate_static_context_escape(requested: bool, debug_build: bool) -> Result<()> {
    if requested && !debug_build {
        bail!(
            "ECX_ALLOW_STATIC_CONTEXT_FOR_TESTS is forbidden in release builds; authenticated Elements RPC is mandatory"
        );
    }
    Ok(())
}

fn validate_matcher_bind(listen: SocketAddr, acknowledged_tls_edge: bool) -> Result<()> {
    if !listen.ip().is_loopback() && !acknowledged_tls_edge {
        bail!(
            "refusing plaintext non-loopback matcher bind {}; terminate authenticated TLS at the edge and set ECX_MATCHER_ALLOW_NON_LOOPBACK_BEHIND_TLS only after verifying that boundary",
            listen
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        load_matcher_key, matcher_public_key, v2_identity_pins, validate_matcher_bind,
        validate_static_context_escape,
    };
    use secp256k1::SecretKey;

    fn write_key(path: &std::path::Path, public: [u8; 32]) {
        let value = serde_json::json!({
            "version": 1,
            "role": "central_single_signer",
            "secret_key_hex": hex::encode([7_u8; 32]),
            "public_key_xonly": hex::encode(public),
        });
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn static_context_escape_is_debug_only() {
        assert!(validate_static_context_escape(false, false).is_ok());
        assert!(validate_static_context_escape(true, true).is_ok());
        assert!(validate_static_context_escape(true, false).is_err());
    }

    #[test]
    fn v2_controls_require_all_identity_pins() {
        let hash = "11".repeat(32);
        assert!(
            v2_identity_pins(
                Some(&hash),
                Some(&hash),
                Some(&hash),
                Some(&hash),
                Some(&hash)
            )
            .is_ok()
        );
        assert!(
            v2_identity_pins(None, Some(&hash), Some(&hash), Some(&hash), Some(&hash)).is_err()
        );
        assert!(
            v2_identity_pins(
                Some(&hash),
                Some(&hash),
                Some(&hash),
                Some(&hash),
                Some(&"00".repeat(32))
            )
            .is_err()
        );
    }

    #[test]
    fn matcher_non_loopback_bind_requires_tls_edge_acknowledgement() {
        let loopback = "127.0.0.1:8088".parse().unwrap();
        let exposed = "0.0.0.0:8088".parse().unwrap();
        assert!(validate_matcher_bind(loopback, false).is_ok());
        assert!(validate_matcher_bind(exposed, false).is_err());
        assert!(validate_matcher_bind(exposed, true).is_ok());
    }

    #[test]
    fn protected_key_file_loads_and_self_verifies() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("matcher.json");
        let expected = SecretKey::from_slice(&[7; 32]).unwrap();
        write_key(&path, matcher_public_key(&expected).serialize());
        assert_eq!(load_matcher_key(&path).unwrap(), expected);
    }

    #[test]
    fn substituted_public_identity_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("matcher.json");
        write_key(&path, [9; 32]);
        assert!(
            load_matcher_key(&path)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn oversized_or_unknown_key_document_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let oversized = temp.path().join("oversized.json");
        std::fs::write(&oversized, vec![b'x'; 4097]).unwrap();
        let unknown = temp.path().join("unknown.json");
        let expected = SecretKey::from_slice(&[7; 32]).unwrap();
        write_key(&unknown, matcher_public_key(&expected).serialize());
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&unknown).unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        std::fs::write(&unknown, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            load_matcher_key(&oversized)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert!(load_matcher_key(&unknown).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn matcher_key_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("matcher.json");
        let link = temp.path().join("matcher-link.json");
        let expected = SecretKey::from_slice(&[7; 32]).unwrap();
        write_key(&target, matcher_public_key(&expected).serialize());
        symlink(&target, &link).unwrap();
        assert!(
            load_matcher_key(&link)
                .unwrap_err()
                .to_string()
                .contains("non-symlink")
        );
    }

    #[cfg(unix)]
    #[test]
    fn broad_key_file_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("matcher.json");
        let expected = SecretKey::from_slice(&[7; 32]).unwrap();
        write_key(&path, matcher_public_key(&expected).serialize());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_matcher_key(&path)
                .unwrap_err()
                .to_string()
                .contains("too broad")
        );
    }
}
