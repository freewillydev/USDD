//! One-shot private client for authenticated incremental-successor order admission.
//!
//! The client signs the lifetime-safe u128 order and its risk commitment,
//! obtains a node-bound trader-state grant from the separate proof-state
//! service, submits the exact triple to the disjoint successor matcher, and
//! independently verifies every returned matcher and execution signature.

use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ecx_matcher::{
    CapitalMode, SuccessorPlaceRequestV2, SuccessorPlaceResponseV2,
    SuccessorTraderStateGrantRequestV2, SuccessorTraderStateGrantResponseV2,
};
use ecx_protocol_core::{
    Hash32, IncrementalSuccessorConfigurationV2, OrderFlags, OrderRiskCommitmentV2, Price,
    Quantity, Side, SuccessorCentralMatcherConfigV2, SuccessorLimitOrderV2,
    SuccessorMatcherCommandKindV2, SuccessorSignedLimitOrderV2, TimeInForce, XOnlyKey,
    successor_matcher_order_command_hash_v2,
};
use fs2::FileExt;
use reqwest::{Client, Url};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_SECRET_BYTES: u64 = 4_096;
const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Sign and submit one authenticated incremental-successor order")]
struct Args {
    #[arg(long)]
    successor_configuration_file: PathBuf,
    #[arg(long)]
    successor_matcher_configuration_file: PathBuf,
    #[arg(long)]
    trader_secret_key_file: PathBuf,
    #[arg(long)]
    grant_service_token_file: PathBuf,
    #[arg(long)]
    grant_service_url: String,
    #[arg(long)]
    matcher_url: String,
    #[arg(long)]
    trader_state_authority_public_key: String,
    #[arg(long)]
    side: String,
    #[arg(long)]
    price_atoms: u64,
    #[arg(long)]
    quantity_atoms: u64,
    #[arg(long)]
    selected_initial_margin_bps: u32,
    #[arg(long)]
    max_fee_bps: u32,
    #[arg(long)]
    nonce: Option<String>,
    /// Durable private high-water mark used by the desktop gateway. The file
    /// contains the last reserved canonical u128 nonce. A reservation is
    /// fsynced before any grant or matcher request, so crashes can burn but
    /// never reuse a signed nonce.
    #[arg(long)]
    nonce_state_file: Option<PathBuf>,
    #[arg(long)]
    valid_from_height: Option<u64>,
    #[arg(long)]
    expires_at_height: Option<u64>,
    /// Derive the validity window from the matcher node-bound successor health
    /// response. Mutually exclusive with explicit validity heights.
    #[arg(long)]
    valid_for_blocks: Option<u64>,
    #[arg(long)]
    client_order_id: Option<String>,
    #[arg(long, default_value = "gtc")]
    time_in_force: String,
    #[arg(long, default_value_t = false)]
    reduce_only: bool,
    #[arg(long, default_value_t = false)]
    post_only: bool,
    #[arg(long)]
    output_receipt_file: PathBuf,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedSuccessorOrderReceiptV2 {
    version: u8,
    signed_order: SuccessorSignedLimitOrderV2,
    grant_response: SuccessorTraderStateGrantResponseV2,
    matcher_response: SuccessorPlaceResponseV2,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorClientHealthV2 {
    status: String,
    proof_profile: String,
    capital_mode: CapitalMode,
    sidechain_height: u64,
    parent_height: u64,
    successor_configuration_hash: String,
    bond_action_configuration_hash: String,
    trader_state_authority: String,
    durable_head_sequence: u128,
    durable_head_receipt_hash: String,
    match_sequence: u128,
    proof_consumed_match_sequence: u128,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedSuccessorOrderGatewayReceiptV2 {
    accepted: bool,
    verified: bool,
    proof_profile: &'static str,
    order_id: String,
    nonce: String,
    valid_from_height: u64,
    expires_at_height: u64,
    selected_initial_margin_bps: u32,
    admission_sequence: String,
    admission_receipt_hash: String,
    filled_quantity_atoms: u64,
    remaining_quantity_atoms: u64,
    resting: bool,
    self_trade_prevented: bool,
}

struct ValidityWindowRequest<'a> {
    health_url: Url,
    configuration: &'a IncrementalSuccessorConfigurationV2,
    authority: XOnlyKey,
    explicit_from: Option<u64>,
    explicit_until: Option<u64>,
    valid_for_blocks: Option<u64>,
    reduce_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    validate_private_output_directory(&args.output_receipt_file)?;
    match std::fs::symlink_metadata(&args.output_receipt_file) {
        Ok(_) => bail!(
            "refusing to submit because output receipt already exists: {}",
            args.output_receipt_file.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting output receipt path"),
    }
    let configuration: IncrementalSuccessorConfigurationV2 = read_json(
        &args.successor_configuration_file,
        MAX_CONFIGURATION_BYTES,
        false,
    )?;
    configuration.validate()?;
    let matcher_configuration: SuccessorCentralMatcherConfigV2 = read_json(
        &args.successor_matcher_configuration_file,
        MAX_CONFIGURATION_BYTES,
        false,
    )?;
    matcher_configuration.validate()?;
    if matcher_configuration.digest() != configuration.successor_matcher_configuration_hash {
        bail!("matcher configuration preimage does not match the successor configuration");
    }
    let trader_secret = read_secret_key(&args.trader_secret_key_file, "trader secret key")?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &trader_secret);
    let (trader_public, _) = XOnlyPublicKey::from_keypair(&keypair);
    let trader = XOnlyKey(trader_public.serialize());
    let authority = XOnlyKey(decode_hash32(
        &args.trader_state_authority_public_key,
        "trader-state authority public key",
    )?);
    XOnlyPublicKey::from_slice(&authority.0)
        .context("invalid trader-state authority public key")?;

    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let matcher_health_url = endpoint(&args.matcher_url, "/successor/health")?;
    let (valid_from_height, expires_at_height) = resolve_validity_window(
        &client,
        ValidityWindowRequest {
            health_url: matcher_health_url,
            configuration: &configuration,
            authority,
            explicit_from: args.valid_from_height,
            explicit_until: args.expires_at_height,
            valid_for_blocks: args.valid_for_blocks,
            reduce_only: args.reduce_only,
        },
    )
    .await?;
    let nonce = resolve_nonce(args.nonce.as_deref(), args.nonce_state_file.as_deref())?;
    let client_order_id = match args.client_order_id.as_deref() {
        Some(value) => decode_fixed::<16>(value, "client order id")?,
        None if args.nonce_state_file.is_some() => nonce.to_be_bytes(),
        None => bail!("client-order-id is required when nonce-state-file is not used"),
    };

    let side = match args.side.as_str() {
        "buy" => Side::Buy,
        "sell" => Side::Sell,
        _ => bail!("side must be buy or sell"),
    };
    let time_in_force = match args.time_in_force.as_str() {
        "gtc" => TimeInForce::GoodTilHeight,
        "ioc" => TimeInForce::ImmediateOrCancel,
        _ => bail!("time-in-force must be gtc or ioc"),
    };
    let flag_bits = (u8::from(args.reduce_only) * OrderFlags::REDUCE_ONLY.bits())
        | (u8::from(args.post_only) * OrderFlags::POST_ONLY.bits());
    let flags = OrderFlags::from_bits(flag_bits).context("invalid successor order flags")?;
    if args.post_only && time_in_force != TimeInForce::GoodTilHeight {
        bail!("post-only successor orders must use gtc");
    }
    let order = SuccessorSignedLimitOrderV2::sign(
        SuccessorLimitOrderV2 {
            version: SuccessorLimitOrderV2::VERSION,
            chain_id: configuration.chain_id,
            market: configuration.market,
            trader,
            side,
            time_in_force,
            flags,
            limit_price: Price::new(args.price_atoms)?,
            quantity: Quantity::new(args.quantity_atoms)?,
            client_order_id,
            max_fee_bps: args.max_fee_bps,
            nonce,
            valid_from_height,
            expires_at_height,
        },
        &trader_secret,
    )?;
    let risk = OrderRiskCommitmentV2::sign(
        configuration.order_configuration_hash,
        order.order_id(),
        trader,
        args.selected_initial_margin_bps,
        &trader_secret,
    )?;

    let grant_url = endpoint(&args.grant_service_url, "/successor/v2/trader-state-grants")?;
    let matcher_url = endpoint(&args.matcher_url, "/successor/v2/orders")?;
    let token_bytes = Zeroizing::new(read_regular_file(
        &args.grant_service_token_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let token = Zeroizing::new(
        std::str::from_utf8(&token_bytes)
            .context("grant-service token is not UTF-8")?
            .trim()
            .to_owned(),
    );
    if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_whitespace) {
        bail!("grant-service token must contain 32..=4096 non-whitespace bytes");
    }
    let grant_response = post_json::<_, SuccessorTraderStateGrantResponseV2>(
        &client,
        grant_url,
        Some(&token),
        &SuccessorTraderStateGrantRequestV2 {
            signed_order: order.clone(),
            risk: risk.clone(),
        },
    )
    .await?;
    validate_grant_response(configuration, authority, &order, &risk, &grant_response)?;

    let matcher_response = post_json::<_, SuccessorPlaceResponseV2>(
        &client,
        matcher_url,
        None,
        &SuccessorPlaceRequestV2 {
            signed_order: order.clone(),
            recovery: grant_response.recovery.clone(),
            trader_state_grant: grant_response.trader_state_grant.clone(),
        },
    )
    .await?;
    validate_matcher_response(
        configuration,
        &matcher_configuration,
        &order,
        &matcher_response,
    )?;
    let filled_quantity_atoms = matcher_response
        .fills
        .iter()
        .try_fold(0u64, |sum, fill| sum.checked_add(fill.trade.quantity.get()))
        .context("successor matcher fill quantity overflow")?;
    let gateway_receipt = VerifiedSuccessorOrderGatewayReceiptV2 {
        accepted: true,
        verified: true,
        proof_profile: "incremental-successor",
        order_id: hex::encode(order.order_id()),
        nonce: nonce.to_string(),
        valid_from_height,
        expires_at_height,
        selected_initial_margin_bps: args.selected_initial_margin_bps,
        admission_sequence: matcher_response
            .admission_receipt
            .body
            .global_sequence
            .to_string(),
        admission_receipt_hash: hex::encode(matcher_response.admission_receipt.receipt_hash()),
        filled_quantity_atoms,
        remaining_quantity_atoms: matcher_response.remaining_quantity_atoms,
        resting: matcher_response.resting,
        self_trade_prevented: matcher_response.self_trade_prevented,
    };
    write_new_private_json(
        &args.output_receipt_file,
        &VerifiedSuccessorOrderReceiptV2 {
            version: 1,
            signed_order: order,
            grant_response,
            matcher_response,
        },
    )?;
    println!("{}", serde_json::to_string(&gateway_receipt)?);
    Ok(())
}

async fn resolve_validity_window(
    client: &Client,
    request: ValidityWindowRequest<'_>,
) -> Result<(u64, u64)> {
    match (
        request.explicit_from,
        request.explicit_until,
        request.valid_for_blocks,
    ) {
        (Some(from), Some(until), None) if from > 0 && until >= from => Ok((from, until)),
        (None, None, Some(blocks)) if (1..=144).contains(&blocks) => {
            let health: SuccessorClientHealthV2 = get_json(client, request.health_url).await?;
            let expected_configuration = hex::encode(request.configuration.digest()?);
            let expected_authority = hex::encode(request.authority.0);
            decode_hash32(
                &health.bond_action_configuration_hash,
                "health bond-action configuration hash",
            )?;
            decode_hash32(
                &health.durable_head_receipt_hash,
                "health durable receipt hash",
            )?;
            if health.status != "ok"
                || health.proof_profile != "incremental-successor"
                || health.sidechain_height == 0
                || health.parent_height == 0
                || health.successor_configuration_hash != expected_configuration
                || health.trader_state_authority != expected_authority
                || health.proof_consumed_match_sequence > health.match_sequence
                || health.durable_head_sequence == u128::MAX
                || !health.capital_mode.permits(request.reduce_only)
            {
                bail!("successor matcher health does not match the frozen client profile");
            }
            let until = health
                .sidechain_height
                .checked_add(blocks)
                .context("successor order validity height overflow")?;
            Ok((health.sidechain_height, until))
        }
        _ => bail!(
            "provide either valid-from-height plus expires-at-height, or valid-for-blocks (1..=144)"
        ),
    }
}

async fn get_json<O: serde::de::DeserializeOwned>(client: &Client, url: Url) -> Result<O> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("reading {url}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        bail!("response from {url} exceeds the client bound");
    }
    if !status.is_success() {
        bail!("request to {url} failed with HTTP {status}");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("decoding exact response from {url}"))
}

fn resolve_nonce(explicit: Option<&str>, state_file: Option<&Path>) -> Result<u128> {
    match (explicit, state_file) {
        (Some(value), None) => parse_canonical_u128(value, "order nonce"),
        (None, Some(path)) => reserve_nonce(path),
        _ => bail!("provide exactly one of nonce or nonce-state-file"),
    }
}

fn reserve_nonce(path: &Path) -> Result<u128> {
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect nonce state {}", path.display()))?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() == 0
        || before.len() > MAX_SECRET_BYTES
    {
        bail!("nonce state must be a bounded regular non-symlink file");
    }
    validate_private_permissions(&before, path, "nonce state")?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open nonce state {}", path.display()))?;
    file.try_lock_exclusive()
        .with_context(|| format!("lock nonce state {}", path.display()))?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("nonce state changed while being opened");
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(after.len())?);
    (&file).take(MAX_SECRET_BYTES + 1).read_to_end(&mut bytes)?;
    let text = std::str::from_utf8(&bytes)?.trim();
    let previous = parse_canonical_u128(text, "last reserved order nonce")?;
    let next = previous.checked_add(1).context("order nonce exhausted")?;
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(next.to_string().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    FileExt::unlock(&file)?;
    Ok(next)
}

fn validate_grant_response(
    configuration: IncrementalSuccessorConfigurationV2,
    authority: XOnlyKey,
    order: &SuccessorSignedLimitOrderV2,
    risk: &OrderRiskCommitmentV2,
    response: &SuccessorTraderStateGrantResponseV2,
) -> Result<()> {
    let grant = &response.trader_state_grant;
    if response.recovery.risk != *risk
        || response.recovery.salt == [0; 32]
        || response.recovery.parent_block_hash == [0; 32]
        || grant.successor_configuration_hash != configuration.digest()?
        || grant.order_id != order.order_id()
        || grant.trader != order.order.trader
        || grant.trader_order_generation != response.recovery.trader_order_generation
        || grant.salt != response.recovery.salt
        || grant.parent_block_hash != response.recovery.parent_block_hash
    {
        bail!("trader-state grant service returned a mismatched order binding");
    }
    grant.verify_signature(authority)
}

fn validate_matcher_response(
    configuration: IncrementalSuccessorConfigurationV2,
    matcher_configuration: &SuccessorCentralMatcherConfigV2,
    order: &SuccessorSignedLimitOrderV2,
    response: &SuccessorPlaceResponseV2,
) -> Result<()> {
    if !response.accepted
        || response.order_id != hex::encode(order.order_id())
        || response.remaining_quantity_atoms > order.order.quantity.get()
        || response.durable_head_sequence != response.admission_receipt.body.global_sequence
        || response.durable_head_receipt_hash
            != hex::encode(response.admission_receipt.receipt_hash())
        || response.admission_receipt.body.chain_id != configuration.chain_id
        || response.admission_receipt.body.command_kind != SuccessorMatcherCommandKindV2::Place
        || response.admission_receipt.body.command_hash
            != successor_matcher_order_command_hash_v2(order)
    {
        bail!("successor matcher returned a mismatched admission response");
    }
    response.admission_receipt.verify(matcher_configuration)?;
    let mut filled = 0u64;
    for fill in &response.fills {
        fill.execution_receipt.verify_match(
            matcher_configuration,
            configuration.chain_id,
            &fill.maker,
            order,
            &fill.trade,
            &response.admission_receipt,
        )?;
        filled = filled
            .checked_add(fill.trade.quantity.get())
            .context("successor matcher fill quantity overflow")?;
    }
    if filled > order.order.quantity.get()
        || filled
            .checked_add(response.remaining_quantity_atoms)
            .context("successor matcher quantity decomposition overflow")?
            != order.order.quantity.get()
        || (response.resting && response.remaining_quantity_atoms == 0)
        || (!response.resting
            && response.remaining_quantity_atoms > 0
            && order.order.time_in_force == TimeInForce::GoodTilHeight
            && !response.self_trade_prevented)
    {
        bail!("successor matcher returned inconsistent fill/resting quantities");
    }
    Ok(())
}

async fn post_json<I: Serialize, O: serde::de::DeserializeOwned>(
    client: &Client,
    url: Url,
    bearer: Option<&str>,
    input: &I,
) -> Result<O> {
    let mut request = client.post(url.clone()).json(input);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("posting to {url}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        bail!("response from {url} exceeds the client bound");
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("HTTP {status}"));
        bail!("request to {url} failed: {message}");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("decoding exact response from {url}"))
}

fn endpoint(base: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(base).context("invalid private service URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("private service URL must not embed credentials, query, or fragment");
    }
    let loopback_plaintext =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() != "https" && !loopback_plaintext {
        bail!("private service URL must use HTTPS unless it is loopback-only");
    }
    url.set_path(path);
    Ok(url)
}

fn parse_canonical_u128(value: &str, name: &str) -> Result<u128> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("{name} must be canonical u128 decimal");
    }
    value.parse().with_context(|| format!("invalid {name}"))
}

fn decode_hash32(value: &str, name: &str) -> Result<Hash32> {
    decode_fixed(value, name)
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be canonical lowercase {}-byte hex", N);
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly {N} bytes"))
}

fn read_secret_key(path: &Path, name: &str) -> Result<SecretKey> {
    let bytes = Zeroizing::new(read_regular_file(path, MAX_SECRET_BYTES, true)?);
    let text = Zeroizing::new(std::str::from_utf8(&bytes)?.trim().to_owned());
    SecretKey::from_slice(&decode_hash32(&text, name)?).with_context(|| format!("invalid {name}"))
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum: u64,
    private: bool,
) -> Result<T> {
    serde_json::from_slice(&read_regular_file(path, maximum, private)?)
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
    if private {
        validate_private_permissions(&before, path, "private input")?;
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("{} changed while being opened", path.display());
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(after.len())?);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}

fn validate_private_permissions(
    metadata: &std::fs::Metadata,
    path: &Path,
    name: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "{name} {} permissions are broader than 0600",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, path, name);
    Ok(())
}

fn validate_private_output_directory(path: &Path) -> Result<()> {
    let directory = path
        .parent()
        .context("output receipt path has no parent directory")?;
    let metadata = std::fs::symlink_metadata(directory)
        .with_context(|| format!("inspect output receipt directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("output receipt directory must be a regular non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("output receipt directory permissions are broader than 0700");
        }
    }
    Ok(())
}

fn write_new_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    validate_private_output_directory(path)?;
    let bytes = serde_json::to_vec(value)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
