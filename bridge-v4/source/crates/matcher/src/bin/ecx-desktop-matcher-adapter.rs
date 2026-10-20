use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ecx_matcher::model::{
    AccountView, CapitalMode, CapitalSnapshotV2, HealthView, MARKET, PublicOrderBookSnapshot,
    PublicTrade, SequencedSubmitOrderOutcome, Side, SubmitOrderRequest, SubmitOrderRequestV2,
    TimeInForce,
};
use ecx_matcher::{
    ACCOUNT_VIEW_NONCE_BYTES, account_view_signing_digest, engine::protocol_limit_order,
    matcher_public_key,
};
use ecx_protocol_core::{OrderRiskCommitmentV2, RiskParams, SignedLimitOrder};
use secp256k1::{
    Keypair, Message, Secp256k1, SecretKey,
    rand::{RngCore, rngs::OsRng},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(about = "Fail-closed signing and market-data adapter for the native ECX desktop")]
struct Args {
    #[arg(long, env = "ECX_MATCHER_URL", default_value = "http://127.0.0.1:8088")]
    matcher_url: String,
    #[arg(
        long,
        env = "ECX_TRUTHCOIN_RPC_URL",
        default_value = "http://127.0.0.1:6013"
    )]
    truthcoin_rpc_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    SignerStatus {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
    },
    Status,
    Capital,
    RiskProfile,
    Trades,
    Book,
    Account {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
    },
    TruthcoinMarkets,
    TruthcoinTrade {
        #[arg(long)]
        market_id: String,
        #[arg(long)]
        outcome_index: usize,
        #[arg(long, value_enum)]
        side: OrderSide,
        #[arg(long)]
        shares: i64,
        #[arg(long)]
        limit_sats: u64,
    },
    Truthcoin {
        #[arg(long, env = "ECX_TRUTHCOIN_PUBLIC_VALUES")]
        public_values: PathBuf,
        #[arg(long, env = "ECX_TRUTHCOIN_VERIFICATION_LOG")]
        verification_log: PathBuf,
        #[arg(long, env = "ECX_TRUTHCOIN_PUBLIC_VALUES_SHA256")]
        expected_sha256: String,
    },
    Submit {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
        #[arg(long, value_enum)]
        side: OrderSide,
        #[arg(long)]
        price_ticks: u64,
        #[arg(long)]
        quantity_lots: u64,
        #[arg(long)]
        nonce: Option<u64>,
        /// Required by the zero-insurance desktop path. The matcher verifies
        /// that the order strictly shrinks the authenticated position.
        #[arg(long, default_value_t = false)]
        reduce_only: bool,
        #[arg(long, default_value_t = 1_000)]
        initial_margin_bps: u32,
        /// Submit the proof-bound risk commitment to the fail-closed v2 route.
        #[arg(long, default_value_t = false)]
        v2: bool,
        #[arg(long, value_enum, default_value_t = OrderTimeInForce::Gtc)]
        time_in_force: OrderTimeInForce,
    },
}

#[derive(Clone, ValueEnum)]
enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, ValueEnum)]
enum OrderTimeInForce {
    Gtc,
    Ioc,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TraderKey {
    version: u16,
    role: String,
    secret_key_hex: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::builder().build()?;
    match args.command {
        Command::Keygen { output } => {
            if output.exists() {
                bail!("refusing to overwrite trader key");
            }
            let secret = SecretKey::new(&mut OsRng);
            let doc = TraderKey {
                version: 1,
                role: "ecx_trader".into(),
                secret_key_hex: hex::encode(secret.secret_bytes()),
            };
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&output)?;
            file.write_all(&serde_json::to_vec_pretty(&doc)?)?;
            file.sync_all()?;
            println!(
                "trader\t{}",
                hex::encode(matcher_public_key(&secret).serialize())
            );
        }
        Command::SignerStatus { key_file } => {
            let secret = load_key(&key_file)?;
            println!(
                "signer\t{}",
                hex::encode(matcher_public_key(&secret).serialize())
            );
        }
        Command::Status => {
            let h: HealthView = get(&client, &format!("{}/health", args.matcher_url)).await?;
            println!(
                "status\t{}\t{}\t{}\t{}\t{}",
                h.status, h.chain_height, h.sequence, h.chain_id, h.matcher_signer
            );
        }
        Command::Capital => {
            let capital: CapitalSnapshotV2 =
                get(&client, &format!("{}/v2/capital", args.matcher_url)).await?;
            let mode = match capital.mode {
                CapitalMode::Normal => "normal",
                CapitalMode::ReduceOnly => "reduce_only",
                CapitalMode::Recovery => "recovery",
            };
            println!(
                "bond-capital-v2\tauthenticated\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t",
                capital.insurance_reserve_quote_units,
                capital.outstanding_bond_units,
                capital.nav_quote_units_per_bond,
                capital.deficit_quote_units,
                capital.target_reserve_quote_units,
                capital.coverage_bps,
                mode,
                capital.funding_epoch,
                hex::encode(capital.redemption_queue_root),
                capital.redemption_head,
                capital.redemption_tail,
                capital.queued_redemption_bond_units,
                hex::encode(capital.configuration_hash),
                capital.bond_inbox.processed_cursor,
                capital.bond_inbox.node_verified_source_entry_count
            );
        }
        Command::RiskProfile => {
            let risk = RiskParams::default();
            println!(
                "risk-profile\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                risk.initial_margin_bps,
                risk.maintenance_margin_bps,
                risk.liquidation_fee_bps,
                risk.maker_fee_bps,
                risk.taker_fee_bps,
                risk.max_abs_funding_rate_ppm,
                risk.maximum_open_interest_lots,
                risk.maximum_liquidation_notional_quote_units,
                risk.socialized_loss_enabled
            );
        }
        Command::Trades => {
            let rows: Vec<PublicTrade> = get(
                &client,
                &format!("{}/v1/markets/{MARKET}/trades?limit=500", args.matcher_url),
            )
            .await?;
            for t in rows {
                println!(
                    "trade\t{}\t{}\t{}",
                    t.executed_at_ms, t.price_ticks, t.sequence
                );
            }
        }
        Command::Book => {
            let book: PublicOrderBookSnapshot = get(
                &client,
                &format!("{}/v1/markets/{MARKET}/orderbook", args.matcher_url),
            )
            .await?;
            for level in book.asks {
                println!("ask\t{}", level.price_ticks);
            }
            for level in book.bids {
                println!("bid\t{}", level.price_ticks);
            }
        }
        Command::Account { key_file } => {
            let secret = load_key(&key_file)?;
            let trader = hex::encode(matcher_public_key(&secret).serialize());
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            let mut nonce = [0_u8; ACCOUNT_VIEW_NONCE_BYTES];
            OsRng.fill_bytes(&mut nonce);
            let digest = account_view_signing_digest(&trader, timestamp, nonce);
            let secp = Secp256k1::new();
            let message = Message::from_digest_slice(&digest)?;
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
            let account: AccountView = client
                .get(format!("{}/v1/accounts/{}", args.matcher_url, trader))
                .header("x-ecx-view-timestamp", timestamp.to_string())
                .header("x-ecx-view-nonce", hex::encode(nonce))
                .header("x-ecx-view-signature", hex::encode(signature.as_ref()))
                .send()
                .await?
                .error_for_status()
                .context("matcher rejected authenticated account view")?
                .json()
                .await?;
            println!(
                "account\t{}\t{}\t{}\t{}",
                account.provisional,
                account.position.net_quantity_lots,
                account.position.average_entry_price_ticks,
                account.position.realized_pnl_quote_units
            );
            for order in account.open_orders {
                println!(
                    "order\t{}\t{:?}\t{}\t{}\t{}\t{}",
                    order.order_id,
                    order.side,
                    order.price_ticks,
                    order.remaining_quantity_lots,
                    order.reduce_only,
                    order.created_sequence
                );
            }
        }
        Command::TruthcoinMarkets => {
            let markets = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "market_list",
                serde_json::json!([]),
            )
            .await?;
            // A fresh Alpha node reports `null` until its first market exists.
            // Treat that as an empty live list, not as an offline transport.
            let markets = match markets.as_array() {
                Some(markets) => markets.as_slice(),
                None if markets.is_null() => &[],
                None => bail!("market_list result is neither an array nor null"),
            };
            let archive_read_only = markets
                .iter()
                .any(|market| market["archive_read_only"].as_bool().unwrap_or(false));
            println!(
                "truthcoin-rpc\t{}",
                if archive_read_only {
                    "archive-read-only"
                } else {
                    "live"
                }
            );

            // Surface a compact read-only health projection for the UI.  Every
            // method below is non-mutating and comes from the same tunneled RPC
            // endpoint as the market list.
            let block_count = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "getblockcount",
                serde_json::json!([]),
            )
            .await?
            .as_u64()
            .unwrap_or(0);
            let balance = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "bitcoin_balance",
                serde_json::json!([]),
            )
            .await?;
            let peers = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "list_peers",
                serde_json::json!([]),
            )
            .await?;
            let decision = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "decision_status",
                serde_json::json!([]),
            )
            .await?;
            let mainchain_hash = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "get_best_mainchain_block_hash",
                serde_json::json!([]),
            )
            .await?;
            let sidechain_hash = truthcoin_rpc(
                &client,
                &args.truthcoin_rpc_url,
                "get_best_sidechain_block_hash",
                serde_json::json!([]),
            )
            .await?;
            println!(
                "truthcoin-node\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                block_count,
                balance["available_sats"].as_u64().unwrap_or(0),
                balance["total_sats"].as_u64().unwrap_or(0),
                peers.as_array().map_or(0, Vec::len),
                decision["current_period"].as_u64().unwrap_or(0),
                clean_field(mainchain_hash.as_str().unwrap_or("")),
                clean_field(sidechain_hash.as_str().unwrap_or("")),
            );
            for market in markets {
                let id = market["market_id"].as_str().context("market id missing")?;
                let detail = truthcoin_rpc(
                    &client,
                    &args.truthcoin_rpc_url,
                    "market_get",
                    serde_json::json!([id]),
                )
                .await?;
                let detail = detail
                    .as_object()
                    .context("market_get result is not a market object")?;
                let title = clean_field(detail["title"].as_str().unwrap_or("Untitled market"));
                let description = clean_field(detail["description"].as_str().unwrap_or(""));
                let state = clean_field(detail["state"].as_str().unwrap_or("unknown"));
                let volume = detail["total_volume_sats"].as_u64().unwrap_or(0);
                let created_at_height = detail["created_at_height"].as_u64().unwrap_or(0);
                let market_archive_read_only = detail
                    .get("archive_read_only")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(archive_read_only);
                for outcome in detail["outcomes"].as_array().into_iter().flatten() {
                    println!(
                        "truthcoin-market\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        id,
                        title,
                        state,
                        volume,
                        outcome["index"].as_u64().unwrap_or(0),
                        clean_field(outcome["name"].as_str().unwrap_or("Outcome")),
                        outcome["probability"].as_f64().unwrap_or(0.0),
                        description,
                        created_at_height,
                        market_archive_read_only
                    );
                }
            }
        }
        Command::TruthcoinTrade {
            market_id,
            outcome_index,
            side,
            shares,
            limit_sats,
        } => {
            if shares <= 0 {
                bail!("shares must be positive");
            }
            let (method, params) = match side {
                OrderSide::Buy => (
                    "market_buy",
                    serde_json::json!([{"market_id": market_id, "outcome_index": outcome_index,
                    "shares_amount": shares, "max_cost": limit_sats, "dry_run": false}]),
                ),
                OrderSide::Sell => {
                    let addresses = truthcoin_rpc(
                        &client,
                        &args.truthcoin_rpc_url,
                        "get_wallet_addresses",
                        serde_json::json!([]),
                    )
                    .await?;
                    let seller = addresses
                        .as_array()
                        .and_then(|a| a.first())
                        .cloned()
                        .context("Truthcoin wallet has no seller address")?;
                    (
                        "market_sell",
                        serde_json::json!([{"market_id": market_id, "outcome_index": outcome_index,
                        "shares_amount": shares, "seller_address": seller, "min_proceeds": limit_sats, "dry_run": false}]),
                    )
                }
            };
            let result = truthcoin_rpc(&client, &args.truthcoin_rpc_url, method, params).await?;
            let txid = result["txid"]
                .as_str()
                .context("Truthcoin RPC did not return a transaction id")?;
            println!(
                "truthcoin-accepted\t{}\t{}",
                txid,
                result["new_price"].as_f64().unwrap_or(0.0)
            );
        }
        Command::Truthcoin {
            public_values,
            verification_log,
            expected_sha256,
        } => {
            let bytes = fs::read(&public_values).context("read Truthcoin public values")?;
            if bytes.len() != 1269 {
                bail!("unexpected Truthcoin public-values length");
            }
            let digest = hex::encode(Sha256::digest(&bytes));
            let verification =
                fs::read_to_string(&verification_log).context("read independent verifier log")?;
            if !verification.contains("status=INDEPENDENT_VERIFY_PASS")
                || !verification.contains("program_id_match=true")
                || !verification.contains("public_values_match=true")
                || digest != expected_sha256.to_ascii_lowercase()
            {
                bail!(
                    "Truthcoin artifact is not bound to a passing independent verification record"
                );
            }
            // TruthcoinSourcePublicValuesV1 has a frozen 1,269-byte canonical layout.
            // The final 462 bytes are TruthcoinLmsrSnapshotV1; source_mtp and
            // yes_probability_ppb are fixed-width big-endian fields.
            let snapshot = bytes.len() - 462;
            let source_mtp = u64::from_be_bytes(bytes[snapshot + 337..snapshot + 345].try_into()?);
            let probability =
                u32::from_be_bytes(bytes[bytes.len() - 73..bytes.len() - 69].try_into()?);
            println!("truthcoin\t{}\t{}\t{}", source_mtp, probability, digest);
        }
        Command::Submit {
            key_file,
            side,
            price_ticks,
            quantity_lots,
            nonce,
            reduce_only,
            initial_margin_bps,
            v2,
            time_in_force,
        } => {
            let health: HealthView = get(&client, &format!("{}/health", args.matcher_url)).await?;
            if health.status != "ok" {
                bail!("matcher health is not ok");
            }
            let secret = load_key(&key_file)?;
            let trader = hex::encode(matcher_public_key(&secret).serialize());
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let client_order_id = hex::encode(
                &ecx_protocol_core::tagged_hash("ECX/desktop-order-id/v1", &now.to_be_bytes())
                    [..16],
            );
            let mut request = SubmitOrderRequest {
                client_order_id,
                chain_id: health.chain_id.clone(),
                trader,
                market: MARKET.into(),
                side: match side {
                    OrderSide::Buy => Side::Buy,
                    OrderSide::Sell => Side::Sell,
                },
                limit_price_ticks: price_ticks,
                quantity_lots,
                time_in_force: match time_in_force {
                    OrderTimeInForce::Gtc => TimeInForce::Gtc,
                    OrderTimeInForce::Ioc => TimeInForce::Ioc,
                },
                post_only: false,
                reduce_only,
                max_fee_bps: 25,
                nonce: nonce.unwrap_or_else(|| (now / 1_000_000).try_into().unwrap_or(u64::MAX)),
                valid_from_height: health.chain_height,
                expires_at_height: health
                    .chain_height
                    .checked_add(144)
                    .context("height overflow")?,
                signature: String::new(),
            };
            if !v2 && initial_margin_bps != 1_000 {
                bail!("non-default initial margin requires --v2 and a proof-bound risk signature");
            }
            let signed_order = SignedLimitOrder::sign(protocol_limit_order(&request)?, &secret)?;
            request.signature = hex::encode(signed_order.signature.0);
            let v2_configuration = if v2 {
                let capital: CapitalSnapshotV2 =
                    get(&client, &format!("{}/v2/capital", args.matcher_url)).await?;
                let expected_configuration = std::env::var("ECX_V2_CONFIGURATION_HASH")
                    .context("ECX_V2_CONFIGURATION_HASH is required for v2 order signing")?;
                if expected_configuration != hex::encode(capital.configuration_hash) {
                    bail!("matcher v2 configuration differs from the wallet's frozen pin");
                }
                Some((expected_configuration, capital.configuration_hash))
            } else {
                None
            };
            let risk_commitment_signature = if let Some((_, configuration_hash)) = &v2_configuration
            {
                hex::encode(
                    OrderRiskCommitmentV2::sign(
                        *configuration_hash,
                        signed_order.order_id(),
                        signed_order.order.trader,
                        initial_margin_bps,
                        &secret,
                    )?
                    .signature
                    .0,
                )
            } else {
                String::new()
            };
            let request_builder = if v2 {
                client
                    .post(format!("{}/v2/orders", args.matcher_url))
                    .json(&SubmitOrderRequestV2 {
                        order: request.clone(),
                        configuration_hash: v2_configuration
                            .as_ref()
                            .expect("v2 configuration was fetched")
                            .0
                            .clone(),
                        initial_margin_bps,
                        risk_commitment_signature: risk_commitment_signature.clone(),
                    })
            } else {
                client
                    .post(format!("{}/v1/orders", args.matcher_url))
                    .json(&request)
            };
            let outcome: SequencedSubmitOrderOutcome = request_builder
                .send()
                .await?
                .error_for_status()
                .context("matcher rejected signed order")?
                .json()
                .await?;
            println!(
                "accepted\t{}\t{}\t{:?}\t{}\t{}\t{}",
                outcome.outcome.order_id,
                outcome.outcome.sequence,
                outcome.outcome.status,
                outcome.outcome.remaining_quantity_lots,
                initial_margin_bps,
                risk_commitment_signature
            );
        }
    }
    Ok(())
}

async fn truthcoin_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let response: serde_json::Value = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        }))
        .send()
        .await?
        .error_for_status()
        .context("Truthcoin RPC transport failed")?
        .json()
        .await?;
    if !response["error"].is_null() {
        bail!("Truthcoin RPC {} failed: {}", method, response["error"]);
    }
    response
        .get("result")
        .cloned()
        .context("Truthcoin RPC response missing result")
}

fn clean_field(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

async fn get<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> Result<T> {
    Ok(client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn load_key(path: &PathBuf) -> Result<SecretKey> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 4096 {
        bail!("trader key must be a small regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("trader key permissions must be 0600 or stricter");
        }
    }
    let doc: TraderKey = serde_json::from_slice(&fs::read(path)?)?;
    if doc.version != 1 || doc.role != "ecx_trader" {
        bail!("invalid trader key document");
    }
    let bytes: [u8; 32] = hex::decode(doc.secret_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
    Ok(SecretKey::from_slice(&bytes)?)
}
