use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use ecx_matcher::{
    AccountView, AppState, CentralMatcherSigner, EngineConfig, HealthView, Journal, JournalEntryV1,
    MARKET, MatcherReceiptView, PublicOrderBookSnapshot, PublicTrade, SequencedSubmitOrderOutcome,
    Side, SubmitOrderRequest, TimeInForce, account_view_signing_digest, matcher_public_key, router,
};
use ecx_protocol_core::{CentralMatcherConfigV1, PRICE_SCALE, SignedLimitOrder, XOnlyKey};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const CHAIN_ID: [u8; 32] = [0x19; 32];
const CHAIN_HEIGHT: u64 = 100;
const PARENT_HEIGHT: u64 = 900_000;
const PARENT_MTP: u64 = 1_700_000_000;

#[tokio::test]
async fn central_matcher_http_restart_and_idempotency() {
    let directory = TempDir::new().unwrap();
    let journal_path = directory.path().join("central-matcher.jsonl");
    let matcher_secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let matcher_config = CentralMatcherConfigV1 {
        version: CentralMatcherConfigV1::VERSION,
        key_epoch: 0,
        signer: XOnlyKey(matcher_public_key(&matcher_secret).serialize()),
        genesis_sequence: 0,
        genesis_receipt_hash: [0x31; 32],
        forced_inclusion_blocks: 6,
    };
    let maker = signed_request(11, 0x51, Side::Sell, 100 * PRICE_SCALE, 5, TimeInForce::Gtc);
    let taker = signed_request(12, 0x52, Side::Buy, 101 * PRICE_SCALE, 3, TimeInForce::Ioc);

    let (base_url, shutdown, server) =
        spawn_matcher(&journal_path, &matcher_config, matcher_secret).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let health = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<HealthView>()
        .await
        .unwrap();
    assert_eq!(health.matcher_mode, "central_single_signer");
    assert_eq!(health.matcher_signer, hex::encode(matcher_config.signer.0));
    assert_eq!(health.chain_id, hex::encode(CHAIN_ID));
    assert_eq!(health.matcher_sequence, matcher_config.genesis_sequence);
    assert!(health.privacy.contains("public prices, timing, roots"));
    assert!(
        health
            .privacy
            .contains("omit quantities and trader identities")
    );
    assert!(
        health
            .privacy
            .contains("matcher sees signed orders, balances, and positions")
    );

    let maker_response = client
        .post(format!("{base_url}/v1/orders"))
        .json(&maker)
        .send()
        .await
        .unwrap();
    assert_eq!(maker_response.status(), StatusCode::CREATED);
    let maker_outcome = maker_response
        .json::<SequencedSubmitOrderOutcome>()
        .await
        .unwrap();
    maker_outcome
        .matcher_receipt
        .verify(&matcher_config)
        .unwrap();
    assert_eq!(maker_outcome.matcher_receipt.body.global_sequence, 1);
    assert_eq!(
        maker_outcome.matcher_receipt.body.observed_parent_height,
        PARENT_HEIGHT
    );
    assert_eq!(
        maker_outcome.matcher_receipt.body.observed_parent_mtp,
        PARENT_MTP
    );
    assert_eq!(
        maker_outcome.matcher_receipt.body.previous_receipt_hash,
        matcher_config.genesis_receipt_hash
    );
    assert_eq!(maker_outcome.outcome.remaining_quantity_lots, 5);
    let retained = client
        .get(format!("{base_url}/v1/receipts/1"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<MatcherReceiptView>()
        .await
        .unwrap();
    assert_eq!(retained.receipt, maker_outcome.matcher_receipt);
    assert_eq!(
        retained.receipt_hash,
        hex::encode(retained.receipt.receipt_hash())
    );
    assert_eq!(
        client
            .get(format!("{base_url}/v1/receipts/999"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let taker_response = client
        .post(format!("{base_url}/v1/orders"))
        .json(&taker)
        .send()
        .await
        .unwrap();
    assert_eq!(taker_response.status(), StatusCode::CREATED);
    let taker_outcome = taker_response
        .json::<SequencedSubmitOrderOutcome>()
        .await
        .unwrap();
    taker_outcome
        .matcher_receipt
        .verify(&matcher_config)
        .unwrap();
    assert_eq!(taker_outcome.matcher_receipt.body.global_sequence, 2);
    assert_eq!(
        taker_outcome.matcher_receipt.body.previous_receipt_hash,
        maker_outcome.matcher_receipt.receipt_hash()
    );
    assert_eq!(taker_outcome.outcome.trades.len(), 1);
    assert_eq!(
        taker_outcome.outcome.trades[0].price_ticks,
        100 * PRICE_SCALE
    );
    assert_eq!(taker_outcome.outcome.trades[0].quantity_lots, 3);

    let book = get_book(&client, &base_url).await;
    assert_eq!(book.asks.len(), 1);
    assert_eq!(book.asks[0].price_ticks, 100 * PRICE_SCALE);
    let trades = get_trades(&client, &base_url).await;
    assert_eq!(trades.len(), 1);

    let public_book_json = serde_json::to_value(&book).unwrap();
    let public_trade_json = serde_json::to_value(&trades).unwrap();
    for (label, value) in [("book", public_book_json), ("trades", public_trade_json)] {
        let encoded = value.to_string();
        for forbidden in [
            "quantity_lots",
            "order_count",
            "order_id",
            "trade_id",
            "buyer",
            "seller",
            "trader",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "public {label} payload leaked {forbidden}"
            );
        }
    }

    let maker_secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let account_url = format!("{base_url}/v1/accounts/{}", maker.trader);
    let account_nonce = [0x71; 16];
    let timestamp = now_ms();
    let signature = account_signature(&maker_secret, &maker.trader, timestamp, account_nonce);
    let account_response = client
        .get(&account_url)
        .header("x-ecx-view-timestamp", timestamp.to_string())
        .header("x-ecx-view-nonce", hex::encode(account_nonce))
        .header("x-ecx-view-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(account_response.status(), StatusCode::OK);
    let account = account_response.json::<AccountView>().await.unwrap();
    assert_eq!(account.trader, maker.trader);
    assert_eq!(account.open_orders.len(), 1);

    // The signed account-view credential is a one-use bearer credential.
    // Replaying every byte of it must not disclose the account twice.
    let replay = client
        .get(&account_url)
        .header("x-ecx-view-timestamp", timestamp.to_string())
        .header("x-ecx-view-nonce", hex::encode(account_nonce))
        .header("x-ecx-view-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let next_nonce = [0x72; 16];
    let next_signature = account_signature(&maker_secret, &maker.trader, timestamp, next_nonce);
    let fresh = client
        .get(&account_url)
        .header("x-ecx-view-timestamp", timestamp.to_string())
        .header("x-ecx-view-nonce", hex::encode(next_nonce))
        .header("x-ecx-view-signature", next_signature)
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);

    let uppercase_alias = client
        .get(format!(
            "{base_url}/v1/accounts/{}",
            maker.trader.to_uppercase()
        ))
        .header("x-ecx-view-timestamp", timestamp.to_string())
        .header("x-ecx-view-nonce", hex::encode([0x73; 16]))
        .header("x-ecx-view-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(uppercase_alias.status(), StatusCode::UNAUTHORIZED);

    let durable_before_bad_requests = std::fs::read_to_string(&journal_path).unwrap();
    let oversized = client
        .post(format!("{base_url}/v1/orders"))
        .header("content-type", "application/json")
        .body("x".repeat(20 * 1024))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let mut unknown_field = serde_json::to_value(&maker).unwrap();
    unknown_field
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!(true));
    let unknown = client
        .post(format!("{base_url}/v1/orders"))
        .json(&unknown_field)
        .send()
        .await
        .unwrap();
    assert!(unknown.status().is_client_error());
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        durable_before_bad_requests
    );

    shutdown.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(
        std::fs::read_to_string(&journal_path)
            .unwrap()
            .lines()
            .count(),
        2
    );

    let (base_url, shutdown, server) =
        spawn_matcher(&journal_path, &matcher_config, matcher_secret).await;
    let recovered_book = get_book(&client, &base_url).await;
    assert_eq!(recovered_book, book);
    let retry_response = client
        .post(format!("{base_url}/v1/orders"))
        .json(&taker)
        .send()
        .await
        .unwrap();
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry = retry_response
        .json::<SequencedSubmitOrderOutcome>()
        .await
        .unwrap();
    assert!(retry.outcome.duplicate);
    assert_eq!(
        retry.matcher_receipt.receipt_hash(),
        taker_outcome.matcher_receipt.receipt_hash()
    );
    assert_eq!(get_trades(&client, &base_url).await.len(), 1);
    shutdown.send(()).unwrap();
    server.await.unwrap();

    // A command/receipt mutation is fail-closed during the next recovery.
    let clean = std::fs::read_to_string(&journal_path).unwrap();
    let mut lines = clean.lines();
    let mut first: JournalEntryV1 = serde_json::from_str(lines.next().unwrap()).unwrap();
    first.receipt.signature.0[0] ^= 1;
    let tampered_path = directory.path().join("tampered.jsonl");
    let tampered = format!(
        "{}\n{}\n",
        serde_json::to_string(&first).unwrap(),
        lines.next().unwrap()
    );
    std::fs::write(&tampered_path, tampered).unwrap();
    assert!(Journal::open(tampered_path, engine_config(), matcher_config, CHAIN_ID).is_err());
}

async fn spawn_matcher(
    journal_path: &Path,
    matcher_config: &CentralMatcherConfigV1,
    matcher_secret: SecretKey,
) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
    let (journal, engine) = Journal::open(
        journal_path,
        engine_config(),
        matcher_config.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        matcher_secret,
        CHAIN_ID,
        100,
        PARENT_HEIGHT,
        PARENT_MTP,
        0,
    )
    .unwrap();
    let state = AppState::new(engine, journal, signer).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async move {
                let _ = receiver.await;
            })
            .await
            .unwrap();
    });
    (format!("http://{address}"), shutdown, server)
}

fn engine_config() -> EngineConfig {
    EngineConfig {
        demo_mode: false,
        chain_height: CHAIN_HEIGHT,
        ..EngineConfig::default()
    }
}

fn signed_request(
    secret_byte: u8,
    client_byte: u8,
    side: Side,
    price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
) -> SubmitOrderRequest {
    let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
    let public = matcher_public_key(&secret);
    let mut request = SubmitOrderRequest {
        client_order_id: hex::encode([client_byte; 16]),
        chain_id: hex::encode(CHAIN_ID),
        trader: hex::encode(public.serialize()),
        market: MARKET.to_owned(),
        side,
        limit_price_ticks: price,
        quantity_lots: quantity,
        time_in_force,
        post_only: false,
        reduce_only: false,
        max_fee_bps: 25,
        nonce: 1,
        valid_from_height: 1,
        expires_at_height: 200,
        signature: String::new(),
    };
    let order = ecx_matcher::engine::protocol_limit_order(&request).unwrap();
    let signed = SignedLimitOrder::sign(order, &secret).unwrap();
    request.signature = hex::encode(signed.signature.0);
    request
}

fn account_signature(secret: &SecretKey, trader: &str, timestamp: u64, nonce: [u8; 16]) -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let message =
        Message::from_digest_slice(&account_view_signing_digest(trader, timestamp, nonce)).unwrap();
    hex::encode(secp.sign_schnorr_no_aux_rand(&message, &keypair).as_ref())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

async fn get_book(client: &reqwest::Client, base_url: &str) -> PublicOrderBookSnapshot {
    client
        .get(format!("{base_url}/v1/markets/{MARKET}/orderbook"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn get_trades(client: &reqwest::Client, base_url: &str) -> Vec<PublicTrade> {
    client
        .get(format!("{base_url}/v1/markets/{MARKET}/trades"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
