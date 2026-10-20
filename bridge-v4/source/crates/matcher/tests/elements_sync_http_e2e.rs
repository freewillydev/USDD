#![recursion_limit = "256"]

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use ecx_matcher::{
    AppState, BondInboxSnapshotV2, CapitalMode, CapitalSnapshotV2, CentralMatcherSigner,
    ElementsConsensusContextV2, ElementsRpcClient, EngineConfig, ExecutionReceiptBatchViewV2,
    HealthView, Journal, MARKET, MatcherExecutionSnapshotV2, OracleModeV2, OracleSnapshotV2,
    PublicOrderBookSnapshot, SequencedSubmitOrderOutcome, SequencedSubmitOrderOutcomeV2, Side,
    SubmitOrderRequest, SubmitOrderRequestV2, TimeInForce, matcher_public_key, router,
};
use ecx_protocol_core::{
    CentralMatcherConfigV1, OrderRiskCommitmentV2, PRICE_SCALE, SignedLimitOrder, XOnlyKey,
};
use secp256k1::SecretKey;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    sync::{RwLock, oneshot},
    task::JoinHandle,
};

const CHAIN_ID: [u8; 32] = [0x19; 32];
const INITIAL_SIDECHAIN_HEIGHT: u64 = 100;
const INITIAL_PARENT_HEIGHT: u64 = 900_000;
const INITIAL_PARENT_MTP: u64 = 1_700_000_000;
const PROOF_PRODUCER_TOKEN: &str = "local-proof-producer-token-with-at-least-32-bytes";

#[derive(Clone)]
struct MockNodeState {
    context: Arc<RwLock<Value>>,
    active_hashes: Arc<RwLock<HashMap<u64, String>>>,
    calls: Arc<AtomicUsize>,
}

impl MockNodeState {
    fn new(context: &ElementsConsensusContextV2) -> Self {
        let mut active_hashes = HashMap::new();
        active_hashes.insert(
            context.sidechain_height,
            hex::encode(context.sidechain_block_hash),
        );
        Self {
            context: Arc::new(RwLock::new(rpc_value(context))),
            active_hashes: Arc::new(RwLock::new(active_hashes)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn set_context(&self, context: &ElementsConsensusContextV2) {
        *self.context.write().await = rpc_value(context);
        self.active_hashes.write().await.insert(
            context.sidechain_height,
            hex::encode(context.sidechain_block_hash),
        );
    }

    async fn set_active_hash(&self, height: u64, hash: [u8; 32]) {
        self.active_hashes
            .write()
            .await
            .insert(height, hex::encode(hash));
    }
}

#[tokio::test]
async fn matcher_tracks_authenticated_node_context_and_fails_closed() {
    let directory = TempDir::new().unwrap();
    let journal_path = directory.path().join("node-backed-matcher.jsonl");
    let matcher_secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let matcher_config = matcher_config(&matcher_secret);

    let initial = consensus_context(
        INITIAL_SIDECHAIN_HEIGHT,
        0x11,
        0x21,
        4,
        0x31,
        2,
        0x61,
        INITIAL_PARENT_HEIGHT,
        INITIAL_PARENT_MTP,
        0x41,
        INITIAL_PARENT_HEIGHT,
    );
    let mock = MockNodeState::new(&initial);
    let (node_url, node_shutdown, node_server) = spawn_mock_node(mock.clone()).await;
    let node_client = ElementsRpcClient::new(&node_url, Some("u".into()), Some("p".into()))
        .expect("loopback authenticated RPC client");
    let authenticated_initial = node_client.consensus_context().await.unwrap();
    assert_eq!(authenticated_initial, initial);

    let (matcher_url, matcher_shutdown, matcher_server) = spawn_node_backed_matcher(
        &journal_path,
        &matcher_config,
        matcher_secret,
        node_client,
        authenticated_initial,
    )
    .await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let height_101 = consensus_context(
        101,
        0x12,
        0x22,
        7,
        0x32,
        2,
        0x61,
        INITIAL_PARENT_HEIGHT + 1,
        INITIAL_PARENT_MTP + 600,
        0x42,
        INITIAL_PARENT_HEIGHT + 1,
    );
    mock.set_context(&height_101).await;
    let expiring_maker = signed_request(
        11,
        0x51,
        Side::Sell,
        100 * PRICE_SCALE,
        5,
        TimeInForce::Gtc,
        102,
    );
    let maker = post_order(&client, &matcher_url, &expiring_maker).await;
    assert_eq!(maker.matcher_receipt.body.observed_sidechain_height, 101);
    assert_eq!(maker.matcher_receipt.body.forced_inbox_cursor, 7);
    assert_eq!(
        maker.matcher_receipt.body.observed_parent_height,
        INITIAL_PARENT_HEIGHT + 1
    );
    assert_eq!(
        maker.matcher_receipt.body.observed_parent_mtp,
        INITIAL_PARENT_MTP + 600
    );
    maker.matcher_receipt.verify(&matcher_config).unwrap();
    assert_eq!(get_book(&client, &matcher_url).await.asks.len(), 1);

    let height_103 = consensus_context(
        103,
        0x13,
        0x23,
        9,
        0x33,
        3,
        0x62,
        INITIAL_PARENT_HEIGHT + 3,
        INITIAL_PARENT_MTP + 1_200,
        0x43,
        INITIAL_PARENT_HEIGHT + 3,
    );
    mock.set_context(&height_103).await;
    let taker = signed_request(
        12,
        0x52,
        Side::Buy,
        101 * PRICE_SCALE,
        3,
        TimeInForce::Ioc,
        200,
    );
    let taker = post_order(&client, &matcher_url, &taker).await;
    assert_eq!(taker.matcher_receipt.body.observed_sidechain_height, 103);
    assert_eq!(taker.matcher_receipt.body.forced_inbox_cursor, 9);
    assert!(taker.outcome.trades.is_empty());
    assert!(get_book(&client, &matcher_url).await.asks.is_empty());

    let health = get_health(&client, &matcher_url).await;
    assert_eq!(health.chain_height, 103);
    assert_eq!(health.matcher_sequence, 2);
    let durable_before_failure = std::fs::read_to_string(&journal_path).unwrap();
    assert_eq!(durable_before_failure.lines().count(), 2);
    let book_before_failure = get_book(&client, &matcher_url).await;

    // A restart must recover the full signed node context, not only the four
    // legacy receipt counters, before it serves or signs anything new.
    matcher_shutdown.send(()).unwrap();
    matcher_server.await.unwrap();
    let restart_node_client =
        ElementsRpcClient::new(&node_url, Some("u".into()), Some("p".into())).unwrap();
    let restart_context = restart_node_client.consensus_context().await.unwrap();
    let (matcher_url, matcher_shutdown, matcher_server) = spawn_node_backed_matcher(
        &journal_path,
        &matcher_config,
        matcher_secret,
        restart_node_client,
        restart_context,
    )
    .await;
    assert_eq!(get_book(&client, &matcher_url).await, book_before_failure);
    assert_eq!(get_health(&client, &matcher_url).await.matcher_sequence, 2);

    // A wallet retry must recover the original durable receipt even after the
    // node context advanced, the matcher restarted, and the order expired.
    // It must not assign a new priority sequence or bind the retry to the new
    // context as though it were a new command.
    let retry_response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(&expiring_maker)
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
        maker.matcher_receipt.receipt_hash()
    );
    assert_eq!(retry.matcher_receipt.body.observed_sidechain_height, 101);
    assert_eq!(get_health(&client, &matcher_url).await.matcher_sequence, 2);
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        durable_before_failure
    );

    // A higher tip is not enough: the last trusted matcher block must still
    // be an active ancestor, otherwise a deep reorg between polls could look
    // superficially monotonic.
    let higher_reorg = consensus_context(
        104,
        0x16,
        0x26,
        9,
        0x33,
        3,
        0x62,
        INITIAL_PARENT_HEIGHT + 4,
        INITIAL_PARENT_MTP + 1_800,
        0x46,
        INITIAL_PARENT_HEIGHT + 4,
    );
    mock.set_context(&higher_reorg).await;
    mock.set_active_hash(103, [0x99; 32]).await;
    let rejected = signed_request(
        15,
        0x55,
        Side::Sell,
        99 * PRICE_SCALE,
        1,
        TimeInForce::Gtc,
        200,
    );
    let response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(&rejected)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        durable_before_failure
    );
    mock.set_context(&height_103).await;

    // A different hash at the same height is a reorg (and changing any other
    // field at one immutable block height is equally invalid). The mutation is
    // rejected before either the engine or journal can change.
    let same_height_reorg = ElementsConsensusContextV2 {
        sidechain_block_hash: [0x14; 32],
        ..height_103.clone()
    };
    mock.set_context(&same_height_reorg).await;
    let rejected = signed_request(
        13,
        0x53,
        Side::Sell,
        99 * PRICE_SCALE,
        1,
        TimeInForce::Gtc,
        200,
    );
    let response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(&rejected)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        durable_before_failure
    );
    assert_eq!(get_book(&client, &matcher_url).await, book_before_failure);
    let readiness = client
        .get(format!("{matcher_url}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);

    let regressed = consensus_context(
        102,
        0x15,
        0x24,
        8,
        0x34,
        2,
        0x61,
        INITIAL_PARENT_HEIGHT + 2,
        INITIAL_PARENT_MTP + 900,
        0x44,
        INITIAL_PARENT_HEIGHT + 2,
    );
    mock.set_context(&regressed).await;
    let rejected = signed_request(
        14,
        0x54,
        Side::Buy,
        98 * PRICE_SCALE,
        1,
        TimeInForce::Ioc,
        200,
    );
    let response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(&rejected)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        durable_before_failure
    );
    assert!(mock.calls.load(Ordering::SeqCst) >= 5);

    matcher_shutdown.send(()).unwrap();
    matcher_server.await.unwrap();

    mock.set_context(&same_height_reorg).await;
    let (journal, engine) = Journal::open(
        &journal_path,
        engine_config(same_height_reorg.sidechain_height),
        matcher_config.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        matcher_secret,
        CHAIN_ID,
        same_height_reorg.sidechain_height,
        same_height_reorg.parent_height,
        same_height_reorg.parent_mtp,
        same_height_reorg.forced_inbox_entry_count,
    )
    .unwrap();
    let node_client =
        ElementsRpcClient::new(&node_url, Some("u".into()), Some("p".into())).unwrap();
    assert!(
        AppState::new_with_node(engine, journal, signer, node_client, same_height_reorg)
            .await
            .is_err()
    );
    node_shutdown.send(()).unwrap();
    node_server.await.unwrap();
}

#[tokio::test]
async fn v2_match_receipts_are_taker_private_producer_authorized_and_restart_durable() {
    let directory = TempDir::new().unwrap();
    let journal_path = directory.path().join("v2-node-backed-matcher.jsonl");
    let matcher_secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let matcher_config = matcher_config(&matcher_secret);
    let mut context = consensus_context(
        INITIAL_SIDECHAIN_HEIGHT,
        0x71,
        0x72,
        0,
        0x73,
        0,
        0x74,
        INITIAL_PARENT_HEIGHT,
        INITIAL_PARENT_MTP,
        0x75,
        INITIAL_PARENT_HEIGHT,
    );
    context.capital_snapshot = Some(healthy_capital_snapshot(context.exchange_state_root));
    let mock = MockNodeState::new(&context);
    let (node_url, node_shutdown, node_server) = spawn_mock_node(mock).await;
    let node_client = ElementsRpcClient::new(&node_url, Some("u".into()), Some("p".into()))
        .expect("loopback authenticated RPC client");
    let authenticated = node_client.consensus_context().await.unwrap();
    let (matcher_url, matcher_shutdown, matcher_server) = spawn_v2_node_backed_matcher(
        &journal_path,
        &matcher_config,
        matcher_secret,
        node_client,
        authenticated,
    )
    .await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // A legacy placement has no signed V2 margin selection. Mixing it into
    // this book would create a fill that the V2 transition must reject.
    let legacy = signed_request(
        30,
        0x30,
        Side::Sell,
        99 * PRICE_SCALE,
        PRICE_SCALE,
        TimeInForce::Gtc,
        INITIAL_SIDECHAIN_HEIGHT + 100,
    );
    let legacy_response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(&legacy)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

    let maker_one = signed_request_v2(
        31,
        0x31,
        Side::Sell,
        100 * PRICE_SCALE,
        2 * PRICE_SCALE,
        1,
        [0x81; 32],
    );
    let maker_two = signed_request_v2(
        32,
        0x32,
        Side::Sell,
        101 * PRICE_SCALE,
        3 * PRICE_SCALE,
        1,
        [0x81; 32],
    );
    let taker = signed_request_v2(
        33,
        0x33,
        Side::Buy,
        101 * PRICE_SCALE,
        5 * PRICE_SCALE,
        1,
        [0x81; 32],
    );
    assert!(
        post_order_v2(&client, &matcher_url, &maker_one)
            .await
            .execution_receipts
            .is_empty()
    );
    assert!(
        post_order_v2(&client, &matcher_url, &maker_two)
            .await
            .execution_receipts
            .is_empty()
    );
    let taker_outcome = post_order_v2(&client, &matcher_url, &taker).await;
    assert_eq!(taker_outcome.execution_receipts.len(), 2);
    assert_eq!(
        taker_outcome
            .execution_receipts
            .iter()
            .map(|receipt| receipt.body.match_sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(taker_outcome.execution_receipts.iter().all(|receipt| {
        receipt.body.admission_sequence == 3
            && receipt.body.observed_sidechain_height == context.sidechain_height
            && receipt.body.execution_parent.block_hash == context.parent_block_hash
            && receipt.verify(&matcher_config).is_ok()
    }));

    // Public trade transport intentionally does not reveal the proof-private
    // quantities, order IDs, participants or execution receipts.
    let public_trades = client
        .get(format!("{matcher_url}/v1/markets/{MARKET}/trades?limit=10"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let public_json = serde_json::to_string(&public_trades).unwrap();
    for forbidden in [
        "quantity",
        "order_id",
        "buyer",
        "seller",
        "execution_receipt",
    ] {
        assert!(!public_json.contains(forbidden), "public leak: {forbidden}");
    }

    let receipt_uri =
        format!("{matcher_url}/v2/proof/execution-receipts?previous_sequence=0&limit=10");
    assert_eq!(
        client.get(&receipt_uri).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let batch = client
        .get(&receipt_uri)
        .bearer_auth(PROOF_PRODUCER_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ExecutionReceiptBatchViewV2>()
        .await
        .unwrap();
    assert_eq!(batch.previous_sequence, 0);
    assert_eq!(batch.next_sequence, 2);
    assert_eq!(batch.durable_head_sequence, 2);
    assert_eq!(batch.execution_receipts, taker_outcome.execution_receipts);
    assert_eq!(batch.taker_admission_receipts.len(), 1);

    matcher_shutdown.send(()).unwrap();
    matcher_server.await.unwrap();
    let restart_node_client =
        ElementsRpcClient::new(&node_url, Some("u".into()), Some("p".into())).unwrap();
    let restart_context = restart_node_client.consensus_context().await.unwrap();
    let (matcher_url, matcher_shutdown, matcher_server) = spawn_v2_node_backed_matcher(
        &journal_path,
        &matcher_config,
        matcher_secret,
        restart_node_client,
        restart_context,
    )
    .await;
    let restarted_batch = client
        .get(format!(
            "{matcher_url}/v2/proof/execution-receipts?previous_sequence=0&limit=10"
        ))
        .bearer_auth(PROOF_PRODUCER_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ExecutionReceiptBatchViewV2>()
        .await
        .unwrap();
    assert_eq!(restarted_batch, batch);

    matcher_shutdown.send(()).unwrap();
    matcher_server.await.unwrap();
    node_shutdown.send(()).unwrap();
    node_server.await.unwrap();
}

#[tokio::test]
async fn node_backed_startup_rejects_signer_context_mismatch() {
    let directory = TempDir::new().unwrap();
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let config = matcher_config(&secret);
    let initial = consensus_context(
        INITIAL_SIDECHAIN_HEIGHT,
        0x11,
        0x21,
        4,
        0x31,
        2,
        0x61,
        INITIAL_PARENT_HEIGHT,
        INITIAL_PARENT_MTP,
        0x41,
        INITIAL_PARENT_HEIGHT,
    );
    let (journal, engine) = Journal::open(
        directory.path().join("mismatched.jsonl"),
        engine_config(INITIAL_SIDECHAIN_HEIGHT),
        config.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        config,
        secret,
        CHAIN_ID,
        initial.sidechain_height,
        initial.parent_height,
        initial.parent_mtp,
        initial.forced_inbox_entry_count + 1,
    )
    .unwrap();
    let node_client =
        ElementsRpcClient::new("http://127.0.0.1:1", Some("u".into()), Some("p".into())).unwrap();

    assert!(
        AppState::new_with_node(engine, journal, signer, node_client, initial)
            .await
            .is_err()
    );
}

async fn mock_rpc(
    State(state): State<MockNodeState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Basic dTpw")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let result = match request.get("method").and_then(Value::as_str) {
        Some("getecxconsensuscontext") if request.get("params") == Some(&json!([])) => {
            state.context.read().await.clone()
        }
        Some("getblockhash") => {
            let Some(height) = request
                .get("params")
                .and_then(Value::as_array)
                .and_then(|params| params.first())
                .and_then(Value::as_u64)
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(hash) = state.active_hashes.read().await.get(&height).cloned() else {
                return StatusCode::NOT_FOUND.into_response();
            };
            Value::String(hash)
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
        "error": null
    }))
    .into_response()
}

async fn spawn_mock_node(state: MockNodeState) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(mock_rpc)).with_state(state),
        )
        .with_graceful_shutdown(async move {
            let _ = receiver.await;
        })
        .await
        .unwrap();
    });
    (format!("http://{address}"), shutdown, server)
}

async fn spawn_node_backed_matcher(
    journal_path: &Path,
    matcher_config: &CentralMatcherConfigV1,
    matcher_secret: SecretKey,
    node_client: ElementsRpcClient,
    initial_context: ElementsConsensusContextV2,
) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
    let (journal, engine) = Journal::open(
        journal_path,
        engine_config(initial_context.sidechain_height),
        matcher_config.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        matcher_secret,
        CHAIN_ID,
        initial_context.sidechain_height,
        initial_context.parent_height,
        initial_context.parent_mtp,
        initial_context.forced_inbox_entry_count,
    )
    .unwrap();
    let state = AppState::new_with_node(engine, journal, signer, node_client, initial_context)
        .await
        .unwrap();
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

async fn spawn_v2_node_backed_matcher(
    journal_path: &Path,
    matcher_config: &CentralMatcherConfigV1,
    matcher_secret: SecretKey,
    node_client: ElementsRpcClient,
    initial_context: ElementsConsensusContextV2,
) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
    let (journal, engine) = Journal::open(
        journal_path,
        engine_config(initial_context.sidechain_height),
        matcher_config.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        matcher_secret,
        CHAIN_ID,
        initial_context.sidechain_height,
        initial_context.parent_height,
        initial_context.parent_mtp,
        initial_context.forced_inbox_entry_count,
    )
    .unwrap();
    let state = AppState::new_with_node(engine, journal, signer, node_client, initial_context)
        .await
        .unwrap()
        .with_v2_capital_controls(true)
        .await
        .unwrap()
        .with_proof_producer_token(PROOF_PRODUCER_TOKEN)
        .unwrap();
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

fn matcher_config(secret: &SecretKey) -> CentralMatcherConfigV1 {
    CentralMatcherConfigV1 {
        version: CentralMatcherConfigV1::VERSION,
        key_epoch: 0,
        signer: XOnlyKey(matcher_public_key(secret).serialize()),
        genesis_sequence: 0,
        genesis_receipt_hash: [0x51; 32],
        forced_inclusion_blocks: 6,
    }
}

fn engine_config(chain_height: u64) -> EngineConfig {
    EngineConfig {
        demo_mode: false,
        chain_height,
        ..EngineConfig::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn consensus_context(
    sidechain_height: u64,
    sidechain_hash_byte: u8,
    exchange_root_byte: u8,
    forced_count: u64,
    forced_root_byte: u8,
    deposit_count: u64,
    deposit_root_byte: u8,
    parent_height: u64,
    parent_mtp: u64,
    parent_hash_byte: u8,
    source_parent_height: u64,
) -> ElementsConsensusContextV2 {
    ElementsConsensusContextV2 {
        sidechain_height,
        sidechain_block_hash: [sidechain_hash_byte; 32],
        exchange_state_root: [exchange_root_byte; 32],
        forced_inbox_head_root: [forced_root_byte; 32],
        forced_inbox_entry_count: forced_count,
        forced_inbox_processed_cursor: forced_count,
        deposit_inbox_head_root: [deposit_root_byte; 32],
        deposit_inbox_entry_count: deposit_count,
        deposit_inbox_processed_cursor: deposit_count,
        parent_height,
        parent_mtp,
        parent_block_hash: [parent_hash_byte; 32],
        source_parent_height,
        capital_snapshot: None,
    }
}

fn healthy_capital_snapshot(exchange_state_root: [u8; 32]) -> CapitalSnapshotV2 {
    CapitalSnapshotV2 {
        version: CapitalSnapshotV2::VERSION,
        exchange_state_root,
        configuration_hash: [0x81; 32],
        bond_asset_id: [0x82; 32],
        bond_deployment_commitment: [0x83; 32],
        transition_program_id: [0x84; 32],
        transition_cmr: [0x85; 32],
        covenant_state_hash: [0x87; 32],
        bond_state_root: [0x88; 32],
        funding_state_root: [0x89; 32],
        insurance_reserve_quote_units: 125,
        outstanding_bond_units: 100,
        nav_quote_units_per_bond: 125_000_000,
        deficit_quote_units: 100,
        target_reserve_quote_units: 125,
        coverage_bps: 12_500,
        mode: CapitalMode::Normal,
        minimum_authenticated_price: 1,
        maximum_authenticated_price: 10,
        funding_epoch: 1,
        funding_rate_ppm: 0,
        redemption_queue_root: [0x86; 32],
        redemption_head: 0,
        redemption_tail: 0,
        queued_redemption_bond_units: 0,
        oracle: OracleSnapshotV2 {
            certificate_hash: [0x8a; 32],
            valid_through_parent_mtp: INITIAL_PARENT_MTP + 86_400,
            mode: OracleModeV2::Normal,
        },
        encrypted_availability_root: [0x8b; 32],
        bond_inbox: BondInboxSnapshotV2 {
            head_root: [0x8c; 32],
            entry_count: 0,
            processed_root: [0x8d; 32],
            processed_cursor: 0,
            outcome_root: [0x8e; 32],
            outcome_count: 0,
            node_verified_source_head_root: [0x8c; 32],
            node_verified_source_entry_count: 0,
        },
        matcher_execution: MatcherExecutionSnapshotV2 {
            receipt_batch_root: [0x8f; 32],
            previous_sequence: 0,
            sequence: 0,
        },
        last_transition_sidechain_height: 9,
        legacy_fee_pool_quote_units: 0,
    }
}

fn rpc_value(context: &ElementsConsensusContextV2) -> Value {
    json!({
        "sidechainheight": context.sidechain_height,
        "sidechainblockhash": hex::encode(context.sidechain_block_hash),
        "exchangestateroot": hex::encode(context.exchange_state_root),
        "forcedinbox": {
            "headroot": hex::encode(context.forced_inbox_head_root),
            "entrycount": context.forced_inbox_entry_count,
            "nextindex": context.forced_inbox_entry_count
            ,"processedcursor": context.forced_inbox_processed_cursor
        },
        "depositinbox": {
            "headroot": hex::encode(context.deposit_inbox_head_root),
            "entrycount": context.deposit_inbox_entry_count,
            "nextindex": context.deposit_inbox_entry_count,
            "processedcursor": context.deposit_inbox_processed_cursor
        },
        "bmm": {
            "authenticated": true,
            "parentheight": context.parent_height,
            "parentmtp": context.parent_mtp,
            "parentblockhash": hex::encode(context.parent_block_hash)
        },
        "sourceparentheight": context.source_parent_height,
        "sourcebacklogoldestparentheight": 0,
        "capital": context.capital_snapshot.as_ref().map(|capital| json!({
            "version": capital.version,
            "proofprofile": "finite-v18",
            "exchangestateroot": hex::encode(capital.exchange_state_root),
            "configurationhash": hex::encode(capital.configuration_hash),
            "bondactionconfigurationhash": hex::encode(capital.configuration_hash),
            "bondassetid": hex::encode(capital.bond_asset_id),
            "bonddeploymentcommitment": hex::encode(capital.bond_deployment_commitment),
            "transitionprogramid": hex::encode(capital.transition_program_id),
            "transitioncmr": hex::encode(capital.transition_cmr),
            "covenantstatehash": hex::encode(capital.covenant_state_hash),
            "bondstateroot": hex::encode(capital.bond_state_root),
            "fundingstateroot": hex::encode(capital.funding_state_root),
            "bondinventorycovenanthash": "ab".repeat(32),
            "insurancereservequoteunits": capital.insurance_reserve_quote_units,
            "issuedbondunits": ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS,
            "outstandingbondunits": capital.outstanding_bond_units,
            "inventorybondunits": ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS
                - capital.outstanding_bond_units,
            "navquoteunitsperbond": capital.nav_quote_units_per_bond,
            "deficitquoteunits": capital.deficit_quote_units,
            "targetreservequoteunits": capital.target_reserve_quote_units,
            "coveragebps": capital.coverage_bps,
            "controlledquoteunits": capital.insurance_reserve_quote_units,
            "mode": match capital.mode {
                CapitalMode::Normal => "Normal",
                CapitalMode::ReduceOnly => "ReduceOnly",
                CapitalMode::Recovery => "Recovery",
            },
            "minimumauthenticatedprice": capital.minimum_authenticated_price,
            "maximumauthenticatedprice": capital.maximum_authenticated_price,
            "fundingepoch": capital.funding_epoch,
            "fundingrateppm": capital.funding_rate_ppm,
            "globalfundingindexnumerator": 0,
            "redemptionqueueroot": hex::encode(capital.redemption_queue_root),
            "redemptionhead": capital.redemption_head,
            "redemptiontail": capital.redemption_tail,
            "queuedredemptionbondunits": capital.queued_redemption_bond_units,
            "oracle": {
                "certificatehash": hex::encode(capital.oracle.certificate_hash),
                "validthroughparentmtp": capital.oracle.valid_through_parent_mtp,
                "mode": match capital.oracle.mode {
                    OracleModeV2::Normal => "Normal",
                    OracleModeV2::ReduceOnly => "ReduceOnly",
                    OracleModeV2::Disputed => "Disputed",
                    OracleModeV2::Halt => "Halt",
                },
            },
            "encryptedavailabilityroot": hex::encode(capital.encrypted_availability_root),
            "bondinbox": {
                "headroot": hex::encode(capital.bond_inbox.head_root),
                "entrycount": capital.bond_inbox.entry_count,
                "processedroot": hex::encode(capital.bond_inbox.processed_root),
                "processedcursor": capital.bond_inbox.processed_cursor,
                "outcomeroot": hex::encode(capital.bond_inbox.outcome_root),
                "outcomecount": capital.bond_inbox.outcome_count,
                "nodeverifiedsourceheadroot": hex::encode(capital.bond_inbox.node_verified_source_head_root),
                "nodeverifiedsourceentrycount": capital.bond_inbox.node_verified_source_entry_count,
            },
            "matcherexecution": {
                "receiptbatchroot": hex::encode(capital.matcher_execution.receipt_batch_root),
                "previoussequence": capital.matcher_execution.previous_sequence,
                "sequence": capital.matcher_execution.sequence,
            },
            "lasttransitionsidechainheight": capital.last_transition_sidechain_height,
            "operationallysafe": true,
            "legacyfeepoolquoteunits": capital.legacy_fee_pool_quote_units
        }))
    })
}

fn signed_request(
    secret_byte: u8,
    client_byte: u8,
    side: Side,
    price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
    expires_at_height: u64,
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
        expires_at_height,
        signature: String::new(),
    };
    let order = ecx_matcher::engine::protocol_limit_order(&request).unwrap();
    let signed = SignedLimitOrder::sign(order, &secret).unwrap();
    request.signature = hex::encode(signed.signature.0);
    request
}

fn signed_request_v2(
    secret_byte: u8,
    client_byte: u8,
    side: Side,
    price: u64,
    quantity: u64,
    nonce: u64,
    configuration_hash: [u8; 32],
) -> SubmitOrderRequestV2 {
    let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
    let mut order = signed_request(
        secret_byte,
        client_byte,
        side,
        price,
        quantity,
        TimeInForce::Gtc,
        INITIAL_SIDECHAIN_HEIGHT + 100,
    );
    order.nonce = nonce;
    let signed = SignedLimitOrder::sign(
        ecx_matcher::engine::protocol_limit_order(&order).unwrap(),
        &secret,
    )
    .unwrap();
    order.signature = hex::encode(signed.signature.0);
    let risk = OrderRiskCommitmentV2::sign(
        configuration_hash,
        signed.order_id(),
        signed.order.trader,
        1_000,
        &secret,
    )
    .unwrap();
    SubmitOrderRequestV2 {
        order,
        configuration_hash: hex::encode(configuration_hash),
        initial_margin_bps: 1_000,
        risk_commitment_signature: hex::encode(risk.signature.0),
    }
}

async fn post_order(
    client: &reqwest::Client,
    matcher_url: &str,
    request: &SubmitOrderRequest,
) -> SequencedSubmitOrderOutcome {
    let response = client
        .post(format!("{matcher_url}/v1/orders"))
        .json(request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json().await.unwrap()
}

async fn post_order_v2(
    client: &reqwest::Client,
    matcher_url: &str,
    request: &SubmitOrderRequestV2,
) -> SequencedSubmitOrderOutcomeV2 {
    let response = client
        .post(format!("{matcher_url}/v2/orders"))
        .json(request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json().await.unwrap()
}

async fn get_book(client: &reqwest::Client, matcher_url: &str) -> PublicOrderBookSnapshot {
    client
        .get(format!("{matcher_url}/v1/markets/{MARKET}/orderbook"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn get_health(client: &reqwest::Client, matcher_url: &str) -> HealthView {
    client
        .get(format!("{matcher_url}/health"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
