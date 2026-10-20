use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ecx_matcher::{
    AppState, CentralMatcherSigner, EngineConfig, Journal, MARKET, Side, SubmitOrderRequest,
    TimeInForce, matcher_public_key, router,
};
use ecx_protocol_core::{CentralMatcherConfigV1, XOnlyKey};
use secp256k1::SecretKey;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn accepted_http_command_is_snapshotted_then_recovers_from_empty_tail() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("matcher.jsonl");
    let chain_id = [9; 32];
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let matcher_config = CentralMatcherConfigV1 {
        version: CentralMatcherConfigV1::VERSION,
        key_epoch: 0,
        signer: XOnlyKey(matcher_public_key(&secret).serialize()),
        genesis_sequence: 0,
        genesis_receipt_hash: [8; 32],
        forced_inclusion_blocks: 6,
    };
    let engine_config = EngineConfig {
        demo_mode: true,
        chain_height: 100,
        ..EngineConfig::default()
    };
    let (journal, engine) = Journal::open(
        &path,
        engine_config.clone(),
        matcher_config.clone(),
        chain_id,
    )
    .unwrap();
    let signer = CentralMatcherSigner::new(
        matcher_config.clone(),
        secret,
        chain_id,
        100,
        900_000,
        1_700_000_000,
        0,
    )
    .unwrap();
    let state = AppState::new(engine, journal, signer)
        .unwrap()
        .with_compaction(1, 10)
        .unwrap();
    let request = SubmitOrderRequest {
        client_order_id: "one".into(),
        chain_id: "demo-chain".into(),
        trader: "demo-maker".into(),
        market: MARKET.into(),
        side: Side::Buy,
        limit_price_ticks: 100,
        quantity_lots: 1,
        time_in_force: TimeInForce::Gtc,
        post_only: false,
        reduce_only: false,
        max_fee_bps: 25,
        nonce: 1,
        valid_from_height: 1,
        expires_at_height: 1_000,
        signature: String::new(),
    };
    let response = router(state)
        .oneshot(
            Request::post("/v1/orders")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert!(path.with_file_name("matcher.jsonl.snapshot").exists());

    let (journal, recovered) =
        Journal::open(&path, engine_config, matcher_config, chain_id).unwrap();
    assert_eq!(journal.head_sequence(), 1);
    assert_eq!(recovered.orderbook(10).bids[0].order_count, 1);
}
