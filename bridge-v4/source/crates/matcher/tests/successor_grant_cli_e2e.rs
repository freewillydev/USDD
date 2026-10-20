use std::{
    fs,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::{get, post},
};
use ecx_matcher::{
    ElementsRpcClient, SuccessorMatcherPlaceRecoveryV2, SuccessorPlaceRequestV2,
    SuccessorPlaceResponseV2, SuccessorTraderArchiveTransitionV2,
    SuccessorTraderStateComposeInputV2, SuccessorTraderStateGrantRequestV2,
    SuccessorTraderStateGrantResponseV2, SuccessorTraderStateGrantServiceV2,
    SuccessorTraderStateGrantV2, SuccessorTraderStateSnapshotV2, V2IdentityPins,
    successor_trader_snapshot_filename, successor_trader_state_grant_router,
};
use ecx_protocol_core::{
    BOND_FIXED_SUPPLY_ATOMS, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
    IncrementalAccountingBoundsV2, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2,
    Int256V2, OrderFlags, OrderRiskCommitmentV2, Price, Quantity, RiskParams, Side,
    SuccessorCentralMatcherConfigV2, SuccessorCentralMatcherReceiptV2, SuccessorLimitOrderV2,
    SuccessorMatcherCommandKindV2, SuccessorMatcherReceiptBodyV2, SuccessorSignedLimitOrderV2,
    TimeInForce, TraderLeafV2, TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2,
    TraderStateReadBatchProofV2, XOnlyKey, successor_matcher_order_command_hash_v2,
};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::Serialize;
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tower::ServiceExt;

fn identity(byte: u8) -> (SecretKey, XOnlyKey) {
    let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
    let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&pair);
    (secret, XOnlyKey(public.serialize()))
}

fn configuration() -> IncrementalSuccessorConfigurationV2 {
    let matcher = matcher_configuration();
    IncrementalSuccessorConfigurationV2 {
        version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        chain_id: [7; 32],
        market: ECX_USDD_MARKET,
        order_configuration_hash: [3; 32],
        successor_matcher_configuration_hash: matcher.digest(),
        risk_params: RiskParams::default(),
        accounting_bounds: IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: u128::from(BOND_FIXED_SUPPLY_ATOMS),
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 20_000_000_000,
            maximum_price_atoms: 10_000_000_000,
        },
        maximum_trader_updates: 64,
        maximum_order_operations: 64,
        maximum_nullifier_updates_per_kind: 64,
    }
}

fn matcher_configuration() -> SuccessorCentralMatcherConfigV2 {
    let (_, matcher_key) = identity(61);
    SuccessorCentralMatcherConfigV2 {
        version: SuccessorCentralMatcherConfigV2::VERSION,
        key_epoch: 9,
        signer: matcher_key,
        genesis_sequence: (1u128 << 96) + 10,
        genesis_receipt_hash: [8; 32],
        forced_inclusion_blocks: 6,
    }
}

fn fixture() -> (
    IncrementalSuccessorConfigurationV2,
    IncrementalPublicStateV2,
    TraderStateReadBatchProofV2,
    SuccessorSignedLimitOrderV2,
    SuccessorMatcherPlaceRecoveryV2,
) {
    let configuration = configuration();
    let (trader_secret, trader) = identity(62);
    let order = SuccessorSignedLimitOrderV2::sign(
        SuccessorLimitOrderV2 {
            version: SuccessorLimitOrderV2::VERSION,
            chain_id: configuration.chain_id,
            market: configuration.market,
            trader,
            side: Side::Sell,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::NONE,
            limit_price: Price::new(100_000_000).unwrap(),
            quantity: Quantity::new(3).unwrap(),
            client_order_id: [4; 16],
            max_fee_bps: 5,
            nonce: (1u128 << 104) + 4,
            valid_from_height: 10,
            expires_at_height: 20,
        },
        &trader_secret,
    )
    .unwrap();
    let recovery = SuccessorMatcherPlaceRecoveryV2 {
        risk: OrderRiskCommitmentV2::sign(
            configuration.order_configuration_hash,
            order.order_id(),
            trader,
            1_000,
            &trader_secret,
        )
        .unwrap(),
        trader_order_generation: (1u128 << 100) + 7,
        salt: [9; 32],
        parent_block_hash: [0x55; 32],
    };
    let leaf = TraderLeafV2 {
        version: TraderLeafV2::VERSION,
        trader,
        account_nonce: 0,
        collateral_atoms: 0,
        cash_residual_numerator: 0,
        position_size_atoms: 0,
        signed_cost_basis_numerator: Int256V2::ZERO,
        last_funding_index_numerator: 0,
        selected_initial_margin_bps: 1_000,
        order_generation: recovery.trader_order_generation,
        salt: [0x31; 32],
    };
    let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
        vec![TraderStateBatchLeafUpdateV2 {
            trader,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
        }],
        configuration.accounting_bounds,
    )
    .unwrap();
    let mut state =
        IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
    state.trader_root = insertion
        .verify(state.trader_root, configuration.accounting_bounds, 1)
        .unwrap();
    let read = TraderStateReadBatchProofV2 {
        leaves: vec![leaf],
        frontier: insertion.frontier,
    };
    (configuration, state, read, order, recovery)
}

fn node_result(
    configuration: IncrementalSuccessorConfigurationV2,
    state: IncrementalPublicStateV2,
) -> Value {
    let mut capital = serde_json::Map::new();
    macro_rules! field {
        ($name:literal, $value:expr) => {
            capital.insert($name.into(), json!($value));
        };
    }
    field!("version", 3);
    field!("proofprofile", "incremental-successor");
    field!(
        "exchangestateroot",
        hex::encode(state.state_root(configuration).unwrap())
    );
    field!(
        "configurationhash",
        hex::encode(configuration.digest().unwrap())
    );
    field!("bondactionconfigurationhash", "66".repeat(32));
    field!("bondassetid", "77".repeat(32));
    field!("bonddeploymentcommitment", "88".repeat(32));
    field!("transitionprogramid", "99".repeat(32));
    field!("transitioncmr", "aa".repeat(32));
    field!("covenantstatehash", "ab".repeat(32));
    field!("bondstateroot", "ac".repeat(32));
    field!("fundingstateroot", "ad".repeat(32));
    field!("bondinventorycovenanthash", "ae".repeat(32));
    field!("insurancereservequoteunits", 125);
    field!("issuedbondunits", BOND_FIXED_SUPPLY_ATOMS);
    field!("outstandingbondunits", 100);
    field!("inventorybondunits", BOND_FIXED_SUPPLY_ATOMS - 100);
    field!("navquoteunitsperbond", 125_000_000);
    field!("deficitquoteunits", 100);
    field!("targetreservequoteunits", 125);
    field!("coveragebps", 12_500);
    field!("controlledquoteunits", 125);
    field!("mode", "Normal");
    field!("minimumauthenticatedprice", 1);
    field!("maximumauthenticatedprice", 10);
    field!("fundingepoch", 7);
    field!("fundingrateppm", 0);
    field!("globalfundingindexnumerator", 0);
    field!("redemptionqueueroot", "bb".repeat(32));
    field!("redemptionhead", 0);
    field!("redemptiontail", 0);
    field!("queuedredemptionbondunits", 0);
    field!(
        "oracle",
        json!({"certificatehash": "bc".repeat(32), "validthroughparentmtp": 1_100, "mode": "Normal"})
    );
    field!("encryptedavailabilityroot", "bd".repeat(32));
    field!(
        "bondinbox",
        json!({
            "headroot": "be".repeat(32), "entrycount": 0,
            "processedroot": "bf".repeat(32), "processedcursor": 0,
            "outcomeroot": "c0".repeat(32), "outcomecount": 0,
            "nodeverifiedsourceheadroot": "be".repeat(32), "nodeverifiedsourceentrycount": 0
        })
    );
    field!(
        "matcherexecution",
        json!({"receiptbatchroot": "c1".repeat(32), "previoussequence": 0, "sequence": 0})
    );
    field!("lasttransitionsidechainheight", 9);
    field!("operationallysafe", true);
    field!("legacyfeepoolquoteunits", 0);
    json!({
        "sidechainheight": 10,
        "sidechainblockhash": "11".repeat(32),
        "exchangestateroot": hex::encode(state.state_root(configuration).unwrap()),
        "forcedinbox": {"headroot": "33".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
        "depositinbox": {"headroot": "44".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
        "bmm": {"authenticated": true, "parentheight": 100, "parentmtp": 1_000, "parentblockhash": "55".repeat(32)},
        "sourceparentheight": 100,
        "sourcebacklogoldestparentheight": 0,
        "capital": Value::Object(capital)
    })
}

fn successor_node_result_at(
    configuration: IncrementalSuccessorConfigurationV2,
    state: IncrementalPublicStateV2,
    sidechain_block_byte: u8,
    parent_block_byte: u8,
) -> Value {
    let mut result = node_result(configuration, state);
    result["sidechainheight"] = json!(state.sidechain_height);
    result["sidechainblockhash"] = json!(hex::encode([sidechain_block_byte; 32]));
    result["bmm"]["parentheight"] = json!(state.sidechain_height + 90);
    result["bmm"]["parentmtp"] = json!(state.parent_median_time_past);
    result["bmm"]["parentblockhash"] = json!(hex::encode([parent_block_byte; 32]));
    result["sourceparentheight"] = json!(state.sidechain_height + 90);
    result["capital"]["lasttransitionsidechainheight"] = json!(state.sidechain_height);
    result["capital"]["matcherexecution"]["previoussequence"] = json!(state.matcher_sequence);
    result["capital"]["matcherexecution"]["sequence"] = json!(state.matcher_sequence);
    result
}

fn write_private(path: &std::path::Path, value: &impl Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn successor_snapshot_composer_writes_only_the_verified_root_named_file() {
    let (configuration, state, read, order, _) = fixture();
    let temporary = tempdir().unwrap();
    let output_directory = temporary.path().join("snapshots");
    fs::create_dir(&output_directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config_path = temporary.path().join("config.json");
    let input_path = temporary.path().join("compose-input.json");
    write_private(&config_path, &configuration);
    write_private(
        &input_path,
        &SuccessorTraderStateComposeInputV2 {
            version: SuccessorTraderStateComposeInputV2::VERSION,
            expected_exchange_state_root: state.state_root(configuration).unwrap(),
            state,
            trader_leaf: read.leaves[0].clone(),
            frontier: read.frontier.clone(),
        },
    );

    let mut command = Command::new(env!(
        "CARGO_BIN_EXE_ecx-successor-trader-state-snapshot-compose"
    ));
    command
        .arg("--successor-configuration-file")
        .arg(&config_path)
        .arg("--compose-input-file")
        .arg(&input_path)
        .arg("--output-directory")
        .arg(&output_directory);
    let first = command.output().unwrap();
    assert!(
        first.status.success(),
        "snapshot composer failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let output = output_directory.join(successor_trader_snapshot_filename(
        state.state_root(configuration).unwrap(),
        order.order.trader,
    ));
    let snapshot: SuccessorTraderStateSnapshotV2 =
        serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(snapshot.state, state);
    assert_eq!(snapshot.trader_read, read);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o077,
            0
        );
        assert!(fs::metadata(&output).unwrap().ino() != 0);
    }

    let second = command.output().unwrap();
    assert!(!second.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successor_online_trader_archive_bootstraps_advances_snapshots_and_reselects_on_reorg() {
    use std::sync::RwLock;

    let configuration = configuration();
    let empty =
        IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
    let (trader_secret, trader) = identity(62);
    let _ = trader_secret;
    let leaf = TraderLeafV2 {
        version: TraderLeafV2::VERSION,
        trader,
        account_nonce: 1,
        collateral_atoms: 0,
        cash_residual_numerator: 0,
        position_size_atoms: 0,
        signed_cost_basis_numerator: Int256V2::ZERO,
        last_funding_index_numerator: 0,
        selected_initial_margin_bps: 1_000,
        order_generation: 1,
        salt: [0x31; 32],
    };
    let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
        vec![TraderStateBatchLeafUpdateV2 {
            trader,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
        }],
        configuration.accounting_bounds,
    )
    .unwrap();
    let mut next = empty;
    next.sidechain_height = 11;
    next.parent_median_time_past = 1_001;
    next.trader_root = insertion
        .verify(empty.trader_root, configuration.accounting_bounds, 1)
        .unwrap();

    let first_result = successor_node_result_at(configuration, empty, 0x11, 0x55);
    let second_result = successor_node_result_at(configuration, next, 0x12, 0x56);
    let current = Arc::new(RwLock::new(first_result.clone()));
    let current_for_server = current.clone();
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let current = current_for_server.clone();
            async move {
                let result = if request["method"] == "getblockhash" {
                    json!("11".repeat(32))
                } else {
                    current.read().unwrap().clone()
                };
                Json(json!({
                    "jsonrpc": "2.0", "id": request["id"],
                    "result": result, "error": null
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let temporary = tempdir().unwrap();
    let archive_directory = temporary.path().join("archive");
    let snapshot_directory = temporary.path().join("snapshots");
    fs::create_dir(&archive_directory).unwrap();
    fs::create_dir(&snapshot_directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&archive_directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&snapshot_directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config_path = temporary.path().join("config.json");
    let empty_path = temporary.path().join("empty.json");
    let transition_path = temporary.path().join("transition.json");
    write_private(&config_path, &configuration);
    write_private(&empty_path, &empty);
    write_private(
        &transition_path,
        &SuccessorTraderArchiveTransitionV2 {
            version: SuccessorTraderArchiveTransitionV2::VERSION,
            previous_sidechain_block_hash: [0x11; 32],
            previous_state: empty,
            next_state: next,
            trader_batch: Some(insertion),
        },
    );

    let extractor = env!("CARGO_BIN_EXE_ecx-successor-trader-state-extract");
    let common = |command: &mut Command| {
        command
            .arg("--successor-configuration-file")
            .arg(&config_path)
            .arg("--archive-directory")
            .arg(&archive_directory)
            .arg("--elements-rpc-url")
            .arg(format!("http://{address}"))
            .arg("--bond-action-configuration-hash")
            .arg("66".repeat(32))
            .arg("--bond-asset-id")
            .arg("77".repeat(32))
            .arg("--bond-deployment-commitment")
            .arg("88".repeat(32))
            .arg("--successor-transition-program-id")
            .arg("99".repeat(32))
            .arg("--successor-transition-cmr")
            .arg("aa".repeat(32));
    };

    let mut bootstrap = Command::new(extractor);
    common(&mut bootstrap);
    bootstrap
        .arg("bootstrap")
        .arg("--public-state-file")
        .arg(&empty_path);
    let output = bootstrap.output().unwrap();
    assert!(
        output.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    *current.write().unwrap() = second_result;
    let mut advance = Command::new(extractor);
    common(&mut advance);
    advance
        .arg("advance")
        .arg("--transition-file")
        .arg(&transition_path);
    let output = advance.output().unwrap();
    assert!(
        output.status.success(),
        "advance failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut snapshot = Command::new(extractor);
    common(&mut snapshot);
    snapshot
        .arg("snapshot")
        .arg("--trader")
        .arg(hex::encode(trader.0))
        .arg("--output-directory")
        .arg(&snapshot_directory);
    let output = snapshot.output().unwrap();
    assert!(
        output.status.success(),
        "snapshot failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot_path = snapshot_directory.join(successor_trader_snapshot_filename(
        next.state_root(configuration).unwrap(),
        trader,
    ));
    let decoded: SuccessorTraderStateSnapshotV2 =
        serde_json::from_slice(&fs::read(snapshot_path).unwrap()).unwrap();
    assert_eq!(decoded.state, next);
    assert_eq!(decoded.trader_read.leaves, vec![leaf]);

    // A reorg to the retained bootstrap checkpoint selects that exact file;
    // the trader is correctly absent rather than being read from the orphan.
    *current.write().unwrap() = first_result;
    let rollback_directory = temporary.path().join("rollback-snapshots");
    fs::create_dir(&rollback_directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&rollback_directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut rollback = Command::new(extractor);
    common(&mut rollback);
    rollback
        .arg("snapshot")
        .arg("--trader")
        .arg(hex::encode(trader.0))
        .arg("--output-directory")
        .arg(&rollback_directory);
    let output = rollback.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trader is absent"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successor_grant_cli_binds_node_root_and_refuses_overwrite() {
    let (configuration, state, read, order, recovery) = fixture();
    let result = node_result(configuration, state);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let result = result.clone();
            async move {
                Json(
                    json!({"jsonrpc": "2.0", "id": request["id"], "result": result, "error": null}),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let temporary = tempdir().unwrap();
    let config_path = temporary.path().join("config.json");
    let state_path = temporary.path().join("state.json");
    let read_path = temporary.path().join("read.json");
    let order_path = temporary.path().join("order.json");
    let recovery_path = temporary.path().join("recovery.json");
    let secret_path = temporary.path().join("authority.key");
    let output_path = temporary.path().join("grant.json");
    write_private(&config_path, &configuration);
    write_private(&state_path, &state);
    write_private(&read_path, &read);
    write_private(&order_path, &order);
    write_private(&recovery_path, &recovery);
    fs::write(&secret_path, "3f".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_ecx-successor-trader-state-grant"));
    command
        .arg("--successor-configuration-file")
        .arg(&config_path)
        .arg("--successor-public-state-file")
        .arg(&state_path)
        .arg("--trader-read-proof-file")
        .arg(&read_path)
        .arg("--signed-order-file")
        .arg(&order_path)
        .arg("--matcher-recovery-file")
        .arg(&recovery_path)
        .arg("--authority-secret-key-file")
        .arg(&secret_path)
        .arg("--output-grant-file")
        .arg(&output_path)
        .arg("--elements-rpc-url")
        .arg(format!("http://{address}"))
        .arg("--bond-action-configuration-hash")
        .arg("66".repeat(32))
        .arg("--bond-asset-id")
        .arg("77".repeat(32))
        .arg("--bond-deployment-commitment")
        .arg("88".repeat(32))
        .arg("--successor-transition-program-id")
        .arg("99".repeat(32))
        .arg("--successor-transition-cmr")
        .arg("aa".repeat(32));
    let first = command.output().unwrap();
    assert!(
        first.status.success(),
        "grant issuer failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let grant: SuccessorTraderStateGrantV2 =
        serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(
        grant.exchange_state_root,
        state.state_root(configuration).unwrap()
    );
    assert_eq!(
        grant.trader_order_generation,
        recovery.trader_order_generation
    );
    assert_ne!(grant.signature.0, [0; 64]);

    let second = command.output().unwrap();
    assert!(!second.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successor_grant_service_binds_private_snapshot_and_rejects_substitution() {
    const TOKEN: &str = "private-successor-trader-state-service-token";
    let (configuration, state, read, order, recovery) = fixture();
    let result = node_result(configuration, state);
    let node_app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let result = result.clone();
            async move {
                Json(
                    json!({"jsonrpc": "2.0", "id": request["id"], "result": result, "error": null}),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, node_app).await.unwrap() });

    let node = ElementsRpcClient::new(&format!("http://{address}"), None, None)
        .unwrap()
        .with_v2_identity_pins(V2IdentityPins {
            configuration_hash: [0x66; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
        })
        .unwrap();
    let context = node.successor_consensus_context().await.unwrap();
    let temporary = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let snapshot_path = temporary.path().join(successor_trader_snapshot_filename(
        context.exchange_state_root,
        order.order.trader,
    ));
    write_private(
        &snapshot_path,
        &SuccessorTraderStateSnapshotV2 {
            version: SuccessorTraderStateSnapshotV2::VERSION,
            exchange_state_root: context.exchange_state_root,
            trader: order.order.trader,
            state,
            trader_read: read.clone(),
        },
    );
    let (authority_secret, authority) = identity(63);
    let service = SuccessorTraderStateGrantServiceV2::new(
        configuration,
        temporary.path().to_path_buf(),
        authority_secret,
        TOKEN,
        node.clone(),
    )
    .unwrap();
    let app = successor_trader_state_grant_router(service);
    let request_body = serde_json::to_vec(&SuccessorTraderStateGrantRequestV2 {
        signed_order: order.clone(),
        risk: recovery.risk.clone(),
    })
    .unwrap();

    let unauthorized = app
        .clone()
        .oneshot(
            Request::post("/successor/v2/trader-state-grants")
                .header("content-type", "application/json")
                .body(Body::from(request_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::post("/successor/v2/trader-state-grants")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::from(request_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let issued: SuccessorTraderStateGrantResponseV2 = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        issued.recovery.trader_order_generation,
        recovery.trader_order_generation
    );
    assert_ne!(issued.recovery.salt, [0; 32]);
    assert_eq!(issued.recovery.parent_block_hash, context.parent_block_hash);
    issued
        .trader_state_grant
        .verify_for(
            authority,
            configuration.digest().unwrap(),
            &context,
            &order,
            &issued.recovery,
        )
        .unwrap();

    let mut substituted = SuccessorTraderStateSnapshotV2 {
        version: SuccessorTraderStateSnapshotV2::VERSION,
        exchange_state_root: context.exchange_state_root,
        trader: order.order.trader,
        state,
        trader_read: read,
    };
    substituted.trader_read.leaves[0].order_generation += 1;
    write_private(&snapshot_path, &substituted);
    let rejected = app
        .oneshot(
            Request::post("/successor/v2/trader-state-grants")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::from(request_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successor_order_client_verifies_grant_and_matcher_before_writing_receipt() {
    const TOKEN: &str = "private-successor-order-client-grant-token";
    let (configuration, state, read, expected_order, _) = fixture();
    let node_value = node_result(configuration, state);
    let node_app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let result = node_value.clone();
            async move {
                Json(
                    json!({"jsonrpc": "2.0", "id": request["id"], "result": result, "error": null}),
                )
            }
        }),
    );
    let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_address = node_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(node_listener, node_app).await.unwrap() });
    let node = ElementsRpcClient::new(&format!("http://{node_address}"), None, None)
        .unwrap()
        .with_v2_identity_pins(V2IdentityPins {
            configuration_hash: [0x66; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
        })
        .unwrap();
    let context = node.successor_consensus_context().await.unwrap();

    let temporary = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let snapshot_path = temporary.path().join(successor_trader_snapshot_filename(
        context.exchange_state_root,
        expected_order.order.trader,
    ));
    write_private(
        &snapshot_path,
        &SuccessorTraderStateSnapshotV2 {
            version: SuccessorTraderStateSnapshotV2::VERSION,
            exchange_state_root: context.exchange_state_root,
            trader: expected_order.order.trader,
            state,
            trader_read: read,
        },
    );
    let (authority_secret, authority) = identity(63);
    let grant_service = SuccessorTraderStateGrantServiceV2::new(
        configuration,
        temporary.path().to_path_buf(),
        authority_secret,
        TOKEN,
        node,
    )
    .unwrap();
    let grant_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grant_address = grant_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            grant_listener,
            successor_trader_state_grant_router(grant_service),
        )
        .await
        .unwrap()
    });

    let matcher_config_for_server = matcher_configuration();
    let (matcher_secret, _) = identity(61);
    let matcher_calls = Arc::new(AtomicUsize::new(0));
    let calls = matcher_calls.clone();
    let matcher_context = context.clone();
    let matcher_health_context = context.clone();
    let matcher_health_configuration = configuration;
    let matcher_app = Router::new().route(
        "/successor/v2/orders",
        post(move |Json(request): Json<SuccessorPlaceRequestV2>| {
            let config = matcher_config_for_server.clone();
            let secret = matcher_secret;
            let context = matcher_context.clone();
            let calls = calls.clone();
            async move {
                let call_index = calls.fetch_add(1, Ordering::SeqCst);
                request
                    .trader_state_grant
                    .verify_for(
                        authority,
                        configuration.digest().unwrap(),
                        &context,
                        &request.signed_order,
                        &request.recovery,
                    )
                    .unwrap();
                let mut receipt = SuccessorCentralMatcherReceiptV2::sign(
                    SuccessorMatcherReceiptBodyV2 {
                        version: SuccessorMatcherReceiptBodyV2::VERSION,
                        chain_id: configuration.chain_id,
                        market: configuration.market,
                        matcher_config_hash: config.digest(),
                        matcher_key_epoch: config.key_epoch,
                        global_sequence: config.genesis_sequence + 1,
                        previous_receipt_hash: config.genesis_receipt_hash,
                        command_kind: SuccessorMatcherCommandKindV2::Place,
                        command_hash: successor_matcher_order_command_hash_v2(
                            &request.signed_order,
                        ),
                        observed_sidechain_height: context.sidechain_height,
                        observed_parent_height: context.parent_height,
                        observed_parent_mtp: context.parent_mtp,
                        forced_inbox_cursor: context.forced_inbox_processed_cursor,
                        availability_root: [0x42; 32],
                    },
                    &secret,
                    &config,
                )
                .unwrap();
                if call_index == 1 {
                    receipt.signature.0[0] ^= 1;
                }
                (
                    StatusCode::ACCEPTED,
                    Json(SuccessorPlaceResponseV2 {
                        accepted: true,
                        order_id: hex::encode(request.signed_order.order_id()),
                        admission_receipt: receipt.clone(),
                        fills: vec![],
                        remaining_quantity_atoms: request.signed_order.order.quantity.get(),
                        resting: true,
                        self_trade_prevented: false,
                        pruned_order_ids: vec![],
                        durable_head_sequence: receipt.body.global_sequence,
                        durable_head_receipt_hash: hex::encode(receipt.receipt_hash()),
                    }),
                )
            }
        }),
    )
    .route(
        "/successor/health",
        get(move || {
            let context = matcher_health_context.clone();
            async move {
                Json(json!({
                    "status": "ok",
                    "proof_profile": "incremental-successor",
                    "capital_mode": "normal",
                    "sidechain_height": context.sidechain_height,
                    "parent_height": context.parent_height,
                    "successor_configuration_hash": hex::encode(matcher_health_configuration.digest().unwrap()),
                    "bond_action_configuration_hash": hex::encode(context.bond_action_configuration_hash),
                    "trader_state_authority": hex::encode(authority.0),
                    "durable_head_sequence": matcher_configuration().genesis_sequence,
                    "durable_head_receipt_hash": hex::encode(matcher_configuration().genesis_receipt_hash),
                    "match_sequence": context.matcher_execution_sequence,
                    "proof_consumed_match_sequence": context.matcher_execution_sequence
                }))
            }
        }),
    );
    let matcher_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matcher_address = matcher_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(matcher_listener, matcher_app).await.unwrap() });

    let config_path = temporary.path().join("successor-config.json");
    let matcher_config_path = temporary.path().join("matcher-config.json");
    let trader_key_path = temporary.path().join("trader.key");
    let token_path = temporary.path().join("grant.token");
    let nonce_path = temporary.path().join("order-nonce.state");
    let output_path = temporary.path().join("verified-order.json");
    write_private(&config_path, &configuration);
    write_private(&matcher_config_path, &matcher_configuration());
    fs::write(&trader_key_path, "3e".repeat(32)).unwrap();
    fs::write(&token_path, TOKEN).unwrap();
    fs::write(&nonce_path, ((1u128 << 104) + 3).to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&trader_key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&nonce_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_ecx-successor-order-client"));
    command
        .arg("--successor-configuration-file")
        .arg(&config_path)
        .arg("--successor-matcher-configuration-file")
        .arg(&matcher_config_path)
        .arg("--trader-secret-key-file")
        .arg(&trader_key_path)
        .arg("--grant-service-token-file")
        .arg(&token_path)
        .arg("--grant-service-url")
        .arg(format!("http://{grant_address}"))
        .arg("--matcher-url")
        .arg(format!("http://{matcher_address}"))
        .arg("--trader-state-authority-public-key")
        .arg(hex::encode(authority.0))
        .arg("--side")
        .arg("sell")
        .arg("--price-atoms")
        .arg("100000000")
        .arg("--quantity-atoms")
        .arg("3")
        .arg("--selected-initial-margin-bps")
        .arg("1000")
        .arg("--max-fee-bps")
        .arg("5")
        .arg("--nonce-state-file")
        .arg(&nonce_path)
        .arg("--valid-for-blocks")
        .arg("10")
        .arg("--output-receipt-file")
        .arg(&output_path);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "successor order client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(matcher_calls.load(Ordering::SeqCst), 1);
    let receipt: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(receipt["version"], 1);
    assert_eq!(
        receipt["signed_order"]["order"]["nonce"].to_string(),
        ((1u128 << 104) + 4).to_string()
    );
    assert_eq!(
        receipt["signed_order"]["order"]["client_order_id"],
        serde_json::to_value(((1u128 << 104) + 4).to_be_bytes()).unwrap()
    );
    assert_eq!(
        fs::read_to_string(&nonce_path).unwrap().trim(),
        ((1u128 << 104) + 4).to_string()
    );

    let second = command.output().unwrap();
    assert!(!second.status.success());
    assert_eq!(matcher_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read_to_string(&nonce_path).unwrap().trim(),
        ((1u128 << 104) + 4).to_string()
    );

    fs::remove_file(&output_path).unwrap();
    let tampered = command.output().unwrap();
    assert!(!tampered.status.success());
    assert!(!output_path.exists());
    assert_eq!(matcher_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fs::read_to_string(&nonce_path).unwrap().trim(),
        ((1u128 << 104) + 5).to_string()
    );
}
