use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use secp256k1::{Message as SecpMessage, Secp256k1, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, broadcast};
use tower_http::{
    cors::CorsLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer,
};

use crate::{
    AccountView, CancelOrderRequest, CapitalMode, CapitalSnapshotV2, CentralMatcherSigner,
    ElementsConsensusContextV2, ElementsRpcClient, Engine, EngineCommand, EngineError,
    ExecutionReceiptBatchViewV2, HealthView, Journal, MARKET, MarketEvent, MatcherReceiptView,
    OrderBookSnapshot, PublicMarketEvent, PublicOrderBookSnapshot, PublicTrade,
    SequencedCancelOrderOutcome, SequencedSubmitOrderOutcome, SequencedSubmitOrderOutcomeV2,
    SubmitOrderRequest, SubmitOrderRequestV2, command_commitment,
    command_commitment_with_context_v2, engine::protocol_order_risk_commitment,
};

const ACCOUNT_VIEW_DOMAIN: &[u8] = b"ECX/ACCOUNT-VIEW/V2";
const ACCOUNT_VIEW_WINDOW_MS: u64 = 30_000;
pub const ACCOUNT_VIEW_NONCE_BYTES: usize = 16;
const MAX_ACCOUNT_VIEW_REPLAY_ENTRIES: usize = 4_096;
const MAX_HTTP_REQUEST_BODY_BYTES: usize = 16 * 1024;
const HTTP_HANDLER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WS_MESSAGE_BYTES: usize = 4 * 1024;
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

type AccountViewReplayKey = ([u8; 32], [u8; ACCOUNT_VIEW_NONCE_BYTES]);

#[derive(Clone)]
pub struct AppState {
    engine: Arc<RwLock<Engine>>,
    journal: Arc<Mutex<Journal>>,
    events: broadcast::Sender<MarketEvent>,
    signer: Arc<CentralMatcherSigner>,
    mutations: Arc<Mutex<()>>,
    demo_mode: bool,
    node_rpc: Option<ElementsRpcClient>,
    last_node_context: Arc<Mutex<Option<ElementsConsensusContextV2>>>,
    account_view_replays: Arc<Mutex<HashMap<AccountViewReplayKey, u64>>>,
    compact_journal_bytes: u64,
    retained_idempotency_receipts: u64,
    zero_insurance_mode: bool,
    v2_capital_controls: bool,
    proof_producer_token_sha256: Option<[u8; 32]>,
}

impl AppState {
    pub fn new(engine: Engine, journal: Journal, signer: CentralMatcherSigner) -> Result<Self> {
        if journal.matcher_config() != signer.config() || journal.chain_id() != signer.chain_id() {
            anyhow::bail!("matcher signer and durable journal configurations differ");
        }
        let demo_mode = engine.demo_mode();
        let (events, _) = broadcast::channel(1_024);
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            journal: Arc::new(Mutex::new(journal)),
            events,
            signer: Arc::new(signer),
            mutations: Arc::new(Mutex::new(())),
            demo_mode,
            node_rpc: None,
            last_node_context: Arc::new(Mutex::new(None)),
            account_view_replays: Arc::new(Mutex::new(HashMap::new())),
            compact_journal_bytes: crate::journal::DEFAULT_COMPACT_JOURNAL_BYTES,
            retained_idempotency_receipts: crate::journal::DEFAULT_IDEMPOTENCY_RECEIPTS,
            zero_insurance_mode: false,
            v2_capital_controls: false,
            proof_producer_token_sha256: None,
        })
    }

    pub fn with_compaction(
        mut self,
        compact_journal_bytes: u64,
        retained_idempotency_receipts: u64,
    ) -> Result<Self> {
        if compact_journal_bytes == 0
            || retained_idempotency_receipts == 0
            || retained_idempotency_receipts > crate::journal::MAX_RETAINED_IDEMPOTENCY_RECEIPTS
        {
            anyhow::bail!("matcher compaction limits must be nonzero");
        }
        self.compact_journal_bytes = compact_journal_bytes;
        self.retained_idempotency_receipts = retained_idempotency_receipts;
        Ok(self)
    }

    /// Fail-closed operational policy for deployments with no insurance fund.
    /// This is deliberately outside EngineConfig so it neither changes the
    /// transition statement nor makes historical journal replay policy-dependent.
    pub async fn with_zero_insurance_mode(mut self, enabled: bool) -> Result<Self> {
        if enabled && self.engine.read().await.has_non_reduce_only_open_orders() {
            anyhow::bail!(
                "zero-insurance mode cannot start while non-reduce-only orders are resting; cancel them first"
            );
        }
        self.zero_insurance_mode = enabled;
        Ok(self)
    }

    /// Enables v2 capital posture reporting and the v2 routes after the
    /// process has installed all mandatory frozen singleton identity pins.
    /// `/v1/orders` retains its v1 behavior.
    pub async fn with_v2_capital_controls(mut self, enabled: bool) -> Result<Self> {
        if enabled && self.engine.read().await.has_open_orders() {
            anyhow::bail!(
                "v2 capital controls cannot start while legacy orders are resting; cancel every order first"
            );
        }
        self.v2_capital_controls = enabled;
        Ok(self)
    }

    pub fn with_proof_producer_token(mut self, token: &str) -> Result<Self> {
        if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_whitespace) {
            anyhow::bail!(
                "proof-producer bearer token must contain 32..=4096 non-whitespace characters"
            );
        }
        self.proof_producer_token_sha256 = Some(Sha256::digest(token.as_bytes()).into());
        Ok(self)
    }

    fn capital_mode(
        &self,
        context: Option<&ElementsConsensusContextV2>,
        require_v2: bool,
    ) -> (CapitalMode, bool) {
        capital_admission_mode(
            require_v2,
            self.zero_insurance_mode,
            context.and_then(|context| context.capital_snapshot.as_ref()),
        )
    }

    pub async fn new_with_node(
        engine: Engine,
        mut journal: Journal,
        signer: CentralMatcherSigner,
        node_rpc: ElementsRpcClient,
        initial_context: ElementsConsensusContextV2,
    ) -> Result<Self> {
        initial_context
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid initial Elements context: {error}"))?;
        if engine.chain_height() != initial_context.sidechain_height {
            anyhow::bail!("matcher engine and Elements node heights differ at startup");
        }
        let node_matcher_context = initial_context.matcher_context()?;
        if signer.default_context() != node_matcher_context {
            anyhow::bail!("matcher signer and initial Elements consensus contexts differ");
        }
        if let Some(durable) = journal.last_elements_context() {
            let verified = node_rpc
                .consensus_context_after(durable)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "initial Elements context does not extend the active durable matcher history: {error}"
                    )
                })?;
            if verified != initial_context {
                anyhow::bail!(
                    "Elements consensus context changed during matcher startup; restart against one stable tip"
                );
            }
        } else if journal.head_sequence() != journal.matcher_config().genesis_sequence {
            anyhow::bail!(
                "existing production journal has no signed full Elements context; explicit migration/reconciliation is required"
            );
        }
        journal
            .validate_authenticated_execution_cursor(&initial_context)
            .context("reconciling proof-verified node execution cursor at matcher startup")?;
        let mut state = Self::new(engine, journal, signer)?;
        state.node_rpc = Some(node_rpc);
        state.last_node_context = Arc::new(Mutex::new(Some(initial_context)));
        Ok(state)
    }

    async fn refresh_node_context(&self) -> Result<Option<ElementsConsensusContextV2>, ApiError> {
        let Some(client) = &self.node_rpc else {
            return Ok(None);
        };
        let mut previous = self.last_node_context.lock().await;
        let current = match previous.as_ref() {
            Some(old) => client.consensus_context_after(old).await,
            None => client.consensus_context().await,
        }
        .map_err(|error| {
            ApiError::Unavailable(format!(
                "Elements consensus context regressed, reorged, or became inconsistent; operator reconciliation required: {error}"
            ))
        })?;
        current
            .matcher_context()
            .map_err(|error| ApiError::Unavailable(error.to_string()))?;
        *previous = Some(current.clone());
        Ok(Some(current))
    }

    async fn consume_account_view_credential(
        &self,
        credential: VerifiedAccountViewCredential,
        current_ms: u64,
    ) -> Result<(), ApiError> {
        let mut replay_cache = self.account_view_replays.lock().await;
        replay_cache.retain(|_, valid_until_ms| *valid_until_ms >= current_ms);
        if replay_cache.contains_key(&credential.replay_key) {
            return Err(ApiError::Unauthorized(
                "account-view credential was already used".into(),
            ));
        }
        if replay_cache.len() >= MAX_ACCOUNT_VIEW_REPLAY_ENTRIES {
            return Err(ApiError::TooManyRequests(
                "account-view replay cache is at its bounded capacity; retry after prior credentials expire"
                    .into(),
            ));
        }
        replay_cache.insert(credential.replay_key, credential.valid_until_ms);
        Ok(())
    }
}

fn capital_admission_mode(
    require_v2: bool,
    zero_insurance_mode: bool,
    capital: Option<&CapitalSnapshotV2>,
) -> (CapitalMode, bool) {
    if require_v2 {
        let authenticated = capital.map_or((CapitalMode::Recovery, false), |capital| {
            (capital.admission_mode(), true)
        });
        if zero_insurance_mode && authenticated.0 == CapitalMode::Normal {
            return (CapitalMode::ReduceOnly, authenticated.1);
        }
        return authenticated;
    }
    if zero_insurance_mode {
        (CapitalMode::ReduceOnly, false)
    } else {
        (CapitalMode::Normal, false)
    }
}

pub fn router(state: AppState) -> Router {
    let demo_mode = state.demo_mode;
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/v1/markets/{market}/orderbook", get(orderbook))
        .route("/v1/markets/{market}/trades", get(trades))
        .route("/v1/markets/{market}/ws", get(market_ws))
        .route("/v1/orders", post(submit_order))
        .route("/v2/orders", post(submit_order_v2))
        .route("/v2/capital", get(capital_snapshot_v2))
        .route("/v2/proof/execution-receipts", get(execution_receipts_v2))
        .route("/v1/orders/{order_id}/cancel", post(cancel_order))
        .route("/v1/receipts/{sequence}", get(receipt))
        .route("/v1/accounts/{trader}", get(account))
        .layer(RequestBodyLimitLayer::new(MAX_HTTP_REQUEST_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            HTTP_HANDLER_TIMEOUT,
        ))
        // The default tower-http span records the complete URI. That would
        // persist trader keys from `/accounts/{trader}` and order IDs from
        // cancellation paths in general request logs. Keep only the method;
        // explicit application events carry non-sensitive operational fields.
        .layer(TraceLayer::new_for_http().make_span_with(private_request_span))
        .with_state(state);
    if demo_mode {
        // Demo UI commonly runs on a separate localhost port. Production stays
        // same-origin unless an operator deliberately adds a narrow CORS policy.
        router = router.layer(CorsLayer::permissive());
    }
    router
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReceiptQueryV2 {
    previous_sequence: u64,
    #[serde(default = "default_execution_receipt_limit")]
    limit: usize,
}

fn default_execution_receipt_limit() -> usize {
    4_096
}

async fn execution_receipts_v2(
    State(state): State<AppState>,
    Query(query): Query<ExecutionReceiptQueryV2>,
    headers: HeaderMap,
) -> Result<Json<ExecutionReceiptBatchViewV2>, ApiError> {
    require_v2_controls(state.v2_capital_controls)?;
    authenticate_proof_producer(&state, &headers)?;
    let journal = state.journal.lock().await;
    let execution_receipts = journal
        .execution_receipts_after(query.previous_sequence, query.limit)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let taker_admission_receipts = journal
        .admission_receipts_for_executions(&execution_receipts)
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let next_sequence = execution_receipts
        .last()
        .map_or(query.previous_sequence, |receipt| {
            receipt.body.match_sequence
        });
    Ok(Json(ExecutionReceiptBatchViewV2 {
        previous_sequence: query.previous_sequence,
        next_sequence,
        durable_head_sequence: journal.head_execution_sequence(),
        durable_history_hash: hex::encode(journal.head_execution_history_hash()),
        execution_receipts,
        taker_admission_receipts,
    }))
}

fn authenticate_proof_producer(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected = state.proof_producer_token_sha256.ok_or_else(|| {
        ApiError::Unavailable("proof-producer receipt export is not configured".into())
    })?;
    let authorization = header_text(headers, "authorization")?;
    let token = authorization.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::Unauthorized("invalid proof-producer authorization scheme".into())
    })?;
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let different = expected
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (left, right)| {
            difference | (*left ^ right)
        });
    if different != 0 {
        return Err(ApiError::Unauthorized(
            "invalid proof-producer bearer token".into(),
        ));
    }
    Ok(())
}

fn private_request_span(request: &Request<Body>) -> tracing::Span {
    tracing::info_span!("matcher_http_request", method = %request.method())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepthQuery {
    #[serde(default = "default_depth")]
    depth: usize,
}

fn default_depth() -> usize {
    20
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthView>, ApiError> {
    // Health is also readiness in node-backed mode. Never report a healthy
    // signer while its authenticated active-chain view is unavailable or has
    // reorged relative to the last view this process accepted.
    let context = state.refresh_node_context().await?;
    let (capital_mode, capital_authenticated) =
        state.capital_mode(context.as_ref(), state.v2_capital_controls);
    let (matcher_sequence, matcher_receipt_hash) = {
        let journal = state.journal.lock().await;
        (
            journal.head_sequence(),
            hex::encode(journal.head_receipt_hash()),
        )
    };
    let engine = state.engine.read().await;
    Ok(Json(HealthView {
        status: "ok".into(),
        market: MARKET.into(),
        mode: if state.demo_mode { "demo" } else { "signed" }.into(),
        chain_height: engine.chain_height(),
        sequence: engine.sequence(),
        privacy: "public prices, timing, roots, and capital aggregates are visible; unauthenticated market views omit quantities and trader identities; the central matcher sees signed orders, balances, and positions".into(),
        matcher_mode: "central_single_signer".into(),
        matcher_signer: hex::encode(state.signer.config().signer.0),
        chain_id: hex::encode(state.signer.chain_id()),
        matcher_sequence,
        matcher_receipt_hash,
        capital_controls_v2: state.v2_capital_controls,
        capital_mode: (state.v2_capital_controls || state.zero_insurance_mode)
            .then_some(capital_mode),
        capital_authenticated,
    }))
}

async fn capital_snapshot_v2(
    State(state): State<AppState>,
) -> Result<Json<CapitalSnapshotV2>, ApiError> {
    require_v2_controls(state.v2_capital_controls)?;
    let context = state.refresh_node_context().await?;
    let snapshot = context
        .and_then(|context| context.capital_snapshot)
        .ok_or_else(|| {
            ApiError::Unavailable(
                "authenticated v2 capital state is unavailable from the Elements node".into(),
            )
        })?;
    Ok(Json(snapshot))
}

async fn receipt(
    Path(sequence): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<MatcherReceiptView>, ApiError> {
    let receipt = state
        .journal
        .lock()
        .await
        .receipt_for_sequence(sequence)
        .ok_or_else(|| {
            ApiError::NotFound("matcher receipt is outside the retained window".into())
        })?;
    Ok(Json(MatcherReceiptView {
        receipt_hash: hex::encode(receipt.receipt_hash()),
        receipt,
    }))
}

async fn orderbook(
    Path(market): Path<String>,
    Query(query): Query<DepthQuery>,
    State(state): State<AppState>,
) -> Result<Json<PublicOrderBookSnapshot>, ApiError> {
    ensure_market(&market)?;
    Ok(Json(PublicOrderBookSnapshot::from(
        state
            .engine
            .read()
            .await
            .orderbook(query.depth.clamp(1, 100)),
    )))
}

async fn trades(
    Path(market): Path<String>,
    Query(query): Query<LimitQuery>,
    State(state): State<AppState>,
) -> Result<Json<Vec<PublicTrade>>, ApiError> {
    ensure_market(&market)?;
    Ok(Json(
        state
            .engine
            .read()
            .await
            .recent_trades(query.limit.clamp(1, 500))
            .into_iter()
            .map(PublicTrade::from)
            .collect(),
    ))
}

async fn submit_order(
    State(state): State<AppState>,
    Json(request): Json<SubmitOrderRequest>,
) -> Result<(StatusCode, Json<SequencedSubmitOrderOutcome>), ApiError> {
    if state.v2_capital_controls {
        return Err(ApiError::Unavailable(
            "v1 placements are disabled for a V2 singleton because they lack the proof-required signed margin commitment; use /v2/orders"
                .into(),
        ));
    }
    let received_at_ms = now_ms()?;
    let command = EngineCommand::Submit {
        request: request.clone(),
        received_at_ms,
    };
    submit_order_inner(state, request, None, command, received_at_ms).await
}

async fn submit_order_v2(
    State(state): State<AppState>,
    Json(request): Json<SubmitOrderRequestV2>,
) -> Result<(StatusCode, Json<SequencedSubmitOrderOutcomeV2>), ApiError> {
    require_v2_controls(state.v2_capital_controls)?;
    protocol_order_risk_commitment(&request)?;
    let received_at_ms = now_ms()?;
    let command = EngineCommand::SubmitV2 {
        request: request.clone(),
        received_at_ms,
    };
    submit_order_v2_inner(
        state,
        request.order.clone(),
        request,
        command,
        received_at_ms,
    )
    .await
}

async fn submit_order_v2_inner(
    state: AppState,
    request: SubmitOrderRequest,
    request_v2: SubmitOrderRequestV2,
    command: EngineCommand,
    received_at_ms: u64,
) -> Result<(StatusCode, Json<SequencedSubmitOrderOutcomeV2>), ApiError> {
    let (status, outcome, execution_receipts) =
        submit_order_mutation(state, request, Some(request_v2), command, received_at_ms).await?;
    Ok((
        status,
        Json(SequencedSubmitOrderOutcomeV2 {
            outcome: outcome.outcome,
            matcher_receipt: outcome.matcher_receipt,
            execution_receipts,
        }),
    ))
}

fn require_v2_controls(enabled: bool) -> Result<(), ApiError> {
    if enabled {
        Ok(())
    } else {
        Err(ApiError::Unavailable(
            "v2 routes are disabled until all frozen singleton identity pins are configured".into(),
        ))
    }
}

async fn submit_order_inner(
    state: AppState,
    request: SubmitOrderRequest,
    request_v2: Option<SubmitOrderRequestV2>,
    command: EngineCommand,
    received_at_ms: u64,
) -> Result<(StatusCode, Json<SequencedSubmitOrderOutcome>), ApiError> {
    let (status, outcome, _) =
        submit_order_mutation(state, request, request_v2, command, received_at_ms).await?;
    Ok((status, Json(outcome)))
}

async fn submit_order_mutation(
    state: AppState,
    request: SubmitOrderRequest,
    request_v2: Option<SubmitOrderRequestV2>,
    command: EngineCommand,
    received_at_ms: u64,
) -> Result<
    (
        StatusCode,
        SequencedSubmitOrderOutcome,
        Vec<ecx_protocol_core::MatcherExecutionReceiptV2>,
    ),
    ApiError,
> {
    let require_v2 = request_v2.is_some();
    let serialization_guard = state.mutations.lock().await;
    let node_context = state.refresh_node_context().await?;
    if let Some(v2) = request_v2.as_ref() {
        let authenticated_configuration = node_context
            .as_ref()
            .and_then(|context| context.capital_snapshot.as_ref())
            .map(|capital| hex::encode(capital.configuration_hash))
            .ok_or_else(|| {
                ApiError::Unavailable(
                    "authenticated v2 singleton configuration is unavailable".into(),
                )
            })?;
        if v2.configuration_hash != authenticated_configuration {
            return Err(ApiError::BadRequest(
                "order risk commitment targets a different v2 singleton configuration".into(),
            ));
        }
    }
    let (capital_mode, _) = state.capital_mode(node_context.as_ref(), require_v2);
    if !capital_mode.permits(request.reduce_only) {
        let permission = match capital_mode {
            CapitalMode::Recovery => {
                "rejects all trading; only recapitalization actions are accepted"
            }
            CapitalMode::ReduceOnly => {
                "rejects new exposure; only strictly reduce-only orders are accepted"
            }
            CapitalMode::Normal => "rejected the order",
        };
        return Err(ApiError::BadRequest(format!(
            "v2 capital mode {capital_mode:?} {permission}"
        )));
    }
    let (next_sequence, previous_receipt_hash) = {
        let mut journal = state.journal.lock().await;
        if let Some(context) = node_context.as_ref() {
            journal
                .validate_authenticated_execution_cursor(context)
                .map_err(|error| ApiError::Unavailable(error.to_string()))?;
        }
        (journal.next_sequence()?, journal.head_receipt_hash())
    };
    let (mutation, receipt, execution_receipts, is_duplicate) = {
        let mut guard = state.engine.write().await;
        if let Some(context) = node_context.as_ref() {
            guard.advance_chain_height(context.sidechain_height)?;
        }
        if require_v2
            && capital_mode != CapitalMode::Normal
            && guard.has_non_reduce_only_open_orders()
        {
            return Err(ApiError::Unavailable(
                "authenticated v2 state is not normal while non-reduce-only resting orders remain; cancel them before matching resumes"
                    .into(),
            ));
        }
        let mut staged = guard.clone();
        let mutation = match request_v2 {
            Some(request) => staged.submit_sequenced_v2(request, received_at_ms, next_sequence)?,
            None => staged.submit_sequenced(request, received_at_ms, next_sequence)?,
        };
        let duplicate = mutation.outcome.duplicate;
        let commitment = match node_context.as_ref() {
            Some(context) => {
                command_commitment_with_context_v2(&command, state.signer.chain_id(), context)
            }
            None => command_commitment(&command, state.signer.chain_id()),
        }
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let (receipt, execution_receipts) = if duplicate {
            let journal = state.journal.lock().await;
            let receipt = journal
                .receipt_for_command(&commitment.command_hash)
                .ok_or_else(|| {
                    ApiError::Internal(
                        "idempotent order is missing its durable matcher receipt".into(),
                    )
                })?;
            let executions = journal.execution_receipts_for_command(&commitment.command_hash);
            (receipt, executions)
        } else {
            let receipt = match node_context.as_ref() {
                Some(context) => state.signer.issue_at(
                    &commitment,
                    next_sequence,
                    previous_receipt_hash,
                    context.matcher_context()?,
                )?,
                None => state
                    .signer
                    .issue(&commitment, next_sequence, previous_receipt_hash)?,
            };
            let execution_receipts = if require_v2 {
                let context = node_context.as_ref().ok_or_else(|| {
                    ApiError::Unavailable(
                        "V2 execution receipts require authenticated Elements context".into(),
                    )
                })?;
                let previous_execution_sequence =
                    state.journal.lock().await.head_execution_sequence();
                mutation
                    .executions_v2
                    .iter()
                    .enumerate()
                    .map(|(index, execution)| {
                        let offset = u64::try_from(index)
                            .map_err(|_| anyhow::anyhow!("execution count overflow"))?;
                        let sequence = previous_execution_sequence
                            .checked_add(offset)
                            .and_then(|value| value.checked_add(1))
                            .ok_or_else(|| anyhow::anyhow!("execution sequence overflow"))?;
                        state
                            .signer
                            .issue_execution_v2(execution, sequence, &receipt, context)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            let mut journal = state.journal.lock().await;
            match (require_v2, node_context.as_ref()) {
                (true, Some(context)) => journal.append_with_execution_receipts(
                    &command,
                    &receipt,
                    context,
                    &mutation.executions_v2,
                    &execution_receipts,
                )?,
                (_, Some(context)) => journal.append_with_context(&command, &receipt, context)?,
                (_, None) => journal.append(&command, &receipt)?,
            }
            *guard = staged;
            if journal.should_compact(state.compact_journal_bytes)? {
                journal.compact(
                    &mut guard,
                    &state.signer,
                    state.retained_idempotency_receipts,
                )?;
            }
            (receipt, execution_receipts)
        };
        (mutation, receipt, execution_receipts, duplicate)
    };
    drop(serialization_guard);
    for event in mutation.events {
        let _ = state.events.send(event);
    }
    Ok((
        if is_duplicate {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        SequencedSubmitOrderOutcome {
            outcome: mutation.outcome,
            matcher_receipt: receipt,
        },
        execution_receipts,
    ))
}

async fn cancel_order(
    Path(order_id): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<CancelOrderRequest>,
) -> Result<Json<SequencedCancelOrderOutcome>, ApiError> {
    let received_at_ms = now_ms()?;
    let command = EngineCommand::Cancel {
        order_id: order_id.clone(),
        request: request.clone(),
        received_at_ms,
    };
    let serialization_guard = state.mutations.lock().await;
    let node_context = state.refresh_node_context().await?;
    let (next_sequence, previous_receipt_hash) = {
        let journal = state.journal.lock().await;
        (journal.next_sequence()?, journal.head_receipt_hash())
    };
    let (mutation, receipt) = {
        let mut guard = state.engine.write().await;
        if let Some(context) = node_context.as_ref() {
            guard.advance_chain_height(context.sidechain_height)?;
        }
        let mut staged = guard.clone();
        let mutation =
            staged.cancel_sequenced(&order_id, request, received_at_ms, next_sequence)?;
        let commitment = match node_context.as_ref() {
            Some(context) => {
                command_commitment_with_context_v2(&command, state.signer.chain_id(), context)
            }
            None => command_commitment(&command, state.signer.chain_id()),
        }
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let receipt = if mutation.outcome.duplicate {
            state
                .journal
                .lock()
                .await
                .receipt_for_command(&commitment.command_hash)
                .ok_or_else(|| {
                    ApiError::Internal(
                        "idempotent cancel is missing its durable matcher receipt".into(),
                    )
                })?
        } else {
            let receipt = match node_context.as_ref() {
                Some(context) => state.signer.issue_at(
                    &commitment,
                    next_sequence,
                    previous_receipt_hash,
                    context.matcher_context()?,
                )?,
                None => state
                    .signer
                    .issue(&commitment, next_sequence, previous_receipt_hash)?,
            };
            let mut journal = state.journal.lock().await;
            match node_context.as_ref() {
                Some(context) => journal.append_with_context(&command, &receipt, context)?,
                None => journal.append(&command, &receipt)?,
            }
            *guard = staged;
            if journal.should_compact(state.compact_journal_bytes)? {
                journal.compact(
                    &mut guard,
                    &state.signer,
                    state.retained_idempotency_receipts,
                )?;
            }
            receipt
        };
        (mutation, receipt)
    };
    drop(serialization_guard);
    for event in mutation.events {
        let _ = state.events.send(event);
    }
    Ok(Json(SequencedCancelOrderOutcome {
        outcome: mutation.outcome,
        matcher_receipt: receipt,
    }))
}

async fn account(
    Path(trader): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccountView>, ApiError> {
    if !(state.demo_mode && trader.starts_with("demo-")) {
        let current_ms = now_ms()?;
        let credential = authenticate_account_view(&trader, &headers, current_ms)?;
        state
            .consume_account_view_credential(credential, current_ms)
            .await?;
    }
    Ok(Json(state.engine.read().await.account(&trader)))
}

async fn market_ws(
    Path(market): Path<String>,
    State(state): State<AppState>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    ensure_market(&market)?;
    let receiver = state.events.subscribe();
    let snapshot = state.engine.read().await.orderbook(40);
    Ok(websocket
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| stream_market(socket, receiver, snapshot))
        .into_response())
}

async fn stream_market(
    socket: WebSocket,
    mut receiver: broadcast::Receiver<MarketEvent>,
    snapshot: OrderBookSnapshot,
) {
    let (mut sender, mut incoming) = socket.split();
    let Ok(initial) = serde_json::to_string(&PublicMarketEvent::Book(snapshot.into())) else {
        return;
    };
    if !matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, sender.send(Message::Text(initial.into()))).await,
        Ok(Ok(()))
    ) {
        return;
    }

    loop {
        tokio::select! {
            message = receiver.recv() => {
                match message {
                    Ok(event) => {
                        let Ok(json) = serde_json::to_string(&PublicMarketEvent::from(event)) else { continue };
                        if !matches!(
                            tokio::time::timeout(
                                WS_SEND_TIMEOUT,
                                sender.send(Message::Text(json.into())),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // A REST snapshot is the explicit recovery path after lag.
                        let marker = r#"{"type":"resync_required","data":{}}"#;
                        if !matches!(
                            tokio::time::timeout(
                                WS_SEND_TIMEOUT,
                                sender.send(Message::Text(marker.into())),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            message = incoming.next() => {
                match message {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

struct VerifiedAccountViewCredential {
    replay_key: AccountViewReplayKey,
    valid_until_ms: u64,
}

fn authenticate_account_view(
    trader: &str,
    headers: &HeaderMap,
    current_ms: u64,
) -> Result<VerifiedAccountViewCredential, ApiError> {
    let timestamp = header_text(headers, "x-ecx-view-timestamp")?
        .parse::<u64>()
        .map_err(|_| ApiError::Unauthorized("invalid account-view timestamp".into()))?;
    if current_ms.abs_diff(timestamp) > ACCOUNT_VIEW_WINDOW_MS {
        return Err(ApiError::Unauthorized(
            "account-view signature is outside the 30-second window".into(),
        ));
    }
    let signature_hex = header_text(headers, "x-ecx-view-signature")?;
    let nonce_hex = header_text(headers, "x-ecx-view-nonce")?;
    let key_bytes = decode_canonical_hex::<32>(trader, "trader key")?;
    let signature_bytes = decode_canonical_hex::<64>(signature_hex, "account-view signature")?;
    let nonce = decode_canonical_hex::<ACCOUNT_VIEW_NONCE_BYTES>(nonce_hex, "account-view nonce")?;
    let key = XOnlyPublicKey::from_slice(&key_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid trader key".into()))?;
    let signature = schnorr::Signature::from_slice(&signature_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid account-view signature".into()))?;
    let digest = account_view_signing_digest(trader, timestamp, nonce);
    let message = SecpMessage::from_digest_slice(&digest)
        .map_err(|_| ApiError::Unauthorized("invalid account-view message".into()))?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &key)
        .map_err(|_| ApiError::Unauthorized("invalid account-view signature".into()))?;
    Ok(VerifiedAccountViewCredential {
        replay_key: (key.serialize(), nonce),
        valid_until_ms: timestamp.saturating_add(ACCOUNT_VIEW_WINDOW_MS),
    })
}

pub fn account_view_signing_digest(
    trader: &str,
    timestamp: u64,
    nonce: [u8; ACCOUNT_VIEW_NONCE_BYTES],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(ACCOUNT_VIEW_DOMAIN.len() + trader.len() + 28);
    payload.extend_from_slice(ACCOUNT_VIEW_DOMAIN);
    payload.extend_from_slice(&(trader.len() as u32).to_be_bytes());
    payload.extend_from_slice(trader.as_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&nonce);
    ecx_protocol_core::tagged_hash("ECX/account-view/v2", &payload)
}

fn decode_canonical_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], ApiError> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::Unauthorized(format!("invalid {name}")));
    }
    let decoded =
        hex::decode(value).map_err(|_| ApiError::Unauthorized(format!("invalid {name}")))?;
    decoded
        .try_into()
        .map_err(|_| ApiError::Unauthorized(format!("invalid {name}")))
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized(format!("missing or invalid {name} header")))?;
    if values.next().is_some() {
        return Err(ApiError::Unauthorized(format!(
            "multiple {name} headers are not allowed"
        )));
    }
    Ok(value)
}

fn ensure_market(market: &str) -> Result<(), ApiError> {
    if market == MARKET {
        Ok(())
    } else {
        Err(ApiError::Engine(EngineError::WrongMarket))
    }
}

fn now_ms() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| ApiError::Internal("system clock is outside u64 milliseconds".into()))
}

#[derive(Debug)]
pub enum ApiError {
    Engine(EngineError),
    Unauthorized(String),
    TooManyRequests(String),
    BadRequest(String),
    Unavailable(String),
    Internal(String),
    NotFound(String),
}

impl From<EngineError> for ApiError {
    fn from(value: EngineError) -> Self {
        Self::Engine(value)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, "unauthorized", message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message),
            Self::TooManyRequests(message) => {
                (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", message)
            }
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Unavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "consensus_context_unavailable",
                message,
            ),
            Self::Internal(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
            }
            Self::Engine(error) => {
                let status = match error {
                    EngineError::AdmissionQuota => StatusCode::TOO_MANY_REQUESTS,
                    EngineError::OrderNotFound => StatusCode::NOT_FOUND,
                    EngineError::InvalidSignature
                    | EngineError::InvalidRiskCommitment
                    | EngineError::DemoDisabled => StatusCode::UNAUTHORIZED,
                    EngineError::WrongMarket
                    | EngineError::ZeroValue
                    | EngineError::RiskBound
                    | EngineError::InvalidInitialMargin
                    | EngineError::InvalidClientOrderId
                    | EngineError::InvalidClientCancelId
                    | EngineError::NotYetLive(_)
                    | EngineError::Expired(_) => StatusCode::BAD_REQUEST,
                    EngineError::ArithmeticOverflow | EngineError::InvalidJournal(_) => {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                    _ => StatusCode::CONFLICT,
                };
                (status, "order_rejected", error.to_string())
            }
        };
        (status, Json(ErrorBody { code, message })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{CentralMatcherConfigV1, XOnlyKey};
    use secp256k1::SecretKey;
    use tempfile::tempdir;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn deterministic_admission_exhaustion_is_http_429() {
        let response = ApiError::Engine(EngineError::AdmissionQuota).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn v2_routes_remain_disabled_until_identity_pins_are_active() {
        assert!(require_v2_controls(true).is_ok());
        let response = require_v2_controls(false).unwrap_err().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn proof_execution_receipts_require_the_exact_private_bearer_token() {
        let directory = tempdir().unwrap();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let chain_id = [9; 32];
        let matcher_config = CentralMatcherConfigV1 {
            version: 1,
            key_epoch: 0,
            signer: XOnlyKey(crate::matcher_public_key(&secret).serialize()),
            genesis_sequence: 0,
            genesis_receipt_hash: [8; 32],
            forced_inclusion_blocks: 6,
        };
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
        let engine_config = crate::EngineConfig {
            demo_mode: false,
            chain_height: 100,
            ..crate::EngineConfig::default()
        };
        let (journal, engine) = Journal::open(
            directory.path().join("matcher.jsonl"),
            engine_config,
            matcher_config,
            chain_id,
        )
        .unwrap();
        let token = "proof-producer-token-that-is-long-enough";
        let state = AppState::new(engine, journal, signer)
            .unwrap()
            .with_v2_capital_controls(true)
            .await
            .unwrap()
            .with_proof_producer_token(token)
            .unwrap();
        let app = router(state);
        let uri = "/v2/proof/execution-receipts?previous_sequence=0&limit=10";

        let missing = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(
                        "authorization",
                        "Bearer proof-producer-token-that-is-not-correct",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(accepted.into_body(), 64 * 1024)
            .await
            .unwrap();
        let payload: ExecutionReceiptBatchViewV2 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.previous_sequence, 0);
        assert_eq!(payload.next_sequence, 0);
        assert_eq!(payload.durable_head_sequence, 0);
        assert!(payload.execution_receipts.is_empty());
        assert!(payload.taker_admission_receipts.is_empty());
    }

    #[test]
    fn missing_v2_capital_fails_closed_and_zero_insurance_cannot_be_overridden() {
        assert_eq!(
            capital_admission_mode(true, false, None),
            (CapitalMode::Recovery, false)
        );
        let capital = CapitalSnapshotV2 {
            version: CapitalSnapshotV2::VERSION,
            exchange_state_root: [7; 32],
            configuration_hash: [8; 32],
            bond_asset_id: [9; 32],
            bond_deployment_commitment: [10; 32],
            transition_program_id: [11; 32],
            transition_cmr: [12; 32],
            covenant_state_hash: [14; 32],
            bond_state_root: [15; 32],
            funding_state_root: [16; 32],
            insurance_reserve_quote_units: 125,
            outstanding_bond_units: 100,
            nav_quote_units_per_bond: 125_000_000,
            deficit_quote_units: 100,
            target_reserve_quote_units: 125,
            coverage_bps: 12_500,
            mode: CapitalMode::Normal,
            minimum_authenticated_price: 1,
            maximum_authenticated_price: 2,
            funding_epoch: 1,
            funding_rate_ppm: 0,
            redemption_queue_root: [13; 32],
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_bond_units: 0,
            oracle: crate::OracleSnapshotV2 {
                certificate_hash: [17; 32],
                valid_through_parent_mtp: 1_000,
                mode: crate::OracleModeV2::Normal,
            },
            encrypted_availability_root: [18; 32],
            bond_inbox: crate::BondInboxSnapshotV2 {
                head_root: [19; 32],
                entry_count: 0,
                processed_root: [20; 32],
                processed_cursor: 0,
                outcome_root: [21; 32],
                outcome_count: 0,
                node_verified_source_head_root: [19; 32],
                node_verified_source_entry_count: 0,
            },
            matcher_execution: crate::MatcherExecutionSnapshotV2 {
                receipt_batch_root: [22; 32],
                previous_sequence: 0,
                sequence: 0,
            },
            last_transition_sidechain_height: 1,
            legacy_fee_pool_quote_units: 0,
        };
        assert_eq!(
            capital_admission_mode(true, false, Some(&capital)),
            (CapitalMode::Normal, true)
        );
        assert_eq!(
            capital_admission_mode(true, true, Some(&capital)),
            (CapitalMode::ReduceOnly, true)
        );
        assert!(!CapitalMode::Recovery.permits(false));
        assert!(!CapitalMode::Recovery.permits(true));
        assert!(!CapitalMode::ReduceOnly.permits(false));
        assert!(CapitalMode::ReduceOnly.permits(true));
    }
}
