//! Private HTTP boundary for the lifetime-safe incremental successor matcher.
//!
//! This router is intentionally disjoint from `/v1` and the finite `/v2`
//! matcher. Every mutation refreshes the node-authenticated
//! `incremental-successor` projection, checks the frozen successor and bond
//! identities, and then commits through `SuccessorMatcherRuntimeV2`'s
//! fsync-before-publish journal path.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ecx_protocol_core::{
    Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2, Signature64,
    SuccessorCentralMatcherReceiptV2, SuccessorMatcherExecutionReceiptV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorTradeMatchV2,
    TraderStateReadBatchProofV2, XOnlyKey, tagged_hash,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

use crate::{
    CapitalMode, ElementsRpcClient, SuccessorElementsConsensusContextV2,
    SuccessorMatcherPlaceRecoveryV2, SuccessorMatcherProofEntryV2, SuccessorMatcherRuntimeV2,
};

const MAX_SUCCESSOR_HTTP_BODY_BYTES: usize = 32 * 1024;
const SUCCESSOR_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct SuccessorApiStateV2 {
    runtime: Arc<Mutex<SuccessorMatcherRuntimeV2>>,
    node: ElementsRpcClient,
    last_context: Arc<Mutex<SuccessorElementsConsensusContextV2>>,
    successor_configuration: IncrementalSuccessorConfigurationV2,
    trader_state_authority: XOnlyKey,
    proof_producer_token_sha256: [u8; 32],
}

impl SuccessorApiStateV2 {
    pub fn new(
        runtime: SuccessorMatcherRuntimeV2,
        node: ElementsRpcClient,
        initial_context: SuccessorElementsConsensusContextV2,
        successor_configuration: IncrementalSuccessorConfigurationV2,
        trader_state_authority: XOnlyKey,
        proof_producer_token: &str,
    ) -> Result<Self> {
        if proof_producer_token.len() < 32
            || proof_producer_token.len() > 4_096
            || proof_producer_token.chars().any(char::is_whitespace)
        {
            bail!("successor proof-producer token must contain 32..=4096 non-whitespace bytes");
        }
        initial_context.validate()?;
        successor_configuration.validate()?;
        XOnlyPublicKey::from_slice(&trader_state_authority.0)
            .context("invalid successor trader-state authority key")?;
        validate_runtime_context(&runtime, &initial_context, successor_configuration)?;
        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            node,
            last_context: Arc::new(Mutex::new(initial_context)),
            successor_configuration,
            trader_state_authority,
            proof_producer_token_sha256: Sha256::digest(proof_producer_token.as_bytes()).into(),
        })
    }

    async fn refresh_context(
        &self,
    ) -> Result<SuccessorElementsConsensusContextV2, SuccessorApiError> {
        let mut last = self.last_context.lock().await;
        let current = self
            .node
            .successor_consensus_context_after(&last)
            .await
            .map_err(|error| SuccessorApiError::Unavailable(error.to_string()))?;
        {
            let runtime = self.runtime.lock().await;
            validate_runtime_context(&runtime, &current, self.successor_configuration)
                .map_err(|error| SuccessorApiError::Unavailable(error.to_string()))?;
        }
        *last = current.clone();
        Ok(current)
    }
}

fn validate_runtime_context(
    runtime: &SuccessorMatcherRuntimeV2,
    context: &SuccessorElementsConsensusContextV2,
    configuration: IncrementalSuccessorConfigurationV2,
) -> Result<()> {
    if configuration.digest()? != context.successor_configuration_hash
        || runtime.book().config().configuration_hash != configuration.order_configuration_hash
        || runtime.matcher_config().digest() != configuration.successor_matcher_configuration_hash
        || runtime.chain_id() != configuration.chain_id
        || runtime.book().config().chain_id != configuration.chain_id
        || runtime.book().config().market != configuration.market
        || runtime.book().config().risk_params != configuration.risk_params
    {
        bail!(
            "successor matcher runtime/configuration preimage differs from the authenticated node"
        );
    }
    if runtime.book().sidechain_height() > context.sidechain_height {
        bail!("successor matcher book is ahead of the authenticated node tip");
    }
    if runtime.book().match_sequence() < context.matcher_execution_sequence {
        bail!("successor matcher is missing proof-consumed execution history");
    }
    Ok(())
}

pub fn successor_router(state: SuccessorApiStateV2) -> Router {
    Router::new()
        .route("/successor/health", get(successor_health))
        .route("/successor/v2/orders", post(successor_place))
        .route("/successor/v2/orders/cancel", post(successor_cancel))
        .route("/successor/v2/proof/head", get(successor_proof_head))
        .route("/successor/v2/proof/entries", get(successor_proof_entries))
        .layer(RequestBodyLimitLayer::new(MAX_SUCCESSOR_HTTP_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            SUCCESSOR_HTTP_TIMEOUT,
        ))
        .with_state(state)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorPlaceRequestV2 {
    pub signed_order: SuccessorSignedLimitOrderV2,
    pub recovery: SuccessorMatcherPlaceRecoveryV2,
    pub trader_state_grant: SuccessorTraderStateGrantV2,
}

/// Private, tip-bound authorization issued by the proof-state service after
/// opening the authenticated trader leaf. This prevents a caller from
/// poisoning the durable matcher journal with a fabricated order generation.
/// The successor proof still opens and verifies the trader leaf independently.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderStateGrantV2 {
    pub version: u8,
    pub successor_configuration_hash: Hash32,
    pub exchange_state_root: Hash32,
    pub sidechain_block_hash: Hash32,
    pub sidechain_height: u64,
    pub order_id: Hash32,
    pub trader: XOnlyKey,
    pub trader_order_generation: u128,
    pub salt: Hash32,
    pub parent_block_hash: Hash32,
    pub signature: Signature64,
}

impl SuccessorTraderStateGrantV2 {
    pub const VERSION: u8 = 1;

    fn signing_digest(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(1 + 32 * 7 + 8 + 16);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.successor_configuration_hash);
        bytes.extend_from_slice(&self.exchange_state_root);
        bytes.extend_from_slice(&self.sidechain_block_hash);
        bytes.extend_from_slice(&self.sidechain_height.to_be_bytes());
        bytes.extend_from_slice(&self.order_id);
        bytes.extend_from_slice(&self.trader.0);
        bytes.extend_from_slice(&self.trader_order_generation.to_be_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.parent_block_hash);
        tagged_hash("ECX/successor-trader-state-grant/v1", &bytes)
    }

    pub fn issue(
        successor_configuration_hash: Hash32,
        context: &SuccessorElementsConsensusContextV2,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
        authority_secret: &SecretKey,
    ) -> Result<Self> {
        let mut grant = Self {
            version: Self::VERSION,
            successor_configuration_hash,
            exchange_state_root: context.exchange_state_root,
            sidechain_block_hash: context.sidechain_block_hash,
            sidechain_height: context.sidechain_height,
            order_id: order.order_id(),
            trader: order.order.trader,
            trader_order_generation: recovery.trader_order_generation,
            salt: recovery.salt,
            parent_block_hash: recovery.parent_block_hash,
            signature: Signature64([0; 64]),
        };
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), authority_secret);
        let message = Message::from_digest(grant.signing_digest());
        grant.signature = Signature64(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .serialize(),
        );
        Ok(grant)
    }

    /// Issue only after independently reconstructing the node-authenticated
    /// public successor state and opening exactly this trader in its typed
    /// sparse tree. This is the proof-state service boundary used before an
    /// order can reach the matcher; it does not replace the recursive proof.
    pub fn issue_from_authenticated_trader_opening(
        configuration: IncrementalSuccessorConfigurationV2,
        context: &SuccessorElementsConsensusContextV2,
        state: IncrementalPublicStateV2,
        trader_read: &TraderStateReadBatchProofV2,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
        authority_secret: &SecretKey,
    ) -> Result<Self> {
        configuration.validate()?;
        context.validate()?;
        let configuration_hash = configuration.digest()?;
        if configuration_hash != context.successor_configuration_hash
            || state.state_root(configuration)? != context.exchange_state_root
            || state.sidechain_height != context.sidechain_height
            || state.parent_median_time_past != context.parent_mtp
            || state.matcher_sequence != context.matcher_execution_sequence
            || recovery.parent_block_hash != context.parent_block_hash
        {
            bail!(
                "successor trader-state grant input does not reconstruct the authenticated node state"
            );
        }
        trader_read
            .verify(state.trader_root, configuration.accounting_bounds)
            .context("invalid authenticated successor trader opening")?;
        let [leaf] = trader_read.leaves.as_slice() else {
            bail!("successor trader-state grant requires exactly one trader opening");
        };
        if leaf.trader != order.order.trader
            || leaf.order_generation != recovery.trader_order_generation
        {
            bail!("successor trader opening does not match the signed order generation");
        }
        Self::issue(
            configuration_hash,
            context,
            order,
            recovery,
            authority_secret,
        )
    }

    pub fn verify_for(
        &self,
        authority: XOnlyKey,
        successor_configuration_hash: Hash32,
        context: &SuccessorElementsConsensusContextV2,
        order: &SuccessorSignedLimitOrderV2,
        recovery: &SuccessorMatcherPlaceRecoveryV2,
    ) -> Result<()> {
        if self.version != Self::VERSION
            || self.successor_configuration_hash != successor_configuration_hash
            || self.exchange_state_root != context.exchange_state_root
            || self.sidechain_block_hash != context.sidechain_block_hash
            || self.sidechain_height != context.sidechain_height
            || self.order_id != order.order_id()
            || self.trader != order.order.trader
            || self.trader_order_generation != recovery.trader_order_generation
            || self.salt != recovery.salt
            || self.parent_block_hash != context.parent_block_hash
            || self.parent_block_hash != recovery.parent_block_hash
        {
            bail!(
                "successor trader-state grant does not match the authenticated tip, order, or recovery"
            );
        }
        self.verify_signature(authority)
    }

    pub fn verify_signature(&self, authority: XOnlyKey) -> Result<()> {
        let public_key = XOnlyPublicKey::from_slice(&authority.0)
            .context("invalid successor trader-state authority key")?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .context("invalid successor trader-state grant signature")?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.signing_digest()),
                &public_key,
            )
            .context("successor trader-state grant signature verification failed")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorFillViewV2 {
    pub maker: SuccessorSignedLimitOrderV2,
    pub trade: SuccessorTradeMatchV2,
    pub execution_receipt: SuccessorMatcherExecutionReceiptV2,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorPlaceResponseV2 {
    pub accepted: bool,
    pub order_id: String,
    pub admission_receipt: SuccessorCentralMatcherReceiptV2,
    pub fills: Vec<SuccessorFillViewV2>,
    pub remaining_quantity_atoms: u64,
    pub resting: bool,
    pub self_trade_prevented: bool,
    pub pruned_order_ids: Vec<String>,
    pub durable_head_sequence: u128,
    pub durable_head_receipt_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorCancelResponseV2 {
    pub accepted: bool,
    pub admission_receipt: SuccessorCentralMatcherReceiptV2,
    pub cancelled_order_id: Option<String>,
    pub pruned_order_ids: Vec<String>,
    pub durable_head_sequence: u128,
    pub durable_head_receipt_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorHealthViewV2 {
    pub status: &'static str,
    pub proof_profile: &'static str,
    pub capital_mode: CapitalMode,
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub successor_configuration_hash: String,
    pub bond_action_configuration_hash: String,
    pub trader_state_authority: String,
    pub durable_head_sequence: u128,
    pub durable_head_receipt_hash: String,
    pub match_sequence: u128,
    pub proof_consumed_match_sequence: u128,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorProofEntryQueryV2 {
    previous_admission_sequence: String,
    #[serde(default = "default_proof_entry_limit")]
    limit: usize,
}

fn default_proof_entry_limit() -> usize {
    64
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessorProofEntryBatchV2 {
    previous_admission_sequence: u128,
    next_admission_sequence: u128,
    durable_head_sequence: u128,
    durable_head_receipt_hash: String,
    entries: Vec<SuccessorMatcherProofEntryV2>,
}

async fn successor_health(
    State(state): State<SuccessorApiStateV2>,
) -> Result<Json<SuccessorHealthViewV2>, SuccessorApiError> {
    let context = state.refresh_context().await?;
    let runtime = state.runtime.lock().await;
    let head = runtime.journal().head();
    Ok(Json(SuccessorHealthViewV2 {
        status: "ok",
        proof_profile: "incremental-successor",
        capital_mode: context.capital_mode,
        sidechain_height: context.sidechain_height,
        parent_height: context.parent_height,
        successor_configuration_hash: hex::encode(context.successor_configuration_hash),
        bond_action_configuration_hash: hex::encode(context.bond_action_configuration_hash),
        trader_state_authority: hex::encode(state.trader_state_authority.0),
        durable_head_sequence: head.sequence,
        durable_head_receipt_hash: hex::encode(head.receipt_hash),
        match_sequence: runtime.book().match_sequence(),
        proof_consumed_match_sequence: context.matcher_execution_sequence,
    }))
}

async fn successor_place(
    State(state): State<SuccessorApiStateV2>,
    Json(request): Json<SuccessorPlaceRequestV2>,
) -> Result<(StatusCode, Json<SuccessorPlaceResponseV2>), SuccessorApiError> {
    let context = state.refresh_context().await?;
    let reduce_only = request
        .signed_order
        .order
        .flags
        .contains(ecx_protocol_core::OrderFlags::REDUCE_ONLY);
    if !context.capital_mode.permits(reduce_only) {
        return Err(SuccessorApiError::BadRequest(format!(
            "authenticated successor capital mode {:?} rejects this order",
            context.capital_mode
        )));
    }
    if request.recovery.risk.configuration_hash
        != state.successor_configuration.order_configuration_hash
        || request.recovery.parent_block_hash != context.parent_block_hash
    {
        return Err(SuccessorApiError::BadRequest(
            "successor order recovery targets a different configuration or parent".into(),
        ));
    }
    request
        .trader_state_grant
        .verify_for(
            state.trader_state_authority,
            context.successor_configuration_hash,
            &context,
            &request.signed_order,
            &request.recovery,
        )
        .map_err(|error| SuccessorApiError::BadRequest(error.to_string()))?;
    let mut runtime = state.runtime.lock().await;
    let outcome = runtime
        .place(
            &request.signed_order,
            &request.recovery,
            context
                .matcher_context()
                .map_err(|error| SuccessorApiError::Unavailable(error.to_string()))?,
        )
        .map_err(|error| SuccessorApiError::BadRequest(error.to_string()))?;
    let head = runtime.journal().head();
    Ok((
        StatusCode::ACCEPTED,
        Json(SuccessorPlaceResponseV2 {
            accepted: true,
            order_id: hex::encode(request.signed_order.order_id()),
            admission_receipt: outcome.admission_receipt,
            fills: outcome
                .fills
                .into_iter()
                .map(|fill| SuccessorFillViewV2 {
                    maker: fill.maker,
                    trade: fill.trade,
                    execution_receipt: fill.execution_receipt,
                })
                .collect(),
            remaining_quantity_atoms: outcome.remaining_quantity_atoms,
            resting: outcome.resting,
            self_trade_prevented: outcome.self_trade_prevented,
            pruned_order_ids: outcome
                .pruned_order_ids
                .into_iter()
                .map(hex::encode)
                .collect(),
            durable_head_sequence: head.sequence,
            durable_head_receipt_hash: hex::encode(head.receipt_hash),
        }),
    ))
}

async fn successor_cancel(
    State(state): State<SuccessorApiStateV2>,
    Json(cancel): Json<SuccessorSignedCancelOrderV2>,
) -> Result<(StatusCode, Json<SuccessorCancelResponseV2>), SuccessorApiError> {
    let context = state.refresh_context().await?;
    if context.capital_mode == CapitalMode::Recovery {
        return Err(SuccessorApiError::BadRequest(
            "recovery mode rejects successor order cancellation".into(),
        ));
    }
    let mut runtime = state.runtime.lock().await;
    let outcome = runtime
        .cancel(
            &cancel,
            context
                .matcher_context()
                .map_err(|error| SuccessorApiError::Unavailable(error.to_string()))?,
        )
        .map_err(|error| SuccessorApiError::BadRequest(error.to_string()))?;
    let head = runtime.journal().head();
    Ok((
        StatusCode::ACCEPTED,
        Json(SuccessorCancelResponseV2 {
            accepted: true,
            admission_receipt: outcome.admission_receipt,
            cancelled_order_id: outcome
                .cancelled_order
                .as_ref()
                .map(|order| hex::encode(order.order_id())),
            pruned_order_ids: outcome
                .pruned_order_ids
                .into_iter()
                .map(hex::encode)
                .collect(),
            durable_head_sequence: head.sequence,
            durable_head_receipt_hash: hex::encode(head.receipt_hash),
        }),
    ))
}

async fn successor_proof_head(
    State(state): State<SuccessorApiStateV2>,
    headers: HeaderMap,
) -> Result<Json<SuccessorHealthViewV2>, SuccessorApiError> {
    authenticate_proof_producer(&state, &headers)?;
    successor_health(State(state)).await
}

async fn successor_proof_entries(
    State(state): State<SuccessorApiStateV2>,
    Query(query): Query<SuccessorProofEntryQueryV2>,
    headers: HeaderMap,
) -> Result<Json<SuccessorProofEntryBatchV2>, SuccessorApiError> {
    authenticate_proof_producer(&state, &headers)?;
    let previous_admission_sequence =
        parse_canonical_u128_query(&query.previous_admission_sequence)?;
    // Refuse to export against a stale/reorged node context even though the
    // journal itself remains cryptographically intact.
    state.refresh_context().await?;
    let runtime = state.runtime.lock().await;
    let entries = runtime
        .proof_entries_after(previous_admission_sequence, query.limit)
        .map_err(|error| SuccessorApiError::BadRequest(error.to_string()))?;
    let head = runtime.journal().head();
    let next_admission_sequence = entries.last().map_or(previous_admission_sequence, |entry| {
        entry.admission_receipt().body.global_sequence
    });
    Ok(Json(SuccessorProofEntryBatchV2 {
        previous_admission_sequence,
        next_admission_sequence,
        durable_head_sequence: head.sequence,
        durable_head_receipt_hash: hex::encode(head.receipt_hash),
        entries,
    }))
}

fn parse_canonical_u128_query(value: &str) -> Result<u128, SuccessorApiError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SuccessorApiError::BadRequest(
            "previous_admission_sequence is not canonical unsigned decimal".into(),
        ));
    }
    value.parse::<u128>().map_err(|_| {
        SuccessorApiError::BadRequest("previous_admission_sequence exceeds u128".into())
    })
}

fn authenticate_proof_producer(
    state: &SuccessorApiStateV2,
    headers: &HeaderMap,
) -> Result<(), SuccessorApiError> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| SuccessorApiError::Unauthorized("missing authorization".into()))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or_else(|| SuccessorApiError::Unauthorized("invalid authorization scheme".into()))?;
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let difference = state
        .proof_producer_token_sha256
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (left, right)| {
            difference | (*left ^ right)
        });
    if difference != 0 {
        return Err(SuccessorApiError::Unauthorized(
            "invalid proof-producer bearer token".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum SuccessorApiError {
    BadRequest(String),
    Unauthorized(String),
    Unavailable(String),
}

impl IntoResponse for SuccessorApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, error),
            Self::Unauthorized(error) => (StatusCode::UNAUTHORIZED, error),
            Self::Unavailable(error) => (StatusCode::SERVICE_UNAVAILABLE, error),
        };
        (status, Json(serde_json::json!({ "error": error }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use ecx_protocol_core::{
        BOND_FIXED_SUPPLY_ATOMS, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        IncrementalAccountingBoundsV2, Int256V2, OrderFlags, OrderRiskCommitmentV2, Price,
        Quantity, RiskParams, Side, SuccessorCentralMatcherConfigV2, SuccessorLimitOrderV2,
        TimeInForce, TraderLeafV2, TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2,
        TraderStateReadBatchProofV2, XOnlyKey,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use serde_json::{Value, json};
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use crate::{
        SuccessorCentralMatcherSignerV2, SuccessorMatcherJournalV2, SuccessorMatcherRuntimeConfigV2,
    };

    use super::*;

    const TOKEN: &str = "successor-proof-producer-token-at-least-32-bytes";

    fn identity(byte: u8) -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn signed_order(
        secret: &SecretKey,
        trader: XOnlyKey,
        chain_id: [u8; 32],
        side: Side,
        nonce: u128,
    ) -> SuccessorSignedLimitOrderV2 {
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader,
                side,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(3).unwrap(),
                client_order_id: [byte_from_nonce(nonce); 16],
                max_fee_bps: 5,
                nonce,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            secret,
        )
        .unwrap()
    }

    fn byte_from_nonce(nonce: u128) -> u8 {
        nonce.to_be_bytes()[15]
    }

    fn recovery(
        order: &SuccessorSignedLimitOrderV2,
        secret: &SecretKey,
        parent_block_hash: [u8; 32],
    ) -> SuccessorMatcherPlaceRecoveryV2 {
        SuccessorMatcherPlaceRecoveryV2 {
            risk: OrderRiskCommitmentV2::sign(
                [3; 32],
                order.order_id(),
                order.order.trader,
                1_000,
                secret,
            )
            .unwrap(),
            trader_order_generation: (1u128 << 100) + 7,
            salt: [9; 32],
            parent_block_hash,
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

    fn successor_configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [7; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [3; 32],
            successor_matcher_configuration_hash: matcher_configuration().digest(),
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

    fn node_result(profile: &str) -> Value {
        let mut capital = serde_json::Map::new();
        macro_rules! field {
            ($name:literal, $value:expr) => {
                capital.insert($name.into(), json!($value));
            };
        }
        field!("version", 3);
        field!("proofprofile", profile);
        field!("exchangestateroot", "22".repeat(32));
        field!(
            "configurationhash",
            hex::encode(successor_configuration().digest().unwrap())
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
        field!(
            "issuedbondunits",
            ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS
        );
        field!("outstandingbondunits", 100);
        field!(
            "inventorybondunits",
            ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS - 100
        );
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
            "exchangestateroot": "22".repeat(32),
            "forcedinbox": {"headroot": "33".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
            "depositinbox": {"headroot": "44".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
            "bmm": {"authenticated": true, "parentheight": 100, "parentmtp": 1_000, "parentblockhash": "55".repeat(32)},
            "sourceparentheight": 100,
            "sourcebacklogoldestparentheight": 0,
            "capital": Value::Object(capital)
        })
    }

    async fn node_client(profile: &'static str) -> ElementsRpcClient {
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| async move {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": node_result(profile),
                    "error": null
                }))
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        ElementsRpcClient::new(&format!("http://{address}"), None, None).unwrap()
    }

    async fn fixture() -> (
        Router,
        SuccessorSignedLimitOrderV2,
        SuccessorMatcherPlaceRecoveryV2,
        SuccessorTraderStateGrantV2,
        tempfile::TempDir,
    ) {
        let temporary = tempdir().unwrap();
        let (matcher_secret, _) = identity(61);
        let chain_id = [7; 32];
        let matcher_config = matcher_configuration();
        let signer =
            SuccessorCentralMatcherSignerV2::new(matcher_config.clone(), matcher_secret, chain_id)
                .unwrap();
        let runtime_config = SuccessorMatcherRuntimeConfigV2 {
            chain_id,
            configuration_hash: [3; 32],
            market: ECX_USDD_MARKET,
            risk_params: RiskParams::default(),
            maximum_live_orders: 64,
        };
        let journal = SuccessorMatcherJournalV2::open(
            temporary.path().join("successor.matcher"),
            matcher_config,
            chain_id,
        )
        .unwrap();
        let runtime = SuccessorMatcherRuntimeV2::open(signer, journal, runtime_config, 10).unwrap();
        let node = node_client("incremental-successor").await;
        let initial = node.successor_consensus_context().await.unwrap();
        let (authority_secret, authority) = identity(63);
        let (trader_secret, trader) = identity(62);
        let order = signed_order(
            &trader_secret,
            trader,
            chain_id,
            Side::Sell,
            (1u128 << 104) + 1,
        );
        let recovery = recovery(&order, &trader_secret, [0x55; 32]);
        let grant = SuccessorTraderStateGrantV2::issue(
            successor_configuration().digest().unwrap(),
            &initial,
            &order,
            &recovery,
            &authority_secret,
        )
        .unwrap();
        let state = SuccessorApiStateV2::new(
            runtime,
            node,
            initial,
            successor_configuration(),
            authority,
            TOKEN,
        )
        .unwrap();
        (successor_router(state), order, recovery, grant, temporary)
    }

    #[tokio::test]
    async fn successor_http_is_profile_bound_high_bit_safe_and_private() {
        let (app, order, recovery, grant, _temporary) = fixture().await;
        let body = serde_json::to_vec(&SuccessorPlaceRequestV2 {
            signed_order: order.clone(),
            recovery: recovery.clone(),
            trader_state_grant: grant.clone(),
        })
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/successor/v2/orders")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap();
        let decoded: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded["accepted"], true);
        assert_eq!(
            decoded["durable_head_sequence"].to_string(),
            ((1u128 << 96) + 11).to_string()
        );
        assert_eq!(
            decoded["admission_receipt"]["body"]["global_sequence"].to_string(),
            ((1u128 << 96) + 11).to_string()
        );

        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/successor/v2/proof/head")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let authorized = app
            .clone()
            .oneshot(
                Request::get("/successor/v2/proof/head")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);

        let proof_entries = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/successor/v2/proof/entries?previous_admission_sequence={}&limit=8",
                    (1u128 << 96) + 10
                ))
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        let proof_status = proof_entries.status();
        let proof_body = axum::body::to_bytes(proof_entries.into_body(), 256 * 1024)
            .await
            .unwrap();
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected proof export: {}",
            String::from_utf8_lossy(&proof_body)
        );
        let proof: Value = serde_json::from_slice(&proof_body).unwrap();
        assert_eq!(proof["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            proof["next_admission_sequence"].to_string(),
            ((1u128 << 96) + 11).to_string()
        );
        assert_eq!(
            proof["entries"][0]["place"]["outcome"]["admission_receipt"]["body"]["global_sequence"]
                .to_string(),
            ((1u128 << 96) + 11).to_string()
        );

        let mut wrong_parent = recovery;
        wrong_parent.parent_block_hash[0] ^= 1;
        let response = app
            .oneshot(
                Request::post("/successor/v2/orders")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&SuccessorPlaceRequestV2 {
                            signed_order: order,
                            recovery: wrong_parent,
                            trader_state_grant: grant,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn successor_trader_state_grant_rejects_poisoning_before_journal_mutation() {
        let (app, order, recovery, grant, _temporary) = fixture().await;
        let mut invalid = Vec::new();

        let mut value = grant.clone();
        value.trader_order_generation += 1;
        invalid.push(value);
        let mut value = grant.clone();
        value.exchange_state_root[0] ^= 1;
        invalid.push(value);
        let mut value = grant.clone();
        value.sidechain_block_hash[0] ^= 1;
        invalid.push(value);
        let mut value = grant.clone();
        value.successor_configuration_hash[0] ^= 1;
        invalid.push(value);
        let mut value = grant.clone();
        value.order_id[0] ^= 1;
        invalid.push(value);
        let mut value = grant.clone();
        value.salt[0] ^= 1;
        invalid.push(value);
        let mut value = grant;
        value.signature.0[0] ^= 1;
        invalid.push(value);

        for trader_state_grant in invalid {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/successor/v2/orders")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&SuccessorPlaceRequestV2 {
                                signed_order: order.clone(),
                                recovery: recovery.clone(),
                                trader_state_grant,
                            })
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let health = app
            .oneshot(
                Request::get("/successor/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let body = axum::body::to_bytes(health.into_body(), 128 * 1024)
            .await
            .unwrap();
        let decoded: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            decoded["durable_head_sequence"].to_string(),
            ((1u128 << 96) + 10).to_string()
        );
    }

    #[tokio::test]
    async fn successor_state_rejects_finite_profile_before_serving() {
        let node = node_client("finite-v18").await;
        assert!(node.successor_consensus_context().await.is_err());
    }

    #[test]
    fn successor_grant_issuer_requires_exact_authenticated_trader_opening() {
        let configuration = successor_configuration();
        let (trader_secret, trader) = identity(62);
        let order = signed_order(
            &trader_secret,
            trader,
            configuration.chain_id,
            Side::Sell,
            (1u128 << 104) + 2,
        );
        let recovery = recovery(&order, &trader_secret, [0x55; 32]);
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
        let trader_read = TraderStateReadBatchProofV2 {
            leaves: vec![leaf],
            frontier: insertion.frontier,
        };
        trader_read
            .verify(state.trader_root, configuration.accounting_bounds)
            .unwrap();
        let context = SuccessorElementsConsensusContextV2 {
            sidechain_height: 10,
            sidechain_block_hash: [0x11; 32],
            exchange_state_root: state.state_root(configuration).unwrap(),
            parent_height: 100,
            parent_mtp: 1_000,
            parent_block_hash: [0x55; 32],
            source_parent_height: 100,
            forced_inbox_processed_cursor: 0,
            successor_configuration_hash: configuration.digest().unwrap(),
            bond_action_configuration_hash: [0x66; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
            capital_mode: CapitalMode::Normal,
            matcher_execution_previous_sequence: 0,
            matcher_execution_sequence: 0,
            last_transition_sidechain_height: 9,
        };
        let (authority_secret, authority) = identity(63);
        let grant = SuccessorTraderStateGrantV2::issue_from_authenticated_trader_opening(
            configuration,
            &context,
            state,
            &trader_read,
            &order,
            &recovery,
            &authority_secret,
        )
        .unwrap();
        grant
            .verify_for(
                authority,
                configuration.digest().unwrap(),
                &context,
                &order,
                &recovery,
            )
            .unwrap();

        let mut wrong_context = context.clone();
        wrong_context.exchange_state_root[0] ^= 1;
        assert!(
            SuccessorTraderStateGrantV2::issue_from_authenticated_trader_opening(
                configuration,
                &wrong_context,
                state,
                &trader_read,
                &order,
                &recovery,
                &authority_secret,
            )
            .is_err()
        );
        let mut wrong_read = trader_read;
        wrong_read.leaves[0].order_generation += 1;
        assert!(
            SuccessorTraderStateGrantV2::issue_from_authenticated_trader_opening(
                configuration,
                &context,
                state,
                &wrong_read,
                &order,
                &recovery,
                &authority_secret,
            )
            .is_err()
        );
    }
}
