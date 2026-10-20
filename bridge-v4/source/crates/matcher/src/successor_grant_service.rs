//! Private, node-bound trader-state grant service for the incremental successor.
//!
//! The service deliberately does not invent or derive trader state. A proof
//! producer must first materialize an exact public-state preimage plus a typed
//! one-trader read proof under a filename bound to the authenticated state root
//! and trader. The service revalidates that snapshot against the node before
//! and after reading it, then returns a fresh recovery salt and signed grant.

use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use ecx_protocol_core::{
    Hash32, IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2, OrderRiskCommitmentV2,
    SuccessorSignedLimitOrderV2, TraderStateReadBatchProofV2,
};
use secp256k1::{SecretKey, rand::RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

use crate::{
    ElementsRpcClient, SuccessorElementsConsensusContextV2, SuccessorMatcherPlaceRecoveryV2,
    SuccessorTraderStateGrantV2,
};

const MAX_GRANT_REQUEST_BYTES: usize = 128 * 1024;
const MAX_TRADER_SNAPSHOT_BYTES: u64 = 12 * 1024 * 1024;
const GRANT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderStateSnapshotV2 {
    pub version: u8,
    pub exchange_state_root: Hash32,
    pub trader: ecx_protocol_core::XOnlyKey,
    pub state: IncrementalPublicStateV2,
    pub trader_read: TraderStateReadBatchProofV2,
}

impl SuccessorTraderStateSnapshotV2 {
    pub const VERSION: u8 = 1;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderStateGrantRequestV2 {
    pub signed_order: SuccessorSignedLimitOrderV2,
    pub risk: OrderRiskCommitmentV2,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderStateGrantResponseV2 {
    pub recovery: SuccessorMatcherPlaceRecoveryV2,
    pub trader_state_grant: SuccessorTraderStateGrantV2,
}

#[derive(Clone)]
pub struct SuccessorTraderStateGrantServiceV2 {
    configuration: IncrementalSuccessorConfigurationV2,
    snapshot_directory: PathBuf,
    authority_secret: Arc<SecretKey>,
    bearer_token_sha256: Hash32,
    node: ElementsRpcClient,
}

impl SuccessorTraderStateGrantServiceV2 {
    pub fn new(
        configuration: IncrementalSuccessorConfigurationV2,
        snapshot_directory: PathBuf,
        authority_secret: SecretKey,
        bearer_token: &str,
        node: ElementsRpcClient,
    ) -> Result<Self> {
        configuration.validate()?;
        validate_private_directory(&snapshot_directory)?;
        if bearer_token.len() < 32
            || bearer_token.len() > 4_096
            || bearer_token.chars().any(char::is_whitespace)
        {
            bail!(
                "successor trader-state bearer token must contain 32..=4096 non-whitespace bytes"
            );
        }
        Ok(Self {
            configuration,
            snapshot_directory,
            authority_secret: Arc::new(authority_secret),
            bearer_token_sha256: Sha256::digest(bearer_token.as_bytes()).into(),
            node,
        })
    }

    async fn issue(
        &self,
        request: SuccessorTraderStateGrantRequestV2,
    ) -> Result<SuccessorTraderStateGrantResponseV2> {
        request
            .signed_order
            .verify()
            .context("invalid successor signed order")?;
        request
            .risk
            .verify(self.configuration.risk_params)
            .context("invalid successor order-risk commitment")?;
        if request.signed_order.order.chain_id != self.configuration.chain_id
            || request.signed_order.order.market != self.configuration.market
            || request.risk.configuration_hash != self.configuration.order_configuration_hash
            || request.risk.order_id != request.signed_order.order_id()
            || request.risk.trader != request.signed_order.order.trader
        {
            bail!("successor grant request does not match the frozen configuration or order");
        }

        let before = self
            .node
            .successor_consensus_context()
            .await
            .context("reading authenticated successor context before trader snapshot")?;
        if before.successor_configuration_hash != self.configuration.digest()? {
            bail!("authenticated successor context has the wrong configuration");
        }
        let path = snapshot_path(
            &self.snapshot_directory,
            before.exchange_state_root,
            request.signed_order.order.trader,
        );
        let snapshot = tokio::task::spawn_blocking(move || read_snapshot(&path))
            .await
            .context("trader snapshot reader panicked")??;
        validate_snapshot(
            self.configuration,
            &before,
            &request.signed_order,
            &snapshot,
        )?;

        let leaf = snapshot
            .trader_read
            .leaves
            .first()
            .context("trader snapshot omitted its typed opening")?;
        let mut salt = [0u8; 32];
        while salt == [0; 32] {
            secp256k1::rand::rngs::OsRng.fill_bytes(&mut salt);
        }
        let recovery = SuccessorMatcherPlaceRecoveryV2 {
            risk: request.risk,
            trader_order_generation: leaf.order_generation,
            salt,
            parent_block_hash: before.parent_block_hash,
        };
        let grant = SuccessorTraderStateGrantV2::issue_from_authenticated_trader_opening(
            self.configuration,
            &before,
            snapshot.state,
            &snapshot.trader_read,
            &request.signed_order,
            &recovery,
            &self.authority_secret,
        )?;

        let after = self
            .node
            .successor_consensus_context_after(&before)
            .await
            .context("rechecking authenticated successor context after trader snapshot")?;
        if after != before {
            bail!("authenticated successor context advanced while issuing trader-state grant");
        }
        Ok(SuccessorTraderStateGrantResponseV2 {
            recovery,
            trader_state_grant: grant,
        })
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<()> {
        let authorization = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .context("missing authorization")?;
        let token = authorization
            .strip_prefix("Bearer ")
            .context("invalid authorization scheme")?;
        let actual: Hash32 = Sha256::digest(token.as_bytes()).into();
        let mut difference = 0u8;
        for (left, right) in actual.iter().zip(self.bearer_token_sha256) {
            difference |= left ^ right;
        }
        if difference != 0 {
            bail!("invalid successor trader-state bearer token");
        }
        Ok(())
    }
}

pub fn successor_trader_state_grant_router(state: SuccessorTraderStateGrantServiceV2) -> Router {
    Router::new()
        .route(
            "/successor/v2/trader-state-grants",
            post(issue_trader_state_grant),
        )
        .layer(RequestBodyLimitLayer::new(MAX_GRANT_REQUEST_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            GRANT_REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

async fn issue_trader_state_grant(
    State(state): State<SuccessorTraderStateGrantServiceV2>,
    headers: HeaderMap,
    Json(request): Json<SuccessorTraderStateGrantRequestV2>,
) -> Result<Json<SuccessorTraderStateGrantResponseV2>, SuccessorGrantServiceError> {
    state
        .authorize(&headers)
        .map_err(|error| SuccessorGrantServiceError::Unauthorized(error.to_string()))?;
    state
        .issue(request)
        .await
        .map(Json)
        .map_err(|error| SuccessorGrantServiceError::Unavailable(error.to_string()))
}

#[derive(Debug)]
enum SuccessorGrantServiceError {
    Unauthorized(String),
    Unavailable(String),
}

impl IntoResponse for SuccessorGrantServiceError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message),
            Self::Unavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn successor_trader_snapshot_filename(
    exchange_state_root: Hash32,
    trader: ecx_protocol_core::XOnlyKey,
) -> String {
    format!(
        "{}-{}.json",
        hex::encode(exchange_state_root),
        hex::encode(trader.0)
    )
}

fn snapshot_path(
    directory: &Path,
    exchange_state_root: Hash32,
    trader: ecx_protocol_core::XOnlyKey,
) -> PathBuf {
    directory.join(successor_trader_snapshot_filename(
        exchange_state_root,
        trader,
    ))
}

fn validate_snapshot(
    configuration: IncrementalSuccessorConfigurationV2,
    context: &SuccessorElementsConsensusContextV2,
    order: &SuccessorSignedLimitOrderV2,
    snapshot: &SuccessorTraderStateSnapshotV2,
) -> Result<()> {
    if snapshot.version != SuccessorTraderStateSnapshotV2::VERSION
        || snapshot.exchange_state_root != context.exchange_state_root
        || snapshot.trader != order.order.trader
        || snapshot.state.state_root(configuration)? != snapshot.exchange_state_root
        || snapshot.state.sidechain_height != context.sidechain_height
        || snapshot.state.parent_median_time_past != context.parent_mtp
        || snapshot.state.matcher_sequence != context.matcher_execution_sequence
        || snapshot.trader_read.leaves.len() != 1
        || snapshot.trader_read.leaves[0].trader != snapshot.trader
    {
        bail!("trader snapshot does not reconstruct the authenticated successor state");
    }
    snapshot
        .trader_read
        .verify(snapshot.state.trader_root, configuration.accounting_bounds)
        .context("trader snapshot has an invalid typed read proof")
}

fn read_snapshot(path: &Path) -> Result<SuccessorTraderStateSnapshotV2> {
    let bytes = read_private_regular_file(path, MAX_TRADER_SNAPSHOT_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding exact trader snapshot {}", path.display()))
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect trader snapshot directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("trader snapshot store must be a regular non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("trader snapshot store permissions are broader than 0700");
        }
    }
    Ok(())
}

fn read_private_regular_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let before =
        std::fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if before.len() == 0 || before.len() > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    #[cfg(unix)]
    {
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
    let mut bytes = Vec::with_capacity(
        usize::try_from(after.len()).context("trader snapshot size does not fit memory")?,
    );
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}
