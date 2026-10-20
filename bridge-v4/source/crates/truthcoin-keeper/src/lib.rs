//! Replaceable availability keeper for canonical scalar-price Truthcoin markets.
//!
//! The keeper can submit only static Decision/market creation data. It neither
//! reads nor emits an oracle price, and proof verification never trusts it.
//! Canonical selection and LMSR state are authenticated separately by
//! `ecx-truthcoin-proof`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ecx_truthcoin_proof::{
    TruthcoinMarketTemplateCommitmentV1, TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
    TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Hash32 = [u8; 32];
const MAX_TRUTHCOIN_PERIOD: u32 = 127;
const PPM_DENOMINATOR: u32 = 1_000_000;
const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_KEEPER_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_KEEPER_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperConfigV1 {
    pub version: u8,
    pub truthcoin_rpc_url: String,
    #[serde(with = "hex32")]
    pub expected_openapi_schema_sha256: Hash32,
    #[serde(with = "hex20")]
    pub source_git_commit_sha1: [u8; 20],
    #[serde(with = "hex32")]
    pub source_patch_manifest_sha256: Hash32,
    #[serde(with = "hex32")]
    pub btc_usd_template_hash: Hash32,
    pub request_timeout_seconds: u64,
    pub pending_retry_blocks: u32,
    /// Number of future production periods to pre-create in addition to the
    /// current one. The keeper still submits at most one transaction per poll.
    #[serde(default)]
    pub market_lookahead_periods: u8,
    pub market: CanonicalMarketTemplateV1,
}

impl KeeperConfigV1 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), KeeperError> {
        if self.version != Self::VERSION {
            return Err(KeeperError::UnsupportedVersion);
        }
        if self.source_git_commit_sha1 != TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1 {
            return Err(KeeperError::UnpinnedSource);
        }
        if self.source_patch_manifest_sha256 != TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256 {
            return Err(KeeperError::UnpinnedSource);
        }
        if self.expected_openapi_schema_sha256 == [0; 32]
            || self.btc_usd_template_hash != self.market.source_template_hash()
            || self.request_timeout_seconds == 0
            || self.request_timeout_seconds > 300
            || self.pending_retry_blocks == 0
            || self.pending_retry_blocks > 100_000
            || self.market_lookahead_periods > 4
        {
            return Err(KeeperError::InvalidConfiguration);
        }
        validate_rpc_url(&self.truthcoin_rpc_url)?;
        self.market.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMarketTemplateV1 {
    pub version: u8,
    /// Every template must contain exactly one `{period}` placeholder.
    pub market_title_template: String,
    pub market_description_template: String,
    pub decision_header_template: String,
    pub decision_description_template: String,
    pub decision_tags: Vec<String>,
    /// IEEE-754 bits are used so the request is pinned to upstream's exact
    /// `f64` consensus representation rather than a lossy config conversion.
    pub scalar_min_f64_bits: u64,
    pub scalar_max_f64_bits: u64,
    pub scalar_increment_f64_bits: u64,
    pub initial_liquidity_sats: u64,
    pub trading_fee_ppm: u32,
    pub tx_fee_sats: u64,
    pub maximum_listing_fee_sats: u64,
    pub tx_pow_hash_selector: u8,
    pub tx_pow_ordering: u8,
    pub tx_pow_difficulty: u8,
}

impl CanonicalMarketTemplateV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), KeeperError> {
        if self.version != Self::VERSION
            || self.initial_liquidity_sats == 0
            || self.tx_fee_sats == 0
            || self.maximum_listing_fee_sats == 0
            || self.trading_fee_ppm > PPM_DENOMINATOR
            || self.tx_pow_difficulty > 32
            || self.tx_pow_difficulty > 0 && self.tx_pow_hash_selector == 0
            || self.decision_tags.len() > 10
        {
            return Err(KeeperError::InvalidConfiguration);
        }
        for template in [
            &self.market_title_template,
            &self.market_description_template,
            &self.decision_header_template,
            &self.decision_description_template,
        ] {
            if template.matches("{period}").count() != 1 {
                return Err(KeeperError::InvalidConfiguration);
            }
        }
        if self.decision_tags.iter().any(|tag| tag.len() > 50) {
            return Err(KeeperError::InvalidConfiguration);
        }

        let min = f64::from_bits(self.scalar_min_f64_bits);
        let max = f64::from_bits(self.scalar_max_f64_bits);
        let increment = f64::from_bits(self.scalar_increment_f64_bits);
        if !min.is_finite()
            || !max.is_finite()
            || !increment.is_finite()
            || min >= max
            || increment <= 0.0
            || !is_step_aligned(max - min, increment)
        {
            return Err(KeeperError::InvalidConfiguration);
        }
        let beta = self.initial_liquidity_sats as f64 / libm::log(2.0);
        if !beta.is_finite() || beta <= 1e-6 || beta >= 1e12 {
            return Err(KeeperError::InvalidConfiguration);
        }

        let rendered = self.render(0)?;
        if rendered.decision_header.len() > 100
            || rendered.decision_description.len() > 2_000
            || rendered.market_title.is_empty()
            || rendered.market_description.is_empty()
        {
            return Err(KeeperError::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn source_template_hash(&self) -> Hash32 {
        self.source_template_commitment().digest()
    }

    pub fn source_template_commitment(&self) -> TruthcoinMarketTemplateCommitmentV1 {
        TruthcoinMarketTemplateCommitmentV1 {
            version: TruthcoinMarketTemplateCommitmentV1::VERSION,
            market_title_template: self.market_title_template.clone(),
            market_description_template: self.market_description_template.clone(),
            decision_header_template: self.decision_header_template.clone(),
            decision_description_template: self.decision_description_template.clone(),
            decision_tags: self.decision_tags.clone(),
            scalar_min_f64_bits: self.scalar_min_f64_bits,
            scalar_max_f64_bits: self.scalar_max_f64_bits,
            scalar_increment_f64_bits: self.scalar_increment_f64_bits,
            minimum_liquidity_sats: self.initial_liquidity_sats,
            trading_fee_ppm: self.trading_fee_ppm,
            tx_pow_hash_selector: self.tx_pow_hash_selector,
            tx_pow_ordering: self.tx_pow_ordering,
            tx_pow_difficulty: self.tx_pow_difficulty,
        }
    }

    pub fn render(&self, period: u32) -> Result<CanonicalMarketIdentity, KeeperError> {
        if period > MAX_TRUTHCOIN_PERIOD {
            return Err(KeeperError::NoRepresentablePeriod(period));
        }
        let period_text = period.to_string();
        let identity = CanonicalMarketIdentity {
            period,
            market_title: self.market_title_template.replace("{period}", &period_text),
            market_description: self
                .market_description_template
                .replace("{period}", &period_text),
            decision_header: self
                .decision_header_template
                .replace("{period}", &period_text),
            decision_description: self
                .decision_description_template
                .replace("{period}", &period_text),
            decision_tags: self.decision_tags.clone(),
            scalar_min_f64_bits: self.scalar_min_f64_bits,
            scalar_max_f64_bits: self.scalar_max_f64_bits,
            scalar_increment_f64_bits: self.scalar_increment_f64_bits,
            initial_liquidity_sats: self.initial_liquidity_sats,
            trading_fee_ppm: self.trading_fee_ppm,
            tx_pow_hash_selector: self.tx_pow_hash_selector,
            tx_pow_ordering: self.tx_pow_ordering,
            tx_pow_difficulty: self.tx_pow_difficulty,
        };
        if identity.decision_header.len() > 100 || identity.decision_description.len() > 2_000 {
            return Err(KeeperError::InvalidConfiguration);
        }
        Ok(identity)
    }
}

fn is_step_aligned(delta: f64, step: f64) -> bool {
    // Mirrors truthcoin-dc 0.17.0 `state/decisions/types.rs`.
    let k = (delta / step).round();
    let tolerance = (step.abs() * 1e-9).max(1e-12);
    (delta - k * step).abs() <= tolerance
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMarketIdentity {
    pub period: u32,
    pub market_title: String,
    pub market_description: String,
    pub decision_header: String,
    pub decision_description: String,
    pub decision_tags: Vec<String>,
    pub scalar_min_f64_bits: u64,
    pub scalar_max_f64_bits: u64,
    pub scalar_increment_f64_bits: u64,
    /// A canonical market may later be permissionlessly amplified, so this is
    /// a minimum effective liquidity base rather than an equality check.
    pub initial_liquidity_sats: u64,
    pub trading_fee_ppm: u32,
    pub tx_pow_hash_selector: u8,
    pub tx_pow_ordering: u8,
    pub tx_pow_difficulty: u8,
}

impl CanonicalMarketIdentity {
    pub fn digest(&self) -> Hash32 {
        let value = serde_json::to_value(self).expect("identity serialization is infallible");
        canonical_json_sha256(&value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSubmissionV1 {
    pub version: u8,
    pub period: u32,
    #[serde(with = "hex32")]
    pub identity_hash: Hash32,
    pub txid: String,
    pub market_id: String,
    pub decision_id: String,
    pub submitted_at_height: u64,
}

impl PendingSubmissionV1 {
    pub fn validate(&self) -> Result<(), KeeperError> {
        if self.version != 1
            || self.period > MAX_TRUTHCOIN_PERIOD
            || self.identity_hash == [0; 32]
            || !is_hex_len(&self.txid, 64)
            || !is_hex_len(&self.market_id, 12)
            || !is_hex_len(&self.decision_id, 6)
        {
            return Err(KeeperError::InvalidPendingState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperStateV1 {
    pub version: u8,
    pub pending: Option<PendingSubmissionV1>,
}

impl Default for KeeperStateV1 {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            pending: None,
        }
    }
}

impl KeeperStateV1 {
    pub const VERSION: u8 = 1;

    pub fn load(path: &Path) -> Result<Self, KeeperError> {
        match read_regular_file_bounded(path, MAX_KEEPER_STATE_BYTES) {
            Ok(bytes) => {
                let state: Self = serde_json::from_slice(&bytes)?;
                if state.version != Self::VERSION {
                    return Err(KeeperError::UnsupportedVersion);
                }
                if let Some(pending) = state.pending.as_ref() {
                    pending.validate()?;
                }
                Ok(state)
            }
            Err(KeeperError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), KeeperError> {
        let parent = path.parent().ok_or(KeeperError::InvalidStatePath)?;
        std::fs::create_dir_all(parent)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(KeeperError::UnsafeLocalFile)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() as u64 > MAX_KEEPER_STATE_BYTES {
            return Err(KeeperError::LocalFileTooLarge);
        }
        use std::io::Write;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| KeeperError::Io(error.error))?;
        let directory = std::fs::File::open(parent)?;
        directory.sync_all()?;
        Ok(())
    }
}

/// Process-lifetime exclusive ownership of one keeper state path.
///
/// The lock is advisory at the operating-system level, so every ECX keeper
/// must acquire it before reading or mutating the associated state file.
#[derive(Debug)]
pub struct KeeperStateLock {
    _file: std::fs::File,
}

impl KeeperStateLock {
    pub fn acquire(state_path: &Path) -> Result<Self, KeeperError> {
        let parent = state_path.parent().ok_or(KeeperError::InvalidStatePath)?;
        std::fs::create_dir_all(parent)?;
        let mut lock_name = state_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = Path::new(&lock_name);

        match std::fs::symlink_metadata(lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(KeeperError::UnsafeLocalFile)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        let opened = file.metadata()?;
        let at_path = std::fs::symlink_metadata(lock_path)?;
        if at_path.file_type().is_symlink() || !opened.is_file() || !at_path.is_file() {
            return Err(KeeperError::UnsafeLocalFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if opened.dev() != at_path.dev() || opened.ino() != at_path.ino() {
                return Err(KeeperError::UnsafeLocalFile);
            }
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.try_lock_exclusive()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock => KeeperError::StateAlreadyLocked,
                _ => KeeperError::Io(error),
            })?;
        Ok(Self { _file: file })
    }
}

pub fn load_keeper_config(path: &Path) -> Result<KeeperConfigV1, KeeperError> {
    let bytes = read_regular_file_bounded(path, MAX_KEEPER_CONFIG_BYTES)?;
    let config: KeeperConfigV1 = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

fn read_regular_file_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, KeeperError> {
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(KeeperError::UnsafeLocalFile);
    }
    if before.len() > maximum {
        return Err(KeeperError::LocalFileTooLarge);
    }
    let mut file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(KeeperError::UnsafeLocalFile);
        }
    }
    let mut bytes = Vec::with_capacity(opened.len().min(maximum) as usize);
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(KeeperError::LocalFileTooLarge);
    }
    let after = std::fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.file_type().is_symlink()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
        {
            return Err(KeeperError::UnsafeLocalFile);
        }
    }
    Ok(bytes)
}

#[allow(async_fn_in_trait)]
pub trait TruthcoinRpc: Sync {
    async fn call(&self, method: &str, params: Value) -> Result<Value, KeeperError>;
}

#[derive(Debug)]
pub struct HttpTruthcoinRpc {
    endpoint: String,
    client: Client,
    request_id: AtomicU64,
}

impl HttpTruthcoinRpc {
    pub fn new(endpoint: String, timeout: Duration) -> Result<Self, KeeperError> {
        validate_rpc_url(&endpoint)?;
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(KeeperError::InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            endpoint,
            client,
            request_id: AtomicU64::new(1),
        })
    }
}

impl TruthcoinRpc for HttpTruthcoinRpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, KeeperError> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(&self.endpoint)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            }))
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            return Err(KeeperError::RpcResponseTooLarge);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
                return Err(KeeperError::RpcResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes)?;
        parse_json_rpc_response(body, id)
    }
}

fn parse_json_rpc_response(body: Value, expected_id: u64) -> Result<Value, KeeperError> {
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || body.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err(KeeperError::MalformedRpcResponse);
    }
    if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
        let object = error.as_object().ok_or(KeeperError::MalformedRpcResponse)?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "code" | "message" | "data"))
        {
            return Err(KeeperError::MalformedRpcResponse);
        }
        let code = object
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(KeeperError::MalformedRpcResponse)?;
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .ok_or(KeeperError::MalformedRpcResponse)?;
        if message.is_empty() {
            return Err(KeeperError::MalformedRpcResponse);
        }
        return Err(KeeperError::Rpc {
            code,
            message: message.to_owned(),
        });
    }
    body.get("result")
        .cloned()
        .ok_or(KeeperError::MalformedRpcResponse)
}

fn validate_rpc_url(endpoint: &str) -> Result<(), KeeperError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| KeeperError::InvalidConfiguration)?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(KeeperError::InvalidConfiguration);
    }
    let host = url.host_str().ok_or(KeeperError::InvalidConfiguration)?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback => Ok(()),
        _ => Err(KeeperError::InvalidConfiguration),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeeperAction {
    Existing {
        period: u32,
        market_id: String,
        decision_id: String,
    },
    Missing {
        period: u32,
        identity_hash: Hash32,
    },
    Pending(PendingSubmissionV1),
    Submitted(PendingSubmissionV1),
}

/// Ensure the fastest claimable (current-period) canonical market exists.
///
/// This method never calls a trading, voting, resolution, or price-setting RPC.
pub async fn ensure_canonical_market<R: TruthcoinRpc>(
    config: &KeeperConfigV1,
    rpc: &R,
    pending: Option<&PendingSubmissionV1>,
) -> Result<KeeperAction, KeeperError> {
    inspect_or_ensure_canonical_market(config, rpc, pending, true).await
}

/// Run the exact production discovery and eligibility checks without invoking
/// the wallet-spending `market_create` method.
pub async fn preflight_canonical_market<R: TruthcoinRpc>(
    config: &KeeperConfigV1,
    rpc: &R,
) -> Result<KeeperAction, KeeperError> {
    inspect_or_ensure_canonical_market(config, rpc, None, false).await
}

async fn inspect_or_ensure_canonical_market<R: TruthcoinRpc>(
    config: &KeeperConfigV1,
    rpc: &R,
    pending: Option<&PendingSubmissionV1>,
    submit: bool,
) -> Result<KeeperAction, KeeperError> {
    config.validate()?;

    let schema = rpc.call("openapi_schema", json!([])).await?;
    let observed_schema_hash = canonical_json_sha256(&schema);
    if observed_schema_hash != config.expected_openapi_schema_sha256 {
        return Err(KeeperError::SchemaMismatch {
            expected: hex::encode(config.expected_openapi_schema_sha256),
            observed: hex::encode(observed_schema_hash),
        });
    }

    let status: DecisionStatus =
        serde_json::from_value(rpc.call("decision_status", json!([])).await?)?;
    if status.is_testing_mode {
        return Err(KeeperError::TestingModeRejected);
    }
    let final_period = status
        .current_period
        .saturating_add(u32::from(config.market_lookahead_periods))
        .min(MAX_TRUTHCOIN_PERIOD);
    let mut last_existing = None;
    for period in status.current_period..=final_period {
        let identity = config.market.render(period)?;
        if let Some((market_id, decision_id)) = find_exact_market(rpc, &identity).await? {
            last_existing = Some(KeeperAction::Existing {
                period: identity.period,
                market_id,
                decision_id,
            });
            continue;
        }
        if !submit {
            return Ok(KeeperAction::Missing {
                period: identity.period,
                identity_hash: identity.digest(),
            });
        }
        return submit_missing_market(config, rpc, pending, identity).await;
    }
    last_existing.ok_or(KeeperError::NoRepresentablePeriod(status.current_period))
}

async fn submit_missing_market<R: TruthcoinRpc>(
    config: &KeeperConfigV1,
    rpc: &R,
    pending: Option<&PendingSubmissionV1>,
    identity: CanonicalMarketIdentity,
) -> Result<KeeperAction, KeeperError> {
    let identity_hash = identity.digest();

    let height = value_as_u64(rpc.call("getblockcount", json!([])).await?)?;
    if let Some(pending) = pending {
        pending.validate()?;
        if pending.version == 1
            && pending.period == identity.period
            && pending.identity_hash == identity_hash
        {
            let transaction = rpc
                .call("get_transaction_info", json!([pending.txid]))
                .await?;
            let retry_height = pending
                .submitted_at_height
                .checked_add(u64::from(config.pending_retry_blocks))
                .ok_or(KeeperError::ArithmeticOverflow)?;
            if !transaction.is_null() {
                let transaction: TransactionInfo = serde_json::from_value(transaction)
                    .map_err(|_| KeeperError::MalformedRpcResponse)?;
                let maximum_fee = config
                    .market
                    .tx_fee_sats
                    .checked_add(config.market.maximum_listing_fee_sats)
                    .ok_or(KeeperError::ArithmeticOverflow)?;
                if transaction.fee_sats == 0
                    || transaction.fee_sats > maximum_fee
                    || transaction.confirmations.is_some() != transaction.txin.is_some()
                {
                    return Err(KeeperError::MalformedRpcResponse);
                }
                if transaction.confirmations.is_some() {
                    return Err(KeeperError::ConfirmedSubmissionMissingMarket {
                        txid: pending.txid.clone(),
                        period: pending.period,
                    });
                }
                return Ok(KeeperAction::Pending(pending.clone()));
            }
            if height < retry_height {
                return Ok(KeeperAction::Pending(pending.clone()));
            }
        }
    }

    let request = market_create_request(config, &identity);
    let response: MarketCreateResponse =
        serde_json::from_value(rpc.call("market_create", json!([request])).await?)?;
    let claimed = response
        .claimed_decisions
        .into_iter()
        .exactly_one()
        .ok_or(KeeperError::MalformedRpcResponse)?;
    if claimed.period_index != identity.period
        || !is_hex_len(&response.txid, 64)
        || !is_hex_len(&response.market_id, 12)
        || !standard_decision_id_matches_period(&claimed.id, identity.period)
    {
        return Err(KeeperError::MalformedRpcResponse);
    }

    Ok(KeeperAction::Submitted(PendingSubmissionV1 {
        version: 1,
        period: identity.period,
        identity_hash,
        txid: response.txid,
        market_id: response.market_id,
        decision_id: claimed.id,
        submitted_at_height: height,
    }))
}

async fn find_exact_market<R: TruthcoinRpc>(
    rpc: &R,
    expected: &CanonicalMarketIdentity,
) -> Result<Option<(String, String)>, KeeperError> {
    let summaries: Vec<MarketSummary> =
        serde_json::from_value(rpc.call("market_list", json!([])).await?)?;
    let mut exact = Vec::new();
    for summary in summaries {
        if summary.title != expected.market_title
            || summary.state != "Trading"
            || !is_hex_len(&summary.market_id, 12)
        {
            continue;
        }
        let summary_market_id = summary.market_id;
        let detail: Option<MarketDetail> =
            serde_json::from_value(rpc.call("market_get", json!([summary_market_id])).await?)?;
        let Some(detail) = detail else {
            continue;
        };
        if detail.market_id != summary_market_id
            || detail.title != expected.market_title
            || detail.description != expected.market_description
            || detail.state != "Trading"
            || detail.decision_ids.len() != 1
            || detail.outcomes.len() != 2
            || !market_parameters_match(&detail, expected)
        {
            continue;
        }
        let decision_id = detail.decision_ids[0].clone();
        if !standard_decision_id_matches_period(&decision_id, expected.period) {
            continue;
        }
        let decision = rpc.call("decision_get", json!([decision_id])).await?;
        if decision_matches(&decision, expected, &detail.decision_ids[0]) {
            exact.push((
                detail.created_at_height,
                detail.market_id,
                detail.decision_ids[0].clone(),
            ));
        }
    }
    exact.sort();
    Ok(exact
        .into_iter()
        .next()
        .map(|(_, market_id, decision_id)| (market_id, decision_id)))
}

fn market_parameters_match(detail: &MarketDetail, expected: &CanonicalMarketIdentity) -> bool {
    let expected_trading_fee = f64::from(expected.trading_fee_ppm) / f64::from(PPM_DENOMINATOR);
    if detail.trading_fee.to_bits() != expected_trading_fee.to_bits()
        || detail.tx_pow_hash_selector != expected.tx_pow_hash_selector
        || detail.tx_pow_ordering != expected.tx_pow_ordering
        || detail.tx_pow_difficulty != expected.tx_pow_difficulty
        || !detail.beta.is_finite()
        || detail.beta <= 0.0
    {
        return false;
    }
    let inferred_liquidity = detail.beta * libm::log(2.0);
    inferred_liquidity.is_finite()
        && inferred_liquidity >= 0.0
        && inferred_liquidity.round() >= expected.initial_liquidity_sats as f64
}

fn decision_matches(
    value: &Value,
    expected: &CanonicalMarketIdentity,
    expected_decision_id: &str,
) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(period) = object.get("period_index").and_then(Value::as_u64) else {
        return false;
    };
    if period != u64::from(expected.period)
        || object.get("decision_id_hex").and_then(Value::as_str) != Some(expected_decision_id)
        || !standard_decision_id_matches_period(expected_decision_id, expected.period)
    {
        return false;
    }
    let Some(content) = object.get("content") else {
        return false;
    };
    let decision = content
        .get("Decision")
        .or_else(|| content.get("decision"))
        .unwrap_or(content);
    if decision.get("is_standard").and_then(Value::as_bool) != Some(true)
        || decision.get("header").and_then(Value::as_str) != Some(expected.decision_header.as_str())
        || decision.get("description").and_then(Value::as_str)
            != Some(expected.decision_description.as_str())
    {
        return false;
    }
    let tags: Vec<String> = decision
        .get("tags")
        .cloned()
        .and_then(|tags| serde_json::from_value(tags).ok())
        .unwrap_or_default();
    if tags != expected.decision_tags {
        return false;
    }
    let Some(kind) = decision.get("decision_type") else {
        return false;
    };
    let scaled = kind
        .get("Scaled")
        .or_else(|| kind.get("scaled"))
        .unwrap_or(kind);
    float_field_bits(scaled, "min") == Some(expected.scalar_min_f64_bits)
        && float_field_bits(scaled, "max") == Some(expected.scalar_max_f64_bits)
        && float_field_bits(scaled, "increment") == Some(expected.scalar_increment_f64_bits)
}

fn float_field_bits(value: &Value, field: &str) -> Option<u64> {
    value.get(field)?.as_f64().map(f64::to_bits)
}

fn market_create_request(config: &KeeperConfigV1, identity: &CanonicalMarketIdentity) -> Value {
    json!({
        "title": identity.market_title,
        "description": identity.market_description,
        "dimensions": [{
            "type": "new",
            "period_index": identity.period,
            "decision_type": "scaled",
            "header": identity.decision_header,
            "description": identity.decision_description,
            "option_0_label": Value::Null,
            "option_1_label": Value::Null,
            "option_labels": Value::Null,
            "tags": identity.decision_tags,
            "min": f64::from_bits(identity.scalar_min_f64_bits),
            "max": f64::from_bits(identity.scalar_max_f64_bits),
            "increment": f64::from_bits(identity.scalar_increment_f64_bits),
        }],
        "beta": Value::Null,
        "trading_fee": f64::from(config.market.trading_fee_ppm) / f64::from(PPM_DENOMINATOR),
        "initial_liquidity": config.market.initial_liquidity_sats,
        "tx_pow_hash_selector": config.market.tx_pow_hash_selector,
        "tx_pow_ordering": config.market.tx_pow_ordering,
        "tx_pow_difficulty": config.market.tx_pow_difficulty,
        "tx_fee_sats": config.market.tx_fee_sats,
        "max_listing_fee_sats": config.market.maximum_listing_fee_sats,
    })
}

#[derive(Debug, Deserialize)]
struct DecisionStatus {
    is_testing_mode: bool,
    current_period: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionInfo {
    confirmations: Option<u32>,
    fee_sats: u64,
    txin: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct MarketSummary {
    market_id: String,
    title: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct MarketDetail {
    market_id: String,
    title: String,
    description: String,
    state: String,
    decision_ids: Vec<String>,
    outcomes: Vec<Value>,
    created_at_height: u32,
    beta: f64,
    trading_fee: f64,
    tx_pow_hash_selector: u8,
    tx_pow_ordering: u8,
    tx_pow_difficulty: u8,
}

#[derive(Debug, Deserialize)]
struct MarketCreateResponse {
    txid: String,
    market_id: String,
    claimed_decisions: Vec<ClaimedDecision>,
}

#[derive(Debug, Deserialize)]
struct ClaimedDecision {
    id: String,
    period_index: u32,
}

trait ExactlyOne<T> {
    fn exactly_one(self) -> Option<T>;
}

impl<T, I: Iterator<Item = T>> ExactlyOne<T> for I {
    fn exactly_one(mut self) -> Option<T> {
        let first = self.next()?;
        if self.next().is_none() {
            Some(first)
        } else {
            None
        }
    }
}

fn value_as_u64(value: Value) -> Result<u64, KeeperError> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .ok_or(KeeperError::MalformedRpcResponse)
}

fn is_hex_len(value: &str, characters: usize) -> bool {
    value.len() == characters && hex::decode(value).is_ok()
}

/// Truthcoin 0.17 `DecisionId` is exactly three bytes: bit 23 marks a
/// production-standard slot and the following seven bits encode period 0..127.
fn standard_decision_id_matches_period(value: &str, period: u32) -> bool {
    let Ok(bytes) = hex::decode(value) else {
        return false;
    };
    bytes.len() == 3
        && period <= 127
        && bytes[0] & 0x80 != 0
        && u32::from(bytes[0] & 0x7f) == period
}

/// Deterministic sorted-key JSON codec used to pin the live node schema.
pub fn canonical_json_sha256(value: &Value) -> Hash32 {
    let mut bytes = Vec::new();
    encode_canonical_json(value, &mut bytes);
    Sha256::digest(bytes).into()
}

fn encode_canonical_json(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => out.extend_from_slice(
            serde_json::to_string(string)
                .expect("string serialization is infallible")
                .as_bytes(),
        ),
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                encode_canonical_json(value, out);
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let sorted: BTreeMap<_, _> = values.iter().collect();
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                encode_canonical_json(&Value::String(key.clone()), out);
                out.push(b':');
                encode_canonical_json(value, out);
            }
            out.push(b'}');
        }
    }
}

#[derive(Debug, Error)]
pub enum KeeperError {
    #[error("unsupported keeper configuration/state version")]
    UnsupportedVersion,
    #[error("keeper is not pinned to the reviewed Truthcoin source")]
    UnpinnedSource,
    #[error("invalid keeper configuration")]
    InvalidConfiguration,
    #[error("Truthcoin testing-mode cadence is not valid for production")]
    TestingModeRejected,
    #[error("Truthcoin period {0} cannot be represented by the pinned source")]
    NoRepresentablePeriod(u32),
    #[error("live Truthcoin RPC schema mismatch: expected {expected}, observed {observed}")]
    SchemaMismatch { expected: String, observed: String },
    #[error("Truthcoin RPC rejected request with code {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("malformed Truthcoin RPC response")]
    MalformedRpcResponse,
    #[error(
        "confirmed Truthcoin submission {txid} for period {period} is missing its canonical market"
    )]
    ConfirmedSubmissionMissingMarket { txid: String, period: u32 },
    #[error("Truthcoin RPC response exceeded the hard size limit")]
    RpcResponseTooLarge,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("invalid keeper state path")]
    InvalidStatePath,
    #[error("invalid pending keeper state")]
    InvalidPendingState,
    #[error("keeper local file is not a stable regular file")]
    UnsafeLocalFile,
    #[error("keeper local file exceeded the hard size limit")]
    LocalFileTooLarge,
    #[error("another keeper already owns this state path")]
    StateAlreadyLocked,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl KeeperError {
    /// Only failures that can plausibly clear without changing frozen local
    /// configuration or operator action may keep continuous mode alive.
    pub fn is_retryable_availability_failure(&self) -> bool {
        match self {
            // Bitcoin/Truthcoin Core-compatible temporary node states.
            Self::Rpc {
                code: -28 | -10 | -9,
                ..
            } => true,
            Self::Http(error) => error.is_connect() || error.is_timeout() || error.is_request(),
            _ => false,
        }
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", bytes.len()))
        })
    }
}

mod hex20 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 20], D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("expected 20 bytes, got {}", bytes.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use axum::{extract::State, routing::post, Json, Router};

    use super::*;

    #[test]
    fn native_decision_id_must_be_standard_and_encode_the_reported_period() {
        assert!(standard_decision_id_matches_period("870001", 7));
        assert!(!standard_decision_id_matches_period("830001", 7));
        assert!(!standard_decision_id_matches_period("070001", 7));
        assert!(!standard_decision_id_matches_period("ff0001", 128));
    }

    #[derive(Debug)]
    struct MockRpc {
        schema: Value,
        calls: Mutex<Vec<(String, Value)>>,
        markets: Value,
        market_detail: Option<Value>,
        decision: Option<Value>,
        transaction: Value,
        testing: bool,
        current_period: u32,
    }

    impl MockRpc {
        fn empty(schema: Value) -> Self {
            Self {
                schema,
                calls: Mutex::new(Vec::new()),
                markets: json!([]),
                market_detail: None,
                decision: None,
                transaction: Value::Null,
                testing: false,
                current_period: 7,
            }
        }

        fn methods(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(method, _)| method.clone())
                .collect()
        }
    }

    impl TruthcoinRpc for MockRpc {
        async fn call(&self, method: &str, params: Value) -> Result<Value, KeeperError> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params.clone()));
            Ok(match method {
                "openapi_schema" => self.schema.clone(),
                "decision_status" => json!({
                    "is_testing_mode": self.testing,
                    "blocks_per_period": 0,
                    "current_period": self.current_period,
                    "current_period_name": "Q3 Y2010",
                }),
                "market_list" => self.markets.clone(),
                "market_get" => self.market_detail.clone().unwrap_or(Value::Null),
                "decision_get" => self.decision.clone().unwrap_or(Value::Null),
                "getblockcount" => json!(100),
                "get_transaction_info" => self.transaction.clone(),
                "market_create" => {
                    let period = params[0]["dimensions"][0]["period_index"]
                        .as_u64()
                        .and_then(|value| u8::try_from(value).ok())
                        .ok_or_else(|| KeeperError::Rpc {
                            code: -32602,
                            message: "missing period".into(),
                        })?;
                    json!({
                        "txid": "11".repeat(32),
                        "market_id": "22".repeat(6),
                        "claimed_decisions": [{
                            "id": format!("{:02x}0001", 0x80 | period),
                            "period_index": period,
                            "listing_fee_paid_sats": 5_000,
                        }],
                    })
                }
                _ => {
                    return Err(KeeperError::Rpc {
                        code: -32601,
                        message: format!("unexpected {method}"),
                    });
                }
            })
        }
    }

    fn schema() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title": "truthcoin", "version": "0.17.0"},
            "paths": {"market_create": {}, "decision_get": {}},
        })
    }

    fn config(schema: &Value) -> KeeperConfigV1 {
        let market = CanonicalMarketTemplateV1 {
            version: 1,
            market_title_template: "ECX BTC/USD period {period}".into(),
            market_description_template: "Canonical BTC/USD forecast for period {period}".into(),
            decision_header_template: "BTC/USD at period {period} close".into(),
            decision_description_template: "Truthcoin BTC/USD scalar for period {period}".into(),
            decision_tags: vec!["ecx-oracle-v1".into(), "btc-usd".into()],
            scalar_min_f64_bits: 10_000.0f64.to_bits(),
            scalar_max_f64_bits: 250_000.0f64.to_bits(),
            scalar_increment_f64_bits: 1.0f64.to_bits(),
            initial_liquidity_sats: 10_000_000,
            trading_fee_ppm: 10_000,
            tx_fee_sats: 1_000,
            maximum_listing_fee_sats: 1_000_000,
            tx_pow_hash_selector: 0,
            tx_pow_ordering: 0,
            tx_pow_difficulty: 0,
        };
        KeeperConfigV1 {
            version: KeeperConfigV1::VERSION,
            truthcoin_rpc_url: "http://127.0.0.1:6013".into(),
            expected_openapi_schema_sha256: canonical_json_sha256(schema),
            source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
            source_patch_manifest_sha256: TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
            btc_usd_template_hash: market.source_template_hash(),
            request_timeout_seconds: 10,
            pending_retry_blocks: 6,
            market_lookahead_periods: 0,
            market,
        }
    }

    fn exact_market() -> (Value, Value, Value) {
        let summaries = json!([{
            "market_id": "22".repeat(6),
            "title": "ECX BTC/USD period 7",
            "description": "Canonical BTC/USD forecast for period 7",
            "outcome_count": 2,
            "state": "Trading",
            "volume_sats": 0,
            "created_at_height": 90,
        }]);
        let detail = json!({
            "market_id": "22".repeat(6),
            "title": "ECX BTC/USD period 7",
            "description": "Canonical BTC/USD forecast for period 7",
            "outcomes": [{"name":"low"},{"name":"high"}],
            "state": "Trading",
            "decision_ids": ["870001"],
            "created_at_height": 90,
            "beta": 10_000_000.0 / libm::log(2.0),
            "trading_fee": 0.01,
            "tx_pow_hash_selector": 0,
            "tx_pow_ordering": 0,
            "tx_pow_difficulty": 0,
        });
        let decision = json!({
            "decision_id_hex": "870001",
            "period_index": 7,
            "decision_index": 1,
            "content": {"Decision": {
                "id": "33".repeat(32),
                "market_maker_pubkey_hash": "44".repeat(20),
                "is_standard": true,
                "decision_type": {"Scaled": {
                    "min": 10_000.0,
                    "max": 250_000.0,
                    "increment": 1.0
                }},
                "header": "BTC/USD at period 7 close",
                "description": "Truthcoin BTC/USD scalar for period 7",
                "tags": ["ecx-oracle-v1", "btc-usd"]
            }}
        });
        (summaries, detail, decision)
    }

    async fn http_fixture(
        State(schema): State<Arc<Value>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let result = match request.get("method").and_then(Value::as_str) {
            Some("openapi_schema") => (*schema).clone(),
            Some("decision_status") => json!({
                "is_testing_mode": false,
                "blocks_per_period": 0,
                "current_period": 7,
                "current_period_name": "Q3 Y2010",
            }),
            Some("market_list") => json!([]),
            Some("getblockcount") => json!(100),
            Some("market_create") => json!({
                "txid": "11".repeat(32),
                "market_id": "22".repeat(6),
                "claimed_decisions": [{
                    "id": "870001",
                    "period_index": 7,
                    "listing_fee_paid_sats": 5_000,
                }],
            }),
            method => {
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": format!("unknown {method:?}")},
                }));
            }
        };
        Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    #[tokio::test]
    async fn existing_exact_market_is_a_noop() {
        let schema = schema();
        let (markets, detail, decision) = exact_market();
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.markets = markets;
        rpc.market_detail = Some(detail);
        rpc.decision = Some(decision);
        let action = ensure_canonical_market(&config(&schema), &rpc, None)
            .await
            .unwrap();
        assert!(matches!(action, KeeperAction::Existing { period: 7, .. }));
        assert!(!rpc.methods().contains(&"market_create".to_string()));
    }

    #[tokio::test]
    async fn preflight_reports_missing_market_without_wallet_or_height_calls() {
        let schema = schema();
        let rpc = MockRpc::empty(schema.clone());
        let action = preflight_canonical_market(&config(&schema), &rpc)
            .await
            .unwrap();
        assert!(matches!(action, KeeperAction::Missing { period: 7, .. }));
        let methods = rpc.methods();
        assert!(!methods.contains(&"market_create".to_string()));
        assert!(!methods.contains(&"getblockcount".to_string()));
        assert!(!methods.contains(&"get_transaction_info".to_string()));
    }

    #[tokio::test]
    async fn lookahead_precreates_next_period_after_current_exists() {
        let schema = schema();
        let (markets, detail, decision) = exact_market();
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.markets = markets;
        rpc.market_detail = Some(detail);
        rpc.decision = Some(decision);
        let mut configuration = config(&schema);
        configuration.market_lookahead_periods = 1;

        let action = ensure_canonical_market(&configuration, &rpc, None)
            .await
            .unwrap();
        let KeeperAction::Submitted(submission) = action else {
            panic!("next-period market must be submitted")
        };
        assert_eq!(submission.period, 8);
        assert_eq!(submission.decision_id, "880001");
        let calls = rpc.calls.lock().unwrap();
        let (_, params) = calls
            .iter()
            .find(|(method, _)| method == "market_create")
            .unwrap();
        assert_eq!(params[0]["dimensions"][0]["period_index"], 8);
        assert_eq!(params[0]["title"], "ECX BTC/USD period 8");
    }

    #[tokio::test]
    async fn final_period_caps_lookahead_without_overflow() {
        let schema = schema();
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.current_period = 127;
        let mut configuration = config(&schema);
        configuration.market_lookahead_periods = 4;
        let action = ensure_canonical_market(&configuration, &rpc, None)
            .await
            .unwrap();
        let KeeperAction::Submitted(submission) = action else {
            panic!("final representable market must be submitted")
        };
        assert_eq!(submission.period, 127);
        assert_eq!(submission.decision_id, "ff0001");
    }

    #[tokio::test]
    async fn lookalike_with_wrong_consensus_parameters_does_not_suppress_creation() {
        let schema = schema();
        let (markets, mut detail, decision) = exact_market();
        detail["trading_fee"] = json!(0.02);
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.markets = markets;
        rpc.market_detail = Some(detail);
        rpc.decision = Some(decision);
        let action = ensure_canonical_market(&config(&schema), &rpc, None)
            .await
            .unwrap();
        assert!(matches!(action, KeeperAction::Submitted(_)));
        assert!(rpc.methods().contains(&"market_create".to_string()));
    }

    #[tokio::test]
    async fn missing_market_submits_static_metadata_without_price_authority() {
        let schema = schema();
        let rpc = MockRpc::empty(schema.clone());
        let action = ensure_canonical_market(&config(&schema), &rpc, None)
            .await
            .unwrap();
        assert!(matches!(action, KeeperAction::Submitted(_)));
        let calls = rpc.calls.lock().unwrap();
        let (_, params) = calls
            .iter()
            .find(|(method, _)| method == "market_create")
            .unwrap();
        let encoded = params.to_string();
        for forbidden in [
            "probability",
            "current_price",
            "yes_probability",
            "resolution",
            "vote_value",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert!(encoded.contains("initial_liquidity"));
        assert!(encoded.contains("decision_type"));
    }

    #[tokio::test]
    async fn real_http_json_rpc_transport_runs_a_complete_keeper_cycle() {
        let schema = schema();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(http_fixture))
            .with_state(Arc::new(schema.clone()));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut configuration = config(&schema);
        configuration.truthcoin_rpc_url = format!("http://{address}");
        let rpc = HttpTruthcoinRpc::new(
            configuration.truthcoin_rpc_url.clone(),
            Duration::from_secs(5),
        )
        .unwrap();
        let action = ensure_canonical_market(&configuration, &rpc, None)
            .await
            .unwrap();
        assert!(matches!(action, KeeperAction::Submitted(_)));
        server.abort();
    }

    #[tokio::test]
    async fn pending_transaction_suppresses_duplicate_creation() {
        let schema = schema();
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.transaction = json!({"confirmations": null, "fee_sats": 1_000, "txin": null});
        let identity = config(&schema).market.render(7).unwrap();
        let pending = PendingSubmissionV1 {
            version: 1,
            period: 7,
            identity_hash: identity.digest(),
            txid: "11".repeat(32),
            market_id: "22".repeat(6),
            decision_id: "870001".into(),
            submitted_at_height: 99,
        };
        let action = ensure_canonical_market(&config(&schema), &rpc, Some(&pending))
            .await
            .unwrap();
        assert_eq!(action, KeeperAction::Pending(pending));
        assert!(!rpc.methods().contains(&"market_create".to_string()));
    }

    #[tokio::test]
    async fn confirmed_submission_without_canonical_market_fails_closed() {
        let schema = schema();
        let mut rpc = MockRpc::empty(schema.clone());
        rpc.transaction = json!({
            "confirmations": 0,
            "fee_sats": 6_000,
            "txin": {"block_hash": "33".repeat(32), "transaction_index": 1}
        });
        let identity = config(&schema).market.render(7).unwrap();
        let pending = PendingSubmissionV1 {
            version: 1,
            period: 7,
            identity_hash: identity.digest(),
            txid: "11".repeat(32),
            market_id: "22".repeat(6),
            decision_id: "870001".into(),
            submitted_at_height: 90,
        };
        assert!(matches!(
            ensure_canonical_market(&config(&schema), &rpc, Some(&pending)).await,
            Err(KeeperError::ConfirmedSubmissionMissingMarket { period: 7, .. })
        ));
        assert!(!rpc.methods().contains(&"market_create".to_string()));
    }

    #[tokio::test]
    async fn malformed_or_over_budget_pending_transaction_fails_closed() {
        let schema = schema();
        let identity = config(&schema).market.render(7).unwrap();
        let pending = PendingSubmissionV1 {
            version: 1,
            period: 7,
            identity_hash: identity.digest(),
            txid: "11".repeat(32),
            market_id: "22".repeat(6),
            decision_id: "870001".into(),
            submitted_at_height: 99,
        };
        for transaction in [
            json!({"confirmations": 1, "fee_sats": 1_000, "txin": null}),
            json!({"confirmations": null, "fee_sats": 1_001_001, "txin": null}),
            json!({"confirmations": null, "fee_sats": 1_000, "txin": null, "extra": true}),
        ] {
            let mut rpc = MockRpc::empty(schema.clone());
            rpc.transaction = transaction;
            assert!(matches!(
                ensure_canonical_market(&config(&schema), &rpc, Some(&pending)).await,
                Err(KeeperError::MalformedRpcResponse)
            ));
            assert!(!rpc.methods().contains(&"market_create".to_string()));
        }
    }

    #[tokio::test]
    async fn absent_submission_retries_only_after_the_frozen_block_delay() {
        let schema = schema();
        let identity = config(&schema).market.render(7).unwrap();
        let mut pending = PendingSubmissionV1 {
            version: 1,
            period: 7,
            identity_hash: identity.digest(),
            txid: "11".repeat(32),
            market_id: "22".repeat(6),
            decision_id: "870001".into(),
            submitted_at_height: 99,
        };
        let rpc = MockRpc::empty(schema.clone());
        assert_eq!(
            ensure_canonical_market(&config(&schema), &rpc, Some(&pending))
                .await
                .unwrap(),
            KeeperAction::Pending(pending.clone())
        );
        assert!(!rpc.methods().contains(&"market_create".to_string()));

        pending.submitted_at_height = 94;
        let rpc = MockRpc::empty(schema.clone());
        assert!(matches!(
            ensure_canonical_market(&config(&schema), &rpc, Some(&pending))
                .await
                .unwrap(),
            KeeperAction::Submitted(_)
        ));
        assert!(rpc.methods().contains(&"market_create".to_string()));
    }

    #[tokio::test]
    async fn schema_and_testing_mode_fail_before_writes() {
        let schema = schema();
        let rpc = MockRpc::empty(json!({"different": true}));
        assert!(matches!(
            ensure_canonical_market(&config(&schema), &rpc, None).await,
            Err(KeeperError::SchemaMismatch { .. })
        ));
        assert!(!rpc.methods().contains(&"market_create".to_string()));

        let mut rpc = MockRpc::empty(schema.clone());
        rpc.testing = true;
        assert!(matches!(
            ensure_canonical_market(&config(&schema), &rpc, None).await,
            Err(KeeperError::TestingModeRejected)
        ));
        assert!(!rpc.methods().contains(&"market_create".to_string()));
    }

    #[test]
    fn schema_hash_ignores_object_insertion_order_but_not_content() {
        let left = json!({"b": 2, "a": {"y": 1, "x": 0}});
        let right = json!({"a": {"x": 0, "y": 1}, "b": 2});
        assert_eq!(canonical_json_sha256(&left), canonical_json_sha256(&right));
        assert_ne!(
            canonical_json_sha256(&left),
            canonical_json_sha256(&json!({"a": {"x": 1, "y": 1}, "b": 2}))
        );
    }

    #[test]
    fn transport_and_json_rpc_envelope_fail_closed() {
        let mut configuration = config(&schema());
        configuration.source_patch_manifest_sha256[0] ^= 1;
        assert!(matches!(
            configuration.validate(),
            Err(KeeperError::UnpinnedSource)
        ));

        let mut configuration = config(&schema());
        configuration.truthcoin_rpc_url = "http://truthcoin.example:6013".into();
        assert!(matches!(
            configuration.validate(),
            Err(KeeperError::InvalidConfiguration)
        ));

        let mut configuration = config(&schema());
        configuration.market.market_title_template = "different {period}".into();
        assert!(matches!(
            configuration.validate(),
            Err(KeeperError::InvalidConfiguration)
        ));

        assert!(matches!(
            parse_json_rpc_response(json!({"jsonrpc":"2.0", "id": 8, "result": {}}), 7),
            Err(KeeperError::MalformedRpcResponse)
        ));
        assert_eq!(
            parse_json_rpc_response(json!({"jsonrpc":"2.0", "id": 7, "result": 42}), 7).unwrap(),
            json!(42)
        );
        let warming = parse_json_rpc_response(
            json!({"jsonrpc":"2.0", "id":7, "error":{"code":-28,"message":"warming up"}}),
            7,
        )
        .unwrap_err();
        assert!(matches!(&warming, KeeperError::Rpc { code: -28, .. }));
        assert!(warming.is_retryable_availability_failure());
        let wallet = parse_json_rpc_response(
            json!({"jsonrpc":"2.0", "id":7, "error":{"code":-6,"message":"insufficient funds"}}),
            7,
        )
        .unwrap_err();
        assert!(matches!(&wallet, KeeperError::Rpc { code: -6, .. }));
        assert!(!wallet.is_retryable_availability_failure());
        for malformed in [
            json!({"jsonrpc":"2.0", "id":7, "error":"failed"}),
            json!({"jsonrpc":"2.0", "id":7, "error":{"message":"failed"}}),
            json!({"jsonrpc":"2.0", "id":7, "error":{"code":-1,"message":""}}),
            json!({"jsonrpc":"2.0", "id":7, "error":{"code":-1,"message":"failed","extra":1}}),
        ] {
            assert!(matches!(
                parse_json_rpc_response(malformed, 7),
                Err(KeeperError::MalformedRpcResponse)
            ));
        }
    }

    #[test]
    fn durable_pending_state_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keeper-state.json");
        let state = KeeperStateV1 {
            version: 1,
            pending: Some(PendingSubmissionV1 {
                version: 1,
                period: 7,
                identity_hash: [7; 32],
                txid: "11".repeat(32),
                market_id: "22".repeat(6),
                decision_id: "870001".into(),
                submitted_at_height: 100,
            }),
        };
        state.save_atomic(&path).unwrap();
        assert_eq!(KeeperStateV1::load(&path).unwrap(), state);

        let mut updated = state.clone();
        updated.pending.as_mut().unwrap().submitted_at_height += 1;
        updated.save_atomic(&path).unwrap();
        assert_eq!(KeeperStateV1::load(&path).unwrap(), updated);

        let mut invalid = updated;
        invalid.pending.as_mut().unwrap().txid = "not-a-txid".into();
        assert!(matches!(
            invalid.pending.unwrap().validate(),
            Err(KeeperError::InvalidPendingState)
        ));
    }

    #[test]
    fn fresh_state_survives_first_save_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keeper-state.json");
        let state = KeeperStateV1::load(&path).unwrap();
        assert_eq!(state.version, KeeperStateV1::VERSION);
        assert_eq!(state.pending, None);

        state.save_atomic(&path).unwrap();
        assert_eq!(KeeperStateV1::load(&path).unwrap(), state);
    }

    #[test]
    fn local_keeper_files_reject_unknown_fields_and_oversized_input() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("keeper.json");
        let schema = schema();
        let mut encoded = serde_json::to_value(config(&schema)).unwrap();
        encoded["unexpected"] = json!(true);
        std::fs::write(&config_path, serde_json::to_vec(&encoded).unwrap()).unwrap();
        assert!(matches!(
            load_keeper_config(&config_path),
            Err(KeeperError::Json(_))
        ));

        let state_path = directory.path().join("state.json");
        std::fs::write(
            &state_path,
            vec![b' '; (MAX_KEEPER_STATE_BYTES + 1) as usize],
        )
        .unwrap();
        assert!(matches!(
            KeeperStateV1::load(&state_path),
            Err(KeeperError::LocalFileTooLarge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn local_keeper_files_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        std::fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("link.json");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            KeeperStateV1::load(&link),
            Err(KeeperError::UnsafeLocalFile)
        ));
        assert!(matches!(
            KeeperStateV1::default().save_atomic(&link),
            Err(KeeperError::UnsafeLocalFile)
        ));
    }

    #[test]
    fn keeper_state_lock_is_exclusive_and_released_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("keeper-state.json");
        let first = KeeperStateLock::acquire(&state_path).unwrap();
        assert!(matches!(
            KeeperStateLock::acquire(&state_path),
            Err(KeeperError::StateAlreadyLocked)
        ));
        drop(first);
        KeeperStateLock::acquire(&state_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock_path = directory.path().join("keeper-state.json.lock");
            assert_eq!(
                std::fs::metadata(lock_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
