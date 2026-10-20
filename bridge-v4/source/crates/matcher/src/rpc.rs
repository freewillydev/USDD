//! Fail-closed synchronization with the patched Elements node.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use ecx_protocol_core::Hash32;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    BondInboxSnapshotV2, CapitalMode, CapitalSnapshotV2, MatcherConsensusContextV1,
    MatcherExecutionSnapshotV2, OracleModeV2, OracleSnapshotV2, SuccessorMatcherConsensusContextV2,
};

const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RPC_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024;
const RPC_CONTEXT_REQUEST_ID: &str = "ecx-matcher-context";
const RPC_ANCESTOR_REQUEST_ID: &str = "ecx-matcher-ancestor";

#[derive(Clone)]
pub struct ElementsRpcClient {
    client: Client,
    url: Url,
    username: Option<String>,
    password: Option<String>,
    v2_identity_pins: Option<V2IdentityPins>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V2IdentityPins {
    pub configuration_hash: Hash32,
    pub bond_asset_id: Hash32,
    pub bond_deployment_commitment: Hash32,
    pub transition_program_id: Hash32,
    pub transition_cmr: Hash32,
}

impl V2IdentityPins {
    pub fn validate(self) -> Result<Self> {
        if [
            self.configuration_hash,
            self.bond_asset_id,
            self.bond_deployment_commitment,
            self.transition_program_id,
            self.transition_cmr,
        ]
        .contains(&[0; 32])
        {
            bail!("v2 identity pins must all be nonzero");
        }
        Ok(self)
    }

    fn matches(self, capital: &CapitalSnapshotV2) -> bool {
        capital.configuration_hash == self.configuration_hash
            && capital.bond_asset_id == self.bond_asset_id
            && capital.bond_deployment_commitment == self.bond_deployment_commitment
            && capital.transition_program_id == self.transition_program_id
            && capital.transition_cmr == self.transition_cmr
    }

    fn matches_successor(self, context: &SuccessorElementsConsensusContextV2) -> bool {
        context.bond_action_configuration_hash == self.configuration_hash
            && context.bond_asset_id == self.bond_asset_id
            && context.bond_deployment_commitment == self.bond_deployment_commitment
            && context.transition_program_id == self.transition_program_id
            && context.transition_cmr == self.transition_cmr
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsConsensusContextV1 {
    pub sidechain_height: u64,
    pub sidechain_block_hash: Hash32,
    pub exchange_state_root: Hash32,
    pub forced_inbox_head_root: Hash32,
    pub forced_inbox_entry_count: u64,
    pub deposit_inbox_head_root: Hash32,
    pub deposit_inbox_entry_count: u64,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub parent_block_hash: Hash32,
    pub source_parent_height: u64,
}

impl ElementsConsensusContextV1 {
    pub fn matcher_context(&self) -> Result<MatcherConsensusContextV1> {
        MatcherConsensusContextV1 {
            sidechain_height: self.sidechain_height,
            parent_height: self.parent_height,
            parent_mtp: self.parent_mtp,
            forced_inbox_cursor: self.forced_inbox_entry_count,
        }
        .validate()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.matcher_context()?;
        if self.source_parent_height == 0
            || self.source_parent_height != self.parent_height
            || self.sidechain_block_hash == [0; 32]
            || self.exchange_state_root == [0; 32]
            || self.forced_inbox_head_root == [0; 32]
            || self.deposit_inbox_head_root == [0; 32]
            || self.parent_block_hash == [0; 32]
        {
            bail!("Elements returned an unavailable ECX consensus context");
        }
        Ok(())
    }
}

/// Versioned successor to the frozen V1 node/snapshot codec. V2 carries the
/// independently processed inbox cursors and the root-bound bond capital
/// projection. It is never deserialized through `ElementsConsensusContextV1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsConsensusContextV2 {
    pub sidechain_height: u64,
    pub sidechain_block_hash: Hash32,
    pub exchange_state_root: Hash32,
    pub forced_inbox_head_root: Hash32,
    pub forced_inbox_entry_count: u64,
    pub forced_inbox_processed_cursor: u64,
    pub deposit_inbox_head_root: Hash32,
    pub deposit_inbox_entry_count: u64,
    pub deposit_inbox_processed_cursor: u64,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub parent_block_hash: Hash32,
    pub source_parent_height: u64,
    // Do not skip this field: the same versioned type is stored in bincode
    // matcher snapshots, where omitting a struct field is not self-describing
    // and makes an otherwise valid snapshot undecodable.
    #[serde(default)]
    pub capital_snapshot: Option<CapitalSnapshotV2>,
}

impl From<ElementsConsensusContextV1> for ElementsConsensusContextV2 {
    fn from(value: ElementsConsensusContextV1) -> Self {
        Self {
            sidechain_height: value.sidechain_height,
            sidechain_block_hash: value.sidechain_block_hash,
            exchange_state_root: value.exchange_state_root,
            forced_inbox_head_root: value.forced_inbox_head_root,
            forced_inbox_entry_count: value.forced_inbox_entry_count,
            forced_inbox_processed_cursor: value.forced_inbox_entry_count,
            deposit_inbox_head_root: value.deposit_inbox_head_root,
            deposit_inbox_entry_count: value.deposit_inbox_entry_count,
            deposit_inbox_processed_cursor: value.deposit_inbox_entry_count,
            parent_height: value.parent_height,
            parent_mtp: value.parent_mtp,
            parent_block_hash: value.parent_block_hash,
            source_parent_height: value.source_parent_height,
            capital_snapshot: None,
        }
    }
}

impl ElementsConsensusContextV2 {
    pub fn matcher_context(&self) -> Result<MatcherConsensusContextV1> {
        MatcherConsensusContextV1 {
            sidechain_height: self.sidechain_height,
            parent_height: self.parent_height,
            parent_mtp: self.parent_mtp,
            forced_inbox_cursor: self.forced_inbox_processed_cursor,
        }
        .validate()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.matcher_context()?;
        if self.source_parent_height == 0
            || self.source_parent_height != self.parent_height
            || self.sidechain_block_hash == [0; 32]
            || self.exchange_state_root == [0; 32]
            || self.forced_inbox_head_root == [0; 32]
            || self.deposit_inbox_head_root == [0; 32]
            || self.parent_block_hash == [0; 32]
            || self.forced_inbox_processed_cursor > self.forced_inbox_entry_count
            || self.deposit_inbox_processed_cursor > self.deposit_inbox_entry_count
        {
            bail!("Elements returned an unavailable ECX v2 consensus context");
        }
        if let Some(capital) = &self.capital_snapshot {
            capital.validate_for_exchange_root(self.exchange_state_root)?;
            if capital.oracle.valid_through_parent_mtp < self.parent_mtp
                || capital.last_transition_sidechain_height > self.sidechain_height
            {
                bail!("Elements returned stale or future v2 capital state");
            }
        }
        Ok(())
    }

    pub(crate) fn validate_successor_of(&self, previous: &Self) -> Result<()> {
        self.validate()?;
        if self.sidechain_height < previous.sidechain_height
            || self.parent_height < previous.parent_height
            || self.parent_mtp < previous.parent_mtp
            || self.source_parent_height < previous.source_parent_height
            || self.forced_inbox_entry_count < previous.forced_inbox_entry_count
            || self.forced_inbox_processed_cursor < previous.forced_inbox_processed_cursor
            || self.deposit_inbox_entry_count < previous.deposit_inbox_entry_count
            || self.deposit_inbox_processed_cursor < previous.deposit_inbox_processed_cursor
        {
            bail!("Elements v2 consensus context regressed");
        }
        if self.sidechain_height == previous.sidechain_height {
            if self != previous {
                bail!("Elements v2 consensus context changed at the same sidechain height");
            }
            return Ok(());
        }
        if previous.capital_snapshot.is_some() && self.capital_snapshot.is_none() {
            bail!("Elements stopped reporting previously authenticated v2 capital state");
        }
        if let (Some(previous), Some(current)) =
            (&previous.capital_snapshot, &self.capital_snapshot)
        {
            if current.funding_epoch < previous.funding_epoch
                || current.matcher_execution.sequence < previous.matcher_execution.sequence
                || current.bond_inbox.entry_count < previous.bond_inbox.entry_count
                || current.bond_inbox.processed_cursor < previous.bond_inbox.processed_cursor
                || current.bond_inbox.outcome_count < previous.bond_inbox.outcome_count
                || current.bond_inbox.node_verified_source_entry_count
                    < previous.bond_inbox.node_verified_source_entry_count
                || current.last_transition_sidechain_height
                    < previous.last_transition_sidechain_height
            {
                bail!("Elements v2 capital projection regressed");
            }
            validate_inbox_successor(
                "bond",
                previous.bond_inbox.entry_count,
                previous.bond_inbox.head_root,
                current.bond_inbox.entry_count,
                current.bond_inbox.head_root,
            )?;
            validate_inbox_successor(
                "node-verified bond source",
                previous.bond_inbox.node_verified_source_entry_count,
                previous.bond_inbox.node_verified_source_head_root,
                current.bond_inbox.node_verified_source_entry_count,
                current.bond_inbox.node_verified_source_head_root,
            )?;
        }
        if self.sidechain_block_hash == previous.sidechain_block_hash {
            bail!("Elements sidechain height advanced without a new block hash");
        }
        if self.parent_height == previous.parent_height {
            if self.parent_block_hash != previous.parent_block_hash
                || self.parent_mtp != previous.parent_mtp
            {
                bail!("Elements BMM parent changed at the same parent height");
            }
        } else if self.parent_block_hash == previous.parent_block_hash {
            bail!("Elements BMM parent height advanced without a new block hash");
        }
        validate_inbox_successor(
            "forced",
            previous.forced_inbox_entry_count,
            previous.forced_inbox_head_root,
            self.forced_inbox_entry_count,
            self.forced_inbox_head_root,
        )?;
        validate_inbox_successor(
            "deposit",
            previous.deposit_inbox_entry_count,
            previous.deposit_inbox_head_root,
            self.deposit_inbox_entry_count,
            self.deposit_inbox_head_root,
        )?;
        Ok(())
    }
}

/// Exact node-authenticated context for the lifetime-safe incremental
/// successor. This is deliberately not an extension of
/// `ElementsConsensusContextV2`: the successor counters are `u128` and its
/// configuration identity is distinct from the frozen bond-action
/// configuration. Keeping a separate type prevents bincode snapshots or V1/V2
/// HTTP callers from silently narrowing a live successor cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorElementsConsensusContextV2 {
    pub sidechain_height: u64,
    pub sidechain_block_hash: Hash32,
    pub exchange_state_root: Hash32,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub parent_block_hash: Hash32,
    pub source_parent_height: u64,
    pub forced_inbox_processed_cursor: u128,
    pub successor_configuration_hash: Hash32,
    pub bond_action_configuration_hash: Hash32,
    pub bond_asset_id: Hash32,
    pub bond_deployment_commitment: Hash32,
    pub transition_program_id: Hash32,
    pub transition_cmr: Hash32,
    pub capital_mode: CapitalMode,
    pub matcher_execution_previous_sequence: u128,
    pub matcher_execution_sequence: u128,
    pub last_transition_sidechain_height: u64,
}

impl SuccessorElementsConsensusContextV2 {
    pub fn matcher_context(&self) -> Result<SuccessorMatcherConsensusContextV2> {
        SuccessorMatcherConsensusContextV2 {
            sidechain_height: self.sidechain_height,
            parent_height: self.parent_height,
            parent_mtp: self.parent_mtp,
            forced_inbox_cursor: self.forced_inbox_processed_cursor,
        }
        .validate()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.matcher_context()?;
        if self.sidechain_block_hash == [0; 32]
            || self.exchange_state_root == [0; 32]
            || self.parent_block_hash == [0; 32]
            || self.source_parent_height != self.parent_height
            || self.successor_configuration_hash == [0; 32]
            || self.bond_action_configuration_hash == [0; 32]
            || self.successor_configuration_hash == self.bond_action_configuration_hash
            || self.bond_asset_id == [0; 32]
            || self.bond_deployment_commitment == [0; 32]
            || self.transition_program_id == [0; 32]
            || self.transition_cmr == [0; 32]
            || self.matcher_execution_previous_sequence > self.matcher_execution_sequence
            || self.last_transition_sidechain_height > self.sidechain_height
        {
            bail!("Elements returned an invalid incremental-successor context");
        }
        Ok(())
    }

    pub(crate) fn validate_successor_of(&self, previous: &Self) -> Result<()> {
        self.validate()?;
        if self.sidechain_height < previous.sidechain_height
            || self.parent_height < previous.parent_height
            || self.parent_mtp < previous.parent_mtp
            || self.source_parent_height < previous.source_parent_height
            || self.forced_inbox_processed_cursor < previous.forced_inbox_processed_cursor
            || self.matcher_execution_sequence < previous.matcher_execution_sequence
            || self.last_transition_sidechain_height < previous.last_transition_sidechain_height
            || self.successor_configuration_hash != previous.successor_configuration_hash
            || self.bond_action_configuration_hash != previous.bond_action_configuration_hash
            || self.bond_asset_id != previous.bond_asset_id
            || self.bond_deployment_commitment != previous.bond_deployment_commitment
            || self.transition_program_id != previous.transition_program_id
            || self.transition_cmr != previous.transition_cmr
        {
            bail!("Elements incremental-successor context regressed or changed identity");
        }
        if self.sidechain_height == previous.sidechain_height {
            if self != previous {
                bail!("Elements incremental-successor context changed at one height");
            }
            return Ok(());
        }
        if self.sidechain_block_hash == previous.sidechain_block_hash {
            bail!("Elements successor height advanced without a new block hash");
        }
        if self.parent_height == previous.parent_height {
            if self.parent_block_hash != previous.parent_block_hash
                || self.parent_mtp != previous.parent_mtp
            {
                bail!("Elements successor BMM parent changed at one parent height");
            }
        } else if self.parent_block_hash == previous.parent_block_hash {
            bail!("Elements successor parent height advanced without a new block hash");
        }
        Ok(())
    }
}

fn validate_inbox_successor(
    name: &str,
    previous_count: u64,
    previous_root: Hash32,
    current_count: u64,
    current_root: Hash32,
) -> Result<()> {
    if (current_count == previous_count) != (current_root == previous_root) {
        bail!("Elements {name} inbox count and root changed inconsistently");
    }
    Ok(())
}

impl ElementsRpcClient {
    pub fn new(endpoint: &str, username: Option<String>, password: Option<String>) -> Result<Self> {
        let url = Url::parse(endpoint).context("invalid Elements RPC URL")?;
        if url.username() != "" || url.password().is_some() {
            bail!("Elements RPC credentials must not be embedded in the URL");
        }
        if url.fragment().is_some() {
            bail!("Elements RPC URL must not contain a fragment");
        }
        let local_plaintext = url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
        if url.scheme() != "https" && !local_plaintext {
            bail!("Elements RPC must use HTTPS unless it is loopback-only");
        }
        if username.is_some() != password.is_some() {
            bail!("Elements RPC username and password must be supplied together");
        }
        let client = Client::builder()
            .connect_timeout(RPC_CONNECT_TIMEOUT)
            .timeout(RPC_TOTAL_TIMEOUT)
            .https_only(!local_plaintext)
            .build()
            .context("building Elements RPC client")?;
        Ok(Self {
            client,
            url,
            username,
            password,
            v2_identity_pins: None,
        })
    }

    /// Install mandatory deployment pins for every startup/refresh/durable
    /// context read. This returns a new client so callers cannot accidentally
    /// mutate the expected identity while requests are in flight.
    pub fn with_v2_identity_pins(mut self, pins: V2IdentityPins) -> Result<Self> {
        self.v2_identity_pins = Some(pins.validate()?);
        Ok(self)
    }

    pub async fn consensus_context(&self) -> Result<ElementsConsensusContextV2> {
        let result: RpcContext = self
            .rpc_call(RPC_CONTEXT_REQUEST_ID, "getecxconsensuscontext", [(); 0])
            .await
            .context("requesting authenticated ECX consensus context")?;
        let context: ElementsConsensusContextV2 = result.try_into()?;
        if let Some(pins) = self.v2_identity_pins {
            let capital = context
                .capital_snapshot
                .as_ref()
                .context("Elements omitted the mandatory pinned v2 capital identity")?;
            if !pins.matches(capital) {
                bail!("Elements v2 capital identity differs from the frozen matcher pins");
            }
        }
        Ok(context)
    }

    /// Read the disjoint incremental-successor projection. The finite decoder
    /// intentionally rejects this profile, and this method intentionally
    /// rejects finite-v18, so callers can never infer a wire version from
    /// counter magnitude or silently reinterpret an old snapshot.
    pub async fn successor_consensus_context(&self) -> Result<SuccessorElementsConsensusContextV2> {
        let result: RpcContext = self
            .rpc_call(
                "ecx-successor-matcher-context",
                "getecxconsensuscontext",
                [(); 0],
            )
            .await
            .context("requesting authenticated incremental-successor context")?;
        let context: SuccessorElementsConsensusContextV2 = result.try_into()?;
        if let Some(pins) = self.v2_identity_pins
            && !pins.matches_successor(&context)
        {
            bail!("Elements successor identity differs from the frozen matcher pins");
        }
        Ok(context)
    }

    /// Reads a successor and proves that the previously accepted sidechain
    /// block is still in the node's active chain. Re-reading the atomic ECX
    /// snapshot after `getblockhash` prevents a moving-tip race from combining
    /// observations from two different active histories.
    pub async fn consensus_context_after(
        &self,
        previous: &ElementsConsensusContextV2,
    ) -> Result<ElementsConsensusContextV2> {
        previous.validate()?;
        let current = self.consensus_context().await?;
        current.validate_successor_of(previous)?;
        if current.sidechain_height == previous.sidechain_height {
            return Ok(current);
        }

        let active_ancestor: String = self
            .rpc_call(
                RPC_ANCESTOR_REQUEST_ID,
                "getblockhash",
                [previous.sidechain_height],
            )
            .await
            .context("checking the previous matcher tip against the active Elements chain")?;
        if decode_hash(&active_ancestor, "active ancestor")? != previous.sidechain_block_hash {
            bail!("previous matcher tip is no longer in the active Elements chain");
        }
        let stable = self.consensus_context().await?;
        if stable != current {
            bail!("Elements consensus context changed during the active-chain ancestry check");
        }
        Ok(current)
    }

    pub async fn successor_consensus_context_after(
        &self,
        previous: &SuccessorElementsConsensusContextV2,
    ) -> Result<SuccessorElementsConsensusContextV2> {
        previous.validate()?;
        let current = self.successor_consensus_context().await?;
        current.validate_successor_of(previous)?;
        if current.sidechain_height == previous.sidechain_height {
            return Ok(current);
        }
        let active_ancestor: String = self
            .rpc_call(
                "ecx-successor-matcher-ancestor",
                "getblockhash",
                [previous.sidechain_height],
            )
            .await
            .context("checking the prior successor matcher tip against the active chain")?;
        if decode_hash(&active_ancestor, "active successor ancestor")?
            != previous.sidechain_block_hash
        {
            bail!("prior successor matcher tip is no longer active");
        }
        let stable = self.successor_consensus_context().await?;
        if stable != current {
            bail!("Elements successor context changed during ancestry verification");
        }
        Ok(current)
    }

    async fn rpc_call<P, T>(&self, id: &str, method: &'static str, params: P) -> Result<T>
    where
        P: Serialize,
        T: DeserializeOwned,
    {
        let payload = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let mut request = self.client.post(self.url.clone()).json(&payload);
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request = request.basic_auth(username, Some(password));
        }
        let mut response = request
            .send()
            .await
            .with_context(|| format!("requesting Elements RPC method {method}"))?
            .error_for_status()
            .context("Elements RPC returned an HTTP error")?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            bail!("Elements RPC response exceeds the {MAX_RPC_RESPONSE_BYTES}-byte bound");
        }
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(MAX_RPC_RESPONSE_BYTES),
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading Elements RPC response")?
        {
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .context("Elements RPC response length overflow")?;
            if next_len > MAX_RPC_RESPONSE_BYTES {
                bail!("Elements RPC response exceeds the {MAX_RPC_RESPONSE_BYTES}-byte bound");
            }
            body.extend_from_slice(&chunk);
        }
        let response: RpcResponse<T> =
            serde_json::from_slice(&body).context("decoding Elements JSON-RPC response")?;
        if response
            .jsonrpc
            .as_deref()
            .is_some_and(|version| version != "2.0")
            || response.id != id
        {
            bail!("Elements RPC returned a mismatched JSON-RPC envelope");
        }
        let result = match (response.result, response.error) {
            (Some(_), Some(_)) => bail!("Elements RPC returned both a result and an error"),
            (Some(result), None) => result,
            (None, Some(error)) => bail!("Elements RPC {}: {}", error.code, error.message),
            (None, None) => bail!("Elements RPC omitted the requested result"),
        };
        Ok(result)
    }
}

#[derive(Serialize)]
struct RpcRequest<'a, P> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcResponse<T> {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: String,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcContext {
    sidechainheight: u64,
    sidechainblockhash: String,
    exchangestateroot: String,
    forcedinbox: RpcInbox,
    depositinbox: RpcInbox,
    bmm: RpcBmm,
    sourceparentheight: u64,
    sourcebacklogoldestparentheight: u64,
    #[serde(default)]
    capital: Option<RpcCapital>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcCapital {
    version: u8,
    proofprofile: RpcProofProfile,
    exchangestateroot: String,
    configurationhash: String,
    bondactionconfigurationhash: String,
    bondassetid: String,
    bonddeploymentcommitment: String,
    transitionprogramid: String,
    transitioncmr: String,
    covenantstatehash: String,
    bondstateroot: String,
    fundingstateroot: String,
    bondinventorycovenanthash: String,
    insurancereservequoteunits: u128,
    issuedbondunits: u64,
    outstandingbondunits: u64,
    inventorybondunits: u64,
    navquoteunitsperbond: u128,
    deficitquoteunits: u128,
    targetreservequoteunits: u128,
    coveragebps: u128,
    controlledquoteunits: u128,
    mode: RpcCapitalMode,
    minimumauthenticatedprice: u64,
    maximumauthenticatedprice: u64,
    fundingepoch: u64,
    fundingrateppm: i32,
    globalfundingindexnumerator: i128,
    redemptionqueueroot: String,
    redemptionhead: u128,
    redemptiontail: u128,
    queuedredemptionbondunits: u64,
    oracle: RpcOracle,
    encryptedavailabilityroot: String,
    bondinbox: RpcBondInbox,
    matcherexecution: RpcMatcherExecution,
    lasttransitionsidechainheight: u64,
    operationallysafe: bool,
    legacyfeepoolquoteunits: u128,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RpcProofProfile {
    #[serde(rename = "finite-v18")]
    FiniteV18,
    #[serde(rename = "incremental-successor")]
    IncrementalSuccessor,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
enum RpcCapitalMode {
    Normal,
    ReduceOnly,
    Recovery,
}

impl From<RpcCapitalMode> for CapitalMode {
    fn from(value: RpcCapitalMode) -> Self {
        match value {
            RpcCapitalMode::Normal => Self::Normal,
            RpcCapitalMode::ReduceOnly => Self::ReduceOnly,
            RpcCapitalMode::Recovery => Self::Recovery,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcOracle {
    certificatehash: String,
    validthroughparentmtp: u64,
    mode: RpcOracleMode,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
enum RpcOracleMode {
    Normal,
    ReduceOnly,
    Disputed,
    Halt,
}

impl From<RpcOracleMode> for OracleModeV2 {
    fn from(value: RpcOracleMode) -> Self {
        match value {
            RpcOracleMode::Normal => Self::Normal,
            RpcOracleMode::ReduceOnly => Self::ReduceOnly,
            RpcOracleMode::Disputed => Self::Disputed,
            RpcOracleMode::Halt => Self::Halt,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcBondInbox {
    headroot: String,
    entrycount: u128,
    processedroot: String,
    processedcursor: u128,
    outcomeroot: String,
    outcomecount: u128,
    nodeverifiedsourceheadroot: String,
    nodeverifiedsourceentrycount: u128,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcMatcherExecution {
    receiptbatchroot: String,
    previoussequence: u128,
    sequence: u128,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcInbox {
    headroot: String,
    entrycount: u64,
    nextindex: u64,
    processedcursor: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcBmm {
    authenticated: bool,
    parentheight: u64,
    parentmtp: u64,
    parentblockhash: String,
}

impl TryFrom<RpcContext> for ElementsConsensusContextV2 {
    type Error = anyhow::Error;

    fn try_from(value: RpcContext) -> Result<Self> {
        if value
            .capital
            .as_ref()
            .is_some_and(|capital| capital.proofprofile != RpcProofProfile::FiniteV18)
        {
            bail!(
                "Elements returned incremental-successor capital through the finite V2 matcher decoder"
            );
        }
        let forced_backlog = value
            .forcedinbox
            .entrycount
            .checked_sub(value.forcedinbox.processedcursor);
        let deposit_backlog = value
            .depositinbox
            .entrycount
            .checked_sub(value.depositinbox.processedcursor);
        let pending_source_entries = forced_backlog
            .and_then(|forced| deposit_backlog.and_then(|deposit| forced.checked_add(deposit)));
        let backlog_marker_consistent = match pending_source_entries {
            Some(0) => value.sourcebacklogoldestparentheight == 0,
            Some(_) => {
                value.sourcebacklogoldestparentheight != 0
                    && value.sourcebacklogoldestparentheight <= value.sourceparentheight
                    && value
                        .sourcebacklogoldestparentheight
                        .checked_add(6)
                        .is_some_and(|deadline| value.sourceparentheight < deadline)
            }
            None => false,
        };
        if value.sidechainheight == 0
            || value.bmm.parentheight == 0
            || value.bmm.parentmtp == 0
            || value.sourceparentheight == 0
            || value.sourceparentheight != value.bmm.parentheight
            || !value.bmm.authenticated
            || value.forcedinbox.entrycount != value.forcedinbox.nextindex
            || value.forcedinbox.processedcursor > value.forcedinbox.entrycount
            || value.depositinbox.entrycount != value.depositinbox.nextindex
            || value.depositinbox.processedcursor > value.depositinbox.entrycount
            || !backlog_marker_consistent
        {
            bail!("Elements returned an unavailable or inconsistent ECX context");
        }
        let context = Self {
            sidechain_height: value.sidechainheight,
            sidechain_block_hash: decode_hash(&value.sidechainblockhash, "sidechain block")?,
            exchange_state_root: decode_hash(&value.exchangestateroot, "exchange state")?,
            forced_inbox_head_root: decode_hash(&value.forcedinbox.headroot, "forced inbox")?,
            forced_inbox_entry_count: value.forcedinbox.entrycount,
            forced_inbox_processed_cursor: value.forcedinbox.processedcursor,
            deposit_inbox_head_root: decode_hash(&value.depositinbox.headroot, "deposit inbox")?,
            deposit_inbox_entry_count: value.depositinbox.entrycount,
            deposit_inbox_processed_cursor: value.depositinbox.processedcursor,
            parent_height: value.bmm.parentheight,
            parent_mtp: value.bmm.parentmtp,
            parent_block_hash: decode_hash(&value.bmm.parentblockhash, "BMM parent block")?,
            source_parent_height: value.sourceparentheight,
            capital_snapshot: value
                .capital
                .map(|capital| -> Result<CapitalSnapshotV2> {
                    let configuration_hash =
                        decode_hash(&capital.configurationhash, "finite v2 configuration")?;
                    if decode_hash(
                        &capital.bondactionconfigurationhash,
                        "bond-action configuration",
                    )? != configuration_hash
                        || capital.issuedbondunits != ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS
                        || capital
                            .outstandingbondunits
                            .checked_add(capital.inventorybondunits)
                            != Some(capital.issuedbondunits)
                        || !capital.operationallysafe
                    {
                        bail!("Elements returned an inconsistent finite-v18 capital projection");
                    }
                    // These are part of the exact current node RPC contract
                    // even though the finite matcher does not need to retain
                    // them in its historical snapshot type.
                    decode_hash(
                        &capital.bondinventorycovenanthash,
                        "bond inventory covenant",
                    )?;
                    let _ = (
                        capital.controlledquoteunits,
                        capital.globalfundingindexnumerator,
                    );
                    Ok(CapitalSnapshotV2 {
                        version: capital.version,
                        exchange_state_root: decode_hash(
                            &capital.exchangestateroot,
                            "capital exchange state",
                        )?,
                        configuration_hash,
                        bond_asset_id: decode_hash(&capital.bondassetid, "bond asset")?,
                        bond_deployment_commitment: decode_hash(
                            &capital.bonddeploymentcommitment,
                            "bond deployment commitment",
                        )?,
                        transition_program_id: decode_hash(
                            &capital.transitionprogramid,
                            "v2 transition program",
                        )?,
                        transition_cmr: decode_hash(
                            &capital.transitioncmr,
                            "v2 Simplicity transition CMR",
                        )?,
                        covenant_state_hash: decode_hash(
                            &capital.covenantstatehash,
                            "v2 covenant state",
                        )?,
                        bond_state_root: decode_hash(&capital.bondstateroot, "v2 bond state")?,
                        funding_state_root: decode_hash(
                            &capital.fundingstateroot,
                            "v2 funding state",
                        )?,
                        insurance_reserve_quote_units: capital.insurancereservequoteunits,
                        outstanding_bond_units: capital.outstandingbondunits,
                        nav_quote_units_per_bond: capital.navquoteunitsperbond,
                        deficit_quote_units: capital.deficitquoteunits,
                        target_reserve_quote_units: capital.targetreservequoteunits,
                        coverage_bps: capital.coveragebps,
                        mode: capital.mode.into(),
                        minimum_authenticated_price: capital.minimumauthenticatedprice,
                        maximum_authenticated_price: capital.maximumauthenticatedprice,
                        funding_epoch: capital.fundingepoch,
                        funding_rate_ppm: capital.fundingrateppm,
                        redemption_queue_root: decode_hash(
                            &capital.redemptionqueueroot,
                            "v2 redemption queue",
                        )?,
                        redemption_head: capital
                            .redemptionhead
                            .try_into()
                            .context("finite-v18 redemption head exceeds u64")?,
                        redemption_tail: capital
                            .redemptiontail
                            .try_into()
                            .context("finite-v18 redemption tail exceeds u64")?,
                        queued_redemption_bond_units: capital.queuedredemptionbondunits,
                        oracle: OracleSnapshotV2 {
                            certificate_hash: decode_hash(
                                &capital.oracle.certificatehash,
                                "v2 oracle certificate",
                            )?,
                            valid_through_parent_mtp: capital.oracle.validthroughparentmtp,
                            mode: capital.oracle.mode.into(),
                        },
                        encrypted_availability_root: decode_hash(
                            &capital.encryptedavailabilityroot,
                            "v2 encrypted availability",
                        )?,
                        bond_inbox: BondInboxSnapshotV2 {
                            head_root: decode_hash(
                                &capital.bondinbox.headroot,
                                "v2 bond inbox head",
                            )?,
                            entry_count: capital
                                .bondinbox
                                .entrycount
                                .try_into()
                                .context("finite-v18 bond inbox count exceeds u64")?,
                            processed_root: decode_hash(
                                &capital.bondinbox.processedroot,
                                "v2 bond inbox processed",
                            )?,
                            processed_cursor: capital
                                .bondinbox
                                .processedcursor
                                .try_into()
                                .context("finite-v18 bond inbox cursor exceeds u64")?,
                            outcome_root: decode_hash(
                                &capital.bondinbox.outcomeroot,
                                "v2 bond inbox outcome",
                            )?,
                            outcome_count: capital
                                .bondinbox
                                .outcomecount
                                .try_into()
                                .context("finite-v18 bond outcome count exceeds u64")?,
                            node_verified_source_head_root: decode_hash(
                                &capital.bondinbox.nodeverifiedsourceheadroot,
                                "v2 node-verified bond source head",
                            )?,
                            node_verified_source_entry_count: capital
                                .bondinbox
                                .nodeverifiedsourceentrycount
                                .try_into()
                                .context("finite-v18 node bond inbox count exceeds u64")?,
                        },
                        matcher_execution: MatcherExecutionSnapshotV2 {
                            receipt_batch_root: decode_hash(
                                &capital.matcherexecution.receiptbatchroot,
                                "v2 matcher execution receipt batch",
                            )?,
                            previous_sequence: capital
                                .matcherexecution
                                .previoussequence
                                .try_into()
                                .context("finite-v18 matcher execution cursor exceeds u64")?,
                            sequence: capital
                                .matcherexecution
                                .sequence
                                .try_into()
                                .context("finite-v18 matcher execution sequence exceeds u64")?,
                        },
                        last_transition_sidechain_height: capital.lasttransitionsidechainheight,
                        legacy_fee_pool_quote_units: capital.legacyfeepoolquoteunits,
                    })
                })
                .transpose()?,
        };
        context.validate()?;
        Ok(context)
    }
}

impl TryFrom<RpcContext> for SuccessorElementsConsensusContextV2 {
    type Error = anyhow::Error;

    fn try_from(value: RpcContext) -> Result<Self> {
        let forced_backlog = value
            .forcedinbox
            .entrycount
            .checked_sub(value.forcedinbox.processedcursor);
        let deposit_backlog = value
            .depositinbox
            .entrycount
            .checked_sub(value.depositinbox.processedcursor);
        let pending_source_entries = forced_backlog
            .and_then(|forced| deposit_backlog.and_then(|deposit| forced.checked_add(deposit)));
        let backlog_marker_consistent = match pending_source_entries {
            Some(0) => value.sourcebacklogoldestparentheight == 0,
            Some(_) => {
                value.sourcebacklogoldestparentheight != 0
                    && value.sourcebacklogoldestparentheight <= value.sourceparentheight
                    && value
                        .sourcebacklogoldestparentheight
                        .checked_add(6)
                        .is_some_and(|deadline| value.sourceparentheight < deadline)
            }
            None => false,
        };
        if value.sidechainheight == 0
            || value.bmm.parentheight == 0
            || value.bmm.parentmtp == 0
            || value.sourceparentheight != value.bmm.parentheight
            || !value.bmm.authenticated
            || value.forcedinbox.entrycount != value.forcedinbox.nextindex
            || value.forcedinbox.processedcursor > value.forcedinbox.entrycount
            || value.depositinbox.entrycount != value.depositinbox.nextindex
            || value.depositinbox.processedcursor > value.depositinbox.entrycount
            || !backlog_marker_consistent
        {
            bail!("Elements returned an unavailable successor ECX context");
        }
        let capital = value
            .capital
            .context("Elements omitted incremental-successor capital")?;
        if capital.proofprofile != RpcProofProfile::IncrementalSuccessor
            || !capital.operationallysafe
            || capital.issuedbondunits != ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS
            || capital
                .outstandingbondunits
                .checked_add(capital.inventorybondunits)
                != Some(capital.issuedbondunits)
            || capital.redemptionhead > capital.redemptiontail
            || capital.bondinbox.processedcursor > capital.bondinbox.entrycount
            || capital.bondinbox.outcomecount != capital.bondinbox.processedcursor
            || capital.bondinbox.nodeverifiedsourceentrycount < capital.bondinbox.entrycount
            || capital.matcherexecution.previoussequence > capital.matcherexecution.sequence
        {
            bail!("Elements returned an inconsistent incremental-successor capital projection");
        }
        let expected_coverage = ecx_protocol_core::coverage_bps(
            capital.insurancereservequoteunits,
            capital.deficitquoteunits,
        )?;
        let expected_target = ecx_protocol_core::target_reserve_125(capital.deficitquoteunits)?;
        let expected_mode = ecx_protocol_core::capital_mode_for(
            capital.insurancereservequoteunits,
            capital.deficitquoteunits,
        )?;
        let mode: CapitalMode = capital.mode.into();
        let mode_matches = matches!(
            (expected_mode, mode),
            (
                ecx_protocol_core::CapitalModeV2::Normal,
                CapitalMode::Normal
            ) | (
                ecx_protocol_core::CapitalModeV2::ReduceOnly,
                CapitalMode::ReduceOnly
            ) | (
                ecx_protocol_core::CapitalModeV2::RecapitalizationOnly,
                CapitalMode::Recovery
            )
        );
        if capital.coveragebps != expected_coverage
            || capital.targetreservequoteunits != expected_target
            || !mode_matches
            || capital.lasttransitionsidechainheight > value.sidechainheight
        {
            bail!("Elements successor capital arithmetic or transition height is invalid");
        }
        if capital.oracle.validthroughparentmtp < value.bmm.parentmtp {
            bail!(
                "Elements successor oracle is stale or uninitialized: valid through parent MTP {}, authenticated parent MTP {}",
                capital.oracle.validthroughparentmtp,
                value.bmm.parentmtp
            );
        }
        // Decode every exact identity/root published by the current RPC even
        // when this compact matcher context retains only the fields required
        // for admission. This keeps malformed or zero projections fail-closed.
        for (encoded, name) in [
            (&capital.covenantstatehash, "successor covenant state"),
            (&capital.bondstateroot, "successor bond state"),
            (&capital.fundingstateroot, "successor funding state"),
            (
                &capital.bondinventorycovenanthash,
                "bond inventory covenant",
            ),
            (&capital.redemptionqueueroot, "successor redemption queue"),
            (
                &capital.oracle.certificatehash,
                "successor oracle certificate",
            ),
            (&capital.encryptedavailabilityroot, "successor availability"),
            (&capital.bondinbox.headroot, "successor bond inbox"),
            (
                &capital.bondinbox.processedroot,
                "successor bond processed root",
            ),
            (
                &capital.bondinbox.outcomeroot,
                "successor bond outcome root",
            ),
            (
                &capital.bondinbox.nodeverifiedsourceheadroot,
                "successor node bond source root",
            ),
            (
                &capital.matcherexecution.receiptbatchroot,
                "successor matcher execution batch",
            ),
        ] {
            decode_hash(encoded, name)?;
        }
        let context = Self {
            sidechain_height: value.sidechainheight,
            sidechain_block_hash: decode_hash(&value.sidechainblockhash, "sidechain block")?,
            exchange_state_root: decode_hash(&value.exchangestateroot, "exchange state")?,
            parent_height: value.bmm.parentheight,
            parent_mtp: value.bmm.parentmtp,
            parent_block_hash: decode_hash(&value.bmm.parentblockhash, "BMM parent block")?,
            source_parent_height: value.sourceparentheight,
            // Source indexing remains physically bounded by the active node's
            // u64 block/index space. Widening here is exact and never narrows a
            // successor receipt or journal cursor.
            forced_inbox_processed_cursor: u128::from(value.forcedinbox.processedcursor),
            successor_configuration_hash: decode_hash(
                &capital.configurationhash,
                "successor configuration",
            )?,
            bond_action_configuration_hash: decode_hash(
                &capital.bondactionconfigurationhash,
                "bond-action configuration",
            )?,
            bond_asset_id: decode_hash(&capital.bondassetid, "bond asset")?,
            bond_deployment_commitment: decode_hash(
                &capital.bonddeploymentcommitment,
                "bond deployment commitment",
            )?,
            transition_program_id: decode_hash(
                &capital.transitionprogramid,
                "successor transition program",
            )?,
            transition_cmr: decode_hash(&capital.transitioncmr, "successor transition CMR")?,
            capital_mode: mode,
            matcher_execution_previous_sequence: capital.matcherexecution.previoussequence,
            matcher_execution_sequence: capital.matcherexecution.sequence,
            last_transition_sidechain_height: capital.lasttransitionsidechainheight,
        };
        context.validate()?;
        Ok(context)
    }
}

fn decode_hash(value: &str, name: &str) -> Result<Hash32> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} hash must be canonical 32-byte lowercase hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decoding {name} hash"))?;
    let hash: Hash32 = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} hash must contain exactly 32 bytes"))?;
    if hash == [0; 32] {
        bail!("{name} hash must be nonzero");
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use axum::{Router, http::StatusCode, routing::post};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn frozen_v1_bincode_fixture_decodes_and_reencodes_byte_exact() {
        let fixture = hex::decode(
            include_str!("../tests/fixtures/elements_consensus_context_v1.bincode.hex").trim(),
        )
        .unwrap();
        let context: ElementsConsensusContextV1 = bincode::deserialize(&fixture).unwrap();
        assert_eq!(
            context,
            ElementsConsensusContextV1 {
                sidechain_height: 0x0102_0304_0506_0708,
                sidechain_block_hash: [0x11; 32],
                exchange_state_root: [0x22; 32],
                forced_inbox_head_root: [0x33; 32],
                forced_inbox_entry_count: 0x1112_1314_1516_1718,
                deposit_inbox_head_root: [0x44; 32],
                deposit_inbox_entry_count: 0x2122_2324_2526_2728,
                parent_height: 0x3132_3334_3536_3738,
                parent_mtp: 0x4142_4344_4546_4748,
                parent_block_hash: [0x55; 32],
                source_parent_height: 0x5152_5354_5556_5758,
            }
        );
        assert_eq!(bincode::serialize(&context).unwrap(), fixture);
    }

    #[test]
    fn rejects_remote_plaintext_or_mismatched_inbox_count() {
        assert!(ElementsRpcClient::new("http://example.com", None, None).is_err());
        let raw = RpcContext {
            sidechainheight: 10,
            sidechainblockhash: "11".repeat(32),
            exchangestateroot: "22".repeat(32),
            forcedinbox: RpcInbox {
                headroot: "33".repeat(32),
                entrycount: 2,
                nextindex: 1,
                processedcursor: 0,
            },
            depositinbox: RpcInbox {
                headroot: "44".repeat(32),
                entrycount: 0,
                nextindex: 0,
                processedcursor: 0,
            },
            bmm: RpcBmm {
                authenticated: true,
                parentheight: 100,
                parentmtp: 1_000,
                parentblockhash: "55".repeat(32),
            },
            sourceparentheight: 100,
            sourcebacklogoldestparentheight: 0,
            capital: None,
        };
        assert!(ElementsConsensusContextV2::try_from(raw).is_err());
    }

    #[test]
    fn rejects_parent_source_mismatch_and_noncanonical_hashes() {
        let raw = valid_rpc_context();
        assert!(ElementsConsensusContextV2::try_from(raw).is_ok());

        let mut parent_mismatch = valid_rpc_context();
        parent_mismatch.sourceparentheight += 1;
        assert!(ElementsConsensusContextV2::try_from(parent_mismatch).is_err());

        let mut uppercase = valid_rpc_context();
        uppercase.sidechainblockhash = "ab".repeat(32);
        uppercase.sidechainblockhash = uppercase.sidechainblockhash.to_uppercase();
        assert!(ElementsConsensusContextV2::try_from(uppercase).is_err());
    }

    #[test]
    fn source_backlog_marker_is_required_and_liveness_bounded() {
        let mut pending = valid_rpc_context();
        pending.forcedinbox.entrycount = 1;
        pending.forcedinbox.nextindex = 1;
        pending.forcedinbox.processedcursor = 0;
        assert!(ElementsConsensusContextV2::try_from(pending).is_err());

        let mut recent = valid_rpc_context();
        recent.forcedinbox.entrycount = 1;
        recent.forcedinbox.nextindex = 1;
        recent.forcedinbox.processedcursor = 0;
        recent.sourcebacklogoldestparentheight = 95;
        assert!(ElementsConsensusContextV2::try_from(recent).is_ok());

        let mut stale = valid_rpc_context();
        stale.forcedinbox.entrycount = 1;
        stale.forcedinbox.nextindex = 1;
        stale.forcedinbox.processedcursor = 0;
        stale.sourcebacklogoldestparentheight = 94;
        assert!(ElementsConsensusContextV2::try_from(stale).is_err());

        let mut false_marker = valid_rpc_context();
        false_marker.sourcebacklogoldestparentheight = 100;
        assert!(ElementsConsensusContextV2::try_from(false_marker).is_err());
    }

    #[test]
    fn accepts_only_root_bound_consistent_v2_capital_state() {
        let mut raw = valid_rpc_context();
        raw.capital = Some(valid_rpc_capital());
        assert_eq!(
            ElementsConsensusContextV2::try_from(raw)
                .unwrap()
                .capital_snapshot
                .unwrap()
                .mode,
            CapitalMode::Normal
        );

        let mut inconsistent = valid_rpc_context();
        let mut capital = valid_rpc_capital();
        capital.insurancereservequoteunits = 99;
        capital.navquoteunitsperbond = 99_000_000;
        capital.coveragebps = 12_500;
        capital.mode = RpcCapitalMode::Normal;
        inconsistent.capital = Some(capital);
        assert!(ElementsConsensusContextV2::try_from(inconsistent).is_err());
    }

    #[test]
    fn parses_root_bound_target_and_fifo_capital_fields() {
        let mut raw = valid_rpc_context();
        raw.capital = Some(valid_rpc_capital());
        let capital = ElementsConsensusContextV2::try_from(raw)
            .unwrap()
            .capital_snapshot
            .unwrap();
        assert_eq!(capital.target_reserve_quote_units, 125);
        assert_eq!(capital.redemption_queue_root, [0xbb; 32]);
        assert_eq!(capital.redemption_head, 0);
        assert_eq!(capital.redemption_tail, 0);
        assert_eq!(capital.queued_redemption_bond_units, 0);

        let mut inconsistent = valid_rpc_context();
        let mut capital = valid_rpc_capital();
        capital.targetreservequoteunits = 124;
        inconsistent.capital = Some(capital);
        assert!(ElementsConsensusContextV2::try_from(inconsistent).is_err());

        let mut impossible_queue = valid_rpc_context();
        let mut capital = valid_rpc_capital();
        capital.redemptionhead = 2;
        capital.redemptiontail = 1;
        impossible_queue.capital = Some(capital);
        assert!(ElementsConsensusContextV2::try_from(impossible_queue).is_err());
    }

    #[tokio::test]
    async fn v2_identity_pins_reject_missing_or_substituted_capital_on_every_read() {
        let pins = V2IdentityPins {
            configuration_hash: [0x66; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
        };
        let valid = rpc_envelope(Some(valid_rpc_capital()));
        let client = rpc_client_with_bodies(vec![valid.clone(), rpc_envelope(None), valid.clone()])
            .await
            .with_v2_identity_pins(pins)
            .unwrap();
        assert!(client.consensus_context().await.is_ok());
        assert!(client.consensus_context().await.is_err());
        assert!(client.consensus_context().await.is_ok());

        let mut substituted = valid_rpc_capital();
        substituted.transitionprogramid = "cc".repeat(32);
        let client = rpc_client_with_bodies(vec![rpc_envelope(Some(substituted))])
            .await
            .with_v2_identity_pins(pins)
            .unwrap();
        assert!(client.consensus_context().await.is_err());
    }

    #[test]
    fn successor_profile_preserves_high_u128_cursors_and_is_not_finite_v2() {
        let mut raw = valid_rpc_context();
        raw.capital = Some(valid_successor_rpc_capital());
        let successor = SuccessorElementsConsensusContextV2::try_from(raw).unwrap();
        assert_eq!(
            successor.matcher_execution_previous_sequence,
            (1u128 << 100) + 21
        );
        assert_eq!(successor.matcher_execution_sequence, (1u128 << 100) + 24);
        assert_eq!(successor.successor_configuration_hash, [0x65; 32]);
        assert_eq!(successor.bond_action_configuration_hash, [0x66; 32]);
        successor.matcher_context().unwrap();

        let mut wrong_decoder = valid_rpc_context();
        wrong_decoder.capital = Some(valid_successor_rpc_capital());
        assert!(ElementsConsensusContextV2::try_from(wrong_decoder).is_err());

        let mut finite = valid_rpc_context();
        finite.capital = Some(valid_rpc_capital());
        assert!(SuccessorElementsConsensusContextV2::try_from(finite).is_err());

        let mut colliding = valid_rpc_context();
        let mut capital = valid_successor_rpc_capital();
        capital.bondactionconfigurationhash = capital.configurationhash.clone();
        colliding.capital = Some(capital);
        assert!(SuccessorElementsConsensusContextV2::try_from(colliding).is_err());
    }

    #[tokio::test]
    async fn successor_rpc_requires_exact_profile_and_frozen_bond_identity_pins() {
        let pins = V2IdentityPins {
            configuration_hash: [0x66; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
        };
        let valid = rpc_envelope_with_id(
            "ecx-successor-matcher-context",
            Some(valid_successor_rpc_capital()),
        );
        let client = rpc_client_with_bodies(vec![valid])
            .await
            .with_v2_identity_pins(pins)
            .unwrap();
        let context = client.successor_consensus_context().await.unwrap();
        assert_eq!(context.successor_configuration_hash, [0x65; 32]);

        let mut substituted = valid_successor_rpc_capital();
        substituted.bondactionconfigurationhash = "67".repeat(32);
        let client = rpc_client_with_bodies(vec![rpc_envelope_with_id(
            "ecx-successor-matcher-context",
            Some(substituted),
        )])
        .await
        .with_v2_identity_pins(pins)
        .unwrap();
        assert!(client.successor_consensus_context().await.is_err());
    }

    #[tokio::test]
    async fn rejects_mismatched_envelope_and_oversized_body() {
        let mismatched = json!({
            "jsonrpc": "2.0",
            "id": "wrong-request",
            "result": {
                "sidechainheight": 10,
                "sidechainblockhash": "11".repeat(32),
                "exchangestateroot": "22".repeat(32),
                "forcedinbox": {
                    "headroot": "33".repeat(32),
                    "entrycount": 0,
                    "nextindex": 0,
                    "processedcursor": 0
                },
                "depositinbox": {
                    "headroot": "44".repeat(32),
                    "entrycount": 0,
                    "nextindex": 0,
                    "processedcursor": 0
                },
                "bmm": {
                    "authenticated": true,
                    "parentheight": 100,
                    "parentmtp": 1_000,
                    "parentblockhash": "55".repeat(32)
                },
                "sourceparentheight": 100,
                "sourcebacklogoldestparentheight": 0
            },
            "error": null
        })
        .to_string();
        let error = format!("{:#}", rpc_response(mismatched).await.err().unwrap());
        assert!(error.contains("mismatched"), "unexpected error: {error}");

        let oversized = "x".repeat(MAX_RPC_RESPONSE_BYTES + 1);
        let error = format!("{:#}", rpc_response(oversized).await.err().unwrap());
        assert!(error.contains("exceeds"), "unexpected error: {error}");
    }

    fn valid_rpc_context() -> RpcContext {
        RpcContext {
            sidechainheight: 10,
            sidechainblockhash: "11".repeat(32),
            exchangestateroot: "22".repeat(32),
            forcedinbox: RpcInbox {
                headroot: "33".repeat(32),
                entrycount: 0,
                nextindex: 0,
                processedcursor: 0,
            },
            depositinbox: RpcInbox {
                headroot: "44".repeat(32),
                entrycount: 0,
                nextindex: 0,
                processedcursor: 0,
            },
            bmm: RpcBmm {
                authenticated: true,
                parentheight: 100,
                parentmtp: 1_000,
                parentblockhash: "55".repeat(32),
            },
            sourceparentheight: 100,
            sourcebacklogoldestparentheight: 0,
            capital: None,
        }
    }

    fn valid_rpc_capital() -> RpcCapital {
        RpcCapital {
            version: CapitalSnapshotV2::VERSION,
            proofprofile: RpcProofProfile::FiniteV18,
            exchangestateroot: "22".repeat(32),
            configurationhash: "66".repeat(32),
            bondactionconfigurationhash: "66".repeat(32),
            bondassetid: "77".repeat(32),
            bonddeploymentcommitment: "88".repeat(32),
            transitionprogramid: "99".repeat(32),
            transitioncmr: "aa".repeat(32),
            covenantstatehash: "ab".repeat(32),
            bondstateroot: "ac".repeat(32),
            fundingstateroot: "ad".repeat(32),
            bondinventorycovenanthash: "ae".repeat(32),
            insurancereservequoteunits: 125,
            issuedbondunits: ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS,
            outstandingbondunits: 100,
            inventorybondunits: ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS - 100,
            navquoteunitsperbond: 125_000_000,
            deficitquoteunits: 100,
            targetreservequoteunits: 125,
            coveragebps: 12_500,
            controlledquoteunits: 125,
            mode: RpcCapitalMode::Normal,
            minimumauthenticatedprice: 1,
            maximumauthenticatedprice: 10,
            fundingepoch: 7,
            fundingrateppm: 0,
            globalfundingindexnumerator: 0,
            redemptionqueueroot: "bb".repeat(32),
            redemptionhead: 0,
            redemptiontail: 0,
            queuedredemptionbondunits: 0,
            oracle: RpcOracle {
                certificatehash: "bc".repeat(32),
                validthroughparentmtp: 1_100,
                mode: RpcOracleMode::Normal,
            },
            encryptedavailabilityroot: "bd".repeat(32),
            bondinbox: RpcBondInbox {
                headroot: "be".repeat(32),
                entrycount: 0,
                processedroot: "bf".repeat(32),
                processedcursor: 0,
                outcomeroot: "c0".repeat(32),
                outcomecount: 0,
                nodeverifiedsourceheadroot: "be".repeat(32),
                nodeverifiedsourceentrycount: 0,
            },
            matcherexecution: RpcMatcherExecution {
                receiptbatchroot: "c1".repeat(32),
                previoussequence: 0,
                sequence: 0,
            },
            lasttransitionsidechainheight: 9,
            operationallysafe: true,
            legacyfeepoolquoteunits: 0,
        }
    }

    fn valid_successor_rpc_capital() -> RpcCapital {
        let mut capital = valid_rpc_capital();
        capital.proofprofile = RpcProofProfile::IncrementalSuccessor;
        capital.configurationhash = "65".repeat(32);
        capital.redemptionhead = (1u128 << 96) + 7;
        capital.redemptiontail = capital.redemptionhead + 1;
        capital.bondinbox.entrycount = (1u128 << 96) + 11;
        capital.bondinbox.processedcursor = capital.bondinbox.entrycount;
        capital.bondinbox.outcomecount = capital.bondinbox.entrycount;
        capital.bondinbox.nodeverifiedsourceentrycount = capital.bondinbox.entrycount + 1;
        capital.matcherexecution.previoussequence = (1u128 << 100) + 21;
        capital.matcherexecution.sequence = capital.matcherexecution.previoussequence + 3;
        capital
    }

    fn rpc_envelope(capital: Option<RpcCapital>) -> String {
        rpc_envelope_with_id(RPC_CONTEXT_REQUEST_ID, capital)
    }

    fn rpc_envelope_with_id(id: &str, capital: Option<RpcCapital>) -> String {
        let capital = capital.map(|capital| serde_json::to_value(capital).unwrap());
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "sidechainheight": 10,
                "sidechainblockhash": "11".repeat(32),
                "exchangestateroot": "22".repeat(32),
                "forcedinbox": {"headroot": "33".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
                "depositinbox": {"headroot": "44".repeat(32), "entrycount": 0, "nextindex": 0, "processedcursor": 0},
                "bmm": {"authenticated": true, "parentheight": 100, "parentmtp": 1_000, "parentblockhash": "55".repeat(32)},
                "sourceparentheight": 100,
                "sourcebacklogoldestparentheight": 0,
                "capital": capital,
            },
            "error": null,
        }).to_string()
    }

    async fn rpc_client_with_bodies(bodies: Vec<String>) -> ElementsRpcClient {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let bodies = Arc::new(bodies);
        let index = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/",
            post(move || {
                let bodies = Arc::clone(&bodies);
                let index = Arc::clone(&index);
                async move {
                    let current = index.fetch_add(1, Ordering::SeqCst);
                    let body = bodies
                        .get(current)
                        .cloned()
                        .unwrap_or_else(|| bodies.last().unwrap().clone());
                    (StatusCode::OK, [("content-type", "application/json")], body)
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        ElementsRpcClient::new(&format!("http://{address}"), None, None).unwrap()
    }

    async fn rpc_response(body: String) -> Result<ElementsConsensusContextV2> {
        let app = Router::new().route(
            "/",
            post(move || {
                let body = body.clone();
                async move { (StatusCode::OK, [("content-type", "application/json")], body) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = ElementsRpcClient::new(&format!("http://{address}"), None, None).unwrap();
        let result = client.consensus_context().await;
        server.abort();
        result
    }
}
