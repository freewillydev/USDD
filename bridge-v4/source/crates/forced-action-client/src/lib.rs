//! Wallet-funded Elements broadcaster for the matcher-independent `ECXF` path.

use ecx_protocol_core::ForcedActionV1;
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

const MAX_RPC_BODY: usize = 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid canonical ECXF payload")]
    InvalidPayload,
    #[error("forced action belongs to a different chain")]
    WrongChain,
    #[error("Elements RPC URL must use HTTPS unless it targets loopback")]
    InsecureRpcUrl,
    #[error("invalid Elements RPC URL")]
    InvalidRpcUrl,
    #[error("Elements RPC transport failed: {0}")]
    Transport(String),
    #[error("Elements RPC returned an oversized response")]
    OversizedResponse,
    #[error("Elements RPC envelope is invalid")]
    InvalidEnvelope,
    #[error("Elements RPC {method} failed ({code}): {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
    },
    #[error("fundrawtransaction returned no transaction")]
    MissingFundedTransaction,
    #[error("wallet did not completely sign the transaction")]
    IncompleteSignature,
    #[error("signed transaction does not contain exactly one expected ECXF output")]
    WrongSignedTransaction,
    #[error("transaction was rejected by mempool policy: {0}")]
    MempoolRejected(String),
    #[error("sendrawtransaction returned an invalid txid")]
    InvalidTxid,
}

#[derive(Clone)]
pub struct ElementsRpc {
    endpoint: Url,
    client: Client,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastReceipt {
    pub txid: String,
    pub payload_hex: String,
}

impl ElementsRpc {
    pub fn new(
        endpoint: &str,
        username: Option<String>,
        password: Option<String>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let endpoint = Url::parse(endpoint).map_err(|_| Error::InvalidRpcUrl)?;
        let secure = endpoint.scheme() == "https";
        let loopback = endpoint
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
            || endpoint.host_str() == Some("localhost");
        if !(secure || endpoint.scheme() == "http" && loopback) {
            return Err(Error::InsecureRpcUrl);
        }
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::InvalidRpcUrl);
        }
        if username.is_some() != password.is_some() {
            return Err(Error::InvalidRpcUrl);
        }
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| Error::Transport(error.to_string()))?;
        Ok(Self {
            endpoint,
            client,
            username,
            password,
        })
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, Error> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let mut builder = self.client.post(self.endpoint.clone()).json(&request);
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            builder = builder.basic_auth(username, Some(password));
        }
        let mut response = builder
            .send()
            .await
            .map_err(|error| Error::Transport(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_BODY as u64)
        {
            return Err(Error::OversizedResponse);
        }
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| Error::Transport(error.to_string()))?
        {
            if chunk.len() > MAX_RPC_BODY - bytes.len() {
                return Err(Error::OversizedResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: RpcResponse<T> =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidEnvelope)?;
        // Bitcoin/Elements Core still uses the legacy response envelope, which
        // omits `jsonrpc`, even when the request names JSON-RPC 2.0. Accept
        // that exact legacy form as well as an explicit 2.0 response.
        if envelope
            .jsonrpc
            .as_deref()
            .is_some_and(|version| version != "2.0")
            || envelope.id != 1
        {
            return Err(Error::InvalidEnvelope);
        }
        if let Some(error) = envelope.error {
            return Err(Error::Rpc {
                method: method.into(),
                code: error.code,
                message: error.message,
            });
        }
        if !status.is_success() {
            return Err(Error::InvalidEnvelope);
        }
        envelope.result.ok_or(Error::InvalidEnvelope)
    }

    pub async fn broadcast_forced_action(
        &self,
        payload: &[u8],
        expected_chain_id: [u8; 32],
    ) -> Result<BroadcastReceipt, Error> {
        let action = ForcedActionV1::decode_payload(payload).map_err(|_| Error::InvalidPayload)?;
        if action.payload_bytes().map_err(|_| Error::InvalidPayload)? != payload {
            return Err(Error::InvalidPayload);
        }
        if action.chain_id() != expected_chain_id {
            return Err(Error::WrongChain);
        }
        let payload_hex = hex::encode(payload);
        let raw: String = self
            .call("createrawtransaction", json!([[], [{"data": payload_hex}]]))
            .await?;
        let funded: Funded = self.call("fundrawtransaction", json!([raw])).await?;
        if funded.hex.is_empty() {
            return Err(Error::MissingFundedTransaction);
        }
        let signed: Signed = self
            .call("signrawtransactionwithwallet", json!([funded.hex]))
            .await?;
        if !signed.complete || signed.hex.is_empty() {
            return Err(Error::IncompleteSignature);
        }

        let decoded: DecodedTransaction = self
            .call("decoderawtransaction", json!([signed.hex]))
            .await?;
        let expected_script = ecxf_script_hex(payload)?;
        let matching = decoded
            .vout
            .iter()
            .filter(|output| output.script_pub_key.hex == expected_script)
            .count();
        if matching != 1
            || decoded.vout.iter().any(|output| {
                output.script_pub_key.hex != expected_script
                    && script_contains_ecxf(&output.script_pub_key.hex)
            })
        {
            return Err(Error::WrongSignedTransaction);
        }

        let accepted: Vec<MempoolAcceptance> = self
            .call("testmempoolaccept", json!([[signed.hex]]))
            .await?;
        if accepted.len() != 1 || !accepted[0].allowed {
            return Err(Error::MempoolRejected(
                accepted
                    .first()
                    .and_then(|entry| entry.reject_reason.clone())
                    .unwrap_or_else(|| "missing acceptance result".into()),
            ));
        }
        let txid: String = self.call("sendrawtransaction", json!([signed.hex])).await?;
        if txid.len() != 64 || hex::decode(&txid).map_or(true, |bytes| bytes.len() != 32) {
            return Err(Error::InvalidTxid);
        }
        Ok(BroadcastReceipt { txid, payload_hex })
    }
}

pub fn ecxf_script_hex(payload: &[u8]) -> Result<String, Error> {
    if payload.len() > u8::MAX as usize {
        return Err(Error::InvalidPayload);
    }
    let mut script = Vec::with_capacity(payload.len() + 3);
    script.push(0x6a);
    if payload.len() <= 75 {
        script.push(payload.len() as u8);
    } else {
        script.extend_from_slice(&[0x4c, payload.len() as u8]);
    }
    script.extend_from_slice(payload);
    Ok(hex::encode(script))
}

fn script_contains_ecxf(script_hex: &str) -> bool {
    hex::decode(script_hex).is_ok_and(|bytes| bytes.windows(4).any(|window| window == b"ECXF"))
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct Funded {
    hex: String,
}

#[derive(Deserialize)]
struct Signed {
    hex: String,
    complete: bool,
}

#[derive(Deserialize)]
struct DecodedTransaction {
    vout: Vec<DecodedOutput>,
}

#[derive(Deserialize)]
struct DecodedOutput {
    #[serde(rename = "scriptPubKey")]
    script_pub_key: DecodedScript,
}

#[derive(Deserialize)]
struct DecodedScript {
    hex: String,
}

#[derive(Deserialize)]
struct MempoolAcceptance {
    allowed: bool,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}
