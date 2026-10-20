use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use ecx_protocol_core::{
    BinaryOutcomeV1, PredictionMarketOrderV1, PredictionMarketSideV1, SignedPredictionMarketOrderV1,
};
use secp256k1::{rand::rngs::OsRng, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_KEY_BYTES: u64 = 4_096;

#[derive(Debug, Parser)]
#[command(name = "ecx-prediction-market-client")]
#[command(about = "Protected BIP340 wallet for ECX Simplicity prediction-market orders")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    Sign {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        market_id: String,
        #[arg(long)]
        payout_script_sha256: String,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        outcome: OutcomeArg,
        #[arg(long)]
        side: SideArg,
        #[arg(long)]
        quantity_units: u64,
        #[arg(long)]
        limit_probability_ppb: u32,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8094")]
        listen: SocketAddr,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        payout_script_sha256: String,
        #[arg(long)]
        token_file: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutcomeArg {
    No,
    Yes,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SideArg {
    Buy,
    Sell,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    version: u16,
    role: String,
    secret_key_hex: String,
    public_key_xonly: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentity {
    version: u16,
    role: &'static str,
    public_key_xonly: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedOrderOutput {
    version: u8,
    chain_id: String,
    market_id: String,
    trader_commitment: String,
    payout_script_sha256: String,
    nonce: String,
    outcome: u8,
    side: &'static str,
    outcome_quantity_units: String,
    limit_probability_ppb: u32,
    order_commitment: String,
    signature: String,
}

#[derive(Clone)]
struct SignerState {
    secret: SecretKey,
    public: [u8; 32],
    chain_id: [u8; 32],
    payout_script_sha256: [u8; 32],
    token: Arc<Zeroizing<Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignRequest {
    version: u8,
    chain_id: String,
    market_id: String,
    trader_commitment: String,
    payout_script_sha256: String,
    nonce: String,
    outcome: u8,
    side: String,
    outcome_quantity_units: String,
    limit_probability_ppb: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Health {
    ready: bool,
    chain_id: String,
    trader_public_key: String,
    payout_script_sha256: String,
}

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Keygen { output } => {
            println!("{}", serde_json::to_string_pretty(&generate(&output)?)?)
        }
        Command::Sign {
            key_file,
            chain_id,
            market_id,
            payout_script_sha256,
            nonce,
            outcome,
            side,
            quantity_units,
            limit_probability_ppb,
        } => {
            let secret = load_key(&key_file)?;
            let chain_id = hash32(&chain_id, "chain id")?;
            let market_id = hash32(&market_id, "market id")?;
            let payout_script_sha256 = hash32(&payout_script_sha256, "payout script sha256")?;
            let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
            let trader = XOnlyPublicKey::from_keypair(&keypair).0.serialize();
            let order = PredictionMarketOrderV1 {
                version: 1,
                chain_id,
                market_id,
                trader_commitment: trader,
                payout_script_sha256,
                nonce,
                outcome: match outcome {
                    OutcomeArg::No => BinaryOutcomeV1::No,
                    OutcomeArg::Yes => BinaryOutcomeV1::Yes,
                },
                side: match side {
                    SideArg::Buy => PredictionMarketSideV1::Buy,
                    SideArg::Sell => PredictionMarketSideV1::Sell,
                },
                outcome_quantity_units: quantity_units,
                limit_probability_ppb,
            };
            let signed = SignedPredictionMarketOrderV1::sign(order, &secret)?;
            let output = SignedOrderOutput {
                version: 1,
                chain_id: hex::encode(chain_id),
                market_id: hex::encode(market_id),
                trader_commitment: hex::encode(trader),
                payout_script_sha256: hex::encode(payout_script_sha256),
                nonce: nonce.to_string(),
                outcome: signed.order.outcome as u8,
                side: match signed.order.side {
                    PredictionMarketSideV1::Buy => "buy",
                    PredictionMarketSideV1::Sell => "sell",
                },
                outcome_quantity_units: quantity_units.to_string(),
                limit_probability_ppb,
                order_commitment: hex::encode(signed.order.commitment()?),
                signature: hex::encode(signed.signature.0),
            };
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::Serve {
            listen,
            key_file,
            chain_id,
            payout_script_sha256,
            token_file,
        } => {
            serve(
                listen,
                &key_file,
                &chain_id,
                &payout_script_sha256,
                &token_file,
            )
            .await?
        }
    }
    Ok(())
}

async fn serve(
    listen: SocketAddr,
    key_file: &Path,
    chain_id: &str,
    payout_script_sha256: &str,
    token_file: &Path,
) -> anyhow::Result<()> {
    if !listen.ip().is_loopback() {
        bail!("prediction-market signer must bind loopback; publish it only through an authenticated local gateway");
    }
    let secret = load_key(key_file)?;
    let public =
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), &secret))
            .0
            .serialize();
    let state = SignerState {
        secret,
        public,
        chain_id: hash32(chain_id, "chain id")?,
        payout_script_sha256: hash32(payout_script_sha256, "payout script sha256")?,
        token: Arc::new(load_token(token_file)?),
    };
    let app = signer_router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn signer_router(state: SignerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/prediction-market/sign", post(sign_http))
        .with_state(state)
}

async fn health(
    State(state): State<SignerState>,
    headers: HeaderMap,
) -> Result<Json<Health>, ApiError> {
    authorize(&state, &headers)?;
    Ok(Json(Health {
        ready: true,
        chain_id: hex::encode(state.chain_id),
        trader_public_key: hex::encode(state.public),
        payout_script_sha256: hex::encode(state.payout_script_sha256),
    }))
}

async fn sign_http(
    State(state): State<SignerState>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignedOrderOutput>, ApiError> {
    authorize(&state, &headers)?;
    if request.version != 1 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "unsupported order version".into(),
        ));
    }
    let chain_id = hash32(&request.chain_id, "chain id").map_err(bad)?;
    if chain_id != state.chain_id {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "order chain id mismatch".into(),
        ));
    }
    let market_id = hash32(&request.market_id, "market id").map_err(bad)?;
    let trader = hash32(&request.trader_commitment, "trader commitment").map_err(bad)?;
    if trader != state.public {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "order trader does not match signer".into(),
        ));
    }
    let payout_script_sha256 =
        hash32(&request.payout_script_sha256, "payout script sha256").map_err(bad)?;
    if payout_script_sha256 != state.payout_script_sha256 {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "order payout script does not match signer policy".into(),
        ));
    }
    let nonce = request
        .nonce
        .parse::<u64>()
        .map_err(|_| bad(anyhow::anyhow!("invalid nonce")))?;
    let quantity = request
        .outcome_quantity_units
        .parse::<u64>()
        .map_err(|_| bad(anyhow::anyhow!("invalid outcome quantity")))?;
    let outcome = match request.outcome {
        0 => BinaryOutcomeV1::No,
        1 => BinaryOutcomeV1::Yes,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "invalid outcome".into())),
    };
    let side = match request.side.as_str() {
        "buy" => PredictionMarketSideV1::Buy,
        "sell" => PredictionMarketSideV1::Sell,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "invalid side".into())),
    };
    let order = PredictionMarketOrderV1 {
        version: 1,
        chain_id,
        market_id,
        trader_commitment: trader,
        payout_script_sha256,
        nonce,
        outcome,
        side,
        outcome_quantity_units: quantity,
        limit_probability_ppb: request.limit_probability_ppb,
    };
    let signed = SignedPredictionMarketOrderV1::sign(order, &state.secret).map_err(bad)?;
    Ok(Json(SignedOrderOutput {
        version: 1,
        chain_id: hex::encode(chain_id),
        market_id: hex::encode(market_id),
        trader_commitment: hex::encode(trader),
        payout_script_sha256: hex::encode(payout_script_sha256),
        nonce: nonce.to_string(),
        outcome: outcome as u8,
        side: match side {
            PredictionMarketSideV1::Buy => "buy",
            PredictionMarketSideV1::Sell => "sell",
        },
        outcome_quantity_units: quantity.to_string(),
        limit_probability_ppb: request.limit_probability_ppb,
        order_commitment: hex::encode(signed.order.commitment().map_err(bad)?),
        signature: hex::encode(signed.signature.0),
    }))
}

fn authorize(state: &SignerState, headers: &HeaderMap) -> Result<(), ApiError> {
    let encoded = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    if encoded.as_bytes().ct_eq(state.token.as_slice()).unwrap_u8() != 1 {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid bearer token".into(),
        ));
    }
    Ok(())
}

fn bad(error: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, error.to_string())
}

fn load_token(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 4096 {
        bail!("signer token must be a non-empty small regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("signer token permissions must be 0600 or stricter");
        }
    }
    let mut token = Zeroizing::new(std::fs::read(path)?);
    while matches!(token.last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    if token.len() < 32 {
        bail!("signer token must contain at least 32 bytes");
    }
    Ok(token)
}

fn generate(output: &Path) -> anyhow::Result<PublicIdentity> {
    if output.exists() {
        bail!(
            "refusing to overwrite existing prediction-market key {}",
            output.display()
        );
    }
    let secret = SecretKey::new(&mut OsRng);
    let public = hex::encode(
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), &secret))
            .0
            .serialize(),
    );
    let mut document = KeyDocument {
        version: 1,
        role: "prediction_market_trader".into(),
        secret_key_hex: hex::encode(secret.secret_bytes()),
        public_key_xonly: public.clone(),
    };
    let mut encoded = Zeroizing::new(serde_json::to_vec_pretty(&document)?);
    encoded.push(b'\n');
    document.zeroize();
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("create protected key {}", output.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    Ok(PublicIdentity {
        version: 1,
        role: "prediction_market_trader",
        public_key_xonly: public,
    })
}

fn load_key(path: &Path) -> anyhow::Result<SecretKey> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("stat key {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_BYTES {
        bail!("prediction-market key must be a small regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("prediction-market key permissions must be 0600 or stricter");
        }
    }
    let mut bytes = Zeroizing::new(std::fs::read(path)?);
    let mut document: KeyDocument = serde_json::from_slice(&bytes)?;
    bytes.zeroize();
    if document.version != 1 || document.role != "prediction_market_trader" {
        bail!("unexpected prediction-market key identity");
    }
    let secret_bytes = Zeroizing::new(hex::decode(&document.secret_key_hex)?);
    let secret = SecretKey::from_slice(&secret_bytes)?;
    let derived = hex::encode(
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), &secret))
            .0
            .serialize(),
    );
    if derived != document.public_key_xonly {
        bail!("prediction-market key self-check failed");
    }
    document.zeroize();
    Ok(secret)
}

fn hash32(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("decode {label}"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    #[test]
    fn protected_key_round_trip_and_no_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trader.json");
        let identity = generate(&path).unwrap();
        let secret = load_key(&path).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        assert_eq!(
            identity.public_key_xonly,
            hex::encode(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
        );
        assert!(generate(&path).is_err());
    }

    #[tokio::test]
    async fn http_signer_requires_auth_and_returns_verifiable_commitment() {
        let secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let public =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), &secret))
                .0
                .serialize();
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let app = signer_router(SignerState {
            secret,
            public,
            chain_id: [7; 32],
            payout_script_sha256: [9; 32],
            token: Arc::new(Zeroizing::new(token.clone())),
        });
        let unauthorized = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let payload = serde_json::json!({"version":1,"chainId":hex::encode([7;32]),"marketId":hex::encode([1;32]),"traderCommitment":hex::encode(public),"payoutScriptSha256":hex::encode([9;32]),"nonce":"12","outcome":1,"side":"buy","outcomeQuantityUnits":"10000","limitProbabilityPpb":999999999});
        let signed = app
            .oneshot(
                Request::post("/v1/prediction-market/sign")
                    .header(
                        "authorization",
                        format!("Bearer {}", String::from_utf8(token).unwrap()),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signed.status(), StatusCode::OK);
        let body = to_bytes(signed.into_body(), 64 * 1024).await.unwrap();
        let output: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(output["orderCommitment"].as_str().unwrap().len(), 64);
        assert_eq!(output["signature"].as_str().unwrap().len(), 128);
    }
}
