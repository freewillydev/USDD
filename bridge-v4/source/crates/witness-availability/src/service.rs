use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};
use zeroize::Zeroizing;

use crate::{
    crypto::{CustodianSecrets, CustodyReceiptV1},
    error::{AvailabilityError, Result},
    format::{WitnessBundle, MAX_BUNDLE_BYTES},
    store::{BundleStore, PutOutcome},
};

const MAX_SERVICE_CONCURRENT_REQUESTS: usize = 32;
const SERVICE_HANDLER_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ServiceConfig {
    pub store: Arc<BundleStore>,
    pub custodian: Option<Arc<CustodianSecrets>>,
    upload_token: Zeroizing<Vec<u8>>,
    read_token: Zeroizing<Vec<u8>>,
    recovery_token: Zeroizing<Vec<u8>>,
}

impl ServiceConfig {
    pub fn new(
        store: Arc<BundleStore>,
        custodian: Option<Arc<CustodianSecrets>>,
        upload_token: Vec<u8>,
        read_token: Vec<u8>,
        recovery_token: Vec<u8>,
    ) -> Result<Self> {
        store.durability_probe()?;
        for token in [&upload_token, &read_token, &recovery_token] {
            validate_bearer_token(token)?;
        }
        if upload_token == read_token
            || upload_token == recovery_token
            || read_token == recovery_token
        {
            return Err(AvailabilityError::Canonical(
                "upload, read, and recovery bearer tokens must be distinct",
            ));
        }
        Ok(Self {
            store,
            custodian,
            upload_token: Zeroizing::new(upload_token),
            read_token: Zeroizing::new(read_token),
            recovery_token: Zeroizing::new(recovery_token),
        })
    }
}

fn validate_bearer_token(token: &[u8]) -> Result<()> {
    if !(32..=256).contains(&token.len()) || !token.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(AvailabilityError::Canonical(
            "bearer token must contain 32 to 256 visible ASCII bytes",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct AppState {
    store: Arc<BundleStore>,
    custodian: Option<Arc<CustodianSecrets>>,
}

#[derive(Clone)]
struct BearerAuth {
    token: Arc<Zeroizing<Vec<u8>>>,
}

pub struct AvailabilityService {
    router: Router,
}

impl AvailabilityService {
    pub fn new(config: ServiceConfig) -> Self {
        let state = AppState {
            store: config.store,
            custodian: config.custodian,
        };
        let upload = Router::new()
            .route("/v1/bundles", post(put_bundle))
            .route_layer(middleware::from_fn_with_state(
                BearerAuth {
                    token: Arc::new(config.upload_token),
                },
                require_bearer,
            ));
        let read = Router::new()
            .route("/v1/bundles/{root}", get(get_bundle))
            .route_layer(middleware::from_fn_with_state(
                BearerAuth {
                    token: Arc::new(config.read_token),
                },
                require_bearer,
            ));
        let recovery = Router::new()
            .route("/v1/bundles/{root}/attest", post(attest_bundle))
            .route_layer(middleware::from_fn_with_state(
                BearerAuth {
                    token: Arc::new(config.recovery_token),
                },
                require_bearer,
            ));
        let router = Router::new()
            .route("/health", get(health))
            .merge(upload)
            .merge(read)
            .merge(recovery)
            .layer(RequestBodyLimitLayer::new(MAX_BUNDLE_BYTES))
            .layer(ConcurrencyLimitLayer::new(MAX_SERVICE_CONCURRENT_REQUESTS))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::GATEWAY_TIMEOUT,
                SERVICE_HANDLER_TIMEOUT,
            ))
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        Self { router }
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        axum::serve(listener, self.router).await
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol: &'static str,
    role: &'static str,
    custodian_index: Option<u8>,
    encryption_public_key: Option<String>,
    attestation_public_key: Option<String>,
    storage: &'static str,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let custodian = state.custodian.as_ref().map(|secrets| secrets.public());
    Json(HealthResponse {
        status: "ok",
        protocol: "ecx-witness-availability-v1",
        role: if custodian.is_some() {
            "custodian"
        } else {
            "replica"
        },
        custodian_index: custodian.map(|value| value.index),
        encryption_public_key: custodian.map(|value| hex::encode(value.encryption_public_key)),
        attestation_public_key: custodian.map(|value| hex::encode(value.attestation_public_key)),
        storage: "durable_write_verified_at_startup",
    })
}

#[derive(Serialize)]
struct PutResponse {
    root: String,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    custody_receipt: Option<CustodyReceiptResponse>,
}

#[derive(Serialize)]
struct CustodyReceiptResponse {
    version: u8,
    bundle_root: String,
    context: String,
    witness_len: u64,
    custodian_index: u8,
    signature: String,
}

impl From<CustodyReceiptV1> for CustodyReceiptResponse {
    fn from(receipt: CustodyReceiptV1) -> Self {
        Self {
            version: receipt.version,
            bundle_root: hex::encode(receipt.bundle_root),
            context: hex::encode(receipt.context),
            witness_len: receipt.witness_len,
            custodian_index: receipt.custodian_index,
            signature: hex::encode(receipt.signature),
        }
    }
}

async fn put_bundle(
    State(state): State<AppState>,
    body: Bytes,
) -> std::result::Result<(StatusCode, Json<PutResponse>), ApiError> {
    let store = state.store.clone();
    let custodian = state.custodian.clone();
    let (root, outcome, custody_receipt) = tokio::task::spawn_blocking(move || {
        let bundle = WitnessBundle::decode(&body)?;
        let (root, outcome) = store.put(&bundle)?;
        // BundleStore::put fsyncs both the immutable file and its directory
        // before this receipt is created.
        let receipt = custodian
            .as_ref()
            .map(|value| value.custody_receipt(&bundle))
            .transpose()?
            .map(CustodyReceiptResponse::from);
        Ok::<_, AvailabilityError>((root, outcome, receipt))
    })
    .await
    .map_err(|_| AvailabilityError::WorkerFailure)??;
    let status = match outcome {
        PutOutcome::Created => StatusCode::CREATED,
        PutOutcome::AlreadyPresent => StatusCode::OK,
    };
    Ok((
        status,
        Json(PutResponse {
            root: hex::encode(root),
            outcome: match outcome {
                PutOutcome::Created => "created",
                PutOutcome::AlreadyPresent => "already_present",
            },
            custody_receipt,
        }),
    ))
}

async fn get_bundle(
    State(state): State<AppState>,
    Path(root): Path<String>,
) -> std::result::Result<Response, ApiError> {
    let root = BundleStore::parse_root_hex(&root)?;
    let store = state.store.clone();
    let encoded = tokio::task::spawn_blocking(move || {
        let bundle = store.get(&root)?;
        bundle.encode()
    })
    .await
    .map_err(|_| AvailabilityError::WorkerFailure)??;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "public, immutable"),
        ],
        Body::from(encoded),
    )
        .into_response())
}

#[derive(Serialize)]
struct AttestationResponse {
    bundle_root: String,
    custodian_index: u8,
    share: String,
    signature: String,
}

async fn attest_bundle(
    State(state): State<AppState>,
    Path(root): Path<String>,
) -> std::result::Result<Json<AttestationResponse>, ApiError> {
    let root = BundleStore::parse_root_hex(&root)?;
    let store = state.store.clone();
    let custodian = state
        .custodian
        .clone()
        .ok_or(ApiError(AvailabilityError::NotFound))?;
    let contribution = tokio::task::spawn_blocking(move || {
        let bundle = store.get(&root)?;
        custodian.attest(&bundle)
    })
    .await
    .map_err(|_| AvailabilityError::WorkerFailure)??;
    Ok(Json(AttestationResponse {
        bundle_root: hex::encode(contribution.bundle_root),
        custodian_index: contribution.custodian_index,
        share: hex::encode(contribution.share),
        signature: hex::encode(contribution.signature),
    }))
}

async fn require_bearer(
    State(auth): State<BearerAuth>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, ApiError> {
    authorize(request.headers(), auth.token.as_ref())?;
    Ok(next.run(request).await)
}

fn authorize(headers: &HeaderMap, expected_token: &[u8]) -> Result<()> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    let mut expected = Vec::with_capacity(7 + expected_token.len());
    expected.extend_from_slice(b"Bearer ");
    expected.extend_from_slice(expected_token);
    if supplied.len() != expected.len() || !bool::from(supplied.ct_eq(&expected)) {
        return Err(AvailabilityError::Unauthorized);
    }
    Ok(())
}

struct ApiError(AvailabilityError);

impl From<AvailabilityError> for ApiError {
    fn from(value: AvailabilityError) -> Self {
        Self(value)
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self.0 {
            AvailabilityError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AvailabilityError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AvailabilityError::TooLarge | AvailabilityError::WitnessSize { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, "too_large")
            }
            AvailabilityError::CorruptStore
            | AvailabilityError::WorkerFailure
            | AvailabilityError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_failure"),
            AvailabilityError::Aead
            | AvailabilityError::InvalidShare
            | AvailabilityError::InvalidAttestation
            | AvailabilityError::NonContributoryKey => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "cryptographic_validation_failed",
            ),
            _ => (StatusCode::BAD_REQUEST, "invalid_request"),
        };
        (status, Json(ErrorResponse { error: code })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::{create_bundle, recover_witness, verify_custody_receipts, RecoveryContribution};

    fn hex_array<const N: usize>(value: &serde_json::Value) -> [u8; N] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[tokio::test]
    async fn five_independent_services_survive_two_custodian_losses() {
        let keys: Vec<_> = (1..=5)
            .map(|index| Arc::new(CustodianSecrets::generate(index).unwrap()))
            .collect();
        let public: Vec<_> = keys.iter().map(|key| key.public()).collect();
        let bundle = create_bundle([0x55; 32], b"five-service failover witness", &public).unwrap();
        let encoded = bundle.encode().unwrap();
        let root = bundle.root().unwrap();
        let upload_token = b"five-service-upload-token-0000000001".to_vec();
        let read_token = b"five-service-read-token-000000000002".to_vec();
        let recovery_token = b"five-service-recovery-token-0000003".to_vec();
        let upload_authorization = format!(
            "Bearer {}",
            String::from_utf8(upload_token.clone()).unwrap()
        );
        let recovery_authorization = format!(
            "Bearer {}",
            String::from_utf8(recovery_token.clone()).unwrap()
        );

        let mut directories = Vec::new();
        let mut services = Vec::new();
        for key in &keys {
            let directory = tempfile::tempdir().unwrap();
            let store = Arc::new(BundleStore::open(directory.path().join("store")).unwrap());
            let router = AvailabilityService::new(
                ServiceConfig::new(
                    store,
                    Some(key.clone()),
                    upload_token.clone(),
                    read_token.clone(),
                    recovery_token.clone(),
                )
                .unwrap(),
            )
            .router();
            directories.push(directory);
            services.push(router);
        }

        let mut receipts = Vec::new();
        for service in &services {
            let response = service
                .clone()
                .oneshot(
                    Request::post("/v1/bundles")
                        .header(header::AUTHORIZATION, &upload_authorization)
                        .body(Body::from(encoded.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let receipt = &value["custody_receipt"];
            receipts.push(CustodyReceiptV1 {
                version: receipt["version"].as_u64().unwrap().try_into().unwrap(),
                bundle_root: hex_array(&receipt["bundle_root"]),
                context: hex_array(&receipt["context"]),
                witness_len: receipt["witness_len"].as_u64().unwrap(),
                custodian_index: receipt["custodian_index"]
                    .as_u64()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                signature: hex_array(&receipt["signature"]),
            });
        }
        verify_custody_receipts(&bundle, &receipts).unwrap();

        // Custodians 2 and 4 are unavailable. Recovery uses only 1, 3, and 5.
        let mut contributions = Vec::new();
        for position in [0_usize, 2, 4] {
            let response = services[position]
                .clone()
                .oneshot(
                    Request::post(format!("/v1/bundles/{}/attest", hex::encode(root)))
                        .header(header::AUTHORIZATION, &recovery_authorization)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            contributions.push(RecoveryContribution {
                bundle_root: hex_array(&value["bundle_root"]),
                custodian_index: value["custodian_index"]
                    .as_u64()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                share: hex_array(&value["share"]),
                signature: hex_array(&value["signature"]),
            });
        }
        let recovered = recover_witness(&bundle, &contributions).unwrap();
        assert_eq!(recovered.as_bytes(), b"five-service failover witness");
        assert_eq!(directories.len(), 5);
    }

    #[tokio::test]
    async fn authenticated_put_get_and_attest_round_trip() {
        let mut keys: Vec<_> = (1..=5)
            .map(|i| CustodianSecrets::generate(i).unwrap())
            .collect();
        let public: Vec<_> = keys.iter().map(CustodianSecrets::public).collect();
        let bundle = create_bundle([5; 32], b"service witness", &public).unwrap();
        let root = bundle.root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(BundleStore::open(temp.path().join("store")).unwrap());
        let upload_token = b"upload-token-with-at-least-32-bytes-01".to_vec();
        let read_token = b"read-token-with-at-least-32-bytes---02".to_vec();
        let recovery_token = b"recovery-token-with-at-least-32-byte-03".to_vec();
        let app = AvailabilityService::new(
            ServiceConfig::new(
                store,
                Some(Arc::new(keys.remove(0))),
                upload_token.clone(),
                read_token.clone(),
                recovery_token.clone(),
            )
            .unwrap(),
        )
        .router();

        let health = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let health_body = health.into_body().collect().await.unwrap().to_bytes();
        let health_json: serde_json::Value = serde_json::from_slice(&health_body).unwrap();
        assert_eq!(health_json["status"], "ok");
        assert_eq!(health_json["protocol"], "ecx-witness-availability-v1");
        assert_eq!(health_json["role"], "custodian");
        assert_eq!(health_json["storage"], "durable_write_verified_at_startup");
        assert_eq!(health_json["custodian_index"], public[0].index);
        assert_eq!(
            health_json["encryption_public_key"],
            hex::encode(public[0].encryption_public_key)
        );
        assert_eq!(
            health_json["attestation_public_key"],
            hex::encode(public[0].attestation_public_key)
        );

        let unauthorized = app
            .clone()
            .oneshot(
                Request::post("/v1/bundles")
                    .body(Body::from(bundle.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let upload_authorization = format!(
            "Bearer {}",
            String::from_utf8(upload_token.clone()).unwrap()
        );
        let put = app
            .clone()
            .oneshot(
                Request::post("/v1/bundles")
                    .header(header::AUTHORIZATION, &upload_authorization)
                    .body(Body::from(bundle.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::CREATED);
        let put_body = put.into_body().collect().await.unwrap().to_bytes();
        let put_json: serde_json::Value = serde_json::from_slice(&put_body).unwrap();
        let receipt = &put_json["custody_receipt"];
        assert_eq!(receipt["version"], 1);
        assert_eq!(receipt["bundle_root"], hex::encode(root));
        assert_eq!(receipt["context"], hex::encode(bundle.context));
        assert_eq!(receipt["witness_len"], bundle.witness_len);
        assert_eq!(receipt["custodian_index"], 1);
        assert_eq!(receipt["signature"].as_str().unwrap().len(), 128);

        let cross_role = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/bundles/{}", hex::encode(root)))
                    .header(header::AUTHORIZATION, &upload_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_role.status(), StatusCode::UNAUTHORIZED);

        let read_authorization = format!("Bearer {}", String::from_utf8(read_token).unwrap());
        let get = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/bundles/{}", hex::encode(root)))
                    .header(header::AUTHORIZATION, &read_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        let bytes = get.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(WitnessBundle::decode(&bytes).unwrap(), bundle);

        let recovery_authorization =
            format!("Bearer {}", String::from_utf8(recovery_token).unwrap());
        let attest = app
            .oneshot(
                Request::post(format!("/v1/bundles/{}/attest", hex::encode(root)))
                    .header(header::AUTHORIZATION, &recovery_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(attest.status(), StatusCode::OK);
    }

    #[test]
    fn service_tokens_must_be_distinct_and_strong() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(BundleStore::open(temporary.path().join("bundles")).unwrap());
        let repeated = b"one-repeated-token-with-at-least-32-bytes".to_vec();
        assert!(
            ServiceConfig::new(store, None, repeated.clone(), repeated.clone(), repeated,).is_err()
        );
    }
}
