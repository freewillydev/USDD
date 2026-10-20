use axum::{extract::State, routing::post, Json, Router};
use ecx_forced_action_client::{ecxf_script_hex, ElementsRpc, Error};
use ecx_protocol_core::{
    CancelOrder, ForcedActionV1, SignedCancelOrder, XOnlyKey, ECX_USDD_MARKET,
};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
struct MockState {
    expected_script: String,
    methods: Arc<Mutex<Vec<String>>>,
    reject: bool,
}

fn payload(chain_id: [u8; 32]) -> Vec<u8> {
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
    ForcedActionV1::Cancel(
        SignedCancelOrder::sign(
            CancelOrder {
                version: CancelOrder::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: XOnlyKey(public.serialize()),
                order_id: [8; 32],
                nonce: 3,
                valid_from_height: 5,
                expires_at_height: 50,
            },
            &secret,
        )
        .unwrap(),
    )
    .payload_bytes()
    .unwrap()
}

async fn rpc(State(state): State<MockState>, Json(request): Json<Value>) -> Json<Value> {
    let method = request["method"].as_str().unwrap().to_owned();
    state.methods.lock().unwrap().push(method.clone());
    let result = match method.as_str() {
        "createrawtransaction" => json!("raw"),
        "fundrawtransaction" => json!({"hex":"funded"}),
        "signrawtransactionwithwallet" => json!({"hex":"signed", "complete":true}),
        "decoderawtransaction" => json!({"vout":[
            {"scriptPubKey":{"hex":state.expected_script}},
            {"scriptPubKey":{"hex":"00140000000000000000000000000000000000000000"}}
        ]}),
        "testmempoolaccept" => {
            if state.reject {
                json!([{"allowed":false,"reject-reason":"policy"}])
            } else {
                json!([{"allowed":true}])
            }
        }
        "sendrawtransaction" => json!("11".repeat(32)),
        _ => panic!("unexpected method"),
    };
    // Bitcoin/Elements Core uses this legacy response envelope and omits a
    // `jsonrpc` version even when the request carries `"jsonrpc":"2.0"`.
    Json(json!({"id":1, "result":result, "error":null}))
}

async fn server(payload: &[u8], reject: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let methods = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        expected_script: ecxf_script_hex(payload).unwrap(),
        methods: methods.clone(),
        reject,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(rpc)).with_state(state),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), methods)
}

#[tokio::test]
async fn funds_signs_verifies_and_broadcasts_exact_payload() {
    let chain_id = [4; 32];
    let payload = payload(chain_id);
    let (url, methods) = server(&payload, false).await;
    let client = ElementsRpc::new(&url, None, None, Duration::from_secs(2)).unwrap();
    let receipt = client
        .broadcast_forced_action(&payload, chain_id)
        .await
        .unwrap();
    assert_eq!(receipt.txid, "11".repeat(32));
    assert_eq!(receipt.payload_hex, hex::encode(payload));
    assert_eq!(
        *methods.lock().unwrap(),
        [
            "createrawtransaction",
            "fundrawtransaction",
            "signrawtransactionwithwallet",
            "decoderawtransaction",
            "testmempoolaccept",
            "sendrawtransaction",
        ]
    );
}

#[tokio::test]
async fn fails_before_rpc_for_bad_chain_and_before_send_for_policy_rejection() {
    let chain_id = [4; 32];
    let payload = payload(chain_id);
    let (url, methods) = server(&payload, true).await;
    let client = ElementsRpc::new(&url, None, None, Duration::from_secs(2)).unwrap();
    assert!(matches!(
        client.broadcast_forced_action(&payload, [5; 32]).await,
        Err(Error::WrongChain)
    ));
    assert!(methods.lock().unwrap().is_empty());
    assert!(matches!(
        client.broadcast_forced_action(&payload, chain_id).await,
        Err(Error::MempoolRejected(_))
    ));
    assert!(!methods
        .lock()
        .unwrap()
        .iter()
        .any(|method| method == "sendrawtransaction"));
}

#[test]
fn rejects_remote_cleartext_rpc_and_encodes_pushdata_canonically() {
    assert!(matches!(
        ElementsRpc::new("http://example.com", None, None, Duration::from_secs(1)),
        Err(Error::InsecureRpcUrl)
    ));
    let mut payload = payload([4; 32]);
    payload.push(0);
    assert!(ecx_forced_action_client::ecxf_script_hex(&payload).is_ok());
}
