//! Opt-in read-only live boundary test. No orders, signing or transactions.
use ecx_matcher::ElementsRpcClient;
use serde_json::Value;

#[tokio::test]
#[ignore = "requires explicit live Alpha endpoint, cookie and frozen profile paths"]
async fn live_alpha_successor_matches_frozen_profile() {
    let endpoint = std::env::var("ECX_E2E_RPC_URL").unwrap();
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let cookie = std::fs::read_to_string(std::env::var("ECX_E2E_COOKIE_PATH").unwrap()).unwrap();
    let (username, password) = cookie.trim().split_once(':').expect("cookie format");
    let client = ElementsRpcClient::new(&endpoint, Some(username.into()), Some(password.into())).unwrap();
    let profile: Value = serde_json::from_slice(&std::fs::read(
        std::env::var("ECX_E2E_PROFILE_PATH").unwrap()).unwrap()).unwrap();
    let context = client.successor_consensus_context().await.expect("live successor decoder");
    // Node RPC hashes use display order; profile arguments use canonical bytes.
    let expected = |name: &str| -> [u8; 32] {
        let bytes = hex::decode(profile["arguments"][name].as_str().unwrap()).unwrap();
        let mut hash: [u8; 32] = bytes.try_into().unwrap();
        hash.reverse();
        hash
    };
    assert_eq!(context.successor_configuration_hash, expected("-ecxbondv2incrementalsuccessorconfigurationhash"));
    assert_eq!(context.transition_program_id, expected("-ecxbondv2incrementalsuccessorprogramid"));
    assert_eq!(context.transition_cmr, expected("-ecxbondv2incrementalsuccessortransitioncmr"));
    context.matcher_context().expect("usable successor matcher clock");
    assert!(client.consensus_context().await.is_err(), "finite profile must not accept successor wire data");
    let refreshed = client.successor_consensus_context_after(&context).await.expect("stable context/ancestry");
    assert!(refreshed.sidechain_height >= context.sidechain_height);
    println!("read-only live successor accepted at child {}, parent {}; frozen profile identities match", refreshed.sidechain_height, refreshed.parent_height);
}
