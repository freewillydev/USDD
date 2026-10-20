//! Opt-in real captured Alpha replay. No RPC, signing, spending, or proof run.
use ecx_truthcoin_replay::{
    execute_production_replay_from_bootstrap, ReplayInputV1, ReviewedNativeBootstrapV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Binding {
    bootstrap: ReviewedNativeBootstrapV1,
    bootstrap_commitment: [u8; 32],
    authentication_hash: [u8; 32],
}

#[test]
#[ignore = "requires hash-pinned real Alpha capture and bootstrap binding"]
fn captured_alpha_produces_authenticated_oracle_values() {
    assert!(cfg!(feature = "truthcoin-alpha-one-day-period"));
    let read_pinned = |path_key: &str, hash_key: &str| {
        let bytes = std::fs::read(std::env::var(path_key).expect(path_key)).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), std::env::var(hash_key).expect(hash_key));
        bytes
    };
    let mut input: ReplayInputV1 = serde_json::from_slice(&read_pinned(
        "ECX_E2E_REPLAY_PATH", "ECX_E2E_REPLAY_SHA256",
    )).unwrap();
    if std::env::var_os("ECX_E2E_SUFFIX_PATH").is_some() {
        use bitcoin::{consensus::{deserialize, serialize}, hashes::Hash};
        let suffix: serde_json::Value = serde_json::from_slice(&read_pinned(
            "ECX_E2E_SUFFIX_PATH", "ECX_E2E_SUFFIX_SHA256",
        )).unwrap();
        assert_eq!(suffix["base_height"], 996995);
        assert_eq!(suffix["endpoint"], 997104);
        for record in suffix["records"].as_array().unwrap() {
            let height = record["height"].as_u64().unwrap();
            let block: bitcoin::Block = deserialize(&hex::decode(record["serialized_block_hex"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(block.block_hash().to_string(), record["hash"].as_str().unwrap());
            assert!(block.check_merkle_root());
            let header = ecx_truthcoin_replay::MainchainHeaderV1 {height, consensus_header: serialize(&block.header)};
            let txs = ecx_truthcoin_replay::MainchainBlockTransactionsV1 {version: 1, height, transactions: block.txdata.iter().map(serialize).collect()};
            let inclusion = serde_json::from_value(record["inclusion"].clone()).unwrap();
            if height <= input.parent.height {
                assert_eq!(input.mainchain_headers.iter().find(|h| h.height == height).unwrap(), &header);
                assert_eq!(input.mainchain_block_transactions.iter().find(|h| h.height == height).unwrap(), &txs);
                assert_eq!(input.coinbase_inclusions.iter().find(|h| h.height == height).unwrap(), &inclusion);
            } else {
                assert_eq!(input.mainchain_headers.last().unwrap().height + 1, height);
                input.mainchain_headers.push(header);
                input.mainchain_block_transactions.push(txs);
                input.coinbase_inclusions.push(inclusion);
            }
        }
        for value in suffix["sidechain_blocks"].as_array().unwrap() {
            let child: ecx_truthcoin_replay::TruthcoinBlockV1 = serde_json::from_value(value.clone()).unwrap();
            if let Some(existing) = input.sidechain_blocks.iter().find(|c| c.height == child.height) {
                assert_eq!(existing, &child);
            } else { input.sidechain_blocks.push(child); }
        }
        let tip: bitcoin::block::Header = deserialize(&input.mainchain_headers.last().unwrap().consensus_header).unwrap();
        let mut times: Vec<u32> = input.mainchain_headers.iter().rev().take(11).map(|h| deserialize::<bitcoin::block::Header>(&h.consensus_header).unwrap().time).collect();
        times.sort_unstable();
        input.parent.height = 997104;
        input.parent.block_hash = tip.block_hash().to_byte_array();
        input.parent.median_time_past = u64::from(times[5]);
        eprintln!("assembled settlement replay: {} parents, {} children, MTP {}", input.mainchain_headers.len(), input.sidechain_blocks.len(), input.parent.median_time_past);
    }
    let binding: Binding = serde_json::from_slice(&read_pinned(
        "ECX_E2E_BOOTSTRAP_BINDING_PATH", "ECX_E2E_BOOTSTRAP_BINDING_SHA256",
    )).unwrap();
    assert_eq!(input.authentication.minimum_bitcoin_confirmations, 6);
    assert_eq!(input.authentication.digest(), binding.authentication_hash);
    let result = execute_production_replay_from_bootstrap(
        &input, &binding.bootstrap, binding.bootstrap_commitment, binding.authentication_hash,
    ).expect("real Alpha replay must produce an eligible authenticated oracle, not merely pass capture integrity");
    assert!(!result.public_values_bytes.is_empty());
}
