//! Offline diagnostic. Never signs, broadcasts, or generates a proof.
use bitcoin::{consensus::{deserialize, serialize}, hashes::Hash};
use ecx_truthcoin_replay::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::{BufReader, Read, Seek, SeekFrom}};

fn pinned<T: serde::de::DeserializeOwned>(path: &str, expected: &str) -> T {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop { let n = file.read(&mut chunk).unwrap(); if n == 0 { break; } hash.update(&chunk[..n]); }
    assert_eq!(hex::encode(hash.finalize()), expected);
    file.seek(SeekFrom::Start(0)).unwrap();
    serde_json::from_reader(BufReader::new(file)).unwrap()
}
#[derive(Deserialize)]
struct Binding { bootstrap: ReviewedNativeBootstrapV1, bootstrap_commitment: [u8;32], authentication_hash: [u8;32] }
#[derive(Deserialize)]
struct Parents { tip_height: u64, tip_hash_bytes: [u8;32], tip_median_time_past: u64,
    mainchain_headers: Vec<MainchainHeaderV1>, coinbase_inclusions: Vec<CoinbaseInclusionV1> }
#[derive(Deserialize)]
struct Full { blocks: Vec<Raw> }
#[derive(Deserialize)]
struct Raw {height:u64, block_hash_display:String, serialized_block:Vec<u8>, serialized_block_sha256:String}
#[derive(Deserialize)]
struct Children { blocks: Vec<TruthcoinBlockV1> }

#[test]
#[ignore = "requires preserved hash-pinned Mac Alpha artifacts"]
fn fresh_alpha_capture() {
    assert!(cfg!(feature="truthcoin-alpha-one-day-period"));
    let root = "/Volumes/T705/SERVERRR/alpha-conversion-integration.6iRnSa/";
    let capture = format!("{root}truthcoin-authenticated-export.gkPgui/");
    let binding: Binding = pinned(&format!("{root}checkpoint16-replay-input-candidate-20260909.json.binding.json"),
        "e2b11d2d9dfc6bf415b99c9ace0b07b0cef18ada9a2e388b9964b59378e9553c");
    assert_eq!(hex::encode(binding.bootstrap_commitment), "442cfe34e661699d3fc8c29defcb20ea747fbf1a2fa6fff227f502906b4d85a0");
    let mut input: ReplayInputV1 = pinned(&std::env::var("ECX_E2E_REPLAY_PATH").unwrap(), &std::env::var("ECX_E2E_REPLAY_SHA256").unwrap());
    assert_eq!(input.authentication.digest(), binding.authentication_hash);
    assert_eq!(input.authentication.minimum_bitcoin_confirmations,6);
    let floor = input.mainchain_headers.first().unwrap().height;
    assert_eq!(floor,996965);
    let parents: Parents = pinned(&format!("{capture}bitcoin-replay.json"), "5db124b95f68cbd389a86be201b4b4784d9d2a41f1f7ba2845d34ac0928fd7e7");
    let full: Full = pinned(&format!("{capture}bitcoin-full-blocks.json"), "9a2a6efd65d169f604cef7894630d893f7c0584792f1393f3fb67aa546bc3c2a");
    let children: Children = pinned(&format!("{capture}truthcoin-sidechain.json"), "6cbd5210abc3ed84d37407d613465cb35720126c77061e5e3891cef37cc7dc91");
    let headers: Vec<_> = parents.mainchain_headers.into_iter().filter(|v|v.height>=floor).collect();
    let inclusions: Vec<_> = parents.coinbase_inclusions.into_iter().filter(|v|v.height>=floor).collect();
    assert!(headers.starts_with(&input.mainchain_headers));
    assert!(inclusions.starts_with(&input.coinbase_inclusions));
    let mut txs = Vec::new();
    for raw in full.blocks.into_iter().filter(|v|v.height>=floor) {
        assert_eq!(raw.height, floor + txs.len() as u64);
        assert_eq!(hex::encode(Sha256::digest(&raw.serialized_block)),raw.serialized_block_sha256);
        let block: bitcoin::Block = deserialize(&raw.serialized_block).unwrap();
        assert_eq!(block.block_hash().to_string(),raw.block_hash_display);
        assert!(block.check_merkle_root());
        assert_eq!(serialize(&block.header),headers[txs.len()].consensus_header);
        txs.push(MainchainBlockTransactionsV1{version:1,height:raw.height,transactions:block.txdata.iter().map(serialize).collect()});
    }
    assert!(txs.starts_with(&input.mainchain_block_transactions));
    let child_blocks:Vec<_> = children.blocks.into_iter().filter(|v|v.bmm_main_height>floor).collect();
    for old in &input.sidechain_blocks { assert!(child_blocks.contains(old)); }
    input.mainchain_headers=headers; input.coinbase_inclusions=inclusions; input.mainchain_block_transactions=txs;
    input.sidechain_blocks=child_blocks;
    input.parent.height=parents.tip_height; input.parent.block_hash=parents.tip_hash_bytes;
    input.parent.median_time_past=parents.tip_median_time_past;
    assert_eq!(input.parent.height,997121);
    let tip: bitcoin::block::Header=deserialize(&input.mainchain_headers.last().unwrap().consensus_header).unwrap();
    assert_eq!(tip.block_hash().to_byte_array(),input.parent.block_hash);
    eprintln!("fresh replay: {} parents, {} children; no proof or broadcast",input.mainchain_headers.len(),input.sidechain_blocks.len());
    let template=&input.market_template;
    let mut charged_bytes=template.market_title_template.len()+template.market_description_template.len()
        +template.decision_header_template.len()+template.decision_description_template.len()
        +template.decision_tags.iter().map(|s|s.len()).sum::<usize>()
        +input.mainchain_headers.iter().map(|h|h.consensus_header.len()).sum::<usize>()
        +input.checkpoint_mtp_headers.iter().map(|h|h.len()).sum::<usize>()
        +input.coinbase_inclusions.iter().map(|c|c.coinbase_transaction.len()+32*c.merkle_siblings.len()).sum::<usize>();
    let mut charged_transactions=0usize;
    let mut first_excess=None;
    for block in &input.mainchain_block_transactions {
        charged_transactions+=block.transactions.len();
        if first_excess.is_none() && charged_transactions>MAX_REPLAY_TRANSACTIONS {
            first_excess=Some(format!("transaction count at parent {}: {} > {}",block.height,charged_transactions,MAX_REPLAY_TRANSACTIONS));
        }
        for tx in &block.transactions {
            charged_bytes+=tx.len();
            if first_excess.is_none() && charged_bytes>MAX_REPLAY_EVIDENCE_BYTES {
                first_excess=Some(format!("evidence bytes at parent {}: {} > {}",block.height,charged_bytes,MAX_REPLAY_EVIDENCE_BYTES));
            }
        }
    }
    for block in &input.sidechain_blocks {
        charged_bytes+=block.header_borsh.len()+block.body.coinbase_borsh.len()
            +block.body.authorizations_borsh.len()+block.body.actor_proofs_borsh.len()
            +block.body.transactions_borsh.iter().map(|t|t.len()).sum::<usize>();
        charged_transactions+=block.body.transactions_borsh.len();
    }
    eprintln!("resource diagnostic: evidence_bytes={charged_bytes}, transactions={charged_transactions}, first_parent_excess={first_excess:?}");
    let result=execute_production_replay_from_bootstrap(&input,&binding.bootstrap,binding.bootstrap_commitment,binding.authentication_hash);
    match result { Ok(v)=>{assert!(!v.public_values_bytes.is_empty()); eprintln!("native replay succeeded; public values {} bytes; guest qualification still required",v.public_values_bytes.len());}, Err(e)=>panic!("fresh native replay rejected: {e:?}") }
}
