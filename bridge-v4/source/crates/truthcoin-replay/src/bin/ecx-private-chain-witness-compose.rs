use std::{env, fs, path::PathBuf};

use bitcoin::{consensus::deserialize, Block};
use ecx_truthcoin_proof::{
    pinned_truthcoin_chain_id, ParentChainContextV1, TruthcoinAuthenticationConfigV1,
    TruthcoinMarketTemplateCommitmentV1, TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
    TRUTHCOIN_LMSR_MATH_COMMITMENT, TRUTHCOIN_SIDECHAIN_NUMBER, TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
    TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
};
use ecx_truthcoin_replay::{
    verify_replay_structure, CoinbaseInclusionV1, MainchainBlockTransactionsV1, MainchainHeaderV1,
    ReplayInputV1, TruthcoinBip300CheckpointStateV1, TruthcoinBlockV1, REPLAY_INPUT_VERSION,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct BitcoinExport {
    checkpoint_height: u64,
    checkpoint_hash_bytes: [u8; 32],
    tip_height: u64,
    tip_hash_bytes: [u8; 32],
    tip_median_time_past: u64,
    checkpoint_mtp_headers: Vec<Vec<u8>>,
    mainchain_headers: Vec<MainchainHeaderV1>,
    coinbase_inclusions: Vec<CoinbaseInclusionV1>,
}

#[derive(Deserialize)]
struct SidechainExport {
    blocks: Vec<TruthcoinBlockV1>,
}

#[derive(Deserialize)]
struct FullBitcoinExport {
    blocks: Vec<FullBitcoinBlock>,
}

#[derive(Deserialize)]
struct FullBitcoinBlock {
    height: u64,
    serialized_block: Vec<u8>,
}

fn label_hash(label: &[u8]) -> [u8; 32] {
    Sha256::digest(label).into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let bitcoin_path = PathBuf::from(args.next().ok_or("missing Bitcoin export path")?);
    let sidechain_path = PathBuf::from(args.next().ok_or("missing sidechain export path")?);
    let full_bitcoin_path = PathBuf::from(args.next().ok_or("missing full Bitcoin export path")?);
    let output_path = PathBuf::from(args.next().ok_or("missing output path")?);
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let bitcoin: BitcoinExport = serde_json::from_slice(&fs::read(bitcoin_path)?)?;
    let sidechain: SidechainExport = serde_json::from_slice(&fs::read(sidechain_path)?)?;
    let full_bitcoin: FullBitcoinExport = serde_json::from_slice(&fs::read(full_bitcoin_path)?)?;
    let mainchain_block_transactions = full_bitcoin
        .blocks
        .into_iter()
        .map(|export| {
            let block: Block = deserialize(&export.serialized_block)?;
            Ok(MainchainBlockTransactionsV1 {
                version: MainchainBlockTransactionsV1::VERSION,
                height: export.height,
                transactions: block
                    .txdata
                    .iter()
                    .map(bitcoin::consensus::serialize)
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, bitcoin::consensus::encode::Error>>()?;
    let genesis = sidechain
        .blocks
        .first()
        .ok_or("sidechain export is empty")?
        .block_hash();

    // Candidate-only template used to exercise the authenticated replay boundary.
    // The native roundtrip does not yet create the frozen production BTC/USD market.
    let market_template = TruthcoinMarketTemplateCommitmentV1 {
        version: TruthcoinMarketTemplateCommitmentV1::VERSION,
        market_title_template: "BTC/USD {period}".to_owned(),
        market_description_template: "Bitcoin price in USD".to_owned(),
        decision_header_template: "BTC/USD".to_owned(),
        decision_description_template: "Final scalar price".to_owned(),
        decision_tags: vec!["btc".to_owned(), "usd".to_owned()],
        scalar_min_f64_bits: 40_000_f64.to_bits(),
        scalar_max_f64_bits: 80_000_f64.to_bits(),
        scalar_increment_f64_bits: 1_f64.to_bits(),
        minimum_liquidity_sats: 10_000,
        trading_fee_ppm: 1_000,
        tx_pow_hash_selector: 0,
        tx_pow_ordering: 0,
        tx_pow_difficulty: 1,
    };
    // Production-period private chains activate sidechain 13 before the epoch
    // checkpoint, so the frozen post-checkpoint BIP300 state is active with no
    // CTIP yet (first M5 deposit arrives later in the header window). Older
    // retained chains that activated after the checkpoint must keep this false.
    let production_period_active = env::var_os("ECX_BIP300_SLOT_ACTIVE_AT_CHECKPOINT")
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    let bip300_checkpoint_state = TruthcoinBip300CheckpointStateV1 {
        version: TruthcoinBip300CheckpointStateV1::VERSION,
        truthcoin_slot_active: production_period_active,
        ctip: None,
    };
    let authentication = TruthcoinAuthenticationConfigV1 {
        version: TruthcoinAuthenticationConfigV1::VERSION,
        source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
        consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
        source_patch_manifest_sha256: TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
        sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
        bitcoin_checkpoint_hash: bitcoin.checkpoint_hash_bytes,
        bitcoin_checkpoint_height: bitcoin.checkpoint_height,
        bip300_checkpoint_state_hash: bip300_checkpoint_state.digest(),
        genesis_sidechain_block_hash: genesis,
        truthcoin_chain_id: pinned_truthcoin_chain_id(genesis),
        truthcoin_branch_id: label_hash(b"ECX/private-regtest-branch/candidate-v1"),
        btc_usd_template_hash: market_template.digest(),
        lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
        // These two identities are intentionally not frozen release values.
        source_proof_program_id: label_hash(b"ECX/unreleased-truthcoin-program/candidate-v1"),
        selection_rule_hash: label_hash(b"ECX/unreleased-selection-rule/candidate-v1"),
        minimum_bitcoin_confirmations: 1,
        maximum_proof_bytes: ecx_protocol_core::MAX_TRUTHCOIN_PROOF_BYTES,
    };
    let input = ReplayInputV1 {
        version: REPLAY_INPUT_VERSION,
        authentication,
        parent: ParentChainContextV1 {
            block_hash: bitcoin.tip_hash_bytes,
            height: bitcoin.tip_height,
            median_time_past: bitcoin.tip_median_time_past,
        },
        market_template,
        bip300_checkpoint_state,
        mainchain_headers: bitcoin.mainchain_headers,
        checkpoint_mtp_headers: bitcoin.checkpoint_mtp_headers,
        coinbase_inclusions: bitcoin.coinbase_inclusions,
        mainchain_block_transactions,
        sidechain_blocks: sidechain.blocks,
    };

    let structure = verify_replay_structure(&input)?;
    fs::write(&output_path, serde_json::to_vec(&input)?)?;
    eprintln!(
        "candidate ReplayInputV1 structurally verified: parent_height={} side_tip_height={} side_blocks={}",
        input.parent.height,
        structure.sidechain_tip_height,
        input.sidechain_blocks.len()
    );
    Ok(())
}
