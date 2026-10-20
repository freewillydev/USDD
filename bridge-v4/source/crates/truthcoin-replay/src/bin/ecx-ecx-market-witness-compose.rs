//! Compose a production-template ECX/USDD ReplayInputV1 from live exports.
//!
//! Unlike `ecx-private-chain-witness-compose`, this uses the frozen ECX keeper
//! market template (`ECX/USDD scalar price period {period}`) so `select_anchor` /
//! `select_market` can match markets created by `market_bootstrap`.

use std::{env, fs, io::Write, path::PathBuf};
use bitcoin::hashes::Hash;

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

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn required_program_id() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let value =
        env::var("ECX_TRUTHCOIN_PROGRAM_ID").map_err(|_| "ECX_TRUTHCOIN_PROGRAM_ID is required")?;
    let value = value.strip_prefix("0x").unwrap_or(&value);
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ECX_TRUTHCOIN_PROGRAM_ID must encode exactly 32 bytes".into());
    }
    let mut program_id = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)?;
        program_id[index] = u8::from_str_radix(text, 16)?;
    }
    Ok(program_id)
}

fn required_slot_active_at_checkpoint() -> Result<bool, Box<dyn std::error::Error>> {
    match env::var("ECX_BIP300_SLOT_ACTIVE_AT_CHECKPOINT")?.as_str() {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => Err("ECX_BIP300_SLOT_ACTIVE_AT_CHECKPOINT must be 0, 1, false, or true".into()),
    }
}

/// Canonical native ECX/USDD template (must match truthcoin-keeper.template.json).
fn ecx_usdd_market_template() -> TruthcoinMarketTemplateCommitmentV1 {
    TruthcoinMarketTemplateCommitmentV1 {
        version: TruthcoinMarketTemplateCommitmentV1::VERSION,
        market_title_template: "ECX/USDD scalar price period {period}".to_owned(),
        market_description_template:
            "Canonical ECX/USDD price forecast for Truthcoin period {period}".to_owned(),
        decision_header_template: "ECX/USDD at Truthcoin period {period} close".to_owned(),
        decision_description_template:
            "Canonical USDD per ECX scalar decision for Truthcoin period {period}".to_owned(),
        decision_tags: vec![
            "ecx-oracle-v2".to_owned(),
            "ecx-usdd".to_owned(),
            "native-elements".to_owned(),
        ],
        // User-approved Alpha market endpoints: 30–300 USDD per ECX.
        // These finite market bounds are not a DEX-wide price cap.
        scalar_min_f64_bits: 4_629_137_466_983_448_576,
        scalar_max_f64_bits: 4_643_985_272_004_935_680,
        scalar_increment_f64_bits: 4_576_918_229_304_087_675,
        // The Alpha bootstrap wallet is intentionally small. This is a
        // consensus minimum, not a cap: operators can permissionlessly
        // amplify the market before relying on it for a larger risk envelope.
        minimum_liquidity_sats: 10_000,
        trading_fee_ppm: 10_000,
        tx_pow_hash_selector: 0,
        tx_pow_ordering: 0,
        tx_pow_difficulty: 0,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().nth(1).as_deref() == Some("--bootstrap-suffix") {
        return bootstrap_suffix();
    }
    if env::args().nth(1).as_deref() == Some("--bootstrap-authentication") {
        return bootstrap_authentication();
    }
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

    let market_template = ecx_usdd_market_template();
    // Alpha slot 13 was active before the selected checkpoint. The exporter
    // and replay still authenticate the exact BIP300 state at that checkpoint.
    let bip300_checkpoint_state = TruthcoinBip300CheckpointStateV1 {
        version: TruthcoinBip300CheckpointStateV1::VERSION,
        truthcoin_slot_active: required_slot_active_at_checkpoint()?,
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
        truthcoin_branch_id: label_hash(b"ECX/truthcoin-alpha-slot13-branch/v1"),
        btc_usd_template_hash: market_template.digest(),
        lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
        source_proof_program_id: required_program_id()?,
        selection_rule_hash: label_hash(b"ECX/truthcoin-alpha-ecx-usdd-selection/v1"),
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
        "ECX-template ReplayInputV1 structurally verified: parent_height={} side_tip_height={} side_blocks={}",
        input.parent.height,
        structure.sidechain_tip_height,
        input.sidechain_blocks.len()
    );
    Ok(())
}

fn bootstrap_suffix() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufReader, Read};
    use serde::de::{Visitor, SeqAccess, Error};
    const START: u64 = 996717;
    #[derive(Deserialize)]
    struct Bound { authentication: TruthcoinAuthenticationConfigV1, bootstrap: ecx_truthcoin_replay::ReviewedNativeBootstrapV1 }
    #[derive(Deserialize)]
    struct Full { #[serde(deserialize_with = "suffix_blocks")] blocks: Vec<MainchainBlockTransactionsV1> }
    fn suffix_blocks<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<MainchainBlockTransactionsV1>, D::Error> {
        struct Blocks;
        impl<'de> Visitor<'de> for Blocks {
            type Value = Vec<MainchainBlockTransactionsV1>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("saved Bitcoin blocks") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(record) = seq.next_element::<FullBitcoinBlock>()? {
                    if record.height < START { continue; }
                    let block: Block = deserialize(&record.serialized_block).map_err(A::Error::custom)?;
                    if bitcoin::consensus::serialize(&block) != record.serialized_block { return Err(A::Error::custom("noncanonical block")); }
                    out.push(MainchainBlockTransactionsV1 { version: MainchainBlockTransactionsV1::VERSION, height:record.height, transactions:block.txdata.iter().map(bitcoin::consensus::serialize).collect() });
                }
                Ok(out)
            }
        }
        d.deserialize_seq(Blocks)
    }
    let args: Vec<PathBuf> = env::args_os().skip(2).map(PathBuf::from).collect();
    let [bound_path, bitcoin_path, sidechain_path, full_path, output] = args.as_slice() else { return Err("--bootstrap-suffix BOUND.json BITCOIN.json CHILD.json FULL.json CREATE_NEW.json".into()); };
    if output.exists() { return Err("output exists".into()); }
    let bound: Bound = serde_json::from_slice(&fs::read(bound_path)?)?;
    if bound.bootstrap.parent.height != START || encode_hex(bound.bootstrap.commitment()) != "26d5ecc593f85272be89e95452aa8fe1eb2a4935f17228340f5354b3f09ef2fd" { return Err("unexpected bootstrap".into()); }
    bound.bootstrap.import(bound.bootstrap.commitment(), bound.authentication.digest())?;
    let bitcoin_bytes = fs::read(bitcoin_path)?;
    let child_bytes = fs::read(sidechain_path)?;
    if encode_hex(Sha256::digest(&bitcoin_bytes)) != "00c1f402a48c424dccb02ad05c3251b774e354b6b008af31a95e645d33ca06db"
        || encode_hex(Sha256::digest(&child_bytes)) != "bfb99fbf527fea661f389ff48b3706cd8ef6c05ca37ab69aa56a6373ea68ff60" { return Err("saved export changed".into()); }
    let mut file = fs::File::open(full_path)?;
    let mut hasher = Sha256::new(); let mut buffer = [0u8;65536];
    loop { let n = file.read(&mut buffer)?; if n == 0 { break; } hasher.update(&buffer[..n]); }
    if encode_hex(hasher.finalize()) != "9f3b080d45ba4be08030dc333be7cf8d78a15583051407c2a780f49555f244dc" { return Err("full block export changed".into()); }
    let bitcoin: BitcoinExport = serde_json::from_slice(&bitcoin_bytes)?;
    let child: SidechainExport = serde_json::from_slice(&child_bytes)?;
    let full: Full = serde_json::from_reader(BufReader::new(fs::File::open(full_path)?))?;
    let mtp: Vec<_> = bitcoin.mainchain_headers.iter().filter(|h| h.height >= START - 11 && h.height < START).map(|h|h.consensus_header.clone()).collect();
    if mtp.len() != 11 { return Err("missing bootstrap MTP predecessors".into()); }
    let input = ReplayInputV1 {
        version:REPLAY_INPUT_VERSION, authentication:bound.authentication,
        parent:ParentChainContextV1 { block_hash:bitcoin.tip_hash_bytes, height:bitcoin.tip_height, median_time_past:bitcoin.tip_median_time_past },
        market_template:ecx_usdd_market_template(), bip300_checkpoint_state:bound.bootstrap.bip300.clone(),
        mainchain_headers:bitcoin.mainchain_headers.into_iter().filter(|h|h.height >= START).collect(),
        checkpoint_mtp_headers:mtp,
        coinbase_inclusions:bitcoin.coinbase_inclusions.into_iter().filter(|i|i.height >= START).collect(),
        mainchain_block_transactions:full.blocks,
        sidechain_blocks:child.blocks.into_iter().filter(|b|b.height > bound.bootstrap.checkpoint.sidechain_tip_height).collect(),
    };
    let result = ecx_truthcoin_replay::execute_production_replay_from_bootstrap(&input, &bound.bootstrap, bound.bootstrap.commitment(), input.authentication.digest());
    eprintln!("saved suffix: {} parent blocks, {} child blocks; native replay: {:?}", input.mainchain_headers.len(), input.sidechain_blocks.len(), result.as_ref().map(|_| "PASS"));
    // Diagnostic input only, not a successful witness or configuration output.
    let file = fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    let mut out = std::io::BufWriter::with_capacity(1024 * 1024, file);
    serde_json::to_writer(&mut out, &input)?;
    std::io::Write::flush(&mut out)?;
    out.get_ref().sync_all()?;
    Ok(())
}

/// Derive a candidate binding from the already pinned native snapshot.
/// This does not claim a successful suffix replay or a reviewed release.
fn bootstrap_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<PathBuf> = env::args_os().skip(2).map(PathBuf::from).collect();
    let [draft_path, sidechain_path, output] = args.as_slice() else {
        return Err("--bootstrap-authentication DRAFT.json SIDECHAIN.json CREATE_NEW.json".into());
    };
    let draft_bytes = fs::read(draft_path)?;
    let sidechain_bytes = fs::read(sidechain_path)?;
    if encode_hex(Sha256::digest(&draft_bytes)) != "ec42d1b357a48b3780647a42736ef39ff12ccc823c312cb157a2c49f9c599ea1"
        || encode_hex(Sha256::digest(&sidechain_bytes)) != "bfb99fbf527fea661f389ff48b3706cd8ef6c05ca37ab69aa56a6373ea68ff60" {
        return Err("frozen bootstrap or native block export changed".into());
    }
    let draft: serde_json::Value = serde_json::from_slice(&draft_bytes)?;
    let mut bootstrap: ecx_truthcoin_replay::ReviewedNativeBootstrapV1 = serde_json::from_value(draft["bootstrap"].clone())?;
    let pin = bootstrap.commitment();
    if encode_hex(pin) != "26d5ecc593f85272be89e95452aa8fe1eb2a4935f17228340f5354b3f09ef2fd" {
        return Err("bootstrap commitment differs from compiled guest pin".into());
    }
    let sidechain: SidechainExport = serde_json::from_slice(&sidechain_bytes)?;
    let genesis_blocks: Vec<_> = sidechain.blocks.iter().filter(|block| block.height == 0).collect();
    if genesis_blocks.len() != 1 { return Err("expected exactly one saved genesis".into()); }
    let genesis = genesis_blocks[0].block_hash();
    let header: bitcoin::block::Header = deserialize(&bootstrap.parent.consensus_header)?;
    let template = ecx_usdd_market_template();
    if template.digest() != bootstrap.checkpoint.market_template_hash { return Err("bootstrap market template mismatch".into()); }
    let authentication = TruthcoinAuthenticationConfigV1 {
        version: TruthcoinAuthenticationConfigV1::VERSION,
        source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
        consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
        source_patch_manifest_sha256: TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
        sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
        bitcoin_checkpoint_hash: header.block_hash().to_byte_array(),
        bitcoin_checkpoint_height: bootstrap.parent.height,
        bip300_checkpoint_state_hash: bootstrap.bip300.digest(),
        genesis_sidechain_block_hash: genesis,
        truthcoin_chain_id: pinned_truthcoin_chain_id(genesis),
        truthcoin_branch_id: label_hash(b"ECX/truthcoin-alpha-slot13-branch/v1"),
        btc_usd_template_hash: template.digest(),
        lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
        source_proof_program_id: required_program_id()?,
        selection_rule_hash: label_hash(b"ECX/truthcoin-alpha-ecx-usdd-selection/v1"),
        minimum_bitcoin_confirmations: 1,
        maximum_proof_bytes: ecx_protocol_core::MAX_TRUTHCOIN_PROOF_BYTES,
    };
    authentication.validate()?;
    let auth_hash = authentication.digest();
    bootstrap.checkpoint.authentication_config_hash = auth_hash;
    if bootstrap.commitment() != pin { return Err("authentication rebind changed compiled pin".into()); }
    bootstrap.import(pin, auth_hash)?;
    let document = serde_json::json!({"proof_ready":false, "status":"candidate authentication; source/release review and live suffix remain required", "authentication":authentication, "authentication_hash_hex":encode_hex(auth_hash), "bootstrap_commitment_hex":encode_hex(pin), "bootstrap":bootstrap});
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&document)?)?;
    file.sync_all()?;
    println!("candidate authentication {}", encode_hex(auth_hash));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_template_identity_and_units_are_frozen() {
        let template = ecx_usdd_market_template();
        assert_eq!(
            hex::encode(template.digest()),
            "974866e2f18868140ee8eed313f2e1a68dd35aa6572d2a087e93a07b25487911"
        );
        assert_eq!(f64::from_bits(template.scalar_min_f64_bits), 30.0);
        assert_eq!(f64::from_bits(template.scalar_max_f64_bits), 300.0);
        assert_eq!(f64::from_bits(template.scalar_increment_f64_bits), 0.01);
        assert!(template.market_title_template.contains("ECX/USDD"));
    }
}
