//! Read-only offline verification of the deployed test token/quote MPT paths.
//! This does NOT authenticate the supplied execution state root with beacon
//! finality and cannot qualify a USDD checkpoint, custody, or complete proof.

use alloy_primitives::keccak256;
use ecx_conversion_foundation_v2::usdd_usd::{
    u256_be_to_u64, verify_ethereum_account_mpt_v2, verify_ethereum_storage_mpt_v2,
    EthereumAccountMptWitnessV2, EthereumStorageMptWitnessV2,
};
use serde::Deserialize;
use std::{env, fs};

const SCHEMA: &str = "ALPHA_SEPOLIA_TEST_DOLLAR_MPT_INPUT_V1";
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    account: EthereumAccountMptWitnessV2,
    storage: EthereumStorageMptWitnessV2,
    expected_runtime_code_hash: [u8; 32],
    runtime_code: Vec<u8>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: String,
    chain_id: u64,
    finality_qualified: bool,
    state_root: [u8; 32],
    token: Contract,
    quote: Contract,
}

fn verify_contract(root: [u8; 32], c: &Contract) -> Result<(), String> {
    if c.runtime_code.is_empty() || c.runtime_code.len() > 24_576 {
        return Err("invalid runtime size".into());
    }
    if keccak256(&c.runtime_code).0 != c.expected_runtime_code_hash
        || c.account.code_hash != c.expected_runtime_code_hash
    {
        return Err("runtime/code-hash identity mismatch".into());
    }
    let account = verify_ethereum_account_mpt_v2(root, &c.account)
        .map_err(|e| format!("account proof: {e}"))?;
    if c.storage.storage_key != [0; 32] {
        return Err("expected token totalSupply / quote slot zero".into());
    }
    verify_ethereum_storage_mpt_v2(account.storage_root, &c.storage)
        .map_err(|e| format!("storage proof: {e}"))?;
    Ok(())
}

fn verify(input: &Input) -> Result<(), String> {
    if input.schema != SCHEMA || input.chain_id != 11_155_111 || input.finality_qualified {
        return Err("wrong schema/chain or unsupported finality qualification".into());
    }
    if input.token.account.address == input.quote.account.address {
        return Err("token and quote addresses must differ".into());
    }
    verify_contract(input.state_root, &input.token)?;
    verify_contract(input.state_root, &input.quote)?;
    if u256_be_to_u64(input.quote.storage.value_be).map_err(|e| e.to_string())? != 100_000_000 {
        return Err("nominal test-dollar quote is not 100000000".into());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: sepolia-test-dollar-mpt-check <input.json>".into());
    }
    let metadata = fs::symlink_metadata(&args[0]).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err("input must be a bounded regular file".into());
    }
    let bytes = fs::read(&args[0]).map_err(|e| e.to_string())?;
    let input: Input = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    verify(&input)?;

    // Use this live proof vector for mandatory negative controls. None can be
    // accepted merely because the RPC metadata or JSON claims it is valid.
    let mut cases = Vec::new();
    let mut altered = input.clone();
    altered.state_root[0] ^= 1;
    cases.push(("wrong_state_root", altered));
    let mut altered = input.clone();
    altered.token.account.address[0] ^= 1;
    cases.push(("wrong_token_address", altered));
    let mut altered = input.clone();
    altered.quote.storage.value_be[31] ^= 1;
    cases.push(("wrong_quote_value", altered));
    let mut altered = input.clone();
    altered.quote.runtime_code[0] ^= 1;
    cases.push(("changed_quote_runtime", altered));
    let mut altered = input.clone();
    altered.token.account.proof_nodes.clear();
    cases.push(("missing_account_proof", altered));
    let mut altered = input.clone();
    altered.finality_qualified = true;
    cases.push(("unsupported_finality_claim", altered));
    for (name, altered) in &cases {
        if verify(altered).is_ok() {
            return Err(format!("negative control accepted: {name}"));
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": "ALPHA_SEPOLIA_TEST_DOLLAR_MPT_CHECK_V1",
            "accountAndStorageProofsValidAgainstSuppliedStateRoot": true,
            "runtimeCodeHashesMatchExpected": true,
            "nominalQuoteAtoms": 100_000_000,
            "negativeControlsRejected": cases.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            "beaconFinalityAuthenticated": false,
            "vaultOrCustodyQualified": false,
            "checkpointQualified": false,
            "proofReady": false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Sepolia binding MPT evidence rejected: {error}");
        std::process::exit(1);
    }
}
