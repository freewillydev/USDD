//! Diagnose the first state-transition divergence in a structurally valid replay witness.

use std::{env, fs, str::FromStr};

use bitcoin::{hashes::Hash as _, hex::FromHex as _, Txid};
use ecx_truthcoin_proof::{
    pinned_truthcoin_chain_id, TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
    TRUTHCOIN_LMSR_MATH_COMMITMENT, TRUTHCOIN_SIDECHAIN_NUMBER, TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
};
use ecx_truthcoin_replay::{
    apply_authenticated_truthcoin_deposit, apply_truthcoin_block_transition,
    verify_production_replay_structure, verify_truthcoin_bip300_deposits, CanonicalStateStoreV1,
    ReplayInputV1,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct DepositExport {
    events: Vec<DepositEvent>,
}

#[derive(Deserialize)]
struct DepositEvent {
    mainchain_height: u64,
    txid_display: String,
    ctip_vout: u32,
    deposit_value_sats: u64,
    address_hex: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("witness diagnose: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let input_path = args.next().ok_or_else(|| {
        "usage: ecx-truthcoin-witness-diagnose INPUT.json [M5-DEPOSITS.json]".to_owned()
    })?;
    let deposits_path = args.next();
    if args.next().is_some() {
        return Err(
            "usage: ecx-truthcoin-witness-diagnose INPUT.json [M5-DEPOSITS.json]".to_owned(),
        );
    }
    let input_bytes =
        fs::read(&input_path).map_err(|error| format!("cannot read input: {error}"))?;
    let input: ReplayInputV1 = serde_json::from_slice(&input_bytes)
        .map_err(|error| format!("input is not ReplayInputV1 JSON: {error}"))?;
    input
        .authentication
        .validate()
        .map_err(|error| format!("authentication configuration rejected: {error}"))?;
    let configuration_checks = [
        (
            "source git commit",
            input.authentication.source_git_commit_sha1 == TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
        ),
        (
            "consensus source manifest",
            input.authentication.consensus_source_manifest_sha256
                == TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
        ),
        (
            "sidechain number",
            input.authentication.sidechain_number == TRUTHCOIN_SIDECHAIN_NUMBER,
        ),
        (
            "derived Truthcoin chain ID",
            input.authentication.truthcoin_chain_id
                == pinned_truthcoin_chain_id(input.authentication.genesis_sidechain_block_hash),
        ),
        (
            "LMSR math commitment",
            input.authentication.lmsr_math_commitment == TRUTHCOIN_LMSR_MATH_COMMITMENT,
        ),
        (
            "BIP300 checkpoint state",
            input.bip300_checkpoint_state.digest()
                == input.authentication.bip300_checkpoint_state_hash,
        ),
        (
            "BTC/USD market template",
            input.market_template.digest() == input.authentication.btc_usd_template_hash,
        ),
    ];
    if let Some((name, _)) = configuration_checks.iter().find(|(_, matches)| !matches) {
        return Err(format!("replay configuration mismatch: {name}"));
    }
    let structure = verify_production_replay_structure(&input)
        .map_err(|error| format!("production structural verification failed: {error}"))?;

    let deposits = match deposits_path {
        Some(path) => {
            let bytes = fs::read(path).map_err(|error| format!("cannot read deposits: {error}"))?;
            serde_json::from_slice::<DepositExport>(&bytes)
                .map_err(|error| format!("invalid deposit export: {error}"))?
                .events
        }
        None => Vec::new(),
    };
    let authenticated_deposits = verify_truthcoin_bip300_deposits(&input)
        .map_err(|error| format!("BIP300 deposit verification failed: {error:?} ({error})"))?;

    let mut store = CanonicalStateStoreV1::new();
    let mut next_deposit = 0_usize;
    let mut next_authenticated_deposit = 0_usize;
    for (index, (block, context)) in structure
        .canonical_sidechain_blocks
        .iter()
        .zip(&structure.canonical_block_contexts)
        .enumerate()
    {
        while let Some(deposit) = authenticated_deposits.get(next_authenticated_deposit) {
            if deposit.mainchain_height > context.bmm_main_height {
                break;
            }
            apply_authenticated_truthcoin_deposit(
                &mut store,
                deposit.txid,
                deposit.vout,
                deposit.address,
                deposit.value_sats,
            )
            .map_err(|error| format!("authenticated deposit rejected: {error:?} ({error})"))?;
            next_authenticated_deposit += 1;
        }
        while let Some(deposit) = deposits.get(next_deposit) {
            if deposit.mainchain_height > context.bmm_main_height {
                break;
            }
            let address_text = std::str::from_utf8(
                &Vec::<u8>::from_hex(&deposit.address_hex)
                    .map_err(|error| format!("invalid deposit address hex: {error}"))?,
            )
            .map_err(|error| format!("deposit address is not UTF-8: {error}"))?
            .to_owned();
            let base58 = if let Some(suffixed) = address_text.strip_prefix("s13_") {
                suffixed
                    .split('_')
                    .next()
                    .ok_or_else(|| format!("deposit address has no payload: {address_text}"))?
            } else {
                address_text.as_str()
            };
            let decoded = bitcoin::base58::decode(base58)
                .map_err(|error| format!("invalid base58 deposit address: {error}"))?;
            let address: [u8; 20] = decoded.try_into().map_err(|decoded: Vec<u8>| {
                format!(
                    "deposit address payload has {} bytes, expected 20",
                    decoded.len()
                )
            })?;
            let txid = Txid::from_str(&deposit.txid_display)
                .map_err(|error| format!("invalid deposit txid: {error}"))?;
            apply_authenticated_truthcoin_deposit(
                &mut store,
                txid.to_byte_array(),
                deposit.ctip_vout,
                address,
                deposit.deposit_value_sats,
            )
            .map_err(|error| {
                format!(
                    "deposit {} at parent height {} rejected: {error:?} ({error})",
                    next_deposit, deposit.mainchain_height
                )
            })?;
            next_deposit += 1;
        }
        if let Err(error) = apply_truthcoin_block_transition(&mut store, block, *context) {
            return Err(format!(
                "transition rejected canonical index {index}, sidechain height {}, parent height {}: {error:?} ({error})",
                block.height, context.bmm_main_height
            ));
        }
    }
    println!(
        "all {} canonical block transitions accepted; final sidechain height {} hash {} at parent height {}",
        structure.canonical_sidechain_blocks.len(),
        structure.sidechain_tip_height,
        hex_string(&structure.sidechain_tip_hash),
        structure
            .canonical_block_contexts
            .last()
            .map(|context| context.bmm_main_height)
            .unwrap_or_default(),
    );
    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
