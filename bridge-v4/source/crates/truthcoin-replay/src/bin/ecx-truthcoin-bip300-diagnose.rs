//! Verify complete Bitcoin transaction evidence and derive authenticated M5 deposits.

use std::{env, fs};

use ecx_truthcoin_replay::{
    verify_replay_structure, verify_truthcoin_bip300_deposits, ReplayInputV1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("BIP300 diagnose: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let input_path = args
        .next()
        .ok_or_else(|| "usage: ecx-truthcoin-bip300-diagnose INPUT.json".to_owned())?;
    if args.next().is_some() {
        return Err("usage: ecx-truthcoin-bip300-diagnose INPUT.json".to_owned());
    }
    let input: ReplayInputV1 = serde_json::from_slice(
        &fs::read(input_path).map_err(|error| format!("cannot read input: {error}"))?,
    )
    .map_err(|error| format!("input is not ReplayInputV1 JSON: {error}"))?;
    verify_replay_structure(&input)
        .map_err(|error| format!("structural replay rejected: {error:?} ({error})"))?;
    let deposits = verify_truthcoin_bip300_deposits(&input)
        .map_err(|error| format!("BIP300 replay rejected: {error:?} ({error})"))?;
    println!("authenticated {} Truthcoin M5 deposits", deposits.len());
    for deposit in deposits {
        println!(
            "height={} sequence={} txid={} vout={} value_sats={}",
            deposit.mainchain_height,
            deposit.sequence_number,
            hex_string(&deposit.txid),
            deposit.vout,
            deposit.value_sats
        );
    }
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
