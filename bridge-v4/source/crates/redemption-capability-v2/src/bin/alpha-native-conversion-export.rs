//! Local candidate packaging only: no RPC, signing, or receipt verification.
use ecx_redemption_capability_v2::native_conversion_wire::{
    decode_native_conversion_input_v3, encode_native_conversion_input_v3,
    NativeConversionInputV3, MAX_NATIVE_CONVERSION_INPUT_BYTES_V3,
};
use std::{env, fs::OpenOptions, io::{Read, Write}, path::Path};

fn policy_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("policy must be exactly 64 lowercase hexadecimal characters".into());
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2*i..2*i+2], 16).map_err(|e| e.to_string())?;
    }
    if result == [0;32] { return Err("zero policy is forbidden".into()); }
    Ok(result)
}

fn package(json: &[u8], expected: [u8;32]) -> Result<Vec<u8>, String> {
    let input: NativeConversionInputV3 = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    let actual = input.policy.as_policy().commitment().map_err(|e| format!("policy: {e:?}"))?;
    if expected == [0;32] || actual != expected { return Err("pinned policy mismatch".into()); }
    let bytes = encode_native_conversion_input_v3(&input).map_err(|e| format!("encode: {e:?}"))?;
    let decoded = decode_native_conversion_input_v3(&bytes).map_err(|e| format!("decode: {e:?}"))?;
    let repeated = encode_native_conversion_input_v3(&decoded).map_err(|e| format!("reencode: {e:?}"))?;
    if repeated != bytes { return Err("non-exact roundtrip".into()); }
    Ok(bytes)
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len()!=4 || args[0]!="--candidate-output" {
        return Err("usage: alpha-native-conversion-export --candidate-output INPUT.json PINNED_POLICY_HASH OUTPUT.alpha-native.candidate".into());
    }
    let expected = policy_hash(&args[2])?;
    let output = Path::new(&args[3]);
    if !args[3].ends_with(".alpha-native.candidate") || output.exists() {
        return Err("output must be a new .alpha-native.candidate file".into());
    }
    // JSON byte arrays can be longer than their binary form; bound both forms.
    let bound = MAX_NATIVE_CONVERSION_INPUT_BYTES_V3 as u64 * 5;
    let mut json = Vec::new();
    std::fs::File::open(&args[1]).map_err(|e| e.to_string())?.take(bound+1)
        .read_to_end(&mut json).map_err(|e| e.to_string())?;
    if json.len() as u64 > bound { return Err("JSON input exceeds bound".into()); }
    let bytes = package(&json, expected)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    println!("candidateBytes={} receiptVerification=false witnessExecuted=false proofReady=false", bytes.len());
    Ok(())
}
fn main() {
    if let Err(error) = run() { eprintln!("candidate export rejected: {error}"); std::process::exit(1); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unpinned_or_noncanonical_policy() {
        for text in ["", "00", &"0".repeat(64), &"A".repeat(64), &"é".repeat(32)] {
            assert!(policy_hash(text).is_err());
        }
        assert_eq!(policy_hash(&"01".repeat(32)).unwrap(), [1;32]);
    }
    #[test]
    fn rejects_missing_and_unknown_input_fields() {
        for json in [b"{}".as_slice(), b"{\"unreviewed\":true}".as_slice()] {
            assert!(package(json, [1;32]).is_err());
        }
    }
}
