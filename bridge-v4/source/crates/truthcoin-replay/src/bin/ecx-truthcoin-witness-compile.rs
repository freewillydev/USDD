//! Offline compiler for an authenticated Truthcoin replay witness export.
//!
//! This tool does not activate the production guest and does not generate a
//! proof. It validates the complete Bitcoin/BMM/body structure, executes the
//! concrete release-candidate state machine, and writes canonical bincode plus
//! candidate-derived public values for independent comparison.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use bincode::Options;
use ecx_truthcoin_replay::{
    execute_production_replay, execute_production_replay_from_bootstrap, ReplayInputV1,
    ReviewedNativeBootstrapV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_JSON_INPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug)]
struct Arguments {
    input_json: PathBuf,
    output_witness: PathBuf,
    output_public_values: PathBuf,
    output_metadata: PathBuf,
    bootstrap: Option<(PathBuf, [u8; 32], [u8; 32])>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    schema: &'static str,
    status: &'static str,
    warning: &'static str,
    input_json: &'a str,
    witness_mode: &'static str,
    reviewed_bootstrap_commitment: Option<String>,
    expected_authentication_hash: Option<String>,
    witness: Artifact<'a>,
    candidate_public_values: Artifact<'a>,
    bitcoin_checkpoint_height: u64,
    bitcoin_tip_height: u64,
    sidechain_tip_height: u64,
    mainchain_header_count: usize,
    sidechain_block_count: usize,
}

#[derive(Serialize)]
struct Artifact<'a> {
    path: &'a str,
    bytes: usize,
    sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("witness compiler: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    ensure_distinct_outputs(&arguments)?;
    for output in [
        &arguments.output_witness,
        &arguments.output_public_values,
        &arguments.output_metadata,
    ] {
        if output.exists() {
            return Err(format!("refusing to overwrite {}", output.display()));
        }
    }

    let json = read_bounded(&arguments.input_json, MAX_JSON_INPUT_BYTES)?;
    let input: ReplayInputV1 = serde_json::from_slice(&json)
        .map_err(|error| format!("input is not ReplayInputV1 JSON: {error}"))?;
    // Compile exactly the relation used by the release guest. A structurally
    // authenticated BMM candidate can still fail the Truthcoin state
    // transition; production fork choice must select the highest ranked
    // state-valid branch before deriving public values.
    let codec = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_JSON_INPUT_BYTES as u64);
    let (result, witness) = if let Some((path, pin, authentication)) = &arguments.bootstrap {
        if !cfg!(feature = "truthcoin-alpha-one-day-period") {
            return Err("bootstrap compilation requires the Alpha one-day feature".into());
        }
        let bootstrap: ReviewedNativeBootstrapV1 = serde_json::from_slice(
            &read_bounded(path, MAX_JSON_INPUT_BYTES)?
        ).map_err(|error| format!("invalid bootstrap JSON: {error}"))?;
        // These two expectations are explicit operator inputs, not extracted
        // from the witness. No artifacts are written unless full replay passes.
        let result = execute_production_replay_from_bootstrap(&input, &bootstrap, *pin, *authentication)
            .map_err(|error| format!("bootstrap replay rejected witness: {error}"))?;
        let pair = (&input, &bootstrap);
        let witness = codec.serialize(&pair).map_err(|error| error.to_string())?;
        let decoded: (ReplayInputV1, ReviewedNativeBootstrapV1) = codec.deserialize(&witness)
            .map_err(|error| format!("guest tuple decode failed: {error}"))?;
        if decoded != (input.clone(), bootstrap) {
            return Err("guest tuple roundtrip differs".into());
        }
        (result, witness)
    } else {
        let result = execute_production_replay(&input)
            .map_err(|error| format!("production replay rejected witness: {error}"))?;
        let witness = codec.serialize(&input).map_err(|error| error.to_string())?;
        (result, witness)
    };
    if witness.len() > MAX_JSON_INPUT_BYTES {
        return Err("canonical witness exceeds the guest input envelope".to_owned());
    }

    let input_json_path = display_path(&arguments.input_json);
    let witness_path = display_path(&arguments.output_witness);
    let public_values_path = display_path(&arguments.output_public_values);
    let metadata = Metadata {
        schema: "ecx-truthcoin-witness-compiler-v1",
        status: "release-candidate-only",
        warning:
            "public values are candidate-derived and require independent comparison before proving",
        input_json: &input_json_path,
        witness_mode: if arguments.bootstrap.is_some() { "reviewed-native-bootstrap-tuple-v1" } else { "genesis-replay-v1" },
        reviewed_bootstrap_commitment: arguments.bootstrap.as_ref().map(|(_, pin, _)| hex::encode(pin)),
        expected_authentication_hash: arguments.bootstrap.as_ref().map(|(_, _, auth)| hex::encode(auth)),
        witness: Artifact {
            path: &witness_path,
            bytes: witness.len(),
            sha256: sha256_hex(&witness),
        },
        candidate_public_values: Artifact {
            path: &public_values_path,
            bytes: result.public_values_bytes.len(),
            sha256: sha256_hex(&result.public_values_bytes),
        },
        bitcoin_checkpoint_height: input.authentication.bitcoin_checkpoint_height,
        bitcoin_tip_height: result.public_values.bitcoin_tip_height,
        sidechain_tip_height: result.public_values.sidechain_tip_height,
        mainchain_header_count: input.mainchain_headers.len(),
        sidechain_block_count: input.sidechain_blocks.len(),
    };
    let metadata = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| format!("cannot encode metadata: {error}"))?;

    write_new(&arguments.output_witness, &witness)?;
    if let Err(error) = write_new(&arguments.output_public_values, &result.public_values_bytes) {
        let _ = fs::remove_file(&arguments.output_witness);
        return Err(error);
    }
    if let Err(error) = write_new(&arguments.output_metadata, &metadata) {
        let _ = fs::remove_file(&arguments.output_witness);
        let _ = fs::remove_file(&arguments.output_public_values);
        return Err(error);
    }

    println!("wrote validated {}-byte replay witness", witness.len());
    println!(
        "wrote {} candidate-derived public-value bytes; independent comparison remains required",
        result.public_values_bytes.len()
    );
    Ok(())
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut values = env::args_os();
    let program = values.next().unwrap_or_default();
    let positional: Vec<PathBuf> = values.map(PathBuf::from).collect();
    if positional.len() != 4 && positional.len() != 7 {
        return Err(format!(
            "usage: {} INPUT.json OUTPUT.witness.bin OUTPUT.public-values.bin OUTPUT.metadata.json [BOOTSTRAP.json REVIEWED_PIN_HEX EXPECTED_AUTH_HEX]",
            Path::new(&program).display()
        ));
    }
    Ok(Arguments {
        input_json: positional[0].clone(),
        output_witness: positional[1].clone(),
        output_public_values: positional[2].clone(),
        output_metadata: positional[3].clone(),
        bootstrap: if positional.len() == 7 {
            Some((positional[4].clone(), parse_hash(&positional[5])?, parse_hash(&positional[6])?))
        } else { None },
    })
}

fn parse_hash(path: &Path) -> Result<[u8; 32], String> {
    let value = path.to_str().ok_or("hash is not UTF-8")?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected 32-byte lowercase hex hash".into());
    }
    let result: [u8; 32] = hex::decode(value).map_err(|e| e.to_string())?.try_into().unwrap();
    if result == [0; 32] { return Err("expected hash cannot be zero".into()); }
    Ok(result)
}

fn ensure_distinct_outputs(arguments: &Arguments) -> Result<(), String> {
    let outputs = [
        &arguments.output_witness,
        &arguments.output_public_values,
        &arguments.output_metadata,
    ];
    for (index, left) in outputs.iter().enumerate() {
        if outputs.iter().skip(index + 1).any(|right| left == right) {
            return Err("output paths must be distinct".to_owned());
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    let length =
        usize::try_from(metadata.len()).map_err(|_| format!("{} is too large", path.display()))?;
    if length == 0 || length > maximum {
        return Err(format!("{} has an invalid byte length", path.display()));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "ecx-truthcoin-witness-compiler-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn bootstrap_expectations_require_exact_nonzero_hashes() {
        assert_eq!(parse_hash(Path::new(&"01".repeat(32))).unwrap(), [1; 32]);
        for invalid in ["00".repeat(32), "AA".repeat(32), "01".repeat(31), "gg".repeat(32)] {
            assert!(parse_hash(Path::new(&invalid)).is_err());
        }
    }

    #[test]
    fn duplicate_output_paths_are_rejected() {
        let repeated = PathBuf::from("same");
        let arguments = Arguments {
            input_json: PathBuf::from("input"),
            output_witness: repeated.clone(),
            output_public_values: repeated,
            output_metadata: PathBuf::from("metadata"),
            bootstrap: None,
        };
        assert!(ensure_distinct_outputs(&arguments).is_err());
    }

    #[test]
    fn output_creation_never_overwrites() {
        let path = temporary_path("overwrite");
        write_new(&path, b"first").unwrap();
        assert!(write_new(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn empty_and_oversized_inputs_are_rejected_before_decode() {
        let path = temporary_path("bounds");
        fs::write(&path, []).unwrap();
        assert!(read_bounded(&path, 1).is_err());
        fs::write(&path, [0_u8; 2]).unwrap();
        assert!(read_bounded(&path, 1).is_err());
        fs::remove_file(path).unwrap();
    }
}
