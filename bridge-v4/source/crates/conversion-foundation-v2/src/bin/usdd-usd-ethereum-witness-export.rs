//! Offline, local-file-only USDD Ethereum source witness exporter.
//!
//! Every variable-sized authenticated input is loaded from an explicit regular
//! file. The command performs the complete pinned Sepolia finality and MPT
//! relation before writing the canonical guest input. It has no RPC client and
//! never accepts an RPC-derived reserve/supply summary.

use ecx_conversion_foundation_v2::usdd_usd::{
    execute_usdd_usd_ethereum_source_v2, UsddUsdEthereumSourceInputV2, MAX_MPT_NODE_BYTES_V2,
    MAX_MPT_PROOF_NODES_V2, MAX_USDD_USD_PREIMAGE_BYTES_V2,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const EXPORT_MANIFEST_VERSION: u8 = 1;
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileManifestV1 {
    version: u8,
    metadata_json: String,
    protocol_manifest: String,
    prior_controller_state: String,
    expected_finalized_state: String,
    finality_proof_cbor: String,
    vault_account_proof_nodes: Vec<String>,
    reserve_token_account_proof_nodes: Vec<String>,
    price_contract_account_proof_nodes: Vec<String>,
    vault_liability_proof_nodes: Vec<String>,
    vault_pause_proof_nodes: Vec<String>,
    vault_governance_proof_nodes: Vec<String>,
    reserve_balance_proof_nodes: Vec<String>,
    reserve_usd_quote_proof_nodes: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("USDD Ethereum witness export rejected: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err(format!(
            "usage: {} <local-file-manifest.json> <output.usdd-ethereum-v2.witness>",
            env::args()
                .next()
                .unwrap_or_else(|| "usdd-usd-ethereum-witness-export".to_owned())
        ));
    }
    let manifest_path = PathBuf::from(&arguments[0]);
    let output_path = PathBuf::from(&arguments[1]);
    if !output_path
        .to_string_lossy()
        .ends_with(".usdd-ethereum-v2.witness")
    {
        return Err("output must end in .usdd-ethereum-v2.witness".to_owned());
    }
    if output_path.exists() {
        return Err("refusing to overwrite an existing output".to_owned());
    }
    let manifest: FileManifestV1 =
        serde_json::from_slice(&read_local_file(&manifest_path, MAX_JSON_BYTES)?)
            .map_err(|error| format!("file manifest is not strict JSON: {error}"))?;
    if manifest.version != EXPORT_MANIFEST_VERSION {
        return Err("unsupported file manifest version".to_owned());
    }
    let root = manifest_path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize manifest: {error}"))?
        .parent()
        .ok_or_else(|| "manifest has no parent directory".to_owned())?
        .to_path_buf();
    let mut input = parse_exact_metadata(&read_manifest_file(
        &root,
        &manifest.metadata_json,
        MAX_JSON_BYTES,
    )?)?;
    require_file_backed_fields_empty(&input)?;

    input.finality.manifest = read_manifest_file(
        &root,
        &manifest.protocol_manifest,
        MAX_USDD_USD_PREIMAGE_BYTES_V2,
    )?;
    input.finality.prior_controller_state = read_manifest_file(
        &root,
        &manifest.prior_controller_state,
        MAX_USDD_USD_PREIMAGE_BYTES_V2,
    )?;
    input.finality.expected_finalized_state = read_manifest_file(
        &root,
        &manifest.expected_finalized_state,
        MAX_USDD_USD_PREIMAGE_BYTES_V2,
    )?;
    input.finality.finality_proof_cbor = read_manifest_file(
        &root,
        &manifest.finality_proof_cbor,
        MAX_USDD_USD_PREIMAGE_BYTES_V2,
    )?;
    input.vault_account.proof_nodes = read_nodes(&root, &manifest.vault_account_proof_nodes)?;
    input.reserve_token_account.proof_nodes =
        read_nodes(&root, &manifest.reserve_token_account_proof_nodes)?;
    input.price_contract_account.proof_nodes =
        read_nodes(&root, &manifest.price_contract_account_proof_nodes)?;
    input.vault_liability.proof_nodes = read_nodes(&root, &manifest.vault_liability_proof_nodes)?;
    input.vault_pause.proof_nodes = read_nodes(&root, &manifest.vault_pause_proof_nodes)?;
    input.vault_governance.proof_nodes = read_nodes(&root, &manifest.vault_governance_proof_nodes)?;
    input.reserve_balance.proof_nodes = read_nodes(&root, &manifest.reserve_balance_proof_nodes)?;
    input.reserve_usd_quote.proof_nodes =
        read_nodes(&root, &manifest.reserve_usd_quote_proof_nodes)?;

    let public_values = execute_usdd_usd_ethereum_source_v2(&input)
        .map_err(|error| format!("authenticated relation failed: {error}"))?;
    let canonical = input
        .canonical_bytes()
        .map_err(|error| format!("canonical encoder rejected witness: {error}"))?;
    let decoded = UsddUsdEthereumSourceInputV2::decode_canonical(&canonical)
        .map_err(|error| format!("canonical round trip failed: {error}"))?;
    if decoded != input {
        return Err("canonical round trip changed the witness".to_owned());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output_path)
        .map_err(|error| format!("cannot create output: {error}"))?;
    output
        .write_all(&canonical)
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("cannot durably write output: {error}"))?;
    println!("status=AUTHENTICATED_ETHEREUM_RELATION_VALIDATED_NO_SP1_RECEIPT");
    println!("witness_bytes={}", canonical.len());
    println!("witness_sha256={}", lower_hex(&Sha256::digest(&canonical)));
    let public_bytes = public_values.canonical_bytes();
    println!("public_values_bytes={}", public_bytes.len());
    println!(
        "public_values_sha256={}",
        lower_hex(&Sha256::digest(&public_bytes))
    );
    println!("output={}", output_path.display());
    Ok(())
}

fn parse_exact_metadata(bytes: &[u8]) -> Result<UsddUsdEthereumSourceInputV2, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("metadata is not valid JSON: {error}"))?;
    let input: UsddUsdEthereumSourceInputV2 = serde_json::from_value(value.clone())
        .map_err(|error| format!("metadata is not a USDD Ethereum source input: {error}"))?;
    let normalized = serde_json::to_value(&input)
        .map_err(|error| format!("cannot normalize USDD Ethereum metadata: {error}"))?;
    if normalized != value {
        return Err(
            "metadata contains unknown fields or a noncanonical JSON representation".to_owned(),
        );
    }
    Ok(input)
}

fn require_file_backed_fields_empty(input: &UsddUsdEthereumSourceInputV2) -> Result<(), String> {
    let nodes = [
        &input.vault_account.proof_nodes,
        &input.reserve_token_account.proof_nodes,
        &input.price_contract_account.proof_nodes,
        &input.vault_liability.proof_nodes,
        &input.vault_pause.proof_nodes,
        &input.vault_governance.proof_nodes,
        &input.reserve_balance.proof_nodes,
        &input.reserve_usd_quote.proof_nodes,
    ];
    if !input.finality.manifest.is_empty()
        || !input.finality.prior_controller_state.is_empty()
        || !input.finality.expected_finalized_state.is_empty()
        || !input.finality.finality_proof_cbor.is_empty()
        || nodes.iter().any(|value| !value.is_empty())
    {
        return Err("metadata must leave every file-backed field empty".to_owned());
    }
    Ok(())
}

fn read_nodes(root: &Path, paths: &[String]) -> Result<Vec<Vec<u8>>, String> {
    if paths.is_empty() || paths.len() > MAX_MPT_PROOF_NODES_V2 {
        return Err("each MPT branch must name 1..=65 node files".to_owned());
    }
    paths
        .iter()
        .map(|path| read_manifest_file(root, path, MAX_MPT_NODE_BYTES_V2))
        .collect()
}

fn read_manifest_file(root: &Path, value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.contains("://") || value.starts_with("file:") {
        return Err("manifest paths must be nonempty local filesystem paths".to_owned());
    }
    let requested = PathBuf::from(value);
    let joined = if requested.is_absolute() {
        requested
    } else {
        root.join(requested)
    };
    let unresolved_metadata = fs::symlink_metadata(&joined)
        .map_err(|error| format!("cannot stat local input {}: {error}", joined.display()))?;
    if unresolved_metadata.file_type().is_symlink() {
        return Err(format!("{} is a symlink", joined.display()));
    }
    let resolved = joined
        .canonicalize()
        .map_err(|error| format!("cannot resolve local input {}: {error}", joined.display()))?;
    read_local_file(&resolved, maximum)
}

fn read_local_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a regular non-symlink file",
            path.display()
        ));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| format!("{} length does not fit usize", path.display()))?;
    if length == 0 || length > maximum {
        return Err(format!(
            "{} violates the {maximum}-byte bound",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() != length {
        return Err(format!(
            "{} changed while it was being read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn isolated_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "usdd-ethereum-exporter-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn uri_and_empty_inputs_are_rejected() {
        assert!(read_manifest_file(Path::new("."), "https://example.invalid/proof", 10).is_err());
        let directory = isolated_directory("empty");
        fs::create_dir(&directory).expect("create isolated test directory");
        fs::write(directory.join("empty"), []).expect("write empty input");
        assert!(read_manifest_file(&directory, "empty", 10).is_err());
        fs::remove_dir_all(directory).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected_before_canonicalization() {
        use std::os::unix::fs::symlink;

        let directory = isolated_directory("symlink");
        fs::create_dir(&directory).expect("create isolated test directory");
        fs::write(directory.join("target"), [1u8]).expect("write target");
        symlink("target", directory.join("link")).expect("create symlink");
        assert!(read_manifest_file(&directory, "link", 10).is_err());
        fs::remove_dir_all(directory).expect("remove isolated test directory");
    }
}
