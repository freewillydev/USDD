//! Offline, local-file-only ECX/BTC witness composer.
//!
//! This command never performs RPC or network access. It composes the exact
//! canonical guest input from an explicit file manifest, runs all deterministic
//! relation checks, and checks the deferred-receipt markers. Because it does
//! not possess an SP1 SDK verifier, it writes only a `.candidate` witness and
//! requires an explicit candidate flag. A production receipt/export pipeline
//! must independently verify the two compressed subreceipts and the final
//! conversion receipt.

use ecx_conversion_foundation_v2::ecx_btc::{
    decode_ecx_btc_conversion_witness_v2, encode_ecx_btc_conversion_witness_v2,
    execute_ecx_btc_conversion_v2, sp1_deferred_receipt_marker_v2, EcxBtcConfidentialOpeningV2,
    EcxBtcConversionWitnessV2, RecursiveReceiptErrorV2, RecursiveReceiptVerifierV2,
    MAX_CHECKPOINT_BYTES_V2, MAX_ECX_BTC_WITNESS_BYTES_V2, MAX_RECORD_BYTES_V2,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const EXPORT_MANIFEST_VERSION: u8 = 1;
const MAX_METADATA_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileManifestV1 {
    version: u8,
    metadata_json: String,
    parent_checkpoint_header: String,
    parent_mtp_context_headers: Vec<String>,
    bip300_complete_all_slots_state: String,
    elements_checkpoint_complete_state: String,
    covenant_simplicity_program: String,
    covenant_deployment_transaction: String,
    parent_successor_blocks: Vec<String>,
    /// One entry per parent block. `null` means that block consumes no
    /// canonical accumulator M6 artifact.
    parent_bip300_m6_artifacts: Vec<Option<String>>,
    elements_blocks: Vec<String>,
    elements_predecessor_transactions: Vec<String>,
    elements_confidential_openings_json: String,
    full_bitcoin_proof_marker: String,
    full_elements_proof_marker: String,
}

struct MarkerOnlyCandidateVerifier;

impl RecursiveReceiptVerifierV2 for MarkerOnlyCandidateVerifier {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), RecursiveReceiptErrorV2> {
        if proof_marker == sp1_deferred_receipt_marker_v2(program_id, public_values) {
            Ok(())
        } else {
            Err(RecursiveReceiptErrorV2)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ECX/BTC candidate export rejected: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[0] != "--candidate-output" {
        return Err(format!(
            "usage: {} --candidate-output <local-file-manifest.json> <output.ecxbtc-v2.candidate>",
            env::args()
                .next()
                .unwrap_or_else(|| "ecx-btc-conversion-witness-export".to_owned())
        ));
    }
    let manifest_path = PathBuf::from(&arguments[1]);
    let output_path = PathBuf::from(&arguments[2]);
    if !output_path
        .to_string_lossy()
        .ends_with(".ecxbtc-v2.candidate")
    {
        return Err("candidate output must end in .ecxbtc-v2.candidate".to_owned());
    }
    if output_path.exists() {
        return Err("refusing to overwrite an existing output".to_owned());
    }
    let manifest_bytes = read_local_file(&manifest_path, MAX_METADATA_JSON_BYTES)?;
    let manifest: FileManifestV1 = serde_json::from_slice(&manifest_bytes)
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

    let metadata_path = resolve_local(&root, &manifest.metadata_json)?;
    let metadata = read_local_file(&metadata_path, MAX_METADATA_JSON_BYTES)?;
    let mut witness: EcxBtcConversionWitnessV2 =
        serde_json::from_slice(&metadata).map_err(|error| {
            format!("metadata is not strict EcxBtcConversionWitnessV2 JSON: {error}")
        })?;
    require_file_backed_fields_empty(&witness)?;

    witness.source_checkpoint.parent.header =
        read_manifest_file(&root, &manifest.parent_checkpoint_header, 80, 80)?;
    witness.source_checkpoint.parent.mtp_context_headers = manifest
        .parent_mtp_context_headers
        .iter()
        .map(|path| read_manifest_file(&root, path, 80, 80))
        .collect::<Result<Vec<_>, _>>()?;
    witness
        .source_checkpoint
        .bip300
        .complete_all_slots_state_preimage = read_manifest_file(
        &root,
        &manifest.bip300_complete_all_slots_state,
        1,
        MAX_CHECKPOINT_BYTES_V2,
    )?;
    witness.source_checkpoint.elements.complete_state_preimage = read_manifest_file(
        &root,
        &manifest.elements_checkpoint_complete_state,
        1,
        MAX_CHECKPOINT_BYTES_V2,
    )?;
    witness.covenant_deployment.simplicity_program_bytes = read_manifest_file(
        &root,
        &manifest.covenant_simplicity_program,
        1,
        MAX_RECORD_BYTES_V2,
    )?;
    witness.covenant_deployment.deployment_transaction = read_manifest_file(
        &root,
        &manifest.covenant_deployment_transaction,
        1,
        MAX_RECORD_BYTES_V2,
    )?;
    witness.parent_successor_blocks = read_records(&root, &manifest.parent_successor_blocks)?;
    witness.parent_bip300_m6_artifacts = manifest
        .parent_bip300_m6_artifacts
        .iter()
        .map(|path| {
            path.as_ref()
                .map(|path| read_manifest_file(&root, path, 1, MAX_RECORD_BYTES_V2))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;
    witness.elements_material.blocks = read_records(&root, &manifest.elements_blocks)?;
    witness.elements_material.predecessor_transactions =
        read_records(&root, &manifest.elements_predecessor_transactions)?;
    let openings_json = read_manifest_file(
        &root,
        &manifest.elements_confidential_openings_json,
        1,
        MAX_ECX_BTC_WITNESS_BYTES_V2,
    )?;
    witness.elements_material.confidential_openings =
        serde_json::from_slice::<Vec<EcxBtcConfidentialOpeningV2>>(&openings_json)
            .map_err(|error| format!("confidential openings are not strict JSON: {error}"))?;
    witness.full_bitcoin_receipt.proof_marker =
        read_manifest_file(&root, &manifest.full_bitcoin_proof_marker, 32, 32)?;
    witness.full_elements_receipt.proof_marker =
        read_manifest_file(&root, &manifest.full_elements_proof_marker, 32, 32)?;

    // This executes the exact deterministic relation, including every inline
    // chain check and both exact marker bindings. MarkerOnlyCandidateVerifier
    // is deliberately incapable of validating a receipt, which is why this
    // command can only produce an explicitly suffixed candidate witness.
    let public_values = execute_ecx_btc_conversion_v2(&witness, &MarkerOnlyCandidateVerifier)
        .map_err(|error| format!("deterministic relation preflight failed: {error}"))?;
    let canonical = encode_ecx_btc_conversion_witness_v2(&witness)
        .map_err(|error| format!("canonical encoder rejected witness: {error}"))?;
    if canonical.len() > MAX_ECX_BTC_WITNESS_BYTES_V2 {
        return Err("canonical witness exceeds guest input bound".to_owned());
    }
    let decoded = decode_ecx_btc_conversion_witness_v2(&canonical)
        .map_err(|error| format!("canonical round trip failed: {error}"))?;
    if decoded != witness {
        return Err("canonical round trip changed the witness".to_owned());
    }

    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output_path)
        .map_err(|error| format!("cannot create candidate output: {error}"))?;
    output
        .write_all(&canonical)
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("cannot durably write candidate output: {error}"))?;
    let witness_sha256: [u8; 32] = Sha256::digest(&canonical).into();
    let public_bytes = public_values.canonical_bytes();
    let public_sha256: [u8; 32] = Sha256::digest(&public_bytes).into();
    println!("status=CANDIDATE_ONLY_RECURSIVE_RECEIPTS_NOT_VERIFIED");
    println!("witness_bytes={}", canonical.len());
    println!("witness_sha256={}", lower_hex(&witness_sha256));
    println!("public_values_bytes={}", public_bytes.len());
    println!("public_values_sha256={}", lower_hex(&public_sha256));
    println!("output={}", output_path.display());
    Ok(())
}

fn require_file_backed_fields_empty(witness: &EcxBtcConversionWitnessV2) -> Result<(), String> {
    if !witness.source_checkpoint.parent.header.is_empty()
        || !witness
            .source_checkpoint
            .parent
            .mtp_context_headers
            .is_empty()
        || !witness
            .source_checkpoint
            .bip300
            .complete_all_slots_state_preimage
            .is_empty()
        || !witness
            .source_checkpoint
            .elements
            .complete_state_preimage
            .is_empty()
        || !witness
            .covenant_deployment
            .simplicity_program_bytes
            .is_empty()
        || !witness
            .covenant_deployment
            .deployment_transaction
            .is_empty()
        || !witness.parent_successor_blocks.is_empty()
        || !witness.parent_bip300_m6_artifacts.is_empty()
        || !witness.elements_material.blocks.is_empty()
        || !witness
            .elements_material
            .predecessor_transactions
            .is_empty()
        || !witness.elements_material.confidential_openings.is_empty()
        || !witness.full_bitcoin_receipt.proof_marker.is_empty()
        || !witness.full_elements_receipt.proof_marker.is_empty()
    {
        return Err(
            "metadata must leave every file-backed field empty; duplicate inline bytes are forbidden"
                .to_owned(),
        );
    }
    Ok(())
}

fn read_records(root: &Path, paths: &[String]) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| read_manifest_file(root, path, 1, MAX_RECORD_BYTES_V2))
        .collect()
}

fn read_manifest_file(
    root: &Path,
    path: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let resolved = resolve_local(root, path)?;
    let bytes = read_local_file(&resolved, maximum)?;
    if bytes.len() < minimum {
        return Err(format!(
            "{} is shorter than {} bytes",
            resolved.display(),
            minimum
        ));
    }
    Ok(bytes)
}

fn resolve_local(root: &Path, value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.contains("://")
        || value.starts_with("file:")
        || value.contains('\0')
    {
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
    joined
        .canonicalize()
        .map_err(|error| format!("cannot resolve local input {}: {error}", joined.display()))
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
            "{} violates the {}-byte file bound",
            path.display(),
            maximum
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

    #[test]
    fn network_and_file_uri_inputs_are_rejected() {
        let root = Path::new(".");
        for path in [
            "https://example.invalid/block",
            "http://example.invalid/block",
            "file:///tmp/block",
        ] {
            assert!(resolve_local(root, path).is_err());
        }
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_missing_m6_alignment_field() {
        let unknown = br#"{
            "version":1,
            "metadata_json":"m",
            "parent_checkpoint_header":"h",
            "parent_mtp_context_headers":[],
            "bip300_complete_all_slots_state":"s",
            "elements_checkpoint_complete_state":"e",
            "covenant_simplicity_program":"p",
            "covenant_deployment_transaction":"t",
            "parent_successor_blocks":[],
            "parent_bip300_m6_artifacts":[],
            "elements_blocks":[],
            "elements_predecessor_transactions":[],
            "elements_confidential_openings_json":"o",
            "full_bitcoin_proof_marker":"b",
            "full_elements_proof_marker":"x",
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<FileManifestV1>(unknown).is_err());

        let missing_m6 = br#"{
            "version":1,
            "metadata_json":"m",
            "parent_checkpoint_header":"h",
            "parent_mtp_context_headers":[],
            "bip300_complete_all_slots_state":"s",
            "elements_checkpoint_complete_state":"e",
            "covenant_simplicity_program":"p",
            "covenant_deployment_transaction":"t",
            "parent_successor_blocks":[],
            "elements_blocks":[],
            "elements_predecessor_transactions":[],
            "elements_confidential_openings_json":"o",
            "full_bitcoin_proof_marker":"b",
            "full_elements_proof_marker":"x"
        }"#;
        assert!(serde_json::from_slice::<FileManifestV1>(missing_m6).is_err());
    }

    #[test]
    fn local_reader_rejects_empty_and_oversized_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "ecx-btc-exporter-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated test directory");
        let empty = directory.join("empty");
        let two = directory.join("two");
        fs::write(&empty, []).expect("write empty fixture");
        fs::write(&two, [1u8, 2]).expect("write bounded fixture");
        assert!(read_local_file(&empty, 8).is_err());
        assert!(read_local_file(&two, 1).is_err());
        assert_eq!(read_local_file(&two, 2).unwrap(), vec![1, 2]);
        fs::remove_dir_all(&directory).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_input_is_rejected_before_canonicalization() {
        use std::os::unix::fs::symlink;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "ecx-btc-exporter-symlink-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated test directory");
        fs::write(directory.join("target"), [1u8]).expect("write target");
        symlink("target", directory.join("link")).expect("create symlink");
        assert!(resolve_local(&directory, "link").is_err());
        fs::remove_dir_all(&directory).expect("remove isolated test directory");
    }
}
