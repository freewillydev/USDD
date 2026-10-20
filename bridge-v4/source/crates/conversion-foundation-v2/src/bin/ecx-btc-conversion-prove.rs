//! Fail-closed SP1 host for the unreleased ECX/BTC conversion guest. This
//! remains in the provenance-pinned conversion workspace so its reviewed
//! `sha2 = 0.10.8` graph is not silently merged with the newer ECX proof graph.

use std::{
    env,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use bincode::Options;
use clap::Parser;
use ecx_conversion_foundation_v2::ecx_btc::{
    decode_ecx_btc_conversion_witness_v2, encode_full_bitcoin_statement_v2,
    encode_full_elements_statement_v2, execute_ecx_btc_conversion_v2,
    sp1_deferred_receipt_marker_v2, EcxBtcConversionWitnessV2, RecursiveReceiptErrorV2,
    RecursiveReceiptVerifierV2, MAX_ECX_BTC_WITNESS_BYTES_V2,
};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};

const NO_LOCAL_PROOF_ENV: &str = "ECX_NO_LOCAL_PROOF";
const ACK_ENV: &str = "ECX_ISOLATED_ECX_BTC_CONVERSION_PROOF";
const ACK_VALUE: &str = "I_UNDERSTAND_THIS_REQUIRES_TWO_REAL_FULL_VALIDITY_PROOFS";
const MAX_ELF_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024 * 1024;
const MAX_VKEY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Execute or prove the unfrozen recursive ECX/BTC conversion")]
struct Arguments {
    #[arg(long)]
    elf: PathBuf,
    #[arg(long)]
    witness: PathBuf,
    #[arg(long)]
    full_bitcoin_compressed_receipt: PathBuf,
    #[arg(long)]
    full_bitcoin_verifying_key: PathBuf,
    #[arg(long)]
    full_elements_compressed_receipt: PathBuf,
    #[arg(long)]
    full_elements_verifying_key: PathBuf,
    #[arg(long)]
    expected_program_id_hex: String,
    #[arg(long)]
    output_public_values: PathBuf,
    #[arg(long)]
    output_receipt: Option<PathBuf>,
    #[arg(long)]
    output_verifying_key: Option<PathBuf>,
    #[arg(long, default_value_t = 2_000_000_000)]
    cycle_limit: u64,
    #[arg(long, default_value_t = false)]
    execute_only: bool,
    #[arg(long)]
    i_understand_this_requires_two_real_full_validity_proofs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceClass {
    FullBitcoin,
    FullElements,
}

struct SourceDescriptor {
    class: SourceClass,
    program_id: [u8; 32],
    public_values: Vec<u8>,
    proof_marker: Vec<u8>,
}

struct LoadedSource {
    class: SourceClass,
    program_id: [u8; 32],
    public_values: Vec<u8>,
    receipt: SP1ProofWithPublicValues,
    verifying_key: SP1VerifyingKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    require_isolated_proof_worker()?;
    let arguments = Arguments::parse();
    require_acknowledgement(&arguments)?;
    validate_output_shape(&arguments)?;

    let witness_bytes = read_bounded(&arguments.witness, MAX_ECX_BTC_WITNESS_BYTES_V2)?;
    let witness = decode_ecx_btc_conversion_witness_v2(&witness_bytes)
        .context("witness is not canonical EcxBtcConversionWitnessV2")?;
    let descriptors = source_descriptors(&witness)?;
    let bitcoin = load_source(
        &descriptors[0],
        &arguments.full_bitcoin_compressed_receipt,
        &arguments.full_bitcoin_verifying_key,
    )?;
    let elements = load_source(
        &descriptors[1],
        &arguments.full_elements_compressed_receipt,
        &arguments.full_elements_verifying_key,
    )?;
    let sources = [bitcoin, elements];

    let prover = ProverClient::builder().cpu().build().await;
    for source in &sources {
        prover
            .verify(&source.receipt, &source.verifying_key, None)
            .with_context(|| {
                format!(
                    "{} receipt SDK verification failed",
                    source_name(source.class)
                )
            })?;
    }
    let expected_public_values =
        execute_ecx_btc_conversion_v2(&witness, &HostSourceVerifier { sources: &sources })
            .context("host ECX/BTC conversion relation rejected")?
            .canonical_bytes();

    let expected_outer_id = parse_program_id(&arguments.expected_program_id_hex)?;
    let elf_bytes = read_bounded(&arguments.elf, MAX_ELF_BYTES)?;
    let proving_key = prover
        .setup(Elf::from(elf_bytes.clone()))
        .await
        .context("ECX/BTC conversion setup failed")?;
    if words_to_bytes(proving_key.verifying_key().hash_u32()) != expected_outer_id {
        bail!("ECX/BTC conversion ELF does not match the expected program ID");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(witness_bytes.clone());
    write_sources(&mut stdin, &sources)?;
    let (executed, report) = prover
        .execute(Elf::from(elf_bytes), stdin)
        .cycle_limit(arguments.cycle_limit)
        .deferred_proof_verification(true)
        .await
        .context("ECX/BTC conversion SP1 execute failed")?;
    if report.exit_code != 0 || executed.as_slice() != expected_public_values {
        bail!("ECX/BTC conversion execute does not match the host relation");
    }
    write_new(&arguments.output_public_values, &expected_public_values)?;
    println!(
        "execute_ok=true cycles={} source_receipts=2 public_values_bytes={}",
        report.total_instruction_count(),
        expected_public_values.len()
    );
    if arguments.execute_only {
        return Ok(());
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(witness_bytes);
    write_sources(&mut stdin, &sources)?;
    let receipt = prover
        .prove(&proving_key, stdin)
        .compressed()
        .cycle_limit(arguments.cycle_limit)
        .deferred_proof_verification(true)
        .await
        .context("ECX/BTC conversion compressed proving failed")?;
    if receipt.tee_proof.is_some()
        || !matches!(&receipt.proof, SP1Proof::Compressed(_))
        || receipt.public_values.as_slice() != expected_public_values
    {
        bail!("SP1 returned a TEE, wrong proof mode, or wrong ECX/BTC public values");
    }
    prover
        .verify(&receipt, proving_key.verifying_key(), None)
        .context("ECX/BTC conversion outer receipt verification failed")?;
    write_new(
        arguments.output_receipt.as_deref().expect("validated"),
        &canonical_serialize(&receipt, MAX_RECEIPT_BYTES)?,
    )?;
    write_new(
        arguments
            .output_verifying_key
            .as_deref()
            .expect("validated"),
        &canonical_serialize(proving_key.verifying_key(), MAX_VKEY_BYTES)?,
    )?;
    println!("proof_verified=true mode=compressed source_receipts=2");
    Ok(())
}

fn source_descriptors(witness: &EcxBtcConversionWitnessV2) -> Result<[SourceDescriptor; 2]> {
    let descriptors = [
        SourceDescriptor {
            class: SourceClass::FullBitcoin,
            program_id: witness.source_checkpoint.full_bitcoin_validator_program_id,
            public_values: encode_full_bitcoin_statement_v2(&witness.full_bitcoin_statement)?,
            proof_marker: witness.full_bitcoin_receipt.proof_marker.clone(),
        },
        SourceDescriptor {
            class: SourceClass::FullElements,
            program_id: witness.source_checkpoint.full_elements_validator_program_id,
            public_values: encode_full_elements_statement_v2(&witness.full_elements_statement)?,
            proof_marker: witness.full_elements_receipt.proof_marker.clone(),
        },
    ];
    for descriptor in &descriptors {
        require_canonical_program_id(descriptor.program_id, source_name(descriptor.class))?;
        if descriptor.proof_marker
            != sp1_deferred_receipt_marker_v2(descriptor.program_id, &descriptor.public_values)
        {
            bail!(
                "{} marker does not bind its exact statement",
                source_name(descriptor.class)
            );
        }
    }
    Ok(descriptors)
}

fn load_source(
    descriptor: &SourceDescriptor,
    receipt_path: &Path,
    vkey_path: &Path,
) -> Result<LoadedSource> {
    let name = source_name(descriptor.class);
    let verifying_key: SP1VerifyingKey = decode_canonical(
        &read_bounded(vkey_path, MAX_VKEY_BYTES)?,
        MAX_VKEY_BYTES,
        "source verifying key",
    )?;
    let actual_id = words_to_bytes(verifying_key.hash_u32());
    if actual_id != descriptor.program_id {
        bail!("{name} verifying key does not match the frozen program ID");
    }
    let receipt: SP1ProofWithPublicValues = decode_canonical(
        &read_bounded(receipt_path, MAX_RECEIPT_BYTES)?,
        MAX_RECEIPT_BYTES,
        "source receipt",
    )?;
    if receipt.tee_proof.is_some()
        || !matches!(&receipt.proof, SP1Proof::Compressed(_))
        || receipt.public_values.as_slice() != descriptor.public_values
    {
        bail!("{name} receipt is a TEE, wrong mode, or has different public values");
    }
    Ok(LoadedSource {
        class: descriptor.class,
        program_id: actual_id,
        public_values: descriptor.public_values.clone(),
        receipt,
        verifying_key,
    })
}

fn write_sources(stdin: &mut SP1Stdin, sources: &[LoadedSource; 2]) -> Result<()> {
    if sources[0].class != SourceClass::FullBitcoin || sources[1].class != SourceClass::FullElements
    {
        bail!("recursive source order changed");
    }
    for source in sources {
        let SP1Proof::Compressed(proof) = &source.receipt.proof else {
            bail!("{} source changed proof mode", source_name(source.class));
        };
        stdin.write_proof((**proof).clone(), source.verifying_key.vk.clone());
    }
    Ok(())
}

struct HostSourceVerifier<'a> {
    sources: &'a [LoadedSource; 2],
}

impl RecursiveReceiptVerifierV2 for HostSourceVerifier<'_> {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), RecursiveReceiptErrorV2> {
        let exact = self
            .sources
            .iter()
            .any(|source| source.program_id == program_id && source.public_values == public_values);
        if !exact || proof_marker != sp1_deferred_receipt_marker_v2(program_id, public_values) {
            return Err(RecursiveReceiptErrorV2);
        }
        Ok(())
    }
}

fn source_name(class: SourceClass) -> &'static str {
    match class {
        SourceClass::FullBitcoin => "full-bitcoin",
        SourceClass::FullElements => "full-elements",
    }
}

fn require_canonical_program_id(program_id: [u8; 32], label: &str) -> Result<()> {
    const MODULUS: u32 = 0x7f00_0001;
    if program_id == [0; 32]
        || program_id
            .chunks_exact(4)
            .any(|word| u32::from_be_bytes(word.try_into().expect("four bytes")) >= MODULUS)
    {
        bail!("{label} is not a canonical SP1 program ID");
    }
    Ok(())
}

fn parse_program_id(value: &str) -> Result<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        bail!("expected program ID must encode exactly 32 bytes");
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).context("program ID is not UTF-8")?;
        bytes[index] = u8::from_str_radix(text, 16).context("program ID is not hexadecimal")?;
    }
    require_canonical_program_id(bytes, "expected outer program ID")?;
    Ok(bytes)
}

fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

fn decode_canonical<T>(bytes: &[u8], maximum: usize, label: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value: T = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(maximum as u64)
        .deserialize(bytes)
        .with_context(|| format!("cannot decode canonical {label}"))?;
    if canonical_serialize(&value, maximum)? != bytes {
        bail!("{label} encoding is not canonical");
    }
    Ok(value)
}

fn canonical_serialize<T: serde::Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(maximum as u64)
        .serialize(value)
        .context("cannot serialize canonical object")?;
    if bytes.len() > maximum {
        bail!("canonical object exceeds its byte bound");
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = path
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        bail!("{} is not a bounded regular file", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{} changed or exceeds its byte bound", path.display());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_output_shape(arguments: &Arguments) -> Result<()> {
    if arguments.cycle_limit == 0 {
        bail!("cycle limit must be nonzero");
    }
    if arguments.execute_only {
        if arguments.output_receipt.is_some() || arguments.output_verifying_key.is_some() {
            bail!("execute-only must not name proof outputs");
        }
    } else if arguments.output_receipt.is_none() || arguments.output_verifying_key.is_none() {
        bail!("proof mode requires receipt and verifying-key outputs");
    }
    Ok(())
}

fn require_isolated_proof_worker() -> Result<()> {
    if env::var_os(NO_LOCAL_PROOF_ENV).is_some() {
        bail!("SP1 setup/proving is disabled by {NO_LOCAL_PROOF_ENV}");
    }
    Ok(())
}

fn require_acknowledgement(arguments: &Arguments) -> Result<()> {
    if !arguments.i_understand_this_requires_two_real_full_validity_proofs
        || env::var(ACK_ENV).as_deref() != Ok(ACK_VALUE)
    {
        bail!(
            "refusing ECX/BTC execution or proving without dual acknowledgement (--i-understand-this-requires-two-real-full-validity-proofs and {ACK_ENV}={ACK_VALUE})"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_order_and_names_are_frozen() {
        assert_eq!(source_name(SourceClass::FullBitcoin), "full-bitcoin");
        assert_eq!(source_name(SourceClass::FullElements), "full-elements");
    }

    #[test]
    fn program_id_parser_is_exact_and_koalabear_bounded() {
        let valid = format!("{:08x}", 1).repeat(8);
        assert!(parse_program_id(&valid).is_ok());
        assert!(parse_program_id("00").is_err());
        assert!(parse_program_id(&"ff".repeat(32)).is_err());
    }
}
