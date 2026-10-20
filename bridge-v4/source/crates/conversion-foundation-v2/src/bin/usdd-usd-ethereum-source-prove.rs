//! Isolated SP1 host for the unreleased USDD Ethereum finality/MPT source
//! guest. The input must already be the canonical output of the local-file
//! exporter; this command has no RPC or network-derived summary path.

use std::{
    env,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use bincode::Options;
use clap::{Parser, ValueEnum};
use ecx_conversion_foundation_v2::usdd_ownerless_v3::{
    execute_usdd_ownerless_source_v3, UsddOwnerlessSourceInputV3,
};
use ecx_conversion_foundation_v2::usdd_usd::{
    execute_usdd_usd_ethereum_source_v2, UsddUsdEthereumSourceInputV2,
    MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2,
};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof, SP1Stdin,
};

const NO_LOCAL_PROOF_ENV: &str = "ECX_NO_LOCAL_PROOF";
const ACK_ENV: &str = "ECX_ISOLATED_USDD_ETHEREUM_SOURCE_PROOF";
const ACK_VALUE: &str = "I_UNDERSTAND_THIS_REQUIRES_AUTHENTICATED_SEPOLIA_STATE";
const MAX_ELF_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024 * 1024;
const MAX_VKEY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SourceRelation {
    LegacyV2,
    OwnerlessV3,
}

fn expected_public_values(relation: SourceRelation, bytes: &[u8]) -> Result<Vec<u8>> {
    match relation {
        SourceRelation::LegacyV2 => {
            let input = UsddUsdEthereumSourceInputV2::decode_canonical(bytes)
                .context("witness is not canonical UsddUsdEthereumSourceInputV2")?;
            if input.canonical_bytes()? != bytes {
                bail!("V2 witness round trip changed the bytes");
            }
            Ok(execute_usdd_usd_ethereum_source_v2(&input)
                .context("host V2 source relation rejected")?.canonical_bytes())
        }
        SourceRelation::OwnerlessV3 => {
            let input = UsddOwnerlessSourceInputV3::decode_exact(bytes)
                .context("witness is not canonical UsddOwnerlessSourceInputV3")?;
            if input.canonical_bytes()? != bytes {
                bail!("V3 witness round trip changed the bytes");
            }
            Ok(execute_usdd_ownerless_source_v3(&input)
                .context("host ownerless V3 source relation rejected")?.canonical_bytes())
        }
    }
}

#[derive(Debug, Parser)]
#[command(about = "Execute or prove the unfrozen USDD Ethereum source guest")]
struct Arguments {
    #[arg(long)]
    elf: PathBuf,
    /// Canonical `.usdd-ethereum-v2.witness` from the offline exporter.
    #[arg(long)]
    witness: PathBuf,
    /// Explicit witness/guest relation. Never auto-detected or retried as another version.
    #[arg(long, value_enum, default_value_t = SourceRelation::LegacyV2)]
    source_relation: SourceRelation,
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
    i_understand_this_requires_authenticated_sepolia_state: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    require_isolated_proof_worker()?;
    let arguments = Arguments::parse();
    require_acknowledgement(&arguments)?;
    validate_output_shape(&arguments)?;

    let witness_bytes = read_bounded(
        &arguments.witness,
        MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2,
    )?;
    let expected_public_values = expected_public_values(arguments.source_relation, &witness_bytes)?;
    let expected_program_id = parse_program_id(&arguments.expected_program_id_hex)?;

    let elf_bytes = read_bounded(&arguments.elf, MAX_ELF_BYTES)?;
    let prover = ProverClient::builder().cpu().build().await;
    let proving_key = prover
        .setup(Elf::from(elf_bytes.clone()))
        .await
        .context("USDD Ethereum source setup failed")?;
    if words_to_bytes(proving_key.verifying_key().hash_u32()) != expected_program_id {
        bail!("USDD Ethereum source ELF does not match the expected program ID");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(witness_bytes.clone());
    let (executed, report) = prover
        .execute(Elf::from(elf_bytes), stdin)
        .cycle_limit(arguments.cycle_limit)
        .await
        .context("USDD Ethereum source SP1 execute failed")?;
    if report.exit_code != 0 || executed.as_slice() != expected_public_values {
        bail!("USDD Ethereum source execute does not match the host relation");
    }
    write_new(&arguments.output_public_values, &expected_public_values)?;
    println!(
        "execute_ok=true cycles={} public_values_bytes={}",
        report.total_instruction_count(),
        expected_public_values.len()
    );
    if arguments.execute_only {
        return Ok(());
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(witness_bytes);
    let receipt = prover
        .prove(&proving_key, stdin)
        .compressed()
        .cycle_limit(arguments.cycle_limit)
        .await
        .context("USDD Ethereum source compressed proving failed")?;
    if receipt.tee_proof.is_some()
        || !matches!(&receipt.proof, SP1Proof::Compressed(_))
        || receipt.public_values.as_slice() != expected_public_values
    {
        bail!("SP1 returned a TEE, wrong proof mode, or wrong Ethereum source public values");
    }
    prover
        .verify(&receipt, proving_key.verifying_key(), None)
        .context("USDD Ethereum source receipt verification failed")?;
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
    println!("proof_verified=true mode=compressed");
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
    const MODULUS: u32 = 0x7f00_0001;
    if bytes == [0; 32]
        || bytes
            .chunks_exact(4)
            .any(|word| u32::from_be_bytes(word.try_into().expect("four bytes")) >= MODULUS)
    {
        bail!("expected program ID is not canonical for SP1");
    }
    Ok(bytes)
}

fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

fn canonical_serialize<T: serde::Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(maximum as u64)
        .serialize(value)
        .context("cannot serialize canonical SP1 object")?;
    if bytes.len() > maximum {
        bail!("canonical SP1 object exceeds its byte bound");
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = path
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        bail!("{} is not a nonempty bounded regular file", path.display());
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
    if !arguments.i_understand_this_requires_authenticated_sepolia_state
        || env::var(ACK_ENV).as_deref() != Ok(ACK_VALUE)
    {
        bail!(
            "refusing Ethereum source execution or proving without dual acknowledgement (--i-understand-this-requires-authenticated-sepolia-state and {ACK_ENV}={ACK_VALUE})"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_relation_selection_is_explicit_and_unknown_versions_rejected() {
        assert!(matches!(SourceRelation::from_str("legacy-v2", false), Ok(SourceRelation::LegacyV2)));
        assert!(matches!(SourceRelation::from_str("ownerless-v3", false), Ok(SourceRelation::OwnerlessV3)));
        assert!(SourceRelation::from_str("auto", false).is_err());
        assert!(SourceRelation::from_str("ownerless-v4", false).is_err());
    }

    #[test]
    fn both_source_relations_reject_empty_and_noncanonical_witnesses() {
        for relation in [SourceRelation::LegacyV2, SourceRelation::OwnerlessV3] {
            for bytes in [Vec::new(), vec![0; 32], vec![0xff; 128]] {
                assert!(expected_public_values(relation, &bytes).is_err());
            }
        }
    }

    #[test]
    fn expected_program_id_is_exact_and_koalabear_bounded() {
        assert!(parse_program_id(&format!("{:08x}", 1).repeat(8)).is_ok());
        assert!(parse_program_id("00").is_err());
        assert!(parse_program_id(&"ff".repeat(32)).is_err());
    }
}
