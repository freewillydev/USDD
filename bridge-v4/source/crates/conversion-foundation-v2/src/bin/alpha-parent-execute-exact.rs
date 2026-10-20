//! One-vector parent execution. LightProver cannot generate receipts.
//! Caller pins must come from reviewed producer evidence, not fixture identities.
use anyhow::{ensure, Result};
use clap::{Parser, ValueEnum};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::{fs::File, io::Read, path::PathBuf};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Role { ReviewedCheckpoint, Transition }
impl Role {
    fn sizes(self) -> (usize, usize) {
        match self {
            Self::ReviewedCheckpoint => (4 << 20, 277),
            Self::Transition => (16 << 20, 333),
        }
    }
}
#[derive(Parser)]
struct Args {
    #[arg(long, value_enum)] role: Role,
    #[arg(long)] elf: PathBuf,
    #[arg(long)] elf_sha256: String,
    #[arg(long)] program_id: String,
    #[arg(long)] input: PathBuf,
    #[arg(long)] input_sha256: String,
    #[arg(long)] expected: PathBuf,
    #[arg(long)] expected_sha256: String,
    #[arg(long)] cycle_limit: u64,
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(s: &str) -> Result<()> {
    ensure!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "noncanonical digest");
    Ok(())
}
fn checked(bytes: Vec<u8>, max: usize, expected: &str) -> Result<Vec<u8>> {
    digest(expected)?;
    ensure!(!bytes.is_empty() && bytes.len() <= max, "input size rejected");
    ensure!(hash(&bytes) == expected, "pinned hash mismatch");
    Ok(bytes)
}
fn read(path: &PathBuf, max: usize, expected: &str) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "not a regular file");
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    checked(bytes, max, expected)
}
fn stdin(input: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input.to_vec());
    stdin
}
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    ensure!(a.cycle_limit > 0, "cycle limit must be positive");
    digest(&a.program_id)?;
    let (max_input, public_len) = a.role.sizes();
    let elf = read(&a.elf, 32 << 20, &a.elf_sha256)?;
    ensure!(elf.starts_with(b"\x7fELF"), "not ELF");
    let input = read(&a.input, max_input, &a.input_sha256)?;
    let expected = read(&a.expected, public_len, &a.expected_sha256)?;
    ensure!(expected.len() == public_len, "wrong role public length");
    println!("stage=setup input_bytes={} cycle_limit={}", input.len(), a.cycle_limit);
    let client = ProverClient::builder().light().build().await;
    let key = client.setup(Elf::from(elf.clone())).await?;
    let id: String = key.verifying_key().hash_u32().iter()
        .flat_map(|w| w.to_be_bytes()).map(|b| format!("{b:02x}")).collect();
    ensure!(id == a.program_id, "program ID mismatch");
    println!("stage=execute program_id={id} calculate_gas=true");
    let (actual, report) = client.execute(Elf::from(elf), stdin(&input))
        .calculate_gas(true).cycle_limit(a.cycle_limit).await?;
    ensure!(report.exit_code == 0, "guest execution failed");
    ensure!(actual.as_slice() == expected.as_slice(), "public values differ");
    println!("execute_exact=true\ncycles={}\nprogram_id={}\ninput_sha256={}\npublic_values_sha256={}\nproof_generated=false\nproof_ready=false",
        report.total_instruction_count(), id, hash(&input), hash(&expected));
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_and_role_bounds_reject_substitution() {
        assert_eq!(Role::ReviewedCheckpoint.sizes(), (4 << 20, 277));
        assert_eq!(Role::Transition.sizes(), (16 << 20, 333));
        let bytes = vec![1, 2, 3];
        assert!(checked(bytes.clone(), 3, &hash(&bytes)).is_ok());
        assert!(checked(bytes.clone(), 2, &hash(&bytes)).is_err());
        assert!(checked(bytes.clone(), 3, &hash(&[1, 2, 4])).is_err());
        assert!(checked(vec![], 3, &hash(&[])).is_err());
        assert!(digest(&"A".repeat(64)).is_err());
        assert!(digest(&"0".repeat(63)).is_err());
    }
    #[test]
    fn transport_is_one_exact_vector() {
        let encoded = stdin(&[0xa3, 0, 1, 255]);
        assert_eq!(encoded.buffer[0], vec![0xa3, 0, 1, 255]);
        assert_eq!(encoded.buffer.len(), 1);
    }
}
