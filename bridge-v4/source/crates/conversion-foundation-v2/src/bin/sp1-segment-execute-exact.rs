//! Execute the Ethereum segment's three separate hints; never generate a proof.
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

fn read(path: &str, max: usize) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    if !f.metadata()?.is_file() { bail!("not a regular file"); }
    let mut bytes = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max { bail!("invalid input size"); }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 8 { bail!("usage: sp1-segment-execute-exact ELF POLICY CHECKPOINT WITNESS EXPECTED OUTPUT CYCLE_LIMIT ELF_SHA256"); }
    let limit: u64 = a[6].parse()?;
    if limit == 0 || Path::new(&a[5]).exists() { bail!("zero limit or existing output"); }
    let elf = read(&a[0], 32 << 20)?;
    if !elf.starts_with(b"\x7fELF") || digest(&elf) != a[7] { bail!("ELF pin mismatch"); }
    let policy = read(&a[1], 4096)?;
    let checkpoint = read(&a[2], 1024)?;
    let witness = read(&a[3], 512 << 10)?;
    let expected = read(&a[4], 1 << 20)?;
    println!("elf={} policy={} checkpoint={} witness={} expected={}", digest(&elf), digest(&policy), digest(&checkpoint), digest(&witness), digest(&expected));
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(policy);
    stdin.write_vec(checkpoint);
    stdin.write_vec(witness);
    let prover = ProverClient::builder().light().build().await;
    let (actual, report) = prover.execute(Elf::from(elf), stdin).cycle_limit(limit).await?;
    if report.exit_code != 0 || actual.as_slice() != expected { bail!("execution or exact journal comparison failed"); }
    let mut out = OpenOptions::new().write(true).create_new(true).open(&a[5])?;
    out.write_all(actual.as_slice())?;
    out.sync_all()?;
    println!("execute_exact=true cycles={} journal_bytes={} proof_generated=false", report.total_instruction_count(), actual.as_slice().len());
    Ok(())
}
