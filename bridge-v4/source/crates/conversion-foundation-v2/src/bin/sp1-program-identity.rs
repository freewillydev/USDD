//! Derive an actual SP1 verification-key identity without proving or executing.
//! The output is an identity, never evidence that a witness or live binding is valid.
use std::{fs::File, io::Read, path::PathBuf};
use anyhow::{bail, Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};

const MAX_ELF_BYTES: usize = 32 * 1024 * 1024;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    elf: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    let file = File::open(&args.elf).context("open ELF")?;
    if !file.metadata()?.is_file() { bail!("ELF must be a regular file"); }
    let mut bytes = Vec::new();
    file.take((MAX_ELF_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ELF_BYTES || !bytes.starts_with(b"\x7fELF") {
        bail!("invalid ELF or ELF exceeds 32 MiB");
    }
    let elf_sha256 = hex(&Sha256::digest(&bytes));
    // LightProver performs real machine setup; its prove operation always errors.
    let prover = ProverClient::builder().light().build().await;
    let pk = prover.setup(Elf::from(bytes)).await.context("real SP1 setup failed")?;
    let program_id: Vec<u8> = pk.verifying_key().hash_u32().into_iter()
        .flat_map(u32::to_be_bytes).collect();
    println!("elf_sha256={elf_sha256}");
    println!("sp1_program_id={}", hex(&program_id));
    println!("witness_executed=false\nproof_generated=false\nproof_ready=false");
    Ok(())
}
