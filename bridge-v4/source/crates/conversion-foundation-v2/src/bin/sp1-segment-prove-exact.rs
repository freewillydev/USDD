//! Local-only segment receipt generation; explicit opt-in required, no network prover.
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path};
use anyhow::{bail, Result};
use bincode::Options;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof, SP1Stdin};

fn read(path: &str, max: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() { bail!("not a regular file"); }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max { bail!("input size rejected"); }
    Ok(bytes)
}
fn hash(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
fn write(path: &str, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?; f.sync_all()?; Ok(())
}
fn stdin(policy: &[u8], checkpoint: &[u8], witness: &[u8]) -> SP1Stdin {
    let mut input = SP1Stdin::new();
    input.write_vec(policy.to_vec()); input.write_vec(checkpoint.to_vec()); input.write_vec(witness.to_vec()); input
}
#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("ECX_NO_LOCAL_PROOF").is_some()
        || std::env::var("ECX_APPROVED_LOCAL_SEGMENT_PROOF").as_deref() != Ok("yes") {
        bail!("local proof requires explicit approval; no proof started");
    }
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len()!=10 { bail!("usage: ELF POLICY CHECKPOINT WITNESS EXPECTED RECEIPT KEY CYCLE_LIMIT ELF_SHA256 PROGRAM_ID"); }
    let limit: u64 = a[7].parse()?;
    if limit==0 || a[5]==a[6] || Path::new(&a[5]).exists() || Path::new(&a[6]).exists() { bail!("invalid output or cycle limit"); }
    let elf = read(&a[0],32<<20)?;
    if !elf.starts_with(b"\x7fELF") || hash(&elf)!=a[8] { bail!("ELF mismatch"); }
    let policy=read(&a[1],4096)?;
    let checkpoint=read(&a[2],1024)?;
    let witness=read(&a[3],512<<10)?;
    let expected=read(&a[4],1<<20)?;
    println!("elf={} policy={} checkpoint={} witness={} expected={}",hash(&elf),hash(&policy),hash(&checkpoint),hash(&witness),hash(&expected));
    let prover=ProverClient::builder().cpu().build().await;
    let key=prover.setup(Elf::from(elf.clone())).await?;
    let id: String=key.verifying_key().hash_u32().iter().flat_map(|w|w.to_be_bytes()).map(|b|format!("{b:02x}")).collect();
    if id!=a[9] { bail!("program ID mismatch"); }
    let (actual, report)=prover.execute(Elf::from(elf),stdin(&policy,&checkpoint,&witness)).cycle_limit(limit).await?;
    if report.exit_code!=0 || actual.as_slice()!=expected { bail!("execute mismatch"); }
    println!("execute_exact=true cycles={}",report.total_instruction_count());
    let receipt=prover.prove(&key,stdin(&policy,&checkpoint,&witness)).compressed().cycle_limit(limit).await?;
    if receipt.tee_proof.is_some() || !matches!(&receipt.proof,SP1Proof::Compressed(_)) || receipt.public_values.as_slice()!=expected { bail!("receipt mode or output mismatch"); }
    prover.verify(&receipt,key.verifying_key(),None)?;
    let encoded=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(64<<20).serialize(&receipt)?;
    let encoded_key=bincode::DefaultOptions::new().with_fixint_encoding().with_limit(16<<20).serialize(key.verifying_key())?;
    write(&a[5],&encoded)?; write(&a[6],&encoded_key)?;
    println!("proof_verified=true receipt_sha256={} key_sha256={} program_id={id}",hash(&encoded),hash(&encoded_key));
    Ok(())
}
