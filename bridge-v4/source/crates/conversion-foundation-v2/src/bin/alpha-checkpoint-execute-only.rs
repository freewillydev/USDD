//! Pinned local execution only; LightProver cannot generate a proof.
use anyhow::{ensure,Result};
use sha2::{Digest,Sha256};
use sp1_sdk::{Elf,Prover,ProverClient,SP1Stdin};
use std::{fs,path::Path};
fn hex(b:&[u8])->String {b.iter().map(|x|format!("{x:02x}")).collect()}
fn pinned(path:&Path,expected:&str)->Result<Vec<u8>> {
    let b=fs::read(path)?;ensure!(hex(&Sha256::digest(&b))==expected,"hash mismatch: {}",path.display());Ok(b)
}
#[tokio::main]
async fn main()->Result<()> {
    let args:Vec<String>=std::env::args().collect();ensure!(args.len()==3,"expected ELF and recovery directory");
    let elf=pinned(Path::new(&args[1]),"934beb7ffb1784e92b22c40ce322ffafc6e3c8bae1fd9fcd3bb88ad889b4a575")?;
    let root=Path::new(&args[2]);
    // Corrected historical BIP16 anchor; old enforcement-suffix candidate is not accepted.
    let input=pinned(&root.join("reviewed-checkpoint-bip16-corrected.bin"),"f50b326ed9b44fbd3679f0ca9e482f79623bbdecbb53074cdd8cbd634aed2df5")?;
    let expected=pinned(&root.join("reviewed-checkpoint-bip16-corrected.public-values.bin"),"6418456110654c7bd42e7813c21742fc53b73e4637ddcf881c35b492b0f10f49")?;
    let mut stdin=SP1Stdin::new();stdin.write_vec(input);
    let client=ProverClient::builder().light().build().await;
    let (public,report)=client.execute(Elf::from(elf),stdin).cycle_limit(100_000_000).await?;
    ensure!(report.exit_code==0,"guest exited unsuccessfully");
    ensure!(public.as_slice()==expected.as_slice(),"guest/native public values differ");
    println!("guest_execution_passed=true\npublic_values_bytes={}\npublic_values_sha256={}\nproof_generated=false\nconsumer_frozen=false\nproof_ready=false",expected.len(),hex(&Sha256::digest(&expected)));
    Ok(())
}
