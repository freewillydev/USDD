//! Local execute-only qualification with one real compressed child receipt.
//! Expected journals/keys must come from the selected configuration, not test placeholders.
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path};
use anyhow::{bail, Result};
use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

fn read(path: &str, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() { bail!("not a regular file: {path}"); }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit { bail!("invalid file size: {path}"); }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], limit: u64) -> Result<T> {
    if bytes.is_empty() || bytes.len() as u64 > limit { bail!("encoded object exceeds bound"); }
    let value = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(limit).reject_trailing_bytes().deserialize(bytes)?;
    let encoded = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&value)?;
    if encoded != bytes { bail!("noncanonical bincode"); }
    Ok(value)
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 10 && args.len() != 15 {
        bail!("usage: sp1-recursive-execute-exact ELF INPUT EXPECTED CHILD_RECEIPT CHILD_KEY CHILD_ID_HEX CHILD_JOURNAL OUTPUT CYCLE_LIMIT ELF_SHA256 [CATCHUP_POLICY VAULT_POLICY SOURCE_STATE ACTION STORAGE_WITNESS]; optional paths select terminal multi-hint mode, with INPUT=configuration");
    }
    let limit: u64 = args[8].parse()?;
    if limit == 0 || Path::new(&args[7]).exists() { bail!("zero cycle limit or existing output"); }
    let elf = read(&args[0], 32 << 20)?;
    if !elf.starts_with(b"\x7fELF") { bail!("not an ELF"); }
    check_digest(&elf, &args[9])?;
    let input = read(&args[1], (4 << 20) + (64 << 10))?;
    let expected = read(&args[2], 1 << 20)?;
    let receipt: SP1ProofWithPublicValues = decode(&read(&args[3], 64 << 20)?, 64 << 20)?;
    let key: SP1VerifyingKey = decode(&read(&args[4], 16 << 20)?, 16 << 20)?;
    let id: String = key.hash_u32().iter().map(|word| format!("{word:08x}")).collect();
    if id != args[5] || receipt.tee_proof.is_some()
        || receipt.public_values.as_slice() != read(&args[6], 1 << 20)? {
        bail!("child identity, mode or exact journal mismatch");
    }
    let SP1Proof::Compressed(proof) = &receipt.proof else { bail!("child must be compressed"); };
    let prover = ProverClient::builder().cpu().build().await;
    prover.verify(&receipt, &key, None)?;
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input);
    if args.len() == 15 {
        // Match the terminal guest's exact ordered read_vec/read<T> ABI.
        stdin.write_vec(read(&args[10], 4 << 10)?);
        stdin.write_vec(read(&args[11], 4 << 10)?);
        stdin.write_vec(read(&args[12], 4 << 10)?);
        stdin.write(&key.hash_u32());
        let journal_digest: [u8; 32] = Sha256::digest(receipt.public_values.as_slice()).into();
        stdin.write(&journal_digest);
        stdin.write_vec(receipt.public_values.as_slice().to_vec());
        stdin.write_vec(read(&args[13], 4 << 10)?);
        stdin.write_vec(read(&args[14], (3 << 20) + (64 << 10))?);
    }
    stdin.write_proof((**proof).clone(), key.vk.clone());
    let (actual, report) = prover.execute(Elf::from(elf), stdin)
        .cycle_limit(limit).deferred_proof_verification(true).await?;
    if report.exit_code != 0 || actual.as_slice() != expected {
        bail!("execution failed or journal differs");
    }
    let mut out = OpenOptions::new().write(true).create_new(true).open(&args[7])?;
    out.write_all(actual.as_slice())?;
    out.sync_all()?;
    println!("execute_exact=true child_receipts=1 cycles={} proof_generated=false", report.total_instruction_count());
    Ok(())
}

fn check_digest(bytes: &[u8], expected: &str) -> Result<()> {
    let actual: String = Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != expected { bail!("selected ELF digest mismatch"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_decode_rejects_trailing_truncated_and_over_limit() {
        let value = vec![1u8, 2, 3];
        let bytes = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&value).unwrap();
        assert_eq!(decode::<Vec<u8>>(&bytes, 64).unwrap(), value);
        let mut extra = bytes.clone(); extra.push(0);
        assert!(decode::<Vec<u8>>(&extra, 64).is_err());
        assert!(decode::<Vec<u8>>(&bytes[..bytes.len()-1], 64).is_err());
        assert!(decode::<Vec<u8>>(&bytes, 2).is_err());
    }
    #[test]
    fn selected_elf_digest_cannot_be_substituted() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(check_digest(b"abc", expected).is_ok());
        assert!(check_digest(b"abd", expected).is_err());
        assert!(check_digest(b"abc", "").is_err());
    }
}
