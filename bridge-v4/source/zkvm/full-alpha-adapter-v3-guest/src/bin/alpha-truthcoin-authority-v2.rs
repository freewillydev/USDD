#![no_main]
//! Distinct authority journal ABI. Never substitute the legacy replay ELF.
sp1_zkvm::entrypoint!(main);
use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3::truthcoin_authority_guest_v2::{decode_input, execute, MAX_INPUT_BYTES};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct RecursiveVerifier;
impl FullAlphaReceiptVerifierV3 for RecursiveVerifier {
    fn verify(&self, program: [u8;32], bytes: &[u8], marker: &[u8])
        -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program, bytes, marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words, &request.public_values_sha256);
        Ok(())
    }
}

fn frozen_policy() -> [u8;32] {
    let encoded = env!("ECX_ALPHA_TRUTHCOIN_AUTHORITY_POLICY").as_bytes();
    assert_eq!(encoded.len(), 64, "policy must be a lowercase 32-byte hex commitment");
    let nibble = |b| match b {
        b'0'..=b'9' => b-b'0', b'a'..=b'f' => b-b'a'+10,
        _ => panic!("invalid frozen policy hex"),
    };
    let mut value = [0;32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = nibble(encoded[2*index]) * 16 + nibble(encoded[2*index+1]);
    }
    assert_ne!(value, [0;32], "missing frozen authority policy");
    value
}

pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced > 0 && announced <= MAX_INPUT_BYTES, "authority input size");
    let bytes = sp1_zkvm::io::read_vec();
    assert_eq!(bytes.len(), announced, "authority hint length changed");
    let input = decode_input(&bytes).expect("invalid canonical authority witness");
    let journal = execute(&input, frozen_policy(), &RecursiveVerifier)
        .expect("Alpha Truthcoin authority rejected");
    // The authority leaf hashes the journal, then passes SHA256 of these
    // exact 32 public bytes to the compressed-proof verifier.
    sp1_zkvm::io::commit_slice(&journal.public_values());
}
