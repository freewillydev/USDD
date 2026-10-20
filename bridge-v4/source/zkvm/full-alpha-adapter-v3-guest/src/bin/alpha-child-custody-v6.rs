#![no_main]

sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3::child_execution_guest_v3::{
    AlphaChildSimplicityReceiptVerifierV3, AlphaChildScriptErrorV3,
};
use ecx_full_alpha_adapter_v3::child_execution_guest_v4::MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4;
use ecx_full_alpha_adapter_v3::child_custody_guest_v6::{
    decode_custody_execution_input_v6, execute_owned_custody_v6,
};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredReceiptVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
        -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program, journal, marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words, &request.public_values_sha256);
        Ok(())
    }
}
impl AlphaChildSimplicityReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
        -> Result<(), AlphaChildScriptErrorV3> {
        FullAlphaReceiptVerifierV3::verify(self, program, journal, marker)
            .map_err(|_| AlphaChildScriptErrorV3::AuthorizationConsensus)
    }
}

pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced > 0 && announced <= MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4,
        "Alpha custody child input is empty or oversized");
    let encoded = sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(), announced, "SP1 hint length changed");
    let input = decode_custody_execution_input_v6(&encoded)
        .expect("noncanonical Alpha custody child input");
    let output = execute_owned_custody_v6(&input,
        &DeferredReceiptVerifier, &DeferredReceiptVerifier)
        .expect("Alpha custody parent/child/accounting execution rejected");
    // Distinct 0xae/407-byte full-anchor statement, never a legacy receipt.
    sp1_zkvm::io::commit_slice(&output.public_values().canonical_bytes());
}
