#![no_main]
//! Membership relative to an authenticated Alpha tip; not a freshness oracle.
//! The relay must pin the binding and authenticate the accepted terminal state.
sp1_zkvm::entrypoint!(main);
use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3,
    parent_finality_wire_v3::{decode_parent_finality_v3, execute_parent_finality_v3,
        MAX_PARENT_FINALITY_WIRE_BYTES_V3, PARENT_FINALITY_PUBLIC_VALUES_BYTES_V3}};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredReceiptVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(&self, program_id: [u8; 32], public_values: &[u8], proof_marker: &[u8])
        -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program_id, public_values, proof_marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words, &request.public_values_sha256);
        Ok(())
    }
}
pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced > 0 && announced <= MAX_PARENT_FINALITY_WIRE_BYTES_V3,
        "Alpha membership input is empty or oversized");
    let encoded = sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(), announced, "SP1 hint length changed");
    let input = decode_parent_finality_v3(&encoded).expect("noncanonical Alpha membership input");
    let public_values = execute_parent_finality_v3(&input, &DeferredReceiptVerifier)
        .expect("Alpha membership verification rejected");
    assert_eq!(public_values.len(), PARENT_FINALITY_PUBLIC_VALUES_BYTES_V3);
    sp1_zkvm::io::commit_slice(&public_values);
}
