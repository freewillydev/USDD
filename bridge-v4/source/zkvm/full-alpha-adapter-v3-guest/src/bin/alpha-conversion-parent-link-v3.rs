#![no_main]

// Distinct 266-byte parent/opaque-M7 journal. NOT a child/conversion/reserve proof.
// Verification must independently pin its rebuilt program and binding hash.
sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::conversion_parent_link_v3::{
    decode_alpha_conversion_parent_link_input_v3, execute_alpha_conversion_parent_link_v3,
    MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3,
};
use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredReceiptVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(
        &self,
        program: [u8; 32],
        public_values: &[u8],
        marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program, public_values, marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words,
            &request.public_values_sha256,
        );
        Ok(())
    }
}

pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(
        announced > 0 && announced <= MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3,
        "Alpha conversion parent-link input is empty or oversized"
    );
    let encoded = sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(), announced, "SP1 hint length changed");
    let input = decode_alpha_conversion_parent_link_input_v3(&encoded)
        .expect("noncanonical Alpha parent-link input");
    let output = execute_alpha_conversion_parent_link_v3(&input, &DeferredReceiptVerifier)
        .expect("Alpha parent/checkpoint/slot24/BMM link rejected");
    sp1_zkvm::io::commit_slice(&output.canonical_bytes());
}
