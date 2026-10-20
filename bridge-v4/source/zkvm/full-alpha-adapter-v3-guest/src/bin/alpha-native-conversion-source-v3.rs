#![no_main]
//! Source/accounting component only. Does not emit the final conversion ABI.
sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::native_conversion_source_v3::{
    decode_native_conversion_source_input_v3, execute_native_conversion_source_v3,
    MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3,
};
use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredReceiptVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(
        &self,
        program: [u8; 32],
        journal: &[u8],
        marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program, journal, marker)?;
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
        announced > 0 && announced <= MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3,
        "native source input is empty or oversized"
    );
    let encoded = sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(), announced, "SP1 hint length changed");
    let input = decode_native_conversion_source_input_v3(&encoded)
        .expect("noncanonical native source input");
    // A generic guest publishes its binding; the enclosing consumer must pin
    // that output to its independently qualified source. This is not review.
    let binding = input
        .binding
        .commitment()
        .expect("invalid native source binding");
    let output = execute_native_conversion_source_v3(&input, binding, &DeferredReceiptVerifier)
        .expect("native source execution/clock/finality/accounting rejected");
    sp1_zkvm::io::commit_slice(&output.canonical_bytes());
}
