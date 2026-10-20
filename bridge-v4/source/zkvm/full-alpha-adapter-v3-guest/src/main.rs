#![no_main]

// Distinct parent-consensus adapter, not an Alpha conversion proof. Release
// must rebuild/freeze this guest and the exact outer AlphaRecursiveBindingV3.
sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::{
    decode_full_alpha_adapter_input_v3, encode_full_alpha_statement_v3,
    execute_full_alpha_adapter_v3, FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3,
    FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3,
};
use ecx_full_alpha_adapter_v3_sp1_guest::{
    announced_input_length_is_valid, receipt_verification_request,
};

struct DeferredReceiptVerifier;

impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program_id, public_values, proof_marker)?;
        // Mandatory cryptographic verification of the next deferred receipt.
        // Marker equality merely aligns the witness with this receipt stream.
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
        announced_input_length_is_valid(announced),
        "full Alpha adapter input is empty or oversized"
    );
    let encoded = sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(), announced, "SP1 hint length changed");
    let input = decode_full_alpha_adapter_input_v3(&encoded)
        .expect("full Alpha adapter input is not canonical");
    let statement = execute_full_alpha_adapter_v3(&input, &DeferredReceiptVerifier)
        .expect("full Alpha recursive adapter rejected");
    let public_values =
        encode_full_alpha_statement_v3(&statement).expect("full Alpha statement encoding rejected");
    assert_eq!(
        public_values.len(),
        FULL_ALPHA_ADAPTER_PUBLIC_VALUES_BYTES_V3
    );
    sp1_zkvm::io::commit_slice(&public_values);
}
