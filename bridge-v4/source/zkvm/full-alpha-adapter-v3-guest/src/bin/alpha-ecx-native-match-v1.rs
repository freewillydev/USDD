//! Separate ECX native outer. Consumers must independently pin ECXNJ1 inputs.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3, FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3::ecx_match_execution_v1::{OwnedEcxNativeMatchV1,
    MAX_ECX_NATIVE_INPUT_BYTES, ConsensusProofVerifier, ConsensusProofVerificationError};
use ecx_full_consensus_validator_v2::elements_v2::{ElementsSimplicityReceiptVerifierV2,
    ElementsStateErrorV2};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredVerifier {
    fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
        -> Result<(), FullAlphaAdapterErrorV3> {
        let request = receipt_verification_request(program, journal, marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words, &request.public_values_sha256);
        Ok(())
    }
}
impl ElementsSimplicityReceiptVerifierV2 for DeferredVerifier {
    fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
        -> Result<(), ElementsStateErrorV2> {
        FullAlphaReceiptVerifierV3::verify(self, program, journal, marker)
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)
    }
}
impl ConsensusProofVerifier for DeferredVerifier {
    fn verify(&self, program: [u8;32], journal: &[u8], marker: &[u8])
        -> Result<(), ConsensusProofVerificationError> {
        FullAlphaReceiptVerifierV3::verify(self, program, journal, marker)
            .map_err(|_| ConsensusProofVerificationError)
    }
}
pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced >= 6 && announced <= MAX_ECX_NATIVE_INPUT_BYTES,
        "invalid ECX native input length");
    let bytes = sp1_zkvm::io::read_vec();
    assert_eq!(bytes.len(), announced, "changed hint length");
    let input = OwnedEcxNativeMatchV1::decode(&bytes).expect("invalid ECX native input");
    let result = input.execute(&DeferredVerifier, &DeferredVerifier, &DeferredVerifier)
        .expect("ECX native execution rejected");
    sp1_zkvm::io::commit_slice(result.journal());
}
