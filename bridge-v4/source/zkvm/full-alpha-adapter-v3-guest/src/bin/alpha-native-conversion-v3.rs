#![no_main]
//! Generic native conversion guest. The outer profile MUST pin both this
//! qualified guest ID and the emitted whole-policy source checkpoint commitment.
sp1_zkvm::entrypoint!(main);
use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3,FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;
use ecx_full_consensus_validator_v2::elements_v2::{ElementsSimplicityReceiptVerifierV2,ElementsStateErrorV2};
use ecx_redemption_capability_v2::native_conversion_wire::{decode_native_conversion_input_v3,
    execute_native_conversion_input_v3,MAX_NATIVE_CONVERSION_INPUT_BYTES_V3};

struct RecursiveVerifier;
impl FullAlphaReceiptVerifierV3 for RecursiveVerifier {
    fn verify(&self,program:[u8;32],journal:&[u8],marker:&[u8])->Result<(),FullAlphaAdapterErrorV3> {
        let request=receipt_verification_request(program,journal,marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(&request.program_words,&request.public_values_sha256);
        Ok(())
    }
}
impl ElementsSimplicityReceiptVerifierV2 for RecursiveVerifier {
    fn verify(&self,program:[u8;32],journal:&[u8],marker:&[u8])->Result<(),ElementsStateErrorV2> {
        let request=receipt_verification_request(program,journal,marker)
            .map_err(|_|ElementsStateErrorV2::AuthorizationConsensus)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(&request.program_words,&request.public_values_sha256);
        Ok(())
    }
}
pub fn main() {
    let announced=sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced>0 && announced<=MAX_NATIVE_CONVERSION_INPUT_BYTES_V3,"invalid native conversion input size");
    let encoded=sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(),announced,"SP1 hint length changed");
    let input=decode_native_conversion_input_v3(&encoded).expect("noncanonical native conversion input");
    // This generic guest proves the relation for this committed policy. It does
    // not review the policy. The outer verifier must compare the emitted hash
    // to its independently frozen profile; a valid proof alone is insufficient.
    let policy=input.policy.as_policy().commitment().expect("invalid native policy");
    let output=execute_native_conversion_input_v3(policy,&input,&RecursiveVerifier,&RecursiveVerifier)
        .expect("native conversion rejected");
    assert_eq!(output.source_checkpoint_commitment,policy);
    let journal=output.canonical_bytes();
    assert_eq!(journal.len(),275);
    sp1_zkvm::io::commit_slice(&journal);
}
