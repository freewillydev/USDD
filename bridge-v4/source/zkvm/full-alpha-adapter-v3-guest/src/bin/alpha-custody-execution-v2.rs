#![no_main]
//! Candidate 64-byte policy/statement composition, NOT the vault's 32-byte ABI.
//! The enclosing release must authenticate policy and canonical parent context.
sp1_zkvm::entrypoint!(main);

use ecx_full_alpha_adapter_v3::{FullAlphaAdapterErrorV3,FullAlphaReceiptVerifierV3};
use ecx_full_alpha_adapter_v3::child_execution_guest_v3::{
    AlphaChildSimplicityReceiptVerifierV3,AlphaChildScriptErrorV3};
use ecx_full_alpha_adapter_v3::custody_execution_wire_v2::{
    decode_custody_execution_v2,MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2};
use ecx_full_alpha_adapter_v3::custody_execution_v2::execute_custody_v2;
use ecx_full_alpha_adapter_v3_sp1_guest::receipt_verification_request;

struct DeferredReceiptVerifier;
impl FullAlphaReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(&self,program:[u8;32],journal:&[u8],marker:&[u8])
        -> Result<(),FullAlphaAdapterErrorV3> {
        let request=receipt_verification_request(program,journal,marker)?;
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &request.program_words,&request.public_values_sha256);
        Ok(())
    }
}
impl AlphaChildSimplicityReceiptVerifierV3 for DeferredReceiptVerifier {
    fn verify(&self,program:[u8;32],journal:&[u8],marker:&[u8])
        -> Result<(),AlphaChildScriptErrorV3> {
        FullAlphaReceiptVerifierV3::verify(self,program,journal,marker)
            .map_err(|_|AlphaChildScriptErrorV3::AuthorizationConsensus)
    }
}

pub fn main() {
    let announced=sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced>0 && announced<=MAX_CUSTODY_EXECUTION_WIRE_BYTES_V2,
        "Alpha custody input is empty or oversized");
    let encoded=sp1_zkvm::io::read_vec();
    assert_eq!(encoded.len(),announced,"SP1 hint length changed");
    let input=decode_custody_execution_v2(&encoded).expect("noncanonical Alpha custody input");
    let output=execute_custody_v2(&input.policy,&input.child,&input.history,
        &input.lineage_receipts,usize::try_from(input.transaction_index).expect("transaction index"),
        input.output_index,&DeferredReceiptVerifier,&DeferredReceiptVerifier)
        .expect("Alpha custody execution rejected");
    // Never discard the policy half: witness-selected trust roots are not
    // authenticated merely by producing a proof of this composition.
    sp1_zkvm::io::commit_slice(&output.canonical_bytes());
}
