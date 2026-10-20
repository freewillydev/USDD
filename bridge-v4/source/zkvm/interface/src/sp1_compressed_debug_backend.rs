use std::borrow::Borrow;

use bincode::Options;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_verifier::{
    compressed::{CompressedError, SP1CompressedVerifier},
    SP1Proof,
};

use crate::DebugCompressedSp1Backend;

#[derive(Debug)]
pub enum Sp1CompressedDebugV6_3_1VerificationError {
    NonCanonicalProof(Box<bincode::ErrorKind>),
    NotCompressed,
    Cryptographic(CompressedError),
    PublicValuesSha256Mismatch,
}

/// Integrity-only SP1 6.3.1 compressed-proof adapter.
///
/// This path is intentionally gated behind `debug-compressed-backend`. It is
/// not an acceptable production proof for confidential positions.
#[derive(Debug, Default)]
pub struct Sp1CompressedDebugV6_3_1Backend;

impl DebugCompressedSp1Backend for Sp1CompressedDebugV6_3_1Backend {
    type Error = Sp1CompressedDebugV6_3_1VerificationError;

    fn verify_debug_compressed_sha256(
        &self,
        proof: &[u8],
        program_id_words: [u32; 8],
        public_values_sha256: [u8; 32],
    ) -> Result<(), Self::Error> {
        let decoded: SP1Proof = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(proof)
            .map_err(Sp1CompressedDebugV6_3_1VerificationError::NonCanonicalProof)?;
        let SP1Proof::Compressed(compressed) = decoded else {
            return Err(Sp1CompressedDebugV6_3_1VerificationError::NotCompressed);
        };

        let program_id = program_id_words.map(SP1Field::from_canonical_u32);
        SP1CompressedVerifier::new()
            .verify_compressed(&compressed, &program_id)
            .map_err(Sp1CompressedDebugV6_3_1VerificationError::Cryptographic)?;

        let recursion_values: &RecursionPublicValues<SP1Field> =
            compressed.proof.public_values.as_slice().borrow();
        let mut committed_digest = [0_u8; 32];
        for (output, field_byte) in committed_digest
            .iter_mut()
            .zip(recursion_values.committed_value_digest.iter().flatten())
        {
            *output = field_byte.as_canonical_u32() as u8;
        }
        if !constant_time_equal(&committed_digest, &public_values_sha256) {
            return Err(Sp1CompressedDebugV6_3_1VerificationError::PublicValuesSha256Mismatch);
        }
        Ok(())
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_compressed_proof_type_is_rejected() {
        let encoded = bincode::serialize(&SP1Proof::Plonk(Default::default())).unwrap();
        let error = Sp1CompressedDebugV6_3_1Backend
            .verify_debug_compressed_sha256(&encoded, [1; 8], [2; 32])
            .unwrap_err();
        assert!(matches!(
            error,
            Sp1CompressedDebugV6_3_1VerificationError::NotCompressed
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected_before_verification() {
        let mut encoded = bincode::serialize(&SP1Proof::Plonk(Default::default())).unwrap();
        encoded.push(0);
        let error = Sp1CompressedDebugV6_3_1Backend
            .verify_debug_compressed_sha256(&encoded, [1; 8], [2; 32])
            .unwrap_err();
        assert!(matches!(
            error,
            Sp1CompressedDebugV6_3_1VerificationError::NonCanonicalProof(_)
        ));
    }
}
