use sha2::{Digest, Sha256};
use sp1_verifier::{Groth16Error, Groth16Verifier, GROTH16_VK_BYTES, VK_ROOT_BYTES};

use crate::{Groth16Sp1Backend, GROTH16_PROOF_LEN, KOALA_BEAR_MODULUS};

const WRAPPER_VKEY_PREFIX_LEN: usize = 4;
const METADATA_WORD_LEN: usize = 32;
const RAW_PROOF_OFFSET: usize = WRAPPER_VKEY_PREFIX_LEN + (3 * METADATA_WORD_LEN);

#[derive(Debug)]
pub enum Sp1Groth16V6_3_1VerificationError {
    WrongProofLength,
    InvalidProgramId,
    WrapperVkeyHashMismatch,
    NonZeroExitCode,
    RecursionVkeyRootMismatch,
    Cryptographic(Groth16Error),
}

/// Pinned, SHA-only adapter around SP1 6.3.1's Groth16 verifier.
///
/// SP1's high-level verifier accepts either SHA-256 or BLAKE3 public-value
/// hashing. Consensus must not call it. This adapter reconstructs the five
/// BN254 public inputs and calls only the low-level Groth16 pairing verifier.
#[derive(Debug, Default)]
pub struct Sp1Groth16V6_3_1Backend;

impl Groth16Sp1Backend for Sp1Groth16V6_3_1Backend {
    type Error = Sp1Groth16V6_3_1VerificationError;

    fn verify_groth16_sha256(
        &self,
        proof: &[u8],
        program_id_words: [u32; 8],
        public_values_sha256: [u8; 32],
    ) -> Result<(), Self::Error> {
        if proof.len() != GROTH16_PROOF_LEN {
            return Err(Sp1Groth16V6_3_1VerificationError::WrongProofLength);
        }
        let program_id_bn254 = program_id_words_to_bn254(program_id_words)
            .ok_or(Sp1Groth16V6_3_1VerificationError::InvalidProgramId)?;

        let wrapper_vkey_sha256 = groth16_wrapper_vkey_sha256();
        if !constant_time_equal(
            &proof[..WRAPPER_VKEY_PREFIX_LEN],
            &wrapper_vkey_sha256[..WRAPPER_VKEY_PREFIX_LEN],
        ) {
            return Err(Sp1Groth16V6_3_1VerificationError::WrapperVkeyHashMismatch);
        }

        let exit_code: [u8; 32] = proof[4..36].try_into().expect("fixed proof metadata");
        if !constant_time_equal(&exit_code, &[0; 32]) {
            return Err(Sp1Groth16V6_3_1VerificationError::NonZeroExitCode);
        }
        let recursion_vkey_root: [u8; 32] = proof[36..68].try_into().expect("fixed proof metadata");
        if !constant_time_equal(&recursion_vkey_root, &*VK_ROOT_BYTES) {
            return Err(Sp1Groth16V6_3_1VerificationError::RecursionVkeyRootMismatch);
        }
        let proof_nonce: [u8; 32] = proof[68..100].try_into().expect("fixed proof metadata");

        // SP1 maps the SHA-256 digest into BN254 by clearing the three most
        // significant bits. The annex still commits the full SHA-256 digest;
        // this conversion is performed exactly once at the circuit boundary.
        let public_values_bn254 = sha256_to_bn254(public_values_sha256);
        Groth16Verifier::verify_gnark_proof(
            &proof[RAW_PROOF_OFFSET..],
            &[
                program_id_bn254,
                public_values_bn254,
                exit_code,
                recursion_vkey_root,
                proof_nonce,
            ],
            *GROTH16_VK_BYTES,
        )
        .map_err(Sp1Groth16V6_3_1VerificationError::Cryptographic)
    }
}

/// SHA-256 identity of SP1 6.3.1's embedded Groth16 wrapper verifying key.
pub fn groth16_wrapper_vkey_sha256() -> [u8; 32] {
    Sha256::digest(*GROTH16_VK_BYTES).into()
}

/// SP1 6.3.1's recursion verifying-key root in canonical BN254 bytes.
pub fn recursion_vkey_root_bn254() -> [u8; 32] {
    *VK_ROOT_BYTES
}

/// Convert SP1's eight canonical KoalaBear vkey words to the BN254 field
/// encoding used by the Groth16 circuit (`acc = acc * 2^31 + word`).
pub fn program_id_words_to_bn254(words: [u32; 8]) -> Option<[u8; 32]> {
    if words == [0; 8] || words.iter().any(|word| *word >= KOALA_BEAR_MODULUS) {
        return None;
    }
    let mut output = [0_u8; 32];
    for word in words {
        for _ in 0..31 {
            let mut carry = 0_u8;
            for byte in output.iter_mut().rev() {
                let next_carry = *byte >> 7;
                *byte = (*byte << 1) | carry;
                carry = next_carry;
            }
            debug_assert_eq!(carry, 0, "eight 31-bit words fit in 248 bits");
        }
        let mut addend = u64::from(word);
        for byte in output.iter_mut().rev() {
            let sum = u64::from(*byte) + (addend & 0xff);
            *byte = sum as u8;
            addend = (addend >> 8) + (sum >> 8);
        }
        debug_assert_eq!(addend, 0, "canonical program ID fits in 248 bits");
    }
    Some(output)
}

pub fn sha256_to_bn254(mut digest: [u8; 32]) -> [u8; 32] {
    digest[0] &= 0x1f;
    digest
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
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
    use slop_algebra::{AbstractField, PrimeField};
    use sp1_hypercube::koalabears_to_bn254;
    use sp1_primitives::SP1Field;

    fn structurally_valid_metadata() -> [u8; GROTH16_PROOF_LEN] {
        let mut proof = [0_u8; GROTH16_PROOF_LEN];
        proof[..4].copy_from_slice(&groth16_wrapper_vkey_sha256()[..4]);
        proof[36..68].copy_from_slice(&recursion_vkey_root_bn254());
        proof[68..100].copy_from_slice(&[0x42; 32]);
        proof
    }

    #[test]
    fn pinned_wrapper_vkey_identity_is_frozen() {
        assert_eq!(
            groth16_wrapper_vkey_sha256(),
            [
                0x43, 0x88, 0xa2, 0x1c, 0x68, 0x7f, 0xdd, 0x5f, 0x21, 0x8d, 0x7e, 0x3d, 0x13, 0x19,
                0x0c, 0xac, 0x4c, 0x53, 0x55, 0x81, 0x8d, 0x36, 0x05, 0xfd, 0x5f, 0xb8, 0x11, 0xdf,
                0x46, 0x8e, 0xe6, 0x96,
            ]
        );
        assert_eq!(
            recursion_vkey_root_bn254(),
            [
                0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08,
                0x14, 0xb0, 0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0,
                0x57, 0xf2, 0x53, 0x52,
            ]
        );
    }

    #[test]
    fn koalabear_to_bn254_conversion_matches_sp1_formula() {
        let words = [1, 2, 3, 4, 5, 6, 7, 8];
        let converted = program_id_words_to_bn254(words).unwrap();
        assert_eq!(
            converted,
            [
                0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x18, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x03,
                0x80, 0x00, 0x00, 0x08,
            ]
        );
        let official = koalabears_to_bn254(&words.map(SP1Field::from_canonical_u32))
            .as_canonical_biguint()
            .to_bytes_be();
        assert_eq!(&converted[32 - official.len()..], official);
        assert!(converted[..32 - official.len()]
            .iter()
            .all(|byte| *byte == 0));
        assert!(program_id_words_to_bn254([0; 8]).is_none());
        assert!(program_id_words_to_bn254([KOALA_BEAR_MODULUS; 8]).is_none());
    }

    #[test]
    fn sha256_mapping_clears_only_the_sp1_bn254_bits() {
        let mut expected = [0xff; 32];
        expected[0] = 0x1f;
        assert_eq!(sha256_to_bn254([0xff; 32]), expected);
    }

    #[test]
    fn malformed_wrapper_metadata_fails_before_pairing() {
        let backend = Sp1Groth16V6_3_1Backend;
        let mut proof = structurally_valid_metadata();

        proof[0] ^= 1;
        assert!(matches!(
            backend.verify_groth16_sha256(&proof, [1; 8], [2; 32]),
            Err(Sp1Groth16V6_3_1VerificationError::WrapperVkeyHashMismatch)
        ));

        let mut proof = structurally_valid_metadata();
        proof[4] = 1;
        assert!(matches!(
            backend.verify_groth16_sha256(&proof, [1; 8], [2; 32]),
            Err(Sp1Groth16V6_3_1VerificationError::NonZeroExitCode)
        ));

        let mut proof = structurally_valid_metadata();
        proof[36] ^= 1;
        assert!(matches!(
            backend.verify_groth16_sha256(&proof, [1; 8], [2; 32]),
            Err(Sp1Groth16V6_3_1VerificationError::RecursionVkeyRootMismatch)
        ));
    }

    #[test]
    fn invalid_raw_proof_is_rejected_cryptographically() {
        let error = Sp1Groth16V6_3_1Backend
            .verify_groth16_sha256(&structurally_valid_metadata(), [1; 8], [2; 32])
            .unwrap_err();
        assert!(matches!(
            error,
            Sp1Groth16V6_3_1VerificationError::Cryptographic(_)
        ));
    }
}
