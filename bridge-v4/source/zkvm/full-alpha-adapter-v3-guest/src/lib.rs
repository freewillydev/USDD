//! Deterministic input/receipt bindings for the full-Alpha SP1 guest.
//!
//! These helpers do NOT verify a proof. Only the guest's call to
//! `sp1_zkvm::lib::verify::verify_sp1_proof` implements recursive verification.

use ecx_full_alpha_adapter_v3::{
    alpha_sp1_program_id_is_canonical_v3, FullAlphaAdapterErrorV3,
    MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3,
};
use sha2::{Digest, Sha256};

/// The exact parameters the guest must pass to SP1 recursive verification.
/// Constructing this request does not establish that a receipt exists or verifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptVerificationRequest {
    pub program_words: [u32; 8],
    pub public_values_sha256: [u8; 32],
}

pub fn announced_input_length_is_valid(announced: usize) -> bool {
    announced != 0 && announced <= MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3
}

/// Same stream-alignment marker as the existing Bitcoin/Elements adapter
/// guests. Its historical tag is shared deliberately; this public hash is not
/// an authentication mechanism and does not replace SP1 verification.
pub fn deferred_receipt_marker(program_id: [u8; 32], public_values: &[u8]) -> [u8; 32] {
    let tag = Sha256::digest(b"ECX/truthcoin-sp1-deferred-proof/v1");
    let digest = Sha256::digest(public_values);
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update(tag);
    hash.update(program_id);
    hash.update(digest);
    hash.finalize().into()
}

pub fn receipt_verification_request(
    program_id: [u8; 32],
    public_values: &[u8],
    proof_marker: &[u8],
) -> Result<ReceiptVerificationRequest, FullAlphaAdapterErrorV3> {
    if !alpha_sp1_program_id_is_canonical_v3(program_id)
        || proof_marker != deferred_receipt_marker(program_id, public_values)
    {
        return Err(FullAlphaAdapterErrorV3::Receipt);
    }
    let mut program_words = [0u32; 8];
    for (word, encoded) in program_words.iter_mut().zip(program_id.chunks_exact(4)) {
        *word = u32::from_be_bytes(
            encoded
                .try_into()
                .map_err(|_| FullAlphaAdapterErrorV3::Receipt)?,
        );
    }
    Ok(ReceiptVerificationRequest {
        program_words,
        public_values_sha256: Sha256::digest(public_values).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_id() -> [u8; 32] {
        let mut id = [0; 32];
        for (i, word) in id.chunks_exact_mut(4).enumerate() {
            word.copy_from_slice(&(i as u32 + 1).to_be_bytes());
        }
        id
    }

    #[test]
    fn input_length_is_bounded_before_allocation() {
        assert!(!announced_input_length_is_valid(0));
        assert!(announced_input_length_is_valid(1));
        assert!(announced_input_length_is_valid(
            MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3
        ));
        assert!(!announced_input_length_is_valid(
            MAX_FULL_ALPHA_ADAPTER_INPUT_BYTES_V3 + 1
        ));
        assert!(!announced_input_length_is_valid(usize::MAX));
    }

    #[test]
    fn known_marker_and_digest_match_existing_adapter_convention() {
        // Independently calculated SHA-256 tagged-hash vector; these are test
        // words, never frozen or proposed production program identities.
        let marker = [
            0x69, 0xb5, 0xc6, 0xa5, 0x44, 0x6e, 0x15, 0xb1, 0x53, 0x15, 0x72, 0x3c, 0x06, 0x1f,
            0x7e, 0x53, 0xc9, 0xbc, 0xbb, 0x7c, 0xa7, 0x52, 0xee, 0x59, 0x97, 0x57, 0x53, 0x1e,
            0x6a, 0x16, 0x2d, 0x4f,
        ];
        assert_eq!(deferred_receipt_marker(program_id(), b"abc"), marker);
        let request = receipt_verification_request(program_id(), b"abc", &marker).unwrap();
        assert_eq!(request.program_words, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            request.public_values_sha256,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn zero_and_every_noncanonical_program_word_are_rejected() {
        let zero = [0; 32];
        assert_eq!(
            receipt_verification_request(zero, b"abc", &deferred_receipt_marker(zero, b"abc")),
            Err(FullAlphaAdapterErrorV3::Receipt),
        );
        for i in 0..8 {
            for invalid in [0x7f00_0001u32, u32::MAX] {
                let mut id = program_id();
                id[4 * i..4 * i + 4].copy_from_slice(&invalid.to_be_bytes());
                assert_eq!(
                    receipt_verification_request(id, b"abc", &deferred_receipt_marker(id, b"abc")),
                    Err(FullAlphaAdapterErrorV3::Receipt),
                );
            }
        }
    }

    #[test]
    fn canonical_field_boundary_and_zero_individual_words_are_permitted() {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&0x7f00_0000u32.to_be_bytes());
        let request =
            receipt_verification_request(id, b"abc", &deferred_receipt_marker(id, b"abc")).unwrap();
        assert_eq!(request.program_words, [0x7f00_0000, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn program_public_values_and_marker_substitutions_are_rejected() {
        let id = program_id();
        let marker = deferred_receipt_marker(id, b"abc");
        for i in 0..32 {
            let mut changed_id = id;
            changed_id[i] ^= 1;
            assert_eq!(
                receipt_verification_request(changed_id, b"abc", &marker),
                Err(FullAlphaAdapterErrorV3::Receipt)
            );
            let mut changed_marker = marker;
            changed_marker[i] ^= 1;
            assert_eq!(
                receipt_verification_request(id, b"abc", &changed_marker),
                Err(FullAlphaAdapterErrorV3::Receipt)
            );
        }
        for bytes in [b"".as_slice(), b"abd", b"abc\0", b"ab"] {
            assert_eq!(
                receipt_verification_request(id, bytes, &marker),
                Err(FullAlphaAdapterErrorV3::Receipt)
            );
        }
        for bytes in [
            marker[..31].to_vec(),
            [marker.as_slice(), &[0]].concat(),
            vec![],
        ] {
            assert_eq!(
                receipt_verification_request(id, b"abc", &bytes),
                Err(FullAlphaAdapterErrorV3::Receipt)
            );
        }
    }
}
