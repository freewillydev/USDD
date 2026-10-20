//! Consensus transport and fail-closed dispatch for the ECX SP1 proof.
//!
//! Production accepts only SP1 6.3.1's Groth16 zero-knowledge wrapper. The
//! transparent compressed proof is available only behind an explicit debug
//! feature and must never be enabled in a confidential-positions deployment.

#![forbid(unsafe_code)]

use core::fmt;

mod incremental_activation_public_values;
mod incremental_successor_public_values;
mod public_values;
#[cfg(feature = "debug-compressed-backend")]
mod sp1_compressed_debug_backend;
#[cfg(feature = "sp1-groth16-backend")]
mod sp1_groth16_backend;

pub use incremental_activation_public_values::{
    IncrementalActivationPublicValuesError, IncrementalActivationPublicValuesV2,
    INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2, INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2,
};
pub use incremental_successor_public_values::{
    IncrementalSuccessorPublicValuesError, IncrementalSuccessorPublicValuesV2,
    INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2, INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2,
};
pub use public_values::{
    PublicValuesError, PublicValuesV3, PublicValuesV4, PublicValuesV5, BOND_FIXED_SUPPLY_ATOMS_V2,
    BOND_SHARE_SCALE_V2, BOND_TARGET_COVERAGE_BPS_V2, MAX_ABS_FUNDING_RATE_PPM_V2,
    PUBLIC_VALUES_V3_LEN, PUBLIC_VALUES_V3_VERSION, PUBLIC_VALUES_V4_LEN, PUBLIC_VALUES_V4_VERSION,
    PUBLIC_VALUES_V5_LEN, PUBLIC_VALUES_V5_VERSION,
};
#[cfg(feature = "debug-compressed-backend")]
pub use sp1_compressed_debug_backend::{
    Sp1CompressedDebugV6_3_1Backend, Sp1CompressedDebugV6_3_1VerificationError,
};
#[cfg(feature = "sp1-groth16-backend")]
pub use sp1_groth16_backend::{
    groth16_wrapper_vkey_sha256, program_id_words_to_bn254, recursion_vkey_root_bn254,
    sha256_to_bn254, Sp1Groth16V6_3_1Backend, Sp1Groth16V6_3_1VerificationError,
};

pub const ANNEX_MAGIC: [u8; 8] = [0x50, b'E', b'C', b'X', b'S', b'P', b'1', 0];
pub const ANNEX_VERSION: u8 = 2;
/// Additive V2 witness transport. Version two above remains the exact V1
/// proof-only annex; version three appends the canonical 609-byte V4 public
/// values after the fixed Groth16 proof.
pub const ANNEX_V2_VERSION: u8 = 3;
/// Live bond-V2 transport. Version three remains historical regression only.
pub const ANNEX_PUBLIC_VALUES_V5_VERSION: u8 = 4;
/// One-shot pristine V18 -> incremental successor activation transport. This
/// version is intentionally not accepted by the normal PublicValuesV5 parser.
pub const ANNEX_INCREMENTAL_ACTIVATION_V2_VERSION: u8 = 5;
/// Incremental successor transport. It is disjoint from both finite V18 and
/// one-shot activation and must be pinned to the successor guest program ID.
pub const ANNEX_INCREMENTAL_SUCCESSOR_V2_VERSION: u8 = 6;
pub const PROOF_MODE_COMPRESSED_DEBUG: u8 = 1;
pub const PROOF_MODE_GROTH16: u8 = 2;
pub const PUBLIC_VALUES_HASH_SHA256: u8 = 1;
pub const ANNEX_HEADER_LEN: usize = 80;
pub const GROTH16_PROOF_LEN: usize = 4 + 32 + 32 + 32 + 256;
pub const GROTH16_V2_PUBLIC_VALUES_OFFSET: usize = ANNEX_HEADER_LEN + GROTH16_PROOF_LEN;
pub const GROTH16_V2_ANNEX_LEN: usize = GROTH16_V2_PUBLIC_VALUES_OFFSET + PUBLIC_VALUES_V4_LEN;
pub const GROTH16_PUBLIC_VALUES_V5_OFFSET: usize = ANNEX_HEADER_LEN + GROTH16_PROOF_LEN;
pub const GROTH16_PUBLIC_VALUES_V5_ANNEX_LEN: usize =
    GROTH16_PUBLIC_VALUES_V5_OFFSET + PUBLIC_VALUES_V5_LEN;
pub const GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET: usize =
    ANNEX_HEADER_LEN + GROTH16_PROOF_LEN;
pub const GROTH16_INCREMENTAL_ACTIVATION_ANNEX_LEN: usize =
    GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET
        + INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2;
pub const GROTH16_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_OFFSET: usize =
    ANNEX_HEADER_LEN + GROTH16_PROOF_LEN;
pub const GROTH16_INCREMENTAL_SUCCESSOR_ANNEX_LEN: usize =
    GROTH16_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_OFFSET + INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2;
pub const DEFAULT_MAX_DEBUG_COMPRESSED_PROOF_BYTES: usize = 8 * 1024 * 1024;
pub const KOALA_BEAR_MODULUS: u32 = 0x7f00_0001;

type ParsedAnnexParts<'a> = (ProgramId, [u8; 32], &'a [u8], &'a [u8]);

/// The SP1 vkey digest as eight canonical KoalaBear words serialized in
/// big-endian order. This is `HashableKey::hash_bytes()`. The Groth16 backend
/// deterministically converts these words to SP1's BN254 `bytes32()` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramId([u8; 32]);

impl ProgramId {
    pub fn from_words(words: [u32; 8]) -> Result<Self, ProgramIdError> {
        if words.iter().any(|word| *word >= KOALA_BEAR_MODULUS) {
            return Err(ProgramIdError::NonCanonicalFieldWord);
        }
        if words == [0; 8] {
            return Err(ProgramIdError::Zero);
        }
        let mut bytes = [0_u8; 32];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProgramIdError> {
        let mut words = [0_u32; 8];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four-byte chunk"));
        }
        Self::from_words(words)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn words(self) -> [u32; 8] {
        let mut words = [0_u32; 8];
        for (word, bytes) in words.iter_mut().zip(self.0.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four-byte chunk"));
        }
        words
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramIdError {
    Zero,
    NonCanonicalFieldWord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Groth16ProofAnnex<'a> {
    pub program_id: ProgramId,
    /// The full, unmasked SHA-256 of the exact guest public values.
    pub public_values_sha256: [u8; 32],
    /// Exact SP1 SDK proof bytes: 4-byte wrapper-vkey prefix, three 32-byte
    /// metadata fields, then the 256-byte raw Groth16 proof.
    pub proof: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Groth16ProofAnnexV2<'a> {
    pub program_id: ProgramId,
    /// SHA-256 committed in the existing header and verified against the exact
    /// trailing public-value bytes before any cryptographic dispatch.
    pub public_values_sha256: [u8; 32],
    pub proof: &'a [u8],
    pub public_values_bytes: &'a [u8],
    pub public_values: PublicValuesV4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Groth16ProofAnnexV5<'a> {
    pub program_id: ProgramId,
    pub public_values_sha256: [u8; 32],
    pub proof: &'a [u8],
    pub public_values_bytes: &'a [u8],
    pub public_values: PublicValuesV5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Groth16IncrementalActivationAnnexV2<'a> {
    pub program_id: ProgramId,
    pub public_values_sha256: [u8; 32],
    pub proof: &'a [u8],
    pub public_values_bytes: &'a [u8],
    pub public_values: IncrementalActivationPublicValuesV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Groth16IncrementalSuccessorAnnexV2<'a> {
    pub program_id: ProgramId,
    pub public_values_sha256: [u8; 32],
    pub proof: &'a [u8],
    pub public_values_bytes: &'a [u8],
    pub public_values: IncrementalSuccessorPublicValuesV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnexError {
    TooShort,
    WrongMagic,
    UnsupportedVersion,
    UnsupportedProofMode,
    UnsupportedPublicValuesHash,
    NonZeroReservedByte,
    InvalidProgramId(ProgramIdError),
    EmptyProof,
    ProofTooLarge,
    WrongGroth16ProofLength,
    LengthMismatch,
    InvalidPublicValues(PublicValuesError),
    InvalidIncrementalActivationPublicValues(IncrementalActivationPublicValuesError),
    InvalidIncrementalSuccessorPublicValues(IncrementalSuccessorPublicValuesError),
    PublicValuesHashMismatch,
}

impl fmt::Display for AnnexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid ECX SP1 annex: {self:?}")
    }
}

impl std::error::Error for AnnexError {}

/// Parse a production Taproot annex. All integers are unsigned big-endian and
/// trailing bytes fail. Production accepts only the fixed-size Groth16 codec.
pub fn parse_groth16_annex(annex: &[u8]) -> Result<Groth16ProofAnnex<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof) = parse_annex_header(annex, PROOF_MODE_GROTH16)?;
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    Ok(Groth16ProofAnnex {
        program_id,
        public_values_sha256,
        proof,
    })
}

pub fn encode_groth16_annex(
    program_id: ProgramId,
    public_values_sha256: [u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    encode_annex_inner(PROOF_MODE_GROTH16, program_id, public_values_sha256, proof)
}

/// Parse the additive V2 witness annex:
///
/// `80-byte version-3 header || 356-byte Groth16 proof || 609-byte PublicValuesV4`.
///
/// V1 parsing is unchanged and rejects this version. V2 parsing rejects V1,
/// duplicate public values, and every trailing or truncated byte.
pub fn parse_groth16_v2_annex(annex: &[u8]) -> Result<Groth16ProofAnnexV2<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof, public_values_bytes) =
        parse_annex_header_with_suffix(
            annex,
            ANNEX_V2_VERSION,
            PROOF_MODE_GROTH16,
            PUBLIC_VALUES_V4_LEN,
        )?;
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values =
        PublicValuesV4::decode(public_values_bytes).map_err(AnnexError::InvalidPublicValues)?;
    let canonical = public_values.encode();
    if !constant_time_equal(&canonical, public_values_bytes) {
        return Err(AnnexError::InvalidPublicValues(
            PublicValuesError::WrongLength,
        ));
    }
    if !constant_time_equal(&public_values.sha256(), &public_values_sha256) {
        return Err(AnnexError::PublicValuesHashMismatch);
    }
    Ok(Groth16ProofAnnexV2 {
        program_id,
        public_values_sha256,
        proof,
        public_values_bytes,
        public_values,
    })
}

pub fn encode_groth16_v2_annex(
    program_id: ProgramId,
    proof: &[u8],
    public_values: &PublicValuesV4,
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values_bytes = public_values.encode();
    // Reuse the decoder as the one canonical semantic gate for the public
    // capital projection; callers cannot encode an unknown mode or bad range.
    PublicValuesV4::decode(&public_values_bytes).map_err(AnnexError::InvalidPublicValues)?;
    encode_annex_inner_with_suffix(
        ANNEX_V2_VERSION,
        PROOF_MODE_GROTH16,
        program_id,
        public_values.sha256(),
        proof,
        &public_values_bytes,
    )
}

/// Parse the only live bond-V2 proof transport:
/// `80-byte wire header || 356-byte proof || 850-byte PublicValuesV5`.
/// The header includes BIP341's leading 0x50 annex marker, so the stripped
/// Simplicity payload is exactly 1,285 bytes and the wire annex is 1,286.
pub fn parse_groth16_public_values_v5_annex(
    annex: &[u8],
) -> Result<Groth16ProofAnnexV5<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof, public_values_bytes) =
        parse_annex_header_with_suffix(
            annex,
            ANNEX_PUBLIC_VALUES_V5_VERSION,
            PROOF_MODE_GROTH16,
            PUBLIC_VALUES_V5_LEN,
        )?;
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values =
        PublicValuesV5::decode(public_values_bytes).map_err(AnnexError::InvalidPublicValues)?;
    if !constant_time_equal(&public_values.encode(), public_values_bytes) {
        return Err(AnnexError::InvalidPublicValues(
            PublicValuesError::WrongLength,
        ));
    }
    if !constant_time_equal(&public_values.sha256(), &public_values_sha256) {
        return Err(AnnexError::PublicValuesHashMismatch);
    }
    Ok(Groth16ProofAnnexV5 {
        program_id,
        public_values_sha256,
        proof,
        public_values_bytes,
        public_values,
    })
}

pub fn encode_groth16_public_values_v5_annex(
    program_id: ProgramId,
    proof: &[u8],
    public_values: &PublicValuesV5,
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values_bytes = public_values.encode();
    PublicValuesV5::decode(&public_values_bytes).map_err(AnnexError::InvalidPublicValues)?;
    encode_annex_inner_with_suffix(
        ANNEX_PUBLIC_VALUES_V5_VERSION,
        PROOF_MODE_GROTH16,
        program_id,
        public_values.sha256(),
        proof,
        &public_values_bytes,
    )
}

/// Parse the one-shot incremental activation transport:
/// `80-byte wire header || 356-byte proof || 364-byte activation public values`.
/// The wire annex is exactly 800 bytes (799 after stripping BIP341's 0x50).
pub fn parse_groth16_incremental_activation_v2_annex(
    annex: &[u8],
) -> Result<Groth16IncrementalActivationAnnexV2<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof, public_values_bytes) =
        parse_annex_header_with_suffix(
            annex,
            ANNEX_INCREMENTAL_ACTIVATION_V2_VERSION,
            PROOF_MODE_GROTH16,
            INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2,
        )?;
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values = IncrementalActivationPublicValuesV2::decode(public_values_bytes)
        .map_err(AnnexError::InvalidIncrementalActivationPublicValues)?;
    if !constant_time_equal(&public_values.encode(), public_values_bytes) {
        return Err(AnnexError::InvalidIncrementalActivationPublicValues(
            IncrementalActivationPublicValuesError::WrongLength,
        ));
    }
    if !constant_time_equal(&public_values.sha256(), &public_values_sha256) {
        return Err(AnnexError::PublicValuesHashMismatch);
    }
    Ok(Groth16IncrementalActivationAnnexV2 {
        program_id,
        public_values_sha256,
        proof,
        public_values_bytes,
        public_values,
    })
}

pub fn encode_groth16_incremental_activation_v2_annex(
    program_id: ProgramId,
    proof: &[u8],
    public_values: &IncrementalActivationPublicValuesV2,
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values_bytes = public_values.encode();
    IncrementalActivationPublicValuesV2::decode(&public_values_bytes)
        .map_err(AnnexError::InvalidIncrementalActivationPublicValues)?;
    encode_annex_inner_with_suffix(
        ANNEX_INCREMENTAL_ACTIVATION_V2_VERSION,
        PROOF_MODE_GROTH16,
        program_id,
        public_values.sha256(),
        proof,
        &public_values_bytes,
    )
}

/// Parse the incremental successor transport:
/// `80-byte wire header || 356-byte proof || 1627-byte successor public values`.
/// The wire annex is exactly 2,031 bytes (2,030 after stripping BIP341's 0x50).
pub fn parse_groth16_incremental_successor_v2_annex(
    annex: &[u8],
) -> Result<Groth16IncrementalSuccessorAnnexV2<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof, public_values_bytes) =
        parse_annex_header_with_suffix(
            annex,
            ANNEX_INCREMENTAL_SUCCESSOR_V2_VERSION,
            PROOF_MODE_GROTH16,
            INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2,
        )?;
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values = IncrementalSuccessorPublicValuesV2::decode(public_values_bytes)
        .map_err(AnnexError::InvalidIncrementalSuccessorPublicValues)?;
    if !constant_time_equal(&public_values.encode(), public_values_bytes) {
        return Err(AnnexError::InvalidIncrementalSuccessorPublicValues(
            IncrementalSuccessorPublicValuesError::WrongLength,
        ));
    }
    if !constant_time_equal(&public_values.sha256(), &public_values_sha256) {
        return Err(AnnexError::PublicValuesHashMismatch);
    }
    Ok(Groth16IncrementalSuccessorAnnexV2 {
        program_id,
        public_values_sha256,
        proof,
        public_values_bytes,
        public_values,
    })
}

pub fn encode_groth16_incremental_successor_v2_annex(
    program_id: ProgramId,
    proof: &[u8],
    public_values: &IncrementalSuccessorPublicValuesV2,
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() != GROTH16_PROOF_LEN {
        return Err(AnnexError::WrongGroth16ProofLength);
    }
    let public_values_bytes = public_values.encode();
    IncrementalSuccessorPublicValuesV2::decode(&public_values_bytes)
        .map_err(AnnexError::InvalidIncrementalSuccessorPublicValues)?;
    encode_annex_inner_with_suffix(
        ANNEX_INCREMENTAL_SUCCESSOR_V2_VERSION,
        PROOF_MODE_GROTH16,
        program_id,
        public_values.sha256(),
        proof,
        &public_values_bytes,
    )
}

/// Consensus backend boundary. Implementations must verify exactly an SP1
/// 6.3.1 Groth16 proof against the frozen wrapper vkey and recursion vkey root,
/// require successful exit, bind the program ID, and use only SHA-256 for the
/// committed public values. The SP1 convenience verifier that accepts SHA-256
/// *or BLAKE3* is unsuitable.
pub trait Groth16Sp1Backend {
    type Error;

    fn verify_groth16_sha256(
        &self,
        proof: &[u8],
        program_id_words: [u32; 8],
        public_values_sha256: [u8; 32],
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum VerifyError<E> {
    Annex(AnnexError),
    WrongProgramId,
    WrongPublicValuesHash,
    Backend(E),
}

/// Parse, bind, and dispatch a production proof. Binding is checked before the
/// pairing operation, and comparisons do not early-exit on a different byte.
pub fn verify_groth16_annex<B: Groth16Sp1Backend>(
    backend: &B,
    annex_bytes: &[u8],
    expected_program_id: ProgramId,
    expected_public_values_sha256: [u8; 32],
) -> Result<(), VerifyError<B::Error>> {
    let annex = parse_groth16_annex(annex_bytes).map_err(VerifyError::Annex)?;
    if !constant_time_equal(annex.program_id.as_bytes(), expected_program_id.as_bytes()) {
        return Err(VerifyError::WrongProgramId);
    }
    if !constant_time_equal(&annex.public_values_sha256, &expected_public_values_sha256) {
        return Err(VerifyError::WrongPublicValuesHash);
    }
    backend
        .verify_groth16_sha256(
            annex.proof,
            annex.program_id.words(),
            annex.public_values_sha256,
        )
        .map_err(VerifyError::Backend)
}

pub fn verify_groth16_v2_annex<B: Groth16Sp1Backend>(
    backend: &B,
    annex_bytes: &[u8],
    expected_program_id: ProgramId,
    expected_public_values_sha256: [u8; 32],
) -> Result<(), VerifyError<B::Error>> {
    let annex = parse_groth16_v2_annex(annex_bytes).map_err(VerifyError::Annex)?;
    if !constant_time_equal(annex.program_id.as_bytes(), expected_program_id.as_bytes()) {
        return Err(VerifyError::WrongProgramId);
    }
    if !constant_time_equal(&annex.public_values_sha256, &expected_public_values_sha256) {
        return Err(VerifyError::WrongPublicValuesHash);
    }
    backend
        .verify_groth16_sha256(
            annex.proof,
            annex.program_id.words(),
            annex.public_values_sha256,
        )
        .map_err(VerifyError::Backend)
}

pub fn verify_groth16_public_values_v5_annex<B: Groth16Sp1Backend>(
    backend: &B,
    annex_bytes: &[u8],
    expected_program_id: ProgramId,
    expected_public_values_sha256: [u8; 32],
) -> Result<(), VerifyError<B::Error>> {
    let annex = parse_groth16_public_values_v5_annex(annex_bytes).map_err(VerifyError::Annex)?;
    if !constant_time_equal(annex.program_id.as_bytes(), expected_program_id.as_bytes()) {
        return Err(VerifyError::WrongProgramId);
    }
    if !constant_time_equal(&annex.public_values_sha256, &expected_public_values_sha256) {
        return Err(VerifyError::WrongPublicValuesHash);
    }
    backend
        .verify_groth16_sha256(
            annex.proof,
            annex.program_id.words(),
            annex.public_values_sha256,
        )
        .map_err(VerifyError::Backend)
}

pub fn verify_groth16_incremental_activation_v2_annex<B: Groth16Sp1Backend>(
    backend: &B,
    annex_bytes: &[u8],
    expected_program_id: ProgramId,
    expected_public_values_sha256: [u8; 32],
) -> Result<(), VerifyError<B::Error>> {
    let annex =
        parse_groth16_incremental_activation_v2_annex(annex_bytes).map_err(VerifyError::Annex)?;
    if !constant_time_equal(annex.program_id.as_bytes(), expected_program_id.as_bytes()) {
        return Err(VerifyError::WrongProgramId);
    }
    if !constant_time_equal(&annex.public_values_sha256, &expected_public_values_sha256) {
        return Err(VerifyError::WrongPublicValuesHash);
    }
    backend
        .verify_groth16_sha256(
            annex.proof,
            annex.program_id.words(),
            annex.public_values_sha256,
        )
        .map_err(VerifyError::Backend)
}

pub fn verify_groth16_incremental_successor_v2_annex<B: Groth16Sp1Backend>(
    backend: &B,
    annex_bytes: &[u8],
    expected_program_id: ProgramId,
    expected_public_values_sha256: [u8; 32],
) -> Result<(), VerifyError<B::Error>> {
    let annex =
        parse_groth16_incremental_successor_v2_annex(annex_bytes).map_err(VerifyError::Annex)?;
    if !constant_time_equal(annex.program_id.as_bytes(), expected_program_id.as_bytes()) {
        return Err(VerifyError::WrongProgramId);
    }
    if !constant_time_equal(&annex.public_values_sha256, &expected_public_values_sha256) {
        return Err(VerifyError::WrongPublicValuesHash);
    }
    backend
        .verify_groth16_sha256(
            annex.proof,
            annex.program_id.words(),
            annex.public_values_sha256,
        )
        .map_err(VerifyError::Backend)
}

/// Integrity-only debug codec for SP1's transparent compressed proof. This is
/// deliberately unavailable unless `debug-compressed-backend` is enabled.
#[cfg(feature = "debug-compressed-backend")]
pub fn parse_debug_compressed_annex(
    annex: &[u8],
    maximum_proof_bytes: usize,
) -> Result<Groth16ProofAnnex<'_>, AnnexError> {
    let (program_id, public_values_sha256, proof) =
        parse_annex_header(annex, PROOF_MODE_COMPRESSED_DEBUG)?;
    if proof.len() > maximum_proof_bytes {
        return Err(AnnexError::ProofTooLarge);
    }
    Ok(Groth16ProofAnnex {
        program_id,
        public_values_sha256,
        proof,
    })
}

#[cfg(feature = "debug-compressed-backend")]
pub fn encode_debug_compressed_annex(
    program_id: ProgramId,
    public_values_sha256: [u8; 32],
    proof: &[u8],
    maximum_proof_bytes: usize,
) -> Result<Vec<u8>, AnnexError> {
    if proof.len() > maximum_proof_bytes {
        return Err(AnnexError::ProofTooLarge);
    }
    encode_annex_inner(
        PROOF_MODE_COMPRESSED_DEBUG,
        program_id,
        public_values_sha256,
        proof,
    )
}

#[cfg(feature = "debug-compressed-backend")]
pub trait DebugCompressedSp1Backend {
    type Error;

    fn verify_debug_compressed_sha256(
        &self,
        proof: &[u8],
        program_id_words: [u32; 8],
        public_values_sha256: [u8; 32],
    ) -> Result<(), Self::Error>;
}

fn parse_annex_header(
    annex: &[u8],
    expected_proof_mode: u8,
) -> Result<(ProgramId, [u8; 32], &[u8]), AnnexError> {
    let (program_id, public_values_sha256, proof, suffix) =
        parse_annex_header_with_suffix(annex, ANNEX_VERSION, expected_proof_mode, 0)?;
    debug_assert!(suffix.is_empty());
    Ok((program_id, public_values_sha256, proof))
}

fn parse_annex_header_with_suffix(
    annex: &[u8],
    expected_version: u8,
    expected_proof_mode: u8,
    suffix_len: usize,
) -> Result<ParsedAnnexParts<'_>, AnnexError> {
    if annex.len() < ANNEX_HEADER_LEN {
        return Err(AnnexError::TooShort);
    }
    if annex[..8] != ANNEX_MAGIC {
        return Err(AnnexError::WrongMagic);
    }
    if annex[8] != expected_version {
        return Err(AnnexError::UnsupportedVersion);
    }
    if annex[9] != expected_proof_mode {
        return Err(AnnexError::UnsupportedProofMode);
    }
    if annex[10] != PUBLIC_VALUES_HASH_SHA256 {
        return Err(AnnexError::UnsupportedPublicValuesHash);
    }
    if annex[11] != 0 {
        return Err(AnnexError::NonZeroReservedByte);
    }

    let mut program_id = [0_u8; 32];
    program_id.copy_from_slice(&annex[12..44]);
    let program_id = ProgramId::from_bytes(program_id).map_err(AnnexError::InvalidProgramId)?;

    let mut public_values_sha256 = [0_u8; 32];
    public_values_sha256.copy_from_slice(&annex[44..76]);

    let proof_len = u32::from_be_bytes(
        annex[76..80]
            .try_into()
            .expect("length field has four bytes"),
    ) as usize;
    if proof_len == 0 {
        return Err(AnnexError::EmptyProof);
    }
    let expected_len = ANNEX_HEADER_LEN
        .checked_add(proof_len)
        .and_then(|length| length.checked_add(suffix_len))
        .ok_or(AnnexError::LengthMismatch)?;
    if annex.len() != expected_len {
        return Err(AnnexError::LengthMismatch);
    }
    let proof_end = ANNEX_HEADER_LEN + proof_len;
    Ok((
        program_id,
        public_values_sha256,
        &annex[ANNEX_HEADER_LEN..proof_end],
        &annex[proof_end..],
    ))
}

fn encode_annex_inner(
    proof_mode: u8,
    program_id: ProgramId,
    public_values_sha256: [u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>, AnnexError> {
    encode_annex_inner_with_suffix(
        ANNEX_VERSION,
        proof_mode,
        program_id,
        public_values_sha256,
        proof,
        &[],
    )
}

fn encode_annex_inner_with_suffix(
    version: u8,
    proof_mode: u8,
    program_id: ProgramId,
    public_values_sha256: [u8; 32],
    proof: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, AnnexError> {
    if proof.is_empty() {
        return Err(AnnexError::EmptyProof);
    }
    if proof.len() > u32::MAX as usize {
        return Err(AnnexError::ProofTooLarge);
    }
    let mut annex = Vec::with_capacity(ANNEX_HEADER_LEN + proof.len() + suffix.len());
    annex.extend_from_slice(&ANNEX_MAGIC);
    annex.extend_from_slice(&[version, proof_mode, PUBLIC_VALUES_HASH_SHA256, 0]);
    annex.extend_from_slice(program_id.as_bytes());
    annex.extend_from_slice(&public_values_sha256);
    annex.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    annex.extend_from_slice(proof);
    annex.extend_from_slice(suffix);
    Ok(annex)
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
    use core::cell::Cell;
    use sha2::{Digest, Sha256};

    fn id(seed: u32) -> ProgramId {
        ProgramId::from_words([seed, 2, 3, 4, 5, 6, 7, 8]).unwrap()
    }

    fn proof() -> [u8; GROTH16_PROOF_LEN] {
        [0xa5; GROTH16_PROOF_LEN]
    }

    fn v4_public_values() -> PublicValuesV4 {
        PublicValuesV4 {
            transition_journal_domain_sha256: [1; 32],
            configuration_hash: [2; 32],
            current_state_hash: [3; 32],
            next_state_hash: [4; 32],
            transition_txid_consensus: [5; 32],
            prior_exchange_header_root: [6; 32],
            prior_parent_block_hash: [7; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [10; 32],
            bond_asset_id: [11; 32],
            bond_deployment_commitment: [12; 32],
            bond_state_root: [13; 32],
            redemption_queue_root: [14; 32],
            funding_state_root: [15; 32],
            conversion_legs_commitment: [16; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 23,
            authenticated_max_price: 24,
            funding_epoch: 25,
            funding_rate_ppm: -26,
            redemption_head: 27,
            redemption_tail: 28,
            queued_redemption_share_atoms: 29,
        }
    }

    fn v5_public_values() -> PublicValuesV5 {
        PublicValuesV5 {
            transition_journal_domain_sha256: [1; 32],
            configuration_hash: [2; 32],
            current_state_hash: [3; 32],
            next_state_hash: [4; 32],
            transition_txid_consensus: [5; 32],
            prior_exchange_header_root: [6; 32],
            prior_parent_block_hash: [7; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [10; 32],
            bond_asset_id: [11; 32],
            bond_deployment_commitment: [12; 32],
            bond_state_root: [13; 32],
            redemption_queue_root: [14; 32],
            funding_state_root: [15; 32],
            conversion_legs_commitment: [16; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 23,
            authenticated_max_price: 24,
            funding_epoch: 25,
            funding_rate_ppm: -26,
            redemption_head: 27,
            redemption_tail: 28,
            queued_redemption_share_atoms: 29,
            oracle_certificate_hash: [17; 32],
            oracle_valid_through_mtp: 30,
            oracle_mode: 0,
            next_encrypted_availability_root: [18; 32],
            bond_inbox_head_root: [19; 32],
            bond_inbox_entry_count: 4,
            bond_inbox_processed_root: [20; 32],
            bond_inbox_cursor: 3,
            bond_inbox_outcome_root: [21; 32],
            bond_inbox_outcome_count: 3,
            matcher_execution_receipt_batch_root: [22; 32],
            previous_matcher_execution_sequence: 5,
            next_matcher_execution_sequence: 6,
        }
    }

    fn incremental_activation_public_values() -> IncrementalActivationPublicValuesV2 {
        IncrementalActivationPublicValuesV2 {
            activation_configuration_hash: [1; 32],
            finite_v18_configuration_hash: [2; 32],
            finite_v18_state_root: [3; 32],
            successor_configuration_hash: [4; 32],
            successor_state_root: [5; 32],
            activation_transaction_txid: [6; 32],
            prior_parent_block_hash: [7; 32],
            chain_id: [8; 32],
            bond_state_root: [9; 32],
            funding_state_root: [10; 32],
            activation_sidechain_height: 11,
            activation_parent_mtp: 12,
            mark_price_atoms: 100,
            price_lower_atoms: 90,
            price_upper_atoms: 110,
        }
    }

    fn incremental_successor_public_values() -> IncrementalSuccessorPublicValuesV2 {
        let mut hashes = [[0_u8; 32]; 40];
        for (index, hash) in hashes.iter_mut().enumerate() {
            hash.fill(u8::try_from(index + 1).unwrap());
        }
        IncrementalSuccessorPublicValuesV2 {
            configuration_hash: hashes[0],
            previous_state_root: hashes[1],
            next_state_root: hashes[2],
            transition_txid_consensus: hashes[3],
            prior_exchange_header_root: hashes[4],
            prior_parent_block_hash: hashes[5],
            risk_extrema_root: hashes[6],
            child_availability_root: hashes[7],
            custodian_registry_hash: hashes[8],
            settlement_action_root: hashes[9],
            combined_settlement_root: hashes[10],
            settlement_configuration_hash: hashes[11],
            v18_configuration_hash: hashes[12],
            chain_id: hashes[13],
            bond_asset_id: hashes[14],
            bond_deployment_commitment: hashes[15],
            bond_inventory_covenant_hash: hashes[16],
            bond_state_root: hashes[17],
            funding_state_root: hashes[18],
            redemption_queue_root: hashes[19],
            oracle_certificate_hash: hashes[20],
            matcher_execution_receipt_batch_root: hashes[21],
            next_bond_inbox_head_root: hashes[22],
            next_bond_inbox_processed_root: hashes[23],
            next_bond_inbox_outcome_root: hashes[24],
            previous_inbox_state_hash: hashes[25],
            next_inbox_state_hash: hashes[26],
            recovered_inbox_candidate_root: hashes[27],
            trader_update_transcript_root: hashes[28],
            trader_update_leaf_projection_root: hashes[29],
            trader_economic_mutation_root: hashes[30],
            action_composition_root: hashes[31],
            previous_deposit_inbox_state_hash: hashes[32],
            next_deposit_inbox_state_hash: hashes[33],
            previous_deposit_inbox_head_root: hashes[34],
            next_deposit_inbox_head_root: hashes[35],
            previous_forced_inbox_state_hash: hashes[36],
            next_forced_inbox_state_hash: hashes[37],
            previous_forced_inbox_head_root: hashes[38],
            next_forced_inbox_head_root: hashes[39],
            prior_parent_height: 30,
            prior_parent_mtp: 31,
            sidechain_height: 32,
            mark_price_atoms: 100,
            price_lower_atoms: 90,
            price_upper_atoms: 110,
            issued_share_atoms: 2_100_000_000_000_000,
            outstanding_share_atoms: 100,
            inventory_share_atoms: 2_099_999_999_999_900,
            queued_redemption_share_atoms: 28,
            funding_epoch: 0,
            oracle_valid_through_parent_mtp: 31,
            global_funding_index_numerator: -33,
            lower_deficit_atoms: 8,
            upper_deficit_atoms: 7,
            full_range_deficit_atoms: 8,
            target_reserve_atoms: 10,
            insurance_reserve_atoms: 9,
            controlled_usdd_atoms: 1_000,
            matcher_sequence: 34,
            nav_per_whole_share_usdd_atoms: 9_000_000,
            coverage_bps: 11_250,
            redemption_head: 26,
            redemption_tail: 27,
            bond_inbox_entry_count: 40,
            bond_inbox_processed_cursor: 39,
            bond_inbox_outcome_count: 38,
            funding_rate_ppm: -100,
            capital_mode: 1,
            oracle_mode: 0,
            operationally_safe: true,
        }
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Cell<usize>,
        reject: bool,
    }

    impl Groth16Sp1Backend for RecordingBackend {
        type Error = &'static str;

        fn verify_groth16_sha256(
            &self,
            proof: &[u8],
            program_id_words: [u32; 8],
            public_values_sha256: [u8; 32],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(proof, [0xa5; GROTH16_PROOF_LEN]);
            assert_eq!(program_id_words, [1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(public_values_sha256, [9; 32]);
            if self.reject {
                Err("cryptographic rejection")
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct V2RecordingBackend {
        calls: Cell<usize>,
    }

    impl Groth16Sp1Backend for V2RecordingBackend {
        type Error = &'static str;

        fn verify_groth16_sha256(
            &self,
            proof: &[u8],
            program_id_words: [u32; 8],
            _public_values_sha256: [u8; 32],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(proof, [0xa5; GROTH16_PROOF_LEN]);
            assert_eq!(program_id_words, [1, 2, 3, 4, 5, 6, 7, 8]);
            Ok(())
        }
    }

    #[test]
    fn production_round_trip_and_dispatch() {
        let annex = encode_groth16_annex(id(1), [9; 32], &proof()).unwrap();
        let parsed = parse_groth16_annex(&annex).unwrap();
        assert_eq!(parsed.program_id, id(1));
        assert_eq!(parsed.public_values_sha256, [9; 32]);
        assert_eq!(parsed.proof, proof());

        let backend = RecordingBackend::default();
        verify_groth16_annex(&backend, &annex, id(1), [9; 32]).unwrap();
        assert_eq!(backend.calls.get(), 1);
    }

    #[test]
    fn v2_annex_round_trip_has_one_frozen_layout() {
        let values = v4_public_values();
        let annex = encode_groth16_v2_annex(id(1), &proof(), &values).unwrap();
        assert_eq!(annex.len(), GROTH16_V2_ANNEX_LEN);
        assert_eq!(GROTH16_V2_PUBLIC_VALUES_OFFSET, 436);
        assert_eq!(GROTH16_V2_ANNEX_LEN, 1_045);
        assert_eq!(annex[8], ANNEX_V2_VERSION);
        assert_eq!(
            &annex[ANNEX_HEADER_LEN..GROTH16_V2_PUBLIC_VALUES_OFFSET],
            &proof()
        );
        assert_eq!(&annex[GROTH16_V2_PUBLIC_VALUES_OFFSET..], &values.encode());
        let parsed = parse_groth16_v2_annex(&annex).unwrap();
        assert_eq!(parsed.program_id, id(1));
        assert_eq!(parsed.proof, proof());
        assert_eq!(parsed.public_values, values);
        assert_eq!(parsed.public_values_bytes, values.encode());
        assert_eq!(parsed.public_values_sha256, values.sha256());
        assert_eq!(
            Sha256::digest(&annex).as_slice(),
            &[
                0x22, 0xa4, 0xc9, 0x92, 0x31, 0xec, 0x17, 0xcd, 0xfa, 0x8d, 0x90, 0x55, 0xb1, 0x4d,
                0x46, 0xfd, 0x96, 0x15, 0x17, 0xbf, 0x38, 0x5e, 0xf6, 0x94, 0x5b, 0xa3, 0xb8, 0x54,
                0x68, 0x94, 0xa7, 0x63,
            ]
        );

        let backend = V2RecordingBackend::default();
        verify_groth16_v2_annex(&backend, &annex, id(1), values.sha256()).unwrap();
        assert_eq!(backend.calls.get(), 1);
        assert_eq!(
            parse_groth16_annex(&annex),
            Err(AnnexError::UnsupportedVersion)
        );
        let v1 = encode_groth16_annex(id(1), values.sha256(), &proof()).unwrap();
        assert_eq!(
            parse_groth16_v2_annex(&v1),
            Err(AnnexError::UnsupportedVersion)
        );
    }

    #[test]
    fn v2_annex_rejects_hash_mismatch_malformed_duplicate_and_trailing_values() {
        let values = v4_public_values();
        let valid = encode_groth16_v2_annex(id(1), &proof(), &values).unwrap();
        let backend = V2RecordingBackend::default();

        let mut wrong_hash = valid.clone();
        wrong_hash[44] ^= 1;
        assert_eq!(
            parse_groth16_v2_annex(&wrong_hash),
            Err(AnnexError::PublicValuesHashMismatch)
        );

        let mut malformed_version = valid.clone();
        malformed_version
            [GROTH16_V2_PUBLIC_VALUES_OFFSET + 32..GROTH16_V2_PUBLIC_VALUES_OFFSET + 36]
            .copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(
            parse_groth16_v2_annex(&malformed_version),
            Err(AnnexError::InvalidPublicValues(
                PublicValuesError::UnsupportedVersion
            ))
        );

        let mut malformed_mode = valid.clone();
        malformed_mode[GROTH16_V2_PUBLIC_VALUES_OFFSET + 556] = 3;
        assert_eq!(
            parse_groth16_v2_annex(&malformed_mode),
            Err(AnnexError::InvalidPublicValues(
                PublicValuesError::InvalidCapitalMode
            ))
        );

        for candidate in [
            valid[..valid.len() - 1].to_vec(),
            {
                let mut bytes = valid.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes.extend_from_slice(&values.encode());
                bytes
            },
        ] {
            assert!(matches!(
                verify_groth16_v2_annex(&backend, &candidate, id(1), values.sha256()),
                Err(VerifyError::Annex(AnnexError::LengthMismatch))
            ));
        }
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn incremental_activation_annex_is_exact_domain_separate_and_dispatches() {
        let values = incremental_activation_public_values();
        assert_eq!(
            values.sha256(),
            [
                0x5c, 0xc1, 0x29, 0x5a, 0x47, 0x57, 0x28, 0x2f, 0x49, 0x66, 0x2e, 0x61, 0xcc, 0x2b,
                0x20, 0xee, 0xc3, 0x25, 0x41, 0x8c, 0x17, 0x80, 0x7d, 0xa9, 0xc3, 0x55, 0x48, 0xcb,
                0x9b, 0x49, 0x51, 0xc2,
            ],
            "cross-language incremental activation public-values vector drifted"
        );
        let annex =
            encode_groth16_incremental_activation_v2_annex(id(1), &proof(), &values).unwrap();
        assert_eq!(GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET, 436);
        assert_eq!(GROTH16_INCREMENTAL_ACTIVATION_ANNEX_LEN, 800);
        assert_eq!(annex.len(), 800);
        assert_eq!(annex[0], 0x50);
        assert_eq!(annex[8], ANNEX_INCREMENTAL_ACTIVATION_V2_VERSION);
        assert_eq!(
            &annex[ANNEX_HEADER_LEN..GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET],
            &proof()
        );
        assert_eq!(
            &annex[GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET..],
            &values.encode()
        );
        let parsed = parse_groth16_incremental_activation_v2_annex(&annex).unwrap();
        assert_eq!(parsed.program_id, id(1));
        assert_eq!(parsed.proof, proof());
        assert_eq!(parsed.public_values, values);
        assert_eq!(parsed.public_values_sha256, values.sha256());

        let backend = V2RecordingBackend::default();
        verify_groth16_incremental_activation_v2_annex(&backend, &annex, id(1), values.sha256())
            .unwrap();
        assert_eq!(backend.calls.get(), 1);

        assert_eq!(
            parse_groth16_public_values_v5_annex(&annex),
            Err(AnnexError::UnsupportedVersion)
        );
        let v5 =
            encode_groth16_public_values_v5_annex(id(1), &proof(), &v5_public_values()).unwrap();
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&v5),
            Err(AnnexError::UnsupportedVersion)
        );
    }

    #[test]
    fn incremental_activation_annex_rejects_semantic_hash_and_framing_mutations() {
        let values = incremental_activation_public_values();
        let valid =
            encode_groth16_incremental_activation_v2_annex(id(1), &proof(), &values).unwrap();

        let mut wrong_hash = valid.clone();
        wrong_hash[44] ^= 1;
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&wrong_hash),
            Err(AnnexError::PublicValuesHashMismatch)
        );

        let mut wrong_version = valid.clone();
        wrong_version[GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET
            ..GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET + 4]
            .copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&wrong_version),
            Err(AnnexError::InvalidIncrementalActivationPublicValues(
                IncrementalActivationPublicValuesError::UnsupportedVersion
            ))
        );

        let mut zero_txid = valid.clone();
        let txid_offset = GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET + 4 + (5 * 32);
        zero_txid[txid_offset..txid_offset + 32].fill(0);
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&zero_txid),
            Err(AnnexError::InvalidIncrementalActivationPublicValues(
                IncrementalActivationPublicValuesError::ZeroIdentity
            ))
        );

        let mut bad_range = valid.clone();
        let lower_offset = GROTH16_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_OFFSET + 348;
        bad_range[lower_offset..lower_offset + 8].copy_from_slice(&111u64.to_be_bytes());
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&bad_range),
            Err(AnnexError::InvalidIncrementalActivationPublicValues(
                IncrementalActivationPublicValuesError::InvalidPriceRange
            ))
        );

        for candidate in [valid[..valid.len() - 1].to_vec(), {
            let mut bytes = valid.clone();
            bytes.push(0);
            bytes
        }] {
            assert_eq!(
                parse_groth16_incremental_activation_v2_annex(&candidate),
                Err(AnnexError::LengthMismatch)
            );
        }
    }

    #[test]
    fn incremental_successor_annex_is_exact_disjoint_and_dispatches() {
        let values = incremental_successor_public_values();
        assert_eq!(
            values.sha256(),
            [
                0x97, 0xaf, 0x54, 0xa6, 0x58, 0x4a, 0x64, 0x53, 0xf6, 0x97, 0xb1, 0x09, 0x9e, 0xcf,
                0x42, 0xeb, 0x68, 0xeb, 0xc3, 0xb7, 0x22, 0x8e, 0x0a, 0x90, 0x8a, 0x34, 0x5f, 0x13,
                0x28, 0xa9, 0xb7, 0x06,
            ]
        );
        let annex =
            encode_groth16_incremental_successor_v2_annex(id(1), &proof(), &values).unwrap();
        assert_eq!(INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2, 1_627);
        assert_eq!(GROTH16_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_OFFSET, 436);
        assert_eq!(GROTH16_INCREMENTAL_SUCCESSOR_ANNEX_LEN, 2_063);
        assert_eq!(annex.len(), GROTH16_INCREMENTAL_SUCCESSOR_ANNEX_LEN);
        assert_eq!(annex[8], ANNEX_INCREMENTAL_SUCCESSOR_V2_VERSION);
        assert_eq!(
            &annex[GROTH16_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_OFFSET..],
            &values.encode()
        );
        let parsed = parse_groth16_incremental_successor_v2_annex(&annex).unwrap();
        assert_eq!(parsed.program_id, id(1));
        assert_eq!(parsed.public_values, values);
        assert_eq!(parsed.public_values_sha256, values.sha256());

        let backend = V2RecordingBackend::default();
        verify_groth16_incremental_successor_v2_annex(&backend, &annex, id(1), values.sha256())
            .unwrap();
        assert_eq!(backend.calls.get(), 1);
        assert_eq!(
            parse_groth16_incremental_activation_v2_annex(&annex),
            Err(AnnexError::UnsupportedVersion)
        );
        assert_eq!(
            parse_groth16_public_values_v5_annex(&annex),
            Err(AnnexError::UnsupportedVersion)
        );
    }

    #[test]
    fn incremental_successor_annex_rejects_semantic_hash_and_framing_mutations() {
        let values = incremental_successor_public_values();
        let valid =
            encode_groth16_incremental_successor_v2_annex(id(1), &proof(), &values).unwrap();
        let offset = GROTH16_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_OFFSET;

        let mut wrong_hash = valid.clone();
        wrong_hash[44] ^= 1;
        assert_eq!(
            parse_groth16_incremental_successor_v2_annex(&wrong_hash),
            Err(AnnexError::PublicValuesHashMismatch)
        );

        let mut wrong_version = valid.clone();
        wrong_version[offset..offset + 4].copy_from_slice(&22u32.to_be_bytes());
        assert_eq!(
            parse_groth16_incremental_successor_v2_annex(&wrong_version),
            Err(AnnexError::InvalidIncrementalSuccessorPublicValues(
                IncrementalSuccessorPublicValuesError::UnsupportedVersion
            ))
        );

        let mut wrong_deficit = valid.clone();
        let wide_offset = offset + 4 + (40 * 32) + (12 * 8) + 16;
        wrong_deficit[wide_offset + 32..wide_offset + 48].copy_from_slice(&9u128.to_be_bytes());
        assert_eq!(
            parse_groth16_incremental_successor_v2_annex(&wrong_deficit),
            Err(AnnexError::InvalidIncrementalSuccessorPublicValues(
                IncrementalSuccessorPublicValuesError::InvalidDeficit
            ))
        );

        let mut noncanonical_bool = valid.clone();
        *noncanonical_bool.last_mut().unwrap() = 2;
        assert_eq!(
            parse_groth16_incremental_successor_v2_annex(&noncanonical_bool),
            Err(AnnexError::InvalidIncrementalSuccessorPublicValues(
                IncrementalSuccessorPublicValuesError::NonCanonicalBoolean
            ))
        );

        for candidate in [valid[..valid.len() - 1].to_vec(), {
            let mut bytes = valid.clone();
            bytes.push(0);
            bytes
        }] {
            assert_eq!(
                parse_groth16_incremental_successor_v2_annex(&candidate),
                Err(AnnexError::LengthMismatch)
            );
        }
    }

    #[test]
    fn sp1_groth16_v4_public_values_v5_annex_is_exact_and_v3_is_historical() {
        let values = v5_public_values();
        let annex = encode_groth16_public_values_v5_annex(id(1), &proof(), &values).unwrap();
        assert_eq!(GROTH16_PUBLIC_VALUES_V5_OFFSET, 436);
        assert_eq!(GROTH16_PUBLIC_VALUES_V5_ANNEX_LEN, 1_286);
        assert_eq!(annex.len(), GROTH16_PUBLIC_VALUES_V5_ANNEX_LEN);
        assert_eq!(annex[0], 0x50);
        assert_eq!(annex[8], ANNEX_PUBLIC_VALUES_V5_VERSION);
        assert_eq!(
            &annex[ANNEX_HEADER_LEN..GROTH16_PUBLIC_VALUES_V5_OFFSET],
            &proof()
        );
        assert_eq!(&annex[GROTH16_PUBLIC_VALUES_V5_OFFSET..], &values.encode());
        let parsed = parse_groth16_public_values_v5_annex(&annex).unwrap();
        assert_eq!(parsed.program_id, id(1));
        assert_eq!(parsed.proof, proof());
        assert_eq!(parsed.public_values, values);
        assert_eq!(parsed.public_values_bytes, values.encode());
        assert_eq!(parsed.public_values_sha256, values.sha256());

        let artifact = include_str!("../../artifacts/annex-v4-public-values-v5-test-vector.json");
        let json_string = |name: &str| {
            let marker = format!("\"{name}\": \"");
            let start = artifact.find(&marker).expect("vector field") + marker.len();
            let end = artifact[start..]
                .find('"')
                .expect("vector string terminator")
                + start;
            &artifact[start..end]
        };
        let hex = |bytes: &[u8]| {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut output = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                output.push(DIGITS[(byte >> 4) as usize] as char);
                output.push(DIGITS[(byte & 0x0f) as usize] as char);
            }
            output
        };
        let chunks_marker = "\"public_values_v5_hex_chunks\": [";
        let chunks_start =
            artifact.find(chunks_marker).expect("vector chunks") + chunks_marker.len();
        let chunks_end = artifact[chunks_start..]
            .find(']')
            .expect("vector chunks terminator")
            + chunks_start;
        let artifact_public_values_hex = artifact[chunks_start..chunks_end]
            .lines()
            .map(|line| line.trim().trim_end_matches(',').trim_matches('"'))
            .collect::<String>();
        assert_eq!(artifact_public_values_hex, hex(&values.encode()));
        assert_eq!(
            json_string("public_values_v5_sha256"),
            hex(&Sha256::digest(values.encode()))
        );
        assert_eq!(
            json_string("annex_header_hex"),
            hex(&annex[..ANNEX_HEADER_LEN])
        );
        assert_eq!(
            json_string("annex_wire_sha256"),
            hex(&Sha256::digest(&annex))
        );
        assert_eq!(
            json_string("annex_stripped_sha256"),
            hex(&Sha256::digest(&annex[1..]))
        );

        let historical = encode_groth16_v2_annex(id(1), &proof(), &v4_public_values()).unwrap();
        assert_eq!(
            parse_groth16_public_values_v5_annex(&historical),
            Err(AnnexError::UnsupportedVersion)
        );
        assert_eq!(
            parse_groth16_v2_annex(&annex),
            Err(AnnexError::UnsupportedVersion)
        );

        let backend = V2RecordingBackend::default();
        verify_groth16_public_values_v5_annex(&backend, &annex, id(1), values.sha256()).unwrap();
        assert_eq!(backend.calls.get(), 1);

        let mut wrong_hash = annex.clone();
        wrong_hash[44] ^= 1;
        assert_eq!(
            parse_groth16_public_values_v5_annex(&wrong_hash),
            Err(AnnexError::PublicValuesHashMismatch)
        );
        for malformed in [
            annex[..annex.len() - 1].to_vec(),
            {
                let mut bytes = annex.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = annex.clone();
                bytes.extend_from_slice(&values.encode());
                bytes
            },
        ] {
            assert_eq!(
                parse_groth16_public_values_v5_annex(&malformed),
                Err(AnnexError::LengthMismatch)
            );
        }
    }

    #[test]
    fn malformed_annexes_fail_before_crypto() {
        let valid = encode_groth16_annex(id(1), [9; 32], &proof()).unwrap();
        let backend = RecordingBackend::default();
        for candidate in [
            valid[..79].to_vec(),
            {
                let mut value = valid.clone();
                value[0] ^= 1;
                value
            },
            {
                let mut value = valid.clone();
                value[8] = 1;
                value
            },
            {
                let mut value = valid.clone();
                value[9] = PROOF_MODE_COMPRESSED_DEBUG;
                value
            },
            {
                let mut value = valid.clone();
                value[10] = 2;
                value
            },
            {
                let mut value = valid.clone();
                value[11] = 1;
                value
            },
            {
                let mut value = valid.clone();
                value.extend_from_slice(b"trailing");
                value
            },
            valid[..valid.len() - 1].to_vec(),
        ] {
            assert!(verify_groth16_annex(&backend, &candidate, id(1), [9; 32]).is_err());
        }
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn wrong_size_is_never_a_groth16_proof() {
        assert_eq!(
            encode_groth16_annex(id(1), [9; 32], &[0; GROTH16_PROOF_LEN - 1]),
            Err(AnnexError::WrongGroth16ProofLength)
        );
    }

    #[test]
    fn every_sha256_value_is_encodable() {
        let annex = encode_groth16_annex(id(1), [0; 32], &proof()).unwrap();
        assert_eq!(
            parse_groth16_annex(&annex).unwrap().public_values_sha256,
            [0; 32]
        );
    }

    #[test]
    fn substituted_statement_or_program_fails_before_crypto() {
        let annex = encode_groth16_annex(id(1), [9; 32], &proof()).unwrap();
        let backend = RecordingBackend::default();
        assert_eq!(
            verify_groth16_annex(&backend, &annex, id(2), [9; 32]),
            Err(VerifyError::WrongProgramId)
        );
        assert_eq!(
            verify_groth16_annex(&backend, &annex, id(1), [8; 32]),
            Err(VerifyError::WrongPublicValuesHash)
        );
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn backend_rejection_is_fail_closed() {
        let annex = encode_groth16_annex(id(1), [9; 32], &proof()).unwrap();
        let backend = RecordingBackend {
            calls: Cell::new(0),
            reject: true,
        };
        assert_eq!(
            verify_groth16_annex(&backend, &annex, id(1), [9; 32]),
            Err(VerifyError::Backend("cryptographic rejection"))
        );
    }

    #[test]
    fn noncanonical_vkey_words_are_rejected() {
        assert_eq!(
            ProgramId::from_words([KOALA_BEAR_MODULUS, 1, 2, 3, 4, 5, 6, 7]),
            Err(ProgramIdError::NonCanonicalFieldWord)
        );
        assert_eq!(ProgramId::from_words([0; 8]), Err(ProgramIdError::Zero));
    }
}
