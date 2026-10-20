use std::io;

#[derive(Debug, thiserror::Error)]
pub enum AvailabilityError {
    #[error("bundle is not canonically encoded: {0}")]
    Canonical(&'static str),
    #[error("bundle exceeds the configured size limit")]
    TooLarge,
    #[error("witness must contain between 1 and {max} bytes")]
    WitnessSize { max: usize },
    #[error("custodian configuration is invalid: {0}")]
    Custodian(&'static str),
    #[error("cryptographic key agreement was non-contributory")]
    NonContributoryKey,
    #[error("authenticated encryption or decryption failed")]
    Aead,
    #[error("share is malformed or fails its Feldman commitment")]
    InvalidShare,
    #[error("custodian attestation is invalid")]
    InvalidAttestation,
    #[error("bundle root does not match")]
    RootMismatch,
    #[error("availability certificate needs at least three and at most five custodians")]
    Threshold,
    #[error("recovery contribution uses a duplicate custodian index")]
    DuplicateCustodian,
    #[error("bundle was not found")]
    NotFound,
    #[error("authorization failed")]
    Unauthorized,
    #[error("stored bundle is corrupt")]
    CorruptStore,
    #[error("witness store is already locked by another process")]
    StoreLocked,
    #[error("witness store exceeds the bounded audit limits")]
    StoreLimit,
    #[error("bounded blocking worker failed")]
    WorkerFailure,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, AvailabilityError>;
