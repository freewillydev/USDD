//! Independent encrypted witness availability for ECX transitions.
//!
//! A bundle encrypts one confidential transition witness under XChaCha20-
//! Poly1305. The payload key is derived from a random Ristretto scalar split
//! into five Feldman-verifiable shares with a threshold of three. Each share is
//! separately encrypted to a custodian's X25519 key. A custodian signs an
//! Ed25519 attestation only after decrypting and validating its share. Recovery
//! requires three distinct, valid custodian attestations.

#![forbid(unsafe_code)]

mod crypto;
mod error;
mod format;
#[cfg(feature = "service")]
mod service;
#[cfg(feature = "service")]
mod store;

#[cfg(feature = "producer")]
pub use crypto::{create_bundle, create_bundle_with_encryption_witness, CustodianSecrets};
pub use crypto::{
    custody_receipt_codec_hash_v1, recover_witness, recovery_certificate_root_v1,
    verify_bundle_encryption, verify_custody_receipts, verify_custody_receipts_compact,
    verify_recovery_certificate, AvailabilityEncryptionWitnessV1, CustodyReceiptV1,
    RecoveredWitness, RecoveryContribution, CUSTODY_RECEIPT_CANONICAL_LEN,
    RECOVERY_CONTRIBUTION_CANONICAL_LEN,
};
pub use error::{AvailabilityError, Result};
pub use format::{
    availability_scheme_hash, custodian_registry_hash, CustodianEnvelope, CustodianPublic,
    WitnessBundle, BUNDLE_VERSION, CUSTODIAN_COUNT, MAX_BUNDLE_BYTES, MAX_WITNESS_BYTES,
    RECOVERY_THRESHOLD,
};
#[cfg(feature = "service")]
pub use service::{AvailabilityService, ServiceConfig};
#[cfg(feature = "service")]
pub use store::{BundleStore, PutOutcome, StoreAuditV1, MAX_STORE_BUNDLES, MAX_STORE_BYTES};
