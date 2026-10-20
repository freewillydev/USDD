//! Authenticated source-chain foundations reused by the V2 conversion guests.
//!
//! The base adapters return intermediate verified state. The `ecx_btc` module
//! composes a conversion statement, but can emit it only after two mandatory
//! recursive full-validity receipts verify. The pinned upstream implementations
//! still cannot alone prove complete Bitcoin fork availability/contextual
//! validity, Elements UTXO/Simplicity validity, ECX reserves, USDD liabilities,
//! or an enforceable USD redemption definition.

#![forbid(unsafe_code)]

#[cfg(feature = "usdd-ethereum")]
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "bitcoin-foundation", feature = "usdd-ethereum"))]
use thiserror::Error;
#[cfg(feature = "bitcoin-foundation")]
use usdd_bitcoin_bmm::{
    verify_header_pow_against_caller_supplied_bits, verify_successor, BitcoinHeader,
    HeaderChainState, PowParameters, Uint256,
};
#[cfg(feature = "usdd-ethereum")]
use usdd_core::{CanonicalDecode, EthereumFinalityWitness, MintControllerState, ProtocolManifest};
#[cfg(feature = "usdd-ethereum")]
use usdd_ethereum_inbound::helios::{SepoliaFinalityProof, SepoliaHeliosFinalityVerifier};

#[cfg(feature = "ecx-btc")]
pub mod ecx_btc;
#[cfg(feature = "usdd-ethereum")]
pub mod usdd_usd;
#[cfg(feature = "usdd-ethereum")]
#[rustfmt::skip]
mod usdd_ownerless_accounting_v2;
#[cfg(feature = "usdd-ethereum")]
pub mod usdd_ownerless_v3;

pub const UPSTREAM_USDD_GIT_URL: &str = "https://github.com/ekulkisnek/USDD.git";
pub const UPSTREAM_USDD_COMMIT: &str = "2c9dc7a72052240613deba3d9cf52a43403368d4";
/// Later clean source pin used only by the ECX/BTC conversion module for its
/// contextual MTP and expanded BIP300 replay. The original pin above remains
/// unchanged for the reviewed Signet/Sepolia foundation adapters.
pub const UPSTREAM_USDD_ECX_BITCOIN_COMMIT: &str = "a0a72d1abf4687172b77175af8c90758fe43e028";

/// A deployment-frozen LayerTwo Signet checkpoint. None of these fields may
/// come from the private proof witness. In particular, a valid-looking header
/// does not authenticate its height, chainwork, or retarget interval start.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "bitcoin-foundation")]
pub struct PinnedBitcoinCheckpoint {
    pub header: [u8; 80],
    pub height: u32,
    pub cumulative_work_be: [u8; 32],
    pub interval_start_time: u32,
}

/// Untrusted successor material. The verifier derives linkage, difficulty,
/// proof of work, height, chainwork, and the resulting tip.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "bitcoin-foundation")]
pub struct BitcoinHeaderBranchWitness {
    pub successor_headers: Vec<[u8; 80]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "bitcoin-foundation")]
pub struct VerifiedBitcoinHeaderFoundation {
    pub tip_hash_internal: [u8; 32],
    pub tip_height: u32,
    pub cumulative_work_be: [u8; 32],
    pub tip_time: u32,
}

/// Alpha proof-of-work parameters for the pinned Bitcoin foundation.
///
/// Mirrors `ecx_btc::alpha_pow_parameters_v3`, which is built on a different
/// pinned revision of the same vendored crate and so cannot be shared. Alpha
/// differs from LayerTwo Signet only in the proof-of-work limit, and has no
/// block-signature challenge.
#[cfg(feature = "bitcoin-foundation")]
fn alpha_foundation_pow_parameters() -> PowParameters {
    let mut limit = [0u8; 32];
    limit[4] = 0xFF;
    limit[5] = 0xFF;
    PowParameters {
        pow_limit: Uint256::from_be_bytes(limit),
        target_timespan: 14 * 24 * 60 * 60,
        target_spacing: 10 * 60,
        allow_min_difficulty_blocks: false,
        no_retargeting: false,
    }
}

/// Verify the concrete header/PoW/retarget subset implemented by the pinned
/// USDD foundation. This function does not claim best-chain membership, MTP,
/// contextual transaction validity, BIP300 replay, or Elements validity.
#[cfg(feature = "bitcoin-foundation")]
pub fn verify_alpha_header_foundation(
    checkpoint: &PinnedBitcoinCheckpoint,
    witness: &BitcoinHeaderBranchWitness,
) -> Result<VerifiedBitcoinHeaderFoundation, FoundationError> {
    if checkpoint.height == 0 || witness.successor_headers.is_empty() {
        return Err(FoundationError::EmptyBitcoinHistory);
    }
    let decoded = BitcoinHeader::decode_exact(&checkpoint.header)
        .map_err(|_| FoundationError::BitcoinCheckpointRejected)?;
    let tip = verify_header_pow_against_caller_supplied_bits(
        &checkpoint.header,
        decoded.bits,
        alpha_foundation_pow_parameters(),
    )
    .map_err(|_| FoundationError::BitcoinCheckpointRejected)?;
    let mut state = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
        checkpoint.height,
        tip,
        Uint256::from_be_bytes(checkpoint.cumulative_work_be),
        checkpoint.interval_start_time,
    )
    .map_err(|_| FoundationError::BitcoinCheckpointRejected)?;
    for header in &witness.successor_headers {
        state = verify_successor(&state, header, alpha_foundation_pow_parameters())
            .map_err(|_| FoundationError::BitcoinSuccessorRejected)?;
    }
    Ok(VerifiedBitcoinHeaderFoundation {
        tip_hash_internal: state.tip.hash.to_internal_bytes(),
        tip_height: state.height,
        cumulative_work_be: state.cumulative_work.to_be_bytes(),
        tip_time: state.tip.header.time,
    })
}

/// Canonical bytes consumed by the pinned Sepolia verifier. All three state
/// records use USDD's strict canonical codec; the finality proof uses its
/// bounded canonical CBOR codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg(feature = "usdd-ethereum")]
pub struct SepoliaFinalityFoundationWitness {
    pub manifest: Vec<u8>,
    pub prior_controller_state: Vec<u8>,
    pub expected_finalized_state: Vec<u8>,
    pub finality_proof_cbor: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "usdd-ethereum")]
pub struct VerifiedSepoliaFinalityFoundation {
    pub prior_light_client_digest: [u8; 32],
    pub prior_finalized_beacon_slot: u64,
    pub prior_finalized_beacon_root: [u8; 32],
    pub prior_finalized_execution_state_root: [u8; 32],
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: [u8; 32],
    pub finalized_execution_block: [u8; 32],
    pub finalized_execution_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub execution_block_timestamp: u64,
    pub ethereum_light_client_digest: [u8; 32],
}

/// Run the pinned Helios SSZ/BLS/finality transition and bind its exact
/// execution state root. Passing this boundary authenticates Sepolia finality;
/// it does not establish which storage slots represent USDD reserve or supply.
#[cfg(feature = "usdd-ethereum")]
pub fn verify_sepolia_finality_foundation(
    witness: &SepoliaFinalityFoundationWitness,
) -> Result<VerifiedSepoliaFinalityFoundation, FoundationError> {
    let manifest = ProtocolManifest::decode_exact(&witness.manifest)
        .map_err(|_| FoundationError::UsddManifestRejected)?;
    let prior = MintControllerState::decode_exact(&witness.prior_controller_state)
        .map_err(|_| FoundationError::UsddPriorStateRejected)?;
    let expected = EthereumFinalityWitness::decode_exact(&witness.expected_finalized_state)
        .map_err(|_| FoundationError::UsddExpectedStateRejected)?;
    let proof = SepoliaFinalityProof::decode_canonical(&witness.finality_proof_cbor)
        .map_err(|_| FoundationError::SepoliaProofCodecRejected)?;
    let derived = SepoliaHeliosFinalityVerifier
        .derive_transition(&manifest, &prior, &proof)
        .map_err(|_| FoundationError::SepoliaFinalityRejected)?;
    if derived != expected {
        return Err(FoundationError::SepoliaOutputMismatch);
    }
    Ok(VerifiedSepoliaFinalityFoundation {
        prior_light_client_digest: prior.ethereum_light_client_digest.0,
        prior_finalized_beacon_slot: prior.finalized_beacon_slot,
        prior_finalized_beacon_root: prior.finalized_beacon_root.0,
        prior_finalized_execution_state_root: prior.finalized_execution_state_root.0,
        finalized_beacon_slot: derived.finalized_beacon_slot,
        finalized_beacon_root: derived.finalized_beacon_root.0,
        finalized_execution_block: derived.finalized_execution_block.0,
        finalized_execution_state_root: derived.finalized_execution_state_root.0,
        execution_block_number: derived.execution_block_number,
        execution_block_timestamp: derived.execution_block_timestamp,
        ethereum_light_client_digest: derived.ethereum_light_client_digest.0,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[cfg(any(feature = "bitcoin-foundation", feature = "usdd-ethereum"))]
pub enum FoundationError {
    #[cfg(feature = "bitcoin-foundation")]
    #[error("Bitcoin checkpoint or successor history is empty")]
    EmptyBitcoinHistory,
    #[cfg(feature = "bitcoin-foundation")]
    #[error("deployment-pinned Bitcoin checkpoint was rejected")]
    BitcoinCheckpointRejected,
    #[cfg(feature = "bitcoin-foundation")]
    #[error("Bitcoin successor failed linkage, retarget, proof-of-work, or chainwork checks")]
    BitcoinSuccessorRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("canonical USDD manifest was rejected")]
    UsddManifestRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("canonical USDD prior controller state was rejected")]
    UsddPriorStateRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("canonical expected Ethereum finalized state was rejected")]
    UsddExpectedStateRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("Sepolia finality proof CBOR was noncanonical or exceeded its bound")]
    SepoliaProofCodecRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("Sepolia SSZ/BLS/finality transition was rejected")]
    SepoliaFinalityRejected,
    #[cfg(feature = "usdd-ethereum")]
    #[error("derived Sepolia finalized state did not equal the expected state")]
    SepoliaOutputMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "bitcoin-foundation", feature = "usdd-ethereum"))]
    fn empty_or_unpinned_inputs_fail_closed() {
        let bitcoin = verify_alpha_header_foundation(
            &PinnedBitcoinCheckpoint {
                header: [0; 80],
                height: 0,
                cumulative_work_be: [0; 32],
                interval_start_time: 0,
            },
            &BitcoinHeaderBranchWitness {
                successor_headers: vec![],
            },
        );
        assert_eq!(bitcoin, Err(FoundationError::EmptyBitcoinHistory));

        let ethereum = verify_sepolia_finality_foundation(&SepoliaFinalityFoundationWitness {
            manifest: vec![],
            prior_controller_state: vec![],
            expected_finalized_state: vec![],
            finality_proof_cbor: vec![],
        });
        assert_eq!(ethereum, Err(FoundationError::UsddManifestRejected));
    }

    #[test]
    fn provenance_pin_is_immutable() {
        assert_eq!(UPSTREAM_USDD_COMMIT.len(), 40);
        assert_eq!(
            UPSTREAM_USDD_COMMIT,
            "2c9dc7a72052240613deba3d9cf52a43403368d4"
        );
        assert_eq!(UPSTREAM_USDD_ECX_BITCOIN_COMMIT.len(), 40);
        assert_eq!(
            UPSTREAM_USDD_ECX_BITCOIN_COMMIT,
            "a0a72d1abf4687172b77175af8c90758fe43e028"
        );
    }
}
