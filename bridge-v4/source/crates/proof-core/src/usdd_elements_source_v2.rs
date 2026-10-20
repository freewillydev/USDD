//! Recursive composition boundary for the USDD Elements/BMM source.
//!
//! This module does not replace a full Bitcoin or Elements validator. It
//! requires one exact compressed receipt from each validator, cross-binds
//! their public statements, and only then emits the fixed 738-byte statement
//! consumed by the USDD/USD conversion guest. A host summary or deferred
//! marker without both verified receipts cannot cross this boundary.

use bincode::Options;
use ecx_protocol_core::{tagged_hash, Hash32};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{UsddElementsSourcePublicValuesV2, USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2};

pub const USDD_ELEMENTS_SOURCE_INPUT_VERSION_V2: u8 = 1;
pub const USDD_ELEMENTS_SOURCE_CONFIGURATION_VERSION_V2: u8 = 1;
pub const USDD_ELEMENTS_FULL_BITCOIN_STATEMENT_VERSION_V2: u8 = 1;
pub const USDD_ELEMENTS_FULL_STATE_STATEMENT_VERSION_V2: u8 = 1;
pub const MAX_USDD_ELEMENTS_SOURCE_INPUT_BYTES_V2: usize = 64 * 1024;
pub const MAX_USDD_ELEMENTS_SOURCE_PROOF_MARKER_BYTES_V2: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenUsddElementsSourceConfigurationV2 {
    pub version: u8,
    pub elements_genesis_hash: Hash32,
    pub elements_source_bootstrap_commitment: Hash32,
    pub full_bitcoin_validator_program_id: Hash32,
    pub full_elements_validator_program_id: Hash32,
    pub usdd_checkpoint_configuration_hash: Hash32,
    pub usdd_asset_id: Hash32,
    pub redemption_covenant_commitment: Hash32,
    pub required_parent_confirmations: u32,
}

impl FrozenUsddElementsSourceConfigurationV2 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(229);
        out.push(self.version);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.elements_source_bootstrap_commitment);
        out.extend_from_slice(&self.full_bitcoin_validator_program_id);
        out.extend_from_slice(&self.full_elements_validator_program_id);
        out.extend_from_slice(&self.usdd_checkpoint_configuration_hash);
        out.extend_from_slice(&self.usdd_asset_id);
        out.extend_from_slice(&self.redemption_covenant_commitment);
        out.extend_from_slice(&self.required_parent_confirmations.to_be_bytes());
        debug_assert_eq!(out.len(), 229);
        out
    }

    pub fn validate(&self) -> Result<(), UsddElementsSourceErrorV2> {
        if self.version != USDD_ELEMENTS_SOURCE_CONFIGURATION_VERSION_V2
            || self.required_parent_confirmations == 0
            || [
                self.elements_genesis_hash,
                self.elements_source_bootstrap_commitment,
                self.full_bitcoin_validator_program_id,
                self.full_elements_validator_program_id,
                self.usdd_checkpoint_configuration_hash,
                self.usdd_asset_id,
                self.redemption_covenant_commitment,
            ]
            .contains(&[0; 32])
            || self.full_bitcoin_validator_program_id == self.full_elements_validator_program_id
        {
            return Err(UsddElementsSourceErrorV2::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, UsddElementsSourceErrorV2> {
        self.validate()?;
        Ok(tagged_hash(
            "ECX/usdd-elements-source-configuration/v1",
            &self.canonical_bytes(),
        ))
    }
}

/// Exact output of the complete contextual Bitcoin/BIP300/BIP301 validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsFullBitcoinStatementV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub source_bootstrap_commitment: Hash32,
    pub observed_parent_block_hash: Hash32,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub bitcoin_bmm_history_root: Hash32,
    pub elements_genesis_hash: Hash32,
    pub elements_tip_hash: Hash32,
    pub elements_height: u64,
    pub exact_elements_branch_commitment: Hash32,
    pub contextual_bitcoin_valid: bool,
    pub best_chain_available: bool,
    pub bip300_bip301_valid: bool,
    pub confirmation_depth_valid: bool,
}

impl UsddElementsFullBitcoinStatementV2 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(253);
        out.push(self.version);
        out.extend_from_slice(&self.source_configuration_commitment);
        out.extend_from_slice(&self.source_bootstrap_commitment);
        out.extend_from_slice(&self.observed_parent_block_hash);
        out.extend_from_slice(&self.observed_parent_height.to_be_bytes());
        out.extend_from_slice(&self.observed_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.bitcoin_bmm_history_root);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.elements_tip_hash);
        out.extend_from_slice(&self.elements_height.to_be_bytes());
        out.extend_from_slice(&self.exact_elements_branch_commitment);
        out.push(u8::from(self.contextual_bitcoin_valid));
        out.push(u8::from(self.best_chain_available));
        out.push(u8::from(self.bip300_bip301_valid));
        out.push(u8::from(self.confirmation_depth_valid));
        debug_assert_eq!(out.len(), 253);
        out
    }

    fn validate_shape(&self) -> Result<(), UsddElementsSourceErrorV2> {
        if self.version != USDD_ELEMENTS_FULL_BITCOIN_STATEMENT_VERSION_V2
            || self.observed_parent_height == 0
            || self.observed_parent_mtp == 0
            || self.elements_height == 0
            || [
                self.source_configuration_commitment,
                self.source_bootstrap_commitment,
                self.observed_parent_block_hash,
                self.bitcoin_bmm_history_root,
                self.elements_genesis_hash,
                self.elements_tip_hash,
                self.exact_elements_branch_commitment,
            ]
            .contains(&[0; 32])
            || !self.contextual_bitcoin_valid
            || !self.best_chain_available
            || !self.bip300_bip301_valid
            || !self.confirmation_depth_valid
        {
            return Err(UsddElementsSourceErrorV2::InvalidBitcoinStatement);
        }
        Ok(())
    }
}

/// Exact output of the complete Elements UTXO/confidential/Simplicity
/// validator for the same BMM-authenticated branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsFullStateStatementV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub source_bootstrap_commitment: Hash32,
    pub elements_genesis_hash: Hash32,
    pub elements_tip_hash: Hash32,
    pub elements_height: u64,
    pub exact_elements_branch_commitment: Hash32,
    pub usdd_checkpoint_configuration_hash: Hash32,
    pub prior_checkpoint_commitment: Hash32,
    pub prior_checkpoint_sequence: u64,
    pub prior_checkpoint_light_client_digest: Hash32,
    pub prior_checkpoint_finalized_beacon_slot: u64,
    pub prior_checkpoint_finalized_beacon_root: Hash32,
    pub prior_checkpoint_execution_state_root: Hash32,
    pub current_checkpoint_commitment: Hash32,
    pub checkpoint_sequence: u64,
    pub checkpoint_light_client_digest: Hash32,
    pub checkpoint_finalized_beacon_slot: u64,
    pub checkpoint_finalized_beacon_root: Hash32,
    pub checkpoint_execution_block_hash: Hash32,
    pub checkpoint_execution_state_root: Hash32,
    pub checkpoint_execution_block_number: u64,
    pub checkpoint_execution_timestamp: u64,
    pub checkpoint_accepted_parent_mtp: u64,
    pub checkpoint_update_proof_commitment: Hash32,
    pub usdd_asset_id: Hash32,
    pub outstanding_usdd_atoms: u128,
    pub redemption_covenant_commitment: Hash32,
    pub redemption_covenant_live: bool,
    pub elements_consensus_state_root: Hash32,
    pub complete_utxo_replay_valid: bool,
    pub confidential_openings_valid: bool,
    pub asset_conservation_valid: bool,
    pub checkpoint_authority_valid: bool,
    pub simplicity_covenant_valid: bool,
    pub issuance_and_reissuance_valid: bool,
    pub all_outputs_classified: bool,
}

impl UsddElementsFullStateStatementV2 {
    /// Project an exact checkpoint transition into the source statement.
    /// This checks linkage and configuration, not Ethereum proof validity or
    /// Elements authority execution. Successful projection clears any prior
    /// `checkpoint_authority_valid` attestation: it cannot authenticate the new
    /// preimages. The producing guest must earn that attestation again through
    /// its authenticated execution relation.
    pub fn bind_checkpoint_transition(
        &mut self,
        config: &ecx_protocol_core::UsddCheckpointConfigV1,
        prior: &ecx_protocol_core::UsddEthereumCheckpointV1,
        current: &ecx_protocol_core::UsddEthereumCheckpointV1,
    ) -> Result<(), UsddElementsSourceErrorV2> {
        if config.digest() != self.usdd_checkpoint_configuration_hash {
            return Err(UsddElementsSourceErrorV2::ConfigurationMismatch);
        }
        ecx_protocol_core::verify_usdd_checkpoint_successor(config, prior, current)
            .map_err(|_| UsddElementsSourceErrorV2::InvalidElementsStatement)?;
        // Mutate only after all checks, so a rejected transition leaves the
        // statement intact. Derive commitments from the exact preimages.
        self.prior_checkpoint_commitment = prior.commitment();
        self.prior_checkpoint_sequence = prior.sequence;
        self.prior_checkpoint_light_client_digest = prior.light_client_digest;
        self.prior_checkpoint_finalized_beacon_slot = prior.finalized_beacon_slot;
        self.prior_checkpoint_finalized_beacon_root = prior.finalized_beacon_root;
        self.prior_checkpoint_execution_state_root = prior.finalized_execution_state_root;
        self.current_checkpoint_commitment = current.commitment();
        self.checkpoint_sequence = current.sequence;
        self.checkpoint_light_client_digest = current.light_client_digest;
        self.checkpoint_finalized_beacon_slot = current.finalized_beacon_slot;
        self.checkpoint_finalized_beacon_root = current.finalized_beacon_root;
        self.checkpoint_execution_block_hash = current.finalized_execution_block_hash;
        self.checkpoint_execution_state_root = current.finalized_execution_state_root;
        self.checkpoint_execution_block_number = current.finalized_execution_block_number;
        self.checkpoint_execution_timestamp = current.finalized_execution_timestamp;
        self.checkpoint_accepted_parent_mtp = current.accepted_parent_mtp;
        self.checkpoint_update_proof_commitment = current.update_proof_commitment;
        self.checkpoint_authority_valid = false;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.source_configuration_commitment);
        out.extend_from_slice(&self.source_bootstrap_commitment);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.elements_tip_hash);
        out.extend_from_slice(&self.elements_height.to_be_bytes());
        out.extend_from_slice(&self.exact_elements_branch_commitment);
        out.extend_from_slice(&self.usdd_checkpoint_configuration_hash);
        out.extend_from_slice(&self.prior_checkpoint_commitment);
        out.extend_from_slice(&self.prior_checkpoint_sequence.to_be_bytes());
        out.extend_from_slice(&self.prior_checkpoint_light_client_digest);
        out.extend_from_slice(&self.prior_checkpoint_finalized_beacon_slot.to_be_bytes());
        out.extend_from_slice(&self.prior_checkpoint_finalized_beacon_root);
        out.extend_from_slice(&self.prior_checkpoint_execution_state_root);
        out.extend_from_slice(&self.current_checkpoint_commitment);
        out.extend_from_slice(&self.checkpoint_sequence.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_light_client_digest);
        out.extend_from_slice(&self.checkpoint_finalized_beacon_slot.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_finalized_beacon_root);
        out.extend_from_slice(&self.checkpoint_execution_block_hash);
        out.extend_from_slice(&self.checkpoint_execution_state_root);
        out.extend_from_slice(&self.checkpoint_execution_block_number.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_execution_timestamp.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_accepted_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_update_proof_commitment);
        out.extend_from_slice(&self.usdd_asset_id);
        out.extend_from_slice(&self.outstanding_usdd_atoms.to_be_bytes());
        out.extend_from_slice(&self.redemption_covenant_commitment);
        out.push(u8::from(self.redemption_covenant_live));
        out.extend_from_slice(&self.elements_consensus_state_root);
        for flag in [
            self.complete_utxo_replay_valid,
            self.confidential_openings_valid,
            self.asset_conservation_valid,
            self.checkpoint_authority_valid,
            self.simplicity_covenant_valid,
            self.issuance_and_reissuance_valid,
            self.all_outputs_classified,
        ] {
            out.push(u8::from(flag));
        }
        out
    }

    fn validate_shape(&self) -> Result<(), UsddElementsSourceErrorV2> {
        let public = self.to_public_values([1; 32], 1, 1, [2; 32]);
        public
            .validate_shape()
            .map_err(|_| UsddElementsSourceErrorV2::InvalidElementsStatement)?;
        if self.version != USDD_ELEMENTS_FULL_STATE_STATEMENT_VERSION_V2
            || !self.complete_utxo_replay_valid
            || !self.confidential_openings_valid
            || !self.asset_conservation_valid
            || !self.checkpoint_authority_valid
            || !self.simplicity_covenant_valid
            || !self.issuance_and_reissuance_valid
            || !self.all_outputs_classified
        {
            return Err(UsddElementsSourceErrorV2::InvalidElementsStatement);
        }
        Ok(())
    }

    fn to_public_values(
        &self,
        observed_parent_block_hash: Hash32,
        observed_parent_height: u64,
        observed_parent_mtp: u64,
        bitcoin_bmm_history_root: Hash32,
    ) -> UsddElementsSourcePublicValuesV2 {
        UsddElementsSourcePublicValuesV2 {
            version: USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2,
            observed_parent_block_hash,
            observed_parent_height,
            observed_parent_mtp,
            bitcoin_bmm_history_root,
            elements_genesis_hash: self.elements_genesis_hash,
            elements_tip_hash: self.elements_tip_hash,
            elements_height: self.elements_height,
            elements_source_configuration_commitment: self.source_configuration_commitment,
            elements_source_bootstrap_commitment: self.source_bootstrap_commitment,
            usdd_checkpoint_configuration_hash: self.usdd_checkpoint_configuration_hash,
            prior_checkpoint_commitment: self.prior_checkpoint_commitment,
            prior_checkpoint_sequence: self.prior_checkpoint_sequence,
            prior_checkpoint_light_client_digest: self.prior_checkpoint_light_client_digest,
            prior_checkpoint_finalized_beacon_slot: self.prior_checkpoint_finalized_beacon_slot,
            prior_checkpoint_finalized_beacon_root: self.prior_checkpoint_finalized_beacon_root,
            prior_checkpoint_execution_state_root: self.prior_checkpoint_execution_state_root,
            current_checkpoint_commitment: self.current_checkpoint_commitment,
            checkpoint_sequence: self.checkpoint_sequence,
            checkpoint_light_client_digest: self.checkpoint_light_client_digest,
            checkpoint_finalized_beacon_slot: self.checkpoint_finalized_beacon_slot,
            checkpoint_finalized_beacon_root: self.checkpoint_finalized_beacon_root,
            checkpoint_execution_block_hash: self.checkpoint_execution_block_hash,
            checkpoint_execution_state_root: self.checkpoint_execution_state_root,
            checkpoint_execution_block_number: self.checkpoint_execution_block_number,
            checkpoint_execution_timestamp: self.checkpoint_execution_timestamp,
            checkpoint_accepted_parent_mtp: self.checkpoint_accepted_parent_mtp,
            checkpoint_update_proof_commitment: self.checkpoint_update_proof_commitment,
            usdd_asset_id: self.usdd_asset_id,
            outstanding_usdd_atoms: self.outstanding_usdd_atoms,
            redemption_covenant_commitment: self.redemption_covenant_commitment,
            redemption_covenant_live: self.redemption_covenant_live,
            elements_consensus_state_root: self.elements_consensus_state_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsRecursiveReceiptReferenceV2 {
    pub proof_marker: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsSourceInputV2 {
    pub version: u8,
    pub configuration: FrozenUsddElementsSourceConfigurationV2,
    pub bitcoin_statement: UsddElementsFullBitcoinStatementV2,
    pub bitcoin_receipt: UsddElementsRecursiveReceiptReferenceV2,
    pub elements_statement: UsddElementsFullStateStatementV2,
    pub elements_receipt: UsddElementsRecursiveReceiptReferenceV2,
}

impl UsddElementsSourceInputV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UsddElementsSourceErrorV2> {
        let bytes = canonical_options()
            .serialize(self)
            .map_err(|_| UsddElementsSourceErrorV2::NonCanonicalEncoding)?;
        if bytes.is_empty() || bytes.len() > MAX_USDD_ELEMENTS_SOURCE_INPUT_BYTES_V2 {
            return Err(UsddElementsSourceErrorV2::ResourceLimit);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, UsddElementsSourceErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_USDD_ELEMENTS_SOURCE_INPUT_BYTES_V2 {
            return Err(UsddElementsSourceErrorV2::ResourceLimit);
        }
        let value: Self = canonical_options()
            .deserialize(bytes)
            .map_err(|_| UsddElementsSourceErrorV2::NonCanonicalEncoding)?;
        if value.canonical_bytes()? != bytes {
            return Err(UsddElementsSourceErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

pub trait UsddElementsFullValidityVerifierV2 {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), UsddElementsSourceErrorV2>;
}

pub fn execute_usdd_elements_source_v2<V>(
    input: &UsddElementsSourceInputV2,
    verifier: &V,
) -> Result<Vec<u8>, UsddElementsSourceErrorV2>
where
    V: UsddElementsFullValidityVerifierV2,
{
    if input.version != USDD_ELEMENTS_SOURCE_INPUT_VERSION_V2 {
        return Err(UsddElementsSourceErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    input.bitcoin_statement.validate_shape()?;
    input.elements_statement.validate_shape()?;
    for marker in [
        &input.bitcoin_receipt.proof_marker,
        &input.elements_receipt.proof_marker,
    ] {
        if marker.is_empty() || marker.len() > MAX_USDD_ELEMENTS_SOURCE_PROOF_MARKER_BYTES_V2 {
            return Err(UsddElementsSourceErrorV2::InvalidProofMarker);
        }
    }

    let configuration_commitment = input.configuration.commitment()?;
    let bitcoin = &input.bitcoin_statement;
    let elements = &input.elements_statement;
    if bitcoin.source_configuration_commitment != configuration_commitment
        || elements.source_configuration_commitment != configuration_commitment
        || bitcoin.source_bootstrap_commitment
            != input.configuration.elements_source_bootstrap_commitment
        || elements.source_bootstrap_commitment
            != input.configuration.elements_source_bootstrap_commitment
        || bitcoin.elements_genesis_hash != input.configuration.elements_genesis_hash
        || elements.elements_genesis_hash != input.configuration.elements_genesis_hash
        || elements.usdd_checkpoint_configuration_hash
            != input.configuration.usdd_checkpoint_configuration_hash
        || elements.usdd_asset_id != input.configuration.usdd_asset_id
        || elements.redemption_covenant_commitment
            != input.configuration.redemption_covenant_commitment
    {
        return Err(UsddElementsSourceErrorV2::ConfigurationMismatch);
    }

    verifier
        .verify(
            input.configuration.full_bitcoin_validator_program_id,
            &bitcoin.canonical_bytes(),
            &input.bitcoin_receipt.proof_marker,
        )
        .map_err(|_| UsddElementsSourceErrorV2::BitcoinReceiptRejected)?;
    verifier
        .verify(
            input.configuration.full_elements_validator_program_id,
            &elements.canonical_bytes(),
            &input.elements_receipt.proof_marker,
        )
        .map_err(|_| UsddElementsSourceErrorV2::ElementsReceiptRejected)?;

    if bitcoin.elements_genesis_hash != elements.elements_genesis_hash
        || bitcoin.elements_tip_hash != elements.elements_tip_hash
        || bitcoin.elements_height != elements.elements_height
        || bitcoin.exact_elements_branch_commitment != elements.exact_elements_branch_commitment
        || elements.checkpoint_accepted_parent_mtp > bitcoin.observed_parent_mtp
    {
        return Err(UsddElementsSourceErrorV2::CrossChainStatementMismatch);
    }

    let public = elements.to_public_values(
        bitcoin.observed_parent_block_hash,
        bitcoin.observed_parent_height,
        bitcoin.observed_parent_mtp,
        bitcoin.bitcoin_bmm_history_root,
    );
    public
        .validate_shape()
        .map_err(|_| UsddElementsSourceErrorV2::InvalidElementsStatement)?;
    Ok(public.canonical_bytes())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_USDD_ELEMENTS_SOURCE_INPUT_BYTES_V2 as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UsddElementsSourceErrorV2 {
    #[error("unsupported USDD Elements source input version")]
    UnsupportedVersion,
    #[error("invalid frozen USDD Elements source configuration")]
    InvalidConfiguration,
    #[error("malformed full Bitcoin/BMM statement")]
    InvalidBitcoinStatement,
    #[error("malformed full Elements state statement")]
    InvalidElementsStatement,
    #[error("recursive proof marker is empty or oversized")]
    InvalidProofMarker,
    #[error("source statement does not match the frozen configuration")]
    ConfigurationMismatch,
    #[error("full Bitcoin/BMM recursive receipt rejected")]
    BitcoinReceiptRejected,
    #[error("full Elements recursive receipt rejected")]
    ElementsReceiptRejected,
    #[error("Bitcoin/BMM and Elements statements do not describe one branch")]
    CrossChainStatementMismatch,
    #[error("noncanonical USDD Elements source input")]
    NonCanonicalEncoding,
    #[error("USDD Elements source input exceeds its resource bound")]
    ResourceLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExactVerifier;

    impl UsddElementsFullValidityVerifierV2 for ExactVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            _public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), UsddElementsSourceErrorV2> {
            if (program_id == [3; 32] && proof_marker == [30])
                || (program_id == [4; 32] && proof_marker == [40])
            {
                Ok(())
            } else {
                Err(UsddElementsSourceErrorV2::InvalidProofMarker)
            }
        }
    }

    #[test]
    fn exact_recursive_composition_emits_existing_fixed_statement() {
        let input = valid_input();
        let bytes = input.canonical_bytes().expect("encode");
        assert_eq!(
            UsddElementsSourceInputV2::decode_canonical(&bytes).expect("decode"),
            input
        );
        let public = execute_usdd_elements_source_v2(&input, &ExactVerifier).expect("execute");
        assert_eq!(
            public.len(),
            crate::USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2
        );
    }

    #[test]
    fn receipt_branch_and_configuration_substitution_reject() {
        let mut input = valid_input();
        input.bitcoin_receipt.proof_marker[0] ^= 1;
        assert_eq!(
            execute_usdd_elements_source_v2(&input, &ExactVerifier),
            Err(UsddElementsSourceErrorV2::BitcoinReceiptRejected)
        );

        let mut input = valid_input();
        input.elements_statement.exact_elements_branch_commitment = [99; 32];
        assert_eq!(
            execute_usdd_elements_source_v2(&input, &ExactVerifier),
            Err(UsddElementsSourceErrorV2::CrossChainStatementMismatch)
        );

        let mut input = valid_input();
        input.elements_statement.usdd_asset_id = [98; 32];
        assert_eq!(
            execute_usdd_elements_source_v2(&input, &ExactVerifier),
            Err(UsddElementsSourceErrorV2::ConfigurationMismatch)
        );
    }

    #[test]
    fn validity_flags_and_trailing_bytes_reject() {
        let mut input = valid_input();
        input.elements_statement.complete_utxo_replay_valid = false;
        assert_eq!(
            execute_usdd_elements_source_v2(&input, &ExactVerifier),
            Err(UsddElementsSourceErrorV2::InvalidElementsStatement)
        );

        let mut encoded = valid_input().canonical_bytes().expect("encode");
        encoded.push(0);
        assert_eq!(
            UsddElementsSourceInputV2::decode_canonical(&encoded),
            Err(UsddElementsSourceErrorV2::NonCanonicalEncoding)
        );
    }

    #[test]
    fn checkpoint_projection_binds_preimages_without_attesting_execution() {
        use ecx_protocol_core::{UsddCheckpointConfigV1, UsddEthereumCheckpointV1};
        let config = UsddCheckpointConfigV1 {
            version: 1,
            ethereum_light_client_configuration_hash: [81; 32],
            authority_configuration_hash: [82; 32],
            maximum_checkpoint_age_seconds: 13 * 24 * 60 * 60,
        };
        let prior = UsddEthereumCheckpointV1 {
            version: 1, configuration_hash: config.digest(), sequence: 0,
            light_client_digest: [83; 32], finalized_beacon_slot: 100,
            finalized_beacon_root: [84; 32], finalized_execution_block_hash: [85; 32],
            finalized_execution_state_root: [86; 32], finalized_execution_block_number: 200,
            finalized_execution_timestamp: 1000, accepted_parent_mtp: 1010,
            prior_checkpoint_commitment: [0; 32], update_proof_commitment: [87; 32],
        };
        let current = UsddEthereumCheckpointV1 {
            sequence: 1, prior_checkpoint_commitment: prior.commitment(),
            light_client_digest: [88; 32], finalized_beacon_slot: 101,
            finalized_beacon_root: [89; 32], finalized_execution_block_hash: [90; 32],
            finalized_execution_state_root: [91; 32], finalized_execution_block_number: 201,
            finalized_execution_timestamp: 1012, accepted_parent_mtp: 1020,
            update_proof_commitment: [92; 32], ..prior
        };
        let mut statement = valid_input().elements_statement;
        statement.usdd_checkpoint_configuration_hash = config.digest();
        // An existing attestation must not survive replacement of its inputs.
        assert!(statement.checkpoint_authority_valid);
        statement.bind_checkpoint_transition(&config, &prior, &current).unwrap();
        assert_eq!(statement.prior_checkpoint_commitment, prior.commitment());
        assert_eq!(statement.current_checkpoint_commitment, current.commitment());
        assert_eq!(statement.checkpoint_execution_state_root, current.finalized_execution_state_root);
        assert_eq!(statement.checkpoint_update_proof_commitment, current.update_proof_commitment);
        assert!(!statement.checkpoint_authority_valid);
        assert_eq!(statement.validate_shape(), Err(UsddElementsSourceErrorV2::InvalidElementsStatement));
        let original = statement.clone();
        let mut bad = current;
        bad.prior_checkpoint_commitment[0] ^= 1;
        assert!(statement.bind_checkpoint_transition(&config, &prior, &bad).is_err());
        assert_eq!(statement, original);
        let mut wrong_config = config;
        wrong_config.authority_configuration_hash[0] ^= 1;
        assert_eq!(statement.bind_checkpoint_transition(&wrong_config, &prior, &current),
            Err(UsddElementsSourceErrorV2::ConfigurationMismatch));
        assert_eq!(statement, original);
    }

    fn valid_input() -> UsddElementsSourceInputV2 {
        let configuration = FrozenUsddElementsSourceConfigurationV2 {
            version: USDD_ELEMENTS_SOURCE_CONFIGURATION_VERSION_V2,
            elements_genesis_hash: [1; 32],
            elements_source_bootstrap_commitment: [2; 32],
            full_bitcoin_validator_program_id: [3; 32],
            full_elements_validator_program_id: [4; 32],
            usdd_checkpoint_configuration_hash: [5; 32],
            usdd_asset_id: [6; 32],
            redemption_covenant_commitment: [7; 32],
            required_parent_confirmations: 6,
        };
        let commitment = configuration.commitment().expect("configuration");
        let branch = [8; 32];
        let bitcoin_statement = UsddElementsFullBitcoinStatementV2 {
            version: USDD_ELEMENTS_FULL_BITCOIN_STATEMENT_VERSION_V2,
            source_configuration_commitment: commitment,
            source_bootstrap_commitment: configuration.elements_source_bootstrap_commitment,
            observed_parent_block_hash: [9; 32],
            observed_parent_height: 900_000,
            observed_parent_mtp: 1_800_000_000,
            bitcoin_bmm_history_root: [10; 32],
            elements_genesis_hash: configuration.elements_genesis_hash,
            elements_tip_hash: [11; 32],
            elements_height: 50_000,
            exact_elements_branch_commitment: branch,
            contextual_bitcoin_valid: true,
            best_chain_available: true,
            bip300_bip301_valid: true,
            confirmation_depth_valid: true,
        };
        let elements_statement = UsddElementsFullStateStatementV2 {
            version: USDD_ELEMENTS_FULL_STATE_STATEMENT_VERSION_V2,
            source_configuration_commitment: commitment,
            source_bootstrap_commitment: configuration.elements_source_bootstrap_commitment,
            elements_genesis_hash: configuration.elements_genesis_hash,
            elements_tip_hash: bitcoin_statement.elements_tip_hash,
            elements_height: bitcoin_statement.elements_height,
            exact_elements_branch_commitment: branch,
            usdd_checkpoint_configuration_hash: configuration.usdd_checkpoint_configuration_hash,
            prior_checkpoint_commitment: [12; 32],
            prior_checkpoint_sequence: 7,
            prior_checkpoint_light_client_digest: [13; 32],
            prior_checkpoint_finalized_beacon_slot: 100,
            prior_checkpoint_finalized_beacon_root: [14; 32],
            prior_checkpoint_execution_state_root: [15; 32],
            current_checkpoint_commitment: [16; 32],
            checkpoint_sequence: 8,
            checkpoint_light_client_digest: [17; 32],
            checkpoint_finalized_beacon_slot: 101,
            checkpoint_finalized_beacon_root: [18; 32],
            checkpoint_execution_block_hash: [19; 32],
            checkpoint_execution_state_root: [20; 32],
            checkpoint_execution_block_number: 21,
            checkpoint_execution_timestamp: 1_799_999_900,
            checkpoint_accepted_parent_mtp: 1_799_999_950,
            checkpoint_update_proof_commitment: [22; 32],
            usdd_asset_id: configuration.usdd_asset_id,
            outstanding_usdd_atoms: 1_000_000,
            redemption_covenant_commitment: configuration.redemption_covenant_commitment,
            redemption_covenant_live: true,
            elements_consensus_state_root: [23; 32],
            complete_utxo_replay_valid: true,
            confidential_openings_valid: true,
            asset_conservation_valid: true,
            checkpoint_authority_valid: true,
            simplicity_covenant_valid: true,
            issuance_and_reissuance_valid: true,
            all_outputs_classified: true,
        };
        configuration.validate().expect("valid configuration");
        UsddElementsSourceInputV2 {
            version: USDD_ELEMENTS_SOURCE_INPUT_VERSION_V2,
            configuration,
            bitcoin_statement,
            bitcoin_receipt: UsddElementsRecursiveReceiptReferenceV2 {
                proof_marker: vec![30],
            },
            elements_statement,
            elements_receipt: UsddElementsRecursiveReceiptReferenceV2 {
                proof_marker: vec![40],
            },
        }
    }
}
