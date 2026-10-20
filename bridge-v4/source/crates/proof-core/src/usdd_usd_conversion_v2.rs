//! Authenticated USDD/USD conversion statement and canonical private witness.
//!
//! This module deliberately separates the deterministic conversion relation
//! from the cryptographic source verifiers.  The SP1 guest supplies a concrete
//! Sepolia finality/MPT verifier and a recursive verifier for the complete
//! Elements/BMM/USDD state receipt.  Host code receives no permissive default.

use bincode::Options;
use ecx_protocol_core::{
    tagged_hash, Hash32, UsddCheckpointConfigV1, UsddEthereumCheckpointV1, PRICE_SCALE,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ConversionLegKindV2, ConversionLegPublicValuesV2};

pub const USDD_USD_CONVERSION_INPUT_VERSION_V2: u8 = 2;
pub const USDD_USD_FROZEN_CONFIGURATION_VERSION_V2: u8 = 1;
pub const USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2: usize = 457;
pub const USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const MAX_USDD_USD_CONVERSION_INPUT_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_USDD_USD_PREIMAGE_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_USDD_USD_PROOF_NODES_V2: usize = 65;
pub const MAX_USDD_USD_PROOF_NODE_BYTES_V2: usize = 4_096;
pub const USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2: usize = 738;

/// Everything that must be chosen and reviewed before a USDD/USD guest
/// program identity is frozen.  This complete record is committed by
/// `ConversionLegPublicValuesV2::source_checkpoint_commitment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenUsddUsdConfigurationV2 {
    pub version: u8,
    pub ethereum_chain_id: u64,
    pub ethereum_light_client_configuration_hash: Hash32,
    pub protocol_manifest_commitment: Hash32,
    pub usdd_asset_id: Hash32,
    pub elements_genesis_hash: Hash32,
    pub ethereum_source_program_id: Hash32,
    pub elements_source_program_id: Hash32,
    /// Commits the independent source verifier's Bitcoin checkpoint, BMM
    /// rules, Elements checkpoint and complete-state bootstrap.
    pub elements_source_configuration_commitment: Hash32,
    /// Exact independently authenticated source receipt/checkpoint from which
    /// the rolling Elements verifier must prove continuity.
    pub elements_source_bootstrap_commitment: Hash32,
    /// Exact spend-and-recreate Elements authority configuration used by the
    /// rolling `UsddEthereumCheckpointV1` lane.
    pub usdd_checkpoint_authority_configuration_hash: Hash32,
    pub redemption_covenant_commitment: Hash32,
    pub usd_redemption_definition_commitment: Hash32,
    pub vault_address: [u8; 20],
    pub vault_runtime_code_hash: Hash32,
    pub reserve_token_address: [u8; 20],
    pub reserve_token_runtime_code_hash: Hash32,
    pub price_contract_address: [u8; 20],
    pub price_contract_runtime_code_hash: Hash32,
    pub vault_liability_storage_key: Hash32,
    pub vault_pause_storage_key: Hash32,
    pub vault_governance_storage_key: Hash32,
    /// Exact authenticated values which reviewed deployment semantics define
    /// as redemption enabled and governance locked. Zero is permitted.
    pub redemption_enabled_pause_value: Hash32,
    pub governance_locked_value: Hash32,
    /// Solidity mapping slot, not the already-hashed balance key.  The
    /// verifier derives `balanceOf(vault)` itself.
    pub reserve_balance_mapping_slot: Hash32,
    pub price_storage_key: Hash32,
    pub reserve_token_atoms_per_whole: u64,
    pub reserve_token_atoms_redeemable_per_whole_usdd: u64,
    pub expected_quote_atoms_per_whole_reserve_token: u64,
    pub maximum_age_seconds: u64,
}

impl FrozenUsddUsdConfigurationV2 {
    /// Exact projection verified inside the independent sha2-0.10.8 Ethereum
    /// source program. Keeping this projection fixed prevents that receipt
    /// from proving a different address, code hash, slot, or safe state.
    pub fn ethereum_source_configuration_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(485);
        out.push(self.version);
        out.extend_from_slice(&self.ethereum_chain_id.to_be_bytes());
        out.extend_from_slice(&self.ethereum_light_client_configuration_hash);
        out.extend_from_slice(&self.usdd_asset_id);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.vault_address);
        out.extend_from_slice(&self.vault_runtime_code_hash);
        out.extend_from_slice(&self.reserve_token_address);
        out.extend_from_slice(&self.reserve_token_runtime_code_hash);
        out.extend_from_slice(&self.price_contract_address);
        out.extend_from_slice(&self.price_contract_runtime_code_hash);
        out.extend_from_slice(&self.vault_liability_storage_key);
        out.extend_from_slice(&self.vault_pause_storage_key);
        out.extend_from_slice(&self.vault_governance_storage_key);
        out.extend_from_slice(&self.redemption_enabled_pause_value);
        out.extend_from_slice(&self.governance_locked_value);
        out.extend_from_slice(&self.reserve_balance_mapping_slot);
        out.extend_from_slice(&self.price_storage_key);
        debug_assert_eq!(out.len(), 485);
        out
    }

    pub fn ethereum_source_configuration_commitment(&self) -> Hash32 {
        tagged_hash(
            "ECX/usdd-usd-ethereum-source-configuration/v2",
            &self.ethereum_source_configuration_bytes(),
        )
    }
}

impl FrozenUsddUsdConfigurationV2 {
    pub fn validate(&self) -> Result<(), UsddUsdConversionErrorV2> {
        let ids = [
            self.ethereum_light_client_configuration_hash,
            self.protocol_manifest_commitment,
            self.usdd_asset_id,
            self.elements_genesis_hash,
            self.ethereum_source_program_id,
            self.elements_source_program_id,
            self.elements_source_configuration_commitment,
            self.elements_source_bootstrap_commitment,
            self.usdd_checkpoint_authority_configuration_hash,
            self.redemption_covenant_commitment,
            self.usd_redemption_definition_commitment,
            self.vault_runtime_code_hash,
            self.reserve_token_runtime_code_hash,
            self.price_contract_runtime_code_hash,
        ];
        if self.version != USDD_USD_FROZEN_CONFIGURATION_VERSION_V2
            || self.ethereum_chain_id == 0
            || self.vault_address == [0; 20]
            || self.reserve_token_address == [0; 20]
            || self.price_contract_address == [0; 20]
            || ids.contains(&[0; 32])
            || self.ethereum_source_program_id == self.elements_source_program_id
            || self.reserve_token_atoms_per_whole == 0
            || self.reserve_token_atoms_redeemable_per_whole_usdd == 0
            || self.expected_quote_atoms_per_whole_reserve_token == 0
            || self.maximum_age_seconds == 0
        {
            return Err(UsddUsdConversionErrorV2::InvalidFrozenConfiguration);
        }
        self.checkpoint_configuration()
            .validate()
            .map_err(|_| UsddUsdConversionErrorV2::InvalidFrozenConfiguration)?;
        Ok(())
    }

    pub fn checkpoint_configuration(&self) -> UsddCheckpointConfigV1 {
        UsddCheckpointConfigV1 {
            version: UsddCheckpointConfigV1::VERSION,
            ethereum_light_client_configuration_hash: self.ethereum_light_client_configuration_hash,
            authority_configuration_hash: self.usdd_checkpoint_authority_configuration_hash,
            maximum_checkpoint_age_seconds: self.maximum_age_seconds,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UsddUsdConversionErrorV2> {
        let mut out = Vec::with_capacity(773);
        out.push(self.version);
        out.extend_from_slice(&self.ethereum_chain_id.to_be_bytes());
        out.extend_from_slice(&self.ethereum_light_client_configuration_hash);
        out.extend_from_slice(&self.protocol_manifest_commitment);
        out.extend_from_slice(&self.usdd_asset_id);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.ethereum_source_program_id);
        out.extend_from_slice(&self.elements_source_program_id);
        out.extend_from_slice(&self.elements_source_configuration_commitment);
        out.extend_from_slice(&self.elements_source_bootstrap_commitment);
        out.extend_from_slice(&self.usdd_checkpoint_authority_configuration_hash);
        out.extend_from_slice(&self.redemption_covenant_commitment);
        out.extend_from_slice(&self.usd_redemption_definition_commitment);
        out.extend_from_slice(&self.vault_address);
        out.extend_from_slice(&self.vault_runtime_code_hash);
        out.extend_from_slice(&self.reserve_token_address);
        out.extend_from_slice(&self.reserve_token_runtime_code_hash);
        out.extend_from_slice(&self.price_contract_address);
        out.extend_from_slice(&self.price_contract_runtime_code_hash);
        out.extend_from_slice(&self.vault_liability_storage_key);
        out.extend_from_slice(&self.vault_pause_storage_key);
        out.extend_from_slice(&self.vault_governance_storage_key);
        out.extend_from_slice(&self.redemption_enabled_pause_value);
        out.extend_from_slice(&self.governance_locked_value);
        out.extend_from_slice(&self.reserve_balance_mapping_slot);
        out.extend_from_slice(&self.price_storage_key);
        out.extend_from_slice(&self.reserve_token_atoms_per_whole.to_be_bytes());
        out.extend_from_slice(
            &self
                .reserve_token_atoms_redeemable_per_whole_usdd
                .to_be_bytes(),
        );
        out.extend_from_slice(
            &self
                .expected_quote_atoms_per_whole_reserve_token
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.maximum_age_seconds.to_be_bytes());
        debug_assert_eq!(out.len(), 773);
        Ok(out)
    }

    pub fn commitment(&self) -> Result<Hash32, UsddUsdConversionErrorV2> {
        Ok(tagged_hash(
            "ECX/usdd-usd-frozen-configuration/v2",
            &self.canonical_bytes()?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EthereumAccountRoleV2 {
    Vault = 0,
    ReserveToken = 1,
    PriceContract = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EthereumStorageRoleV2 {
    VaultLiability = 0,
    VaultPaused = 1,
    VaultGovernance = 2,
    ReserveBalance = 3,
    ReserveUsdQuote = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumAccountProofV2 {
    pub role: EthereumAccountRoleV2,
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance_be: Hash32,
    pub storage_root: Hash32,
    pub runtime_code_hash: Hash32,
    pub proof_nodes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumStorageProofV2 {
    pub role: EthereumStorageRoleV2,
    pub account_role: EthereumAccountRoleV2,
    pub storage_key: Hash32,
    /// Zero-valued Solidity slots are canonically absent from the MPT.
    pub present: bool,
    pub value_be: Hash32,
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Exact input to the pinned Sepolia verifier plus account/storage branches
/// under the execution state root that verifier derives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumUsddStateWitnessV2 {
    pub protocol_manifest: Vec<u8>,
    pub prior_controller_state: Vec<u8>,
    pub expected_finalized_state: Vec<u8>,
    pub finality_proof_cbor: Vec<u8>,
    pub account_proofs: Vec<EthereumAccountProofV2>,
    pub storage_proofs: Vec<EthereumStorageProofV2>,
}

/// Fixed output of the independent pinned-USDD/Sepolia source verifier. The
/// conversion guest recursively verifies the receipt before consuming these
/// values, avoiding any dependency rewrite between the frozen sha2 0.10.8
/// USDD graph and the existing sha2 0.10.9 ECX graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddEthereumSourcePublicValuesV2 {
    pub version: u8,
    pub frozen_configuration_commitment: Hash32,
    pub protocol_manifest_commitment: Hash32,
    pub update_proof_commitment: Hash32,
    pub prior_light_client_digest: Hash32,
    pub prior_finalized_beacon_slot: u64,
    pub prior_finalized_beacon_root: Hash32,
    pub prior_finalized_execution_state_root: Hash32,
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: Hash32,
    pub finalized_execution_block_hash: Hash32,
    pub finalized_execution_state_root: Hash32,
    pub execution_block_number: u64,
    pub execution_block_timestamp: u64,
    pub light_client_digest: Hash32,
    pub vault_liability_reserve_atoms: u128,
    pub reserve_balance_atoms: u128,
    pub quote_atoms_per_whole_reserve_token: u64,
    pub vault_pause_value: Hash32,
    pub vault_governance_value: Hash32,
}

impl UsddEthereumSourcePublicValuesV2 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2);
        out.push(self.version);
        out.extend_from_slice(&self.frozen_configuration_commitment);
        out.extend_from_slice(&self.protocol_manifest_commitment);
        out.extend_from_slice(&self.update_proof_commitment);
        out.extend_from_slice(&self.prior_light_client_digest);
        out.extend_from_slice(&self.prior_finalized_beacon_slot.to_be_bytes());
        out.extend_from_slice(&self.prior_finalized_beacon_root);
        out.extend_from_slice(&self.prior_finalized_execution_state_root);
        out.extend_from_slice(&self.finalized_beacon_slot.to_be_bytes());
        out.extend_from_slice(&self.finalized_beacon_root);
        out.extend_from_slice(&self.finalized_execution_block_hash);
        out.extend_from_slice(&self.finalized_execution_state_root);
        out.extend_from_slice(&self.execution_block_number.to_be_bytes());
        out.extend_from_slice(&self.execution_block_timestamp.to_be_bytes());
        out.extend_from_slice(&self.light_client_digest);
        out.extend_from_slice(&self.vault_liability_reserve_atoms.to_be_bytes());
        out.extend_from_slice(&self.reserve_balance_atoms.to_be_bytes());
        out.extend_from_slice(&self.quote_atoms_per_whole_reserve_token.to_be_bytes());
        out.extend_from_slice(&self.vault_pause_value);
        out.extend_from_slice(&self.vault_governance_value);
        debug_assert_eq!(out.len(), USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2);
        out
    }

    pub fn validate_shape(&self) -> Result<(), UsddUsdConversionErrorV2> {
        if self.version != USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2
            || self.prior_finalized_beacon_slot == 0
            || self.finalized_beacon_slot <= self.prior_finalized_beacon_slot
            || self.execution_block_number == 0
            || self.execution_block_timestamp == 0
            || self.quote_atoms_per_whole_reserve_token == 0
            || [
                self.frozen_configuration_commitment,
                self.protocol_manifest_commitment,
                self.update_proof_commitment,
                self.prior_light_client_digest,
                self.prior_finalized_beacon_root,
                self.prior_finalized_execution_state_root,
                self.finalized_beacon_root,
                self.finalized_execution_block_hash,
                self.finalized_execution_state_root,
                self.light_client_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(UsddUsdConversionErrorV2::InvalidEthereumState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddEthereumSourceReceiptV2 {
    pub public_values: UsddEthereumSourcePublicValuesV2,
    pub proof_marker: Vec<u8>,
}

/// Fixed public statement of the independent Elements/BMM source verifier.
/// It must be recursively verified; equality with these bytes alone is never
/// authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsSourcePublicValuesV2 {
    pub version: u8,
    pub observed_parent_block_hash: Hash32,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub bitcoin_bmm_history_root: Hash32,
    pub elements_genesis_hash: Hash32,
    pub elements_tip_hash: Hash32,
    pub elements_height: u64,
    pub elements_source_configuration_commitment: Hash32,
    pub elements_source_bootstrap_commitment: Hash32,
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
}

impl UsddElementsSourcePublicValuesV2 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2);
        out.push(self.version);
        out.extend_from_slice(&self.observed_parent_block_hash);
        out.extend_from_slice(&self.observed_parent_height.to_be_bytes());
        out.extend_from_slice(&self.observed_parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.bitcoin_bmm_history_root);
        out.extend_from_slice(&self.elements_genesis_hash);
        out.extend_from_slice(&self.elements_tip_hash);
        out.extend_from_slice(&self.elements_height.to_be_bytes());
        out.extend_from_slice(&self.elements_source_configuration_commitment);
        out.extend_from_slice(&self.elements_source_bootstrap_commitment);
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
        debug_assert_eq!(out.len(), USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2);
        out
    }

    pub fn validate_shape(&self) -> Result<(), UsddUsdConversionErrorV2> {
        if self.version != USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2
            || self.observed_parent_height == 0
            || self.observed_parent_mtp == 0
            || self.elements_height == 0
            || self.checkpoint_sequence == 0
            || self.prior_checkpoint_sequence.checked_add(1) != Some(self.checkpoint_sequence)
            || self.checkpoint_finalized_beacon_slot == 0
            || self.prior_checkpoint_finalized_beacon_slot == 0
            || self.checkpoint_execution_block_number == 0
            || self.checkpoint_execution_timestamp == 0
            || self.checkpoint_accepted_parent_mtp == 0
            || self.outstanding_usdd_atoms == 0
            || [
                self.observed_parent_block_hash,
                self.bitcoin_bmm_history_root,
                self.elements_genesis_hash,
                self.elements_tip_hash,
                self.elements_source_configuration_commitment,
                self.elements_source_bootstrap_commitment,
                self.usdd_checkpoint_configuration_hash,
                self.current_checkpoint_commitment,
                self.prior_checkpoint_commitment,
                self.prior_checkpoint_light_client_digest,
                self.prior_checkpoint_finalized_beacon_root,
                self.prior_checkpoint_execution_state_root,
                self.checkpoint_light_client_digest,
                self.checkpoint_finalized_beacon_root,
                self.checkpoint_execution_block_hash,
                self.checkpoint_execution_state_root,
                self.checkpoint_update_proof_commitment,
                self.usdd_asset_id,
                self.redemption_covenant_commitment,
                self.elements_consensus_state_root,
            ]
            .contains(&[0; 32])
        {
            return Err(UsddUsdConversionErrorV2::InvalidElementsPublicValues);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsSourceReceiptV2 {
    pub public_values: UsddElementsSourcePublicValuesV2,
    /// Canonical SP1 deferred-proof marker.  The full compressed receipt is a
    /// separate content-addressed input to the prover, as in the outer V2
    /// transition proof.
    pub proof_marker: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddUsdConversionInputV2 {
    pub version: u8,
    pub frozen_configuration: FrozenUsddUsdConfigurationV2,
    pub public_values: ConversionLegPublicValuesV2,
    pub ethereum_receipt: UsddEthereumSourceReceiptV2,
    pub elements_receipt: UsddElementsSourceReceiptV2,
    pub redemption_covenant_preimage: Vec<u8>,
    pub usd_redemption_definition_preimage: Vec<u8>,
}

impl UsddUsdConversionInputV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UsddUsdConversionErrorV2> {
        let encoded = canonical_encode(self)?;
        if encoded.len() > MAX_USDD_USD_CONVERSION_INPUT_BYTES_V2 {
            return Err(UsddUsdConversionErrorV2::ResourceLimit);
        }
        Ok(encoded)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, UsddUsdConversionErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_USDD_USD_CONVERSION_INPUT_BYTES_V2 {
            return Err(UsddUsdConversionErrorV2::ResourceLimit);
        }
        let value: Self = canonical_options()
            .deserialize(bytes)
            .map_err(|_| UsddUsdConversionErrorV2::NonCanonicalEncoding)?;
        if value.canonical_bytes()? != bytes {
            return Err(UsddUsdConversionErrorV2::NonCanonicalEncoding);
        }
        value.validate_envelope()?;
        Ok(value)
    }

    pub fn validate_envelope(&self) -> Result<(), UsddUsdConversionErrorV2> {
        if self.version != USDD_USD_CONVERSION_INPUT_VERSION_V2
            || self.public_values.kind != ConversionLegKindV2::UsddUsd
            || self.public_values.version != 2
            || self.elements_receipt.proof_marker.len() != 32
            || self.redemption_covenant_preimage.is_empty()
            || self.redemption_covenant_preimage.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
            || self.usd_redemption_definition_preimage.is_empty()
            || self.usd_redemption_definition_preimage.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
            || self.ethereum_receipt.proof_marker.len() != 32
        {
            return Err(UsddUsdConversionErrorV2::InvalidEnvelope);
        }
        self.frozen_configuration.validate()?;
        self.ethereum_receipt.public_values.validate_shape()?;
        self.elements_receipt.public_values.validate_shape()?;
        Ok(())
    }
}

pub trait UsddUsdEthereumVerifierV2 {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), UsddUsdConversionErrorV2>;
}

pub trait UsddElementsSourceVerifierV2 {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), UsddUsdConversionErrorV2>;
}

/// Execute the complete deterministic relation.  Public values are returned
/// only after both independent source verifiers authorize their inputs.
pub fn execute_usdd_usd_conversion_v2<E, L>(
    input: &UsddUsdConversionInputV2,
    ethereum_verifier: &E,
    elements_verifier: &L,
) -> Result<Vec<u8>, UsddUsdConversionErrorV2>
where
    E: UsddUsdEthereumVerifierV2,
    L: UsddElementsSourceVerifierV2,
{
    input.validate_envelope()?;
    let config = &input.frozen_configuration;
    let public = &input.public_values;
    let ethereum = &input.ethereum_receipt.public_values;
    let elements = &input.elements_receipt.public_values;
    let frozen_configuration_commitment = config.commitment()?;

    if tagged_hash(
        "ECX/usdd-usd-redemption-covenant/v2",
        &input.redemption_covenant_preimage,
    ) != config.redemption_covenant_commitment
        || tagged_hash(
            "ECX/usdd-usd-redemption-definition/v2",
            &input.usd_redemption_definition_preimage,
        ) != config.usd_redemption_definition_commitment
        || ethereum.frozen_configuration_commitment
            != config.ethereum_source_configuration_commitment()
        || ethereum.protocol_manifest_commitment != config.protocol_manifest_commitment
        || frozen_configuration_commitment != public.source_checkpoint_commitment
    {
        return Err(UsddUsdConversionErrorV2::FrozenCommitmentMismatch);
    }

    ethereum_verifier.verify(
        config.ethereum_source_program_id,
        &ethereum.canonical_bytes(),
        &input.ethereum_receipt.proof_marker,
    )?;
    elements_verifier.verify(
        config.elements_source_program_id,
        &elements.canonical_bytes(),
        &input.elements_receipt.proof_marker,
    )?;
    let checkpoint_configuration = config.checkpoint_configuration();
    let checkpoint_configuration_hash = checkpoint_configuration.digest();
    let checkpoint = UsddEthereumCheckpointV1 {
        version: UsddEthereumCheckpointV1::VERSION,
        configuration_hash: checkpoint_configuration_hash,
        sequence: elements.checkpoint_sequence,
        light_client_digest: elements.checkpoint_light_client_digest,
        finalized_beacon_slot: elements.checkpoint_finalized_beacon_slot,
        finalized_beacon_root: elements.checkpoint_finalized_beacon_root,
        finalized_execution_block_hash: elements.checkpoint_execution_block_hash,
        finalized_execution_state_root: elements.checkpoint_execution_state_root,
        finalized_execution_block_number: elements.checkpoint_execution_block_number,
        finalized_execution_timestamp: elements.checkpoint_execution_timestamp,
        accepted_parent_mtp: elements.checkpoint_accepted_parent_mtp,
        prior_checkpoint_commitment: elements.prior_checkpoint_commitment,
        update_proof_commitment: elements.checkpoint_update_proof_commitment,
    };
    checkpoint
        .validate(&checkpoint_configuration)
        .map_err(|_| UsddUsdConversionErrorV2::InvalidElementsPublicValues)?;

    if elements.elements_genesis_hash != config.elements_genesis_hash
        || elements.elements_source_configuration_commitment
            != config.elements_source_configuration_commitment
        || elements.elements_source_bootstrap_commitment
            != config.elements_source_bootstrap_commitment
        || elements.usdd_checkpoint_configuration_hash != checkpoint_configuration_hash
        || elements.checkpoint_update_proof_commitment != ethereum.update_proof_commitment
        || elements.current_checkpoint_commitment != checkpoint.commitment()
        || elements.checkpoint_accepted_parent_mtp > elements.observed_parent_mtp
        || elements.usdd_asset_id != config.usdd_asset_id
        || elements.redemption_covenant_commitment != config.redemption_covenant_commitment
        || !elements.redemption_covenant_live
        || elements.checkpoint_finalized_beacon_slot != ethereum.finalized_beacon_slot
        || elements.checkpoint_finalized_beacon_root != ethereum.finalized_beacon_root
        || elements.checkpoint_execution_block_hash != ethereum.finalized_execution_block_hash
        || elements.checkpoint_execution_state_root != ethereum.finalized_execution_state_root
        || elements.checkpoint_execution_block_number != ethereum.execution_block_number
        || elements.checkpoint_execution_timestamp != ethereum.execution_block_timestamp
        || elements.checkpoint_light_client_digest != ethereum.light_client_digest
        || elements.prior_checkpoint_light_client_digest != ethereum.prior_light_client_digest
        || elements.prior_checkpoint_finalized_beacon_slot != ethereum.prior_finalized_beacon_slot
        || elements.prior_checkpoint_finalized_beacon_root != ethereum.prior_finalized_beacon_root
        || elements.prior_checkpoint_execution_state_root
            != ethereum.prior_finalized_execution_state_root
        || ethereum.vault_pause_value != config.redemption_enabled_pause_value
        || ethereum.vault_governance_value != config.governance_locked_value
    {
        return Err(UsddUsdConversionErrorV2::CrossChainBindingMismatch);
    }

    let quote_per_base_numerator = u128::from(config.reserve_token_atoms_redeemable_per_whole_usdd)
        .checked_mul(u128::from(ethereum.quote_atoms_per_whole_reserve_token))
        .ok_or(UsddUsdConversionErrorV2::ArithmeticOverflow)?;
    let reserve_denominator = u128::from(config.reserve_token_atoms_per_whole);
    if quote_per_base_numerator % reserve_denominator != 0 {
        return Err(UsddUsdConversionErrorV2::InexactRedemptionScale);
    }
    let quote_atoms_per_whole_base = u64::try_from(quote_per_base_numerator / reserve_denominator)
        .map_err(|_| UsddUsdConversionErrorV2::ArithmeticOverflow)?;
    if ethereum.quote_atoms_per_whole_reserve_token
        != config.expected_quote_atoms_per_whole_reserve_token
    {
        return Err(UsddUsdConversionErrorV2::UsdQuoteMismatch);
    }

    let required_reserve_atoms = ceil_div(
        elements
            .outstanding_usdd_atoms
            .checked_mul(u128::from(
                config.reserve_token_atoms_redeemable_per_whole_usdd,
            ))
            .ok_or(UsddUsdConversionErrorV2::ArithmeticOverflow)?,
        u128::from(PRICE_SCALE),
    )?;
    if ethereum.vault_liability_reserve_atoms < required_reserve_atoms
        || ethereum.reserve_balance_atoms < ethereum.vault_liability_reserve_atoms
    {
        return Err(UsddUsdConversionErrorV2::ReserveShortfall);
    }
    let reserve_quote_atoms = ethereum
        .reserve_balance_atoms
        .checked_mul(u128::from(ethereum.quote_atoms_per_whole_reserve_token))
        .ok_or(UsddUsdConversionErrorV2::ArithmeticOverflow)?
        / reserve_denominator;

    let valid_until = ethereum
        .execution_block_timestamp
        .checked_add(config.maximum_age_seconds)
        .ok_or(UsddUsdConversionErrorV2::ArithmeticOverflow)?;
    let source_state_root = usdd_usd_source_state_root_v2(elements, ethereum);
    if public.observed_parent_block_hash != elements.observed_parent_block_hash
        || public.observed_parent_height != elements.observed_parent_height
        || public.observed_parent_mtp != elements.observed_parent_mtp
        || ethereum.execution_block_timestamp > elements.observed_parent_mtp
        || elements
            .observed_parent_mtp
            .saturating_sub(ethereum.execution_block_timestamp)
            > config.maximum_age_seconds
        || public.source_height != ethereum.execution_block_number
        || public.source_mtp != ethereum.execution_block_timestamp
        || public.valid_until_mtp != valid_until
        || public.base_asset_id != config.usdd_asset_id
        || public.quote_unit_id != config.ethereum_light_client_configuration_hash
        || public.redemption_covenant_commitment != config.redemption_covenant_commitment
        || public.source_state_root != source_state_root
        || public.quote_atoms_per_whole_base != quote_atoms_per_whole_base
        || public.outstanding_base_atoms != elements.outstanding_usdd_atoms
        || public.redeemable_reserve_quote_atoms != reserve_quote_atoms
        || !public.redemption_enabled
    {
        return Err(UsddUsdConversionErrorV2::PublicValuesMismatch);
    }
    Ok(public.canonical_bytes())
}

pub fn usdd_usd_source_state_root_v2(
    elements: &UsddElementsSourcePublicValuesV2,
    ethereum: &UsddEthereumSourcePublicValuesV2,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(240);
    bytes.extend_from_slice(&elements.elements_consensus_state_root);
    bytes.extend_from_slice(&elements.current_checkpoint_commitment);
    bytes.extend_from_slice(&ethereum.finalized_execution_state_root);
    bytes.extend_from_slice(&ethereum.finalized_beacon_root);
    bytes.extend_from_slice(&ethereum.light_client_digest);
    bytes.extend_from_slice(&ethereum.vault_liability_reserve_atoms.to_be_bytes());
    bytes.extend_from_slice(&ethereum.reserve_balance_atoms.to_be_bytes());
    bytes.extend_from_slice(&ethereum.quote_atoms_per_whole_reserve_token.to_be_bytes());
    bytes.extend_from_slice(&ethereum.vault_pause_value);
    bytes.extend_from_slice(&ethereum.vault_governance_value);
    tagged_hash("ECX/usdd-usd-source-state/v2", &bytes)
}

/// Commitment carried by `UsddEthereumCheckpointV1::update_proof_commitment`.
/// The length prefixes make the three strict upstream codecs unambiguous and
/// prevent a host from rebinding the same bytes across field boundaries.
pub fn usdd_finality_update_proof_commitment_v2(
    witness: &EthereumUsddStateWitnessV2,
) -> Result<Hash32, UsddUsdConversionErrorV2> {
    let fields = [
        witness.prior_controller_state.as_slice(),
        witness.expected_finalized_state.as_slice(),
        witness.finality_proof_cbor.as_slice(),
    ];
    let mut bytes = Vec::new();
    for field in fields {
        if field.is_empty() || field.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2 {
            return Err(UsddUsdConversionErrorV2::ResourceLimit);
        }
        bytes.extend_from_slice(
            &u64::try_from(field.len())
                .map_err(|_| UsddUsdConversionErrorV2::ResourceLimit)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    Ok(tagged_hash(
        "ECX/usdd-sepolia-finality-update-proof/v2",
        &bytes,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UsddUsdConversionErrorV2 {
    #[error("USDD/USD witness encoding is noncanonical")]
    NonCanonicalEncoding,
    #[error("USDD/USD witness exceeds a frozen resource bound")]
    ResourceLimit,
    #[error("USDD/USD witness envelope is incomplete or malformed")]
    InvalidEnvelope,
    #[error("USDD/USD frozen configuration is invalid")]
    InvalidFrozenConfiguration,
    #[error("USDD/USD Ethereum account/storage proof roles are not exact")]
    InvalidEthereumProofRoles,
    #[error("USDD/USD Ethereum state or MPT proof was rejected")]
    InvalidEthereumState,
    #[error("USDD/USD Sepolia finality proof was rejected")]
    EthereumFinalityRejected,
    #[error("USDD Elements/BMM source public values are malformed")]
    InvalidElementsPublicValues,
    #[error("USDD Elements/BMM recursive proof was rejected")]
    ElementsReceiptRejected,
    #[error("a deployment-frozen USDD/USD commitment did not match")]
    FrozenCommitmentMismatch,
    #[error("Ethereum finality and the BMM-authenticated Elements checkpoint disagree")]
    CrossChainBindingMismatch,
    #[error("the USD quote storage proof does not match the frozen quote")]
    UsdQuoteMismatch,
    #[error("USDD redemption conversion has a non-integral frozen scale")]
    InexactRedemptionScale,
    #[error("authenticated reserve or liability is insufficient")]
    ReserveShortfall,
    #[error("USDD/USD public values were not derived exactly from authenticated state")]
    PublicValuesMismatch,
    #[error("USDD/USD conversion arithmetic overflow")]
    ArithmeticOverflow,
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_USDD_USD_CONVERSION_INPUT_BYTES_V2 as u64)
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, UsddUsdConversionErrorV2> {
    canonical_options()
        .serialize(value)
        .map_err(|_| UsddUsdConversionErrorV2::NonCanonicalEncoding)
}

fn ceil_div(value: u128, denominator: u128) -> Result<u128, UsddUsdConversionErrorV2> {
    value
        .checked_add(denominator - 1)
        .ok_or(UsddUsdConversionErrorV2::ArithmeticOverflow)
        .map(|sum| sum / denominator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_public_values_length_is_frozen() {
        let mut value = empty_elements();
        value.redemption_covenant_live = true;
        assert_eq!(
            value.canonical_bytes().len(),
            USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2
        );
    }

    #[test]
    fn canonical_codec_rejects_trailing_bytes() {
        let input = empty_input();
        let mut encoded = input.canonical_bytes().unwrap();
        encoded.push(0);
        assert_eq!(
            UsddUsdConversionInputV2::decode_canonical(&encoded),
            Err(UsddUsdConversionErrorV2::NonCanonicalEncoding)
        );
    }

    #[test]
    fn empty_witness_fails_before_any_source_verifier() {
        let input = empty_input();
        assert!(matches!(
            input.validate_envelope(),
            Err(UsddUsdConversionErrorV2::InvalidEnvelope)
                | Err(UsddUsdConversionErrorV2::InvalidFrozenConfiguration)
        ));
    }

    #[test]
    fn fully_authenticated_relation_derives_exact_public_values() {
        let input = valid_input();
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements).unwrap(),
            input.public_values.canonical_bytes()
        );
        let encoded = input.canonical_bytes().unwrap();
        assert_eq!(
            UsddUsdConversionInputV2::decode_canonical(&encoded).unwrap(),
            input
        );
    }

    #[test]
    fn forged_elements_receipt_and_checkpoint_substitution_reject() {
        let mut input = valid_input();
        input.elements_receipt.proof_marker[0] ^= 1;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::ElementsReceiptRejected)
        );

        let mut input = valid_input();
        input
            .elements_receipt
            .public_values
            .checkpoint_execution_state_root[0] ^= 1;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::CrossChainBindingMismatch)
        );
    }

    #[test]
    fn stale_under_reserved_paused_and_governed_states_reject() {
        let mut input = valid_input();
        input.elements_receipt.public_values.observed_parent_mtp = input
            .ethereum_receipt
            .public_values
            .execution_block_timestamp
            + input.frozen_configuration.maximum_age_seconds
            + 1;
        input.public_values.observed_parent_mtp =
            input.elements_receipt.public_values.observed_parent_mtp;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::PublicValuesMismatch)
        );

        let mut input = valid_input();
        input.ethereum_receipt.public_values.reserve_balance_atoms = input
            .ethereum_receipt
            .public_values
            .vault_liability_reserve_atoms
            - 1;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::ReserveShortfall)
        );

        let mut input = valid_input();
        input.ethereum_receipt.public_values.vault_pause_value = [1; 32];
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::CrossChainBindingMismatch)
        );

        let mut input = valid_input();
        input.ethereum_receipt.public_values.vault_governance_value = [1; 32];
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::CrossChainBindingMismatch)
        );
    }

    #[test]
    fn public_summary_or_source_receipt_substitution_cannot_authorize() {
        let mut input = valid_input();
        input.public_values.redeemable_reserve_quote_atoms -= 1;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::PublicValuesMismatch)
        );

        let mut input = valid_input();
        input.ethereum_receipt.proof_marker[0] ^= 1;
        assert_eq!(
            execute_usdd_usd_conversion_v2(&input, &MockEthereum, &MockElements),
            Err(UsddUsdConversionErrorV2::EthereumFinalityRejected)
        );
    }

    struct MockEthereum;

    impl UsddUsdEthereumVerifierV2 for MockEthereum {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), UsddUsdConversionErrorV2> {
            if program_id == [5; 32]
                && public_values.len() == USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2
                && proof_marker == [10; 32]
            {
                Ok(())
            } else {
                Err(UsddUsdConversionErrorV2::EthereumFinalityRejected)
            }
        }
    }

    struct MockElements;

    impl UsddElementsSourceVerifierV2 for MockElements {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), UsddUsdConversionErrorV2> {
            if program_id == [7; 32]
                && public_values.len() == USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_LEN_V2
                && proof_marker == [9; 32]
            {
                Ok(())
            } else {
                Err(UsddUsdConversionErrorV2::ElementsReceiptRejected)
            }
        }
    }

    fn valid_input() -> UsddUsdConversionInputV2 {
        let manifest = b"canonical-pinned-USDD-manifest".to_vec();
        let covenant = b"reviewed-redemption-covenant".to_vec();
        let definition = b"reviewed-USD-redemption-definition".to_vec();
        let config = FrozenUsddUsdConfigurationV2 {
            version: USDD_USD_FROZEN_CONFIGURATION_VERSION_V2,
            ethereum_chain_id: 11_155_111,
            ethereum_light_client_configuration_hash: tagged_hash(
                "ECX/usdd-sepolia-light-client-configuration/v2",
                &manifest,
            ),
            protocol_manifest_commitment: tagged_hash(
                "ECX/usdd-usd-protocol-manifest/v2",
                &manifest,
            ),
            usdd_asset_id: [3; 32],
            elements_genesis_hash: [4; 32],
            ethereum_source_program_id: [5; 32],
            elements_source_program_id: [7; 32],
            elements_source_configuration_commitment: [8; 32],
            elements_source_bootstrap_commitment: [9; 32],
            usdd_checkpoint_authority_configuration_hash: [6; 32],
            redemption_covenant_commitment: tagged_hash(
                "ECX/usdd-usd-redemption-covenant/v2",
                &covenant,
            ),
            usd_redemption_definition_commitment: tagged_hash(
                "ECX/usdd-usd-redemption-definition/v2",
                &definition,
            ),
            vault_address: [10; 20],
            vault_runtime_code_hash: [11; 32],
            reserve_token_address: [12; 20],
            reserve_token_runtime_code_hash: [13; 32],
            price_contract_address: [14; 20],
            price_contract_runtime_code_hash: [15; 32],
            vault_liability_storage_key: [16; 32],
            vault_pause_storage_key: [17; 32],
            vault_governance_storage_key: [18; 32],
            redemption_enabled_pause_value: [0; 32],
            governance_locked_value: [0; 32],
            reserve_balance_mapping_slot: [19; 32],
            price_storage_key: [20; 32],
            reserve_token_atoms_per_whole: 1_000_000,
            reserve_token_atoms_redeemable_per_whole_usdd: 1_000_000,
            expected_quote_atoms_per_whole_reserve_token: PRICE_SCALE,
            maximum_age_seconds: 600,
        };
        let ethereum = UsddEthereumSourcePublicValuesV2 {
            version: USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2,
            frozen_configuration_commitment: config.ethereum_source_configuration_commitment(),
            protocol_manifest_commitment: config.protocol_manifest_commitment,
            update_proof_commitment: [28; 32],
            prior_light_client_digest: [21; 32],
            prior_finalized_beacon_slot: 9_968,
            prior_finalized_beacon_root: [22; 32],
            prior_finalized_execution_state_root: [23; 32],
            finalized_beacon_slot: 10_000,
            finalized_beacon_root: [24; 32],
            finalized_execution_block_hash: [25; 32],
            finalized_execution_state_root: [26; 32],
            execution_block_number: 20_000_000,
            execution_block_timestamp: 1_800_000_000,
            light_client_digest: [27; 32],
            vault_liability_reserve_atoms: 1_000_000,
            reserve_balance_atoms: 2_000_000,
            quote_atoms_per_whole_reserve_token: PRICE_SCALE,
            vault_pause_value: config.redemption_enabled_pause_value,
            vault_governance_value: config.governance_locked_value,
        };
        let mut elements = UsddElementsSourcePublicValuesV2 {
            version: USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2,
            observed_parent_block_hash: [30; 32],
            observed_parent_height: 900_000,
            observed_parent_mtp: ethereum.execution_block_timestamp + 60,
            bitcoin_bmm_history_root: [31; 32],
            elements_genesis_hash: config.elements_genesis_hash,
            elements_tip_hash: [32; 32],
            elements_height: 50_000,
            elements_source_configuration_commitment: config
                .elements_source_configuration_commitment,
            elements_source_bootstrap_commitment: config.elements_source_bootstrap_commitment,
            usdd_checkpoint_configuration_hash: config.checkpoint_configuration().digest(),
            prior_checkpoint_commitment: [33; 32],
            prior_checkpoint_sequence: 1,
            prior_checkpoint_light_client_digest: ethereum.prior_light_client_digest,
            prior_checkpoint_finalized_beacon_slot: ethereum.prior_finalized_beacon_slot,
            prior_checkpoint_finalized_beacon_root: ethereum.prior_finalized_beacon_root,
            prior_checkpoint_execution_state_root: ethereum.prior_finalized_execution_state_root,
            current_checkpoint_commitment: [34; 32],
            checkpoint_sequence: 2,
            checkpoint_light_client_digest: ethereum.light_client_digest,
            checkpoint_finalized_beacon_slot: ethereum.finalized_beacon_slot,
            checkpoint_finalized_beacon_root: ethereum.finalized_beacon_root,
            checkpoint_execution_block_hash: ethereum.finalized_execution_block_hash,
            checkpoint_execution_state_root: ethereum.finalized_execution_state_root,
            checkpoint_execution_block_number: ethereum.execution_block_number,
            checkpoint_execution_timestamp: ethereum.execution_block_timestamp,
            checkpoint_accepted_parent_mtp: ethereum.execution_block_timestamp + 30,
            checkpoint_update_proof_commitment: ethereum.update_proof_commitment,
            usdd_asset_id: config.usdd_asset_id,
            outstanding_usdd_atoms: u128::from(PRICE_SCALE),
            redemption_covenant_commitment: config.redemption_covenant_commitment,
            redemption_covenant_live: true,
            elements_consensus_state_root: [35; 32],
        };
        let checkpoint = UsddEthereumCheckpointV1 {
            version: UsddEthereumCheckpointV1::VERSION,
            configuration_hash: elements.usdd_checkpoint_configuration_hash,
            sequence: elements.checkpoint_sequence,
            light_client_digest: elements.checkpoint_light_client_digest,
            finalized_beacon_slot: elements.checkpoint_finalized_beacon_slot,
            finalized_beacon_root: elements.checkpoint_finalized_beacon_root,
            finalized_execution_block_hash: elements.checkpoint_execution_block_hash,
            finalized_execution_state_root: elements.checkpoint_execution_state_root,
            finalized_execution_block_number: elements.checkpoint_execution_block_number,
            finalized_execution_timestamp: elements.checkpoint_execution_timestamp,
            accepted_parent_mtp: elements.checkpoint_accepted_parent_mtp,
            prior_checkpoint_commitment: elements.prior_checkpoint_commitment,
            update_proof_commitment: elements.checkpoint_update_proof_commitment,
        };
        elements.current_checkpoint_commitment = checkpoint.commitment();
        let source_state_root = usdd_usd_source_state_root_v2(&elements, &ethereum);
        let public_values = ConversionLegPublicValuesV2 {
            version: 2,
            kind: ConversionLegKindV2::UsddUsd,
            observed_parent_block_hash: elements.observed_parent_block_hash,
            observed_parent_height: elements.observed_parent_height,
            observed_parent_mtp: elements.observed_parent_mtp,
            source_height: ethereum.execution_block_number,
            source_mtp: ethereum.execution_block_timestamp,
            valid_until_mtp: ethereum.execution_block_timestamp + config.maximum_age_seconds,
            base_asset_id: config.usdd_asset_id,
            quote_unit_id: config.ethereum_light_client_configuration_hash,
            redemption_covenant_commitment: config.redemption_covenant_commitment,
            source_checkpoint_commitment: config.commitment().unwrap(),
            source_state_root,
            quote_atoms_per_whole_base: PRICE_SCALE,
            outstanding_base_atoms: elements.outstanding_usdd_atoms,
            redeemable_reserve_quote_atoms: 2 * u128::from(PRICE_SCALE),
            redemption_enabled: true,
        };
        UsddUsdConversionInputV2 {
            version: USDD_USD_CONVERSION_INPUT_VERSION_V2,
            frozen_configuration: config,
            public_values,
            ethereum_receipt: UsddEthereumSourceReceiptV2 {
                public_values: ethereum,
                proof_marker: vec![10; 32],
            },
            elements_receipt: UsddElementsSourceReceiptV2 {
                public_values: elements,
                proof_marker: vec![9; 32],
            },
            redemption_covenant_preimage: covenant,
            usd_redemption_definition_preimage: definition,
        }
    }

    fn empty_input() -> UsddUsdConversionInputV2 {
        UsddUsdConversionInputV2 {
            version: USDD_USD_CONVERSION_INPUT_VERSION_V2,
            frozen_configuration: FrozenUsddUsdConfigurationV2 {
                version: USDD_USD_FROZEN_CONFIGURATION_VERSION_V2,
                ethereum_chain_id: 0,
                ethereum_light_client_configuration_hash: [0; 32],
                protocol_manifest_commitment: [0; 32],
                usdd_asset_id: [0; 32],
                elements_genesis_hash: [0; 32],
                ethereum_source_program_id: [0; 32],
                elements_source_program_id: [0; 32],
                elements_source_configuration_commitment: [0; 32],
                elements_source_bootstrap_commitment: [0; 32],
                usdd_checkpoint_authority_configuration_hash: [0; 32],
                redemption_covenant_commitment: [0; 32],
                usd_redemption_definition_commitment: [0; 32],
                vault_address: [0; 20],
                vault_runtime_code_hash: [0; 32],
                reserve_token_address: [0; 20],
                reserve_token_runtime_code_hash: [0; 32],
                price_contract_address: [0; 20],
                price_contract_runtime_code_hash: [0; 32],
                vault_liability_storage_key: [0; 32],
                vault_pause_storage_key: [0; 32],
                vault_governance_storage_key: [0; 32],
                redemption_enabled_pause_value: [0; 32],
                governance_locked_value: [0; 32],
                reserve_balance_mapping_slot: [0; 32],
                price_storage_key: [0; 32],
                reserve_token_atoms_per_whole: 0,
                reserve_token_atoms_redeemable_per_whole_usdd: 0,
                expected_quote_atoms_per_whole_reserve_token: 0,
                maximum_age_seconds: 0,
            },
            public_values: ConversionLegPublicValuesV2 {
                version: 2,
                kind: ConversionLegKindV2::UsddUsd,
                observed_parent_block_hash: [0; 32],
                observed_parent_height: 0,
                observed_parent_mtp: 0,
                source_height: 0,
                source_mtp: 0,
                valid_until_mtp: 0,
                base_asset_id: [0; 32],
                quote_unit_id: [0; 32],
                redemption_covenant_commitment: [0; 32],
                source_checkpoint_commitment: [0; 32],
                source_state_root: [0; 32],
                quote_atoms_per_whole_base: 0,
                outstanding_base_atoms: 0,
                redeemable_reserve_quote_atoms: 0,
                redemption_enabled: false,
            },
            ethereum_receipt: UsddEthereumSourceReceiptV2 {
                public_values: empty_ethereum(),
                proof_marker: vec![],
            },
            elements_receipt: UsddElementsSourceReceiptV2 {
                public_values: empty_elements(),
                proof_marker: vec![],
            },
            redemption_covenant_preimage: vec![],
            usd_redemption_definition_preimage: vec![],
        }
    }

    fn empty_ethereum() -> UsddEthereumSourcePublicValuesV2 {
        UsddEthereumSourcePublicValuesV2 {
            version: USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2,
            frozen_configuration_commitment: [0; 32],
            protocol_manifest_commitment: [0; 32],
            update_proof_commitment: [0; 32],
            prior_light_client_digest: [0; 32],
            prior_finalized_beacon_slot: 0,
            prior_finalized_beacon_root: [0; 32],
            prior_finalized_execution_state_root: [0; 32],
            finalized_beacon_slot: 0,
            finalized_beacon_root: [0; 32],
            finalized_execution_block_hash: [0; 32],
            finalized_execution_state_root: [0; 32],
            execution_block_number: 0,
            execution_block_timestamp: 0,
            light_client_digest: [0; 32],
            vault_liability_reserve_atoms: 0,
            reserve_balance_atoms: 0,
            quote_atoms_per_whole_reserve_token: 0,
            vault_pause_value: [0; 32],
            vault_governance_value: [0; 32],
        }
    }

    fn empty_elements() -> UsddElementsSourcePublicValuesV2 {
        UsddElementsSourcePublicValuesV2 {
            version: USDD_ELEMENTS_SOURCE_PUBLIC_VALUES_VERSION_V2,
            observed_parent_block_hash: [0; 32],
            observed_parent_height: 0,
            observed_parent_mtp: 0,
            bitcoin_bmm_history_root: [0; 32],
            elements_genesis_hash: [0; 32],
            elements_tip_hash: [0; 32],
            elements_height: 0,
            elements_source_configuration_commitment: [0; 32],
            elements_source_bootstrap_commitment: [0; 32],
            usdd_checkpoint_configuration_hash: [0; 32],
            prior_checkpoint_commitment: [0; 32],
            prior_checkpoint_sequence: 0,
            prior_checkpoint_light_client_digest: [0; 32],
            prior_checkpoint_finalized_beacon_slot: 0,
            prior_checkpoint_finalized_beacon_root: [0; 32],
            prior_checkpoint_execution_state_root: [0; 32],
            current_checkpoint_commitment: [0; 32],
            checkpoint_sequence: 0,
            checkpoint_light_client_digest: [0; 32],
            checkpoint_finalized_beacon_slot: 0,
            checkpoint_finalized_beacon_root: [0; 32],
            checkpoint_execution_block_hash: [0; 32],
            checkpoint_execution_state_root: [0; 32],
            checkpoint_execution_block_number: 0,
            checkpoint_execution_timestamp: 0,
            checkpoint_accepted_parent_mtp: 0,
            checkpoint_update_proof_commitment: [0; 32],
            usdd_asset_id: [0; 32],
            outstanding_usdd_atoms: 0,
            redemption_covenant_commitment: [0; 32],
            redemption_covenant_live: false,
            elements_consensus_state_root: [0; 32],
        }
    }
}
