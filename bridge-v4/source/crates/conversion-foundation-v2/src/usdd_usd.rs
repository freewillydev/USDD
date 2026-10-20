//! Generic Ethereum MPT verification used by the USDD/USD conversion guest.
//!
//! The algorithms and dependency versions are the same `alloy-trie` family
//! used by the provenance-pinned USDD deposit verifier.  These helpers do not
//! assign protocol meaning to addresses or slots; the conversion relation must
//! compare every address, code hash, storage key and value role with its frozen
//! configuration.

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::{proof, Nibbles, TrieAccount};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use usdd_core::{CanonicalDecode, ProtocolManifest};

use crate::{
    verify_sepolia_finality_foundation, SepoliaFinalityFoundationWitness,
    VerifiedSepoliaFinalityFoundation,
};

pub const MAX_MPT_PROOF_NODES_V2: usize = 65;
pub const MAX_MPT_NODE_BYTES_V2: usize = 4_096;
pub const MAX_MPT_WITNESS_BYTES_V2: usize = 4 * 1024 * 1024;
pub const USDD_USD_ETHEREUM_SOURCE_INPUT_VERSION_V2: u8 = 1;
pub const USDD_USD_FROZEN_CONFIGURATION_VERSION_V2: u8 = 1;
pub const USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_LEN_V2: usize = 457;
pub const MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2: usize = 32 * 1024 * 1024;
pub const MAX_USDD_USD_PREIMAGE_BYTES_V2: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedUsddManifestIdentityV2 {
    pub ethereum_chain_id: u64,
    pub ethereum_light_client_configuration_hash: [u8; 32],
    pub vault_address: [u8; 20],
    pub reserve_token_address: [u8; 20],
    pub usdd_asset_id: [u8; 32],
    pub elements_genesis_hash: [u8; 32],
    pub vault_runtime_code_hash: [u8; 32],
}

pub fn verify_usdd_manifest_identity_v2(
    canonical_manifest: &[u8],
) -> Result<VerifiedUsddManifestIdentityV2, EthereumMptErrorV2> {
    let manifest = ProtocolManifest::decode_exact(canonical_manifest)
        .map_err(|_| EthereumMptErrorV2::InvalidManifest)?;
    manifest
        .validate()
        .map_err(|_| EthereumMptErrorV2::InvalidManifest)?;
    Ok(VerifiedUsddManifestIdentityV2 {
        ethereum_chain_id: manifest.ethereum_chain_id,
        ethereum_light_client_configuration_hash: manifest.controller_configuration_hash.0,
        vault_address: manifest.vault.0,
        reserve_token_address: manifest.usdt.0,
        usdd_asset_id: manifest.usdd_asset.0,
        elements_genesis_hash: manifest.elements_genesis.0,
        vault_runtime_code_hash: manifest.vault_code_hash.0,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumAccountMptWitnessV2 {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance_be: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
    pub proof_nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEthereumAccountV2 {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance_be: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumStorageMptWitnessV2 {
    pub storage_key: [u8; 32],
    /// Solidity removes zero values from its storage trie.  `false` therefore
    /// proves non-inclusion and requires an all-zero `value_be`.
    pub present: bool,
    pub value_be: [u8; 32],
    pub proof_nodes: Vec<Vec<u8>>,
}

pub fn verify_ethereum_account_mpt_v2(
    state_root: [u8; 32],
    witness: &EthereumAccountMptWitnessV2,
) -> Result<VerifiedEthereumAccountV2, EthereumMptErrorV2> {
    if state_root == [0; 32]
        || witness.address == [0; 20]
        || witness.storage_root == [0; 32]
        || witness.code_hash == [0; 32]
    {
        return Err(EthereumMptErrorV2::InvalidAccount);
    }
    validate_nodes(&witness.proof_nodes, false)?;
    let account = TrieAccount {
        nonce: witness.nonce,
        balance: U256::from_be_bytes(witness.balance_be),
        storage_root: B256::new(witness.storage_root),
        code_hash: B256::new(witness.code_hash),
    };
    let address_hash = keccak256(witness.address);
    let path = Nibbles::unpack(Bytes::copy_from_slice(address_hash.as_slice()));
    let nodes = alloy_nodes(&witness.proof_nodes);
    proof::verify_proof(
        B256::new(state_root),
        path,
        Some(alloy_rlp::encode(account)),
        nodes.iter(),
    )
    .map_err(|_| EthereumMptErrorV2::AccountProofRejected)?;
    Ok(VerifiedEthereumAccountV2 {
        address: witness.address,
        nonce: witness.nonce,
        balance_be: witness.balance_be,
        storage_root: witness.storage_root,
        code_hash: witness.code_hash,
    })
}

pub fn verify_ethereum_storage_mpt_v2(
    storage_root: [u8; 32],
    witness: &EthereumStorageMptWitnessV2,
) -> Result<[u8; 32], EthereumMptErrorV2> {
    if storage_root == [0; 32]
        || (witness.present && witness.value_be == [0; 32])
        || (!witness.present && witness.value_be != [0; 32])
    {
        return Err(EthereumMptErrorV2::InvalidStorage);
    }
    // EIP-1186 proves absence in an entirely empty storage trie with no
    // nodes. Alloy still requires the exact EMPTY_ROOT_HASH and None value;
    // an empty proof cannot authorize a different root or a nonzero value.
    validate_nodes(&witness.proof_nodes, true)?;
    let key_hash = keccak256(witness.storage_key);
    let path = Nibbles::unpack(Bytes::copy_from_slice(key_hash.as_slice()));
    let expected = witness
        .present
        .then(|| alloy_rlp::encode(U256::from_be_bytes(witness.value_be)));
    let nodes = alloy_nodes(&witness.proof_nodes);
    proof::verify_proof(B256::new(storage_root), path, expected, nodes.iter())
        .map_err(|_| EthereumMptErrorV2::StorageProofRejected)?;
    Ok(witness.value_be)
}

/// Solidity `keccak256(abi.encode(address, mappingSlot))`.
pub fn solidity_address_mapping_storage_key_v2(
    address: [u8; 20],
    mapping_slot: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0u8; 64];
    encoded[12..32].copy_from_slice(&address);
    encoded[32..].copy_from_slice(&mapping_slot);
    keccak256(encoded).0
}

pub fn u256_be_to_u128(value: [u8; 32]) -> Result<u128, EthereumMptErrorV2> {
    if value[..16] != [0; 16] {
        return Err(EthereumMptErrorV2::IntegerOverflow);
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&value[16..]);
    Ok(u128::from_be_bytes(low))
}

pub fn u256_be_to_u64(value: [u8; 32]) -> Result<u64, EthereumMptErrorV2> {
    if value[..24] != [0; 24] {
        return Err(EthereumMptErrorV2::IntegerOverflow);
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&value[24..]);
    Ok(u64::from_be_bytes(low))
}

/// Frozen identities and slot selectors for the complete direct Sepolia/MPT
/// half of the USDD/USD conversion statement. Storage slot zero is valid and
/// is therefore never used as a missing-value sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsddUsdEthereumFoundationConfigurationV2 {
    pub version: u8,
    pub ethereum_chain_id: u64,
    pub ethereum_light_client_configuration_hash: [u8; 32],
    pub usdd_asset_id: [u8; 32],
    pub elements_genesis_hash: [u8; 32],
    pub vault_address: [u8; 20],
    pub vault_runtime_code_hash: [u8; 32],
    pub reserve_token_address: [u8; 20],
    pub reserve_token_runtime_code_hash: [u8; 32],
    pub price_contract_address: [u8; 20],
    pub price_contract_runtime_code_hash: [u8; 32],
    pub vault_liability_storage_key: [u8; 32],
    pub vault_pause_storage_key: [u8; 32],
    pub vault_governance_storage_key: [u8; 32],
    pub reserve_balance_mapping_slot: [u8; 32],
    pub price_storage_key: [u8; 32],
    pub redemption_enabled_pause_value: [u8; 32],
    pub governance_locked_value: [u8; 32],
}

impl UsddUsdEthereumFoundationConfigurationV2 {
    pub fn validate(&self) -> Result<(), EthereumMptErrorV2> {
        if self.version != USDD_USD_FROZEN_CONFIGURATION_VERSION_V2
            || self.ethereum_chain_id == 0
            || self.vault_address == [0; 20]
            || self.reserve_token_address == [0; 20]
            || self.price_contract_address == [0; 20]
            || [
                self.ethereum_light_client_configuration_hash,
                self.usdd_asset_id,
                self.elements_genesis_hash,
                self.vault_runtime_code_hash,
                self.reserve_token_runtime_code_hash,
                self.price_contract_runtime_code_hash,
            ]
            .contains(&[0; 32])
        {
            return Err(EthereumMptErrorV2::InvalidFrozenConfiguration);
        }
        Ok(())
    }

    /// This fixed layout is duplicated independently in `ecx-proof-core` and
    /// compared through the recursive receipt. It intentionally does not use
    /// Rust's representation-dependent serialization.
    pub fn canonical_bytes(&self) -> Vec<u8> {
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

    pub fn commitment(&self) -> Result<[u8; 32], EthereumMptErrorV2> {
        self.validate()?;
        Ok(tagged_hash(
            "ECX/usdd-usd-ethereum-source-configuration/v2",
            &self.canonical_bytes(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsddUsdEthereumFoundationWitnessV2 {
    pub finality: SepoliaFinalityFoundationWitness,
    pub vault_account: EthereumAccountMptWitnessV2,
    pub reserve_token_account: EthereumAccountMptWitnessV2,
    pub price_contract_account: EthereumAccountMptWitnessV2,
    pub vault_liability: EthereumStorageMptWitnessV2,
    pub vault_pause: EthereumStorageMptWitnessV2,
    pub vault_governance: EthereumStorageMptWitnessV2,
    pub reserve_balance: EthereumStorageMptWitnessV2,
    pub reserve_usd_quote: EthereumStorageMptWitnessV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsddUsdEthereumSourceInputV2 {
    pub version: u8,
    pub frozen_configuration: UsddUsdEthereumFoundationConfigurationV2,
    pub finality: SepoliaFinalityFoundationWitness,
    pub vault_account: EthereumAccountMptWitnessV2,
    pub reserve_token_account: EthereumAccountMptWitnessV2,
    pub price_contract_account: EthereumAccountMptWitnessV2,
    pub vault_liability: EthereumStorageMptWitnessV2,
    pub vault_pause: EthereumStorageMptWitnessV2,
    pub vault_governance: EthereumStorageMptWitnessV2,
    pub reserve_balance: EthereumStorageMptWitnessV2,
    pub reserve_usd_quote: EthereumStorageMptWitnessV2,
}

impl UsddUsdEthereumSourceInputV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EthereumMptErrorV2> {
        self.validate_envelope()?;
        canonical_options()
            .serialize(self)
            .map_err(|_| EthereumMptErrorV2::NonCanonicalEncoding)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, EthereumMptErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2 {
            return Err(EthereumMptErrorV2::ResourceLimit);
        }
        let value: Self = canonical_options()
            .deserialize(bytes)
            .map_err(|_| EthereumMptErrorV2::NonCanonicalEncoding)?;
        if value.canonical_bytes()? != bytes {
            return Err(EthereumMptErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    pub fn validate_envelope(&self) -> Result<(), EthereumMptErrorV2> {
        self.frozen_configuration.validate()?;
        if self.version != USDD_USD_ETHEREUM_SOURCE_INPUT_VERSION_V2
            || self.finality.manifest.is_empty()
            || self.finality.manifest.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
            || self.finality.prior_controller_state.is_empty()
            || self.finality.prior_controller_state.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
            || self.finality.expected_finalized_state.is_empty()
            || self.finality.expected_finalized_state.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
            || self.finality.finality_proof_cbor.is_empty()
            || self.finality.finality_proof_cbor.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2
        {
            return Err(EthereumMptErrorV2::InvalidEnvelope);
        }
        for proof in [
            &self.vault_account,
            &self.reserve_token_account,
            &self.price_contract_account,
        ] {
            validate_nodes(&proof.proof_nodes, false)?;
        }
        for proof in [
            &self.vault_liability,
            &self.vault_pause,
            &self.vault_governance,
            &self.reserve_balance,
            &self.reserve_usd_quote,
        ] {
            validate_nodes(&proof.proof_nodes, true)?;
            if (proof.present && proof.value_be == [0; 32])
                || (!proof.present && proof.value_be != [0; 32])
            {
                return Err(EthereumMptErrorV2::InvalidStorage);
            }
        }
        Ok(())
    }

    pub fn foundation_witness(&self) -> UsddUsdEthereumFoundationWitnessV2 {
        UsddUsdEthereumFoundationWitnessV2 {
            finality: self.finality.clone(),
            vault_account: self.vault_account.clone(),
            reserve_token_account: self.reserve_token_account.clone(),
            price_contract_account: self.price_contract_account.clone(),
            vault_liability: self.vault_liability.clone(),
            vault_pause: self.vault_pause.clone(),
            vault_governance: self.vault_governance.clone(),
            reserve_balance: self.reserve_balance.clone(),
            reserve_usd_quote: self.reserve_usd_quote.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsddEthereumSourcePublicValuesV2 {
    pub version: u8,
    pub frozen_configuration_commitment: [u8; 32],
    pub protocol_manifest_commitment: [u8; 32],
    pub update_proof_commitment: [u8; 32],
    pub prior_light_client_digest: [u8; 32],
    pub prior_finalized_beacon_slot: u64,
    pub prior_finalized_beacon_root: [u8; 32],
    pub prior_finalized_execution_state_root: [u8; 32],
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: [u8; 32],
    pub finalized_execution_block_hash: [u8; 32],
    pub finalized_execution_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub execution_block_timestamp: u64,
    pub light_client_digest: [u8; 32],
    pub vault_liability_reserve_atoms: u128,
    pub reserve_balance_atoms: u128,
    pub quote_atoms_per_whole_reserve_token: u64,
    pub vault_pause_value: [u8; 32],
    pub vault_governance_value: [u8; 32],
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
}

pub fn execute_usdd_usd_ethereum_source_v2(
    input: &UsddUsdEthereumSourceInputV2,
) -> Result<UsddEthereumSourcePublicValuesV2, EthereumMptErrorV2> {
    input.validate_envelope()?;
    let verified = verify_usdd_usd_ethereum_foundation_v2(
        &input.frozen_configuration,
        &input.foundation_witness(),
    )?;
    if verified.vault_pause_value != input.frozen_configuration.redemption_enabled_pause_value
        || verified.vault_governance_value != input.frozen_configuration.governance_locked_value
    {
        return Err(EthereumMptErrorV2::FrozenStateMismatch);
    }
    let finality = verified.finality;
    Ok(UsddEthereumSourcePublicValuesV2 {
        version: USDD_ETHEREUM_SOURCE_PUBLIC_VALUES_VERSION_V2,
        frozen_configuration_commitment: input.frozen_configuration.commitment()?,
        protocol_manifest_commitment: tagged_hash(
            "ECX/usdd-usd-protocol-manifest/v2",
            &input.finality.manifest,
        ),
        update_proof_commitment: finality_update_commitment(&input.finality)?,
        prior_light_client_digest: finality.prior_light_client_digest,
        prior_finalized_beacon_slot: finality.prior_finalized_beacon_slot,
        prior_finalized_beacon_root: finality.prior_finalized_beacon_root,
        prior_finalized_execution_state_root: finality.prior_finalized_execution_state_root,
        finalized_beacon_slot: finality.finalized_beacon_slot,
        finalized_beacon_root: finality.finalized_beacon_root,
        finalized_execution_block_hash: finality.finalized_execution_block,
        finalized_execution_state_root: finality.finalized_execution_state_root,
        execution_block_number: finality.execution_block_number,
        execution_block_timestamp: finality.execution_block_timestamp,
        light_client_digest: finality.ethereum_light_client_digest,
        vault_liability_reserve_atoms: verified.vault_liability_reserve_atoms,
        reserve_balance_atoms: verified.reserve_balance_atoms,
        quote_atoms_per_whole_reserve_token: verified.quote_atoms_per_whole_reserve_token,
        vault_pause_value: verified.vault_pause_value,
        vault_governance_value: verified.vault_governance_value,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedUsddUsdEthereumFoundationV2 {
    pub finality: VerifiedSepoliaFinalityFoundation,
    pub vault_liability_reserve_atoms: u128,
    pub reserve_balance_atoms: u128,
    pub quote_atoms_per_whole_reserve_token: u64,
    pub vault_pause_value: [u8; 32],
    pub vault_governance_value: [u8; 32],
}

/// Verify the complete direct Ethereum half of the relation without assigning
/// meaning to an unfrozen address, code hash, slot, or caller-supplied total.
pub fn verify_usdd_usd_ethereum_foundation_v2(
    configuration: &UsddUsdEthereumFoundationConfigurationV2,
    witness: &UsddUsdEthereumFoundationWitnessV2,
) -> Result<VerifiedUsddUsdEthereumFoundationV2, EthereumMptErrorV2> {
    let manifest = verify_usdd_manifest_identity_v2(&witness.finality.manifest)?;
    if manifest.ethereum_chain_id != configuration.ethereum_chain_id
        || manifest.ethereum_light_client_configuration_hash
            != configuration.ethereum_light_client_configuration_hash
        || manifest.vault_address != configuration.vault_address
        || manifest.reserve_token_address != configuration.reserve_token_address
        || manifest.usdd_asset_id != configuration.usdd_asset_id
        || manifest.elements_genesis_hash != configuration.elements_genesis_hash
        || manifest.vault_runtime_code_hash != configuration.vault_runtime_code_hash
    {
        return Err(EthereumMptErrorV2::FrozenIdentityMismatch);
    }
    let finality = verify_sepolia_finality_foundation(&witness.finality)
        .map_err(|_| EthereumMptErrorV2::FinalityRejected)?;

    let vault = verify_expected_account(
        finality.finalized_execution_state_root,
        &witness.vault_account,
        configuration.vault_address,
        configuration.vault_runtime_code_hash,
    )?;
    let reserve = verify_expected_account(
        finality.finalized_execution_state_root,
        &witness.reserve_token_account,
        configuration.reserve_token_address,
        configuration.reserve_token_runtime_code_hash,
    )?;
    let price = verify_expected_account(
        finality.finalized_execution_state_root,
        &witness.price_contract_account,
        configuration.price_contract_address,
        configuration.price_contract_runtime_code_hash,
    )?;

    let liability = verify_expected_storage(
        vault.storage_root,
        &witness.vault_liability,
        configuration.vault_liability_storage_key,
    )?;
    let pause = verify_expected_storage(
        vault.storage_root,
        &witness.vault_pause,
        configuration.vault_pause_storage_key,
    )?;
    let governance = verify_expected_storage(
        vault.storage_root,
        &witness.vault_governance,
        configuration.vault_governance_storage_key,
    )?;
    let reserve_key = solidity_address_mapping_storage_key_v2(
        configuration.vault_address,
        configuration.reserve_balance_mapping_slot,
    );
    let reserve_balance =
        verify_expected_storage(reserve.storage_root, &witness.reserve_balance, reserve_key)?;
    let quote = verify_expected_storage(
        price.storage_root,
        &witness.reserve_usd_quote,
        configuration.price_storage_key,
    )?;

    Ok(VerifiedUsddUsdEthereumFoundationV2 {
        finality,
        vault_liability_reserve_atoms: u256_be_to_u128(liability)?,
        reserve_balance_atoms: u256_be_to_u128(reserve_balance)?,
        quote_atoms_per_whole_reserve_token: u256_be_to_u64(quote)?,
        vault_pause_value: pause,
        vault_governance_value: governance,
    })
}

fn verify_expected_account(
    state_root: [u8; 32],
    witness: &EthereumAccountMptWitnessV2,
    expected_address: [u8; 20],
    expected_code_hash: [u8; 32],
) -> Result<VerifiedEthereumAccountV2, EthereumMptErrorV2> {
    if witness.address != expected_address || witness.code_hash != expected_code_hash {
        return Err(EthereumMptErrorV2::FrozenIdentityMismatch);
    }
    verify_ethereum_account_mpt_v2(state_root, witness)
}

fn verify_expected_storage(
    storage_root: [u8; 32],
    witness: &EthereumStorageMptWitnessV2,
    expected_key: [u8; 32],
) -> Result<[u8; 32], EthereumMptErrorV2> {
    if witness.storage_key != expected_key {
        return Err(EthereumMptErrorV2::FrozenIdentityMismatch);
    }
    verify_ethereum_storage_mpt_v2(storage_root, witness)
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2 as u64)
}

fn finality_update_commitment(
    witness: &SepoliaFinalityFoundationWitness,
) -> Result<[u8; 32], EthereumMptErrorV2> {
    let fields = [
        witness.prior_controller_state.as_slice(),
        witness.expected_finalized_state.as_slice(),
        witness.finality_proof_cbor.as_slice(),
    ];
    let mut bytes = Vec::new();
    for field in fields {
        if field.is_empty() || field.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2 {
            return Err(EthereumMptErrorV2::ResourceLimit);
        }
        bytes.extend_from_slice(
            &u64::try_from(field.len())
                .map_err(|_| EthereumMptErrorV2::ResourceLimit)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    Ok(tagged_hash(
        "ECX/usdd-sepolia-finality-update-proof/v2",
        &bytes,
    ))
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

fn validate_nodes(nodes: &[Vec<u8>], allow_empty: bool) -> Result<(), EthereumMptErrorV2> {
    if (!allow_empty && nodes.is_empty()) || nodes.len() > MAX_MPT_PROOF_NODES_V2
        // The upstream empty-root branch returns immediately. Reject any
        // tail nodes that would otherwise be ignored after canonical 0x80.
        || (nodes.first().is_some_and(|n| n.as_slice() == [0x80]) && nodes.len() != 1)
    {
        return Err(EthereumMptErrorV2::ResourceLimit);
    }
    let mut total = 0usize;
    for node in nodes {
        if node.is_empty() || node.len() > MAX_MPT_NODE_BYTES_V2 {
            return Err(EthereumMptErrorV2::ResourceLimit);
        }
        total = total
            .checked_add(node.len())
            .ok_or(EthereumMptErrorV2::ResourceLimit)?;
        if total > MAX_MPT_WITNESS_BYTES_V2 {
            return Err(EthereumMptErrorV2::ResourceLimit);
        }
    }
    Ok(())
}

fn alloy_nodes(nodes: &[Vec<u8>]) -> Vec<Bytes> {
    nodes
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum EthereumMptErrorV2 {
    #[error("canonical USDD protocol manifest was rejected")]
    InvalidManifest,
    #[error("frozen USDD/USD Ethereum source configuration is malformed")]
    InvalidFrozenConfiguration,
    #[error("USDD/USD Ethereum source input envelope is malformed")]
    InvalidEnvelope,
    #[error("USDD/USD Ethereum source encoding is noncanonical")]
    NonCanonicalEncoding,
    #[error("a manifest, account, code hash, or storage key differs from frozen configuration")]
    FrozenIdentityMismatch,
    #[error("the pinned Sepolia finality transition was rejected")]
    FinalityRejected,
    #[error("authenticated pause or governance state differs from frozen safe value")]
    FrozenStateMismatch,
    #[error("Ethereum MPT witness exceeds a frozen resource bound")]
    ResourceLimit,
    #[error("Ethereum account witness is malformed")]
    InvalidAccount,
    #[error("Ethereum storage witness is malformed")]
    InvalidStorage,
    #[error("Ethereum account MPT proof was rejected")]
    AccountProofRejected,
    #[error("Ethereum storage MPT proof was rejected")]
    StorageProofRejected,
    #[error("authenticated Ethereum uint256 does not fit the required integer width")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Encodable;
    use alloy_trie::nodes::LeafNode;

    fn leaf(path: B256, value: Vec<u8>) -> Vec<u8> {
        let node = LeafNode::new(
            Nibbles::unpack(Bytes::copy_from_slice(path.as_slice())),
            value,
        );
        let mut encoded = Vec::new();
        node.encode(&mut encoded);
        encoded
    }

    #[test]
    fn exact_account_and_storage_leaf_verify() {
        let address = [7; 20];
        // Solidity storage slot zero is valid and must not be treated as a
        // missing-value sentinel.
        let key = [0; 32];
        let mut value = [0u8; 32];
        value[31] = 9;
        let storage_leaf = leaf(
            keccak256(key),
            alloy_rlp::encode(U256::from_be_bytes(value)),
        );
        let storage_root = keccak256(&storage_leaf).0;
        let account = TrieAccount {
            nonce: 3,
            balance: U256::from(4u64),
            storage_root: B256::new(storage_root),
            code_hash: B256::new([5; 32]),
        };
        let account_leaf = leaf(keccak256(address), alloy_rlp::encode(account));
        let state_root = keccak256(&account_leaf).0;
        let verified = verify_ethereum_account_mpt_v2(
            state_root,
            &EthereumAccountMptWitnessV2 {
                address,
                nonce: 3,
                balance_be: {
                    let mut bytes = [0; 32];
                    bytes[31] = 4;
                    bytes
                },
                storage_root,
                code_hash: [5; 32],
                proof_nodes: vec![account_leaf],
            },
        )
        .unwrap();
        assert_eq!(verified.storage_root, storage_root);
        assert_eq!(
            verify_ethereum_storage_mpt_v2(
                storage_root,
                &EthereumStorageMptWitnessV2 {
                    storage_key: key,
                    present: true,
                    value_be: value,
                    proof_nodes: vec![storage_leaf],
                }
            )
            .unwrap(),
            value
        );
    }

    #[test]
    fn wrong_value_and_noncanonical_zero_reject() {
        let bad = EthereumStorageMptWitnessV2 {
            storage_key: [1; 32],
            present: false,
            value_be: [2; 32],
            proof_nodes: vec![vec![1]],
        };
        assert_eq!(
            verify_ethereum_storage_mpt_v2([3; 32], &bad),
            Err(EthereumMptErrorV2::InvalidStorage)
        );
    }

    #[test]
    fn empty_storage_trie_absence_requires_exact_root_and_zero_value() {
        let mut witness = EthereumStorageMptWitnessV2 {
            storage_key: [0; 32],
            present: false,
            value_be: [0; 32],
            proof_nodes: Vec::new(),
        };
        let empty_root = alloy_trie::EMPTY_ROOT_HASH.0;
        assert_eq!(verify_ethereum_storage_mpt_v2(empty_root, &witness), Ok([0; 32]));
        witness.storage_key = [9; 32];
        assert_eq!(verify_ethereum_storage_mpt_v2(empty_root, &witness), Ok([0; 32]));
        assert_eq!(verify_ethereum_storage_mpt_v2([3; 32], &witness),
            Err(EthereumMptErrorV2::StorageProofRejected));
        witness.present = true;
        witness.value_be[31] = 1;
        assert_eq!(verify_ethereum_storage_mpt_v2(empty_root, &witness),
            Err(EthereumMptErrorV2::StorageProofRejected));
        witness.present = false;
        assert_eq!(verify_ethereum_storage_mpt_v2(empty_root, &witness),
            Err(EthereumMptErrorV2::InvalidStorage));
    }

    #[test]
    fn explicit_empty_storage_node_rejects_ignored_tail() {
        let mut witness = EthereumStorageMptWitnessV2 {
            storage_key: [0; 32], present: false, value_be: [0; 32],
            proof_nodes: vec![vec![0x80]],
        };
        assert_eq!(verify_ethereum_storage_mpt_v2(alloy_trie::EMPTY_ROOT_HASH.0, &witness),
            Ok([0; 32]));
        witness.proof_nodes.push(vec![0x80]);
        assert_eq!(verify_ethereum_storage_mpt_v2(alloy_trie::EMPTY_ROOT_HASH.0, &witness),
            Err(EthereumMptErrorV2::ResourceLimit));
    }

    #[test]
    fn empty_account_proof_is_still_rejected() {
        let witness = EthereumAccountMptWitnessV2 {
            address: [1; 20], nonce: 1, balance_be: [0; 32],
            storage_root: alloy_trie::EMPTY_ROOT_HASH.0,
            code_hash: [2; 32], proof_nodes: Vec::new(),
        };
        assert_eq!(verify_ethereum_account_mpt_v2(alloy_trie::EMPTY_ROOT_HASH.0, &witness),
            Err(EthereumMptErrorV2::ResourceLimit));
    }

    #[test]
    fn mapping_key_uses_full_abi_words() {
        let mut slot = [0; 32];
        slot[31] = 4;
        let key = solidity_address_mapping_storage_key_v2([1; 20], slot);
        assert_ne!(key, [0; 32]);
        assert_ne!(key, solidity_address_mapping_storage_key_v2([2; 20], slot));
    }
}
