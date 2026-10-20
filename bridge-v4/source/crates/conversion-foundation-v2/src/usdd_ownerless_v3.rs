//! Version-three source statement for the ownerless Solidity USDDVaultV2.
//!
//! Unlike the legacy source, this authenticates the actual ownerless accounting
//! slots and reports conservative minted backing, not arbitrary reserve surplus.
//! The only public execution entrypoint first verifies Sepolia finality and all
//! account/storage MPT proofs. There is no host-supplied verified-state adapter.
//! The outer conversion relation must pin the prior checkpoint and authenticate
//! matching Elements supply; this source alone does not prove redemption liveness.
//!
//! Configuration is a TRUSTED, reviewed deployment input. Actual immutable-patched
//! EXTCODEHASH pins and constructor bindings must be established independently.
//! Proxy token/price/relay/verifier layouts are unsupported by this immutable-code
//! profile. A code hash does not itself establish a source-to-deployment mapping.
//! The inherited ProtocolManifestV1 is used only for its unchanged finality and
//! common identity fields; it is not relabelled as an ownerless deployment record.

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::usdd_ownerless_accounting_v2 as accounting;
use crate::usdd_usd::{
    solidity_address_mapping_storage_key_v2, u256_be_to_u64, verify_ethereum_account_mpt_v2,
    verify_ethereum_storage_mpt_v2, verify_usdd_manifest_identity_v2, EthereumAccountMptWitnessV2,
    EthereumMptErrorV2, EthereumStorageMptWitnessV2, VerifiedEthereumAccountV2,
    MAX_MPT_NODE_BYTES_V2, MAX_MPT_PROOF_NODES_V2, MAX_MPT_WITNESS_BYTES_V2,
    MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2, MAX_USDD_USD_PREIMAGE_BYTES_V2,
};
use crate::{verify_sepolia_finality_foundation, SepoliaFinalityFoundationWitness};

pub const OWNERLESS_SOURCE_VERSION_V3: u8 = 3;
pub const OWNERLESS_CONFIGURATION_LEN_V3: usize = 560;
pub const OWNERLESS_SOURCE_PUBLIC_VALUES_LEN_V3: usize = 732;
pub const OWNERLESS_VAULT_SLOTS_V3: [u64; 9] = [0, 1, 2, 3, 4, 5, 6, 19, 20];

/// Commits the ORIGINAL accounting source artifact (before removal of its
/// crate-level no_std attribute), exact Solidity closure, layout, cap, and
/// denomination. A regression test reconstructs and hashes that original from
/// the integrated copy. This is neither the local module hash nor deployed code.
pub fn ownerless_layout_commitment_v3() -> [u8; 32] {
    tagged_hash(
        "ECX/usdd-ownerless-layout/v3",
        concat!(
            "accounting-sha256=976d3449ed92b7e9116e1f29fb22af0dbdf8bcf5d337d534a0fc63ca50dfabb1;",
            "inbound-sha256=4aceb9c54766ec9f5ff0bdbeae8edc1c882bdadb185b95d53f8622f2b503fd79;",
            "vault-sha256=59ff23df4fabb7ec77b954d3ef2538f88ed16ee3b09c98cdcf8aa25e81e7d6a9;",
            "slots=0,1,2,3,4,5,6,19,20;nonces=u64-low,u64-next;",
            "cap-usdt6=1000000000000000;token-decimals=6;usdd-decimals=8;quote-decimals=8"
        )
        .as_bytes(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerlessContractIdentityV3 {
    pub address: [u8; 20],
    pub runtime_code_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsddOwnerlessSourceConfigurationV3 {
    pub version: u8,
    pub ethereum_chain_id: u64,
    pub ethereum_light_client_configuration_hash: [u8; 32],
    pub usdd_asset_id: [u8; 32],
    pub elements_genesis_hash: [u8; 32],
    pub custody_id: [u8; 32],
    pub vault: OwnerlessContractIdentityV3,
    pub reserve_token: OwnerlessContractIdentityV3,
    pub relay: OwnerlessContractIdentityV3,
    pub redemption_verifier: OwnerlessContractIdentityV3,
    pub price_contract: OwnerlessContractIdentityV3,
    pub relay_verifier_configuration_hash: [u8; 32],
    pub terminal_vault_policy_hash: [u8; 32],
    pub ownerless_layout_commitment: [u8; 32],
    pub reserve_balance_mapping_slot: [u8; 32],
    pub price_storage_key: [u8; 32],
    pub reserve_token_decimals: u8,
    pub usdd_decimals: u8,
    pub quote_decimals: u8,
}

impl UsddOwnerlessSourceConfigurationV3 {
    fn identities(&self) -> [OwnerlessContractIdentityV3; 5] {
        [
            self.vault,
            self.reserve_token,
            self.relay,
            self.redemption_verifier,
            self.price_contract,
        ]
    }

    pub fn validate(&self) -> Result<(), OwnerlessSourceErrorV3> {
        if self.version != OWNERLESS_SOURCE_VERSION_V3
            || self.ethereum_chain_id != 11_155_111
            || [
                self.ethereum_light_client_configuration_hash,
                self.usdd_asset_id,
                self.elements_genesis_hash,
                self.custody_id,
                self.relay_verifier_configuration_hash,
                self.terminal_vault_policy_hash,
            ]
            .contains(&[0; 32])
            || self.ownerless_layout_commitment != ownerless_layout_commitment_v3()
            || (
                self.reserve_token_decimals,
                self.usdd_decimals,
                self.quote_decimals,
            ) != (6, 8, 8)
        {
            return Err(OwnerlessSourceErrorV3::InvalidConfiguration);
        }
        let identities = self.identities();
        for (i, identity) in identities.iter().enumerate() {
            if identity.address == [0; 20]
                || identity.runtime_code_hash == [0; 32]
                || identities[..i]
                    .iter()
                    .any(|other| other.address == identity.address)
            {
                return Err(OwnerlessSourceErrorV3::InvalidConfiguration);
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnerlessSourceErrorV3> {
        self.validate()?;
        let mut out = Vec::with_capacity(OWNERLESS_CONFIGURATION_LEN_V3);
        out.push(self.version);
        out.extend(self.ethereum_chain_id.to_be_bytes());
        for field in [
            self.ethereum_light_client_configuration_hash,
            self.usdd_asset_id,
            self.elements_genesis_hash,
            self.custody_id,
        ] {
            out.extend(field);
        }
        for identity in self.identities() {
            out.extend(identity.address);
            out.extend(identity.runtime_code_hash);
        }
        for field in [
            self.relay_verifier_configuration_hash,
            self.terminal_vault_policy_hash,
            self.ownerless_layout_commitment,
            self.reserve_balance_mapping_slot,
            self.price_storage_key,
        ] {
            out.extend(field);
        }
        out.extend([
            self.reserve_token_decimals,
            self.usdd_decimals,
            self.quote_decimals,
        ]);
        debug_assert_eq!(out.len(), OWNERLESS_CONFIGURATION_LEN_V3);
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], OwnerlessSourceErrorV3> {
        Ok(tagged_hash(
            "ECX/usdd-usd-ownerless-source-configuration/v3",
            &self.canonical_bytes()?,
        ))
    }

    fn accounting_configuration(&self) -> accounting::ConfigurationV2 {
        let identity = |i: OwnerlessContractIdentityV3| accounting::ContractIdentityV2 {
            address: i.address,
            runtime_code_hash: i.runtime_code_hash,
        };
        accounting::ConfigurationV2 {
            version: accounting::ADAPTER_VERSION,
            chain_id: self.ethereum_chain_id,
            vault: identity(self.vault),
            token: identity(self.reserve_token),
            relay: identity(self.relay),
            redemption_verifier: identity(self.redemption_verifier),
            relay_verifier_config_hash: self.relay_verifier_configuration_hash,
            terminal_vault_policy_hash: self.terminal_vault_policy_hash,
            token_vault_balance_storage_key: solidity_address_mapping_storage_key_v2(
                self.vault.address,
                self.reserve_balance_mapping_slot,
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsddOwnerlessEthereumWitnessV3 {
    /// Fixed role order: vault, token, relay, redemption verifier, quote contract.
    pub accounts: [EthereumAccountMptWitnessV2; 5],
    /// Fixed slot order OWNERLESS_VAULT_SLOTS_V3; zero requires non-inclusion.
    pub vault_storage: [EthereumStorageMptWitnessV2; 9],
    pub reserve_balance: EthereumStorageMptWitnessV2,
    pub reserve_usd_quote: EthereumStorageMptWitnessV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsddOwnerlessSourceInputV3 {
    pub version: u8,
    pub frozen_configuration: UsddOwnerlessSourceConfigurationV3,
    pub finality: SepoliaFinalityFoundationWitness,
    pub ethereum: UsddOwnerlessEthereumWitnessV3,
}

impl UsddOwnerlessSourceInputV3 {
    pub fn validate_envelope(&self) -> Result<(), OwnerlessSourceErrorV3> {
        if self.version != OWNERLESS_SOURCE_VERSION_V3 {
            return Err(OwnerlessSourceErrorV3::InvalidEnvelope);
        }
        self.frozen_configuration.validate()?;
        for bytes in [
            &self.finality.manifest,
            &self.finality.prior_controller_state,
            &self.finality.expected_finalized_state,
            &self.finality.finality_proof_cbor,
        ] {
            if bytes.is_empty() || bytes.len() > MAX_USDD_USD_PREIMAGE_BYTES_V2 {
                return Err(OwnerlessSourceErrorV3::InvalidEnvelope);
            }
        }
        for account in &self.ethereum.accounts {
            validate_nodes(&account.proof_nodes, false)?;
        }
        for storage in self.ethereum.vault_storage.iter().chain([
            &self.ethereum.reserve_balance,
            &self.ethereum.reserve_usd_quote,
        ]) {
            validate_nodes(&storage.proof_nodes, true)?;
            if storage.present == (storage.value_be == [0; 32]) {
                return Err(OwnerlessSourceErrorV3::InvalidEnvelope);
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnerlessSourceErrorV3> {
        self.validate_envelope()?;
        canonical_options()
            .serialize(self)
            .map_err(|_| OwnerlessSourceErrorV3::InvalidEnvelope)
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, OwnerlessSourceErrorV3> {
        if bytes.len() > MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2 {
            return Err(OwnerlessSourceErrorV3::ResourceLimit);
        }
        let input: Self = canonical_options()
            .deserialize(bytes)
            .map_err(|_| OwnerlessSourceErrorV3::InvalidEnvelope)?;
        input.validate_envelope()?;
        Ok(input)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsddOwnerlessSourcePublicValuesV3 {
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
    pub next_intent_nonce: u64,
    pub next_committed_deposit_nonce: u64,
    pub reserve_usdt6: [u8; 32],
    pub accounted_custody_usdt6: [u8; 32],
    pub pending_principal_usdt6: [u8; 32],
    pub pending_bounty_usdt6: [u8; 32],
    pub committed_principal_usdt6: [u8; 32],
    pub committed_bounty_usdt6: [u8; 32],
    pub unresolved_committed_usdt6: [u8; 32],
    pub mint_acknowledged_usdt6: [u8; 32],
    pub other_obligations_usdt6: [u8; 32],
    pub minted_redemption_backing_usdt6: [u8; 32],
    pub unallocated_surplus_usdt6: [u8; 32],
    pub quote_atoms_per_whole_reserve_token: u64,
    pub reserve_token_decimals: u8,
    pub usdd_decimals: u8,
    pub quote_decimals: u8,
}

impl UsddOwnerlessSourcePublicValuesV3 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OWNERLESS_SOURCE_PUBLIC_VALUES_LEN_V3);
        out.push(self.version);
        for field in [
            self.frozen_configuration_commitment,
            self.protocol_manifest_commitment,
            self.update_proof_commitment,
            self.prior_light_client_digest,
        ] {
            out.extend(field);
        }
        out.extend(self.prior_finalized_beacon_slot.to_be_bytes());
        out.extend(self.prior_finalized_beacon_root);
        out.extend(self.prior_finalized_execution_state_root);
        out.extend(self.finalized_beacon_slot.to_be_bytes());
        out.extend(self.finalized_beacon_root);
        out.extend(self.finalized_execution_block_hash);
        out.extend(self.finalized_execution_state_root);
        out.extend(self.execution_block_number.to_be_bytes());
        out.extend(self.execution_block_timestamp.to_be_bytes());
        out.extend(self.light_client_digest);
        out.extend(self.next_intent_nonce.to_be_bytes());
        out.extend(self.next_committed_deposit_nonce.to_be_bytes());
        for word in [
            self.reserve_usdt6,
            self.accounted_custody_usdt6,
            self.pending_principal_usdt6,
            self.pending_bounty_usdt6,
            self.committed_principal_usdt6,
            self.committed_bounty_usdt6,
            self.unresolved_committed_usdt6,
            self.mint_acknowledged_usdt6,
            self.other_obligations_usdt6,
            self.minted_redemption_backing_usdt6,
            self.unallocated_surplus_usdt6,
        ] {
            out.extend(word);
        }
        out.extend(self.quote_atoms_per_whole_reserve_token.to_be_bytes());
        out.extend([
            self.reserve_token_decimals,
            self.usdd_decimals,
            self.quote_decimals,
        ]);
        debug_assert_eq!(out.len(), OWNERLESS_SOURCE_PUBLIC_VALUES_LEN_V3);
        out
    }
}

/// All externally callable executions go through genuine finalized Sepolia
/// verification. The private MPT helper is not an alternative trusted-state API.
pub fn execute_usdd_ownerless_source_v3(
    input: &UsddOwnerlessSourceInputV3,
) -> Result<UsddOwnerlessSourcePublicValuesV3, OwnerlessSourceErrorV3> {
    input.validate_envelope()?;
    let c = &input.frozen_configuration;
    let manifest = verify_usdd_manifest_identity_v2(&input.finality.manifest)?;
    if manifest.ethereum_chain_id != c.ethereum_chain_id
        || manifest.ethereum_light_client_configuration_hash
            != c.ethereum_light_client_configuration_hash
        || manifest.vault_address != c.vault.address
        || manifest.vault_runtime_code_hash != c.vault.runtime_code_hash
        || manifest.reserve_token_address != c.reserve_token.address
        || manifest.usdd_asset_id != c.usdd_asset_id
        || manifest.elements_genesis_hash != c.elements_genesis_hash
    {
        return Err(OwnerlessSourceErrorV3::FrozenIdentityMismatch);
    }
    let f = verify_sepolia_finality_foundation(&input.finality)
        .map_err(|_| OwnerlessSourceErrorV3::FinalityRejected)?;
    let anchor = accounting::FinalizedAnchorV2 {
        chain_id: c.ethereum_chain_id,
        execution_block_hash: f.finalized_execution_block,
        execution_state_root: f.finalized_execution_state_root,
        execution_block_number: f.execution_block_number,
        execution_timestamp: f.execution_block_timestamp,
    };
    let (report, quote) = authenticate_ownerless_mpt(c, anchor, &input.ethereum)?;
    Ok(UsddOwnerlessSourcePublicValuesV3 {
        version: OWNERLESS_SOURCE_VERSION_V3,
        frozen_configuration_commitment: c.commitment()?,
        protocol_manifest_commitment: tagged_hash(
            "ECX/usdd-usd-protocol-manifest/v2",
            &input.finality.manifest,
        ),
        update_proof_commitment: finality_update_commitment(&input.finality),
        prior_light_client_digest: f.prior_light_client_digest,
        prior_finalized_beacon_slot: f.prior_finalized_beacon_slot,
        prior_finalized_beacon_root: f.prior_finalized_beacon_root,
        prior_finalized_execution_state_root: f.prior_finalized_execution_state_root,
        finalized_beacon_slot: f.finalized_beacon_slot,
        finalized_beacon_root: f.finalized_beacon_root,
        finalized_execution_block_hash: f.finalized_execution_block,
        finalized_execution_state_root: f.finalized_execution_state_root,
        execution_block_number: f.execution_block_number,
        execution_block_timestamp: f.execution_block_timestamp,
        light_client_digest: f.ethereum_light_client_digest,
        next_intent_nonce: report.nonces.next_intent_nonce,
        next_committed_deposit_nonce: report.nonces.next_committed_deposit_nonce,
        reserve_usdt6: report.reserve_usdt6.0,
        accounted_custody_usdt6: report.accounted_custody_usdt6.0,
        pending_principal_usdt6: report.pending_principal_usdt6.0,
        pending_bounty_usdt6: report.pending_bounty_usdt6.0,
        committed_principal_usdt6: report.committed_principal_usdt6.0,
        committed_bounty_usdt6: report.committed_bounty_usdt6.0,
        unresolved_committed_usdt6: report.unresolved_committed_usdt6.0,
        mint_acknowledged_usdt6: report.mint_acknowledged_usdt6.0,
        other_obligations_usdt6: report.other_obligations_usdt6.0,
        minted_redemption_backing_usdt6: report.minted_redemption_backing_usdt6.0,
        unallocated_surplus_usdt6: report.unallocated_surplus_usdt6.0,
        quote_atoms_per_whole_reserve_token: quote,
        reserve_token_decimals: c.reserve_token_decimals,
        usdd_decimals: c.usdd_decimals,
        quote_decimals: c.quote_decimals,
    })
}

/// Private, completely authenticated account+storage projection. Constructed
/// once per verified anchor; no cross-anchor or unverified JSON-RPC cache exists.
struct AuthenticatedOwnerlessMptState {
    anchor: accounting::FinalizedAnchorV2,
    accounts: Vec<VerifiedEthereumAccountV2>,
    storage: Vec<([u8; 20], [u8; 32], [u8; 32])>,
}
impl accounting::AuthenticatedEthereumStateV2 for AuthenticatedOwnerlessMptState {
    fn anchor(&self) -> accounting::FinalizedAnchorV2 {
        self.anchor
    }
    fn account_code_hash(&self, address: [u8; 20]) -> Option<[u8; 32]> {
        self.accounts
            .iter()
            .find(|a| a.address == address)
            .map(|a| a.code_hash)
    }
    fn storage_word(&self, address: [u8; 20], key: [u8; 32]) -> Option<[u8; 32]> {
        self.storage
            .iter()
            .find(|(a, k, _)| *a == address && *k == key)
            .map(|(_, _, v)| *v)
    }
}

fn authenticate_ownerless_mpt(
    c: &UsddOwnerlessSourceConfigurationV3,
    anchor: accounting::FinalizedAnchorV2,
    witness: &UsddOwnerlessEthereumWitnessV3,
) -> Result<(accounting::AccountingReportV2, u64), OwnerlessSourceErrorV3> {
    c.validate()?;
    for account in &witness.accounts {
        validate_nodes(&account.proof_nodes, false)?;
    }
    for storage in witness
        .vault_storage
        .iter()
        .chain([&witness.reserve_balance, &witness.reserve_usd_quote])
    {
        validate_nodes(&storage.proof_nodes, true)?;
    }
    let mut state = AuthenticatedOwnerlessMptState {
        anchor,
        accounts: Vec::new(),
        storage: Vec::new(),
    };
    for (w, expected) in witness.accounts.iter().zip(c.identities()) {
        if w.address != expected.address || w.code_hash != expected.runtime_code_hash {
            return Err(OwnerlessSourceErrorV3::FrozenIdentityMismatch);
        }
        state.accounts.push(verify_ethereum_account_mpt_v2(
            anchor.execution_state_root,
            w,
        )?);
    }
    for (w, slot) in witness.vault_storage.iter().zip(OWNERLESS_VAULT_SLOTS_V3) {
        let key = accounting::U256::from_u64(slot).0;
        if w.storage_key != key {
            return Err(OwnerlessSourceErrorV3::FrozenIdentityMismatch);
        }
        let value = verify_ethereum_storage_mpt_v2(state.accounts[0].storage_root, w)?;
        state.storage.push((c.vault.address, key, value));
    }
    let ac = c.accounting_configuration();
    if witness.reserve_balance.storage_key != ac.token_vault_balance_storage_key
        || witness.reserve_usd_quote.storage_key != c.price_storage_key
    {
        return Err(OwnerlessSourceErrorV3::FrozenIdentityMismatch);
    }
    let reserve =
        verify_ethereum_storage_mpt_v2(state.accounts[1].storage_root, &witness.reserve_balance)?;
    state.storage.push((
        c.reserve_token.address,
        ac.token_vault_balance_storage_key,
        reserve,
    ));
    let quote = u256_be_to_u64(verify_ethereum_storage_mpt_v2(
        state.accounts[4].storage_root,
        &witness.reserve_usd_quote,
    )?)?;
    if quote == 0 {
        return Err(OwnerlessSourceErrorV3::InvalidQuote);
    }
    // This source has no independently authenticated Elements supply. Derive
    // backing only; the outer relation MUST compare actual supply with backing.
    let report =
        accounting::evaluate_ownerless_vault_v2(&ac, anchor, &state, accounting::U256::ZERO)
            .map_err(|e| OwnerlessSourceErrorV3::AccountingRejected(format!("{e:?}")))?;
    Ok((report, quote))
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_USDD_USD_ETHEREUM_SOURCE_INPUT_BYTES_V2 as u64)
}
fn validate_nodes(nodes: &[Vec<u8>], allow_empty: bool) -> Result<(), OwnerlessSourceErrorV3> {
    // Only storage witnesses may omit nodes. Authentication below still
    // requires a canonical empty-trie root and zero-valued non-inclusion.
    if (!allow_empty && nodes.is_empty()) || nodes.len() > MAX_MPT_PROOF_NODES_V2
        // alloy's empty-root branch returns immediately. Reject ignored tails.
        || (nodes.first().is_some_and(|n| n.as_slice() == [0x80]) && nodes.len() != 1)
        || nodes.iter().any(|n| n.is_empty() || n.len() > MAX_MPT_NODE_BYTES_V2)
        || nodes.iter().map(Vec::len).sum::<usize>() > MAX_MPT_WITNESS_BYTES_V2
    {
        return Err(OwnerlessSourceErrorV3::ResourceLimit);
    }
    Ok(())
}
fn finality_update_commitment(witness: &SepoliaFinalityFoundationWitness) -> [u8; 32] {
    let mut bytes = Vec::new();
    for field in [
        &witness.prior_controller_state,
        &witness.expected_finalized_state,
        &witness.finality_proof_cbor,
    ] {
        bytes.extend((field.len() as u64).to_be_bytes());
        bytes.extend(field);
    }
    tagged_hash("ECX/usdd-sepolia-finality-update-proof/v2", &bytes)
}
fn tagged_hash(tag: &str, bytes: &[u8]) -> [u8; 32] {
    let tag: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(bytes);
    h.finalize().into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OwnerlessSourceErrorV3 {
    #[error("invalid ownerless source configuration")]
    InvalidConfiguration,
    #[error("invalid versioned source input envelope")]
    InvalidEnvelope,
    #[error("source resource limit exceeded")]
    ResourceLimit,
    #[error("frozen ownerless identity or exact storage slot mismatch")]
    FrozenIdentityMismatch,
    #[error("genuine Sepolia finality rejected")]
    FinalityRejected,
    #[error("authenticated reserve USD quote is zero")]
    InvalidQuote,
    #[error("ownerless accounting rejected: {0}")]
    AccountingRejected(String),
    #[error(transparent)]
    Ethereum(#[from] EthereumMptErrorV2),
}

#[cfg(test)]
mod tests;
