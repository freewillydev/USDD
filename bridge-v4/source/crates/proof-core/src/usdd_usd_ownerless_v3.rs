//! Ownerless Solidity-vault-V2 conversion, with new version-3 source roles.
//!
//! This is a test-dollar relation: a six-decimal Sepolia test token has a
//! frozen nominal quote of one test dollar. It makes no real-USD backing or
//! market-price assertion, and does not change the separate 30-USDD mark.
//! The existing V2 conversion and source wire formats are not reinterpreted.
//!
//! Both source receipts must be cryptographically verified by the caller.
//! In particular, the legacy Elements source receipt is NOT sufficient for
//! the new custody-bound V2 burn/redemption role. There is no default verifier
//! and no receipt producer or deployment qualification in this module.

use bincode::Options;
use ecx_protocol_core::{
    tagged_hash, Hash32, UsddCheckpointConfigV1, UsddEthereumCheckpointV1, PRICE_SCALE,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::usdd_usd_conversion_v2::UsddElementsSourcePublicValuesV2;
use crate::{ConversionLegKindV2, ConversionLegPublicValuesV2};

pub const OWNERLESS_VERSION_V3: u8 = 3;
pub const OWNERLESS_SOURCE_CONFIGURATION_LEN_V3: usize = 560;
pub const OWNERLESS_ETHEREUM_PUBLIC_VALUES_LEN_V3: usize = 732;
pub const OWNERLESS_ELEMENTS_PUBLIC_VALUES_LEN_V3: usize = 835;
pub const USDD_ATOMS_PER_RESERVE_ATOM: u128 = 100;
/// Exact source/layout commitment from foundation's
/// `usdd_ownerless_v3::ownerless_layout_commitment_v3`; not an EXTCODEHASH.
pub const OWNERLESS_LAYOUT_COMMITMENT_V3: Hash32 = [
    0xe6, 0xe5, 0x5d, 0x4f, 0x73, 0x7e, 0x06, 0x51, 0x45, 0x31, 0xa1, 0x96, 0x18, 0xfd, 0xfa, 0xd8,
    0xa7, 0x2b, 0xff, 0xff, 0xe5, 0xc6, 0x5a, 0xf7, 0x71, 0xae, 0x2b, 0x02, 0xcd, 0xfc, 0xdb, 0xec,
];
const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_PREIMAGE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessContractIdentityV3 {
    pub address: [u8; 20],
    pub runtime_code_hash: Hash32,
}

/// Byte-exact projection of the independent foundation source configuration.
/// Addresses, immutable-patched code hashes and constructor bindings must be
/// independently reviewed from actual deployment evidence; none are defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessSourceConfigurationV3 {
    pub version: u8,
    pub ethereum_chain_id: u64,
    pub ethereum_light_client_configuration_hash: Hash32,
    pub usdd_asset_id: Hash32,
    pub elements_genesis_hash: Hash32,
    pub custody_id: Hash32,
    pub vault: OwnerlessContractIdentityV3,
    pub reserve_token: OwnerlessContractIdentityV3,
    pub relay: OwnerlessContractIdentityV3,
    pub redemption_verifier: OwnerlessContractIdentityV3,
    pub price: OwnerlessContractIdentityV3,
    pub relay_verifier_configuration_hash: Hash32,
    pub terminal_vault_policy_hash: Hash32,
    pub ownerless_layout_commitment: Hash32,
    pub reserve_balance_mapping_slot: Hash32,
    pub price_storage_key: Hash32,
    pub token_decimals: u8,
    pub usdd_decimals: u8,
    pub quote_decimals: u8,
}

impl OwnerlessSourceConfigurationV3 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        out.extend_from_slice(&self.ethereum_chain_id.to_be_bytes());
        for h in [
            self.ethereum_light_client_configuration_hash,
            self.usdd_asset_id,
            self.elements_genesis_hash,
            self.custody_id,
        ] {
            out.extend_from_slice(&h);
        }
        for c in [
            &self.vault,
            &self.reserve_token,
            &self.relay,
            &self.redemption_verifier,
            &self.price,
        ] {
            out.extend_from_slice(&c.address);
            out.extend_from_slice(&c.runtime_code_hash);
        }
        for h in [
            self.relay_verifier_configuration_hash,
            self.terminal_vault_policy_hash,
            self.ownerless_layout_commitment,
            self.reserve_balance_mapping_slot,
            self.price_storage_key,
        ] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&[self.token_decimals, self.usdd_decimals, self.quote_decimals]);
        debug_assert_eq!(out.len(), OWNERLESS_SOURCE_CONFIGURATION_LEN_V3);
        out
    }

    pub fn commitment(&self) -> Hash32 {
        tagged_hash(
            "ECX/usdd-usd-ownerless-source-configuration/v3",
            &self.canonical_bytes(),
        )
    }

    pub fn validate(&self) -> Result<(), OwnerlessConversionErrorV3> {
        if self.version != 3
            || self.ethereum_chain_id != 11_155_111
            || (self.token_decimals, self.usdd_decimals, self.quote_decimals) != (6, 8, 8)
            || self.ownerless_layout_commitment != OWNERLESS_LAYOUT_COMMITMENT_V3
            || PRICE_SCALE != 100_000_000
            || [
                self.ethereum_light_client_configuration_hash,
                self.usdd_asset_id,
                self.elements_genesis_hash,
                self.custody_id,
                self.relay_verifier_configuration_hash,
                self.terminal_vault_policy_hash,
                self.ownerless_layout_commitment,
            ]
            .contains(&[0; 32])
            || [
                &self.vault,
                &self.reserve_token,
                &self.relay,
                &self.redemption_verifier,
                &self.price,
            ]
            .iter()
            .any(|c| c.address == [0; 20] || c.runtime_code_hash == [0; 32])
        {
            return Err(OwnerlessConversionErrorV3::Configuration);
        }
        // Storage slot zero is legitimate, not a missing-address surrogate.
        let identities = [
            &self.vault,
            &self.reserve_token,
            &self.relay,
            &self.redemption_verifier,
            &self.price,
        ];
        for (i, identity) in identities.iter().enumerate() {
            if identities[..i]
                .iter()
                .any(|other| other.address == identity.address)
            {
                return Err(OwnerlessConversionErrorV3::Configuration);
            }
        }
        Ok(())
    }
}

/// The exact authenticated Ethereum source statement (all monetary words are
/// unsigned 256-bit big-endian micro-token values). No totals come from an
/// unproved conversion witness field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessEthereumPublicValuesV3 {
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
    pub next_intent_nonce: u64,
    pub next_committed_deposit_nonce: u64,
    pub reserve: Hash32,
    pub accounted_custody: Hash32,
    pub pending_principal: Hash32,
    pub pending_bounty: Hash32,
    pub committed_principal: Hash32,
    pub committed_bounty: Hash32,
    pub unresolved_committed: Hash32,
    pub mint_acknowledged: Hash32,
    pub other_obligations: Hash32,
    pub minted_redemption_backing: Hash32,
    pub unallocated_surplus: Hash32,
    pub quote_atoms_per_whole_reserve_token: u64,
    pub token_decimals: u8,
    pub usdd_decimals: u8,
    pub quote_decimals: u8,
}

impl OwnerlessEthereumPublicValuesV3 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        for h in [
            self.frozen_configuration_commitment,
            self.protocol_manifest_commitment,
            self.update_proof_commitment,
            self.prior_light_client_digest,
        ] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&self.prior_finalized_beacon_slot.to_be_bytes());
        out.extend_from_slice(&self.prior_finalized_beacon_root);
        out.extend_from_slice(&self.prior_finalized_execution_state_root);
        out.extend_from_slice(&self.finalized_beacon_slot.to_be_bytes());
        for h in [
            self.finalized_beacon_root,
            self.finalized_execution_block_hash,
            self.finalized_execution_state_root,
        ] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&self.execution_block_number.to_be_bytes());
        out.extend_from_slice(&self.execution_block_timestamp.to_be_bytes());
        out.extend_from_slice(&self.light_client_digest);
        out.extend_from_slice(&self.next_intent_nonce.to_be_bytes());
        out.extend_from_slice(&self.next_committed_deposit_nonce.to_be_bytes());
        for h in [
            self.reserve,
            self.accounted_custody,
            self.pending_principal,
            self.pending_bounty,
            self.committed_principal,
            self.committed_bounty,
            self.unresolved_committed,
            self.mint_acknowledged,
            self.other_obligations,
            self.minted_redemption_backing,
            self.unallocated_surplus,
        ] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&self.quote_atoms_per_whole_reserve_token.to_be_bytes());
        out.extend_from_slice(&[self.token_decimals, self.usdd_decimals, self.quote_decimals]);
        debug_assert_eq!(out.len(), OWNERLESS_ETHEREUM_PUBLIC_VALUES_LEN_V3);
        out
    }

    pub fn validate_shape(&self) -> Result<(), OwnerlessConversionErrorV3> {
        if self.version != 3
            || self.prior_finalized_beacon_slot == 0
            || self.finalized_beacon_slot <= self.prior_finalized_beacon_slot
            || self.execution_block_number == 0
            || self.execution_block_timestamp == 0
            || (self.token_decimals, self.usdd_decimals, self.quote_decimals) != (6, 8, 8)
            || self.quote_atoms_per_whole_reserve_token != PRICE_SCALE
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
            return Err(OwnerlessConversionErrorV3::EthereumStatement);
        }
        Ok(())
    }

    /// Defense-in-depth against a mismatched source implementation. These
    /// equations never substitute for the authenticated finality/MPT receipt.
    pub fn validate_accounting(&self) -> Result<(), OwnerlessConversionErrorV3> {
        let committed = add256(self.unresolved_committed, self.mint_acknowledged)?;
        let accounted = sum256(&[
            self.pending_principal,
            self.pending_bounty,
            self.committed_principal,
            self.committed_bounty,
        ])?;
        let other = sum256(&[
            self.pending_principal,
            self.pending_bounty,
            self.unresolved_committed,
            self.committed_bounty,
        ])?;
        let surplus = sub256(self.reserve, accounted)?;
        let free = sub256(self.reserve, other)?;
        if self.committed_principal != committed
            || self.accounted_custody != accounted
            || self.other_obligations != other
            || self.unallocated_surplus != surplus
            || self.minted_redemption_backing != self.mint_acknowledged.min(free)
        {
            return Err(OwnerlessConversionErrorV3::Accounting);
        }
        Ok(())
    }
}

/// New, separate proof role; nesting the old checkpoint/supply layout does
/// not turn an old receipt into this statement. The source must prove complete
/// Elements/BMM state plus custody-bound V2 burn/M6/redemption semantics.
/// The complete source producer for this role is a remaining integration gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessElementsPublicValuesV3 {
    pub version: u8,
    pub role: Hash32,
    pub common: UsddElementsSourcePublicValuesV2,
    pub custody_id: Hash32,
    pub redemption_binding_commitment: Hash32,
}

impl OwnerlessElementsPublicValuesV3 {
    pub fn required_role() -> Hash32 {
        tagged_hash(
            "ECX/usdd-ownerless-elements-role/v3",
            b"complete-state/custody-bound-v2-burn-m6-redemption",
        )
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        out.extend_from_slice(&self.role);
        out.extend_from_slice(&self.common.canonical_bytes());
        out.extend_from_slice(&self.custody_id);
        out.extend_from_slice(&self.redemption_binding_commitment);
        debug_assert_eq!(out.len(), OWNERLESS_ELEMENTS_PUBLIC_VALUES_LEN_V3);
        out
    }
    pub fn validate_shape(&self) -> Result<(), OwnerlessConversionErrorV3> {
        if self.version != 3
            || self.role != Self::required_role()
            || self.custody_id == [0; 32]
            || self.redemption_binding_commitment == [0; 32]
        {
            return Err(OwnerlessConversionErrorV3::ElementsRole);
        }
        if self.common.outstanding_usdd_atoms == 0 {
            return Err(OwnerlessConversionErrorV3::ZeroSupply);
        }
        self.common
            .validate_shape()
            .map_err(|_| OwnerlessConversionErrorV3::ElementsStatement)
    }
}

/// These program/configuration bindings require an actual reviewed strong
/// V2 redemption implementation; a Rust claim codec is not that proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessRedemptionBindingV3 {
    pub strong_redemption_program_id: Hash32,
    pub strong_redemption_configuration_hash: Hash32,
    pub covenant_script_commitment: Hash32,
}
impl OwnerlessRedemptionBindingV3 {
    pub fn commitment(&self, source: &OwnerlessSourceConfigurationV3) -> Hash32 {
        let mut bytes = source.canonical_bytes();
        bytes.extend_from_slice(&self.strong_redemption_program_id);
        bytes.extend_from_slice(&self.strong_redemption_configuration_hash);
        bytes.extend_from_slice(&self.covenant_script_commitment);
        bytes.extend_from_slice(&USDD_ATOMS_PER_RESERVE_ATOM.to_be_bytes());
        tagged_hash("ECX/usdd-ownerless-redemption-binding/v3", &bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenOwnerlessConversionConfigurationV3 {
    pub version: u8,
    pub source: OwnerlessSourceConfigurationV3,
    pub protocol_manifest_commitment: Hash32,
    pub ethereum_source_program_id: Hash32,
    pub elements_source_program_id: Hash32,
    pub elements_source_configuration_commitment: Hash32,
    pub elements_source_bootstrap_commitment: Hash32,
    pub checkpoint_authority_configuration_hash: Hash32,
    pub redemption: OwnerlessRedemptionBindingV3,
    pub maximum_age_seconds: u64,
}

impl FrozenOwnerlessConversionConfigurationV3 {
    pub fn validate(&self) -> Result<(), OwnerlessConversionErrorV3> {
        self.source.validate()?;
        // These are three distinct proof relations. A nonzero identifier is
        // insufficient: binding redemption to a source guest must not produce
        // an apparently valid frozen configuration or checkpoint commitment.
        let programs = [
            self.ethereum_source_program_id,
            self.elements_source_program_id,
            self.redemption.strong_redemption_program_id,
        ];
        if programs.iter().enumerate().any(|(i, program)| programs[..i].contains(program)) {
            return Err(OwnerlessConversionErrorV3::Configuration);
        }
        if self.version != 3
            || self.maximum_age_seconds == 0
            || [
                self.protocol_manifest_commitment,
                self.ethereum_source_program_id,
                self.elements_source_program_id,
                self.elements_source_configuration_commitment,
                self.elements_source_bootstrap_commitment,
                self.checkpoint_authority_configuration_hash,
                self.redemption.strong_redemption_program_id,
                self.redemption.strong_redemption_configuration_hash,
                self.redemption.covenant_script_commitment,
            ]
            .contains(&[0; 32])
        {
            return Err(OwnerlessConversionErrorV3::Configuration);
        }
        self.checkpoint_configuration()
            .validate()
            .map_err(|_| OwnerlessConversionErrorV3::Configuration)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        out.extend_from_slice(&self.source.canonical_bytes());
        for h in [
            self.protocol_manifest_commitment,
            self.ethereum_source_program_id,
            self.elements_source_program_id,
            self.elements_source_configuration_commitment,
            self.elements_source_bootstrap_commitment,
            self.checkpoint_authority_configuration_hash,
            self.redemption.strong_redemption_program_id,
            self.redemption.strong_redemption_configuration_hash,
            self.redemption.covenant_script_commitment,
        ] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&self.maximum_age_seconds.to_be_bytes());
        out
    }
    pub fn commitment(&self) -> Result<Hash32, OwnerlessConversionErrorV3> {
        self.validate()?;
        Ok(tagged_hash(
            "ECX/usdd-usd-ownerless-frozen-configuration/v3",
            &self.canonical_bytes(),
        ))
    }
    pub fn checkpoint_configuration(&self) -> UsddCheckpointConfigV1 {
        UsddCheckpointConfigV1 {
            version: UsddCheckpointConfigV1::VERSION,
            ethereum_light_client_configuration_hash: self
                .source
                .ethereum_light_client_configuration_hash,
            authority_configuration_hash: self.checkpoint_authority_configuration_hash,
            maximum_checkpoint_age_seconds: self.maximum_age_seconds,
        }
    }
    pub fn redemption_covenant_commitment(&self) -> Hash32 {
        self.redemption.commitment(&self.source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerlessConversionInputV3 {
    pub version: u8,
    pub frozen_configuration: FrozenOwnerlessConversionConfigurationV3,
    /// Existing 275-byte final ABI, under a NEW conversion guest identity and
    /// V3 configuration commitment. This does not change the old V2 program.
    pub public_values: ConversionLegPublicValuesV2,
    pub ethereum_public_values: OwnerlessEthereumPublicValuesV3,
    pub ethereum_proof_marker: Vec<u8>,
    pub elements_public_values: OwnerlessElementsPublicValuesV3,
    pub elements_proof_marker: Vec<u8>,
    pub covenant_script_preimage: Vec<u8>,
}
impl OwnerlessConversionInputV3 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnerlessConversionErrorV3> {
        let bytes = options()
            .serialize(self)
            .map_err(|_| OwnerlessConversionErrorV3::Encoding)?;
        if bytes.len() > MAX_INPUT {
            return Err(OwnerlessConversionErrorV3::Encoding);
        }
        Ok(bytes)
    }
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, OwnerlessConversionErrorV3> {
        if bytes.is_empty() || bytes.len() > MAX_INPUT {
            return Err(OwnerlessConversionErrorV3::Encoding);
        }
        let value: Self = options()
            .deserialize(bytes)
            .map_err(|_| OwnerlessConversionErrorV3::Encoding)?;
        if value.canonical_bytes()? != bytes {
            return Err(OwnerlessConversionErrorV3::Encoding);
        }
        value.validate_envelope()?;
        Ok(value)
    }
    pub fn validate_envelope(&self) -> Result<(), OwnerlessConversionErrorV3> {
        if self.version != 3
            || self.public_values.version != 2
            || self.public_values.kind != ConversionLegKindV2::UsddUsd
            || self.ethereum_proof_marker.len() != 32
            || self.elements_proof_marker.len() != 32
            || self.covenant_script_preimage.is_empty()
            || self.covenant_script_preimage.len() > MAX_PREIMAGE
        {
            return Err(OwnerlessConversionErrorV3::Envelope);
        }
        self.frozen_configuration.validate()?;
        self.ethereum_public_values.validate_shape()?;
        self.elements_public_values.validate_shape()
    }
}

/// Production callers must implement both methods with genuine proof
/// verification for the frozen IDs and byte-exact statements. No host flag,
/// mock codec check, or legacy-receipt fallback is part of this API.
pub trait OwnerlessSourceReceiptVerifierV3 {
    fn verify_ethereum(
        &self,
        program: Hash32,
        statement: &[u8],
        marker: &[u8],
    ) -> Result<(), OwnerlessConversionErrorV3>;
    fn verify_elements_v2_redemption(
        &self,
        program: Hash32,
        statement: &[u8],
        marker: &[u8],
    ) -> Result<(), OwnerlessConversionErrorV3>;
}

pub fn execute_ownerless_conversion_v3<V: OwnerlessSourceReceiptVerifierV3>(
    input: &OwnerlessConversionInputV3,
    verifier: &V,
) -> Result<Vec<u8>, OwnerlessConversionErrorV3> {
    input.validate_envelope()?;
    let c = &input.frozen_configuration;
    let e = &input.ethereum_public_values;
    let l = &input.elements_public_values.common;
    if e.frozen_configuration_commitment != c.source.commitment()
        || e.protocol_manifest_commitment != c.protocol_manifest_commitment
        || tagged_hash(
            "ECX/usdd-ownerless-covenant-script/v3",
            &input.covenant_script_preimage,
        ) != c.redemption.covenant_script_commitment
        || input.elements_public_values.custody_id != c.source.custody_id
        || input.elements_public_values.redemption_binding_commitment
            != c.redemption_covenant_commitment()
    {
        return Err(OwnerlessConversionErrorV3::Binding);
    }
    verifier.verify_ethereum(
        c.ethereum_source_program_id,
        &e.canonical_bytes(),
        &input.ethereum_proof_marker,
    )?;
    verifier.verify_elements_v2_redemption(
        c.elements_source_program_id,
        &input.elements_public_values.canonical_bytes(),
        &input.elements_proof_marker,
    )?;
    e.validate_accounting()?;
    let checkpoint = checkpoint_from_elements(l);
    checkpoint
        .validate(&c.checkpoint_configuration())
        .map_err(|_| OwnerlessConversionErrorV3::Checkpoint)?;
    if l.elements_genesis_hash != c.source.elements_genesis_hash
        || l.elements_source_configuration_commitment != c.elements_source_configuration_commitment
        || l.elements_source_bootstrap_commitment != c.elements_source_bootstrap_commitment
        || l.usdd_checkpoint_configuration_hash != c.checkpoint_configuration().digest()
        || l.checkpoint_update_proof_commitment != e.update_proof_commitment
        || l.current_checkpoint_commitment != checkpoint.commitment()
        || l.checkpoint_accepted_parent_mtp > l.observed_parent_mtp
        || l.usdd_asset_id != c.source.usdd_asset_id
        || l.redemption_covenant_commitment != c.redemption_covenant_commitment()
        || !l.redemption_covenant_live
        || l.checkpoint_finalized_beacon_slot != e.finalized_beacon_slot
        || l.checkpoint_finalized_beacon_root != e.finalized_beacon_root
        || l.checkpoint_execution_block_hash != e.finalized_execution_block_hash
        || l.checkpoint_execution_state_root != e.finalized_execution_state_root
        || l.checkpoint_execution_block_number != e.execution_block_number
        || l.checkpoint_execution_timestamp != e.execution_block_timestamp
        || l.checkpoint_light_client_digest != e.light_client_digest
        || l.prior_checkpoint_light_client_digest != e.prior_light_client_digest
        || l.prior_checkpoint_finalized_beacon_slot != e.prior_finalized_beacon_slot
        || l.prior_checkpoint_finalized_beacon_root != e.prior_finalized_beacon_root
        || l.prior_checkpoint_execution_state_root != e.prior_finalized_execution_state_root
    {
        return Err(OwnerlessConversionErrorV3::Checkpoint);
    }
    // No rounding away liability. Zero supply is unsupported by the existing
    // final conversion relation, and is deliberately rejected here as well.
    if l.outstanding_usdd_atoms == 0 {
        return Err(OwnerlessConversionErrorV3::ZeroSupply);
    }
    if l.outstanding_usdd_atoms % USDD_ATOMS_PER_RESERVE_ATOM != 0 {
        return Err(OwnerlessConversionErrorV3::InexactLiability);
    }
    let backing = word_to_u128(e.minted_redemption_backing)?;
    if backing < l.outstanding_usdd_atoms / USDD_ATOMS_PER_RESERVE_ATOM {
        return Err(OwnerlessConversionErrorV3::ReserveShortfall);
    }
    let reserve_quote = backing
        .checked_mul(USDD_ATOMS_PER_RESERVE_ATOM)
        .ok_or(OwnerlessConversionErrorV3::Arithmetic)?;
    let valid_until = e
        .execution_block_timestamp
        .checked_add(c.maximum_age_seconds)
        .ok_or(OwnerlessConversionErrorV3::Arithmetic)?;
    if e.execution_block_timestamp > l.observed_parent_mtp || l.observed_parent_mtp > valid_until {
        return Err(OwnerlessConversionErrorV3::StaleCheckpoint);
    }
    let expected = ConversionLegPublicValuesV2 {
        version: 2,
        kind: ConversionLegKindV2::UsddUsd,
        observed_parent_block_hash: l.observed_parent_block_hash,
        observed_parent_height: l.observed_parent_height,
        observed_parent_mtp: l.observed_parent_mtp,
        source_height: e.execution_block_number,
        source_mtp: e.execution_block_timestamp,
        valid_until_mtp: valid_until,
        base_asset_id: c.source.usdd_asset_id,
        quote_unit_id: c.source.ethereum_light_client_configuration_hash,
        redemption_covenant_commitment: c.redemption_covenant_commitment(),
        source_checkpoint_commitment: c.commitment()?,
        source_state_root: ownerless_source_state_root_v3(&input.elements_public_values, e),
        quote_atoms_per_whole_base: PRICE_SCALE,
        outstanding_base_atoms: l.outstanding_usdd_atoms,
        redeemable_reserve_quote_atoms: reserve_quote,
        redemption_enabled: true,
    };
    if input.public_values != expected {
        return Err(OwnerlessConversionErrorV3::PublicValues);
    }
    Ok(expected.canonical_bytes())
}

pub fn ownerless_source_state_root_v3(
    l: &OwnerlessElementsPublicValuesV3,
    e: &OwnerlessEthereumPublicValuesV3,
) -> Hash32 {
    let mut bytes = l.canonical_bytes();
    bytes.extend_from_slice(&e.canonical_bytes());
    tagged_hash("ECX/usdd-usd-ownerless-source-state/v3", &bytes)
}

fn checkpoint_from_elements(l: &UsddElementsSourcePublicValuesV2) -> UsddEthereumCheckpointV1 {
    UsddEthereumCheckpointV1 {
        version: UsddEthereumCheckpointV1::VERSION,
        configuration_hash: l.usdd_checkpoint_configuration_hash,
        sequence: l.checkpoint_sequence,
        light_client_digest: l.checkpoint_light_client_digest,
        finalized_beacon_slot: l.checkpoint_finalized_beacon_slot,
        finalized_beacon_root: l.checkpoint_finalized_beacon_root,
        finalized_execution_block_hash: l.checkpoint_execution_block_hash,
        finalized_execution_state_root: l.checkpoint_execution_state_root,
        finalized_execution_block_number: l.checkpoint_execution_block_number,
        finalized_execution_timestamp: l.checkpoint_execution_timestamp,
        accepted_parent_mtp: l.checkpoint_accepted_parent_mtp,
        prior_checkpoint_commitment: l.prior_checkpoint_commitment,
        update_proof_commitment: l.checkpoint_update_proof_commitment,
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_INPUT as u64)
}
fn add256(a: Hash32, b: Hash32) -> Result<Hash32, OwnerlessConversionErrorV3> {
    let mut out = [0; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let x = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = x as u8;
        carry = x >> 8;
    }
    if carry != 0 {
        return Err(OwnerlessConversionErrorV3::Arithmetic);
    }
    Ok(out)
}
fn sum256(values: &[Hash32]) -> Result<Hash32, OwnerlessConversionErrorV3> {
    values
        .iter()
        .try_fold([0; 32], |total, value| add256(total, *value))
}
fn sub256(a: Hash32, b: Hash32) -> Result<Hash32, OwnerlessConversionErrorV3> {
    if a < b {
        return Err(OwnerlessConversionErrorV3::ReserveShortfall);
    }
    let mut out = [0; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let x = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = x as u8;
        borrow = i16::from(x < 0);
    }
    Ok(out)
}
fn word_to_u128(word: Hash32) -> Result<u128, OwnerlessConversionErrorV3> {
    if word[..16] != [0; 16] {
        return Err(OwnerlessConversionErrorV3::Arithmetic);
    }
    Ok(u128::from_be_bytes(
        word[16..].try_into().expect("fixed 16-byte tail"),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OwnerlessConversionErrorV3 {
    #[error("noncanonical or resource-exceeding ownerless input")]
    Encoding,
    #[error("invalid ownerless input envelope")]
    Envelope,
    #[error("invalid or incomplete ownerless frozen configuration")]
    Configuration,
    #[error("invalid version-3 authenticated Ethereum statement")]
    EthereumStatement,
    #[error("legacy or wrong-role Elements statement cannot prove V2 redemption")]
    ElementsRole,
    #[error("invalid complete Elements source statement")]
    ElementsStatement,
    #[error("frozen custody, script, manifest, or source configuration mismatch")]
    Binding,
    #[error("Ethereum source proof rejected")]
    EthereumProof,
    #[error("custody-bound V2 Elements redemption source proof rejected")]
    ElementsProof,
    #[error("authenticated ownerless accounting identities disagree")]
    Accounting,
    #[error("authenticated prior/current cross-chain checkpoints disagree")]
    Checkpoint,
    #[error("zero outstanding supply is unsupported by the conversion relation")]
    ZeroSupply,
    #[error("USDD atom liability does not map to integral six-decimal reserve atoms")]
    InexactLiability,
    #[error("authenticated minted backing is insufficient")]
    ReserveShortfall,
    #[error("checked monetary or timestamp arithmetic overflow")]
    Arithmetic,
    #[error("authenticated Ethereum checkpoint is stale or from the future")]
    StaleCheckpoint,
    #[error("final conversion public values are not byte-exact derived results")]
    PublicValues,
}

#[cfg(test)]
mod tests;
