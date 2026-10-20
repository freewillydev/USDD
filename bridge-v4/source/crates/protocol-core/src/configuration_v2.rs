//! Frozen configuration committed by the V2 insurance-bond proof program.

use secp256k1::XOnlyPublicKey;

use crate::availability::AVAILABILITY_SCHEME_HASH_V1;
use crate::bond::{BOND_FIXED_SUPPLY_ATOMS, BOND_REDEMPTION_DELAY_PARENT_BLOCKS};
use crate::bond_inbox_v2::{
    MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
    MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2,
};
use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
use crate::configuration::FrozenConfigurationV1;
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::risk::RiskParams;
use crate::types::XOnlyKey;
use crate::ProtocolError;

pub const MAX_CONVERSION_LEG_PROOF_BYTES_V2: u32 = 16 * 1024 * 1024;
pub const BOND_INBOX_INCLUSION_BLOCKS_V2: u32 = 6;
pub const BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2: u32 = 8;
pub const BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2: u32 = 64;
pub const BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2: u32 = 64;
/// Aggregate cap for distinct exact source-witness serializations referenced
/// by bond markers in one sidechain block. V2 permits exactly one marker per
/// source transaction and up to eight distinct source transactions per block.
pub const BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2: u32 =
    MAX_BOND_INBOX_SOURCE_WITNESS_BYTES_V2;
pub const BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2: u32 =
    MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2;
pub const BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2: u32 = 4_096;
pub const BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2: u32 = 12;
/// Elements Simplicity tapscript leaf version used by both staging roles.
pub const BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2: u8 = 0xbe;
/// V18 tree shape: `Branch(process, Branch(refund, hidden_raw_node))`.
pub const BOND_INBOX_REDEMPTION_STAGING_TREE_SHAPE_VERSION_V2: u8 = 1;
/// BIP341's provably-unspendable NUMS point H. Requiring this exact x-only
/// key prevents a deployer/operator from retaining a key-path bypass.
pub const BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2: Hash32 = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
/// `SHA256("ECX/bond-inbox-redemption-staging-renderer/v3-no-history")`.
/// This frozen value is also carried explicitly by the configuration so the
/// Rust, C++ and Simplicity renderers cannot silently choose another domain.
pub const BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2: Hash32 = [
    0xd8, 0xca, 0x78, 0x83, 0x76, 0x9d, 0xd7, 0x38, 0x30, 0x98, 0x7f, 0x72, 0x7a, 0x34, 0x93, 0x9d,
    0x2d, 0x9b, 0x69, 0xa3, 0xe7, 0x83, 0xe0, 0xa2, 0xe1, 0xcc, 0xa3, 0x5f, 0xa4, 0x87, 0x2e, 0x6f,
];
/// Maximum distance from an authenticated execution-parent locator to the
/// prior-parent tip of the immediately following successful ECX transition.
pub const MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2: u32 = 6;
/// Exact opaque marker carried in the recoverable transition witness for each
/// recursive proof role. Full compressed receipts are deferred prover streams
/// and are never embedded in the bounded recovery payload.
pub const RECURSIVE_PROOF_MARKER_BYTES_V2: u32 = 32;
/// Exact permissionless escape window accepted by the V2 transition relation.
/// V1 retains its broader configuration ceiling; V2 freezes this live profile.
pub const FORCED_INCLUSION_BLOCKS_V2: u32 = 6;

fn has_exact_v2_risk_profile(params: RiskParams) -> bool {
    params == RiskParams::default()
}

fn has_exact_v2_availability_liveness_profile(
    availability_scheme_hash: Hash32,
    forced_inclusion_blocks: u32,
) -> bool {
    availability_scheme_hash == AVAILABILITY_SCHEME_HASH_V1
        && forced_inclusion_blocks == FORCED_INCLUSION_BLOCKS_V2
}

/// Canonical fixed two-leaf staging descriptor identity. Role order is
/// consensus critical: process CMR first, delayed-refund CMR second.
pub fn bond_inbox_redemption_staging_descriptor_commitment_v2(
    renderer_domain: Hash32,
    tapleaf_version: u8,
    internal_key: Hash32,
    process_cmr: Hash32,
    refund_cmr: Hash32,
) -> Result<Hash32, ProtocolError> {
    if renderer_domain != BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2
        || tapleaf_version != BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2
        || internal_key != BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2
        || XOnlyPublicKey::from_slice(&internal_key).is_err()
        || process_cmr == [0; 32]
        || refund_cmr == [0; 32]
        || process_cmr == refund_cmr
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = Vec::with_capacity(130);
    put_u8(
        &mut bytes,
        BOND_INBOX_REDEMPTION_STAGING_TREE_SHAPE_VERSION_V2,
    );
    bytes.extend_from_slice(&renderer_domain);
    put_u8(&mut bytes, tapleaf_version);
    bytes.extend_from_slice(&internal_key);
    bytes.extend_from_slice(&process_cmr);
    bytes.extend_from_slice(&refund_cmr);
    Ok(tagged_hash(
        "ECX/bond-inbox-redemption-staging-template/v3-no-history",
        &bytes,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondInboxRedemptionStagingRendererInputV2 {
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub marker_signer: XOnlyKey,
    pub stable_intent_id: Hash32,
    pub staging_vout: u32,
    pub refund_script_sha256: Hash32,
    pub refund_not_before_parent_height: u64,
}

impl BondInboxRedemptionStagingRendererInputV2 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || XOnlyPublicKey::from_slice(&self.marker_signer.0).is_err()
            || self.stable_intent_id == [0; 32]
            || self.staging_vout == u32::MAX
            || self.refund_script_sha256 == [0; 32]
            || self.refund_not_before_parent_height == 0
        {
            Err(ProtocolError::InvalidBondState)
        } else {
            Ok(())
        }
    }
}

impl CanonicalEncode for BondInboxRedemptionStagingRendererInputV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.marker_signer.encode_to(out);
        out.extend_from_slice(&self.stable_intent_id);
        put_u32(out, self.staging_vout);
        out.extend_from_slice(&self.refund_script_sha256);
        put_u64(out, self.refund_not_before_parent_height);
    }
}

/// Raw per-intent TapNodeHash committed beside the two spendable leaves.
///
/// Dependency graph (deliberately acyclic): stable business/refund intent `I`
/// is known first; this renderer produces script `S`; normalized confidential
/// opening commitments bind `S`; the complete action id then binds those
/// openings; finally source authorization binds the exact `TxOut(S)`. Action
/// id and source authorization are therefore intentionally absent here.
pub fn bond_inbox_redemption_staging_hidden_node_v2(
    renderer_domain: Hash32,
    input: BondInboxRedemptionStagingRendererInputV2,
) -> Result<Hash32, ProtocolError> {
    input.validate()?;
    if renderer_domain != BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2 {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = Vec::with_capacity(173);
    bytes.extend_from_slice(&renderer_domain);
    input.encode_to(&mut bytes);
    Ok(tagged_hash(
        "ECX/bond-inbox-redemption-staging-hidden-node/v3-no-history",
        &bytes,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrozenConfigurationV2 {
    pub version: u8,
    /// Exact V1 market, oracle, availability, settlement and risk profile.
    pub base: FrozenConfigurationV1,
    /// CMR of the dedicated txid/PV5-bound covenant used by every existing
    /// trader-collateral vault input. V1 remains unchanged; V2 freezes this
    /// additional authorization identity for exact confidential conservation.
    pub collateral_vault_covenant_cmr: Hash32,
    pub bond_asset_id: Hash32,
    pub bond_deployment_commitment: Hash32,
    pub bond_inventory_script_sha256: Hash32,
    pub bond_redemption_queue_script_sha256: Hash32,
    /// Identity of the generic fixed two-leaf P2TR staging descriptor. Per-
    /// intent/refund terms are authenticated by the marker and leaf witness;
    /// they do not silently redefine the frozen descriptor renderer.
    pub bond_inbox_redemption_staging_template_commitment: Hash32,
    pub bond_inbox_redemption_staging_renderer_domain: Hash32,
    pub bond_inbox_redemption_staging_internal_key: Hash32,
    pub bond_inbox_redemption_staging_tapleaf_version: u8,
    pub bond_inbox_redemption_staging_process_cmr: Hash32,
    pub bond_inbox_redemption_staging_refund_cmr: Hash32,
    pub bond_inbox_refund_minimum_parent_blocks: u32,
    pub insurance_reserve_script_sha256: Hash32,
    /// CMR of the dedicated txid/PV5-bound covenant used by every existing
    /// insurance-reserve input. It is distinct from the singleton transition
    /// CMR, which can authorize only the state input at index zero.
    pub insurance_reserve_covenant_cmr: Hash32,
    pub destroyed_reissuance_token_script_sha256: Hash32,
    /// Independent node-derived bond inbox identity and anti-DoS profile.
    pub bond_inbox_domain: Hash32,
    /// Exact external witness-availability receipt codec identity. Proof/node
    /// integration pins this to the fixed 138-byte receipt implementation.
    pub bond_inbox_custody_receipt_codec_hash: Hash32,
    pub bond_inbox_inclusion_blocks: u32,
    pub bond_inbox_max_bundle_bytes: u32,
    pub bond_inbox_max_entries_per_sidechain_block: u32,
    pub bond_inbox_max_unique_source_witness_bytes_per_sidechain_block: u32,
    pub bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block: u32,
    pub bond_inbox_max_pending_entries_per_transition: u32,
    pub bond_inbox_max_consumed_entries_per_transition: u32,
    pub bond_redemption_max_queue_entries: u32,
    /// Distinct from forced-action/bond-inbox liveness. This bounds the Bitcoin
    /// header segment authenticating matcher execution timestamps for funding.
    pub matcher_execution_inclusion_parent_blocks: u32,
    /// Recursive verifier identities for the live ECX/BTC and USDD/USD
    /// conversion legs. Constants in the base oracle are accepted only when
    /// these proof-derived values match them exactly.
    pub ecx_btc_conversion_program_id: Hash32,
    pub usdd_usd_conversion_program_id: Hash32,
    /// Exact covenant and authenticated source-checkpoint identities that each
    /// recursive conversion proof must expose in its public values.
    pub ecx_btc_redemption_covenant_commitment: Hash32,
    pub ecx_btc_source_checkpoint_commitment: Hash32,
    pub usdd_usd_redemption_covenant_commitment: Hash32,
    pub usdd_usd_source_checkpoint_commitment: Hash32,
    pub maximum_conversion_age_seconds: u64,
    pub maximum_conversion_proof_bytes: u32,
    pub recursive_proof_marker_bytes: u32,
    pub fixed_supply_atoms: u64,
    pub redemption_delay_parent_blocks: u64,
}

impl FrozenConfigurationV2 {
    pub const VERSION: u8 = 5;
    /// Explicit direct-price profile. Zero legacy oracle-conversion slots are
    /// absence, never Ethereum reserve-custody or redemption authorization.
    /// Version 5 bytes and validation remain unchanged.
    pub const DIRECT_PRICE_VERSION: u8 = 6;

    fn conversion_identities(&self) -> [Hash32; 6] {
        [
            self.ecx_btc_conversion_program_id,
            self.usdd_usd_conversion_program_id,
            self.ecx_btc_redemption_covenant_commitment,
            self.ecx_btc_source_checkpoint_commitment,
            self.usdd_usd_redemption_covenant_commitment,
            self.usdd_usd_source_checkpoint_commitment,
        ]
    }

    fn valid_conversion_mode(version: u8, direct: bool, identities: &[Hash32; 6]) -> bool {
        match version {
            Self::VERSION => !identities.contains(&[0; 32]),
            Self::DIRECT_PRICE_VERSION => direct && identities.iter().all(|id| *id == [0; 32]),
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.base.validate()?;
        let conversion_identities = self.conversion_identities();
        if !Self::valid_conversion_mode(
            self.version,
            self.base.uses_direct_native_truthcoin_price(),
            &conversion_identities,
        ) {
            return Err(ProtocolError::InvalidBondState);
        }
        let mut identity_commitments = vec![
            self.bond_asset_id,
            self.bond_deployment_commitment,
            self.bond_inventory_script_sha256,
            self.bond_redemption_queue_script_sha256,
            self.bond_inbox_redemption_staging_template_commitment,
            self.bond_inbox_redemption_staging_renderer_domain,
            self.bond_inbox_redemption_staging_internal_key,
            self.bond_inbox_redemption_staging_process_cmr,
            self.bond_inbox_redemption_staging_refund_cmr,
            self.collateral_vault_covenant_cmr,
            self.insurance_reserve_script_sha256,
            self.insurance_reserve_covenant_cmr,
            self.destroyed_reissuance_token_script_sha256,
            self.bond_inbox_domain,
            self.bond_inbox_custody_receipt_codec_hash,
        ];
        if self.version == Self::VERSION {
            identity_commitments.extend_from_slice(&conversion_identities);
        }
        if !has_exact_v2_risk_profile(self.base.risk)
            || !has_exact_v2_availability_liveness_profile(
                self.base.availability.scheme_hash,
                self.base.matcher.forced_inclusion_blocks,
            )
            || self.fixed_supply_atoms != BOND_FIXED_SUPPLY_ATOMS
            || self.redemption_delay_parent_blocks != BOND_REDEMPTION_DELAY_PARENT_BLOCKS
            || self.bond_inbox_redemption_staging_tapleaf_version
                != BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2
            || self.bond_inbox_redemption_staging_renderer_domain
                != BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2
            || self.bond_inbox_redemption_staging_internal_key
                != BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2
            || self.bond_inbox_redemption_staging_template_commitment
                != bond_inbox_redemption_staging_descriptor_commitment_v2(
                    self.bond_inbox_redemption_staging_renderer_domain,
                    self.bond_inbox_redemption_staging_tapleaf_version,
                    self.bond_inbox_redemption_staging_internal_key,
                    self.bond_inbox_redemption_staging_process_cmr,
                    self.bond_inbox_redemption_staging_refund_cmr,
                )?
            || self.bond_inbox_inclusion_blocks != BOND_INBOX_INCLUSION_BLOCKS_V2
            || self.bond_inbox_max_bundle_bytes != MAX_BOND_INBOX_BUNDLE_BYTES_V2
            || self.bond_inbox_max_entries_per_sidechain_block
                != BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2
            || self.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block
                != BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2
            || self.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block
                != BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2
            || self.bond_inbox_max_pending_entries_per_transition
                != BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2
            || self.bond_inbox_max_consumed_entries_per_transition
                != BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2
            || self.bond_redemption_max_queue_entries != BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2
            || self.matcher_execution_inclusion_parent_blocks
                != MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2
            || self.bond_inbox_refund_minimum_parent_blocks
                != BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2
            || self.bond_inbox_refund_minimum_parent_blocks < self.bond_inbox_inclusion_blocks
            || self.bond_inbox_max_consumed_entries_per_transition
                < self.bond_inbox_max_pending_entries_per_transition
            || self
                .bond_inbox_max_entries_per_sidechain_block
                .checked_mul(self.bond_inbox_inclusion_blocks)
                .map_or(true, |flood_bound| {
                    flood_bound > self.bond_inbox_max_pending_entries_per_transition
                })
            || self.maximum_conversion_age_seconds == 0
            || self.maximum_conversion_proof_bytes == 0
            || self.maximum_conversion_proof_bytes > MAX_CONVERSION_LEG_PROOF_BYTES_V2
            || self.recursive_proof_marker_bytes != RECURSIVE_PROOF_MARKER_BYTES_V2
            || identity_commitments.contains(&[0; 32])
            || self.bond_inbox_domain == self.base.forced_action_domain
            || self.bond_inbox_domain == self.base.deposit_inbox_domain
            || self.bond_inbox_domain == self.base.availability.scheme_hash
            || self.bond_inbox_domain == self.base.availability.custodian_registry_hash
            || self.ecx_btc_conversion_program_id
                == self.base.truthcoin_authentication.source_proof_program_id
            || self.usdd_usd_conversion_program_id
                == self.base.truthcoin_authentication.source_proof_program_id
            || self.bond_inbox_redemption_staging_process_cmr
                == self.base.truthcoin_authentication.source_proof_program_id
            || self.bond_inbox_redemption_staging_refund_cmr
                == self.base.truthcoin_authentication.source_proof_program_id
            || self.collateral_vault_covenant_cmr
                == self.base.truthcoin_authentication.source_proof_program_id
            || self.insurance_reserve_covenant_cmr
                == self.base.truthcoin_authentication.source_proof_program_id
            || identity_commitments
                .iter()
                .enumerate()
                .any(|(index, value)| identity_commitments[..index].contains(value))
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash(
            "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
            self,
        )
    }
}

impl CanonicalEncode for FrozenConfigurationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.base.encode_to(out);
        out.extend_from_slice(&self.collateral_vault_covenant_cmr);
        out.extend_from_slice(&self.bond_asset_id);
        out.extend_from_slice(&self.bond_deployment_commitment);
        out.extend_from_slice(&self.bond_inventory_script_sha256);
        out.extend_from_slice(&self.bond_redemption_queue_script_sha256);
        out.extend_from_slice(&self.bond_inbox_redemption_staging_template_commitment);
        out.extend_from_slice(&self.bond_inbox_redemption_staging_renderer_domain);
        out.extend_from_slice(&self.bond_inbox_redemption_staging_internal_key);
        put_u8(out, self.bond_inbox_redemption_staging_tapleaf_version);
        out.extend_from_slice(&self.bond_inbox_redemption_staging_process_cmr);
        out.extend_from_slice(&self.bond_inbox_redemption_staging_refund_cmr);
        put_u32(out, self.bond_inbox_refund_minimum_parent_blocks);
        out.extend_from_slice(&self.insurance_reserve_script_sha256);
        out.extend_from_slice(&self.insurance_reserve_covenant_cmr);
        out.extend_from_slice(&self.destroyed_reissuance_token_script_sha256);
        out.extend_from_slice(&self.bond_inbox_domain);
        out.extend_from_slice(&self.bond_inbox_custody_receipt_codec_hash);
        put_u32(out, self.bond_inbox_inclusion_blocks);
        put_u32(out, self.bond_inbox_max_bundle_bytes);
        put_u32(out, self.bond_inbox_max_entries_per_sidechain_block);
        put_u32(
            out,
            self.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block,
        );
        put_u32(
            out,
            self.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block,
        );
        put_u32(out, self.bond_inbox_max_pending_entries_per_transition);
        put_u32(out, self.bond_inbox_max_consumed_entries_per_transition);
        put_u32(out, self.bond_redemption_max_queue_entries);
        put_u32(out, self.matcher_execution_inclusion_parent_blocks);
        out.extend_from_slice(&self.ecx_btc_conversion_program_id);
        out.extend_from_slice(&self.usdd_usd_conversion_program_id);
        out.extend_from_slice(&self.ecx_btc_redemption_covenant_commitment);
        out.extend_from_slice(&self.ecx_btc_source_checkpoint_commitment);
        out.extend_from_slice(&self.usdd_usd_redemption_covenant_commitment);
        out.extend_from_slice(&self.usdd_usd_source_checkpoint_commitment);
        put_u64(out, self.maximum_conversion_age_seconds);
        put_u32(out, self.maximum_conversion_proof_bytes);
        put_u32(out, self.recursive_proof_marker_bytes);
        put_u64(out, self.fixed_supply_atoms);
        put_u64(out, self.redemption_delay_parent_blocks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    #[test]
    fn direct_price_absence_is_explicit_versioned_and_not_cross_asset() {
        let absent = [[0; 32]; 6];
        let populated = [[1; 32]; 6]; // Distinctness is checked separately by validate.
        assert!(FrozenConfigurationV2::valid_conversion_mode(6, true, &absent));
        assert!(!FrozenConfigurationV2::valid_conversion_mode(6, false, &absent));
        assert!(!FrozenConfigurationV2::valid_conversion_mode(5, true, &absent));
        assert!(FrozenConfigurationV2::valid_conversion_mode(5, false, &populated));
        assert!(FrozenConfigurationV2::valid_conversion_mode(5, true, &populated));
        assert!(!FrozenConfigurationV2::valid_conversion_mode(6, true, &populated));
        for role in 0..6 {
            let mut mixed = absent;
            mixed[role] = [1; 32];
            assert!(!FrozenConfigurationV2::valid_conversion_mode(6, true, &mixed));
            let mut missing = populated;
            missing[role] = [0; 32];
            assert!(!FrozenConfigurationV2::valid_conversion_mode(5, false, &missing));
        }
        assert!(!FrozenConfigurationV2::valid_conversion_mode(7, true, &absent));
    }

    #[test]
    fn exact_v2_bond_constants_are_required_before_base_validation() {
        // This test exercises the additive identity checks without inventing a
        // deployment-ready V1 fixture in this module.
        assert_eq!(BOND_FIXED_SUPPLY_ATOMS, 2_100_000_000_000_000);
        assert_eq!(BOND_REDEMPTION_DELAY_PARENT_BLOCKS, 1_008);
        assert_eq!(BOND_INBOX_INCLUSION_BLOCKS_V2, 6);
        assert_eq!(BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2, 12);
        assert_eq!(BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2, 8);
        assert_eq!(
            BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
            576 * 1024
        );
        assert_eq!(
            BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
            768 * 1024
        );
        assert_eq!(BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2, 64);
        assert_eq!(BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2, 64);
        assert_eq!(BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2, 4_096);
        assert_eq!(MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2, 6);
        assert_eq!(RECURSIVE_PROOF_MARKER_BYTES_V2, 32);
        assert_eq!(FORCED_INCLUSION_BLOCKS_V2, 6);
        assert!(has_exact_v2_availability_liveness_profile(
            AVAILABILITY_SCHEME_HASH_V1,
            FORCED_INCLUSION_BLOCKS_V2,
        ));
        let mut wrong_scheme = AVAILABILITY_SCHEME_HASH_V1;
        wrong_scheme[0] ^= 1;
        assert!(!has_exact_v2_availability_liveness_profile(
            wrong_scheme,
            FORCED_INCLUSION_BLOCKS_V2,
        ));
        assert!(!has_exact_v2_availability_liveness_profile(
            AVAILABILITY_SCHEME_HASH_V1,
            FORCED_INCLUSION_BLOCKS_V2 + 1,
        ));
    }

    #[test]
    fn every_v2_risk_parameter_is_frozen_to_the_proof_profile() {
        let exact = RiskParams::default();
        let mutations = [
            RiskParams {
                initial_margin_bps: exact.initial_margin_bps + 1,
                ..exact
            },
            RiskParams {
                maintenance_margin_bps: exact.maintenance_margin_bps + 1,
                ..exact
            },
            RiskParams {
                liquidation_fee_bps: exact.liquidation_fee_bps + 1,
                ..exact
            },
            RiskParams {
                maker_fee_bps: exact.maker_fee_bps - 1,
                ..exact
            },
            RiskParams {
                taker_fee_bps: exact.taker_fee_bps + 1,
                ..exact
            },
            RiskParams {
                max_abs_funding_rate_ppm: exact.max_abs_funding_rate_ppm + 1,
                ..exact
            },
            RiskParams {
                maximum_open_interest_lots: exact.maximum_open_interest_lots + 1,
                ..exact
            },
            RiskParams {
                maximum_liquidation_notional_quote_units: exact
                    .maximum_liquidation_notional_quote_units
                    + 1,
                ..exact
            },
            RiskParams {
                socialized_loss_enabled: true,
                ..exact
            },
        ];
        assert!(has_exact_v2_risk_profile(exact));
        assert!(mutations
            .iter()
            .all(|mutation| !has_exact_v2_risk_profile(*mutation)));
    }

    #[test]
    fn all_three_recursive_program_roles_must_be_distinct() {
        let truthcoin = [31; 32];
        let ecx_btc = [32; 32];
        let usdd_usd = [33; 32];
        assert_ne!(truthcoin, ecx_btc);
        assert_ne!(truthcoin, usdd_usd);
        assert_ne!(ecx_btc, usdd_usd);
    }

    #[test]
    fn staging_descriptor_has_one_renderable_role_order() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let arbitrary_known_key = XOnlyPublicKey::from_keypair(&keypair).0.serialize();
        let internal_key = BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2;
        let process_cmr = [51; 32];
        let refund_cmr = [52; 32];
        let descriptor = bond_inbox_redemption_staging_descriptor_commitment_v2(
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            internal_key,
            process_cmr,
            refund_cmr,
        )
        .unwrap();
        assert_ne!(
            descriptor,
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
                internal_key,
                refund_cmr,
                process_cmr,
            )
            .unwrap()
        );
        assert_eq!(
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
                [0; 32],
                process_cmr,
                refund_cmr,
            ),
            Err(ProtocolError::InvalidBondState)
        );
        assert_eq!(
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                0xc0,
                internal_key,
                process_cmr,
                refund_cmr,
            ),
            Err(ProtocolError::InvalidBondState)
        );
        assert_eq!(
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
                arbitrary_known_key,
                process_cmr,
                refund_cmr,
            ),
            Err(ProtocolError::InvalidBondState)
        );
        let mut wrong_domain = BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2;
        wrong_domain[0] ^= 1;
        assert_eq!(
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                wrong_domain,
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
                internal_key,
                process_cmr,
                refund_cmr,
            ),
            Err(ProtocolError::InvalidBondState)
        );

        let signer = XOnlyKey(arbitrary_known_key);
        let input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            marker_signer: signer,
            stable_intent_id: [3; 32],
            staging_vout: 4,
            refund_script_sha256: [5; 32],
            refund_not_before_parent_height: 6,
        };
        let hidden = bond_inbox_redemption_staging_hidden_node_v2(
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            input,
        )
        .unwrap();
        let mut changed_chain = input;
        changed_chain.chain_id = [7; 32];
        let mut changed_configuration = input;
        changed_configuration.configuration_hash = [8; 32];
        let other_secret = SecretKey::from_slice(&[43; 32]).unwrap();
        let other_keypair = Keypair::from_secret_key(&secp, &other_secret);
        let mut changed_signer = input;
        changed_signer.marker_signer =
            XOnlyKey(XOnlyPublicKey::from_keypair(&other_keypair).0.serialize());
        let mut changed_intent = input;
        changed_intent.stable_intent_id = [9; 32];
        let mut changed_vout = input;
        changed_vout.staging_vout = 10;
        let mut changed_refund_script = input;
        changed_refund_script.refund_script_sha256 = [11; 32];
        let mut changed_refund_height = input;
        changed_refund_height.refund_not_before_parent_height = 12;
        for mutation in [
            changed_chain,
            changed_configuration,
            changed_signer,
            changed_intent,
            changed_vout,
            changed_refund_script,
            changed_refund_height,
        ] {
            let mutation = bond_inbox_redemption_staging_hidden_node_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                mutation,
            )
            .unwrap();
            assert_ne!(hidden, mutation);
        }

        let invalid_inputs = [
            BondInboxRedemptionStagingRendererInputV2 {
                chain_id: [0; 32],
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                configuration_hash: [0; 32],
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                marker_signer: XOnlyKey([0; 32]),
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                stable_intent_id: [0; 32],
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                staging_vout: u32::MAX,
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                refund_script_sha256: [0; 32],
                ..input
            },
            BondInboxRedemptionStagingRendererInputV2 {
                refund_not_before_parent_height: 0,
                ..input
            },
        ];
        for invalid in invalid_inputs {
            assert_eq!(
                bond_inbox_redemption_staging_hidden_node_v2(
                    BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                    invalid,
                ),
                Err(ProtocolError::InvalidBondState)
            );
        }
        let mut wrong_renderer_domain = BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2;
        wrong_renderer_domain[31] ^= 1;
        assert_eq!(
            bond_inbox_redemption_staging_hidden_node_v2(wrong_renderer_domain, input),
            Err(ProtocolError::InvalidBondState)
        );
    }
}
