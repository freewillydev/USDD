//! Canonical frozen protocol configuration.
//!
//! Deployment JSON is an operator convenience; this fixed-width record is the
//! value actually committed by `configuration_hash` in the singleton state.

use crate::availability::AvailabilityConfigV1;
use crate::codec::{put_u32, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::matcher_receipt::CentralMatcherConfigV1;
use crate::oracle::{HybridOracleConfigV1, TruthcoinAuthenticationConfigV1};
use crate::risk::RiskParams;
use crate::truthcoin_anchor::{truthcoin_anchor_configuration_hash, TruthcoinAnchorDeploymentV1};
use crate::types::{MarketId, ECX_USDD_MARKET, PRICE_SCALE};
use crate::usdd_checkpoint::UsddCheckpointConfigV1;
use crate::ProtocolError;

/// Absolute circuit-facing transition-operation cap. A deployment may choose
/// a smaller value, but never a larger one.
pub const MAX_TRANSITION_ACTIONS: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrozenConfigurationV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub ecx_asset_id: Hash32,
    pub usdd_asset_id: Hash32,
    pub policy_asset_id: Hash32,
    pub state_authority_asset_id: Hash32,
    /// Complete finalized-Ethereum checkpoint policy for USDD collateral.
    pub usdd_checkpoint: UsddCheckpointConfigV1,
    pub risk: RiskParams,
    /// Exact encrypted-witness scheme and ordered 3-of-5 custodian registry.
    pub availability: AvailabilityConfigV1,
    /// Complete source/checkpoint/program trust root for the Truthcoin oracle.
    pub truthcoin_authentication: TruthcoinAuthenticationConfigV1,
    /// Exact Elements singleton asset/value and Taproot/Simplicity tree profile
    /// for the rolling Truthcoin source checkpoint.
    pub truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1,
    pub oracle: HybridOracleConfigV1,
    /// The one configured, non-quorum matcher signer and its receipt-chain origin.
    pub matcher: CentralMatcherConfigV1,
    /// Domain of the Elements forced-action accumulator.
    pub forced_action_domain: Hash32,
    /// Independent domain of the node-derived confidential-deposit accumulator.
    pub deposit_inbox_domain: Hash32,
    /// SHA-256 of the exact frozen collateral-vault script bytes.
    pub collateral_vault_script_sha256: Hash32,
    pub maximum_transition_actions: u32,
}

impl FrozenConfigurationV1 {
    pub const VERSION: u8 = 3;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION || self.market != ECX_USDD_MARKET {
            return Err(ProtocolError::UnsupportedVersion);
        }
        self.market.validate()?;
        self.risk.validate()?;
        self.availability.validate()?;
        self.usdd_checkpoint.validate()?;
        self.truthcoin_authentication.validate()?;
        self.truthcoin_anchor_deployment
            .validate(self.policy_asset_id)?;
        self.oracle.validate()?;
        self.matcher.validate()?;
        if self.truthcoin_authentication.truthcoin_chain_id != self.oracle.truthcoin_chain_id
            || self.truthcoin_authentication.truthcoin_branch_id != self.oracle.truthcoin_branch_id
            || self.truthcoin_authentication.btc_usd_template_hash
                != self.oracle.btc_usd_template_hash
            || self.truthcoin_authentication.lmsr_math_commitment
                != self.oracle.lmsr_math_commitment
            || self.truthcoin_authentication.minimum_bitcoin_confirmations
                < self.oracle.minimum_source_confirmations
        {
            return Err(ProtocolError::InvalidOracleConfiguration);
        }
        // Elements uses the pegged/native asset as the policy (fee) asset unless
        // a deployment explicitly selects a separate fee asset.  ECX is the
        // native asset on the ECX sidechain, so that one alias is canonical.
        // Every other protocol identity must remain distinct.
        let identities_without_policy = [
            self.chain_id,
            self.ecx_asset_id,
            self.usdd_asset_id,
            self.state_authority_asset_id,
            self.usdd_checkpoint
                .ethereum_light_client_configuration_hash,
            self.usdd_checkpoint.authority_configuration_hash,
            self.truthcoin_anchor_deployment.authority_asset_id,
            self.matcher.genesis_receipt_hash,
            self.forced_action_domain,
            self.deposit_inbox_domain,
            self.collateral_vault_script_sha256,
        ];
        let has_duplicate_identity = identities_without_policy
            .iter()
            .enumerate()
            .any(|(index, value)| identities_without_policy[..index].contains(value));
        let policy_asset_collides = self.policy_asset_id != self.ecx_asset_id
            && identities_without_policy.contains(&self.policy_asset_id);
        if identities_without_policy.contains(&[0; 32])
            || self.policy_asset_id == [0; 32]
            || has_duplicate_identity
            || policy_asset_collides
            || self.maximum_transition_actions == 0
            || self.maximum_transition_actions > MAX_TRANSITION_ACTIONS
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/frozen-configuration/v3", self)
    }

    pub fn truthcoin_anchor_configuration_hash(&self) -> Hash32 {
        truthcoin_anchor_configuration_hash(
            &self.truthcoin_authentication,
            &self.truthcoin_anchor_deployment,
            self.policy_asset_id,
        )
    }

    /// Select the proof-native ECX/USDD oracle lane without changing the
    /// frozen configuration wire format.
    ///
    /// The lane is deliberately narrow: ECX must be the Elements policy
    /// asset and both legacy conversion constants must be the exact fixed-
    /// point identity. In that configuration the Truthcoin scalar market is
    /// already denominated in USDD per ECX, so recursive BTC and USD
    /// redemption receipts would be unrelated to the traded pair.
    pub fn uses_direct_native_truthcoin_price(&self) -> bool {
        self.ecx_asset_id == self.policy_asset_id
            && self.oracle.ecx_satoshis_per_coin == PRICE_SCALE
            && self.oracle.usdd_usd_price_units == PRICE_SCALE
    }
}

impl CanonicalEncode for FrozenConfigurationV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.ecx_asset_id);
        out.extend_from_slice(&self.usdd_asset_id);
        out.extend_from_slice(&self.policy_asset_id);
        out.extend_from_slice(&self.state_authority_asset_id);
        self.usdd_checkpoint.encode_to(out);
        self.risk.encode_to(out);
        self.availability.encode_to(out);
        self.truthcoin_authentication.encode_to(out);
        self.truthcoin_anchor_deployment.encode_to(out);
        self.oracle.encode_to(out);
        self.matcher.encode_to(out);
        out.extend_from_slice(&self.forced_action_domain);
        out.extend_from_slice(&self.deposit_inbox_domain);
        out.extend_from_slice(&self.collateral_vault_script_sha256);
        put_u32(out, self.maximum_transition_actions);
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use crate::oracle::PPM_DENOMINATOR;
    use crate::types::{XOnlyKey, PRICE_SCALE};

    #[test]
    fn truthcoin_authority_compiler_parameters_are_bound_and_role_separated() {
        use crate::truthcoin_authority_policy::{TruthcoinAuthoritySourcePolicyV1, PolicyError,
            STATE_DOMAIN, EXECUTION_DOMAIN, KEYLESS_INTERNAL_KEY};
        use sha2::{Digest, Sha256};
        let policy = TruthcoinAuthoritySourcePolicyV1 {
            covenant_source_sha256: [41; 32], compiler_source_closure_sha256: [42; 32],
            catalogue_sha256: [43; 32], projection_source_closure_sha256: [44; 32],
        };
        let c = configuration();
        let auth = c.truthcoin_authentication;
        let mut deployment = c.truthcoin_anchor_deployment;
        deployment.script_tree_configuration_hash = policy.commitment().unwrap();
        let args = policy.compiler_arguments(&auth, &deployment, c.policy_asset_id, [45; 32]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&args).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 9);
        for (name, value) in [
            ("STATE_NODE_DOMAIN_SHA256", <[u8;32]>::from(Sha256::digest(STATE_DOMAIN))),
            ("EXECUTION_DOMAIN_SHA256", Sha256::digest(EXECUTION_DOMAIN).into()),
            ("KEYLESS_INTERNAL_KEY", KEYLESS_INTERNAL_KEY),
            ("CONFIGURATION_HASH", crate::truthcoin_anchor::truthcoin_anchor_configuration_hash(&auth, &deployment, c.policy_asset_id)),
            ("AUTHORITY_ASSET", deployment.authority_asset_id),
            ("POLICY_ASSET", c.policy_asset_id),
            ("PROJECTION_PROGRAM_ID", [45;32]),
        ] {
            assert_eq!(json[name]["type"], "u256");
            assert_eq!(json[name]["value"], format!("0x{}", value.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        }
        assert_eq!(json["TAPLEAF_VERSION"], serde_json::json!({"type":"u8","value":"190"}));
        assert_eq!(json["AUTHORITY_AMOUNT"], serde_json::json!({"type":"u64","value":"1"}));
        for id in [[0;32], auth.source_proof_program_id] {
            assert_eq!(policy.compiler_arguments(&auth, &deployment, c.policy_asset_id, id), Err(PolicyError::ProgramRole));
        }
        assert!(policy.compiler_arguments(&auth, &deployment, [0;32], [45;32]).is_err());
        assert!(policy.compiler_arguments(&auth, &deployment, deployment.authority_asset_id, [45;32]).is_err());
        let mut wrong_auth = auth.clone();
        wrong_auth.version = 0;
        assert!(policy.compiler_arguments(&wrong_auth, &deployment, c.policy_asset_id, [45;32]).is_err());
        deployment.script_tree_configuration_hash[0] ^= 1;
        assert_eq!(policy.compiler_arguments(&auth, &deployment, c.policy_asset_id, [45;32]), Err(PolicyError::InvalidConfiguration));
    }

    fn configuration() -> FrozenConfigurationV1 {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (matcher_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        FrozenConfigurationV1 {
            version: FrozenConfigurationV1::VERSION,
            chain_id: [1; 32],
            market: ECX_USDD_MARKET,
            ecx_asset_id: [2; 32],
            usdd_asset_id: [3; 32],
            policy_asset_id: [4; 32],
            state_authority_asset_id: [5; 32],
            usdd_checkpoint: UsddCheckpointConfigV1 {
                version: UsddCheckpointConfigV1::VERSION,
                ethereum_light_client_configuration_hash: [24; 32],
                authority_configuration_hash: [25; 32],
                maximum_checkpoint_age_seconds: crate::USDD_MAX_CHECKPOINT_AGE_SECONDS,
            },
            risk: RiskParams::default(),
            availability: AvailabilityConfigV1 {
                version: AvailabilityConfigV1::VERSION,
                scheme_hash: [19; 32],
                custodian_registry_hash: [20; 32],
                recovery_threshold: crate::AVAILABILITY_RECOVERY_THRESHOLD,
                custodian_count: crate::AVAILABILITY_CUSTODIAN_COUNT,
                maximum_witness_bytes: crate::MAX_AVAILABILITY_WITNESS_BYTES,
            },
            truthcoin_authentication: TruthcoinAuthenticationConfigV1 {
                version: TruthcoinAuthenticationConfigV1::VERSION,
                source_git_commit_sha1: [1; 20],
                consensus_source_manifest_sha256: [18; 32],
                source_patch_manifest_sha256: [23; 32],
                sidechain_number: 13,
                bitcoin_checkpoint_hash: [16; 32],
                bitcoin_checkpoint_height: 100,
                bip300_checkpoint_state_hash: [24; 32],
                genesis_sidechain_block_hash: [17; 32],
                truthcoin_chain_id: [6; 32],
                truthcoin_branch_id: [7; 32],
                btc_usd_template_hash: [8; 32],
                lmsr_math_commitment: [9; 32],
                source_proof_program_id: [14; 32],
                selection_rule_hash: [15; 32],
                minimum_bitcoin_confirmations: 6,
                maximum_proof_bytes: 1_024,
            },
            truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
                version: TruthcoinAnchorDeploymentV1::VERSION,
                authority_asset_id: [21; 32],
                authority_amount: 1,
                script_tree_configuration_hash: [22; 32],
            },
            oracle: HybridOracleConfigV1 {
                version: 1,
                truthcoin_chain_id: [6; 32],
                truthcoin_branch_id: [7; 32],
                btc_usd_template_hash: [8; 32],
                lmsr_math_commitment: [9; 32],
                schedule_origin_mtp: 1,
                epoch_length_seconds: 600,
                minimum_source_confirmations: 6,
                maximum_anchor_age_seconds: 3_600,
                maximum_snapshot_age_seconds: 120,
                minimum_lmsr_b: 1_000,
                minimum_sample_count: 3,
                base_lmsr_weight_ppm: 0,
                maximum_lmsr_weight_ppm: PPM_DENOMINATOR as u32,
                initial_anchor_band_bps: 100,
                maximum_anchor_band_bps: 2_000,
                risk_haircut_bps: 100,
                boundary_guard_ppb: 10_000,
                maximum_unanchored_deviation_bps: 5_000,
                ecx_satoshis_per_coin: 1_000,
                usdd_usd_price_units: PRICE_SCALE,
            },
            matcher: CentralMatcherConfigV1 {
                version: 1,
                key_epoch: 0,
                signer: XOnlyKey(matcher_key.serialize()),
                genesis_sequence: 0,
                genesis_receipt_hash: [10; 32],
                forced_inclusion_blocks: 6,
            },
            forced_action_domain: [11; 32],
            deposit_inbox_domain: [12; 32],
            collateral_vault_script_sha256: [13; 32],
            maximum_transition_actions: MAX_TRANSITION_ACTIONS,
        }
    }

    #[test]
    fn digest_changes_with_every_subconfiguration() {
        let config = configuration();
        config.validate().unwrap();
        let expected = config.digest();
        let mut changed = config.clone();
        changed.usdd_checkpoint.maximum_checkpoint_age_seconds -= 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config.clone();
        changed.risk.taker_fee_bps += 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config.clone();
        changed.availability.custodian_registry_hash[0] ^= 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config.clone();
        changed.oracle.maximum_snapshot_age_seconds += 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config.clone();
        changed.truthcoin_authentication.bitcoin_checkpoint_height += 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config.clone();
        changed
            .truthcoin_anchor_deployment
            .script_tree_configuration_hash[0] ^= 1;
        assert_ne!(changed.digest(), expected);
        let mut changed = config;
        changed.matcher.forced_inclusion_blocks += 1;
        assert_ne!(changed.digest(), expected);
    }

    #[test]
    fn source_authentication_must_match_oracle_and_have_a_checkpoint() {
        let mut wrong_chain = configuration();
        wrong_chain.truthcoin_authentication.truthcoin_chain_id = [42; 32];
        assert!(matches!(
            wrong_chain.validate(),
            Err(ProtocolError::InvalidOracleConfiguration)
        ));

        let mut missing_checkpoint = configuration();
        missing_checkpoint
            .truthcoin_authentication
            .bitcoin_checkpoint_height = 0;
        assert!(matches!(
            missing_checkpoint.validate(),
            Err(ProtocolError::InvalidOracleConfiguration)
        ));

        let mut insufficient_finality = configuration();
        insufficient_finality
            .truthcoin_authentication
            .minimum_bitcoin_confirmations =
            insufficient_finality.oracle.minimum_source_confirmations - 1;
        assert!(matches!(
            insufficient_finality.validate(),
            Err(ProtocolError::InvalidOracleConfiguration)
        ));
    }

    #[test]
    fn direct_native_truthcoin_lane_requires_the_exact_native_identity_profile() {
        let mut direct = configuration();
        direct.policy_asset_id = direct.ecx_asset_id;
        direct.oracle.ecx_satoshis_per_coin = PRICE_SCALE;
        direct.oracle.usdd_usd_price_units = PRICE_SCALE;
        direct.validate().unwrap();
        assert!(direct.uses_direct_native_truthcoin_price());

        let mut separate_policy_asset = direct.clone();
        separate_policy_asset.policy_asset_id = [4; 32];
        assert!(!separate_policy_asset.uses_direct_native_truthcoin_price());

        let mut non_identity_ecx_scale = direct.clone();
        non_identity_ecx_scale.oracle.ecx_satoshis_per_coin -= 1;
        assert!(!non_identity_ecx_scale.uses_direct_native_truthcoin_price());

        let mut non_identity_usdd_scale = direct;
        non_identity_usdd_scale.oracle.usdd_usd_price_units -= 1;
        assert!(!non_identity_usdd_scale.uses_direct_native_truthcoin_price());
    }

    #[test]
    fn transition_action_limit_is_absolute() {
        let mut excessive = configuration();
        excessive.maximum_transition_actions = MAX_TRANSITION_ACTIONS + 1;
        assert_eq!(
            excessive.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );

        let mut zero = configuration();
        zero.maximum_transition_actions = 0;
        assert_eq!(zero.validate(), Err(ProtocolError::NonCanonicalEncoding));
    }

    #[test]
    fn native_ecx_is_a_valid_policy_asset() {
        let mut native_fee_configuration = configuration();
        native_fee_configuration.policy_asset_id = native_fee_configuration.ecx_asset_id;
        native_fee_configuration.validate().unwrap();
    }

    #[test]
    fn policy_asset_cannot_alias_other_protocol_assets() {
        let mut usdd_fee_configuration = configuration();
        usdd_fee_configuration.policy_asset_id = usdd_fee_configuration.usdd_asset_id;
        assert_eq!(
            usdd_fee_configuration.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );

        let mut authority_fee_configuration = configuration();
        authority_fee_configuration.policy_asset_id =
            authority_fee_configuration.state_authority_asset_id;
        assert_eq!(
            authority_fee_configuration.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn truthcoin_anchor_authority_is_distinct_and_frozen() {
        let config = configuration();
        assert_ne!(
            config.truthcoin_anchor_configuration_hash(),
            config.truthcoin_authentication.digest()
        );

        let mut policy_asset_authority = config.clone();
        policy_asset_authority
            .truthcoin_anchor_deployment
            .authority_asset_id = policy_asset_authority.policy_asset_id;
        assert_eq!(
            policy_asset_authority.validate(),
            Err(ProtocolError::InvalidTruthcoinAnchor)
        );

        let mut exchange_authority_alias = config;
        exchange_authority_alias
            .truthcoin_anchor_deployment
            .authority_asset_id = exchange_authority_alias.state_authority_asset_id;
        assert_eq!(
            exchange_authority_alias.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }
}
