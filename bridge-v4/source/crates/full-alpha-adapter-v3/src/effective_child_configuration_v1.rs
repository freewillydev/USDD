//! Non-circular effective Alpha consensus composition. This is not the DEX V18
//! configuration, a checkpoint, or evidence of execution-engine qualification.
use crate::{child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    child_header_policy_v3::ChildHeaderPolicyV3, native_deposit_policy_v4::AlphaDepositPolicyV4};

/// Private components prevent constructing a purported checked composition
/// without deriving the hashes from the actual consumer policies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveChildConfigurationV1 { components: [[u8; 32]; 8], reward: [u8; 12] }

impl EffectiveChildConfigurationV1 {
    pub const ENCODED_LENGTH: usize = 1 + 8 * 32 + 12;

    pub fn from_policies(policy: &ChildCustodyExecutionPolicyV3,
        header: &ChildHeaderPolicyV3, deposit: &AlphaDepositPolicyV4,
    ) -> Result<Self, &'static str> {
        let deposit_hash = deposit.commitment().ok_or("deposit policy")?;
        let header_hash = header.commitment()?;
        let classification = policy.classification.commitment().map_err(|_| "classification")?;
        let deployments = policy.deployments.commitment().map_err(|_| "deployments")?;
        let subsidy = policy.reward.subsidy_asset.into_inner().to_byte_array();
        if policy.genesis_internal != deposit.child_genesis_internal
            || policy.classification.native_pegged_asset_id != deposit.historical.pegged_asset_internal
            || subsidy != deposit.historical.pegged_asset_internal
            || policy.header_policy_commitment != header_hash
            || policy.reward.halving_interval == 0
            || policy.reward.genesis_subsidy > 2_100_000_000_000_000 {
            return Err("component disagreement");
        }
        let components = [policy.genesis_internal, deposit.protocol_manifest,
            deployments, header_hash, deposit_hash, policy.creation.commitment(),
            classification, subsidy];
        if components.contains(&[0; 32]) { return Err("zero component"); }
        let mut reward = [0; 12];
        reward[..8].copy_from_slice(&policy.reward.genesis_subsidy.to_be_bytes());
        reward[8..].copy_from_slice(&policy.reward.halving_interval.to_be_bytes());
        Ok(Self { components, reward })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LENGTH);
        bytes.push(1);
        for component in self.components { bytes.extend_from_slice(&component); }
        bytes.extend_from_slice(&self.reward);
        bytes
    }

    pub fn commitment(&self) -> [u8; 32] {
        crate::tagged_hash("ECX/alpha-effective-child-configuration/v1", &self.encode())
    }

    /// Call only after construction from the exact guest-consumed policies.
    /// The supplied configuration hash is excluded from the preimage itself.
    pub fn require_bound(&self, expected: [u8; 32]) -> Result<(), &'static str> {
        if expected == [0; 32] || self.commitment() != expected {
            return Err("effective configuration binding");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_composition_checks_agreement_without_self_hash() {
        use crate::child_deployments_v3::*;
        let deposit = crate::native_deposit_policy_v4::tests::policy();
        // Real Alpha network/deployment parameters; synthetic bootstrap and
        // custody identity. This qualifies composition, not a live release.
        let versionbits = |bit, start| ElementsVersionbitsV3 {
            bit, start, timeout: i64::MAX, min_activation_height: 0,
            period: 2016, threshold: 1815,
        };
        let header = ChildHeaderPolicyV3 {
            epoch_length: 10,
            bootstrap: crate::native_child_context_v3::NativeDynafedBootstrap {
                legacy_challenge: elements::Script::from(vec![0x51]),
                maximum_signature_size: 1000, fedpeg_script: vec![],
                start_p2wsh: false, first_extension_space: vec![],
            },
        };
        let mut policy = ChildCustodyExecutionPolicyV3 {
            creation: crate::native_creation_policy_v1::NativeCreationPolicyV1 {
                explicit_only_height: Some(100),
            },
            genesis_internal: deposit.child_genesis_internal,
            consensus_configuration_commitment: [0;32],
            deployments: ChildDeploymentConfigurationV3 {
                buried: BuriedDeploymentsV3 { height_in_coinbase: 1,
                    strict_der: 1, cltv: 1, csv: 1, segwit: 0 },
                taproot: versionbits(2, -1), dynafed: versionbits(25, -2),
                simplicity: versionbits(21, -1), bip16_exception_internal: [0;32],
                usdd_sp1_annex: true,
            },
            reward: crate::native_reward_v3::RewardParameters {
                subsidy_asset: elements::AssetId::from_slice(&deposit.historical.pegged_asset_internal).unwrap(),
                genesis_subsidy: 0, halving_interval: 210000,
            },
            classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3 {
                native_pegged_asset_id: deposit.historical.pegged_asset_internal,
                custody_asset_id: [7;32],
            },
            header_policy_commitment: header.commitment().unwrap(),
        };
        let original = EffectiveChildConfigurationV1::from_policies(&policy, &header, &deposit).unwrap();
        policy.consensus_configuration_commitment = original.commitment();
        assert_eq!(EffectiveChildConfigurationV1::from_policies(&policy, &header, &deposit).unwrap(), original);
        original.require_bound(policy.consensus_configuration_commitment).unwrap();
        let upgraded = crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4 {
            base: policy, explicit_reissuance_height: Some(120),
        };
        let current = EffectiveChildConfigurationV2::from_policies(&upgraded, &header, &deposit).unwrap();
        assert_ne!(current.commitment(), original.commitment());
        assert!(current.require_bound(original.commitment()).is_err());
        let mut bound = upgraded;
        bound.base.consensus_configuration_commitment = current.commitment();
        assert_eq!(EffectiveChildConfigurationV2::from_policies(&bound, &header, &deposit).unwrap(), current);
        assert_ne!(bound.commitment().unwrap(), bound.base.commitment().unwrap());
        let mut changed = bound;
        changed.explicit_reissuance_height = Some(121);
        assert_ne!(changed.commitment().unwrap(), bound.commitment().unwrap());
        assert_ne!(EffectiveChildConfigurationV2::from_policies(&changed, &header, &deposit).unwrap(), current);
        changed.explicit_reissuance_height = Some(99);
        assert!(changed.commitment().is_err());
        assert!(EffectiveChildConfigurationV2::from_policies(&changed, &header, &deposit).is_err());
        policy.consensus_configuration_commitment = [9;32];
        assert_eq!(EffectiveChildConfigurationV1::from_policies(&policy, &header, &deposit).unwrap(), original);
        assert!(original.require_bound(policy.consensus_configuration_commitment).is_err());
        for field in 0..6 {
            let mut changed = policy;
            match field {
                0 => changed.genesis_internal[0] ^= 1,
                1 => changed.classification.native_pegged_asset_id[0] ^= 1,
                2 => changed.reward.subsidy_asset = elements::AssetId::from_slice(&[8;32]).unwrap(),
                3 => changed.header_policy_commitment[0] ^= 1,
                4 => changed.reward.halving_interval = 0,
                _ => changed.reward.genesis_subsidy = u64::MAX,
            }
            assert_eq!(EffectiveChildConfigurationV1::from_policies(&changed, &header, &deposit), Err("component disagreement"));
        }
        let mut changed = policy;
        changed.creation.explicit_only_height = None;
        assert_ne!(EffectiveChildConfigurationV1::from_policies(&changed, &header, &deposit).unwrap().commitment(), original.commitment());
        let mut wrong_network = deposit.clone();
        wrong_network.parent_genesis_internal[0] ^= 1;
        assert_eq!(EffectiveChildConfigurationV1::from_policies(&policy, &header, &wrong_network), Err("deposit policy"));
        let mut bad_header = header.clone();
        bad_header.epoch_length = 0;
        assert_eq!(EffectiveChildConfigurationV1::from_policies(&policy, &bad_header, &deposit), Err("zero header epoch"));
    }
    #[test]
    fn fixed_encoding_binds_every_component() {
        // Encoding-only vector, not a qualified Alpha policy set.
        let value = EffectiveChildConfigurationV1 { components: [[1;32];8], reward: [2;12] };
        assert_eq!(value.encode().len(), EffectiveChildConfigurationV1::ENCODED_LENGTH);
        assert_eq!(value.encode()[0], 1);
        let hash = value.commitment();
        value.require_bound(hash).unwrap();
        assert!(value.require_bound([0;32]).is_err());
        for component in 0..8 {
            let mut changed = value.clone(); changed.components[component][0] ^= 1;
            assert!(changed.require_bound(hash).is_err());
        }
        for index in 0..12 {
            let mut changed = value.clone(); changed.reward[index] ^= 1;
            assert!(changed.require_bound(hash).is_err());
        }
    }
}

/// Versioned effective composition for separately activated explicit reissuance.
/// Reuses the checked base components but replaces the creation-policy binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveChildConfigurationV2(EffectiveChildConfigurationV1);

impl EffectiveChildConfigurationV2 {
    pub fn from_policies(policy: &crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4,
        header: &ChildHeaderPolicyV3, deposit: &AlphaDepositPolicyV4,
    ) -> Result<Self, &'static str> {
        let mut base = EffectiveChildConfigurationV1::from_policies(&policy.base, header, deposit)?;
        base.components[5] = policy.creation().commitment()?;
        Ok(Self(base))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.0.encode();
        bytes[0] = 2;
        bytes
    }

    pub fn commitment(&self) -> [u8;32] {
        crate::tagged_hash("ECX/alpha-effective-child-configuration/v2", &self.encode())
    }

    pub fn require_bound(&self, expected: [u8;32]) -> Result<(), &'static str> {
        if expected == [0;32] || self.commitment() != expected {
            return Err("effective configuration binding");
        }
        Ok(())
    }
}
