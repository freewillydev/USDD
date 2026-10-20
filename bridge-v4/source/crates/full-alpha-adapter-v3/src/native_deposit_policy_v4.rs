//! Explicit Alpha maturity schedule. Not yet wired into a qualified guest.
//! The legacy V3 deposit commitment retains its scalar semantics.
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::child_execution_guest_v3::AlphaDepositConfigurationV3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaDepositPolicyV4 {
    pub historical: AlphaDepositConfigurationV3,
    pub child_genesis_internal: [u8; 32],
    pub parent_genesis_internal: [u8; 32],
    pub protocol_manifest: [u8; 32],
    pub slot: u8,
}

impl AlphaDepositPolicyV4 {
    fn validate(&self) -> Option<[u8; 32]> {
        let child = bitcoin::BlockHash::from_str("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd").ok()?.to_byte_array();
        let manifest = bitcoin::hashes::sha256::Hash::from_str("fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6").ok()?.to_byte_array();
        if self.child_genesis_internal != child
            || self.parent_genesis_internal != crate::child_execution_guest_v3::alpha_parent_genesis()
            || self.protocol_manifest != manifest || self.slot != 24
            || self.historical.minimum_depth != 100 {
            return None;
        }
        self.historical.commitment().ok()
    }

    /// Commit the schedule separately from the immutable historical parameters.
    pub fn commitment(&self) -> Option<[u8; 32]> {
        let historical = self.validate()?;
        let mut bytes = vec![4];
        for hash in [historical, self.child_genesis_internal,
            self.parent_genesis_internal, self.protocol_manifest] {
            bytes.extend_from_slice(&hash);
        }
        bytes.push(self.slot);
        bytes.extend_from_slice(&64u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        Some(crate::tagged_hash("ECX/alpha-native-deposit-policy/v4", &bytes))
    }

    /// The enclosing executor MUST supply its authenticated predecessor height.
    /// A caller-provided height alone is not checkpoint authentication.
    pub fn required_depth(&self, predecessor_height: u32) -> Option<u32> {
        self.validate()?;
        let height = predecessor_height.checked_add(1)?;
        if height > i32::MAX as u32 { return None; }
        Some(if height >= 64 { 1 } else { 100 })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn policy() -> AlphaDepositPolicyV4 {
        AlphaDepositPolicyV4 {
            historical: AlphaDepositConfigurationV3 {
                pegged_asset_internal: bitcoin::BlockHash::from_str("62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4").unwrap().to_byte_array(),
                minimum_depth: 100, p2pkh_prefix: 68, p2sh_prefix: 13,
                blinded_prefix: 6, bech_hrp: "elements".into(), blech_hrp: "elementsl".into(),
            },
            child_genesis_internal: bitcoin::BlockHash::from_str("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd").unwrap().to_byte_array(),
            parent_genesis_internal: crate::child_execution_guest_v3::alpha_parent_genesis(),
            protocol_manifest: bitcoin::hashes::sha256::Hash::from_str("fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6").unwrap().to_byte_array(),
            slot: 24,
        }
    }
    #[test]
    fn maturity_schedule_and_legacy_domain_are_distinct() {
        let p = policy();
        for (predecessor, depth) in [(0,100),(62,100),(63,1),(64,1),(82,1)] {
            assert_eq!(p.required_depth(predecessor), Some(depth));
        }
        assert_eq!(p.required_depth(u32::MAX), None);
        assert_eq!(p.required_depth(i32::MAX as u32), None);
        assert_ne!(p.commitment(), p.historical.commitment().ok());
    }
    #[test]
    fn rejects_substituted_upgrade_identity() {
        let p = policy();
        for field in 0..5 {
            let mut changed = p.clone();
            match field {
                0 => changed.child_genesis_internal[0] ^= 1,
                1 => changed.parent_genesis_internal[0] ^= 1,
                2 => changed.protocol_manifest[0] ^= 1,
                3 => changed.slot ^= 1,
                _ => changed.historical.minimum_depth = 1,
            }
            assert!(changed.commitment().is_none());
            assert!(changed.required_depth(63).is_none());
        }
    }
}
