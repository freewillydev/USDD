//! Versioned statement contract for ECX-aware child execution and capital state.
//! These codecs are not proof verification. Consumers must verify the selected
//! V4 guest receipt and independently pin every source binding and clock.
use crate::child_execution_guest_v3::{AlphaChildExecutionBindingV3,
    AlphaChildExecutionErrorV3, AlphaChildExecutionPublicValuesV3,
    ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3, ALPHA_CHILD_EXECUTION_VERSION_V3};
use crate::Hash32;

// Revision 2 adds a committed optional successor identity. Never accept the
// previous 0xa9 receipt/input layout as this relation.
pub const ALPHA_CHILD_EXECUTION_VERSION_V4: u8 = 0xaa;
pub const ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V4: usize = ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionBindingV4 {
    /// The predecessor commitment here is V4, not a V3 execution projection.
    pub execution: AlphaChildExecutionBindingV3,
    pub evaluator_binding: Hash32,
    pub environment: Hash32,
    pub genesis_bindings: Hash32,
    pub successor: Option<SuccessorIdentityV4>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorIdentityV4 {
    pub configuration_hash: Hash32,
    pub program_id: Hash32,
    pub transition_cmr: Hash32,
}

impl SuccessorIdentityV4 {
    pub fn validate(&self) -> Result<(), AlphaChildExecutionErrorV3> {
        if [self.configuration_hash, self.program_id, self.transition_cmr].contains(&[0;32]) {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        Ok(())
    }
}

impl AlphaChildExecutionBindingV4 {
    pub fn commitment(&self) -> Result<Hash32, AlphaChildExecutionErrorV3> {
        let execution = self.execution.commitment()?;
        if [self.evaluator_binding, self.environment, self.genesis_bindings].contains(&[0;32]) {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        let mut bytes = vec![ALPHA_CHILD_EXECUTION_VERSION_V4];
        for hash in [execution, self.evaluator_binding, self.environment, self.genesis_bindings] {
            bytes.extend_from_slice(&hash);
        }
        bytes.push(u8::from(self.successor.is_some()));
        if let Some(successor) = self.successor {
            successor.validate()?;
            for hash in [successor.configuration_hash, successor.program_id, successor.transition_cmr] {
                bytes.extend_from_slice(&hash);
            }
        }
        Ok(crate::tagged_hash("ECX/alpha-child-execution-binding/v4", &bytes))
    }
}

/// Wire fields reuse the explicit 407-byte layout, but the version and source
/// binding are distinct. Both checkpoint fields refer to complete V4 states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlphaChildExecutionPublicValuesV4(pub AlphaChildExecutionPublicValuesV3);

impl AlphaChildExecutionPublicValuesV4 {
    pub fn canonical_bytes(self) -> [u8; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V4] {
        let mut out = self.0.canonical_bytes();
        out[0] = ALPHA_CHILD_EXECUTION_VERSION_V4;
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AlphaChildExecutionErrorV3> {
        if bytes.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V4
            || bytes[0] != ALPHA_CHILD_EXECUTION_VERSION_V4 {
            return Err(AlphaChildExecutionErrorV3::Input);
        }
        // Share structural validation, never receipt verification or dispatch.
        let mut layout: [u8; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V4] = bytes.try_into().unwrap();
        layout[0] = ALPHA_CHILD_EXECUTION_VERSION_V3;
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&layout).map(Self)
    }
}

/// Per-input evaluator relation. Source closure is explicit; the opaque V4
/// evaluator binding is not reused with a different meaning. Both checkpoint
/// fields in its public statement refer to complete V5 anchor-bearing states.
pub const ALPHA_CHILD_EXECUTION_VERSION_V5: u8 = 0xab;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionBindingV5 {
    pub execution: AlphaChildExecutionBindingV3,
    pub evaluator_source_closure: Hash32,
    pub environment: Hash32,
    pub genesis_bindings: Hash32,
    pub successor: Option<SuccessorIdentityV4>,
}

impl AlphaChildExecutionBindingV5 {
    pub fn commitment(&self) -> Result<Hash32, AlphaChildExecutionErrorV3> {
        let execution = self.execution.commitment()?;
        if [self.evaluator_source_closure, self.environment, self.genesis_bindings].contains(&[0;32]) {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        let mut bytes = vec![ALPHA_CHILD_EXECUTION_VERSION_V5];
        for hash in [execution, self.evaluator_source_closure, self.environment, self.genesis_bindings] {
            bytes.extend_from_slice(&hash);
        }
        bytes.push(u8::from(self.successor.is_some()));
        if let Some(successor) = self.successor {
            successor.validate()?;
            for hash in [successor.configuration_hash, successor.program_id, successor.transition_cmr] {
                bytes.extend_from_slice(&hash);
            }
        }
        Ok(crate::tagged_hash("ECX/alpha-child-execution-binding/v5", &bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlphaChildExecutionPublicValuesV5(pub AlphaChildExecutionPublicValuesV3);

impl AlphaChildExecutionPublicValuesV5 {
    pub fn canonical_bytes(self) -> [u8; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] {
        let mut bytes = self.0.canonical_bytes();
        bytes[0] = ALPHA_CHILD_EXECUTION_VERSION_V5;
        bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AlphaChildExecutionErrorV3> {
        if bytes.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || bytes[0] != ALPHA_CHILD_EXECUTION_VERSION_V5 {
            return Err(AlphaChildExecutionErrorV3::Input);
        }
        let mut layout: [u8; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] = bytes.try_into().unwrap();
        layout[0] = ALPHA_CHILD_EXECUTION_VERSION_V3;
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&layout).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_additional_execution_trust_root_is_required_and_committed() {
        let binding = AlphaChildExecutionBindingV4 {
            execution: AlphaChildExecutionBindingV3 { parent_binding: [1;32],
                predecessor_checkpoint: [2;32], execution_policy: [3;32],
                simplicity_evaluator_program_id: [4;32], deposit_configuration: [5;32] },
            evaluator_binding: [6;32], environment: [7;32], genesis_bindings: [8;32], successor: None,
        };
        let expected = binding.commitment().unwrap();
        let v5 = AlphaChildExecutionBindingV5 { execution: binding.execution,
            evaluator_source_closure: binding.evaluator_binding,
            environment: binding.environment, genesis_bindings: binding.genesis_bindings,
            successor: binding.successor };
        let v5_hash = v5.commitment().unwrap();
        assert_ne!(v5_hash, expected);
        for field in 0..3 {
            for value in [[0;32], [15;32]] {
                let mut changed = v5;
                match field { 0 => changed.evaluator_source_closure = value,
                    1 => changed.environment = value, _ => changed.genesis_bindings = value }
                if value == [0;32] { assert!(changed.commitment().is_err()); }
                else { assert_ne!(changed.commitment().unwrap(), v5_hash); }
            }
        }
        assert_ne!(expected, binding.execution.commitment().unwrap());
        for field in 0..3 {
            for value in [[0;32], [9;32]] {
                let mut changed = binding;
                match field { 0 => changed.evaluator_binding = value,
                    1 => changed.environment = value, _ => changed.genesis_bindings = value }
                if value == [0;32] { assert!(changed.commitment().is_err()); }
                else { assert_ne!(changed.commitment().unwrap(), expected); }
            }
        }
        let mut successor_binding = binding;
        successor_binding.successor = Some(SuccessorIdentityV4 {
            configuration_hash: [10;32], program_id: [11;32], transition_cmr: [12;32] });
        let successor_commitment = successor_binding.commitment().unwrap();
        assert_ne!(successor_commitment, expected);
        for field in 0..3 {
            for value in [[0;32], [13;32]] {
                let mut changed = successor_binding;
                let identity = changed.successor.as_mut().unwrap();
                match field { 0 => identity.configuration_hash = value,
                    1 => identity.program_id = value, _ => identity.transition_cmr = value }
                if value == [0;32] { assert!(changed.commitment().is_err()); }
                else { assert_ne!(changed.commitment().unwrap(), successor_commitment); }
            }
        }
    }

    #[test]
    fn journals_reject_legacy_version_suffix_and_wrong_alpha_profile() {
        use crate::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3;
        let values = AlphaChildExecutionPublicValuesV4(AlphaChildExecutionPublicValuesV3 {
            source_binding: [1;32], predecessor_checkpoint: [2;32], next_checkpoint: [3;32],
            child_hash_internal: [4;32], child_height: 7, observation_time: 100,
            parent: AlphaConversionParentLinkPublicValuesV3 {
                binding_commitment: [5;32], parent_statement_commitment: [6;32],
                parent_predecessor_state_commitment: [7;32], parent_terminal_state_commitment: [8;32],
                parent_block_hash_internal: [9;32], parent_height: 100,
                parent_predecessor_hash_internal: [10;32], m7_critical_hash_internal: [11;32], m7_coinbase_vout: 1,
            },
        });
        let bytes = values.canonical_bytes();
        let v5 = AlphaChildExecutionPublicValuesV5(values.0);
        let v5_bytes = v5.canonical_bytes();
        assert_eq!(v5_bytes.len(), 407);
        assert_eq!(AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&v5_bytes).unwrap(), v5);
        assert!(AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&bytes).is_err());
        assert!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&v5_bytes).is_err());
        assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&v5_bytes).is_err());
        let mut v5_suffix = v5_bytes.to_vec(); v5_suffix.push(0);
        assert!(AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&v5_suffix).is_err());
        assert_eq!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&bytes).unwrap(), values);
        assert!(AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&bytes).is_err());
        assert!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&values.0.canonical_bytes()).is_err());
        let mut suffix = bytes.to_vec(); suffix.push(0);
        assert!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&suffix).is_err());
        let mut altered = bytes; altered[144] ^= 1;
        assert!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&altered).is_err());
        let mut previous_revision = bytes; previous_revision[0] = 0xa9;
        assert!(AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&previous_revision).is_err());
    }
}
