//! Receipt-authenticated child observation for enclosing consumers.
//! Expected values MUST come from a frozen source policy and verified parent
//! observation, not from the receipt being checked. This does not choose a
//! canonical chain or authenticate the origin of those external expectations.
use crate::{FullAlphaReceiptVerifierV3, Hash32};
use crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5;
use crate::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3;

/// Consumer-selected policy. These values must be frozen outside the witness.
pub struct FrozenChildObservationPolicyV5 {
    pub program_id: Hash32,
    pub source_binding: Hash32,
    pub predecessor_checkpoint: Hash32,
    pub parent_binding_commitment: Hash32,
    pub minimum_parent_confirmations: u32,
}

/// Parent endpoint is obtained from executed Alpha replay, not the child's BMM
/// inclusion block. The latter may be an ancestor of this observation.
pub struct VerifiedParentChildObservationV5 {
    child: VerifiedChildObservationV5,
    parent: crate::FullAlphaStatementV3,
}
impl VerifiedParentChildObservationV5 {
    pub fn child(&self) -> &VerifiedChildObservationV5 { &self.child }
    pub fn parent(&self) -> &crate::FullAlphaStatementV3 { &self.parent }
}

/// Execute both parent relations, prove inclusion-to-observation ancestry, then
/// authenticate the child's exact receipt against that independently derived
/// clock. No witness-supplied height or MTP is accepted as a trusted input.
pub fn verify_child_at_parent_observation_v5(
    frozen: &FrozenChildObservationPolicyV5,
    inclusion: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    observation: &crate::FullAlphaAdapterInputV3,
    continuation: &[Vec<u8>],
    public_values: &[u8],
    proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<VerifiedParentChildObservationV5, &'static str> {
    verify_at_parent(frozen, inclusion, observation, continuation, public_values,
        proof_marker, verifier, false)
}

/// Full-anchor V6 lane. Same parent/finality relation, distinct child decoder
/// and exact receipt bytes; never convert a V6 statement into a V5 receipt.
pub fn verify_child_at_parent_observation_v6(
    frozen: &FrozenChildObservationPolicyV5,
    inclusion: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    observation: &crate::FullAlphaAdapterInputV3,
    continuation: &[Vec<u8>],
    public_values: &[u8],
    proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<VerifiedParentChildObservationV5, &'static str> {
    verify_at_parent(frozen, inclusion, observation, continuation, public_values,
        proof_marker, verifier, true)
}

fn verify_at_parent(
    frozen: &FrozenChildObservationPolicyV5,
    inclusion: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    observation: &crate::FullAlphaAdapterInputV3,
    continuation: &[Vec<u8>], public_values: &[u8], proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3, full_anchor_v6: bool,
) -> Result<VerifiedParentChildObservationV5, &'static str> {
    if frozen.parent_binding_commitment == [0;32]
        || frozen.minimum_parent_confirmations == 0
        || inclusion.binding.commitment().map_err(|_| "invalid parent policy")?
            != frozen.parent_binding_commitment
        || observation.binding != inclusion.binding.parent {
        return Err("parent observation policy mismatch");
    }
    let parent = crate::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(
        inclusion, verifier).map_err(|_| "parent inclusion rejected")?;
    let endpoint = crate::execute_full_alpha_adapter_v3(observation, verifier)
        .map_err(|_| "parent observation rejected")?;
    crate::native_conversion_source_v3::verify_continuation(
        &parent, &endpoint, continuation, frozen.minimum_parent_confirmations)
        .map_err(|_| "parent observation ancestry rejected")?;
    let child = verify_child_observation(&ExpectedChildObservationV5 {
        program_id: frozen.program_id,
        source_binding: frozen.source_binding,
        predecessor_checkpoint: frozen.predecessor_checkpoint,
        observation_time: endpoint.terminal_mtp,
        parent,
    }, public_values, proof_marker, verifier, full_anchor_v6)?;
    Ok(VerifiedParentChildObservationV5 { child, parent: endpoint })
}

pub struct ExpectedChildObservationV5 {
    pub program_id: Hash32,
    pub source_binding: Hash32,
    pub predecessor_checkpoint: Hash32,
    pub observation_time: u64,
    pub parent: AlphaConversionParentLinkPublicValuesV3,
}

/// No public constructor or Deserialize: height is released only after receipt
/// verification and exact source, predecessor, clock and parent matching.
pub struct VerifiedChildObservationV5 {
    height: u32,
    checkpoint: Hash32,
}
impl VerifiedChildObservationV5 {
    pub fn height(&self) -> u32 { self.height }
    pub fn checkpoint(&self) -> Hash32 { self.checkpoint }
}

pub fn verify_child_observation_v5(
    expected: &ExpectedChildObservationV5,
    public_values: &[u8],
    proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<VerifiedChildObservationV5, &'static str> {
    verify_child_observation(expected, public_values, proof_marker, verifier, false)
}

pub fn verify_child_observation_v6(
    expected: &ExpectedChildObservationV5, public_values: &[u8], proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<VerifiedChildObservationV5, &'static str> {
    verify_child_observation(expected, public_values, proof_marker, verifier, true)
}

fn verify_child_observation(
    expected: &ExpectedChildObservationV5, public_values: &[u8], proof_marker: &[u8],
    verifier: &impl FullAlphaReceiptVerifierV3, full_anchor_v6: bool,
) -> Result<VerifiedChildObservationV5, &'static str> {
    if !crate::alpha_sp1_program_id_is_canonical_v3(expected.program_id)
        || expected.predecessor_checkpoint == [0;32] {
        return Err("invalid frozen child observation policy");
    }
    let child = if full_anchor_v6 {
        crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6::from_canonical_bytes(public_values)
            .map_err(|_| "invalid V6 child statement")?.0
    } else {
        AlphaChildExecutionPublicValuesV5::from_canonical_bytes(public_values)
            .map_err(|_| "invalid V5 child statement")?.0
    };
    child.require_source_and_clock(expected.source_binding, expected.observation_time)
        .map_err(|_| "child source or clock mismatch")?;
    if child.predecessor_checkpoint != expected.predecessor_checkpoint
        || child.parent != expected.parent {
        return Err("child checkpoint or parent mismatch");
    }
    verifier.verify(expected.program_id, public_values, proof_marker)
        .map_err(|_| "child receipt rejected")?;
    Ok(VerifiedChildObservationV5 { height: child.child_height,
        checkpoint: child.next_checkpoint })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::child_execution_guest_v3::AlphaChildExecutionPublicValuesV3;
    struct Exact(Vec<u8>);
    impl FullAlphaReceiptVerifierV3 for Exact {
        fn verify(&self, program: Hash32, bytes: &[u8], marker: &[u8])
            -> Result<(), crate::FullAlphaAdapterErrorV3> {
            if program == [1;32] && bytes == self.0 && marker == [7] { Ok(()) }
            else { Err(crate::FullAlphaAdapterErrorV3::Receipt) }
        }
    }
    #[test]
    fn requires_exact_receipt_source_clock_checkpoint_and_parent() {
        // Synthetic verifier tests composition only, not SP1 cryptography.
        let parent = AlphaConversionParentLinkPublicValuesV3 {
            binding_commitment: [1;32], parent_statement_commitment: [2;32],
            parent_predecessor_state_commitment: [3;32], parent_terminal_state_commitment: [4;32],
            parent_block_hash_internal: [5;32], parent_height: 100,
            parent_predecessor_hash_internal: [6;32], m7_critical_hash_internal: [7;32], m7_coinbase_vout: 1,
        };
        let statement = AlphaChildExecutionPublicValuesV5(AlphaChildExecutionPublicValuesV3 {
            source_binding: [8;32], predecessor_checkpoint: [9;32], next_checkpoint: [10;32],
            child_hash_internal: [11;32], child_height: 50, observation_time: 123, parent,
        });
        let bytes = statement.canonical_bytes();
        let exact = Exact(bytes.to_vec());
        let mut expected = ExpectedChildObservationV5 { program_id: [1;32], source_binding: [8;32],
            predecessor_checkpoint: [9;32], observation_time: 123, parent };
        let verified = verify_child_observation_v5(&expected, &bytes, &[7], &exact).unwrap();
        assert_eq!(verified.height(), 50);
        assert_eq!(verified.checkpoint(), [10;32]);
        assert!(verify_child_observation_v5(&expected, &bytes, &[], &exact).is_err());
        let mut altered = bytes; altered[132] ^= 1;
        assert!(verify_child_observation_v5(&expected, &altered, &[7], &exact).is_err());
        for field in 0..5 {
            match field {
                0 => expected.source_binding[0] ^= 1,
                1 => expected.observation_time += 1,
                2 => expected.predecessor_checkpoint[0] ^= 1,
                3 => expected.parent.parent_height += 1,
                _ => expected.program_id = [0;32],
            }
            assert!(verify_child_observation_v5(&expected, &bytes, &[7], &exact).is_err());
            expected.source_binding = [8;32]; expected.observation_time = 123;
            expected.predecessor_checkpoint = [9;32]; expected.parent = parent;
        }
    }

    #[test]
    fn full_anchor_observation_rejects_legacy_roles_and_changed_context() {
        // Exact-byte verifier tests binding, not cryptographic proof validity.
        let parent = AlphaConversionParentLinkPublicValuesV3 {
            binding_commitment: [1;32], parent_statement_commitment: [2;32],
            parent_predecessor_state_commitment: [3;32], parent_terminal_state_commitment: [4;32],
            parent_block_hash_internal: [5;32], parent_height: 100,
            parent_predecessor_hash_internal: [6;32], m7_critical_hash_internal: [7;32], m7_coinbase_vout: 1,
        };
        let statement = crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6(
            AlphaChildExecutionPublicValuesV3 {
                source_binding: [8;32], predecessor_checkpoint: [9;32], next_checkpoint: [10;32],
                child_hash_internal: [11;32], child_height: 50, observation_time: 123, parent,
            });
        let bytes = statement.canonical_bytes();
        let exact = Exact(bytes.to_vec());
        let expected = || ExpectedChildObservationV5 { program_id: [1;32], source_binding: [8;32],
            predecessor_checkpoint: [9;32], observation_time: 123, parent };
        assert_eq!(verify_child_observation_v6(&expected(), &bytes, &[7], &exact).unwrap().height(), 50);
        assert!(verify_child_observation_v5(&expected(), &bytes, &[7], &exact).is_err());
        for tag in [0xaa, 0xab, 0xac, 0xad] {
            let mut bad = bytes; bad[0] = tag;
            assert!(verify_child_observation_v6(&expected(), &bad, &[7], &Exact(bad.to_vec())).is_err());
        }
        for field in 0..7 {
            let mut bad = expected();
            match field {
                0 => bad.source_binding[0] ^= 1,
                1 => bad.predecessor_checkpoint[0] ^= 1,
                2 => bad.observation_time += 1,
                3 => bad.parent.parent_height += 1,
                4 => bad.parent.parent_block_hash_internal[0] ^= 1,
                5 => bad.parent.m7_critical_hash_internal[0] ^= 1,
                _ => bad.program_id = [2;32],
            }
            assert!(verify_child_observation_v6(&bad, &bytes, &[7], &exact).is_err());
        }
        assert!(verify_child_observation_v6(&expected(), &bytes, &[], &exact).is_err());
    }
}
