//! Full authority relation shared by host qualification and the SP1 entrypoint.
//! Authentication/deployment/CMR are proved claims checked by the spending
//! leaf through configuration, transaction and its own script. They are not
//! compiled into this guest (doing so would make its program ID circular).
use bincode::Options;
use serde::{Serialize, Deserialize};
use crate::{FullAlphaReceiptVerifierV3, Hash32};
use crate::custody_child_lineage_v2::{CustodyAccountingLineagePolicyV4,
    CustodyAccountingLineageReceiptV6, verify_custody_accounting_lineage_v6,
    custody_accounting_lineage_commitment_v6, custody_accounting_binding_v6};
use ecx_protocol_core::{HybridOracleConfigV1, TruthcoinAnchorStateV1,
    TruthcoinAnchorUpdateV1, TruthcoinAnchorDeploymentV1};
use ecx_truthcoin_replay::{ReplayInputV1, ReviewedNativeBootstrapV1};

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGuestPolicyV2 {
    pub bootstrap_commitment: Hash32,
    pub checkpoint_chainwork: Hash32,
    pub oracle: HybridOracleConfigV1,
    // Existing full-anchor CHILD execution lineage, despite the accounting
    // module's name. Its receipts are 407-byte V6 child statements, not the
    // 144-byte accounting projection. Includes genesis initialization.
    pub child: CustodyAccountingLineagePolicyV4,
    pub minimum_parent_confirmations: u32,
}
impl AuthorityGuestPolicyV2 {
    pub fn commitment(&self) -> Result<Hash32, String> {
        if self.bootstrap_commitment == [0;32] || self.checkpoint_chainwork == [0;32]
            || self.minimum_parent_confirmations == 0 {
            return Err("missing frozen authority policy".into());
        }
        custody_accounting_lineage_commitment_v6(&self.child).map_err(|_| "invalid child policy")?;
        self.oracle.validate().map_err(|_| "invalid oracle policy")?;
        let bytes = bincode::DefaultOptions::new().with_fixint_encoding()
            .serialize(self).map_err(|e| e.to_string())?;
        Ok(crate::tagged_hash("ECX/alpha-truthcoin-authority-guest-policy/v2", &bytes))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGuestInputV2 {
    pub policy: AuthorityGuestPolicyV2,
    pub replay: ReplayInputV1,
    pub bootstrap: ReviewedNativeBootstrapV1,
    pub prior: TruthcoinAnchorStateV1,
    pub update: TruthcoinAnchorUpdateV1,
    pub deployment: TruthcoinAnchorDeploymentV1,
    pub policy_asset: Hash32,
    pub authority_cmr: Hash32,
    pub settlement: ecx_elements_settlement::TruthcoinAnchorSettlementV1,
    pub inclusion: crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    pub observation: crate::FullAlphaAdapterInputV3,
    pub continuation: Vec<Vec<u8>>,
    pub child_lineage: Vec<CustodyAccountingLineageReceiptV6>,
}

pub fn decode_input(bytes: &[u8]) -> Result<AuthorityGuestInputV2, String> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err("authority input size".into());
    }
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_INPUT_BYTES as u64).deserialize(bytes).map_err(|e| e.to_string())
}

pub fn execute(input: &AuthorityGuestInputV2, frozen_policy: Hash32,
    verifier: &impl FullAlphaReceiptVerifierV3)
    -> Result<ecx_protocol_core::truthcoin_authority_journal::TruthcoinAuthorityJournalV1, String> {
    if frozen_policy == [0;32] || input.policy.commitment()? != frozen_policy {
        return Err("authority policy commitment mismatch".into());
    }
    let last = input.child_lineage.last().ok_or("missing child observation")?;
    let child = crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6::
        from_canonical_bytes(&last.receipt.public_values).map_err(|_| "invalid child statement")?.0;
    // The predecessor changes over time. Authenticate the whole supplied
    // lineage against the fixed reviewed root instead of freezing one block.
    verify_custody_accounting_lineage_v6(&input.policy.child, &input.child_lineage,
        child.next_checkpoint, child.child_height, verifier).map_err(|_| "child lineage rejected")?;
    let observation = crate::verified_child_observation_v5::verify_child_at_parent_observation_v6(
        &crate::verified_child_observation_v5::FrozenChildObservationPolicyV5 {
            program_id: input.policy.child.roots.execution.execution_program,
            source_binding: custody_accounting_binding_v6(&input.policy.child,
                child.predecessor_checkpoint, last.projection_predecessor, last.environment)
                .map_err(|_| "invalid child source binding")?,
            predecessor_checkpoint: child.predecessor_checkpoint,
            parent_binding_commitment: input.policy.child.roots.execution.parent_binding,
            minimum_parent_confirmations: input.policy.minimum_parent_confirmations,
        }, &input.inclusion, &input.observation, &input.continuation,
        &last.receipt.public_values, &last.receipt.proof_marker, verifier)?;
    let journal = ecx_truthcoin_replay::authority::execute_authority_settlement_from_bootstrap(
        &input.replay, &input.bootstrap,
        ecx_truthcoin_replay::authority::AuthorityReplayTrustV1 {
            reviewed_bootstrap_commitment: input.policy.bootstrap_commitment,
            checkpoint_chainwork: input.policy.checkpoint_chainwork,
            // Public configuration claim: independently constrained by the
            // actual authority leaf, not a witness-selected trust root here.
            authentication_hash: input.replay.authentication.digest(),
        }, &input.prior, &input.update, &input.policy.oracle, &input.deployment,
        input.policy_asset, u64::from(observation.child().height()),
        input.authority_cmr, &input.settlement)?;
    let endpoint = observation.parent();
    if journal.prior_parent_hash != endpoint.terminal_tip_hash_internal
        || journal.prior_parent_height != u64::from(endpoint.terminal_selected_height)
        || journal.prior_parent_mtp != endpoint.terminal_mtp
        || journal.prior_parent_chainwork != endpoint.terminal_chainwork_be {
        return Err("Truthcoin replay and Alpha observation endpoints differ".into());
    }
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> AuthorityGuestPolicyV2 {
        AuthorityGuestPolicyV2 {
            bootstrap_commitment: [1;32], checkpoint_chainwork: [2;32],
            minimum_parent_confirmations: 1,
            child: CustodyAccountingLineagePolicyV4 { genesis_initialization: [9;32],
                roots: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV5 {
                execution: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV2 {
                    execution_program: [1;32], initial_checkpoint: [2;32], initial_height: 0,
                    parent_binding: [3;32], execution_policy: [4;32],
                    simplicity_program: [5;32], deposit_configuration: [6;32],
                }, evaluator_source_closure: [7;32], genesis_bindings: [8;32], successor: None,
            } },
            oracle: HybridOracleConfigV1 {
                version: 1, truthcoin_chain_id: [1;32], truthcoin_branch_id: [2;32],
                btc_usd_template_hash: [3;32], lmsr_math_commitment: [4;32],
                schedule_origin_mtp: 100, epoch_length_seconds: 86400,
                minimum_source_confirmations: 1, maximum_anchor_age_seconds: 1000,
                maximum_snapshot_age_seconds: 1000, minimum_lmsr_b: 1, minimum_sample_count: 1,
                base_lmsr_weight_ppm: 0, maximum_lmsr_weight_ppm: 100_000,
                initial_anchor_band_bps: 100, maximum_anchor_band_bps: 200,
                risk_haircut_bps: 0, boundary_guard_ppb: 0,
                maximum_unanchored_deviation_bps: 100, ecx_satoshis_per_coin: 100_000_000,
                usdd_usd_price_units: 100_000_000,
            },
        }
    }
    #[test]
    fn policy_commits_all_decodable_bytes_and_rejects_missing_trust() {
        // Synthetic codec/policy values only; never production defaults.
        let p = policy();
        let expected = p.commitment().unwrap();
        let encoded = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&p).unwrap();
        for index in 0..encoded.len() {
            let mut altered = encoded.clone(); altered[index] ^= 1;
            if let Ok(changed) = bincode::DefaultOptions::new().with_fixint_encoding()
                .reject_trailing_bytes().deserialize::<AuthorityGuestPolicyV2>(&altered) {
                assert_ne!(changed.commitment(), Ok(expected), "unbound byte {index}");
            }
        }
        let mut bad = policy(); bad.bootstrap_commitment = [0;32];
        assert!(bad.commitment().is_err());
        let mut bad = policy(); bad.checkpoint_chainwork = [0;32];
        assert!(bad.commitment().is_err());
        let mut bad = policy(); bad.minimum_parent_confirmations = 0;
        assert!(bad.commitment().is_err());
        let mut bad = policy(); bad.oracle.minimum_source_confirmations = 0;
        assert!(bad.commitment().is_err());
        let mut bad = policy(); bad.child.genesis_initialization = [0;32];
        assert!(bad.commitment().is_err());
        assert_ne!(expected, crate::tagged_hash("ECX/alpha-truthcoin-authority-guest-policy/v1", &encoded));
        assert!(decode_input(&[]).is_err());
        assert!(decode_input(&[0;32]).is_err());
    }

    #[test]
    fn authority_v6_lineage_binds_full_checkpoint_and_release_roots() {
        // Synthetic statements isolate composition; NOT SP1 proof qualification.
        use crate::child_execution_guest_v3::AlphaChildExecutionPublicValuesV3;
        use crate::child_custody_guest_v6::CustodyExecutionPublicValuesV6;
        use crate::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3;
        let mut p = policy();
        p.child.roots.successor = Some(crate::child_execution_statement_v4::SuccessorIdentityV4 {
            configuration_hash: [20;32], program_id: [21;32], transition_cmr: [22;32],
        });
        let roots = &p.child.roots.execution;
        let parent = AlphaConversionParentLinkPublicValuesV3 {
            binding_commitment: roots.parent_binding, parent_statement_commitment: [10;32],
            parent_predecessor_state_commitment: [11;32], parent_terminal_state_commitment: [12;32],
            parent_block_hash_internal: [13;32], parent_height: 100,
            parent_predecessor_hash_internal: [14;32], m7_critical_hash_internal: [15;32], m7_coinbase_vout: 1,
        };
        let mut entry = CustodyAccountingLineageReceiptV6 {
            projection_predecessor: [16;32], environment: [17;32],
            receipt: crate::AlphaRecursiveReceiptBindingV3 { public_values: vec![], proof_marker: vec![1] },
        };
        let public = CustodyExecutionPublicValuesV6(AlphaChildExecutionPublicValuesV3 {
            source_binding: custody_accounting_binding_v6(&p.child, roots.initial_checkpoint,
                entry.projection_predecessor, entry.environment).unwrap(),
            predecessor_checkpoint: roots.initial_checkpoint, next_checkpoint: [18;32],
            child_hash_internal: [19;32], child_height: 1, observation_time: 123, parent,
        }).canonical_bytes().to_vec();
        entry.receipt.public_values = public.clone();
        struct Exact(Vec<u8>);
        impl FullAlphaReceiptVerifierV3 for Exact {
            fn verify(&self, id: Hash32, bytes: &[u8], marker: &[u8]) -> Result<(),crate::FullAlphaAdapterErrorV3> {
                if id == [1;32] && bytes == self.0 && marker == [1] { Ok(()) }
                else { Err(crate::FullAlphaAdapterErrorV3::Receipt) }
            }
        }
        let exact = Exact(public);
        let check = |p: &CustodyAccountingLineagePolicyV4, e: &CustodyAccountingLineageReceiptV6| {
            verify_custody_accounting_lineage_v6(p, &[e.clone()], [18;32], 1, &exact)
        };
        assert!(check(&p.child, &entry).is_ok());
        for field in 0..9 {
            let mut bad = p.child.clone();
            match field {
                0 => bad.roots.execution.initial_checkpoint[0] ^= 1,
                1 => bad.roots.execution.execution_program[0] ^= 1,
                2 => bad.genesis_initialization[0] ^= 1,
                3 => bad.roots.genesis_bindings[0] ^= 1,
                4 => bad.roots.evaluator_source_closure[0] ^= 1,
                5 => bad.roots.successor.as_mut().unwrap().configuration_hash[0] ^= 1,
                6 => bad.roots.successor.as_mut().unwrap().program_id[0] ^= 1,
                7 => bad.roots.successor.as_mut().unwrap().transition_cmr[0] ^= 1,
                _ => bad.roots.execution.parent_binding[0] ^= 1,
            }
            assert!(check(&bad, &entry).is_err(), "unbound policy field {field}");
        }
        for field in 0..5 {
            let mut bad = entry.clone();
            match field {
                0 => bad.projection_predecessor[0] ^= 1,
                1 => bad.environment[0] ^= 1,
                2 => bad.receipt.public_values[0] = 0xab,
                3 => bad.receipt.public_values.truncate(144),
                _ => bad.receipt.proof_marker.clear(),
            }
            assert!(check(&p.child, &bad).is_err(), "unbound receipt field {field}");
        }
        assert!(verify_custody_accounting_lineage_v6(&p.child, &[], [18;32], 1, &exact).is_err());
        assert!(verify_custody_accounting_lineage_v6(&p.child, &[entry], [18;32], 2, &exact).is_err());
    }
}
