//! Additional authority material derived INSIDE the native production replay.
//! The legacy 1269-byte source receipt is unchanged. These fields are not
//! authenticated by that receipt's old program ID: an enclosing authority guest
//! must call this entrypoint and bind its result to its own public journal.
use super::*;

/// Verifier-selected trust inputs, never copied from an untrusted witness.
/// Checkpoint work includes the checkpoint block itself, in numeric big endian.
/// Its pairing with the reviewed checkpoint must be frozen in the outer guest
/// configuration; the existing bootstrap commitment does not include work.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityReplayTrustV1 {
    pub reviewed_bootstrap_commitment: Hash32,
    pub authentication_hash: Hash32,
    pub checkpoint_chainwork: Hash32,
}

/// Enclosing-verifier entry point: authenticate replay, derive the successor,
/// render both state scripts, and validate the exact settlement transaction.
/// No caller-supplied successor or script descriptors are accepted.
///
/// The enclosing guest must select trust/oracle/deployment/asset from its frozen
/// policy and bind elements_height to execution context. The CMR is checked by
/// the spending leaf against its own CMR; embedding that final CMR in the guest
/// would create a guest-ID / leaf-CMR cycle. This function alone is NOT a guest.
#[cfg(feature = "authority-settlement")]
#[allow(clippy::too_many_arguments)]
pub fn execute_authority_settlement_from_bootstrap(
    input: &ReplayInputV1,
    bootstrap: &ReviewedNativeBootstrapV1,
    trust: AuthorityReplayTrustV1,
    prior: &TruthcoinAnchorStateV1,
    update: &ecx_protocol_core::TruthcoinAnchorUpdateV1,
    oracle_policy: &ecx_protocol_core::HybridOracleConfigV1,
    deployment: &ecx_protocol_core::TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
    elements_height: u64,
    authority_cmr: Hash32,
    settlement: &ecx_elements_settlement::TruthcoinAnchorSettlementV1,
) -> Result<ecx_protocol_core::truthcoin_authority_journal::TruthcoinAuthorityJournalV1, String> {
    let replay = execute_authority_replay_from_bootstrap(input, bootstrap, trust)
        .map_err(|e| format!("authority replay: {e}"))?;
    let successor = replay.derive_successor(prior, update, oracle_policy,
        &input.authentication, deployment, policy_asset_id, elements_height)
        .map_err(|e| format!("authority successor: {e}"))?;
    ecx_elements_settlement::truthcoin_authority::rendered_settlement_journal(
        settlement, prior, &successor, update, authority_cmr,
        &input.authentication, deployment, policy_asset_id,
    ).map_err(|e| format!("authority settlement: {e}"))
}

/// No public constructor or Deserialize: consumers get this only through
/// production replay, not by wrapping host-selected roots in a receipt type.
#[derive(Debug)]
pub struct AuthorityReplayOutputV1 {
    source: ReplayOutputV1,
    bitcoin_tip_chainwork: Hash32,
    child_tip_parent_hash: Hash32,
    decision_registry_root: Hash32,
}

impl AuthorityReplayOutputV1 {
    pub fn source(&self) -> &ReplayOutputV1 { &self.source }
    pub fn bitcoin_tip_chainwork(&self) -> Hash32 { self.bitcoin_tip_chainwork }
    pub fn child_tip_parent_hash(&self) -> Hash32 { self.child_tip_parent_hash }
    pub fn decision_registry_root(&self) -> Hash32 { self.decision_registry_root }

    /// Construct the complete next state from production replay, not a caller's
    /// proposed source roots. The outer verifier must pin the oracle policy and
    /// bind `elements_height` to its execution context. This is not a script or
    /// transaction verifier; those checks remain mandatory at the outer boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_successor(
        &self,
        prior: &TruthcoinAnchorStateV1,
        update: &ecx_protocol_core::TruthcoinAnchorUpdateV1,
        oracle_policy: &ecx_protocol_core::HybridOracleConfigV1,
        authentication: &ecx_protocol_core::TruthcoinAuthenticationConfigV1,
        deployment: &ecx_protocol_core::TruthcoinAnchorDeploymentV1,
        policy_asset_id: Hash32,
        elements_height: u64,
    ) -> Result<TruthcoinAnchorStateV1, ReplayError> {
        let p = &self.source.public_values;
        authentication.validate().map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
        deployment.validate(policy_asset_id).map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
        if p.authentication_config_hash != authentication.digest()
            || prior.configuration_hash != ecx_protocol_core::truthcoin_anchor_configuration_hash(
                authentication, deployment, policy_asset_id)
            || update.update_public_values_hash != p.digest()
            || prior.truthcoin_genesis_hash != p.sidechain_genesis_hash
            || p.observed_parent_block_hash != p.bitcoin_tip_hash
            || p.observed_parent_height != p.bitcoin_tip_height {
            return Err(ReplayError::InvalidIncrementalAnchorBinding);
        }
        let quote = ecx_protocol_core::derive_hybrid_quote(
            oracle_policy, &p.anchor, &p.lmsr_snapshot, p.observed_parent_mtp,
        ).map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
        let mut next = prior.clone();
        next.sequence = prior.sequence.checked_add(1)
            .ok_or(ReplayError::InvalidIncrementalAnchorBinding)?;
        next.bitcoin_checkpoint_hash = p.bitcoin_tip_hash;
        next.bitcoin_checkpoint_height = p.bitcoin_tip_height;
        next.bitcoin_checkpoint_mtp = p.observed_parent_mtp;
        next.bitcoin_checkpoint_chainwork = self.bitcoin_tip_chainwork;
        next.truthcoin_tip_hash = p.sidechain_tip_hash;
        next.truthcoin_tip_height = p.sidechain_tip_height;
        next.truthcoin_tip_parent_bitcoin_hash = self.child_tip_parent_hash;
        next.canonical_path_root = p.canonical_chain_root;
        next.replay_transcript_root = p.replay_transcript_root;
        next.complete_state_root = p.replayed_state_root;
        next.decision_registry_root = self.decision_registry_root;
        next.market_registry_root = p.lmsr_snapshot.registry_root;
        next.lmsr_state_root = p.lmsr_snapshot.lmsr_state_root;
        next.sample_window_root = p.lmsr_snapshot.sample_window_root;
        next.selected_anchor_commitment = p.anchor.digest();
        next.selected_fast_market_commitment = p.lmsr_snapshot.digest();
        next.oracle_certificate_commitment = quote.certificate_hash();
        next.last_update_elements_height = elements_height;
        next.source_data_available_through_height = p.bitcoin_tip_height;
        next.last_update_proof_commitment = p.digest();
        next.cumulative_update_root = ecx_protocol_core::truthcoin_anchor_history_root(
            prior, &next, update,
        );
        ecx_protocol_core::verify_truthcoin_anchor_successor(prior, &next, update)
            .map_err(|_| ReplayError::InvalidIncrementalAnchorBinding)?;
        Ok(next)
    }
}

pub fn execute_authority_replay_from_bootstrap(
    input: &ReplayInputV1,
    bootstrap: &ReviewedNativeBootstrapV1,
    trust: AuthorityReplayTrustV1,
) -> Result<AuthorityReplayOutputV1, ReplayError> {
    if trust.checkpoint_chainwork == [0; 32] {
        return Err(ReplayError::InvalidIncrementalCheckpoint);
    }
    replay_bootstrap_with(input, bootstrap, trust.reviewed_bootstrap_commitment,
        trust.authentication_hash, |structure, store, state, headers| {
            let source = finalize_replay_output(input, structure, state)?;
            let context = structure.canonical_block_contexts.last()
                .ok_or(ReplayError::EmptySidechain)?;
            if context.sidechain_block_hash != source.public_values.sidechain_tip_hash
                || context.sidechain_height != source.public_values.sidechain_tip_height
                || store.root()? != source.public_values.replayed_state_root {
                return Err(ReplayError::InvalidStateMachineOutput);
            }
            Ok(AuthorityReplayOutputV1 {
                source,
                bitcoin_tip_chainwork: accumulate_work(trust.checkpoint_chainwork, headers)?,
                child_tip_parent_hash: context.bmm_main_block_hash,
                decision_registry_root: decision_registry_root(store)?,
            })
        })
}

// Headers have already passed ancestry, difficulty, PoW and MTP verification.
// Use explicit checked addition: a wrapped 256-bit work counter is invalid.
fn accumulate_work(mut work: Hash32, headers: &[BitcoinHeader]) -> Result<Hash32, ReplayError> {
    let checkpoint = headers.first().ok_or(ReplayError::EmptyMainchain)?;
    if work < checkpoint.work().to_be_bytes() {
        return Err(ReplayError::InvalidIncrementalCheckpoint);
    }
    for header in headers.iter().skip(1) {
        work = add_work(work, header.work().to_be_bytes())?;
    }
    Ok(work)
}

fn add_work(mut total: Hash32, increment: Hash32) -> Result<Hash32, ReplayError> {
    let mut carry = 0_u16;
    for i in (0..32).rev() {
        let sum = u16::from(total[i]) + u16::from(increment[i]) + carry;
        total[i] = sum as u8;
        carry = sum >> 8;
    }
    if carry != 0 { return Err(ReplayError::InvalidIncrementalCheckpoint); }
    Ok(total)
}

// A distinct, versioned commitment to ALL decision records/history/outcomes,
// not a relabelled complete-state root or host-selected winning decision.
// Table IDs, counts and byte lengths make table/entry boundaries unambiguous.
fn decision_registry_root(store: &CanonicalStateStoreV1) -> Result<Hash32, ReplayError> {
    let mut h = TaggedHasher::new("ECX/truthcoin-decision-registry/v1");
    for id in [TruthcoinDatabaseId::PeriodDecisions,
        TruthcoinDatabaseId::DecisionStateHistories, TruthcoinDatabaseId::DecisionOutcomes] {
        let table = store.table(id.as_u8())?;
        h.bytes(&[id.as_u8()]);
        h.u64(table.entries.len() as u64);
        for entry in &table.entries {
            h.length_prefixed(&entry.key);
            h.length_prefixed(&entry.value);
        }
    }
    Ok(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_protocol_core::codec::CanonicalEncode;

    #[test]
    fn successor_mapping_and_substitution_rejection() {
        use ecx_protocol_core::*;
        // Synthetic mapping test, not a claim of successful native replay.
        let (input, mut source) = crate::tests::authority_mapping_fixture();
        let a = &input.authentication;
        let policy = HybridOracleConfigV1 {
            version: 1, truthcoin_chain_id: a.truthcoin_chain_id,
            truthcoin_branch_id: a.truthcoin_branch_id,
            btc_usd_template_hash: a.btc_usd_template_hash,
            lmsr_math_commitment: a.lmsr_math_commitment,
            schedule_origin_mtp: source.public_values.lmsr_snapshot.epoch_start_mtp - 200,
            epoch_length_seconds: 100, minimum_source_confirmations: 1,
            maximum_anchor_age_seconds: 1000, maximum_snapshot_age_seconds: 1000,
            minimum_lmsr_b: 1, minimum_sample_count: 1,
            base_lmsr_weight_ppm: 0, maximum_lmsr_weight_ppm: 100_000,
            initial_anchor_band_bps: 100, maximum_anchor_band_bps: 200,
            risk_haircut_bps: 100, boundary_guard_ppb: 1,
            maximum_unanchored_deviation_bps: 5000,
            ecx_satoshis_per_coin: 1000, usdd_usd_price_units: 100_000_000,
        };
        let p = &mut source.public_values;
        p.anchor.slot_id = policy.canonical_slot_id(1).unwrap();
        p.anchor.observation_end_mtp = policy.epoch_start(2).unwrap();
        p.lmsr_snapshot.slot_id = policy.canonical_slot_id(2).unwrap();
        p.lmsr_snapshot.resolves_at_mtp = policy.epoch_end(2).unwrap();
        source.public_values_bytes = p.canonical_bytes();
        let replay = AuthorityReplayOutputV1 { source, bitcoin_tip_chainwork: [3;32],
            child_tip_parent_hash: [4;32], decision_registry_root: [5;32] };
        let p = &replay.source.public_values;
        let deployment = TruthcoinAnchorDeploymentV1 { version: 1,
            authority_asset_id: [6;32], authority_amount: 1,
            script_tree_configuration_hash: [7;32] };
        let asset = [8;32];
        let prior = TruthcoinAnchorStateV1 {
            version: 1, configuration_hash: truthcoin_anchor_configuration_hash(a, &deployment, asset),
            sequence: 0, bitcoin_checkpoint_hash: [1;32],
            bitcoin_checkpoint_height: p.bitcoin_tip_height - 1,
            bitcoin_checkpoint_mtp: p.observed_parent_mtp,
            bitcoin_checkpoint_chainwork: [2;32],
            truthcoin_genesis_hash: p.sidechain_genesis_hash,
            truthcoin_tip_hash: [1;32], truthcoin_tip_height: p.sidechain_tip_height - 1,
            truthcoin_tip_parent_bitcoin_hash: [1;32], canonical_path_root: [1;32],
            replay_transcript_root: [1;32], complete_state_root: [1;32],
            decision_registry_root: [1;32], market_registry_root: [1;32],
            lmsr_state_root: [1;32], sample_window_root: [1;32],
            selected_anchor_commitment: [1;32], selected_fast_market_commitment: [1;32],
            oracle_certificate_commitment: [1;32], last_update_elements_height: 1,
            source_data_available_through_height: p.bitcoin_tip_height - 1,
            cumulative_update_root: [1;32], last_update_proof_commitment: [0;32],
        };
        let update = TruthcoinAnchorUpdateV1 { version: 1,
            prior_authority_outpoint: AnchorOutpointV1 { txid: [9;32], vout: 0 },
            successor_transaction_id: [10;32], successor_authority_output_index: 0,
            update_public_values_hash: p.digest() };
        let derive = |prior: &TruthcoinAnchorStateV1, update: &TruthcoinAnchorUpdateV1,
            policy: &HybridOracleConfigV1, auth: &TruthcoinAuthenticationConfigV1, height| {
            replay.derive_successor(prior, update, policy, auth, &deployment, asset, height)
        };
        let next = derive(&prior, &update, &policy, a, 2).unwrap();
        assert_eq!(next.truthcoin_tip_parent_bitcoin_hash, [4;32]);
        assert_eq!(next.decision_registry_root, [5;32]);
        assert_eq!(next.bitcoin_checkpoint_chainwork, [3;32]);
        assert_eq!(next.complete_state_root, p.replayed_state_root);
        assert_eq!(next.oracle_certificate_commitment,
            derive_hybrid_quote(&policy, &p.anchor, &p.lmsr_snapshot, p.observed_parent_mtp)
                .unwrap().certificate_hash());
        let mut bad_update = update.clone(); bad_update.update_public_values_hash = [11;32];
        assert!(derive(&prior, &bad_update, &policy, a, 2).is_err());
        let mut bad_prior = prior.clone(); bad_prior.configuration_hash = [12;32];
        assert!(derive(&bad_prior, &update, &policy, a, 2).is_err());
        let mut bad_auth = a.clone(); bad_auth.source_proof_program_id = [13;32];
        assert!(derive(&prior, &update, &policy, &bad_auth, 2).is_err());
        let mut bad_policy = policy.clone(); bad_policy.truthcoin_chain_id = [14;32];
        assert!(derive(&prior, &update, &bad_policy, a, 2).is_err());
        assert!(derive(&prior, &update, &policy, a, 1).is_err());
    }

    #[test]
    fn work_is_big_endian_checked_and_checkpoint_is_not_double_counted() {
        let header = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        let start = header.work().to_be_bytes();
        assert_eq!(accumulate_work(start, &[header]).unwrap(), start);
        assert_eq!(accumulate_work(start, &[header, header]).unwrap(),
            add_work(start, start).unwrap());
        assert!(accumulate_work([0;32], &[header]).is_err());
        assert!(accumulate_work(start, &[]).is_err());
        assert!(add_work([255;32], start).is_err());
        let mut x = [0;32]; x[31] = 255;
        let mut one = [0;32]; one[31] = 1;
        let mut expected = [0;32]; expected[30] = 1;
        assert_eq!(add_work(x, one).unwrap(), expected);
    }

    #[test]
    fn decision_registry_binds_all_tables_keys_values_and_boundaries() {
        let empty = CanonicalStateStoreV1::new();
        let root = decision_registry_root(&empty).unwrap();
        assert_ne!(root, empty.root().unwrap());
        let mut roots = std::collections::BTreeSet::new();
        for id in [TruthcoinDatabaseId::PeriodDecisions,
            TruthcoinDatabaseId::DecisionStateHistories, TruthcoinDatabaseId::DecisionOutcomes] {
            let mut store = empty.clone();
            store.put(id.as_u8(), vec![1], vec![2,3]).unwrap();
            let first = decision_registry_root(&store).unwrap();
            assert_ne!(first, root);
            assert!(roots.insert(first));
            store.put(id.as_u8(), vec![1], vec![2,4]).unwrap();
            assert_ne!(first, decision_registry_root(&store).unwrap());
            let mut repartitioned = empty.clone();
            repartitioned.put(id.as_u8(), vec![1,2], vec![3]).unwrap();
            assert_ne!(first, decision_registry_root(&repartitioned).unwrap());
        }
    }
}
