//! Synthetic relation tests, NOT proof receipts or deployed chain evidence.
use super::*;

fn word(n: u128) -> Hash32 {
    let mut out = [0; 32];
    out[16..].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn frozen_configuration_rejects_every_aliased_proof_role() {
    let original = fixture();
    original.frozen_configuration.validate().unwrap();
    for pair in 0..3 {
        let mut input = original.clone();
        let c = &mut input.frozen_configuration;
        match pair {
            0 => c.elements_source_program_id = c.ethereum_source_program_id,
            1 => c.redemption.strong_redemption_program_id = c.ethereum_source_program_id,
            2 => c.redemption.strong_redemption_program_id = c.elements_source_program_id,
            _ => unreachable!(),
        }
        assert_eq!(c.validate(), Err(OwnerlessConversionErrorV3::Configuration));
        assert_eq!(c.commitment(), Err(OwnerlessConversionErrorV3::Configuration));
        let encoded = input.canonical_bytes().unwrap();
        assert_eq!(OwnerlessConversionInputV3::decode_canonical(&encoded),
            Err(OwnerlessConversionErrorV3::Configuration));
        assert_eq!(execute_ownerless_conversion_v3(&input, &ExactFixtureVerifier::new(&input)),
            Err(OwnerlessConversionErrorV3::Configuration));
    }
}

fn checkpoint_preparation_prior(i: &OwnerlessConversionInputV3) -> UsddEthereumCheckpointV1 {
    let e = &i.ethereum_public_values;
    UsddEthereumCheckpointV1 {
        version: 1,
        configuration_hash: i.frozen_configuration.checkpoint_configuration().digest(),
        sequence: 0,
        light_client_digest: e.prior_light_client_digest,
        finalized_beacon_slot: e.prior_finalized_beacon_slot,
        finalized_beacon_root: e.prior_finalized_beacon_root,
        finalized_execution_block_hash: [80; 32],
        finalized_execution_state_root: e.prior_finalized_execution_state_root,
        finalized_execution_block_number: e.execution_block_number - 1,
        finalized_execution_timestamp: e.execution_block_timestamp - 12,
        accepted_parent_mtp: e.execution_block_timestamp,
        prior_checkpoint_commitment: [0; 32],
        update_proof_commitment: [81; 32],
    }
}

#[test]
fn checkpoint_preparer_derives_exact_successor_from_frozen_source_receipt() {
    use crate::usdd_checkpoint_authority_v3::prepare_ownerless_checkpoint_transition_v3;
    let i = fixture();
    let prior = checkpoint_preparation_prior(&i);
    let mtp = i.ethereum_public_values.execution_block_timestamp + 60;
    let prepared = prepare_ownerless_checkpoint_transition_v3(
        &i.frozen_configuration, &prior, &i.ethereum_public_values,
        &i.ethereum_proof_marker, mtp, &ExactFixtureVerifier::new(&i),
    ).unwrap();
    let next = prepared.successor();
    assert_eq!(prepared.prior(), &prior);
    assert_eq!(next.sequence, prior.sequence + 1);
    assert_eq!(next.prior_checkpoint_commitment, prior.commitment());
    assert_eq!(next.accepted_parent_mtp, mtp);
    assert_eq!(next.finalized_execution_block_hash, i.ethereum_public_values.finalized_execution_block_hash);
    assert_eq!(next.update_proof_commitment, i.ethereum_public_values.update_proof_commitment);
    ecx_protocol_core::verify_usdd_checkpoint_successor(
        &i.frozen_configuration.checkpoint_configuration(), &prior, next,
    ).unwrap();
}

#[test]
fn checkpoint_preparer_rejects_prior_state_substitution_and_stale_acceptance() {
    use crate::usdd_checkpoint_authority_v3::prepare_ownerless_checkpoint_transition_v3;
    let i = fixture();
    let prior = checkpoint_preparation_prior(&i);
    let verifier = ExactFixtureVerifier::new(&i);
    for index in 0..7 {
        let mut bad = prior;
        match index {
            0 => bad.light_client_digest[0] ^= 1,
            1 => bad.finalized_beacon_slot -= 1,
            2 => bad.finalized_beacon_root[0] ^= 1,
            3 => bad.finalized_execution_state_root[0] ^= 1,
            4 => bad.configuration_hash[0] ^= 1,
            5 => { bad.sequence = u64::MAX; bad.prior_checkpoint_commitment = [82; 32]; },
            6 => bad.finalized_execution_block_number = i.ethereum_public_values.execution_block_number,
            _ => unreachable!(),
        }
        assert!(prepare_ownerless_checkpoint_transition_v3(
            &i.frozen_configuration, &bad, &i.ethereum_public_values,
            &i.ethereum_proof_marker, i.ethereum_public_values.execution_block_timestamp + 60,
            &verifier,
        ).is_err(), "accepted substituted prior field {index}");
    }
    for mtp in [i.ethereum_public_values.execution_block_timestamp - 1,
        i.ethereum_public_values.execution_block_timestamp + i.frozen_configuration.maximum_age_seconds + 1] {
        assert!(prepare_ownerless_checkpoint_transition_v3(
            &i.frozen_configuration, &prior, &i.ethereum_public_values,
            &i.ethereum_proof_marker, mtp, &verifier,
        ).is_err());
    }
}

#[test]
fn checkpoint_preparer_requires_exact_proof_program_statement_and_marker() {
    use crate::usdd_checkpoint_authority_v3::prepare_ownerless_checkpoint_transition_v3;
    let i = fixture();
    let prior = checkpoint_preparation_prior(&i);
    let verifier = ExactFixtureVerifier::new(&i);
    for index in 0..7 {
        let mut candidate = i.clone();
        match index {
            0 => candidate.frozen_configuration.ethereum_source_program_id[0] ^= 1,
            1 => candidate.ethereum_public_values.finalized_execution_block_hash[0] ^= 1,
            2 => candidate.ethereum_public_values.protocol_manifest_commitment[0] ^= 1,
            3 => candidate.ethereum_proof_marker[0] ^= 1,
            4 => candidate.ethereum_proof_marker.clear(),
            5 => candidate.ethereum_proof_marker = vec![70; 65],
            6 => candidate.ethereum_public_values.minted_redemption_backing = word(999_999),
            _ => unreachable!(),
        }
        assert!(prepare_ownerless_checkpoint_transition_v3(
            &candidate.frozen_configuration, &prior, &candidate.ethereum_public_values,
            &candidate.ethereum_proof_marker, candidate.ethereum_public_values.execution_block_timestamp + 60,
            &verifier,
        ).is_err(), "accepted substituted receipt {index}");
    }
}

fn identity(address: u8, code: u8) -> OwnerlessContractIdentityV3 {
    OwnerlessContractIdentityV3 {
        address: [address; 20],
        runtime_code_hash: [code; 32],
    }
}

fn fixture() -> OwnerlessConversionInputV3 {
    let source = OwnerlessSourceConfigurationV3 {
        version: 3,
        ethereum_chain_id: 11_155_111,
        ethereum_light_client_configuration_hash: [1; 32],
        usdd_asset_id: [2; 32],
        elements_genesis_hash: [3; 32],
        custody_id: [4; 32],
        vault: identity(10, 20),
        reserve_token: identity(11, 21),
        relay: identity(12, 22),
        redemption_verifier: identity(13, 23),
        price: identity(14, 24),
        relay_verifier_configuration_hash: [30; 32],
        terminal_vault_policy_hash: [31; 32],
        ownerless_layout_commitment: OWNERLESS_LAYOUT_COMMITMENT_V3,
        reserve_balance_mapping_slot: [33; 32],
        price_storage_key: [0; 32],
        token_decimals: 6,
        usdd_decimals: 8,
        quote_decimals: 8,
    };
    let script = b"synthetic-only-custody-bound-v2-script".to_vec();
    let c = FrozenOwnerlessConversionConfigurationV3 {
        version: 3,
        source,
        protocol_manifest_commitment: [40; 32],
        ethereum_source_program_id: [41; 32],
        elements_source_program_id: [42; 32],
        elements_source_configuration_commitment: [43; 32],
        elements_source_bootstrap_commitment: [44; 32],
        checkpoint_authority_configuration_hash: [45; 32],
        redemption: OwnerlessRedemptionBindingV3 {
            strong_redemption_program_id: [46; 32],
            strong_redemption_configuration_hash: [47; 32],
            covenant_script_commitment: tagged_hash(
                "ECX/usdd-ownerless-covenant-script/v3",
                &script,
            ),
        },
        maximum_age_seconds: 13 * 24 * 60 * 60,
    };
    let e = OwnerlessEthereumPublicValuesV3 {
        version: 3,
        frozen_configuration_commitment: c.source.commitment(),
        protocol_manifest_commitment: c.protocol_manifest_commitment,
        update_proof_commitment: [50; 32],
        prior_light_client_digest: [51; 32],
        prior_finalized_beacon_slot: 9_968,
        prior_finalized_beacon_root: [52; 32],
        prior_finalized_execution_state_root: [53; 32],
        finalized_beacon_slot: 10_000,
        finalized_beacon_root: [54; 32],
        finalized_execution_block_hash: [55; 32],
        finalized_execution_state_root: [56; 32],
        execution_block_number: 20_000_000,
        execution_block_timestamp: 1_800_000_000,
        light_client_digest: [57; 32],
        next_intent_nonce: 9,
        next_committed_deposit_nonce: 7,
        reserve: word(3_200_000),
        accounted_custody: word(1_700_000),
        pending_principal: word(200_000),
        pending_bounty: word(100_000),
        committed_principal: word(1_300_000),
        committed_bounty: word(100_000),
        unresolved_committed: word(300_000),
        mint_acknowledged: word(1_000_000),
        other_obligations: word(700_000),
        minted_redemption_backing: word(1_000_000),
        unallocated_surplus: word(1_500_000),
        quote_atoms_per_whole_reserve_token: PRICE_SCALE,
        token_decimals: 6,
        usdd_decimals: 8,
        quote_decimals: 8,
    };
    let mut l = UsddElementsSourcePublicValuesV2 {
        version: 1,
        observed_parent_block_hash: [60; 32],
        observed_parent_height: 900_000,
        observed_parent_mtp: e.execution_block_timestamp + 60,
        bitcoin_bmm_history_root: [61; 32],
        elements_genesis_hash: c.source.elements_genesis_hash,
        elements_tip_hash: [62; 32],
        elements_height: 50_000,
        elements_source_configuration_commitment: c.elements_source_configuration_commitment,
        elements_source_bootstrap_commitment: c.elements_source_bootstrap_commitment,
        usdd_checkpoint_configuration_hash: c.checkpoint_configuration().digest(),
        prior_checkpoint_commitment: [63; 32],
        prior_checkpoint_sequence: 1,
        prior_checkpoint_light_client_digest: e.prior_light_client_digest,
        prior_checkpoint_finalized_beacon_slot: e.prior_finalized_beacon_slot,
        prior_checkpoint_finalized_beacon_root: e.prior_finalized_beacon_root,
        prior_checkpoint_execution_state_root: e.prior_finalized_execution_state_root,
        current_checkpoint_commitment: [64; 32],
        checkpoint_sequence: 2,
        checkpoint_light_client_digest: e.light_client_digest,
        checkpoint_finalized_beacon_slot: e.finalized_beacon_slot,
        checkpoint_finalized_beacon_root: e.finalized_beacon_root,
        checkpoint_execution_block_hash: e.finalized_execution_block_hash,
        checkpoint_execution_state_root: e.finalized_execution_state_root,
        checkpoint_execution_block_number: e.execution_block_number,
        checkpoint_execution_timestamp: e.execution_block_timestamp,
        checkpoint_accepted_parent_mtp: e.execution_block_timestamp + 30,
        checkpoint_update_proof_commitment: e.update_proof_commitment,
        usdd_asset_id: c.source.usdd_asset_id,
        outstanding_usdd_atoms: 100_000_000,
        redemption_covenant_commitment: c.redemption_covenant_commitment(),
        redemption_covenant_live: true,
        elements_consensus_state_root: [65; 32],
    };
    l.current_checkpoint_commitment = checkpoint_from_elements(&l).commitment();
    let elements = OwnerlessElementsPublicValuesV3 {
        version: 3,
        role: OwnerlessElementsPublicValuesV3::required_role(),
        common: l,
        custody_id: c.source.custody_id,
        redemption_binding_commitment: c.redemption_covenant_commitment(),
    };
    let public = ConversionLegPublicValuesV2 {
        version: 2,
        kind: ConversionLegKindV2::UsddUsd,
        observed_parent_block_hash: elements.common.observed_parent_block_hash,
        observed_parent_height: elements.common.observed_parent_height,
        observed_parent_mtp: elements.common.observed_parent_mtp,
        source_height: e.execution_block_number,
        source_mtp: e.execution_block_timestamp,
        valid_until_mtp: e.execution_block_timestamp + c.maximum_age_seconds,
        base_asset_id: c.source.usdd_asset_id,
        quote_unit_id: c.source.ethereum_light_client_configuration_hash,
        redemption_covenant_commitment: c.redemption_covenant_commitment(),
        source_checkpoint_commitment: c.commitment().unwrap(),
        source_state_root: ownerless_source_state_root_v3(&elements, &e),
        quote_atoms_per_whole_base: PRICE_SCALE,
        outstanding_base_atoms: elements.common.outstanding_usdd_atoms,
        redeemable_reserve_quote_atoms: 100_000_000,
        redemption_enabled: true,
    };
    OwnerlessConversionInputV3 {
        version: 3,
        frozen_configuration: c,
        public_values: public,
        ethereum_public_values: e,
        ethereum_proof_marker: vec![70; 32],
        elements_public_values: elements,
        elements_proof_marker: vec![71; 32],
        covenant_script_preimage: script,
    }
}

/// Test-only, exact-byte authorization. This deliberately does not claim to
/// perform cryptographic verification or provide a production implementation.
struct ExactFixtureVerifier {
    ethereum: Vec<u8>,
    elements: Vec<u8>,
    ethereum_program: Hash32,
    elements_program: Hash32,
}
impl ExactFixtureVerifier {
    fn new(i: &OwnerlessConversionInputV3) -> Self {
        Self {
            ethereum: i.ethereum_public_values.canonical_bytes(),
            elements: i.elements_public_values.canonical_bytes(),
            ethereum_program: i.frozen_configuration.ethereum_source_program_id,
            elements_program: i.frozen_configuration.elements_source_program_id,
        }
    }
}
impl OwnerlessSourceReceiptVerifierV3 for ExactFixtureVerifier {
    fn verify_ethereum(
        &self,
        p: Hash32,
        s: &[u8],
        m: &[u8],
    ) -> Result<(), OwnerlessConversionErrorV3> {
        if p == self.ethereum_program && s == self.ethereum && m == [70; 32] {
            Ok(())
        } else {
            Err(OwnerlessConversionErrorV3::EthereumProof)
        }
    }
    fn verify_elements_v2_redemption(
        &self,
        p: Hash32,
        s: &[u8],
        m: &[u8],
    ) -> Result<(), OwnerlessConversionErrorV3> {
        if p == self.elements_program && s == self.elements && m == [71; 32] {
            Ok(())
        } else {
            Err(OwnerlessConversionErrorV3::ElementsProof)
        }
    }
}
fn run(i: &OwnerlessConversionInputV3) -> Result<Vec<u8>, OwnerlessConversionErrorV3> {
    execute_ownerless_conversion_v3(i, &ExactFixtureVerifier::new(i))
}
fn refresh_public(i: &mut OwnerlessConversionInputV3) {
    i.public_values.source_state_root =
        ownerless_source_state_root_v3(&i.elements_public_values, &i.ethereum_public_values);
    i.public_values.outstanding_base_atoms = i.elements_public_values.common.outstanding_usdd_atoms;
    i.public_values.redeemable_reserve_quote_atoms =
        word_to_u128(i.ethereum_public_values.minted_redemption_backing).unwrap() * 100;
}

#[test]
fn exact_output_counts_only_mint_acknowledged_backing() {
    let i = fixture();
    let output = run(&i).unwrap();
    assert_eq!(output, i.public_values.canonical_bytes());
    assert_eq!(output.len(), 275);
    assert_eq!(i.ethereum_public_values.reserve, word(3_200_000));
    assert_eq!(i.public_values.redeemable_reserve_quote_atoms, 100_000_000);
}

#[test]
fn frozen_wire_sizes_and_input_roundtrip() {
    let i = fixture();
    assert_eq!(i.frozen_configuration.source.canonical_bytes().len(), 560);
    assert_eq!(i.ethereum_public_values.canonical_bytes().len(), 732);
    assert_eq!(i.elements_public_values.canonical_bytes().len(), 835);
    let bytes = i.canonical_bytes().unwrap();
    assert_eq!(
        OwnerlessConversionInputV3::decode_canonical(&bytes).unwrap(),
        i
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        OwnerlessConversionInputV3::decode_canonical(&trailing),
        Err(OwnerlessConversionErrorV3::Encoding)
    );
    assert!(OwnerlessConversionInputV3::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn old_roles_and_versions_are_rejected_not_relabelled() {
    let mut i = fixture();
    i.version = 2;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Envelope));
    let mut i = fixture();
    i.ethereum_public_values.version = 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::EthereumStatement));
    let mut i = fixture();
    i.elements_public_values.version = 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ElementsRole));
    let mut i = fixture();
    i.elements_public_values.role = [0; 32];
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ElementsRole));
    let i = fixture();
    let mut old_receipt_verifier = ExactFixtureVerifier::new(&i);
    old_receipt_verifier.elements = i.elements_public_values.common.canonical_bytes();
    assert_eq!(old_receipt_verifier.elements.len(), 738);
    assert_eq!(
        execute_ownerless_conversion_v3(&i, &old_receipt_verifier),
        Err(OwnerlessConversionErrorV3::ElementsProof)
    );
}

#[test]
fn both_byte_exact_proofs_are_required_before_accounting() {
    let i = fixture();
    let verifier = ExactFixtureVerifier::new(&i);
    let mut changed = i.clone();
    changed.ethereum_public_values.minted_redemption_backing = word(2_000_000);
    assert_eq!(
        execute_ownerless_conversion_v3(&changed, &verifier),
        Err(OwnerlessConversionErrorV3::EthereumProof)
    );
    let mut changed = i.clone();
    changed.elements_public_values.common.outstanding_usdd_atoms += 100;
    assert_eq!(
        execute_ownerless_conversion_v3(&changed, &verifier),
        Err(OwnerlessConversionErrorV3::ElementsProof)
    );
    let mut changed = i.clone();
    changed.ethereum_proof_marker[0] ^= 1;
    assert_eq!(
        run(&changed),
        Err(OwnerlessConversionErrorV3::EthereumProof)
    );
    let mut changed = i.clone();
    changed.elements_proof_marker[0] ^= 1;
    assert_eq!(
        run(&changed),
        Err(OwnerlessConversionErrorV3::ElementsProof)
    );
    let mut changed = i.clone();
    changed.frozen_configuration.ethereum_source_program_id[0] ^= 1;
    assert_eq!(
        execute_ownerless_conversion_v3(&changed, &verifier),
        Err(OwnerlessConversionErrorV3::EthereumProof)
    );
    let mut changed = i;
    changed.frozen_configuration.elements_source_program_id[0] ^= 1;
    assert_eq!(
        execute_ownerless_conversion_v3(&changed, &verifier),
        Err(OwnerlessConversionErrorV3::ElementsProof)
    );
}

#[test]
fn custody_script_and_strong_redemption_bindings_are_exact() {
    let mut i = fixture();
    i.elements_public_values.custody_id[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Binding));
    let mut i = fixture();
    i.elements_public_values.redemption_binding_commitment[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Binding));
    let mut i = fixture();
    i.covenant_script_preimage.push(0);
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Binding));
    let mut i = fixture();
    i.frozen_configuration
        .redemption
        .strong_redemption_program_id[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Binding));
    let mut i = fixture();
    i.ethereum_public_values.frozen_configuration_commitment[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Binding));
}

#[test]
fn authenticated_prior_and_current_checkpoints_must_match() {
    let mut i = fixture();
    i.ethereum_public_values.prior_light_client_digest[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Checkpoint));
    let mut i = fixture();
    i.ethereum_public_values.finalized_execution_state_root[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Checkpoint));
    let mut i = fixture();
    i.elements_public_values
        .common
        .elements_source_bootstrap_commitment[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Checkpoint));
    let mut i = fixture();
    i.elements_public_values.common.redemption_covenant_live = false;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Checkpoint));
}

#[test]
fn donations_do_not_increase_redeemable_backing() {
    let mut i = fixture();
    i.ethereum_public_values.reserve = word(100_000_000);
    i.ethereum_public_values.unallocated_surplus = word(98_300_000);
    refresh_public(&mut i);
    assert_eq!(i.public_values.redeemable_reserve_quote_atoms, 100_000_000);
    assert!(run(&i).is_ok());
    i.public_values.redeemable_reserve_quote_atoms = 100_000_000 * 100;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::PublicValues));
}

#[test]
fn pending_unresolved_and_bounty_liabilities_do_not_increase_backing() {
    let mut i = fixture();
    i.ethereum_public_values.pending_principal = word(2_000_000);
    i.ethereum_public_values.pending_bounty = word(1_000_000);
    i.ethereum_public_values.unresolved_committed = word(3_000_000);
    i.ethereum_public_values.committed_bounty = word(1_000_000);
    i.ethereum_public_values.committed_principal = word(4_000_000);
    i.ethereum_public_values.accounted_custody = word(8_000_000);
    i.ethereum_public_values.other_obligations = word(7_000_000);
    i.ethereum_public_values.reserve = word(9_500_000);
    refresh_public(&mut i);
    assert!(run(&i).is_ok());
    assert_eq!(i.public_values.redeemable_reserve_quote_atoms, 100_000_000);
    i.ethereum_public_values.minted_redemption_backing = word(8_000_000);
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Accounting));
}

#[test]
fn all_accounting_equations_are_checked_after_source_authentication() {
    for field in 0..6 {
        let mut i = fixture();
        match field {
            0 => i.ethereum_public_values.committed_principal = word(1_300_001),
            1 => i.ethereum_public_values.accounted_custody = word(1_700_001),
            2 => i.ethereum_public_values.other_obligations = word(700_001),
            3 => i.ethereum_public_values.unallocated_surplus = word(1_500_001),
            4 => i.ethereum_public_values.minted_redemption_backing = word(1_000_001),
            _ => i.ethereum_public_values.mint_acknowledged = word(1_000_001),
        }
        assert_eq!(
            run(&i),
            Err(OwnerlessConversionErrorV3::Accounting),
            "field {field}"
        );
    }
    let mut i = fixture();
    i.ethereum_public_values.reserve = word(1_699_999);
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ReserveShortfall));
}

#[test]
fn liability_scale_is_exact_including_smallest_redeemable_unit() {
    let mut i = fixture();
    i.elements_public_values.common.outstanding_usdd_atoms = 100;
    refresh_public(&mut i);
    assert!(run(&i).is_ok());
    for amount in [1, 99, 101, 99_999_999, u128::MAX] {
        i.elements_public_values.common.outstanding_usdd_atoms = amount;
        assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::InexactLiability));
    }
    i.elements_public_values.common.outstanding_usdd_atoms = 100_000_100;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ReserveShortfall));
    i.elements_public_values.common.outstanding_usdd_atoms = 0;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ZeroSupply));
}

fn set_backing_only(i: &mut OwnerlessConversionInputV3, backing: Hash32) {
    let e = &mut i.ethereum_public_values;
    e.reserve = backing;
    e.accounted_custody = backing;
    e.pending_principal = [0; 32];
    e.pending_bounty = [0; 32];
    e.committed_principal = backing;
    e.committed_bounty = [0; 32];
    e.unresolved_committed = [0; 32];
    e.mint_acknowledged = backing;
    e.other_obligations = [0; 32];
    e.minted_redemption_backing = backing;
    e.unallocated_surplus = [0; 32];
}

#[test]
fn one_to_one_backing_excludes_separately_funded_resolver_bounties() {
    // One whole USDD (8 decimals) requires one whole reserve token
    // (6 decimals). Bounties are additional obligations, never mint backing.
    for bounty in [0u128, 1, 1_000_000, 1_000_000_000_000_000] {
        let mut i = fixture();
        set_backing_only(&mut i, word(1_000_000));
        i.elements_public_values.common.outstanding_usdd_atoms = 100_000_000;
        let e = &mut i.ethereum_public_values;
        e.pending_bounty = word(bounty);
        e.committed_bounty = word(bounty);
        e.other_obligations = word(2 * bounty);
        e.reserve = word(1_000_000 + 2 * bounty);
        e.accounted_custody = e.reserve;
        refresh_public(&mut i);
        assert!(run(&i).is_ok(), "separately funded bounty {bounty}");
        assert_eq!(i.public_values.redeemable_reserve_quote_atoms, 100_000_000);

        // Even one reserve microtoken missing must reject: bounty escrow
        // cannot be borrowed to keep the advertised mint backing unchanged.
        let mut underfunded = i.clone();
        underfunded.ethereum_public_values.reserve = word(999_999 + 2 * bounty);
        assert_eq!(run(&underfunded), Err(OwnerlessConversionErrorV3::ReserveShortfall));

        // A larger escrow cannot justify minting even one extra redeemable unit.
        i.elements_public_values.common.outstanding_usdd_atoms += 100;
        assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::ReserveShortfall));
    }
}

#[test]
fn u256_and_u128_overflow_are_rejected_not_truncated() {
    let mut i = fixture();
    let mut over_u128 = [0; 32];
    over_u128[15] = 1;
    set_backing_only(&mut i, over_u128);
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Arithmetic));
    let mut i = fixture();
    set_backing_only(&mut i, word(u128::MAX / 100 + 1));
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Arithmetic));
    let mut i = fixture();
    i.ethereum_public_values.unresolved_committed = [255; 32];
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Arithmetic));
    assert_eq!(
        add256([255; 32], word(1)),
        Err(OwnerlessConversionErrorV3::Arithmetic)
    );
    assert_eq!(
        sub256(word(0), word(1)),
        Err(OwnerlessConversionErrorV3::ReserveShortfall)
    );
    assert_eq!(sub256(over_u128, word(1)).unwrap(), word(u128::MAX));
}

#[test]
fn no_market_quote_or_decimal_substitution() {
    let mut i = fixture();
    i.ethereum_public_values.quote_atoms_per_whole_reserve_token = 30 * PRICE_SCALE;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::EthereumStatement));
    let mut i = fixture();
    i.ethereum_public_values.token_decimals = 18;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::EthereumStatement));
    let mut i = fixture();
    i.frozen_configuration.source.usdd_decimals = 6;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Configuration));
    let mut i = fixture();
    i.frozen_configuration.source.ethereum_chain_id = 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Configuration));
}

#[test]
fn no_missing_or_aliased_contract_roles_or_overlong_age() {
    let mut i = fixture();
    i.frozen_configuration.source.vault.address = [0; 20];
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Configuration));
    let mut i = fixture();
    i.frozen_configuration.source.price.address = i.frozen_configuration.source.vault.address;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Configuration));
    let mut i = fixture();
    i.frozen_configuration.maximum_age_seconds += 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::Configuration));
}

#[test]
fn final_bytes_must_bind_all_authenticated_totals_and_context() {
    let mut i = fixture();
    i.public_values.source_state_root[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::PublicValues));
    let mut i = fixture();
    i.public_values.source_checkpoint_commitment[0] ^= 1;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::PublicValues));
    let mut i = fixture();
    i.public_values.redemption_enabled = false;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::PublicValues));
    let mut i = fixture();
    i.elements_public_values.common.observed_parent_mtp +=
        i.frozen_configuration.maximum_age_seconds;
    assert_eq!(run(&i), Err(OwnerlessConversionErrorV3::StaleCheckpoint));
}

#[test]
fn ownerless_wire_fixture() {
    let mut i = fixture();
    // Same independent fixture as foundation::usdd_ownerless_v3::tests.
    i.frozen_configuration.source.reserve_balance_mapping_slot = word(9);
    i.frozen_configuration.source.price_storage_key = word(7);
    let e = &mut i.ethereum_public_values;
    e.frozen_configuration_commitment = i.frozen_configuration.source.commitment();
    e.protocol_manifest_commitment = [40; 32];
    e.update_proof_commitment = [41; 32];
    e.prior_light_client_digest = [42; 32];
    e.prior_finalized_beacon_slot = 43;
    e.prior_finalized_beacon_root = [44; 32];
    e.prior_finalized_execution_state_root = [45; 32];
    e.finalized_beacon_slot = 46;
    e.finalized_beacon_root = [47; 32];
    e.finalized_execution_block_hash = [48; 32];
    e.finalized_execution_state_root = [49; 32];
    e.execution_block_number = 50;
    e.execution_block_timestamp = 51;
    e.light_client_digest = [52; 32];
    e.next_intent_nonce = 20;
    e.next_committed_deposit_nonce = 10;
    e.reserve = word(200);
    e.accounted_custody = word(155);
    e.pending_principal = word(20);
    e.pending_bounty = word(2);
    e.committed_principal = word(130);
    e.committed_bounty = word(3);
    e.unresolved_committed = word(30);
    e.mint_acknowledged = word(100);
    e.other_obligations = word(55);
    e.minted_redemption_backing = word(100);
    e.unallocated_surplus = word(45);
    i.frozen_configuration.source.validate().unwrap();
    e.validate_shape().unwrap();
    e.validate_accounting().unwrap();
    // Reproducible synthetic cross-crate wire vector, never chain evidence.
    println!(
        "OWNERLESS_CONFIG_HEX={}",
        hex::encode(i.frozen_configuration.source.canonical_bytes())
    );
    println!(
        "OWNERLESS_PV_HEX={}",
        hex::encode(i.ethereum_public_values.canonical_bytes())
    );
}
