//! Synthetic policy-boundary tests, not authenticated live-chain replay.
//! Blocks here deliberately omit full PoW/script validation; the enclosing
//! relation must establish it before invoking the BIP300-only transition.

use super::*;
use crate::bip300_v2::{
    generic_m6id, Bip300ActiveSlotV2, Bip300CtipV2, Bip300PendingM6idV2, Bip300ProposalV2,
    BIP300_MAX_PENDING_M6IDS_V2, BIP300_MAX_PENDING_PROPOSALS_V2,
    BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2, M1_TAG, M2_TAG, M4_TAG, M7_TAG, M8_TAG,
    OP_DRIVECHAIN,
};
use bitcoin::absolute;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::hashes::sha256d;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};

const SLOT: u8 = 24;
const PROPOSAL: [u8; 32] = [42; 32];

fn op_return(payload: &[u8]) -> ScriptBuf {
    assert!(payload.len() <= 75);
    let mut bytes = vec![0x6a, payload.len() as u8];
    bytes.extend_from_slice(payload);
    ScriptBuf::from_bytes(bytes)
}

fn m1(slot: u8, description: &[u8]) -> ScriptBuf {
    let mut payload = M1_TAG.to_vec();
    payload.push(slot);
    payload.extend_from_slice(description);
    op_return(&payload)
}

fn m2(slot: u8, hash: [u8; 32]) -> ScriptBuf {
    let mut payload = M2_TAG.to_vec();
    payload.push(slot);
    payload.extend_from_slice(&hash);
    op_return(&payload)
}

fn transaction(previous_output: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn block(state: &AlphaBip300AllSlotStateV3, scripts: &[ScriptBuf], txs: &[Transaction]) -> Block {
    let coinbase = transaction(
        OutPoint::null(),
        scripts
            .iter()
            .map(|script| TxOut {
                value: Amount::ZERO,
                script_pubkey: script.clone(),
            })
            .collect(),
    );
    let mut txdata = vec![coinbase];
    txdata.extend_from_slice(txs);
    Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: state.state.tip_hash.unwrap_or(BlockHash::all_zeros()),
            merkle_root: TxMerkleNode::all_zeros(),
            time: state.state.next_height,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata,
    }
}

fn apply(
    state: &AlphaBip300AllSlotStateV3,
    scripts: &[ScriptBuf],
) -> (AlphaBip300AllSlotStateV3, Bip300BlockEffectsV2) {
    apply_alpha_bip300_block_v3(state, &block(state, scripts, &[])).unwrap()
}

fn initialized(next_height: u32) -> AlphaBip300AllSlotStateV3 {
    let mut inner = AlphaBip300AllSlotStateV3::before_genesis().state;
    inner.next_height = next_height;
    inner.tip_hash = Some(BlockHash::from_byte_array([1; 32]));
    AlphaBip300AllSlotStateV3::from_authenticated_state(inner).unwrap()
}

fn active() -> Bip300ActiveSlotV2 {
    Bip300ActiveSlotV2 {
        proposal_hash: [7; 32],
        activation_height: ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
        ctip: None,
        next_treasury_sequence: 0,
        pending_m6ids: Vec::new(),
    }
}

fn m7(slot: u8, child: BlockHash) -> ScriptBuf {
    let mut payload = M7_TAG.to_vec();
    payload.push(slot);
    payload.extend_from_slice(child.as_byte_array());
    op_return(&payload)
}

fn m8(slot: u8, child: BlockHash, previous: BlockHash, input_tag: u8) -> Transaction {
    let mut payload = M8_TAG.to_vec();
    payload.push(slot);
    payload.extend_from_slice(child.as_byte_array());
    payload.extend_from_slice(previous.as_byte_array());
    transaction(
        OutPoint {
            txid: Txid::from_byte_array([input_tag; 32]),
            vout: 0,
        },
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return(&payload),
        }],
    )
}

#[test]
fn alpha_m8_same_slot_duplicate_is_rejected_atomically() {
    let mut state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    let child = BlockHash::from_byte_array([2; 32]);
    let previous = state.state.tip_hash.unwrap();
    let first = m8(SLOT, child, previous, 3);
    let second = m8(SLOT, child, previous, 4);
    assert_ne!(first.compute_txid(), second.compute_txid());
    // Both requests independently satisfy M7 and parent matching. Distinct
    // txids ensure this is not a duplicate-transaction/block-foundation test.
    for tx in [&first, &second] {
        let (_, effects) = apply_alpha_bip300_block_v3(
            &state,
            &block(&state, &[m7(SLOT, child)], std::slice::from_ref(tx)),
        )
        .unwrap();
        assert_eq!(effects.matching_m8_requests, 1);
    }
    for height in [
        ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
        ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 1,
    ] {
        state.state.next_height = height;
        let before = state.clone();
        let commitment = state.commitment().unwrap();
        for txs in [
            vec![first.clone(), second.clone()],
            vec![second.clone(), first.clone()],
        ] {
            let result =
                apply_alpha_bip300_block_v3(&state, &block(&state, &[m7(SLOT, child)], &txs));
            assert_eq!(result, Err(Bip300ReplayErrorV2::DuplicateM8Slot));
            assert_eq!(state, before);
            assert_eq!(state.commitment().unwrap(), commitment);
        }
    }
}

#[test]
fn alpha_m8_one_per_distinct_slot_is_accepted() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    let previous = state.state.tip_hash.unwrap();
    let slots = [0, SLOT, 255];
    let children = slots.map(|slot| BlockHash::from_byte_array([slot.wrapping_add(1); 32]));
    let messages: Vec<_> = slots
        .iter()
        .zip(children)
        .map(|(&slot, child)| m7(slot, child))
        .collect();
    let txs: Vec<_> = slots
        .iter()
        .zip(children)
        .map(|(&slot, child)| m8(slot, child, previous, slot))
        .collect();
    let (_, effects) =
        apply_alpha_bip300_block_v3(&state, &block(&state, &messages, &txs)).unwrap();
    assert_eq!(effects.matching_m8_requests, 3);
    assert_eq!(effects.bmm_commitments.len(), 3);
}

#[test]
fn alpha_m8_duplicate_check_does_not_replace_binding_validation() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    let child = BlockHash::from_byte_array([2; 32]);
    let previous = state.state.tip_hash.unwrap();
    let first = m8(SLOT, child, previous, 3);
    for (second, expected) in [
        (
            m8(SLOT, BlockHash::from_byte_array([5; 32]), previous, 4),
            Bip300ReplayErrorV2::M8WrongChildHash,
        ),
        (
            m8(SLOT, child, BlockHash::from_byte_array([5; 32]), 4),
            Bip300ReplayErrorV2::M8Expired,
        ),
        (
            m8(SLOT + 1, child, previous, 4),
            Bip300ReplayErrorV2::M8WithoutMatchingM7,
        ),
    ] {
        assert_eq!(
            apply_alpha_bip300_block_v3(
                &state,
                &block(&state, &[m7(SLOT, child)], &[first.clone(), second])
            ),
            Err(expected)
        );
    }
}

#[test]
fn alpha_m8_noncanonical_or_nonzero_output_is_not_a_second_request() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    let child = BlockHash::from_byte_array([2; 32]);
    let previous = state.state.tip_hash.unwrap();
    let first = m8(SLOT, child, previous, 3);
    let canonical = m8(SLOT, child, previous, 4);
    let mut trailing = canonical.clone();
    let mut bytes = trailing.output[0].script_pubkey.to_bytes();
    bytes.push(0);
    trailing.output[0].script_pubkey = ScriptBuf::from_bytes(bytes);
    let mut nonzero = canonical.clone();
    nonzero.output.insert(
        0,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        },
    );
    let mut nonminimal = canonical;
    let original = nonminimal.output[0].script_pubkey.to_bytes();
    let mut bytes = vec![0x6a, 0x4c, 68];
    bytes.extend_from_slice(&original[2..]);
    nonminimal.output[0].script_pubkey = ScriptBuf::from_bytes(bytes);
    for non_request in [trailing, nonzero, nonminimal] {
        for txs in [
            vec![first.clone(), non_request.clone()],
            vec![non_request, first.clone()],
        ] {
            let (_, effects) =
                apply_alpha_bip300_block_v3(&state, &block(&state, &[m7(SLOT, child)], &txs))
                    .unwrap();
            assert_eq!(effects.matching_m8_requests, 1);
        }
    }
}

#[test]
fn alpha_m8_duplicate_limit_resets_for_each_block() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    let child = BlockHash::from_byte_array([2; 32]);
    let first = m8(SLOT, child, state.state.tip_hash.unwrap(), 3);
    let (next, effects) =
        apply_alpha_bip300_block_v3(&state, &block(&state, &[m7(SLOT, child)], &[first])).unwrap();
    assert_eq!(effects.matching_m8_requests, 1);
    let second = m8(SLOT, child, next.state.tip_hash.unwrap(), 4);
    let (_, effects) =
        apply_alpha_bip300_block_v3(&next, &block(&next, &[m7(SLOT, child)], &[second])).unwrap();
    assert_eq!(effects.matching_m8_requests, 1);
}

#[test]
fn alpha_m8_duplicates_are_ignored_before_activation_and_v2_is_unchanged() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3 - 1);
    let child = BlockHash::from_byte_array([2; 32]);
    let previous = state.state.tip_hash.unwrap();
    let candidate = block(
        &state,
        &[m7(SLOT, child)],
        &[m8(SLOT, child, previous, 3), m8(SLOT, child, previous, 4)],
    );
    let (_, alpha_effects) = apply_alpha_bip300_block_v3(&state, &candidate).unwrap();
    assert_eq!(alpha_effects.matching_m8_requests, 0);
    assert!(alpha_effects.bmm_commitments.is_empty());
    // This separate legacy relation intentionally is not represented as the
    // corrected Alpha relation. Its previous acceptance behavior stays fixed.
    let (_, legacy_effects) =
        crate::bip300_v2::apply_bip300_block_v2(&state.state, &candidate).unwrap();
    assert_eq!(legacy_effects.matching_m8_requests, 2);
}

fn proposal_state(used: bool, age: u32, votes: u16) -> AlphaBip300AllSlotStateV3 {
    let height = ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 200;
    let mut state = initialized(height);
    if used {
        state.state.active_slots.insert(SLOT, active());
    }
    state.state.proposals.insert(
        (SLOT, PROPOSAL),
        Bip300ProposalV2 {
            slot: SLOT,
            proposal_hash: PROPOSAL,
            proposal_height: height - age,
            votes,
        },
    );
    state.validate().unwrap();
    state
}

#[test]
fn legacy_uniform_commitment_bytes_remain_unchanged() {
    // Independent Node.js SHA-256 calculation of the pre-existing 58-byte v2
    // encoding, using a synthetic nonzero genesis and the unchanged SHORT
    // policy. This checks format preservation, not a real network identity.
    let state = Bip300AllSlotStateV2::before_genesis(
        BlockHash::from_byte_array([1; 32]),
        BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
    )
    .unwrap();
    assert_eq!(
        hex::encode(state.commitment().unwrap()),
        "dd53e83b20869e955a7594e236d08106dec55a9a5ec0d674c7d5142de01fac40"
    );
}

#[test]
fn fixed_policy_rejects_short_network_and_witness_selected_overrides() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 1);
    let original = state.commitment().unwrap();
    assert_ne!(original, state.state.commitment().unwrap());
    for field in 0..4 {
        let mut changed = state.state.clone();
        match field {
            0 => changed.consensus_parameters.proposal_max_age -= 1,
            1 => changed.consensus_parameters.proposal_activation_threshold -= 1,
            2 => changed.consensus_parameters.withdrawal_max_age -= 1,
            _ => changed.consensus_parameters.withdrawal_inclusion_threshold -= 1,
        }
        assert_eq!(
            AlphaBip300AllSlotStateV3::from_authenticated_state(changed),
            Err(Bip300ReplayErrorV2::InvalidConsensusParameters),
        );
    }
    let mut wrong_network = state.state.clone();
    wrong_network.network_genesis =
        bitcoin::blockdata::constants::genesis_block(Network::Signet).block_hash();
    assert!(AlphaBip300AllSlotStateV3::from_authenticated_state(wrong_network).is_err());
    let mut short = state.state.clone();
    short.consensus_parameters = BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2;
    assert_eq!(
        AlphaBip300AllSlotStateV3::from_authenticated_state(short.clone()),
        Err(Bip300ReplayErrorV2::InvalidConsensusParameters),
    );
    // Legacy uniform v2 remains usable only through its separate API/domain.
    short.validate().unwrap();
    assert_ne!(short.commitment().unwrap(), original);
    for name in [
        "policy",
        "activation_height",
        "unused_slot_threshold",
        "network",
    ] {
        let mut encoded = serde_json::to_value(&state).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert(name.into(), serde_json::json!(5));
        assert!(serde_json::from_value::<AlphaBip300AllSlotStateV3>(encoded).is_err());
    }
    // Even a deserializable mutation of the legacy storage is rejected by
    // transition/commitment validation; deserialization is not authentication.
    let mut encoded = serde_json::to_value(&state).unwrap();
    encoded["state"]["consensus_parameters"]["withdrawal_inclusion_threshold"] =
        serde_json::json!(5);
    let malicious: AlphaBip300AllSlotStateV3 = serde_json::from_value(encoded).unwrap();
    assert!(malicious.commitment().is_err());
    assert!(apply_alpha_bip300_block_v3(&malicious, &block(&malicious, &[], &[])).is_err());
}

#[test]
fn alpha_profile_is_frozen_and_pending_bounds_cover_long_windows() {
    assert_eq!(
        hex::encode(alpha_bip300_policy_commitment_v3()),
        // Independent Node.js SHA-256 vector over the documented fixed policy
        // serialization; not computed with the production helper in this test.
        "5396683035fcdfa1f31cdd656081d9e4d08d5d33d2181edfd44c3f91a5047f72",
    );
    assert_eq!(ALPHA_BIP300_POLICY_VERSION_V3, 2);
    assert_ne!(
        hex::encode(alpha_bip300_policy_commitment_v3()),
        "fa43a107ed0cc73921529aed6ee4ad3aa0b70aea202dee561ff0608dbf49e3df",
        "the previous incomplete Alpha policy must not retain its identity",
    );
    assert_eq!(ALPHA_MAX_PENDING_PROPOSALS_V3, 111_111 * 146);
    assert_eq!(ALPHA_MAX_PENDING_M6IDS_V3, 111_111 * 146);
    assert!(ALPHA_MAX_PENDING_PROPOSALS_V3 > BIP300_MAX_PENDING_PROPOSALS_V2);
    assert!(ALPHA_MAX_PENDING_M6IDS_V3 > BIP300_MAX_PENDING_M6IDS_V2);
    let state = proposal_state(false, 30, 29);
    let mut changed = state.clone();
    changed
        .state
        .proposals
        .get_mut(&(SLOT, PROPOSAL))
        .unwrap()
        .votes -= 1;
    assert_ne!(changed.commitment().unwrap(), state.commitment().unwrap());
}

#[test]
fn preactivation_ignores_messages_and_treasury_then_exact_height_enables_m1() {
    let state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3 - 1);
    let description = b"alpha-slot";
    let hash = sha256d::Hash::hash(description).to_byte_array();
    let messages = [m1(SLOT, description), m2(SLOT, hash), m2(SLOT, hash)];
    // A bogus unmatched M8 and treasury output would be rejected/processed
    // after activation but must be ignored in plain Bitcoin prehistory.
    let mut payload = M8_TAG.to_vec();
    payload.push(SLOT);
    payload.extend_from_slice(&[2; 32]);
    payload.extend_from_slice(&[3; 32]);
    let bogus_m8 = transaction(
        OutPoint::null(),
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return(&payload),
        }],
    );
    let treasury = transaction(
        OutPoint::null(),
        vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: ScriptBuf::from_bytes(vec![OP_DRIVECHAIN, 1, SLOT, 0x51]),
        }],
    );
    let (next, effects) =
        apply_alpha_bip300_block_v3(&state, &block(&state, &messages, &[bogus_m8, treasury]))
            .unwrap();
    assert_eq!(next.state.next_height, ALPHA_BIP300_ACTIVATION_HEIGHT_V3);
    assert_eq!(effects, Bip300BlockEffectsV2::default());
    assert!(next.state.proposals.is_empty());
    assert!(next.state.active_slots.is_empty());
    let (enabled, effects) = apply(&next, &[m1(SLOT, description), m2(SLOT, hash)]);
    assert_eq!(enabled.state.proposals[&(SLOT, hash)].votes, 0);
    assert!(effects.activations.is_empty());
    let before = next.clone();
    assert_eq!(
        apply_alpha_bip300_block_v3(&next, &block(&next, &messages, &[])),
        Err(Bip300ReplayErrorV2::DuplicateM2),
    );
    assert_eq!(next, before);
    let mut illegal = next.state;
    illegal.active_slots.insert(SLOT, active());
    assert!(AlphaBip300AllSlotStateV3::from_authenticated_state(illegal).is_err());
}

#[test]
fn proposal_thresholds_are_strict_for_unused_and_used_slots() {
    for (used, threshold) in [(false, 30u16), (true, 72u16)] {
        let initial_height = ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 1;
        let mut state = initialized(initial_height);
        if used {
            state.state.active_slots.insert(SLOT, active());
        }
        let description = b"boundary-proposal";
        let hash = sha256d::Hash::hash(description).to_byte_array();
        (state, _) = apply(&state, &[m1(SLOT, description), m2(SLOT, hash)]);
        assert_eq!(state.state.proposals[&(SLOT, hash)].votes, 0);
        for vote in 1..=threshold + 1 {
            let (next, effects) = apply(&state, &[m2(SLOT, hash)]);
            if vote <= threshold {
                assert!(effects.activations.is_empty());
                assert_eq!(next.state.proposals[&(SLOT, hash)].votes, vote);
            } else {
                assert_eq!(effects.activations.len(), 1);
                assert_eq!(effects.activations[0].replaced_existing, used);
                assert_eq!(
                    effects.activations[0].block_height,
                    initial_height + u32::from(vote)
                );
            }
            state = next;
        }
    }
}

#[test]
fn proposal_age_is_inclusive_and_expiry_uses_exact_unreachable_vote_boundary() {
    for (used, max_age, threshold) in [(false, 36, 30u16), (true, 144, 72u16)] {
        let state = proposal_state(used, max_age, threshold);
        let (accepted, effects) = apply(&state, &[m2(SLOT, PROPOSAL)]);
        assert_eq!(effects.activations.len(), 1);
        assert_eq!(accepted.state.active_slots[&SLOT].proposal_hash, PROPOSAL);
        let (_, effects) = apply(
            &proposal_state(used, max_age + 1, threshold),
            &[m2(SLOT, PROPOSAL)],
        );
        assert!(effects.activations.is_empty());

        let (last_live, _) = apply(&proposal_state(used, max_age - 1, threshold), &[]);
        assert!(last_live.state.proposals.contains_key(&(SLOT, PROPOSAL)));
        let (expired, _) = apply(&state, &[]);
        assert!(!expired.state.proposals.contains_key(&(SLOT, PROPOSAL)));

        let max_fails = max_age - u32::from(threshold);
        let (still_live, _) = apply(&proposal_state(used, max_fails, 0), &[]);
        assert!(still_live.state.proposals.contains_key(&(SLOT, PROPOSAL)));
        let (just_failed, _) = apply(&proposal_state(used, max_fails + 1, 1), &[]);
        assert!(!just_failed.state.proposals.contains_key(&(SLOT, PROPOSAL)));
        let (still_possible, _) = apply(&proposal_state(used, max_fails + 1, 2), &[]);
        assert!(still_possible
            .state
            .proposals
            .contains_key(&(SLOT, PROPOSAL)));
    }
}

#[test]
fn occupancy_is_current_state_not_a_witness_flag_or_proposal_time_snapshot() {
    let unused = proposal_state(false, 31, 30);
    assert_eq!(apply(&unused, &[m2(SLOT, PROPOSAL)]).1.activations.len(), 1);
    let mut now_used = unused.clone();
    now_used.state.active_slots.insert(SLOT, active());
    let (not_activated, effects) = apply(&now_used, &[m2(SLOT, PROPOSAL)]);
    assert!(effects.activations.is_empty());
    assert_eq!(not_activated.state.proposals[&(SLOT, PROPOSAL)].votes, 31);

    // Activation earlier in this same coinbase changes the failure policy for
    // the other proposal for that slot to the used-slot policy.
    let mut competing = unused;
    let other_hash = [43; 32];
    competing.state.proposals.insert(
        (SLOT, other_hash),
        Bip300ProposalV2 {
            slot: SLOT,
            proposal_hash: other_hash,
            proposal_height: competing.state.next_height - 7,
            votes: 1,
        },
    );
    let (without_activation, _) = apply(&competing, &[]);
    assert!(!without_activation
        .state
        .proposals
        .contains_key(&(SLOT, other_hash)));
    let (with_activation, _) = apply(&competing, &[m2(SLOT, PROPOSAL)]);
    assert!(with_activation
        .state
        .proposals
        .contains_key(&(SLOT, other_hash)));
}

fn withdrawal_state(age: u32, score: u16) -> (AlphaBip300AllSlotStateV3, Transaction) {
    let mut state = initialized(ALPHA_BIP300_ACTIVATION_HEIGHT_V3 + 200);
    let old = Bip300CtipV2 {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([8; 32]),
            vout: 0,
        },
        value_sat: 1_000,
        sequence: 0,
    };
    let withdrawal = transaction(
        old.outpoint,
        vec![
            TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::from_bytes(vec![OP_DRIVECHAIN, 1, SLOT, 0x51]),
            },
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    );
    let mut active = active();
    active.ctip = Some(old);
    active.next_treasury_sequence = 1;
    active.pending_m6ids.push(Bip300PendingM6idV2 {
        m6id: generic_m6id(&withdrawal, 1_000, 900).unwrap(),
        proposal_height: state.state.next_height - age,
        score,
    });
    state.state.active_slots.insert(SLOT, active);
    state.validate().unwrap();
    (state, withdrawal)
}

#[test]
fn withdrawal_144_is_live_145_expires_and_score_must_exceed_72() {
    let (state, withdrawal) = withdrawal_state(144, 72);
    let original = state.clone();
    assert_eq!(
        apply_alpha_bip300_block_v3(&state, &block(&state, &[], &[withdrawal.clone()])),
        Err(Bip300ReplayErrorV2::M6InsufficientScore),
    );
    assert_eq!(state, original);
    let (state, withdrawal) = withdrawal_state(144, 73);
    let (accepted, effects) =
        apply_alpha_bip300_block_v3(&state, &block(&state, &[], &[withdrawal])).unwrap();
    assert_eq!(effects.successful_m6s.len(), 1);
    assert_eq!(
        accepted.state.active_slots[&SLOT].ctip.unwrap().value_sat,
        900
    );
    assert!(accepted.state.active_slots[&SLOT].pending_m6ids.is_empty());

    let (state, _) = withdrawal_state(144, 73);
    let (last_live, effects) = apply(&state, &[]);
    assert!(effects.expired_m6ids.is_empty());
    assert_eq!(last_live.state.active_slots[&SLOT].pending_m6ids.len(), 1);
    let (expired, effects) = apply(&last_live, &[]);
    assert_eq!(effects.expired_m6ids.len(), 1);
    assert!(expired.state.active_slots[&SLOT].pending_m6ids.is_empty());

    let (expired_state, withdrawal) = withdrawal_state(145, 73);
    assert_eq!(
        apply_alpha_bip300_block_v3(&expired_state, &block(&expired_state, &[], &[withdrawal])),
        Err(Bip300ReplayErrorV2::M6MissingPendingBundle),
    );
}

#[test]
fn same_block_m4_can_cross_threshold_but_cannot_resurrect_an_expired_bundle() {
    let mut payload = M4_TAG.to_vec();
    payload.extend_from_slice(&[1, 0]); // OneByte upvote at index zero.
    let vote = op_return(&payload);
    let (state, withdrawal) = withdrawal_state(144, 72);
    let (_, effects) =
        apply_alpha_bip300_block_v3(&state, &block(&state, &[vote.clone()], &[withdrawal]))
            .unwrap();
    assert_eq!(effects.successful_m6s.len(), 1);
    let (state, withdrawal) = withdrawal_state(145, 72);
    assert_eq!(
        apply_alpha_bip300_block_v3(&state, &block(&state, &[vote], &[withdrawal])),
        Err(Bip300ReplayErrorV2::M6MissingPendingBundle),
    );
}

#[test]
fn used_slot_replacement_preserves_ctip_sequence_and_pending_withdrawals() {
    let (mut state, _) = withdrawal_state(20, 15);
    let previous = state.state.active_slots[&SLOT].clone();
    state.state.proposals.insert(
        (SLOT, PROPOSAL),
        Bip300ProposalV2 {
            slot: SLOT,
            proposal_hash: PROPOSAL,
            proposal_height: state.state.next_height - 73,
            votes: 72,
        },
    );
    let (next, effects) = apply(&state, &[m2(SLOT, PROPOSAL)]);
    assert!(effects.activations[0].replaced_existing);
    let replaced = &next.state.active_slots[&SLOT];
    assert_eq!(replaced.proposal_hash, PROPOSAL);
    assert_eq!(replaced.ctip, previous.ctip);
    assert_eq!(
        replaced.next_treasury_sequence,
        previous.next_treasury_sequence
    );
    assert_eq!(replaced.pending_m6ids, previous.pending_m6ids);
}
