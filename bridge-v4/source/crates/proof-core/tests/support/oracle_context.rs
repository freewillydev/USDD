//! Synthetic oracle transcripts for composition tests only.
//! Rebuilds context-bound fixture bytes; never use as authenticated live evidence.
use ecx_protocol_core::{FrozenConfigurationV2, Hash32, Price, OracleMode, derive_hybrid_quote, hash::tagged_hash};
use ecx_proof_core::{ConversionLegConsensusProofV2, verify_authenticated_conversion_legs_v2, derive_authenticated_price_range_v2};
use ecx_truthcoin_proof::{TruthcoinConsensusProofV1, ConsensusProofVerifier,
    ConsensusProofVerificationError};
use sha2::{Digest, Sha256};
use ecx_protocol_core::codec::CanonicalEncode;
use bincode::Options;

/// Reproduced from whole_system_e2e's first oracle lifecycle with
/// ECX_EXPORT_ORACLE_TEST_SEED=1 and the exact happy-path test filter.
/// Fixed seed for synthetic composition tests, never a production checkpoint.
pub fn seed() -> (FrozenConfigurationV2, TruthcoinConsensusProofV1,
    ConversionLegConsensusProofV2, ConversionLegConsensusProofV2) {
    let bytes = hex::decode(include_str!("oracle-test-seed.hex").trim()).unwrap();
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .deserialize(&bytes).unwrap()
}

#[test]
fn seed_reproduces_its_oracle_context() {
    let (configuration, truthcoin, ecx_btc, usdd_usd) = seed();
    let parent = &truthcoin.public_values;
    let refreshed = context_with_anchor(&configuration, &truthcoin, &ecx_btc, &usdd_usd,
        parent.observed_parent_block_hash, parent.observed_parent_height,
        parent.observed_parent_mtp, None);
    assert_eq!(refreshed.truthcoin.public_values.observed_parent_block_hash,
        parent.observed_parent_block_hash);
}

pub struct TestDigestVerifier;
impl ConsensusProofVerifier for TestDigestVerifier {
    fn verify(&self, program_id: Hash32, public_values: &[u8], proof: &[u8])
        -> Result<(), ConsensusProofVerificationError> {
        if proof == test_truthcoin_proof(program_id, public_values) { Ok(()) }
        else { Err(ConsensusProofVerificationError) }
    }
}
fn test_truthcoin_proof(program_id: Hash32, public_values: &[u8]) -> Vec<u8> {
    let mut bytes = program_id.to_vec();
    bytes.extend_from_slice(public_values);
    Sha256::digest(bytes).to_vec()
}

pub struct V2TestAuthenticatedContext {
    pub truthcoin: TruthcoinConsensusProofV1,
    pub ecx_btc: ConversionLegConsensusProofV2,
    pub usdd_usd: ConversionLegConsensusProofV2,
    pub oracle_certificate_hash: Hash32,
    pub mark: Price,
    pub liquidation_low: Price,
    pub liquidation_high: Price,
    pub oracle_valid_through_mtp: u64,
    pub authenticated_min_price: Price,
    pub authenticated_max_price: Price,
    pub authenticated_price_range_commitment: Hash32,
}

pub fn context_with_anchor(
    configuration: &FrozenConfigurationV2,
    previous_truthcoin: &TruthcoinConsensusProofV1,
    previous_ecx_btc: &ConversionLegConsensusProofV2,
    previous_usdd_usd: &ConversionLegConsensusProofV2,
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
    anchor_btc_usd_price: Option<Price>,
) -> V2TestAuthenticatedContext {
    let oracle = &configuration.base.oracle;
    let mut truthcoin = previous_truthcoin.clone();
    let public = &mut truthcoin.public_values;
    let snapshot_epoch =
        parent_mtp.checked_sub(oracle.schedule_origin_mtp).unwrap() / oracle.epoch_length_seconds;
    assert!(snapshot_epoch > 0);
    let anchor_epoch = snapshot_epoch - 1;
    let snapshot_start = oracle.epoch_start(snapshot_epoch).unwrap();
    public.observed_parent_block_hash = parent_hash;
    public.observed_parent_height = parent_height;
    public.observed_parent_mtp = parent_mtp;
    public.bitcoin_tip_hash = parent_hash;
    public.bitcoin_tip_height = parent_height;
    public.sidechain_tip_mtp = parent_mtp;
    public.sidechain_tip_hash = tagged_hash(
        "ECX/test-v18-truthcoin-tip/v2",
        &[parent_hash.as_slice(), &parent_mtp.to_be_bytes()].concat(),
    );
    public.canonical_chain_root = tagged_hash(
        "ECX/test-v18-truthcoin-chain/v2",
        &[parent_hash.as_slice(), &parent_height.to_be_bytes()].concat(),
    );
    public.replay_transcript_root = tagged_hash(
        "ECX/test-v18-truthcoin-replay/v2",
        &[parent_hash.as_slice(), &parent_mtp.to_be_bytes()].concat(),
    );
    public.replayed_state_root = tagged_hash(
        "ECX/test-v18-truthcoin-state/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    public.anchor.epoch = anchor_epoch;
    public.anchor.slot_id = oracle.canonical_slot_id(anchor_epoch).unwrap();
    public.anchor.source_mtp = parent_mtp;
    public.anchor.observation_end_mtp = snapshot_start;
    public.anchor.finalized_at_mtp = parent_mtp;
    public.anchor.source_block_hash = tagged_hash(
        "ECX/test-v18-anchor-block/v2",
        &[parent_hash.as_slice(), &anchor_epoch.to_be_bytes()].concat(),
    );
    public.anchor.source_state_root = tagged_hash(
        "ECX/test-v18-anchor-state/v2",
        &[parent_hash.as_slice(), &anchor_epoch.to_be_bytes()].concat(),
    );
    if let Some(price) = anchor_btc_usd_price {
        public.anchor.btc_usd_price = price;
    }
    public.lmsr_snapshot.epoch = snapshot_epoch;
    public.lmsr_snapshot.slot_id = oracle.canonical_slot_id(snapshot_epoch).unwrap();
    public.lmsr_snapshot.source_mtp = parent_mtp;
    public.lmsr_snapshot.epoch_start_mtp = snapshot_start;
    public.lmsr_snapshot.resolves_at_mtp = oracle.epoch_end(snapshot_epoch).unwrap();
    public.lmsr_snapshot.source_block_hash = tagged_hash(
        "ECX/test-v18-snapshot-block/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    public.lmsr_snapshot.source_state_root = tagged_hash(
        "ECX/test-v18-snapshot-state/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    public.lmsr_snapshot.registry_root = tagged_hash(
        "ECX/test-v18-snapshot-registry/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    public.lmsr_snapshot.selection_proof_root = tagged_hash(
        "ECX/test-v18-snapshot-selection/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    public.lmsr_snapshot.sample_window_root = tagged_hash(
        "ECX/test-v18-snapshot-window/v2",
        &[parent_hash.as_slice(), &snapshot_epoch.to_be_bytes()].concat(),
    );
    truthcoin.proof = test_truthcoin_proof(
        configuration
            .base
            .truthcoin_authentication
            .source_proof_program_id,
        &truthcoin.public_values.canonical_bytes(),
    );

    let refresh_conversion = |mut proof: ConversionLegConsensusProofV2, program_id| {
        proof.public_values.observed_parent_block_hash = parent_hash;
        proof.public_values.observed_parent_height = parent_height;
        proof.public_values.observed_parent_mtp = parent_mtp;
        proof.public_values.source_mtp = parent_mtp;
        proof.public_values.valid_until_mtp = parent_mtp + 60;
        proof.public_values.source_state_root = tagged_hash(
            "ECX/test-v18-conversion-state/v2",
            &[
                parent_hash.as_slice(),
                &[proof.public_values.kind as u8],
                &parent_mtp.to_be_bytes(),
            ]
            .concat(),
        );
        proof.proof = test_truthcoin_proof(program_id, &proof.public_values.canonical_bytes());
        proof
    };
    let ecx_btc = refresh_conversion(
        previous_ecx_btc.clone(),
        configuration.ecx_btc_conversion_program_id,
    );
    let usdd_usd = refresh_conversion(
        previous_usdd_usd.clone(),
        configuration.usdd_usd_conversion_program_id,
    );
    let conversions = verify_authenticated_conversion_legs_v2(
        configuration,
        parent_hash,
        parent_height,
        parent_mtp,
        &ecx_btc,
        &usdd_usd,
        &TestDigestVerifier,
    )
    .unwrap();
    let scalar = &truthcoin.public_values.lmsr_snapshot;
    let (minimum, maximum, range_commitment) = derive_authenticated_price_range_v2(
        configuration,
        scalar.scalar_lower_bound.get(),
        scalar.scalar_upper_bound.get(),
        conversions,
    )
    .unwrap();
    let quote = derive_hybrid_quote(
        oracle,
        &truthcoin.public_values.anchor,
        &truthcoin.public_values.lmsr_snapshot,
        parent_mtp,
    )
    .unwrap();
    assert_eq!(quote.oracle_mode, OracleMode::Normal);
    let oracle_valid_through_mtp = truthcoin
        .public_values
        .anchor
        .finalized_at_mtp
        .checked_add(oracle.maximum_anchor_age_seconds)
        .unwrap()
        .min(
            truthcoin
                .public_values
                .lmsr_snapshot
                .source_mtp
                .checked_add(oracle.maximum_snapshot_age_seconds)
                .unwrap(),
        );
    V2TestAuthenticatedContext {
        truthcoin,
        ecx_btc,
        usdd_usd,
        oracle_certificate_hash: quote.certificate_hash(),
        mark: quote.ecx_usdd_index,
        liquidation_low: quote.ecx_usdd_low,
        liquidation_high: quote.ecx_usdd_high,
        oracle_valid_through_mtp,
        authenticated_min_price: Price::new(minimum).unwrap(),
        authenticated_max_price: Price::new(maximum).unwrap(),
        authenticated_price_range_commitment: range_commitment,
    }
}
