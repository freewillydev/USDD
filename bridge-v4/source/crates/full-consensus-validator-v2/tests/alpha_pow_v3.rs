//! Public live-Alpha header regressions only. These fixtures do not establish
//! authenticated checkpoint provenance, full-block validity or proof readiness.

use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{BlockHash, Network};
use ecx_full_consensus_validator_v2::alpha_pow_v3::{
    alpha_pow_profile_commitment_v3, expected_alpha_next_target_v3, verify_alpha_next_header_v3,
    AlphaHeaderContextV3, ALPHA_FORK_HEIGHT_V3, ALPHA_MAX_FUTURE_SECONDS_V3,
    ALPHA_RETARGET_INTERVAL_V3,
};
use ecx_full_consensus_validator_v2::{
    expected_next_target_v2, median_time_past_v2, verify_next_header_context_v2,
    BitcoinPowContextV2, FullValidatorPrimitiveErrorV2,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/alpha-public-headers-v3.json");
const FIXTURE_SHA256: &str = "7eeccac22afcf708d44178acf5970c5e3d4d048b4ba03f6a85a0ef10c74935ad";
const PROFILE_COMMITMENT: &str = "c32161db8077b081ef9440f2fee521737511e33fbb58baec16ed557cb57a1a53";

#[derive(Deserialize)]
struct Fixture {
    schema: String,
    genesis_hash: String,
    alpha_fork_height: u32,
    retarget_interval: u32,
    snapshot_tip_height: u32,
    snapshot_tip_hash: String,
    recent_retarget_height: u32,
    headers: Vec<HeaderRecord>,
}

#[derive(Deserialize)]
struct HeaderRecord {
    height: u32,
    hash: String,
    raw: String,
    previous_block_hash: Option<String>,
    time: u32,
    median_time: u32,
    bits: String,
}

impl HeaderRecord {
    fn header(&self) -> Header {
        let bytes = hex::decode(&self.raw).unwrap();
        assert_eq!(bytes.len(), 80);
        deserialize(&bytes).unwrap()
    }
}

impl Fixture {
    fn at(&self, height: u32) -> &HeaderRecord {
        self.headers
            .iter()
            .find(|record| record.height == height)
            .unwrap()
    }

    fn context_at(&self, height: u32) -> AlphaHeaderContextV3 {
        let epoch = height / ALPHA_RETARGET_INTERVAL_V3 * ALPHA_RETARGET_INTERVAL_V3;
        AlphaHeaderContextV3 {
            previous_height: height,
            previous_header: self.at(height).header(),
            previous_11_times: (height - 10..=height).map(|h| self.at(h).time).collect(),
            retarget_epoch_start_time: self.at(epoch).time,
        }
    }
}

fn fixture() -> Fixture {
    assert_eq!(
        sha256::Hash::hash(FIXTURE.as_bytes()).to_string(),
        FIXTURE_SHA256
    );
    let fixture: Fixture = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture.schema, "ECX_ALPHA_PUBLIC_HEADER_FIXTURES_V3");
    assert_eq!(fixture.alpha_fork_height, ALPHA_FORK_HEIGHT_V3);
    assert_eq!(fixture.retarget_interval, ALPHA_RETARGET_INTERVAL_V3);
    fixture
}

#[test]
fn frozen_public_headers_match_hashes_fields_and_observed_mtp() {
    let fixture = fixture();
    assert_eq!(
        fixture.genesis_hash,
        bitcoin::blockdata::constants::genesis_block(Network::Bitcoin)
            .block_hash()
            .to_string()
    );
    assert_eq!(fixture.at(0).hash, fixture.genesis_hash);
    assert_eq!(
        fixture.at(fixture.snapshot_tip_height).hash,
        fixture.snapshot_tip_hash
    );
    for record in &fixture.headers {
        let header = record.header();
        assert_eq!(header.block_hash().to_string(), record.hash);
        assert_eq!(header.time, record.time);
        assert_eq!(format!("{:08x}", header.bits.to_consensus()), record.bits);
        if let Some(previous) = &record.previous_block_hash {
            assert_eq!(&header.prev_blockhash.to_string(), previous);
        }
        header.validate_pow(header.target()).unwrap();
    }
    for height in [
        ALPHA_FORK_HEIGHT_V3 - 1,
        fixture.recent_retarget_height - 1,
        fixture.snapshot_tip_height,
    ] {
        let context = fixture.context_at(height);
        assert_eq!(
            median_time_past_v2(&context.previous_11_times).unwrap(),
            fixture.at(height).median_time
        );
        context.commitment().unwrap();
    }
}

#[test]
fn real_alpha_fork_reset_matches_both_alpha_paths_and_rejects_stock_target() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    let header = fixture.at(ALPHA_FORK_HEIGHT_V3).header();
    assert_eq!(context.previous_header.bits.to_consensus(), 0x1702353d);
    assert_eq!(
        expected_alpha_next_target_v3(&context)
            .unwrap()
            .to_consensus(),
        0x1d00ffff
    );
    assert_eq!(header.bits.to_consensus(), 0x1d00ffff);
    // A test time selected from the fixture is not a production authenticated clock.
    let next = verify_alpha_next_header_v3(&context, header, u64::from(header.time)).unwrap();
    assert_eq!(next.previous_height, ALPHA_FORK_HEIGHT_V3);
    assert_eq!(next.retarget_epoch_start_time, header.time);
    assert_eq!(next.previous_11_times[10], header.time);

    let legacy_named_alpha = BitcoinPowContextV2 {
        previous_height: context.previous_height,
        previous_header: context.previous_header,
        previous_11_times: context.previous_11_times.clone(),
        retarget_epoch_start_time: context.retarget_epoch_start_time,
    };
    // Independently calculated from the live previous epoch: 1,225,690 seconds.
    assert_eq!(
        bitcoin::pow::CompactTarget::from_next_work_required(
            context.previous_header.bits, 1_225_690, bitcoin::consensus::Params::MAINNET)
            .to_consensus(),
        0x17023cc1
    );
    assert_eq!(
        expected_next_target_v2(&legacy_named_alpha, header.time)
            .unwrap()
            .to_consensus(),
        0x1d00ffff
    );
    verify_next_header_context_v2(&legacy_named_alpha, header, u64::from(header.time)).unwrap();
    let mut wrong_target = header;
    wrong_target.bits = bitcoin::pow::CompactTarget::from_consensus(0x17023cc1);
    assert!(matches!(
        verify_next_header_context_v2(&legacy_named_alpha, wrong_target, u64::from(header.time)),
        Err(FullValidatorPrimitiveErrorV2::ProofOfWork)
    ));
    assert!(matches!(
        verify_alpha_next_header_v3(&context, wrong_target, u64::from(header.time)),
        Err(FullValidatorPrimitiveErrorV2::ProofOfWork)
    ));
}

#[test]
fn real_post_fork_header_and_recent_retarget_update_exact_context() {
    let fixture = fixture();
    for height in [ALPHA_FORK_HEIGHT_V3, fixture.recent_retarget_height] {
        let context = fixture.context_at(height - 1);
        let header = fixture.at(height).header();
        let next = verify_alpha_next_header_v3(&context, header, u64::from(header.time)).unwrap();
        assert_eq!(next.retarget_epoch_start_time, header.time);
        assert_eq!(
            &next.previous_11_times[..10],
            &context.previous_11_times[1..]
        );
        let after_header = fixture.at(height + 1).header();
        let after =
            verify_alpha_next_header_v3(&next, after_header, u64::from(after_header.time)).unwrap();
        assert_eq!(after.previous_height, height + 1);
        assert_eq!(after.retarget_epoch_start_time, header.time);
        assert_eq!(after_header.bits, header.bits);
    }
    let context = fixture.context_at(fixture.recent_retarget_height - 1);
    assert_eq!(context.previous_header.bits.to_consensus(), 0x1903fffc);
    assert_eq!(
        expected_alpha_next_target_v3(&context)
            .unwrap()
            .to_consensus(),
        0x1900ffff
    );
}

#[test]
fn wrong_link_and_mtp_fail_before_any_pow_acceptance() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    let header = fixture.at(ALPHA_FORK_HEIGHT_V3).header();
    let mut wrong_link = header;
    wrong_link.prev_blockhash = BlockHash::all_zeros();
    assert!(matches!(
        verify_alpha_next_header_v3(&context, wrong_link, u64::from(header.time)),
        Err(FullValidatorPrimitiveErrorV2::HeaderLink)
    ));
    let mut old_time = header;
    old_time.time = median_time_past_v2(&context.previous_11_times).unwrap();
    assert!(matches!(
        verify_alpha_next_header_v3(&context, old_time, u64::from(header.time)),
        Err(FullValidatorPrimitiveErrorV2::HeaderTime)
    ));
}

#[test]
fn future_time_bound_and_clock_overflow_fail_closed() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    let header = fixture.at(ALPHA_FORK_HEIGHT_V3).header();
    let exact_bound = u64::from(header.time) - ALPHA_MAX_FUTURE_SECONDS_V3;
    verify_alpha_next_header_v3(&context, header, exact_bound).unwrap();
    for bad_clock in [exact_bound - 1, u64::MAX] {
        assert!(matches!(
            verify_alpha_next_header_v3(&context, header, bad_clock),
            Err(FullValidatorPrimitiveErrorV2::HeaderTime)
        ));
    }
}

#[test]
fn wrong_bits_nonce_and_version_fail_closed() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    let header = fixture.at(ALPHA_FORK_HEIGHT_V3).header();
    let mut bad_bits = header;
    bad_bits.bits = CompactTarget::from_consensus(0x207fffff);
    let mut bad_version = header;
    bad_version.version = Version::from_consensus(1);
    let mut bad_pow = header;
    let mut found_bad_pow = false;
    for offset in 1..=1024 {
        bad_pow.nonce = header.nonce.wrapping_add(offset);
        if bad_pow.validate_pow(Target::from(header.bits)).is_err() {
            found_bad_pow = true;
            break;
        }
    }
    assert!(
        found_bad_pow,
        "Fixture must supply a demonstrably invalid nonce"
    );
    for invalid in [bad_bits, bad_version, bad_pow] {
        assert!(matches!(
            verify_alpha_next_header_v3(&context, invalid, u64::from(header.time)),
            Err(FullValidatorPrimitiveErrorV2::ProofOfWork)
        ));
    }
}

#[test]
fn network_and_pow_parameters_cannot_be_selected_by_witness() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    // There is no network/parameters field in the Rust API, and serde refuses
    // attempted extension fields rather than silently accepting them.
    for (field, value) in [
        ("network", serde_json::json!("signet")),
        ("pow_limit_bits", serde_json::json!(0x207fffffu32)),
        ("allow_min_difficulty_blocks", serde_json::json!(true)),
    ] {
        let mut witness = serde_json::to_value(&context).unwrap();
        witness
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        assert!(serde_json::from_value::<AlphaHeaderContextV3>(witness).is_err());
    }
}

#[test]
fn context_is_exact_and_profile_commitment_is_frozen() {
    let fixture = fixture();
    let context = fixture.context_at(ALPHA_FORK_HEIGHT_V3 - 1);
    assert_eq!(
        hex::encode(alpha_pow_profile_commitment_v3()),
        PROFILE_COMMITMENT
    );
    let original = context.commitment().unwrap();
    let mut changed_mtp = context.clone();
    changed_mtp.previous_11_times[0] += 1;
    assert_ne!(changed_mtp.commitment().unwrap(), original);
    let mut changed_epoch = context.clone();
    changed_epoch.retarget_epoch_start_time += 1;
    assert_ne!(changed_epoch.commitment().unwrap(), original);

    let mut missing_time = context.clone();
    missing_time.previous_11_times.remove(0);
    let mut wrong_last = context.clone();
    wrong_last.previous_11_times[10] += 1;
    let mut missing_epoch = context.clone();
    missing_epoch.retarget_epoch_start_time = 0;
    let mut easy_target = context;
    easy_target.previous_header.bits = CompactTarget::from_consensus(0x207fffff);
    for invalid in [missing_time, wrong_last, missing_epoch, easy_target] {
        assert!(matches!(
            expected_alpha_next_target_v3(&invalid),
            Err(FullValidatorPrimitiveErrorV2::DifficultyContext)
        ));
        assert!(invalid.commitment().is_err());
    }
}
