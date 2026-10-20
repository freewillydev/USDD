//! Bounded Bitcoin-header authentication for V2 matcher execution timestamps.
//!
//! The outer proof already binds `expected_tip_*` to its authenticated prior
//! parent context. This verifier proves that every signed execution locator is
//! on that exact bounded ancestry, recomputes its 11-header median-time-past,
//! and checks each included header's claimed proof of work against the frozen
//! Alpha proof-of-work limit.
//!
//! Seventeen headers cannot independently establish an arbitrary retarget
//! interval or cumulative best-chain work. Those
//! remain obligations of the authenticated parent-tip source. In particular,
//! this module never treats the matcher signature as proof of Bitcoin ancestry.

use ecx_protocol_core::{Hash32, MatcherExecutionReceiptV2, SuccessorMatcherExecutionReceiptV2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const FUNDING_PARENT_CHAIN_WITNESS_VERSION_V2: u8 = 1;
pub const FUNDING_PARENT_MTP_WINDOW_V2: usize = 11;
pub const FUNDING_PARENT_PREHISTORY_V2: u64 = 10;
pub const FUNDING_PARENT_MAX_HEADERS_V2: usize = 17;

/// Exact 80-byte Bitcoin header encoded without any variable-length inner
/// field. The three chunks exist solely because serde's stable array support is
/// bounded; canonical bincode still emits exactly 80 raw bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinHeader80V2 {
    pub first_32: [u8; 32],
    pub second_32: [u8; 32],
    pub final_16: [u8; 16],
}

impl BitcoinHeader80V2 {
    pub fn from_raw(raw: [u8; 80]) -> Self {
        let mut first_32 = [0; 32];
        first_32.copy_from_slice(&raw[..32]);
        let mut second_32 = [0; 32];
        second_32.copy_from_slice(&raw[32..64]);
        let mut final_16 = [0; 16];
        final_16.copy_from_slice(&raw[64..]);
        Self {
            first_32,
            second_32,
            final_16,
        }
    }

    pub fn raw(self) -> [u8; 80] {
        let mut raw = [0; 80];
        raw[..32].copy_from_slice(&self.first_32);
        raw[32..64].copy_from_slice(&self.second_32);
        raw[64..].copy_from_slice(&self.final_16);
        raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FundingParentChainWitnessV2 {
    pub version: u8,
    /// Height of `headers[0]`. For a nonempty execution batch this must be
    /// exactly ten blocks before the earliest execution parent.
    pub start_height: u64,
    /// Consecutive canonical headers through the exact authenticated prior tip.
    pub headers: Vec<BitcoinHeader80V2>,
}

impl FundingParentChainWitnessV2 {
    pub const VERSION: u8 = FUNDING_PARENT_CHAIN_WITNESS_VERSION_V2;

    pub const fn empty() -> Self {
        Self {
            version: Self::VERSION,
            start_height: 0,
            headers: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFundingParentChainV2 {
    pub tip_hash_internal: Hash32,
    pub tip_height: u64,
    pub tip_mtp: u64,
    pub header_count: u8,
    pub execution_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FundingParentChainErrorV2 {
    #[error("unsupported funding parent-chain witness version")]
    UnsupportedVersion,
    #[error("empty/nonempty funding parent witness disagrees with the execution batch")]
    EmptyWitnessMismatch,
    #[error("funding parent-chain witness shape, start height, or bound is invalid")]
    InvalidWitnessShape,
    #[error("Alpha header compact target is invalid or above the Alpha proof-of-work limit")]
    InvalidTarget,
    #[error("Bitcoin header does not satisfy its claimed proof of work")]
    InsufficientProofOfWork,
    #[error("Bitcoin header ancestry link is broken")]
    BrokenParentLink,
    #[error("authenticated prior-parent tip hash/height/MTP does not match the witness")]
    TipMismatch,
    #[error("execution parent is absent, too old, or has a wrong hash/MTP")]
    ExecutionParentMismatch,
    #[error("Bitcoin contextual median-time-past rule is violated")]
    InvalidHeaderTime,
    #[error("integer arithmetic overflow")]
    ArithmeticOverflow,
}

/// Verify the exact bounded parent ancestry consumed by V2 funding.
///
/// Hashes use Bitcoin's internal serialized byte order: raw SHA256d digest
/// bytes, which are the byte order present in the next header's prev-block
/// field. Exporters must reverse the usual RPC/display hex before populating a
/// locator if their RPC library exposes display order.
pub fn verify_funding_parent_chain_v2(
    witness: &FundingParentChainWitnessV2,
    expected_tip_hash_internal: Hash32,
    expected_tip_height: u64,
    expected_tip_mtp: u64,
    execution_receipts: &[MatcherExecutionReceiptV2],
    maximum_execution_depth: u32,
) -> Result<VerifiedFundingParentChainV2, FundingParentChainErrorV2> {
    let parents = execution_receipts
        .iter()
        .map(|receipt| FundingExecutionParentV2 {
            block_hash: receipt.body.execution_parent.block_hash,
            height: receipt.body.execution_parent.height,
            median_time_past: receipt.body.execution_parent.median_time_past,
        })
        .collect::<Vec<_>>();
    verify_funding_parent_chain_locators_v2(
        witness,
        expected_tip_hash_internal,
        expected_tip_height,
        expected_tip_mtp,
        &parents,
        maximum_execution_depth,
    )
}

pub fn verify_successor_funding_parent_chain_v2(
    witness: &FundingParentChainWitnessV2,
    expected_tip_hash_internal: Hash32,
    expected_tip_height: u64,
    expected_tip_mtp: u64,
    execution_receipts: &[SuccessorMatcherExecutionReceiptV2],
    maximum_execution_depth: u32,
) -> Result<VerifiedFundingParentChainV2, FundingParentChainErrorV2> {
    let parents = execution_receipts
        .iter()
        .map(|receipt| FundingExecutionParentV2 {
            block_hash: receipt.body.execution_parent.block_hash,
            height: receipt.body.execution_parent.height,
            median_time_past: receipt.body.execution_parent.median_time_past,
        })
        .collect::<Vec<_>>();
    verify_funding_parent_chain_locators_v2(
        witness,
        expected_tip_hash_internal,
        expected_tip_height,
        expected_tip_mtp,
        &parents,
        maximum_execution_depth,
    )
}

#[derive(Clone, Copy)]
struct FundingExecutionParentV2 {
    block_hash: Hash32,
    height: u64,
    median_time_past: u64,
}

fn verify_funding_parent_chain_locators_v2(
    witness: &FundingParentChainWitnessV2,
    expected_tip_hash_internal: Hash32,
    expected_tip_height: u64,
    expected_tip_mtp: u64,
    execution_parents: &[FundingExecutionParentV2],
    maximum_execution_depth: u32,
) -> Result<VerifiedFundingParentChainV2, FundingParentChainErrorV2> {
    if witness.version != FundingParentChainWitnessV2::VERSION {
        return Err(FundingParentChainErrorV2::UnsupportedVersion);
    }
    if execution_parents.is_empty() {
        if witness.start_height != 0 || !witness.headers.is_empty() {
            return Err(FundingParentChainErrorV2::EmptyWitnessMismatch);
        }
        return Ok(VerifiedFundingParentChainV2 {
            tip_hash_internal: expected_tip_hash_internal,
            tip_height: expected_tip_height,
            tip_mtp: expected_tip_mtp,
            header_count: 0,
            execution_count: 0,
        });
    }
    if expected_tip_hash_internal == [0; 32]
        || expected_tip_height == 0
        || expected_tip_mtp == 0
        || maximum_execution_depth == 0
        || witness.headers.len() < FUNDING_PARENT_MTP_WINDOW_V2
        || witness.headers.len() > FUNDING_PARENT_MAX_HEADERS_V2
    {
        return Err(FundingParentChainErrorV2::InvalidWitnessShape);
    }
    let earliest = execution_parents
        .iter()
        .map(|parent| parent.height)
        .min()
        .ok_or(FundingParentChainErrorV2::EmptyWitnessMismatch)?;
    let expected_start = earliest
        .checked_sub(FUNDING_PARENT_PREHISTORY_V2)
        .ok_or(FundingParentChainErrorV2::InvalidWitnessShape)?;
    let derived_tip_height = witness
        .start_height
        .checked_add(
            u64::try_from(witness.headers.len() - 1)
                .map_err(|_| FundingParentChainErrorV2::ArithmeticOverflow)?,
        )
        .ok_or(FundingParentChainErrorV2::ArithmeticOverflow)?;
    if witness.start_height != expected_start || derived_tip_height != expected_tip_height {
        return Err(FundingParentChainErrorV2::InvalidWitnessShape);
    }

    let mut hashes = Vec::with_capacity(witness.headers.len());
    let mut times = Vec::with_capacity(witness.headers.len());
    for (index, header) in witness.headers.iter().copied().enumerate() {
        let raw = header.raw();
        let hash = bitcoin_header_hash_internal_v2(&raw);
        let bits = u32::from_le_bytes(raw[72..76].try_into().expect("fixed Bitcoin header field"));
        let target = decode_alpha_target_le(bits)?;
        if compare_u256_le(&hash, &target).is_gt() {
            return Err(FundingParentChainErrorV2::InsufficientProofOfWork);
        }
        if index > 0 && raw[4..36] != hashes[index - 1] {
            return Err(FundingParentChainErrorV2::BrokenParentLink);
        }
        let time = u32::from_le_bytes(raw[68..72].try_into().expect("fixed Bitcoin header field"));
        if index >= FUNDING_PARENT_MTP_WINDOW_V2
            && time <= median_time_past(&times[index - FUNDING_PARENT_MTP_WINDOW_V2..index])?
        {
            return Err(FundingParentChainErrorV2::InvalidHeaderTime);
        }
        hashes.push(hash);
        times.push(time);
    }

    let tip_mtp = u64::from(median_time_past(
        &times[times.len() - FUNDING_PARENT_MTP_WINDOW_V2..],
    )?);
    if hashes.last().copied() != Some(expected_tip_hash_internal)
        || derived_tip_height != expected_tip_height
        || tip_mtp != expected_tip_mtp
    {
        return Err(FundingParentChainErrorV2::TipMismatch);
    }

    for parent in execution_parents {
        let depth = expected_tip_height
            .checked_sub(parent.height)
            .ok_or(FundingParentChainErrorV2::ExecutionParentMismatch)?;
        let index = parent
            .height
            .checked_sub(witness.start_height)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < hashes.len())
            .ok_or(FundingParentChainErrorV2::ExecutionParentMismatch)?;
        if depth > u64::from(maximum_execution_depth)
            || index < FUNDING_PARENT_PREHISTORY_V2 as usize
            || hashes[index] != parent.block_hash
            || u64::from(median_time_past(
                &times[index + 1 - FUNDING_PARENT_MTP_WINDOW_V2..=index],
            )?) != parent.median_time_past
        {
            return Err(FundingParentChainErrorV2::ExecutionParentMismatch);
        }
    }

    Ok(VerifiedFundingParentChainV2 {
        tip_hash_internal: expected_tip_hash_internal,
        tip_height: expected_tip_height,
        tip_mtp,
        header_count: u8::try_from(witness.headers.len())
            .map_err(|_| FundingParentChainErrorV2::ArithmeticOverflow)?,
        execution_count: u32::try_from(execution_parents.len())
            .map_err(|_| FundingParentChainErrorV2::ArithmeticOverflow)?,
    })
}

pub fn bitcoin_header_hash_internal_v2(raw: &[u8; 80]) -> Hash32 {
    let first = Sha256::digest(raw);
    Sha256::digest(first).into()
}

/// Reverse a conventional Bitcoin RPC/display hash into the raw internal byte
/// order used in serialized header links and ECX proof bindings. Applying the
/// function twice returns the original value.
pub fn reverse_bitcoin_hash_byte_order_v2(mut hash: Hash32) -> Hash32 {
    hash.reverse();
    hash
}

/// Compose and immediately verify a bounded witness from explicit local raw
/// headers. This function performs no RPC or network access; callers must
/// source the consecutive headers and authenticated expected tip separately.
pub fn compose_funding_parent_chain_v2(
    start_height: u64,
    raw_headers: &[[u8; 80]],
    expected_tip_hash_internal: Hash32,
    expected_tip_height: u64,
    expected_tip_mtp: u64,
    execution_receipts: &[MatcherExecutionReceiptV2],
    maximum_execution_depth: u32,
) -> Result<FundingParentChainWitnessV2, FundingParentChainErrorV2> {
    let witness = FundingParentChainWitnessV2 {
        version: FundingParentChainWitnessV2::VERSION,
        start_height,
        headers: raw_headers
            .iter()
            .copied()
            .map(BitcoinHeader80V2::from_raw)
            .collect(),
    };
    verify_funding_parent_chain_v2(
        &witness,
        expected_tip_hash_internal,
        expected_tip_height,
        expected_tip_mtp,
        execution_receipts,
        maximum_execution_depth,
    )?;
    Ok(witness)
}

fn median_time_past(times: &[u32]) -> Result<u32, FundingParentChainErrorV2> {
    if times.len() != FUNDING_PARENT_MTP_WINDOW_V2 {
        return Err(FundingParentChainErrorV2::InvalidWitnessShape);
    }
    let mut sorted = [0u32; FUNDING_PARENT_MTP_WINDOW_V2];
    sorted.copy_from_slice(times);
    sorted.sort_unstable();
    Ok(sorted[FUNDING_PARENT_MTP_WINDOW_V2 / 2])
}

fn decode_alpha_target_le(bits: u32) -> Result<[u8; 32], FundingParentChainErrorV2> {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative || overflow || word == 0 {
        return Err(FundingParentChainErrorV2::InvalidTarget);
    }
    let mut target = [0u8; 32];
    if size <= 3 {
        target[..4].copy_from_slice(&word.to_le_bytes());
    } else {
        let offset =
            usize::try_from(size - 3).map_err(|_| FundingParentChainErrorV2::InvalidTarget)?;
        for (index, byte) in word.to_le_bytes().into_iter().enumerate().take(3) {
            if byte != 0 {
                *target
                    .get_mut(offset + index)
                    .ok_or(FundingParentChainErrorV2::InvalidTarget)? = byte;
            }
        }
    }
    // Alpha's proof-of-work limit, the Bitcoin mainnet limit implied by
    // compact bits 0x1d00ffff. Big-endian that is 0x00000000ffff0000 followed
    // by zeros, so little-endian it is 0xffff at indices 26 and 27. This is
    // strictly harder than the Signet limit it replaces.
    const POW_LIMIT_LE: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        0, 0, 0, 0,
    ];
    if compare_u256_le(&target, &POW_LIMIT_LE).is_gt() {
        return Err(FundingParentChainErrorV2::InvalidTarget);
    }
    Ok(target)
}

fn compare_u256_le(left: &[u8; 32], right: &[u8; 32]) -> core::cmp::Ordering {
    left.iter().rev().cmp(right.iter().rev())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_protocol_core::{
        MatcherExecutionParentV2, MatcherExecutionReceiptBodyV2, Price, Quantity, Signature64,
        ECX_USDD_MARKET,
    };

    const MAINNET_HEADERS_0_TO_16: [&str; 17] = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
        "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
        "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
        "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
        "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
        "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
        "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8",
        "010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c",
        "010000005e2b8043bd9f8db558c284e00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86",
        "0100000089304d4ba5542a22fb616d1ca019e94222ee45c1ad95a83120de515c00000000560164b8bad7675061aa0f43ced718884bdd8528cae07f24c58bb69592d8afe185d36649ffff001d29cbad24",
        "01000000378a6f6593e2f0251132d96616e837eb6999bca963f6675a0c7af180000000000d080260d107d269ccba9247cfc64c952f1d13514b49e9f1230b3a197a8b7450fa276849ffff001d38d8fb98",
        "010000007384231257343f2fa3c55ee69ea9e676a709a06dcfd2f73e8c2c32b300000000442ee91b2b999fb15d61f6a88ecf2988e9c8ed48f002476128e670d3dac19fe706286849ffff001d049e12d6",
    ];

    fn headers() -> Vec<BitcoinHeader80V2> {
        MAINNET_HEADERS_0_TO_16
            .iter()
            .map(|encoded| {
                let raw: [u8; 80] = hex::decode(encoded).unwrap().try_into().unwrap();
                BitcoinHeader80V2::from_raw(raw)
            })
            .collect()
    }

    fn mtp(headers: &[BitcoinHeader80V2], index: usize) -> u64 {
        let times = headers[index + 1 - FUNDING_PARENT_MTP_WINDOW_V2..=index]
            .iter()
            .map(|header| u32::from_le_bytes(header.raw()[68..72].try_into().unwrap()))
            .collect::<Vec<_>>();
        u64::from(median_time_past(&times).unwrap())
    }

    fn receipt(
        headers: &[BitcoinHeader80V2],
        height: usize,
        sequence: u64,
    ) -> MatcherExecutionReceiptV2 {
        MatcherExecutionReceiptV2 {
            body: MatcherExecutionReceiptBodyV2 {
                version: MatcherExecutionReceiptBodyV2::VERSION,
                chain_id: [1; 32],
                market: ECX_USDD_MARKET,
                matcher_config_hash: [2; 32],
                matcher_key_epoch: 1,
                taker_admission_receipt_hash: [3; 32],
                match_id: [4; 32],
                maker_order_id: [5; 32],
                taker_order_id: [6; 32],
                admission_sequence: 1,
                match_sequence: sequence,
                price: Price::new(1).unwrap(),
                quantity: Quantity::new(1).unwrap(),
                observed_sidechain_height: 1,
                execution_parent: MatcherExecutionParentV2 {
                    block_hash: bitcoin_header_hash_internal_v2(&headers[height].raw()),
                    height: height as u64,
                    median_time_past: mtp(headers, height),
                },
            },
            signature: Signature64([0; 64]),
        }
    }

    fn valid_fixture() -> (
        FundingParentChainWitnessV2,
        Vec<MatcherExecutionReceiptV2>,
        Hash32,
        u64,
    ) {
        let headers = headers();
        let receipts = vec![receipt(&headers, 10, 1), receipt(&headers, 16, 2)];
        let tip = bitcoin_header_hash_internal_v2(&headers[16].raw());
        let tip_mtp = mtp(&headers, 16);
        (
            FundingParentChainWitnessV2 {
                version: FundingParentChainWitnessV2::VERSION,
                start_height: 0,
                headers,
            },
            receipts,
            tip,
            tip_mtp,
        )
    }

    #[test]
    fn authenticates_exact_headers_tip_mtp_and_execution_locators() {
        let (witness, receipts, tip, tip_mtp) = valid_fixture();
        let verified =
            verify_funding_parent_chain_v2(&witness, tip, 16, tip_mtp, &receipts, 6).unwrap();
        assert_eq!(verified.header_count, 17);
        assert_eq!(verified.execution_count, 2);
    }

    #[test]
    fn header_link_pow_tip_mtp_depth_and_locator_mutations_fail_closed() {
        let (witness, receipts, tip, tip_mtp) = valid_fixture();

        let mut broken_link = witness.clone();
        broken_link.headers[5].first_32[4] ^= 1;
        assert!(matches!(
            verify_funding_parent_chain_v2(&broken_link, tip, 16, tip_mtp, &receipts, 6),
            Err(FundingParentChainErrorV2::BrokenParentLink)
                | Err(FundingParentChainErrorV2::InsufficientProofOfWork)
        ));

        let mut invalid_target = witness.clone();
        let mut raw = invalid_target.headers[0].raw();
        raw[72..76].copy_from_slice(&0x2100_ffffu32.to_le_bytes());
        invalid_target.headers[0] = BitcoinHeader80V2::from_raw(raw);
        assert_eq!(
            verify_funding_parent_chain_v2(&invalid_target, tip, 16, tip_mtp, &receipts, 6),
            Err(FundingParentChainErrorV2::InvalidTarget)
        );

        let mut wrong_tip = tip;
        wrong_tip[0] ^= 1;
        assert_eq!(
            verify_funding_parent_chain_v2(&witness, wrong_tip, 16, tip_mtp, &receipts, 6),
            Err(FundingParentChainErrorV2::TipMismatch)
        );
        assert_eq!(
            verify_funding_parent_chain_v2(&witness, tip, 16, tip_mtp + 1, &receipts, 6),
            Err(FundingParentChainErrorV2::TipMismatch)
        );

        let mut wrong_locator = receipts.clone();
        wrong_locator[0].body.execution_parent.median_time_past += 1;
        assert_eq!(
            verify_funding_parent_chain_v2(&witness, tip, 16, tip_mtp, &wrong_locator, 6),
            Err(FundingParentChainErrorV2::ExecutionParentMismatch)
        );
        assert_eq!(
            verify_funding_parent_chain_v2(&witness, tip, 16, tip_mtp, &receipts, 5),
            Err(FundingParentChainErrorV2::ExecutionParentMismatch)
        );
    }

    #[test]
    fn exact_shape_and_empty_batch_are_canonical() {
        let (mut witness, receipts, tip, tip_mtp) = valid_fixture();
        witness.start_height = 1;
        assert_eq!(
            verify_funding_parent_chain_v2(&witness, tip, 16, tip_mtp, &receipts, 6),
            Err(FundingParentChainErrorV2::InvalidWitnessShape)
        );
        let empty = FundingParentChainWitnessV2::empty();
        assert_eq!(
            verify_funding_parent_chain_v2(&empty, tip, 16, tip_mtp, &[], 6)
                .unwrap()
                .header_count,
            0
        );
        let mut noncanonical_empty = empty;
        noncanonical_empty.start_height = 1;
        assert_eq!(
            verify_funding_parent_chain_v2(&noncanonical_empty, tip, 16, tip_mtp, &[], 6),
            Err(FundingParentChainErrorV2::EmptyWitnessMismatch)
        );
    }

    #[test]
    fn offline_composer_checks_tip_byte_order_and_exact_tip_receipt() {
        let all = headers();
        let receipt = receipt(&all, 16, 1);
        let raw = all[6..=16]
            .iter()
            .copied()
            .map(BitcoinHeader80V2::raw)
            .collect::<Vec<_>>();
        let tip = bitcoin_header_hash_internal_v2(&all[16].raw());
        let witness = compose_funding_parent_chain_v2(
            6,
            &raw,
            tip,
            16,
            mtp(&all, 16),
            std::slice::from_ref(&receipt),
            6,
        )
        .unwrap();
        assert_eq!(witness.headers.len(), 11);
        assert_eq!(
            reverse_bitcoin_hash_byte_order_v2(reverse_bitcoin_hash_byte_order_v2(tip)),
            tip
        );
        assert_eq!(
            compose_funding_parent_chain_v2(
                6,
                &raw,
                reverse_bitcoin_hash_byte_order_v2(tip),
                16,
                mtp(&all, 16),
                &[receipt],
                6,
            ),
            Err(FundingParentChainErrorV2::TipMismatch)
        );
    }


    /// Alpha replaced LayerTwo Signet here. Signet's limit is far easier, so a
    /// silent revert would let this relation accept parent headers carrying a
    /// fraction of Alpha's required work. These assert the boundary directly.
    #[test]
    fn alpha_target_limit_rejects_signet_level_difficulty() {
        // 0x1d00ffff is exactly Alpha's limit and must be accepted.
        let at_limit = decode_alpha_target_le(0x1d00_ffff)
            .expect("Alpha pow limit itself must decode");

        // 0x1e0377ae sits at the old Signet limit: easier than Alpha's, and
        // previously accepted here. It must now be rejected.
        assert!(matches!(
            decode_alpha_target_le(0x1e03_77ae),
            Err(FundingParentChainErrorV2::InvalidTarget)
        ));

        // Anything harder than the limit stays acceptable.
        let harder = decode_alpha_target_le(0x1c00_ffff)
            .expect("a target below the limit must decode");
        assert_eq!(compare_u256_le(&harder, &at_limit), core::cmp::Ordering::Less);
    }

    #[test]
    fn alpha_target_limit_is_the_mainnet_limit_little_endian() {
        // Rebuild 0x00000000ffff0000... big-endian, reverse it, and confirm
        // the decoder agrees with the constant it enforces.
        let mut be = [0u8; 32];
        be[4] = 0xff;
        be[5] = 0xff;
        let mut expected_le = be;
        expected_le.reverse();
        assert_eq!(
            decode_alpha_target_le(0x1d00_ffff).unwrap(),
            expected_le
        );
    }
}
