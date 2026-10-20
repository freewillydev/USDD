//! Canonical BIP301/BMM parent-chain proof envelope and execution primitives.

use bitcoin::consensus::encode::{Decodable, Encodable};
use bitcoin::hashes::{sha256d, Hash as _};
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{BlockHash, MerkleBlock, Transaction};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use thiserror::Error;

pub const BMM_PROOF_SCHEMA_VERSION_V2: u8 = 1;
pub const BMM_SIDECHAIN_SLOT_V2: u8 = 24;
pub const MAX_BMM_PROOF_ENTRIES_V2: usize = 128;
pub const MAX_BMM_PROOF_BYTES_V2: usize = 1_000_000;
pub const MAX_BMM_ENTRY_COMPONENT_BYTES_V2: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmmL1StateV2 {
    pub block_hash: BlockHash,
    pub height: u32,
    pub block_time: u32,
    pub bits: u32,
    pub period_start_height: u32,
    pub period_start_time: u32,
    pub recent_times: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmmProofEntryV2 {
    pub coinbase_transaction: Vec<u8>,
    pub coinbase_merkle_proof: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmmProofV2 {
    pub version: u8,
    pub previous_state: BmmL1StateV2,
    pub entries: Vec<BmmProofEntryV2>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedBmmProofEntryV2 {
    pub coinbase: Transaction,
    pub merkle_block: MerkleBlock,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Alpha BMM consensus parameters. There is no network selector and no Signet
/// challenge: Alpha blocks carry no challenge solution, so the parent coinbase
/// is committed exactly as mined rather than rewritten before hashing.
pub struct BmmConsensusParametersV2 {
    pub pow_limit: Target,
    pub target_timespan: u32,
    pub target_spacing: u32,
    pub sidechain_slot: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum BmmErrorV2 {
    #[error("BMM proof is malformed, noncanonical, or trailing")]
    NonCanonicalEncoding,
    #[error("BMM proof exceeds its consensus resource bounds")]
    ResourceLimit,
    #[error("BMM proof envelope or parent state is invalid")]
    InvalidState,
    #[error("BMM proof does not authenticate exactly the parent coinbase")]
    CoinbaseMerkleProof,
    #[error("BMM parent header linkage, time, target, or proof of work is invalid")]
    HeaderConsensus,
    #[error("BMM final parent or slot commitment is missing, duplicate, or mismatched")]
    CriticalCommitment,
}

impl BmmL1StateV2 {
    pub fn validate(&self, difficulty_adjustment_interval: u32) -> Result<(), BmmErrorV2> {
        if self.block_hash == BlockHash::all_zeros()
            || self.height == 0
            || self.block_time == 0
            || self.bits == 0
            || difficulty_adjustment_interval == 0
            || self.period_start_height > self.height
            || !self
                .period_start_height
                .is_multiple_of(difficulty_adjustment_interval)
            || self.height - self.period_start_height >= difficulty_adjustment_interval
            || self.period_start_time == 0
            || self.recent_times.len() != 11
            || self.recent_times.last() != Some(&self.block_time)
        {
            return Err(BmmErrorV2::InvalidState);
        }
        Ok(())
    }

    pub fn median_time_past(&self) -> Result<u32, BmmErrorV2> {
        let mut times: [u32; 11] = self
            .recent_times
            .clone()
            .try_into()
            .map_err(|_| BmmErrorV2::InvalidState)?;
        times.sort_unstable();
        Ok(times[5])
    }
}

/// Network-agnostic canonical identity of the authenticated BMM parent state.
/// Consensus parameters remain separately frozen; this commits every mutable
/// field needed to continue header validation.
pub fn bmm_l1_state_commitment_v2(state: &BmmL1StateV2) -> Result<[u8; 32], BmmErrorV2> {
    if state.block_hash == BlockHash::all_zeros()
        || state.height == 0
        || state.block_time == 0
        || state.bits == 0
        || state.period_start_height > state.height
        || state.period_start_time == 0
        || state.recent_times.len() != 11
        || state.recent_times.last() != Some(&state.block_time)
    {
        return Err(BmmErrorV2::InvalidState);
    }
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(b"ECX/full-elements-bmm-l1-state/v2");
    payload.extend_from_slice(state.block_hash.as_byte_array());
    payload.extend_from_slice(&state.height.to_be_bytes());
    payload.extend_from_slice(&state.block_time.to_be_bytes());
    payload.extend_from_slice(&state.bits.to_be_bytes());
    payload.extend_from_slice(&state.period_start_height.to_be_bytes());
    payload.extend_from_slice(&state.period_start_time.to_be_bytes());
    for time in &state.recent_times {
        payload.extend_from_slice(&time.to_be_bytes());
    }
    Ok(sha256d::Hash::hash(&payload).to_byte_array())
}

impl BmmProofV2 {
    pub fn decode(raw: &[u8]) -> Result<Self, BmmErrorV2> {
        if raw.is_empty() || raw.len() > MAX_BMM_PROOF_BYTES_V2 {
            return Err(BmmErrorV2::ResourceLimit);
        }
        let mut cursor = Cursor::new(raw);
        let version = read_u8(&mut cursor)?;
        let previous_state = decode_state(&mut cursor)?;
        let entry_count = read_compact_size(&mut cursor)?;
        if entry_count == 0 || entry_count > MAX_BMM_PROOF_ENTRIES_V2 as u64 {
            return Err(BmmErrorV2::ResourceLimit);
        }
        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(BmmProofEntryV2 {
                coinbase_transaction: read_bounded_bytes(&mut cursor)?,
                coinbase_merkle_proof: read_bounded_bytes(&mut cursor)?,
            });
        }
        if cursor.position() != raw.len() as u64 || version != BMM_PROOF_SCHEMA_VERSION_V2 {
            return Err(BmmErrorV2::NonCanonicalEncoding);
        }
        let proof = Self {
            version,
            previous_state,
            entries,
        };
        if proof.encode()? != raw {
            return Err(BmmErrorV2::NonCanonicalEncoding);
        }
        Ok(proof)
    }

    pub fn encode(&self) -> Result<Vec<u8>, BmmErrorV2> {
        if self.version != BMM_PROOF_SCHEMA_VERSION_V2
            || self.entries.is_empty()
            || self.entries.len() > MAX_BMM_PROOF_ENTRIES_V2
        {
            return Err(BmmErrorV2::InvalidState);
        }
        let mut output = Vec::new();
        output.push(self.version);
        encode_state(&self.previous_state, &mut output)?;
        write_compact_size(self.entries.len() as u64, &mut output);
        for entry in &self.entries {
            write_bounded_bytes(&entry.coinbase_transaction, &mut output)?;
            write_bounded_bytes(&entry.coinbase_merkle_proof, &mut output)?;
        }
        if output.len() > MAX_BMM_PROOF_BYTES_V2 {
            return Err(BmmErrorV2::ResourceLimit);
        }
        Ok(output)
    }

    pub fn commitment(&self) -> Result<[u8; 32], BmmErrorV2> {
        Ok(sha256d::Hash::hash(&self.encode()?).to_byte_array())
    }

    pub fn decode_entries(&self) -> Result<Vec<DecodedBmmProofEntryV2>, BmmErrorV2> {
        self.entries.iter().map(BmmProofEntryV2::decode).collect()
    }
}

impl BmmProofEntryV2 {
    pub fn decode(&self) -> Result<DecodedBmmProofEntryV2, BmmErrorV2> {
        if self.coinbase_transaction.is_empty()
            || self.coinbase_merkle_proof.is_empty()
            || self.coinbase_transaction.len() > MAX_BMM_ENTRY_COMPONENT_BYTES_V2
            || self.coinbase_merkle_proof.len() > MAX_BMM_ENTRY_COMPONENT_BYTES_V2
        {
            return Err(BmmErrorV2::ResourceLimit);
        }
        let coinbase: Transaction = decode_exact(&self.coinbase_transaction)?;
        let merkle_block: MerkleBlock = decode_exact(&self.coinbase_merkle_proof)?;
        if coinbase.input.len() != 1 || !coinbase.input[0].previous_output.is_null() {
            return Err(BmmErrorV2::CoinbaseMerkleProof);
        }
        let mut matches = Vec::new();
        let mut indices = Vec::new();
        merkle_block
            .extract_matches(&mut matches, &mut indices)
            .map_err(|_| BmmErrorV2::CoinbaseMerkleProof)?;
        if matches.as_slice() != [coinbase.compute_txid()] || indices.as_slice() != [0] {
            return Err(BmmErrorV2::CoinbaseMerkleProof);
        }
        Ok(DecodedBmmProofEntryV2 {
            coinbase,
            merkle_block,
        })
    }
}

pub fn bmm_proof_commitment_v2(raw: &[u8]) -> Result<[u8; 32], BmmErrorV2> {
    let proof = BmmProofV2::decode(raw)?;
    proof.commitment()
}

/// Alpha's retarget profile. Takes no network argument: Alpha is the only
/// parent chain and shares Bitcoin mainnet's timespan and spacing.
pub fn bmm_network_profile_v2() -> (u32, u32) {
    let params = bitcoin::consensus::Params::MAINNET;
    (
        params.pow_target_timespan as u32,
        params.pow_target_spacing as u32,
    )
}

/// Execute the canonical BMM envelope through its authenticated parent state.
/// Alpha is the only parent chain, and it carries no challenge solution, so
/// the parent coinbase is committed exactly as mined.
pub fn execute_bmm_proof_v2(
    raw: &[u8],
    expected_previous: &BmmL1StateV2,
    expected_parent_hash: BlockHash,
    expected_critical_hash: [u8; 32],
    consensus: &BmmConsensusParametersV2,
) -> Result<BmmL1StateV2, BmmErrorV2> {
    let proof = BmmProofV2::decode(raw)?;
    if &proof.previous_state != expected_previous
        || consensus.target_spacing == 0
        || consensus.target_timespan == 0
        || !consensus
            .target_timespan
            .is_multiple_of(consensus.target_spacing)
    {
        return Err(BmmErrorV2::InvalidState);
    }
    let interval = consensus.target_timespan / consensus.target_spacing;
    expected_previous.validate(interval)?;
    let mut state = expected_previous.clone();
    let decoded = proof.decode_entries()?;
    for entry in &decoded {
        let header = entry.merkle_block.header;
        let expected_bits = expected_next_bits(&state, consensus)?;
        let target = Target::from_compact(expected_bits);
        if header.prev_blockhash != state.block_hash
            || header.bits != expected_bits
            || header.time <= state.median_time_past()?
            || target == Target::ZERO
            || target > consensus.pow_limit
            || header.validate_pow(target).is_err()
        {
            return Err(BmmErrorV2::HeaderConsensus);
        }
        state.height = state
            .height
            .checked_add(1)
            .ok_or(BmmErrorV2::InvalidState)?;
        state.block_hash = header.block_hash();
        state.block_time = header.time;
        state.bits = header.bits.to_consensus();
        state.recent_times.remove(0);
        state.recent_times.push(header.time);
        if state.height.is_multiple_of(interval) {
            state.period_start_height = state.height;
            state.period_start_time = state.block_time;
        }
    }
    let final_entry = decoded.last().ok_or(BmmErrorV2::InvalidState)?;
    if final_entry.merkle_block.header.prev_blockhash != expected_parent_hash {
        return Err(BmmErrorV2::CriticalCommitment);
    }
    let mined = extract_unique_m8_commitment(&final_entry.coinbase, consensus.sidechain_slot)?;
    if mined != expected_critical_hash {
        return Err(BmmErrorV2::CriticalCommitment);
    }
    Ok(state)
}

fn expected_next_bits(
    state: &BmmL1StateV2,
    consensus: &BmmConsensusParametersV2,
) -> Result<CompactTarget, BmmErrorV2> {
    let interval = consensus.target_timespan / consensus.target_spacing;
    let next_height = state
        .height
        .checked_add(1)
        .ok_or(BmmErrorV2::InvalidState)?;
    if !next_height.is_multiple_of(interval) {
        return Ok(CompactTarget::from_consensus(state.bits));
    }
    // Alpha shares Bitcoin mainnet's retarget arithmetic. The supplied
    // parameters must agree with it exactly; there is no network to select.
    let network = bitcoin::consensus::Params::MAINNET;
    if network.pow_target_timespan != u64::from(consensus.target_timespan)
        || network.pow_target_spacing != u64::from(consensus.target_spacing)
        || network.max_attainable_target != consensus.pow_limit
    {
        return Err(BmmErrorV2::HeaderConsensus);
    }
    Ok(CompactTarget::from_next_work_required(
        CompactTarget::from_consensus(state.bits),
        u64::from(state.block_time.saturating_sub(state.period_start_time)),
        network,
    ))
}

fn extract_unique_m8_commitment(
    coinbase: &Transaction,
    sidechain_slot: u8,
) -> Result<[u8; 32], BmmErrorV2> {
    const M8_MAGIC: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];
    let mut found = None;
    for output in &coinbase.output {
        let instructions: Vec<_> = output.script_pubkey.instructions().collect();
        let [first, second] = instructions.as_slice() else {
            continue;
        };
        if !matches!(first, Ok(bitcoin::script::Instruction::Op(op)) if *op == bitcoin::opcodes::all::OP_RETURN)
        {
            continue;
        }
        let Ok(bitcoin::script::Instruction::PushBytes(bytes)) = second else {
            continue;
        };
        let bytes = bytes.as_bytes();
        if bytes.len() != 37 || bytes[..4] != M8_MAGIC || bytes[4] != sidechain_slot {
            continue;
        }
        if found.is_some() {
            return Err(BmmErrorV2::CriticalCommitment);
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[5..]);
        // M8 carries the human/display byte order used by Core's GetHex().
        hash.reverse();
        found = Some(hash);
    }
    found.ok_or(BmmErrorV2::CriticalCommitment)
}


fn decode_state(cursor: &mut Cursor<&[u8]>) -> Result<BmmL1StateV2, BmmErrorV2> {
    let block_hash = BlockHash::from_byte_array(read_hash(cursor)?);
    let height = read_u32(cursor)?;
    let block_time = read_u32(cursor)?;
    let bits = read_u32(cursor)?;
    let period_start_height = read_u32(cursor)?;
    let period_start_time = read_u32(cursor)?;
    let count = read_compact_size(cursor)?;
    if count > 11 {
        return Err(BmmErrorV2::InvalidState);
    }
    let mut recent_times = Vec::with_capacity(count as usize);
    for _ in 0..count {
        recent_times.push(read_u32(cursor)?);
    }
    Ok(BmmL1StateV2 {
        block_hash,
        height,
        block_time,
        bits,
        period_start_height,
        period_start_time,
        recent_times,
    })
}

fn encode_state(state: &BmmL1StateV2, output: &mut Vec<u8>) -> Result<(), BmmErrorV2> {
    output.extend_from_slice(&state.block_hash.to_byte_array());
    output.extend_from_slice(&state.height.to_le_bytes());
    output.extend_from_slice(&state.block_time.to_le_bytes());
    output.extend_from_slice(&state.bits.to_le_bytes());
    output.extend_from_slice(&state.period_start_height.to_le_bytes());
    output.extend_from_slice(&state.period_start_time.to_le_bytes());
    if state.recent_times.len() > 11 {
        return Err(BmmErrorV2::InvalidState);
    }
    write_compact_size(state.recent_times.len() as u64, output);
    for time in &state.recent_times {
        output.extend_from_slice(&time.to_le_bytes());
    }
    Ok(())
}

fn decode_exact<T: Decodable + Encodable>(raw: &[u8]) -> Result<T, BmmErrorV2> {
    let mut cursor = Cursor::new(raw);
    let value = T::consensus_decode(&mut cursor).map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    if cursor.position() != raw.len() as u64 {
        return Err(BmmErrorV2::NonCanonicalEncoding);
    }
    let mut canonical = Vec::new();
    value
        .consensus_encode(&mut canonical)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    if canonical != raw {
        return Err(BmmErrorV2::NonCanonicalEncoding);
    }
    Ok(value)
}

fn read_bounded_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, BmmErrorV2> {
    let length = read_compact_size(cursor)?;
    if length == 0 || length > MAX_BMM_ENTRY_COMPONENT_BYTES_V2 as u64 {
        return Err(BmmErrorV2::ResourceLimit);
    }
    let mut bytes = vec![0; length as usize];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(bytes)
}

fn write_bounded_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), BmmErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_BMM_ENTRY_COMPONENT_BYTES_V2 {
        return Err(BmmErrorV2::ResourceLimit);
    }
    write_compact_size(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_compact_size(cursor: &mut Cursor<&[u8]>) -> Result<u64, BmmErrorV2> {
    let first = read_u8(cursor)?;
    let value = match first {
        0..=252 => u64::from(first),
        253 => u64::from(read_u16(cursor)?),
        254 => u64::from(read_u32(cursor)?),
        255 => read_u64(cursor)?,
    };
    if (first == 253 && value < 253)
        || (first == 254 && value <= u64::from(u16::MAX))
        || (first == 255 && value <= u64::from(u32::MAX))
    {
        return Err(BmmErrorV2::NonCanonicalEncoding);
    }
    Ok(value)
}

fn write_compact_size(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=252 => output.push(value as u8),
        253..=0xffff => {
            output.push(253);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(254);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(255);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, BmmErrorV2> {
    let mut bytes = [0; 1];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(bytes[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, BmmErrorV2> {
    let mut bytes = [0; 2];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, BmmErrorV2> {
    let mut bytes = [0; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, BmmErrorV2> {
    let mut bytes = [0; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_hash(cursor: &mut Cursor<&[u8]>) -> Result<[u8; 32], BmmErrorV2> {
    let mut bytes = [0; 32];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| BmmErrorV2::NonCanonicalEncoding)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("non-hex fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn state() -> BmmL1StateV2 {
        BmmL1StateV2 {
            block_hash: BlockHash::from_byte_array([1; 32]),
            height: 100,
            block_time: 100_000,
            bits: 0x207f_ffff,
            period_start_height: 0,
            period_start_time: 40_000,
            recent_times: (0..11).map(|index| 94_000 + index * 600).collect(),
        }
    }

    #[test]
    fn bmm_state_and_envelope_codec_are_exact_and_bounded() {
        let proof = BmmProofV2 {
            version: 1,
            previous_state: state(),
            entries: vec![BmmProofEntryV2 {
                coinbase_transaction: vec![1],
                coinbase_merkle_proof: vec![2],
            }],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(BmmProofV2::decode(&encoded).unwrap(), proof);
        assert_eq!(proof.previous_state.median_time_past(), Ok(97_000));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            BmmProofV2::decode(&trailing),
            Err(BmmErrorV2::NonCanonicalEncoding)
        );
        let mut bad_version = encoded;
        bad_version[0] = 2;
        assert_eq!(
            BmmProofV2::decode(&bad_version),
            Err(BmmErrorV2::NonCanonicalEncoding)
        );
        let mut invalid = state();
        invalid.recent_times.pop();
        assert_eq!(invalid.validate(2_016), Err(BmmErrorV2::InvalidState));
    }

    #[test]
    fn actual_cpp_bmm_envelope_and_coinbase_merkle_vector_match() {
        let raw = decode_hex("01010000000000000000000000000000000000000000000000000000000000000064000000a0860100ffff7f2000000000409c00000b306f010088710100e07301003876010090780100e87a0100407d0100987f0100f081010048840100a0860100019402000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020165ffffffff020000000000000000266a24aa21a9ed00000000000000000000000000000000000000000000000000000000000000000000000000000000276a25d1617368186217259457ff73f5980c0896bcbd4a74b9e9e9633072fb1bb2ded34a3df0e9f80000000077000000200100000000000000000000000000000000000000000000000000000000000000c6f502b371e5e73a535646442c0cd2c093a54dbf7d262172d72cfc6bedbe0c27f8880100ffff7f20010000000100000001c6f502b371e5e73a535646442c0cd2c093a54dbf7d262172d72cfc6bedbe0c270101");
        let proof = BmmProofV2::decode(&raw).unwrap();
        assert_eq!(proof.encode().unwrap(), raw);
        assert_eq!(proof.previous_state.height, 100);
        assert_eq!(proof.previous_state.median_time_past(), Ok(97_000));
        assert_eq!(proof.entries.len(), 1);
        let decoded = proof.decode_entries().unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].coinbase.is_coinbase());
        assert_eq!(decoded[0].merkle_block.header.time, 100_600);

        let critical = extract_unique_m8_commitment(&decoded[0].coinbase, 24).unwrap();
        let consensus = BmmConsensusParametersV2 {
            pow_limit: Target::from_compact(CompactTarget::from_consensus(0x207f_ffff)),
            target_timespan: 14 * 24 * 60 * 60,
            target_spacing: 600,
            sidechain_slot: 24,
        };
        let next = execute_bmm_proof_v2(
            &raw,
            &proof.previous_state,
            proof.previous_state.block_hash,
            critical,
            &consensus,
        )
        .unwrap();
        assert_eq!(next.height, 101);
        assert_eq!(next.block_hash, decoded[0].merkle_block.header.block_hash());
        let mut substituted = critical;
        substituted[0] ^= 1;
        assert_eq!(
            execute_bmm_proof_v2(
                &raw,
                &proof.previous_state,
                proof.previous_state.block_hash,
                substituted,
                &consensus,
            ),
            Err(BmmErrorV2::CriticalCommitment)
        );
    }
}
