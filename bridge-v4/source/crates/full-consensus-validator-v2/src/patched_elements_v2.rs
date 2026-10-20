//! Canonical decoder for the patched Elements V18 block wire format.
//!
//! Upstream `rust-elements` does not know the BMM, ECX state, inbox, cursor,
//! or parent-height header extensions used by the deployable node.  Reusing
//! its `Block` decoder would therefore parse a different consensus message.
//! This module is deliberately disjoint from the upstream/V1 decoder.

use crate::bmm_v2::{execute_bmm_proof_v2, BmmConsensusParametersV2, BmmL1StateV2};
use elements::dynafed::Params;
use elements::encode::{Decodable, Encodable};
use elements::hashes::{sha256d, Hash as _};
use elements::Transaction;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use thiserror::Error;

pub type Hash32 = [u8; 32];

pub const DYNAFED_HF_MASK_V2: u32 = 1 << 31;
pub const WITHDRAWAL_BUNDLE_HF_MASK_V2: u32 = 1 << 30;
pub const BMM_PROOF_HF_MASK_V2: u32 = 1 << 20;
pub const EXCHANGE_STATE_HF_MASK_V2: u32 = 1 << 19;
pub const FORCED_INBOX_HF_MASK_V2: u32 = 1 << 18;
pub const DEPOSIT_INBOX_HF_MASK_V2: u32 = 1 << 17;
pub const INBOX_CURSOR_HF_MASK_V2: u32 = 1 << 16;

pub const PATCHED_ELEMENTS_MAX_BLOCK_BYTES_V2: usize = 4_000_000;
pub const PATCHED_ELEMENTS_MAX_BMM_PROOF_BYTES_V2: usize = 1_000_000;
pub const PATCHED_ELEMENTS_MAX_SIGNBLOCK_WITNESS_BYTES_V2: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPatchedElementsBlockFoundationV2 {
    pub block_hash: Hash32,
    pub bmm_critical_hash: Option<Hash32>,
    pub transaction_count: usize,
    pub serialized_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPatchedElementsBmmTransitionV2 {
    pub foundation: VerifiedPatchedElementsBlockFoundationV2,
    pub next_parent_state: BmmL1StateV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchedElementsHeaderV2 {
    /// Exact serialized version, including all presence bits.
    pub wire_version: u32,
    pub previous_block_hash: Hash32,
    pub transaction_merkle_root: Hash32,
    pub withdrawal_bundle_hash: Option<Hash32>,
    pub bmm_proof_hash: Option<Hash32>,
    pub time: u32,
    pub height: u32,
    pub current_dynafed_parameters: Params,
    pub proposed_dynafed_parameters: Params,
    pub exchange_state_root: Option<Hash32>,
    pub forced_inbox_root: Option<Hash32>,
    pub deposit_inbox_root: Option<Hash32>,
    pub ecx_parent_height: Option<u32>,
    pub forced_processed_cursor: Option<u64>,
    pub deposit_processed_cursor: Option<u64>,
    pub source_backlog_oldest_parent_height: Option<u64>,
    pub signblock_witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchedElementsBlockV2 {
    pub header: PatchedElementsHeaderV2,
    pub transactions: Vec<Transaction>,
    pub bmm_proof: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PatchedElementsCodecErrorV2 {
    #[error("patched Elements message exceeds the consensus resource bound")]
    ResourceLimit,
    #[error("only the frozen dynamic-federation V18 wire format is accepted")]
    UnsupportedHeader,
    #[error("patched Elements header presence fields are noncanonical")]
    PresenceMismatch,
    #[error("patched Elements bytes are truncated, malformed, or trailing")]
    NonCanonicalEncoding,
    #[error("patched Elements transaction Merkle root is invalid")]
    TransactionMerkleRoot,
    #[error("patched Elements coinbase ordering or transaction uniqueness is invalid")]
    TransactionStructure,
    #[error("patched Elements BMM body commitment is invalid")]
    BmmProofCommitment,
    #[error("patched Elements BMM parent commitment or proof execution is invalid")]
    BmmConsensus,
}

impl PatchedElementsHeaderV2 {
    pub fn has(&self, mask: u32) -> bool {
        self.wire_version & mask != 0
    }

    pub fn validate_presence(&self) -> Result<(), PatchedElementsCodecErrorV2> {
        if !self.has(DYNAFED_HF_MASK_V2) {
            return Err(PatchedElementsCodecErrorV2::UnsupportedHeader);
        }
        check_presence(
            self.has(WITHDRAWAL_BUNDLE_HF_MASK_V2),
            self.withdrawal_bundle_hash.is_some(),
        )?;
        check_presence(
            self.has(BMM_PROOF_HF_MASK_V2),
            self.bmm_proof_hash.is_some(),
        )?;
        check_presence(
            self.has(EXCHANGE_STATE_HF_MASK_V2),
            self.exchange_state_root.is_some(),
        )?;
        check_presence(
            self.has(FORCED_INBOX_HF_MASK_V2),
            self.forced_inbox_root.is_some(),
        )?;
        check_presence(
            self.has(DEPOSIT_INBOX_HF_MASK_V2),
            self.deposit_inbox_root.is_some(),
        )?;
        let has_parent_height =
            self.has(FORCED_INBOX_HF_MASK_V2) && self.has(DEPOSIT_INBOX_HF_MASK_V2);
        check_presence(has_parent_height, self.ecx_parent_height.is_some())?;
        let cursors = self.has(INBOX_CURSOR_HF_MASK_V2);
        check_presence(cursors, self.forced_processed_cursor.is_some())?;
        check_presence(cursors, self.deposit_processed_cursor.is_some())?;
        check_presence(cursors, self.source_backlog_oldest_parent_height.is_some())?;
        Ok(())
    }

    /// Exact C++ `GetHash()` preimage: header serialization with witness
    /// suppressed while retaining every extension and presence bit.
    pub fn block_hash(&self) -> Result<Hash32, PatchedElementsCodecErrorV2> {
        Ok(sha256d::Hash::hash(&self.encode_without_witness()?).to_byte_array())
    }

    /// Exact C++ `GetBmmCriticalHash()` preimage: the same header with the BMM
    /// proof commitment replaced by zero while its presence bit remains set.
    pub fn bmm_critical_hash(&self) -> Result<Hash32, PatchedElementsCodecErrorV2> {
        if !self.has(BMM_PROOF_HF_MASK_V2) {
            return Err(PatchedElementsCodecErrorV2::PresenceMismatch);
        }
        let mut critical = self.clone();
        critical.bmm_proof_hash = Some([0; 32]);
        Ok(sha256d::Hash::hash(&critical.encode_without_witness()?).to_byte_array())
    }

    pub fn encode_without_witness(&self) -> Result<Vec<u8>, PatchedElementsCodecErrorV2> {
        self.encode(false)
    }

    pub fn encode_with_witness(&self) -> Result<Vec<u8>, PatchedElementsCodecErrorV2> {
        self.encode(true)
    }

    fn encode(&self, include_witness: bool) -> Result<Vec<u8>, PatchedElementsCodecErrorV2> {
        self.validate_presence()?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.wire_version.to_le_bytes());
        output.extend_from_slice(&self.previous_block_hash);
        output.extend_from_slice(&self.transaction_merkle_root);
        extend_optional(&mut output, self.withdrawal_bundle_hash);
        extend_optional(&mut output, self.bmm_proof_hash);
        output.extend_from_slice(&self.time.to_le_bytes());
        output.extend_from_slice(&self.height.to_le_bytes());
        encode_consensus(&self.current_dynafed_parameters, &mut output)?;
        encode_consensus(&self.proposed_dynafed_parameters, &mut output)?;
        extend_optional(&mut output, self.exchange_state_root);
        extend_optional(&mut output, self.forced_inbox_root);
        extend_optional(&mut output, self.deposit_inbox_root);
        if let Some(value) = self.ecx_parent_height {
            output.extend_from_slice(&value.to_le_bytes());
        }
        if let Some(value) = self.forced_processed_cursor {
            output.extend_from_slice(&value.to_le_bytes());
        }
        if let Some(value) = self.deposit_processed_cursor {
            output.extend_from_slice(&value.to_le_bytes());
        }
        if let Some(value) = self.source_backlog_oldest_parent_height {
            output.extend_from_slice(&value.to_le_bytes());
        }
        if include_witness {
            encode_consensus(&self.signblock_witness, &mut output)?;
            if output.len() > PATCHED_ELEMENTS_MAX_SIGNBLOCK_WITNESS_BYTES_V2 {
                return Err(PatchedElementsCodecErrorV2::ResourceLimit);
            }
        }
        Ok(output)
    }
}

impl PatchedElementsBlockV2 {
    pub fn decode(raw: &[u8]) -> Result<Self, PatchedElementsCodecErrorV2> {
        if raw.len() > PATCHED_ELEMENTS_MAX_BLOCK_BYTES_V2 {
            return Err(PatchedElementsCodecErrorV2::ResourceLimit);
        }
        let mut cursor = Cursor::new(raw);
        let header = decode_header(&mut cursor)?;
        let transactions = decode_consensus(&mut cursor)?;
        let bmm_proof = if header.has(BMM_PROOF_HF_MASK_V2) {
            let proof: Vec<u8> = decode_consensus(&mut cursor)?;
            if proof.len() > PATCHED_ELEMENTS_MAX_BMM_PROOF_BYTES_V2 {
                return Err(PatchedElementsCodecErrorV2::ResourceLimit);
            }
            Some(proof)
        } else {
            None
        };
        if cursor.position() != raw.len() as u64 {
            return Err(PatchedElementsCodecErrorV2::NonCanonicalEncoding);
        }
        Ok(Self {
            header,
            transactions,
            bmm_proof,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PatchedElementsCodecErrorV2> {
        check_presence(
            self.header.has(BMM_PROOF_HF_MASK_V2),
            self.bmm_proof.is_some(),
        )?;
        let mut output = self.header.encode_with_witness()?;
        encode_consensus(&self.transactions, &mut output)?;
        if let Some(proof) = &self.bmm_proof {
            if proof.len() > PATCHED_ELEMENTS_MAX_BMM_PROOF_BYTES_V2 {
                return Err(PatchedElementsCodecErrorV2::ResourceLimit);
            }
            encode_consensus(proof, &mut output)?;
        }
        if output.len() > PATCHED_ELEMENTS_MAX_BLOCK_BYTES_V2 {
            return Err(PatchedElementsCodecErrorV2::ResourceLimit);
        }
        Ok(output)
    }
}

/// Decode the exact patched block and validate every context-independent
/// commitment introduced by its wire format. Contextual DynaFed authorization,
/// BMM parent-chain execution, transaction authorization, and UTXO mutation
/// remain mandatory separate relations.
pub fn verify_patched_elements_block_foundation_v2(
    raw: &[u8],
) -> Result<VerifiedPatchedElementsBlockFoundationV2, PatchedElementsCodecErrorV2> {
    let block = PatchedElementsBlockV2::decode(raw)?;
    if block.transactions.is_empty()
        || !block.transactions[0].is_coinbase()
        || block.transactions[1..].iter().any(Transaction::is_coinbase)
    {
        return Err(PatchedElementsCodecErrorV2::TransactionStructure);
    }
    let mut txids = std::collections::HashSet::with_capacity(block.transactions.len());
    let leaves: Vec<Hash32> = block
        .transactions
        .iter()
        .map(|transaction| transaction.txid().to_byte_array())
        .collect();
    if !leaves.iter().copied().all(|txid| txids.insert(txid)) {
        return Err(PatchedElementsCodecErrorV2::TransactionStructure);
    }
    if merkle_root(leaves).ok_or(PatchedElementsCodecErrorV2::TransactionStructure)?
        != block.header.transaction_merkle_root
    {
        return Err(PatchedElementsCodecErrorV2::TransactionMerkleRoot);
    }
    let bmm_critical_hash = if let Some(proof) = &block.bmm_proof {
        let expected = sha256d::Hash::hash(proof).to_byte_array();
        if block.header.bmm_proof_hash != Some(expected) {
            return Err(PatchedElementsCodecErrorV2::BmmProofCommitment);
        }
        Some(block.header.bmm_critical_hash()?)
    } else {
        None
    };
    Ok(VerifiedPatchedElementsBlockFoundationV2 {
        block_hash: block.header.block_hash()?,
        bmm_critical_hash,
        transaction_count: block.transactions.len(),
        serialized_bytes: raw.len(),
    })
}

/// Compose the patched block foundation with the exact BMM proof execution.
/// This authenticates the sidechain coinbase's unique L1-parent commitment,
/// the header critical hash, and the complete prior-to-successor parent state.
pub fn verify_patched_elements_bmm_transition_v2(
    raw: &[u8],
    expected_previous_parent_state: &BmmL1StateV2,
    consensus: &BmmConsensusParametersV2,
) -> Result<VerifiedPatchedElementsBmmTransitionV2, PatchedElementsCodecErrorV2> {
    let foundation = verify_patched_elements_block_foundation_v2(raw)?;
    let block = PatchedElementsBlockV2::decode(raw)?;
    let proof = block
        .bmm_proof
        .as_deref()
        .ok_or(PatchedElementsCodecErrorV2::BmmConsensus)?;
    let critical_hash = foundation
        .bmm_critical_hash
        .ok_or(PatchedElementsCodecErrorV2::BmmConsensus)?;
    let parent_hash = extract_unique_sidechain_parent_hash(
        block
            .transactions
            .first()
            .ok_or(PatchedElementsCodecErrorV2::TransactionStructure)?,
    )?;
    let next_parent_state = execute_bmm_proof_v2(
        proof,
        expected_previous_parent_state,
        elements_hash_to_bitcoin(parent_hash),
        critical_hash,
        consensus,
    )
    .map_err(|_| PatchedElementsCodecErrorV2::BmmConsensus)?;
    Ok(VerifiedPatchedElementsBmmTransitionV2 {
        foundation,
        next_parent_state,
    })
}

fn elements_hash_to_bitcoin(bytes: Hash32) -> bitcoin::BlockHash {
    bitcoin::BlockHash::from_byte_array(bytes)
}

fn extract_unique_sidechain_parent_hash(
    coinbase: &Transaction,
) -> Result<Hash32, PatchedElementsCodecErrorV2> {
    use elements::opcodes::all::OP_RETURN;
    use elements::script::Instruction;
    let mut found = None;
    for output in &coinbase.output {
        let mut instructions = output.script_pubkey.instructions();
        if !matches!(instructions.next(), Some(Ok(Instruction::Op(OP_RETURN)))) {
            continue;
        }
        let Some(Ok(Instruction::PushBytes(bytes))) = instructions.next() else {
            continue;
        };
        if bytes.len() != 32 || instructions.next().is_some() {
            continue;
        }
        if found.is_some() {
            return Err(PatchedElementsCodecErrorV2::BmmConsensus);
        }
        let mut parent = [0; 32];
        parent.copy_from_slice(bytes);
        found = Some(parent);
    }
    found.ok_or(PatchedElementsCodecErrorV2::BmmConsensus)
}

fn merkle_root(mut nodes: Vec<Hash32>) -> Option<Hash32> {
    if nodes.is_empty() {
        return None;
    }
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            nodes.push(*nodes.last()?);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| {
                let mut preimage = [0; 64];
                preimage[..32].copy_from_slice(&pair[0]);
                preimage[32..].copy_from_slice(&pair[1]);
                sha256d::Hash::hash(&preimage).to_byte_array()
            })
            .collect();
    }
    nodes.pop()
}

fn decode_header(
    cursor: &mut Cursor<&[u8]>,
) -> Result<PatchedElementsHeaderV2, PatchedElementsCodecErrorV2> {
    let wire_version = read_u32(cursor)?;
    if wire_version & DYNAFED_HF_MASK_V2 == 0 {
        return Err(PatchedElementsCodecErrorV2::UnsupportedHeader);
    }
    let previous_block_hash = read_hash(cursor)?;
    let transaction_merkle_root = read_hash(cursor)?;
    let withdrawal_bundle_hash =
        read_conditional_hash(cursor, wire_version & WITHDRAWAL_BUNDLE_HF_MASK_V2 != 0)?;
    let bmm_proof_hash = read_conditional_hash(cursor, wire_version & BMM_PROOF_HF_MASK_V2 != 0)?;
    let time = read_u32(cursor)?;
    let height = read_u32(cursor)?;
    let current_dynafed_parameters = decode_consensus(cursor)?;
    let proposed_dynafed_parameters = decode_consensus(cursor)?;
    let exchange_state_root =
        read_conditional_hash(cursor, wire_version & EXCHANGE_STATE_HF_MASK_V2 != 0)?;
    let forced_inbox_root =
        read_conditional_hash(cursor, wire_version & FORCED_INBOX_HF_MASK_V2 != 0)?;
    let deposit_inbox_root =
        read_conditional_hash(cursor, wire_version & DEPOSIT_INBOX_HF_MASK_V2 != 0)?;
    let ecx_parent_height = if wire_version & FORCED_INBOX_HF_MASK_V2 != 0
        && wire_version & DEPOSIT_INBOX_HF_MASK_V2 != 0
    {
        Some(read_u32(cursor)?)
    } else {
        None
    };
    let has_cursors = wire_version & INBOX_CURSOR_HF_MASK_V2 != 0;
    let forced_processed_cursor = has_cursors.then(|| read_u64(cursor)).transpose()?;
    let deposit_processed_cursor = has_cursors.then(|| read_u64(cursor)).transpose()?;
    let source_backlog_oldest_parent_height = has_cursors.then(|| read_u64(cursor)).transpose()?;
    let signblock_witness: Vec<Vec<u8>> = decode_consensus(cursor)?;
    let header = PatchedElementsHeaderV2 {
        wire_version,
        previous_block_hash,
        transaction_merkle_root,
        withdrawal_bundle_hash,
        bmm_proof_hash,
        time,
        height,
        current_dynafed_parameters,
        proposed_dynafed_parameters,
        exchange_state_root,
        forced_inbox_root,
        deposit_inbox_root,
        ecx_parent_height,
        forced_processed_cursor,
        deposit_processed_cursor,
        source_backlog_oldest_parent_height,
        signblock_witness,
    };
    header.validate_presence()?;
    Ok(header)
}

fn check_presence(expected: bool, present: bool) -> Result<(), PatchedElementsCodecErrorV2> {
    if expected == present {
        Ok(())
    } else {
        Err(PatchedElementsCodecErrorV2::PresenceMismatch)
    }
}

fn extend_optional(output: &mut Vec<u8>, value: Option<Hash32>) {
    if let Some(value) = value {
        output.extend_from_slice(&value);
    }
}

fn read_conditional_hash(
    cursor: &mut Cursor<&[u8]>,
    present: bool,
) -> Result<Option<Hash32>, PatchedElementsCodecErrorV2> {
    if present {
        Ok(Some(read_hash(cursor)?))
    } else {
        Ok(None)
    }
}

fn read_hash(cursor: &mut Cursor<&[u8]>) -> Result<Hash32, PatchedElementsCodecErrorV2> {
    let mut value = [0; 32];
    cursor
        .read_exact(&mut value)
        .map_err(|_| PatchedElementsCodecErrorV2::NonCanonicalEncoding)?;
    Ok(value)
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, PatchedElementsCodecErrorV2> {
    let mut bytes = [0; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| PatchedElementsCodecErrorV2::NonCanonicalEncoding)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, PatchedElementsCodecErrorV2> {
    let mut bytes = [0; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| PatchedElementsCodecErrorV2::NonCanonicalEncoding)?;
    Ok(u64::from_le_bytes(bytes))
}

fn decode_consensus<T: Decodable>(
    cursor: &mut Cursor<&[u8]>,
) -> Result<T, PatchedElementsCodecErrorV2> {
    T::consensus_decode(cursor).map_err(|_| PatchedElementsCodecErrorV2::NonCanonicalEncoding)
}

fn encode_consensus<T: Encodable>(
    value: &T,
    output: &mut Vec<u8>,
) -> Result<(), PatchedElementsCodecErrorV2> {
    value
        .consensus_encode(output)
        .map(|_| ())
        .map_err(|_| PatchedElementsCodecErrorV2::NonCanonicalEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::sha256;
    use elements::{LockTime, Script, TxIn, TxOut};
    use std::str::FromStr;

    fn complete_header() -> PatchedElementsHeaderV2 {
        PatchedElementsHeaderV2 {
            wire_version: DYNAFED_HF_MASK_V2
                | WITHDRAWAL_BUNDLE_HF_MASK_V2
                | BMM_PROOF_HF_MASK_V2
                | EXCHANGE_STATE_HF_MASK_V2
                | FORCED_INBOX_HF_MASK_V2
                | DEPOSIT_INBOX_HF_MASK_V2
                | INBOX_CURSOR_HF_MASK_V2
                | 7,
            previous_block_hash: [1; 32],
            transaction_merkle_root: [2; 32],
            withdrawal_bundle_hash: Some([3; 32]),
            bmm_proof_hash: Some([4; 32]),
            time: 1_700_000_000,
            height: 42,
            current_dynafed_parameters: Params::Null,
            proposed_dynafed_parameters: Params::Null,
            exchange_state_root: Some([5; 32]),
            forced_inbox_root: Some([6; 32]),
            deposit_inbox_root: Some([7; 32]),
            ecx_parent_height: Some(101),
            forced_processed_cursor: Some(11),
            deposit_processed_cursor: Some(12),
            source_backlog_oldest_parent_height: Some(99),
            signblock_witness: vec![vec![8; 64], vec![9; 3]],
        }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                asset: Asset::Null,
                value: Value::Null,
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x6a]),
                witness: Default::default(),
            }],
        }
    }

    fn coinbase_with_parent(parent: [u8; 32]) -> Transaction {
        let mut transaction = coinbase();
        let mut script = vec![0x6a, 0x20];
        script.extend_from_slice(&parent);
        transaction.output.push(TxOut {
            asset: Asset::Null,
            value: Value::Null,
            nonce: Nonce::Null,
            script_pubkey: Script::from(script),
            witness: Default::default(),
        });
        transaction
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
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

    #[test]
    fn patched_v18_block_roundtrip_and_hash_domains_are_exact() {
        let block = PatchedElementsBlockV2 {
            header: complete_header(),
            transactions: vec![],
            bmm_proof: Some(vec![10, 11, 12]),
        };
        let encoded = block.encode().unwrap();
        assert_eq!(PatchedElementsBlockV2::decode(&encoded).unwrap(), block);
        assert_eq!(block.header.encode_with_witness().unwrap().len(), 336);
        assert_eq!(block.header.encode_without_witness().unwrap().len(), 266);
        assert_ne!(
            block.header.block_hash().unwrap(),
            block.header.bmm_critical_hash().unwrap()
        );

        let mut critical = block.header.clone();
        critical.bmm_proof_hash = Some([0; 32]);
        assert_eq!(
            block.header.bmm_critical_hash().unwrap(),
            sha256d::Hash::hash(&critical.encode_without_witness().unwrap()).to_byte_array()
        );
    }

    #[test]
    fn actual_cpp_v18_serializer_vector_matches_byte_for_byte() {
        // Generated by the actual patched CBlock serializer and independently
        // checked here. This is not an upstream rust-elements vector.
        let wire = decode_hex(concat!(
            "07001fc0",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "00f153652a000000010151e8030000",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "650000000b000000000000000c000000000000006300000000000000",
            "0240080808080808080808080808080808080808080808080808080808080808",
            "0808080808080808080808080808080808080808080808080808080808080808",
            "08080309090900030a0b0c"
        ));
        let decoded = PatchedElementsBlockV2::decode(&wire).unwrap();
        assert_eq!(decoded.encode().unwrap(), wire);
        assert_eq!(
            decoded.header.current_dynafed_parameters,
            Params::Compact {
                signblockscript: Script::from(vec![0x51]),
                signblock_witness_limit: 1_000,
                elided_root: sha256::Midstate::from_byte_array([0xaa; 32]),
            }
        );
        assert_eq!(decoded.header.proposed_dynafed_parameters, Params::Null);
        assert_eq!(decoded.bmm_proof, Some(vec![10, 11, 12]));
        assert_eq!(
            decoded.header.block_hash().unwrap(),
            sha256d::Hash::from_str(
                "8f78c0bc49ab9b5e9aec8b5afe2b60a177930ce3e608b3d8d52685774e271aa3"
            )
            .unwrap()
            .to_byte_array()
        );
        assert_eq!(
            decoded.header.bmm_critical_hash().unwrap(),
            sha256d::Hash::from_str(
                "df374c9af9779d2188865aa1ff378aad8ad1e8ba5363fb325e6c49e1f9419687"
            )
            .unwrap()
            .to_byte_array()
        );
    }

    #[test]
    fn patched_v18_codec_rejects_presence_trailing_and_resource_mutations() {
        let mut header = complete_header();
        header.bmm_proof_hash = None;
        assert_eq!(
            header.encode_with_witness(),
            Err(PatchedElementsCodecErrorV2::PresenceMismatch)
        );

        let block = PatchedElementsBlockV2 {
            header: complete_header(),
            transactions: vec![],
            bmm_proof: Some(vec![]),
        };
        let mut trailing = block.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            PatchedElementsBlockV2::decode(&trailing),
            Err(PatchedElementsCodecErrorV2::NonCanonicalEncoding)
        );

        let mut unsupported = block.encode().unwrap();
        unsupported[3] &= 0x7f;
        assert_eq!(
            PatchedElementsBlockV2::decode(&unsupported),
            Err(PatchedElementsCodecErrorV2::UnsupportedHeader)
        );

        assert_eq!(
            PatchedElementsBlockV2::decode(&vec![0; PATCHED_ELEMENTS_MAX_BLOCK_BYTES_V2 + 1]),
            Err(PatchedElementsCodecErrorV2::ResourceLimit)
        );
    }

    #[test]
    fn patched_v18_foundation_binds_merkle_coinbase_and_bmm_body() {
        let transaction = coinbase();
        let proof = vec![10, 11, 12];
        let mut header = complete_header();
        header.transaction_merkle_root = transaction.txid().to_byte_array();
        header.bmm_proof_hash = Some(sha256d::Hash::hash(&proof).to_byte_array());
        let block = PatchedElementsBlockV2 {
            header,
            transactions: vec![transaction],
            bmm_proof: Some(proof),
        };
        let raw = block.encode().unwrap();
        let verified = verify_patched_elements_block_foundation_v2(&raw).unwrap();
        assert_eq!(verified.block_hash, block.header.block_hash().unwrap());
        assert_eq!(verified.transaction_count, 1);

        let mut wrong_body = block.clone();
        wrong_body.bmm_proof.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            verify_patched_elements_block_foundation_v2(&wrong_body.encode().unwrap()),
            Err(PatchedElementsCodecErrorV2::BmmProofCommitment)
        );
        let mut wrong_merkle = block.clone();
        wrong_merkle.header.transaction_merkle_root[0] ^= 1;
        assert_eq!(
            verify_patched_elements_block_foundation_v2(&wrong_merkle.encode().unwrap()),
            Err(PatchedElementsCodecErrorV2::TransactionMerkleRoot)
        );
        let mut duplicate = block;
        duplicate
            .transactions
            .push(duplicate.transactions[0].clone());
        assert_eq!(
            verify_patched_elements_block_foundation_v2(&duplicate.encode().unwrap()),
            Err(PatchedElementsCodecErrorV2::TransactionStructure)
        );
    }

    #[test]
    fn patched_v18_block_executes_bmm_parent_transition_atomically() {
        use crate::bmm_v2::*;
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::serialize;
        use bitcoin::hash_types::TxMerkleNode as BitcoinMerkleNode;
        use bitcoin::merkle_tree::{MerkleBlock, PartialMerkleTree};
        use bitcoin::pow::{CompactTarget, Target};
        use bitcoin::{
            absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn as BitcoinTxIn,
            TxOut as BitcoinTxOut, Witness,
        };

        let previous = BmmL1StateV2 {
            block_hash: bitcoin::BlockHash::from_byte_array([1; 32]),
            height: 100,
            block_time: 100_000,
            bits: 0x207f_ffff,
            period_start_height: 0,
            period_start_time: 40_000,
            recent_times: (0..11).map(|index| 94_000 + index * 600).collect(),
        };
        let sidechain_coinbase = coinbase_with_parent(previous.block_hash.to_byte_array());
        let mut sidechain_header = complete_header();
        sidechain_header.withdrawal_bundle_hash = Some([3; 32]);
        sidechain_header.transaction_merkle_root = sidechain_coinbase.txid().to_byte_array();
        sidechain_header.bmm_proof_hash = Some([0; 32]);
        let critical = sidechain_header.bmm_critical_hash().unwrap();

        let mut m8 = vec![0xd1, 0x61, 0x73, 0x68, 24];
        let mut display_critical = critical;
        display_critical.reverse();
        m8.extend_from_slice(&display_critical);
        let bitcoin_coinbase = bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![BitcoinTxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::script::Builder::new().push_int(101).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![BitcoinTxOut {
                value: Amount::ZERO,
                script_pubkey: bitcoin::script::Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                    .push_slice(bitcoin::script::PushBytesBuf::try_from(m8).unwrap())
                    .into_script(),
            }],
        };
        let txid = bitcoin_coinbase.compute_txid();
        let mut bitcoin_header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: previous.block_hash,
            merkle_root: BitcoinMerkleNode::from_byte_array(txid.to_byte_array()),
            time: 100_600,
            bits: CompactTarget::from_consensus(previous.bits),
            nonce: 0,
        };
        let target = Target::from_compact(bitcoin_header.bits);
        while bitcoin_header.validate_pow(target).is_err() {
            bitcoin_header.nonce = bitcoin_header.nonce.wrapping_add(1);
        }
        let merkle_block = MerkleBlock {
            header: bitcoin_header,
            txn: PartialMerkleTree::from_txids(&[txid], &[true]),
        };
        let proof = BmmProofV2 {
            version: 1,
            previous_state: previous.clone(),
            entries: vec![BmmProofEntryV2 {
                coinbase_transaction: serialize(&bitcoin_coinbase),
                coinbase_merkle_proof: serialize(&merkle_block),
            }],
        }
        .encode()
        .unwrap();
        sidechain_header.bmm_proof_hash = Some(sha256d::Hash::hash(&proof).to_byte_array());
        let block = PatchedElementsBlockV2 {
            header: sidechain_header,
            transactions: vec![sidechain_coinbase],
            bmm_proof: Some(proof),
        };
        let consensus = BmmConsensusParametersV2 {
            pow_limit: target,
            target_timespan: 14 * 24 * 60 * 60,
            target_spacing: 600,
            sidechain_slot: 24,
        };
        let verified = verify_patched_elements_bmm_transition_v2(
            &block.encode().unwrap(),
            &previous,
            &consensus,
        )
        .unwrap();
        assert_eq!(verified.next_parent_state.height, 101);
        assert_eq!(
            verified.next_parent_state.block_hash,
            bitcoin_header.block_hash()
        );

        let mut wrong_previous = previous;
        wrong_previous.height -= 1;
        assert_eq!(
            verify_patched_elements_bmm_transition_v2(
                &block.encode().unwrap(),
                &wrong_previous,
                &consensus,
            ),
            Err(PatchedElementsCodecErrorV2::BmmConsensus)
        );
    }
}
