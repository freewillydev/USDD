//! Bitcoin Core-compatible Script parsing and numeric primitives.
//!
//! This module is not yet a complete interpreter. It is kept behind the
//! mandatory `BitcoinScriptVerifierV2` boundary until opcode evaluation,
//! sighashes, ECDSA/Schnorr and the frozen differential corpus all pass.

use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash as _};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{
    ecdsa, schnorr, Message, PublicKey, Secp256k1, VerifyOnly, XOnlyPublicKey,
};
use bitcoin::sighash::{
    Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighash, TapSighashType,
};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{Amount, Script, ScriptBuf, Transaction};
use std::cell::Cell;
use thiserror::Error;

pub const MAX_SCRIPT_SIZE_V2: usize = 10_000;
pub const MAX_SCRIPT_ELEMENT_SIZE_V2: usize = 520;
pub const MAX_OPS_PER_SCRIPT_V2: u32 = 201;
pub const MAX_STACK_ITEMS_V2: usize = 1_000;
pub const LOCKTIME_THRESHOLD_V2: u32 = 500_000_000;
pub const SCRIPT_VERIFY_P2SH_V2: u32 = 1 << 0;
pub const SCRIPT_VERIFY_STRICTENC_V2: u32 = 1 << 1;
pub const SCRIPT_VERIFY_DERSIG_V2: u32 = 1 << 2;
pub const SCRIPT_VERIFY_LOW_S_V2: u32 = 1 << 3;
pub const SCRIPT_VERIFY_NULLDUMMY_V2: u32 = 1 << 4;
pub const SCRIPT_VERIFY_SIGPUSHONLY_V2: u32 = 1 << 5;
pub const SCRIPT_VERIFY_MINIMALDATA_V2: u32 = 1 << 6;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS_V2: u32 = 1 << 7;
pub const SCRIPT_VERIFY_CLEANSTACK_V2: u32 = 1 << 8;
pub const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2: u32 = 1 << 9;
pub const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2: u32 = 1 << 10;
pub const SCRIPT_VERIFY_WITNESS_V2: u32 = 1 << 11;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_V2: u32 = 1 << 12;
pub const SCRIPT_VERIFY_MINIMALIF_V2: u32 = 1 << 13;
pub const SCRIPT_VERIFY_NULLFAIL_V2: u32 = 1 << 14;
pub const SCRIPT_VERIFY_WITNESS_PUBKEYTYPE_V2: u32 = 1 << 15;
pub const SCRIPT_VERIFY_CONST_SCRIPTCODE_V2: u32 = 1 << 16;
pub const SCRIPT_VERIFY_TAPROOT_V2: u32 = 1 << 17;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScriptLockContextV2 {
    /// Program-selected Alpha dialect; never serialized as a witness rule.
    /// Bitcoin and Elements callers leave this false.
    pub alpha_drivechain: bool,
    pub transaction_version: u32,
    pub transaction_lock_time: u32,
    pub input_sequence: u32,
    pub check_lock_time_verify: bool,
    pub check_sequence_verify: bool,
    pub null_fail: bool,
    pub null_dummy: bool,
    pub discourage_upgradable_nops: bool,
    pub const_script_code: bool,
    pub witness_v0: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LegacyScriptFlagsV2 {
    pub require_minimal_push: bool,
    pub require_minimal_if: bool,
    pub verify_p2sh: bool,
    pub clean_stack: bool,
    pub verify_witness: bool,
    pub verify_taproot: bool,
    pub witness_pubkey_type: bool,
    pub discourage_upgradable_witness_program: bool,
    pub strict_der: bool,
    pub strict_encoding: bool,
    pub low_s: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WitnessV0FlagsV2 {
    pub require_minimal_if: bool,
    pub require_compressed_public_key: bool,
    pub strict_der: bool,
    pub strict_encoding: bool,
    pub low_s: bool,
}

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedOpcodeV2 {
    pub opcode: u8,
    pub pushed: Option<Vec<u8>>,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ScriptPrimitiveErrorV2 {
    #[error("script exceeds the consensus size limit")]
    ScriptSize,
    #[error("pushdata length or payload is truncated")]
    TruncatedPush,
    #[error("pushed stack element exceeds the consensus size limit")]
    ElementSize,
    #[error("script exceeds the operation-count limit")]
    OperationCount,
    #[error("push operation is not minimally encoded")]
    NonMinimalPush,
    #[error("script number is oversized or non-minimal")]
    ScriptNumber,
    #[error("disabled, reserved, or immediately failing opcode")]
    BadOpcode,
    #[error("script stack or alternate stack is invalid")]
    InvalidStack,
    #[error("conditional execution structure or argument is invalid")]
    InvalidConditional,
    #[error("VERIFY operation evaluated false")]
    Verify,
    #[error("absolute or relative script locktime check failed")]
    LockTime,
    #[error("signature check or signature encoding failed")]
    Signature,
}

pub trait ScriptSignatureCheckerV2 {
    /// Elements-only pre-tapscript operation. Bitcoin checkers must reject it.
    fn check_signature_from_stack(
        &self, _signature: &[u8], _data: &[u8], _public_key: &[u8],
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        Err(ScriptPrimitiveErrorV2::BadOpcode)
    }

    fn check_ecdsa_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        script_code: &[u8],
        code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2>;

    fn check_schnorr_signature(
        &self,
        _signature_with_hash_type: &[u8],
        _public_key: &[u8],
        _code_separator_position: u32,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        Err(ScriptPrimitiveErrorV2::Signature)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptDialectV2 {
    Legacy,
    TapScript,
}

struct RejectSignaturesV2;

impl ScriptSignatureCheckerV2 for RejectSignaturesV2 {
    fn check_ecdsa_signature(
        &self,
        _signature_with_hash_type: &[u8],
        _public_key: &[u8],
        _script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        Err(ScriptPrimitiveErrorV2::Signature)
    }
}

pub struct LegacyEcdsaCheckerV2<'a> {
    pub transaction: &'a Transaction,
    pub input_index: usize,
    pub strict_der: bool,
    pub strict_encoding: bool,
    pub low_s: bool,
    pub const_script_code: bool,
    secp: Secp256k1<VerifyOnly>,
}

impl<'a> LegacyEcdsaCheckerV2<'a> {
    pub fn new(
        transaction: &'a Transaction,
        input_index: usize,
        strict_der: bool,
        strict_encoding: bool,
        low_s: bool,
        const_script_code: bool,
    ) -> Self {
        Self {
            transaction,
            input_index,
            strict_der,
            strict_encoding,
            low_s,
            const_script_code,
            secp: Secp256k1::verification_only(),
        }
    }
}

pub(crate) fn remove_exact_signature_pushes_v2(
    script_code: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ScriptPrimitiveErrorV2> {
    let signature = PushBytesBuf::try_from(signature.to_vec())
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
    let encoded_push = Builder::new().push_slice(signature).into_script();
    let operations = parse_script_v2(script_code, false)?;
    let mut cleaned = Vec::with_capacity(script_code.len());
    for operation in operations {
        let bytes = &script_code[operation.start..operation.end];
        if bytes != encoded_push.as_bytes() {
            cleaned.extend_from_slice(bytes);
        }
    }
    Ok(cleaned)
}

pub(crate) fn remove_code_separators_v2(
    script_code: &[u8],
) -> Result<Vec<u8>, ScriptPrimitiveErrorV2> {
    let operations = parse_script_v2(script_code, false)?;
    let mut cleaned = Vec::with_capacity(script_code.len());
    for operation in operations {
        if operation.opcode != 0xab {
            cleaned.extend_from_slice(&script_code[operation.start..operation.end]);
        }
    }
    Ok(cleaned)
}

pub(crate) fn valid_defined_sighash_type_v2(hash_type: u8) -> bool {
    matches!(hash_type & 0x7f, 1..=3)
}

pub(crate) fn valid_strict_der_signature_encoding_v2(signature: &[u8]) -> bool {
    if !(9..=73).contains(&signature.len())
        || signature[0] != 0x30
        || usize::from(signature[1]) != signature.len() - 3
        || signature[2] != 0x02
    {
        return false;
    }
    let r_length = usize::from(signature[3]);
    if r_length == 0
        || 5 + r_length >= signature.len()
        || signature[4] & 0x80 != 0
        || (r_length > 1 && signature[4] == 0 && signature[5] & 0x80 == 0)
        || signature[r_length + 4] != 0x02
    {
        return false;
    }
    let s_length = usize::from(signature[r_length + 5]);
    if s_length == 0
        || r_length + s_length + 7 != signature.len()
        || signature[r_length + 6] & 0x80 != 0
        || (s_length > 1 && signature[r_length + 6] == 0 && signature[r_length + 7] & 0x80 == 0)
    {
        return false;
    }
    true
}

impl ScriptSignatureCheckerV2 for LegacyEcdsaCheckerV2<'_> {
    fn check_ecdsa_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        if signature_with_hash_type.is_empty() {
            return Ok(false);
        }
        let (&hash_type, der) = signature_with_hash_type
            .split_last()
            .ok_or(ScriptPrimitiveErrorV2::Signature)?;
        if self.strict_der && !valid_strict_der_signature_encoding_v2(signature_with_hash_type) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if self.strict_encoding && !valid_defined_sighash_type_v2(hash_type) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let signature_result = if self.strict_der {
            ecdsa::Signature::from_der(der)
        } else {
            ecdsa::Signature::from_der_lax(der)
        };
        let signature = match signature_result {
            Ok(signature) => signature,
            Err(_) if self.strict_der => return Err(ScriptPrimitiveErrorV2::Signature),
            Err(_) => return Ok(false),
        };
        let mut normalized_signature = signature;
        normalized_signature.normalize_s();
        if self.low_s && normalized_signature != signature {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if self.strict_encoding
            && !matches!(public_key, [0x02 | 0x03, ..] if public_key.len() == 33)
            && !matches!(public_key, [0x04, ..] if public_key.len() == 65)
        {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let public_key = match PublicKey::from_slice(public_key) {
            Ok(public_key) => public_key,
            Err(_) if self.strict_encoding => return Err(ScriptPrimitiveErrorV2::Signature),
            Err(_) => return Ok(false),
        };
        let without_signature =
            remove_exact_signature_pushes_v2(script_code, signature_with_hash_type)?;
        if self.const_script_code && without_signature.len() != script_code.len() {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let cleaned_script = remove_code_separators_v2(&without_signature)?;
        let cleaned_script = bitcoin::ScriptBuf::from_bytes(cleaned_script);
        // Preserve the historical SIGHASH_SINGLE bug: when there is no
        // corresponding output Core signs uint256::ONE instead of failing.
        let digest = if hash_type & 0x1f == 3 && self.input_index >= self.transaction.output.len() {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        } else {
            SighashCache::new(self.transaction)
                .legacy_signature_hash(self.input_index, &cleaned_script, u32::from(hash_type))
                .map_err(|_| ScriptPrimitiveErrorV2::Signature)?
                .to_byte_array()
        };
        let message = Message::from_digest(digest);
        Ok(self
            .secp
            .verify_ecdsa(&message, &normalized_signature, &public_key)
            .is_ok())
    }
}

pub struct WitnessV0EcdsaCheckerV2<'a> {
    pub transaction: &'a Transaction,
    pub input_index: usize,
    pub spent_value: Amount,
    pub strict_der: bool,
    pub strict_encoding: bool,
    pub low_s: bool,
    pub require_compressed_public_key: bool,
    secp: Secp256k1<VerifyOnly>,
}

impl<'a> WitnessV0EcdsaCheckerV2<'a> {
    pub fn new(
        transaction: &'a Transaction,
        input_index: usize,
        spent_value: Amount,
        require_compressed_public_key: bool,
        strict_der: bool,
        strict_encoding: bool,
        low_s: bool,
    ) -> Self {
        Self {
            transaction,
            input_index,
            spent_value,
            strict_der,
            strict_encoding,
            low_s,
            require_compressed_public_key,
            secp: Secp256k1::verification_only(),
        }
    }
}

impl ScriptSignatureCheckerV2 for WitnessV0EcdsaCheckerV2<'_> {
    fn check_ecdsa_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        if signature_with_hash_type.is_empty() {
            return Ok(false);
        }
        let (&hash_type, der) = signature_with_hash_type
            .split_last()
            .ok_or(ScriptPrimitiveErrorV2::Signature)?;
        if self.strict_encoding && !valid_defined_sighash_type_v2(hash_type) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let signature = if self.strict_der {
            ecdsa::Signature::from_der(der)
        } else {
            ecdsa::Signature::from_der_lax(der)
        }
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let mut normalized_signature = signature;
        normalized_signature.normalize_s();
        if self.low_s && normalized_signature != signature {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if self.require_compressed_public_key
            && !(public_key.len() == 33 && matches!(public_key.first(), Some(0x02 | 0x03)))
        {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let public_key =
            PublicKey::from_slice(public_key).map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        // rust-bitcoin intentionally normalizes non-standard ECDSA sighash
        // bytes in `EcdsaSighashType`. Core uses the normalized value for the
        // ALL/NONE/SINGLE and ANYONECANPAY branches, but commits the original
        // raw byte as the final u32 in the BIP143 preimage. Preserve both
        // properties by encoding with normalized branch semantics and then
        // restoring the raw final word before hashing.
        let mut signing_data = Vec::new();
        SighashCache::new(self.transaction)
            .segwit_v0_encode_signing_data_to(
                &mut signing_data,
                self.input_index,
                Script::from_bytes(script_code),
                self.spent_value,
                EcdsaSighashType::from_consensus(u32::from(hash_type)),
            )
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let raw_hash_type = u32::from(hash_type).to_le_bytes();
        let final_word = signing_data
            .len()
            .checked_sub(raw_hash_type.len())
            .ok_or(ScriptPrimitiveErrorV2::Signature)?;
        signing_data[final_word..].copy_from_slice(&raw_hash_type);
        let message = Message::from_digest(sha256d::Hash::hash(&signing_data).to_byte_array());
        Ok(self
            .secp
            .verify_ecdsa(&message, &normalized_signature, &public_key)
            .is_ok())
    }
}

pub struct TapscriptSchnorrCheckerV2<'a> {
    transaction: &'a Transaction,
    input_index: usize,
    spent_outputs: &'a [bitcoin::TxOut],
    leaf_hash: TapLeafHash,
    annex: Option<&'a [u8]>,
    remaining_signature_budget: Cell<i64>,
}

impl<'a> TapscriptSchnorrCheckerV2<'a> {
    fn new(
        transaction: &'a Transaction,
        input_index: usize,
        spent_outputs: &'a [bitcoin::TxOut],
        leaf_hash: TapLeafHash,
        annex: Option<&'a [u8]>,
        signature_budget: usize,
    ) -> Result<Self, ScriptPrimitiveErrorV2> {
        Ok(Self {
            transaction,
            input_index,
            spent_outputs,
            leaf_hash,
            annex,
            remaining_signature_budget: Cell::new(
                i64::try_from(signature_budget)
                    .map_err(|_| ScriptPrimitiveErrorV2::OperationCount)?,
            ),
        })
    }
}

impl ScriptSignatureCheckerV2 for TapscriptSchnorrCheckerV2<'_> {
    fn check_ecdsa_signature(
        &self,
        _signature_with_hash_type: &[u8],
        _public_key: &[u8],
        _script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        Err(ScriptPrimitiveErrorV2::Signature)
    }

    fn check_schnorr_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        code_separator_position: u32,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        // BIP342's ordering is consensus critical: an empty public key fails
        // even when the signature is empty. Future non-32-byte public-key
        // types retain the signature's empty/non-empty truth value.
        if public_key.is_empty() {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if signature_with_hash_type.is_empty() {
            return Ok(false);
        }
        let remaining = self
            .remaining_signature_budget
            .get()
            .checked_sub(50)
            .ok_or(ScriptPrimitiveErrorV2::OperationCount)?;
        if remaining < 0 {
            return Err(ScriptPrimitiveErrorV2::OperationCount);
        }
        self.remaining_signature_budget.set(remaining);
        if public_key.len() != 32 {
            return Ok(true);
        }
        let (signature_bytes, sighash_type) = match signature_with_hash_type {
            bytes if bytes.len() == 64 => (bytes, TapSighashType::Default),
            bytes if bytes.len() == 65 => {
                let (&raw_type, signature) = bytes
                    .split_last()
                    .ok_or(ScriptPrimitiveErrorV2::Signature)?;
                let sighash_type = TapSighashType::from_consensus_u8(raw_type)
                    .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
                if sighash_type == TapSighashType::Default {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }
                (signature, sighash_type)
            }
            _ => return Err(ScriptPrimitiveErrorV2::Signature),
        };
        let signature = schnorr::Signature::from_slice(signature_bytes)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let public_key = XOnlyPublicKey::from_slice(public_key)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let prevouts = Prevouts::All(self.spent_outputs);
        let annex = self
            .annex
            .map(Annex::new)
            .transpose()
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let mut engine = TapSighash::engine();
        SighashCache::new(self.transaction)
            .taproot_encode_signing_data_to(
                &mut engine,
                self.input_index,
                &prevouts,
                annex,
                Some((self.leaf_hash, code_separator_position)),
                sighash_type,
            )
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let message = Message::from_digest(TapSighash::from_engine(engine).to_byte_array());
        Ok(Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &public_key)
            .is_ok())
    }
}

fn read_push_length(
    script: &[u8],
    cursor: &mut usize,
    opcode: u8,
) -> Result<Option<usize>, ScriptPrimitiveErrorV2> {
    let length = match opcode {
        OP_0 => Some(0),
        0x01..=0x4b => Some(usize::from(opcode)),
        OP_PUSHDATA1 => {
            let byte = *script
                .get(*cursor)
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?;
            *cursor += 1;
            Some(usize::from(byte))
        }
        OP_PUSHDATA2 => {
            let bytes = script
                .get(*cursor..cursor.saturating_add(2))
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?;
            *cursor += 2;
            Some(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
        }
        OP_PUSHDATA4 => {
            let bytes = script
                .get(*cursor..cursor.saturating_add(4))
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?;
            *cursor += 4;
            Some(
                usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                    .map_err(|_| ScriptPrimitiveErrorV2::TruncatedPush)?,
            )
        }
        _ => None,
    };
    Ok(length)
}

fn minimally_pushed_v2(opcode: u8, pushed: &[u8]) -> bool {
    match pushed {
        [] => opcode == OP_0,
        [1..=16] => opcode == OP_1 + pushed[0] - 1,
        [0x81] => opcode == OP_1NEGATE,
        _ if pushed.len() <= 75 => opcode == pushed.len() as u8,
        _ if pushed.len() <= u8::MAX as usize => opcode == OP_PUSHDATA1,
        _ if pushed.len() <= u16::MAX as usize => opcode == OP_PUSHDATA2,
        _ => opcode == OP_PUSHDATA4,
    }
}

fn parse_script_internal_v2(
    script: &[u8],
    push_policy: Option<bool>,
    enforce_legacy_limits: bool,
) -> Result<Vec<ParsedOpcodeV2>, ScriptPrimitiveErrorV2> {
    if enforce_legacy_limits && script.len() > MAX_SCRIPT_SIZE_V2 {
        return Err(ScriptPrimitiveErrorV2::ScriptSize);
    }
    let mut cursor = 0usize;
    let mut operation_count = 0u32;
    let mut parsed = Vec::new();
    while cursor < script.len() {
        let start = cursor;
        let opcode = script[cursor];
        cursor += 1;
        if enforce_legacy_limits && opcode > OP_16 {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(ScriptPrimitiveErrorV2::OperationCount)?;
            if operation_count > MAX_OPS_PER_SCRIPT_V2 {
                return Err(ScriptPrimitiveErrorV2::OperationCount);
            }
        }
        let pushed = if let Some(length) = read_push_length(script, &mut cursor, opcode)? {
            if push_policy.is_some() && length > MAX_SCRIPT_ELEMENT_SIZE_V2 {
                return Err(ScriptPrimitiveErrorV2::ElementSize);
            }
            let end = cursor
                .checked_add(length)
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?;
            let bytes = script
                .get(cursor..end)
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?
                .to_vec();
            cursor = end;
            if push_policy == Some(true) && !minimally_pushed_v2(opcode, &bytes) {
                return Err(ScriptPrimitiveErrorV2::NonMinimalPush);
            }
            Some(bytes)
        } else {
            None
        };
        parsed.push(ParsedOpcodeV2 {
            opcode,
            pushed,
            start,
            end: cursor,
        });
    }
    Ok(parsed)
}

pub fn parse_script_v2(
    script: &[u8],
    require_minimal_push: bool,
) -> Result<Vec<ParsedOpcodeV2>, ScriptPrimitiveErrorV2> {
    parse_script_internal_v2(script, Some(require_minimal_push), true)
}

pub fn script_is_push_only_v2(script: &[u8]) -> Result<bool, ScriptPrimitiveErrorV2> {
    Ok(parse_script_internal_v2(script, Some(false), true)?
        .iter()
        .all(|operation| operation.opcode <= OP_16))
}

pub fn cast_to_bool_v2(bytes: &[u8]) -> bool {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            return !(index == bytes.len() - 1 && *byte == 0x80);
        }
    }
    false
}

pub fn decode_script_number_v2(
    bytes: &[u8],
    require_minimal: bool,
    maximum_bytes: usize,
) -> Result<i64, ScriptPrimitiveErrorV2> {
    if bytes.len() > maximum_bytes || bytes.len() > 8 {
        return Err(ScriptPrimitiveErrorV2::ScriptNumber);
    }
    if require_minimal
        && !bytes.is_empty()
        && (bytes[bytes.len() - 1] & 0x7f) == 0
        && (bytes.len() == 1 || bytes[bytes.len() - 2] & 0x80 == 0)
    {
        return Err(ScriptPrimitiveErrorV2::ScriptNumber);
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut magnitude = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        magnitude |= u64::from(*byte) << (8 * index);
    }
    let negative = bytes[bytes.len() - 1] & 0x80 != 0;
    if negative {
        magnitude &= !(0x80u64 << (8 * (bytes.len() - 1)));
    }
    let signed = i64::try_from(magnitude).map_err(|_| ScriptPrimitiveErrorV2::ScriptNumber)?;
    Ok(if negative { -signed } else { signed })
}

pub fn encode_script_number_v2(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut encoded = Vec::new();
    while magnitude != 0 {
        encoded.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(if negative { 0x80 } else { 0 });
    } else if negative {
        let last = encoded.len() - 1;
        encoded[last] |= 0x80;
    }
    encoded
}

fn is_disabled_opcode_v2(opcode: u8) -> bool {
    matches!(
        opcode,
        0x7e..=0x81 // CAT, SUBSTR, LEFT, RIGHT
            | 0x83..=0x86 // INVERT, AND, OR, XOR
            | 0x8d..=0x8e // 2MUL, 2DIV
            | 0x95..=0x99 // MUL, DIV, MOD, LSHIFT, RSHIFT
    )
}

fn is_tapscript_op_success_v2(opcode: u8) -> bool {
    matches!(
        opcode,
        0x50
            | 0x62
            | 0x7e..=0x81
            | 0x83..=0x86
            | 0x89..=0x8a
            | 0x8d..=0x8e
            | 0x95..=0x99
            | 0xbb..=0xfe
    )
}

fn tapscript_has_op_success_v2(script: &[u8]) -> Result<bool, ScriptPrimitiveErrorV2> {
    let mut cursor = 0usize;
    while cursor < script.len() {
        let opcode = script[cursor];
        cursor += 1;
        if is_tapscript_op_success_v2(opcode) {
            return Ok(true);
        }
        if let Some(length) = read_push_length(script, &mut cursor, opcode)? {
            cursor = cursor
                .checked_add(length)
                .ok_or(ScriptPrimitiveErrorV2::TruncatedPush)?;
            if cursor > script.len() {
                return Err(ScriptPrimitiveErrorV2::TruncatedPush);
            }
        }
    }
    Ok(false)
}

fn pop_stack_v2(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ScriptPrimitiveErrorV2> {
    stack.pop().ok_or(ScriptPrimitiveErrorV2::InvalidStack)
}

fn check_stack_limit_v2(
    stack: &[Vec<u8>],
    alternate: &[Vec<u8>],
) -> Result<(), ScriptPrimitiveErrorV2> {
    if stack.len() + alternate.len() > MAX_STACK_ITEMS_V2 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

fn pop_number_v2(
    stack: &mut Vec<Vec<u8>>,
    require_minimal: bool,
) -> Result<i64, ScriptPrimitiveErrorV2> {
    decode_script_number_v2(&pop_stack_v2(stack)?, require_minimal, 4)
}

/// Executes the consensus-common parser/control/stack foundation. Signature,
/// hash, arithmetic, locktime and witness-specific opcodes deliberately fail
/// closed until their exact modules are integrated.
pub fn execute_script_base_v2(
    script: &[u8],
    initial_stack: Vec<Vec<u8>>,
    require_minimal_push: bool,
    require_minimal_if: bool,
) -> Result<Vec<Vec<u8>>, ScriptPrimitiveErrorV2> {
    execute_script_with_locks_v2(
        script,
        initial_stack,
        require_minimal_push,
        require_minimal_if,
        ScriptLockContextV2::default(),
    )
}

pub fn execute_script_with_locks_v2(
    script: &[u8],
    initial_stack: Vec<Vec<u8>>,
    require_minimal_push: bool,
    require_minimal_if: bool,
    lock_context: ScriptLockContextV2,
) -> Result<Vec<Vec<u8>>, ScriptPrimitiveErrorV2> {
    execute_script_with_signatures_v2(
        script,
        initial_stack,
        require_minimal_push,
        require_minimal_if,
        lock_context,
        &RejectSignaturesV2,
    )
}

pub fn execute_script_with_signatures_v2<C: ScriptSignatureCheckerV2>(
    script: &[u8],
    initial_stack: Vec<Vec<u8>>,
    require_minimal_push: bool,
    require_minimal_if: bool,
    lock_context: ScriptLockContextV2,
    signature_checker: &C,
) -> Result<Vec<Vec<u8>>, ScriptPrimitiveErrorV2> {
    execute_script_dialect_v2(
        script,
        initial_stack,
        require_minimal_push,
        require_minimal_if,
        lock_context,
        signature_checker,
        ScriptDialectV2::Legacy,
    )
}

fn execute_script_dialect_v2<C: ScriptSignatureCheckerV2>(
    script: &[u8],
    initial_stack: Vec<Vec<u8>>,
    require_minimal_push: bool,
    require_minimal_if: bool,
    lock_context: ScriptLockContextV2,
    signature_checker: &C,
    dialect: ScriptDialectV2,
) -> Result<Vec<Vec<u8>>, ScriptPrimitiveErrorV2> {
    // Alpha Core's OP_DRIVECHAIN immediately ends a four-byte script whose
    // first byte is OP_DRIVECHAIN. In BASE/WITNESS_V0 the remaining bytes are
    // deliberately not decoded (even malformed pushes). Tapscript's earlier
    // OP_SUCCESS scan remains in the witness dispatcher, just as in Core.
    if lock_context.alpha_drivechain && script.len() == 4 && script[0] == 0xb4 {
        let mut stack = initial_stack;
        stack.push(vec![0xdc]);
        check_stack_limit_v2(&stack, &[])?;
        return Ok(stack);
    }
    let operations =
        parse_script_internal_v2(script, Some(false), dialect == ScriptDialectV2::Legacy)?;
    let mut operation_count = if dialect == ScriptDialectV2::Legacy {
        u32::try_from(
            operations
                .iter()
                .filter(|operation| operation.opcode > OP_16)
                .count(),
        )
        .map_err(|_| ScriptPrimitiveErrorV2::OperationCount)?
    } else {
        0
    };
    let mut stack = initial_stack;
    let mut alternate = Vec::new();
    let mut condition_stack: Vec<bool> = Vec::new();
    let mut code_separator_position = 0usize;
    let mut code_separator_opcode_position = u32::MAX;
    check_stack_limit_v2(&stack, &alternate)?;
    for (opcode_index, operation) in operations.into_iter().enumerate() {
        let opcode = operation.opcode;
        if is_disabled_opcode_v2(opcode) || matches!(opcode, 0x65 | 0x66) {
            return Err(ScriptPrimitiveErrorV2::BadOpcode);
        }
        if opcode == 0xab && dialect == ScriptDialectV2::Legacy && lock_context.const_script_code {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let executing = condition_stack.iter().all(|condition| *condition);
        if let Some(pushed) = operation.pushed {
            if executing {
                if require_minimal_push && !minimally_pushed_v2(opcode, &pushed) {
                    return Err(ScriptPrimitiveErrorV2::NonMinimalPush);
                }
                stack.push(pushed);
            }
            check_stack_limit_v2(&stack, &alternate)?;
            continue;
        }
        if opcode == 0x63 || opcode == 0x64 {
            let value = if executing {
                let argument = pop_stack_v2(&mut stack)?;
                if require_minimal_if && !argument.is_empty() && argument.as_slice() != [1] {
                    return Err(ScriptPrimitiveErrorV2::InvalidConditional);
                }
                let value = cast_to_bool_v2(&argument);
                if opcode == 0x64 {
                    !value
                } else {
                    value
                }
            } else {
                false
            };
            condition_stack.push(value);
            continue;
        }
        if opcode == 0x67 {
            let last = condition_stack
                .last_mut()
                .ok_or(ScriptPrimitiveErrorV2::InvalidConditional)?;
            *last = !*last;
            continue;
        }
        if opcode == 0x68 {
            condition_stack
                .pop()
                .ok_or(ScriptPrimitiveErrorV2::InvalidConditional)?;
            continue;
        }
        if !executing {
            continue;
        }
        match opcode {
            OP_1NEGATE => stack.push(encode_script_number_v2(-1)),
            OP_1..=OP_16 => stack.push(encode_script_number_v2(i64::from(opcode - OP_1 + 1))),
            0x61 => {} // NOP
            0x69 => {
                if !cast_to_bool_v2(&pop_stack_v2(&mut stack)?) {
                    return Err(ScriptPrimitiveErrorV2::Verify);
                }
            }
            0x6a => return Err(ScriptPrimitiveErrorV2::BadOpcode), // RETURN
            0x6b => alternate.push(pop_stack_v2(&mut stack)?),
            0x6c => stack.push(pop_stack_v2(&mut alternate)?),
            0x6d => {
                pop_stack_v2(&mut stack)?;
                pop_stack_v2(&mut stack)?;
            }
            0x6e => {
                if stack.len() < 2 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                stack.extend_from_within(stack.len() - 2..);
            }
            0x6f => {
                if stack.len() < 3 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                stack.extend_from_within(stack.len() - 3..);
            }
            0x70 => {
                if stack.len() < 4 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let length = stack.len();
                stack.push(stack[length - 4].clone());
                stack.push(stack[length - 3].clone());
            }
            0x71 => {
                if stack.len() < 6 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let index = stack.len() - 6;
                let first = stack.remove(index);
                let second = stack.remove(index);
                stack.push(first);
                stack.push(second);
            }
            0x72 => {
                if stack.len() < 4 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let length = stack.len();
                stack.swap(length - 4, length - 2);
                stack.swap(length - 3, length - 1);
            }
            0x73 => {
                let top = stack.last().ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
                if cast_to_bool_v2(top) {
                    stack.push(top.clone());
                }
            }
            0x74 => stack.push(encode_script_number_v2(stack.len() as i64)),
            0x75 => {
                pop_stack_v2(&mut stack)?;
            }
            0x76 => stack.push(
                stack
                    .last()
                    .cloned()
                    .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?,
            ),
            0x77 => {
                if stack.len() < 2 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                stack.remove(stack.len() - 2);
            }
            0x78 => {
                if stack.len() < 2 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                stack.push(stack[stack.len() - 2].clone());
            }
            0x79 | 0x7a => {
                let depth = pop_number_v2(&mut stack, require_minimal_push)?;
                let depth =
                    usize::try_from(depth).map_err(|_| ScriptPrimitiveErrorV2::InvalidStack)?;
                if depth >= stack.len() {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let index = stack.len() - 1 - depth;
                let value = if opcode == 0x7a {
                    stack.remove(index)
                } else {
                    stack[index].clone()
                };
                stack.push(value);
            }
            0x7b => {
                if stack.len() < 3 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let index = stack.len() - 3;
                let value = stack.remove(index);
                stack.push(value);
            }
            0x7c => {
                if stack.len() < 2 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let length = stack.len();
                stack.swap(length - 1, length - 2);
            }
            0x7d => {
                if stack.len() < 2 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let value = stack
                    .last()
                    .cloned()
                    .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
                let index = stack.len() - 2;
                stack.insert(index, value);
            }
            0x82 => {
                let length = stack
                    .last()
                    .map(Vec::len)
                    .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
                stack.push(encode_script_number_v2(length as i64));
            }
            0x87 | 0x88 => {
                let right = pop_stack_v2(&mut stack)?;
                let left = pop_stack_v2(&mut stack)?;
                let equal = left == right;
                if opcode == 0x88 {
                    if !equal {
                        return Err(ScriptPrimitiveErrorV2::Verify);
                    }
                } else {
                    stack.push(encode_script_number_v2(i64::from(equal)));
                }
            }
            0x8b..=0x92 => {
                let value = pop_number_v2(&mut stack, require_minimal_push)?;
                let result = match opcode {
                    0x8b => value.checked_add(1),
                    0x8c => value.checked_sub(1),
                    0x8f => value.checked_neg(),
                    0x90 => value.checked_abs(),
                    0x91 => Some(i64::from(value == 0)),
                    0x92 => Some(i64::from(value != 0)),
                    _ => None, // disabled 2MUL/2DIV were rejected above
                }
                .ok_or(ScriptPrimitiveErrorV2::ScriptNumber)?;
                stack.push(encode_script_number_v2(result));
            }
            0x93 | 0x94 | 0x9a..=0xa2 => {
                let right = pop_number_v2(&mut stack, require_minimal_push)?;
                let left = pop_number_v2(&mut stack, require_minimal_push)?;
                let result = match opcode {
                    0x93 => left.checked_add(right),
                    0x94 => left.checked_sub(right),
                    0x9a => Some(i64::from(left != 0 && right != 0)),
                    0x9b => Some(i64::from(left != 0 || right != 0)),
                    0x9c | 0x9d => Some(i64::from(left == right)),
                    0x9e => Some(i64::from(left != right)),
                    0x9f => Some(i64::from(left < right)),
                    0xa0 => Some(i64::from(left > right)),
                    0xa1 => Some(i64::from(left <= right)),
                    0xa2 => Some(i64::from(left >= right)),
                    _ => None,
                }
                .ok_or(ScriptPrimitiveErrorV2::ScriptNumber)?;
                if opcode == 0x9d {
                    if result == 0 {
                        return Err(ScriptPrimitiveErrorV2::Verify);
                    }
                } else {
                    stack.push(encode_script_number_v2(result));
                }
            }
            0xa3 | 0xa4 => {
                let right = pop_number_v2(&mut stack, require_minimal_push)?;
                let left = pop_number_v2(&mut stack, require_minimal_push)?;
                stack.push(encode_script_number_v2(if opcode == 0xa3 {
                    left.min(right)
                } else {
                    left.max(right)
                }));
            }
            0xa5 => {
                let maximum = pop_number_v2(&mut stack, require_minimal_push)?;
                let minimum = pop_number_v2(&mut stack, require_minimal_push)?;
                let value = pop_number_v2(&mut stack, require_minimal_push)?;
                stack.push(encode_script_number_v2(i64::from(
                    minimum <= value && value < maximum,
                )));
            }
            0xa6..=0xaa => {
                let value = pop_stack_v2(&mut stack)?;
                let digest = match opcode {
                    0xa6 => ripemd160::Hash::hash(&value).to_byte_array().to_vec(),
                    0xa7 => sha1::Hash::hash(&value).to_byte_array().to_vec(),
                    0xa8 => sha256::Hash::hash(&value).to_byte_array().to_vec(),
                    0xa9 => hash160::Hash::hash(&value).to_byte_array().to_vec(),
                    0xaa => sha256d::Hash::hash(&value).to_byte_array().to_vec(),
                    _ => unreachable!(),
                };
                stack.push(digest);
            }
            0xab => {
                code_separator_position = operation.end;
                code_separator_opcode_position = u32::try_from(opcode_index)
                    .map_err(|_| ScriptPrimitiveErrorV2::OperationCount)?;
            }
            0xac | 0xad => {
                let public_key = pop_stack_v2(&mut stack)?;
                let signature = pop_stack_v2(&mut stack)?;
                let valid = match dialect {
                    ScriptDialectV2::Legacy => signature_checker.check_ecdsa_signature(
                        &signature,
                        &public_key,
                        &script[code_separator_position..],
                        code_separator_position,
                    )?,
                    ScriptDialectV2::TapScript => signature_checker.check_schnorr_signature(
                        &signature,
                        &public_key,
                        code_separator_opcode_position,
                    )?,
                };
                if !valid && lock_context.null_fail && !signature.is_empty() {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }
                if opcode == 0xad {
                    if !valid {
                        return Err(ScriptPrimitiveErrorV2::Verify);
                    }
                } else {
                    stack.push(encode_script_number_v2(i64::from(valid)));
                }
            }
            0xae | 0xaf => {
                if dialect == ScriptDialectV2::TapScript {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
                let public_key_count =
                    usize::try_from(pop_number_v2(&mut stack, require_minimal_push)?)
                        .map_err(|_| ScriptPrimitiveErrorV2::InvalidStack)?;
                if public_key_count > 20 {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                operation_count = operation_count
                    .checked_add(
                        u32::try_from(public_key_count)
                            .map_err(|_| ScriptPrimitiveErrorV2::OperationCount)?,
                    )
                    .ok_or(ScriptPrimitiveErrorV2::OperationCount)?;
                if operation_count > MAX_OPS_PER_SCRIPT_V2 {
                    return Err(ScriptPrimitiveErrorV2::OperationCount);
                }
                if stack.len() < public_key_count {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let mut public_keys = Vec::with_capacity(public_key_count);
                for _ in 0..public_key_count {
                    public_keys.push(pop_stack_v2(&mut stack)?);
                }

                let signature_count =
                    usize::try_from(pop_number_v2(&mut stack, require_minimal_push)?)
                        .map_err(|_| ScriptPrimitiveErrorV2::InvalidStack)?;
                if signature_count > public_key_count || stack.len() <= signature_count {
                    return Err(ScriptPrimitiveErrorV2::InvalidStack);
                }
                let mut signatures = Vec::with_capacity(signature_count);
                for _ in 0..signature_count {
                    signatures.push(pop_stack_v2(&mut stack)?);
                }
                let dummy = pop_stack_v2(&mut stack)?;
                if lock_context.null_dummy && !dummy.is_empty() {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }

                let mut script_code = script[code_separator_position..].to_vec();
                if !lock_context.witness_v0 {
                    for signature in &signatures {
                        let without_signature =
                            remove_exact_signature_pushes_v2(&script_code, signature)?;
                        if lock_context.const_script_code
                            && without_signature.len() != script_code.len()
                        {
                            return Err(ScriptPrimitiveErrorV2::Signature);
                        }
                        script_code = without_signature;
                    }
                }
                let mut signature_index = 0usize;
                let mut public_key_index = 0usize;
                while signature_index < signatures.len() && public_key_index < public_keys.len() {
                    if signature_checker.check_ecdsa_signature(
                        &signatures[signature_index],
                        &public_keys[public_key_index],
                        &script_code,
                        code_separator_position,
                    )? {
                        signature_index += 1;
                    }
                    public_key_index += 1;
                    if signatures.len() - signature_index > public_keys.len() - public_key_index {
                        break;
                    }
                }
                let valid = signature_index == signatures.len();
                if !valid
                    && lock_context.null_fail
                    && signatures.iter().any(|signature| !signature.is_empty())
                {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }
                if opcode == 0xaf {
                    if !valid {
                        return Err(ScriptPrimitiveErrorV2::Verify);
                    }
                } else {
                    stack.push(encode_script_number_v2(i64::from(valid)));
                }
            }
            0xc1 | 0xc2 if dialect == ScriptDialectV2::Legacy => {
                let public_key = pop_stack_v2(&mut stack)?;
                let data = pop_stack_v2(&mut stack)?;
                let signature = pop_stack_v2(&mut stack)?;
                // Native pre-tapscript CSFS fails the entire script on a
                // false signature, independently of NULLFAIL and VERIFY form.
                if !signature_checker.check_signature_from_stack(&signature, &data, &public_key)? {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }
                if opcode == 0xc1 { stack.push(vec![1]); }
            }
            0xba => {
                if dialect != ScriptDialectV2::TapScript {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
                let public_key = pop_stack_v2(&mut stack)?;
                let value = pop_number_v2(&mut stack, require_minimal_push)?;
                let signature = pop_stack_v2(&mut stack)?;
                let valid = signature_checker.check_schnorr_signature(
                    &signature,
                    &public_key,
                    code_separator_opcode_position,
                )?;
                // In Tapscript a non-empty signature that does not verify is
                // a consensus failure, including through CHECKSIGADD. An
                // empty signature remains the intentional false value.
                if !valid && !signature.is_empty() {
                    return Err(ScriptPrimitiveErrorV2::Signature);
                }
                stack.push(encode_script_number_v2(
                    value
                        .checked_add(i64::from(valid))
                        .ok_or(ScriptPrimitiveErrorV2::ScriptNumber)?,
                ));
            }
            0xb4 if lock_context.alpha_drivechain => {}
            0xb0 | 0xb3..=0xb9 => {
                if lock_context.discourage_upgradable_nops {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
            }
            0xb1 => {
                if lock_context.check_lock_time_verify {
                    let operand = stack.last().ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
                    let required = decode_script_number_v2(operand, require_minimal_push, 5)?;
                    let required =
                        u32::try_from(required).map_err(|_| ScriptPrimitiveErrorV2::LockTime)?;
                    let same_type = (required < LOCKTIME_THRESHOLD_V2)
                        == (lock_context.transaction_lock_time < LOCKTIME_THRESHOLD_V2);
                    if !same_type
                        || required > lock_context.transaction_lock_time
                        || lock_context.input_sequence == u32::MAX
                    {
                        return Err(ScriptPrimitiveErrorV2::LockTime);
                    }
                } else if lock_context.discourage_upgradable_nops {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
            }
            0xb2 => {
                if lock_context.check_sequence_verify {
                    const DISABLE_FLAG: u32 = 1 << 31;
                    const TYPE_FLAG: u32 = 1 << 22;
                    const MASK: u32 = 0x0000_ffff;
                    let operand = stack.last().ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
                    let required = decode_script_number_v2(operand, require_minimal_push, 5)?;
                    if required < 0 {
                        return Err(ScriptPrimitiveErrorV2::LockTime);
                    }
                    if (required as u64) & u64::from(DISABLE_FLAG) == 0 {
                        let required = u32::try_from(required)
                            .map_err(|_| ScriptPrimitiveErrorV2::LockTime)?;
                        let sequence = lock_context.input_sequence;
                        if lock_context.transaction_version < 2
                            || sequence & DISABLE_FLAG != 0
                            || required & TYPE_FLAG != sequence & TYPE_FLAG
                            || (required & (TYPE_FLAG | MASK)) > (sequence & (TYPE_FLAG | MASK))
                        {
                            return Err(ScriptPrimitiveErrorV2::LockTime);
                        }
                    }
                } else if lock_context.discourage_upgradable_nops {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
            }
            _ => return Err(ScriptPrimitiveErrorV2::BadOpcode),
        }
        check_stack_limit_v2(&stack, &alternate)?;
    }
    if !condition_stack.is_empty() {
        return Err(ScriptPrimitiveErrorV2::InvalidConditional);
    }
    Ok(stack)
}

fn is_pay_to_script_hash_v2(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

fn require_true_top_v2(stack: &[Vec<u8>]) -> Result<(), ScriptPrimitiveErrorV2> {
    if !matches!(stack.last(), Some(element) if cast_to_bool_v2(element)) {
        return Err(ScriptPrimitiveErrorV2::Verify);
    }
    Ok(())
}

/// Evaluate a legacy scriptSig/scriptPubKey pair with the consensus P2SH
/// stack-restoration rule. Witness programs and Taproot are deliberately not
/// interpreted by this entry point.
pub fn verify_legacy_script_pair_v2<C: ScriptSignatureCheckerV2>(
    script_sig: &[u8],
    script_pubkey: &[u8],
    lock_context: ScriptLockContextV2,
    signature_checker: &C,
    flags: LegacyScriptFlagsV2,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let p2sh = flags.verify_p2sh && is_pay_to_script_hash_v2(script_pubkey);
    if p2sh
        && parse_script_v2(script_sig, flags.require_minimal_push)?
            .iter()
            .any(|operation| operation.opcode > OP_16)
    {
        return Err(ScriptPrimitiveErrorV2::BadOpcode);
    }
    let script_sig_stack = execute_script_with_signatures_v2(
        script_sig,
        Vec::new(),
        flags.require_minimal_push,
        flags.require_minimal_if,
        lock_context,
        signature_checker,
    )?;
    let script_pubkey_stack = execute_script_with_signatures_v2(
        script_pubkey,
        script_sig_stack.clone(),
        flags.require_minimal_push,
        flags.require_minimal_if,
        lock_context,
        signature_checker,
    )?;
    require_true_top_v2(&script_pubkey_stack)?;

    let final_stack = if p2sh {
        let mut restored = script_sig_stack;
        let redeem_script = restored.pop().ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
        let stack = execute_script_with_signatures_v2(
            &redeem_script,
            restored,
            flags.require_minimal_push,
            flags.require_minimal_if,
            lock_context,
            signature_checker,
        )?;
        require_true_top_v2(&stack)?;
        stack
    } else {
        script_pubkey_stack
    };
    if flags.clean_stack && final_stack.len() != 1 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

/// Verify a native version-0 witness program. Wrapped P2SH-witness dispatch is
/// performed by the higher script-pair layer and must present the same program
/// bytes here after exact redeem-script validation.
pub fn verify_witness_v0_program_v2(
    transaction: &Transaction,
    input_index: usize,
    spent_value: Amount,
    witness_program: &[u8],
    witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2,
    flags: WitnessV0FlagsV2,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let (execution_script, initial_stack) = match witness_program {
        [0x00, 0x14, public_key_hash @ ..] if public_key_hash.len() == 20 => {
            if witness.len() != 2 {
                return Err(ScriptPrimitiveErrorV2::InvalidStack);
            }
            let hash_push = PushBytesBuf::try_from(public_key_hash.to_vec())
                .map_err(|_| ScriptPrimitiveErrorV2::InvalidStack)?;
            let script = Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_DUP)
                .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                .push_slice(hash_push)
                .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .into_script();
            (script, witness.to_vec())
        }
        [0x00, 0x20, witness_script_hash @ ..] if witness_script_hash.len() == 32 => {
            let (witness_script, stack) = witness
                .split_last()
                .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
            if witness_script.len() > MAX_SCRIPT_SIZE_V2
                || sha256::Hash::hash(witness_script).to_byte_array() != witness_script_hash
            {
                return Err(ScriptPrimitiveErrorV2::Verify);
            }
            (
                ScriptBuf::from_bytes(witness_script.clone()),
                stack.to_vec(),
            )
        }
        _ => return Err(ScriptPrimitiveErrorV2::BadOpcode),
    };
    if initial_stack
        .iter()
        .any(|element| element.len() > MAX_SCRIPT_ELEMENT_SIZE_V2)
    {
        return Err(ScriptPrimitiveErrorV2::ElementSize);
    }
    let checker = WitnessV0EcdsaCheckerV2::new(
        transaction,
        input_index,
        spent_value,
        flags.require_compressed_public_key,
        flags.strict_der,
        flags.strict_encoding,
        flags.low_s,
    );
    let stack = execute_script_with_signatures_v2(
        execution_script.as_bytes(),
        initial_stack,
        false,
        flags.require_minimal_if,
        ScriptLockContextV2 {
            null_fail: true,
            null_dummy: true,
            // CONST_SCRIPTCODE is a BASE-script rule. BIP143 witness-v0
            // scripts retain CODESEPARATOR semantics.
            const_script_code: false,
            witness_v0: true,
            ..lock_context
        },
        &checker,
    )?;
    require_true_top_v2(&stack)?;
    if stack.len() != 1 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

/// Execute a native witness program with a caller-supplied signature checker.
/// This is used by Elements DynaFed block proofs, whose ECDSA message is the
/// patched block-header hash rather than a transaction sighash.
pub fn verify_native_witness_program_with_checker_v2<C: ScriptSignatureCheckerV2>(
    witness_program: &[u8],
    witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2,
    flags: WitnessV0FlagsV2,
    checker: &C,
) -> Result<(), ScriptPrimitiveErrorV2> {
    verify_witness_program_with_execution_flags_v3(
        witness_program, witness,
        ScriptLockContextV2 { null_fail: true, null_dummy: true, ..lock_context },
        flags, false, checker,
    )
}

/// Witness execution with explicit native flags. Unlike the compatibility
/// wrapper, this does not force transaction NULLFAIL or discard MINIMALDATA.
/// Signature/key encoding remains the supplied checker's responsibility.
pub fn verify_witness_program_with_execution_flags_v3<C: ScriptSignatureCheckerV2>(
    witness_program: &[u8],
    witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2,
    flags: WitnessV0FlagsV2,
    require_minimal_push: bool,
    checker: &C,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let (version, program) =
        decode_witness_program_v2(witness_program).ok_or(ScriptPrimitiveErrorV2::BadOpcode)?;
    if version != 0 {
        // GenericVerifyScript does not discourage unknown native witness
        // versions under the frozen DynaFed proof flags.
        return Ok(());
    }
    let (execution_script, initial_stack) = match program {
        public_key_hash if public_key_hash.len() == 20 => {
            if witness.len() != 2 {
                return Err(ScriptPrimitiveErrorV2::InvalidStack);
            }
            let hash_push = PushBytesBuf::try_from(public_key_hash.to_vec())
                .map_err(|_| ScriptPrimitiveErrorV2::InvalidStack)?;
            (
                Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_DUP)
                    .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                    .push_slice(hash_push)
                    .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                    .into_script(),
                witness.to_vec(),
            )
        }
        witness_script_hash if witness_script_hash.len() == 32 => {
            let (witness_script, stack) = witness
                .split_last()
                .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
            if witness_script.len() > MAX_SCRIPT_SIZE_V2
                || sha256::Hash::hash(witness_script).to_byte_array() != witness_script_hash
            {
                return Err(ScriptPrimitiveErrorV2::Verify);
            }
            (
                ScriptBuf::from_bytes(witness_script.clone()),
                stack.to_vec(),
            )
        }
        _ => return Err(ScriptPrimitiveErrorV2::BadOpcode),
    };
    if initial_stack
        .iter()
        .any(|element| element.len() > MAX_SCRIPT_ELEMENT_SIZE_V2)
    {
        return Err(ScriptPrimitiveErrorV2::ElementSize);
    }
    let stack = execute_script_with_signatures_v2(
        execution_script.as_bytes(),
        initial_stack,
        require_minimal_push,
        flags.require_minimal_if,
        ScriptLockContextV2 {
            const_script_code: false,
            witness_v0: true,
            ..lock_context
        },
        checker,
    )?;
    require_true_top_v2(&stack)?;
    if stack.len() != 1 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

/// Execute legacy, P2SH, native witness-v0, or P2SH-wrapped witness-v0 from
/// raw consensus components with caller-supplied signature checkers.  This
/// keeps the script machine reusable by Elements, whose signature preimages
/// differ from Bitcoin's. Taproot is deliberately rejected here and must be
/// handled by a chain-specific verifier with the authenticated genesis hash.
pub fn verify_script_components_with_checkers_v2<L, W>(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2,
    legacy_checker: &L,
    witness_v0_checker: &W,
    flags: LegacyScriptFlagsV2,
) -> Result<(), ScriptPrimitiveErrorV2>
where
    L: ScriptSignatureCheckerV2,
    W: ScriptSignatureCheckerV2,
{
    verify_script_components_execution_v3(script_sig, script_pubkey, witness,
        lock_context, legacy_checker, witness_v0_checker, flags, false)
}

/// Native block-proof variant: retain explicit witness NULLFAIL/MINIMALDATA.
pub fn verify_native_script_components_v3<L: ScriptSignatureCheckerV2, W: ScriptSignatureCheckerV2>(
    script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2, legacy_checker: &L, witness_v0_checker: &W,
    flags: LegacyScriptFlagsV2,
) -> Result<(), ScriptPrimitiveErrorV2> {
    verify_script_components_execution_v3(script_sig, script_pubkey, witness,
        lock_context, legacy_checker, witness_v0_checker, flags, true)
}

fn verify_script_components_execution_v3<L: ScriptSignatureCheckerV2, W: ScriptSignatureCheckerV2>(
    script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2, legacy_checker: &L, witness_v0_checker: &W,
    flags: LegacyScriptFlagsV2, native_flags: bool,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let witness_context = if native_flags { lock_context } else {
        ScriptLockContextV2 { null_fail: true, null_dummy: true, ..lock_context }
    };
    if flags.verify_witness {
        if let Some((version, program)) = decode_witness_program_v2(script_pubkey) {
            if !script_sig.is_empty() {
                return Err(ScriptPrimitiveErrorV2::InvalidStack);
            }
            if version == 0 {
                if !matches!(program.len(), 20 | 32) {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
                return verify_witness_program_with_execution_flags_v3(
                    script_pubkey,
                    witness,
                    witness_context,
                    WitnessV0FlagsV2 {
                        require_minimal_if: flags.require_minimal_if,
                        require_compressed_public_key: flags.witness_pubkey_type,
                        strict_der: flags.strict_der,
                        strict_encoding: flags.strict_encoding,
                        low_s: flags.low_s,
                    },
                    native_flags && flags.require_minimal_push,
                    witness_v0_checker,
                );
            }
            if version == 1 && program.len() == 32 && flags.verify_taproot {
                return Err(ScriptPrimitiveErrorV2::BadOpcode);
            }
            return if flags.discourage_upgradable_witness_program {
                Err(ScriptPrimitiveErrorV2::BadOpcode)
            } else {
                Ok(())
            };
        }
    }

    let wrapped =
        if flags.verify_witness && flags.verify_p2sh && is_pay_to_script_hash_v2(script_pubkey) {
            let operations = parse_script_v2(script_sig, flags.require_minimal_push)?;
            match operations.as_slice() {
                [ParsedOpcodeV2 {
                    pushed: Some(redeem),
                    ..
                }] if decode_witness_program_v2(redeem).is_some() => Some(redeem.clone()),
                _ => None,
            }
        } else {
            None
        };
    verify_legacy_script_pair_v2(
        script_sig,
        script_pubkey,
        lock_context,
        legacy_checker,
        LegacyScriptFlagsV2 {
            clean_stack: flags.clean_stack && wrapped.is_none(),
            require_minimal_if: false,
            ..flags
        },
    )?;
    if let Some(program) = wrapped {
        let (version, bytes) =
            decode_witness_program_v2(&program).ok_or(ScriptPrimitiveErrorV2::BadOpcode)?;
        if version == 0 {
            if !matches!(bytes.len(), 20 | 32) {
                return Err(ScriptPrimitiveErrorV2::BadOpcode);
            }
            return verify_witness_program_with_execution_flags_v3(
                &program,
                witness,
                witness_context,
                WitnessV0FlagsV2 {
                    require_minimal_if: flags.require_minimal_if,
                    require_compressed_public_key: flags.witness_pubkey_type,
                    strict_der: flags.strict_der,
                    strict_encoding: flags.strict_encoding,
                    low_s: flags.low_s,
                },
                native_flags && flags.require_minimal_push,
                witness_v0_checker,
            );
        }
        return if flags.discourage_upgradable_witness_program {
            Err(ScriptPrimitiveErrorV2::BadOpcode)
        } else {
            Ok(())
        };
    }
    if flags.verify_witness && !witness.is_empty() {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

fn decode_witness_program_v2(script: &[u8]) -> Option<(u8, &[u8])> {
    if !(4..=42).contains(&script.len()) {
        return None;
    }
    let version = match script[0] {
        OP_0 => 0,
        OP_1..=OP_16 => script[0] - OP_1 + 1,
        _ => return None,
    };
    let program_length = usize::from(script[1]);
    if !(2..=40).contains(&program_length) || script[1] > 0x4b || script.len() != program_length + 2
    {
        return None;
    }
    Some((version, &script[2..]))
}

pub fn verify_taproot_key_spend_v2(
    transaction: &Transaction,
    input_index: usize,
    spent_outputs: &[bitcoin::TxOut],
    witness_program: &[u8],
    witness: &[Vec<u8>],
) -> Result<(), ScriptPrimitiveErrorV2> {
    let output_key_bytes = match witness_program {
        [OP_1, 0x20, output_key @ ..] if output_key.len() == 32 => output_key,
        _ => return Err(ScriptPrimitiveErrorV2::BadOpcode),
    };
    if spent_outputs.len() != transaction.input.len() {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    let (signature_bytes, annex_bytes) = match witness {
        [signature] => (signature.as_slice(), None),
        [signature, annex] if annex.first() == Some(&0x50) => {
            (signature.as_slice(), Some(annex.as_slice()))
        }
        _ => return Err(ScriptPrimitiveErrorV2::InvalidStack),
    };
    let (signature_bytes, sighash_type) = match signature_bytes {
        bytes if bytes.len() == 64 => (bytes, TapSighashType::Default),
        bytes if bytes.len() == 65 => {
            let (&raw_type, signature) = bytes
                .split_last()
                .ok_or(ScriptPrimitiveErrorV2::Signature)?;
            let sighash_type = TapSighashType::from_consensus_u8(raw_type)
                .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
            if sighash_type == TapSighashType::Default {
                return Err(ScriptPrimitiveErrorV2::Signature);
            }
            (signature, sighash_type)
        }
        _ => return Err(ScriptPrimitiveErrorV2::Signature),
    };
    let signature = schnorr::Signature::from_slice(signature_bytes)
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
    let output_key = XOnlyPublicKey::from_slice(output_key_bytes)
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
    let prevouts = Prevouts::All(spent_outputs);
    let mut cache = SighashCache::new(transaction);
    let sighash = if let Some(annex_bytes) = annex_bytes {
        let annex = Annex::new(annex_bytes).map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let mut engine = TapSighash::engine();
        cache
            .taproot_encode_signing_data_to(
                &mut engine,
                input_index,
                &prevouts,
                Some(annex),
                None,
                sighash_type,
            )
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        TapSighash::from_engine(engine)
    } else {
        cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?
    };
    let message = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &output_key)
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)
}

/// Authenticate a Taproot script path and execute the currently implemented
/// non-signature Tapscript subset. Signature opcodes and OP_SUCCESS remain
/// fail-closed until the full BIP342 machine is wired.
pub fn verify_taproot_script_path_foundation_v2(
    transaction: &Transaction,
    input_index: usize,
    spent_outputs: &[bitcoin::TxOut],
    witness_program: &[u8],
    witness: &[Vec<u8>],
    lock_context: ScriptLockContextV2,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let output_key_bytes = match witness_program {
        [OP_1, 0x20, output_key @ ..] if output_key.len() == 32 => output_key,
        _ => return Err(ScriptPrimitiveErrorV2::BadOpcode),
    };
    let annex = witness
        .last()
        .filter(|item| item.first() == Some(&0x50))
        .map(Vec::as_slice);
    let without_annex = if annex.is_some() {
        &witness[..witness.len() - 1]
    } else {
        witness
    };
    if without_annex.len() < 2 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    let control_bytes = without_annex
        .last()
        .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
    let script_bytes = &without_annex[without_annex.len() - 2];
    let initial_stack = without_annex[..without_annex.len() - 2].to_vec();
    if initial_stack
        .iter()
        .any(|item| item.len() > MAX_SCRIPT_ELEMENT_SIZE_V2)
    {
        return Err(ScriptPrimitiveErrorV2::ElementSize);
    }
    let control =
        ControlBlock::decode(control_bytes).map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
    let output_key = XOnlyPublicKey::from_slice(output_key_bytes)
        .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
    let script = Script::from_bytes(script_bytes);
    if !control.verify_taproot_commitment(&Secp256k1::verification_only(), output_key, script) {
        return Err(ScriptPrimitiveErrorV2::Signature);
    }
    if control.leaf_version != LeafVersion::TapScript {
        return Ok(());
    }
    if tapscript_has_op_success_v2(script_bytes)? {
        return Ok(());
    }
    let leaf_hash = TapLeafHash::from_script(script, control.leaf_version);
    let signature_budget = transaction
        .input
        .get(input_index)
        .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?
        .witness
        .size()
        .checked_add(50)
        .ok_or(ScriptPrimitiveErrorV2::OperationCount)?;
    let checker = TapscriptSchnorrCheckerV2::new(
        transaction,
        input_index,
        spent_outputs,
        leaf_hash,
        annex,
        signature_budget,
    )?;
    let stack = execute_script_dialect_v2(
        script_bytes,
        initial_stack,
        false,
        true,
        ScriptLockContextV2 {
            check_lock_time_verify: true,
            check_sequence_verify: true,
            null_fail: true,
            null_dummy: true,
            ..lock_context
        },
        &checker,
        ScriptDialectV2::TapScript,
    )?;
    require_true_top_v2(&stack)?;
    if stack.len() != 1 {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

/// Dispatch one input across legacy, native witness-v0, or P2SH-wrapped
/// witness-v0 semantics and reject any unconsumed witness stack.
pub fn verify_script_input_v2<C: ScriptSignatureCheckerV2>(
    transaction: &Transaction,
    input_index: usize,
    spent_outputs: &[bitcoin::TxOut],
    lock_context: ScriptLockContextV2,
    legacy_signature_checker: &C,
    flags: LegacyScriptFlagsV2,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let input = transaction
        .input
        .get(input_index)
        .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
    let spent_output = spent_outputs
        .get(input_index)
        .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
    let script_sig = input.script_sig.as_bytes();
    let script_pubkey = spent_output.script_pubkey.as_bytes();
    let witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();

    if flags.verify_witness {
        if let Some((witness_version, program)) = decode_witness_program_v2(script_pubkey) {
            if !script_sig.is_empty() {
                return Err(ScriptPrimitiveErrorV2::InvalidStack);
            }
            if witness_version == 0 {
                if !matches!(program.len(), 20 | 32) {
                    return Err(ScriptPrimitiveErrorV2::BadOpcode);
                }
                return verify_witness_v0_program_v2(
                    transaction,
                    input_index,
                    spent_output.value,
                    script_pubkey,
                    &witness,
                    lock_context,
                    WitnessV0FlagsV2 {
                        require_minimal_if: flags.require_minimal_if,
                        require_compressed_public_key: flags.witness_pubkey_type,
                        strict_der: flags.strict_der,
                        strict_encoding: flags.strict_encoding,
                        low_s: flags.low_s,
                    },
                );
            }
            if witness_version == 1 && program.len() == 32 && flags.verify_taproot {
                let without_annex_len = witness.len().saturating_sub(usize::from(
                    witness.len() >= 2
                        && witness.last().and_then(|item| item.first()) == Some(&0x50),
                ));
                return if without_annex_len == 1 {
                    verify_taproot_key_spend_v2(
                        transaction,
                        input_index,
                        spent_outputs,
                        script_pubkey,
                        &witness,
                    )
                } else {
                    verify_taproot_script_path_foundation_v2(
                        transaction,
                        input_index,
                        spent_outputs,
                        script_pubkey,
                        &witness,
                        lock_context,
                    )
                };
            }
            return if flags.discourage_upgradable_witness_program {
                Err(ScriptPrimitiveErrorV2::BadOpcode)
            } else {
                Ok(())
            };
        }
    }

    let wrapped_witness_program =
        if flags.verify_witness && flags.verify_p2sh && is_pay_to_script_hash_v2(script_pubkey) {
            let operations = parse_script_v2(script_sig, flags.require_minimal_push)?;
            if let [ParsedOpcodeV2 {
                pushed: Some(redeem_script),
                ..
            }] = operations.as_slice()
            {
                if decode_witness_program_v2(redeem_script).is_some() {
                    Some(redeem_script.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
    verify_legacy_script_pair_v2(
        script_sig,
        script_pubkey,
        lock_context,
        legacy_signature_checker,
        LegacyScriptFlagsV2 {
            clean_stack: flags.clean_stack && wrapped_witness_program.is_none(),
            require_minimal_if: false,
            ..flags
        },
    )?;

    if let Some(redeem_script) = wrapped_witness_program {
        let (version, program) =
            decode_witness_program_v2(&redeem_script).ok_or(ScriptPrimitiveErrorV2::BadOpcode)?;
        if version == 0 {
            if !matches!(program.len(), 20 | 32) {
                return Err(ScriptPrimitiveErrorV2::BadOpcode);
            }
            return verify_witness_v0_program_v2(
                transaction,
                input_index,
                spent_output.value,
                &redeem_script,
                &witness,
                lock_context,
                WitnessV0FlagsV2 {
                    require_minimal_if: flags.require_minimal_if,
                    require_compressed_public_key: flags.witness_pubkey_type,
                    strict_der: flags.strict_der,
                    strict_encoding: flags.strict_encoding,
                    low_s: flags.low_s,
                },
            );
        }
        return if flags.discourage_upgradable_witness_program {
            Err(ScriptPrimitiveErrorV2::BadOpcode)
        } else {
            Ok(())
        };
    }
    if flags.verify_witness && !witness.is_empty() {
        return Err(ScriptPrimitiveErrorV2::InvalidStack);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn bitcoin_checker_does_not_enable_elements_stack_signatures() {
        for opcode in [0xc1, 0xc2] {
            assert_eq!(super::verify_native_script_components_v3(
                &[0, 0, 0], &[opcode, 0x51], &[],
                super::ScriptLockContextV2::default(),
                &super::RejectSignaturesV2, &super::RejectSignaturesV2,
                super::LegacyScriptFlagsV2::default()),
                Err(super::ScriptPrimitiveErrorV2::BadOpcode));
        }
    }

    #[test]
    fn native_witness_execution_preserves_nullfail_and_minimaldata_flags() {
        use super::*;
        struct FalseSignature;
        impl ScriptSignatureCheckerV2 for FalseSignature {
            fn check_ecdsa_signature(&self, _: &[u8], _: &[u8], _: &[u8], _: usize)
                -> Result<bool, ScriptPrimitiveErrorV2> { Ok(false) }
        }
        let run = |script: Vec<u8>, stack: Vec<Vec<u8>>, null_fail, minimal| {
            let mut program = vec![0, 32];
            program.extend_from_slice(&sha256::Hash::hash(&script).to_byte_array());
            let mut witness = stack;
            witness.push(script);
            verify_witness_program_with_execution_flags_v3(
                &program, &witness,
                ScriptLockContextV2 { null_fail, null_dummy: true, ..Default::default() },
                WitnessV0FlagsV2::default(), minimal, &FalseSignature,
            )
        };
        // CHECKSIG NOT: a false nonempty signature is a valid script result
        // without NULLFAIL; enabling NULLFAIL must reject before NOT executes.
        assert_eq!(run(vec![0xac, 0x91], vec![vec![1], vec![2]], false, true), Ok(()));
        assert!(run(vec![0xac, 0x91], vec![vec![1], vec![2]], true, true).is_err());
        // PUSHDATA1 01 01 is a nonminimal encoding of OP_1.
        assert_eq!(run(vec![0x4c, 1, 1], vec![], false, false), Ok(()));
        assert!(run(vec![0x4c, 1, 1], vec![], false, true).is_err());
        assert_eq!(run(vec![0x51], vec![], false, true), Ok(()));
    }
    use super::*;
    use bitcoin::absolute;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::transaction;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    struct ExpectedSignatureChecker {
        result: bool,
    }

    impl ScriptSignatureCheckerV2 for ExpectedSignatureChecker {
        fn check_ecdsa_signature(
            &self,
            signature_with_hash_type: &[u8],
            public_key: &[u8],
            script_code: &[u8],
            code_separator_position: usize,
        ) -> Result<bool, ScriptPrimitiveErrorV2> {
            let expected_position = if signature_with_hash_type.is_empty() {
                4
            } else {
                5
            };
            if public_key != [0x21]
                || script_code != [0xac]
                || code_separator_position != expected_position
                || (!signature_with_hash_type.is_empty() && signature_with_hash_type != [0x30])
            {
                return Err(ScriptPrimitiveErrorV2::Signature);
            }
            Ok(self.result)
        }
    }

    #[test]
    fn raw_push_parser_enforces_exact_lengths_minimality_and_limits() {
        assert_eq!(
            parse_script_v2(&[0x02, 0xaa, 0xbb, OP_1, 0x61], true).unwrap(),
            vec![
                ParsedOpcodeV2 {
                    opcode: 0x02,
                    pushed: Some(vec![0xaa, 0xbb]),
                    start: 0,
                    end: 3,
                },
                ParsedOpcodeV2 {
                    opcode: OP_1,
                    pushed: None,
                    start: 3,
                    end: 4,
                },
                ParsedOpcodeV2 {
                    opcode: 0x61,
                    pushed: None,
                    start: 4,
                    end: 5,
                },
            ]
        );
        assert_eq!(
            parse_script_v2(&[OP_PUSHDATA1, 1, 17], true),
            Err(ScriptPrimitiveErrorV2::NonMinimalPush)
        );
        assert_eq!(
            parse_script_v2(&[2, 1], false),
            Err(ScriptPrimitiveErrorV2::TruncatedPush)
        );
        let oversized = [OP_PUSHDATA2, 0x09, 0x02];
        assert_eq!(
            parse_script_v2(&oversized, false),
            Err(ScriptPrimitiveErrorV2::ElementSize)
        );
        assert_eq!(
            parse_script_v2(&vec![0x61; 202], false),
            Err(ScriptPrimitiveErrorV2::OperationCount)
        );
        assert_eq!(
            parse_script_v2(&vec![OP_0; MAX_SCRIPT_SIZE_V2 + 1], false),
            Err(ScriptPrimitiveErrorV2::ScriptSize)
        );
    }

    #[test]
    fn tapscript_op_success_short_circuits_trailing_decode_but_not_pushed_bytes() {
        assert_eq!(tapscript_has_op_success_v2(&[0x50, OP_PUSHDATA1]), Ok(true));
        assert_eq!(
            tapscript_has_op_success_v2(&[OP_1, OP_PUSHDATA1]),
            Err(ScriptPrimitiveErrorV2::TruncatedPush)
        );
        assert_eq!(tapscript_has_op_success_v2(&[0x01, 0x50]), Ok(false));
        // BIP342 deliberately removes the legacy 10,000-byte script limit.
        assert_eq!(
            tapscript_has_op_success_v2(&vec![OP_1; MAX_SCRIPT_SIZE_V2 + 1]),
            Ok(false)
        );
    }

    #[test]
    fn script_numbers_and_negative_zero_match_core_encoding() {
        let cases = [
            (0, vec![]),
            (1, vec![1]),
            (-1, vec![0x81]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x00]),
            (-128, vec![0x80, 0x80]),
            (32_767, vec![0xff, 0x7f]),
            (-32_767, vec![0xff, 0xff]),
            (
                i64::MIN,
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80],
            ),
        ];
        for (value, encoded) in cases {
            assert_eq!(encode_script_number_v2(value), encoded);
            if encoded.len() <= 8 {
                assert_eq!(decode_script_number_v2(&encoded, true, 8).unwrap(), value);
            }
        }
        assert!(!cast_to_bool_v2(&[]));
        assert!(!cast_to_bool_v2(&[0]));
        assert!(!cast_to_bool_v2(&[0, 0x80]));
        assert!(cast_to_bool_v2(&[0x80, 0]));
        assert_eq!(
            decode_script_number_v2(&[0x00], true, 4),
            Err(ScriptPrimitiveErrorV2::ScriptNumber)
        );
        assert_eq!(
            decode_script_number_v2(&[1, 0, 0, 0, 0], true, 4),
            Err(ScriptPrimitiveErrorV2::ScriptNumber)
        );
    }

    #[test]
    fn base_machine_enforces_control_flow_stack_and_disabled_opcodes() {
        // 1 IF 2 DUP DUP EQUALVERIFY ELSE RETURN ENDIF -> [2]
        let script = [OP_1, 0x63, 0x52, 0x76, 0x76, 0x88, 0x67, 0x6a, 0x68];
        assert_eq!(
            execute_script_base_v2(&script, vec![], true, true).unwrap(),
            vec![vec![2]]
        );
        assert_eq!(
            execute_script_base_v2(&[0x63], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::InvalidStack)
        );
        assert_eq!(
            execute_script_base_v2(&[OP_1, 0x63], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::InvalidConditional)
        );
        assert_eq!(
            execute_script_base_v2(&[0x02, 1, 0, 0x63, 0x68], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::InvalidConditional)
        );
        // Disabled opcodes fail even in an unexecuted branch.
        assert_eq!(
            execute_script_base_v2(&[OP_0, 0x63, 0x7e, 0x68], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::BadOpcode)
        );
        assert_eq!(
            execute_script_base_v2(&[0x6c], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::InvalidStack)
        );
        assert_eq!(
            execute_script_base_v2(&[OP_0, 0x69], vec![], true, true),
            Err(ScriptPrimitiveErrorV2::Verify)
        );

        let mut inactive_oversized_push = vec![OP_0, 0x63, OP_PUSHDATA2, 0x09, 0x02];
        inactive_oversized_push.extend(std::iter::repeat_n(7, 521));
        inactive_oversized_push.extend([0x68, OP_1]);
        assert_eq!(
            execute_script_base_v2(&inactive_oversized_push, vec![], true, true),
            Err(ScriptPrimitiveErrorV2::ElementSize)
        );
        assert_eq!(
            execute_script_base_v2(
                &[OP_0, 0x63, OP_PUSHDATA1, 0x01, 0x11, 0x68, OP_1],
                vec![],
                true,
                true,
            )
            .unwrap(),
            vec![vec![1]]
        );
    }

    #[test]
    fn deterministic_stack_numeric_and_hash_opcodes_are_exact() {
        // 2 3 ADD 5 NUMEQUALVERIFY "abc" SHA256
        let script = [0x52, 0x53, 0x93, 0x55, 0x9d, 0x03, b'a', b'b', b'c', 0xa8];
        assert_eq!(
            execute_script_base_v2(&script, vec![], true, true).unwrap(),
            vec![sha256::Hash::hash(b"abc").to_byte_array().to_vec()]
        );

        // 1 2 3 2 PICK -> 1 2 3 1; then 2 ROLL -> 1 3 1 2.
        let transforms = [0x51, 0x52, 0x53, 0x52, 0x79, 0x52, 0x7a];
        assert_eq!(
            execute_script_base_v2(&transforms, vec![], true, true).unwrap(),
            vec![vec![1], vec![3], vec![1], vec![2]]
        );

        // WITHIN is lower-inclusive and upper-exclusive.
        assert_eq!(
            execute_script_base_v2(&[0x52, 0x52, 0x53, 0xa5], vec![], true, true).unwrap(),
            vec![vec![1]]
        );
        assert_eq!(
            execute_script_base_v2(&[0x53, 0x52, 0x53, 0xa5], vec![], true, true).unwrap(),
            vec![Vec::<u8>::new()]
        );
    }

    #[test]
    fn cltv_and_csv_match_transaction_type_version_and_sequence_boundaries() {
        let cltv = [0x01, 100, 0xb1];
        let mut context = ScriptLockContextV2 {
            alpha_drivechain: false,
            transaction_version: 2,
            transaction_lock_time: 100,
            input_sequence: u32::MAX - 1,
            check_lock_time_verify: true,
            check_sequence_verify: true,
            null_fail: false,
            null_dummy: false,
            discourage_upgradable_nops: false,
            const_script_code: false,
            witness_v0: false,
        };
        assert_eq!(
            execute_script_with_locks_v2(&cltv, vec![], true, true, context).unwrap(),
            vec![vec![100]]
        );
        context.transaction_lock_time = 99;
        assert_eq!(
            execute_script_with_locks_v2(&cltv, vec![], true, true, context),
            Err(ScriptPrimitiveErrorV2::LockTime)
        );
        context.transaction_lock_time = LOCKTIME_THRESHOLD_V2;
        assert_eq!(
            execute_script_with_locks_v2(&cltv, vec![], true, true, context),
            Err(ScriptPrimitiveErrorV2::LockTime)
        );
        context.transaction_lock_time = 100;
        context.input_sequence = u32::MAX;
        assert_eq!(
            execute_script_with_locks_v2(&cltv, vec![], true, true, context),
            Err(ScriptPrimitiveErrorV2::LockTime)
        );

        let csv = [0x55, 0xb2];
        context.input_sequence = 5;
        assert!(execute_script_with_locks_v2(&csv, vec![], true, true, context).is_ok());
        context.input_sequence = 4;
        assert_eq!(
            execute_script_with_locks_v2(&csv, vec![], true, true, context),
            Err(ScriptPrimitiveErrorV2::LockTime)
        );
        context.input_sequence = 5;
        context.transaction_version = 1;
        assert_eq!(
            execute_script_with_locks_v2(&csv, vec![], true, true, context),
            Err(ScriptPrimitiveErrorV2::LockTime)
        );

        // A CSV operand with its disable bit set is a NOP after activation.
        let disabled_csv = [0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0xb2];
        assert!(execute_script_with_locks_v2(
            &disabled_csv,
            vec![],
            true,
            true,
            ScriptLockContextV2 {
                transaction_version: 1,
                input_sequence: u32::MAX,
                check_sequence_verify: true,
                ..ScriptLockContextV2::default()
            },
        )
        .is_ok());
    }

    #[test]
    fn checksig_binds_codesep_script_slice_and_nullfail() {
        let script = [0x01, 0x30, 0x01, 0x21, 0xab, 0xac];
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![],
                true,
                true,
                ScriptLockContextV2::default(),
                &ExpectedSignatureChecker { result: true },
            )
            .unwrap(),
            vec![vec![1]]
        );
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![],
                true,
                true,
                ScriptLockContextV2 {
                    null_fail: true,
                    ..ScriptLockContextV2::default()
                },
                &ExpectedSignatureChecker { result: false },
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
        let empty_signature = [OP_0, 0x01, 0x21, 0xab, 0xac];
        assert_eq!(
            execute_script_with_signatures_v2(
                &empty_signature,
                vec![],
                true,
                true,
                ScriptLockContextV2 {
                    null_fail: true,
                    ..ScriptLockContextV2::default()
                },
                &ExpectedSignatureChecker { result: false },
            )
            .unwrap(),
            vec![Vec::<u8>::new()]
        );
    }

    fn legacy_signature_fixture_v2(
        code_separator: bool,
    ) -> (Transaction, Vec<u8>, Vec<u8>, Vec<u8>) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
        let public_key_push = PushBytesBuf::try_from(public_key.to_vec()).unwrap();
        let mut script = Builder::new();
        if code_separator {
            script = script.push_opcode(bitcoin::opcodes::all::OP_CODESEPARATOR);
        }
        let script = script
            .push_slice(public_key_push)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let script_code = if code_separator {
            &script.as_bytes()[1..]
        } else {
            script.as_bytes()
        };
        let sighash = SighashCache::new(&transaction)
            .legacy_signature_hash(
                0,
                ScriptBuf::from_bytes(script_code.to_vec()).as_script(),
                1,
            )
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let mut signature = secp
            .sign_ecdsa(&message, &secret_key)
            .serialize_der()
            .to_vec();
        signature.push(1);
        (
            transaction,
            script.into_bytes(),
            signature,
            public_key.to_vec(),
        )
    }

    #[test]
    fn legacy_ecdsa_checker_verifies_real_signature_and_exact_sighash_context() {
        for code_separator in [false, true] {
            let (transaction, script, signature, public_key) =
                legacy_signature_fixture_v2(code_separator);
            let checker = LegacyEcdsaCheckerV2::new(&transaction, 0, true, true, true, false);
            let script_code = if code_separator {
                &script[1..]
            } else {
                &script
            };
            assert!(checker
                .check_ecdsa_signature(&signature, &public_key, script_code, 0)
                .unwrap());
            assert_eq!(
                execute_script_with_signatures_v2(
                    &script,
                    vec![signature.clone()],
                    true,
                    true,
                    ScriptLockContextV2 {
                        null_fail: true,
                        ..ScriptLockContextV2::default()
                    },
                    &checker,
                )
                .unwrap(),
                vec![vec![1]]
            );

            let mut mutated_transaction = transaction.clone();
            mutated_transaction.output[0].value = Amount::from_sat(50_001);
            let mutated_checker =
                LegacyEcdsaCheckerV2::new(&mutated_transaction, 0, true, true, true, false);
            assert!(!mutated_checker
                .check_ecdsa_signature(&signature, &public_key, script_code, 0)
                .unwrap());
            assert_eq!(
                execute_script_with_signatures_v2(
                    &script,
                    vec![signature.clone()],
                    true,
                    true,
                    ScriptLockContextV2 {
                        null_fail: true,
                        ..ScriptLockContextV2::default()
                    },
                    &mutated_checker,
                ),
                Err(ScriptPrimitiveErrorV2::Signature)
            );

            let mut undefined_sighash = signature.clone();
            *undefined_sighash.last_mut().unwrap() = 4;
            assert_eq!(
                checker.check_ecdsa_signature(&undefined_sighash, &public_key, script_code, 0,),
                Err(ScriptPrimitiveErrorV2::Signature)
            );
        }
    }

    fn legacy_multisig_fixture_v2() -> (Transaction, Vec<u8>, Vec<Vec<u8>>) {
        let secp = Secp256k1::new();
        let secret_keys = [
            SecretKey::from_slice(&[11; 32]).unwrap(),
            SecretKey::from_slice(&[12; 32]).unwrap(),
            SecretKey::from_slice(&[13; 32]).unwrap(),
        ];
        let public_keys: Vec<PushBytesBuf> = secret_keys
            .iter()
            .map(|secret_key| {
                PushBytesBuf::try_from(
                    PublicKey::from_secret_key(&secp, secret_key)
                        .serialize()
                        .to_vec(),
                )
                .unwrap()
            })
            .collect();
        let script = Builder::new()
            .push_int(2)
            .push_slice(public_keys[0].clone())
            .push_slice(public_keys[1].clone())
            .push_slice(public_keys[2].clone())
            .push_int(3)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(75_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let sighash = SighashCache::new(&transaction)
            .legacy_signature_hash(0, script.as_script(), 1)
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let signatures = secret_keys
            .iter()
            .map(|secret_key| {
                let mut signature = secp
                    .sign_ecdsa(&message, secret_key)
                    .serialize_der()
                    .to_vec();
                signature.push(1);
                signature
            })
            .collect();
        (transaction, script.into_bytes(), signatures)
    }

    #[test]
    fn legacy_checkmultisig_enforces_order_dummy_nullfail_and_real_signatures() {
        let (transaction, script, signatures) = legacy_multisig_fixture_v2();
        let checker = LegacyEcdsaCheckerV2::new(&transaction, 0, true, true, true, false);
        let context = ScriptLockContextV2 {
            null_fail: true,
            null_dummy: true,
            ..ScriptLockContextV2::default()
        };
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![vec![], signatures[0].clone(), signatures[2].clone()],
                true,
                true,
                context,
                &checker,
            )
            .unwrap(),
            vec![vec![1]]
        );
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![vec![], signatures[2].clone(), signatures[0].clone()],
                true,
                true,
                context,
                &checker,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![vec![1], signatures[0].clone(), signatures[2].clone()],
                true,
                true,
                context,
                &checker,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
        let mut mutated = signatures[2].clone();
        mutated[8] ^= 1;
        assert_eq!(
            execute_script_with_signatures_v2(
                &script,
                vec![vec![], signatures[0].clone(), mutated],
                true,
                true,
                context,
                &checker,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
    }

    #[test]
    fn p2sh_restores_push_only_stack_and_enforces_redeem_and_cleanstack() {
        let redeem_script = Builder::new().push_int(1).into_script();
        let redeem_push = PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap();
        let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
        let hash_push = PushBytesBuf::try_from(redeem_hash.to_byte_array().to_vec()).unwrap();
        let script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(hash_push)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let script_sig = Builder::new().push_slice(redeem_push.clone()).into_script();
        let flags = LegacyScriptFlagsV2 {
            require_minimal_push: true,
            require_minimal_if: true,
            verify_p2sh: true,
            clean_stack: true,
            verify_witness: false,
            verify_taproot: false,
            witness_pubkey_type: false,
            discourage_upgradable_witness_program: false,
            ..LegacyScriptFlagsV2::default()
        };
        assert_eq!(
            verify_legacy_script_pair_v2(
                script_sig.as_bytes(),
                script_pubkey.as_bytes(),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );

        let non_push_script_sig = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_NOP)
            .push_slice(redeem_push.clone())
            .into_script();
        assert_eq!(
            verify_legacy_script_pair_v2(
                non_push_script_sig.as_bytes(),
                script_pubkey.as_bytes(),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::BadOpcode)
        );

        let dirty_stack_script_sig = Builder::new()
            .push_int(1)
            .push_slice(redeem_push)
            .into_script();
        assert_eq!(
            verify_legacy_script_pair_v2(
                dirty_stack_script_sig.as_bytes(),
                script_pubkey.as_bytes(),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::InvalidStack)
        );

        let false_redeem = Builder::new().push_int(0).into_script();
        let false_push = PushBytesBuf::try_from(false_redeem.as_bytes().to_vec()).unwrap();
        let false_hash = hash160::Hash::hash(false_redeem.as_bytes());
        let false_hash_push = PushBytesBuf::try_from(false_hash.to_byte_array().to_vec()).unwrap();
        let false_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(false_hash_push)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let false_sig = Builder::new().push_slice(false_push).into_script();
        assert_eq!(
            verify_legacy_script_pair_v2(
                false_sig.as_bytes(),
                false_pubkey.as_bytes(),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::Verify)
        );
    }

    #[test]
    fn witness_v0_commits_prevout_value_and_executes_p2wpkh_and_p2wsh() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[19; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
        let public_key_hash = hash160::Hash::hash(&public_key);
        let mut p2wpkh_program = vec![0x00, 0x14];
        p2wpkh_program.extend_from_slice(&public_key_hash.to_byte_array());
        let spent_value = Amount::from_sat(90_000);
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(80_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let sighash = SighashCache::new(&transaction)
            .p2wpkh_signature_hash(
                0,
                Script::from_bytes(&p2wpkh_program),
                spent_value,
                EcdsaSighashType::All,
            )
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let mut signature = secp
            .sign_ecdsa(&message, &secret_key)
            .serialize_der()
            .to_vec();
        signature.push(1);
        let witness = vec![signature, public_key.to_vec()];
        assert_eq!(
            verify_witness_v0_program_v2(
                &transaction,
                0,
                spent_value,
                &p2wpkh_program,
                &witness,
                ScriptLockContextV2::default(),
                WitnessV0FlagsV2 {
                    require_minimal_if: true,
                    require_compressed_public_key: false,
                    strict_der: true,
                    strict_encoding: true,
                    low_s: true,
                },
            ),
            Ok(())
        );
        assert_eq!(
            verify_witness_v0_program_v2(
                &transaction,
                0,
                Amount::from_sat(90_001),
                &p2wpkh_program,
                &witness,
                ScriptLockContextV2::default(),
                WitnessV0FlagsV2 {
                    require_minimal_if: true,
                    require_compressed_public_key: false,
                    strict_der: true,
                    strict_encoding: true,
                    low_s: true,
                },
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );

        let witness_script = Builder::new().push_int(1).into_script();
        let witness_script_hash = sha256::Hash::hash(witness_script.as_bytes());
        let mut p2wsh_program = vec![0x00, 0x20];
        p2wsh_program.extend_from_slice(&witness_script_hash.to_byte_array());
        assert_eq!(
            verify_witness_v0_program_v2(
                &transaction,
                0,
                spent_value,
                &p2wsh_program,
                &[witness_script.as_bytes().to_vec()],
                ScriptLockContextV2::default(),
                WitnessV0FlagsV2 {
                    require_minimal_if: true,
                    require_compressed_public_key: false,
                    strict_der: true,
                    strict_encoding: true,
                    low_s: true,
                },
            ),
            Ok(())
        );
        let mut wrong_program = p2wsh_program.clone();
        wrong_program[10] ^= 1;
        assert_eq!(
            verify_witness_v0_program_v2(
                &transaction,
                0,
                spent_value,
                &wrong_program,
                &[witness_script.as_bytes().to_vec()],
                ScriptLockContextV2::default(),
                WitnessV0FlagsV2 {
                    require_minimal_if: true,
                    require_compressed_public_key: false,
                    strict_der: true,
                    strict_encoding: true,
                    low_s: true,
                },
            ),
            Err(ScriptPrimitiveErrorV2::Verify)
        );
    }

    #[test]
    fn script_input_dispatches_native_wrapped_witness_and_rejects_unconsumed_witness() {
        let witness_script = Builder::new().push_int(1).into_script();
        let witness_script_hash = sha256::Hash::hash(witness_script.as_bytes());
        let mut witness_program = vec![0x00, 0x20];
        witness_program.extend_from_slice(&witness_script_hash.to_byte_array());
        let spent_value = Amount::from_sat(100_000);
        let make_transaction = |script_sig: ScriptBuf| {
            let mut witness = Witness::new();
            witness.push(witness_script.as_bytes());
            Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig,
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness,
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(99_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            }
        };
        let flags = LegacyScriptFlagsV2 {
            require_minimal_push: true,
            require_minimal_if: true,
            verify_p2sh: true,
            clean_stack: true,
            verify_witness: true,
            verify_taproot: true,
            witness_pubkey_type: false,
            discourage_upgradable_witness_program: false,
            ..LegacyScriptFlagsV2::default()
        };

        let native_transaction = make_transaction(ScriptBuf::new());
        let native_spent = TxOut {
            value: spent_value,
            script_pubkey: ScriptBuf::from_bytes(witness_program.clone()),
        };
        assert_eq!(
            verify_script_input_v2(
                &native_transaction,
                0,
                std::slice::from_ref(&native_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );
        let native_with_script_sig = make_transaction(Builder::new().push_int(1).into_script());
        assert_eq!(
            verify_script_input_v2(
                &native_with_script_sig,
                0,
                std::slice::from_ref(&native_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::InvalidStack)
        );

        let witness_program_push = PushBytesBuf::try_from(witness_program.clone()).unwrap();
        let wrapped_script_sig = Builder::new()
            .push_slice(witness_program_push)
            .into_script();
        let wrapped_transaction = make_transaction(wrapped_script_sig);
        let wrapped_hash = hash160::Hash::hash(&witness_program);
        let wrapped_hash_push =
            PushBytesBuf::try_from(wrapped_hash.to_byte_array().to_vec()).unwrap();
        let wrapped_spent = TxOut {
            value: spent_value,
            script_pubkey: Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                .push_slice(wrapped_hash_push)
                .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
                .into_script(),
        };
        assert_eq!(
            verify_script_input_v2(
                &wrapped_transaction,
                0,
                std::slice::from_ref(&wrapped_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );

        let legacy_spent = TxOut {
            value: spent_value,
            script_pubkey: Builder::new().push_int(1).into_script(),
        };
        assert_eq!(
            verify_script_input_v2(
                &native_transaction,
                0,
                std::slice::from_ref(&legacy_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::InvalidStack)
        );

        let future_witness_spent = TxOut {
            value: spent_value,
            script_pubkey: ScriptBuf::from_bytes({
                let mut script = vec![0x52, 0x20];
                script.extend_from_slice(&[9; 32]);
                script
            }),
        };
        assert_eq!(
            verify_script_input_v2(
                &native_transaction,
                0,
                std::slice::from_ref(&future_witness_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );
        let malformed_v0_spent = TxOut {
            value: spent_value,
            script_pubkey: ScriptBuf::from_bytes(vec![OP_0, 0x02, 1, 2]),
        };
        assert_eq!(
            verify_script_input_v2(
                &native_transaction,
                0,
                std::slice::from_ref(&malformed_v0_spent),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::BadOpcode)
        );
    }

    #[test]
    fn taproot_key_path_50_prefix_is_not_annex_and_commits_all_prevouts() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[23; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let (output_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut program = vec![OP_1, 0x20];
        program.extend_from_slice(&output_key.serialize());
        let spent_output = TxOut {
            value: Amount::from_sat(110_000),
            script_pubkey: ScriptBuf::from_bytes(program.clone()),
        };
        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(109_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // A single signature beginning with the annex tag remains a key-path
        // signature. Annex detection requires at least two witness elements.
        // Deterministically vary a signed output to obtain this regression case.
        let signature = (0..10_000u64).find_map(|nonce| {
            transaction.output[0].value = Amount::from_sat(109_000 - nonce);
            let sighash = SighashCache::new(&transaction)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(std::slice::from_ref(&spent_output)),
                    TapSighashType::Default,
                ).unwrap();
            let signature = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(sighash.to_byte_array()), &keypair).serialize();
            (signature[0] == 0x50).then_some(signature)
        }).expect("deterministic 0x50-prefixed signature fixture");
        transaction.input[0].witness.push(signature);
        let flags = LegacyScriptFlagsV2 {
            require_minimal_push: true,
            require_minimal_if: true,
            verify_p2sh: true,
            clean_stack: true,
            verify_witness: true,
            verify_taproot: true,
            witness_pubkey_type: false,
            discourage_upgradable_witness_program: false,
            ..LegacyScriptFlagsV2::default()
        };
        assert_eq!(
            verify_script_input_v2(
                &transaction,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );
        let mut wrong_spent_output = spent_output.clone();
        wrong_spent_output.value = Amount::from_sat(110_001);
        assert_eq!(
            verify_script_input_v2(
                &transaction,
                0,
                std::slice::from_ref(&wrong_spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
        let mut mutated_signature = signature;
        mutated_signature[10] ^= 1;
        transaction.input[0].witness = Witness::new();
        transaction.input[0].witness.push(mutated_signature);
        assert_eq!(
            verify_script_input_v2(
                &transaction,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
    }

    #[test]
    fn taproot_script_path_authenticates_control_block_and_executes_safe_subset() {
        let secp = Secp256k1::new();
        let internal_secret = SecretKey::from_slice(&[29; 32]).unwrap();
        let internal_keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(&secp, &internal_secret);
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&internal_keypair);
        let tapscript = Builder::new().push_int(1).into_script();
        let spend_info = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, tapscript.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control = spend_info
            .control_block(&(tapscript.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut program = vec![OP_1, 0x20];
        program.extend_from_slice(&spend_info.output_key().serialize());
        let spent_output = TxOut {
            value: Amount::from_sat(120_000),
            script_pubkey: ScriptBuf::from_bytes(program),
        };
        let mut witness = Witness::new();
        witness.push(tapscript.as_bytes());
        witness.push(control.serialize());
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(119_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let flags = LegacyScriptFlagsV2 {
            require_minimal_push: true,
            require_minimal_if: true,
            verify_p2sh: true,
            clean_stack: true,
            verify_witness: true,
            verify_taproot: true,
            witness_pubkey_type: false,
            discourage_upgradable_witness_program: false,
            ..LegacyScriptFlagsV2::default()
        };
        assert_eq!(
            verify_script_input_v2(
                &transaction,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );
        let mut mutated_transaction = transaction.clone();
        let mut mutated_control = control.serialize();
        mutated_control[1] ^= 1;
        mutated_transaction.input[0].witness = Witness::new();
        mutated_transaction.input[0]
            .witness
            .push(tapscript.as_bytes());
        mutated_transaction.input[0].witness.push(mutated_control);
        assert_eq!(
            verify_script_input_v2(
                &mutated_transaction,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
    }

    #[test]
    fn tapscript_checksig_uses_bip342_leaf_and_schnorr_signature() {
        let secp = Secp256k1::new();
        let internal_secret = SecretKey::from_slice(&[31; 32]).unwrap();
        let internal_keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(&secp, &internal_secret);
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&internal_keypair);
        let signing_secret = SecretKey::from_slice(&[32; 32]).unwrap();
        let signing_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &signing_secret);
        let (signing_key, _) = XOnlyPublicKey::from_keypair(&signing_keypair);
        let signing_key_push = PushBytesBuf::try_from(signing_key.serialize().to_vec()).unwrap();
        let tapscript = Builder::new()
            .push_slice(signing_key_push)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend_info = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, tapscript.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control = spend_info
            .control_block(&(tapscript.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut program = vec![OP_1, 0x20];
        program.extend_from_slice(&spend_info.output_key().serialize());
        let spent_output = TxOut {
            value: Amount::from_sat(130_000),
            script_pubkey: ScriptBuf::from_bytes(program),
        };
        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(129_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let leaf_hash = TapLeafHash::from_script(&tapscript, LeafVersion::TapScript);
        let sighash = SighashCache::new(&transaction)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&spent_output)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp
            .sign_schnorr_no_aux_rand(&message, &signing_keypair)
            .serialize();
        transaction.input[0].witness.push(signature);
        transaction.input[0].witness.push(tapscript.as_bytes());
        transaction.input[0].witness.push(control.serialize());
        let flags = LegacyScriptFlagsV2 {
            require_minimal_push: true,
            require_minimal_if: true,
            verify_p2sh: true,
            clean_stack: true,
            verify_witness: true,
            verify_taproot: true,
            witness_pubkey_type: false,
            discourage_upgradable_witness_program: false,
            ..LegacyScriptFlagsV2::default()
        };
        assert_eq!(
            verify_script_input_v2(
                &transaction,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Ok(())
        );
        let mut mutated = transaction.clone();
        let mut bad_signature = signature;
        bad_signature[9] ^= 1;
        mutated.input[0].witness = Witness::new();
        mutated.input[0].witness.push(bad_signature);
        mutated.input[0].witness.push(tapscript.as_bytes());
        mutated.input[0].witness.push(control.serialize());
        assert_eq!(
            verify_script_input_v2(
                &mutated,
                0,
                std::slice::from_ref(&spent_output),
                ScriptLockContextV2::default(),
                &RejectSignaturesV2,
                flags,
            ),
            Err(ScriptPrimitiveErrorV2::Signature)
        );
    }
}
